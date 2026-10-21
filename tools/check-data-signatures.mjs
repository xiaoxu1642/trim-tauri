#!/usr/bin/env node
// check-data-signatures.mjs —— 数据产物逐件验签门禁（T1c-M02，v7.2 C09；D1-M03 扩到五件 + 双向对账）
//
// 抓什么：带签名的数据产物被**手改或漏签**时，Node 侧必须当场判红。此前只有残留域有验签
// （check-residue-rule-contract），清理域与优化域被改后 Node 全绿——损失拖到应用装载时
// （fail-closed 拒收）才暴露，违反「改后必须重签」的发布纪律却没有发布前判红路径。
//
// D1-M03（v7.2 P1）补的是**登记面漏件**这一维：`src-tauri/data/` 里带 `_sig` 的有四件，
// 而本门禁原先只登记三件 —— 两块优化面板侧表（nara / privacy）改了不重签，Node 侧一条腿
// 都不会红。现在的口径不是「清单别写漏」而是**双向对账**：
//   · 盘上有签名（内联 `_sig` 或裸数组的 sidecar）却没登记验签点 ⇒ 红（本次要抓的形态）
//   · 登记了验签点但正文没有签名/sidecar ⇒ 红（登记漂移，或生成器只剥不签）
// 新增带签名产物时必须同时进 TARGETS，否则当场判红 —— 靠对账而不是靠人记得住。
//
// 段序是判据的一部分：**对账必须在正向对照之前**。正向对照那段判红即整条退出，
// 排在它后面的话，「漏登记」这种最该先看到的缺口会被「对照样本本身不对」盖住
// （2026-10-21 破坏验证实测：把两块面板从登记面摘掉，红的却是对照段）。
//
// 判据真源：验签实现 import 自 tools/sign-cleanup-rules.mjs（canonicalBodyText /
// verifyBody / verifyRulesFile 单一实现，§5.16 不抄第二份）；公钥**运行期解析自
// src-tauri/src/engine/rules_signature.rs 的 RULES_PUBKEY_PEM**（真源在 Rust 侧）。
//
// 正向对照（§4.1）：每件内联签名产物都必须「真样本通过 / 正文追加一个空格判红 /
// 签名换尾八字节判红」。对照失效（对篡改放行）即本门禁整条断言不可信。
// 裸数组 + sidecar 那件走 verifyRulesFile 自己的分支，不在这里重复做字节对照。
//
// 用法：node tools/check-data-signatures.mjs
'use strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, readdirSync, existsSync } from 'node:fs';

import { gate } from './lib/gate.mjs';
import { verifyBody, canonicalBodyText, verifyRulesFile } from './sign-cleanup-rules.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DATA_DIR = join(ROOT, 'src-tauri', 'data');
const g = gate(import.meta.url);

const TARGETS = [
  'src-tauri/data/cleanup-rules.json',
  'src-tauri/data/uninstall-residue-rules.json',
  'src-tauri/data/optimizer-runtime.json',
  'src-tauri/data/optimizer-nara-panel.json',
  'src-tauri/data/optimizer-privacy-panel.json',
];

// ---------- 1. 双向对账：现算签名面 ⇄ 本门禁登记面 ----------
{
  // 口径：顶层对象看 `_sig.sig`；顶层裸数组看同名 sidecar `<file>.sig.json`（§5.21 两形态）。
  // sidecar 自身不算「带签名的数据件」—— 它是签名载体不是正文。
  const signed = [];
  for (const f of readdirSync(DATA_DIR).filter((f) => f.endsWith('.json'))) {
    if (f.endsWith('.sig.json')) continue;
    const abs = join(DATA_DIR, f);
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(abs, 'utf8'));
    } catch {
      continue; // 损坏件由各域自己的门禁点名（check-data-parity 第 5 组已管 JSON 合法性）
    }
    const hasSig = Array.isArray(parsed)
      ? existsSync(`${abs}.sig.json`)
      : Boolean(parsed && typeof parsed === 'object' && parsed._sig?.sig);
    if (hasSig) signed.push(`src-tauri/data/${f}`);
  }
  signed.sort();
  const roster = [...TARGETS].sort();
  const rosterSet = new Set(roster);
  const signedSet = new Set(signed);
  const unregistered = signed.filter((rel) => !rosterSet.has(rel));
  const phantom = roster.filter((rel) => !signedSet.has(rel));
  if (unregistered.length) {
    g.fail(`带签名却无验签点（改了不重签不会判红）：${unregistered.join('、')}`);
  }
  if (phantom.length) {
    g.fail(`登记了验签点但正文没有签名/sidecar（登记漂移或生成器只剥不签）：${phantom.join('、')}`);
  }
  if (!unregistered.length && !phantom.length) {
    g.ok(`签名面现算 ${signed.length} 件 ⇄ 登记面 ${roster.length} 件双向咬合：${signed.join('、')}`);
  }
}

// ---------- 2. 正向对照：判定器必须能判红（对篡改样本），真样本必须放行 ----------
{
  // 做字节级篡改对照的对象：顶层对象带内联 `_sig` 的那些。optimizer-runtime.json 是裸数组
  // 走 sidecar `.sig.json`（§5.21 的另一形态），它的验签在第 3 段的 verifyRulesFile 里完成。
  const inlineSigTargets = TARGETS.filter((rel) => !rel.endsWith('optimizer-runtime.json'));
  const problems = [];
  const passed = [];
  for (const rel of inlineSigTargets) {
    const abs = join(ROOT, rel);
    if (!existsSync(abs)) {
      g.skipUnlessPresent(abs, `${rel}（内联签名产物体正对照）`);
      continue;
    }
    const parsed = JSON.parse(readFileSync(abs, 'utf8'));
    if (!parsed?._sig?.sig) {
      problems.push(`${rel}：登记在内联签名对照面里，正文却没有 _sig —— 对照面与真实形状分叉`);
      continue;
    }
    const body = canonicalBodyText(parsed);
    const sig = parsed._sig.sig;
    // 真样本过不了 ⇒ **不在这儿**判「判定器不可信」。这儿是判定器的自检面，而「改了没重签」
    // 是一件具体产物的事实，归第 3 段逐件验签去点名（那里的 reason 带着「需要重签」的可执行措辞）。
    // 混在一起的症状（2026-10-22 实测）：改完 nara 面板的 `_comment` 未重签，红的却是
    // 「验签判定器不可信」——把真实原因盖成一句对本门禁自身的指控。
    // 判定器自检只保留两条「必须拒」：正文被改、签名被换尾。
    if (verifyBody(`${body} `, sig)) problems.push(`${rel}：正文篡改（追加一个空格）被放行——判定器对改内容失明`);
    if (verifyBody(body, `${sig.slice(0, -8)}Zm9vYmFy`)) problems.push(`${rel}：签名被换尾后仍放行——判定器对改签名失明`);
    if (verifyBody(body, sig)) passed.push(rel);
  }
  if (problems.length) {
    g.fail(`正向对照失败：验签判定器不可信\n  ${problems.join('\n  ')}`);
    g.finish();
    process.exit(1);
  }
  g.ok(`正向对照 ${passed.length} 件（逐件：真样本通过 / 正文与签名篡改均判红）：${passed.join('、')}`);
}

// ---------- 3. 真仓：登记面逐件验签 ----------
const bad = [];
for (const rel of TARGETS) {
  const r = verifyRulesFile(join(ROOT, rel));
  if (!r.ok) bad.push(`${rel} — ${r.why}`);
  else g.ok(`${rel} 验签通过`);
}
if (bad.length) g.fail(`存在签名不符/缺失的产物（改后必须重签：node tools/sign-cleanup-rules.mjs sign [--file …]）：\n  ${bad.join('\n  ')}`);

g.finish('数据产物验签门禁全部通过');
