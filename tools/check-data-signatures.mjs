#!/usr/bin/env node
// check-data-signatures.mjs —— 数据产物逐件验签门禁（T1c-M02，v7.2 C09）
//
// 抓什么：三个带签名的数据产物（清理规则库 / 卸载残留规则库 / 优化运行时+sidecar）
// 被**手改或漏签**时，Node 侧必须当场判红。此前只有残留域有验签（check-residue-
// rule-contract），清理域与优化域被改后 Node 全绿——损失拖到应用装载时（fail-closed
// 拒收）才暴露，违反「改后必须重签」的发布纪律却没有发布前判红路径。
//
// 判据真源：验签实现 import 自 tools/sign-cleanup-rules.mjs（canonicalBodyText /
// verifyBody / verifyRulesFile 单一实现，§5.16 不抄第二份）；公钥**运行期解析自
// src-tauri/src/engine/rules_signature.rs 的 RULES_PUBKEY_PEM**（真源在 Rust 侧）。
//
// 正向对照（§4.1）：真样本必须通过；正文篡改一个字节、签名换尾四字节都必须判红——
// 对照失效（对篡改放行）即本门禁断言不可信。
//
// 用法：node tools/check-data-signatures.mjs
'use strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

import { gate } from './lib/gate.mjs';
import { verifyBody, canonicalBodyText, verifyRulesFile } from './sign-cleanup-rules.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const g = gate(import.meta.url);

const TARGETS = [
  'src-tauri/data/cleanup-rules.json',
  'src-tauri/data/uninstall-residue-rules.json',
  'src-tauri/data/optimizer-runtime.json',
];

// ---------- 正向对照：判定器必须能判红（对篡改样本），真样本必须放行 ----------
{
  const problems = [];
  const realText = readFileSync(join(ROOT, TARGETS[0]), 'utf8');
  const parsed = JSON.parse(realText);
  const body = canonicalBodyText(parsed);
  const sig = parsed?._sig?.sig ?? '';
  if (!verifyBody(body, sig)) problems.push('真样本被判红（验签判定器对合法签名误报）');
  if (verifyBody(`${body} `, sig)) problems.push('正文篡改（追加一个空格）被放行——判定器对改内容失明');
  if (verifyBody(body, `${sig.slice(0, -8)}Zm9vYmFy`)) problems.push('签名被换尾后仍放行——判定器对改签名失明');
  if (problems.length) {
    g.fail(`正向对照失败：验签判定器不可信\n  ${problems.join('\n  ')}`);
    g.finish();
    process.exit(1);
  }
  g.ok('正向对照：真样本通过 / 正文篡改与签名篡改均判红（验签判定器可信）');
}

// ---------- 真仓：三件产物逐件验签 ----------
const bad = [];
for (const rel of TARGETS) {
  const r = verifyRulesFile(join(ROOT, rel));
  if (!r.ok) bad.push(`${rel} — ${r.why}`);
  else g.ok(`${rel} 验签通过`);
}
if (bad.length) g.fail(`存在签名不符/缺失的产物（改后必须重签：node tools/sign-cleanup-rules.mjs sign [--file …]）：\n  ${bad.join('\n  ')}`);

g.finish('数据产物验签门禁全部通过');
