#!/usr/bin/env node
// sign-cleanup-rules.mjs - 清理规则库签名与前端兜底副本生成（P0 规则库最终优化方案 2026-09-27）
//
// 背景：原 Electron 轨的 scripts/sign-rules.js / gen-fallback.js 随仓库切换没有跟过来，
// 但 src-tauri/data/cleanup-rules.json 带 Ed25519 签名（rules_signature.rs 验签 +
// real_rules_file_verdict 测试盯着），check-data-parity 还要求它与
// src/scripts/cleanup-fallback.generated.js 逐字节一致。本工具把两个动作收进本仓库：
//
//   node tools/sign-cleanup-rules.mjs sign                     签名 src-tauri/data/cleanup-rules.json
//   node tools/sign-cleanup-rules.mjs gen-fallback             从规则 JSON 重新生成前端兜底副本
//   node tools/sign-cleanup-rules.mjs sign --file <相对路径>    签名其他规则文件（同款密钥/规范化），
//                                                              如 --file src-tauri/data/uninstall-residue-rules.json
//
// 签名私钥固定在 ~/.trim-signing/rules-ed25519-private.pem（发布机私有，绝不入仓库）。
// 签名对象 = 根对象去掉 _sig 后的紧凑 JSON（键序 = 原解析插入序），与
// src-tauri/src/engine/rules_signature.rs::canonical_body_text 完全一致。
// 用法顺序：改规则 JSON → sign → gen-fallback → node tools/check-data-parity.mjs。
'use strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
// --file <相对路径>：U-1 起签名工具泛化为「规则文件签名器」（同一密钥、同一规范化），
// 默认仍是 cleanup-rules.json，存量用法零改动
const argv = process.argv.slice(2);
const fileArg = argv.includes('--file') ? argv[argv.indexOf('--file') + 1] : null;
const RULES = fileArg ? path.join(ROOT, fileArg) : path.join(ROOT, 'src-tauri', 'data', 'cleanup-rules.json');
const FALLBACK = path.join(ROOT, 'src', 'scripts', 'cleanup-fallback.generated.js');
const PRIV_KEY = path.join(os.homedir(), '.trim-signing', 'rules-ed25519-private.pem');

function canonicalBodyText(parsed) {
  // ⚠️ **数组顶层必须原样序列化**（M4 实测踩到）：`Object.entries(array)`枚举出的是
  // **索引键**，所以下面那段「逐键重建」会把 `[{...}]` 变成 `{"0":{...}}` ——
  // 与 Rust 侧 `serde_json::to_string(&array)` 逐字节不同，签名永远对不上。
  // 症状极具迷惑性：Node 侧「签名成功」、Rust 侧「验签失败，内容可能被篡改」。
  if (Array.isArray(parsed)) {
    return JSON.stringify(parsed);
  }
  // 对象顶层：键序必须等于原文件解析插入序（JS 对象保序），与 Rust 侧逐键重建口径一致
  const body = {};
  for (const [k, v] of Object.entries(parsed)) {
    if (k === '_sig') continue;
    body[k] = v;
  }
  return JSON.stringify(body);
}

/**
 * 把 `_sig` 挂到解析结果上，返回实际写出的路径。
 *
 * **顶层是数组时不能挂**（M4 实测踩到）：`optimizer-runtime.json` 的顶层是
 * 裸数组，`arr._sig = {...}` 静默无效 —— 那是给数组对象加了个普通属性，而
 * `JSON.stringify` **不序列化**数组的非索引属性，于是「已签名」打印出来了、
 * 文件里却一个字节都没变。本仓最讨厌的一类假绿。
 *
 * 也不能「追加一个 `{"_sig":…}` 元素」—— 那会污染 `options()` 的迭代。
 * 所以数组形态用**独立 sidecar**：`<file>.sig.json`。
 */
function attachSig(parsed, sigObj) {
  if (Array.isArray(parsed)) {
    const sidecar = `${RULES}.sig.json`;
    fs.writeFileSync(
      sidecar,
      `${JSON.stringify({ alg: 'ed25519', sig: sigObj.sig, covers: path.basename(RULES) }, null, 2)}\n`,
      'utf8',
    );
    return sidecar;
  }
  delete parsed._sig;
  parsed._sig = sigObj;
  fs.writeFileSync(RULES, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');
  return RULES;
}

function sign() {
  if (!fs.existsSync(PRIV_KEY)) {
    console.error(`未找到私钥: ${PRIV_KEY}（签名私钥只存在于发布机）`);
    process.exit(1);
  }
  const parsed = JSON.parse(fs.readFileSync(RULES, 'utf8'));
  const bodyText = canonicalBodyText(parsed);
  const sig = crypto
    .sign(null, Buffer.from(bodyText, 'utf8'), crypto.createPrivateKey(fs.readFileSync(PRIV_KEY, 'utf8')))
    .toString('base64');
  // _sig 追加在键序末尾（与旧签名文件形态一致）；整体重写为 2 空格缩进 + 末尾换行。
  // 顶层是数组时改走 sidecar（见 attachSig 的注释）——`arr._sig = …` 静默无效，
  // 那是「打印了已签名但文件没变」的假绿。
  const written = attachSig(parsed, { alg: 'ed25519', sig });
  console.log(`已签名: ${written}`);
}

function genFallback() {
  const raw = fs.readFileSync(RULES, 'utf8');
  JSON.parse(raw); // 源必须是合法 JSON，坏源直接抛错终止
  // 以 JSON.parse(字符串字面量) 内联，而非对象字面量直拼——数据源经 JSON.stringify 转义后
  // 不再作为 JS 代码解析，未来数据引入不可信内容也不会注入执行（沿用 Electron 轨审查结论）
  const out = `// 本文件由 tools/sign-cleanup-rules.mjs 从 src-tauri/data/cleanup-rules.json 自动生成。
// 勿手改——修改规则 JSON 后运行 node tools/sign-cleanup-rules.mjs gen-fallback 重新生成。
// 用途：cleanup.js 浏览器预览 / IPC 不可用时的分类兜底（经 buildCategoriesFromRules 构建）。
(function (root) {
  'use strict';
  root.CLEANUP_RULES_FALLBACK = JSON.parse(${JSON.stringify(raw.trim())});
})(typeof window !== 'undefined' ? window : globalThis);
`;
  fs.writeFileSync(FALLBACK, out, 'utf8');
  console.log(`已生成: ${FALLBACK}`);
}

const cmd = argv[0];
if (cmd === 'sign') sign();
else if (cmd === 'gen-fallback') genFallback();
else {
  console.error('用法: node tools/sign-cleanup-rules.mjs <sign|gen-fallback> [--file <相对路径>]');
  process.exit(1);
}
