#!/usr/bin/env node
// sign-cleanup-rules.mjs - 清理规则库签名与前端兜底副本生成（P0 规则库最终优化方案 2026-09-27）
//
// 背景：原 Electron 轨的 scripts/sign-rules.js / gen-fallback.js 随仓库切换没有跟过来，
// 但 src-tauri/data/cleanup-rules.json 带 Ed25519 签名（rules_signature.rs 验签 +
// real_rules_file_verdict 测试盯着），check-data-parity 还要求它与
// src/scripts/cleanup-fallback.generated.js 逐字节一致。本工具把两个动作收进本仓库：
//
//   node tools/sign-cleanup-rules.mjs sign          签名 src-tauri/data/cleanup-rules.json
//   node tools/sign-cleanup-rules.mjs gen-fallback  从规则 JSON 重新生成前端兜底副本
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
const RULES = path.join(ROOT, 'src-tauri', 'data', 'cleanup-rules.json');
const FALLBACK = path.join(ROOT, 'src', 'scripts', 'cleanup-fallback.generated.js');
const PRIV_KEY = path.join(os.homedir(), '.trim-signing', 'rules-ed25519-private.pem');

function canonicalBodyText(parsed) {
  // 键序必须等于原文件解析插入序（JS 对象保序），与 Rust 侧逐键重建口径一致
  const body = {};
  for (const [k, v] of Object.entries(parsed)) {
    if (k === '_sig') continue;
    body[k] = v;
  }
  return JSON.stringify(body);
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
  // _sig 追加在键序末尾（与旧签名文件形态一致）；整体重写为 2 空格缩进 + 末尾换行
  delete parsed._sig;
  parsed._sig = { alg: 'ed25519', sig };
  fs.writeFileSync(RULES, JSON.stringify(parsed, null, 2) + '\n', 'utf8');
  console.log(`已签名: ${RULES}`);
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

const cmd = process.argv[2];
if (cmd === 'sign') sign();
else if (cmd === 'gen-fallback') genFallback();
else {
  console.error('用法: node tools/sign-cleanup-rules.mjs <sign|gen-fallback>');
  process.exit(1);
}
