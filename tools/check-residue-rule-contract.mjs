#!/usr/bin/env node
// check-residue-rule-contract.mjs — 卸载残留规则库契约门禁（U-1，2026-09-28）
//
// 对 src-tauri/data/uninstall-residue-rules.json 做 schema + 签名 + token 三层断言：
//   A. 根结构：rulesVersion（≥ 20260928 棘轮，只升不降）/ prov / rules 数组
//   B. 规则条目：id 唯一非空；displayName / publisher / uninstallKey 三条件组**至少两组非空**
//      （与 Rust 侧 residue_rules_hits 的「双条件命中」拍板口径对齐，单侧维护即红）
//   C. residue 条目：kind ∈ {folder, file, reg_key}；target 只允许已登记 %TOKEN% 或
//      盘符/UNC 绝对路径；note 非空（面板 reason 要展示）
//   D. 签名：Ed25519 验签通过（与 sign-cleanup-rules.mjs 同密钥同规范化）
//   E. 内置副本接线：src-tauri/src/commands/uninstall.rs 必须 include_str! 本文件
//
// 用法：node tools/check-residue-rule-contract.mjs
'use strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const RULES = path.join(ROOT, 'src-tauri', 'data', 'uninstall-residue-rules.json');
const UNINSTALL_RS = path.join(ROOT, 'src-tauri', 'src', 'commands', 'uninstall.rs');
const PRIV_KEY = path.join(os.homedir(), '.trim-signing', 'rules-ed25519-private.pem');
// token 登记表：新 token 必须先在这里登记、Rust 侧 expand_env_path 能展开才放行
const RESOLVABLE_TOKENS = [
  'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'PROGRAMFILES',
  'PROGRAMFILES(X86)', 'PROGRAMW6432', 'COMMONPROGRAMFILES', 'USERPROFILE',
  'WINDIR', 'SYSTEMROOT',
];
const MIN_VERSION = 20260928;

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 卸载残留规则库契约门禁 ===\n');

let raw = '';
let parsed = null;
try {
  raw = fs.readFileSync(RULES, 'utf8');
  parsed = JSON.parse(raw);
  check(true, '0. 规则文件可读且为合法 JSON');
} catch (e) {
  check(false, '0. 规则文件可读且为合法 JSON', e.message);
  console.log('\n存在未通过断言，门禁不通过');
  process.exit(1);
}

// ---- A. 根结构 ----
const ver = typeof parsed.rulesVersion === 'number' ? parsed.rulesVersion : 0;
check(ver >= MIN_VERSION, `A1. rulesVersion 棘轮 ≥ ${MIN_VERSION}（当前 ${ver}）`);
check(Array.isArray(parsed.prov) && parsed.prov.length > 0, 'A2. prov 来源登记非空');
check(
  parsed.prov.every((p) => p && typeof p.sourceClass === 'string' && p.sourceClass && typeof p.reviewedAt === 'string'),
  'A3. prov 条目含 sourceClass / reviewedAt',
);

// ---- B/C. 规则条目 ----
const rules = Array.isArray(parsed.rules) ? parsed.rules : [];
check(rules.length > 0, `B1. rules 非空（当前 ${rules.length} 条）`);
const ids = rules.map((r) => r && r.id);
check(ids.every((id) => typeof id === 'string' && id), 'B2. 每条规则 id 非空字符串');
check(new Set(ids).size === ids.length, 'B3. 规则 id 无重复');
const badCond = rules.filter((r) => {
  const groups = ['displayName', 'publisher', 'uninstallKey'];
  return groups.filter((g) => Array.isArray(r[g]) && r[g].length > 0).length < 2;
});
check(badCond.length === 0, 'B4. 三条件组至少两组非空（双条件拍板口径）',
  badCond.length ? `不达标: ${badCond.map((r) => r.id).join(', ')}` : '');

const targetOk = (t) => {
  if (typeof t !== 'string' || !t.trim()) return false;
  if (/^%[A-Za-z0-9_()]+%[\\/]/.test(t)) {
    // 从第 2 个字符起找闭合 %（开头的 % 会命中 indexOf('%')==0，切片恒空）
    const token = t.slice(1, t.indexOf('%', 1));
    return RESOLVABLE_TOKENS.includes(token);
  }
  return /^[A-Za-z]:[\\/]/.test(t) || t.startsWith('\\\\') || /^(HKCU|HKLM)\\/.test(t);
};
const badResidue = [];
for (const r of rules) {
  const residue = Array.isArray(r.residue) ? r.residue : [];
  if (!residue.length) badResidue.push(`${r.id}: residue 为空`);
  for (const e of residue) {
    if (!['folder', 'file', 'reg_key'].includes(e.kind)) badResidue.push(`${r.id}: kind 非法 ${e.kind}`);
    if (!targetOk(e.target)) badResidue.push(`${r.id}: target 未登记 token 或非绝对路径 ${e.target}`);
    if (typeof e.note !== 'string' || !e.note.trim()) badResidue.push(`${r.id}: note 缺失（target=${e.target}）`);
  }
}
check(badResidue.length === 0, 'C. residue 条目 kind/target/note 全部合规',
  badResidue.length ? `${badResidue.length} 处：${badResidue.slice(0, 5).join('；')}` : '');

// ---- D. 签名验签 ----
const body = {};
for (const [k, v] of Object.entries(parsed)) {
  if (k === '_sig') continue;
  body[k] = v;
}
const sigB64 = parsed._sig && parsed._sig.sig;
let sigOk = false;
let sigDetail = '';
if (!sigB64) {
  sigDetail = '缺少 _sig（先跑 node tools/sign-cleanup-rules.mjs sign --file src-tauri/data/uninstall-residue-rules.json）';
} else if (!fs.existsSync(PRIV_KEY)) {
  // 发布机才有私钥；公钥验签不依赖私钥——用文件内公钥证书不可得，退化为「内置公钥 PEM 校验」
  sigOk = false;
  sigDetail = '本机无私钥，无法做存在性对拍；改用公钥验签（见下）';
}
// 公钥验签（不依赖本机私钥）：内置公钥与 rules_signature.rs::RULES_PUBKEY_PEM 一致
const PUBKEY_PEM = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAQehWbhuKKCxcWOje/8AZXYN192Z3Ryi8+cQ6ENwXAtY=\n-----END PUBLIC KEY-----';
try {
  const pubKey = crypto.createPublicKey(PUBKEY_PEM);
  const ok = crypto.verify(null, Buffer.from(JSON.stringify(body), 'utf8'), pubKey, Buffer.from(sigB64 || '', 'base64'));
  sigOk = ok;
  if (!ok) sigDetail = '验签失败：内容与签名不匹配（篡改或未重新签名）';
} catch (e) {
  sigOk = false;
  sigDetail = `验签异常: ${e.message}`;
}
check(sigOk, 'D. Ed25519 验签通过', sigDetail);

// ---- E. Rust 侧接线 ----
const rsText = fs.readFileSync(UNINSTALL_RS, 'utf8');
check(
  rsText.includes('include_str!("../../data/uninstall-residue-rules.json")'),
  'E. uninstall.rs 内置副本已接线（include_str!）',
);

console.log(fail === 0 ? '\n门禁通过' : `\n${fail} 项未通过`);
process.exit(fail === 0 ? 0 : 1);
