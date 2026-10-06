#!/usr/bin/env node
// check-delete-callsites.mjs —— 删除原语调用点棘轮（v2-L4P-31 / E-7、B-9，2026-10-02）
//
// 抓什么：remove_file / remove_dir / remove_dir_all / RegDeleteTreeW / RegDeleteValueW /
// RegDeleteKeyW / RegDeleteKeyExW / DeleteFileW 的**真实调用点**（先剥注释与字符串字面量，
// 文本提及数不算数——L4 RPT-02 的教训：54/32 那类「文本提及数」把注释、函数名、文档全算进去）。
// 范围：src-tauri/src + native-scanner/src（后者不在 workspace，主仓 cargo test 扫不到）。
//
// 棘轮口径：
//   · 某文件首次出现某删除 API 调用 → 红（新出口必须走 review 并登记进基线）；
//   · 某文件调用点数超过基线 → 红；
//   · 数量下降不红（收敛是好事），提示用 --write 收紧基线即可。
// 判红自证：临时加一行 remove_file → 红。
//
// 用法：node tools/check-delete-callsites.mjs [--write]
'use strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { walkRs } from './lib/fs-walk.mjs';
import { gate } from './lib/gate.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE_PATH = join(ROOT, 'tools', 'fixtures', 'delete-callsites-baseline.json');
const SCAN_ROOTS = [join(ROOT, 'src-tauri', 'src'), join(ROOT, 'native-scanner', 'src')];
const APIS = ['remove_file', 'remove_dir_all', 'remove_dir', 'DeleteFileW', 'RegDeleteTreeW', 'RegDeleteValueW', 'RegDeleteKeyW', 'RegDeleteKeyExW'];

/** 剥 Rust 注释与字符串字面量（与 check-delete-exits 的 stripRustComments 同口径） */
function stripRustComments(src) {
  let out = '', i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i], d = i + 1 < n ? src[i + 1] : '';
    if (c === '/' && d === '/') { while (i < n && src[i] !== '\n') i++; continue; }
    if (c === '/' && d === '*') {
      let depth = 1; i += 2;
      while (i < n && depth > 0) {
        if (src[i] === '/' && src[i + 1] === '*') { depth++; i += 2; }
        else if (src[i] === '*' && src[i + 1] === '/') { depth--; i += 2; }
        else i++;
      }
      out += ' ';
      continue;
    }
    if (c === '"') {
      i++;
      while (i < n && src[i] !== '"') { if (src[i] === '\\') i++; i++; }
      i++; out += '""';
      continue;
    }
    if (c === 'r' && (d === '"' || d === '#')) {
      let hashes = 0, j = i + 1;
      while (src[j] === '#') { hashes++; j++; }
      if (src[j] === '"') {
        const close = '"' + '#'.repeat(hashes);
        const end = src.indexOf(close, j + 1);
        i = end < 0 ? n : end + close.length;
        out += '""';
        continue;
      }
    }
    if (c === "'") {
      const m = /^'(\\.|[^'\\])'/.exec(src.slice(i, i + 5));
      if (m) { i += m[0].length; out += "''"; continue; }
      out += c; i++;
      continue;
    }
    out += c; i++;
  }
  return out;
}

// ---- 现算调用点：api → { "rel/path.rs": count } ----
const current = {};
let scanned = 0;
for (const root of SCAN_ROOTS) {
  for (const f of walkRs(root)) {
    scanned++;
    const clean = stripRustComments(readFileSync(f, 'utf8'));
    const rel = relative(ROOT, f).replace(/\\/g, '/');
    for (const api of APIS) {
      const re = new RegExp(`\\b${api}\\s*\\(`, 'g');
      const n = [...clean.matchAll(re)].length;
      if (n > 0) {
        current[api] = current[api] ?? {};
        current[api][rel] = (current[api][rel] ?? 0) + n;
      }
    }
  }
}

// ---- 基线 ----
if (process.argv.includes('--write')) {
  writeFileSync(BASELINE_PATH, JSON.stringify(current, null, 2) + '\n', 'utf8');
  const total = Object.values(current).reduce((a, o) => a + Object.values(o).reduce((x, y) => x + y, 0), 0);
  console.log(`✓ 基线已重算落盘：${BASELINE_PATH}（删除 API 调用点共 ${total} 处，文件 ${scanned} 个）`);
  process.exit(0);
}
const g = gate(import.meta.url);
if (!existsSync(BASELINE_PATH)) {
  g.fail('基线文件缺失，先跑一次 --write 生成');
  g.finish();
}
const baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf8'));

const problems = [];
const shrinkHints = [];
for (const api of APIS) {
  const cur = current[api] ?? {};
  const base = baseline[api] ?? {};
  // 新文件出现调用点 → 红
  for (const f of Object.keys(cur)) {
    if (!(f in base)) problems.push(`${f} 新出现 ${api} 调用点 ${cur[f]} 处（新删除出口必须 review 后进基线）`);
    else if (cur[f] > base[f]) problems.push(`${f} 的 ${api} 调用点 ${base[f]} → ${cur[f]}（新增须 review）`);
    else if (cur[f] < base[f]) shrinkHints.push(`${f} ${api} ${base[f]}→${cur[f]}`);
  }
  // 基线里已消失的文件/条目：收敛，提示收紧基线
  for (const f of Object.keys(base)) {
    if (!(f in cur)) shrinkHints.push(`${f} ${api} ${base[f]}→0`);
  }
}

const total = Object.values(current).reduce((a, o) => a + Object.values(o).reduce((x, y) => x + y, 0), 0);
const baseTotal = Object.values(baseline).reduce((a, o) => a + Object.values(o).reduce((x, y) => x + y, 0), 0);
if (problems.length === 0) {
  console.log(`✓ 删除原语调用点 ${total} 处（基线 ${baseTotal}），扫描 Rust 文件 ${scanned} 个，无未登记新增`);
} else {
  g.fail(`删除原语调用点出现未登记变化：\n  ${problems.join('\n  ')}`);
}
if (shrinkHints.length) {
  console.log(`ℹ 有 ${shrinkHints.length} 处收敛（${shrinkHints.slice(0, 5).join('；')}${shrinkHints.length > 5 ? '…' : ''}）——确认无误后跑 --write 收紧基线（只减不增的棘轮方向）`);
}

g.finish('check-delete-callsites: 全部通过');
