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

const totalOf = (m) => Object.values(m).reduce((a, o) => a + Object.values(o).reduce((x, y) => x + y, 0), 0);
const total = totalOf(current);

// ---- 扫描面地板（T1-K02 / v4-K08）----
// 扫描器失明的三种触发：SCAN_ROOTS 被搬/改名、APIS 名单没跟新增、stripRustComments 回归
// 把代码吞成空白。任一发生，结果逼近空集，而棘轮「数量下降不红」会静默放行 —— 一次
// --write 就能把基线永久清零，此后新增任何删除出口都不再判红。地板：0 文件直接拒；
// 有基线时命中数 < 30% 也拒（--write 同样拦：收紧基线是人工决定，不许一次收紧清账）。
const FLOOR_RATIO = 0.3;
const oldBaseline = existsSync(BASELINE_PATH) ? JSON.parse(readFileSync(BASELINE_PATH, 'utf8')) : null;
const oldTotal = oldBaseline ? totalOf(oldBaseline) : 0;
const floorViolation = () => {
  for (const root of SCAN_ROOTS) {
    if (!existsSync(root)) return `扫描根 ${relative(ROOT, root).replace(/\\/g, '/')} 不存在 ⇒ 该根下调用点整批静默消失（被搬/改名？）`;
  }
  if (scanned === 0) return '扫描 Rust 文件 0 个 ⇒ 扫描面失明';
  if (oldTotal > 0 && total < oldTotal * FLOOR_RATIO)
    return `命中 ${total} 处 < 基线 ${oldTotal} 处的 ${FLOOR_RATIO * 100}% ⇒ 疑似扫描器失明或批量退役`;
  return null;
};
/** 相对旧基线被移除/减少的调用点（首次生成无对比，返回空表） */
const removedVsBaseline = () => {
  const out = [];
  for (const api of Object.keys(oldBaseline || {})) {
    for (const f of Object.keys(oldBaseline[api])) {
      const was = oldBaseline[api][f];
      const now = current[api]?.[f] ?? 0;
      if (now < was) out.push(`${f} ${api} ${was}→${now}`);
    }
  }
  return out;
};

// ---- 基线 ----
if (process.argv.includes('--write')) {
  const removed = removedVsBaseline();
  const floor = floorViolation();
  if (floor) {
    console.error(`✗ --write 被扫描面地板拦下：${floor}`);
    if (removed.length) {
      console.error(`  本次将被移除的调用点 ${removed.length} 条（逐条核对属实后再重跑 --write）：`);
      for (const r of removed) console.error(`    · ${r}`);
    }
    process.exit(1);
  }
  writeFileSync(BASELINE_PATH, JSON.stringify(current, null, 2) + '\n', 'utf8');
  console.log(`✓ 基线已重算落盘：${BASELINE_PATH}（删除 API 调用点共 ${total} 处，文件 ${scanned} 个）`);
  if (removed.length) {
    console.log(`  本次收紧移除 ${removed.length} 条：`);
    for (const r of removed) console.log(`    · ${r}`);
  }
  process.exit(0);
}
const g = gate(import.meta.url);
if (!existsSync(BASELINE_PATH)) {
  g.fail('基线文件缺失，先跑一次 --write 生成');
  g.finish();
}
const baseline = oldBaseline;

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

const baseTotal = totalOf(baseline);
if (problems.length > 0) {
  g.fail(`删除原语调用点出现未登记变化：\n  ${problems.join('\n  ')}`);
}
const floor = floorViolation();
if (floor) {
  g.fail(`扫描面地板判红：${floor} —— 先人工核对是真实退役还是扫描器失明，再决定是否 --write`);
}
if (problems.length === 0 && !floor) {
  console.log(`✓ 删除原语调用点 ${total} 处（基线 ${baseTotal}），扫描 Rust 文件 ${scanned} 个，无未登记新增`);
}
if (shrinkHints.length) {
  console.log(`ℹ 有 ${shrinkHints.length} 处收敛（${shrinkHints.slice(0, 5).join('；')}${shrinkHints.length > 5 ? '…' : ''}）——确认无误后跑 --write 收紧基线（只减不增的棘轮方向）`);
}

g.finish('check-delete-callsites: 全部通过');
