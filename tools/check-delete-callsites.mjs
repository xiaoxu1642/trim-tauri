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
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { walkRs } from './lib/fs-walk.mjs';
import { gate } from './lib/gate.mjs';
import { DELETE_APIS } from './lib/delete-apis.mjs';
import { blankNonCode, splitFunctions } from './lib/src-scan.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE_PATH = join(ROOT, 'tools', 'fixtures', 'delete-callsites-baseline.json');
const SCAN_ROOTS = [join(ROOT, 'src-tauri', 'src'), join(ROOT, 'native-scanner', 'src')];
// T1a-M07：名单唯一真源见 tools/lib/delete-apis.mjs（与 check-delete-exits 共用）。
const APIS = DELETE_APIS;
const GENERATOR_VERSION = 'p1-04e-v1';
const CLEANUP_OVERLAP_GENERATOR = 'p1-04e-overlap-v1';
const CLEANUP_OVERLAP_FIXTURE = join(ROOT, 'tools', 'fixtures', 'cleanup-overlaps.json');

const callKey = (call) => `${call.api}\n${call.file}\n${call.fn}\n${call.anchor}`;
const inputHash = (calls) => createHash('sha256').update(JSON.stringify(calls)).digest('hex').slice(0, 16);

/** 文件+函数+API+行锚点的现算台账；按稳定键排序后才算输入哈希。 */
function collectCallDetails(file) {
  const clean = blankNonCode(readFileSync(file, 'utf8'));
  const rel = relative(ROOT, file).replace(/\\/g, '/');
  const aliases = deleteAliases(clean);
  const fns = splitFunctions(clean.replace(/[^\x00-\x7F]/g, 'x'), 'rs');
  const records = [];
  for (const api of APIS) {
    const names = [api, ...[...aliases.entries()].filter(([, target]) => target === api).map(([alias]) => alias)];
    for (const name of names) {
      for (const found of clean.matchAll(new RegExp(`\\b${name}\\s*\\(`, 'g'))) {
        const fn = [...fns].reverse().find((candidate) => candidate.start <= found.index && found.index < candidate.end);
        const fnMatch = fn ? /fn\s+([^\s(<{]+)/u.exec(clean.slice(fn.start, fn.bodyStart)) : null;
        const lineStart = clean.lastIndexOf('\n', found.index) + 1;
        let lineEnd = clean.indexOf('\n', found.index);
        if (lineEnd < 0) lineEnd = clean.length;
        records.push({
          api,
          file: rel,
          fn: fnMatch ? fnMatch[1] : '(top-level)',
          anchor: clean.slice(lineStart, lineEnd).trim().replace(/\s+/g, ' '),
        });
      }
    }
  }
  return records;
}

function deleteAliases(clean) {
  const aliases = new Map();
  for (const api of APIS) {
    for (const m of clean.matchAll(new RegExp(`\\b(?:use\\s+[^;]*?\\b${api}\\s+as\\s+|let\\s+)([A-Za-z_][A-Za-z0-9_]*)\\s*(?:=[^;]*\\b${api}\\s*;|;)`, 'g'))) {
      aliases.set(m[1], api);
    }
  }
  return aliases;
}


// ---- 现算调用点：api → { "rel/path.rs": count } ----
const current = {};
const currentDetails = [];
let scanned = 0;
for (const root of SCAN_ROOTS) {
  for (const f of walkRs(root)) {
    scanned++;
    const clean = blankNonCode(readFileSync(f, 'utf8'));
    const rel = relative(ROOT, f).replace(/\\/g, '/');
    const aliases = deleteAliases(clean);
    for (const api of APIS) {
      const re = new RegExp(`\\b${api}\\s*\\(`, 'g');
      const n = [...clean.matchAll(re)].length;
      const aliasHits = [...aliases.entries()]
        .filter(([, target]) => target === api)
        .reduce((sum, [alias]) => sum + [...clean.matchAll(new RegExp(`\\b${alias}\\s*\\(`, 'g'))].length, 0);
      const hits = n + aliasHits;
      if (hits > 0) {
        current[api] = current[api] ?? {};
        current[api][rel] = (current[api][rel] ?? 0) + hits;
      }
    }
    currentDetails.push(...collectCallDetails(f));
  }
}
currentDetails.sort((a, b) => callKey(a).localeCompare(callKey(b)));

const aliasBad = deleteAliases('use std::fs::remove_file as rm; let f = std::fs::remove_file; rm(p); f(q);');
if (aliasBad.get('rm') !== 'remove_file' || aliasBad.get('f') !== 'remove_file') {
  console.error('✗ 正向对照失败：删除 API 别名表没有抓到 use-as / let 绑定');
  process.exit(1);
}
const detailControl = collectCallDetails(join(ROOT, 'src-tauri', 'src', 'commands', 'appearance.rs'));
if (detailControl.length === 0 || detailControl.some((call) => !call.file || !call.fn || !call.api || !call.anchor)) {
  console.error('✗ 正向对照失败：调用点明细未记录文件+函数+API+行锚点');
  process.exit(1);
}
console.log('对照: 删除原语别名两类样本必被现算调用点捕获');

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
  // v5 批次 9（门禁候选 3，6a8f02b 先例）：收紧也是棘轮操作——一次 --write 抹掉
  // 大量基线条目，会把「无关批次顺手放宽」伪装成「本批收敛」。收紧 > 3 条时必须
  // 显式加 --confirm-shrink 重新落盘，且逐条点名（下方 removed 列表即点名）。
  if (removed.length > 3 && !process.argv.includes('--confirm-shrink')) {
    console.error(`✗ --write 将收紧 ${removed.length} 条基线（> 3）——若确属本批收敛，重跑加 --confirm-shrink：`);
    for (const r of removed) console.error(`    · ${r}`);
    process.exit(1);
  }
  const body = {
    _说明: '删除原语调用点棘轮基线：由 `node tools/check-delete-callsites.mjs --write` 现算回填，禁止手抄。顶层 api→file→count 保留棘轮口径，details 记录文件/函数/API/行锚点，meta 记录生成器版本与输入哈希。',
    meta: {
      generatorVersion: GENERATOR_VERSION,
      inputHash: inputHash(currentDetails),
      callCount: currentDetails.length,
      cleanupCallCount: currentDetails.filter((call) => call.file.includes('cleanup')).length,
    },
    details: currentDetails,
    ...current,
  };
  writeFileSync(BASELINE_PATH, JSON.stringify(body, null, 2) + '\n', 'utf8');
  console.log(`✓ 基线已重算落盘：${BASELINE_PATH}（删除 API 调用点共 ${total} 处，文件 ${scanned} 个，明细 ${currentDetails.length} 条）`);
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

const detailProblems = [];
if (!baseline.meta || baseline.meta.generatorVersion !== GENERATOR_VERSION) {
  detailProblems.push(`生成器版本缺失或不一致（应为 ${GENERATOR_VERSION}）——重跑 --write 登记本次调用点明细`);
}
if (!baseline.meta || !Number.isInteger(baseline.meta.callCount) || baseline.meta.callCount !== currentDetails.length) {
  detailProblems.push(`明细条数元数据与现算不一致（登记 ${baseline.meta?.callCount ?? '缺失'} / 现算 ${currentDetails.length}）——重跑 --write`);
}
if (!Array.isArray(baseline.details)) {
  detailProblems.push('details 明细缺失——重跑 --write 记录文件+函数+API+行锚点');
} else {
  const baselineDetails = [...baseline.details].sort((a, b) => callKey(a).localeCompare(callKey(b)));
  if (inputHash(baselineDetails) !== inputHash(currentDetails)) {
    detailProblems.push(`details 输入哈希与现算不一致（登记 ${baseline.meta?.inputHash ?? '缺失'} / 现算 ${inputHash(currentDetails)}）——API 替换、改函数或挪锚点都必须 --write 重新登记`);
  }
  const nowKeys = new Set(currentDetails.map(callKey));
  for (const call of baselineDetails) {
    if (!nowKeys.has(callKey(call))) {
      detailProblems.push(`登记明细已漂移：${call.file}::${call.fn} ${call.api}「${call.anchor}」`);
    }
  }
}
if (detailProblems.length > 0) {
  g.fail(`删除调用点台账失真：\n  ${detailProblems.join('\n  ')}`);
}

const overlapProblems = [];
if (!existsSync(CLEANUP_OVERLAP_FIXTURE)) {
  overlapProblems.push(`${relative(ROOT, CLEANUP_OVERLAP_FIXTURE).replace(/\\/g, '/')} 不存在（fixture 被删，覆盖台账失明）`);
} else {
  const overlap = JSON.parse(readFileSync(CLEANUP_OVERLAP_FIXTURE, 'utf8'));
  if (overlap.meta?.generatorVersion !== CLEANUP_OVERLAP_GENERATOR || !/^[0-9a-f]{16}$/.test(overlap.meta?.inputHash ?? '')) {
    overlapProblems.push(`cleanup-overlaps fixture 缺生成器版本或输入哈希（应为 ${CLEANUP_OVERLAP_GENERATOR} + 16 位 hex）——重跑 --emit-overlaps 现算回填`);
  }
}
if (overlapProblems.length > 0) {
  g.fail(`派生 fixture 元数据缺口：\n  ${overlapProblems.join('\n  ')}`);
}

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

const baseCount = APIS.reduce((sum, api) => {
  const group = baseline[api];
  if (!group || typeof group !== 'object' || Array.isArray(group)) return sum;
  return sum + Object.values(group).reduce((inner, count) => inner + count, 0);
}, 0);
if (problems.length > 0) {
  g.fail(`删除原语调用点出现未登记变化：\n  ${problems.join('\n  ')}`);
}
const floor = floorViolation();
if (floor) {
  g.fail(`扫描面地板判红：${floor} —— 先人工核对是真实退役还是扫描器失明，再决定是否 --write`);
}
if (problems.length === 0 && !floor) {
  console.log(`✓ 删除原语调用点 ${total} 处（基线 ${baseCount}），扫描 Rust 文件 ${scanned} 个，明细 ${currentDetails.length} 条，无未登记新增`);
}
if (shrinkHints.length) {
  console.log(`ℹ 有 ${shrinkHints.length} 处收敛（${shrinkHints.slice(0, 5).join('；')}${shrinkHints.length > 5 ? '…' : ''}）——确认无误后跑 --write 收紧基线（只减不增的棘轮方向）`);
}

g.finish('check-delete-callsites: 全部通过');
