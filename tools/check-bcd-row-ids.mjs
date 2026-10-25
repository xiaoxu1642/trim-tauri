#!/usr/bin/env node
// check-bcd-row-ids.mjs —— 永劫 BCD 行 id 四端对拍（P2-E / P3 卡 A6-M02，2026-10-26）
//
// 签名面板 JSON 是行 id 的权威，但「预勾集 / 渲染行 / 查询行 / 目标表分支」由另外三处
// 代码字面量决定。四端今天恰好相等，却没有任何门禁对拍：单端新增一个 id ⇒
// JS 默认勾选、Rust 体检不覆盖、row_targets 走 `_ => Vec::new()`，全部静默。
//
// 四端：
//   ① src-tauri/data/optimizer-nara-panel.json 的 sections[bcd].items（已签名，字符串数组）
//   ② src/scripts/optimizer.js 的 NARA_ROW_LABEL 键
//   ③ src-tauri/src/commands/optimizer/bcd.rs 的 ALL_ROW_IDS
//   ④ 同文件 row_targets 的 match 分支（`"nara_bcd_*" => vec![...]`）
//
// 判据：四集合两两相等；任一端解析为空/失败 ⇒ fail-closed（空集不许当相等）。
// 用法：node tools/check-bcd-row-ids.mjs
'use strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PANEL = join(ROOT, 'src-tauri', 'data', 'optimizer-nara-panel.json');
const JS = join(ROOT, 'src', 'scripts', 'optimizer.js');
const BCD = join(ROOT, 'src-tauri', 'src', 'commands', 'optimizer', 'bcd.rs');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

/** 纯判定器：真仓与合成样本共用（AGENTS §4.1） */
function bcdSetProblems({ panel, js, all, arms }) {
  const out = [];
  const sets = { panel, js, all, arms };
  for (const [k, v] of Object.entries(sets)) {
    if (!Array.isArray(v) || v.length === 0) out.push(`${k} 端解析为空（fail-closed，不算相等）`);
  }
  const labels = { panel: '面板 JSON', js: 'NARA_ROW_LABEL', all: 'ALL_ROW_IDS', arms: 'row_targets' };
  const keys = Object.keys(sets);
  for (let i = 0; i < keys.length; i++) {
    for (let j = i + 1; j < keys.length; j++) {
      const a = new Set(sets[keys[i]]);
      const b = new Set(sets[keys[j]]);
      const onlyA = [...a].filter((x) => !b.has(x));
      const onlyB = [...b].filter((x) => !a.has(x));
      if (onlyA.length) out.push(`${labels[keys[i]]} 多出：${onlyA.join('、')}`);
      if (onlyB.length) out.push(`${labels[keys[j]]} 多出：${onlyB.join('、')}`);
    }
  }
  return out;
}

// ---------- 正向对照 ----------
{
  const clean = { panel: ['a', 'b'], js: ['a', 'b'], all: ['a', 'b'], arms: ['a', 'b'] };
  check(bcdSetProblems(clean).length === 0, '对照：四端相等放行');
  check(bcdSetProblems({ ...clean, js: ['a'] }).length > 0, '对照：单端缺一项必须判红');
  check(bcdSetProblems({ ...clean, arms: ['a', 'b', 'c'] }).length > 0, '对照：单端多一项必须判红');
  check(bcdSetProblems({ ...clean, panel: [] }).length > 0, '对照：解析为空必须判红（不许空集放行）');
}

// ---------- 真仓 ----------
console.log('');
for (const f of [PANEL, JS, BCD]) {
  if (!existsSync(f)) {
    console.error(`✗ 输入缺失：${f}（本节未校验，不是通过）`);
    process.exit(1);
  }
}
const panelJson = JSON.parse(readFileSync(PANEL, 'utf8'));
const bcdSection = (panelJson.sections || []).find((s) => s.id === 'bcd');
const panelIds = Array.isArray(bcdSection?.items) ? bcdSection.items.filter((x) => typeof x === 'string') : [];

const jsText = readFileSync(JS, 'utf8');
const jsBlock = (jsText.match(/NARA_ROW_LABEL\s*=\s*\{([\s\S]*?)\n\s*\};/) || [])[1] || '';
const jsIds = [...jsBlock.matchAll(/(nara_bcd_[a-z0-9_]+)\s*:/g)].map((m) => m[1]);

const bcdText = readFileSync(BCD, 'utf8');
const allBlock = (bcdText.match(/ALL_ROW_IDS[^\[]*\[([\s\S]*?)\];/) || [])[1] || '';
const allIds = [...allBlock.matchAll(/"(nara_bcd_[a-z0-9_]+)"/g)].map((m) => m[1]);
const armsBlock = (bcdText.match(/fn\s+row_targets\([\s\S]*?\n\}/) || [])[0] || '';
const armIds = [...armsBlock.matchAll(/"(nara_bcd_[a-z0-9_]+)"\s*=>/g)].map((m) => m[1]);

const problems = bcdSetProblems({ panel: panelIds, js: jsIds, all: allIds, arms: armIds });
check(
  panelIds.length >= 5 && jsIds.length >= 5 && allIds.length >= 5 && armIds.length >= 5 && problems.length === 0,
  `四端行 id 相等（面板 ${panelIds.length} / JS ${jsIds.length} / ALL ${allIds.length} / arms ${armIds.length}）`,
  problems.join('；'),
);

console.log('');
if (fail > 0) {
  console.error(`check-bcd-row-ids: ${fail} 组断言未通过`);
  process.exit(1);
}
console.log('check-bcd-row-ids: 全部通过');
