#!/usr/bin/env node
// check-optimizer-schema-sync.mjs —— 优化域跨端标量 ⇄ rule-schema.optimizer（P2-C / D4，2026-10-26）
//
// schema 是单源；Rust 常量、渲染层常量、数据层取值、侧表版本各自是对端副本。
// 本门禁只对拍**标量/类型清单**，item 完整形状仍由优化域契约门禁与 catalog.rs 管。
// 为什么要有它：WU_PAUSE_MAX_DAYS 在两处各写一份、注释只写「改一处必须同步」——
// 那是靠人记；风险档清单与侧表 schemaVer 同样没有对拍点。
//
// 用法：node tools/check-optimizer-schema-sync.mjs
'use strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadSchema } from './rule-schema.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (...p) => readFileSync(join(ROOT, ...p), 'utf8');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

/** 纯判定器：真仓与合成样本共用同一实现（AGENTS §4.1） */
function syncProblems({ schemaOpt, rustDays, jsDays, jsRiskKeys, dataRisks, sideVer }) {
  const out = [];
  const wantDays = schemaOpt?.limits?.wuPauseMaxDays;
  if (rustDays !== wantDays) out.push(`Rust WU_PAUSE_MAX_DAYS=${rustDays} ≠ schema ${wantDays}`);
  if (jsDays !== wantDays) out.push(`渲染层 WU_PAUSE_MAX_DAYS=${jsDays} ≠ schema ${wantDays}`);
  const wantRisks = [...(schemaOpt?.riskLevels || [])].sort().join(',');
  const gotRisks = [...jsRiskKeys].sort().join(',');
  if (wantRisks !== gotRisks) out.push(`RISK_TEXT 键集 ${gotRisks} ≠ schema ${wantRisks}`);
  const badRisks = [...new Set(dataRisks)].filter((r) => !(schemaOpt?.riskLevels || []).includes(r));
  if (badRisks.length) out.push(`目录出现未登记的 risk：${badRisks.join('、')}`);
  if (sideVer === undefined) out.push('侧表 schemaVer 未解析到');
  else if (sideVer !== schemaOpt?.sideTableSchemaVer) out.push(`侧表 schemaVer=${sideVer} ≠ schema ${schemaOpt?.sideTableSchemaVer}`);
  return out;
}

console.log('=== 优化域标量 ⇄ 契约表同步门禁 ===\n');

// ---- 正向对照：齐全放行，五类漂移各自判红 ----
{
  const base = {
    schemaOpt: { limits: { wuPauseMaxDays: 35 }, riskLevels: ['low', 'medium', 'high'], sideTableSchemaVer: 1 },
    rustDays: 35,
    jsDays: 35,
    jsRiskKeys: ['low', 'medium', 'high'],
    dataRisks: ['low', 'high'],
    sideVer: 1,
  };
  check(syncProblems(base).length === 0, '对照：齐全样本放行');
  check(syncProblems({ ...base, rustDays: 30 }).some((x) => x.includes('Rust')), '对照：Rust 常量漂移必须判红');
  check(syncProblems({ ...base, jsDays: 30 }).some((x) => x.includes('渲染层')), '对照：渲染层常量漂移必须判红');
  check(syncProblems({ ...base, jsRiskKeys: ['low', 'high'] }).some((x) => x.includes('RISK_TEXT')), '对照：风险档清单漂移必须判红');
  check(syncProblems({ ...base, dataRisks: ['low', 'critical'] }).some((x) => x.includes('critical')), '对照：目录越档 risk 必须判红');
  check(syncProblems({ ...base, sideVer: 2 }).some((x) => x.includes('schemaVer')), '对照：侧表版本漂移必须判红');
}

// ---- 真仓 ----
const schema = loadSchema();
const opt = schema.optimizer;
if (!opt || typeof opt !== 'object') {
  console.error('✗ 契约表缺 optimizer 段（tools/rule-schema.json）');
  process.exit(1);
}
const applyRs = read('src-tauri', 'src', 'commands', 'optimizer', 'apply.rs');
const optJs = read('src', 'scripts', 'optimizer.js');
const subJson = JSON.parse(read('src-tauri', 'data', 'optimizer-subitems.json'));
const runtime = JSON.parse(read('src-tauri', 'data', 'optimizer-runtime.json'));
const rustDays = Number((applyRs.match(/WU_PAUSE_MAX_DAYS:\s*i64\s*=\s*(\d+)/) || [])[1]);
const jsDays = Number((optJs.match(/const WU_PAUSE_MAX_DAYS\s*=\s*(\d+)/) || [])[1]);
const riskBlock = (optJs.match(/const RISK_TEXT\s*=\s*\{([^}]*)\}/) || [])[1] || '';
const jsRiskKeys = [...riskBlock.matchAll(/(\w+)\s*:/g)].map((m) => m[1]);
const dataRisks = runtime.map((x) => x.risk).filter(Boolean);
const problems = syncProblems({ schemaOpt: opt, rustDays, jsDays, jsRiskKeys, dataRisks, sideVer: subJson.schemaVer });

check(
  Array.isArray(opt.riskLevels) && opt.riskLevels.length >= 3
    && typeof opt.sideTableSchemaVer === 'number'
    && typeof opt.limits?.wuPauseMaxDays === 'number',
  '1. optimizer 段形状（riskLevels / sideTableSchemaVer / limits.wuPauseMaxDays）',
);
check(
  problems.length === 0,
  `2. 跨端标量 ⇄ schema（Rust ${rustDays} / JS ${jsDays} / risk 键 ${jsRiskKeys.length} / 目录 ${dataRisks.length} 项 / 侧表 v${subJson.schemaVer}）`,
  problems.join('；'),
);

console.log('');
if (fail > 0) {
  console.error(`check-optimizer-schema-sync: ${fail} 组断言未通过`);
  process.exit(1);
}
console.log('check-optimizer-schema-sync: 全部通过');
