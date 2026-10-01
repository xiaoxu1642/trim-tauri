#!/usr/bin/env node
// check-positive-controls.mjs —— 找违规型断言的正向对照管辖门禁
// （v2-L4P-44 / E-8、E-15，2026-10-02）
//
// 抓什么：「找违规型」门禁有两条失效方向——① 扫描前提失效（目录改名、正则过时）
// 导致 0 命中恒绿；② 判定器被误改坏（如正则加了个永远为 false 的分支）。两者都
// 不会让门禁本身报错，防线在无声中消失。范本是 check-cleanup-rule-contract 的
// 37 条反例自检：判定器必须能对**已知违规样本**判红，✓ 才可信。
//
// 本门禁断言：登记在案的每个找违规型门禁必须 (a) 内置 POSITIVE_CONTROLS 自检块、
// (b) 实际执行 exit 0（自检与扫描都在门禁自身内跑通）。新增找违规型门禁不登记即红。
'use strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// 需要正向对照的找违规型门禁清单（新增必须登记，带理由）
const REGISTRY = [
  { file: 'check-delete-exits.mjs', reason: '删除出口枚举：剥离/命中两向自检' },
  { file: 'check-escape-delegation.mjs', reason: 'escape 委托：非委托样本自检' },
  { file: 'check-html-contract.mjs', reason: 'HTML 合同：内联 script 样本自检' },
  { file: 'check-cleanup-rule-contract.mjs', reason: '规则契约：37 条反例自检（既有范本）' },
];

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 正向对照管辖门禁 ===\n');
const missingSelfTest = [];
const brokenRun = [];
for (const e of REGISTRY) {
  const p = join(ROOT, 'tools', e.file);
  let text;
  try {
    text = readFileSync(p, 'utf8');
  } catch {
    brokenRun.push(`${e.file} 文件不存在`);
    continue;
  }
  if (!text.includes('POSITIVE_CONTROLS') && !text.includes('反例') && !text.includes('正向对照') && !text.includes('判定器自检')) {
    missingSelfTest.push(`${e.file}（${e.reason}）`);
    continue;
  }
  const r = spawnSync(process.execPath, [p], { cwd: ROOT, encoding: 'utf8' });
  if (r.status !== 0) brokenRun.push(`${e.file} 执行 exit ${r.status}`);
}
check(
  missingSelfTest.length === 0,
  `1. ${REGISTRY.length} 个找违规型门禁均内置正向对照自检`,
  missingSelfTest.join('；'),
);
check(
  brokenRun.length === 0,
  '2. 全部登记门禁实际执行 exit 0（自检在门禁内随跑随验）',
  brokenRun.join('；'),
);

if (fail > 0) {
  console.error('check-positive-controls: 存在缺口');
  process.exit(1);
}
console.log('check-positive-controls: 全部通过');
