#!/usr/bin/env node
// check-fixture-freshness.mjs —— 测试夹具新鲜度门禁（T1c-M05，v7.2 C09）
//
// 抓什么：tools/fixtures/ 与 src-tauri/data/ 里的生成型产物被**手改**（或源用例改后
// 忘了重跑生成器）。此前夹具与生成器之间没有任何对拍：手改一条 ok:false → ok:true，
// Rust 与 Node 两侧「独立实现、同口径」的隐含前提同时静默变绿——夹具是两侧共享的
// 口径真源，它烂了两边的断言一起烂，且无任何信号。
//
// 判据：生成器导出的构造函数（唯一实现）在内存里重算，与盘上产物**逐字节**比。
// 覆盖四件：residue-contract（gen-residue-fixture）/ winerror-codes（gen-winerror-codes，
// 产出在 src-tauri/data/）/ finder-delete-modes（gen-finder-delete-modes）/
// rules-canonical（tools/fixtures/rules-canonical/gen.mjs，签名规范化跨语言共享夹具）。
// protect-parity 夹具不在本门禁：它的内存重算由 check-data-parity P4 负责
// （psVectors 需真实 PS，T1c-M07 后 MUST_RUN 档位不含，重生成走显式路径）。
//
// 正向对照（§4.1）：比对器方向（isFresh）用正反合成样本钉住；「真夹具新鲜」这半腿
// 由主断言本身承担——破坏自证 = 手改任一夹具必须红（见 C09 交接文档 §4）。
//
// 用法：node tools/check-fixture-freshness.mjs
'use strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { gate } from './lib/gate.mjs';
import { fixtureText } from './gen-residue-fixture.mjs';
import { projectWinerrorDoc } from './gen-winerror-codes.mjs';
import { buildDoc } from './gen-finder-delete-modes.mjs';
import { buildDoc as buildRulesCanonicalDoc } from './fixtures/rules-canonical/gen.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const g = gate(import.meta.url);

const TARGETS = [
  { out: 'tools/fixtures/residue-contract.json', build: fixtureText },
  { out: 'src-tauri/data/winerror-codes.json', build: projectWinerrorDoc },
  { out: 'tools/fixtures/finder-delete-modes.json', build: buildDoc },
  { out: 'tools/fixtures/rules-canonical/cases.json', build: buildRulesCanonicalDoc },
];

/** 比对器（唯一实现）：主断言与正向对照共用，不许各写一份。 */
function isFresh(have, want) {
  return have === want;
}

// ---------- 正向对照：比对器方向必须钉住（反相 = 全绿假象） ----------
{
  const problems = [];
  if (!isFresh('x', 'x')) problems.push('比对器对相同字节判「不新鲜」（方向反了）');
  if (isFresh('x', 'y')) problems.push('比对器对不一致字节判「新鲜」（方向反了）');
  if (problems.length) {
    g.fail(`正向对照失败：夹具比对器不可信\n  ${problems.join('\n  ')}`);
    g.finish();
    process.exit(1);
  }
  g.ok('正向对照：比对器正反样本各命中（相同放行 / 不一致判红）');
}

// ---------- 真仓：三件产物 ⇄ 生成器导出逐字节比 ----------
const stale = [];
for (const { out, build } of TARGETS) {
  const want = build();
  const have = readFileSync(join(ROOT, out), 'utf8');
  if (!isFresh(have, want)) stale.push(`${out} 与生成器输出不一致（手改或改源未重跑；重跑对应 gen-*.mjs）`);
  else g.ok(`${out} 与生成器输出逐字节一致`);
}
if (stale.length) g.fail(`夹具新鲜度缺口：\n  ${stale.join('\n  ')}`);

g.finish('夹具新鲜度门禁全部通过');
