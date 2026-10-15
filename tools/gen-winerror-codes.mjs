#!/usr/bin/env node
// gen-winerror-codes.mjs — 从 winerror-codes.source.mjs 生成 src-tauri/data/winerror-codes.json
//
// P1-A / Dism++ D-04b（2026-10-16）。源是人工策展的维护错误码人话表（含 curator 专用
// 的 tasks 元数据）；生成物是 Rust 编译期嵌入（include_str!）的运行期数据。
//
// 投影纪律：源里的 `tasks`（这条码常见于哪些维护任务）是**策展元数据**，运行期无消费者
// ——v3 约束「无消费者的字段禁止入库」，所以生成时投影掉，只落 code/title/detail。
// check-data-parity.mjs 的 P4b 组按同一投影对拍。
//
// 用法：node tools/gen-winerror-codes.mjs（改源后必须重跑；不重跑 = 注解用旧表）。

import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { WINERROR_CODES } from './winerror-codes.source.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'src-tauri', 'data', 'winerror-codes.json');

function fail(msg) {
  console.error(`✗ ${msg}`);
  process.exit(1);
}

if (!Array.isArray(WINERROR_CODES) || WINERROR_CODES.length === 0) fail('源表为空');
const seen = new Set();
for (const c of WINERROR_CODES) {
  if (!c || typeof c.code !== 'string' || !/^0x[0-9a-f]{8}$/.test(c.code))
    fail(`code 形如 0x + 8 位小写 hex：${JSON.stringify(c?.code)}`);
  if (seen.has(c.code)) fail(`code 重复：${c.code}`);
  seen.add(c.code);
  for (const k of ['title', 'detail']) {
    if (typeof c[k] !== 'string' || c[k].trim().length === 0) fail(`${c.code} 缺 ${k}`);
  }
}

const doc = {
  version: 1,
  _comment:
    '由 tools/gen-winerror-codes.mjs 从 tools/winerror-codes.source.mjs 生成，勿手改——改源后重跑生成器。维护错误码人话表（P1-A / Dism++ D-04b）。',
  codes: WINERROR_CODES.map((c) => ({ code: c.code, title: c.title, detail: c.detail })),
};

writeFileSync(OUT, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
console.log(`✓ 已落盘 ${OUT}（${doc.codes.length} 个错误码）`);
