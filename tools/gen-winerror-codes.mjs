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
// 用法：node tools/gen-winerror-codes.mjs            重算并落盘（改源后必须重跑）
//       node tools/gen-winerror-codes.mjs --check    只读校验：盘上产物 ⇄ 投影逐字节比
//                                                    （T1c-M05：手改产物即红；门禁 import 同一实现）
//
// 投影函数导出（T1c-M05）：check-fixture-freshness.mjs import 同一份实现做逐字节对拍，
// 「投影口径」不再允许在门禁里抄第二份。

import { writeFileSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

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

/** 投影（唯一实现）：源表 → 运行期 JSON 文本（含末尾换行）。生成与校验共用。 */
export function projectWinerrorDoc() {
  const doc = {
    version: 1,
    _comment:
      '由 tools/gen-winerror-codes.mjs 从 tools/winerror-codes.source.mjs 生成，勿手改——改源后重跑生成器。维护错误码人话表（P1-A / Dism++ D-04b）。',
    codes: WINERROR_CODES.map((c) => ({ code: c.code, title: c.title, detail: c.detail })),
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

const IS_MAIN = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (IS_MAIN && process.argv.includes('--check')) {
  const want = projectWinerrorDoc();
  let have = '';
  try {
    have = readFileSync(OUT, 'utf8');
  } catch (e) {
    fail(`产物不可读：${e.message}`);
  }
  if (have !== want) {
    console.error('✗ 盘上 winerror-codes.json 与投影不一致——产物被手改或源改后未重跑。重跑：node tools/gen-winerror-codes.mjs');
    process.exit(1);
  }
  console.log(`✓ winerror-codes.json 与投影逐字节一致（${JSON.parse(want).codes.length} 个错误码）`);
  process.exit(0);
}

if (IS_MAIN) {
  writeFileSync(OUT, projectWinerrorDoc(), 'utf8');
  console.log(`✓ 已落盘 ${OUT}（${JSON.parse(projectWinerrorDoc()).codes.length} 个错误码）`);
}
