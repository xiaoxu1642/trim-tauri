#!/usr/bin/env node
// check-layering.mjs —— 分层方向门禁（v2-L4P-41 / D-1，2026-10-02）
//
// 抓什么：engine / security / pwsh 三层是**下层**，不得反向引用 `crate::commands::`。
// 实测根因：reg_backup.rs 曾调 `crate::commands::runtimes::sha256_file`（2 处，2026-10-02
// 已下沉 engine/hash.rs 清零）。下层引用上层 = 依赖方向倒挂， commands 层的任何改动都会
// 波及引擎层，解耦永远无从谈起。
// 判红：注释里的字样不豁免（注释写 API 全名同样会误导 grep 式检索），但 0 命中时
// 必须有正向对照防恒绿——本仓至少存在一处合法的 `crate::commands::`（commands 层自身内部）。
'use strict';
import { readFileSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { walkRs } from './lib/fs-walk.mjs';
import { gate } from './lib/gate.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src-tauri', 'src');
const LOWER_LAYERS = [
  { dir: 'engine', label: 'engine/**' },
  { dir: 'security', label: 'security/**' },
  { dir: 'pwsh', label: 'pwsh/**' },
];

const g = gate(import.meta.url);
const hits = [];
let scanned = 0;
for (const { dir, label } of LOWER_LAYERS) {
  for (const f of walkRs(join(SRC, dir))) {
    scanned++;
    const rel = relative(SRC, f).replace(/\\/g, '/');
    const lines = readFileSync(f, 'utf8').split(/\r?\n/);
    lines.forEach((line, i) => {
      if (line.includes('crate::commands::')) {
        hits.push(`${rel}:${i + 1}`);
      }
    });
  }
}
if (hits.length === 0) {
  console.log(`✓ 分层方向：下层（${LOWER_LAYERS.map((l) => l.label).join(' / ')}，共 ${scanned} 文件）零 crate::commands:: 反向引用`);
} else {
  g.fail(`分层方向违规：下层不得引用 crate::commands:: —— ${hits.join(', ')}`);
}

// 正向对照（防恒绿）：commands 层自身必须仍存在 crate::commands:: 引用（同层互调是合法的），
// 若连它都搜不到，说明符号改名/扫描前提失效，本门禁要跟着改而不是静默变绿。
const cmdHits = walkRs(join(SRC, 'commands')).filter((f) =>
  readFileSync(f, 'utf8').includes('crate::commands::')).length;
if (cmdHits > 0) {
  console.log(`✓ 正向对照：commands 层自身仍存在 ${cmdHits} 个 crate::commands:: 文件（扫描器活着）`);
} else {
  g.fail('正向对照失败：commands 层搜不到任何 crate::commands::——符号可能已改名，请复核本门禁');
}

g.finish('check-layering: 全部通过');
