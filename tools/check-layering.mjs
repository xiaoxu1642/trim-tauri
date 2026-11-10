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
import { blankNonCode } from './lib/src-scan.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src-tauri', 'src');
const LOWER_LAYERS = [
  { dir: 'engine', label: 'engine/**' },
  { dir: 'security', label: 'security/**' },
  { dir: 'pwsh', label: 'pwsh/**' },
  // T1a-L04：diag 也是下层模块（不依赖 commands），此前不在射程。
  { dir: 'diag', label: 'diag/**' },
];

const g = gate(import.meta.url);
// v6-P2：判定器抽成纯函数 + 合成样本自检（T1 假绿扫尾）——「下层不得引用
// crate::commands::」此前只有真仓扫描，判据本身恒绿无对照。
//
// T1a-L05：旧判据只认 `crate::commands::` 这个**带尾双冒号**的字面。两条绕过形态：
//   ① `use crate::commands;`（短路径，后面不再接 `::`）；
//   ② `use crate::commands as c;` + `c::foo()`（别名，行内根本没有 crate::commands）。
// 现在：判定器吃「本文件现算的别名表」，间接引用同样判红。
const RE_DIRECT = /\bcrate::commands\b/;
function layeringHit(line, aliases = []) {
  if (RE_DIRECT.test(line)) return true;
  return aliases.some((a) => new RegExp(`\\b${a}\\s*::`).test(line));
}
/** 从文件里现算 `use crate::commands as <alias>;` 的别名表（剥注释后再找）。 */
function commandAliases(text) {
  const clean = blankNonCode(text, 'rs');
  return [...clean.matchAll(/\buse\s+crate::\{?\s*commands\s+as\s+([A-Za-z_][A-Za-z0-9_]*)\s*\}?\s*;/g)].map((m) => m[1]);
}
{
  // 正向对照五件：代码行必中；**注释行也必中**（口径明写「注释里的字样不豁免」——
  // 注释写 API 全名同样误导 grep 式检索，这条口径若被悄悄改掉必须红）；短路径必中；
  // 别名解引用必中（且缺别名表时放行 —— 证明别名腿真的在起作用）；干净行放行。
  const code = layeringHit('use crate::commands::contextmenu;');
  const comment = layeringHit('// 对照 crate::commands::foo 的旧写法');
  const shortPath = layeringHit('use crate::commands;');
  const aliased = layeringHit('c::contextmenu::open();', ['c']);
  const aliasUnwired = layeringHit('c::contextmenu::open();');
  const clean = layeringHit('use crate::engine::paths;');
  const bracedAlias = commandAliases('use crate::{commands as c};')[0] === 'c'
    && layeringHit('c::contextmenu::open();', ['c']);
  if (!code || !comment || !shortPath || !aliased || aliasUnwired || clean) {
    g.fail(`layering 判定器自检失败：代码行=${code} 注释行=${comment} 短路径=${shortPath} 别名=${aliased}（应 true） 无别名表=${aliasUnwired} 干净行=${clean}（应 false）`);
  } else if (!bracedAlias) {
    g.fail('layering 判定器自检失败：花括号 commands as 别名未被抽取或解引用未判红');
  } else {
    console.log('对照: 代码行/注释行/短路径/别名解引用/花括号别名必中、干净行放行');
  }
}
const hits = [];
let scanned = 0;
let aliasFiles = 0;
for (const { dir, label } of LOWER_LAYERS) {
  for (const f of walkRs(join(SRC, dir))) {
    scanned++;
    const rel = relative(SRC, f).replace(/\\/g, '/');
    const text = readFileSync(f, 'utf8');
    const aliases = commandAliases(text);
    if (aliases.length) aliasFiles++;
    const lines = text.split(/\r?\n/);
    lines.forEach((line, i) => {
      if (layeringHit(line, aliases)) {
        hits.push(`${rel}:${i + 1}`);
      }
    });
  }
}
if (hits.length === 0) {
  console.log(`✓ 分层方向：下层（${LOWER_LAYERS.map((l) => l.label).join(' / ')}，共 ${scanned} 文件）零 crate::commands 反向引用（直连 / 短路径 / use-as 别名解引用三形态）`);
} else {
  g.fail(`分层方向违规：下层不得引用 crate::commands —— ${hits.join(', ')}（别名文件 ${aliasFiles} 个）`);
}

// v5 批次 9（门禁候选 6）：扫描面地板——目录塌缩（改名/搬走/被清空）时 scanned 趋零，
// 「0 文件 0 命中」与「真合规」在旧判据里长得一模一样（恒绿）。地板：三层的 .rs 合计
// 必须达到粗下界（现算 39，取 30：塌缩任一层 ≈ −15 即红；改前先现算）。
if (scanned < 30) {
  g.fail(`扫描面地板：下层只扫到 ${scanned} 个 .rs（< 30）⇒ 目录塌缩/扫描根失明（engine/security/pwsh 任一被搬走都会这样）`);
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
