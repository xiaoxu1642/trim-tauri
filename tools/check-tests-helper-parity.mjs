#!/usr/bin/env node
// check-tests-helper-parity.mjs —— X1-M06（v7.2 C08）：tests/ 底座 helper 单一真源兜点
//
// 为什么要有它：`tests/common/mod.rs` 是 MockRuntime 底座 helper 的唯一真源
// （AGENTS §4.2 的不变量），但 2026-10-19 审查时**全仓零兜点**——tools/*.mjs 里
// 没有任何门禁读 src-tauri/tests/。不变量的现状是靠「人记得」维持的：一旦有人在
// 某个 tests/x.rs 里抄一份 `fn main_window()`（历史上六个 helper 就曾私有于
// ipc_smoke.rs，靠复制扩散），两份实现会各自漂移，而所有测试依旧全绿。
// 本门禁把「不变量成立」变成可机检：本地重复定义必须为 0，调用了 helper 的
// 文件必须接真源（`use common::` / `common::`）。
//
// 判据口径（三条，全部现算、不硬编码名单）：
//   ① 真源清单从 common/mod.rs 现解析 `pub fn`（改 helper 名单不用改本门禁），
//      并设下限防「清单塌缩后恒绿」；
//   ② 扫 src-tauri/tests/**/*.rs（剔除 common/mod.rs 自身）：任何底座 helper 的
//      本地 `fn`/`pub fn`/`async fn` 定义 ⇒ 判红（剥离注释后判定，注释里的示例
//      代码不误伤；被注释掉的定义也不是活定义）；
//   ③ 文件里出现任一 helper 调用、但全文（剥注释后）没有 `common` 引用 ⇒ 判红
//      （调了底座却另起一份私有实现的形态）。
//   helper 的 0 引用**不判红**：`ipc_fire_no_assert` 就是刻意保留的 0 引用件
//      （档位场景「只求不拒杀」的预留形态，doc 里有对照判据），死代码由
//      common/mod.rs 的 `#![allow(dead_code)]` 整表处理。
//
// 假绿防线（AGENTS §4.1）：判红能力由文件尾 POSITIVE_CONTROLS 的合成样本验证
// （抄一份定义必须判红、干净用法必须放行）。
'use strict';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gate } from './lib/gate.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TESTS = join(ROOT, 'src-tauri', 'tests');
const COMMON = join(TESTS, 'common', 'mod.rs');

const g = gate(import.meta.url);

// 真源 helper 数下限：2026-10-19 审查现算 8 个 pub helper（C08 又加 reset_snapshots /
// skip_and_record 后为 10）。设下限而不是上限——删到只剩一两个时判据会恒绿，
// 那正是「清单塌缩」型假绿（sub_windows 元断言同一条纪律）。
const HELPER_FLOOR = 8;

/** 剥 Rust 行注释与块注释（不处理嵌套块注释——本仓 tests/ 无此形态）。 */
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** 从 common/mod.rs 现解析 pub helper 名单（单一真源，不硬编码）。 */
function parseHelpers(src) {
  return [...src.matchAll(/^pub\s+fn\s+(\w+)/gm)].map((m) => m[1]);
}

/**
 * 审一个文件内容，返回问题列表（合成样本也走它，保证自检与实判同一实现）。
 * @param {string} content 文件原文
 * @param {string[]} helpers 真源 helper 名单
 */
function auditContent(content, helpers) {
  const problems = [];
  const code = stripComments(content);
  const defRe = (name) => new RegExp(`\\b(?:pub\\s+)?(?:async\\s+)?fn\\s+${name}\\s*[(<]`);
  for (const h of helpers) {
    if (defRe(h).test(code)) {
      problems.push(`本地重复定义 fn ${h}() —— 底座 helper 唯一真源在 tests/common/mod.rs，复制会各自漂移`);
    }
  }
  // 判「调用」前先把 helper 定义行剔掉：定义行本身匹配调用正则，不剔会让
  // 「抄了一份定义」的样本多报一条「未接真源」（判定器与样本口径不一致）。
  const codeNoDefs = code.replace(
    new RegExp(`\\b(?:pub\\s+)?(?:async\\s+)?fn\\s+(?:${helpers.join('|')})\\s*[(<]`, 'g'),
    'fn __dup_def__(',
  );
  const callsHelper = helpers.some((h) => new RegExp(`\\b${h}\\s*\\(`).test(codeNoDefs));
  const wired = /(?:^|\n)\s*use\s+common\s*::|\bcommon\s*::/.test(code);
  if (callsHelper && !wired) {
    problems.push('调用了底座 helper 但全文没有 common:: 引用（另一份私有实现的形态）');
  }
  return problems;
}

/** 递归列 .rs 文件（tests/ 下现只有 common/mod.rs，但目录会长子目录）。 */
function listRs(dir) {
  const out = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) out.push(...listRs(p));
    else if (ent.name.endsWith('.rs')) out.push(p);
  }
  return out;
}

if (!existsSync(COMMON)) {
  // tests/ 是跟踪文件：干净克隆里 common/mod.rs 必须在，缺失即真问题（不是 SKIP）
  g.fail('src-tauri/tests/common/mod.rs 不在 —— 底座真源失踪，本门禁无从对拍');
  g.finish();
}

const commonSrc = readFileSync(COMMON, 'utf8');
const helpers = parseHelpers(commonSrc);
if (helpers.length < HELPER_FLOOR) {
  g.fail(`common/mod.rs 只解析出 ${helpers.length} 个 pub helper（下限 ${HELPER_FLOOR}）—— 真源清单塌缩后判据恒绿`);
} else {
  g.ok(`底座真源解析出 ${helpers.length} 个 pub helper：${helpers.join(', ')}`);
}

const files = listRs(TESTS).filter((p) => p !== COMMON);
if (files.length === 0) {
  g.fail('tests/ 下没有任何 .rs 文件（除 common/mod.rs）—— 扫描面塌缩');
  g.finish();
}

let dupCount = 0;
let wiredCount = 0;
for (const f of files) {
  const label = relative(ROOT, f).replace(/\\/g, '/');
  const problems = auditContent(readFileSync(f, 'utf8'), helpers);
  for (const p of problems) {
    g.fail(`${label}: ${p}`);
    if (p.startsWith('本地重复定义')) dupCount++;
    else wiredCount++;
  }
}
if (dupCount === 0 && wiredCount === 0) {
  g.ok(`${files.length} 个测试文件均无本地重复定义、调用方全部接真源（${files.map((f) => relative(ROOT, f)).join(', ')}）`);
}

// ==================== POSITIVE_CONTROLS：判定器自检 ====================
// 合成样本喂同一个 auditContent：抄定义必须判红、干净用法必须放行。
// 防的是判据本身退化成「永远红」（把正常用法也判违规）或「永远绿」（正则永不命中）。
{
  const cases = [
    {
      label: '抄一份 fn main_window()（审计给出的反例形态）',
      content: 'mod common;\n\nfn main_window() -> u8 { 0 }\n',
      want: 1,
    },
    {
      label: 'pub async fn invoke() 变体同样算重复定义',
      content: 'pub async fn invoke() {}\n',
      want: 1,
    },
    {
      label: '干净用法（use common + 调用）',
      content: 'use common::{invoke, main_window};\n\n#[test]\nfn t() { let _ = invoke(&main_window(), "x", json!({})); }\n',
      want: 0,
    },
    {
      label: '全路径 common:: 调用同样算接真源',
      content: '#[test]\nfn t() { common::ipc_fire_no_assert(&common::main_window(), "x", json!({})); }\n',
      want: 0,
    },
    {
      label: '调了 helper 却另起一份（没接真源）',
      content: '#[test]\nfn t() { let w = main_window(); let _ = invoke(&w, "x", json!({})); }\n',
      want: 1,
    },
    {
      label: '注释里的 fn main_window() 不是活定义（不误伤）',
      content: '// 反例：fn main_window() 抄一份就红\n/// 文档：fn invoke() 长这样\n#[test]\nfn t() { let _ = common::sub_windows(); }\n',
      want: 0,
    },
  ];
  let controlFailed = 0;
  for (const c of cases) {
    const got = auditContent(c.content, helpers).length;
    if (got !== c.want) {
      controlFailed++;
      g.fail(`正向对照「${c.label}」：期望 ${c.want} 处问题，实测 ${got} 处 —— 本门禁的判定器与样本口径不一致`);
    }
  }
  if (controlFailed === 0) {
    g.ok(`POSITIVE_CONTROLS：${cases.length} 条判定器样本（红/放行）结论正确`);
  }
}

g.finish('check-tests-helper-parity: 全部通过');
