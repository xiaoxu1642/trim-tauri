#!/usr/bin/env node
// check-tools-doc-paths.mjs —— tools/ 不许把 `docs/`（本机未跟踪资料区）当数据源（v6-K23）
//
// 为什么要有它：`docs/` 是 .gitignore 排除的本机资料区，**干净克隆里
// 根本不存在**。工具的默认入参一旦指向 docs/，别人 clone 下来第一跑就是 ENOENT 堆栈，
// 要么以为是仓库坏了，要么（更糟）照着自己的机器补一份"差不多"的路径把口径改歪。
// import-winapp2.mjs 的 `--src` 缺省兜底就是这么长出来的（v6-K23 点名）。
//
// 判据（三形态，全部按「**代码里的路径构造**」判，注释不算）：
//   ① `path.join(... 'docs' ...)` / `path.resolve(... 'docs' ...)` —— 独立段 'docs'；
//   ② 字符串字面量以 `docs/` 或 `docs\` 开头 —— 直接写死的仓外相对路径；
//   ③ 模板串同样按 ② 判（`` `docs/${x}` `` 与 'docs/x' 等价）。
//
// 口径细节（写判据时踩过的坑，勿放宽）：
//   · 先剥注释、**保留字符串**——上一条同族门禁（check-doc-refs）的 stripRust 会把
//     字符串洗成 `""`，那样 ②③ 永远不命中；本门禁要的恰恰是字符串内容。
//   · 只认「以 docs/ 开头」的字面量：正文/日志里说「不含 vendor/、docs/」不算
//     （不在开头就不会命中）。
//   · `check-doc-refs.mjs` 是唯一登记例外：它的扫描对象就是 docs/ 引用本身
//     （REF_RE 正则里必须出现 docs 形态）——这不是把 docs 当数据源。
//   · 行号进输出（仓内工具=可维护代码，不是判据锚点），ASGENTS §5.19 的禁行号只约束
//     「判据锚定」场景；这里报错要给到人肉可改的位置。
//
// 用法：node tools/check-tools-doc-paths.mjs
'use strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { gate } from './lib/gate.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TOOLS = join(ROOT, 'tools');

/** 登记例外：{ file, reason }（文件级；新增必须写清为什么不是"把 docs 当数据源"） */
const EXEMPTS = [
  {
    file: 'check-doc-refs.mjs',
    reason: '该门禁的扫描对象就是 docs/ 引用本身（REF_RE 正则与对照集），不是把 docs 当数据源',
  },
  {
    file: 'check-tools-doc-paths.mjs',
    reason: '本门禁自身的正反对照样本必须写出 docs 三形态；豁免自身不改变判定面（扫描面 − 1 已声明）',
  },
  {
    file: 'check-readme-negative-claims.mjs',
    reason: '以 docs 为承诺真源，但已做 existsSync + SKIP（干净克隆下明确"未校验"且 exit 0，不崩）——K23 禁止的是无兜底的默认指向',
  },
];

/** 剥注释、保留字符串与代码（与 check-doc-refs 的剥法相反，见头注） */
function stripCommentsKeepStrings(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i], d = i + 1 < n ? src[i + 1] : '';
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && d === '*') {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (src[i] === '/' && src[i + 1] === '*') { depth++; i += 2; }
        else if (src[i] === '*' && src[i + 1] === '/') { depth--; i += 2; }
        else { if (src[i] === '\n') out += '\n'; i++; }
      }
      continue;
    }
    if (c === '"' || c === '\'' || c === '`') {
      const q = c;
      let j = i + 1;
      while (j < n && src[j] !== q) {
        if (src[j] === '\\') j++;
        j++;
      }
      out += src.slice(i, Math.min(j + 1, n));
      i = j + 1;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/** 判定器（纯函数，合成样本可对拍）：返回违规描述数组 */
export function judgeDocPaths(code) {
  const out = [];
  // ① path.join / path.resolve 里的独立 'docs' 段（单双引号与模板串的裸段都算）
  for (const m of code.matchAll(/path\.(?:join|resolve)\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    // 取平衡括号内文本
    let depth = 0, end = -1;
    for (let i = open; i < code.length; i++) {
      if (code[i] === '(') depth++;
      else if (code[i] === ')') { depth--; if (depth === 0) { end = i; break; } }
    }
    const args = end > 0 ? code.slice(open + 1, end) : '';
    if (/(?:^|,)\s*['"`]docs['"`]\s*(?:,|$)/.test(args)) {
      out.push(`path.join/resolve 用了 'docs' 段@字节 ${m.index}`);
    }
  }
  // ② 字符串/模板字面量以 docs/ 或 docs\ 开头（写死的仓外相对路径）
  for (const m of code.matchAll(/(['"`])docs[\\/]/g)) {
    out.push(`写死的 docs 路径字面量 ${m[0]}…@字节 ${m.index}`);
  }
  return out;
}

/** 行号（报错给人看的）：字节偏移 → 1 基行号 */
function lineOf(code, byteIdx) {
  return code.slice(0, byteIdx).split('\n').length;
}

// ---------- 正向对照（合成样本双向验，AGENTS §4.1） ----------
const g = gate(import.meta.url);
{
  const bad = [
    "const p = path.join(ROOT, 'docs', 'x.ini');",
    "const p = path.resolve(ROOT, \"docs\", 'x');",
       'const p = "docs\\\\a\\\\b.md";',
    'const p = `docs/x`;',
  ].join('\n');
  const good = [
    "const p = path.join(ROOT, 'src-tauri', 'data', 'cleanup-rules.json');",
    '// 语料排除 vendor/ 与 docs/（注释不算）',
    'console.log("不含 docs/ 目录");',
  ].join('\n');
  const nBad = judgeDocPaths(stripCommentsKeepStrings(bad)).length;
  const nGood = judgeDocPaths(stripCommentsKeepStrings(good)).length;
  if (nBad < 4) {
    g.fail(`对照a：四形态假样本必须判红（实得命中 ${nBad}/4）`);
  } else {
    console.log(`✓ 对照a：四形态假样本命中 ${nBad} 条`);
  }
  if (nGood !== 0) {
    g.fail(`对照b：合规样本必须放行（实得误报 ${nGood} 条：${judgeDocPaths(stripCommentsKeepStrings(good)).join('；')}）`);
  } else {
    console.log('✓ 对照b：合规样本零误报（路径不含 docs、注释与日志里的提及不算）');
  }
}

// ---------- 真仓扫描 ----------
const exempt = new Set(EXEMPTS.map((e) => e.file));
// T1b-L01（v7.2 C09）：扫描面从「顶层 .mjs」扩到 tools/**/*.mjs（含 lib/ 两个共享件）；
// 旧口径输出「tools/ 下 78 个 .mjs」对 tools/**/*.mjs（现算 80）是错口径，lib/ 里的
// fs-walk/gate 永远不在射程。exempt 的键仍是**文件名**（EXEMPTS 以 {file} 登记）。
const files = [];
{
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.mjs')) files.push(p);
    }
  };
  walk(TOOLS);
}
let scanned = 0;
let hits = 0;
for (const abs of files) {
  const f = relative(TOOLS, abs).replace(/\\/g, '/');
  if (exempt.has(f)) continue;
  scanned++;
  const raw = readFileSync(abs, 'utf8');
  const code = stripCommentsKeepStrings(raw);
  for (const v of judgeDocPaths(code)) {
    const at = /@字节 (\d+)$/.exec(v);
    const line = at ? lineOf(code, Number(at[1])) : '?';
    g.fail(`tools/${f}:${line} ${v.replace(/@字节 \d+$/, '')}`);
    hits++;
  }
}
if (scanned < 20) g.fail(`扫描面 ${scanned} 个 .mjs（< 20）⇒ 目录读面失明`);
console.log(`\n扫描：tools/**/*.mjs 共 ${files.length} 个（例外 ${exempt.size} 个）→ 实际 ${scanned} 个，命中 ${hits} 处`);
g.finish('check-tools-doc-paths: 全部通过');
