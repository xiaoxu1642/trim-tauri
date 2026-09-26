// check-fail-closed.mjs —— fail-closed 口径门禁（审查 v3-M2 / v3-L7）
//
// 为什么判红：安全敏感的目录解析与路径转换一旦带「降级回退」，就是把 fail-closed
// 改成 fail-open ——
//   A. `paths::temp_script_dir()` 在私有 tmp 被 junction 替换时返回 Err（审查 L12 的
//      成果），任何调用方把 Err 回退成 `std::env::temp_dir()` 都等于在提权上下文里
//      用可预测路径写文件再导入（TOCTOU 提权窗口）。真实违规见 optimizer.rs 的
//      `Err(_) => std::env::temp_dir()`（v3-M2，已修）。
//   B. `Path::to_str().unwrap()` 在含孤立代理项的非 UTF-8 路径上直接 panic；本项目
//      口径（AGENTS §5 / I3）是批量操作单项失败要跳过并回传，不是崩溃。
//
// 判定粒度是「语句」（向前扩到最近的 ;{}，向后扩到括号深度 0 的分号），而不是
// 函数级 —— 函数级会误伤 cleanup_temp_scripts 这类「私有 tmp + 遗留 %TEMP% 残留
// 都要扫着删」的合法清扫槽。
//
// 用法：node tools/check-fail-closed.mjs

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const SRC = join(REPO_ROOT, 'src-tauri', 'src');

function walk(dir, out = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith('.rs')) out.push(p);
  }
  return out;
}

/**
 * 豁免清单（file:line → 理由）。line 以门禁自己的行号计算为准。
 * 目标是保持为空；新增豁免必须写明为什么不违反 fail-closed。
 */
const EXEMPT = {
  // 空集：pwsh/mod.rs:452 的 `unwrap_or_else(|_| PathBuf::from("."))` 不含
  // env::temp_dir，天然不触发断言 A（清扫槽只删不写）。
};

/** 取 occurrence 起所在「语句」文本（只向后扫）。
 * 规则：括号深度计数（字符串字面量内容不计），停在深度 0 的 `;`；
 * 但若某个 `}` 把深度从 1 归 0 且其后的首个非空白字符不是 `;`（块语句收尾，
 * 如 `if let … { … }` 后直接换行），也在此停 —— 不越过语句边界吞进下一条。
 * 这样 `match temp_script_dir() { … Err(_) => env::temp_dir() };` 整体纳入，
 * 而 cleanup_temp_scripts 里相邻的 `dirs.push(env::temp_dir()…)` 不会被误并。 */
function statementFrom(text, idx) {
  let end = idx;
  let depth = 0;
  for (; end < text.length; end++) {
    const c = text[end];
    if (c === '"' || c === "'") {
      const q = c;
      end++;
      while (end < text.length && text[end] !== q) {
        if (text[end] === '\\') end++;
        end++;
      }
      continue;
    }
    if (c === '{' || c === '(' || c === '[') depth++;
    else if (c === '}' || c === ')' || c === ']') {
      depth--;
      if (depth === 0 && c === '}') {
        let k = end + 1;
        while (k < text.length && /\s/.test(text[k])) k++;
        if (text[k] !== ';') { end = k; break; }
      }
    } else if (c === ';' && depth === 0) break;
  }
  return text.slice(idx, end);
}

const files = walk(SRC);
let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== fail-closed 口径门禁 ===\n');

// ---- A. temp_script_dir() 的结果不得在同语句回退到 env::temp_dir() ----
const aHits = [];
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  const rel = relative(REPO_ROOT, f).replace(/\\/g, '/');
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  const lineOf = (off) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= off) lo = mid; else hi = mid - 1;
    }
    return lo;
  };
  const re = /temp_script_dir\(/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    // 注释/文档里出现是讲原理（paths.rs 定义处、pwsh 模块头），不是调用点
    const lnIdx = lineOf(m.index);
    const lineStart = starts[lnIdx];
    const lineEnd = text.indexOf('\n', lineStart);
    if (text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd).trimStart().startsWith('//')) continue;
    const stmt = statementFrom(text, m.index);
    if (!/env::temp_dir\(\)/.test(stmt)) continue;
    const ln = lnIdx + 1;
    if (EXEMPT[`${rel}:${ln}`]) continue;
    aHits.push(`${rel}:${ln}`);
  }
}
check(
  aHits.length === 0,
  'A. temp_script_dir() 的结果不得在同语句回退到 env::temp_dir()',
  aHits.length ? `违规 ${JSON.stringify(aHits)}（私有 tmp 被替换时必须 Err 传播，不得降级到全局可写 %TEMP%）` : '',
);

// ---- B. 生产代码禁 to_str().unwrap()（非 UTF-8 路径 panic） ----
const bHits = [];
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  const rel = relative(REPO_ROOT, f).replace(/\\/g, '/');
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  const lineOf = (off) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= off) lo = mid; else hi = mid - 1;
    }
    return lo;
  };
  const re = /\.(to_str|to_string)\(\)\s*\.unwrap\(\)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const lnIdx = lineOf(m.index);
    const lineStart = starts[lnIdx];
    const lineEnd = text.indexOf('\n', lineStart);
    if (text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd).trimStart().startsWith('//')) continue;
    const ln = lnIdx + 1;
    if (EXEMPT[`${rel}:${ln}`]) continue;
    bHits.push(`${rel}:${ln}`);
  }
}
check(
  bHits.length === 0,
  'B. 路径转字符串禁用 unwrap()（非 UTF-8 路径会 panic，应跳过并回传失败）',
  bHits.length ? `违规 ${JSON.stringify(bHits)}` : '',
);

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 组断言未通过`);
  process.exit(1);
}
console.log('fail-closed 门禁全部通过');
