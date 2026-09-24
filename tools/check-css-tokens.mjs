// check-css-tokens.mjs —— 「引用了未定义的自定义属性」的机器断言（审查 v2-L6）
//
// 为什么要这条门禁：main.css 里躺着 5 处 `var(--bg-elev)` / `var(--border-soft)` ——
// 名字全仓**没有定义**，于是每一处都静默退到 fallback 字面值（`--bg-elev` 就是
// `--bg-elevated` 写漏了后缀）。更糟的形态是**连 fallback 都没写**的那几条：
// 按 CSS 变量规范，引用未定义且无 fallback 的声明在 computed-value 阶段被判 invalid，
// 整条声明直接丢弃 —— 例：`.nav-parent-toggle:active { background: var(--bg-card-active) }`
// 从来没有过按压反馈，`.optimizer-net-hint` 从来没有底色和边框。
// 「没报错」不等于「生效」，这类缺陷人眼在 29 万行 CSS 里查不动，只能机器盯。
//
// ⚠️ 判据必须**精确到名字边界**，不能用前缀匹配：`--bg-elev` 会误吞 `--bg-elevated`、
// `--border` 会误吞 `--border-default`（本轮报告作者自己的第一次统计就踩了这个坑）。
// 统一用 `(?![\w-])` 收尾，`var(` 侧同理。
//
// 三份集合：
//   定义面 = CSS 里 `--x:` 声明（先去注释，注释里的举例不算定义）
//            ∪ JS/HTML 里运行时写入的 `setProperty('--x' …)` 与内联 `--x: value`
//   引用面 = CSS/HTML/JS 里的 `var(--x)` + JS 里的 `getPropertyValue('--x')` 读取
//   差集   = 引用面 - 定义面 → 非空即红
//
// 引用面把 JS/HTML 也算进来是刻意的：内联 style 与 canvas 取色走的是同一套解析规则，
// 少查一边等于给「JS 里写 var(--xxx) 却没人定义」留缝。
//
// 用法：node tools/check-css-tokens.mjs
//   退出码 0 = 全绿；1 = 存在未定义引用（本门禁没有「只警告」档，静默即失职）。

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

/**
 * 名字边界：前后都不许再接 \w 或 `-`。
 * 这是本门禁的立身之本 —— 少了这层边界，`--bg-elev` 会匹配到 `--bg-elevated` 的前缀，
 * `--border` 会匹配到 `--border-default` 的前缀，报告里那份「31 处引用未定义」的假红
 * 就是这么来的（审查 v2-L6 附注：报告作者第一次统计也踩了同一个坑）。
 */
const NAME = '--[A-Za-z0-9_-]+';          // 属性名本体（一律带捕获组使用）
const B = '(?<![\\w-])';                  // 左边界
const E = '(?![\\w-])';                   // 右边界
const RE_VAR = new RegExp(`var\\(\\s*(${NAME})${E}`, 'g');
const RE_GET = new RegExp(`getPropertyValue\\(\\s*['"](${NAME})['"]`, 'g');
const RE_DEFINE = new RegExp(`${B}(${NAME})${E}\\s*:`, 'g');
const RE_SET = new RegExp(`setProperty\\(\\s*['"](${NAME})['"]`, 'g');
/**
 * JS 里「把属性名当字符串参数传出去」的形态：`crossfadeBg('--app-bg-fade', …)` ——
 * 真正 setProperty 的那一行拿的是变量（fadeVar），只看 RE_SET 会漏。
 * **注释行不算证据**（`--c` 在本仓只出现在注释里，算进去就等于把真缺陷洗白）。
 */
const RE_NAME_LITERAL = /['"`](--[A-Za-z0-9_-]+)['"`]/g;

/**
 * 白名单：不是「查不准就先放过」，而是**这一类变量本就不该有写入方**，
 * 它们的语义是「有则覆盖、无则退到 token」的兜底钩子。
 * 每条必须写清出处，新增条目要先回答「为什么 CSS 里查不到它」——否则等于把门禁掏空。
 *   · --c / --cf：AGENTS.md §2「分类/分组不得用离表色（审查 M20）」点名的姿势本身——
 *     看板与卡片的分组标识色走 `var(--c, var(--accent))` / `var(--cf, var(--accent-text))`
 *     的 token 兜底；M20 删掉了注入侧（GROUP_ACCENT / CAT_META.color），所以全仓无人写入
 *     是**预期状态**，不是 v2-L6 那种写错名字的架空。main.css 里 21 处引用都带兜底。
 */
const ALLOW_UNDECLARED = new Map([
  ['--c', 'M20 分组色 token 兜底钩子（AGENTS §2），无写入方是预期'],
  ['--cf', '同上（前景色一档）']
]);

function listFiles(dir, filter) {
  return readdirSync(dir).filter(filter).map((f) => join(dir, f));
}

const cssFiles = listFiles(join(REPO_ROOT, 'src', 'styles'), (f) => f.endsWith('.css'));
const htmlFiles = listFiles(join(REPO_ROOT, 'src'), (f) => f.endsWith('.html'));
const jsFiles = listFiles(join(REPO_ROOT, 'src', 'scripts'), (f) => f.endsWith('.js'));

/** 把 CSS 块注释替换成等长空白：偏移量不变，报出来的行号才对得上原文件 */
function blankComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

const defined = new Set();     // 定义面
const declaredIn = new Map();  // 名字 -> 首个定义位置（报错时给读者一个去处）
const refs = new Map();        // 名字 -> [{ at, hasFallback }]

function collect(text, re, fn) {
  for (const m of text.matchAll(re)) fn(m);
}

function addDefinition(name, at) {
  if (!defined.has(name)) {
    defined.add(name);
    declaredIn.set(name, at);
  }
}

function addReference(name, at, hasFallback) {
  if (!refs.has(name)) refs.set(name, []);
  refs.get(name).push({ at, hasFallback });
}

// ---- 定义面：CSS 声明（去注释后） ----
for (const file of cssFiles) {
  const text = blankComments(readFileSync(file, 'utf8'));
  const rel = file.slice(REPO_ROOT.length + 1).replace(/\\/g, '/');
  // `var(--x,` 里的逗号后才可能跟 `--y:`，那不是定义；要求名字前不是 `var(`
  for (const m of text.matchAll(RE_DEFINE)) {
    const before = text.slice(Math.max(0, m.index - 6), m.index);
    if (/var\(\s*$/.test(before)) continue;
    addDefinition(m[1], `${rel}:${lineOf(text, m.index)}`);
  }
}

// ---- 定义面：JS / HTML 里的运行时写入（setProperty、内联 --x: value、把名字当字符串传出去） ----
for (const file of [...jsFiles, ...htmlFiles]) {
  const text = readFileSync(file, 'utf8');
  const rel = file.slice(REPO_ROOT.length + 1).replace(/\\/g, '/');
  collect(text, RE_SET, (m) => addDefinition(m[1], `${rel}:${lineOf(text, m.index)}`));
  // 内联声明：字符串/模板里的 `--x: v`（style 属性、insertAdjacentHTML、setProperty 的拼接形态）
  for (const m of text.matchAll(RE_DEFINE)) {
    const before = text.slice(Math.max(0, m.index - 6), m.index);
    if (/var\(\s*$/.test(before)) continue;
    addDefinition(m[1], `${rel}:${lineOf(text, m.index)}`);
  }
  // 名字作参数传递（setProperty 在 helper 里拿变量）：逐行判，注释行不算证据
  if (rel.endsWith('.js')) {
    let lineNo = 0;
    for (const line of text.split('\n')) {
      lineNo++;
      const t = line.trim();
      if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) continue;
      for (const m of line.matchAll(RE_NAME_LITERAL)) addDefinition(m[1], `${rel}:${lineNo}`);
    }
  }
}

// ---- 引用面：CSS / HTML / JS ----
for (const file of [...cssFiles, ...htmlFiles, ...jsFiles]) {
  const raw = readFileSync(file, 'utf8');
  const rel = file.slice(REPO_ROOT.length + 1).replace(/\\/g, '/');
  // CSS 里的引用要去注释；JS/HTML 注释里出现 var(--x) 不构成真引用，但 JS 块注释与
  // 正则字面量的 `/*` 语义不同，去注释反而会误伤 —— 故只对 .css 去注释。
  const isCss = rel.endsWith('.css');
  const text = isCss ? blankComments(raw) : raw;
  for (const m of text.matchAll(RE_VAR)) {
    // var() 的 fallback 判据：紧跟名字之后的第一个分隔符是逗号（不是括号）才算有兜底
    const hasFallback = /^\s*,/.test(text.slice(m.index + m[0].length));
    addReference(m[1], `${rel}:${lineOf(text, m.index)}`, hasFallback);
  }
  if (rel.endsWith('.js')) {
    collect(text, RE_GET, (m) => addReference(m[1], `${rel}:${lineOf(text, m.index)}`, false));
  }
}

// ---- 判红 ----
const bad = [...refs.keys()]
  .filter((n) => !defined.has(n) && !ALLOW_UNDECLARED.has(n))
  .sort();

console.log(`引用面 ${refs.size} 个自定义属性；定义面 ${defined.size} 个（CSS 声明 + JS/HTML 运行时写入）`);

if (!bad.length) {
  console.log('✓ 全部引用的自定义属性都有定义（无静默 fallback、无被丢弃的声明）');
  process.exit(0);
}

for (const name of bad) {
  const sites = refs.get(name);
  const noFallback = sites.filter((s) => !s.hasFallback).length;
  console.log(`✗ ${name} 无定义 —— ${sites.length} 处引用：${sites.map((s) => s.at).join(', ')}`);
  console.log(`  ${noFallback ? `其中 ${noFallback} 处连 fallback 都没有 ⇒ 整条声明被解析器丢弃（功能静默消失）` : '全部恒吃 fallback ⇒ token 被架空'}`);
}
console.log(`\n${bad.length} 个未定义的自定义属性被引用（v2-L6 类缺陷）`);
process.exit(1);
