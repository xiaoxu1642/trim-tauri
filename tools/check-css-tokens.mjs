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
 *     是**预期状态**，不是 v2-L6 那种写错名字的架空。main.css / main-pages.css 里
 *     `var(--c[,)]` 的引用都带兜底（条数现算：`grep -o "var(--c[,)]" src/styles/*.css | wc -l`，
 *     不在注释里手抄）。
 */
const ALLOW_UNDECLARED = new Map([
  ['--c', 'M20 分组色 token 兜底钩子（AGENTS §2），无写入方是预期'],
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

// ==================== 纯判据（v6-P2，T1 假绿扫尾） ====================
// 三组判定抽成纯函数，合成样本自检与真仓扫描共用同一实现。
// 圆角：字面值必须落档位 4/6/8/10/14（<4 禁字面值、≥90 胶囊放行）。
function radiusViolations(text, rel) {
  const out = [];
  // T1d-M11：按整条声明取值，逐个 px 判档；var()/%/calc/inherit 不含字面 px，自然放行。
  // 旧实现只认「单值 Npx」，`0 2px 2px 0` 这类多值写法整条从判据消失。
  for (const m of text.matchAll(/border[a-z-]*radius\s*:\s*([^;}]+)/gi)) {
    const label = m[0].split(':')[0].trim();
    for (const pxm of m[1].matchAll(/(\d+(?:\.\d+)?)px/g)) {
      const px = Number(pxm[1]);
      if (px >= 90) continue;
      if (px < 4) out.push(`${rel} ${label}: ${px}px（低于 badge 档 4px，禁字面值，走 var(--radius-badge)）`);
      else if (![4, 6, 8, 10, 14].includes(px)) out.push(`${rel} ${label}: ${px}px（不在档位 4/6/8/10/14）`);
    }
  }
  return out;
}
// 未定义引用：refs（名字 → 引用位）∧ ¬defined ∧ ¬allow ⇒ 红。
function undeclaredTokenRefs(refs, defined, allow) {
  return [...refs.keys()].filter((n) => !defined.has(n) && !allow.has(n)).sort();
}
// 动效曲线：JS 内 cubic-bezier 数值序列必须 ∈ token 值集（返回违例 + 位置供行号）。
function curveOffenders(text, easeTokens) {
  const out = [];
  for (const m of text.matchAll(/cubic-bezier\(([^)]+)\)/g)) {
    const norm = m[1].split(',').map((x) => Number(x.trim())).join(',');
    if (!easeTokens.has(norm)) out.push({ index: m.index, norm, raw: m[1].trim() });
  }
  return out;
}
{
  // 正向对照：违档必红 / 档位与胶囊放行 / 未定义引用必红 / 已定义与 ALLOW 放行 /
  // 曲线越集必红、值集内放行。
  const r = (px) => radiusViolations(`.x { border-radius: ${px}px; }`, 'fake.css').length;
  const rMulti = radiusViolations('.x { border-radius: 0 2px 2px 0; }', 'fake.css').length;
  const radiusOk = r(5) === 1 && r(2) === 1 && r(8) === 0 && r(999) === 0 && r(10) === 0 && rMulti === 2;
  const u = (refs, defined, allow = new Set()) => undeclaredTokenRefs(refs, defined, allow);
  const undefOk =
    u(new Map([['--ghost', []]]), new Set(), new Set()).length === 1 &&
    u(new Map([['--real', []]]), new Set(['--real']), new Set()).length === 0 &&
    u(new Map([['--allowed', []]]), new Set(), new Set(['--allowed'])).length === 0;
  const ease = new Set(['0.111,0.222,0.333,1']);
  const cBad = curveOffenders('.x { a: cubic-bezier(0.4,0,0.2,1); }', ease).length;
  const cOk = curveOffenders('.x { a: cubic-bezier(0.111, 0.222, 0.333, 1); }', ease).length;
  if (!radiusOk || !undefOk || cBad !== 1 || cOk !== 0) {
    console.error(`✗ 正向对照失败：圆角=${radiusOk} 未定义引用=${undefOk} 曲线越集=${cBad}（应 1） 曲线放行=${cOk}（应 0）——三组判定器至少一组失灵`);
    process.exit(1);
  }
  console.log('✓ 判定器自检：圆角档位 / 未定义引用 / 动效曲线 三组合成样本全对');
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
// v2-L4P-44（E-13）：JS/HTML 的定义面同样要先剥注释——注释里的 `--x: v` 举例
// 会把「真身未定义」的变量洗白成已定义（CSS 侧 v2-M16 已修，此处是同族漏网）。
// 剥除用等长空白替换，行号偏移保持不变。
function blankJsComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, (m, keep) => keep + m.slice(keep.length).replace(/[^\n]/g, ' '));
}
function blankHtmlComments(text) {
  return text.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, ' '));
}
for (const file of [...jsFiles, ...htmlFiles]) {
  const raw = readFileSync(file, 'utf8');
  const kind = file.slice(-4).toLowerCase();
  const text = kind === '.js' ? blankJsComments(raw) : kind === 'html' ? blankHtmlComments(raw) : raw;
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

// ---- 判红（v6-P2：判据本体是 undeclaredTokenRefs，与自检共用同一实现） ----
const bad = undeclaredTokenRefs(refs, defined, ALLOW_UNDECLARED);
// T1d-M01：豁免不是免检通道——条目必须仍有引用，且每处都带 fallback。
const allowBad = [...ALLOW_UNDECLARED.keys()].filter((n) =>
  !refs.has(n) || refs.get(n).some((s) => !s.hasFallback));
if (allowBad.length) {
  for (const n of allowBad) console.log(`✗ ALLOW_UNDECLARED 条目 ${n} 已失效（零引用或存在无 fallback 引用）`);
  process.exit(1);
}

// ---- 圆角 token 纪律（v2 批次 D4，2026-10-01）----
// 为什么跟 token 门禁放一起：都是「CSS 字面值绕过设计系统」的同类纪律。
// AGENTS 圆角档位 badge 4 / small 6 / btn 8 / medium 10 / large 14（胶囊 999 与圆 50% 除外），
// <6px 的字面值此前散落 27 处绕开 token，收敛后禁回潮：sub-6px 一律 var(--radius-badge)，
// 档位之间（5/7/9px 等）不得自造。CSS 圆角会被钳制到盒尺寸一半，微元素上 2/3px→badge(4px)
// 渲染等价——这正是当年敢统一收敛的依据，回潮即红。
const radiusBad = [];
for (const file of cssFiles) {
  const text = blankComments(readFileSync(file, 'utf8'));
  const rel = file.slice(REPO_ROOT.length + 1).replace(/\\/g, '/');
  // v2-L4P-44（E-14）：扩到四角写法 border-top-right-radius 等——只盯简写会漏掉
  // 单角字面值（同一档位纪律，四角写法是同一约束的逃逸口）。
  // v6-P2：判据本体是 radiusViolations（与自检共用同一实现）。
  radiusBad.push(...radiusViolations(text, rel));
}

console.log(`引用面 ${refs.size} 个自定义属性；定义面 ${defined.size} 个（CSS 声明 + JS/HTML 运行时写入）`);
console.log(`圆角纪律：${radiusBad.length ? `${radiusBad.length} 处违档` : '✓ 全部字面值落在档位或 token 上'}`);
for (const r of radiusBad) console.log(`✗ ${r}`);

// ---- 动效曲线纪律（P3-5 / F5-G-5）：JS 内联 cubic-bezier 必须 ∈ token 值集 ----
// 背景：F5 审查现算命中 xtable.js 的 `cubic-bezier(0.4,0,0.2,1)` —— 正是雾屿 V1
// 已退役的 M2 legacy 曲线（token 注释明写）。判据：从两份 CSS 里解析 `--ease-*` 的
// cubic-bezier 值集，JS 里任何 cubic-bezier 字面量的**数值序列**必须落在值集内；
// 开屏一次性走场（splash.js）按 AGENTS §2 豁免登记。
const EASE_TOKENS = new Set();
for (const file of cssFiles) {
  const text = blankComments(readFileSync(file, 'utf8'));
  for (const m of text.matchAll(/--ease-[\w-]+\s*:\s*cubic-bezier\(([^)]+)\)/g)) {
    EASE_TOKENS.add(m[1].split(',').map((x) => Number(x.trim())).join(','));
  }
}
// T1d-L04：豁免按「文件 + 锚点子串」登记（§5.19 禁行号），同文件新增曲线不再整文件免检。
const CURVE_EXEMPT = [
  { file: 'splash.js', anchor: 'MORPH_MS / 1000', why: '开屏一次性走场（AGENTS §2 唯一豁免）' },
];
const curveBad = [];
let curveSites = 0;
{
  const jsDir = join(REPO_ROOT, 'src', 'scripts');
  for (const f of readdirSync(jsDir).filter((n) => n.endsWith('.js'))) {
    // 剥注释再扫：注释里说明「原曲线是 X」是史实，不是违规（判定面=可执行代码）
    const text = readFileSync(join(jsDir, f), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[^:\w])\/\/.*$/gm, '$1');
    for (const m of text.matchAll(/cubic-bezier\(([^)]+)\)/g)) {
      curveSites++;
    }
    // v6-P2：违例判定走 curveOffenders（与自检共用同一实现）；行号在这里补
    for (const off of curveOffenders(text, EASE_TOKENS)) {
      const near = text.slice(Math.max(0, off.index - 160), off.index + 160);
      if (CURVE_EXEMPT.some((e) => e.file === f && near.includes(e.anchor))) continue;
      curveBad.push(`${f}:${text.slice(0, off.index).split('\n').length} cubic-bezier(${off.raw}) 不在 token 值集（${[...EASE_TOKENS].join(' | ')}）`);
    }
  }
}
console.log(`动效曲线纪律：${curveBad.length ? `${curveBad.length} 处越集` : `✓ JS 内 ${curveSites - CURVE_EXEMPT.length} 处曲线全在 token 值集`}`);
for (const c of curveBad) console.log(`✗ ${c}`);
// 正向对照：值集外样本必须判红、值集内样本必须放行（判定器自检）
{
  const inSet = EASE_TOKENS.size > 0;
  const outSet = !EASE_TOKENS.has('0.123,0.456,0.789,1');
  if (!inSet || !outSet) {
    console.log('✗ 动效曲线判定器失效（token 值集解析异常）');
    curveBad.push('判定器自检失败');
  }
}
if (curveSites === 0) {
  console.log('✗ JS 内曲线扫描 0 处 ⇒ 语料/正则失明');
  curveBad.push('扫描面失明');
}

// ---- 数值双真源逐值对拍（P3-5 / F5-G-3）：--glass-blur 基准 ⇄ ds.GLASS_MAX_BLUR_PX ----
// （`--bg-blur` 由 theme/pathbinding 运行时写入，无静态定义面，不在本对拍内——如实标注。）
{
  const mainCss = readFileSync(join(REPO_ROOT, 'src', 'styles', 'main.css'), 'utf8');
  const dsJs = readFileSync(join(REPO_ROOT, 'src', 'scripts', 'ds.js'), 'utf8');
  const cssBlur = mainCss.match(/--glass-blur:\s*(\d+)px/);
  const jsBlur = dsJs.match(/GLASS_MAX_BLUR_PX\s*=\s*(\d+)/);
  if (!cssBlur || !jsBlur) {
    console.log('✗ 数值双真源：--glass-blur 或 GLASS_MAX_BLUR_PX 找不到（改名/删除？）');
    curveBad.push('数值双真源解析失明');
  } else if (cssBlur[1] !== jsBlur[1]) {
    console.log(`✗ 数值双真源漂移：--glass-blur=${cssBlur[1]}px ⇄ ds.GLASS_MAX_BLUR_PX=${jsBlur[1]}（两处必须同值）`);
    curveBad.push('--glass-blur ⇄ GLASS_MAX_BLUR_PX 漂移');
  } else {
    console.log(`✓ 数值双真源同值：--glass-blur = GLASS_MAX_BLUR_PX = ${cssBlur[1]}px`);
  }
}

// ---- 反向棘轮（T1d-M01）：定义但全仓零消费的 token 必须逐条登记理由 ----
// 与 ALLOW_UNDECLARED（引用无定义）方向相反；新增死 token 不在表内即红。
const DEAD_TOKEN_ALLOW = new Map([
  // spacing：布局档位表（保留栅格档，当前页面未消费；新增布局优先走它）
  ['--spacing-1', '布局间距档位（当前未消费，保留栅格表）'],
  ['--spacing-2', '布局间距档位（当前未消费，保留栅格表）'],
  ['--spacing-3', '布局间距档位（当前未消费，保留栅格表）'],
  ['--spacing-4', '布局间距档位（当前未消费，保留栅格表）'],
  ['--spacing-5', '布局间距档位（当前未消费，保留栅格表）'],
  ['--spacing-6', '布局间距档位（当前未消费，保留栅格表）'],
  ['--spacing-8', '布局间距档位（当前未消费，保留栅格表）'],
  ['--spacing-10', '布局间距档位（当前未消费，保留栅格表）'],
  ['--spacing-12', '布局间距档位（当前未消费，保留栅格表）'],
  // 材质/玻璃：保留的语义档，当前只消费主档
  ['--bg-acrylic', '材质层语义档（当前未消费，保留给亚克力面）'],
  ['--bg-mica', '材质层语义档（当前未消费，保留给 Mica 面）'],
  ['--bg-overlay', '浮层底色档（当前未消费，保留给覆盖层）'],
  ['--bg-surface-1', '表面层级档（当前未消费，保留给分层卡片）'],
  ['--bg-surface-3', '表面层级档（当前未消费，保留给分层卡片）'],
  ['--glass-blur-faint', '液态玻璃模糊三档之一（当前只消费 --glass-blur 主档，保留弱/中档）'],
  ['--glass-blur-soft', '液态玻璃模糊三档之一（当前只消费 --glass-blur 主档，保留弱/中档）'],
  ['--glass-blur-strong', '液态玻璃模糊三档之一（当前只消费 --glass-blur 主档，保留强档）'],
  ['--lg-glass-fg', '液态玻璃前景状态槽（当前未消费，保留给运行时材质调试）'],
  ['--lg-mx', '液态玻璃指针位置状态槽（JS 写入、样式当前未消费）'],
  ['--lg-my', '液态玻璃指针位置状态槽（JS 写入、样式当前未消费）'],
  // 语义色/交互态：保留档
  ['--accent-glow', 'accent 发光态（当前未接入，保留交互态档）'],
  ['--accent-press', 'accent 按下态（当前未接入，保留交互态档）'],
  // 受保护色一族：U-F1b 删掉 ds.css 的 .badge.system/.protected 死规则后整族零消费。
  // 整族删除属 U-F1a-L01（死 token 24 个）射程，且要同步 TRIPLET_BASES 与浅底预期值表，
  // 故本批先登记、不在收红阶段顺手删（AGENTS §4.1：登记必须写清由谁收口）。
  ['--protected', '受保护色主档（U-F1b 删死 badge 规则后整族零消费；待 U-F1a-L01 连同 -soft/-rgb 一并删）'],
  ['--protected-rgb', '受保护色 RGB 档（当前 UI 未使用；与 --protected 同值）'],
  ['--protected-soft', '受保护色浅染档（当前 UI 未使用；与 --protected 同值）'],
  // 尺寸/阴影：兼容或预留档
  ['--radius-xl', '圆角兼容别名（14px，全仓零引用；保留旧样式兼容）'],
  ['--fs-page-title', '页面标题字号档（当前未消费，保留字号表档位）'],
  ['--shadow-island-flyout', '浮岛浮层阴影档（当前未消费，保留浮层阴影）'],
  ['--shadow-tooltip', '提示气泡阴影档（当前未消费，保留提示阴影）'],
]);

const deadTokens = [...defined].filter((n) => !refs.has(n) && !DEAD_TOKEN_ALLOW.has(n)).sort();
const staleDead = [...DEAD_TOKEN_ALLOW.keys()].filter((n) => !defined.has(n) || refs.has(n));
if (deadTokens.length || staleDead.length) {
  for (const n of deadTokens) console.log(`✗ 未登记的零消费 token：${n}（定义于 ${declaredIn.get(n)}）`);
  for (const n of staleDead) console.log(`✗ 死 token 登记已失效（已有消费方或定义被删）：${n}`);
  console.log(`\n反向棘轮缺口：${deadTokens.length} 个未登记 + ${staleDead.length} 个失效登记`);
  process.exit(1);
}
console.log(`✓ 反向棘轮：${defined.size} 个定义中零消费 ${DEAD_TOKEN_ALLOW.size} 条均有理由`);

// ---- 三值同步（T1d-M05）：--x ⇄ --x-rgb ⇄ --x-soft 的三通道必须同源 ----
const TRIPLET_BASES = ['--warning', '--success', '--danger', '--info', '--protected'];
function judgeTriplets(defs) {
  const bad = [];
  for (const base of TRIPLET_BASES) {
    const hex = defs[base];
    const rgb = defs[`${base}-rgb`];
    const soft = defs[`${base}-soft`];
    if (!hex || !rgb || !soft) {
      bad.push(`${base} 缺 hex/-rgb/-soft 之一`);
      continue;
    }
    const hm = hex.match(/^#([0-9a-f]{6})$/i);
    if (!hm) {
      bad.push(`${base} 不是 6 位 hex：${hex}`);
      continue;
    }
    const want = [0, 2, 4].map((i) => parseInt(hm[1].slice(i, i + 2), 16)).join(',');
    const gotRgb = rgb.split(',').map((x) => x.trim()).join(',');
    if (want !== gotRgb) bad.push(`${base}-rgb=${rgb} 与 ${hex} 不同源`);
    const sm = soft.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i);
    if (!sm) bad.push(`${base}-soft 不是 rgba()：${soft}`);
    else if ([sm[1], sm[2], sm[3]].join(',') !== want) bad.push(`${base}-soft=${soft} 与 ${hex} 不同源`);
  }
  return bad;
}
const tripletProblems = [];
{
  const defsOf = (block) => {
    const out = {};
    for (const m of block.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) out[m[1]] = m[2].trim();
    return out;
  };
  const mainCssText = blankComments(readFileSync(join(REPO_ROOT, 'src', 'styles', 'main.css'), 'utf8'));
  const rootM = mainCssText.match(/:root\s*\{([\s\S]*?)\}/);
  const lightM = mainCssText.match(/\.theme-light\s*\{([\s\S]*?)\}/);
  if (!rootM || !lightM) {
    tripletProblems.push('theme token 块解析失败（:root / .theme-light 未找到）');
  } else {
    tripletProblems.push(...judgeTriplets(defsOf(rootM[1])));
    tripletProblems.push(...judgeTriplets(defsOf(lightM[1])));
  }
  // 对照：一个错三元组必须判红、干净样本必须放行。
  const good = {
    '--warning': '#F0B24D', '--warning-rgb': '240, 178, 77', '--warning-soft': 'rgba(240, 178, 77, 0.14)',
    '--success': '#3DBE7B', '--success-rgb': '61, 190, 123', '--success-soft': 'rgba(61, 190, 123, 0.14)',
    '--danger': '#F0524D', '--danger-rgb': '240, 82, 77', '--danger-soft': 'rgba(240, 82, 77, 0.14)',
    '--info': '#4DA3F0', '--info-rgb': '77, 163, 240', '--info-soft': 'rgba(77, 163, 240, 0.14)',
    '--protected': '#6A45D6', '--protected-rgb': '106, 69, 214', '--protected-soft': 'rgba(106, 69, 214, 0.1)',
  };
  const bad = { ...good, '--danger-rgb': '240, 82, 78' };
  if (judgeTriplets(good).length !== 0 || judgeTriplets(bad).length !== 1) {
    console.error('✗ 三值同步判定器自检失败（干净样本误报 / 错三元组未判红）');
    process.exit(1);
  }
}
if (tripletProblems.length) for (const p of tripletProblems) console.log(`✗ 三值同步：${p}`);

if (!bad.length && !radiusBad.length && !curveBad.length && !tripletProblems.length) {
  console.log('✓ 全部引用的自定义属性都有定义（无静默 fallback、无被丢弃的声明）');
  process.exit(0);
}

for (const name of bad) {
  const sites = refs.get(name);
  const noFallback = sites.filter((s) => !s.hasFallback).length;
  console.log(`✗ ${name} 无定义 —— ${sites.length} 处引用：${sites.map((s) => s.at).join(', ')}`);
  console.log(`  ${noFallback ? `其中 ${noFallback} 处连 fallback 都没有 ⇒ 整条声明被解析器丢弃（功能静默消失）` : '全部恒吃 fallback ⇒ token 被架空'}`);
}
console.log(`\n${bad.length} 个未定义的自定义属性被引用（v2-L6 类缺陷）${radiusBad.length ? `；${radiusBad.length} 处圆角违档（v2 批次 D4）` : ''}${curveBad.length ? `；${curveBad.length} 处动效曲线越集（F5-G-5）` : ''}${tripletProblems.length ? `；${tripletProblems.length} 处三值不同步（T1d-M05）` : ''}`);
process.exit(1);
