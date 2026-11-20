// check-css-tokens.mjs —— 「引用了未定义的自定义属性」的机器断言（审查 v2-L6）
//
// 为什么要这条门禁：门禁上线前 main.css 里存在 `var(--bg-elev)` / `var(--border-soft)`
// （2026-11 复核实测现盘已归零；现存计数以现算为准：
// `rg -n "var\(--bg-elev\)|var\(--border-soft\)" src/styles/main.css`）——
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
import { blankNonCode } from './lib/src-scan.mjs';

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

// T1d-L03：扫描面地板。`src/styles` 少一份 CSS 时，定义面塌缩会让「引用−定义」整片变红
// （方向对但不是本门禁想说的话），而圆角/曲线两段会静默打印 ✓ —— 0 对象的绿不算通过。
const CSS_FLOOR = 4;
if (cssFiles.length !== CSS_FLOOR) {
  console.error(`✗ 输入面：src/styles 只找到 ${cssFiles.length} 份 CSS（应 ${CSS_FLOOR}）⇒ token/圆角/曲线判据失明，先修输入面再谈合规`);
  process.exit(1);
}

/** 把 CSS 块注释替换成等长空白：偏移量不变，报出来的行号才对得上原文件 */
const blankComments = (text) => blankNonCode(text, 'css', { keepStrings: true });

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
// T1d-M07：JS 内联圆角（style 模板串里的 `border-radius:2px` 与 `borderRadius: '6px'`）。
// 内联样式是渲染层真实生效的圆角，只扫 CSS 等于把绕过 token 的逃逸口留在射程外。
function jsRadiusViolations(text, rel) {
  const out = [...radiusViolations(text, rel)];
  for (const m of text.matchAll(/\bborder(?:Top|Right|Bottom|Left)?Radius\s*[:=]\s*(['"`])([^'"`]*)\1/g)) {
    for (const pxm of m[2].matchAll(/(\d+(?:\.\d+)?)px/g)) {
      const px = Number(pxm[1]);
      if (px >= 90) continue;
      if (px < 4) out.push(`${rel} borderRadius: ${px}px（低于 badge 档 4px，禁字面值，走 var(--radius-badge)）`);
      else if (![4, 6, 8, 10, 14].includes(px)) out.push(`${rel} borderRadius: ${px}px（不在档位 4/6/8/10/14）`);
    }
  }
  return out;
}
// T1d-M07 颜色侧：用户可见的颜色属性（color/background*/border-color/fill/stroke）
// 出现颜色字面量即命中。var() 的 fallback 与 rgba(var(--x-rgb), a) 不算硬编码；
// 既有刻意设计登记在 COLOR_ALLOW，每条必须唯一命中（登记腐烂双向判红）。
const COLOR_PROPS = new Set(['color', 'background', 'background-color', 'border-color', 'fill', 'stroke']);
const COLOR_ALLOW = [
  // LiteBox 是图片对比专用独立调色板（纯黑底/白色控件），AGENTS §2 明确保留，整文件登记。
  { file: 'src/styles/litebox.css', fileWide: true, why: 'LiteBox 图片对比独立调色板（纯黑底/白色控件，AGENTS §2 刻意设计）' },
  { file: 'src/styles/main.css', anchor: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent)', why: '进度条流光高光（动效前景，非容器表面）' },
  { file: 'src/styles/main.css', anchor: 'color-mix(in srgb, var(--bg-app) 60%, rgba(0, 0, 0, 0.4))', why: '全屏遮罩的压暗层（叠加在主题底上）' },
  { file: 'src/styles/main.css', anchor: 'background: rgba(255, 255, 255, 0.28)', why: '按钮涟漪高光（动效前景）' },
  { file: 'src/styles/main.css', anchor: 'rgba(255, 255, 255, .38)', why: '启动页独立覆盖层的白色暗角（不随玻璃皮肤联动）' },
  { file: 'src/styles/main.css', anchor: 'background: rgba(255, 255, 255, .78)', why: '启动页徽章底色（启动页独立调色板）' },
  { file: 'src/styles/main.css', anchor: 'color: #fff', why: '启动页进入按钮文字（启动页独立调色板）' },
  { file: 'src/styles/main.css', anchor: 'background: rgba(0, 0, 0, 0.04)', why: 'win-inactive 纱（后绘制覆盖层，不破坏玻璃采样）' },
  { file: 'src/styles/main.css', anchor: 'background: #ffffff', why: '滑块旋钮恒白（保证任意强调色/壁纸上可见）' },
  // 表面实色化（2026-11-21）摘除的条目：液态玻璃白纱、electron-mica 恒浅色标题栏回退、
  // 四块材质样块渐变与底色、玻璃边框高光 0.55 —— 对应源码已退役，登记只减不增。
];

/** 去掉 var(...) 与其 fallback、以及 rgba(var(--x-rgb), a) 整段，剩下的才是硬编码色。 */
function stripVarColors(value) {
  return String(value)
    .replace(/rgba?\(\s*var\([^)]*\)[^)]*\)/gi, '')
    .replace(/var\([^)]*\)/gi, '');
}

/** CSS 声明级颜色扫描：返回 { line, prop, value, text }[]。 */
function colorViolations(text, rel) {
  const out = [];
  for (const m of text.matchAll(/([-\w]+)\s*:\s*([^;{}]+)/g)) {
    if (m[1].startsWith('--')) continue;
    if (!COLOR_PROPS.has(m[1].toLowerCase())) continue;
    const value = m[2].trim();
    if (!value) continue;
    const rest = stripVarColors(value);
    if (!/#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)/.test(rest)) continue;
    out.push({ line: lineOf(text, m.index), prop: m[1], value, text: m[0] });
  }
  return out;
}

/** JS/HTML 内联样式里的颜色字面量（token fallback 不算）。 */
function inlineColorViolations(text, rel) {
  const out = [];
  let line = 0;
  for (const raw of text.split('\n')) {
    line++;
    const t = raw.trim();
    if (!t || t.startsWith('//') || t.startsWith('*') || (t[0] === '/' && t[1] === '*')) continue;
    if (/cssVar\(|getCssColor\(/.test(raw)) continue;
    // T1d-L07：`<meta name="theme-color" content="#…">` 与
    // `setAttribute('content', '#…')` 原先不入网 —— 它们同样是把颜色写死在代码里。
    // 这两类命中后交由「主题色单源」判据裁决（必须等于 --bg-app），不在这里直接判红：
    // 4 份 HTML 的静态 meta 是合法载体，需要的是「与 token 对拍」而不是「禁写」。
    const metaThemeColor = /<meta\s+name="theme-color"\s+content="(#[0-9a-fA-F]{3,8})"/i.exec(raw);
    if (metaThemeColor) {
      out.push({ line, prop: 'theme-color', value: metaThemeColor[1], text: t, metaThemeColor: true });
      continue;
    }
    const setAttrThemeColor = /setAttribute\(\s*['"]content['"]\s*,\s*['"](#[0-9a-fA-F]{3,8})['"]/i.exec(raw);
    if (setAttrThemeColor) {
      out.push({ line, prop: 'theme-color', value: setAttrThemeColor[1], text: t, metaThemeColor: true });
      continue;
    }
    const isProp = /(?:^|[;{'"`\s])(color|background|background-color|border-color|fill|stroke)\s*:/i.test(raw)
      || /\.style\.(color|background|backgroundColor|borderColor|fill|stroke)\s*=/i.test(raw);
    if (!isProp) continue;
    const rest = stripVarColors(raw);
    if (!/#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)/.test(rest)) continue;
    out.push({ line, prop: 'inline', value: t, text: t });
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
  // T1d-M07 对照：HTML 串里的 CSS 形态与 JS 赋值形态都要命中；合法档位与变量放行。
  const jsInline = jsRadiusViolations('el.style = "border-radius:2px"', 'fake.js').length;
  const jsAssign = jsRadiusViolations("el.style.borderRadius = '3px';", 'fake.js').length;
  const jsOk = jsRadiusViolations("el.style.borderRadius = '6px'; el.style = 'border-radius:var(--radius-badge)'", 'fake.js').length;
  const radiusOk = r(5) === 1 && r(2) === 1 && r(8) === 0 && r(999) === 0 && r(10) === 0 && rMulti === 2
    && jsInline === 1 && jsAssign === 1 && jsOk === 0;
  const u = (refs, defined, allow = new Set()) => undeclaredTokenRefs(refs, defined, allow);
  const undefOk =
    u(new Map([['--ghost', []]]), new Set(), new Set()).length === 1 &&
    u(new Map([['--real', []]]), new Set(['--real']), new Set()).length === 0 &&
    u(new Map([['--allowed', []]]), new Set(), new Set(['--allowed'])).length === 0;
  // T1d-M07 颜色侧对照：裸色必红；var()、var fallback、rgba(var()) 与 token 定义放行。
  const colorHit = colorViolations('.x { color: #123456; }', 'fake.css').length === 1;
  const colorVar = colorViolations('.x { color: var(--fg); }', 'fake.css').length === 0;
  const colorFallback = colorViolations('.x { color: var(--fg, #123456); }', 'fake.css').length === 0;
  const colorRgbVar = colorViolations('.x { background: rgba(var(--x-rgb), .1); }', 'fake.css').length === 0;
  const colorToken = colorViolations(':root { --x: #123456; }', 'fake.css').length === 0;
  const inlineHit = inlineColorViolations("el.style.color = '#123456';", 'fake.js').length === 1;
  const colorOk = colorHit && colorVar && colorFallback && colorRgbVar && colorToken && inlineHit;
  const ease = new Set(['0.111,0.222,0.333,1']);
  const cBad = curveOffenders('.x { a: cubic-bezier(0.4,0,0.2,1); }', ease).length;
  const cOk = curveOffenders('.x { a: cubic-bezier(0.111, 0.222, 0.333, 1); }', ease).length;
  // 写入未消费五向，各自独立：① 死槽未登记必红 ② 样式侧真吃了不红 ③ 登记豁免不红
  // ④ 豁免项已被样式侧消费 ⇒ 登记失效 ⑤ 豁免项的写入点没了 ⇒ 登记失效
  const j1 = judgeWriteUnconsumed(new Set(['--dead']), new Set(), new Set());
  const j2 = judgeWriteUnconsumed(new Set(['--used']), new Set(['--used']), new Set());
  const j3 = judgeWriteUnconsumed(new Set(['--exempt']), new Set(), new Set(['--exempt']));
  const j4 = judgeWriteUnconsumed(new Set(['--exempt']), new Set(['--exempt']), new Set(['--exempt']));
  const j5 = judgeWriteUnconsumed(new Set(), new Set(), new Set(['--gone']));
  const writeOk = j1[0].join() === '--dead' && j1[1].length === 0
    && j2[0].length === 0 && j2[1].length === 0
    && j3[0].length === 0 && j3[1].length === 0
    && j4[0].length === 0 && j4[1].join() === '--exempt'
    && j5[0].length === 0 && j5[1].join() === '--gone';
  if (!radiusOk || !undefOk || !writeOk || !colorOk || cBad !== 1 || cOk !== 0) {
    console.error(`✗ 正向对照失败：圆角=${radiusOk} 未定义引用=${undefOk} 写入未消费=${writeOk} 颜色=${colorOk} 曲线越集=${cBad}（应 1） 曲线放行=${cOk}（应 0）——五组判定器至少一组失灵`);
    process.exit(1);
  }
  console.log('✓ 判定器自检：圆角档位 / 未定义引用 / 写入未消费 / 硬编码颜色 / 动效曲线 五组合成样本全对');
}

const defined = new Set();     // 定义面
const declaredIn = new Map();  // 名字 -> 首个定义位置（报错时给读者一个去处）
const refs = new Map();        // 名字 -> [{ at, hasFallback }]
// 第三维度（v7.2 P1 · U-F1a-L08）：JS 运行期**写入**的名字集合，与「CSS 侧是否真吃这个变量」
// 分开统计。为什么不能只看现有两个方向：定义面把 `setProperty('--x')` 也算定义，于是
// 「JS 写、CSS 从不读」的死跨语言 API 在正向差集（引用−定义）里根本不存在，
// 在反向棘轮（定义−引用）里只要登记过就放行 —— `--lg-mx/--lg-my` 就是这么绿了很久的。
const writeNames = new Set();
const cssRefs = new Set();     // 只由 src/styles/*.css 的 var() 填充（JS getPropertyValue 不算消费方）

function collect(text, re, fn) {
  for (const m of text.matchAll(re)) fn(m);
}

function addDefinition(name, at, isWrite = false) {
  if (isWrite) writeNames.add(name);
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
const blankJsComments = (text) => blankNonCode(text, 'js', { keepStrings: true });
function blankHtmlComments(text) {
  return text.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, ' '));
}
for (const file of [...jsFiles, ...htmlFiles]) {
  const raw = readFileSync(file, 'utf8');
  const kind = file.slice(-4).toLowerCase();
  const text = kind === '.js' ? blankJsComments(raw) : kind === 'html' ? blankHtmlComments(raw) : raw;
  const rel = file.slice(REPO_ROOT.length + 1).replace(/\\/g, '/');
  collect(text, RE_SET, (m) => addDefinition(m[1], `${rel}:${lineOf(text, m.index)}`, true));
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
  // 引用面同样只认可执行代码（T1d-L02/L03）：CSS 去块注释；JS 复用定义面的 blankJsComments
  // （它与「写名面注释行不算证据」同一口径，正则字面量的 `\/\/` 有前导反斜杠保护）；
  // HTML 去 `<!-- -->`。此前 JS/HTML 注释里的 var(--x) 会被算作真实引用，反向棘轮
  // 于是可被一行注释喂活 —— 与定义面的口径自相矛盾。
  const isCss = rel.endsWith('.css');
  const text = isCss ? blankComments(raw) : rel.endsWith('.js') ? blankJsComments(raw) : blankHtmlComments(raw);
  for (const m of text.matchAll(RE_VAR)) {
    // var() 的 fallback 判据：紧跟名字之后的第一个分隔符是逗号（不是括号）才算有兜底
    const hasFallback = /^\s*,/.test(text.slice(m.index + m[0].length));
    addReference(m[1], `${rel}:${lineOf(text, m.index)}`, hasFallback);
    // 只有 `.css` 里的 var() 才算「样式侧真吃了这个变量」：JS 的 getPropertyValue 读回来
    // 只可能在脚本里做算术，不产生样式，槽依然是死的 —— 那正是本档要抓的形态。
    if (isCss) cssRefs.add(m[1]);
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
// T1d-M07：JS 内联圆角同档位（剥注释后判，注释里的史实不算）。
for (const file of jsFiles) {
  const rel = file.slice(REPO_ROOT.length + 1).replace(/\\/g, '/');
  radiusBad.push(...jsRadiusViolations(blankJsComments(readFileSync(file, 'utf8')), rel));
}

// T1d-M07 颜色侧：用户可见颜色属性不得出现未登记的硬编码色。
const colorBad = [];
const colorHits = [];

// ==================== P3 C-01..C-04 新增判据 ====================
// 本段落补齐五组判据，逐条对应 P3 施工卡的一项验收；每组都带注入反例的对照自检。
//   ① 同选择器重复圆角：同选择器（同媒体上下文）出现两个不同圆角值 → 红
//   ② ds.css 组件层纪律：圆角/浮层投影/字号三处不得再写字面量 → 红
//   ③ CSS 版式：`}` 与 `@media` 不得紧贴同一行 → 红
//   ④ 主题色单源：4 份 HTML 的 theme-color 必须等于 --bg-app，JS 不得写死 → 红
//   ⑤ 动效 token 对拍：xtable.js 的 duration/easing 必须等于 --duration-slow/--ease-standard → 红

// 主题色真源：main.css 的 .theme-light 段里的 --bg-app（应用恒浅色，取浅色档）。
const MAIN_CSS_TEXT = readFileSync(join(REPO_ROOT, 'src', 'styles', 'main.css'), 'utf8');
const THEME_BG_APP = (() => {
  const block = /\.theme-light\s*\{([\s\S]*?)\n\}/.exec(blankComments(MAIN_CSS_TEXT));
  const m = block && /--bg-app:\s*(#[0-9a-fA-F]{3,8})/.exec(block[1]);
  return m ? m[1] : '';
})();
for (const file of cssFiles) {
  const rel = file.slice(REPO_ROOT.length + 1).replace(/\\/g, '/');
  colorHits.push(...colorViolations(blankComments(readFileSync(file, 'utf8')), rel).map((h) => ({ ...h, rel })));
}
for (const file of jsFiles) {
  const rel = file.slice(REPO_ROOT.length + 1).replace(/\\/g, '/');
  colorHits.push(...inlineColorViolations(blankJsComments(readFileSync(file, 'utf8')), rel).map((h) => ({ ...h, rel })));
}
for (const file of htmlFiles) {
  const rel = file.slice(REPO_ROOT.length + 1).replace(/\\/g, '/');
  colorHits.push(...inlineColorViolations(blankHtmlComments(readFileSync(file, 'utf8')), rel).map((h) => ({ ...h, rel })));
}
const colorAllowCount = new Map(COLOR_ALLOW.map((a, i) => [i, 0]));
for (const h of colorHits) {
  // T1d-L07 主题色单源：4 份 HTML 的静态 meta 合法，但必须与 --bg-app 同值；
  // JS 侧写死主题色（setAttribute('content', '#…')）一律红 —— 它应当从计算样式读。
  if (h.metaThemeColor) {
    if (h.rel.endsWith('.html')) {
      if (h.value.toLowerCase() !== THEME_BG_APP.toLowerCase()) {
        colorBad.push(`${h.rel}:${h.line} theme-color=${h.value} 与 --bg-app=${THEME_BG_APP} 不等（标题栏底色必须与 token 同源）`);
      }
      continue;
    }
    colorBad.push(`${h.rel}:${h.line} theme-color 写死为 ${h.value}（必须从 --bg-app 计算样式读）`);
    continue;
  }
  const idx = COLOR_ALLOW.findIndex((a) => a.file === h.rel && (a.fileWide || h.text.includes(a.anchor)));
  if (idx >= 0) {
    colorAllowCount.set(idx, colorAllowCount.get(idx) + 1);
    continue;
  }
  colorBad.push(`${h.rel}:${h.line} ${h.value}（未登记的硬编码颜色）`);
}
for (const [i, a] of COLOR_ALLOW.entries()) {
  const n = colorAllowCount.get(i);
  const okCount = a.fileWide ? n >= 1 : n === 1;
  if (!okCount) colorBad.push(`COLOR_ALLOW 条目${n === 0 ? '失效（未命中）' : `重复命中 ${n} 处`}：${a.file} ${a.fileWide ? '（整文件）' : a.anchor}`);
}
console.log(`颜色纪律：${colorBad.length ? `${colorBad.length} 处未登记/登记失效` : `✓ ${colorHits.length} 处既有刻意设计均有登记`}`);
for (const c of colorBad) console.log(`✗ ${c}`);

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
    const text = blankNonCode(readFileSync(join(jsDir, f), 'utf8'), 'js', { keepStrings: true });
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

// ---- 数值双真源逐值对拍（P3-5 / F5-G-3）已随玻璃磨砂链退役（2026-11-21）----
// 原 --glass-blur ⇄ ds.GLASS_MAX_BLUR_PX 对拍随 token 与 ds 常量一并删除；
// 壁纸层 --bg-blur 由 theme/pathbinding 运行时写入、上限真源 ds.WALLPAPER_MAX_BLUR_PX，
// 无静态 CSS 定义面，不在静态对拍内（如实标注）。

// ---- 反向棘轮（T1d-M01）：定义但全仓零消费的 token 必须逐条登记理由 ----
// 与 ALLOW_UNDECLARED（引用无定义）方向相反；新增死 token 不在表内即红。
// 零消费 token 的登记台账（反向棘轮：定义了但全仓无 `var()` 消费的档位）。
// v7.2 P1 · U-F1a-L01 / U-F1b-L02（2026-10-22）整批退役 27 条：这些档位已从 `main.css`
// 定义面删除，登记留在表里会被下一条 `staleDead` 判红 —— 而「判红」正是这条断言存在的意义
// （登记必须与盘上现状同步，否则台账会变成一堆「理由」的化石）。
// （2026-10-25 D 轮：`--accent-press` 已从本表摘掉 —— 它被 `.checkbox.checked` /
//  `.checkbox.indeterminate` 消费了，P2-D 勾形对比度修复用它压出 4.14:1 / 8.24:1，
//  真机 computed 实测 rgb(77,61,168)。留在表里会被 staleDead 判红，正是这条棘轮的意义。）
// （2026-11-21：`--accent-glow` 已从本表摘掉 —— 提案 V1 落地为侧栏选中项图标辉光
//  （.sidebar .nav-item.active > .nav-icon 的 drop-shadow 消费），不再是「等接入」的预留档。）
const DEAD_TOKEN_ALLOW = new Map([]);

const deadTokens = [...defined].filter((n) => !refs.has(n) && !DEAD_TOKEN_ALLOW.has(n)).sort();
const staleDead = [...DEAD_TOKEN_ALLOW.keys()].filter((n) => !defined.has(n) || refs.has(n));
if (deadTokens.length || staleDead.length) {
  for (const n of deadTokens) console.log(`✗ 未登记的零消费 token：${n}（定义于 ${declaredIn.get(n)}）`);
  for (const n of staleDead) console.log(`✗ 死 token 登记已失效（已有消费方或定义被删）：${n}`);
  console.log(`\n反向棘轮缺口：${deadTokens.length} 个未登记 + ${staleDead.length} 个失效登记`);
  process.exit(1);
}
console.log(`✓ 反向棘轮：${defined.size} 个定义中零消费 ${DEAD_TOKEN_ALLOW.size} 条均有理由`);

// ---- 写入未消费（v7.2 P1 · U-F1a-L08）：JS `setProperty` 写进 DOM、CSS 侧从不 `var()` 读 ----
// 与上面两档的分工：正向差集管「引用了却没定义」，反向棘轮管「定义了却没人引用」，
// 本档管**第三个维度**「写了但样式不吃」。前两个方向都看不见死跨语言 API：`setProperty`
// 把名字算进了定义面，于是「JS 写、CSS 从不读」既不在引用−定义里，也能靠登记在定义−引用里放行。
// 为什么判红而不做告警档：AGENTS §4.1 的口径是恒绿断言视同没写；死 API 长期挂账的代价是
// 每次事件都同步做一次无用的写入与读取（`--lg-mx/--lg-my` 当年就附赠一次 getBoundingClientRect）。
// 与 DEAD_TOKEN_ALLOW 分两张表不是重复实现同一判据：两者的问句不同（是否有 `var()` 消费
// vs 是否有样式侧消费），同一条豁免要成立必须在各自的问句下写清理由。
// 2026-10-22 用户裁定删除自定义强调色链路（F1a-U02）后，JS 侧对 `--accent-glow` /
// `--accent-press` 的写入点整条消失 ⇒ 这两条「写入未消费」豁免**已失效**，必须删掉
// （留着会被 stale 判据判红，也正好说明这条棘轮在工作）。它们作为**定义**仍零消费，
// 所以仍在 DEAD_TOKEN_ALLOW 里登记——两张表问的是不同的问题，不能互相顶替。
const WRITE_UNCONSUMED = new Map([
]);

/** 纯函数：返回 [未登记的「写入未消费」, 已失效的登记]，与自检共用同一实现（§5.16） */
function judgeWriteUnconsumed(writes, cssConsumed, allow) {
  const bad = [...writes].filter((n) => !cssConsumed.has(n) && !allow.has(n)).sort();
  const stale = [...allow].filter((n) => !writes.has(n) || cssConsumed.has(n)).sort();
  return [bad, stale];
}
{
  const [wBad, wStale] = judgeWriteUnconsumed(writeNames, cssRefs, new Set(WRITE_UNCONSUMED.keys()));
  if (wBad.length || wStale.length) {
    for (const n of wBad) console.log(`✗ JS 写入但 CSS 从不消费：${n}（补样式消费方，或删写入点并撤登记）`);
    for (const n of wStale) console.log(`✗ 「写入未消费」登记已失效（写入点已删或样式侧已消费）：${n}`);
    console.log(`\n写入未消费缺口：${wBad.length} 个未登记 + ${wStale.length} 个失效登记`);
    process.exit(1);
  }
  console.log(`✓ 写入未消费：JS 写入 ${writeNames.size} 个自定义属性，样式侧无消费方的 ${WRITE_UNCONSUMED.size} 条均有登记理由（${[...WRITE_UNCONSUMED.keys()].join(' / ')}）`);
}

// ---- 三值同步（T1d-M05）：--x ⇄ --x-rgb ⇄ --x-soft 的三通道必须同源 ----
// `--protected` 一族已于 v7.2 P1 · U-F1a-L01 整族从 `main.css` 退役（ds.css 的死徽章规则
// 先删掉后整族零消费），故不再列入三元组基名表 —— 留在表里会让下一条断言去找已不存在的定义。
const TRIPLET_BASES = ['--warning', '--success', '--danger', '--info'];
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
    // 表面实色化（2026-11-21）后 -soft 不再是 rgba() 而是实色宿主的 color-mix：
    // 判据改为「染层基色必须是同名语义档、宿主必须是实色表面家族（--bg-card/--bg-app，
    // 暗色 danger-soft 因亮红对卡底不达 AA 用更深的 --bg-app，check-contrast A1 现算在案）」。
    const sm = soft.match(/^color-mix\(in srgb,\s*var\((--[\w-]+)\)\s+([\d.]+)%,\s*var\((--[\w-]+)\)\)$/i);
    if (!sm) bad.push(`${base}-soft 不是 color-mix(语义档 %, 实色宿主)：${soft}`);
    else if (sm[1] !== base) bad.push(`${base}-soft 染层基色是 ${sm[1]}，与 ${base} 不同源`);
    else if (sm[3] !== '--bg-card' && sm[3] !== '--bg-app') bad.push(`${base}-soft 宿主是 ${sm[3]}，必须是 --bg-card/--bg-app 家族`);
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
  // 对照：错三元组必须判红、干净样本（color-mix 形态）必须放行。
  const good = {
    '--warning': '#F0B24D', '--warning-rgb': '240, 178, 77', '--warning-soft': 'color-mix(in srgb, var(--warning) 14%, var(--bg-card))',
    '--success': '#3DBE7B', '--success-rgb': '61, 190, 123', '--success-soft': 'color-mix(in srgb, var(--success) 14%, var(--bg-card))',
    '--danger': '#F0524D', '--danger-rgb': '240, 82, 77', '--danger-soft': 'color-mix(in srgb, var(--danger) 14%, var(--bg-app))',
    '--info': '#4DA3F0', '--info-rgb': '77, 163, 240', '--info-soft': 'color-mix(in srgb, var(--info) 14%, var(--bg-card))',
  };
  const bad = { ...good, '--danger-rgb': '240, 82, 78' };
  const badHost = { ...good, '--info-soft': 'color-mix(in srgb, var(--info) 14%, var(--bg-base))' };
  if (judgeTriplets(good).length !== 0 || judgeTriplets(bad).length !== 1 || judgeTriplets(badHost).length !== 1) {
    console.error('✗ 三值同步判定器自检失败（干净样本误报 / 错三元组或错宿主未判红）');
    process.exit(1);
  }
}
if (tripletProblems.length) for (const p of tripletProblems) console.log(`✗ 三值同步：${p}`);

// ==================== P3 C-01..C-04：新增判据本体 ====================
// 逐条对应一张施工卡的验收项，全部能靠注入反例判红（见下方对照自检）。

/** 扫出 CSS 规则（按大括号配对，支持 @media 嵌套），返回 { ctx, prelude, body }。
 * ctx 是外层 @-rule 链：媒体查询里的响应式覆盖不算「同选择器二次声明」。 */
function cssRules(text) {
  const out = [];
  const walk = (src, ctx) => {
    let buf = '';
    let i = 0;
    while (i < src.length) {
      const ch = src[i];
      if (ch === '{') {
        const prelude = buf.trim();
        buf = '';
        let depth = 1;
        let j = i + 1;
        while (j < src.length && depth > 0) {
          if (src[j] === '{') depth++;
          else if (src[j] === '}') depth--;
          j++;
        }
        const body = src.slice(i + 1, j - 1);
        if (prelude.startsWith('@')) walk(body, ctx ? `${ctx}|${prelude}` : prelude);
        else out.push({ ctx, prelude, body });
        i = j;
        continue;
      }
      if (ch === '}') {
        buf = '';
        i++;
        continue;
      }
      buf += ch;
      i++;
    }
  };
  walk(text, '');
  return out;
}

/** 圆角档位表：`6px` 与 `var(--radius-small)` 视为同档，避免同义写法被当成冲突。 */
function radiusTokenTable(cssText) {
  const table = new Map();
  for (const m of cssText.matchAll(/--radius-([a-z-]+)\s*:\s*(\d+)px/g)) table.set(`${m[2]}px`, `--radius-${m[1]}`);
  return table;
}

/** 归一圆角取值。 */
function normalizeRadiusValue(value, pxToToken) {
  const v = value.trim();
  if (pxToToken.has(v)) return pxToToken.get(v);
  const varM = /^var\((--radius-[a-z-]+)\)$/.exec(v);
  return varM ? varM[1] : v;
}

/** ① 同选择器重复圆角（同一媒体上下文内出现两个不同圆角）→ 违例。 */
function cssRadiusDuplicateViolations(entries, pxToToken) {
  const out = [];
  for (const { rel, text } of entries) {
    const seen = new Map();
    for (const rule of cssRules(text)) {
      const m = rule.body.match(/border[a-z-]*radius\s*:\s*([^;}]+)/i);
      if (!m) continue;
      const value = normalizeRadiusValue(m[1], pxToToken);
      for (const sel of rule.prelude.split(',')) {
        const name = sel.trim().replace(/\s+/g, ' ');
        if (!name) continue;
        const key = `${rule.ctx}|${name}`;
        if (!seen.has(key)) seen.set(key, { value, rel, name });
        else if (seen.get(key).value !== value) {
          out.push(`${rel}: ${name} 同时出现 ${seen.get(key).value} 与 ${value}（同选择器两个圆角 = 后者静默改写前者）`);
        }
      }
    }
  }
  return out;
}

/** ② ds.css 组件层纪律：圆角走 token、浮层投影走 --shadow-*、字号走 --fs-*。 */
const DS_RADIUS_ALLOWED = new Set(['999px', '50%']);
const DS_SHADOW_ALLOWED = new Set(['0 1px 4px rgba(0, 0, 0, 0.35)']);
const DS_FONT_BARE_PX = new Set(['10px', '11.5px']);
function dsCssLiteralViolations(text) {
  const out = [];
  for (const rule of cssRules(text)) {
    for (const m of rule.body.matchAll(/(border[a-z-]*radius|box-shadow|font-size)\s*:\s*([^;}]+)/gi)) {
      const prop = m[1].toLowerCase();
      const value = m[2].trim();
      if (prop.startsWith('border') && prop.endsWith('radius')) {
        if (!/^var\(--radius-[a-z-]+\)$/.test(value) && !DS_RADIUS_ALLOWED.has(value)) {
          out.push(`ds.css ${prop}: ${value}（组件层圆角必须走 var(--radius-*)，胶囊/圆形除外）`);
        }
      } else if (prop === 'box-shadow') {
        if (!/^var\(--shadow-[a-z-]+\)$/.test(value) && !DS_SHADOW_ALLOWED.has(value)) {
          out.push(`ds.css box-shadow: ${value}（浮层投影必须走 var(--shadow-*)，控件投影需登记）`);
        }
      } else if (prop === 'font-size') {
        const bare = /^calc\(([\d.]+)px\s*\*\s*var\(--font-size-scale/.exec(value);
        if (!/^var\(--fs-[a-z-]+\)$/.test(value) && !(bare && DS_FONT_BARE_PX.has(`${bare[1]}px`))) {
          out.push(`ds.css font-size: ${value}（有字阶 token 的字号必须走 var(--fs-*)，无 token 的裸值需登记）`);
        }
      }
    }
  }
  return out;
}

/** ③ CSS 版式：`}` 与 `@media`/`@supports` 不得紧贴同一行。 */
function cssLayoutViolations(entries) {
  const out = [];
  for (const { rel, text } of entries) {
    text.split('\n').forEach((line, idx) => {
      if (/}\s*@(media|supports)\b/.test(line)) {
        out.push(`${rel}:${idx + 1} \`}\` 与 \`@media\` 紧贴同一行（闭合块与媒体查询之间须换行）`);
      }
    });
  }
  return out;
}

/** ⑤ 动效 token 对拍：xtable.js 的 duration/easing 必须等于 --duration-slow/--ease-standard。 */
function motionTokenViolations(jsText, rel, durationSlowMs, easeStandard) {
  const out = [];
  const dur = /duration:\s*(\d+)/.exec(jsText);
  if (dur && Number(dur[1]) !== durationSlowMs) {
    out.push(`${rel}: duration ${dur[1]}ms 与 --duration-slow ${durationSlowMs}ms 不等（改 token 后动画时长会静默漂移）`);
  }
  const ease = /easing:\s*'([^']+)'/.exec(jsText);
  if (ease) {
    const norm = (s) => s.replace(/\s+/g, '');
    if (norm(ease[1]) !== norm(easeStandard)) {
      out.push(`${rel}: easing ${ease[1]} 与 --ease-standard ${easeStandard} 不等`);
    }
  }
  return out;
}

const PX_TO_TOKEN = radiusTokenTable(MAIN_CSS_TEXT);
const CSS_ENTRIES = cssFiles.map((f) => ({
  rel: f.slice(REPO_ROOT.length + 1).replace(/\\/g, '/'),
  text: blankComments(readFileSync(f, 'utf8'))
}));

const radiusDupBad = cssRadiusDuplicateViolations(CSS_ENTRIES, PX_TO_TOKEN);
const dsLiteralBad = dsCssLiteralViolations(blankComments(readFileSync(join(REPO_ROOT, 'src', 'styles', 'ds.css'), 'utf8')));
const layoutBad = cssLayoutViolations(CSS_ENTRIES);
const durationSlowM = /--duration-slow:\s*(\d+)ms/.exec(MAIN_CSS_TEXT);
const easeStandardM = /--ease-standard:\s*(cubic-bezier\([^)]*\))/.exec(MAIN_CSS_TEXT);
const motionBad = durationSlowM && easeStandardM
  ? motionTokenViolations(
      readFileSync(join(REPO_ROOT, 'src', 'scripts', 'xtable.js'), 'utf8'),
      'src/scripts/xtable.js',
      Number(durationSlowM[1]),
      easeStandardM[1]
    )
  : ['main.css 解析不到 --duration-slow / --ease-standard（动效对拍失明）'];

console.log(`同选择器重复圆角：${radiusDupBad.length ? `${radiusDupBad.length} 处冲突` : '✓ 无同选择器双圆角'}`);
for (const v of radiusDupBad) console.log(`✗ ${v}`);
console.log(`ds.css 组件层字面量：${dsLiteralBad.length ? `${dsLiteralBad.length} 处违例` : '✓ 圆角/投影/字号全部走 token'}`);
for (const v of dsLiteralBad) console.log(`✗ ${v}`);
console.log(`CSS 版式：${layoutBad.length ? `${layoutBad.length} 处紧贴写法` : '✓ 无 `}@media` 紧贴'}`);
for (const v of layoutBad) console.log(`✗ ${v}`);
console.log(`动效 token 对拍：${motionBad.length ? `${motionBad.length} 处漂移` : '✓ xtable.js 时长/曲线与 token 一致'}`);
for (const v of motionBad) console.log(`✗ ${v}`);

// 新增判据的正向对照：每条断言「注入违例必红 / 合规必放行」，否则恒绿等于没写。
{
  const problems = [];
  const expect = (label, got, want) => {
    if (got !== want) problems.push(`${label}（期望 ${want}，实得 ${got}）`);
  };
  // ① 同选择器两次不同圆角必红；同值不算冲突
  expect('① 同选择器两次不同圆角判红',
    cssRadiusDuplicateViolations([{ rel: 's.css', text: '.a{border-radius:6px}\n.b{border-radius:14px}\n.a{border-radius:10px}' }], PX_TO_TOKEN).length > 0, true);
  expect('① 同选择器同值不判红',
    cssRadiusDuplicateViolations([{ rel: 's.css', text: '.a{border-radius:6px}\n.a{border-radius:var(--radius-small)}' }], PX_TO_TOKEN).length, 0);
  // ② ds.css 字面量必红；合规放行
  expect('② ds.css 圆角字面量判红', dsCssLiteralViolations('.x{border-radius:6px}').length > 0, true);
  expect('② ds.css 浮层投影字面量判红', dsCssLiteralViolations('.x{box-shadow:0 6px 18px rgba(0,0,0,.3)}').length > 0, true);
  expect('② ds.css 字号字面量判红', dsCssLiteralViolations('.x{font-size:12px}').length > 0, true);
  expect('② ds.css 合规写法放行',
    dsCssLiteralViolations('.x{border-radius:var(--radius-small);box-shadow:var(--shadow-flyout);font-size:var(--fs-meta)}').length, 0);
  // ③ 版式紧贴判红；换行放行
  expect('③ `}@media` 紧贴判红', cssLayoutViolations([{ rel: 's.css', text: '.a{color:red}@media (max-width:9px){' }]).length > 0, true);
  expect('③ 换行写法放行', cssLayoutViolations([{ rel: 's.css', text: '.a{color:red}\n\n@media (max-width:9px){' }]).length, 0);
  // ⑤ 动效对拍：漂移必红；一致放行
  expect('⑤ duration 漂移判红', motionTokenViolations("{duration: 320}", 'x.js', 280, 'cubic-bezier(0.23, 1, 0.32, 1)').length > 0, true);
  expect('⑤ easing 漂移判红', motionTokenViolations("{easing: 'cubic-bezier(0.4, 0, 0.2, 1)'}", 'x.js', 320, 'cubic-bezier(0.23, 1, 0.32, 1)').length > 0, true);
  expect('⑤ 完全一致放行', motionTokenViolations("{duration: 320, easing: 'cubic-bezier(0.23, 1, 0.32, 1)'}", 'x.js', 320, 'cubic-bezier(0.23, 1, 0.32, 1)').length, 0);
  if (problems.length) {
    console.error(`✗ 新增判据正向对照失败（恒绿断言视同没写）：\n  ${problems.join('\n  ')}`);
    process.exit(1);
  }
  console.log('✓ 新增判据正向对照 11 组全部命中（①~③、⑤ 注入违例必红 + 合规必放行）');
}

// ==================== 表面实色化防回流（S1–S4，方案 v1.6 §6.8，2026-11-21） ====================
// 退役只靠人记必然复发：叠加块回流、异层异色、写了不生效的死声明，肉眼都查不出来。
// 四条断言常驻，判据全部带可判红的合成对照（见下方自检）。
const solidBad = [];

/** 复合选择器的「主体」：按连接符切开后最后一段（`.a > .b::x` 的主体是 `.b`）。 */
const surfaceSubject = (seg) => seg.trim().split(/[\s>+~]+/).pop() || '';
/** 主体是否命中某表面（body / .layout / .titlebar；伪元素规则不计——那是装饰层不是表面本体）。 */
const surfaceHits = (prelude, re) =>
  prelude.split(',').some((seg) => !/::/.test(seg) && re.test(surfaceSubject(seg)));
const BODY_RULE = /^body(?:[.[:]|$)/;
const LAYOUT_RULE = /^\.layout(?:[.[:]|$)/;
const TITLEBAR_RULE = /^\.titlebar(?:[.[:]|$)/;
// 同层同色允许的 token 家族：--bg-app 与 --bg-base 两档同值（弹窗遮罩依赖 --bg-app 的独立名，
// main.css :root 注释在案），视为同一家族。
const SURFACE_FAMILY = /^var\(--(bg-base|bg-app)\)$/;
// 刻意透明的白名单：壁纸贯通（标题栏 / 布局层在壁纸激活时放行壁纸，方案 §3.2 层序）。
// 这些状态的 transparent 是「让画布/壁纸透出」的刻意设计，不是叠加块回流。
const SURFACE_SEE_THROUGH = /data-preset-bg|bg-image-on/;

/** 抽取规则块里的 background / background-color 声明（末条生效；shorthand 与 longhand 都收）。 */
function surfaceBackgrounds(ruleBody) {
  const out = [];
  for (const m of ruleBody.matchAll(/(?:^|[;{])\s*(background(?:-color)?)\s*:\s*([^;}]+)/g)) {
    out.push({ prop: m[1], value: m[2].trim() });
  }
  return out;
}

// ---- S1+S2：body / .layout / .titlebar 的底色必须实色且同源 ----
// S1（画布不透明）：出现 alpha<1 字面色 / color-mix(…, transparent) / transparent 即红。
// S2（同层同色）：底色必须是 SURFACE_FAMILY（--bg-base/--bg-app）；transparent 只许
//   出现在壁纸贯通白名单（data-preset-bg / bg-image-on）的规则里。
{
  for (const rel of ['src/styles/main.css', 'src/styles/main-pages.css']) {
    const rules = cssRules(blankComments(readFileSync(join(REPO_ROOT, rel), 'utf8')));
    for (const rule of rules) {
      const isBody = surfaceHits(rule.prelude, BODY_RULE);
      const isLayout = surfaceHits(rule.prelude, LAYOUT_RULE);
      const isTitlebar = surfaceHits(rule.prelude, TITLEBAR_RULE);
      if (!isBody && !isLayout && !isTitlebar) continue;
      for (const d of surfaceBackgrounds(rule.body)) {
        const v = d.value;
        // S1（画布不透明）：color-mix 混透明 / 字面 alpha<1 即红；bare transparent 归 S2 管辖
        const alphaM = /rgba?\(\s*[^()]*(?:\([^()]*\)[^()]*)*,\s*([\d.]+)\s*\)/i.exec(v);
        const alpha = alphaM ? parseFloat(alphaM[1]) : null;
        const semi = /color-mix\([^)]*transparent/i.test(v) || (alpha !== null && alpha < 1);
        if (semi) {
          solidBad.push(`S1 表面非实色：${rel} « ${rule.prelude} » { ${d.prop}: ${v} }`);
          continue;
        }
        // S2（同层同色）：transparent 只许出现在壁纸贯通白名单里；其余取值必须实色家族
        if (/^\s*transparent\s*$/i.test(v)) {
          if (!SURFACE_SEE_THROUGH.test(rule.prelude) && !isBody) {
            solidBad.push(`S2 异层透明：${rel} « ${rule.prelude} » { ${d.prop}: transparent }（非壁纸贯通白名单）`);
          }
          continue;
        }
        if (!SURFACE_FAMILY.test(v) && !/^var\(--/.test(v) && !/^color-mix\(/i.test(v)) {
          solidBad.push(`S2 异层异色：${rel} « ${rule.prelude} » { ${d.prop}: ${v} }（须为 --bg-base/--bg-app 家族）`);
        }
      }
    }
  }
}

// ---- S3 叠加族零回流：退役叠加 token / 材质类不得以任何生效声明回流（注释不算） ----
// 与「rg 归零」的验收等价，但机器常驻：加回一条 var(--lg-glass-floor) 必红。
const RETIRED_OVERLAY =
  /--lg-glass-floor|--lg-tint-|--lg-glass-border|--lg-glass-highlight|--mat-veil|--surface-alpha|--surface-tint|\.electron-mica|data-skin="glass"|--glass-blur|--glass-satur|--glass-bright|--aurora-veil/;
{
  const cssFiles = ['src/styles/main.css', 'src/styles/main-pages.css', 'src/styles/ds.css', 'src/styles/litebox.css'];
  const htmlFiles = ['src/index.html', 'src/models-window.html', 'src/process-manager-window.html', 'src/residue-window.html'];
  for (const rel of [...cssFiles, ...htmlFiles]) {
    const text = blankComments(readFileSync(join(REPO_ROOT, rel), 'utf8'));
    text.split('\n').forEach((line, i) => {
      if (RETIRED_OVERLAY.test(line)) solidBad.push(`S3 叠加族回流：${rel}:${i + 1} ${line.trim().slice(0, 90)}`);
    });
  }
}

// ---- S4 无死声明：background-image 末段必须是图像函数；颜色收尾 = 整条声明无效（§1.7 幽灵层） ----
// 「写了但没生效」肉眼查不出：body 的两条光晕当年就是这么静默失效的。
const IMAGE_TAIL = /^(none|url\(|linear-gradient\(|radial-gradient\(|conic-gradient\(|repeating-)/i;
// var() 引用已知颜色 token 家族 ⇒ 末段是颜色，整条声明无效（方案对照样本：`…, var(--bg-base)` 必红）；
// 其余 var 名（--glass-top-hi / --glass-sweep / --app-bg-image 等图像令牌）静态不可判，放行。
const COLOR_VAR_TAIL = /^var\(--(bg|fg|accent|success|warning|danger|info|surface|border|shadow|knob-bg)[\w-]*\)/;
const LITERAL_COLOR_TAIL = /^(#[0-9a-fA-F]{3,8}\b|rgba?\(|color-mix\()/i;
function backgroundImageTailViolations(ruleBody) {
  const out = [];
  for (const m of ruleBody.matchAll(/(?:^|[;{])\s*background-image\s*:\s*([^;}]+)/gi)) {
    const segs = [];
    let depth = 0, buf = '';
    for (const ch of m[1]) {
      if (ch === '(') depth++;
      if (ch === ')') depth--;
      if (ch === ',' && depth === 0) { segs.push(buf); buf = ''; continue; }
      buf += ch;
    }
    segs.push(buf);
    const tail = segs[segs.length - 1].trim();
    const imageish = IMAGE_TAIL.test(tail) || (/^var\(/.test(tail) && !COLOR_VAR_TAIL.test(tail));
    if (!imageish && (COLOR_VAR_TAIL.test(tail) || LITERAL_COLOR_TAIL.test(tail))) {
      out.push(`background-image 末段不是图像：${tail}`);
    }
  }
  return out;
}
{
  for (const rel of ['src/styles/main.css', 'src/styles/main-pages.css', 'src/styles/ds.css', 'src/styles/litebox.css']) {
    const rules = cssRules(blankComments(readFileSync(join(REPO_ROOT, rel), 'utf8')));
    for (const rule of rules) {
      for (const msg of backgroundImageTailViolations(rule.body)) {
        solidBad.push(`S4 死声明：${rel} « ${rule.prelude} » ${msg}`);
      }
    }
  }
}

{
  // 正向对照：合成样本必判红 / 合规样本放行（每条断言都能翻红才算数）。
  const expect = (name, got, want) => { if (got !== want) solidBad.push(`S 组对照失败：${name}（got ${got}，want ${want}）`); };
  // S1：半透明 body 必红；实色 var 放行
  {
    const rules = cssRules('body.electron-mica:not(.win-maximized) { background: rgba(15, 17, 21, 0.35) !important; }');
    const hit = rules.some((r) => surfaceHits(r.prelude, BODY_RULE) &&
      surfaceBackgrounds(r.body).some((d) => /rgba?\([^)]*,\s*0?\.35\s*\)/.test(d.value)));
    expect('S1 半透明 body 判红', hit, true);
    const ok = cssRules('body { background: var(--bg-base); }').every((r) =>
      surfaceBackgrounds(r.body).every((d) => SURFACE_FAMILY.test(d.value)));
    expect('S1 实色 body 放行', ok, true);
  }
  // S2：无壁纸状态的 .titlebar transparent 判红；壁纸白名单放行
  {
    const rules = cssRules('.titlebar { background: transparent; }');
    const hit = rules.some((r) => surfaceHits(r.prelude, TITLEBAR_RULE) &&
      surfaceBackgrounds(r.body).some((d) => /^\s*transparent\s*$/i.test(d.value)) &&
      !SURFACE_SEE_THROUGH.test(r.prelude));
    expect('S2 异层 transparent 判红', hit, true);
    const ok = cssRules('body[data-preset-bg] .titlebar { background: transparent; }').every((r) =>
      surfaceBackgrounds(r.body).every((d) => /^\s*transparent\s*$/i.test(d.value) && SURFACE_SEE_THROUGH.test(r.prelude)));
    expect('S2 壁纸贯通放行', ok, true);
  }
  // S3：回流样本判红；装饰层（spot/sweep/top-hi）与弹簧变量放行
  expect('S3 floor 回流判红',
    RETIRED_OVERLAY.test('.btn { background: linear-gradient(var(--lg-glass-floor), var(--lg-glass-floor)); }'), true);
  expect('S3 装饰层放行',
    RETIRED_OVERLAY.test('.card::after { background-image: var(--glass-spot), var(--glass-sweep); }'), false);
  // S4：颜色收尾判红；图像收尾放行
  expect('S4 颜色收尾判红',
    backgroundImageTailViolations('background-image: radial-gradient(1px, red), var(--bg-base);').length, 1);
  expect('S4 图像收尾放行',
    backgroundImageTailViolations("background-image: linear-gradient(180deg, rgba(247,248,251,.3), rgba(247,248,251,.55)), url('../a.jpg');").length, 0);
  expect('S4 none 收尾放行',
    backgroundImageTailViolations('background-image: none;').length, 0);
}

if (solidBad.length) {
  console.error('✗ 表面实色化防回流（S1–S4）缺口：');
  for (const s of solidBad) console.error(`  ${s}`);
}

if (
  !bad.length && !radiusBad.length && !curveBad.length && !tripletProblems.length && !colorBad.length
  && !radiusDupBad.length && !dsLiteralBad.length && !layoutBad.length && !motionBad.length && !solidBad.length
) {
  console.log('✓ 全部引用的自定义属性都有定义（无静默 fallback、无被丢弃的声明）；硬编码颜色均有登记');
  console.log('✓ 表面实色化防回流 S1–S4：画布实色 / 同层同色 / 叠加族零回流 / 无死声明（含 7 组可判红对照）');
  process.exit(0);
}

for (const name of bad) {
  const sites = refs.get(name);
  const noFallback = sites.filter((s) => !s.hasFallback).length;
  console.log(`✗ ${name} 无定义 —— ${sites.length} 处引用：${sites.map((s) => s.at).join(', ')}`);
  console.log(`  ${noFallback ? `其中 ${noFallback} 处连 fallback 都没有 ⇒ 整条声明被解析器丢弃（功能静默消失）` : '全部恒吃 fallback ⇒ token 被架空'}`);
}
console.log(`\n${bad.length} 个未定义的自定义属性被引用（v2-L6 类缺陷）${radiusBad.length ? `；${radiusBad.length} 处圆角违档（v2 批次 D4）` : ''}${curveBad.length ? `；${curveBad.length} 处动效曲线越集（F5-G-5）` : ''}${tripletProblems.length ? `；${tripletProblems.length} 处三值不同步（T1d-M05）` : ''}${colorBad.length ? `；${colorBad.length} 处硬编码颜色未登记（T1d-M07）` : ''}`);
process.exit(1);
