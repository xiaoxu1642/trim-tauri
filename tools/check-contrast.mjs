// check-contrast.mjs —— 对比度门禁（审查 v2-U1 闭环）
//
// 为什么需要它：U1「对比度」此前一直挂在「待真机/计算样式实测」，而项目**不使用 CDP**，
// 于是它永远没人算。实际上静态可算的部分占绝大多数：main.css 的颜色全是 token，
// 两个主题变量块（:root = 暗色默认 / .theme-light = 亮色）里的值都是字面量，
// 「背景 token × 前景 token」的对比度可以纯算，不需要 WebView。
//
// 三组断言：
//   A. 实底组合：同一规则内 `background: <底>` + `color: var(--x)`（两主题）≥ 4.5:1
//      A1  实底（合成后不透明）
//      A1b 纯图标/图形控件 ≥ 3:1（WCAG 1.4.11），登记制 + 双向棘轮
//      A2  浅染底 4.4~4.5 边界项，登记制 + 双向棘轮（非致命但带棘轮）
//   B. 正文组合：--fg-primary/secondary/tertiary × 页面底/卡片合成底（两主题）≥ 4.5:1
//   C. 覆盖率下限：算出来的组合数不得低于 BASELINE_MIN —— 防止选择器写法一变
//      就静默变成「0 组全通过」的假绿（本项目有假绿前科：v1 M13 / v2-M16）。
//      C2 逐文件地板：每份在扫描面里的 CSS 各自的组合数下限（见 SCAN_FLOOR）
//
// 扫描面（2026-10-03 L4 审查 L-28 收口后）：`main.css` + `ds.css` 两份。
// 解析失明（K1）与**覆盖面失明**（L-28）是两回事：K1 修的是「能算的算不出来」，
// L-28 修的是「压根没进扫描面 / 按 token 后缀整族跳过」。两者都要判红才算修完。
//
// 已知不覆盖（如实标注，不冒充已验）：
//   - ::before/::after 伪元素：本仓一律是装饰件（content:'' 或纯色圆点/竖条），
//     不承载文本，不适用 WCAG 文本对比度 —— 配对父级 color 只会产生误报，故直接跳过；
//   - hover/active 只改背景的规则：其前景按「去掉伪类后的基础选择器」回溯继承，
//     是**启发式**（CSS 真实级联更复杂），命中数计入 C 组但结论强度弱于 A/B；
//   - 运行时写入的色值（`pathbinding.js` 的自定义强调色、JS 内联 style）不在扫描面。
//
// 用法：node tools/check-contrast.mjs

import { readFileSync } from 'node:fs';

/**
 * 扫描面：**两份 CSS 都算**（审查 L-28，2026-10-03 L4 收口）。
 *
 * 原先只扫 main.css，ds.css 完全在射程外 —— 那是纯 CSS 盲区（不是 main.css 里解析
 * 不到，是根本没读那份文件）。ds.css 的 18 条 bg+fg 组合全是真实产品件：
 * 徽章六色（.ds-badge.ok/.warn/.bad/.neutral/.accent）+ 旧类别名后置覆盖 8 条
 * + .ds-tooltip + .ds-menu-item 四个态。任何一条将来写错 token 组合，
 * 旧门禁一律看不见。
 *
 * **各自解析、不合并**（与 CSS 真实加载序无关，只为解析干净）：
 * 主题变量表（`:root` / `.theme-light`）只在 main.css 里，合并会让 ds.css 的
 * 任何选择器都参与 theme-block 扫描，多一层「ds.css 里冒出个 :root 就污染主题表」
 * 的隐患。行号也因此天然是**文件内行号**，不需要跨文件偏移量 —— 合并方案要手工
 * 维护偏移，ds.css 一增删行就整体漂移（已实测踩过：拼 offsets 算出的
 * `ds.css:9793` 指向 main.css 第 9000 行，比不写行号更难查）。
 *
 * ds.css 必须在 main.css **之后加载**（其文件头明写），所以它的规则在级联里更晚，
 * 冲突时以它为准 —— 这与「先扫谁」无关，门禁只是把两者的组合各自算一遍。
 */
const CSS_FILES = [
  { label: 'main.css', path: new URL('../src/styles/main.css', import.meta.url) },
  { label: 'ds.css', path: new URL('../src/styles/ds.css', import.meta.url) },
];
// 剥离注释但**保留换行与字符数**：这样按 index 算出来的行号仍然准确，
// 且选择器不会被块前注释污染 —— 否则棘轮键「选择器|前景」会随注释文字改动而漂移
// （与 check-system-bin 的 file:line 漂移是同一类坑）。
const stripComments = (raw) => raw.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
// 每份文件独立成一份「带标签的解析原料」。THEME 变量表只取 main.css（见上方说明）。
const CSS_PARTS = CSS_FILES.map((f) => ({
  label: f.label,
  text: stripComments(readFileSync(f.path, 'utf8')),
}));
const MAIN = CSS_PARTS[0];
const LINES = MAIN.text.split('\n');
const lineRef = (file, lineNo) => `${file}:${lineNo}`;

const AA_NORMAL = 4.5;

// 算出来的组合数下限：低于它说明选择器/变量解析退化成了空集，而不是「真的都达标」
//
// 审查 L-28：这是**下限**棘轮（防退化）。收口 SOLID_SKIP 盲区 + 纳入 ds.css 后
// 现算 454 组（原先 278）—— 下限故意留在 30 不动，因为下限只能证明「没退化」，
// 证明不了「新收进来的那 176 组没被解析层悄悄吃掉」。那件事由下面
// SCAN_FLOOR 单独钉住。
const BASELINE_MIN = 30;
// 审查 L-28：**每一份**在扫描面里的 CSS 都必须至少产出 N 组组合。
// 为什么需要：LOWER 是总量下限，两份文件里若有一份整体解析失败（比如 ds.css
// 某次重构把 background 全改成 shorthand 之外的形式），总量仍可能靠 main.css
// 撑过 30 ⇒ 假绿。逐文件设地板才能把「某一整份失明」与「组合变少」区分开。
// 2026-10-03 现算：main.css 422 / ds.css 32（收口后）。
const SCAN_FLOOR = { 'main.css': 380, 'ds.css': 24 };

// ---------- 1. 两个主题变量块 ----------
function blockVars(startIdx) {
  const vars = new Map();
  for (let i = startIdx; i < LINES.length; i++) {
    const line = LINES[i];
    if (/^\}/.test(line)) break;
    const m = line.match(/^\s*(--[\w-]+)\s*:\s*([^;]+);/);
    if (m) vars.set(m[1], m[2].trim());
  }
  return vars;
}
// K1 失明源三（2026-10-03 L3 审查）：本仓 main.css 里有 **6 个** `:root` / `.theme-light`
// 块（:root 三处、.theme-light 三处）。CSS 语义是**同选择器的多个块按源码顺序层叠合并**，
// 而旧代码每遇一个块就 THEMES.push 一份 ⇒ 产出 6 个"主题"，其中 4 个是残缺块
// （如 8497 行只定义 --lg-glass-fg）。后果：
//   ① 主题数虚高，报告里"两主题"的口径名不副实；
//   ② 残缺块缺 --fg-primary 等主 token ⇒ parseColor 返回 null ⇒ 半数组合被静默跳过
//      （修复前 SKIPPED 现算 443 条的真实来源）。
// 现在按选择器合并；`.theme-light` 在 HTML 上与 `:root` 同时挂在 <html>，故以 :root 铺底
// 再叠加亮色自身的覆写（与浏览器级联一致）。核心 token 缺失直接判红，不允许继续跑。
const themeMap = new Map();
LINES.forEach((l, i) => {
  const m = l.match(/^(:root|\.theme-light)\s*\{/);
  if (!m) return;
  const name = m[1] === ':root' ? '暗色(:root)' : '亮色(.theme-light)';
  if (!themeMap.has(name)) themeMap.set(name, new Map());
  const target = themeMap.get(name);
  for (const [k, v] of blockVars(i + 1)) target.set(k, v);
});
const darkVars = themeMap.get('暗色(:root)') || new Map();
const THEMES = [...themeMap.entries()].map(([name, own]) => {
  if (name === '暗色(:root)') return { name, vars: new Map(own) };
  const merged = new Map(darkVars);
  for (const [k, v] of own) merged.set(k, v);
  return { name, vars: merged };
});
// 主题表解析退化的自检：块没被识别 / 选择器改名都必须在这里红，
// 否则"两主题"会悄悄退化成两套残缺 token，而所有组合都被 SKIPPED 吃掉 → 假绿。
const CORE_TOKENS = ['--fg-primary', '--fg-secondary', '--fg-tertiary', '--bg-app', '--surface-solid', '--accent'];
const THEME_INCOMPLETE = [];
for (const t of THEMES) {
  for (const k of CORE_TOKENS) if (!t.vars.has(k)) THEME_INCOMPLETE.push(`${t.name} 缺 ${k}`);
}

// ---------- 2. 颜色解析与 WCAG 相对亮度 ----------
// 顶层分隔：只在括号深度 0 处切逗号 / 斜杠。
// 为什么需要：var(--c, var(--accent)) 的回退逗号在括号内，不能当顶层分隔；
// rgb(var(--surface-tint) / var(--alpha)) 的斜杠同理。正则做不到"深度 0"这件事。
function splitTopLevel(s, ch) {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (c === ch && depth === 0) return [s.slice(0, i), s.slice(i + 1)];
  }
  return null;
}
// var(--name) 与 var(--name, fallback) 都要能解；回退值优先查变量表，查不到再解字面量。
function splitVarArgs(inner) {
  const cut = splitTopLevel(inner, ',');
  if (!cut) return [inner, ''];
  return [cut[0], cut[1]];
}
// alpha 分量解析：裸数字 / 百分比 / var() 链。
// 为什么不能复用 parseColor：alpha 不是颜色，`var(--surface-alpha-card)` 展开成裸数字
// `0`，走颜色解析必然 null —— 那会让 --bg-card / --bg-elevated / --bg-input 三张
// "表面 tint + alpha" 卡的 192 个组合继续静默失明。
function resolveAlpha(raw, vars, depth = 0) {
  if (depth > 6) return null;
  const s = String(raw).trim();
  const bare = s.match(/^([\d.]+)(%?)$/);
  if (bare) return bare[2] ? parseFloat(bare[1]) / 100 : parseFloat(bare[1]);
  const m = s.match(/^var\(([\s\S]*)\)$/);
  if (!m) return null;
  const [namePart, fallback] = splitVarArgs(m[1].trim());
  const next = vars.get(namePart.trim());
  if (next !== undefined) return resolveAlpha(next, vars, depth + 1);
  if (fallback.trim()) return resolveAlpha(fallback, vars, depth + 1);
  return null;
}
// 空格版 `rgb(r g b / a)`（CSS Color 4）：--bg-card / --bg-elevated / --bg-input
// 都是 rgb(var(--surface-tint) / var(--surface-alpha-xxx)) 这一形态。
// 通道可写裸三元组，或一个 var() 承载 "r g b"。
function parseRgbSpace(s, vars) {
  const m = s.match(/^rgba?\(\s*([\s\S]*?)\s*\)$/);
  if (!m) return null;
  const cut = splitTopLevel(m[1], '/');
  if (!cut) return null;
  const chanPart = cut[0].trim();
  const alphaPart = cut[1] === undefined ? null : cut[1].trim();
  let nums = null;
  const direct = chanPart.split(/\s+/);
  if (direct.length === 3 && direct.every((c) => /^\d+$/.test(c))) {
    nums = direct.map(Number);
  } else {
    const vm = chanPart.match(/^var\(([\s\S]*)\)$/);
    if (!vm) return null;
    const [namePart, fallback] = splitVarArgs(vm[1].trim());
    const raw = (vars.get(namePart.trim()) ?? fallback.trim()).trim();
    const t = raw.match(/^(\d+)\s+(\d+)\s+(\d+)$/);
    if (!t) return null;
    nums = [+t[1], +t[2], +t[3]];
  }
  let a = 1;
  if (alphaPart !== null && alphaPart !== '') {
    a = resolveAlpha(alphaPart, vars);
    if (a === null) return null;
  }
  return { r: nums[0], g: nums[1], b: nums[2], a };
}
function parseColor(raw, vars) {
  let s = String(raw).trim();
  for (let hop = 0; hop < 6; hop++) {
    const m = s.match(/^var\(([\s\S]*)\)$/);
    if (!m) break;
    const [namePart, fallback] = splitVarArgs(m[1].trim());
    const next = vars.get(namePart.trim());
    if (next !== undefined) { s = next.trim(); continue; }
    // --c 由 JS 运行时注入、--fg-secondary 有兜底值两种情形都走这条：静态算只能取兜底值，
    // 而那正是变量缺失时的真实渲染结果，方向正确（不是乐观放行）。
    if (fallback.trim()) { s = fallback.trim(); continue; }
    return null;
  }
  let m = s.match(/^#([0-9a-f]{3})$/i);
  if (m) return { r: parseInt(m[1][0] + m[1][0], 16), g: parseInt(m[1][1] + m[1][1], 16), b: parseInt(m[1][2] + m[1][2], 16), a: 1 };
  m = s.match(/^#([0-9a-f]{6})$/i);
  if (m) return { r: parseInt(m[1].slice(0, 2), 16), g: parseInt(m[1].slice(2, 4), 16), b: parseInt(m[1].slice(4, 6), 16), a: 1 };
  m = s.match(/^rgba?\(\s*var\(([\s\S]*?)\)\s*,\s*([\d.]+)\s*\)$/);
  if (m) {
    const [namePart, fallback] = splitVarArgs(m[1].trim());
    const raw = (vars.get(namePart.trim()) ?? fallback.trim()).trim();
    const t = raw.match(/^(\d+)\s*,\s*(\d+)\s*,\s*(\d+)$/);
    if (t) return { r: +t[1], g: +t[2], b: +t[3], a: parseFloat(m[2]) };
  }
  // 逗号版 rgba(255, 158, 11, 0.15)：通道为裸数字，alpha 允许 .78 这种前导点写法
  m = s.match(/^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)$/);
  if (m) return { r: +m[1], g: +m[2], b: +m[3], a: m[4] === undefined ? 1 : +m[4] };
  return parseRgbSpace(s, vars);
}
const lin = (c) => { const x = c / 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); };
const lum = ({ r, g, b }) => 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
const contrast = (a, b) => {
  const la = lum(a), lb = lum(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
};
const hex = ({ r, g, b }) => '#' + [r, g, b].map((v) => Math.round(v).toString(16).padStart(2, '0')).join('').toUpperCase();

/**
 * 浅染底 AA 边界项登记清单（双向棘轮）。
 *
 * 2026-09-28 清空：原 5 项（`.rt-badge.scanning` / `.maint-tab.active .maint-tab-count` /
 * `.maint-status-running` / `.checkup-btn:hover` 的 accent 染底 8%、`.checkup-btn-ignore:hover`
 * 的 --fg-tertiary 染底 10%）已按建议修法降到 6% / 8%，实测 4.53~4.59:1 全部达标，
 * 故登记移除。**清单为空是预期状态**：今后再出现 <4.5 的浅染底组合会直接判「新增未登记」而红。
 *
 * 修法备忘（下次遇到同族问题照此办理，不要去动 `--accent` 之类的主色 token）：
 * 把该规则的染底浓度降 2 个百分点（8%→6% / 10%→8%），底更接近页面底色 ⇒ 对比度上升约 0.12，
 * 视觉几乎无感，且不波及同 token 的其他用法。
 */

/**
 * 预览窗固定底色（AGENTS §2 明令的刻意设计：预览窗纯黑底）。
 * 为什么门禁需要它：`.pv-*` 的白色半透明控件叠在**黑底**上，本仓 main.css 里
 * `body.pv-window { background: #000 }` 是唯一底色声明；门禁若把 rgba(255,255,255,.06)
 * 合成到亮色主题的 --bg-app 上，会算出 1.09:1 的假违规 —— 那是门禁底猜错，不是产品错。
 * 声明在这里而不是改产品：产品口径（纯黑底）是用户拍板的，改它才是回归。
 */
const PREVIEW_WINDOW_BASE = '#000000';

/**
/**
 * 「解析不了 / 合成底不可知」登记表。双向棘轮：登记项必须仍然存在于 main.css，
 * 未登记的一律计入 SKIPPED 并由 E 组棘轮判红。
 *
 * 2026-10-03（K1 修复连带）逐条理由：
 *   - `.pv-*` 全族：窗内白色半透明控件，底是**预览窗固定纯黑底**（AGENTS §2 刻意设计）。
 *     这类不登记 —— 已由 PREVIEW_BASE_SELECTORS 按正确底重算，见 flattenBg。
 *   - `--lg-glass-fg` 族（body.lg-mode-* 的 .maint-tab-count / .filter-tab.active）：
 *     液态玻璃三档下标签底色由宿主材质 + backdrop 决定，静态不可知；
 *     且 --lg-glass-fg 在两主题下都 = var(--fg-primary)，前景本身不是问题。
 *   - `.btn > .btn-ripple`：纯装饰波纹层（无文本），不承载任何内容。
 *   - `.splash-badge` / `.splash-enter`：开屏一次性走场（AGENTS §2 明令豁免动效的同一节），
 *     且 splash 覆盖层是**独立局部调色板**（--splash-* 定义在 .splash-overlay 内，
 *     刻意固定浅色不随主题联动），与主题 token 表无继承关系。
 *   - `.maint-admin-tag` / `.maint-status-warn`：前景写成 color-mix(...80%, #000)，
 *     门禁的 parseBg 只解 var() 起手的形态；这两条的对比度已由 B 组（正文前景 × 页面底）覆盖。
 *   - `.ctx-apply-bar`：底写 var(--warning-soft, rgba(...)) 带兜底值，静态按兜底算不出
 *     主题相关结果，实际两主题取值相同。
 */
const UNKNOWN_BASE_ALLOW = [
  'body.lg-mode-full .maint-tab.active .maint-tab-count, body.lg-mode-standard .maint-tab.active .maint-tab-count, body.lg-mode-frost .maint-tab.active .maint-tab-count',
  'body.lg-mode-full .filter-tab.active .maint-tab-count, body.lg-mode-standard .filter-tab.active .maint-tab-count, body.lg-mode-frost .filter-tab.active .maint-tab-count',
  '.btn > .btn-ripple',
  '.splash-badge',
  '.splash-enter',
  '.maint-admin-tag',
  '.maint-status-warn',
  '.ctx-apply-bar',
  'body.theme-light .nav-subdot',
  // 审查 L-28 连带：--splash-* 是开屏覆盖层的独立局部调色板（刻意固定、不随主题
  // 联动，见 UNKNOWN_BASE_ALLOW 上方说明），主主题变量表里根本没有这些 token。
  // 收口 SOLID_SKIP 盲区后 .splash-enter:hover 的 --splash-brand-hover 落进 E 组，
  // 按「未登记 = 失明 = 红」的规矩必须显式登记理由（与 .splash-enter 同一个理由）。
  '.splash-enter:hover',
];
// 这些选择器的半透明底一律按 PREVIEW_WINDOW_BASE 合成（窗内白控件的真实底）
const PREVIEW_BASE_SELECTORS = /^\.pv-/;
const TINT_WEAK_ALLOW = [];
// ---------- 3. A 组：实底背景 × 前景 ----------
// 实底 = background 直接是 var(--x)，且不是 -soft/-light/-glow 这类染底 token
//
// 审查 L-28（2026-10-03 L4）——**这里原先是一处覆盖面盲区，不是解析盲区**：
// K1 修好了「解析失明」（能算的都算了），但 SOLID_SKIP 按 token 后缀整族跳过
// `-soft|-light|-hover|-press`，而 M-13 的五条真违规恰好全都是「`-soft`/`-light` 染底
// × 专用墨色字」—— 修好了「看得见」，「看得见的范围」本身还有个洞。
//
// 改成**不按后缀跳过、改按「能不能合成出底色」判定**：
//   · 染底（-soft/-light/-hover）本身是可算的（flattenBg 会把它合成到 --bg-app），
//     所以它们进 A 组、走 TINT 组判定（TINT_WEAK_ALLOW 那套 4.4~4.5 边界棘轮）；
//   · 真正算不出的是 --splash-* 族（独立局部调色板，不随主题联动）——
//     那些走 UNKNOWN_BASE_ALLOW 登记，登记项仍由 E 组棘轮守着。
// 实测代价（本次收口时现算）：+144 组，仅 `.bg-list-del:hover` 一条落到 4.16:1，
// 且它是**纯图标**按钮（`✕`，pathbinding.js:461），适用 WCAG 1.4.11 的 3:1 而非
// 1.4.3 的 4.5:1 ⇒ 进 ICON_ONLY 清单，不是违规。
const SOLID_SKIP = /^$/;
// K1 失明源一（2026-10-03 L3 审查）：属性值的**括号平衡**读取器。
// 为什么不能用一层嵌套的正则：color-mix(in srgb, var(--a) 5%, var(--b)) 里 var() 自己
// 带括号，两层正则对"第二分量含 var()"会截断或不匹配，而截断是**无声**的（整行被
// continue 掉）—— 这正是 11 条真实规则失明的根因。改成"从 ( 开始数括号深度"与 CSS
// 语义同形，且提取层与解析层（parseBg）共用同一形状，不再两层不同步（两层不同步本身
// 就是本条根因：提取层允许一层嵌套，解析层写的是 [^)]+）。
function readValue(body, from) {
  // 先跳过前导空白与注释：正则 (?::s*) 的 `s*` 已经吃掉了冒号后的空白，
  // lastIndex 落在值首格；不跳过的话 readValue 会把前导空格当值的一部分返回，
  // 后面 /^(var(|...)/ 的形状校验整条判不中 —— 表现为"规则全被跳过"的假绿。
  let i = from;
  while (i < body.length && /\s/.test(body[i])) i++;
  const start = i;
  let depth = 0;
  for (; i < body.length; i++) {
    const ch = body[i];
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return body.slice(start, i + 1);
    } else if (depth === 0 && ch === ';') return null;
  }
  return null;
}
function readValues(body, prop) {
  const out = [];
  const re = new RegExp("(?:^|;)\\s*" + prop + "(?:-color)?\\s*:\\s*", "g");
  let m;
  while ((m = re.exec(body))) {
    const v = readValue(body, re.lastIndex);
    if (!v) continue;
    // 与 parseBg 的白名单同源：var() / color-mix() / 字面色 / rgb() 都收
    const val = v.trim();
    if (/^(var\(|color-mix\(|#|rgb|rgba)/.test(val)) out.push(val);
      // 必须把 lastIndex 推到值末尾：否则下一轮 exec 从旧位置重扫，又命中同一个
      // background: 前缀、readValue 从同一处再读一遍 —— 表现为"一条 background 都读不出来"。
      re.lastIndex = m.index + m[0].length + val.length;
  }
  return out;
}
const ruleRe = /([^{}]+)\{([^{}]*)\}/g;
const rules = [];
// 审查 L-28：两份 CSS 各解析一遍，`file` 字段带上来源，行号是**文件内行号**
// （各自 parse 自己的 text，所以不需要任何跨文件偏移量）。
for (const part of CSS_PARTS) {
  let mm;
  const localRe = new RegExp(ruleRe.source, 'g');
  while ((mm = localRe.exec(part.text))) {
    const body = mm[2];
    // color-mix 里嵌套 var() 带括号，模式要允许一层嵌套
    const bgRaw = readValues(body, "background");
    // K2 失明源（2026-10-03 L3 审查）：前景不只可能是 var(--x)——`color: #000000`
    // 这类字面色此前整条不落进 fgs，于是 .qc-admin-note 的暗色 1.22:1 对门禁完全不可见。
    // 改成记原始表达式，字面色交给 parseColor 走同一套字面量解析。
    const fgs = [...body.matchAll(/(?:^|;)\s*color\s*:\s*([^;]+)/g)].map((x) => x[1].trim())
      .filter((x) => x !== "inherit" && x !== "transparent");
    if (!bgRaw.length && !fgs.length) continue;
    rules.push({
      selector: mm[1].trim().replace(/\s+/g, ' '),
      file: part.label,
      lineNo: part.text.slice(0, mm.index).split('\n').length,
      bgRaw,
      fgs,
    });
  }
}

const baseOf = (sel) => sel.replace(/::?[\w-]+(\([^()]*\))?/g, '').replace(/\s+/g, ' ').trim();
// 键是 `file|base`：审查 L-28 引入 ds.css 后，前景回溯**必须按文件分区**——
// 否则 `.ds-menu-item` 在 ds.css 里、它的 `:hover` 态如果只写 color，回溯会拿到
// main.css 里同名 base 的 color（或者反过来），算出跨文件的假组合。
// ds.css 明确是「后置覆盖」语义，与 main.css 是覆盖关系而不是同一条规则的两半。
const colorByBase = new Map();
for (const r of rules) {
  if (!r.fgs.length) continue;
  // K1 失明源四（2026-10-03 L3）：伪元素的 color 不是父级的 color。
  // ::before / ::after 是独立元素、自带 color，baseOf 把选择器剥成同一个 base 后，
  // `.opt-card.selected::before` 的 color 会被当成 `.opt-card.selected` 的前景回溯用
  // ⇒ 实算出 1.04:1 的假违规（真实 ::before 组合 5.81:1 达标，且 ::before 按装饰件口径已跳过）。
  if (/::(before|after)\b/.test(r.selector)) continue;
  const b = baseOf(r.selector);
  const k = `${r.file}|${b}`;
  if (b && !colorByBase.has(k)) colorByBase.set(k, r.fgs);
}
function inheritedFg(sel, file) {
  const base = baseOf(sel);
  if (!base) return null;
  const parts = base.split(' ');
  for (let i = parts.length; i > 0; i--) {
    const cand = parts.slice(0, i).join(' ');
    const hit = colorByBase.get(`${file}|${cand}`);
    if (hit) return hit;
  }
  return null;
}
function parseBg(raw, vars) {
  // K1 修复点（2026-10-03 L3）：第二分量必须取到**括号平衡**的整段，
  // 原先写 ([^)]+) 会在第一个右括号处截断 —— `color-mix(in srgb, var(--a) 5%, var(--b))`
  // 只截到 `var(--b`，于是这 11 条真实规则永久解析失败被静默跳过。提取层（readValues）
  // 已经给出括号平衡的整串，这里用贪婪的 (.+) 匹配到**末尾**的右括号即可。
  const m = raw.match(/^color-mix\(\s*in\s+srgb\s*,\s*var\(([\s\S]*?)\)\s*([\d.]+)%\s*,\s*(.+)\)$/);
  if (!m) return parseColor(raw, vars);
  // 第一分量可能是 var(--c, var(--accent)) 回退形态（分组标识色 --c 由 JS 运行时注入，
  // CSS 里只给兜底值）—— 静态算取兜底值正是 --c 缺失时的真实渲染结果，方向正确。
  const a = parseColor(`var(${m[1]})`, vars);
  const p = parseFloat(m[2]) / 100;
  const rest = m[3].trim();
  // transparent = 叠在页面底色上（按 --bg-app 合成）
  const b = rest === 'transparent' ? parseColor('var(--bg-app)', vars) : parseColor(rest, vars);
  if (!a || !b) return null;
  const mix = (x, y) => x * p + y * (1 - p);
  return { r: mix(a.r, b.r), g: mix(a.g, b.g), b: mix(a.b, b.b), a: 1 };
}

// 半透明底按**它真实浮在的那个底**合成。
// 为什么必须做：alpha < 1 的 token 绝大多数是 --bg-card / --bg-elevated / --bg-input
// 这三张「表面 tint + alpha」卡，实质就是叠在页面底上的半透明层（暗色下 --bg-card 的
// alpha 恰好是 0）。原先 `b.a < 1 → continue` 把它们整批跳过，192 个组合永久失明 ——
// 与 K1 同族：解析不出来 / 判不了就静默跳过。合成方向与既有 transparent 约定一致。
//
// selector 参数不能省：预览窗（.pv-*）浮在**固定纯黑底**上（AGENTS §2 刻意设计），
// 用 --bg-app 当底会算出 1.09:1 的假违规 —— 门禁底猜错，不是产品对比度错。
function flattenBg(c, vars, selector) {
  if (!c || c.a >= 1) return c;
  const baseExpr = selector && PREVIEW_BASE_SELECTORS.test(selector)
    ? PREVIEW_WINDOW_BASE
    : 'var(--bg-app)';
  const page = parseColor(baseExpr, vars);
  if (!page) return null;
  const mix = (x, y) => x * c.a + y * (1 - c.a);
  return { r: mix(c.r, page.r), g: mix(c.g, page.g), b: mix(c.b, page.b), a: 1 };
}

const solidRows = [];
// K1 第二条棘轮（2026-10-03 L3 审查）：解析层丢掉的组合必须**可棘轮**。
// 原缺陷形态是「parseColor 返回 null 就整行 continue」—— 门禁永远打 ✓，失明不可见。
// 现在每个跳过的组合都留痕；超出 SKIPPED_MAX 即判红（新增失明 = 红，不许无声增长）。
// 2026-10-03 现算：修复前 566（color-mix 截断 + 半透明底 + 字面色前景 + 主题块残缺），
// 修复后 0 条。**上限刻意留 4 条余量**：splash 一次性走场这类刻意设计可能引入新形态，
// 但任何新增都必须在下面显式登记理由，不许默默进来。
const SKIPPED_MAX = 4;
const SKIPPED = [];
for (const r of rules) {
  if (!r.bgRaw.length) continue;
  // 伪元素一律装饰件，不承载文本 → 不适用文本对比度，跳过（否则全是误报）
  if (/::(before|after)\b/.test(r.selector)) continue;
  const fgs = r.fgs.length ? r.fgs : inheritedFg(r.selector, r.file) || [];
  for (const raw of r.bgRaw) {
    const varOnly = raw.match(/^var\(\s*(--[\w-]+)\s*\)$/);
    if (varOnly && SOLID_SKIP.test(varOnly[1])) continue;
    for (const fg of fgs) {
      for (const t of THEMES) {
        const b = flattenBg(parseBg(raw, t.vars), t.vars, r.selector);
        // K2：fg 现在是**原始表达式**（var(--x) 或 #000000），parseColor 两种都吃
        const f = parseColor(fg, t.vars);
        // 半透明前景（rgba(255,255,255,.85) 这类）按 WCAG 惯例合成到底色再算：
        // 合成方向与背景一致（都压到同一个底），否则白字 0.85 直接判低会误报。
        const fFlat = f && f.a < 1 ? flattenBg(f, t.vars, r.selector) : f;
        if (!b || !fFlat || fFlat.a < 1) {
          // 已登记的「合成底不可知」不计棘轮；未登记的必须让 E 组判红
          if (!UNKNOWN_BASE_ALLOW.includes(r.selector)) SKIPPED.push(`${r.selector} :: ${raw} / ${fg}`);
          continue;
        }
        solidRows.push({
          theme: t.name, selector: r.selector, file: r.file, lineNo: r.lineNo,
          bgExpr: raw.replace(/\s+/g, ' '), fg, ratio: contrast(b, fFlat), bgHex: hex(b), fgHex: hex(fFlat),
          // 浅染底与实底分开判定：见 TINT_WEAK_ALLOW 的说明。
          // 审查 L-28：判据从「写法是不是 color-mix(」扩成「**合成前有没有透明度**」——
          // 前者只认字面写法，于是 `var(--accent-soft)`（rgba(...,0.08)）这种更常见的
          // 染底形态被归进「实底」走 A1 硬判；后者按语义判，染底一律走 A2 边界棘轮。
          tint: /^color-mix\(/.test(raw.trim()) || (parseBg(raw, t.vars) || { a: 1 }).a < 1,
        });
      }
    }
  }
}

// ---------- 4. B 组：正文前景 × 页面底 / 卡片合成底 ----------
const TEXT_FG = ['--fg-primary', '--fg-secondary', '--fg-tertiary'];
const TEXT_BG = ['--bg-app', '--surface-solid'];
function compositeCard(vars) {
  const tint = (vars.get('--surface-tint') || '').trim().match(/^(\d+)\s+(\d+)\s+(\d+)$/);
  const alpha = parseFloat(vars.get('--surface-alpha-elevated') || '');
  const base = parseColor('var(--bg-app)', vars);
  if (!tint || !isFinite(alpha) || !base) return null;
  const over = { r: +tint[1], g: +tint[2], b: +tint[3] };
  const mix = (x, y) => x * alpha + y * (1 - alpha);
  return { r: mix(over.r, base.r), g: mix(over.g, base.g), b: mix(over.b, base.b), a: 1 };
}
const textRows = [];
for (const t of THEMES) {
  const bgs = [];
  for (const n of TEXT_BG) {
    const c = parseColor(`var(${n})`, t.vars);
    if (c) bgs.push({ name: n, c });
  }
  const card = compositeCard(t.vars);
  if (card) bgs.push({ name: '--bg-card(合成)', c: card });
  for (const fg of TEXT_FG) {
    for (const b of bgs) {
      const f = parseColor(`var(${fg})`, t.vars);
      if (!f || f.a < 1 || b.c.a < 1) continue;
      textRows.push({ theme: t.name, fg, bg: b.name, ratio: contrast(b.c, f) });
    }
  }
}

// ---------- 5. 判定 ----------
let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 对比度门禁（WCAG 2.1 AA，普通文本 4.5:1）===\n');

const fmt = (r) => `${r.ratio.toFixed(2)}:1 ${r.theme} ${r.selector}(${lineRef(r.file, r.lineNo)}) 底${r.bgExpr}=${r.bgHex} 字${r.fg}=${r.fgHex}`;

check(
  THEME_INCOMPLETE.length === 0,
  `D. 主题 token 表完整（${THEMES.length} 个主题：${THEMES.map((t) => `${t.name} ${t.vars.size} token`).join(" / ")}）`,
  THEME_INCOMPLETE.join("；"),
);
check(
  SKIPPED.length <= SKIPPED_MAX,
  `E. 解析跳过数不超棘轮（实算 ${SKIPPED.length} / 上限 ${SKIPPED_MAX}）`,
  SKIPPED.length ? `新增失明组合：${[...new Set(SKIPPED)].slice(0, 6).join("；")}` : "",
);
const weak = solidRows.filter((r) => r.ratio < AA_NORMAL);
// 审查 L-28：纯图标/图形控件走 WCAG **1.4.11 非文本对比度 = 3:1**，不是 1.4.3 的 4.5:1。
// 登记制 + 双向棘轮：登记项必须仍然低于 4.5（否则说明它修好了，从清单移除），
// 未登记的一律按 4.5 硬判 ⇒ 有人拿「这是图标」当借口放行新组合，门禁会红。
//
// 2026-10-03 现算：收口 SOLID_SKIP 盲区后 +144 组，只有 1 组落到 4.5~3 之间 ——
// `.bg-list-del:hover`（✕ 删除按钮，pathbinding.js:461，**纯图标无文本**）实测 4.16:1。
const ICON_ONLY_MIN = 3.0;
const ICON_ONLY_ALLOW = [
  '.bg-list-del:hover',
];
const iconRows = solidRows.filter((r) => r.ratio >= ICON_ONLY_MIN && r.ratio < AA_NORMAL);
const iconNew = [...new Set(iconRows.map((r) => r.selector))].filter((s) => !ICON_ONLY_ALLOW.includes(s)).sort();
const iconStale = ICON_ONLY_ALLOW.filter((s) => !iconRows.some((r) => r.selector === s));
const iconBad = solidRows.filter((r) => r.ratio < ICON_ONLY_MIN);
const hardBad = weak.filter((r) => !r.tint && !ICON_ONLY_ALLOW.includes(r.selector)).sort((a, b) => a.ratio - b.ratio);
const tintBad = weak.filter((r) => r.tint);
// 棘轮键：选择器|前景（同一处两主题各算一行，去重后比对）
const tintKeys = [...new Set(tintBad.map((r) => `${r.selector}|${r.fg}`))].sort();
const tintNew = tintKeys.filter((k) => !TINT_WEAK_ALLOW.includes(k));
const tintStale = TINT_WEAK_ALLOW.filter((k) => !tintKeys.includes(k));

check(
  hardBad.length === 0,
  `A1. 实底前景组合 ${solidRows.filter((r) => !r.tint).length} 组全部 ≥ ${AA_NORMAL}:1`,
  hardBad.length ? hardBad.map(fmt).join('；') : '',
);
check(
  iconNew.length === 0 && iconStale.length === 0 && iconBad.length === 0,
  `A1b. 纯图标控件（WCAG 1.4.11 = ${ICON_ONLY_MIN}:1）登记一致（登记 ${ICON_ONLY_ALLOW.length} / 实际 ${iconRows.length}）`,
  iconBad.length
    ? `低于 ${ICON_ONLY_MIN}:1（连图形都看不清）：${iconBad.map(fmt).join('；')}`
    : iconNew.length
      ? `新增未登记的图标组合 ${JSON.stringify(iconNew)}`
      : iconStale.length
        ? `清单已失效（该项已达标，请移除）${JSON.stringify(iconStale)}`
        : '',
);
if (iconRows.length) {
  console.log('\n   A1b 清单（纯图标，适用 3:1 而非 4.5:1）：');
  for (const r of iconRows) console.log(`     ${fmt(r)}`);
}
check(
  tintNew.length === 0 && tintStale.length === 0,
  `A2. 浅染底 AA 边界项与登记清单一致（登记 ${TINT_WEAK_ALLOW.length} / 实际 ${tintKeys.length}，非致命但带棘轮）`,
  tintNew.length
    ? `新增未登记的 AA 边界项 ${JSON.stringify(tintNew)}`
    : tintStale.length
      ? `清单已失效（该项已达标，请移除）${JSON.stringify(tintStale)}`
      : '',
);
if (tintBad.length) {
  console.log('\n   A2 清单（浅染底 4.4–4.5:1，保守下界，未判红）：');
  for (const r of tintBad) console.log(`     ${fmt(r)}`);
  console.log('     修法：染底浓度 8%→6% / 10%→8%（改完 4.59:1，只动这几条规则，不动 token）');
}

const textBad = textRows.filter((r) => r.ratio < AA_NORMAL).sort((a, b) => a.ratio - b.ratio);
check(
  textBad.length === 0,
  `B. 正文前景 × 页面底色 ${textRows.length} 组全部 ≥ ${AA_NORMAL}:1`,
  textBad.length ? textBad.map((r) => `${r.ratio.toFixed(2)}:1 ${r.theme} ${r.fg} on ${r.bg}`).join('；') : '',
);

const total = solidRows.length + textRows.length;
check(
  total >= BASELINE_MIN,
  `C. 覆盖率不低于基线（实算 ${total} 组 / 下限 ${BASELINE_MIN}）`,
  total < BASELINE_MIN ? '组合数骤降说明解析退化，不是「真的都达标」' : '',
);
// 审查 L-28：逐文件地板。solidRows 里带 file 字段（B 组是 token 对，不归属文件）。
const perFile = {};
for (const r of solidRows) perFile[r.file] = (perFile[r.file] || 0) + 1;
const floorBad = Object.entries(SCAN_FLOOR)
  .filter(([f, n]) => (perFile[f] || 0) < n)
  .map(([f, n]) => `${f} 实算 ${perFile[f] || 0} < 地板 ${n}`);
// 台账里有、扫描面里没有的也算漂移（有人把文件移出扫描面就会在这里红）
const orphanFiles = Object.keys(SCAN_FLOOR).filter((f) => !perFile[f]);
check(
  floorBad.length === 0 && orphanFiles.length === 0,
  `C2. 逐文件组合数不低于地板（${Object.entries(SCAN_FLOOR).map(([f, n]) => `${f} ${perFile[f] || 0}/${n}`).join(' / ')}）`,
  floorBad.length
    ? floorBad.join('；')
    : orphanFiles.length
      ? `扫描面台账里的文件已无组合产出（被移出扫描面？）：${orphanFiles.join('、')}`
      : '',
);

const worst = [...solidRows, ...textRows].sort((a, b) => a.ratio - b.ratio)[0];
if (worst) console.log(`\n最低一档：${worst.ratio.toFixed(2)}:1（${worst.theme} ${worst.selector || worst.fg + ' on ' + worst.bg}）`);
console.log('');

if (fail > 0) {
  console.error(`门禁失败：${fail} 组断言未通过`);
  process.exit(1);
}
console.log('对比度门禁全部通过');
