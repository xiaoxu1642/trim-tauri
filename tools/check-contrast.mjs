// check-contrast.mjs —— 对比度门禁（审查 v2-U1 闭环）
//
// 为什么需要它：U1「对比度」此前一直挂在「待真机/计算样式实测」，而项目**不使用 CDP**，
// 于是它永远没人算。实际上静态可算的部分占绝大多数：main.css 的颜色全是 token，
// 两个主题变量块（:root = 暗色默认 / .theme-light = 亮色）里的值都是字面量，
// 「背景 token × 前景 token」的对比度可以纯算，不需要 WebView。
//
// 三组断言：
//   A. 实底组合：同一规则内 `background: <实底>` + `color: var(--x)`（两主题）≥ 4.5:1
//   B. 正文组合：--fg-primary/secondary/tertiary × 页面底/卡片合成底（两主题）≥ 4.5:1
//   C. 覆盖率下限：算出来的组合数不得低于 BASELINE_MIN —— 防止选择器写法一变
//      就静默变成「0 组全通过」的假绿（本项目有假绿前科：v1 M13 / v2-M16）。
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

const CSS_PATH = new URL('../src/styles/main.css', import.meta.url);
const CSS_RAW = readFileSync(CSS_PATH, 'utf8');
// 剥离注释但**保留换行与字符数**：这样 `CSS.slice(0, index)` 算出来的行号仍然准确，
// 且选择器不会被块前注释污染 —— 否则棘轮键「选择器|前景」会随注释文字改动而漂移
// （与 check-system-bin 的 file:line 漂移是同一类坑）。
const CSS = CSS_RAW.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
const LINES = CSS.split('\n');

const AA_NORMAL = 4.5;

// 算出来的组合数下限：低于它说明选择器/变量解析退化成了空集，而不是「真的都达标」
const BASELINE_MIN = 30;

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
const THEMES = [];
LINES.forEach((l, i) => {
  if (/^:root\s*\{/.test(l)) THEMES.push({ name: '暗色(:root)', vars: blockVars(i + 1) });
  else if (/^\.theme-light\s*\{/.test(l)) THEMES.push({ name: '亮色(.theme-light)', vars: blockVars(i + 1) });
});

// ---------- 2. 颜色解析与 WCAG 相对亮度 ----------
function parseColor(raw, vars) {
  let s = raw.trim();
  for (let hop = 0; hop < 5; hop++) {
    const m = s.match(/^var\(\s*(--[\w-]+)\s*\)$/);
    if (!m) break;
    const next = vars.get(m[1]);
    if (!next) return null;
    s = next.trim();
  }
  let m = s.match(/^#([0-9a-f]{3})$/i);
  if (m) return { r: parseInt(m[1][0] + m[1][0], 16), g: parseInt(m[1][1] + m[1][1], 16), b: parseInt(m[1][2] + m[1][2], 16), a: 1 };
  m = s.match(/^#([0-9a-f]{6})$/i);
  if (m) return { r: parseInt(m[1].slice(0, 2), 16), g: parseInt(m[1].slice(2, 4), 16), b: parseInt(m[1].slice(4, 6), 16), a: 1 };
  m = s.match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)$/);
  if (m) return { r: +m[1], g: +m[2], b: +m[3], a: m[4] === undefined ? 1 : +m[4] };
  return null;
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
const TINT_WEAK_ALLOW = [];

// ---------- 3. A 组：实底背景 × 前景 ----------
// 实底 = background 直接是 var(--x)，且不是 -soft/-light/-glow 这类染底 token
const SOLID_SKIP = /-(soft|light|glow|tint|alpha|hover|press)$/;
const ruleRe = /([^{}]+)\{([^{}]*)\}/g;
const rules = [];
let mm;
while ((mm = ruleRe.exec(CSS))) {
  const body = mm[2];
  // color-mix 里嵌套 var() 带括号，模式要允许一层嵌套
  const bgRaw = [...body.matchAll(/(?:^|;)\s*background(?:-color)?\s*:\s*(var\(\s*--[\w-]+\s*\)|color-mix\((?:[^()]|\([^()]*\))*\))/g)]
    .map((x) => x[1].trim());
  const fgs = [...body.matchAll(/(?:^|;)\s*color\s*:\s*var\(\s*(--[\w-]+)\s*\)/g)].map((x) => x[1]);
  if (!bgRaw.length && !fgs.length) continue;
  rules.push({
    selector: mm[1].trim().replace(/\s+/g, ' '),
    lineNo: CSS.slice(0, mm.index).split('\n').length,
    bgRaw,
    fgs,
  });
}

const baseOf = (sel) => sel.replace(/::?[\w-]+(\([^()]*\))?/g, '').replace(/\s+/g, ' ').trim();
const colorByBase = new Map();
for (const r of rules) {
  if (!r.fgs.length) continue;
  const b = baseOf(r.selector);
  if (b && !colorByBase.has(b)) colorByBase.set(b, r.fgs);
}
function inheritedFg(sel) {
  const base = baseOf(sel);
  if (!base) return null;
  const parts = base.split(' ');
  for (let i = parts.length; i > 0; i--) {
    const cand = parts.slice(0, i).join(' ');
    if (colorByBase.has(cand)) return colorByBase.get(cand);
  }
  return null;
}
function parseBg(raw, vars) {
  const m = raw.match(/color-mix\(\s*in\s+srgb\s*,\s*var\(\s*(--[\w-]+)\s*\)\s*([\d.]+)%\s*,\s*([^)]+)\)/);
  if (!m) return parseColor(raw, vars);
  const a = parseColor(`var(${m[1]})`, vars);
  const p = parseFloat(m[2]) / 100;
  const rest = m[3].trim();
  // transparent = 叠在页面底色上（按 --bg-app 合成）
  const b = rest === 'transparent' ? parseColor('var(--bg-app)', vars) : parseColor(rest, vars);
  if (!a || !b) return null;
  const mix = (x, y) => x * p + y * (1 - p);
  return { r: mix(a.r, b.r), g: mix(a.g, b.g), b: mix(a.b, b.b), a: 1 };
}

const solidRows = [];
for (const r of rules) {
  if (!r.bgRaw.length) continue;
  // 伪元素一律装饰件，不承载文本 → 不适用文本对比度，跳过（否则全是误报）
  if (/::(before|after)\b/.test(r.selector)) continue;
  const fgs = r.fgs.length ? r.fgs : inheritedFg(r.selector) || [];
  for (const raw of r.bgRaw) {
    const varOnly = raw.match(/^var\(\s*(--[\w-]+)\s*\)$/);
    if (varOnly && SOLID_SKIP.test(varOnly[1])) continue;
    for (const fg of fgs) {
      for (const t of THEMES) {
        const b = parseBg(raw, t.vars);
        const f = parseColor(`var(${fg})`, t.vars);
        if (!b || !f || b.a < 1 || f.a < 1) continue;
        solidRows.push({
          theme: t.name, selector: r.selector, lineNo: r.lineNo,
          bgExpr: raw.replace(/\s+/g, ' '), fg, ratio: contrast(b, f), bgHex: hex(b), fgHex: hex(f),
          // 浅染底（低浓度叠底）与实底分开判定：见 TINT_WEAK_ALLOW 的说明
          tint: /^color-mix\(/.test(raw.trim()),
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

const fmt = (r) => `${r.ratio.toFixed(2)}:1 ${r.theme} ${r.selector}(main.css:${r.lineNo}) 底${r.bgExpr}=${r.bgHex} 字${r.fg}=${r.fgHex}`;

const weak = solidRows.filter((r) => r.ratio < AA_NORMAL);
const hardBad = weak.filter((r) => !r.tint).sort((a, b) => a.ratio - b.ratio);
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

const worst = [...solidRows, ...textRows].sort((a, b) => a.ratio - b.ratio)[0];
if (worst) console.log(`\n最低一档：${worst.ratio.toFixed(2)}:1（${worst.theme} ${worst.selector || worst.fg + ' on ' + worst.bg}）`);
console.log('');

if (fail > 0) {
  console.error(`门禁失败：${fail} 组断言未通过`);
  process.exit(1);
}
console.log('对比度门禁全部通过');
