#!/usr/bin/env node
// check-a11y.mjs —— 可达性四断言（P3-1/P3-3，2026-10-09）
//
// 四条「找违规型」断言，各配**内置正向对照自检**（违例样本必须判红；只打印 ✓
// 的恒绿断言视同没写，AGENTS §4.1）：
//   ① 勾选框模板三属性：`class="checkbox"` 的元素必须同现
//      `role="checkbox"` / `tabindex="0"` / `aria-checked`（自绘控件三件套，
//      缺一键盘用户就摸不到/读不出；disabled 语义额外挂 aria-disabled，不在本断言范围）。
//   ② 异步状态宿主必须带 aria-live：id 以 `GlobalHint` 结尾、或为 `toastContainer`
//      的宿主，读屏靠 aria-live 才知道内容变了 —— 没有它，提示等于静默。
//   ③ `data-tip` 反 `title`（AGENTS §2）：禁 `title="` 属性与元素 `.title =` 赋值
//      （原生 title 与自绘 tooltip 会双气泡；`document.title` 是窗口标题，除外）。
//   ④ prefers-reduced-motion 归零覆盖面（v4 F1）：main.css 的 RM 归零段必须
//      点名 **body 自身**（三子窗 body fadeIn 挂在 body 上，`body > *` 漏掉它）
//      且覆盖 `::-webkit-slider-thumb`（厂商伪元素，::before/::after 式管不到）。
//
// 扫描面地板：三类命中数低于粗下界即判红（防「正则过时 ⇒ 0 命中恒绿」）。
//
// 用法：node tools/check-a11y.mjs
'use strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { gate } from './lib/gate.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src');

const read = (p) => readFileSync(p, 'utf8');
const htmlFiles = readdirSync(SRC).filter((f) => f.endsWith('.html')).map((f) => join(SRC, f));
const jsDir = join(SRC, 'scripts');
const jsFiles = readdirSync(jsDir).filter((f) => f.endsWith('.js')).map((f) => join(jsDir, f));
const rel = (p) => relative(ROOT, p).replace(/\\/g, '/');

// ---------- ① 勾选框模板三属性 ----------
const CHECKBOX_ATTRS = ['role="checkbox"', 'tabindex="0"', 'aria-checked'];
function checkboxViolations(text) {
  const out = [];
  for (const m of text.matchAll(/class="checkbox/g)) {
    // 元素窗口：从 match 起到第一个 `>` 为止（这些模板的模板表达式内不含 `>`）
    const seg = text.slice(m.index, m.index + 600);
    const end = seg.indexOf('>');
    const el = end >= 0 ? seg.slice(0, end) : seg;
    const missing = CHECKBOX_ATTRS.filter((a) => !el.includes(a));
    if (missing.length) out.push(missing);
  }
  return out;
}

// ---------- ② 异步状态宿主 aria-live ----------
function ariaLiveViolations(html) {
  const out = [];
  for (const m of html.matchAll(/id="([A-Za-z]*GlobalHint|toastContainer)"/g)) {
    const open = html.lastIndexOf('<', m.index);
    const close = html.indexOf('>', m.index);
    const tag = open >= 0 && close > open ? html.slice(open, close) : '';
    if (!/aria-live\s*=/.test(tag)) out.push(m[1]);
  }
  return out;
}

// ---------- ③ data-tip 反 title ----------
function titleViolations(text, isJs) {
  const out = [];
  // 属性形态一定是 `title="…"` / `title='…'`（无空格）；带空格的 `title = ''` 是
  // 解构默认值/普通赋值，不当属性处理（避免误伤 `{ title = '' }` 参数写法）。
  for (const m of text.matchAll(/\btitle=["']/g)) out.push('title 属性');
  if (isJs) {
    for (const m of text.matchAll(/(\w[\w.]*)\.title\s*=/g)) {
      if (m[1] !== 'document') out.push(`${m[1]}.title 赋值`);
    }
  }
  return out;
}

// ---------- ④ prefers-reduced-motion 归零覆盖面 ----------
// v4 F1 红线：归零通配从 `body > *` 起算会漏掉 **body 自身**（三子窗 body fadeIn
// 就挂在 body 上）；滑块拇指 `::-webkit-slider-thumb` 是厂商伪元素，归零表的
// ::before/::after 两式覆盖不到 —— 两处各配断言，漏一处即红（点名 `body` 自身）。
function rmViolations(css) {
  const out = [];
  const blocks = [...css.matchAll(/@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{([\s\S]*?)\n\}/g)]
    .map((m) => m[1])
    .join('\n');
  if (!blocks) return ['没有任何 prefers-reduced-motion 归零段'];
  // ① 归零选择器表必须含**裸 body 选择器项**（`body,` 打头的表项，不是仅 `body > *`）
  if (!/(^|[\s{}])body\s*,/m.test(blocks)) out.push('归零选择器表未点名 body 自身（body fadeIn 过渡漏归零）');
  // ② 滑块拇指（厂商伪元素）过渡必须被归零
  if (!/::-webkit-slider-thumb/.test(blocks)) out.push('::-webkit-slider-thumb 过渡未归零（滑块的 scale 过渡在 RM 下仍会动）');
  return out;
}

// ---------- ⑤⑥ 交互卫生（P3-5） ----------
// ⑤ 同一元素同一事件不得重复注册（F4a-G-3 / M04 回归形态）：只判**可选链形态**
//    `X?.addEventListener('evt'` 的同 receiver+event 重复 —— 循环/多作用域里的普通
//    变量名重复（如 `btn`）是合法写法，全量判会误报洪水（现算 21 例全属此类）。
// ⑥ 子窗脚本代码不得依赖 window.app（F3-G-3）：子窗不加载 app.js，window.app 恒
//    undefined，依赖它 = 功能静默失效（注释里说明「不存在」不算）。
const RE_OPT_CHAIN_REG = /([A-Za-z_$][\w$]*)\s*\?\.\s*addEventListener\(\s*['"](\w+)['"]/g;
function dupOptChainRegistrations(text) {
  const seen = new Map();
  const out = [];
  for (const m of text.matchAll(RE_OPT_CHAIN_REG)) {
    const k = `${m[1]}|${m[2]}`;
    if (seen.has(k)) out.push(`${k}（@${seen.get(k)} 与 @${text.slice(0, m.index).split('\n').length}）`);
    else seen.set(k, text.slice(0, m.index).split('\n').length);
  }
  return out;
}
function windowAppViolations(text) {
  const out = [];
  const lines = text.split('\n');
  for (const m of text.matchAll(/window\s*\.\s*app\b/g)) {
    const lineNo = text.slice(0, m.index).split('\n').length - 1;
    const line = lines[lineNo] || '';
    // 特性探测形豁免：`if (window.app?.x)` —— 这是「两窗可用」的正确姿势
    //（探测存在性后走各自出口），不是对它的依赖。裸 `window.app?.toast(…)` 语句
    // 仍要红：可选链会把副窗的 undefined 静默吞掉，用户点了没反应。
    if (/\bif\s*\([^)]*window\s*\.\s*app/.test(line)) continue;
    out.push(`@${lineNo + 1}`);
  }
  return out;
}

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 可达性门禁（勾选框三属性 / aria-live 宿主 / data-tip 反 title）===\n');

// ---- 正向对照自检：判定器必须能对违例样本判红、对合规样本放行 ----
{
  const badCheckbox = '<span class="checkbox checked" data-x="1"></span>';
  const goodCheckbox =
    '<span class="checkbox" data-x="1" role="checkbox" tabindex="0" aria-checked="false"></span>';
  check(checkboxViolations(badCheckbox).length === 1, '对照①a：缺三属性的勾选框样本必须判红');
  check(checkboxViolations(goodCheckbox).length === 0, '对照①b：三属性齐全的样本必须放行');

  const badLive = '<span class="mw-foot-hint" id="xxGlobalHint" style="margin:0"></span>';
  const goodLive = '<span id="xxGlobalHint" role="status" aria-live="polite"></span>';
  check(ariaLiveViolations(badLive).length === 1, '对照②a：无 aria-live 的提示宿主必须判红');
  check(ariaLiveViolations(goodLive).length === 0, '对照②b：带 aria-live 的宿主必须放行');

  const badTitle = '<div title="旧提示"></div>';
  const badTitleJs = "el.title = '旧提示';";
  const goodTitleJs = "document.title = '窗口标题'; el.setAttribute('data-tip', '新提示');";
  check(titleViolations(badTitle, false).length === 1, '对照③a：title 属性样本必须判红');
  check(titleViolations(badTitleJs, true).length === 1, '对照③b：元素 .title 赋值样本必须判红');
  check(titleViolations(goodTitleJs, true).length === 0, '对照③c：document.title 与 data-tip 样本必须放行');

  const badRmNoBody = '@media (prefers-reduced-motion: reduce) {\n  body > *:not(#splash) { animation-duration: 0.01ms !important; }\n}\n';
  const badRmNoThumb = '@media (prefers-reduced-motion: reduce) {\n  body, body > * { transition-duration: 0.01ms !important; }\n}\n';
  const goodRm = '@media (prefers-reduced-motion: reduce) {\n  body,\n  body > *:not(#splash) { transition-duration: 0.01ms !important; }\n  input[type="range"]::-webkit-slider-thumb { transition-duration: 0.01ms !important; }\n}\n';
  check(rmViolations(badRmNoBody).some((v) => v.includes('body 自身')), '对照④a：归零表漏 body 自身的样本必须判红');
  check(rmViolations(badRmNoThumb).some((v) => v.includes('slider-thumb')), '对照④b：拇指未归零的样本必须判红');
  check(rmViolations(goodRm).length === 0, '对照④c：body 自身 + 拇指都归零的样本必须放行');

  const badDup = "a?.addEventListener('click', f1);\na?.addEventListener('click', f2);";
  const goodDup = "a?.addEventListener('click', f1);\nb.addEventListener('click', f2);\nrows.forEach(el => el.addEventListener('click', f3));";
  check(dupOptChainRegistrations(badDup).length === 1, '对照⑤a：同元素同事件的可选链重复注册必须判红');
  check(dupOptChainRegistrations(goodDup).length === 0, '对照⑤b：不同元素/循环内注册必须放行');
  check(windowAppViolations('const x = window.app?.toast?.(1);').length === 1, '对照⑥a：子窗代码依赖 window.app 必须判红');
}

// ---- 真仓扫描 ----
const g = gate(import.meta.url);
const sources = [...htmlFiles.map((p) => [p, read(p), false]), ...jsFiles.map((p) => [p, read(p), true])];

let checkboxSites = 0;
let liveHosts = 0;
let tipSites = 0;
for (const [p, text, isJs] of sources) {
  for (const miss of checkboxViolations(text)) {
    g.fail(`${rel(p)}：勾选框模板缺 ${miss.join('、')}（自绘控件三件套必须同现）`);
  }
  checkboxSites += [...text.matchAll(/class="checkbox/g)].length;

  if (!isJs) {
    for (const id of ariaLiveViolations(text)) g.fail(`${rel(p)}：#${id} 宿主必须带 aria-live（异步状态读屏靠它）`);
  }
  liveHosts += [...text.matchAll(/id="([A-Za-z]*GlobalHint|toastContainer)"/g)].length;

  for (const what of titleViolations(text, isJs)) g.fail(`${rel(p)}：${what}（提示一律走 data-tip，AGENTS §2）`);
  tipSites += [...text.matchAll(/data-tip/g)].length;
}

// ---- 扫描面地板（低于粗下界 ⇒ 疑似正则/目录失明，判红） ----
if (checkboxSites < 4) g.fail(`勾选框模板命中 ${checkboxSites} 处（< 4）⇒ 扫描面疑似失明`);
if (liveHosts < 4) g.fail(`异步提示宿主命中 ${liveHosts} 处（< 4）⇒ 扫描面疑似失明`);
if (tipSites < 10) g.fail(`data-tip 命中 ${tipSites} 处（< 10）⇒ 扫描面疑似失明`);

// ---- ④ 真仓扫描：main.css 的 RM 归零段（ds.css 的拇指归零自成一格，不强制耦合） ----
{
  const mainCss = readFileSync(join(SRC, 'styles', 'main.css'), 'utf8');
  for (const v of rmViolations(mainCss)) g.fail(`src/styles/main.css：${v}`);
}

// ---- ⑤⑥ 真仓扫描 ----
{
  // ⑤ 可选链重复注册（剥注释）
  const strip = (t) => t.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:\w])\/\/.*$/gm, '$1');
  let regSites = 0;
  for (const [p, text, isJs] of sources) {
    if (!isJs) continue;
    const clean = strip(text);
    regSites += [...clean.matchAll(RE_OPT_CHAIN_REG)].length;
    for (const d of dupOptChainRegistrations(clean)) g.fail(`${rel(p)}：同元素同事件重复注册 ${d}`);
  }
  if (regSites < 3) g.fail(`可选链注册命中 ${regSites} 处（< 3）⇒ 扫描面疑似失明`);

  // ⑥ 子窗脚本不得依赖 window.app（子窗 = 非 index.html 的 HTML 所挂脚本）
  const subScriptNames = new Set();
  for (const p of htmlFiles) {
    if (p.endsWith('index.html')) continue;
    const t = readFileSync(p, 'utf8');
    for (const m of t.matchAll(/src="([^"]*\.js)"/g)) subScriptNames.add(m[1].split('/').pop());
  }
  let subChecked = 0;
  for (const [p, text] of sources) {
    const base = p.split(/[\\/]/).pop();
    if (!subScriptNames.has(base) || base === 'tauri-api.js' || base === 'ds.js') continue; // 适配层/公共件除外
    subChecked++;
    for (const v of windowAppViolations(strip(text))) g.fail(`${rel(p)}：子窗脚本依赖 window.app ${v}（子窗不加载 app.js，恒 undefined）`);
  }
  if (subChecked < 3) g.fail(`子窗脚本扫描面 ${subChecked} 个（< 3）⇒ 清单/语料失明`);
}

console.log(
  `\n扫描：${sources.length} 个源文件 · 勾选框模板 ${checkboxSites} 处 · 提示宿主 ${liveHosts} 处 · data-tip ${tipSites} 处`,
);
if (fail > 0) {
  console.error(`check-a11y: 正向对照自检 ${fail} 处失败（判定器失效，本门禁不可信）`);
  process.exit(1);
}
g.finish('check-a11y: 全部通过');
