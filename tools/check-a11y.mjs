#!/usr/bin/env node
// check-a11y.mjs —— 可达性三断言（P3-1，2026-10-09）
//
// 三条「找违规型」断言，各配**内置正向对照自检**（违例样本必须判红；只打印 ✓
// 的恒绿断言视同没写，AGENTS §4.1）：
//   ① 勾选框模板三属性：`class="checkbox"` 的元素必须同现
//      `role="checkbox"` / `tabindex="0"` / `aria-checked`（自绘控件三件套，
//      缺一键盘用户就摸不到/读不出；disabled 语义额外挂 aria-disabled，不在本断言范围）。
//   ② 异步状态宿主必须带 aria-live：id 以 `GlobalHint` 结尾、或为 `toastContainer`
//      的宿主，读屏靠 aria-live 才知道内容变了 —— 没有它，提示等于静默。
//   ③ `data-tip` 反 `title`（AGENTS §2）：禁 `title="` 属性与元素 `.title =` 赋值
//      （原生 title 与自绘 tooltip 会双气泡；`document.title` 是窗口标题，除外）。
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

console.log(
  `\n扫描：${sources.length} 个源文件 · 勾选框模板 ${checkboxSites} 处 · 提示宿主 ${liveHosts} 处 · data-tip ${tipSites} 处`,
);
if (fail > 0) {
  console.error(`check-a11y: 正向对照自检 ${fail} 处失败（判定器失效，本门禁不可信）`);
  process.exit(1);
}
g.finish('check-a11y: 全部通过');
