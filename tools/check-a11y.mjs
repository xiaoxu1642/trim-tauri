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
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { gate } from './lib/gate.mjs';
import { styleLinks } from './lib/html-tags.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src');

const read = (p) => readFileSync(p, 'utf8');
const htmlFiles = readdirSync(SRC).filter((f) => f.endsWith('.html')).map((f) => join(SRC, f));
// T1d-K01（v7.2 C09）：语料面从「顶层 scripts」扩到 scripts/** + vendor/**（递归）。
// src/vendor/litebox.js 是主窗运行件（app.js PAGE_SCRIPTS 在 cleanup/backups 两页注入），
// 不是只读基线；它里面有 7 处 title="（已随本批迁 data-tip），旧语料面全程看不见。
const walkJs = (base) => {
  const out = [];
  const walk = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js')) out.push(p);
    }
  };
  walk(base);
  return out;
};
const jsFiles = [...new Set([...walkJs(join(SRC, 'scripts')), ...walkJs(join(SRC, 'vendor'))])].sort();
// 采集面地板：语料塌缩（目录改名）时「全部通过」就是空集假绿（现算 48+1，地板取显著下界）
const JS_CORPUS_FLOOR = 20;
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
// T1d-M08：焦点环判据的唯一实现（自检与真仓扫描共用，不许各写一份正则）。
const focusVisibleMissing = (css) => !/:focus-visible/.test(css);
function rmViolations(css) {  const out = [];
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

// ---------- ⑦ 折叠头 / 行点击头的键盘接线（A3-M03，2026-10-25 D 轮） ----------
// 形状：div/span 当折叠开关，或「点击整行看详情」是唯一入口，却只挂 click ⇒ 键盘既
// 聚焦不了也按不动。`ds.accordion.enhance` 只补 ARIA，**不算**键盘通路（A3 实测两个
// 调用点都以为自己有护栏）。修法：绑定处补 tabindex + role + keydown(Enter/Space→click)。
// 判据 = 「点名站点还在 + 同文件必须有键盘绑定」：站点被搬走 → 本条点名红；
// 键盘绑定被删 → 本条红。为什么不塞进 ds.js 做通用件：ds.js 在首屏 12 脚本内，
// 而首屏预算 2026-10-22 已裁定不再上调（现算余量 48 B），这条能力只有按需页用。
const COLLAPSE_SITES = [
  { file: 'src/scripts/cleanup.js', needle: '[data-group-toggle]', why: '磁盘清理一级分类折叠' },
  { file: 'src/scripts/cleanup.js', needle: '[data-sub-toggle]', why: '磁盘清理二级分类折叠' },
  { file: 'src/scripts/pathbinding.js', needle: 'systemInfoToggle', why: '设置页系统信息折叠头' },
  { file: 'src/scripts/pathbinding-background.js', needle: 'bgListToggle', why: '已导入图片列表折叠头' },
  { file: 'src/scripts/memoryclean.js', needle: '.mem-region-row', why: '内存清理区域行（点击查看简介是唯一入口）' },
  { file: 'src/scripts/processes.js', needle: 'mem-group-row', why: '进程树分组行（aria-expanded 的展开/收起）' },
];
function collapseKeyWiring(text) {
  return /addEventListener\(\s*['"]keydown['"]/.test(text) && /['"]Enter['"]/.test(text);
}

// ---------- ⑧ 会变的状态面 live region 覆盖（A3-M01，2026-10-26） ----------
// A3 报告的总数与它自己列出的坐标对不上：本门禁以**坐标清单**为准（进度块 / 计数与摘要 /
// 实时数值 / 状态文字四类），不按报告总数凑数，差异记在台账。进度块的宿主挂容器 ——
// label/value 是子节点，再挂一层会双重播报。
// 主窗的坐标由 src/scripts/a11y-live.js 在首帧后挂（走 IDLE_SCRIPTS，字节不进首屏预算）；
// 子窗 pmCount 与 maintBatchProgressText 直接写 HTML —— 后者本来就有宿主（文字节点），
// 块本体不再挂。实时数值挂 off（2026-10-26 小旭拍板：每秒播报对读屏不可用）。
const LIVE_MOUNT_FILE = join(SRC, 'scripts', 'a11y-live.js');
const APP_JS_FILE = join(SRC, 'scripts', 'app.js');
const LIVE_BASELINE = [
  { id: 'dupProgressSection', mode: 'polite', where: 'idle' },
  { id: 'emptyProgressSection', mode: 'polite', where: 'idle' },
  { id: 'anProgressSection', mode: 'polite', where: 'idle' },
  { id: 'totalSize', mode: 'polite', where: 'idle' },
  { id: 'selectedCount', mode: 'polite', where: 'idle' },
  { id: 'dupGroupCount', mode: 'polite', where: 'idle' },
  { id: 'dupSize', mode: 'polite', where: 'idle' },
  { id: 'emptyCount', mode: 'polite', where: 'idle' },
  { id: 'emptyDirCount', mode: 'polite', where: 'idle' },
  { id: 'anTotalSize', mode: 'polite', where: 'idle' },
  { id: 'anCounts', mode: 'polite', where: 'idle' },
  { id: 'anElapsed', mode: 'polite', where: 'idle' },
  { id: 'memRegionCount', mode: 'polite', where: 'idle' },
  { id: 'optimizerSummary', mode: 'polite', where: 'idle' },
  { id: 'contextSummary', mode: 'polite', where: 'idle' },
  { id: 'ovHealthCard', mode: 'polite', where: 'idle' },
  { id: 'ovHealthAdvice', mode: 'polite', where: 'idle' },
  { id: 'lockQueryResult', mode: 'polite', where: 'idle' },
  { id: 'startupDefendState', mode: 'polite', where: 'idle' },
  { id: 'qcCount', mode: 'polite', where: 'idle' },
  { id: 'cleanupAgeHint', mode: 'polite', where: 'idle' },
  { id: 'updaterCheckHint', mode: 'polite', where: 'idle' },
  { id: 'infoCdpState', mode: 'polite', where: 'idle' },
  { id: 'memUseValue', mode: 'off', where: 'idle' },
  { id: 'memFreeValue', mode: 'off', where: 'idle' },
  { id: 'memPagefileValue', mode: 'off', where: 'idle' },
  { id: 'memCacheValue', mode: 'off', where: 'idle' },
  { id: 'realtimeDown', mode: 'off', where: 'idle' },
  { id: 'realtimeUp', mode: 'off', where: 'idle' },
  { id: 'realtimeLossDetail', mode: 'off', where: 'idle' },
  { id: 'contextSelectedCount', mode: 'off', where: 'idle' },
  { id: 'maintBatchProgressText', mode: 'polite', where: 'html' },
  { id: 'pmCount', mode: 'polite', where: 'html' },
];
function parseLiveMountTable(text) {
  const grab = (name) => {
    const m = text.match(new RegExp(name + '\\s*=\\s*\\[([\\s\\S]*?)\\]'));
    return m ? [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]) : null;
  };
  return { polite: grab('POLITE_HOSTS'), off: grab('LIVE_OFF_HOSTS') };
}
function tagOfId(htmlText, id) {
  const m = htmlText.match(new RegExp('id="' + id + '"'));
  if (!m) return null;
  const open = htmlText.lastIndexOf('<', m.index);
  const close = htmlText.indexOf('>', m.index);
  return open >= 0 && close > open ? htmlText.slice(open, close + 1) : null;
}
function liveCoverageProblems(table, baseline, findTag) {
  const out = [];
  if (!table || !table.polite || !table.off) return ['挂载表解析不到 POLITE_HOSTS / LIVE_OFF_HOSTS（判定失明）'];
  const baseIds = new Set(baseline.map((b) => b.id));
  for (const { id, mode, where } of baseline) {
    if (where === 'idle') {
      const list = mode === 'polite' ? table.polite : table.off;
      if (!list.includes(id)) out.push(`${id} 未按 ${mode} 出现在 a11y-live.js（漏挂或挂错档）`);
    } else {
      const tag = findTag(id);
      if (!tag) out.push(`${id} 在任何 HTML 里都找不到`);
      else if (!new RegExp("aria-live\\s*=\\s*[\"']" + mode + "[\"']").test(tag)) {
        out.push(`${id} 的 HTML 宿主缺 aria-live="${mode}"`);
      }
    }
  }
  for (const [mode, ids] of [['polite', table.polite], ['off', table.off]]) {
    for (const id of ids) {
      if (!baseIds.has(id)) out.push(`${id} 在挂载表（${mode}）里但不在门禁基线 —— 新增面必须同步基线`);
    }
  }
  const dup = table.polite.filter((id) => table.off.includes(id));
  if (dup.length) out.push(`同一 id 挂在两档：${dup.join('、')}`);
  return out;
}

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
  // 焦点环（v5-K05 批次 8 补，门禁候选「6 条断言 0 处管焦点环」）：判据 = 该窗加载的
  // CSS 合并集存在 :focus-visible 规则（A3 裁决：ds.css:181 规则以 bg+color 作替代
  // 指示，存在性判据即可，不规定实现形态）。
  check(focusVisibleMissing('body { color: red; }'), '对照④d：无 :focus-visible 规则的样本必须判红');
  check(!focusVisibleMissing(':focus-visible { outline: 2px solid; }'), '对照④e：有焦点环的样本必须放行');

  const badDup = "a?.addEventListener('click', f1);\na?.addEventListener('click', f2);";
  const goodDup = "a?.addEventListener('click', f1);\nb.addEventListener('click', f2);\nrows.forEach(el => el.addEventListener('click', f3));";
  check(dupOptChainRegistrations(badDup).length === 1, '对照⑤a：同元素同事件的可选链重复注册必须判红');
  check(dupOptChainRegistrations(goodDup).length === 0, '对照⑤b：不同元素/循环内注册必须放行');
  check(windowAppViolations('const x = window.app?.toast?.(1);').length === 1, '对照⑥a：子窗代码依赖 window.app 必须判红');
  check(!collapseKeyWiring("el.addEventListener('click', f);"), '对照⑦a：只有 click 绑定的折叠头样本必须判红');
  check(collapseKeyWiring("el.addEventListener('keydown', e => { if (e.key === 'Enter') el.click(); });"), '对照⑦b：补了 Enter 键盘通路的样本必须放行');

  const base = [
    { id: 'a', mode: 'polite', where: 'idle' },
    { id: 'c', mode: 'off', where: 'idle' },
    { id: 'p', mode: 'polite', where: 'html' },
  ];
  const goodTable = { polite: ['a'], off: ['c'] };
  const goodTag = (id) => (id === 'p' ? '<span id="p" role="status" aria-live="polite">' : null);
  check(liveCoverageProblems(goodTable, base, goodTag).length === 0, '对照⑧a：覆盖齐全的样本必须放行');
  check(liveCoverageProblems({ polite: [], off: ['c'] }, base, goodTag).some((v) => v.includes('a ')), '对照⑧b：漏挂必须判红');
  check(liveCoverageProblems({ polite: [], off: ['a', 'c'] }, base, goodTag).some((v) => v.includes('a ')), '对照⑧c：挂错档必须判红');
  check(liveCoverageProblems(goodTable, base, () => '<span id="p">').some((v) => v.includes('aria-live')), '对照⑧d：HTML 宿主缺属性必须判红');
  check(liveCoverageProblems({ polite: ['a', 'x'], off: ['c'] }, base, goodTag).some((v) => v.includes('x ')), '对照⑧e：表里多出未登记 id 必须判红');
  check(liveCoverageProblems({ polite: ['a'], off: ['c', 'a'] }, base, goodTag).some((v) => v.includes('两档')), '对照⑧f：同 id 挂两档必须判红');
  check(liveCoverageProblems(null, base, goodTag).length > 0, '对照⑧g：挂载表解析不到必须判红');
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

// ---- ⑦ 真仓扫描：折叠头键盘接线 ----
{
  const byRel = new Map(sources.map(([p, text]) => [rel(p).replace(/\\/g, '/'), text]));
  let wired = 0;
  for (const s of COLLAPSE_SITES) {
    const text = byRel.get(s.file);
    if (text === undefined) {
      g.fail(`⑦ 站点文件 ${s.file} 不在扫描面里（改名/移出 ⇒ 清单与语料必须同步，本条不能静默跳过）`);
      continue;
    }
    if (!text.includes(s.needle)) {
      g.fail(`⑦ ${s.file} 找不到锚点 ${s.needle}（${s.why}）⇒ 站点被搬走或改名，键盘接线判据已失明`);
      continue;
    }
    if (!collapseKeyWiring(text)) {
      g.fail(`⑦ ${s.file} 的折叠头 ${s.needle} 缺键盘等价路径（${s.why}）：只挂 click ⇒ 键盘用户折叠不了、也打不开详情`);
      continue;
    }
    wired++;
  }
  if (wired === COLLAPSE_SITES.length) g.ok(`⑦ 折叠头/行点击头键盘接线 ${wired}/${COLLAPSE_SITES.length} 站点全部在位`);
}

// ---- ⑧ 真仓扫描：live region 覆盖（A3-M01） ----
if (g.skipUnlessPresent(LIVE_MOUNT_FILE, 'src/scripts/a11y-live.js（A3-M01 挂载表）')) {
  const appText = existsSync(APP_JS_FILE) ? read(APP_JS_FILE) : '';
  const idleBlock = (appText.match(/IDLE_SCRIPTS\s*=\s*\[([\s\S]*?)\]/) || [])[1] || '';
  if (!idleBlock.includes("'scripts/a11y-live.js'")) {
    g.fail('⑧ a11y-live.js 没登记进 app.js 的 IDLE_SCRIPTS ⇒ 挂载表是死代码（页面永远不会挂上）');
  } else if (appText) {
    g.ok('⑧ a11y-live.js 已登记进 IDLE_SCRIPTS（首帧后挂载，不占首屏预算）');
  }
  const table = parseLiveMountTable(read(LIVE_MOUNT_FILE));
  const htmlTexts = htmlFiles.map((p) => read(p));
  const findTag = (id) => {
    for (const t of htmlTexts) {
      const tag = tagOfId(t, id);
      if (tag) return tag;
    }
    return null;
  };
  for (const v of liveCoverageProblems(table, LIVE_BASELINE, findTag)) g.fail(`⑧ ${v}`);
  if (table && table.polite && table.off) {
    if (table.polite.length < 20) g.fail(`⑧ polite 表只解析到 ${table.polite.length} 条（< 20）⇒ 语料塌缩`);
    if (table.off.length < 6) g.fail(`⑧ off 表只解析到 ${table.off.length} 条（< 6）⇒ 语料塌缩`);
    const htmlHosts = LIVE_BASELINE.filter((b) => b.where === 'html').length;
    g.ok(`⑧ live region 覆盖 ${LIVE_BASELINE.length} 个宿主（idle polite ${table.polite.length} / off ${table.off.length} + HTML 宿主 ${htmlHosts}）`);
  }
}

// ---- 扫描面地板（低于粗下界 ⇒ 疑似正则/目录失明，判红） ----
if (checkboxSites < 4) g.fail(`勾选框模板命中 ${checkboxSites} 处（< 4）⇒ 扫描面疑似失明`);
if (liveHosts < 4) g.fail(`异步提示宿主命中 ${liveHosts} 处（< 4）⇒ 扫描面疑似失明`);
if (tipSites < 10) g.fail(`data-tip 命中 ${tipSites} 处（< 10）⇒ 扫描面疑似失明`);

// ---- ④ 真仓扫描：**逐窗** RM 归零覆盖 + 焦点环（v5-K05 批次 8 改回能判红） ----
// P0 子窗 CSS 按需（6a8f02b）曾把全窗 RM 归零段搬进只主窗加载的 main-pages.css，
// 四子窗动效归零整段失效（可达动效 32/19/14/16 条照播），而旧判据「main+pages 合并判」
// 照绿——合并集把「搬错文件」读成「已覆盖」。归零覆盖面是**每扇窗**的属性：
// 逐窗解析各自 <link> 的 CSS 合并集判，「归零段搬错文件 / 子窗漏挂 CSS」都会红。
{
  const cssCache = new Map();
  const loadCss = (f) => {
    if (!cssCache.has(f)) cssCache.set(f, readFileSync(join(SRC, 'styles', f), 'utf8'));
    return cssCache.get(f);
  };
  let windowCount = 0;
  for (const p of htmlFiles) {
    const html = read(p);
    const links = styleLinks(html).map((h) => h.split('/').pop());
    if (links.length === 0) {
      g.fail(`${rel(p)}：没有解析到任何 stylesheet link（窗体 CSS 覆盖判定失明）`);
      continue;
    }
    windowCount++;
    const merged = links.map(loadCss).join('\n');
    for (const v of rmViolations(merged)) {
      g.fail(`${rel(p)}：${v}（该窗加载 ${links.join(', ')}）`);
    }
    if (focusVisibleMissing(merged)) {
      g.fail(`${rel(p)}：该窗加载的 CSS（${links.join(', ')}）无 :focus-visible 规则（键盘焦点不可见）`);
    }
  }
  // preview 子窗退役后主窗+3 子窗 = 4 份（2026-10-13）
  if (windowCount < 4) g.fail(`逐窗 RM 判定只覆盖 ${windowCount} 份 HTML（< 4）⇒ 语料失明`);
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

// T1d-K01：采集面地板——jsFiles 塌缩（scripts/ 或 vendor/ 改名）时其余断言全是空集假绿
if (jsFiles.length < JS_CORPUS_FLOOR) {
  g.fail(`前端 js 语料只有 ${jsFiles.length} 个（< ${JS_CORPUS_FLOOR}）⇒ 采集面塌陷（scripts/** + vendor/** 递归现算），拒绝判绿`);
}

console.log(
  `\n扫描：${sources.length} 个源文件（js 语料 ${jsFiles.length} 个） · 勾选框模板 ${checkboxSites} 处 · 提示宿主 ${liveHosts} 处 · data-tip ${tipSites} 处`,
);
if (fail > 0) {
  console.error(`check-a11y: 正向对照自检 ${fail} 处失败（判定器失效，本门禁不可信）`);
  process.exit(1);
}
g.finish('check-a11y: 全部通过');
