#!/usr/bin/env node
// check-html-contract.mjs —— HTML 合同门禁（v2-L4P-16 E-4 / L4 §7.3，2026-10-02）
//
// 两条硬红线此前无任何机检（E-4），全靠「注释里写了要这么做」：
//   1. src/*.html 禁内联 <script>（无 src 属性的 script 会被 CSP 静默拦截，
//      「页面功能失灵但零报错」——本仓最阴的一类回归）；
//   2. 每个窗口 HTML 都必须挂 ds.css + ds.js（modal 焦点陷阱按「window.ds 缺席即降级」
//      写，少挂 = 子窗高危确认没有 Tab 圈闭、data-tip 退回无样式）。
//   3. 加载序：ds.js 必须先于 liquid-glass.js / spotlight.js（AGENTS §2）。
// 判红自证：注入一个内联 script / 摘掉一个 ds 引用都会红。
'use strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

const htmlFiles = readdirSync(SRC).filter((f) => f.endsWith('.html'));
const inlineHits = [];
const missingDs = [];
const orderHits = [];
const idDups = [];

for (const f of htmlFiles) {
  const text = readFileSync(join(SRC, f), 'utf8');
  // 1. 内联 script（无 src 的 <script> 或 <script>…</script> 带体）。注释里的字样
  //    先剥掉再判——HTML 注释里引用「禁内联 script」属文档，不是违规。
  const clean = text.replace(/<!--[\s\S]*?-->/g, ' ');
  if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(clean)) {
    inlineHits.push(f);
  }
  // 2. ds.css + ds.js 挂载
  if (!/href="[^"]*styles\/ds\.css"/.test(clean)) missingDs.push(`${f}: ds.css`);
  if (!/src="[^"]*scripts\/ds\.js"/.test(clean)) missingDs.push(`${f}: ds.js`);
  // 3. 加载序（AGENTS §2 实口径）：spotlight.js 在 liquid-glass.js 之后；
  //    ds.js 先于确证的 window.ds 使用方（modal.js；liquid-glass 已核实零 ds 依赖，不在此列）
  const posDs = clean.search(/src="[^"]*scripts\/ds\.js"/);
  const posGlass = clean.search(/src="[^"]*scripts\/liquid-glass\.js"/);
  const posSpot = clean.search(/src="[^"]*scripts\/spotlight\.js"/);
  if (posGlass >= 0 && posSpot >= 0 && posSpot < posGlass) {
    orderHits.push(`${f}: spotlight.js 未在 liquid-glass.js 之后`);
  }
  const posModal = clean.search(/src="[^"]*scripts\/modal\.js"/);
  if (posModal >= 0 && posDs >= 0 && posModal < posDs) {
    orderHits.push(`${f}: modal.js（ds 使用方）先于 ds.js 加载`);
  }
  // 4. 同文档 id 唯一（P2-4 / F3-M05）：重复 id 会让 getElementById 恒取文档里第一个 ——
  //    bgBlurVal×2 曾让原生滑块读数写进另一套控件的 span、自己恒停 0%（界面与真实值相反）。
  //    判据取「前导空白 + id=」：排除 data-id 这类复合属性名（其 `id` 前是 `-` 非空白）。
  const ids = [...clean.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]);
  const dup = [...new Set(ids.filter((x, i) => ids.indexOf(x) !== i))];
  if (dup.length) idDups.push(`${f}: ${dup.join(' / ')}`);
}

check(
  inlineHits.length === 0,
  '1. src/*.html 零内联 <script>（CSP 静默拦截红线）',
  inlineHits.join(', '),
);
check(
  missingDs.length === 0,
  `2. ${htmlFiles.length} 个窗口 HTML 全部挂载 ds.css + ds.js`,
  missingDs.join(', '),
);
check(
  orderHits.length === 0,
  '3. 加载序：spotlight 在 liquid-glass 之后；ds.js 先于确证的 ds 使用方',
  orderHits.join('；'),
);
check(
  idDups.length === 0,
  `4. ${htmlFiles.length} 份 HTML 文档内 id 唯一（重复 id 会让 getElementById 指向错元素）`,
  idDups.join('；'),
);

// ---- 5. DOM 契约名双向对拍（P3-5 / F4a-G-8） ----
// 判据：JS 里 `getElementById('x')` / `el('x')` 引用的 id，必须在**某份 HTML** 里存在，
// 或能在 src 全量里找到**生成点**（模板 `id="x"` / `.id = 'x'` / `setAttribute('id','x')` /
// `id: 'x'`——运行时创建的弹窗/Toast 覆盖这一列）。找不到 = 拼写漂移或死代码引用
// （现算实例：deviceinfo.js 的 deviceInfoRows/deviceInfoStatus —— 板块移除后成了死引用）。
const jsIds = new Map();
const jsFiles5 = readdirSync(join(SRC, 'scripts')).filter((f) => f.endsWith('.js'));
const jsSources = jsFiles5.map((f) => [f, readFileSync(join(SRC, 'scripts', f), 'utf8')]);
const allSources = [
  ...jsSources,
  ...htmlFiles.map((f) => [f, readFileSync(join(SRC, f), 'utf8')]),
];
for (const [f, text] of jsSources) {
  if (f === 'tauri-api.js') continue; // 适配层自身引用 caption 节点，生成点也在这里
  for (const m of text.matchAll(/(?:el|getElementById)\(\s*'([A-Za-z][\w-]*)'\s*\)/g)) {
    if (!jsIds.has(m[1])) jsIds.set(m[1], f);
  }
}
const knownIds = new Set();
for (const [f, text] of allSources) {
  for (const m of text.matchAll(/\bid="([^"]+)"/g)) knownIds.add(m[1]);
}
const generatedId = (id) => {
  const pats = [
    new RegExp(`\\.id\\s*=\\s*['"]${id}['"]`),
    new RegExp(`setAttribute\\(\\s*['"]id['"]\\s*,\\s*['"]${id}['"]`),
    new RegExp(`id:\\s*['"]${id}['"]`),
  ];
  return allSources.some(([, t]) => pats.some((p) => p.test(t)));
};
const ghostIds = [...jsIds].filter(([id]) => !knownIds.has(id) && !generatedId(id));
check(
  jsIds.size >= 100,
  `5. JS 引用的 id 总量 ${jsIds.size}（≥100 为地板，防扫描面失明）`,
  jsIds.size < 100 ? '引用集趋零 ⇒ 语料或正则失明' : '',
);
check(
  ghostIds.length === 0,
  `5b. JS 引用的 ${jsIds.size} 个 id 全部在 HTML 或生成点里成立`,
  ghostIds.length ? ghostIds.slice(0, 10).map(([id, f]) => `${f}: ${id}`).join('；') : '',
);

// ---- 6. 表头 ⇄ 行单元属性名成对（P3-5 / F5-G-4） ----
// xtable 的表头 `data-col`（xtable.js 渲染）与行单元 `data-cell`（cleanup.js 渲染）
// 必须由**同一个列键表达式**派生（`${col.key}`）—— 一旦两侧各写各的键名，
// 列宽/排序改的是表头、行却对不上（F5-M07 的同族形态）。
{
  const xtable = readFileSync(join(SRC, 'scripts', 'xtable.js'), 'utf8');
  const cleanup = readFileSync(join(SRC, 'scripts', 'cleanup.js'), 'utf8');
  const colSide = /data-col="\$\{col\.key\}"/.test(xtable);
  const cellSide = /data-cell="\$\{col\.key\}"/.test(cleanup);
  check(
    colSide && cellSide,
    '6. xtable 表头 data-col 与行单元 data-cell 同源（${col.key}）',
    colSide && cellSide ? '' : `表头侧=${colSide} / 行侧=${cellSide} —— 两侧键名表达式必须同为 \${col.key}`,
  );
}

if (fail > 0) {
  console.error('check-html-contract: 存在违规');
  process.exit(1);
}

// ---- E-8/E-15 正向对照自检（v2-L4P-16/44）：内联检测正则必须抓得到真实违规 ----
const POSITIVE_CONTROLS = (() => {
  const dirty = '<body><script>alert(1)</script></body>';
  const clean = '<script src="scripts/app.js"></script>';
  const re = /<script(?![^>]*\bsrc=)[^>]*>/i;
  if (!re.test(dirty.replace(/<!--[\s\S]*?-->/g, ' ')) || re.test(clean)) {
    console.error('✗ 正向对照失败：内联 script 判定失效');
    process.exit(1);
  }
  console.log('✓ 正向对照自检通过（内联样本命中、外链样本放行）');
  return true;
})();

console.log('check-html-contract: 全部通过');
