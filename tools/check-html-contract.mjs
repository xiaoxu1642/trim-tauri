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
// T1d-M08：内联 script 判据的唯一实现（真仓扫描与对照共用）。
const stripHtmlComments = (text) => text.replace(/<!--[\s\S]*?-->/g, ' ');
const hasInlineScript = (text) => /<script(?![^>]*\bsrc=)[^>]*>/i.test(stripHtmlComments(text));
// T1d-M12：ds 使用方集合现算（剥注释后逐文件），不是手抄一个 modal.js。
const jsFiles = readdirSync(join(SRC, 'scripts')).filter((f) => f.endsWith('.js'));
const dsUsers = new Set();
for (const f of jsFiles) {
  if (f === 'ds.js') continue;
  const code = readFileSync(join(SRC, 'scripts', f), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, '$1');
  if (/\bwindow\.ds\b|\bds\.[A-Za-z_$]/.test(code)) dsUsers.add(f);
}
const inlineHits = [];
const missingDs = [];
const spotOrderHits = [];
const dsOrderHits = [];
const idDups = [];
let spotPairs = 0; // 同一份 HTML 里 spotlight 与 liquid-glass 都静态挂载的对数（本仓为 0）

for (const f of htmlFiles) {
  const text = readFileSync(join(SRC, f), 'utf8');
  // 1. 内联 script（无 src 的 <script> 或 <script>…</script> 带体）。注释里的字样
  //    先剥掉再判——HTML 注释里引用「禁内联 script」属文档，不是违规。
  const clean = stripHtmlComments(text);
  if (hasInlineScript(text)) {
    inlineHits.push(f);
  }
  // 2. ds.css + ds.js 挂载
  if (!/href="[^"]*styles\/ds\.css"/.test(clean)) missingDs.push(`${f}: ds.css`);
  if (!/src="[^"]*scripts\/ds\.js"/.test(clean)) missingDs.push(`${f}: ds.js`);
  // 3. 加载序（AGENTS §2 实口径）：spotlight.js 在 liquid-glass.js 之后；
  //    ds.js 先于**全部**现算出的 window.ds 使用方（T1d-M12）。
  const srcs = [...clean.matchAll(/<script[^>]*\bsrc="([^"]+)"/g)].map((m) => m[1]);
  const dsIdx = srcs.findIndex((s) => /scripts\/ds\.js$/.test(s));
  const posGlass = clean.search(/src="[^"]*scripts\/liquid-glass\.js"/);
  const posSpot = clean.search(/src="[^"]*scripts\/spotlight\.js"/);
  if (posGlass >= 0 && posSpot >= 0) spotPairs++;
  spotOrderHits.push(...spotOrderViolations(text, f));
  for (const [i, s] of srcs.entries()) {
    const name = s.split('/').pop();
    if (dsUsers.has(name) && dsIdx >= 0 && i < dsIdx) {
      dsOrderHits.push(`${f}: ${name}（ds 使用方）先于 ds.js 加载`);
    }
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
// ── 3a（P2-A/A-5）：spotlight ⇄ liquid-glass 的加载序，带**可判对象数下限** ──
// 拆两条之前：spotlight 那一支与有对象的 ds 支共用一条 ✓，而它自己恒 0 对象 ——
// 本仓 spotlight.js 只出现在 app.js 的 IDLE_SCRIPTS（首帧后注入），liquid-glass.js 才是
// 静态 defer，「同一份 HTML 里两者都静态挂载」永不成立。0 对象的断言不是「通过」是「没测」，
// 摘掉 spotlight 的按需入口这种回归不会留下任何信号。现在把可判对象算成
// 「静态对 + 按需注入支」，掉到 0 即红。
//
// T1d-M31：两类计数**分开印**——「静态可比对」才是真正的序判定对象（比较同一份
// HTML 里两份静态挂载的位置）；「按需注入支」只是**存在性代理**（spotlight 在
// IDLE_SCRIPTS 且 index.html 有 liquid-glass），它的「1」不随真实序对象数变
//（E1h 反例：把 spotlight 静态挂进没有 liquid-glass 的窗口，仍印 1）。代理成立的
// 前提「IDLE 注入晚于首帧」由 check-idle-scripts 钉住，本件不重复判。
function spotOrderViolations(html, label) {
  const clean = stripHtmlComments(html);
  const posGlass = clean.search(/src="[^"]*scripts\/liquid-glass\.js"/);
  const posSpot = clean.search(/src="[^"]*scripts\/spotlight\.js"/);
  if (posGlass >= 0 && posSpot >= 0 && posSpot < posGlass) {
    return [`${label}: spotlight.js 未在 liquid-glass.js 之后`];
  }
  return [];
}
// 合成对照（T1d-M31）：「静态对且序反」必红、「序正」放行 —— 判定器与真仓扫描共用同一实现。
check(
  spotOrderViolations('<script src="scripts/spotlight.js" defer></script><script src="scripts/liquid-glass.js" defer></script>', 't').length === 1,
  '3a 对照a：静态对且序反的样本必须判红',
);
check(
  spotOrderViolations('<script src="scripts/liquid-glass.js" defer></script><script src="scripts/spotlight.js" defer></script>', 't').length === 0,
  '3a 对照b：序正的样本必须放行',
);
check(
  spotOrderViolations('<script src="scripts/spotlight.js" defer></script>', 't').length === 0,
  '3a 对照c：只有 spotlight 没有 liquid-glass 的样本不得误报',
);
let appJs = '';
try { appJs = readFileSync(join(SRC, 'scripts', 'app.js'), 'utf8'); } catch { /* 下面按未校验处理 */ }
let indexHtml = '';
try { indexHtml = readFileSync(join(SRC, 'index.html'), 'utf8'); } catch { /* 同上 */ }
const idleList = (appJs.match(/const IDLE_SCRIPTS\s*=\s*\[([\s\S]*?)\]/) || ['', ''])[1];
const spotInIdle = /'scripts\/spotlight\.js'/.test(appJs) && /spotlight\.js/.test(idleList);
const liquidStatic = /scripts\/liquid-glass\.js/.test(indexHtml);
const spotObjects = spotPairs + (spotInIdle && liquidStatic ? 1 : 0);
check(
  !!appJs && spotOrderHits.length === 0 && spotObjects >= 1,
  `3a. spotlight 在 liquid-glass 之后（静态可比对 ${spotPairs} 对；按需注入支 ${spotInIdle && liquidStatic ? 1 : 0} = 存在性代理，前提「IDLE 晚于首帧」由 check-idle-scripts 钉）`,
  !appJs ? 'app.js 读不到 ⇒ 本节未校验（按失败处理，不冒充通过）'
    : spotOrderHits.length ? spotOrderHits.join('；')
      : spotObjects === 0
        ? '0 个可判对象：spotlight.js 既不在 IDLE_SCRIPTS、也没有静态对 ⇒ 判据已失明（摘掉按需入口正是这个形状），不是仓库变干净'
        : '',
);
check(
  dsOrderHits.length === 0,
  `3b. ds.js 先于全部现算 ds 使用方（使用方 ${dsUsers.size} 个 / HTML ${htmlFiles.length} 份）`,
  dsOrderHits.join('；'),
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

// ---- 7. 依赖边：凡加载 intro.js 的面必须同时加载 modelpicker.js（F3-M07） ----
// intro.js 无条件渲染「选择模型」按钮，点击时读 window.modelpicker.open；读不到时
// 降级成 toast「模型选择暂不可用」——按钮常显、点击永远失败（残留副窗的真实案例）。
// 扫描面 = src/*.html 静态 script 标签 + app.js 的 PAGE_SCRIPTS 每页清单与 IDLE_SCRIPTS
// （两条动态注入路径都要看，漏一面 = 规则只在静态挂载上生效）。
const judgeIntroPickerEdges = (surfaces) =>
  surfaces.filter((s) => s.names.includes('intro.js') && !s.names.includes('modelpicker.js')).map((s) => s.label);

/** 取 from 中 at 处开括号配对到对应闭括号的文本（at<0 或失配返回 ''） */
const balanced = (from, at) => {
  if (at < 0) return '';
  const open = from[at];
  const close = open === '{' ? '}' : open === '[' ? ']' : '';
  if (!close) return '';
  let d = 0;
  for (let i = at; i < from.length; i++) {
    if (from[i] === open) d++;
    else if (from[i] === close) { d--; if (d === 0) return from.slice(at, i + 1); }
  }
  return '';
};

{
  const surfaces = [];
  for (const f of htmlFiles) {
    const clean = stripHtmlComments(readFileSync(join(SRC, f), 'utf8'));
    surfaces.push({ label: f, names: [...clean.matchAll(/<script[^>]*\bsrc="([^"]+)"/g)].map((m) => m[1].split('/').pop()) });
  }
  const appJs = readFileSync(join(SRC, 'scripts', 'app.js'), 'utf8');
  const pageAt = appJs.indexOf('PAGE_SCRIPTS');
  const idleAt = appJs.indexOf('IDLE_SCRIPTS');
  if (pageAt < 0 || idleAt < 0) {
    check(false, '7. 依赖边 intro.js → modelpicker.js', 'app.js 里定位不到 PAGE_SCRIPTS/IDLE_SCRIPTS 锚点 —— 扫描面失明，先修锚点再谈判定');
  } else {
    const pageBlock = balanced(appJs, appJs.indexOf('{', pageAt));
    for (const m of pageBlock.matchAll(/['"]?([\w-]+)['"]?\s*:\s*\[/g)) {
      const arr = balanced(pageBlock, pageBlock.indexOf('[', m.index));
      surfaces.push({ label: `app.js PAGE_SCRIPTS.${m[1]}`, names: [...arr.matchAll(/'([^']+)'/g)].map((x) => x[1].split('/').pop()) });
    }
    const idleBlock = balanced(appJs, appJs.indexOf('[', idleAt));
    surfaces.push({ label: 'app.js IDLE_SCRIPTS', names: [...idleBlock.matchAll(/'([^']+)'/g)].map((x) => x[1].split('/').pop()) });

    const edgeBad = judgeIntroPickerEdges(surfaces);
    // 扫描面地板（§4.1）：含 intro.js 的面为 0 = 清单解析失明、规则恒绿，不许判绿
    const introFaces = surfaces.filter((s) => s.names.includes('intro.js')).length;
    check(
      edgeBad.length === 0 && introFaces > 0,
      `7. 依赖边：凡加载 intro.js 的面（现算 ${surfaces.length} 面 / 含 intro ${introFaces} 面）必须同时加载 modelpicker.js`,
      edgeBad.join('；') || (introFaces === 0 ? `扫描面里 0 个 intro.js 面 = 解析失明（现算 ${surfaces.length} 面）` : ''),
    );

    // 正向对照自检（§4.1）：缺挂必红 / 双挂放行 / 无 intro 放行
    const selfOk =
      JSON.stringify(judgeIntroPickerEdges([{ label: 'bad', names: ['intro.js'] }])) === JSON.stringify(['bad']) &&
      JSON.stringify(judgeIntroPickerEdges([{ label: 'ok', names: ['modelpicker.js', 'intro.js'] }])) === '[]' &&
      JSON.stringify(judgeIntroPickerEdges([{ label: 'other', names: ['xtable.js'] }])) === '[]';
    check(selfOk, '7s. 依赖边判定器正向对照（缺挂必红 / 双挂放行 / 无 intro 放行）');
  }
}

if (fail > 0) {
  console.error('check-html-contract: 存在违规');
  process.exit(1);
}

// ---- E-8/E-15 正向对照自检（v2-L4P-16/44）：内联检测正则必须抓得到真实违规 ----
const POSITIVE_CONTROLS = (() => {
  const dirty = '<body><script>alert(1)</script></body>';
  const clean = '<script src="scripts/app.js"></script>';
  if (!hasInlineScript(dirty) || hasInlineScript(clean)) {
    console.error('✗ 正向对照失败：内联 script 判定失效');
    process.exit(1);
  }
  console.log('✓ 正向对照自检通过（内联样本命中、外链样本放行）');
  return true;
})();

console.log('check-html-contract: 全部通过');
