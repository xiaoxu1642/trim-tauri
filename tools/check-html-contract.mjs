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
