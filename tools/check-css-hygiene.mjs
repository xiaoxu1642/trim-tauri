#!/usr/bin/env node
// check-css-hygiene.mjs —— CSS 卫生五断言（P2-E / P3 库存 F1a-L01…L06、F1c-M01，2026-10-26）
//
// 为什么单独成门禁：这五类都是「改动后渲染等价、但下一任维护者会被坑」的形态，
// check-css-tokens 管 token 引用/圆角档位，check-contrast 管对比度，都不管：
//   ① 已定义 token 的 var() 不得再带颜色字面兜底（第二套口径留在引用点）
//   ② var(--x, var(--x)) 同名自引用（无效构造，会被误读成另一档）
//   ③ 注释提前终止：非贪婪剥注释后仍残留 `*/`（文字会进入声明流）
//   ④ 胶囊圆角：>=90px 的字面值必须恰好 999（99px 一类混写）
//   ⑤ .ctx-detail-modal 外壳的 border / border-radius / box-shadow 只能各声明一次
//      （同特异度多份声明靠源序定胜负，改一条不生效）
//   ⑥ .titlebar-title 的文字色必须走 token（离表 hex 在恒浅色下是死值）
//
// 用法：node tools/check-css-hygiene.mjs
'use strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CSS_FILES = ['main.css', 'main-pages.css', 'ds.css', 'litebox.css'].map((f) => join(ROOT, 'src', 'styles', f));
const read = (p) => readFileSync(p, 'utf8');
const blank = (t) => t.replace(/\/\*[\s\S]*?\*\//g, ' ');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

// ---------- 纯判据（真仓与合成样本共用） ----------
function colorFallbacks(text) {
  return [...text.matchAll(/var\(--([a-zA-Z0-9-]+),\s*(#[0-9A-Fa-f]{3,8}|rgba?\([^)]*\))/g)]
    .map((m) => ({ token: m[1], raw: m[0] }));
}
function selfRefs(text) {
  return [...text.matchAll(/var\(--([a-z-]+),\s*var\(--\1\)\)/g)].map((m) => m[0]);
}
function residualCloseComments(text) {
  return (blank(text).match(/\*\//g) || []).length;
}
function capsuleRadiusViolations(text) {
  const out = [];
  for (const m of text.matchAll(/border[a-z-]*radius\s*:\s*([^;}]+)/gi)) {
    for (const px of m[1].matchAll(/(\d+(?:\.\d+)?)px/g)) {
      const v = Number(px[1]);
      if (v >= 90 && v !== 999) out.push(m[0].trim());
    }
  }
  return out;
}
function ctxModalDecls(text) {
  const blocks = [...text.matchAll(/\.ctx-detail-modal\s*\{([\s\S]*?)\}/g)].map((m) => m[1]);
  const n = (re) => blocks.reduce((a, b) => a + (b.match(re) || []).length, 0);
  return { blocks: blocks.length, border: n(/(?:^|[\s;])border\s*:/g), radius: n(/border-radius\s*:/g), shadow: n(/box-shadow\s*:/g) };
}
function titlebarHex(text) {
  const m = text.match(/\.titlebar-title\s*\{([\s\S]*?)\}/);
  if (!m) return ['找不到 .titlebar-title 规则'];
  const color = (m[1].match(/color\s*:\s*([^;]+)/) || [])[1] || '';
  return /#[0-9A-Fa-f]{3,8}/.test(color) ? [`color: ${color.trim()} 是离表 hex`] : [];
}

// ---------- 正向对照 ----------
{
  check(colorFallbacks('a{color:var(--fg,#123456)}').length === 1, '对照①a：定义内 token 带颜色兜底必须判红');
  check(colorFallbacks('a{color:var(--fg)}').length === 0, '对照①b：无兜底必须放行');
  check(colorFallbacks('a{transform:translate(var(--lg-x, 0px))}').length === 0, '对照①c：数值兜底不误报');
  check(selfRefs('a{color:var(--x, var(--x))}').length === 1, '对照②a：同名自引用必须判红');
  check(selfRefs('a{color:var(--x, var(--y))}').length === 0, '对照②b：改名过渡写法放行');
  check(residualCloseComments('/* a --d-*/--e-* */') === 1, '对照③a：注释提前终止必须判红');
  check(residualCloseComments('/* a --d-* / --e-* */') === 0, '对照③b：打断后放行');
  check(capsuleRadiusViolations('a{border-radius:99px}').length === 1, '对照④a：99px 必须判红');
  check(capsuleRadiusViolations('a{border-radius:999px}').length === 0, '对照④b：999px 放行');
  check(capsuleRadiusViolations('a{border-radius:50%}').length === 0, '对照④c：50% 放行');
  check(ctxModalDecls('.ctx-detail-modal{border:1px solid;border-radius:8px;box-shadow:none}').radius === 1, '对照⑤a：单份声明放行');
  check(ctxModalDecls('.ctx-detail-modal{border-radius:8px}.ctx-detail-modal{border-radius:10px}').radius === 2, '对照⑤b：同属性两份必须能被数出');
  check(titlebarHex('.titlebar-title{color:#1C1C1C}').length === 1, '对照⑥a：离表 hex 必须判红');
  check(titlebarHex('.titlebar-title{color:var(--fg-primary)}').length === 0, '对照⑥b：token 放行');
}

// ---------- 真仓 ----------
console.log('');
const present = CSS_FILES.filter((f) => existsSync(f));
check(present.length === CSS_FILES.length, `输入面：${present.length}/${CSS_FILES.length} 份 CSS 在盘`, present.length !== CSS_FILES.length ? '缺件 ⇒ 本节 SKIP，不是通过' : '');
if (present.length !== CSS_FILES.length) {
  console.log('SKIP：CSS 输入不全，卫生断言**未校验**');
  process.exit(1);
}
const texts = present.map((f) => ({ f, raw: read(f), bare: blank(read(f)) }));
const commentFloor = texts.reduce((a, t) => a + (t.raw.match(/\/\*/g) || []).length, 0);
check(commentFloor >= 300, `注释扫描面地板：/* 共 ${commentFloor} 个（>= 300）`);

const fb = texts.flatMap((t) => colorFallbacks(t.bare).map((x) => `${t.f.slice(ROOT.length + 1)}: ${x.raw}`));
check(fb.length === 0, '① 已定义 token 的 var() 无颜色字面兜底', fb.join('；'));
const sr = texts.flatMap((t) => selfRefs(t.bare).map((x) => `${t.f.slice(ROOT.length + 1)}: ${x}`));
check(sr.length === 0, '② 无 var(--x, var(--x)) 同名自引用', sr.join('；'));
const rc = texts.flatMap((t) => {
  const n = residualCloseComments(t.raw);
  return n ? [`${t.f.slice(ROOT.length + 1)}: 残留 ${n} 处 */`] : [];
});
check(rc.length === 0, '③ 注释无提前终止（剥注释后残留 */ 为 0）', rc.join('；'));
const cap = texts.flatMap((t) => capsuleRadiusViolations(t.bare).map((x) => `${t.f.slice(ROOT.length + 1)}: ${x}`));
check(cap.length === 0, '④ 胶囊圆角字面值只允许 999px（>=90 的其它值判红）', cap.join('；'));
const modal = ctxModalDecls(texts.find((t) => t.f.endsWith('main.css')).bare);
check(
  modal.blocks >= 2 && modal.border === 1 && modal.radius === 1 && modal.shadow === 1,
  `⑤ .ctx-detail-modal 外壳声明各一份（${modal.blocks} 个规则块 / border ${modal.border} / radius ${modal.radius} / shadow ${modal.shadow}）`,
);
const tb = titlebarHex(texts.find((t) => t.f.endsWith('main.css')).bare);
check(tb.length === 0, '⑥ .titlebar-title 文字色走 token', tb.join('；'));

console.log('');
if (fail > 0) {
  console.error(`check-css-hygiene: ${fail} 组断言未通过`);
  process.exit(1);
}
console.log('check-css-hygiene: 全部通过');
