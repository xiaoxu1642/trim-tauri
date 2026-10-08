// check-escape-delegation.mjs —— 本地 escape* 薄包装「只许委托、不许重实现/新增」门禁
// （审查 L3 2026-10-01 NEW-3）
//
// 背景：转义唯一真源是 ds.js（ds.esc / ds.escAttr；escAttr 与 esc 同字符集，因
// 「哪个引号包属性」会随改动变——见 AGENTS.md 硬性红线）。历史上各脚本留下本地
// escapeHtml/escapeAttr 薄包装，红线口径为「历史存量不扩散」。真实危害是**重实现**
// （字符集与 ds 不一致 → 转义口径分叉、单引号漏 escaping 导致属性逃逸），而非委托
// 本身。故本门禁断言两件事：
//   1) 每一个本地 escapeHtml/escapeAttr 定义体必须是纯委托
//      `return window.ds.esc(...)` / `return window.ds.escAttr(...)`（含薄计算亦可，
//      但必须以 window.ds.esc/escAttr 的返回值为最终返回）；
//   2) 定义总数不得超过 BASELINE（29，2026-10-01 现盘实测）——只许随收敛递减，
//      新文件/新代码再定义即红（棘轮）。
// 完全收敛（删包装、调用点直用 window.ds.*）为渐进目标：触到哪个文件顺手改哪个，
// 改完把 BASELINE 相应下调即可（下调无需审批，上调即红）。
//
// 判红验证：① 把任一包装体改成非委托实现（如 `return s;`）→ 红；
//           ② 任一文件临时加 `function escapeHtml(s) { return s; }` → 红（计数+形态双红）。
//
// 用法：node tools/check-escape-delegation.mjs

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

// 基线 = 2026-10-02 v2-L4P-16（E-2）重算：`function` 定义 29 + 箭头定义 1
// （runtimes.js:9 `const escapeHtml = (s) => window.ds.esc(s)`，旧正则看不见）
// = 30。只许下调。
const BASELINE = 30;

const dir = join(REPO_ROOT, 'src', 'scripts');
const files = readdirSync(dir).filter((f) => f.endsWith('.js')).sort();

function stripBlockComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
}

// 定义体允许跨行；体内容不含 `}` 的前提下整段截取（包装函数极薄，足够）
const RE_DEF = /function\s+(escapeHtml|escapeAttr)\s*\([^)]*\)\s*\{([^}]*)\}/g;
// v2-L4P-16（E-2）：箭头函数定义形（`const escapeHtml = (s) => window.ds.esc(s)`）
// 与 `const x = function (...) {…}` 形——旧正则只认 function 声明，存量因此少算 1。
const RE_DEF_ARROW = /(?:const|let|var)\s+(escapeHtml|escapeAttr)\s*=\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*([^;\n]+)/g;
const RE_DEF_FNEXPR = /(?:const|let|var)\s+(escapeHtml|escapeAttr)\s*=\s*function\s*\([^)]*\)\s*\{([^}]*)\}/g;

let fail = 0;
let count = 0;
const badForm = [];

const delegated = (kind, body) =>
  new RegExp(`window\\.ds\\.${kind === 'escapeHtml' ? 'esc' : 'escAttr'}\\s*\\(`).test(body);

for (const f of files) {
  const text = stripBlockComments(readFileSync(join(dir, f), 'utf8'));
  let m;
  RE_DEF.lastIndex = 0;
  while ((m = RE_DEF.exec(text)) !== null) {
    count++;
    if (!delegated(m[1], m[2].trim())) {
      const line = text.slice(0, m.index).split('\n').length;
      badForm.push(`${f}:${line} ${m[1]}`);
    }
  }
  RE_DEF_ARROW.lastIndex = 0;
  while ((m = RE_DEF_ARROW.exec(text)) !== null) {
    count++;
    if (!delegated(m[1], m[2])) {
      const line = text.slice(0, m.index).split('\n').length;
      badForm.push(`${f}:${line} ${m[1]}(箭头形)`);
    }
  }
  RE_DEF_FNEXPR.lastIndex = 0;
  while ((m = RE_DEF_FNEXPR.exec(text)) !== null) {
    count++;
    if (!delegated(m[1], m[2].trim())) {
      const line = text.slice(0, m.index).split('\n').length;
      badForm.push(`${f}:${line} ${m[1]}(函数表达式)`);
    }
  }
}

console.log('=== 本地 escape* 薄包装委托与棘轮门禁 ===\n');
// 扫描面地板（P0-4）：src/scripts 被改名/清空 ⇒ files=[]、count=0，旧输出
// 「✓ 定义总数 0 ≤ 基线 30」是空集假绿。基线 > 0 时定义数归零只能是正则或语料损坏。
if (files.length === 0) {
  console.error('✗ src/scripts 下没有 .js 文件 ⇒ 扫描面失效（目录被搬/改名？），拒绝判绿');
  fail++;
}
if (BASELINE > 0 && count === 0) {
  console.error(`✗ escape* 定义排查结果 0 条（基线 ${BASELINE}）⇒ 判定正则或语料失效，不允许判绿`);
  fail++;
}
for (const b of badForm) {
  console.error(`✗ ${b} — 定义体不是 window.ds.esc/escAttr 纯委托（重实现会与真源字符集分叉）`);
  fail++;
}
const okCount = count <= BASELINE;
console.log(`${okCount ? '✓' : '✗'} 定义总数 ${count} ${okCount ? '≤' : '>'} 基线 ${BASELINE}（只许递减，禁止新增）`);
if (!okCount) fail++;

// ---- P3-5（F4a-M01）：字节格式化同口径 —— 本地 formatSize/formatBytes/fmtBytes 只许委托 ----
// 与 escape* 同一红线（AGENTS §2：转义/字节格式化唯一真源 ds.js）。真源本体在 ds.js，
// 不计入；其余文件的本地定义必须是纯委托 `window.ds.fmtBytes(...)`（棘轮 ≤ 现算 7）。
const BYTE_BASELINE = 7;
const RE_BYTE_DEF = /function\s+(formatSize|formatBytes|fmtBytes)\s*\([^)]*\)\s*\{([^}]*)\}/g;
let byteCount = 0;
const byteBad = [];
for (const f of files) {
  if (f === 'ds.js') continue; // 真源本体
  const text = stripBlockComments(readFileSync(join(dir, f), 'utf8'));
  RE_BYTE_DEF.lastIndex = 0;
  let m;
  while ((m = RE_BYTE_DEF.exec(text)) !== null) {
    byteCount++;
    if (!/window\.ds\.fmtBytes\s*\(/.test(m[2])) {
      byteBad.push(`${f}:${text.slice(0, m.index).split('\n').length} ${m[1]}`);
    }
  }
}
if (BYTE_BASELINE > 0 && byteCount === 0) {
  console.error(`✗ 字节格式化定义排查 0 条（基线 ${BYTE_BASELINE}）⇒ 判定正则或语料失效，不允许判绿`);
  fail++;
}
for (const b of byteBad) {
  console.error(`✗ ${b} — 本地字节格式化不是 window.ds.fmtBytes 纯委托（§2 红线：真源唯一在 ds.js）`);
  fail++;
}
const byteOk = byteCount <= BYTE_BASELINE;
console.log(`${byteOk ? '✓' : '✗'} 字节格式化本地包装 ${byteCount} ${byteOk ? '≤' : '>'} 基线 ${BYTE_BASELINE}（只许递减）`);
if (!byteOk) fail++;
// 正向对照：非委托样本必须判形态红；委托样本必须放行
{
  const bad = 'function formatSize(bytes) { return bytes.toFixed(1) + " KB"; }';
  const good = 'function formatSize(bytes) { return window.ds.fmtBytes(bytes); }';
  const re = new RegExp(RE_BYTE_DEF.source, 'g');
  const bm = re.exec(bad);
  re.lastIndex = 0;
  const gm = re.exec(good);
  if (!bm || /window\.ds\.fmtBytes\s*\(/.test(bm[2]) || !gm || !/window\.ds\.fmtBytes\s*\(/.test(gm[2])) {
    console.error('✗ 正向对照失败：字节格式化判定器失效（非委托未判红或委托被误判）');
    fail++;
  }
}

console.log('');
if (fail > 0) {
  console.error('门禁失败：本地 escape* 包装违反委托/棘轮约束（见上）');
  process.exit(1);
}

// ---- E-8/E-15 正向对照自检（v2-L4P-16/44）：判定正则必须抓得到违规与新增 ----
const POSITIVE_CONTROLS = (() => {
  const synth = 'const escapeHtml = (s) => s;'; // 箭头形 + 非委托：应同时被「计数」与「形态」抓到
  let n = 0, bad = false;
  let m;
  const re = new RegExp(RE_DEF_ARROW.source, 'g');
  while ((m = re.exec(synth)) !== null) { n++; if (!delegated(m[1], m[2])) bad = true; }
  if (n !== 1 || !bad) {
    console.error('✗ 正向对照失败：非委托箭头定义未被识别——判定器已失效');
    process.exit(1);
  }
  console.log('✓ 正向对照自检通过（非委托箭头定义可被抓到）');
  return true;
})();

console.log(`本地 escape* 包装门禁通过（${count}/${BASELINE}）`);
