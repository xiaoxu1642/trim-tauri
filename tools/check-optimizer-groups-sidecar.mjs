#!/usr/bin/env node
// check-optimizer-groups-sidecar.mjs —— E7 分类侧表 ⇄ 渲染层兜底常量对拍
//
// 为什么需要它：E7 把分类顺序与重映射规则从 `optimizer.js` 搬到
// `src-tauri/data/optimizer-groups.json`（分类口径属产品口径，埋在渲染层就没法
// 被门禁对拍）。但渲染层**仍留了一份兜底常量** `GROUP_FALLBACK`（侧表通道失败时
// 用它，否则分类导航会整块空白）。
//
// 有了两份就有了漂移：改侧表忘了改兜底 ⇒ 侧表通道一失败，分类顺序就静默变回旧的。
// 而且**这种漂移在正常路径下完全不可见**（侧表一直在，兜底永远不被读到）——
// 只有「通道失败」时才暴露，而那恰好是最不该出意外的场合。
//
// 所以本门禁的价值是：把「兜底那份」钉死成「侧表那份」的镜像。
//
// 另外钉两条纪律（AGENTS §2 + M20 审查结论）：
//   ① 侧表**不得含任何颜色字段** —— GROUP_COLORS / GROUP_ACCENT 已在 M20 删除，
//      借这次搬家请回来就是离表色复活。
//   ② 渲染层的**未登记分类兜底**（`renderGroups` 里
//      `Object.keys(byGroup).filter(g => GROUP_ORDER.indexOf(g) === -1)`）必须保留 ——
//      数据层出现新分类而侧表没登记时，它让新分类仍能显示（而不是整类消失）。
'use strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (...p) => readFileSync(join(ROOT, ...p), 'utf8');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

const sidecar = JSON.parse(read('src-tauri', 'data', 'optimizer-groups.json'));
const js = read('src', 'scripts', 'optimizer.js');
const groups = sidecar.groups || {};

// ---- A. 侧表形状 ----
const aProblems = [];
if (!Array.isArray(groups.default) || !groups.default.length) {
  aProblems.push('groups.default 缺失或为空数组');
}
if (!groups.custom || typeof groups.custom.groupMap !== 'object' || !groups.custom || typeof groups.custom.itemOverride !== 'object') {
  aProblems.push('groups.custom.groupMap / groups.custom.itemOverride 缺失或不是对象');
}
check(
  aProblems.length === 0,
  `A. 侧表形状：default ${(groups.default || []).length} 个分类 / groupMap ${Object.keys(groups.custom?.groupMap || {}).length} 条 / itemOverride ${Object.keys(groups.custom?.itemOverride || {}).length} 条`,
  aProblems.join('; '),
);

// ---- B. 侧表**不得含颜色字段**（M20 已删 GROUP_COLORS / GROUP_ACCENT）----
const COLOR_KEYS = /^(color|colors|accent|accents|groupColor|groupAccent|gradient|gradients|bg|background)$/i;
const colorHits = [];
// ⚠️ 判红实验 2 踩到的坑：首版写 `if (pathIn !== '' && COLOR_KEYS.test(k))`，
// 而 `walk(groups, '')` 的**第一层**（`default` / `custom` / `colors`）的 `pathIn`
// 恰好是 `''` —— 于是 `groups.colors` 这种最典型的放法**被放过了**。
// 正确做法：从 `sidecar`（而不是 `groups`）起步，并且**不排除第一层**。
// 键名白名单式匹配（COLOR_KEYS）本身就是精确的，不需要用深度去排除误报。
(function walk(node, pathIn, depth) {
  if (!node || typeof node !== 'object') return;
  for (const [k, v] of Object.entries(node)) {
    if (k === '_comment' || k === '_rule') continue; // 说明性字段，允许提到颜色
    if (COLOR_KEYS.test(k)) colorHits.push(`${pathIn ? `${pathIn}.` : ''}${k}`);
    if (typeof v === 'object' && v !== null) walk(v, pathIn ? `${pathIn}.${k}` : k, depth + 1);
  }
})(sidecar, '', 0);
check(
  colorHits.length === 0,
  'B. 侧表不含任何颜色字段（M20 已删 GROUP_COLORS/GROUP_ACCENT，分类列统一吃 --c/--cf token 兜底）',
  colorHits.length ? `发现颜色字段 ${colorHits.join(', ')} —— 借这次搬家请回来就是离表色复活` : '',
);

// ---- C. 兜底常量 ⇄ 侧表 双向一致 ----
// 提取 JS 里的 GROUP_FALLBACK（用 JSON 段落锚点解析，不 eval —— eval 渲染层代码
// 是门禁自己引入的注入面）
function extractFallback() {
  const start = js.indexOf('const GROUP_FALLBACK = {');
  if (start < 0) return null;
  const bodyStart = js.indexOf('{', start);
  // 逐括号配平（大括号 + 字符串内的括号需跳过引号）
  let depth = 0, i = bodyStart, inStr = null;
  for (; i < js.length; i++) {
    const ch = js[i];
    if (inStr) {
      if (ch === inStr && js[i - 1] !== '\\') inStr = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') { inStr = ch; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) { i++; break; } }
  }
  const lit = js.slice(bodyStart, i);
  // JS 对象字面量 → JSON。**不 eval**（eval 渲染层代码是门禁自己引入的注入面），
  // 逐 token 手工转：单引号字符串 → JSON 字符串、裸键 → 加引号。
  // 顺序要紧：先处理字符串（否则字符串里的 `:` 会被当成键分隔符）。
  let out = '';
  let k = 0;
  while (k < lit.length) {
    const ch = lit[k];
    if (ch === "'" || ch === '"') {
      const quote = ch;
      let str = quote;
      k++;
      while (k < lit.length) {
        const c = lit[k];
        if (c === '\\') { str += c + lit[k + 1]; k += 2; continue; }
        str += c;
        k++;
        if (c === quote) break;
      }
      // JS 单引号串 → JSON 双引号串（内容里没有双引号时才安全；本表的中文串满足）
      out += quote === '"' ? str : `"${str.slice(1, -1).replace(/"/g, '\\"')}"`;
      continue;
    }
    // 裸键：标识符后紧跟冒号
    const m = /^([A-Za-z_$][\w$]*)(\s*:)/.exec(lit.slice(k));
    if (m) {
      out += `"${m[1]}"${m[2]}`;
      k += m[0].length;
      continue;
    }
    out += ch;
    k++;
  }
  return JSON.parse(out);
}
const fb = extractFallback();
const cProblems = [];
if (!fb) {
  cProblems.push('渲染层找不到 GROUP_FALLBACK（兜底常量被删了？侧表通道一失败分类导航就空白）');
} else {
  if (JSON.stringify(fb.default) !== JSON.stringify(groups.default || [])) {
    cProblems.push(`default 顺序不一致：兜底 ${JSON.stringify(fb.default)} / 侧表 ${JSON.stringify(groups.default)}`);
  }
  if (JSON.stringify(fb.groupMap) !== JSON.stringify(groups.custom?.groupMap || {})) {
    cProblems.push(`groupMap 不一致：兜底 ${JSON.stringify(fb.groupMap)} / 侧表 ${JSON.stringify(groups.custom?.groupMap)}`);
  }
  if (JSON.stringify(fb.itemOverride) !== JSON.stringify(groups.custom?.itemOverride || {})) {
    cProblems.push(`itemOverride 不一致：兜底 ${JSON.stringify(fb.itemOverride)} / 侧表 ${JSON.stringify(groups.custom?.itemOverride)}`);
  }
}
check(
  cProblems.length === 0,
  'C. 渲染层 GROUP_FALLBACK ⇄ 侧表 双向一致（漂移只在「侧表通道失败」时暴露，必须钉死）',
  cProblems.join('; '),
);

// ---- D. 未登记分类兜底必须保留 ----
// 数据层出现新分类而侧表没登记时，这一行让新分类仍能显示（而不是整类消失）。
// 删掉它 = 数据层加一项而侧表忘了登记 ⇒ 那一项在界面上凭空不见。
const dProblems = [];
if (!/Object\.keys\(byGroup\)\.filter\(\s*g\s*=>\s*GROUP_ORDER\.indexOf\(g\)\s*===\s*-1\s*\)/.test(js)) {
  dProblems.push('renderGroups 里的「未登记分类兜底」不见了 —— 数据层加一项而侧表忘了登记 ⇒ 该项在界面凭空消失');
}
check(dProblems.length === 0, 'D. 未登记分类兜底仍在 renderGroups 里', dProblems.join('; '));

// ---- E. 侧表被真正消费（防止建了表没人用）----
const eProblems = [];
if (!js.includes('applyGroupSidecar')) {
  eProblems.push('渲染层没有 applyGroupSidecar —— 建了侧表却没人读');
}
if (!/window\.api\.optimizer\.listGroups\(\)/.test(js)) {
  eProblems.push('init 里没有调 listGroups() —— 侧表永远不会被下发');
}
if (!js.includes('GROUP_FALLBACK')) {
  eProblems.push('渲染层没有 GROUP_FALLBACK —— 侧表通道失败时分类导航会空白');
}
check(eProblems.length === 0, 'E. 侧表被真正消费（applyGroupSidecar + listGroups + 兜底常量）', eProblems.join('; '));

console.log('');
if (fail > 0) {
  console.error(`E7 分类侧表门禁失败 ${fail} 项。`);
  process.exit(1);
}
console.log('✓ E7 分类侧表：形状 / 无颜色 / 兜底对拍 / 未登记兜底 / 真消费 全通过');

// ==================== POSITIVE_CONTROLS ====================
// 逐条对已知违规样本跑同一份判据函数，必须报红。
(function positiveControls() {
  // 与 B 组同一份口径：从**侧表根**起步、不排除第一层、跳过 _comment/_rule。
  // 自检必须复用真判据的行为 —— 首版自检里的复刻版带着「排除第一层」的同一个 bug，
  // 于是「违规: groupMap 里带 color」那条样本其实测的是另一个形态。
  const colorHit = (g) => {
    const hits = [];
    (function walk(node, p) {
      if (!node || typeof node !== 'object') return;
      for (const [k, v] of Object.entries(node)) {
        if (k === '_comment' || k === '_rule') continue;
        if (COLOR_KEYS.test(k)) hits.push(`${p ? `${p}.` : ''}${k}`);
        if (typeof v === 'object' && v !== null) walk(v, p ? `${p}.${k}` : k);
      }
    })(g, '');
    return hits;
  };
  const fallbackMiss = (a, b) =>
    JSON.stringify(a) !== JSON.stringify(b);

  const cases = [
    ['干净侧表：无颜色字段', colorHit({ default: ['A'], custom: { groupMap: {}, itemOverride: {} } }).length === 0, true],
    ['违规：groupMap 里带 color', colorHit({ default: ['A'], custom: { groupMap: { x: 'y' }, color: 'red' } }).length > 0, true],
    ['违规：default 顺序不一致', fallbackMiss(['A', 'B'], ['B', 'A']), true],
    ['干净：default 顺序一致', fallbackMiss(['A', 'B'], ['A', 'B']), false],
    ['违规：groupMap 不一致', fallbackMiss({ k: 'v1' }, { k: 'v2' }), true],
    ['违规：itemOverride 不一致', fallbackMiss({ k: 'v1' }, {}), true],
  ];
  const findings = [];
  for (const [name, got, want] of cases) if (got !== want) findings.push(name);
  console.log(`${findings.length === 0 ? '✓' : '✗'} 自检：${cases.length} 条已知样本，判据行为全对 ${cases.length - findings.length} 条`);
  if (findings.length) {
    console.error(`  ✗ 判据失灵：${JSON.stringify(findings)}`);
    process.exit(1);
  }
})();
