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
// 另外钉三条纪律（AGENTS §2 + M20 审查结论 + T1f-L07）：
//   ① 侧表**不得含任何颜色字段** —— GROUP_COLORS / GROUP_ACCENT 已在 M20 删除，
//      借这次搬家请回来就是离表色复活。
//   ② 渲染层的**未登记分类兜底**（`renderGroups` 里
//      `Object.keys(byGroup).filter(g => GROUP_ORDER.indexOf(g) === -1)`）必须保留 ——
//      数据层出现新分类而侧表没登记时，它让新分类仍能显示（而不是整类消失）。
//   ③ 本门禁读的三张优化侧表（groups / nara 面板 / privacy 面板）的 `schemaVer` 必须等于
//      契约表 `optimizer.sideTableSchemaVer`（A2；此前只有 optimizer-subitems 那张有人读）。
'use strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSchema } from './rule-schema.mjs';

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
// 两张签名面板也在这里读（A2 的版本对拍 + F 的隐藏集各用一次）——读一次、两处共用。
const naraPanel = JSON.parse(read('src-tauri', 'data', 'optimizer-nara-panel.json'));
const privacyPanel = JSON.parse(read('src-tauri', 'data', 'optimizer-privacy-panel.json'));

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

// ---- A2. 版本对拍（T1f-L07）----
// `schemaVer` 在 `rule-schema.json` 里只有一个键（`optimizer.sideTableSchemaVer`），而除
// `optimizer-subitems.json`（由 check-optimizer-subitem-contract / -schema-sync 读）之外
// 没有任何门禁读过它 ⇒ schema 升级时侧表版本漂移不会红。本门禁本来就在读这三张表，
// 就地把它钉到契约表上。
// 另注：`optimizer-defaults` / `-provenance` / `-writes` 的 `schemaVer` 至今没有门禁读
// （读那三张的是 check-optimizer-write-contract，那里没有版本断言）—— 要覆盖须在那边加，
// 本文件不复制第三份读取。
function sideVerProblems(tables, want) {
  const out = [];
  if (typeof want !== 'number') out.push(`契约表 optimizer.sideTableSchemaVer 不是数字：${JSON.stringify(want)}`);
  for (const [name, v] of Object.entries(tables)) {
    if (v === undefined) out.push(`${name} 没有 schemaVer（版本闸失效）`);
    else if (v !== want) out.push(`${name} schemaVer=${v} ≠ 契约表 ${want}`);
  }
  return out;
}
{
  const want = loadSchema().optimizer?.sideTableSchemaVer;
  const problems = sideVerProblems({
    'optimizer-groups.json': sidecar.schemaVer,
    'optimizer-nara-panel.json': naraPanel.schemaVer,
    'optimizer-privacy-panel.json': privacyPanel.schemaVer,
  }, want);
  check(problems.length === 0,
    `A2. 三张侧表 schemaVer = 契约表 ${want}（groups / nara 面板 / privacy 面板）`,
    problems.join('; '));
}

// ---- B. 侧表**不得含颜色字段**（M20 已删 GROUP_COLORS / GROUP_ACCENT）----
const COLOR_KEYS = /^(color|colors|accent|accents|groupColor|groupAccent|gradient|gradients|bg|background)$/i;
// ⚠️ 判红实验 2 踩到的坑：首版写 `if (pathIn !== '' && COLOR_KEYS.test(k))`，
// 而 `walk(groups, '')` 的**第一层**（`default` / `custom` / `colors`）的 `pathIn`
// 恰好是 `''` —— 于是 `groups.colors` 这种最典型的放法**被放过了**。
// 正确做法：从侧表根（而不是 `groups`）起步，并且**不排除第一层**。
// 键名白名单式匹配（COLOR_KEYS）本身就是精确的，不需要用深度去排除误报。
//
// T1f-L06：这段 walk 抽成**命名函数**，真判据与文件尾的 POSITIVE_CONTROLS 调同一份 ——
// 旧自检复刻了第二份，真判据以后加跳过键或改深度条件时自检不会跟着变。
function colorHitsOf(sidecarObj) {
  const hits = [];
  (function walk(node, pathIn) {
    if (!node || typeof node !== 'object') return;
    for (const [k, v] of Object.entries(node)) {
      if (k === '_comment' || k === '_rule') continue; // 说明性字段，允许提到颜色
      if (COLOR_KEYS.test(k)) hits.push(`${pathIn ? `${pathIn}.` : ''}${k}`);
      if (typeof v === 'object' && v !== null) walk(v, pathIn ? `${pathIn}.${k}` : k);
    }
  })(sidecarObj, '');
  return hits;
}
const colorHits = colorHitsOf(sidecar);
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

// C 的两份比较抽成命名函数，真判据与 POSITIVE_CONTROLS 共用（T1f-L06）。
// T1f-L06：旧实现一律用 `JSON.stringify(a) !== JSON.stringify(b)`。`default` 是**有序**
// 分类序列（导航顺序就是契约），顺序不同必须红；而 `groupMap` / `itemOverride` 是**映射**，
// 键序不是语义 —— 生成器按字母序重排、或手工挪一行，旧实现都会假红。
// 门禁自己误报比漏报更糟（它会让下一位去改本来正确的那份），所以映射必须做键序无关比较。
function sameOrdered(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}
function sameMap(a, b) {
  const A = a && typeof a === 'object' ? a : {};
  const B = b && typeof b === 'object' ? b : {};
  const ka = Object.keys(A).sort();
  const kb = Object.keys(B).sort();
  if (ka.length !== kb.length) return false;
  for (let i = 0; i < ka.length; i++) {
    if (ka[i] !== kb[i]) return false;
    if (A[ka[i]] !== B[kb[i]]) return false;
  }
  return true;
}
/** 兜底常量 ⇄ 侧表的全部差异（返回问题列表，空 = 一致） */
function fallbackProblems(fallback, sidecarGroups) {
  const out = [];
  if (!fallback) {
    out.push('渲染层找不到 GROUP_FALLBACK（兜底常量被删了？侧表通道一失败分类导航就空白）');
    return out;
  }
  if (!sameOrdered(fallback.default, sidecarGroups.default || [])) {
    out.push(`default 顺序不一致：兜底 ${JSON.stringify(fallback.default)} / 侧表 ${JSON.stringify(sidecarGroups.default)}`);
  }
  if (!sameMap(fallback.groupMap, sidecarGroups.custom?.groupMap || {})) {
    out.push(`groupMap 不一致：兜底 ${JSON.stringify(fallback.groupMap)} / 侧表 ${JSON.stringify(sidecarGroups.custom?.groupMap)}`);
  }
  if (!sameMap(fallback.itemOverride, sidecarGroups.custom?.itemOverride || {})) {
    out.push(`itemOverride 不一致：兜底 ${JSON.stringify(fallback.itemOverride)} / 侧表 ${JSON.stringify(sidecarGroups.custom?.itemOverride)}`);
  }
  return out;
}
const cProblems = fallbackProblems(fb, groups);
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

// ---- F. 展示分组 ⇄ 面板隐藏集（D1-M03，2026-10-26） ----
// 判据轴 = runtime 的「映射后展示分组」：itemOverride → groupMap → 原始 group。
// 未写进 default 的分组若还有人没被面板隐藏，界面就会多出一个导航组，而 readme
// 仍写 8；privacy 面板另做双向：隐藏集必须恰好等于「映射后属隐私防护」的成员。
function groupCoverageProblems({ runtime, defaultGroups, groupMap, itemOverride, hiddenUnion, privacyHidden, privacyGroup }) {
  const out = [];
  const runtimeGroups = new Set(runtime.map((x) => x.group));
  const deadMap = Object.keys(groupMap).filter((k) => !runtimeGroups.has(k));
  if (deadMap.length) out.push(`groupMap 死映射：${deadMap.join('、')}（runtime 无此原始分组）`);
  const ids = new Set(runtime.map((x) => x.id));
  const deadOverride = Object.keys(itemOverride).filter((id) => !ids.has(id));
  if (deadOverride.length) out.push(`itemOverride 死 id：${deadOverride.join('、')}`);
  const byDisplay = new Map();
  for (const it of runtime) {
    const g = itemOverride[it.id] || groupMap[it.group] || it.group;
    if (!byDisplay.has(g)) byDisplay.set(g, []);
    byDisplay.get(g).push(it.id);
  }
  const extra = [...byDisplay.keys()].filter((g) => !defaultGroups.includes(g));
  for (const g of extra) {
    const loose = byDisplay.get(g).filter((id) => !hiddenUnion.has(id));
    if (loose.length) out.push(`未登记分组「${g}」有 ${loose.length} 项未被任何面板隐藏：${loose.slice(0, 5).join('、')}`);
  }
  const members = new Set(byDisplay.get(privacyGroup) || []);
  const onlyMembers = [...members].filter((id) => !privacyHidden.has(id));
  const onlyHidden = [...privacyHidden].filter((id) => !members.has(id));
  if (onlyMembers.length) out.push(`「${privacyGroup}」组成员未进隐私面板隐藏集：${onlyMembers.join('、')}`);
  if (onlyHidden.length) out.push(`隐私面板隐藏集里不属于「${privacyGroup}」组：${onlyHidden.join('、')}`);
  return { problems: out, displayGroups: byDisplay.size, extraGroups: extra.length };
}
{
  const runtime = JSON.parse(read('src-tauri', 'data', 'optimizer-runtime.json'));
  const hiddenUnion = new Set([...(privacyPanel.hiddenFromOptimizer || []), ...(naraPanel.hiddenFromOptimizer || [])]);
  const privacyHidden = new Set(privacyPanel.hiddenFromOptimizer || []);
  const base = {
    runtime: [{ id: 'a', group: 'G1' }, { id: 'b', group: 'X' }],
    defaultGroups: ['G1'],
    groupMap: { X: '隐私防护' },
    itemOverride: {},
    hiddenUnion: new Set(['b']),
    privacyHidden: new Set(['b']),
    privacyGroup: '隐私防护',
  };
  const good = groupCoverageProblems(base);
  check(good.problems.length === 0 && good.extraGroups === 1, 'F. 对照：齐全样本放行', JSON.stringify(good));
  check(
    groupCoverageProblems({ ...base, hiddenUnion: new Set() }).problems.some((p) => p.includes('未被任何面板隐藏')),
    'F. 对照：未隐藏的未登记组必须判红',
  );
  check(
    groupCoverageProblems({ ...base, groupMap: { X: '隐私防护', Dead: 'G1' } }).problems.some((p) => p.includes('死映射')),
    'F. 对照：死映射必须判红',
  );
  check(
    groupCoverageProblems({ ...base, privacyHidden: new Set() }).problems.some((p) => p.includes('未进隐私面板')),
    'F. 对照：隐私双向差集必须判红',
  );
  const res = groupCoverageProblems({
    runtime,
    defaultGroups: groups.default || [],
    groupMap: groups.custom?.groupMap || {},
    itemOverride: groups.custom?.itemOverride || {},
    hiddenUnion,
    privacyHidden,
    privacyGroup: '隐私防护',
  });
  check(
    res.problems.length === 0,
    `F. 展示分组 ⇄ 面板隐藏集（映射后 ${res.displayGroups} 组 / 未登记 ${res.extraGroups} 组）`,
    res.problems.join('; '),
  );
}

console.log('');
if (fail > 0) {
  console.error(`E7 分类侧表门禁失败 ${fail} 项。`);
  process.exit(1);
}
console.log('✓ E7 分类侧表：形状 / 无颜色 / 兜底对拍 / 未登记兜底 / 真消费 全通过');

// ==================== POSITIVE_CONTROLS ====================
// 逐条对已知违规样本跑**与真判据同一份函数**，必须报红（T1f-L06：旧自检复刻了一份
// `colorHit` / `fallbackMiss`，真判据改了它们不会跟着变，等于自检自己骗自己）。
(function positiveControls() {
  const cleanGroups = { default: ['A'], custom: { groupMap: {}, itemOverride: {} } };
  const cases = [
    // B 组：颜色字段（从侧表根起步、不排除第一层、跳过 _comment/_rule）
    ['干净侧表：无颜色字段', colorHitsOf(cleanGroups).length === 0, true],
    ['违规：第一层带 colors', colorHitsOf({ ...cleanGroups, colors: ['#fff'] }).length > 0, true],
    ['违规：groupMap 里带 color', colorHitsOf({ default: ['A'], custom: { groupMap: { x: 'y' }, color: 'red' } }).length > 0, true],
    ['干净：_comment 里提到 colors 不算', colorHitsOf({ ...cleanGroups, _comment: 'colors 已删除' }).length === 0, true],
    // C 组：default 有序、映射键序无关
    ['违规：default 顺序不一致', fallbackProblems({ ...cleanGroups, default: ['B', 'A'] }, cleanGroups).length > 0, true],
    ['干净：default 顺序一致', fallbackProblems({ ...cleanGroups }, cleanGroups).length === 0, true],
    [
      '干净：groupMap / itemOverride 键序不同但语义相同（旧实现会假红）',
      fallbackProblems(
        { default: ['A'], groupMap: { b: '2', a: '1' }, itemOverride: { y: 'A', x: 'A' } },
        { default: ['A'], custom: { groupMap: { a: '1', b: '2' }, itemOverride: { x: 'A', y: 'A' } } },
      ).length === 0,
      true,
    ],
    ['违规：groupMap 值不一致', fallbackProblems({ ...cleanGroups, groupMap: { k: 'v1' } }, { default: ['A'], custom: { groupMap: { k: 'v2' }, itemOverride: {} } }).length > 0, true],
    ['违规：groupMap 少一个键', fallbackProblems({ ...cleanGroups, groupMap: { a: '1', b: '2' } }, { default: ['A'], custom: { groupMap: { a: '1' }, itemOverride: {} } }).length > 0, true],
    ['违规：itemOverride 不一致', fallbackProblems({ ...cleanGroups, itemOverride: { k: 'v1' } }, { default: ['A'], custom: { groupMap: {}, itemOverride: {} } }).length > 0, true],
    // A2：版本对拍
    ['干净：三张表版本与契约表一致', sideVerProblems({ a: 1, b: 1 }, 1).length === 0, true],
    ['违规：某张表版本漂移', sideVerProblems({ a: 1, b: 2 }, 1).length > 0, true],
    ['违规：某张表缺版本字段', sideVerProblems({ a: 1, b: undefined }, 1).length > 0, true],
    ['违规：契约表键不是数字', sideVerProblems({ a: 1 }, undefined).length > 0, true],
  ];
  const findings = [];
  for (const [name, got, want] of cases) if (got !== want) findings.push(name);
  console.log(`${findings.length === 0 ? '✓' : '✗'} 自检：${cases.length} 条已知样本，判据行为全对 ${cases.length - findings.length} 条`);
  if (findings.length) {
    console.error(`  ✗ 判据失灵：${JSON.stringify(findings)}`);
    process.exit(1);
  }
})();
console.log('对照: 齐全样本放行，未登记组 / 死映射 / 双向差集必须判红');
