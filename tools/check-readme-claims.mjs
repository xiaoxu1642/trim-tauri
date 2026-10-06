#!/usr/bin/env node
// check-readme-claims.mjs — readme 承诺数字对拍数据真源门禁（v2 方案批次 A4，2026-10-01）
//
// 为什么要有这条：M-B5 的根因不是「写错一个数字」，而是 readme 里的数字没有任何
// 机器对拍——清理库每加一条规则、优化项每动一次数据层，readme 的承诺就静默漂移
// 一次（71→76 漂了 5 个、114→111 漂了 3 个，都是人工核对才发现）。这条门禁把
// 「readme 数字与实现一致」从人工纪律变成可机检断言。
//
// 对拍口径（全部来自数据真源，不在本门禁里维护第二份数字）：
//   清理项总数   = cleanup-rules.json  groups[].subGroups[].items 逐层求和
//   优化项总数   = optimizer-runtime.json 顶层数组长度
//   高风险项数   = 其中 risk === 'high' 的条数
//   无还原高风险 = 其中 risk==='high' 且 restoreAvailable===false 的条数
//   展示分组数   = optimizer.js GROUP_ORDER 数组长度（前端展示口径的唯一真源，
//                  数据层原始分组经重映射归并到这 12 组，两者不等是设计不是漂移）
//   前端可见项   = 优化项总数 − 聚合进虚拟卡的 runId 数 + 虚拟卡数 − HIDE_ON_SSD 长度
//                  （SSD 视角；HIDE_ON_HDD 当前为空数组，若日后非空需在此同步口径）
//   pwsh 项/步   = tools/count-ps-steps.mjs 的 countPsSteps()（v2-R6：readme 那句
//                  「优化中心含 pwsh 步骤的 N 项 / M 步」是本门禁里唯一带两个数的声明，
//                  也是「还剩几个 PS 点」对用户公开的那一处。v2 R6 明令这个数字必须从
//                  门禁现算、不许手写，所以这里 import 计数函数而不是再抄一遍口径 ——
//                  自己数一遍等于制造第二份真源，两份各自漂移时门禁反而恒绿）
//
// 判定原则：readme 中**每一处**同类声明都必须与真源相等——只查第一处会让
// 「§二改了、§十三漏改」这种 M-B5 原始形态从指缝漏过去。
//
// 用法：node tools/check-readme-claims.mjs
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { countPsSteps } from './count-ps-steps.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== readme 承诺数字对拍门禁 ===\n');

// ---------- 数据真源 ----------
const cleanup = JSON.parse(read('src-tauri/data/cleanup-rules.json'));
let cleanupTotal = 0;
for (const g of cleanup.groups ?? []) {
  for (const sg of g.subGroups ?? []) cleanupTotal += (sg.items ?? []).length;
}

const optimizer = JSON.parse(read('src-tauri/data/optimizer-runtime.json'));
const optItems = Array.isArray(optimizer) ? optimizer : [];
const optTotal = optItems.length;
const optHigh = optItems.filter((o) => o.risk === 'high').length;
const optHighNoRestore = optItems.filter((o) => o.risk === 'high' && o.restoreAvailable === false).length;

// ---------- 前端口径（optimizer.js 解析，解析失败即红——不许静默跳过） ----------
const optJs = read('src/scripts/optimizer.js');
// 展示分组数的真源是 **`GROUP_FALLBACK.default` 数组**，不是 `GROUP_ORDER` 变量。
// E7（2026-10-03）把分组改成两层侧表后，`GROUP_ORDER` 变成
// `let GROUP_ORDER = GROUP_FALLBACK.default.slice()`（运行时可被侧表覆盖），
// 原先那条 `const GROUP_ORDER = \[` 匹配从此永远落空 → 解析出 NaN →
// 断言 4「优化项按 N 个分组」拿 NaN 当真源比，与 readme 写多少都不相等。
// 这就是「判据自己悄悄失效」的那一类：门禁一直红着，红的原因却不是它在盯的东西。
// 侧表 `optimizer-groups.json` 的 default 与此数组由 check-optimizer-groups-sidecar 对拍，
// 本门禁只管读数，不重复那份对拍职责。
const groupOrder = optJs.match(/const GROUP_FALLBACK = \{[\s\S]*?default:\s*\[([^\]]*)\]/);
const groupCount = groupOrder ? groupOrder[1].split(',').filter((s) => s.trim()).length : NaN;
const hideOnSsd = optJs.match(/const HIDE_ON_SSD = \[([^\]]*)\]/);
const hideOnSsdCount = hideOnSsd ? hideOnSsd[1].split(',').filter((s) => s.trim()).length : NaN;
const virtualBlk = optJs.match(/const VIRTUAL_GROUPS = \{([\s\S]*?)\n  \};/);
const virtualCards = virtualBlk ? (virtualBlk[1].match(/^    [a-zA-Z_]+: \{/gm) ?? []).length : NaN;
const virtualRunIds = virtualBlk ? (virtualBlk[1].match(/runId: '/g) ?? []).length : NaN;
// 前端列表可见数：被聚合的 runId 摘掉、虚拟卡插回，再减 SSD 隐藏项
const visibleSsd = optTotal - virtualRunIds + virtualCards - hideOnSsdCount;

check(Number.isFinite(groupCount), 'optimizer.js GROUP_FALLBACK.default 可解析', `展示分组 ${groupCount}`);
check(Number.isFinite(hideOnSsdCount) && Number.isFinite(virtualCards) && Number.isFinite(virtualRunIds),
  'optimizer.js HIDE_ON_SSD / VIRTUAL_GROUPS 可解析',
  `HIDE_ON_SSD=${hideOnSsdCount} 虚拟卡=${virtualCards} 聚合runId=${virtualRunIds}`);

console.log(`真源读数：清理项=${cleanupTotal} 优化项=${optTotal} 高风险=${optHigh} 高风险无还原=${optHighNoRestore} 展示分组=${groupCount} SSD可见=${visibleSsd}\n`);

// ---------- readme 声明逐处对拍 ----------
const readme = read('readme.md');
const findAll = (re) => [...readme.matchAll(re)].map((m) => Number(m[1]));

const assertAllEqual = (label, re, truth) => {
  const got = findAll(re);
  if (got.length === 0) {
    check(false, label, 'readme 中未找到该声明（声明被删或措辞变了？）');
    return;
  }
  const bad = got.filter((n) => n !== truth);
  check(bad.length === 0, `${label}（${got.length} 处）`,
    bad.length === 0 ? `全部为 ${truth}` : `漂移：${bad.join(' / ')} ≠ 真源 ${truth}`);
};

assertAllEqual('1. 清理项总数 = cleanup-rules.json 实数', /共\s*(\d+)\s*个清理项/g, cleanupTotal);
assertAllEqual('2. 清理库条数 = cleanup-rules.json 实数', /清理库\s*(\d+)\s*条/g, cleanupTotal);
assertAllEqual('3. 优化项总数 = optimizer-runtime.json 实数', /共\s*(\d+)\s*个优化项/g, optTotal);
// 3b/3c（v2-R3 补）：本节初版只有「共 N 个优化项」这一种措辞进了对拍，于是
// 「110 个优化项按 12 个分组」（使用步骤）与「110 项里有 14 项高风险」（重要提示）
// 两处同义声明**不在覆盖内**——tf_fso 退役后它们仍写着 111，是人眼看出的，不是门禁拦的。
// 一条承诺被写在几种措辞里，就必须有几种措辞的正则；否则「§二改了、§六漏改」这个
// M-B5 原始形态只挡住了一半。
assertAllEqual('3b. 优化项总数（使用步骤措辞，无「共」字）', /(\d+)\s*个优化项按\s*\d+\s*个分组/g, optTotal);
assertAllEqual('3c. 优化项总数（重要提示措辞）', /(\d+)\s*项里有\s*\d+\s*项高风险/g, optTotal);
assertAllEqual('4. 优化项按 N 个分组 = GROUP_ORDER 长度', /个优化项按\s*(\d+)\s*个分组/g, groupCount);
// 5/6 的两种措辞各配一条单捕获组正则（「§重要提示」与「§注意事项」两处口径都要钉）
assertAllEqual('5a. 高风险项数（重要提示措辞）', /项里有\s*(\d+)\s*项高风险/g, optHigh);
assertAllEqual('5b. 高风险项数（注意事项措辞）', /(\d+)\s*项高风险里/g, optHigh);
assertAllEqual('6a. 高风险无还原数（重要提示措辞）', /其中\s*\*{0,2}(\d+)\s*项执行后无自动还原/g, optHighNoRestore);
assertAllEqual('6b. 高风险无还原数（注意事项措辞）', /\d+\s*项高风险里\s*(\d+)\s*项无自动还原/g, optHighNoRestore);
assertAllEqual('7. SSD 通常可见项数 = 前端口径实算', /通常可见\s*(\d+)\s*项/g, visibleSsd);

// 8（v2-R6）：「还剩几个 PS 步」这句对用户公开的数字。readme 里它是唯一一处**双数**声明
// （N 项 / M 步），所以不复用 assertAllEqual，单独对拍两个捕获组。
// 措辞变了导致 0 处命中同样判红：这句是「本应用不要求你安装任何组件」的支撑数据。
const psTruth = countPsSteps(optItems);
const psClaims = [...readme.matchAll(/含 pwsh 步骤的\s*(\d+)\s*项\s*\/\s*(\d+)\s*步/g)];
if (psClaims.length === 0) {
  check(false, '8. pwsh 项/步数（readme「含 pwsh 步骤的 N 项 / M 步」）', 'readme 中未找到该声明（措辞变了或被删？）');
} else {
  const bad = psClaims.filter((m) => Number(m[1]) !== psTruth.applyItems || Number(m[2]) !== psTruth.applySteps);
  check(
    bad.length === 0,
    `8. pwsh 项/步数 = countPsSteps() 实算（${psClaims.length} 处）`,
    bad.length === 0
      ? `全部为 ${psTruth.applyItems} 项 / ${psTruth.applySteps} 步`
      : `漂移：${bad.map((m) => `${m[1]} 项 / ${m[2]} 步`).join('、')} ≠ 真源 ${psTruth.applyItems} 项 / ${psTruth.applySteps} 步`,
  );
  // 恢复方向单独声明（若将来写进 readme 也要钉；当前没有该措辞，只打印不判红）
  console.log(`   ↳ 真源分账：正向 ${psTruth.applyItems} 项/${psTruth.applySteps} 步，恢复 ${psTruth.restoreItems} 项/${psTruth.restoreSteps} 步，合计 ${psTruth.applySteps + psTruth.restoreSteps} 步`);
}

console.log('');

// ---------- 9~12（审查 M-8 补，2026-10-03）：分域明细 / 右键分类数 / 内存区域数 / 网络诊断数 ----------
// 此前只有总数进了对拍：分域 35/23/9/5/4、16 类、6 区域、6 诊断各自对应一份独立清单
// （cleanup-rules.json groups、contextmenu.rs scenes ⇄ contextmenu.js CATEGORY_ORDER、
// memoryclean.js REGIONS、netcheck.js ITEM_META），改任一份只漂分项、总断言全绿——
// 这正是 B5「数字漂移」最隐蔽的形态。四组真源全部现算，不在本文件维护第二份数字。

// 9. 清理项分域明细：readme「系统 35 / 应用 23 / 浏览器 9 / 显卡 5 / 特殊 4」⇄ groups 逐组实算。
//    readme 用简称，与 groups title 的对应关系登记在 DOMAIN_MAP（「显卡」↔「图形与加速」、
//    「特殊」↔「维护与特殊操作」不是字面前缀）；groups 增删组或改名都会红，引导同步改 readme。
const DOMAIN_MAP = [
  ['系统', '系统清理'], ['应用', '应用清理'], ['浏览器', '浏览器清理'],
  ['显卡', '图形与加速'], ['特殊', '维护与特殊操作'],
];
const groupCounts = new Map((cleanup.groups ?? []).map((g) => [
  g.title, (g.subGroups ?? []).reduce((a, s) => a + (s.items ?? []).length, 0),
]));
const domainRe = new RegExp(DOMAIN_MAP.map(([short]) => `${short}\\s*(\\d+)`).join('\\s*/\\s*'), 'g');
const domainClaims = [...readme.matchAll(domainRe)];
if (domainClaims.length === 0) {
  check(false, '9. 清理项分域明细', 'readme 中未找到分域声明（措辞变了或被删？）');
} else {
  const expected = DOMAIN_MAP.map(([, title]) => groupCounts.get(title));
  const bad = domainClaims.filter((m) => DOMAIN_MAP.some((_, i) => Number(m[i + 1]) !== expected[i]));
  check(bad.length === 0, `9. 清理项分域明细 = groups 逐组实算（${domainClaims.length} 处）`,
    bad.length === 0
      ? `全部为 ${expected.join(' / ')}`
      : `漂移：${bad.map((m) => DOMAIN_MAP.map((_, i) => m[i + 1]).join('/')).join('、')} ≠ 真源 ${expected.join(' / ')}`);
}
// 9b. groups 分组名单 ⇄ 门禁登记的 title 集合双向一致（改名/加组/减组即红，
//     防止「title 变了但 items 数没变」让简称映射静默失配）。
{
  const titles = new Set((cleanup.groups ?? []).map((g) => g.title));
  const mapped = new Set(DOMAIN_MAP.map(([, t]) => t));
  const extra = [...titles].filter((t) => !mapped.has(t));
  const missing = [...mapped].filter((t) => !titles.has(t));
  check(extra.length === 0 && missing.length === 0, '9b. groups 分组名单 ⇄ 门禁登记一致',
    extra.length ? `groups 多出未登记分组：${extra.join('、')}`
      : missing.length ? `登记分组在 groups 中不存在：${missing.join('、')}`
        : `${titles.size} 组全部登记`);
}
// 9c. 「5 大类」本身也是承诺数字，对 groups.length。
assertAllEqual('9c. 清理项大类数 = groups.length', /(\d+)\s*大类共\s*\d+\s*个清理项/g, (cleanup.groups ?? []).length);

// 10. 右键菜单扫描类数：readme「按 N 类扫描」⇄ 后端可达类数实算
//     = contextmenu.rs scenes 表条目数 + 四个特殊 category 字面量（发送到/Win+X/新建菜单/
//     打开方式，各自只有一段生成代码）。UWP/PackagedCom 后端未实现（contextmenu.rs:440
//     自述「暂未实现」），所以这个数小于侧边栏 CATEGORY_ORDER.length —— readme 只承诺
//     「扫得出数据的类数」。补实现或隐藏 UWP 属业务裁定： whichever 方向落地，两侧
//     数字一起动，本门禁的对拍会引导 readme 同步。
const ctxRs = read('src-tauri/src/engine/native/contextmenu.rs');
const scenesBlk = ctxRs.match(/let scenes: &\[\(&str, &\[&str\]\)\] = &\[([\s\S]*?)\];/);
const sceneCount = scenesBlk ? (scenesBlk[1].match(/\("([^"]+)"/g) ?? []).length : NaN;
const SPECIAL_CATS = ['发送到', 'Win+X', '新建菜单', '打开方式'];
const specialHit = scenesBlk ? SPECIAL_CATS.filter((c) => ctxRs.includes(`category: "${c}"`)) : [];
const ctxReachable = Number.isFinite(sceneCount) ? sceneCount + specialHit.length : NaN;
check(Number.isFinite(ctxReachable), 'contextmenu.rs scenes 表 + 特殊类别可解析',
  `scenes 表 ${sceneCount} 类 + 特殊 ${specialHit.length} 类 = 后端可达 ${ctxReachable}`);
assertAllEqual('10. 右键菜单扫描类数 = 后端可达类数实算', /按\s*(\d+)\s*类扫描/g, ctxReachable);
const ctxJs = read('src/scripts/contextmenu.js');
const catOrderBlk = ctxJs.match(/const CATEGORY_ORDER = \[([\s\S]*?)\];/);
const catOrderCount = catOrderBlk ? catOrderBlk[1].split(',').filter((s) => s.trim()).length : NaN;
check(Number.isFinite(catOrderCount) && catOrderCount >= ctxReachable,
  '10b. 侧边栏 CATEGORY_ORDER ≥ 后端可达类数',
  `侧边栏 ${catOrderCount} 类 / 后端可达 ${ctxReachable} 类`);
if (Number.isFinite(catOrderCount) && catOrderCount > ctxReachable) {
  console.log(`   ↳ 提醒（不判红，业务裁定项）：侧边栏有 ${catOrderCount - ctxReachable} 类后端未实现（UWP应用），点击恒为空列表`);
}

// 11. 内存清理区域数：readme「按 N 个区域勾选」⇄ REGIONS 实算。
//     口径：条目以首行 `{ id: '` 计（desc 跨行不影响）。2026-10-06 起列表不含灰显项——
//     fileCache/registryCache（系统文件缓存/注册表缓存）按用户裁定直接隐藏入口（后端
//     mem_clean 白名单本就不提供 82/84）。regionUnavailable 兜底保留：将来若再出现
//     `sysUnavailable: true` 条目，仍不计入「可勾选区域」。
const mcJs = read('src/scripts/memoryclean.js');
const regionsBlk = mcJs.match(/const REGIONS = \[([\s\S]*?)\n  \];/);
const regionTotal = regionsBlk ? (regionsBlk[1].match(/^\s*\{ id: '/gm) ?? []).length : NaN;
const regionUnavailable = regionsBlk ? (regionsBlk[1].match(/sysUnavailable: true/g) ?? []).length : 0;
const regionUsable = Number.isFinite(regionTotal) ? regionTotal - regionUnavailable : NaN;
check(Number.isFinite(regionUsable), 'memoryclean.js REGIONS 可解析',
  `共 ${regionTotal} 项 / 灰显 ${regionUnavailable} / 可勾选 ${regionUsable}`);
assertAllEqual('11. 内存清理可勾选区域数 = REGIONS 实算', /按\s*(\d+)\s*个区域勾选/g, regionUsable);

// 12. 网络检测诊断项数：readme「N 项只读诊断」⇄ netcheck.js ITEM_META 键数
//     （该表注释自述「键名与后端回传 items 一致」——前端表即口径真源）。
const ncJs = read('src/scripts/netcheck.js');
const metaBlk = ncJs.match(/const ITEM_META = \{([\s\S]*?)\n  \};/);
const netItems = metaBlk ? (metaBlk[1].match(/^\s{4}\w+: \{ name:/gm) ?? []).length : NaN;
check(Number.isFinite(netItems), 'netcheck.js ITEM_META 可解析', `诊断项 ${netItems}`);
assertAllEqual('12. 网络检测诊断项数 = ITEM_META 实算', /(\d+)\s*项只读诊断/g, netItems);

console.log('');
if (fail > 0) {
  console.error('门禁失败：readme 承诺数字与数据真源不一致（或声明措辞变更导致对拍落空）');
  process.exit(1);
}
console.log('readme 承诺数字对拍门禁全部通过');
