#!/usr/bin/env node
// check-gate-roster.mjs —— 门禁运行集合台账（v2-L4P-01，2026-10-02）
// 抓什么：磁盘 check-*.mjs 集合 ⇄ AGENTS §4 清单 ⇄ OPTIONAL/RETIRED 注册表 三方漂移。
// 背景：L4 审查报告把「24 条可跑」写成「22 条」且无法回算（RPT-04）；本门禁让
// 「磁盘上有哪些门禁、哪些在必跑清单、哪些刻意可选/退役」永远可机器对拍，
// 报告里不得再手写这类总数——要引用数字就跑本脚本贴输出。
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TOOLS = join(ROOT, 'tools');
const AGENTS = join(ROOT, 'AGENTS.md');

// 刻意不在 §4 必跑清单的门禁注册表。新增可选/退役门禁必须在这里登记（带理由），
// 否则磁盘多出一个 check 文件而清单没有 → 红。
const OPTIONAL = [
  // 上游基线腐烂检查：依赖 vendor/ 只读快照，日常迭代不动 vendor 时跑它只会常绿
  { name: 'check-origin-drift', reason: '可选：仅 vendor/ 或上游同步动作后必跑' },
];
const RETIRED = [
  // D-2 裁定退役：PS 替换管线随外部 PS7 通道整条删除（AGENTS §4.1 有退役理由）
  { name: 'check-ps-substitution', reason: '已退役（v2-D2）：外部 PS7 通道删除后无对象' },
];

let failed = 0;
const fail = (msg) => { console.error(`✗ ${msg}`); failed++; };
const ok = (msg) => console.log(`✓ ${msg}`);

// ── 1. 解析 AGENTS §4 的 node tools/ 清单 ──
const agentsText = readFileSync(AGENTS, 'utf8');
const s4 = agentsText.indexOf('## 4.');
const s41 = agentsText.indexOf('### 4.1');
if (s4 < 0 || s41 < 0 || s41 < s4) fail('AGENTS.md 找不到 §4 区间（## 4. … ### 4.1）');
const sec4 = s4 >= 0 && s41 > s4 ? agentsText.slice(s4, s41) : '';
const agentsTools = [...sec4.matchAll(/node tools\/([A-Za-z0-9_-]+\.mjs)/g)].map((m) => m[1]);
const agentsCheck = agentsTools.filter((n) => n.startsWith('check-')).map((n) => n.replace(/\.mjs$/, ''));
const agentsCheckFiles = agentsTools.filter((n) => n.startsWith('check-'));
const agentsNonCheck = agentsTools.filter((n) => !n.startsWith('check-'));

// ── 2. 磁盘现状 ──
const diskAll = readdirSync(TOOLS).filter((f) => f.endsWith('.mjs'));
const diskCheck = diskAll.filter((f) => /^check-.*\.mjs$/.test(f)).map((f) => f.replace(/\.mjs$/, ''));
const diskCheckFiles = diskAll.filter((f) => /^check-.*\.mjs$/.test(f));
const optionalNames = OPTIONAL.map((o) => o.name);
const retiredNames = RETIRED.map((o) => o.name);

// ── 3. 三方对拍 ──
// 3a. AGENTS 清单里的每条工具必须在磁盘上存在（清单指向虚无 = 红线落点消失，D-3 同族）
for (const name of agentsTools) {
  if (!diskAll.includes(name)) fail(`AGENTS §4 列出的 tools/${name} 磁盘上不存在`);
}
// 3b. 磁盘 check 文件必须三方有其一：AGENTS 必跑 / OPTIONAL / RETIRED
for (const f of diskCheck) {
  if (agentsCheck.includes(f)) continue;
  if (optionalNames.includes(f) || retiredNames.includes(f)) continue;
  fail(`磁盘存在 tools/${f}，但既不在 AGENTS §4 清单、也不在 OPTIONAL/RETIRED 注册表（新门禁必须先进清单再进验收）`);
}
// 3c. 注册表条目必须真实存在于磁盘（防注册表腐烂成第二本假账）
for (const { name, reason } of [...OPTIONAL, ...RETIRED]) {
  if (!reason || reason.trim().length < 8) fail(`注册表条目 ${name} 缺少理由（OPTIONAL/RETIRED 必须带书面 scope）`);
  if (!existsSync(join(TOOLS, `${name}.mjs`))) fail(`注册表登记的 tools/${name}.mjs 磁盘上不存在（请把条目从注册表摘掉或恢复文件）`);
}
// 3d. 注册表条目不得同时出现在 §4 必跑清单（双重身份 = 口径含糊）
for (const { name } of [...OPTIONAL, ...RETIRED]) {
  if (agentsCheck.includes(name)) fail(`tools/${name} 同时出现在 §4 必跑清单与 OPTIONAL/RETIRED 注册表`);
}
// 3e. AGENTS 清单自身去重（重复列两条会让台账虚高）
const dup = agentsTools.filter((n, i) => agentsTools.indexOf(n) !== i);
for (const n of dup) fail(`AGENTS §4 重复列出 tools/${n}`);

// ── 4. 台账输出（报告引用数字只能从这里抄） ──
if (failed === 0) {
  ok(`门禁运行集合台账对拍一致：磁盘 check ${diskCheck.length} 条 = §4 必跑 ${agentsCheck.length} + OPTIONAL ${optionalNames.length} + RETIRED ${retiredNames.length}`);
  ok(`§4 非 check 工具 ${agentsNonCheck.length} 条（${agentsNonCheck.join(', ')}）全部存在于磁盘`);
  console.log(`check-gate-roster: 全部通过（check 必跑 ${agentsCheck.length} / 可选 ${optionalNames.length} / 退役 ${retiredNames.length}）`);
} else {
  console.error(`check-gate-roster: ${failed} 处不一致`);
  process.exit(1);
}
