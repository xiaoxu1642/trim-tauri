#!/usr/bin/env node
// check-gate-roster.mjs —— 门禁运行集合台账（v2-L4P-01，2026-10-02）
// 抓什么：磁盘 check-*.mjs 集合 ⇄ 脚本内 MUST_RUN 注册表 ⇄ OPTIONAL/RETIRED 注册表 三方漂移。
// 背景：L4 审查报告把「24 条可跑」写成「22 条」且无法回算（RPT-04）；本门禁让
// 「磁盘上有哪些门禁、哪些必跑、哪些刻意可选/退役」永远可机器对拍，报告里不得再手写这类总数。
//
// 2026-10-07 分层整理：AGENTS.md 不再逐条列门禁清单（常驻手册只留入口），必跑清单的唯一真源
// 收进本文件的 MUST_RUN。新增门禁先加进这里再进验收；`--run` 即验收用的门禁总入口。
//
// 用法：node tools/check-gate-roster.mjs          # 只做三方对拍
//       node tools/check-gate-roster.mjs --run    # 对拍后按 MUST_RUN 顺序跑完全部必跑门禁
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TOOLS = join(ROOT, 'tools');
const AGENTS = join(ROOT, 'AGENTS.md');

// 必跑门禁唯一真源。顺序即 `--run` 的执行顺序；新增门禁必须登记在这里（不再写进 AGENTS.md）。
const MUST_RUN = [
  'check-channel-map',
  'check-guard-tiers',
  'check-layering',
  'check-delete-exits',
  'check-delete-callsites',
  'check-fail-closed',
  'check-system-bin',
  'check-residue-rule-contract',
  'check-cleanup-rule-contract',
  'check-scan-rule-diff',
  'check-ps-callsites',
  'check-ps-extraction',
  'check-html-contract',
  'check-csp-consistency',
  'check-a11y',
  'check-native-hygiene',
  'check-css-tokens',
  'check-assets-used',
  'check-asset-size',
  'check-artifact-size',
  'check-first-paint',
  'check-contrast',
  'check-subwindow-css',
  'check-idle-scripts',
  'check-escape-delegation',
  'check-subwindow-init',
  'check-confirm-danger',
  'check-treemap-layout',
  'check-item-intro',
  'check-desktop-entry',
  'check-data-parity',
  'check-rule-schema-sync',
  'check-optimizer-dynamic',
  'check-optimizer-security',
  'check-optimizer-subitem-contract',
  'check-optimizer-groups-sidecar',
  'check-optimizer-write-contract',
  'check-power-write-surface',
  'check-cleanup-postactions',
  'check-desc-vs-writes',
  'check-elapsed-facts',
  'check-version-sync',
  'check-updater-pubkey',
  'check-readme-claims',
  'check-readme-negative-claims',
  'check-doc-refs',
  'check-tools-doc-paths',
  'check-comment-rot',
  'check-positive-controls',
  'check-review-units',
  'check-tests-helper-parity',
  // T1c-M02 / T1c-M05（v7.2 C09）：「改后必须重签」与「夹具不许手改」的 Node 侧判红路径
  'check-data-signatures',
  'check-fixture-freshness',
  'check-gate-roster',
];

// 少数门禁需要非默认参数；登记在这里，`--run` 会照实传。
const GATE_ARGS = {
  'check-channel-map': ['--strict'],
};

// T1b-L09：副作用档。`--run --tier=readonly` 跳过会 spawn 外部进程/写盘的门禁；
// 不带 --tier 时维持原行为（全跑，供发版/收尾验收）。
const SIDE_EFFECT = new Map([
  ['check-ps-extraction', 'spawn 真实 pwsh（--run 档）'],
  ['check-scan-rule-diff', 'spawn cargo test'],
  ['check-data-parity', 'spawn PowerShell 解析数据产物'],
  ['check-positive-controls', 'spawn 全部 REGISTRY 门禁'],
  ['check-headless-cli', 'spawn cargo build + 真实扫描（OPTIONAL）'],
]);
const RUN = process.argv.includes('--run');
const TIER_ARG = (process.argv.find((a) => a.startsWith('--tier=')) || '').split('=')[1] || '';
if (TIER_ARG && TIER_ARG !== 'readonly') {
  console.error(`✗ 未知 --tier=${TIER_ARG}（只支持 readonly）`);
  process.exit(1);
}
const READONLY_TIER = TIER_ARG === 'readonly';

// 刻意不在必跑清单的门禁注册表。新增可选/退役门禁必须在这里登记（带理由），
// 否则磁盘多出一个 check 文件而两处注册表都没有 → 红。
const OPTIONAL = [
  // 上游基线腐烂检查：依赖 vendor/ 只读快照，日常迭代不动 vendor 时跑它只会常绿
  { name: 'check-origin-drift', reason: '可选：仅 vendor/ 或上游同步动作后必跑' },
  // 产物新鲜度：改完代码还没到发版时刻是流程的正常中间态，进必跑等于天天红。
  // 只在①发版前人工触发 ②审查复核线上产物这两个时刻跑；无产物时脚本自己 SKIP（不判红）。
  { name: 'check-release-freshness', reason: '可选：发版前 / 审查复核产物时人工触发（日常迭代产物本就该旧）' },
  // P2-B 无头扫描 CLI 冒烟：构建依赖 cargo（重）、执行扫真实系统（机器状态相关），
  // 不适合日常必跑；发版前 / examples/scan.rs 或 scan_execute.rs 改动时人工触发。
  { name: 'check-headless-cli', reason: '可选：发版前 / 无头 CLI 链路改动时跑（依赖 cargo 构建与真实系统扫描）' },
];
const RETIRED = [
  // D-2 裁定退役：PS 替换管线随外部 PS7 通道整条删除（见 AGENTS.md §4.1 与 §5.12）。
  { name: 'check-ps-substitution', reason: '已退役（v2-D2）：外部 PS7 通道删除后无对象' },
];

let failed = 0;
const fail = (msg) => { console.error(`✗ ${msg}`); failed++; };
const ok = (msg) => console.log(`✓ ${msg}`);

const diskAll = readdirSync(TOOLS).filter((f) => f.endsWith('.mjs'));
const diskCheck = diskAll.filter((f) => /^check-.*\.mjs$/.test(f)).map((f) => f.replace(/\.mjs$/, ''));
const optionalNames = OPTIONAL.map((o) => o.name);
const retiredNames = RETIRED.map((o) => o.name);
for (const key of SIDE_EFFECT.keys()) {
  if (!MUST_RUN.includes(key) && !optionalNames.includes(key)) fail(`SIDE_EFFECT 登记的 ${key} 不在 MUST_RUN / OPTIONAL 里`);
}

// ── 1. 注册表内部一致性 ──
const dup = MUST_RUN.filter((n, i) => MUST_RUN.indexOf(n) !== i);
for (const n of dup) fail(`MUST_RUN 重复登记 ${n}`);
for (const { name } of [...OPTIONAL, ...RETIRED]) {
  if (MUST_RUN.includes(name)) fail(`${name} 同时出现在 MUST_RUN 与 OPTIONAL/RETIRED 注册表（双重身份 = 口径含糊）`);
}
for (const key of Object.keys(GATE_ARGS)) {
  if (!MUST_RUN.includes(key)) fail(`GATE_ARGS 登记的 ${key} 不在 MUST_RUN 里`);
}

// ── 2. 注册表 ⇄ 磁盘 ──
// 2a. 注册表条目必须在磁盘上存在（注册表腐烂成第二本假账）。
for (const name of MUST_RUN) {
  if (!diskAll.includes(`${name}.mjs`)) fail(`MUST_RUN 登记的 tools/${name}.mjs 磁盘上不存在`);
}
// 2b. 磁盘 check 文件必须三方有其一：MUST_RUN / OPTIONAL / RETIRED。
for (const f of diskCheck) {
  if (MUST_RUN.includes(f) || optionalNames.includes(f) || retiredNames.includes(f)) continue;
  fail(`磁盘存在 tools/${f}.mjs，但既不在 MUST_RUN、也不在 OPTIONAL/RETIRED 注册表（新门禁必须先进注册表）`);
}
// 2c. OPTIONAL/RETIRED 条目必须真实存在且带书面理由。
for (const { name, reason } of [...OPTIONAL, ...RETIRED]) {
  if (!reason || reason.trim().length < 8) fail(`注册表条目 ${name} 缺少理由（OPTIONAL/RETIRED 必须带书面 scope）`);
  if (!existsSync(join(TOOLS, `${name}.mjs`))) fail(`注册表登记的 tools/${name}.mjs 磁盘上不存在`);
}

// ── 3. AGENTS.md 只做轻量引用校验（必跑清单已不在这里，不再解析 §4 全表）──
// AGENTS.md 是未跟踪的本机协作约束，干净克隆里没有；缺文件时显式 SKIP，不崩也不打 ✓ 冒充通过。
const agentsPresent = existsSync(AGENTS);
if (!agentsPresent) {
  console.log('⚠ AGENTS.md 不在本机（未跟踪文件）：AGENTS 引用校验**未执行**');
} else {
  const agentsText = readFileSync(AGENTS, 'utf8');
  const refs = [...agentsText.matchAll(/tools\/([A-Za-z0-9_-]+\.mjs)/g)].map((m) => m[1]);
  for (const ref of new Set(refs)) {
    if (!diskAll.includes(ref)) fail(`AGENTS.md 引用的 tools/${ref} 磁盘上不存在`);
  }
  // 源码注释按 §4.1 引用假绿防线；丢了会让引用指空。
  if (!agentsText.includes('### 4.1')) fail('AGENTS.md 缺少 §4.1 标题（源码注释按 §4.1 引用假绿防线）');
}

// ── 4. 台账输出（报告引用数字只能从这里抄）──
if (failed > 0) {
  console.error(`check-gate-roster: ${failed} 处不一致`);
  process.exit(1);
}
ok(`门禁运行集合台账对拍一致：磁盘 check ${diskCheck.length} 条 = MUST_RUN ${MUST_RUN.length} + OPTIONAL ${optionalNames.length} + RETIRED ${retiredNames.length}`);
// T1a-M06（v7.2 C09）：成员名单必须进输出——「51+3+1」三个数答不了「哪条是 RETIRED、
// 它为什么不算验证」，而 AGENTS §4 明写「必跑/可选/退役一律以本命令现算为准」。
for (const { name, reason } of OPTIONAL) console.log(`  OPTIONAL: ${name} — ${reason}`);
for (const { name, reason } of RETIRED) console.log(`  RETIRED: ${name} — ${reason}`);
for (const [name, why] of SIDE_EFFECT) console.log(`  SIDE_EFFECT: ${name} — ${why}`);

if (!RUN) {
  console.log(`check-gate-roster: 全部通过（可加 --run 跑完 ${MUST_RUN.length} 条必跑门禁）`);
  process.exit(0);
}

// ── 5. --run：按 MUST_RUN 顺序跑完全部必跑门禁 ──
let runFailed = 0;
let runSkipped = 0;
const selfReported = [];
for (const name of MUST_RUN) {
  if (READONLY_TIER && SIDE_EFFECT.has(name)) {
    console.log(`– SKIP ${name}（--tier=readonly 跳过副作用：${SIDE_EFFECT.get(name)}）`);
    runSkipped++;
    continue;
  }
  const args = [join(TOOLS, `${name}.mjs`), ...(GATE_ARGS[name] || [])];
  const res = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (res.status === 0) {
    ok(`run ${name}`);
    // T1-M06（v4-K07）：exit 0 ≠ 无失败断言 —— 子门禁可能自报 ✗（短路 bug / 未修完的断言），
    // 也可能自报 SKIP/未校验/0 对象。计数后单列，让「全绿」不再盖住子门禁自己的失败输出。
    // skip 的判据收紧到独立词形态（`skipped_reparse`/「跳过块」这类代码术语不算，否则满是误报）。
    const out = `${res.stdout || ''}\n${res.stderr || ''}`;
    const count = (re) => (out.match(re) || []).length;
    const marks = {
      x: count(/✗/g),
      // T1a-M06（v7.2 C09）：词表补「未验证 / RETIRED（ / 不算验证」——check-ps-extraction
      // 的「✓ 文本层门禁通过（行为层未验证）」此前被当成纯 ✓ 漏计，自报 SKIP 统计失真。
      // RETIRED 带（ 全角括号锚定：只认「RETIRED（未执行任何断言）」这类自报形态，
      // 不把本门禁自己打印的注册表成员名单（`RETIRED: 名字`）误计进去。
      skip: count(/(?:^|[^\w])SKIP(?![A-Za-z0-9_])|未校验|未验证|RETIRED（|不算验证/g),
      zero: count(/(?:^|[^\w])0\s*(?:个|条|处)(?![\w])/g),
    };
    if (marks.x + marks.skip + marks.zero > 0) selfReported.push({ name, ...marks });
  } else {
    runFailed++;
    console.error(`✗ run ${name}（exit ${res.status ?? 'null'}）`);
    if (res.stdout) process.stderr.write(res.stdout);
    if (res.stderr) process.stderr.write(res.stderr);
    if (res.error) process.stderr.write(`${res.error}\n`);
  }
}
if (runFailed > 0) {
  console.error(`check-gate-roster --run: ${runFailed}/${MUST_RUN.length} 条门禁失败`);
  process.exit(1);
}
if (selfReported.length > 0) {
  console.log(
    `\n〔子门禁自报标记〕以下 ${selfReported.length} 条 exit 0，但输出含失败（✗）/SKIP·未校验/0 对象标记——` +
      '「exit 0」只等于没有非 0 退出码，不等于没有失败断言：',
  );
  for (const s of selfReported) {
    console.log(`  · ${s.name}: ✗${s.x} / SKIP·未校验${s.skip} / 0 对象${s.zero}`);
  }
}
console.log(`check-gate-roster --run: ${MUST_RUN.length} 条必跑门禁全部通过${runSkipped ? `（SKIP ${runSkipped} 条副作用门禁，未校验）` : ''}`);
