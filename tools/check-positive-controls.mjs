#!/usr/bin/env node
// check-positive-controls.mjs —— 找违规型断言的正向对照管辖门禁
// （v2-L4P-44 / E-8、E-15，2026-10-02）
//
// 抓什么：「找违规型」门禁有两条失效方向——① 扫描前提失效（目录改名、正则过时）
// 导致 0 命中恒绿；② 判定器被误改坏（如正则加了个永远为 false 的分支）。两者都
// 不会让门禁本身报错，防线在无声中消失。范本是 check-cleanup-rule-contract 的
// 37 条反例自检：判定器必须能对**已知违规样本**判红，✓ 才可信。
//
// 本门禁断言：登记在案的每个找违规型门禁必须 (a) 内置 POSITIVE_CONTROLS 自检块、
// (b) 实际执行 exit 0（自检与扫描都在门禁自身内跑通）。新增找违规型门禁不登记即红。
'use strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// 需要正向对照的找违规型门禁清单（新增必须登记，带理由）
const REGISTRY = [
  { file: 'check-delete-exits.mjs', reason: '删除出口枚举：剥离/命中两向自检' },
  { file: 'check-escape-delegation.mjs', reason: 'escape 委托：非委托样本自检' },
  { file: 'check-html-contract.mjs', reason: 'HTML 合同：内联 script 样本自检' },
  { file: 'check-cleanup-rule-contract.mjs', reason: '规则契约：37 条反例自检（既有范本）' },
  { file: 'check-rule-schema-sync.mjs', reason: '契约表⇄Rust 装载侧：5 条判定器自检（干净样本 / token 注入 / 缺键查询 / 路径漂移 / 剥离失败）' },
  { file: 'check-elapsed-facts.mjs', reason: 'E4 耗时字段：7 条违规样本自检（B 反向判定 / C 失败路径计时）' },
  { file: 'check-optimizer-write-contract.mjs', reason: 'M2 写入坐标侧表：7 条样本自检（含 1 条应放行的干净样本，防判据变成「永远红」）' },
  { file: 'check-subwindow-init.mjs', reason: '副窗初始化：每页两条正向对照（注入指向不存在元素的绑定 + 抽掉一个真实 id），对照失效即红' },
  { file: 'check-a11y.mjs', reason: '可达性三断言：勾选框三属性 / aria-live 宿主 / data-tip 反 title 各配正反样本自检 + 三类扫描面地板' },
  { file: 'check-contrast.mjs', reason: 'F 组玻璃面 floor 断言配正反向样本自检（P3-2）；A1/B/C 与 token 表等既有组仍缺合成样本' },
  { file: 'check-comment-rot.mjs', reason: '注释腐烂：三条断言各配正反向对照（不存在路径/章节号/数字必判红 + 真实样本不假红）；另经真破坏验证——关掉待修豁免表后 8 处真实腐烂全被抓到，exit 1' },
];

// MUST_RUN 里尚未配「内置正向对照自检」的存量门禁（T1-M05，2026-10-09 现算 33 条）。
// 每条登记必须写清「当前缺口形态」；本表**只减不增**：配好内置对照后移到 REGISTRY 并
// 从本表删除（断言 4/5 会核对两张表与 MUST_RUN 的一致性）。新增必跑门禁一律进 REGISTRY，
// 进不了就先在这里登记并写明为什么暂缺 —— 不登记即红。
const PENDING_CONTROLS = [
  { name: 'check-channel-map', reason: '对拍型：桥接表 ⇄ Rust 通道集合双向比对，缺「删/添一侧必须红」的合成样本' },
  { name: 'check-guard-tiers', reason: '对拍型：档位表 ⇄ 命令体 guard 调用逐条核对，缺合成样本' },
  { name: 'check-layering', reason: '找违规型：下层反向引用上层即红，缺违规样本自检' },
  { name: 'check-delete-callsites', reason: '棘轮+地板：超基线/扫描面归零即红；缺「人为加一行 remove_file 必须红」的合成样本' },
  { name: 'check-fail-closed', reason: '找违规型：降级回退形态即红，缺违规样本自检' },
  { name: 'check-system-bin', reason: '找违规型：裸 exe 名启动即红，缺合规/违规双向样本' },
  { name: 'check-residue-rule-contract', reason: '对拍型：卸载残留规则库 ⇄ 执行侧契约，缺合成样本' },
  { name: 'check-scan-rule-diff', reason: '差分型：规则改动 → 命中集差分（按设计 spawn cargo test，重编译成本高），对照方案待定' },
  { name: 'check-ps-callsites', reason: '对拍型：PS 调用点 ⇄ 三张登记表（含超时秒数逐点核对），缺合成样本' },
  { name: 'check-ps-extraction', reason: '对拍型：JS 源 ⇄ .ps1 正文逐字（文本层 + --run 行为层双档），缺「单字节漂移必须红」样本' },
  { name: 'check-csp-consistency', reason: '对拍型：meta CSP ⇄ 三子窗副本逐字一致，缺合成样本' },
  { name: 'check-css-tokens', reason: '找违规型：未定义 token 引用 / 圆角离档即红，缺违规样本自检' },
  { name: 'check-assets-used', reason: '找违规型：src/assets 零引用文件即红，缺违规样本自检' },
  { name: 'check-asset-size', reason: '棘轮型：资源体积超基线即红，缺「人为塞大文件必须红」样本' },
  { name: 'check-idle-scripts', reason: '找违规型：缺 readyState 守卫 / 提前 init 即红，缺违规样本自检（已有空集地板）' },
  { name: 'check-confirm-danger', reason: '找违规型：确认入口首参对象字面量即红，缺违规样本自检（已有目录塌陷地板）' },
  { name: 'check-treemap-layout', reason: '性质型：squarified 布局数学性质（面积和/包含关系），缺「人为破坏性质必须红」样本' },
  { name: 'check-item-intro', reason: '对拍型：item-intro.json 多形态 ⇄ 前端消费口径，缺合成样本' },
  { name: 'check-desktop-entry', reason: '对拍型：桌面入口 ⇄ 发布暂存目录合并状态，缺合成样本' },
  { name: 'check-data-parity', reason: '对拍型：data/*.json 派生副本 ⇄ 真源（6+1 个），缺「改一侧必须红」样本' },
  { name: 'check-optimizer-dynamic', reason: '对拍型：dynamic 标记 ⇄ 后端 is_dynamic 分支要求，缺合成样本' },
  { name: 'check-optimizer-security', reason: '找违规型：扩库夹带关闭安全组件即红，缺违规样本自检' },
  { name: 'check-optimizer-subitem-contract', reason: '对拍型：可自选目标契约 ⇄ 侧表，缺合成样本' },
  { name: 'check-optimizer-groups-sidecar', reason: '对拍型：分类侧表 ⇄ 渲染层兜底常量，缺合成样本' },
  { name: 'check-bugcheck-codes', reason: '对拍型：蓝屏码库结构/唯一性/枚举合法性，缺合成样本' },
  { name: 'check-version-sync', reason: '对拍型：版本号四处一致，缺「单处漂移必须红」样本' },
  { name: 'check-updater-pubkey', reason: '对拍型：pubkey 形状（base64(minisign)），缺合成样本' },
  { name: 'check-readme-claims', reason: '对拍型：readme 数字 ⇄ 数据真源，缺合成样本' },
  { name: 'check-readme-negative-claims', reason: '找违规型：否定式承诺漂移即红，缺违规样本自检' },
  { name: 'check-doc-refs', reason: '找违规型：文档互引路径存在性 + 私钥令牌黑名单，缺违规样本自检' },
  { name: 'check-positive-controls', reason: '本文件即管辖门禁：其对照 = REGISTRY 各条实跑检查 + 差集断言（自指，不重复登记）' },
  { name: 'check-gate-roster', reason: '台账对拍：磁盘集合 ⇄ 三个注册表，缺「人为加/删一条注册必须红」样本' },
];

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 正向对照管辖门禁 ===\n');
const missingSelfTest = [];
const brokenRun = [];
for (const e of REGISTRY) {
  const p = join(ROOT, 'tools', e.file);
  let text;
  try {
    text = readFileSync(p, 'utf8');
  } catch {
    brokenRun.push(`${e.file} 文件不存在`);
    continue;
  }
  if (!text.includes('POSITIVE_CONTROLS') && !text.includes('反例') && !text.includes('正向对照') && !text.includes('判定器自检')) {
    missingSelfTest.push(`${e.file}（${e.reason}）`);
    continue;
  }
  const r = spawnSync(process.execPath, [p], { cwd: ROOT, encoding: 'utf8' });
  if (r.status !== 0) brokenRun.push(`${e.file} 执行 exit ${r.status}`);
}
check(
  missingSelfTest.length === 0,
  `1. ${REGISTRY.length} 个找违规型门禁均内置正向对照自检`,
  missingSelfTest.join('；'),
);
check(
  brokenRun.length === 0,
  '2. 全部登记门禁实际执行 exit 0（自检在门禁内随跑随验）',
  brokenRun.join('；'),
);

// ── 3~5（T1-M05）：MUST_RUN ⇄ REGISTRY 差集 —— 新增必跑门禁不登记即红 ──
// 唯一真源在 check-gate-roster.mjs 的 MUST_RUN；本文件不复制清单、只解析文本
// （复制一份必然漂移，两个真源各自漂移正是这条缺口当初的形态）。
const mustRun = (() => {
  const src = readFileSync(join(ROOT, 'tools', 'check-gate-roster.mjs'), 'utf8');
  const m = /const MUST_RUN = \[([\s\S]*?)\];/.exec(src);
  return m ? [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]) : [];
})();
check(
  mustRun.length >= 30,
  '3. MUST_RUN 解析自检（≥30 条；解析失效会让差集恒空 = 又一处「0 对象假绿」）',
  `解析到 ${mustRun.length} 条`,
);
const registeredNames = new Set(REGISTRY.map((e) => e.file.replace(/\.mjs$/, '')));
const pendingNames = new Set(PENDING_CONTROLS.map((e) => e.name));
const uncovered = mustRun.filter((n) => !registeredNames.has(n) && !pendingNames.has(n));
check(
  uncovered.length === 0,
  '4. MUST_RUN − REGISTRY − PENDING 为空（新增必跑门禁必须二选一登记）',
  uncovered.length
    ? `未登记：${uncovered.join('；')}`
    : `REGISTRY ${REGISTRY.length} 条 + PENDING ${PENDING_CONTROLS.length} 条 = MUST_RUN ${mustRun.length} 条`,
);
const stalePending = PENDING_CONTROLS.filter(
  (e) => !mustRun.includes(e.name) || registeredNames.has(e.name),
).map((e) => e.name);
check(
  stalePending.length === 0,
  '5. PENDING 白名单不腐烂（不在 MUST_RUN、或已进 REGISTRY 的条目必须删——迁移即收缩）',
  stalePending.join('；'),
);

if (fail > 0) {
  console.error('check-positive-controls: 存在缺口');
  process.exit(1);
}
console.log('check-positive-controls: 全部通过');
