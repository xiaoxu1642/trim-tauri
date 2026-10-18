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
  { file: 'check-elapsed-facts.mjs', manual: true, reason: 'E4 耗时字段：7 条违规样本自检（B 反向判定 / C 失败路径计时）' },
  { file: 'check-optimizer-write-contract.mjs', manual: true, reason: 'M2 写入坐标侧表：7 条样本自检（含 1 条应放行的干净样本，防判据变成「永远红」）' },
  { file: 'check-subwindow-init.mjs', reason: '副窗初始化：每页两条正向对照（注入指向不存在元素的绑定 + 抽掉一个真实 id），对照失效即红' },
  { file: 'check-subwindow-css.mjs', reason: '子窗 CSS 按需：S1 样式表序列 / S2 引用面 / S3 层叠翻转 / S4 token 真源四组各配正反样本 + 解析器形状对照（@media 内层与花括号字符串）' },
  { file: 'check-a11y.mjs', reason: '可达性四断言：勾选框三属性 / aria-live 宿主 / data-tip 反 title / RM 归零覆盖面各配正反样本自检 + 三类扫描面地板' },
  { file: 'check-contrast.mjs', reason: 'F 组玻璃面 floor 断言配正反向样本自检（P3-2）；F1a~F6b 操作面登记台账七类反例（裸 --bg-card / 后级覆写 / 修饰类另写底 / 台账过期 / background-image 绕开 floor / 语义实底被中性降级 / 折射白名单含未登记类）+ F3b 锚点对照（抹掉 wantRefract 的按钮排除必判红）+ floor 栈合成对照（空栈与只垫 floor 必红、完整栈放行）；A1/B/C 与 token 表等既有组仍缺合成样本' },
  { file: 'check-native-hygiene.mjs', reason: 'N1–N9 各配正反样本自检（裸 output / 定长解码 / 句柄丢弃 / .reg 读取 / 深度护栏 / 取最新 / 快照域 / origin 字面量闸 / 取用点登记闸），+ 模块可达性与扫描面地板' },
  { file: 'check-confirm-danger.mjs', reason: 'confirmedHighRisk 字面量判定器配正反样本自检（P3-5）；调用形态两组仍靠扫描面塌陷地板兜底' },
  { file: 'check-idle-scripts.mjs', manual: true, reason: 'loadScript 三态断言配「违例 3 条全命中 / 合规放行」样本自检（P3-4）；守卫与启动名单两组仍靠扫描面地板兜底' },
  { file: 'check-comment-rot.mjs', manual: true, reason: '注释腐烂：三条断言各配正反向对照（不存在路径/章节号/数字必判红 + 真实样本不假红）；另经真破坏验证——关掉待修豁免表后 8 处真实腐烂全被抓到，exit 1' },
  { file: 'check-review-units.mjs', reason: '审查单元台账：U1–U5 五条断言各配合成正反向样本（超上限/重复点名/未认领/台账塌缩必判红，干净表不假红）；另经真破坏验证——改名+降上限+抬地板三处同时判红，exit 1' },
  // v3 P2-I 新增三条：判据抽出成纯函数后与自检共用同一实现（不在别处抄第二套判据）
  { file: 'check-artifact-size.mjs', reason: '产物体积棘轮：4 组合成样本自检（超 cap 必红 / 等值放行 / 缩小只提示 / 未登记角色必红）；产物缺失走 SKIP 不冒充通过，另经真破坏验证——压低基线 cap 后 exit 1 并点名差值' },
  { file: 'check-first-paint.mjs', reason: '首屏关键路径：F1 预算双向 + F2 defer 不变量 + F4 首屏∩按需，7 组合成样本自检；豁免表与对照双向咬合——清空豁免表会让对照②立即判红（真破坏 exit 1），不是只松真样本' },
  { file: 'check-asset-size.mjs', reason: '资源体积三段判据抽出为单一 judgeAssets，5 组合成样本与之共用同一实现（塞未登记大文件 / 条目失踪 / 超 cap 必红，等值与干净样本放行）；从 PENDING_CONTROLS 迁入本表' },
  { file: 'check-desc-vs-writes.mjs', reason: 'P1-03 文案⇄写入：原缺陷形态判红 /「其余」精确限定与无声称放行，3 条判定器自检' },
  { file: 'check-power-write-surface.mjs', reason: 'P0-1 电源写面：9 条正反样本自检（powercfg 写命令/电源命名空间必判红，只读查询与页面文件步骤必须放行）+ ALLOW 双棘轮（登记不命中必红）' },
  { file: 'check-system-bin.mjs', reason: 'v6-K01/P0-2：判定器抽成 extractHitsFromText 后与 H 组 5 个合成样本共用同一实现（裸字面量/raw 版裸字面量/安装包路径误塞系统工具入口必判红，PINNED 解析与变量形态放行）+ F 组生产实参地板（12 个生产在用名掉表即红，与 systembin 单测两道防线）+ quiet 组扩到 timeout/raw 三个 spawn 门面（39+ 处超时调用点不再对 A/B 失明）+ G 组路径形态实参必红' },
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
  // check-system-bin 已于 2026-10-18 v6 P0-2 配齐正向对照并迁入 REGISTRY（本表只减不增）。
  { name: 'check-residue-rule-contract', reason: '对拍型：卸载残留规则库 ⇄ 执行侧契约，缺合成样本' },
  { name: 'check-scan-rule-diff', reason: '差分型：规则改动 → 命中集差分（按设计 spawn cargo test，重编译成本高），对照方案待定' },
  { name: 'check-ps-callsites', reason: '对拍型：PS 调用点 ⇄ 三张登记表（含超时秒数逐点核对），缺合成样本' },
  { name: 'check-ps-extraction', reason: '对拍型：JS 源 ⇄ .ps1 正文逐字（文本层 + --run 行为层双档），缺「单字节漂移必须红」样本' },
  { name: 'check-csp-consistency', reason: '对拍型：meta CSP ⇄ 三子窗副本逐字一致，缺合成样本' },
  { name: 'check-css-tokens', reason: '找违规型：未定义 token 引用 / 圆角离档即红，缺违规样本自检' },
  { name: 'check-assets-used', reason: '找违规型：src/assets 零引用文件即红，缺违规样本自检' },
  // check-asset-size 已于 2026-10-14 v3 P2-I 配好内置正向对照并迁入 REGISTRY（本表只减不增）。
  { name: 'check-treemap-layout', reason: '性质型：squarified 布局数学性质（面积和/包含关系），缺「人为破坏性质必须红」样本' },
  { name: 'check-item-intro', reason: '对拍型：item-intro.json 多形态 ⇄ 前端消费口径，缺合成样本' },
  { name: 'check-desktop-entry', reason: '对拍型：桌面入口 ⇄ 发布暂存目录合并状态，缺合成样本' },
  { name: 'check-data-parity', reason: '对拍型：data/*.json 派生副本 ⇄ 真源（6+1 个），缺「改一侧必须红」样本' },
  { name: 'check-optimizer-dynamic', reason: '对拍型：dynamic 标记 ⇄ 后端 is_dynamic 分支要求，缺合成样本' },
  { name: 'check-optimizer-security', reason: '找违规型：扩库夹带关闭安全组件即红，缺违规样本自检' },
  { name: 'check-optimizer-subitem-contract', reason: '对拍型：可自选目标契约 ⇄ 侧表，缺合成样本' },
  { name: 'check-optimizer-groups-sidecar', reason: '对拍型：分类侧表 ⇄ 渲染层兜底常量，缺合成样本' },
  { name: 'check-version-sync', reason: '对拍型：版本号四处一致，缺「单处漂移必须红」样本' },
  { name: 'check-updater-pubkey', reason: '对拍型：pubkey 形状（base64(minisign)），缺合成样本' },
  { name: 'check-readme-claims', reason: '对拍型：readme 数字 ⇄ 数据真源，缺合成样本' },
  { name: 'check-cleanup-postactions', reason: '对拍型：后置动作侧表 ⇄ 路径机械重算（双向），缺「单条侧表漂移必须红」合成样本' },
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
// v5 批次 9（门禁候选 4）：第 1 组从「文本关键词」改结构化对拍——旧判据只查文件里
// 含不含「正向对照」四个字，注释里写一句就过（被注释满足 = K07 同族的假绿）。
// 结构化判据：剥注释后必须存在**真实的对照断言行**（check(/fail( 调用且 label 含
// 「对照」）——写得出这行 = 判定器真有可判红的对照样本。
const missingSelfTest = [];
const brokenRun = [];
// v5 批次 9（门禁候选 4）：manual: true = 该门禁的对照形态是「人工/真破坏验证」
// （自检形态不在机检识别集内），显式登记而非静默漏判；机检条目数收口见第 1 组断言。
const manualEntries = [];
for (const e of REGISTRY) {
  if (e.manual) {
    manualEntries.push(e.file);
    continue;
  }
  const p = join(ROOT, 'tools', e.file);
  let text;
  try {
    text = readFileSync(p, 'utf8');
  } catch {
    brokenRun.push(`${e.file} 文件不存在`);
    continue;
  }
  const clean = text.replace(/^\s*\/\/.*$/gm, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');
  // 两种真实对照形态都要认：
  // ① check(/g.fail( 调用窗口内含「对照/正向/判红」（check 常跨行 ⇒ 起点后 400 字符窗口）；
  // ② fail-closed 对照串（`正向对照失败` 等 console.error+exit 形态，如
  //    check-escape-delegation / check-html-contract——字符串字面量在代码里，剥注释后仍在）。
  const hasRealControl =
    /正向对照失败|本门禁失效|必须判红|必须放行|永远不会被测坏|坏成永远放行|判定器没抓住|判定器误红/.test(clean) ||
    [...clean.matchAll(/(?:^|\n)\s*(?:check|g\.fail)\s*\(/g)].some(
      (m) => /对照|正向|判红/.test(clean.slice(m.index, m.index + 400)),
    );
  if (!hasRealControl) {
    missingSelfTest.push(`${e.file}（${e.reason}）—— 剥注释后无任何 check/fail 型对照断言行`);
    continue;
  }
  const r = spawnSync(process.execPath, [p], { cwd: ROOT, encoding: 'utf8' });
  if (r.status !== 0) brokenRun.push(`${e.file} 执行 exit ${r.status}`);
}
check(
  missingSelfTest.length === 0,
  `1. ${REGISTRY.length - manualEntries.length} 个机检型门禁均内置真实对照断言（剥注释后可判）+ ${manualEntries.length} 个显式登记人工/真破坏验证`,
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
