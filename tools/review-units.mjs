'use strict';
// tools/review-units.mjs —— 审查单元台账唯一真源（多 agent 派单的分工表）
//
// 为什么这张表必须在**跟踪文件**里：v4 战役的单元清单只存在于本机资料区的文档表里，于是
// 「卡片由表生成、表腐烂则卡片跟着烂」（实测：11 处静态数字错、3 张卡片照抄已作废红线、
// 一份分报告派单时基线文件根本不存在），而且新增目录会**静默退出审查台账**——与
// check-guard-tiers 那条「搬进子目录的命令自动退出档位台账」是同一类假绿。
// 本表把「谁审哪些文件」变成可机检的代码，判据实现只有一份（AGENTS §5.16 N6）：
// 文档只写角色与判据，不复制清单；规模一律由 tools/check-review-units.mjs 现算。
//
// 规模口径由本仓唯一实现定义：**UTF-8 非空行**（等价 pwsh7 的 `Get-Content | Where Trim -ne ''`；
// PS 5.1 按 cp936 解码会吞换行、少算行数，v4 实测撞过，不许再用它出规模）。
//
// 认领语义（**先到先得**，按本表数组顺序）：
//   - `files` 显式点名（相对仓库根，正斜杠）；
//   - `dirs` 目录认领：{dir, ext?, depth?, onlyPrefix?, notPrefix?}，只认领此前无人认领的文件；
//   - 所以「其余」类单元必须排在同目录的点名单元之后——新增文件自动落进「其余」单元，
//     不会没人审，但单元超上限会被 U2 判红，逼人来重切（这是刻意的棘轮方向）。
//   - `generated` 从「需精读规模」里剔除，只进抽验清单（生成物逐行读没有意义）。

/** 单单元精读行数上限（2026-10-09 用户拍板：8000；6000 会逼着把红线层拆散，弃）。 */
export const CAP_LINES = 8000;

/** U5 地板：单元数塌到这个数以下 = 表烂了，不是仓库变小了。 */
export const FLOOR = { longitudinal: 20, cross: 10, antiPattern: 6 };

/**
 * 认领根：U4「每个文件必须被恰好一个纵向单元认领」的并集来源。
 * depth:1 = 只看该目录直属文件（commands 顶层与其三个子域分属不同单元）。
 */
export const AUDIT_ROOTS = [
  { dir: 'src-tauri/src', ext: ['.rs'], depth: 1 },
  { dir: 'src-tauri/src/engine', ext: ['.rs'], depth: 1 },
  { dir: 'src-tauri/src/engine/native', ext: ['.rs'], depth: 1 },
  { dir: 'src-tauri/src/commands', ext: ['.rs'], depth: 1 },
  { dir: 'src-tauri/src/commands/uninstall', ext: ['.rs'], depth: 1 },
  { dir: 'src-tauri/src/commands/optimizer', ext: ['.rs'] },
  { dir: 'src-tauri/src/commands/cleanup', ext: ['.rs'] },
  { dir: 'src-tauri/src/pwsh', ext: ['.rs'] },
  { dir: 'src-tauri/src/security', ext: ['.rs'] },
  { dir: 'src-tauri/src/diag', ext: ['.rs'] },
  { dir: 'src/scripts', ext: ['.js'], depth: 1 },
  { dir: 'src/styles', ext: ['.css'], depth: 1 },
  { dir: 'src', ext: ['.html'], depth: 1 },
  { dir: 'native-scanner/src', ext: ['.rs'] },
  { dir: 'native-scanner/tests', ext: ['.rs'] },
  { dir: 'tools', ext: ['.mjs'], depth: 1 },
  { dir: 'tools/lib', ext: ['.mjs'], depth: 1 },
  { dir: 'src-tauri/data', ext: ['.json'], depth: 1 },
  { dir: 'src-tauri/capabilities', ext: ['.json'], depth: 1 },
  { dir: 'src-tauri/tests' },
  { file: 'src-tauri/tauri.conf.json' },
];

const E = 'src-tauri/src/engine';
const N = `${E}/native`;
const C = 'src-tauri/src/commands';
const U = `${C}/uninstall`;
const S = 'src/scripts';

/** 纵向单元：认领具体文件，一个文件只归一个单元（顺序即优先级）。 */
export const UNITS = [
  // ── Rust 侧 ──
  {
    id: 'R8', owner: 'sub', name: '入口与命令注册',
    files: ['src-tauri/src/lib.rs', 'src-tauri/src/main.rs'],
    contract: 'generate_handler! 注册面 / 建窗握手 / with_browser_args',
    boundary: '只审注册面与建窗握手；命令体内逻辑归各域单元',
    gates: ['check-guard-tiers', 'check-channel-map'],
  },
  {
    id: 'R6a', owner: 'main', name: 'engine 红线核心（主 agent 自审）',
    files: [`${E}/guard.rs`, `${E}/protect.rs`, `${E}/paths.rs`, `${E}/snapshot.rs`,
      `${E}/systembin.rs`, `${E}/reg_backup.rs`, `${E}/rules_signature.rs`, `${E}/rule_schema.rs`,
      `${E}/pssteps.rs`, `${E}/mod.rs`],
    contract: 'guard 档位 / protect 受保护路径 / 数据目录 / 快照槽 / PS 双通道编译器 / 规则验签',
    boundary: '产出《红线口径基线》，定性优先于任何域单元；条目单列、不并入 subagent 已审统计',
    gates: ['check-guard-tiers', 'check-ps-callsites', 'check-rule-schema-sync'],
  },
  {
    id: 'R6b', owner: 'sub', name: 'engine 其余（外设/图标/系统信息）',
    dirs: [{ dir: E, ext: ['.rs'], depth: 1 }],
    contract: 'restore_pack / optimization_state / shellicon / winhttp / pnp / sysrestore 等',
    boundary: '红线口径一律引用 R6a 基线、不自解释；engine::native 归 R5a/R5b',
    gates: ['check-guard-tiers', 'check-data-parity'],
  },
  {
    id: 'R5a', owner: 'sub', name: 'native 三胖（清理/右键/启动项执行层）',
    files: [`${N}/cleanup.rs`, `${N}/contextmenu.rs`, `${N}/startup.rs`],
    contract: '删除出口 / shellex 与 winx 启停 / 启动项台账',
    boundary: 'engine 顶层口径归 R6a；删除闸数按基线核，不核存在性',
    gates: ['check-delete-callsites', 'check-native-hygiene'],
  },
  {
    id: 'R5b', owner: 'sub', name: 'native 其余（扫描/注册表/进程/体检）',
    dirs: [{ dir: N, ext: ['.rs'] }],
    contract: 'bsod / registry / process / runtimes_net / diagnostics / syspanel / paths_scan 等',
    boundary: '外部进程与句柄卫生与 A5 交叉，本单元只审域内逻辑',
    gates: ['check-native-hygiene', 'check-system-bin'],
  },
  {
    id: 'R1a', owner: 'sub', name: 'commands 顶层·设置与更新链',
    files: [`${C}/settings.rs`, `${C}/updater.rs`, `${C}/elevate.rs`, `${C}/appearance.rs`,
      `${C}/state.rs`, `${C}/log.rs`, `${C}/misc.rs`, `${C}/system.rs`, `${C}/syspanel.rs`,
      `${C}/app.rs`, `${C}/paths.rs`, `${C}/benchhistory.rs`, `${C}/residue.rs`, `${C}/overview.rs`,
      `${C}/maintenance.rs`, `${C}/preview.rs`, `${C}/device.rs`, `${C}/mod.rs`],
    contract: 'settings 读写 / updater 验签 / 提权入口 / 状态真源',
    boundary: '提权与高危确认字段是本单元红线；扫描与查询类命令归 R1b',
    gates: ['check-guard-tiers', 'check-confirm-danger', 'check-updater-pubkey'],
  },
  {
    id: 'R2a', owner: 'sub', name: 'uninstall 残留链（扫描→更新→待删）',
    files: [`${U}/residue.rs`, `${U}/residue_update.rs`, `${U}/pending_delete.rs`,
      `${U}/backup_report.rs`, `${U}/vendor_registry.rs`, `${U}/dead.rs`, `${U}/authenticode.rs`,
      `${U}/helpers.rs`, `${U}/mod.rs`, `${U}/residue_trace_tests.rs`],
    contract: '残留三链 / 重启后删除三件套 / 规则库消费侧',
    boundary: '孤儿扫描族与列表执行归 R2b；窄窗口集档位以 check-guard-tiers 现算为准',
    gates: ['check-residue-rule-contract', 'check-data-parity'],
  },
  {
    id: 'R1b', owner: 'sub', name: 'commands 顶层·扫描与系统工具链（含新增命令文件自动落入）',
    dirs: [{ dir: C, ext: ['.rs'], depth: 1 }],
    contract: 'finder / fileclean / contextmenu / startup / models / runtimes / quickcmds 等命令面',
    boundary: '不含三个子目录域；native 执行层归 R5a/R5b',
    gates: ['check-guard-tiers', 'check-channel-map', 'check-scan-rule-diff'],
  },
  {
    id: 'R2b', owner: 'sub', name: 'uninstall 孤儿与执行（列表/运行/七类孤儿）',
    dirs: [{ dir: U, ext: ['.rs'] }],
    contract: 'uninstall_run 等待链 / services_orphan / game_platform_orphan / run_keys / com_orphan 等',
    boundary: '等待链「不强杀卸载器、超时如实上报」是红线（AGENTS §5.24）',
    gates: ['check-delete-exits', 'check-guard-tiers'],
  },
  {
    id: 'R3', owner: 'sub', name: 'commands/optimizer',
    dirs: [{ dir: `${C}/optimizer` }],
    contract: 'apply / overview / backup_restore / 写入契约测试',
    boundary: '灰态三源并集与写入坐标侧表是本单元专属红线',
    gates: ['check-optimizer-write-contract', 'check-optimizer-dynamic'],
  },
  {
    id: 'R4', owner: 'sub', name: 'commands/cleanup',
    dirs: [{ dir: `${C}/cleanup` }],
    contract: 'rules / scan_execute / backup / recycle_bin',
    boundary: '「常规清理固定永久删」是唯一受控例外，核五道约束别核存在性',
    gates: ['check-data-parity', 'check-scan-rule-diff'],
  },
  {
    id: 'R7', owner: 'sub', name: 'PS 执行层与安全基元',
    files: ['src-tauri/src/safestorage.rs'],
    dirs: [{ dir: 'src-tauri/src/pwsh' }, { dir: 'src-tauri/src/security' }, { dir: 'src-tauri/src/diag' }],
    contract: 'run_inbox_script 唯一咽喉 / atomic_write_json / update_json 三态 / SECRET_MASK',
    boundary: 'PS 单一入口与原子写是本单元红线；调用点合规性归各调用方单元',
    gates: ['check-ps-callsites', 'check-ps-extraction', 'check-fail-closed'],
  },

  // ── 前端 ──
  {
    id: 'F2', owner: 'sub', name: '契约层 tauri-api.js',
    files: [`${S}/tauri-api.js`],
    contract: 'CHANNEL_MAP 通道→命令唯一真源 / preload 白名单',
    boundary: '只审映射表与转发；通道后端实现归 Rust 各单元',
    gates: ['check-channel-map'],
  },
  {
    id: 'F1b', owner: 'sub', name: '设计系统脚本与子窗样式',
    files: [`${S}/ds.js`, 'src/styles/ds.css'],
    contract: 'ds.esc / ds.escAttr / ds.fmtBytes / bindCheckboxKeys',
    boundary: '转义与字节格式化唯一真源，禁本地实现',
    gates: ['check-escape-delegation', 'check-a11y'],
  },
  {
    id: 'F1a', owner: 'sub', name: '设计系统 token（main.css，分段审）',
    dirs: [{ dir: 'src/styles', ext: ['.css'] }],
    segmented: true,
    segmentBy: '锚点子串分段（token 基础段 / 组件段 / 动效与材质段），禁写行号（AGENTS §5.19）',
    contract: 'token 唯一真源 / 圆角档位 / --lg-glass-floor / --ease-standard',
    boundary: '单文件超上限，按段派读；禁离表色与装饰性氛围光',
    gates: ['check-css-tokens', 'check-contrast'],
  },
  {
    id: 'F3', owner: 'sub', name: '引导与窗口',
    files: [`${S}/app.js`, `${S}/splash.js`, `${S}/theme-boot.js`, `${S}/theme.js`,
      `${S}/window-material.js`, `${S}/intro.js`, `${S}/logger.js`, `${S}/modal.js`, `${S}/sub-toast.js`],
    dirs: [{ dir: 'src', ext: ['.html'], depth: 1 }],
    contract: 'init() 幂等台账 / 黑闪握手 / CSP meta / 开屏走场',
    boundary: '「窗口刻意设计」清单见方法论 §7.1，不许当缺陷报',
    gates: ['check-csp-consistency', 'check-html-contract', 'check-idle-scripts'],
  },
  {
    id: 'F5', owner: 'sub', name: '视觉特效',
    files: [`${S}/liquid-glass.js`, `${S}/spotlight.js`, `${S}/tilt.js`, `${S}/mouse-trail.js`, `${S}/xtable.js`],
    contract: '加载序依赖 / prefers-reduced-motion 实时求值 / 玻璃面 floor',
    boundary: 'spotlight 必须在 liquid-glass 之后（既成契约）',
    gates: ['check-contrast', 'check-css-tokens'],
  },
  {
    id: 'F4a', owner: 'sub', name: '清理与卸载链脚本',
    files: [`${S}/cleanup.js`, `${S}/uninstall.js`, `${S}/residue-window.js`, `${S}/memoryclean.js`,
      `${S}/peripheral.js`, `${S}/quickcmds.js`, `${S}/quickcmds-data.js`, `${S}/maintenance.js`,
      `${S}/startup.js`, `${S}/contextmenu.js`, `${S}/pathbinding.js`],
    contract: '各域页面渲染 ⇄ 命令回执消费口径',
    boundary: '状态真源分裂（localStorage 镜像 vs 后端真源）是本单元红线',
    gates: ['check-channel-map', 'check-a11y'],
  },
  {
    id: 'F4b', owner: 'sub', name: '优化与查询链脚本',
    files: [`${S}/optimizer.js`, `${S}/finder.js`, `${S}/overview.js`, `${S}/models-window.js`,
      `${S}/modelpicker.js`, `${S}/diskbench.js`, `${S}/netspeed.js`, `${S}/netspeed-detector.js`,
      `${S}/netcheck.js`, `${S}/realtime.js`, `${S}/processes.js`, `${S}/process-manager-window.js`],
    contract: '优化项执行 / 磁盘查找 / 测速 / 实时视图',
    boundary: '灰态与回执三态的消费侧形状按 R3/R4 契约写',
    gates: ['check-channel-map', 'check-treemap-layout'],
  },
  {
    id: 'F4c', owner: 'sub', name: '系统面板与更新脚本（新增前端脚本自动落入）',
    dirs: [{ dir: S, ext: ['.js'], depth: 1 }],
    generated: [`${S}/cleanup-fallback.generated.js`, `${S}/icon-fallback.js`],
    contract: 'syspanel / sysrestore / runtimes / fontmanager / deviceinfo / updater-ui / preview-window 等',
    boundary: '本单元是前端脚本的兜底认领位，U4 会点名靠兜底进来的文件',
    gates: ['check-channel-map', 'check-subwindow-init'],
  },

  // ── 外围 ──
  {
    id: 'N1', owner: 'sub', name: '原生扫描器',
    dirs: [{ dir: 'native-scanner/src' }, { dir: 'native-scanner/tests' }],
    contract: 'scan.rs / cleanup_scan.rs / 行协议 / recycle',
    boundary: 'path 依赖、非 workspace 成员；测试唯一自动入口是 check-scan-rule-diff',
    gates: ['check-scan-rule-diff'],
  },
  {
    id: 'T1a', owner: 'sub', name: '门禁·安全与执行面',
    files: ['tools/check-channel-map.mjs', 'tools/check-guard-tiers.mjs',
      'tools/check-delete-callsites.mjs', 'tools/check-delete-exits.mjs',
      'tools/check-ps-callsites.mjs', 'tools/check-ps-extraction.mjs',
      'tools/check-ps-substitution.mjs', 'tools/check-system-bin.mjs',
      'tools/check-fail-closed.mjs', 'tools/check-layering.mjs',
      'tools/check-confirm-danger.mjs', 'tools/check-csp-consistency.mjs',
      'tools/check-escape-delegation.mjs', 'tools/check-native-hygiene.mjs',
      'tools/check-positive-controls.mjs', 'tools/check-gate-roster.mjs',
      'tools/check-doc-refs.mjs', 'tools/check-optimizer-write-contract.mjs',
      'tools/check-subwindow-init.mjs', 'tools/check-idle-scripts.mjs',
      'tools/check-review-units.mjs'],
    contract: '档位 / 通道 / 删除出口 / PS 调用点 / 门禁自身假绿 / 派单台账',
    boundary: '审的是门禁**自身**会不会假绿，不是拿它审别的模块',
    gates: ['check-gate-roster', 'check-positive-controls'],
  },
  {
    id: 'T1c', owner: 'sub', name: '生成器与发布工具',
    dirs: [{ dir: 'tools', ext: ['.mjs'], depth: 1, notPrefix: 'check-' }, { dir: 'tools/lib', ext: ['.mjs'], depth: 1 }],
    contract: 'sync-ps-from-js / sign-* / gen-* / publish-atomgit / rule-schema / ps-mapping',
    boundary: '生成物禁手改；改源→重生成→重签的链是本单元红线',
    gates: ['check-ps-extraction', 'check-data-parity'],
  },
  {
    id: 'T1b', owner: 'sub', name: '门禁·数据产物与样式（新增门禁自动落入）',
    dirs: [{ dir: 'tools', ext: ['.mjs'], depth: 1, onlyPrefix: 'check-' }],
    contract: '数据对拍 / 版本同步 / readme 承诺 / 注释腐烂 / 样式与可达性',
    boundary: '未点名进 T1a 的 check-*.mjs 一律落本单元（兜底认领位）',
    gates: ['check-data-parity', 'check-version-sync', 'check-comment-rot'],
  },
  {
    id: 'D1', owner: 'sub', name: '数据与配置',
    files: ['src-tauri/tauri.conf.json'],
    dirs: [{ dir: 'src-tauri/data', ext: ['.json'], depth: 1 },
      { dir: 'src-tauri/capabilities', ext: ['.json'], depth: 1 }],
    generated: ['src-tauri/data/cleanup-rules.json', 'src-tauri/data/bugcheck-codes.json',
      'src-tauri/data/uninstall-residue-rules.json', 'src-tauri/data/optimizer-runtime.json',
      'src-tauri/data/optimizer-runtime.json.sig.json'],
    contract: '规则库 ⇄ 签名 sidecar / capabilities 能力面 / bundle 清单',
    boundary: '生成物只进抽验清单（逐行读没意义），审的是签名链与源一致',
    gates: ['check-data-parity', 'check-cleanup-rule-contract', 'check-version-sync'],
  },
  {
    id: 'X1', owner: 'sub', name: '测试底座',
    dirs: [{ dir: 'src-tauri/tests' }],
    contract: 'common/mod.rs helper 单一真源 / ipc_smoke 回归网 / module_smoke',
    boundary: '只含主仓 tests/；域内 contract_tests.rs 归各域单元',
    gates: ['check-gate-roster'],
  },
];

/**
 * 主 agent 横切项（X0）：不属于任何目录，纵向单元审不了的东西。
 * X0-7…X0-10 是 v4 修复阶段四条真机回归的直接编码——它们当时在单元表里根本没有工位。
 */
export const CROSS_UNITS = [
  { id: 'X0-1', name: '跨层契约四处对账', how: 'generate_handler! ⇄ CHANNEL_MAP ⇄ 调用点 ⇄ capabilities；给「查了 N 条、命中 M 条、缺 K 条」' },
  { id: 'X0-2', name: '双源一致性', how: '同一张表的 JSON ⇄ 前端字面量 ⇄ 生成物；每对答「有没有门禁、能不能抓这种漂移」' },
  { id: 'X0-3', name: '全局数字漂移', how: 'readme 承诺与文档内数字 ⇄ 现算值；只贴命令与结果，不抄结论' },
  { id: 'X0-4', name: '跨窗与跨进程握手', how: '建窗、事件投递、提权握手、旧实例让位（两端在不同单元）' },
  { id: 'X0-5', name: '发版与产物面', how: '版本同步 / 产物新鲜度（cargo check 的 Finished 不算新鲜）/ 清单与资产双向对拍' },
  { id: 'X0-6', name: '跨单元观察池', how: '逐条回读原始坐标，按被观察者所属单元决定复审或结案' },
  { id: 'X0-7', name: '分槽与索引的键基数', how: '每张「按 X 分槽」的表逐条答「这一层的键唯一标识了什么」；合并前后维度必须等价（v4 真机：快照槽丢域维）' },
  { id: 'X0-8', name: '集合与基线的键稳定性', how: '键会不会被自己的写路径改动（重命名、加后缀、路径迁移、id 重算）（v4 真机：叶名重命名致计数清不掉）' },
  { id: 'X0-9', name: '形状与读器对拍', how: '每个 JSON 读写点 ⇄ 盘上真实形状（对象/裸数组/sidecar）；合法但形状不符 ≠ 损坏（v4 真机：数组文件被判 Corrupt）' },
  { id: 'X0-10', name: '并发写者图', how: '每个被读-改-写的文件列全部写点、是否共享同一把锁；原语内部的锁不保护域内自建台账' },
];

/**
 * 横向反模式单元：一条反模式 = 一个单元，全仓扫同族实例。
 * 授权边界（铁律 E 的第二类豁免）：只报「某坐标命中本判据」，不给域内修法、不评价该单元其他质量。
 * 动机：v4 的 111 条中危要手工收成 28 组，根因是缺陷按反模式分布而单元按目录切。
 */
export const ANTI_UNITS = [
  { id: 'A1', name: '三态不分（失败 / 确无结果 / 未配置）', how: '每个回执字段能否区分这三种，且渲染层消费口径能区分' },
  { id: 'A2', name: '未 catch 的 Promise 与软锁', how: '每个 await 的 reject 有无出口；「上锁之后、try 之前有 await」= 一次 reject 锁死整页' },
  { id: 'A3', name: '键盘与读屏可达性', how: '勾选框三属性 / 焦点环 / aria-live 宿主 / reduced-motion 归零覆盖面' },
  { id: 'A4', name: '注释与文档的清单型、数字型声称', how: '每条「N 个 / N 条 / N 步」有没有现算入口；无入口即腐烂候选' },
  { id: 'A5', name: '外部进程与句柄卫生', how: '裸子进程调用无超时 / 句柄未检 is_ok / 定长 UTF-16 整体解码 / .reg 按文本读' },
  { id: 'A6', name: '判定的字节 ≠ 执行的字节', how: '同一条链上「校验用的副本」与「真正用的原件」是否同源' },
];

/** 主 agent 四面（编排角色，不是路径认领单元；判据文本给文档与派单卡片引用）。 */
export const MAIN_FACES = [
  { id: 'M1', name: 'R6 红线真源自审', when: '第一批开工前' },
  { id: 'M2', name: 'X0 横切项（含 X0-7…X0-10）', when: '收齐分报告之后，最后跑' },
  { id: 'M3', name: '修法判据复核', when: '写修复方案时；被改判据的全量样本必须先现算' },
  { id: 'M4', name: '变更自审（X-REG）', when: '每批提交前，按 AGENTS §1.6 三问' },
];
