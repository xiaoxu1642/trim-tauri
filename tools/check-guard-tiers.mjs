// check-guard-tiers.mjs —— IPC 来源校验档位门禁（审查 v2-F5）
//
// 为什么需要它：`capabilities/*.json` **不约束命令**（审查 v2-L1 实测 0/139 条应用命令
// 受其约束），命令级的唯一闸门就是每个命令体内那一次 `guard::guard*` 调用。而在本门禁
// 出现之前，15 条 Node 门禁 + `ipc_smoke` 里**没有一条**断言档位 —— 现场实跑全绿时
// F4（`settings_save` 写密钥却挂最宽档）与 F6（`open-in-regedit` 会写注册表 + 弹 UAC
// 却挂最宽档）两个错档完全隐形。
//
// 四组断言：
//   A. 覆盖率：每个 `#[tauri::command]` 都必须有来源校验调用；exempt 清单里的
//      （`app_first_paint`，见 F15）必须逐条登记理由。
//   B. 主窗档双向棘轮：`MUST_MAIN` 与实际判出的 MAIN 集合必须**完全相等** ——
//      只升不降或只降不升都会红，任何档位变动都必须同步改这张表并被 review 看见。
//   C. MAIN 档的调用形态必须是 `guard(&window, guard::MAIN)`（不允许出现
//      `guard_readonly` 与 MAIN 意图混写）。
//   D. 只读档双向棘轮（R1-1.2b，2026-10-03 补）：`MUST_READONLY` 与实际判出的
//      READONLY 集合必须完全相等。补这组是因为 **A/B/C 全都不管 readonly 档**——
//      详见 MUST_READONLY 上方那段注释描述的静默放宽路径。
//   E. MAIN 与 readonly 两张清单无交集（一条命令只能有一个档）。
//
// ==================== 已知档位疑点（2026-10-03 R1-1.2b 登记） ====================
// MUST_READONLY 是**现状如实登记**，不是背书。以下条目实测确有写/删/起进程副作用，
// 却挂在 readonly 档（放行全部五个窗口 label），逐条带「疑点」注释：
//
//   memory_kill · app_open_external · paths_browse ·
//   startup_openlocation · models_save / models_test / models_set_scope ·
//   fonts_import / fonts_remove_imported / fonts_save_config ·
//   log_write / log_export · paths_save ·
//   appearance_set_material / appearance_set_material_enabled ·
//   bench_history_add / bench_history_clear / bench_history_delete ·
//   realtime_report_save / realtime_report_clear / realtime_report_delete ·
//
// **本批刻意不改这些档位**。理由三条：
//   1. 改档会锁死或放开功能，是 AGENTS §3「M1~M3 教训」点名的方向性风险，必须先查
//      「谁真的需要调它」—— 多数条目可能只有主窗消费，但也有可能子窗在用（`modal_*`
//      那一类就是子窗专用）。查错方向就是 100% 功能不可用。
//   2. readonly 档并不等于「无害」：这四个子窗加载的脚本面比主窗窄，实际可利用性要
//      逐条看渲染层有没有消费方，属于另一轮审计的范围。
//   3. 本批的交付物是**棘轮**（让未来的放宽变红），把审档和补棘轮混在一批里会让审档
//      的结论被当成已定论—— 那正是 v0.5.0 `startType`「以为执行链是好的」那类事故的成因。
//
// 用法：node tools/check-guard-tiers.mjs [--update|--update readonly]
//   --update [readonly]：把当前实际判出的该档集合打印成可直接粘回本文件的清单
//     （维护用，不判红）。`--update` 等价于 `--update main`。
const UPDATE = process.argv.includes('--update')
  ? (process.argv[process.argv.indexOf('--update') + 1] === 'readonly' ? 'readonly' : true)
  : false;

import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';
import { walkRs } from './lib/fs-walk.mjs';

const CMD_DIR = join(REPO_ROOT, 'src-tauri', 'src', 'commands');


/**
 * 显式允许「不走统一 guard」的命令。
 *
 * 每条都必须写明理由与审查编号 —— 这张表是 A 组断言的唯一豁免口，
 * 空理由等于给自己留后门（审查 v1 M13「假绿」的前车）。
 */
const EXEMPT = {
  // 审查 v2-F15：139 条里唯一手写 `label() != "main"` 的命令，无高危副作用
  // （仅触发提前显窗）。留痕不一致已单独记 F15，此处只豁免「必须有 guard 调用」这一条。
  app_first_paint: 'v2-F15：手写 label 判定，无高危副作用；缺口是**留痕**不是档位',
};

/**
 * 必须是主窗档（guard::MAIN）的命令清单。
 *
 * 维护约定：改任何一条命令的档位，都必须同步改这张表 —— B 组断言是双向的，
 * 只改代码或只改表都会红。新增 MAIN 档命令时把名字加进来并写明理由。
 * 由 v2 审查现场枚举（138 条走 guard，其中 guard(MAIN) 35 条）+ 本轮 F4/F6 升档得出。
 */
const MUST_MAIN = [
  'appearance_bg_delete',
  'appearance_bg_import',
  'appearance_bg_list',
  'appearance_bg_open_dir',
  'cleanup_execute',
  // G-2 全局年龄策略：读写都只从主窗设置页发起（同 finder_ignore_* 三命令口径）
  'cleanup_age_policy',
  'cleanup_set_age_policy',
  // G-4（2026-10-07）回收站清空改 Shell API：查询条目数与体积（幂等只读，但消费方
  // 只有主窗清理页，按 AGENTS §3「没有子窗调用点就不给放宽」判 MAIN）、
  // 清空（不可逆破坏性动作，必须主窗专属）
  'cleanup_recycle_stats',
  'cleanup_empty_recycle_bin',
  // G-4 修订（2026-10-07）：回收站行「明细」= 打开系统回收站。幂等无写面，但
  // 消费方只有主窗清理页——同 cleanup_recycle_stats 口径判 MAIN。
  'cleanup_open_recycle_bin',
  'cleanup_kill_locked_processes',
  // C1-1（2026-10-16）：占用查询入口只在主窗磁盘清理页（内嵌卡片），按「谁真的需要
  // 调它」判 MAIN——比 readonly 紧；与 check-locked 的 readonly 不冲突（那条的候选
  // 来自扫描快照，子窗确认链也要用）。
  'cleanup_query_locked',
  'cleanup_reg_backup_restore', // C-4：reg import 写注册表，只放主窗
  'cleanup_file_backup_restore', // C-4：文件备份拷回原路径（写面），只放主窗
  'contextmenu_open_in_regedit', // v2-F6：会写 HKCU（Regedit\LastKey）且失败时 runas 弹 UAC
  // 2026-10-09（D3）：contextmenu_remove / contextmenu_restore 随右键删除链整链退役
  'contextmenu_restart_explorer',
  'contextmenu_toggle',
  'uninstall_report_get', // U-6：读批次报告，卸载域全档 MAIN 约定
  'uninstall_report_list', // U-6：同上
  'diskbench_run',
  'elevate_request', // AGENTS §3：提权入口只认主窗口 label
  'cleanup_allow_preview_assets', // 图片预览 asset 按需放行（主窗内嵌 LiteBox 的承接命令）
  'fileclean_delete_file', // 预览子窗退役后删除入口只剩主窗，档位 APP_WINDOWS → MAIN
  'fileclean_execute',
  'finder_delete',
  'finder_ignore_folder', // 2026-10-06 任务四：空目录忽略名单写侧（app_data 名单文件，只从主窗空目录页/名单弹窗触发）
  'finder_ignore_list',   // 同上：名单弹窗的读侧（只读语义但只有主窗消费方，同档 MAIN）
  'finder_ignore_remove', // 同上：名单移除（写侧）
  'maintenance_run',
  'memory_clean',
  // v2-H2：两条顽固软件治理命令会批量结束进程 / 改服务启动类型 + 删计划任务，
  // 后端不校验任何前端确认值，且只有主窗加载 memoryclean.js —— 必须锁为主窗档。
  'memory_stubborn_block',
  'memory_stubborn_kill',
  'netcheck_repair',
  'optimizer_backup_reg',
  'optimizer_create_restore',
  'optimizer_restore_frequency', // 2026-10-06：还原点弹窗「恢复默认创建频率」——写 HKLM，只从主窗弹窗触发
  'optimizer_restore_reg',
  'optimizer_run',
  'optimizer_list_groups', // E7 分类侧表：只被主窗优化页消费（check-channel-map D5 组判「只读档须有子窗消费方」⇒ 判 MAIN）
  'optimizer_touch_recent', // E10 最近使用写：主窗档
  'optimizer_bcd_enum', // C3 BCD 面板枚举：主窗永劫专项面板消费，档位 MAIN（同 optimizer_list_groups 的 check-channel-map D5 判据）
  'optimizer_external_scan', // 账外核对（2026-10-15）：只读但只被主窗优化页消费，判 MAIN（同 check-channel-map D5 判据）
  'optimizer_nara_panel', // C3 永劫专项面板侧表下发：主窗 optimizer 页消费，档位 MAIN（同 optimizer_list_groups 的 check-channel-map D5 判据）
  'optimizer_privacy_panel', // WinUtil 借鉴 V3 隐私自护面板侧表下发：主窗 optimizer 页消费，档位 MAIN（同上）
  'optimizer_stale_dismiss', // 2026-10-03 根治：「未完成还原」横幅的 per-id 忽略——写记账 prefs 段，优化页只在主窗
  // 2026-10-07：外设优化由独立子窗改为**主窗应用内弹窗**（src/scripts/peripheral.js），
  // label `peripheral` 退役，三条通道的唯一调用方变成主窗，档位由 APP_WINDOWS 升到 MAIN。
  'peripheral_query',
  'peripheral_apply',
  'peripheral_restore_backup',
  // 'pwsh_prepare' 已于 B11（2026-09-26）整链摘除，不再是一条命令
  // v0.5.0 残留扫描副窗：主窗入口按钮是唯一调用点（关窗侧在 MUST_READONLY）
  'residue_open_window',
  'runtimes_install',
  // 'settings_save' 已于 v2-F4 整链摘除（2026-09-26），不再是一条命令
  'startup_add',
  'startup_delete',
  'startup_open_source', // B-6 增强：定位登记来源（写 HKCU regedit LastKey + 拉起 regedit/explorer；主窗档）
  'startup_toggle',
  'updater_cancel_download',
  'updater_check',
  'updater_completion', // 读后即删的「更新已完成」标记：只有主窗首启要弹完成提示，不给子窗
  'updater_download',
  'updater_install',
  // updater_get_mirror / updater_set_mirror 已于 2026-10-06 随「更新线路」UI 整链退役
  // （顺序固化 AtomGit 国内源优先、GitHub 兜底，不再暴露选择）。
  // 卸载域 MVP（竞品借鉴落地方案 P0 §11）：卸载/残留执行是高危写操作，
  // 且只有主窗加载 uninstall.js —— 六条命令全档 MAIN。
  // 其中 check/update-residue 两条按「谁真的需要调它」定档（AGENTS §3 的 M1~M3 教训）：
  // 更新入口在卸载页（主窗），**不得**因为"检查版本看着像只读"就下放成放行四个子窗的档位。
  'uninstall_list',
  'uninstall_run',
  'uninstall_modify',
  // v0.7.0：残留链 8 条（三链扫描 / 执行 / 不再提示 / 重启后删除三件套）从 MAIN 迁到
  // **窄窗口集** `guard::RESIDUE_WINDOWS`，登记口在下面 MUST_WINDOWSET —— 面板整块搬进
  // residue 副窗后主窗不再调它们，留在 MAIN 会让副窗每次 IPC 判越权（§3 M1~M3）。
  'uninstall_dir_size',
  // D1 还原入口：列表也走 MAIN（与 restore 同一弹窗，没必要放行子窗），
  // restore 会 reg import 写注册表，必须主窗专属 + 危险确认。
  'uninstall_reg_backup_list',
  'uninstall_reg_backup_restore',
  // H1（2026-09-29）：还原包两个入口都只在主窗备份弹窗。list 与同门
  // uninstall_reg_backup_list 同档（子窗无消费方，按 readonly 放行等于白给目录列举面）；
  // restore 往磁盘写文件，档位方向写错会锁死功能（M1~M3 教训的反面）
  'uninstall_batch_list',
  'uninstall_batch_restore',
  // P2 §3.6（2026-10-03 RAINZ 对标）：系统面板三条 —— 电源方案写侧、系统级、
  // 只在主窗 settings 页有入口；pagefile_state 虽只读但同域同档，
  // 免得下一批加写侧时又要改档位（AGENTS §3 M1~M3 教训的"反向"：判档要看**下一批**会不会翻）。
  'syspanel_power_plan_get',
  'syspanel_power_plan_apply',
  // v5 P0：电源计划新建/导入/导出/删除与逐设置编辑会话；入口只在主窗 settings 页，
  // 写侧全部系统级，按 AGENTS §3「没有子窗调用点就不给放宽」判 MAIN。
  'syspanel_power_settings_dump',
  'syspanel_power_plan_duplicate',
  'syspanel_power_plan_rename',
  'syspanel_power_plan_delete',
  'syspanel_power_plan_import',
  'syspanel_power_plan_export',
  'syspanel_power_settings_unlock',
  'syspanel_power_settings_apply',
  'syspanel_power_settings_revert',
  'syspanel_power_settings_compare',      // v5 P2：跨方案对照读（只在主窗编辑器里触发）
  'syspanel_power_settings_open_regedit', // v5 P2：拉起 regedit 只从主窗编辑器触发
  // G-04（2026-10-16 裁定）：开启卓越性能 / 隐藏高性能 / 还原高性能 —— 写侧、系统级、
  // 只在主窗「Windows设置 → 电源计划」卡触发，无子窗调用点 ⇒ MAIN。
  'syspanel_power_ultimate_enable',
  'syspanel_power_hide_high_performance',
  'syspanel_power_restore_high_performance',
  'syspanel_pagefile_state',
  'syspanel_pagefile_apply',
  // v4-K04（2026-10-09）：quickcmds_run 从 readonly 升 MAIN —— 白名单里含
  // `sys-cmd-admin`（`Start-Process cmd -Verb RunAs`）：挂 readonly 档等于让子窗
  // 渲染层失陷即可弹 UAC、拿到管理员 CMD，等效提权出口按 §3「不得下放」。
  // 子窗消费面实测为 0（四份子窗 HTML 均未挂 quickcmds.js），改档零功能代价。
  'quickcmds_run',
  // R1a-M01（P1-W2）：paths:save 是唯一把「任意绝对路径」写进清理配置的渲染面，
  // 下游会按配置永久删除；子窗无消费方 ⇒ 按 AGENTS §3 判 MAIN（先移最重的一条）。
  'paths_save',
];

// ---- 枚举所有 #[tauri::command] 及其档位 ----
// v3 D2：命令文件会再往下沉目录（commands/uninstall/*.rs），这里必须递归扫——
// 只扫一层等于「搬进子目录的命令自动退出档位台账」，那是假绿不是收敛。
// 相对 CMD_DIR 的正斜杠路径（下方按 join(CMD_DIR, f) 回拼绝对路径读文件）。
const files = walkRs(CMD_DIR).map((p) => relative(CMD_DIR, p).replace(/\\/g, '/'));
/** @type {Map<string, {file:string, tier:string|null, line:number}>} */
const tiers = new Map();
/** @type {Map<string, string>} 命令名 → 命令体全文（group F 的判据面） */
const commandBodies = new Map();

for (const f of files) {
  const text = readFileSync(join(CMD_DIR, f), 'utf8');
  const lines = text.split('\n');
  const marks = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('#[tauri::command]')) marks.push(i);
  }
  for (let k = 0; k < marks.length; k++) {
    const start = marks[k];
    const end = k + 1 < marks.length ? marks[k + 1] : lines.length;
    let name = null;
    for (let j = start + 1; j < Math.min(start + 8, end); j++) {
      const m = lines[j].match(/pub\s+(?:async\s+)?fn\s+(\w+)/);
      if (m) { name = m[1]; break; }
    }
    if (!name) continue;

    let tier = null;
    let windowSetConst = null;
    for (let j = start; j < end && tier === null; j++) {
      const line = lines[j];
      // 顺序即判据：MAIN / readonly / APP_WINDOWS 全集先认，剩下才可能是「自定义窄窗口集」。
      // 窗口集分支必须留在 `tier === null` 之后 —— 早先把它写成独立语句时，
      // `guard::MAIN` 会被第二段 else-if 重判成 GUARD_OTHER，B 组当场 59 条全红。
      const cm = line.match(/guard::guard\(\s*&window,\s*guard::(\w+)\s*\)/);
      if (/guard::guard\(\s*&window,\s*guard::MAIN\s*\)/.test(line)) tier = 'MAIN';
      else if (/guard::guard_readonly\(/.test(line)) tier = 'READONLY';
      else if (/guard::guard\(\s*&window,\s*guard::APP_WINDOWS\s*\)/.test(line)) tier = 'APP_WINDOWS';
      // E 组（v0.7.0）：`guard(&window, guard::<某窗口集常量>)` —— 既不是 MAIN 也不是
      // 全集 readonly 的**窄窗口集**。抓住常量名，E2 再去 guard.rs 对拍成员。
      // 不认这一形态的话，「MAIN 改成任意窗口集」会落进 GUARD_OTHER 而两条棘轮都不红。
      else if (cm) {
        tier = 'WINDOWSET';
        windowSetConst = cm[1];
      } else if (/guard::guard\(/.test(line)) tier = 'GUARD_OTHER';
      // 手写 label 判定：`window.label() != "main"` 之外，也可能先取出 label 再比较
      // （`app_first_paint` 为写日志就是这样）。认 `.label()` 调用，避免改个写法就漏判。
      else if (/window\.label\(\)/.test(line)) tier = 'HANDWRITTEN';
    }
    tiers.set(name, { file: f, tier, line: start + 1, windowSetConst });
    commandBodies.set(name, lines.slice(start, end).join('\n'));
  }
}

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== IPC 来源校验档位门禁 ===\n');

if (UPDATE) {
  const which = UPDATE === 'readonly' ? 'READONLY' : 'MAIN';
  const listName = UPDATE === 'readonly' ? 'MUST_READONLY' : 'MUST_MAIN';
  const actual = [...tiers.entries()].filter(([, v]) => v.tier === which).map(([k]) => k).sort();
  console.log(`--update ${which}：当前实际 ${which} 档命令（共 ${actual.length} 条）\n`);
  for (const n of actual) console.log(`  '${n}',`);
  console.log(`\n（把上面这份替换进 ${listName}；本模式不判红）\n`);
  process.exit(0);
}

// ---- A1. 覆盖率：每条命令都必须做来源校验（手写 label 判定也算，但受 A2 约束） ----
const noGuard = [...tiers.entries()].filter(([, v]) => v.tier === null);
check(
  noGuard.length === 0,
  `A1. 全部 ${tiers.size} 条命令均有来源校验`,
  noGuard.length ? `缺校验 ${JSON.stringify(noGuard.map(([n, v]) => `${v.file}:${v.line} ${n}`))}` : '',
);

// T1a-L03：tiers 是从「#[tauri::command] 后 8 行内找 fn」抽出来的；抽不到会静默 continue。
// 这里用 generate_handler! 的实数钉住 tiers.size（登记网不能比注册网小）。
const handlerNames = (() => {
  const src = readFileSync(join(REPO_ROOT, 'src-tauri', 'src', 'lib.rs'), 'utf8');
  const m = src.match(/generate_handler!\[([\s\S]*?)\]/);
  if (!m) return new Set();
  return new Set(m[1].split(',').map((s) => s.trim().split('::').pop()).filter(Boolean));
})();
check(
  handlerNames.size > 0 && tiers.size === handlerNames.size,
  `A1b. 档位台账条数 ⇄ generate_handler! 注册条数（${tiers.size} / ${handlerNames.size}）`,
  tiers.size === handlerNames.size ? '' : `差 ${tiers.size - handlerNames.size} 条——名字抽取窗口失明或命令漏注册`,
);

// ---- A2. 手写判定豁免双向棘轮 ----
// 统一 guard 会在拒绝时写日志（`engine/guard.rs` 的 `guard()` 注释），手写 `label() != "main"` 不会 ——
// 静默拒绝会掩盖注入尝试，所以「不走统一 guard」必须是有意为之且被登记。
const handwritten = [...tiers.entries()].filter(([, v]) => v.tier === 'HANDWRITTEN').map(([k]) => k);
const unregistered = handwritten.filter((n) => !EXEMPT[n]); // 代码里手写了但清单没登记
const staleExempt = Object.keys(EXEMPT).filter(
  (n) => !tiers.has(n) || !['HANDWRITTEN', null].includes(tiers.get(n).tier),
); // 清单登记了但代码已改用统一 guard
check(
  unregistered.length === 0 && staleExempt.length === 0,
  `A2. 不走统一 guard 的命令逐条登记（豁免 ${Object.keys(EXEMPT).length} / 实际 ${handwritten.length}）`,
  unregistered.length
    ? `手写判定未登记 ${JSON.stringify(unregistered)}`
    : staleExempt.length
      ? `豁免清单已失效（已改用统一 guard，请移除）${JSON.stringify(staleExempt)}`
      : '',
);

// ---- B. 主窗档双向棘轮 ----
const actualMain = [...tiers.entries()].filter(([, v]) => v.tier === 'MAIN').map(([k]) => k).sort();
const wantMain = [...MUST_MAIN].sort();
const missing = wantMain.filter((n) => !actualMain.includes(n)); // 登记了但代码里不是 MAIN
const extra = actualMain.filter((n) => !wantMain.includes(n)); // 代码里是 MAIN 但没登记
const unknown = wantMain.filter((n) => !tiers.has(n)); // 清单里写了不存在的命令名
check(
  missing.length === 0 && extra.length === 0 && unknown.length === 0,
  `B. 主窗档清单与实际完全一致（清单 ${wantMain.length} / 实际 ${actualMain.length}）`,
  unknown.length
    ? `清单里有不存在的命令 ${JSON.stringify(unknown)}`
    : missing.length
      ? `应为 MAIN 实际不是 ${JSON.stringify(missing.map((n) => `${tiers.get(n)?.file}:${tiers.get(n)?.line} ${n}(${tiers.get(n)?.tier})`))}`
      : extra.length
        ? `实际是 MAIN 但清单未登记 ${JSON.stringify(extra)}`
        : '',
);

// ---- C. MAIN 档不能有 guard_readonly 混写 ----
const mixed = [...tiers.entries()].filter(([n, v]) => {
  if (!MUST_MAIN.includes(n) || v.tier !== 'MAIN') return false;
  const text = readFileSync(join(CMD_DIR, v.file), 'utf8').split('\n');
  const end = text.findIndex((l, i) => i > v.line && l.includes('#[tauri::command]'));
  const body = text.slice(v.line - 1, end < 0 ? text.length : end);
  return body.some((l) => /guard_readonly\(/.test(l));
});
check(
  mixed.length === 0,
  'C. MAIN 档命令体内无 guard_readonly 混写',
  mixed.length ? JSON.stringify(mixed.map(([n, v]) => `${v.file}:${v.line} ${n}`)) : '',
);

// ---- D. 只读档双向棘轮（R1-1.2b，2026-10-03） ----
// 为什么必须补这一组：A1 只查「有没有 guard」，A2 只管 HANDWRITTEN，B/C 只管 MAIN ——
// **`guard_readonly` 这一档此前没有任何一组断言在管**。后果是一条真实的静默放宽路径：
// 把某MAIN 命令改成 `guard_readonly`（来源校验从「只认主窗」放宽到「五个窗口 label 全放行」）
// **并且**顺手删掉它在 MUST_MAIN 的登记 ⇒ A1 仍绿（有 guard）、A2 不适用、B 因已删登记而不红、
// C 因已不是 MAIN 而不适用 —— 四组全部放行。
// 而 readonly 档的语义是「放行全部五个窗」，放宽它等于把主窗专属的写操作暴露给四个子窗。
//
// 口径与 B 组对称：代码里判 readonly 的命令集合 == 清单登记的集合，双向差集非空即红。
// 注意与 B 组的区别：B 组管「MAIN 档是谁」，本组管「**谁被放宽到了 readonly**」——
// 一条命令在这两组里只能出现一次，两组同时绿才说明档位没有被偷偷挪动。
const MUST_READONLY = [
  // ⚠️ 本清单是**现状如实登记**，不是背书。R1-1.2b 的目的是让「偷偷放宽到 readonly」
  // 变成门禁红，不是重新审一遍全部档位。带「疑点」注释的条目确有写/删/起进程副作用，
  // 却挂在 readonly 档（放行全部五个窗口 label）—— 逐条列在文件头「已知档位疑点」一节。
  // 本批**不改**这些档位：改档会锁死或放开功能，须按 AGENTS §3「档位以谁真的需要调它
  // 为准」的 M1~M3 教训单独评审。
  'aidesc_get',
  'app_get_info',
  'app_open_external', // 疑点：起浏览器/协议处理器
  'app_read_usage',
  'appearance_get_env',
  'appearance_get_material',
  'appearance_set_material', // 疑点：改窗口材质（写系统设置）
  'appearance_set_material_enabled', // 疑点：改窗口材质开关
  'bench_history_add', // 疑点：写测速历史
  'bench_history_clear', // 疑点：删测速历史
  'bench_history_delete', // 疑点：删测速历史
  'bench_history_list',
  'cleanup_check_locked',
  'cleanup_file_backup_list',
  'cleanup_item_detail',
  'cleanup_reg_backup_list',
  'cleanup_rules',
  'cleanup_scan',
  'contextmenu_icons',
  'contextmenu_scan',
  'debug_data_dirs',
  'device_scan',
  'diag_dwm_conflict',
  'fileclean_scan',
  'finder_delete_manifest',
  'finder_open_backup_dir',
  'finder_scan',
  'fonts_import', // 疑点：导入字体文件
  'fonts_list',
  'fonts_remove_imported', // 疑点：删已导入字体
  'fonts_save_config', // 疑点：写字体配置
  'intro_load',
  'log_export', // 疑点：导出日志到磁盘
  'log_read',
  'log_write', // 疑点：写日志文件
  'maintenance_tasks',
  'memory_info',
  'memory_kill', // 疑点：按 PID 结束进程
  'memory_processes',
  'modal_close',
  'modal_open',
  'models_close_window',
  'models_open_window',
  'models_save', // 疑点：写模型配置文件
  'models_set_scope', // 疑点：写模型作用域设置
  'models_test', // 疑点：起进程测连通性
  'netcheck_collect',
  'optimizer_batch_preflight',
  'optimizer_check_optimized',
  'optimizer_check_restore',
  'optimizer_genadvice',
  'optimizer_list',
  'optimizer_list_restore',
  'optimizer_state_overview',
  'optimizer_svc_mem_current',
  'overview_hardware',
  'overview_metrics',
  'paths_app_icon',
  'paths_browse', // 疑点：起系统文件对话框
  'paths_file_icon',
  'paths_load',
  // 'paths_save' 已按 R1a-M01 迁 MAIN（写路径配置会进入永久删链）。
  'paths_scan',
  'process_manager_close_window',
  'process_manager_open_window',
  'process_manager_report',
  'realtime_adapters',
  'realtime_loss',
  'realtime_report_clear', // 疑点：清实时报告
  'realtime_report_delete', // 疑点：删实时报告
  'realtime_report_get',
  'realtime_report_list',
  'realtime_report_save', // 疑点：写实时报告
  'realtime_sample',
  // v0.5.0 残留扫描副窗（label `residue`）：关窗由副窗自己调，属放行全窗的只读档；
  // 开窗只有主窗入口会调，落在 MUST_MAIN（check-channel-map D5 的判据：没有子窗调用点就不给放宽）
  'residue_close_window',
  'runtimes_collect',
  // P2-13：UI 偏好键读写迁后端真源（settings.json）。两命令都只碰 PREF_KEYS 白名单键，
  // 不含密钥面；挂 readonly 是因为消费方横跨窗口 —— 残留副窗要读写「删除前备份」开关、
  // 模型/进程副窗的玻璃引擎要读档位偏好。写侧只改 settings.json 自身的偏好段。
  'settings_get_prefs',
  'settings_load',
  'settings_set_pref',
  'startup_openlocation', // 疑点：打开资源管理器目录
  'startup_scan',
  'system_disk_list',
  'system_disk_type',
  'uninstall_appx_logo', // 疑点：写 logo 缓存文件
];
const actualReadonly = [...tiers.entries()].filter(([, v]) => v.tier === 'READONLY').map(([k]) => k).sort();
const wantReadonly = [...MUST_READONLY].sort();

// ==================== E 组：窄窗口集（v0.7.0，2026-10-05） ====================
//
// 为什么要有这一组：D 组把「MAIN → guard_readonly」这条静默放宽路径堵住了，但同一族的
// 另一条它管不到 —— 把 `guard(MAIN)` 改成 `guard(&window, guard::某个窗口集常量)`，
// 命令就同时离开 MUST_MAIN 与 MUST_READONLY 两张表，A 组只看「有没有 guard」照样绿。
// 残留链 8 条正是走这条形态（副窗要调、又不该给全集放行），所以判据必须**双向**登记：
//   E1 命令 ⇄ 表 ⇄ 实际档位三方集合完全相等；
//   E2 表里声明的成员标签 ⇄ engine/guard.rs 常量实体的成员**逐字相等**（顺序无关）；
//   E3 常量成员必须 ⊆ APP_WINDOWS（往常量里塞一个没在 capabilities 登记过的 label 即红）。
const MUST_WINDOWSET = {
  // 2026-10-13：清理域失败引导给主窗开了「登记重启后删除」的入口（写 PFRO 是永久删
  // 出口，窗口集从纯 residue 扩成 main+residue；models/processManager 无调用场景不放）。
  // 2026-10-18（v6-K13）：list/revoke 从 RESIDUE_WINDOWS 移入本集——待删清单对主窗
  // 清理域也要「可见可撤回」（主窗登记的条目在残留窗以外的路径上看不见 = 撤不回）。
  // add/list/revoke 三条同集；residue 的 scan/execute 仍独占 RESIDUE_WINDOWS。
  PENDING_DELETE_WINDOWS: {
    labels: ['main', 'residue'],
    cmds: [
      'uninstall_pending_add',
      'uninstall_pending_list',
      'uninstall_pending_revoke',
    ],
  },
  RESIDUE_WINDOWS: {
    labels: ['residue'],
    // v0.7.0 机-wide 扫描整条退役：dead-scan / orphan-scan / orphan-ignore / residue-deep-scan
    // 四条命令已删除；v6-K13 起 pending 三件套整体移入 PENDING_DELETE_WINDOWS，
    // 本集只剩「该应用四类残留扫描 + 执行」。
    cmds: [
      'uninstall_residue_execute',
      'uninstall_residue_scan',
    ],
  },
};

// 从 guard.rs 里把 `pub const X: &[&str] = &[...]` 的成员抠出来（现算，不抄静态数字）
const guardSrc = readFileSync(join(REPO_ROOT, 'src-tauri', 'src', 'engine', 'guard.rs'), 'utf8');
const constMembers = {};
for (const m of guardSrc.matchAll(/pub const (\w+): &\[&str\] = &\[([^\]]*)\];/g)) {
  constMembers[m[1]] = [...m[2].matchAll(/"([^"]+)"/g)].map((x) => x[1]).sort();
}
const appWindowsSet = constMembers.APP_WINDOWS || [];

const actualWindowset = [...tiers.entries()].filter(([, v]) => v.tier === 'WINDOWSET');
const wsTableCmds = Object.entries(MUST_WINDOWSET).flatMap(([k, v]) => v.cmds.map((c) => `${c}@${k}`)).sort();
const wsActualCmds = actualWindowset.map(([n, v]) => `${n}@${v.windowSetConst}`).sort();
const wsUnknown = wsTableCmds.filter((s) => !tiers.has(s.split('@')[0]));
check(
  wsUnknown.length === 0 && wsTableCmds.length === wsActualCmds.length
    && wsTableCmds.every((s, i) => s === wsActualCmds[i]),
  `E1. 窄窗口集档位清单与实际完全一致（登记 ${wsTableCmds.length} / 实际 ${wsActualCmds.length}）`,
  wsUnknown.length
    ? `表里登记了不存在的命令 ${JSON.stringify(wsUnknown)}`
    : `差异 ${JSON.stringify({ 只在表里: wsTableCmds.filter((s) => !wsActualCmds.includes(s)), 只在代码: wsActualCmds.filter((s) => !wsTableCmds.includes(s)) })}`,
);

for (const [konst, spec] of Object.entries(MUST_WINDOWSET)) {
  const members = constMembers[konst];
  check(!!members, `E2a. engine/guard.rs 里找得到常量 ${konst}`, members ? '' : '改名/删除必须同步本表');
  if (!members) continue;
  const want = [...spec.labels].sort();
  const eq = want.length === members.length && want.every((v, i) => v === members[i]);
  check(eq, `E2b. ${konst} 成员与登记完全相等`, `登记 ${JSON.stringify(want)} ⇄ 代码 ${JSON.stringify(members)}`);
  const alien = members.filter((lbl) => !appWindowsSet.includes(lbl));
  check(alien.length === 0, `E3. ${konst} 的每个 label 都在 APP_WINDOWS 内`, alien.length ? `多出来 ${JSON.stringify(alien)}（capabilities/subwindows.json 里没有它，IPC 必判越权）` : '');
}

// ==================== H 组：APP_WINDOWS ⇄ capabilities/*.json 并集（R8-L03） ====================
// 为什么必须双向：`APP_WINDOWS` 多一个 capabilities 里没有的 label ⇒ 窗口建得出来、
// 每次 IPC 判越权；capabilities 多一个 `APP_WINDOWS` 里没有的 label ⇒ 权限清单给了一个
// 不在册的窗口（或被删窗口的残留权限）。此前三个在册脚本都只做单向/子集判定，
// 「新增子窗只同步了两处（guard.rs / capabilities）」这类漏项没有一道门禁能抓到。
{
  const capDir = join(REPO_ROOT, 'src-tauri', 'capabilities');
  const capLabels = new Set();
  for (const f of readdirSync(capDir).filter((n) => n.endsWith('.json'))) {
    const j = JSON.parse(readFileSync(join(capDir, f), 'utf8'));
    for (const w of j.windows ?? []) capLabels.add(String(w));
  }
  const onlyGuard = appWindowsSet.filter((l) => !capLabels.has(l));
  const onlyCap = [...capLabels].filter((l) => !appWindowsSet.includes(l)).sort();
  check(
    onlyGuard.length === 0 && onlyCap.length === 0,
    `H. APP_WINDOWS ⇄ capabilities windows 并集双向一致（${appWindowsSet.length} / ${capLabels.size}）`,
    onlyGuard.length
      ? `只在 APP_WINDOWS 里 ${JSON.stringify(onlyGuard)}（窗口建得出来但每次 IPC 判越权）`
      : onlyCap.length
        ? `只在 capabilities 里 ${JSON.stringify(onlyCap)}（权限清单给了不在册/已退役的窗口）`
        : '',
  );
}
const roMissing = wantReadonly.filter((n) => !actualReadonly.includes(n));
const roExtra = actualReadonly.filter((n) => !wantReadonly.includes(n));
const roUnknown = wantReadonly.filter((n) => !tiers.has(n));
check(
  roMissing.length === 0 && roExtra.length === 0 && roUnknown.length === 0,
  `D. 只读档清单与实际完全一致（清单 ${wantReadonly.length} / 实际 ${actualReadonly.length}）——放宽来源校验必须被看见`,
  roUnknown.length
    ? `清单里有不存在的命令 ${JSON.stringify(roUnknown)}`
    : roMissing.length
      ? `登记为只读但代码不是 ${JSON.stringify(roMissing.map((n) => `${tiers.get(n)?.file}:${tiers.get(n)?.line} ${n}(${tiers.get(n)?.tier})`))}`
      : roExtra.length
        ? `代码判只读但清单未登记 ${JSON.stringify(roExtra)}`
        : '',
);

// ---- E. 两档不许互相登记（防止 MAIN 与 readonly 同时出现在两张表里） ----
// 上面两组各自双向都够，但「同一条命令被登记进两张表」这种错误两组都能放过：
// B 组只查 MAIN 集合，MUST_READONLY 里多一条 MAIN 命令不会被 D 组抓到
//（D 组查的是 readonly 集合，MUST_MAIN 的名字出现在那里不影响）。
// 一条命令只能有一个档，两个表同时登记它就是自相矛盾。
const inBoth = MUST_MAIN.filter((n) => MUST_READONLY.includes(n));
check(
  inBoth.length === 0,
  'E. MAIN 与只读两张清单无交集',
  inBoth.length ? `同时登记在两张表里 ${JSON.stringify(inBoth)}` : '',
);

// ---- F. runas ⇒ 必须 MAIN 档（P3-5，R1-G-4） ----
// 命令体内出现 runas（ShellExecuteW 的提权动词 / `-Verb RunAs`）⇒ 等效提权出口 ——
// 挂 readonly 档等于让子窗渲染层失陷即可弹 UAC（AGENTS §3「不得下放」）。
// 现算靶心三条：elevate_request / contextmenu_open_in_regedit / quickcmds_run。
{
  const runasCmds = [];
  const wrongTier = [];
  for (const [name, body] of commandBodies) {
    if (!/runas/i.test(body)) continue;
    runasCmds.push(name);
    if (!MUST_MAIN.includes(name)) wrongTier.push(`${name}（${tiers.get(name)?.file}:${tiers.get(name)?.line}）`);
  }
  check(
    runasCmds.length >= 3,
    `F. 命令体含 runas 的 ${runasCmds.length} 条（≥3 为地板，防语料失明）`,
    runasCmds.length < 3 ? 'runas 判定器疑似失明' : runasCmds.join(', '),
  );
  check(
    wrongTier.length === 0,
    'F2. 含 runas（等效提权出口）的命令全部登记 MAIN 档',
    wrongTier.length ? `未升档：${JSON.stringify(wrongTier)}` : '',
  );
}

// ---- G. 全集档与其它 guard 形态的双向棘轮（v6-K19） ----
// 为什么必须补：A1 只看「有没有 guard」，A2 只管 HANDWRITTEN，B/C 只管 MAIN，D 管
// READONLY，E 管 `guard::<窗口集常量>` —— 剩下两档**此前没有任何一组在管**：
//   · `guard(&window, guard::APP_WINDOWS)`（五窗全集）：把一条 MAIN 命令改成它、
//     并顺手删掉 MUST_MAIN 登记 ⇒ A1 仍绿、A2 不适用、B 因已删登记而不红、
//     C/E 不适用 —— 来源校验从「只认主窗」静默放宽到「五窗全放行」；
//   · `guard(&window, <任意内联数组>)`（GUARD_OTHER）：新出口可以完全绕开三张清单。
// 口径（K19 原文「要么有登记表，要么出现即红」）：两张表都必须与实况**完全一致**，
// 空表即「出现即红」。当前两档实况均为 0 条，所以两张表是空的——这是有意的，
// 不是漏登记。
const MUST_APP_WINDOWS = [];
/** 其它 guard 形态的登记表：元素 { name, reason }；空表 = 出现即红 */
const GUARD_OTHER = [];
{
  const actualAW = [...tiers.entries()].filter(([, v]) => v.tier === 'APP_WINDOWS').map(([k]) => k).sort();
  const wantAW = [...MUST_APP_WINDOWS].sort();
  const awMissing = wantAW.filter((n) => !actualAW.includes(n));
  const awExtra = actualAW.filter((n) => !wantAW.includes(n));
  const awUnknown = wantAW.filter((n) => !tiers.has(n));
  check(
    awMissing.length === 0 && awExtra.length === 0 && awUnknown.length === 0,
    `G1. APP_WINDOWS 全集档清单与实际完全一致（登记 ${wantAW.length} / 实际 ${actualAW.length}；空表=出现即红）`,
    awUnknown.length
      ? `清单里有不存在的命令 ${JSON.stringify(awUnknown)}`
      : awMissing.length
        ? `登记为全集但代码不是 ${JSON.stringify(awMissing)}`
        : awExtra.length
          ? `代码放行全集但清单未登记 ${JSON.stringify(awExtra.map((n) => `${tiers.get(n)?.file}:${tiers.get(n)?.line} ${n}`))}`
          : '',
  );
  const actualOther = [...tiers.entries()].filter(([, v]) => v.tier === 'GUARD_OTHER').map(([k]) => k).sort();
  const wantOther = GUARD_OTHER.map((e) => e.name).sort();
  const otherMissing = wantOther.filter((n) => !actualOther.includes(n));
  const otherExtra = actualOther.filter((n) => !wantOther.includes(n));
  check(
    otherMissing.length === 0 && otherExtra.length === 0,
    `G2. GUARD_OTHER 形态逐条登记（登记 ${wantOther.length} / 实际 ${actualOther.length}；空表=出现即红）`,
    otherMissing.length
      ? `登记了但代码已不是该形态 ${JSON.stringify(otherMissing)}`
      : otherExtra.length
        ? `未登记的其它 guard 形态 ${JSON.stringify(otherExtra.map((n) => `${tiers.get(n)?.file}:${tiers.get(n)?.line} ${n}`))}`
        : '',
  );
}

// ---- 统计报告（不判红） ----
const byTier = {};
for (const [, v] of tiers) byTier[v.tier ?? 'NONE'] = (byTier[v.tier ?? 'NONE'] ?? 0) + 1;
console.log('\n档位分布：' + Object.entries(byTier).map(([k, v]) => `${k}=${v}`).join('  '));

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 组断言未通过`);
  process.exit(1);
}
console.log('档位门禁全部通过');
