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
//   memory_kill · quickcmds_run · app_open_external · paths_browse ·
//   startup_openlocation · models_save / models_test / models_set_scope ·
//   fonts_import / fonts_remove_imported / fonts_save_config ·
//   log_write / log_export · paths_save · contextmenu_backup ·
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

import { readFileSync } from 'node:fs';
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
  'actions_open_window',  // v0.7.0：只有主窗入口按钮会调（副窗只调 close），同 residue_open_window 口径
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
  'cleanup_reg_backup_restore', // C-4：reg import 写注册表，只放主窗
  'cleanup_file_backup_restore', // C-4：文件备份拷回原路径（写面），只放主窗
  'cleanup_retry_failed_delete',
  'contextmenu_open_in_regedit', // v2-F6：会写 HKCU（Regedit\LastKey）且失败时 runas 弹 UAC
  'contextmenu_remove',
  'contextmenu_restart_explorer',
  'contextmenu_restore',
  'contextmenu_toggle',
  'contextmenu_win11_classic',
  'uninstall_report_get', // U-6：读批次报告，卸载域全档 MAIN 约定
  'uninstall_report_list', // U-6：同上
  'diskbench_run',
  'elevate_request', // AGENTS §3：提权入口只认主窗口 label
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
  'optimizer_list_groups', // E7 分类侧表：只被主窗优化页消费（D5 组判「只读档须有子窗消费方」⇒ 判 MAIN）
  'optimizer_touch_recent', // E10 最近使用写：主窗档
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
  'syspanel_pagefile_state',
  'syspanel_pagefile_apply',
];

// ---- 枚举所有 #[tauri::command] 及其档位 ----
// v3 D2：命令文件会再往下沉目录（commands/uninstall/*.rs），这里必须递归扫——
// 只扫一层等于「搬进子目录的命令自动退出档位台账」，那是假绿不是收敛。
// 相对 CMD_DIR 的正斜杠路径（下方按 join(CMD_DIR, f) 回拼绝对路径读文件）。
const files = walkRs(CMD_DIR).map((p) => relative(CMD_DIR, p).replace(/\\/g, '/'));
/** @type {Map<string, {file:string, tier:string|null, line:number}>} */
const tiers = new Map();

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

// ---- A2. 手写判定豁免双向棘轮 ----
// 统一 guard 会在拒绝时写日志（`guard.rs:29-32`），手写 `label() != "main"` 不会 ——
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
  'actions_close_window',  // v0.7.0：副窗自己关自己
  'actions_list',  // v0.7.0：副窗读清单与落点（无副作用）
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
  'contextmenu_backup', // 疑点：导出右键菜单备份到磁盘
  'contextmenu_blocked_list',
  'contextmenu_icons',
  'contextmenu_scan',
  'debug_data_dirs',
  'device_scan',
  'diag_dwm_conflict',
  'fileclean_read_image',
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
  'overview_checkup',
  'overview_hardware',
  'overview_metrics',
  'paths_app_icon',
  'paths_browse', // 疑点：起系统文件对话框
  'paths_file_icon',
  'paths_load',
  'paths_save', // 疑点：写路径配置
  'paths_scan',
  'preview_close_window',
  'preview_image_deleted',
  'preview_open_window',
  'process_manager_close_window',
  'process_manager_open_window',
  'process_manager_report',
  'quickcmds_run', // 疑点：起 cmd 执行系统命令
  'realtime_adapters',
  'realtime_loss',
  'realtime_report_clear', // 疑点：清实时报告
  'realtime_report_delete', // 疑点：删实时报告
  'realtime_report_get',
  'realtime_report_list',
  'realtime_report_save', // 疑点：写实时报告
  'realtime_sample',
  // v0.5.0 残留扫描副窗（label `residue`）：关窗由副窗自己调，属放行全窗的只读档；
  // 开窗只有主窗入口会调，落在 MUST_MAIN（D5 的判据：没有子窗调用点就不给放宽）
  'residue_close_window',
  'runtimes_collect',
  'settings_load',
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
  RESIDUE_WINDOWS: {
    labels: ['residue'],
    // v0.7.0 机-wide 扫描整条退役：dead-scan / orphan-scan / orphan-ignore / residue-deep-scan
    // 四条命令已删除，本集只剩「该应用四类残留扫描 + 执行 + 重启后删三件套」。
    cmds: [
      'uninstall_pending_add',
      'uninstall_pending_list',
      'uninstall_pending_revoke',
      'uninstall_residue_execute',
      'uninstall_residue_scan',
    ],
  },
  // v0.7.0 第四期：右键菜单动作面板的写侧（只写 HKCU，删除只走 TRIM. 前缀窄口子）
  ACTIONS_WINDOWS: {
    labels: ['actions'],
    cmds: ['actions_apply', 'actions_remove', 'actions_run_script'],
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
