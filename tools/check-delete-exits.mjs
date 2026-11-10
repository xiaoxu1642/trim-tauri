#!/usr/bin/env node
// check-delete-exits.mjs —— 删除/破坏性出口枚举门禁（v2 方案批次 D1，2026-10-01）
//
// 为什么要有这条：2026-10-01 复核（v2 报告 §3.1 / V-4）抓到 `uninstall:pending-add`
// ——基线内新增的永久删出口没进审查矩阵，且缺 `is_path_protected` 与批量上限。
// 根因是出口清单靠人工维护：新命令落地时没人记得往矩阵里加一行。这条门禁把
// 「新命令没进矩阵」从审查纪律变成机检断言。
//
// 三层断言（fail-closed，新面孔默认可疑）：
//   1. 命令清单由 `lib.rs::generate_handler!` 派生（唯一真源），每个命令的函数体
//      在 src-tauri/src 下定位并做删除 API 扫描；
//   2. 函数体命中删除标记（Win32/std 删除 API + 引擎删除函数）却不引用
//      `is_path_protected` 的，必须在 EXEMPTS 注册**带理由**的豁免——「注册制」，
//      不是白名单：新出口默认红，想放行就得写清为什么不需要这道闸；
//   3. MUST_PROTECT 正向清单（审查矩阵逐列核过的文件型删除出口）反向断言：
//      谁把 protect 判定删了，这里判红——双向棘轮，防「既有出口悄悄掉闸」。
//
// 局限（如实声明）：函数体扫描看不到「命令 → 引擎函数 → 删除」的二跳委托，
// 引擎删除函数名单（ENGINE_DELETE_FNS）就是为补这层视差维护的；新增引擎级删除
// 函数时必须同步本清单，否则委托型出口不会被扫描网捕获。
//
// 用法：node tools/check-delete-exits.mjs
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { walkRs } from './lib/fs-walk.mjs';
import { blankNonCode } from './lib/src-scan.mjs';
import { DELETE_APIS as DELETE_MARKERS } from './lib/delete-apis.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src-tauri');
let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

// ---- 删除标记：唯一真源 tools/lib/delete-apis.mjs（T1a-M07，与 callsites 共用） ----
// 本门禁按**命令体**扫描（generate_handler! 派生），native-scanner 没有命令体；
// 其 Shell 级删除出口由 check-delete-callsites 的同一名单覆盖，不在这里重复造网。

// ---- 豁免注册制：命中删除标记但**不该**走 is_path_protected 的出口，逐条带理由 ----
// 新增条目必须回答「为什么文件面 protect 不适用」；没有理由的豁免等于拆门禁。
// （首跑 2026-10-01 发现网抓到 realtime/fonts 四条自有数据目录出口，逐一核实后在此
//   登记；optimizer_apply 为矩阵旧称——真命令 optimizer_run 体内无删除标记，无需豁免；
//   prune_quarantined 是启动期内部函数非命令，命令级门禁罩不住，由 security 自检管。）
//
// T1a-L13：豁免此前是**命令级**的 —— 已豁免命令体里再长出删除调用（新文件面）不会红。
// 现在每条豁免同时登记**删除 API 的现算计数**（`apis`），与命令体逐 API 对拍：加一处、
// 换 API、删一处都要回来改计数（棘轮方向：只许同步台账，不许静默扩面）。
// PS 文本删除（`Remove-Item` / `reg delete` / `cmd del`）不在本网：`pssteps::compile` 只接受
// 注册表路径（pssteps.rs），内联脚本的文件删除归属 check-ps-callsites 的调用点登记表
// （run_inbox_script 逐点登记）+ 人工评审，不在这里重复造网。
const EXEMPTS = new Map([
  // 注册表/启动项出口：注册表无文件路径语义，闸门是注册表禁删面与白名单目标
  ['startup_delete', { apis: { send_to_trash_os: 1, startup_delete: 2 }, why: '注册表项/启动文件夹快捷方式删除，闸门=native::startup_delete 白名单目标，非文件 protect' }],
  // 自有报告目录：report_path() 已做 basename 化 + .json 后缀白名单防路径穿越；
  // protect 清单整含 app_data_dir，对自有数据目录恒拒、无判定意义
  ['realtime_report_delete', { apis: { remove_file: 1 }, why: '保留永久删：删 Trim 自有网速报告（app_data_dir/report），basename+.json 白名单防穿越，非用户内容' }],
  ['realtime_report_clear', { apis: { remove_file: 1 }, why: '保留永久删：清空自有报告目录内 *.json，目录固定+后缀白名单，非用户内容' }],
  // v2-L4P-12（B-1）：backgrounds 住在 app_data_dir() 里，而 configure_from_app 把
  // app_data_dir() 整棵登记为 subtree ⇒ is_path_protected 恒拒，功能完全不可用。
  // 闸门收口为四件套（见命令体注释），故从 MUST_PROTECT 挪入豁免并写明依据：
  ['appearance_bg_delete', { apis: { send_to_trash_os: 1 }, why: '仅删 backgrounds 直接子项：父目录归属校验 + 扩展名白名单 + is_reparse 拒 + 回收站 _os；文件面 protect 对自有数据目录恒拒无判定意义' }],
  // S3（2026-10-05）更新完成标记：路径是 `paths::join_data("update-applied.json")` ——
  // 一个 Trim 自己写的单文件标记名，既不是用户内容也不接受任何外部输入（命令体里没有
  // 路径参数），protect 对它恒拒（app_data_dir 整棵是 subtree）反而会让功能完全不可用，
  // 所以按 realtime_report_delete 那条例外姿势登记，不套一层无意义的闸门。
  ['updater_install', { apis: { remove_file: 1 }, why: '安装失败时清掉 Trim 自写的 update-applied.json 标记（文件名常量，无外部输入）；protect 对自有数据目录恒拒无判定意义' }],
  ['updater_completion', { apis: { remove_file: 1 }, why: '读后即删同一份 update-applied.json 标记（防「更新已完成」提示反复弹）；另经 clean_installer 删**下载目录里我们自己存的那份安装包**——路径取自标记，删除前过「文件名必须是 Trim_<版本>_x64-setup.exe 形状 + 父目录必须等于 %USERPROFILE%\\Downloads」双闸，不合形状直接不碰文件' }],
  // v2-L4P-27（B-5）：fonts_import 旧副本删除补齐归属校验后的口径说明由代码兑现；
  // 豁免理由不变（只删自有副本目录内目标）。
  // G-4（2026-10-07）：清空回收站走系统 Shell API（SHEmptyRecycleBinW），**没有路径参数**
  // ——它作用于「所有盘的回收站」这一系统实体，文件面 is_path_protected 无从判定。
  // 本次改动的真实闸门是三条，逐条列出（缺一条这条豁免就不成立）：
  //   ① 主窗档 `guard(&window, guard::MAIN)`（不可逆动作不给四个子窗放行）；
  //   ② 渲染层红色高危确认 `confirmDanger`，且确认文案里带**清空前的条目数与体积**
  //      （cleanup:recycle-stats 现查，不是扫描占位行的 0）；
  //   ③ 条目 `domain == "special"` ⇒ 永不默认勾选（cleanup.js 的默认勾选分支显式跳过）。
  ['cleanup_empty_recycle_bin', { apis: { SHEmptyRecycleBinW: 1 }, why: '清空回收站（SHEmptyRecycleBinW）作用于系统回收站整体、无路径参数，protect 不适用；闸门=主窗档 + 渲染层红色高危确认（含条目数/体积）+ special 域默认不勾选' }],
  // T1a-M07：`reg_import_apply` 并入统一名单后暴露的两条还原命令——它们写回的是
  // 已过四道闸的注册表 sections（严格解析 / 受保护面 / 封条核对 / HKLM 提权），
  // 文件面 is_path_protected 对注册表键没有判定语义。
  ['uninstall_reg_backup_restore', { apis: { reg_import_apply: 1 }, why: '注册表备份还原：reg_backup_restore_guards 四道闸，执行臂吃同一份 sections；文件面 protect 不适用' }],
  ['cleanup_reg_backup_restore', { apis: { reg_import_apply: 1 }, why: '同上——清理域与卸载域共用同一 reg_backup_restore_guards 公共件；删除函数指针在命令体的 spawn_blocking 闭包内传入，实际执行仍在 blocking helper' }],
]);

// ---- 正向清单：审查矩阵逐列核过的文件型删除出口，protect 判定不许掉 ----
// 审查 L-4（2026-10-03）补入 optimizer_run：@@RECYCLE@@ 回收站出口的 protect 调用就在
// apply.rs 命令体内（现算行号：rg -n "is_path_protected" src-tauri/src/commands/optimizer/apply.rs），此前只靠第 3 组「恰好 includes is_path_protected」放行
// ——谁删掉那行，门禁不会红。进正向清单后「掉闸即红」。
const MUST_PROTECT = [
  'fileclean_delete_file',
  'fileclean_execute',
  'finder_delete',
  'optimizer_run',
  'uninstall_residue_execute',
  // 2026-10-09（D3）：contextmenu_remove 随右键删除链整链退役，从正向清单摘除
  // （cm_remove 与其 RegDeleteTreeW/回收站出口一并删除；toggle 不删文件）。
];
// T1a-M19：正向清单本身无地板 ——「新出口默认红」只拦添加方向、不拦拆台账方向
//（探针 P6：清单清空 ⇒ 1b/1c/2 三组计数全 0 仍绿）。钉住规模，拆台账即红。
// 2026-11-02：`uninstall_pending_add` 随「登记重启后删除」注册入口退役（用户裁定），
// 清单由 6 → 5，地板同步下调 —— 属逐条给出的退役理由，不是拆台账。
  check(MUST_PROTECT.length >= 5, `1a. 正向清单 MUST_PROTECT 规模地板（现算 ${MUST_PROTECT.length} 条 ≥ 5；T1a-M19）`,
  MUST_PROTECT.length < 5 ? '清单被拆 ⇒ 1b/1c/2 三组判定对象一起消失（假绿），拆动必须逐条给理由' : '');

// C01（v7.2）：保护闸的两种在位形态。v7.2 之后出口闸收口到
// `protect::validate_mutation_target`（组合闸：受保护面→别名面→系统面→reparse），
// 命令体里出现组合闸调用 = 受保护面在位（组合闸内部必调 is_path_protected，
// 由下方 C01 断言组钉死组合闸本身不许掉闸）。
const PROTECT_MARKERS = ['is_path_protected', 'validate_mutation_target'];
function markerPropagates(body, marker) {
  const re = new RegExp(`\\b${marker}\\s*\\(`, 'g');
  let match;
  while ((match = re.exec(body)) !== null) {
    const idx = match.index;
    const before = body.slice(Math.max(0, idx - 200), idx);
    if (/\blet\s+_\s*=\s*(?:\w+::)*\s*$/.test(before)) continue;
    const tail = body.slice(idx, Math.min(body.length, idx + 500));
    if (/\)\s*\?/.test(tail.slice(0, 120))) return true;
    const brace = tail.indexOf('{');
    if (brace >= 0) {
      const block = tail.slice(brace, brace + 300);
      if (/^\{\s*\}/.test(block)) continue;
      if (/\breturn\b|\bcontinue\b/.test(block)) return true;
      if (/\bif\b|\bmatch\b/.test(before.slice(-120))) return true;
    }
    if (/\bif\s+!/.test(before + tail.slice(0, 120))) return true;
    if (/\belse\s*\{/.test(before + tail)) return true;
  }
  return false;
}
const bodyHasProtect = (body, markers = PROTECT_MARKERS) =>
  (Array.isArray(markers) ? markers : [markers]).some((m) => markerPropagates(body, m));

// 二跳出口的正向棘轮（审查 L-4）：protect 不在命令体内、而在本仓 helper 里。
// 登记 {命令, helper}，钉住 helper 体内的 protect 调用——helper 改名/protect 被删/
// 搬出 src 均红。（2026-10-12：原首条 cleanup_retry_failed_delete /
// retry_failed_delete_blocking 随回收站重试链整链退役撤除。）
//
// ⚠️ 第三段 `file` 是 2026-10-04 磁盘清理审计 §2.1 补的，且**不是可选的锦上添花**：
//
//   已修：见 `MUST_PROTECT_VIA_HELPER` 第三段 `file=src/engine/native/cleanup.rs`。
//   命令体与引擎函数同名，登记表指名文件后由 2b 钉住 helper 体内的保护判定；
//   第三段相对 src-tauri，ROOT 就是 src-tauri。
const MUST_PROTECT_VIA_HELPER = [
  // 2026-10-09（v4-K09 修复）：cleanup_execute 拆出薄包装——删前备份根需要可注入
  // （三个端到端用例的备份副本原先写进用户真实数据目录），实现体搬进
  // `cleanup_execute_with_backup_root`，`cleanup_execute` 退化为一行转发。protect 闸随
  // 实现体移动，本表 helper 名同步跟随；该函数再改名/搬走时 2b 依旧判红。
  ['cleanup_execute', 'cleanup_execute_with_backup_root', 'src/engine/native/cleanup.rs'],
  // R1b-M02（v7.2 C01）：外设备份修剪此前整体在本发现网之外——prune_backups 是独立
  // fn，命令体扫描看不到二跳委托，护栏被动过零告警。它的闸不是文件面 protect
  // （裁根是固定的 backup_write_dir 单根，protect 对自有数据目录恒拒无判定意义），
  // 而是 reparse 拒 + 封条同生同死 ⇒ 第四段指名本行的必须标记（2b 支持自定义）。
  ['peripheral_apply', 'prune_backups', 'src/commands/peripheral.rs', 'is_reparse'],
  // P2/R1b-L10（字体导入三段式）与 R1b-L11（命名空间闸先于触盘）之后，
  // 字体导入的删旧副本动作搬进了 `stage_font_import`（命令体只调它），
  // 且真正的删除原语在 `remove_owned_font_copy`（归属 + reparse + 回收站）。
  // 命令体扫描看不到二跳委托 ⇒ 登记进本表，闸门由 2b 钉在 helper 体内。
  ['fonts_import', 'stage_font_import', 'src/commands/fonts.rs', 'remove_owned_font_copy'],
  ['fonts_remove_imported', 'remove_owned_font_copy', 'src/commands/fonts.rs', 'is_reparse'],
];

// ==================== C01 断言组（v7.2 R1d-K01/R2a-M01/R3-M03/R4-M01/R1b-M02） ====================
// 判定器全部抽成纯函数，与下方 POSITIVE_CONTROLS 的合成样本共用同一实现。

/** C01-a/b：组合闸本体必须四闸俱全、且不得含任何删除/写回原语（只判定不执行）。 */
function judgeValidatorBody(body) {
  const issues = [];
  for (const gate of ['is_path_protected', 'final_path_protected', 'is_system_namespace', 'is_reparse']) {
    if (!body.includes(gate)) issues.push(`组合闸缺 ${gate} 闸`);
  }
  // 方案 C01 红线：函数不执行删除/写回、不收 to_recycle——共同判据吞掉四个
  // 破坏性出口的显式动作类型即红。
  const forbidden = [...DELETE_MARKERS, 'std::fs::copy', 'to_recycle'];
  for (const f of forbidden) {
    if (body.includes(f)) issues.push(`共同判据体内出现 ${f}（只判定不执行，出口语义不许被吞）`);
  }
  return issues;
}

/** C01-c：成对棘轮——文件面产源/出口文件里 is_path_protected 与 is_system_namespace 必须共现。 */
function judgeProtectPair(src) {
  const issues = [];
  if (src.includes('is_path_protected') && !src.includes('is_system_namespace')) {
    issues.push('有 is_path_protected 却无 is_system_namespace——%WINDIR% 子孙会穿过保护面（两闸必须成对）');
  }
  return issues;
}

/** T1a-M01：成对对象按「两闸都出现的文件」计数；只数文件数会让 0 对也打 ✓。 */
function countProtectPairs(src) {
  const n = (re) => (src.match(re) ?? []).length;
  return Math.min(n(/\bis_path_protected\s*\(/g), n(/\bis_system_namespace\s*\(/g));
}

// 审查 L-5（2026-10-03）二跳盲区登记（只登记不改，按白名单纪律）：
// diskbench_run 的 remove_dir_all 住在 helper cleanup_residue 里，命令体不含删除标记，
// 不进本门禁扫描网。**已有防护**：cleanup_residue 前置 dir_delete_blocked（属性位逐层查）。
// 若该 helper 的防护被动过，须回本门禁补扫描口径，而不是依赖这条注释。

// ---- 1. 命令清单：generate_handler! 派生 ----
const libSrc = fs.readFileSync(path.join(ROOT, 'src', 'lib.rs'), 'utf8');
const handlerBlk = libSrc.match(/generate_handler!\[([\s\S]*?)\]/);
if (!handlerBlk) {
  console.error('✗ lib.rs 中找不到 generate_handler![...] —— 门禁失去真源，直接判红');
  process.exit(1);
}
const commands = [...new Set(handlerBlk[1].split(',').map((s) => s.trim().split('::').pop()).filter(Boolean))];
console.log(`=== 删除出口枚举门禁 ===\n命令清单（generate_handler! 派生）：${commands.length} 条\n`);

// ---- 2. 函数体定位（命令名 → {file, body}） ----
const srcFiles = walkRs(path.join(ROOT, 'src'));

// v2-L4P-31（E-6 同族）：剥离 Rust 注释与字符串字面量后再做标记匹配。实测教训：
// appearance_bg_delete 的说明注释里写了 API 名，`body.includes()` 被注释文本洗白——
// 状态机剥除（处理块注释/行注释/字符串/字符/生存期撇号）后，断言只看真实代码。

function extractBody(name) {
  // T1a-M20：同名 fn 跨文件（现算多条命令同名，如 cleanup_execute 在命令层与引擎层）
  // 且 readdir 原生序 ≠ 排序序 ⇒ 取首个命中是机器相关行为。先按 #[tauri::command]
  // 属性收敛到命令层；过滤后仍歧义即红，不许静默选一个（引擎体里被删的 protect 看不见）。
  const hits = [];
  for (const file of srcFiles) {
    if (new RegExp(`\\bfn\\s+${name}\\s*[<(]`).test(fs.readFileSync(file, 'utf8'))) hits.push(file);
  }
  if (hits.length > 1) {
    const cmdHits = hits.filter((f) => /#\[tauri::command\]/.test(fs.readFileSync(f, 'utf8')));
    if (cmdHits.length !== 1) {
      check(false, `extractBody 歧义：fn ${name} 同名 ${hits.length} 处且属性过滤后 ${cmdHits.length} 处（T1a-M20）`,
        hits.map((f) => path.relative(ROOT, f).replace(/\\/g, '/')).join('、'));
      return null;
    }
    hits.length = 0;
    hits.push(cmdHits[0]);
  }
  const file = hits[0];
  if (!file) return null;
  const src = fs.readFileSync(file, 'utf8');
  const re = new RegExp(`\\bfn\\s+${name}\\s*[<(]`);
  const m = src.match(re);
  // 从 fn 起始做花括号配平（在剥离注释/字符串后的文本上做，防止字符串里的
  // 花括号截断函数体——E-6 的判绿方向风险）
  const clean = blankNonCode(src);
  const mc = clean.match(re);
  let i = mc ? clean.indexOf('{', mc.index) : -1;
  if (i < 0) return null;
  let depth = 0, end = -1;
  for (; i < clean.length; i++) {
    if (clean[i] === '{') depth++;
    else if (clean[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  return { file: path.relative(ROOT, file).replace(/\\/g, '/'), body: end > 0 ? clean.slice(mc.index, end) : '' };
}

// 二跳登记表可带第三段 `file`（相对 src-tauri）。**同名函数必须指名**：
// 命令体与引擎函数可以同名（cleanup_execute 就是这种），按名字搜会命中
// readdir 顺序里的第一个，那正是审计 §2.1 里「登记了等于没登记」的成因。
// 不指名时这里显式报歧义而不是默默取第一个 —— 歧义本身就该红。
function resolveHelperBody(helper, file) {
  if (!file) {
    const all = srcFiles
      .filter((f) => new RegExp(`\\bfn\\s+${helper}\\s*[<(]`).test(blankNonCode(fs.readFileSync(f, 'utf8'))))
      .map((f) => path.relative(ROOT, f).replace(/\\/g, '/'));
    if (all.length > 1) {
      return { err: `helper ${helper} 在 ${all.length} 个文件里同名（${all.join(' / ')}）——必须登记第三段 file 指名` };
    }
    return { body: extractBody(helper) };
  }
  const abs = path.join(ROOT, file);
  if (!fs.existsSync(abs)) return { err: `helper ${helper} 登记的文件 ${file} 不存在` };
  const src = fs.readFileSync(abs, 'utf8');
  const re = new RegExp(`\\bfn\\s+${helper}\\s*[<(]`);
  const clean = blankNonCode(src);
  const mc = clean.match(re);
  if (!mc) return { err: `${file} 里找不到 fn ${helper}（改名/搬走了？）` };
  const start = clean.indexOf('{', mc.index);
  let depth = 0, end = -1;
  for (let i = start; i < clean.length; i++) {
    if (clean[i] === '{') depth++;
    else if (clean[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  return { body: { file, body: end > 0 ? clean.slice(mc.index, end) : '' } };
}

const bodies = new Map();
const missing = [];
for (const name of commands) {
  const hit = extractBody(name);
  if (hit) bodies.set(name, hit);
  else missing.push(name);
}

// ---- 3. 三层断言 ----
// 二跳登记的命令同样算「已受控」：它的闸门由 2b 钉在 helper 体内，不在命令体里。
const HELPER_CMDS = new Set(MUST_PROTECT_VIA_HELPER.map(([cmd]) => cmd));
const exemptStale = [...EXEMPTS.keys()].filter((k) => !commands.includes(k));
check(exemptStale.length === 0, '1a. 豁免清单无陈旧条目（命令已退役须同步摘除）', exemptStale.join(', ') || '全部在册');
const mustStale = MUST_PROTECT.filter((k) => !commands.includes(k));
check(mustStale.length === 0, '1b. 正向清单无陈旧条目', mustStale.join(', ') || '全部在册');
const helperStale = [...HELPER_CMDS].filter((k) => !commands.includes(k));
check(helperStale.length === 0, '1d. 二跳登记表无陈旧条目', helperStale.join(', ') || '全部在册');
// 同一命令不得同时出现在两张表：命令体口径与 helper 体口径互斥，
// 同时登记等于「哪张表漏了都能被另一张表顶替」，棘轮就松了。
const dualRegistered = MUST_PROTECT.filter((k) => HELPER_CMDS.has(k));
check(dualRegistered.length === 0, '1e. 同一命令不得同时登记在正向清单与二跳表',
  dualRegistered.join(', ') || '无重复登记');

const missMUST = MUST_PROTECT.filter((k) => !bodies.has(k));
check(missMUST.length === 0, '1c. 正向清单命令全部在源码中定位到函数体', missMUST.length ? missMUST.join(', ') : `${MUST_PROTECT.length}/${MUST_PROTECT.length}`);

const lostProtect = MUST_PROTECT.filter((k) => bodies.has(k) && !bodyHasProtect(bodies.get(k).body));
check(lostProtect.length === 0, '2. 正向出口的 is_path_protected 前置不许掉（双向棘轮）',
  lostProtect.length ? lostProtect.map((k) => `${k}(${bodies.get(k).file})`).join(', ') : `${MUST_PROTECT.length} 条全部在位`);

// 2b. 二跳出口的 helper 正向棘轮（L-4）：helper 定位失败即红（fail-closed），
//     helper 体内的 is_path_protected 被删即红。
{
  const helperIssues = [];
  for (const [cmd, helper, file, marker = 'is_path_protected'] of MUST_PROTECT_VIA_HELPER) {
    if (!commands.includes(cmd)) { helperIssues.push(`命令 ${cmd} 已不在 generate_handler! 清单——登记陈旧`); continue; }
    const r = resolveHelperBody(helper, file);
    if (r.err) { helperIssues.push(r.err); continue; }
    if (!r.body) { helperIssues.push(`${cmd} 的 helper ${helper} 未能在源码中定位（改名/搬走了？）`); continue; }
    if (!bodyHasProtect(r.body.body, marker)) helperIssues.push(`${helper}(${r.body.file}) 体内 ${marker} 未传播 Err/早退——${cmd} 的删除闸被拆`);
  }
  check(helperIssues.length === 0, '2b. 二跳出口的 helper 体内 is_path_protected 在位（L-4 棘轮）',
    helperIssues.length ? helperIssues.join('；') : `${MUST_PROTECT_VIA_HELPER.length} 条 helper 链全部在位`);
}

const unknownExits = [];
const exemptMissing = [];
for (const [name, { file, body }] of bodies) {
  const hit = DELETE_MARKERS.find((mk) => body.includes(mk));
  if (!hit) continue;
  if (bodyHasProtect(body)) continue;
  if (EXEMPTS.has(name)) continue;
    if (HELPER_CMDS.has(name)) {
    // 闸门在 helper 体内，由 2b 钉住；命令体自身没有 protect 是**登记形态**而非缺口。
    // 反向盲区：若某天命令体自己开始删文件（不再委托 helper），命令体里出现删除标记
    // 而 protect 仍只在 helper 里，就成了「新出口未被棘轮覆盖」。那种情况必须红。
    const helperResolved = MUST_PROTECT_VIA_HELPER
      .filter(([cmd]) => cmd === name)
      .map(([, helper, f, marker = 'is_path_protected']) => {
        const r = resolveHelperBody(helper, f);
        return !r.err && r.body && bodyHasProtect(r.body.body, marker);
      })
      .some(Boolean);
    if (!helperResolved) {
      unknownExits.push(`${name}(${file}) 命令体命中删除标记 [${hit}]，而其 helper 体内已无 is_path_protected——新出口未被棘轮覆盖`);
    }
    continue;
  }
  if (MUST_PROTECT.includes(name)) {
    unknownExits.push(`${name}(${file}) 正向清单出口却未扫到 is_path_protected`);
  } else {
    unknownExits.push(`${name}(${file}) 命中删除标记 [${hit}] 且未注册豁免`);
  }
}
for (const name of EXEMPTS.keys()) {
  const b = bodies.get(name);
  if (b && !DELETE_MARKERS.some((mk) => b.body.includes(mk))) {
    exemptMissing.push(`${name}(${b.file}) 注册了豁免但函数体已扫不到任何删除标记——复核后摘条目`);
  }
}
check(unknownExits.length === 0, '3. 无未注册的删除出口（新出口默认红，放行须在 EXEMPTS 带理由登记）',
  unknownExits.length ? unknownExits.join('；') : `${[...bodies.values()].filter((b) => DELETE_MARKERS.some((mk) => b.body.includes(mk))).length} 条命中删除标记的命令全部受控`);

// T1a-L13：豁免计数棘轮 —— 每条豁免登记它认领的删除 API 及次数，与命令体实际调用逐项对拍。
// 长 API 名先匹配并抹掉，避免 `remove_dir_all` 被 `remove_dir` 重复计数。
function apiCounts(body) {
  // 还原执行臂的真实名称是 `reg_import_apply_sections`；共享删除名单把它归在
  // `reg_import_apply` 家族，计数前先归一，避免豁免把真实调用记成 0。
  let rest = body.replace(/\breg_import_apply_sections\b/g, 'reg_import_apply');
  const out = {};
  for (const mk of [...DELETE_MARKERS].sort((a, b) => b.length - a.length)) {
    const re = new RegExp(`\\b${mk}\\b`, 'g');
    const n = (rest.match(re) ?? []).length;
    if (n) out[mk] = n;
    rest = rest.replace(re, ' ');
  }
  return out;
}
const exemptDrift = [];
let exemptTotal = 0;
for (const [name, entry] of EXEMPTS) {
  const b = bodies.get(name);
  if (!b) continue; // 命令未定位由 5 组单独判红
  const got = apiCounts(b.body);
  exemptTotal += Object.values(got).reduce((a, n) => a + n, 0);
  const want = entry.apis ?? {};
  for (const k of new Set([...Object.keys(got), ...Object.keys(want)])) {
    const g = got[k] ?? 0;
    const w = want[k] ?? 0;
    if (g !== w) exemptDrift.push(`${name}(${b.file}) 的 ${k}：现算 ${g} 处 ≠ 登记 ${w} 处——豁免只覆盖登记过的调用点/次数，扩面须先复核`);
  }
}
check(exemptDrift.length === 0, '4b. 豁免条目的删除 API 计数 ⇄ 命令体逐项一致（T1a-L13）',
  exemptDrift.length ? exemptDrift.join('；') : `${EXEMPTS.size} 条豁免共 ${exemptTotal} 处删除调用，全部在账`);
check(exemptMissing.length === 0, '4. 豁免条目与函数体现状一致', exemptMissing.join('；') || '无漂移');

// v2-L4P-16（E-5）：定位失败从「ℹ 放行」改为判红。函数改名/搬出 src-tauri/src 会让
// 删除出口网整条脱网——「新永久删出口默认红」的防线可以在无声中被绕掉，方向必须
// fail-closed。豁免/正向清单里的命令仍允许仅提示（它们的受控性由登记理由兜住）。
const missingCmds = missing.filter((n) => !EXEMPTS.has(n) && !MUST_PROTECT.includes(n) && !HELPER_CMDS.has(n));
check(missingCmds.length === 0, '5. 命令体定位失败即红（fail-closed，防出口网无声脱网）',
  missingCmds.length ? `未定位：${missingCmds.join(', ')}` : `${commands.length} 条命令全部定位到函数体`);
if (missing.length > missingCmds.length) {
  console.log(`ℹ 豁免/正向清单内未定位的命令（受控性由登记理由兜住）：${missing.filter((n) => EXEMPTS.has(n) || MUST_PROTECT.includes(n) || HELPER_CMDS.has(n)).join(', ')}`);
}

// ---- C01 断言组（v7.2）----
{
  // C01-a/b：组合闸本体（protect.rs::validate_mutation_target，指名文件——
  // 同名判定不许歧义）。
  const validatorPath = path.join(ROOT, 'src', 'engine', 'protect.rs');
  const validatorSrc = blankNonCode(fs.readFileSync(validatorPath, 'utf8'));
  const vm = validatorSrc.match(/\bfn\s+validate_mutation_target\s*[<(]/);
  let validatorBody = '';
  if (vm) {
    let i = validatorSrc.indexOf('{', vm.index);
    let depth = 0;
    for (; i < validatorSrc.length && i >= 0; i++) {
      if (validatorSrc[i] === '{') depth++;
      else if (validatorSrc[i] === '}') { depth--; if (depth === 0) break; }
    }
    validatorBody = validatorSrc.slice(vm.index, i);
  }
  if (!vm || !validatorBody) {
    check(false, 'C01-a. 组合闸 validate_mutation_target 在 protect.rs 中定位到', '缺失——共同判据被删，C01 整组回退');
  } else {
    const issues = judgeValidatorBody(validatorBody);
    check(issues.length === 0, 'C01-a. 组合闸四闸俱全且只判定不执行（受保护面→别名面→系统面→reparse，无删除原语）',
      issues.length ? issues.join('；') : '在位');
  }
  // C01-c：成对棘轮（R2a 彻底方案）——residue* 的文件面产源/出口，
  // is_path_protected 与 is_system_namespace 必须共现，出现孤立即红。
  // 测试文件只断言 is_system_namespace 本身，不构成生产删除出口；把它留在扫描面会
  // 让「每文件至少贡献 1 对」永远无法成立，也会把真实成对对象稀释成文件数。
  const pairFiles = srcFiles.filter((f) => {
    const rel = path.relative(ROOT, f).replace(/\\/g, '/');
    return /uninstall\/residue/.test(rel) && !/_tests\.rs$/.test(rel);
  });
  const pairIssues = [];
  const pairDead = [];
  let pairSites = 0;
  for (const f of pairFiles) {
    const clean = blankNonCode(fs.readFileSync(f, 'utf8'));
    const pairs = countProtectPairs(clean);
    pairSites += pairs;
    if (pairs === 0) {
      pairDead.push(`${path.relative(ROOT, f).replace(/\\/g, '/')}（protect=${(clean.match(/\bis_path_protected\s*\(/g) ?? []).length}/sysns=${(clean.match(/\bis_system_namespace\s*\(/g) ?? []).length}）`);
    }
    for (const issue of judgeProtectPair(clean)) {
      pairIssues.push(`${path.relative(ROOT, f).replace(/\\/g, '/')}: ${issue}`);
    }
  }
  check(pairIssues.length === 0, `C01-c. 删除产源/出口两闸成对（is_path_protected ⇄ is_system_namespace，扫 ${pairFiles.length} 个文件）`,
    pairIssues.length ? pairIssues.join('；') : '全部成对');
  // T1a-M01：地板从「文件数」改为「成对站点数」，且每个生产文件至少贡献 1 对。
  // 0 对时「全部成对」不再成立——这正是 residue_trace_tests.rs 曾把文件数地板
  // 顶绿、真实成对对象只有 2 的缺口。
  check(
    pairSites >= 2 && pairDead.length === 0,
    `C01-c 成对站点地板（residue 现算 ${pairSites} 对 / ${pairFiles.length} 个生产文件，每文件 ≥1 对且合计 ≥2）`,
    pairDead.length
      ? `以下文件两闸未共现：${pairDead.join('；')}`
      : pairSites < 2
        ? '成对对象不足 2：protect/sysns 可能被整体下沉或删除，C01-c 已退化成 0 对象 ✓'
        : '',
  );
}

console.log('');
if (fail > 0) {
  console.error('门禁失败：删除出口枚举存在未受控项');
  process.exit(1);
}

// ---- E-8/E-15 正向对照自检（v2-L4P-16/44）：判定器必须能抓真实违规，否则恒绿 ----
const POSITIVE_CONTROLS = (() => {
  const checks = [];
  // ① 剥注释后，注释里的 API 名不得再命中标记
  const sample = blankNonCode('fn x() {\n    // remove_file 不算\n    let s = "remove_dir_all 也不算";\n}');
  checks.push(['注释/字符串被剥离', !sample.includes('remove_file') && !sample.includes('remove_dir_all')]);
  // ② 真实调用仍然命中
  const sample2 = blankNonCode('fn y() { let _ = remove_file(p); }');
  checks.push(['真实调用仍命中', sample2.includes('remove_file')]);
  // ②b T1a-L07：核心判据 bodyHasProtect 的两向样本（此前只有 tokenizer 对照）
  checks.push(['删除体无 protect 判红', !bodyHasProtect('fn z() { remove_file(p); }')]);
  checks.push(['删除体有 protect 放行', bodyHasProtect('fn z() { if !is_path_protected(p) { return Err("x".into()); } remove_file(p); }')]);
  checks.push(['let _ 吞掉 protect 判红', !bodyHasProtect('fn z() { let _ = validate_mutation_target(p); remove_file(p); }')]);
  checks.push(['空分支 protect 判红', !bodyHasProtect('fn z() { if !is_path_protected(p) {} remove_file(p); }')]);
  checks.push(['问号传播 protect 放行', bodyHasProtect('fn z() -> Result<()> { validate_mutation_target(p)?; remove_file(p); Ok(()) }')]);
  checks.push(['if let Err 返回放行', bodyHasProtect('fn z() { if let Err(e) = validate_mutation_target(p) { return Err(e); } remove_file(p); }')]);
  // ③ C01-a：四闸俱全的组合闸放行
  const goodValidator =
    'fn validate_mutation_target(p: &str) -> Result<(), String> { if is_path_protected(p) { return Err("x".into()); } if final_path_protected(p) { return Err("x".into()); } if is_system_namespace(p) { return Err("x".into()); } if is_reparse(&md) { return Err("x".into()); } Ok(()) }';
  checks.push(['C01 四闸俱全的组合闸放行', judgeValidatorBody(blankNonCode(goodValidator)).length === 0]);
  // ④ C01-a：缺系统面闸必须红（R1d-K01 的病灶形态）
  const missingSystem = goodValidator.replace('if is_system_namespace(p) { return Err("x".into()); } ', '');
  checks.push(['C01 缺 is_system_namespace 判红', judgeValidatorBody(blankNonCode(missingSystem)).length > 0]);
  // ⑤ C01-b：组合闸里塞删除原语必须红（共同判据吞出口形态）
  const swallowing = goodValidator.replace('Ok(())', 'let _ = remove_file(p); Ok(())');
  checks.push(['C01 组合闸含删除原语判红', judgeValidatorBody(blankNonCode(swallowing)).length > 0]);
  // ⑥ C01-c：成对棘轮两向（孤立即红 / 成对放行）
  checks.push(['C01 成对棘轮：孤立 protect 判红', judgeProtectPair('fn a() { is_path_protected(p); }').length > 0]);
  checks.push(['C01 成对棘轮：两闸共现放行', judgeProtectPair('fn a() { is_path_protected(p); is_system_namespace(p); }').length === 0]);
  checks.push(['C01 成对计数：只有 sysns 记 0 对', countProtectPairs('fn a() { is_system_namespace(p); }') === 0]);
  for (const [label, ok] of checks) {
    if (!ok) { console.error(`✗ 正向对照失败：${label}——判定器已失效，本门禁的 ✓ 不可信`); process.exit(1); }
  }
  console.log(`✓ 正向对照自检通过（剥离 + 命中 + C01 四向，共 ${checks.length} 组）`);
  return true;
})();

console.log('删除出口枚举门禁全部通过');
