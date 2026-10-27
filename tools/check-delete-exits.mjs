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
const EXEMPTS = new Map([
  // 注册表/启动项出口：注册表无文件路径语义，闸门是注册表禁删面与白名单目标
  ['startup_delete', '注册表项/启动文件夹快捷方式删除，闸门=native::startup_delete 白名单目标，非文件 protect'],
  // 自有报告目录：report_path() 已做 basename 化 + .json 后缀白名单防路径穿越；
  // protect 清单整含 app_data_dir，对自有数据目录恒拒、无判定意义
  ['realtime_report_delete', '删 Trim 自有网速报告（app_data_dir/report），basename+.json 白名单防穿越，非用户内容'],
  ['realtime_report_clear', '同上——清空自有报告目录内 *.json，目录固定+后缀白名单'],
  // 自有字体副本：只动 Trim 导入时生成的副本，绝不触用户原始字体文件
  ['fonts_import', 'remove_file 只删自有字体副本目录内「上一份导入副本」（替换语义）'],
  ['fonts_remove_imported', '移除记录 + 删 settings.fontImported 登记的自有副本，不触用户原始文件'],
  // v2-L4P-12（B-1）：backgrounds 住在 app_data_dir() 里，而 configure_from_app 把
  // app_data_dir() 整棵登记为 subtree ⇒ is_path_protected 恒拒，功能 100% 不可用。
  // 闸门收口为四件套（见命令体注释），故从 MUST_PROTECT 挪入豁免并写明依据：
  ['appearance_bg_delete', '仅删 backgrounds 直接子项：父目录归属校验 + 扩展名白名单 + is_reparse 拒 + 回收站 _os；文件面 protect 对自有数据目录恒拒无判定意义'],
  // S3（2026-10-05）更新完成标记：路径是 `paths::join_data("update-applied.json")` ——
  // 一个 Trim 自己写的单文件标记名，既不是用户内容也不接受任何外部输入（命令体里没有
  // 路径参数），protect 对它恒拒（app_data_dir 整棵是 subtree）反而会让功能 100% 不可用，
  // 所以按 realtime_report_delete 那条例外姿势登记，不套一层无意义的闸门。
  ['updater_install', '安装失败时清掉 Trim 自写的 update-applied.json 标记（文件名常量，无外部输入）；protect 对自有数据目录恒拒无判定意义'],
  ['updater_completion', '读后即删同一份 update-applied.json 标记（防「更新已完成」提示反复弹）；另经 clean_installer 删**下载目录里我们自己存的那份安装包**——路径取自标记，删除前过「文件名必须是 Trim_<版本>_x64-setup.exe 形状 + 父目录必须等于 %USERPROFILE%\\Downloads」双闸，不合形状直接不碰文件'],
  // v2-L4P-27（B-5）：fonts_import 旧副本删除补齐归属校验后的口径说明由代码兑现；
  // 豁免理由不变（只删自有副本目录内目标）。
  // G-4（2026-10-07）：清空回收站走系统 Shell API（SHEmptyRecycleBinW），**没有路径参数**
  // ——它作用于「所有盘的回收站」这一系统实体，文件面 is_path_protected 无从判定。
  // 本次改动的真实闸门是三条，逐条列出（缺一条这条豁免就不成立）：
  //   ① 主窗档 `guard(&window, guard::MAIN)`（不可逆动作不给四个子窗放行）；
  //   ② 渲染层红色高危确认 `confirmDanger`，且确认文案里带**清空前的条目数与体积**
  //      （cleanup:recycle-stats 现查，不是扫描占位行的 0）；
  //   ③ 条目 `domain == "special"` ⇒ 永不默认勾选（cleanup.js 的默认勾选分支显式跳过）。
  ['cleanup_empty_recycle_bin', '清空回收站（SHEmptyRecycleBinW）作用于系统回收站整体、无路径参数，protect 不适用；闸门=主窗档 + 渲染层红色高危确认（含条目数/体积）+ special 域默认不勾选'],
  // T1a-M07：`reg_import_apply` 并入统一名单后暴露的两条还原命令——它们写回的是
  // 已过四道闸的注册表 sections（严格解析 / 受保护面 / 封条核对 / HKLM 提权），
  // 文件面 is_path_protected 对注册表键没有判定语义。
  ['uninstall_reg_backup_restore', '注册表备份还原：reg_backup_restore_guards 四道闸，执行臂吃同一份 sections；文件面 protect 不适用'],
  ['cleanup_reg_backup_restore', '同上——清理域与卸载域共用同一 reg_backup_restore_guards 公共件'],
]);

// ---- 正向清单：审查矩阵逐列核过的文件型删除出口，protect 判定不许掉 ----
// 审查 L-4（2026-10-03）补入 optimizer_run：@@RECYCLE@@ 回收站出口的 protect 调用就在
// apply.rs 命令体内（714 行），此前只靠第 3 组「恰好 includes is_path_protected」放行
// ——谁删掉那行，门禁不会红。进正向清单后「掉闸即红」。
const MUST_PROTECT = [
  'fileclean_delete_file',
  'fileclean_execute',
  'finder_delete',
  'optimizer_run',
  'uninstall_residue_execute',
  'uninstall_pending_add',
  // 2026-10-09（D3）：contextmenu_remove 随右键删除链整链退役，从正向清单摘除
  // （cm_remove 与其 RegDeleteTreeW/回收站出口一并删除；toggle 不删文件）。
];
// T1a-M19：正向清单本身无地板 ——「新出口默认红」只拦添加方向、不拦拆台账方向
//（探针 P6：清单清空 ⇒ 1b/1c/2 三组计数全 0 仍绿）。钉住规模，拆台账即红。
check(MUST_PROTECT.length >= 6, `1a. 正向清单 MUST_PROTECT 规模地板（现算 ${MUST_PROTECT.length} 条 ≥ 6；T1a-M19）`,
  MUST_PROTECT.length < 6 ? '清单被拆 ⇒ 1b/1c/2 三组判定对象一起消失（假绿），拆动必须逐条给理由' : '');

// C01（v7.2）：保护闸的两种在位形态。v7.2 之后出口闸收口到
// `protect::validate_mutation_target`（组合闸：受保护面→别名面→系统面→reparse），
// 命令体里出现组合闸调用 = 受保护面在位（组合闸内部必调 is_path_protected，
// 由下方 C01 断言组钉死组合闸本身不许掉闸）。
const PROTECT_MARKERS = ['is_path_protected', 'validate_mutation_target'];
const bodyHasProtect = (body) => PROTECT_MARKERS.some((m) => body.includes(m));

// 二跳出口的正向棘轮（审查 L-4）：protect 不在命令体内、而在本仓 helper 里。
// 登记 {命令, helper}，钉住 helper 体内的 protect 调用——helper 改名/protect 被删/
// 搬出 src 均红。（2026-10-12：原首条 cleanup_retry_failed_delete /
// retry_failed_delete_blocking 随回收站重试链整链退役撤除。）
//
// ⚠️ 第三段 `file` 是 2026-10-04 磁盘清理审计 §2.1 补的，且**不是可选的锦上添花**：
//
//   cleanup_execute 此前登记在 MUST_PROTECT（命令体口径）。但命令体
//   （commands/cleanup/scan_execute.rs）里唯一的 is_path_protected 在 384 行，位于
//   `if to_recycle && …` 分支内 —— v3.3.0 用户裁定「常规清理 toRecycle 恒 false」
//   之后**产品语义上不可达**。真正执行永久删除的闸门在
//   `engine/native/cleanup.rs::cleanup_execute:680`，那个文件不在本门禁扫描网内。
//   判红实验：把 680 行改成 `else if false`，本门禁四组断言**全部照绿**（已实测）。
//   也就是说「删掉全仓唯一永久删除链的保护判定」是零告警的。
//
//   修法两条，缺一不可：
//   ① 把 cleanup_execute 从 MUST_PROTECT 挪进本表，并**指名文件**——
//      `extractBody` 只按函数名搜索，而命令体与引擎函数**同名**
//      （scan_execute.rs / engine/native/cleanup.rs 都是 `cleanup_execute`），
//      不指名就会解析到命令体那个，等于什么都没修。
//   ② 指名文件后本组判的是引擎函数；命令体那处 384 行不再能满足任何一条棘轮，
//      也就回到报告里要求的「384 单独不足以满足正向棘轮」。
//
//   第三段 file 是**相对 src-tauri** 的（ROOT 就是 src-tauri，见 :28）。
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
function stripRustComments(src) {
  let out = '', i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i], d = i + 1 < n ? src[i + 1] : '';
    if (c === '/' && d === '/') { while (i < n && src[i] !== '\n') i++; continue; }
    if (c === '/' && d === '*') {
      let depth = 1; i += 2;
      while (i < n && depth > 0) {
        if (src[i] === '/' && src[i + 1] === '*') { depth++; i += 2; }
        else if (src[i] === '*' && src[i + 1] === '/') { depth--; i += 2; }
        else i++;
      }
      out += ' ';
      continue;
    }
    if (c === '"') {
      i++;
      while (i < n && src[i] !== '"') { if (src[i] === '\\') i++; i++; }
      i++; out += '""';
      continue;
    }
    if (c === 'r' && (d === '"' || d === '#')) {
      // raw string r"..." / r#"..."#
      let hashes = 0, j = i + 1;
      while (src[j] === '#') { hashes++; j++; }
      if (src[j] === '"') {
        const close = '"' + '#'.repeat(hashes);
        const end = src.indexOf(close, j + 1);
        i = end < 0 ? n : end + close.length;
        out += '""';
        continue;
      }
    }
    if (c === "'") {
      // 字符字面量或生存期（'a）：看第二个引号前的形态
      const m = /^'(\\.|[^'\\])'/.exec(src.slice(i, i + 5));
      if (m) { i += m[0].length; out += "''"; continue; }
      out += c; i++;
      continue;
    }
    out += c; i++;
  }
  return out;
}

function extractBody(name) {
  for (const file of srcFiles) {
    const src = fs.readFileSync(file, 'utf8');
    const re = new RegExp(`\\bfn\\s+${name}\\s*[<(]`);
    const m = src.match(re);
    if (!m) continue;
    // 从 fn 起始做花括号配平（在剥离注释/字符串后的文本上做，防止字符串里的
    // 花括号截断函数体——E-6 的判绿方向风险）
    const clean = stripRustComments(src);
    const mc = clean.match(re);
    let i = mc ? clean.indexOf('{', mc.index) : -1;
    if (i < 0) continue;
    let depth = 0, end = -1;
    for (; i < clean.length; i++) {
      if (clean[i] === '{') depth++;
      else if (clean[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    return { file: path.relative(ROOT, file).replace(/\\/g, '/'), body: end > 0 ? clean.slice(mc.index, end) : '' };
  }
  return null;
}

// 二跳登记表可带第三段 `file`（相对 src-tauri）。**同名函数必须指名**：
// 命令体与引擎函数可以同名（cleanup_execute 就是这种），按名字搜会命中
// readdir 顺序里的第一个，那正是审计 §2.1 里「登记了等于没登记」的成因。
// 不指名时这里显式报歧义而不是默默取第一个 —— 歧义本身就该红。
function resolveHelperBody(helper, file) {
  if (!file) {
    const all = srcFiles
      .filter((f) => new RegExp(`\\bfn\\s+${helper}\\s*[<(]`).test(stripRustComments(fs.readFileSync(f, 'utf8'))))
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
  const clean = stripRustComments(src);
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
    if (!r.body.body.includes(marker)) helperIssues.push(`${helper}(${r.body.file}) 体内已无 ${marker}——${cmd} 的删除闸被拆`);
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
        return !r.err && r.body && r.body.body.includes(marker);
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
  const validatorSrc = stripRustComments(fs.readFileSync(validatorPath, 'utf8'));
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
  // C01-c：成对棘轮（R2a 彻底方案）——residue* 与 pending_delete 的文件面产源/出口，
  // is_path_protected 与 is_system_namespace 必须共现，出现孤立即红。
  const pairFiles = srcFiles.filter((f) => /uninstall[/\\](residue|pending_delete)/.test(path.relative(ROOT, f)));
  const pairIssues = [];
  for (const f of pairFiles) {
    for (const issue of judgeProtectPair(stripRustComments(fs.readFileSync(f, 'utf8')))) {
      pairIssues.push(`${path.relative(ROOT, f).replace(/\\/g, '/')}: ${issue}`);
    }
  }
  check(pairIssues.length === 0, `C01-c. 删除产源/出口两闸成对（is_path_protected ⇄ is_system_namespace，扫 ${pairFiles.length} 个文件）`,
    pairIssues.length ? pairIssues.join('；') : '全部成对');
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
  const sample = stripRustComments('fn x() {\n    // remove_file 不算\n    let s = "remove_dir_all 也不算";\n}');
  checks.push(['注释/字符串被剥离', !sample.includes('remove_file') && !sample.includes('remove_dir_all')]);
  // ② 真实调用仍然命中
  const sample2 = stripRustComments('fn y() { let _ = remove_file(p); }');
  checks.push(['真实调用仍命中', sample2.includes('remove_file')]);
  // ②b T1a-L07：核心判据 bodyHasProtect 的两向样本（此前只有 tokenizer 对照）
  checks.push(['删除体无 protect 判红', !bodyHasProtect('fn z() { remove_file(p); }')]);
  checks.push(['删除体有 protect 放行', bodyHasProtect('fn z() { is_path_protected(p); remove_file(p); }')]);
  // ③ C01-a：四闸俱全的组合闸放行
  const goodValidator =
    'fn validate_mutation_target(p: &str) -> Result<(), String> { if is_path_protected(p) { return Err("x".into()); } if final_path_protected(p) { return Err("x".into()); } if is_system_namespace(p) { return Err("x".into()); } if is_reparse(&md) { return Err("x".into()); } Ok(()) }';
  checks.push(['C01 四闸俱全的组合闸放行', judgeValidatorBody(stripRustComments(goodValidator)).length === 0]);
  // ④ C01-a：缺系统面闸必须红（R1d-K01 的病灶形态）
  const missingSystem = goodValidator.replace('if is_system_namespace(p) { return Err("x".into()); } ', '');
  checks.push(['C01 缺 is_system_namespace 判红', judgeValidatorBody(stripRustComments(missingSystem)).length > 0]);
  // ⑤ C01-b：组合闸里塞删除原语必须红（共同判据吞出口形态）
  const swallowing = goodValidator.replace('Ok(())', 'let _ = remove_file(p); Ok(())');
  checks.push(['C01 组合闸含删除原语判红', judgeValidatorBody(stripRustComments(swallowing)).length > 0]);
  // ⑥ C01-c：成对棘轮两向（孤立即红 / 成对放行）
  checks.push(['C01 成对棘轮：孤立 protect 判红', judgeProtectPair('fn a() { is_path_protected(p); }').length > 0]);
  checks.push(['C01 成对棘轮：两闸共现放行', judgeProtectPair('fn a() { is_path_protected(p); is_system_namespace(p); }').length === 0]);
  for (const [label, ok] of checks) {
    if (!ok) { console.error(`✗ 正向对照失败：${label}——判定器已失效，本门禁的 ✓ 不可信`); process.exit(1); }
  }
  console.log(`✓ 正向对照自检通过（剥离 + 命中 + C01 四向，共 ${checks.length} 组）`);
  return true;
})();

console.log('删除出口枚举门禁全部通过');
