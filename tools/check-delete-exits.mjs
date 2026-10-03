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

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src-tauri');
let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

// ---- 删除标记：Win32/std 删除 API + 引擎删除函数（新增引擎删除函数须同步此处） ----
const DELETE_MARKERS = [
  'MoveFileExW',          // PFRO 延迟删（pending-add）
  'remove_dir_all',       // 递归删树
  'remove_file',          // 单文件删
  'DeleteFileW',
  'SHFileOperation',
  'RegDeleteTreeW', 'RegDeleteValueW', 'RegDeleteKeyW', 'RegDeleteKeyExW',
  'remove_dir',          // 单目录删（B-9：此前漏登，只盯了递归删）
  // 引擎删除函数（二跳委托的发现网）
  'send_to_trash',        // trim_finder 回收站
  'send_to_trash_os',     // trim_finder 回收站（OsStr 直传形态）
  'remove_owned_font_copy', // fonts 自有副本删除 helper（v2-L4P-27：三道闸内聚于此）
  'reg_key_remove',       // native::RegDeleteTree 封装
  'reg_restore_delete',   // native::reg_value 恢复语义的删值
  'startup_delete',       // native::启动项删除
  'cm_remove',            // native::右键菜单移除
];

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
  // v2-L4P-27（B-5）：fonts_import 旧副本删除补齐归属校验后的口径说明由代码兑现；
  // 豁免理由不变（只删自有副本目录内目标）。
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
  'contextmenu_remove',
];

// 二跳出口的正向棘轮（审查 L-4）：protect 不在命令体内、而在本仓 helper 里。
// cleanup_retry_failed_delete 命令体是薄包装（guard + 组装 targets），真正的
// remove_dir_all/remove_file + is_path_protected 全在 retry_failed_delete_blocking ——
// 命令体口径的 MUST_PROTECT 对它恒红，所以单独登记 {命令, helper}，钉住 helper 体内
// 的 protect 调用。helper 改名/protect 被删/搬出 src 均红。
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
  ['cleanup_retry_failed_delete', 'retry_failed_delete_blocking'],
  ['cleanup_execute', 'cleanup_execute', 'src/engine/native/cleanup.rs'],
];

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
const srcFiles = [];
const walk = (dir) => {
  for (const f of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, f.name);
    if (f.isDirectory()) walk(p);
    else if (f.name.endsWith('.rs')) srcFiles.push(p);
  }
};
walk(path.join(ROOT, 'src'));

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

const lostProtect = MUST_PROTECT.filter((k) => bodies.has(k) && !bodies.get(k).body.includes('is_path_protected'));
check(lostProtect.length === 0, '2. 正向出口的 is_path_protected 前置不许掉（双向棘轮）',
  lostProtect.length ? lostProtect.map((k) => `${k}(${bodies.get(k).file})`).join(', ') : `${MUST_PROTECT.length} 条全部在位`);

// 2b. 二跳出口的 helper 正向棘轮（L-4）：helper 定位失败即红（fail-closed），
//     helper 体内的 is_path_protected 被删即红。
{
  const helperIssues = [];
  for (const [cmd, helper, file] of MUST_PROTECT_VIA_HELPER) {
    if (!commands.includes(cmd)) { helperIssues.push(`命令 ${cmd} 已不在 generate_handler! 清单——登记陈旧`); continue; }
    const r = resolveHelperBody(helper, file);
    if (r.err) { helperIssues.push(r.err); continue; }
    if (!r.body) { helperIssues.push(`${cmd} 的 helper ${helper} 未能在源码中定位（改名/搬走了？）`); continue; }
    if (!r.body.body.includes('is_path_protected')) helperIssues.push(`${helper}(${r.body.file}) 体内已无 is_path_protected——${cmd} 的删除闸被拆`);
  }
  check(helperIssues.length === 0, '2b. 二跳出口的 helper 体内 is_path_protected 在位（L-4 棘轮）',
    helperIssues.length ? helperIssues.join('；') : `${MUST_PROTECT_VIA_HELPER.length} 条 helper 链全部在位`);
}

const unknownExits = [];
const exemptMissing = [];
for (const [name, { file, body }] of bodies) {
  const hit = DELETE_MARKERS.find((mk) => body.includes(mk));
  if (!hit) continue;
  if (body.includes('is_path_protected')) continue;
  if (EXEMPTS.has(name)) continue;
  if (HELPER_CMDS.has(name)) {
    // 闸门在 helper 体内，由 2b 钉住；命令体自身没有 protect 是**登记形态**而非缺口。
    // 反向盲区：若某天命令体自己开始删文件（不再委托 helper），命令体里出现删除标记
    // 而 protect 仍只在 helper 里，就成了「新出口未被棘轮覆盖」。那种情况必须红。
    const helperResolved = MUST_PROTECT_VIA_HELPER
      .filter(([cmd]) => cmd === name)
      .map(([, helper, f]) => resolveHelperBody(helper, f))
      .some((r) => !r.err && r.body && r.body.body.includes('is_path_protected'));
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
  for (const [label, ok] of checks) {
    if (!ok) { console.error(`✗ 正向对照失败：${label}——判定器已失效，本门禁的 ✓ 不可信`); process.exit(1); }
  }
  console.log('✓ 正向对照自检通过（剥离 + 命中两向）');
  return true;
})();

console.log('删除出口枚举门禁全部通过');
