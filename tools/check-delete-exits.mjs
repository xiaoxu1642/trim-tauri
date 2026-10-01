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
  'RegDeleteTreeW', 'RegDeleteValueW', 'RegDeleteKeyW',
  // 引擎删除函数（二跳委托的发现网）
  'send_to_trash',        // trim_finder 回收站
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
]);

// ---- 正向清单：审查矩阵逐列核过的文件型删除出口，protect 判定不许掉 ----
const MUST_PROTECT = [
  'cleanup_execute',
  'fileclean_delete_file',
  'fileclean_execute',
  'finder_delete',
  'appearance_bg_delete',
  'uninstall_residue_execute',
  'uninstall_pending_add',
  'contextmenu_remove',
];

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

function extractBody(name) {
  for (const file of srcFiles) {
    const src = fs.readFileSync(file, 'utf8');
    const re = new RegExp(`\\bfn\\s+${name}\\s*[<(]`);
    const m = src.match(re);
    if (!m) continue;
    // 从 fn 起始做花括号配平
    let i = src.indexOf('{', m.index);
    if (i < 0) continue;
    let depth = 0, end = -1;
    for (; i < src.length; i++) {
      if (src[i] === '{') depth++;
      else if (src[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    return { file: path.relative(ROOT, file).replace(/\\/g, '/'), body: end > 0 ? src.slice(m.index, end) : '' };
  }
  return null;
}

const bodies = new Map();
const missing = [];
for (const name of commands) {
  const hit = extractBody(name);
  if (hit) bodies.set(name, hit);
  else missing.push(name);
}

// ---- 3. 三层断言 ----
const exemptStale = [...EXEMPTS.keys()].filter((k) => !commands.includes(k));
check(exemptStale.length === 0, '1a. 豁免清单无陈旧条目（命令已退役须同步摘除）', exemptStale.join(', ') || '全部在册');
const mustStale = MUST_PROTECT.filter((k) => !commands.includes(k));
check(mustStale.length === 0, '1b. 正向清单无陈旧条目', mustStale.join(', ') || '全部在册');

const missMUST = MUST_PROTECT.filter((k) => !bodies.has(k));
check(missMUST.length === 0, '1c. 正向清单命令全部在源码中定位到函数体', missMUST.length ? missMUST.join(', ') : `${MUST_PROTECT.length}/${MUST_PROTECT.length}`);

const lostProtect = MUST_PROTECT.filter((k) => bodies.has(k) && !bodies.get(k).body.includes('is_path_protected'));
check(lostProtect.length === 0, '2. 正向出口的 is_path_protected 前置不许掉（双向棘轮）',
  lostProtect.length ? lostProtect.map((k) => `${k}(${bodies.get(k).file})`).join(', ') : `${MUST_PROTECT.length} 条全部在位`);

const unknownExits = [];
const exemptMissing = [];
for (const [name, { file, body }] of bodies) {
  const hit = DELETE_MARKERS.find((mk) => body.includes(mk));
  if (!hit) continue;
  if (body.includes('is_path_protected')) continue;
  if (EXEMPTS.has(name)) continue;
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

const missingCmds = missing.filter((n) => !EXEMPTS.has(n) && !MUST_PROTECT.includes(n));
if (missing.length) {
  console.log(`ℹ 未定位到函数体的命令（定义可能在宏/其他 crate 内，按现状放行但列出）：${missing.join(', ')}`);
}

console.log('');
if (fail > 0) {
  console.error('门禁失败：删除出口枚举存在未受控项');
  process.exit(1);
}
console.log('删除出口枚举门禁全部通过');
