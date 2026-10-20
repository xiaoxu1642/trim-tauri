#!/usr/bin/env node
// check-native-hygiene.mjs —— 原生层卫生门禁（P3-5，2026-10-09）
//
// N1–N9「找违规型」断言族，各配**内置正向对照自检**（违例样本必须判红、合规样本必须放行，
// AGENTS §4.1）：
//   N1 裸 `quiet_cmd(...).output()` ⇒ 红：无超时的子进程是无界等待，挂住即锁 IPC。
//      （R5-G-4；11+1 个调用点已收口到 quiet_cmd_timeout / _raw，新写裸形态即红。）
//   N2 定长 UTF-16 数组**整体解码** ⇒ 红：`from_utf16_lossy(&x.szName)` 会把尾部
//      NUL 填充带进字符串、比较恒不命中（R5-M01 的实测根因）。必须用
//      `native::wide_str(x.szName.as_ptr())` 或显式按 NUL 截断后再解码。
//   N3 句柄型 API 返回值被 `.is_ok()/.is_err()` **直接判定** ⇒ 红：返回值即句柄
//      （FindFirstFileW/CreateFileW/OpenProcess…），判布尔即丢句柄。`RegOpenKeyExW` 这类
//      句柄走 out-param（`&mut hk`）的调用是合法形，不计入。
//   N4 `.reg` 内容读取必须经 `reg_backup::read_reg_text_file`（编码感知）⇒
//      reg 备份的文本读取点任一不在该入口即红（R5-G-1；UTF-16 的 .reg 用 UTF-8 读必炸）。
//   N5 模块可达性：`src-tauri/src` 与 `native-scanner/src` 下每个 `.rs` 都必须被
//      某个 `mod` 声明链覆盖 ⇒ 不在编译面/不在可达面的文件即红（R2-M05 派生，
//      `minifilter_orphan.rs` 就是漏网的活样本）。
//   N6 递归遍历必须保留深度常量（登记式棘轮，见 WALK_DEPTH_SITES）。
//   N7 「取最新」实现唯一化（现算唯一实现是 common::pick_newest_file）。
//   N8 快照槽必须域限定：所有 `snapshot::{set,get,clear}` 的键参数必须经 domain_key。
//   N9（X-1 同批，2026-10-15）快照表跨窗顶账的三种可机检形态：A origin 字面量闸 /
//      B CLEANUP 快照取用点登记闸 / C 两表 static 声明反合并声明（见段内详注）。
//
// 判据全部先剥 Rust 注释与字符串字面量（文本提及不算数，与 check-delete-callsites 同口径）。
// 例外：N9-A 刻意跑**原文字节**——字符串被剥后只剩 `""`，字面量与变量的区分就在引号本身。
//
// 用法：node tools/check-native-hygiene.mjs
'use strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { walkRs } from './lib/fs-walk.mjs';
import { gate } from './lib/gate.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ROOTS = [join(ROOT, 'src-tauri', 'src'), join(ROOT, 'native-scanner', 'src')];

/** 剥 Rust 注释与字符串字面量（与 check-delete-callsites 同口径的简化版） */
function stripRust(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const d = i + 1 < n ? src[i + 1] : '';
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
    // v6-P2：Rust **原始串** `r"..."` / `r#"..."#`——不处理转义，`r"\\?\"` 的尾部 `\`
    // 不是转义引号。旧实现把它当普通串的 \" 消费，一个 raw 串就把后面整段吃进
    // "字符串"（N1-N4/N8/N10 对路径密集文件集体失明——diskbench.rs 实测全文件
    // 只剩一个 ""）。`r` 前面必须是非标识符字符（防把 `for`/变量名 `r` 当串前缀）。
    if (c === 'r' && (d === '"' || d === '#')) {
      const prev = i > 0 ? src[i - 1] : '';
      if (!/[A-Za-z0-9_]/.test(prev)) {
        const m = /^r(#*)"/.exec(src.slice(i, i + 16));
        if (m) {
          // 终止符 = 哈希 + **单个**引号（r"…" → '"'；r#"…"# → '"#"'）。曾错写成
          // `"${m[1]}"`（两侧都包引号）⇒ 单哈希串找的是连续两个引号，一个 raw 串
          // 就把后面整段吃进"字符串"。
          const close = `${m[1]}"`;
          const end = src.indexOf(close, i + m[0].length);
          i = end === -1 ? n : end + close.length;
          out += '""';
          continue;
        }
      }
    }
    if (c === '"') {
      i++;
      while (i < n && src[i] !== '"') { if (src[i] === '\\') i++; i++; }
      i++; out += '""';
      continue;
    }
    if (c === "'") {
      const m = /^'(\\.|[^'\\])'/.exec(src.slice(i, i + 5));
      if (m) { i += m[0].length; out += "''"; continue; }
    }
    out += c; i++;
  }
  return out;
}

/** 从 `(` 起取平衡括号内的全文（返回 [content, endIndex]；不匹配返回 null） */
function balanced(text, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')') {
      depth--;
      if (depth === 0) return [text.slice(openIdx + 1, i), i];
    }
  }
  return null;
}

// ---------- 判定器（合成样本可直接对拍） ----------
// v5 批次 9 门禁候选 2：N3 名单补 OpenServiceW / OpenSCManagerW / CreateJobObjectW
// （服务/SCM/作业对象同属「返回句柄、is_ok 判定即泄漏」的家族；服务残留域在用）。
const HANDLE_APIS = /(?:FindFirstFileW|FindFirstVolumeW|CreateFileW|OpenProcess|CreateToolhelp32Snapshot|CreateEventW|CreateMutexW|CreateProcessW|OpenServiceW|OpenSCManagerW|CreateJobObjectW)\s*\(/g;

/** @returns {string[]} 违规描述 */
function hygieneViolations(clean) {
  const out = [];
  // N1 裸 quiet_cmd().output()
  for (const m of clean.matchAll(/quiet_cmd\s*\(/g)) {
    const pre = clean.slice(Math.max(0, m.index - 24), m.index);
    if (/quiet_cmd_timeout(_raw)?$/.test(pre) || /fn\s+quiet_cmd$/.test(pre)) continue;
    const win = clean.slice(m.index, m.index + 400);
    if (/\.output\s*\(/.test(win)) out.push(`裸 quiet_cmd().output()（无超时）@${m.index}`);
  }
  // N2 定长 UTF-16 数组整体解码（字段后**不跟** `[` 界；`(?![\w\[])` 防回溯截断）
  for (const m of clean.matchAll(/from_utf16_lossy\s*\(\s*&[A-Za-z_][\w]*\.(sz\w+|FriendlyName)(?![\w\[])/g)) {
    out.push(`定长 UTF-16 整体解码 ${m[1]}（应走 wide_str / NUL 截断）@${m.index}`);
  }
  // N3 句柄型 API 返回值被 is_ok/is_err 直接判定（out-param 形合法，见头注）
  for (const m of clean.matchAll(HANDLE_APIS)) {
    const open = m.index + m[0].length - 1;
    const bal = balanced(clean, open);
    if (!bal) continue;
    const [argText, close] = bal;
    if (argText.includes('&mut')) continue; // 句柄走 out-param（RegOpenKeyExW 类合法形）
    if (/^\s*\.\s*is_(ok|err)\s*\(/.test(clean.slice(close + 1, close + 40))) {
      out.push(`${m[0].trim()} 返回值被 is_ok/is_err 直接判定（句柄被丢弃）@${m.index}`);
    }
  }
  // N8 快照槽必须域限定（2026-10-09 真机修复）：主窗里 startup / contextmenu 共用
  // label 槽会互相顶账 —— 切页回来后勾选/启停按另一域的 id 集校验，整批被拒
  //（真机症状「切换项不是最近一次扫描结果」）。所有 snapshot::{set,get,clear} 的
  // 键参数必须经 domain_key 组合。
  for (const m of clean.matchAll(/snapshot::(?:set|get|clear)\s*\(/g)) {
    const win = clean.slice(m.index, m.index + 200);
    if (!win.includes('domain_key')) {
      out.push(`snapshot 调用未用 domain_key 限定域（跨域顶账）@${m.index}`);
    }
  }
  // N8c（v6-K09）：自建快照表（commands/finder.rs 的 FINDER_SNAPSHOTS）的槽键也必须
  // 带域——它不归 engine::snapshot 管，N8 主判据看不见。5 种扫描类型共用一个 label 槽
  // 会把 emptyfolder 条目的 `empty` 标记顶掉（空树复检闸整块失效，§5.25 同族）。
  // 判据：`store.entry(` 的实参必须直接含 `domain_key(`，或是同文件里由 `domain_key(`
  // 赋值的变量（两跳，形态与 check-system-bin 的 C 组同思路）。
  for (const m of clean.matchAll(/store\.entry\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const bal = balanced(clean, open);
    const arg = bal ? bal[0].trim() : '';
    let ok = arg.includes('domain_key');
    if (!ok) {
      const ident = /^([A-Za-z_][A-Za-z0-9_]*)/.exec(arg);
      if (ident) {
        ok = new RegExp(`let\\s+${ident[1]}\\s*=\\s*[^;]*domain_key\\s*\\(`).test(clean);
      }
    }
    if (!ok) {
      out.push(`自建快照表 store.entry 的槽键未带域（domain_key）@${m.index}`);
    }
  }
  return out;
}

const READ_CALL = /(?:std::fs::)?read_to_string\s*\(|std::fs::read\s*\(/g;

/** N4：`.reg` 内容的文本读取必须经编码感知的 read_reg_text_file。
 *  判据：任一 `read_to_string(` / `fs::read(` 调用，其 ±2 行窗口的**代码**里出现
 *  `.reg` 字面量 ⇒ 该读取点就在读 .reg 却没走唯一入口（UTF-16 的 .reg 用 UTF-8 读必炸）。
 *  实现要点：调用位置取自剥注释文本（注释提及不算数），但 `.reg` 字面量只存在于
 *  **未剥**的源码里（strip 会把字符串换成 `""`）——窗口回读原文、滤掉纯注释行后再判。 */
function regReaderViolations(clean, original = clean) {
  const out = [];
  const origLines = original.split('\n');
  for (const m of clean.matchAll(READ_CALL)) {
    const lineNo = clean.slice(0, m.index).split('\n').length - 1;
    const win = origLines
      .slice(Math.max(0, lineNo - 2), lineNo + 3)
      .filter((l) => !l.trim().startsWith('//'))
      .join('\n');
    if (/\.reg["']/.test(win) || /["']\.reg/.test(win)) out.push(`读 .reg 文本未走 read_reg_text_file @${lineNo + 1}`);
  }
  return out;
}

// ---------- N9：快照表跨窗顶账的三种可机检形态（X-1 同批，2026-10-15） ----------
// 背景（X-1，§5.25 同族）：cleanup 的扫描快照表是全局 HashMap<label, …>，而
// cleanup_scan 档位 guard_readonly（APP_WINDOWS 四个 label 都能调）——任何「整表替换」
// 都会把其它窗口的槽清空，对方已扫条目执行时全报「不是最近一次扫描结果」。
// 三条判据各有各守的形态：
//   A（origin 字面量闸）：`residue_snapshot_put` 第二实参（origin）必须是**字符串字面量**
//     ——dead.rs 按 `origin != Some(origin)` 分桶替换，origin 非编译期字面量时替换语义
//     退化成累加（v4 P2-F 事故形态）。判据跑**原文**：剥字符串后只剩 `""`，
//     字面量与变量的区分就在引号本身；空字面量 `""` 同样判红（空 origin 等于无分桶）。
//   B（取用点登记闸）：CLEANUP 快照表的每个取用点（`snapshots()…lock()`）必须登记在
//     下方表内——表外新增即红（新取用点必须有人确认它只动本槽）。登记键
//     `{file, anchor}`（§5.19 禁行号）：锚点命中 0 处（被改/被移）或 ≥2 处
//     （锚点不够判别性）都判红。
//   C（反合并声明）：两张表的 static 声明必须仍在各自文件（RESIDUE 在
//     uninstall/helpers.rs、CLEANUP 在 cleanup/state.rs）——任一消失即红并追问
//     「被合进 engine::snapshot 了吗？槽键现在带域（domain_key）吗？」
//     （§5.25 那类「合并丢维度」唯一可机检的形态）。
//
// 三个已知失明/假阳性形态（写判据时踩过，勿放宽）：
//   ① `snapshots(` 不加前缀守卫会命中 `residue_snapshots()` / `fn snapshots()` 定义
//      ——本组用「域前缀限定 + 取用点必须带 .lock()」两个条件排除；
//   ② 取用点扫描必须跑在 stripRust() 之后（本脚本已立该纪律），否则 command/state.rs
//      里「只提及不使用」的注释会自撞；
//   ③ `commands/finder.rs` 也有同名 `fn snapshots()`（它自己的 FINDER_SNAPSHOTS 表）
//      ——B 组**按 `commands/cleanup/` 前缀限定**，别卷进 finder 的表；这条限定是
//      刻意写死的有意排除，不是正则 bug，勿放宽。

/** N9-A：residue_snapshot_put 第二实参必须是字符串字面量（跑原文，见段注释） */
function n9OriginLiteralIssues(raw) {
  const out = [];
  for (const m of raw.matchAll(/residue_snapshot_put\s*\(/g)) {
    const lineStart = raw.lastIndexOf('\n', m.index - 1) + 1;
    if (raw.slice(lineStart, m.index).includes('//')) continue; // 行注释里的提及不算数
    const pre = raw.slice(Math.max(0, m.index - 24), m.index);
    if (/fn\s+$/.test(pre)) continue; // 函数定义不是调用点
    // 锚定到**本次调用的实参表**（^ 起于调用自己的 `(`）——不锚定的话窗口会滑到后续
    // 代码里别的 `(…, "…")`，把变量实参放行（本门禁首跑自犯：改走变量仍判绿）。
    const open = m.index + m[0].length - 1; // 本次调用的 `(`
    const after = raw.slice(open + 1, open + 160);
    if (!/^\s*[^,]{1,120},\s*"(?!")/.test(after)) {
      out.push(`residue_snapshot_put 第二实参不是字符串字面量（origin 须为编译期字面量，否则分桶替换退化成累加）@字节 ${m.index}`);
    }
  }
  return out;
}

/** N9-B：登记锚点必须恰好命中 1 处（0=被改/被移，≥2=锚点不够判别性） */
function n9AnchorIssue(raw, anchor) {
  const n = raw.split(anchor).length - 1;
  if (n === 0) return `登记锚点未命中（0 处）——被改/被移？锚点：${anchor.slice(0, 60)}…`;
  if (n > 1) return `登记锚点命中 ${n} 处（应恰 1）——扩长锚点或改计数判据：${anchor.slice(0, 60)}…`;
  return null;
}

/** N9-C：跨窗快照表的 static 声明必须仍在各自文件（readFile 可注入，供对照样本） */
function n9TableDeclIssues(readFile, entries) {
  const out = [];
  for (const e of entries) {
    const text = readFile(e.file);
    if (text === null || text === undefined) {
      out.push(`${e.file} 读不到 —— 文件被搬走了？`);
      continue;
    }
    if (!stripRust(text).includes(`static ${e.token}`)) {
      out.push(`${e.file} 的 ${e.token}（${e.name}）声明不见了 —— 被合进 engine::snapshot 了吗？槽键现在带域（domain_key）吗？`);
    }
  }
  return out;
}

/** N9-B 登记表：CLEANUP 快照表的六个取用点（{file, anchor}，§5.19 禁行号）。
 *  锚点选择：两处 `let snapshot = snapshots()` 与两处 `let buckets = …` 同形，
 *  用**前一行上下文**或**精确缩进（含前导换行）**扩到唯一——裸缩进子串会被
 *  更深的缩进版吞掉。 */
const CLEANUP_SNAPSHOT_SITES = [
  { file: 'src-tauri/src/commands/cleanup/scan_execute.rs', anchor: 'let mut guard = snapshots().lock()' },
  { file: 'src-tauri/src/commands/cleanup/scan_execute.rs', anchor: 'let auto_rebuild = auto_rebuild.unwrap_or(false);\n    let snapshot = snapshots()' },
  { file: 'src-tauri/src/commands/cleanup/scan_execute.rs', anchor: '.insert(label.clone(), HashMap::new());' },
  { file: 'src-tauri/src/commands/cleanup/scan_execute.rs', anchor: '\n        let buckets = snapshots().lock().unwrap_or_else(|e| e.into_inner());' },
  { file: 'src-tauri/src/commands/cleanup/scan_execute.rs', anchor: '\n            let buckets = snapshots().lock().unwrap_or_else(|e| e.into_inner());' },
  { file: 'src-tauri/src/commands/cleanup/scan_execute.rs', anchor: 'let label = window.label().to_string();\n    let snapshot = snapshots()' },
];
/** N9-C 登记表：两张跨窗快照表（与取它的访问器同文件，注释见 helpers.rs 头） */
const SNAPSHOT_TABLES = [
  { file: 'src-tauri/src/commands/uninstall/helpers.rs', token: 'RESIDUE_SNAPSHOTS', name: '残留执行快照表' },
  { file: 'src-tauri/src/commands/cleanup/state.rs', token: 'CLEANUP_SNAPSHOTS', name: '清理执行快照表' },
];
/** N9-B 取用点形态：`snapshots()` 之后 60 字符窗口内出现 `.lock()` */
const SNAPSHOT_LOCK_CALL = /snapshots\(\)[\s\S]{0,60}?\.lock\(\)/g;

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 原生层卫生门禁（N1 裸 output / N2 定长解码 / N3 句柄丢弃 / N4 .reg 读取 / N5 模块可达性 / N6 深度护栏 / N7 取最新唯一 / N8 快照域 / N9 快照表顶账）===\n');

// ---- 正向对照自检 ----
{
  const POSITIVE_CONTROLS = {
    bad: 'let o = quiet_cmd(system_tool("x")).arg("y").output();\n' +      // N1
      'let s = String::from_utf16_lossy(&pe.szExeFile);\n' +               // N2
      'if OpenProcess(PROCESS_ALL_ACCESS, false, pid).is_ok() { }\n',      // N3
    good: 'let o = crate::engine::systembin::quiet_cmd_timeout(system_tool("x"), &[], T)?;\n' +
      'let s = wide_str(pe.szExeFile.as_ptr());\n' +
      'let h = match OpenProcess(PROCESS_TERMINATE, false, pid) { Ok(h) => h, Err(_) => return };\n' +
      'if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() { }\n', // out-param 合法
  };
  const badV = hygieneViolations(stripRust('// quiet_cmd(system_tool("x")).output() 是旧形态（注释不算数）\n' + POSITIVE_CONTROLS.bad));
  const goodV = hygieneViolations(POSITIVE_CONTROLS.good);
  check(badV.length >= 3, `对照N1-N3a：三类违例样本合计命中 ${badV.length} 条（应 ≥3；注释里的提及不算数）`);
  check(goodV.length === 0, '对照N1-N3b：合规样本（timeout 版 / wide_str / match 接句柄 / out-param）全部放行', goodV.join('；'));
  // N8 判定器：裸 label 槽必须判红、domain_key 槽必须放行
  check(
    hygieneViolations('snapshot::set(&label, map);').some((v) => v.includes('domain_key')),
    '对照N8a：裸 label 槽的 snapshot 调用必须判红',
  );
  check(
    hygieneViolations('snapshot::set(&snapshot::domain_key(&label, "startup"), map);').length === 0,
    '对照N8b：domain_key 限定的调用必须放行',
  );
  // N8c（K09）：自建快照表裸 label 槽必须判红；domain_key 直接实参 / 两跳变量放行
  check(
    hygieneViolations('let slot = store.entry(label.to_string()).or_default();').some((v) => v.includes('自建快照表')),
    '对照N8c：自建快照表裸 label 槽必须判红',
  );
  check(
    hygieneViolations('let slot = store.entry(crate::engine::snapshot::domain_key(label, ty)).or_default();').length === 0
      && hygieneViolations(
        'let slot_key = crate::engine::snapshot::domain_key(label, ty);\nlet slot = store.entry(slot_key.clone()).or_default();',
      ).length === 0,
    '对照N8d：domain_key 直接实参 / 两跳变量都放行',
  );
  // N4 判定器：同窗口代码出现 .reg 的读取必须判红；JSON 清单读取不得假红
  check(
    regReaderViolations(
      stripRust('let Ok(text) = std::fs::read_to_string(&p) else { continue };\nif name.ends_with(".reg") { use_text(text); }'),
      'let Ok(text) = std::fs::read_to_string(&p) else { continue };\nif name.ends_with(".reg") { use_text(text); }',
    ).length === 1,
    '对照N4a：读 .reg 文本的样本判红',
  );
  check(
    regReaderViolations(stripRust('let Ok(text) = std::fs::read_to_string(&manifest_path) else { continue };\nlet Ok(v) = serde_json::from_str::<Value>(&text) else { continue };')) .length === 0,
    '对照N4b：JSON 清单读取不假红',
  );
  // N9 判定器：A（origin 字面量）/ B（锚点唯一性）/ C（表声明在位）
  check(
    n9OriginLiteralIssues('residue_snapshot_put(&label, origin_var, findings);').length === 1,
    '对照N9a：origin 第二实参传变量必须判红',
  );
  check(
    n9OriginLiteralIssues('residue_snapshot_put(&label, "app", findings);').length === 0
      && n9OriginLiteralIssues('residue_snapshot_put(&label, "", findings);').length === 1,
    '对照N9b：字面量放行、空字面量判红（空 origin 等于无分桶）',
  );
  check(
    n9AnchorIssue('a a b', 'a') !== null && n9AnchorIssue('a b', 'a') === null && n9AnchorIssue('x', 'a') !== null,
    '对照N9c：锚点 0 处 / ≥2 处判红、恰 1 处放行',
  );
  check(
    n9TableDeclIssues(
      (f) => (f === 'ok.rs' ? 'pub(super) static RESIDUE_SNAPSHOTS: X = Y;' : null),
      [{ file: 'ok.rs', token: 'RESIDUE_SNAPSHOTS' }, { file: 'gone.rs', token: 'RESIDUE_SNAPSHOTS' }],
    ).length === 1,
    '对照N9d：表声明在位放行；缺失/文件读不到判红',
  );
}

const g = gate(import.meta.url);

// ---- 真仓扫描 ----
const files = [];
for (const root of ROOTS) for (const f of walkRs(root)) files.push(f);

let n1 = 0;
let n2 = 0;
let n3 = 0;
let n4 = 0;
let n8viol = 0;
let n8sites = 0;
let n9locks = 0;
for (const f of files) {
  const rel = relative(ROOT, f).replace(/\\/g, '/');
  const original = readFileSync(f, 'utf8');
  const clean = stripRust(original);
  n8sites += [...clean.matchAll(/snapshot::(?:set|get|clear)\s*\(/g)].length;
  for (const v of hygieneViolations(clean)) {
    if (v.startsWith('裸 quiet_cmd')) n1++;
    else if (v.startsWith('定长 UTF-16')) n2++;
    else if (v.startsWith('snapshot 调用')) n8viol++;
    else n3++;
    g.fail(`${rel}: ${v}`);
  }
  // N4：.reg 文本读取唯一入口 —— 同语句窗口的代码里出现 .reg 判定的读取点一律红
  for (const v of regReaderViolations(clean, original)) {
    n4++;
    g.fail(`${rel}: ${v}`);
  }
}

// N5 模块可达性：所有 .rs 必须被某个 mod 声明链覆盖
const declared = new Set();
for (const f of files) {
  const dir = dirname(f);
  const text = readFileSync(f, 'utf8');
  for (const m of text.matchAll(/^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z_][a-z0-9_]*)\s*;/gm)) {
    const modPath = join(dir, `${m[1]}.rs`);
    const modDir = join(dir, m[1], 'mod.rs');
    if (existsSync(modPath)) declared.add(modPath);
    else if (existsSync(modDir)) declared.add(modDir);
  }
}
const unreachable = files.filter((f) => !declared.has(f) && !f.endsWith('lib.rs') && !f.endsWith('main.rs'));
for (const f of unreachable) g.fail(`${relative(ROOT, f).replace(/\\/g, '/')}：没有任何 mod 声明链可达（不在编译面/不在可达面）`);

// ---- N6/N7（P3-5，R5-G-9/G-5）：登记式棘轮（防回退，不是全覆盖） ----
// N6：两条已收口的递归遍历必须保留深度常量 ——
// 这是「DFS 必须有深度上限或登记豁免」的登记面；新增递归遍历时把文件登记进来。
// v5-K07 批次 9：断言改**真名**——旧断言 includes('MAX_WALK_DEPTH') 对 cleanup.rs
// 的命中完全来自两条注释（代码真名 ENGINE_WALK_MAX_DEPTH 不含该子串：MAX 与 WALK
// 顺序相反），删掉真护栏它照绿（probe-n6-n3 三态实测的假绿新形态）；对
// cleanup_scan.rs 则是真命中（crate::scan::MAX_WALK_DEPTH）。按登记点分别钉真名。
const WALK_DEPTH_SITES = [
  { file: 'src-tauri/src/engine/native/cleanup.rs', name: '执行侧删除遍历', token: 'ENGINE_WALK_MAX_DEPTH' },
  { file: 'native-scanner/src/cleanup_scan.rs', name: '清理扫描遍历（两处递归共用）', token: 'MAX_WALK_DEPTH' },
  // v7.2-C03（N1a-L04）：第三个深度上限入棘轮——fileKeys 快照遍历对齐 PS -Depth 24，
  // 与工程护栏 MAX_WALK_DEPTH 目的不同、数值不同，但同样是「删掉判据门禁照绿」的假绿面。
  { file: 'native-scanner/src/cleanup_scan.rs', name: 'fileKeys 快照遍历（对齐 PS -Depth 24）', token: 'FK_SNAPSHOT_MAX_DEPTH' },
  // v7.2-C06（R5b-M13）：顽固软件治理的计划任务 DFS 此前无上限、不查重解析点，且不在 N6 面。
  { file: 'src-tauri/src/engine/native/process.rs', name: '顽固软件计划任务 DFS', token: 'STUBBORN_TASKS_MAX_DEPTH' },
];
for (const s of WALK_DEPTH_SITES) {
  const f = join(ROOT, s.file);
  const text = existsSync(f) ? readFileSync(f, 'utf8') : '';
  if (!text.includes(s.token)) g.fail(`N6：${s.file}（${s.name}）不再引用 ${s.token} —— 深度护栏被移除？`);
}
// N7：按 mtime 取最新的实现唯一化 —— 现算唯一实现是 startup::pick_newest_file；
// 新出现同名职责函数（fn *newest*/*latest*）即红，须复用或在登记表加一条理由。
// v6-P2：stripRust 修好 raw-string 吞段后，测试区里的用例名（如
// ledger_takes_the_newest_copy_not_the_new_root）也会被看见——N7 守的是**生产**
// 实现唯一性，测试区与 N10 同口径在首个 #[cfg(test)] 处切割。
const NEWEST_FN = /fn\s+\w*(?:newest|latest)\w*\s*\(/g;
function stripRustProduction(src) {
  const cut = src.search(/^\s*#\s*\[cfg\(test\)\]/m);
  return stripRust(cut === -1 ? src : src.slice(0, cut));
}
let n7sites = 0;
{
  const found = [];
  for (const f of files) {
    const rel = relative(ROOT, f).replace(/\\/g, '/');
    const clean = stripRustProduction(readFileSync(f, 'utf8'));
    for (const m of clean.matchAll(NEWEST_FN)) {
      found.push(`${rel}: ${m[0].trim()}`);
    }
  }
  n7sites = found.length;
  const unexpected = found.filter((x) => !x.includes('native/common.rs: fn pick_newest_file'));
  if (unexpected.length) g.fail(`N7：出现新的「取最新」实现（应复用 pick_newest_file 或在此登记理由）：${unexpected.join('；')}`);
  if (!found.some((x) => x.includes('pick_newest_file'))) g.fail('N7：pick_newest_file 没找到（扫描面或改名漂移）');
}

// ---- N9（X-1 同批，2026-10-15）：快照表跨窗顶账的三种形态 ----
// A：origin 字面量闸（uninstall 域；跑原文——字符串剥后只剩空壳，判据字节级见段注释）
{
  const uninstallDomain = files.filter((f) =>
    relative(ROOT, f).replace(/\\/g, '/').startsWith('src-tauri/src/commands/uninstall/'),
  );
  for (const f of uninstallDomain) {
    for (const v of n9OriginLiteralIssues(readFileSync(f, 'utf8'))) {
      g.fail(`${relative(ROOT, f).replace(/\\/g, '/')}: ${v}`);
    }
  }
}
// B：CLEANUP 快照取用点登记闸（**按 commands/cleanup/ 前缀限定**——finder.rs 有同名
//    访问器 fn snapshots()，它是自己的表，刻意不卷进来，见段注释 ③）
{
  const cleanupDomain = files.filter((f) =>
    relative(ROOT, f).replace(/\\/g, '/').startsWith('src-tauri/src/commands/cleanup/'),
  );
  for (const f of cleanupDomain) {
    n9locks += [...stripRust(readFileSync(f, 'utf8')).matchAll(SNAPSHOT_LOCK_CALL)].length;
  }
  if (n9locks !== CLEANUP_SNAPSHOT_SITES.length) {
    g.fail(
      `N9-B：CLEANUP 快照取用点现算 ${n9locks} 处 ≠ 登记 ${CLEANUP_SNAPSHOT_SITES.length} 条 —— ` +
        '表外新增/删除必须同步登记并确认「只动本槽」（X-1：整表替换会清掉其它窗口的槽）',
    );
  }
  for (const s of CLEANUP_SNAPSHOT_SITES) {
    const raw = readFileSync(join(ROOT, s.file), 'utf8');
    const issue = n9AnchorIssue(raw, s.anchor);
    if (issue) g.fail(`N9-B：${s.file} —— ${issue}`);
  }
}
// C：两表 static 声明反合并声明（消失即追问：被合进 engine::snapshot 了吗？槽键带域吗？）
{
  const readRel = (rel) => {
    const abs = join(ROOT, rel);
    return existsSync(abs) ? readFileSync(abs, 'utf8') : null;
  };
  for (const v of n9TableDeclIssues(readRel, SNAPSHOT_TABLES)) {
    g.fail(`N9-C：${v}`);
  }
}

// ---- N10（v6-P2，R5/A5 panic 族）：生产面 panic/unwrap 登记棘轮 ----
// 口径：src-tauri/src + native-scanner/src 的**生产代码**（首个 #[cfg(test)] 之后不算、
// 注释不算——stripRust 已剥）出现 `.unwrap()/.expect(/panic!(/unreachable!(/todo!(
// /unimplemented!(` ⇒ 必须逐文件登记（{file, count, reason}），计数对不上即红——
// 「登记后偷偷加一处」与「登记后偷偷删一处（登记失效信号）」都拦。
// 现存 7 处全部是登记例外：util.rs 的 panic 是**编译期** const 布局断言（只在编译错
// 时触发）；lib.rs 的 expect 是启动期窗口/运行时创建（无 UI 可落，fail-fast 唯一选择）；
// 三份生成器产物 JSON 的 expect 由 contract_tests 钉住合法性（对 build 产物 fail-fast 正确）。
// 其余生产 unwrap 已在 P2 批全部结构化消灭（services/fileclean/contextmenu/bcd/
// game_platform_orphan 五处：match/filter_map/let-else/&'static str 收紧）。
const PANIC_RE = /\.unwrap\(\)|\.expect\(|panic!\(|unreachable!\(|todo!\(|unimplemented!\(/;
function panicViolations(src) {
  const out = [];
  const lines = src.split('\n');
  let inTest = false;
  lines.forEach((l, i) => {
    if (/^\s*#\s*\[cfg\(test\)\]/.test(l)) inTest = true;
    if (inTest) return;
    if (PANIC_RE.test(l)) out.push({ line: i + 1, snippet: l.trim().slice(0, 80) });
  });
  return out;
}
{
  // 正向对照：合成样本——生产区命中、注释与测试区不算、干净样本零误报
  const sample = [
    'fn a(x: Option<u8>) -> u8 { x.unwrap() }',
    '/// 注释里的 unwrap() 与 expect( 不算',
    '#[cfg(test)]',
    'mod t { fn b() { let y = v.expect("x"); } }',
  ].join('\n');
  const vs = panicViolations(sample);
  if (vs.length !== 1) g.fail(`N10 对照a：合成样本必须恰好命中 1 处（实得 ${vs.length}）`);
  if (!/unwrap/.test(vs[0]?.snippet || '')) g.fail(`N10 对照a：命中的应是生产区那行（实得 ${JSON.stringify(vs[0])}）`);
  if (panicViolations('fn c(r: Result<u8, E>) -> Option<u8> { r.ok() }').length !== 0) {
    g.fail('N10 对照b：干净样本不得误报');
  }
}
const PANIC_ALLOW = [
  { file: 'native-scanner/src/util.rs', count: 3, reason: '编译期 const 布局断言（RM_PROCESS_INFO 668/12/652），panic 只可能发生在编译错' },
  { file: 'src-tauri/src/lib.rs', count: 2, reason: '启动期 main 窗口创建 / Tauri 运行时构建失败——无 UI 可落，fail-fast 是唯一选择' },
  { file: 'src-tauri/src/commands/cleanup/rules.rs', count: 1, reason: '生成器产物 cleanup-postactions.json 的 expect，合法性由 contract_tests 钉住（对 build 产物 fail-fast 正确）' },
  { file: 'src-tauri/src/commands/maintenance.rs', count: 1, reason: '生成器产物 maintenance-tasks.json 的 expect，同上' },
  { file: 'src-tauri/src/commands/optimizer/subitems.rs', count: 1, reason: '生成器产物 optimizer-subitems.json 的 expect，同上' },
];
{
  const counts = new Map();
  for (const f of files) {
    const rel = relative(ROOT, f).replace(/\\/g, '/');
    // 整文件测试模块的豁免：`#[cfg(test)] mod contract_tests;` 的 cfg 属性挂在
    // mod.rs 的声明上、不在文件内，行级切割看不见——按命名约定（*_tests.rs）
    // 识别。新形态出现（不叫 *_tests.rs 的整文件测试模块）会被 N10 当生产面
    // 未登记点名，届时改命名或在这里补规则——两个方向都必须被看见。
    if (/_tests\.rs$/.test(rel)) continue;
    const vs = panicViolations(stripRust(readFileSync(f, 'utf8')));
    if (vs.length) counts.set(rel, vs);
  }
  for (const [rel, vs] of counts) {
    const allow = PANIC_ALLOW.find((a) => a.file === rel);
    if (!allow) {
      g.fail(
        `N10：${rel} 生产面出现 ${vs.length} 处 panic/unwrap（未登记）——改为 fail-closed ` +
          `（match/filter_map/let-else）或在 PANIC_ALLOW 登记理由；首处 L${vs[0].line} ${vs[0].snippet}`,
      );
    } else if (allow.count !== vs.length) {
      g.fail(`N10：${rel} panic/unwrap 现算 ${vs.length} ≠ 登记 ${allow.count}（增删都必须同步本表）——${allow.reason}`);
    }
  }
  for (const a of PANIC_ALLOW) {
    if (!counts.has(a.file)) {
      g.fail(`N10：${a.file} 登记了 ${a.count} 处但现算为 0 —— 判据失明或代码已改（同步本表）：${a.reason}`);
    }
  }
}

// ---- N11（v7.2 C02，R5a-K02）：右键/启动域 Reg*/rename 写点必须过容器准入 ----
// 口径：contextmenu.rs / startup.rs（C02 文件面）里，凡函数体含 Reg 写系调用
// （RegSetValueExW/RegDeleteValueW/RegRenameKey/RegCreateKeyExW）或 std::fs::rename，
// 函数体必须同时出现一个容器准入 verdict 调用，或在 N11_ALLOW 逐条登记（含理由）。
// 这是「写侧准入」的点名棘轮：新增写点函数不带闸即红；把闸从函数里删掉也红。
const N11_WRITE_RE = /RegSetValueExW\(|RegDeleteValueW\(|RegRenameKey\(|RegCreateKeyExW\(|fs::rename\(/;
const N11_VERDICT_RE = /cm_registry_container_ok\(|cm_winx_root_ok\(|cm_sendto_root_ok\(|registry_container_verdict\(|folder_source_verdict\(|folder_restore_verdict\(|backup_in_root_verdict\(|backup_victim_within_root\(/;
const N11_FILES = [
  'src-tauri/src/engine/native/contextmenu.rs',
  'src-tauri/src/engine/native/startup.rs',
];
/** 例外登记：{file, fn, reason}。只收「天然 contained」的形状（固定键/常量落点）。 */
const N11_ALLOW = [
  { file: 'src-tauri/src/engine/native/contextmenu.rs', fn: 'toggle_cm_item', reason: '屏蔽表臂写固定键 Shell Extensions\\Blocked 且值名过 is_guid——天然 contained（winx/filesystem/registry 各臂已有 verdict）' },
  { file: 'src-tauri/src/engine/native/startup.rs', fn: 'set_approved_bit', reason: '写 StartupApproved 固定子键（approved_subkey 白名单产出），值名来自台账但键面固定' },
  { file: 'src-tauri/src/engine/native/startup.rs', fn: 'startup_add', reason: '新增启动项写固定键 HKCU\\...\\CurrentVersion\\Run（key 为常量字面量），值名/值数据是用户显式输入的产品功能面' },
];
/** 把 Rust 源按 fn 边界粗切成 {name, body}（含 fn 头行到下一个 fn 头之前）。 */
function rustFns(src) {
  const lines = src.split('\n');
  const fns = [];
  let cur = null;
  for (const l of lines) {
    const m = /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)/.exec(l);
    if (m) {
      if (cur) fns.push(cur);
      cur = { name: m[1], body: l };
    } else if (cur) {
      cur.body += '\n' + l;
    }
  }
  if (cur) fns.push(cur);
  return fns;
}
{
  // 正向对照（判定器自证）：
  const guarded = 'fn a() { registry_container_verdict("HKCU", "x")?; RegSetValueExW(h, p, Some(0), REG_SZ, Some(&b)); }';
  const naked = 'fn b() { RegSetValueExW(h, p, Some(0), REG_SZ, Some(&b)); }';
  const ok1 = rustFns(guarded).every((f) => !N11_WRITE_RE.test(f.body) || N11_VERDICT_RE.test(f.body));
  const ok2 = rustFns(naked).every((f) => !N11_WRITE_RE.test(f.body) || N11_VERDICT_RE.test(f.body));
  if (!ok1) g.fail('N11 对照a：带闸样本必须放行');
  if (ok2) g.fail('N11 对照b：裸写样本必须判红');
  if (!N11_WRITE_RE.test('let _ = std::fs::rename(a, b);')) g.fail('N11 对照c：rename 写点必须被识别');
  // 真仓扫描
  for (const rel of N11_FILES) {
    const f = join(ROOT, rel);
    if (!existsSync(f)) { g.fail(`N11：${rel} 读不到（文件面漂移，同步 N11_FILES）`); continue; }
    const src = stripRust(readFileSync(f, 'utf8'));
    for (const fn of rustFns(src)) {
      if (!N11_WRITE_RE.test(fn.body) || N11_VERDICT_RE.test(fn.body)) continue;
      const allow = N11_ALLOW.find((a) => a.file === rel && a.fn === fn.name);
      if (!allow) {
        g.fail(`N11：${rel}::${fn.name} 含 Reg*/rename 写点但没有容器准入闸（cm_registry_container_ok/` +
          `cm_winx_root_ok/cm_sendto_root_ok/registry_container_verdict/folder_*_verdict/backup_*）——` +
          `补闸或在 N11_ALLOW 登记理由`);
      }
    }
    for (const a of N11_ALLOW.filter((x) => x.file === rel)) {
      const fns = rustFns(src);
      if (!fns.some((f) => f.name === a.fn && N11_WRITE_RE.test(f.body))) {
        g.fail(`N11：${rel}::${a.fn} 登记了例外但现算无写点（代码已改或判据失明）——${a.reason}`);
      }
    }
  }
}

// 扫描面地板：源文件数过少 ⇒ walkRs 失明；快照调用点命中过少 ⇒ N8 语料失明；
// CLEANUP 取用点命中过少 ⇒ N9-B 语料失明（N9 取用点本应 ≥6，命中 0~5 即正则/域前缀出事）
if (files.length < 50) g.fail(`扫描面只有 ${files.length} 个 .rs（< 50）⇒ 疑似 root 失明`);
if (n8sites < 10) g.fail(`snapshot 调用点命中 ${n8sites} 处（< 10）⇒ N8 语料/正则失明`);
if (n9locks < 6) g.fail(`CLEANUP 快照取用点命中 ${n9locks} 处（< 6）⇒ N9-B 语料/正则失明`);

console.log(
  `\n扫描：${files.length} 个 .rs · 违例 N1=${n1} / N2=${n2} / N3=${n3} / N4=${n4} / N5=${unreachable.length} / N8=${n8viol} · N8 语料 ${n8sites} 处 · N9 取用点 ${n9locks} 处（登记 ${CLEANUP_SNAPSHOT_SITES.length}）· 登记点 N6=${WALK_DEPTH_SITES.length} / N7=${n7sites}`,
);
if (fail > 0) {
  console.error(`check-native-hygiene: 正向对照自检 ${fail} 处失败（判定器失效）`);
  process.exit(1);
}
if (g.failed > 0) process.exit(1); // 真仓扫描的判红也要带退出码（别只靠打印）
console.log('check-native-hygiene: 全部通过');
