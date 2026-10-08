#!/usr/bin/env node
// check-native-hygiene.mjs —— 原生层卫生门禁（P3-5，2026-10-09）
//
// 五条「找违规型」断言，各配**内置正向对照自检**（违例样本必须判红、合规样本必须放行，
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
//
// 判据全部先剥 Rust 注释与字符串字面量（文本提及不算数，与 check-delete-callsites 同口径）。
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
const HANDLE_APIS = /(?:FindFirstFileW|FindFirstVolumeW|CreateFileW|OpenProcess|CreateToolhelp32Snapshot|CreateEventW|CreateMutexW|CreateProcessW)\s*\(/g;

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

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 原生层卫生门禁（N1 裸 output / N2 定长解码 / N3 句柄丢弃 / N4 .reg 读取 / N5 模块可达性）===\n');

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
}

const g = gate(import.meta.url);

// ---- 真仓扫描 ----
const files = [];
for (const root of ROOTS) for (const f of walkRs(root)) files.push(f);

let n1 = 0;
let n2 = 0;
let n3 = 0;
let n4 = 0;
for (const f of files) {
  const rel = relative(ROOT, f).replace(/\\/g, '/');
  const original = readFileSync(f, 'utf8');
  const clean = stripRust(original);
  for (const v of hygieneViolations(clean)) {
    if (v.startsWith('裸 quiet_cmd')) n1++;
    else if (v.startsWith('定长 UTF-16')) n2++;
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

// 扫描面地板：源文件数过少 ⇒ walkRs 失明
if (files.length < 50) g.fail(`扫描面只有 ${files.length} 个 .rs（< 50）⇒ 疑似 root 失明`);

console.log(
  `\n扫描：${files.length} 个 .rs · 违例 N1=${n1} / N2=${n2} / N3=${n3} / N4=${n4} / N5=${unreachable.length}`,
);
if (fail > 0) {
  console.error(`check-native-hygiene: 正向对照自检 ${fail} 处失败（判定器失效）`);
  process.exit(1);
}
if (g.failed > 0) process.exit(1); // 真仓扫描的判红也要带退出码（别只靠打印）
console.log('check-native-hygiene: 全部通过');
