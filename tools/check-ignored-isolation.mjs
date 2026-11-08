'use strict';
// tools/check-ignored-isolation.mjs —— `#[ignore]` 真机探针的两道对账
//
// 第一道（B0，2026-10-24 重审 X1-K01）：`engine::paths::DATA_DIR` 是 `OnceLock` ——
// **谁先取根谁定死**。`src-tauri/tests/**` 的真机探针若不先调
// `tests/common/mod.rs::ensure_test_data_root()`，一旦它先跑到，同一测试二进制里
// 所有用例的数据根就退回真实 `%APPDATA%\com.xiaoxu.trim`，同批写型探针
// （settings / appearance / 注册表备份）随之落进用户目录。
// 该判据的作用范围刻意只到 `src-tauri/tests/**`：`ensure_test_data_root` /
// `probe_guard` / `MockRuntime` / `mock_builder` 是 tests 侧 helper，src 单元测试
// 没有这套底座，套过去只会得到「没有定根动作」的假红。
//
// 第二道（G0.1，2026-11-01 全仓重审）：`#[ignore]` 真机用例会真写注册表。
// 2026-11-01 之前的实现有两层假绿：
//   ① 只扫 `src-tauri/tests`，`R3b-K01` 所在的
//      `src-tauri/src/commands/optimizer/contract_tests.rs` 完全在射程外；
//   ② 判定读原文 `code`（未 blankNonCode），且函数体里出现 `created` / `original`
//      字样就放行 —— 注释里写一句就能洗白。
// 现在扫描 `src-tauri/src/**/*.rs` + `src-tauri/tests/**/*.rs`（递归，忽略 target），
// 判据作用在 `blankNonCode` 之后的**完整函数体**上：注释与字符串里的 `created` /
// `original` 无效；只有真语句才算恢复路径。
//
// 判定口径（非测试自有命名空间）：
//   - Drop 里实际回写原值（引用 self 派生值）⇒ 放行；
//   - Drop 里按 `created` 条件删除（`if !self.created { return; }` 或
//     `if created { delete }`）⇒ 放行；
//   - `original` 在 match / if 条件里参与回写或删除 ⇒ 放行；
//   - 函数体内按 `created` 条件删除 / 用 `original` 回写 ⇒ 放行。
// X1-K01 的形态必须判红：`let _guard = Cleanup;` 的 Drop **无条件删真实值**，
// 即使函数在前面提前 return 跳过，Drop 仍会执行 —— 这种「无 created 闸的
// Drop 删除」不是恢复路径。R3b-K01 的 `RestoreReg`（Drop + original）才是。
//
// 使用 `splitFunctions` 前先把非 ASCII 字符等长替换成 `x`：共享件
// `tools/lib/src-scan.mjs` 的 Rust 函数名正则只认 `[A-Za-z0-9_]`，
// `fn 真机_...` 与 `fn m2_删除...` 会被截断或整个漏掉。替换保持长度不变，
// 偏移仍对应原文，真实名字从原文函数签名里取。共享件本身不动。
//
// 用法：node tools/check-ignored-isolation.mjs

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gate } from './lib/gate.mjs';
import { blankNonCode, splitFunctions, lineAt, skipBraces } from './lib/src-scan.mjs';

// 仓根由本文件位置推出，不用 `process.cwd()`：在 src-tauri/ 下单跑会「判据对象消失」
// 假红（T1b-L01 实测 rc=1，四处不一致全是路径算出来的）。
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TESTS = join(ROOT, 'src-tauri', 'tests');
const SRC = join(ROOT, 'src-tauri', 'src');
// 幂等放行：这些写法本身就会先定根（`common/mod.rs` 的 runtime 构造路径）。
// ⚠ 不要用 `rt(` 当判据：它是 `alert(` / `insert(` / `sort(` 的子串，会把一切探针都放行
//   （首版就因此把 `startup_scan_real_count_vs_writer_cap_probe` 误判成「已隔离」）。
const ISOLATED = ['ensure_test_data_root(', 'probe_guard(', 'MockRuntime', 'mock_builder'];
const LIB_REF = /trim_tauri_lib\s*::|app_data_dir\s*\(/;
// 对象地板：2026-11-01 全仓现算 100 条（src 76 / tests 24）。
// 取 90 的理由：旧函数名正则（只认 ASCII）即使扫全仓也只能认出 81 条，
// 旧版只扫 tests 更只有 24 条 —— 地板必须高于 81，才能让任一旧解析回归判红；
// 同时低于 100，留出删除少量探针的余量。tests 侧另有 24 条下限。
const MIN_IGNORED_REPO = 90;
const MIN_IGNORED_TESTS = 24;

// 第一道判据的过渡豁免：只减不增。新增真机探针必须首语句自己定根。
const TRANSITION = [];

// 第二道判据的登记表：只收「自有 scratch + Drop 恢复」经人工确认、但静态判据
// 暂时表达不了的探针；双向咬合 —— 修好后仍挂着同样判红。当前 18 条命中全部
// 能由自有命名空间或 created/original 真语句放行，故为空。
const WRITE_GUARD_TRANSITION = [
  {
    rel: 'src-tauri/tests/module_smoke.rs',
    fn: 'cleanup_reg_backup_restore_shares_the_uninstall_domain_gates',
    batch: '2026-11-02 M条中危收口',
    reason: '夹具 .reg 内容只写进私有 tmp 文件供恢复链读取，从不执行 reg import；'
      + '文件内的 HKLM\\SOFTWARE / HKCU\\Software 正是被测的拒绝面（必须能构造出危险目标）。'
      + '用例自身有 Drop 清理两个夹具文件，无真实注册表副作用。',
  },
];

/** 递归收集 .rs 文件，忽略 target（构建产物里也有同名测试源码）。 */
function listRs(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'target') continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...listRs(p));
    else if (e.isFile() && e.name.endsWith('.rs')) out.push(p);
  }
  return out;
}

/** 取函数真实名字：共享件的名字正则会在中文/非 ASCII 处截断。 */
function fnName(code, fn) {
  const sig = code.slice(fn.start, fn.bodyStart);
  const m = /fn\s+([^\s(<{]+)/u.exec(sig);
  return m ? m[1] : fn.name;
}

/**
 * 收集一段源码里的 `#[ignore]` 函数。属性与函数按「属性之后的下一个 fn」绑定：
 * 不能按「fn 前 400 字内有属性」扫，否则 `impl Drop { fn drop }` 这类嵌套函数
 * 会继承外层测试的属性，既虚增对象数，也会把 Drop 体误当成独立用例。
 * @returns {Array<{abs:string,rel:string,code:string,blanked:string,lit:string,
 *   name:string,line:number,bodyCode:string,bodyLit:string,bodyStart:number,end:number}>}
 */
function scanSource(code, abs, rel) {
  const out = [];
  if (!code.includes('#[ignore')) return out;
  const blanked = blankNonCode(code, 'rs');
  const lit = blankNonCode(code, 'rs', { keepStrings: true });
  // 等长 ASCII 化：共享件的函数名正则只认 ASCII，中文函数名会被漏掉。
  const norm = blanked.replace(/[^\x00-\x7F]/g, 'x');
  const fns = splitFunctions(norm, 'rs');
  const attrRe = /#\[ignore[^\]]*\]/g;
  const seen = new Set();
  let m;
  while ((m = attrRe.exec(blanked))) {
    const fn = fns.find((x) => x.start > m.index);
    if (!fn || seen.has(fn.start)) continue; // 同一函数挂着多个属性时只算一条
    seen.add(fn.start);
    out.push({
      abs,
      rel,
      code,
      blanked,
      lit,
      name: fnName(code, fn),
      line: lineAt(code, fn.start),
      bodyCode: blanked.slice(fn.bodyStart, fn.end - 1),
      bodyLit: lit.slice(fn.bodyStart, fn.end - 1),
      bodyStart: fn.bodyStart,
      end: fn.end,
    });
  }
  return out;
}

function collectIgnored(files) {
  const out = [];
  for (const abs of files) {
    const code = readFileSync(abs, 'utf8');
    out.push(...scanSource(code, abs, relative(ROOT, abs).split('\\').join('/')));
  }
  return out;
}

// ==================== 第二道：注册表写守卫 ====================

// 注册表写原语。只认这些「写/删/建键/导入」入口：
//   - 产品链的 reg_restore_* / reg_key_* / reg_import_apply(_sections) /
//     reg_backup_restore(_guards) / restore_backup_values；
//   - 原生 Win32 的 RegSetValueExW / RegDeleteValueW / RegCreateKeyExW /
//     RegDeleteKeyExW / RegDeleteTreeW / RegRenameKey；
//   - `reg add|delete|import` 命令行（含本地 `reg_add` 闭包背后的 Command::new("reg")）。
// PFRO / 分页文件 / 电源方案等间接写不在本判据的「注册表值写」面内：它们的目标
// 不是值名/键名这一层，无法用「自有命名空间 / created / original」判定。
const HARD_WRITE = /\b(?:reg_restore_write(?:_checked)?|reg_restore_delete(?:_checked)?|reg_key_ensure(?:_checked)?|reg_key_remove(?:_checked)?|reg_import_apply(?:_sections)?|reg_backup_restore(?:_guards)?|restore_backup_values|RegSetValueExW|RegDeleteValueW|RegCreateKeyExW|RegDeleteKeyExW|RegDeleteTreeW|RegRenameKey)\s*\(/;
const STARTUP_WRITE = /\b(?:startup_toggle|startup_delete)\s*\(/;
const REG_CLI = /Command::new\s*\(\s*"reg(?:\.exe)?"\s*\)/;
const REG_CLI_MODE = /"(?:add|delete|import)"/;
const REG_SCRIPT = /\breg(?:\.exe)?\s+(?:add|delete|import)\b/i;
const DELETE_CALL = /\b(?:reg_restore_delete(?:_checked)?|reg_key_remove(?:_checked)?|RegDeleteValueW|RegDeleteKeyExW|RegDeleteTreeW)\s*\(/;
const WRITE_CALL = /\b(?:reg_restore_write(?:_checked)?|reg_import_apply(?:_sections)?|restore_backup_values|RegSetValueExW|RegCreateKeyExW)\s*\(/;

// 测试自有命名空间：`TrimProbe` / `Software\Trim...Probe` 等。只认两种「目标」：
//   ① 路径串自身带自有标记（`Software\TrimRestoreProbe`）；
//   ② 值名常量赋自有串（`const NAME = "TrimProbeToggleX"`）。
// 只在提示语里出现 `TrimProbe` 不算 —— 那可能是在给真实值名做文案。
const OWN_NS = /Trim[A-Za-z0-9_]*Probe/i;
const PATH_LIKE = /(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|Software|SOFTWARE|SYSTEM)\\/;

function stringLits(lit) {
  const out = [];
  const re = /"((?:\\.|[^"\\])*)"/g;
  let m;
  while ((m = re.exec(lit))) out.push(m[1]);
  return out;
}

function hasOwnTarget(lit) {
  for (const s of stringLits(lit)) {
    // 带空白的串多半是提示语；真实键路径/值名不含空白，不能让它充当自有目标。
    if (OWN_NS.test(s) && PATH_LIKE.test(s) && !/\s/.test(s)) return true;
  }
  const decl = /(?:\bconst\b|\bstatic\b|\blet\b)\s+[A-Za-z_][A-Za-z0-9_]*\s*(?::\s*[^=;]+)?=\s*r?"([^"]*)"/g;
  let m;
  while ((m = decl.exec(lit))) if (OWN_NS.test(m[1]) && !/\s/.test(m[1])) return true;
  return false;
}

function isContainerPath(s) {
  const un = s.trim().replace(/^\[/, '').replace(/\]$/, '')
    .replace(/^(?:HKEY_(?:CURRENT_USER|LOCAL_MACHINE|CLASSES_ROOT|USERS)|HKCU|HKLM|HKCR|HKU)\\/i, '');
  return /^(?:Software\\)?Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|Explorer\\StartupApproved\\(?:Run|Run32))$/i.test(un);
}

/**
 * 自有命名空间放行：函数里必须真的出现自有目标，且所有路径字面量都是
 * 自有 / 启动项容器 / 带 `{变量}` 的模板；reg.exe `/v` 的字面值名同样不得越界。
 * 只写 `TrimProbe*` 值名（容器键是系统 Run / StartupApproved）属于自有名字，放行。
 */
function ownScratchOnly(t) {
  const lit = t.bodyLit;
  if (!hasOwnTarget(lit)) return false;
  for (const s of stringLits(lit)) {
    if (!PATH_LIKE.test(s)) continue;
    if (OWN_NS.test(s) || isContainerPath(s) || s.includes('{')) continue;
    return false;
  }
  for (const m of lit.matchAll(/"\/v"\s*,\s*"([^"]*)"/g)) {
    if (OWN_NS.test(m[1]) || m[1].includes('{')) continue;
    return false;
  }
  // 直接调 reg_restore_* 时，容器键上的值名若是非自有字面量 ⇒ 不算「只写自有名字」。
  // 这一条堵的是「同函数里既写自有 scratch、又顺手写真实 Run 值」的混写形态。
  if (hasNonOwnValueOnContainer(t)) return false;
  return true;
}

/** 解析函数内 `const/static/let NAME = "字面量"`，供直接调用参数判别。 */
function localConsts(lit) {
  const map = new Map();
  const re = /(?:\bconst\b|\bstatic\b|\blet\b)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=;]+)?=\s*r?"((?:\\.|[^"\\])*)"/g;
  let m;
  while ((m = re.exec(lit))) map.set(m[1], m[2]);
  return map;
}

function resolveArg(arg, consts) {
  const t = arg.trim();
  const q = /^r?"((?:\\.|[^"\\])*)"$/.exec(t);
  if (q) return { kind: 'lit', value: q[1] };
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(t) && consts.has(t)) return { kind: 'lit', value: consts.get(t) };
  if (t.includes('{') || t.includes('format!')) return { kind: 'template' };
  return { kind: 'other' };
}

/** 代码视图找调用括号（字符串已抹白，括号计数安全）；字面量视图按同一偏移取参数。 */
function matchParen(code, open) {
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === '(') depth++;
    else if (code[i] === ')') { depth--; if (depth === 0) return i + 1; }
  }
  return code.length;
}

function splitTopArgs(lit) {
  const out = [];
  let depth = 0;
  let start = 0;
  let i = 0;
  while (i < lit.length) {
    const c = lit[i];
    if (c === '"') {
      i++;
      while (i < lit.length) {
        if (lit[i] === '\\') { i += 2; continue; }
        if (lit[i] === '"') { i++; break; }
        i++;
      }
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) { out.push(lit.slice(start, i)); start = i + 1; }
    i++;
  }
  out.push(lit.slice(start));
  return out;
}

function hasNonOwnValueOnContainer(t) {
  const consts = localConsts(t.bodyLit);
  const re = /\breg_restore_(?:write|delete)(?:_checked)?\s*\(/g;
  let m;
  while ((m = re.exec(t.bodyCode))) {
    const open = m.index + m[0].length - 1;
    const end = matchParen(t.bodyCode, open);
    const args = splitTopArgs(t.bodyLit.slice(open + 1, end - 1));
    if (args.length < 3) continue;
    const sub = resolveArg(args[1], consts);
    const val = resolveArg(args[2], consts);
    if (sub.kind === 'lit' && isContainerPath(sub.value)
      && val.kind === 'lit' && !OWN_NS.test(val.value) && !val.value.includes('{')) return true;
  }
  return false;
}

/** 函数体内所有 `impl Drop` 的 drop 体（代码视图与字面量视图，偏移对齐）。 */
function findDrops(t) {
  const out = [];
  const re = /\bimpl\s+Drop\s+for\s+[A-Za-z0-9_]+\s*\{/g;
  const slice = t.blanked.slice(t.bodyStart, t.end - 1);
  let m;
  while ((m = re.exec(slice))) {
    const open = t.bodyStart + m.index + m[0].length - 1;
    const end = skipBraces(t.blanked, open);
    const inner = t.blanked.slice(open + 1, end - 1);
    const fm = /\bfn\s+drop\s*\([^)]*\)\s*\{/.exec(inner);
    if (!fm) continue;
    const dOpen = open + 1 + fm.index + fm[0].length - 1;
    const dEnd = skipBraces(t.blanked, dOpen);
    out.push({
      code: t.blanked.slice(dOpen + 1, dEnd - 1),
      lit: t.lit.slice(dOpen + 1, dEnd - 1),
    });
  }
  return out;
}

function dropDeletes(lit) {
  return DELETE_CALL.test(lit)
    || (REG_CLI.test(lit) && /"delete"/.test(lit))
    || (REG_SCRIPT.test(lit) && /delete/i.test(lit));
}

function dropWrites(lit) {
  return WRITE_CALL.test(lit) || (REG_CLI.test(lit) && /"(?:add|import)"/.test(lit));
}

/**
 * `created` 必须出现在 if 条件里，且真的保护删除：
 *   - `if !self.created { return; }` ⇒ 同体后续删除受保护；
 *   - `if created { ... delete ... }` ⇒ 条件块内真的删。
 */
function createdGuardsDelete(code, lit) {
  if (/\bif\b[^{;]*!\s*(?:self\s*\.\s*)?created\b[^{]*\{[^}]*\breturn\b/.test(code)) return true;
  const m = /\bif\b[^{;]*\bcreated\b[^{]*\{/.exec(code);
  if (!m) return false;
  const open = m.index + m[0].length - 1;
  const end = skipBraces(code, open);
  return dropDeletes(lit.slice(open, end));
}

/** `original` 必须参与控制表达式（match / if），只做变量名不算。 */
function originalGuards(code) {
  return /\bmatch\s+[^/{;]*\boriginal\b/.test(code)
    || /\bif\s+let\s+[^{;]*\boriginal\b/.test(code)
    || /\bif\b[^{;]*\boriginal\b/.test(code);
}

/** 函数体内（不限于 Drop）按 created 条件删除。 */
function conditionalCreatedDelete(t) {
  return createdGuardsDelete(t.bodyCode, t.bodyLit);
}

/** 函数体内用 original 回写/删除：先读原值，之后在 match 或写删调用里使用。 */
function originalWriteback(t) {
  const hasRead = /\b(?:let|let mut)\s+original\b[^;]*\b(?:read|query|get)\w*\s*\(/.test(t.bodyCode);
  if (!hasRead) return false;
  const rest = t.bodyCode.replace(/\b(?:let|let mut)\s+original\b[^;]*;/g, '');
  return /\bmatch\b[^{;]*\boriginal\b/.test(rest)
    || /\b(?:reg_restore_write(?:_checked)?|reg_restore_delete(?:_checked)?|reg_key_remove(?:_checked)?|RegSetValueExW|RegDeleteValueW)\s*\([^;]*\boriginal\b/.test(rest);
}

/** 该函数是否触及本判据认定的注册表写面。 */
function registryWriteKinds(t) {
  const kinds = [];
  if (HARD_WRITE.test(t.bodyCode)) kinds.push('api');
  if (/\buninstall_reg_backup_restore\b/.test(t.bodyLit)) kinds.push('command');
  if (REG_CLI.test(t.bodyLit) && REG_CLI_MODE.test(t.bodyLit)) kinds.push('reg-cli');
  if (REG_SCRIPT.test(t.bodyLit)) kinds.push('reg-script');
  const startup = STARTUP_WRITE.test(t.bodyCode);
  if (startup && (/"registry"/.test(t.bodyLit) || /reg\|/.test(t.bodyLit) || /"valueName"|"regPath"|"hive"/.test(t.bodyLit) || REG_CLI.test(t.bodyLit) || REG_CLI_MODE.test(t.bodyLit))) {
    kinds.push('startup');
  }
  return kinds;
}

/**
 * 返回 `{ ok, reason }`。顺序：
 *   1. 自有命名空间（只写自有名字，Drop 删的也是它）⇒ 放行；
 *   2. 任一 Drop 无条件删真实值 ⇒ 判红（X1-K01；即使另有安全 Drop 也不抵消）；
 *   3. Drop 按 created 条件删 / 按 original 恢复 / 回写 self 派生值 ⇒ 放行；
 *   4. 函数体内 created 条件删除 / original 原值回写 ⇒ 放行；
 *   5. 其余 ⇒ 判红。
 */
function classifyWriteGuard(t) {
  if (ownScratchOnly(t)) return { ok: true, reason: '自有命名空间' };
  const drops = findDrops(t);
  let safe = null;
  let unguarded = null;
  for (const d of drops) {
    const deletes = dropDeletes(d.lit);
    const created = createdGuardsDelete(d.code, d.lit);
    const original = originalGuards(d.code);
    if (deletes && !created && !original) unguarded = d;
    else if (deletes && created) safe = 'Drop 按 created 条件删除';
    else if (deletes && original) safe = 'Drop 按 original 原值恢复';
    else if (dropWrites(d.lit) && /\b(?:match|if\s+let)\b[^{;]*\bself\b|\blet\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*self\b/.test(d.code)) {
      safe = 'Drop 回写原值';
    }
  }
  if (unguarded) return { ok: false, reason: 'Drop 无条件删除真实值（无 created 闸，提前 return 也挡不住）' };
  if (safe) return { ok: true, reason: safe };
  if (conditionalCreatedDelete(t)) return { ok: true, reason: 'created 条件删除' };
  if (originalWriteback(t)) return { ok: true, reason: 'original 原值回写' };
  return { ok: false, reason: '无 created/original 恢复路径' };
}

// ==================== 合成对照：同一判定函数，样本正反各走一遍 ====================

const CONTROLS = [
  {
    label: 'a 写真实值且无守卫 ⇒ 必红',
    code: String.raw`#[ignore = "t"]
fn a() {
    reg_restore_write(HKEY_LOCAL_MACHINE, r"Software\Contoso\Policy", "RealValue", REG_DWORD, &1u32.to_le_bytes());
}`,
    want: 'red',
  },
  {
    label: 'b 写真实值 + Drop 按原值恢复 ⇒ 放行',
    code: String.raw`#[ignore = "t"]
fn b() {
    struct G { original: Option<i64> }
    impl Drop for G {
        fn drop(&mut self) {
            match self.original {
                Some(v) => { let _ = reg_restore_write(HKEY_LOCAL_MACHINE, r"Software\Contoso\Policy", "RealValue", REG_DWORD, &(v as u32).to_le_bytes()); }
                None => { let _ = reg_restore_delete(HKEY_LOCAL_MACHINE, r"Software\Contoso\Policy", "RealValue"); }
            }
        }
    }
    let original = read_reg_dword_opt(HKEY_LOCAL_MACHINE, r"Software\Contoso\Policy", "RealValue");
    let _g = G { original };
    reg_restore_write(HKEY_LOCAL_MACHINE, r"Software\Contoso\Policy", "RealValue", REG_DWORD, &1u32.to_le_bytes());
}`,
    want: 'ok:original',
  },
  {
    label: 'c 写自有 TrimProbe* + Drop 清理 ⇒ 放行',
    code: String.raw`#[ignore = "t"]
fn c() {
    const SUB: &str = r"Software\TrimProbeControlC";
    struct G;
    impl Drop for G { fn drop(&mut self) { let _ = reg_key_remove(HKEY_CURRENT_USER, SUB, true); } }
    let _g = G;
    reg_restore_write(HKEY_CURRENT_USER, SUB, "v", REG_SZ, &[0u8, 0]);
}`,
    want: 'ok:自有',
  },
  {
    label: 'd 注释/字符串里写 created/original ⇒ 必须红（防洗白）',
    code: String.raw`#[ignore = "t"]
fn d() {
    // created = true; original 会在 Drop 里恢复（只是注释）
    let _note = "created / original 只是字符串";
    reg_restore_write(HKEY_CURRENT_USER, r"Software\Contoso\Run", "RealValue", REG_SZ, &[0u8, 0]);
}`,
    want: 'red',
  },
  {
    label: 'e 无 created 闸的 Drop 无条件删真实值 ⇒ 必红（X1-K01 形态）',
    code: String.raw`#[ignore = "t"]
fn e() {
    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::process::Command::new("reg")
                .args(["delete", RUN_KEY, "/v", "ctfmon", "/f"]).output();
        }
    }
    let _guard = Cleanup;
    if preexisting() { return; }
    let _ = std::process::Command::new("reg")
        .args(["add", RUN_KEY, "/v", "ctfmon", "/d", r"C:\Windows\System32\notepad.exe", "/f"]).output();
}`,
    want: 'red:无条件',
  },
  {
    label: 'f Drop 按 created 条件删除 ⇒ 放行',
    code: String.raw`#[ignore = "t"]
fn f() {
    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    struct Cleanup { created: bool }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if !self.created { return; }
            let _ = std::process::Command::new("reg")
                .args(["delete", RUN_KEY, "/v", "ctfmon", "/f"]).output();
        }
    }
    let mut guard = Cleanup { created: false };
    let _ = std::process::Command::new("reg")
        .args(["add", RUN_KEY, "/v", "ctfmon", "/d", r"C:\Windows\System32\notepad.exe", "/f"]).output();
    guard.created = true;
}`,
    want: 'ok:created',
  },
  {
    label: 'g 只在提示语里提 TrimProbe、真实值无守卫 ⇒ 必红',
    code: String.raw`#[ignore = "t"]
fn g() {
    let _ = "TrimProbe 只是提示语，不是写入目标";
    reg_restore_write(HKEY_CURRENT_USER, r"Software\Contoso\Run", "RealValue", REG_SZ, &[0u8, 0]);
}`,
    want: 'red',
  },
  {
    label: 'h 同函数写自有 scratch + 容器键上的真实值名 ⇒ 必红（混写不得借自有放行）',
    code: String.raw`#[ignore = "t"]
fn h() {
    const SUB: &str = r"Software\TrimProbeMixed";
    struct G;
    impl Drop for G { fn drop(&mut self) { let _ = reg_key_remove(HKEY_CURRENT_USER, SUB, true); } }
    let _g = G;
    reg_restore_write(HKEY_CURRENT_USER, SUB, "v", REG_SZ, &[0u8, 0]);
    reg_restore_write(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "ctfmon", REG_SZ, &[0u8, 0]);
}`,
    want: 'red',
  },
];

function analyzeControl(code) {
  const items = scanSource(code, '(control)', '(control)');
  if (items.length === 0) return { ok: false, reason: 'not-a-probe' };
  const writes = items.filter((t) => registryWriteKinds(t).length > 0);
  if (writes.length === 0) return { ok: false, reason: 'not-in-scope' };
  return classifyWriteGuard(writes[0]);
}

// ==================== 执行 ====================

const g = gate(import.meta.url);

/**
 * T1e-L09：缺目录收口。逐个做在场检查（打印显式 SKIP 文案），返回「是否全部在场」。
 * 调用方**必须**消费返回值并短路退出——旧实现丢了返回值，缺目录时退化成
 * 「SKIP 文案 + 对象地板判红」（`g.finish()` 在 0 失败时不退出，那就不是 SKIP 收口）。
 * `check` 参数供合成对照注入，不打印假 SKIP。
 */
function inputsAllPresent(dirs, check) {
  let present = true;
  for (const [dir, label] of dirs) present = check(dir, label) && present;
  return present;
}

// 本门禁两段判据的对象都在 src-tauri 下；缺目录时显式 SKIP，不冒充满分。
const INPUTS = [
  [SRC, 'src-tauri/src（注册表写守卫）'],
  [TESTS, 'src-tauri/tests（隔离根 + 注册表写守卫）'],
];
if (!inputsAllPresent(INPUTS, g.skipUnlessPresent)) {
  console.warn('⚠ 输入缺失：两道对账（隔离根 / 注册表写守卫）全部**未校验**（SKIP，不是通过）');
  g.finish();
  process.exit(0);
}
const files = [...listRs(SRC), ...listRs(TESTS)].sort();
const ignored = collectIgnored(files);
const testsIgnored = ignored.filter((t) => t.rel.startsWith('src-tauri/tests/'));
const srcIgnored = ignored.length - testsIgnored.length;

// ---- 第一道：tests 侧隔离根 ----
const isoExempt = new Map(TRANSITION.map((t) => [t.fn, t]));
let isoBad = 0;
const isoSeen = new Set();
for (const t of testsIgnored) {
  isoSeen.add(t.name);
  const isoAt = Math.min(...ISOLATED.map((s) => { const i = t.bodyCode.indexOf(s); return i < 0 ? Infinity : i; }));
  const libAt = t.bodyCode.search(LIB_REF);
  const isolated = Number.isFinite(isoAt);
  const ordered = libAt < 0 || (isolated && isoAt < libAt);
  if (isolated && ordered) {
    if (isoExempt.has(t.name)) {
      g.fail(`${t.rel}:${t.line} ${t.name} 已先定隔离根，但 TRANSITION 还挂着它（豁免未回收 = 第二类假绿）`);
    }
    continue;
  }
  isoBad++;
  const why = !isolated
    ? `没有 ${ISOLATED[1]} / ${ISOLATED[0]} 等定根动作`
    : '定根动作出现在触库之后（OnceLock 已被前一个调用定死）';
  if (!isoExempt.has(t.name)) {
    g.fail(`${t.rel}:${t.line} ${t.name} 是 #[ignore] 真机探针，${why}，也不在过渡豁免里`);
  }
}
for (const [fn, t] of isoExempt) {
  if (!isoSeen.has(fn)) g.fail(`TRANSITION 条目失效（盘上已无同名 #[ignore] 探针）：${fn}（${t.batch}）`);
  if (!t.batch || !t.reason || t.reason.length < 8) g.fail(`TRANSITION 条目缺批次或理由：${fn}`);
}
if (testsIgnored.length < MIN_IGNORED_TESTS) {
  g.fail(`tests 侧对象地板不成立：只认出 ${testsIgnored.length} 条 #[ignore] 探针（下限 ${MIN_IGNORED_TESTS}）⇒ 属性解析或目录根失效`);
}

// ---- 第二道：全仓注册表写守卫 ----
const writeItems = [];
for (const t of ignored) {
  const kinds = registryWriteKinds(t);
  if (kinds.length === 0) continue;
  const verdict = classifyWriteGuard(t);
  writeItems.push({ ...t, kinds, ...verdict });
}
const wgExempt = new Map(WRITE_GUARD_TRANSITION.map((t) => [`${t.rel}::${t.fn}`, t]));
let writeBad = 0;
const wgSeen = new Set();
for (const t of writeItems) {
  const key = `${t.rel}::${t.name}`;
  wgSeen.add(key);
  if (!t.ok) {
    writeBad++;
    if (!wgExempt.has(key)) {
      g.fail(`${t.rel}:${t.line} ${t.name} 对非自有注册表目标执行写/删，${t.reason}（跑一次发布前门禁会改掉用户真实状态）`);
    }
  } else if (wgExempt.has(key)) {
    g.fail(`${t.rel}:${t.line} ${t.name} 已具备恢复路径，但 WRITE_GUARD_TRANSITION 还挂着它（双向咬合：修好必须回收）`);
  }
}
for (const [key, t] of wgExempt) {
  if (!wgSeen.has(key)) g.fail(`WRITE_GUARD_TRANSITION 条目失效（盘上已无同名写型 #[ignore] 探针）：${key}（${t.batch}）`);
  if (!t.batch || !t.reason || t.reason.length < 8) g.fail(`WRITE_GUARD_TRANSITION 条目缺批次或理由：${key}`);
}

// 现场哨兵：两个真实病灶必须留在射程内且判定方向正确（防「解析失明变绿」）。
const r3b = writeItems.find((t) => t.rel === 'src-tauri/src/commands/optimizer/contract_tests.rs'
  && t.name.includes('删除语义判据方向正确'));
if (!r3b) {
  g.fail('R3b-K01 现场不在判定对象里：commands/optimizer/contract_tests.rs 的 m2_删除语义判据方向正确 未被识别（扫描失明）');
} else if (!r3b.ok || !/original/.test(r3b.reason)) {
  g.fail(`R3b-K01 现场判定漂了：${r3b.name} 应因 RestoreReg 的 original 原值恢复放行，实得 ${r3b.ok ? r3b.reason : `红（${r3b.reason}）`}`);
} else {
  g.ok(`现场 R3b-K01 已识别：${r3b.rel}:${r3b.line} ${r3b.name}（${r3b.reason}）`);
}
const x1 = writeItems.find((t) => t.rel === 'src-tauri/tests/module_smoke.rs'
  && t.name === 'u_ctfmon_startup_chain_guard_live');
if (!x1) {
  g.fail('X1-K01 现场不在判定对象里：tests/module_smoke.rs 的 u_ctfmon_startup_chain_guard_live 未被识别（扫描失明）');
} else if (!x1.ok || !/created/.test(x1.reason)) {
  g.fail(`X1-K01 现场判定漂了：${x1.name} 应因 Cleanup.created 闸放行，实得 ${x1.ok ? x1.reason : `红（${x1.reason}）`}`);
} else {
  g.ok(`现场 X1-K01 已识别：${x1.rel}:${x1.line} ${x1.name}（${x1.reason}）`);
}

// 对象地板：低于地板说明属性解析或目录根失效，不是仓库变干净。
if (ignored.length < MIN_IGNORED_REPO) {
  g.fail(`全仓对象地板不成立：只认出 ${ignored.length} 条 #[ignore] 探针（地板 ${MIN_IGNORED_REPO}）⇒ 属性解析或目录根失效`);
}

// 合成对照（每次都跑）
let ctrlBad = 0;
const ctrlResults = [];
for (const c of CONTROLS) {
  const got = analyzeControl(c.code);
  const [wantKind, wantReason] = c.want.split(':');
  const pass = wantKind === 'red'
    ? !got.ok
    : got.ok && (!wantReason || got.reason.includes(wantReason));
  if (!pass) {
    ctrlBad++;
    console.error(`✗ 正向对照失败：${c.label}（实得 ${got.ok ? `放行/${got.reason}` : `红/${got.reason}`}，应为 ${c.want}）`);
  } else {
    ctrlResults.push(c.label.split(' ')[0]);
  }
}

// 结构对照（T1e-L09）：SKIP 收口必须消费返回值 —— 丢返回值 / 恒放行的实现必须在这里判红。
{
  const fakeSkip = (dir) => !dir.includes('__absent__');
  const allHere = inputsAllPresent([['a', 'A'], ['b', 'B']], fakeSkip);
  const missingOne = inputsAllPresent([['a', 'A'], ['__absent__', 'B']], fakeSkip);
  if (!allHere) g.fail('结构对照：目录齐全时误走 SKIP 收口（正常仓库会整轮静默跳过，判据全灭）');
  if (missingOne) g.fail('结构对照：缺一个目录仍判「齐全」—— skip 返回值被丢弃（T1e-L09 原缺陷形态）');
  if (allHere && !missingOne) g.ok('结构对照：目录齐全放行 / 缺一个必不通过（SKIP 收口消费返回值）');
}

// 汇总输出：对象数、分面、R3b 现场、对照组数都要能从 stdout 直接看出。
g.ok(`全仓 #[ignore] 对象：${ignored.length} 条（src ${srcIgnored} / tests ${testsIgnored.length}；地板 ${MIN_IGNORED_REPO}）`);
g.ok(`tests 侧隔离根对账：${testsIgnored.length} 条 / 未先定根 ${isoBad} 条（豁免 ${isoExempt.size} 条，只减不增）`);
g.ok(`真机写注册表守卫对账：命中 ${writeItems.length} 条 / 无守卫 ${writeBad} 条（登记表 ${wgExempt.size} 条）`);
g.controlFailed(
  ctrlBad,
  CONTROLS.length,
  `正向对照（通过 ${ctrlResults.length} 组：${ctrlResults.join(' / ')}；含「注释洗白必红」「无 created 闸 Drop 删除必红」）`,
);
g.finish('check-ignored-isolation: 全部通过（隔离根仅 tests 侧；注册表写守卫覆盖 src + tests）');
