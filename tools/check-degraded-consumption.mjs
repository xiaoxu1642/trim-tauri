'use strict';
// tools/check-degraded-consumption.mjs —— 后端已分态的 `degraded`，前端不得折回单态（B0 门禁）
//
// 出处：2026-10-24 全仓重审 F4a2-K02（🔴）与族 F-2 / A1；2026-11-01 重审 §6.3 第 5 条（假绿 #5，
// 来源 F4a2 / T1e）把它收紧为下面四条：
//   ① **双视图**：发射判定同时看「注释抹白、字符串保留」视图（`"degraded"` 字段名可见：
//      `json!({ "degraded": true })`、`o.insert("degraded".into(), …)` 都算）与「注释+字符串全抹」
//      视图（结构体字面量 `Health { degraded }` 这类标识符形态）。注释里的字样两视图都不算；
//      只有变量传值（`let (v, degraded) = …; (v, degraded)`）不算发射，因为它没有构造字段。
//   ② **射程**：从 `#[tauri::command]` 函数体扩到**所有构造该字段的函数**（命令 + helper，
//      helper 用 `via` 说明经哪条命令回传）；前端消费点按**函数体**核验（`anchor.fn`），
//      不再接受「文件里任意位置出现过」。
//   ③ **登记表**：主键统一 `file#fn`；pending/exempt 是收紧后存量违例的过渡表，逐条带
//      `理由 + 批次归属`，只减不增（兑现后锚点命中即判红，逼回收条目）。不整体跳过任何生产文件。
//   ④ **合成对照**每次运行都跑：字符串命中 / 注释不命中 / 值传递不误报 / helper 入册 /
//      结构体简写入册 / 测试模块与 `#[cfg(test)]` 函数排除 / 消费点缺失必红 /
//      消费点藏在注释、日志字符串、模板串或别的函数里都不顶账。
//
// 用法：node tools/check-degraded-consumption.mjs

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gate } from './lib/gate.mjs';
import { blankNonCode, splitFunctions, skipBraces, lineAt } from './lib/src-scan.mjs';

const ROOT = process.cwd();
const SRC_RS = join(ROOT, 'src-tauri', 'src');
const SRC_JS = join(ROOT, 'src', 'scripts');
const MIN_COMMANDS = 8; // 命令地板：低于此数说明命令解析失效，不是「大家都接好了」
const MIN_HELPERS = 2; // helper 地板：现盘 pending_load / power_plan_state 两处，归零即判据失明
const MIN_JS_CONSUMERS = 5; // 前端消费函数地板：低于此数说明 JS 扫描面塌了

const relOf = (abs) => relative(ROOT, abs).split('\\').join('/');
const keyOf = (file, fn) => `${file}#${fn}`;
// 测试支撑文件不进生产发射面（测试里的字面量不是回执）。
const TEST_FILE = /(^|\/)(?:tests?|testutil|contract_tests|[^/]+_tests)\.rs$/;

// ── 过渡表（唯一判据面，主键 `file#fn`）────────────────────────────────────────────
// consumed —— 消费点已落地：`anchor` 必须命中，并落在 `anchor.fn` 的**函数体**内；
// pending  —— 收紧射程后仍缺消费方的存量违例：`anchor` 是「修好后会命中的消费点文本」，
//             一旦命中即判红（逼当天回收条目）；必须给 `batch` + `reason`；
// exempt   —— 结构上没有前端消费方（例如只由原生侧/无头 CLI 用）：理由 ≥8 字 + 批次。
// ⚠ 这张表是收紧后（2026-11-02）的基线，只减不增：新增发射必须在同批接上消费，
//   不许再往 pending 里塞新行；「先补表不补判据」会被上面的双向咬合当场判红。
const TABLE = [
  // ---- consumed：anchors 全部钉到具体消费函数 ----
  { file: 'src-tauri/src/commands/paths.rs', fn: 'paths_load', status: 'consumed',
    anchor: { file: 'src/scripts/pathbinding.js', fn: 'load', text: 'resp.degraded === true' } },
  { file: 'src-tauri/src/commands/settings.rs', fn: 'settings_load', status: 'consumed',
    anchor: { file: 'src/scripts/models-window.js', fn: 'load', text: 'resp.degraded === true' } },
  { file: 'src-tauri/src/commands/appearance.rs', fn: 'appearance_get_prefs', status: 'consumed',
    anchor: { file: 'src/scripts/pathbinding-appearance.js', fn: 'syncAppearanceFromBackend', text: 'resp.degraded === true' } },
  { file: 'src-tauri/src/commands/fileclean.rs', fn: 'fileclean_scan', status: 'consumed',
    anchor: { file: 'src/scripts/cleanup.js', fn: 'refreshPendingBadge', text: 'data.degraded' } },
  { file: 'src-tauri/src/commands/startup.rs', fn: 'startup_scan', status: 'consumed',
    anchor: { file: 'src/scripts/startup.js', fn: 'scan', text: 'resp.degraded === true' } },
  { file: 'src-tauri/src/commands/uninstall/pending_delete.rs', fn: 'uninstall_pending_list', status: 'consumed',
    anchor: { file: 'src/scripts/residue-window.js', fn: 'updatePendingButtons', text: 'data.degraded' } },
  // pending_load 是台账读侧 helper，损坏分支发 degraded，经 uninstall_pending_list 回传前端。
  { file: 'src-tauri/src/commands/uninstall/pending_delete.rs', fn: 'pending_load', status: 'consumed',
    via: 'uninstall_pending_list',
    anchor: { file: 'src/scripts/residue-window.js', fn: 'updatePendingButtons', text: 'data.degraded' } },
  // ---- pending：收紧后现存违例，逐条带理由与归属，只减不增 ----
  { file: 'src-tauri/src/commands/appearance.rs', fn: 'appearance_get_material', status: 'pending',
    batch: 'B3/P1-6',
    reason: '材质面未见消费方：window-material.js 现算无 degraded；归 B3/P1-6 展示层分态',
    anchor: { file: 'src/scripts/window-material.js', text: 'degraded' } },
  { file: 'src-tauri/src/commands/optimizer/overview.rs', fn: 'optimizer_state_overview', status: 'pending',
    batch: 'B3/P1-6A',
    reason: '与 R3b-M10 同一条链（目录不可用 vs 空目录）；归 B3/P1-6A',
    anchor: { file: 'src/scripts/optimizer.js', text: 'degraded' } },
  { file: 'src-tauri/src/commands/overview.rs', fn: 'overview_hardware', status: 'pending',
    batch: 'G4-b/假绿#5',
    reason: '收紧射程后新露出：扫描失败回落旧缓存，但 overview.js 对 degraded 零消费；归前端分态批次（P1 波3）',
    anchor: { file: 'src/scripts/overview.js', text: 'degraded' } },
  { file: 'src-tauri/src/engine/native/syspanel.rs', fn: 'power_plan_state', status: 'pending',
    via: 'syspanel_power_plan_get',
    batch: 'G4-b/假绿#5',
    reason: 'helper 发射经 syspanel_power_plan_get 回传，syspanel.js 对 degraded 零消费；是否要求前端消费待域单元裁定，归前端分态批次',
    anchor: { file: 'src/scripts/syspanel.js', text: 'degraded' } },
];

const walk = (dir, ext) => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(join(dir, e.name), ext) : (e.name.endsWith(ext) ? [join(dir, e.name)] : []));

// ── 视图一：Rust「注释抹白、字符串保留」——字段名 `"degraded"` 在这一视图里可见 ──────────
const rustStringsKept = (code) => blankNonCode(code, 'rs', { keepStrings: true });
// ── 视图二：Rust「注释+字符串全抹」——只剩标识符，供结构体字面量字段识别 ────────────────
const rustCodeOnly = (code) => blankNonCode(code, 'rs');

// `json!({ "degraded": … })` / `o.insert("degraded".into(), …)`；冒号与 .into( 都是字段构造形态。
const FIELD_KEY = /"degraded"\s*(?::|\.into\s*\()/;
// 结构体字面量里的字段：`Health { degraded }` / `HealthInfo { degraded: flag, … }`。
// 只认大写开头的类型名，避免把 `if cond { degraded }` 这类表达式误判成发射。
const STRUCT_FIELD = /\b[A-Z][A-Za-z0-9_]*(?:::[A-Z][A-Za-z0-9_]*)*\s*\{[^{}]*\bdegraded\b[^{}]*\}/;

/** `#[cfg(test)] mod …` 的字符区间：测试体里的 `"degraded": true` 是断言夹具，不是回执。 */
function testModRanges(code) {
  const blanked = rustCodeOnly(code);
  const out = [];
  const pat = /#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{/g;
  let m;
  while ((m = pat.exec(blanked))) out.push([m.index, skipBraces(blanked, blanked.indexOf('{', m.index))]);
  return out;
}
const inRanges = (ranges, idx) => ranges.some(([a, b]) => idx >= a && idx < b);

/** `#[cfg(test)]` 直接修饰的函数（不在 mod 里）也排除：属性到 `fn` 之间只允许空白/其它属性/可见性。 */
function isTestOnlyFn(blanked, start) {
  const head = blanked.slice(Math.max(0, start - 300), start);
  const attr = head.lastIndexOf('#[cfg(test)]');
  if (attr < 0) return false;
  // 中间出现 `;` / `{` / `}` 说明这个属性属于前一条语句或前一个测试函数，不是本函数。
  return !/[;{}]/.test(head.slice(attr + '#[cfg(test)]'.length));
}

/**
 * 单个 Rust 文件的发射面与命令面（纯函数，真仓与合成对照共用）。
 * @param {string} code
 * @returns {{commands: string[], emitters: {name:string,line:number,isCommand:boolean}[]}}
 */
export function scanRustFile(code) {
  const tests = testModRanges(code);
  const blanked = rustCodeOnly(code);
  const commands = [];
  const cmdRe = /#\[tauri::command\][\s\S]{0,600}?\bfn\s+([A-Za-z0-9_]+)/g;
  let m;
  while ((m = cmdRe.exec(blanked))) if (!inRanges(tests, m.index)) commands.push(m[1]);
  const emitters = [];
  if (code.includes('degraded')) {
    const strings = rustStringsKept(code);
    for (const f of splitFunctions(code, 'rs')) {
      if (inRanges(tests, f.start) || isTestOnlyFn(blanked, f.start)) continue;
      const bodyCode = blanked.slice(f.bodyStart, f.end - 1);
      const bodyStr = strings.slice(f.bodyStart, f.end - 1);
      // 双视图取并集：字段名（字符串保留视图）或结构体字段（全抹视图）任一成立即算发射；
      // 仅变量传值不构造字段，两个视图都不命中。
      if (!FIELD_KEY.test(bodyStr) && !STRUCT_FIELD.test(bodyCode)) continue;
      const head = blanked.slice(Math.max(0, f.start - 600), f.start);
      emitters.push({ name: f.name, line: lineAt(code, f.start), isCommand: /#\[tauri::command\]/.test(head) });
    }
  }
  return { commands, emitters };
}

/** 合成对照用：只要发射面。 */
export const detectEmitters = (code) => scanRustFile(code).emitters;

// ── 前端视图：注释、普通字符串、模板串内容全部抹白；`${…}` 内插代码保留 ────────────────
// 为什么不直接用 src-scan 的 blankNonCode：它遇到「模板里套 ${…} 再套模板」会失准
// （models-window.js 从第一个 `return \`` 之后整段被抹掉），锚点会永久假红。
// 这里用等长抹除 + 递归内插扫描；换行一律保留，行号可直接用。
// 已知精度上限：不建模正则字面量（与旧实现同口径），正则里出现 `//` 会多抹本行。
export function blankJs(code) {
  const out = code.split('');
  const n = code.length;
  const blank = (a, b) => {
    for (let k = a; k < b && k < n; k++) if (out[k] !== '\n' && out[k] !== '\r') out[k] = ' ';
  };
  let i = 0;
  const scanTemplate = () => {
    i++; // 开引号
    while (i < n) {
      const c = code[i];
      if (c === '\\') { blank(i, i + 2); i += 2; continue; }
      if (c === '`') { i++; return; }
      if (c === '$' && code[i + 1] === '{') {
        blank(i, i + 2); // ${ 与 } 本身不是消费点
        i += 2;
        scanCode(true);
        continue;
      }
      blank(i, i + 1);
      i++;
    }
  };
  const scanCode = (inInterp) => {
    let depth = 0;
    while (i < n) {
      const c = code[i], d = code[i + 1];
      if (c === '/' && d === '/') {
        const s = i; while (i < n && code[i] !== '\n') i++;
        blank(s, i); continue;
      }
      if (c === '/' && d === '*') {
        const s = i; i += 2;
        while (i < n && !(code[i] === '*' && code[i + 1] === '/')) i++;
        i = Math.min(n, i + 2); blank(s, i); continue;
      }
      if (c === "'" || c === '"') {
        const q = c, s = i; i++;
        while (i < n) {
          if (code[i] === '\\') { i += 2; continue; }
          if (code[i] === q) { i++; break; }
          if (code[i] === '\n') break;
          i++;
        }
        blank(s, i); continue;
      }
      if (c === '`') { scanTemplate(); continue; }
      if (inInterp) {
        if (c === '{') { depth++; i++; continue; }
        if (c === '}') { if (depth === 0) { i++; return; } depth--; i++; continue; }
      }
      i++;
    }
  };
  scanCode(false);
  return out.join('');
}

// 函数声明（行首）：`function name(` / `const name = (…) =>` / `name: (…) =>`。
// 只用于把消费点归属到函数体（文本级行窗口），不追求语法级解析。
const JS_DECL = /^[ \t]*(?:async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(|^[ \t]*(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z0-9_$]+)\s*=>|^[ \t]*([A-Za-z0-9_$]+)\s*:\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z0-9_$]+)\s*=>/gm;

function jsDecls(view) {
  const out = [];
  JS_DECL.lastIndex = 0;
  let m;
  while ((m = JS_DECL.exec(view))) out.push({ name: m[1] || m[2] || m[3], line: lineAt(view, m.index) });
  return out;
}
const enclosingFn = (decls, line) => {
  let name = null;
  for (const d of decls) { if (d.line <= line) name = d.name; else break; }
  return name;
};

/**
 * 前端 degraded 消费面：按函数聚合「可执行代码里出现过 degraded」的位置。
 * 注释、字符串、模板串内容不算消费（blankJs 已抹）。
 * @returns {{fn:string,line:number}[]}
 */
export function scanJsConsumers(code) {
  const view = blankJs(code);
  const decls = jsDecls(view);
  const fns = new Map();
  for (const m of view.matchAll(/\bdegraded\b/g)) {
    const line = lineAt(view, m.index);
    const fn = enclosingFn(decls, line) || '(顶层)';
    if (!fns.has(fn)) fns.set(fn, line);
  }
  return [...fns].map(([fn, line]) => ({ fn, line }));
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * 锚点判定（真仓与合成样本共用）：
 *   · 文本必须出现在**可执行代码**里（注释 / 普通字符串 / 模板串内容都不顶账）；
 *   · 若给了 `anchor.fn`，命中点必须落在该函数的行窗口内（消费点删掉或搬走即判红）。
 * @returns {{hit:boolean, line?:number, why?:string}}
 */
export function judgeAnchorInText(src, anchor) {
  const view = blankJs(src);
  const re = new RegExp(escapeRe(anchor.text), 'g');
  const lines = [];
  let m;
  while ((m = re.exec(view))) lines.push(lineAt(view, m.index));
  if (!lines.length) return { hit: false, why: '可执行代码里一次都没出现（注释 / 字符串 / 模板不顶账）' };
  if (!anchor.fn) return { hit: true, line: lines[0] };
  const decls = jsDecls(view);
  const line = lines.find((ln) => enclosingFn(decls, ln) === anchor.fn);
  if (line == null) {
    const got = [...new Set(lines.map((ln) => enclosingFn(decls, ln) || '(顶层)'))].join('、');
    return { hit: false, why: `只在 ${got} 里出现，不在登记的消费函数 ${anchor.fn} 内` };
  }
  return { hit: true, line };
}

const anchorJudge = (anchor) => {
  const abs = join(ROOT, anchor.file);
  if (!existsSync(abs)) return { hit: false, why: `${anchor.file} 不存在（消费点缺失）` };
  return judgeAnchorInText(readFileSync(abs, 'utf8'), anchor);
};

/**
 * 纯判据：发射面 ⇄ 过渡表双向对账（T1e-M01 / 假绿 #5）。
 * 真仓与合成样本共用同一实现 —— 「新增发射不登记」「消费点被删」「pending 修好不回收」
 * 三条腿都必须能被样本驱动，不再对字面量数组做同义反复。
 * @param {Map<string,{file:string,fn:string,line:number,kind:'command'|'helper'}>} emitterMap
 * @param {Map<string,object>} tableMap
 * @param {(anchor:object)=>{hit:boolean,line?:number,why?:string}} anchorJudgeFn
 * @param {Set<string>} [knownCommands] 盘上命令名（校验 helper 的 via）
 */
export function judgeReconciliation(emitterMap, tableMap, anchorJudgeFn, knownCommands) {
  const out = [];
  const STATUSES = ['consumed', 'pending', 'exempt'];
  for (const [key, where] of emitterMap) {
    const t = tableMap.get(key);
    if (!t) {
      out.push(`${where.file}:${where.line} ${where.fn}() 构造 degraded 字段，但过渡表里没有 ${key} ⇒ 新增分态必须回答「前端接不接」`);
      continue;
    }
    if (!STATUSES.includes(t.status)) {
      out.push(`${key} 的 status 非法：${t.status}`);
      continue;
    }
    if (where.kind === 'helper' && !t.via) {
      out.push(`${key} 是 helper 发射，必须用 via 说明经哪条命令回传前端`);
    }
    if (t.via && knownCommands && !knownCommands.has(t.via)) {
      out.push(`${key} 的 via ${t.via} 不是盘上命令（归属链断了）`);
    }
    if (t.status === 'consumed') {
      if (!t.anchor || !t.anchor.file || !t.anchor.text) {
        out.push(`${key} 登记为 consumed 却没给可核锚点（等于免检）`);
        continue;
      }
      if (!t.anchor.fn) {
        out.push(`${key} 的 consumed 锚点缺 anchor.fn —— 射程必须落到消费函数体，不接受文件级文本命中`);
        continue;
      }
      const r = anchorJudgeFn(t.anchor);
      if (!r.hit) {
        out.push(`${key} 登记为 consumed，但 ${t.anchor.file}#${t.anchor.fn} 的消费点「${t.anchor.text}」未命中：${r.why}`);
      }
      continue;
    }
    if (!t.batch) out.push(`${key} 是 ${t.status} 但缺批次归属`);
    if (!t.reason || t.reason.trim().length < 8) out.push(`${key} 是 ${t.status} 但缺理由（≥8 字）`);
    if (t.anchor) {
      if (!t.anchor.file || !t.anchor.text) {
        out.push(`${key} 的 ${t.status} 锚点不完整（file/text 都要有）`);
      } else {
        const r = anchorJudgeFn(t.anchor);
        if (r.hit) {
          out.push(`${key} 仍登记为 ${t.status}（${t.batch}），但消费点已在 ${t.anchor.file} 命中（行 ${r.line}）⇒ 修完要回收条目`);
        }
      }
    } else if (t.status === 'pending') {
      out.push(`${key} 是 pending 却没给消费点锚点 ⇒ 「兑现即回收」这条腿对它永久失效（补 anchor，或写成书面 exempt）`);
    }
  }
  for (const [key, t] of tableMap) {
    if (!emitterMap.has(key)) {
      out.push(`过渡表条目失效：盘上已无 ${key} 构造 degraded（${t.status === 'pending' ? t.batch : 'consumed'}）`);
    }
  }
  return out;
}

const g = gate(import.meta.url);

// T1e-L09：SKIP 必须**短路** —— `g.finish()` 在 0 失败时不退出，继续 walk 会抛 ENOENT
// 栈，把「显式 SKIP」退化成崩溃（AGENTS §5 要求缺输入给 SKIP，不许 ENOENT 崩）。
if (!g.skipUnlessPresent(SRC_RS, 'src-tauri/src（本门禁的判定对象）')
  || !g.skipUnlessPresent(SRC_JS, 'src/scripts（前端消费面）')) { g.finish(); process.exit(0); }

// ── 盘上现算：Rust 发射面 + 命令名集合 ──────────────────────────────────────────────
const emitters = new Map();
const knownCommands = new Set();
for (const abs of walk(SRC_RS, '.rs')) {
  const rel = relOf(abs);
  if (TEST_FILE.test(rel)) continue; // 测试支撑文件：不是生产回执面（不是「整体跳过生产文件」）
  const { commands, emitters: found } = scanRustFile(readFileSync(abs, 'utf8'));
  for (const c of commands) knownCommands.add(c);
  for (const e of found) {
    const key = keyOf(rel, e.name);
    if (emitters.has(key)) { g.fail(`同名函数在同一文件出现两次，登记键冲突：${key}`); continue; }
    emitters.set(key, { file: rel, fn: e.name, line: e.line, kind: e.isCommand ? 'command' : 'helper' });
  }
}

// ── 盘上现算：前端 degraded 消费函数面 ─────────────────────────────────────────────
const consumers = new Map(); // file#fn → {file, fn, line}
for (const abs of walk(SRC_JS, '.js')) {
  const rel = relOf(abs);
  for (const c of scanJsConsumers(readFileSync(abs, 'utf8'))) {
    consumers.set(keyOf(rel, c.fn), { file: rel, fn: c.fn, line: c.line });
  }
}

const table = new Map(TABLE.map((t) => [keyOf(t.file, t.fn), t]));

for (const p of judgeReconciliation(emitters, table, anchorJudge, knownCommands)) g.fail(p);

// ── 地板：命令 / helper / 前端消费函数任一归零都说明判据失明，不是仓库变安全 ─────────
const commandCount = [...emitters.values()].filter((e) => e.kind === 'command').length;
const helperCount = [...emitters.values()].filter((e) => e.kind === 'helper').length;
if (commandCount < MIN_COMMANDS) g.fail(`断言对象地板不成立：只认出 ${commandCount} 个 degraded 发射命令（地板 ${MIN_COMMANDS}）`);
if (helperCount < MIN_HELPERS) g.fail(`断言对象地板不成立：只认出 ${helperCount} 个 degraded 发射 helper（地板 ${MIN_HELPERS}）`);
if (consumers.size < MIN_JS_CONSUMERS) g.fail(`前端扫描面地板不成立：只认出 ${consumers.size} 个 degraded 消费函数（地板 ${MIN_JS_CONSUMERS}）⇒ 前端消费面解析失效`);
const consumed = [...emitters.keys()].filter((k) => table.get(k)?.status === 'consumed').length;
const pending = [...emitters.keys()].filter((k) => table.get(k)?.status === 'pending').length;
g.ok(`degraded 契约对账（双视图 / 函数级）：发射 ${commandCount} 命令 + ${helperCount} helper；前端消费函数 ${consumers.size} 个（${[...consumers.values()].map((c) => `${c.file}#${c.fn}`).join('、')}）；已接 ${consumed} / 过渡 pending ${pending}`);

// ── 合成对照：发射判定（双视图）────────────────────────────────────────────────────
{
  const cases = [
    ['字符串字段名（json! 字面量）必须判为发射', 'fn lit() -> Value { json!({ "degraded": true }) }', 1],
    ['字符串字段名（map insert .into()）必须判为发射', 'fn ins() -> Value { let mut o = Map::new(); o.insert("degraded".into(), json!(true)); json!(o) }', 1],
    ['字符串字段名 + 值标识符必须判为发射', 'fn pair(d: bool) -> Value { json!({ "degraded": d }) }', 1],
    ['结构体字面量字段必须判为发射（抹白视图）', 'fn st() -> H { H { degraded: true } }', 1],
    ['结构体简写字段必须判为发射（抹白视图）', 'fn sh(degraded: bool) -> H { H { degraded } }', 1],
    ['只出现在块注释 / 行注释 / doc 注释里不得判为发射', '/// "degraded": true\n/*\n "degraded": true\n*/\nfn no() -> Value { /* "degraded": true */ json!({ "success": true }) } // "degraded": true\n', 0],
    ['只在变量传值里出现不得判为发射', 'fn pass() -> (Value, bool) { let (v, degraded) = read(); (v, degraded) }', 0],
  ];
  const bad = cases.filter(([, code, want]) => detectEmitters(code).length !== want)
    .map(([label, code, want]) => `${label}（期望 ${want}，实得 ${detectEmitters(code).length}）`);
  if (bad.length) g.fail(`发射判定器对照失败：${bad.join('；')}`);
  else g.ok(`发射判定器对照 ${cases.length} 组：字符串命中 / 结构体命中 / 注释不命中 / 变量传值不误报`);

  const helper = detectEmitters('fn power_plan_state() -> Value { json!({ "degraded": true }) }')[0];
  const cmd = detectEmitters('#[tauri::command]\nfn cmd_x() -> Value { json!({ "degraded": true }) }')[0];
  const testMod = detectEmitters('#[cfg(test)]\nmod tests { fn t() -> Value { json!({ "degraded": true }) } }');
  const testFn = detectEmitters('#[cfg(test)]\nfn fixture() -> Value { json!({ "degraded": true }) }');
  if (!helper || helper.isCommand || !cmd || !cmd.isCommand || testMod.length || testFn.length) {
    g.fail(`发射面归属对照失败：helper/命令归属或测试排除失真（helper=${JSON.stringify(helper)} cmd=${JSON.stringify(cmd)} testMod=${testMod.length} testFn=${testFn.length}）`);
  } else {
    g.ok('发射面归属对照：无属性函数归 helper、带 #[tauri::command] 归命令、测试模块与 #[cfg(test)] 函数不进场');
  }
}

// ── 合成对照：消费锚点（注释 / 字符串 / 模板 / 别的函数都不顶账）────────────────────
{
  const JS_SAMPLE = [
    'function load() {',
    '  if (resp.degraded === true) { recover(); }',
    '  console.log("resp.degraded === true");',
    '  // resp.degraded === true',
    '  const t = `resp.degraded === true ${resp.degraded ? 1 : 0}`;',
    '}',
    'function other() { /* resp.degraded === true */ }',
    'const plain = "resp.degraded === true";',
  ].join('\n');
  const cases = [
    ['真实代码命中', { file: 's.js', fn: 'load', text: 'resp.degraded === true' }, true],
    ['日志字符串不顶账', { file: 's.js', fn: 'load', text: 'console.log("resp.degraded === true")' }, false],
    ['注释不顶账', { file: 's.js', fn: 'load', text: '// resp.degraded === true' }, false],
    ['模板串内容不顶账', { file: 's.js', fn: 'load', text: 'resp.degraded === true ${' }, false],
    ['别的函数里的命中不顶账', { file: 's.js', fn: 'other', text: 'if (resp.degraded === true)' }, false],
  ];
  const bad = cases.filter(([, a, want]) => judgeAnchorInText(JS_SAMPLE, a).hit !== want).map(([label]) => label);
  if (bad.length) g.fail(`消费锚点判定器对照失败：${bad.join('、')}`);
  else g.ok(`消费锚点判定器对照 ${cases.length} 组：函数体命中；日志字符串 / 注释 / 模板内容 / 别的函数不顶账`);
}

// ── 合成对照：对账判据（新增发射必红 / 消费点缺失必红 / pending 未回收必红）──────────
{
  const emitOf = (file, fn, kind = 'command') => new Map([[keyOf(file, fn), { file, fn, line: 1, kind }]]);
  const tblOf = (rows) => new Map(rows.map((r) => [keyOf(r.file, r.fn), r]));
  const neverHit = () => ({ hit: false, why: '消费点缺失' });
  const alwaysHit = () => ({ hit: true, line: 1 });
  const cleanCmd = { file: 'a.rs', fn: 'c_cmd', status: 'consumed', anchor: { file: 'f.js', fn: 'load', text: 't' } };
  const cases = [
    ['新增发射不登记必红', judgeReconciliation(emitOf('a.rs', 'new_cmd'), tblOf([]), neverHit, new Set(['new_cmd'])).length, 1],
    ['消费点缺失必红', judgeReconciliation(emitOf('a.rs', 'c_cmd'), tblOf([cleanCmd]), neverHit, new Set(['c_cmd'])).length, 1],
    ['consumed 锚点缺 fn 必红', judgeReconciliation(emitOf('a.rs', 'c_cmd'), tblOf([{ ...cleanCmd, anchor: { file: 'f.js', text: 't' } }]), alwaysHit, new Set(['c_cmd'])).length, 1],
    ['consumed 缺锚点必红', judgeReconciliation(emitOf('a.rs', 'c_cmd'), tblOf([{ file: 'a.rs', fn: 'c_cmd', status: 'consumed' }]), neverHit, new Set(['c_cmd'])).length, 1],
    ['pending 锚点命中未回收必红', judgeReconciliation(emitOf('a.rs', 'p_cmd'), tblOf([{ file: 'a.rs', fn: 'p_cmd', status: 'pending', batch: 'Bx', reason: '理由足够长的一句话', anchor: { file: 'f.js', text: 't' } }]), alwaysHit, new Set(['p_cmd'])).length, 1],
    ['pending 无锚点必红', judgeReconciliation(emitOf('a.rs', 'p_cmd'), tblOf([{ file: 'a.rs', fn: 'p_cmd', status: 'pending', batch: 'Bx', reason: '理由足够长的一句话' }]), neverHit, new Set(['p_cmd'])).length, 1],
    ['exempt 缺理由必红', judgeReconciliation(emitOf('a.rs', 'e_cmd'), tblOf([{ file: 'a.rs', fn: 'e_cmd', status: 'exempt', batch: 'Bx' }]), neverHit, new Set(['e_cmd'])).length, 1],
    ['helper 缺 via 必红', judgeReconciliation(emitOf('a.rs', 'h_fn', 'helper'), tblOf([{ file: 'a.rs', fn: 'h_fn', status: 'pending', batch: 'Bx', reason: '理由足够长的一句话', anchor: { file: 'f.js', text: 't' } }]), neverHit, new Set()).length, 1],
    ['via 指向不存在的命令必红', judgeReconciliation(emitOf('a.rs', 'h_fn', 'helper'), tblOf([{ file: 'a.rs', fn: 'h_fn', status: 'pending', batch: 'Bx', via: 'ghost_cmd', reason: '理由足够长的一句话', anchor: { file: 'f.js', text: 't' } }]), neverHit, new Set(['other'])).length, 1],
    ['非法 status 必红', judgeReconciliation(emitOf('a.rs', 'c_cmd'), tblOf([{ ...cleanCmd, status: 'bogus' }]), alwaysHit, new Set(['c_cmd'])).length, 1],
    ['表里多出命令必红', judgeReconciliation(new Map(), tblOf([cleanCmd]), alwaysHit, new Set()).length, 1],
    ['干净样本放行', judgeReconciliation(emitOf('a.rs', 'c_cmd'), tblOf([cleanCmd]), alwaysHit, new Set(['c_cmd'])).length, 0],
  ];
  const bad = cases.filter(([, got, want]) => got !== want).map(([label, got, want]) => `${label}（期望 ${want}，实得 ${got}）`);
  if (bad.length) g.fail(`对账判据对照失败：${bad.join('；')}`);
  else g.ok(`对账判据对照 ${cases.length} 组：新增发射 / 消费点缺失 / pending 未回收 / consumed 锚点缺 fn / 缺理由 / 缺 via / 失效 via / 非法 status / 表多出 全部必红，干净样本放行`);
}

// ---------- B3-4（2026-10-27）：时序前提 ——「还没读到配置」不得与「配置就绪」同形 ----------
// 病根：`pathConfigState` 初值是 'ok'，于是 load 未完成时也自称就绪；补扫定时器窗口内点
// 「重新扫描」会拿空 pathConfig 逐键 paths.save，把真源重建成扫描所见 —— 与本门禁主判据
// 盯的 A1-M12 是同一处真源，只是入口换成了「时序」而不是「状态位丢失」。
// 判据：初值必须是 'loading'；扫描/写回入口必须以 `!== 'ok'` 前置（只拒 degraded 会让
// loading / unavailable 穿过去）。
{
  const initState = (text) => {
    const m = /let\s+pathConfigState\s*=\s*'([a-z]+)'/.exec(text);
    return m ? m[1] : null;
  };
  // 正向对照：判定器必须能把两种初值区分开（否则下面两条绿是空绿）
  if (initState("let pathConfigState = 'ok';") !== 'ok'
    || initState("let pathConfigState = 'loading';") !== 'loading') {
    g.fail('B3-4 正向对照失败：pathConfigState 初值判定器失真');
  }
  const pb = join(ROOT, 'src', 'scripts', 'pathbinding.js');
  if (!existsSync(pb)) {
    g.fail('B3-4：src/scripts/pathbinding.js 不存在（判定对象缺失）');
  } else {
    const pbsrc = readFileSync(pb, 'utf8');
    const init = initState(pbsrc);
    if (init === null) g.fail('B3-4：找不到 pathConfigState 声明（判据锚点失效）');
    else if (init !== 'loading') {
      g.fail(`B3-4：pathConfigState 初值是 '${init}'，应为 'loading' —— 未落地时自称就绪，扫描会拿空配置覆盖真源`);
    } else {
      g.ok("B3-4：pathConfigState 初值为 'loading'（load 未完成不再冒充就绪）");
    }
    if (/if\s*\(\s*pathConfigState\s*!==\s*'ok'\s*\)/.test(pbsrc)) {
      g.ok("B3-4：扫描入口以 `!== 'ok'` 前置（loading / unavailable / degraded 一并拒）");
    } else {
      g.fail("B3-4：扫描入口缺少 `pathConfigState !== 'ok'` 前置 —— 只拒 degraded 会让 loading/unavailable 穿过");
    }
  }
}

// ---------- F4b-M13（2026-10-27 · P1）：settings_load 的两个消费方都得接 degraded ----------
// 病根：后端为「Corrupt ≠ Absent」专留 degraded，两个消费方（模型管理窗 / 模型选择器）都只判
// success+data ⇒ 配置损坏被画成「还没配」，用户去重复填写，随后的保存把可恢复的原文件覆盖掉。
// 判据：两处源码都必须同时命中「degraded 判定」与「可见提示出口」（只有 log 不算 —— 用户看不见）。
// 2026-11-02：判定视图改用本件 blankJs（注释/字符串/模板抹白），日志字符串不能再顶账。
{
  const consumersToCheck = [
    { file: 'src/scripts/models-window.js', hint: 'toast(' },
    { file: 'src/scripts/modelpicker.js', hint: 'toastOut(' },
  ];
  const probe = (src, hint) => {
    const code = blankJs(src);
    return code.includes('resp.degraded === true') && code.includes(hint);
  };
  // 正向对照：判定器必须能把「接了 degraded」与「只判 success」区分开，否则下面两条绿是空绿
  const POS = 'const resp = await window.api.settings.load(); if (resp.degraded === true) { toastOut("error", "x"); }';
  const NEG = 'const resp = await window.api.settings.load(); if (resp && resp.success && resp.data) { x(); }';
  if (!probe(POS, 'toastOut(') || probe(NEG, 'toastOut(')) {
    g.fail('F4b-M13 正向对照失败：degraded 消费判定器失真（必须能把「接 degraded」与「只判 success」分开）');
  }
  let bad = 0;
  for (const c of consumersToCheck) {
    const abs = join(ROOT, c.file);
    if (!existsSync(abs)) { g.fail(`F4b-M13：${c.file} 不存在（判定对象缺失）`); bad++; continue; }
    if (!probe(readFileSync(abs, 'utf8'), c.hint)) {
      g.fail(`F4b-M13：${c.file} 未同时具备 degraded 判定与可见提示 ⇒ 配置损坏会被画成「还没配」`);
      bad++;
    }
  }
  if (bad === 0) g.ok('F4b-M13：settings_load 的两个消费方都接了 degraded 且都有用户可见提示');
}

g.finish(`check-degraded-consumption: 全部通过（双视图发射 ${emitters.size} 条；过渡表 pending ${pending} 条，只减不增）`);
