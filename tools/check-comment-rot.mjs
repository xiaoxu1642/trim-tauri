#!/usr/bin/env node
// check-comment-rot.mjs —— 注释腐烂门禁（符号 / AGENTS 章节号 / 写死数字 三向对拍）
// （2026-10-08，审查方法论 §4.7.2「注释治理：不删，纳入机检」）
//
// 抓什么：本仓 2026-10-08 盘点出 **675 处**注释引用 `AGENTS §`／红线／白名单、
// **约 1,806 处**约束型注释（必须/禁止/否则/红线/不得/严禁/根因…），这些是
// 「为什么这么写」的唯一载体，因此裁定**不删**（删了 Rust 侧产物 0 变化、前端
// 仅省 <100KB，却要断掉全部跨文档引用）。代价是它们腐烂时**没有任何门禁会红**：
// 注释里写的符号被改名、引用的章节号被重排、写死的数字与现算分叉，全部静默。
//
// 三条断言（只判「注释提到的东西还在不在」，不判注释质量/风格/啰嗦）：
//   R1 符号腐烂 —— 注释里反引号包裹的本仓模块路径（engine::protect::xxx）与
//      本仓文件引用（tools/xxx.mjs、src-tauri/ps/xxx.ps1）在盘上已不存在即红。
//   R2 章节号腐烂 —— 注释里**紧邻 AGENTS 字样**的 `§x.y` 编号在 AGENTS.md 里
//      已不存在即红。裸 § 编号（可能指交接文档/方法论/发版手册）只统计不判红。
//   R3 数字腐烂 —— 注释里写死的「N 个 .ps1」「N 条门禁」与现算值不符即红；
//      带「曾经/历史/旧/退役/此前」等历史叙述词的整行豁免（那是陈述过去，不是承诺现在）。
//
// 两条必须知道的解析前提（踩过才写在这里）：
//   - AGENTS.md 的 §5/§7/§9 是**编号列表**（`1. xxx` … `24. xxx`），不是 markdown
//     子标题。只查 `^## 5.16` 会把全部 §5.x 引用误判成腐烂——必须支持「节内第 M 条」。
//   - 注释大量用**简写路径**（`protect::is_path_protected` 指 `engine::protect::…`）
//     与 **crate 别名**（`trim_finder::` = native-scanner crate）。只做严格顶层解析
//     会误报，只做模糊匹配又会放过真腐烂，故采用「先严格、失败后限深搜索」两段式。
//
// 纪律：
//   - AGENTS.md 是未跟踪的本机约束（.gitignore 第 10 行），干净克隆里没有。
//     缺文件时 R2 **显式 SKIP 并声明未校验**，不 ENOENT 崩、也不打 ✓ 冒充通过。
//   - 只判存在性，不判文风 —— 误报洪水会把真信号淹掉，这条不能破。
//   - 每条断言自带 POSITIVE_CONTROLS 合成样本自检（正反向都要：能判红 + 真样本不假红）。
//
// 用法：node tools/check-comment-rot.mjs
'use strict';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { walkFiles } from './lib/fs-walk.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC_RS = join(ROOT, 'src-tauri', 'src');
const SRC_TESTS = join(ROOT, 'src-tauri', 'tests');
const NATIVE_RS = join(ROOT, 'native-scanner', 'src');
const FRONTEND_JS = join(ROOT, 'src', 'scripts');
const FRONTEND_CSS = join(ROOT, 'src', 'styles');
const PS_DIR = join(ROOT, 'src-tauri', 'ps');
const TOOLS = join(ROOT, 'tools');
const AGENTS_MD = join(ROOT, 'AGENTS.md');

const IGNORE_DIR = (n) => n === 'target' || n === 'node_modules' || n === 'vendor' || n === 'fixtures' || n === '.git';
const isRs = (n) => n.endsWith('.rs');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 注释腐烂门禁（符号 / 章节号 / 数字 三向对拍）===\n');

// ────────────────────────────────────────────────────────────────────
// 0. 采集注释行
// ────────────────────────────────────────────────────────────────────

/**
 * 抽出文件里的注释行。块注释按状态机跨行收集；行注释要求 `//` 前不是 `:` 或
 * 单词字符（排除 `https://`、路径 `a//b` 这类假注释）。
 */
function commentLines(text) {
  const out = [];
  const lines = text.split(/\r?\n/);
  let inBlock = false;
  lines.forEach((raw, idx) => {
    const t = raw.trim();
    if (inBlock) {
      out.push({ line: idx + 1, text: raw });
      if (t.includes('*/')) inBlock = false;
      return;
    }
    if (/(?<![:\w\\/])\/\//.test(raw)) { out.push({ line: idx + 1, text: raw }); return; }
    if (t.startsWith('/*') || t.startsWith('/**')) {
      out.push({ line: idx + 1, text: raw });
      if (!t.includes('*/')) inBlock = true;
    }
  });
  return out;
}

const SCAN_ROOTS = [SRC_RS, SRC_TESTS, NATIVE_RS, FRONTEND_JS, FRONTEND_CSS];
const EXTS = (n) => n.endsWith('.rs') || n.endsWith('.js') || n.endsWith('.css');

const commentsByFile = new Map();
let commentLineTotal = 0;
for (const base of SCAN_ROOTS) {
  for (const fAbs of walkFiles(base, EXTS, { ignoreDir: IGNORE_DIR })) {
    const rel = relative(ROOT, fAbs).replace(/\\/g, '/');
    const cs = commentLines(readFileSync(fAbs, 'utf8'));
    if (cs.length) {
      commentsByFile.set(rel, cs);
      commentLineTotal += cs.length;
    }
  }
}

// ────────────────────────────────────────────────────────────────────
// R1 符号腐烂
// ────────────────────────────────────────────────────────────────────

const FOREIGN_CRATES = new Set([
  // 第三方 crate
  'std', 'core', 'alloc', 'serde', 'serde_json', 'tauri', 'tokio', 'anyhow', 'thiserror',
  'once_cell', 'regex', 'windows', 'winapi', 'log', 'chrono', 'uuid', 'base64', 'sha2',
  'hex', 'dirs', 'sysinfo', 'walkdir', 'indexmap', 'toml', 'url', 'reqwest', 'notify',
  // std 子模块的常见简写（`fs::read_to_string`、`env::var_os`）——注释里高频出现，
  // 它们不是本仓符号。宁可漏报一条也不制造误报洪水。
  'fs', 'env', 'io', 'path', 'process', 'thread', 'time', 'sync', 'collections', 'os',
  'cmp', 'fmt', 'str', 'ops', 'num', 'mem', 'ptr', 'ffi', 'cell', 'rc', 'iter', 'convert',
  'string', 'option', 'result', 'panic', 'marker', 'hash', 'future', 'task', 'pin', 'net',
  'error', 'slice', 'char', 'vec', 'boxed', 'borrow', 'clone', 'default', 'hint', 'array',
]);
// crate 别名 → 源码根（trim_finder 是 native-scanner 的 crate 名；trim_tauri_lib 是主 crate）
const CRATE_ROOTS = {
  trim_finder: NATIVE_RS,
  native_scanner: NATIVE_RS,
  trim_tauri_lib: SRC_RS,
  crate: SRC_RS,
};
const RE_MODPATH = /`([a-z_][a-z0-9_]*(?:::[a-z_][a-z0-9_]*)+)`/g;
const RE_LOCALFILE = /`(?:tools|src-tauri|src|native-scanner)\/[A-Za-z0-9_\-./]*\.(?:mjs|js|ps1|json|rs|css|html)`/g;

// 符号定义索引（含 `mod xxx;` 内联声明，因为简写路径会停在内联 mod 上）
const defIndex = new Map();
const RE_DEF = /\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?(?:fn|const|static|struct|enum|trait|type|union|macro_rules!|mod)\s+([A-Za-z_][A-Za-z0-9_]*)/g;
function defsOf(file) {
  if (defIndex.has(file)) return defIndex.get(file);
  const s = new Set();
  try {
    const text = readFileSync(file, 'utf8');
    let m;
    RE_DEF.lastIndex = 0;
    while ((m = RE_DEF.exec(text)) !== null) s.add(m[1]);
  } catch { /* 读不到即空集，由调用方判红 */ }
  defIndex.set(file, s);
  return s;
}
const dirHasDef = (dir, name) => {
  if (!existsSync(dir)) return false;
  for (const f of walkFiles(dir, isRs, { ignoreDir: IGNORE_DIR })) {
    if (defsOf(f).has(name)) return true;
  }
  return false;
};

/**
 * 严格解析：逐段推进状态集 {dir, file}。段可以是文件、目录模块，或文件内联 `mod`。
 * 末段额外允许「是某个已解析文件/目录里定义的符号」。
 */
function tryResolve(root, segs) {
  let states = [{ dir: root, file: null }];
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    const next = [];
    for (const st of states) {
      const asFile = join(st.dir, `${seg}.rs`);
      const asDir = join(st.dir, seg);
      if (existsSync(asFile)) next.push({ dir: asDir, file: asFile });
      if (existsSync(asDir) && existsSync(join(asDir, 'mod.rs'))) next.push({ dir: asDir, file: join(asDir, 'mod.rs') });
      else if (existsSync(asDir)) next.push({ dir: asDir, file: null });
      if (st.file && defsOf(st.file).has(seg)) next.push({ dir: st.dir, file: st.file });
      if (!st.file && dirHasDef(st.dir, seg)) next.push({ dir: st.dir, file: null });
    }
    if (next.length === 0) {
      if (i !== segs.length - 1) return false;
      // 末段当符号
      for (const st of states) {
        if (st.file && defsOf(st.file).has(seg)) return true;
        if (dirHasDef(st.dir, seg)) return true;
      }
      return false;
    }
    states = next;
  }
  return states.length > 0;
}

/** 限深搜索：找 name 作为文件/目录出现的所有父目录（用于简写路径）。 */
function findCandidateDirs(root, name, maxDepth = 3) {
  const out = [];
  const go = (d, depth) => {
    if (depth > maxDepth) return;
    let ents;
    try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (!e.isDirectory()) continue;
      const p = join(d, e.name);
      if (IGNORE_DIR(e.name)) continue;
      if (existsSync(join(p, `${name}.rs`)) || existsSync(join(p, name))) out.push(p);
      go(p, depth + 1);
    }
  };
  go(root, 1);
  return out;
}

function resolveModPath(rawSegs) {
  const segs = rawSegs.filter((s) => s !== 'crate' && s !== 'self' && s !== 'super');
  if (segs.length === 0) return true;
  const alias = CRATE_ROOTS[rawSegs[0]];
  const attempts = [];
  if (alias) attempts.push([alias, segs.filter((s) => s !== rawSegs[0])]);
  attempts.push([SRC_RS, segs], [NATIVE_RS, segs]);
  for (const [root, ss] of attempts) {
    if (ss.length === 0) continue;
    if (tryResolve(root, ss)) return true;
    // 简写：首段不在顶层时，限深搜索后重试（只放宽首段，后续段仍然严格）
    if (ss.length >= 1) {
      for (const base of findCandidateDirs(root, ss[0], 3)) {
        if (tryResolve(join(base, '..'), ss)) return true;
      }
    }
  }
  return false;
}

// 误报豁免：登记一条必须写清「为什么它不是本仓符号」。
const ALLOW_SYMBOLS = new Set([
  // 初版空表 —— 跑通后按实际误报逐条补（与 check-escape-delegation 的 BASELINE 同纪律）。
]);
// 已确认腐烂但暂不改注释的（**待修**：修完注释即从本表移除，理由必须写清实情）
const TOLERATED_SYMBOLS = new Map([
  ['trim_finder::scan::recycle::send_to_trash', '实际函数名是 send_to_trash_os（native-scanner/src/scan.rs:1676），注释差 `_os` 后缀'],
  // 该符号确已删除，而注释陈述的正是「v3 C-1 把它收敛到 engine::native::to_wide」这桩史实
  // （同段落首行有「v3 C-1 …全部收敛到此」，但命中行本身不含历史词，故按坐标登记）。
  ['contextmenu::to_wide16', '符号已随 v3 C-1 收敛删除；注释在陈述收敛史，建议改写为「原 contextmenu::to_wide16」'],
]);
// Electron 轨（上游只读基线）坐标：本仓是 Tauri 轨，`src/main/`、`src/data/`、
// `src/platform_impl/` 是上游的目录形态，注释引用它们是**跨轨说明**不是腐烂。
const ALLOW_FILE_PREFIXES = [
  { prefix: 'src/main/', reason: 'Electron 轨（上游只读基线）坐标，非本仓路径' },
  { prefix: 'src/platform_impl/', reason: 'Electron 轨坐标' },
  { prefix: 'src/data/', reason: 'Electron 轨坐标（本仓对应 src-tauri/data/）' },
];
// 已确认腐烂但暂不改注释的（**待修**：修完注释即从本表移除）
const TOLERATED_FILES = new Map([
  ['tools/cdp-smoke.mjs', 'CDP 已弃用（AGENTS §5.14）；注释是历史说明，待改成「曾有的工具」措辞'],
]);

// 陈述过去的注释不判红（「v3 C-1 把 contextmenu::to_wide16 收敛到此」是史实，
// 该符号确实已删——这正是注释在说明的事，不是腐烂）
const RE_HISTORICAL = /曾经|曾|历史|旧版|原来|此前|过后|退役|早期|过去|一度|之前|原本|旧|收敛到此|已删|统一走|v\d|原 /;

const rotSymbols = [];
const rotFiles = [];
const toleratedHits = [];
for (const [rel, cs] of commentsByFile) {
  for (const c of cs) {
    if (RE_HISTORICAL.test(c.text)) continue;
    let m;
    RE_MODPATH.lastIndex = 0;
    while ((m = RE_MODPATH.exec(c.text)) !== null) {
      const raw = m[1];
      if (ALLOW_SYMBOLS.has(raw)) continue;
      const segs = raw.split('::');
      if (segs.length < 2) continue;
      if (FOREIGN_CRATES.has(segs[0])) continue;
      if (!resolveModPath(segs)) {
        if (TOLERATED_SYMBOLS.has(raw)) toleratedHits.push(`${rel}:${c.line} \`${raw}\``);
        else rotSymbols.push(`${rel}:${c.line} \`${raw}\``);
      }
    }
    RE_LOCALFILE.lastIndex = 0;
    while ((m = RE_LOCALFILE.exec(c.text)) !== null) {
      const p = m[0].slice(1, -1);
      if (ALLOW_FILE_PREFIXES.some((a) => p.startsWith(a.prefix))) continue;
      if (TOLERATED_FILES.has(p)) { toleratedHits.push(`${rel}:${c.line} ${p}`); continue; }
      if (!existsSync(join(ROOT, p))) rotFiles.push(`${rel}:${c.line} ${m[0]}`);
    }
  }
}
check(
  rotSymbols.length === 0,
  `R1a. 注释引用的本仓模块路径全部在盘上存在（扫 ${commentLineTotal} 行注释）`,
  rotSymbols.length ? rotSymbols.slice(0, 10).join('；') + (rotSymbols.length > 10 ? ` …共 ${rotSymbols.length} 处` : '') : '无腐烂',
);
check(
  rotFiles.length === 0,
  'R1b. 注释引用的本仓文件路径全部在盘上存在',
  rotFiles.length ? rotFiles.slice(0, 10).join('；') : '无腐烂',
);

// ────────────────────────────────────────────────────────────────────
// R2 章节号腐烂（AGENTS.md 缺席即 SKIP，不打 ✓）
// ────────────────────────────────────────────────────────────────────

// 已确认腐烂但暂不改注释的章节号（**待修**）。
// AGENTS.md 2026-10-07 重排后把原 §7.1–§7.6、§8 迁去《本机发版手册》，并在文末
// 留了「## 旧编号锚点」对照表。注释里仍写 `AGENTS §7.3` / `AGENTS §9.2` 的，
// 指向的是**迁移前**的编号——现在按图索骥会找不到，属真腐烂，应改指发版手册。
const TOLERATED_SECTIONS = new Map([
  ['7.3', '原 §7.3 已迁《本机发版手册》同名小节（AGENTS.md「旧编号锚点」节），注释应改指发版手册'],
  ['9.2', 'AGENTS.md §9 现为 `-` 列表无子编号，§9.2 是重排前残留，注释应改指实际小节'],
]);

const agentsPresent = existsSync(AGENTS_MD);
let rotSections = [];
let bareSectionRefs = 0;
let checkedSectionRefs = 0;

if (!agentsPresent) {
  console.log('⚠ AGENTS.md 不在本机（未跟踪文件）：R2 章节号腐烂**未校验**');
} else {
  const agentsText = readFileSync(AGENTS_MD, 'utf8');
  const agentsLines = agentsText.split(/\r?\n/);
  const esc = (s) => s.replace(/\./g, '\\.');

  /** 章节号是否在 AGENTS.md 中存在：① markdown 标题 ② 节内第 M 条列表项 */
  const hasSection = (num) => {
    if (new RegExp(`^\\s{0,3}#{1,6}\\s*§?\\s*${esc(num)}(?!\\d)`, 'm').test(agentsText)) return true;
    if (new RegExp(`§\\s*${esc(num)}(?!\\d)`).test(agentsText)) return true;
    const two = /^(\d+)\.(\d+)$/.exec(num);
    if (!two) return false;
    const [, top, sub] = two;
    // 定位 `## <top>.` 标题，到下一个 `## ` 之间找第 <sub> 条
    let start = -1;
    let end = agentsLines.length;
    for (let i = 0; i < agentsLines.length; i++) {
      const hm = /^\s{0,3}#{2,6}\s*§?\s*(\d+)\s*[.、]?\s/.exec(agentsLines[i]);
      if (!hm) continue;
      if (hm[1] === top && start < 0) { start = i; continue; }
      if (start >= 0) { end = i; break; }
    }
    if (start < 0) return false;
    const listRe = new RegExp(`^\\s*${sub}\\s*[.、)）]`);
    for (let i = start + 1; i < end; i++) {
      if (listRe.test(agentsLines[i])) return true;
    }
    return false;
  };

  // 归属：只判「AGENTS 紧邻 §」。若中间插入别的文档名（交接/方法论/发版手册…），
  // 那个 § 不属于 AGENTS，只统计不判红。
  const RE_AGENTS_REF = /AGENTS(?:\.md)?([^§\n]{0,30}?)§\s*(\d+(?:\.\d+)*)/g;
  const OTHER_DOC = /交接|方法论|发版手册|方案|报告|手册|文档|规范/;
  for (const [rel, cs] of commentsByFile) {
    for (const c of cs) {
      RE_AGENTS_REF.lastIndex = 0;
      let m;
      let matchedHere = 0;
      while ((m = RE_AGENTS_REF.exec(c.text)) !== null) {
        const between = m[1] || '';
        if (OTHER_DOC.test(between)) { bareSectionRefs++; continue; }
        matchedHere++;
        checkedSectionRefs++;
        if (!hasSection(m[2])) {
          if (TOLERATED_SECTIONS.has(m[2])) toleratedHits.push(`${rel}:${c.line} AGENTS §${m[2]}`);
          else rotSections.push(`${rel}:${c.line} §${m[2]}`);
        }
      }
      // 整行其余裸 § 编号（无 AGENTS 归属）只统计
      const rest = c.text.replace(RE_AGENTS_REF, '');
      bareSectionRefs += (rest.match(/§\s*\d+(?:\.\d+)*/g) || []).length;
      void matchedHere;
    }
  }
}
check(
  !agentsPresent || rotSections.length === 0,
  agentsPresent
    ? `R2. 注释引用的 AGENTS 章节号全部存在（判 ${checkedSectionRefs} 处；另有 ${bareSectionRefs} 处裸 § 编号只统计）`
    : 'R2. AGENTS 章节号检查 SKIP（AGENTS.md 不在本机）',
  agentsPresent
    ? (rotSections.length ? rotSections.slice(0, 10).join('；') + (rotSections.length > 10 ? ` …共 ${rotSections.length} 处` : '') : '无腐烂')
    : '本节未校验',
);

// ────────────────────────────────────────────────────────────────────
// R3 数字腐烂（历史叙述豁免）
// ────────────────────────────────────────────────────────────────────

const ps1Count = existsSync(PS_DIR) ? readdirSync(PS_DIR).filter((f) => f.endsWith('.ps1')).length : -1;
const gateCount = readdirSync(TOOLS).filter((f) => /^check-.*\.mjs$/.test(f)).length;

const R3_PATTERNS = [
  { re: /(\d+)\s*(?:个|条|份|只)?\s*\.ps1/g, expect: ps1Count, label: '.ps1 脚本数' },
  { re: /(\d+)\s*条\s*(?:Node\s*)?门禁/g, expect: gateCount, label: '门禁条数' },
];
// RE_HISTORICAL 已在 R1 段定义，此处复用（「曾经 66 个 .ps1」是史实，不是承诺）

const rotNumbers = [];
for (const [rel, cs] of commentsByFile) {
  for (const c of cs) {
    if (RE_HISTORICAL.test(c.text)) continue;
    for (const p of R3_PATTERNS) {
      if (p.expect < 0) continue;
      p.re.lastIndex = 0;
      let m;
      while ((m = p.re.exec(c.text)) !== null) {
        if (Number(m[1]) !== p.expect) rotNumbers.push(`${rel}:${c.line} 写「${m[0]}」现算 ${p.expect}（${p.label}）`);
      }
    }
  }
}
check(
  rotNumbers.length === 0,
  `R3. 注释写死的数字与现算一致（.ps1 ${ps1Count} / 门禁 ${gateCount}）`,
  rotNumbers.length ? rotNumbers.slice(0, 10).join('；') + (rotNumbers.length > 10 ? ` …共 ${rotNumbers.length} 处` : '') : '无腐烂',
);

// ────────────────────────────────────────────────────────────────────
// 收尾
// ────────────────────────────────────────────────────────────────────

if (fail > 0) {
  console.error(`\ncheck-comment-rot: ${fail} 组断言未通过（注释已腐烂，见上）`);
  process.exit(1);
}
if (toleratedHits.length) {
  console.log(`\n⚠ 待修：${toleratedHits.length} 处已确认腐烂，暂缓豁免使门禁可绿，**应改注释后从豁免表移除**`);
  for (const h of toleratedHits) console.log(`    · ${h}`);
  console.log('');
}

// ---- 正向对照自检：三条断言各自的判定器必须能判红，且真样本不假红 ----
const POSITIVE_CONTROLS = (() => {
  const problems = [];

  // R1a 反向：真实路径必须判是（防判定器变成「永远红」）
  if (!resolveModPath(['engine', 'protect'])) problems.push('R1a 失效：engine::protect 未判为存在');
  if (!resolveModPath(['engine', 'protect', 'is_path_protected'])) problems.push('R1a 失效：engine::protect::is_path_protected 未判为存在');
  if (!resolveModPath(['trim_finder', 'cleanup_scan', 'run_json'])) problems.push('R1a 失效：trim_finder::cleanup_scan::run_json 未判为存在');
  if (!resolveModPath(['protect', 'is_path_protected'])) problems.push('R1a 失效：简写 protect::is_path_protected 未判为存在');
  // R1a 正向：不存在必须判否
  if (resolveModPath(['engine', 'no_such_module_xyz', 'nope_fn'])) problems.push('R1a 失效：不存在的模块路径被判为存在');
  if (resolveModPath(['no_such_module_xyz', 'nope_fn'])) problems.push('R1a 失效：不存在的简写被判为存在');

  // R2：合成不存在的章节号必须判否（且真章节号必须判是）
  if (agentsPresent) {
    const agentsText = readFileSync(AGENTS_MD, 'utf8');
    const agentsLines2 = agentsText.split(/\r?\n/);
    const esc2 = (s) => s.replace(/\./g, '\\.');
    const has = (num) => {
      if (new RegExp(`^\\s{0,3}#{1,6}\\s*§?\\s*${esc2(num)}(?!\\d)`, 'm').test(agentsText)) return true;
      if (new RegExp(`§\\s*${esc2(num)}(?!\\d)`).test(agentsText)) return true;
      const two = /^(\d+)\.(\d+)$/.exec(num);
      if (!two) return false;
      let start = -1; let end = agentsLines2.length;
      for (let i = 0; i < agentsLines2.length; i++) {
        const hm = /^\s{0,3}#{2,6}\s*§?\s*(\d+)\s*[.、]?\s/.exec(agentsLines2[i]);
        if (!hm) continue;
        if (hm[1] === two[1] && start < 0) { start = i; continue; }
        if (start >= 0) { end = i; break; }
      }
      if (start < 0) return false;
      const re = new RegExp(`^\\s*${two[2]}\\s*[.、)）]`);
      for (let i = start + 1; i < end; i++) if (re.test(agentsLines2[i])) return true;
      return false;
    };
    if (has('987.654')) problems.push('R2 失效：合成章节号 §987.654 被判为存在');
    if (!has('4.1')) problems.push('R2 失效：真实章节号 §4.1 未判为存在（会假红洪水）');
    if (!has('2')) problems.push('R2 失效：真实章节号 §2 未判为存在（标题带中文句号的形态漏了）');
  }

  // R3：合成数字必须被抓且与现算不符；一致的数字不得判红
  const synth = '// 现役脚本 99999 个 .ps1，别看错';
  let hit = false;
  R3_PATTERNS[0].re.lastIndex = 0;
  let mm;
  while ((mm = R3_PATTERNS[0].re.exec(synth)) !== null) if (Number(mm[1]) !== ps1Count) hit = true;
  if (!hit) problems.push('R3 失效：合成数字 99999 未被抓到');
  const good = `// 现役脚本 ${ps1Count} 个 .ps1，别看错`;
  let falseRed = false;
  R3_PATTERNS[0].re.lastIndex = 0;
  while ((mm = R3_PATTERNS[0].re.exec(good)) !== null) if (Number(mm[1]) !== ps1Count) falseRed = true;
  if (falseRed) problems.push('R3 失效：与现算一致的数字被判红');

  if (problems.length) {
    for (const p of problems) console.error(`✗ ${p}`);
    process.exit(1);
  }
  console.log('✓ 正向对照自检通过（三条断言均可判红，且真样本不假红）');
  return true;
})();

console.log(`check-comment-rot: 全部通过（扫 ${commentsByFile.size} 个文件 / ${commentLineTotal} 行注释）`);
