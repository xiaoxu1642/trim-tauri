#!/usr/bin/env node
// check-comment-rot.mjs —— 注释腐烂门禁（符号 / AGENTS 章节号 / 写死数字 三向对拍）
// （2026-10-08，审查方法论 §4.7.2「注释治理：不删，纳入机检」）
//
// 抓什么：本仓 2026-10-08 盘点出一批注释引用 `AGENTS §`／红线／白名单、以及大量
// 约束型注释（必须/禁止/否则/红线/不得/严禁/根因…），这些是
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
//   - AGENTS.md 自 2026-10-24 起入库；万一缺席时 R2 **显式 SKIP 并声明未校验**，
//     不 ENOENT 崩、也不打 ✓ 冒充通过。
//   - 只判存在性，不判文风 —— 误报洪水会把真信号淹掉，这条不能破。
//   - 每条断言自带 POSITIVE_CONTROLS 合成样本自检（正反向都要：能判红 + 真样本不假红）。
//
// 用法：node tools/check-comment-rot.mjs
'use strict';
import { readFileSync, existsSync, readdirSync, writeFileSync } from 'node:fs';
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

// P3-5（T1-M01，2026-10-09）语料扩容：收 tools/ 与 .mjs —— 门禁自己的注释里
// 写死的数字/坐标同样会腐烂，而旧语料只扫 src 侧，`tools/` 不在 SCAN_ROOTS、
// `.mjs` 不在 EXTS，属「判据对象整片缺席」。
const SCAN_ROOTS = [SRC_RS, SRC_TESTS, NATIVE_RS, FRONTEND_JS, FRONTEND_CSS, TOOLS];
const EXTS = (n) => n.endsWith('.rs') || n.endsWith('.js') || n.endsWith('.css') || n.endsWith('.mjs');
// 本门禁自己的 POSITIVE_CONTROLS 合成样本（`'// …99999 个 .ps1…'` 这类字符串字面量）
// 会被 commentLines 当成注释行扫到 —— 样本是刻意写假的，扫描语料必须排除本文件
// （与 check-idle-scripts 的 include_str! 自指是同一类坑：判定器不得吃自己的样本）。
const SELF_FILE = 'tools/check-comment-rot.mjs';

const commentsByFile = new Map();
let commentLineTotal = 0;
for (const base of SCAN_ROOTS) {
  for (const fAbs of walkFiles(base, EXTS, { ignoreDir: IGNORE_DIR })) {
    const rel = relative(ROOT, fAbs).replace(/\\/g, '/');
    if (rel === SELF_FILE) continue; // 自指豁免：本文件的合成样本见上注
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
// P3-5（2026-10-09）：两条历史命中已按建议改注释（`send_to_trash_os` 补后缀 /
// 「原 contextmenu::to_wide16」补历史词），本表清零 —— 清零态就是棘轮上限，再出现只能真修。
const TOLERATED_SYMBOLS = new Map([]);
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
// T1b-K02（v7.2 C09）：`v\d` 从豁免词表移除。本仓 `v2-F15`/`v6-K13` 是引用编号习惯
// （不是过去时），把「写过批次号的注释」整片划出判定面，等于给现在时的结构声称
// 开了无边界后门——实测 3125 行豁免里 1515 行只因含 `v<数字>`，其中就藏着
// app.rs「139 条命令」这种真腐烂。过去时语义由其余词（曾经/旧版/此前/退役…）承担，
// 带 `v` 的史实句要豁免就用过去时措辞写，不靠批次号自动豁免。
const RE_HISTORICAL = /曾经|曾|历史|旧版|原来|此前|过后|退役|早期|过去|一度|之前|原本|旧|收敛到此|已删|统一走|原 /;

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
// P3-5（2026-10-09）：7.3 / 9.2 的六处引用已改指《本机发版手册》《红线依据-竞品反例》
// 同名小节（AGENTS.md「## 旧编号锚点」节给了对照），本表清零。
const TOLERATED_SECTIONS = new Map([]);

const agentsPresent = existsSync(AGENTS_MD);
let rotSections = [];
let bareSectionRefs = 0;
let checkedSectionRefs = 0;

if (!agentsPresent) {
  console.log('⚠ AGENTS.md 缺席（未随仓库分发）：R2 章节号腐烂**未校验**');
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
    : 'R2. AGENTS 章节号检查 SKIP（AGENTS.md 缺席）',
  agentsPresent
    ? (rotSections.length ? rotSections.slice(0, 10).join('；') + (rotSections.length > 10 ? ` …共 ${rotSections.length} 处` : '') : '无腐烂')
    : '本节未校验',
);

// ────────────────────────────────────────────────────────────────────
// R3 数字腐烂（历史叙述豁免）—— P3-5 扩到四种形态（T1-M01，2026-10-09）：
//   ① .ps1 脚本数 / Node 门禁条数（原有）
//   ② 命令条数（「N 条命令」）—— 现算 = lib.rs generate_handler! 注册条目数
//   ③ `NAME=NUM`（反引号内）—— 现算 = 源码里该常量的数值字面量；常量不存在即红
//   ④ `file:行` 坐标 —— 文件须在盘上且行号 ≤ 文件行数（禁「按图索骥找不到」）
//   KB 体积**不设硬数字比对**（体积随每次编辑合法漂移，硬比对必假红）——
//   改为策略性禁止：注释不写精确 KB（判据=模式命中即红，改「约百 KB 量级」措辞）。
//   这套形态取自 v4 报告组 10 的 11 个实例（R6-L02/R8-L02/R2-L01/R3-L02/R1-L02/
//   F3-L01/L14 等），每条的实例修法见对应提交。
// ────────────────────────────────────────────────────────────────────

const ps1Count = existsSync(PS_DIR) ? readdirSync(PS_DIR).filter((f) => f.endsWith('.ps1')).length : -1;
const gateCount = readdirSync(TOOLS).filter((f) => /^check-.*\.mjs$/.test(f)).length;
// 命令条数与 check-channel-map 的 D2 口径一致：只数 generate_handler! 块里的注册条目
const registeredCmdCount = (() => {
  const lib = readFileSync(join(ROOT, 'src-tauri', 'src', 'lib.rs'), 'utf8');
  const s = lib.indexOf('generate_handler![');
  const e = lib.indexOf('])', s);
  return s < 0 || e < 0 ? -1 : [...lib.slice(s, e).matchAll(/commands::\w+::\w+/g)].length;
})();

// `NAME=NUM` 的现算源：全仓源码里该常量的数值字面量（const/static，RS 与 JS 通用）
const CONST_DEF_RE = (name) =>
  new RegExp(String.raw`(?:const|static)\s+` + name + String.raw`\b[^=\n]*=\s*(\d+)`);
/** 源码全文（用于常量现算；语料面与注释扫描一致） */
const srcTexts = (() => {
  const out = [];
  for (const base of SCAN_ROOTS) {
    for (const fAbs of walkFiles(base, (n) => n.endsWith('.rs') || n.endsWith('.js') || n.endsWith('.mjs'), { ignoreDir: IGNORE_DIR })) {
      out.push(readFileSync(fAbs, 'utf8'));
    }
  }
  return out;
})();
function constValueOf(name) {
  for (const t of srcTexts) {
    const m = CONST_DEF_RE(name).exec(t);
    if (m) return Number(m[1]);
  }
  return null;
}

const R3_PATTERNS = [
  { re: /(\d+)\s*(?:个|条|份|只)?\s*\.ps1/g, expect: ps1Count, label: '.ps1 脚本数' },
  { re: /(\d+)\s*条\s*(?:Node\s*)?门禁/g, expect: gateCount, label: '门禁条数' },
  { re: /(\d+)\s*条(?:已注册|注册)?命令/g, expect: registeredCmdCount, label: '注册命令条数' },
];
// RE_HISTORICAL 已在 R1 段定义，此处复用（「曾经 66 个 .ps1」是史实，不是承诺）

// ③ `NAME=NUM`（反引号内，全大写常量名——避免误伤 `x=1` 这类示意）
const RE_CONST_EQ = /`([A-Z][A-Z0-9_]{2,})=(\d+)`/g;
// 外部 API 常量登记：这些名字的数值定义在 windows crate（本仓只引用），
// 现算不到不代表腐烂；登记须写明属于哪个 API 族。
const ALLOW_EXTERNAL_CONST = new Map([
  ['DN_STARTED', 'Windows cfgmgr32 设备状态位（windows crate 常量）'],
  ['DN_HAS_PROBLEM', '同上'],
  ['CR_BUFFER_SMALL', 'Windows cfgmgr32 CONFIGRET 返回码'],
]);
// ④ `file:行`：只判带仓内前缀的路径（裸文件名与 docs/ 本机资料区不在判定面——
// 前者无法解析、后者不入库；判据是「干净克隆里按图索骥仍找得到」）
const RE_FILE_LINE = /`((?:src|src-tauri|tools|native-scanner)\/[\w./-]+\.(?:rs|js|mjs|ps1|json|css|html)):(\d+)`/g;
// ⑤ KB 体积：注释不写「测量型」精确 KB（体积随编辑漂移，硬数字必腐烂）；
//    「约定常量型」（缓冲区/截断/规格值）按 {file, needle} 登记放行 —— 这类数字
//    描述的是代码常量或系统规格，不是对当前文件的测量。带「级」的量级措辞天然放行。
const RE_KB_CLAIM = /(\d+)\s*KB\b(?!\s*级)/g;
const KB_SPEC_ALLOW = [
  { file: 'src-tauri/src/engine/log.rs', needle: '512KB', reason: '日志读取截断常量（代码常量，非测量）' },
  { file: 'src-tauri/src/commands/log.rs', needle: '512KB', reason: '同上（log:read 语义对齐注释）' },
  { file: 'src-tauri/src/commands/settings.rs', needle: '64KB', reason: '偏好值上限闸（代码常量）' },
  { file: 'src-tauri/src/engine/winhttp.rs', needle: '64KB', reason: '流式读取缓冲尺寸（代码常量）' },
  { file: 'src/scripts/netspeed.js', needle: '256 KB/s', reason: '活动判定阈值（SPIKE_BPS 常量）' },
  { file: 'src-tauri/src/engine/systembin.rs', needle: '4 KB', reason: 'Windows 匿名管道默认缓冲量级——系统约定值而非测量结果，且它是 v3 P0-1「边跑边读」判据的核心临界点' },
  { file: 'native-scanner/src/cleanup_scan.rs', needle: '2 KB', reason: 'to_long_path 的缓冲下限由代码常量 max(1024) 个 u16 推得（=2048 B），是约定值非测量；v3 P1-8 用它论证出口短路值得做' },
  { file: 'native-scanner/src/util.rs', needle: '2 KB', reason: '同上——同一常量的出处侧' },
];

const rotNumbers = [];
const rotConstEq = [];
const rotFileLine = [];
const rotKb = [];
const rotPs1 = [];
// T1b-K03（R3f）：`.ps1` 提及判定面。白名单登记 {file, anchor, reason}（§5.19 禁行号），
// 每条必须真命中 ≥1 次，否则判「白名单腐烂」。
const RE_PS1_MENTION = /`?([\w.-]+\.ps1)(?::(\d+))?`?/g;
const psOnDisk = existsSync(PS_DIR)
  ? new Set(readdirSync(PS_DIR).filter((f) => f.endsWith('.ps1')))
  : new Set();
const PS1_MENTION_ALLOW = [
  // 测试沙箱自造文件名（pwsh/mod.rs 超时用例把 old.ps1 的 mtime 推前）——
  // 非仓内坐标、非史实，按 §5.19 用 anchor 登记；改名即腐烂（命中 0 判红）。
  { file: 'src-tauri/src/pwsh/mod.rs', anchor: 'old.ps1', reason: '测试沙箱自造文件名（超时用例推 mtime），非仓内脚本引用' },
];
const ps1AllowUsed = new Set();
// T1b-K01（v7.2 C09）：逐形态对象数。旧地板把四类加总（实算 16），而 R3a 的 .ps1
// 形态与 R3c 的 file:行 形态在真语料上都是 0——加总被 R3b/R3d 喂饱后，
// 「R3c 摘网不会有任何信号」。现在每形态单独计数：真语料 0 对象的形态必须
// 在 CONTROLLED_R3_FORMS 里登记（对应下方自检块的合成对照），没登记的 0 对象形态判红。
const r3FormCounts = R3_PATTERNS.map((p) => ({ label: p.label, n: 0 }));
let constEqObjects = 0;
let fileLineObjects = 0;
let kbObjects = 0;
let r3Objects = 0; // 断言对象计数（0 ⇒ 语料/模式失明，是 T1-M01 的复现形态）
for (const [rel, cs] of commentsByFile) {
  for (const c of cs) {
    if (RE_HISTORICAL.test(c.text)) continue;
    for (const [pi, p] of R3_PATTERNS.entries()) {
      if (p.expect < 0) continue;
      p.re.lastIndex = 0;
      let m;
      while ((m = p.re.exec(c.text)) !== null) {
        r3Objects++;
        r3FormCounts[pi].n++;
        if (Number(m[1]) !== p.expect) rotNumbers.push(`${rel}:${c.line} 写「${m[0]}」现算 ${p.expect}（${p.label}）`);
      }
    }
    RE_CONST_EQ.lastIndex = 0;
    let m;
    while ((m = RE_CONST_EQ.exec(c.text)) !== null) {
      r3Objects++;
      constEqObjects++;
      if (ALLOW_EXTERNAL_CONST.has(m[1])) continue; // 外部 API 常量（见登记表）
      const actual = constValueOf(m[1]);
      if (actual === null) rotConstEq.push(`${rel}:${c.line} 写 \`${m[1]}=${m[2]}\`，但全仓找不到该常量的数值定义`);
      else if (actual !== Number(m[2])) rotConstEq.push(`${rel}:${c.line} 写 \`${m[1]}=${m[2]}\`，现算 ${actual}`);
    }
    RE_FILE_LINE.lastIndex = 0;
    while ((m = RE_FILE_LINE.exec(c.text)) !== null) {
      r3Objects++;
      fileLineObjects++;
      const p = join(ROOT, m[1]);
      if (!existsSync(p)) { rotFileLine.push(`${rel}:${c.line} 引用 ${m[1]}:${m[2]}，但文件不存在`); continue; }
      const lineNo = Number(m[2]);
      const lines = readFileSync(p, 'utf8').split('\n');
      if (lineNo > lines.length) rotFileLine.push(`${rel}:${c.line} 引用 ${m[1]}:${lineNo}，但该文件只有 ${lines.length} 行`);
      // R3e（P2-A/A-3）：R3c 只验「文件在、行号没越界」，这是**结构空转** ——
      // 坐标可以指着完全无关的一行而照样绿。现在要求同一条注释里用反引号点名被指对象，
      // 且该符号必须出现在引用行 ±2 行内。二者任一不成立即红：
      //   · 只给坐标不给名字 ⇒ 行号一漂，没人知道这条引用原本指谁；
      //   · 给了名字但 ±2 行找不到 ⇒ 要么坐标漂了、要么符号改名了，两种都是腐烂。
      const syms = [...c.text.matchAll(/`([A-Za-z_][A-Za-z0-9_]{2,})`/g)].map((x) => x[1]);
      if (syms.length === 0) {
        rotFileLine.push(`${rel}:${c.line} ${m[1]}:${lineNo} 只给坐标、没点名对象 ⇒ 补一个反引号符号名（否则行号一漂这条引用就成了无人认领的坐标）`);
        continue;
      }
      const win = lines.slice(Math.max(0, lineNo - 3), Math.min(lines.length, lineNo + 1)).join('\n');
      if (!syms.some((s) => new RegExp(`\\b${s}\\b`).test(win))) {
        rotFileLine.push(`${rel}:${c.line} 点名 ${syms.map((s) => `\`${s}\``).join(' / ')}，但 ${m[1]}:${lineNo} 的 ±2 行里没有它 ⇒ 坐标漂移或符号已改名`);
      }
    }
    RE_KB_CLAIM.lastIndex = 0;
    while ((m = RE_KB_CLAIM.exec(c.text)) !== null) {
      r3Objects++;
      kbObjects++;
      const allowed = KB_SPEC_ALLOW.some((a) => rel === a.file && c.text.includes(a.needle));
      if (!allowed) rotKb.push(`${rel}:${c.line} 写「${m[0]}」—— 测量型精确体积必腐烂；约定常量请登记 KB_SPEC_ALLOW，其余改「约百 KB 量级」措辞`);
    }
    // T1b-K03（R3f）：`.ps1` 提及的 basename 必须在 `src-tauri/ps/` 真实存在。
    // 本仓 PS 产物现算只剩 1 个脚本；历史脚本名必须以过去时措辞出现（史实句豁免走
    // RE_HISTORICAL），不许用现在时引用一个干净克隆里必然落空的文件。
    // 自造名（测试沙箱/示例）走 {file, anchor, reason} 登记制，每条必须真命中 ≥1。
    RE_PS1_MENTION.lastIndex = 0;
    while ((m = RE_PS1_MENTION.exec(c.text)) !== null) {
      const base = m[1];
      if (psOnDisk.has(base)) continue;
      const allowedIdx = PS1_MENTION_ALLOW.findIndex((a) => rel === a.file && c.text.includes(a.anchor));
      if (allowedIdx >= 0) { ps1AllowUsed.add(allowedIdx); continue; }
      rotPs1.push(`${rel}:${c.line} 提及「${base}」，但 src-tauri/ps/ 里没有这个脚本（PS 产物已退役；史实请用过去时措辞，示例名请登记 PS1_MENTION_ALLOW）`);
    }
  }
}
check(
  rotNumbers.length === 0,
  `R3a. 注释写死的数字与现算一致（.ps1 ${ps1Count} / 门禁 ${gateCount} / 命令 ${registeredCmdCount}）`,
  rotNumbers.length ? rotNumbers.slice(0, 10).join('；') + (rotNumbers.length > 10 ? ` …共 ${rotNumbers.length} 处` : '') : '无腐烂',
);
check(
  rotConstEq.length === 0,
  'R3b. 注释里 `NAME=NUM` 与源码常量值一致（含常量不存在的情况）',
  rotConstEq.length ? rotConstEq.slice(0, 10).join('；') : '无腐烂',
);
check(
  rotFileLine.length === 0,
  'R3c+R3e. 注释里的 `file:行` 坐标在盘上成立（文件存在、行号在范围内），且点名被指符号（±2 行内必须命中）',
  rotFileLine.length ? rotFileLine.slice(0, 10).join('；') : '无腐烂',
);
check(
  rotKb.length === 0,
  'R3d. 注释不写精确 KB 体积（改量级措辞，防体积漂移腐烂）',
  rotKb.length ? rotKb.slice(0, 10).join('；') : '无腐烂',
);
check(
  rotPs1.length === 0,
  `R3f. 注释提及的 .ps1 脚本必须在 src-tauri/ps/ 存在（现算盘上 ${psOnDisk.size} 个）`,
  rotPs1.length ? rotPs1.slice(0, 10).join('；') + (rotPs1.length > 10 ? ` …共 ${rotPs1.length} 处` : '') : '无死引用',
);
// T1b-K03：白名单每条必须真命中 ≥1（§5.19「不命中=腐烂」纪律，抄 doc-refs 2b 组）
check(
  ps1AllowUsed.size === PS1_MENTION_ALLOW.length,
  `R3f 白名单对账（登记 ${PS1_MENTION_ALLOW.length} 条 / 真命中 ${ps1AllowUsed.size} 条）`,
  ps1AllowUsed.size !== PS1_MENTION_ALLOW.length
    ? '存在从未命中的豁免条目——示例名已改名或登记已腐烂，删掉该条'
    : '',
);
// 扫描面地板：四类数字断言的对象总数为 0 ⇒ 模式/语料失明（T1-M01 的复现形态），判红
check(
  r3Objects >= 3,
  `R3 扫描面地板（数字断言对象 ${r3Objects} 处 ≥ 3）`,
  r3Objects < 3 ? '断言对象趋零 ⇒ 语料或模式失明' : '',
);
// T1b-K01：逐形态盲区核对。真语料 0 对象的形态必须有合成对照（下方自检块），
// 否则判红——「0 对象 + 无对照」= 判据死了没人知道。
const CONTROLLED_R3_FORMS = new Set([
  0, // .ps1 脚本数：自检块有 99999 合成样本（正反向）
  1, // 门禁条数：本批补的合成对照
  2, // 注册命令条数：自检块有合成样本
  3, // NAME=NUM（RE_CONST_EQ）：自检块 THROTTLE_MS / NO_SUCH_CONST 两向
  4, // file:行（RE_FILE_LINE）：自检块真坐标 / 幽灵坐标两向
  5, // KB 体积（RE_KB_CLAIM）：自检块量级措辞 / 测量型两向
]);
const zeroForms = [
  ...r3FormCounts.filter((f) => f.n === 0).map((f) => f.label),
  ...(constEqObjects === 0 ? ['NAME=NUM'] : []),
  ...(fileLineObjects === 0 ? ['file:行'] : []),
  ...(kbObjects === 0 ? ['KB 体积'] : []),
];
const uncontrolledZeros = zeroForms.filter((l) => {
  if (l === '.ps1 脚本数') return !CONTROLLED_R3_FORMS.has(0);
  if (l === '门禁条数') return !CONTROLLED_R3_FORMS.has(1);
  if (l === '注册命令条数') return !CONTROLLED_R3_FORMS.has(2);
  if (l === 'NAME=NUM') return !CONTROLLED_R3_FORMS.has(3);
  if (l === 'file:行') return !CONTROLLED_R3_FORMS.has(4);
  if (l === 'KB 体积') return !CONTROLLED_R3_FORMS.has(5);
  return true;
});
check(
  uncontrolledZeros.length === 0,
  `R3 逐形态盲区核对（.ps1 ${r3FormCounts[0].n} / 门禁 ${r3FormCounts[1].n} / 命令 ${r3FormCounts[2].n} / NAME=NUM ${constEqObjects} / file:行 ${fileLineObjects} / KB ${kbObjects}）`,
  uncontrolledZeros.length
    ? `这些形态真语料 0 对象且无合成对照：${uncontrolledZeros.join('、')}——补对照样本或登记 CONTROLLED_R3_FORMS`
    : '0 对象形态均有合成对照，其余形态对象数 > 0',
);

// ────────────────────────────────────────────────────────────────────
// 收尾
// ────────────────────────────────────────────────────────────────────

// P2-A/A-1：这里**原本**是 `if (fail > 0) process.exit(1)`，而 K08 对账块排在它后面并继续
// `fail++` —— 于是 K08 判红时退出码恒 0、门禁照样打印「全部通过」。假绿门禁比没门禁更糟：
// 台账上写着「check-comment-rot 通过」，而它根本没看这一组。
// 现在把退出闸门挪到全部断言之后（文件末尾），K08 与正向对照都在闸门之前。

// ────────────────────────────────────────────────────────────────────
// K08 对账门禁（v5 批次 9，A4-R01 / X0-K01 家族）：模块注释若声称某通道
// 「已注册 / 已落地」，该通道名必须能在盘上对上（lib.rs 注册或 CHANNEL_MAP）。
// 守的是「主动否认缺口」复发：residue_update.rs 曾写「均已落地」而四处对账
// 全空、还把「尚未接入」的旧说法标注为「只描述当时状态」——注释改为如实
// 描述「未接入」后本断言恒绿；它只在有人再把缺口写成成就时变红。
// ────────────────────────────────────────────────────────────────────
{
  const rupd = join(ROOT, 'src-tauri', 'src', 'commands', 'uninstall', 'residue_update.rs');
  if (existsSync(rupd)) {
    const text = readFileSync(rupd, 'utf8');
    const claimed = [
      ...text.matchAll(/(?:已注册|已落地|均已落地)[^\n]*?(uninstall:[\w-]+)/g),
    ].map((m) => m[1]);
    // A-1 的真破坏验证暴露出第二处缺陷：CHANNEL_MAP 那份文件的真实路径是
    // `src/scripts/tauri-api.js`，这里原先写 `src-tauri/src/scripts/...` —— 没有声称时
    // 循环不执行，路径错了也无人发现；一旦真有人写下「已落地 uninstall:x」，本门禁不是
    // 判红而是 ENOENT 崩栈（AGENTS §5 明令：读不到要显式 SKIP 并声明未校验，不崩、不假绿）。
    const libPath = join(ROOT, 'src-tauri', 'src', 'lib.rs');
    const cmapPath = join(ROOT, 'src', 'scripts', 'tauri-api.js');
    if (claimed.length > 0 && (!existsSync(libPath) || !existsSync(cmapPath))) {
      console.error(`✗ K08 对账无法执行：声称了 ${claimed.join('、')}，但注册面文件缺失（lib.rs ${existsSync(libPath) ? '在' : '缺'} / CHANNEL_MAP ${existsSync(cmapPath) ? '在' : '缺'}）——这一节未校验，按失败处理`);
      fail++;
    } else {
      const lib = claimed.length > 0 ? readFileSync(libPath, 'utf8') : '';
      const cmap = claimed.length > 0 ? readFileSync(cmapPath, 'utf8') : '';
      for (const ch of claimed) {
        if (!lib.includes(ch) && !cmap.includes(ch)) {
          console.error(`✗ K08 对账：residue_update.rs 声称 ${ch} 已注册/已落地，但 lib.rs 与 CHANNEL_MAP 都找不到（注释写成了成就）`);
          fail++;
        }
      }
    }
    if (claimed.length === 0) {
      console.log('✓ K08 对账：residue_update.rs 无「已注册/已落地」声称（在线更新退役口径如实）');
    }
  }
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

  // R3a 命令条数：合成错数必须命中；现算数必须放行
  R3_PATTERNS[2].re.lastIndex = 0;
  const cmdSynth = `// 共 ${registeredCmdCount + 1} 条注册命令`;
  if (!R3_PATTERNS[2].re.test(cmdSynth)) problems.push('R3a 失效：命令条数合成样本未被抓到');
  const cmdGood = `// 共 ${registeredCmdCount} 条注册命令`;
  R3_PATTERNS[2].re.lastIndex = 0;
  const gm = R3_PATTERNS[2].re.exec(cmdGood);
  if (!gm || Number(gm[1]) !== registeredCmdCount) problems.push('R3a 失效：现算命令条数被判红');

  // R3a 门禁条数（T1b-K01 补）：该形态真语料 0 对象，判据活性只能靠合成样本证明
  R3_PATTERNS[1].re.lastIndex = 0;
  const gateSynth = `// 共 ${gateCount + 1} 条 Node 门禁`;
  if (!R3_PATTERNS[1].re.test(gateSynth)) problems.push('R3a 失效：门禁条数合成样本未被抓到');
  const gateGood = `// 共 ${gateCount} 条 Node 门禁`;
  R3_PATTERNS[1].re.lastIndex = 0;
  const gGood = R3_PATTERNS[1].re.exec(gateGood);
  if (!gGood || Number(gGood[1]) !== gateCount) problems.push('R3a 失效：现算门禁条数被判红');

  // R3f（T1b-K03）：盘上不存在的 .ps1 必须被抓；盘上真名必须放行
  {
    const onDisk = [...psOnDisk][0];
    if (!onDisk) {
      problems.push('R3f 失效：src-tauri/ps/ 为空，R3f 的放行腿无法自证（登记 RETIRED 前先想清楚）');
    } else {
      const badLine = '// 对应 retired_probe_xyz.ps1 的旧语义';
      RE_PS1_MENTION.lastIndex = 0;
      const bm = RE_PS1_MENTION.exec(badLine);
      if (!bm || psOnDisk.has(bm[1])) problems.push('R3f 失效：不存在的 .ps1 提及未被抓到');
      const goodLine = `// 对应 ${onDisk} 的现役脚本`;
      RE_PS1_MENTION.lastIndex = 0;
      const gm2 = RE_PS1_MENTION.exec(goodLine);
      if (!gm2 || !psOnDisk.has(gm2[1])) problems.push('R3f 失效：盘上真名被判为死引用');
      RE_PS1_MENTION.lastIndex = 0;
    }
  }

  // R3b：不存在的常量必须现算 null；真实常量（mouse-trail.js THROTTLE_MS=22）必须现算到
  if (constValueOf('NO_SUCH_CONST_XYZ') !== null) problems.push('R3b 失效：不存在的常量现算不为 null');
  if (constValueOf('THROTTLE_MS') !== 22) problems.push('R3b 失效：真实常量 THROTTLE_MS 现算不到 22');

  // R3c：真实存在的 file:行 不得假红；不存在的文件必须命中
  const realRef = '`tools/check-comment-rot.mjs:1`';
  const realPath = join(ROOT, 'tools/check-comment-rot.mjs');
  if (!existsSync(realPath) || 1 > readFileSync(realPath, 'utf8').split('\n').length) problems.push('R3c 失效：真实 file:行 被判红');
  const ghost = '`tools/no-such-file-xyz.mjs:9`';
  const g2 = /`((?:src|src-tauri|tools|native-scanner)\/[\w./-]+\.(?:rs|js|mjs|ps1|json|css|html)):(\d+)`/.exec(ghost);
  if (!g2 || existsSync(join(ROOT, g2[1]))) problems.push('R3c 失效：不存在的坐标未被抓到');

  // R3e（P2-A/A-3）：坐标**存在但指错地方**必须被抓到 —— R3c 只验「文件在、行号没越界」，
  // 这三条合成样本喂给同一个判定器（同一实现，不另抄一份判据）：
  //   E1 只给坐标、不点名对象 ⇒ 红；E2 点了名但 ±2 行没有它 ⇒ 红；E3 名字与坐标都对 ⇒ 放行。
  const r3eJudge = (comment, targetFile, targetLine) => {
    const syms = [...comment.matchAll(/`([A-Za-z_][A-Za-z0-9_]{2,})`/g)].map((x) => x[1]);
    if (syms.length === 0) return false;
    const win = readFileSync(targetFile, 'utf8').split('\n')
      .slice(Math.max(0, targetLine - 3), targetLine + 1).join('\n');
    return syms.some((s) => new RegExp(`\\b${s}\\b`).test(win));
  };
  if (r3eJudge('见 `tools/check-comment-rot.mjs:1`', realPath, 1) !== false) {
    problems.push('R3e 失效：只给坐标、没点名的引用竟被放行');
  }
  if (r3eJudge('点名 `no_such_symbol_qwerty` 于 `tools/check-comment-rot.mjs:1`', realPath, 1) !== false) {
    problems.push('R3e 失效：±2 行里找不到被点名符号，竟被放行（坐标漂移或符号改名）');
  }
  // R3e 的样本共用**同一份注释文本**：两条唯一不同的是行号对不对。
  // 锚点**现算**（不写死）：这条门禁自己的行号会随每次编辑漂移，写死数字等于
  // 制造一条必然腐烂的注释 —— 正是本门禁要抓的形态。
  const e3File = 'tools/check-comment-rot.mjs';
  const e3Line = readFileSync(realPath, 'utf8').split('\n').findIndex((l) => l.startsWith('const RE_FILE_LINE')) + 1;
  const e3Comment = `\`RE_FILE_LINE\` 的定义见 \`${e3File}:${e3Line}\``;
  const e3Wrong = `\`RE_FILE_LINE\` 的定义见 \`${e3File}:1\``;
  if (r3eJudge(e3Comment, realPath, e3Line) !== true) {
    problems.push('R3e 失效：名字与坐标都对的真样本被误判红（判定器变成永远红）');
  }
  if (r3eJudge(e3Wrong, realPath, 1) !== false) {
    problems.push('R3e 失效：同一条注释、坐标漂到第 1 行，却仍被放行（判定器对漂移不敏感）');
  }

  // R3d：带「级」的量级措辞与登记常量必须放行；裸测量型 KB 必须命中
  if (RE_KB_CLAIM.test('规则 JSON 全文（60KB 级）')) problems.push('R3d 失效：量级措辞「60KB 级」被判红');
  RE_KB_CLAIM.lastIndex = 0;
  if (!RE_KB_CLAIM.test('首屏解析 ~813 KB')) problems.push('R3d 失效：测量型 KB 未被抓到');

  if (problems.length) {
    for (const p of problems) console.error(`✗ ${p}`);
    process.exit(1);
  }
  console.log('✓ 正向对照自检通过（六形态判据均可判红，且真样本不假红；0 对象形态由合成对照证明活性）');
  return true;
})();

// ---------- R3g（P2-B 阶段2，2026-10-25 D 轮）：注释里的「数字声明」必须旁有取数命令 ----------
// 判据的来处：《方法论》U8 与修复方案 P2-B 阶段2 —— 表格与注释里的数字是下一轮审查的
// 派单依据，数字旁边没有取数命令，漂移就无人能发现（v5 轮 X0-3 现算过 14+12 处过期）。
// 阶段1 已把「有现算入口」的四类（R3a/R3b/R3c+R3e/R3d/R3f）做成逐形态判红；本条补的是
// **剩下没有入口的那一大片**：形态 = 注释行里出现「数字 + 量词」，但同一行没有取数标记。
// 为什么是总量棘轮 + 按文件基线，而不是「今天全部改完」：现算命中约 392 处 / 100 个文件，
// 一次大编辑会把注释区改成没人再读的取数命令堆（方案 §4 明确禁止合并成一次大编辑）。
// 所以：基线落 `tools/fixtures/comment-number-baseline.json`（按文件计数），
// **任一文件计数上升或新文件进场即红**，下降则提示同步收紧 —— 只减不增，逐批清零。
const RE_NUM_CLAIM = /\d+\s*(处|条|个|行|字节|KB|MB|ms|%|组|站点|文件|窗|键|项|步)/;
const RE_FETCH_MARK = /现算|取数命令|命令[:：]|node tools\/|node --|cargo |rg |grep |readdir|统计自|由.+生成/;
function numberClaimsWithoutSource(cs) {
  const out = [];
  for (const c of cs) {
    if (RE_NUM_CLAIM.test(c.text) && !RE_FETCH_MARK.test(c.text)) out.push(c.line);
  }
  return out;
}
const R3G_FIXTURE = join(ROOT, 'tools', 'fixtures', 'comment-number-baseline.json');
{
  const live = new Map();
  for (const [rel, cs] of commentsByFile) {
    const hits = numberClaimsWithoutSource(cs);
    if (hits.length) live.set(rel, hits.length);
  }
  const liveTotal = [...live.values()].reduce((s, n) => s + n, 0);
  if (process.argv.includes('--write-r3g')) {
    const body = JSON.stringify({ _说明: 'R3g 过渡基线：注释里「数字声明但无取数命令」的按文件计数，只减不增。生成：node tools/check-comment-rot.mjs --write-r3g', files: Object.fromEntries([...live.entries()].sort()) }, null, 1) + '\n';
    writeFileSync(R3G_FIXTURE, body);
    console.log(`✓ R3g 基线已重算落盘：tools/fixtures/comment-number-baseline.json（${liveTotal} 处 / ${live.size} 个文件）`);
  } else if (!existsSync(R3G_FIXTURE)) {
    fail++;
    console.error('✗ R3g 基线文件缺失（tools/fixtures/comment-number-baseline.json，随仓库跟踪）⇒ 本条**未校验**，跑 --write-r3g 生成');
  } else {
    const base = JSON.parse(readFileSync(R3G_FIXTURE, 'utf8')).files || {};
    const worse = [];
    const shrunk = [];
    for (const [f, n] of live) {
      if (base[f] === undefined) worse.push(`${f} 新增 ${n} 处（不在基线里）`);
      else if (n > base[f]) worse.push(`${f} ${base[f]}→${n}`);
      else if (n < base[f]) shrunk.push(`${f} ${base[f]}→${n}`);
    }
    for (const f of Object.keys(base)) if (!live.has(f)) shrunk.push(`${f} ${base[f]}→0`);
    if (worse.length) {
      fail++;
      console.error(`✗ R3g 注释数字声明上升（只减不增）：${worse.slice(0, 8).join('；')}${worse.length > 8 ? ` …共 ${worse.length} 处` : ''}`);
      console.error('   修法二选一：把数字改成现算措辞（同行写「现算」或给出取数命令），或让这句话根本不带数字。');
    } else {
      check(true, `R3g. 注释「数字声明必带取数命令」按文件棘轮在位（现算 ${liveTotal} 处 / ${live.size} 个文件；基线 ${Object.values(base).reduce((s, n) => s + n, 0)}）`);
    }
    if (shrunk.length) {
      console.log(`ℹ R3g 有 ${shrunk.length} 个文件债务已减（跑 --write-r3g 收紧基线）：${shrunk.slice(0, 5).join('；')}${shrunk.length > 5 ? ' …' : ''}`);
    }
  }
  // 正向对照：同一判定器必须能判红，且「带取数命令」的写法必须放行（否则清零永远做不完）
  {
    const badLines = numberClaimsWithoutSource([{ line: 7, text: '  // 命中 394 处，涉及 100 个文件' }]);
    const goodLines = numberClaimsWithoutSource([{ line: 7, text: '  // 现算命中 394 处（node tools/check-comment-rot.mjs --write-r3g 可重算）' }]);
    const problems = [];
    if (badLines.length !== 1) problems.push('R3g 失效：裸数字声明样本没被判红');
    if (goodLines.length !== 0) problems.push('R3g 失效：带取数命令的样本被误判红（清零永远做不完）');
    if (problems.length) {
      for (const p of problems) console.error(`✗ ${p}`);
      fail++;
    } else {
      check(true, 'R3g 正向对照：裸数字声明判红、带取数命令放行（判定器本身可判红）');
    }
  }
}

// P2-A/A-1 的退出闸门：必须排在**全部**断言（含上面的正向对照与前面的 K08 对账）之后。
if (fail > 0) {
  console.error(`\ncheck-comment-rot: ${fail} 组断言未通过（注释已腐烂，见上）`);
  process.exit(1);
}

console.log(`check-comment-rot: 全部通过（扫 ${commentsByFile.size} 个文件 / ${commentLineTotal} 行注释）`);
