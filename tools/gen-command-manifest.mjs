#!/usr/bin/env node
// gen-command-manifest.mjs —— 命令清单生成器（P4 命令清单化）
//
// 真源：tools/command-manifest.json（唯一手改入口）。
// 生成物（begin/end 锚区之间勿手改；--write 幂等，可重复跑）：
//   src-tauri/src/lib.rs         generate_handler! 条目（zone rust-handler）
//   src/scripts/tauri-api.js     CHANNEL_MAP 键值对（zone channel-map）
//   tools/check-guard-tiers.mjs  MUST_MAIN / MUST_READONLY 条目（zone must-main / must-readonly）
// 门禁侧对拍：tools/check-channel-map.mjs 与 tools/check-guard-tiers.mjs 各有一条 M 组断言，
// 直接调用本文件的 checkZones()（与 --check 同口径）—— 清单与生成物不一致即红。
//
// 清单 schema：{ _doc?, commands: [{ name, module, channel, tier, group }] }
//   name    Rust 命令名（snake_case；generate_handler 与两张 MUST 表的条目）
//   module  commands/ 下模块段（生成 commands::module::name）
//   channel 前端 invoke 通道（CHANNEL_MAP 键）；null = 无 invoke 通道（send / 直连 / 探针类，
//           send 通道仍手维在 tauri-api.js 的 SEND_MAP，不在本清单）
//   tier    'main' | 'readonly' | null；null = 不进两张 MUST 表，档位由 check-guard-tiers
//           的其余登记面管理（窄窗口集 / 豁免 / 其它 guard 形态）
//   group   三处生成区共用的分组标签（承载域分组注释）
// 校验 fail-fast：缺字段 / 字段非法 / 重名 / 重通道一律判红退出 —— 漏填通道或档位过不了
// 生成器；档位与命令体 guard 实况不符则由 check-guard-tiers 的双向棘轮判红。
//
// 用法：node tools/gen-command-manifest.mjs --check   生成物与清单不一致时输出差异、退出码非零
//       node tools/gen-command-manifest.mjs --write   把生成区写回源码文件（幂等）
//       不带参数只打印用法。--write 不管档位实况 —— 那归 check-guard-tiers 管。

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const TOOLS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(TOOLS_DIR, '..');
const MANIFEST_REL = 'tools/command-manifest.json';
const MANIFEST_PATH = join(REPO_ROOT, MANIFEST_REL);

const ZONES = [
  { id: 'rust-handler', file: join(REPO_ROOT, 'src-tauri', 'src', 'lib.rs'), rel: 'src-tauri/src/lib.rs', kind: 'rust' },
  { id: 'channel-map', file: join(REPO_ROOT, 'src', 'scripts', 'tauri-api.js'), rel: 'src/scripts/tauri-api.js', kind: 'js' },
  { id: 'must-main', file: join(REPO_ROOT, 'tools', 'check-guard-tiers.mjs'), rel: 'tools/check-guard-tiers.mjs', kind: 'tier', tier: 'main' },
  { id: 'must-readonly', file: join(REPO_ROOT, 'tools', 'check-guard-tiers.mjs'), rel: 'tools/check-guard-tiers.mjs', kind: 'tier', tier: 'readonly' },
];

/**
 * 清单结构校验：任何结构问题都以可读文案抛出（fail-fast，调用方决定打印或判红）。
 * 顶层和命令级未知字段也算非法 —— 字段拼错名（如 tiers）会静默漏同步，宁红勿漏。
 */
function validateManifestDoc(doc) {
  const bad = (msg) => { throw new Error('清单校验失败：' + msg); };
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) bad('顶层必须是对象');
  for (const k of Object.keys(doc)) {
    if (!['_doc', 'commands'].includes(k)) bad('顶层有未知字段 ' + k);
  }
  if (doc._doc !== undefined && typeof doc._doc !== 'string') bad('_doc 必须是字符串');
  if (!Array.isArray(doc.commands) || doc.commands.length === 0) bad('commands 必须是非空数组');
  const seenName = new Set();
  const seenChannel = new Set();
  const tierOk = new Set(['main', 'readonly', null]);
  const identRe = /^[a-z_][a-z0-9_]*$/;
  const chanRe = /^[A-Za-z0-9_][\w-]*:[\w-]+$/;
  for (const [i, c] of doc.commands.entries()) {
    const at = 'commands[' + i + ']';
    if (!c || typeof c !== 'object' || Array.isArray(c)) bad(at + ' 必须是对象');
    for (const k of Object.keys(c)) {
      if (!['name', 'module', 'channel', 'tier', 'group'].includes(k)) bad(at + ' 有未知字段 ' + k);
    }
    if (typeof c.name !== 'string' || !identRe.test(c.name)) bad(at + '.name 非法（须 snake_case）：' + JSON.stringify(c.name ?? null));
    if (typeof c.module !== 'string' || !identRe.test(c.module)) bad(at + '.module 非法：' + JSON.stringify(c.module ?? null));
    if (!(c.channel === null || (typeof c.channel === 'string' && chanRe.test(c.channel)))) {
      bad(at + '.channel 非法（须「域:名」形态或 null）：' + JSON.stringify(c.channel ?? null));
    }
    if (!tierOk.has(c.tier)) bad(at + '.tier 非法（main|readonly|null）：' + JSON.stringify(c.tier ?? null));
    if (typeof c.group !== 'string' || c.group.trim() === '') bad(at + '.group 必须是非空字符串');
    if (seenName.has(c.name)) bad(at + '.name 重复：' + c.name);
    seenName.add(c.name);
    if (c.channel !== null) {
      if (seenChannel.has(c.channel)) bad(at + '.channel 重复（一条通道只能指向一条命令）：' + c.channel);
      seenChannel.add(c.channel);
    }
  }
  return doc.commands;
}

/** 读入并解析清单真源，随后做结构校验；返回已校验的命令数组。 */
export function loadManifest() {
  let raw;
  try {
    raw = readFileSync(MANIFEST_PATH, 'utf8');
  } catch (e) {
    throw new Error('读不到清单 ' + MANIFEST_REL + '（' + e.message + '）—— 命令面真源缺席，按失败处理');
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (e) {
    throw new Error(MANIFEST_REL + ' 不是合法 JSON：' + e.message);
  }
  return validateManifestDoc(doc);
}

/** 生成一个 zone 的内容行（不含锚注释行；rust 按 manifest 序、tier 表按名字典序） */
function zoneLines(zone, commands) {
  const lines = [];
  if (zone.kind === 'rust') {
    let prevGroup = null;
    for (const c of commands) {
      if (c.group !== prevGroup) {
        lines.push('        // ---- ' + c.group + ' ----');
        prevGroup = c.group;
      }
      lines.push('        commands::' + c.module + '::' + c.name + ',');
    }
  } else if (zone.kind === 'js') {
    let prevGroup = null;
    for (const c of commands) {
      if (c.channel === null) continue;
      if (c.group !== prevGroup) {
        lines.push('    // ' + c.group);
        prevGroup = c.group;
      }
      lines.push('    \'' + c.channel + '\': \'' + c.name + '\',');
    }
  } else {
    const names = commands.filter((c) => c.tier === zone.tier).map((c) => c.name).sort();
    for (const n of names) lines.push('  \'' + n + '\',');
  }
  return lines;
}

/** 生成一个 zone 的完整锚区内容（含尾随换行；空内容时为空串）。 */
function zoneContent(zone, commands, eol) {
  const lines = zoneLines(zone, commands);
  return lines.length ? lines.join(eol) + eol : '';
}

/** 比较 zone 实况与内存生成内容；一致返回 null，不一致返回可读差异串。 */
function zoneProblem(zone, actual, commands, eol) {
  const expected = zoneContent(zone, commands, eol);
  return actual === expected ? null : diffSummary(zone, actual, expected, eol);
}

/** 定位 zone 内容区间：begin 行末之后到 end 行行首（end 行自身原样保留，rust 的 end 锚骑在「])」行上） */
function zoneSpan(text, zoneId) {
  const beginMark = '// command-manifest:begin ' + zoneId;
  const endMark = '// command-manifest:end ' + zoneId;
  const bi = text.indexOf(beginMark);
  if (bi < 0) throw new Error('找不到 begin 锚「' + beginMark + '」—— 生成区未初始化或被删');
  const bl = text.indexOf('\n', bi);
  if (bl < 0) throw new Error('begin 锚之后没有换行');
  const contentStart = bl + 1;
  const ei = text.indexOf(endMark, contentStart);
  if (ei < 0) throw new Error('找不到 end 锚「' + endMark + '」—— 生成区不完整');
  const contentEnd = text.lastIndexOf('\n', ei) + 1;
  if (contentEnd < contentStart) throw new Error('end 锚出现在 begin 锚之前');
  return { contentStart, contentEnd };
}

const eolOf = (text) => (text.includes('\r\n') ? '\r\n' : '\n');

/** 行级差异摘要（zone 行数有限，LCS 足够）；返回的问题串首行为标题，其后为 +/- 样例 */
function diffSummary(zone, actual, expected, eol) {
  const stripTrailingEmpty = (s) => (s === '' ? [] : s.split(eol).filter((l, i, arr) => !(l === '' && i === arr.length - 1)));
  const a = stripTrailingEmpty(actual);
  const b = stripTrailingEmpty(expected);
  const n = a.length;
  const m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const added = m - dp[0][0];
  const removed = n - dp[0][0];
  const head = zone.rel + ' zone ' + zone.id + ' 与清单不一致（生成物多 ' + added + ' 行 / 少 ' + removed + ' 行）';
  const out = [];
  let i = 0;
  let j = 0;
  while ((i < n || j < m) && out.length < 6) {
    if (i < n && j < m && a[i] === b[j]) { i++; j++; continue; }
    if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) { out.push('  + ' + b[j]); j++; continue; }
    out.push('  - ' + a[i]);
    i++;
  }
  if (i < n || j < m) out.push('  …（余略）');
  return head + (out.length ? '\n' + out.join('\n') : '');
}

/**
 * 「清单 ⇄ 生成物」对拍（门禁与 --check 共用）：
 * 逐 zone 重新生成内容并与盘上锚区逐字比对，再跑只读合成反例；清单非法、
 * 锚区缺失或反例漏判都计为问题（fail-closed）。
 */
export function checkZones() {
  const problems = [];
  let commands;
  try {
    commands = loadManifest();
  } catch (e) {
    return { ok: false, problems: [e.message] };
  }
  const fileCache = new Map();
  const zoneActual = new Map();
  for (const zone of ZONES) {
    let text;
    try {
      if (!fileCache.has(zone.file)) fileCache.set(zone.file, readFileSync(zone.file, 'utf8'));
      text = fileCache.get(zone.file);
    } catch (e) {
      problems.push(zone.rel + ' 读不到（' + e.message + '）');
      continue;
    }
    let span;
    try {
      span = zoneSpan(text, zone.id);
    } catch (e) {
      problems.push(zone.rel + '：' + e.message);
      continue;
    }
    const eol = eolOf(text);
    const actual = text.slice(span.contentStart, span.contentEnd);
    zoneActual.set(zone.id, { actual, eol });
    const problem = zoneProblem(zone, actual, commands, eol);
    if (problem) problems.push(problem);
  }
  problems.push(...syntheticProblems(commands, zoneActual));
  return { ok: problems.length === 0, problems };
}

/**
 * 内存合成反例：确认对照逻辑会因删条目、坏 tier、重复通道和未知字段判红。
 * 只用当前清单和已读 zone 内容构造，不落盘、不新建 fixture。
 */
function syntheticProblems(commands, zoneActual) {
  const problems = [];
  const requireProblem = (problem, label) => {
    if (!problem) problems.push('合成对照未判红：' + label);
  };
  const requireInvalid = (doc, label) => {
    try {
      validateManifestDoc(doc);
      problems.push('合成对照未判红：' + label);
    } catch {
      // 预期失败；反例只关心能判红。
    }
  };
  const zone = ZONES[0];
  const zoneSnapshot = zoneActual.get(zone.id);
  if (!zoneSnapshot) problems.push('合成对照缺 zone 实况：' + zone.id);
  else requireProblem(zoneProblem(zone, zoneSnapshot.actual, commands.slice(1), zoneSnapshot.eol), '删生成区条目');

  const base = commands[0];
  requireProblem(
    zoneProblem(
      zone,
      zoneSnapshot?.actual ?? '',
      [...commands, { ...base, name: base.name + '_synthetic', channel: null, tier: 'invalid-tier' }],
      zoneSnapshot?.eol ?? '\n',
    ),
    '生成区 tier 改坏',
  );

  const channelBase = commands.find((c) => c.channel !== null);
  const duplicate = channelBase
    ? { ...channelBase, name: channelBase.name + '_synthetic' }
    : { ...base, name: base.name + '_synthetic', channel: 'synthetic:probe' };
  requireInvalid({ _doc: '合成对照', commands: [...commands, duplicate] }, '重复通道');
  requireInvalid({ _doc: '合成对照', commands: [{ ...base, syntheticUnknown: true }] }, '命令级未知字段');
  requireInvalid({ _doc: '合成对照', commands, syntheticUnknown: true }, '顶层未知字段');
  return problems;
}

/** --write：把生成区写回源码文件（幂等）；返回发生改写的 zone 描述 */
export function writeZones() {
  const commands = loadManifest();
  const changed = [];
  for (const zone of ZONES) {
    const text = readFileSync(zone.file, 'utf8');
    const span = zoneSpan(text, zone.id);
    const eol = eolOf(text);
    const actual = text.slice(span.contentStart, span.contentEnd);
    const expected = zoneContent(zone, commands, eol);
    if (actual === expected) continue;
    const next = text.slice(0, span.contentStart) + expected + text.slice(span.contentEnd);
    writeFileSync(zone.file, next, 'utf8');
    changed.push(zone.rel + ' zone ' + zone.id);
  }
  return changed;
}

function main() {
  const argv = process.argv.slice(2);
  const wantWrite = argv.includes('--write');
  const wantCheck = argv.includes('--check');
  if (wantWrite === wantCheck) {
    console.log('用法：node tools/gen-command-manifest.mjs --check | --write');
    console.log('  --check  生成物与清单不一致时输出差异、退出码非零（门禁同口径）');
    console.log('  --write  把三处生成区写回源码文件（幂等，可重复跑）');
    process.exit(2);
  }
  if (wantWrite) {
    let changed;
    try {
      changed = writeZones();
    } catch (e) {
      console.error('✗ ' + e.message);
      process.exit(1);
    }
    if (changed.length) console.log('✓ 已重写生成区：\n  ' + changed.join('\n  '));
    else console.log('✓ 生成物已与清单一致，无需改写（幂等）');
    process.exit(0);
  }
  const res = checkZones();
  if (res.ok) {
    console.log('✓ 命令清单 ⇄ 生成物一致（' + ZONES.length + ' 处生成区）');
    process.exit(0);
  }
  console.error('✗ 命令清单 ⇄ 生成物不一致：');
  for (const p of res.problems) console.error(p);
  process.exit(1);
}

const self = (process.argv[1] || '').replace(/\\/g, '/');
if (self.endsWith('gen-command-manifest.mjs')) main();
