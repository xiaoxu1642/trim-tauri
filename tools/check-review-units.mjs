#!/usr/bin/env node
// check-review-units.mjs —— 审查单元台账机检（多 agent 派单的分工表自身会不会烂）
//
// 抓什么（全部来自 v4 战役的实测账单，不是设想）：
//   U1 认领根存在且非空 —— 目录改名/删掉后，派单卡片会指向不存在的范围（v4 真事故：
//      主 agent 一度点名一个不存在的命令文件，靠双证才纠正）。
//   U2 单元规模 ≤ CAP —— 「子 agent 单元切太大」是本轮用户裁定的头号编排问题；上限 8000 行
//      必须有机检，否则下一轮加文件又悄悄超回去。生成物剔除；单文件超限只允许标 segmented 的单元放行。
//   U3 认领冲突 —— 同一文件被两个单元点名 = 两份分报告都会写它、主 agent 去重成本回来了；
//      显式点名的文件已被前序单元的目录认领吃掉 = 死条目（表在骗人）。
//   U4 覆盖率 —— 认领根里的每个文件必须有人认领。**新增目录/新增文件静默退出审查台账**
//      是 check-guard-tiers 那条「搬进子目录自动退出档位台账」的同族假绿。
//   U5 地板 —— 单元数/横切项数/反模式单元数塌下去就是表烂了，不是仓库变小了（断言对象 0 的绿不算通过）。
//   U6 分报告 coverage 对账 —— 只在主 agent 给出台账（--coverage）时判；断言「说读了」≥「表里认领的」。
//   U7 文档点名路径与单元 ID —— 只在 --doc 指向文档时判。文档在仓库外的本机资料区，
//      **刻意没有默认路径**（AGENTS §2：跟踪文件不得关联未跟踪路径），缺参数就显式 SKIP 并声明未校验。
//
// 用法：node tools/check-review-units.mjs [--coverage <json>] [--doc <path>] [--self-test]
'use strict';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { walkFiles } from './lib/fs-walk.mjs';
import { CAP_LINES, FLOOR, AUDIT_ROOTS, UNITS, CROSS_UNITS, ANTI_UNITS } from './review-units.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const norm = (p) => p.replace(/\\/g, '/');

const IGNORE_DIR = (n) => n === 'target' || n === 'node_modules' || n === 'vendor' || n === '.git';
const argOf = (flag) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : null;
};
const SELF_TEST = process.argv.includes('--self-test');

let fail = 0;
let skipped = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};
const skip = (label, detail = '') => {
  console.log(`– SKIP ${label}${detail ? ' — ' + detail : ''}`);
  skipped++;
};
const info = (line) => console.log(line);

/** UTF-8 非空行 —— 本仓规模的唯一口径（PS 5.1 按 cp936 解码会吞换行，v4 撞过，禁用）。 */
function nonEmptyLines(absPath) {
  let text;
  try {
    text = readFileSync(absPath, 'utf8');
  } catch {
    return 0;
  }
  let n = 0;
  for (const line of text.split(/\r?\n/)) if (line.trim() !== '') n++;
  return n;
}

// ── 纯判定器（不碰盘，好让 POSITIVE_CONTROLS 喂合成样本）──────────────────────

/** U1：认领根空了 = 目录改名或被删。 */
export function detectEmptyRoots(rootCounts) {
  return Object.entries(rootCounts).filter(([, n]) => n === 0).map(([label]) => label);
}

/** U3：显式点名（含 generated 剔除清单）与实际归属对拍。 */
export function detectOverlap(units, ownerOf) {
  const seen = new Map();
  const dup = [];
  const drifted = [];
  for (const u of units) {
    for (const kind of ['files', 'generated']) {
      for (const f of u[kind] ?? []) {
        const who = ownerOf.get(f);
        if (!who) { drifted.push(`${u.id} 的${kind === 'files' ? '点名' : '生成物剔除'} ${f} 无人认领（认领根没覆盖它）`); continue; }
        if (seen.has(f)) dup.push(`${f}：${seen.get(f)} 与 ${u.id} 都点名`);
        else seen.set(f, u.id);
        if (who !== u.id) {
          drifted.push(`${f}：写在 ${u.id} 名下，实际归属 ${who}（${kind === 'generated' ? '剔除清单漂走 = 白剔一行' : '点名成了装饰'}）`);
        }
      }
    }
  }
  return { dup, drifted };
}

/** U4：未认领文件（新目录/新文件静默退出审查台账就是这里红）。 */
export function detectUnclaimed(allFiles, ownerOf) {
  return allFiles.filter((f) => !ownerOf.has(f));
}

/** U2：单元规模超上限。segmented 单元只在其认领文件 >1 时仍判红。 */
export function detectOverCap(units, sizeOf, cap) {
  const out = [];
  for (const u of units) {
    const claimed = u.claimed ?? [];
    const counted = claimed.filter((f) => !(u.generated ?? []).includes(f));
    const lines = counted.reduce((a, f) => a + (sizeOf.get(f) ?? 0), 0);
    if (u.segmented) {
      if (counted.length > 1) out.push(`${u.id} 标了 segmented 却认领 ${counted.length} 个文件（分段审只对单文件成立）`);
      continue;
    }
    if (lines > cap) out.push(`${u.id} ${lines} 行 > 上限 ${cap}（要重切：优先按页面/执行链，其次按目录）`);
  }
  return out;
}

/** U5：台账塌缩地板。 */
export function detectFloor({ units, cross, anti }) {
  const out = [];
  if (units.length < FLOOR.longitudinal) out.push(`纵向单元 ${units.length} < 地板 ${FLOOR.longitudinal}`);
  if (cross.length < FLOOR.cross) out.push(`横切项 ${cross.length} < 地板 ${FLOOR.cross}`);
  if (anti.length < FLOOR.antiPattern) out.push(`反模式单元 ${anti.length} < 地板 ${FLOOR.antiPattern}`);
  const ids = new Set(units.map((u) => u.id));
  for (const u of units) {
    if (!u.name || !u.contract || !u.boundary) out.push(`${u.id} 缺 name/contract/boundary 之一（卡片没判据可抄）`);
    if (u.owner !== 'main' && u.owner !== 'sub') out.push(`${u.id} 归属必须是 main/sub`);
    if (!u.gates || u.gates.length === 0) out.push(`${u.id} 没登记必跑门禁`);
  }
  for (const c of [...cross, ...anti]) if (!c.how || !c.name) out.push(`${c.id} 缺 name/how`);
  return { out, dupIds: units.map((u) => u.id).filter((id, i, a) => a.indexOf(id) !== i), ids };
}

/** U7：从文档正文抽仓库内路径与单元 ID（只认反引号里的仓库相对形状）。 */
export function extractRepoPaths(text) {
  const out = new Set();
  // 历史叙述行整行豁免：陈述「曾经有过/已删」不是承诺现在存在（与注释腐烂门禁同一口径）
  const HIST = /(已删|已退役|此前|曾经|历史|旧|原)/;
  for (const line of text.split(/\r?\n/)) {
    if (HIST.test(line)) continue;
    // 必须以反引号收尾：`tools/check-*.mjs` 这类通配若不收口会被截成 `tools/check` 而误报
    const re = /`((?:src-tauri|native-scanner|tools|src)\/[A-Za-z0-9_.\-/]*[A-Za-z0-9_.])`/g;
    let m;
    while ((m = re.exec(line))) {
      // 通配/前缀形状（`tools/check-*.mjs` 会截成 `tools/check-`）不是坐标，跳过
      if (/[-/]$/.test(m[1]) || /\*|\{\}/.test(m[1])) continue;
      out.add(m[1]);
    }
  }
  return [...out];
}
export function extractUnitIds(text) {
  const out = new Set();
  // 形状放宽到「任何像单元 ID 的记号」：只认现存 ID 的话，R9 / F4d 这类笔误根本不会被抽出来，
  // 也就永远不判红 —— 那正是本门禁要防的「恒绿断言」。
  // 但 N/D/A 只收**精确 ID**：文档里 `N6`（耦合账编号）、`D4/D5/D6`（发现分级）、`A7/A9`（附录组）
  // 与本仓的单元 ID 形状撞车，放宽就会把别套编号体系误判成单元。
  const re = /\b(R\d[abc]?|F\d[abc]?|T1[abc]?|N1|D1|X0-\d+|A[1-6])\b/g;
  let m;
  while ((m = re.exec(text))) out.add(m[1]);
  return [...out];
}
/** 裸前缀算族名（`R6` 指 R6a/R6b、`F4` 指 F4a/F4b/F4c），不算未知 ID。 */
export function isKnownUnitId(id, unitIds) {
  if (unitIds.has(id)) return true;
  if (/^(X0-\d+|A[1-6])$/.test(id)) return true;
  return [...unitIds].some((u) => u.startsWith(id));
}

// ── 正向对照自检（§4.1：能判红 + 真样本不假红，两向都要）──────────────────────
const POSITIVE_CONTROLS = [
  {
    label: 'U1 认领根归零必判红',
    run: () => detectEmptyRoots({ 'tools/*.mjs': 0, 'src/scripts': 7 }) ,
    expect: (v) => v.length === 1 && v[0] === 'tools/*.mjs',
  },
  {
    label: 'U2 超上限必判红 / 干净样本不假红',
    run: () => {
      const sizeOf = new Map([['a.js', 5000], ['b.js', 4000]]);
      const over = detectOverCap([{ id: 'X', claimed: ['a.js', 'b.js'] }], sizeOf, 8000);
      const clean = detectOverCap([{ id: 'Y', claimed: ['a.js'] }], sizeOf, 8000);
      const seg = detectOverCap([{ id: 'Z', segmented: true, claimed: ['a.js'] }], sizeOf, 8000);
      const segAbuse = detectOverCap([{ id: 'W', segmented: true, claimed: ['a.js', 'b.js'] }], sizeOf, 8000);
      return over.length === 1 && clean.length === 0 && seg.length === 0 && segAbuse.length === 1;
    },
    expect: (v) => v === true,
  },
  {
    label: 'U3 点名与归属漂移必判红 / 一致样本不假红',
    run: () => {
      const bad = detectOverlap([{ id: 'P', files: ['x.rs'] }, { id: 'Q', files: ['x.rs'] }], new Map([['x.rs', 'P']]));
      const drift = detectOverlap([{ id: 'P', generated: ['g.json'] }], new Map([['g.json', 'Q']]));
      const none = detectOverlap([{ id: 'P', files: ['x.rs'] }], new Map([['x.rs', 'P']]));
      return bad.dup.length === 1 && drift.drifted.length === 1 && none.dup.length === 0 && none.drifted.length === 0;
    },
    expect: (v) => v === true,
  },
  {
    label: 'U4 未认领文件必点名 / 已认领不假红',
    run: () => {
      const owner = new Map([['a.rs', 'R1']]);
      return detectUnclaimed(['a.rs', 'new-dir/b.rs'], owner).length === 1
        && detectUnclaimed(['a.rs'], owner).length === 0;
    },
    expect: (v) => v === true,
  },
  {
    label: 'U5 台账塌缩必判红（单元清空 / 每条都缺 boundary）',
    run: () => {
      const collapsed = detectFloor({ units: [], cross: [], anti: [] });
      const noBoundary = detectFloor({
        units: Array.from({ length: FLOOR.longitudinal }, (_, i) => ({
          id: `U${i}`, owner: 'sub', name: 'n', contract: 'c', gates: ['g'],
        })),
        cross: CROSS_UNITS, anti: ANTI_UNITS,
      });
      const real = detectFloor({
        units: UNITS.map((u) => ({ ...u })), cross: CROSS_UNITS, anti: ANTI_UNITS,
      });
      return collapsed.out.length >= 3 && noBoundary.out.length === FLOOR.longitudinal
        && real.out.length === 0 && real.dupIds.length === 0;
    },
    expect: (v) => v === true,
  },
  {
    label: 'U7 路径与 ID 抽取：腐烂样本必命中 / 通配与历史叙述不误报',
    run: () => {
      const paths = extractRepoPaths(
        '见 `tools/ghost.mjs` 与 `src-tauri/src/engine/guard.rs`\n' +
        '（原 `tools/dual-run-batchA.mjs` 已删）\n' +
        '磁盘 `tools/check-*.mjs` 排期实现');
      const ids = extractUnitIds('单元 R2a / F4c / X0-7 / A5 / R9');
      const known = new Set(UNITS.map((u) => u.id));
      return paths.length === 2 && paths.includes('tools/ghost.mjs')
        && !paths.some((p) => p.includes('dual-run') || p.includes('*'))
        && isKnownUnitId('R2a', known) && isKnownUnitId('R6', known) === true
        && isKnownUnitId('F4', known) === true && !isKnownUnitId('R9', known)
        && ids.filter((i) => !isKnownUnitId(i, known)).join() === 'R9';
    },
    expect: (v) => v === true,
  },
];

if (SELF_TEST) {
  console.log('=== check-review-units 正向对照自检 ===');
  for (const c of POSITIVE_CONTROLS) {
    let ok = false;
    try {
      ok = c.expect(c.run());
    } catch (e) {
      ok = false;
      info(`  （异常：${e.message}）`);
    }
    check(ok, c.label);
  }
  if (fail) process.exit(1);
  process.exit(0);
}

// ── 真跑 ──────────────────────────────────────────────────────────────
console.log('=== 审查单元台账机检（认领根 / 规模 / 互斥 / 覆盖 / 地板）===\n');

const rootCounts = {};
const allFiles = new Set();
const rootLabels = [];
for (const r of AUDIT_ROOTS) {
  if (r.file) {
    const label = r.file;
    rootLabels.push(label);
    const n = existsSync(join(ROOT, r.file)) ? 1 : 0;
    rootCounts[label] = n;
    if (n) allFiles.add(r.file);
    continue;
  }
  const abs = join(ROOT, r.dir);
  const label = `${r.dir}${r.ext ? ' *' + r.ext.join(',') : ''}${r.depth ? ' (直属)' : ''}`;
  rootLabels.push(label);
  if (!existsSync(abs) || !statSync(abs).isDirectory()) { rootCounts[label] = 0; continue; }
  let files;
  if (r.depth === 1) {
    files = readdirSync(abs, { withFileTypes: true })
      .filter((e) => e.isFile() && (!r.ext || r.ext.some((x) => e.name.endsWith(x))))
      .map((e) => norm(join(relative(ROOT, abs), e.name)));
  } else {
    files = walkFiles(abs, (n) => !r.ext || r.ext.some((x) => n.endsWith(x)), { ignoreDir: IGNORE_DIR })
      .map((p) => norm(relative(ROOT, p)));
  }
  rootCounts[label] = files.length;
  for (const f of files) allFiles.add(f);
}

const emptyRoots = detectEmptyRoots(rootCounts);
check(emptyRoots.length === 0, `U1 认领根全部非空（${rootLabels.length} 个根 / ${allFiles.size} 个文件）`,
  emptyRoots.join('、'));

// 先到先得的认领
const ownerOf = new Map();
const unitsWithClaims = UNITS.map((u) => {
  const claimed = [];
  for (const f of [...(u.files ?? [])]) {
    if (!allFiles.has(f)) continue; // 缺件由下面的 U1/U4 与「点名不存在」判红
    if (!ownerOf.has(f)) { ownerOf.set(f, u.id); claimed.push(f); }
  }
  const dirClaimed = [];
  for (const d of u.dirs ?? []) {
    const abs = join(ROOT, d.dir);
    if (!existsSync(abs)) continue;
    let files;
    if (d.depth === 1) {
      files = readdirSync(abs, { withFileTypes: true })
        .filter((e) => e.isFile() && (!d.ext || d.ext.some((x) => e.name.endsWith(x))))
        .map((e) => norm(join(relative(ROOT, d.dir), e.name)));
    } else {
      files = walkFiles(abs, (n) => !d.ext || d.ext.some((x) => n.endsWith(x)), { ignoreDir: IGNORE_DIR })
        .map((p) => norm(relative(ROOT, p)));
    }
    for (const f of files) {
      if (d.onlyPrefix && !f.split('/').pop().startsWith(d.onlyPrefix)) continue;
      if (d.notPrefix && f.split('/').pop().startsWith(d.notPrefix)) continue;
      if (ownerOf.has(f)) continue;
      ownerOf.set(f, u.id);
      claimed.push(f);
      dirClaimed.push(f);
    }
  }
  return { ...u, claimed, dirClaims: [dirClaimed] };
});

const sizeOf = new Map([...allFiles].map((f) => [f, nonEmptyLines(join(ROOT, f))]));

const missingNamed = [];
for (const u of unitsWithClaims) {
  for (const f of [...(u.files ?? []), ...(u.generated ?? [])]) {
    if (!allFiles.has(f)) missingNamed.push(`${u.id} → ${f}`);
  }
}
check(missingNamed.length === 0, 'U1b 表内点名的文件全部真实存在且落在认领根内',
  missingNamed.slice(0, 8).join('、'));

const { dup, drifted } = detectOverlap(unitsWithClaims, ownerOf);
check(dup.length === 0 && drifted.length === 0, 'U3 认领无冲突（重复点名 0 / 点名⇄归属漂移 0）',
  [...dup, ...drifted].slice(0, 6).join('、'));

const unclaimed = detectUnclaimed([...allFiles].sort(), ownerOf);
check(unclaimed.length === 0, `U4 覆盖率 100%（${allFiles.size} 个文件全部有归属）`,
  unclaimed.slice(0, 20).join('、') + (unclaimed.length > 20 ? ` …共 ${unclaimed.length} 个` : ''));

const overCap = detectOverCap(unitsWithClaims, sizeOf, CAP_LINES);
check(overCap.length === 0, `U2 每单元精读行数 ≤ ${CAP_LINES}（生成物不计，口径=UTF-8 非空行）`,
  overCap.join(' | '));

const floor = detectFloor({ units: UNITS, cross: CROSS_UNITS, anti: ANTI_UNITS });
check(floor.out.length === 0 && floor.dupIds.length === 0,
  `U5 地板与完整性（纵向 ${UNITS.length} ≥${FLOOR.longitudinal} · 横切 ${CROSS_UNITS.length} · 反模式 ${ANTI_UNITS.length} · 主审面 4）`,
  [...floor.out, ...floor.dupIds.map((i) => `单元 ID 重复：${i}`)].slice(0, 8).join('、'));

// 逐单元台账（派单时直接抄这张表，不手抄数字）
info('\n单元台账（现算，精读行数不含生成物）：');
for (const u of unitsWithClaims) {
  const counted = u.claimed.filter((f) => !(u.generated ?? []).includes(f));
  const lines = counted.reduce((a, f) => a + sizeOf.get(f), 0);
  const byDir = u.dirClaims[0].length;
  info(`  ${u.id.padEnd(4)} [${u.owner === 'main' ? '主审' : '派单'}] ${(u.name ?? '').padEnd(34, ' ')} ` +
    `文件 ${String(u.claimed.length).padStart(3)} · 精读 ${String(lines).padStart(5)} 行 · 其中靠目录兜底 ${byDir}`);
}
const anti = ANTI_UNITS.map((a) => a.id).join('/');
info(`\n横向反模式单元（全仓扫、只报命中不给修法）：${anti}`);
info(`主 agent 四面：R6 红线真源 · X0 横切 ${CROSS_UNITS.length} 项 · 修法判据复核 · 变更自审 X-REG`);

// U6 / U7：外部输入，缺件一律显式 SKIP
const covPath = argOf('--coverage');
if (!covPath) {
  skip('U6 分报告 coverage 对账', '未给 --coverage 台账（主 agent 派单后落一份 JSON 才校验），本节未校验');
} else if (!existsSync(covPath)) {
  skip('U6 分报告 coverage 对账', `--coverage 指向的文件不存在：${covPath}，本节未校验`);
} else {
  const ledger = JSON.parse(readFileSync(covPath, 'utf8'));
  const unknown = Object.keys(ledger).filter((k) => !floor.ids.has(k));
  const gaps = [];
  for (const [id, rec] of Object.entries(ledger)) {
    if (!floor.ids.has(id)) continue;
    const unit = unitsWithClaims.find((u) => u.id === id);
    const covered = new Set(rec.covered ?? []);
    const missed = unit.claimed.filter((f) => !covered.has(f));
    if (missed.length) gaps.push(`${id} 漏 ${missed.length}：${missed.slice(0, 3).join(',')}`);
  }
  check(unknown.length === 0 && gaps.length === 0,
    `U6 coverage 台账对拍（${Object.keys(ledger).length} 份）`,
    [...unknown.map((u) => `台账里出现未知单元 ${u}`), ...gaps].join(' | '));
}

const docPath = argOf('--doc');
if (!docPath) {
  skip('U7 文档点名路径与单元 ID', '未给 --doc（文档在仓库外的本机资料区，脚本刻意无默认路径），本节未校验');
} else if (!existsSync(docPath)) {
  skip('U7 文档点名路径与单元 ID', `--doc 指向的文件不存在：${docPath}，本节未校验`);
} else {
  const text = readFileSync(docPath, 'utf8');
  const paths = extractRepoPaths(text);
  const broken = paths.filter((p) => !existsSync(join(ROOT, p)) && !existsSync(join(ROOT, `${p}/`)));
  const ids = extractUnitIds(text);
  const unknownIds = ids.filter((i) => !isKnownUnitId(i, floor.ids));
  check(broken.length === 0 && unknownIds.length === 0,
    `U7 文档对拍（点名路径 ${paths.length} 条、单元 ID ${ids.length} 个）`,
    [...broken.map((b) => `路径不存在 ${b}`), ...unknownIds.map((u) => `未知单元 ${u}`)].join(' | '));
}

console.log(`\ncheck-review-units: ${fail === 0 ? '全部通过' : `${fail} 项失败`}${skipped ? `（SKIP ${skipped} 节，未校验）` : ''}`);
// 打印红不等于判红：判据必须落在退出码上（AGENTS §4.1）
if (fail > 0) process.exit(1);
