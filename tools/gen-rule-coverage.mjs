#!/usr/bin/env node
// gen-rule-coverage.mjs —— 规则库覆盖面矩阵与基线棘轮（V2 P1-A4，2026-09-30）
//
// 为什么要有这个：CRS/semgrep 那两份参照里，Trim 唯一完全缺的一层是**覆盖面承诺**——
// semgrep 用 `stats/metacategory_to_support_tier.yml` + `high_signal_coverage.md` 做到
// 「先给可核对的定义，再出表，再分 tier1/2/3」。Trim 今天只有"76 + 6 条"这一个数字，
// 回答不了"哪一类残留我们根本不打算覆盖"。
//
// 三条口径先钉死（定义不写清楚，表就是自嗨）：
//   1. **有效条目** = 条目至少有一个当前引擎真会读的路径来源。活来源键与专用分流登记
//      全部取自 `tools/rule-schema.json` 的 crossTrack（与装载侧 A13 同一份定义），
//      不在这里另写一套——否则"矩阵说有覆盖、引擎其实不消费"这种分叉迟早出现。
//   2. **域内密度**按 `domain` × `nature` 出，不按"分组标题"出（标题是文案）。
//   3. **基线只增不减**：`tools/fixtures/rule-coverage-baseline.json` 记下
//      「有效条目 id 集合」。条目变少 = 覆盖缩水，必须显式 `--bump-baseline` 并在
//      审核记录里写原因，否则判红。参照的是 semgrep 的做法：存量可以慢慢加，
//      但倒退必须有人签字。
//
// 用法：
//   node tools/gen-rule-coverage.mjs              打印矩阵并与基线比对（缩水即红）
//   node tools/gen-rule-coverage.mjs --write      刷新基线（覆盖扩大或有意收缩时用）
//   node tools/gen-rule-coverage.mjs --md out.md  另外落一份 Markdown 表
'use strict';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\//, '')).replace(/\\/g, '/'), '..');
const CLEANUP = path.join(ROOT, 'src-tauri', 'data', 'cleanup-rules.json');
const RESIDUE = path.join(ROOT, 'src-tauri', 'data', 'uninstall-residue-rules.json');
const SCHEMA = path.join(ROOT, 'tools', 'rule-schema.json');
const BASELINE = path.join(ROOT, 'tools', 'fixtures', 'rule-coverage-baseline.json');

const argv = process.argv.slice(2);
const WRITE = argv.includes('--write');
const mdIdx = argv.indexOf('--md');

const schema = JSON.parse(fs.readFileSync(SCHEMA, 'utf8'));
const liveKeys = schema.crossTrack.liveSourceKeys;
const handlers = schema.crossTrack.specialHandlers;

const isLive = (it) => {
  for (const k of liveKeys) {
    const v = it[k];
    if (v === undefined || v === null) continue;
    if (Array.isArray(v) ? v.length > 0 : true) return true;
  }
  const h = handlers.find((x) => it[x.key] !== undefined);
  return Boolean(h && (h.values || []).includes(it[h.key]));
};

const itemsOf = (rules) =>
  (rules.groups || []).flatMap((g) => [...(g.items || []), ...(g.subGroups || []).flatMap((s) => s.items || [])]);

const bump = (m, k) => m.set(k, (m.get(k) ?? 0) + 1);
const sortedCount = (m) => [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));

const cleanup = JSON.parse(fs.readFileSync(CLEANUP, 'utf8'));
const residue = JSON.parse(fs.readFileSync(RESIDUE, 'utf8'));
const cItems = itemsOf(cleanup);
const live = cItems.filter(isLive);
const inert = cItems.filter((it) => !isLive(it));

const byDomain = new Map();
const byNature = new Map();
const byRisk = new Map();
const bySourceClass = new Map();
for (const it of live) {
  bump(byDomain, it.domain ?? '(缺)');
  bump(byNature, `${it.domain}/${it.nature}`);
  bump(byRisk, `${it.domain}·${it.risk}`);
  bump(bySourceClass, it.prov?.sourceClass ?? '(缺)');
}

// 残留库按"能对上什么"算：三条件组决定它匹配的是名字、发行商还是卸载键
const rRules = Array.isArray(residue.rules) ? residue.rules : [];
const rGroups = new Map();
for (const r of rRules) {
  const g = ['displayName', 'publisher', 'uninstallKey'].filter((k) => (r[k] || []).length > 0);
  bump(rGroups, g.join('+') || '(无条件组)');
}

const coveredIds = [...live.map((it) => `cleanup:${it.id}`), ...rRules.map((r) => `residue:${r.id}`)].sort();

let baseline = null;
if (fs.existsSync(BASELINE)) {
  try {
    baseline = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
  } catch (e) {
    console.error(`✗ 基线不可读：${e.message}`);
    process.exit(1);
  }
}

const lines = [];
const say = (s = '') => lines.push(s);
say('# 规则库覆盖面矩阵（gen-rule-coverage.mjs 产出，勿手改）');
say('');
say(`- 清理库：${cItems.length} 条，其中**有效** ${live.length} 条；无活路径来源 ${inert.length} 条${inert.length ? `（${inert.map((i) => i.id).join('、')}）` : ''}`);
say(`- 残留库：${rRules.length} 条规则（按条件组匹配，全部计入覆盖）`);
say(`- 「有效」的定义：条目至少有一个当前引擎真会读的路径来源（${liveKeys.join('/')}），或带已登记的专用分流标记（${handlers.map((h) => `${h.key}=${h.values.join('|')}`).join('，')}）。定义与装载侧 A13 同源，取自 tools/rule-schema.json。`);
say('');
say('## 清理域 × 覆盖密度');
say('');
say('| domain | 有效条目 |');
say('|---|---|');
for (const [k, v] of sortedCount(byDomain)) say(`| ${k} | ${v} |`);
say('');
say('## domain/nature 细分');
say('');
say('| domain/nature | 条目 |');
say('|---|---|');
for (const [k, v] of sortedCount(byNature)) say(`| ${k} | ${v} |`);
say('');
say('## 风险档分布（domain·risk）');
say('');
say('| domain·risk | 条目 |');
say('|---|---|');
for (const [k, v] of sortedCount(byRisk)) say(`| ${k} | ${v} |`);
say('');
say('## 溯源级别（prov.sourceClass）');
say('');
say('| sourceClass | 条目 |');
say('|---|---|');
for (const [k, v] of sortedCount(bySourceClass)) say(`| ${k} | ${v} |`);
say('');
say('## 残留库条件组形态');
say('');
say('| 条件组 | 规则 |');
say('|---|---|');
for (const [k, v] of sortedCount(rGroups)) say(`| ${k} | ${v} |`);
say('');
say('## 明确不覆盖（写下来才有边界，空着等于没想过）');
say('');
const notCovered = schema.crossTrack.notCovered ?? [];
if (!notCovered.length) say('- （契约表 crossTrack.notCovered 为空 —— 需要显式列出「我们看过但裁定不做」的类别，否则这一节永远是摆设）');
for (const n of notCovered) say(`- **${n.area}**：${n.reason}${n.status ? `（${n.status}）` : ''}`);
say('');
const out = lines.join('\n');
console.log(out);

if (mdIdx >= 0 && argv[mdIdx + 1]) fs.writeFileSync(argv[mdIdx + 1], out + '\n');

let fail = 0;
if (WRITE) {
  fs.writeFileSync(BASELINE, JSON.stringify({ rulesVersion: cleanup.rulesVersion, covered: coveredIds }, null, 2) + '\n');
  console.log(`\n↻ 基线已刷新：${coveredIds.length} 条覆盖项 → ${path.relative(ROOT, BASELINE)}`);
} else if (!baseline) {
  console.error('\n✗ 没有基线文件，先跑 node tools/gen-rule-coverage.mjs --write 建立');
  process.exit(1);
} else {
  const before = new Set(baseline.covered || []);
  const now = new Set(coveredIds);
  const lost = [...before].filter((x) => !now.has(x));
  const added = [...now].filter((x) => !before.has(x));
  if (lost.length) {
    console.error(`\n✗ 覆盖缩水 ${lost.length} 条：${lost.join('、')}`);
    console.error('  条目被删或路径来源变成引擎不认的键都算缩水。有意收缩请跑 --bump-baseline 并在审核记录里写明原因。');
    fail = 1;
  } else {
    console.log(`\n✓ 覆盖基线未缩水（${now.size} 条${added.length ? `，本轮新增 ${added.length} 条：${added.join('、')}` : ''}）`);
  }
  if (baseline.rulesVersion !== cleanup.rulesVersion) {
    console.log(`  注意：基线建在 rulesVersion=${baseline.rulesVersion}，当前库=${cleanup.rulesVersion}`);
  }
}
process.exit(fail);
