#!/usr/bin/env node
// check-cleanup-rule-contract.mjs - 清理规则库契约门禁（P0，规则库最终优化方案 2026-09-27）
//
// 防三类问题复发：
//   1. 规则里的 %TOKEN% 展开器解析不了 → 「扫描命中、执行 0 删、状态成功」
//      （printSpoolCache 实锤：%WINDIR% 大写形态在旧执行侧白名单展开器下永远展不开）；
//   2. 扫描/执行两侧口径不一致的字段混进规则库（执行侧未实现的 excludeKeys、
//      扫描侧支持而执行侧不支持的 `?` 通配 / `/` 分隔符 / 多星 pattern）；
//   3. 精确重复规则与已裁决移除的 deleteMode 字段回潮。
//
// V2（2026-09-30）改造两点：
//   · 词汇与上限不再抄在本文件里，统一取自 `tools/rule-schema.json`（Rust 装载侧读同一份字节）；
//     断言实现抽到 `tools/cleanup-contract.mjs`，与 Rust 的 `validate_cleanup_package` 各自独立、
//     靠 `tools/fixtures/cleanup-contract.json` 钉口径 —— 本文件不调 Rust。
//   · 判定器自检升级为**双向核对**：夹具必须能打到每条登记过的断言（漏样本红），
//     样本引用的断言必须在登记表里（引用不存在红），合法样本必须零错（判定器过严红）。
//     背景：真实规则库里没有反例，光跑数据永远测不出"判定器坏成永远放行"（AGENTS §4 假绿前科）。
//
// 可判红要求（AGENTS §4）：新增断言后至少人为破坏一次、确认退出码非 0、再恢复。
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
import { loadSchema, number as schemaNumber } from './rule-schema.mjs';
import { ASSERTIONS, validateCleanupPackage, selfTest } from './cleanup-contract.mjs';

const RULES_REL = path.join('src-tauri', 'data', 'cleanup-rules.json');
const FIXTURE_REL = path.join('tools', 'fixtures', 'cleanup-contract.json');

// P1-4 winapp2Version 冻结棘轮：它只是历史素材基线，不再是扩库成果指标，
// 禁止随「计划同步」「看到新版库」抬值。确需抬值必须改契约表并写明依据（版本、日期、决策）。
const FROZEN_KEY = 'frozenWinapp2Version';

const errors = [];
function fail(msg) {
  console.error(`✗ ${msg}`);
  errors.push(msg);
}

function collectItems(rules) {
  const items = [];
  for (const g of rules.groups ?? []) {
    for (const it of g.items ?? []) items.push(it);
    for (const sg of g.subGroups ?? []) for (const it of sg.items ?? []) items.push(it);
  }
  return items;
}

function main() {
  // ---- 0. 契约表本身可用（表坏了 ⇒ 两侧判定都会变形，先钉住） ----
  let schema;
  try {
    schema = loadSchema();
  } catch (e) {
    fail(`[A0] 契约表不可用：${e.message}`);
    return;
  }

  // ---- 1. 判定器自检（坏判定器必红，且不放过"过严"这一侧） ----
  for (const why of selfTest(validateCleanupPackage)) {
    fail(`[A0] 判定器自检失败：${why}`);
  }

  // ---- 2. 夹具双向核对：每条断言都要有反例，每个反例都要打中登记的断言 ----
  const fixturePath = path.join(ROOT, FIXTURE_REL);
  let fixture;
  try {
    fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  } catch (e) {
    fail(`[A0] 夹具不可读：${e.message}`);
    return;
  }
  const declaredIds = Array.isArray(fixture.assertionIds) ? fixture.assertionIds : [];
  const cases = Array.isArray(fixture.packages) ? fixture.packages : [];
  if (cases.length < 12) fail(`[A0] 夹具用例只有 ${cases.length} 条，覆盖不住各保护类别`);

  // 2a 断言登记表 ↔ 夹具声明 一致（两边必须列同一批 ID，缺一边即红）
  const implIds = Object.keys(ASSERTIONS);
  for (const id of implIds) {
    if (!declaredIds.includes(id)) fail(`[A0] 断言 ${id} 已实现但没进夹具 assertionIds（等于永远不会被测坏）`);
  }
  for (const id of declaredIds) {
    if (!implIds.includes(id)) fail(`[A0] 夹具声明的断言 ${id} 在 cleanup-contract.mjs 里不存在（空登记）`);
  }
  // 2b 每条断言至少一个反例
  for (const id of implIds) {
    if (!cases.some((c) => (c.mustTrigger ?? []).includes(id))) {
      fail(`[A0] 断言 ${id}（${ASSERTIONS[id]}）没有任何夹具反例 ⇒ 这条断言永远不会被测坏`);
    }
  }
  // 2c 逐用例判定
  const firedByCase = [];
  for (const c of cases) {
    const label = c.label ?? '?';
    const errs = validateCleanupPackage(c.pkg ?? {});
    const ids = [...new Set(errs.map((e) => (e.match(/^\[(A\d+)\]/) ?? [, '?'])[1]))];
    firedByCase.push({ label, ok: Boolean(c.ok), ids, count: errs.length });
    if (c.ok) {
      if (errs.length !== 0) fail(`[A0] 夹具合法用例「${label}」被判红：${errs.join('；')}`);
      continue;
    }
    if (errs.length === 0) {
      fail(`[A0] 夹具反例「${label}」被放行 ⇒ 判定器坏成永远放行（应命中 ${(c.mustTrigger ?? []).join('/')}`);
      continue;
    }
    for (const id of c.mustTrigger ?? []) {
      if (!ids.includes(id)) fail(`[A0] 夹具反例「${label}」应命中 ${id}（${ASSERTIONS[id] ?? '?'}），实际只命中 ${ids.join('/') || '无'}`);
    }
    for (const id of ids) {
      if (!implIds.includes(id)) fail(`[A0] 夹具反例「${label}」命中了未登记的断言 ${id}`);
    }
  }

  // ---- 3. 真实规则库过同一个校验器 ----
  const file = path.join(ROOT, RULES_REL);
  let rules;
  try {
    rules = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    fail(`规则 JSON 不可读: ${e.message}`);
    return;
  }
  const items = collectItems(rules);
  if (items.length === 0) fail('规则库没有任何条目（groups 结构异常？）');

  const pkgErrs = validateCleanupPackage(rules);
  for (const e of pkgErrs) fail(`真实规则库：${e}`);

  // ---- 4. 门禁专属断言（不属于"包语义"，不放进夹具） ----
  // ---- 4z 跨轨登记表不许腐烂（V2 P2-D7）----
  // 登记的是"实测不等价点"。一旦有人动了消费方代码（修 D19、扩那份硬编码 id 清单、
  // 换专用通道），这张表就从证据变成神话 —— 所以每条都拿 anchor 回代码里对一遍。
  const xt = schema.crossTrack ?? {};
  const points = Array.isArray(xt.points) ? xt.points : [];
  if (points.length === 0) {
    fail('[A13] 契约表 crossTrack.points 为空：已实测的不等价点必须登记（没有也要写明"本轮未发现"）');
  }
  for (const p2 of [...points, ...(Array.isArray(xt.specialHandlers) ? xt.specialHandlers : [])]) {
    const file = p2.consumer;
    const anchor = p2.anchor;
    const label = p2.id ?? p2.key ?? '?';
    if (!file || !anchor) {
      fail(`[A13] 登记项 ${label} 缺 consumer/anchor（没有坐标的登记表无法核对）`);
      continue;
    }
    let text;
    try {
      text = fs.readFileSync(path.join(ROOT, file), 'utf8');
    } catch (e) {
      fail(`[A13] 登记项 ${label} 的消费方读不到：${file}（${e.message}）`);
      continue;
    }
    if (!text.includes(anchor)) {
      fail(`[A13] 登记项 ${label} 的 anchor 在 ${file} 里已找不到 ⇒ 代码已改动，本条登记过期，复核后更新或删除`);
    }
  }
  // 取值域与库对齐：未登记取值 = A13 红（装载侧同口径）；登记了但库里没人用 = 表没跟着收缩
  for (const h of Array.isArray(xt.specialHandlers) ? xt.specialHandlers : []) {
    const used = new Set(items.map((it) => it[h.key]).filter((v) => v !== undefined));
    const unknown = [...used].filter((v) => !(h.values || []).includes(v));
    if (unknown.length) fail(`[A13] 条目里出现未登记的 ${h.key} 取值：${unknown.join('/')}（先实测消费方再进表）`);
    const stale = (h.values || []).filter((v) => !used.has(v));
    if (stale.length) fail(`[A13] ${h.key} 登记了库内已不存在的取值：${stale.join('/')}（登记表必须跟着真库收缩）`);
  }
  // 死键使用者必须全数登记：将来有人修那份硬编码 id 清单时，这份清单就是改动面
  for (const k of Array.isArray(xt.deadSourceKeys) ? xt.deadSourceKeys : []) {
    const users = items.filter((it) => Array.isArray(it[k]) && it[k].length > 0).map((it) => it.id);
    const pt = points.find((x) => String(x.key ?? '').includes(k));
    if (pt && users.length) {
      const listed = new Set(pt.affectedItems ?? []);
      const missing = users.filter((id) => !listed.has(id));
      if (missing.length) fail(`[A13] 使用死键 ${k} 的条目未全数登记：缺 ${missing.join('/')}（affectedItems 要跟库对齐）`);
    }
  }

  // 4a winapp2Version 冻结棘轮（值取自契约表，改值必须同时改表 ⇒ 留痕）
  const frozen = schema.cleanup[FROZEN_KEY];
  if (!frozen) {
    fail(`[A5] 契约表缺 cleanup.${FROZEN_KEY}.winapp2Version（冻结值没了等于放开抬值）`);
  } else if ('winapp2Version' in rules && String(rules.winapp2Version) !== String(frozen)) {
    fail(
      `[A5] winapp2Version=${rules.winapp2Version} 与冻结值 ${frozen} 不符——P1-4 已裁决它只是历史素材基线，` +
        `禁止随「计划同步」抬值；确需变动请同时改 tools/rule-schema.json 与本门禁的注释并写明依据`,
    );
  }
  // 4b rulesVersion 下限棘轮（只升不降；上限交给装载侧防回滚链）
  const minVer = Number(schema.cleanup.versionRatchetMin ?? 0);
  if (!minVer) {
    fail('[A5] 契约表缺 cleanup.versionRatchetMin');
  } else if (typeof rules.rulesVersion !== 'number' || rules.rulesVersion < minVer) {
    fail(`[A5] rulesVersion 必须是不低于 ${minVer} 的数字`);
  }
  // 4c 父子路径重叠 → 人工复核清单（非致命，P1-2）
  const filePaths = [];
  for (const it of items) {
    for (const fk of it.fileKeys ?? []) {
      filePaths.push({ id: it.id, path: (fk.path ?? '').toLowerCase().replace(/\\+$/, '') });
    }
  }
  const overlaps = [];
  for (let i = 0; i < filePaths.length; i++) {
    for (let j = 0; j < filePaths.length; j++) {
      if (i === j) continue;
      const a = filePaths[i];
      const b = filePaths[j];
      if (a.id === b.id || !a.path || !b.path || a.path.includes('*') || b.path.includes('*')) continue;
      if (b.path.startsWith(a.path + '\\')) overlaps.push([a, b]);
    }
  }
  if (overlaps.length > 0) {
    console.log(
      `\n〔人工复核清单〕父子路径重叠 ${overlaps.length} 组（不判红，但每批发布前须有明确合并/排除/共存结论，记录见 docs/规则库审核记录-*.md）：`,
    );
    for (const [parent, child] of overlaps) {
      console.log(`  · ${parent.id}（${parent.path}）⊃ ${child.id}（${child.path}）`);
    }
  }
  // 4d 上限口径提示（阈值本身由校验器把关，这里只报当前水位，防"贴着上限"无人察觉）
  const maxItems = schemaNumber('cleanup', 'maxItems');
  if (items.length > maxItems * 0.9) {
    console.log(`\n〔水位提示〕条目数 ${items.length} 已接近上限 ${maxItems}（90%），扩库前先确认上限是不是被随手抬过`);
  }

  if (errors.length > 0) {
    console.error(`\n清理规则契约门禁：${errors.length} 处违约（共检查 ${items.length} 条规则 / 夹具 ${cases.length} 用例）`);
    process.exit(1);
  }
  console.log(
    `✓ 清理规则契约门禁通过：${items.length} 条规则；判定器自检与夹具 ${cases.length} 用例双向核对 ` +
      `（${implIds.length} 条断言全部有反例）；契约表 schemaVersion=${schema.schemaVersion}`,
  );
  console.log(`  覆盖明细：${implIds.map((id) => `${id}=${firedByCase.filter((c) => !c.ok && c.ids.includes(id)).length} 反例`).join(' ')}`);
}

main();
