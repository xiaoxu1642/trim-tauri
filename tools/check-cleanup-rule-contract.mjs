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
import { allItems } from './lib/rule-shape.mjs';
import { findWholeTreeOverlaps } from './lib/rule-overlap.mjs';

const RULES_REL = path.join('src-tauri', 'data', 'cleanup-rules.json');
const FIXTURE_REL = path.join('tools', 'fixtures', 'cleanup-contract.json');
// 跨条目整树覆盖台账（现算回填，见 4c）
const OVERLAP_REL = path.join('tools', 'fixtures', 'cleanup-overlaps.json');

// P1-4 winapp2Version 冻结棘轮：它只是历史素材基线，不再是扩库成果指标，
// 禁止随「计划同步」「看到新版库」抬值。确需抬值必须改契约表并写明依据（版本、日期、决策）。
const FROZEN_KEY = 'frozenWinapp2Version';

const errors = [];
function fail(msg) {
  console.error(`✗ ${msg}`);
  errors.push(msg);
  // T1-K01（v4-K07）：任何一条 fail 都必须让进程退出码非 0。此前三处「致命错误 + return」
  // 绕过末尾的 exit(1)，打 ✗ 也 exit 0；exitCode 兜底后，将来再有人写 return 短路同样判红。
  process.exitCode = 1;
}

// 条目遍历口径统一走 tools/lib/rule-shape.mjs（顶层 items 与 subGroups.items 两层都算）；
// 本门禁只保留变量名，避免同一份遍历在三个门禁里各写一遍、扁平化某个域时半数门禁数不到。
const collectItems = allItems;

function main() {
  // ---- 0. 契约表本身可用（表坏了 ⇒ 两侧判定都会变形，先钉住） ----
  let schema;
  try {
    schema = loadSchema();
  } catch (e) {
    fail(`[A0] 契约表不可用：${e.message}`);
    return process.exit(1);
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
    return process.exit(1);
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
    return process.exit(1);
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
  // 4c 跨条目整树覆盖：由「不判红的人工复核清单」升级为**判红棘轮**（2026-10-23）
  //
  // 旧形态瞎在三处，每一条都被这次真机实测踩到：只收 fileKeys（`nvidiaCache` 是 pathPs，
  // 根本不入表）、`a.path.includes('*') || b.path.includes('*')` 直接跳过（`%LOCALAPPDATA%\NVIDIA\*Cache`
  // 正是那个把 DXCache/GLCache 罩住的通配根）、且只打印不判红。判据本体在
  // `tools/lib/rule-overlap.mjs`（唯一实现，下面 4c-selftest 的合成样本与生产共用它）。
  // 台账 `tools/fixtures/cleanup-overlaps.json` 由 `--emit-overlaps` **现算回填**，
  // 不手抄、不许随行号或本机路径变化；双向对账：新出现而未裁决的覆盖对判红，
  // 台账里已不存在的陈旧登记同样判红（否则旧条目会给新重叠打掩护）。
  const ovPath = path.join(ROOT, OVERLAP_REL);
  const { pairs: ovPairs, unresolved: ovUnresolved } = findWholeTreeOverlaps(items);
  const ovKey = (p) => `${p.parentId}\n${p.childId}\n${p.parentTarget}\n${p.childTarget}`;
  if (process.argv.includes('--emit-overlaps')) {
    const body = {
      _说明:
        '清理规则「跨条目整树覆盖」台账：由 `node tools/check-cleanup-rule-contract.mjs --emit-overlaps` 现算回填，禁止手抄。' +
        '每一行都是一处「逐条相加会算两遍」的实据；新增行必须伴随评审结论（合并 / 排除 / 明确共存），删行必须确认该覆盖关系真的消失了。',
      pairs: ovPairs,
      unresolved: ovUnresolved,
    };
    fs.writeFileSync(ovPath, JSON.stringify(body, null, 1) + '\n', 'utf8');
    console.log(`✓ 已现算回填覆盖台账：${ovPairs.length} 条有向覆盖关系 / ${ovUnresolved.length} 条不可判形态 → ${OVERLAP_REL}`);
  } else {
    let ledger = null;
    try {
      ledger = JSON.parse(fs.readFileSync(ovPath, 'utf8'));
    } catch (e) {
      fail(`[A16] 覆盖台账 ${OVERLAP_REL} 不可读：${e.message}（要用 --emit-overlaps 现算回填，不许手抄，也不许当成「没有重叠」放行）`);
    }
    if (ledger) {
      const wasPairs = new Map((Array.isArray(ledger.pairs) ? ledger.pairs : []).map((p) => [ovKey(p), p]));
      const nowPairs = new Map(ovPairs.map((p) => [ovKey(p), p]));
      for (const [k, p] of nowPairs) {
        if (wasPairs.has(k)) continue;
        fail(
          `[A16] 新增跨条目整树覆盖未经裁决：${p.parentId}（「${p.parentTarget}」）整树覆盖 ${p.childId}（「${p.childTarget}」）` +
            '—— 同一批文件会被逐条相加算两遍；要么合并/排除规则，要么 --emit-overlaps 现算回填并在评审里写明共存结论',
        );
      }
      for (const [k, p] of wasPairs) {
        if (nowPairs.has(k)) continue;
        fail(`[A16] 覆盖台账里的陈旧条目已不成立：${p.parentId} ⊃ ${p.childId}（「${p.parentTarget}」/「${p.childTarget}」）—— 必须删行，留着会给新重叠打掩护`);
      }
      const wasUn = new Map((Array.isArray(ledger.unresolved) ? ledger.unresolved : []).map((u) => [`${u.id}\n${u.expr}`, u]));
      const nowUn = new Map(ovUnresolved.map((u) => [`${u.id}\n${u.expr}`, u]));
      for (const [k, u] of nowUn) {
        if (wasUn.has(k)) continue;
        fail(`[A16] pathPs 出现判据解析不了的形态：${u.id} = ${JSON.stringify(u.expr)}（本判据对它失明，必须显式裁决而不是静默跳过）`);
      }
      for (const [k, u] of wasUn) {
        if (nowUn.has(k)) continue;
        fail(`[A16] 不可判形态台账有陈旧条目：${u.id} = ${JSON.stringify(u.expr)}（已不存在，必须删行）`);
      }
      console.log(
        `✓ 跨条目整树覆盖：现算 ${ovPairs.length} 条有向覆盖关系 / ${ovUnresolved.length} 条不可判形态，与台账双向对账一致`,
      );
    }
  }
  // 4c-selftest 判据自检：合成样本与生产**共用同一个** findWholeTreeOverlaps
  // （AGENTS §4.1 正向对照——恒绿型判据必须先证明自己能判红，还要证明没判严）
  {
    const samples = [
      {
        name: '整树父条罩住通配子条（真机 nvidiaCache ⊃ nvidiaShaderCache 的形态）',
        items: [
          { id: 'ap', pathPs: "$env:LOCALAPPDATA + '\\NVIDIA'" },
          { id: 'ac', fileKeys: [{ path: '%LOCALAPPDATA%\\NVIDIA\\*Cache', pattern: '*', recurse: true }] },
        ],
        expectPairs: 1,
      },
      {
        name: '同根但子条只取根级（真机 D3DSCache 的形态）',
        items: [
          { id: 'dp', pathPs: "$env:LOCALAPPDATA + '\\D3DSCache'" },
          { id: 'dc', fileKeys: [{ path: '%LOCALAPPDATA%\\D3DSCache', pattern: '*', recurse: false }] },
        ],
        expectPairs: 1,
      },
      {
        name: '双方同根且都整树 ⇒ 两个方向各算一遍',
        items: [
          { id: 'ep', pathPs: "$env:PROGRAMDATA + '\\NVIDIA Corporation\\NV_Cache'" },
          { id: 'ec', fileKeys: [{ path: '%PROGRAMDATA%\\NVIDIA Corporation\\NV_Cache', pattern: '*', recurse: true }] },
        ],
        expectPairs: 2,
      },
      {
        name: '父条 recurse:false 不构成整树覆盖（判据不许过严）',
        items: [
          { id: 'fp', fileKeys: [{ path: '%LOCALAPPDATA%\\NVIDIA', pattern: '*', recurse: false }] },
          { id: 'fc', fileKeys: [{ path: '%LOCALAPPDATA%\\NVIDIA\\DXCache', pattern: '*', recurse: true }] },
        ],
        expectPairs: 0,
      },
      {
        name: '兄弟目录不重叠（判据不许过严）',
        items: [
          { id: 'gp', pathPs: "$env:LOCALAPPDATA + '\\Alpha'" },
          { id: 'gc', pathPs: "$env:LOCALAPPDATA + '\\Beta'" },
        ],
        expectPairs: 0,
      },
      {
        name: '父子关系（非通配、深层子目录）',
        items: [
          { id: 'hp', pathPs: "$env:APPDATA + '\\Tencent\\QQ'" },
          { id: 'hc', pathPs: "$env:APPDATA + '\\Tencent\\QQ\\Temp'" },
        ],
        expectPairs: 1,
      },
      {
        name: '路径里的 ++ 是路径字符，不得误报成未知形态',
        items: [{ id: 'ip', pathPs: "$env:LOCALAPPDATA + '\\Dism++Backup'" }],
        expectPairs: 0,
        expectUnresolved: 0,
      },
      {
        name: '空字面量 pathPs 必须显式报不可判（静默跳过就是旧门禁的失明方式）',
        items: [{ id: 'jp', pathPs: "''" }],
        expectPairs: 0,
        expectUnresolved: 1,
      },
    ];
    for (const s of samples) {
      const r = findWholeTreeOverlaps(s.items);
      if (r.pairs.length !== s.expectPairs) {
        fail(
          `[A16-selftest] 样本「${s.name}」应判出 ${s.expectPairs} 条覆盖关系，实到 ${r.pairs.length}` +
            `（${r.pairs.length > s.expectPairs ? '判据过严会把合法规则打死' : '判据坏成永远放行'}）：` +
            r.pairs.map((p) => `${p.parentId}⊃${p.childId}`).join(','),
        );
      }
      if (s.expectUnresolved !== undefined && r.unresolved.length !== s.expectUnresolved) {
        fail(`[A16-selftest] 样本「${s.name}」的不可判形态应报 ${s.expectUnresolved} 条，实到 ${r.unresolved.length}`);
      }
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
