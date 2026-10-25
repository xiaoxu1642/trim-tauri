#!/usr/bin/env node
// check-optimizer-subitem-contract.mjs —— 批量优化项「可自选目标」契约门禁
//
// 为什么需要它（2026-10-03）：用户裁定「移除内置 UWP / 禁用冗余外设 /
// 禁用非必要服务」这三项不该只能一键全选，要能逐项勾选。落法是新增侧表
// `data/optimizer-subitems.json` 登记可勾选清单，后端按选择重建脚本。
//
// 这条门禁锁的是那份侧表与**数据层 pwsh 文本**的一致性。危险形态很具体：
// 侧表 `targets` 少写一个服务名 → 界面勾不到它 → 用户以为全选了却少禁一个；
// 侧表多写一个 → 界面能勾，但脚本重建时找不到对应来源，行为不可预期。
// 两边都是**静默**的：执行回执照样报「完成」。
//
// 为什么不把清单塞进 optimizer-runtime.json：那份与 vendor/upstream-js 的 OPTIONS
// 逐字段双源对拍（check-data-parity P2），往里加字段必判红。姿势同 optimizer-writes.json：
// 单源展示数据 + 本门禁对拍，真源始终是数据层的 pwsh 文本。
//
// 断言清单：
//   1. 侧表结构合法（items 键、每项的 targets/labels/extras）
//   2. `targets` 与 optimizer-runtime.json 里该项 pwsh 的 @("...") 数组**逐项同序相等**
//   3. `labels` 的键必须 ⊆ `targets`（不许有登记了但清单里没有的幽灵项）
//   4. `extras[].id` 不得与 `targets` 里的服务名冲突
//   5. 三项必须全部登记（新增同类批量项时忘了登记会红）
//   6. labels 覆盖率棘轮：登记率不得低于基线（防止悄悄删掉解释文案）
//   7. 标题数字不许写死（2026-10-05 裁定）：数据层无数字，侧表必须逐字跟随
//   8. 简介里的总数声明必须等于 targets 长度（2026-10-26 双源账补）
//
// 用法：node tools/check-optimizer-subitem-contract.mjs [--verbose]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSchema } from './rule-schema.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const VERBOSE = process.argv.includes('--verbose');

// 必须登记的批量项（新增同类项时追加；忘了登记 = 界面上仍是一键全选）
// tf_dev_disable 是 2026-10-05 补的：用户反馈「禁用冗余板载设备」只能一键全禁，
// 而它根本没进侧表 ⇒ `rebuild_steps` 走 `_ => None` ⇒ 界面上连勾选弹窗都不会出现。
const REQUIRED = ['tf_svc_bulk', 'tf_drv_disable', 'tf_appx', 'tf_dev_disable'];

// labels 覆盖率棘轮（已登记解释文案的目标数 / 清单总数，取下界）
const LABEL_COVERAGE_FLOOR = 0.6;

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
  return ok;
};

console.log('=== 批量优化项可自选目标契约门禁 ===\n');

const subPath = 'src-tauri/data/optimizer-subitems.json';
if (!fs.existsSync(path.join(ROOT, subPath))) {
  console.error(`✗ 读取 ${subPath} — 文件不存在`);
  process.exit(1);
}
let sub;
let runtime;
try {
  sub = JSON.parse(read(subPath));
} catch (e) {
  console.error(`✗ ${subPath} 不是合法 JSON — ${e.message}`);
  process.exit(1);
}
try {
  runtime = JSON.parse(read('src-tauri/data/optimizer-runtime.json'));
} catch (e) {
  console.error(`✗ optimizer-runtime.json 不是合法 JSON — ${e.message}`);
  process.exit(1);
}
const byId = new Map((Array.isArray(runtime) ? runtime : []).map((o) => [o.id, o]));

/**
 * 从一段 pwsh 文本里抽出**全部** `@("a","b",…)` 数组（T1b-L02：旧实现只看 steps[0]
 * 的第一个数组，restore 与后续 steps 里的清单整本漏掉）。
 */
function extractArrays(pwsh) {
  if (typeof pwsh !== 'string') return [];
  return [...pwsh.matchAll(/@\(((?:"[^"]*"\s*,?\s*)+)\)/g)]
    .map((m) => [...m[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]));
}

// ---- 1. 结构与必登项 ----
const items = sub.items ?? {};
const SIDE_SCHEMA_VER = loadSchema().optimizer?.sideTableSchemaVer;
check(sub.schemaVer === SIDE_SCHEMA_VER, `1. schemaVer = ${SIDE_SCHEMA_VER}（契约表 optimizer.sideTableSchemaVer）`, `实际 ${sub.schemaVer}`);
for (const id of REQUIRED) {
  check(Object.prototype.hasOwnProperty.call(items, id), `1. 已登记批量项 ${id}`);
}

// ---- 2~4. 逐项对拍 ----
for (const id of REQUIRED) {
  const row = items[id];
  if (!row) continue;
  const opt = byId.get(id);
  if (!check(!!opt, `2. ${id} 在 optimizer-runtime.json 里存在`)) continue;

  const allPwsh = [...(opt.steps ?? []), ...(opt.restore ?? [])]
    .map((s) => s.pwsh || '')
    .join('\n');
  const arrays = extractArrays(allPwsh);
  if (!check(arrays.length === 1, `2. ${id} 的 steps/restore 里恰好一个 @("...") 清单`,
    arrays.length === 0 ? '没有可解析清单' : `实得 ${arrays.length} 个（侧表只登记一本账，需扩展契约）`)) {
    continue;
  }
  const fromScript = arrays[0];

  const full = row.targets;
  if (!check(Array.isArray(full) && full.length > 0, `2. ${id} 的 targets 是非空数组`)) continue;

  // 逐项同序比较：顺序变了也要红 —— 界面上勾选的第 N 项必须对应脚本里的第 N 项
  const sameLen = full.length === fromScript.length;
  let firstDiff = -1;
  const n = Math.min(full.length, fromScript.length);
  for (let i = 0; i < n; i++) {
    if (full[i] !== fromScript[i]) { firstDiff = i; break; }
  }
  check(sameLen && firstDiff === -1, `2. ${id} 的 targets 与数据层脚本逐项同序相等`,
    sameLen
      ? (firstDiff === -1 ? `${full.length} 项一致` : `第 ${firstDiff} 项不同：侧表「${full[firstDiff]}」 vs 脚本「${fromScript[firstDiff]}」`)
      : `条数不同：侧表 ${full.length} / 脚本 ${fromScript.length}`);

  // ---- 3. labels 键 ⊆ full ----
  const labels = row.labels ?? {};
  const labelKeys = Object.keys(labels);
  const ghost = labelKeys.filter((k) => !full.includes(k));
  check(ghost.length === 0, `3. ${id} 的 labels 无幽灵键`, ghost.length ? `不在 targets 里：${ghost.join('、')}` : `${labelKeys.length} 条`);
  if (VERBOSE) labelKeys.forEach((k) => console.log(`     · ${k} → ${labels[k]}`));

  // ---- 4. extras id 不与 full 冲突 ----
  const extras = row.extras ?? [];
  check(Array.isArray(extras), `4. ${id} 的 extras 是数组`);
  const extraIds = extras.map((e) => e?.id).filter((x) => typeof x === 'string');
  const clash = extraIds.filter((id2) => full.includes(id2));
  check(clash.length === 0, `4. ${id} 的 extras id 不与清单冲突`, clash.length ? `冲突：${clash.join('、')}` : `${extraIds.length} 条`);
  const badExtra = extras.filter((e) => typeof e?.id !== 'string' || typeof e?.label !== 'string' || typeof e?.note !== 'string');
  check(badExtra.length === 0, `4. ${id} 的 extras 每条都有 id/label/note`, `${extras.length} 条`);

  // ---- 6. labels 覆盖率棘轮 ----
  const cov = full.length ? labelKeys.filter((k) => full.includes(k)).length / full.length : 0;
  check(cov >= LABEL_COVERAGE_FLOOR, `6. ${id} 的解释文案覆盖率 ≥ ${LABEL_COVERAGE_FLOOR}`,
    `${labelKeys.length}/${full.length} = ${(cov * 100).toFixed(0)}%`);
}

// ---- 7. 标题：数字不许写死（2026-10-05 用户裁定）----
// 数据层标题此前带写死数字，与侧表实数已经不符，而且清单每增补一次就再谎报一次。
// 2026-10-26 已把数据源与侧表标题统一成**无数字**说法（实数由勾选区按清单长度现算）。
// 这里判红而不是提醒：标题覆盖只在 `display_title` 一处生效，侧表漏登记 = 界面退回
// 带假数字的旧标题，肉眼看不出来。
for (const id of REQUIRED) {
  const row = items[id];
  const opt = byId.get(id);
  if (!row || !opt) continue;
  const dataTitle = String(opt.title ?? '');
  const t = row.title;
  if (!check(typeof t === 'string' && t.trim() !== '', `7. ${id} 侧表登记了标题`)) continue;
  if (/\d/.test(dataTitle)) {
    check(!/\d/.test(t), `7. ${id} 的侧表标题不含写死的数字`, `数据层「${dataTitle}」→ 侧表「${t}」`);
    check(t !== dataTitle, `7. ${id} 的侧表标题确实替换了带数字的那条`, `侧表「${t}」`);
  } else {
    // 数据层本来就没写数字 ⇒ 不许借「覆盖」改名：两条说法并存会让日志与界面对不上
    check(t === dataTitle, `7. ${id} 的侧表标题与数据层逐字一致（无数字就不该改名）`,
      `数据层「${dataTitle}」/ 侧表「${t}」`);
  }
}

// ---- 反向：侧表里不得有数据层不存在的项（防残留登记腐化，与 channel-map 的 RETIRED 同向）----
for (const id of Object.keys(items)) {
  if (REQUIRED.includes(id)) continue;
  check(false, `反向：侧表里的 ${id} 不在必登清单内（项已退役或拼错？摘掉这条登记）`);
}

// ---- 8. 简介里的总数声明必须等于 targets 长度（2026-10-26 双源账） ----
// 标题已统一无数字（第 7 组）；简介仍允许写总数，但必须与实盘清单一致，
// 否则就是 D1 抓到的「24/25、70+/65」同族谎报。判据只认「数字 + 该条目的名词」，
// 不碰简介里的子计数（如 tf_dev_disable 的「7 个 WAN Miniport」）。
const COUNT_NOUN = {
  tf_svc_bulk: /(\d+)\s*\+?\s*(?:个|项|条)?[^。；]{0,8}非必要服务/,
  tf_drv_disable: /(\d+)\s*个[^。；]{0,8}高风险驱动/,
  tf_appx: /(\d+)\s*个[^。；]{0,6}内置\s*UWP/,
  tf_dev_disable: /(\d+)\s*个[^。；]{0,12}板载设备/,
};
const countClaimOf = (text, id) => {
  const m = String(text || '').match(COUNT_NOUN[id] || /$^/);
  return m ? Number(m[1]) : null;
};
{
  // 正向对照：命中正确数字 / 旧文案能命中 / 子计数不误报
  check(countClaimOf('批量禁用 25 项非必要服务', 'tf_svc_bulk') === 25, '8. 对照：数字 + 名词能解析');
  check(countClaimOf('批量禁用串口、并口等 24 个极少使用的板载设备', 'tf_dev_disable') === 24, '8. 对照：旧文案能命中');
  check(countClaimOf('批量禁用串口、并口等极少使用的板载设备', 'tf_dev_disable') === null, '8. 对照：去计数后的文案不误报');
  check(countClaimOf('禁用 7 个 WAN Miniport', 'tf_dev_disable') === null, '8. 对照：子计数不误报');

  let intro = null;
  try {
    intro = JSON.parse(read('src-tauri/data/item-intro.json'));
  } catch (e) {
    check(false, '8. item-intro.json 读取失败', e.message);
  }
  const byIntro = (intro && intro.scopes && intro.scopes.optimizer && intro.scopes.optimizer.byId) || {};
  for (const id of REQUIRED) {
    const opt = byId.get(id);
    const row = items[id];
    if (!opt || !row) continue;
    const n = Array.isArray(row.targets) ? row.targets.length : -1;
    const title = String(opt.title ?? '');
    check(!/\d/.test(title), `8. ${id} 数据层标题不含写死数字`, `「${title}」`);
    const desc = (byIntro[id] && byIntro[id].desc) || '';
    const claim = countClaimOf(desc, id);
    if (claim === null) {
      check(true, `8. ${id} 简介未写死总数（标题已无数字，实数由勾选区现算）`);
    } else {
      check(claim === n, `8. ${id} 简介总数 = targets 长度`, `简介 ${claim} / 清单 ${n}`);
    }
  }
}

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 项不一致`);
  process.exit(1);
}
console.log('批量优化项可自选目标契约门禁全部通过');
