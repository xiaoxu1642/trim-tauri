// check-optimizer-dynamic.mjs —— 「dynamic 优化项的 id ⇄ 控件 ⇄ 参数」三方对拍（审查 v2-M10）
//
// 为什么需要这条门禁：v2-M10 的缺陷形态是「界面可见可点、后端永远报错」——
// 数据层把 perf_wu_pause 标成 `dynamic: true`，后端 is_dynamic 分支要求 `p.days`，
// 而前端把所有 dynamic 项一刀切画成内存 GB 下拉、只发 `{gb}`。
// 三方各改一处都不会有编译错误、不会有测试红，只有用户看见「这个优化项永远失败」。
// 唯一能长期钉住它的是静态对拍：**三份集合必须一致**。
//
// 七条断言：
//   A1 数据层 `dynamic:true` 的 id 集合 == optimizer.js 的 DYNAMIC_CONTROLS 键集合（双向差集）
//   A2 每个 dynamic id 在 Rust 的 is_dynamic 分支里有 `option_id == "<id>"` 分支
//   A3 前端 paramKey == 该分支读的 `p.<字段>`，且字段存在于 RunParams
//   A4 暂停天数上限两侧一致（JS WU_PAUSE_MAX_DAYS == Rust 同名常量）
//   A5 前端不得再按 `dynamic` 一刀切：`.opt-mem-select` 必须归零、执行参数走 dynamicParams、
//      批量入口不得再发裸 `{}`（那正是 v2-M10 的第二条失法路径）
//   A6 生效粒度侧表 optimizer-scope.json ⇄ 按步骤机械重算（详见块内注释）
//   A7 虚拟合集卡（optimizer.js 的 VIRTUAL_GROUPS）⇄ 数据层：runId 必须真存在、
//      一卡至少两态、同一真实项不得被两卡抢、整卡档位不得低于成员最高档
//   A8 D0 三侧覆盖契约：数据层 steps 的每个字段必须被「执行 / 检测 / 备份」三侧
//      同时消费（详见下方块内注释）
//
// 用法：node tools/check-optimizer-dynamic.mjs
//   退出码 0 = 八条全绿；1 = 任一不符（无「只警告」档）。

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const R = (rel) => readFileSync(join(REPO_ROOT, ...rel.split('/')), 'utf8');

const dataJson = R('src-tauri/data/optimizer-runtime.json');
const jsOpt = R('src/scripts/optimizer.js');
// v3 D4：optimizer.rs 拆目录后按**契约面点名文件**，不拼整个目录——A 组靠
// `let is_dynamic` 字面前缀定位 4000 字符窗口、再按 `option_id == "<id>"` 取体，
// 拼接会让 overview.rs 里那个刻意改名的同名声明抢先命中，窗口就切错位置了。
const rustOpt = R('src-tauri/src/commands/optimizer/apply.rs');
const rustCatalog = R('src-tauri/src/commands/optimizer/catalog.rs');
// D0 三侧覆盖需要另外两侧的源码：检测侧在 overview.rs，备份侧在 backup_restore.rs。
const rustOverview = R('src-tauri/src/commands/optimizer/overview.rs');
const rustBackup = R('src-tauri/src/commands/optimizer/backup_restore.rs');

let fail = 0;
function check(ok, name, detail) {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ' —— ' + detail : ''}`);
  if (!ok) fail++;
}

/** 从 `const NAME = {` 起按括号配平切出对象字面量（比按行猜 `};` 稳） */
function objectLiteral(src, declRegex) {
  const m = declRegex.exec(src);
  if (!m) return null;
  const start = src.indexOf('{', m.index);
  let depth = 0;
  for (let i = start; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (depth === 0) return src.slice(start, i + 1); }
  }
  return null;
}

/** 取对象字面量的**顶层**键：按花括号深度扫，depth===1 时出现的 `ident:` 才是顶层键。
 *  不能按缩进猜（本仓 optimizer.js 的表在 IIFE 里、键是 4 空格；写死 2 空格会解析出空集合，
 *  于是 A1 把"前端缺全部登记"报成缺陷——门禁自己误报比漏报更糟，它会让人去改对的代码）。 */
function topLevelKeys(lit) {
  const out = [];
  let depth = 0;
  for (const rawLine of lit.split(/\r?\n/)) {
    // 字符串字面量里的花括号不参与配平
    const line = rawLine.replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""');
    if (depth === 1) {
      const m = /^\s*([A-Za-z0-9_]+)\s*:/.exec(line);
      if (m) out.push(m[1]);
    }
    for (const ch of line) {
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
    }
  }
  return out;
}

// ---- A1：数据层 dynamic 集合 ⇄ 前端分派表键集合 ----
let options = null;
try { options = JSON.parse(dataJson); } catch { /* 下面判红 */ }
if (!Array.isArray(options)) {
  check(false, 'A1. 数据层 dynamic 集合 ⇄ 前端分派表', 'optimizer-runtime.json 读不到或不是数组');
} else {
  const dynIds = options.filter((o) => o && o.dynamic === true).map((o) => o.id).sort();
  const table = objectLiteral(jsOpt, /const DYNAMIC_CONTROLS\s*=/);
  if (!table) {
    check(false, 'A1. 数据层 dynamic 集合 ⇄ 前端分派表', 'optimizer.js 里找不到 const DYNAMIC_CONTROLS');
  } else {
    // 只取对象字面量**顶层**的 key（按深度扫，不猜缩进）
    const jsIds = topLevelKeys(table).sort();
    const missing = dynIds.filter((i) => !jsIds.includes(i));
    const extra = jsIds.filter((i) => !dynIds.includes(i));
    const a1Pass = missing.length === 0 && extra.length === 0 && dynIds.length > 0;
    check(
      a1Pass,
      `A1. 数据层 dynamic 集合 ⇄ 前端分派表（各 ${dynIds.length} / ${jsIds.length}）`,
      a1Pass ? '' : dynIds.length === 0 ? '数据层一个 dynamic 项都没有——是否整份数据被换掉'
        : missing.length ? `前端缺控件登记：${missing.join(', ')}`
          : `前端表里有数据层不存在的死条目：${extra.join(', ')}`
    );

    // ---- A2 / A3：Rust 分支与字段名 ----
    const dynBlockStart = rustOpt.indexOf('let is_dynamic');
    const branchIds = dynBlockStart < 0 ? [] :
      [...rustOpt.slice(dynBlockStart, dynBlockStart + 4000)
        .matchAll(/option_id == "([^"]+)"/g)].map((m) => m[1]);
    check(
      dynBlockStart >= 0 && branchIds.length > 0 && dynIds.every((i) => branchIds.includes(i)),
      `A2. 每个 dynamic id 在 Rust is_dynamic 分支有对应判断（Rust 侧 ${branchIds.join(', ') || '无'}）`,
      dynBlockStart < 0 ? 'optimizer.rs 里找不到 let is_dynamic' : ''
    );

    const runParams = objectLiteral(rustOpt, /pub struct RunParams/) || '';
    let fieldOk = true;
    const lines = [];
    for (const id of jsIds) {
      const block = objectLiteral(table, new RegExp(`^\\s*${id}: \\{`, 'm'));
      const pm = block && /paramKey: '([^']+)'/.exec(block);
      if (!pm) { fieldOk = false; lines.push(`${id}: 缺 paramKey`); continue; }
      const key = pm[1];
      // 该 id 的 Rust 分支体内必须读 p.<key>
      const idAt = rustOpt.indexOf(`option_id == "${id}"`, Math.max(dynBlockStart, 0));
      const body = idAt < 0 ? '' : rustOpt.slice(idAt, idAt + 1200);
      const readsOwn = new RegExp(`p\\.${key}\\b`).test(body);
      const declared = new RegExp(`(^|\\n)\\s*(pub )?${key}:\\s*Option<`).test(runParams);
      if (!readsOwn || !declared) {
        fieldOk = false;
        lines.push(`${id}: paramKey=${key} 但 ${!readsOwn ? 'Rust 分支没读 p.' + key : !declared ? 'RunParams 里没有 ' + key : ''}`);
      }
    }
    check(fieldOk, `A3. 前端 paramKey ⇄ Rust 读取字段 ⇄ RunParams 声明（${jsIds.length} 项）`,
      fieldOk ? '' : lines.join(' / '));

    // ---- A4：暂停天数上限两侧一致 ----
    const jsMax = /const WU_PAUSE_MAX_DAYS\s*=\s*(\d+)/.exec(jsOpt);
    const rustMax = /const WU_PAUSE_MAX_DAYS:\s*\w+\s*=\s*(\d+)/.exec(rustOpt);
    check(
      !!(jsMax && rustMax) && jsMax[1] === rustMax[1],
      `A4. WU_PAUSE_MAX_DAYS 两侧一致（JS ${jsMax ? jsMax[1] : '缺'} / Rust ${rustMax ? rustMax[1] : '缺'}）`,
      jsMax && rustMax && jsMax[1] !== rustMax[1] ? '只改一侧会让前端给出的天数被后端判成越界' : ''
    );
  }
}

// ---- A5：前端不得再按 dynamic 一刀切画内存下拉、批量不得发裸 {} ----
const staleSelectClass = (jsOpt.match(/opt-mem-select/g) || []).length;
const usesDynSelect = jsOpt.includes("querySelector('.opt-dyn-select')");
const usesDynParams = jsOpt.includes('dynamicParams(') && jsOpt.includes('const dyn = DYNAMIC_CONTROLS[o.id]');
const bareBatchParams = (jsOpt.match(/runOptionActive\(\{\}/g) || []).length;
const a5Pass = staleSelectClass === 0 && usesDynSelect && usesDynParams && bareBatchParams === 0;
check(
  a5Pass,
  `A5. 前端按 id 取控件/参数（.opt-mem-select ${staleSelectClass} 处、裸 {} 批量 ${bareBatchParams} 处）`,
  a5Pass ? '' // 全绿时不得再落进下面的原因链——原先收尾分支没有守卫，✓ 也会打印「仍在发空参数对象」
    : staleSelectClass ? '仍按单一内存类名找下拉'
      : !usesDynSelect ? '弹窗没有统一走 .opt-dyn-select'
        : !usesDynParams ? '没走 DYNAMIC_CONTROLS / dynamicParams 分派'
          : '批量入口仍在发空参数对象'
);

// ---------------------------------------------------------------------------
// A6 生效粒度侧表（BoosterX §B2）—— 三件事必须同时成立：
//   ① 表里的 id 都还在数据层目录里（项退役没清表 = 建议挂在空气上）
//   ② 表的集合与「按步骤触碰位置机械重算」的结果**逐条相等**。档位不是人肉判断
//      （本机不可能为了标注去真跑 114 项优化），所以它必须是可重算的派生量；
//      规则只有这一份实现，改规则=改这里，然后重出表。
//   ③ Rust 与 JS 的档位序表同键同序：前端「整批取最大值只提示一次」靠的就是这张表，
//      两侧键不一致会让某一档在前端被当成 0（= 静默不提示）。
// ---------------------------------------------------------------------------
{
  const SCOPE_REBOOT_CMD = /\b(fsutil|powercfg|DISM|schtasks|sc config|sc stop|net stop)\b/i;
  const SCOPE_REBOOT_KEY = /(HKLM|HKEY_LOCAL_MACHINE)\\SYSTEM\\CurrentControlSet\\(Services|Control|FileSystem)/i;
  const SCOPE_EXPLORER_KEY = /CurrentVersion\\Explorer|Policies\\Explorer|CurrentVersion\\Winlogon|ContextMenuHandlers|Control Panel\\Mouse|(HKCR|HKEY_CLASSES_ROOT)\\/i;
  const SCOPE_LABELS = ['none', 'explorer', 'reboot'];

  let scopeTbl = null;
  try {
    scopeTbl = JSON.parse(R('src-tauri/data/optimizer-scope.json')).scope;
  } catch (e) {
    check(false, 'A6 生效粒度侧表 optimizer-scope.json', `读不到或不是合法 JSON：${e.message.slice(0, 60)}`);
  }
  if (scopeTbl) {
    const opts = JSON.parse(dataJson);
    const known = new Set(opts.map((o) => o.id));
    const recomputed = new Map();
    for (const o of opts) {
      const hay = [...(o.steps || []), ...(o.restore || [])]
        .map((s) => `${s.cmd || ''} ${s.reg || ''} ${s.service || ''}`)
        .join(' ; ');
      let sc = 'none';
      if (SCOPE_REBOOT_CMD.test(hay) || SCOPE_REBOOT_KEY.test(hay)) sc = 'reboot';
      else if (SCOPE_EXPLORER_KEY.test(hay)) sc = 'explorer';
      if (sc !== 'none') recomputed.set(o.id, sc);
    }
    const stale = Object.keys(scopeTbl).filter((id) => !known.has(id));
    const badLabel = Object.entries(scopeTbl).filter(([, v]) => !SCOPE_LABELS.includes(v));
    const missing = [...recomputed.keys()].filter((id) => scopeTbl[id] !== recomputed.get(id));
    const extra = Object.keys(scopeTbl).filter((id) => recomputed.get(id) !== scopeTbl[id]);
    check(
      stale.length === 0 && badLabel.length === 0 && missing.length === 0 && extra.length === 0,
      `A6 生效粒度侧表 ⇄ 机械重算（表 ${Object.keys(scopeTbl).length} 条 / 重算 ${recomputed.size} 条）`,
      stale.length ? `表里有目录中不存在的 id：${stale.slice(0, 6).join(',')}`
        : badLabel.length ? `非法档位：${badLabel.slice(0, 4).map(([k, v]) => `${k}=${v}`).join(',')}`
          : missing.length ? `规则判定需要提示但表里没标：${missing.slice(0, 8).join(',')}`
            : extra.length ? `表里标了规则判不出该档位的项（新增提示面须同时改规则）：${extra.slice(0, 8).join(',')}`
              : ''
    );

    // ③ 两侧档位序表同键同序
    const rustBlock = (rustCatalog.match(/const SCOPE_RANK: &\[\(&str, u8\)\] = &\[[^\]]+\]/) || [''])[0];
    const jsBlock = (jsOpt.match(/const SCOPE_RANK = \{[^}]+\}/) || [''])[0];
    const rustKeys = [...rustBlock.matchAll(/\("([a-z_]+)",\s*(\d+)\)/g)].map((m) => `${m[1]}:${m[2]}`);
    const jsKeys = [...jsBlock.matchAll(/\b([a-z_]+)\s*:\s*(\d+)/g)].map((m) => `${m[1]}:${m[2]}`);
    check(
      rustKeys.length > 0 && jsKeys.length > 0 && JSON.stringify(rustKeys) === JSON.stringify(jsKeys),
      `A6b 档位序表 Rust ⇄ JS（${rustKeys.join(' ') || '取不到'}）`,
      rustKeys.length === 0 ? 'Rust 侧 SCOPE_RANK 表取不到（结构变了要同步改这里的正则）'
        : jsKeys.length === 0 ? '前端没有 SCOPE_RANK 常量（取最大粒度无处可依）'
          : JSON.stringify(rustKeys) !== JSON.stringify(jsKeys)
            ? `两侧档位键或序不一致：Rust [${rustKeys.join(',')}] vs JS [${jsKeys.join(',')}] —— 对不上的那档在前端按 0 处理，等于不提示`
            : ''
    );
  }
}

// ---------------------------------------------------------------------------
// A7 虚拟合集卡（2026-09-30 聚合层）—— 卡上的每个 runId 都是**真实执行目标**，
//   数据层一退役/改名，卡片就会「点开看得见、执行必失败」，与 v2-M10 同一失法形态。
//   四件事必须成立：① runId 真在目录里；② 一张卡至少两态（否则不叫聚合）；
//   ③ 同一真实项不被两张卡抢（展开会重复执行）；④ 整卡标注的档位不得低于任何成员的
//   最高档 —— 否则「整卡标 low、选中态是高危禁用」会绕过红色确认（AGENTS §3）。
// ---------------------------------------------------------------------------
{
  const lit = objectLiteral(jsOpt, /const VIRTUAL_GROUPS\s*=/);
  if (!lit) {
    check(false, 'A7. 虚拟合集卡 ⇄ 数据层', 'optimizer.js 里找不到 const VIRTUAL_GROUPS（聚合层被删了？那列表过滤与批量前置闸也该一并清）');
  } else if (!Array.isArray(options)) {
    check(false, 'A7. 虚拟合集卡 ⇄ 数据层', '数据层读不到，无法对拍');
  } else {
    const RISK_ORDER = { low: 0, medium: 1, high: 2 };
    const byId = new Map(options.map((o) => [o.id, o]));
    const cards = [...lit.matchAll(/^ {4}([A-Za-z0-9_]+): \{([\s\S]*?)^ {4}\}/gm)];
    const seenRun = new Map();
    const bad = [];
    for (const [, cardId, body] of cards) {
      const rm = /risk: '([a-z]+)'/.exec(body);
      const cardRank = rm ? RISK_ORDER[rm[1]] : undefined;
      if (cardRank === undefined) bad.push(`${cardId}: 缺 risk 或档位非法`);
      const runs = [...body.matchAll(/runId: '([^']+)'/g)].map((x) => x[1]);
      if (runs.length < 2) bad.push(`${cardId}: 只有 ${runs.length} 个选项，聚合至少两态`);
      let maxRank = -1;
      for (const r of runs) {
        const real = byId.get(r);
        if (!real) { bad.push(`${cardId}: runId=${r} 不在数据层目录里（点开必失败）`); continue; }
        if (seenRun.has(r)) bad.push(`${r}: 被 ${seenRun.get(r)} 与 ${cardId} 两张卡同时聚合`);
        seenRun.set(r, cardId);
        maxRank = Math.max(maxRank, RISK_ORDER[real.risk] ?? 0);
      }
      if (cardRank !== undefined && cardRank < maxRank) {
        bad.push(`${cardId}: 整卡标 ${rm[1]}，低于选中态最高档（会降档绕过红色确认）`);
      }
    }
    check(cards.length > 0 && bad.length === 0,
      `A7. 虚拟合集卡 ⇄ 数据层（${cards.length} 张卡 / 聚合 ${seenRun.size} 个真实项）`,
      bad.join(' / '));
  }
}

// ==================== A8. D0 三侧覆盖契约（R0-b 新增） ====================
//
// 为什么是「三侧」而不是报告 §5.2 设计的「只查 collect_checks」：
// v0.5.0 的 startType **执行链根本没读这个字段**（`grep -rn startType src-tauri/src/`
// 全仓 3 处命中全是注释），而报告判定它是「检测盲区 · 0.5 天」并写明
// 「执行链已走 Set-Service 解释器分支，是好的」。只查检测侧的门禁会把这个
// 真缺陷完整放过去 —— 门禁查的那一侧恰好是当时唯一「看起来有进展」的一侧。
//
// 三侧各自的判据在 Rust 源码里用唯一锚点标记（overview.rs 文件头
// D0-COVERAGE-ANCHOR 契约表声明了矩阵），门禁按锚点静态对拍。锚点被删或改名
// 同样判红 —— 契约不许被静默撤销。
{
  const CONTRACT_ANCHOR = 'D0-COVERAGE-ANCHOR';

  // ① 契约表本身必须存在且仍声明着三侧矩阵
  const hasContract = rustOverview.includes(CONTRACT_ANCHOR);
  check(hasContract,
    `A8.1 D0 契约锚点存在（overview.rs 头部三侧矩阵）`,
    hasContract ? '' : `${CONTRACT_ANCHOR} 缺失 —— 三侧覆盖契约被整体删除`);

  // ② 数据层实际用到的 step 字段全集
  const STEP_FIELDS = new Set();
  for (const o of options) {
    for (const s of (o.steps || [])) {
      for (const k of Object.keys(s)) STEP_FIELDS.add(k);
    }
  }

  // ③ 每侧的覆盖判据。执行/检测/备份三侧都按「锚点字符串出现次数」判，
  //    不做正则猜字段名 —— 猜字段名会在重构时静默失配。
  //
  //    UNCOVERED_BY_DESIGN：显式白名单，必须带理由。新增字段**不许**顺手加进来。
  const UNCOVERED_BY_DESIGN = {
    // 纯展示字段，无系统副作用，三侧都不需要消费它
    label: '纯展示文案，不参与写入/检测/备份',
    // 下面两项的「已生效判定」要按脚本语义推：一条 pwsh 步骤可能改 3 个键
    // 也可能只改 1 个，按字段名对拍会误红。要移出白名单必须先给出检测原语。
    pwsh: '按脚本语义判定（pssteps 解释器），字段名对拍会误红',
    cmd: '按命令语义判定（run_cmd_step + svc_names_writing_start），字段名对拍会误红',
  };

  const SIDE_ANCHORS = [
    ['执行', rustOpt, 'D0-EXEC-SIDE'],
    ['检测', rustOverview, 'D0-CHECK-SIDE'],
    ['备份', rustBackup, 'D0-BACKUP-SIDE'],
  ];

  // 每个「有副作用的字段」在各侧应当出现的标记。label 不参与（纯展示）。
  // service 的检测锚点与 startType 共用一行（同一个 svcStart 分支），
  // 这里按「该字段是否有任一锚点覆盖」判，不要求一一对应。
  //
  // 标记一律取**该侧源码里真实存在的字符串**：执行侧 reg 步是直接
  // `s.get("reg")` 消费（不经独立解析函数），所以判据不能用函数名。
  const FIELD_REQUIRED_SIDES = {
    reg: { 执行: 'get("reg")', 检测: 'kind: "reg"', 备份: 'parse_reg_targets' },
    service: { 执行: 'service_stop_pub', 检测: 'kind: "svc"', 备份: 'svc_start_target' },
    startType: { 执行: 'D0-EXEC-SIDE', 检测: 'D0-CHECK-SIDE', 备份: 'D0-BACKUP-SIDE' },
    disable: { 执行: 'want_disable', 检测: 'kind: "svc"', 备份: 'has_disable' },
  };

  const uncovered = [];
  for (const f of STEP_FIELDS) {
    if (f in UNCOVERED_BY_DESIGN) continue;
    const need = FIELD_REQUIRED_SIDES[f];
    if (!need) {
      uncovered.push(`未知 step 字段「${f}」：既不在 UNCOVERED_BY_DESIGN 白名单，也没有对应检测原语 —— 新增字段必须同时给出三侧覆盖`);
      continue;
    }
    for (const [sideName] of SIDE_ANCHORS) {
      if (!(sideName in need)) continue;
      if (!need[sideName]) continue;
      const src = sideName === '执行' ? rustOpt : sideName === '检测' ? rustOverview : rustBackup;
      if (!src.includes(need[sideName])) {
        uncovered.push(`「${f}」在${sideName}侧无覆盖标记（期望出现 \`${need[sideName]}\`）`);
      }
    }
  }

  const sideList = SIDE_ANCHORS.map(([n]) => n).join(' / ');
  check(uncovered.length === 0,
    `A8.2 step 字段三侧覆盖（${STEP_FIELDS.size} 个字段 / ${sideList}）`,
    uncovered.join(' | '));

  // ④ 三侧锚点在各自源码里必须真的存在（防止 FIELD_REQUIRED_SIDES 写了
  //    一个源码里已经没有的标记，门禁却因为「字段集为空」而空绿）
  const missingAnchors = SIDE_ANCHORS
    .filter(([, src, marker]) => !src.includes(marker))
    .map(([n, , marker]) => `${n}侧锚点 ${marker} 不在源码里`);
  check(missingAnchors.length === 0,
    'A8.3 三侧锚点均落在对应源码中',
    missingAnchors.join(' | '));

  // ⑤ 白名单不得为空转：白名单字段必须真的在数据层出现，否则是僵尸白名单
  const zombie = Object.keys(UNCOVERED_BY_DESIGN)
    .filter((f) => !STEP_FIELDS.has(f));
  check(zombie.length === 0,
    'A8.4 白名单无僵尸条目（每条都对应真实存在的字段）',
    zombie.length ? `白名单里的 ${zombie.join(',')} 在数据层已不存在，应删除` : '');

  // ⑥ 覆盖率棘轮：数据层出现新字段时，三侧覆盖必须跟上。
  //    这条是本门禁的真正价值 —— v0.5.0 那 4 个盲区就是「扩库忘了扩检测器」。
  console.log(`   · D0 三侧覆盖矩阵：${[...STEP_FIELDS].sort().join(', ')}`);
}

console.log(`\n${fail === 0 ? '门禁通过' : `${fail} 项未通过`}`);
process.exit(fail === 0 ? 0 : 1);
