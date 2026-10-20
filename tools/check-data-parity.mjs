// check-data-parity.mjs —— 「派生数据 ⇄ 上游真源」双源对拍门禁（审查 v2-M17）
//
// 为什么需要它：本仓有 6 个 `src-tauri/data/*.json` 与 1 个 `src/scripts/*.generated.js`，
// 全部是**派生物**，但仓库里既没有再生成脚本、也没有任何一条断言（v2-M17 实测
// `grep -rn "data/" tools/*.mjs` = 0 命中）。附录 G 当时逐条深比对是「零漂移」——
// 可「一致」和「有断言守着」是两件事：前者会漂，且漂移的表现是**静默**：
//   · 规则库只改了 JSON ⇒ 兜底副本停在旧 71 项，IPC 异常时界面展示过期分类且不报错
//     （`cleanup.js:55` 直接吃 FALLBACK）；
//   · 优化项只改了前端 OPTIONS ⇒ JSON 停在旧字段，Rust 侧按旧值下发步骤；
//   · 受保护路径基线重拷了 vendor 却没重跑夹具 ⇒ Rust 测的是过期期望值，看着绿其实在测旧口径。
// 本门禁把附录 G 的四条对拍固化下来，四条都是**纯内存重算**（不写盘、不起 pwsh、不开窗口）。
// v0.4.9 RAINZ 对标 §3.1 曾加 P5：蓝屏码库 `tools/bugcheck-codes.source.mjs` ⇄ `data/*.json`；
// 2026-10-12 随「体检结论」全链路退役移除（bsod.rs / 生成器 / data json 一并拆除）。
//
// 用法：node tools/check-data-parity.mjs [--strict] [--verbose]
//   --strict   与默认行为等价（本门禁没有「可选层」，五项源全在仓库内，读不到即判红）；
//              接受该 flag 只为和 §4 其它门禁统一写法
//   --verbose  额外打印每条漂移的字段名（默认只打印前若干条）
// 退出码：0 = 各组逐条一致；1 = 任一组漂移或源不可读

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

import { ORIGIN, REPO_ROOT } from './ps-origin.mjs';
import { buildParityFixture, FIXTURE_PATH } from './gen-protect-parity.mjs';

const VERBOSE = process.argv.includes('--verbose');
const require = createRequire(import.meta.url);

// P4b 的源表（ESM）：动态导入，导入失败记下来由该组判红，不让整个门禁崩栈
let WINERROR_CODES = null;
let winerrorImportWhy = '';
try {
  ({ WINERROR_CODES } = await import('./winerror-codes.source.mjs'));
} catch (e) {
  winerrorImportWhy = `源导入失败：${e.message.slice(0, 120)}`;
}

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
  return ok;
};

/** 读 JSON；读不到/解析失败直接判红（绝不「跳过即通过」） */
function readJson(rel) {
  const abs = join(REPO_ROOT, rel);
  if (!existsSync(abs)) { check(false, `读取 ${rel}`, '文件不存在'); return null; }
  try { return JSON.parse(readFileSync(abs, 'utf8')); }
  catch (e) { check(false, `读取 ${rel}`, e.message.slice(0, 120)); return null; }
}

/** 逐条目、逐字段的深比对（顺序敏感：JSON 里条目顺序本身是要钉的语义） */
function diffArrays(a, b, labelA, labelB) {
  const out = [];
  if (!Array.isArray(a) || !Array.isArray(b)) {
    return [`${labelA}/${labelB} 不是数组（结构变了？labelA=${Array.isArray(a)} labelB=${Array.isArray(b)}）`];
  }
  if (a.length !== b.length) {
    out.push(`条目数不同：${labelA} ${a.length} / ${labelB} ${b.length}`);
  }
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const ai = a[i] ?? {};
    const bi = b[i] ?? {};
    const id = ai.id ?? bi.id ?? `#${i}`;
    if (ai.id !== bi.id) out.push(`第 ${i} 位 id 不同（顺序漂移）：${labelA}=${ai.id} / ${labelB}=${bi.id}`);
    const keys = new Set([...Object.keys(ai), ...Object.keys(bi)]);
    for (const k of keys) {
      if (JSON.stringify(ai[k]) !== JSON.stringify(bi[k])) {
        const va = VERBOSE ? JSON.stringify(ai[k]) : JSON.stringify(ai[k] ?? null).slice(0, 40);
        const vb = VERBOSE ? JSON.stringify(bi[k]) : JSON.stringify(bi[k] ?? null).slice(0, 40);
        out.push(`${id}.${k}: ${labelA}=${va} / ${labelB}=${vb}`);
      }
    }
  }
  return out;
}
const show = (drift) => drift.length ? `${drift.length} 处漂移：${drift.slice(0, VERBOSE ? 99 : 5).join(' | ')}` : '';

console.log('=== 派生数据 ⇄ 上游真源 双源对拍门禁（v2-M17）===\n');

// ---------------------------------------------------------------------------
// P1 `data/cleanup-rules.json` ⇄ `src/scripts/cleanup-fallback.generated.js`
// 兜底副本是 IPC 异常时界面唯一能看到的数据，漂了就是「静默展示过期分类」。
// 比对取 JSON.stringify 全等：键序、`_sig`、`rulesVersion` 一并钉住
// （`_sig` 是规则库验签摘要，副本里停着旧签名等于把「签名对不上」也一起过期掉）。
// ---------------------------------------------------------------------------
const RULES_REL = join('src-tauri', 'data', 'cleanup-rules.json');
const FALLBACK_REL = join('src', 'scripts', 'cleanup-fallback.generated.js');
{
  const rules = readJson(RULES_REL);
  const fbPath = join(REPO_ROOT, FALLBACK_REL);
  let parsed = null;
  let why = '';
  if (rules && existsSync(fbPath)) {
    const text = readFileSync(fbPath, 'utf8');
    // 生成物的形状是 root.CLEANUP_RULES_FALLBACK = JSON.parse("<转义后的 JSON 文本>")；
    // 那段字面量是合法的 JSON 字符串字面量，所以可以「先解字面量、再解其中的 JSON」，
    // 不必复刻生成器的转义规则（复刻一份转义规则本身就是下一个漂移点）。
    const at = text.indexOf('JSON.parse("');
    const lit = at >= 0 ? text.slice(at + 'JSON.parse('.length).match(/^"(?:[^"\\]|\\.)*"/) : null;
    if (!lit) why = '没找到 JSON.parse("<字面量>") 形状，生成方式变了？';
    else {
      try { parsed = JSON.parse(JSON.parse(lit[0])); } catch (e) { why = `字面量解析失败：${e.message.slice(0, 80)}`; }
    }
  } else if (!existsSync(fbPath)) why = '兜底副本文件不存在';

  if (!rules || !parsed) {
    check(false, 'P1 cleanup-rules.json ⇄ cleanup-fallback.generated.js', why || '源不可读');
  } else {
    const same = JSON.stringify(parsed) === JSON.stringify(rules);
    let items = 0;
    for (const g of (rules.groups || [])) for (const sg of (g.subGroups || [])) items += (sg.items || []).length;
    check(same && items > 0,
      `P1 清理规则库 ⇄ 前端兜底副本（组 ${rules.groups?.length ?? '?'} / 项 ${items}，含 _sig 与 rulesVersion ${rules.rulesVersion}）`,
      same ? '' : 'JSON.stringify 不等（内容或键序已漂移；改规则 JSON 后需重新生成副本）');
  }
}

// ---------------------------------------------------------------------------
// P2 `vendor/…/optimizer-scripts.js OPTIONS` ⇄ `data/optimizer-runtime.json`
// 上游真源在 vendor 基线里（§5.12：只读基线）。这里是「基线重拷了、派生 JSON 没重出」
// 的唯一机器拦截点。字段级 + 顺序级都要钉：Rust 侧按 id 取项，但前端分组展示按数组序。
// ---------------------------------------------------------------------------
{
  const optSrc = require(`${ORIGIN}/src/scripts-powershell/optimizer-scripts.js`);
  const json = readJson(join('src-tauri', 'data', 'optimizer-runtime.json'));
  const srcArr = Array.isArray(optSrc?.OPTIONS) ? optSrc.OPTIONS : null;
  if (!srcArr || !json) {
    check(false, 'P2 optimizer OPTIONS ⇄ optimizer-runtime.json', `源不可读（OPTIONS=${!!srcArr}）`);
  } else {
    const drift = diffArrays(srcArr, json, 'OPTIONS', 'JSON');
    const groups = new Set(srcArr.map(o => o.group)).size;
    check(drift.length === 0,
      `P2 优化项 OPTIONS ⇄ 运行时 JSON（${srcArr.length} 项 / ${groups} 组，逐字段）`,
      show(drift));
  }
}

// ---------------------------------------------------------------------------
// P3 `vendor/…/maintenance-scripts.js list()` ⇄ `data/maintenance-tasks.json`
// 任务表还带 categories：它必须与上游 CATEGORY_ORDER 同序（界面按它分组）。
// ---------------------------------------------------------------------------
{
  const mm = require(`${ORIGIN}/src/scripts-powershell/maintenance-scripts.js`);
  const json = readJson(join('src-tauri', 'data', 'maintenance-tasks.json'));
  const srcArr = typeof mm?.list === 'function' ? mm.list() : null;
  if (!Array.isArray(srcArr) || !json) {
    check(false, 'P3 maintenance list() ⇄ maintenance-tasks.json', '源不可读');
  } else {
    const drift = diffArrays(srcArr, json.tasks, 'list()', 'JSON');
    check(drift.length === 0, `P3 维护任务 list() ⇄ 任务表 JSON（${srcArr.length} 项）`, show(drift));
    const catSame = JSON.stringify(mm.CATEGORY_ORDER) === JSON.stringify(json.categories);
    check(catSame, `P3b 维护任务分组顺序 ⇄ CATEGORY_ORDER（${mm.CATEGORY_ORDER?.length ?? '?'} 组）`,
      catSame ? '' : `上游 ${JSON.stringify(mm.CATEGORY_ORDER)} / JSON ${JSON.stringify(json.categories)}`);
  }
}

// ---------------------------------------------------------------------------
// P4 `tools/fixtures/protect-parity.json` ⇄ `vendor/…/ps-protect-path.js`
// 附录 G 已注明：`protect.rs` 那条 `matches_js_authority` 抓的是 **Rust 侧口径漂移**，
// 抓不到「基线重拷了、夹具没重跑」——夹具是入库快照，期望值本身过期时 Rust 测的是旧口径。
// 这里用生成器的同一个函数在内存里重算一遍与落盘夹具比（就是那条缺的腿）；
// 分档理由见块内注释（夹具冻的是出生机的用户目录）。
// ---------------------------------------------------------------------------
{
  let committed = null;
  try { committed = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')); }
  catch (e) { check(false, 'P4 protect-parity 夹具 ⇄ JS 权威实现', `读不到：${e.message.slice(0, 80)}`); }
  if (committed) {
    // T1c-M07（v7.2 C09）：runPs 默认 false ⇒ 本门禁（MUST_RUN）不再真实 spawn
    // powershell.exe。内存重算不含 psVectors，比对前两边都剥掉该字段——
    // psVectors 的口径由「显式重生成路径」（node tools/gen-protect-parity.mjs）
    // 负责，它的 PS↔JS 一致性在生成时当场断言并打印。
    const fresh = buildParityFixture();
    const stripPs = (f) => { const c = { ...f }; delete c.psVectors; return c; };
    const freshNoPs = stripPs(fresh);
    const committedNoPs = stripPs(committed);
    // 夹具冻的是**出生机**的用户目录（JS 权威实现的默认清单读 process.env，
    // `protect.rs` 那条用例也读自己进程的 env）—— 实测把 USERPROFILE 换成别的值，
    // `cargo test --lib protect::` 立刻红。所以这里分两档，既不放纵漂移也不误报：
    //   · 本机就是出生机 ⇒ 整串逐字节比（最强，基线重拷没重跑夹具必红）
    //   · 本机不是出生机 ⇒ 只比「机器中立那半」（不含 C:\Users\ 的条目与向量判定），
    //     并把用户目录那一半显式标为未比对（不静默、不判绿充数）
    const homeOf = (o) => {
      const m = JSON.stringify(o).match(/users[\\/]+([^\s"'\\/]+)/i);
      return m ? m[1].toLowerCase() : '';
    };
    const localHome = homeOf({ p: process.env.USERPROFILE || '' });
    const fixtureHome = homeOf(committed);
    const isBirthMachine = !!localHome && localHome === fixtureHome;
    // 「机器中立」判据：路径里不含用户目录段（users\<name> 之后的部分也可能带用户相关目录名，
    // 所以整条一起排除，宁可少判也不误判）
    const neutral = (v) => !/users[\\/]/i.test(typeof v === 'string' ? v : JSON.stringify(v));
    const detail = [];
    if (isBirthMachine) {
      if (JSON.stringify(freshNoPs) !== JSON.stringify(committedNoPs)) detail.push('整串不一致 ⇒ 基线被重拷过或夹具被手改');
    } else {
      const pick = (f) => ({
        roots: Object.fromEntries(Object.entries(f.roots).map(([k, v]) => [k, v.filter(neutral)])),
        vectors: f.vectors.filter(v => neutral(v.p)).map(v => `${v.p}=${v.protected}`).sort(),
      });
      const a = JSON.stringify(pick(freshNoPs));
      const b = JSON.stringify(pick(committedNoPs));
      if (a !== b) detail.push('机器中立部分不一致 ⇒ 基线口径变了');
    }
    const denied = fresh.vectors.filter(v => v.protected).length;
    check(detail.length === 0,
      `P4 受保护路径夹具 ⇄ JS 权威现算（向量 ${fresh.vectors.length}：判拒 ${denied} / 放行 ${fresh.vectors.length - denied}；`
      + `${isBirthMachine ? `本机即夹具出生机，整串比对` : `出生机=${fixtureHome || '?'} ≠ 本机=${localHome || '?'}，只比机器中立部分`}）`,
      detail.join('；') || (isBirthMachine ? '' :
        '※ 用户目录相关条目未比对（换机后 `cargo test --lib protect::` 同样会红，需先重跑生成器）'),
    );
    if (!isBirthMachine) {
      console.log('  · 想让夹具机器中立，得先让 protect.rs 那条用例把「默认段」也吃夹具输入（见 gen-protect-parity.mjs 顶部说明）。');
    }
  }
}

// P5 蓝屏码库对拍组已于 2026-10-12 随「体检结论」全链路退役移除
// （bsod.rs / bugcheck-codes.source.mjs / gen / data json / check-bugcheck-codes 一并拆除）。

// ---------------------------------------------------------------------------
// P4b `tools/winerror-codes.source.mjs` ⇄ `data/winerror-codes.json`
// 维护错误码人话表（P1-A / Dism++ D-04b，2026-10-16）：源是人工策展表（含 curator
// 专用的 tasks 元数据），JSON 是 Rust 编译期 include_str! 嵌入的运行期数据。
// 抓两件事：改了源忘重生成、手改生成物。投影口径与 gen-winerror-codes.mjs 一致——
// tasks 无运行期消费者故不落 JSON；顺序敏感（注解按表序输出）。
// ---------------------------------------------------------------------------
{
  const json = readJson(join('src-tauri', 'data', 'winerror-codes.json'));
  const projected = Array.isArray(WINERROR_CODES)
    ? WINERROR_CODES.map((c) => ({ code: c.code, title: c.title, detail: c.detail }))
    : null;
  if (!projected || !json || !Array.isArray(json.codes)) {
    check(false, 'P4b winerror source ⇄ winerror-codes.json', winerrorImportWhy || '源或生成物不可读');
  } else {
    const drift = diffArrays(projected, json.codes, 'source', 'JSON');
    check(drift.length === 0,
      `P4b 维护错误码表 source ⇄ JSON（${json.codes.length} 码，逐字段）`,
      show(drift));
  }
}


// ---------------------------------------------------------------------------
// 第 4.5 组（T1b-K05，v7.2 C09）：「无对拍对象」从报告句升格为断言。
// 旧实现是一段 console.log——两件文件被整体删除后门禁仍 exit 0（组 5 地板
// checkedNames<20 也拦不住：实算 37 个点名里这两件各贡献 1 个，删掉仍 35≥20）。
// 现在改成真断言：① 件必须存在；② 「没有对拍」本身必须逐件登记理由（登记式
// 棘轮，件数进断言对象计数）——「无人守护」必须每次都被看见，且被机器看见。
// ---------------------------------------------------------------------------
const NO_PARITY_REGISTRY = [
  {
    rel: join('src-tauri', 'data', 'reg-ownership.json'),
    why: '无 Rust 消费方（现算 grep 0 命中）、暂无第二真源可对拍；登记 = 让「无人守护」可见',
  },
  {
    rel: join('src-tauri', 'data', 'retired-optimizations.json'),
    why: '退役目录：唯一消费方 catalog.rs include_str!（只读），无对拍上游',
  },
];
{
  const noParityProblems = [];
  for (const { rel, why } of NO_PARITY_REGISTRY) {
    const abs = join(REPO_ROOT, rel);
    if (!existsSync(abs)) {
      noParityProblems.push(`${rel.replace(/\\/g, '/')} 缺失（登记理由：${why}）——登记还在、文件没了 = 被人删了没走处置`);
      continue;
    }
    try {
      const j = JSON.parse(readFileSync(abs, 'utf8'));
      const shape = Array.isArray(j) ? `${j.length} 条` : `键 ${Object.keys(j).length}`;
      console.log(`  · 无对拍对象（已登记）：${rel.replace(/\\/g, '/')}（${shape}）`);
    } catch (e) {
      noParityProblems.push(`${rel.replace(/\\/g, '/')} JSON 损坏：${e.message.slice(0, 80)}`);
    }
  }
  const regRels = new Set(NO_PARITY_REGISTRY.map((r) => r.rel.replace(/\\/g, '/')));
  // 「已归属」清单（显式登记，不是后缀排除）：这些文件各自有对拍组或专属门禁。
  // 新增 data/*.json 既不在此表、也不在 NO_PARITY_REGISTRY ⇒ 红（R-D 的三档处置纪律）。
  const PARITY_COVERED = new Set([
    'cleanup-postactions.json', 'cleanup-rules.json', 'item-intro.json',
    'maintenance-tasks.json', 'optimizer-defaults.json', 'optimizer-groups.json',
    'optimizer-nara-panel.json', 'optimizer-privacy-panel.json', 'optimizer-provenance.json',
    'optimizer-runtime.json', 'optimizer-runtime.json.sig.json', 'optimizer-scope.json',
    'optimizer-security.json', 'optimizer-subitems.json', 'optimizer-writes.json',
    'uninstall-residue-rules.json', 'winerror-codes.json',
  ]);
  const dataDir = join(REPO_ROOT, 'src-tauri', 'data');
  const unregistered = readdirSync(dataDir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => `src-tauri/data/${f}`)
    .filter((rel) => !regRels.has(rel) && !PARITY_COVERED.has(rel.split('/').pop()));
  if (unregistered.length > 0) {
    noParityProblems.push(`src-tauri/data/ 出现未登记的数据文件（无对拍对象清单没跟上）：${unregistered.join('、')}`);
  }
  check(
    noParityProblems.length === 0,
    `4.5. 无对拍对象逐件登记（${NO_PARITY_REGISTRY.length} 件，缺失/损坏/漏登记即红）`,
    noParityProblems.join('；') || '两件在盘、理由在册',
  );
}

// ==================== 第 5 组：_comment 点名的仓内坐标必须存活 ====================
// v5 批次 9（门禁候选 8；v4 D1-M03 + 本轮真死 1 条）：数据 JSON 的 _comment 是
// 下一任维护者的导航——retired-optimizations.json 曾把真实读取方写成已删除的
// optimizer.rs（真死，2026-10-13 修真）、reg-ownership.json 曾引用不存在的
// check-reg-ownership.js（v2-L4P-42 勘误）。判据：_comment 中 `*.rs|.mjs|.json|
// .js|.ps1` 形态的文件名按 basename 与全仓索引对拍，无任何盘上命中即红。
{
  const { readdirSync, statSync } = await import('node:fs');
  const pathMod = await import('node:path');
  const nameIndex = new Map();
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'target' || e.name === 'node_modules' || e.name.startsWith('.')) continue;
      const p = pathMod.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else {
        const arr = nameIndex.get(e.name) || [];
        arr.push(p);
        nameIndex.set(e.name, arr);
      }
    }
  };
  walk(REPO_ROOT);
  // 运行期生成文件（%APPDATA%，不落仓）：_comment 提及它们是讲数据来源，不是仓内坐标
  const RUNTIME_GENERATED = new Set(['optimizer-backups.json', 'optimizer-runtime.json.sig.json']);
  const dataDir = join(REPO_ROOT, 'src-tauri', 'data');
  const extRe = /\b([\w-]+(?:\.[\w-]+)*\.(?:rs|mjs|json|js|ps1))\b/g;
  const dead = [];
  let checkedNames = 0;
  for (const f of readdirSync(dataDir)) {
    if (!f.endsWith('.json')) continue;
    // T1b-M01：JSON.parse 套 try——损坏件必须以判红点名，不许拿 node 堆栈当失败输出
    let v;
    try {
      v = JSON.parse(readFileSync(pathMod.join(dataDir, f), 'utf8'));
    } catch (e) {
      fail++;
      console.error(`✗ 5. _comment 坐标存活：${f} JSON 损坏（${e.message.slice(0, 80)}）`);
      continue;
    }
    const comment = v && typeof v === 'object' && !Array.isArray(v) ? v._comment : null;
    if (typeof comment !== 'string') continue;
    for (const m of comment.matchAll(extRe)) {
      const base = pathMod.basename(m[1]);
      if (RUNTIME_GENERATED.has(base)) continue;
      checkedNames++;
      if (!nameIndex.has(base)) dead.push(`${f}: ${m[1]}`);
    }
  }
  if (checkedNames < 20) fail++, console.error(`✗ 5. _comment 坐标存活：只解析到 ${checkedNames} 个点名（< 20）⇒ 语料失明`);
  else if (dead.length > 0) fail++, console.error(`✗ 5. _comment 点名的仓内坐标不存在（判据见上）：${dead.join('；')}`);
  else console.log(`✓ 5. _comment 坐标存活：${checkedNames} 个点名全部落盘`);
}

// ==================== 第 6 组：备份根 ⇄ prune 过滤器形状覆盖 ====================
// v5 批次 9（门禁候选 7 = D1-M04/M05 门禁化）：「备份保留上限覆盖全部备份类目录」
// 不是描述句——每个有写入的备份根都必须有对应 prune 出口且过滤器形状能命中根的
// 实际内容。D1-M04（pagefile 全 .json 而 prune_backups 只数 .reg ⇒ 上限恒空转）
// 与 D1-M05（startup-backup/deleted 零 prune 无界）就是缺口实例；修复后按
// {what, file, token} 登记钉住（登记式棘轮，check-native-hygiene N6 同款）。
{
  const PRUNE_COVERAGE = [
    { what: 'cleanup-reg-backup（.reg+封条）', file: 'src-tauri/src/engine/native/cleanup.rs', token: 'prune_backups(' },
    { what: 'uninstall-reg-backup（.reg+封条）', file: 'src-tauri/src/commands/uninstall/residue.rs', token: 'prune_backups(' },
    { what: 'peripheral-backup', file: 'src-tauri/src/commands/peripheral.rs', token: 'prune_backups(' },
    { what: 'cleanup-files-backup（目录树）', file: 'src-tauri/src/engine/native/cleanup.rs', token: 'prune_file_backups' },
    { what: 'fileclean-backup（manifest 台账）', file: 'src-tauri/src/engine/native/cleanup.rs', token: 'prune_file_backups' },
    { what: 'pagefile-backups（<ts>.json）', file: 'src-tauri/src/engine/native/syspanel.rs', token: 'prune_stamped_files' },
    { what: 'power-plan-backups（G-04 隐藏高性能备份 <ts>.powrplan）', file: 'src-tauri/src/engine/native/syspanel.rs', token: 'prune_stamped_files' },
    { what: 'startup-backup/deleted（{ts}_*）', file: 'src-tauri/src/engine/native/startup.rs', token: 'prune_stamped_files' },
  ];
  const gaps = [];
  for (const c of PRUNE_COVERAGE) {
    const p = join(REPO_ROOT, c.file);
    if (!existsSync(p) || !readFileSync(p, 'utf8').includes(c.token)) {
      gaps.push(`${c.what} ⇒ ${c.file} 缺 ${c.token}`);
    }
  }
  if (gaps.length > 0) fail++, console.error(`✗ 6. 备份根 prune 覆盖面缺口：${gaps.join('；')}`);
  else console.log(`✓ 6. 备份根 prune 覆盖面：${PRUNE_COVERAGE.length} 个备份根都有对应裁剪出口`);
}

// T1b-M01：汇总行必须在**全部判定组之后**（旧实现在第 5/6 组之前就打「全部一致」，
// 实跑输出顺序可见）。这是末尾唯一的汇总出口。
console.log(`\n${fail === 0 ? '✓ 数据对拍各组全部一致' : `${fail} 项未通过`}`);

process.exit(fail === 0 ? 0 : 1);
