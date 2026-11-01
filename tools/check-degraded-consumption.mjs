'use strict';
// tools/check-degraded-consumption.mjs —— 后端已分态的 `degraded`，前端不得折回单态（B0 门禁）
//
// 出处：2026-10-24 全仓重审 F4a2-K02（🔴）与族 F-2 / A1。
// 形状：后端为「Corrupt ≠ Absent」专门回传 `degraded`（`src-tauri/src/commands/paths.rs:102-104` 的 A1-M12
// 注释就是这条的出处），前端只看 `success` + `data` ⇒ 配置损坏被当成「这台机器从没扫过」，
// 1.5 秒后自动重扫并把猜测值逐键写回真源，而该真源被清理链原样采纳并永久删除。
// A1 现算：后端 9 个命令文件发射 `degraded`，前端只有 3 个文件消费 ⇒ 这是系统性缺口，
// 不是一次笔误。所以钉成机检：谁新发一个 `degraded` 而前端不接，本门禁当场判红。
//
// 三态登记表（本门禁的唯一判据面）：
//   consumed —— 前端确实读这个位；`anchor` 必须在点名文件里命中 ≥1 次；
//   pending  —— 已排进批次但**尚未**兑现；`anchor` 命中即判红（逼你在修完当天回收条目）；
//   exempt   —— 结构上没有前端消费方（例如只由原生侧或无头 CLI 用）；理由 ≥8 字。
// 双向咬合：盘上新增发射而表里没有 ⇒ 红；表里有而盘上没有 ⇒ 红。
//
// 用法：node tools/check-degraded-consumption.mjs

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gate } from './lib/gate.mjs';
import { blankNonCode, splitFunctions, lineAt } from './lib/src-scan.mjs';

const ROOT = process.cwd();
const SRC_RS = join(ROOT, 'src-tauri', 'src');
const MIN_EMITTERS = 5; // 对象地板：低于此数说明命令解析失效，不是「大家都接好了」

// ⚠ 命令名与发射点是**盘上现算**得到的（首版按 v1 方案里猜的名字写表，7 条全部对不上）：
//   本判据（标识符形态）射程内是这 7 条（`appearance_*` 两条）。T1e-L01 更正旧注释：
//   `startup_scan`（startup.rs）、`overview_hardware`（overview.rs）与 helper 形态的
//   `power_plan_state` **也发射 degraded**，但它们是 `"degraded": true` 字面量 / helper
//   形态，落在本判据射程外（根因与修法见 T1e-M01，该条属中危、本批未修）。
//   consumed 行必须给可核锚点；pending 行给「修好后会出现的消费点文本」作锚点 ——
//   锚点一旦命中即判红，逼回收条目（T1e-L02：无锚点 pending 会让这条腿对它们永久失效）。
const TABLE = [
  { cmd: 'paths_load', status: 'consumed', anchor: { file: 'src/scripts/pathbinding.js', text: 'resp.degraded === true' } },
  { cmd: 'settings_load', status: 'consumed', anchor: { file: 'src/scripts/models-window.js', text: 'resp.degraded === true' } },
  { cmd: 'fileclean_scan', status: 'pending', batch: 'B3/P1-6', anchor: { file: 'src/scripts/cleanup.js', text: 'degraded === true' }, reason: 'A1 命中：未接（展示层假绿族）' },
  { cmd: 'appearance_get_material', status: 'pending', batch: 'B3/P1-6', anchor: { file: 'src/scripts/window-material.js', text: 'degraded === true' }, reason: '材质面未见消费方：window-material.js 现算无 degraded' },
  { cmd: 'optimizer_state_overview', status: 'pending', batch: 'B3/P1-6A', anchor: { file: 'src/scripts/optimizer.js', text: 'degraded === true' }, reason: '与 R3b-M10 同一条链（目录不可用 vs 空目录）' },
  { cmd: 'appearance_get_prefs', status: 'consumed', anchor: { file: 'src/scripts/pathbinding-appearance.js', text: 'resp.degraded === true' } },
  { cmd: 'uninstall_pending_list', status: 'consumed', anchor: { file: 'src/scripts/residue-window.js', text: 'data.degraded' } },
];

const walkRs = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walkRs(join(dir, e.name)) : (e.name.endsWith('.rs') ? [join(dir, e.name)] : []));

/**
 * 锚点命中判定：只认**可执行代码**（T1e-L10）。
 *
 * 为什么不用 `blankNonCode`：它的模板分支对「模板里套 ${…} 再套模板」失准 —— 实测
 * `src/scripts/models-window.js` 从第一个 `return \`` 之后整段被当成字符串抹掉，该文件的
 * consumed 锚点会永远判红（假红比漏报更糟）。所以本件自带一份保守剥除：
 *   块注释（含不以 `*` 开头的中间行）、行注释、单/双引号字符串；
 * 模板字符串不抹 —— 现有锚点都不在模板字面量里，保守方向是「宁可判红」（见下方对照）。
 * 旧实现只剥整行注释：`console.log('resp.degraded === true')` 或块注释中间行都能顶账。
 */
const codeOnly = (src) => src
  .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
  .replace(/(^|[^:"'])\/\/[^\n]*/g, (m, keep) => keep + ' '.repeat(m.length - keep.length))
  .replace(/'(?:\\.|[^'\\\n])*'/g, (m) => ' '.repeat(m.length))
  .replace(/"(?:\\.|[^"\\\n])*"/g, (m) => ' '.repeat(m.length));
const anchorHitIn = (src, text) => codeOnly(src).includes(text);
const anchorHit = (abs, text) => existsSync(abs) && anchorHitIn(readFileSync(abs, 'utf8'), text);

const g = gate(import.meta.url);
{
  // 正向对照：真实代码命中；块注释中间行 / 字符串字面量顶账必须拒绝。
  const real = 'if (resp && resp.degraded === true) { recover(); }';
  const comment = '/* 说明：\n   resp.degraded === true\n*/\nconst x = 1;';
  const logString = 'console.log("resp.degraded === true");';
  const ok = anchorHitIn(real, 'resp.degraded === true')
    && !anchorHitIn(comment, 'resp.degraded === true')
    && !anchorHitIn(logString, 'resp.degraded === true');
  if (!ok) g.fail('锚点判定器正向对照失败：真实代码未命中，或注释/字符串顶账未被拒绝');
  else g.ok('锚点判定器对照：真实代码命中；块注释中间行与字符串字面量不顶账');
}

// T1e-L09：SKIP 必须**短路** —— `g.finish()` 在 0 失败时不退出，继续 walkRs 会抛 ENOENT
// 栈，把「显式 SKIP」退化成崩溃（AGENTS §5 要求缺输入给 SKIP，不许 ENOENT 崩）。
if (!g.skipUnlessPresent(join(SRC_RS, 'engine', 'protect.rs'), 'src-tauri/src（本门禁的判定对象）')) { g.finish(); process.exit(0); }

const emitters = new Map(); // cmd → {rel, line}
for (const abs of walkRs(SRC_RS)) {
  const code = readFileSync(abs, 'utf8');
  if (!code.includes('"degraded"') && !/\bdegraded\b/.test(code)) continue;
  const blanked = blankNonCode(code, 'rs');
  for (const f of splitFunctions(code, 'rs')) {
    const head = blanked.slice(Math.max(0, f.start - 600), f.start);
    if (!/#\[tauri::command\]/.test(head)) continue;
    const body = blanked.slice(f.bodyStart, f.end - 1);
    // ⚠ 判据必须作用在**标识符**上：`blankNonCode` 会把 `"degraded"` 这个字符串字面量一起抹掉，
    // 所以在抹空后的文本里搜 `"degraded"` 永远搜不到（首版就因此数出 0 个发射命令）。
    // 真实代码里 `degraded` 一定以变量/字段值形态出现（`json!({ "degraded": degraded })`），
    // 标识符不会被抹掉；文件级预筛仍用原文找字符串字面量。
    if (!/\bdegraded\b/.test(body)) continue;
    emitters.set(f.name, { rel: relative(ROOT, abs).split('\\').join('/'), line: lineAt(code, f.start) });
  }
}

const table = new Map(TABLE.map((t) => [t.cmd, t]));

/**
 * 纯判据：发射面 ⇄ 登记表双向对账（T1e-L01）。
 * 真仓与合成样本共用同一实现 —— 旧「正向对照」只对一个字面量数组做 filter，
 * 删掉整个扫描逻辑它照样绿，等于没有对照。
 * @param {Map<string,{rel:string,line:number}>} emitterMap 盘上发射面
 * @param {Map<string,object>} tableMap 登记表
 * @param {(anchor:{file:string,text:string})=>boolean} anchorHitFn 锚点判定（合成样本传桩）
 */
export function judgeReconciliation(emitterMap, tableMap, anchorHitFn) {
  const out = [];
  const STATUSES = ['consumed', 'pending', 'exempt'];
  for (const [cmd, where] of emitterMap) {
    const t = tableMap.get(cmd);
    if (!t) {
      out.push(`${where.rel}:${where.line} 命令 ${cmd} 回传 degraded，但登记表里没有它 ⇒ 新增分态必须显式回答「前端接不接」`);
      continue;
    }
    if (!STATUSES.includes(t.status)) {
      out.push(`${cmd} 的 status 非法：${t.status}`);
      continue;
    }
    if (t.status === 'consumed') {
      if (!t.anchor || !t.anchor.file || !t.anchor.text) {
        out.push(`${cmd} 登记为 consumed 却没给可核锚点（等于免检）`);
        continue;
      }
      if (!anchorHitFn(t.anchor)) {
        out.push(`${cmd} 登记为 consumed，但 ${t.anchor.file} 里找不到锚点「${t.anchor.text}」⇒ 消费点被删了或锚点写错`);
      }
      continue;
    }
    if (!t.batch) out.push(`${cmd} 是 ${t.status} 但缺批次归属`);
    if (!t.reason || t.reason.trim().length < 8) out.push(`${cmd} 是 ${t.status} 但缺理由（≥8 字）`);
    if (t.anchor) {
      if (!t.anchor.file || !t.anchor.text) out.push(`${cmd} 的 ${t.status} 锚点不完整（file/text 都要有）`);
      else if (anchorHitFn(t.anchor)) {
        out.push(`${cmd} 仍登记为 ${t.status}（${t.batch}），但锚点已在盘上命中 ⇒ 修完要回收条目`);
      }
    } else if (t.status === 'pending') {
      out.push(`${cmd} 是 pending 却没给消费点锚点 ⇒ 「兑现即回收」这条腿对它永久失效（补 anchor，或写成书面 exempt）`);
    }
  }
  for (const [cmd, t] of tableMap) {
    if (!emitterMap.has(cmd)) {
      out.push(`登记表条目失效：盘上已无命令 ${cmd} 发射 degraded（${t.status === 'pending' ? t.batch : 'consumed'}）`);
    }
  }
  return out;
}

for (const p of judgeReconciliation(emitters, table, (a) => anchorHit(join(ROOT, a.file), a.text))) g.fail(p);

if (emitters.size < MIN_EMITTERS) {
  g.fail(`断言对象地板不成立：只认出 ${emitters.size} 个 degraded 发射命令（地板 ${MIN_EMITTERS}）⇒ 命令解析或属性判定失效`);
}
const consumed = [...emitters.keys()].filter((c) => table.get(c)?.status === 'consumed').length;
g.ok(`degraded 消费契约对账：发射 ${emitters.size} 条 / 前端已接 ${consumed} 条 / 过渡 pending ${[...emitters.keys()].filter((c) => table.get(c)?.status === 'pending').length} 条（B0 落地时的缺口，逐条带批次）`);

// 合成样本正向对照（T1e-L01）：两条主判据**各自**被样本驱动，不再对字面量数组做同义反复。
//   ① 新增发射不登记必红；② pending 锚点命中（修好了没回收）必红；
//   ③ consumed 缺锚点 / gone 命令反向咬合 / exempt 缺理由；④ 干净样本必须放行。
{
  const emitOf = (cmd) => new Map([[cmd, { rel: 'sample.rs', line: 1 }]]);
  const tblOf = (rows) => new Map(rows.map((r) => [r.cmd, r]));
  const neverHit = () => false;
  const cases = [
    ['新增发射不登记未命中', judgeReconciliation(emitOf('new_cmd'), tblOf([]), neverHit).length],
    ['pending 锚点命中未回收未命中', judgeReconciliation(
      emitOf('p_cmd'),
      tblOf([{ cmd: 'p_cmd', status: 'pending', batch: 'Bx', reason: '理由足够长的一句话', anchor: { file: 'f.js', text: 't' } }]),
      () => true,
    ).length],
    ['pending 无锚点未命中', judgeReconciliation(
      emitOf('p_cmd'),
      tblOf([{ cmd: 'p_cmd', status: 'pending', batch: 'Bx', reason: '理由足够长的一句话' }]),
      neverHit,
    ).length],
    ['consumed 缺锚点未命中', judgeReconciliation(emitOf('c_cmd'), tblOf([{ cmd: 'c_cmd', status: 'consumed' }]), neverHit).length],
    ['exempt 缺理由未命中', judgeReconciliation(emitOf('e_cmd'), tblOf([{ cmd: 'e_cmd', status: 'exempt', batch: 'Bx' }]), neverHit).length],
    ['登记表多出命令未命中', judgeReconciliation(new Map(), tblOf([{ cmd: 'gone', status: 'consumed', anchor: { file: 'f', text: 't' } }]), neverHit).length],
    ['干净样本误报', judgeReconciliation(
      emitOf('c_cmd'),
      tblOf([{ cmd: 'c_cmd', status: 'consumed', anchor: { file: 'f.js', text: 't' } }]),
      () => true,
    ).length],
  ];
  const bad = cases.filter(([, got], i) => got !== (i === cases.length - 1 ? 0 : 1));
  if (bad.length) g.fail(`正向对照失效：${bad.map(([n, got]) => `${n}（实得 ${got}）`).join('、')}`);
  else g.ok(`正向对照 ${cases.length} 组命中（新增发射必红 / pending 锚点回收必红 / 无锚点 pending 必红 / 缺锚点必红 / 缺理由必红 / 表多出必红 / 干净放行）`);
}

// ---------- B3-4（2026-10-27）：时序前提 ——「还没读到配置」不得与「配置就绪」同形 ----------
// 病根：`pathConfigState` 初值是 'ok'，于是 load 未完成时也自称就绪；补扫定时器窗口内点
// 「重新扫描」会拿空 pathConfig 逐键 paths.save，把真源重建成扫描所见 —— 与本门禁主判据
// 盯的 A1-M12 是同一处真源，只是入口换成了「时序」而不是「状态位丢失」。
// 判据：初值必须是 'loading'；扫描/写回入口必须以 `!== 'ok'` 前置（只拒 degraded 会让
// loading / unavailable 穿过去）。
{
  const initState = (text) => {
    const m = /let\s+pathConfigState\s*=\s*'([a-z]+)'/.exec(text);
    return m ? m[1] : null;
  };
  // 正向对照：判定器必须能把两种初值区分开（否则下面两条绿是空绿）
  if (initState("let pathConfigState = 'ok';") !== 'ok'
    || initState("let pathConfigState = 'loading';") !== 'loading') {
    g.fail('B3-4 正向对照失败：pathConfigState 初值判定器失真');
  }
  const pb = join(ROOT, 'src', 'scripts', 'pathbinding.js');
  if (!existsSync(pb)) {
    g.fail('B3-4：src/scripts/pathbinding.js 不存在（判定对象缺失）');
  } else {
    const pbsrc = readFileSync(pb, 'utf8');
    const init = initState(pbsrc);
    if (init === null) g.fail('B3-4：找不到 pathConfigState 声明（判据锚点失效）');
    else if (init !== 'loading') {
      g.fail(`B3-4：pathConfigState 初值是 '${init}'，应为 'loading' —— 未落地时自称就绪，扫描会拿空配置覆盖真源`);
    } else {
      g.ok("B3-4：pathConfigState 初值为 'loading'（load 未完成不再冒充就绪）");
    }
    if (/if\s*\(\s*pathConfigState\s*!==\s*'ok'\s*\)/.test(pbsrc)) {
      g.ok("B3-4：扫描入口以 `!== 'ok'` 前置（loading / unavailable / degraded 一并拒）");
    } else {
      g.fail("B3-4：扫描入口缺少 `pathConfigState !== 'ok'` 前置 —— 只拒 degraded 会让 loading/unavailable 穿过");
    }
  }
}

// ---------- F4b-M13（2026-10-27 · P1）：settings_load 的两个消费方都得接 degraded ----------
// 病根：后端为「Corrupt ≠ Absent」专留 degraded，两个消费方（模型管理窗 / 模型选择器）都只判
// success+data ⇒ 配置损坏被画成「还没配」，用户去重复填写，随后的保存把可恢复的原文件覆盖掉。
// 判据：两处源码都必须同时命中「degraded 判定」与「可见提示出口」（只有 log 不算 —— 用户看不见）。
{
  const consumers = [
    { file: 'src/scripts/models-window.js', hint: 'toast(' },
    { file: 'src/scripts/modelpicker.js', hint: 'toastOut(' },
  ];
  const probe = (src, hint) => {
    const lines = src.split('\n').map(l => {
      const t = l.trim();
      if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return '';
      return l.replace(/\/\/.*$/, '');
    });
    const code = lines.join('\n');
    return code.includes('resp.degraded === true') && code.includes(hint);
  };
  // 正向对照：判定器必须能把「接了 degraded」与「只判 success」区分开，否则下面两条绿是空绿
  const POS = 'const resp = await window.api.settings.load(); if (resp.degraded === true) { toastOut("error", "x"); }';
  const NEG = 'const resp = await window.api.settings.load(); if (resp && resp.success && resp.data) { x(); }';
  if (!probe(POS, 'toastOut(') || probe(NEG, 'toastOut(')) {
    g.fail('F4b-M13 正向对照失败：degraded 消费判定器失真（必须能把「接 degraded」与「只判 success」分开）');
  }
  let bad = 0;
  for (const c of consumers) {
    const abs = join(ROOT, c.file);
    if (!existsSync(abs)) { g.fail(`F4b-M13：${c.file} 不存在（判定对象缺失）`); bad++; continue; }
    if (!probe(readFileSync(abs, 'utf8'), c.hint)) {
      g.fail(`F4b-M13：${c.file} 未同时具备 degraded 判定与可见提示 ⇒ 配置损坏会被画成「还没配」`);
      bad++;
    }
  }
  if (bad === 0) g.ok('F4b-M13：settings_load 的两个消费方都接了 degraded 且都有用户可见提示');
}

g.finish('check-degraded-consumption: 全部通过（pending ' + (emitters.size - consumed) + ' 条待 B1/B3 清零）');
