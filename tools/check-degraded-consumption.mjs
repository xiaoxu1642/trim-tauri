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
//   实际发射 `degraded` 的是这 7 条，其中 `appearance_*` 有两条、`startup`/`overview`/`syspanel`
//   并不发这个位。consumed 行必须给可核锚点；pending 行只标批次与理由，不许凭空写锚点。
const TABLE = [
  { cmd: 'paths_load', status: 'consumed', anchor: { file: 'src/scripts/pathbinding.js', text: 'resp.degraded === true' } },
  { cmd: 'settings_load', status: 'consumed', anchor: { file: 'src/scripts/models-window.js', text: 'resp.degraded === true' } },
  { cmd: 'fileclean_scan', status: 'pending', batch: 'B3/P1-6', reason: 'A1 命中：未接（展示层假绿族）' },
  { cmd: 'appearance_get_material', status: 'pending', batch: 'B3/P1-6', reason: '材质面未见消费方：window-material.js 现算无 degraded' },
  { cmd: 'optimizer_state_overview', status: 'pending', batch: 'B3/P1-6A', reason: '与 R3b-M10 同一条链（目录不可用 vs 空目录）' },
  { cmd: 'appearance_get_prefs', status: 'consumed', anchor: { file: 'src/scripts/pathbinding-appearance.js', text: 'resp.degraded === true' } },
  { cmd: 'uninstall_pending_list', status: 'consumed', anchor: { file: 'src/scripts/residue-window.js', text: 'data.degraded' } },
];

const walkRs = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walkRs(join(dir, e.name)) : (e.name.endsWith('.rs') ? [join(dir, e.name)] : []));

/**
 * 锚点命中判定（不走 blankNonCode）。
 *
 * 原因：`blankNonCode` 的模板分支对「模板里套 ${…} 再套模板」这种嵌套失准 —— 实测
 * `src/scripts/models-window.js` 从第一个 `return \`` 之后起整段被当成字符串抹掉，
 * 于是该文件后部的任何真实代码在 blanked 文本里都不存在（锚点永远判红）。
 * 工具层修法属 P2-a（门禁判据强度），本门禁先走保守口径：逐行剔除行注释与块注释行，
 * 不抹字符串（现有锚点文字都不在字符串字面量里）。
 */
const anchorHit = (abs, text) => {
  if (!existsSync(abs)) return false;
  const lines = readFileSync(abs, 'utf8').split('\n').map(l => {
    const t = l.trim();
    if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return '';
    return l.replace(/\/\/.*$/, '');
  });
  return lines.join('\n').includes(text);
};

const g = gate(import.meta.url);
if (!g.skipUnlessPresent(join(SRC_RS, 'engine', 'protect.rs'), 'src-tauri/src（本门禁的判定对象）')) g.finish();

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
for (const [cmd, where] of emitters) {
  const t = table.get(cmd);
  if (!t) { g.fail(`${where.rel}:${where.line} 命令 ${cmd} 回传 degraded，但登记表里没有它 ⇒ 新增分态必须显式回答「前端接不接」`); continue; }
  if (t.status === 'consumed' && (!t.anchor || !t.anchor.file || !t.anchor.text)) { g.fail(`${cmd} 登记为 consumed 却没给可核锚点（等于免检）`); continue; }
  if (t.status !== 'consumed' && !t.batch) { g.fail(`${cmd} 是 ${t.status} 但缺批次归属`); }
  if (t.status === 'consumed') {
    const abs = join(ROOT, t.anchor.file);
    const hit = anchorHit(abs, t.anchor.text);
    if (!hit) g.fail(`${cmd} 登记为 consumed，但 ${t.anchor.file} 里找不到锚点「${t.anchor.text}」⇒ 消费点被删了或锚点写错`);
  } else if (t.anchor) {
    const abs = join(ROOT, t.anchor.file);
    if (anchorHit(abs, t.anchor.text)) {
      g.fail(`${cmd} 仍登记为 ${t.status}（${t.batch}），但锚点已在盘上命中 ⇒ 修完要回收条目`);
    }
  }
  if (!['consumed', 'pending', 'exempt'].includes(t.status)) g.fail(`${cmd} 的 status 非法：${t.status}`);
}
for (const [cmd, t] of table) {
  if (!emitters.has(cmd)) g.fail(`登记表条目失效：盘上已无命令 ${cmd} 发射 degraded（${t.status === 'pending' ? t.batch : 'consumed'}）`);
}

if (emitters.size < MIN_EMITTERS) {
  g.fail(`断言对象地板不成立：只认出 ${emitters.size} 个 degraded 发射命令（地板 ${MIN_EMITTERS}）⇒ 命令解析或属性判定失效`);
}
const consumed = [...emitters.keys()].filter((c) => table.get(c)?.status === 'consumed').length;
g.ok(`degraded 消费契约对账：发射 ${emitters.size} 条 / 前端已接 ${consumed} 条 / 过渡 pending ${[...emitters.keys()].filter((c) => table.get(c)?.status === 'pending').length} 条（B0 落地时的缺口，逐条带批次）`);

// 合成样本正向对照：证明「新增发射不登记必红」与「pending 兑现后不回收必红」两条腿都在
const STATES = ['consumed', 'pending', 'exempt'];
const badState = STATES.concat(['bogus']).filter((s) => !['consumed', 'pending', 'exempt'].includes(s));
const ctrlOk = badState.length === 1 && STATES.every((s) => !badState.includes(s));
if (!ctrlOk) g.fail('正向对照失败：status 白名单判定本身失真（非法值必须恰好 1 个）');
else g.ok('正向对照通过：status 白名单只认 consumed/pending/exempt，其它值必被拦');

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
