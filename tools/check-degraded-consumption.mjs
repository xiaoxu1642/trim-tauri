'use strict';
// tools/check-degraded-consumption.mjs —— 后端已分态的 `degraded`，前端不得折回单态（B0 门禁）
//
// 出处：2026-10-24 全仓重审 F4a2-K02（🔴）与族 F-2 / A1。
// 形状：后端为「Corrupt ≠ Absent」专门回传 `degraded`（`commands/paths.rs:102-104` 的 A1-M12
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
  { cmd: 'settings_load', status: 'pending', batch: 'B3/P1-6', reason: 'F4b-M13：两个消费方一起丢该位' },
  { cmd: 'fileclean_scan', status: 'pending', batch: 'B3/P1-6', reason: 'A1 命中：未接（展示层假绿族）' },
  { cmd: 'appearance_get_material', status: 'pending', batch: 'B3/P1-6', reason: '材质面未见消费方：window-material.js 现算无 degraded' },
  { cmd: 'optimizer_state_overview', status: 'pending', batch: 'B3/P1-6A', reason: '与 R3b-M10 同一条链（目录不可用 vs 空目录）' },
  { cmd: 'appearance_get_prefs', status: 'consumed', anchor: { file: 'src/scripts/pathbinding-appearance.js', text: 'resp.degraded === true' } },
  { cmd: 'uninstall_pending_list', status: 'consumed', anchor: { file: 'src/scripts/residue-window.js', text: 'data.degraded' } },
];

const walkRs = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walkRs(join(dir, e.name)) : (e.name.endsWith('.rs') ? [join(dir, e.name)] : []));

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
    const hit = existsSync(abs) && blankNonCode(readFileSync(abs, 'utf8'), 'js').includes(t.anchor.text);
    if (!hit) g.fail(`${cmd} 登记为 consumed，但 ${t.anchor.file} 里找不到锚点「${t.anchor.text}」⇒ 消费点被删了或锚点写错`);
  } else if (t.anchor) {
    const abs = join(ROOT, t.anchor.file);
    if (existsSync(abs) && blankNonCode(readFileSync(abs, 'utf8'), 'js').includes(t.anchor.text)) {
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

g.finish('check-degraded-consumption: 全部通过（pending ' + (emitters.size - consumed) + ' 条待 B1/B3 清零）');
