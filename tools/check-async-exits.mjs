'use strict';
// tools/check-async-exits.mjs —— busy 锁窗口与裸 async handler 的 reject 出口（B0 门禁）
//
// 出处：2026-10-24 全仓重审 F4a1-M12 / F4a2-K02 同族 / A2 族（横向）/ F4b-M12 / F4c-M01。
// 两个真实形状：
//   ① **置 busy 之后、`try` 之前还有 `await`** ⇒ 这段里任何 reject 或同步抛错都跳过
//      `finally`，标志位永远不复位（R5a/F4a1 确证：`cleanup.js:1421` 置 `isCleaning`，
//      到 `:1609` 才有 `try`，中间四个 `await confirm*`）；
//   ② **裸 `async` 事件处理器没有 catch** ⇒ IPC reject 变成 unhandled rejection，
//      用户只看到「点了没反应」（`cleanup.js:2493`「撤回全部」正是 AGENTS 例外 B
//      第五道约束「重启前可撤回」的唯一前端出口）。
//
// 判据不碰的东西（v2 §0.3 E10 明确纠正 v1 的过宽判断）：
//   `window.app?.X(...)` 在 `app` 不存在时返回 undefined，**不必然**抛 TypeError。
//   所以本门禁**不因单个 `?.` 定罪**，只看「busy 窗口里的 await」与「handler 有没有 reject 出口」。
//
// 用法：node tools/check-async-exits.mjs

import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gate } from './lib/gate.mjs';
import { blankNonCode, skipBraces, splitFunctions, lineAt } from './lib/src-scan.mjs';

const ROOT = process.cwd();
const SCRIPTS = join(ROOT, 'src', 'scripts');
const BUSY = /\b([A-Za-z0-9_]*(?:busy|Busy|cleaning|Cleaning|running|Running|locked|Locked|inProgress|pending|Pending)[A-Za-z0-9_]*)\s*=\s*true\b/g;
const MIN_OBJECTS = 6; // 对象地板：busy 赋值 + async handler 的合计站点数，低于此数说明判定失效

// 过渡基线（B3 清零）。锚点 = 变量名 / handler 首句代码文本，**不写行号**（AGENTS 反模式「无坐标豁免」）。
// 键串由本门禁在 `135301c` 上现算得到，不是照抄分报告的行号。
const TRANSITION = [
  { file: 'src/scripts/cleanup.js', kind: 'busy-window', where: 'isCleaning', batch: 'B3/P1-7', reason: 'F4a1-M12：置锁后到 try 之间四个 confirm/预查询 await' },
  { file: 'src/scripts/memoryclean.js', kind: 'busy-window', where: 'memBusy', batch: 'B3/P1-7', reason: '门禁新发现：内存清理同形状（置 busy 后先 await 再 try）' },
  { file: 'src/scripts/fontmanager.js', kind: 'bare-handler', where: '|settings.family=modal.select.value', batch: 'B3/P1-7', reason: '字体应用 handler 无 reject 出口（与 F4c-M01 同形）' },
  { file: 'src/scripts/models-window.js', kind: 'bare-handler', where: '|constkey=btn.dataset.model', batch: 'B3/P1-7', reason: '模型选择 handler 无 reject 出口' },
  { file: 'src/scripts/pathbinding-background.js', kind: 'bare-handler', where: '|constresp=awaitwindow.api.appearance.importBg.()', batch: 'B3/P1-7', reason: 'F4c-M01：导入背景图 await 无 try/catch' },
  { file: 'src/scripts/pathbinding-background.js', kind: 'bare-handler', where: '|e.stopPropagation()', batch: 'B3/P1-7', reason: 'F4c-M01：删除背景图 handler 无 reject 出口' },
];

const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(join(dir, e.name)) : (e.name.endsWith('.js') ? [join(dir, e.name)] : []));

const g = gate(import.meta.url);
if (!g.skipUnlessPresent(SCRIPTS, 'src/scripts（本门禁的判定对象）')) g.finish();

const keyOf = (rel, kind, where) => `${rel}#${kind}#${where}`;
const exempt = new Map(TRANSITION.map((t) => [keyOf(t.file, t.kind, t.where), t]));
let objects = 0;
const seen = new Map(); // key → 命中次数（锚点不唯一必须显式红，不能靠序号偷偷去重）

/**
 * 锚点：不写行号（AGENTS 反模式「无坐标豁免：插行即漂移」）。
 *  - busy 型 → 变量名；
 *  - handler 型 → handler 体内**第一条非空代码行**的前 48 字符（页面脚本整体在 IIFE 里，
 *    按函数名定锚会全部落到 `(匿名)` 而互相撞车，首版即如此；首句文本天然互异）。
 */
function anchorOf(code, offset) {
  const blanked = blankNonCode(code, 'js');
  const fns = splitFunctions(code, 'js');
  const f = fns.find((x) => offset >= x.start && offset < x.end);
  return f && f.name !== '(匿名)' ? f.name : '';
}
function firstCodeLine(blanked, open, end) {
  const seg = blanked.slice(open + 1, end - 1);
  for (const raw of seg.split('\n')) {
    const t = raw.trim();
    if (t) return t.replace(/[^\w$.:'"()=]/g, '').slice(0, 48);
  }
  return '(空)';
}

function analyze(rel, code) {
  const blanked = blankNonCode(code, 'js');
  const note = (k) => seen.set(k, (seen.get(k) || 0) + 1);
  // ① busy 窗口：逐个 `<busyish> = true`，取其后到函数/块结束前第一个 `try` 之间的片段
  for (const m of [...blanked.matchAll(BUSY)]) {
    objects++;
    const from = m.index + m[0].length;
    const tryAt = blanked.indexOf('try', from);
    const stop = tryAt < 0 ? Math.min(from + 4000, blanked.length) : tryAt;
    if (!/\bawait\b/.test(blanked.slice(from, stop))) continue;
    const k = keyOf(rel, 'busy-window', m[1]);
    note(k);
    if (!exempt.has(k)) g.fail(`${rel}:${lineAt(code, m.index)} [${k}] 置 ${m[1]} = true 之后、下一个 try 之前存在 await ⇒ 一次 reject 就永久锁死；未登记在过渡豁免里`);
  }
  // ② 裸 async 事件处理器：handler 体内既无 try/catch、也没有 .catch 出口
  const hpat = /addEventListener\(\s*['"][^'"]+['"]\s*,\s*(async\s*)?\s*\(?[^)]*\)?\s*=>\s*\{/g;
  for (const m of [...blanked.matchAll(hpat)]) {
    if (!m[1]) continue; // 非 async handler 不会有 reject 逃逸问题
    const open = blanked.indexOf('{', m.index + m[0].length - 1);
    if (open < 0) continue;
    const end = skipBraces(blanked, open);
    const body = blanked.slice(open + 1, end - 1);
    objects++;
    const guarded = /\btry\b/.test(body) || /\bcatch\b/.test(body) || /\.catch\s*\(/.test(body) || /guardAsync|guardBatch|withPowerBusy|confirmViaModal/.test(body);
    if (guarded) continue;
    const k = keyOf(rel, 'bare-handler', `${anchorOf(code, m.index)}|${firstCodeLine(blanked, open, end)}`);
    note(k);
    if (!exempt.has(k)) g.fail(`${rel}:${lineAt(code, m.index)} [${k}] 裸 async 事件处理器没有 try/catch 也没有 .catch 出口 ⇒ IPC reject 静默消失；未登记在过渡豁免里`);
  }
}

for (const abs of walk(SCRIPTS)) {
  analyze(relative(ROOT, abs).split('\\').join('/'), readFileSync(abs, 'utf8'));
}

// 已登记但盘上找不到的豁免（代码修好了却还挂着 = 第二类假绿；锚点按函数名，不随行号漂移）
for (const [k, t] of exempt) {
  if (!seen.has(k)) g.fail(`TRANSITION 条目失效：${k}（${t.batch}）⇒ 该处已修复或函数已改名，必须回收条目`);
  if (!t.batch || !t.reason || t.reason.length < 8) g.fail(`TRANSITION 条目缺批次或理由：${k}`);
}
for (const [k, n] of seen) {
  if (n > 1) g.fail(`锚点不唯一：${k} 命中 ${n} 次 ⇒ 无法逐条登记豁免，请在该函数内改用更细的锚点（本门禁刻意不靠序号偷偷去重）`);
}
if (objects < MIN_OBJECTS) {
  g.fail(`断言对象地板不成立：只扫到 ${objects} 个判定对象（地板 ${MIN_OBJECTS}）⇒ busy 正则或 handler 正则失效，不是仓库变干净`);
}
g.ok(`前端 await/出口对账：判定对象 ${objects} 个 / 命中 ${seen.size} 处（登记豁免 ${exempt.size} 条，待 B3 清零）`);

// 合成样本正向对照（每次都跑）
const mk = (body) => `const x = { addEventListener: () => {} };\nfunction run() {\n${body}\n}\n`;
const CONTROLS = [
  { label: 'A1 置 busy 后 try 前有 await ⇒ 必须判红', code: mk('  isCleaning = true;\n  await ask();\n  try { go(); } finally { isCleaning = false; }'), want: 1 },
  { label: 'A2 置 busy 后立刻 try ⇒ 不判红（合法姿势）', code: mk('  isCleaning = true;\n  try { await go(); } finally { isCleaning = false; }'), want: 0 },
  { label: 'A3 await 只出现在注释里 ⇒ 不判红（文本命中不算，反向也要成立）', code: mk('  isCleaning = true;\n  // await ask();\n  try { go(); } finally { isCleaning = false; }'), want: 0 },
];
let ctrlBad = 0;
for (const c of CONTROLS) {
  const blanked = blankNonCode(c.code, 'js');
  let hits = 0;
  for (const m of [...blanked.matchAll(BUSY)]) {
    const from = m.index + m[0].length;
    const tryAt = blanked.indexOf('try', from);
    const stop = tryAt < 0 ? Math.min(from + 4000, blanked.length) : tryAt;
    if (/\bawait\b/.test(blanked.slice(from, stop))) hits++;
  }
  if (hits !== c.want) { ctrlBad++; console.error(`✗ 正向对照失败：${c.label}（实得 ${hits}，应为 ${c.want}）`); }
}
if (ctrlBad === 0) g.ok(`正向对照 ${CONTROLS.length} 组通过（含「await 在 try 前必判红」与「注释里的 await 不得判红」两个方向）`);

g.finish('check-async-exits: 全部通过（过渡豁免 ' + exempt.size + ' 条待 B3 清零）');
