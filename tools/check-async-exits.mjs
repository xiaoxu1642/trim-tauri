'use strict';
// tools/check-async-exits.mjs —— busy 锁窗口与裸 async handler 的 reject 出口（B0 门禁）
//
// 出处：2026-10-24 全仓重审 F4a1-M12 / F4a2-K02 同族 / A2 族（横向）/ F4b-M12 / F4c-M01。
// 两个真实形状：
//   ① **置 busy 之后、`try` 之前还有 `await`** ⇒ 这段里任何 reject 或同步抛错都跳过
//      `finally`，标志位永远不复位（R5a/F4a1 确证：`cleanup.js` 的 `clean()` 置 `isCleaning`
//      后连着四个 `await confirm*`，直到执行段才有 `try`）；
//   ② **裸 `async` 事件处理器没有 catch** ⇒ IPC reject 变成 unhandled rejection，
//      用户只看到「点了没反应」（`cleanup.js` 的「撤回全部」handler 正是 AGENTS 例外 B
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

// 过渡基线。锚点 = 变量名 / handler 首句代码文本，**不写行号**（AGENTS 反模式「无坐标豁免」）。
// 键串由本门禁在 `135301c` 上现算得到，不是照抄分报告的行号。
// B3（2026-10-25）清零，共回收 6 条：
//   · `cleanup.js#busy-window#isCleaning` —— 确认段拆成 `confirmCleanPlan()`，busy 移到
//     确认通过之后**同步**置起，置起到 `try` 之间 await 数为 0；
//   · `memoryclean.js#busy-window#memBusy` —— 原判红是「窗口越出函数体」导致的**误报**，
//     该处解锁本来就走 Promise 链的 `.finally`；判据已修正并补 A4/A5 两条对照钉住方向；
//   · `fontmanager.js` 应用按钮 / `models-window.js` 保存按钮 / `pathbinding-background.js`
//     导入与删除两处 —— 各自补上 reject 出口（确认件缺失还要与「用户拒绝」分档报出）。
// 本表**只减不增**：新增违例必须先修代码，不进门禁台账。
const TRANSITION = [];

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

/**
 * busy 窗口判据（抽成纯函数：真仓扫描与合成对照共用同一实现，不在两处各抄一份）。
 *
 * 窗口必须钉在**包含该赋值的那个函数体**内。旧写法是 `indexOf('try', from)` 全文找下一个
 * `try`，于是「本函数根本没有 await、解锁走 Promise 链的 `.finally`，下一个函数里才有
 * await」会被判红 —— `memoryclean.js` 的 `withMemBusy` 就是被这样误报的，而它本来就是
 * 安全形态（`.finally(() => memBusy = false)` 对 reject 同样执行）。
 * 误报积累的后果是「豁免表里躺着安全代码」，那才是这条门禁的第二类假绿。
 */
function findBusyViolations(blanked, fns) {
  const out = [];
  for (const m of [...blanked.matchAll(BUSY)]) {
    const from = m.index + m[0].length;
    // 取**最内层**包含该赋值的函数：本仓页面脚本整体套在一个 IIFE 里，`find` 拿到的
    // 第一条必然是那个覆盖整文件的 IIFE ⇒ 窗口等于全文件，越出函数体的误报原样保留。
    const enclosing = fns
      .filter((x) => m.index >= x.bodyStart && m.index < x.end)
      .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0];
    const bound = enclosing ? enclosing.end - 1 : blanked.length;
    const tryAt = blanked.indexOf('try', from);
    const stop = tryAt < 0 || tryAt >= bound ? bound : tryAt;
    out.push({ index: m.index, name: m[1], bad: /\bawait\b/.test(blanked.slice(from, stop)) });
  }
  return out;
}

/**
 * 裸 async 事件处理器判据（同样抽成纯函数，真仓与合成对照共用）。
 * handler 体内必须有 try / catch / `.catch(` / 仓内既有护栏之一。
 */
const HPAT = /addEventListener\(\s*['"][^'"]+['"]\s*,\s*(async\s*)?\s*\(?[^)]*\)?\s*=>\s*\{/g;
const GUARD_TOKENS = /\btry\b|\bcatch\b|\.catch\s*\(|guardAsync|guardBatch|withPowerBusy|confirmViaModal/;
function findHandlerViolations(blanked) {
  const out = [];
  for (const m of [...blanked.matchAll(HPAT)]) {
    if (!m[1]) continue; // 非 async handler 不会有 reject 逃逸问题
    const open = blanked.indexOf('{', m.index + m[0].length - 1);
    if (open < 0) continue;
    const end = skipBraces(blanked, open);
    const body = blanked.slice(open + 1, end - 1);
    out.push({ index: m.index, open, end, bad: !GUARD_TOKENS.test(body) });
  }
  return out;
}

function analyze(rel, code) {
  const blanked = blankNonCode(code, 'js');
  const fns = splitFunctions(code, 'js');
  const note = (k) => seen.set(k, (seen.get(k) || 0) + 1);
  // ① busy 窗口：见 findBusyViolations
  for (const v of findBusyViolations(blanked, fns)) {
    objects++;
    if (!v.bad) continue;
    const k = keyOf(rel, 'busy-window', v.name);
    note(k);
    if (!exempt.has(k)) g.fail(`${rel}:${lineAt(code, v.index)} [${k}] 置 ${v.name} = true 之后、同一函数内的下一个 try 之前存在 await ⇒ 一次 reject 就永久锁死；未登记在过渡豁免里`);
  }
  // ② 裸 async 事件处理器：见 findHandlerViolations
  for (const v of findHandlerViolations(blanked)) {
    objects++;
    if (!v.bad) continue;
    const k = keyOf(rel, 'bare-handler', `${anchorOf(code, v.index)}|${firstCodeLine(blanked, v.open, v.end)}`);
    note(k);
    if (!exempt.has(k)) g.fail(`${rel}:${lineAt(code, v.index)} [${k}] 裸 async 事件处理器没有 try/catch 也没有 .catch 出口 ⇒ IPC reject 静默消失；未登记在过渡豁免里`);
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
const mkH = (body) => `const el = { addEventListener: () => {} };\nel.addEventListener('click', async () => {\n${body}\n});\n`;
const CONTROLS = [
  { kind: 'busy', label: 'A1 置 busy 后 try 前有 await ⇒ 必须判红', code: mk('  isCleaning = true;\n  await ask();\n  try { go(); } finally { isCleaning = false; }'), want: 1 },
  { kind: 'busy', label: 'A2 置 busy 后立刻 try ⇒ 不判红（合法姿势）', code: mk('  isCleaning = true;\n  try { await go(); } finally { isCleaning = false; }'), want: 0 },
  { kind: 'busy', label: 'A3 await 只出现在注释里 ⇒ 不判红（文本命中不算，反向也要成立）', code: mk('  isCleaning = true;\n  // await ask();\n  try { go(); } finally { isCleaning = false; }'), want: 0 },
  {
    // 这一条钉的是本门禁**唯一会误伤安全代码**的那处形状：窗口越出函数体。
    kind: 'busy',
    label: 'A4 本函数无 await、下一个函数才有 await ⇒ 不判红（窗口不得越出函数体）',
    code: 'function holder() {\n  memBusy = true;\n  Promise.resolve().then(fn).finally(() => { memBusy = false; });\n}\nasync function other() {\n  try { await go(); } finally { memBusy = false; }\n}\n',
    want: 0,
  },
  {
    kind: 'busy',
    label: 'A5 同一函数内、无 try 兜底且直接 await ⇒ 必须判红（A4 的反向，防止把窗口收死成永不判红）',
    code: 'function holder() {\n  memBusy = true;\n  await go();\n}\n',
    want: 1,
  },
  { kind: 'handler', label: 'B1 普通 async handler 无出口 ⇒ 必须判红', code: mkH('  const r = await api.save();'), want: 1 },
  { kind: 'handler', label: 'B2 handler 里有 try ⇒ 不判红', code: mkH('  try { await api.save(); } catch (e) { log(e); }'), want: 0 },
  {
    // 这一条钉的是 lib/src-scan 的抹白器：正则字面量 `/^https?:\/\//i` 里的 `//` 若被当成
    // 行注释，本行后半段（含结尾 `{`）一起抹掉 ⇒ 后面那个 `}` 变成多余闭合 ⇒
    // skipBraces 提前收口，handler 被切短，**真实存在的 try 看不见**（B3 在
    // models-window.js 的保存按钮上实测到误报）。
    kind: 'handler',
    label: 'B3 handler 体内的正则字面量含 // ⇒ 不得因此看不见 try（抹白器不得把正则当注释）',
    code: mkH("  if (!/^https?:\\/\\//i.test(url)) { log('bad'); return; }\n  try { await api.save(); } catch (e) { log(e); }"),
    want: 0,
  },
];
let ctrlBad = 0;
for (const c of CONTROLS) {
  const blanked = blankNonCode(c.code, 'js');
  const hits = c.kind === 'busy'
    ? findBusyViolations(blanked, splitFunctions(c.code, 'js')).filter((v) => v.bad).length
    : findHandlerViolations(blanked).filter((h) => h.bad).length;
  if (hits !== c.want) { ctrlBad++; console.error(`✗ 正向对照失败：${c.label}（实得 ${hits}，应为 ${c.want}）`); }
}
if (ctrlBad === 0) g.ok(`正向对照 ${CONTROLS.length} 组通过（busy 三向 + 窗口不越函数体两向 + handler 三向，含「正则字面量不得被当注释」）`);

g.finish('check-async-exits: 全部通过（过渡豁免 ' + exempt.size + ' 条，逐条见 TRANSITION）');
