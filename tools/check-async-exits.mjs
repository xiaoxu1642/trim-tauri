'use strict';
// tools/check-async-exits.mjs —— busy 锁窗口与 async handler 的 reject 出口（B0 门禁）
//
// 出处：2026-10-24 全仓重审 F4a1-M12 / F4a2-K02 同族 / A2 族（横向）/ F4b-M12 / F4c-M01；
// 2026-11-01 重审《_总报告》§6.3 #4（F4a1-M04 / A2 / T1e-M06 / T1e-L06）修正射程：
//   旧 handler 腿只认内联 `async (…) => {`，且「函数体任意位置有 try/catch/词」即放行 ——
//   具名 handler（`addEventListener('click', clean)`）与 `on(id,type,IDENT)` 绑定零覆盖，
//   `try { … } finally { … }`（无 catch）也算出口。两个真实形状仍然成立：
//   ① **置 busy 之后、`try` 之前还有 `await`** ⇒ 这段里任何 reject 或同步抛错都跳过
//      `finally`，标志位永远不复位（R5a/F4a1 确证：`cleanup.js` 的 `clean()` 置 `isCleaning`
//      后连着四个 `await confirm*`，直到执行段才有 `try`）；
//   ② **async 事件处理器里存在没有 catch 接收者的 `await`** ⇒ IPC reject 变成 unhandled
//      rejection，用户只看到「点了没反应」（`cleanup.js` 的「撤回全部」handler 正是 AGENTS
//      例外 B 第五道约束「重启前可撤回」的唯一前端出口）。
//
// handler 腿的判据（本轮修正）：
//   · 射程 = 内联 async 回调 + `addEventListener(…, IDENT)` 具名 async 函数 +
//     `on(id,type,IDENT)`（同文件自定义的三参 `on` 助手）具名/内联 async 回调；
//   · 逐 `await` 判：必须在**同一函数体内**被一个带 `catch` 子句的 `try` 块包住，
//     或该 await 表达式自带 `.catch(` 接收者；`try { … } finally { … }` 没有 catch 不算；
//     「函数别处有 try」不算（旧实现 `GUARD_TOKENS` 的假绿通道）。
//
// 判据不碰的东西（v2 §0.3 E10 明确纠正 v1 的过宽判断）：
//   `window.app?.X(...)` 在 `app` 不存在时返回 undefined，**不必然**抛 TypeError。
//   所以本门禁**不因单个 `?.` 定罪**，只看「busy 窗口里的 await」与「await 有没有 catch 接收者」。
//
// 用法：node tools/check-async-exits.mjs

import { readFileSync, readdirSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gate } from './lib/gate.mjs';
import { blankNonCode, skipBraces, splitFunctions, lineAt } from './lib/src-scan.mjs';

// 仓根由本文件位置推出，不用 `process.cwd()`：在 src-tauri/ 下单跑时判定对象会变成
// 「不在本机」而打 SKIP + exit 0，门禁静默变成未校验（T1b-L01）。
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPTS = join(ROOT, 'src', 'scripts');
const BUSY = /\b([A-Za-z0-9_]*(?:busy|Busy|cleaning|Cleaning|running|Running|locked|Locked|inProgress|pending|Pending)[A-Za-z0-9_]*)\s*=\s*true\b/g;
const MIN_BUSY = 6; // busy 赋值对象地板（单腿）：低于此数说明 BUSY 正则失效
const MIN_INLINE = 6; // 内联 async 事件处理器对象地板
const MIN_NAMED = 12; // 具名 async handler（addEventListener(…, IDENT)）对象地板
const MIN_ON = 2; // on(id,type,IDENT) 具名 async 回调对象地板（撤回重启后删绑定退役后的现盘值；取数命令：node tools/check-async-exits.mjs）
// T1e-L08：旧实现把两条腿合并成一个地板（18 + 33 = 51），任一腿归零另一腿仍能过线。
// 现在三桶各自计对象、各自判地板 —— 单腿失明必须能被看见。
// 收紧后的具名/on 两桶各留约三成余量：正则整体失效（归零）或半失效都会低于地板。

// 过渡基线。锚点 = 变量名 / handler 名字 / handler 首两句代码文本，**不写行号**
// （AGENTS 反模式「无坐标豁免：插行即漂移」）。
// 键串由本门禁在盘上现算得到，不是照抄分报告的行号。
// B3（2026-10-25）清零，共回收 6 条（busy 窗口两条 + 应用/保存/导入/删除四处出口）。
// 2026-11-02（门禁假绿 #4）：handler 腿由「任意位置有 try」收紧为「逐 await 有 catch 接收者」，
// 射程扩到具名（含 `const NAME = async () => {`）与 on() 绑定；当日盘上存量一次性登记如下
// （条数由运行输出现算，不写死）；此后**只减不增**：新增违例必须先修代码，不得往表里加行
// （TRANSITION_CAP 是硬上限，改它本身就是一次会被复核的动作）。
// 存量形状只有三类：① 确认件 await 在 try 之外（确认组件 reject ⇒「点了没反应」）；
// ② 后端/IPC await 在 try 之外；③ `try { await … } finally { … }` 缺 catch。
// 唯一的形状命中而非 reject 源：cleanup.js 的固定延时 Promise（见该条理由，保留可见而非静默豁免）。
const TRANSITION = [
  { file: 'src/scripts/cleanup.js', kind: 'bare-handler', where: '|killBtn.disabled=true|killBtn.textContent=', batch: '门禁假绿#4', unit: 'F4a1', reason: '固定延时 Promise（setTimeout 包在 Promise 里，executor 无 reject 源）；判据按逐 await 收口，形状与真违例同形，保留登记' },
  { file: 'src/scripts/cleanup.js', kind: 'bare-handler', where: '|constok=awaitwindow.app.confirmWarning(|', batch: '门禁假绿#4', unit: 'F4a1', reason: '重启资源管理器确认件、延时等待、await clean() 三处都在 try 外：确认组件或 clean() reject 即「点了没反应」' },
  { file: 'src/scripts/cleanup.js', kind: 'bare-handler', where: '|constp=packsbtn.getAttribute()|if(p)return', batch: '门禁假绿#4', unit: 'F4a1', reason: '跳转「安装包备份」页前的 confirmDanger 确认件在 try 外，确认组件 reject 时按钮无反馈' },
  { file: 'src/scripts/cleanup.js', kind: 'bare-handler', where: '|constb=uninstbtn.getAttribute()|if(b)return', batch: '门禁假绿#4', unit: 'F4a1', reason: '跳转「卸载残留」页前的 confirmDanger 确认件在 try 外，确认组件 reject 时按钮无反馈' },
  { file: 'src/scripts/cleanup.js', kind: 'bare-handler', where: '|constb=backupsbtn.getAttribute()|if(b)return', batch: '门禁假绿#4', unit: 'F4a1', reason: '跳转「备份还原」页前的 confirmDanger 确认件在 try 外，确认组件 reject 时按钮无反馈' },
  { file: 'src/scripts/diskbench.js', kind: 'bare-handler', where: '|constid=btn.dataset.deleteId|constok=awaitwindow.app.confirm.(', batch: '门禁假绿#4', unit: 'F4b', reason: '删除单条测速记录的 confirm 确认件在 try 外，确认组件 reject 时「点了没反应」' },
  { file: 'src/scripts/diskbench.js', kind: 'bare-handler', where: '|constok=awaitwindow.app.confirmDanger.(|', batch: '门禁假绿#4', unit: 'F4b', reason: '清空测速历史的 confirmDanger 确认件在 try 外，确认组件 reject 时按钮无反馈' },
  { file: 'src/scripts/finder.js', kind: 'named', where: 'openIgnoreList', batch: '门禁假绿#4', unit: 'F4b', reason: '打开忽略名单末尾的 await refreshIgnoreList() 在 try 外（同函数其余 IPC 均有 catch），名单读取 reject 即静默' },
  { file: 'src/scripts/fontmanager.js', kind: 'bare-handler', where: '|if(window.api.fonts.removeImported)window.app.to|if(fontList.some(f=f.imported))return', batch: '门禁假绿#4', unit: 'F4c', reason: '删除已导入字体的 confirmDanger 确认件在 try 外，确认组件 reject 时按钮无反馈' },
  { file: 'src/scripts/pathbinding.js', kind: 'bare-handler', where: '|constbtn=e.currentTarget|btn.disabled=true', batch: '门禁假绿#4', unit: 'F4a2', reason: '`try { await autoScan(false); } finally { … }` 没有 catch：autoScan reject 会穿过 finally 变成 unhandled（T1e-L06 的实测形状）' },
  { file: 'src/scripts/peripheral.js', kind: 'bare-handler', where: '|if(window.api.peripheralWindow.restoreBackup)toa|constbtn=e.currentTarget', batch: '门禁假绿#4', unit: 'F4a2', reason: '还原外设备份的 confirmDanger 确认件在 try 外，确认组件 reject 时按钮无反馈' },
  { file: 'src/scripts/peripheral.js', kind: 'bare-handler', where: '|if(window.api.peripheralWindow.apply)toast()retu|constbtn=e.currentTarget', batch: '门禁假绿#4', unit: 'F4a2', reason: '恢复 Windows 默认值的 confirmDanger 确认件在 try 外，确认组件 reject 时按钮无反馈' },
  { file: 'src/scripts/realtime.js', kind: 'bare-handler', where: '|constrow=btn.closest()|constname=row.dataset.name', batch: '门禁假绿#4', unit: 'F4b', reason: '删除单份网速报告的 confirm 确认件在 try 外，确认组件 reject 时「点了没反应」' },
  { file: 'src/scripts/realtime.js', kind: 'bare-handler', where: '|if(typeofwindow.api.realtime.reportClear==)|window.app.toast()', batch: '门禁假绿#4', unit: 'F4b', reason: '清空全部网速报告的 confirm 确认件在 try 外，确认组件 reject 时按钮无反馈' },
  { file: 'src/scripts/syspanel.js', kind: 'named', where: 'submit', batch: '门禁假绿#4', unit: 'F4c', reason: '新建电源计划弹窗的 submit 用 `try { await onSubmit(val) } finally { … }` 没有 catch：onSubmit reject 会穿过 finally 变成 unhandled（T1e-L06 同形）' },
  { file: 'src/scripts/syspanel.js', kind: 'named', where: 'editorCancel', batch: '门禁假绿#4', unit: 'F4c', reason: '放弃未保存修改的 confirmWarning 确认件在 try 外（函数后续保存段有 catch），确认组件 reject 时「放弃修改」无反馈' },
];
const TRANSITION_CAP = 16;

const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(join(dir, e.name)) : (e.name.endsWith('.js') ? [join(dir, e.name)] : []));

const g = gate(import.meta.url);
if (!g.skipUnlessPresent(SCRIPTS, 'src/scripts（本门禁的判定对象）')) { g.finish(); process.exit(0); }

const keyOf = (rel, kind, where) => `${rel}#${kind}#${where}`;
const exempt = new Map(TRANSITION.map((t) => [keyOf(t.file, t.kind, t.where), t]));
let busyObjects = 0;
let inlineObjects = 0;
let namedObjects = 0;
let onObjects = 0;
const seen = new Map(); // key → 命中次数（锚点不唯一必须显式红，不能靠序号偷偷去重）

/**
 * `blankNonCode(code,'js')` 只抹双引号与模板串（单引号在 JS 分支被有意保留给 Rust 字符
 * 字面量口径），于是 `'try'` / `'await'` 这类单引号串会顶账（T1e-L07）。这里补一层
 * 等长抹白，保证判据都作用在「无字符串」的文本上。
 */
const blankSingleQuoted = (text) => text.replace(/'(?:\\.|[^'\\\n])*'/g, (m) => ' '.repeat(m.length));

/**
 * 锚点：不写行号（AGENTS 反模式「无坐标豁免：插行即漂移」）。
 *  - busy 型 → 变量名；
 *  - 具名 handler / on 回调 → 函数名；
 *  - 内联 handler → handler 体内**第一条非空代码行**的前 48 字符（页面脚本整体在 IIFE 里，
 *    按函数名定锚会全部落到 `(匿名)` 而互相撞车，首版即如此；首句文本天然互异）。
 */
function anchorOf(code, offset) {
  const blanked = blankNonCode(code, 'js');
  const fns = splitFunctions(code, 'js');
  const f = fns.find((x) => offset >= x.start && offset < x.end);
  return f && f.name !== '(匿名)' ? f.name : '';
}
function firstCodeLines(blanked, open, end, n = 2) {
  const seg = blanked.slice(open + 1, end - 1);
  const out = [];
  for (const raw of seg.split('\n')) {
    const t = raw.trim();
    if (!t) continue;
    out.push(t.replace(/[^\w$.:'"()=]/g, '').slice(0, 48));
    if (out.length >= n) break;
  }
  return out.length ? out.join('|') : '(空)';
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
    // T1e-L07：旧实现 `indexOf('try', from)` 是**子串**搜索 —— `entry` / `retry` /
    // `country` 里的 try 会把窗口提前截断，其后的 await 就此隐形。改词边界正则。
    const tryRe = /\btry\b/g;
    tryRe.lastIndex = from;
    const tryM = tryRe.exec(blanked);
    const tryAt = tryM ? tryM.index : -1;
    const stop = tryAt < 0 || tryAt >= bound ? bound : tryAt;
    out.push({ index: m.index, name: m[1], bad: /\bawait\b/.test(blanked.slice(from, stop)) });
  }
  return out;
}

// ---------------- handler 腿：逐 await 判 catch 接收者 ----------------

/** [start,end) 内的每个 `try { … }` 块区间，以及它的 `}` 后面是否跟着 `catch`。 */
function tryBlocksIn(blanked, start, end) {
  const out = [];
  const re = /\btry\b/g;
  re.lastIndex = start;
  let m;
  while ((m = re.exec(blanked)) && m.index < end) {
    const open = blanked.indexOf('{', m.index + 3);
    if (open < 0 || open >= end) continue;
    const close = skipBraces(blanked, open);
    if (close > end) continue;
    out.push({ start: open, end: close, catches: /^\s*catch\b/.test(blanked.slice(close, close + 16)) });
  }
  return out;
}

function awaitsIn(blanked, start, end) {
  const out = [];
  const re = /\bawait\b/g;
  re.lastIndex = start;
  let m;
  while ((m = re.exec(blanked)) && m.index < end) out.push(m.index);
  return out;
}

/**
 * `await f().catch(…)` 是真正的 reject 接收者（T1e-L06 的彻底方案口径）。
 * 只认语句内、深度 0 的 `.catch(`；语句边界按 `;` 或右括号收口（本仓页面脚本统一写分号）。
 */
function hasChainedCatch(blanked, at, end) {
  let depth = 0;
  for (let i = at; i < end && i - at <= 400; i++) {
    const c = blanked[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) return false;
      depth--;
    } else if (c === ';' && depth === 0) {
      return false;
    } else if (c === '.' && depth === 0 && /^\.catch\s*\(/.test(blanked.slice(i, i + 9))) {
      return true;
    }
  }
  return false;
}

/**
 * handler 体内没有 catch 接收者的 await 偏移列表。
 * `nested` 是嵌在本 handler 体内的其他 handler 区间：它们的 await 属于内层 handler 的
 * reject 面，不能被外层的 try 顶账，也不能记到外层头上（`showHistory` 弹窗内嵌着
 * 「删除单条 / 清空全部」两个内联 handler，不剥离会一条 await 记两处）。
 */
function uncoveredAwaits(blanked, start, end, nested = []) {
  const covered = tryBlocksIn(blanked, start, end).filter((t) => t.catches);
  return awaitsIn(blanked, start, end).filter((a) =>
    !nested.some(([s, e]) => a > s && a < e)
    && !covered.some((t) => a > t.start && a < t.end)
    && !hasChainedCatch(blanked, a, end));
}

// 内联 async 回调（箭头 / 函数表达式）；`[^,()]*` 匹配被抹白的事件名或裸标识符。
const AE_INLINE = /addEventListener\(\s*[^,()]*\s*,\s*(?:async\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>|async\s+function\s*[A-Za-z0-9_$]*\s*\([^)]*\))\s*\{/g;
const AE_REF = /addEventListener\(\s*[^,()]*\s*,\s*([A-Za-z_$][\w$]*)\s*\)/g;
// `on(id, type, handler)` 是本仓子窗的绑定助手（`residue-window.js`）；只在该文件自己
// 定义了三参 `function on(` 时才启用这条腿，避免把别处的同名调用误认成事件绑定。
const ON_DEF = /\bfunction\s+on\s*\([^)]*,[^)]*,[^)]*\)/;
const ON_INLINE = /\bon\(\s*[^,()]*\s*,\s*[^,()]*\s*,\s*(?:async\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>|async\s+function\s*[A-Za-z0-9_$]*\s*\([^)]*\))\s*\{/g;
const ON_REF = /\bon\(\s*[^,()]*\s*,\s*[^,()]*\s*,\s*([A-Za-z_$][\w$]*)\s*\)/g;

/**
 * 收集一个文件里的 handler 绑定（三腿：内联 / 具名 addEventListener / on 回调）。
 * 同一函数体被多处绑定只判一次（`restartExplorer` 等确有双绑定），否则锚点会重复。
 */
function collectHandlers(code, blanked) {
  const fns = splitFunctions(code, 'js');
  const asyncByName = new Map();
  const add = (name, start, bodyStart, end) => {
    if (!asyncByName.has(name)) asyncByName.set(name, []);
    asyncByName.get(name).push({ name, start, bodyStart, end });
  };
  for (const f of fns) {
    if (f.name === '(匿名)') continue;
    if (!/\basync\b/.test(blanked.slice(f.start, f.bodyStart))) continue;
    add(f.name, f.start, f.bodyStart, f.end);
  }
  // splitFunctions 只认 `async function NAME(` 与 `NAME: async (…) =>`；本仓另有一批
  // `const NAME = async (…) => {` 的具名 handler（`syspanel.js` 的两个 `submit`），
  // 不补这一形状就等于漏掉报告点名的具名 handler 里的两个（`submit`）。
  const ASYNC_VAR = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>|async\s+function\s*[A-Za-z0-9_$]*\s*\([^)]*\))\s*\{/g;
  for (const m of blanked.matchAll(ASYNC_VAR)) {
    const open = blanked.indexOf('{', m.index + m[0].length - 1);
    if (open < 0) continue;
    add(m[1], m.index, open + 1, skipBraces(blanked, open));
  }
  const inline = [];
  const pushInline = (m) => {
    const open = blanked.indexOf('{', m.index + m[0].length - 1);
    if (open < 0) return;
    inline.push({ kind: 'inline', index: m.index, name: '', bodyStart: open + 1, end: skipBraces(blanked, open) });
  };
  for (const m of blanked.matchAll(AE_INLINE)) pushInline(m);
  if (ON_DEF.test(blanked)) for (const m of blanked.matchAll(ON_INLINE)) pushInline(m);

  const bound = [];
  const judged = new Set(inline.map((h) => h.bodyStart));
  const pushRef = (kind, m) => {
    for (const f of asyncByName.get(m[1]) || []) {
      if (judged.has(f.bodyStart)) continue;
      judged.add(f.bodyStart);
      bound.push({ kind, index: m.index, name: m[1], bodyStart: f.bodyStart, end: f.end });
    }
  };
  for (const m of blanked.matchAll(AE_REF)) pushRef('named', m);
  if (ON_DEF.test(blanked)) for (const m of blanked.matchAll(ON_REF)) pushRef('on', m);
  return { inline, bound };
}

function analyze(rel, code) {
  const blanked = blankSingleQuoted(blankNonCode(code, 'js'));
  const fns = splitFunctions(code, 'js');
  // seen 只记**当前仍在判红**的锚点：条目在盘上找不到 ⇒ 该处已修复，必须回收；
  // 「只要函数还在就算命中」会让修好的豁免永远挂着（第二类假绿）。
  const note = (k) => seen.set(k, (seen.get(k) || 0) + 1);
  // ① busy 窗口：见 findBusyViolations
  for (const v of findBusyViolations(blanked, fns)) {
    busyObjects++;
    if (!v.bad) continue;
    const k = keyOf(rel, 'busy-window', v.name);
    note(k);
    if (!exempt.has(k)) g.fail(`${rel}:${lineAt(code, v.index)} [${k}] 置 ${v.name} = true 之后、同一函数内的下一个 try 之前存在 await ⇒ 一次 reject 就永久锁死；未登记在过渡豁免里`);
  }
  // ② handler 出口：逐 await 判 catch 接收者
  const hs = collectHandlers(code, blanked);
  inlineObjects += hs.inline.length;
  const all = [...hs.inline, ...hs.bound];
  const nestedOf = (h) => all
    .filter((o) => o !== h && o.bodyStart > h.bodyStart && o.end <= h.end)
    .map((o) => [o.bodyStart, o.end - 1]);
  for (const h of hs.inline) {
    const gaps = uncoveredAwaits(blanked, h.bodyStart, h.end - 1, nestedOf(h));
    if (!gaps.length) continue;
    const k = keyOf(rel, 'bare-handler', `${anchorOf(code, h.index)}|${firstCodeLines(blanked, h.bodyStart - 1, h.end)}`);
    note(k);
    if (!exempt.has(k)) g.fail(`${rel}:${lineAt(code, h.index)} [${k}] 内联 async 事件处理器有 ${gaps.length} 个 await 没有 catch 接收者（${gaps.map((a) => lineAt(code, a)).join('/')} 行）⇒ IPC reject 静默消失；未登记在过渡豁免里`);
  }
  for (const h of hs.bound) {
    if (h.kind === 'named') namedObjects++; else onObjects++;
    const gaps = uncoveredAwaits(blanked, h.bodyStart, h.end - 1, nestedOf(h));
    if (!gaps.length) continue;
    const k = keyOf(rel, h.kind, h.name);
    note(k);
    if (!exempt.has(k)) g.fail(`${rel}:${lineAt(code, h.index)} [${k}] ${h.kind === 'on' ? 'on() 绑定' : '具名'} async handler ${h.name} 有 ${gaps.length} 个 await 没有 catch 接收者（${gaps.map((a) => lineAt(code, a)).join('/')} 行）⇒ IPC reject 静默消失；未登记在过渡豁免里`);
  }
}

for (const abs of walk(SCRIPTS)) {
  analyze(relative(ROOT, abs).split('\\').join('/'), readFileSync(abs, 'utf8'));
}

// 已登记但盘上找不到的豁免（代码修好了却还挂着 = 第二类假绿；锚点按函数名，不随行号漂移）
for (const [k, t] of exempt) {
  if (!seen.has(k)) g.fail(`TRANSITION 条目失效：${k}（${t.batch}）⇒ 该处已修复或函数已改名，必须回收条目`);
  if (!t.batch || !t.unit || !t.reason || t.reason.length < 8) g.fail(`TRANSITION 条目缺批次/归属单元/理由：${k}`);
}
if (TRANSITION.length > TRANSITION_CAP) {
  g.fail(`TRANSITION 超上限：${TRANSITION.length} > ${TRANSITION_CAP} ⇒ 过渡表只减不增，新增违例必须先修代码`);
}
for (const [k, n] of seen) {
  if (n > 1) g.fail(`锚点不唯一：${k} 命中 ${n} 次 ⇒ 无法逐条登记豁免，请在该函数内改用更细的锚点（本门禁刻意不靠序号偷偷去重）`);
}
if (busyObjects < MIN_BUSY) {
  g.fail(`busy 腿对象地板不成立：只扫到 ${busyObjects} 个 busy 赋值（地板 ${MIN_BUSY}）⇒ BUSY 正则失效，不是仓库变干净`);
}
if (inlineObjects < MIN_INLINE) {
  g.fail(`内联 handler 腿对象地板不成立：只扫到 ${inlineObjects} 个（地板 ${MIN_INLINE}）⇒ 内联回调正则或抹白器失效，不是仓库变干净`);
}
if (namedObjects < MIN_NAMED) {
  g.fail(`具名 handler 腿对象地板不成立：只扫到 ${namedObjects} 个 addEventListener(…, IDENT) 的 async 函数（地板 ${MIN_NAMED}）⇒ AE_REF 或函数解析失效`);
}
if (onObjects < MIN_ON) {
  g.fail(`on() 腿对象地板不成立：只扫到 ${onObjects} 个 on(id,type,IDENT) 的 async 回调（地板 ${MIN_ON}）⇒ ON_REF 失效`);
}
g.ok(`前端 await/出口对账：busy 对象 ${busyObjects} 个 / 内联 async handler ${inlineObjects} 个 / 具名 async handler ${namedObjects} 个 / on() async 回调 ${onObjects} 个（命中 ${seen.size} 处，登记豁免 ${exempt.size} 条）`);

// 合成样本正向对照（每次都跑）
const mk = (body) => `const x = { addEventListener: () => {} };\nfunction run() {\n${body}\n}\n`;
const mkH = (body) => `const el = { addEventListener: () => {} };\nel.addEventListener('click', async () => {\n${body}\n});\n`;
const mkN = (body) => `const el = { addEventListener: () => {} };\nel.addEventListener('click', save);\nasync function save() {\n${body}\n}\n`;
const mkO = (body) => `function on(id, type, handler) { return handler; }\non('btn', 'click', doIt);\nasync function doIt() {\n${body}\n}\n`;
const countHandlerViolations = (code) => {
  const blanked = blankSingleQuoted(blankNonCode(code, 'js'));
  const hs = collectHandlers(code, blanked);
  return [...hs.inline, ...hs.bound].filter((h) => uncoveredAwaits(blanked, h.bodyStart, h.end - 1).length > 0).length;
};
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
  {
    // T1e-L07：`entry` 里的 try 是子串，旧 indexOf 会把窗口截在 await 之前（漏报）。
    kind: 'busy',
    label: 'A6 变量名含 try 子串（entry）不得截断 busy 窗口 ⇒ 必须判红',
    code: mk('  isCleaning = true;\n  const entry = pick();\n  await go();\n  try { x(); } finally { isCleaning = false; }'),
    want: 1,
  },
  { kind: 'handler', label: 'B1 普通内联 async handler 无 catch ⇒ 必须判红', code: mkH('  const r = await api.save();'), want: 1 },
  { kind: 'handler', label: 'B2 内联 handler 的 await 被 try/catch 包住 ⇒ 不判红', code: mkH('  try { await api.save(); } catch (e) { log(e); }'), want: 0 },
  {
    // T1e-L07：双引号事件名在 blankNonCode 后整段变空白，旧 HPAT 的 ['"] 分支永不命中。
    kind: 'handler',
    label: 'B4 双引号事件名的裸 async handler ⇒ 必须判红（不得因抹白而失明）',
    code: 'const el = { addEventListener: () => {} };\nel.addEventListener("click", async () => {\n  await api.save();\n});\n',
    want: 1,
  },
  {
    // T1e-L07：单引号串在 JS 模式不被 blankNonCode 抹白，'try' 会顶护栏词。
    kind: 'handler',
    label: 'B5 字符串字面量里的 try 不算出口 ⇒ 仍必须判红',
    code: mkH("  log('try');\n  await api.save();"),
    want: 1,
  },
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
  {
    // 门禁假绿 #4 的主对照：旧口径对具名 handler 零覆盖。
    kind: 'handler',
    label: 'C1 addEventListener 绑定的具名 async handler 无 catch ⇒ 必须判红',
    code: mkN('  const r = await api.save();'),
    want: 1,
  },
  {
    kind: 'handler',
    label: 'C2 具名 async handler 的 await 被 try/catch 包住 ⇒ 不判红',
    code: mkN('  try { await api.save(); } catch (e) { log(e); }'),
    want: 0,
  },
  {
    kind: 'handler',
    label: 'C3 on(id,type,IDENT) 绑定的具名 async 回调无 catch ⇒ 必须判红',
    code: mkO('  await api.save();'),
    want: 1,
  },
  {
    kind: 'handler',
    label: 'C4 on() 回调的 await 被 try/catch 包住 ⇒ 不判红',
    code: mkO('  try { await api.save(); } catch (e) { log(e); }'),
    want: 0,
  },
  {
    // 「任意位置有 try 即放行」是旧实现的假绿形态，反向钉住：try 不在包裹位置不算。
    kind: 'handler',
    label: 'C5 函数里别处有 try、本 await 仍在 try 外 ⇒ 必须判红',
    code: mkN('  try { await api.x(); } catch (e) { log(e); }\n  await api.save();'),
    want: 1,
  },
  {
    // T1e-L06：try/finally 没有 catch，reject 照样穿过 finally 逃逸。
    kind: 'handler',
    label: 'C6 try/finally 无 catch ⇒ 必须判红（finally 不是 reject 接收者）',
    code: mkN('  try { await api.save(); } finally { done(); }'),
    want: 1,
  },
  {
    kind: 'handler',
    label: 'C7 await 在 try 内的嵌套块里 ⇒ 仍算被包住（不判红）',
    code: mkN('  try { if (ok) { await api.save(); } } catch (e) { log(e); }'),
    want: 0,
  },
  {
    kind: 'handler',
    label: "C8 await 自带 .catch 接收者（await f().catch(…)）⇒ 不判红",
    code: mkN('  const r = await api.save().catch(function () {});'),
    want: 0,
  },
  {
    // 射程边界：没被绑成 handler 的 async 函数由调用方负责，本门禁不越界定罪。
    kind: 'handler',
    label: 'C9 未被事件绑定的具名 async 函数 ⇒ 不在本门禁射程（不判红）',
    code: 'async function helper() {\n  await api.save();\n}\n',
    want: 0,
  },
  {
    kind: 'handler',
    label: 'C10 on() 的内联 async arrow 无 catch ⇒ 必须判红',
    code: "function on(id, type, handler) { return handler; }\non('btn', 'click', async () => {\n  await api.save();\n});\n",
    want: 1,
  },
];
let ctrlBad = 0;
for (const c of CONTROLS) {
  const blanked = blankSingleQuoted(blankNonCode(c.code, 'js'));
  const hits = c.kind === 'busy'
    ? findBusyViolations(blanked, splitFunctions(c.code, 'js')).filter((v) => v.bad).length
    : countHandlerViolations(c.code);
  if (hits !== c.want) { ctrlBad++; console.error(`✗ 正向对照失败：${c.label}（实得 ${hits}，应为 ${c.want}）`); }
}
g.controlFailed(
  ctrlBad,
  CONTROLS.length,
  '正向对照（busy 三向 + 窗口不越函数体两向 + try 子串 + 内联/具名/on 三腿各正反 + 别处 try 不算 + try/finally 不算 + 嵌套块 + .catch 链 + 射程边界）',
);

g.finish('check-async-exits: 全部通过（过渡豁免 ' + exempt.size + ' 条，逐条见 TRANSITION）');
