#!/usr/bin/env node
// check-subwindow-init.mjs —— 副窗口「初始化不崩 + 首屏真的会发请求」行为门禁
//
// 为什么需要它（2026-10-05，用户真机截图坐实）：v0.6.1 把主窗内联的残留面板搬进
// `residue-window.html` 时，容器改名成 rsChainBody / rsDeepBody，而 DOMContentLoaded 里
// 两行绑定仍写着已经不存在的 `el('rsBody')` → 在 null 上取 addEventListener 抛 TypeError
// → **整条初始化中断在 scanAll() 之前**。真机症状是界面永远停在「正在扫描三类残留…」，
// 看起来像功能没做，实际是一行绑定的事。
//
// 这类缺陷为什么现有门禁全测不到：`cargo test` 走 MockRuntime 不建真实 DOM；其余 Node 门禁
// 全是文本层对拍。所以这里**用最小 DOM 桩把脚本真的跑一遍**，断言 ① 初始化不抛错
// ② 初始化期间没有「缺少元素」告警 ③ 首屏请求确实发出。
//
// ② 的判据来自被测代码自己：副窗的绑定走文件里的 `on(id,type,fn)` 时，缺件只 console.warn
// 而不抛错，这条 warn 正好是本门禁的信号，**不需要任何手工豁免表**。
//
// 2026-11-02 门禁假绿 #9 收紧（来源 T1h-M01 / 全仓-2026-11-01-重审 §6.3 第 9 条）：
// 旧版对 models / processManager 两窗是**零信号绿**——两窗的元素绑定全走 `?.` 可选链，
// 缺件时静默 no-op，断言 1/2/3 全绿（T1h 探针 probe-drop-body 实测：抽掉 #mwBody 这种
// 「容器改名」的原始事故形态仍然全绿）。收紧后的判定分三层：
//   ① 结构对拍（断言 7）：脚本里的 `?.` 绑定 ⇄ 同页 HTML 静态 id ⇄ PAGES 台账，三向相等；
//      判定作用在「只抹注释」的代码底稿上，注释里写一遍不算（对照 C2 钉住）。
//   ② 初始化调用 ⇄ 窗口标签/页面一一对应（断言 3）：subwindows.json 的 label → html →
//      script → 调用集合，集合精确相等，且每个调用都能在调用栈里追到本页脚本。
//   ③ 切页/刷新重入不重跑 init（断言 9）：重入一次后 init 期绑定计数不变、调用只按重入路径 +N。
// 为什么不能只做文本对拍：`?.` 把缺件吞成 null，文本里写着 `el('pmCloseBtn')` 也可能从未绑定
// —— 所以静态判定只认「代码区 + 结构对拍」，运行判定只认「桩上真的被调到」。
//
// 过渡表 TRANSITION：两窗的产品侧仍是 `?.` 直挂（未迁 on() 降级 warn），逐条登记、双向咬合
// ——新增未登记即红、登记项消失即红，只减不增；不得整文件跳过。
//
// 合成对照（AGENTS §4.1）：每次运行都跑 C0–C8，`?.` 漏绑 / 注释顶账 / 重入重跑 init /
// 首屏少发调用 / 页面少加载脚本 / 未登记的 `?.` 调用 / 未登记的新绑定 / 失效的过渡条目，
// 任一放行 ⇒ 本门禁自己判红。
//
// 用法：node tools/check-subwindow-init.mjs [--verbose]
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { lineAt } from './lib/src-scan.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src');
const VERBOSE = process.argv.includes('--verbose');

const PAGES = [
  {
    label: 'residue',
    html: 'residue-window.html',
    script: 'scripts/residue-window.js',
    // 断言 3b：本页初始化期间**全部**可观测调用（顺序无关、多重集精确相等）。
    // 这不是「文本里有什么」，而是桩上真的被调到的集合——少一条、多一条都判红。
    initCalls: ['ds.bindCheckboxKeys', 'residueWindow.onTarget', 'settings.getPrefs', 'settings.setPref', 'uninstall.pendingList', 'uninstall.residueScan'],
    // 断言 7：`?.` 元素绑定台账（脚本扫描 ⇄ 本页 HTML id ⇄ 本表 三向相等）。
    // 空 = 本页绑定全走 on() 降级 warn，缺件由断言 2/6 看得见。
    optionalBindings: [],
    // 断言 8：`?.` 能力调用台账；invokeAtInit 的必须在初始化时真的被调到。
    optionalCaps: [{ path: 'ds.bindCheckboxKeys', invokeAtInit: true }],
    // 断言 9：切页/刷新重入动作与「只多发这一次调用」的预期。
    reentry: { id: 'rsRescanBtn', event: 'click', delta: { 'uninstall.residueScan': 1 } },
    // 本窗只由「卸载完成后自动弹出」唤起，appId 经 URL query 带入；无 appId 时前端不发起
    // 扫描请求，所以桩里必须带上 query 才谈得上首屏请求。
    search: '?app=' + encodeURIComponent('HKLM|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TrimProbe'),
    // 注入点：该页 DOMContentLoaded 里的第一行真实语句
    poisonAnchor: 'state.appId = targetFromSearch();',
    // T1h-L02：注入语句必须用**本页自己的取元素助手**（本页是 el(id)），
    // 用错助手抛的是 ReferenceError，正向对照照样红，但没走「缺件 → null」通道。
    poisonCall: "el('notAnElementForControl')",
    dropIdProbe: 'rsBackupToggle',
    // 绑定走 on() 降级 warn 机制 ⇒ 抽件对照（断言 6）有 warn 通道可断
    expectDropWarn: true,
    api: () => ({
      'uninstall.residueScan': async (a) => ({ success: true, data: { appName: '示例程序', findings: [], notes: [] }, _echo: a }),
      'uninstall.residueExecute': async () => ({ success: true, data: { details: [], okCount: 0, failCount: 0 } }),
      'uninstall.pendingRevoke': async () => ({ success: true, data: { revoked: 0 } }),
      'uninstall.pendingList': async () => ({ success: true, data: { entries: [] } }),
      'residueWindow.closeWindow': async () => ({ success: true }),
      'residueWindow.onTarget': () => undefined,
      // 假绿 #9：这三条是脚本里的 `?.` 可选链调用。桩里不给 = 真机缺通道时静默 no-op，
      // 而本门禁看不见（断言 8 现在要求桩面齐全）。真源：tauri-api.js 的
      // settings:get-prefs / settings:set-pref / log:write。
      'settings.getPrefs': async () => ({ success: true, data: {} }),
      'settings.setPref': async () => ({ success: true }),
      'log.write': () => undefined,
    }),
    // `window.ds?.bindCheckboxKeys?.` 同样走可选链：桩不给就静默跳过，键盘勾选没有任何证据。
    ds: { bindCheckboxKeys: () => undefined },
    expectHosts: ['rsChainBody:click'],
  },
  {
    label: 'models',
    html: 'models-window.html',
    script: 'scripts/models-window.js',
    initCalls: ['settings.load'],
    // 假绿 #9 的原始两窗之一：绑定是 `els.refresh?.addEventListener(...)`（先 `els.x = $('id')`
    // 再可选链直挂）。台账按「id:事件」逐条钉住，新增/删改都要同步本表。
    optionalBindings: [
      { id: 'mwRefreshBtn', event: 'click' },
      { id: 'mwCloseBtn', event: 'click' },
    ],
    expectHosts: [],
    optionalCaps: [],
    reentry: { id: 'mwRefreshBtn', event: 'click', delta: { 'settings.load': 1 } },
    poisonAnchor: 'function init() {',
    // 本页助手是 $(id)（models-window.js 顶部），不是 el()
    poisonCall: "$('notAnElementForControl')",
    api: () => ({
      'settings.load': async () => ({ success: true, data: { models: {}, modelDefaults: {} } }),
      'models.save': async () => ({ success: true }),
      'models.test': async () => ({ success: true, data: { ok: true } }),
      'modelsWindow.close': async () => ({ success: true }),
      // `window.api?.app?.openDoc?.(...)`：点击文档入口才走，但桩面必须齐全（断言 8）。
      'app.openDoc': async () => ({ ok: true }),
    }),
  },
  {
    label: 'processManager',
    html: 'process-manager-window.html',
    script: 'scripts/process-manager-window.js',
    // 首屏 = load() ⇒ ProcessTools.fetchProcesses()；render 侧的 renderTree 同属初始化可见面。
    initCalls: ['ProcessTools.fetchProcesses', 'ProcessTools.renderTree'],
    optionalBindings: [
      { id: 'pmCloseBtn', event: 'click' },
      { id: 'pmRefreshBtn', event: 'click' },
      { id: 'pmSearch', event: 'input' },
    ],
    expectHosts: [],
    optionalCaps: [],
    reentry: { id: 'pmRefreshBtn', event: 'click', delta: { 'ProcessTools.fetchProcesses': 1, 'ProcessTools.renderTree': 1 } },
    poisonAnchor: 'function init() {',
    poisonCall: "el('notAnElementForControl')",
    api: () => ({
      'processManager.report': (a) => a,
      'processManager.closeWindow': async () => ({ success: true }),
    }),
    // 该窗的进程列表经 window.ProcessTools（非 tauri api 表）拉取，桩里同样计数
    extraGlobals: () => ({
      ProcessTools: {
        fetchProcesses: async () => [],
        renderTree: () => {},
      },
    }),
  },
];

// 页数地板：capabilities/subwindows.json 登记的每个子窗 label 必须有对应 PAGES 条目
// （label 驼峰 ⇄ html 文件 kebab 的映射表在此，改文件名同步改这里）。漏窗 = 该窗的
// 「初始化不崩 + 首屏真的会发请求」无人看守。
const LABEL_HTML = {
  models: 'models-window.html',
  processManager: 'process-manager-window.html',
  residue: 'residue-window.html',
};

// 断言 3a：页面脚本用到的 window 级组件必须由本页 HTML 真加载。
// 桩里无条件提供这些全局件 ⇒ 少加载一个 <script> 旧版完全看不见（真机整页绑死）。
const GLOBAL_PROVIDER = {
  ds: 'scripts/ds.js',
  subToast: 'scripts/sub-toast.js',
  modal: 'scripts/modal.js',
  intro: 'scripts/intro.js',
  ProcessTools: 'scripts/processes.js',
};

// 过渡表：两窗仍是 `?.` 直挂（产品侧未迁 on() 降级 warn，缺件静默）。逐条登记、双向咬合：
// 登记项在脚本里消失 ⇒ 判红（条目该删）；脚本里出现未登记的 `?.` 绑定 ⇒ 判红（只减不增）。
// 迁 on(id,type,fn) 后必须删除对应条目。理由里不写行号（会随插行漂）。
const TRANSITION = [
  {
    file: 'src/scripts/models-window.js',
    fn: 'init',
    id: 'mwRefreshBtn:click',
    batch: 'v7.2 假绿#9 / T1h-M01',
    reason: '刷新按钮是 els.refresh?.addEventListener 可选链直挂：缺件静默 no-op，没有 warn 通道。当前由断言 7 的结构对拍（脚本 ⇄ 本页 HTML id ⇄ 台账三向相等）+ 断言 4 的实绑证据兜住；迁 on() 降级告警后删除本条目',
  },
  {
    file: 'src/scripts/models-window.js',
    fn: 'init',
    id: 'mwCloseBtn:click',
    batch: 'v7.2 假绿#9 / T1h-M01',
    reason: '关闭按钮同上（els.close?.addEventListener）：缺件静默，右上一个点了没反应的按钮不会有任何告警。结构对拍 + 实绑证据兜住；迁 on() 后删除本条目',
  },
  {
    file: 'src/scripts/process-manager-window.js',
    fn: 'init',
    id: 'pmCloseBtn:click',
    batch: 'v7.2 假绿#9 / T1h-M01',
    reason: '关闭按钮是 el(pmCloseBtn)?.addEventListener 直挂：缺件静默 no-op。结构对拍 + 实绑证据兜住；迁 on() 后删除本条目',
  },
  {
    file: 'src/scripts/process-manager-window.js',
    fn: 'init',
    id: 'pmRefreshBtn:click',
    batch: 'v7.2 假绿#9 / T1h-M01',
    reason: '刷新按钮同上：这是断言 9 的切页/刷新重入入口，绑定没发生就没有任何证据能看见列表读不动了。迁 on() 后删除本条目',
  },
  {
    file: 'src/scripts/process-manager-window.js',
    fn: 'init',
    id: 'pmSearch:input',
    batch: 'v7.2 假绿#9 / T1h-M01',
    reason: '搜索框同上：缺件时输入框变哑巴且零告警。结构对拍 + 实绑证据兜住；迁 on() 后删除本条目',
  },
];

let fail = 0;
let skipped = 0;
const skip = (label, detail = '') => {
  console.log(`– SKIP ${label}${detail ? ' — ' + detail : ''}`);
  skipped++;
};
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
  return ok;
};

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const escRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const flush = () => new Promise((r) => setTimeout(r, 0));

// ---- 只抹注释的扫描底稿（字符串原样保留：判定要读 `el('id')` 里的 id） ----
// 为什么不用 tools/lib/src-scan.mjs 的 blankNonCode：它的模板串插值靠 skipBraces 配平，
// 不认插值里的**嵌套模板串**；models-window.js 的 render() 正是「模板里嵌模板」，
// 实测从该函数之后整个文件被抹成空白 —— 扫描器恰好在绑定所在处失明（假绿 #9 的同一类事故）。
// 这里用「模板 / 插值 / 注释 / 正则」四种状态各自配平，注释抹成等长空格（行号不漂）。
function skipQuoted(text, i) {
  const q = text[i];
  let j = i + 1;
  while (j < text.length) {
    if (text[j] === '\\') { j += 2; continue; }
    if (text[j] === q) return j + 1;
    if (text[j] === '\n') return j + 1; // 未闭合的普通串：按行尾收口
    j++;
  }
  return j;
}
function skipBlockComment(text, i) {
  let j = i + 2;
  while (j < text.length && !(text[j] === '*' && text[j + 1] === '/')) j++;
  return Math.min(text.length, j + 2);
}
function skipInterp(text, i) {
  let depth = 1;
  while (i < text.length) {
    const c = text[i];
    if (c === "'" || c === '"') { i = skipQuoted(text, i); continue; }
    if (c === '`') { i = skipTemplate(text, i); continue; }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (c === '/' && text[i + 1] === '*') { i = skipBlockComment(text, i); continue; }
    if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return i;
    i++;
  }
  return text.length;
}
function skipTemplate(text, i) {
  let j = i + 1;
  while (j < text.length) {
    if (text[j] === '\\') { j += 2; continue; }
    if (text[j] === '`') return j + 1;
    if (text[j] === '$' && text[j + 1] === '{') { j = skipInterp(text, j + 2) + 1; continue; }
    j++;
  }
  return j;
}
function blankJsComments(text) {
  const out = text.split('');
  const blank = (a, b) => { for (let i = a; i < b && i < out.length; i++) if (out[i] !== '\n' && out[i] !== '\r') out[i] = ' '; };
  let i = 0;
  let prevSig = '';
  // `/` 是正则起点还是除号：标识符/数字/右括号结尾 ⇒ 除号
  const regexAllowed = () => !prevSig || !/[0-9A-Za-z_$)\]}]/.test(prevSig);
  while (i < text.length) {
    const c = text[i];
    if (c === '/' && text[i + 1] === '/') {
      let j = i;
      while (j < text.length && text[j] !== '\n') j++;
      blank(i, j);
      i = j;
      continue;
    }
    if (c === '/' && text[i + 1] === '*') { const j = skipBlockComment(text, i); blank(i, j); i = j; continue; }
    if (c === "'" || c === '"') { i = skipQuoted(text, i); prevSig = c; continue; }
    if (c === '`') { i = skipTemplate(text, i); prevSig = '`'; continue; }
    if (c === '/' && regexAllowed()) {
      let j = i + 1, inClass = false, closed = false;
      while (j < text.length) {
        const e = text[j];
        if (e === '\\') { j += 2; continue; }
        if (e === '\n') break;
        if (inClass) { if (e === ']') inClass = false; j++; continue; }
        if (e === '[') { inClass = true; j++; continue; }
        if (e === '/') { closed = true; j++; break; }
        j++;
      }
      if (closed) { while (j < text.length && /[a-z]/.test(text[j])) j++; i = j; prevSig = '/'; continue; }
    }
    if (!/\s/.test(c)) prevSig = c;
    i++;
  }
  return out.join('');
}

/** 多重集差：a 里比 b 多出来的项（含重复计数）。 */
function multisetDiff(a, b) {
  const rest = new Map();
  for (const x of b) rest.set(x, (rest.get(x) || 0) + 1);
  const out = [];
  for (const x of a) {
    const n = rest.get(x) || 0;
    if (n > 0) rest.set(x, n - 1);
    else out.push(x);
  }
  return out;
}

/**
 * 桩面清单：本页能不能「看见」某个可选链调用，取决于这里有没有对应路径。
 * 结构判定（断言 8）与运行判定共用这一份清单，不另抄一套。
 */
function stubInventory(page) {
  const s = new Set(['subToast.hintLine', 'ds.esc', 'ds.escAttr', 'ds.fmtBytes']);
  for (const flat of Object.keys(page.api())) {
    const [ns, m] = flat.split('.');
    s.add(`api.${ns}.${m}`);
  }
  for (const m of Object.keys(page.ds || {})) s.add(`ds.${m}`);
  for (const [name, obj] of Object.entries(page.extraGlobals ? page.extraGlobals() : {})) {
    for (const [m, fn] of Object.entries(obj)) if (typeof fn === 'function') s.add(`${name}.${m}`);
  }
  return s;
}

/** 页面脚本里的取元素助手（`function el(id){return document.getElementById(id)}` 一类）。 */
function findHelpers(code) {
  return [...code.matchAll(/function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{\s*return\s+document\.getElementById\(\s*\2\s*\)/g)].map((m) => m[1]);
}

/** 从 `?.` 的 `?` 处往前收回接收者链（`?.` 归一成 `.`）。 */
function readChainBackward(code, at) {
  let i = at;
  while (i > 0 && /[A-Za-z0-9_$.?\]\[]/.test(code[i - 1])) i--;
  return code.slice(i, at).replace(/\?\./g, '.');
}

/** 取 `?.addEventListener(` 的接收者：`el('x')` / `$('x')` / `document.getElementById('x')` / `els.x`。 */
function readReceiver(code, at) {
  let j = at;
  while (j > 0 && /\s/.test(code[j - 1])) j--;
  if (code[j - 1] === ')') {
    let depth = 0;
    let k = j - 1;
    for (; k >= 0; k--) {
      if (code[k] === ')') depth++;
      else if (code[k] === '(' && --depth === 0) break;
    }
    if (k < 0) return { kind: 'unknown', text: '?' };
    let s = k;
    while (s > 0 && /[A-Za-z0-9_$.]/.test(code[s - 1])) s--;
    const callee = code.slice(s, k);
    const lit = code.slice(k + 1, j - 1).match(/^\s*'([^']+)'\s*$/);
    return { kind: 'call', callee, arg: lit ? lit[1] : null, text: `${callee}(…)` };
  }
  let s = j;
  while (s > 0 && /[A-Za-z0-9_$.]/.test(code[s - 1])) s--;
  return { kind: 'chain', text: code.slice(s, j) };
}

/** 脚本里的 `?.` 元素绑定（连同 `els.x = $('id')` 这类别名一起解析）。 */
function scanOptionalBindings(code, helpers) {
  const alias = new Map();
  const helperAlt = [...helpers, 'getElementById'].map(escRe).join('|');
  const assignRe = new RegExp(String.raw`([A-Za-z_$][\w$]*)(?:\.([A-Za-z_$][\w$]*))?\s*=\s*(?:document\.)?(?:${helperAlt})\(\s*'([^']+)'\s*\)`, 'g');
  for (const m of code.matchAll(assignRe)) alias.set(m[2] ? `${m[1]}.${m[2]}` : m[1], m[3]);
  const out = [];
  for (const m of code.matchAll(/\?\.\s*addEventListener\s*\(/g)) {
    const recv = readReceiver(code, m.index);
    const ev = (code.slice(m.index + m[0].length).match(/^\s*'([^']+)'/) || [])[1] || null;
    const line = lineAt(code, m.index);
    if (recv.kind === 'call') {
      const isHelper = recv.callee === 'getElementById' || helpers.includes(recv.callee);
      if (isHelper && recv.arg) out.push({ kind: 'element', id: recv.arg, event: ev, line });
      else out.push({ kind: 'unresolved', id: null, event: ev, line, why: `接收者 ${recv.text} 不是本页取元素助手` });
    } else if (recv.kind === 'chain') {
      if (recv.text === 'document') out.push({ kind: 'document', id: null, event: ev, line });
      else {
        const id = alias.get(recv.text) || null;
        out.push(id
          ? { kind: 'element', id, event: ev, line }
          : { kind: 'unresolved', id: null, event: ev, line, why: `接收者 ${recv.text} 未在本页解析成元素 id` });
      }
    } else out.push({ kind: 'unresolved', id: null, event: ev, line, why: '接收者形状无法解析' });
  }
  return { alias, bindings: out };
}

/** 脚本里的取元素调用（el/$/getElementById/on）⇄ 本页 HTML 静态 id 的对拍底稿。 */
function scanElementRefs(code, helpers) {
  const refs = new Map();
  for (const h of [...helpers, 'getElementById']) {
    const re = new RegExp(String.raw`(?:document\.)?${escRe(h)}\(\s*'([^']+)'`, 'g');
    for (const m of code.matchAll(re)) if (!refs.has(m[1])) refs.set(m[1], h);
  }
  for (const m of code.matchAll(/\bon\(\s*'([^']+)'\s*,/g)) if (!refs.has(m[1])) refs.set(m[1], 'on');
  return refs;
}

/**
 * `?.` 可选链**调用**（`window.api?.settings?.getPrefs?.()` / `window.ds?.bindCheckboxKeys?.()`
 * 一类，任务书里的 `window.x?.init?.()` 同形）。只认 window 根：脚本自有局部对象
 * （`trap?.release()`）归脚本自己管，不在本门禁射程。
 */
function scanOptionalCalls(code) {
  const out = [];
  for (const m of code.matchAll(/\?\.\s*([A-Za-z_$][\w$]*)\s*(?:\?\.)?\s*\(/g)) {
    const chain = readChainBackward(code, m.index);
    if (!chain.startsWith('window.')) continue;
    out.push({ segs: chain.split('.').slice(1), method: m[1], line: lineAt(code, m.index) });
  }
  return out;
}

/** 断言 3a：label → html → script，以及脚本用到的组件全局件确实由本页 HTML 加载。 */
function judgeWiring(page, htmlText, code) {
  const v = [];
  const scripts = [...htmlText.matchAll(/<script[^>]*\bsrc="([^"]+)"/g)].map((m) => m[1].replace(/^\.\//, '').replace(/\\/g, '/'));
  if (!scripts.includes(page.script)) v.push(`本页 HTML 没加载本页脚本 <script src="${page.script}">`);
  const used = new Set([...code.matchAll(/window\.([A-Za-z_$][\w$]*)/g)].map((m) => m[1]));
  for (const g of used) {
    if (g === 'api' || !GLOBAL_PROVIDER[g]) continue;
    if (!scripts.includes(GLOBAL_PROVIDER[g])) v.push(`脚本用到 window.${g}，但本页 HTML 没加载 ${GLOBAL_PROVIDER[g]}`);
  }
  return v;
}

/** 断言 7：脚本里的 `?.` 绑定 ⇄ 本页 HTML 静态 id ⇄ PAGES 台账，三向相等。 */
function judgeElementLedger(page, htmlText, code) {
  const v = [];
  const helpers = findHelpers(code);
  if (helpers.length === 0) v.push('本页取元素助手没找到（脚本形状变了，扫描面失明）');
  const ids = new Set([...htmlText.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
  const refs = scanElementRefs(code, helpers);
  for (const [id, fn] of refs) if (!ids.has(id)) v.push(`脚本引用了本页 HTML 不存在的 #${id}（${fn}）`);
  const { bindings } = scanOptionalBindings(code, helpers);
  for (const b of bindings) {
    if (b.kind === 'unresolved') { v.push(`第 ${b.line} 行的 ?. 绑定解析不出元素 id：${b.why}`); continue; }
    if (b.kind === 'document') continue;
    if (!ids.has(b.id)) v.push(`第 ${b.line} 行的 ?. 绑定 #${b.id} 不在本页 HTML 静态 id 里（缺件会静默 no-op）`);
  }
  const scanned = new Set(bindings.filter((b) => b.kind === 'element').map((b) => `${b.id}:${b.event}`));
  const declared = new Set(page.optionalBindings.map((b) => `${b.id}:${b.event}`));
  for (const k of scanned) if (!declared.has(k)) v.push(`脚本里的 ?. 绑定 ${k} 没登记进 PAGES 台账（新增绑定必须记账）`);
  for (const k of declared) if (!scanned.has(k)) v.push(`PAGES 台账的 ?. 绑定 ${k} 在脚本里找不到（删绑定/改名后同步台账）`);
  return { violations: v, bindings, scanned, declared };
}

/** 断言 8：脚本里的 `?.` 调用必须在桩面里（否则真机缺通道时静默 no-op，本门禁看不见）。 */
function judgeOptionalCalls(page, code, inventory) {
  const v = [];
  const calls = scanOptionalCalls(code);
  for (const c of calls) {
    const path = c.segs[0] === 'api'
      ? (c.segs.length === 2 ? `api.${c.segs[1]}.${c.method}` : null)
      : `${c.segs[0]}.${c.method}`;
    if (!path) { v.push(`第 ${c.line} 行的 ?. 调用路径无法解析（window.${c.segs.join('.')}?.${c.method}）`); continue; }
    if (!inventory.has(path)) v.push(`第 ${c.line} 行的 ?. 调用 ${path} 在桩里不存在（真机缺通道时静默 no-op）`);
  }
  return { violations: v, calls };
}

/**
 * 最小 DOM 桩：只实现被测脚本用到的那些面，且**严格按本页 HTML 的静态 id 决定
 * getElementById 能不能拿到东西** —— 脚本引用了本页没有的 id 就会像真机一样拿到 null。
 * 节点会记住处理器，供断言 9 的「切页/刷新重入」真实触发。
 */
function buildCtx(page, opts = {}) {
  const htmlText = opts.htmlText ?? readFileSync(join(SRC, page.html), 'utf8');
  let text = opts.scriptText ?? readFileSync(join(SRC, page.script), 'utf8');
  const staticIds = new Set([...htmlText.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
  for (const id of opts.dropIds || []) staticIds.delete(id);
  const calls = [];
  const bound = [];
  const warns = [];

  const mkNode = (id) => {
    const handlers = Object.create(null);
    return {
      id,
      hidden: false,
      checked: false,
      disabled: false,
      value: '',
      type: 'text',
      textContent: '',
      innerHTML: '',
      style: {},
      dataset: {},
      classList: { toggle: () => {}, add: () => {}, remove: () => {}, contains: () => false },
      setAttribute: () => {},
      getAttribute: () => null,
      removeAttribute: () => {},
      addEventListener(t, fn) {
        bound.push(`${id}:${t}`);
        (handlers[t] ||= []).push(fn);
      },
      /** 断言 9 用：按真机口径触发一次已注册的处理器（快照，避免重入时无限递归）。 */
      fire(t, ev) {
        const list = (handlers[t] || []).slice();
        for (const fn of list) fn(ev);
        return list.length > 0;
      },
      appendChild: () => {},
      remove: () => {},
      focus: () => {},
      querySelector: () => null,
      querySelectorAll: () => [],
      closest: () => null,
      insertAdjacentHTML: () => {},
      scrollIntoView: () => {},
    };
  };
  const nodes = new Map();
  const doc = {
    getElementById(id) {
      if (!staticIds.has(id)) return null;
      if (!nodes.has(id)) nodes.set(id, mkNode(id));
      return nodes.get(id);
    },
    addEventListener(type, fn) {
      // T1h-L06：按 type 收集为数组（真机同一事件可注册多个处理器）。
      ((doc._handlers ||= {})[type] ||= []).push(fn);
      bound.push(`document:${type}`);
    },
    removeEventListener: () => {},
    querySelector: () => null,
    querySelectorAll: () => [],
    createElement: () => mkNode('created'),
    createDocumentFragment: () => mkNode('frag'),
    body: mkNode('body'),
    documentElement: mkNode('html'),
    head: mkNode('head'),
    // 真机加载期 readyState 恒 'loading'——models/residue 等窗的脚本按它分流
    // （'loading' ⇒ DOMContentLoaded 注册，否则直接 init）。缺这个字段会让
    // 脚本走 else 分支直接 init，DOMContentLoaded 判定失明。
    readyState: 'loading',
  };

  // window.api.<ns>.<method> 由扁平表造出来；表里没有的方法**故意不存在**：
  // 脚本调它就像真机一样抛 TypeError，本门禁据此判红，而不是替它兜住。
  // 记录调用栈：断言 3c 要求每个首屏调用都能追到本页脚本。
  const api = {};
  for (const [flat, fn] of Object.entries(page.api())) {
    const [ns, m] = flat.split('.');
    (api[ns] ||= {})[m] = (...args) => {
      calls.push({ name: flat, stack: new Error().stack || '' });
      return fn(...args);
    };
  }

  const ds = { esc, escAttr: esc, fmtBytes: (n) => String(n) };
  for (const [m, fn] of Object.entries(page.ds || {})) {
    ds[m] = (...args) => {
      calls.push({ name: `ds.${m}`, stack: new Error().stack || '' });
      return fn(...args);
    };
  }

  const win = {
    api,
    ds,
    location: { search: page.search || '', href: 'http://localhost/' + page.html },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    subToast: { hintLine: () => {} },
    modal: null,
    intro: { mountIntroPanel: () => ({}) },
    confirmDanger: async () => true,
  };
  // 非 api 表的全局对象（如 ProcessTools）同样进桩并计数——它们的首屏调用与
  // api 方法在「首屏真的会动」的判据里同权。
  for (const [name, obj] of Object.entries(page.extraGlobals ? page.extraGlobals() : {})) {
    for (const [m, fn] of Object.entries(obj)) {
      if (typeof fn !== 'function') continue;
      obj[m] = (...args) => {
        calls.push({ name: `${name}.${m}`, stack: new Error().stack || '' });
        return fn(...args);
      };
    }
    win[name] = obj;
  }
  const ctx = vm.createContext({
    document: doc,
    window: win,
    location: win.location,
    localStorage: win.localStorage,
    navigator: { userAgent: 'node' },
    console: {
      log: () => {},
      debug: () => {},
      info: () => {},
      warn: (...a) => warns.push(a.join(' ')),
      error: (...a) => warns.push('error:' + a.join(' ')),
    },
    setTimeout: (fn) => { fn(); return 0; },
    clearTimeout: () => {},
    setInterval: () => 0,
    clearInterval: () => {},
    requestAnimationFrame: () => 0,
    URLSearchParams,
    Promise,
    JSON,
    Math,
    Date,
    Object,
    Array,
    String,
    Number,
    Boolean,
    Map,
    Set,
    WeakMap,
    Error,
    RegExp,
    Intl,
    encodeURIComponent,
    decodeURIComponent,
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
  });
  win.document = doc;

  if (opts.poison) {
    if (!text.includes(opts.poison)) throw new Error(`正向对照锚点没命中：${opts.poison}`);
    const call = page.poisonCall || "el('notAnElementForControl')";
    text = text.replace(opts.poison, `${opts.poison}\n    ${call}.addEventListener('click', function () {});`);
  }
  return {
    ctx,
    doc,
    calls,
    bound,
    warns,
    text,
    fire: (id, type, ev) => (nodes.has(id) ? nodes.get(id).fire(type, ev) : false),
  };
}

/** 跑一遍某页的初始化，返回可判定的全部事实 */
async function runInit(page, opts = {}) {
  const b = buildCtx(page, opts);
  let threw = null;
  try {
    vm.runInContext(b.text, b.ctx, { filename: page.script });
    // T1h-L06：同一脚本可能注册多个 DOMContentLoaded（真机全部会跑）。
    const hs = (b.doc._handlers && b.doc._handlers.DOMContentLoaded) || [];
    if (hs.length === 0) threw = '脚本没有注册 DOMContentLoaded 处理器';
    else for (const h of hs) await h();
  } catch (e) {
    threw = `${e && e.constructor ? e.constructor.name : 'Error'}: ${(e && e.message) || e}`;
  }
  await flush();
  return { ...b, threw };
}

/** 断言 3b/3c：初始化调用 ⇄ 台账精确相等，且每个调用都真的由本页脚本发出。 */
function judgeInit(page, r) {
  const got = r.calls.map((c) => c.name).sort();
  const want = [...page.initCalls].sort();
  const missing = multisetDiff(want, got);
  const extra = multisetDiff(got, want);
  const foreign = r.calls.filter((c) => !String(c.stack).includes(page.script)).map((c) => c.name);
  return { got, want, missing, extra, foreign };
}

/**
 * 断言 9：切页/刷新重入一次，init 只跑一次的可见证据 = ① init 期登记的每个绑定计数不变
 * （重跑 init 会让 document:keydown / 按钮 click 翻倍）② 调用只按重入路径 +N。
 * 桩里没有动态子节点，所以「重入后绑定计数不变」成立的前提是本页不靠 render 再绑静态 id。
 */
async function runReentry(page, opts = {}) {
  const r = await runInit(page, opts);
  const count = (xs) => {
    const m = new Map();
    for (const x of xs) m.set(x, (m.get(x) || 0) + 1);
    return m;
  };
  const before = count(r.bound);
  const beforeCalls = count(r.calls.map((c) => c.name));
  const fired = r.fire(page.reentry.id, page.reentry.event, { key: '', target: null });
  await flush();
  return { r, fired, before, after: count(r.bound), beforeCalls, afterCalls: count(r.calls.map((c) => c.name)) };
}

function judgeReentry(page, re) {
  const v = [];
  if (!re.fired) v.push(`重入动作 #${page.reentry.id}:${page.reentry.event} 没有处理器（绑定没发生或事件名改了）`);
  const keys = new Set([...re.before.keys(), ...re.after.keys()]);
  const grew = [];
  for (const k of keys) {
    const a = re.before.get(k) || 0;
    const b = re.after.get(k) || 0;
    if (a !== b) grew.push(`${k} ${a}→${b}`);
  }
  if (grew.length) v.push(`重入后 init 期绑定计数变了（init 被重跑）：${grew.join('、')}`);
  const callKeys = new Set([...re.beforeCalls.keys(), ...re.afterCalls.keys()]);
  const delta = [];
  for (const k of callKeys) {
    const a = re.beforeCalls.get(k) || 0;
    const b = re.afterCalls.get(k) || 0;
    const want = (page.reentry.delta[k] || 0);
    if (b - a !== want) delta.push(`${k} 期望 +${want}，实际 +${b - a}`);
  }
  if (delta.length) v.push(`重入只该走本页重入路径：${delta.join('、')}`);
  const observed = [...callKeys].filter((k) => (re.afterCalls.get(k) || 0) - (re.beforeCalls.get(k) || 0) !== 0);
  return { violations: v, observed };
}

/** 断言 10：过渡表与脚本扫描双向咬合（登记项必须还真实存在；扫到的必须都已登记）。 */
function judgeTransition(scans) {
  const v = [];
  for (const t of TRANSITION) {
    if (!t.file || !t.fn || !t.id || !t.batch) v.push(`TRANSITION 条目缺字段：${t.file}#${t.fn} ${t.id || ''}`);
    if (!t.reason || t.reason.length < 8) v.push(`TRANSITION 条目缺理由：${t.file}#${t.id || t.fn}`);
    if (/\.js:\d+/.test(t.reason || '')) v.push(`TRANSITION 理由里带行号（会随插行漂移）：${t.file}#${t.id}`);
    const page = PAGES.find((p) => `src/${p.script}` === t.file);
    if (!page) { v.push(`TRANSITION 条目指向未纳入 PAGES 的文件：${t.file}`); continue; }
    const scan = scans.get(page.html);
    if (!scan) { v.push(`TRANSITION 条目所指页面没被扫描：${t.file}`); continue; }
    if (!scan.bindings.some((b) => b.kind === 'element' && `${b.id}:${b.event}` === t.id)) {
      v.push(`TRANSITION 条目已失效（脚本里没有 ${t.id}）：${t.file}#${t.fn}——绑定已迁走/改名，条目必须删掉`);
    }
    const fns = new RegExp(String.raw`\bfunction\s+${escRe(t.fn)}\s*\(`).test(blankJsComments(readFileSync(join(ROOT, t.file), 'utf8')));
    if (!fns) v.push(`TRANSITION 条目的函数锚点不存在：${t.file}#${t.fn}`);
  }
  for (const page of PAGES) {
    const scan = scans.get(page.html);
    if (!scan) continue;
    for (const b of scan.bindings) {
      if (b.kind !== 'element') continue;
      const key = `${b.id}:${b.event}`;
      if (!TRANSITION.some((t) => t.file === `src/${page.script}` && t.id === key)) {
        v.push(`${page.html} 的 ?. 绑定 ${key} 未登记过渡表（只减不增：要么迁 on()，要么补条目）`);
      }
    }
  }
  return v;
}

console.log('=== 副窗初始化与首屏请求门禁 ===\n');

// 页数地板（判据见 LABEL_HTML 注释）。
const sub = JSON.parse(readFileSync(join(ROOT, 'src-tauri', 'capabilities', 'subwindows.json'), 'utf8'));
const labels = sub.windows || [];
// T1h-L01：`windows` 缺失/改键/置空时 labels=[]，下面那条 missing 检查是零对象绿。
check(
  labels.length > 0,
  '0a. subwindows.json 的 windows 清单非空（0 个 = 页数地板没有对照集）',
  `解析得 ${labels.length} 个 label`,
);
const missingPages = labels.filter((l) => !LABEL_HTML[l] || !PAGES.some((p) => p.html === LABEL_HTML[l]));
check(
  missingPages.length === 0,
  `0. 页数地板：PAGES 覆盖 subwindows.json 的全部 ${labels.length} 个子窗`,
  missingPages.length ? `缺：${missingPages.join('、')}` : PAGES.map((p) => p.html).join(', '),
);
// T1h-L01 反向：磁盘上的子窗页面必须都有 PAGES 条目（新增 html 而漏登记 = 无人看守）
const diskWindows = readdirSync(SRC).filter((n) => /-window\.html$/.test(n));
const unlisted = diskWindows.filter((n) => !PAGES.some((p) => p.html === n));
check(
  unlisted.length === 0,
  `0b. src/*-window.html 全部有 PAGES 条目（${diskWindows.length} 个页面文件）`,
  unlisted.length ? `未登记：${unlisted.join('、')}` : diskWindows.join(', '),
);
// T1h-L01：initCalls 为空时断言 3b 的集合相等也是零对象绿
const noExpect = PAGES.filter((p) => !p.initCalls.length).map((p) => p.html);
check(
  noExpect.length === 0,
  '0c. 每页都登记了首屏调用集合（initCalls 为空 = 断言 3b 零对象绿）',
  noExpect.length ? `未登记：${noExpect.join('、')}` : PAGES.map((p) => `${p.label}:${p.initCalls.length}`).join(' | '),
);
// 假绿 #9：label → html → script 必须是双射（两窗共用一个页面、或 label 与 PAGES 对不上，
// 都会让「初始化调用 ⇄ 窗口标签」失去一一对应）
const wireBad = [];
for (const p of PAGES) {
  if (!labels.includes(p.label)) wireBad.push(`${p.html} 的 label=${p.label} 不在 subwindows.json`);
  if (LABEL_HTML[p.label] !== p.html) wireBad.push(`LABEL_HTML[${p.label}]=${LABEL_HTML[p.label]} ≠ ${p.html}`);
}
for (const l of labels) {
  const hits = PAGES.filter((p) => p.label === l);
  if (hits.length !== 1) wireBad.push(`label=${l} 命中 ${hits.length} 个 PAGES 条目`);
}
check(
  wireBad.length === 0,
  `0d. 窗口标签 ⇄ 页面 ⇄ 脚本一一对应（${labels.length} 个 label 与 ${PAGES.length} 个 PAGES 条目双射）`,
  wireBad.length ? wireBad.join(' | ') : labels.map((l) => `${l}→${LABEL_HTML[l]}`).join(', '),
);

const scans = new Map();

for (const page of PAGES) {
  const tag = page.html;
  const htmlText = readFileSync(join(SRC, page.html), 'utf8');
  const scriptText = readFileSync(join(SRC, page.script), 'utf8');
  const code = blankJsComments(scriptText);
  const inventory = stubInventory(page);

  // ---- 断言 3a：label → 本页脚本 / 组件提供脚本确实被 HTML 加载 ----
  const wireV = judgeWiring(page, htmlText, code);
  check(
    wireV.length === 0,
    `3a. ${page.label} → ${tag} → ${page.script}：本页 HTML 确实加载了本页脚本与依赖组件`,
    wireV.length ? wireV.join(' | ') : page.script,
  );

  // ---- 断言 7：`?.` 绑定 / 取元素调用 ⇄ HTML id ⇄ 台账 ----
  const ledger = judgeElementLedger(page, htmlText, code);
  scans.set(tag, ledger);
  const bindDesc = [...ledger.scanned].join(',') || '(none)';
  check(
    ledger.violations.length === 0,
    `7. ${tag} 的 ?. 绑定台账三向对拍（${ledger.scanned.size} 条：${bindDesc}）`,
    ledger.violations.length ? ledger.violations.join(' | ') : `取元素引用 ${scanElementRefs(code, findHelpers(code)).size} 个，全部存在于本页 HTML`,
  );

  // ---- 断言 8：`?.` 调用必须落在桩面上（真机缺通道时静默 no-op 的唯一可见处） ----
  const capV = judgeOptionalCalls(page, code, inventory);
  for (const cap of page.optionalCaps) {
    if (!inventory.has(cap.path)) capV.violations.push(`能力台账 ${cap.path} 在桩里不存在`);
  }
  check(
    capV.violations.length === 0,
    `8. ${tag} 的 ?. 调用都在桩面上（${capV.calls.length} 处可选调用 / ${page.optionalCaps.length} 条能力台账）`,
    capV.violations.length ? capV.violations.join(' | ') : capV.calls.map((c) => `${c.segs.join('?.')}?.${c.method}`).join(', ') || '(none)',
  );

  // ---- 运行面：断言 1 / 2 / 3b / 3c ----
  const r = await runInit(page, { htmlText, scriptText });
  check(!r.threw, `1. ${tag} 的 DOMContentLoaded 未抛错`, r.threw || '');
  check(r.warns.length === 0, `2. ${tag} 初始化期间没有「缺少元素/异常」告警`, r.warns.join(' | '));
  const initV = judgeInit(page, r);
  check(
    initV.missing.length === 0 && initV.extra.length === 0,
    `3b. ${tag} 的初始化调用集合与台账精确一致（${page.initCalls.length} 条，label=${page.label}）`,
    initV.missing.length || initV.extra.length
      ? `少：${initV.missing.join('、') || '-'}；多：${initV.extra.join('、') || '-'}`
      : initV.got.join(',') || '(none)',
  );
  check(
    initV.foreign.length === 0,
    `3c. ${tag} 的每个初始化调用都来自本页脚本（调用栈归属）`,
    initV.foreign.length ? `追不到 ${page.script} 的调用：${initV.foreign.join('、')}` : `${r.calls.length} 个调用全部命中 ${page.script}`,
  );

  // ---- 断言 4：绑定方式已入账，且每条在运行期真的绑上了 ----
  const declaredBindings = [
    ...page.expectHosts.map((k) => ({ key: k, why: 'on() 委托宿主' })),
    ...page.optionalBindings.map((b) => ({ key: `${b.id}:${b.event}`, why: '?. 直挂' })),
  ];
  const unbound = declaredBindings.filter((d) => !r.bound.includes(d.key));
  check(
    declaredBindings.length > 0 && unbound.length === 0,
    `4. ${tag} 的绑定已入账且运行期确实绑上（on() ${page.expectHosts.length} 条 / ?. ${page.optionalBindings.length} 条）`,
    declaredBindings.length === 0
      ? '本页既无 on() 宿主也无 ?. 台账 = 绑定面完全没看守'
      : unbound.length ? `没绑上：${unbound.map((d) => `${d.key}（${d.why}）`).join('、')}` : declaredBindings.map((d) => d.key).join(', '),
  );
  for (const cap of page.optionalCaps) {
    if (!cap.invokeAtInit) continue;
    const hit = r.calls.filter((c) => c.name === cap.path).length;
    check(hit === 1, `8b. ${tag} 的能力台账 ${cap.path} 在初始化时被调到 1 次`, `实际 ${hit} 次`);
  }
  if (VERBOSE) console.log(`     · calls=${JSON.stringify(r.calls.map((c) => c.name))}\n     · bound=${JSON.stringify(r.bound)}`);

  // ---- 断言 9：切页/刷新重入不重跑 init ----
  const re = await runReentry(page, { htmlText, scriptText });
  const reV = judgeReentry(page, re);
  check(
    reV.violations.length === 0,
    `9. ${tag} 切页/刷新重入不重跑 init（重入 = #${page.reentry.id}:${page.reentry.event}）`,
    reV.violations.length ? reV.violations.join(' | ') : `init 期绑定计数不变；重入只多发：${reV.observed.join('、') || '(none)'}`,
  );

  // ---- 正向对照：注入一行指向不存在元素的绑定，必须被 1/3/7 判红 ----
  const p = await runInit(page, { htmlText, scriptText, poison: page.poisonAnchor });
  const controlWorks = !!p.threw || p.warns.length > 0 || page.initCalls.some((c) => !p.calls.some((x) => x.name === c));
  check(
    controlWorks,
    `5. ${tag} 的正向对照能判红（注入 #notAnElementForControl 绑定后仍全绿 = 本门禁失效）`,
    controlWorks ? `抛错=${p.threw ? p.threw.slice(0, 80) : 'no'} · 告警=${p.warns.length} · 少发调用=${page.initCalls.filter((c) => !p.calls.some((x) => x.name === c)).length}` : '注入后依然全绿',
  );

  // ---- 抽件对照 ----
  if (page.expectDropWarn) {
    // on() 降级通道：抽掉一个真实 id，断言 2 的 warn 必须看得见
    const d = await runInit(page, { htmlText, scriptText, dropIds: [page.dropIdProbe] });
    check(
      d.warns.length > 0,
      `6. ${tag} 抽掉 #${page.dropIdProbe} 后断言 2 判红（on() 的降级路径不是静默黑洞）`,
      d.warns.length > 0 ? d.warns[0] : '抽件后没有任何告警',
    );
  } else if (page.optionalBindings.length > 0) {
    // `?.` 直挂没有 warn 通道 —— 抽件对照改走结构判定：逐条抽掉 HTML 里的 id，
    // 断言 7 必须逐条判红（这就是 2026-10-05 事故在本门禁里的等价形态）。
    const missed = [];
    for (const b of page.optionalBindings) {
      const html2 = htmlText.replace(new RegExp(String.raw`\s*id="${escRe(b.id)}"`), '');
      const v2 = judgeElementLedger(page, html2, code).violations;
      if (!v2.some((x) => x.includes(b.id))) missed.push(b.id);
    }
    check(
      missed.length === 0,
      `6. ${tag} 抽掉任一 ?. 绑定 id 后断言 7 判红（?. 的静默缺件不再零信号）`,
      missed.length ? `抽件后仍绿：${missed.join('、')}` : page.optionalBindings.map((b) => b.id).join(', '),
    );
  } else {
    skip(`6. ${tag} 抽件对照`, '既无 warn 通道也无 ?. 台账，本节未校验');
  }
}

// ---- 断言 10：过渡表双向咬合 ----
const trV = judgeTransition(scans);
check(
  trV.length === 0,
  `10. 过渡表双向咬合（${TRANSITION.length} 条 ?. 直挂登记；新增未登记/登记项消失都判红）`,
  trV.length ? trV.join(' | ') : TRANSITION.map((t) => `${t.file.split('/').pop()}#${t.id}`).join(', '),
);

// ---- 合成对照（AGENTS §4.1）：判定器必须在已知破坏样本上判红，干净样本不得假红 ----
// 与生产判定共用同一批 judge 函数（不复制第二套判据）。
{
  const pageBy = (label) => PAGES.find((p) => p.label === label);
  const texts = (page) => ({
    html: readFileSync(join(SRC, page.html), 'utf8'),
    script: readFileSync(join(SRC, page.script), 'utf8'),
  });
  const models = pageBy('models');
  const process = pageBy('processManager');
  const residue = pageBy('residue');
  const mt = texts(models);
  const pt = texts(process);
  const rt = texts(residue);

  const controls = [
    {
      label: 'C0 干净样本：三窗结构判定必须 0 违例（判定器不假红）',
      red: false,
      run: () => PAGES.flatMap((p) => {
        const t = texts(p);
        const c = blankJsComments(t.script);
        return [...judgeWiring(p, t.html, c), ...judgeElementLedger(p, t.html, c).violations, ...judgeOptionalCalls(p, c, stubInventory(p)).violations];
      }),
    },
    {
      label: 'C1 ?. 漏绑：models 的 els.refresh 指向不存在的 id ⇒ 必须判红',
      red: true,
      run: () => judgeElementLedger(
        models,
        mt.html,
        blankJsComments(mt.script.replace("$('mwRefreshBtn')", "$('mwRefreshBtnRenamed')")),
      ).violations,
    },
    {
      label: 'C2 文本形状不算：process 的 ?. 绑定整行注释掉、原文留在注释里 ⇒ 必须判红',
      red: true,
      run: () => judgeElementLedger(
        process,
        pt.html,
        blankJsComments(pt.script.replace(
          "    el('pmCloseBtn')?.addEventListener('click', closeWindow);",
          "    // el('pmCloseBtn')?.addEventListener('click', closeWindow);",
        )),
      ).violations,
    },
    {
      label: 'C3 切页重跑 init：models 刷新处理器改成再调 init() ⇒ 必须判红',
      red: true,
      run: async () => {
        const script2 = mt.script.replace("els.refresh?.addEventListener('click', () => load());", "els.refresh?.addEventListener('click', () => { init(); });");
        const re2 = await runReentry(models, { htmlText: mt.html, scriptText: script2 });
        return judgeReentry(models, re2).violations;
      },
    },
    {
      label: 'C4 首屏少发调用：residue 的 init 不再 scanAll() ⇒ 断言 3b 必须判红',
      red: true,
      run: async () => {
        const script2 = rt.script.replace('    updatePendingButtons();\n    scanAll();\n  });', '    updatePendingButtons();\n  });');
        const r2 = await runInit(residue, { htmlText: rt.html, scriptText: script2 });
        return judgeInit(residue, r2).missing;
      },
    },
    {
      label: 'C5 页面少加载本页脚本：models HTML 去掉自己的 <script> ⇒ 断言 3a 必须判红',
      red: true,
      run: () => judgeWiring(models, mt.html.replace('  <script src="scripts/models-window.js"></script>\n', ''), blankJsComments(mt.script)),
    },
    {
      label: 'C6 未登记的 ?. 调用（window.x?.init?.() 一类）⇒ 断言 8 必须判红',
      red: true,
      run: () => judgeOptionalCalls(
        models,
        blankJsComments(mt.script.replace('  function init() {', '  function init() {\n    window.optimizerWindow?.init?.();')),
        stubInventory(models),
      ).violations,
    },
    {
      label: 'C7 新增未登记的 ?. 绑定 ⇒ 断言 7 必须判红（台账只减不增）',
      red: true,
      run: () => judgeElementLedger(
        models,
        mt.html,
        blankJsComments(mt.script.replace('  function init() {', "  function init() {\n    $('mwBody')?.addEventListener('click', () => {});")),
      ).violations,
    },
    {
      label: 'C8 过渡表留着已失效的登记 ⇒ 断言 10 必须判红（双向咬合）',
      red: true,
      run: () => {
        TRANSITION.push({
          file: 'src/scripts/models-window.js',
          fn: 'init',
          id: 'mwNotBound:click',
          batch: 'control',
          reason: '对照用：脚本里根本没有这条 ?. 绑定，登记项必须被判红后删除',
        });
        try { return judgeTransition(scans); } finally { TRANSITION.pop(); }
      },
    },
  ];

  for (const c of controls) {
    const hits = await c.run();
    const ok = c.red ? hits.length > 0 : hits.length === 0;
    check(ok, `11. ${c.label}`, hits.length ? hits.slice(0, 2).join(' | ') : '0 违例');
  }
}

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 项`);
  process.exit(1);
}
console.log(`副窗初始化与首屏请求门禁全部通过${skipped ? `（SKIP ${skipped} 节，未校验）` : ''}`);
