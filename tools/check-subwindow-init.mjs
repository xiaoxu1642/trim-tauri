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
// 全是文本层对拍（id ⇄ 引用那类要判准就得维护一张「哪些 id 由 JS 运行时创建」的豁免表，
// 见本门禁里为什么改成让代码自己报告）。所以这里**用最小 DOM 桩把脚本真的跑一遍**，
// 断言三件事：① 初始化不抛错 ② 初始化期间没有「缺少元素」告警 ③ 首屏请求确实发出。
//
// ② 的判据来自被测代码自己：副窗的绑定一律走文件里的 `on(id,type,fn)`，缺件时它只
// console.warn 而不抛错（保证一个 id 写错不再带崩整页）。这条 warn 正好是本门禁的信号，
// **不需要任何手工豁免表** —— 代码里新增一个指向不存在元素的绑定即红。
//
// 正向对照（AGENTS §4.1）：每个页面都再跑一遍「人为注入一行指向不存在元素的绑定」，
// 必须能被判红。注入后仍然全绿 ⇒ 判定器已经失效，本门禁自己判红。
//
// v5 批次 9（门禁候选 5）：从只跑 residue 一窗扩到 **4 子窗全覆盖**（页数地板钉住），
// 另三窗的桩形状见各自 PAGES 条目注释。
//
// 用法：node tools/check-subwindow-init.mjs [--verbose]
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VERBOSE = process.argv.includes('--verbose');

const PAGES = [
  {
    html: 'residue-window.html',
    script: 'scripts/residue-window.js',
    // 首屏必须发出的请求（点名对象，§4.1 纪律①：只断「没报错」会被「根本没跑到」穿透）
    expectCalls: ['uninstall.residueScan'],
    expectHosts: ['rsChainBody:click'],
    // 本窗只由「卸载完成后自动弹出」唤起，appId 经 URL query 带入；无 appId 时前端不发起
    // 扫描请求（避免对着空目标发一次必失败的命令），所以桩里必须带上 query 才谈得上首屏请求。
    search: '?app=' + encodeURIComponent('HKLM|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TrimProbe'),
    // 注入点：该页 DOMContentLoaded 里的第一行真实语句
    poisonAnchor: "state.appId = targetFromSearch();",
    dropIdProbe: 'rsBackupToggle',
    // 绑定走 on() 降级 warn 机制 ⇒ 抽件对照（断言 6）有 warn 通道可断
    expectDropWarn: true,
    api: () => ({
      'uninstall.residueScan': async (a) => ({ success: true, data: { appName: '示例程序', findings: [], notes: [] }, _echo: a }),
      'uninstall.residueExecute': async () => ({ success: true, data: { details: [], okCount: 0, failCount: 0 } }),
      'uninstall.pendingAdd': async () => ({ success: true, data: {} }),
      'uninstall.pendingRevoke': async () => ({ success: true, data: { revoked: 0 } }),
      'uninstall.pendingList': async () => ({ success: true, data: { entries: [] } }),
      'residueWindow.closeWindow': async () => ({ success: true }),
      'residueWindow.onTarget': () => undefined,
    }),
  },
  // v5 批次 9（门禁候选 5）：页数地板（4 子窗全覆盖）——此前只跑 residue 一窗，
  // 另外 3 窗的「初始化不崩 + 首屏真的会发请求」完全没人管。
  {
    html: 'models-window.html',
    script: 'scripts/models-window.js',
    expectCalls: ['settings.load'],
    expectHosts: [],
    poisonAnchor: "function init() {",
    dropIdProbe: 'mwBody',
    api: () => ({
      'settings.load': async () => ({ success: true, data: { models: {}, modelDefaults: {} } }),
      'models.save': async () => ({ success: true }),
      'models.test': async () => ({ success: true, data: { ok: true } }),
      'modelsWindow.close': async () => ({ success: true }),
    }),
  },
  {
    html: 'preview-window.html',
    script: 'scripts/preview-window.js',
    // 本窗由主窗以 onData 回调投喂图片数据（无 invoke 型首屏请求）：「首屏真的会动」
    // 的点名对象 = onData 注册本身发生。
    expectCalls: ['previewWindow.onData'],
    expectHosts: [],
    poisonAnchor: "function init() {",
    dropIdProbe: 'pvClose',
    api: () => ({
      'previewWindow.onData': (fn) => fn({ images: [], itemName: '探针', index: 0 }),
      'previewWindow.close': async () => ({ success: true }),
      'previewWindow.notifyDeleted': (a) => a,
      'fileclean.readImage': async () => ({ success: true, data: { dataUrl: 'data:image/png;base64,' } }),
      'fileclean.deleteFile': async () => ({ success: true }),
    }),
  },
  {
    html: 'process-manager-window.html',
    script: 'scripts/process-manager-window.js',
    // 首屏 = load() ⇒ ProcessTools.fetchProcesses()（report 只在 kill 后发，不是首屏）
    expectCalls: ['ProcessTools.fetchProcesses'],
    expectHosts: [],
    poisonAnchor: "function init() {",
    dropIdProbe: 'pmBody',
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

// v5 批次 9（门禁候选 5）：页数地板——capabilities/subwindows.json 登记的每个子窗
// label 必须有对应 PAGES 条目（label 驼峰 ⇄ html 文件 kebab 的映射表在此，改文件名
// 同步改这里）。漏窗 = 该窗的「初始化不崩 + 首屏真的会发请求」无人看守。
const LABEL_HTML = {
  preview: 'preview-window.html',
  models: 'models-window.html',
  processManager: 'process-manager-window.html',
  residue: 'residue-window.html',
};

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
  return ok;
};

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

/**
 * 最小 DOM 桩：只实现被测脚本用到的那些面，且**严格按本页 HTML 的静态 id 决定
 * getElementById 能不能拿到东西** —— 脚本引用了本页没有的 id 就会像真机一样拿到 null。
 */
function buildCtx(page, poison, dropId) {
  const html = readFileSync(join(ROOT, 'src', page.html), 'utf8');
  const staticIds = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
  // 正向对照 2：假装本页少了一个静态 id（模拟「HTML 改了、脚本没跟上」的漂移）。
  // 专门喂断言 2 —— on() 把缺件降级成 warn 而不是抛错，只有 warn 通道能看见它。
  if (dropId) staticIds.delete(dropId);
  const calls = [];
  const bound = [];
  const warns = [];

  const mkNode = (id) => ({
    id,
    hidden: false,
    checked: false,
    disabled: false,
    value: '',
    textContent: '',
    innerHTML: '',
    style: {},
    dataset: {},
    classList: { toggle: () => {}, add: () => {}, remove: () => {}, contains: () => false },
    setAttribute: () => {},
    getAttribute: () => null,
    addEventListener: (t) => bound.push(`${id}:${t}`),
    appendChild: () => {},
    remove: () => {},
    focus: () => {},
    querySelector: () => null,
    querySelectorAll: () => [],
    closest: () => null,
    insertAdjacentHTML: () => {},
    scrollIntoView: () => {},
  });
  const nodes = new Map();
  const doc = {
    getElementById(id) {
      if (!staticIds.has(id)) return null;
      if (!nodes.has(id)) nodes.set(id, mkNode(id));
      return nodes.get(id);
    },
    addEventListener(type, fn) {
      (doc._handlers ||= {})[type] = fn;
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
    // 真机加载期 readyState 恒 'loading'——models/preview 等窗的脚本按它分流
    // （'loading' ⇒ DOMContentLoaded 注册，否则直接 init）。缺这个字段会让
    // 脚本走 else 分支直接 init，DOMContentLoaded 判定失明。
    readyState: 'loading',
  };

  // window.api.<ns>.<method> 由扁平表造出来；表里没有的方法**故意不存在**：
  // 脚本调它就像真机一样抛 TypeError，本门禁据此判红，而不是替它兜住。
  const api = {};
  for (const [flat, fn] of Object.entries(page.api())) {
    const [ns, m] = flat.split('.');
    (api[ns] ||= {})[m] = (...args) => {
      calls.push(flat);
      return fn(...args);
    };
  }

  const win = {
    api,
    ds: { esc, escAttr: esc, fmtBytes: (n) => String(n) },
    location: { search: page.search || '', href: 'http://localhost/' + page.html },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    subToast: { hintLine: () => {} },
    modal: null,
    intro: { mountIntroPanel: () => ({}) },
    confirmDanger: async () => true,
  };
  // v5 批次 9（门禁候选 5）：非 api 表的全局对象（如 ProcessTools）同样进桩并计数——
  // 它们的首屏调用（fetchProcesses）与 api 方法在「首屏真的会动」的判据里同权。
  for (const [name, obj] of Object.entries(page.extraGlobals ? page.extraGlobals() : {})) {
    for (const [m, fn] of Object.entries(obj)) {
      if (typeof fn !== 'function') continue;
      obj[m] = (...args) => {
        calls.push(`${name}.${m}`);
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

  let text = readFileSync(join(ROOT, 'src', page.script), 'utf8');
  if (poison) {
    if (!text.includes(poison)) throw new Error(`正向对照锚点没命中：${poison}`);
    text = text.replace(poison, `${poison}\n    el('notAnElementForControl').addEventListener('click', function () {});`);
  }
  return { ctx, doc, calls, bound, warns, text };
}

/** 跑一遍某页的初始化，返回可判定的三件事 */
async function runInit(page, poison, dropId) {
  const { ctx, doc, calls, bound, warns, text } = buildCtx(page, poison, dropId);
  let threw = null;
  try {
    vm.runInContext(text, ctx, { filename: page.script });
    const h = doc._handlers && doc._handlers.DOMContentLoaded;
    if (typeof h !== 'function') threw = '脚本没有注册 DOMContentLoaded 处理器';
    else await h();
  } catch (e) {
    threw = `${e && e.constructor ? e.constructor.name : 'Error'}: ${(e && e.message) || e}`;
  }
  await new Promise((r) => setTimeout(r, 0));
  return { threw, calls, bound, warns };
}

console.log('=== 副窗初始化与首屏请求门禁 ===\n');

// v5 批次 9（门禁候选 5）：页数地板（判据见 LABEL_HTML 注释）。
{
  const sub = JSON.parse(readFileSync(join(ROOT, 'src-tauri', 'capabilities', 'subwindows.json'), 'utf8'));
  const labels = sub.windows || [];
  const missing = labels.filter((l) => !LABEL_HTML[l] || !PAGES.some((p) => p.html === LABEL_HTML[l]));
  check(
    missing.length === 0,
    `0. 页数地板：PAGES 覆盖 subwindows.json 的全部 ${labels.length} 个子窗`,
    missing.length ? `缺：${missing.join('、')}` : PAGES.map((p) => p.html).join(', '),
  );
}

for (const page of PAGES) {
  const r = await runInit(page);
  const tag = page.html;
  check(!r.threw, `1. ${tag} 的 DOMContentLoaded 未抛错`, r.threw || '');
  check(r.warns.length === 0, `2. ${tag} 初始化期间没有「缺少元素/异常」告警`, r.warns.join(' | '));
  const missing = page.expectCalls.filter((c) => !r.calls.includes(c));
  check(missing.length === 0, `3. ${tag} 首屏确实发出了 ${page.expectCalls.length} 个请求`, missing.length ? `未发出：${missing.join('、')}` : r.calls.join(','));
  const noHost = page.expectHosts.filter((h) => !r.bound.includes(h));
  check(noHost.length === 0, `4. ${tag} 的委托宿主确实绑上了`, noHost.length ? `缺：${noHost.join('、')}` : page.expectHosts.join(','));
  if (VERBOSE) console.log(`     · calls=${JSON.stringify(r.calls)}\n     · bound=${JSON.stringify(r.bound)}`);

  // ---- 正向对照：注入一行指向不存在元素的绑定，必须被 1/3 判红 ----
  const p = await runInit(page, page.poisonAnchor);
  const controlWorks = !!p.threw || p.warns.length > 0 || page.expectCalls.some((c) => !p.calls.includes(c));
  check(
    controlWorks,
    `5. ${tag} 的正向对照能判红（注入 #notAnElementForControl 绑定后仍全绿 = 本门禁失效）`,
    controlWorks ? `抛错=${p.threw ? 'yes' : 'no'} · 告警=${p.warns.length} · 少发请求=${page.expectCalls.filter((c) => !p.calls.includes(c)).length}` : '注入后依然全绿',
  );

  // ---- 正向对照 2：抽掉一个真实存在的 id，断言 2 的 warn 通道必须看得见 ----
  // 仅对绑定走 on() 降级 warn 机制的窗有意义（residue）；models/preview/process
  // 的绑定是 `?.` 可选链直挂（缺 id ⇒ null ⇒ 静默），无 warn 通道可看——那几窗的
  // 初始化崩不崩由断言 1 管，这里显式跳过并声明，不做假绿。
  if (page.expectDropWarn) {
    const d = await runInit(page, null, page.dropIdProbe);
    check(
      d.warns.length > 0,
      `6. ${tag} 抽掉 #${page.dropIdProbe} 后断言 2 判红（on() 的降级路径不是静默黑洞）`,
      d.warns.length > 0 ? d.warns[0] : '抽件后没有任何告警',
    );
  } else {
    console.log(`6. ${tag} SKIP 抽件对照（绑定不走 on() 降级，无 warn 通道可断）`);
  }
}

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 项`);
  process.exit(1);
}
console.log('副窗初始化与首屏请求门禁全部通过');
