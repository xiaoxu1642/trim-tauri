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
    expectCalls: ['uninstall.deadScan', 'uninstall.orphanScan', 'uninstall.residueDeepScan'],
    expectHosts: ['rsChainBody:click', 'rsDeepBody:click'],
    // 注入点：该页 DOMContentLoaded 里的第一行真实语句
    poisonAnchor: "state.appId = targetFromSearch();",
    dropIdProbe: 'rsBackupToggle',
    api: () => ({
      'uninstall.residueScan': async (a) => ({ success: true, data: { appName: '示例程序', findings: [] }, _echo: a }),
      'uninstall.deadScan': async () => ({ success: true, data: { findings: [], notes: [] } }),
      'uninstall.orphanScan': async () => ({ success: true, data: { findings: [] } }),
      'uninstall.residueDeepScan': async () => ({
        success: true,
        data: { report: { groups: [], protected: [], protectedCount: 0, notes: [], scanned: {}, platforms: {} } },
      }),
      'uninstall.execute': async () => ({ success: true, data: { results: [] } }),
      'uninstall.pendingAdd': async () => ({ success: true, data: {} }),
      'uninstall.pendingRevoke': async () => ({ success: true, data: { revoked: 0 } }),
      'uninstall.pendingList': async () => ({ success: true, data: { items: [] } }),
      'uninstall.orphanIgnore': async () => ({ success: true, data: {} }),
      'residueWindow.closeWindow': async () => ({ success: true }),
      'residueWindow.onTarget': () => undefined,
    }),
  },
  {
    html: 'actions-window.html',
    script: 'scripts/actions-window.js',
    expectCalls: ['actionsWindow.list'],
    expectHosts: ['acBody:click'],
    poisonAnchor: "on('acBody', 'click', onClick);",
    dropIdProbe: 'acRunBtn',
    api: () => ({
      'actionsWindow.list': async () => ({
        success: true,
        data: { items: [{ id: 'openInNotepad', name: '用记事本打开', class: '*', installed: false, removable: false }], droppedInvalid: 0 },
      }),
      'actionsWindow.apply': async () => ({ success: true, data: { written: [], failed: [] } }),
      'actionsWindow.remove': async () => ({ success: true, data: { removed: [], failed: [] } }),
      'actionsWindow.runScript': async () => ({ success: true, data: { exitCode: 0, stdout: '', stderr: '', timedOut: false, elevated: false } }),
      'actionsWindow.closeWindow': async () => ({ success: true }),
    }),
  },
];

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
    location: { search: '', href: 'http://localhost/' + page.html },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    subToast: { hintLine: () => {} },
    modal: null,
    intro: { mountIntroPanel: () => ({}) },
    confirmDanger: async () => true,
  };
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
  const d = await runInit(page, null, page.dropIdProbe);
  check(
    d.warns.length > 0,
    `6. ${tag} 抽掉 #${page.dropIdProbe} 后断言 2 判红（on() 的降级路径不是静默黑洞）`,
    d.warns.length > 0 ? d.warns[0] : '抽件后没有任何告警',
  );
}

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 项`);
  process.exit(1);
}
console.log('副窗初始化与首屏请求门禁全部通过');
