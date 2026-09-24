// dual-run-batchA.mjs —— D6 规则 1「双跑对照」工具（Phase 1 起，逐批复用）
//
// 原理：适配层 D1 完整复刻了 preload 的 window.api 形状，因此**同一段 window.api
// 表达式在 Electron 与 Tauri 两侧都可用**；本工具把同一批调用分别打到两侧，
// 逐字段深比对。这样一次同时验证三件事：
//   ① Rust 命令实现与 Electron 主进程语义一致；
//   ② 适配层的参数整形（execute 的 force/toRecycle、scan 的 refresh 默认值等）不走样；
//   ③ D5 数据搬迁后读到的配置与旧目录一致。
//
// 用法：TRIM_ORIGIN=<Electron 仓库根> node tools/dual-run-batchA.mjs
//   可选 TRIM_ELECTRON=<electron.exe 路径>（缺省取 $TRIM_ORIGIN/node_modules/electron/dist/electron.exe）
// 前置：Tauri 侧以 TRIM_DEV_NOACTIVATE=1 + CDP 9334 后台运行（本工具只连它的 CDP，不 spawn 它）；
//       Electron 侧由本工具自行拉起（9333）。
//
// 注意（AGENTS.md 4.3）：宿主环境会注入 ELECTRON_RUN_AS_NODE 与 NODE_OPTIONS，
// 必须删除后 spawn，且父进程须存活，否则 Electron 会被随母进程回收。
//
// 审查 v2-L9：坐标一律来自环境变量，本文件不写死本机绝对路径（AGENTS.md §2 禁单机坐标入库）。
// 本工具**按设计就要 spawn 旧 Electron 应用**（双跑对照是它的存在理由），所以缺 TRIM_ORIGIN
// 时直接报错退出，而不是给一个「能猜中开发机」的默认值——猜错的代价是静默比错对象。

import { spawn, execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const REPO = process.env.TRIM_ORIGIN || '';
const ELECTRON = process.env.TRIM_ELECTRON || (REPO ? join(REPO, 'node_modules', 'electron', 'dist', 'electron.exe') : '');
if (!REPO || !existsSync(ELECTRON)) {
  console.error(`✗ 双跑需要旧轨在位：设 TRIM_ORIGIN 指向 Electron 仓库根（现值「${REPO || '未设'}」），`
    + `必要时用 TRIM_ELECTRON 指定 electron.exe（现值「${ELECTRON || '未推导'}」）`);
  process.exit(1);
}
const ELECTRON_PORT = 9333;
const TAURI_PORT = 9334;


// 运行期天然抖动字段：任意深度下都跳过
const VOLATILE = new Set([
  'cpu', 'memory', 'free', 'used', 'percent', 'uptime', 'processes',
  'cached', 'cachedAt', 'at', 'timestamp', 'engine', 'refresh',
]);

// 逐通道的预期差异白名单（差异是设计使然，需在此显式登记才算「已知」）
const EXPECTED_DIFF = {
  'app.getInfo': new Set(['electron', 'node', 'chrome', 'runtime', 'dataDir']),
  // overview.metrics 已切到原生引擎（trim-finder lib 直调 ov-metrics），
  // 因此 cpuRaw / system.caption 与 Electron **严格一致**，不再豁免；
  // 仅 cpu 本身因两侧各自采样的时刻不同而天然抖动。
  'overview.metrics': new Set(['cpu']),
  // 图标：两侧都是「Shell 图标 → PNG dataURL」，但提取管线不同（Electron NativeImage
  // vs SHGetFileInfoW+GetDIBits），像素不保证逐字节相同。此处只要求契约一致
  // （success/dataUrl 齐备且为 PNG dataURL）；有效性另由 A 批自检校验 PNG 头与尺寸。
  'paths.fileIcon': new Set(['dataUrl']),
  'paths.appIcon': new Set(['dataUrl']),
};

// 逐通道的比对前归一（处理运行期必然抖动的值，避免假失败）
const NORMALIZE = {
  // 体检里的「系统盘空间」随两次调用之间的磁盘写入而变（406.7 vs 406.8 GB），
  // 只保留结构不比对数值
  'overview.checkup': (v) => {
    const checks = v?.data?.checks;
    if (Array.isArray(checks)) {
      for (const c of checks) if (c && c.id === 'sys_drive_free') c.value = '<volatile>';
    }
    return v;
  },
  // 丢包检测：网络实时抖动（已发/已收/丢失计数、往返时延），只保留结构与默认网关
  'realtime.loss': (v) => {
    if (v && typeof v === 'object') {
      for (const k of ['sent', 'received', 'lost', 'lossPercent', 'minRtt', 'maxRtt', 'avgRtt']) delete v[k];
    }
    return v;
  },
};

// 只读或幂等的对照项；含对话框/写用户数据的通道不在此列（另行人工验证）
const CASES = [
  ['app.getInfo', `window.api.app.getInfo()`],
  ['app.getTheme', `window.api.app.getTheme()`],
  ['app.readUsage', `window.api.app.readUsage()`],
  ['app.openExternal(拒绝 file:)', `window.api.app.openExternal('file:///c:/windows/win.ini')`],
  ['app.openExternal(空串)', `window.api.app.openExternal('')`],
  ['window.updateOverlay', `window.api.window.updateOverlay(true)`],
  ['modal.open', `window.api.modal.open({ id: 'dualrun', title: '双跑探针' })`],
  ['modal.close', `window.api.modal.close({ id: 'dualrun' })`],
  ['diag.dwmConflict', `window.api.diag.dwmConflict()`],
  ['intro.load', `window.api.intro.load()`],
  ['system.diskType(refresh)', `window.api.system.diskType({ refresh: true })`],
  ['device.scan', `window.api.device.scan()`],
  ['overview.metrics', `window.api.overview.metrics()`],
  ['overview.hardware', `window.api.overview.hardware({ refresh: false })`],
  ['overview.checkup', `window.api.overview.checkup({ refresh: false })`],
  ['paths.load', `window.api.paths.load()`],
  ['paths.validate(存在)', `window.api.paths.validate('C:\\\\Windows')`],
  ['paths.validate(不存在)', `window.api.paths.validate('C:\\\\__trim_nope__')`],
  ['realtime.adapters', `window.api.realtime.adapters()`],
  ['realtime.loss', `window.api.realtime.loss()`],
  ['paths.fileIcon', `window.api.paths.fileIcon('C:\\\\Windows\\\\System32\\\\notepad.exe')`],
  ['paths.appIcon', `window.api.paths.appIcon('C:\\\\Program Files\\\\Tencent\\\\QQNT', ['QQ.exe','QQScLauncher.exe'])`],
];

function killLeftovers() {
  for (const name of ['electron', 'electron.exe']) {
    try { execFileSync('taskkill', ['/F', '/IM', name, '/T'], { stdio: 'ignore' }); } catch { /* 无残留 */ }
  }
}

async function cdpEndpoint(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (r.ok) return true;
    } catch { /* 还没起来 */ }
    await sleep(500);
  }
  return false;
}

async function pageTarget(port, urlHint) {
  const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  // 只认应用页面：Electron 会同时暴露 devtools:// 页面，选中它会拿到空 window.api
  const pages = list.filter(t => t.type === 'page' && !(t.url || '').startsWith('devtools://'));
  const byHint = pages.find(t => (t.url || '').includes(urlHint));
  return byHint || pages[0] || list[0];
}

function connect(target) {
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  let seq = 0;
  const pend = new Map();
  ws.addEventListener('message', e => {
    const m = JSON.parse(e.data);
    if (m.id && pend.has(m.id)) {
      const q = pend.get(m.id); pend.delete(m.id);
      m.error ? q.rej(new Error(JSON.stringify(m.error))) : q.res(m.result);
    }
  });
  const ready = new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
  const send = (method, params = {}) => {
    const id = ++seq;
    ws.send(JSON.stringify({ id, method, params }));
    return new Promise((res, rej) => pend.set(id, { res, rej }));
  };
  return { ws, ready, send };
}

async function evaluate(send, expression, timeoutMs) {
  const r = await send('Runtime.evaluate', {
    expression: `(async () => { try { const v = await (${expression}); return JSON.stringify({ ok: true, v }); } catch (e) { return JSON.stringify({ ok: false, e: String(e && e.message || e) }); } })()`,
    returnByValue: true, awaitPromise: true, timeout: timeoutMs,
  });
  if (r.exceptionDetails) return { ok: false, e: 'EXCEPTION: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text) };
  const parsed = JSON.parse(r.result.value);
  return parsed;
}

function deepDiff(a, b, allowed, path = '', out = []) {
  if (out.length > 30) return out;
  const key = path.split('.').pop().replace(/\[\d+\]$/, '');
  if (VOLATILE.has(key) || allowed.has(path)) return out;
  if (typeof a !== typeof b) { out.push(`${path || '(root)'}: 类型 ${typeof a} vs ${typeof b}`); return out; }
  if (a === null || b === null || typeof a !== 'object') {
    if (a !== b) out.push(`${path || '(root)'}: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
    return out;
  }
  if (Array.isArray(a) !== Array.isArray(b)) { out.push(`${path}: 数组性不同`); return out; }
  if (Array.isArray(a)) {
    if (a.length !== b.length) out.push(`${path}: 数组长度 ${a.length} vs ${b.length}`);
    for (let i = 0; i < Math.min(a.length, b.length); i++) deepDiff(a[i], b[i], allowed, `${path}[${i}]`, out);
    return out;
  }
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of keys) {
    const p = path ? `${path}.${k}` : k;
    if (VOLATILE.has(k) || allowed.has(p)) continue;
    if (!(k in a)) { out.push(`${p}: 仅 Tauri 有`); continue; }
    if (!(k in b)) { out.push(`${p}: 仅 Electron 有`); continue; }
    deepDiff(a[k], b[k], allowed, p, out);
  }
  return out;
}

// ---------------- 主流程 ----------------
killLeftovers();
console.log('启动 Electron（原仓库 3.7.3）…');
const env = { ...process.env };
delete env.ELECTRON_RUN_AS_NODE;
delete env.NODE_OPTIONS;
const electron = spawn(ELECTRON, ['.', `--remote-debugging-port=${ELECTRON_PORT}`], {
  cwd: REPO, env, stdio: 'ignore', detached: false,
});

let exitCode = 1;
try {
  if (!await cdpEndpoint(ELECTRON_PORT, 60000)) throw new Error('Electron CDP 未就绪');
  if (!await cdpEndpoint(TAURI_PORT, 5000)) throw new Error('Tauri CDP(9334) 未就绪——请先以后台模式启动 Tauri 侧');
  const eTarget = await pageTarget(ELECTRON_PORT, 'index.html');
  const tTarget = await pageTarget(TAURI_PORT, 'tauri.localhost');
  console.log(`Electron target: ${eTarget.url}\nTauri    target: ${tTarget.url}\n`);
  const e = connect(eTarget), t = connect(tTarget);
  await e.ready; await t.ready;
  await e.send('Runtime.enable'); await t.send('Runtime.enable');

  const rows = [];
  let fails = 0;
  for (const [name, expr] of CASES) {
    const started = Date.now();
    const ev = await evaluate(e.send, expr, 150000);
    const tv = await evaluate(t.send, expr, 150000);
    let verdict, detail;
    if (!ev.ok || !tv.ok) {
      verdict = '✗'; fails++;
      detail = `Electron=${ev.ok ? 'ok' : ev.e} / Tauri=${tv.ok ? 'ok' : tv.e}`;
    } else {
      const base = name.split('(')[0];
      const allowed = EXPECTED_DIFF[base] || new Set();
      const norm = NORMALIZE[base];
      const tvv = norm ? norm(structuredClone(tv.v)) : tv.v;
      const evv = norm ? norm(structuredClone(ev.v)) : ev.v;
      const diff = deepDiff(tvv, evv, allowed);
      if (diff.length === 0) { verdict = '✓'; detail = allowed.size ? `一致（已登记预期差异: ${[...allowed].join('/')}）` : (norm ? '一致（已归一抖动值）' : '完全一致'); }
      else { verdict = '✗'; fails++; detail = diff.slice(0, 5).join(' | '); }
    }
    rows.push([name, verdict, detail, Date.now() - started]);
  }

  console.log('通道'.padEnd(30) + '比对  耗时  说明');
  for (const [n, v, d, ms] of rows) console.log(`${n.padEnd(28)} ${v}  ${String(ms).padStart(6)}ms  ${d}`);
  console.log(`\n合计 ${rows.length - fails}/${rows.length} 一致`);
  exitCode = fails === 0 ? 0 : 1;
} catch (err) {
  console.error('双跑失败：', err.message);
} finally {
  try { electron.kill(); } catch { /* 已退出 */ }
  await sleep(800);
  killLeftovers();
  console.log('\nElectron 已关闭');
}
process.exit(exitCode);