// src/main/updater.js — 应用自动更新（electron-updater + GitHub Releases，多线路容灾）
// 批次：自动更新接入（2026-09-12，方案见 docs规范/update/9.12/electron-updater自动更新方案）
//       v2.6.0（P2-8）多线路容灾：GitHub 直连失败时按序回退镜像线路（复用规则库更新
//       「多源按序回退」模式；electron-updater 单实例无法并发竞速，顺序回退是等价容灾）。
// 约束：
// 1) 仅打包后生效（app.isPackaged），开发环境 npm start 直接短路（resources 下无 app-update.yml）；
// 2) 状态全部经 'updater:state-changed' 事件推给渲染层，由渲染层统一弹窗服务呈现，主进程不弹原生 dialog；
// 3) 发现新版不自动下载、下载完成不强制退出：避免偷跑流量与打断清理/测速/大文件扫描任务；
// 4) 更新源来自打包时自动生成的 resources/app-update.yml（build.publish 配置），不要手写、不要入库；
// 5) 完整性锚点说明（v3.6.5 M1-1 重写）：
//    latest.yml 与安装包同源同前缀，通道被接管时可同时提供「恶意 latest.yml（写恶意包 sha512）」
//    与「恶意安装包（sha512 自洽）」，故 sha512 绝不能由通道提供，必须由**应用内置公钥**背书。
//    这与规则库更新（rules-signature.js，锚点是内置 ed25519 公钥）是同一个信任模型。
//
//    【已落地】latest.yml 的 ed25519 验签：
//      发布侧产出旁路签名 latest.yml.sig（scripts/sign-update.js sign 生成并上传）。
//      本模块在**检查阶段**先验签，再从已验签的原文抽出 version/sha512/path 作为可信锚点，
//      并把通道给的值与锚点逐字比对；**下载前再复验一次**（用户可能隔几分钟才点下载，关掉 TOCTOU 窗口）。
//      三态判定：verified 放行；unsigned（漏签/发布事故）与 mismatch（疑似篡改）一律拒绝该线路；
//      仅 unreachable（网络失败）才沿用既有的「回退下一条线路」逻辑——绝不因拿不到签名就降级放行。
//
//    【Phase B 预留，本次不启用】Authenticode 代码签名校验：
//      实测本机 v3.6.2 两个产物 Get-AuthenticodeSignature 均为 Status:2（未进行数字签名）。
//      此时若配置 publisherName，electron-updater 会因 Status !== 0 拒绝**所有**更新
//      （包括我们自己发布的正式版），等于把全部用户锁死在无法更新的状态。
//      启用前置条件：① 受信任 CA 签发的代码签名证书（OV/EV，自签名证书会自锁）；
//      ② 两个 win 产物均已签名；③ 在 build.publish[0].publisherName 填**完整 DN**（只给 CN 等于弱匹配）。
//      条件满足后无需改代码即可生效，故此处不留任何开关代码。
//
//    锁死风险的四条对策（详见设计文档 §2.1.3）：S1 postrelease 钩子自动签名 + 回读自验；
//      S2 签完立即用内置公钥自验；S3 签名与 yml 同源、逐线路成对拉取；
//      S4 内置公钥设计为数组以支持轮换（顺序硬约束：先 [旧,新] → 稳定后再收敛为 [新]）。
//    在以上两项都完备前，镜像域名应被视为「需要信任」而非「无需白名单」。
const { autoUpdater, CancellationToken } = require('electron-updater');
const { app } = require('electron');
const fs = require('fs');
const path = require('path');
// v3.6.5 M1-1：更新信息的可信锚点验签（纯 Node 模块，不含 electron，可被 test-features.js 直接单测）
const UPDATE_SIG = require('./update-signature');

// —— 线路定义（P2-8）——
// 默认线路：GitHub Releases（来自 app-update.yml）；镜像线路：gh-proxy 系对
// releases/latest/download/ 的转发（generic provider，直接拉 latest.yml 与安装包）。
// 新增镜像时同步更新渲染层设置页下拉（src/scripts/updater-ui.js 的 MIRROR_OPTIONS）。
const GITHUB_FEED = { provider: 'github', owner: 'xiaoxu1642', repo: 'Trim' };
const MIRRORS = [
  { id: 'gh-proxy', label: 'gh-proxy 镜像', base: 'https://gh-proxy.com/https://github.com/xiaoxu1642/Trim/releases/latest/download/' },
  { id: 'ghfast', label: 'ghfast 镜像', base: 'https://ghfast.top/https://github.com/xiaoxu1642/Trim/releases/latest/download/' }
];
const MIRROR_IDS = ['auto', 'github', ...MIRRORS.map(m => m.id)];
const MIRROR_FILE = 'update-mirror.json'; // 数据目录下的用户镜像偏好
const CHECK_TIMEOUT_MS = 20000;           // 单线路检查超时（竞速另一条前不再等太久）
// v3.6.5 M1-1：GitHub 直连的下载基址，与 MIRRORS[].base 同构，用于取 latest.yml 与 latest.yml.sig。
// 为什么要单独一个常量：验签要自己拉一次 yml+sig，而 electron-updater 的 generic provider 只把
// 结果加工成对象，无法把「通道传来的 sha512」变成「内置公钥背书的 sha512」。
const GITHUB_DOWNLOAD_BASE = 'https://github.com/xiaoxu1642/Trim/releases/latest/download/';
const ANCHOR_MAX_BYTES = 64 * 1024;       // latest.yml 体积上限（正常约 1KB），超限即断，防异常响应撑爆内存
const SIG_MAX_BYTES = 4 * 1024;           // latest.yml.sig 体积上限（ed25519 base64 约 88 字节）

// 版本单调比较（审查 H-1 防降级，2026-09-14）：按点分段逐段比较数字，任一段远端 < 当前即降级。
// 预发布标签（-beta 等）截取主体版本再比；任一段无法解析为有限数字或比较过程异常一律拒绝安装
// （火眼眼审查 2026-09-14 MED：fail-closed——畸形远端版本不得绕过降级拦截，宁可漏更不可错降）。
function isVersionNewerOrEqual(remote, current) {
  try {
    const a = String(remote).split('-')[0].split('.').map(Number);
    const b = String(current).split('-')[0].split('.').map(Number);
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) {
      const x = a[i] || 0, y = b[i] || 0;
      if (!Number.isFinite(x) || !Number.isFinite(y)) return false;
      if (x > y) return true;
      if (x < y) return false;
    }
    return true;
  } catch { return false; }
}

// —— v3.6.5 M1-1：拉取并验签 latest.yml，得到可信锚点 ——
// 带体积上限与超时的字节拉取。验签对象是**原始字节**，必须防异常响应把内存撑爆。
async function fetchBytesLimited(url, maxBytes, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'trim-updater' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > maxBytes) throw new Error(`响应过大（${buf.length} > ${maxBytes} 字节）`);
    return buf;
  } finally {
    clearTimeout(timer);
  }
}

// 对单条线路取得可信锚点。返回 { ok:true, version, sha512, file } 或 { ok:false, kind, reason }。
// 三种 kind 语义严格区分（见文件头注释）：
//   unreachable —— 网络/HTTP 失败，属既有「线路不通」，调用方应回退下一条线路
//   unsigned    —— 拿到了 yml 但没有合法签名（发布事故），拒绝该线路
//   mismatch    —— 签名验不过（疑似篡改），拒绝该线路
async function resolveTrustedAnchor(feed) {
  const base = feed.id === 'github' ? GITHUB_DOWNLOAD_BASE : (feed.config && feed.config.url) || '';
  if (!base) return { ok: false, kind: 'unreachable', reason: '线路缺少下载基址' };
  let raw, sigText;
  try {
    raw = await fetchBytesLimited(new URL('latest.yml', base).toString(), ANCHOR_MAX_BYTES, 15000);
    sigText = (await fetchBytesLimited(new URL('latest.yml.sig', base).toString(), SIG_MAX_BYTES, 15000)).toString('utf8');
  } catch (e) {
    return { ok: false, kind: 'unreachable', reason: e.name === 'AbortError' ? '拉取更新信息超时' : e.message };
  }
  const v = UPDATE_SIG.verifyUpdateInfoSignature(raw, sigText);
  if (!v.ok) return { ok: false, kind: v.kind, reason: v.reason };
  const anchor = UPDATE_SIG.extractUpdateAnchor(raw.toString('utf8'));
  if (!anchor) return { ok: false, kind: 'unsigned', reason: 'latest.yml 结构不符合预期，已拒绝' };
  return { ok: true, ...anchor };
}

let winRef = null;
let writeLog = () => {};
let cancelToken = null;
let started = false;
let checking = false;
let dataDir = null;        // 由 main.js 注入（镜像偏好持久化位置）
let mirrorPref = 'auto';   // auto = GitHub 优先失败自动回退；指定镜像 = 镜像优先
let activeMirror = 'github'; // 最近一次成功线路（回报渲染层）
// v3.6.5 M1-1：本次检查得到的「已验签锚点」与「待下载的锚点」
// verifiedAnchor —— safeCheck 阶段由内置公钥验签通过得出的可信锚点
// pendingAnchor  —— update-available 时锁定，供 startDownload 复验（关掉 TOCTOU 窗口）
let verifiedAnchor = null;
let pendingAnchor = null;

// 统一向主窗口渲染层推送状态（phase: idle/checking/available/latest/downloading/ready/error）
function push(state) {
  try {
    if (winRef && !winRef.isDestroyed()) winRef.webContents.send('updater:state-changed', state);
  } catch (_) { /* 窗口已销毁时静默 */ }
}

// GitHub releaseNotes 可能是字符串、{note} 对象数组或空值，统一拍平成纯文本
function normalizeNotes(notes) {
  if (!notes) return '';
  if (typeof notes === 'string') return notes;
  if (Array.isArray(notes)) {
    return notes.map(n => (n && (n.note || n.title)) || '').filter(Boolean).join('\n');
  }
  return String(notes);
}

// —— 镜像偏好持久化（P2-8）——
function loadMirrorPref() {
  if (!dataDir) return 'auto';
  try {
    const file = path.join(dataDir, MIRROR_FILE);
    if (!fs.existsSync(file)) return 'auto';
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    const id = cfg && typeof cfg.mirror === 'string' ? cfg.mirror : 'auto';
    return MIRROR_IDS.includes(id) ? id : 'auto';
  } catch (_) {
    return 'auto';
  }
}

function saveMirrorPref(id) {
  if (!dataDir) return { ok: false, reason: 'no-datadir' };
  if (!MIRROR_IDS.includes(id)) return { ok: false, reason: 'unknown-mirror' };
  try {
    fs.mkdirSync(dataDir, { recursive: true });
    const tmp = path.join(dataDir, MIRROR_FILE + '.tmp');
    fs.writeFileSync(tmp, JSON.stringify({ mirror: id }), 'utf8');
    fs.renameSync(tmp, path.join(dataDir, MIRROR_FILE));
    mirrorPref = id;
    return { ok: true };
  } catch (e) {
    writeLog('warn', `[updater] 保存镜像偏好失败: ${e.message}`);
    return { ok: false, reason: e.message };
  }
}

// 按用户偏好排出线路尝试顺序：指定镜像时镜像优先（GitHub 兜底），auto 时 GitHub 优先
function orderedFeeds() {
  const defaultFeed = { id: 'github', label: 'GitHub 直连', config: GITHUB_FEED };
  const mirrorFeeds = MIRRORS.map(m => ({
    id: m.id,
    label: m.label,
    config: { provider: 'generic', url: m.base }
  }));
  if (mirrorPref !== 'auto' && mirrorPref !== 'github') {
    const first = mirrorFeeds.find(m => m.id === mirrorPref);
    if (first) return [first, defaultFeed, ...mirrorFeeds.filter(m => m.id !== first.id)];
  }
  return [defaultFeed, ...mirrorFeeds];
}

// mainWindow：主窗口引用；logger：项目现有 writeLog(level, msg)；opts.dataDir：数据目录（镜像偏好持久化）
function initUpdater(mainWindow, logger, opts = {}) {
  if (started) return;
  started = true;
  winRef = mainWindow;
  if (typeof logger === 'function') writeLog = logger;
  dataDir = typeof opts.dataDir === 'string' ? opts.dataDir : null;
  mirrorPref = loadMirrorPref();
  if (mirrorPref !== 'auto') writeLog('info', `[updater] 已加载更新镜像偏好: ${mirrorPref}`);

  if (!app.isPackaged) {
    writeLog('info', '[updater] 开发环境，跳过自动更新');
    return;
  }

  autoUpdater.autoDownload = false;       // 发现新版先问用户，不偷跑流量
  autoUpdater.autoInstallOnAppQuit = true; // 已下载完时，退出应用顺手安装
  // v3.6.5 M1-1：上游 electron-updater 明确建议关闭 web installer（该分支的签名校验更弱）。
  // 本项目 nsis target 未使用 web installer，故本行无副作用，仅作纵深防御。
  autoUpdater.disableWebInstaller = true;
  autoUpdater.logger = {
    info: m => writeLog('info', `[updater] ${m}`),
    warn: m => writeLog('warn', `[updater] ${m}`),
    error: m => writeLog('error', `[updater] ${m}`),
    debug: () => {}
  };

  autoUpdater.on('checking-for-update', () => push({ phase: 'checking' }));
  autoUpdater.on('update-available', info => {
    const cur = String(info.currentVersion || app.getVersion());
    const remote = String(info.version);
    if (!isVersionNewerOrEqual(remote, cur)) {
      writeLog('warn', `[updater] 拒绝降级安装：远端 ${remote} < 当前 ${cur}（防降级，已忽略该次更新）`);
      push({ phase: 'latest', currentVersion: cur, via: activeMirror, downgradeBlocked: true });
      return;
    }
    // v3.6.5 M1-1：通道给的 version/sha512 必须与「已被内置公钥验签」的锚点逐字一致。
    // 为什么两个字段都比：version 决定我们下载哪个发布，sha512 决定校验哪个产物，缺一即可被替换。
    if (!verifiedAnchor || verifiedAnchor.version !== remote || String(info.sha512 || '') !== verifiedAnchor.sha512) {
      writeLog('error', `[updater] 更新信息与已验签锚点不一致，已拒绝（锚点版本 ${verifiedAnchor ? verifiedAnchor.version : '无'} / 通道版本 ${remote}）`);
      push({ phase: 'error', sigFailed: true, message: '更新信息与发布签名不一致，已阻止。请前往官方 Releases 页面手动下载安装包。' });
      return;
    }
    pendingAnchor = verifiedAnchor; // 交给 startDownload 在下载前复验
    writeLog('info', `[updater] 发现新版本 ${remote}（当前 ${cur}）`);
    push({
      phase: 'available',
      version: remote,
      currentVersion: cur,
      releaseNotes: normalizeNotes(info.releaseNotes),
      releaseDate: info.releaseDate,
      via: activeMirror
    });
  });
  autoUpdater.on('update-not-available', () =>
    push({ phase: 'latest', currentVersion: String(autoUpdater.currentVersion || app.getVersion()), via: activeMirror }));
  autoUpdater.on('download-progress', p => push({
    phase: 'downloading',
    percent: Math.round(p.percent || 0),
    speed: p.bytesPerSecond || 0,
    transferred: p.transferred || 0,
    total: p.total || 0
  }));
  autoUpdater.on('update-downloaded', info => {
    writeLog('info', `[updater] 新版本 ${info.version} 下载完成，等待用户确认安装`);
    push({ phase: 'ready', version: info.version });
  });
  autoUpdater.on('error', err => {
    // 后台静默检查常见网络抖动（国内访问 GitHub）：记日志即可，是否打扰用户由 safeCheck 的 silent 决定；
    // 但 autoUpdater 自身的 error 事件不区分触发来源，渲染层按本次检查是否手动决定是否弹窗。
    writeLog('error', `[updater] ${(err && err.stack) || err}`);
    push({ phase: 'error', message: (err && err.message) || String(err) });
  });

  // 启动 8s 后静默检查一次：避开窗口动画与概览预热的资源抢占期
  setTimeout(() => { safeCheck(true); }, 8000);
}

// 按单条线路检查一次；electron-updater 的 error 事件在本进程内先于 checkForUpdates 的
// rejection 回流，这里靠 mute 窗口期吞掉事件侧的重复推送，只以返回值为准。
function checkOnce(feed, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; resolve({ ok: false, error: `检查超时（${feed.label}）` }); }
    }, timeoutMs);
    autoUpdater.setFeedURL(feed.config);
    autoUpdater.checkForUpdates().then(() => {
      if (!settled) { settled = true; clearTimeout(timer); resolve({ ok: true, feed }); }
    }).catch(e => {
      if (!settled) { settled = true; clearTimeout(timer); resolve({ ok: false, error: e.message }); }
    });
  });
}

// silent=true：网络失败/无新版都不打扰用户（启动后台检查用）；
// 手动检查传 false，错误态由渲染层显性提示。
// 多线路容灾（P2-8）：按 orderedFeeds() 顺序逐条尝试，任一线路成功即止；
// 全部失败才报 error。成功线路记入 activeMirror 并回报渲染层（via 字段）。
async function safeCheck(silent = false) {
  if (!app.isPackaged) return { skipped: true, reason: 'dev' };
  if (checking) return { skipped: true, reason: 'already-checking' };
  checking = true;
  push({ phase: 'checking' });
  let lastError = '';
  let sigFailure = null; // v3.6.5 M1-1：签名类失败（与网络失败严格区分）
  try {
    const feeds = orderedFeeds();
    for (const feed of feeds) {
      // v3.6.5 M1-1：先验签，再让 electron-updater 检查。
      // 为什么逐线路独立验签而不是整轮拒绝：三条线路各自受同一把内置公钥约束，回退本身
      // 不放大风险，同时保留既有「镜像被污染时自动回落 GitHub 直连」的容灾能力（P2-8 的设计意图）。
      const anchor = await resolveTrustedAnchor(feed);
      if (!anchor.ok) {
        writeLog(anchor.kind === 'unreachable' ? 'warn' : 'error',
          `[updater] 线路 ${feed.label} 锚点校验未通过（${anchor.kind}）: ${anchor.reason}`);
        if (anchor.kind !== 'unreachable') sigFailure = anchor; // unsigned / mismatch
        lastError = anchor.reason;
        continue;                                               // 换下一条线路
      }
      verifiedAnchor = anchor;
      const r = await checkOnce(feed, CHECK_TIMEOUT_MS);
      if (r.ok) {
        activeMirror = feed.id;
        if (feed.id !== 'github') writeLog('info', `[updater] 经 ${feed.label} 检查成功`);
        return { ok: true, via: feed.id };
      }
      lastError = r.error || '未知错误';
      writeLog('warn', `[updater] 线路 ${feed.label} 检查失败: ${lastError}`);
    }
    writeLog('error', `[updater] 检查失败（全部线路）: ${lastError}`);
    // 签名类失败必须显性告知并给出手动出口——没有出口的安全策略会变成功能故障
    if (sigFailure) {
      if (!silent) push({ phase: 'error', sigFailed: true, message: sigFailure.kind === 'unsigned'
        ? '未取得发布签名，已阻止自动更新。请前往官方 Releases 页面手动下载安装包。'
        : '更新信息签名校验失败，可能被篡改，已阻止。请前往官方 Releases 页面手动下载安装包。' });
    } else if (!silent) push({ phase: 'error', message: lastError });
    return { ok: false, error: lastError };
  } finally {
    checking = false;
  }
}

async function startDownload() {
  if (cancelToken) return { ok: false, error: 'already-downloading' };
  // v3.6.5 M1-1：下载前复验。用户可能隔几分钟才点下载，期间发布侧内容可能已变化——
  // 若直接用检查阶段的锚点，就留出了一个 TOCTOU 窗口。这里重取一次并与锁定值比对。
  if (!pendingAnchor) {
    writeLog('warn', '[updater] 未取得已验签锚点，已拒绝下载（fail-closed）');
    push({ phase: 'error', sigFailed: true, message: '未取得发布签名，已阻止下载。请重新检查更新。' });
    return { ok: false, error: 'unsigned-or-unverified' };
  }
  const feed = orderedFeeds().find(f => f.id === activeMirror) || orderedFeeds()[0];
  const anchor = await resolveTrustedAnchor(feed);
  if (!anchor.ok || anchor.version !== pendingAnchor.version || anchor.sha512 !== pendingAnchor.sha512) {
    writeLog('warn', '[updater] 下载前复验失败，已拒绝下载');
    push({ phase: 'error', sigFailed: true, message: '发布签名在本次会话内发生变化，已阻止下载。请重新检查更新。' });
    return { ok: false, error: 'anchor-changed' };
  }
  cancelToken = new CancellationToken();
  try {
    await autoUpdater.downloadUpdate(cancelToken);
    return { ok: true };
  } catch (e) {
    // 用户主动取消时 electron-updater 抛 canceled，归位 idle 且不算错误弹窗
    const canceled = /cancel/i.test(e && e.message || '');
    cancelToken = null;
    writeLog('error', `[updater] 下载失败: ${e.message}`);
    push({ phase: canceled ? 'idle' : 'error', message: canceled ? '' : e.message });
    return { ok: false, canceled, error: e.message };
  }
}

function cancelDownload() {
  try { cancelToken && cancelToken.cancel(); } catch (_) {}
  cancelToken = null;
  push({ phase: 'idle' });
}

function installUpdate() {
  writeLog('info', '[updater] 用户确认安装，退出并执行替换');
  // isSilent=true 由 NSIS 静默安装；isForceRunAfter=true 安装完自动重启 Trim
  autoUpdater.quitAndInstall(true, true);
}

// P2-8：渲染层设置页切换镜像（'auto' = GitHub 优先 + 自动回退）
function setMirror(id) {
  const r = saveMirrorPref(id);
  if (r.ok) writeLog('info', `[updater] 更新镜像偏好已保存: ${id}`);
  return { ...r, mirror: mirrorPref };
}

function getMirror() {
  return { mirror: mirrorPref, options: [{ id: 'auto', label: '自动（推荐）' }, { id: 'github', label: 'GitHub 直连' }, ...MIRRORS.map(m => ({ id: m.id, label: m.label }))] };
}

module.exports = { initUpdater, safeCheck, startDownload, cancelDownload, installUpdate, setMirror, getMirror, MIRRORS };
