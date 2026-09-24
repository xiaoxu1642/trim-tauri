'use strict';
// ============================================================================
// pwsh-runtime.js —— 内置 PowerShell 7 运行时（v3.3.x，方案 A 兜底）
//
// 设计来源：update history/内置PowerShell7运行时-方案设计-2026-09-15.md
// 核心原则：随包 zip 作离线兜底、永远不删 zip、解压到 %LOCALAPPDATA%\Trim\pwsh\<version>\、
//           仅 .ready 标记存在才加入候选链、候选链末位（尊重用户自装版本）。
//
// 目录结构：
//   %LOCALAPPDATA%\Trim\pwsh\
//     ├─ 7.6.6\           ← 当前使用（内含 pwsh.exe）
//     │   └─ .ready       ← 校验通过的标记文件（含版本 + 解压时间戳）
//     └─ .extracting      ← 解压过程锁（防止并发解压，内容为持有者 pid）
//
// v3.5.4 加固（复核 N2/N3/N4/N6，2026-09-16）：
//   N2  内置 zip 解压前强制 SHA-256 比对随包 .sha256 校验件（fail-closed）
//   N3  运行时目录拒绝符号链接/联接点；解压后全树扫描拒绝符号链接条目（zip-slip 防护）
//   N4  .extracting 锁写入持有者 pid：pid 已死或锁过旧即判陈旧，清锁重试（原先永久卡死）
//   N6  cleanupOldVersions 一并回收陈旧 .extracting 锁
// ============================================================================

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PWSH_VERSION = '7.6.6';
const PWSH_ZIP_NAME = `PowerShell-${PWSH_VERSION}-win-x64.zip`;

// M3（v3.6.5）N-1：解压进度为确定性估算，以下常量即各阶段边界（见 extractBundledRuntime）。
const PROGRESS_EXTRACT_MIN = 10;   // 解压阶段起点（%）
const PROGRESS_EXTRACT_MAX = 70;   // 解压阶段封顶（%），此后进入校验/写标记阶段
const PROGRESS_FALLBACK_STEP = 6;  // 拿不到 zip 条目总数时的确定性步进（%/tick，单调不倒退）

// 内置 zip 的定位：打包后在 resources/pwsh/ 下，dev 形态在 vendor/pwsh/ 下
function resolveBundledZip() {
  const candidates = [
    process.resourcesPath ? path.join(process.resourcesPath, 'pwsh', PWSH_ZIP_NAME) : null,
    path.join(__dirname, '..', '..', 'vendor', 'pwsh', PWSH_ZIP_NAME),
    path.join(process.cwd(), 'vendor', 'pwsh', PWSH_ZIP_NAME),
  ].filter(Boolean);
  for (const c of candidates) {
    try { if (fs.existsSync(c) && fs.statSync(c).size > 0) return c; } catch (_) {}
  }
  return null;
}

// N2：内置 zip 完整性校验（fail-closed）。
// 随包必须带 <zip>.sha256 校验件（构建期由 Get-FileHash 生成，见 package.json
// extraResources）。zip 落在用户可写目录（dev 形态 vendor / 打包后仍可能被本机
// 软件篡改），仅靠安装包外层签名不够；解压前流式比对 SHA-256，不一致即拒绝。
function sha256File(file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(file, { highWaterMark: 4 * 1024 * 1024 });
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function verifyBundledZipIntegrity(zipPath) {
  const sidecar = `${zipPath}.sha256`;
  if (!fs.existsSync(sidecar)) {
    throw new Error(`内置 PowerShell 7 缺少校验件 ${path.basename(sidecar)}（构建期应随 zip 生成），已拒绝解压`);
  }
  let expected = '';
  try {
    // 校验件兼容三种格式：纯哈希 / "<hash>  <文件名>"（sha256sum）/ Get-FileHash 列表输出
    const text = fs.readFileSync(sidecar, 'utf8');
    const m = text.match(/\b[0-9a-fA-F]{64}\b/);
    if (!m) throw new Error('未找到 64 位十六进制哈希');
    expected = m[0].toLowerCase();
  } catch (e) {
    throw new Error(`内置 PowerShell 7 校验件不可读: ${e.message}`);
  }
  const actual = await sha256File(zipPath);
  if (actual !== expected) {
    throw new Error(`内置 PowerShell 7 zip 完整性校验失败（SHA-256 不匹配，预期 ${expected.slice(0, 12)}…，实际 ${actual.slice(0, 12)}…），已拒绝解压`);
  }
}

// N3：目录符号链接/联接点拒绝（与 writeTempScript 的 A1 基线对齐）。
// 运行时目录在用户可写位置，若被替换为链接，后续提权 pwsh 将执行任意目标。
function assertRealDirNoSymlink(dir) {
  let st;
  try { st = fs.lstatSync(dir); } catch (_) { return; } // 不存在由调用方处理
  if (st.isSymbolicLink()) {
    throw new Error(`运行时目录已被替换为符号链接/联接点，已拒绝使用: ${dir}`);
  }
}

// N3：解压后全树扫描，发现任何符号链接条目即拒绝（zip 内可构造 symlink 条目）。
function scanTreeForSymlinks(rootDir) {
  const stack = [rootDir];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) return full;
      if (e.isDirectory()) stack.push(full);
    }
  }
  return null;
}

// N4：.extracting 锁陈旧判定。锁内容为持有者 pid：
//   - pid 已不存在 → 持有进程已死（解压中途被杀），陈旧，可安全清锁重试
//   - 内容不可解析且超过 10 分钟 → 陈旧兜底
//   - 其余情况视为另一实例正在解压（already-extracting）
const LOCK_STALE_MS = 10 * 60 * 1000;
function isPidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}
function isStaleExtractingLock(lockFile) {
  let text = '';
  let mtimeMs = 0;
  try {
    text = fs.readFileSync(lockFile, 'utf8').trim();
    mtimeMs = fs.statSync(lockFile).mtimeMs;
  } catch (_) { return false; }
  const pid = parseInt(text, 10);
  if (Number.isFinite(pid) && pid > 0) return !isPidAlive(pid);
  return Date.now() - mtimeMs > LOCK_STALE_MS;
}

// 运行时根目录：%LOCALAPPDATA%\Trim\pwsh
function runtimeRootDir() {
  const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  return path.join(localAppData, 'Trim', 'pwsh');
}

// 某版本的 pwsh.exe 完整路径
function pwshExePathFor(version) {
  return path.join(runtimeRootDir(), version, 'pwsh.exe');
}

// 某版本目录的 .ready 标记路径
function readyMarkerPath(version) {
  return path.join(runtimeRootDir(), version, '.ready');
}

// 指定版本是否就绪（目录存在 + pwsh.exe 存在 + .ready 标记存在）
function isVersionReady(version) {
  const exe = pwshExePathFor(version);
  const marker = readyMarkerPath(version);
  try {
    return fs.existsSync(exe) && fs.statSync(exe).size > 0 && fs.existsSync(marker);
  } catch (_) {
    return false;
  }
}

// 找到所有已就绪版本（返回版本号数组，按 mtime 倒序，最新的在前）
function listReadyVersions() {
  const root = runtimeRootDir();
  if (!fs.existsSync(root)) return [];
  try {
    const entries = fs.readdirSync(root, { withFileTypes: true });
    const ready = [];
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      if (isVersionReady(e.name)) {
        try {
          const mt = fs.statSync(readyMarkerPath(e.name)).mtimeMs;
          ready.push({ version: e.name, mtime: mt });
        } catch (_) { /* 忽略 */ }
      }
    }
    ready.sort((a, b) => b.mtime - a.mtime);
    return ready.map(r => r.version);
  } catch (_) {
    return [];
  }
}

// 取最新已就绪版本的 pwsh.exe 路径（候选链入口 ⑤ 用这个）
function latestReadyExePath() {
  const versions = listReadyVersions();
  if (!versions.length) return null;
  const exe = pwshExePathFor(versions[0]);
  return fs.existsSync(exe) ? exe : null;
}

// 写 .ready 标记
function writeReadyMarker(version) {
  const marker = readyMarkerPath(version);
  const payload = JSON.stringify({
    version,
    readyAt: new Date().toISOString(),
    source: 'bundled-zip',
  });
  fs.writeFileSync(marker, payload, 'utf8');
}

// M3（v3.6.5）N-2：固定使用系统自带 tar.exe 的**绝对路径**（%SystemRoot%\System32\tar.exe）。
// 根因：原实现 spawn('tar.exe', ...) 依赖 PATH 查找。Trim 常驻且可能以管理员身份运行，
// 而 PATH 中用户可写目录（当前工作目录 / %USERPROFILE% / 用户自定义 PATH 项）可放置同名文件，
// 一旦被解析即在解压流程中获得执行机会（PATH 劫持 → 提权执行面）。
// 约束：找不到系统 tar.exe 时 fail-closed 抛错，**绝不回落到 PATH 查找**。
function resolveSystemTarExe() {
  const systemRoot = process.env.SystemRoot || process.env.windir || '';
  if (!systemRoot) {
    throw new Error('无法确定 SystemRoot，拒绝调用 tar.exe（防 PATH 劫持）');
  }
  const exe = path.join(systemRoot, 'System32', 'tar.exe');
  let st = null;
  try { st = fs.statSync(exe); } catch (_) { st = null; }
  if (!st || !st.isFile() || st.size === 0) {
    throw new Error(`未找到系统自带 tar.exe（${exe}），已拒绝回落到 PATH 查找（防劫持）；需要 Win10 1803+`);
  }
  return exe;
}

// M3（v3.6.5）N-1：读取 zip 条目总数（tar -tf 列表行数；目录条目以 / 结尾，不计入），
// 作为解压进度的分母。失败（条目过多致进程异常、磁盘错误等）返回 0，
// 调用方据此退化到「确定性阶段推进」，绝不使用随机数。
function countZipEntries(tarExe, zipPath) {
  return new Promise((resolve) => {
    let out = '';
    let child;
    try {
      child = spawn(tarExe, ['-tf', zipPath], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    } catch (_) {
      resolve(0);
      return;
    }
    child.stdout.on('data', (d) => { out += d.toString('utf8'); });
    child.on('error', () => resolve(0));
    child.on('close', (code) => {
      if (code !== 0) { resolve(0); return; }
      const n = out.split('\n').filter((l) => {
        const line = l.trim();
        return line && !line.endsWith('/');
      }).length;
      resolve(n > 0 ? n : 0);
    });
  });
}

// M3（v3.6.5）N-1：已落地文件数（迭代遍历，仅计文件，口径与 countZipEntries 对齐）。
// 读取失败（解压中途目录被占用等）返回已统计值——进度只会因单调约束停住，绝不倒退。
function countExtractedFiles(dir) {
  let sum = 0;
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch (_) { continue; }
    for (const e of entries) {
      if (e.isDirectory()) stack.push(path.join(cur, e.name));
      else sum++;
    }
  }
  return sum;
}

// 异步解压内置 zip 到目标版本目录；解压期间放 .extracting 锁，
// 成功后写 .ready；失败时清理半成品目录（保留 zip 本身不动）。
// onProgress(percent)  0-100，确定性估算且**单调递增**（永不倒退）：
//   解压阶段 = 10% + (已落地文件数 / zip 条目总数) × 60%；条目总数拿不到时按固定步进推进；
//   校验/写标记阶段为固定值 75/85/95/100。
function extractBundledRuntime({ onProgress, isPwsh7Executable } = {}) {
  return new Promise((resolve, reject) => {
    const zipPath = resolveBundledZip();
    if (!zipPath) {
      reject(new Error('未找到内置 PowerShell 7 zip 包'));
      return;
    }
    const rootDir = runtimeRootDir();
    const versionDir = path.join(rootDir, PWSH_VERSION);
    const lockFile = path.join(rootDir, '.extracting');
    let tarExe = '';       // M3 N-2：系统 tar.exe 绝对路径（解析失败即终止）
    let totalEntries = 0;  // M3 N-1：zip 条目总数（0 = 拿不到，退化阶段推进）

    try {
      if (fs.existsSync(rootDir)) {
        // N3：根目录若被替换为符号链接/联接点，直接拒绝（fail-closed）
        assertRealDirNoSymlink(rootDir);
      } else {
        // mode 0o700：仅所有者可进入（Windows 上 ACL 继承自用户目录，此处为跨平台双保险）
        fs.mkdirSync(rootDir, { recursive: true, mode: 0o700 });
      }
      // 解压互斥：已有另一处在解压则直接等（这里不做事件通知，直接返回 pending 态）。
      // N4：锁存在不等于有人在解压——持有者 pid 已死即陈旧锁，清掉重试，
      // 否则进程在解压中途被杀后内置 pwsh 将永久不可用（复核 N4）。
      if (fs.existsSync(lockFile)) {
        if (isStaleExtractingLock(lockFile)) {
          try { fs.unlinkSync(lockFile); } catch (_) {}
        } else {
          resolve({ status: 'already-extracting' });
          return;
        }
      }
      // 已就绪则直接返回
      if (isVersionReady(PWSH_VERSION)) {
        resolve({ status: 'already-ready', version: PWSH_VERSION, exe: pwshExePathFor(PWSH_VERSION) });
        return;
      }
      // 清掉半成品（上次解压被打断的残留）
      if (fs.existsSync(versionDir)) {
        try { fs.rmSync(versionDir, { recursive: true, force: true, maxRetries: 3 }); } catch (_) {}
      }
      fs.mkdirSync(versionDir, { recursive: true, mode: 0o700 });
      assertRealDirNoSymlink(versionDir);
      // 写入持有者 pid，供陈旧判定（N4）
      fs.writeFileSync(lockFile, String(process.pid), 'utf8');
    } catch (e) {
      reject(new Error(`无法创建运行时目录: ${e.message}`));
      return;
    }

    // M3（v3.6.5）N-1：进度出口统一走 emitProgress，保证**永不倒退**。
    // 原实现每 800ms 回调 onProgress(10 + Math.floor(Math.random() * 55))：与实际解压
    // 进度无关且会前后乱跳（进度条倒退），也掩盖了「是否卡住」的判断依据。
    let lastPercent = 0;
    const emitProgress = (percent) => {
      if (!onProgress) return;
      const p = Math.max(0, Math.min(100, Math.round(percent)));
      if (p <= lastPercent) return; // 单调约束：只允许前进
      lastPercent = p;
      onProgress(p);
    };

    emitProgress(5);

    let settled = false;
    const finish = (err, result) => {
      if (settled) return;
      settled = true;
      try { fs.unlinkSync(lockFile); } catch (_) {}
      if (err) {
        // 失败清理半成品
        try { if (fs.existsSync(versionDir)) fs.rmSync(versionDir, { recursive: true, force: true, maxRetries: 3 }); } catch (_) {}
        reject(err);
      } else {
        resolve(result);
      }
    };

    // N2：解压前强制完整性校验（SHA-256 比对随包 .sha256 校验件，fail-closed）
    verifyBundledZipIntegrity(zipPath).then(() => {
      // M3 N-2：解析系统 tar.exe 绝对路径（fail-closed，不回落到 PATH）
      tarExe = resolveSystemTarExe();
      // M3 N-1：取 zip 条目总数作为确定性进度分母（拿不到则返回 0，退化阶段推进）
      return countZipEntries(tarExe, zipPath);
    }).then((entries) => {
      totalEntries = entries;
      startTar();
    }).catch((e) => { finish(e); });

    function startTar() {
    // 用系统自带 tar.exe 解压（bsdtar，Win10 1803+，速度快且无长路径问题）。
    // M3 N-2：进程路径固定为上一步解析出的绝对路径（tarExe），不再走 PATH 查找。
    let child;
    try {
      child = spawn(tarExe, ['-xf', zipPath, '-C', versionDir], {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (e) {
      finish(new Error(`无法启动 tar.exe: ${e.message}`));
      return;
    }

    // M3（v3.6.5）N-1：确定性进度——已落地文件数 / zip 条目总数 映射到 10%~70%；
    // 条目总数不可得时按固定步进单调推进（fallback 亦为确定值，绝不使用随机数）。
    let fallbackStage = PROGRESS_EXTRACT_MIN;
    let progressTimer = setInterval(() => {
      if (totalEntries > 0) {
        const ratio = Math.min(1, countExtractedFiles(versionDir) / totalEntries);
        emitProgress(PROGRESS_EXTRACT_MIN + ratio * (PROGRESS_EXTRACT_MAX - PROGRESS_EXTRACT_MIN));
      } else {
        fallbackStage = Math.min(PROGRESS_EXTRACT_MAX, fallbackStage + PROGRESS_FALLBACK_STEP);
        emitProgress(fallbackStage);
      }
    }, 800);

    child.on('error', (err) => {
      clearInterval(progressTimer);
      finish(new Error(`tar.exe 启动失败: ${err.message}`));
    });
    child.on('close', (code) => {
      clearInterval(progressTimer);
      if (code !== 0) {
        finish(new Error(`tar.exe 解压失败，退出码 ${code}`));
        return;
      }
      emitProgress(75);

      // N3：解压产物全树扫描——zip 内若被构造符号链接条目，落地后必须拒绝
      const symlinkHit = scanTreeForSymlinks(versionDir);
      if (symlinkHit) {
        finish(new Error(`解压产物中发现符号链接条目（${path.relative(versionDir, symlinkHit)}），包可能被篡改，已拒绝`));
        return;
      }

      // 校验：pwsh.exe 必须存在且非 0 字节
      const exe = pwshExePathFor(PWSH_VERSION);
      if (!fs.existsSync(exe) || fs.statSync(exe).size === 0) {
        finish(new Error('解压完成但 pwsh.exe 不存在，包可能损坏'));
        return;
      }
      emitProgress(85);

      // 调用方传进来的 pwsh 可执行性校验（带超时参数）
      if (typeof isPwsh7Executable === 'function') {
        try {
          const ok = isPwsh7Executable(exe, 15000);
          if (!ok) {
            finish(new Error('解压后 pwsh.exe 无法运行（可能被安全软件拦截）'));
            return;
          }
        } catch (e) {
          finish(new Error(`pwsh 校验异常: ${e.message}`));
          return;
        }
      }
      emitProgress(95);

      try {
        writeReadyMarker(PWSH_VERSION);
      } catch (e) {
        finish(new Error(`写入 .ready 标记失败: ${e.message}`));
        return;
      }
      emitProgress(100);
      finish(null, { status: 'ready', version: PWSH_VERSION, exe });
    });
    } // startTar
  });
}

// 清理旧版本：保留当前版 + 上一版，其余删除（避免占用无限膨胀）。
// N6：一并回收陈旧 .extracting 锁（持有者已死才清，正在解压时不动）。
function cleanupOldVersions(keepVersions = []) {
  const root = runtimeRootDir();
  if (!fs.existsSync(root)) return { removed: 0 };
  let removed = 0;
  try {
    const lockFile = path.join(root, '.extracting');
    if (fs.existsSync(lockFile) && isStaleExtractingLock(lockFile)) {
      try { fs.unlinkSync(lockFile); } catch (_) {}
    }
    const ready = listReadyVersions();
    const keep = new Set([...keepVersions, ...ready.slice(0, 2)]);
    const entries = fs.readdirSync(root, { withFileTypes: true });
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      if (keep.has(e.name)) continue;
      try {
        fs.rmSync(path.join(root, e.name), { recursive: true, force: true, maxRetries: 3 });
        removed++;
      } catch (_) { /* 忽略删不掉的（可能正被占用）*/ }
    }
    return { removed };
  } catch (_) {
    return { removed };
  }
}

module.exports = {
  PWSH_VERSION,
  PWSH_ZIP_NAME,
  resolveBundledZip,
  runtimeRootDir,
  pwshExePathFor,
  isVersionReady,
  listReadyVersions,
  latestReadyExePath,
  extractBundledRuntime,
  cleanupOldVersions,
  writeReadyMarker,
};
