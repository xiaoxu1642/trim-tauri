'use strict';
// ============================================================================
// v2.2 第 2 批（D18）：受保护路径清单的**唯一权威实现**（JS 判定 + PowerShell 判定）
//
// 为什么要有这个模块：
//   1. D18 的原始缺口——永久删除主路径 Remove-PathSafely **完全没有**保护判定
//      （main.js 的 isProtectedDeletePath 只挂在回收站落地、回收失败重试、
//      finder:delete 三处），而清理脚本要删的路径来自「快照 items」，
//      快照又源自**可被外部写入的规则 JSON**（在线更新 + 完全不验签的
//      %APPDATA%\Trim\cleanup\custom\*.json）。也就是说：能改规则文件 = 能让脚本
//      递归删除任意路径，中间一道闸都没有。故保护判定必须**前置到 PS 删除入口**。
//   2. 判定规则原先只存在于 main.js，且只有一种语义（子树），
//      一旦照抄注入 PS 会立刻炸掉既有功能（见下「双语义的由来」）。
//      两侧必须同源：清单与语义在 JS 算好，PS 只做同口径字符串比较。
//
// 双语义的由来（实测结论，勿再改回单语义）：
//   旧实现把 6 个系统根一律按「子树」判拒（等于根 **或** 在根之下都拒）。
//   用内置规则求值基线（48 条非空 pathPs/candidatesPs）跑一遍，**16 条被误判**：
//     WINDIR\Prefetch、WINDIR\SoftwareDistribution\Download、WINDIR\Logs\WindowsUpdate、
//     WINDIR\System32\winevt\Logs、WINDIR\System32\DriverStore\Temp、WINDIR\WinSxS\Temp、
//     WINDIR\Minidump、WINDIR\Installer\$PatchCache$、WINDIR\System32\winevt\Logs、
//     PROGRAMDATA\Microsoft\Diagnosis、PROGRAMDATA\...\WER\ReportArchive、
//     PROGRAMDATA\...\Defender\Scans\History\Results、PROGRAMDATA\NVIDIA Corporation\NV_Cache、
//     C:\Program Files (x86)\Steam\appcache、C:\$Recycle.Bin
//   ——清理工具的本质就是删系统根**之下**的缓存/日志，子树语义与之天然冲突。
//   现状只影响「删除进回收站」分支（默认未勾选，所以问题一直潜伏）；
//   若把旧清单原样前置到 Remove-PathSafely，等于把 Prefetch、更新缓存等主力项一起废掉。
//   因此拆成两种语义：
//     · subtree：目标 === 根 或 目标在根之下 → 拒。用于「整棵都不许碰」的目录
//       （应用自身数据、注册表配置单元）。
//     · exact  ：目标 === 根 或 根在目标之下（目标是根的祖先）→ 拒。用于「根本身不许
//       被端掉，但里面的缓存照删」的容器（系统根、用户内容根）。
//   注意：USERPROFILE / APPDATA / LOCALAPPDATA **绝不能**进 subtree 清单，
//   否则 %APPDATA%\Tencent\QQ、%APPDATA%\Code、Documents\xwechat_files\*\temp
//   这类既有合法目标全部误伤。
//
// 为什么 C:\$Recycle.Bin 不在清单里（刻意决策）：
//   内置规则 recycleBin 的 pathPs 就是 'C:\$Recycle.Bin'，且 UI 把它作为
//   「回收站」清理项呈现给用户。按 exact 收录会让这个用户可见功能直接失效，
//   属删除面语义变更，超出本批「纯安全收口」范围。回收站内容本就是用户已丢弃之物，
//   清空它是清理工具的正常职责而非误删风险。
//   → 已记入待办：D19 批把该规则改写为 Clear-RecycleBin / 逐 SID 子目录口径
//     （现在这条规则是硬编码 C: 盘 + 递归删根，本身也不规范），届时再把
//     回收站根收回 exact 清单。
//
// 已知局限（与旧实现一致，未在本批扩大范围）：
//   · 符号链接/junction 不解析：目标是链接时按链接路径本身判定，删链接不会递归到
//     真实目录内容（Remove-Item 语义），故风险可控。
//   · 8.3 短名与 \\?\ 前缀已在归一化里处理（短名一律 fail-closed 判受保护）。
//   · 相对路径由各自进程 CWD 解析（JS=path.resolve，PS=[IO.Path]::GetFullPath），
//     理论上两侧基准目录不同；实际入口路径恒为绝对路径，且解析异常一律 fail-closed。
//   · 注册表条目（regKeys）走独立的 excludeKeys 保护，不在文件系统清单内。
// ============================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');

// ---------------------------------------------------------------------------
// 路径归一化：判定前两侧都走同一套规则（JS 与 PS 实现必须逐条对应）
//   1) 空串/纯空白 → 视为受保护（fail-closed，拒绝删除未知目标）
//   2) 解析为绝对路径（顺带折叠 . 与 ..，堵掉 C:\Windows\..\Windows 之类写法）
//   3) 8.3 短名先触盘展开再判定（v3.7.2 受保护路径误杀修复）：
//      运行时环境会把合法短名喂进来（本机 TEMP=C:\Users\ADMINI~1\...，tempFiles
//      规则求值即命中），磁盘上存在的短名组件展开为长名后正常参与判定；
//      展开不掉（目标/前缀不存在）保留 fail-closed。
//   4) 去掉尾部空白与点号（Win32 路径比较会忽略它们，不能靠这个绕过）
//   5) 去掉尾部分隔符，盘符根归一为 "C:" 后单独判拒
//   6) 统一小写（Windows 路径大小写不敏感；JS toLowerCase 与 PS ToLowerInvariant 等价）
// ---------------------------------------------------------------------------

// 8.3 短名展开（v3.7.2）：fs.realpathSync.native 在 Windows 走 GetFinalPathNameByHandle，
// 能把磁盘上已存在的短名组件展开为长名（与 PS 侧 [IO.Path]::GetFullPath 的展开语义对齐：
// 已存在组件展开、不存在组件原样保留）。整条路径不存在时退化为「最深已存在祖先展开 +
// 保留剩余段」。任何一步失败都返回空串，由调用方保持 fail-closed。
// 仅处理本地盘符路径：UNC / 相对路径不做触盘展开（宁可多拦不误放）。
function expandShortPathWin(p) {
  if (!/^[A-Za-z]:[\\/]/.test(p)) return '';
  try {
    return fs.realpathSync.native(p);
  } catch (e) { /* 末端不存在，向下找已存在祖先 */ }
  const segs = p.split(/[\\/]+/).filter(Boolean);
  for (let i = segs.length - 2; i >= 1; i--) {
    try {
      const long = fs.realpathSync.native(segs.slice(0, i + 1).join('\\'));
      const rest = segs.slice(i + 1);
      return rest.length ? long.replace(/[\\/]+$/, '') + '\\' + rest.join('\\') : long;
    } catch (e) { /* 继续向上找 */ }
  }
  return '';
}

function normalizeForCompare(p) {
  let s = String(p == null ? '' : p).trim();
  if (!s) return { ok: false, low: '' };
  // \\?\ 前缀是 Win32 的「跳过解析」形式，去掉后再走归一化，否则可绕过全部比较。
  // UNC（\\server\share）不去：清理目标可能是网络位置，交给白名单语义处理。
  if (s.startsWith('\\\\?\\')) s = s.slice(4);
  // 裸盘符 "C:" 必须在 resolve 之前拦下：Node 的 path.resolve 会把它当「驱动器相对路径」
  // 拼上当前工作目录（结果随 CWD 变化），而 .NET 的 GetFullPath 原样返回，两侧会分歧。
  if (/^[A-Za-z]:$/.test(s)) return { ok: true, low: s.toLowerCase(), driveRoot: true };
  try {
    s = path.resolve(s);
  } catch (e) {
    return { ok: false, low: '' };
  }
  // 8.3 短名：先触盘展开（合法短名放行、口径与 PS 侧 GetFullPath 对齐），展开不掉才拒。
  // 展开必须发生在 resolve 之后：resolve 折叠 .. 与 PS GetFullPathName 的折叠行为一致，
  // 两侧对「短名 + ..」混写的折叠结果相同（折叠后短名消失与 Win32 逐段解析语义等价）。
  if (/~\d/.test(s)) {
    const ex = expandShortPathWin(s);
    if (ex) s = ex; else return { ok: false, low: '', shortName: true };
  }
  s = s.replace(/[ .]+$/, '');
  while (s.length > 1 && (s.endsWith('\\') || s.endsWith('/'))) {
    s = s.slice(0, -1);
  }
  if (/^[A-Za-z]:$/.test(s)) return { ok: true, low: s.toLowerCase(), driveRoot: true };
  const low = s.toLowerCase().replace(/\//g, '\\');
  // 展开/归一后仍含短名（磁盘上不存在的短名组件，与 PS 侧 GetFullPath 之后的第二次
  // 判定同位）同样 fail-closed
  if (/~\d/.test(low)) return { ok: false, low: '', shortName: true };
  return { ok: true, low, driveRoot: false };
}

function envPath(...segs) {
  return path.join(...segs);
}

// Windows 环境变量名大小写不敏感，但 Node 的 process.env 保留原始大小写，
// 实测不同启动方式（Electron / pwsh 子进程 / CI）给出的键名大小写并不一致，
// 故按三种常见写法兜底取值，绝不允许因为取不到 APPDATA 就退化成「无保护」。
function env(name) {
  const v = process.env[name] || process.env[name.toUpperCase()] || process.env[name.toLowerCase()];
  return (typeof v === 'string' && v.trim()) ? v.trim() : '';
}

// 默认清单：只依赖 process.env（主进程与测试进程都能算出同一结果）
function buildDefaultRoots() {
  const drive = (env('SystemDrive') || 'C:').replace(/[\\]+$/, '');
  const home = env('USERPROFILE') || os.homedir();
  const appData = env('APPDATA') || envPath(home, 'AppData', 'Roaming');
  const localAppData = env('LOCALAPPDATA') || envPath(home, 'AppData', 'Local');
  const windir = env('WINDIR') || envPath(drive, 'Windows');
  const programData = env('PROGRAMDATA') || envPath(drive, 'ProgramData');
  // 归一化清单每一项（折叠 . / ..、去尾分隔符、小写），避免 env 值带尾斜杠
  // 时清单与待判路径口径不一致导致「看起来配了其实没生效」。
  const norm = (list) => Array.from(new Set(list.map((x) => normalizeForCompare(x).low).filter(Boolean)));
  return {
    // 整棵不许碰：应用自身数据（规则库/自定义规则/日志/备份/临时脚本都在里面）、
    // 注册表配置单元目录（SAM/SECURITY/SYSTEM 蜂巢及其事务日志）。
    // 系统还原点容器见下方 anyDrive（旧实现按子树拦，本批保持同等覆盖面、
    // 并顺带补上旧实现漏掉的其他分区）。
    subtree: norm([
      envPath(appData, 'Trim'),
      envPath(windir, 'System32', 'config'),
    ]),
    // 根本身不许端掉、祖先不许顺带，但根之下的缓存/日志照常清理。
    // 系统根一律取自环境变量而非「SystemDrive + 硬编码目录名」：
    // Windows 可装在任何盘、任何目录名（多语言/自定义安装），硬编码会静默失效。
    exact: norm([
      windir,
      env('ProgramFiles') || envPath(drive, 'Program Files'),
      env('ProgramFiles(x86)') || envPath(drive, 'Program Files (x86)'),
      programData,
      home,
      envPath(home, 'Desktop'),
      envPath(home, 'Documents'),
      envPath(home, 'Downloads'),
      appData,
      localAppData,
    ]),
    // 「任意盘符下的这个目录名」整棵不许碰。盘符根与系统卷信息在每个分区都存在，
    // 旧实现只按 SystemDrive 生成一份，其他盘（清理工具常见目标）等于不设防；
    // 目录名不本地化，故可用固定字符串匹配。
    anyDrive: ['system volume information'],
  };
}

let _roots = null;

// 主进程启动后补一次真实值：Electron 的 known folder 会被注册表重定向
// （桌面/文档/下载常见于 OneDrive 接管），纯 env 推导覆盖不到；
// APP_DATA_DIR 在 dev 形态也可能不是 %APPDATA%\Trim。
function configureProtectedRoots(extra) {
  const cfg = extra || {};
  _roots = buildDefaultRoots();
  for (const r of (cfg.extraSubtree || [])) {
    const n = normalizeForCompare(r);
    if (n.ok && !_roots.subtree.includes(n.low)) _roots.subtree.push(n.low);
  }
  for (const r of (cfg.extraExact || [])) {
    const n = normalizeForCompare(r);
    if (n.ok && !_roots.exact.includes(n.low)) _roots.exact.push(n.low);
  }
  for (const r of (cfg.extraAnyDrive || [])) {
    const nm = String(r || '').trim().toLowerCase();
    if (nm && !_roots.anyDrive.includes(nm)) _roots.anyDrive.push(nm);
  }
  return _roots;
}

function protectedRoots() {
  if (!_roots) _roots = buildDefaultRoots();
  return _roots;
}

// 语义与 PS 侧 Test-PathProtected 必须逐字对应，test-features 用同一批向量对拍两侧。
function isPathProtected(p, roots) {
  const R = roots || protectedRoots();
  const n = normalizeForCompare(p);
  if (!n.ok) return true;
  if (n.driveRoot) return true;
  const low = n.low;
  // 任意盘符下的同名目录（如每个分区的 System Volume Information）整棵受保护。
  // 不用正则：PS 侧正则里的反斜杠要穿三层转义（JS 模板 / PS 字符串 / .NET 正则），
  // 极易出错，两侧统一改成 Substring/startsWith 的字面量比较。
  for (const nm of (R.anyDrive || [])) {
    if (!nm) continue;
    if (low.length < nm.length + 3) continue; // 至少要有 "x:\" + 目录名
    if (low[1] !== ':' || low[2] !== '\\') continue;
    const tail = low.slice(3);
    if (tail === nm || tail.startsWith(nm + '\\')) return true;
  }
  for (const r of (R.subtree || [])) {
    if (low === r || low.startsWith(r + '\\')) return true;
  }
  for (const r of (R.exact || [])) {
    if (low === r || r.startsWith(low + '\\')) return true;
  }
  return false;
}

// 注入 PS 的清单：JSON 里存的已经是「归一化后的小写绝对路径」，
// PS 只需把待判路径归一化到同一口径再比字符串，语义不可能漂移。
function protectedRootsJson() {
  const R = protectedRoots();
  return JSON.stringify({
    subtree: R.subtree.slice(),
    exact: R.exact.slice(),
    anyDrive: (R.anyDrive || []).slice(),
  });
}

// ---------------------------------------------------------------------------
// PowerShell 侧判定片段（模板字符串内严禁出现反引号，会终止 JS 模板）
// 约定：函数体内不得 Write-Output 任何诊断文本，否则污染返回值（本项目既有陷阱）。
// ---------------------------------------------------------------------------
const PROTECT_PATH_PS = `
# ==== 受保护路径判定（与 src/main/ps-protect-path.js 的 JS 实现同语义）====
# 入参 $tfProtectedRoots 由主进程注入：{ subtree = [...], exact = [...], anyDrive = [...] }，
# 元素均为「已归一化小写绝对路径」或「小写目录名」，故这里只做字符串比较。
function Resolve-TFPathKey {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
  $bs = [string][char]92
  $s = $Path.Trim()
  # 长路径前缀（两个反斜杠 + 问号 + 一个反斜杠）会让 Win32 跳过路径解析，
  # 必须剥掉再比较，否则可绕过下面全部判定。UNC 的两个反斜杠 + 服务器名保留。
  if ($s.StartsWith(($bs + $bs + '?' + $bs))) { $s = $s.Substring(4) }
  # 裸盘符提前拦下，与 JS 侧 normalizeForCompare 同位置判定（.NET 对裸盘符的处理
  # 与 Node 的 path.resolve 不同口径，交给下游解析会两侧分歧）
  if ($s -match '^[A-Za-z]:$') { return $s.ToLowerInvariant() }
  $n = ''
  # v3.7.2 受保护路径误杀修复：先 GetFullPath 再判短名。
  # .NET GetFullPath（GetFullPathNameW）会把磁盘上已存在的短名组件展开成长名——
  # 运行时环境喂进来的合法短名（本机 TEMP=C:\Users\ADMINI~1\...，tempFiles 规则
  # 求值即命中）借此正常放行；展开不掉（目标不存在，字符串原样保留）时，
  # 下方解析后的第二次 ~数字 判定仍 fail-closed。旧逻辑「进解析前见 ~ 就拒」
  # 对「规则以字面路径出现」的假设成立，但对 $env:TEMP 这类运行时展开是误杀。
  try { $n = [System.IO.Path]::GetFullPath($s) } catch { return '' }
  $n = $n.TrimEnd(' ', '.')
  while ($n.Length -gt 1 -and ($n.EndsWith($bs) -or $n.EndsWith('/'))) {
    $n = $n.Substring(0, $n.Length - 1)
  }
  $low = $n.ToLowerInvariant()
  # 解析/展开后仍含短名（该短名组件在磁盘上不存在，GetFullPathName 原样保留）
  # 同样 fail-closed：宁可多拦不误放
  if ($low -match '~[0-9]') { return '' }
  return $low
}

# 返回 $true = 受保护（必须拒绝删除）。归一化失败一律 $true（fail-closed）。
function Test-PathProtected {
  param([string]$Path, $Roots)
  $low = Resolve-TFPathKey -Path $Path
  if ($low -eq '') { return $true }
  if ($low -match '^[A-Za-z]:$') { return $true }
  $sub = @()
  $exa = @()
  $any = @()
  if ($Roots) {
    $sub = @($Roots.subtree)
    $exa = @($Roots.exact)
    $any = @($Roots.anyDrive)
  }
  $bs = [string][char]92
  # 任意盘符下的同名目录（每个分区的系统卷信息等）整棵受保护。
  # 与 JS 侧同样用字面量 Substring 比较，不走正则（正则里的反斜杠要穿三层转义，易错）。
  foreach ($nm in $any) {
    if (-not $nm) { continue }
    if ($low.Length -lt ($nm.Length + 3)) { continue }
    if ($low.Substring(1, 2) -ne (':' + $bs)) { continue }
    $tail = $low.Substring(3)
    if ($tail -eq $nm -or $tail.StartsWith($nm + $bs)) { return $true }
  }
  foreach ($r in $sub) {
    if (-not $r) { continue }
    if ($low -eq $r -or $low.StartsWith($r + $bs)) { return $true }
  }
  foreach ($r in $exa) {
    if (-not $r) { continue }
    if ($low -eq $r -or $r.StartsWith($low + $bs)) { return $true }
  }
  return $false
}
`;

module.exports = {
  buildDefaultRoots,
  configureProtectedRoots,
  protectedRoots,
  protectedRootsJson,
  isPathProtected,
  normalizeForCompare,
  PROTECT_PATH_PS,
};
