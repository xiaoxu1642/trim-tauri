// PowerShell 清理脚本（嵌入为 JS 字符串）
// 参考了 上级目录中的 cmd/bat 清理脚本逻辑：
//   - 删除 Windows 更新缓存.cmd (stop wuauserv + rd SoftwareDistribution + md)
//   - 删除临时文件.cmd (takeown + RD /S /Q + MKDIR)
//   - 删除日志文件.cmd (del *.log)
//   - 清除 DNS 缓存.cmd (ipconfig /flushdns)
//   - 重建性能计数器.cmd (lodctr /r)
// 并扩展为完整版（参考 require.md 中 19 大类）
//
// 数据化（P1-9）：清理项定义以 src/data/cleanup-rules.json 为唯一数据源。
// 「规则引擎升级（P1）」起条目支持三类目标模型，扫描/执行均按以下优先级路由：
//   1. special === 'dism'   专项分支（DISM /ResetBase，不走文件/注册表模型）
//   2. fileKeys[]           文件模式清理（路径支持 %ENV% 与 * 通配、pattern 文件名
//                           过滤、removeSelf 剪除空目录；excludeKeys 排除目录/文件）
//   3. regKeys[]            注册表清理（扫描只做存在性计数；执行按 value 语义删除：
//                           无 value=删整树（受 excludeKeys reg 保护分支约束）、
//                           value:'*'=仅清键值、value:'名'=删指定值）
//   4. pathPs               目录型条目（整目录，向后兼容既有条目）
// 通用字段：detect[]（安装检测，OR 语义，全部不命中则该条目不参与扫描）；
//           requiredStoppedProcesses（已接线：扫描标注 blockedBy 提示，执行命中即跳过）。
// 规则 JSON 整体经 RULES_JSON_PLACEHOLDER 注入（单引号转义，不注入可执行代码），
// 避免逐字段拼 PS 源码的转义风险。
//
// 「规则库在线更新（P2）」：主进程把更新后的规则写到数据目录 cleanup\rules.json，
// loadRules() 读取优先级 = 数据目录 rules.json > 内置 JSON > 空；custom\*.json
// 为用户自定义开关（仅 {id, enabled} 引用内置条目，不得自带删除目标，审查 B-3）。

const fs = require('fs');
const path = require('path');
const DIAG = require('../main/diag');
// v2.2 第 2 批（D1）：规则路径表达式受限求值器片段，与 pathscan-scripts 共用同一定义
const { RULE_PATH_EVAL_PS } = require('../main/ps-rule-path-eval');
// v2.2 第 2 批（D18）：受保护路径清单的唯一来源。main.js 启动时用 Electron known folder
// 补全后调 configureProtectedRoots，本模块经 require 缓存拿到同一份清单再注入 PS。
const PROTECT = require('../main/ps-protect-path');
// 🟡1：数据目录规则读取侧复验 ed25519 签名，与写入侧 main.js cleanup:update-rules 共用同一实现。
const RULES_SIG = require('../main/rules-signature');
// 火眼眼审查 2026-09-14（MED）：规则库防回滚水位线——验签只证「内容出自发布方」，
// 不证「是最新一份」；能写数据目录者可重放一份旧但合法签名的规则集，重新引入已下线的
// 危险删除目标。本模块在每次成功采用更高版本后记录 rulesVersion 水位线，读侧与更新侧
// 低于水位线（或低于内置版本）的已验签规则一律拒绝（fail-closed，只升不降）。
const SECURITY = require('../main/security');

const RULES_FILE = path.join(__dirname, '..', 'data', 'cleanup-rules.json');
// 数据目录与 main.js APP_DATA_DIR（%APPDATA%\Trim）保持一致；此处不依赖 electron app
const DATA_RULES_DIR = path.join(process.env.APPDATA || path.join(require('os').homedir(), 'AppData', 'Roaming'), 'Trim', 'cleanup');
const DATA_RULES_FILE = path.join(DATA_RULES_DIR, 'rules.json');
const CUSTOM_RULES_DIR = path.join(DATA_RULES_DIR, 'custom');
const RULES_WATERMARK_FILE = path.join(DATA_RULES_DIR, 'rules-watermark.json');

let RULES_CACHE = null;
let RULES_CACHE_SIG = '';

function safeReadJson(file) {
  try {
    if (!fs.existsSync(file)) return null;
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return parsed && Array.isArray(parsed.groups) ? parsed : null;
  } catch (e) {
    return null;
  }
}

function collectGroupItems(group) {
  if (group.subGroups) return group.subGroups.flatMap(sg => sg.items || []);
  return group.items || [];
}

// 合并自定义规则（审查 B-3 收口，2026-09-14）：custom\*.json 只允许 {id, enabled} 开关
// 内置条目，不再「同名 id 覆盖字段 / 新 id 追加条目」。规则决定删除目标，而 custom 目录
// 是用户级可写位置——若允许自定义条目自带 pathPs/candidatesPs/regKeys 等删除目标，任何
// 能写该目录的进程都可借 Trim 的管理员执行面递归删除任意目录（延迟投递通道）。
// 出现白名单外字段即整文件拒载（fail-closed、不半生效）；enabled=false 同样合法（关掉某内置项）。
const CUSTOM_TOGGLE_FIELDS = new Set(['id', 'enabled']);
function applyCustomToggles(rules, parsed, fileLabel) {
  const byId = new Map();
  for (const g of (rules.groups || [])) {
    for (const it of collectGroupItems(g)) byId.set(it.id, it);
  }
  // 第一遍：全量校验，任一条目携带白名单外字段即拒载整份文件
  for (const g of (parsed.groups || [])) {
    for (const it of collectGroupItems(g)) {
      if (!it || typeof it !== 'object') continue;
      const extra = Object.keys(it).filter(k => !CUSTOM_TOGGLE_FIELDS.has(k));
      if (extra.length) {
        console.warn(`[cleanup] 自定义规则 ${fileLabel} 条目 ${it.id || '(缺 id)'} 携带禁止字段（${extra.join('、')}），整文件拒载（审查 B-3：custom 目录仅允许 {id, enabled} 开关内置条目）`);
        return false;
      }
    }
  }
  // 第二遍：逐条应用开关；引用未知 id 只忽略该条，不影响文件内其余开关
  for (const g of (parsed.groups || [])) {
    for (const it of collectGroupItems(g)) {
      if (!it || !it.id) continue;
      const hit = byId.get(it.id);
      if (!hit) { console.warn(`[cleanup] 自定义规则 ${fileLabel} 引用未知条目 id: ${it.id}，已忽略`); continue; }
      if (typeof it.enabled === 'boolean') { hit.enabled = it.enabled; }
    }
  }
  return true;
}

// 火眼眼审查 2026-09-14（MED）：防回滚水位线读写。水位线只升不降（取历史最大值），
// 损坏/不可读按 0 处理（不阻断正常流程；规则文件本身仍有验签兜底）。
function getRulesWatermark() {
  try {
    const m = JSON.parse(fs.readFileSync(RULES_WATERMARK_FILE, 'utf8'));
    const v = Number(m && m.rulesVersion);
    return Number.isFinite(v) && v > 0 ? v : 0;
  } catch (e) {
    return 0;
  }
}

function setRulesWatermark(version) {
  const v = Number(version);
  if (!Number.isFinite(v) || v <= 0 || v <= getRulesWatermark()) return false;
  try {
    SECURITY.atomicWriteJson(RULES_WATERMARK_FILE, { rulesVersion: v, at: new Date().toISOString() });
    return true;
  } catch (e) {
    console.warn('[cleanup] 写规则版本水位线失败:', e.message);
    return false;
  }
}

// 🟡1：读取数据目录规则并复验 ed25519 签名。仅当签名通过且结构合法才返回，否则 null（回退内置规则）。
// 写入侧 main.js cleanup:update-rules 已在落盘前验签；此处补上读取侧复验，堵住「下载后被本地篡改」的旁路。
// 火眼眼审查 2026-09-14（MED）：验签通过后另做防回滚比对——低于内置版本（应用自带的更可信）
// 或低于历史已采用水位线的规则一律拒绝，防止重放旧签名文件重新引入已下线的危险删除目标。
function readVerifiedDataRules() {
  try {
    if (!fs.existsSync(DATA_RULES_FILE)) return null;
    const text = fs.readFileSync(DATA_RULES_FILE, 'utf8');
    const verdict = RULES_SIG.verifyRulesSignature(text);
    if (!verdict.ok) {
      console.warn('[cleanup] 数据目录规则验签未通过，已回退内置规则:', verdict.reason);
      return null;
    }
    const parsed = JSON.parse(text);
    if (!parsed || !Array.isArray(parsed.groups)) return null;
    const v = Number(parsed.rulesVersion) || 0;
    const builtin = safeReadJson(RULES_FILE);
    const builtinVersion = Number(builtin && builtin.rulesVersion) || 0;
    const watermark = getRulesWatermark();
    const floor = Math.max(builtinVersion, watermark);
    if (floor > 0 && v < floor) {
      console.warn(`[cleanup] 数据目录规则版本(${v})低于防回滚下限(${floor})，疑似旧签名文件重放，已回退内置规则`);
      return null;
    }
    return parsed;
  } catch (e) {
    return null;
  }
}

function loadRules() {
  const custom = [];
  try {
    if (fs.existsSync(CUSTOM_RULES_DIR)) {
      for (const f of fs.readdirSync(CUSTOM_RULES_DIR)) {
        if (!f.toLowerCase().endsWith('.json')) continue;
        const full = path.join(CUSTOM_RULES_DIR, f);
        const stat = fs.statSync(full);
        custom.push({ path: full, mtimeMs: stat.mtimeMs });
      }
    }
  } catch (e) { /* 自定义目录不可读则忽略 */ }
  let dataMTime = 0;
  let dataSize = 0;
  try {
    if (fs.existsSync(DATA_RULES_FILE)) {
      const st = fs.statSync(DATA_RULES_FILE);
      dataMTime = st.mtimeMs;
      dataSize = st.size;
    }
  } catch (e) {}
  // size 一并入缓存键：防「保留 mtime 的篡改」绕过读取侧复验（🟡1）
  const sig = dataMTime + '|' + dataSize + '|' + custom.length + '|' + custom.map(c => c.mtimeMs).join(',');
  if (RULES_CACHE && sig === RULES_CACHE_SIG) return RULES_CACHE;

  // 优先级：数据目录（在线更新产物）> 内置。数据目录走验签复验（fail-closed），失败自动回退内置。
  // custom\*.json 不再并入规则正文，只允许做内置条目的启用开关（applyCustomToggles，审查 B-3）。
  let rules = readVerifiedDataRules() || safeReadJson(RULES_FILE);
  if (!rules) rules = { version: 0, rulesVersion: 0, groups: [] };
  for (const c of custom) {
    const parsed = safeReadJson(c.path);
    if (parsed && !applyCustomToggles(rules, parsed, path.basename(c.path))) {
      console.warn(`[cleanup] 自定义规则文件已拒载: ${c.path}`);
    }
  }
  RULES_CACHE = rules;
  RULES_CACHE_SIG = sig;
  return rules;
}

// PS 单引号字符串转义：' → ''（用于注入 JSON/字面量值）
function psEscapeSingle(s) {
  return String(s).replace(/'/g, "''");
}

// v2.1 扫描加速：主进程经 setFastSizeDll 注入 TrimFastSize.dll 绝对路径，
// 模板内 FASTSIZE_DLL_PLACEHOLDER 替换为 PS 单引号转义后的路径；
// 为空或加载失败时脚本侧 $useFastSize=false，自动降级回 Get-ChildItem 原实现。
let FASTSIZE_DLL = '';
function setFastSizeDll(p) {
  FASTSIZE_DLL = (p && typeof p === 'string') ? p : '';
}

// ==================== 扫描脚本 ====================
const SCAN_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# v2.2 第1批（D5）：全局 SilentlyContinue 有意保留——扫描要遍历成百上千个 ACL 受限目录，
# 逐条非终止错误若抛出会淹没 stdout 并把退出码变成非 0（主进程按整体失败处理）。
# 但它会吞掉「真失败」，故本轮补两条腿：① 致命错误（规则/入参解析失败）显式写 stderr + 非 0 退出；
# ② 规模统计改走 Get-PathStats 三态出口，统计失败不再伪装成 0 字节。
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
${DIAG.PS_PREAMBLE}

# 扫描加速（v2.1）：TrimFastSize.dll 走 FindFirstFile 枚举直接带出 Length（5.3x）。
# 主进程注入绝对路径；DLL 缺失或加载失败时 $useFastSize=false，函数自动降级回原实现。
$__fastDll = '\${FASTSIZE_DLL_PLACEHOLDER}'
$useFastSize = $false
if ($__fastDll -and (Test-Path -LiteralPath $__fastDll)) {
  try { Add-Type -Path $__fastDll; $useFastSize = $true } catch { $useFastSize = $false }
}

$rulesJson = '\${RULES_JSON_PLACEHOLDER}'
# 超长 JSON 用 -InputObject 解析（管道长字符串在本机 pwsh 有解析异常风险）
$rules = ConvertFrom-Json -InputObject $rulesJson
$categories = ('\${CATEGORIES_PLACEHOLDER}' | ConvertFrom-Json)
$configuredPaths = ('\${CONFIGURED_PATHS_PLACEHOLDER}' | ConvertFrom-Json)

# v2.2 第1批（D5）：致命错误必须显式失败。全局静默下 ConvertFrom-Json 失败只会得到 $null，
# 旧行为是「扫完输出 0 项 + 退出码 0」，渲染层显示「无可清理」，用户完全看不出规则库坏了。
if ($null -eq $rules) { [Console]::Error.WriteLine('规则库解析失败：cleanup-rules 内容不可用'); exit 2 }
# 空数组 [] 解析后同样是 $null，但主进程 cleanup:scan 入口已强制 categories.length >= 1，
# 走到这里说明入参被破坏（或被绕过主进程直接调用），当致命错误处理不会误伤正常流程。
if ($null -eq $categories) { [Console]::Error.WriteLine('扫描分类参数解析失败'); exit 2 }
if ($null -eq $configuredPaths) { [Console]::Error.WriteLine('路径绑定配置解析失败'); exit 2 }

# id -> 规则条目映射（数据目录覆盖与自定义合并已在主进程完成）
$ruleMap = @{}
foreach ($g in $rules.groups) {
  if ($g.subGroups) { foreach ($sg in $g.subGroups) { foreach ($it in $sg.items) { $ruleMap[$it.id] = $it } } }
  elseif ($g.items) { foreach ($it in $g.items) { $ruleMap[$it.id] = $it } }
}

# P1：一次性取全量进程名（requiredStoppedProcesses 扫描侧探测，逐条 Get-Process 太慢）
$runningProcessNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $null = $runningProcessNames.Add($p.ProcessName) }

${RULE_PATH_EVAL_PS}
# %ENV% 展开：未定义的变量保持原样，便于在路径列直接看出配置问题
function Expand-EnvPath {
  param([string]$Path)
  return [regex]::Replace($Path, '%([^%]+)%', {
    param($m)
    $v = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
    if ($v) { $v } else { $m.Value }
  })
}

# 目录通配解析：逐段展开 * / ?（** 暂不支持），返回真实存在的目录列表。
# 跳过 ReparsePoint（junction/symlink）防循环；裸盘符修正为根目录。
function Resolve-GlobDirs {
  param([string]$Pattern)
  $expanded = Expand-EnvPath $Pattern
  if (-not $expanded.Contains('*')) {
    if (Test-Path -LiteralPath $expanded -PathType Container) { return @($expanded) }
    return @()
  }
  $segments = @($expanded -split '[\\\\/]' | Where-Object { $_ })
  if ($segments.Count -eq 0) { return @() }
  $roots = @()
  $start = 0
  if ($segments[0].EndsWith(':')) { $roots = @($segments[0] + '\\'); $start = 1 }
  else { $roots = @('\\') }
  for ($i = $start; $i -lt $segments.Count; $i++) {
    $seg = $segments[$i]
    $next = New-Object System.Collections.Generic.List[string]
    foreach ($r in $roots) {
      if ($seg.Contains('*') -or $seg.Contains('?')) {
        foreach ($c in (Get-ChildItem -Path (Join-Path $r $seg) -Directory -Force -ErrorAction SilentlyContinue)) {
          if (-not ($c.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $next.Add($c.FullName) }
        }
      } else {
        $p = Join-Path $r $seg
        if (Test-Path -LiteralPath $p -PathType Container) { $next.Add($p) }
      }
    }
    $roots = @($next | Select-Object -Unique)
    if ($roots.Count -eq 0) { return @() }
  }
  return $roots
}

# 注册表路径映射：HKCU\\... → Registry::HKEY_CURRENT_USER\\...（不依赖 PSDrive 挂载）
function Convert-RegPath {
  param([string]$RegPath)
  $idx = $RegPath.IndexOf('\\')
  if ($idx -lt 0) { return $null }
  $hive = $RegPath.Substring(0, $idx).ToUpperInvariant()
  $rest = $RegPath.Substring($idx + 1)
  $map = @{ HKCU = 'HKEY_CURRENT_USER'; HKLM = 'HKEY_LOCAL_MACHINE'; HKCR = 'HKEY_CLASSES_ROOT'; HKU = 'HKEY_USERS'; HKCC = 'HKEY_CURRENT_CONFIG' }
  if (-not $map.ContainsKey($hive)) { return $null }
  return ('Registry::' + $map[$hive] + '\\' + $rest)
}

function Test-RegPathExists {
  param([string]$RegPath)
  $p = Convert-RegPath $RegPath
  if (-not $p) { return $false }
  return (Test-Path -LiteralPath $p)
}

# P1：安装检测（OR 语义）——detect 为空时退化为「主路径存在性判定」（v2.2 第4批 D9）。
# 旧语义：无 detect 恒命中 → 44 条不写 detect 的条目无论软件装没装都错误出现，
# 与 readme「没装的软件对应条目扫描时自动隐藏」相悖。现退化为判定该规则要清理的主路径
# 是否存在：不存在（软甲未装/从未产生）即隐藏。detect 是一次求值、通用于本函数。
function Test-RuleDetect {
  param($Rule)
  # 注意：属性缺失时 @($null) 的 Count 是 1，必须先判空，否则未声明 detect 的条目会被误判为未命中
  if ($Rule.detect) {
    $d = @($Rule.detect)
    if ($d.Count -ne 0) {
      foreach ($c in $d) {
        if (-not $c -or -not $c.path) { continue }
        if ($c.type -eq 'reg') {
          if (Test-RegPathExists (Expand-EnvPath ([string]$c.path))) { return $true }
        } else {
          $p = Expand-EnvPath ([string]$c.path)
          if ($p.Contains('*')) {
            if ((Resolve-GlobDirs $p).Count -gt 0) { return $true }
          } elseif (Test-Path -LiteralPath $p) { return $true }
        }
      }
      return $false
    }
  }
  # v2.2 第4批（D9）：无 detect → 退化为「主路径存在性判定」。取该规则自身要清理的主路径：
  # fileKeys 首键 glob 展开命中、pathPs 求值路径存在、regKeys 首键存在任一即命中；
  # 三类都取不到（special 条目不按路径清理）时保留恒命中，避免误隐藏特殊项。
  $rkF = @($Rule.fileKeys)
  if ($rkF.Count -gt 0 -and $rkF[0] -and $rkF[0].path) {
    $fp = Expand-EnvPath ([string]$rkF[0].path)
    if ($fp.Contains('*')) { return ((Resolve-GlobDirs $fp).Count -gt 0) }
    return (Test-Path -LiteralPath $fp)
  }
  if ($Rule.pathPs) {
    $rpc = Resolve-RulePath -Expr ([string]$Rule.pathPs)
    if ($rpc.ok) { return (Test-Path -LiteralPath ([string]$rpc.path)) }
    return $true # 表达式求值失败（受限语法）→ 保守命中，交给主循环 fail-closed 跳过节流
  }
  $rkR = @($Rule.regKeys)
  if ($rkR.Count -gt 0 -and $rkR[0] -and $rkR[0].path) {
    return (Test-RegPathExists (Expand-EnvPath ([string]$rkR[0].path)))
  }
  return $true
}

# P1：requiredStoppedProcesses 扫描侧探测 → blockedBy（渲染层展示提示标签）
function Get-BlockedProcesses {
  param($Rule)
  $out = @()
  foreach ($pn in @($Rule.requiredStoppedProcesses)) {
    if ($pn -and $runningProcessNames.Contains([string]$pn)) { $out += [string]$pn }
  }
  return @($out)
}

# 收集一个条目 fileKeys 的全部候选文件：通配基目录枚举 + pattern 过滤 +
# excludeKeys（dir 前缀 / file 全路径）过滤 + 跨键 FullName 去重 + 跳过 ReparsePoint
function Get-FileKeySnapshot {
  param($Rule)
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $exclDirs = @(); $exclFiles = @()
  foreach ($ex in @($Rule.excludeKeys)) {
    if (-not $ex -or -not $ex.path -or $ex.type -eq 'reg') { continue }
    $ep = (Expand-EnvPath ([string]$ex.path)).TrimEnd('\\')
    if ($ex.type -eq 'dir') { $exclDirs += $ep.ToLowerInvariant() }
    else { $exclFiles += $ep.ToLowerInvariant() }
  }
  $files = New-Object System.Collections.Generic.List[object]
  foreach ($fk in @($Rule.fileKeys)) {
    if (-not $fk -or -not $fk.path) { continue }
    $pattern = '*'; if ($fk.pattern) { $pattern = [string]$fk.pattern }
    $recurse = $true; if ($fk.recurse -eq $false) { $recurse = $false }
    foreach ($dir in (Resolve-GlobDirs ([string]$fk.path))) {
      $gciArgs = @{ LiteralPath = $dir; Filter = $pattern; File = $true; Force = $true; ErrorAction = 'SilentlyContinue' }
      if ($recurse) { $gciArgs.Recurse = $true; $gciArgs.Depth = 24 }
      foreach ($f in (Get-ChildItem @gciArgs)) {
        if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        $full = $f.FullName
        if (-not $seen.Add($full)) { continue }
        $low = $full.ToLowerInvariant()
        $skip = $false
        foreach ($d in $exclDirs) { if ($low.StartsWith($d + '\\')) { $skip = $true; break } }
        if (-not $skip) { foreach ($fe in $exclFiles) { if ($low -eq $fe) { $skip = $true; break } } }
        if ($skip) { continue }
        $files.Add([pscustomobject]@{ Path = $full; Size = [long]$f.Length })
      }
    }
  }
  # 注意：本机 pwsh 对非空 List[object] 做 @() 包裹会抛 ArgumentException（实测），
  # 必须用 ToArray() 转数组
  return $files.ToArray()
}

# v2.2 第3批（D7）：PS 侧可删性探针（TrimFastSize.dll 不可用时的降级路径）。
# 以独占方式打开（FileShare.None），任一进程持该文件句柄即失败 → 判为不可删。
# 语义与 TrimFastSize.ListDeletable 的 Deletable() 完全一致（保守：宁可少报，不可虚报）。
# 函数体内无任何写 stdout 输出，返回值不会被诊断行污染。
function Test-FileDeletable {
  param([string]$Path)
  try {
    $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'None')
    try { $null = $fs.Length } finally { $fs.Dispose() }
    return $true
  } catch { return $false }
}

# v2.2 第3批（D7/D13）：fileKeys 扫描侧可删性探测——枚举具体文件 + 独占打开探测，
# 被占用文件不计入 size/count（根治「显示 8GB、清理完只释放 300MB」的虚报）。
# 返回 total=可删字节合计；count=可删文件数；locked=被占用数；files=可删文件清单
#（Path/Size，供调用方以 @@PLANFILE@@ 行流式回传；执行阶段只删这份清单，不再重 glob，D13）。
# 口径与 Get-FileKeyStats 一致：DLL 可用且规则无 excludeKeys/recurse:false 时
# 用 ListDeletable 按目录一次拿全（C# 内探测）；否则降级 Get-FileKeySnapshot + PS 探测。
function Get-FileKeyDeletable {
  param($Rule)
  $hasExcl = $false
  if ($Rule.excludeKeys) { if (@($Rule.excludeKeys).Count -gt 0) { $hasExcl = $true } }
  # M2/M3（2026-09-14 重复点审查）：声明了 restartProcesses 的条目（图标/缩略图缓存、打印后台缓存）
  # 会在执行侧临时停止占用进程，因此扫描阶段不做占用探测 —— 否则这些文件会被 explorer/spoolsv 独占，
  # 全部判为 locked 而不进计划清单，执行侧拿不到可删文件（等于清不掉）。
  # 陷阱修复（Rust 化对拍发现）：旧写法 @($Rule.restartProcesses).Count 在属性缺失时 @($null).Count
  # 是 1（架构第十节判空陷阱），导致未声明该键的条目全部被误判为「免探测」，locked 恒 0、
  # 被占用文件混进计划清单（D7 口径失效）。判空必须先 -not $x。
  $rp = $Rule.restartProcesses
  $skipLockCheck = ($null -ne $rp -and (@($rp | Where-Object { $_ }).Count -gt 0))
  $needList = $skipLockCheck -or (-not $useFastSize) -or $hasExcl
  if (-not $needList) {
    foreach ($fk in @($Rule.fileKeys)) {
      if ($fk -and $fk.recurse -eq $false) { $needList = $true; break }
    }
  }
  $files = New-Object 'System.Collections.Generic.List[object]'
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $totalCount = 0L; $totalSize = 0L; $deletableCount = 0L
  if ($needList) {
    $snap = @(Get-FileKeySnapshot -Rule $Rule)
    foreach ($f in $snap) {
      $totalCount++
      if ($skipLockCheck -or (Test-FileDeletable -Path ([string]$f.Path))) {
        $totalSize += [long]$f.Size
        $deletableCount++
        $files.Add([pscustomobject]@{ Path = [string]$f.Path; Size = [long]$f.Size })
      }
    }
  } else {
    foreach ($fk in @($Rule.fileKeys)) {
      if (-not $fk -or -not $fk.path) { continue }
      $pattern = '*'; if ($fk.pattern) { $pattern = [string]$fk.pattern }
      foreach ($dir in (Resolve-GlobDirs ([string]$fk.path))) {
        try {
          $res = [TrimFastSize]::ListDeletable($dir, $pattern)
          $totalCount += [long]$res.TotalCount
          foreach ($f in @($res.Files)) {
            $deletableCount++
            if (-not $seen.Add([string]$f.Path)) { continue }
            $totalSize += [long]$f.Size
            $files.Add([pscustomobject]@{ Path = [string]$f.Path; Size = [long]$f.Size })
          }
        } catch { }
      }
    }
  }
  return [pscustomobject]@{
    total = $totalSize
    count = [long]$files.Count
    locked = ($totalCount - $deletableCount)
    files = $files.ToArray()
  }
}

# v2.2 第3批（D7）：目录型条目（pathPs）的扫描统计改走可删口径——与 Get-PathStats 同为
# 三态出口（ok/missing/size/nfiles），但 size/nfiles 只计探测通过的可删文件，locked=被占用数。
# DLL 可用时用 ListDeletable（C# 内探测，单次枚举）；否则 Get-ChildItem + PS 探测降级。
# 注意：本函数只存在于 SCAN 模板。EXECUTE 的 freed 实测仍用 Get-PathStats 全量口径——
# 删除前后全量差值 = 实际释放字节，删不掉的被占用文件自然留在 after 侧，不会被冒领。
function Get-PathDeletableStats {
  param([string]$Path)
  if (-not $Path) { return [pscustomobject]@{ ok = $false; missing = $true; size = 0L; nfiles = 0L; locked = 0L } }
  $isDir = [System.IO.Directory]::Exists($Path)
  if (-not $isDir) {
    if ([System.IO.File]::Exists($Path)) {
      if (-not (Test-FileDeletable -Path $Path)) {
        return [pscustomobject]@{ ok = $true; missing = $false; size = 0L; nfiles = 0L; locked = 1L }
      }
      try { return [pscustomobject]@{ ok = $true; missing = $false; size = [long]([System.IO.FileInfo]::new($Path).Length); nfiles = 1L; locked = 0L } }
      catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L; locked = 0L } }
    }
    return [pscustomobject]@{ ok = $true; missing = $true; size = 0L; nfiles = 0L; locked = 0L }
  }
  try {
    $probe = [System.IO.Directory]::EnumerateFileSystemEntries($Path).GetEnumerator()
    try { $null = $probe.MoveNext() } finally { $probe.Dispose() }
  } catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L; locked = 0L } }
  if ($useFastSize) {
    try {
      $res = [TrimFastSize]::ListDeletable($Path, '*')
      $size = 0L
      foreach ($f in @($res.Files)) { $size += [long]$f.Size }
      return [pscustomobject]@{ ok = $true; missing = $false; size = $size; nfiles = [long]@($res.Files).Count; locked = ([long]$res.TotalCount - [long]@($res.Files).Count) }
    } catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L; locked = 0L } }
  }
  $size = 0L; $n = 0L; $lk = 0L
  try {
    foreach ($f in (Get-ChildItem -LiteralPath $Path -File -Recurse -Depth 24 -Force -ErrorAction SilentlyContinue)) {
      if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
      if (Test-FileDeletable -Path $f.FullName) { $size += [long]$f.Length; $n++ } else { $lk++ }
    }
    return [pscustomobject]@{ ok = $true; missing = $false; size = $size; nfiles = $n; locked = $lk }
  } catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L; locked = 0L } }
}

# 注册表条目扫描：只做存在性 + 规模计数（删除留到执行阶段）
function Measure-RegRule {
  param($Rule)
  $exists = $false; $count = 0
  foreach ($rk in @($Rule.regKeys)) {
    if (-not $rk -or -not $rk.path) { continue }
    $p = Convert-RegPath (Expand-EnvPath ([string]$rk.path))
    if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
    $exists = $true; $count++
    if ($rk.value) { continue }
    $key = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
    if ($key) {
      $count += @($key.GetValueNames()).Count
      $count += @(Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue).Count
    }
  }
  return [pscustomobject]@{ exists = $exists; count = $count }
}

# v2.2 第1批（D5/D6）：规模统计统一出口，把「路径不存在 / 真的是 0 / 统计失败」三态分开。
# 旧 Get-PathSize 把所有异常 catch 成 0：ACL 拒绝、长路径失败都会被当成「0 字节可清理」，
# 删除侧也就无从校验释放量（D6 的虚报正建立在这个假象上）。
# 返回 pscustomobject：ok=能否统计；missing=路径不存在；size=字节；nfiles=文件数
#（nfiles 顺带给出，供删除后残留复查复用，避免再遍历一次）。
# 注意：本函数在 SCAN / EXECUTE 两个模板里必须保持逐字一致，test-features.js 有双源断言。
function Get-PathStats {
  param([string]$Path)
  if (-not $Path) { return [pscustomobject]@{ ok = $false; missing = $true; size = 0L; nfiles = 0L } }
  # 存在性用 .NET 判定（与下面的枚举探针同源，不混用两套 API）。实测：目录存在但无列举权限时
  # Test-Path 仍返回 True，所以「存在」与「可统计」是两态，后者只能靠枚举探针区分
  $isDir = [System.IO.Directory]::Exists($Path)
  if (-not $isDir) {
    if ([System.IO.File]::Exists($Path)) {
      try { return [pscustomobject]@{ ok = $true; missing = $false; size = [long]([System.IO.FileInfo]::new($Path).Length); nfiles = 1L } }
      catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L } }
    }
    return [pscustomobject]@{ ok = $true; missing = $true; size = 0L; nfiles = 0L }
  }
  # 根目录连一个子项都列不出来 = 无法统计，绝不能报 0（权限不足 / 重解析目标异常）
  # 注意必须在 MoveNext 处捕获：EnumerateFileSystemEntries 是惰性迭代器，
  # FindFirstFile 的 ACL 拒绝异常要到第一次 MoveNext 才抛出（调用本身不会失败）。
  try {
    $probe = [System.IO.Directory]::EnumerateFileSystemEntries($Path).GetEnumerator()
    try { $null = $probe.MoveNext() } finally { $probe.Dispose() }
  } catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L } }
  if ($useFastSize) {
    # TrimFastSize.SumCount：FindFirstFile 枚举直接带出 Length，跳 ReparsePoint、忽略无权限子项
    try {
      $sc = [TrimFastSize]::SumCount($Path, '*')
      return [pscustomobject]@{ ok = $true; missing = $false; size = [long]$sc[0]; nfiles = [long]$sc[1] }
    } catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L } }
  }
  try {
    $files = @(Get-ChildItem -LiteralPath $Path -File -Recurse -Depth 24 -Force -ErrorAction SilentlyContinue)
    $sum = ($files | Measure-Object -Property Length -Sum).Sum
    return [pscustomobject]@{ ok = $true; missing = $false; size = [long]($sum -as [long]); nfiles = [long]$files.Count }
  } catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L } }
}

# 兼容旧调用点：只要字节数（无法统计按 0 处理）
function Get-PathSize {
  param([string]$Path)
  return [long](Get-PathStats -Path $Path).size
}

# 扫描阶段只取「总大小 + 文件数」：DLL 可用且规则无 excludeKeys、无 recurse:false 时
# 用 SumCount 按目录一次拿全（零对象构造，5.3x）；否则降级回逐文件枚举，
# 口径与 Get-FileKeySnapshot 一致（ReparsePoint 跳过、excludeKeys 过滤、跨键 FullName 去重）。
function Get-FileKeyStats {
  param($Rule)
  $hasExcl = $false
  if ($Rule.excludeKeys) { if (@($Rule.excludeKeys).Count -gt 0) { $hasExcl = $true } }
  $needList = (-not $useFastSize) -or $hasExcl
  if (-not $needList) {
    foreach ($fk in @($Rule.fileKeys)) {
      if ($fk -and $fk.recurse -eq $false) { $needList = $true; break }
    }
  }
  if ($needList) {
    $snap = @(Get-FileKeySnapshot -Rule $Rule)
    $t = 0L
    foreach ($f in $snap) { $t += $f.Size }
    return [pscustomobject]@{ total = $t; count = $snap.Count }
  }
  $total = 0L; $count = 0L
  foreach ($fk in @($Rule.fileKeys)) {
    if (-not $fk -or -not $fk.path) { continue }
    $pattern = '*'; if ($fk.pattern) { $pattern = [string]$fk.pattern }
    foreach ($dir in (Resolve-GlobDirs ([string]$fk.path))) {
      try {
        $sc = [TrimFastSize]::SumCount($dir, $pattern)
        $total += [long]$sc[0]; $count += [long]$sc[1]
      } catch { }
    }
  }
  return [pscustomobject]@{ total = $total; count = $count }
}

foreach ($cat in $categories) {
  $rule = $ruleMap[$cat]
  if ($null -eq $rule) { continue }

  # DISM 组件清理：非路径型条目，固定返回"可执行"状态（大小以实际执行结果为准）
  if ($rule.special -eq 'dism') {
    $dismItem = @{
      id = $cat
      name = $rule.name
      configuredPath = 'C:\\Windows\\WinSxS'
      path = 'C:\\Windows\\WinSxS'
      pathSource = 'configured'
      pathCandidates = @()
      autoPath = ''
      autoSize = 0
      size = 0
      risk = $rule.risk
      exists = $true
      blockedBy = @()
    }
    Write-Output ('@@ITEM@@' + ($dismItem | ConvertTo-Json -Compress -Depth 4))
    [Console]::Out.Flush()
    continue
  }

  # P1：安装检测——目标应用未安装的条目直接不输出（渲染层扫描后隐藏）
  if (-not (Test-RuleDetect -Rule $rule)) { continue }

  $blocked = @(Get-BlockedProcesses -Rule $rule)

  # ---- 文件模式条目（fileKeys）----
  if ($rule.fileKeys -and @($rule.fileKeys).Count -gt 0) {
    # v2.2 第3批（D7/D13）：扫描即产「可删文件清单」——被占用文件剔除出 size/count，
    # 清单以 @@PLANFILE@@ 行流式回传主进程（进快照）；明细与执行都只消费这份清单，
    # 不再做第二、第三次重枚举（D13 两阶段）。
    $st = Get-FileKeyDeletable -Rule $rule
    $total = $st.total
    $display = [string]$rule.fileKeys[0].path
    if (@($rule.fileKeys).Count -gt 1) { $display = $display + ' 等 ' + @($rule.fileKeys).Count + ' 处' }
    Write-Output ('@@ITEM@@' + (@{
      id = $cat
      name = $rule.name
      configuredPath = $display
      path = $display
      pathSource = 'rules'
      pathCandidates = @()
      autoPath = ''
      autoSize = 0
      size = $total
      fileCount = $st.count
      lockedCount = $st.locked
      risk = $rule.risk
      exists = ($st.count -gt 0)
      blockedBy = $blocked
    } | ConvertTo-Json -Compress -Depth 4))
    foreach ($pf in @($st.files)) {
      Write-Output ('@@PLANFILE@@' + (@{ id = $cat; path = $pf.Path; size = $pf.Size } | ConvertTo-Json -Compress))
    }
    [Console]::Out.Flush()
    continue
  }

  # ---- 注册表条目（regKeys）----
  if ($rule.regKeys -and @($rule.regKeys).Count -gt 0) {
    $m = Measure-RegRule -Rule $rule
    $display = [string]$rule.regKeys[0].path
    if (@($rule.regKeys).Count -gt 1) { $display = $display + ' 等 ' + @($rule.regKeys).Count + ' 处' }
    Write-Output ('@@ITEM@@' + (@{
      id = $cat
      name = $rule.name
      configuredPath = $display
      path = $display
      pathSource = 'rules'
      pathCandidates = @()
      autoPath = ''
      autoSize = 0
      size = $null
      fileCount = 0
      regCount = $m.count
      risk = $rule.risk
      exists = $m.exists
      blockedBy = $blocked
    } | ConvertTo-Json -Compress -Depth 4))
    [Console]::Out.Flush()
    continue
  }

  # ---- 目录型条目（pathPs）----
  if (-not $rule.pathPs) { continue }
  # v2.2 第2批（D1）：pathPs 改走受限求值器（语法见 RULE_PATH_EVAL_PS 注释）。
  # 同时废除旧兜底「求值失败就把表达式原文当路径」——那会让未求值的字面量
  # （如 $env:TEMP + '\\x'）直接进入路径列；受限求值失败一律 fail-closed 跳过该条。
  $rp = Resolve-RulePath -Expr ([string]$rule.pathPs)
  if (-not $rp.ok) {
    Write-TFDiag -Stage 'scan.pathPs' -Mutation 'skip' -Detail ($cat + ' pathPs 表达式不符合受限语法，已拒绝求值')
    continue
  }
  $path = [string]$rp.path
  $evaluatedPath = $path
  $pathSource = 'configured'
  $pathCandidates = @()
  $autoPath = ''
  # 应用缓存优先采用设置页已确认的路径；没有确认路径时才走内置候选。
  $configKeyMap = @{
    neteaseMusicCache = 'neteaseCacheDir'
    wechatCache = 'wechatCacheDir'
    douyinCache = 'douyinCacheDir'
    qqCache = 'qqCacheDir'
  }
  $configuredValue = [string]$configuredPaths.$cat
  if ($configKeyMap.ContainsKey($cat)) { $configuredValue = [string]$configuredPaths.($configKeyMap[$cat]) }
  if ($configuredValue) {
    $path = $configuredValue
    $pathSource = 'configured'
  }
  # [D19 根因·已知缺陷] 下面两个分支读的键名是 candidates / globCandidates，
  # 而规则 JSON 实际叫 candidatesPs / globCandidatesPs（全库无不带 Ps 的键），
  # 故两分支恒不执行：内置候选回退与微信缓存的通配候选整体失效。
  # 本轮（纯安全收口）刻意不修键名——一改就让 neteaseMusicCache/qqCache/douyinCache 换用
  # 候选路径、wechatCache 从「整条不出现」变成可删条目，属删除面行为变更，留待 D19 批评估。
  # 但 Invoke-Expression 必须先从这里拿掉：一旦将来补上键名，不重新引入任意代码执行面。
  if ($rule.candidates) {
    foreach ($cExpr in @($rule.candidates)) {
      if (-not $cExpr) { continue }
      $rc = Resolve-RulePath -Expr ([string]$cExpr)
      if ($rc.ok) { $pathCandidates += [string]$rc.path }
    }
    if (-not (Test-Path -LiteralPath $path)) {
      foreach ($candidate in $pathCandidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { $autoPath = [string]$candidate; $path = $autoPath; $pathSource = 'auto'; break }
      }
    }
  }
  if ($rule.globCandidates) {
    foreach ($gExpr in @($rule.globCandidates)) {
      if (-not $gExpr) { continue }
      $rg = Resolve-RulePath -Expr ([string]$gExpr)
      if (-not $rg.ok) { continue }
      $pat = [string]$rg.path
      $match = Get-ChildItem -Path $pat -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($match -and -not (Test-Path -LiteralPath $path)) { $autoPath = $match.FullName; $path = $autoPath; $pathSource = 'auto'; $pathCandidates += $match.FullName; break }
    }
  }
  # v2.2 第3批（D7）：目录型统计改走可删口径（Get-PathDeletableStats）——被占用文件
  # 不计入 size，扫描值即「真实可删值」；locked 只进协议不进 UI（本批渲染层不加提示）。
  $pathStats = Get-PathDeletableStats -Path $path
  # v2.2 第1批（D5）：统计失败上报 size=null——渲染层 size 单元格对 null 走「—」分支（cleanup.js:687），
  # 不再用 0 B 冒充「这里没有东西可清」；聚合总数时 null 按 0 计，不影响合计。
  $size = $null
  if ($pathStats.ok) { $size = $pathStats.size }
  # P1 修复：autoPath 命中时 size 即是 autoPath 的大小，不再二次枚举（原 autoSize 重复计算）
  $autoSize = 0
  if ($autoPath -and $path -eq $autoPath) { $autoSize = $size }
  # P1-12：逐项流式输出，主进程按行解析后增量推送渲染层（真实进度）
  Write-Output ('@@ITEM@@' + (@{
    id = $cat
    name = $rule.name
    configuredPath = $evaluatedPath
    path = $path
    pathSource = $pathSource
    pathCandidates = @($pathCandidates)
    autoPath = $autoPath
    autoSize = $autoSize
    size = $size
    lockedCount = $pathStats.locked
    risk = $rule.risk
    exists = (Test-Path -LiteralPath $path)
    blockedBy = $blocked
  } | ConvertTo-Json -Compress -Depth 4))
  [Console]::Out.Flush()
}

# P1-12：结果经 @@ITEM@@ 行流式回传，主进程按行聚合
`;

// ==================== 清理脚本 ====================
// P3：toRecycle=true 时进入「回收站模式」——PS 只枚举待删目标并输出 @@RECYCLE@@ 行，
// 实际移入回收站由主进程 shell.trashItem 完成（PS 内不做任何文件删除）；
// 注册表条目与 DISM 无回收站语义，仍在 PS 内直接执行（详情文案注明）。
// 删除模式下每项完成后做「残留复查」（residual：删除后仍存在的文件/注册表计数）。
const EXECUTE_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# v2.2 第1批（D5）：全局 SilentlyContinue 保留（删除期被占用文件逐条抛错会淹没结果协议输出），
# 但删除动作不再依赖「没报错 = 删干净」：Remove-PathSafely 统一按删除前后实测差值出结论，
# 有残留即 partial；同时规则/入参解析失败改为显式 stderr + 非 0 退出。
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
${DIAG.PS_PREAMBLE}

# 扫描加速（v2.1）：TrimFastSize.dll 走 FindFirstFile 枚举直接带出 Length（5.3x）。
# 主进程注入绝对路径；DLL 缺失或加载失败时 $useFastSize=false，函数自动降级回原实现。
$__fastDll = '\${FASTSIZE_DLL_PLACEHOLDER}'
$useFastSize = $false
if ($__fastDll -and (Test-Path -LiteralPath $__fastDll)) {
  try { Add-Type -Path $__fastDll; $useFastSize = $true } catch { $useFastSize = $false }
}

$itemsJson = '\${ITEMS_PLACEHOLDER}'
$force = \${FORCE_PLACEHOLDER}
$recycle = \${RECYCLE_PLACEHOLDER}
$autoRebuild = \${AUTO_REBUILD_PLACEHOLDER}
$items = $itemsJson | ConvertFrom-Json
$rulesJson = '\${RULES_JSON_PLACEHOLDER}'
$rules = ConvertFrom-Json -InputObject $rulesJson
# v2.2 第1批（D5）：解析失败绝不能「静默删 0 项 + 报成功」。
# 实测坑：'[]' | ConvertFrom-Json 与解析失败一样落变量都是 $null（PS 空数组语义），
# 两者无从区分，故合并为一条守卫——反正结果都是「无项可删」，必须显式失败而非返回成功。
if ($null -eq $items) { [Console]::Error.WriteLine('清理项不可用（入参解析失败或清单为空），拒绝执行'); exit 2 }
if ($null -eq $rules) { [Console]::Error.WriteLine('规则库解析失败：cleanup-rules 内容不可用'); exit 2 }

# v2.2 第2批（D18）：保护路径前置硬校验。永久删除主路径（Remove-PathSafely）原先
# **完全没有**保护判定，而删除目标源自可被外部写入的规则 JSON（在线更新 + 不验签的
# custom 目录）——能改规则文件就等于能删任意路径。清单与 JS 判定同源于
# src/main/ps-protect-path.js，这里只做同口径字符串比较。
# 清单解析失败必须显式退出：静默放行等于把新增的这道闸自己关掉（同 D5 的空值坑）。
${PROTECT.PROTECT_PATH_PS}
$tfProtectedRoots = ConvertFrom-Json -InputObject '\${PROTECTED_JSON_PLACEHOLDER}'
if ($null -eq $tfProtectedRoots) { [Console]::Error.WriteLine('受保护路径清单不可用，拒绝执行'); exit 2 }

$totalFreed = 0
$success = 0
$failed = 0
$skipped = 0
$details = @()

$ruleMap = @{}
foreach ($g in $rules.groups) {
  if ($g.subGroups) { foreach ($sg in $g.subGroups) { foreach ($it in $sg.items) { $ruleMap[$it.id] = $it } } }
  elseif ($g.items) { foreach ($it in $g.items) { $ruleMap[$it.id] = $it } }
}

# 系统关键进程白名单（这些文件不能删）
$protectedProcesses = @('svchost', 'explorer', 'winlogon', 'csrss', 'lsass')

# P1：执行侧一次性进程名快照（requiredStoppedProcesses 复检用）
$runningProcessNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $null = $runningProcessNames.Add($p.ProcessName) }

function Expand-EnvPath {
  param([string]$Path)
  return [regex]::Replace($Path, '%([^%]+)%', {
    param($m)
    $v = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
    if ($v) { $v } else { $m.Value }
  })
}

function Resolve-GlobDirs {
  param([string]$Pattern)
  $expanded = Expand-EnvPath $Pattern
  if (-not $expanded.Contains('*')) {
    if (Test-Path -LiteralPath $expanded -PathType Container) { return @($expanded) }
    return @()
  }
  $segments = @($expanded -split '[\\\\/]' | Where-Object { $_ })
  if ($segments.Count -eq 0) { return @() }
  $roots = @()
  $start = 0
  if ($segments[0].EndsWith(':')) { $roots = @($segments[0] + '\\'); $start = 1 }
  else { $roots = @('\\') }
  for ($i = $start; $i -lt $segments.Count; $i++) {
    $seg = $segments[$i]
    $next = New-Object System.Collections.Generic.List[string]
    foreach ($r in $roots) {
      if ($seg.Contains('*') -or $seg.Contains('?')) {
        foreach ($c in (Get-ChildItem -Path (Join-Path $r $seg) -Directory -Force -ErrorAction SilentlyContinue)) {
          if (-not ($c.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $next.Add($c.FullName) }
        }
      } else {
        $p = Join-Path $r $seg
        if (Test-Path -LiteralPath $p -PathType Container) { $next.Add($p) }
      }
    }
    $roots = @($next | Select-Object -Unique)
    if ($roots.Count -eq 0) { return @() }
  }
  return $roots
}

function Convert-RegPath {
  param([string]$RegPath)
  $idx = $RegPath.IndexOf('\\')
  if ($idx -lt 0) { return $null }
  $hive = $RegPath.Substring(0, $idx).ToUpperInvariant()
  $rest = $RegPath.Substring($idx + 1)
  $map = @{ HKCU = 'HKEY_CURRENT_USER'; HKLM = 'HKEY_LOCAL_MACHINE'; HKCR = 'HKEY_CLASSES_ROOT'; HKU = 'HKEY_USERS'; HKCC = 'HKEY_CURRENT_CONFIG' }
  if (-not $map.ContainsKey($hive)) { return $null }
  return ('Registry::' + $map[$hive] + '\\' + $rest)
}

# v2.2 第3批（D4）：reg.exe 不认 PowerShell 的 Registry:: provider 前缀，且 hive 必须用缩写
# （HKCU/HKLM...）才能导出；把 Convert-RegPath 的结果反向归一化后喂给 reg.exe export。
# 归一化失败时原样返回，reg.exe 大概率报错 → 走调用方的 fail-closed 分支，方向安全。
function Convert-RegPathForExport {
  param([string]$RegPath)
  $p = $RegPath
  if ($p.StartsWith('Registry::', [System.StringComparison]::OrdinalIgnoreCase)) {
    $p = $p.Substring('Registry::'.Length)
  }
  $map = @{ 'HKEY_CURRENT_USER' = 'HKCU'; 'HKEY_LOCAL_MACHINE' = 'HKLM'; 'HKEY_CLASSES_ROOT' = 'HKCR'; 'HKEY_USERS' = 'HKU'; 'HKEY_CURRENT_CONFIG' = 'HKCC' }
  foreach ($k in $map.Keys) {
    if ($p.StartsWith($k, [System.StringComparison]::OrdinalIgnoreCase)) {
      return ($map[$k] + $p.Substring($k.Length))
    }
  }
  return $p
}

function Get-BlockedProcesses {
  param($Rule)
  $out = @()
  foreach ($pn in @($Rule.requiredStoppedProcesses)) {
    if ($pn -and $runningProcessNames.Contains([string]$pn)) { $out += [string]$pn }
  }
  return @($out)
}

# M2/M3（2026-09-14 重复点审查）：restartProcesses —— 声明「必须临时停止占用进程才能清理、
# 清完立刻拉回」的条目（图标/缩略图缓存需 explorer、打印后台缓存需 spoolsv）。
# 与 requiredStoppedProcesses 的区别：后者命中即跳过、把关闭动作留给用户；前者由脚本自己停自己起。
# restart 取值：'process'（Stop-Process + 按原 Path 拉起）/ 'service'（Stop-Service + Start-Service）。
function Stop-Restartables {
  param($Rule)
  $done = @()
  foreach ($rp in @($Rule.restartProcesses)) {
    if (-not $rp -or -not $rp.name) { continue }
    if ([string]$rp.restart -eq 'service') {
      $svcName = [string]$rp.service
      if (-not $svcName) { $svcName = [string]$rp.name }
      $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
      if ($svc -and $svc.Status -eq 'Running') {
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 400
        $now = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($now -and $now.Status -ne 'Running') { $done += [pscustomobject]@{ kind = 'service'; target = $svc.Name; exe = '' } }
      }
    } else {
      $proc = Get-Process -Name ([string]$rp.name) -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($proc) {
        $exe = ''
        try { $exe = [string]$proc.Path } catch { $exe = '' }
        Stop-Process -Name ([string]$rp.name) -Force -ErrorAction SilentlyContinue
        $done += [pscustomobject]@{ kind = 'process'; target = [string]$rp.name; exe = $exe }
      }
    }
  }
  return @($done)
}

function Start-Restartables {
  param($Stopped)
  foreach ($d in @($Stopped)) {
    if (-not $d) { continue }
    if ([string]$d.kind -eq 'service') {
      Start-Service -Name ([string]$d.target) -ErrorAction SilentlyContinue
    } else {
      $exe = [string]$d.exe
      if ($exe -and (Test-Path -LiteralPath $exe)) { Start-Process -FilePath $exe -ErrorAction SilentlyContinue }
      else { Start-Process -FilePath ([string]$d.target + '.exe') -ErrorAction SilentlyContinue }
    }
  }
}

# 收集 fileKeys 候选文件（与扫描脚本同一实现，执行期重新快照以缩小 TOCTOU 窗口）
function Get-FileKeySnapshot {
  param($Rule)
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $exclDirs = @(); $exclFiles = @()
  foreach ($ex in @($Rule.excludeKeys)) {
    if (-not $ex -or -not $ex.path -or $ex.type -eq 'reg') { continue }
    $ep = (Expand-EnvPath ([string]$ex.path)).TrimEnd('\\')
    if ($ex.type -eq 'dir') { $exclDirs += $ep.ToLowerInvariant() }
    else { $exclFiles += $ep.ToLowerInvariant() }
  }
  $files = New-Object System.Collections.Generic.List[object]
  foreach ($fk in @($Rule.fileKeys)) {
    if (-not $fk -or -not $fk.path) { continue }
    $pattern = '*'; if ($fk.pattern) { $pattern = [string]$fk.pattern }
    $recurse = $true; if ($fk.recurse -eq $false) { $recurse = $false }
    foreach ($dir in (Resolve-GlobDirs ([string]$fk.path))) {
      $gciArgs = @{ LiteralPath = $dir; Filter = $pattern; File = $true; Force = $true; ErrorAction = 'SilentlyContinue' }
      if ($recurse) { $gciArgs.Recurse = $true; $gciArgs.Depth = 24 }
      foreach ($f in (Get-ChildItem @gciArgs)) {
        if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        $full = $f.FullName
        if (-not $seen.Add($full)) { continue }
        $low = $full.ToLowerInvariant()
        $skip = $false
        foreach ($d in $exclDirs) { if ($low.StartsWith($d + '\\')) { $skip = $true; break } }
        if (-not $skip) { foreach ($fe in $exclFiles) { if ($low -eq $fe) { $skip = $true; break } } }
        if ($skip) { continue }
        $files.Add([pscustomobject]@{ Path = $full; Size = [long]$f.Length })
      }
    }
  }
  # 注意：本机 pwsh 对非空 List[object] 做 @() 包裹会抛 ArgumentException（实测），
  # 必须用 ToArray() 转数组
  return $files.ToArray()
}

# v2.2 第1批（D5/D6）：规模统计统一出口，把「路径不存在 / 真的是 0 / 统计失败」三态分开。
# 旧 Get-PathSize 把所有异常 catch 成 0：ACL 拒绝、长路径失败都会被当成「0 字节可清理」，
# 删除侧也就无从校验释放量（D6 的虚报正建立在这个假象上）。
# 返回 pscustomobject：ok=能否统计；missing=路径不存在；size=字节；nfiles=文件数
#（nfiles 顺带给出，供删除后残留复查复用，避免再遍历一次）。
# 注意：本函数在 SCAN / EXECUTE 两个模板里必须保持逐字一致，test-features.js 有双源断言。
function Get-PathStats {
  param([string]$Path)
  if (-not $Path) { return [pscustomobject]@{ ok = $false; missing = $true; size = 0L; nfiles = 0L } }
  # 存在性用 .NET 判定（与下面的枚举探针同源，不混用两套 API）。实测：目录存在但无列举权限时
  # Test-Path 仍返回 True，所以「存在」与「可统计」是两态，后者只能靠枚举探针区分
  $isDir = [System.IO.Directory]::Exists($Path)
  if (-not $isDir) {
    if ([System.IO.File]::Exists($Path)) {
      try { return [pscustomobject]@{ ok = $true; missing = $false; size = [long]([System.IO.FileInfo]::new($Path).Length); nfiles = 1L } }
      catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L } }
    }
    return [pscustomobject]@{ ok = $true; missing = $true; size = 0L; nfiles = 0L }
  }
  # 根目录连一个子项都列不出来 = 无法统计，绝不能报 0（权限不足 / 重解析目标异常）
  # 注意必须在 MoveNext 处捕获：EnumerateFileSystemEntries 是惰性迭代器，
  # FindFirstFile 的 ACL 拒绝异常要到第一次 MoveNext 才抛出（调用本身不会失败）。
  try {
    $probe = [System.IO.Directory]::EnumerateFileSystemEntries($Path).GetEnumerator()
    try { $null = $probe.MoveNext() } finally { $probe.Dispose() }
  } catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L } }
  if ($useFastSize) {
    # TrimFastSize.SumCount：FindFirstFile 枚举直接带出 Length，跳 ReparsePoint、忽略无权限子项
    try {
      $sc = [TrimFastSize]::SumCount($Path, '*')
      return [pscustomobject]@{ ok = $true; missing = $false; size = [long]$sc[0]; nfiles = [long]$sc[1] }
    } catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L } }
  }
  try {
    $files = @(Get-ChildItem -LiteralPath $Path -File -Recurse -Depth 24 -Force -ErrorAction SilentlyContinue)
    $sum = ($files | Measure-Object -Property Length -Sum).Sum
    return [pscustomobject]@{ ok = $true; missing = $false; size = [long]($sum -as [long]); nfiles = [long]$files.Count }
  } catch { return [pscustomobject]@{ ok = $false; missing = $false; size = 0L; nfiles = 0L } }
}

# 兼容旧调用点：只要字节数（无法统计按 0 处理）
function Get-PathSize {
  param([string]$Path)
  return [long](Get-PathStats -Path $Path).size
}

# REMOVESELF 语义：自深至浅剪除空目录（含 fileKey 基目录本身）
function Prune-EmptyDirs {
  param([string]$Pattern)
  $n = 0
  foreach ($dir in (Resolve-GlobDirs $Pattern)) {
    # v2.2 第2批（D18）：剪枝虽然只删空目录，但基目录来自可被外部改写的规则 glob，
    # 与 Remove-PathSafely 同等对待——命中保护清单直接不碰（只删空目录的语义不变）。
    if (Test-PathProtected -Path $dir -Roots $tfProtectedRoots) { continue }
    $dirs = @(Get-ChildItem -LiteralPath $dir -Directory -Recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
      Sort-Object { $_.FullName.Length } -Descending)
    foreach ($d in $dirs) {
      if (@(Get-ChildItem -LiteralPath $d.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item -LiteralPath $d.FullName -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $d.FullName)) { $n++ }
      }
    }
    if (Test-Path -LiteralPath $dir -PathType Container) {
      if (@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $dir)) { $n++ }
      }
    }
  }
  return $n
}

# 注册表树删除（排除分支保护）：递归删除 $Path 子树，但整体保留 $Protected 命中的分支。
# 受保护内容未清空时键本身保留（Remove-Item 非递归对非空键失败），由调用方按结果计数。
function Remove-RegTreeExcept {
  param([string]$Path, [string[]]$Protected)
  $low = $Path.ToLowerInvariant().TrimEnd('\\')
  foreach ($p in $Protected) {
    $pl = $p.ToLowerInvariant().TrimEnd('\\')
    if ($low -eq $pl -or $low.StartsWith($pl + '\\')) { return 0 }
  }
  $count = 0
  $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
  if (-not $key) { return 0 }
  foreach ($v in @($key.GetValueNames())) {
    try { Remove-ItemProperty -LiteralPath $Path -Name $v -Force -ErrorAction Stop; $count++ } catch {}
  }
  foreach ($c in @(Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue)) {
    $count += (Remove-RegTreeExcept -Path ($Path.TrimEnd('\\') + '\\' + $c.PSChildName) -Protected $Protected)
  }
  Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
  if (-not (Test-Path -LiteralPath $Path)) { $count++ }
  return $count
}

# v2.2 第1批（D6/D14）：按「删除前后实测差值」出结论，替换旧的「按删除前全量 size 报功」。
# 旧实现的漏洞链：Remove-Item 静默失败 → 目录还在 → New-Item -Force 必然成功 → 返回 ok + 全额 freed，
# 用户看到「已清理并重建，释放 3.2 GB」而实际一字节没少（main.js 的日志也照抄这个虚报值）。
# 现在：freed = before.size - after.size（钳 ≥0：删除期间新写入的文件不冲抵已释放量）；
# after 仍有内容一律 partial，残留文件数顺带产出给上层，不再另起一次口径不一致的复查。
function Resolve-RemoveOutcome {
  param([string]$Path, $Before, [string]$OkMessage, [string]$PartialMessage)
  $note = ''
  if (-not $Before.ok) { $note = '（原目录规模无法统计，未计入释放量）' }
  $after = Get-PathStats -Path $Path
  if ($after.missing) {
    # 整目录已消失：删除前测到多少就是释放多少
    $gone = 0L
    if ($Before.ok) { $gone = [long]$Before.size }
    return @{ freed = $gone; status = 'ok'; message = ($OkMessage + $note); residual = 0 }
  }
  if (-not $after.ok) {
    # 删完连目录都列不出来：规模与残留都无从核实，宁可报 partial 也不假装清干净
    # 诊断行交给调用方输出：函数内直接 Write-TFDiag 会把诊断文本混进返回值（返回值变数组）
    return @{ freed = 0; status = 'partial'; message = ($PartialMessage + '，残留无法核实'); residual = 0; diag = ('删除后无法统计残留: ' + $Path); diagState = 'partial' }
  }
  $freed = 0L
  if ($Before.ok) {
    $freed = [long]$Before.size - [long]$after.size
    if ($freed -lt 0) { $freed = 0L }
  }
  if ($after.size -gt 0 -or $after.nfiles -gt 0) {
    return @{ freed = $freed; status = 'partial'; message = ($PartialMessage + $note); residual = [long]$after.nfiles }
  }
  return @{ freed = $freed; status = 'ok'; message = ($OkMessage + $note); residual = 0 }
}

function Remove-PathSafely {
  param([string]$Path, [bool]$Force, [string]$Risk, [string]$Mode = 'tree', [bool]$AutoRebuild = $true)
  # v2.2 第3批（D2）：contents = 只删目录内容、保留目录本身。旧实现整目录递归删后靠
  # 路径字符串猜测重建（Temp/Prefetch/Recent 三个硬编码），猜测漏掉就把目录删没了；
  # 改为逐子项删除后目录天然保留，无需重建；猜测逻辑保留在 tree 模式下兜底自定义规则。
  if (-not $Mode) { $Mode = 'tree' }
  # v2.2 第2批（D18）：入口硬拒，且必须放在这里而不是主循环——本函数是所有永久删除
  # 分支（Temp 重建 / 更新缓存停服务 / 通用递归删）的汇聚点，调用方还有一处 special
  # 之外的兜底路径，逐个调用点挂闸必然漏。命中即返回 error（不计 skipped，
  # 让上层统计把这条当成"没删成"而不是"正常跳过"）。
  # 注意：函数体内绝不能 Write-TFDiag（会污染返回值），诊断走 diag/diagState 交主循环输出。
  if (Test-PathProtected -Path $Path -Roots $tfProtectedRoots) {
    return @{ freed = 0; status = 'error'; message = '受保护路径，已拒绝'; residual = 0; diag = ('受保护路径拒绝删除: ' + $Path); diagState = 'skip' }
  }
  if (-not (Test-Path -LiteralPath $Path)) {
    return @{ freed = 0; status = 'skip'; message = '路径不存在'; residual = 0 }
  }
  # v2.2 第1批（D6）：门禁前置。旧实现先花几秒统计全量 size 再判高风险/进程占用，
  # skip 分支根本用不到规模，白算一轮（分析文档 D6 顺带点出的「先算后判」）。
  # v2.2 第4批（D10）：中风险并入强制删除门禁；$Risk 信任源来自 $rule.risk（调用方传 $item.risk，同源）
  if ($Risk -in @('high', 'medium') -and -not $Force) {
    return @{ freed = 0; status = 'skip'; message = '高/中风险项按默认策略跳过'; residual = 0 }
  }
  # 检查路径中是否有被保护的进程占用
  $procCheck = Get-Process | Where-Object { $_.Path -like ($Path + '*') } | Select-Object -First 1
  if ($procCheck -and $protectedProcesses -contains $procCheck.ProcessName) {
    return @{ freed = 0; status = 'skip'; message = '系统关键进程占用'; residual = 0 }
  }
  try {
    # 删除前基线（DLL 可用时走 TrimFastSize.SumCount，比 Get-ChildItem 快 5.3x）
    $before = Get-PathStats -Path $Path

    # v2.2 第3批（D2）：contents 语义（规则声明 deleteMode:"contents"，pathPs 目录型条目）。
    # 逐子项删除前对每个子项再过一次保护判定：父级放行不代表子项可删（纵深防御）。
    # 目标是文件时 contents 无意义，退化为整文件删除；Windows Update 下载目录的子项
    # 常被 wuauserv 占用，与 tree 分支同因先停服务，删除完成后恢复并校验。
    if ($Mode -eq 'contents') {
      if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        return Resolve-RemoveOutcome -Path $Path -Before $before -OkMessage '已清理' -PartialMessage '部分文件被占用'
      }
      $isWU = $Path -like '*SoftwareDistribution\\Download*'
      if ($isWU) {
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service -Name UsoSvc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
      }
      $childOk = 0; $childFail = 0
      foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
        if (Test-PathProtected -Path $child.FullName -Roots $tfProtectedRoots) { continue }
        try { Remove-Item -LiteralPath $child.FullName -Recurse -Force -ErrorAction Stop; $childOk++ } catch { $childFail++ }
      }
      if ($isWU) {
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        Start-Service -Name UsoSvc -ErrorAction SilentlyContinue
        $wuOk = ((Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status -eq 'Running')
        $usoOk = ((Get-Service -Name UsoSvc -ErrorAction SilentlyContinue).Status -eq 'Running')
      }
      $out = Resolve-RemoveOutcome -Path $Path -Before $before -OkMessage '已清空目录内容' -PartialMessage '部分子项被占用，已清空剩余内容'
      if ($isWU -and (-not $wuOk -or -not $usoOk)) {
        $out.status = 'partial'
        $out.message = $out.message + '；更新服务未全部恢复'
      } elseif ($childFail -gt 0 -and $out.status -eq 'ok') {
        # 删失败但实测无残留的罕见情形（如空目录竞态），仍按 D6 实测口径降级提示
        $out.status = 'partial'
        $out.message = $out.message + '（' + $childFail + ' 个子项未删除）'
      }
      return $out
    }

    # 高风险：临时文件目录清理后重建（参考 cmd 脚本）
    if ($Path -like '*\\Temp' -or $Path -like '*\\Prefetch' -or $Path -like '*\\Recent') {
      Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
      $rebuilt = $false
      if ($AutoRebuild) {
        # v2.2 第4批（D8）：重建时机由 autoRebuild 统一控制（关闭自动重建时清空目录、保留壳，不再硬重建）
        try { New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null; $rebuilt = $true } catch { return @{ freed = 0; status = 'error'; message = '目录重建失败: ' + $_.Exception.Message; residual = 0 } }
      }
      if ($rebuilt -and -not (Test-Path -LiteralPath $Path -PathType Container)) { return @{ freed = 0; status = 'error'; message = '目录重建未生效'; residual = 0 } }
      # 重建成功不代表删干净（目录没删掉时 New-Item -Force 同样「成功」），结论只能来自实测
      return Resolve-RemoveOutcome -Path $Path -Before $before -OkMessage ($(if ($rebuilt) { '已清理并重建' } else { '已清理' })) -PartialMessage '部分文件被占用，已清理并重建'
    }

    # Windows Update Download 需先停止服务
    if ($Path -like '*SoftwareDistribution\\Download*') {
      Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
      Stop-Service -Name UsoSvc -Force -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 1
      Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
      if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue }
      if ($AutoRebuild) {
        # v2.2 第4批（D8）：更新缓存目录的重建同受 autoRebuild 控制
        try { New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null } catch { return @{ freed = 0; status = 'error'; message = '更新缓存目录重建失败: ' + $_.Exception.Message; residual = 0 } }
      }
      Start-Service -Name wuauserv -ErrorAction SilentlyContinue
      Start-Service -Name UsoSvc -ErrorAction SilentlyContinue
      $wuOk = ((Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status -eq 'Running')
      $usoOk = ((Get-Service -Name UsoSvc -ErrorAction SilentlyContinue).Status -eq 'Running')
      $out = Resolve-RemoveOutcome -Path $Path -Before $before -OkMessage '已停止更新服务并清理' -PartialMessage '部分文件被占用'
      # v2.2 第1批（D6）：服务未恢复照样降级 partial，但 freed 仍取实测差值（旧实现此处直接冒领全额）
      if (-not $wuOk -or -not $usoOk) {
        $out.status = 'partial'
        $out.message = $out.message + '；更新服务未全部恢复'
      }
      return $out
    }

    # 普通清理
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    # v2.2 第1批（D6）：旧实现在这里两头都不准——有残留时报 freed=0（少报），
    # 无残留时报删除前 size（可能虚报）。统一走实测差值后两个偏差一起消除。
    return Resolve-RemoveOutcome -Path $Path -Before $before -OkMessage '已清理' -PartialMessage '部分文件被占用'
  } catch {
    return @{ freed = 0; status = 'error'; message = $_.Exception.Message; residual = 0; diag = ($Path + ' -> ' + $_.Exception.Message); diagState = 'rolled_back' }
  }
}

# M2/M3：restartProcesses 的「起」放在这里 —— 条目分支里大量 continue 会跳过循环末尾，
# 故在下一轮开头统一把上一轮停掉的进程拉回，循环结束后再由末尾兜底处理最后一条。
$pendingRestart = @()
foreach ($item in $items) {
  if ($pendingRestart.Count -gt 0) { Start-Restartables -Stopped $pendingRestart; $pendingRestart = @() }
  $rule = $ruleMap[$item.id]

  # DISM 组件清理：执行 StartComponentCleanup + ResetBase（不按路径删除）
  if ($item.id -eq 'dismComponentCleanup') {
    $dismOut = & dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
      $success++
      $details += @{ id = 'dismComponentCleanup'; name = $item.name; status = 'ok'; freed = 0; message = 'DISM 组件存储清理完成（/ResetBase 已执行，更新将不可卸载）' }
    } else {
      $failed++
      $tail = ($dismOut -split '\\r?\\n' | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' '
      Write-TFDiag -Stage 'execute.dism' -Mutation 'partial' -Detail ('dismComponentCleanup exit=' + $LASTEXITCODE + ' ' + $tail)
      $details += @{ id = 'dismComponentCleanup'; name = $item.name; status = 'error'; freed = 0; message = ('DISM 执行失败: ' + $tail) }
    }
    continue
  }

  # P1：requiredStoppedProcesses 执行侧复检 → 命中即整体跳过并写明原因（不静默半清）
  $blocked = @()
  if ($rule) { $blocked = @(Get-BlockedProcesses -Rule $rule) }
  if ($blocked.Count -gt 0) {
    $skipped++
    $details += @{ id = $item.id; name = $item.name; status = 'skip'; freed = 0; message = ('请先关闭后再清理: ' + ($blocked -join ', ')) }
    continue
  }

  # M2/M3：restartProcesses 条目的占用进程由脚本自己停，清完拉回 —— 不走上面的「命中即跳过」
  if ($rule -and @($rule.restartProcesses).Count -gt 0) {
    $pendingRestart = @($pendingRestart + @(Stop-Restartables -Rule $rule))
  }

  # ---- 文件模式条目（fileKeys）----
  if ($rule -and $rule.fileKeys -and @($rule.fileKeys).Count -gt 0) {
    # D10：中风险并入强制删除门禁，信任源统一为 $rule.risk（渲染层红色/黄色确认同源）
    if ([string]$rule.risk -in @('high', 'medium') -and -not $force) {
      $skipped++
      $details += @{ id = $item.id; name = $item.name; status = 'skip'; freed = 0; message = '高/中风险项按默认策略跳过' }
      continue
    }
    # v2.2 第3批（D13）：执行只消费扫描快照里的「可删文件清单」（items.files），不再现场
    # 重 glob——扫描后新出现的匹配文件不在清单里，就不会被误删（TOCTOU 根治）。
    # 空清单 = 扫描时全部被占用或本无可删，直接跳过（不与执行期状态纠缠）。
    $planFiles = @($item.files)
    if ($planFiles.Count -eq 0 -or $null -eq $planFiles[0]) {
      $skipped++
      $details += @{ id = $item.id; name = $item.name; status = 'skip'; freed = 0; message = '无可清理文件'; residual = 0 }
      continue
    }
    # v2.2 第2批（D18）：fileKeys 走 Remove-Item 内联删除，不经过 Remove-PathSafely，
    # 必须单独挂闸。口径：任一计划文件命中即整条拒绝（而非跳过命中的那个）——
    # 一是同一 id 拆两行 details 会打乱渲染层按 id 对齐的行协议，
    # 二是 fileKeys 的 glob 本来就是「一簇同类文件」，混出保护路径说明规则被篡改，整条更可信。
    # 内置规则实测 0 误伤，这里纯粹拦外部注入。
    $rej = 0
    foreach ($pf in $planFiles) { if (Test-PathProtected -Path ([string]$pf.path) -Roots $tfProtectedRoots) { $rej++ } }
    if ($rej -gt 0) {
      Write-TFDiag -Stage 'execute.protect' -Mutation 'skip' -Detail ($item.id + ' fileKeys 命中受保护路径 ' + $rej + ' 项，整体拒绝')
      $failed++
      $details += @{ id = $item.id; name = $item.name; status = 'error'; freed = 0; message = '受保护路径，已拒绝'; residual = 0 }
      continue
    }
    # 计划内文件按 path 去重（跨键 glob 重叠时同一文件只删一次、只计一次）
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $unique = New-Object 'System.Collections.Generic.List[object]'
    foreach ($pf in $planFiles) {
      $p = [string]$pf.path
      if ($p -and $seen.Add($p)) { $unique.Add($pf) }
    }
    if ($recycle) {
      # P3 回收站模式：PS 只枚举目标（@@RECYCLE@@ 行），移入回收站由主进程 shell.trashItem 执行。
      # 只发计划内仍存在的文件——扫描后已被移走的文件跳过，不会误报失败。
      $bytes = 0L; $cnt = 0
      foreach ($pf in $unique) {
        $p = [string]$pf.path
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $sz = [long]$pf.size
        $bytes += $sz
        $cnt++
        Write-Output ('@@RECYCLE@@' + (@{ id = $item.id; path = $p; size = $sz; isDir = $false } | ConvertTo-Json -Compress))
      }
      $details += @{ id = $item.id; name = $item.name; status = 'recycle'; freed = $bytes; message = '待移入回收站'; residual = 0; fileCount = $cnt }
      continue
    }
    $freed = 0L; $deleted = 0; $failedFiles = 0; $alreadyGone = 0
    foreach ($pf in $unique) {
      $p = [string]$pf.path
      if (-not (Test-Path -LiteralPath $p)) { $alreadyGone++; continue }   # 已不存在 = 已删，不算失败
      try {
        Remove-Item -LiteralPath $p -Force -ErrorAction Stop
        $freed += [long]$pf.size
        $deleted++
      } catch { $failedFiles++ }
    }
    $pruned = 0
    foreach ($fk in @($rule.fileKeys)) {
      if ($fk -and $fk.removeSelf) { $pruned += (Prune-EmptyDirs -Pattern ([string]$fk.path)) }
    }
    $totalFreed += $freed
    # P3 残留复查：删除后重新快照计数（0 = 清干净）；执行期被锁定的计划文件会计入残留，如实上报
    $residual = @(Get-FileKeySnapshot -Rule $rule).Count
    if ($failedFiles -eq 0) {
      $success++
      $msg = '已清理 ' + $deleted + ' 个文件'
      if ($alreadyGone -gt 0) { $msg = $msg + '，' + $alreadyGone + ' 个已不存在' }
      if ($pruned -gt 0) { $msg = $msg + '，剪除 ' + $pruned + ' 个空目录' }
      $details += @{ id = $item.id; name = $item.name; status = 'ok'; freed = $freed; message = $msg; residual = $residual }
    } elseif ($deleted -gt 0) {
      $failed++
      $details += @{ id = $item.id; name = $item.name; status = 'partial'; freed = $freed; message = '已清理 ' + $deleted + ' 个文件，' + $failedFiles + ' 个被占用'; residual = $residual }
    } else {
      $failed++
      $details += @{ id = $item.id; name = $item.name; status = 'error'; freed = 0; message = $failedFiles + ' 个文件全部被占用'; residual = $residual }
    }
    continue
  }

  # ---- 注册表条目（regKeys）----
  if ($rule -and $rule.regKeys -and @($rule.regKeys).Count -gt 0) {
    # D10：中风险并入强制删除门禁，信任源统一为 $rule.risk
    if ([string]$rule.risk -in @('high', 'medium') -and -not $force) {
      $skipped++
      $details += @{ id = $item.id; name = $item.name; status = 'skip'; freed = 0; message = '高/中风险项按默认策略跳过' }
      continue
    }
    $protected = @()
    foreach ($ex in @($rule.excludeKeys)) {
      if ($ex -and $ex.type -eq 'reg' -and $ex.path) {
        $cp = Convert-RegPath (Expand-EnvPath ([string]$ex.path))
        if ($cp) { $protected += $cp }
      }
    }
    # v2.2 第3批（D4）：删除前逐键 reg.exe export 备份，先全备份、后统一删除。
    # readme 第 162 行承诺「删除类操作执行前会自动备份」，此前清理链路并未兑现；
    # optimizer:backup-reg 是值级 JSON 存档，装不下整棵子树，只能走 reg.exe export。
    # 任一键备份失败即整条规则不删（fail-closed）：宁可少删，不可无备份地删。
    # 回收站模式下 regKeys 同样是直接删除（注册表不进回收站），故两种模式都要备份。
    # 备份目录与既有 startup-backup/fileclean-backup 同层同风格，命名带规则 id 便于回溯。
    $regBackupDir = Join-Path (Join-Path $env:APPDATA 'Trim') 'cleanup-reg-backup'
    New-Item -ItemType Directory -Path $regBackupDir -Force -ErrorAction SilentlyContinue | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupFiles = @()
    $backupFailed = $false
    $bkIdx = 0
    foreach ($rk in @($rule.regKeys)) {
      if (-not $rk -or -not $rk.path) { continue }
      $p = Convert-RegPath (Expand-EnvPath ([string]$rk.path))
      if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
      $bkIdx++
      $file = Join-Path $regBackupDir ($stamp + '_reg_' + $item.id + '_' + $bkIdx + '.reg')
      & reg.exe export (Convert-RegPathForExport $p) $file /y 2>&1 | Out-Null
      if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) {
        Write-TFDiag -Stage 'execute.regbackup' -Mutation 'skip' -Detail ($item.id + ' 注册表备份失败: ' + (Convert-RegPathForExport $p))
        $backupFailed = $true
        break
      }
      $backupFiles += $file
    }
    if ($backupFailed) {
      $failed++
      $details += @{ id = $item.id; name = $item.name; status = 'error'; freed = 0; message = '注册表备份失败，未执行删除'; residual = 0 }
      continue
    }
    $okCount = 0; $regFail = 0
    foreach ($rk in @($rule.regKeys)) {
      if (-not $rk -or -not $rk.path) { continue }
      $p = Convert-RegPath (Expand-EnvPath ([string]$rk.path))
      if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
      if ($rk.value) {
        if ([string]$rk.value -eq '*') {
          $key = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
          if ($key) {
            foreach ($v in @($key.GetValueNames())) {
              try { Remove-ItemProperty -LiteralPath $p -Name $v -Force -ErrorAction Stop; $okCount++ } catch { $regFail++ }
            }
          }
        } else {
          try { Remove-ItemProperty -LiteralPath $p -Name ([string]$rk.value) -Force -ErrorAction Stop; $okCount++ } catch { $regFail++ }
        }
      } elseif ($protected.Count -gt 0) {
        $okCount += (Remove-RegTreeExcept -Path $p -Protected $protected)
      } else {
        try { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop; $okCount++ } catch { $regFail++ }
      }
    }
    $bakNote = ''
    if ($backupFiles.Count -gt 0) { $bakNote = '；已备份 ' + $backupFiles.Count + ' 个 .reg 文件' }
    if ($regFail -eq 0) {
      $success++
      $msg = '注册表：已清理 ' + $okCount + ' 项' + $bakNote
      if ($recycle) { $msg = $msg + '（注册表不进回收站，已直接删除）' }
      $details += @{ id = $item.id; name = $item.name; status = 'ok'; freed = 0; message = $msg; residual = 0 }
    } elseif ($okCount -gt 0) {
      $failed++
      $details += @{ id = $item.id; name = $item.name; status = 'partial'; freed = 0; message = ('注册表：清理 ' + $okCount + ' 项，失败 ' + $regFail + ' 项' + $bakNote); residual = 0 }
    } else {
      $failed++
      $details += @{ id = $item.id; name = $item.name; status = 'error'; freed = 0; message = '注册表：清理失败（可能需要管理员权限）'; residual = 0 }
    }
    continue
  }

  # ---- 目录型条目（pathPs）----
  if ($recycle) {
    # P3 回收站模式：整目录交给主进程移入回收站（跳过 Temp 重建/停服务等删除期特殊分支）
    if (-not (Test-Path -LiteralPath $item.path)) {
      $skipped++
      $details += @{ id = $item.id; name = $item.name; status = 'skip'; freed = 0; message = '路径不存在'; residual = 0 }
      continue
    }
    # D10：中风险并入强制删除门禁，信任源统一为 $rule.risk（与渲染层分级确认同源）
    if ([string]$rule.risk -in @('high', 'medium') -and -not $force) {
      $skipped++
      $details += @{ id = $item.id; name = $item.name; status = 'skip'; freed = 0; message = '高/中风险项按默认策略跳过'; residual = 0 }
      continue
    }
    # v2.2 第2批（D18）：回收站模式不经过 Remove-PathSafely（由主进程 trashItem 落地），
    # 这里在算体积前硬拒，免得把受保护路径经 @@RECYCLE@@ 协议递给主进程。
    # 主进程 trashOrUnlink 侧还有一道同源判定，属纵深防御：脚本侧拦掉才不会污染统计与明细。
    if (Test-PathProtected -Path $item.path -Roots $tfProtectedRoots) {
      Write-TFDiag -Stage 'execute.protect' -Mutation 'skip' -Detail ($item.id + ' 目录命中受保护路径，拒绝清理')
      $failed++
      $details += @{ id = $item.id; name = $item.name; status = 'error'; freed = 0; message = '受保护路径，已拒绝'; residual = 0 }
      continue
    }
    $rsize = Get-PathSize -Path $item.path
    Write-Output ('@@RECYCLE@@' + (@{ id = $item.id; path = $item.path; size = $rsize; isDir = $true } | ConvertTo-Json -Compress))
    $details += @{ id = $item.id; name = $item.name; status = 'recycle'; freed = $rsize; message = '待移入回收站'; residual = 0 }
    continue
  }
  # v2.2 第3批（D2）：规则声明的 deleteMode 传入（contents = 只删内容保留目录；未声明/自定义规则走 tree）；
  # v2.2 第4批（D8）：autoRebuild 一并传入，删后是否重建统一由该开关决定
  $result = Remove-PathSafely -Path $item.path -Force $force -Risk $item.risk -Mode ([string]$rule.deleteMode) -AutoRebuild $autoRebuild
  # 诊断行必须在循环体内输出（函数内 Write-TFDiag 会污染函数返回值）
  if ($result.diag) { Write-TFDiag -Stage 'execute.remove' -Mutation ([string]$result.diagState) -Detail ([string]$result.diag) }
  $totalFreed += $result.freed
  # v2.2 第1批（D14）：残留计数直接取 Remove-PathSafely 的删除后实测结果。
  # 旧实现另起一次 Get-ChildItem -Depth 6 复查：一是第三次遍历目录（成本翻倍），
  # 二是深度口径与统计侧（-Depth 24 / TrimFastSize 不限深）不一致，
  # 三是 'ok' 分支永远复查到刚重建的空目录 → 恒为 0，掩盖真实残留。
  $residual = [long]$result.residual
  switch ($result.status) {
    'ok' { $success++ }
    'skip' { $skipped++ }
    'error' { $failed++ }
    'partial' { $failed++ }
  }
  $details += @{
    id = $item.id
    name = $item.name
    status = $result.status
    freed = $result.freed
    message = $result.message
    residual = $residual
  }
}

# M2/M3：循环结束兜底 —— 最后一条 restartProcesses 条目停掉的进程在这里拉回
if ($pendingRestart.Count -gt 0) { Start-Restartables -Stopped $pendingRestart; $pendingRestart = @() }

@{
  totalFreed = $totalFreed
  success = $success
  failed = $failed
  skipped = $skipped
  details = $details
} | ConvertTo-Json -Compress -Depth 6
`;

// ==================== 条目明细脚本（P3 明细预览，只读枚举） ====================
// 输出协议：@@DETAIL@@ 元信息行（kind/total/truncated）+ @@ITEMFILE@@ 文件行（上限 600）。
// fileKeys 条目走规则快照；目录型优先用渲染层传入的「扫描时已解析路径」；注册表/DISM 仅返回元信息。
const DETAIL_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
${DIAG.PS_PREAMBLE}

$rulesJson = '\${DETAIL_RULES_JSON_PLACEHOLDER}'
$id = '\${DETAIL_ID_PLACEHOLDER}'
$targetPath = '\${DETAIL_PATH_PLACEHOLDER}'
$rules = ConvertFrom-Json -InputObject $rulesJson

$ruleMap = @{}
foreach ($g in $rules.groups) {
  if ($g.subGroups) { foreach ($sg in $g.subGroups) { foreach ($it in $sg.items) { $ruleMap[$it.id] = $it } } }
  elseif ($g.items) { foreach ($it in $g.items) { $ruleMap[$it.id] = $it } }
}

${RULE_PATH_EVAL_PS}
function Expand-EnvPath {
  param([string]$Path)
  return [regex]::Replace($Path, '%([^%]+)%', {
    param($m)
    $v = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
    if ($v) { $v } else { $m.Value }
  })
}

function Resolve-GlobDirs {
  param([string]$Pattern)
  $expanded = Expand-EnvPath $Pattern
  if (-not $expanded.Contains('*')) {
    if (Test-Path -LiteralPath $expanded -PathType Container) { return @($expanded) }
    return @()
  }
  $segments = @($expanded -split '[\\\\/]' | Where-Object { $_ })
  if ($segments.Count -eq 0) { return @() }
  $roots = @()
  $start = 0
  if ($segments[0].EndsWith(':')) { $roots = @($segments[0] + '\\'); $start = 1 }
  else { $roots = @('\\') }
  for ($i = $start; $i -lt $segments.Count; $i++) {
    $seg = $segments[$i]
    $next = New-Object System.Collections.Generic.List[string]
    foreach ($r in $roots) {
      if ($seg.Contains('*') -or $seg.Contains('?')) {
        foreach ($c in (Get-ChildItem -Path (Join-Path $r $seg) -Directory -Force -ErrorAction SilentlyContinue)) {
          if (-not ($c.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $next.Add($c.FullName) }
        }
      } else {
        $p = Join-Path $r $seg
        if (Test-Path -LiteralPath $p -PathType Container) { $next.Add($p) }
      }
    }
    $roots = @($next | Select-Object -Unique)
    if ($roots.Count -eq 0) { return @() }
  }
  return $roots
}

function Convert-RegPath {
  param([string]$RegPath)
  $idx = $RegPath.IndexOf('\\')
  if ($idx -lt 0) { return $null }
  $hive = $RegPath.Substring(0, $idx).ToUpperInvariant()
  $rest = $RegPath.Substring($idx + 1)
  $map = @{ HKCU = 'HKEY_CURRENT_USER'; HKLM = 'HKEY_LOCAL_MACHINE'; HKCR = 'HKEY_CLASSES_ROOT'; HKU = 'HKEY_USERS'; HKCC = 'HKEY_CURRENT_CONFIG' }
  if (-not $map.ContainsKey($hive)) { return $null }
  return ('Registry::' + $map[$hive] + '\\' + $rest)
}

function Get-FileKeySnapshot {
  param($Rule)
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $exclDirs = @(); $exclFiles = @()
  foreach ($ex in @($Rule.excludeKeys)) {
    if (-not $ex -or -not $ex.path -or $ex.type -eq 'reg') { continue }
    $ep = (Expand-EnvPath ([string]$ex.path)).TrimEnd('\\')
    if ($ex.type -eq 'dir') { $exclDirs += $ep.ToLowerInvariant() }
    else { $exclFiles += $ep.ToLowerInvariant() }
  }
  $files = New-Object System.Collections.Generic.List[object]
  foreach ($fk in @($Rule.fileKeys)) {
    if (-not $fk -or -not $fk.path) { continue }
    $pattern = '*'; if ($fk.pattern) { $pattern = [string]$fk.pattern }
    $recurse = $true; if ($fk.recurse -eq $false) { $recurse = $false }
    foreach ($dir in (Resolve-GlobDirs ([string]$fk.path))) {
      $gciArgs = @{ LiteralPath = $dir; Filter = $pattern; File = $true; Force = $true; ErrorAction = 'SilentlyContinue' }
      if ($recurse) { $gciArgs.Recurse = $true; $gciArgs.Depth = 24 }
      foreach ($f in (Get-ChildItem @gciArgs)) {
        if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        $full = $f.FullName
        if (-not $seen.Add($full)) { continue }
        $low = $full.ToLowerInvariant()
        $skip = $false
        foreach ($d in $exclDirs) { if ($low.StartsWith($d + '\\')) { $skip = $true; break } }
        if (-not $skip) { foreach ($fe in $exclFiles) { if ($low -eq $fe) { $skip = $true; break } } }
        if ($skip) { continue }
        $files.Add([pscustomobject]@{ Path = $full; Size = [long]$f.Length })
      }
    }
  }
  return $files.ToArray()
}

$rule = $ruleMap[$id]
if (-not $rule) {
  Write-Output ('@@DETAIL@@' + (@{ kind = 'none'; total = 0; truncated = $false } | ConvertTo-Json -Compress))
  exit
}
if ($rule.special -eq 'dism') {
  Write-Output ('@@DETAIL@@' + (@{ kind = 'dism'; total = 0; truncated = $false } | ConvertTo-Json -Compress))
  exit
}
if ($rule.regKeys -and @($rule.regKeys).Count -gt 0) {
  $count = 0
  foreach ($rk in @($rule.regKeys)) {
    if (-not $rk -or -not $rk.path) { continue }
    $p = Convert-RegPath (Expand-EnvPath ([string]$rk.path))
    if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
    $count++
    if ($rk.value) { continue }
    $key = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
    if ($key) {
      $count += @($key.GetValueNames()).Count
      $count += @(Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue).Count
    }
  }
  Write-Output ('@@DETAIL@@' + (@{ kind = 'reg'; total = $count; truncated = $false } | ConvertTo-Json -Compress))
  exit
}

$cap = 600
$total = 0
$emitted = 0
if ($rule.fileKeys -and @($rule.fileKeys).Count -gt 0) {
  $snap = @(Get-FileKeySnapshot -Rule $rule)
  foreach ($f in $snap) {
    $total++
    if ($emitted -lt $cap) {
      $emitted++
      Write-Output ('@@ITEMFILE@@' + (@{ path = $f.Path; size = $f.Size } | ConvertTo-Json -Compress))
    }
  }
  Write-Output ('@@DETAIL@@' + (@{ kind = 'files'; total = $total; truncated = ($total -gt $cap) } | ConvertTo-Json -Compress))
  exit
}

# 目录型：优先用扫描时已解析的路径（渲染层传入），否则回退求值 pathPs
# v2.2 第2批（D1）：回退求值同样走受限求值器；失败即视为「无路径可预览」，
# 绝不把表达式原文交给 Test-Path / Get-ChildItem。
$p = $targetPath
if (-not $p) {
  $rp = Resolve-RulePath -Expr ([string]$rule.pathPs)
  if ($rp.ok) { $p = [string]$rp.path } else { $p = '' }
}
if (-not $p -or -not (Test-Path -LiteralPath $p)) {
  Write-Output ('@@DETAIL@@' + (@{ kind = 'files'; total = 0; truncated = $false } | ConvertTo-Json -Compress))
  exit
}
foreach ($f in (Get-ChildItem -LiteralPath $p -File -Recurse -Depth 24 -Force -ErrorAction SilentlyContinue)) {
  if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
  $total++
  if ($emitted -lt $cap) {
    $emitted++
    Write-Output ('@@ITEMFILE@@' + (@{ path = $f.FullName; size = [long]$f.Length } | ConvertTo-Json -Compress))
  }
}
Write-Output ('@@DETAIL@@' + (@{ kind = 'files'; total = $total; truncated = ($total -gt $cap) } | ConvertTo-Json -Compress))
`;

module.exports = {
  // 规则注入（扫描 Rust 化 P3）：rulesOverride 供 test-features 双引擎对拍断言传入合成规则，
  // 生产链路不传参走 loadRules()（内置 + 数据目录验签合并），注入面不新增信任假设
  scan(categories, configuredPaths = {}, rulesOverride = null) {
    const catsJson = psEscapeSingle(JSON.stringify(categories || []));
    const pathsJson = psEscapeSingle(JSON.stringify(configuredPaths || {}));
    const rulesJson = psEscapeSingle(JSON.stringify(rulesOverride || loadRules()));
    return SCAN_SCRIPT
      .replace('\u0024{CATEGORIES_PLACEHOLDER}', () => catsJson)
      .replace('\u0024{CONFIGURED_PATHS_PLACEHOLDER}', () => pathsJson)
      .replace('\u0024{RULES_JSON_PLACEHOLDER}', () => rulesJson)
      .replace('\u0024{FASTSIZE_DLL_PLACEHOLDER}', () => psEscapeSingle(FASTSIZE_DLL || ''));
  },
  execute(items, force, toRecycle = false, autoRebuild = false) {
    const itemsJson = psEscapeSingle(JSON.stringify(items || []));
    const rulesJson = psEscapeSingle(JSON.stringify(loadRules()));
    // v2.2 第2批（D18）：清单由主进程侧 configureProtectedRoots 补全（Electron known folder
    // 只有主进程拿得到），此处经 require 缓存取同一份，保证 JS/PS 两侧口径同源。
    const protectedJson = psEscapeSingle(PROTECT.protectedRootsJson());
    return EXECUTE_SCRIPT
      .replace('\u0024{FORCE_PLACEHOLDER}', () => (force ? '$true' : '$false'))
      .replace('\u0024{RECYCLE_PLACEHOLDER}', () => (toRecycle ? '$true' : '$false'))
      .replace('\u0024{AUTO_REBUILD_PLACEHOLDER}', () => (autoRebuild ? '$true' : '$false'))
      .replace('\u0024{ITEMS_PLACEHOLDER}', () => itemsJson)
      .replace('\u0024{RULES_JSON_PLACEHOLDER}', () => rulesJson)
      .replace('\u0024{PROTECTED_JSON_PLACEHOLDER}', () => protectedJson)
      .replace('\u0024{FASTSIZE_DLL_PLACEHOLDER}', () => psEscapeSingle(FASTSIZE_DLL || ''));
  },
  // 供渲染层通过 IPC 读取的清理规则原始数据（P1-9 数据化：唯一数据源）
  setFastSizeDll,
  rules() {
    return loadRules();
  },
  // 在线更新（P2）：数据目录规则所在目录（主进程写入目标）
  dataRulesDir() {
    return DATA_RULES_DIR;
  },
  // 火眼眼审查 2026-09-14（MED）：防回滚水位线（主进程更新落盘成功后抬升）
  getRulesWatermark,
  setRulesWatermark,
  // 条目明细（P3）：枚举单个条目将删除的文件清单（只读）；resolvedPath 为扫描时已解析的目录
  detail(id, resolvedPath = '') {
    const rulesJson = psEscapeSingle(JSON.stringify(loadRules()));
    return DETAIL_SCRIPT
      .replace('\u0024{DETAIL_ID_PLACEHOLDER}', () => psEscapeSingle(String(id || '')))
      .replace('\u0024{DETAIL_PATH_PLACEHOLDER}', () => psEscapeSingle(String(resolvedPath || '')))
      .replace('\u0024{DETAIL_RULES_JSON_PLACEHOLDER}', () => rulesJson);
  }
};
