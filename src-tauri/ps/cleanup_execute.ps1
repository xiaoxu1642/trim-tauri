# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/cleanup-scripts.js → 常量 EXECUTE_SCRIPT（模板模式：占位符保留，运行前由 Rust 同口径替换）
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：磁盘清理执行（模板：ITEMS / FORCE / RECYCLE / AUTO_REBUILD / RULES_JSON / PROTECTED_JSON / FASTSIZE_DLL 占位符）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# v2.2 第1批（D5）：全局 SilentlyContinue 保留（删除期被占用文件逐条抛错会淹没结果协议输出），
# 但删除动作不再依赖「没报错 = 删干净」：Remove-PathSafely 统一按删除前后实测差值出结论，
# 有残留即 partial；同时规则/入参解析失败改为显式 stderr + 非 0 退出。
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ---- Trim 诊断四元组 (P1-11) ----
function Write-TFDiag {
  param([string]$Stage, [string]$Mutation, [string]$Detail)
  try {
    $native = 0
    try { $native = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } catch { }
    if ($native -eq 0 -and $null -ne $LASTEXITCODE) { $native = $LASTEXITCODE }
    $key = $Stage + '|' + $Mutation + '|' + $Detail
    $digest = '{0:X8}' -f [Math]::Abs($key.GetHashCode())
    $o = [ordered]@{
      failure_stage = $Stage
      mutation_state = $Mutation
      diagnostic_digest = $digest
      native_error_code = [int64]$native
      detail = [string]$Detail
    }
    Write-Output ('@@DIAG@@' + ($o | ConvertTo-Json -Compress))
  } catch { }
}
trap {
  Write-TFDiag -Stage 'script' -Mutation 'unknown' -Detail $_.Exception.Message
  continue
}


# 扫描加速（v2.1）：TrimFastSize.dll 走 FindFirstFile 枚举直接带出 Length（5.3x）。
# 主进程注入绝对路径；DLL 缺失或加载失败时 $useFastSize=false，函数自动降级回原实现。
$__fastDll = '${FASTSIZE_DLL_PLACEHOLDER}'
$useFastSize = $false
if ($__fastDll -and (Test-Path -LiteralPath $__fastDll)) {
  try { Add-Type -Path $__fastDll; $useFastSize = $true } catch { $useFastSize = $false }
}

$itemsJson = '${ITEMS_PLACEHOLDER}'
$force = ${FORCE_PLACEHOLDER}
$recycle = ${RECYCLE_PLACEHOLDER}
$autoRebuild = ${AUTO_REBUILD_PLACEHOLDER}
$items = $itemsJson | ConvertFrom-Json
$rulesJson = '${RULES_JSON_PLACEHOLDER}'
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
  # 运行时环境喂进来的合法短名（本机 TEMP=C:UsersADMINI~1...，tempFiles 规则
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

$tfProtectedRoots = ConvertFrom-Json -InputObject '${PROTECTED_JSON_PLACEHOLDER}'
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
  $segments = @($expanded -split '[\\/]' | Where-Object { $_ })
  if ($segments.Count -eq 0) { return @() }
  $roots = @()
  $start = 0
  if ($segments[0].EndsWith(':')) { $roots = @($segments[0] + '\'); $start = 1 }
  else { $roots = @('\') }
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
  $idx = $RegPath.IndexOf('\')
  if ($idx -lt 0) { return $null }
  $hive = $RegPath.Substring(0, $idx).ToUpperInvariant()
  $rest = $RegPath.Substring($idx + 1)
  $map = @{ HKCU = 'HKEY_CURRENT_USER'; HKLM = 'HKEY_LOCAL_MACHINE'; HKCR = 'HKEY_CLASSES_ROOT'; HKU = 'HKEY_USERS'; HKCC = 'HKEY_CURRENT_CONFIG' }
  if (-not $map.ContainsKey($hive)) { return $null }
  return ('Registry::' + $map[$hive] + '\' + $rest)
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
    $ep = (Expand-EnvPath ([string]$ex.path)).TrimEnd('\')
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
        foreach ($d in $exclDirs) { if ($low.StartsWith($d + '\')) { $skip = $true; break } }
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
  $low = $Path.ToLowerInvariant().TrimEnd('\')
  foreach ($p in $Protected) {
    $pl = $p.ToLowerInvariant().TrimEnd('\')
    if ($low -eq $pl -or $low.StartsWith($pl + '\')) { return 0 }
  }
  $count = 0
  $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
  if (-not $key) { return 0 }
  foreach ($v in @($key.GetValueNames())) {
    try { Remove-ItemProperty -LiteralPath $Path -Name $v -Force -ErrorAction Stop; $count++ } catch {}
  }
  foreach ($c in @(Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue)) {
    $count += (Remove-RegTreeExcept -Path ($Path.TrimEnd('\') + '\' + $c.PSChildName) -Protected $Protected)
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
      $isWU = $Path -like '*SoftwareDistribution\Download*'
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
    if ($Path -like '*\Temp' -or $Path -like '*\Prefetch' -or $Path -like '*\Recent') {
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
    if ($Path -like '*SoftwareDistribution\Download*') {
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
      $tail = ($dismOut -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' '
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
