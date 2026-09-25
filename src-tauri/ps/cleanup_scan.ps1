# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/cleanup-scripts.js → 常量 SCAN_SCRIPT（模板模式：占位符保留，运行前由 Rust 同口径替换）
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：磁盘清理扫描（模板：CATEGORIES / CONFIGURED_PATHS / RULES_JSON / FASTSIZE_DLL 占位符）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# v2.2 第1批（D5）：全局 SilentlyContinue 有意保留——扫描要遍历成百上千个 ACL 受限目录，
# 逐条非终止错误若抛出会淹没 stdout 并把退出码变成非 0（主进程按整体失败处理）。
# 但它会吞掉「真失败」，故本轮补两条腿：① 致命错误（规则/入参解析失败）显式写 stderr + 非 0 退出；
# ② 规模统计改走 Get-PathStats 三态出口，统计失败不再伪装成 0 字节。
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

$rulesJson = '${RULES_JSON_PLACEHOLDER}'
# 超长 JSON 用 -InputObject 解析（管道长字符串在本机 pwsh 有解析异常风险）
$rules = ConvertFrom-Json -InputObject $rulesJson
$categories = ('${CATEGORIES_PLACEHOLDER}' | ConvertFrom-Json)
$configuredPaths = ('${CONFIGURED_PATHS_PLACEHOLDER}' | ConvertFrom-Json)

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


$RULE_PATH_MAX_DEPTH = 32
function Resolve-RulePrim {
  param($St)
  # 审查 L-7（2026-09-14）：嵌套括号深度上限，防止恶意/异常规则表达式让 PowerShell 栈递归爆掉。
  $St.depth = [int]$St.depth + 1
  if ($St.depth -gt $RULE_PATH_MAX_DEPTH) { $St.ok = $false; return }
  $ws = ' ' + [char]9
  while ($St.i -lt $St.s.Length -and $ws.Contains($St.s[$St.i])) { $St.i = $St.i + 1 }
  if ($St.i -ge $St.s.Length) { $St.ok = $false; return }
  $c = $St.s[$St.i]
  if ($c -eq '(') {
    $St.i = $St.i + 1
    Resolve-RuleConcat $St
    if (-not $St.ok) { return }
    while ($St.i -lt $St.s.Length -and $ws.Contains($St.s[$St.i])) { $St.i = $St.i + 1 }
    if ($St.i -ge $St.s.Length -or $St.s[$St.i] -ne ')') { $St.ok = $false; return }
    $St.i = $St.i + 1
    return
  }
  if ($c -eq "'") {
    $St.i = $St.i + 1
    $sb = New-Object System.Text.StringBuilder
    while ($true) {
      if ($St.i -ge $St.s.Length) { $St.ok = $false; return }
      $ch = $St.s[$St.i]
      if ($ch -eq "'") {
        if ($St.i + 1 -lt $St.s.Length -and $St.s[$St.i + 1] -eq "'") { [void]$sb.Append("'"); $St.i = $St.i + 2; continue }
        $St.i = $St.i + 1
        break
      }
      [void]$sb.Append($ch)
      $St.i = $St.i + 1
    }
    $St.val = $sb.ToString()
    return
  }
  if ($c -eq '$') {
    $rest = $St.s.Substring($St.i)
    if (-not $rest.StartsWith('$env:')) { $St.ok = $false; return }
    $St.i = $St.i + 5
    $start = $St.i
    while ($St.i -lt $St.s.Length -and $St.s[$St.i] -match '[A-Za-z0-9_]') { $St.i = $St.i + 1 }
    if ($St.i -eq $start) { $St.ok = $false; return }
    $name = $St.s.Substring($start, $St.i - $start)
    $v = [Environment]::GetEnvironmentVariable($name)
    if ($null -eq $v) { $v = '' }
    $St.val = [string]$v
    return
  }
  $St.ok = $false
}

function Resolve-RuleConcat {
  param($St)
  Resolve-RulePrim $St
  if (-not $St.ok) { return }
  $acc = [string]$St.val
  $ws = ' ' + [char]9
  while ($true) {
    $j = $St.i
    while ($j -lt $St.s.Length -and $ws.Contains($St.s[$j])) { $j = $j + 1 }
    if ($j -lt $St.s.Length -and $St.s[$j] -eq '+') {
      $St.i = $j + 1
      Resolve-RulePrim $St
      if (-not $St.ok) { return }
      $acc = $acc + [string]$St.val
    } else { break }
  }
  $St.val = $acc
}

# 返回 [pscustomobject]{ok, path}：ok=$false 表示表达式不符合受限语法（调用方须 fail-closed）。
# 注意：函数体内禁止 Write-Output / Write-TFDiag —— 任何意外管道输出都会污染返回值（既有陷阱）。
function Resolve-RulePath {
  param([string]$Expr)
  if ([string]::IsNullOrEmpty($Expr)) { return [pscustomobject]@{ ok = $false; path = '' } }
  $s = [string]$Expr
  $st = @{ s = $s; i = 0; ok = $true; val = ''; depth = 0 }
  Resolve-RuleConcat $st
  if (-not $st.ok) { return [pscustomobject]@{ ok = $false; path = '' } }
  $k = [int]$st.i
  $ws = ' ' + [char]9
  while ($k -lt $s.Length -and $ws.Contains($s[$k])) { $k = $k + 1 }
  if ($k -ne $s.Length) { return [pscustomobject]@{ ok = $false; path = '' } }
  return [pscustomobject]@{ ok = $true; path = [string]$st.val }
}

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

# 注册表路径映射：HKCU\... → Registry::HKEY_CURRENT_USER\...（不依赖 PSDrive 挂载）
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
      configuredPath = 'C:\Windows\WinSxS'
      path = 'C:\Windows\WinSxS'
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
  # （如 $env:TEMP + '\x'）直接进入路径列；受限求值失败一律 fail-closed 跳过该条。
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
  # [D19 修复·2026-09-25] 键名已修正为 candidatesPs / globCandidatesPs，
  # 与规则 JSON 实际键一致。修复后 neteaseMusicCache/qqCache/douyinCache 会启用
  # 内置候选路径回退，wechatCache 通配候选生效（属删除面行为变更，经审计 P2-08 授权修复）。
  # Invoke-Expression 已在此前安全收口时移除，不重新引入任意代码执行面。
  if ($rule.candidatesPs) {
    foreach ($cExpr in @($rule.candidatesPs)) {
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
  if ($rule.globCandidatesPs) {
    foreach ($gExpr in @($rule.globCandidatesPs)) {
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
