# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/cleanup-scripts.js → 常量 DETAIL_SCRIPT（模板模式：占位符保留，运行前由 Rust 同口径替换）
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：条目明细枚举（模板：DETAIL_ID / DETAIL_PATH / DETAIL_RULES_JSON 占位符）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
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


$rulesJson = '${DETAIL_RULES_JSON_PLACEHOLDER}'
$id = '${DETAIL_ID_PLACEHOLDER}'
$targetPath = '${DETAIL_PATH_PLACEHOLDER}'
$rules = ConvertFrom-Json -InputObject $rulesJson

$ruleMap = @{}
foreach ($g in $rules.groups) {
  if ($g.subGroups) { foreach ($sg in $g.subGroups) { foreach ($it in $sg.items) { $ruleMap[$it.id] = $it } } }
  elseif ($g.items) { foreach ($it in $g.items) { $ruleMap[$it.id] = $it } }
}


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
