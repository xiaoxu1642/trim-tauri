# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/startup-scripts.js → scan()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：启动项扫描（只读）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$backupDir = Join-Path $env:APPDATA 'Trim\startup-backup'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$disabledFile = Join-Path $backupDir 'disabled.json'

$results = @()

# ---- v3.7.0 议题二 P1：StartupApproved 判定（与任务管理器同轨） ----
# 背景：任务管理器禁用启动项时并不删除 Run 值，只往 StartupApproved 写 12 字节 blob
# （4 字节状态 + 8 字节 FILETIME）。此前 Trim 把注册表/文件夹项的 enabled 硬编码为 $true，
# 且全仓从未读过 StartupApproved → 结构上不可能显示「被任务管理器禁用的启动项」。
# 语义（2026-09-23 本机受控写读往返已验证 + 5 个真实样本交叉验证）：
#   首字节 bit0 = 1 → 禁用（0x01 / 0x03）；bit0 = 0 → 启用（0x02 / 0x06）
#   无对应 blob → 回落为「启用」（Windows 语义：无记录即默认放行）
$approvedBase = @{
  HKCU = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
  HKLM = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
}
# tag -> @{ 值名(小写) = 是否禁用 }
$approvedMap = @{}
foreach ($hv in @('HKCU', 'HKLM')) {
  foreach ($sub in @('Run', 'StartupFolder')) {
    $p = 'Registry::' + $approvedBase[$hv] + '\' + $sub
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $k = Get-Item -LiteralPath $p
    foreach ($n in $k.GetValueNames()) {
      if ([string]::IsNullOrWhiteSpace($n)) { continue }
      $b = $k.GetValue($n)
      $disabled = $false
      if ($b -and @($b).Count -ge 1) { $disabled = (([byte[]]$b)[0] -band 1) -eq 1 }
      $approvedMap[$hv + '|' + $sub + '|' + $n.ToLower()] = $disabled
    }
  }
}
function Get-ApprovedDisabled([string]$tag, [string]$valueName) {
  if ([string]::IsNullOrWhiteSpace($valueName)) { return $null }
  $k = $tag + '|' + $valueName.ToLower()
  if ($approvedMap.ContainsKey($k)) { return [bool]$approvedMap[$k] }
  return $null   # 无记录：调用方按「启用」回落
}

# ---- 辅助：从命令行提取可执行路径（支持引号包裹与参数）----
function Get-CmdPath([string]$cmd) {
  if ([string]::IsNullOrWhiteSpace($cmd)) { return '' }
  $c = $cmd.Trim()
  if ($c.StartsWith('"')) {
    $idx = $c.IndexOf('"', 1)
    if ($idx -gt 0) { return $c.Substring(1, $idx - 1) }
  }
  $sp = $c.IndexOf(' ')
  if ($sp -gt 0) { return $c.Substring(0, $sp) }
  return $c
}
# ---- 辅助：取文件发布者（CompanyName）----
function Get-Publisher([string]$path) {
  if ([string]::IsNullOrWhiteSpace($path)) { return '' }
  try {
    $vi = (Get-Item -LiteralPath $path -ErrorAction SilentlyContinue).VersionInfo
    if ($vi -and -not [string]::IsNullOrWhiteSpace([string]$vi.CompanyName)) { return [string]$vi.CompanyName }
  } catch {}
  return ''
}
# ---- 辅助：解析 .lnk 快捷方式目标路径 ----
$script:wshShell = $null
function Resolve-Lnk([string]$lnkPath) {
  if ([string]::IsNullOrWhiteSpace($lnkPath)) { return '' }
  try {
    if (-not $script:wshShell) { $script:wshShell = New-Object -ComObject WScript.Shell }
    $sc = $script:wshShell.CreateShortcut($lnkPath)
    if ($sc -and -not [string]::IsNullOrWhiteSpace([string]$sc.TargetPath)) { return [string]$sc.TargetPath }
  } catch {}
  return ''
}

# ---------- 注册表 Run / RunOnce（含 32/64 位视图） ----------
$runPaths = @(
  @{ hive = 'HKCU'; path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'; label = '注册表 · 当前用户\Run' },
  @{ hive = 'HKCU'; path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'; label = '注册表 · 当前用户\RunOnce' },
  @{ hive = 'HKCU32'; path = 'HKEY_CURRENT_USER\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; label = '注册表 · 当前用户(32位)\Run' },
  @{ hive = 'HKCU32'; path = 'HKEY_CURRENT_USER\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; label = '注册表 · 当前用户(32位)\RunOnce' },
  @{ hive = 'HKLM'; path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; label = '注册表 · 所有用户\Run' },
  @{ hive = 'HKLM'; path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; label = '注册表 · 所有用户\RunOnce' },
  @{ hive = 'HKLM32'; path = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; label = '注册表 · 所有用户(32位)\Run' },
  @{ hive = 'HKLM32'; path = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; label = '注册表 · 所有用户(32位)\RunOnce' }
)

foreach ($rp in $runPaths) {
  $regKey = 'Registry::' + $rp.path
  if (-not (Test-Path -LiteralPath $regKey)) { continue }
  $key = Get-Item -LiteralPath $regKey
  foreach ($vp in $key.GetValueNames()) {
    if ([string]::IsNullOrWhiteSpace($vp)) { continue }
    $kind = $key.GetValueKind($vp)
    $data = $key.GetValue($vp)
    if ($kind -eq 'String' -and [string]::IsNullOrWhiteSpace([string]$data)) { continue }
    $id = 'reg|' + $rp.path + '|' + $vp
    $vData = ''
    $vDataB64 = ''
    $vDataArr = @()
    if ($kind -eq 'Binary') { $vDataB64 = [Convert]::ToBase64String([byte[]]$data) }
    elseif ($kind -eq 'MultiString') { $vDataArr = @([string[]]$data) }
    else { $vData = [string]$data }
    $cmdPath = ''
    if ($kind -eq 'String' -or $kind -eq 'ExpandString') {
      $cmdPath = Get-CmdPath ([Environment]::ExpandEnvironmentVariables([string]$data))
    }
    # v3.7.0：Registry 项的启用状态按 StartupApproved blob 判定，不再硬编码 $true。
    # 32 位视图（WOW6432Node）没有独立的 StartupApproved，按 hive 归属到 HKCU / HKLM 主键。
    $saTag = if ($rp.hive -like 'HKLM*') { 'HKLM|Run' } else { 'HKCU|Run' }
    $saDisabled = Get-ApprovedDisabled $saTag $vp
    $en = $true
    if ($null -ne $saDisabled) { $en = -not $saDisabled }
    $results += [pscustomobject]@{
      id = $id; name = $vp; command = [string]$data; source = 'registry';
      hive = $rp.hive; regPath = $rp.path; valueName = $vp; valueType = $kind.ToString();
      valueData = $vData; valueDataB64 = $vDataB64; valueDataArray = @($vDataArr);
      filePath = ''; taskPath = ''; taskName = '';
      enabled = $en; location = $rp.label; scope = $rp.hive;
      # disabledBy：'system' = 被任务管理器/系统禁用（blob bit0=1）；'' = 启用或 Trim 自行禁用
      disabledBy = $(if ((-not $en) -and ($null -ne $saDisabled)) { 'system' } else { '' });
      publisher = (Get-Publisher $cmdPath); resolvedPath = $cmdPath
    }
  }
}

# ---------- 启动文件夹 ----------
$folders = @(
  @{ path = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'; label = '启动文件夹 · 当前用户'; scope = 'HKCU' },
  @{ path = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'; label = '启动文件夹 · 所有用户'; scope = 'HKLM' }
)

foreach ($f in $folders) {
  if (-not (Test-Path -LiteralPath $f.path)) { continue }
  Get-ChildItem -LiteralPath $f.path -Force -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Name -ieq 'desktop.ini') { return }
    $id = 'folder|' + $_.FullName
    $lnkTarget = ''
    if ($_.Extension -ieq '.lnk') { $lnkTarget = Resolve-Lnk $_.FullName }
    $pubPath = if ($lnkTarget) { $lnkTarget } else { $_.FullName }
    # v3.7.0：启动文件夹项同样读 StartupApprovedStartupFolder（值名为快捷方式文件名；
    # 驱动/系统写法不统一，先按带扩展名找，再按不带扩展名找，都找不到才回落「启用」）
    $saTag = if ($f.scope -eq 'HKLM') { 'HKLM|StartupFolder' } else { 'HKCU|StartupFolder' }
    $saDisabled = Get-ApprovedDisabled $saTag $_.Name
    if ($null -eq $saDisabled) { $saDisabled = Get-ApprovedDisabled $saTag ([IO.Path]::GetFileNameWithoutExtension($_.Name)) }
    $en = $true
    if ($null -ne $saDisabled) { $en = -not $saDisabled }
    $results += [pscustomobject]@{
      id = $id; name = [IO.Path]::GetFileNameWithoutExtension($_.Name); command = $_.FullName; source = 'folder';
      hive = $f.scope; regPath = ''; valueName = ''; valueType = '';
      valueData = ''; valueDataB64 = ''; valueDataArray = @();
      filePath = $_.FullName; taskPath = ''; taskName = '';
      enabled = $en; location = $f.label; scope = $f.scope;
      disabledBy = $(if ((-not $en) -and ($null -ne $saDisabled)) { 'system' } else { '' });
      publisher = (Get-Publisher $pubPath); resolvedPath = $(if ($lnkTarget) { $lnkTarget } else { $_.FullName })
    }
  }
}

# ---------- 计划任务（登录/开机触发器，排除 Microsoft 系统任务） ----------
$allTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
foreach ($t in $allTasks) {
  $triggers = @($t.Triggers)
  $hasLogon = @($triggers | Where-Object { ($_.CimClass.CimClassName -like '*Logon*') -or ($_.CimClass.CimClassName -like '*Boot*') }).Count -gt 0
  if (-not $hasLogon) { continue }
  $actions = @($t.Actions | ForEach-Object { if ($_.Execute) { (($_.Execute + ' ' + $_.Arguments).Trim()) } }) | Where-Object { $_ }
  $command = ($actions -join '  |  ')
  $taskName = [string]$t.TaskName
  $taskPath = [string]$t.TaskPath
  $id = 'task|' + $taskPath + $taskName
  $enabled = ($t.State -ne 'Disabled')
  $results += [pscustomobject]@{
    id = $id; name = $taskName; command = $command; source = 'task';
    hive = ''; regPath = ''; valueName = ''; valueType = '';
    valueData = ''; valueDataB64 = ''; valueDataArray = @();
    filePath = ''; taskPath = $taskPath; taskName = $taskName;
    enabled = $enabled; location = '计划任务' + $taskPath.TrimEnd('\'); scope = 'HKLM';
    # 计划任务的禁用语义由任务自身状态决定，与 StartupApproved 无关
    disabledBy = $(if (-not $enabled) { 'system' } else { '' });
    publisher = ''; resolvedPath = ''
  }
}

# ---------- 合并已禁用记录（注册表/文件夹项被移除后仍可回显并启用） ----------
if (Test-Path -LiteralPath $disabledFile) {
  try { $records = @(Get-Content -LiteralPath $disabledFile -Raw -Encoding UTF8 | ConvertFrom-Json) }
  catch { $records = @() }
  foreach ($r in $records) {
    if (-not $r.id) { continue }
    if (@($results | Where-Object { $_.id -eq $r.id }).Count -gt 0) { continue }
    $results += [pscustomobject]@{
      id = $r.id; name = $r.name; command = $r.command; source = $r.source;
      hive = $r.hive; regPath = $r.regPath; valueName = $r.valueName; valueType = $r.valueType;
      valueData = $r.valueData; valueDataB64 = $r.valueDataB64; valueDataArray = @($r.valueDataArray);
      filePath = $r.filePath; taskPath = $r.taskPath; taskName = $r.taskName;
      enabled = $false; location = $r.location; scope = $r.scope;
      # 这条来自 Trim 自己的禁用记录（旧版删值式禁用 / 文件夹移出），标记为 trim
      disabledBy = 'trim';
      publisher = $r.publisher; resolvedPath = $r.resolvedPath
    }
  }
}

if (@($results).Count -eq 0) { '[]' }
else { @($results) | ConvertTo-Json -Depth 8 -Compress }
