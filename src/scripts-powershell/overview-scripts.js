// overview-scripts.js - 系统概览实时指标采集（仅读取本机信息，不访问网络）
// CPU：PerfFormattedData 瞬时占用；内存：Win32_OperatingSystem 可见内存
// 磁盘：Win32_LogicalDisk 固定盘（DriveType=3）；开机时长：(当前时间 - LastBootUpTime)
const OVERVIEW_METRICS_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$os = Get-CimInstance Win32_OperatingSystem
$cpu = if ($os) { (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'") } else { $null }
$cpuLoad = 0.0
if ($cpu -and $null -ne $cpu.PercentProcessorTime) {
  $cpuLoad = [Math]::Round([double]$cpu.PercentProcessorTime, 1)
  if ($cpuLoad -lt 0) { $cpuLoad = 0 }
  if ($cpuLoad -gt 100) { $cpuLoad = 100 }
}

# 内存（KB）
$memTotalKB = 0.0
$memFreeKB = 0.0
if ($os) {
  $memTotalKB = [double]$os.TotalVisibleMemorySize
  $memFreeKB = [double]$os.FreePhysicalMemory
}
$memUsedKB = $memTotalKB - $memFreeKB
$memPercent = if ($memTotalKB -gt 0) { [Math]::Round($memUsedKB * 100.0 / $memTotalKB, 1) } else { 0 }
if ($memPercent -lt 0) { $memPercent = 0 }; if ($memPercent -gt 100) { $memPercent = 100 }

# 磁盘（固定盘）
$disks = @()
Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3' | ForEach-Object {
  $total = [double]$_.Size
  $free = [double]$_.FreeSpace
  $used = $total - $free
  $percent = if ($total -gt 0) { [Math]::Round($used * 100.0 / $total, 1) } else { 0 }
  if ($percent -lt 0) { $percent = 0 }; if ($percent -gt 100) { $percent = 100 }
  $disks += @{
    name = [string]$_.DeviceID
    label = [string]$_.VolumeName
    total = $total
    free = $free
    used = $used
    percent = $percent
  }
}

# 开机时长
$uptimeText = '--'
if ($os -and $os.LastBootUpTime) {
  $span = (Get-Date) - $os.LastBootUpTime
  $days = [Math]::Floor($span.TotalDays)
  $hours = $span.Hours
  $mins = $span.Minutes
  if ($days -gt 0) { $uptimeText = "$days 天 $hours 小时 $mins 分钟" }
  elseif ($hours -gt 0) { $uptimeText = "$hours 小时 $mins 分钟" }
  else { $uptimeText = "$mins 分钟" }
}

$processCount = @(Get-Process -ErrorAction SilentlyContinue).Count

@{
  success = $true
  cpu = $cpuLoad
  memory = @{ total = $memTotalKB * 1KB; free = $memFreeKB * 1KB; used = $memUsedKB * 1KB; percent = $memPercent }
  disks = $disks
  uptime = $uptimeText
  processes = $processCount
  system = @{
    caption = [string]$os.Caption
    version = [string]$os.Version
    build = [string]$os.BuildNumber
    computerName = [string]$env:COMPUTERNAME
    userName = [string]$env:USERNAME
  }
} | ConvertTo-Json -Compress -Depth 6
`;

module.exports = { metrics() { return OVERVIEW_METRICS_SCRIPT; } };

// ==================== 系统体检（v2.6.0 P1-6，只读诊断） ====================
// 借鉴 Pavise SystemAudit 的设计哲学：全部只读、不代改；每条结论自带证据等级
// （本机实测 / 机制明确 / 未验证），检测不出时如实标「未验证」，不伪造结论。
// status 分级：ok=正常 / warn=注意 / bad=异常 / unknown=无法判定。
const SYSTEM_CHECKUP_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$checks = @()
function Add-Check([string]$id, [string]$title, [string]$status, [string]$value, [string]$detail, [string]$evidence) {
  $script:checks += [pscustomobject]@{ id = $id; title = $title; status = $status; value = $value; detail = $detail; evidence = $evidence }
}

# ---- 1. CPU 拓扑（核数/线程数 + 混合架构判定） ----
$cores = 0; $logical = 0
Get-CimInstance Win32_Processor | ForEach-Object { $cores += [int]$_.NumberOfCores; $logical += [int]$_.NumberOfLogicalProcessors }
if ($cores -gt 0) {
  # 混合架构：内核按逻辑处理器公开 EfficiencyClass（0=E核 1+=P核），分级存在即为 P/E 混合
  $ecVals = @(Get-ChildItem 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor' -ErrorAction SilentlyContinue | ForEach-Object { (Get-ItemProperty -Path $_.PSPath -Name EfficiencyClass -ErrorAction SilentlyContinue).EfficiencyClass } | Where-Object { $null -ne $_ })
  $uniqueEc = @($ecVals | Sort-Object -Unique)
  if ($uniqueEc.Count -gt 1) {
    Add-Check 'cpu_topology' 'CPU 拓扑' 'ok' "$cores 核 $logical 线程（P/E 混合架构）" '检测到效率类分级，游戏场景建议绑定性能核' '机制明确'
  } else {
    Add-Check 'cpu_topology' 'CPU 拓扑' 'ok' "$cores 核 $logical 线程" '同构多核架构，无需区分核类型调度' '本机实测'
  }
} else {
  Add-Check 'cpu_topology' 'CPU 拓扑' 'unknown' '无法读取' '未读取到处理器信息' '未验证'
}

# ---- 2. 内存通道与频率 ----
$mems = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | Where-Object { $null -ne $_ })
if ($mems.Count -gt 0) {
  $speeds = @($mems | ForEach-Object { [int]$_.Speed } | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
  $speedText = if ($speeds.Count -gt 0) { "$($speeds -join '/') MT/s" } else { '频率未知' }
  $capSum = ($mems | Measure-Object -Property Capacity -Sum).Sum
  $capGB = if ($capSum) { [Math]::Round($capSum / 1GB, 1) } else { 0 }
  if ($mems.Count -ge 2) {
    Add-Check 'memory_channels' '内存通道' 'ok' "$($mems.Count) 条 / $capGB GB / $speedText" '已组多通道，内存带宽充足' '本机实测'
  } else {
    Add-Check 'memory_channels' '内存通道' 'warn' "1 条 / $capGB GB / $speedText" '单通道运行，加装同规格内存组双通道可提升带宽' '本机实测'
  }
} else {
  Add-Check 'memory_channels' '内存通道' 'unknown' '无法读取' 'SMBIOS 未返回内存条信息' '未验证'
}

# ---- 3. 当前电源计划 ----
$planLine = (powercfg /getactivescheme 2>$null) | Select-Object -First 1
if ("$planLine" -match '\\((.+)\\)') {
  $planName = $Matches[1]
  if ("$planName" -match '节能|Power saver') {
    Add-Check 'power_plan' '电源计划' 'warn' $planName '节能计划会限制性能释放，建议切换平衡或高性能' '本机实测'
  } elseif ("$planName" -match '高性能|卓越|High|Ultimate') {
    Add-Check 'power_plan' '电源计划' 'ok' $planName '高性能计划已启用' '本机实测'
  } else {
    Add-Check 'power_plan' '电源计划' 'ok' $planName '平衡计划（系统默认）；追求极限响应可切换高性能' '本机实测'
  }
} else {
  Add-Check 'power_plan' '电源计划' 'unknown' '无法读取' 'powercfg 无有效输出' '未验证'
}

# ---- 4. 开机自启数量（注册表 Run/RunOnce + 启动文件夹，与启动项管理页同口径子集） ----
$startupCount = 0
foreach ($rk in @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce')) {
  $k = Get-Item -Path $rk -ErrorAction SilentlyContinue
  if ($k) { $startupCount += @($k.GetValueNames() | Where-Object { "$_" }).Count }
}
foreach ($folder in @((Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'), (Join-Path $env:ProgramData 'Microsoft\\Windows\\Start Menu\\Programs\\StartUp'))) {
  if (Test-Path $folder) { $startupCount += @(Get-ChildItem $folder -File -ErrorAction SilentlyContinue).Count }
}
if ($startupCount -gt 15) {
  Add-Check 'startup_count' '开机自启' 'warn' "$startupCount 项" '自启项偏多，建议在「启动项管理」中精简' '本机实测'
} else {
  Add-Check 'startup_count' '开机自启' 'ok' "$startupCount 项" '自启数量正常（注册表 Run/RunOnce + 启动文件夹）' '本机实测'
}

# ---- 5. 磁盘健康（SMART） ----
$pdDisks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $null -ne $_ })
$unhealthy = @($pdDisks | Where-Object { $_.HealthStatus -and ("$($_.HealthStatus)" -ne 'Healthy') })
if ($pdDisks.Count -gt 0 -and $unhealthy.Count -gt 0) {
  Add-Check 'disk_health' '磁盘健康' 'bad' "$($unhealthy.Count) 块异常（共 $($pdDisks.Count) 块）" 'SMART 报告异常，请立即备份数据' '机制明确'
} elseif ($pdDisks.Count -gt 0) {
  Add-Check 'disk_health' '磁盘健康' 'ok' "$($pdDisks.Count) 块全部健康" 'SMART 健康状态正常' '机制明确'
} else {
  $wmiDisks = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Where-Object { $null -ne $_ })
  $badWmi = @($wmiDisks | Where-Object { $_.Status -and ("$($_.Status)" -ne 'OK') })
  if ($wmiDisks.Count -gt 0 -and $badWmi.Count -gt 0) {
    Add-Check 'disk_health' '磁盘健康' 'bad' "$($badWmi.Count) 块异常" '设备状态异常，请备份数据' '本机实测'
  } elseif ($wmiDisks.Count -gt 0) {
    Add-Check 'disk_health' '磁盘健康' 'ok' "$($wmiDisks.Count) 块状态正常" 'WMI 设备状态正常（未读取 SMART 明细）' '本机实测'
  } else {
    Add-Check 'disk_health' '磁盘健康' 'unknown' '无法读取' '未获取到磁盘状态' '未验证'
  }
}

# ---- 6. 可精简服务（公认无日常用途的服务仍在启用时提示） ----
$nonessential = @('DiagTrack','dmwappushservice','MapsBroker','Fax','RemoteRegistry','RetailDemo','SharedAccess','WMPNetworkSvc','WerSvc','WalletService','PhoneSvc','TapiSrv','SCardSvr','SCPolicySvc','PcaSvc','SensrSvc')
$svcOn = @(Get-Service -Name $nonessential -ErrorAction SilentlyContinue | Where-Object { $_.StartType -ne 'Disabled' -and ($_.Status -eq 'Running' -or $_.StartType -eq 'Automatic') })
if ($svcOn.Count -gt 0) {
  Add-Check 'nonessential_services' '可精简服务' 'warn' "$($svcOn.Count) 个仍在启用" '遥测/传真/远程注册表等可精简服务未禁用，可在「电脑优化中心-系统服务」按需处理' '机制明确'
} else {
  Add-Check 'nonessential_services' '可精简服务' 'ok' '无' '公认可精简的服务均已禁用或未安装' '机制明确'
}

# ---- 7. 显示器刷新率 ----
$maxHz = 0
Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object { $hz = [int]$_.CurrentRefreshRate; if ($hz -gt $maxHz) { $maxHz = $hz } }
if ($maxHz -gt 1) {
  if ($maxHz -le 60) {
    Add-Check 'refresh_rate' '显示器刷新率' 'warn' "$maxHz Hz" '当前刷新率 60Hz 及以下；高刷屏请在系统显示设置中调高' '本机实测'
  } else {
    Add-Check 'refresh_rate' '显示器刷新率' 'ok' "$maxHz Hz" '刷新率高于 60Hz' '本机实测'
  }
} else {
  Add-Check 'refresh_rate' '显示器刷新率' 'unknown' '无法读取' '未获取到当前刷新率' '未验证'
}

# ---- 8. Defender 实时防护 ----
$mpStatus = $null
try { $mpStatus = Get-MpComputerStatus -ErrorAction Stop } catch { $mpStatus = $null }
if ($mpStatus) {
  $rt = [bool]$mpStatus.RealTimeProtectionEnabled
  $am = [bool]$mpStatus.AMServiceEnabled
  if ($rt -and $am) {
    Add-Check 'defender_status' '实时防护' 'ok' '已开启' 'Defender 实时保护与防恶意软件服务均正常' '本机实测'
  } else {
    Add-Check 'defender_status' '实时防护' 'bad' '已关闭' '系统安全暴露风险较高（若为主动关闭请自行权衡）' '本机实测'
  }
} else {
  $wd = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
  if ($wd -and $wd.Status -eq 'Running') {
    Add-Check 'defender_status' '实时防护' 'ok' '服务运行中' '防护状态明细不可读（可能被安全软件接管），Defender 服务正常' '本机实测'
  } elseif ($wd) {
    Add-Check 'defender_status' '实时防护' 'warn' '服务未运行' '可能已由第三方安全软件接管防护，请确认防护来源' '本机实测'
  } else {
    Add-Check 'defender_status' '实时防护' 'unknown' '无法判定' '本机未检测到 Defender 服务' '未验证'
  }
}

# ---- 9. 系统盘剩余空间 ----
$sysDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
if ($sysDrive -and [double]$sysDrive.Size -gt 0) {
  $freePct = [Math]::Round([double]$sysDrive.FreeSpace * 100.0 / [double]$sysDrive.Size, 1)
  $freeGB = [Math]::Round([double]$sysDrive.FreeSpace / 1GB, 1)
  if ($freePct -lt 10) {
    Add-Check 'sys_drive_free' '系统盘空间' 'bad' "剩余 $freeGB GB（$freePct%）" '系统盘空间严重不足，会影响系统更新与虚拟内存' '本机实测'
  } elseif ($freePct -lt 20) {
    Add-Check 'sys_drive_free' '系统盘空间' 'warn' "剩余 $freeGB GB（$freePct%）" '系统盘空间偏紧，建议前往「磁盘清理」释放空间' '本机实测'
  } else {
    Add-Check 'sys_drive_free' '系统盘空间' 'ok' "剩余 $freeGB GB（$freePct%）" '系统盘空间充足' '本机实测'
  }
} else {
  Add-Check 'sys_drive_free' '系统盘空间' 'unknown' '无法读取' '未获取到系统盘信息' '未验证'
}

@{ checks = $checks } | ConvertTo-Json -Depth 5 -Compress
`;

module.exports.checkup = function () { return SYSTEM_CHECKUP_SCRIPT; };
