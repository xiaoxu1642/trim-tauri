// memory-scripts.js - 内存清理 PowerShell 脚本生成器
// 参考 Mem Reduct 3.5.3（C:\kaifa\winclean\old\memreduct-master）：
// 通过 NtSetSystemInformation 按内存区域掩码顺序清理工作集 / 系统文件缓存 /
// 备用列表 / 修改列表 / 注册表缓存 / 合并物理内存页。需要管理员权限。
'use strict';

// ==================== 内存信息 ====================
// 物理内存 / 页面文件 / 系统缓存（CIM + 性能计数器，PowerShell 下比 P/Invoke 稳定）
const MEM_INFO_SCRIPT = `
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$os = Get-CimInstance Win32_OperatingSystem
$total = [long]$os.TotalVisibleMemorySize * 1KB
$free = [long]$os.FreePhysicalMemory * 1KB
$used = $total - $free
$load = [int][math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100)
if ($load -lt 0) { $load = 0 }
$pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
$pageTotal = 0
if ($pf) { $pageTotal = [long](($pf | Measure-Object -Property AllocatedBaseSize -Sum).Sum * 1MB) }
$pageUsed = 0
if ($pf) { $pageUsed = [long](($pf | Measure-Object -Property CurrentUsage -Sum).Sum * 1MB) }
$cache = 0
$cs = Get-Counter -Counter '\\Memory\\Cache Bytes' -ErrorAction SilentlyContinue
if ($cs) { $cache = [long]($cs.CounterSamples | Select-Object -First 1 -ExpandProperty CookedValue) }
[ordered]@{
  total = $total
  free = $free
  used = $used
  load = $load
  pageTotal = $pageTotal
  pageUsed = $pageUsed
  cache = $cache
} | ConvertTo-Json -Compress
`;

// ==================== 内存清理 ====================
// items: ['workingSet','fileCache','standbyPriority0','modified','standby','registry','combine']
// 按 Mem Reduct 顺序：工作集 → 系统文件缓存 → 修改列表 → 备用列表 → 低优先级备用列表 → 注册表缓存 → 合并物理内存页
function cleanScript(items) {
  // 信息类基于 Windows 11 27H2 实测：80=内存列表、87=合并物理内存页。
  // 82（SystemFileCacheInformationEx）在 27H2 上返回 STATUS_ACCESS_VIOLATION、
  // 84（SystemRegistryReconciliationInformation）返回 STATUS_INVALID_INFO_CLASS，
  // 故不提供这两项（MemReduct 的 winternl 值在新系统已不可用）。
  const order = [
    { key: 'workingSet', cls: 80,  kind: 'int',   value: 1, label: '工作集' },
    { key: 'modified',   cls: 80,  kind: 'int',   value: 2, label: '修改列表' },
    { key: 'standby',    cls: 80,  kind: 'int',   value: 3, label: '备用列表' },
    { key: 'standbyPriority0', cls: 80, kind: 'int', value: 4, label: '低优先级备用列表' },
    { key: 'combine',    cls: 87,  kind: 'combine', value: null, label: '合并物理内存页' }
  ].filter(o => items.includes(o.key));

  const lines = [
    '$ErrorActionPreference = \'SilentlyContinue\'',
    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
    `Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class MemNt {
  [DllImport("ntdll.dll")]
  public static extern int NtSetSystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength);
}
public static class Priv {
  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, IntPtr TokenHandle);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, IntPtr lpLuid);
  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, IntPtr NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
}
'@`,
    // 启用内存清理所需特权（Mem Reduct 也先做这一步）：
    // SeProfileSingleProcessPrivilege + SeIncreaseQuotaPrivilege，缺一不可
    'function Enable-Privilege([string]$privName) {',
    '  $hTok = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)',
    '  $ok = $false',
    '  try { $ok = [Priv]::OpenProcessToken([System.Diagnostics.Process]::GetCurrentProcess().Handle, 0x28, $hTok) } catch { }',
    '  if (-not $ok) { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($hTok); return }',
    '  $tok = [System.Runtime.InteropServices.Marshal]::ReadInt64($hTok)',
    '  [System.Runtime.InteropServices.Marshal]::FreeHGlobal($hTok)',
    '  $hLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)',
    '  $ok2 = $false',
    '  try { $ok2 = [Priv]::LookupPrivilegeValue($null, $privName, $hLuid) } catch { }',
    '  if (-not $ok2) { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($hLuid); return }',
    '  $luid = [System.Runtime.InteropServices.Marshal]::ReadInt64($hLuid)',
    '  [System.Runtime.InteropServices.Marshal]::FreeHGlobal($hLuid)',
    '  # TOKEN_PRIVILEGES = PrivilegeCount(4) + Luid(8) + Attributes(4)，Attributes=2 表示启用',
    '  $buf = New-Object byte[] 16',
    '  $buf[0] = 1',
    '  for ($i = 0; $i -lt 8; $i++) { $buf[4 + $i] = [byte](($luid -shr ($i * 8)) -band 0xFF) }',
    '  $buf[12] = 2',
    '  $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)',
    '  try {',
    '    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 16)',
    '    [Priv]::AdjustTokenPrivileges($tok, $false, $ptr, 0, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null',
    '  } finally { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr) }',
    '}',
    'Enable-Privilege \'SeProfileSingleProcessPrivilege\'',
    'Enable-Privilege \'SeIncreaseQuotaPrivilege\'',
    'function Set-NtInfo([int]$cls, [byte[]]$buf) {',
    '  $ptr = [IntPtr]::Zero',
    '  $len = 0',
    '  if ($buf -ne $null -and $buf.Length -gt 0) {',
    '    $len = $buf.Length',
    '    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($len)',
    '    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, $len)',
    '  }',
    '  try { return [MemNt]::NtSetSystemInformation($cls, $ptr, $len) }',
    '  finally { if ($ptr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr) } }',
    '}',
    'function Get-Bytes([long]$n) {',
    '  $b = New-Object byte[] 8',
    '  for ($i = 0; $i -lt 8; $i++) { $b[$i] = [byte](($n -shr ($i * 8)) -band 0xFF) }',
    '  return $b',
    '}',
    '$results = @()',
    // 清理前可用内存（CIM，比 GlobalMemoryStatusEx 的 ref 调用更稳定）
    '$before = [long]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory) * 1KB'
  ];

  for (const op of order) {
    const label = op.label;
    switch (op.kind) {
      case 'int':
        lines.push(`$st = Set-NtInfo ${op.cls} (Get-Bytes ${op.value})`);
        lines.push(`$results += [pscustomobject]@{ id = '${op.key}'; name = '${label}'; ok = ($st -eq 0); status = $st }`);
        break;
      case 'filecache':
        // SYSTEM_FILECACHE_INFORMATION：前两个 SIZE_T（Minimum/MaximumWorkingSet）置 MAXSIZE_T(0xFF..) 表示清空
        lines.push(`$fc = New-Object byte[] 48`);
        lines.push(`for ($i = 0; $i -lt 16; $i++) { $fc[$i] = 0xFF }`);
        lines.push(`$st = Set-NtInfo ${op.cls} $fc`);
        lines.push(`$results += [pscustomobject]@{ id = '${op.key}'; name = '${label}'; ok = ($st -eq 0); status = $st }`);
        break;
      case 'combine':
        // MEMORY_COMBINE_INFORMATION_EX：HandleCount=0 表示合并全部
        lines.push(`$cb = New-Object byte[] 8`);
        lines.push(`$st = Set-NtInfo ${op.cls} $cb`);
        lines.push(`$results += [pscustomobject]@{ id = '${op.key}'; name = '${label}'; ok = ($st -eq 0); status = $st }`);
        break;
      case 'null':
        lines.push(`$st = Set-NtInfo ${op.cls} $null`);
        lines.push(`$results += [pscustomobject]@{ id = '${op.key}'; name = '${label}'; ok = ($st -eq 0); status = $st }`);
        break;
    }
  }

  lines.push(
    // 清理后可用内存
    '$after = [long]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory) * 1KB',
    '$freed = $after - $before',
    'if ($freed -lt 0) { $freed = 0 }',
    '[pscustomobject]@{ before = $before; after = $after; freed = $freed; results = $results } | ConvertTo-Json -Compress -Depth 4'
  );

  return lines.join('\n');
}

// ==================== 运行进程列表 ====================
// 按内存占用降序返回前 300 个进程（Id / 名称 / 工作集 / 路径）
const PROCESSES_SCRIPT = `
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$procs = @(Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 300 Id, ProcessName, @{n='mem';e={[long]$_.WorkingSet64}}, Path)
'@@PROC@@' + ($procs | ConvertTo-Json -Compress)
`;

// ==================== 顽固软件专杀 ====================
// 清理 MuMu 模拟器 / 网易 UU 远程 / 抖音 / 剪映 / WPS 金山办公 / 微软电脑管家 的
// 后台常驻与守护进程（含其前台进程，故执行前会由 UI 层提示「默认不勾选」）。
// 输出 { killed, failed, leftover } 供渲染层 toast + 日志回传。
const STUBBORN_TARGET_PROCESSES = [
  'edrservice', 'douyin_guard', 'douyin', 'douyin_tray',
  'GameViewer', 'GameViewerService', 'GameViewerServer', 'GameViewerHealthd',
  'MuMuNxMain', 'MuMuNxService', 'MuMuRemoteService', 'MuMuRemoteBackend', 'MumuRemoteHealthd',
  'VEDetector', 'JianyingPro', 'JianyingProTray',
  'wps', 'et', 'wpp', 'wpspdf', 'wpscloudsvr',
  'MSPCManager', 'MSPCManagerCore', 'MSPCManagerService'
];
const STUBBORN_KILL_SCRIPT = `
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$processes = @(${STUBBORN_TARGET_PROCESSES.map(p => `'${p}'`).join(', ')})
$killed = @()
$failed = @()
foreach ($p in $processes) {
  $procs = Get-Process -Name $p -ErrorAction SilentlyContinue
  foreach ($pr in $procs) {
    try {
      Stop-Process -Id $pr.Id -Force -ErrorAction Stop
      $killed += "$($pr.Name)#$($pr.Id)"
    } catch {
      $failed += "$($pr.Name)#$($pr.Id)"
    }
  }
}
$leftover = @()
foreach ($p in $processes) {
  if (Get-Process -Name $p -ErrorAction SilentlyContinue) { $leftover += $p }
}
[pscustomobject]@{ killed = $killed.Count; failed = $failed.Count; leftover = $leftover } | ConvertTo-Json -Compress
`;

// ==================== 顽固软件：阻止开机自启（N1，2026-09-14 重复点审查） ====================
// 从已下线的「电脑优化中心 - 顽固软件策略专杀」迁移而来，与内存清理页合并为同一张
// 「顽固软件治理」卡片的两层：第一层「立即结束进程」= 上面的 STUBBORN_KILL_SCRIPT（一次性），
// 本脚本是第二层「阻止开机自启」（持久）。
// 动作：MuMu / 网易 UU 远程 / 微软电脑管家等常驻服务改为「手动」并停止；停止 WPS 云文档服务；
// 删除 WPS 更新计划任务并关闭其自动升级。属持久化策略，不提供自动还原（与优化项时代一致）。
const STUBBORN_BLOCK_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# M-1（2026-09-15）：拒绝静默空吞——每个操作回读校验，成功/失败分开记账，
# 未提权或单项失败不再无条件报绿。内存清理单次会话内最多弹 3 次错误。
$changedServices = [System.Collections.Generic.List[string]]::new()
$failServices = [System.Collections.Generic.List[string]]::new()
$failed = 0
function Add-SvcResult($name, $ok) {
  if ($ok) { $script:changedServices.Add($name) } else { $script:failServices.Add($name); $script:failed++ }
}
$services = @('Edrservice','GameViewerService','MuMuRemoteService','PCManager Service Store')
foreach ($svc in $services) {
  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if (-not $s) { continue }
  try {
    if ($s.Status -eq 'Running') { Stop-Service -Name $svc -Force -ErrorAction Stop }
    Set-Service -Name $svc -StartupType Manual -ErrorAction Stop
    $after = Get-Service -Name $svc -ErrorAction SilentlyContinue
    Add-SvcResult $svc ($null -ne $after -and $after.StartType -eq 'Manual')
  } catch { Add-SvcResult $svc $false }
}
$wc = Get-Service -Name 'wpscloudsvr' -ErrorAction SilentlyContinue
if ($wc) {
  try {
    if ($wc.Status -eq 'Running') { Stop-Service -Name 'wpscloudsvr' -Force -ErrorAction Stop }
    $wcAfter = Get-Service -Name 'wpscloudsvr' -ErrorAction SilentlyContinue
    Add-SvcResult 'wpscloudsvr' ($null -ne $wcAfter -and $wcAfter.Status -eq 'Stopped')
  } catch { Add-SvcResult 'wpscloudsvr' $false }
}
$changedTasks = [System.Collections.Generic.List[string]]::new()
$failTasks = [System.Collections.Generic.List[string]]::new()
# 审查 M-6（2026-09-14）：Unregister-ScheduledTask 不可逆，删除前先 Export-ScheduledTask
# 到 %APPDATA%\Trim\backup\tasks\<name>.xml，与 startup/contextmenu 的「删除前备份」纪律对齐。
$taskBackupDir = Join-Path $env:APPDATA 'Trim\backup\tasks'
foreach ($taskName in @('WpsUpdateTask_CHENG','WpsUpdateLogonTask_CHENG')) {
  if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { continue }
  try {
    if (-not (Test-Path $taskBackupDir)) { New-Item -Path $taskBackupDir -ItemType Directory -Force | Out-Null }
    Export-ScheduledTask -TaskName $taskName | Out-File -FilePath (Join-Path $taskBackupDir ($taskName + '.xml')) -Encoding UTF8 -ErrorAction Stop
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
      $failTasks.Add($taskName); $script:failed++
    } else { $changedTasks.Add($taskName) }
  } catch { $failTasks.Add($taskName); $script:failed++ }
}
$wpsKey = 'HKCU:\\Software\\Kingsoft\\Office\\6.0\\Common\\updateinfo'
if (Test-Path $wpsKey) {
  try { Set-ItemProperty -Path $wpsKey -Name 'UpdateMode' -Value 'close' -ErrorAction Stop } catch { $script:failed++ }
}
[pscustomobject]@{
  services = @($changedServices); tasks = @($changedTasks)
  failedServices = @($failServices); failedTasks = @($failTasks); failedCount = $script:failed
} | ConvertTo-Json -Compress
`;

// ==================== 结束进程 ====================
function killScript(pid, expectedName = '') {
  const psName = String(expectedName).replace(/'/g, "''");
  return `
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$p = Get-Process -Id ${Number(pid)} -ErrorAction SilentlyContinue
if ($null -eq $p) {
  [pscustomobject]@{ success = $false; message = '进程不存在或已退出' } | ConvertTo-Json -Compress
  exit 0
}
$expected = '${psName}'
if ($expected -and $p.ProcessName -ne $expected) {
  [pscustomobject]@{ success = $false; message = '进程 ID 已被系统复用，已拒绝结束' } | ConvertTo-Json -Compress
  exit 0
}
$name = $p.ProcessName
Stop-Process -Id ${Number(pid)} -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
$alive = Get-Process -Id ${Number(pid)} -ErrorAction SilentlyContinue
if ($null -eq $alive) {
  [pscustomobject]@{ success = $true; message = "已结束进程 $name (PID ${Number(pid)})" } | ConvertTo-Json -Compress
} else {
  [pscustomobject]@{ success = $false; message = "无法结束进程 $name (PID ${Number(pid)})，可能需要管理员权限" } | ConvertTo-Json -Compress
}
`;
}

module.exports = { MEM_INFO_SCRIPT, cleanScript, PROCESSES_SCRIPT, killScript, STUBBORN_KILL_SCRIPT, STUBBORN_BLOCK_SCRIPT };
