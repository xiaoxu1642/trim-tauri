// 外设优化（更多调优项）注册表读写脚本
// 三组调优：
//   Win32PrioritySeparation  @ HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl           （默认 2）
//   KeyboardDataQueueSize    @ HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters      （默认 100）
//   MouseDataQueueSize       @ HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters      （默认 100）
// 注意：键鼠队列大小需重启电脑后生效。

const QUERY_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Get-TFDword([string]$p, [string]$n) {
  try { [int](Get-ItemPropertyValue -LiteralPath $p -Name $n -ErrorAction Stop) } catch { -1 }
}
$q = [pscustomobject]@{
  win32 = Get-TFDword 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl' 'Win32PrioritySeparation'
  keyboard = Get-TFDword 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\kbdclass\\Parameters' 'KeyboardDataQueueSize'
  mouse = Get-TFDword 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mouclass\\Parameters' 'MouseDataQueueSize'
}
'@@PERIPHERAL@@' + ($q | ConvertTo-Json -Compress)
`;

const APPLY_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$options = '__OPTIONS_JSON__' | ConvertFrom-Json
$targets = @(
  @{ Path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl'; Name = 'Win32PrioritySeparation'; Value = [int]$options.win32 },
  @{ Path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\kbdclass\\Parameters'; Name = 'KeyboardDataQueueSize'; Value = [int]$options.keyboard },
  @{ Path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mouclass\\Parameters'; Name = 'MouseDataQueueSize'; Value = [int]$options.mouse }
)
# PE-5（S6，2026-09-15）：写入前备份原值到 %APPDATA%\Trim\peripheral-backup\。
# 复核 N1（2026-09-16）：随本文件新增 RESTORE_BACKUP_SCRIPT，「还原修改前的值」
# 导入最新一份备份；「恢复 Windows 默认」才写出厂默认值，两个语义分开。
$backupDir = Join-Path $env:APPDATA 'Trim\\peripheral-backup'
if (-not (Test-Path -LiteralPath $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
$backupFile = Join-Path $backupDir ('backup_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.reg')
$regPaths = @()
foreach ($t in $targets) {
  if ($t.Value -lt 0) { continue }
  $stdPath = $t.Path -replace '^HKLM:', 'HKEY_LOCAL_MACHINE'
  if ($regPaths -notcontains $stdPath) { $regPaths += $stdPath }
}
# 导出整个父键（值可能存在/可能不存在），失败不阻断写入——有备份比没备份强
foreach ($rp in $regPaths) {
  & reg.exe export "$rp" "$backupFile" /y 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) { break }
}
foreach ($t in $targets) {
  if ($t.Value -lt 0) { continue }
  if (-not (Test-Path $t.Path)) { New-Item -Path $t.Path -Force | Out-Null }
  Set-ItemProperty -Path $t.Path -Name $t.Name -Value $t.Value -Type DWord
  Write-Output ('SET ' + $t.Name + '=' + $t.Value)
}
Write-Output 'PERIPHERAL-APPLY-OK'
`;

// 复核 N1（2026-09-16）：导入最新一份备份 .reg，还原用户修改前的真实注册表值。
// 仅认本应用备份目录内、文件名严格匹配 backup_*.reg 的最新一份，不接受任意路径。
const RESTORE_BACKUP_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$backupDir = Join-Path $env:APPDATA 'Trim\\peripheral-backup'
if (-not (Test-Path -LiteralPath $backupDir)) {
  Write-Output ('@@PERIPHERAL_RESTORE@@' + ({ ok = $false; reason = 'no-backup' } | ConvertTo-Json -Compress))
  exit 0
}
$latest = Get-ChildItem -LiteralPath $backupDir -Filter 'backup_*.reg' -File -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $latest) {
  Write-Output ('@@PERIPHERAL_RESTORE@@' + ({ ok = $false; reason = 'no-backup' } | ConvertTo-Json -Compress))
  exit 0
}
& reg.exe import "$($latest.FullName)" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  Write-Output ('@@PERIPHERAL_RESTORE@@' + ({ ok = $false; reason = 'import-failed' } | ConvertTo-Json -Compress))
  exit 0
}
Write-Output ('@@PERIPHERAL_RESTORE@@' + ({ ok = $true; file = $latest.Name } | ConvertTo-Json -Compress))
`;

module.exports = {
  query() { return QUERY_SCRIPT; },
  apply(options) {
    const json = JSON.stringify(options || {});
    return APPLY_SCRIPT.replace('__OPTIONS_JSON__', json.replace(/'/g, "''"));
  },
  restoreBackup() { return RESTORE_BACKUP_SCRIPT; }
};
