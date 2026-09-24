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
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$regPaths = @()
foreach ($t in $targets) {
  if ($t.Value -lt 0) { continue }
  $stdPath = $t.Path -replace '^HKLM:', 'HKEY_LOCAL_MACHINE'
  if ($regPaths -notcontains $stdPath) { $regPaths += $stdPath }
}
# 审查 v2-M12：**每个**父键都要备份，旧写法导出第一个成功件后就 break —— 三组全选调优时
# 只有 PriorityControl 有备份，KeyboardDataQueueSize / MouseDataQueueSize 的修改前值毫无记录，
# 用户点「还原修改前的值」却拿到绿色提示，实际键鼠队列值仍是优化后的（承诺的可逆性不成立）。
# 同一批次共用一个时间戳、按键分片成 backup_<stamp>_<n>.reg，还原时按批整组导入。
$backupCount = 0
$part = 0
foreach ($rp in $regPaths) {
  $part++
  $backupFile = Join-Path $backupDir ('backup_' + $stamp + '_' + $part + '.reg')
  & reg.exe export "$rp" "$backupFile" /y 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) { $backupCount++ }
  # 导出失败的半成品分片不留：否则还原时会去导入一个内容不完整的 .reg
  else { Remove-Item -LiteralPath $backupFile -Force -ErrorAction SilentlyContinue }
}
Write-Output ('BACKUP ' + $backupCount + '/' + $regPaths.Count)
foreach ($t in $targets) {
  if ($t.Value -lt 0) { continue }
  if (-not (Test-Path $t.Path)) { New-Item -Path $t.Path -Force | Out-Null }
  Set-ItemProperty -Path $t.Path -Name $t.Name -Value $t.Value -Type DWord
  Write-Output ('SET ' + $t.Name + '=' + $t.Value)
}
Write-Output 'PERIPHERAL-APPLY-OK'
`;

// 复核 N1（2026-09-16）：导入备份 .reg，还原用户修改前的真实注册表值。
// 仅认本应用备份目录内、文件名严格匹配 backup_*.reg 的**最新一批**（v2-M12 起同时间戳分片成组），
// 不接受任意路径入参。
const RESTORE_BACKUP_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$backupDir = Join-Path $env:APPDATA 'Trim\\peripheral-backup'
if (-not (Test-Path -LiteralPath $backupDir)) {
  Write-Output ('@@PERIPHERAL_RESTORE@@' + ({ ok = $false; reason = 'no-backup' } | ConvertTo-Json -Compress))
  exit 0
}
$all = @(Get-ChildItem -LiteralPath $backupDir -Filter 'backup_*.reg' -File -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending)
if ($all.Count -eq 0) {
  Write-Output ('@@PERIPHERAL_RESTORE@@' + ({ ok = $false; reason = 'no-backup' } | ConvertTo-Json -Compress))
  exit 0
}
# 审查 v2-M12：一次 apply 会留下同时间戳的多个分片（backup_<stamp>_1..N.reg），旧写法
# 「Select-Object -First 1」只导最新那一个 ⇒ 三键只还原一键却报「已还原」。现在按**批**整组导入。
$stamp = ''
if ($all[0].Name -match '^backup_(\\d{8}_\\d{6})') { $stamp = $Matches[1] }
$group = @()
if ($stamp) { $group = @($all | Where-Object { $_.Name -like ('backup_' + $stamp + '*.reg') }) }
if (@($group).Count -eq 0) { $group = @($all[0]) }
$imported = 0
foreach ($f in $group) {
  & reg.exe import "$($f.FullName)" 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) { $imported++ }
}
$total = @($group).Count
$ok = ($imported -gt 0 -and $imported -eq $total)
$reason = ''
if (-not $ok) { if ($imported -eq 0) { $reason = 'import-failed' } else { $reason = 'partial' } }
# restored/total 必须回传：部分成功不能再报成全成功（v2-M12 的另一半是「谎报」）
Write-Output ('@@PERIPHERAL_RESTORE@@' + ({ ok = $ok; reason = $reason; restored = $imported; total = $total; file = $all[0].Name } | ConvertTo-Json -Compress))
`;

module.exports = {
  query() { return QUERY_SCRIPT; },
  apply(options) {
    const json = JSON.stringify(options || {});
    return APPLY_SCRIPT.replace('__OPTIONS_JSON__', json.replace(/'/g, "''"));
  },
  restoreBackup() { return RESTORE_BACKUP_SCRIPT; }
};
