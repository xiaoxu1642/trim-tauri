# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/peripheral-scripts.js → apply({"__trim_sentinel__":true})
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：应用外设优化（哨兵 options JSON）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$options = '{"__trim_sentinel__":true}' | ConvertFrom-Json
$targets = @(
  @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl'; Name = 'Win32PrioritySeparation'; Value = [int]$options.win32 },
  @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters'; Name = 'KeyboardDataQueueSize'; Value = [int]$options.keyboard },
  @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters'; Name = 'MouseDataQueueSize'; Value = [int]$options.mouse }
)
# PE-5（S6，2026-09-15）：写入前备份原值到 %APPDATA%Trimperipheral-backup。
# 复核 N1（2026-09-16）：随本文件新增 RESTORE_BACKUP_SCRIPT，「还原修改前的值」
# 导入最新一份备份；「恢复 Windows 默认」才写出厂默认值，两个语义分开。
$backupDir = Join-Path $env:APPDATA 'Trim\peripheral-backup'
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
