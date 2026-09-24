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
