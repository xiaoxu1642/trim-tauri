# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/peripheral-scripts.js → restoreBackup()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：从备份恢复外设设置（危险）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$backupDir = Join-Path $env:APPDATA 'Trim\peripheral-backup'
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
if ($all[0].Name -match '^backup_(\d{8}_\d{6})') { $stamp = $Matches[1] }
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
