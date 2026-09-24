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
