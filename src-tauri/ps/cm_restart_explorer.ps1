# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/contextmenu-scripts.js → restartExplorer()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：重启资源管理器
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$mySession = (Get-Process -Id $PID).SessionId
$targets = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $mySession })
if (-not $targets.Count) {
  [pscustomobject]@{ success = $false; killed = 0; restarted = 0; alive = 0; message = '当前会话没有运行中的资源管理器' } | ConvertTo-Json -Compress
  exit
}
# 先记下原路径，逐个原样拉回（多显示器/多实例场景下 Path 可能不同）
$paths = @($targets | ForEach-Object { [string]$_.Path } | Where-Object { $_ } | Select-Object -Unique)
foreach ($p in $targets) { try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch {} }
Start-Sleep -Milliseconds 700
$started = 0
foreach ($path in $paths) {
  if ($path -and (Test-Path -LiteralPath $path)) {
    try { Start-Process -FilePath $path -ErrorAction Stop; $started++ } catch {}
  }
}
if ($started -eq 0) {
  $fallback = Join-Path $env:SystemRoot 'explorer.exe'
  try { Start-Process -FilePath $fallback -ErrorAction Stop; $started = 1 } catch {}
}
Start-Sleep -Milliseconds 900
$alive = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $mySession }).Count
[pscustomobject]@{
  success   = ($alive -gt 0)
  killed    = $targets.Count
  restarted = $started
  alive     = $alive
  message   = $(if ($alive -gt 0) { '已重启资源管理器' } else { '资源管理器未能自动拉起，请手动启动 explorer.exe' })
} | ConvertTo-Json -Compress
