# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/memory-scripts.js → 常量 STUBBORN_KILL_SCRIPT
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：顽固软件专杀（结束进程）
# PROVENANCE>>>

$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$processes = @('edrservice', 'douyin_guard', 'douyin', 'douyin_tray', 'GameViewer', 'GameViewerService', 'GameViewerServer', 'GameViewerHealthd', 'MuMuNxMain', 'MuMuNxService', 'MuMuRemoteService', 'MuMuRemoteBackend', 'MumuRemoteHealthd', 'VEDetector', 'JianyingPro', 'JianyingProTray', 'wps', 'et', 'wpp', 'wpspdf', 'wpscloudsvr', 'MSPCManager', 'MSPCManagerCore', 'MSPCManagerService')
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
