# <<<PROVENANCE
# 来源：vendor/upstream-js/main.js → 常量 REALTIME_STREAM_SCRIPT（内联模板字面量）
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：常驻流式采样器（每秒一行 JSON，前台长驻，由 Rust 侧生命周期管理）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$first = @{}
while ($true) {
  $cur = @{}
  try {
    Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface -ErrorAction Stop |
      Where-Object { $_.Name -notlike '*_Total*' } |
      ForEach-Object { $cur[[string]$_.Name] = @{ rx = [double]$_.BytesReceivedPersec; tx = [double]$_.BytesSentPersec } }
  } catch {}
  if ($first.Count -gt 0 -and $cur.Count -gt 0) {
    $adapters = @()
    foreach ($k in $cur.Keys) {
      if (-not $first.ContainsKey($k)) { continue }
      $rx = [Math]::Max(0, $cur[$k].rx - $first[$k].rx)
      $tx = [Math]::Max(0, $cur[$k].tx - $first[$k].tx)
      $adapters += @{ name = [string]$k; up = [Math]::Round($tx, 0); down = [Math]::Round($rx, 0) }
    }
    @{ t = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); adapters = $adapters } | ConvertTo-Json -Compress -Depth 4 | Write-Output
  }
  $first = $cur
  Start-Sleep -Milliseconds 1000
}
