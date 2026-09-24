# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/realtime-scripts.js → loss()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：丢包检测：ping 默认网关（只读）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$gateway = $null
try {
  $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
           Sort-Object -Property RouteMetric |
           Select-Object -First 1
  $gateway = [string]$route.NextHop
} catch {}
if (-not $gateway) {
  try {
    $route6 = Get-NetRoute -DestinationPrefix '::/0' -ErrorAction Stop |
              Sort-Object -Property RouteMetric |
              Select-Object -First 1
    $gateway = [string]$route6.NextHop
  } catch {}
}

$sent = 3
$received = 0
$latencySum = 0.0

if ($gateway) {
  # 火眼眼审查 2026-09-14（LOW）：网关地址拼入 WQL 过滤器前转义单引号（' → ''），
  # 防异常网关值破坏引号边界
  $gatewayWql = [string]$gateway
  $gatewayWql = $gatewayWql.Replace("'", "''")
  for ($i = 0; $i -lt $sent; $i++) {
    try {
      $p = Get-CimInstance -ClassName Win32_PingStatus -Filter ("Address='" + $gatewayWql + "' AND Timeout=600") -ErrorAction Stop
      if ($p -and $p.StatusCode -eq 0) {
        $received++
        $latencySum += [double]$p.ResponseTime
      }
    } catch {}
    Start-Sleep -Milliseconds 100
  }
}

$lost = $sent - $received
$lossRate = if ($sent -gt 0) { [Math]::Round($lost * 100.0 / $sent, 1) } else { 0 }
$avgLatency = if ($received -gt 0) { [Math]::Round($latencySum / $received, 1) } else { 0 }

@{
  success = $true
  gateway = $gateway
  sent = $sent
  received = $received
  lost = $lost
  lossRate = $lossRate
  latencyMs = $avgLatency
} | ConvertTo-Json -Compress
