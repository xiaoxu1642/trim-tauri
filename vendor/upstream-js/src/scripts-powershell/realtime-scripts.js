// realtime-scripts.js - 实时网速监控 PowerShell 脚本
// 流量采集：Win32_PerfRawData_Tcpip_NetworkInterface 性能计数器两次采样差值（累计字节）
// 网卡枚举：Win32_NetworkAdapter（PhysicalAdapter=True）
// 丢包检测：Win32_PingStatus ping 默认网关

// 枚举本机物理网卡
const ADAPTERS_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$adapters = @()
try {
  Get-CimInstance Win32_NetworkAdapter -ErrorAction Stop |
    Where-Object { $_.PhysicalAdapter -eq $true } |
    ForEach-Object {
      $status = switch ([int]$_.NetConnectionStatus) {
        2 { 'Up' } 1 { 'Connecting' } 0 { 'Down' } 3 { 'Disconnecting' } 7 { 'MediaDisconnected' } 9 { 'AuthSucceeded' } default { 'Unknown' }
      }
      $adapters += @{
        name = [string]$_.Name
        connectionName = [string]$_.NetConnectionID
        description = [string]$_.Name
        status = $status
        mac = [string]$_.MACAddress
        linkSpeed = [string]$_.Speed
      }
    }
} catch {}

if ($adapters.Count -eq 0) {
  @{ success = $false; message = '未检测到物理网卡'; adapters = @() } | ConvertTo-Json -Compress -Depth 4
} else {
  @{ success = $true; adapters = $adapters } | ConvertTo-Json -Compress -Depth 4
}
`;

// 单次流量采样：对每个网络接口做两次累计字节采样，差值 / 间隔 = 速率(B/s)
const SAMPLE_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$intervalMs = 900

# 首次采样
$first = @{}
try {
  Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface -ErrorAction Stop |
    Where-Object { $_.Name -notlike '*_Total*' } |
    ForEach-Object {
      $first[[string]$_.Name] = @{ rx = [double]$_.BytesReceivedPersec; tx = [double]$_.BytesSentPersec }
    }
} catch {}

Start-Sleep -Milliseconds $intervalMs

# 二次采样，计算速率（B/s）
$adapters = @()
try {
  Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface -ErrorAction Stop |
    Where-Object { $_.Name -notlike '*_Total*' } |
    ForEach-Object {
      $name = [string]$_.Name
      if ($first.ContainsKey($name)) {
        $rx = [Math]::Max(0, ([double]$_.BytesReceivedPersec - $first[$name].rx))
        $tx = [Math]::Max(0, ([double]$_.BytesSentPersec - $first[$name].tx))
        $seconds = $intervalMs / 1000.0
        $adapters += @{
          name = $name
          up = [Math]::Round($tx / $seconds, 0)     # 上传 B/s
          down = [Math]::Round($rx / $seconds, 0)   # 下载 B/s
        }
      }
    }
} catch {}

@{ success = $true; adapters = $adapters } | ConvertTo-Json -Compress -Depth 4
`;

// 丢包检测：解析默认网关（IPv4 优先，回退 IPv6），Win32_PingStatus 发 3 个探测包
const LOSS_SCRIPT = `
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
`;

module.exports = {
  adapters() { return ADAPTERS_SCRIPT; },
  sample() { return SAMPLE_SCRIPT; },
  loss() { return LOSS_SCRIPT; }
};
