# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/netspeed-scripts.js → ping()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：网络延迟/抖动探测（只读）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

# 启动一个本地 TCP 监听器用于回环测速
$port = 19999
$listener = $null
try {
  $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
  $listener.Start()
} catch {
  # 端口占用也算正常
}

# 使用 Test-Connection 测试 127.0.0.1 延迟
$pingResults = @()
for ($i = 0; $i -lt 10; $i++) {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect([System.Net.IPAddress]::Loopback, $port, $null, $null)
    $success = $iar.AsyncWaitHandle.WaitOne(2000)
    $sw.Stop()
    if ($success) {
      $client.EndConnect($iar)
      $client.Close()
      $pingResults += $sw.Elapsed.TotalMilliseconds
    } else {
      $client.Close()
    }
  } catch {}
  Start-Sleep -Milliseconds 100
}

if ($listener) { $listener.Stop() }

if ($pingResults.Count -gt 0) {
  $avg = ($pingResults | Measure-Object -Average).Average
  $min = ($pingResults | Measure-Object -Minimum).Minimum
  $max = ($pingResults | Measure-Object -Maximum).Maximum
  $sorted = $pingResults | Sort-Object
  $jitter = 0
  for ($i = 1; $i -lt $sorted.Count; $i++) {
    $jitter += [Math]::Abs($sorted[$i] - $sorted[$i-1])
  }
  if ($sorted.Count -gt 1) { $jitter = $jitter / ($sorted.Count - 1) }

  @{
    success = $true
    avg = [Math]::Round($avg, 2)
    min = [Math]::Round($min, 2)
    max = [Math]::Round($max, 2)
    jitter = [Math]::Round($jitter, 2)
    samples = $pingResults
  } | ConvertTo-Json -Compress
} else {
  @{ success = $false; message = '无法建立本地回环连接' } | ConvertTo-Json -Compress
}
