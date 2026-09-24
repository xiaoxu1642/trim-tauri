// 本地网络测速 PowerShell 脚本
// 优先使用本地回环 (127.0.0.1) 避免防火墙干扰

const PING_SCRIPT = `
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
`;

const THROUGHPUT_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

# 起本地 TCP 服务，客户端循环发送数据测吞吐
$port = 19999
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
$listener.Start()

$bufferSize = 64 * 1024
$stop = $false
$received = 0
$scriptblock = {
  param($listener, $bufferSize, $stopFlag)
  $client = $listener.AcceptTcpClient()
  $stream = $client.GetStream()
  $buffer = New-Object byte[] $bufferSize
  while (-not $stopFlag.IsSet) {
    try {
      $n = $stream.Read($buffer, 0, $bufferSize)
      if ($n -eq 0) { break }
      $script:received += $n
    } catch { break }
  }
  $client.Close()
}
$stopFlag = [pscustomobject]@{ IsSet = $false }

# 异步接收
$runspace = [runspacefactory]::CreateRunspace()
$runspace.Open()
$runspace.SessionStateProxy.SetVariable('script:received', 0)
$ps = [System.Management.Automation.PowerShell]::Create()
$ps.Runspace = $runspace
$ps.AddScript($scriptblock).AddArgument($listener).AddArgument($bufferSize).AddArgument($stopFlag) | Out-Null
$handle = $ps.BeginInvoke()

# 客户端发送数据
$duration = \${DURATION_PLACEHOLDER}
$client = New-Object System.Net.Sockets.TcpClient
$client.Connect([System.Net.IPAddress]::Loopback, $port)
$stream = $client.GetStream()
$payload = New-Object byte[] $bufferSize
(New-Object Random).NextBytes($payload)

$startTime = Get-Date
$totalSent = 0
$elapsed = 0
$samples = @()

try {
  while ($elapsed -lt $duration) {
    $stream.Write($payload, 0, $payload.Length)
    $totalSent += $payload.Length
    $elapsed = ((Get-Date) - $startTime).TotalSeconds

    # 每 0.2 秒记录一次瞬时速度
    if (($samples.Count -eq 0) -or (($elapsed * 5) -ge $samples.Count)) {
      $instBps = $totalSent / [Math]::Max($elapsed, 0.001)
      $samples += @{ time = [Math]::Round($elapsed, 2); speed = [Math]::Round($instBps / 1MB, 2) }
    }
  }
} catch {}

$stream.Close()
$client.Close()
$stopFlag.IsSet = $true
$ps.EndInvoke($handle)
$listener.Stop()
$ps.Dispose()
$runspace.Close()

$actualDuration = [Math]::Max($elapsed, 0.001)
$avgBps = $totalSent / $actualDuration
$downloadMbps = [Math]::Round($avgBps * 8 / 1MB, 2)
$uploadMbps = $downloadMbps  # 回环测速上下行一致

# 抖动计算
$speeds = $samples | ForEach-Object { $_.speed }
$jitter = 0
for ($i = 1; $i -lt $speeds.Count; $i++) {
  $jitter += [Math]::Abs($speeds[$i] - $speeds[$i-1])
}
if ($speeds.Count -gt 1) { $jitter = $jitter / ($speeds.Count - 1) }

@{
  success = $true
  duration = [Math]::Round($actualDuration, 2)
  downloadMbps = $downloadMbps
  uploadMbps = $uploadMbps
  totalBytes = $totalSent
  jitter = [Math]::Round($jitter, 2)
  samples = $samples
} | ConvertTo-Json -Compress -Depth 3
`;

module.exports = {
  ping() {
    return PING_SCRIPT;
  },
  throughput(duration = 5) {
    return THROUGHPUT_SCRIPT.replace('\u0024{DURATION_PLACEHOLDER}', () => String(duration));
  }
};
