// 磁盘基准测试：顺序读写 + 真实 4K 随机读写 / IOPS / 延迟
// 在测试路径（默认 Downloads）创建测试文件，完成后立即删除。
// 各阶段均为限时循环：顺序写/读 = duration 秒，4K 随机读/写 = duration/2 秒，
// 总时长约 3×duration（4s→12s、8s→24s、16s→48s），确保用户选择的时长真实生效。
// 进度通过 stdout 输出 "__PROG__{json}" 行，由主进程转发给渲染进程展示。
const DISKBENCH_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$options = '__OPTIONS_JSON__' | ConvertFrom-Json
$root = [string]$options.path
if (-not (Test-Path -LiteralPath $root)) { throw '测试磁盘路径不存在' }
# 测试文件存放在测试路径下的专用子目录，测试完毕后删除
$tempDir = Join-Path $root 'Trim-DiskBench'
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$block = [Math]::Max(4096, [int]$options.blockSize)
# 时长仅允许 4/8/16 秒，异常值回落 8 秒
$duration = [double]$options.duration
if (($duration -ne 4.0) -and ($duration -ne 8.0) -and ($duration -ne 16.0)) { $duration = 8.0 }
$duration = [Math]::Max(4.0, [Math]::Min(16.0, $duration))
$buffer = New-Object byte[] $block
(New-Object System.Random).NextBytes($buffer)

# ---------- 进度上报（阶段权重：写32 读32 随机读18 随机写18） ----------
$script:lastPct = -1
function Report-Progress([string]$phase, [double]$frac) {
  $starts = @{ seqwrite = 0.0;  seqread = 32.0; randread = 64.0; randwrite = 82.0 }
  $weights = @{ seqwrite = 32.0; seqread = 32.0; randread = 18.0; randwrite = 18.0 }
  $f = $frac; if ($f -lt 0.0) { $f = 0.0 }; if ($f -gt 1.0) { $f = 1.0 }
  $pct = [int][Math]::Round($starts[$phase] + $weights[$phase] * $f)
  if ($pct -gt 100) { $pct = 100 }
  if ($pct -ne $script:lastPct) {
    $script:lastPct = $pct
    $json = ConvertTo-Json -Compress -InputObject @{ phase = $phase; percent = $pct }
    [Console]::WriteLine(('__PROG__' + $json))
  }
}

# ---------- 顺序写（限时 duration 秒，256MB 窗口内循环覆盖写入） ----------
$file = Join-Path $tempDir ('bench_seq_' + [guid]::NewGuid().ToString('N') + '.dat')
$blocksPerWindow = [Math]::Max(1, [int]((256MB) / $block))
$stream = [IO.File]::Open($file, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
$stream.SetLength([long]$blocksPerWindow * $block)
$writeBytes = [long]0
$wrSw = [Diagnostics.Stopwatch]::StartNew()
$wrIndex = 0
while ($wrSw.Elapsed.TotalSeconds -lt $duration) {
  $stream.Write($buffer, 0, $buffer.Length)
  $writeBytes += $buffer.Length
  $wrIndex++
  if ($wrIndex -ge $blocksPerWindow) { $stream.Flush($false); $stream.Position = 0; $wrIndex = 0 }
  if (($wrIndex % 64) -eq 0) { Report-Progress 'seqwrite' ($wrSw.Elapsed.TotalSeconds / $duration) }
}
$wrSw.Stop()
$stream.Flush($true); $stream.Dispose()
$writeSec = [Math]::Max($wrSw.Elapsed.TotalSeconds, 0.001)
$sequentialWrite = ($writeBytes / 1MB) / $writeSec

# ---------- 顺序读（限时 duration 秒，文件内循环读取） ----------
$readBytesAll = [long]0
$stream = [IO.File]::OpenRead($file)
$rdSw = [Diagnostics.Stopwatch]::StartNew()
$rdIndex = 0
while ($rdSw.Elapsed.TotalSeconds -lt $duration) {
  $n = $stream.Read($buffer, 0, $buffer.Length)
  if ($n -le 0) { $stream.Position = 0; continue }
  $readBytesAll += $n
  $rdIndex++
  if (($rdIndex % 128) -eq 0) { Report-Progress 'seqread' ($rdSw.Elapsed.TotalSeconds / $duration) }
}
$rdSw.Stop()
$stream.Dispose()
$readSec = [Math]::Max($rdSw.Elapsed.TotalSeconds, 0.001)
$sequentialRead = ($readBytesAll / 1MB) / $readSec

# ---------- 真实 4K 随机读（限时 duration/2 秒，IOPS / 延迟） ----------
$rndFile = Join-Path $tempDir ('bench_rand_' + [guid]::NewGuid().ToString('N') + '.dat')
$rndSize = 128MB
$rBuf = New-Object byte[] (256KB)
(New-Object System.Random).NextBytes($rBuf)
$rs = [IO.File]::Open($rndFile, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
$rs.Write($rBuf, 0, $rBuf.Length)
# 扩展到目标大小
$pos = $rs.Length
$chunk = New-Object byte[] (1MB)
while ($pos -lt $rndSize) {
  $writeLen = [Math]::Min($chunk.Length, [int]($rndSize - $pos))
  $rs.Write($chunk, 0, $writeLen)
  $pos += $writeLen
}
$rs.Flush(($true)); $rs.Dispose()

$rstream = [IO.File]::Open($rndFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
$rnd = New-Object System.Random
$ioSize = 4096
$randBuf = New-Object byte[] $ioSize
$rngMax = [Math]::Max(1, [int]($rndSize / $ioSize) - 1)
$rrSec = $duration / 2.0
$latList = New-Object System.Collections.ArrayList
$rngSw = [Diagnostics.Stopwatch]::StartNew()
$rngDoneOps = [long]0
$rrIndex = 0
while ($rngSw.Elapsed.TotalSeconds -lt $rrSec) {
  $idx = $rnd.Next(0, $rngMax)
  $offset = [long]$idx * $ioSize
  $lSw = [Diagnostics.Stopwatch]::StartNew()
  $rstream.Position = $offset
  $readCount = $rstream.Read($randBuf, 0, $ioSize)
  $lSw.Stop()
  if ($readCount -gt 0) {
    [void]$latList.Add($lSw.Elapsed.TotalMilliseconds)
    $rngDoneOps++
  }
  $rrIndex++
  if (($rrIndex % 256) -eq 0) { Report-Progress 'randread' ($rngSw.Elapsed.TotalSeconds / $rrSec) }
}
$rngSw.Stop()
$randomReadOps = $rngDoneOps
$randomReadMBps = ($randomReadOps * $ioSize / 1MB) / [Math]::Max($rngSw.Elapsed.TotalSeconds, 0.001)
$iops = [int]($randomReadOps / [Math]::Max($rngSw.Elapsed.TotalSeconds, 0.001))
$latSum = 0.0; foreach ($v in $latList) { $latSum += $v }
$latencyAvg = $latSum / [Math]::Max($latList.Count, 1)

# 清理随机文件
$rstream.Dispose(); Remove-Item -LiteralPath $rndFile -Force -ErrorAction SilentlyContinue

# ---------- 真实 4K 随机写（限时 duration/2 秒，单块覆盖写，Q1） ----------
$rwStream = [IO.File]::Open($file, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
$rwSize = [Math]::Min($rwStream.Length, 64MB)  # 随机写覆盖范围
$rwMax = [Math]::Max(1, [int]($rwSize / $ioSize) - 1)
$wrTargetSec = $duration / 2.0
$wr2Sw = [Diagnostics.Stopwatch]::StartNew()
$wrOps = [long]0
$wb = New-Object byte[] $ioSize
(New-Object System.Random).NextBytes($wb)
$flushAcc = 0
$rwIndex = 0
while ($wr2Sw.Elapsed.TotalSeconds -lt $wrTargetSec) {
  $idx = $rnd.Next(0, $rwMax)
  $rwStream.Position = [long]$idx * $ioSize
  $rwStream.Write($wb, 0, $ioSize)
  $wrOps++
  $flushAcc += $ioSize
  if ($flushAcc -ge 8MB) { $rwStream.Flush($false); $flushAcc = 0 }
  $rwIndex++
  if (($rwIndex % 256) -eq 0) { Report-Progress 'randwrite' ($wr2Sw.Elapsed.TotalSeconds / $wrTargetSec) }
}
$wr2Sw.Stop()
if ($flushAcc -gt 0) { $rwStream.Flush($false) }
$rwStream.Dispose()
$randomWriteMBps = ($wrOps * $ioSize / 1MB) / [Math]::Max($wr2Sw.Elapsed.TotalSeconds, 0.001)

# 清理顺序文件与临时目录
Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
if (-not (Get-ChildItem -LiteralPath $tempDir -ErrorAction SilentlyContinue)) {
  Remove-Item -LiteralPath $tempDir -Force -ErrorAction SilentlyContinue
}

[pscustomobject]@{
  sequentialRead = [math]::Round($sequentialRead, 1)
  sequentialWrite = [math]::Round($sequentialWrite, 1)
  randomRead = [math]::Round($randomReadMBps, 1)
  randomWrite = [math]::Round($randomWriteMBps, 1)
  iops = $iops
  latency = [math]::Round($latencyAvg, 3)
  blockSize = $block
  # v3.7.0 议题四：以下两项仅作结果标签回写，不参与 I/O —— 四个测试循环均为同步单流读写，
  # 主进程传入的是常量 1/1。真实 QD 与线程数调节尚未实现。
  queueDepth = [int]$options.queueDepth
  threads = [int]$options.threads
  measured = $true
} | ConvertTo-Json -Compress
`;

module.exports = {
  run(options) {
    const json = JSON.stringify(options || {});
    return DISKBENCH_SCRIPT.replace('__OPTIONS_JSON__', json.replace(/'/g, "''"));
  }
};
