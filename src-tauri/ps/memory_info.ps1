# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/memory-scripts.js → 常量 MEM_INFO_SCRIPT
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：物理内存/页面文件/系统缓存（只读）
# PROVENANCE>>>

$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$os = Get-CimInstance Win32_OperatingSystem
$total = [long]$os.TotalVisibleMemorySize * 1KB
$free = [long]$os.FreePhysicalMemory * 1KB
$used = $total - $free
$load = [int][math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100)
if ($load -lt 0) { $load = 0 }
$pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
$pageTotal = 0
if ($pf) { $pageTotal = [long](($pf | Measure-Object -Property AllocatedBaseSize -Sum).Sum * 1MB) }
$pageUsed = 0
if ($pf) { $pageUsed = [long](($pf | Measure-Object -Property CurrentUsage -Sum).Sum * 1MB) }
$cache = 0
$cs = Get-Counter -Counter '\Memory\Cache Bytes' -ErrorAction SilentlyContinue
if ($cs) { $cache = [long]($cs.CounterSamples | Select-Object -First 1 -ExpandProperty CookedValue) }
[ordered]@{
  total = $total
  free = $free
  used = $used
  load = $load
  pageTotal = $pageTotal
  pageUsed = $pageUsed
  cache = $cache
} | ConvertTo-Json -Compress
