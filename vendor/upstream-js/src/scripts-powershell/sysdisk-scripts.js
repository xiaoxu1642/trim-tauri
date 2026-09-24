// sysdisk-scripts.js - 系统盘介质类型探测（C2，2026-09-14 重复点审查）
// 用途：让「电脑优化中心」与「磁盘清理」按「系统盘是 SSD 还是 HDD」显隐预读相关选项：
//   · SSD  → 隐藏「加快预读能力改善速度」(perf_prefetcher_fast)；Prefetch 清理项保留
//            （SSD 上 Prefetch 收益低，清掉无损失）
//   · HDD  → 隐藏「关闭预读」(prefetch_off) 与磁盘清理的 prefetchFiles
//            （HDD 依赖预读与 Prefetch 缓存，清了反而变慢）
//   · 判定失败(unknown) → 两边都不隐藏，保守处理，绝不因为探测失败而藏掉用户要用的选项
// 判定优先级：Get-PhysicalDisk.MediaType（最准）→ BusType=NVMe → 型号关键字兜底。
// 只读脚本，不改任何设置。
const SYSDISK_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$letter = ($env:SystemDrive).TrimEnd(':')
$media = ''
$bus = ''
$model = ''
$detector = ''
try {
  $pd = Get-Partition -DriveLetter $letter -ErrorAction Stop | Get-Disk -ErrorAction Stop | Get-PhysicalDisk -ErrorAction Stop
  if ($pd) {
    $media = [string]$pd.MediaType
    $bus = [string]$pd.BusType
    $model = [string]$pd.FriendlyName
    if ($media -eq 'SSD' -or $media -eq 'HDD') { $detector = 'PhysicalDisk.MediaType' }
  }
} catch { }
if (-not $detector -and $bus -eq 'NVMe') { $media = 'SSD'; $detector = 'BusType=NVMe' }
if (-not $detector) {
  try {
    $idx = (Get-Partition -DriveLetter $letter -ErrorAction Stop).DiskNumber
    $dd = Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Where-Object { $_.Index -eq $idx } | Select-Object -First 1
    if ($dd) {
      if (-not $model) { $model = [string]$dd.Model }
      if ($model -match '(?i)SSD|NVMe|固态') { $media = 'SSD'; $detector = 'Model 关键字' }
      else { $media = 'HDD'; $detector = 'Model 未见 SSD 关键字（推断）' }
    }
  } catch { }
}
$isSsd = ($media -eq 'SSD')
$known = ($media -eq 'SSD' -or $media -eq 'HDD')
[pscustomobject]@{
  letter = $letter
  media = $media
  busType = $bus
  model = $model
  isSsd = $isSsd
  known = $known
  detector = $detector
} | ConvertTo-Json -Compress
`;

module.exports = { scan() { return SYSDISK_SCRIPT; } };
