# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/sysdisk-scripts.js → scan()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统盘介质类型探测（只读）
# PROVENANCE>>>

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
