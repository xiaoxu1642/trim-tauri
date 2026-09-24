// 设备信息采集脚本。仅读取本机 CIM/WMI 信息，不访问网络。
const DEVICE_INFO_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$gpus = @(Get-CimInstance Win32_VideoController | Where-Object { $_.Name -and $_.Name -notmatch 'Basic Display|Remote Display' })
$board = Get-CimInstance Win32_BaseBoard | Select-Object -First 1
# 芯片组：从主板产品名解析（B650/X670/Z790/B760...）。多数主板型号会带芯片组代号，属真实信息而非推算
$chipsetPattern = 'WRX90|WRX80|TRX50|TRX40|X870|X670|X570|X470|X370|Z890|Z790|Z690|Z590|Z490|Z390|Z370|B860|B760|B660|B560|B460|B360|B250|A620|A520|A320|B650|B550|B450|B350|H970|H810|H770|H710|H670|H610|H570|H510|H410|H310|H270|X299|X99|Q670|W790|W680'
$chipset = if ([string]$board.Product -match $chipsetPattern) { $matches[0] } else { '' }
$disks = @(Get-CimInstance Win32_DiskDrive | Where-Object { $_.Size -gt 0 })
$monitors = @(Get-CimInstance Win32_DesktopMonitor | Where-Object { $_.Name })
$memory = @(Get-CimInstance Win32_PhysicalMemory | Where-Object { $_.Capacity -gt 0 })

function Format-GB([object]$Bytes) {
  if (-not $Bytes) { return '' }
  return ('{0:0}GB' -f ([double]$Bytes / 1GB))
}
function Format-SizeGB([object]$Bytes) {
  if (-not $Bytes) { return '' }
  return ('{0:0}GB' -f ([double]$Bytes / 1GB))
}

$gpuItems = @($gpus | ForEach-Object {
  $gpu = $_
  $vramBytes = $null
  # 显存优先读注册表 HardwareInformation.qwMemorySize(QWORD 64 位)：
  # Win32_VideoController.AdapterRAM 是 32 位字段，>4GB 显存会溢出/误报(RTX 5060 8G 常见)
  $classKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}'
  $pnp = [string]$gpu.PNPDeviceID
  Get-ChildItem -LiteralPath $classKey -ErrorAction SilentlyContinue | ForEach-Object {
    $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
    if (-not $props) { return }
    $desc = [string]$props.DriverDesc
    $matching = [string]$props.MatchingDeviceId
    $isThis = ($desc -and $gpu.Name -and $desc.Trim() -eq $gpu.Name.Trim())
    if (-not $isThis -and $matching -and $pnp) {
      $pattern = '^' + [regex]::Escape($matching).Replace('\*', '.*').Replace('\?', '.')
      $isThis = $pnp -match $pattern
    }
    if ($isThis) {
      $qw = $props.'HardwareInformation.qwMemorySize'
      if ($qw -and [long]$qw -gt 0) { $vramBytes = [long]$qw }
    }
  }
  if (-not $vramBytes) { $vramBytes = [long]$gpu.AdapterRAM }
  [pscustomobject]@{ name = $gpu.Name; memory = (Format-GB $vramBytes); driver = $gpu.DriverVersion }
})
$diskItems = @($disks | ForEach-Object {
  $media = if ($_.Model -match '(?i)SSD|NVMe|固态') { 'SSD' } else { '硬盘' }
  [pscustomobject]@{ name = $_.Model; capacity = (Format-SizeGB $_.Size); media = $media }
})
$memoryItems = @($memory | ForEach-Object {
  [pscustomobject]@{ manufacturer = $_.Manufacturer; part = $_.PartNumber; capacity = (Format-GB $_.Capacity); speed = ([int]($_.ConfiguredClockSpeed -as [int])); locator = $_.DeviceLocator }
})
$monitorItems = @()
# 显示器：优先 WmiMonitorID 读取 EDID 友好名称（SANC G41 等），回退 Win32_DesktopMonitor
$monName = ''
try {
  $wmiMon = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue) | Select-Object -First 1
  if ($wmiMon -and $wmiMon.UserFriendlyName) {
    $bytes = @($wmiMon.UserFriendlyName | Where-Object { $_ -ne 0 })
    if ($bytes.Count -gt 0) { $monName = [System.Text.Encoding]::ASCII.GetString([byte[]]$bytes).Trim() }
  }
} catch {}
if (-not $monName) {
  $dm = Get-CimInstance Win32_DesktopMonitor -ErrorAction SilentlyContinue | Where-Object { $_.Name -and $_.Name -notmatch '(?i)generic' } | Select-Object -First 1
  if ($dm) { $monName = $dm.Name }
}
# 分辨率/刷新率：取当前有显示输出的显卡设置
$vga = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Where-Object { $_.CurrentHorizontalResolution -gt 0 } | Select-Object -First 1
$resW = $null; $resH = $null; $refresh = $null
if ($vga) { $resW = $vga.CurrentHorizontalResolution; $resH = $vga.CurrentVerticalResolution; $refresh = $vga.CurrentRefreshRate }
# 屏幕尺寸：从 EDID 物理尺寸(WmiMonitorBasicDisplayParams)计算斜边对角线(英寸)
$sizeInch = ''
try {
  $bmp = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($bmp -and [int]$bmp.MaxHorizontalImageSize -gt 0 -and [int]$bmp.MaxVerticalImageSize -gt 0) {
    $h = [double]$bmp.MaxHorizontalImageSize
    $v = [double]$bmp.MaxVerticalImageSize
    $sizeInch = ('{0:0.#}英寸' -f ([math]::Sqrt($h * $h + $v * $v) / 2.54))
  }
} catch {}
if ($monName) {
  $monitorItems = @([pscustomobject]@{ name = $monName; width = $resW; height = $resH; refresh = $refresh; size = $sizeInch })
}

[pscustomobject]@{
  system = [pscustomobject]@{ caption = $os.Caption; architecture = $os.OSArchitecture; version = $os.Version; build = $os.BuildNumber }
  processor = [pscustomobject]@{ name = $cpu.Name.Trim(); cores = $cpu.NumberOfCores; threads = $cpu.NumberOfLogicalProcessors; process = '' }
  graphics = $gpuItems
  motherboard = [pscustomobject]@{ product = $board.Product; manufacturer = $board.Manufacturer; chipset = $chipset }
  disks = $diskItems
  monitors = $monitorItems
  memory = $memoryItems
} | ConvertTo-Json -Depth 8 -Compress
`;

module.exports = { scan() { return DEVICE_INFO_SCRIPT; } };
