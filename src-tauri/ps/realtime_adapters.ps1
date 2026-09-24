# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/realtime-scripts.js → adapters()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：物理网卡枚举（只读）
# PROVENANCE>>>

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
