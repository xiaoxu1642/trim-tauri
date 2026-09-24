# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/maintenance-scripts.js → run("tf_net_nic")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统维护任务：网卡高级属性（低延迟）（需管理员）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ---- Trim 诊断四元组 (P1-11) ----
function Write-TFDiag {
  param([string]$Stage, [string]$Mutation, [string]$Detail)
  try {
    $native = 0
    try { $native = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } catch { }
    if ($native -eq 0 -and $null -ne $LASTEXITCODE) { $native = $LASTEXITCODE }
    $key = $Stage + '|' + $Mutation + '|' + $Detail
    $digest = '{0:X8}' -f [Math]::Abs($key.GetHashCode())
    $o = [ordered]@{
      failure_stage = $Stage
      mutation_state = $Mutation
      diagnostic_digest = $digest
      native_error_code = [int64]$native
      detail = [string]$Detail
    }
    Write-Output ('@@DIAG@@' + ($o | ConvertTo-Json -Compress))
  } catch { }
}
trap {
  Write-TFDiag -Stage 'script' -Mutation 'unknown' -Detail $_.Exception.Message
  continue
}

Write-Output ('· 遍历网卡 Class 写入低延迟 SZ 参数')
$___eap = $ErrorActionPreference
try {
  $ErrorActionPreference = 'Stop'
$root = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
$sz = @{
  "AutoPowerSaveModeEnabled"="0"; "AutoDisableGigabit"="0"; "AdvancedEEE"="0"; "DisableDelayedPowerUp"="2";
  "*EEE"="0"; "EEE"="0"; "EnablePME"="0"; "EEELinkAdvertisement"="0"; "EnableGreenEthernet"="0";
  "EnableSavePowerNow"="0"; "EnablePowerManagement"="0"; "EnableDynamicPowerGating"="0";
  "EnableConnectedPowerGating"="0"; "EnableWakeOnLan"="0"; "GigaLite"="0"; "NicAutoPowerSaver"="2";
  "PowerDownPll"="0"; "PowerSavingMode"="0"; "ReduceSpeedOnPowerDown"="0"; "SmartPowerDownEnable"="0";
  "S5NicKeepOverrideMacAddrV2"="0"; "S5WakeOnLan"="0"; "ULPMode"="0"; "WakeOnDisconnect"="0";
  "*WakeOnMagicPacket"="0"; "*WakeOnPattern"="0"; "WakeOnLink"="0"; "WolShutdownLinkSpeed"="2";
  "JumboPacket"="1514"; "TransmitBuffers"="4096"; "ReceiveBuffers"="512";
  "IPChecksumOffloadIPv4"="0"; "LsoV1IPv4"="0"; "LsoV2IPv4"="0"; "PMARPOffload"="0";
  "PMNSOffload"="0"; "TCPChecksumOffloadIPv4"="0";
  "UDPChecksumOffloadIPv4"="0";
  "RSS"="1"; "*NumRssQueues"="2"; "RSSProfile"="3"; "*FlowControl"="0"; "FlowControlCap"="0";
  "TxIntDelay"="0"; "TxAbsIntDelay"="0"; "RxIntDelay"="0"; "RxAbsIntDelay"="0";
  "FatChannelIntolerant"="0"; "*InterruptModeration"="0"
}
Get-ChildItem $root -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "^\d{4}$" } | ForEach-Object {
  $k = $_.PSPath
  foreach ($n in $sz.Keys) { New-ItemProperty -Path $k -Name $n -Value $sz[$n] -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null }
}
} catch {
  Write-TFDiag -Stage 'maint.opt.pwsh' -Mutation 'partial' -Detail $_.Exception.Message
} finally {
  $ErrorActionPreference = $___eap
}
Write-Output '@@RESULT@@ok'
