# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/maintenance-scripts.js → run("tf_net_tcpip")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统维护任务：Tcpip 注册表参数（需管理员）
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

Write-Output ('· Tcpip / ServiceProvider / Winsock / Nagle / DeliveryOptimization')
$___tmpDir = if ($env:TRIM_TMP) { $env:TRIM_TMP } else { Join-Path $env:APPDATA "Trim\tmp" }
if (-not (Test-Path -LiteralPath $___tmpDir)) { New-Item -ItemType Directory -Path $___tmpDir -Force | Out-Null }
$___rf = Join-Path $___tmpDir ("tfmaint_" + [guid]::NewGuid().ToString("N") + ".reg")
$___rc = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"DefaultTTL"=dword:00000040
"Tcp1323Opts"=dword:00000001
"TcpMaxDupAcks"=dword:00000002
"SackOpts"=dword:00000000
"MaxUserPort"=dword:0000fffe
"TcpTimedWaitDelay"=dword:0000001e

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider]
"LocalPriority"=dword:00000004
"HostsPriority"=dword:00000005
"DnsPriority"=dword:00000006
"NetbtPriority"=dword:00000007

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock]
"MinSockAddrLength"=dword:00000010
"MaxSockAddrLength"=dword:00000010

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces]
"TcpAckFrequency"=dword:00000001
"TCPNoDelay"=dword:00000001
"TcpDelAckTicks"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config]
"DODownloadMode"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings]
"DownloadMode"=dword:00000000

'@
Set-Content -Path $___rf -Value $___rc -Encoding ASCII
& reg.exe import $___rf *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.reg' -Mutation 'partial' -Detail ('reg import exit=' + $LASTEXITCODE) }
Remove-Item $___rf -Force -ErrorAction SilentlyContinue
Write-Output '@@RESULT@@ok'
