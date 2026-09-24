# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/maintenance-scripts.js → run("net_disable_netbios")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统维护任务：NetBIOS 旧式解析排查（需管理员）
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

Write-Output ('· 遍历网卡关闭 NetBIOS')
$___eap = $ErrorActionPreference
try {
  $ErrorActionPreference = 'Stop'
$base = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
if (Test-Path $base) { Get-ChildItem $base | ForEach-Object { New-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -PropertyType DWord -Force | Out-Null } }
} catch {
  Write-TFDiag -Stage 'maint.opt.pwsh' -Mutation 'partial' -Detail $_.Exception.Message
} finally {
  $ErrorActionPreference = $___eap
}
Write-Output '@@RESULT@@ok'
