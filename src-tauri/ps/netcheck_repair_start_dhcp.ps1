# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/netcheck-scripts.js → repair("start-dhcp", {})
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：启动 DHCP 服务并设为自动（修复动作，判需管理员）
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

Write-Output '正在启动 DHCP 服务并设为自动…'
Set-Service -Name Dhcp -StartupType Automatic -ErrorAction Stop
Start-Service -Name Dhcp -ErrorAction Stop
$st = (Get-Service -Name Dhcp -ErrorAction SilentlyContinue).Status
if ($st -eq 'Running') { Write-Output (@{ ok = $true; message = 'DHCP 服务已启动' } | ConvertTo-Json -Compress) }
else { Write-Output (@{ ok = $false; message = 'DHCP 服务未处于运行态' } | ConvertTo-Json -Compress) }
