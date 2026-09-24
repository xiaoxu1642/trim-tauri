# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/netcheck-scripts.js → repair("enable-adapter", {"name":"__TRIM_ADAPTER_NAME__"})
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：启用被禁用的网卡（修复动作，判需管理员）
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

Write-Output '正在启用被禁用的网卡…'
$names = '__TRIM_ADAPTER_NAME__'.Split(',').Where({ $_ -and $_.Trim() })
Enable-NetAdapter -Name $names -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$ok = @(Get-NetAdapter -Name $names -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }).Count -gt 0
if ($ok) { Write-Output (@{ ok = $true; message = '网卡已启用' } | ConvertTo-Json -Compress) }
else { Write-Output (@{ ok = $false; message = '网卡已执行启用命令但当前未处于 Up 状态' } | ConvertTo-Json -Compress) }
