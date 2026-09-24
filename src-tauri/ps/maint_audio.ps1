# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/maintenance-scripts.js → run("audio")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统维护任务：重启音频服务（需管理员）
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


Restart-Service -Name Audiosrv -Force -ErrorAction SilentlyContinue
Restart-Service -Name AudioEndpointBuilder -Force -ErrorAction SilentlyContinue
$ok = (Get-Service Audiosrv -ErrorAction SilentlyContinue).Status -eq 'Running'
if ($ok) { Write-Output '音频服务已重启' ; Write-Output '@@RESULT@@ok' }
else { Write-TFDiag -Stage 'maint.audio' -Mutation 'partial' -Detail 'Audiosrv 未处于运行态'; Write-Output '@@RESULT@@warn' }

