# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/maintenance-scripts.js → run("store")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统维护任务：重置 Microsoft Store 缓存
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


Write-Output '正在清理 Store 缓存 (wsreset)…'
$p = Start-Process -FilePath 'wsreset.exe' -PassThru
Start-Sleep -Seconds 3
if ($p -and -not $p.HasExited) { Start-Sleep -Seconds 5 }
Write-Output 'Store 缓存清理已触发（完成后商店会自动打开，可手动关闭）'
Write-Output '@@RESULT@@ok'

