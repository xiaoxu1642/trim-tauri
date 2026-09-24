# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/netcheck-scripts.js → repair("reset-winhttp", {})
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：重置 WinHTTP 代理（修复动作，判需管理员）
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

Write-Output '正在重置 WinHTTP 代理…'
$out = & netsh.exe winhttp reset proxy 2>&1 | Out-String
Write-Output ($out.Trim())
# F1（2026-09-15）：原为无条件 ok=true（netsh 结果从未判定）。改为按 netsh 退出码判定。
if ($LASTEXITCODE -eq 0) { Write-Output (@{ ok = $true; message = 'WinHTTP 代理已重置（部分服务需重启后生效）' } | ConvertTo-Json -Compress) }
else { Write-Output (@{ ok = $false; message = ('WinHTTP 重置失败 (exit=' + $LASTEXITCODE + ')') } | ConvertTo-Json -Compress) }
