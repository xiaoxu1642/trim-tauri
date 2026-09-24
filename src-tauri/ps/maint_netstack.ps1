# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/maintenance-scripts.js → run("netstack")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统维护任务：重置网络栈 (Winsock/IP)（需管理员）
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


Write-Output '正在重置 Winsock…'
& netsh.exe winsock reset 2>&1 | ForEach-Object { Write-Output $_ }
$ok1 = $LASTEXITCODE
Write-Output '正在重置 TCP/IP…'
& netsh.exe int ip reset 2>&1 | ForEach-Object { Write-Output $_ }
$ok2 = $LASTEXITCODE
& ipconfig.exe /flushdns 2>&1 | Out-Null
# F1（2026-09-15）：原为无条件 @@RESULT@@ok；改为按两条 netsh 的退出码判定。
if ($ok1 -eq 0 -and $ok2 -eq 0) { Write-Output '网络栈已重置（部分改动需重启电脑后完全生效）'; Write-Output '@@RESULT@@ok' }
else { Write-TFDiag -Stage 'maint.netstack' -Mutation 'partial' -Detail ('winsock=' + $ok1 + ' ip=' + $ok2); Write-Output '@@RESULT@@warn' }

