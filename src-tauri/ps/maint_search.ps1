# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/maintenance-scripts.js → run("search")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统维护任务：重建搜索索引（需管理员）
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


Stop-Service -Name WSearch -Force -ErrorAction SilentlyContinue
$pf = $env:ProgramData
$idx = Join-Path $pf 'Microsoft\Search\Data\Applications\Windows'
$cleared = $true
if (Test-Path -LiteralPath $idx) {
  Remove-Item -Path (Join-Path $idx '*') -Recurse -Force -ErrorAction SilentlyContinue
  # F1（2026-09-15）：回读索引目录是否真的清空（原先无条件报成功）
  $left = @(Get-ChildItem -LiteralPath $idx -Force -ErrorAction SilentlyContinue).Count
  if ($left -gt 0) { $cleared = $false; Write-TFDiag -Stage 'maint.search' -Mutation 'partial' -Detail ('索引目录仍有残留: ' + $left) }
  else { Write-Output '已清空旧索引数据' }
}
Start-Service -Name WSearch -ErrorAction SilentlyContinue
$svcOk = (Get-Service -Name WSearch -ErrorAction SilentlyContinue).Status -eq 'Running'
if ($svcOk -and $cleared) { Write-Output '搜索服务已重启，索引将在后台重建'; Write-Output '@@RESULT@@ok' }
else { Write-TFDiag -Stage 'maint.search' -Mutation 'partial' -Detail ('回读: WSearch=' + $svcOk + ' cleared=' + $cleared); Write-Output '@@RESULT@@warn' }

