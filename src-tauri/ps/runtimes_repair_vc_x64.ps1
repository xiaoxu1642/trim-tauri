# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/runtimes-scripts.js → repair("vc-x64", "@@TRIM_INSTALLER_PATH@@")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：静默执行本地安装包：VC++ 2015-2022 x64（哨兵模板：安装包路径）
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

Write-Output '正在安装 VC++ 2015-2022 x64（静默模式，请稍候）...'
$result = Start-Process -FilePath '@@TRIM_INSTALLER_PATH@@' -ArgumentList '/install /quiet /norestart' -Wait -PassThru
Write-Output ('安装程序退出码: ' + $result.ExitCode)
if ($result.ExitCode -eq 0) {
  Write-Output '@@RESULT@@ok'
} elseif ($result.ExitCode -eq 3010) {
  Write-Output '安装成功，需重启电脑后完全生效'
  Write-Output '@@RESULT@@ok'
} elseif ($result.ExitCode -eq 1638) {
  Write-Output '已安装相同或更新版本，无需重复安装'
  Write-Output '@@RESULT@@ok'
} else {
  Write-TFDiag -Stage 'runtimes.install' -Mutation 'partial' -Detail ('exit=' + $result.ExitCode)
  Write-Output ('安装失败，退出码 ' + $result.ExitCode)
  Write-Output '@@RESULT@@warn'
}
