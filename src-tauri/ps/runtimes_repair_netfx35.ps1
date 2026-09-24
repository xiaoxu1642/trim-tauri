# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/runtimes-scripts.js → repair("netfx35", "")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：启用 .NET Framework 3.5（DISM，不消费安装包）
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

Write-Output '正在启用 .NET Framework 3.5（需要联网从 Windows Update 获取组件）...'
$result = Start-Process -FilePath 'dism.exe' -ArgumentList '/Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart' -Wait -PassThru -WindowStyle Hidden
Write-Output ('DISM 退出码: ' + $result.ExitCode)
if ($result.ExitCode -eq 0) {
  Write-Output '@@RESULT@@ok'
} elseif ($result.ExitCode -eq 3010) {
  Write-Output '启用成功，需重启电脑后完全生效'
  Write-Output '@@RESULT@@ok'
} else {
  Write-Output '启用失败。常见原因：Windows Update 不可用或被策略限制。'
  Write-Output '人工指引：挂载与系统版本一致的 Windows 安装镜像后执行'
  Write-Output 'DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:<镜像盘符>\sources\sxs'
  Write-Output '@@RESULT@@warn'
}
