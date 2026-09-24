# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/maintenance-scripts.js → run("tf_net_lanman")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统维护任务：LanmanServer 会话参数（需管理员）
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

Write-Output ('· LanmanServer Parameters')
$___tmpDir = if ($env:TRIM_TMP) { $env:TRIM_TMP } else { Join-Path $env:APPDATA "Trim\tmp" }
if (-not (Test-Path -LiteralPath $___tmpDir)) { New-Item -ItemType Directory -Path $___tmpDir -Force | Out-Null }
$___rf = Join-Path $___tmpDir ("tfmaint_" + [guid]::NewGuid().ToString("N") + ".reg")
$___rc = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters]
"autodisconnect"=dword:ffffffff
"Size"=dword:00000003
"EnableOplocks"=dword:00000000
"IRPStackSize"=dword:00000014
"SharingViolationDelay"=dword:00000000
"SharingViolationRetries"=dword:00000000

'@
Set-Content -Path $___rf -Value $___rc -Encoding ASCII
& reg.exe import $___rf *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.reg' -Mutation 'partial' -Detail ('reg import exit=' + $LASTEXITCODE) }
Remove-Item $___rf -Force -ErrorAction SilentlyContinue
Write-Output '@@RESULT@@ok'
