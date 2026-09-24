# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/maintenance-scripts.js → run("tf_net_tcp")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统维护任务：TCP/IP 全局参数调优（需管理员）
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

Write-Output ('· 网络节流指数最大化')
$___tmpDir = if ($env:TRIM_TMP) { $env:TRIM_TMP } else { Join-Path $env:APPDATA "Trim\tmp" }
if (-not (Test-Path -LiteralPath $___tmpDir)) { New-Item -ItemType Directory -Path $___tmpDir -Force | Out-Null }
$___rf = Join-Path $___tmpDir ("tfmaint_" + [guid]::NewGuid().ToString("N") + ".reg")
$___rc = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"NetworkThrottlingIndex"=dword:ffffffff
"SystemResponsiveness"=dword:0000000a

'@
Set-Content -Path $___rf -Value $___rc -Encoding ASCII
& reg.exe import $___rf *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.reg' -Mutation 'partial' -Detail ('reg import exit=' + $LASTEXITCODE) }
Remove-Item $___rf -Force -ErrorAction SilentlyContinue
Write-Output ('· netsh TCP 全局参数')
$___cmd='netsh int tcp set global autotuninglevel=disabled ecncapability=disabled dca=enabled netdma=enabled rsc=disabled rss=enabled timestamps=disabled initialrto=2000 nonsackrttresiliency=disabled maxsynretransmissions=2'
& $env:ComSpec /c $___cmd *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.cmd' -Mutation 'partial' -Detail ('cmd exit=' + $LASTEXITCODE) }
Write-Output ('· RSS 基准 CPU')
$___cmd='netsh int tcp set global rssbasecpu=1'
& $env:ComSpec /c $___cmd *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.cmd' -Mutation 'partial' -Detail ('cmd exit=' + $LASTEXITCODE) }
Write-Output ('· 关闭安全配置文件')
$___cmd='netsh int tcp set security profiles=disabled'
& $env:ComSpec /c $___cmd *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.cmd' -Mutation 'partial' -Detail ('cmd exit=' + $LASTEXITCODE) }
Write-Output ('· 关闭 MPP')
$___cmd='netsh int tcp set security mpp=disabled'
& $env:ComSpec /c $___cmd *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.cmd' -Mutation 'partial' -Detail ('cmd exit=' + $LASTEXITCODE) }
Write-Output ('· 关闭缩放启发式')
$___cmd='netsh int tcp set heuristics disabled'
& $env:ComSpec /c $___cmd *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.cmd' -Mutation 'partial' -Detail ('cmd exit=' + $LASTEXITCODE) }
Write-Output ('· ARP 邻居缓存 4096')
$___cmd='netsh int ip set global neighborcachelimit=4096'
& $env:ComSpec /c $___cmd *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.cmd' -Mutation 'partial' -Detail ('cmd exit=' + $LASTEXITCODE) }
Write-Output ('· 启用 CTCP')
$___cmd='netsh int tcp set supplemental Internet congestionprovider=ctcp'
& $env:ComSpec /c $___cmd *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.cmd' -Mutation 'partial' -Detail ('cmd exit=' + $LASTEXITCODE) }
Write-Output ('· 关闭任务卸载')
$___cmd='netsh int ip set global taskoffload=disabled'
& $env:ComSpec /c $___cmd *> $null
if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.cmd' -Mutation 'partial' -Detail ('cmd exit=' + $LASTEXITCODE) }
Write-Output ('· 所有网卡 MTU 设为 1500')
$___eap = $ErrorActionPreference
try {
  $ErrorActionPreference = 'Stop'
Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object { netsh interface ipv4 set subinterface "$($_.Name)" mtu=1500 store=persistent *> $null }
} catch {
  Write-TFDiag -Stage 'maint.opt.pwsh' -Mutation 'partial' -Detail $_.Exception.Message
} finally {
  $ErrorActionPreference = $___eap
}
Write-Output '@@RESULT@@ok'
