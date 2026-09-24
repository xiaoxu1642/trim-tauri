# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/maintenance-scripts.js → run("wu")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：系统维护任务：重置 Windows Update 组件（需管理员）
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


$svcs = @('wuauserv','bits','cryptsvc','appidsvc','msiserver')
foreach ($s in $svcs) { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue }
Write-Output '已停止更新相关服务'
Start-Sleep -Seconds 2
$sd = Join-Path $env:WINDIR 'SoftwareDistribution'
$cr = Join-Path $env:WINDIR 'System32\catroot2'
$reset = 0; $skip = 0
  # MA-3（2026-09-15 v7）：清扫上一轮遗留的 *.old_* 缓存备份（各保留最近 1 个供回退）。
  # 原实现每次重置都新增一个数百 MB 目录且永不清理，累积可达 GB 级。放在本次改名前执行，
  # 本轮新备份不受影响。
  # 复核 N2（删除红线，2026-09-16）：不再在 PS 内裸 Remove-Item，改为逐行输出 @@WU_OLD_BAK@@<路径>，
  # 由主进程 trashOrUnlink（回收站优先）执行；Where-Object 过滤空值，规避 @($null).Count=1 判空陷阱。
  foreach ($base in @($sd,$cr)) {
    $stale = @((Get-ChildItem -LiteralPath (Split-Path -Parent $base) -Filter ((Split-Path -Leaf $base) + '.old_*') -Directory -ErrorAction SilentlyContinue) | Where-Object { $_ } | Sort-Object LastWriteTime -Descending | Select-Object -Skip 1)
    foreach ($b in $stale) { Write-Output ('@@WU_OLD_BAK@@' + $b.FullName) }
  }
foreach ($d in @($sd,$cr)) {
  if (Test-Path -LiteralPath $d) {
    $bak = $d + '.old_' + (Get-Date -Format 'yyyyMMddHHmmss')
    try { Rename-Item -LiteralPath $d -NewName (Split-Path $bak -Leaf) -ErrorAction Stop; $reset++; Write-Output ('已重置缓存目录: ' + $d) }
    catch { $skip++; Write-TFDiag -Stage 'maint.wu' -Mutation 'partial' -Detail ('重命名失败(可能被占用): ' + $d + ' -> ' + $_.Exception.Message); Write-Output ('跳过(占用): ' + $d) }
  }
}
foreach ($s in $svcs) { Start-Service -Name $s -ErrorAction SilentlyContinue }
# F1（2026-09-15）：原为无条件 @@RESULT@@ok。改为回读：wuauserv 必须运行，且没有被占用的
# 缓存目录（skip=0 表示全部目标目录都成功改名）；否则如实报 warn。
$svcOk = (Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status -eq 'Running'
if ($svcOk -and $skip -eq 0) { Write-Output '已重启更新服务'; Write-Output '@@RESULT@@ok' }
else { Write-TFDiag -Stage 'maint.wu' -Mutation 'partial' -Detail ('回读: wuauserv=' + $svcOk + ' reset=' + $reset + ' skip=' + $skip); Write-Output '@@RESULT@@warn' }

