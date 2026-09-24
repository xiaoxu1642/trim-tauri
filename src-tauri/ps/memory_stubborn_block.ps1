# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/memory-scripts.js → 常量 STUBBORN_BLOCK_SCRIPT
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：顽固软件自启阻断（改服务/删计划任务）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# M-1（2026-09-15）：拒绝静默空吞——每个操作回读校验，成功/失败分开记账，
# 未提权或单项失败不再无条件报绿。内存清理单次会话内最多弹 3 次错误。
$changedServices = [System.Collections.Generic.List[string]]::new()
$failServices = [System.Collections.Generic.List[string]]::new()
$failed = 0
function Add-SvcResult($name, $ok) {
  if ($ok) { $script:changedServices.Add($name) } else { $script:failServices.Add($name); $script:failed++ }
}
$services = @('Edrservice','GameViewerService','MuMuRemoteService','PCManager Service Store')
foreach ($svc in $services) {
  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if (-not $s) { continue }
  try {
    if ($s.Status -eq 'Running') { Stop-Service -Name $svc -Force -ErrorAction Stop }
    Set-Service -Name $svc -StartupType Manual -ErrorAction Stop
    $after = Get-Service -Name $svc -ErrorAction SilentlyContinue
    Add-SvcResult $svc ($null -ne $after -and $after.StartType -eq 'Manual')
  } catch { Add-SvcResult $svc $false }
}
$wc = Get-Service -Name 'wpscloudsvr' -ErrorAction SilentlyContinue
if ($wc) {
  try {
    if ($wc.Status -eq 'Running') { Stop-Service -Name 'wpscloudsvr' -Force -ErrorAction Stop }
    $wcAfter = Get-Service -Name 'wpscloudsvr' -ErrorAction SilentlyContinue
    Add-SvcResult 'wpscloudsvr' ($null -ne $wcAfter -and $wcAfter.Status -eq 'Stopped')
  } catch { Add-SvcResult 'wpscloudsvr' $false }
}
$changedTasks = [System.Collections.Generic.List[string]]::new()
$failTasks = [System.Collections.Generic.List[string]]::new()
# 审查 M-6（2026-09-14）：Unregister-ScheduledTask 不可逆，删除前先 Export-ScheduledTask
# 到 %APPDATA%Trimackup	asks<name>.xml，与 startup/contextmenu 的「删除前备份」纪律对齐。
$taskBackupDir = Join-Path $env:APPDATA 'Trimackup	asks'
foreach ($taskName in @('WpsUpdateTask_CHENG','WpsUpdateLogonTask_CHENG')) {
  if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { continue }
  try {
    if (-not (Test-Path $taskBackupDir)) { New-Item -Path $taskBackupDir -ItemType Directory -Force | Out-Null }
    Export-ScheduledTask -TaskName $taskName | Out-File -FilePath (Join-Path $taskBackupDir ($taskName + '.xml')) -Encoding UTF8 -ErrorAction Stop
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
      $failTasks.Add($taskName); $script:failed++
    } else { $changedTasks.Add($taskName) }
  } catch { $failTasks.Add($taskName); $script:failed++ }
}
$wpsKey = 'HKCU:\Software\Kingsoft\Office\6.0\Common\updateinfo'
if (Test-Path $wpsKey) {
  try { Set-ItemProperty -Path $wpsKey -Name 'UpdateMode' -Value 'close' -ErrorAction Stop } catch { $script:failed++ }
}
[pscustomobject]@{
  services = @($changedServices); tasks = @($changedTasks)
  failedServices = @($failServices); failedTasks = @($failTasks); failedCount = $script:failed
} | ConvertTo-Json -Compress
