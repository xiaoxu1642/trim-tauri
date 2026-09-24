# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/startup-scripts.js → remove(["__TRIM_ITEMS_JSON__"])
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：删除启动项（哨兵 items）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

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


$backupDir = Join-Path $env:APPDATA 'Trim\startup-backup'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$disabledFile = Join-Path $backupDir 'disabled.json'
$deletedDir = Join-Path $backupDir 'deleted'
New-Item -ItemType Directory -Path $deletedDir -Force | Out-Null

$items = '["__TRIM_ITEMS_JSON__"]' | ConvertFrom-Json
$results = @()
$success = 0
$failed = 0
$fsDelete = @()

$records = @()
if (Test-Path -LiteralPath $disabledFile) {
  try { $records = @(Get-Content -LiteralPath $disabledFile -Raw -Encoding UTF8 | ConvertFrom-Json) }
  catch { $records = @() }
}
$records = @($records | Where-Object { $_ })

foreach ($item in @($items)) {
  $id = [string]$item.id
  $name = [string]$item.name
  $source = [string]$item.source
  $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  try {
    if ($source -eq 'registry') {
      $stdPath = [string]$item.regPath
      $regPath = 'Registry::' + $stdPath
      $vp = [string]$item.valueName
      if (-not (Test-Path -LiteralPath $regPath)) { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '注册表路径不存在' }; continue }
      # 备份整个键到 .reg（安全网）
      $safe = ($name -replace '[^\w\-\u4e00-\u9fa5]', '_')
      $regFile = Join-Path $deletedDir ($stamp + '_reg_' + $safe + '.reg')
      $stdPathEsc = $stdPath -replace 'HKEY_LOCAL_MACHINE', 'HKLM'
      $stdPathEsc = $stdPathEsc -replace 'HKEY_CURRENT_USER', 'HKCU'
      & reg.exe export "$stdPathEsc" "$regFile" /y | Out-Null
      if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $regFile)) {
        $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '注册表备份失败，未执行删除' }; continue
      }
      Remove-ItemProperty -LiteralPath $regPath -Name $vp -ErrorAction Stop
      if ($null -eq (Get-Item -LiteralPath $regPath).GetValue($vp)) {
        $records = @($records | Where-Object { $_.id -ne $id })
        if (@($records).Count -eq 0) { Remove-Item -LiteralPath $disabledFile -Force -ErrorAction SilentlyContinue }
        else { @($records) | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $disabledFile -Encoding UTF8 }
        $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已删除（已备份注册表键）' }
      } else {
        $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '删除未生效（可能需要管理员权限）' }
      }
      continue
    }

    if ($source -eq 'folder') {
      $filePath = [string]$item.filePath
      # 若为已禁用记录，则从备份目录删除；否则备份到 deleted 再删
      # 复核 N1（删除红线，2026-09-16）：文件夹/快捷方式类不再在 PS 内裸 Remove-Item，
      # 备份后回传主进程走 trashOrUnlink（回收站优先）+ 全局删除清单；deferred 结果由主进程回填。
      $rec = @($records | Where-Object { $_.id -eq $id }) | Select-Object -First 1
      if ($rec -and $rec.filePath -and (Test-Path -LiteralPath $rec.filePath) -and -not (Test-Path -LiteralPath $filePath)) {
        $fsDelete += @{ id = $id; name = $name; path = [string]$rec.filePath; kind = 'backup-file' }
        $records = @($records | Where-Object { $_.id -ne $id })
        if (@($records).Count -eq 0) { Remove-Item -LiteralPath $disabledFile -Force -ErrorAction SilentlyContinue }
        else { @($records) | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $disabledFile -Encoding UTF8 }
        $results += @{ id = $id; name = $name; status = 'deferred'; message = '备份文件待主进程回收站删除' }
      } elseif (Test-Path -LiteralPath $filePath) {
        $safe = ($name -replace '[^\w\-\u4e00-\u9fa5]', '_')
        $dest = Join-Path $deletedDir ($stamp + '_folder_' + $safe + [IO.Path]::GetExtension($filePath))
        Copy-Item -LiteralPath $filePath -Destination $dest -Force -ErrorAction Stop
        $fsDelete += @{ id = $id; name = $name; path = $filePath; kind = 'startup-file' }
        $results += @{ id = $id; name = $name; status = 'deferred'; message = '已备份，待主进程回收站删除' }
      } else {
        $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '文件不存在' }
      }
      continue
    }

    if ($source -eq 'task') {
      $taskPath = [string]$item.taskPath
      $taskName = [string]$item.taskName
      if ([string]::IsNullOrWhiteSpace($taskName)) { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '缺少任务名' }; continue }
      $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
      if (-not $task) { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '计划任务不存在' }; continue }
      $safe = ($taskName -replace '[^\w\-\u4e00-\u9fa5]', '_')
      $xmlFile = Join-Path $deletedDir ($stamp + '_task_' + $safe + '.xml')
      Export-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Set-Content -LiteralPath $xmlFile -Encoding UTF8
      if (-not (Test-Path -LiteralPath $xmlFile)) {
        $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '计划任务备份失败，未执行删除' }; continue
      }
      Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
      if (-not (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue)) {
        $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已删除（已导出任务备份）' }
      } else {
        $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '删除未生效（可能需要管理员权限）' }
      }
      continue
    }

    $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '未知来源类型' }
  } catch {
    $failed++
    Write-TFDiag -Stage 'startup.mutate' -Mutation 'rolled_back' -Detail ($id + ' [' + $source + '] -> ' + $_.Exception.Message)
    $results += @{ id = $id; name = $name; status = 'error'; message = $_.Exception.Message }
  }
}

[pscustomobject]@{ success = $success; failed = $failed; results = @($results); fsDelete = @($fsDelete) } | ConvertTo-Json -Depth 6 -Compress
