# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/startup-scripts.js → toggle([["__TRIM_ITEMS_JSON__"]], true)
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：启用启动项（哨兵 items，$true 变体）
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
$filesDir = Join-Path $backupDir 'files'
New-Item -ItemType Directory -Path $filesDir -Force | Out-Null

$enable = $true
$items = '[["__TRIM_ITEMS_JSON__"]]' | ConvertFrom-Json
$results = @()
$success = 0
$failed = 0

# 读取已禁用记录
$records = @()
if (Test-Path -LiteralPath $disabledFile) {
  try { $records = @(Get-Content -LiteralPath $disabledFile -Raw -Encoding UTF8 | ConvertFrom-Json) }
  catch { $records = @() }
}
$records = @($records | Where-Object { $_ })

function Save-Records {
  if (@($records).Count -eq 0) {
    Remove-Item -LiteralPath $disabledFile -Force -ErrorAction SilentlyContinue
  } else {
    @($records) | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $disabledFile -Encoding UTF8
  }
}

# ---- v3.7.0 议题二 P1：StartupApproved 读写（与任务管理器同轨）----
# 旧行为：禁用 = Remove-ItemProperty 删掉 Run 值 + 备份进 disabled.json。
# 问题：Windows 自己禁用启动项时保留 Run 值、只写 StartupApproved blob，两边互不可见；
# 且删值属于破坏性动作，卸载重装或 Trim 自身异常时就没有还原依据。
# 新行为：禁用 = 保留 Run 值 + 写 blob 置 bit0；启用 = 清掉 bit0。
# disabled.json 退化为「Trim 自己动过手」的记账（兼容旧版已删值的条目），不再是唯一真相。
function Get-ApprovedKeyPath([string]$hive, [string]$sub) {
  $base = if ($hive -like 'HKLM*') { 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved' }
          else { 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved' }
  return ('Registry::' + $base + '\' + $sub)
}
# 返回 @{ ok = bool; message = string }
function Set-ApprovedBit([string]$keyPath, [string]$valueName, [bool]$disable) {
  try {
    if (-not (Test-Path -LiteralPath $keyPath)) { New-Item -Path $keyPath -Force -ErrorAction Stop | Out-Null }
    $k = Get-Item -LiteralPath $keyPath -ErrorAction Stop
    $cur = $k.GetValue($valueName)
    if ($null -eq $cur -or @($cur).Count -lt 12) {
      $bytes = [byte[]]::new(12)
      if ($null -ne $cur -and @($cur).Count -ge 1) { $bytes[0] = ([byte[]]$cur)[0] }
      else { $bytes[0] = 2 }   # 无记录时按「启用」起手（0x02），再按目标翻转 bit0
    } else {
      $bytes = [byte[]]$cur
    }
    if ($disable) { $bytes[0] = $bytes[0] -bor 1 } else { $bytes[0] = $bytes[0] -band 0xFE }
    New-ItemProperty -LiteralPath $keyPath -Name $valueName -PropertyType Binary -Value $bytes -Force -ErrorAction Stop | Out-Null
    # 写后回读：成功不等于生效（语义同正向执行的回读校验）
    $k2 = Get-Item -LiteralPath $keyPath -ErrorAction Stop
    $back = [byte[]]$k2.GetValue($valueName)
    $got = (($back[0] -band 1) -eq 1)
    if ($got -ne $disable) { return @{ ok = $false; message = 'StartupApproved 回读不符（可能被策略或安全软件覆盖）' } }
    return @{ ok = $true; message = '' }
  } catch {
    return @{ ok = $false; message = '写 StartupApproved 失败：' + $_.Exception.Message }
  }
}

foreach ($item in @($items)) {
  $id = [string]$item.id
  $name = [string]$item.name
  $source = [string]$item.source
  try {
    if ($source -eq 'registry') {
      $regPath = 'Registry::' + [string]$item.regPath
      $vp = [string]$item.valueName
      if ($enable) {
        # v3.7.0：Run 值还在 → 走 StartupApproved 清 bit0（与任务管理器同轨），不再删值
        $saPath = Get-ApprovedKeyPath ([string]$item.hive) 'Run'
        $runKey = Get-Item -LiteralPath $regPath -ErrorAction SilentlyContinue
        if ($runKey -and ($null -ne $runKey.GetValue($vp))) {
          $r = Set-ApprovedBit $saPath $vp $false
          if ($r.ok) {
            # 值仍在，无需保留旧的删值式记录
            $records = @($records | Where-Object { $_.id -ne $id })
            Save-Records
            $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已启用' }
          } else {
            $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = $r.message }
          }
          continue
        }
        # 值已被删除（旧版 Trim 的删值式禁用 / 应用自行卸载）：回退到记录回写
        $rec = @($records | Where-Object { $_.id -eq $id }) | Select-Object -First 1
        if (-not $rec) {
          $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '缺少启用记录，且注册表中已无该项' }
          continue
        }
        if (-not (Test-Path -LiteralPath $regPath)) { New-Item -ItemType Directory -Path $regPath -Force | Out-Null }
        $pt = [Microsoft.Win32.RegistryValueKind]::String
        $kindStr = [string]$rec.valueType
        switch ($kindStr) {
          'ExpandString' { $pt = [Microsoft.Win32.RegistryValueKind]::ExpandString }
          'DWord' { $pt = [Microsoft.Win32.RegistryValueKind]::DWord }
          'QWord' { $pt = [Microsoft.Win32.RegistryValueKind]::QWord }
          'Binary' { $pt = [Microsoft.Win32.RegistryValueKind]::Binary }
          'MultiString' { $pt = [Microsoft.Win32.RegistryValueKind]::MultiString }
          'String' { $pt = [Microsoft.Win32.RegistryValueKind]::String }
          default { $pt = [Microsoft.Win32.RegistryValueKind]::String }
        }
        if ($kindStr -eq 'Binary') {
          $bytes = [Convert]::FromBase64String([string]$rec.valueDataB64)
          New-ItemProperty -LiteralPath $regPath -Name $vp -PropertyType $pt -Value $bytes -Force -ErrorAction Stop | Out-Null
        } elseif ($kindStr -eq 'MultiString') {
          New-ItemProperty -LiteralPath $regPath -Name $vp -PropertyType $pt -Value @([string[]]$rec.valueDataArray) -Force -ErrorAction Stop | Out-Null
        } elseif ($kindStr -eq 'DWord' -or $kindStr -eq 'QWord') {
          New-ItemProperty -LiteralPath $regPath -Name $vp -PropertyType $pt -Value ([int64][string]$rec.valueData) -Force -ErrorAction Stop | Out-Null
        } else {
          New-ItemProperty -LiteralPath $regPath -Name $vp -PropertyType $pt -Value ([string]$rec.valueData) -Force -ErrorAction Stop | Out-Null
        }
        # SU-3（2026-09-15）：写后回读校验（S1）——原实现只查「值存在」即判成功，
        # 若类型/内容因 ExpandString/MultiString/Binary 转换失真会误报已恢复。
        $ok = $false
        $ckey = Get-Item -LiteralPath $regPath -ErrorAction SilentlyContinue
        if ($ckey) {
          $cval = $ckey.GetValue($vp)
          $ckindOk = ($null -ne $cval) -and ($ckey.GetValueKind($vp).ToString() -eq $kindStr)
          $cdataOk = $false
          if ($kindStr -eq 'Binary') {
            try { $cdataOk = ([Convert]::ToBase64String([byte[]]$cval) -eq [string]$rec.valueDataB64) } catch { $cdataOk = $false }
          } elseif ($kindStr -eq 'MultiString') {
            try {
              $expect = @([string[]]$rec.valueDataArray)
              $actualArr = @([string[]]$cval)
              $cdataOk = ($expect.Count -eq $actualArr.Count) -and ((Compare-Object $expect $actualArr -SyncWindow 0).Count -eq 0)
            } catch { $cdataOk = $false }
          } elseif ($kindStr -eq 'DWord' -or $kindStr -eq 'QWord') {
            try { $cdataOk = ([string]$cval) -eq ([string][int64][string]$rec.valueData) } catch { $cdataOk = $false }
          } else {
            try { $cdataOk = ([string]$cval) -eq ([string]$rec.valueData) } catch { $cdataOk = $false }
          }
          $ok = $ckindOk -and $cdataOk
        }
        if ($ok) {
          $records = @($records | Where-Object { $_.id -ne $id })
          Save-Records
          $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已启用' }
        } else {
          $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '回写未生效或类型/内容失真（可能需要管理员权限）' }
        }
      } else {
        # v3.7.0：禁用改为「保留 Run 值 + 写 StartupApproved blob」，不再删除注册表值。
        # 与任务管理器同一条轨道：值还在系统里，随时可一键还原，也不再与 Windows 互相不可见。
        if (-not (Test-Path -LiteralPath $regPath)) { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '注册表路径不存在' }; continue }
        $key = Get-Item -LiteralPath $regPath
        if ($null -eq $key.GetValue($vp)) { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '值不存在' }; continue }
        $saPath = Get-ApprovedKeyPath ([string]$item.hive) 'Run'
        $r = Set-ApprovedBit $saPath $vp $true
        if ($r.ok) {
          # 值仍在，且不写 disabled.json——否则它会被当成「已删值」在扫描里回显成幽灵项
          $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已禁用（注册表值保留，可随时还原）' }
        } else {
          # 写 blob 失败（多为 HKLM 未提权）→ 回退旧行为：删值 + 落记录，保证禁用仍然生效
          $kind = $key.GetValueKind($vp)
          $data = $key.GetValue($vp)
          $vData = ''; $vDataB64 = ''; $vDataArr = @()
          if ($kind -eq 'Binary') { $vDataB64 = [Convert]::ToBase64String([byte[]]$data) }
          elseif ($kind -eq 'MultiString') { $vDataArr = @([string[]]$data) }
          else { $vData = [string]$data }
          $rec = [pscustomobject]@{
            id = $id; name = $name; command = [string]$data; source = 'registry';
            hive = $item.hive; regPath = $item.regPath; valueName = $vp; valueType = $kind.ToString();
            valueData = $vData; valueDataB64 = $vDataB64; valueDataArray = @($vDataArr);
            filePath = ''; taskPath = ''; taskName = '';
            location = $item.location; scope = $item.scope;
            publisher = $item.publisher; resolvedPath = $item.resolvedPath
          }
          Remove-ItemProperty -LiteralPath $regPath -Name $vp -ErrorAction Stop
          if ($null -eq (Get-Item -LiteralPath $regPath).GetValue($vp)) {
            $records = @($records | Where-Object { $_.id -ne $id }) + @($rec)
            Save-Records
            $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已禁用（回退为删除值方式：' + $r.message + '）' }
          } else {
            $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = $r.message }
          }
        }
      }
      continue
    }

    if ($source -eq 'folder') {
      $filePath = [string]$item.filePath
      if ($enable) {
        $rec = @($records | Where-Object { $_.id -eq $id }) | Select-Object -First 1
        if (-not $rec) { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '缺少启用记录' }; continue }
        $backupPath = [string]$rec.filePath
        $origPath = [string]$rec.valueData  # 记录里存原路径
        if (-not $origPath -or -not (Test-Path -LiteralPath $backupPath)) { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '备份文件不存在' }; continue }
        $destDir = [IO.Path]::GetDirectoryName($origPath)
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        Move-Item -LiteralPath $backupPath -Destination $origPath -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $origPath) {
          $records = @($records | Where-Object { $_.id -ne $id })
          Save-Records
          $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已启用' }
        } else {
          $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '移回未生效' }
        }
      } else {
        if (-not (Test-Path -LiteralPath $filePath)) { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '文件不存在' }; continue }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $safeName = ($name -replace '[^\w\-\u4e00-\u9fa5]', '_')
        $dest = Join-Path $filesDir ($stamp + '_' + $safeName + [IO.Path]::GetExtension($filePath))
        Move-Item -LiteralPath $filePath -Destination $dest -Force -ErrorAction Stop
        $rec = [pscustomobject]@{
          id = $id; name = $name; command = $filePath; source = 'folder';
          hive = $item.hive; regPath = ''; valueName = ''; valueType = '';
          valueData = $filePath; valueDataB64 = ''; valueDataArray = @();
          filePath = $dest; taskPath = ''; taskName = '';
          location = $item.location; scope = $item.scope;
          publisher = $item.publisher; resolvedPath = $item.resolvedPath
        }
        $records = @($records | Where-Object { $_.id -ne $id }) + @($rec)
        Save-Records
        $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已禁用' }
      }
      continue
    }

    if ($source -eq 'task') {
      $taskPath = [string]$item.taskPath
      $taskName = [string]$item.taskName
      if ([string]::IsNullOrWhiteSpace($taskName)) { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '缺少任务名' }; continue }
      $fullName = $taskPath + $taskName
      $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
      if (-not $task) { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '计划任务不存在' }; continue }
      if ($enable) {
        if ($task.State -ne 'Disabled') { $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已处于启用状态' }; continue }
        Enable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop | Out-Null
        $state = (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath).State
        if ($state -ne 'Disabled') { $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已启用' } }
        else { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '启用未生效（可能需要管理员权限）' } }
      } else {
        if ($task.State -eq 'Disabled') { $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已处于禁用状态' }; continue }
        Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop | Out-Null
        $state = (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath).State
        if ($state -eq 'Disabled') { $success++; $results += @{ id = $id; name = $name; status = 'ok'; message = '已禁用' } }
        else { $failed++; $results += @{ id = $id; name = $name; status = 'error'; message = '禁用未生效（可能需要管理员权限）' } }
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

[pscustomobject]@{ success = $success; failed = $failed; results = @($results) } | ConvertTo-Json -Depth 6 -Compress
