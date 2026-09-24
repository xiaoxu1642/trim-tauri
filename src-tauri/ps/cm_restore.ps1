# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/contextmenu-scripts.js → restore()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：从备份恢复右键菜单（危险）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$desktop = [Environment]::GetFolderPath('Desktop')
$backupDirs = Get-ChildItem -LiteralPath $desktop -Directory -Filter '右键菜单备份_*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
if (-not $backupDirs) { @{ success = $false; message = '未找到备份目录' } | ConvertTo-Json -Compress; exit }
$latestBackup = $backupDirs[0].FullName
$imported = 0
$failed = 0
$skipped = 0
$skipReasons = @()

# CM-15：吞掉 reg.exe 的 stdout（否则污染本脚本的 JSON 返回值），只取退出码。
# 调用形式必须用 $args 位置参数，不能用数组字面量（见 BACKUP_SCRIPT 同处的说明）。
function Invoke-RegCmd {
  $eap = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  try { & reg.exe @args 2>$null | Out-Null } finally { $ErrorActionPreference = $eap }
  return $LASTEXITCODE
}

# CM-9（2026-09-19）：导入前校验 .reg 头部 hive。reg.exe 遇到 [HKEY_CLASSES_ROOT\...] 头会把
# 键写进 HKLM\\SOFTWARE\\Classes（合并视图的机器级），即「用户级项恢复成全机项」，
# 且非管理员上下文下还会直接失败。旧版 Trim 产生的这类备份一律拒绝导入并如实回报。
function Get-RegFileHeaderHive {
  param([string]$File)
  foreach ($line in @(Get-Content -LiteralPath $File -TotalCount 8 -ErrorAction SilentlyContinue)) {
    $t = [string]$line
    if ($t.StartsWith('[')) {
      $h = $t.TrimStart('[')
      foreach ($root in @('HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS')) {
        if ($h.StartsWith($root)) { return $root }
      }
      return 'OTHER'
    }
  }
  return ''
}

function Get-RegFileFirstKey {
  param([string]$File)
  foreach ($line in @(Get-Content -LiteralPath $File -TotalCount 8 -ErrorAction SilentlyContinue)) {
    $t = [string]$line
    if ($t.StartsWith('[')) { return $t.TrimStart('[').TrimEnd(']', '\') }
  }
  return ''
}

foreach ($regFile in @(Get-ChildItem -LiteralPath $latestBackup -Filter '*.reg' -ErrorAction SilentlyContinue)) {
  try {
    $hdr = Get-RegFileHeaderHive $regFile.FullName
    if (-not $hdr -or $hdr -eq 'HKEY_CLASSES_ROOT' -or $hdr -eq 'OTHER') {
      $skipped++
      $hdrText = if ($hdr) { $hdr } else { '无法识别' }
      $skipReasons += ($regFile.Name + '（备份头为 ' + $hdrText + '，非真实 hive，已拒绝导入）')
      continue
    }
    $impCode = Invoke-RegCmd import $regFile.FullName
    if ($impCode -ne 0) { $failed++; continue }
    # 导入后回读：退出码 0 但键没落地不算成功（防假成功）
    $firstKey = Get-RegFileFirstKey $regFile.FullName
    if ($firstKey -and -not (Test-Path -LiteralPath ('Registry::' + $firstKey))) {
      $failed++
      $skipReasons += ($regFile.Name + '（reg import 报成功但键未出现）')
      continue
    }
    $imported++
  } catch { $failed++ }
}
$restored = 0
$manifestPath = Join-Path $latestBackup 'manifest.json'
if (Test-Path -LiteralPath $manifestPath) {
  try {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    foreach ($record in @($manifest.files)) {
      if ((Test-Path -LiteralPath $record.backup) -and $record.source) {
        try { New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($record.source)) -Force | Out-Null; Copy-Item -LiteralPath $record.backup -Destination $record.source -Force -Recurse; $restored++ } catch { $failed++ }
      }
    }
  } catch {}
}
[pscustomobject]@{ success = (($imported + $restored) -gt 0 -and $failed -eq 0); backupDir = $latestBackup; imported = $imported; restored = $restored; skipped = $skipped; skipReasons = @($skipReasons); failed = $failed } | ConvertTo-Json -Compress
