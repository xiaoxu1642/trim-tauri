# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/contextmenu-scripts.js → restore()
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

# v2-K1（2026-09-24 全仓审查）：还原方向的输入一律不被信任。
# 桌面与 manifest.json 对**中等完整性的用户态进程可写**，而本脚本由提权侧以管理员令牌跑
# reg.exe —— 旧写法「自己挑最新目录 + 遍历目录内全部 *.reg」把「谁能往桌面塞一个文件」
# 直接放大成「谁能往 HKLM 写键」（IFEO Debugger 是标准提权持久化载荷）。三道闸门：
#   ① 件必须登记在 manifest.registryFiles[] 且物理落在这次选中的备份目录内；
#   ② 硬闸门是从 **.reg 正文**解析出的每一条键路径都要过白名单 —— manifest 可被伪造，
#      而文件正文与写死在脚本里的白名单不能；
#   ③ 文件分支要求 backup 在本目录内、source 命中「发送到 / Win+X」三个已知根。
# 残余风险如实记录：能写桌面者仍可伪造「合法范围内」的右键菜单项（COM 注册），彻底解法是
# 把备份根从桌面迁到 app_data_dir 并给 manifest 加完整性校验（审查报告 v2-K1 彻底方案）。
function Get-RegFileAllKeys {
  param([string]$File)
  $keys = @()
  foreach ($line in @(Get-Content -LiteralPath $File -ErrorAction SilentlyContinue)) {
    $t = ([string]$line).Trim()
    if ($t.StartsWith('[') -and $t.EndsWith(']')) {
      # '[-HKEY...]' 是删除键语法：reg export 永不产出这种行，出现即非本工具生成的备份
      $keys += $t.Substring(1, $t.Length - 2).TrimEnd('\')
    }
  }
  return ,$keys
}

function Get-FullPathSafe {
  param([string]$Path)
  try { return [IO.Path]::GetFullPath([string]$Path) } catch { return '' }
}

function Test-RegKeyAllowedForRestore {
  param([string]$KeyPath)
  $p = ([string]$KeyPath).Trim()
  foreach ($pair in @('HKEY_LOCAL_MACHINE|HKLM', 'HKEY_CURRENT_USER|HKCU', 'HKEY_USERS|HKU', 'HKEY_CLASSES_ROOT|HKCR', 'HKEY_CURRENT_CONFIG|HKCC')) {
    $long = $pair.Split('|')[0]
    if ($p.StartsWith($long, [StringComparison]::OrdinalIgnoreCase)) { $p = $pair.Split('|')[1] + $p.Substring($long.Length); break }
  }
  # 本工具的右键菜单项只落在 HKLM/HKCU 的 Software\Classes 之下（含 Wow6432Node 合并视图）。
  # HKCR 头刻意不在允许集内：CM-9 已证 reg.exe 会把 HKCR 头的件静默写进机器级 Classes。
  foreach ($prefix in @('HKLM\SOFTWARE\Classes\', 'HKCU\SOFTWARE\Classes\')) {
    if ($p.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}

# manifest 先读：没有可信 manifest 就等于没有任何可导入的件（宁可不导，也不猜）
$manifest = $null
$manifestPath = Join-Path $latestBackup 'manifest.json'
if (Test-Path -LiteralPath $manifestPath) {
  try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json } catch { $manifest = $null }
}
$listedBackups = @()
if ($manifest) {
  foreach ($rec in @($manifest.registryFiles)) {
    if ($rec -and $rec.backup) { $listedBackups += (Get-FullPathSafe ([string]$rec.backup)) }
  }
} else {
  $skipReasons += 'manifest.json 缺失或不可解析：本次拒绝导入任何 .reg（该备份请用当前版本重做一次）'
}
$backupPrefix = $latestBackup + [IO.Path]::DirectorySeparatorChar

foreach ($regFile in @(Get-ChildItem -LiteralPath $latestBackup -Filter 'registry_*.reg' -ErrorAction SilentlyContinue)) {
  try {
    $full = Get-FullPathSafe $regFile.FullName
    if (-not $full.StartsWith($backupPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      $skipped++
      $skipReasons += ($regFile.Name + '（不在本次选中的备份目录内，已拒绝导入）')
      continue
    }
    $listed = $false
    foreach ($a in $listedBackups) { if ($a -and ($a -ieq $full)) { $listed = $true; break } }
    if (-not $listed) {
      $skipped++
      $skipReasons += ($regFile.Name + '（未在 manifest.registryFiles 登记，已拒绝导入）')
      continue
    }
    $hdr = Get-RegFileHeaderHive $regFile.FullName
    if (-not $hdr -or $hdr -eq 'HKEY_CLASSES_ROOT' -or $hdr -eq 'OTHER') {
      $skipped++
      $hdrText = if ($hdr) { $hdr } else { '无法识别' }
      $skipReasons += ($regFile.Name + '（备份头为 ' + $hdrText + '，非真实 hive，已拒绝导入）')
      continue
    }
    # 逐条键路径过白名单：一件里有一条不合规就整件拒（reg import 是整文件生效的）
    $keys = @(Get-RegFileAllKeys $regFile.FullName)
    $badKey = ''
    if (@($keys).Count -eq 0) { $badKey = '正文里没有可识别的键行' }
    foreach ($k in @($keys)) { if (-not (Test-RegKeyAllowedForRestore $k)) { $badKey = $k; break } }
    if ($badKey) {
      $skipped++
      $skipReasons += ($regFile.Name + '（键路径不在右键菜单合法范围内，已拒绝导入：' + $badKey + '）')
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
if ($manifest) {
  # 文件分支的合法落点只有三个：用户与公共「发送到」、Win+X。前缀之外一律不覆盖，
  # 否则「backup 与 source 两个绝对路径都取自明文 manifest」等于让用户态进程往启动目录写文件。
  $allowedFileRoots = @(
    (Get-FullPathSafe (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Microsoft\Windows\SendTo')),
    (Get-FullPathSafe (Join-Path $env:ProgramData 'Microsoft\Windows\SendTo')),
    (Get-FullPathSafe (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WinX'))
  )
  foreach ($record in @($manifest.files)) {
    if (-not $record) { continue }
    $b = Get-FullPathSafe ([string]$record.backup)
    $s = Get-FullPathSafe ([string]$record.source)
    $okBackup = $b.StartsWith($backupPrefix, [StringComparison]::OrdinalIgnoreCase)
    $okSource = $false
    foreach ($r in $allowedFileRoots) {
      if ($r -and $s.StartsWith($r + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { $okSource = $true; break }
    }
    if (-not ($okBackup -and $okSource)) {
      $skipped++
      $skipReasons += ('文件项（来源不在发送到/Win+X 合法目录内，已拒绝还原：' + $s + '）')
      continue
    }
    if ((Test-Path -LiteralPath $b) -and $s) {
      try { New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($s)) -Force | Out-Null; Copy-Item -LiteralPath $b -Destination $s -Force -Recurse; $restored++ } catch { $failed++ }
    }
  }
}
[pscustomobject]@{ success = (($imported + $restored) -gt 0 -and $failed -eq 0); backupDir = $latestBackup; imported = $imported; restored = $restored; skipped = $skipped; skipReasons = @($skipReasons); failed = $failed } | ConvertTo-Json -Compress
