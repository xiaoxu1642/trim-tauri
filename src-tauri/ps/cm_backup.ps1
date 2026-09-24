# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/contextmenu-scripts.js → backup(["__TRIM_ITEMS_JSON__"])
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：右键菜单项注册表备份（哨兵 items）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$items = '["__TRIM_ITEMS_JSON__"]' | ConvertFrom-Json
$desktop = [Environment]::GetFolderPath('Desktop')
$backupDir = Join-Path $desktop ('右键菜单备份_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$filesDir = Join-Path $backupDir 'files'
New-Item -ItemType Directory -Path $filesDir -Force | Out-Null
$backupFiles = @()
$fileRecords = @()
$index = 0

function Convert-ToRegPath([string]$Path) {
  $p = [string]$Path
  $p = $p -replace '^.*?Registry::', ''
  $p = $p -replace '^HKEY_CLASSES_ROOT', 'HKCR'
  $p = $p -replace '^HKEY_CURRENT_USER', 'HKCU'
  $p = $p -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
  $p = $p -replace '^HKEY_USERS', 'HKU'
  return $p
}

# 审查 CM-9（2026-09-19）：导出后校验 .reg 头部的 hive 与来源 hive 一致。
# 老实现把 HKCR（合并视图）路径直接交给 reg.exe，导出的 .reg 头是 [HKEY_CLASSES_ROOT\...]，
# 而 reg.exe **import** 这种头时会写进 HKLM\\SOFTWARE\\Classes —— 于是「删掉自己用户的项、
# 恢复后变成全机项」。这里两头都堵：导出只用真实 hive 路径，导入前再校验一次头部。
function Get-RegFileHeaderHive([string]$File) {
  if (-not (Test-Path -LiteralPath $File)) { return '' }
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

# CM-15（2026-09-19）：reg.exe 会把「操作已成功完成」写到 **stdout**，而本脚本的返回值也是
# stdout——主进程 JSON.parse(stdout) 会因此直接失败。这里统一走 Invoke-RegCmd：吞掉子进程
# 输出、只取退出码（结果一律用文件内容/注册表回读来验证）。
# 注意调用形式：函数用自动变量 $args 接收，调用处写成 Invoke-RegCmd export $k $f '/y'。
# 不要写成 param([string[]]$RegArgs) 再用 Invoke-RegCmd @('export', ...) 这种数组字面量调用
# —— 命令参数模式里的数组字面量会被拼成单个字符串传给 reg.exe，
# 报 Invalid Argument/Option '@export ...'。
function Invoke-RegCmd {
  $eap = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  try { & reg.exe @args 2>$null | Out-Null } finally { $ErrorActionPreference = $eap }
  return $LASTEXITCODE
}

$exported = 0
$exportFailed = 0
$regRecords = @()
foreach ($item in @($items)) {
  $index++
  $source = [string]$item.source
  $regPath = [string]$item.regPath
  # 文件类来源（发送到 / Win+X）走复制备份，绝不能掉进下面的 reg export 分支
  if ($source -eq 'filesystem' -or $source -eq 'winx') {
    if (-not (Test-Path -LiteralPath $regPath)) { continue }
    $name = 'file_{0}_{1}_{2}' -f $index, ([IO.Path]::GetFileNameWithoutExtension($regPath)), ([IO.Path]::GetExtension($regPath).TrimStart('.'))
    $dest = Join-Path $filesDir $name
    try { Copy-Item -LiteralPath $regPath -Destination $dest -Force -Recurse; $fileRecords += [pscustomobject]@{ source = $regPath; backup = $dest }; $backupFiles += $dest } catch {}
    continue
  }
  # 一律用扫描阶段解析出的真实 hive 路径；缺失（旧缓存/异常）时退回 regPath 但仍拒绝 HKCR 头
  $writePath = [string]$item.nativeRegPath
  if ([string]::IsNullOrWhiteSpace($writePath)) { $writePath = $regPath }
  if ([string]::IsNullOrWhiteSpace($writePath)) { $exportFailed++; continue }
  if ($writePath -match '^HKEY_CLASSES_ROOT(?=\\|$)') {
    # 无法归位到具体 hive（键已消失或解析失败）——不产备份，交由上层阻断删除
    $exportFailed++
    continue
  }
  $nativePath = Convert-ToRegPath $writePath
  # CM-14（2026-09-19）：文件名必须连反斜杠一起替换。旧写法是正则字符类 '[\\/:*?...]'，
  # 但这段脚本活在 JS 模板字符串里，文件中的 \\\\ 经模板转义后只剩 \\，
  # 字符类里根本没有反斜杠 → 文件名带着路径分隔符 → reg.exe 报「Unable to write to the file」
  # → 注册表项备份从来没成功过，删除被自己的备份步骤阻断。
  # 这里改用 [IO.Path]::GetInvalidFileNameChars() + String.Replace：不写正则、不写转义，
  # 从根上没有二次转义陷阱（也别用 [string]$x.ToCharArray()，那是把 char 数组拼成带空格字符串）。
  $safeName = [string]$nativePath
  foreach ($ch in [IO.Path]::GetInvalidFileNameChars()) {
    $safeName = $safeName.Replace([string]$ch, '_')
  }
  if ($safeName.Length -gt 120) { $safeName = $safeName.Substring($safeName.Length - 120) }
  $regFile = Join-Path $backupDir ('registry_{0}_{1}.reg' -f $index, $safeName)
  try {
    $expCode = Invoke-RegCmd export $writePath $regFile '/y'
    $hdr = Get-RegFileHeaderHive $regFile
    if ($expCode -eq 0 -and $hdr -and $hdr -ne 'HKEY_CLASSES_ROOT' -and $writePath.StartsWith($hdr)) {
      $backupFiles += $regFile; $exported++
      $regRecords += [pscustomobject]@{ source = $writePath; backup = $regFile; hive = $hdr }
    } else {
      if (Test-Path -LiteralPath $regFile) { Remove-Item -LiteralPath $regFile -Force -ErrorAction SilentlyContinue }
      $exportFailed++
    }
  } catch { $exportFailed++ }
}

$manifest = [pscustomobject]@{ version = 2; created = (Get-Date).ToString('o'); items = @($items); files = @($fileRecords); registryFiles = @($regRecords) }
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $backupDir 'manifest.json') -Encoding UTF8
[pscustomobject]@{ backupDir = $backupDir; files = @($backupFiles); count = ($exported + @($fileRecords).Count); exported = $exported; copied = @($fileRecords).Count; failed = $exportFailed } | ConvertTo-Json -Compress
