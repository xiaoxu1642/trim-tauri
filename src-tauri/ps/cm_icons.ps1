# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/contextmenu-scripts.js → icons(["__TRIM_ITEMS_JSON__"])
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：右键菜单图标修复（哨兵 items）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Drawing

$items = '["__TRIM_ITEMS_JSON__"]' | ConvertFrom-Json
$icons = @{}

foreach ($it in $items) {
  $clsid = ([string]$it.clsid).Trim()
  if (-not $clsid -or -not $clsid.StartsWith('{')) { continue }
  $dll = ''
  foreach ($view in @('Registry::HKEY_CLASSES_ROOT\CLSID', 'Registry::HKEY_CLASSES_ROOT\WOW6432Node\CLSID', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Wow6432Node\CLSID')) {
    $regPath = $view + '\' + $clsid + '\InprocServer32'
    if (-not (Test-Path -LiteralPath $regPath)) { continue }
    $serverKey = Get-Item -LiteralPath $regPath -ErrorAction SilentlyContinue
    if ($serverKey) {
      $dll = ([string]$serverKey.GetValue('')).Trim().Trim('"')
      if ($dll) { break }
    }
  }
  if (-not $dll) { continue }
  $dll = [Environment]::ExpandEnvironmentVariables($dll)
  if (-not (Test-Path -LiteralPath $dll)) { continue }
  try {
    $icon = [System.Drawing.Icon]::ExtractAssociatedIcon($dll)
    if (-not $icon) { continue }
    $bmp = $icon.ToBitmap()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $b64 = [Convert]::ToBase64String($ms.ToArray())
    $icons[$clsid] = 'data:image/png;base64,' + $b64
    $ms.Dispose(); $bmp.Dispose(); $icon.Dispose()
  } catch {}
}

$icons | ConvertTo-Json -Compress
