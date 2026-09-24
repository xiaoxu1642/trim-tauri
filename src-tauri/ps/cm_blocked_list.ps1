# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/contextmenu-scripts.js → blockedList()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：被拦截的右键项清单（只读）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$roots = @(
  @{ scope = 'machine'; path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' },
  @{ scope = 'user';    path = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' }
)
$entries = @()
foreach ($r in $roots) {
  $k = Get-Item -LiteralPath $r.path -ErrorAction SilentlyContinue
  if (-not $k) { continue }
  foreach ($vn in @($k.GetValueNames())) {
    $g = ([string]$vn).Trim()
    if ($g -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') { continue }
    $entries += [pscustomobject]@{ guid = $g; scope = $r.scope }
  }
}
[pscustomobject]@{ success = $true; entries = @($entries) } | ConvertTo-Json -Depth 4 -Compress
