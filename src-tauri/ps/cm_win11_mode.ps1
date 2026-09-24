# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/contextmenu-scripts.js → win11Mode("__TRIM_WIN11_ACTION__")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：Win11 经典/现代右键切换（白名单动作哨兵）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$action = 'get'

$clsidRoot = 'Registry::HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
$inproc = $clsidRoot + '\InprocServer32'

function Get-CurrentMode {
  $k = Get-Item -LiteralPath $inproc -ErrorAction SilentlyContinue
  if (-not $k) { return 'modern' }
  $v = $k.GetValue('')
  if ($null -eq $v) { return 'modern' }
  if ([string]::IsNullOrEmpty([string]$v)) { return 'classic' }
  return 'modern'
}

$before = Get-CurrentMode
if ($action -eq 'get') {
  [pscustomobject]@{ success = $true; mode = $before; changed = $false; requireRestart = $false } | ConvertTo-Json -Compress
  exit
}

$mode = 'modern'
if ($action -eq 'set-classic') {
  try {
    if (-not (Test-Path -LiteralPath $inproc)) { New-Item -Path $inproc -Force -ErrorAction Stop | Out-Null }
    # 默认值必须是「存在的空字符串」，不是「不存在」——这是该开关生效的唯一形态
    New-ItemProperty -LiteralPath $inproc -Name '(default)' -PropertyType String -Value '' -Force -ErrorAction Stop | Out-Null
    $mode = 'classic'
  } catch {
    [pscustomobject]@{ success = $false; mode = $before; changed = $false; message = ('写入失败: ' + $_.Exception.Message) } | ConvertTo-Json -Compress
    exit
  }
} elseif ($action -eq 'set-modern') {
  try {
    if (Test-Path -LiteralPath $clsidRoot) { Remove-Item -LiteralPath $clsidRoot -Recurse -Force -ErrorAction Stop }
    $mode = 'modern'
  } catch {
    [pscustomobject]@{ success = $false; mode = $before; changed = $false; message = ('还原失败: ' + $_.Exception.Message) } | ConvertTo-Json -Compress
    exit
  }
} else {
  [pscustomobject]@{ success = $false; mode = $before; changed = $false; message = '未知动作' } | ConvertTo-Json -Compress
  exit
}

# 回读校验：写没生效绝不报成功（该开关必须重启资源管理器才可见，故 requireRestart 恒真）
$after = Get-CurrentMode
[pscustomobject]@{
  success        = ($after -eq $mode)
  mode           = $after
  changed        = ($after -ne $before)
  requireRestart = $true
  message        = $(if ($after -eq $mode) { '已切换，重启资源管理器后生效' } else { '切换未生效' })
} | ConvertTo-Json -Compress
