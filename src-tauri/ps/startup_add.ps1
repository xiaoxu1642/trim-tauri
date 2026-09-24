# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/startup-scripts.js → add("__TRIM_STARTUP_PATH__", "__TRIM_STARTUP_NAME__")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：添加启动项（哨兵 路径/名称）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$path = '__TRIM_STARTUP_PATH__'
$name = '__TRIM_STARTUP_NAME__'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (-not (Test-Path -LiteralPath $runKey)) { New-Item -ItemType Directory -Path $runKey -Force | Out-Null }
# 冲突检查：已存在同名启动项时返回原值，避免静默覆盖
$existing = $null
try { $existing = (Get-ItemProperty -LiteralPath $runKey -Name $name -ErrorAction SilentlyContinue).$name } catch {}
if ($null -ne $existing -and [string]$existing -ne '') {
  'EXISTS:' + [string]$existing
} else {
  New-ItemProperty -LiteralPath $runKey -Name $name -Value ('"' + $path + '"') -PropertyType String -Force | Out-Null
  'OK'
}
