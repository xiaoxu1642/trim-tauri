# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/memory-scripts.js → 常量 PROCESSES_SCRIPT
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：进程快照（@@PROC 前缀协议，只读）
# PROVENANCE>>>

$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$procs = @(Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 300 Id, ProcessName, @{n='mem';e={[long]$_.WorkingSet64}}, Path)
'@@PROC@@' + ($procs | ConvertTo-Json -Compress)
