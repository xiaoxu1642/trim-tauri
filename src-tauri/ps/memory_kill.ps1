# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/memory-scripts.js → killScript(987654321, "__TRIM_PROC_NAME__")
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：结束指定进程（哨兵模板）
# PROVENANCE>>>

$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$p = Get-Process -Id 987654321 -ErrorAction SilentlyContinue
if ($null -eq $p) {
  [pscustomobject]@{ success = $false; message = '进程不存在或已退出' } | ConvertTo-Json -Compress
  exit 0
}
$expected = '__TRIM_PROC_NAME__'
if ($expected -and $p.ProcessName -ne $expected) {
  [pscustomobject]@{ success = $false; message = '进程 ID 已被系统复用，已拒绝结束' } | ConvertTo-Json -Compress
  exit 0
}
$name = $p.ProcessName
Stop-Process -Id 987654321 -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
$alive = Get-Process -Id 987654321 -ErrorAction SilentlyContinue
if ($null -eq $alive) {
  [pscustomobject]@{ success = $true; message = "已结束进程 $name (PID 987654321)" } | ConvertTo-Json -Compress
} else {
  [pscustomobject]@{ success = $false; message = "无法结束进程 $name (PID 987654321)，可能需要管理员权限" } | ConvertTo-Json -Compress
}
