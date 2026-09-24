# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/peripheral-scripts.js → query()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：外设优化项状态查询（只读）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Get-TFDword([string]$p, [string]$n) {
  try { [int](Get-ItemPropertyValue -LiteralPath $p -Name $n -ErrorAction Stop) } catch { -1 }
}
$q = [pscustomobject]@{
  win32 = Get-TFDword 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation'
  keyboard = Get-TFDword 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters' 'KeyboardDataQueueSize'
  mouse = Get-TFDword 'HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters' 'MouseDataQueueSize'
}
'@@PERIPHERAL@@' + ($q | ConvertTo-Json -Compress)
