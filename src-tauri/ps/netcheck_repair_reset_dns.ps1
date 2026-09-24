# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/netcheck-scripts.js → repair("reset-dns", {"interfaceIndex":987654321})
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：DNS 服务器重置为自动获取（修复动作，判需管理员）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ---- Trim 诊断四元组 (P1-11) ----
function Write-TFDiag {
  param([string]$Stage, [string]$Mutation, [string]$Detail)
  try {
    $native = 0
    try { $native = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } catch { }
    if ($native -eq 0 -and $null -ne $LASTEXITCODE) { $native = $LASTEXITCODE }
    $key = $Stage + '|' + $Mutation + '|' + $Detail
    $digest = '{0:X8}' -f [Math]::Abs($key.GetHashCode())
    $o = [ordered]@{
      failure_stage = $Stage
      mutation_state = $Mutation
      diagnostic_digest = $digest
      native_error_code = [int64]$native
      detail = [string]$Detail
    }
    Write-Output ('@@DIAG@@' + ($o | ConvertTo-Json -Compress))
  } catch { }
}
trap {
  Write-TFDiag -Stage 'script' -Mutation 'unknown' -Detail $_.Exception.Message
  continue
}

Write-Output '正在把 DNS 服务器重置为自动获取…'
Set-DnsClientServerAddress -InterfaceIndex 987654321 -ResetServerAddresses -ErrorAction Stop
# F1（2026-09-15）：原为「-ErrorAction Stop + 紧跟无条件 ok=true」，Stop 被 PS_PREAMBLE
# 的 trap{continue} 吞掉后仍报成功。改为写后回读：DNS 服务器列表为空才算重置成功。
$srv = @(Get-DnsClientServerAddress -InterfaceIndex 987654321 -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
if ($srv.Count -eq 0) { Write-Output (@{ ok = $true; message = 'DNS 已重置为自动获取' } | ConvertTo-Json -Compress) }
else { Write-Output (@{ ok = $false; message = ('DNS 仍为手动配置: ' + ($srv -join ', ')) } | ConvertTo-Json -Compress) }
