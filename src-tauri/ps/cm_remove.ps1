# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/contextmenu-scripts.js → remove(["__TRIM_ITEMS_JSON__"])
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：移除右键菜单项（哨兵 items）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

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

$items = '["__TRIM_ITEMS_JSON__"]' | ConvertFrom-Json
$success = 0
$failed = 0
$results = @()
foreach ($item in @($items)) {
  if ($item.risk -eq 'protected') { $results += @{ name = $item.name; status = 'skip'; message = '系统保护项' }; continue }
  # 复核 N1（删除红线，2026-09-16）：文件系统项（「发送到」快捷方式）不再在 PS 内裸删，
  # 主进程已改为 trashOrUnlink（回收站优先）+ 全局删除清单；本脚本若仍收到此类项，跳过并如实回报。
  if ([string]$item.source -eq 'filesystem' -or [string]$item.source -eq 'winx') {
    $results += @{ name = $item.name; status = 'skip'; message = '文件系统项由主进程回收站删除' }
    continue
  }
  try {
    # CM-9（2026-09-19）：删除也走真实 hive 路径，与备份/恢复同源；
    # 原来经 HKEY_CLASSES_ROOT 合并视图删，删的是「解析到的那一份」，与备份的 hive 可能对不上
    $target = [string]$item.nativeRegPath
    if ([string]::IsNullOrWhiteSpace($target)) { $target = [string]$item.regPath }
    if ([string]::IsNullOrWhiteSpace($target) -or $target -match '(?i)^(Registry::)?HKEY_(CLASSES_ROOT|LOCAL_MACHINE|CURRENT_USER|USERS|CURRENT_CONFIG)\\?$') {
      $results += @{ name = $item.name; status = 'skip'; message = '无效或过宽路径' }; continue
    }
    # 标准路径（HKEY_CURRENT_USER\...）转 PowerShell 提供程序路径
    if ($target -match '^HKEY_') { $target = 'Registry::' + $target }
    # R7（v3.6.6 M1）：ShellNew 项共享父键 PostSetupShellNew，-Recurse 会删整键连带其他 9 项。
    # ShellNew 的禁用/启用应通过修改 Classes 值列表实现（由启停通道处理），不走删除通道。
    if ([string]$item.source -eq 'shellnew') {
      $results += @{ id = [string]$item.id; name = $item.name; status = 'skip'; message = '新建菜单项请通过启停操作管理，禁止整键删除' }
      continue
    }
    if (Test-Path -LiteralPath $target) {
      Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
      if (Test-Path -LiteralPath $target) {
        $failed++; $results += @{ id = [string]$item.id; name = $item.name; status = 'error'; message = '删除后键仍存在（可能被占用或权限不足）' }
      } else {
        $success++
        $results += @{ id = [string]$item.id; name = $item.name; status = 'ok'; message = '已删除' }
      }
    } else { $results += @{ id = [string]$item.id; name = $item.name; status = 'skip'; message = '路径不存在' } }
  } catch { $failed++; Write-TFDiag -Stage 'contextmenu.remove' -Mutation 'rolled_back' -Detail ([string]$item.regPath + ' -> ' + $_.Exception.Message); $results += @{ name = $item.name; status = 'error'; message = $_.Exception.Message } }
}
[pscustomobject]@{ success = $success; failed = $failed; results = @($results) } | ConvertTo-Json -Depth 6 -Compress
