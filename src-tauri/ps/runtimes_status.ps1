# <<<PROVENANCE
# 来源：C:/KaiFa/Trim/src/scripts-powershell/runtimes-scripts.js → status()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：运行库检测（只读）
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

$releaseMap = ConvertFrom-Json ('[[533320,"4.8.1"],[528040,"4.8"],[461808,"4.7.2"],[461308,"4.7.1"],[460798,"4.7"],[394802,"4.6.2"],[393295,"4.6"],[379893,"4.5.2"],[378389,"4.5"]]')
$dx9List = ConvertFrom-Json ('["d3dx9_43.dll","d3dx9_42.dll","d3dx11_43.dll","d3dx10_43.dll","d3dcompiler_43.dll","xinput1_3.dll","xaudio2_7.dll"]')
$items = @()

# ---------- 1. VC++ 2015-2022（x64 / x86，注册表 + dll 双源交叉） ----------
foreach ($arch in @('x64', 'x86')) {
  $it = @{ id = 'vc-' + $arch; status = 'unknown'; evidence = @(); detail = ''; repair = $null }
  $regPath = 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\' + $arch
  if ($arch -eq 'x86') { $regPath = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x86' }
  $reg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
  $installed = ($reg -ne $null) -and ($reg.Installed -eq 1)
  $verText = [string]$reg.Version
  $dllDir = 'C:\Windows\System32'
  if ($arch -eq 'x86') { $dllDir = 'C:\Windows\SysWOW64' }
  $missing = @()
  $vcDlls = ConvertFrom-Json ('{"x64":["msvcp140.dll","vcruntime140.dll","vcruntime140_1.dll","concrt140.dll"],"x86":["msvcp140.dll","vcruntime140.dll","vcruntime140_1.dll","concrt140.dll"]}')
  foreach ($dll in $vcDlls.$arch) {
    if (-not (Test-Path (Join-Path $dllDir $dll))) { $missing += $dll }
  }
  if ($installed -and $missing.Count -eq 0) {
    $it.status = 'ok'
    $it.evidence += ('注册表：' + $verText)
    $it.evidence += ('关键 dll 齐全（' + $dllDir + '）')
  } elseif (-not $installed -and $missing.Count -eq 0) {
    # 注册表不在但 dll 齐全：视为已可用（某些精简安装路径），如实标注
    $it.status = 'ok'
    $it.evidence += '注册表项缺失，但关键 dll 齐全'
  } elseif ($installed -and $missing.Count -gt 0) {
    # 核心价值场景：注册表在、dll 被清理工具/杀软误删
    $it.status = 'fail'
    $it.detail = 'VC++ 运行库已安装但关键 dll 缺失（可能被清理工具误删）'
    $it.evidence += ('注册表：' + $verText)
    foreach ($m in $missing) { $it.evidence += ($dllDir + '\' + $m + ' 缺失') }
    $it.repair = @{ id = 'vc-' + $arch; name = 'VC++ 2015-2022 ' + $arch.ToUpper() }
  } else {
    $it.status = 'fail'
    $it.detail = 'VC++ 2015-2022 ' + $arch + ' 未安装'
    $it.evidence += '注册表：未安装'
    foreach ($m in $missing) { $it.evidence += ($dllDir + '\' + $m + ' 缺失') }
    $it.repair = @{ id = 'vc-' + $arch; name = 'VC++ 2015-2022 ' + $arch.ToUpper() }
  }
  $items += $it
}

# ---------- 2. .NET Framework 4.x ----------
$netItem = @{ id = 'netfx4x'; status = 'unknown'; evidence = @(); detail = ''; repair = $null }
$ndp4 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
if ($ndp4 -and $ndp4.Install -eq 1 -and $ndp4.Release) {
  $rel = [int]$ndp4.Release
  $verName = '4.x（Release ' + $rel + '）'
  foreach ($pair in $releaseMap) {
    if ($rel -ge [int]$pair[0]) { $verName = $pair[1] + '（Release ' + $rel + '）'; break }
  }
  $netItem.evidence += $verName
  if ($rel -ge 528040) { $netItem.status = 'ok' }
  else {
    $netItem.status = 'warn'
    $netItem.detail = '.NET Framework 低于 4.8，部分新软件可能无法运行'
    $netItem.repair = @{ id = 'netfx48'; name = '.NET Framework 4.8' }
  }
} else {
  $netItem.status = 'fail'
  $netItem.detail = '.NET Framework 4.x 未安装'
  $netItem.evidence += '注册表：未安装'
  $netItem.repair = @{ id = 'netfx48'; name = '.NET Framework 4.8' }
}
$items += $netItem

# ---------- 3. .NET Framework 3.5 ----------
$net35 = @{ id = 'netfx35'; status = 'unknown'; evidence = @(); detail = ''; repair = $null }
$ndp35 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' -ErrorAction SilentlyContinue
$feat35 = Get-WindowsOptionalFeature -Online -FeatureName 'NetFx3' -ErrorAction SilentlyContinue
if (($ndp35 -and $ndp35.Install -eq 1) -or ($feat35 -and $feat35.State -eq 'Enabled')) {
  $net35.status = 'ok'
  $net35.evidence += '.NET Framework 3.5 已启用'
} else {
  # 信息级：部分老游戏/软件需要；不强制
  $net35.status = 'warn'
  $net35.detail = '.NET Framework 3.5 未启用（部分老游戏/老软件需要）'
  $net35.evidence += '注册表/可选功能：未启用'
  $net35.repair = @{ id = 'netfx35'; name = '.NET Framework 3.5（DISM 启用）' }
}
$items += $net35

# ---------- 4. DirectX 旧版组件（d3dx9/x10/x11 等，双目录检查） ----------
$dxItem = @{ id = 'dx9'; status = 'ok'; evidence = @(); detail = ''; repair = $null }
$dxMissing = @()
foreach ($dll in $dx9List) {
  $in64 = Test-Path (Join-Path 'C:\Windows\System32' $dll)
  $in86 = Test-Path (Join-Path 'C:\Windows\SysWOW64' $dll)
  if (-not $in64 -and -not $in86) { $dxMissing += $dll }
}
if ($dxMissing.Count -gt 0) {
  $dxItem.status = 'fail'
  $dxItem.detail = 'DirectX 9.0c 附属组件缺失，部分老游戏无法启动'
  foreach ($m in $dxMissing) { $dxItem.evidence += ($m + ' 缺失（System32 与 SysWOW64 均未找到）') }
  # 微软官方已下架 DirectX End-User Runtime 独立安装包（实测 404），不提供一键修复，
  # 诚实指引：通过安装带 DX9 的游戏/Steam 校验，或系统文件修复
} else {
  $dxItem.evidence += 'DirectX 9.0c 关键附属组件齐全'
}
# DX12 系统组件（缺失属异常但不可单独安装）
foreach ($dll in @('d3d12.dll', 'd3d12core.dll')) {
  if (-not (Test-Path (Join-Path 'C:\Windows\System32' $dll))) {
    $dxItem.status = 'fail'
    $dxItem.evidence += ('System32\' + $dll + ' 缺失（DX12 系统组件，建议系统文件修复）')
  }
}
$items += $dxItem

# ---------- 5. 旧版 VC++ 2005-2013（信息级列举，不判定不修复） ----------
$oldVc = @()
$uninstKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
foreach ($k in $uninstKeys) {
  Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
    $dn = [string]$_.'DisplayName'
    if ($dn -match '^Microsoft Visual C\+\+ (2005|2008|2010|2012|2013) Redistributable') { $oldVc += $dn }
  }
}
$oldItem = @{ id = 'vc-old'; status = 'info'; evidence = @(); detail = ''; repair = $null }
if ($oldVc.Count -gt 0) {
  $uniq = $oldVc | Select-Object -Unique
  foreach ($n in $uniq) { $oldItem.evidence += $n }
} else {
  $oldItem.evidence += '未发现旧版 VC++（2005-2013）'
}
$oldItem.detail = '信息级：仅列出已装版本，不判定异常'
$items += $oldItem

$summary = @{ total = $items.Count; ok = @($items | Where-Object { $_.status -eq 'ok' }).Count; warn = @($items | Where-Object { $_.status -eq 'warn' }).Count; fail = @($items | Where-Object { $_.status -eq 'fail' }).Count }
$out = @{ items = $items; summary = $summary }
ConvertTo-Json $out -Depth 5 -Compress
