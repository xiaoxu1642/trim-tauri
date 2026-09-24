// runtimes-scripts.js - 运行库修复（v3.3.0，第一期）
// 检测：VC++ 2015-2022 (x64/x86) / .NET Framework 4.x·3.5 / DirectX 旧版组件 + DX12，
// 全程只读，单脚本一次采集输出单个 JSON；判定必须双源交叉（注册表 + 关键 dll 文件面）。
// 修复：白名单动作（vc-x64 / vc-x86 / netfx48 / netfx35），本地安装包路径由主进程传入，
// 渲染层只传 actionId；安装包下载与校验全部在主进程（见 main.js downloadRedist）。
// DirectX 9 独立安装包已被微软官方下架（download.microsoft.com 直链 404 实测），
// 按方案「不伪造结论」原则：dx9 缺失仅给出诚实指引，不提供一键修复按钮。
// 约束（照 test-features 断言）：PS 片段禁反引号、禁模板字符串 ${、注释不带反斜杠。

const DIAG = require('../main/diag');

// ==================== 常量区 ====================
// VC++ 2015-2022 的关键 dll（System32 = x64 位视图，SysWOW64 = x86 位视图）
const KEY_DLLS = {
  x64: ['msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll', 'concrt140.dll'],
  x86: ['msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll', 'concrt140.dll']
};

// .NET Framework Release 下限 → 版本对照（判定表内置，不查表反推）
const NETFX_RELEASE_MAP = [
  [533320, '4.8.1'],
  [528040, '4.8'],
  [461808, '4.7.2'],
  [461308, '4.7.1'],
  [460798, '4.7'],
  [394802, '4.6.2'],
  [393295, '4.6'],
  [379893, '4.5.2'],
  [378389, '4.5']
];

// DirectX 旧版组件关键子集（不随 Win10/11 提供，缺失即老游戏无法启动）
// 注意：d3dcompiler_47/d3d9/d3d11/dxgi 随系统提供，绝不能作为缺失判据
const DX9_DLLS = ['d3dx9_43.dll', 'd3dx9_42.dll', 'd3dx11_43.dll', 'd3dx10_43.dll', 'd3dcompiler_43.dll', 'xinput1_3.dll', 'xaudio2_7.dll'];

// 修复动作白名单：id → 安装包元数据（url/sha256/bytes 为 2026-09-14 实测值，
// 探针脚本实测 aka.ms / go.microsoft.com 官方直链；改包必须重新实测同步）
const INSTALLERS = {
  'vc-x64': {
    name: 'VC++ 2015-2022 x64',
    url: 'https://aka.ms/vs/17/release/vc_redist.x64.exe',
    sha256: 'cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b',
    bytes: 25635768,
    args: '/install /quiet /norestart',
    timeoutSec: 300
  },
  'vc-x86': {
    name: 'VC++ 2015-2022 x86',
    url: 'https://aka.ms/vs/17/release/vc_redist.x86.exe',
    sha256: '0c09f2611660441084ce0df425c51c11e147e6447963c3690f97e0b25c55ed64',
    bytes: 13953392,
    args: '/install /quiet /norestart',
    timeoutSec: 300
  },
  'netfx48': {
    name: '.NET Framework 4.8',
    url: 'https://go.microsoft.com/fwlink/?linkid=2088631',
    sha256: '0a3a390c47e639d0f7fc65b21195fee6b7f65b066f80f70c60fab191d14b7e40',
    bytes: 121346568,
    args: '/q /norestart',
    timeoutSec: 600
  }
};

const ALLOWED_ACTIONS = new Set(Object.keys(INSTALLERS).concat(['netfx35']));
const HEADER = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
`;

// Release 下限 → 版本（注入 PS 常量区）
const RELEASE_JS = JSON.stringify(NETFX_RELEASE_MAP);
const DX9_JS = JSON.stringify(DX9_DLLS);

function status() {
  return HEADER + DIAG.PS_PREAMBLE + `
$releaseMap = ConvertFrom-Json ('${RELEASE_JS.replace(/'/g, "''")}')
$dx9List = ConvertFrom-Json ('${DX9_JS.replace(/'/g, "''")}')
$items = @()

# ---------- 1. VC++ 2015-2022（x64 / x86，注册表 + dll 双源交叉） ----------
foreach ($arch in @('x64', 'x86')) {
  $it = @{ id = 'vc-' + $arch; status = 'unknown'; evidence = @(); detail = ''; repair = $null }
  $regPath = 'HKLM:\\SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\' + $arch
  if ($arch -eq 'x86') { $regPath = 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x86' }
  $reg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
  $installed = ($reg -ne $null) -and ($reg.Installed -eq 1)
  $verText = [string]$reg.Version
  $dllDir = 'C:\\Windows\\System32'
  if ($arch -eq 'x86') { $dllDir = 'C:\\Windows\\SysWOW64' }
  $missing = @()
  $vcDlls = ConvertFrom-Json ('${JSON.stringify(KEY_DLLS).replace(/'/g, "''")}')
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
    foreach ($m in $missing) { $it.evidence += ($dllDir + '\\' + $m + ' 缺失') }
    $it.repair = @{ id = 'vc-' + $arch; name = 'VC++ 2015-2022 ' + $arch.ToUpper() }
  } else {
    $it.status = 'fail'
    $it.detail = 'VC++ 2015-2022 ' + $arch + ' 未安装'
    $it.evidence += '注册表：未安装'
    foreach ($m in $missing) { $it.evidence += ($dllDir + '\\' + $m + ' 缺失') }
    $it.repair = @{ id = 'vc-' + $arch; name = 'VC++ 2015-2022 ' + $arch.ToUpper() }
  }
  $items += $it
}

# ---------- 2. .NET Framework 4.x ----------
$netItem = @{ id = 'netfx4x'; status = 'unknown'; evidence = @(); detail = ''; repair = $null }
$ndp4 = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full' -ErrorAction SilentlyContinue
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
$ndp35 = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5' -ErrorAction SilentlyContinue
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
  $in64 = Test-Path (Join-Path 'C:\\Windows\\System32' $dll)
  $in86 = Test-Path (Join-Path 'C:\\Windows\\SysWOW64' $dll)
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
  if (-not (Test-Path (Join-Path 'C:\\Windows\\System32' $dll))) {
    $dxItem.status = 'fail'
    $dxItem.evidence += ('System32\\' + $dll + ' 缺失（DX12 系统组件，建议系统文件修复）')
  }
}
$items += $dxItem

# ---------- 5. 旧版 VC++ 2005-2013（信息级列举，不判定不修复） ----------
$oldVc = @()
$uninstKeys = @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*')
foreach ($k in $uninstKeys) {
  Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
    $dn = [string]$_.'DisplayName'
    if ($dn -match '^Microsoft Visual C\\+\\+ (2005|2008|2010|2012|2013) Redistributable') { $oldVc += $dn }
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
`;
}

// 修复脚本：本地安装包静默执行（路径由主进程生成，渲染层不传任何路径/参数）
// netfx35 走 DISM（需联网取源，失败时给人工指引，不静默重试）
function repair(actionId, installerPath) {
  if (!ALLOWED_ACTIONS.has(actionId)) throw new Error('未知的修复动作: ' + actionId);
  if (actionId === 'netfx35') {
    return HEADER + DIAG.PS_PREAMBLE + `
Write-Output '正在启用 .NET Framework 3.5（需要联网从 Windows Update 获取组件）...'
$result = Start-Process -FilePath 'dism.exe' -ArgumentList '/Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart' -Wait -PassThru -WindowStyle Hidden
Write-Output ('DISM 退出码: ' + $result.ExitCode)
if ($result.ExitCode -eq 0) {
  Write-Output '@@RESULT@@ok'
} elseif ($result.ExitCode -eq 3010) {
  Write-Output '启用成功，需重启电脑后完全生效'
  Write-Output '@@RESULT@@ok'
} else {
  Write-Output '启用失败。常见原因：Windows Update 不可用或被策略限制。'
  Write-Output '人工指引：挂载与系统版本一致的 Windows 安装镜像后执行'
  Write-Output 'DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:<镜像盘符>\\sources\\sxs'
  Write-Output '@@RESULT@@warn'
}
`;
  }
  const meta = INSTALLERS[actionId];
  if (!installerPath || !fsCheck(installerPath)) throw new Error('安装包不存在: ' + actionId);
  const safePath = String(installerPath).replace(/'/g, "''");
  return HEADER + DIAG.PS_PREAMBLE + `
Write-Output '正在安装 ${meta.name}（静默模式，请稍候）...'
$result = Start-Process -FilePath '${safePath}' -ArgumentList '${meta.args}' -Wait -PassThru
Write-Output ('安装程序退出码: ' + $result.ExitCode)
if ($result.ExitCode -eq 0) {
  Write-Output '@@RESULT@@ok'
} elseif ($result.ExitCode -eq 3010) {
  Write-Output '安装成功，需重启电脑后完全生效'
  Write-Output '@@RESULT@@ok'
} elseif ($result.ExitCode -eq 1638) {
  Write-Output '已安装相同或更新版本，无需重复安装'
  Write-Output '@@RESULT@@ok'
} else {
  Write-TFDiag -Stage 'runtimes.install' -Mutation 'partial' -Detail ('exit=' + $result.ExitCode)
  Write-Output ('安装失败，退出码 ' + $result.ExitCode)
  Write-Output '@@RESULT@@warn'
}
`;
}

// 简单的存在性检查（repair 生成前的本地包校验）
function fsCheck(p) {
  try { return require('fs').existsSync(p); } catch (e) { return false; }
}

function listActions() {
  return Object.keys(INSTALLERS).map(id => ({ id, ...INSTALLERS[id] }));
}

module.exports = { status, repair, INSTALLERS, ALLOWED_ACTIONS, NETFX_RELEASE_MAP, listActions };
