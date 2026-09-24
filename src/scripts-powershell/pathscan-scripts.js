// pathscan-scripts.js - 安装路径自动扫描 PowerShell 脚本
// 路径解析优先级（经调研微软官方文档与通行实践确定）：
//   1. 已知候选目录（各家固定安装位置，命中即最快返回）
//   2. App Paths 注册表（HKLM/HKCU \...\App Paths\<exe> 默认值直接给出主程序全路径，最精准）
//   3. 卸载注册表（Uninstall 的 InstallLocation > DisplayIcon > UninstallString，
//      注意 DisplayIcon 常带图标索引后缀如 "foo.exe,0"，解析时必须剥离）
//   4. 开始菜单快捷方式（WScript.Shell 解析 .lnk 的 TargetPath，兜底无注册表信息的 excerpts）
// 参考 lizi/laji-lizi 的软件路径绑定思路，但输出保持当前 Electron IPC 契约。
//
// 任务3：扫描应用的「安装/文件/缓存目录候选」与清理规则库共用同一数据源——
// main.js 注入当前生效规则 JSON（含在线更新与自定义合并），本脚本优先取
// 规则的 candidatesPs / globCandidatesPs 求值结果，内置候选降级为兜底。

const fs = require('fs');
const path = require('path');
// v2.2 第 2 批（D1）：规则候选表达式（candidatesPs/globCandidatesPs）改用受限求值器，
// 与 cleanup-scripts 共用同一定义。这里的求值分支是**活代码**（键名与 JSON 一致），
// 且读的规则 JSON 由 main.js 注入「当前生效版本」——含不验签的自定义规则目录，
// 原先等于把不可信文件内容直接喂给 Invoke-Expression，是本批最高优先级的收口点。
const { RULE_PATH_EVAL_PS } = require('../main/ps-rule-path-eval');

const BUILTIN_RULES_FILE = path.join(__dirname, '..', 'data', 'cleanup-rules.json');
const DATA_RULES_FILE = path.join(process.env.APPDATA || path.join(require('os').homedir(), 'AppData', 'Roaming'), 'Trim', 'cleanup', 'rules.json');

function psEscapeSingle(s) {
  return String(s).replace(/'/g, "''");
}

// 读取生效规则（数据目录优先，与 cleanup-scripts.loadRules 同语义；失败返回空串走兜底）
function loadEffectiveRulesJson() {
  for (const file of [DATA_RULES_FILE, BUILTIN_RULES_FILE]) {
    try {
      if (fs.existsSync(file)) {
        const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (parsed && Array.isArray(parsed.groups)) return JSON.stringify(parsed);
      }
    } catch (e) { /* 读取失败尝试下一级 */ }
  }
  return '';
}

const SCAN_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$rulesJson = '\${RULES_JSON_PLACEHOLDER}'

${RULE_PATH_EVAL_PS}
$results = @{}
$script:inventory = @()

function Normalize-Path([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
  $v = [Environment]::ExpandEnvironmentVariables($Value.Trim().Trim('"'))
  # 兼容 DisplayIcon / UninstallString 的 "路径,图标索引" 后缀（如 app.exe,0）
  if ($v -match '^(.*?)\\.(exe|dll|msi|cmd|bat)(?:\\s*,\\s*\\d+)?(?:\\s+.*)?$') { $v = ($Matches[1] + '.' + $Matches[2]) }
  try { return [IO.Path]::GetFullPath($v).TrimEnd('\\') } catch { return $v.TrimEnd('\\') }
}

# ---- App Paths 解析：QQ.exe / WeChat.exe 等主程序在此登记全路径 ----
function Resolve-FromAppPaths([string]$ExeName) {
  foreach ($root in @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths',
                      'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths',
                      'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths')) {
    $keyPath = Join-Path $root $ExeName
    if (-not (Test-Path -LiteralPath $keyPath)) { continue }
    try {
      $exe = Normalize-Path ([string](Get-ItemPropertyValue -LiteralPath $keyPath -Name '(default)' -ErrorAction SilentlyContinue))
      if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) { return (Split-Path -Parent $exe) }
    } catch {}
  }
  return ''
}

# ---- 开始菜单快捷方式解析：一次构建 名称模式可匹配的 lnk 目标缓存 ----
$script:startMenuTargets = $null
function Get-StartMenuTargets {
  if ($null -ne $script:startMenuTargets) { return $script:startMenuTargets }
  $map = @{}
  $sh = New-Object -ComObject WScript.Shell
  foreach ($root in @(([Environment]::GetFolderPath('Programs')), ([Environment]::GetFolderPath('CommonPrograms')))) {
    if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)) { continue }
    foreach ($lnk in @(Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue)) {
      try {
        $target = Normalize-Path ([string]$sh.CreateShortcut($lnk.FullName).TargetPath)
        if ($target -and (Test-Path -LiteralPath $target -PathType Leaf)) { $map[$lnk.BaseName.ToLowerInvariant()] = $target }
      } catch {}
    }
  }
  $script:startMenuTargets = $map
  return $map
}

function Resolve-FromStartMenu([string[]]$Patterns) {
  $map = Get-StartMenuTargets
  foreach ($pattern in $Patterns) {
    $p = $pattern.ToLowerInvariant()
    foreach ($name in @($map.Keys)) {
      if ($name -match [regex]::Escape($p)) { return (Split-Path -Parent $map[$name]) }
    }
  }
  return ''
}

function Resolve-InstallPath([object]$Entry) {
  $candidates = @()
  if ($Entry.InstallLocation) { $candidates += [string]$Entry.InstallLocation }
  if ($Entry.DisplayIcon) { $candidates += [string]$Entry.DisplayIcon }
  if ($Entry.UninstallString) { $candidates += [string]$Entry.UninstallString }
  foreach ($candidate in $candidates) {
    $normalized = Normalize-Path $candidate
    if (-not $normalized) { continue }
    if (Test-Path -LiteralPath $normalized -PathType Leaf) { return (Split-Path -Parent $normalized) }
    if (Test-Path -LiteralPath $normalized -PathType Container) { return $normalized }
    if ($candidate -match '^\\s*"([^"]+\\.(exe|msi))"') {
      $exe = Normalize-Path $Matches[1]
      if (Test-Path -LiteralPath $exe) { return (Split-Path -Parent $exe) }
    }
  }
  return ''
}

function Add-InventoryEntry([object]$Entry, [string]$Source) {
  $name = [string]$Entry.DisplayName
  if ([string]::IsNullOrWhiteSpace($name)) { return }
  if ([string]$Entry.SystemComponent -eq '1' -or [string]$Entry.ReleaseType -match '(?i)update|hotfix|security') { return }
  $install = Resolve-InstallPath $Entry
  if (-not $install) { return }
  $key = (($name.Trim().ToLowerInvariant()) + '|' + $install.ToLowerInvariant())
  if ($script:inventoryKeys.ContainsKey($key)) { return }
  $script:inventoryKeys[$key] = $true
  $script:inventory += [pscustomobject]@{
    name = $name.Trim()
    version = [string]$Entry.DisplayVersion
    publisher = [string]$Entry.Publisher
    installPath = $install
    source = $Source
    uninstallKey = [string]$Entry.PSPath
  }
}

$script:inventoryKeys = @{}
$uninstallRoots = @(
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
foreach ($root in $uninstallRoots) {
  foreach ($entry in @(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
    Add-InventoryEntry $entry $root
  }
}

function Find-InstalledMatch([string[]]$Patterns) {
  foreach ($entry in @($script:inventory)) {
    if ($entry.name -match ('(?i)' + (($Patterns | ForEach-Object { [regex]::Escape($_) }) -join '|'))) { return $entry.installPath }
  }
  return ''
}

function First-Existing([string[]]$Candidates) {
  foreach ($candidate in $Candidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
    $normalized = Normalize-Path $candidate
    if (Test-Path -LiteralPath $normalized -PathType Container) { return $normalized }
  }
  return ''
}

# 应用安装目录：已知目录 → App Paths → 卸载注册表 → 开始菜单快捷方式，多级兜底避免只依赖固定盘符。
$results.qqInstallPath = First-Existing @(
  ($env:LOCALAPPDATA + '\\Programs\\Tencent\\QQNT'),
  ($env:PROGRAMFILES + '\\Tencent\\QQNT'),
  (\${env:ProgramFiles(x86)} + '\\Tencent\\QQNT'),
  (Resolve-FromAppPaths 'QQ.exe'),
  (Find-InstalledMatch @('QQ')),
  (Resolve-FromStartMenu @('QQ'))
)
if (-not $results.qqInstallPath) { $results.qqInstallPath = First-Existing @($env:LOCALAPPDATA + '\\Tencent\\QQNT') }

$results.wechatInstallPath = First-Existing @(
  ($env:LOCALAPPDATA + '\\Programs\\Tencent\\WeChat'),
  ($env:PROGRAMFILES + '\\Tencent\\WeChat'),
  (\${env:ProgramFiles(x86)} + '\\Tencent\\WeChat'),
  (Resolve-FromAppPaths 'WeChat.exe'),
  (Resolve-FromAppPaths 'WeChatApp.exe'),
  (Find-InstalledMatch @('WeChat', '微信')),
  (Resolve-FromStartMenu @('WeChat', '微信'))
)

$results.douyinInstallPath = First-Existing @(
  ($env:LOCALAPPDATA + '\\Douyin'),
  ($env:LOCALAPPDATA + '\\Programs\\Douyin'),
  ($env:LOCALAPPDATA + '\\TikTok'),
  (Resolve-FromAppPaths 'Douyin.exe'),
  (Find-InstalledMatch @('Douyin', '抖音', 'TikTok')),
  (Resolve-FromStartMenu @('Douyin', '抖音'))
)

$results.neteaseMusicInstallPath = First-Existing @(
  ($env:LOCALAPPDATA + '\\Programs\\Netease\\CloudMusic'),
  ($env:PROGRAMFILES + '\\CloudMusic'),
  (\${env:ProgramFiles(x86)} + '\\CloudMusic'),
  ($env:PROGRAMFILES + '\\Netease\\CloudMusic'),
  (Resolve-FromAppPaths 'CloudMusic.exe'),
  (Find-InstalledMatch @('CloudMusic', '网易云音乐')),
  (Resolve-FromStartMenu @('CloudMusic', '网易云音乐'))
)

# 任务3：从规则库取应用「安装/文件/缓存目录候选」（candidatesPs/globCandidatesPs 求值）。
# 规则库经 main.js 注入当前生效版本（在线更新/自定义规则即时同步）；解析失败走内置兜底。
$ruleCacheCandidates = @{ neteaseMusicCache = @(); qqCache = @(); douyinCache = @() }
$ruleWechatGlobs = @()
try {
  if ($rulesJson) {
    $rules = ConvertFrom-Json -InputObject $rulesJson
    $ruleMap = @{}
    foreach ($g in $rules.groups) {
      if ($g.subGroups) { foreach ($sg in $g.subGroups) { foreach ($it in $sg.items) { $ruleMap[$it.id] = $it } } }
      elseif ($g.items) { foreach ($it in $g.items) { $ruleMap[$it.id] = $it } }
    }
    foreach ($id in @('neteaseMusicCache', 'qqCache', 'douyinCache')) {
      $r = $ruleMap[$id]
      if ($r -and $r.candidatesPs) {
        foreach ($expr in @($r.candidatesPs)) {
          if (-not $expr) { continue }
          $rc = Resolve-RulePath -Expr ([string]$expr)
          if ($rc.ok -and $rc.path) { $ruleCacheCandidates[$id] += [string]$rc.path }
        }
      }
    }
    $w = $ruleMap['wechatCache']
    if ($w -and $w.globCandidatesPs) {
      foreach ($expr in @($w.globCandidatesPs)) {
        if (-not $expr) { continue }
        $rg = Resolve-RulePath -Expr ([string]$expr)
        if ($rg.ok -and $rg.path) { $ruleWechatGlobs += [string]$rg.path }
      }
    }
  }
} catch {}

# 用户数据目录。xwechat_files 下按最近修改时间选择用户目录，避免固定 wxid 失效。
$qqFileCandidates = @(
  ($env:USERPROFILE + '\\Documents\\Tencent Files'),
  ($env:USERPROFILE + '\\Documents\\QQ Files'),
  ($env:APPDATA + '\\Tencent\\QQ\\Files')
)
$results.qqFileDir = First-Existing $qqFileCandidates

$wxRootCandidates = @(
  ($env:USERPROFILE + '\\Documents\\xwechat_files'),
  ($env:USERPROFILE + '\\Documents\\WeChat Files')
)
$wxRoot = First-Existing $wxRootCandidates
$results.wechatFileDir = $wxRoot

$wxTemp = ''
if ($wxRoot -and (Split-Path -Leaf $wxRoot) -ne 'xwechat_files' -and (Split-Path -Leaf $wxRoot) -ne 'WeChat Files') {
  $wxTemp = Join-Path $wxRoot 'temp'
} else {
  # 任务3：glob 候选优先取规则库；按最近修改时间选择用户目录，避免固定 wxid 失效
  $wxGlobPatterns = @($ruleWechatGlobs)
  if ($wxGlobPatterns.Count -eq 0) {
    $wxGlobPatterns = @(
      ($env:USERPROFILE + '\\Documents\\xwechat_files\\*\\temp'),
      ($env:USERPROFILE + '\\Documents\\WeChat Files\\*\\FileStorage\\Cache')
    )
  }
  foreach ($pat in $wxGlobPatterns) {
    $wxTemp = Get-ChildItem -Path $pat -Directory -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
    if ($wxTemp) { break }
  }
}

# 缓存目录供清理模块复用；找不到时保留空值，绝不写入猜测路径。
# 任务3：候选目录优先取规则库求值结果（在线更新/自定义规则即时同步），内置候选兜底。
$results.neteaseCacheDir = First-Existing @(
  $ruleCacheCandidates['neteaseMusicCache'] +
  @(
    ($env:LOCALAPPDATA + '\\NetEase\\CloudMusic\\Cache'),
    ($env:LOCALAPPDATA + '\\Netease\\CloudMusic\\Cache'),
    ($env:APPDATA + '\\NetEase\\CloudMusic\\Cache')
  )
)
$results.wechatCacheDir = $wxTemp
$results.douyinCacheDir = First-Existing @(
  $ruleCacheCandidates['douyinCache'] +
  @(($env:LOCALAPPDATA + '\\Douyin'), ($env:LOCALAPPDATA + '\\TikTok'))
)
$results.qqCacheDir = First-Existing @(
  $ruleCacheCandidates['qqCache'] +
  @(
    ($env:LOCALAPPDATA + '\\Tencent\\QQNT\\User Data\\Cache'),
    ($env:APPDATA + '\\Tencent\\QQ\\Cache'),
    ($env:APPDATA + '\\Tencent Files\\Cache')
  )
)

$results.softwareInventory = @($script:inventory | Sort-Object name, installPath)
$results.scanVersion = 2
$results.scannedAt = (Get-Date).ToString('o')
$results | ConvertTo-Json -Compress -Depth 6
`;

module.exports = {
  // rulesJson：main.js 注入的当前生效规则库（在线更新/自定义合并后）；空串时走内置兜底
  scan(rulesJson = '') {
    const payload = typeof rulesJson === 'string' && rulesJson ? rulesJson : loadEffectiveRulesJson();
    return SCAN_SCRIPT.replace('\u0024{RULES_JSON_PLACEHOLDER}', () => psEscapeSingle(payload));
  }
};
