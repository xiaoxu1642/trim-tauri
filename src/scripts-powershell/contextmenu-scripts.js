// 右键菜单扫描 / 备份 / 删除 PowerShell 脚本
// 扫描逻辑对齐参考实现 ContextMenuManager（BluePointLilac）：
//   - 场景路径常量（MENUPATH_*）：HKCR\* / Folder / Directory / Background / DesktopBackground /
//     Drive / AllFilesystemObjects / CLSID\{20D04FE0}(此电脑) / CLSID\{645FF040}(回收站) /
//     LibraryFolder(库) / SystemFileAssociations\.exe(exe) 等
//   - Shell 项菜单名解析：MUIVerb(含 @dll,-id 资源串) > 默认值(非多级菜单) > 键名
//   - ShellEx 项：GUID 从键默认值解析，失败回退键名本身；名称取 CLSID
//     LocalizedString/InfoTip/默认值 > InprocServer32 DLL 的 FileDescription > 键名
//   - 厂商：DLL VersionInfo.CompanyName > CLSID 键 Company 值
//   - 去重：同一场景内 keyName 去重 + 全局 category|name|clsid 去重；跳过
//     -ContextMenuHandlers 禁用前缀键（规避幽灵项与重复扫描）
// 扫描分类：文件、EXE文件、LNK文件、目录、文件夹、驱动器、回收站、目录背景、
//           桌面背景、此电脑、库、发送到、UWP应用

const DIAG = require('../main/diag');

const SCAN_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
\$OutputEncoding = [System.Text.Encoding]::UTF8
\$ErrorActionPreference = 'SilentlyContinue'
\$ProgressPreference = 'SilentlyContinue'

\$script:results = @()

# ==================== 间接资源串解析（@shell32.dll,-30345 形式） ====================
# 对齐参考实现 ResourceString.GetDirectString：LoadLibrary + LoadString
if (-not ('WinCleanRes' -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class WinCleanRes {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr LoadLibraryW(string lpFileName);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool FreeLibrary(IntPtr hModule);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern int LoadStringW(IntPtr hInstance, int uID, StringBuilder lpBuffer, int nBufferMax);
  public static string GetString(string dllPath, int id) {
    IntPtr h = LoadLibraryW(dllPath);
    if (h == IntPtr.Zero) return null;
    try {
      StringBuilder sb = new StringBuilder(1024);
      int len = LoadStringW(h, id, sb, sb.Capacity);
      return len > 0 ? sb.ToString() : null;
    } finally { FreeLibrary(h); }
  }
}
"@
}

function Get-ResourceString {
  param([string]\$Ref)
  if ([string]::IsNullOrWhiteSpace(\$Ref)) { return \$null }
  \$m = [regex]::Match(\$Ref.Trim(), '^@\\s*([^,]+?)\\s*,\\s*-(\\d+)')
  if (-not \$m.Success) { return \$null }
  \$dllPath = \$m.Groups[1].Value.Trim('"').Trim()
  if ([string]::IsNullOrWhiteSpace(\$dllPath)) { return \$null }
  \$dllPath = [Environment]::ExpandEnvironmentVariables(\$dllPath)
  if (-not (\$dllPath -match '[\\\\/]')) {
    # 相对库名（如 shell32.dll）：尝试系统目录
    \$sysCandidate = Join-Path \$env:WINDIR ('System32\\' + \$dllPath)
    if (Test-Path -LiteralPath \$sysCandidate) { \$dllPath = \$sysCandidate }
  }
  if (-not (Test-Path -LiteralPath \$dllPath)) { return \$null }
  try { return [WinCleanRes]::GetString(\$dllPath, [int]\$m.Groups[2].Value) } catch { return \$null }
}

# 直接字符串：@ 引用串优先走资源解析，解析失败回退原文
function Get-DirectString {
  param([string]\$Value)
  if ([string]::IsNullOrWhiteSpace(\$Value)) { return '' }
  \$v = \$Value.Trim()
  if (\$v.StartsWith('@')) {
    \$resolved = Get-ResourceString \$v
    if (\$resolved) { return \$resolved }
    return ''
  }
  return \$v
}

# ==================== 工具 ====================
function Test-GuidText {
  param([string]\$Text)
  if ([string]::IsNullOrWhiteSpace(\$Text)) { return \$false }
  return \$Text.Trim() -match '^\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}\$'
}

# PSPath -> 标准注册表路径（HKEY_CLASSES_ROOT\\...，去除 Registry:: 提供程序前缀）
function Convert-ToStdRegPath {
  param([string]\$PsPath)
  return ([string]\$PsPath) -replace '^Microsoft\\.PowerShell\\.Core\\\\Registry::', ''
}

# HKCR -> 真实 hive 路径（审查 CM-9，2026-09-19）
#   根因：HKEY_CLASSES_ROOT 是 HKCU\\Software\\Classes 与 HKLM\\SOFTWARE\\Classes 的合并视图，
#   PowerShell 提供程序按「HKCU 优先」解析，所以经 HKCR 路径删除删掉的是 HKCU 那份；
#   但 reg.exe 的 HKCR 别名在 **import** 时落到 HKLM\\SOFTWARE\\Classes。
#   实测复现：项建在 HKCU -> 经 HKCR 导出 -> 删除 -> reg import -> 恢复到 HKLM（变成全机项，
#   且再删需要管理员）。故所有写入/导出/导入一律用真实 hive 路径。
#   解析顺序必须与合并视图一致：HKCU 命中即取，否则 HKLM，都无则原样返回。
function Resolve-NativeRegPath {
  param([string]\$StdPath)
  \$p = ([string]\$StdPath) -replace '^Registry::', ''
  if (\$p -notmatch '^HKEY_CLASSES_ROOT(\\\\|\$)') { return \$p }
  \$rest = \$p -replace '^HKEY_CLASSES_ROOT\\\\?', ''
  \$cu = 'HKEY_CURRENT_USER\\Software\\Classes\\' + \$rest
  if (Test-Path -LiteralPath ('Registry::' + \$cu)) { return \$cu }
  \$lm = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\' + \$rest
  if (Test-Path -LiteralPath ('Registry::' + \$lm)) { return \$lm }
  return \$p
}

# 动词隐藏判据（四值模型）—— 必须与 TOGGLE_SCRIPT 的写入端严格对称，
# 否则会出现「写 A 判据、按 B 判据读回」的假状态（本机实测有 3 项被判成已启用而菜单里根本没有）。
#   LegacyDisable            : 经典禁用动词
#   ProgrammaticAccessOnly   : 仅程序可调用，不显示在菜单（Win11 常用）
#   HideBasedOnVelocityId    : 0x639bc8 = 系统按特性开关隐藏的动词
#   CommandFlags             : 低 4 位含 0x8 视为隐藏
#   Blocked                  : Trim 早期一并读取的兼容值，保留
function Test-VerbHidden {
  param(\$Key)
  if (\$null -eq \$Key) { return \$false }
  foreach (\$vn in @('LegacyDisable', 'Blocked', 'ProgrammaticAccessOnly')) {
    if (\$null -ne \$Key.GetValue(\$vn)) { return \$true }
  }
  \$velocity = \$Key.GetValue('HideBasedOnVelocityId')
  if (\$null -ne \$velocity) { try { if ([int]\$velocity -eq 0x639bc8) { return \$true } } catch {} }
  \$flags = \$Key.GetValue('CommandFlags')
  if (\$null -ne \$flags) { try { if ((([int]\$flags) % 16) -ge 8) { return \$true } } catch {} }
  return \$false
}

# 「打开 / 浏览」类动词保护（对齐参考实现 ShellItem.TryProtectOpenItem / ProtectedMenuItemGuard）：
# 这类动词被禁用后用户最容易感知为「双击打不开了」，必须走红色二次确认。
function Get-VerbConfirm {
  param([string]\$VerbName)
  \$v = ([string]\$VerbName).ToLowerInvariant()
  if (\$v -eq 'open' -or \$v -eq 'explore') {
    return @{ required = \$true; reason = '该项是对象的基础「打开/浏览」动词，禁用或删除后双击与默认打开行为可能改变' }
  }
  return @{ required = \$false; reason = '' }
}

# 清洗字符串：移除会导致 JSON / UTF-8 输出损坏的字符
# （孤立代理 U+D800~U+DFFF、非字符 U+FFFE/U+FFFF、控制字符 U+0000~U+001F 与 U+007F）
# 这些字符常见于注册表脏数据，会破坏 JSON 字符串终止引号
function Format-CleanStr {
  param([string]\$s)
  if ([string]::IsNullOrEmpty(\$s)) { return '' }
  \$sb = New-Object System.Text.StringBuilder
  foreach (\$ch in \$s.ToCharArray()) {
    \$cp = [int][char]\$ch
    if (\$cp -lt 0x20) { continue }
    if (\$cp -eq 0x7f) { continue }
    if (\$cp -ge 0xD800 -and \$cp -le 0xDFFF) { continue }
    if (\$cp -eq 0xFFFE -or \$cp -eq 0xFFFF) { continue }
    \$null = \$sb.Append(\$ch)
  }
  return \$sb.ToString()
}

# 安全 JSON 序列化：手工拼出合法 JSON 字符串字面量，把所有非 ASCII 字符转义为 \\uXXXX，
# 使整段输出为纯 ASCII，彻底规避两类问题：
#   (1) PowerShell ConvertTo-Json 对注册表脏数据偶发丢失字符串终止引号的缺陷；
#   (2) 管道输出 UTF-8/UTF-16LE 编码不一致导致的中文乱码（\\uXXXX 与流编码无关，JSON.parse 可还原）。
function ConvertTo-JsonSafeString {
  param([string]\$s)
  if (\$null -eq \$s) { \$s = '' }
  \$s = [string]\$s
  \$sb = New-Object System.Text.StringBuilder
  \$null = \$sb.Append('"')
  foreach (\$ch in \$s.ToCharArray()) {
    \$cp = [int][char]\$ch
    if (\$cp -eq 34) { \$null = \$sb.Append('\\"'); }        # " 双引号
    elseif (\$cp -eq 92) { \$null = \$sb.Append('\\\\'); }    # \ 反斜杠
    elseif (\$cp -eq 8) { \$null = \$sb.Append('\\b'); }
    elseif (\$cp -eq 12) { \$null = \$sb.Append('\\f'); }
    elseif (\$cp -eq 10) { \$null = \$sb.Append('\\n'); }
    elseif (\$cp -eq 13) { \$null = \$sb.Append('\\r'); }
    elseif (\$cp -eq 9) { \$null = \$sb.Append('\\t'); }
    elseif (\$cp -lt 0x20 -or (\$cp -ge 0x7f -and \$cp -le 0x9f) -or \$cp -ge 0x80) {
      \$null = \$sb.Append('\\u' + \$cp.ToString('x4'))
    }
    else { \$null = \$sb.Append(\$ch) }
  }
  \$null = \$sb.Append('"')
  return \$sb.ToString()
}

function ConvertTo-JsonSafeBool {
  param([bool]\$b)
  if (\$b) { return 'true' } else { return 'false' }
}

\$protectedCLSIDs = @(
  '{20D04FE0-3AEA-1069-A2D8-08002B30309D}',
  '{450D8FBA-AD25-11D0-98A8-0800361B1103}',
  '{208D2C60-3AEA-1069-A2D2-08002B30309D}',
  '{1F4DE370-D627-11D1-BA4F-00A0C91EEDBA}',
  '{59031A47-3F72-35A7-89EC-6E8B9A8A5B5E}',
  '{59BE1D4E-E3A4-4D8A-91A3-69D69F66A4AC}',
  '{645FF040-5081-101B-9F08-00AA002F954E}'
)

\$knownSystem = @(
  'CopyAsPathMenu', 'FileExplorerClassic', 'ModernSharing', 'WorkFolders', 'EPP',
  'FileSyncConfig', 'OpenWithList', 'Open', 'Explore', 'find', 'printto', 'Properties',
  'RunAs', 'RunAsUser', 'CompatibilityPage', 'Map Network Drive', 'Disconnect Network Drive',
  'EmptyRecycleBin', 'Delete', 'Restore', 'Cut', 'Copy', 'Paste', 'Rename', 'open', 'explore',
  'opennewprocess', 'opennewtab', 'opennewwindow', 'pintohome', 'pintohomefile', 'runas',
  'runasuser', 'cmd', 'Powershell', 'change-passphrase', 'change-pin', 'encrypt-bde',
  'manage-bde', 'resume-bde', 'unlock-bde', 'empty', 'Personalize', 'Display',
  'DesktopSlideshow', 'New', 'Compatibility', 'OpenWith', 'PinToStartScreen', 'Preview',
  'edit', 'print', 'play', 'Set defaults', 'Sync', 'Share', 'GiveAccessTo', 'UpdatePerUserSystemParameters',
  '获取所有权', 'takeown', 'Print', 'PinToQuickAccess', 'UnpinFromQuickAccess', 'SyncCenter',
  'IncludeInLibrary', 'PinToStart', 'PinToTaskbar', 'PreviousVersions', 'ScanWithWindowsDefender',
  'Windows.ModernShare', 'Windows.Share', 'Windows.PinToHome', 'Windows.Cut', 'Windows.Copy',
  'Windows.Paste', 'Windows.Rename', 'Windows.Delete', 'Windows.Properties'
)

# ==================== CLSID 信息解析（对齐参考 GuidInfo.GetFilePath / GetText） ====================
# CLSID 查找视图：HKCR\\CLSID（主）、HKCR\\WOW6432Node\\CLSID、HKLM 32 位视图
\$clsidViews = @(
  'Registry::HKEY_CLASSES_ROOT\\CLSID',
  'Registry::HKEY_CLASSES_ROOT\\WOW6432Node\\CLSID',
  'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Wow6432Node\\CLSID'
)
\$script:clsidCache = @{}

function Get-ClsidInfo {
  param([string]\$GuidText)
  \$g = ([string]\$GuidText).Trim()
  \$empty = @{ name = ''; company = ''; filePath = '' }
  if (-not (Test-GuidText \$g)) { return \$empty }
  if (\$script:clsidCache.ContainsKey(\$g)) { return \$script:clsidCache[\$g] }

  \$info = @{ name = ''; company = ''; filePath = '' }
  foreach (\$view in \$clsidViews) {
    \$keyPath = '{0}\\{1}' -f \$view, \$g
    if (-not (Test-Path -LiteralPath \$keyPath)) { continue }
    try {
      \$key = Get-Item -LiteralPath \$keyPath -ErrorAction Stop
      # 名称链（对齐 GuidInfo.GetText）：LocalizedString > InfoTip > 默认值（均支持 @dll,-id 资源串）
      foreach (\$vn in @('LocalizedString', 'InfoTip', '')) {
        \$raw = if (\$vn) { [string]\$key.GetValue(\$vn) } else { [string]\$key.GetValue('') }
        \$resolved = Get-DirectString \$raw
        if (\$resolved) { \$info.name = \$resolved; break }
      }
      # 厂商：CLSID 键 Company 值
      \$companyRaw = [string]\$key.GetValue('Company')
      if (\$companyRaw) { \$info.company = \$companyRaw }
      # 文件路径（对齐 GuidInfo.GetFilePath：InprocServer32 > LocalServer32，CodeBase 优先）
      \$filePath = ''
      foreach (\$sub in @('InprocServer32', 'LocalServer32')) {
        \$serverKey = Get-Item -LiteralPath (\$keyPath + '\\' + \$sub) -ErrorAction SilentlyContinue
        if (-not \$serverKey) { continue }
        \$candidate = ''
        \$codeBase = [string]\$serverKey.GetValue('CodeBase')
        if (\$codeBase) {
          \$candidate = \$codeBase.Replace('file:///', '').Replace('/', '\\')
        }
        if (-not \$candidate) { \$candidate = ([string]\$serverKey.GetValue('')).Trim().Trim('"') }
        if (-not \$candidate) { continue }
        \$candidate = [Environment]::ExpandEnvironmentVariables(\$candidate)
        # 可执行命令可能带参数：提取实际文件路径
        if (\$candidate -match '^"([^"]+)"') { \$candidate = \$Matches[1] }
        elseif (\$candidate -match '^(\\S+\\.(dll|exe|ocx|cpl|sys))') { \$candidate = \$Matches[1] }
        if (\$candidate -and (Test-Path -LiteralPath \$candidate)) { \$filePath = \$candidate; break }
      }
      if (\$filePath) {
        \$info.filePath = \$filePath
        try {
          \$fileItem = Get-Item -LiteralPath \$filePath -ErrorAction SilentlyContinue
          if (\$fileItem -and \$fileItem.VersionInfo) {
            # 厂商优先取文件版本信息（比注册表 Company 值更可靠）
            if (\$fileItem.VersionInfo.CompanyName) { \$info.company = [string]\$fileItem.VersionInfo.CompanyName }
            # 名称回退：DLL 的 FileDescription（对齐参考实现最后回退链）
            if (-not \$info.name -and \$fileItem.VersionInfo.FileDescription) {
              \$info.name = [string]\$fileItem.VersionInfo.FileDescription
            }
          }
        } catch {}
      }
    } catch { continue }
    break
  }
  \$script:clsidCache[\$g] = \$info
  return \$info
}

# ==================== 第三方判定 ====================
function Is-ThirdParty {
  param([string]\$Name, [string]\$Company, [string]\$Source, [string]\$FilePath)
  # 微软厂商 → 系统原生
  if (\$Company -match '(?i)microsoft|windows\\s+(corp|corporation)') { return \$false }
  # 系统目录下的 DLL 且无厂商信息 → 系统组件（shell32/shellext 等未签名描述的扩展）
  if ([string]::IsNullOrWhiteSpace(\$Company) -and \$FilePath -match '(?i)^C:\\\\Windows\\\\') { return \$false }
  if (\$knownSystem -contains \$Name) { return \$false }
  if (\$Source -eq 'shell' -and \$Name -match '(?i)^@?.*(Windows|System32|shell32|themecpl|display)') { return \$false }
  if ([string]::IsNullOrWhiteSpace(\$Company) -and \$Name -match '^(Open|Explore|Properties|RunAs|新建|发送到|打开|打开方式|打开文件位置|打开所在位置|在资源管理器中打开|在.+中打开|固定到|固定|复制|剪切|粘贴|删除|重命名|属性|共享|压缩|添加到|发送|扫描|打印|编辑|播放|预览|打开文件|解压|挂载|装载)$') { return \$false }
  return \$true
}

// ==================== 结果收集 ====================
function Add-Result {
  param([string]\$Name, [string]\$CLSID, [string]\$RegPath, [string]\$Location,
        [string]\$Category, [string]\$Source, [string]\$CompanyOverride = '', [string]\$FilePath = '', [string]\$Command = '',
        [bool]\$Enabled = \$true, [bool]\$ConfirmRequired = \$false, [string]\$ConfirmReason = '', [bool]\$UnknownConvention = \$false,
        [string]\$Target = '', [bool]\$Orphan = \$false)
  # 幽灵项过滤：无有效名称不输出
  if ([string]::IsNullOrWhiteSpace(\$Name)) { return }
  # 注册表类来源必须有有效路径，否则后续删除/启停/备份无法定位，直接丢弃
  if (\$Source -ne 'filesystem' -and [string]::IsNullOrWhiteSpace(\$RegPath)) { return }
  \$clsidText = ([string]\$CLSID).Trim()
  \$company = [string]\$CompanyOverride
  \$filePath = [string]\$FilePath
  if (Test-GuidText \$clsidText) {
    \$info = Get-ClsidInfo \$clsidText
    if (-not \$company) { \$company = \$info.company }
    if (-not \$filePath) { \$filePath = \$info.filePath }
  }
  \$isThirdParty = Is-ThirdParty -Name \$Name -Company \$company -Source \$Source -FilePath \$filePath
  \$isProtected = \$protectedCLSIDs -contains \$clsidText
  \$risk = if (\$isProtected) { 'protected' } elseif (\$isThirdParty) { 'high' } else { 'low' }
  # 失效残留（批次 C）：CLSID 登记还在、但 InprocServer32 指向的文件已经没了 —— 典型的卸载残留。
  # 只在「解析出了路径且路径不存在」时才判残留；解析不出路径的伪 CLSID（如 Taskband Pin /
  # Start Menu Pin 这类由 shell 内部实现的）不算，否则会误伤合法系统项。
  \$componentMissing = \$false
  if ((Test-GuidText \$clsidText) -and -not [string]::IsNullOrWhiteSpace(\$filePath)) {
    \$expandedPath = [Environment]::ExpandEnvironmentVariables(([string]\$filePath).Trim().Trim('"'))
    if (\$expandedPath -and -not (Test-Path -LiteralPath \$expandedPath)) { \$componentMissing = \$true }
  }
  \$orphanFlag = [bool]\$Orphan -or \$componentMissing
  \$orphanWhy = if (\$componentMissing) { '登记的处理程序文件已不存在（' + \$filePath + '）' } elseif ([bool]\$Orphan) { '列表里还挂着这个类型，但对应的 ShellNew 键已不存在' } else { '' }
  # CM-16（批次 B）：命中 Shell Extensions\\Blocked 的 CLSID，Explorer 根本不会加载它，
  # 等价于「已禁用」。这张表过去 Trim 完全看不见，被别的工具屏蔽过的项会显示成启用。
  \$blockedBy = ''
  if (\$clsidText -and \$script:blockedGuids.ContainsKey(\$clsidText.ToUpper())) {
    \$blockedBy = [string]\$script:blockedGuids[\$clsidText.ToUpper()]
    \$Enabled = \$false
  }
  # 快捷方式的「打开」处理器（ShellExc OpenWith/lnk open GUID）与 open 动词同等保护
  if (-not \$ConfirmRequired -and \$clsidText -ieq '{00021401-0000-0000-C000-000000000046}') {
    \$ConfirmRequired = \$true
    \$ConfirmReason = '该项承载快捷方式的「打开」行为，禁用后 .lnk 双击可能失效'
  }
  # nativeRegPath = 真实 hive 路径，所有写操作（删除/启停/备份）一律用它，见 Resolve-NativeRegPath；
  # 文件系统类来源（发送到 / Win+X）没有 hive 概念，原样保留
  \$isFileSource = (\$Source -eq 'filesystem' -or \$Source -eq 'winx')
  \$nativePath = if (\$isFileSource) { \$RegPath } else { Resolve-NativeRegPath \$RegPath }
  \$script:results += [pscustomobject]@{
    name = \$Name; clsid = \$clsidText; regPath = \$RegPath; nativeRegPath = \$nativePath; company = \$company
    location = \$Location; category = \$Category; source = \$Source; filePath = \$filePath; command = [string]\$Command
    isThirdParty = \$isThirdParty; isProtected = \$isProtected; risk = \$risk; enabled = \$Enabled
    confirmRequired = \$ConfirmRequired; confirmReason = \$ConfirmReason; unknownConvention = \$UnknownConvention
    blockedBy = \$blockedBy; target = [string]\$Target; orphan = \$orphanFlag; orphanReason = \$orphanWhy
  }
}

# ==================== Shell 项扫描（对齐 LoadShellItems + ShellItem 解析） ====================
# 菜单名优先级：MUIVerb(资源串解析) > 默认值(多级母菜单除外) > 键名
function Scan-ShellItems {
  param([string]\$Category, [string]\$ShellPath, [hashtable]\$SeenKeys)
  if (-not (Test-Path -LiteralPath \$ShellPath)) { return }
  \$shellKey = Get-Item -LiteralPath \$ShellPath -ErrorAction SilentlyContinue
  if (-not \$shellKey) { return }
  foreach (\$child in @(\$shellKey.GetSubKeyNames())) {
    try {
      # 同一场景内键名去重（多视图扫描防重复）
      if (\$SeenKeys.ContainsKey(\$child)) { continue }
      \$SeenKeys[\$child] = \$true
      \$keyPath = \$ShellPath + '\\' + \$child
      \$key = Get-Item -LiteralPath \$keyPath -ErrorAction Stop

      # 菜单名称（对齐 ShellItem.ItemText）
      \$name = Get-DirectString ([string]\$key.GetValue('MUIVerb'))
      if (-not \$name) {
        # 多级母菜单（SubCommands/ExtendedSubCommandsKey）不支持默认值作名称
        \$hasSub = [string]\$key.GetValue('SubCommands')
        \$extSub = [string]\$key.GetValue('ExtendedSubCommandsKey')
        if (-not \$hasSub -and -not \$extSub) {
          \$name = Get-DirectString ([string]\$key.GetValue(''))
        }
      }
      if (-not \$name) { \$name = \$child }

      # GUID 提取（对齐 ShellItem.Guid：command\\DelegateExecute > DropTarget\\CLSID > ExplorerCommandHandler）
      \$clsid = ''
      \$commandKey = Get-Item -LiteralPath (\$keyPath + '\\command') -ErrorAction SilentlyContinue
      if (\$commandKey) {
        \$v = [string]\$commandKey.GetValue('DelegateExecute')
        if (Test-GuidText \$v) { \$clsid = \$v.Trim() }
      }
      if (-not \$clsid) {
        \$dropKey = Get-Item -LiteralPath (\$keyPath + '\\DropTarget') -ErrorAction SilentlyContinue
        if (\$dropKey) {
          \$v = [string]\$dropKey.GetValue('CLSID')
          if (Test-GuidText \$v) { \$clsid = \$v.Trim() }
        }
      }
      if (-not \$clsid) {
        \$v = [string]\$key.GetValue('ExplorerCommandHandler')
        if (Test-GuidText \$v) { \$clsid = \$v.Trim() }
      }

      \$command = ''
      if (\$commandKey) { \$command = Get-DirectString ([string]\$commandKey.GetValue('')) }

      # 启用状态（审查 CM-10，2026-09-19）：改为四值可见性判据 Test-VerbHidden，与写入端对称。
      # 旧实现只看 LegacyDisable/Blocked，漏掉 ProgrammaticAccessOnly 与 HideBasedOnVelocityId，
      # 本机实测 3 项（\\*\\shell\\removeproperties、Folder\\shell\\explore、
      # AllFilesystemObjects\\shell\\OfflineFilesLaunchSyncCenter）被误判为「已启用」。
      \$enabled = -not (Test-VerbHidden \$key)
      # 键名以 AutorunsDisabled 开头（Autoruns 的重命名禁用约定，无下划线形式才是真实写法）
      \$unknownConv = \$false
      if (\$child -match '(?i)^AutorunsDisabled') {
        \$enabled = \$false
        \$unknownConv = \$true
        \$name = \$name + '（未识别的禁用约定）'
      }
      \$confirm = Get-VerbConfirm \$child
      Add-Result -Name \$name -CLSID \$clsid -RegPath (Convert-ToStdRegPath \$key.PSPath) -Location \$ShellPath -Category \$Category -Source 'shell' -Command \$command -Enabled \$enabled -ConfirmRequired \$confirm.required -ConfirmReason \$confirm.reason -UnknownConvention \$unknownConv
    } catch { continue }
  }
}

# ==================== ShellEx 项扫描（对齐 GetPathAndGuids） ====================
# 读取 ContextMenuHandlers（含禁用重命名形态）：
#   - 子键名以 '-' 开头（如 -Foo）→ 已禁用的单个处理器，输出时还原名称并标记 enabled=false
#   - 父键被改名为 '-ContextMenuHandlers' → 整组禁用，由 Scan-Scene 以 HandlersDirName 指定扫描
function Scan-ShellExHandlers {
  param([string]\$Category, [string]\$ShellExPath, [hashtable]\$SeenKeys, [string]\$HandlersDirName = 'ContextMenuHandlers')
  \$cmPath = \$ShellExPath + '\\' + \$HandlersDirName
  if (-not (Test-Path -LiteralPath \$cmPath)) { return }
  \$cmKey = Get-Item -LiteralPath \$cmPath -ErrorAction SilentlyContinue
  if (-not \$cmKey) { return }
  foreach (\$child in @(\$cmKey.GetSubKeyNames())) {
    try {
      # 启用状态与真实键名（'-' 前缀为禁用标记）
      \$enabled = \$true
      \$realName = [string]\$child
      if (\$realName.StartsWith('-')) { \$enabled = \$false; \$realName = \$realName.Substring(1) }
      if (-not \$realName) { continue }
      if (\$SeenKeys.ContainsKey(\$child)) { continue }
      \$SeenKeys[\$child] = \$true
      \$keyPath = \$cmPath + '\\' + \$child
      \$key = Get-Item -LiteralPath \$keyPath -ErrorAction Stop
      \$defaultValue = [string]\$key.GetValue('')
      # GUID：默认值优先，失败回退真实键名（对齐 GuidEx.TryParse(keyName)）
      \$guid = \$defaultValue
      if (-not (Test-GuidText \$guid)) { \$guid = \$realName }
      if (-not (Test-GuidText \$guid)) {
        # 审查 CM-11（2026-09-19）：解析不出 GUID 过去直接 continue，会把别人禁过的项
        # 完全吞掉（本机实测 4 处 Autoruns 约定项，其中 2 处就在 Trim 会扫的活跃组里），
        # 用户看到的是「干净」列表。现在如实输出为「已禁用 + 未识别约定」。
        if (\$realName -match '(?i)^AutorunsDisabled') {
          Add-Result -Name ('未识别的禁用项（' + \$realName + '）') -CLSID '' -RegPath (Convert-ToStdRegPath \$key.PSPath) -Location \$cmPath -Category \$Category -Source 'shellex' -Enabled \$false -UnknownConvention \$true
        }
        continue
      }
      \$guid = \$guid.Trim()

      \$info = Get-ClsidInfo \$guid
      # 名称（对齐 ShellExItem.ItemText）：CLSID 友好名 > (键名为 GUID 时用默认值) > 真实键名
      \$name = \$info.name
      if (-not \$name) {
        if ((Test-GuidText \$realName) -and \$defaultValue -and -not (Test-GuidText \$defaultValue)) {
          \$name = \$defaultValue
        } else {
          \$name = \$realName
        }
      }
      Add-Result -Name \$name -CLSID \$guid -RegPath (Convert-ToStdRegPath \$key.PSPath) -Location \$cmPath -Category \$Category -Source 'shellex' -CompanyOverride \$info.company -FilePath \$info.filePath -Enabled \$enabled
    } catch { continue }
  }
}

# ==================== 场景扫描（对齐 ShellList.LoadItems：shell + ShellEx 两个子树） ====================
function Scan-Scene {
  param([string]\$Category, [string[]]\$ScenePaths)
  foreach (\$scenePath in @(\$ScenePaths)) {
    if ([string]::IsNullOrWhiteSpace(\$scenePath)) { continue }
    if (-not (Test-Path -LiteralPath \$scenePath)) { continue }
    Scan-ShellItems -Category \$Category -ShellPath (\$scenePath + '\\shell') -SeenKeys @{}
    Scan-ShellExHandlers -Category \$Category -ShellExPath (\$scenePath + '\\ShellEx') -SeenKeys @{}
    # 整组禁用形态：父键改名为 '-ContextMenuHandlers'（其子键全部视为禁用项）
    Scan-ShellExHandlers -Category \$Category -ShellExPath (\$scenePath + '\\ShellEx') -SeenKeys @{} -HandlersDirName '-ContextMenuHandlers'
  }
}

# 注册表视图：HKCR 合并视图（主，天然合并 HKCU+HKLM）+ HKCU 显式视图（捕获被
# HKLM 同名键遮蔽的用户级项）+ HKLM 32 位视图（原路径 Software\\WOW6432Node\\Classes
# 实为无效路径，修正为 Software\\Classes\\Wow6432Node）
\$HKCR = 'Registry::HKEY_CLASSES_ROOT'
\$HKCU_CLASSES = 'Registry::HKEY_CURRENT_USER\\Software\\Classes'
\$HKLM_WOW64_CLASSES = 'Registry::HKEY_LOCAL_MACHINE\\Software\\Classes\\Wow6432Node'

# ---- Shell Extensions\\Blocked：Windows 原生的 COM 屏蔽表（CM-16，批次 B）----
# 值名就是 {CLSID}，命中即该扩展不被加载。HKCU=当前用户、HKLM=全机；机器级优先。
# 必须在任何 Add-Result 之前装载，因为它会改写条目的 enabled。
\$script:blockedGuids = @{}
\$script:blockedPaths = @{
  user    = 'Registry::HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Blocked'
  machine = 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Blocked'
}
foreach (\$scope in @('machine', 'user')) {
  \$bk = Get-Item -LiteralPath \$script:blockedPaths[\$scope] -ErrorAction SilentlyContinue
  if (-not \$bk) { continue }
  foreach (\$vn in @(\$bk.GetValueNames())) {
    \$g = ([string]\$vn).Trim()
    if (-not (Test-GuidText \$g)) { continue }
    # 先写 machine 再写 user：user 覆盖 machine，与 Explorer「用户级可解除机器级屏蔽」的语义一致
    \$script:blockedGuids[\$g.ToUpper()] = \$scope
  }
}

function Get-SceneViews {
  param([string]\$Suffix)
  return @(
    (\$HKCR + \$Suffix),
    (\$HKCU_CLASSES + \$Suffix),
    (\$HKLM_WOW64_CLASSES + \$Suffix)
  )
}

# ---- 场景清单（对齐参考 MENUPATH_* 常量与 Scenes 映射）----
# 文件（HKCR\\*，AllFilesystemObjects 归入文件分类）
Scan-Scene '文件' (Get-SceneViews '\\*')
Scan-Scene '文件' (Get-SceneViews '\\AllFilesystemObjects')
# EXE 文件（对齐 Scenes.ExeFile：exefile + SystemFileAssociations\\.exe）
Scan-Scene 'EXE文件' (Get-SceneViews '\\exefile')
Scan-Scene 'EXE文件' (Get-SceneViews '\\SystemFileAssociations\\.exe')
# LNK 文件
Scan-Scene 'LNK文件' (Get-SceneViews '\\lnkfile')
Scan-Scene 'LNK文件' (Get-SceneViews '\\SystemFileAssociations\\.lnk')
# 目录 / 文件夹 / 驱动器 / 目录背景 / 桌面背景
Scan-Scene '目录' (Get-SceneViews '\\Directory')
Scan-Scene '文件夹' (Get-SceneViews '\\Folder')
Scan-Scene '驱动器' (Get-SceneViews '\\Drive')
Scan-Scene '目录背景' (Get-SceneViews '\\Directory\\Background')
Scan-Scene '桌面背景' (Get-SceneViews '\\DesktopBackground')
# 回收站（对齐参考：CLSID\\{645FF040} 主路径 + RecycleBinFolder 补充）
Scan-Scene '回收站' @((\$HKCR + '\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}'), (\$HKCR + '\\RecycleBinFolder'))
# 此电脑（新增，对齐 MENUPATH_COMPUTER）
Scan-Scene '此电脑' @((\$HKCR + '\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}'))
# 库（新增，对齐 Scenes.Library：LibraryFolder + Background + UserLibraryFolder 三个子树）
Scan-Scene '库' @((\$HKCR + '\\LibraryFolder'), (\$HKCR + '\\LibraryFolder\\Background'), (\$HKCR + '\\UserLibraryFolder'))

# ---- 发送到（文件系统目录，非注册表） ----
\$sendToPaths = @(
  ([Environment]::GetFolderPath('ApplicationData') + '\\Microsoft\\Windows\\SendTo'),
  (\$env:ProgramData + '\\Microsoft\\Windows\\SendTo')
)
foreach (\$sendToPath in \$sendToPaths) {
  if (-not (Test-Path -LiteralPath \$sendToPath)) { continue }
  foreach (\$item in @(Get-ChildItem -LiteralPath \$sendToPath -Force -ErrorAction SilentlyContinue)) {
    if (\$item.Name -ieq 'desktop.ini') { continue }
    \$systemExtensions = @('.DeskLink', '.MAPIMail', '.ZFSendToTarget', '.mydocs')
    \$company = if (\$systemExtensions -contains \$item.Extension) { 'Microsoft Corporation' } else { '' }
    Add-Result -Name \$item.BaseName -CLSID '' -RegPath \$item.FullName -Location \$sendToPath -Category '发送到' -Source 'filesystem' -CompanyOverride \$company
  }
}

# ---- UWP / 打包应用（PackagedCom 与 FileExplorerContextMenus 合约） ----
\$uwpRoots = @('Registry::HKEY_CLASSES_ROOT\\PackagedCom',
              'Registry::HKEY_CURRENT_USER\\Software\\Classes\\PackagedCom',
              'Registry::HKEY_LOCAL_MACHINE\\Software\\Classes\\PackagedCom')
foreach (\$uwpRoot in \$uwpRoots) {
  if (-not (Test-Path -LiteralPath \$uwpRoot)) { continue }
  foreach (\$key in @(Get-ChildItem -LiteralPath \$uwpRoot -Recurse -ErrorAction SilentlyContinue)) {
    if (\$key.PSPath -notmatch '(?i)(ContextMenu|ShellExt|ExplorerCommand|IContextMenu)') { continue }
    \$props = Get-ItemProperty -LiteralPath \$key.PSPath -ErrorAction SilentlyContinue
    \$clsid = [string]\$props.'(default)'
    if (-not \$clsid) { continue }
    \$packageName = (\$key.PSPath -split '\\\\')[-2]
    if ([string]::IsNullOrWhiteSpace(\$packageName)) { \$packageName = [string]\$key.PSChildName }
    Add-Result -Name \$packageName -CLSID \$clsid -RegPath (Convert-ToStdRegPath \$key.PSPath) -Location \$uwpRoot -Category 'UWP应用' -Source 'packagedcom'
  }
}

\$uwpContractRoots = @('Registry::HKEY_CLASSES_ROOT\\Extensions\\ContractId\\Windows.FileExplorerContextMenus',
                      'Registry::HKEY_CURRENT_USER\\Software\\Classes\\Extensions\\ContractId\\Windows.FileExplorerContextMenus',
                      'Registry::HKEY_LOCAL_MACHINE\\Software\\Classes\\Extensions\\ContractId\\Windows.FileExplorerContextMenus')
foreach (\$contractRoot in \$uwpContractRoots) {
  if (-not (Test-Path -LiteralPath \$contractRoot)) { continue }
  foreach (\$key in @(Get-ChildItem -LiteralPath \$contractRoot -Recurse -ErrorAction SilentlyContinue)) {
    \$props = Get-ItemProperty -LiteralPath \$key.PSPath -ErrorAction SilentlyContinue
    \$packageName = [string]\$props.PackageId
    if (-not \$packageName -and \$key.PSPath -match '(?i)PackageId\\\\([^\\\\]+)') { \$packageName = \$Matches[1] }
    if (-not \$packageName) { continue }
    \$clsid = [string]\$props.Clsid
    if (-not \$clsid) { \$clsid = [string]\$props.'(default)' }
    Add-Result -Name \$packageName -CLSID \$clsid -RegPath (Convert-ToStdRegPath \$key.PSPath) -Location \$contractRoot -Category 'UWP应用' -Source 'uwp-contract'
  }
}

# ---- Win+X 菜单（批次 C：%LOCALAPPDATA%\\Microsoft\\Windows\\WinX\\Group{1,2,3}\\*.lnk）----
# 侧边栏一直有「Win+X」分类却没有任何数据源（死 tab）。Explorer 只列 .lnk，
# 所以可逆禁用 = 扩展名改成 .lnk.disabled；删除仍由主进程走回收站（source 归入文件类）。
\$winxRoot = Join-Path \$env:LOCALAPPDATA 'Microsoft\\Windows\\WinX'
foreach (\$group in @('Group1', 'Group2', 'Group3')) {
  \$gdir = Join-Path \$winxRoot \$group
  if (-not (Test-Path -LiteralPath \$gdir)) { continue }
  foreach (\$f in @(Get-ChildItem -LiteralPath \$gdir -Force -ErrorAction SilentlyContinue)) {
    if (\$f.PSIsContainer) { continue }
    if (\$f.Name -ieq 'desktop.ini') { continue }
    \$isOff = (\$f.Extension -ieq '.disabled')
    \$label = if (\$isOff) { ([string]\$f.BaseName -replace '(?i)\\.lnk\$', '') } else { [string]\$f.BaseName }
    if ([string]::IsNullOrWhiteSpace(\$label)) { continue }
    Add-Result -Name \$label -CLSID '' -RegPath \$f.FullName -Location \$gdir -Category 'Win+X' -Source 'winx' -CompanyOverride 'Microsoft Corporation' -Enabled (-not \$isOff)
  }
}

# ---- 新建菜单（批次 C：由 HKCU 的 PostSetup\\ShellNew 的 Classes 值驱动）----
# 「新建」子菜单出现哪些类型，取决于这张 REG_MULTI_SZ 列表；本机实测 10 项里
# .doc/.ppt/.xls 等已经没有对应的 ShellNew 键 = 卸载残留（悬空项），照样占着菜单位。
# 可逆禁用 = 从 Classes 列表摘掉该类名，不碰 ShellNew 键本身；整张表在 HKCU → 不需要管理员。
# 刻意不做全量 HKCR 扩展名枚举：那会让每次扫描多花数秒，而「有 ShellNew 却不在列表里」的类
# 本来就不会出现在菜单中，价值低。
\$postSetupStd = 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Discardable\\PostSetup\\ShellNew'
\$psKey = Get-Item -LiteralPath ('Registry::' + \$postSetupStd) -ErrorAction SilentlyContinue
if (\$psKey) {
  foreach (\$cls in @(\$psKey.GetValue('Classes'))) {
    \$c = ([string]\$cls).Trim()
    if ([string]::IsNullOrWhiteSpace(\$c)) { continue }
    \$hasShellNew = \$false
    foreach (\$view in @(\$HKCR, \$HKCU_CLASSES, \$HKLM_WOW64_CLASSES)) {
      if (Test-Path -LiteralPath (\$view + '\\' + \$c + '\\ShellNew')) { \$hasShellNew = \$true; break }
    }
    \$nm = if (\$hasShellNew) { ('新建 ' + \$c) } else { ('新建 ' + \$c + '（残留：无 ShellNew 键）') }
    Add-Result -Name \$nm -CLSID '' -RegPath \$postSetupStd -Location \$postSetupStd -Category '新建菜单' -Source 'shellnew' -CompanyOverride 'Microsoft Corporation' -Enabled \$true -Target \$c -Orphan (-not \$hasShellNew)
  }
}

# ---- 打开方式（批次 C：HKCR\\Applications\\<app>\\shell\\<verb>，禁用 = 写 NoOpenWith）----
\$appRoot = \$HKCR + '\\Applications'
if (Test-Path -LiteralPath \$appRoot) {
  foreach (\$app in @((Get-Item -LiteralPath \$appRoot -ErrorAction SilentlyContinue).GetSubKeyNames())) {
    \$appPath = \$appRoot + '\\' + \$app
    \$shellPath = \$appPath + '\\shell'
    if (-not (Test-Path -LiteralPath \$shellPath)) { continue }
    \$verbs = @((Get-Item -LiteralPath \$shellPath -ErrorAction SilentlyContinue).GetSubKeyNames())
    if (-not \$verbs.Count) { continue }
    \$appKey = Get-Item -LiteralPath \$appPath -ErrorAction SilentlyContinue
    if (-not \$appKey) { continue }
    \$friendly = Get-DirectString ([string]\$appKey.GetValue('FriendlyAppName'))
    if ([string]::IsNullOrWhiteSpace(\$friendly)) { \$friendly = \$app }
    \$noOpen = (\$null -ne \$appKey.GetValue('NoOpenWith'))
    Add-Result -Name \$friendly -CLSID '' -RegPath (Convert-ToStdRegPath \$appPath) -Location \$appRoot -Category '打开方式' -Source 'openwith' -Enabled (-not \$noOpen) -Command (\$verbs -join ', ')
  }
}
# *\\OpenWithList\\<app>：对所有文件生效的「打开方式」候选；禁用 = 键名加 '-' 前缀（与 shellex 同约定）
\$owlRoot = \$HKCR + '\\*\\OpenWithList'
if (Test-Path -LiteralPath \$owlRoot) {
  foreach (\$child in @((Get-Item -LiteralPath \$owlRoot -ErrorAction SilentlyContinue).GetSubKeyNames())) {
    \$real = [string]\$child
    \$en = \$true
    if (\$real.StartsWith('-')) { \$en = \$false; \$real = \$real.Substring(1) }
    if ([string]::IsNullOrWhiteSpace(\$real)) { continue }
    \$k = Get-Item -LiteralPath (\$owlRoot + '\\' + \$child) -ErrorAction SilentlyContinue
    if (-not \$k) { continue }
    Add-Result -Name (\$real + '（所有文件）') -CLSID '' -RegPath (Convert-ToStdRegPath \$k.PSPath) -Location \$owlRoot -Category '打开方式' -Source 'openwith-list' -Enabled \$en -Command ([string]\$k.GetValue(''))
  }
}

# ---- 全局去重：同一分类、名称、CLSID、启用状态在多个注册表视图中只展示一次 ----
# （enabled 参与去重：同名处理器可能在活跃组与 '-ContextMenuHandlers' 禁用组各出现一次）
# CM-9 附带修正：无 CLSID 的条目改用 nativeRegPath 作身份键。原来用 regPath（HKCR 合并视图路径），
# 同一物理键经 HKCR 与 HKCU 两个视图各扫一次时会留下两行（重复行 + 禁一半的观感来源）。
\$seen = @{}
\$deduped = @()
foreach (\$result in @(\$script:results)) {
  \$enabledText = if (\$result.enabled) { '1' } else { '0' }
  \$key = if ([string]::IsNullOrWhiteSpace([string]\$result.clsid)) {
    '{0}|{1}|{2}|{3}|{4}' -f \$result.category, \$result.name, \$result.source, \$result.nativeRegPath, \$enabledText
  } else {
    '{0}|{1}|{2}|{3}' -f \$result.category, \$result.name, \$result.clsid, \$enabledText
  }
  if (\$seen.ContainsKey(\$key)) { continue }
  \$seen[\$key] = \$true
  \$deduped += \$result
}
# ---- 手工构建合法 JSON（纯 ASCII：非 ASCII 字符转义为 \\uXXXX），彻底规避 ConvertTo-Json 对脏数据的缺陷 ----
\$jsonParts = @()
foreach (\$result in @(\$deduped)) {
  \$obj = '{' +
    '"name":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.name)) + ',' +
    '"clsid":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.clsid)) + ',' +
    '"regPath":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.regPath)) + ',' +
    '"nativeRegPath":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.nativeRegPath)) + ',' +
    '"company":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.company)) + ',' +
    '"location":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.location)) + ',' +
    '"category":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.category)) + ',' +
    '"source":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.source)) + ',' +
    '"filePath":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.filePath)) + ',' +
    '"command":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.command)) + ',' +
    '"isThirdParty":' + (ConvertTo-JsonSafeBool \$result.isThirdParty) + ',' +
    '"isProtected":' + (ConvertTo-JsonSafeBool \$result.isProtected) + ',' +
    '"confirmRequired":' + (ConvertTo-JsonSafeBool \$result.confirmRequired) + ',' +
    '"unknownConvention":' + (ConvertTo-JsonSafeBool \$result.unknownConvention) + ',' +
    '"orphan":' + (ConvertTo-JsonSafeBool \$result.orphan) + ',' +
    '"orphanReason":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.orphanReason)) + ',' +
    '"blockedBy":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.blockedBy)) + ',' +
    '"target":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.target)) + ',' +
    '"confirmReason":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.confirmReason)) + ',' +
    '"risk":' + (ConvertTo-JsonSafeString (Format-CleanStr \$result.risk)) + ',' +
    '"enabled":' + (ConvertTo-JsonSafeBool \$result.enabled) +
    '}'
  \$jsonParts += \$obj
}
if (\$jsonParts.Count -eq 0) { '[]' } else { '[' + (\$jsonParts -join ',') + ']' }
`;

const BACKUP_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
\$OutputEncoding = [System.Text.Encoding]::UTF8
\$ErrorActionPreference = 'SilentlyContinue'
\$items = '__ITEMS_JSON__' | ConvertFrom-Json
\$desktop = [Environment]::GetFolderPath('Desktop')
\$backupDir = Join-Path \$desktop ('右键菜单备份_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path \$backupDir -Force | Out-Null
\$filesDir = Join-Path \$backupDir 'files'
New-Item -ItemType Directory -Path \$filesDir -Force | Out-Null
\$backupFiles = @()
\$fileRecords = @()
\$index = 0

function Convert-ToRegPath([string]\$Path) {
  \$p = [string]\$Path
  \$p = \$p -replace '^.*?Registry::', ''
  \$p = \$p -replace '^HKEY_CLASSES_ROOT', 'HKCR'
  \$p = \$p -replace '^HKEY_CURRENT_USER', 'HKCU'
  \$p = \$p -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
  \$p = \$p -replace '^HKEY_USERS', 'HKU'
  return \$p
}

# 审查 CM-9（2026-09-19）：导出后校验 .reg 头部的 hive 与来源 hive 一致。
# 老实现把 HKCR（合并视图）路径直接交给 reg.exe，导出的 .reg 头是 [HKEY_CLASSES_ROOT\\...]，
# 而 reg.exe **import** 这种头时会写进 HKLM\\\\SOFTWARE\\\\Classes —— 于是「删掉自己用户的项、
# 恢复后变成全机项」。这里两头都堵：导出只用真实 hive 路径，导入前再校验一次头部。
function Get-RegFileHeaderHive([string]\$File) {
  if (-not (Test-Path -LiteralPath \$File)) { return '' }
  foreach (\$line in @(Get-Content -LiteralPath \$File -TotalCount 8 -ErrorAction SilentlyContinue)) {
    \$t = [string]\$line
    if (\$t.StartsWith('[')) {
      \$h = \$t.TrimStart('[')
      foreach (\$root in @('HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS')) {
        if (\$h.StartsWith(\$root)) { return \$root }
      }
      return 'OTHER'
    }
  }
  return ''
}

# CM-15（2026-09-19）：reg.exe 会把「操作已成功完成」写到 **stdout**，而本脚本的返回值也是
# stdout——主进程 JSON.parse(stdout) 会因此直接失败。这里统一走 Invoke-RegCmd：吞掉子进程
# 输出、只取退出码（结果一律用文件内容/注册表回读来验证）。
# 注意调用形式：函数用自动变量 \$args 接收，调用处写成 Invoke-RegCmd export \$k \$f '/y'。
# 不要写成 param([string[]]\$RegArgs) 再用 Invoke-RegCmd @('export', ...) 这种数组字面量调用
# —— 命令参数模式里的数组字面量会被拼成单个字符串传给 reg.exe，
# 报 Invalid Argument/Option '@export ...'。
function Invoke-RegCmd {
  \$eap = \$ErrorActionPreference
  \$ErrorActionPreference = 'SilentlyContinue'
  try { & reg.exe @args 2>\$null | Out-Null } finally { \$ErrorActionPreference = \$eap }
  return \$LASTEXITCODE
}

\$exported = 0
\$exportFailed = 0
\$regRecords = @()
foreach (\$item in @(\$items)) {
  \$index++
  \$source = [string]\$item.source
  \$regPath = [string]\$item.regPath
  # 文件类来源（发送到 / Win+X）走复制备份，绝不能掉进下面的 reg export 分支
  if (\$source -eq 'filesystem' -or \$source -eq 'winx') {
    if (-not (Test-Path -LiteralPath \$regPath)) { continue }
    \$name = 'file_{0}_{1}_{2}' -f \$index, ([IO.Path]::GetFileNameWithoutExtension(\$regPath)), ([IO.Path]::GetExtension(\$regPath).TrimStart('.'))
    \$dest = Join-Path \$filesDir \$name
    try { Copy-Item -LiteralPath \$regPath -Destination \$dest -Force -Recurse; \$fileRecords += [pscustomobject]@{ source = \$regPath; backup = \$dest }; \$backupFiles += \$dest } catch {}
    continue
  }
  # 一律用扫描阶段解析出的真实 hive 路径；缺失（旧缓存/异常）时退回 regPath 但仍拒绝 HKCR 头
  \$writePath = [string]\$item.nativeRegPath
  if ([string]::IsNullOrWhiteSpace(\$writePath)) { \$writePath = \$regPath }
  if ([string]::IsNullOrWhiteSpace(\$writePath)) { \$exportFailed++; continue }
  if (\$writePath -match '^HKEY_CLASSES_ROOT(?=\\\\|\$)') {
    # 无法归位到具体 hive（键已消失或解析失败）——不产备份，交由上层阻断删除
    \$exportFailed++
    continue
  }
  \$nativePath = Convert-ToRegPath \$writePath
  # CM-14（2026-09-19）：文件名必须连反斜杠一起替换。旧写法是正则字符类 '[\\\\/:*?...]'，
  # 但这段脚本活在 JS 模板字符串里，文件中的 \\\\\\\\ 经模板转义后只剩 \\\\，
  # 字符类里根本没有反斜杠 → 文件名带着路径分隔符 → reg.exe 报「Unable to write to the file」
  # → 注册表项备份从来没成功过，删除被自己的备份步骤阻断。
  # 这里改用 [IO.Path]::GetInvalidFileNameChars() + String.Replace：不写正则、不写转义，
  # 从根上没有二次转义陷阱（也别用 [string]\$x.ToCharArray()，那是把 char 数组拼成带空格字符串）。
  \$safeName = [string]\$nativePath
  foreach (\$ch in [IO.Path]::GetInvalidFileNameChars()) {
    \$safeName = \$safeName.Replace([string]\$ch, '_')
  }
  if (\$safeName.Length -gt 120) { \$safeName = \$safeName.Substring(\$safeName.Length - 120) }
  \$regFile = Join-Path \$backupDir ('registry_{0}_{1}.reg' -f \$index, \$safeName)
  try {
    \$expCode = Invoke-RegCmd export \$writePath \$regFile '/y'
    \$hdr = Get-RegFileHeaderHive \$regFile
    if (\$expCode -eq 0 -and \$hdr -and \$hdr -ne 'HKEY_CLASSES_ROOT' -and \$writePath.StartsWith(\$hdr)) {
      \$backupFiles += \$regFile; \$exported++
      \$regRecords += [pscustomobject]@{ source = \$writePath; backup = \$regFile; hive = \$hdr }
    } else {
      if (Test-Path -LiteralPath \$regFile) { Remove-Item -LiteralPath \$regFile -Force -ErrorAction SilentlyContinue }
      \$exportFailed++
    }
  } catch { \$exportFailed++ }
}

\$manifest = [pscustomobject]@{ version = 2; created = (Get-Date).ToString('o'); items = @(\$items); files = @(\$fileRecords); registryFiles = @(\$regRecords) }
\$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path \$backupDir 'manifest.json') -Encoding UTF8
[pscustomobject]@{ backupDir = \$backupDir; files = @(\$backupFiles); count = (\$exported + @(\$fileRecords).Count); exported = \$exported; copied = @(\$fileRecords).Count; failed = \$exportFailed } | ConvertTo-Json -Compress
`;

const REMOVE_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
\$OutputEncoding = [System.Text.Encoding]::UTF8
\$ErrorActionPreference = 'SilentlyContinue'
${DIAG.PS_PREAMBLE}
\$items = '__ITEMS_JSON__' | ConvertFrom-Json
\$success = 0
\$failed = 0
\$results = @()
foreach (\$item in @(\$items)) {
  if (\$item.risk -eq 'protected') { \$results += @{ name = \$item.name; status = 'skip'; message = '系统保护项' }; continue }
  # 复核 N1（删除红线，2026-09-16）：文件系统项（「发送到」快捷方式）不再在 PS 内裸删，
  # 主进程已改为 trashOrUnlink（回收站优先）+ 全局删除清单；本脚本若仍收到此类项，跳过并如实回报。
  if ([string]\$item.source -eq 'filesystem' -or [string]\$item.source -eq 'winx') {
    \$results += @{ name = \$item.name; status = 'skip'; message = '文件系统项由主进程回收站删除' }
    continue
  }
  try {
    # CM-9（2026-09-19）：删除也走真实 hive 路径，与备份/恢复同源；
    # 原来经 HKEY_CLASSES_ROOT 合并视图删，删的是「解析到的那一份」，与备份的 hive 可能对不上
    \$target = [string]\$item.nativeRegPath
    if ([string]::IsNullOrWhiteSpace(\$target)) { \$target = [string]\$item.regPath }
    if ([string]::IsNullOrWhiteSpace(\$target) -or \$target -match '(?i)^(Registry::)?HKEY_(CLASSES_ROOT|LOCAL_MACHINE|CURRENT_USER|USERS|CURRENT_CONFIG)\\\\?\$') {
      \$results += @{ name = \$item.name; status = 'skip'; message = '无效或过宽路径' }; continue
    }
    # 标准路径（HKEY_CURRENT_USER\\...）转 PowerShell 提供程序路径
    if (\$target -match '^HKEY_') { \$target = 'Registry::' + \$target }
    # R7（v3.6.6 M1）：ShellNew 项共享父键 PostSetup\ShellNew，-Recurse 会删整键连带其他 9 项。
    # ShellNew 的禁用/启用应通过修改 Classes 值列表实现（由启停通道处理），不走删除通道。
    if ([string]\$item.source -eq 'shellnew') {
      \$results += @{ id = [string]\$item.id; name = \$item.name; status = 'skip'; message = '新建菜单项请通过启停操作管理，禁止整键删除' }
      continue
    }
    if (Test-Path -LiteralPath \$target) {
      Remove-Item -LiteralPath \$target -Recurse -Force -ErrorAction Stop
      if (Test-Path -LiteralPath \$target) {
        \$failed++; \$results += @{ id = [string]\$item.id; name = \$item.name; status = 'error'; message = '删除后键仍存在（可能被占用或权限不足）' }
      } else {
        \$success++
        \$results += @{ id = [string]\$item.id; name = \$item.name; status = 'ok'; message = '已删除' }
      }
    } else { \$results += @{ id = [string]\$item.id; name = \$item.name; status = 'skip'; message = '路径不存在' } }
  } catch { \$failed++; Write-TFDiag -Stage 'contextmenu.remove' -Mutation 'rolled_back' -Detail ([string]\$item.regPath + ' -> ' + \$_.Exception.Message); \$results += @{ name = \$item.name; status = 'error'; message = \$_.Exception.Message } }
}
[pscustomobject]@{ success = \$success; failed = \$failed; results = @(\$results) } | ConvertTo-Json -Depth 6 -Compress
`;

const RESTORE_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
\$OutputEncoding = [System.Text.Encoding]::UTF8
\$ErrorActionPreference = 'SilentlyContinue'
\$desktop = [Environment]::GetFolderPath('Desktop')
\$backupDirs = Get-ChildItem -LiteralPath \$desktop -Directory -Filter '右键菜单备份_*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
if (-not \$backupDirs) { @{ success = \$false; message = '未找到备份目录' } | ConvertTo-Json -Compress; exit }
\$latestBackup = \$backupDirs[0].FullName
\$imported = 0
\$failed = 0
\$skipped = 0
\$skipReasons = @()

# CM-15：吞掉 reg.exe 的 stdout（否则污染本脚本的 JSON 返回值），只取退出码。
# 调用形式必须用 \$args 位置参数，不能用数组字面量（见 BACKUP_SCRIPT 同处的说明）。
function Invoke-RegCmd {
  \$eap = \$ErrorActionPreference
  \$ErrorActionPreference = 'SilentlyContinue'
  try { & reg.exe @args 2>\$null | Out-Null } finally { \$ErrorActionPreference = \$eap }
  return \$LASTEXITCODE
}

# CM-9（2026-09-19）：导入前校验 .reg 头部 hive。reg.exe 遇到 [HKEY_CLASSES_ROOT\\...] 头会把
# 键写进 HKLM\\\\SOFTWARE\\\\Classes（合并视图的机器级），即「用户级项恢复成全机项」，
# 且非管理员上下文下还会直接失败。旧版 Trim 产生的这类备份一律拒绝导入并如实回报。
function Get-RegFileHeaderHive {
  param([string]\$File)
  foreach (\$line in @(Get-Content -LiteralPath \$File -TotalCount 8 -ErrorAction SilentlyContinue)) {
    \$t = [string]\$line
    if (\$t.StartsWith('[')) {
      \$h = \$t.TrimStart('[')
      foreach (\$root in @('HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS')) {
        if (\$h.StartsWith(\$root)) { return \$root }
      }
      return 'OTHER'
    }
  }
  return ''
}

function Get-RegFileFirstKey {
  param([string]\$File)
  foreach (\$line in @(Get-Content -LiteralPath \$File -TotalCount 8 -ErrorAction SilentlyContinue)) {
    \$t = [string]\$line
    if (\$t.StartsWith('[')) { return \$t.TrimStart('[').TrimEnd(']', '\\') }
  }
  return ''
}

foreach (\$regFile in @(Get-ChildItem -LiteralPath \$latestBackup -Filter '*.reg' -ErrorAction SilentlyContinue)) {
  try {
    \$hdr = Get-RegFileHeaderHive \$regFile.FullName
    if (-not \$hdr -or \$hdr -eq 'HKEY_CLASSES_ROOT' -or \$hdr -eq 'OTHER') {
      \$skipped++
      \$hdrText = if (\$hdr) { \$hdr } else { '无法识别' }
      \$skipReasons += (\$regFile.Name + '（备份头为 ' + \$hdrText + '，非真实 hive，已拒绝导入）')
      continue
    }
    \$impCode = Invoke-RegCmd import \$regFile.FullName
    if (\$impCode -ne 0) { \$failed++; continue }
    # 导入后回读：退出码 0 但键没落地不算成功（防假成功）
    \$firstKey = Get-RegFileFirstKey \$regFile.FullName
    if (\$firstKey -and -not (Test-Path -LiteralPath ('Registry::' + \$firstKey))) {
      \$failed++
      \$skipReasons += (\$regFile.Name + '（reg import 报成功但键未出现）')
      continue
    }
    \$imported++
  } catch { \$failed++ }
}
\$restored = 0
\$manifestPath = Join-Path \$latestBackup 'manifest.json'
if (Test-Path -LiteralPath \$manifestPath) {
  try {
    \$manifest = Get-Content -LiteralPath \$manifestPath -Raw | ConvertFrom-Json
    foreach (\$record in @(\$manifest.files)) {
      if ((Test-Path -LiteralPath \$record.backup) -and \$record.source) {
        try { New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName(\$record.source)) -Force | Out-Null; Copy-Item -LiteralPath \$record.backup -Destination \$record.source -Force -Recurse; \$restored++ } catch { \$failed++ }
      }
    }
  } catch {}
}
[pscustomobject]@{ success = ((\$imported + \$restored) -gt 0 -and \$failed -eq 0); backupDir = \$latestBackup; imported = \$imported; restored = \$restored; skipped = \$skipped; skipReasons = @(\$skipReasons); failed = \$failed } | ConvertTo-Json -Compress
`;

// 启停切换脚本（勾选=启用，取消=禁用，可逆操作）
// 禁用/启用约定（CM-10，2026-09-19 升级为四值模型，与扫描端 Test-VerbHidden 同源）：
//   - shell 项：禁用写 LegacyDisable + ProgrammaticAccessOnly + HideBasedOnVelocityId=0x639bc8，
//     启用删这三值并清 CommandFlags 的 0x8 位；**Folder\\shell\\opennewwindow 例外**，
//     它绝不能带 LegacyDisable（会连带废掉 Win+E 与任务栏「新开窗口」，两家参考实现均硬特判）
//   - shellex 项：处理器键名加/去 '-' 前缀（重命名，可逆）
//   - 发送到（filesystem）：切换文件 Hidden 属性（发送到菜单忽略隐藏文件）
//   - UWP（packagedcom / uwp-contract）：本批仍拒绝（改走 Shell Extensions\\Blocked 屏蔽表在批次 B）
// 所有写入一律用 nativeRegPath（真实 hive），避免合并视图把用户级项写到机器级
// 每项操作后均回读验证，权限不足（HKLM 需要管理员）时报告失败而非静默假成功
const TOGGLE_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
\$OutputEncoding = [System.Text.Encoding]::UTF8
\$ErrorActionPreference = 'SilentlyContinue'
\$items = '__ITEMS_JSON__' | ConvertFrom-Json
\$success = 0
\$failed = 0
\$results = @()

# 与 SCAN_SCRIPT 中的同名函数保持一致（两段脚本各自独立进程执行，故各存一份）
function Test-VerbHidden {
  param(\$Key)
  if (\$null -eq \$Key) { return \$false }
  foreach (\$vn in @('LegacyDisable', 'Blocked', 'ProgrammaticAccessOnly')) {
    if (\$null -ne \$Key.GetValue(\$vn)) { return \$true }
  }
  \$velocity = \$Key.GetValue('HideBasedOnVelocityId')
  if (\$null -ne \$velocity) { try { if ([int]\$velocity -eq 0x639bc8) { return \$true } } catch {} }
  \$flags = \$Key.GetValue('CommandFlags')
  if (\$null -ne \$flags) { try { if ((([int]\$flags) % 16) -ge 8) { return \$true } } catch {} }
  return \$false
}

# Shell Extensions\\Blocked 两级路径（CM-16）
\$blockedPaths = @{
  user    = 'Registry::HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Blocked'
  machine = 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Blocked'
}

# 该 CLSID 的 COM 服务器是否落在 Windows 系统目录。
# 用「归属」而不是「GUID 名单」来判系统内置扩展：把内置命令的 ExplorerCommandHandler 加进
# 屏蔽表可能让整个 Win11 现代菜单失效、Explorer 回退经典菜单，所以这类一律拒绝入表。
function Test-SystemComServer {
  param([string]\$Guid)
  \$g = ([string]\$Guid).Trim()
  if (-not \$g) { return \$false }
  \$sysRoot = [string]\$env:SystemRoot
  foreach (\$view in @('Registry::HKEY_CLASSES_ROOT\\CLSID',
                       'Registry::HKEY_CLASSES_ROOT\\WOW6432Node\\CLSID',
                       'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Wow6432Node\\CLSID')) {
    foreach (\$sub in @('InprocServer32', 'LocalServer32')) {
      \$p = \$view + '\\' + \$g + '\\' + \$sub
      if (-not (Test-Path -LiteralPath \$p)) { continue }
      \$raw = [string](Get-Item -LiteralPath \$p -ErrorAction SilentlyContinue).GetValue('')
      if ([string]::IsNullOrWhiteSpace(\$raw)) { \$raw = [string](Get-Item -LiteralPath \$p).GetValue('CodeBase') }
      if ([string]::IsNullOrWhiteSpace(\$raw)) { continue }
      \$expanded = [Environment]::ExpandEnvironmentVariables(\$raw.Trim().Trim('"'))
      if (\$expanded.StartsWith(\$sysRoot, [StringComparison]::OrdinalIgnoreCase)) { return \$true }
    }
  }
  return \$false
}

foreach (\$item in @(\$items)) {
  \$name = [string]\$item.name
  \$source = [string]\$item.source
  # CM-9：优先真实 hive 路径（重命名后回传的 newNativeRegPath 也是这个口径）
  \$target = [string]\$item.nativeRegPath
  if ([string]::IsNullOrWhiteSpace(\$target)) { \$target = [string]\$item.regPath }
  \$displayPath = [string]\$item.regPath
  # ConvertFrom-Json 已将 enabled 解析为布尔，直接比较避免 -not/-and 优先级陷阱
  \$wantEnabled = (\$item.enabled -eq \$true)
  # CM-17（批次 B）：与 REMOVE_SCRIPT 对齐，系统保护项在服务端就拒绝——
  # 不能只靠渲染层 isToggleable 的自觉，IPC 是信任边界。
  if ([string]\$item.risk -eq 'protected') {
    \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'skip'; message = '系统保护项' }
    continue
  }
  if ([string]::IsNullOrWhiteSpace(\$target)) { \$results += @{ name = \$name; regPath = ''; status = 'skip'; message = '缺少目标路径' }; continue }

  try {
    \$blockedBy = [string]\$item.blockedBy
    \$clsid = ([string]\$item.clsid).Trim()

    # ---- Shell Extensions\\Blocked 屏蔽表（CM-16，批次 B）----
    # 适用两类：① UWP / 打包 COM 项——过去直接「暂不支持启停」，现在用 Windows 原生屏蔽表
    # 实现可逆禁用；② 任何本来就靠屏蔽表禁用的项（blockedBy 非空）——必须用同一机制还原，
    # 否则「启用」只会去改键名，屏蔽值还在，项照样不出现。
    # 安全边界：默认只写 HKCU（当前用户）；blockedBy=machine 时才写 HKLM，那条路径由主进程
    # 的 contextmenuWriteNeedsAdmin 拦住要提权。系统内置 GUID 一律拒绝入表——把内置命令的
    # ExplorerCommandHandler 加进屏蔽表可能让整个 Win11 现代菜单失效、Explorer 回退经典菜单。
    if (\$source -eq 'packagedcom' -or \$source -eq 'uwp-contract' -or \$blockedBy) {
      if (\$clsid -notmatch '^\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}\$') {
        \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'skip'; message = '缺少有效 CLSID，无法用屏蔽表启停' }; continue
      }
      if (([string]\$item.risk -eq 'protected') -or (Test-SystemComServer \$clsid)) {
        \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'skip'; message = '系统内置扩展不允许加入屏蔽表（可能导致整个新式右键菜单失效）' }; continue
      }
      \$scope = if (\$blockedBy -eq 'machine') { 'machine' } else { 'user' }
      \$blkPath = \$blockedPaths[\$scope]
      if (-not (Test-Path -LiteralPath \$blkPath)) { New-Item -Path \$blkPath -Force -ErrorAction Stop | Out-Null }
      if (\$wantEnabled) {
        Remove-ItemProperty -LiteralPath \$blkPath -Name \$clsid -ErrorAction SilentlyContinue
      } else {
        New-ItemProperty -LiteralPath \$blkPath -Name \$clsid -PropertyType String -Value '' -Force -ErrorAction Stop | Out-Null
      }
      \$bk = Get-Item -LiteralPath \$blkPath -ErrorAction SilentlyContinue
      \$stillBlocked = (\$bk -and (\$null -ne \$bk.GetValue(\$clsid)))
      if (\$stillBlocked -eq (-not \$wantEnabled)) {
        \$success++
        \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'ok'; newBlockedBy = \$(if (\$wantEnabled) { '' } else { \$scope }); message = (\$(if (\$wantEnabled) { '已解除屏蔽' } else { '已屏蔽（不加载该扩展）' })) }
      } else {
        \$failed++
        \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'error'; message = \$(if (\$scope -eq 'machine') { '屏蔽表写入未生效（机器级需要管理员权限）' } else { '屏蔽表写入未生效' }) }
      }
      continue
    }

    # ---- Win+X：.lnk ⇄ .lnk.disabled 重命名（Explorer 的 Win+X 只列 .lnk）----
    if (\$source -eq 'winx') {
      if (-not (Test-Path -LiteralPath \$target)) { \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'skip'; message = '文件不存在' }; continue }
      \$leaf = [IO.Path]::GetFileName(\$target)
      \$dir = [IO.Path]::GetDirectoryName(\$target)
      \$isOff = (\$leaf -match '(?i)\\.disabled\$')
      if (\$wantEnabled -and -not \$isOff) { \$success++; \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'ok'; message = '已处于启用状态' }; continue }
      if (-not \$wantEnabled -and \$isOff) { \$success++; \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'ok'; message = '已处于禁用状态' }; continue }
      \$newLeaf = if (\$wantEnabled) { \$leaf -replace '(?i)\\.disabled\$', '' } else { \$leaf + '.disabled' }
      Rename-Item -LiteralPath \$target -NewName \$newLeaf -ErrorAction Stop
      \$newPath = Join-Path \$dir \$newLeaf
      if ((Test-Path -LiteralPath \$newPath) -and -not (Test-Path -LiteralPath \$target)) {
        \$success++
        \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; newRegPath = \$newPath; newNativeRegPath = \$newPath; status = 'ok'; message = (\$(if (\$wantEnabled) { '已启用' } else { '已禁用' })) }
      } else {
        \$failed++; \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'error'; message = '重命名未生效' }
      }
      continue
    }

    # ---- 发送到：Hidden 属性切换 ----
    if (\$source -eq 'filesystem') {
      if (-not (Test-Path -LiteralPath \$target)) { \$results += @{ name = \$name; regPath = \$displayPath; status = 'skip'; message = '文件不存在' }; continue }
      \$file = Get-Item -LiteralPath \$target -Force
      if (\$wantEnabled) {
        \$file.Attributes = \$file.Attributes -band (-bnot [IO.FileAttributes]::Hidden)
      } else {
        \$file.Attributes = \$file.Attributes -bor [IO.FileAttributes]::Hidden
      }
      \$nowHidden = (([IO.FileAttributes]::Hidden -band (Get-Item -LiteralPath \$target -Force).Attributes) -ne 0)
      if (\$nowHidden -eq (-not \$wantEnabled)) {
        \$success++; \$results += @{ name = \$name; regPath = \$displayPath; status = 'ok'; message = (\$(if (\$wantEnabled) { '已启用' } else { '已禁用' })) }
      } else {
        \$failed++; \$results += @{ name = \$name; regPath = \$displayPath; status = 'error'; message = '切换未生效' }
      }
      continue
    }

    # ---- 注册表项：统一转 PowerShell 提供程序路径 ----
    \$regPath = \$target
    if (\$regPath -match '^HKEY_') { \$regPath = 'Registry::' + \$regPath }
    if (-not (Test-Path -LiteralPath \$regPath)) { \$results += @{ name = \$name; regPath = \$displayPath; status = 'skip'; message = '注册表路径不存在' }; continue }

    # ---- 新建菜单：改 HKCU PostSetup\\ShellNew 的 Classes（REG_MULTI_SZ）列表 ----
    # 只摘/加类名，不动各扩展名下的 ShellNew 键本身 —— 键还在，随时可还原。
    if (\$source -eq 'shellnew') {
      \$cls = ([string]\$item.target).Trim()
      if ([string]::IsNullOrWhiteSpace(\$cls)) { \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'skip'; message = '缺少类名（target）' }; continue }
      \$psk = Get-Item -LiteralPath \$regPath -ErrorAction Stop
      # 先 Where-Object 过滤再 @() 包装：@(\$null).Count 是 1，PS 判空陷阱
      \$cur = @(\$psk.GetValue('Classes') | Where-Object { -not [string]::IsNullOrWhiteSpace([string]\$_) } | ForEach-Object { [string]\$_ })
      \$has = (@(\$cur | Where-Object { \$_ -ieq \$cls }).Count -gt 0)
      if (\$wantEnabled -and \$has) { \$success++; \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'ok'; message = '已处于启用状态' }; continue }
      if (-not \$wantEnabled -and -not \$has) { \$success++; \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'ok'; message = '已处于禁用状态' }; continue }
      if (\$wantEnabled) {
        \$new = @(\$cur) + \$cls
      } else {
        \$new = @(\$cur | Where-Object { \$_ -ine \$cls })
      }
      if (\$new.Count -eq 0) {
        Remove-ItemProperty -LiteralPath \$regPath -Name 'Classes' -ErrorAction Stop
      } else {
        Set-ItemProperty -LiteralPath \$regPath -Name 'Classes' -Value ([string[]]\$new) -Type MultiString -ErrorAction Stop
      }
      \$chk = Get-Item -LiteralPath \$regPath -ErrorAction SilentlyContinue
      \$nowHas = \$false
      if (\$chk) { \$nowHas = (@(@(\$chk.GetValue('Classes')) | Where-Object { [string]\$_ -ieq \$cls }).Count -gt 0) }
      if (\$nowHas -eq \$wantEnabled) {
        \$success++; \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'ok'; message = (\$(if (\$wantEnabled) { '已启用' } else { '已禁用' })) }
      } else {
        \$failed++; \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'error'; message = 'Classes 列表写入未生效' }
      }
      continue
    }

    # ---- 打开方式（应用）：NoOpenWith 值的写入与清除 ----
    if (\$source -eq 'openwith') {
      if (\$wantEnabled) {
        Remove-ItemProperty -LiteralPath \$regPath -Name 'NoOpenWith' -ErrorAction SilentlyContinue
      } else {
        New-ItemProperty -LiteralPath \$regPath -Name 'NoOpenWith' -PropertyType String -Value '' -Force -ErrorAction Stop | Out-Null
      }
      \$ok2 = Get-Item -LiteralPath \$regPath -ErrorAction SilentlyContinue
      \$nowOff = (\$ok2 -and (\$null -ne \$ok2.GetValue('NoOpenWith')))
      if (\$nowOff -eq (-not \$wantEnabled)) {
        \$success++; \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'ok'; message = (\$(if (\$wantEnabled) { '已启用' } else { '已禁用' })) }
      } else {
        \$failed++; \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'error'; message = '切换未生效（可能需要管理员权限）' }
      }
      continue
    }

    if (\$source -eq 'shell') {
      # 四值可见性模型（CM-10）：禁用一次性写 LegacyDisable + ProgrammaticAccessOnly +
      # HideBasedOnVelocityId(0x639bc8)，启用一次性删三值并清 CommandFlags 的 0x8 位；
      # 写入与读回共用同一个 Test-VerbHidden，杜绝「按 A 写、按 B 判」的假状态。
      # （Split-Path 对 'Registry::' 路径会报参数集冲突，用字符串切分）
      \$sepIdx = \$regPath.LastIndexOf('\\')
      \$leaf = if (\$sepIdx -ge 0) { \$regPath.Substring(\$sepIdx + 1) } else { \$regPath }
      \$parent = if (\$sepIdx -gt 0) { \$regPath.Substring(0, \$sepIdx) } else { '' }
      \$renamedTo = ''
      if (\$wantEnabled) {
        # Autoruns 的重命名禁用约定：真实写法是无下划线的 'AutorunsDisabled'，
        # 旧实现只认 'AutorunsDisabled_' 前缀，导致这类键还原不了
        if (\$leaf -match '(?i)^AutorunsDisabled_?(.+)\$') {
          \$renamedTo = \$Matches[1]
          Rename-Item -LiteralPath \$regPath -NewName \$renamedTo -ErrorAction Stop
          \$regPath = \$parent + '\\' + \$renamedTo
        }
        foreach (\$vn in @('LegacyDisable', 'Blocked', 'ProgrammaticAccessOnly', 'HideBasedOnVelocityId')) {
          Remove-ItemProperty -LiteralPath \$regPath -Name \$vn -ErrorAction SilentlyContinue
        }
        # CommandFlags 只清 0x8（隐藏位）；其余位是合法动词属性，不能整值删除
        \$kNow = Get-Item -LiteralPath \$regPath -ErrorAction SilentlyContinue
        \$cf = if (\$kNow) { \$kNow.GetValue('CommandFlags') } else { \$null }
        if (\$null -ne \$cf) {
          try {
            \$cleared = ([int]\$cf) -band (-bnot 0x8)
            if (\$cleared -eq 0) {
              Remove-ItemProperty -LiteralPath \$regPath -Name 'CommandFlags' -ErrorAction SilentlyContinue
            } else {
              Set-ItemProperty -LiteralPath \$regPath -Name 'CommandFlags' -Value \$cleared -Type DWord -ErrorAction SilentlyContinue
            }
          } catch {}
        }
      } else {
        New-ItemProperty -LiteralPath \$regPath -Name 'ProgrammaticAccessOnly' -PropertyType String -Value '' -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath \$regPath -Name 'HideBasedOnVelocityId' -PropertyType DWord -Value 0x639bc8 -Force -ErrorAction SilentlyContinue | Out-Null
        # opennewwindow 硬特判：带 LegacyDisable 会连带废掉 Win+E 与任务栏「新开窗口」，
        # 只靠 ProgrammaticAccessOnly + velocity 即可达成「不在菜单显示」而不破坏程序化调用
        if (\$regPath -notmatch '(?i)\\\\Folder\\\\shell\\\\opennewwindow\$') {
          New-ItemProperty -LiteralPath \$regPath -Name 'LegacyDisable' -PropertyType String -Value '' -Force -ErrorAction Stop | Out-Null
        }
      }
      \$kFinal = Get-Item -LiteralPath \$regPath -ErrorAction SilentlyContinue
      \$nowHidden = Test-VerbHidden \$kFinal
      # 特例项不写 LegacyDisable，因此只校验「确实处于隐藏态」而非逐值比对
      if (\$nowHidden -eq (-not \$wantEnabled)) {
        \$success++
        \$res = @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; status = 'ok'; message = (\$(if (\$wantEnabled) { '已启用' } else { '已禁用' })) }
        if (\$renamedTo) {
          \$res.newNativeRegPath = (\$regPath -replace '^Registry::', '')
          if (\$displayPath) {
            \$dIdx = \$displayPath.LastIndexOf('\\')
            if (\$dIdx -ge 0) { \$res.newRegPath = (\$displayPath.Substring(0, \$dIdx + 1) + \$renamedTo) }
          }
        }
        \$results += \$res
      } else {
        \$failed++; \$results += @{ name = \$name; regPath = \$displayPath; status = 'error'; message = '切换未生效（可能需要管理员权限）' }
      }
      continue
    }

    # ---- shellex：处理器键名 '-' 前缀重命名 ----
    # 注意：PowerShell 7 的 Split-Path/Join-Path 对 'Registry::' 提供程序路径会报参数集冲突，
    # 这里一律用字符串切分与拼接
    \$sepIdx = \$regPath.LastIndexOf('\\')
    \$parent = if (\$sepIdx -gt 0) { \$regPath.Substring(0, \$sepIdx) } else { '' }
    \$leaf = if (\$sepIdx -ge 0) { \$regPath.Substring(\$sepIdx + 1) } else { \$regPath }
    if (\$wantEnabled) {
      if (-not \$leaf.StartsWith('-')) { \$success++; \$results += @{ name = \$name; regPath = \$displayPath; status = 'ok'; message = '已处于启用状态' }; continue }
      \$newName = \$leaf.Substring(1)
    } else {
      if (\$leaf.StartsWith('-')) { \$success++; \$results += @{ name = \$name; regPath = \$displayPath; status = 'ok'; message = '已处于禁用状态' }; continue }
      \$newName = '-' + \$leaf
    }
    Rename-Item -LiteralPath \$regPath -NewName \$newName -ErrorAction Stop
    \$newPath = \$parent + '\\' + \$newName
    if ((Test-Path -LiteralPath \$newPath) -and -not (Test-Path -LiteralPath \$regPath)) {
      # 返回重命名后的新路径（标准格式，剥离 Registry:: 前缀）；
      # newRegPath=展示用（HKCR 口径，渲染层按它关联）、newNativeRegPath=真实 hive（主进程回写快照）
      \$success++
      \$stdNew = \$newPath -replace '^Registry::', ''
      \$dIdx = \$displayPath.LastIndexOf('\\')
      \$newDisplay = if (\$dIdx -ge 0) { \$displayPath.Substring(0, \$dIdx + 1) + \$newName } else { \$displayPath }
      \$results += @{ id = [string]\$item.id; name = \$name; regPath = \$displayPath; newRegPath = \$newDisplay; newNativeRegPath = \$stdNew; status = 'ok'; message = (\$(if (\$wantEnabled) { '已启用' } else { '已禁用' })) }
    } else {
      \$failed++; \$results += @{ name = \$name; regPath = \$displayPath; status = 'error'; message = '重命名未生效（可能需要管理员权限）' }
    }
  } catch {
    \$failed++
    \$results += @{ name = \$name; regPath = \$displayPath; status = 'error'; message = \$_.Exception.Message }
  }
}
[pscustomobject]@{ success = \$success; failed = \$failed; results = @(\$results) } | ConvertTo-Json -Depth 6 -Compress
`;

// 图标提取脚本：根据 CLSID 解析 InprocServer32 指向的 DLL 并提取程序图标（PNG base64）
const ICONS_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
\$OutputEncoding = [System.Text.Encoding]::UTF8
\$ErrorActionPreference = 'SilentlyContinue'
\$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Drawing

\$items = '__ITEMS_JSON__' | ConvertFrom-Json
\$icons = @{}

foreach (\$it in \$items) {
  \$clsid = ([string]\$it.clsid).Trim()
  if (-not \$clsid -or -not \$clsid.StartsWith('{')) { continue }
  \$dll = ''
  foreach (\$view in @('Registry::HKEY_CLASSES_ROOT\\CLSID', 'Registry::HKEY_CLASSES_ROOT\\WOW6432Node\\CLSID', 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Wow6432Node\\CLSID')) {
    \$regPath = \$view + '\\' + \$clsid + '\\InprocServer32'
    if (-not (Test-Path -LiteralPath \$regPath)) { continue }
    \$serverKey = Get-Item -LiteralPath \$regPath -ErrorAction SilentlyContinue
    if (\$serverKey) {
      \$dll = ([string]\$serverKey.GetValue('')).Trim().Trim('"')
      if (\$dll) { break }
    }
  }
  if (-not \$dll) { continue }
  \$dll = [Environment]::ExpandEnvironmentVariables(\$dll)
  if (-not (Test-Path -LiteralPath \$dll)) { continue }
  try {
    \$icon = [System.Drawing.Icon]::ExtractAssociatedIcon(\$dll)
    if (-not \$icon) { continue }
    \$bmp = \$icon.ToBitmap()
    \$ms = New-Object System.IO.MemoryStream
    \$bmp.Save(\$ms, [System.Drawing.Imaging.ImageFormat]::Png)
    \$b64 = [Convert]::ToBase64String(\$ms.ToArray())
    \$icons[\$clsid] = 'data:image/png;base64,' + \$b64
    \$ms.Dispose(); \$bmp.Dispose(); \$icon.Dispose()
  } catch {}
}

\$icons | ConvertTo-Json -Compress
`;

// ==================== 批次 B：生效链路与 Win11 菜单模型 ====================

// 重启资源管理器：只动「当前交互会话」的 explorer。
// 服务会话 / 其他登录用户的 explorer 一律不碰（参考实现 ExplorerRestartService 的同款约束），
// 也绝不按进程名无差别 taskkill —— 那是多用户机器上的事故来源。
const RESTART_EXPLORER_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
\$OutputEncoding = [System.Text.Encoding]::UTF8
\$ErrorActionPreference = 'SilentlyContinue'

\$mySession = (Get-Process -Id \$PID).SessionId
\$targets = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { \$_.SessionId -eq \$mySession })
if (-not \$targets.Count) {
  [pscustomobject]@{ success = \$false; killed = 0; restarted = 0; alive = 0; message = '当前会话没有运行中的资源管理器' } | ConvertTo-Json -Compress
  exit
}
# 先记下原路径，逐个原样拉回（多显示器/多实例场景下 Path 可能不同）
\$paths = @(\$targets | ForEach-Object { [string]\$_.Path } | Where-Object { \$_ } | Select-Object -Unique)
foreach (\$p in \$targets) { try { Stop-Process -Id \$p.Id -Force -ErrorAction Stop } catch {} }
Start-Sleep -Milliseconds 700
\$started = 0
foreach (\$path in \$paths) {
  if (\$path -and (Test-Path -LiteralPath \$path)) {
    try { Start-Process -FilePath \$path -ErrorAction Stop; \$started++ } catch {}
  }
}
if (\$started -eq 0) {
  \$fallback = Join-Path \$env:SystemRoot 'explorer.exe'
  try { Start-Process -FilePath \$fallback -ErrorAction Stop; \$started = 1 } catch {}
}
Start-Sleep -Milliseconds 900
\$alive = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { \$_.SessionId -eq \$mySession }).Count
[pscustomobject]@{
  success   = (\$alive -gt 0)
  killed    = \$targets.Count
  restarted = \$started
  alive     = \$alive
  message   = \$(if (\$alive -gt 0) { '已重启资源管理器' } else { '资源管理器未能自动拉起，请手动启动 explorer.exe' })
} | ConvertTo-Json -Compress
`;

// Win11 右键菜单模式：{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32 默认值置空
// = 经典完整菜单（Win10 样式，所有扩展直接平铺）；删掉该 CLSID 键 = 回到新版精简菜单。
// 只碰 HKCU：HKLM 侧那份是系统默认（本机实测默认值指向 Windows.UI.FileExplorer.dll），
// 用户级键天然覆盖它，改 HKCU 不需要管理员、也不影响其他账户。
const WIN11_MODE_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
\$OutputEncoding = [System.Text.Encoding]::UTF8
\$ErrorActionPreference = 'SilentlyContinue'
\$action = '__ACTION__'

\$clsidRoot = 'Registry::HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
\$inproc = \$clsidRoot + '\\InprocServer32'

function Get-CurrentMode {
  \$k = Get-Item -LiteralPath \$inproc -ErrorAction SilentlyContinue
  if (-not \$k) { return 'modern' }
  \$v = \$k.GetValue('')
  if (\$null -eq \$v) { return 'modern' }
  if ([string]::IsNullOrEmpty([string]\$v)) { return 'classic' }
  return 'modern'
}

\$before = Get-CurrentMode
if (\$action -eq 'get') {
  [pscustomobject]@{ success = \$true; mode = \$before; changed = \$false; requireRestart = \$false } | ConvertTo-Json -Compress
  exit
}

\$mode = 'modern'
if (\$action -eq 'set-classic') {
  try {
    if (-not (Test-Path -LiteralPath \$inproc)) { New-Item -Path \$inproc -Force -ErrorAction Stop | Out-Null }
    # 默认值必须是「存在的空字符串」，不是「不存在」——这是该开关生效的唯一形态
    New-ItemProperty -LiteralPath \$inproc -Name '(default)' -PropertyType String -Value '' -Force -ErrorAction Stop | Out-Null
    \$mode = 'classic'
  } catch {
    [pscustomobject]@{ success = \$false; mode = \$before; changed = \$false; message = ('写入失败: ' + \$_.Exception.Message) } | ConvertTo-Json -Compress
    exit
  }
} elseif (\$action -eq 'set-modern') {
  try {
    if (Test-Path -LiteralPath \$clsidRoot) { Remove-Item -LiteralPath \$clsidRoot -Recurse -Force -ErrorAction Stop }
    \$mode = 'modern'
  } catch {
    [pscustomobject]@{ success = \$false; mode = \$before; changed = \$false; message = ('还原失败: ' + \$_.Exception.Message) } | ConvertTo-Json -Compress
    exit
  }
} else {
  [pscustomobject]@{ success = \$false; mode = \$before; changed = \$false; message = '未知动作' } | ConvertTo-Json -Compress
  exit
}

# 回读校验：写没生效绝不报成功（该开关必须重启资源管理器才可见，故 requireRestart 恒真）
\$after = Get-CurrentMode
[pscustomobject]@{
  success        = (\$after -eq \$mode)
  mode           = \$after
  changed        = (\$after -ne \$before)
  requireRestart = \$true
  message        = \$(if (\$after -eq \$mode) { '已切换，重启资源管理器后生效' } else { '切换未生效' })
} | ConvertTo-Json -Compress
`;

// 屏蔽表枚举：只返回 GUID 与作用域，友好名由渲染层拿扫描结果反查
// （扫描已覆盖同一批 CLSID，避免在两段脚本里各维护一份名称解析链）。
const BLOCKED_LIST_SCRIPT = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
\$OutputEncoding = [System.Text.Encoding]::UTF8
\$ErrorActionPreference = 'SilentlyContinue'
\$roots = @(
  @{ scope = 'machine'; path = 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Blocked' },
  @{ scope = 'user';    path = 'Registry::HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Blocked' }
)
\$entries = @()
foreach (\$r in \$roots) {
  \$k = Get-Item -LiteralPath \$r.path -ErrorAction SilentlyContinue
  if (-not \$k) { continue }
  foreach (\$vn in @(\$k.GetValueNames())) {
    \$g = ([string]\$vn).Trim()
    if (\$g -notmatch '^\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}\$') { continue }
    \$entries += [pscustomobject]@{ guid = \$g; scope = \$r.scope }
  }
}
[pscustomobject]@{ success = \$true; entries = @(\$entries) } | ConvertTo-Json -Depth 4 -Compress
`;

function serializeItems(items) {
  const json = JSON.stringify(Array.isArray(items) ? items : []);
  return json.replace(/'/g, "''");
}

module.exports = {
  scan() { return SCAN_SCRIPT; },
  backup(items) { return BACKUP_SCRIPT.replace('__ITEMS_JSON__', serializeItems(items)); },
  remove(items) { return REMOVE_SCRIPT.replace('__ITEMS_JSON__', serializeItems(items)); },
  toggle(items) { return TOGGLE_SCRIPT.replace('__ITEMS_JSON__', serializeItems(items)); },
  restore() { return RESTORE_SCRIPT; },
  icons(items) { return ICONS_SCRIPT.replace('__ITEMS_JSON__', serializeItems(items)); },
  restartExplorer() { return RESTART_EXPLORER_SCRIPT; },
  // 动作是白名单枚举后才拼进脚本，杜绝把渲染层字符串直接插进 PowerShell
  win11Mode(action) {
    const allowed = ['get', 'set-classic', 'set-modern'];
    const a = allowed.includes(String(action)) ? String(action) : 'get';
    return WIN11_MODE_SCRIPT.replace('__ACTION__', a);
  },
  blockedList() { return BLOCKED_LIST_SCRIPT; }
};
