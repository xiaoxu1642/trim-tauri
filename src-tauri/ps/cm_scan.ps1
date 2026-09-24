# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/contextmenu-scripts.js → scan()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：右键菜单扫描（只读）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$script:results = @()

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
  param([string]$Ref)
  if ([string]::IsNullOrWhiteSpace($Ref)) { return $null }
  $m = [regex]::Match($Ref.Trim(), '^@\s*([^,]+?)\s*,\s*-(\d+)')
  if (-not $m.Success) { return $null }
  $dllPath = $m.Groups[1].Value.Trim('"').Trim()
  if ([string]::IsNullOrWhiteSpace($dllPath)) { return $null }
  $dllPath = [Environment]::ExpandEnvironmentVariables($dllPath)
  if (-not ($dllPath -match '[\\/]')) {
    # 相对库名（如 shell32.dll）：尝试系统目录
    $sysCandidate = Join-Path $env:WINDIR ('System32\' + $dllPath)
    if (Test-Path -LiteralPath $sysCandidate) { $dllPath = $sysCandidate }
  }
  if (-not (Test-Path -LiteralPath $dllPath)) { return $null }
  try { return [WinCleanRes]::GetString($dllPath, [int]$m.Groups[2].Value) } catch { return $null }
}

# 直接字符串：@ 引用串优先走资源解析，解析失败回退原文
function Get-DirectString {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
  $v = $Value.Trim()
  if ($v.StartsWith('@')) {
    $resolved = Get-ResourceString $v
    if ($resolved) { return $resolved }
    return ''
  }
  return $v
}

# ==================== 工具 ====================
function Test-GuidText {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
  return $Text.Trim() -match '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'
}

# PSPath -> 标准注册表路径（HKEY_CLASSES_ROOT\...，去除 Registry:: 提供程序前缀）
function Convert-ToStdRegPath {
  param([string]$PsPath)
  return ([string]$PsPath) -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
}

# HKCR -> 真实 hive 路径（审查 CM-9，2026-09-19）
#   根因：HKEY_CLASSES_ROOT 是 HKCU\Software\Classes 与 HKLM\SOFTWARE\Classes 的合并视图，
#   PowerShell 提供程序按「HKCU 优先」解析，所以经 HKCR 路径删除删掉的是 HKCU 那份；
#   但 reg.exe 的 HKCR 别名在 **import** 时落到 HKLM\SOFTWARE\Classes。
#   实测复现：项建在 HKCU -> 经 HKCR 导出 -> 删除 -> reg import -> 恢复到 HKLM（变成全机项，
#   且再删需要管理员）。故所有写入/导出/导入一律用真实 hive 路径。
#   解析顺序必须与合并视图一致：HKCU 命中即取，否则 HKLM，都无则原样返回。
function Resolve-NativeRegPath {
  param([string]$StdPath)
  $p = ([string]$StdPath) -replace '^Registry::', ''
  if ($p -notmatch '^HKEY_CLASSES_ROOT(\\|$)') { return $p }
  $rest = $p -replace '^HKEY_CLASSES_ROOT\\?', ''
  $cu = 'HKEY_CURRENT_USER\Software\Classes\' + $rest
  if (Test-Path -LiteralPath ('Registry::' + $cu)) { return $cu }
  $lm = 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\' + $rest
  if (Test-Path -LiteralPath ('Registry::' + $lm)) { return $lm }
  return $p
}

# 动词隐藏判据（四值模型）—— 必须与 TOGGLE_SCRIPT 的写入端严格对称，
# 否则会出现「写 A 判据、按 B 判据读回」的假状态（本机实测有 3 项被判成已启用而菜单里根本没有）。
#   LegacyDisable            : 经典禁用动词
#   ProgrammaticAccessOnly   : 仅程序可调用，不显示在菜单（Win11 常用）
#   HideBasedOnVelocityId    : 0x639bc8 = 系统按特性开关隐藏的动词
#   CommandFlags             : 低 4 位含 0x8 视为隐藏
#   Blocked                  : Trim 早期一并读取的兼容值，保留
function Test-VerbHidden {
  param($Key)
  if ($null -eq $Key) { return $false }
  foreach ($vn in @('LegacyDisable', 'Blocked', 'ProgrammaticAccessOnly')) {
    if ($null -ne $Key.GetValue($vn)) { return $true }
  }
  $velocity = $Key.GetValue('HideBasedOnVelocityId')
  if ($null -ne $velocity) { try { if ([int]$velocity -eq 0x639bc8) { return $true } } catch {} }
  $flags = $Key.GetValue('CommandFlags')
  if ($null -ne $flags) { try { if ((([int]$flags) % 16) -ge 8) { return $true } } catch {} }
  return $false
}

# 「打开 / 浏览」类动词保护（对齐参考实现 ShellItem.TryProtectOpenItem / ProtectedMenuItemGuard）：
# 这类动词被禁用后用户最容易感知为「双击打不开了」，必须走红色二次确认。
function Get-VerbConfirm {
  param([string]$VerbName)
  $v = ([string]$VerbName).ToLowerInvariant()
  if ($v -eq 'open' -or $v -eq 'explore') {
    return @{ required = $true; reason = '该项是对象的基础「打开/浏览」动词，禁用或删除后双击与默认打开行为可能改变' }
  }
  return @{ required = $false; reason = '' }
}

# 清洗字符串：移除会导致 JSON / UTF-8 输出损坏的字符
# （孤立代理 U+D800~U+DFFF、非字符 U+FFFE/U+FFFF、控制字符 U+0000~U+001F 与 U+007F）
# 这些字符常见于注册表脏数据，会破坏 JSON 字符串终止引号
function Format-CleanStr {
  param([string]$s)
  if ([string]::IsNullOrEmpty($s)) { return '' }
  $sb = New-Object System.Text.StringBuilder
  foreach ($ch in $s.ToCharArray()) {
    $cp = [int][char]$ch
    if ($cp -lt 0x20) { continue }
    if ($cp -eq 0x7f) { continue }
    if ($cp -ge 0xD800 -and $cp -le 0xDFFF) { continue }
    if ($cp -eq 0xFFFE -or $cp -eq 0xFFFF) { continue }
    $null = $sb.Append($ch)
  }
  return $sb.ToString()
}

# 安全 JSON 序列化：手工拼出合法 JSON 字符串字面量，把所有非 ASCII 字符转义为 \uXXXX，
# 使整段输出为纯 ASCII，彻底规避两类问题：
#   (1) PowerShell ConvertTo-Json 对注册表脏数据偶发丢失字符串终止引号的缺陷；
#   (2) 管道输出 UTF-8/UTF-16LE 编码不一致导致的中文乱码（\uXXXX 与流编码无关，JSON.parse 可还原）。
function ConvertTo-JsonSafeString {
  param([string]$s)
  if ($null -eq $s) { $s = '' }
  $s = [string]$s
  $sb = New-Object System.Text.StringBuilder
  $null = $sb.Append('"')
  foreach ($ch in $s.ToCharArray()) {
    $cp = [int][char]$ch
    if ($cp -eq 34) { $null = $sb.Append('\"'); }        # " 双引号
    elseif ($cp -eq 92) { $null = $sb.Append('\\'); }    #  反斜杠
    elseif ($cp -eq 8) { $null = $sb.Append('\b'); }
    elseif ($cp -eq 12) { $null = $sb.Append('\f'); }
    elseif ($cp -eq 10) { $null = $sb.Append('\n'); }
    elseif ($cp -eq 13) { $null = $sb.Append('\r'); }
    elseif ($cp -eq 9) { $null = $sb.Append('\t'); }
    elseif ($cp -lt 0x20 -or ($cp -ge 0x7f -and $cp -le 0x9f) -or $cp -ge 0x80) {
      $null = $sb.Append('\u' + $cp.ToString('x4'))
    }
    else { $null = $sb.Append($ch) }
  }
  $null = $sb.Append('"')
  return $sb.ToString()
}

function ConvertTo-JsonSafeBool {
  param([bool]$b)
  if ($b) { return 'true' } else { return 'false' }
}

$protectedCLSIDs = @(
  '{20D04FE0-3AEA-1069-A2D8-08002B30309D}',
  '{450D8FBA-AD25-11D0-98A8-0800361B1103}',
  '{208D2C60-3AEA-1069-A2D2-08002B30309D}',
  '{1F4DE370-D627-11D1-BA4F-00A0C91EEDBA}',
  '{59031A47-3F72-35A7-89EC-6E8B9A8A5B5E}',
  '{59BE1D4E-E3A4-4D8A-91A3-69D69F66A4AC}',
  '{645FF040-5081-101B-9F08-00AA002F954E}'
)

$knownSystem = @(
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
# CLSID 查找视图：HKCR\CLSID（主）、HKCR\WOW6432Node\CLSID、HKLM 32 位视图
$clsidViews = @(
  'Registry::HKEY_CLASSES_ROOT\CLSID',
  'Registry::HKEY_CLASSES_ROOT\WOW6432Node\CLSID',
  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Wow6432Node\CLSID'
)
$script:clsidCache = @{}

function Get-ClsidInfo {
  param([string]$GuidText)
  $g = ([string]$GuidText).Trim()
  $empty = @{ name = ''; company = ''; filePath = '' }
  if (-not (Test-GuidText $g)) { return $empty }
  if ($script:clsidCache.ContainsKey($g)) { return $script:clsidCache[$g] }

  $info = @{ name = ''; company = ''; filePath = '' }
  foreach ($view in $clsidViews) {
    $keyPath = '{0}\{1}' -f $view, $g
    if (-not (Test-Path -LiteralPath $keyPath)) { continue }
    try {
      $key = Get-Item -LiteralPath $keyPath -ErrorAction Stop
      # 名称链（对齐 GuidInfo.GetText）：LocalizedString > InfoTip > 默认值（均支持 @dll,-id 资源串）
      foreach ($vn in @('LocalizedString', 'InfoTip', '')) {
        $raw = if ($vn) { [string]$key.GetValue($vn) } else { [string]$key.GetValue('') }
        $resolved = Get-DirectString $raw
        if ($resolved) { $info.name = $resolved; break }
      }
      # 厂商：CLSID 键 Company 值
      $companyRaw = [string]$key.GetValue('Company')
      if ($companyRaw) { $info.company = $companyRaw }
      # 文件路径（对齐 GuidInfo.GetFilePath：InprocServer32 > LocalServer32，CodeBase 优先）
      $filePath = ''
      foreach ($sub in @('InprocServer32', 'LocalServer32')) {
        $serverKey = Get-Item -LiteralPath ($keyPath + '\' + $sub) -ErrorAction SilentlyContinue
        if (-not $serverKey) { continue }
        $candidate = ''
        $codeBase = [string]$serverKey.GetValue('CodeBase')
        if ($codeBase) {
          $candidate = $codeBase.Replace('file:///', '').Replace('/', '\')
        }
        if (-not $candidate) { $candidate = ([string]$serverKey.GetValue('')).Trim().Trim('"') }
        if (-not $candidate) { continue }
        $candidate = [Environment]::ExpandEnvironmentVariables($candidate)
        # 可执行命令可能带参数：提取实际文件路径
        if ($candidate -match '^"([^"]+)"') { $candidate = $Matches[1] }
        elseif ($candidate -match '^(\S+\.(dll|exe|ocx|cpl|sys))') { $candidate = $Matches[1] }
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { $filePath = $candidate; break }
      }
      if ($filePath) {
        $info.filePath = $filePath
        try {
          $fileItem = Get-Item -LiteralPath $filePath -ErrorAction SilentlyContinue
          if ($fileItem -and $fileItem.VersionInfo) {
            # 厂商优先取文件版本信息（比注册表 Company 值更可靠）
            if ($fileItem.VersionInfo.CompanyName) { $info.company = [string]$fileItem.VersionInfo.CompanyName }
            # 名称回退：DLL 的 FileDescription（对齐参考实现最后回退链）
            if (-not $info.name -and $fileItem.VersionInfo.FileDescription) {
              $info.name = [string]$fileItem.VersionInfo.FileDescription
            }
          }
        } catch {}
      }
    } catch { continue }
    break
  }
  $script:clsidCache[$g] = $info
  return $info
}

# ==================== 第三方判定 ====================
function Is-ThirdParty {
  param([string]$Name, [string]$Company, [string]$Source, [string]$FilePath)
  # 微软厂商 → 系统原生
  if ($Company -match '(?i)microsoft|windows\s+(corp|corporation)') { return $false }
  # 系统目录下的 DLL 且无厂商信息 → 系统组件（shell32/shellext 等未签名描述的扩展）
  if ([string]::IsNullOrWhiteSpace($Company) -and $FilePath -match '(?i)^C:\\Windows\\') { return $false }
  if ($knownSystem -contains $Name) { return $false }
  if ($Source -eq 'shell' -and $Name -match '(?i)^@?.*(Windows|System32|shell32|themecpl|display)') { return $false }
  if ([string]::IsNullOrWhiteSpace($Company) -and $Name -match '^(Open|Explore|Properties|RunAs|新建|发送到|打开|打开方式|打开文件位置|打开所在位置|在资源管理器中打开|在.+中打开|固定到|固定|复制|剪切|粘贴|删除|重命名|属性|共享|压缩|添加到|发送|扫描|打印|编辑|播放|预览|打开文件|解压|挂载|装载)$') { return $false }
  return $true
}

// ==================== 结果收集 ====================
function Add-Result {
  param([string]$Name, [string]$CLSID, [string]$RegPath, [string]$Location,
        [string]$Category, [string]$Source, [string]$CompanyOverride = '', [string]$FilePath = '', [string]$Command = '',
        [bool]$Enabled = $true, [bool]$ConfirmRequired = $false, [string]$ConfirmReason = '', [bool]$UnknownConvention = $false,
        [string]$Target = '', [bool]$Orphan = $false)
  # 幽灵项过滤：无有效名称不输出
  if ([string]::IsNullOrWhiteSpace($Name)) { return }
  # 注册表类来源必须有有效路径，否则后续删除/启停/备份无法定位，直接丢弃
  if ($Source -ne 'filesystem' -and [string]::IsNullOrWhiteSpace($RegPath)) { return }
  $clsidText = ([string]$CLSID).Trim()
  $company = [string]$CompanyOverride
  $filePath = [string]$FilePath
  if (Test-GuidText $clsidText) {
    $info = Get-ClsidInfo $clsidText
    if (-not $company) { $company = $info.company }
    if (-not $filePath) { $filePath = $info.filePath }
  }
  $isThirdParty = Is-ThirdParty -Name $Name -Company $company -Source $Source -FilePath $filePath
  $isProtected = $protectedCLSIDs -contains $clsidText
  $risk = if ($isProtected) { 'protected' } elseif ($isThirdParty) { 'high' } else { 'low' }
  # 失效残留（批次 C）：CLSID 登记还在、但 InprocServer32 指向的文件已经没了 —— 典型的卸载残留。
  # 只在「解析出了路径且路径不存在」时才判残留；解析不出路径的伪 CLSID（如 Taskband Pin /
  # Start Menu Pin 这类由 shell 内部实现的）不算，否则会误伤合法系统项。
  $componentMissing = $false
  if ((Test-GuidText $clsidText) -and -not [string]::IsNullOrWhiteSpace($filePath)) {
    $expandedPath = [Environment]::ExpandEnvironmentVariables(([string]$filePath).Trim().Trim('"'))
    if ($expandedPath -and -not (Test-Path -LiteralPath $expandedPath)) { $componentMissing = $true }
  }
  $orphanFlag = [bool]$Orphan -or $componentMissing
  $orphanWhy = if ($componentMissing) { '登记的处理程序文件已不存在（' + $filePath + '）' } elseif ([bool]$Orphan) { '列表里还挂着这个类型，但对应的 ShellNew 键已不存在' } else { '' }
  # CM-16（批次 B）：命中 Shell Extensions\Blocked 的 CLSID，Explorer 根本不会加载它，
  # 等价于「已禁用」。这张表过去 Trim 完全看不见，被别的工具屏蔽过的项会显示成启用。
  $blockedBy = ''
  if ($clsidText -and $script:blockedGuids.ContainsKey($clsidText.ToUpper())) {
    $blockedBy = [string]$script:blockedGuids[$clsidText.ToUpper()]
    $Enabled = $false
  }
  # 快捷方式的「打开」处理器（ShellExc OpenWith/lnk open GUID）与 open 动词同等保护
  if (-not $ConfirmRequired -and $clsidText -ieq '{00021401-0000-0000-C000-000000000046}') {
    $ConfirmRequired = $true
    $ConfirmReason = '该项承载快捷方式的「打开」行为，禁用后 .lnk 双击可能失效'
  }
  # nativeRegPath = 真实 hive 路径，所有写操作（删除/启停/备份）一律用它，见 Resolve-NativeRegPath；
  # 文件系统类来源（发送到 / Win+X）没有 hive 概念，原样保留
  $isFileSource = ($Source -eq 'filesystem' -or $Source -eq 'winx')
  $nativePath = if ($isFileSource) { $RegPath } else { Resolve-NativeRegPath $RegPath }
  $script:results += [pscustomobject]@{
    name = $Name; clsid = $clsidText; regPath = $RegPath; nativeRegPath = $nativePath; company = $company
    location = $Location; category = $Category; source = $Source; filePath = $filePath; command = [string]$Command
    isThirdParty = $isThirdParty; isProtected = $isProtected; risk = $risk; enabled = $Enabled
    confirmRequired = $ConfirmRequired; confirmReason = $ConfirmReason; unknownConvention = $UnknownConvention
    blockedBy = $blockedBy; target = [string]$Target; orphan = $orphanFlag; orphanReason = $orphanWhy
  }
}

# ==================== Shell 项扫描（对齐 LoadShellItems + ShellItem 解析） ====================
# 菜单名优先级：MUIVerb(资源串解析) > 默认值(多级母菜单除外) > 键名
function Scan-ShellItems {
  param([string]$Category, [string]$ShellPath, [hashtable]$SeenKeys)
  if (-not (Test-Path -LiteralPath $ShellPath)) { return }
  $shellKey = Get-Item -LiteralPath $ShellPath -ErrorAction SilentlyContinue
  if (-not $shellKey) { return }
  foreach ($child in @($shellKey.GetSubKeyNames())) {
    try {
      # 同一场景内键名去重（多视图扫描防重复）
      if ($SeenKeys.ContainsKey($child)) { continue }
      $SeenKeys[$child] = $true
      $keyPath = $ShellPath + '\' + $child
      $key = Get-Item -LiteralPath $keyPath -ErrorAction Stop

      # 菜单名称（对齐 ShellItem.ItemText）
      $name = Get-DirectString ([string]$key.GetValue('MUIVerb'))
      if (-not $name) {
        # 多级母菜单（SubCommands/ExtendedSubCommandsKey）不支持默认值作名称
        $hasSub = [string]$key.GetValue('SubCommands')
        $extSub = [string]$key.GetValue('ExtendedSubCommandsKey')
        if (-not $hasSub -and -not $extSub) {
          $name = Get-DirectString ([string]$key.GetValue(''))
        }
      }
      if (-not $name) { $name = $child }

      # GUID 提取（对齐 ShellItem.Guid：command\DelegateExecute > DropTarget\CLSID > ExplorerCommandHandler）
      $clsid = ''
      $commandKey = Get-Item -LiteralPath ($keyPath + '\command') -ErrorAction SilentlyContinue
      if ($commandKey) {
        $v = [string]$commandKey.GetValue('DelegateExecute')
        if (Test-GuidText $v) { $clsid = $v.Trim() }
      }
      if (-not $clsid) {
        $dropKey = Get-Item -LiteralPath ($keyPath + '\DropTarget') -ErrorAction SilentlyContinue
        if ($dropKey) {
          $v = [string]$dropKey.GetValue('CLSID')
          if (Test-GuidText $v) { $clsid = $v.Trim() }
        }
      }
      if (-not $clsid) {
        $v = [string]$key.GetValue('ExplorerCommandHandler')
        if (Test-GuidText $v) { $clsid = $v.Trim() }
      }

      $command = ''
      if ($commandKey) { $command = Get-DirectString ([string]$commandKey.GetValue('')) }

      # 启用状态（审查 CM-10，2026-09-19）：改为四值可见性判据 Test-VerbHidden，与写入端对称。
      # 旧实现只看 LegacyDisable/Blocked，漏掉 ProgrammaticAccessOnly 与 HideBasedOnVelocityId，
      # 本机实测 3 项（\*\shell\removeproperties、Folder\shell\explore、
      # AllFilesystemObjects\shell\OfflineFilesLaunchSyncCenter）被误判为「已启用」。
      $enabled = -not (Test-VerbHidden $key)
      # 键名以 AutorunsDisabled 开头（Autoruns 的重命名禁用约定，无下划线形式才是真实写法）
      $unknownConv = $false
      if ($child -match '(?i)^AutorunsDisabled') {
        $enabled = $false
        $unknownConv = $true
        $name = $name + '（未识别的禁用约定）'
      }
      $confirm = Get-VerbConfirm $child
      Add-Result -Name $name -CLSID $clsid -RegPath (Convert-ToStdRegPath $key.PSPath) -Location $ShellPath -Category $Category -Source 'shell' -Command $command -Enabled $enabled -ConfirmRequired $confirm.required -ConfirmReason $confirm.reason -UnknownConvention $unknownConv
    } catch { continue }
  }
}

# ==================== ShellEx 项扫描（对齐 GetPathAndGuids） ====================
# 读取 ContextMenuHandlers（含禁用重命名形态）：
#   - 子键名以 '-' 开头（如 -Foo）→ 已禁用的单个处理器，输出时还原名称并标记 enabled=false
#   - 父键被改名为 '-ContextMenuHandlers' → 整组禁用，由 Scan-Scene 以 HandlersDirName 指定扫描
function Scan-ShellExHandlers {
  param([string]$Category, [string]$ShellExPath, [hashtable]$SeenKeys, [string]$HandlersDirName = 'ContextMenuHandlers')
  $cmPath = $ShellExPath + '\' + $HandlersDirName
  if (-not (Test-Path -LiteralPath $cmPath)) { return }
  $cmKey = Get-Item -LiteralPath $cmPath -ErrorAction SilentlyContinue
  if (-not $cmKey) { return }
  foreach ($child in @($cmKey.GetSubKeyNames())) {
    try {
      # 启用状态与真实键名（'-' 前缀为禁用标记）
      $enabled = $true
      $realName = [string]$child
      if ($realName.StartsWith('-')) { $enabled = $false; $realName = $realName.Substring(1) }
      if (-not $realName) { continue }
      if ($SeenKeys.ContainsKey($child)) { continue }
      $SeenKeys[$child] = $true
      $keyPath = $cmPath + '\' + $child
      $key = Get-Item -LiteralPath $keyPath -ErrorAction Stop
      $defaultValue = [string]$key.GetValue('')
      # GUID：默认值优先，失败回退真实键名（对齐 GuidEx.TryParse(keyName)）
      $guid = $defaultValue
      if (-not (Test-GuidText $guid)) { $guid = $realName }
      if (-not (Test-GuidText $guid)) {
        # 审查 CM-11（2026-09-19）：解析不出 GUID 过去直接 continue，会把别人禁过的项
        # 完全吞掉（本机实测 4 处 Autoruns 约定项，其中 2 处就在 Trim 会扫的活跃组里），
        # 用户看到的是「干净」列表。现在如实输出为「已禁用 + 未识别约定」。
        if ($realName -match '(?i)^AutorunsDisabled') {
          Add-Result -Name ('未识别的禁用项（' + $realName + '）') -CLSID '' -RegPath (Convert-ToStdRegPath $key.PSPath) -Location $cmPath -Category $Category -Source 'shellex' -Enabled $false -UnknownConvention $true
        }
        continue
      }
      $guid = $guid.Trim()

      $info = Get-ClsidInfo $guid
      # 名称（对齐 ShellExItem.ItemText）：CLSID 友好名 > (键名为 GUID 时用默认值) > 真实键名
      $name = $info.name
      if (-not $name) {
        if ((Test-GuidText $realName) -and $defaultValue -and -not (Test-GuidText $defaultValue)) {
          $name = $defaultValue
        } else {
          $name = $realName
        }
      }
      Add-Result -Name $name -CLSID $guid -RegPath (Convert-ToStdRegPath $key.PSPath) -Location $cmPath -Category $Category -Source 'shellex' -CompanyOverride $info.company -FilePath $info.filePath -Enabled $enabled
    } catch { continue }
  }
}

# ==================== 场景扫描（对齐 ShellList.LoadItems：shell + ShellEx 两个子树） ====================
function Scan-Scene {
  param([string]$Category, [string[]]$ScenePaths)
  foreach ($scenePath in @($ScenePaths)) {
    if ([string]::IsNullOrWhiteSpace($scenePath)) { continue }
    if (-not (Test-Path -LiteralPath $scenePath)) { continue }
    Scan-ShellItems -Category $Category -ShellPath ($scenePath + '\shell') -SeenKeys @{}
    Scan-ShellExHandlers -Category $Category -ShellExPath ($scenePath + '\ShellEx') -SeenKeys @{}
    # 整组禁用形态：父键改名为 '-ContextMenuHandlers'（其子键全部视为禁用项）
    Scan-ShellExHandlers -Category $Category -ShellExPath ($scenePath + '\ShellEx') -SeenKeys @{} -HandlersDirName '-ContextMenuHandlers'
  }
}

# 注册表视图：HKCR 合并视图（主，天然合并 HKCU+HKLM）+ HKCU 显式视图（捕获被
# HKLM 同名键遮蔽的用户级项）+ HKLM 32 位视图（原路径 Software\WOW6432Node\Classes
# 实为无效路径，修正为 Software\Classes\Wow6432Node）
$HKCR = 'Registry::HKEY_CLASSES_ROOT'
$HKCU_CLASSES = 'Registry::HKEY_CURRENT_USER\Software\Classes'
$HKLM_WOW64_CLASSES = 'Registry::HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node'

# ---- Shell Extensions\Blocked：Windows 原生的 COM 屏蔽表（CM-16，批次 B）----
# 值名就是 {CLSID}，命中即该扩展不被加载。HKCU=当前用户、HKLM=全机；机器级优先。
# 必须在任何 Add-Result 之前装载，因为它会改写条目的 enabled。
$script:blockedGuids = @{}
$script:blockedPaths = @{
  user    = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked'
  machine = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked'
}
foreach ($scope in @('machine', 'user')) {
  $bk = Get-Item -LiteralPath $script:blockedPaths[$scope] -ErrorAction SilentlyContinue
  if (-not $bk) { continue }
  foreach ($vn in @($bk.GetValueNames())) {
    $g = ([string]$vn).Trim()
    if (-not (Test-GuidText $g)) { continue }
    # 先写 machine 再写 user：user 覆盖 machine，与 Explorer「用户级可解除机器级屏蔽」的语义一致
    $script:blockedGuids[$g.ToUpper()] = $scope
  }
}

function Get-SceneViews {
  param([string]$Suffix)
  return @(
    ($HKCR + $Suffix),
    ($HKCU_CLASSES + $Suffix),
    ($HKLM_WOW64_CLASSES + $Suffix)
  )
}

# ---- 场景清单（对齐参考 MENUPATH_* 常量与 Scenes 映射）----
# 文件（HKCR\*，AllFilesystemObjects 归入文件分类）
Scan-Scene '文件' (Get-SceneViews '\*')
Scan-Scene '文件' (Get-SceneViews '\AllFilesystemObjects')
# EXE 文件（对齐 Scenes.ExeFile：exefile + SystemFileAssociations\.exe）
Scan-Scene 'EXE文件' (Get-SceneViews '\exefile')
Scan-Scene 'EXE文件' (Get-SceneViews '\SystemFileAssociations\.exe')
# LNK 文件
Scan-Scene 'LNK文件' (Get-SceneViews '\lnkfile')
Scan-Scene 'LNK文件' (Get-SceneViews '\SystemFileAssociations\.lnk')
# 目录 / 文件夹 / 驱动器 / 目录背景 / 桌面背景
Scan-Scene '目录' (Get-SceneViews '\Directory')
Scan-Scene '文件夹' (Get-SceneViews '\Folder')
Scan-Scene '驱动器' (Get-SceneViews '\Drive')
Scan-Scene '目录背景' (Get-SceneViews '\Directory\Background')
Scan-Scene '桌面背景' (Get-SceneViews '\DesktopBackground')
# 回收站（对齐参考：CLSID\{645FF040} 主路径 + RecycleBinFolder 补充）
Scan-Scene '回收站' @(($HKCR + '\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}'), ($HKCR + '\RecycleBinFolder'))
# 此电脑（新增，对齐 MENUPATH_COMPUTER）
Scan-Scene '此电脑' @(($HKCR + '\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}'))
# 库（新增，对齐 Scenes.Library：LibraryFolder + Background + UserLibraryFolder 三个子树）
Scan-Scene '库' @(($HKCR + '\LibraryFolder'), ($HKCR + '\LibraryFolder\Background'), ($HKCR + '\UserLibraryFolder'))

# ---- 发送到（文件系统目录，非注册表） ----
$sendToPaths = @(
  ([Environment]::GetFolderPath('ApplicationData') + '\Microsoft\Windows\SendTo'),
  ($env:ProgramData + '\Microsoft\Windows\SendTo')
)
foreach ($sendToPath in $sendToPaths) {
  if (-not (Test-Path -LiteralPath $sendToPath)) { continue }
  foreach ($item in @(Get-ChildItem -LiteralPath $sendToPath -Force -ErrorAction SilentlyContinue)) {
    if ($item.Name -ieq 'desktop.ini') { continue }
    $systemExtensions = @('.DeskLink', '.MAPIMail', '.ZFSendToTarget', '.mydocs')
    $company = if ($systemExtensions -contains $item.Extension) { 'Microsoft Corporation' } else { '' }
    Add-Result -Name $item.BaseName -CLSID '' -RegPath $item.FullName -Location $sendToPath -Category '发送到' -Source 'filesystem' -CompanyOverride $company
  }
}

# ---- UWP / 打包应用（PackagedCom 与 FileExplorerContextMenus 合约） ----
$uwpRoots = @('Registry::HKEY_CLASSES_ROOT\PackagedCom',
              'Registry::HKEY_CURRENT_USER\Software\Classes\PackagedCom',
              'Registry::HKEY_LOCAL_MACHINE\Software\Classes\PackagedCom')
foreach ($uwpRoot in $uwpRoots) {
  if (-not (Test-Path -LiteralPath $uwpRoot)) { continue }
  foreach ($key in @(Get-ChildItem -LiteralPath $uwpRoot -Recurse -ErrorAction SilentlyContinue)) {
    if ($key.PSPath -notmatch '(?i)(ContextMenu|ShellExt|ExplorerCommand|IContextMenu)') { continue }
    $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
    $clsid = [string]$props.'(default)'
    if (-not $clsid) { continue }
    $packageName = ($key.PSPath -split '\\')[-2]
    if ([string]::IsNullOrWhiteSpace($packageName)) { $packageName = [string]$key.PSChildName }
    Add-Result -Name $packageName -CLSID $clsid -RegPath (Convert-ToStdRegPath $key.PSPath) -Location $uwpRoot -Category 'UWP应用' -Source 'packagedcom'
  }
}

$uwpContractRoots = @('Registry::HKEY_CLASSES_ROOT\Extensions\ContractId\Windows.FileExplorerContextMenus',
                      'Registry::HKEY_CURRENT_USER\Software\Classes\Extensions\ContractId\Windows.FileExplorerContextMenus',
                      'Registry::HKEY_LOCAL_MACHINE\Software\Classes\Extensions\ContractId\Windows.FileExplorerContextMenus')
foreach ($contractRoot in $uwpContractRoots) {
  if (-not (Test-Path -LiteralPath $contractRoot)) { continue }
  foreach ($key in @(Get-ChildItem -LiteralPath $contractRoot -Recurse -ErrorAction SilentlyContinue)) {
    $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
    $packageName = [string]$props.PackageId
    if (-not $packageName -and $key.PSPath -match '(?i)PackageId\\([^\\]+)') { $packageName = $Matches[1] }
    if (-not $packageName) { continue }
    $clsid = [string]$props.Clsid
    if (-not $clsid) { $clsid = [string]$props.'(default)' }
    Add-Result -Name $packageName -CLSID $clsid -RegPath (Convert-ToStdRegPath $key.PSPath) -Location $contractRoot -Category 'UWP应用' -Source 'uwp-contract'
  }
}

# ---- Win+X 菜单（批次 C：%LOCALAPPDATA%\Microsoft\Windows\WinX\Group{1,2,3}\*.lnk）----
# 侧边栏一直有「Win+X」分类却没有任何数据源（死 tab）。Explorer 只列 .lnk，
# 所以可逆禁用 = 扩展名改成 .lnk.disabled；删除仍由主进程走回收站（source 归入文件类）。
$winxRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WinX'
foreach ($group in @('Group1', 'Group2', 'Group3')) {
  $gdir = Join-Path $winxRoot $group
  if (-not (Test-Path -LiteralPath $gdir)) { continue }
  foreach ($f in @(Get-ChildItem -LiteralPath $gdir -Force -ErrorAction SilentlyContinue)) {
    if ($f.PSIsContainer) { continue }
    if ($f.Name -ieq 'desktop.ini') { continue }
    $isOff = ($f.Extension -ieq '.disabled')
    $label = if ($isOff) { ([string]$f.BaseName -replace '(?i)\.lnk$', '') } else { [string]$f.BaseName }
    if ([string]::IsNullOrWhiteSpace($label)) { continue }
    Add-Result -Name $label -CLSID '' -RegPath $f.FullName -Location $gdir -Category 'Win+X' -Source 'winx' -CompanyOverride 'Microsoft Corporation' -Enabled (-not $isOff)
  }
}

# ---- 新建菜单（批次 C：由 HKCU 的 PostSetup\ShellNew 的 Classes 值驱动）----
# 「新建」子菜单出现哪些类型，取决于这张 REG_MULTI_SZ 列表；本机实测 10 项里
# .doc/.ppt/.xls 等已经没有对应的 ShellNew 键 = 卸载残留（悬空项），照样占着菜单位。
# 可逆禁用 = 从 Classes 列表摘掉该类名，不碰 ShellNew 键本身；整张表在 HKCU → 不需要管理员。
# 刻意不做全量 HKCR 扩展名枚举：那会让每次扫描多花数秒，而「有 ShellNew 却不在列表里」的类
# 本来就不会出现在菜单中，价值低。
$postSetupStd = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Discardable\PostSetup\ShellNew'
$psKey = Get-Item -LiteralPath ('Registry::' + $postSetupStd) -ErrorAction SilentlyContinue
if ($psKey) {
  foreach ($cls in @($psKey.GetValue('Classes'))) {
    $c = ([string]$cls).Trim()
    if ([string]::IsNullOrWhiteSpace($c)) { continue }
    $hasShellNew = $false
    foreach ($view in @($HKCR, $HKCU_CLASSES, $HKLM_WOW64_CLASSES)) {
      if (Test-Path -LiteralPath ($view + '\' + $c + '\ShellNew')) { $hasShellNew = $true; break }
    }
    $nm = if ($hasShellNew) { ('新建 ' + $c) } else { ('新建 ' + $c + '（残留：无 ShellNew 键）') }
    Add-Result -Name $nm -CLSID '' -RegPath $postSetupStd -Location $postSetupStd -Category '新建菜单' -Source 'shellnew' -CompanyOverride 'Microsoft Corporation' -Enabled $true -Target $c -Orphan (-not $hasShellNew)
  }
}

# ---- 打开方式（批次 C：HKCR\Applications\<app>\shell\<verb>，禁用 = 写 NoOpenWith）----
$appRoot = $HKCR + '\Applications'
if (Test-Path -LiteralPath $appRoot) {
  foreach ($app in @((Get-Item -LiteralPath $appRoot -ErrorAction SilentlyContinue).GetSubKeyNames())) {
    $appPath = $appRoot + '\' + $app
    $shellPath = $appPath + '\shell'
    if (-not (Test-Path -LiteralPath $shellPath)) { continue }
    $verbs = @((Get-Item -LiteralPath $shellPath -ErrorAction SilentlyContinue).GetSubKeyNames())
    if (-not $verbs.Count) { continue }
    $appKey = Get-Item -LiteralPath $appPath -ErrorAction SilentlyContinue
    if (-not $appKey) { continue }
    $friendly = Get-DirectString ([string]$appKey.GetValue('FriendlyAppName'))
    if ([string]::IsNullOrWhiteSpace($friendly)) { $friendly = $app }
    $noOpen = ($null -ne $appKey.GetValue('NoOpenWith'))
    Add-Result -Name $friendly -CLSID '' -RegPath (Convert-ToStdRegPath $appPath) -Location $appRoot -Category '打开方式' -Source 'openwith' -Enabled (-not $noOpen) -Command ($verbs -join ', ')
  }
}
# *\OpenWithList\<app>：对所有文件生效的「打开方式」候选；禁用 = 键名加 '-' 前缀（与 shellex 同约定）
$owlRoot = $HKCR + '\*\OpenWithList'
if (Test-Path -LiteralPath $owlRoot) {
  foreach ($child in @((Get-Item -LiteralPath $owlRoot -ErrorAction SilentlyContinue).GetSubKeyNames())) {
    $real = [string]$child
    $en = $true
    if ($real.StartsWith('-')) { $en = $false; $real = $real.Substring(1) }
    if ([string]::IsNullOrWhiteSpace($real)) { continue }
    $k = Get-Item -LiteralPath ($owlRoot + '\' + $child) -ErrorAction SilentlyContinue
    if (-not $k) { continue }
    Add-Result -Name ($real + '（所有文件）') -CLSID '' -RegPath (Convert-ToStdRegPath $k.PSPath) -Location $owlRoot -Category '打开方式' -Source 'openwith-list' -Enabled $en -Command ([string]$k.GetValue(''))
  }
}

# ---- 全局去重：同一分类、名称、CLSID、启用状态在多个注册表视图中只展示一次 ----
# （enabled 参与去重：同名处理器可能在活跃组与 '-ContextMenuHandlers' 禁用组各出现一次）
# CM-9 附带修正：无 CLSID 的条目改用 nativeRegPath 作身份键。原来用 regPath（HKCR 合并视图路径），
# 同一物理键经 HKCR 与 HKCU 两个视图各扫一次时会留下两行（重复行 + 禁一半的观感来源）。
$seen = @{}
$deduped = @()
foreach ($result in @($script:results)) {
  $enabledText = if ($result.enabled) { '1' } else { '0' }
  $key = if ([string]::IsNullOrWhiteSpace([string]$result.clsid)) {
    '{0}|{1}|{2}|{3}|{4}' -f $result.category, $result.name, $result.source, $result.nativeRegPath, $enabledText
  } else {
    '{0}|{1}|{2}|{3}' -f $result.category, $result.name, $result.clsid, $enabledText
  }
  if ($seen.ContainsKey($key)) { continue }
  $seen[$key] = $true
  $deduped += $result
}
# ---- 手工构建合法 JSON（纯 ASCII：非 ASCII 字符转义为 \uXXXX），彻底规避 ConvertTo-Json 对脏数据的缺陷 ----
$jsonParts = @()
foreach ($result in @($deduped)) {
  $obj = '{' +
    '"name":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.name)) + ',' +
    '"clsid":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.clsid)) + ',' +
    '"regPath":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.regPath)) + ',' +
    '"nativeRegPath":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.nativeRegPath)) + ',' +
    '"company":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.company)) + ',' +
    '"location":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.location)) + ',' +
    '"category":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.category)) + ',' +
    '"source":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.source)) + ',' +
    '"filePath":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.filePath)) + ',' +
    '"command":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.command)) + ',' +
    '"isThirdParty":' + (ConvertTo-JsonSafeBool $result.isThirdParty) + ',' +
    '"isProtected":' + (ConvertTo-JsonSafeBool $result.isProtected) + ',' +
    '"confirmRequired":' + (ConvertTo-JsonSafeBool $result.confirmRequired) + ',' +
    '"unknownConvention":' + (ConvertTo-JsonSafeBool $result.unknownConvention) + ',' +
    '"orphan":' + (ConvertTo-JsonSafeBool $result.orphan) + ',' +
    '"orphanReason":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.orphanReason)) + ',' +
    '"blockedBy":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.blockedBy)) + ',' +
    '"target":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.target)) + ',' +
    '"confirmReason":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.confirmReason)) + ',' +
    '"risk":' + (ConvertTo-JsonSafeString (Format-CleanStr $result.risk)) + ',' +
    '"enabled":' + (ConvertTo-JsonSafeBool $result.enabled) +
    '}'
  $jsonParts += $obj
}
if ($jsonParts.Count -eq 0) { '[]' } else { '[' + ($jsonParts -join ',') + ']' }
