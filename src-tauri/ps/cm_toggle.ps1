# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/contextmenu-scripts.js → toggle(["__TRIM_ITEMS_JSON__"])
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：启用/禁用右键菜单项（哨兵 items）
# PROVENANCE>>>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$items = '["__TRIM_ITEMS_JSON__"]' | ConvertFrom-Json
$success = 0
$failed = 0
$results = @()

# 与 SCAN_SCRIPT 中的同名函数保持一致（两段脚本各自独立进程执行，故各存一份）
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

# Shell Extensions\Blocked 两级路径（CM-16）
$blockedPaths = @{
  user    = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked'
  machine = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked'
}

# 该 CLSID 的 COM 服务器是否落在 Windows 系统目录。
# 用「归属」而不是「GUID 名单」来判系统内置扩展：把内置命令的 ExplorerCommandHandler 加进
# 屏蔽表可能让整个 Win11 现代菜单失效、Explorer 回退经典菜单，所以这类一律拒绝入表。
function Test-SystemComServer {
  param([string]$Guid)
  $g = ([string]$Guid).Trim()
  if (-not $g) { return $false }
  $sysRoot = [string]$env:SystemRoot
  foreach ($view in @('Registry::HKEY_CLASSES_ROOT\CLSID',
                       'Registry::HKEY_CLASSES_ROOT\WOW6432Node\CLSID',
                       'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Wow6432Node\CLSID')) {
    foreach ($sub in @('InprocServer32', 'LocalServer32')) {
      $p = $view + '\' + $g + '\' + $sub
      if (-not (Test-Path -LiteralPath $p)) { continue }
      $raw = [string](Get-Item -LiteralPath $p -ErrorAction SilentlyContinue).GetValue('')
      if ([string]::IsNullOrWhiteSpace($raw)) { $raw = [string](Get-Item -LiteralPath $p).GetValue('CodeBase') }
      if ([string]::IsNullOrWhiteSpace($raw)) { continue }
      $expanded = [Environment]::ExpandEnvironmentVariables($raw.Trim().Trim('"'))
      if ($expanded.StartsWith($sysRoot, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
  }
  return $false
}

foreach ($item in @($items)) {
  $name = [string]$item.name
  $source = [string]$item.source
  # CM-9：优先真实 hive 路径（重命名后回传的 newNativeRegPath 也是这个口径）
  $target = [string]$item.nativeRegPath
  if ([string]::IsNullOrWhiteSpace($target)) { $target = [string]$item.regPath }
  $displayPath = [string]$item.regPath
  # ConvertFrom-Json 已将 enabled 解析为布尔，直接比较避免 -not/-and 优先级陷阱
  $wantEnabled = ($item.enabled -eq $true)
  # CM-17（批次 B）：与 REMOVE_SCRIPT 对齐，系统保护项在服务端就拒绝——
  # 不能只靠渲染层 isToggleable 的自觉，IPC 是信任边界。
  if ([string]$item.risk -eq 'protected') {
    $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'skip'; message = '系统保护项' }
    continue
  }
  if ([string]::IsNullOrWhiteSpace($target)) { $results += @{ name = $name; regPath = ''; status = 'skip'; message = '缺少目标路径' }; continue }

  try {
    $blockedBy = [string]$item.blockedBy
    $clsid = ([string]$item.clsid).Trim()

    # ---- Shell Extensions\Blocked 屏蔽表（CM-16，批次 B）----
    # 适用两类：① UWP / 打包 COM 项——过去直接「暂不支持启停」，现在用 Windows 原生屏蔽表
    # 实现可逆禁用；② 任何本来就靠屏蔽表禁用的项（blockedBy 非空）——必须用同一机制还原，
    # 否则「启用」只会去改键名，屏蔽值还在，项照样不出现。
    # 安全边界：默认只写 HKCU（当前用户）；blockedBy=machine 时才写 HKLM，那条路径由主进程
    # 的 contextmenuWriteNeedsAdmin 拦住要提权。系统内置 GUID 一律拒绝入表——把内置命令的
    # ExplorerCommandHandler 加进屏蔽表可能让整个 Win11 现代菜单失效、Explorer 回退经典菜单。
    if ($source -eq 'packagedcom' -or $source -eq 'uwp-contract' -or $blockedBy) {
      if ($clsid -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') {
        $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'skip'; message = '缺少有效 CLSID，无法用屏蔽表启停' }; continue
      }
      if (([string]$item.risk -eq 'protected') -or (Test-SystemComServer $clsid)) {
        $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'skip'; message = '系统内置扩展不允许加入屏蔽表（可能导致整个新式右键菜单失效）' }; continue
      }
      $scope = if ($blockedBy -eq 'machine') { 'machine' } else { 'user' }
      $blkPath = $blockedPaths[$scope]
      if (-not (Test-Path -LiteralPath $blkPath)) { New-Item -Path $blkPath -Force -ErrorAction Stop | Out-Null }
      if ($wantEnabled) {
        Remove-ItemProperty -LiteralPath $blkPath -Name $clsid -ErrorAction SilentlyContinue
      } else {
        New-ItemProperty -LiteralPath $blkPath -Name $clsid -PropertyType String -Value '' -Force -ErrorAction Stop | Out-Null
      }
      $bk = Get-Item -LiteralPath $blkPath -ErrorAction SilentlyContinue
      $stillBlocked = ($bk -and ($null -ne $bk.GetValue($clsid)))
      if ($stillBlocked -eq (-not $wantEnabled)) {
        $success++
        $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'ok'; newBlockedBy = $(if ($wantEnabled) { '' } else { $scope }); message = ($(if ($wantEnabled) { '已解除屏蔽' } else { '已屏蔽（不加载该扩展）' })) }
      } else {
        $failed++
        $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'error'; message = $(if ($scope -eq 'machine') { '屏蔽表写入未生效（机器级需要管理员权限）' } else { '屏蔽表写入未生效' }) }
      }
      continue
    }

    # ---- Win+X：.lnk ⇄ .lnk.disabled 重命名（Explorer 的 Win+X 只列 .lnk）----
    if ($source -eq 'winx') {
      if (-not (Test-Path -LiteralPath $target)) { $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'skip'; message = '文件不存在' }; continue }
      $leaf = [IO.Path]::GetFileName($target)
      $dir = [IO.Path]::GetDirectoryName($target)
      $isOff = ($leaf -match '(?i)\.disabled$')
      if ($wantEnabled -and -not $isOff) { $success++; $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'ok'; message = '已处于启用状态' }; continue }
      if (-not $wantEnabled -and $isOff) { $success++; $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'ok'; message = '已处于禁用状态' }; continue }
      $newLeaf = if ($wantEnabled) { $leaf -replace '(?i)\.disabled$', '' } else { $leaf + '.disabled' }
      Rename-Item -LiteralPath $target -NewName $newLeaf -ErrorAction Stop
      $newPath = Join-Path $dir $newLeaf
      if ((Test-Path -LiteralPath $newPath) -and -not (Test-Path -LiteralPath $target)) {
        $success++
        $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; newRegPath = $newPath; newNativeRegPath = $newPath; status = 'ok'; message = ($(if ($wantEnabled) { '已启用' } else { '已禁用' })) }
      } else {
        $failed++; $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'error'; message = '重命名未生效' }
      }
      continue
    }

    # ---- 发送到：Hidden 属性切换 ----
    if ($source -eq 'filesystem') {
      if (-not (Test-Path -LiteralPath $target)) { $results += @{ name = $name; regPath = $displayPath; status = 'skip'; message = '文件不存在' }; continue }
      $file = Get-Item -LiteralPath $target -Force
      if ($wantEnabled) {
        $file.Attributes = $file.Attributes -band (-bnot [IO.FileAttributes]::Hidden)
      } else {
        $file.Attributes = $file.Attributes -bor [IO.FileAttributes]::Hidden
      }
      $nowHidden = (([IO.FileAttributes]::Hidden -band (Get-Item -LiteralPath $target -Force).Attributes) -ne 0)
      if ($nowHidden -eq (-not $wantEnabled)) {
        $success++; $results += @{ name = $name; regPath = $displayPath; status = 'ok'; message = ($(if ($wantEnabled) { '已启用' } else { '已禁用' })) }
      } else {
        $failed++; $results += @{ name = $name; regPath = $displayPath; status = 'error'; message = '切换未生效' }
      }
      continue
    }

    # ---- 注册表项：统一转 PowerShell 提供程序路径 ----
    $regPath = $target
    if ($regPath -match '^HKEY_') { $regPath = 'Registry::' + $regPath }
    if (-not (Test-Path -LiteralPath $regPath)) { $results += @{ name = $name; regPath = $displayPath; status = 'skip'; message = '注册表路径不存在' }; continue }

    # ---- 新建菜单：改 HKCU PostSetup\ShellNew 的 Classes（REG_MULTI_SZ）列表 ----
    # 只摘/加类名，不动各扩展名下的 ShellNew 键本身 —— 键还在，随时可还原。
    if ($source -eq 'shellnew') {
      $cls = ([string]$item.target).Trim()
      if ([string]::IsNullOrWhiteSpace($cls)) { $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'skip'; message = '缺少类名（target）' }; continue }
      $psk = Get-Item -LiteralPath $regPath -ErrorAction Stop
      # 先 Where-Object 过滤再 @() 包装：@($null).Count 是 1，PS 判空陷阱
      $cur = @($psk.GetValue('Classes') | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
      $has = (@($cur | Where-Object { $_ -ieq $cls }).Count -gt 0)
      if ($wantEnabled -and $has) { $success++; $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'ok'; message = '已处于启用状态' }; continue }
      if (-not $wantEnabled -and -not $has) { $success++; $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'ok'; message = '已处于禁用状态' }; continue }
      if ($wantEnabled) {
        $new = @($cur) + $cls
      } else {
        $new = @($cur | Where-Object { $_ -ine $cls })
      }
      if ($new.Count -eq 0) {
        Remove-ItemProperty -LiteralPath $regPath -Name 'Classes' -ErrorAction Stop
      } else {
        Set-ItemProperty -LiteralPath $regPath -Name 'Classes' -Value ([string[]]$new) -Type MultiString -ErrorAction Stop
      }
      $chk = Get-Item -LiteralPath $regPath -ErrorAction SilentlyContinue
      $nowHas = $false
      if ($chk) { $nowHas = (@(@($chk.GetValue('Classes')) | Where-Object { [string]$_ -ieq $cls }).Count -gt 0) }
      if ($nowHas -eq $wantEnabled) {
        $success++; $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'ok'; message = ($(if ($wantEnabled) { '已启用' } else { '已禁用' })) }
      } else {
        $failed++; $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'error'; message = 'Classes 列表写入未生效' }
      }
      continue
    }

    # ---- 打开方式（应用）：NoOpenWith 值的写入与清除 ----
    if ($source -eq 'openwith') {
      if ($wantEnabled) {
        Remove-ItemProperty -LiteralPath $regPath -Name 'NoOpenWith' -ErrorAction SilentlyContinue
      } else {
        New-ItemProperty -LiteralPath $regPath -Name 'NoOpenWith' -PropertyType String -Value '' -Force -ErrorAction Stop | Out-Null
      }
      $ok2 = Get-Item -LiteralPath $regPath -ErrorAction SilentlyContinue
      $nowOff = ($ok2 -and ($null -ne $ok2.GetValue('NoOpenWith')))
      if ($nowOff -eq (-not $wantEnabled)) {
        $success++; $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'ok'; message = ($(if ($wantEnabled) { '已启用' } else { '已禁用' })) }
      } else {
        $failed++; $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'error'; message = '切换未生效（可能需要管理员权限）' }
      }
      continue
    }

    if ($source -eq 'shell') {
      # 四值可见性模型（CM-10）：禁用一次性写 LegacyDisable + ProgrammaticAccessOnly +
      # HideBasedOnVelocityId(0x639bc8)，启用一次性删三值并清 CommandFlags 的 0x8 位；
      # 写入与读回共用同一个 Test-VerbHidden，杜绝「按 A 写、按 B 判」的假状态。
      # （Split-Path 对 'Registry::' 路径会报参数集冲突，用字符串切分）
      $sepIdx = $regPath.LastIndexOf('\')
      $leaf = if ($sepIdx -ge 0) { $regPath.Substring($sepIdx + 1) } else { $regPath }
      $parent = if ($sepIdx -gt 0) { $regPath.Substring(0, $sepIdx) } else { '' }
      $renamedTo = ''
      if ($wantEnabled) {
        # Autoruns 的重命名禁用约定：真实写法是无下划线的 'AutorunsDisabled'，
        # 旧实现只认 'AutorunsDisabled_' 前缀，导致这类键还原不了
        if ($leaf -match '(?i)^AutorunsDisabled_?(.+)$') {
          $renamedTo = $Matches[1]
          Rename-Item -LiteralPath $regPath -NewName $renamedTo -ErrorAction Stop
          $regPath = $parent + '\' + $renamedTo
        }
        foreach ($vn in @('LegacyDisable', 'Blocked', 'ProgrammaticAccessOnly', 'HideBasedOnVelocityId')) {
          Remove-ItemProperty -LiteralPath $regPath -Name $vn -ErrorAction SilentlyContinue
        }
        # CommandFlags 只清 0x8（隐藏位）；其余位是合法动词属性，不能整值删除
        $kNow = Get-Item -LiteralPath $regPath -ErrorAction SilentlyContinue
        $cf = if ($kNow) { $kNow.GetValue('CommandFlags') } else { $null }
        if ($null -ne $cf) {
          try {
            $cleared = ([int]$cf) -band (-bnot 0x8)
            if ($cleared -eq 0) {
              Remove-ItemProperty -LiteralPath $regPath -Name 'CommandFlags' -ErrorAction SilentlyContinue
            } else {
              Set-ItemProperty -LiteralPath $regPath -Name 'CommandFlags' -Value $cleared -Type DWord -ErrorAction SilentlyContinue
            }
          } catch {}
        }
      } else {
        New-ItemProperty -LiteralPath $regPath -Name 'ProgrammaticAccessOnly' -PropertyType String -Value '' -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $regPath -Name 'HideBasedOnVelocityId' -PropertyType DWord -Value 0x639bc8 -Force -ErrorAction SilentlyContinue | Out-Null
        # opennewwindow 硬特判：带 LegacyDisable 会连带废掉 Win+E 与任务栏「新开窗口」，
        # 只靠 ProgrammaticAccessOnly + velocity 即可达成「不在菜单显示」而不破坏程序化调用
        if ($regPath -notmatch '(?i)\\Folder\\shell\\opennewwindow$') {
          New-ItemProperty -LiteralPath $regPath -Name 'LegacyDisable' -PropertyType String -Value '' -Force -ErrorAction Stop | Out-Null
        }
      }
      $kFinal = Get-Item -LiteralPath $regPath -ErrorAction SilentlyContinue
      $nowHidden = Test-VerbHidden $kFinal
      # 特例项不写 LegacyDisable，因此只校验「确实处于隐藏态」而非逐值比对
      if ($nowHidden -eq (-not $wantEnabled)) {
        $success++
        $res = @{ id = [string]$item.id; name = $name; regPath = $displayPath; status = 'ok'; message = ($(if ($wantEnabled) { '已启用' } else { '已禁用' })) }
        if ($renamedTo) {
          $res.newNativeRegPath = ($regPath -replace '^Registry::', '')
          if ($displayPath) {
            $dIdx = $displayPath.LastIndexOf('\')
            if ($dIdx -ge 0) { $res.newRegPath = ($displayPath.Substring(0, $dIdx + 1) + $renamedTo) }
          }
        }
        $results += $res
      } else {
        $failed++; $results += @{ name = $name; regPath = $displayPath; status = 'error'; message = '切换未生效（可能需要管理员权限）' }
      }
      continue
    }

    # ---- shellex：处理器键名 '-' 前缀重命名 ----
    # 注意：PowerShell 7 的 Split-Path/Join-Path 对 'Registry::' 提供程序路径会报参数集冲突，
    # 这里一律用字符串切分与拼接
    $sepIdx = $regPath.LastIndexOf('\')
    $parent = if ($sepIdx -gt 0) { $regPath.Substring(0, $sepIdx) } else { '' }
    $leaf = if ($sepIdx -ge 0) { $regPath.Substring($sepIdx + 1) } else { $regPath }
    if ($wantEnabled) {
      if (-not $leaf.StartsWith('-')) { $success++; $results += @{ name = $name; regPath = $displayPath; status = 'ok'; message = '已处于启用状态' }; continue }
      $newName = $leaf.Substring(1)
    } else {
      if ($leaf.StartsWith('-')) { $success++; $results += @{ name = $name; regPath = $displayPath; status = 'ok'; message = '已处于禁用状态' }; continue }
      $newName = '-' + $leaf
    }
    Rename-Item -LiteralPath $regPath -NewName $newName -ErrorAction Stop
    $newPath = $parent + '\' + $newName
    if ((Test-Path -LiteralPath $newPath) -and -not (Test-Path -LiteralPath $regPath)) {
      # 返回重命名后的新路径（标准格式，剥离 Registry:: 前缀）；
      # newRegPath=展示用（HKCR 口径，渲染层按它关联）、newNativeRegPath=真实 hive（主进程回写快照）
      $success++
      $stdNew = $newPath -replace '^Registry::', ''
      $dIdx = $displayPath.LastIndexOf('\')
      $newDisplay = if ($dIdx -ge 0) { $displayPath.Substring(0, $dIdx + 1) + $newName } else { $displayPath }
      $results += @{ id = [string]$item.id; name = $name; regPath = $displayPath; newRegPath = $newDisplay; newNativeRegPath = $stdNew; status = 'ok'; message = ($(if ($wantEnabled) { '已启用' } else { '已禁用' })) }
    } else {
      $failed++; $results += @{ name = $name; regPath = $displayPath; status = 'error'; message = '重命名未生效（可能需要管理员权限）' }
    }
  } catch {
    $failed++
    $results += @{ name = $name; regPath = $displayPath; status = 'error'; message = $_.Exception.Message }
  }
}
[pscustomobject]@{ success = $success; failed = $failed; results = @($results) } | ConvertTo-Json -Depth 6 -Compress
