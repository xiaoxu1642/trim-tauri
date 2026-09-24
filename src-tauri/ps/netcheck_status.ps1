# <<<PROVENANCE
# 来源：vendor/upstream-js/src/scripts-powershell/netcheck-scripts.js → status()
# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；
#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。
# 说明：网络连通性全面检测（只读）
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

$tcpTargets = ConvertFrom-Json ('[{"host":"223.5.5.5","port":443},{"host":"www.baidu.com","port":443}]')
# ---------- 1. 网络硬件配置 ----------
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
  Where-Object { $_.Virtual -ne $true }
$upList = @($adapters | Where-Object { $_.Status -eq 'Up' })
$badList = @($adapters | Where-Object { $_.Status -ne 'Up' })
$disabledList = @($adapters | Where-Object { $_.Status -eq 'Disabled' })

$adapterItem = @{ id = 'adapter'; status = 'unknown'; evidence = @(); detail = '' }
if ($upList.Count -gt 0) {
  foreach ($a in $upList) {
    # LinkSpeed 本身就是格式化字符串（如 1 Gbps），不要再做数值转换（方法异常会中断本项赋值）
    $adapterItem.evidence += ('网卡 ' + $a.Name + '：Up，' + $a.LinkSpeed)
  }
  if ($disabledList.Count -gt 0) {
    # 只有「已禁用」的网卡提供一键启用；媒体断开（如 WLAN 未连接）属正常状态，仅列出
    $adapterItem.status = 'warn'
    foreach ($a in $badList) { $adapterItem.evidence += ('网卡 ' + $a.Name + '：' + $a.Status) }
    $adapterItem.detail = '存在被禁用的网卡'
    $disabledNames = @($disabledList | ForEach-Object { $_.Name }) -join ','
    $adapterItem.repair = @{ id = 'enable-adapter'; name = $disabledNames }
  } else {
    $adapterItem.status = 'ok'
  }
} elseif ($badList.Count -gt 0) {
  $adapterItem.status = 'fail'
  foreach ($a in $badList) { $adapterItem.evidence += ('网卡 ' + $a.Name + '：' + $a.Status) }
  $adapterItem.detail = '没有可用网卡'
  if ($disabledList.Count -gt 0) {
    $disabledNames = @($disabledList | ForEach-Object { $_.Name }) -join ','
    $adapterItem.repair = @{ id = 'enable-adapter'; name = $disabledNames }
  }
} else {
  $adapterItem.status = 'unknown'
  $adapterItem.detail = '未枚举到物理网卡'
}

# ---------- 2. 网络连接配置 ----------
$ipItem = @{ id = 'ipconfig'; status = 'unknown'; evidence = @(); detail = '' }
$ipcfgs = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.NetAdapter.Status -eq 'Up' })
$hasApipa = $false
$hasGateway = $false
$hasValidIp = $false
foreach ($c in $ipcfgs) {
  foreach ($ip in @($c.IPv4Address)) {
    $addr = [string]$ip.IPAddress
    if (-not $addr) { continue }
    $iface = '网卡 ' + $c.InterfaceAlias + '：' + $addr
    if ($addr.StartsWith('169.254.')) {
      $hasApipa = $true
      $ipItem.evidence += ($iface + '（APIPA，未从 DHCP 取到地址）')
    } else {
      $hasValidIp = $true
      $ipItem.evidence += $iface
    }
  }
  foreach ($gw in @($c.IPv4DefaultGateway)) {
    if ($gw -and $gw.NextHop) {
      $hasGateway = $true
      $ipItem.evidence += ('默认网关 ' + $gw.NextHop + '（' + $c.InterfaceAlias + '）')
    }
  }
}
if ($hasApipa) {
  $ipItem.status = 'fail'
  $ipItem.detail = '网卡持有 169.254 自动私有地址，DHCP 未取到有效地址'
} elseif ($hasValidIp -and $hasGateway) {
  $ipItem.status = 'ok'
} elseif ($hasValidIp) {
  $ipItem.status = 'warn'
  $ipItem.detail = '有 IPv4 地址但没有默认网关（可能为孤立网络或静态配置）'
} else {
  $ipItem.detail = '未取到有效 IPv4 配置'
}

# ---------- 3. DHCP 服务 ----------
# NT-3（2026-09-15）：静态 IP 用户 DHCP 服务未运行属合法配置，不再误报红色。
# 仅当有活动网卡实际启用 DHCP 但服务未跑时才判 fail；否则给 warn/ok 并说明。
$dhcpItem = @{ id = 'dhcp'; status = 'ok'; evidence = @(); detail = '' }
$dhcpSvc = Get-Service -Name Dhcp -ErrorAction SilentlyContinue
$dhcpInUse = $false
foreach ($c in $ipcfgs) {
  if ($c.Dhcp -eq $true) { $dhcpInUse = $true; break }
}
if (-not $dhcpSvc) {
  $dhcpItem.status = 'warn'
  $dhcpItem.detail = '未找到 Dhcp 服务'
} elseif ($dhcpSvc.Status -eq 'Running') {
  $dhcpItem.status = 'ok'
  $dhcpItem.detail = 'Dhcp 服务运行正常'
} elseif ($dhcpInUse) {
  # 有网卡走 DHCP 但服务停了：真正的问题
  $dhcpItem.status = 'fail'
  $dhcpItem.detail = '有网卡使用 DHCP（自动获取 IP），但 DHCP 服务未运行'
  $dhcpItem.repair = @{ id = 'start-dhcp' }
} else {
  # 静态 IP（无网卡依赖 DHCP）：DHCP 服务停属合法，仅提示，可一键开启备查
  $dhcpItem.status = 'warn'
  $dhcpItem.detail = '当前网卡均使用静态 IP（不依赖 DHCP），DHCP 服务未运行属正常'
  $dhcpItem.repair = @{ id = 'start-dhcp' }
}
$dhcpItem.evidence += ('Dhcp 服务：' + $dhcpSvc.Status + '，启动类型 ' + $dhcpSvc.StartType + '；DHCP 网卡启用：' + $dhcpInUse)

# ---------- 4. DNS 服务与配置 ----------
$dnsItem = @{ id = 'dns'; status = 'unknown'; evidence = @(); detail = '' }
$dnsSvc = Get-Service -Name Dnscache -ErrorAction SilentlyContinue
$dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 })
if ($dnsSvc) { $dnsItem.evidence += ('Dnscache 服务：' + $dnsSvc.Status + '，启动类型 ' + $dnsSvc.StartType) }
foreach ($s in $dnsServers) {
  $dnsItem.evidence += ('DNS ' + $s.InterfaceAlias + '：' + ($s.ServerAddresses -join ', '))
}
$dnsSvcStopped = ($dnsSvc -and $dnsSvc.Status -ne 'Running')
$dnsNone = ($dnsServers.Count -eq 0)
if ($dnsSvcStopped -or $dnsNone) {
  $dnsItem.status = 'fail'
  if ($dnsSvcStopped) {
    $dnsItem.detail = 'DNS Client 服务未运行'
    $dnsItem.repair = @{ id = 'start-dnscache' }
  } else {
    $dnsItem.detail = '所有网卡均未配置 DNS 服务器'
    # 重置目标接口：取检测时活动网卡（有默认网关优先）的接口索引，由主进程快照固定下来
    $activeIdx = $null
    foreach ($c in $ipcfgs) {
      if (@($c.IPv4DefaultGateway).Count -gt 0) { $activeIdx = [int]$c.InterfaceIdentifier; break }
    }
    if (-not $activeIdx -and $ipcfgs.Count -gt 0) { $activeIdx = [int]$ipcfgs[0].InterfaceIdentifier }
    if ($activeIdx) { $dnsItem.repair = @{ id = 'reset-dns'; interfaceIndex = $activeIdx } }
  }
} elseif ($dnsSvc) {
  $dnsItem.status = 'ok'
}

# ---------- 5. Web 代理设置 ----------
$proxyItem = @{ id = 'proxy'; status = 'unknown'; evidence = @(); detail = '' }
$uReg = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$pEnable = ($uReg -and $uReg.ProxyEnable -eq 1)
$pServer = if ($uReg) { [string]$uReg.ProxyServer } else { '' }
$pGpo = $false
$polDefs = Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
if ($polDefs -and $polDefs.ProxyEnable -eq 1) { $pGpo = $true }

# WinHTTP 代理（NT-4：IPv4 与域名型都要识别，避免域名代理被漏报跳过）
$winhttp = & netsh.exe winhttp show proxy 2>$null | Out-String
$winhttpHasProxy = ($winhttp -match 'proxy|代理服务器') -and -not ($winhttp -match '直接访问|DIRECT')
$winhttpServer = ''
$m = [regex]::Match($winhttp, '((?:d{1,3}.){3}d{1,3}|[a-zA-Z0-9._-]+):d{2,5}')
if ($m.Success) { $winhttpServer = $m.Groups[1].Value }

# 掩码显示（NT-4）：避免完整代理地址出现在 UI 与日志（日志同口径）。
# 三种形态一律遮盖：IPv4 掩中间两段、域名只留首标签、userinfo(user:pass@)整体打码。
function Mask-Proxy([string]$s) {
  if (-not $s) { return '' }
  $body = $s
  $sc = [regex]::Match($body, '^[a-zA-Z][a-zA-Z0-9+.-]*://')
  if ($sc.Success) { $body = $body.Substring($sc.Length) }
  $mask = $body
  $at = $body.LastIndexOf('@')
  if ($at -ge 0) { $mask = $body.Substring($at + 1) }
  if ($mask -match '^d{1,3}.d{1,3}.d{1,3}.d{1,3}') {
    $mask = ($mask -replace '^(d{1,3}.d{1,3}).d{1,3}.d{1,3}', '$1.*.*')
  } else {
    $dot = $mask.IndexOf('.')
    if ($dot -gt 0) { $mask = $mask.Substring(0, $dot) + '.*' }
  }
  if ($at -ge 0) { $mask = '***:***@' + $mask }
  return $mask
}

if ($pGpo) {
  $proxyItem.status = 'warn'
  $proxyItem.evidence += '检测到组策略下发的代理（由组织管理）'
  $proxyItem.detail = '代理由组策略下发，本工具不提供修复入口'
} elseif ($pEnable -and $pServer) {
  $proxyItem.evidence += ('用户代理已启用：' + (Mask-Proxy $pServer))
  $portMatch = [regex]::Match($pServer, ':(d{2,5})')
  $listening = $false
  if ($portMatch.Success) {
    $port = [int]$portMatch.Groups[1].Value
    $listen = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
    if ($listen.Count -gt 0) { $listening = $true }
  }
  if ($pServer.Contains('127.0.0.1') -and -not $listening) {
    $proxyItem.status = 'warn'
    $proxyItem.detail = '代理指向本机但无进程监听该端口（残留代理，典型「能连但打不开网页」根因）'
    $proxyItem.repair = @{ id = 'disable-user-proxy' }
    # NT-2（2026-09-15）：修复槽位分流——不再让 reset-winhttp 覆盖 disable-user-proxy
    $proxyItem.repairs = @(@{ id = 'disable-user-proxy' })
  } else {
    $proxyItem.status = 'ok'
    $proxyItem.detail = '检测到用户自配代理（属合法配置，不做改动）'
  }
} else {
  $proxyItem.evidence += '用户代理（WinINET）：未启用'
}
if ($winhttpHasProxy -and $winhttpServer) {
  $proxyItem.evidence += ('系统代理（WinHTTP）：' + (Mask-Proxy $winhttpServer))
  if ($proxyItem.status -eq 'ok') { $proxyItem.status = 'warn' }
  $proxyItem.detail = 'WinHTTP 层配置了代理，可能影响系统服务联网'
  $winhttpRepair = @{ id = 'reset-winhttp' }
  # 若已有 disable-user-proxy，追加为第二个修复槽；否则直接作为唯一修复
  if ($proxyItem.repairs) {
    $proxyItem.repairs += $winhttpRepair
    $proxyItem.repair = $proxyItem.repairs[0] # 兼容旧渲染层，取第一个
  } else {
    $proxyItem.repair = $winhttpRepair
    $proxyItem.repairs = @($winhttpRepair)
  }
}
if ($proxyItem.status -eq 'unknown') {
  $proxyItem.status = 'ok'
  if (-not $proxyItem.detail) { $proxyItem.detail = '未检测到代理' }
}

# ---------- 6. 连通性 ----------
$netItem = @{ id = 'connectivity'; status = 'unknown'; evidence = @(); detail = '' }
$gwIp = $null
foreach ($c in $ipcfgs) {
  foreach ($gw in @($c.IPv4DefaultGateway)) {
    if ($gw -and $gw.NextHop) { $gwIp = [string]$gw.NextHop; break }
  }
  if ($gwIp) { break }
}
$gwOk = $false
if ($gwIp) {
  $ping = Test-Connection -ComputerName $gwIp -Count 2 -Quiet -ErrorAction SilentlyContinue
  if ($ping) {
    $gwOk = $true
    $netItem.evidence += ('网关 ' + $gwIp + '：ping 通')
  } else {
    # ICMP 被防火墙拦截时补 TCP 探测二次确认，仍失败才判异常，证据行如实注明
    foreach ($p in 445,80) {
      $c1 = New-Object System.Net.Sockets.TcpClient
      try {
        $ar = $c1.BeginConnect($gwIp, $p, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne(2500)) { $c1.EndConnect($ar); $gwOk = $true }
      } catch { } finally { try { $c1.Close() } catch { } }
      if ($gwOk) {
        $netItem.evidence += ('网关 ' + $gwIp + '：ICMP 不通但 TCP ' + $p + ' 可达（ping 被防火墙拦截）')
        break
      }
    }
    if (-not $gwOk) { $netItem.evidence += ('网关 ' + $gwIp + '：不可达') }
  }
} else {
  $netItem.evidence += '无默认网关，跳过网关探测'
}

$netOk = $false
foreach ($t in $tcpTargets) {
  $c2 = New-Object System.Net.Sockets.TcpClient
  try {
    $ar2 = $c2.BeginConnect($t.host, $t.port, $null, $null)
    if ($ar2.AsyncWaitHandle.WaitOne(2500)) {
      $c2.EndConnect($ar2)
      $netOk = $true
      $netItem.evidence += ('外网 ' + $t.host + ':' + $t.port + '：可达')
      break
    }
  } catch { } finally { try { $c2.Close() } catch { } }
}
if (-not $netOk) {
  try {
    $ips = [System.Net.Dns]::GetHostAddresses('www.baidu.com')
    if ($ips -and $ips.Count -gt 0) {
      $netOk = $true
      $netItem.evidence += ('DNS 解析 www.baidu.com 成功')
    }
  } catch {
    $netItem.evidence += ('外网探测不可达（TCP 443 与 DNS 解析均失败）')
  }
}

if ($gwOk -and $netOk) {
  $netItem.status = 'ok'
} elseif ($gwOk) {
  $netItem.status = 'warn'
  $netItem.detail = '网关可达但外网不通（出口/运营商问题，本机无修复项）'
} else {
  $netItem.status = 'fail'
  $netItem.detail = '网关不可达（本地链路问题）'
}

# ---------- 7. 网卡高级属性（v3.7.0 议题六 P1：只读枚举）----------
# 设计约束（方案 §7.5 第一阶段）：
#   - 只枚举、不写入；本段不出现任何 Set- 开头的网卡命令。
#   - Get-NetAdapter -Physical 只拿物理网卡，按 有线 / 无线 / 其他 分组。
#   - 虚拟网卡（VPN、虚拟交换机、Hyper-V 等）单独列出并标 writable=$false，
#     Trim 第一版不对其开放任何写入入口（RAINZ 的 -Name '*' 一刀切不能照抄）。
#   - 属性表按驱动真实枚举生成（ValidDisplayValues 来自驱动），不硬编码「所有网卡都支持 X」。
$nicProps = @{ physical = @(); virtual = @(); writableOnly = $true }

function Get-NicKind($a) {
  $pmt = [string]$a.PhysicalMediaType
  $mt = [string]$a.MediaType
  if ($pmt -match '802.11|Wireless|Wi-?Fi' -or $mt -match 'Native 802.11') { return 'wlan' }
  if ($pmt -match '802.3|Ethernet' -or $mt -match '802.3') { return 'ethernet' }
  return 'other'
}

foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)) {
  $props = @()
  foreach ($p in @(Get-NetAdapterAdvancedProperty -Name $a.Name -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -and $_.DisplayValue })) {
    $props += @([pscustomobject]@{
      name = [string]$p.DisplayName
      key = [string]$p.RegistryKeyword
      value = [string]$p.DisplayValue
      # 驱动支持的取值集合（第一版只用于展示；写入阶段才做目标值校验）
      valid = @(@($p.ValidDisplayValues) | Where-Object { $_ })
    })
  }
  # RSS / 校验和卸载 / 电源管理：单独三条只读状态，不与高级属性表混成一条命令
  $rss = Get-NetAdapterRss -Name $a.Name -ErrorAction SilentlyContinue
  $csum = Get-NetAdapterChecksumOffload -Name $a.Name -ErrorAction SilentlyContinue
  $pmg = Get-NetAdapterPowerManagement -Name $a.Name -ErrorAction SilentlyContinue
  $nicProps.physical += @([pscustomobject]@{
    name = [string]$a.Name
    desc = [string]$a.InterfaceDescription
    status = [string]$a.Status
    speed = [string]$a.LinkSpeed
    kind = (Get-NicKind $a)
    writable = $true
    props = @($props)
    rss = $(if ($rss) { [bool]$rss.Enabled } else { $null })
    csum = $(if ($csum) { (@([string]$csum.Ipv4TransmitChecksum, [string]$csum.Ipv4ReceiveChecksum) -join '/') } else { '' })
    pmOff = $(if ($pmg) { [bool]$pmg.AllowComputerToTurnOffDevice } else { $null })
    wolMagic = $(if ($pmg) { [bool]$pmg.WakeOnMagicPacket } else { $null })
  })
}

foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Virtual -eq $true })) {
  $nicProps.virtual += @([pscustomobject]@{
    name = [string]$a.Name
    desc = [string]$a.InterfaceDescription
    status = [string]$a.Status
    # 红线：虚拟网卡不进入写入候选，渲染层据此隐藏所有写操作入口
    writable = $false
  })
}

$items = @($adapterItem, $ipItem, $dhcpItem, $dnsItem, $proxyItem, $netItem)
$out = @{ items = $items; nicProps = $nicProps; collectedAt = (Get-Date -Format 'o') }
Write-Output ($out | ConvertTo-Json -Compress -Depth 8)
