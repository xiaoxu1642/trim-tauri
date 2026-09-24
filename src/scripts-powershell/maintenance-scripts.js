// maintenance-scripts.js - 系统维护修复组（P2-16）
// 修复任务清单，本土化自 MangoDisk「系统维护」，分 3 类：
//   系统修复(7)：sfc / dism / wu / print / store / audio / perfcounters
//   搜索与界面(2)：iconthumb / search
//   网络连接(11)：dns / netstack + 原「电脑优化中心-网络优化」并入的 9 项调优
// 每项独立执行、独立确认；脚本统一注入诊断四元组（P1-11）。
// 命令均为幂等修复型操作，不删除用户数据（WU/Store 缓存重置仅停服务+改名缓存目录）。

const DIAG = require('../main/diag');

// 生成一段带回车行的干净 .reg 块（与 optimizer-scripts.regBlock 同规则）
function regBlock(entries) {
  const sections = Object.keys(entries);
  const parts = ['Windows Registry Editor Version 5.00', ''];
  for (const sec of sections) {
    parts.push(`[${sec}]`);
    const kvs = entries[sec];
    for (const k of Object.keys(kvs)) parts.push(`"${k}"=${kvs[k]}`);
    parts.push('');
  }
  return parts.join('\r\n');
}

// 将优化项 steps（reg/cmd/service/pwsh）转换为维护脚本片段。
// 转换规则与 optimizer-scripts.buildScript 一致；输出改为维护版逐行进度文本。
function stepsToPs(steps) {
  const L = [];
  steps.forEach((s) => {
    if (s.label) L.push(`Write-Output ('· ${String(s.label).replace(/'/g, "''")}')`);
    if (s.reg) {
      // MA-1（2026-09-15 v7）：.reg 中间文件改写应用私有目录（主进程 spawn 时经 TRIM_TMP
      // 注入 %APPDATA%\Trim\tmp），不再落全局可写 %TEMP%（S10 TOCTOU）；缺 env 回退 TEMP 保功能。
      L.push('$___tmpDir = if ($env:TRIM_TMP) { $env:TRIM_TMP } else { Join-Path $env:APPDATA "Trim\\tmp" }');
      L.push('if (-not (Test-Path -LiteralPath $___tmpDir)) { New-Item -ItemType Directory -Path $___tmpDir -Force | Out-Null }');
      L.push('$___rf = Join-Path $___tmpDir ("tfmaint_" + [guid]::NewGuid().ToString("N") + ".reg")');
      L.push("$___rc = @'");
      L.push(s.reg);
      L.push("'@");
      L.push('Set-Content -Path $___rf -Value $___rc -Encoding ASCII');
      L.push('& reg.exe import $___rf *> $null');
      L.push(`if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.reg' -Mutation 'partial' -Detail ('reg import exit=' + $LASTEXITCODE) }`);
      L.push('Remove-Item $___rf -Force -ErrorAction SilentlyContinue');
    } else if (s.cmd) {
      const safe = String(s.cmd).replace(/'/g, "''");
      L.push(`$___cmd='${safe}'`);
      L.push('& $env:ComSpec /c $___cmd *> $null');
      L.push(`if ($LASTEXITCODE -ne 0) { Write-TFDiag -Stage 'maint.opt.cmd' -Mutation 'partial' -Detail ('cmd exit=' + $LASTEXITCODE) }`);
    } else if (s.service) {
      L.push(`Stop-Service -Name '${s.service}' -Force -ErrorAction SilentlyContinue`);
      if (s.disable) L.push(`Set-Service -Name '${s.service}' -StartupType Disabled -ErrorAction SilentlyContinue`);
    } else if (s.pwsh) {
      // F1（2026-09-15）：与 optimizer buildScript 同模式——原 pwsh 步骤裸拼，
      // 失败被 PS_PREAMBLE 的 trap{continue} 吞掉后仍走到 @@RESULT@@ok。
      // 改为逐步骤 try/catch + Stop + 失败记诊断（注：不影响 stepsToPs 内其他步骤）。
      L.push('$___eap = $ErrorActionPreference');
      L.push('try {');
      L.push("  $ErrorActionPreference = 'Stop'");
      L.push(s.pwsh);
      L.push('} catch {');
      L.push(`  Write-TFDiag -Stage 'maint.opt.pwsh' -Mutation 'partial' -Detail $_.Exception.Message`);
      L.push('} finally {');
      L.push('  $ErrorActionPreference = $___eap');
      L.push('}');
    }
  });
  L.push("Write-Output '@@RESULT@@ok'");
  return L.join('\n');
}

// 任务定义：ps 为返回 PowerShell 脚本片段的函数（可含多行）。
// 输出协议：普通行作为进度/结果文本回传；@@DIAG@@ 行由主进程提取写日志。
const TASKS = {
  sfc: {
    title: '系统文件修复 (SFC)',
    desc: '运行 sfc /scannow 校验并修复受保护的系统文件。耗时较长（数分钟），期间请勿关闭电脑。',
    category: '系统修复',
    admin: true,
    ps: () => `
Write-Output '正在运行系统文件检查（sfc /scannow），请稍候…'
$out = & sfc.exe /scannow 2>&1 | Out-String
$lines = ($out -split '\\r?\\n' | Where-Object { $_.Trim() })
Write-Output ($lines -join [Environment]::NewLine)
if ($LASTEXITCODE -eq 0) { Write-Output '@@RESULT@@ok' } else { Write-TFDiag -Stage 'maint.sfc' -Mutation 'partial' -Detail ('sfc exit=' + $LASTEXITCODE); Write-Output '@@RESULT@@warn' }
`
  },
  dism: {
    title: '组件存储修复 (DISM /RestoreHealth)',
    desc: '运行 DISM /RestoreHealth 修复 Windows 组件存储（WinSxS）。常用于 SFC 无法修复时。',
    category: '系统修复',
    admin: true,
    ps: () => `
Write-Output '正在运行 DISM 组件存储修复（/RestoreHealth），请稍候…'
$out = & dism.exe /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String
$lines = ($out -split '\\r?\\n' | Where-Object { $_.Trim() } | Select-Object -Last 8)
Write-Output ($lines -join [Environment]::NewLine)
if ($LASTEXITCODE -eq 0) { Write-Output '@@RESULT@@ok' } else { Write-TFDiag -Stage 'maint.dism' -Mutation 'partial' -Detail ('dism exit=' + $LASTEXITCODE); Write-Output '@@RESULT@@warn' }
`
  },
  wu: {
    title: '重置 Windows Update 组件',
    desc: '停止更新服务并重置 SoftwareDistribution / catroot2 缓存目录后重启服务，修复更新卡住/下载失败。不会删除已安装更新。',
    category: '系统修复',
    admin: true,
    ps: () => `
$svcs = @('wuauserv','bits','cryptsvc','appidsvc','msiserver')
foreach ($s in $svcs) { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue }
Write-Output '已停止更新相关服务'
Start-Sleep -Seconds 2
$sd = Join-Path $env:WINDIR 'SoftwareDistribution'
$cr = Join-Path $env:WINDIR 'System32\\catroot2'
$reset = 0; $skip = 0
  # MA-3（2026-09-15 v7）：清扫上一轮遗留的 *.old_* 缓存备份（各保留最近 1 个供回退）。
  # 原实现每次重置都新增一个数百 MB 目录且永不清理，累积可达 GB 级。放在本次改名前执行，
  # 本轮新备份不受影响。
  # 复核 N2（删除红线，2026-09-16）：不再在 PS 内裸 Remove-Item，改为逐行输出 @@WU_OLD_BAK@@<路径>，
  # 由主进程 trashOrUnlink（回收站优先）执行；Where-Object 过滤空值，规避 @($null).Count=1 判空陷阱。
  foreach ($base in @($sd,$cr)) {
    $stale = @((Get-ChildItem -LiteralPath (Split-Path -Parent $base) -Filter ((Split-Path -Leaf $base) + '.old_*') -Directory -ErrorAction SilentlyContinue) | Where-Object { $_ } | Sort-Object LastWriteTime -Descending | Select-Object -Skip 1)
    foreach ($b in $stale) { Write-Output ('@@WU_OLD_BAK@@' + $b.FullName) }
  }
foreach ($d in @($sd,$cr)) {
  if (Test-Path -LiteralPath $d) {
    $bak = $d + '.old_' + (Get-Date -Format 'yyyyMMddHHmmss')
    try { Rename-Item -LiteralPath $d -NewName (Split-Path $bak -Leaf) -ErrorAction Stop; $reset++; Write-Output ('已重置缓存目录: ' + $d) }
    catch { $skip++; Write-TFDiag -Stage 'maint.wu' -Mutation 'partial' -Detail ('重命名失败(可能被占用): ' + $d + ' -> ' + $_.Exception.Message); Write-Output ('跳过(占用): ' + $d) }
  }
}
foreach ($s in $svcs) { Start-Service -Name $s -ErrorAction SilentlyContinue }
# F1（2026-09-15）：原为无条件 @@RESULT@@ok。改为回读：wuauserv 必须运行，且没有被占用的
# 缓存目录（skip=0 表示全部目标目录都成功改名）；否则如实报 warn。
$svcOk = (Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status -eq 'Running'
if ($svcOk -and $skip -eq 0) { Write-Output '已重启更新服务'; Write-Output '@@RESULT@@ok' }
else { Write-TFDiag -Stage 'maint.wu' -Mutation 'partial' -Detail ('回读: wuauserv=' + $svcOk + ' reset=' + $reset + ' skip=' + $skip); Write-Output '@@RESULT@@warn' }
`
  },
  // M3（2026-09-14 重复点审查）：原 print「清理打印队列」已下线。
  // 该能力统一由「磁盘清理」承接，条目路径取本页原实现的真实路径
  // （C:\Windows\System32\spool\PRINTERS；优化中心旧实现写的 C:\Windows\spool\printers
  //  在现代 Windows 上并不存在，属空操作）。
  store: {
    title: '重置 Microsoft Store 缓存',
    desc: '运行 wsreset 清理 Microsoft Store 应用缓存，修复商店打不开/下载异常。会关闭商店窗口。',
    category: '系统修复',
    admin: false,
    ps: () => `
Write-Output '正在清理 Store 缓存 (wsreset)…'
$p = Start-Process -FilePath 'wsreset.exe' -PassThru
Start-Sleep -Seconds 3
if ($p -and -not $p.HasExited) { Start-Sleep -Seconds 5 }
Write-Output 'Store 缓存清理已触发（完成后商店会自动打开，可手动关闭）'
Write-Output '@@RESULT@@ok'
`
  },
  audio: {
    title: '重启音频服务',
    desc: '重启 Windows Audio / AudioEndpointBuilder 服务，修复无声/耳机识别异常。不影响正在播放的内容之外的设置。',
    category: '系统修复',
    admin: true,
    ps: () => `
Restart-Service -Name Audiosrv -Force -ErrorAction SilentlyContinue
Restart-Service -Name AudioEndpointBuilder -Force -ErrorAction SilentlyContinue
$ok = (Get-Service Audiosrv -ErrorAction SilentlyContinue).Status -eq 'Running'
if ($ok) { Write-Output '音频服务已重启' ; Write-Output '@@RESULT@@ok' }
else { Write-TFDiag -Stage 'maint.audio' -Mutation 'partial' -Detail 'Audiosrv 未处于运行态'; Write-Output '@@RESULT@@warn' }
`
  },
  perfcounters: {
    title: '重建性能计数器',
    desc: '运行 lodctr /r 重建设能计数器库，修复任务管理器/性能监视器数据异常或报错。',
    category: '系统修复',
    admin: true,
    ps: () => `
Write-Output '正在重建性能计数器 (lodctr /r)…'
$out = & lodctr.exe /r 2>&1 | Out-String
Write-Output ($out.Trim())
if ($LASTEXITCODE -eq 0) { Write-Output '@@RESULT@@ok' } else { Write-TFDiag -Stage 'maint.perfcounters' -Mutation 'partial' -Detail ('lodctr exit=' + $LASTEXITCODE); Write-Output '@@RESULT@@warn' }
`
  },
  // M2（2026-09-14 重复点审查）：原 iconthumb「重建图标与缩略图缓存」已下线。
  // 它与「磁盘清理 - 缓存与预读」的 iconCacheFiles / thumbnailCacheFiles 作用于同一目录
  // （%LOCALAPPDATA%\Microsoft\Windows\Explorer），属功能重复，统一由磁盘清理承接。
  search: {
    title: '重建搜索索引',
    desc: '重置 Windows 搜索索引数据库，修复开始菜单/文件搜索无结果或结果过期。后台重建需一段时间。',
    category: '搜索与界面',
    admin: true,
    ps: () => `
Stop-Service -Name WSearch -Force -ErrorAction SilentlyContinue
$pf = $env:ProgramData
$idx = Join-Path $pf 'Microsoft\\Search\\Data\\Applications\\Windows'
$cleared = $true
if (Test-Path -LiteralPath $idx) {
  Remove-Item -Path (Join-Path $idx '*') -Recurse -Force -ErrorAction SilentlyContinue
  # F1（2026-09-15）：回读索引目录是否真的清空（原先无条件报成功）
  $left = @(Get-ChildItem -LiteralPath $idx -Force -ErrorAction SilentlyContinue).Count
  if ($left -gt 0) { $cleared = $false; Write-TFDiag -Stage 'maint.search' -Mutation 'partial' -Detail ('索引目录仍有残留: ' + $left) }
  else { Write-Output '已清空旧索引数据' }
}
Start-Service -Name WSearch -ErrorAction SilentlyContinue
$svcOk = (Get-Service -Name WSearch -ErrorAction SilentlyContinue).Status -eq 'Running'
if ($svcOk -and $cleared) { Write-Output '搜索服务已重启，索引将在后台重建'; Write-Output '@@RESULT@@ok' }
else { Write-TFDiag -Stage 'maint.search' -Mutation 'partial' -Detail ('回读: WSearch=' + $svcOk + ' cleared=' + $cleared); Write-Output '@@RESULT@@warn' }
`
  },
  dns: {
    title: '刷新 DNS 缓存',
    desc: '执行 ipconfig /flushdns 清空本地 DNS 解析缓存，修复网页打不开/解析到旧地址。',
    category: '网络连接',
    admin: false,
    ps: () => `
$out = & ipconfig.exe /flushdns 2>&1 | Out-String
Write-Output ($out.Trim())
if ($LASTEXITCODE -eq 0) { Write-Output '@@RESULT@@ok' } else { Write-TFDiag -Stage 'maint.dns' -Mutation 'partial' -Detail ('flushdns exit=' + $LASTEXITCODE); Write-Output '@@RESULT@@warn' }
`
  },
  netstack: {
    title: '重置网络栈 (Winsock/IP)',
    desc: '重置 Winsock 目录与 TCP/IP 栈后刷新 DNS，修复联网异常。会清空自定义网络筛选器，需重连网络。',
    category: '网络连接',
    admin: true,
    ps: () => `
Write-Output '正在重置 Winsock…'
& netsh.exe winsock reset 2>&1 | ForEach-Object { Write-Output $_ }
$ok1 = $LASTEXITCODE
Write-Output '正在重置 TCP/IP…'
& netsh.exe int ip reset 2>&1 | ForEach-Object { Write-Output $_ }
$ok2 = $LASTEXITCODE
& ipconfig.exe /flushdns 2>&1 | Out-Null
# F1（2026-09-15）：原为无条件 @@RESULT@@ok；改为按两条 netsh 的退出码判定。
if ($ok1 -eq 0 -and $ok2 -eq 0) { Write-Output '网络栈已重置（部分改动需重启电脑后完全生效）'; Write-Output '@@RESULT@@ok' }
else { Write-TFDiag -Stage 'maint.netstack' -Mutation 'partial' -Detail ('winsock=' + $ok1 + ' ip=' + $ok2); Write-Output '@@RESULT@@warn' }
`
  }
};

const CATEGORY_ORDER = ['系统修复', '搜索与界面', '网络连接'];

// ==================== 网络连接扩容（原「电脑优化中心-网络优化」并入） ====================
// 与维护版 dns / netstack 功能重复的「网络栈全量重置」不再迁移，以系统维护为准；
// 其余网络调优项全部并入「网络连接」分类后，优化中心已删除整个「网络优化」分组。
const NET_MIGRATED = [
  {
    id: 'net_response', title: '加快网络响应', risk: 'medium',
    desc: '关闭网络节流、系统响应降级，加快网络吞吐与系统反馈。',
    steps: [
      {
        label: '网络节流阈值 / 系统响应性', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile': {
            'NetworkThrottlingIndex': 'dword:ffffffff',
            'SystemResponsiveness': 'dword:00000000'
          }
        })
      }
    ]
  },
  {
    id: 'tf_net_tcp', title: 'TCP/IP 全局参数调优', risk: 'medium',
    desc: 'netsh 全局调优：关闭自动调优/ECN/RSC/时间戳/启发式/安全配置文件/任务卸载，启用 DCA/NetDMA/RSS，CTCP 拥塞提供程序，ARP 缓存 4096，初始 RTO 2000，MTU 1500，最大 SYN 重传 2，关闭 MPP（不涉及任何 IPv6 相关设置）。',
    steps: [
      { label: '网络节流指数最大化', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile': {
          'NetworkThrottlingIndex': 'dword:ffffffff',
          'SystemResponsiveness': 'dword:0000000a'
        }
      }) },
      { label: 'netsh TCP 全局参数', cmd: 'netsh int tcp set global autotuninglevel=disabled ecncapability=disabled dca=enabled netdma=enabled rsc=disabled rss=enabled timestamps=disabled initialrto=2000 nonsackrttresiliency=disabled maxsynretransmissions=2' },
      { label: 'RSS 基准 CPU', cmd: 'netsh int tcp set global rssbasecpu=1' },
      { label: '关闭安全配置文件', cmd: 'netsh int tcp set security profiles=disabled' },
      { label: '关闭 MPP', cmd: 'netsh int tcp set security mpp=disabled' },
      { label: '关闭缩放启发式', cmd: 'netsh int tcp set heuristics disabled' },
      { label: 'ARP 邻居缓存 4096', cmd: 'netsh int ip set global neighborcachelimit=4096' },
      { label: '启用 CTCP', cmd: 'netsh int tcp set supplemental Internet congestionprovider=ctcp' },
      { label: '关闭任务卸载', cmd: 'netsh int ip set global taskoffload=disabled' },
      { label: '所有网卡 MTU 设为 1500', pwsh: 'Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object { netsh interface ipv4 set subinterface "$($_.Name)" mtu=1500 store=persistent *> $null }' }
    ]
  },
  {
    id: 'tf_net_tcpip', title: 'Tcpip 注册表参数', risk: 'medium',
    desc: '注册表网络参数：TTL=64、窗口缩放、TcpMaxDupAcks=2、关闭 SACK、MaxUserPort=65534、TIME_WAIT=30s、Dns/Hosts 优先级、Winsock 地址长度、关闭 Nagle 算法、关闭传递优化。',
    steps: [
      {
        label: 'Tcpip / ServiceProvider / Winsock / Nagle / DeliveryOptimization', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters': {
            'DefaultTTL': 'dword:00000040',
            'Tcp1323Opts': 'dword:00000001',
            'TcpMaxDupAcks': 'dword:00000002',
            'SackOpts': 'dword:00000000',
            'MaxUserPort': 'dword:0000fffe',
            'TcpTimedWaitDelay': 'dword:0000001e'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider': {
            'LocalPriority': 'dword:00000004',
            'HostsPriority': 'dword:00000005',
            'DnsPriority': 'dword:00000006',
            'NetbtPriority': 'dword:00000007'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Winsock': {
            'MinSockAddrLength': 'dword:00000010',
            'MaxSockAddrLength': 'dword:00000010'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces': {
            'TcpAckFrequency': 'dword:00000001',
            'TCPNoDelay': 'dword:00000001',
            'TcpDelAckTicks': 'dword:00000000'
          },
          // M1（2026-09-14 重复点审查）：Config\DownloadMode 归「电脑优化中心 - 遥测优化」，
          // 维护侧不再写入。同一注册表键被两个模块写入时，任一方的「还原」都会误删
          // 对方写入的键值，故按 reg-ownership 归属表收归单一写入方。
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config': {
            'DODownloadMode': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Settings': {
            'DownloadMode': 'dword:00000000'
          }
        })
      }
    ]
  },
  {
    id: 'tf_net_lanman', title: 'LanmanServer 会话参数', risk: 'medium',
    desc: 'SMB 服务器参数：空闲不断开(4294967295)、Size=3、关闭 Oplocks、IRPStackSize=20、共享冲突延迟/重试为 0。',
    steps: [
      {
        label: 'LanmanServer Parameters', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters': {
            'autodisconnect': 'dword:ffffffff',
            'Size': 'dword:00000003',
            'EnableOplocks': 'dword:00000000',
            'IRPStackSize': 'dword:00000014',
            'SharingViolationDelay': 'dword:00000000',
            'SharingViolationRetries': 'dword:00000000'
          }
        })
      }
    ]
  },
  {
    id: 'tf_net_nic', title: '网卡高级属性（低延迟）', risk: 'medium',
    desc: '遍历网卡 Class 注册表：关闭全部节能/绿色以太网/WoL/中断调节，关闭校验和与 LSO 卸载，关闭流控，RSS 开启(2队列/Profile3)，收发缓冲 4096/512，JumboPacket=1514。',
    steps: [
      { label: '遍历网卡 Class 写入低延迟 SZ 参数', pwsh: [
        '$root = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"',
        '$sz = @{',
        '  "AutoPowerSaveModeEnabled"="0"; "AutoDisableGigabit"="0"; "AdvancedEEE"="0"; "DisableDelayedPowerUp"="2";',
        '  "*EEE"="0"; "EEE"="0"; "EnablePME"="0"; "EEELinkAdvertisement"="0"; "EnableGreenEthernet"="0";',
        '  "EnableSavePowerNow"="0"; "EnablePowerManagement"="0"; "EnableDynamicPowerGating"="0";',
        '  "EnableConnectedPowerGating"="0"; "EnableWakeOnLan"="0"; "GigaLite"="0"; "NicAutoPowerSaver"="2";',
        '  "PowerDownPll"="0"; "PowerSavingMode"="0"; "ReduceSpeedOnPowerDown"="0"; "SmartPowerDownEnable"="0";',
        '  "S5NicKeepOverrideMacAddrV2"="0"; "S5WakeOnLan"="0"; "ULPMode"="0"; "WakeOnDisconnect"="0";',
        '  "*WakeOnMagicPacket"="0"; "*WakeOnPattern"="0"; "WakeOnLink"="0"; "WolShutdownLinkSpeed"="2";',
        '  "JumboPacket"="1514"; "TransmitBuffers"="4096"; "ReceiveBuffers"="512";',
        '  "IPChecksumOffloadIPv4"="0"; "LsoV1IPv4"="0"; "LsoV2IPv4"="0"; "PMARPOffload"="0";',
        '  "PMNSOffload"="0"; "TCPChecksumOffloadIPv4"="0";',
        '  "UDPChecksumOffloadIPv4"="0";',
        '  "RSS"="1"; "*NumRssQueues"="2"; "RSSProfile"="3"; "*FlowControl"="0"; "FlowControlCap"="0";',
        '  "TxIntDelay"="0"; "TxAbsIntDelay"="0"; "RxIntDelay"="0"; "RxAbsIntDelay"="0";',
        '  "FatChannelIntolerant"="0"; "*InterruptModeration"="0"',
        '}',
        'Get-ChildItem $root -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "^\\d{4}$" } | ForEach-Object {',
        '  $k = $_.PSPath',
        '  foreach ($n in $sz.Keys) { New-ItemProperty -Path $k -Name $n -Value $sz[$n] -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null }',
        '}'
      ].join('\n') }
    ]
  },
  {
    id: 'tf_net_weakhost', title: '启用 WeakHost 收发', risk: 'low',
    desc: '对所有网卡（含隐藏）启用 WeakHostSend / WeakHostReceive，改善多网卡下的路由收发；轻微降低网络隔离安全性。',
    steps: [
      { label: 'WeakHost Send/Receive Enabled', pwsh: 'Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue' }
    ]
  },
  {
    id: 'net_qos_scheduler', title: 'QoS 保留带宽策略排查', risk: 'medium',
    desc: 'NonBestEffortLimit=0，关闭 QoS 默认保留带宽的 PSched 策略；不承诺固定带宽收益，企业、校园、VPN 或域策略可能覆盖。',
    steps: [
      { label: 'NonBestEffortLimit=0', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Psched': {
          'NonBestEffortLimit': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'net_disable_netbios', title: 'NetBIOS 旧式解析排查', risk: 'medium',
    desc: '将所有网卡接口 NetbiosOptions 设为 2（关闭 NetBIOS over TCP/IP）；需确认 LAN 游戏、NAS、家庭路由器、老式共享或企业网络不依赖它。',
    steps: [
      {
        label: '遍历网卡关闭 NetBIOS', pwsh: [
          '$base = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"',
          'if (Test-Path $base) { Get-ChildItem $base | ForEach-Object { New-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -PropertyType DWord -Force | Out-Null } }'
        ].join('\n')
      }
    ]
  },
  {
    id: 'net_disable_lmhosts', title: 'LMHOSTS 旧式解析排查', risk: 'medium',
    desc: 'EnableLMHOSTS=0，关闭 LMHOSTS 文件查找；需确认局域网共享、NAS、VPN、老式名称解析或企业网络不依赖它。',
    steps: [
      { label: 'EnableLMHOSTS=0', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters': {
          'EnableLMHOSTS': 'dword:00000000'
        }
      }) }
    ]
  }
];
NET_MIGRATED.forEach((item) => {
  if (!Array.isArray(item.steps) || !item.steps.length) return;
  TASKS[item.id] = {
    title: item.title,
    desc: item.desc,
    category: '网络连接',
    admin: true,
    ps: () => stepsToPs(item.steps)
  };
});

// 任务清单（供渲染层 IPC 拉取，不含 ps 函数）
function list() {
  return Object.entries(TASKS).map(([id, t]) => ({
    id,
    title: t.title,
    desc: t.desc,
    category: t.category,
    admin: !!t.admin
  }));
}

// 生成某个任务的完整执行脚本（注入诊断 preamble）
function run(taskId) {
  const t = TASKS[taskId];
  if (!t) throw new Error('未知的维护任务: ' + taskId);
  return `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
${DIAG.PS_PREAMBLE}
${t.ps()}
`;
}

module.exports = { list, run, CATEGORY_ORDER };
