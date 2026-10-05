// 优化电脑 选项目录 + 进度型 PowerShell 生成器
// 来源目录：old\zhenghe（已按功能去重整合，剔除二进制 exe）
// Trim.bat (内置性能调优集（2353 行）) 已全量嵌入，按分组分类；
// 脚本中的 wmic 循环改写为 Get-CimInstance / Get-PnpDevice（Win11 27H2 无 wmic），
// 外部工具（nvidiaProfileInspector / OOSU10 / 电源计划 / DevManView）改为下载后静默执行，
// 脚本自身语法 bug（seplatformtick、GpuEnergyDr、Microsoftd、智能引号 MTU、
// DisableWebSearch 反值、HDCP 双反斜杠）在嵌入时已修正。
// 执行模型：每个选项 = steps 数组；runner 生成一个 pwsh 脚本顺序执行，
// 并逐步输出 "@@PROGRESS:n@@" 上报 0-100%；结束时输出 "@@DONE@@"。
// step 支持 4 种动作：
//   reg     -> { label, reg }  .reg 内容，用 reg.exe import 临时文件（保证原样保真）
//   cmd     -> { label, cmd }  交由 cmd.exe /c 执行（ipconfig/netsh/fsutil/reg add）
//   service -> { label, service, disable }  Stop-Service + 可选 Set-Service Disabled
//   pwsh    -> { label, pwsh }  内联 PowerShell 语句（可多行；禁止内含独立成行的 '@）

const DIAG = require('../main/diag');

// PS 单引号字面量（用于把步骤 label 安全嵌入诊断 Detail 表达式）
function psQuoteForScript(s) {
  return "'" + String(s).replace(/'/g, "''") + "'";
}

// 内存 SVCHost 拆分阈值：内存GB -> KB（对齐 zhenghe\内存调整 各档位）
const MEMORY_KB = {
  4: 4194304, 6: 6291456, 8: 8388608, 12: 12582912,
  16: 16777216, 20: 20971520, 24: 25165824, 32: 33554432,
  default: 380000           // 重置为默认值
};

// 生成一段带回车行的干净 .reg 块（统一去掉作者水印/尾注，保证 reg import 可解析）
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

// EDGE 策略单键项生成器（原「EDGE浏览器专优」整合项按功能拆分为独立可勾选/执行/还原项）
const EDGE_POLICY_PATH = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Edge';
function edgePolicyItem(id, title, risk, valueName, regValue, desc) {
  return {
    id, group: '浏览器优化', title, risk, desc,
    steps: [{ label: `Edge 策略 ${valueName}=${regValue}`, reg: regBlock({ [EDGE_POLICY_PATH]: { [valueName]: regValue } }) }],
    restore: [{ label: `还原：删除 ${valueName} 键值（恢复 Edge 默认行为）`, reg: regBlock({ [EDGE_POLICY_PATH]: { [valueName]: '-' } }) }]
  };
}

// 策略型 QoS（DSCP）单进程取值构造器 —— 11 个字段与「按 Application Name 匹配」的组策略
// 形态一致：DSCP 46 = Expedited Forwarding，Throttle Rate -1 = 不限速，其余为通配。
// 进程名清单取自 RAINZ DBUG 3.5.0 的 `网络优化修复/2.QoS调整.bat` 原文（[A] 级：实测其脚本
// 字节），Trim **未在本机复现过其效果**，故该项不登记 EFFECT_MAP（如实回落到「未验证」）。
// 已知边界：LeagueClient.exe 是英雄联盟的客户端/大厅进程，对局进程不是它 —— 本条只覆盖大厅
// 流量；未取得对局进程名的可靠证据前不擅自替换（§9.3 纪律①：不拿推断当实测）。
function qosDscpValues(exe) {
  return {
    'Version': '"1.0"',
    'Application Name': `"${exe}"`,
    'Protocol': '"*"',
    'Local Port': '"*"',
    'Local IP': '"*"',
    'Local IP Prefix Length': '"*"',
    'Remote Port': '"*"',
    'Remote IP': '"*"',
    'Remote IP Prefix Length': '"*"',
    'DSCP Value': '"46"',
    'Throttle Rate': '"-1"'
  };
}
// ==================== 选项目录 ====================
// risk: low / medium / high；title 在卡片上显示；steps 为执行动作；restore 可选（有源还原）

// 审查 B-1（2026-09-14）：O&O ShutUp10++ 1.9.1436 导出的隐私配置模板（base64，原 2382 字节）。
// 来源：Trim 内置（不再从 ancel1x/... raw/main 第三方可变分支拉取）。如需更新配置，
// 在 OOSU10++ 中导出 cfg 后用 node -e "console.log(fs.readFileSync(path).toString('base64'))" 重新生成。
const OOSU_CFG_B64 = 'IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIw0KIyBUaGlzIGZpbGUgd2FzIGNyZWF0ZWQgd2l0aCBPJk8gU2h1dFVwMTArKyBWMS45LjE0MzYNCiMgYW5kIGNhbiBiZSBpbXBvcnRlZCBvbnRvIGFub3RoZXIgY29tcHV0ZXIuIA0KIw0KIyBEb3dubG9hZCB0aGUgYXBwbGljYXRpb24gYXQgaHR0cHM6Ly93d3cub28tc29mdHdhcmUuY29tL3NodXR1cDEwDQojIFlvdSBjYW4gdGhlbiBpbXBvcnQgdGhlIGZpbGUgZnJvbSB3aXRoaW4gdGhlIHByb2dyYW0uIA0KIw0KIyBBbHRlcm5hdGl2ZWx5IHlvdSBjYW4gaW1wb3J0IGl0IGF1dG9tYXRpY2FsbHkgb3ZlciBhIGNvbW1hbmQgbGluZS4NCiMgU2ltcGx5IHVzZSB0aGUgZm9sbG93aW5nIHBhcmFtZXRlcjogDQojIE9PU1UxMC5leGUgPHBhdGggdG8gZmlsZT4NCiMgDQojIFNlbGVjdGluZyB0aGUgT3B0aW9uIC9xdWlldCBlbmRzIHRoZSBhcHAgcmlnaHQgYWZ0ZXIgdGhlIGltcG9ydCBhbmQgdGhlDQojIHVzZXIgZG9lcyBub3QgZ2V0IGFueSBmZWVkYmFjayBhYm91dCB0aGUgaW1wb3J0Lg0KIw0KIyBXZSBhcmUgYWx3YXlzIGhhcHB5IHRvIGFuc3dlciBhbnkgcXVlc3Rpb25zIHlvdSBtYXkgaGF2ZSENCiMgwqkgMjAxNS0yMDIzIE8mTyBTb2Z0d2FyZSBHbWJILCBCZXJsaW4uIEFsbCByaWdodHMgcmVzZXJ2ZWQuDQojIGh0dHBzOi8vd3d3Lm9vLXNvZnR3YXJlLmNvbS8NCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMNCg0KUDAwMQkrDQpQMDAyCSsNClAwMDMJKw0KUDAwNAktDQpQMDA1CSsNClAwMDYJKw0KUDAwOAkrDQpQMDI2CS0NClAwMjcJKw0KUDAyOAktDQpQMDY0CSsNClAwNjUJKw0KUDA2NgkrDQpQMDY3CSsNClAwNzAJKw0KUDA2OQktDQpQMDA5CSsNClAwMTAJKw0KUDAxNQkrDQpQMDY4CSsNClAwMTYJKw0KQTAwMQkrDQpBMDAyCSsNCkEwMDMJKw0KQTAwNAktDQpBMDA2CSsNCkEwMDUJLQ0KUDAwNwktDQpQMDM2CSsNClAwMjUJKw0KUDAzMwktDQpQMDIzCSsNClAwNTYJKw0KUDA1NwkrDQpQMDEyCS0NClAwMzQJLQ0KUDAxMwktDQpQMDM1CS0NClAwNjIJKw0KUDA2MwkrDQpQMDgxCSsNClAwNDcJKw0KUDAxOQkrDQpQMDQ4CS0NClAwNDkJKw0KUDAyMAktDQpQMDM3CSsNClAwMTEJLQ0KUDAzOAkrDQpQMDUwCS0NClAwNTEJKw0KUDAxOAktDQpQMDM5CSsNClAwMjEJLQ0KUDA0MAkrDQpQMDIyCS0NClAwNDEJKw0KUDAxNAktDQpQMDQyCSsNClAwNTIJLQ0KUDA1MwkrDQpQMDU0CS0NClAwNTUJKw0KUDAyOQktDQpQMDQzCSsNClAwMzAJLQ0KUDA0NAkrDQpQMDMxCS0NClAwNDUJKw0KUDAzMgktDQpQMDQ2CSsNClAwNTgJLQ0KUDA1OQkrDQpQMDYwCS0NClAwNjEJKw0KUDAyNAkrDQpTMDAxCS0NClMwMDIJKw0KUzAwMwkrDQpTMDA4CS0NCkUxMDEJKw0KRTIwMQktDQpFMTE1CSsNCkUyMTUJLQ0KRTExOAkrDQpFMjE4CS0NCkUxMDcJKw0KRTIwNwktDQpFMTExCSsNCkUyMTEJLQ0KRTExMgkrDQpFMjEyCS0NCkUxMDkJKw0KRTIwOQktDQpFMTIxCSsNCkUyMjEJLQ0KRTEwMwkrDQpFMjAzCS0NCkUxMjMJKw0KRTIyMwktDQpFMTI0CSsNCkUyMjQJLQ0KRTEyOAkrDQpFMjI4CS0NCkUxMTkJKw0KRTIxOQktDQpFMTIwCSsNCkUyMjAJLQ0KRTEyMgkrDQpFMjIyCS0NCkUxMjUJKw0KRTIyNQktDQpFMTI2CSsNCkUyMjYJLQ0KRTEwNgkrDQpFMjA2CS0NCkUxMjcJKw0KRTIyNwktDQpFMDAxCSsNCkUwMDIJKw0KRTAwMwkrDQpFMDA4CSsNCkUwMDcJLQ0KRTAxMAkrDQpFMDExCS0NCkUwMTIJLQ0KRTAwOQkrDQpFMDA0CSsNCkUwMDUJKw0KRTAxMwkrDQpFMDE0CSsNCkUwMDYJKw0KWTAwMQkrDQpZMDAyCSsNClkwMDMJKw0KWTAwNAkrDQpZMDA1CSsNClkwMDYJKw0KWTAwNwkrDQpDMDEyCSsNCkMwMDIJKw0KQzAxMwktDQpDMDA3CSsNCkMwMDgJLQ0KQzAwOQkrDQpDMDEwCS0NCkMwMTEJKw0KQzAxNAkrDQpDMDE1CS0NCkwwMDEJKw0KTDAwMwkrDQpMMDA0CSsNCkwwMDUJKw0KVTAwMQkrDQpVMDA0CSsNClUwMDUJKw0KVTAwNgktDQpVMDA3CS0NClcwMDEJLQ0KVzAxMQktDQpXMDA0CS0NClcwMDUJKw0KVzAxMAkrDQpXMDA5CS0NClAwMTcJKw0KVzAwNgktDQpXMDA4CS0NCk0wMDYJKw0KTTAxMQkrDQpNMDEwCSsNCk8wMDMJLQ0KTzAwMQkrDQpTMDEyCSsNClMwMTMJKw0KUzAxNAkrDQpLMDAxCSsNCkswMDIJKw0KSzAwNQkrDQpNMDAzCSsNCk0wMTUJKw0KTTAxNgkrDQpNMDE3CS0NCk0wMTgJKw0KTTAxOQktDQpNMDIwCSsNCk0wMjIJKw0KTTAwMQkrDQpNMDA0CSsNCk0wMDUJKw0KTTAyNAkrDQpNMDEyCS0NCk0wMTMJLQ0KTTAxNAktDQpNMDIzCS0NCk4wMDEJLQ0K';

const OPTIONS = [
  // ---------- 启动与响应 ----------
  // 第六大点-A/B（2026-09-14 重复点审查）：原「SSD 固态硬盘优化」(ssd_opt) 已下线。
  // 它的两步都被别处覆盖，且其中一步与 tf_ntfs 取值相反：
  //   · fsutil disableLastAccess 0（原描述"启用最后访问时间戳"）与 tf_ntfs 的 disablelastaccess=1
  //     冲突；且在 SSD 上启用最后访问只会增加元数据写入，与"SSD 优化"目标相反 → 以 tf_ntfs 为准。
  //   · fsutil disable8dot3 1 与 storage_8dot3_off 完全同值同动作。
  // 退役登记见 data/retired-optimizations.json。
  {
    id: 'tf_ntfs', group: '启动与响应', title: 'NTFS 文件系统调优', risk: 'medium',
    desc: 'Trim fsutil 五项：memoryusage=2、mftzone=4、disablelastaccess=1、disabledeletenotify=0（开启删除通知/TRIM）、encryptpagingfile=0。',
    steps: [
      { label: 'NTFS 内存占用 2', cmd: 'fsutil behavior set memoryusage 2' },
      { label: 'MFT 区域 4', cmd: 'fsutil behavior set mftzone 4' },
      { label: '禁用最后访问时间', cmd: 'fsutil behavior set disablelastaccess 1' },
      { label: '开启删除通知(TRIM)', cmd: 'fsutil behavior set disabledeletenotify 0' },
      { label: '页面文件不加密', cmd: 'fsutil behavior set encryptpagingfile 0' }
    ]
  },
  {
    id: 'tf_hibern_off', group: '启动与响应', title: '关闭休眠与快速启动', risk: 'medium',
    desc: 'Trim：powercfg /h off、HiberbootEnabled=0、HibernateEnabled=0、关闭睡眠可靠性诊断与 SleepStudy，彻底关闭休眠文件与快速启动。',
    steps: [
      { label: '关闭休眠', cmd: 'powercfg /h off' },
      {
        label: '快速启动 / 休眠 / 睡眠诊断注册表', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power': {
            'HiberbootEnabled': 'dword:00000000',
            'HibernateEnabled': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SleepReliability': {
            'SleepReliabilityDetailedDiagnostics': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SleepStudy': {
            'SleepStudyDisabled': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'tf_core_misc', group: '启动与响应', title: '核心响应性杂项', risk: 'medium',
    desc: 'Trim 核心键集合：Win32PrioritySeparation=38、LargeSystemCache=1、菜单延迟 0、HwSchMode=2（硬件调度）、DistributeTimers=1、禁用 FTH、MoveImages=0、DisablePagingExecutive=1、DpiMapIommuContiguous=1、关闭自动维护、IE DEP 关闭。',
    steps: [
      {
        label: '核心响应性注册表', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl': {
            'Win32PrioritySeparation': 'dword:00000026'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management': {
            'LargeSystemCache': 'dword:00000001',
            'DisablePagingExecutive': 'dword:00000001',
            'MoveImages': 'dword:00000000',
            'DpiMapIommuContiguous': 'dword:00000001'
          },
          'HKEY_CURRENT_USER\\Control Panel\\Desktop': {
            'MenuShowDelay': '"0"'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers': {
            'HwSchMode': 'dword:00000002'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel': {
            'DistributeTimers': 'dword:00000001'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\FTH': {
            'Enabled': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Maintenance': {
            'MaintenanceDisabled': 'dword:00000001'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Internet Explorer\\Main': {
            'DEPOff': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'tf_timer_coal', group: '启动与响应', title: '合并计时器与现代待机', risk: 'medium',
    desc: 'Trim：7 条路径 CoalescingTimerInterval=0，关闭 PlatformAoAc/ModernSleep/CsEnabled，EnergyEstimation/EventProcessor 关闭，PowerThrottlingOff=1，降低定时器合并带来的延迟。',
    steps: [
      {
        label: 'CoalescingTimerInterval / ModernSleep / PowerThrottling', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel': {
            'CoalescingTimerInterval': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power': {
            'CoalescingTimerInterval': 'dword:00000000',
            'PlatformAoAcOverride': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management': {
            'CoalescingTimerInterval': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Executive': {
            'CoalescingTimerInterval': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power': {
            'CoalescingTimerInterval': 'dword:00000000',
            'EnergyEstimationEnabled': 'dword:00000000',
            'EventProcessorEnabled': 'dword:00000000',
            'CsEnabled': 'dword:00000000',
            'PowerThrottlingOff': 'dword:00000001'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\ModernSleep': {
            'CoalescingTimerInterval': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile': {
            'CoalescingTimerInterval': 'dword:00000000'
          }
        })
      }
    ]
  },
  // ---------- 游戏与多媒体 ----------
  {
    id: 'game_dvr', group: '游戏与多媒体', title: '关闭游戏 DVR 录制', risk: 'low',
    desc: '关闭 GameDVR / 游戏栏后台录制（GameDVR_Enabled / AllowGameDVR / AppCaptureEnabled），减少后台录制带来的性能占用。全屏优化(FSO)相关键已统一由「全屏优化(FSO)行为」负责——本项原先也写 GameDVR_FSEBehaviorMode 等 4 个同域键，与 tf_fso 取值相反（2/0 vs 0/1），执行顺序决定结果，第六大点-A（2026-09-14）已移交。',
    steps: [
      {
        label: 'GameDVR 录制开关', reg: regBlock({
          'HKEY_CURRENT_USER\\System\\GameConfigStore': {
            'GameDVR_Enabled': 'dword:00000000',
            'GameDVR_FSEBehavior': 'dword:00000002'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR': {
            'AllowGameDVR': 'dword:0'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\default\\ApplicationManagement\\AllowGameDVR': {
            'value': 'dword:0'
          },
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR': {
            'AppCaptureEnabled': 'dword:00000000'
          }
        })
      }
    ]
  },
  {
    id: 'nara_prio', group: '游戏与多媒体', title: '永劫无间 CPU 高优先级', risk: 'low',
    desc: '为「永劫无间」(NarakaBladepoint.exe) 进程设置高 CPU 优先级类。',
    steps: [
      {
        label: 'Naraka CpuPriorityClass=3', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\NarakaBladepoint.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000003'
          }
        })
      }
    ]
  },
  {
    id: 'net_qos_dscp', group: '游戏与多媒体', title: '游戏 QoS 优先（DSCP 46）', risk: 'medium',
    desc: '为 8 款竞技游戏的进程写入策略型 QoS（DSCP 46 / Expedited Forwarding），给这些进程的本机出向流量打上高优先标记。只改写标记、不改变本机带宽分配与上行上限；是否真被提速取决于沿途路由器与运营商是否尊重 DSCP（多数家庭网络不做区分）。',
    steps: [
      {
        label: 'QoS 策略 DSCP=46（8 个游戏进程）', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\VALORANT-Win64-Shipping.exe': qosDscpValues('VALORANT-Win64-Shipping.exe'),
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\FortniteClient-Win64-Shipping.exe': qosDscpValues('FortniteClient-Win64-Shipping.exe'),
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\DeltaForceClient-Win64-Shipping.exe': qosDscpValues('DeltaForceClient-Win64-Shipping.exe'),
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\NarakaBladepoint.exe': qosDscpValues('NarakaBladepoint.exe'),
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\LeagueClient.exe': qosDscpValues('LeagueClient.exe'),
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\TslGame.exe': qosDscpValues('TslGame.exe'),
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\cs2.exe': qosDscpValues('cs2.exe'),
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\r5apex.exe': qosDscpValues('r5apex.exe')
        })
      }
    ]
  },
  {
    id: 'disable_uac', group: '游戏与多媒体', title: '禁用 UAC（用户账户控制）', risk: 'high',
    desc: '关闭 UAC 提升提示。会降低系统安全性，请谨慎使用。',
    steps: [
      { label: 'EnableLUA=0', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System': { 'EnableLUA': 'dword:00000000' }
      }) }
    ]
  },
  {
    id: 'tf_gamemode', group: '游戏与多媒体', title: '开启游戏模式', risk: 'low',
    desc: 'Trim：AllowAutoGameMode=1、AutoGameModeEnabled=1，让 Windows 游戏模式自动提升游戏进程优先级。',
    steps: [
      {
        label: 'Game Mode 开启', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\GameBar': {
            'AllowAutoGameMode': 'dword:00000001',
            'AutoGameModeEnabled': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'tf_gamebar', group: '游戏与多媒体', title: '关闭游戏栏后台捕获', risk: 'low',
    desc: 'Trim：PresenceWriter ActivationType=0 并停止 PresenceWriter 服务，关闭游戏栏后台捕获与游戏状态写入器；AppCaptureEnabled 由「关闭游戏 DVR 录制」负责，本项不再重复写入。',
    steps: [
      {
        label: 'PresenceWriter 捕获写入器', reg: regBlock({
          // 第六大点-B（2026-09-14）：AppCaptureEnabled 归「关闭游戏 DVR 录制」(game_dvr)，
          // 本项不再重复写入该键。
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsRuntime\\ActivatableClassId\\Windows.Media.Capture.AppCaptureBroadcastContract\\PresenceWriter': {
            'ActivationType': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\PresenceWriter': {
            'Start': 'dword:00000004'
          }
        })
      }
    ]
  },
  
  {
    id: 'tf_gpu_latency', group: '游戏与多媒体', title: 'GPU 延迟容忍度调优', risk: 'medium',
    desc: 'Trim Latency Tolerance：DXGKrnl MonitorLatencyTolerance/MonitorRefreshLatencyTolerance=1，Control\\Power 9 键=1，GraphicsDrivers\\Power 24 键=1（含 DefaultD3TransitionLatency*、DefaultLatencyTolerance*、Miracast 等）。',
    steps: [
      {
        label: 'DXGKrnl / Control Power 延迟键', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DXGKrnl': {
            'MonitorLatencyTolerance': 'dword:00000001',
            'MonitorRefreshLatencyTolerance': 'dword:00000001'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power': {
            'ExitLatency': 'dword:00000001',
            'ExitLatencyCheckEnabled': 'dword:00000001',
            'Latency': 'dword:00000001',
            'LatencyToleranceDefault': 'dword:00000001',
            'LatencyToleranceFSVP': 'dword:00000001',
            'LatencyTolerancePerfOverride': 'dword:00000001',
            'LatencyToleranceScreenOffIR': 'dword:00000001',
            'LatencyToleranceVSyncEnabled': 'dword:00000001',
            'RtlCapabilityCheckLatency': 'dword:00000001'
          }
        })
      },
      { label: 'GraphicsDrivers\\Power 24 键', pwsh: [
        '$p = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Power"',
        'New-Item -Path $p -Force | Out-Null',
        '$names = @("ExitLatency","ExitLatencyCheckEnabled","Latency","LatencyToleranceDefault","LatencyToleranceFSVP","LatencyTolerancePerfOverride","LatencyToleranceScreenOffIR","LatencyToleranceVSyncEnabled","RtlCapabilityCheckLatency","DefaultD3TransitionLatency","DefaultD3TransitionLatencyEnabled","DefaultD3TransitionLatencyHMD","DefaultD3TransitionLatencyHMDEnabled","DefaultD3TransitionLatencyMedia","DefaultD3TransitionLatencyMediaEnabled","DefaultLatencyTolerance","DefaultLatencyToleranceEnabled","DefaultLatencyToleranceHMD","DefaultLatencyToleranceHMDEndabled","DefaultMemoryRefreshLatency","DefaultMemoryRefreshLatencyEnabled","MaxIAverageGraphicsLatencyInOneBucket","MiracastPerfTrackGraphicsLatency","MonitorLatencyTolerance","MonitorRefreshLatencyTolerance","TransitionLatency")',
        'foreach ($n in $names) { New-ItemProperty -Path $p -Name $n -Value 1 -PropertyType DWord -Force | Out-Null }'
      ].join('\n') }
    ]
  },
  {
    id: 'tf_ifeo_perf', group: '游戏与多媒体', title: '进程 CPU/IO 优先级（IFEO PerfOptions）', risk: 'high',
    desc: 'Trim：dwm/ntoskrnl/csrss Cpu=4/Io=3，lsass Cpu=1/Io=0/PagePriority=0，SearchIndexer/svchost/TrustedInstaller/wuauclt/audiodg Cpu=1/2，在 SOFTWARE 与 WOW6432Node 两个蜂巢写入 PerfOptions。',
    steps: [
      {
        label: 'IFEO PerfOptions（双蜂巢）', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\dwm.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000004', 'IoPriority': 'dword:00000003'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ntoskrnl.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000004', 'IoPriority': 'dword:00000003'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\csrss.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000004', 'IoPriority': 'dword:00000003'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001', 'IoPriority': 'dword:00000000', 'PagePriority': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SearchIndexer.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001', 'IoPriority': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\TrustedInstaller.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001', 'IoPriority': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wuauclt.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001', 'IoPriority': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MsMpEng.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MsMpEngCP.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001'
          },
          'HKEY_LOCAL_MACHINE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\dwm.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000004', 'IoPriority': 'dword:00000003'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ntoskrnl.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000004', 'IoPriority': 'dword:00000003'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\csrss.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000004', 'IoPriority': 'dword:00000003'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001', 'IoPriority': 'dword:00000000', 'PagePriority': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SearchIndexer.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001', 'IoPriority': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\TrustedInstaller.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001', 'IoPriority': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wuauclt.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000001', 'IoPriority': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\audiodg.exe\\PerfOptions': {
            'CpuPriorityClass': 'dword:00000002'
          }
        })
      }
    ]
  },
  {
    id: 'tf_ifeo_wipe', group: '游戏与多媒体', title: '清空 IFEO 调试项', risk: 'high',
    desc: '清除 Image File Execution Options 下的调试劫持值（Debugger/GlobalFlag/UseFilter 等）。已与「进程 CPU/IO 优先级」兼容：保留各程序的 PerfOptions 子项（IFEO 优先级设置）不被误删，仅清除杀软/病毒常用的 Debugger 劫持入口。',
    steps: [
      {
        label: '清除 Debugger 劫持值（保留 PerfOptions）', pwsh: [
          "$root = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'",
          "Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {",
          "  $sub = $_",
          "  foreach ($v in @('Debugger','GlobalFlag','UseFilter','ModifiedImagePath')) {",
          "    if ($null -ne (Get-ItemProperty -LiteralPath $sub.PSPath -Name $v -ErrorAction SilentlyContinue)) { Remove-ItemProperty -LiteralPath $sub.PSPath -Name $v -ErrorAction SilentlyContinue }",
          "  }",
          "  $hasPerf = Test-Path -LiteralPath (Join-Path $sub.PSPath 'PerfOptions')",
          "  if (-not $hasPerf) {",
          "    $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue",
          "    $vals = @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }).Count",
          "    $childCount = @(Get-ChildItem -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue).Count",
          "    if ($vals -eq 0 -and $childCount -eq 0) { Remove-Item -LiteralPath $sub.PSPath -Force -ErrorAction SilentlyContinue }",
          "  }",
          "}"
        ].join('\n')
      }
    ]
  },

  // ---------- 系统服务与内存 ----------
  // 第六大点-B（2026-09-14 重复点审查）：原「禁用下载地图管理器」(maps_off) 与
  // 「禁用冗余后台服务」(services_off) 已下线，合并进「禁用 70+ 非必要服务」(tf_svc_bulk)：
  //   · MapsBroker 本就在 tf_svc_bulk 清单内；
  //   · services_off 的 5 个独有服务（XblAuthManager / XblGameSave / XboxNetApiSvc /
  //     WpnService / lfsvc）已并入 tf_svc_bulk 清单，其余 4 个（SysMain / DiagTrack /
  //     BcastDVRUserService / dmwappushservice）本就重复。
  // 注意机制差异：services_off 用 Stop-Service + Set-Service Disabled，不改变下次开机的
  // 启动类型；tf_svc_bulk 用注册表 Start=4，两者不等价 —— 合并后统一为 Start=4。
  {
    id: 'svc_mem_gb', group: '系统服务与内存', title: 'SVCHost 内存拆分阈值', risk: 'medium',
    desc: '调整服务宿主进程拆分阈值，减少服务内存碎片（下拉选择内存大小，可重置）。',
    dynamic: true   // 由渲染层传入 gb 参数
  },
  // 第六大点-B（2026-09-14 重复点审查）：原「禁用内存压缩」(mem_compress) 已下线 ——
  // 它是「关闭内存压缩与内存页合并」(tf_mmagent) 的子集（后者 = 本项 + PageCombining），
  // 合并后只保留超集项，避免同一项 Disable-MMAgent 被两个入口各执行一次。
  {
    id: 'tf_mmagent', group: '系统服务与内存', title: '关闭内存压缩与内存页合并', risk: 'medium',
    desc: '关闭 Windows 内存页合并（PageCombining）与内存压缩：Disable-MMAgent -MemoryCompression -PageCombining（比内置「禁用内存压缩」多 PageCombining）。PageCombining 是 Windows 的持续内存去重机制；「内存清理 - 即时合并物理内存页」是此刻调用 NtSetSystemInformation 整理一次，两者不是同一功能，互不影响。',
    steps: [
      { label: '关闭内存压缩', pwsh: 'Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue' },
      { label: '关闭页面合并', pwsh: 'Disable-MMAgent -PageCombining -ErrorAction SilentlyContinue' }
    ]
  },
  {
    id: 'tf_svc_bulk', group: '系统服务与内存', title: '禁用 70+ 非必要服务', risk: 'high',
    desc: '批量调整服务启动类型：Windows 应用商店与同步相关服务保持系统默认（不再修改），其余非必要服务全部禁用(Start=4)，并关闭 Edge 预启动/预加载。\n\n执行时会单独弹窗询问是否连商店相关服务一并禁用——含 ClipSVC（许可）、InstallService（安装）、PushToInstall（远程安装）、wuauserv（Windows 更新）、DoSvc（传递优化下载），选择禁用会影响 Windows 应用商店的使用、更新与下载以及系统更新。\n\n禁用(Start=4)服务清单：TapiSrv、FontCache3.0.0.0、WpcMonSvc、SEMgrSvc、PNRPsvc、LanmanWorkstation、WEPHOSTSVC、p2psvc、p2pimsvc、PhoneSvc、Wecsvc、perceptionsimulation、StiSvc、WMPNetworkSvc、autotimesvc、edgeupdatem、MicrosoftEdgeElevationService、ALG、QWAVE、IpxlatCfgSvc、icssvc、DusmSvc、MapsBroker、edgeupdate、SensorService、shpamsvc、svsvc、SysMain、MSiSCSI、Netlogon、CscService、ssh-agent、AppReadiness、tzautoupdate、NfsClnt、wisvc、defragsvc、SharedRealitySvc、RetailDemo、lltdsvc、TrkWks、CryptSvc、DiagTrack、diagsvc、DPS、WdiServiceHost、WdiSystemHost、dmwappushsvc、TroubleshootingSvc、DsSvc、FrameServer、FontCache、OSRSS、sedsvc、SENS、TabletInputService、Themes、BcastDVRUserService、CaptureService、diagnosticshub.standardcollector.service、XblAuthManager、XblGameSave、XboxNetApiSvc、WpnService、lfsvc。',
    steps: [
      { label: '批量禁用非必要服务（商店/同步保持默认）', pwsh: [
        '$disabled = @("TapiSrv","FontCache3.0.0.0","WpcMonSvc","SEMgrSvc","PNRPsvc","LanmanWorkstation","WEPHOSTSVC","p2psvc","p2pimsvc","PhoneSvc","Wecsvc","perceptionsimulation","StiSvc","WMPNetworkSvc","autotimesvc","edgeupdatem","MicrosoftEdgeElevationService","ALG","QWAVE","IpxlatCfgSvc","icssvc","DusmSvc","MapsBroker","edgeupdate","SensorService","shpamsvc","svsvc","SysMain","MSiSCSI","Netlogon","CscService","ssh-agent","AppReadiness","tzautoupdate","NfsClnt","wisvc","defragsvc","SharedRealitySvc","RetailDemo","lltdsvc","TrkWks","CryptSvc","DiagTrack","diagsvc","DPS","WdiServiceHost","WdiSystemHost","dmwappushsvc","TroubleshootingSvc","DsSvc","FrameServer","FontCache","OSRSS","sedsvc","SENS","TabletInputService","Themes","BcastDVRUserService","CaptureService","diagnosticshub.standardcollector.service","XblAuthManager","XblGameSave","XboxNetApiSvc","WpnService","lfsvc")',
        'foreach ($n in $disabled) { $p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 4 -PropertyType DWord -Force | Out-Null; Stop-Service -Name $n -Force -ErrorAction SilentlyContinue } }',
        '$p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\wuauserv"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 3 -PropertyType DWord -Force | Out-Null }',
        '$p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration"; New-Item -Path $p -Force | Out-Null; New-ItemProperty -Path $p -Name Status -Value 0 -PropertyType DWord -Force | Out-Null',
        'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main" -Force | Out-Null; New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main" -Name AllowPrelaunch -Value 0 -PropertyType DWord -Force | Out-Null',
        'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\TabPreloader" -Force | Out-Null; New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\TabPreloader" -Name AllowTabPreloading -Value 0 -PropertyType DWord -Force | Out-Null'
      ].join('\n') }
    ]
  },
  {
    id: 'tf_drv_disable', group: '系统服务与内存', title: '禁用高风险驱动服务', risk: 'high',
    desc: 'Trim DisableDrivers（21 项 Start=4）：acpipagr、AcpiPmi、Beep、CAD、GpuEnergyDrv、CLFS、CSC、luafv、RasAcd/Rasl2tp/RasPppoe/RasSstp、tcpipreg、dam、PEAUTH、QWAVEdrv、cdrom、fileinfo、FileCrypt。可能影响光驱/VPN，高风险（已剔除 IPv6 相关驱动 Tcpip6/wanarpv6，遵守项目硬约束）。',
    steps: [
      { label: '驱动服务 Start=4', pwsh: [
        '$drv = @("acpipagr","AcpiPmi","Beep","CAD","GpuEnergyDrv","CLFS","CSC","luafv","RasAcd","Rasl2tp","RasPppoe","RasSstp","tcpipreg","dam","PEAUTH","QWAVEdrv","cdrom","fileinfo","FileCrypt")',
        'foreach ($n in $drv) { $p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 4 -PropertyType DWord -Force | Out-Null } }'
      ].join('\n') }
    ]
  },

  // ---------- 安全与隐私 ----------
  {
    id: 'share_off', group: '安全与隐私', title: '关闭默认共享', risk: 'medium',
    desc: '关闭 LanmanServer 的默认管理共享（C$/ADMIN$）与空会话管道。',
    steps: [
      { label: 'LanmanServer 共享参数', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters': {
          'AutoShareWks': 'dword:00000000',
          'AutoShareServer': 'dword:00000000',
          'EnableAuthenticateUserSharing': 'dword:00000000',
          'restrictnullsessaccess': 'dword:00000001',
          'enablesecuritysignature': 'dword:00000000',
          'requiresecuritysignature': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'telemetry_optimize', group: '安全与隐私', title: '遥测优化', risk: 'medium',
    desc: '合并原「关闭系统遥测」与「停用遥测计划任务/日志」：策略层关闭 AllowTelemetry、广告 ID、传递优化上传与网页内容评估；任务层禁用 30+ 个遥测/兼容性/客户体验计划任务（含 Office、Application Experience、Media Center 等）并将 35 个 AutoLogger 会话 Start=0；服务层停止并禁用 DiagTrack/dmwappushservice/diagnosticshub。策略+任务+日志+服务四层一体掐断遥测采集与上传。',
    steps: [
      { label: '遥测与广告策略', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection': { 'AllowTelemetry': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection': { 'AllowTelemetry': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection': { 'AllowTelemetry': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo': { 'DisabledByGroupPolicy': 'dword:00000001' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config': { 'DownloadMode': 'dword:00000000' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo': { 'Enabled': 'dword:00000000' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\AppHost': { 'EnableWebContentEvaluation': 'dword:00000000' },
        'HKEY_CURRENT_USER\\Control Panel\\International\\User Profile': { 'HttpAcceptLanguageOptOut': 'dword:00000001' }
      }) },
      { label: '禁用遥测计划任务', pwsh: [
        '$tasks = @(',
        '"\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",',
        '"\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",',
        '"\\Microsoft\\Windows\\Application Experience\\StartupAppTask",',
        '"\\Microsoft\\Windows\\Autochk\\Proxy",',
        '"\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",',
        '"\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",',
        '"\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",',
        '"\\Microsoft\\Windows\\Customer Experience Improvement Program\\HypervisorFlightingTask",',
        '"\\Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",',
        '"\\Microsoft\\Windows\\Feedback\\Siuf\\DmClient",',
        '"\\Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",',
        '"\\Microsoft\\Windows\\Maps\\MapsToastTask",',
        '"\\Microsoft\\Windows\\Maps\\MapsUpdateTask",',
        '"\\Microsoft\\Windows\\PI\\Sqm-Tasks",',
        '"\\Microsoft\\Windows\\Power Efficiency Diagnostics\\AnalyzeSystem",',
        '"\\Microsoft\\Windows\\Windows Error Reporting\\QueueReporting",',
        '"\\Microsoft\\Windows\\Media Center\\ActivateWindowsSearch",',
        '"\\Microsoft\\Windows\\Media Center\\ConfigureInternetTimeService",',
        '"\\Microsoft\\Windows\\Media Center\\DispatchRecoveryTasks",',
        '"\\Microsoft\\Windows\\Media Center\\ehDRMInit",',
        '"\\Microsoft\\Windows\\Media Center\\InstallPlayReady",',
        '"\\Microsoft\\Windows\\Media Center\\mcupdate",',
        '"\\Microsoft\\Windows\\Media Center\\MediaCenterRecoveryTask",',
        '"\\Microsoft\\Windows\\Media Center\\ObjectStoreRecoveryTask",',
        '"\\Microsoft\\Windows\\Media Center\\PvrScheduleTask",',
        '"\\Microsoft\\Windows\\Media Center\\RegisterSearch",',
        '"\\Microsoft\\Windows\\Media Center\\ReindexSearchRoot",',
        '"\\Microsoft\\Office\\OfficeTelemetryAgentFallBack",',
        '"\\Microsoft\\Office\\OfficeTelemetryAgentLogOn",',
        '"\\Microsoft\\Office\\OfficeTelemetryAgentFallBack2016",',
        '"\\Microsoft\\Office\\OfficeTelemetryAgentLogOn2016",',
        '"\\Microsoft\\Windows\\CloudExperienceHost\\CreateObjectTask",',
        '"\\Microsoft\\Windows\\AppxDeploymentClient\\Pre-staged app cleanup",',
        '"\\Microsoft\\Windows\\ApplicationData\\DsSvcCleanup"',
        ')',
        'foreach ($t in $tasks) { schtasks /change /tn $t /disable 2>$null | Out-Null }'
      ].join('\n') },
      { label: 'AutoLogger Start=0', pwsh: [
        '$root = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger"',
        'if (Test-Path $root) { Get-ChildItem $root | ForEach-Object { New-ItemProperty -Path $_.PSPath -Name Start -Value 0 -PropertyType DWord -Force | Out-Null } }'
      ].join('\n') },
      { label: '停止遥测服务', pwsh: [
        'foreach ($s in @("DiagTrack","dmwappushservice","diagnosticshub.standardcollector.service")) { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue; sc.exe config $s start= disabled 2>$null | Out-Null }'
      ].join('\n') }
    ]
  },
  {
    id: 'power_off', group: '安全与隐私', title: '禁用电源节能', risk: 'medium',
    desc: '关闭 USB/PCIe 省电、核心停放与节流、电源节流与驱动搜索（台式机推荐，笔记本会增加耗电）。快速启动（HiberbootEnabled）由「关闭休眠与快速启动」负责，本项不再重复写入。',
    steps: [
      { label: '关闭节能与休眠默认值', reg: regBlock({
        // 第六大点-B（2026-09-14）：HiberbootEnabled（快速启动）归「关闭休眠与快速启动」(tf_hibern_off)，
        // 本项不再重复写入同一键。
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power': { 'HibernateEnabledDefault': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling': { 'PowerThrottlingOff': 'dword:00000001' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching': { 'SearchOrderConfig': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\943c8cb6-6f93-4227-ad87-e9a3feec08d1': { 'Attributes': 'dword:00000002' }
      }) }
    ]
  },
  {
    id: 'tf_defender', group: '安全与隐私', title: '关闭 Defender 与 SmartScreen', risk: 'high',
    desc: 'Trim：禁用 Microsoft Defender 反间谍/实时保护/云上报/SmartScreen/Edge 钓鱼过滤，并停用 Sense、WinDefend、WdNisSvc、SecurityHealthService、wscsvc（高风险，系统将无杀毒防护）。',
    steps: [
      { label: 'Defender 策略与服务', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting': { 'DisableGenericRePorts': 'dword:00000001', 'DisableEnhancedNotifications': 'dword:00000001' },
        // v3.7.0 议题六 P1：SubmitSamplesConsent 已从此项移出，归新的低风险项
        // privacy_defender_sample（同一键被两个普通优化项写会互相覆盖，必须先拆键再开放 UI）。
        // 本高危总项继续独占实时保护 / 行为监控 / SmartScreen / 服务停用。
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet': { 'DisableBlockAtFirstSeen': 'dword:00000001', 'LocalSettingOverrideSpynetReporting': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SmartScreen': { 'ConfigureAppInstallControlEnabled': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Threats': { 'Threats_ThreatSeverityDefaultAction': 'dword:00000001' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\UX Configuration': { 'Notification_Suppress': 'dword:00000001' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender': { 'DisableAntiSpyware': 'dword:00000001', 'DisableRoutinelyTakingAction': 'dword:00000001', 'ServiceKeepAlive': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection': { 'DisableRealtimeMonitoring': 'dword:00000001', 'DisableBehaviorMonitoring': 'dword:00000001', 'DisableOnAccessProtection': 'dword:00000001', 'DisableScanOnRealtimeEnable': 'dword:00000001' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System': { 'EnableSmartScreen': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter': { 'EnabledV9': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MRT': { 'DontReportInfectionInformation': 'dword:00000001' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsErrorReporting\\SecurityCenter': { 'DisableSecurityCenter': 'dword:00000001' },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Sense': { 'Start': 'dword:00000004' },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc': { 'Start': 'dword:00000004' },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend': { 'Start': 'dword:00000004' },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService': { 'Start': 'dword:00000004' },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wscsvc': { 'Start': 'dword:00000004' }
      }) },
      { label: 'Defender 威胁默认动作(字符串6)', pwsh: [
        '$base = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction"',
        'New-Item -Path $base -Force | Out-Null',
        'foreach ($k in @("1","2","4","5")) { New-ItemProperty -Path $base -Name $k -Value "6" -PropertyType String -Force | Out-Null }'
      ].join('\n') }
    ]
  },
  // ==================== v3.7.0 议题六 P1：Defender 低风险分项 ====================
  // 只拆两类隐私向、可逆、不影响防护能力的开关：云保护(MAPS) 与 样本自动提交。
  // 实时保护 / 行为监控 / SmartScreen / 篡改保护继续留在 tf_defender 高危总项，
  // 不新增普通开关——把它们做成"顺手一点"的选项是危险的。
  // 篡改保护只做只读状态与指引，Trim 不提供脚本关闭，也不做降级写入链。
  {
    id: 'privacy_defender_cloud', group: '安全与隐私', title: '关闭 Defender 云保护（MAPS）', risk: 'low',
    desc: '把 MAPS 云保护报告级别设为 0（不参与云端信誉查询）。只影响「可疑文件是否送微软云端比对」这一条参与度，实时扫描与本地特征库仍然工作；代价是新威胁的云端判定速度会下降。与「关闭 Defender 与 SmartScreen」不共用任何注册表键，可独立开关。',
    steps: [
      { label: 'MAPS 云保护报告级别 = 0', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet': {
          'SpynetReporting': 'dword:00000000'
        }
      }) }
    ],
    restore: [
      { label: '还原：移除 MAPS 报告级别策略（回到系统默认）', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet': {
          'SpynetReporting': '-'
        }
      }) }
    ]
  },
  {
    id: 'privacy_defender_sample', group: '安全与隐私', title: '关闭可疑样本自动提交', risk: 'low',
    desc: '把自动样本提交设为「永不发送」。只影响可疑文件是否自动上传微软分析，不影响本地查杀能力；代价是微软对新样本的响应速度会变慢。',
    steps: [
      // 映射说明：策略 SubmitSamplesConsent 的取值 0=每次询问 / 1=自动发送安全样本 /
      // 2=永不发送 / 3=自动发送全部样本。此处取 2（永不发送）。
      // 待受控验证：本机 Defender 策略区为空且 Get-MpPreference 相关字段返回空值，
      // 无法在本机做写入回读比对，故按微软文档映射落地，后续需在 Defender 正常启用的机器上复核。
      { label: '样本自动提交 = 永不发送', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet': {
          'SubmitSamplesConsent': 'dword:00000002'
        }
      }) }
    ],
    restore: [
      { label: '还原：移除样本提交策略（回到系统默认）', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet': {
          'SubmitSamplesConsent': '-'
        }
      }) }
    ]
  },
  {
    id: 'tf_privacy', group: '安全与隐私', title: '系统隐私设置', risk: 'medium',
    desc: 'Trim 隐私大项：关闭开始菜单建议、操作中心通知、跨设备同步(CDP)、搜索建议与 Cortana 同意项、实验性体验、TaggedEnergy，并停用 GpuEnergyDrv（麦克风/摄像头权限保留允许）。\n\n归属划分（第六大点-B，2026-09-14）：内容推荐/商店推广类键归「禁用商店自动更新与推广内容」，云推荐与锁屏聚焦类键归「云推荐内容排查」，广告 ID 归「广告 ID 个性化排查」，遥测策略归「遥测优化」，错误报告归「Windows Error Reporting 策略排查」。本项不再重复写入上述键，只想单项处理时请用对应专项项。',
    steps: [
      { label: '隐私注册表键', reg: regBlock({
        // 第六大点-B（2026-09-14 重复点审查）：ContentDeliveryManager 的全部键已移出本项，
        // 按用途分别归「禁用商店自动更新与推广内容」(tf_store_autoupdate) 与
        // 「云推荐内容排查」(privacy_cloud_content)，避免同一键被三处重复写入。
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent': {
          'DisableSoftLanding': 'dword:00000001',
          'DisableWindowsSpotlightFeatures': 'dword:00000001', 'DisableTailoredExperiencesWithDiagnosticData': 'dword:00000001'
        },
        'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
          'Start_TrackProgs': 'dword:00000000'
        },
        'HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer': {
          'ShowOrHideMostUsedApps': 'dword:00000000'
        },
        'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer': {
          'NoInstrumentation': 'dword:00000001'
        },
        // 第六大点-B：AdvertisingInfo 两键（DisabledByGroupPolicy / Enabled）已归
        // 「广告 ID 个性化排查」(privacy_advertising_id)。
        'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search': {
          'CortanaConsent': 'dword:00000000', 'BingSearchEnabled': 'dword:00000000',
          'DeviceHistoryEnabled': 'dword:00000000', 'HistoryViewEnabled': 'dword:00000000'
        },
        'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications': {
          'ToastEnabled': 'dword:00000000'
        },
        'HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer': {
          'DisableSearchBoxSuggestions': 'dword:00000001'
        },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection': {
          'AllowTelemetry': 'dword:00000000', 'AllowDeviceNameInTelemetry': 'dword:00000000',
          'MaxTelemetryAllowed': 'dword:00000000'
        },
        // 第六大点-B：CurrentVersion\Policies\DataCollection 的 AllowTelemetry 已归
        // 「遥测优化」(telemetry_optimize)。
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting': {
          'Disabled': 'dword:00000001', 'DontSendAdditionalData': 'dword:00000001',
          'LoggingDisabled': 'dword:00000001', 'AutoApproveOSDumps': 'dword:00000000',
          'DontShowUI': 'dword:00000001'
        },
        // 第六大点-B：SOFTWARE\Microsoft\Windows\Windows Error Reporting 的 Disabled 已归
        // 「Windows Error Reporting 策略排查」(privacy_wer_off)；本项仍保留 Policies 下的
        // WER 策略组（Disabled / DontSendAdditionalData / LoggingDisabled 等）。
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds': {
          'AllowBuildPreview': 'dword:00000000'
        },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System': {
          'EnableExperimentation': 'dword:00000000'
        },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection': {
          'DoNotShowFeedbackNotifications': 'dword:00000001'
        },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack': {
          'ShowedToastAtLevel': 'dword:00000001'
        },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\System\\AllowExperimentation': {
          'value': 'dword:00000000'
        },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\GpuEnergyDrv': {
          'Start': 'dword:00000004'
        }
      }) },
      { label: 'QuietHours 通知关闭与反馈频率', pwsh: [
        '$qh = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings"',
        'New-Item -Path $qh -Force | Out-Null',
        'New-ItemProperty -Path $qh -Name NOC_GLOBAL_SETTING_TOASTS_ENABLED -Value 0 -PropertyType DWord -Force | Out-Null',
        '$fb = "HKCU:\\SOFTWARE\\Microsoft\\Siuf\\Rules"',
        'New-Item -Path $fb -Force | Out-Null',
        'New-ItemProperty -Path $fb -Name NumberOfSIUFInPeriod -Value 0 -PropertyType DWord -Force | Out-Null',
        'New-ItemProperty -Path $fb -Name PeriodInNanoSeconds -Value 0 -PropertyType QWord -Force | Out-Null'
      ].join('\n') }
    ]
  },
  // ---------- 系统精简（原「系统清理」已并入） ----------
  // 注：「清理临时文件」已移除，功能由「磁盘清理」覆盖。
  // ---------- 显卡优化 ----------
  
  {
    id: 'tf_nvidia_telemetry', group: '显卡优化', title: 'NVIDIA：关闭遥测与自动更新', risk: 'low',
    desc: 'Trim：删除开机启动 NvBackend，OptInOrOutPreference=0，FTS EnableRID66610/64640/44231=0，并禁用 7 个 NvTm/NvDriverUpdateCheck/GeForce Experience SelfUpdate 计划任务（仅 NVIDIA 系统有对应项，缺失自动跳过）。',
    steps: [
      { label: 'NVIDIA 遥测注册表', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\NVIDIA Corporation\\NvControlPanel2\\Client': { 'OptInOrOutPreference': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\NVIDIA Corporation\\Global\\FTS': { 'EnableRID66610': 'dword:00000000', 'EnableRID64640': 'dword:00000000', 'EnableRID44231': 'dword:00000000' }
      }) },
      { label: '删除 NvBackend 启动项', pwsh: [
        'Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name NvBackend -Force -ErrorAction SilentlyContinue',
        '$sfx = "_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"',
        'foreach ($t in @("NvTmRep_CrashReport1","NvTmRep_CrashReport2","NvTmRep_CrashReport3","NvTmRep_CrashReport4","NvDriverUpdateCheckDaily","NVIDIA GeForce Experience SelfUpdate","NvTmMon")) { schtasks /change /tn ($t + $sfx) /disable 2>$null | Out-Null }'
      ].join('\n') }
    ]
  },

  // ---------- 键鼠与外设 ----------
  {
    id: 'tf_keys_sticky', group: '键鼠与外设', title: '彻底禁用粘滞/筛选/切换键', risk: 'low',
    desc: 'Trim KBM：StickyKeys Flags="506"、Keyboard Response(筛选键) Flags="122"、ToggleKeys Flags="58"，连按 Shift 8 秒等误触发快捷键全部失效。',
    steps: [
      { label: '辅助功能热键 Flags', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Accessibility\\StickyKeys': { 'Flags': '506' },
        'HKEY_CURRENT_USER\\Control Panel\\Accessibility\\Keyboard Response': { 'Flags': '122' },
        'HKEY_CURRENT_USER\\Control Panel\\Accessibility\\ToggleKeys': { 'Flags': '58' }
      }) }
    ]
  },
  
  {
    id: 'tf_usb_power', group: '键鼠与外设', title: '关闭 USB 选择性暂停', risk: 'low',
    desc: 'Trim：所有 USB 控制器 Device Parameters 下 AllowIdleIrpInD3/D3ColdSupported/DeviceSelectiveSuspended/EnableSelectiveSuspend/EnhancedPowerManagementEnabled/SelectiveSuspendEnabled/SelectiveSuspendOn 全部=0，Services\\USB DisableSelectiveSuspend=1，杜绝鼠标键盘间歇掉线。',
    steps: [
      { label: 'USB 省电键=0', pwsh: [
        '$keys = @("AllowIdleIrpInD3","D3ColdSupported","DeviceSelectiveSuspended","EnableSelectiveSuspend","EnhancedPowerManagementEnabled","SelectiveSuspendEnabled","SelectiveSuspendOn")',
        'Get-CimInstance Win32_USBController | Where-Object { $_.PNPDeviceID -like "PCI*" } | ForEach-Object {',
        '  $dp = "HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\" + $_.PNPDeviceID + "\\Device Parameters"',
        '  if (Test-Path $dp) { foreach ($n in $keys) { New-ItemProperty -Path $dp -Name $n -Value 0 -PropertyType DWord -Force | Out-Null } }',
        '}',
        'New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USB" -Force | Out-Null; New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USB" -Name DisableSelectiveSuspend -Value 1 -PropertyType DWord -Force | Out-Null'
      ].join('\n') }
    ]
  },
  {
    id: 'mouse_optimize', group: '键鼠与外设', title: '鼠标优化', risk: 'medium',
    desc: '合并原「鼠标：去加速 + 6/11 灵敏度」与「清空平滑鼠标曲线」：MouseSpeed/MouseThreshold1/MouseThreshold2="0" 彻底关闭"提高指针精确度"（鼠标加速），MouseSensitivity="10" 即 6/11 中位灵敏度，SmoothMouseXCurve/YCurve 写入 0 字节清空平滑曲线，指针移动完全线性 1:1，电竞瞄准更精准（少数驱动会重建曲线值，需重启后生效）。',
    steps: [
      { label: '鼠标加速关闭 + 6/11 灵敏度', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Mouse': {
          'MouseSpeed': '"0"', 'MouseThreshold1': '"0"', 'MouseThreshold2': '"0"', 'MouseSensitivity': '"10"'
        }
      }) },
      { label: 'SmoothMouse 曲线清零', pwsh: [
        '$zero = New-Object byte[] 40',
        '$m = "HKCU:\\Control Panel\\Mouse"',
        'New-ItemProperty -Path $m -Name SmoothMouseXCurve -Value $zero -PropertyType Binary -Force | Out-Null',
        'New-ItemProperty -Path $m -Name SmoothMouseYCurve -Value $zero -PropertyType Binary -Force | Out-Null'
      ].join('\n') }
    ]
  },
  {
    id: 'tf_keyboard', group: '键鼠与外设', title: '键盘：零延迟 + 队列深度', risk: 'low',
    desc: 'Trim：KeyboardDelay="0"、KeyboardSpeed="31"（控制面板里最短重复延迟/最快重复速度）、kbdclass KeyboardDataQueueSize=8、端口路由三值回驱动默认档（ConnectMultiplePorts=0 / MaximumPortsServed=3 / SendOutputToAllPorts=1）、kernel DebugPollInterval=1000，减少输入排队延迟。鼠标队列深度由「外设优化」窗口的鼠标组单独管理，本项不写鼠标驱动键。',
    steps: [
      { label: '键盘类参数', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Keyboard': { 'KeyboardDelay': '0', 'KeyboardSpeed': '31' },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\kbdclass\\Parameters': { 'KeyboardDataQueueSize': 'dword:00000008', 'ConnectMultiplePorts': 'dword:00000000', 'MaximumPortsServed': 'dword:00000003', 'SendOutputToAllPorts': 'dword:00000001' },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel': { 'DebugPollInterval': 'dword:000003e8' }
      }) }
    ]
  },
  {
    id: 'tf_dev_disable', group: '键鼠与外设', title: '禁用 24 个冗余板载设备', risk: 'high',
    desc: 'Trim DisableDevices（DevManView 已改写为 Disable-PnpDevice，按设备名匹配）：高精度事件定时器(HPET)、GS 波表合成、RRAS 根枚举、Intel ME/MEI/SMBus、SM Bus、Amdlog、AMD PSP、系统扬声器、复合总线枚举、虚拟驱动器枚举、Hyper-V 虚拟化基础结构、NDIS 虚拟网卡枚举、远程桌面重定向总线、UMBus、7 个 WAN Miniport 等（已剔除 IPv6 相关虚拟适配器，遵守项目硬约束）。禁用 HPET/ME 属高风险，可能影响设备管理或虚拟化。',
    steps: [
      { label: '按名称禁用设备', pwsh: [
        '$names = @("High Precision Event Timer","Microsoft GS Wavetable Synth","Microsoft RRAS Root Enumerator","Intel Management Engine","Intel Management Engine Interface","Intel SMBus","SM Bus Controller","Amdlog","AMD PSP","System Speaker","Composite Bus Enumerator","Microsoft Virtual Drive Enumerator","Microsoft Hyper-V Virtualization Infrastructure Driver","NDIS Virtual Network Adapter Enumerator","Remote Desktop Device Redirector Bus","UMBus Root Bus Enumerator","WAN Miniport (IP)","WAN Miniport (IKEv2)","WAN Miniport (L2TP)","WAN Miniport (PPPOE)","WAN Miniport (PPTP)","WAN Miniport (SSTP)","WAN Miniport (Network Monitor)")',
        'foreach ($n in $names) { Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -eq $n -and $_.Status -eq "OK" } | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue }'
      ].join('\n') }
    ]
  },
  {
    id: 'tf_dev_audio', group: '键鼠与外设', title: '禁用高清音频控制器', risk: 'high',
    desc: 'Trim 可选项：禁用 "High Definition Audio Controller"（HDMI/DP 声卡与板载声卡会消失，仅在使用独立 USB 声卡且想彻底禁用板载音频时使用）。',
    steps: [
      { label: '禁用 HD Audio Controller', pwsh: [
        'Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -eq "High Definition Audio Controller" -and $_.Status -eq "OK" } | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue'
      ].join('\n') }
    ]
  },
  {
    id: 'tf_dev_printer', group: '键鼠与外设', title: '禁用打印队列设备', risk: 'high',
    desc: 'Trim 可选项：禁用 "Root Print Queue" 打印队列根设备（无打印机的机器可禁用；有打印机请勿使用）。',
    steps: [
      { label: '禁用 Root Print Queue', pwsh: [
        'Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -eq "Root Print Queue" -and $_.Status -eq "OK" } | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue'
      ].join('\n') }
    ]
  },
  // C1（2026-09-14 重复点审查）：原「PCCleaner 深度清理」(tf_pccleaner) 已整体下线。
  // 磁盘清理尚未覆盖的项已整合进 src/data/cleanup-rules.json：
  //   cbsLogs（C:\Windows\Logs\CBS）、dismLogs（C:\Windows\Logs\DISM）、
  //   printSpoolCache（C:\Windows\System32\spool\PRINTERS，取系统维护 print 的原正确路径）
  // 其余路径与磁盘清理现有条目重复（Windows Temp / %TEMP% / Prefetch / 回收站 / Explorer *.db），
  // 或为现代 Windows 上已不存在的死路径（Windows tmp / history / cookies / recent / spool\printers）。
  // 全盘递归删 *.tmp/*.log 等模式因无路径边界、扫描需全盘递归，与本模块「逐目录可扫描可排除」
  // 的模型不兼容，未予整合（见 2026-09-14 审查报告）。
  // 该项另用裸 Remove-Item 绕过 trashOrUnlink / 删除清单 / confirmDanger，违反项目安全红线。
  // ---------- 系统精简 ----------
  {
    // 对比审查 P0（2026-09-14）：此前 PROS_CONS 有本项文案、main.js optimizer:create-restore
    // 也按本 id 取脚本，但 OPTIONS 无定义 → 还原点创建链路整体失效（回退保障为空）。
    id: 'tf_restore_point', group: '系统精简', title: '创建系统还原点', risk: 'low',
    desc: '为所有已启用系统保护的磁盘创建一个还原点，作为后续高风险优化的回退保障（异常时到「系统设置 → 恢复」或本页「系统还原点管理」回退）。注意：创建过程会临时将还原点创建频率限制改为 0（解除 24h 限制，原始值已进值级备份，可经「还原」回写）。PS7 无 Checkpoint-Computer，走 root\\default SystemRestore WMI 静态方法创建；需管理员权限，且至少一个卷已开启系统保护。',
    steps: [
      {
        label: '解除还原点创建频率限制',
        // 用 reg 步骤（而非 pwsh 写注册表）：可进 optimizer-backups 值级备份，
        // 也让 checkOptimizedInternal / verifyOptionApplied 有逐键比对手段。
        reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore': {
            'SystemRestorePointCreationFrequency': 'dword:00000000'
          }
        })
      },
      {
        label: '创建还原点', pwsh: [
          "# EventType 100 = BEGIN_SYSTEM_CHANGE，RestorePointType 0 = APPLICATION_INSTALL",
          "$null = Invoke-CimMethod -Namespace 'root/default' -ClassName 'SystemRestore' -MethodName 'CreateRestorePoint' -Arguments @{ Description = 'Trim 优化前还原点'; EventType = [uint32]100; RestorePointType = [uint32]0 } -ErrorAction Stop"
        ].join('\n')
      }
    ],
    // 一键还原：删除本项写入的频率覆写（无该值时系统按默认 24 小时限制工作）；
    // 还原点本身属系统快照，不提供脚本级撤销。
    restore: [
      { label: '还原：移除创建频率覆写', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore': {
          'SystemRestorePointCreationFrequency': '-'
        }
      }) }
    ]
  },
  {
    id: 'tf_appx', group: '系统精简', title: '移除 25 个内置 UWP 应用', risk: 'high',
    desc: 'Trim Debloat：按名称通配移除所有用户下的预装 AppX——3D Builder、Bing 全家桶（资讯/财经/体育/天气）、CommsPhone、Drawboard PDF、Facebook、Getstarted、Messaging、Office Hub、OneNote、人脉、Skype、纸牌合集、Sway、Twitter、闹钟时钟、手机、地图、反馈中心、录音机、邮件日历、Zune（Groove/影视）等。移除后部分应用需从商店重装。',
    steps: [
      { label: '移除预装 AppX 清单', pwsh: [
        '$apps = @("*3DBuilder*","*bing*","*bingfinance*","*bingsports*","*BingWeather*","*CommsPhone*","*Drawboard PDF*","*Facebook*","*Getstarted*","*Microsoft.Messaging*","*MicrosoftOfficeHub*","*Office.OneNote*","*OneNote*","*people*","*SkypeApp*","*solit*","*Sway*","*Twitter*","*WindowsAlarms*","*WindowsPhone*","*WindowsMaps*","*WindowsFeedbackHub*","*WindowsSoundRecorder*","*windowscommunicationsapps*","*zune*")',
        'foreach ($a in $apps) { Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue }'
      ].join('\n') }
    ]
  },
  {
    id: 'tf_cortana', group: '系统精简', title: '禁用 Cortana 与网页搜索', risk: 'medium',
    desc: 'Trim DisableCortana：写入 Windows Search 策略（AllowCortana/AllowCloudSearch/AllowCortanaAboveLock/AllowSearchToUseLocation/ConnectedSearchUseWeb/ConnectedSearchUseWebOverMeteredConnections=0，DisableWebSearch=1——已修正 Trim 原版此处反写成 0 的 bug），并卸载 Cortana AppX（Microsoft.549981C3F5F10）。',
    steps: [
      {
        label: 'Cortana / 网页搜索策略', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search': {
            'AllowCortana': 'dword:00000000',
            'AllowCloudSearch': 'dword:00000000',
            'AllowCortanaAboveLock': 'dword:00000000',
            'AllowSearchToUseLocation': 'dword:00000000',
            'ConnectedSearchUseWeb': 'dword:00000000',
            'ConnectedSearchUseWebOverMeteredConnections': 'dword:00000000',
            'DisableWebSearch': 'dword:00000001'
          }
        })
      },
      { label: '卸载 Cortana AppX', pwsh: [
        'Get-AppxPackage -AllUsers -Name "*Microsoft.549981C3F5F10*" -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue'
      ].join('\n') }
    ]
  },
  {
    id: 'tf_onedrive', group: '系统精简', title: '彻底卸载 OneDrive', risk: 'high',
    // 对比审查 P0/B-2（2026-09-14）：desc 改为逐条列出删除目标绝对路径；数据目录删除
    // 不再 PS 内 Remove-Item -Recurse -Force 裸删（绕过统一删除出口、不可逆），改经
    // @@RECYCLE@@ 协议交回主进程 shell.trashItem（回收站优先，可还原）。
    desc: 'Trim DisableOneDrive：运行 OneDriveSetup /UNINSTALL，将 OneDrive 数据目录移入回收站（可在系统回收站还原）：C:\\OneDriveTemp、%USERPROFILE%\\OneDrive（注意：其中是您自己的文档/桌面/照片等同步内容）、%LOCALAPPDATA%\\Microsoft\\OneDrive、%PROGRAMDATA%\\Microsoft OneDrive；再清空资源管理器左栏 OneDrive 入口 CLSID 属性（HKCR 与 Wow6432Node 双 hive），并写入禁用文件同步的组策略（DisableFileSync/DisableFileSyncNGSC=1）。',
    steps: [
      { label: '运行 OneDrive 卸载器', pwsh: [
        '$setup = Join-Path $env:SystemRoot "SYSWOW64\\ONEDRIVESETUP.EXE"',
        'if (Test-Path $setup) { Start-Process -FilePath $setup -ArgumentList "/UNINSTALL" -Wait -NoNewWindow }'
      ].join('\n') },
      { label: '上报 OneDrive 数据目录（主进程移入回收站）', pwsh: [
        // 只枚举存在性并上报，不执行任何删除；体积测量省略（OneDrive 目录可达数 GB，
        // 递归统计会显著拖慢执行，回收站消息不依赖体积）。
        '$odDirs = @("$env:SystemDrive\\OneDriveTemp", "$env:USERPROFILE\\OneDrive", "$env:LOCALAPPDATA\\Microsoft\\OneDrive", "$env:PROGRAMDATA\\Microsoft OneDrive")',
        "foreach ($d in $odDirs) { if (Test-Path -LiteralPath $d) { Write-Output ('@@RECYCLE@@' + (@{ id = 'tf_onedrive'; path = $d; isDir = $true } | ConvertTo-Json -Compress)) } }"
      ].join('\n') },
      {
        label: 'OneDrive 入口 / 策略', reg: regBlock({
          'HKEY_CLASSES_ROOT\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\ShellFolder': { 'Attributes': 'dword:00000000' },
          'HKEY_CLASSES_ROOT\\Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\ShellFolder': { 'Attributes': 'dword:00000000' },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive': {
            'DisableFileSync': 'dword:00000001',
            'DisableFileSyncNGSC': 'dword:00000001',
            'DisableMeteredNetworkFileSync': 'dword:00000000',
            'DisableLibrariesDefaultSaveToOneDrive': 'dword:00000000'
          }
        })
      }
    ]
  },
  // ---------- 音频优化（对齐 Trim BuildAudioModule） ----------
  {
    id: 'audio_disable_enhancements', group: '音频优化', title: '关闭音频增强', risk: 'medium',
    desc: '为所有播放设备关闭系统音频增强处理（Enhancements），减少额外音效加工，让游戏与媒体声音更干净稳定。',
    steps: [
      {
        label: '遍历渲染设备关闭增强', pwsh: [
          '$render = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Render"',
          'if (Test-Path $render) { Get-ChildItem $render | ForEach-Object { $fx = Join-Path $_.PSPath "FxProperties"; if (Test-Path $fx) { New-ItemProperty -Path $fx -Name "{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null } } }'
        ].join('\n')
      }
    ]
  },
  {
    id: 'audio_disable_spatial_sound', group: '音频优化', title: '关闭空间音效', risk: 'medium',
    desc: '关闭 Windows Sonic / Dolby Atmos 等虚拟环绕声，让原始声道信号直达耳机/音箱；需确认空间音效体验变化。',
    steps: [
      {
        label: '关闭空间音效', pwsh: [
          '$render = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Render"',
          'if (Test-Path $render) { Get-ChildItem $render | ForEach-Object { $fx = Join-Path $_.PSPath "FxProperties"; if (Test-Path $fx) { New-ItemProperty -Path $fx -Name "{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},7" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null } } }'
        ].join('\n')
      }
    ]
  },
  {
    id: 'audio_mmcss_priority', group: '音频优化', title: '提高音频任务优先级', risk: 'medium',
    desc: '将 MMCSS Audio 任务 Priority 设为 6、Scheduling Category 设为 Pro Audio，提升音频线程调度优先级；不会启用应用或音频端点的独占模式。',
    steps: [
      {
        label: 'MMCSS Audio Priority=6 / Pro Audio', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Audio': {
            'Priority': 'dword:00000006',
            'Scheduling Category': '"Pro Audio"'
          }
        })
      }
    ]
  },
  {
    id: 'audio_mmcss_schedule', group: '音频优化', title: '调整音频任务调度', risk: 'medium',
    desc: '调整 MMCSS Audio 任务的 Affinity、Scheduling Category 与 SFIO Priority，优化音频线程核心分布与 IO 优先级；Priority 由「提高音频任务优先级」独立管理。',
    steps: [
      {
        label: 'MMCSS Audio Affinity/SFIO', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Audio': {
            'Affinity': 'dword:00000000',
            'SFIO Priority': '"High"',
            'Background Only': '"False"',
            'Clock Rate': 'dword:00002710'
          }
        })
      }
    ]
  },
  {
    id: 'audio_disable_comm_ducking', group: '音频优化', title: '关闭通讯优先压低', risk: 'medium',
    desc: '禁用 Windows 检测到通讯活动时自动压低其他声音的逻辑（Communications Ducking），避免游戏/媒体音量被通话突然压低。',
    steps: [
      {
        label: '关闭通讯压低', pwsh: [
          '$paths = @("HKCU:\\Software\\Microsoft\\Multimedia\\Audio","HKCU:\\Software\\Microsoft\\Multimedia\\Audio\\User")',
          'foreach ($p in $paths) { New-Item -Path $p -Force | Out-Null; New-ItemProperty -Path $p -Name "CommDucking" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }',
          '$ap = "HKCU:\\Software\\Microsoft\\Multimedia\\Audio\\Ducking\\Mode"',
          'New-Item -Path $ap -Force | Out-Null; New-ItemProperty -Path $ap -Name "Default" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null'
        ].join('\n')
      }
    ]
  },
  {
    id: 'audio_disable_service_restart', group: '音频优化', title: '禁用 Windows Audio 延迟启动', risk: 'medium',
    desc: '将 Audiosrv 的 DelayedAutoStart 设为 0，让 Windows 音频服务随系统同步启动；不会更改 AudioEndpointBuilder 或服务故障恢复策略。',
    steps: [
      {
        label: 'Audiosrv DelayedAutoStart=0', pwsh: [
          '$p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Audiosrv"',
          'if (Test-Path $p) { New-ItemProperty -Path $p -Name DelayedAutoStart -Value 0 -PropertyType DWord -Force | Out-Null }'
        ].join('\n')
      }
    ]
  },
      {
    id: 'audio_disable_narrator_ducking', group: '音频优化', title: '关闭讲述人压低其他应用音量', risk: 'medium',
    desc: 'DuckAudio=0，关闭讲述人说话时自动降低其他应用音量；依赖讲述人的用户需要手动平衡音量。',
    steps: [
      {
        label: '关闭讲述人压低音量', pwsh: [
          '$p = "HKCU:\\Software\\Microsoft\\Narrator\\NoRoam"',
          'New-Item -Path $p -Force | Out-Null; New-ItemProperty -Path $p -Name "DuckAudio" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null',
          '$p2 = "HKLM:\\SOFTWARE\\Microsoft\\Narrator\\NoRoam"',
          'New-Item -Path $p2 -Force | Out-Null; New-ItemProperty -Path $p2 -Name "DuckAudio" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null'
        ].join('\n')
      }
    ]
  },
  // ---------- 桌面体验（对齐 Trim BuildExplorerModule） ----------
  {
    id: 'desktop_show_ext', group: '桌面体验', title: '显示文件扩展名', risk: 'medium',
    desc: 'HideFileExt=0，使所有文件始终显示其扩展名，防止伪装成文档的恶意程序。',
    steps: [
      {
        label: '显示文件扩展名', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
            'HideFileExt': 'dword:00000000'
          }
        })
      }
    ]
  },
  {
    id: 'desktop_show_hidden', group: '桌面体验', title: '显示隐藏文件和文件夹', risk: 'medium',
    desc: 'Hidden=1，方便排查配置、Mod、日志和游戏数据目录；误删风险上升。',
    steps: [
      {
        label: '显示隐藏文件', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
            'Hidden': 'dword:00000001',
            'ShowSuperHidden': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'desktop_thumb_delay', group: '桌面体验', title: '移除缩略图悬停延迟', risk: 'medium',
    desc: '缩短任务栏预览/缩略图悬停等待时间，让窗口切换更快；窗口很多时可能更容易误触预览。',
    steps: [
      {
        label: '缩短悬停延迟', reg: regBlock({
          'HKEY_CURRENT_USER\\Control Panel\\Mouse': {
            'MouseHoverTime': '"50"'
          },
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
            'TaskbarThumbnailDelay': 'dword:00000032'
          }
        })
      }
    ]
  },
  {
    id: 'desktop_sep_process', group: '桌面体验', title: '独立进程打开文件夹窗口', risk: 'medium',
    desc: 'SeparateProcess=1，单个资源管理器窗口异常时不会拖垮整个桌面和任务栏。',
    steps: [
      {
        label: '独立进程打开文件夹', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
            'SeparateProcess': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'desktop_taskbar_left', group: '桌面体验', title: '任务栏图标左对齐', risk: 'medium',
    desc: 'TaskbarAl=0，将 Win11 任务栏与开始按钮靠左显示，更接近 Win10 使用习惯。',
    steps: [
      {
        label: '任务栏图标左对齐', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
            'TaskbarAl': 'dword:00000000'
          }
        })
      }
    ]
  },
  {
    id: 'desktop_taskbar_show_desktop', group: '桌面体验', title: '启用任务栏角落显示桌面', risk: 'medium',
    desc: 'TaskbarSd=1，点击任务栏最右侧角落可显示桌面，适合频繁切换窗口的用户。',
    steps: [
      {
        label: '启用角落显示桌面', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
            'TaskbarSd': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'desktop_taskbar_multi', group: '桌面体验', title: '在所有显示器显示任务栏', risk: 'medium',
    desc: 'MMTaskbarEnabled=1，多屏游戏/直播/办公时每个屏幕都能直接访问任务栏。',
    steps: [
      {
        label: '所有显示器显示任务栏', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
            'MMTaskbarEnabled': 'dword:00000001',
            'MMTaskbarShowAllIcons': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'desktop_low_disk_off', group: '桌面体验', title: '低磁盘空间提醒排查', risk: 'medium',
    desc: 'NoLowDiskSpaceChecks=1，关闭系统低磁盘空间提醒弹窗；请确认不依赖 Windows 低磁盘提醒后再关闭。',
    steps: [
      {
        label: '关闭低磁盘提醒', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer': {
            'NoLowDiskSpaceChecks': 'dword:00000001'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer': {
            'NoLowDiskSpaceChecks': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'explorer_autorestart', group: '桌面体验', title: '资源管理器崩溃时自动重启', risk: 'low',
    desc: 'AutoRestartShell=1，explorer.exe 意外退出后由系统自动拉起，桌面与任务栏无需手动重启（HKCU 为参考项目原路径，同时写入实际生效的 HKLM Winlogon）。',
    steps: [
      {
        label: 'AutoRestartShell=1（HKCU + HKLM）', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon': { 'AutoRestartShell': 'dword:00000001' },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon': { 'AutoRestartShell': 'dword:00000001' }
        })
      }
    ]
  },
  {
    id: 'explorer_refresh_policy', group: '桌面体验', title: '优化文件列表刷新策略', risk: 'low',
    desc: 'NoSimpleNetIDList=1，禁用简化的网络标识列表，让资源管理器按完整信息刷新文件列表，减少新建/重命名后不即时显示的问题。',
    steps: [
      {
        label: 'NoSimpleNetIDList=1', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer': { 'NoSimpleNetIDList': 'dword:00000001' }
        })
      }
    ]
  },
  // N3（2026-09-14 重复点审查）：原「总是从内存中卸载无用的 DLL」(always_unload_dll) 已下线。
  // 它与「内存清理 - 进程工作集」目标重叠（都为降低常驻内存占用），且该键值为传统优化项，
  // 现代 Windows 上部分组件已不再读取，收益存疑。退役登记见 data/retired-optimizations.json。
  // C3（2026-09-14 重复点审查）：原「退出时清除最近打开的文件历史」已下线。
  // 它与「磁盘清理 - 隐私历史」的 explorerRecentDocs（清 RecentDocs 注册表树）与
  // recentFiles（清 %APPDATA%\Microsoft\Windows\Recent）目标相同，只保留磁盘清理那一套。
  // ---------- 任务调度（对齐 Trim BuildTasksModule） ----------
  // 第六大点-B（2026-09-14 重复点审查）：原「CEIP Consolidator 任务排查」「USB CEIP 任务排查」
  // 「磁盘诊断数据采集任务排查」三项已下线 —— 它们的目标任务（Consolidator / UsbCeip /
  // Microsoft-Windows-DiskDiagnosticDataCollector）都已被「遥测优化」(telemetry_optimize) 的
  // 任务清单覆盖，属批量项与专项项重复，合并后保留批量项。
  // 附带修正：原 tasks_disable_disk_diag 写的任务名 DiskDiagnosticDataCollector 缺
  // 「Microsoft-Windows-」前缀（本机实测真实名为 Microsoft-Windows-DiskDiagnosticDataCollector），
  // 该项在旧实现里必然静默失败。
  {
    id: 'tasks_disable_defrag', group: '任务调度', title: '计划碎片整理触发排查', risk: 'medium',
    desc: '停用 \\Microsoft\\Windows\\Defrag\\ScheduledDefrag 计划任务；可能影响 HDD 整理或 SSD/TRIM 维护节奏，需保留恢复路径。',
    steps: [
      { label: '停用计划碎片整理', pwsh: 'Disable-ScheduledTask -TaskPath "\\Microsoft\\Windows\\Defrag\\" -TaskName "ScheduledDefrag" -ErrorAction SilentlyContinue' }
    ],
    restore: [
      { label: '启用计划碎片整理', pwsh: 'Enable-ScheduledTask -TaskPath "\\Microsoft\\Windows\\Defrag\\" -TaskName "ScheduledDefrag" -ErrorAction SilentlyContinue' }
    ]
  },
  {
    id: 'tasks_disable_silent_cleanup', group: '任务调度', title: 'SilentCleanup 触发排查', risk: 'medium',
    desc: '停用 \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup 计划任务；关闭后可减少空闲时突然触发的磁盘和后台活动，需保留恢复路径。',
    steps: [
      { label: '停用 SilentCleanup', pwsh: 'Disable-ScheduledTask -TaskPath "\\Microsoft\\Windows\\DiskCleanup\\" -TaskName "SilentCleanup" -ErrorAction SilentlyContinue' }
    ],
    restore: [
      { label: '启用 SilentCleanup', pwsh: 'Enable-ScheduledTask -TaskPath "\\Microsoft\\Windows\\DiskCleanup\\" -TaskName "SilentCleanup" -ErrorAction SilentlyContinue' }
    ]
  },
  {
    id: 'tasks_disable_winbackup', group: '任务调度', title: 'Windows Backup 监视排查', risk: 'medium',
    desc: '停用 \\Microsoft\\Windows\\WindowsBackup\\AutomaticBackup 计划任务；需确认不依赖系统备份提醒或旧备份工作流。',
    steps: [
      { label: '停用 Windows Backup 监视', pwsh: 'Disable-ScheduledTask -TaskPath "\\Microsoft\\Windows\\WindowsBackup\\" -TaskName "AutomaticBackup" -ErrorAction SilentlyContinue' }
    ],
    restore: [
      { label: '启用 Windows Backup 监视', pwsh: 'Enable-ScheduledTask -TaskPath "\\Microsoft\\Windows\\WindowsBackup\\" -TaskName "AutomaticBackup" -ErrorAction SilentlyContinue' }
    ]
  },
  {
    id: 'tasks_disable_settingsync', group: '任务调度', title: 'SettingSync 后台同步任务排查', risk: 'medium',
    desc: '停用 \\Microsoft\\Windows\\SettingSync\\BackgroundUploadTask 计划任务；需确认不依赖设置同步、跨设备偏好或账户恢复。',
    steps: [
      { label: '停用 SettingSync 后台同步', pwsh: 'Disable-ScheduledTask -TaskPath "\\Microsoft\\Windows\\SettingSync\\" -TaskName "BackgroundUploadTask" -ErrorAction SilentlyContinue' }
    ],
    restore: [
      { label: '启用 SettingSync 后台同步', pwsh: 'Enable-ScheduledTask -TaskPath "\\Microsoft\\Windows\\SettingSync\\" -TaskName "BackgroundUploadTask" -ErrorAction SilentlyContinue' }
    ]
  },
  // 第六大点-B（2026-09-14 重复点审查）：原「Office Telemetry 登录任务排查」已下线 ——
  // 目标任务 OfficeTelemetryAgentLogOn 已被「遥测优化」(telemetry_optimize) 覆盖。
  // 注意：telemetry_optimize 里原有的 \Microsoft\Windows\Office\OfficeTelemetryAgentLogOn
  // 与 FallBack 两条多了一层 Windows（真实路径为 \Microsoft\Office\），同批已修正。
  // N1（2026-09-14 重复点审查）：原「顽固软件策略专杀」(tasks_stubborn_strategy) 已下线 ——
  // 它与「内存清理 - 顽固软件治理」是同一批目标（MuMu / 网易 UU 远程 / 微软电脑管家 / WPS）
  // 的两个层次，现合并到内存清理页那张卡片：「立即结束进程」+「阻止开机自启」。
  // 脚本已迁移为 src/scripts-powershell/memory-scripts.js 的 STUBBORN_BLOCK_SCRIPT，
  // IPC 通道为 memory:stubborn-block。
  // ---------- 外设调优新增（对齐 Trim BuildPeripheralModule） ----------
  {
    id: 'peripheral_inactive_scroll', group: '外设调优', title: '关闭非活动窗口滚动', risk: 'medium',
    desc: 'MouseWheelRouting=0，滚动仅作用于当前活动窗口，避免误滚动到背景窗口；多窗口用户慎用。',
    steps: [
      { label: 'MouseWheelRouting=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Desktop': {
          'MouseWheelRouting': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'peripheral_winkey_off', group: '外设调优', title: '禁用 Win 键误触', risk: 'medium',
    desc: '写入 Scancode Map 屏蔽左右 Win 键，避免游戏中误触 Windows 键切出；会禁用 Win+快捷键。',
    steps: [
      { label: 'Scancode Map 屏蔽 Win 键', pwsh: [
        '$p = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout"',
        '$map = [byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x5b,0xe0,0x00,0x00,0x5c,0xe0,0x00,0x00,0x00,0x00)',
        'New-Item -Path $p -Force | Out-Null',
        'New-ItemProperty -Path $p -Name "Scancode Map" -Value $map -PropertyType Binary -Force | Out-Null'
      ].join('\n') }
    ],
    restore: [
      { label: '还原 Scancode Map', pwsh: 'Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout" -Name "Scancode Map" -ErrorAction SilentlyContinue' }
    ]
  },
  {
    id: 'peripheral_mouse_trails', group: '外设调优', title: '关闭硬件鼠标轨迹', risk: 'medium',
    desc: 'MouseTrails=0，关闭鼠标拖尾效果，让指针显示更干净，减少视觉干扰。',
    steps: [
      { label: 'MouseTrails=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Mouse': {
          'MouseTrails': '"0"'
        }
      }) }
    ]
  },
  {
    id: 'peripheral_snap_to', group: '外设调优', title: '禁用 SnapTo（自动跳到默认按钮）', risk: 'medium',
    desc: 'SnapToDefaultButton=0，禁止鼠标自动跳到对话框默认按钮，避免误操作。',
    steps: [
      { label: 'SnapToDefaultButton=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Mouse': {
          'SnapToDefaultButton': '"0"'
        }
      }) }
    ]
  },
  // ---------- 隐私防护新增（对齐 Trim BuildPrivacyModule；相机/麦克风/联系人按需排除） ----------
  {
    id: 'privacy_advertising_id', group: '隐私防护', title: '广告 ID 个性化排查', risk: 'medium',
    desc: 'AdvertisingInfo Enabled=0 并重置 AdvertisingInfo Id，关闭广告个性化；需确认是否依赖个性化广告或应用推荐体验。',
    steps: [
      {
        label: '关闭广告 ID', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo': {
            'Enabled': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo': {
            'DisabledByGroupPolicy': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'privacy_wer_off', group: '隐私防护', title: 'Windows Error Reporting 策略排查', risk: 'medium',
    desc: 'WER Disabled=1，关闭 Windows 错误报告收集；需确认崩溃诊断、故障反馈和企业问题分析取舍。',
    steps: [
      {
        label: '关闭 WER', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting': {
            'Disabled': 'dword:00000001'
          },
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Windows Error Reporting': {
            'Disabled': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'privacy_compat_telemetry', group: '隐私防护', title: '兼容性遥测排查', risk: 'medium',
    desc: 'DisableUAR=1，关闭兼容性评估数据回传；需确认应用兼容性诊断、升级评估和企业策略取舍。',
    steps: [
      { label: 'DisableUAR=1', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System': {
          'EnableUAR': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'privacy_settingsync_off', group: '隐私防护', title: '设置/应用同步排查', risk: 'medium',
    desc: 'DisableSettingSync=1，关闭设置和应用同步，减少风险并受账号状态和组织策略影响；需复查跨设备偏好、账户恢复或新设备迁移取舍。',
    steps: [
      {
        label: '关闭设置同步', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\SettingSync': {
            'DisableSettingSync': 'dword:00000001',
            'DisableSettingSyncUserOverride': 'dword:00000001'
          },
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\SettingSync': {
            'DisableSettingSync': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'privacy_cloud_content', group: '隐私防护', title: '云推荐内容排查', risk: 'medium',
    desc: '关闭 Spotlight、消费者体验和部分推荐内容策略，减少风险并受账号状态和组织策略影响；需复查锁屏聚焦、推荐内容和个性化体验变化。',
    steps: [
      {
        label: '关闭云推荐内容', reg: regBlock({
          'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager': {
            'SystemPaneSuggestionsEnabled': 'dword:00000000',
            'SubscribedContent-338389Enabled': 'dword:00000000',
            'SubscribedContent-310093Enabled': 'dword:00000000',
            'SubscribedContent-338388Enabled': 'dword:00000000',
            'RotatingLockScreenEnabled': 'dword:00000000',
            'RotatingLockScreenOverlayEnabled': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent': {
            'DisableWindowsConsumerFeatures': 'dword:00000001'
          }
        })
      }
    ]
  },
  {
    id: 'privacy_permissions_tune', group: '隐私防护', title: '各类权限精调', risk: 'medium',
    desc: '按 Trim 缺失项合并精调 20+ 项权限与数据收集开关：应用访问（文件系统/文档/日历/联系人/位置拒绝）、活动收集、应用启动跟踪、写作习惯、键入文本、输入个性化、键入见解、OOBE 隐私体验、通讯录收集、自动连接热点、.NET/PowerShell 遥测环境变量（机器级）、启用剪贴板历史、停用 SMS 路由器服务（原「网站语言跟踪」「Bing 搜索」「定向广告」「兼容性遥测」「页面预测」「设置应用建议」「赞助商应用」「搜索历史」已被现有优化项覆盖，不再重复写入）。',
    steps: [
      { label: '应用访问权限（ConsentStore=Deny）', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\documentsLibrary': { 'Value': '"Deny"' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\documents': { 'Value': '"Deny"' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\appointments': { 'Value': '"Deny"' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\contacts': { 'Value': '"Deny"' }
      }) },
      { label: '位置服务拒绝', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location': { 'Value': '"Deny"' }
      }) },
      { label: '启动跟踪 / 活动收集 / 启用剪贴板历史', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': { 'Start_TrackEnabled': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System': {
          'EnableActivityFeed': 'dword:00000000',
          'AllowClipboardHistory': 'dword:00000001'
        }
      }) },
      { label: '输入与写作习惯收集', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\WritingTips': { 'Enabled': 'dword:00000000' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Input\\TIPC': { 'Enabled': 'dword:00000000' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\InputPersonalization': {
          'RestrictImplicitTextCollection': 'dword:00000001',
          'RestrictImplicitInkCollection': 'dword:00000001'
        },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Input\\Settings': { 'InsightsEnabled': 'dword:00000000' }
      }) },
      { label: 'OOBE 隐私体验与通讯录收集', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\OOBE': { 'DisablePrivacyExperience': 'dword:00000001' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContactData': { 'ContactDataCollectionEnabled': 'dword:00000000' }
      }) },
      { label: '禁止自动连接开放热点', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config': { 'AutoConnectAllowedOEM': 'dword:00000000' }
      }) },
      { label: '.NET / PowerShell 遥测环境变量（机器级）', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment': {
          'DOTNET_CLI_TELEMETRY_OPTOUT': '"1"',
          'POWERSHELL_TELEMETRY_OPTOUT': '"1"'
        }
      }) },
      { label: '停用 SMS 路由器服务', service: 'MessagingService', disable: true }
    ]
  },
  // ==================== 系统服务（对齐 Trim BuildServicesModule 独立策略）====================
  {
    id: 'svc_connected_devices_manual', group: '系统服务', title: '跨设备平台服务设为手动', risk: 'medium',
    desc: 'CDPSvc / CDPUserSvc Start=3，让跨设备、手机连接和附近共享相关服务按需启动；不承诺固定资源收益，需要这些体验时可恢复原启动类型。',
    steps: [
      {
        label: 'CDPSvc / CDPUserSvc 设为手动', pwsh: [
          '$svcs = @("CDPSvc","CDPUserSvc")',
          'foreach ($n in $svcs) { $p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 3 -PropertyType DWord -Force | Out-Null } }'
        ].join('\n')
      }
    ],
    restore: [
      {
        label: '恢复为自动(2)', pwsh: [
          '$svcs = @("CDPSvc","CDPUserSvc")',
          'foreach ($n in $svcs) { $p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 2 -PropertyType DWord -Force | Out-Null } }'
        ].join('\n')
      }
    ]
  },
    {
    id: 'svc_remote_registry_disable', group: '系统服务', title: 'RemoteRegistry 远程管理排查', risk: 'medium',
    desc: 'RemoteRegistry 服务 Start=4 并停止；仅在确认不依赖远程注册表管理、资产盘点、运维工具或企业策略时请求关闭，并保留恢复路径。',
    steps: [
      { label: 'RemoteRegistry Start=4', pwsh: '$p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 4 -PropertyType DWord -Force | Out-Null; Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue }' }
    ]
  },
  {
    id: 'svc_remote_connectivity_manual', group: '系统服务', title: '远程连接服务设为手动', risk: 'medium',
    desc: 'RasMan / RasAuto / RDP 相关服务 Start=3；需确认不依赖 VPN、拨号、远程接入或自动连接远程资源，并保留恢复路径。',
    steps: [
      {
        label: '远程连接相关服务设为手动', pwsh: [
          '$svcs = @("RasMan","RasAuto","RemoteAccess","TermService","UmRdpService","SessionEnv")',
          'foreach ($n in $svcs) { $p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 3 -PropertyType DWord -Force | Out-Null } }'
        ].join('\n')
      }
    ]
  },
  {
    id: 'svc_bluetooth_disable', group: '系统服务', title: '蓝牙后台服务使用排查', risk: 'medium',
    desc: 'bthserv 服务 Start=4 并停止；仅在确认不用蓝牙耳机、手柄、鼠标、键盘、手机互联或配对流程时请求关闭；需按设备和驱动复测。',
    steps: [
      { label: 'bthserv Start=4', pwsh: '$p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bthserv"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 4 -PropertyType DWord -Force | Out-Null; Stop-Service -Name bthserv -Force -ErrorAction SilentlyContinue }' }
    ]
  },
  // ==================== 系统调校补齐（对齐 Trim BuildSystemModule）====================
  {
    id: 'power_aspm_off', group: '系统调校', title: '禁用 PCI-E ASPM 节能', risk: 'medium',
    desc: '电源方案与设备级关闭 PCIe 链路节能(ASPM)，可能减少显卡、硬盘或网卡从低功耗状态唤醒时的卡顿。',
    steps: [
      {
        label: '电源方案关闭 ASPM', pwsh: [
          'powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0',
          'powercfg /setdcvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0',
          'powercfg /setactive SCHEME_CURRENT'
        ].join('\n')
      },
      {
        label: '设备级 ASPM 关闭', pwsh: [
          '$root = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}"',
          'if (Test-Path $root) { Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object { New-ItemProperty -Path $_.PSPath -Name "EnableASPM" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null } }'
        ].join('\n')
      }
    ]
  },
  {
    id: 'storage_8dot3_off', group: '系统调校', title: '禁用 NTFS 8.3 短文件名', risk: 'medium',
    desc: '关闭 8.3 短文件名生成（fsutil 8dot3name set 1），减少短文件名维护开销；旧安装器、脚本或驱动兼容性需确认。',
    steps: [
      { label: 'fsutil 禁用 8.3', cmd: 'fsutil behavior set disable8dot3 1' }
    ],
    restore: [
      { label: '恢复 8.3（默认0）', cmd: 'fsutil behavior set disable8dot3 0' }
    ]
  },
  // 注：「清空待机列表（StandbyList）」已移除，功能由「内存清理」覆盖。
  // ==================== 性能调优补齐（对齐 Trim BuildPerformanceModule）====================
  {
    id: 'perf_uwp_background_off', group: '性能调优', title: 'UWP 后台运行排查', risk: 'medium',
    desc: 'GlobalUserDisabled=1，请求限制通用应用后台运行；需确认通知、同步和后台刷新需求，不承诺固定资源收益。',
    steps: [
      { label: '后台应用全局禁用', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications': {
          'GlobalUserDisabled': 'dword:00000001'
        },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy': {
          'LetAppsRunInBackground': 'dword:00000002'
        }
      }) }
    ]
  },
  {
    id: 'perf_store_auto_update_off', group: '性能调优', title: '商店应用自动更新排查', risk: 'medium',
    desc: 'AutoDownload=2，请求改为手动检查 Microsoft Store 应用更新；需复查是否影响更新、下载、安装和本机带宽/I/O。',
    steps: [
      { label: 'WindowsStore AutoDownload=2', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore': {
          'AutoDownload': 'dword:00000002'
        },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Store': {
          'AutoDownload': 'dword:00000002'
        }
      }) }
    ]
  },
  // ==================== v3.7.0 议题六 P1：Windows Update 三态 ====================
  // 此前只有「关」一个开关（NoAutoUpdate=1），没有「暂停到日期」这条主推荐路径。
  // 三态分工：
  //   perf_wu_pause  —— 暂停到日期（主路径，普通风险，1~35 天档位）
  //   perf_wu_enable —— 启用（清 Trim 自己写入的暂停值与 NoAutoUpdate 策略）
  //   perf_windows_update_off —— 彻底禁用（高危，红色二次确认，第一版只写策略不动服务）
  // 注意：暂停不停 wuauserv / UsoSvc / BITS —— 这三个服务被商店、组件安装、
  // Defender 更新复用，停服不是暂停更新的必要条件（实测本机 Start=3/3/2）。
  {
    id: 'perf_windows_update_off', group: '性能调优', title: 'Windows 更新：彻底禁用（高危）', risk: 'high',
    desc: 'NoAutoUpdate=1，彻底停止自动检查与安装更新；安全更新将不再自动送达，仅建议在明确知晓风险并使用其它补丁维护方式时选择。第一版只写策略层，不直接停用 wuauserv / UsoSvc / BITS。若只是想推迟一段时间，请用「Windows 更新：暂停到日期」。',
    steps: [
      { label: 'WindowsUpdate NoAutoUpdate=1', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU': {
          'NoAutoUpdate': 'dword:00000001'
        }
      }) }
    ],
    restore: [
      { label: '还原：移除 NoAutoUpdate 策略（恢复系统默认更新行为）', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU': {
          'NoAutoUpdate': '-'
        }
      }) }
    ]
  },
  {
    id: 'perf_wu_pause', group: '性能调优', title: 'Windows 更新：暂停到日期', risk: 'medium',
    desc: '写入 Windows 官方的功能更新 / 质量更新暂停键（起止时间 + 过期时间均为 FILETIME），把更新推迟到指定天数之后。这是推迟更新的主推荐方式：服务照常运行、到期自动恢复，不需要禁用任何组件。支持 1~35 天档位；不宣称绕过系统自身的暂停上限。',
    dynamic: true,
    steps: [] // 由 windowsUpdatePauseSteps(days) 动态生成
  },
  {
    id: 'perf_wu_enable', group: '性能调优', title: 'Windows 更新：恢复自动更新', risk: 'low',
    desc: '清除 Trim 自己写入的暂停键与 NoAutoUpdate 策略，让 Windows 恢复默认的自动检查与安装。只删 Trim 写过的键，不改动你没有让 Trim 动过的设置。',
    steps: [
      { label: '清除暂停键与 NoAutoUpdate 策略', pwsh: [
        '$base = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"',
        'if (Test-Path -LiteralPath $base) {',
        '  foreach ($n in @("PauseFeatureUpdatesStartTime","PauseFeatureUpdatesEndTime","PauseQualityUpdatesStartTime","PauseQualityUpdatesEndTime","PauseUpdatesStartTime","PauseUpdatesExpiryTime")) {',
        '    Remove-ItemProperty -Path $base -Name $n -Force -ErrorAction SilentlyContinue',
        '  }',
        '}',
        '$au = Join-Path $base "AU"',
        'if (Test-Path -LiteralPath $au) { Remove-ItemProperty -Path $au -Name "NoAutoUpdate" -Force -ErrorAction SilentlyContinue }'
      ].join('\n') }
    ]
  },
  {
    id: 'perf_notifications_off', group: '性能调优', title: '关闭 Windows 全局通知横幅', risk: 'medium',
    desc: 'ToastEnabled=0，减少通知横幅打断，降低操作干扰；可能错过安全、会议、聊天和系统提醒。',
    steps: [
      { label: 'Explorer ToastEnabled=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Explorer': {
          'ToastEnabled': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'perf_vbs_off', group: '性能调优', title: '关闭 VBS / 内存完整性', risk: 'high',
    desc: '关闭 VBS/HVCI 设备保护（EnableVirtualizationBasedSecurity=0、HypervisorEnforcedCodeIntegrity=0），会降低系统安全防护，仅适合定位安全隔离是否影响特定游戏或软件表现；需重启生效。',
    steps: [
      {
        label: '关闭 VBS/HVCI', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard': {
            'EnableVirtualizationBasedSecurity': 'dword:00000000'
          },
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity': {
            'Enabled': 'dword:00000000'
          }
        })
      }
    ]
  },
  {
    id: 'perf_remote_assist_off', group: '性能调优', title: '关闭远程协助', risk: 'low',
    desc: 'fAllowToGetHelp=0，禁用 Windows 远程协助的受邀协助入口，减少攻击面与后台监听；使用"请求远程协助"功能时需还原。',
    steps: [
      {
        label: 'fAllowToGetHelp=0', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance': { 'fAllowToGetHelp': 'dword:00000000' }
        })
      }
    ]
  },
  {
    id: 'perf_prefetcher_fast', group: '性能调优', title: '加快预读能力改善速度', risk: 'low',
    desc: 'EnablePrefetcher=3，同时启用应用与启动预读，改善程序启动与文件访问速度；SSD 上收益有限且 Prefetch 已被清理模块清理时可能短暂回退。',
    steps: [
      {
        label: 'EnablePrefetcher=3', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters': { 'EnablePrefetcher': 'dword:00000003' }
        })
      }
    ]
  },
  {
    id: 'perf_crash_autoreboot', group: '性能调优', title: '蓝屏时自动重启', risk: 'low',
    desc: 'AutoReboot=1，系统蓝屏后自动重启而非停留在选择界面，适合无人值守场景；排查蓝屏时建议临时关闭以读取完整停机码。',
    steps: [
      {
        label: 'AutoReboot=1', reg: regBlock({
          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl': { 'AutoReboot': 'dword:00000001' }
        })
      }
    ]
  },
  {
    id: 'perf_exploit_protection_off', group: '性能调优', title: '关闭 Exploit Protection（乱序内存）', risk: 'high',
    desc: '写入内核 MitigationOptions 二进制值（22,22,22,00,00,02,00,00,00,02,00,00,00,00,00,00，与 Trim「关闭Exploit Protection（乱序内存）」一致），关闭一系列漏洞利用缓解（含 SEHOP/强制 ASLR 等），可小幅提升部分应用的内存分配性能，但显著降低漏洞利用防护（高风险，需确认后执行）。',
    steps: [
      {
        label: 'MitigationOptions (Binary)', pwsh: [
          '$k = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel"',
          'New-ItemProperty -Path $k -Name MitigationOptions -Value ([byte[]](0x22,0x22,0x22,0x00,0x00,0x02,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null'
        ].join('\n') }
    ],
    restore: [
      {
        label: '删除 MitigationOptions（恢复系统默认缓解策略）', pwsh: [
          '$k = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel"',
          'Remove-ItemProperty -Path $k -Name MitigationOptions -ErrorAction SilentlyContinue'
        ].join('\n') }
    ]
  },
  // ---------- D 批 1（v0.4.9 RAINZ 对标 §3.5）：网络与更新策略 4 项 ----------
  // 4 项**全是纯 reg 步骤**，`restoreAvailable` 由 2116 那条 forEach 的推理机制自动置 true
  // （删除写入的键 = 恢复系统默认），不重复手写 restore 数组。
  // 全部避开 check-optimizer-security 的 (段路径, 键名, 写入值) 三元组：
  //   · DoDownloadMode=0 / EnableActiveProbing=0 / ShowCopilotButton=0 / SubscribedContent-*
  //     都不在 VALUE_RULES 的 nameRe 清单里，红判据不会误伤、也不给它们开后门。
  // group 分配按语义走（性能调优 / 桌面体验 / 隐私防护），不再要求文件位置与 group 一致。
  {
    id: 'wu_do_download_mode_off', group: '性能调优', title: '关闭 Windows 更新 P2P 分发', risk: 'low',
    desc: 'DeliveryOptimization 的 DoDownloadMode=0（HTTP only），Windows 更新与商店应用不再从局域网/互联网其他机器拉取分块。同网段多台机器一起更新时整体下载可能变慢；单机用户无损。',
    steps: [
      { label: 'DeliveryOptimization DoDownloadMode=0', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization': {
          'DoDownloadMode': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'net_no_active_probe', group: '性能调优', title: '关闭 NCSI 主动探测', risk: 'medium',
    desc: 'EnableActiveProbing=0，Windows 不再周期性访问 msftconnecttest.com 判断"是否有互联网"。副作用：任务栏网络图标失去"是否联网"的准确指示；酒店/机场 captive portal 不会自动弹出登录页。',
    steps: [
      { label: 'NlaSvc EnableActiveProbing=0', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet': {
          'EnableActiveProbing': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'sys_copilot_hide_button', group: '桌面体验', title: '隐藏任务栏 Copilot 按钮', risk: 'low',
    desc: 'HKCU Explorer\\Advanced 的 ShowCopilotButton=0，任务栏不再显示 Copilot 图标。仅影响视觉入口；Copilot 运行时与后台服务不由本项控制（对应项见 tf_ai_off）。',
    steps: [
      { label: 'ShowCopilotButton=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
          'ShowCopilotButton': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'sys_startmenu_ads_off', group: '隐私防护', title: '关闭开始菜单"建议"应用推广', risk: 'low',
    desc: 'ContentDeliveryManager 的 SubscribedContent-338388Enabled=0，开始菜单不再展示微软推荐的应用（俗称"开始菜单广告"）。',
    steps: [
      { label: 'SubscribedContent-338388Enabled=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager': {
          'SubscribedContent-338388Enabled': 'dword:00000000'
        }
      }) }
    ]
  },
  // ---------- D 批 2（v0.4.9 RAINZ 对标 §3.5）：隐私与遥测补齐 3 项 ----------
  // 三条 SubscribedContent-* 变体与上面的 338388 同段（HKCU ContentDeliveryManager），
  // 语义各不重叠：338389 = 开始菜单提示；310093 = 设置首页"为你推荐"；353694 = OneDrive 存储同步建议。
  // 全部纯 reg、low risk、由推理机制自动可还原。
  {
    id: 'sys_startmenu_tip_off', group: '隐私防护', title: '关闭开始菜单"提示"', risk: 'low',
    desc: 'ContentDeliveryManager 的 SubscribedContent-338389Enabled=0，开始菜单不再展示功能提示与新手引导卡片。',
    steps: [
      { label: 'SubscribedContent-338389Enabled=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager': {
          'SubscribedContent-338389Enabled': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'sys_settings_ads_off', group: '隐私防护', title: '关闭设置页"为你推荐"', risk: 'low',
    desc: 'ContentDeliveryManager 的 SubscribedContent-310093Enabled=0，Windows 设置首页不再展示"为你推荐"卡片（多为微软自家功能与服务推广）。',
    steps: [
      { label: 'SubscribedContent-310093Enabled=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager': {
          'SubscribedContent-310093Enabled': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'sys_filesync_ads_off', group: '隐私防护', title: '关闭 OneDrive 存储同步建议', risk: 'low',
    desc: 'ContentDeliveryManager 的 SubscribedContent-353694Enabled=0，Windows 不再弹「自动把新文档保存到 OneDrive」的建议。不改变 OneDrive 客户端自身行为，只关掉这个提示通道。',
    steps: [
      { label: 'SubscribedContent-353694Enabled=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager': {
          'SubscribedContent-353694Enabled': 'dword:00000000'
        }
      }) }
    ]
  },
  // ---------- D 批 4（v0.4.9 RAINZ 对标 §3.5）：桌面体验与视觉 4 项 ----------
  // 全部走 HKCU、纯 reg、可推理还原；scope 判据（check-optimizer-dynamic A6）：
  //   · MinAnimate / FontSmoothingType 落在 HKCU\Control Panel\Desktop → 不 match explorer regex → none
  //   · TaskbarAnimations / DisableThumbnailCache 落在 HKCU\...\Explorer\Advanced → explorer
  // 「none 档不进 optimizer-scope.json」是 A6 判据（表 ⇄ 重算必须完全相等）；
  // 只有 explorer / reboot 档才登记。
  {
    id: 'sys_minanimate_off', group: '桌面体验', title: '关闭窗口开合动画', risk: 'low',
    desc: 'HKCU Control Panel\\Desktop 的 MinAnimate=0，最小化/最大化窗口时不再播放缩放动画，视觉响应更"直接"。低配机与远程桌面上感知更明显。',
    steps: [
      { label: 'MinAnimate=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Desktop': {
          'MinAnimate': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'sys_taskbar_anim_off', group: '桌面体验', title: '关闭任务栏按钮动画', risk: 'low',
    desc: 'HKCU Explorer\\Advanced 的 TaskbarAnimations=0，任务栏按钮在窗口切换/最小化时不再播放滑动动画。属偏好设置。',
    steps: [
      { label: 'TaskbarAnimations=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
          'TaskbarAnimations': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'sys_thumb_cache_off', group: '桌面体验', title: '禁用缩略图缓存（thumbcache）', risk: 'low',
    desc: 'HKCU Explorer\\Advanced 的 DisableThumbnailCache=1，资源管理器不再把缩略图写入 thumbcache_*.db。隐私向：U 盘/多人共用机器上避免缩略图残留；代价是每次进同一目录要重算缩略图，SSD 上开销可忽略。',
    steps: [
      { label: 'DisableThumbnailCache=1', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': {
          'DisableThumbnailCache': 'dword:00000001'
        }
      }) }
    ]
  },
  {
    id: 'sys_font_smoothing_cleartype', group: '桌面体验', title: '字体平滑强制 ClearType', risk: 'low',
    desc: 'HKCU Control Panel\\Desktop 的 FontSmoothingType=2（ClearType）。默认已是 2；本项用于「被精简脚本或老系统改回 1（标准）后拉回来」。LCD 屏上文字更清晰，CRT/部分高 DPI 缩放场景可能反而劣化。',
    steps: [
      { label: 'FontSmoothingType=2 (ClearType)', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Desktop': {
          'FontSmoothingType': 'dword:00000002'
        }
      }) }
    ]
  },
  // ---------- D 批 收尾（v0.4.9 RAINZ 对标 §2/§3.5）：4 项补齐 ----------
  // 方案 §2 差集清单里"值得单独成项"且**不与既有语义重叠 + 键路径有把握**的剩余项：
  //   · AUOptions=2（Windows Update 通知下载和安装）—— 只在 NoAutoUpdate=0 时生效，
  //     与 perf_windows_update_off / perf_wu_pause 语义正交
  //   · NoAutoRebootWithLoggedOnUsers=1（更新装完后不强制重启）—— 与 NoAutoUpdate 无关，
  //     防的是"补丁装好 → 半夜自动重启"这类经典坑；不触发 check-optimizer-security
  //     的 wu-off 三元组（键名不是 NoAutoUpdate）
  //   · EnableTransparency=0（HKCU Themes Personalize 关系统级透明效果）—— 与 Trim 窗材质
  //     属性（`data-material="none"`，AGENTS §2 刻意设计）不同层，本项管 Windows 开始菜单/
  //     任务栏/窗口边框的透明；低配机与远程桌面上关闭能减少 DWM 合成开销
  //   · ShowHiddenDevices=1（设备管理器默认显示隐藏设备）—— 落 HKLM\SYSTEM\CurrentControlSet\
  //     Control\DeviceManager，触发 SCOPE_REBOOT_KEY 的 `HKLM\SYSTEM\CurrentControlSet\Control`
  //     → optimizer-scope.json 登记为 reboot
  // **明确不做**（AGENTS §9.3 纪律 ① + §3.5 落法 6，写清理由避免下次会话误补回来）：
  //   · TcpAckFrequency / TcpNoDelay / TcpSlowStartRestart：键路径在 Tcpip\Parameters\
  //     Interfaces\{网卡 GUID}，接口子键要枚举；方案 §3.5 表格里自己也标注"trim
  //     tf_net_nic 已下线的写侧邻域"，且 tf_net_tcp / tf_net_tcpip 已覆盖同类语义
  //   · DisableAIFeatures：与既有 tf_ai_off 高度重叠（后者策略级关 Copilot/Recall/
  //     Click to Do/AI Agent 全家桶，本项是其子集）
  //   · 蓝牙 EnhancedDiscovery / EnableAutoPairing：键路径本机现查证据不足（§9.3
  //     "不拿推断当实测"），需要真机 `reg query` 复核后再决定
  //   · UserPreferencesMask：REG_BINARY 位掩码，"关某个动画"要读写回整个 8 字节，
  //     会连累用户其他偏好；与 §3.5 落法 1「不走数量」的最小改动原则冲突
  {
    id: 'wu_au_options_notify', group: '性能调优', title: 'Windows 更新：改为通知下载和安装', risk: 'medium',
    desc: 'AUOptions=2，Windows Update 检测到新补丁后弹提示由用户决定何时下载与安装，不再自动跑完流程。仅在 NoAutoUpdate=0（自动更新开着）时生效；已开 perf_windows_update_off 的机器本项无实际作用。',
    steps: [
      { label: 'AU AUOptions=2 (通知下载和安装)', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU': {
          'AUOptions': 'dword:00000002'
        }
      }) }
    ]
  },
  {
    id: 'wu_no_auto_reboot', group: '性能调优', title: 'Windows 更新：登录时不强制重启', risk: 'low',
    desc: 'NoAutoRebootWithLoggedOnUsers=1，补丁安装完成后即使到了计划的重启时间，只要有用户登录就不会自动重启，避免"半夜补丁装完把机器重启、工作丢失"。不影响补丁本身下载安装。',
    steps: [
      { label: 'AU NoAutoRebootWithLoggedOnUsers=1', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU': {
          'NoAutoRebootWithLoggedOnUsers': 'dword:00000001'
        }
      }) }
    ]
  },
  {
    id: 'sys_transparency_off', group: '桌面体验', title: '关闭系统透明效果', risk: 'low',
    desc: 'HKCU Themes\\Personalize 的 EnableTransparency=0，开始菜单/任务栏/窗口边框不再叠加透明材质。低配机与远程桌面上能减少 DWM 合成开销；Win11 主题视觉会变"实"一些。与 Trim 窗材质设置（`data-material`）不同层，本项管的是 Windows 系统级透明。',
    steps: [
      { label: 'EnableTransparency=0', reg: regBlock({
        'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize': {
          'EnableTransparency': 'dword:00000000'
        }
      }) }
    ]
  },
  {
    id: 'devmgr_show_hidden_default', group: '系统调校', title: '设备管理器默认显示隐藏设备', risk: 'low',
    desc: 'HKLM DeviceManager 的 ShowHiddenDevices=1，打开设备管理器时默认展开"显示隐藏设备"（灰色显示未插着的旧驱动、断开的历史设备）。便于排查残留驱动，不改变任何硬件行为。',
    steps: [
      { label: 'DeviceManager ShowHiddenDevices=1', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceManager': {
          'ShowHiddenDevices': 'dword:00000001'
        }
      }) }
    ]
  },
  // ---------- D 批 3（v0.4.9 RAINZ 对标 §3.5）：服务改「手动」而非「禁用」4 项 ----------
  // 方案 §3.5 D 批 3 主题就是「可恢复停发」。AGENTS §5.12 二次扩宽允许本文件的 service
  // 模板新增 startType 枚举分支；对应 Rust 侧解释器在 `engine/pssteps.rs` 里加 Set-Service
  // match 分支，走 PsOp::SvcSetStart → service_set_start_pub（原生 Windows API）。
  // 语义硬约束：改 Manual **不立即 Stop-Service**，当前运行不受影响、下次开机不再自动启动；
  // 还原走 Set-StartupType Automatic，也不 Start-Service（下次开机自动起）。
  // 4 项默认启动类型均为 Automatic（本机 `sc qc` 可读），改动可回退；不选 WebClient/msiserver
  // 是因为它们默认已是 Manual，「改 Manual」对它们是 no-op、不登记（AGENTS §3.5 落法 6：
  // 人工确认不与既有语义重叠 —— 与"当前启动类型已是目标"的 no-op 项同理，不收）。
  {
    id: 'svc_w32time_manual', group: '系统服务', title: 'Windows Time 改手动启动', risk: 'low',
    desc: 'W32Time 启动类型从 Automatic 改为 Manual，下次开机不再常驻。当前运行不受影响；AD 域环境 / 双系统时间冲突场景请谨慎，或改用「时间同步故障排查」类专项。',
    steps: [
      { label: 'W32Time → Manual（不立即停止）', service: 'W32Time', startType: 'manual' }
    ],
    restore: [
      { label: '还原：W32Time 改回 Automatic', service: 'W32Time', startType: 'automatic' }
    ]
  },
  {
    id: 'svc_fdrespum_manual', group: '系统服务', title: 'Function Discovery Resource Publication 改手动启动', risk: 'low',
    desc: 'FDResPub 启动类型改 Manual，下次开机不再常驻；这台机器在局域网中的"可发现性"会下降（其他设备不再自动看到本机的共享资源）。当前运行不受影响。',
    steps: [
      { label: 'FDResPub → Manual（不立即停止）', service: 'FDResPub', startType: 'manual' }
    ],
    restore: [
      { label: '还原：FDResPub 改回 Automatic', service: 'FDResPub', startType: 'automatic' }
    ]
  },
  {
    id: 'svc_storsvc_manual', group: '系统服务', title: 'Storage Service 改手动启动', risk: 'low',
    desc: 'StorSvc 启动类型改 Manual，下次开机不再常驻。不用 Windows 存储空间（Storage Spaces）与便携设备镜像的机器无影响；用了的请先手动启动再操作。当前运行不受影响。',
    steps: [
      { label: 'StorSvc → Manual（不立即停止）', service: 'StorSvc', startType: 'manual' }
    ],
    restore: [
      { label: '还原：StorSvc 改回 Automatic', service: 'StorSvc', startType: 'automatic' }
    ]
  },
  {
    id: 'svc_xblauthmgr_manual', group: '系统服务', title: 'Xbox Live Auth Manager 改手动启动', risk: 'low',
    desc: 'XblAuthManager 启动类型改 Manual，下次开机不再常驻。不用 Xbox App / Xbox Game Pass / Microsoft Store 游戏登录的机器无损；用到时首次启动会多一次登录。当前运行不受影响。',
    steps: [
      { label: 'XblAuthManager → Manual（不立即停止）', service: 'XblAuthManager', startType: 'manual' }
    ],
    restore: [
      { label: '还原：XblAuthManager 改回 Automatic', service: 'XblAuthManager', startType: 'automatic' }
    ]
  },
  // ---------- 浏览器优化（EDGE 专优拆分为 16 个独立项） ----------
  edgePolicyItem('edge_hide_firstrun', '禁用首次运行体验', 'low', 'HideFirstRunExperience', 'dword:00000001',
    '不显示 Edge 首次运行欢迎页与数据导入向导，新装或新配置文件直接可用。'),
  edgePolicyItem('edge_bg_mode_off', '禁用关闭后后台运行', 'low', 'BackgroundModeEnabled', 'dword:00000000',
    'Edge 关闭所有窗口后不再驻留后台运行扩展与进程，释放内存与后台占用。'),
  edgePolicyItem('edge_startup_boost_off', '禁用启动增强', 'low', 'StartupBoostEnabled', 'dword:00000000',
    '关闭系统启动时后台预加载 Edge 的"启动增强"，开机进程更少、速度更纯粹。'),
  edgePolicyItem('edge_intrusive_ads_off', '阻止侵入式广告', 'medium', 'AdsSettingForIntrusiveAdsSites', 'dword:00000002',
    '在所有网站上阻止侵入式广告，减少恶意弹窗与误导下载按钮的干扰。'),
  edgePolicyItem('edge_ntp_quicklinks_off', '隐藏新标签页快速链接', 'low', 'NewTabPageQuickLinksEnabled', 'dword:00000000',
    '从新标签页隐藏默认的热门站点快速链接，页面更干净。'),
  edgePolicyItem('edge_sidebar_off', '禁用 Edge 边栏', 'low', 'HubsSidebarEnabled', 'dword:00000000',
    '隐藏浏览器右侧边栏（Copilot、发现、搜索入口），减少误触与视觉干扰。'),
  edgePolicyItem('edge_unsupported_os_warn_off', '禁用旧系统通知警告', 'low', 'SuppressUnsupportedOSWarning', 'dword:00000001',
    '关闭"此版本的 Windows 即将停止支持"的 Edge 通知横幅。'),
  edgePolicyItem('edge_metrics_off', '禁用诊断数据上报', 'medium', 'MetricsReportingEnabled', 'dword:00000000',
    '不向微软发送任何浏览器诊断数据，收敛浏览器侧的隐私外发通道。'),
  edgePolicyItem('edge_tab_perf_detector_off', '禁用标签页性能检测器', 'low', 'TabPerformanceDetectorEnabled', 'dword:00000000',
    '关闭标签页性能问题检测，不再弹出"此页面正在拖慢浏览器"提示。'),
  edgePolicyItem('edge_ntp_content_off', '禁用新标签页资讯内容', 'low', 'NewTabPageContentEnabled', 'dword:00000000',
    '新标签页不再展示微软资讯信息流，仅保留搜索框与常用项。'),
  edgePolicyItem('edge_personalization_off', '禁用个性化广告报告', 'medium', 'PersonalizationReportingEnabled', 'dword:00000000',
    '不向微软发送浏览历史用于个性化广告、新闻与体验推荐。'),
  edgePolicyItem('edge_insecure_download_warn_off', '禁用不安全下载警告', 'medium', 'InsecureContentWarningForDownloadsEnabled', 'dword:00000000',
    '关闭对不安全（HTTP）下载的警告拦截，仅建议明确了解风险的熟练用户使用。'),
  edgePolicyItem('edge_rewards_hide', '隐藏 Microsoft Rewards', 'low', 'ShowMicrosoftRewards', 'dword:00000000',
    '隐藏 Edge 中的 Microsoft Rewards 积分入口与提醒。'),
  {
    id: 'edge_sxs_service_off', group: '浏览器优化', title: '禁用 SxsService 服务', risk: 'medium',
    desc: '关闭 EdgeUpdate 客户端组件 SxsService（Edge 并行版本相关服务），减少后台组件活动；不影响浏览器本体与常规更新。',
    steps: [{ label: 'EdgeUpdate ClientState SxsService=0', reg: regBlock({
      'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EdgeUpdate\\ClientState': { 'SxsService': 'dword:00000000' }
    }) }],
    restore: [{ label: '还原：删除 SxsService 键值（恢复默认状态）', reg: regBlock({
      'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EdgeUpdate\\ClientState': { 'SxsService': '-' }
    }) }]
  },
  {
    id: 'edge_update_task_disable', group: '浏览器优化', title: '停用 Edge Update 计划任务', risk: 'medium',
    desc: '停用 MicrosoftEdgeUpdateTaskMachineCore 计划任务，停止 Edge 的自动更新检查；停用后请定期手动更新浏览器以获取安全补丁。',
    steps: [{ label: '停用 Edge Update Machine Core', pwsh: 'Get-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue' }],
    restore: [{ label: '重新启用 Edge Update Machine Core', pwsh: 'Get-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore" -ErrorAction SilentlyContinue | Enable-ScheduledTask -ErrorAction SilentlyContinue' }]
  },
  // D 批 2（v0.4.9 RAINZ 对标 §3.5）：禁用 Edge 地址栏 Copilot 搜索集成
  // Edge 官方策略键 DisableCopilotSearchIntegration；已装 Edge 若未支持该策略则无效果（不谎报）。
  edgePolicyItem('edge_copilot_search_off', '禁用 Edge 搜索页 Copilot 集成', 'low', 'DisableCopilotSearchIntegration', 'dword:00000001',
    'Edge 地址栏搜索结果页不再自动接入 Copilot 侧栏回答。仅影响 Edge；不改变 Copilot 应用与系统级 Copilot（那由 tf_ai_off / sys_copilot_hide_button 覆盖）。'),
  // 第六大点-B（2026-09-14 重复点审查）：原「禁用 Edge 游戏助手覆盖层」
  // (edge_game_assistant_overlay_off) 已下线 —— 它的唯一动作就是写 HubsSidebarEnabled=0，
  // 与「禁用 Edge 边栏」(edge_sidebar_off) 完全相同（Edge 并未提供独立的游戏助手策略键），
  // 属纯重复项。需要该效果时直接用「禁用 Edge 边栏」。

  // ==================== 优化总表补全（对照 old\优化总表.md 差异评估采纳项） ====================

  // Windows AI 全组（总表 81-89，9 项）
  {
    id: 'tf_ai_off', group: '性能调优', title: '关闭 Windows AI 组件', risk: 'low',
    desc: '按策略关闭 Windows AI 全家桶：Copilot（组策略+任务栏按钮+键盘键）、Recall 数据分析与快照（DisableAIDataAnalysis）、Click to Do、AI Agent 连接器/远程连接器/工作区、AI 设置代理（AgentRuntime 服务）。全部可一键还原。',
    steps: [
      { label: 'AI 策略键（Copilot/Recall/ClickToDo/Agent）', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\WindowsCopilot': { 'TurnOffWindowsCopilot': 'dword:00000001' },
        'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\WindowsAI': {
          'DisableAIDataAnalysis': 'dword:00000001',
          'DisableClickToDo': 'dword:00000001',
          'DisableAgentConnectors': 'dword:00000001',
          'DisableRemoteAgentConnectors': 'dword:00000001',
          'DisableAgentWorkspaces': 'dword:00000001',
          'DisableSettingsAgents': 'dword:00000001'
        },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI': {
          'DisableAIDataAnalysis': 'dword:00000001',
          'DisableClickToDo': 'dword:00000001'
        },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': { 'ShowCopilotButton': 'dword:00000000' }
      }) },
      { label: '停止 AI 运行时服务（AgentRuntime）', pwsh: [
        'foreach ($n in @("AgentRuntimeService","AgentActivationRuntimeService")) { Stop-Service -Name $n -Force -ErrorAction SilentlyContinue; sc.exe config $n start= disabled 2>$null | Out-Null }'
      ].join('\n') }
    ],
    restore: [
      { label: '还原：删除 AI 策略键', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\WindowsCopilot': { 'TurnOffWindowsCopilot': '-' },
        'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\WindowsAI': {
          'DisableAIDataAnalysis': '-', 'DisableClickToDo': '-', 'DisableAgentConnectors': '-',
          'DisableRemoteAgentConnectors': '-', 'DisableAgentWorkspaces': '-', 'DisableSettingsAgents': '-'
        },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI': { 'DisableAIDataAnalysis': '-', 'DisableClickToDo': '-' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': { 'ShowCopilotButton': '-' }
      }) },
      { label: '还原：AI 运行时服务恢复手动启动', pwsh: [
        'foreach ($n in @("AgentRuntimeService","AgentActivationRuntimeService")) { $p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 3 -PropertyType DWord -Force | Out-Null } }'
      ].join('\n') }
    ]
  },

  // 系统响应杂项（总表 34/38/41/42，4 项）
  {
    // N4（2026-09-30）：原「提高前台程序显示速度」「加快关机速度」「缩短服务关闭等待时间」三项
    // 与合集目标同类（都是 HKCU/HKLM 的响应与关机等待微调），单项摆出来既占版面又与合集重复，
    // 故整并进本项；退役登记见 data/retired-optimizations.json。
    id: 'tf_perf_misc', group: '性能调优', title: '系统响应微调合集', risk: 'low',
    desc: '开机启动延迟归零（StartupDelayInMSec=0）、禁用窗口摇晃（拖动标题栏摇晃不再最小化其它窗口）、禁用失效快捷方式链接解析（不再全盘/联网查找目标）、关闭运行对话框与资源管理器自动建议、前台程序立即获得焦点（ForegroundLockTimeout=0）、关机等待应用与服务退出的超时各缩到 2000 毫秒（WaitToKillAppTimeout / WaitToKillServiceTimeout）。',
    steps: [
      { label: '启动延迟归零 + 禁用窗口摇晃 + 禁用链接解析', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Serialize': { 'StartupDelayInMSec': 'dword:00000000' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': { 'DisallowShaking': 'dword:00000001' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer': { 'DisableSearchLinkTracking': 'dword:00000001' }
      }) },
      { label: '关闭自动建议（AutoSuggest）', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoComplete': { 'AutoSuggest': '"NO"' }
      }) },
      { label: 'ForegroundLockTimeout=0', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Desktop': { 'ForegroundLockTimeout': 'dword:00000000' }
      }) },
      { label: 'WaitToKillAppTimeout=2000', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Desktop': { 'WaitToKillAppTimeout': '"2000"' }
      }) },
      { label: 'WaitToKillServiceTimeout=2000', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control': { 'WaitToKillServiceTimeout': '"2000"' }
      }) }
    ],
    restore: [
      { label: '还原：删除对应键值（恢复默认行为）', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Serialize': { 'StartupDelayInMSec': '-' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': { 'DisallowShaking': '-' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer': { 'DisableSearchLinkTracking': '-' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoComplete': { 'AutoSuggest': '"YES"' }
      }) },
      { label: '还原：删除前台焦点与关机等待键值（恢复系统默认）', reg: regBlock({
        'HKEY_CURRENT_USER\\Control Panel\\Desktop': { 'ForegroundLockTimeout': '-', 'WaitToKillAppTimeout': '-' },
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control': { 'WaitToKillServiceTimeout': '-' }
      }) }
    ]
  },

  // 隐私补漏（总表 56/57/65/72/74/102，6 项 + AITEnable）
  {
    id: 'tf_privacy_extra', group: '隐私防护', title: '第三方遥测与许可遥测关闭', risk: 'low',
    desc: 'Chrome 指标上报与反馈收集（企业策略）、Firefox 遥测与默认浏览器代理（企业策略）、Visual Studio 各版本 SQM 遥测、Windows 许可遥测（NoGenTicket）、任务栏新闻和兴趣信息流、步骤记录器（DisableUAR）、应用兼容性遥测（AITEnable）。',
    steps: [
      { label: 'Chrome / Firefox 企业策略遥测关闭', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome': { 'MetricsReportingEnabled': 'dword:00000000', 'FeedbackSurveysEnabled': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Mozilla\\Firefox': { 'DisableTelemetry': 'dword:00000001', 'DefaultBrowserSettingEnabled': 'dword:00000000' }
      }) },
      { label: 'Visual Studio SQM / 许可遥测 / 新闻兴趣 / 步骤记录器', reg: regBlock({
        'HKEY_CURRENT_USER\\Software\\Microsoft\\VSCommon\\15.0\\SQM': { 'OptIn': 'dword:00000000' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\VSCommon\\16.0\\SQM': { 'OptIn': 'dword:00000000' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\VSCommon\\17.0\\SQM': { 'OptIn': 'dword:00000000' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform': { 'NoGenTicket': 'dword:00000001' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Feeds': { 'EnableFeeds': 'dword:00000000' },
        'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Steps Recorder': { 'DisableUAR': 'dword:00000001' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat': { 'AITEnable': 'dword:00000000' }
      }) }
    ],
    restore: [
      { label: '还原：删除对应策略键值', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome': { 'MetricsReportingEnabled': '-', 'FeedbackSurveysEnabled': '-' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Mozilla\\Firefox': { 'DisableTelemetry': '-', 'DefaultBrowserSettingEnabled': '-' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\VSCommon\\15.0\\SQM': { 'OptIn': '-' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\VSCommon\\16.0\\SQM': { 'OptIn': '-' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\VSCommon\\17.0\\SQM': { 'OptIn': '-' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform': { 'NoGenTicket': '-' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Feeds': { 'EnableFeeds': '-' },
        'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Steps Recorder': { 'DisableUAR': '-' },
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat': { 'AITEnable': '-' }
      }) }
    ]
  },

  // 服务精简补漏（总表 90/92/93/94/95，5 项）
  // v3.0：UCPD 已从此项剔除——该驱动是系统对默认应用选择的防篡改保护层，
  // 不随服务批量优化项被永久禁用。
  // v3.7.0：「默认应用接管」功能已整体移除，Trim 不再提供任何禁用该驱动的入口；
  // 该裁定本身不变（批量服务优化项仍不得禁用 UCPD），故此处只改指向文案，行为不动。
  {
    id: 'tf_svc_extra5', group: '系统服务', title: '传感器与存储感知等服务精简', risk: 'medium',
    desc: '禁用传感器服务（SensrSvc/SensorDataService）、存储感知（StorSvc，改用手动清理更可控）、应用兼容性助手（PcaSvc）、性能改进建议（WDI 诊断场景）。打印机/扫码仪等外设依赖传感器服务时请勿禁用。UCPD 用户选择保护驱动属系统防篡改保护层，本产品不禁用。',
    steps: [
      { label: '禁用传感器 / 存储感知 / PCA 服务', pwsh: [
        'foreach ($n in @("SensrSvc","SensorDataService","StorSvc","PcaSvc")) { Stop-Service -Name $n -Force -ErrorAction SilentlyContinue; sc.exe config $n start= disabled 2>$null | Out-Null }'
      ].join('\n') },
      { label: '关闭性能改进建议（WDI 场景）', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WDI': { 'ScenarioExecutionEnabled': 'dword:00000000' }
      }) }
    ],
    restore: [
      { label: '还原：服务恢复手动/自动启动', pwsh: [
        '$map = @{ SensrSvc = 3; SensorDataService = 3; StorSvc = 2; PcaSvc = 2 }; foreach ($n in $map.Keys) { $p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value $map[$n] -PropertyType DWord -Force | Out-Null } }'
      ].join('\n') },
      { label: '还原：删除 WDI 策略键值', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WDI': { 'ScenarioExecutionEnabled': '-' }
      }) }
    ]
  },

  // 应用与界面：复制/移动上下文菜单（总表 114；116 搜索 WebView2 已由 tf_cortana 覆盖）
  {
    id: 'tf_ctx_copymove', group: '桌面体验', title: '右键菜单添加复制/移动到文件夹', risk: 'low',
    desc: '为所有文件与文件夹的右键菜单添加「复制到文件夹…」与「移动到文件夹…」经典对话框入口，无需剪切粘贴即可搬运文件；还原即移除菜单项。',
    steps: [
      { label: '注册 CopyTo / MoveTo 上下文菜单处理器', reg: regBlock({
        'HKEY_CLASSES_ROOT\\AllFilesystemObjects\\shellex\\ContextMenuHandlers\\CopyTo': { '@': '"{f3d06e7c-1e45-4a26-847e-f9fcdee59be0}"' },
        'HKEY_CLASSES_ROOT\\AllFilesystemObjects\\shellex\\ContextMenuHandlers\\MoveTo': { '@': '"{c2fbb631-2971-11d1-a18c-00c04fd75d13}"' }
      }) }
    ],
    restore: [
      { label: '还原：移除 CopyTo / MoveTo 菜单项', reg: regBlock({
        'HKEY_CLASSES_ROOT\\AllFilesystemObjects\\shellex\\ContextMenuHandlers\\CopyTo': { '@': '-' },
        'HKEY_CLASSES_ROOT\\AllFilesystemObjects\\shellex\\ContextMenuHandlers\\MoveTo': { '@': '-' }
      }) }
    ]
  },

  // 磁盘与文件系统补漏（总表 108/109/110，3 项）
  {
    // M6（2026-09-14 重复点审查）：全项目有三处 DISM 入口，标题统一带「DISM + 具体参数」
    // 以便用户区分——本项为 /Set-ReservedStorageState（释放保留存储），
    // 系统维护 dism 为 /RestoreHealth（修复），磁盘清理 dismComponentCleanup 为 /ResetBase（清理）。
    id: 'tf_disk_extra3', group: '系统调校', title: 'NTFS 加密与保留存储精简 (DISM /Set-ReservedStorageState)', risk: 'low',
    desc: '禁用 NTFS 文件系统级加密（NtfsDisableEncryption，不影响 BitLocker/BitLocker To Go）、开始菜单搜索仅限索引位置（Start_SearchFiles=0，减少全盘扫描）、禁用更新保留存储（DISM 释放约 7 GB 保留空间）。',
    steps: [
      { label: '禁用 NTFS 加密 + 搜索仅限索引位置', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\FileSystem': { 'NtfsDisableEncryption': 'dword:00000001' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': { 'Start_SearchFiles': 'dword:00000000' }
      }) },
      { label: '禁用更新保留存储（DISM）', cmd: 'DISM /Online /Set-ReservedStorageState /State:Disabled /Quiet' }
    ],
    restore: [
      { label: '还原：恢复 NTFS 加密与搜索范围', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\FileSystem': { 'NtfsDisableEncryption': 'dword:00000000' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced': { 'Start_SearchFiles': 'dword:00000002' }
      }) },
      { label: '还原：重新启用更新保留存储', cmd: 'DISM /Online /Set-ReservedStorageState /State:Enabled /Quiet' }
    ]
  },

  // 应用与界面（总表 117，商店自动更新与推广内容）
  {
    id: 'tf_store_autoupdate', group: '桌面体验', title: '禁用商店自动更新与推广内容', risk: 'medium',
    desc: '关闭 Microsoft Store 应用自动下载更新（AutoDownloadSetting=2），并关闭「消费者特性」推荐与推广弹窗（ContentDeliveryAllowed、SilentInstalledAppsEnabled 等）；应用更新需手动打开商店检查。',
    steps: [
      { label: '商店自动更新关闭 + 推广内容屏蔽', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore': { 'AutoDownloadSetting': 'dword:00000002' },
        // 第六大点-B（2026-09-14）：SubscribedContent-310093 / -338388 与 SystemPaneSuggestionsEnabled
        // 归「云推荐内容排查」(privacy_cloud_content)，本项只负责商店自动更新与预装/推广应用开关。
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager': {
          'ContentDeliveryAllowed': 'dword:00000000',
          'OemPreInstalledAppsEnabled': 'dword:00000000',
          'PreInstalledAppsEnabled': 'dword:00000000',
          'SilentInstalledAppsEnabled': 'dword:00000000'
        }
      }) }
    ],
    restore: [
      { label: '还原：恢复商店自动更新与默认推荐', reg: regBlock({
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore': { 'AutoDownloadSetting': '-' },
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager': {
          'ContentDeliveryAllowed': '-',
          'OemPreInstalledAppsEnabled': '-',
          'PreInstalledAppsEnabled': '-',
          'SilentInstalledAppsEnabled': '-'
        }
      }) }
    ]
  }
];

// ==================== 内存 SVCHost 拆分阈值 ====================
function memorySteps(gb) {
  const known = MEMORY_KB[gb] != null;
  const kb = known ? MEMORY_KB[gb] : MEMORY_KB[8];
  // 复核 OPT-4（2026-09-16）：异常 gb 不再直接拼进文案（原样显示垃圾 label），
  // 按查表/回退后的真实阈值命名；default 语义保留。
  const gbName = (gb === 'default') ? '重置为默认值' : (known ? (gb + 'GB') : ('8GB（请求值异常，已回退到 8GB 阈值）'));
  return [{
    label: `SVCHost 拆分阈值 ${gbName}`,
    cmd: `reg add "HKLM\\SYSTEM\\ControlSet001\\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d ${kb} /f`
  }];
}

// ==================== v3.7.0：Windows Update 暂停到日期（动态步骤） ====================
// 渲染层只传天数档位（1~35），FILETIME 全部在 PowerShell 内生成——
// 不接受渲染层拼好的注册表值，避免 64 位整数在 JS 侧精度丢失或格式错误。
// 键位与 Windows 官方一致：功能更新与质量更新各有起止，另有过期的 PauseUpdates*。
const WU_PAUSE_KEYS = [
  'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime',
  'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime',
  'PauseUpdatesStartTime', 'PauseUpdatesExpiryTime'
];
const WU_PAUSE_MAX_DAYS = 35;
function windowsUpdatePauseSteps(days) {
  const n = Number(days);
  const d = Number.isFinite(n) ? Math.min(Math.max(Math.trunc(n), 1), WU_PAUSE_MAX_DAYS) : 7;
  return [{
    label: `暂停 Windows 更新 ${d} 天`,
    pwsh: [
      `$days = ${d}`,
      '$base = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"',
      'New-Item -Path $base -Force -ErrorAction SilentlyContinue | Out-Null',
      // FILETIME = 自 1601-01-01 起的 100ns 计数，写入 REG_QWORD
      '$ft = [DateTime]::UtcNow.AddDays($days).ToFileTimeUtc()',
      '$nowFt = [DateTime]::UtcNow.ToFileTimeUtc()',
      'foreach ($n in @("PauseFeatureUpdatesStartTime","PauseQualityUpdatesStartTime","PauseUpdatesStartTime")) { New-ItemProperty -Path $base -Name $n -Value $nowFt -PropertyType QWord -Force | Out-Null }',
      'foreach ($n in @("PauseFeatureUpdatesEndTime","PauseQualityUpdatesEndTime","PauseUpdatesExpiryTime")) { New-ItemProperty -Path $base -Name $n -Value $ft -PropertyType QWord -Force | Out-Null }'
    ].join('\n')
  }];
}

// ==================== tf_svc_bulk 商店服务附加分支 ====================
// 用户在执行前经单独弹窗选择「是否禁用商店相关服务」：
//   是 → main.js 用本函数在基础清单后追加商店 5 服务步骤（基础步骤在前把 wuauserv
//        置 Start=3，本步骤在后覆盖为 4，顺序即语义）；
//   否 → 原样执行基础清单（商店/同步保持默认，既有行为不变）。
// 覆盖面为用户裁定（2026-09-14）：商店本体 + 更新下载通道。
const STORE_TOGGLE_SERVICES = ['ClipSVC', 'InstallService', 'PushToInstall', 'wuauserv', 'DoSvc'];
function svcBulkAppendStoreSteps(baseSteps) {
  const steps = Array.isArray(baseSteps) ? JSON.parse(JSON.stringify(baseSteps)) : [];
  steps.push({
    label: '禁用商店相关服务（ClipSVC/InstallService/PushToInstall/wuauserv/DoSvc，经用户弹窗确认）',
    pwsh: [
      `$storeSvc = @("${STORE_TOGGLE_SERVICES.join('","')}")`,
      'foreach ($n in $storeSvc) { $p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 4 -PropertyType DWord -Force | Out-Null; Stop-Service -Name $n -Force -ErrorAction SilentlyContinue } }'
    ].join('\n')
  });
  return steps;
}

// ==================== 脚本生成器 ====================
function buildScript(steps) {
  const total = steps.length;
  const L = [];
  L.push("$ErrorActionPreference = 'SilentlyContinue'");
  L.push("$ProgressPreference = 'SilentlyContinue'");
  L.push('$failedSteps = 0');
  L.push(DIAG.PS_PREAMBLE.trim());
  steps.forEach((s, i) => {
    const pct = Math.round(((i + 1) / total) * 100);
    const label = (s.label || '第 ' + (i + 1) + ' 步').replace(/\r?\n/g, ' ');
    const labelPs = psQuoteForScript(label);
    L.push(`# step ${i + 1}: ${label}`);
    if (s.reg) {
      // 复核 N2（优化中心，2026-09-16）：reg 临时文件原写 $env:TEMP，未走 A1 加固目录；
      // 与 MA-1 同款改法——优先取 runPwshChild 注入的 TRIM_TMP（%APPDATA%\Trim\tmp，0o600），
      // 兜底自建应用私有目录，不再落全局 %TEMP%。
      L.push('$___tmpDir = if ($env:TRIM_TMP) { $env:TRIM_TMP } else { Join-Path $env:APPDATA "Trim\\tmp" }');
      L.push('if (-not (Test-Path -LiteralPath $___tmpDir)) { New-Item -ItemType Directory -Path $___tmpDir -Force | Out-Null }');
      L.push('$___rf = Join-Path $___tmpDir ("wcopt_" + [guid]::NewGuid().ToString("N") + ".reg")');
      L.push("$___rc = @'");
      L.push(s.reg);
      L.push("'@");
      // OPT-3（2026-09-15）：ASCII 编码会把注册表中非 ASCII（中文路径/名称/locale 值）写坏，
      // 而 reg.exe import 本就约定 UTF-16 LE(.reg 官方编码，带 BOM)。改 Unicode 保真。
      L.push('Set-Content -Path $___rf -Value $___rc -Encoding Unicode');
      L.push('& reg.exe import $___rf *> $null');
      L.push(`if ($LASTEXITCODE -ne 0) { $failedSteps++; Write-TFDiag -Stage 'optimizer.reg' -Mutation 'rolled_back' -Detail ('step ' + (${i} + 1) + ' [' + ${labelPs} + '] reg import exit=' + $LASTEXITCODE) }`);
      L.push('Remove-Item $___rf -Force -ErrorAction SilentlyContinue');
    } else if (s.cmd) {
      const safe = s.cmd.replace(/'/g, "''");
      L.push(`$___cmd='${safe}'`);
      L.push('& $env:ComSpec /c $___cmd *> $null');
      L.push(`if ($LASTEXITCODE -ne 0) { $failedSteps++; Write-TFDiag -Stage 'optimizer.cmd' -Mutation 'partial' -Detail ('step ' + (${i} + 1) + ' [' + ${labelPs} + '] exit=' + $LASTEXITCODE) }`);
    } else if (s.service) {
      // OPT-2（2026-09-15）：s.service 统一走 psQuoteForScript 生成单引号字面量，
      // 杜绝服务名含单引号时脱出引号拼接（当前内置常量无该字符，属前置加固）。
      const svcPs = psQuoteForScript(s.service);
      // v0.4.9 D 批 3（RAINZ 对标 §3.5，AGENTS §5.12 二次扩宽允许本模板加枚举分支）：
      // 新增 `startType: 'manual' | 'automatic' | 'disabled'`，走 Set-Service -StartupType。
      // 语义分工：manual / automatic **不 Stop-Service**（只改下次开机行为，当前运行不受影响），
      // disabled 与既有 `{ disable: true }` 等价（Stop + Set Disabled）。
      // **向后兼容硬约束**：未带 startType 字段的既有项走 else 分支，生成字节与旧版逐字节一致
      // （sync-ps-from-js --check 哨兵 steps 全部落在这条 else 上）。
      const st = s.startType;
      const wantsStartType = st === 'manual' || st === 'automatic' || st === 'disabled';
      if (wantsStartType) {
        if (st === 'disabled') {
          L.push(`Stop-Service -Name ${svcPs} -Force -ErrorAction SilentlyContinue`);
        }
        const stCap = st === 'manual' ? 'Manual' : st === 'automatic' ? 'Automatic' : 'Disabled';
        L.push(`Set-Service -Name ${svcPs} -StartupType ${stCap} -ErrorAction SilentlyContinue`);
      } else {
        L.push(`Stop-Service -Name ${svcPs} -Force -ErrorAction SilentlyContinue`);
        if (s.disable) L.push(`Set-Service -Name ${svcPs} -StartupType Disabled -ErrorAction SilentlyContinue`);
      }
      L.push(`if (-not (Get-Service -Name ${svcPs} -ErrorAction SilentlyContinue)) { $failedSteps++; Write-TFDiag -Stage 'optimizer.service' -Mutation 'rolled_back' -Detail ('step ' + (${i} + 1) + ' [' + ${labelPs} + '] 服务不存在: ' + ${svcPs}) }`);
    } else if (s.pwsh) {
      // SR-1（2026-09-15）：此前 pwsh 步骤原样裸拼、成败无人记账；又因 PS_PREAMBLE 的
      // `trap { continue }` 会把 -ErrorAction Stop 的终止性错误吞掉（脚本退出码仍为 0），
      // 导致 create-restore 恒报成功、还原点门禁被架空。改为逐步骤 try/catch + 强制 Stop
      // （try/catch 优先于 trap，可正常捕获）→ 异常即 $failedSteps++ 并留诊断。
      L.push('$___eap = $ErrorActionPreference');
      L.push('try {');
      L.push("  $ErrorActionPreference = 'Stop'");
      L.push(s.pwsh);
      L.push('} catch {');
      L.push(`  $failedSteps++; Write-TFDiag -Stage 'optimizer.pwsh' -Mutation 'failed' -Detail ('step ' + (${i} + 1) + ' [' + ${labelPs} + '] ' + $_.Exception.Message)`);
      L.push('} finally {');
      L.push('  $ErrorActionPreference = $___eap');
      L.push('}');
    }
    L.push(`Write-Output "@@PROGRESS:${pct}@@"`);
  });
  L.push('Write-Output ("@@FAILED:" + $failedSteps + "@@")');
  L.push('Write-Output "@@DONE@@"');
  return L.join('\n');
}

// ==================== 各优化项优点 / 缺点（简洁短句，供展开详情展示） ====================
const PROS_CONS = {
  'net_response': { pros: '关闭网络节流与多媒体系统响应降级，网络吞吐更稳、系统反馈更快。', cons: '改动多媒体系统响应性可能略增后台调度与功耗，个别在线视频场景表现略有变化。' },
  'tf_net_reset': { pros: '一次性重置 IP/TCP/Winsock/防火墙等 11 项网络栈，能修复多数异常网络与延迟问题。', cons: '会清空自定义防火墙规则并断开现有连接，可能需要重连网络与重配软件。' },
  'tf_net_tcp': { pros: '调整 TCP 窗口与延迟确认等参数，提升高延迟或高吞吐场景下的传输效率。', cons: '非标准参数在个别运营商或网络环境下可能引起不稳定或兼容性问题。' },
  'tf_net_tcpip': { pros: '写入更适合低延迟的 Tcpip 注册表参数，减少小包传输的额外等待。', cons: '参数与系统默认不同，极端网络条件下可能影响连接稳定性。' },
  'tf_net_lanman': { pros: '优化 SMB 会话相关参数，局域网文件共享与访问响应更快。', cons: '改动 LanmanServer 参数在共享服务高负载时可能影响兼容性。' },
  'tf_net_nic': { pros: '批量关闭网卡节能并开启低延迟相关属性，降低网络唤醒与传输抖动。', cons: '关闭节能会让网卡功耗略升，老旧网卡可能不支持部分高级属性。' },
  'tf_net_weakhost': { pros: '开启 WeakHost 收发可改善多网卡下的本地访问与回流场景。', cons: '轻微降低网络隔离安全性，仅建议在明确需要时启用。' },
  'tf_microcode_del': { pros: '删除 CPU 微码更新 DLL，减少启动与运行时的一处校验开销。', cons: '移除微码补丁会重新暴露已知 CPU 漏洞与稳定性修复，安全风险较大。' },
  'tf_ntfs': { pros: '关闭 8.3 短名与末次访问时间戳、增大内存使用，可提升文件系统吞吐。', cons: '8.3 名称关闭会让个别老软件找不到文件，NTFS 改动一般不可逆。' },
  'tf_hibern_off': { pros: '彻底关闭休眠与快速启动，可释放磁盘空间并减少关机/启动异常。', cons: '失去快速启动带来的开机加速，且无法再使用休眠功能。' },
  'tf_core_misc': { pros: '调整系统响应与前台优先级等杂项，桌面操作整体更跟手。', cons: '多个小改动叠加，个别后台任务的响应优先级可能被削弱。' },
  'tf_timer_coal': { pros: '关闭计时器合并与部分现代待机，可降低输入与网络延迟噪声。', cons: '增加 CPU 唤醒次数与功耗，笔记本续航可能下降。' },
  'tf_restore_point': { pros: '创建系统还原点，为后续高风险优化提供回退保障。', cons: '占用少量磁盘空间，本身不带来性能收益。' },
  'game_dvr': { pros: '关闭游戏 DVR 后台录制，减少游戏内掉帧与录制延迟。', cons: '无法再使用 Xbox 游戏录制与回放功能。' },
  'mmcss_optimize': { pros: '合并游戏高优先级与系统级增强：游戏调度优先级、GPU 优先级与低延迟标记一体化，画面更稳、输入延迟更低。', cons: '非标准调度参数在个别音频设备上可能不稳定，且可能抢占音频与后台资源。' },
  'mmcss_svc': { pros: '禁用 MMCSS 服务后多媒体调度开销减少。', cons: '音频/视频应用的 QoS 调度失效，可能引起爆音或音画不稳。' },
  'nara_prio': { pros: '为永劫无间等游戏进程设置高 CPU 优先级，降低游戏卡顿。', cons: '仅对特定游戏进程有效，固定高优先级可能挤占其他程序。' },
  'net_qos_dscp': { pros: '为本机 8 款竞技游戏的进程流量打上 DSCP 46 高优先标记，供沿途网络设备识别。', cons: '只改标记不改带宽：多数家用路由器与运营商不区分 DSCP，此时没有任何实际效果；其中 LeagueClient.exe 是英雄联盟的客户端进程而非对局进程，覆盖不到对局流量。' },
  'disable_uac': { pros: '关闭 UAC 可消除频繁弹窗，减少提权流程干扰。', cons: '显著降低系统安全性，恶意程序更易获得高权限。' },
  'tf_gamemode': { pros: '开启游戏模式，系统优先保障游戏所需的 CPU/GPU 资源。', cons: '后台任务（更新/同步）可能被推迟，影响日常使用。' },
  'tf_gamebar': { pros: '关闭游戏栏后台捕获与 PresenceWriter，减少叠加层与遥测开销。', cons: '无法使用 Win+G 游戏栏的录屏与性能面板。' },
  'tf_fso': { pros: '关闭全屏优化破坏，可消除部分游戏全屏切换卡顿与输入延迟。', cons: '个别游戏依赖全屏优化特性，关闭后可能出现异常。' },
  'tf_gpu_latency': { pros: '下调 GPU 预渲染帧数与延迟容忍度，能降低输入到画面的延迟。', cons: '设置过低可能引起帧率波动或卡顿，需按显卡性能取舍。' },
  'tf_resource_policy': { pros: '解除系统资源策略限制，释放被节流的 CPU/内存额度。', cons: '绕开系统配额保护，失控进程可能占满系统资源。' },
  'tf_ifeo_perf': { pros: '为进程写入 IFEO CPU/IO 优先级，常驻程序与游戏更跟手。', cons: 'IFEO 针对特定进程，路径或名称变更后失效，全局生效存在风险。' },
  'tf_ifeo_wipe': { pros: '清空 IFEO 调试项，排除被劫持或调试器附加的隐患。', cons: '可能一并删除系统或游戏反作弊所需的兼容性条目。' },
  // 'prefetch_off'（关闭预读）条目已移除：该优化项已不在 OPTIONS 中，属历史孤儿映射
  'svc_mem_gb': { pros: '按内存档位调整 SVCHost 拆分阈值，减少服务进程内存碎片。', cons: '阈值与内存不匹配时反而增加进程切换开销。' },
  'tf_mmagent': { pros: '关闭内存压缩与页合并，进一步压低 CPU 后台开销。', cons: '物理内存不足时稳定性下降，可能出现更高硬盘写入。' },
  'tf_svc_bulk': { pros: '批量禁用 70+ 非必要服务，显著释放内存并减少后台活动。', cons: '高度激进，可能破坏打印机、蓝牙、商店等功能，风险较高。' },
  'tf_drv_disable': { pros: '禁用高风险驱动服务，减少内核攻击面与运行时开销。', cons: '可能影响硬件识别或安全软件，需要谨慎选择。' },
  'spectre_off': { pros: '关闭幽灵/熔断缓解，可明显提升 CPU 密集与游戏性能。', cons: '重新暴露 Spectre/Meltdown 类漏洞，系统安全性下降。' },
  'share_off': { pros: '关闭默认管理共享与弱会话，降低局域网被入侵的风险。', cons: '无法再使用 \\\\主机\\C$ 之类管理共享，远程管理不便。' },
  'telemetry_optimize': { pros: '策略+任务+日志+服务四层一体关闭遥测，最大限度减少后台上传与隐私泄露。', cons: '影响诊断反馈与部分个性化/商店功能，系统诊断与日志复盘能力下降。' },
  'power_off': { pros: '禁用部分电源节能，CPU 与设备响应更积极。', cons: '功耗与发热上升，笔记本续航缩短。' },
  'keys_off': { pros: '屏蔽粘滞键等热键，避免误触弹窗干扰。', cons: '确有需要的辅助功能将被一并禁用。' },
  'tf_defender': { pros: '彻底关闭 Defender 与 SmartScreen，减少实时扫描的 CPU/磁盘占用。', cons: '失去实时防病毒保护，系统安全风险显著上升。' },
  'tf_mitigations': { pros: '关闭全部进程与内核缓解，最大化释放性能。', cons: '安全代价极高，易受漏洞利用攻击，不建议日常启用。' },
  'tf_privacy': { pros: '批量关闭内容推送、遥测、反馈等隐私项，界面更干净。', cons: '个性化内容与部分开始菜单建议会消失。' },
  'tf_gpu_msi': { pros: '为独立显卡启用 MSI 中断，可降低图形中断延迟。', cons: '少数老显卡或驱动在 MSI 模式下可能不稳定。' },
  'tf_nvidia_tweaks': { pros: 'NVIDIA 低延迟、TDR 与驱动微调，游戏响应更佳。', cons: '对驱动与显卡兼容性要求高，个别型号可能出现异常。' },
  'tf_nvidia_telemetry': { pros: '关闭 NVIDIA 遥测与自动更新，减少后台联网活动。', cons: '无法自动获取驱动更新，需要手动维护。' },
  'tf_amd_tweaks': { pros: 'AMD 低延迟/省电相关开关调优，游戏与日常响应提升。', cons: '与驱动版本强相关，部分参数可能被忽略或导致异常。' },
  'tf_keys_sticky': { pros: '彻底禁用粘滞/筛选/切换键，杜绝误触弹窗。', cons: '依赖这些辅助功能的用户将无法使用。' },
  'tf_usb_msi': { pros: 'USB 控制器启用 MSI 中断，改善键鼠输入响应。', cons: '个别老旧 USB 设备在 MSI 模式下可能不稳定。' },
  'tf_usb_power': { pros: '关闭 USB 选择性暂停，避免外设休眠唤醒延迟。', cons: 'USB 设备持续供电，笔记本轻微增加耗电。' },
  'mouse_optimize': { pros: '去加速 + 6/11 灵敏度 + 平滑曲线清零一体完成，指针移动完全线性，定位更精准一致。', cons: '习惯带加速手感的用户需要重新适应，少数驱动会重建曲线值，需重启后生效。' },
  'tf_keyboard': { pros: '键盘零延迟并把驱动队列深度与端口路由一并写为目标档，输入响应更直接。', cons: '队列深度固定写 8、端口路由固定为驱动默认档（不再提供档位选择），修改需重启电脑后生效。' },
  'tf_dev_disable': { pros: '禁用 HPET/ME 等冗余设备，减少中断与延迟。', cons: '可能影响设备管理、虚拟化或系统稳定性，风险较高。' },
  'tf_dev_audio': { pros: '禁用板载/HDMI 声卡控制器，消除多余音频设备。', cons: '板载与 HDMI 音频将不可用，仅适用独立 USB 声卡用户。' },
  'tf_dev_printer': { pros: '禁用打印队列根设备，无打印需求者减少后台开销。', cons: '之后无法打印，需要打印时须重新启用该设备。' },
  'tf_appx': { pros: '移除 25 个预装 UWP 应用，释放磁盘并减少后台活动。', cons: '部分应用移除后需从商店重装，个别系统集成可能异常。' },
  'tf_cortana': { pros: '禁用 Cortana 与网页搜索，减少后台联网与隐私追踪。', cons: '失去 Cortana 语音助手与任务栏网页搜索能力。' },
  'tf_onedrive': { pros: '彻底卸载 OneDrive 并清理数据目录，释放空间、减少同步。', cons: '云端文件不再自动同步，恢复需重新安装并登录。' },
  'explorer_autorestart': { pros: 'explorer.exe 崩溃后自动拉起，桌面与任务栏无需手动重启。', cons: '崩溃发生时重启过程会有短暂桌面黑屏闪烁。' },
  'explorer_refresh_policy': { pros: '按完整信息刷新文件列表，新建/重命名后图标即时显示。', cons: '禁用简化标识列表在个别网络环境下可能略微增加刷新开销。' },
  'perf_remote_assist_off': { pros: '禁用远程协助入口，减少攻击面与后台监听。', cons: '无法再使用"请求远程协助"功能。' },
  'perf_prefetcher_fast': { pros: '启用应用与启动预读，程序启动与文件访问更快。', cons: 'SSD 上收益有限，Prefetch 被清理后需重新积累。' },
  'perf_crash_autoreboot': { pros: '蓝屏后自动重启，无人值守场景恢复更快。', cons: '排查蓝屏时看不到完整停机码，建议排查期临时关闭。' },
  'perf_exploit_protection_off': { pros: '关闭内核缓解（乱序内存等），部分应用内存分配性能小幅提升。', cons: '显著降低漏洞利用防护，系统更容易受提权/ROP 类攻击。' },
  'edge_hide_firstrun': { pros: '跳过首次运行欢迎与导入向导，新环境开箱即用。', cons: '无法通过向导自动导入其他浏览器的收藏与设置，需手动导入。' },
  'edge_bg_mode_off': { pros: '关闭 Edge 后进程全部退出，释放内存与后台占用。', cons: '依赖 Edge 后台通知的网页推送（如网页版邮件）将不再及时送达。' },
  'edge_startup_boost_off': { pros: '开机不再预启动 Edge，减少后台进程与开机资源占用。', cons: '首次点击 Edge 启动会略微变慢。' },
  'edge_intrusive_ads_off': { pros: '全站拦截侵入式广告，减少误导弹窗与虚假下载按钮。', cons: '个别依赖广告收入的站点可能提示关闭拦截或内容异常。' },
  'edge_ntp_quicklinks_off': { pros: '新标签页更干净，不显示默认推送的热门站点。', cons: '常用站点需手动收藏或输入地址访问。' },
  'edge_sidebar_off': { pros: '去掉右侧边栏（Copilot/发现等），界面清爽、减少误触。', cons: '需要使用侧边栏搜索或 Copilot 入口时需重新开启。' },
  'edge_unsupported_os_warn_off': { pros: '不再弹出旧系统停止支持的通知横幅。', cons: '可能错过重要的安全更新提醒。' },
  'edge_metrics_off': { pros: '浏览器诊断数据零上报，隐私外发通道彻底关闭。', cons: '微软无法收集自动诊断信息，远程协助排查浏览器问题的依据减少。' },
  'edge_tab_perf_detector_off': { pros: '不再弹出标签页性能检测提示，减少打扰。', cons: '个别页面真有性能问题时缺少系统级提醒。' },
  'edge_ntp_content_off': { pros: '新标签页无资讯信息流，加载更快、注意力更集中。', cons: '喜欢在标签页浏览新闻的用户需要主动访问资讯站点。' },
  'edge_personalization_off': { pros: '浏览历史不用于个性化广告与推荐，隐私更好。', cons: '推荐内容不再贴合个人兴趣。' },
  'edge_insecure_download_warn_off': { pros: 'HTTP 下载不再被警告拦截，熟练用户操作更顺畅。', cons: '不安全下载缺少提醒，可能误下被篡改的文件。' },
  'edge_rewards_hide': { pros: '隐藏 Rewards 积分入口，界面更简洁。', cons: '使用 Microsoft Rewards 攒积分的用户需要重新开启。' },
  'edge_sxs_service_off': { pros: '关闭 EdgeUpdate 的 SxsService 后台组件，减少后台活动。', cons: '依赖该组件的 Edge 并行版本功能不可用（多数用户无感知）。' },
  'edge_update_task_disable': { pros: '停止 Edge 自动更新检查，消除后台更新占用。', cons: '浏览器安全补丁不再自动安装，必须定期手动更新。' },
  'privacy_permissions_tune': { pros: '一次精调 20+ 项应用权限与数据收集开关，输入习惯、活动历史、通讯录等不再被收集。', cons: '应用可能失去文档/日历/联系人访问权限，剪贴板历史被启用，个别权限需手动在设置中恢复。' },
  'tf_ai_off': { pros: '策略级关闭 Copilot/Recall/Click to Do/AI Agent 全家桶并禁用 AgentRuntime 服务，释放后台内存与 CPU，隐私零上传。', cons: '无法使用 Windows 内置 AI 功能（Copilot、Recall 等），系统更新后部分策略可能被重置需重新执行。' },
  'tf_perf_misc': { pros: '启动延迟归零、禁用窗口摇晃与失效快捷方式全盘解析，桌面响应更跟手；前台窗口即时抢到焦点，关机不再卡在"正在关闭"。', cons: '个别依赖 Aero Shake 的使用习惯失效；禁用链接解析后指向网络位置的失效快捷方式打开更慢；未保存工作的应用与个别服务可能被更快结束，关机前请先保存。' },
  'tf_privacy_extra': { pros: '补漏关闭 Chrome/Firefox/VS 遥测、许可验证上报、新闻兴趣流与步骤记录器，第三方数据外发通道进一步收窄。', cons: '浏览器与 VS 的官方反馈/体验改进计划退出，个别企业环境可能检测策略与预期不符。' },
  'tf_svc_extra5': { pros: '停用传感器、存储感知、PCA 等非必要服务，减少后台进程与定时唤醒。', cons: '亮度自动调节等传感器功能失效，打印机兼容性助手不再提示，外设依赖相关服务时需还原。' },
  'tf_ctx_copymove': { pros: '右键菜单直达「复制/移动到文件夹」对话框，搬运文件免剪贴粘贴。', cons: '右键菜单新增两项条目，菜单略长；个别精简系统该 CLSID 处理器可能缺失而无效果。' },
  'tf_disk_extra3': { pros: '禁用 NTFS 目录加密、搜索仅限索引位置并释放约 7GB 更新保留存储，磁盘空间与扫描开销双降。', cons: 'EFS 文件加密不可用（BitLocker 不受影响），索引范围外的文件搜索变慢，保留存储还原需 DISM 联网。' },
  'tf_store_autoupdate': { pros: '商店应用不再自动下载更新，消除后台偷跑流量与磁盘 IO，推广弹窗一并关闭。', cons: '应用须手动到商店检查更新，长期不更新可能错过安全补丁与新功能。' },
  // ===== v0.4.9 D 批 1（RAINZ 对标 §3.5）新增 4 项 =====
  'wu_do_download_mode_off': { pros: 'Windows 更新只从微软官方源下载，本机不再向 LAN/互联网其他机器上传分块，后台带宽与磁盘 IO 更稳。', cons: '同网段多台 Windows 一起更新时整体下载速度可能变慢（失去 P2P 加速）；企业用 Delivery Optimization 做缓存分发的场景不适用。' },
  'net_no_active_probe': { pros: '不再周期性向 msftconnecttest.com 发探测请求，隐私外发面收窄；断网时也不会反复重试。', cons: '任务栏网络图标失去"是否联网"的准确指示，可能一直显示正常；酒店/机场 captive portal 不会自动弹出登录页。' },
  'sys_copilot_hide_button': { pros: '任务栏视觉更清爽，减少误点 Copilot 图标。', cons: '需要 Copilot 时要走其它入口触发（搜索或快捷键）；不影响 Copilot 后台服务（那由 tf_ai_off 覆盖）。' },
  'sys_startmenu_ads_off': { pros: '开始菜单不再展示微软推广的应用图标，视觉更干净、少一层数据上报。', cons: '失去"这个应用可能对你有用"的推荐入口，需要自己搜装。' },
  // ===== v0.4.9 D 批 2（RAINZ 对标 §3.5）新增 4 项 =====
  'sys_startmenu_tip_off': { pros: '开始菜单不再弹功能提示与新手引导卡片，视觉稳定；也不弹"这个新技能你可以试试"的推广。', cons: '首次接触 Windows 新功能时缺少官方引导，需要自己查文档。' },
  'sys_settings_ads_off': { pros: 'Windows 设置首页不再展示"为你推荐"卡片，进入设置就是设置本身。', cons: '偶尔有用的系统功能提示（例如BitLocker 提醒）可能一并被压制。' },
  'sys_filesync_ads_off': { pros: '不再弹「把新文档自动保存到 OneDrive」的建议卡片，减少把本地文件误上云的引导压力。', cons: '真正需要云同步的用户要自己去 OneDrive 设置里手动开启 Known Folder Move。' },
  'edge_copilot_search_off': { pros: 'Edge 地址栏搜索结果页不再自动接入 Copilot 侧栏回答，搜索体验回到普通结果列表；也少一层向微软服务端发送查询内容的通道。', cons: '需要 Copilot 回答时要手动点开或在应用里访问；已装 Edge 若未支持该策略则无效果。' },
  // ===== v0.4.9 D 批 4（RAINZ 对标 §3.5）新增 4 项 =====
  'sys_minanimate_off': { pros: '窗口最小化/最大化不再播缩放动画，视觉响应更直接；低配机与远程桌面上感知明显。', cons: '失去开合过渡的"柔和感"，习惯动画的用户短期会不适应。' },
  'sys_taskbar_anim_off': { pros: '任务栏按钮切换与最小化不再播滑动动画，减少视觉噪声。', cons: '属偏好设置，喜欢 Windows 原生动画观感的用户会不习惯。' },
  'sys_thumb_cache_off': { pros: '资源管理器不再把缩略图写入 thumbcache_*.db，多人共用/U 盘场景避免缩略图残留；隐私收益更明确。', cons: '每次进同一目录要重新计算缩略图，SSD 上开销可忽略、机械盘大目录略慢。' },
  'sys_font_smoothing_cleartype': { pros: '把 FontSmoothingType 拉回 2（ClearType），LCD 屏上中文与英文都更清晰。', cons: '默认已是 2；本项只在被改回标准/无平滑时才有意义。CRT 或部分非整数 DPI 缩放下 ClearType 反而劣化。' },
  // ===== v0.4.9 D 批 3（RAINZ 对标 §3.5）新增 4 项：服务改手动启动 =====
  'svc_w32time_manual': { pros: 'W32Time 下次开机不再自动常驻，少一个后台服务；当前运行不受影响。', cons: 'AD 域环境与依赖精确系统时间的场景（证书校验、Kerberos）需要该服务在线；改成手动后要么依赖登录时组策略触发、要么手动启动。' },
  'svc_fdrespum_manual': { pros: 'FDResPub 下次开机不再常驻，本机不再主动通过 WS-Discovery 广播可发现性。', cons: '局域网内其他 Windows 设备不再自动看到本机的共享资源；需要网络发现时要手动启动。' },
  'svc_storsvc_manual': { pros: 'StorSvc 下次开机不再常驻，普通家用/办公机不用存储空间就没损失。', cons: '用到 Windows 存储空间、便携设备镜像或某些存储池管理操作时需要该服务在线，可能要手动启动。' },
  'svc_xblauthmgr_manual': { pros: 'XblAuthManager 下次开机不再常驻，不用 Xbox App/Game Pass 的机器无损失。', cons: '首次登录 Xbox 相关应用时会多一次服务冷启动，个别 Store 游戏登录体验略慢。' },
  // ===== v0.4.9 D 批 收尾 新增 4 项 =====
  'wu_au_options_notify': { pros: 'Windows 更新不再自动跑完"检测→下载→安装"全流程，改为每次弹提示由你决定何时动手；能避开"正在演示/开会时突然开始下载"的场面。', cons: '只在 NoAutoUpdate=0 时生效；关掉自动更新（perf_windows_update_off）的机器本项无实际作用，且需要主动留意提示。' },
  'wu_no_auto_reboot': { pros: '补丁装完后只要有用户登录就不会自动重启，避免"下班忘了关工作簿、半夜被 Windows 重启"。不影响补丁本身下载安装。', cons: '需要重启才能生效的补丁会被推迟，长期不主动重启会让部分修复未落地；建议偶尔手动重启。' },
  'sys_transparency_off': { pros: '系统级透明效果关掉，低配机与远程桌面上 DWM 合成开销更少；开始菜单/任务栏/窗口边框视觉更"实"。', cons: '失去 Win11 标志性的透明/云母质感，视觉上更像传统实色窗口。与 Trim 窗材质设置不同层。' },
  'devmgr_show_hidden_default': { pros: '打开设备管理器默认就能看见灰色"未插着"的历史设备，方便清理残留驱动（比如换过 WiFi 卡后老卡的驱动）。', cons: '列表会更长、混杂更多无关条目；不改变任何硬件行为，纯展示层。' }
};

// 将优点/缺点注入到选项目录（不改动上方 OPTIONS 结构）
OPTIONS.forEach(o => {
  const pc = PROS_CONS[o.id];
  o.pros = pc && pc.pros ? pc.pros : '';
  o.cons = pc && pc.cons ? pc.cons : '';
});

// ==================== 还原推理（安全兜底） ====================
// 对注册表优化项推理还原操作：
//  - 有显式 restore 的项直接标记可恢复；
//  - steps 仅含 reg 块的项，可推理出「删除全部对应键值」的还原操作
//    （策略键与系统杂项键删除后即恢复系统默认行为）；
//  - 含 cmd / pwsh / service 步骤的项无法可靠推理出还原值，标记为不可恢复
//    （前端「立即恢复」按钮将置灰，点击仅展示简介）。
function invertRegBlock(block) {
  // 将 .reg 文本中的每条 "键"=值 改写为 "键"=-（删除），保留段落结构
  return String(block).replace(/^"([^"]+)"=(.+)$/gm, (m, k) => `"${k}"=-`);
}
OPTIONS.forEach(o => {
  const steps = o.steps || [];
  const regSteps = steps.filter(s => s && s.reg);
  const hasNonReg = steps.some(s => s && !s.reg);
  if (Array.isArray(o.restore) && o.restore.length) {
    o.restoreAvailable = true;
    return;
  }
  if (regSteps.length && !hasNonReg) {
    o.restore = regSteps.map(s => ({
      label: '推理还原：删除上述注册表键值（恢复系统默认行为）',
      reg: invertRegBlock(s.reg)
    }));
    o.restoreInferred = true;
    o.restoreAvailable = true;
  } else {
    o.restoreAvailable = false;
  }
});

// ==================== 预期效果分级（v2.6.0 P2-7） ====================
// 借鉴 Pavise「诚实的效果说明」设计哲学：预期效果是经验分级，不是本机实测数据，
// 在渲染层详情弹窗明示这一点。分级口径：
//   明显   = 收益可直观感知或量化较大（后台进程/占用显著减少、存储空间大幅释放等）
//   一般   = 机制明确、特定场景下有可测收益（隐私面收敛、响应/延迟、稳定性）
//   微小   = 收益存在但多数场景难以感知（经典玄学项、依赖型收益）
//   未验证 = 缺乏可靠依据或收益因机型/负载而异，无法给出负责任的结论
const EFFECT_MAP = {
  tf_ntfs: '一般',
  tf_hibern_off: '一般',
  tf_core_misc: '一般',
  tf_timer_coal: '微小',
  game_dvr: '一般',
  mmcss_optimize: '微小',
  nara_prio: '一般',
  disable_uac: '微小',
  tf_gamemode: '一般',
  tf_gamebar: '一般',
  tf_fso: '未验证',
  tf_gpu_latency: '微小',
  tf_ifeo_perf: '未验证',
  tf_ifeo_wipe: '一般',
  svc_mem_gb: '一般',
  tf_mmagent: '微小',
  tf_svc_bulk: '明显',
  tf_drv_disable: '微小',
  share_off: '一般',
  telemetry_optimize: '一般',
  power_off: '一般',
  tf_defender: '一般',
  tf_privacy: '一般',
  tf_gpu_msi: '未验证',
  tf_nvidia_telemetry: '一般',
  tf_keys_sticky: '明显',
  tf_usb_msi: '未验证',
  tf_usb_power: '一般',
  mouse_optimize: '一般',
  tf_keyboard: '一般',
  tf_dev_disable: '一般',
  tf_dev_audio: '微小',
  tf_dev_printer: '微小',
  tf_appx: '明显',
  tf_cortana: '一般',
  tf_onedrive: '一般',
  audio_disable_enhancements: '一般',
  audio_disable_spatial_sound: '一般',
  audio_mmcss_priority: '微小',
  audio_mmcss_schedule: '微小',
  audio_disable_comm_ducking: '一般',
  audio_disable_service_restart: '微小',
  audio_disable_voice_activation: '一般',
  audio_disable_voice_activation_last_used: '微小',
  audio_disable_narrator_ducking: '微小',
  desktop_show_ext: '一般',
  desktop_show_hidden: '一般',
  desktop_thumb_delay: '微小',
  desktop_sep_process: '一般',
  desktop_taskbar_left: '一般',
  desktop_taskbar_show_desktop: '一般',
  desktop_taskbar_multi: '一般',
  desktop_low_disk_off: '微小',
  explorer_autorestart: '一般',
  explorer_refresh_policy: '一般',
  tasks_disable_defrag: '未验证',
  tasks_disable_silent_cleanup: '一般',
  tasks_disable_winbackup: '微小',
  tasks_disable_settingsync: '一般',
  peripheral_inactive_scroll: '一般',
  peripheral_winkey_off: '明显',
  peripheral_mouse_trails: '微小',
  peripheral_snap_to: '微小',
  privacy_advertising_id: '一般',
  privacy_wer_off: '微小',
  privacy_compat_telemetry: '微小',
  privacy_settingsync_off: '一般',
  privacy_cloud_content: '一般',
  privacy_permissions_tune: '一般',
  svc_connected_devices_manual: '一般',
  svc_fax_disable: '微小',
  svc_remote_registry_disable: '一般',
  svc_remote_connectivity_manual: '微小',
  svc_bluetooth_disable: '微小',
  power_aspm_off: '一般',
  storage_8dot3_off: '一般',
  perf_uwp_background_off: '一般',
  perf_store_auto_update_off: '一般',
  perf_windows_update_off: '微小',
  perf_notifications_off: '一般',
  perf_vbs_off: '一般',
  perf_remote_assist_off: '微小',
  perf_prefetcher_fast: '微小',
  perf_crash_autoreboot: '一般',
  perf_exploit_protection_off: '未验证',
  edge_hide_firstrun: '一般',
  edge_bg_mode_off: '一般',
  edge_startup_boost_off: '一般',
  edge_intrusive_ads_off: '明显',
  edge_ntp_quicklinks_off: '微小',
  edge_sidebar_off: '一般',
  edge_unsupported_os_warn_off: '微小',
  edge_metrics_off: '一般',
  edge_tab_perf_detector_off: '微小',
  edge_ntp_content_off: '一般',
  edge_personalization_off: '一般',
  edge_insecure_download_warn_off: '微小',
  edge_rewards_hide: '一般',
  edge_sxs_service_off: '微小',
  edge_update_task_disable: '微小',
  tf_ai_off: '一般',
  tf_perf_misc: '一般',
  tf_privacy_extra: '一般',
  tf_svc_extra5: '一般',
  tf_ctx_copymove: '一般',
  tf_disk_extra3: '一般',
  tf_store_autoupdate: '一般',
  // ===== v0.4.9 D 批 1（RAINZ 对标 §3.5）=====
  // 4 项都在**微软文档公开的策略键**上；效果分级按"多数用户可感 vs 少数用户可感 vs 未验证"给。
  // 「未验证」留给"要跑机器 + 场景 + 长期观察才能定"的效果 —— D 批 1 里没有一条属于此类，
  // 但保留注释位以便下一批沿用同一路子。
  wu_do_download_mode_off: '一般',
  net_no_active_probe: '一般',
  sys_copilot_hide_button: '微小',
  sys_startmenu_ads_off: '一般',
  // ===== v0.4.9 D 批 2 =====
  sys_startmenu_tip_off: '一般',
  sys_settings_ads_off: '一般',
  sys_filesync_ads_off: '一般',
  edge_copilot_search_off: '微小',
  // ===== v0.4.9 D 批 4 =====
  sys_minanimate_off: '微小',
  sys_taskbar_anim_off: '微小',
  sys_thumb_cache_off: '一般',
  sys_font_smoothing_cleartype: '一般',
  // ===== v0.4.9 D 批 3 =====
  svc_w32time_manual: '微小',
  svc_fdrespum_manual: '微小',
  svc_storsvc_manual: '微小',
  svc_xblauthmgr_manual: '微小',
  // ===== v0.4.9 D 批 收尾 =====
  wu_au_options_notify: '一般',
  wu_no_auto_reboot: '一般',
  sys_transparency_off: '微小',
  devmgr_show_hidden_default: '微小'
};
// 注入预期效果；未登记的项（未来新增）默认「未验证」——诚实兜底，宁可不标好话
OPTIONS.forEach(o => { o.effect = EFFECT_MAP[o.id] || '未验证'; });

module.exports = {
  OPTIONS, MEMORY_KB, memorySteps, svcBulkAppendStoreSteps, STORE_TOGGLE_SERVICES, buildScript,
  // v3.7.0 议题六 P1
  windowsUpdatePauseSteps, WU_PAUSE_KEYS, WU_PAUSE_MAX_DAYS
};

