// quickcmds-data.js - 快捷指令数据（63 条 / 8 分类）
// 来源：old\快捷指令\QuickLauncher-解包分析报告.md（快捷指令大全 v6.0 解包逆向）
// 每条：{ id, name, desc, cmd, cat }
//   id   —— 稳定标识（主进程白名单校验用，渲染层仅传 id）
//   name —— 指令中文名
//   desc —— 英文/说明副标题
//   cmd  —— 实际执行的命令（主进程 spawn 白名单，不接受用户输入）
// UMD 兼容：主进程 require 取 module.exports；渲染层 <script> 取 window.QUICKCMDS_DATA
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.QUICKCMDS_DATA = api;
})(typeof self !== 'undefined' ? self : this, function () {
  const CATEGORIES = [
    '系统工具', '硬件与设备', '服务与进程', '网络',
    '程序和功能', '辅助工具', '维护与诊断', '休眠唤醒排查'
  ];

  const CMDS = [
    // 系统工具
    { id: 'sys-cmd', name: '命令提示符', desc: 'cmd', cmd: 'cmd', cat: '系统工具' },
    { id: 'sys-cmd-admin', name: '管理员CMD', desc: 'elevated cmd', cmd: 'powershell -Command "Start-Process cmd -Verb RunAs"', cat: '系统工具' },
    { id: 'sys-powershell', name: 'PowerShell', desc: 'powershell', cmd: 'powershell', cat: '系统工具' },
    { id: 'sys-regedit', name: '注册表编辑器', desc: 'regedit', cmd: 'regedit', cat: '系统工具' },
    { id: 'sys-msconfig', name: '系统配置', desc: 'msconfig', cmd: 'msconfig', cat: '系统工具' },
    { id: 'sys-msinfo32', name: '系统信息', desc: 'msinfo32', cmd: 'msinfo32', cat: '系统工具' },
    { id: 'sys-sysdm', name: '系统属性(综合)', desc: 'sysdm.cpl hub', cmd: 'sysdm.cpl', cat: '系统工具' },
    { id: 'sys-winver', name: 'Windows版本', desc: 'winver', cmd: 'winver', cat: '系统工具' },
    { id: 'sys-rstrui', name: '系统还原', desc: 'rstrui', cmd: 'rstrui', cat: '系统工具' },
    { id: 'sys-envvar', name: '环境变量编辑', desc: 'environment variables', cmd: 'rundll32.exe sysdm.cpl,EditEnvironmentVariables', cat: '系统工具' },
    { id: 'sys-winupdate', name: 'Windows更新(综合)', desc: 'windows update hub', cmd: 'control /name Microsoft.WindowsUpdate', cat: '系统工具' },
    { id: 'sys-sdclt', name: '备份还原', desc: 'sdclt', cmd: 'sdclt', cat: '系统工具' },
    { id: 'sys-eventvwr', name: '事件查看器', desc: 'eventvwr.msc', cmd: 'eventvwr.msc', cat: '系统工具' },
    { id: 'sys-perfmon-rel', name: '可靠性蓝屏记录', desc: 'perfmon /rel', cmd: 'perfmon /rel', cat: '系统工具' },
    // 硬件与设备
    { id: 'hw-devmgmt', name: '设备管理器(综合)', desc: 'devmgmt.msc hub', cmd: 'devmgmt.msc', cat: '硬件与设备' },
    { id: 'hw-diskmgmt', name: '磁盘管理', desc: 'diskmgmt.msc', cmd: 'diskmgmt.msc', cat: '硬件与设备' },
    { id: 'hw-desk', name: '显示设置', desc: 'desk.cpl', cmd: 'desk.cpl', cat: '硬件与设备' },
    { id: 'hw-main', name: '鼠标属性', desc: 'main.cpl', cmd: 'main.cpl', cat: '硬件与设备' },
    { id: 'hw-keyboard', name: '键盘属性', desc: 'control keyboard', cmd: 'control keyboard', cat: '硬件与设备' },
    { id: 'hw-powercfg', name: '电源选项', desc: 'powercfg.cpl', cmd: 'powercfg.cpl', cat: '硬件与设备' },
    { id: 'hw-printers', name: '设备和打印机', desc: 'control printers', cmd: 'control printers', cat: '硬件与设备' },
    { id: 'hw-mmsys', name: '声音设置', desc: 'mmsys.cpl', cmd: 'mmsys.cpl', cat: '硬件与设备' },
    { id: 'hw-autoplay', name: '自动播放设置', desc: 'control autoplay', cmd: 'control /name Microsoft.AutoPlay', cat: '硬件与设备' },
    // 服务与进程
    { id: 'svc-services', name: '系统服务', desc: 'services.msc', cmd: 'services.msc', cat: '服务与进程' },
    { id: 'svc-taskmgr', name: '任务管理器', desc: 'taskmgr', cmd: 'taskmgr', cat: '服务与进程' },
    { id: 'svc-perfmon', name: '性能监视器', desc: 'perfmon.msc', cmd: 'perfmon.msc', cat: '服务与进程' },
    { id: 'svc-resmon', name: '资源监视器', desc: 'resmon', cmd: 'resmon', cat: '服务与进程' },
    { id: 'svc-taskschd', name: '计划任务', desc: 'taskschd.msc', cmd: 'taskschd.msc', cat: '服务与进程' },
    // 网络
    { id: 'net-ncpa', name: '网络连接', desc: 'ncpa.cpl', cmd: 'ncpa.cpl', cat: '网络' },
    { id: 'net-wf', name: '防火墙设置', desc: 'wf.msc', cmd: 'wf.msc', cat: '网络' },
    { id: 'net-ipconfig', name: '本机IP地址', desc: 'ipconfig', cmd: 'cmd /k ipconfig /all', cat: '网络' },
    { id: 'net-mstsc', name: '远程桌面', desc: 'mstsc', cmd: 'mstsc', cat: '网络' },
    { id: 'net-msra', name: '远程协助', desc: 'msra', cmd: 'msra', cat: '网络' },
    { id: 'net-nasc', name: '网络和共享中心', desc: 'NetworkAndSharingCenter', cmd: 'control /name Microsoft.NetworkAndSharingCenter', cat: '网络' },
    // 程序和功能
    { id: 'app-appwiz', name: '程序和功能', desc: 'appwiz.cpl', cmd: 'appwiz.cpl', cat: '程序和功能' },
    { id: 'app-default', name: '默认程序', desc: 'DefaultPrograms', cmd: 'control /name Microsoft.DefaultPrograms', cat: '程序和功能' },
    { id: 'app-startup', name: '启动文件夹', desc: 'shell:startup', cmd: 'explorer shell:startup', cat: '程序和功能' },
    { id: 'app-fonts', name: '字体文件夹', desc: 'shell:fonts', cmd: 'explorer shell:fonts', cat: '程序和功能' },
    { id: 'app-optional', name: '管理可选功能', desc: 'optionalfeatures', cmd: 'optionalfeatures', cat: '程序和功能' },
    // 辅助工具
    { id: 'util-calc', name: '计算器', desc: 'calc', cmd: 'calc', cat: '辅助工具' },
    { id: 'util-mspaint', name: '画图', desc: 'mspaint', cmd: 'mspaint', cat: '辅助工具' },
    { id: 'util-notepad', name: '记事本', desc: 'notepad', cmd: 'notepad', cat: '辅助工具' },
    { id: 'util-osk', name: '屏幕键盘', desc: 'osk', cmd: 'osk', cat: '辅助工具' },
    { id: 'util-charmap', name: '字符映射表', desc: 'charmap', cmd: 'charmap', cat: '辅助工具' },
    { id: 'util-cleanmgr', name: '磁盘清理', desc: 'cleanmgr', cmd: 'cleanmgr', cat: '辅助工具' },
    { id: 'util-snipping', name: '截图工具', desc: 'snippingtool', cmd: 'snippingtool', cat: '辅助工具' },
    { id: 'util-psr', name: '步骤记录器', desc: 'psr', cmd: 'psr', cat: '辅助工具' },
    { id: 'util-utilman', name: '辅助功能', desc: 'utilman', cmd: 'utilman', cat: '辅助工具' },
    { id: 'util-narrator', name: '讲述人', desc: 'narrator', cmd: 'narrator', cat: '辅助工具' },
    { id: 'util-lock', name: '锁屏', desc: 'LockWorkStation', cmd: 'rundll32.exe user32.dll,LockWorkStation', cat: '辅助工具' },
    // 维护与诊断
    { id: 'diag-recent', name: '最近文件', desc: 'shell:recent', cmd: 'explorer shell:recent', cat: '维护与诊断' },
    { id: 'diag-downloads', name: '下载文件夹', desc: 'shell:downloads', cmd: 'explorer shell:downloads', cat: '维护与诊断' },
    { id: 'diag-temp', name: '临时文件夹', desc: 'temp', cmd: 'explorer %temp%', cat: '维护与诊断' },
    { id: 'diag-desktop', name: '桌面文件夹', desc: 'shell:desktop', cmd: 'explorer shell:desktop', cat: '维护与诊断' },
    { id: 'diag-appdata', name: 'AppData文件夹', desc: 'appdata', cmd: 'explorer %appdata%', cat: '维护与诊断' },
    { id: 'diag-dxdiag', name: 'DirectX诊断', desc: 'dxdiag', cmd: 'dxdiag', cat: '维护与诊断' },
    { id: 'diag-dfrgui', name: '磁盘碎片整理', desc: 'dfrgui', cmd: 'dfrgui', cat: '维护与诊断' },
    { id: 'diag-slmgr', name: '系统激活状态', desc: 'slmgr /xpr', cmd: 'cmd /k slmgr.vbs /xpr', cat: '维护与诊断' },
    { id: 'diag-storagesense', name: '存储感知', desc: 'ms-settings:storagesense', cmd: 'ms-settings:storagesense', cat: '维护与诊断' },
    { id: 'diag-documents', name: '文档目录', desc: 'Documents', cmd: 'explorer %userprofile%\\Documents', cat: '维护与诊断' },
    // 休眠唤醒排查
    { id: 'power-lastwake', name: '上次唤醒设备', desc: 'powercfg -lastwake', cmd: 'cmd /k powercfg -lastwake', cat: '休眠唤醒排查' },
    { id: 'power-wake-armed', name: '可唤醒设备列表', desc: 'powercfg wake_armed', cmd: 'cmd /k powercfg -devicequery wake_armed', cat: '休眠唤醒排查' },
    { id: 'power-wake-any', name: '所有唤醒设备详情', desc: 'powercfg wake_from_any', cmd: 'cmd /k powercfg -devicequery wake_from_any', cat: '休眠唤醒排查' }
  ];

  return { CATEGORIES, CMDS };
});
