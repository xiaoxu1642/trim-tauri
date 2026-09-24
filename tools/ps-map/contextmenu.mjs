// tools/ps-map/contextmenu.mjs —— contextmenu 域（D 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
// items 类脚本统一用哨兵数组 `[['__TRIM_ITEMS_JSON__']]`：JS 的 serializeItems 是
// `JSON.stringify(items).replace(/'/g,"''")`，数组里放一个「不可能与真实数据碰撞」的
// 字符串哨兵即可原样落入正文；运行前由 Rust 按同口径序列化替换。
// win11Mode 的 __ACTION__ 是白名单枚举（get/set-classic/set-modern），同一份模板 + 哨兵。
import { ORIGIN } from '../ps-origin.mjs';

const JS = `${ORIGIN}/src/scripts-powershell/contextmenu-scripts.js`;
const ITEMS = [['__TRIM_ITEMS_JSON__']];

export const MAP = [
  { name: 'cm_scan', js: JS, call: 'scan', ps1: 'cm_scan.ps1', note: '右键菜单扫描（只读）' },
  { name: 'cm_backup', js: JS, call: 'backup', args: ITEMS, ps1: 'cm_backup.ps1', note: '右键菜单项注册表备份（哨兵 items）', noRun: '带哨兵参数，行为层豁免' },
  { name: 'cm_remove', js: JS, call: 'remove', args: ITEMS, ps1: 'cm_remove.ps1', note: '移除右键菜单项（哨兵 items）', noRun: '会改注册表，行为层豁免' },
  { name: 'cm_toggle', js: JS, call: 'toggle', args: ITEMS, ps1: 'cm_toggle.ps1', note: '启用/禁用右键菜单项（哨兵 items）', noRun: '会改注册表，行为层豁免' },
  { name: 'cm_restore', js: JS, call: 'restore', ps1: 'cm_restore.ps1', note: '从备份恢复右键菜单（危险）', noRun: '会改注册表，行为层豁免' },
  { name: 'cm_icons', js: JS, call: 'icons', args: ITEMS, ps1: 'cm_icons.ps1', note: '右键菜单图标修复（哨兵 items）', noRun: '带哨兵参数，行为层豁免' },
  { name: 'cm_restart_explorer', js: JS, call: 'restartExplorer', ps1: 'cm_restart_explorer.ps1', note: '重启资源管理器', noRun: '会结束 explorer.exe，行为层豁免' },
  { name: 'cm_win11_mode', js: JS, call: 'win11Mode', args: ['__TRIM_WIN11_ACTION__'], ps1: 'cm_win11_mode.ps1', note: 'Win11 经典/现代右键切换（白名单动作哨兵）', noRun: '会改注册表，行为层豁免' },
  { name: 'cm_blocked_list', js: JS, call: 'blockedList', ps1: 'cm_blocked_list.ps1', note: '被拦截的右键项清单（只读）' },
];