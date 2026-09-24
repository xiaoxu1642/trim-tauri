// tools/ps-map/startup.mjs —— startup 域（D 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
// toggle 的 enable 布尔在 JS 侧映射为 PS 的 `$true`/`$false`（历史陷阱：PowerShell 无
// 裸 true/false 字面量），故按两个变体各生成一份；items 用哨兵数组。
import { ORIGIN } from '../ps-origin.mjs';

const JS = `${ORIGIN}/src/scripts-powershell/startup-scripts.js`;
const ITEMS = [['__TRIM_ITEMS_JSON__']];

export const MAP = [
  { name: 'startup_scan', js: JS, call: 'scan', ps1: 'startup_scan.ps1', note: '启动项扫描（只读）' },
  { name: 'startup_add', js: JS, call: 'add', args: ['__TRIM_STARTUP_PATH__', '__TRIM_STARTUP_NAME__'], ps1: 'startup_add.ps1', note: '添加启动项（哨兵 路径/名称）', noRun: '会写注册表 Run 键，行为层豁免' },
  { name: 'startup_enable', js: JS, call: 'toggle', args: [ITEMS, true], ps1: 'startup_enable.ps1', note: '启用启动项（哨兵 items，$true 变体）', noRun: '会改注册表，行为层豁免' },
  { name: 'startup_disable', js: JS, call: 'toggle', args: [ITEMS, false], ps1: 'startup_disable.ps1', note: '禁用启动项（哨兵 items，$false 变体）', noRun: '会改注册表，行为层豁免' },
  { name: 'startup_remove', js: JS, call: 'remove', args: ITEMS, ps1: 'startup_remove.ps1', note: '删除启动项（哨兵 items）', noRun: '会改注册表，行为层豁免' },
];