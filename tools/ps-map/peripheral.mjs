// tools/ps-map/peripheral.mjs —— peripheral 域（D 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
import { ORIGIN } from '../ps-origin.mjs';

const JS = `${ORIGIN}/src/scripts-powershell/peripheral-scripts.js`;

export const MAP = [
  { name: 'peripheral_query', js: JS, call: 'query', ps1: 'peripheral_query.ps1', note: '外设优化项状态查询（只读）' },
  { name: 'peripheral_apply', js: JS, call: 'apply', args: [{ __trim_sentinel__: true }], ps1: 'peripheral_apply.ps1', note: '应用外设优化（哨兵 options JSON）', noRun: '会改系统设置，行为层豁免' },
  { name: 'peripheral_restore', js: JS, call: 'restoreBackup', ps1: 'peripheral_restore.ps1', note: '从备份恢复外设设置（危险）', noRun: '会改系统设置，行为层豁免' },
];