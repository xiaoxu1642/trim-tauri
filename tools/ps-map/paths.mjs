// tools/ps-map/paths.mjs —— paths 域（C 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
import { ORIGIN } from '../ps-origin.mjs';

const JS = `${ORIGIN}/src/scripts-powershell/pathscan-scripts.js`;

export const MAP = [
  // 规则库 JSON 由主进程注入（60KB 级，运行期值）：生成期用哨兵占位，运行前替换
  { name: 'paths_scan', js: JS, call: 'scan', args: ['__TRIM_RULES_JSON__'], ps1: 'paths_scan.ps1', note: '安装路径自动扫描（哨兵模板）', noRun: '带哨兵参数（规则库 JSON），行为层豁免' },
];