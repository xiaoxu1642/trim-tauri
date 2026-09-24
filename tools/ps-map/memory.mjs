// tools/ps-map/memory.mjs —— memory 域（B 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
// 原则：能取模块常量（`const`）就不调用；参数化脚本一律「哨兵 + noRun」。
import { ORIGIN } from '../ps-origin.mjs';

const JS = `${ORIGIN}/src/scripts-powershell/memory-scripts.js`;

export const MAP = [
  // 内存信息（只读）
  { name: 'memory_info', js: JS, const: 'MEM_INFO_SCRIPT', ps1: 'memory_info.ps1', note: '物理内存/页面文件/系统缓存（只读）' },
  // 进程列表（只读）
  { name: 'memory_processes', js: JS, const: 'PROCESSES_SCRIPT', ps1: 'memory_processes.ps1', note: '进程快照（@@PROC 前缀协议，只读）' },
  // 顽固软件专杀 / 自启阻断（危险：结束进程、改服务启动类型）
  { name: 'memory_stubborn_kill', js: JS, const: 'STUBBORN_KILL_SCRIPT', ps1: 'memory_stubborn_kill.ps1', note: '顽固软件专杀（结束进程）', noRun: '危险脚本（结束第三方进程），行为层豁免' },
  { name: 'memory_stubborn_block', js: JS, const: 'STUBBORN_BLOCK_SCRIPT', ps1: 'memory_stubborn_block.ps1', note: '顽固软件自启阻断（改服务/删计划任务）', noRun: '危险脚本（改系统服务启动类型），行为层豁免' },
  // 结束进程：PID 与进程名由渲染层快照提供，生成期用哨兵占位，运行前由 Rust 替换
  //   987654321 → 真实 PID（JS 内部 Number(pid)，故哨兵必须是数字字面量）
  //   __TRIM_PROC_NAME__ → 真实进程名（JS 只做单引号转义，哨兵原样落入正文）
  { name: 'memory_kill', js: JS, call: 'killScript', args: [987654321, '__TRIM_PROC_NAME__'], ps1: 'memory_kill.ps1', note: '结束指定进程（哨兵模板）', noRun: '带哨兵参数，行为层需真实 PID，豁免' },
];