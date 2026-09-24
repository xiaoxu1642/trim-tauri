// tools/ps-map/netspeed.mjs —— netspeed 域（B 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
import { ORIGIN } from '../ps-origin.mjs';

const JS = `${ORIGIN}/src/scripts-powershell/netspeed-scripts.js`;

export const MAP = [
  { name: 'netspeed_ping', js: JS, call: 'ping', ps1: 'netspeed_ping.ps1', note: '网络延迟/抖动探测（只读）' },
  // 时长由渲染层传入（1~60s），生成期用哨兵数字占位，运行前由 Rust 替换
  { name: 'netspeed_throughput', js: JS, call: 'throughput', args: ['987654321'], ps1: 'netspeed_throughput.ps1', note: '上下行吞吐测速（哨兵时长模板）', noRun: '带哨兵参数，行为层需真实时长，豁免' },
];