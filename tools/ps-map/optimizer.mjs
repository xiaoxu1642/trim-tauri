// tools/ps-map/optimizer.mjs —— optimizer 域（D 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
// buildScript(steps) 的 steps 由主进程从 OPTIONS 定义里取出（渲染层只传 optionId），
// 用哨兵数组占位：运行前由 Rust 把真实 steps 按 JS 同口径序列化（buildScript 内部对 steps
// 的序列化方式以源码为准，替换时必须与 check-ps-substitution 的同口径对拍保持一致）。
import { ORIGIN } from '../ps-origin.mjs';

const JS = `${ORIGIN}/src/scripts-powershell/optimizer-scripts.js`;

export const MAP = [
  { name: 'optimizer_build', js: JS, call: 'buildScript', args: [[{ __trim_sentinel__: true }]], ps1: 'optimizer_build.ps1', note: '优化项执行脚本（哨兵 steps；40 个优化项共用一份模板）', noRun: '会改注册表/服务/系统设置，行为层豁免' },
];