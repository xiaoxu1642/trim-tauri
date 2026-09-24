// tools/ps-map/maintenance.mjs —— maintenance 域（D 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
// maintenance.run(taskId) 是**每个任务一份完整脚本**（任务 ID 经白名单枚举），
// 变体清单直接从 JS 模块的 TASKS 键读取（9 个：sfc/dism/wu/store/audio/perfcounters/
// search/dns/netstack），源仓库新增任务时这里自动跟上。
import { createRequire } from 'node:module';
import { ORIGIN } from '../ps-origin.mjs';

const require = createRequire(import.meta.url);
const JS = `${ORIGIN}/src/scripts-powershell/maintenance-scripts.js`;
const MAINT = require(JS);

// list() 是纯 JS 数据（任务清单，无 PS）；run(taskId) 每个变体一份 .ps1。
export const MAP = MAINT.list().map(t => ({
  name: `maint_${t.id}`,
  js: JS,
  call: 'run',
  args: [t.id],
  ps1: `maint_${t.id}.ps1`,
  note: `系统维护任务：${t.title}${t.admin ? '（需管理员）' : ''}`,
  noRun: t.admin
    ? '会改系统且需管理员，行为层豁免'
    : '维护类脚本（可能重启服务/清缓存），行为层豁免',
}));