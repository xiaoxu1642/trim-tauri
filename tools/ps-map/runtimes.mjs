// tools/ps-map/runtimes.mjs —— runtimes 域（B 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
//
// 修复动作的变体清单**从 JS 模块自身读取**（INSTALLERS 的键 + netfx35），不手工维护：
// 源仓库新增安装项时这里自动跟上，避免「JS 能装、Tauri 说未知动作」的静默缺口。
import { createRequire } from 'node:module';
import { ORIGIN } from '../ps-origin.mjs';

const require = createRequire(import.meta.url);
const JS = `${ORIGIN}/src/scripts-powershell/runtimes-scripts.js`;
const RUNTIMES = require(JS);

// 哨兵：repair() 会用 fsCheck(installerPath) 做存在性校验，生成期必须传一个**真实存在的路径**
// （否则直接抛「安装包不存在」）。取本模块自身的绝对路径过校验，再由 ps-mapping 的
// `sentinelPath` 统一换成 `@@TRIM_INSTALLER_PATH@@` —— 绝对路径不得进 .ps1/PROVENANCE 头
// （审查 M22：那会把开发者机器布局编进发布的二进制，且坐标一变文本层对拍就红）。
const PATH_SENTINEL = JS;

export const MAP = [
  { name: 'runtimes_status', js: JS, call: 'status', ps1: 'runtimes_status.ps1', note: '运行库检测（只读）' },
  { name: 'runtimes_repair_netfx35', js: JS, call: 'repair', args: ['netfx35', ''], ps1: 'runtimes_repair_netfx35.ps1', note: '启用 .NET Framework 3.5（DISM，不消费安装包）', noRun: '安装型脚本（启用系统功能），行为层豁免' },
  ...Object.keys(RUNTIMES.INSTALLERS).map(actionId => ({
    name: `runtimes_repair_${actionId.replace(/[^a-z0-9]/gi, '_')}`,
    js: JS,
    call: 'repair',
    args: [actionId, PATH_SENTINEL],
    sentinelPath: PATH_SENTINEL,
    actionId,
    ps1: `runtimes_repair_${actionId.replace(/[^a-z0-9]/gi, '_')}.ps1`,
    note: `静默执行本地安装包：${RUNTIMES.INSTALLERS[actionId].name}（哨兵模板：安装包路径）`,
    noRun: '安装型脚本（执行第三方安装包），行为层豁免',
  })),
];