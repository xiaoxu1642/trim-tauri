// tools/ps-map/netcheck.mjs —— netcheck 域（B 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
import { ORIGIN } from '../ps-origin.mjs';

const JS = `${ORIGIN}/src/scripts-powershell/netcheck-scripts.js`;

// 修复动作的每个变体各生成一份 .ps1：变化收敛在生成期，Rust 只按 actionId 选文件，
// 避免在 Rust 里复刻「参数 → 脚本片段」的分支逻辑（那是又一处会漂移的重复实现）。
// 变体清单 = netcheck-scripts.js:repair() 的 if 分支全集（改 JS 后必须同步本表，
// 生成器会在出现未知 actionId 时抛错，恰好是一道防漏闸）。
// 变体参数里的运行期值用哨兵：
//   __TRIM_ADAPTER_NAME__  网卡名（enable-adapter，来自检测快照）
//   987654321              接口索引（reset-dns，来自检测快照）
const REPAIR_VARIANTS = [
  ['enable_adapter', ['enable-adapter', { name: '__TRIM_ADAPTER_NAME__' }], '启用被禁用的网卡'],
  ['start_dhcp', ['start-dhcp', {}], '启动 DHCP 服务并设为自动'],
  ['start_dnscache', ['start-dnscache', {}], '启动 DNS Client 服务'],
  ['reset_dns', ['reset-dns', { interfaceIndex: 987654321 }], 'DNS 服务器重置为自动获取'],
  ['disable_user_proxy', ['disable-user-proxy', {}], '关闭残留的用户（WinINET）代理'],
  ['reset_winhttp', ['reset-winhttp', {}], '重置 WinHTTP 代理'],
];

export const MAP = [
  { name: 'netcheck_status', js: JS, call: 'status', ps1: 'netcheck_status.ps1', note: '网络连通性全面检测（只读）' },
  ...REPAIR_VARIANTS.map(([suffix, args, note]) => ({
    name: `netcheck_repair_${suffix}`,
    js: JS,
    call: 'repair',
    args,
    ps1: `netcheck_repair_${suffix}.ps1`,
    note: `${note}（修复动作，判需管理员）`,
    noRun: '修复脚本会改系统配置，行为层豁免',
  })),
];