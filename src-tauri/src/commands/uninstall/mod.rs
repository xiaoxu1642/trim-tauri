//! commands/uninstall —— 卸载域（竞品借鉴落地方案 P0，2026-09-28；v3 D2 起按命令契约分文件）
//!
//! 方案边界（方案 §4.1，违反即回退）：
//! - 只做「看见已安装程序 → 调原厂卸载器 → 残留扫描/解释/受控清理」；
//! - 不做全量注册表清理器、不默认强删程序目录、不盲目静默卸载；
//! - 静默命令由构造器裁决（B1）：厂商 QuietUninstallString 优先，但必须先过闸
//!   （绝对路径 .exe、非 shell/脚本宿主、无重定向/管道/复合/变量替换），
//!   不过闸则回退 msi/inno/nsis 白名单模板派生；命令串一律**后端现读注册表**，
//!   绝不信任渲染层回传的任何命令文本（防注入面）；
//! - 残留文件/目录回收站优先（is_path_protected 前置 + trim_finder 回收站），
//!   回收站失败不做永久删除兜底；注册表先 export 备份再删，备份失败整项跳过；
//! - 残留执行只认**本次会话扫描快照**里的目标（任意单项不得绕过快照）。
//!
//! 文件划分（v3 D2：一个命令契约一文件，`#[tauri::command]` 留在定义处，本 mod.rs 只
//! re-export —— 所以 lib.rs 的 generate_handler!、CHANNEL_MAP 与 guard 档位都不因物理
//! 移动改变）：helpers（注册表读取助手 + 快照台账）/ appx / list_run / residue /
//! residue_update / pending_delete；`dead` / `ownership` / 七个深扫器模块在机-wide 扫描
//! 整条退役后**保留为内部代码**（只由 residue 的四类扫描复用），不再暴露命令。
//! 跨契约面的回归网单独放 residue_trace_tests（cfg(test)）。
//!
//! 注册（lib.rs generate_handler + CHANNEL_MAP + check-guard-tiers MUST_MAIN 同步落）：
//! ```text
//! commands::uninstall::uninstall_list,
//! commands::uninstall::uninstall_run,
//! commands::uninstall::uninstall_residue_scan,
//! commands::uninstall::uninstall_residue_execute,
//! ```

mod appx;
pub use appx::{uninstall_appx_logo, __cmd__uninstall_appx_logo, __tauri_command_name_uninstall_appx_logo};
// v0.7.0 机-wide 扫描整条退役后，七个深扫器与它们的判据/签名助手**保留为内部代码**（不再有
// 界面、也不再有可直接调用的命令）。`services_orphan` / `drivers_orphan` 仍被 residue 的四类扫描
// 部分复用，其余模块当前没有生产调用方 —— 逐模块 `allow(dead_code)` 是为了不让「刻意保留」
// 撞上 AGENTS §4 的零警告线（先例：engine/pnp.rs、engine/native/bsod.rs 的同类标注）。
#[allow(dead_code)]
mod authenticode;
#[allow(dead_code)]
mod capability_orphan;
// R-1 后续阶段（2026-10-07）：COM/CLSID 与 File Types / Applications 只读可见面
#[allow(dead_code)]
mod com_orphan;
mod backup_report;
pub use backup_report::{uninstall_reg_backup_list, __cmd__uninstall_reg_backup_list, __tauri_command_name_uninstall_reg_backup_list, uninstall_reg_backup_restore, __cmd__uninstall_reg_backup_restore, __tauri_command_name_uninstall_reg_backup_restore, uninstall_batch_list, __cmd__uninstall_batch_list, __tauri_command_name_uninstall_batch_list, uninstall_batch_restore, __cmd__uninstall_batch_restore, __tauri_command_name_uninstall_batch_restore, uninstall_report_list, __cmd__uninstall_report_list, __tauri_command_name_uninstall_report_list, uninstall_report_get, __cmd__uninstall_report_get, __tauri_command_name_uninstall_report_get};
mod dead;
#[allow(dead_code)]
mod drivers_orphan;
#[allow(dead_code)]
mod game_platform_orphan;
mod helpers;
#[allow(dead_code)]
mod ifeo_orphan;
mod list_run;
pub use list_run::{uninstall_dir_size, __cmd__uninstall_dir_size, __tauri_command_name_uninstall_dir_size, uninstall_list, __cmd__uninstall_list, __tauri_command_name_uninstall_list, uninstall_run, __cmd__uninstall_run, __tauri_command_name_uninstall_run};
mod ownership;
mod pending_delete;
pub use pending_delete::{uninstall_pending_add, __cmd__uninstall_pending_add, __tauri_command_name_uninstall_pending_add, uninstall_pending_list, __cmd__uninstall_pending_list, __tauri_command_name_uninstall_pending_list, uninstall_pending_revoke, __cmd__uninstall_pending_revoke, __tauri_command_name_uninstall_pending_revoke};
mod residue;
pub use residue::{uninstall_residue_scan, __cmd__uninstall_residue_scan, __tauri_command_name_uninstall_residue_scan, uninstall_residue_execute, __cmd__uninstall_residue_execute, __tauri_command_name_uninstall_residue_execute};
// v0.7.0：`commands::residue`（副窗建窗侧）要复用执行侧那对取值闸，AGENTS §5.16/N6 禁止
// 在第二处再写一份「看起来等价」的 app_id 校验。模块本体继续私有，只把这两个判据函数透出去。
pub(crate) use appx::valid_appx_fullname;
pub(crate) use helpers::valid_uninstall_key_path;
#[cfg(test)]
mod residue_trace_tests;
mod residue_update;
pub use residue_update::{residue_rules_dir, residue_watermark, uninstall_modify, __cmd__uninstall_modify, __tauri_command_name_uninstall_modify};
// R-1（2026-10-07）：Run/RunOnce 只读可见面（`reg_value_gate` 仍被 residue 执行链复用）
#[allow(dead_code)]
mod run_keys;
#[allow(dead_code)]
mod services_orphan;
// 服务键形状预筛透出给集成测试：服务/驱动桶候选的 target 天生落在 HKLM\SYSTEM 禁删树内
// （执行走八道判据的窄口子，不走 protect 通用闸），测试断「形状命中窄口子」必须调同一个
// 函数（§5.16/N6），不许在 tests/ 手写第二份前缀匹配。
pub use services_orphan::looks_like_service_key;
#[allow(dead_code)]
mod vendor_registry;

