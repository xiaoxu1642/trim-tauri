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
//! residue_update / ownership / dead / backup_report / pending_delete；
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
mod authenticode;
mod capability_orphan;
mod backup_report;
pub use backup_report::{uninstall_reg_backup_list, __cmd__uninstall_reg_backup_list, __tauri_command_name_uninstall_reg_backup_list, uninstall_reg_backup_restore, __cmd__uninstall_reg_backup_restore, __tauri_command_name_uninstall_reg_backup_restore, uninstall_batch_list, __cmd__uninstall_batch_list, __tauri_command_name_uninstall_batch_list, uninstall_batch_restore, __cmd__uninstall_batch_restore, __tauri_command_name_uninstall_batch_restore, uninstall_report_list, __cmd__uninstall_report_list, __tauri_command_name_uninstall_report_list, uninstall_report_get, __cmd__uninstall_report_get, __tauri_command_name_uninstall_report_get};
mod dead;
mod drivers_orphan;
pub use dead::{uninstall_dead_scan, __cmd__uninstall_dead_scan, __tauri_command_name_uninstall_dead_scan};
mod game_platform_orphan;
mod helpers;
mod ifeo_orphan;
mod list_run;
mod minifilter_orphan;
pub use list_run::{uninstall_dir_size, __cmd__uninstall_dir_size, __tauri_command_name_uninstall_dir_size, uninstall_list, __cmd__uninstall_list, __tauri_command_name_uninstall_list, uninstall_run, __cmd__uninstall_run, __tauri_command_name_uninstall_run};
mod ownership;
pub use ownership::{uninstall_orphan_scan, __cmd__uninstall_orphan_scan, __tauri_command_name_uninstall_orphan_scan, uninstall_orphan_ignore, __cmd__uninstall_orphan_ignore, __tauri_command_name_uninstall_orphan_ignore};
mod pending_delete;
pub use pending_delete::{uninstall_pending_add, __cmd__uninstall_pending_add, __tauri_command_name_uninstall_pending_add, uninstall_pending_list, __cmd__uninstall_pending_list, __tauri_command_name_uninstall_pending_list, uninstall_pending_revoke, __cmd__uninstall_pending_revoke, __tauri_command_name_uninstall_pending_revoke};
mod residue;
pub use residue::{uninstall_residue_scan, __cmd__uninstall_residue_scan, __tauri_command_name_uninstall_residue_scan, uninstall_residue_execute, __cmd__uninstall_residue_execute, __tauri_command_name_uninstall_residue_execute};
mod residue_deep;
pub use residue_deep::{uninstall_residue_deep_scan, __cmd__uninstall_residue_deep_scan, __tauri_command_name_uninstall_residue_deep_scan};
#[cfg(test)]
mod residue_trace_tests;
mod residue_update;
pub use residue_update::{residue_rules_dir, residue_watermark, set_residue_watermark, uninstall_modify, __cmd__uninstall_modify, __tauri_command_name_uninstall_modify, uninstall_check_residue_version, __cmd__uninstall_check_residue_version, __tauri_command_name_uninstall_check_residue_version, uninstall_update_residue_rules, __cmd__uninstall_update_residue_rules, __tauri_command_name_uninstall_update_residue_rules};
mod services_orphan;
mod vendor_registry;

