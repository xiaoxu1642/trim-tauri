//! B1 PS→Rust 迁移：原生 Windows API 实现（v3 D1 起按功能域分文件）
//!
//! 各域的实现与它的回归测试同文件；本 mod.rs 只做模块声明与对外 re-export，
//! 不承载业务实现。调用方一律用 `native::<符号>`，跨域共享的底层在
//! common.rs / registry.rs / services.rs。
//!
//! 状态：纯原生（方案 S3）。各域 `.ps1` 已删除，本模块是唯一实现，**不存在 PS 回退**；
//! 调用失败一律如实返回错误，权限拒绝、参数非法等不回退，由调用方按错误类型判断。

mod bsod;
mod cleanup;
pub use cleanup::{cleanup_detail, CleanupExecuteResult, cleanup_execute, find_rule_by_id};
mod common;
mod contextmenu;
pub use contextmenu::{cm_win11_mode, cm_blocked_list, cm_restart_explorer, cm_scan, cm_toggle, cm_remove, cm_backup, cm_restore};
mod diagnostics;
pub use diagnostics::{sysdisk, overview_checkup, device_info};
mod maintenance;
pub use maintenance::{task_change, MAINT_CMD_TIMEOUT, maint_run};
pub(crate) use maintenance::{dir_delete_blocked};
mod memory;
pub use memory::{memory_info, NativeProcess, memory_processes};
mod paths_scan;
pub use paths_scan::{paths_scan};
mod peripheral;
pub use peripheral::{peripheral_query, peripheral_apply, peripheral_restore};
mod process;
pub use process::{kill_process, stubborn_kill, stubborn_block};
mod realtime;
pub use realtime::{realtime_adapters, realtime_loss};
mod registry;
pub use registry::{read_reg_binary_opt, read_reg_dword_opt, read_reg_qword_opt, read_hklm_dword, reg_key_exists, reg_key_ensure, reg_key_ensure_checked, reg_key_remove, reg_enum_subkeys_pub, reg_enum_dev_ids, reg_key_last_write_ms, read_reg_string, read_reg_value_text, read_reg_value_faithful, decode_reg_value_bytes, hive_hklm, hive_hkcu, hive_hkcr, hive_hku, hive_hkcc, reg_restore_write, reg_restore_write_checked, file_ads_bytes, reg_enum_value_names_pub, reg_restore_delete};
mod runtimes_net;
pub use runtimes_net::{runtimes_status, netcheck_status, runtimes_repair, netcheck_repair};
mod services;
pub use services::{
    service_exists, service_start_type_is, start_type_from_label, SVC_START_AUTO,
    SVC_START_DISABLED, SVC_START_MANUAL, service_stop_pub, service_set_start_pub,
};
mod startup;
pub use startup::{startup_scan, startup_toggle, startup_delete, startup_add};
mod syspanel;
pub use syspanel::{PagefileEntry, pagefile_apply, pagefile_state, power_plan_apply, power_plan_state};


