//! optimizer 域（D 批）：优化中心 17 条通道
//!
//! 对照 Electron main.js 2825-3875、5145-5174 + src/scripts-powershell/optimizer-scripts.js。
//!
//! 本文件第一批：list / run / check-optimized / state-overview / svc-mem-current，
//! 外加 PS 脚本生成器 build_script、动态步骤、fail-closed 记账（engine::optimization_state）。
//!
//! 关键安全/语义（OPT-1/R1/R2/OPT-3/OPT-5/B-2 全部保留）：
//! - run 恒需管理员；高危 id 需渲染层红色确认回执（正向与还原方向都卡，R2）。
//! - 还原方向必须有专属 restore 步骤，禁止回落正向步骤（R2）。
//! - 执行前先记账 pending（写不进就不改系统）；成功后回读校验再 markApplied。
//! - reg 临时文件写 TRIM_TMP 加固目录、Unicode 编码（OPT-3）；服务名/标签单引号字面量。
//! - @@RECYCLE@@ 协议：删除目标回主进程，受保护路径拒绝、其余进回收站（B-2）。
//! - WU 暂停天数服务端钳制 1~35，FILETIME 在 PS 内算（渲染层不参与）。
//!
//! v3 D4（2026-10-02）按契约拆成 commands/optimizer/ 目录：catalog（选项数据 + 生效粒度
//! + 退役账本 + 高危表）/ apply（PS 脚本构建、动态与原生步骤、optimizer_run、回读验证、
//! RunParams 与在途互斥）/ overview（只读视图与 .reg 期望值解析）/
//! backup_restore（值级备份与还原）/ restore_point（系统还原点）/ advice（genadvice）；
//! 跨面用例单独放 contract_tests（cfg(test)）。`#[tauri::command]` 留在定义处，
//! mod.rs 只做模块声明与 pub use 台账，命令签名、generate_handler! 与 guard 档位零改动。

mod advice;
pub use advice::{optimizer_genadvice, __cmd__optimizer_genadvice, __tauri_command_name_optimizer_genadvice};
mod apply;
pub use apply::{RunParams, optimizer_run, __cmd__optimizer_run, __tauri_command_name_optimizer_run};
mod backup_restore;
pub use backup_restore::{optimizer_backup_reg, __cmd__optimizer_backup_reg, __tauri_command_name_optimizer_backup_reg, optimizer_restore_reg, __cmd__optimizer_restore_reg, __tauri_command_name_optimizer_restore_reg};
mod subitems;
mod catalog;
#[cfg(test)]
mod contract_tests;
mod overview;
pub use overview::{optimizer_list, __cmd__optimizer_list, __tauri_command_name_optimizer_list, optimizer_svc_mem_current, __cmd__optimizer_svc_mem_current, __tauri_command_name_optimizer_svc_mem_current, optimizer_check_optimized, __cmd__optimizer_check_optimized, __tauri_command_name_optimizer_check_optimized, optimizer_batch_preflight, __cmd__optimizer_batch_preflight, __tauri_command_name_optimizer_batch_preflight, optimizer_state_overview, __cmd__optimizer_state_overview, __tauri_command_name_optimizer_state_overview, optimizer_stale_dismiss, __cmd__optimizer_stale_dismiss, __tauri_command_name_optimizer_stale_dismiss, optimizer_list_groups, __cmd__optimizer_list_groups, __tauri_command_name_optimizer_list_groups, optimizer_touch_recent, __cmd__optimizer_touch_recent, __tauri_command_name_optimizer_touch_recent};
mod restore_point;
pub use restore_point::{optimizer_check_restore, __cmd__optimizer_check_restore, __tauri_command_name_optimizer_check_restore, optimizer_create_restore, __cmd__optimizer_create_restore, __tauri_command_name_optimizer_create_restore, optimizer_list_restore, __cmd__optimizer_list_restore, __tauri_command_name_optimizer_list_restore};

