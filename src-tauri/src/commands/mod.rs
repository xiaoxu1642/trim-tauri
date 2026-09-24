//! IPC 命令注册面（迁移方案 7.2：一域一文件）
//!
//! 命令命名：Rust snake_case，`<域>_<动作>`；适配层 CHANNEL_MAP 是通道名的唯一真源（D2）。
//! 新增命令必须同时登记 CHANNEL_MAP 与一致性断言，防"Rust 有了、前端没接"的静默断裂。

pub mod app;
pub mod device;
pub mod log;
pub mod misc;
pub mod overview;
pub mod paths;
pub mod realtime;
pub mod spike;
pub mod system;
// ---- B 批（只读扫描 + 安全与运行时）----
pub mod finder;
pub mod memory;
pub mod netcheck;
pub mod netspeed;
pub mod diskbench;
pub mod preview;
pub mod processmanager;
pub mod pwshruntime;
pub mod runtimes;
// ---- C 批（安全与规则）----
pub mod cleanup;
pub mod models;
pub mod settings;
pub mod aidesc;
pub mod quickcmds;
pub mod benchhistory;
pub mod fonts;
// ---- D 批（删除与高危）----
pub mod fileclean;
pub mod contextmenu;
pub mod startup;
pub mod peripheral;
pub mod optimizer;
pub mod maintenance;