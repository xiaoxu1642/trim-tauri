//! Trim 原生引擎库（Phase 1 lib 化）
//!
//! 背景与目标（迁移方案 B 批 / C5 / Phase 4）：
//! - 原形态是纯 CLI（`finder.exe`），以 `@@ITEM@@{json}` / `@@PROGRESS:n@@` 行协议向
//!   Electron 主进程输出；Tauri 侧若继续 spawn 子进程，则「高频轮询」类命令
//!   （ov-metrics 每 ~2.5s 一拍）会持续付出进程创建成本。
//! - lib 化后 Tauri 可直接函数直调；CLI 入口**原样保留**供独立调试
//!   （Phase 5 只移除 [[bin]] 的分发配置，不移除调试入口）。
//!
//! 骨架约定：
//! - 模块声明集中在 lib.rs；bin（main.rs）改为 `use trim_finder::...`，不再重复声明模块
//!   （否则同一模块会被编译两份）。
//! - `util` 的三个助手在 crate 根重导出，使 `crate::json_escape` 等既有写法零改动
//!   ——这是本次 lib 化能做到「CLI 行为逐字不变」的关键。
//!
//! 现阶段的边界（诚实说明）：
//! - `cleanup_scan` 的入口仍以「写 stdout」为输出方向（B 批未触及）。
//! - `perf` 提供**数据返回式**接口：`ov_metrics_json` / `mem_clean_json` / `diskbench_json`
//!   与 `NetSampler`（见 perf.rs），Tauri 侧直接函数直调。
//! - 扫描类命令（duplicates/bigfiles/empty/appdata/sizes/delete）已迁到 `scan` 模块，
//!   输出方向反转成 `Sink` 回调；CLI（main.rs）用 `StdoutSink` 原样写回 stdout，
//!   保证对外可观测行为逐字节不变。

pub mod cleanup_scan;
pub mod perf;
pub mod scan;
pub mod util;

// 保持 `crate::json_escape` / `crate::is_reparse` / `crate::to_long_path` 既有引用可解析
pub use util::{is_reparse, json_escape, to_long_path};