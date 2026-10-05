//! cleanup 域（C 批）：cleanup 9 条通道（规则库 / 扫描 / 执行 / 占用检测 / 明细）
//!
//! 对照 Electron `main.js` 1188-2042（含规则在线更新 1560-1786）。
//!
//! 迁移要点：
//! - **规则库**：内置规则编译期嵌入（`include_str!`，与 Electron `src/data/cleanup-rules.json`
//!   逐字节一致）；数据目录规则必须过 `engine::rules_signature` 验签 + 防回滚水位线
//!   `<数据目录>\cleanup\rules-watermark.json`（只升不降），不通过一律回退内置。
//!   `custom\*.json` 只允许 `{id, enabled}` 开关内置条目（白名单外字段整文件拒载）。
//! - **扫描引擎**：纯原生（`trim_finder::cleanup_scan::run_json` 进程内直调，逐行回调
//!   驱动 `cleanup:scan-progress`）。失败/非 0 退出如实返回错误——旧「回退 PS 引擎
//!   （`ps/cleanup_scan.ps1` 模板替换后执行）」分支已随脚本删除退役；本段注释曾长期
//!   与代码事实不符（2026-09-25 审计修正）。
//! - **PS 残留**：`src-tauri/ps/` 现仅余哨兵模板 `optimizer_build.ps1`（R1，2026-10-01：
//!   `cm_icons.ps1` 随右键图标改原生 `ExtractIconExW` 退役），由
//!   `tools/check-ps-extraction.mjs` 继续对拍（check-ps-substitution 已随 S3 退役，D-2）。
//!   cleanup 域自身的模板替换链已随脚本删除一并退役。
//! - **快照槽**：扫描快照 / 回收站失败项 / 占用检测 PID 白名单全部按 `window.label()` 分槽
//!   （Electron 按 `event.sender.id`），执行与结束进程只认本槽内容。
//! - **删除安全**：受保护路径判定统一走 `engine::protect`（三端同源）；危险操作前
//!   `log::flush_sync()`；回收站优先（`trim_finder::scan::recycle::send_to_trash`），
//!   回收站失败项留槽等渲染层红色确认后再永久删除。
//! - **HTTP 已接入**：`cleanup:update-rules` / `cleanup:check-rules-version` 走
//!   `engine::winhttp::get_text`（不新增 Cargo 依赖），全链为来源清单 → 尺寸闸 →
//!   ed25519 验签 → 结构校验 → 版本防降级 → 字节级原子落盘 → 抬水位线，git 回退仅开发机。
//!
//! 需在 `lib.rs` 的 `generate_handler!` 注册：
//! ```text
//! // ---- C 批：cleanup ----
//! commands::cleanup::cleanup_rules,
//! commands::cleanup::cleanup_scan,
//! commands::cleanup::cleanup_execute,
//! commands::cleanup::cleanup_retry_failed_delete,
//! commands::cleanup::cleanup_item_detail,
//! commands::cleanup::cleanup_update_rules,
//! commands::cleanup::cleanup_check_rules_version,
//! commands::cleanup::cleanup_check_locked,
//! commands::cleanup::cleanup_kill_locked_processes,
//! ```
//!
//! 与 Electron 的已知差异（如实登记，供双跑对照时豁免）：
//! 1. **在途清理计数**：Electron 的 `activeCleanupRuns` 供「关窗后台静默退出等删除任务归零」用，
//!    属 Phase 2 的关闭编排，本批未引入（清理命令本身的返回语义一致）。
//! 2. **无 60s 占用检测超时**：原生 `checklocked` 进程内直调不可 kill，故不返回
//!    「占用检测超时」（与 B 批 finder 扫描同一处置，见 commands/finder.rs 差异 1）。
//! 3. **（已失效，v3-M5 订正）**：旧版曾有「原生不可用回退 PS 时进度改为一次性解析」
//!    的差异——PS 回退引擎已随 S3 删除（见 :11），cleanup:scan 现在只有原生路径，
//!    始终边扫边发 `cleanup:scan-progress`。保留编号只为对照历史审查记录。
//! 4. **快照回收**：Electron 在 webContents destroy 时删桶；这里按 `window.label()` 分槽
//!    且 `guard` 只放行 main（唯一槽），未注册 destroy 钩子。
//! 5. **结束进程失败文案**：Node `process.kill` 抛 errno 文案（ESRCH/EPERM），
//!    Rust 侧用 TerminateProcess 的可读文案（`{...p, message}` 字段形状一致）。
//! 6. **HTTP 传输层**：已接 `engine::winhttp`（见上），真网用例是 `#[ignore]` 的发布前
//!    门禁用例（`cargo test --lib -- --ignored`），日常 `cargo test` 不触网。

//!
//! v3 D3（2026-10-02）按命令契约拆成 commands/cleanup/ 目录：
//! rules（规则库装载与语义校验）/ state（路径绑定 + 分槽快照 + JS 口径）/
//! backup（reg 与 file 两类备份还原入口）/ scan_execute（扫描、执行、重试、明细、锁定进程）/
//! rules_update（在线更新）；跨面的验收用例单独放 contract_tests（cfg(test)）。
//! `#[tauri::command]` 留在定义处，mod.rs 只做模块声明与 pub use 台账，
//! 因此 lib.rs 的 generate_handler!、CHANNEL_MAP 与 guard 档位不因物理移动改变。

mod backup;
pub use backup::{cleanup_reg_backup_list, __cmd__cleanup_reg_backup_list, __tauri_command_name_cleanup_reg_backup_list, cleanup_reg_backup_restore, __cmd__cleanup_reg_backup_restore, __tauri_command_name_cleanup_reg_backup_restore, cleanup_file_backup_list, __cmd__cleanup_file_backup_list, __tauri_command_name_cleanup_file_backup_list, cleanup_file_backup_restore, __cmd__cleanup_file_backup_restore, __tauri_command_name_cleanup_file_backup_restore};
mod rules;
pub use rules::{data_rules_dir, rules_watermark, set_rules_watermark, rules_value, cleanup_rules, __cmd__cleanup_rules, __tauri_command_name_cleanup_rules};
pub(crate) use rules::{release_source_urls_for};
mod rules_update;
pub use rules_update::{cleanup_update_rules, __cmd__cleanup_update_rules, __tauri_command_name_cleanup_update_rules, cleanup_check_rules_version, __cmd__cleanup_check_rules_version, __tauri_command_name_cleanup_check_rules_version};
pub(crate) use rules_update::{load_update_override, assemble_sources, http_get_limited};
mod scan_execute;
pub use scan_execute::{cleanup_scan, __cmd__cleanup_scan, __tauri_command_name_cleanup_scan, cleanup_execute, __cmd__cleanup_execute, __tauri_command_name_cleanup_execute, cleanup_retry_failed_delete, __cmd__cleanup_retry_failed_delete, __tauri_command_name_cleanup_retry_failed_delete, cleanup_item_detail, __cmd__cleanup_item_detail, __tauri_command_name_cleanup_item_detail, cleanup_check_locked, __cmd__cleanup_check_locked, __tauri_command_name_cleanup_check_locked, cleanup_kill_locked_processes, __cmd__cleanup_kill_locked_processes, __tauri_command_name_cleanup_kill_locked_processes, cleanup_export_plan, __cmd__cleanup_export_plan, __tauri_command_name_cleanup_export_plan};
mod state;

#[cfg(test)]

#[cfg(test)]
mod contract_tests;
