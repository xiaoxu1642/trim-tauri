//! 命令安全包装（迁移方案 7.3 安全模型对照的 Rust 侧落点）
//!
//! Electron：`handleSafe/onSafe` 统一注册 + 来源校验（只读白名单外全校验来源）。
//! Tauri：capabilities/default.json 权限白名单 + **每个命令显式校验 Window label**。
//! 多窗口应用不能裸注册 command——子窗口（preview/processManager…）一旦被注入脚本，
//! 裸注册会使其能调用主窗口专属的高危通道。故此包装是 Phase 1 起的强制入口。
//!
//! 注：Phase 0/1 只有主窗口 main；B/C 批起子窗口（models / preview / processManager /
//! residue / actions）也要读自己的配置并写日志——Electron 侧只读通道本就对所有窗口开放
//! （handleSafe 的只读白名单），故这里把子窗口 label 一并纳入。
//! 原 `peripheral` 子窗已退役（外设优化改为主窗应用内弹窗，见 `commands/peripheral.rs`）。

use tauri::{Runtime, WebviewWindow};

use crate::engine::log;

/// 已知应用窗口 label 全集（与 tauri-api.js 的 currentLabel 取值、各域建窗时的 label 一致）
///
/// `residue` 是 v0.5.0 新增的残留扫描副窗（`commands/residue.rs`）；
/// 加这里的同一轮必须同步 `capabilities/subwindows.json`，否则窗口建得出来、
/// 权限却拿不到 IPC。
pub const APP_WINDOWS: &[&str] = &["main", "models", "preview", "processManager", "residue", "actions"];

/// 主窗口 label（多数高危及「主窗专属」通道只允许它调用）
pub const MAIN: &[&str] = &["main"];

/// 残留链（该应用四类残留扫描 + 执行 + 重启后删除登记）专属窗口集。
///
/// v0.7.0 把主窗内联的残留面板整体搬进 `residue` 副窗，这几条命令的**唯一**渲染层调用方
/// 就变成了那扇窗。**现状成员共 5 条**（顺序无关，成员与 `tools/check-guard-tiers.mjs`
/// 的 E 组逐字相等）：`uninstall_residue_scan` / `uninstall_residue_execute` /
/// `uninstall_pending_add` / `uninstall_pending_list` / `uninstall_pending_revoke`。
/// `uninstall_dead_scan` / `uninstall_orphan_scan` / `uninstall_orphan_ignore` /
/// `uninstall_residue_deep_scan` 已随「机-wide 扫描整条退役」删除，不再属于本集。
/// 这里刻意**不**用 `MAIN`、也刻意**不**放宽到 `APP_WINDOWS` 全集：
/// - 用 `MAIN`：副窗一调就判越权，功能 100% 不可用（§3 M1~M3 的老坑）；
/// - 用 `APP_WINDOWS`：注入 `preview` 任一子窗就能拿到「自己扫一遍再删一遍」
///   的完整能力 —— 按 label 分槽的快照只保证「只能执行自己扫出来的东西」，不保证
///   「别的窗口不能自己扫」。
///
/// 新增成员必须同步 `tools/check-guard-tiers.mjs` 的 E 组（双向棘轮）与
/// `capabilities/subwindows.json`，否则窗口建得出来、IPC 判越权。
pub const RESIDUE_WINDOWS: &[&str] = &["residue"];

/// 右键菜单动作面板（`commands/actions.rs`）专属窗口集。
///
/// 这里的两条写侧命令（`actions_apply` / `actions_remove`）会往 `HKCU\Software\Classes`
/// 底下建键删键，合法调用方只有那一扇窗。同 RESIDUE_WINDOWS 的理由：留 MAIN 副窗判越权，
/// 放宽到 APP_WINDOWS 又等于「注入任一子窗就能改右键菜单」。
pub const ACTIONS_WINDOWS: &[&str] = &["actions"];

/// 校验调用来源窗口；返回 label 或错误消息（错误消息直接回给渲染层）。
/// 校验失败同时写日志——静默拒绝会掩盖注入尝试。
pub fn guard<R: Runtime>(window: &WebviewWindow<R>, allowed: &[&str]) -> Result<String, String> {
    let label = window.label().to_string();
    if allowed.contains(&label.as_str()) {
        Ok(label)
    } else {
        log::write_log(
            "error",
            &format!("IPC 来源校验失败: 窗口 '{label}' 无权调用该通道（未知来源或已越权）"),
        );
        Err(format!("IPC 来源校验失败: 窗口 '{label}' 无权调用该通道"))
    }
}

/// 宽松档：放行**全部已知应用窗口**（含四个子窗），用于非主窗专属的通道。
///
/// ⚠️ 名字里的 readonly 是 Electron 侧 `handleSafe` 只读白名单的历史叫法，
/// **它不校验副作用、也不排除子窗口**——判据只有「label 在 `APP_WINDOWS` 内」。
/// 因此「能不能被子窗调到」由这里选哪一档决定，与命令本身是否只读无关。
/// 真正的读/写差异在命令体内（路径绑定、快照槽、`is_path_protected` 等）。
/// 需要主窗专属的通道请显式用 `guard(window, MAIN)`。
pub fn guard_readonly<R: Runtime>(window: &WebviewWindow<R>) -> Result<String, String> {
    guard(window, APP_WINDOWS)
}