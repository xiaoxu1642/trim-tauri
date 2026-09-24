//! 命令安全包装（迁移方案 7.3 安全模型对照的 Rust 侧落点）
//!
//! Electron：`handleSafe/onSafe` 统一注册 + 来源校验（只读白名单外全校验来源）。
//! Tauri：capabilities/default.json 权限白名单 + **每个命令显式校验 Window label**。
//! 多窗口应用不能裸注册 command——子窗口（preview/processManager…）一旦被注入脚本，
//! 裸注册会使其能调用主窗口专属的高危通道。故此包装是 Phase 1 起的强制入口。
//!
//! 注：Phase 0/1 只有主窗口 main；B/C 批起子窗口（models / preview / processManager /
//! peripheral）也要读自己的配置并写日志——Electron 侧只读通道本就对所有窗口开放
//! （handleSafe 的只读白名单），故这里把四个子窗口 label 一并纳入。

use tauri::{Runtime, WebviewWindow};

use crate::engine::log;

/// 已知应用窗口 label 全集（与 tauri-api.js 的 currentLabel 取值、各域建窗时的 label 一致）
pub const APP_WINDOWS: &[&str] = &["main", "models", "preview", "processManager", "peripheral"];

/// 主窗口 label（多数高危及「主窗专属」通道只允许它调用）
pub const MAIN: &[&str] = &["main"];

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

/// 只读通道便捷包装（当前与 guard 同实现；保留命名以对齐 7.3 的只读白名单语义，
/// 后续若为只读通道放开子窗口，只改这一处）
pub fn guard_readonly<R: Runtime>(window: &WebviewWindow<R>) -> Result<String, String> {
    guard(window, APP_WINDOWS)
}