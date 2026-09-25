//! netspeed 域（B 批）：netspeed:ping / netspeed:throughput
//!
//! 实现体来源：main.js 5767-5794（本地回环 TCP 延迟/吞吐，只读）。
//! S3：已删除 PS 回退，纯 Rust 原生实现。

use serde_json::{json, Value};
use tauri::WebviewWindow;

use crate::engine::{guard, native};

/// netspeed:ping — 回环 TCP 延迟测试
///
/// S3：纯 Rust 原生，无 PS 回退。
#[tauri::command]
pub async fn netspeed_ping<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    match tauri::async_runtime::spawn_blocking(native::netspeed_ping).await {
        Ok(Ok(v)) => Ok(json!({ "success": true, "data": v, "engine": "rust" })),
        Ok(Err(e)) => Ok(json!({ "success": false, "message": format!("原生测速失败: {e}") })),
        Err(e) => Ok(json!({ "success": false, "message": format!("Ping 任务异常: {e}") })),
    }
}

/// netspeed:throughput — 上下行吞吐测速（本地回环）
///
/// S3：纯 Rust 原生，无 PS 回退。
#[tauri::command]
pub async fn netspeed_throughput<R: tauri::Runtime>(window: WebviewWindow<R>, duration: Option<f64>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let requested = match duration {
        Some(n) if n.is_finite() && n != 0.0 => n,
        _ => 10.0,
    };
    let secs = requested.max(1.0).min(60.0);
    match tauri::async_runtime::spawn_blocking(move || native::netspeed_throughput(secs)).await {
        Ok(Ok(v)) => Ok(json!({ "success": true, "data": v, "engine": "rust" })),
        Ok(Err(e)) => Ok(json!({ "success": false, "message": format!("原生测速失败: {e}") })),
        Err(e) => Ok(json!({ "success": false, "message": format!("测速任务异常: {e}") })),
    }
}
