//! device 域（批次 A）：device:scan —— 设备信息采集（只读，注册表+系统 API）
//!
//! S3：已删除 PS 回退，纯 Rust 原生实现（注册表读取系统/CPU/GPU/主板/磁盘信息，
//! GetPhysicallyInstalledSystemMemory 读取内存）。

use tauri::WebviewWindow;

use crate::engine::guard;

#[tauri::command]
pub async fn device_scan<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let result = tauri::async_runtime::spawn_blocking(|| collect_device_info()).await;
    match result {
        Ok(Ok(data)) => Ok(serde_json::json!({ "success": true, "data": data })),
        Ok(Err(message)) => Ok(serde_json::json!({ "success": false, "message": message })),
        Err(e) => Ok(serde_json::json!({ "success": false, "message": format!("采集任务异常: {e}") })),
    }
}

/// 跑一次设备信息采集（注册表+系统 API）
pub(crate) fn collect_device_info() -> Result<serde_json::Value, String> {
    crate::engine::native::device_info().map_err(|e| format!("原生采集失败: {e}"))
}
