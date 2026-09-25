//! system 域（批次 A）：system:disk-type —— 系统盘介质类型（SSD/HDD）探测
//!
//! 供「电脑优化中心」与「磁盘清理」按硬件显隐预读相关选项：判定失败一律返回
//! success:false，渲染层按 unknown 处理（两边都不隐藏）——绝不让探测失败
//! 反而藏掉用户要用的选项。系统盘介质不会变化，进程内缓存一次即可。
//! S3：已删除 PS 回退，纯 Rust 原生实现。

use std::sync::Mutex;

use tauri::WebviewWindow;

use crate::engine::guard;

static CACHE: Mutex<Option<serde_json::Value>> = Mutex::new(None);

#[tauri::command]
pub async fn system_disk_type<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    refresh: Option<bool>,
) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let refresh = refresh.unwrap_or(false);
    if !refresh {
        if let Some(cached) = CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Ok(serde_json::json!({ "success": true, "data": cached, "cached": true }));
        }
    }
    let result = tauri::async_runtime::spawn_blocking(|| {
        match crate::engine::native::sysdisk() {
            Ok(data) => Ok(data),
            Err(e) => Err(format!("原生探测失败: {e}")),
        }
    })
    .await;

    match result {
        Ok(Ok(data)) => {
            *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some(data.clone());
            Ok(serde_json::json!({ "success": true, "data": data, "cached": false }))
        }
        Ok(Err(message)) => Ok(serde_json::json!({ "success": false, "message": message })),
        Err(e) => Ok(serde_json::json!({ "success": false, "message": format!("探测任务异常: {e}") })),
    }
}
