//! log 域（批次 A）：log:write / log:read / log:export

use tauri::{AppHandle, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::engine::{guard, log};

/// log:write — 直接透传渲染层入参，level/message 强制转字符串（LOG-2 兜底）
#[tauri::command]
pub fn log_write<R: tauri::Runtime>(window: WebviewWindow<R>, level: String, message: String) -> Result<String, String> {
    guard::guard_readonly(&window)?;
    Ok(log::write_log(&level, &message))
}

/// log:read — 默认当天；日期格式白名单防路径穿越；只取末尾 512KB 并丢弃半行
#[tauri::command]
pub fn log_read<R: tauri::Runtime>(window: WebviewWindow<R>, date: Option<String>) -> Result<String, String> {
    guard::guard_readonly(&window)?;
    Ok(log::read_log(date.as_deref()))
}

/// log:export — 原生保存对话框选目标文件后复制当天日志
#[tauri::command]
pub async fn log_export<R: tauri::Runtime>(app: AppHandle<R>, window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let file = app
        .dialog()
        .file()
        .set_title("导出日志")
        .set_file_name(format!("Trim-log-{}.txt", crate::engine::now_ms()))
        .add_filter("文本文件", &["txt", "log"])
        .blocking_save_file();
    let Some(path) = file else {
        return Ok(serde_json::json!({ "success": false, "message": "已取消" }));
    };
    let dest = path
        .into_path()
        .map_err(|e| format!("无效的保存路径: {e}"))?;
    match log::export_log(&dest) {
        Ok(()) => Ok(serde_json::json!({
            "success": true,
            "path": dest.to_string_lossy(),
        })),
        Err(e) => Ok(serde_json::json!({ "success": false, "message": e })),
    }
}