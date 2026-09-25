//! system 域（批次 A）：system:disk-type —— 系统盘介质类型（SSD/HDD）探测
//!
//! 供「电脑优化中心」与「磁盘清理」按硬件显隐预读相关选项：判定失败一律返回
//! success:false，渲染层按 unknown 处理（两边都不隐藏）——绝不让探测失败
//! 反而藏掉用户要用的选项。系统盘介质不会变化，进程内缓存一次即可。

use std::sync::Mutex;
use std::time::Duration;

use tauri::WebviewWindow;

use crate::engine::guard;
use crate::pwsh;

/// PS 脚本编译期嵌入（源：src/scripts-powershell/sysdisk-scripts.js，逐字搬运）
const SYSDISK_PS: &str = include_str!("../../ps/sysdisk.ps1");

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
        // B10 S2：默认原生，TRIM_LEGACY_SYSDISK=1 回退 PS
        let legacy = std::env::var("TRIM_LEGACY_SYSDISK").map(|v| v == "1").unwrap_or(false);
        if !legacy {
            match crate::engine::native::sysdisk() {
                Ok(data) => return Ok(data),
                Err(e) => return Err(format!("原生探测失败（设 TRIM_LEGACY_SYSDISK=1 可回退 PS）: {e}")),
            }
        }
        let script = pwsh::write_temp_script(SYSDISK_PS, ".ps1")?;
        let out = pwsh::run_file(&script, Duration::from_secs(30), Some("system:disk-type"));
        let _ = std::fs::remove_file(&script);
        let out = out?;
        if out.code != 0 {
            return Err(if out.stderr.trim().is_empty() {
                "系统盘介质探测失败".into()
            } else {
                out.stderr.trim().to_string()
            });
        }
        serde_json::from_str::<serde_json::Value>(out.stdout.trim())
            .map_err(|e| format!("系统盘介质解析失败: {e}"))
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