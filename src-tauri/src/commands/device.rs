//! device 域（批次 A）：device:scan —— 设备信息采集（只读 CIM/WMI，不访问网络）

use tauri::WebviewWindow;

use crate::engine::guard;
use crate::pwsh;

/// PS 脚本编译期嵌入（源：src/scripts-powershell/device-info-scripts.js，逐字搬运）
const DEVICE_INFO_PS: &str = include_str!("../../ps/device_info.ps1");

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

/// 跑一次设备信息采集（超时 60s，与 Electron 版同值）
pub(crate) fn collect_device_info() -> Result<serde_json::Value, String> {
    let script = pwsh::write_temp_script(DEVICE_INFO_PS, ".ps1")?;
    let result = pwsh::run_file(&script, std::time::Duration::from_secs(60), Some("device:scan"));
    let _ = std::fs::remove_file(&script);
    let out = result?;
    if out.code != 0 {
        return Err(if out.stderr.trim().is_empty() {
            "设备信息扫描失败".into()
        } else {
            out.stderr.trim().to_string()
        });
    }
    serde_json::from_str(out.stdout.trim()).map_err(|e| format!("设备信息解析失败: {e}"))
}