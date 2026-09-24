//! netspeed 域（B 批）：netspeed:ping / netspeed:throughput
//!
//! 需在 lib.rs 的 invoke_handler 中注册（本任务不改 lib.rs，请统一登记）：
//!   commands::netspeed::netspeed_ping,
//!   commands::netspeed::netspeed_throughput,
//!
//! 实现体来源：main.js 5767-5794（本地回环 TCP 延迟/吞吐，只读）。
//! - ping：脚本 `netspeed_ping.ps1`，超时 8s；code 0 且 JSON 可解析 → `{success:true,data}`，
//!   否则 `{success:false,message}`（超时文案 'Ping 测试超时，请重试'、其余 'Ping 测试失败'）。
//! - throughput：脚本 `netspeed_throughput.ps1`，哨兵 `987654321` 替换为校验后的时长秒数
//!   `clamp(1,60)`（`Number(duration) || 10` 同口径），替换后校验哨兵已消失；
//!   超时 `duration*1000 + 15000` ms；文案 '测速超时，请重试' / `stderr || '测速失败'`。

use std::time::Duration;

use serde_json::{json, Value};
use tauri::WebviewWindow;

use crate::engine::guard;
use crate::pwsh;

/// PS 脚本编译期嵌入（生成自源仓库，见 tools/sync-ps-from-js.mjs）
const NETSPEED_PING_PS: &str = include_str!("../../ps/netspeed_ping.ps1");
const NETSPEED_THROUGHPUT_PS: &str = include_str!("../../ps/netspeed_throughput.ps1");

/// 吞吐脚本的时长哨兵（生成期占位值 987654321）
const DURATION_SENTINEL: &str = "987654321";

/// 写临时脚本并执行，执行后删除（返回原始 PsOutput）
fn run_script(script: &str, timeout: Duration, op: &str) -> Result<pwsh::PsOutput, String> {
    let path = pwsh::write_temp_script(script, ".ps1")?;
    let out = pwsh::run_file(&path, timeout, Some(op));
    let _ = std::fs::remove_file(&path);
    out
}

/// netspeed:ping — 网络延迟/抖动探测
#[tauri::command]
pub async fn netspeed_ping<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let result =
        tauri::async_runtime::spawn_blocking(|| run_script(NETSPEED_PING_PS, Duration::from_secs(8), "netspeed:ping"))
            .await;
    Ok(match result {
        Ok(Ok(out)) => {
            if out.code == 0 {
                if let Ok(v) = serde_json::from_str::<Value>(out.stdout.trim()) {
                    return Ok(json!({ "success": true, "data": v }));
                }
            }
            json!({
                "success": false,
                "message": if out.timed_out { "Ping 测试超时，请重试" } else { "Ping 测试失败" }
            })
        }
        Ok(Err(message)) => json!({ "success": false, "message": message }),
        Err(e) => json!({ "success": false, "message": format!("Ping 任务异常: {e}") }),
    })
}

/// netspeed:throughput — 上下行吞吐测速（本地回环）
#[tauri::command]
pub async fn netspeed_throughput<R: tauri::Runtime>(window: WebviewWindow<R>, duration: Option<f64>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    // 对齐 JS：Number(duration) || 10，再 clamp(1,60)
    let requested = match duration {
        Some(n) if n.is_finite() && n != 0.0 => n,
        _ => 10.0,
    };
    let secs = requested.max(1.0).min(60.0);

    let script = NETSPEED_THROUGHPUT_PS.replace(DURATION_SENTINEL, &format!("{secs}"));
    if script.contains(DURATION_SENTINEL) {
        return Ok(json!({ "success": false, "message": "测速脚本时长替换失败" }));
    }
    let timeout = Duration::from_millis((secs * 1000.0) as u64 + 15_000);

    let result = tauri::async_runtime::spawn_blocking(move || {
        run_script(&script, timeout, "netspeed:throughput")
    })
    .await;
    Ok(match result {
        Ok(Ok(out)) => {
            if out.code == 0 {
                if let Ok(v) = serde_json::from_str::<Value>(out.stdout.trim()) {
                    return Ok(json!({ "success": true, "data": v }));
                }
            }
            let message = if out.timed_out {
                "测速超时，请重试".to_string()
            } else if out.stderr.trim().is_empty() {
                "测速失败".to_string()
            } else {
                out.stderr.trim().to_string()
            };
            json!({ "success": false, "message": message })
        }
        Ok(Err(message)) => json!({ "success": false, "message": message }),
        Err(e) => json!({ "success": false, "message": format!("测速任务异常: {e}") }),
    })
}