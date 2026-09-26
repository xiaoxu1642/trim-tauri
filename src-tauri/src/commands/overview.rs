//! overview 域（批次 A）：overview:metrics / overview:hardware / overview:checkup
//!
//! 缓存与在途去重语义（对照 main.js 5195-5379 段）：
//! - metrics：内存缓存 2.5s；采集为**纯原生进程内调用**（无 pwsh；用 std 互斥锁在阻塞线程上
//!   串行化，等价 JS 侧的 overviewMetricsInflight 去重，避免轮询打满进程）——
//!   旧注释「同一时刻最多一个 pwsh 进程」为 Electron 时代遗物（2026-09-25 审计修正）；
//! - hardware：磁盘缓存 system-info.json（首扫落盘，之后读缓存，refresh=true 强扫）；
//!   扫描失败时回落旧缓存并标 degraded:true（不让一次失败把页面清空）；
//! - checkup：磁盘缓存 checkup.json + TTL 30 分钟（F1：原实现永不过期的旧"正常"结论
//!   会在系统恶化时误报，故加 TTL 到期自动重扫）。

use std::sync::Mutex;

use serde_json::Value;
use tauri::WebviewWindow;

use crate::engine::{guard, paths};
use crate::security;

/// metrics 结果缓存与串行锁
static METRICS_CACHE: Mutex<Option<(i64, Value)>> = Mutex::new(None);
static METRICS_LOCK: Mutex<()> = Mutex::new(());
const METRICS_CACHE_TTL_MS: i64 = 2500;
/// CPU 差分用上一拍原始计数（`cpuRaw`）。
/// 对照 main.js 5279-5290：原生引擎无状态，只输出原始 busy/idle 计数，
/// **差分必须由调用方持有**——首拍或计数回绕时 cpu 保持 null（渲染层显示 `--`）。
static CPU_PREV: Mutex<Option<(u64, u64)>> = Mutex::new(None);

const CHECKUP_CACHE_TTL_MS: i64 = 30 * 60 * 1000;

/// 由原始计数差分出 CPU 百分比（对照 main.js cpuPercentFromRaw）
fn cpu_percent_from_raw(raw: Option<&Value>) -> Option<f64> {
    let (busy, idle) = match raw {
        Some(v) => (
            v.get("busy").and_then(|x| x.as_u64())?,
            v.get("idle").and_then(|x| x.as_u64())?,
        ),
        None => return None,
    };
    let mut prev = CPU_PREV.lock().unwrap_or_else(|e| e.into_inner());
    let old = *prev;
    *prev = Some((busy, idle));
    let (pb, pi) = old?; // 首拍
    let busy_delta = busy.checked_sub(pb)?; // 计数回绕 → null
    let idle_delta = idle.checked_sub(pi)?;
    let total = busy_delta + idle_delta;
    if total == 0 {
        return None;
    }
    Some((busy_delta as f64 * 100.0 / total as f64).clamp(0.0, 100.0))
}

/// 原生引擎采集（lib 直调，替代 spawn finder.exe）：返回 (data, engine)
fn collect_metrics_native() -> Result<Value, String> {
    let json = trim_finder::perf::ov_metrics_json();
    let mut data: Value =
        serde_json::from_str(&json).map_err(|e| format!("原生指标解析失败: {e}"))?;
    if data.get("success").and_then(|v| v.as_bool()) != Some(true) {
        return Err("原生采集失败".into());
    }
    // 差分回填 cpu（原生路径下 cpu 恒为 null，必须由调用方补）
    let cpu = cpu_percent_from_raw(data.get("cpuRaw"));
    if let (Some(c), Some(obj)) = (cpu, data.as_object_mut()) {
        obj.insert("cpu".into(), serde_json::json!(c));
    }
    Ok(data)
}

/// overview:metrics — 实时系统指标
///
/// S3：纯 Rust 原生，无 PS 回退。
#[tauri::command]
pub async fn overview_metrics<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Some((at, data)) = METRICS_CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        if crate::engine::now_ms() - at < METRICS_CACHE_TTL_MS {
            return Ok(serde_json::json!({ "success": true, "data": data, "cached": true }));
        }
    }
    let result = tauri::async_runtime::spawn_blocking(move || {
        // 串行化：重叠请求在此排队，保证任一时刻只有一次采集在跑
        let _serialize = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        match collect_metrics_native() {
            Ok(data) => Ok((data, "rust")),
            Err(e) => Err(format!("原生采集失败: {e}")),
        }
    })
    .await;
    match result {
        Ok(Ok((data, engine))) => {
            *METRICS_CACHE.lock().unwrap_or_else(|e| e.into_inner()) =
                Some((crate::engine::now_ms(), data.clone()));
            Ok(serde_json::json!({ "success": true, "data": data, "engine": engine }))
        }
        Ok(Err(message)) => Ok(serde_json::json!({ "success": false, "message": message })),
        Err(e) => Ok(serde_json::json!({ "success": false, "message": format!("采集任务异常: {e}") })),
    }
}

/// overview:hardware — 硬件信息（磁盘缓存优先）
#[tauri::command]
pub async fn overview_hardware<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    refresh: Option<bool>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let refresh = refresh.unwrap_or(false);
    if !refresh {
        if let Some(cached) = load_system_info_cache() {
            return Ok(serde_json::json!({
                "success": true, "data": cached.1, "cached": true, "cachedAt": cached.0
            }));
        }
    }
    let result = tauri::async_runtime::spawn_blocking(crate::commands::device::collect_device_info)
        .await;
    match result {
        Ok(Ok(data)) => {
            save_system_info_cache(&data);
            Ok(serde_json::json!({ "success": true, "data": data, "cached": false }))
        }
        Ok(Err(message)) => {
            // 扫描失败回落旧缓存（degraded），避免一次失败把页面清空
            match load_system_info_cache() {
                Some((at, data)) => Ok(serde_json::json!({
                    "success": true, "data": data, "cached": true, "cachedAt": at, "degraded": true
                })),
                None => Ok(serde_json::json!({ "success": false, "message": message })),
            }
        }
        Err(e) => Ok(serde_json::json!({ "success": false, "message": format!("采集任务异常: {e}") })),
    }
}

fn load_system_info_cache() -> Option<(i64, Value)> {
    let text = std::fs::read_to_string(paths::system_info_file()).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let ts = v.get("timestamp")?.as_i64()?;
    let data = v.get("data")?;
    if data.is_null() {
        return None;
    }
    Some((ts, data.clone()))
}

fn save_system_info_cache(data: &Value) {
    let payload = serde_json::json!({ "timestamp": crate::engine::now_ms(), "data": data });
    if let Err(e) = security::atomic_write_json(&paths::system_info_file(), &payload) {
        crate::engine::log::write_log("error", &format!("保存系统信息缓存失败: {e}"));
    }
}

/// overview:checkup — 系统体检（磁盘缓存 + 30 分钟 TTL）
#[tauri::command]
pub async fn overview_checkup<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    refresh: Option<bool>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let refresh = refresh.unwrap_or(false);
    if !refresh {
        if let Some((ts, data)) = crate::engine::load_scan_cache("checkup.json") {
            if crate::engine::now_ms() - ts < CHECKUP_CACHE_TTL_MS {
                return Ok(serde_json::json!({
                    "success": true,
                    "data": { "checks": data, "at": ts },
                    "cached": true
                }));
            }
        }
    }
    let result = tauri::async_runtime::spawn_blocking(|| {
        match crate::engine::native::overview_checkup() {
            Ok(data) => Ok(data),
            Err(e) => Err(format!("原生体检失败: {e}")),
        }
    })
    .await;
    match result {
        Ok(Ok(parsed)) => {
            // 脚本返回 { checks: [...] }；兼容直接返回数组的历史形态
            let checks = if parsed.is_array() {
                parsed.clone()
            } else {
                parsed.get("checks").cloned().unwrap_or_else(|| serde_json::json!([]))
            };
            crate::engine::save_scan_cache("checkup.json", &checks);
            Ok(serde_json::json!({
                "success": true,
                "data": { "checks": checks, "at": crate::engine::now_ms() }
            }))
        }
        Ok(Err(message)) => Ok(serde_json::json!({ "success": false, "message": message })),
        Err(e) => Ok(serde_json::json!({ "success": false, "message": format!("体检任务异常: {e}") })),
    }
}