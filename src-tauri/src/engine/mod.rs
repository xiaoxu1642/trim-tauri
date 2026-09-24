//! 跨域共用基础设施（迁移方案 7.2：跨域共用逻辑下沉 engine/）
//!
//! 本模块只放**被多个命令域共用**的东西：路径解析、日志、来源校验、扫描缓存。
//! 单一域专用的实现留在对应 commands/<domain>.rs 内，避免 engine 变成杂物间。

pub mod appearance;
pub mod delete_manifest;
pub mod guard;
pub mod log;
pub mod optimization_state;
pub mod paths;
pub mod protect;
pub mod rules_signature;
pub mod shellicon;
pub mod sysinfo;
pub mod winhttp;

use serde_json::Value;

/// 扫描结果持久缓存（对照 main.js loadScanCache/saveScanCache）
/// 结构 `{ timestamp: <ms>, data: <任意> }`；缓存不可用返回 None。
pub fn load_scan_cache(name: &str) -> Option<(i64, Value)> {
    let file = paths::scan_cache_file(name);
    let text = std::fs::read_to_string(&file).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let ts = v.get("timestamp")?.as_i64()?;
    let data = v.get("data")?;
    if data.is_null() {
        return None;
    }
    Some((ts, data.clone()))
}

/// 写扫描缓存（原子写，失败只记日志）
pub fn save_scan_cache(name: &str, data: &Value) -> bool {
    let file = paths::scan_cache_file(name);
    let payload = serde_json::json!({ "timestamp": now_ms(), "data": data });
    match crate::security::atomic_write_json(&file, &payload) {
        Ok(()) => true,
        Err(e) => {
            log::write_log("error", &format!("保存扫描缓存 {name} 失败: {e}"));
            false
        }
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}