//! 跨域共用基础设施（迁移方案 7.2：跨域共用逻辑下沉 engine/）
//!
//! 本模块只放**被多个命令域共用**的东西：路径解析、日志、来源校验、扫描缓存。
//! 单一域专用的实现留在对应 commands/<domain>.rs 内，避免 engine 变成杂物间。

pub mod appearance;
pub mod delete_manifest;
pub mod guard;
pub mod hash;
pub mod log;
pub mod native;
pub mod optimization_state;
pub mod paths;
/// A3 PnP 设备原生侧（只读 spike，未接任何 IPC 命令）
pub mod pnp;
pub mod protect;
pub mod reg_backup;
pub mod restore_pack;
pub mod pssteps;
pub mod rule_schema;
pub mod rules_signature;
pub mod shellicon;
pub mod snapshot;
/// A11 还原点原生侧（只读 spike，未接任何 IPC 命令）
pub mod sysrestore;
pub mod sysinfo;
pub mod systembin;
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

/// Unix 天数（1970-01-01 起）→ 公历 `(年, 月, 日)`。
///
/// Howard Hinnant `civil_from_days`（含闰年修正）。P2-3（审查 2026-10-07）：该算法此前在
/// `engine::log` / `engine::delete_manifest` / `commands::settings` /
/// `commands::uninstall::list_run` / `commands::optimizer::restore_point` 各存一份，
/// 收敛为这里的唯一实现。（`native-scanner` 是独立 crate，无法反向依赖本 crate，
/// 其 `scan.rs::civil_year` 只取年份，另保一份同源算法。）
pub fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}