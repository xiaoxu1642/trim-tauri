//! 运行期状态：路径绑定配置（loadPathsConfig 对照）、分槽快照与回收失败槽、
//! 锁定进程白名单，以及 JS 数值/字符串口径的强转助手。
//!
//! 「执行只认本次会话快照里的槽」是本域的硬约束：validate_snapshot_items + in_scope
//! 决定能不能删，跳过它等于给用户的手抖开一条直通删除的通道。
//! js_number/js_truthy 这些是把 Rust 值喂回 JS 口径的比较逻辑，改它们要对照前端。

use crate::engine::paths;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use super::rules::*;
// ==================== 路径绑定配置（对照 loadPathsConfig） ====================

pub(super) fn load_paths_config() -> Value {
    let file = paths::paths_config_file();
    match std::fs::read_to_string(&file) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(mut v) => {
                // 剥离历史版本遗留的软件清单（不再展示与维护）
                if let Some(obj) = v.as_object_mut() {
                    obj.remove("softwareInventory");
                }
                if v.is_object() {
                    v
                } else {
                    json!({})
                }
            }
            Err(_) => json!({}),
        },
        Err(_) => json!({}),
    }
}

// ==================== 分槽快照（对照 cleanupSnapshots / trashFailureSlots / lastLockCheckProcs） ====================

pub(super) static CLEANUP_SNAPSHOTS: OnceLock<Mutex<HashMap<String, HashMap<String, Value>>>> = OnceLock::new();
pub(super) static TRASH_FAILURES: OnceLock<Mutex<HashMap<String, Vec<Value>>>> = OnceLock::new();
pub(super) static LOCK_WHITELIST: OnceLock<Mutex<HashMap<String, Vec<Value>>>> = OnceLock::new();

pub(super) fn snapshots() -> &'static Mutex<HashMap<String, HashMap<String, Value>>> {
    CLEANUP_SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()))
}
pub(super) fn trash_failures() -> &'static Mutex<HashMap<String, Vec<Value>>> {
    TRASH_FAILURES.get_or_init(|| Mutex::new(HashMap::new()))
}
pub(super) fn lock_whitelist() -> &'static Mutex<HashMap<String, Vec<Value>>> {
    LOCK_WHITELIST.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 对照 `snapshotById`
pub(super) fn snapshot_by_id(items: &[Value]) -> HashMap<String, Value> {
    let mut map = HashMap::new();
    for item in items {
        let Some(id) = item.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        if id.chars().count() <= 160 {
            map.insert(id.to_string(), item.clone());
        }
    }
    map
}

/// `path.resolve` 的词法折叠等价物（不触盘；用于快照 path 比对）
pub(super) fn path_resolve(p: &str) -> String {
    let text = if Path::new(p).is_absolute() {
        p.to_string()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => format!("{}\\{}", cwd.to_string_lossy(), p),
            Err(_) => p.to_string(),
        }
    };
    let bytes = text.as_bytes();
    let prefix_len = if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        2
    } else if text.starts_with(r"\\") {
        let parts: Vec<&str> = text[2..]
            .split(|c| c == '\\' || c == '/')
            .filter(|c| !c.is_empty())
            .collect();
        if parts.len() >= 2 {
            2 + parts[0].len() + 1 + parts[1].len()
        } else {
            0
        }
    } else {
        0
    };
    let (prefix, body) = text.split_at(prefix_len.min(text.len()));
    let mut segs: Vec<&str> = Vec::new();
    for c in body.split(|c| c == '\\' || c == '/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c == ".." {
            segs.pop();
            continue;
        }
        segs.push(c);
    }
    let joined = segs.join("\\");
    if prefix.is_empty() {
        joined
    } else if joined.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}\\{joined}")
    }
}

/// 对照 `validateSnapshotItems`：全部命中本窗口快照且 path 未被改写才放行
pub(super) fn validate_snapshot_items(items: Option<&Value>, snapshot: &HashMap<String, Value>) -> Option<Vec<Value>> {
    let arr = items?.as_array()?;
    if arr.is_empty() || arr.len() > EXECUTE_MAX_ITEMS {
        return None;
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        if !item.is_object() {
            return None;
        }
        let id = item.get("id").and_then(|v| v.as_str())?;
        let known = snapshot.get(id)?;
        if let (Some(a), Some(b)) = (
            item.get("path").and_then(|v| v.as_str()),
            known.get("path").and_then(|v| v.as_str()),
        ) {
            if !a.is_empty() && !b.is_empty() && path_resolve(a) != path_resolve(b) {
                return None;
            }
        }
        out.push(known.clone());
    }
    Some(out)
}

// ==================== 数值/字符串的 JS 口径 ====================

/// `Number(x)`：不可解析为 NaN
pub(super) fn js_number(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => s.trim().parse::<f64>().unwrap_or(f64::NAN),
        Value::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Value::Null => 0.0,
        _ => f64::NAN,
    }
}

/// `Number(x) || 0`
pub(super) fn js_num_or_zero(v: Option<&Value>) -> f64 {
    match v.map(js_number) {
        Some(n) if n.is_finite() => n,
        _ => 0.0,
    }
}

pub(super) fn js_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// 数字按 JS `String(n)` 呈现（整数不带 `.0`）
pub(super) fn js_num_str(n: f64) -> String {
    if !n.is_finite() {
        return "NaN".to_string();
    }
    if n.fract() == 0.0 && n.abs() < 9e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// `new Date().toISOString()`
pub(super) fn iso_now() -> String {
    let ms = crate::engine::now_ms();
    let secs = ms.div_euclid(1000);
    let milli = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milli:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

