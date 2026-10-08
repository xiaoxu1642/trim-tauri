//! benchhistory 域（C 批）：bench-history:add / list / delete / clear
//!
//! 对照 main.js 5553-5643。落盘 `<数据目录>/bench-history.json`，**最多 50 条**，
//! 一律走 `crate::security::atomic_write_json`（临时件 + fsync + rename，与 Electron
//! 的 SECURITY.atomicWriteJson 同口径，杜绝半截 JSON 污染历史）。
//!
//! `bench-history:add` 的 schema 校验逐条照抄（复核 N2，2026-09-16）：
//! - 记录必须是对象（数组/标量整条拒绝）；
//! - 10 个数值字段必须是**有限数值**（字符串/NaN/Infinity 拒绝）；
//! - `path` 只接受 ≤1024 的字符串；`engine` 只接受 `rust` / `powershell`；
//! - `sequentialRead` / `sequentialWrite` 全缺 = 没有测速结果，整条拒绝。
//! 非法记录不再原样落盘（旧实现会污染 bench-history.json）。
//!
//! 需要加入 lib.rs `generate_handler!` 的完整行：
//!   commands::benchhistory::bench_history_add,
//!   commands::benchhistory::bench_history_list,
//!   commands::benchhistory::bench_history_delete,
//!   commands::benchhistory::bench_history_clear,

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{json, Map, Value};
use tauri::WebviewWindow;

use crate::engine::{guard, log, paths};
use crate::security;

/// 历史记录上限（超出丢弃最旧的尾部记录）
const MAX_HISTORY: usize = 50;
/// 数值字段白名单（与 JS numericFields 逐条同序）
const NUMERIC_FIELDS: &[&str] = &[
    "blockSize",
    "queueDepth",
    "threads",
    "duration",
    "sequentialRead",
    "sequentialWrite",
    "randomRead",
    "randomWrite",
    "iops",
    "latency",
];
/// 路径字段长度上限
const MAX_PATH_LEN: usize = 1024;

fn bench_history_file() -> PathBuf {
    paths::join_data("bench-history.json")
}

/// `loadBenchHistory`：非数组 / 损坏一律当空数组（与 JS 的 try/catch 同语义）
///
/// v4 组 1：读路径改走三态读 —— 解析失败自动隔离、IO 失败自动留痕
/// （旧实现 `read_to_string` 的 Err 静默吞，列表页把「读失败」渲染成「没有历史」）。
/// v4 修复（2026-10-09）：文件是**裸数组**，必须走 `read_json_array_state`（对象版把
/// 合法数组判 Corrupt，会让本函数恒空、[`update_bench_history`] 恒拒）。
/// 写路径见 [`update_bench_history`]：损坏时**拒写**，不再把整张历史静默清空。
fn load_bench_history() -> Vec<Value> {
    match security::read_json_array_state(&bench_history_file()) {
        security::JsonState::Ok(Value::Array(items)) => items.iter().cloned().collect(),
        _ => Vec::new(),
    }
}

/// 读-改-写（v4 组 1 / R7-M01「读失败绝不落到写」）：`Ok`/`Absent` 才执行 `f` 并落盘；
/// 结构异常（非数组）与读取失败都**拒绝本次写入**并如实回报——旧实现把两者都当
/// 「空数组」继续跑，一次 add/clear 就把用户历史整表覆写，且无日志无隔离。
/// v4 修复（2026-10-09）：走数组形态三态读器（同 load_bench_history 的理由）。
fn update_bench_history(f: impl FnOnce(&mut Vec<Value>)) -> Result<(), String> {
    let mut records: Vec<Value> = match security::read_json_array_state(&bench_history_file()) {
        security::JsonState::Ok(Value::Array(items)) => items.iter().cloned().collect(),
        security::JsonState::Ok(_) => {
            crate::engine::log::write_log("warn", "测速历史结构异常（非数组），本次写入已拒绝");
            return Err("测速历史文件结构异常，本次操作已拒绝（可删除该文件后重试）".into());
        }
        security::JsonState::Corrupt => {
            return Err("测速历史读取失败（现场已隔离/见日志），本次操作已拒绝".into());
        }
        security::JsonState::Absent => Vec::new(),
    };
    f(&mut records);
    if save_bench_history(&records) {
        Ok(())
    } else {
        Err("写入失败".into())
    }
}

/// `saveBenchHistory`：截断到 50 条后原子落盘
fn save_bench_history(records: &[Value]) -> bool {
    let trimmed: Vec<Value> = records.iter().take(MAX_HISTORY).cloned().collect();
    match security::atomic_write_json(&bench_history_file(), &Value::Array(trimmed)) {
        Ok(()) => true,
        Err(e) => {
            log::write_log("error", &format!("保存测速历史失败: {e}"));
            false
        }
    }
}

/// `Date.now() + '_' + Math.random().toString(36).slice(2, 8)` 等价物
/// （JS 侧也只是 6 位 base36 随机串，非安全用途）
fn new_record_id() -> String {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed) as u64;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let mut x = nanos ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    let mut suffix = String::with_capacity(6);
    let mut v = x;
    for _ in 0..6 {
        suffix.push(char::from_digit((v % 36) as u32, 36).unwrap_or('0'));
        v /= 36;
    }
    format!("{}_{suffix}", crate::engine::now_ms())
}

/// bench-history:add — 追加一条测速记录（schema 校验不通过整条拒绝）
#[tauri::command]
pub fn bench_history_add<R: tauri::Runtime>(window: WebviewWindow<R>, record: Option<Value>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let record = match record {
        Some(Value::Object(m)) => Value::Object(m),
        _ => return Ok(json!({ "success": false, "message": "记录格式不合法" })),
    };
    let mut clean = Map::new();
    for field in NUMERIC_FIELDS {
        match record.get(*field) {
            None | Some(Value::Null) => continue, // 可选字段缺省不落盘
            Some(Value::Number(n)) => {
                let finite = n.as_f64().map(|v| v.is_finite()).unwrap_or(false);
                if !finite {
                    return Ok(json!({
                        "success": false,
                        "message": format!("字段 {field} 必须为有限数值")
                    }));
                }
                clean.insert((*field).to_string(), Value::Number(n.clone()));
            }
            Some(_) => {
                return Ok(json!({
                    "success": false,
                    "message": format!("字段 {field} 必须为有限数值")
                }))
            }
        }
    }
    if let Some(path) = record.get("path") {
        match path {
            // 与 JS `path.length`（UTF-16 码元数）同口径
            Value::String(s) if s.encode_utf16().count() <= MAX_PATH_LEN => {
                clean.insert("path".into(), json!(s));
            }
            _ => return Ok(json!({ "success": false, "message": "路径字段不合法" })),
        }
    }
    // v3.7.1 R1：引擎标识（rust/powershell）——历史记录不跨引擎换算，仅作对比参考
    if let Some(engine) = record.get("engine") {
        match engine.as_str() {
            Some("rust") | Some("powershell") => {
                clean.insert("engine".into(), engine.clone());
            }
            _ => return Ok(json!({ "success": false, "message": "引擎标识不合法" })),
        }
    }
    if !clean.contains_key("sequentialRead") && !clean.contains_key("sequentialWrite") {
        return Ok(json!({ "success": false, "message": "缺少测速结果数值" }));
    }

    let mut entry = Map::new();
    entry.insert("id".into(), json!(new_record_id()));
    entry.insert("timestamp".into(), json!(super::settings::iso_utc_now()));
    for (k, v) in clean {
        entry.insert(k, v);
    }
    if let Err(msg) = update_bench_history(|records| { records.insert(0, Value::Object(entry)); }) {
        return Ok(json!({ "success": false, "message": format!("测速历史未保存：{msg}") }));
    }
    Ok(json!({ "success": true }))
}

/// bench-history:list — 读取全部历史（最多 50 条，最新在前）
#[tauri::command]
pub fn bench_history_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    Ok(json!({ "success": true, "data": load_bench_history() }))
}

/// bench-history:delete — 按 id 删除单条
#[tauri::command]
pub fn bench_history_delete<R: tauri::Runtime>(window: WebviewWindow<R>, id: Option<String>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let id = id.unwrap_or_default();
    if let Err(msg) = update_bench_history(|records| {
        records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id.as_str()));
    }) {
        return Ok(json!({ "success": false, "message": format!("记录未删除：{msg}") }));
    }
    Ok(json!({ "success": true }))
}

/// bench-history:clear — 清空全部
#[tauri::command]
pub fn bench_history_clear<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Err(msg) = update_bench_history(|records| { records.clear(); }) {
        return Ok(json!({ "success": false, "message": format!("记录未清空：{msg}") }));
    }
    Ok(json!({ "success": true }))
}
