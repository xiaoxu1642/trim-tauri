//! 优化项「已应用状态」记账（对照 src/main/optimization-state.js，v2.6.0 P0-1）。
//!
//! fail-closed 三条不变式：
//!   ① 先记账：执行前写 pending，写不进去就不改系统；
//!   ② 执行成功才转正 applied，并记录回读验证结果；
//!   ③ 还原成功才销账，失败保留记录等下次重试。
//!
//! 数据文件：`<数据目录>/optimization-state.json`，损坏隔离（与 settings 同策略）。
//! v2.7.0 起同时承载 detected 段：{ id: { optimized: bool, at: ISO } }。

use serde_json::{json, Map, Value};

use crate::engine::{log, paths};
use crate::security;

fn state_file() -> std::path::PathBuf {
    paths::app_data_dir().join("optimization-state.json")
}

fn empty_state() -> Value {
    json!({ "version": 1, "items": {}, "detected": {} })
}

fn load() -> Value {
    let f = state_file();
    let v = security::read_json_or_quarantine(&f);
    match v {
        Value::Object(m) if m.get("items").map(|x| x.is_object()).unwrap_or(false) => {
            let mut o = m;
            if !o.get("detected").map(|x| x.is_object()).unwrap_or(false) {
                o.insert("detected".into(), json!({}));
            }
            Value::Object(o)
        }
        _ => empty_state(),
    }
}

fn save(state: &Value) -> bool {
    match security::atomic_write_json(&state_file(), state) {
        Ok(()) => true,
        Err(e) => {
            log::write_log("error", &format!("写入优化状态失败: {e}"));
            false
        }
    }
}

fn iso_now() -> String {
    crate::engine::delete_manifest::iso_now()
}

/// 执行前记账（pending）。false = 写入失败，调用方必须中止（fail-closed）。
pub fn record_pending(id: &str, title: &str, kinds: &[String]) -> bool {
    if id.is_empty() {
        return false;
    }
    let mut state = load();
    let allowed: Vec<Value> = kinds
        .iter()
        .filter(|k| matches!(k.as_str(), "reg" | "cmd" | "service"))
        .map(|k| json!(k))
        .collect();
    if let Some(items) = state.get_mut("items").and_then(|v| v.as_object_mut()) {
        items.insert(
            id.into(),
            json!({
                "title": if title.is_empty() { id } else { title },
                "appliedAt": iso_now(),
                "kinds": allowed,
                "status": "pending",
                "lastVerify": Value::Null,
                "verifiedAt": Value::Null
            }),
        );
    }
    save(&state)
}

/// 执行后转正（applied）+ 回读验证三态
pub fn mark_applied(id: &str, verify: &str) -> bool {
    let v = normalize_verify(verify);
    let mut state = load();
    let Some(rec) = state
        .get_mut("items")
        .and_then(|i| i.as_object_mut())
        .and_then(|m| m.get_mut(id))
        .and_then(|r| r.as_object_mut())
    else {
        return false;
    };
    rec.insert("status".into(), json!("applied"));
    rec.insert("lastVerify".into(), json!(v));
    rec.insert("verifiedAt".into(), json!(iso_now()));
    save(&state)
}

/// 还原成功销账（本就不存在视为成功）
pub fn remove(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    let mut state = load();
    let Some(items) = state.get_mut("items").and_then(|v| v.as_object_mut()) else {
        return true;
    };
    if !items.contains_key(id) {
        return true;
    }
    items.remove(id);
    save(&state)
}

/// 全部记账条目
pub fn all() -> Map<String, Value> {
    load()
        .get("items")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
}

/// 单条记账（无则 null）
pub fn get(id: &str) -> Option<Value> {
    load().get("items")?.get(id).cloned()
}

/// 回写单条检测结果
pub fn set_detected_entry(id: &str, optimized: bool) -> bool {
    if id.is_empty() {
        return false;
    }
    let mut state = load();
    if let Some(d) = state.get_mut("detected").and_then(|v| v.as_object_mut()) {
        d.insert(
            id.into(),
            json!({ "optimized": optimized, "at": iso_now() }),
        );
    }
    save(&state)
}

/// 读取全部检测结果
pub fn detected_all() -> Map<String, Value> {
    load()
        .get("detected")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
}

fn normalize_verify(v: &str) -> &'static str {
    match v {
        "pass" => "pass",
        "partial" => "partial",
        _ => "unknown",
    }
}
