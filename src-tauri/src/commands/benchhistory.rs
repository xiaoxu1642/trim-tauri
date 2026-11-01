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
/// 测速历史的三态读取（A1-M06，v7.2 P1）：`Corrupt` 不再与「确实没有历史」同归空数组。
fn load_bench_history_state() -> Result<Vec<Value>, String> {
    match security::read_json_array_state(&bench_history_file()) {
        security::JsonState::Ok(Value::Array(items)) => Ok(items),
        security::JsonState::Ok(_) => Err("测速历史文件结构异常（不是数组）".into()),
        security::JsonState::Corrupt => {
            Err("测速历史读取失败（现场已隔离/见日志），本次未把它当成空历史".into())
        }
        security::JsonState::Absent => Ok(Vec::new()),
    }
}

/// 读-改-写（v4 组 1 / R7-M01「读失败绝不落到写」）：`Ok`/`Absent` 才执行 `f` 并落盘；
/// 结构异常（非数组）与读取失败都**拒绝本次写入**并如实回报——旧实现把两者都当
/// 「空数组」继续跑，一次 add/clear 就把用户历史整表覆写，且无日志无隔离。
/// R7-M07（v7.2 C06）：改用数组形态的 RMW 原语，三态闸/原子落盘/进程内锁不再在本文件复制。
fn update_bench_history(f: impl FnOnce(&mut Vec<Value>)) -> Result<(), String> {
    security::update_json_array(&bench_history_file(), |records| {
        f(records);
        records.truncate(MAX_HISTORY);
        Ok(())
    })
    .map(|_| ())
    .map_err(|e| {
        log::write_log("error", &format!("保存测速历史失败: {e}"));
        e
    })
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
    guard::guard(&window, guard::MAIN)?;
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
    guard::guard(&window, guard::MAIN)?;
    match load_bench_history_state() {
        Ok(data) => Ok(json!({ "success": true, "data": data })),
        // A1-M06：读失败必须回 success:false；空数组只代表「确实没有历史」。
        Err(msg) => Ok(json!({ "success": false, "message": msg })),
    }
}

/// `bench-history:delete` 的入参判据：缺 id / 空 id 一律拒。
///
/// 为什么必须在这里拒：`retain` 的条件是「记录的 id 不等于入参」，而记录的 id 恒非空
/// ⇒ 空入参会把**每一条**都留下，命令却仍然跑完。成功位不能由「跑完了」派生。
fn delete_id_problem(id: Option<&str>) -> Option<&'static str> {
    match id {
        Some(s) if !s.is_empty() => None,
        _ => Some("缺少记录 id"),
    }
}

/// 按 id 移除记录，返回**真的删掉了几条**（删除命令的成功位由这个数字派生）。
fn remove_records_by_id(records: &mut Vec<Value>, id: &str) -> usize {
    let before = records.len();
    records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
    before - records.len()
}

/// bench-history:delete — 按 id 删除单条
#[tauri::command]
pub fn bench_history_delete<R: tauri::Runtime>(window: WebviewWindow<R>, id: Option<String>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    // 缺 id 时 retain 会把每条记录都保留（记录 id 恒非空），旧实现却回 success:true ——
    // 前端据 success 把条目移出列表，磁盘上还在。成功位必须由「真删到了几条」派生。
    if let Some(why) = delete_id_problem(id.as_deref()) {
        return Ok(json!({ "success": false, "message": why }));
    }
    let id = id.unwrap_or_default();
    let mut removed = 0usize;
    if let Err(msg) = update_bench_history(|records| {
        removed = remove_records_by_id(records, &id);
    }) {
        return Ok(json!({ "success": false, "message": format!("记录未删除：{msg}") }));
    }
    if removed == 0 {
        return Ok(json!({ "success": false, "message": "未找到该记录（可能已被删除）" }));
    }
    Ok(json!({ "success": true }))
}

/// bench-history:clear — 清空全部
#[tauri::command]
pub fn bench_history_clear<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if let Err(msg) = update_bench_history(|records| { records.clear(); }) {
        return Ok(json!({ "success": false, "message": format!("记录未清空：{msg}") }));
    }
    Ok(json!({ "success": true }))
}

#[cfg(test)]
mod tests {
    use super::{delete_id_problem, remove_records_by_id};
    use serde_json::json;

    /// R1a-L07：缺 id 的删除必须当场拒，不许回 success:true。
    ///
    /// 反面对照是这条用例的真正判据：把空 id 放进 retain 里，**每一条**记录都会被留下
    /// （`retain` 判的是「id 不等于入参」）—— 所以「缺 id 也能删成功」在实现上等于「一条没删」。
    #[test]
    fn 缺记录id的删除必须拒而不是回成功() {
        assert_eq!(delete_id_problem(None), Some("缺少记录 id"), "缺参必须拒");
        assert_eq!(delete_id_problem(Some("")), Some("缺少记录 id"), "空串必须拒");
        assert_eq!(
            delete_id_problem(Some("1700000000000_abc123")),
            None,
            "正常 id 被误拒 ⇒ 前端永远删不掉任何记录"
        );
        let mut records = vec![json!({ "id": "a" }), json!({ "id": "b" })];
        assert_eq!(remove_records_by_id(&mut records, ""), 0, "空 id 居然删掉了记录");
        assert_eq!(records.len(), 2, "空 id 把记录删掉了");
    }

    /// R1a-L07：成功位由「真删到了几条」派生 —— 一条都没删掉时必须能与删成功区分。
    #[test]
    fn 删除条数由实际移除数派生() {
        let mut records = vec![
            json!({ "id": "a" }),
            json!({ "id": "b" }),
            json!({ "id": "b" }),
        ];
        assert_eq!(remove_records_by_id(&mut records, "b"), 2, "同 id 的重复记录必须全部移除");
        assert_eq!(records.len(), 1);
        assert_eq!(remove_records_by_id(&mut records, "不存在的 id"), 0, "未命中必须回 0（不是 1）");
        // 记录侧 id 缺失或非字符串时不得被字符串入参命中（否则会误删别人的记录）
        let mut odd = vec![json!({ "x": 1 }), json!({ "id": 5 })];
        assert_eq!(remove_records_by_id(&mut odd, "5"), 0, "非字符串 id 被字符串入参命中了");
        assert_eq!(odd.len(), 2, "非字符串 id 的记录被误删");
    }

    /// 判据必须真的被命令用到：只测纯函数会漏掉「helper 留着、命令改回旧写法」这种回退。
    #[test]
    fn 删除命令必须真的走缺id判据与移除计数() {
        let src = include_str!("benchhistory.rs");
        let start = src
            .find("fn bench_history_delete")
            .expect("找不到 bench_history_delete，判据坐标已漂");
        let rest = &src[start..];
        let end = rest.find("\n#[tauri::command]").unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains(&["delete_id_problem", "(id.as_deref())"].concat()),
            "删除命令没走缺 id 判据 ⇒ 缺参又会回 success:true"
        );
        assert!(
            body.contains(&["removed = remove_records_by_id", "(records, &id);"].concat()),
            "删除命令没由移除计数派生成功位 ⇒ 删 0 条也会报成功"
        );
    }
}
