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

/// 占用检测的候选文件装配（`cleanup:check-locked` 专用）。
///
/// 抽成纯函数是为了能脱离磁盘与 IPC 断言**上限真的生效** —— 原实现里那句
/// `PLAN_LOCK_CAP` 是在整个 `files` 向量**填完之后**才施加的，而 `ids` 本身
/// 无长度限制、无去重，单个条目的 fileKeys 上限是 10 万 ⇒ 渲染层一次
/// `Array(200000).fill(<任一已扫 id>)` 就能让主进程堆 2×10¹⁰ 个 `Value`。
/// 这个形状没法用集成测试验（测它等于真的把进程 OOM 掉），只能钉在纯函数上。
///
/// 与 `validate_snapshot_items` 同族的约束：**只认本窗口快照里的槽**。
/// 快照里没有的 id 直接跳过（不是报错），所以渲染层传什么 id 都无法把
/// 「不在快照里的文件」塞进占用检测的候选集。
///
/// 返回 `(候选, 是否被截断)`。`truncated` 必须在**装配过程中**判定：
/// 装配后再比 `len()` 的话，有上限就永远等于上限，那句比较恒假、
/// 「被截断」永远报 false —— 与审计 §3.5 要修的静默失效是同一类，只是方向相反。
pub(super) fn collect_lock_candidates(
    ids: Option<&Value>,
    snapshot: &HashMap<String, Value>,
    max_files: usize,
) -> (Vec<Value>, bool) {
    let Some(arr) = ids.and_then(Value::as_array) else {
        return (Vec::new(), false);
    };
    // ids 长度对「快照条目数」封顶用调用方的 EXECUTE_MAX_ITEMS 口径；
    // 这里再兜一层 `snapshot.len()`：用户不可能同时勾比快照还多的条目。
    let id_cap = EXECUTE_MAX_ITEMS.min(snapshot.len().max(1));
    let mut truncated = arr.len() > id_cap;
    let mut out: Vec<Value> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in arr.iter().take(id_cap) {
        let Some(id) = s.as_str() else { continue };
        // 同一 id 重复传不再翻倍：去重集合本身也有上限（受 id_cap 约束）
        if !seen.insert(id.to_string()) {
            continue;
        }
        let Some(it) = snapshot.get(id) else { continue };
        let Some(list) = it.get("files").and_then(Value::as_array) else { continue };
        for f in list {
            if out.len() >= max_files {
                truncated = true;
                return (out, truncated);
            }
            let Some(p) = f.get("path").and_then(Value::as_str) else { continue };
            if p.is_empty() {
                continue;
            }
            out.push(json!({ "path": p, "id": id }));
        }
    }
    (out, truncated)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(files: &[&str]) -> HashMap<String, Value> {
        let mut m = HashMap::new();
        m.insert(
            "item-a".to_string(),
            json!({
                "path": "C:\\Temp",
                "files": files.iter().map(|p| json!({ "path": p, "size": 1 })).collect::<Vec<_>>(),
            }),
        );
        m
    }

    /// 2026-10-04 磁盘清理审计 §3.5：占用检测候选装配的三条上限。
    ///
    /// 这些断言**不需要真的把进程打爆** —— 原缺陷的形状就是「装配完 2×10¹⁰ 个元素
    /// 再截断」，能验它只能靠纯函数 + 小 `max_files`，这也是把装配抽出来的原因。
    #[test]
    fn 占用检测候选装配_上限与去重都生效() {
        let s = snap(&["C:\\Temp\\a", "C:\\Temp\\b"]);

        // ① 正常路径：一项两个文件，既不截断也不丢
        let (out, trunc) = collect_lock_candidates(Some(&json!(["item-a"])), &s, 100);
        assert_eq!(out.len(), 2, "正常路径必须拿到全部候选: {out:?}");
        assert!(!trunc, "未触上限时 truncated 必须是 false");

        // ② 重复 id 不翻倍（原实现无去重，同一 id 传 N 次就吐 N 遍文件）
        let (out, _) = collect_lock_candidates(Some(&json!(["item-a", "item-a", "item-a"])), &s, 100);
        assert_eq!(out.len(), 2, "重复 id 必须去重，不得翻倍: {out:?}");

        // ③ max_files 早退且**如实报截断**
        //    （这一条是重点：装配后再比 len() 会让 truncated 恒假）
        let (out, trunc) = collect_lock_candidates(Some(&json!(["item-a"])), &s, 1);
        assert_eq!(out.len(), 1, "必须停在 max_files: {out:?}");
        assert!(trunc, "被上限截断时 truncated 必须为 true —— 否则面板永远不显示「已截断」");

        // ④ 快照外的 id 一律跳过（不得凭渲染层的 id 造出候选）
        let (out, _) = collect_lock_candidates(Some(&json!(["__不在快照里__"])), &s, 100);
        assert!(out.is_empty(), "快照外的 id 必须被跳过: {out:?}");

        // ⑤ 非数组 / 空数组 → 空集且不截断（fail-closed，不是报错）
        for bad in [json!(null), json!("item-a"), json!([]), json!({})] {
            let (out, trunc) = collect_lock_candidates(Some(&bad), &s, 100);
            assert!(out.is_empty() && !trunc, "非数组输入应得空集: {bad} => {out:?}");
        }

        // ⑥ 空 path 不进候选（原实现靠 `!p.is_empty()` 过滤，这里钉住）
        let mut s2 = HashMap::new();
        s2.insert(
            "item-a".to_string(),
            json!({ "path": "C:\\Temp", "files": [{ "path": "", "size": 1 }, { "path": "C:\\Temp\\x" }] }),
        );
        let (out, _) = collect_lock_candidates(Some(&json!(["item-a"])), &s2, 100);
        assert_eq!(out.len(), 1, "空 path 必须被过滤: {out:?}");
        assert_eq!(out[0]["path"], json!("C:\\Temp\\x"));

        // ⑦ ids 超长也必须截断而不是全量展开
        let s3 = {
            let mut m = HashMap::new();
            for i in 0..600 {
                m.insert(
                    format!("i{i}"),
                    json!({ "path": "C:\\Temp", "files": [{ "path": format!("C:\\Temp\\{i}") }] }),
                );
            }
            m
        };
let many: Vec<String> = (0..600).map(|i| format!("i{i}")).collect();
        let (out, trunc) = collect_lock_candidates(Some(&json!(many)), &s3, 100_000);
        assert!(trunc, "600 个 id 超过 EXECUTE_MAX_ITEMS 上限，truncated 必须为 true");
        assert!(out.len() <= EXECUTE_MAX_ITEMS, "越界 id 不得被展开: {}", out.len());
    }
}