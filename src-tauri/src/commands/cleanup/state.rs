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
                    // 审查 M-08：三种回退原本都零日志，用户只会看到「扫描结果为空」，
                    // 分不清是首启动没有配置、还是配置损坏被丢弃了。逐条说清是哪一种。
                    let actual = if v.is_array() {
                        "array"
                    } else if v.is_string() {
                        "string"
                    } else if v.is_number() {
                        "number"
                    } else {
                        "其他非 object 值"
                    };
                    crate::engine::log::write_log(
                        "warn",
                        &format!(
                            "路径配置 {} 顶层不是 object（实际 {actual}），已按空配置继续",
                            file.display()
                        ),
                    );
                    json!({})
                }
            }
            Err(e) => {
                crate::engine::log::write_log(
                    "error",
                    &format!("路径配置 {} JSON 解析失败: {e}（已按空配置继续，绑定项会退回默认值）", file.display()),
                );
                json!({})
            }
        },
        Err(e) => {
            // NotFound 属首启动正常态，用 info；其余（权限/占用等）才是 warn。
            let level = if e.kind() == std::io::ErrorKind::NotFound { "info" } else { "warn" };
            crate::engine::log::write_log(
                level,
                &format!("路径配置 {} 读取失败: {e}（已按空配置继续，绑定项会退回默认值）", file.display()),
            );
            json!({})
        }
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
            // M-5（审查 2026-10-07）：Windows 路径大小写不敏感，比较前统一小写，
            // 否则 `C:\Users\X\a.log` 与 `c:\users\x\A.LOG` 这类同路径不同写法
            // 会被判成「路径被改写」而误拒合法清理。
            if !a.is_empty()
                && !b.is_empty()
                && path_resolve(a).to_lowercase() != path_resolve(b).to_lowercase()
            {
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

/// 2026-10-04 审计 §4.3：确认清单与实际删除集的口径差留痕（纯函数，便于断言）。
///
/// 执行侧**重新遍历**每个目标、从不读快照的 `files` 数组；用户在确认弹窗里看到
/// 的是快照那份清单。于是「扫描后新增的文件」「超出 `PLAN_CAP_*` 被截掉的行」
/// 会被永久删除却从未被列出、从未计入确认体积。**语义不在这里改**——把执行绑死
/// 到快照文件集是另一个产品裁定（会同时改变「新增文件也清」的既定行为，且
/// `filesTruncated` 时绑定一份残缺清单反而少删），本轮只让差异可见：
/// 返回逐条 warn 文案（清单被截断的条目、实测清理数超过清单条数的条目），
/// 由 `scan_execute::cleanup_execute` 原样 `write_log`。
pub(super) fn plan_delta_warnings(details: &[Value], snapshot: &HashMap<String, Value>) -> Vec<String> {
    let mut out = Vec::new();
    for d in details {
        let Some(id) = d.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(known) = snapshot.get(id) else {
            continue;
        };
        // 只对「真的删了文件」的条目对账：skip/error/fail 的条目没有「删多」可言，
        // 回收站/注册表/DISM 型条目没有 files 清单概念（listed=0 时两条都不触发）
        if !matches!(
            d.get("status").and_then(Value::as_str),
            Some("ok") | Some("partial")
        ) {
            continue;
        }
        let listed = known
            .get("files")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        let truncated = known
            .get("filesTruncated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let deleted = js_num_or_zero(d.get("fileCount")) as usize;
        if truncated {
            out.push(format!(
                "条目 {id} 的确认清单超出单次上限被截断（清单仅列 {listed} 项），实际清理范围可能大于所列"
            ));
        } else if listed > 0 && deleted > listed {
            out.push(format!(
                "条目 {id} 实际清理 {deleted} 项，多于确认清单列出的 {listed} 项（扫描与执行之间新增的文件也在清理范围内）"
            ));
        }
    }
    out
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

    fn snap_item(files: usize, truncated: bool) -> Value {
        let mut it = json!({
            "path": "C:\\Temp",
            "files": (0..files).map(|i| json!({ "path": format!("C:\\Temp\\f{i}"), "size": 1 })).collect::<Vec<_>>(),
        });
        if truncated {
            it["filesTruncated"] = json!(true);
        }
        it
    }

    /// 2026-10-04 磁盘清理审计 §4.3：确认清单与实际删除集的口径差必须留痕。
    ///
    /// 本函数体测的是 `plan_delta_warnings` 的**记账政策**（谁该出 warn、文案带不带数）；
    /// 「命令层真的把它喂给了 write_log」这层接线由末尾的源码形态断言钉住 ——
    /// 审计 §9.4 教训：纯函数断言走不到接线那一步，判红实验必须两条路都验。
    #[test]
    fn 口径差留痕_截断与删多都要出warn() {
        let mut s = HashMap::new();
        s.insert("trunc".to_string(), snap_item(3, true));
        s.insert("grown".to_string(), snap_item(3, false));
        s.insert("reg".to_string(), json!({ "path": "HKCU\\Foo" })); // 注册表型：无 files

        let details = vec![
            // 截断条目：哪怕删得不多也要报（清单本身不完整）
            json!({ "id": "trunc", "status": "ok", "fileCount": 3 }),
            // 删多：快照列 3 项、实测清了 5 项
            json!({ "id": "grown", "status": "ok", "fileCount": 5 }),
            // 删得比清单少（部分被占用）：不是「清单外多删」，不报
            json!({ "id": "grown", "status": "partial", "fileCount": 2 }),
            // 注册表型条目没有 files 概念：listed=0，两条判据都不触发
            json!({ "id": "reg", "status": "ok", "fileCount": 7 }),
            // skip/error 条目没有「删多」可言
            json!({ "id": "grown", "status": "skip", "fileCount": 99 }),
            // 快照外 id / 无 id：直接跳过
            json!({ "id": "ghost", "status": "ok", "fileCount": 9 }),
            json!({ "status": "ok", "fileCount": 9 }),
        ];
        let warns = plan_delta_warnings(&details, &s);
        assert_eq!(warns.len(), 2, "截断 1 条 + 删多 1 条，其余不得误报: {warns:?}");
        assert!(warns[0].contains("trunc") && warns[0].contains("截断"), "截断文案要能对上条目: {}", warns[0]);
        assert!(warns[1].contains("grown") && warns[1].contains("5") && warns[1].contains("3"), "删多文案要带两个数: {}", warns[1]);

        // 刚好等于清单条数：不算删多（口径是「多于」）
        let mut s2 = HashMap::new();
        s2.insert("a".to_string(), snap_item(4, false));
        let warns2 = plan_delta_warnings(&[json!({ "id": "a", "status": "ok", "fileCount": 4 })], &s2);
        assert!(warns2.is_empty(), "删除数 == 清单数不得报: {warns2:?}");
    }

    /// §4.3 的接线钉：纯函数的 warn 文案必须在 scan_execute 的清理完成路径里
    /// 被逐条 write_log —— 只测函数不测接线的话，把调用删了测试照样全绿
    /// （审计 §9.4 第一次判红实验没红的同款盲区）。
    #[test]
    fn 口径差留痕_命令层接线在位() {
        let src = include_str!("scan_execute.rs");
        let calls: Vec<usize> = src
            .match_indices("plan_delta_warnings(")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            calls.len(),
            1,
            "plan_delta_warnings 在命令层应恰好 1 处调用（多了=口径分叉，少了=接线被摘）: {}",
            calls.len()
        );
        assert!(
            src.contains("for w in plan_delta_warnings("),
            "接线形态变了（不再是逐条 write_log 的循环）——请同步改本断言并复核判红"
        );
    }
}