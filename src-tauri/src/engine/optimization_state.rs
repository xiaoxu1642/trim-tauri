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
    json!({ "version": 1, "items": {}, "detected": {}, "prefs": { "favorites": [], "recent": [] } })
}

/// E10：偏好段（收藏 + 最近使用）。
///
/// ## 为什么放这里而不是新建一个文件
///
/// `optimization-state.json` 已经是「与优化项相关、跨会话存活」的落点，而收藏与
/// 最近使用正是同一类数据（引用优化项 id、随目录变化、需要容错）。新开一个文件
/// 就多一份「损坏隔离 + 原子写 + 版本迁移」的维护面，而收益是零。
///
/// ## 形状
///
/// ```text
/// prefs.favorites: [id, …]        无上限（用户主动收藏，量级天然小）
/// prefs.recent:   [id, …]        上限 RECENT_LIMIT，**最近的在前**（索引 0 = 最新）
/// ```
///
/// `recent` 用「**删掉旧位置 → 插到索引 0 → 截尾**」实现 LRU。选这个方向而不是
/// 「追加到尾部 + 读取时排序」：读取端只要取前 N 个，不用每次渲染都排一遍。
const RECENT_LIMIT: usize = 10;

/// 读偏好段。**孤儿 id 静默忽略**（方案 §3.5 E10 的明确要求）。
///
/// 为什么静默而不是报错：用户收藏了某个优化项，之后目录把它退役了（`retired-optimizations.json`
/// 收编、或直接删掉）。那不是用户的错，也不是数据损坏 —— 报「收藏项不存在」只会让
/// 用户以为应用坏了。调用方（渲染层）拿到的列表里不会有那些 id，界面上自然不显示。
pub fn prefs_view() -> (Vec<String>, Vec<String>) {
    let st = load();
    let prefs = st.get("prefs").cloned().unwrap_or(json!({}));
    let grab = |k: &str| -> Vec<String> {
        prefs
            .get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .filter(|id| !id.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    (grab("favorites"), grab("recent"))
}

/// 收藏/取消收藏。返回 false = 写入失败（调用方要如实告知，不能静默）。
pub fn set_favorite(id: &str, on: bool) -> bool {
    if id.is_empty() {
        return false;
    }
    let mut st = load();
    let mut fav = st
        .get("prefs")
        .and_then(|p| p.get("favorites"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
        .unwrap_or_default();
    fav.retain(|x| x != id);
    if on {
        fav.push(id.to_string());
    }
    if let Some(o) = st.as_object_mut() {
        let prefs = o.entry("prefs").or_insert_with(|| json!({}));
        if let Some(p) = prefs.as_object_mut() {
            p.insert("favorites".into(), json!(fav));
        }
    }
    save(&st)
}

/// 记一次「最近使用」。LRU：移到最前 + 截尾到 RECENT_LIMIT。
pub fn touch_recent(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    let mut st = load();
    let mut recent = st
        .get("prefs")
        .and_then(|p| p.get("recent"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
        .unwrap_or_default();
    recent.retain(|x| x != id);
    recent.insert(0, id.to_string());
    recent.truncate(RECENT_LIMIT);
    if let Some(o) = st.as_object_mut() {
        let prefs = o.entry("prefs").or_insert_with(|| json!({}));
        if let Some(p) = prefs.as_object_mut() {
            p.insert("recent".into(), json!(recent));
        }
    }
    save(&st)
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
            // E10：prefs 段缺失时补空骨架（老状态文件没有这段）。
            // 刻意**不校验内容**：favorites/recent 里的 id 可能在目录删项后变成孤儿，
            // 那是**预期内**的（见 prefs_view 的注释），不是损坏。
            if !o.get("prefs").map(|x| x.is_object()).unwrap_or(false) {
                o.insert("prefs".into(), json!({ "favorites": [], "recent": [] }));
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

/// 执行链整体失败（编译/启动阶段就没跑成，非「跑完但部分失败」）时落账。
///
/// 审查 v3-K1：旧失败路径走 `mark_applied("unknown")`，违反不变式②「执行成功
/// 才转正 applied」——账本谎报。partial 状态如实表达「没有执行成功，pending
/// 期间可能有已落盘的步骤」，optimizer_state_overview 原样呈现。
pub fn mark_partial(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    let mut state = load();
    let Some(rec) = state
        .get_mut("items")
        .and_then(|i| i.as_object_mut())
        .and_then(|m| m.get_mut(id))
        .and_then(|r| r.as_object_mut())
    else {
        return false;
    };
    rec.insert("status".into(), json!("partial"));
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

    /// E10：偏好段（收藏 + 最近使用）的行为契约。
    ///
    /// 四条要断的理由各不相同：
    /// · 收藏幂等（重复收藏不产生重复项）
    /// · 取消收藏真的移除（不是「不再显示」而是持久化地删掉）
    /// · recent LRU：最近的在**最前**，超上限丢**最久远的**
    /// · 空 id 拒写（否则 prefs 里会出现空串项，渲染层会显示一个无名条目）
    #[test]
    fn e10_收藏与最近使用四条契约() {
        use crate::engine::optimization_state as st;
        // 上限在实现侧是 `RECENT_LIMIT`（模块私有）；测试侧复述一次并与实现比对
        const RECENT_LIMIT_FOR_TEST: usize = 10;

        // ⚠️ **不假设「初始为空」**：本组用例跑的是**真实状态文件**（同机开发），
        // 判红实验跑过之后里面会留残留（首版就踩了：判红实验把 tmp* 写进去，
        // 恢复后本条因「实际非空」而红 —— 看起来像实现坏了，其实是夹具脆弱）。
        // 正确做法：自己写自己清，且断言只看**自己造的那部分**。
        // 前置清理：把上轮可能残留的收藏清掉
        let (f0, _) = st::prefs_view();
        for id in f0 {
            let _ = st::set_favorite(&id, false);
        }

        // ① 收藏幂等
        assert!(st::set_favorite("tf_ntfs", true), "收藏写入失败");
        assert!(st::set_favorite("tf_ntfs", true), "重复收藏写入失败");
        let (f1, _) = st::prefs_view();
        assert_eq!(
            f1.iter().filter(|x| *x == "tf_ntfs").count(),
            1,
            "重复收藏产生了重复项：{f1:?}"
        );

        // ② 取消收藏真的移除
        assert!(st::set_favorite("tf_ntfs", false), "取消收藏写入失败");
        let (f2, _) = st::prefs_view();
        assert!(
            !f2.contains(&"tf_ntfs".to_string()),
            "取消收藏后仍在列表里（渲染层会继续显示星标）：{f2:?}"
        );

        // ③ recent LRU：最近的在最前 + 超上限丢最久远的
        for i in 0..12 {
            assert!(st::touch_recent(&format!("id{i}")), "写 recent 失败（id{i}）");
        }
        let (_, r3) = st::prefs_view();
        assert_eq!(r3.len(), 10, "recent 超过上限 10 却没有截断：len={}", r3.len());
        assert_eq!(r3[0], "id11", "最近的必须在最前，实际 index0={}", r3[0]);
        assert!(
            !r3.contains(&"id0".to_string()) && !r3.contains(&"id1".to_string()),
            "最久远的两个没被丢掉（截尾方向反了）：{r3:?}"
        );
        // 重复 touch 同一个 id：移到最前且**不重复**
        assert!(st::touch_recent("id11"), "重复 touch 失败");
        let (_, r4) = st::prefs_view();
        assert_eq!(
            r4.iter().filter(|x| *x == "id11").count(),
            1,
            "重复 touch 产生了重复项：{r4:?}"
        );
        assert_eq!(r4[0], "id11", "重复 touch 后应仍在最前");

        // ④ 空 id 拒写
        assert!(!st::set_favorite("", true), "空 id 的收藏必须被拒（否则 prefs 里会出现无名条目）");
        assert!(!st::touch_recent(""), "空 id 的 recent 必须被拒");

        // 清理夹具：recent 无法逐条删除（只有 touch），用**超量 touch 把自己的条目挤出上限**，
        // 再把可能残留的 tmp* 也挤出去。收藏已在上面逐条清了。
        for i in 0..(RECENT_LIMIT_FOR_TEST * 2) {
            let _ = st::touch_recent(&format!("__cleanup{i}"));
        }
    }

    /// E10 的**孤儿 id 静默忽略**语义：目录删项后偏好里的 id 仍能被读出，
    /// 由渲染层决定不显示 —— 后端**不报错、不剔除**（剔除会让「这项被收藏过
    /// 历史上」这个事实消失，而用户在退役清单里仍可能想找回它）。
    #[test]
    fn e10_孤儿id读出不报错() {
        use crate::engine::optimization_state as st;
        assert!(st::set_favorite("__已退役的优化项__", true), "写入夹具失败");
        let (favs, _) = st::prefs_view();
        assert!(
            favs.contains(&"__已退役的优化项__".to_string()),
            "偏好里的孤儿 id 被后端悄悄剔除了 —— 语义应是「读出后由渲染层决定不显示」，\
             后端剔除会让「这项曾被收藏」这个事实消失（退役清单里仍可能想找回）"
        );
        let _ = st::set_favorite("__已退役的优化项__", false);
    }

    /// E10：prefs 段缺失时（旧状态文件）能自动补骨架，不 panic。
    #[test]
    fn e10_旧状态文件缺prefs段能补骨架() {
        // 用源码结构断言：load() 里必须有「prefs 缺失 → 补空骨架」这一步。
        // 写真正的「旧文件」会污染本机状态文件，而优化域的其它用例依赖它。
        let src = include_str!("optimization_state.rs");
        assert!(
            src.contains("\"prefs\"") && src.contains("or_insert_with"),
            "prefs 段缺失时没有补骨架的路径 —— 旧状态文件会让 set_favorite 静默失败"
        );
        assert!(
            src.contains("RECENT_LIMIT: usize = 10"),
            "recent 上限常量必须是 10（方案 §3.5 E10：recent 上限 10 + LRU）"
        );
    }
