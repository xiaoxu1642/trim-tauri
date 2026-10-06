//! 扫描结果快照：`窗口 label → (item.id → 扫描项)` 的进程内注册表。
//!
//! P2-2（审查 2026-10-07）：`startup` / `contextmenu` 此前各持一份同名 `SNAPSHOTS`
//! 静态表与 `snap_get` / `snap_set` / `snapshot_by_id`，宽严不一（一份按 id 长度 160
//! 静默剔除、一份不剔），收敛到这里。
//!
//! 语义：**写操作只接受快照内的 id**，且副作用参数一律取快照副本、不采信调用方传值
//! （防渲染层篡改）。分槽口径与 Electron 的 `sender.id` 对齐 —— 跨窗口/跨页签互不覆盖。
//!
//! **各域仍各自保留 `validate_snapshot_items`**：它们的额外判据确实不同（启动项比
//! `filePath`、清理比 `path`、右键菜单另受 `EXECUTE_MAX_ITEMS` 上限约束且已删掉失效的
//! `path` 分支），强行合并会让某个域丢掉自己的那道防线，故此处只统一注册表与 `by_id`。

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

/// 按窗口 label 分槽（对照 Electron 的 sender.id）
static SNAPSHOTS: Mutex<Option<HashMap<String, HashMap<String, Value>>>> = Mutex::new(None);

/// 取某窗口槽的快照副本（`None` = 该窗口还没扫过或已清除）。
pub fn get(label: &str) -> Option<HashMap<String, Value>> {
    SNAPSHOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(label).cloned())
}

/// 写入某窗口槽（覆盖该槽旧快照，不影响其它槽）。
pub fn set(label: &str, map: HashMap<String, Value>) {
    let mut g = SNAPSHOTS.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashMap::new).insert(label.to_string(), map);
}

/// 清除某窗口槽（只影响本窗口）。
pub fn clear(label: &str) {
    if let Some(g) = SNAPSHOTS.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        g.remove(label);
    }
}

/// 扫描项数组 → `id → 项`。
///
/// **不按 id 长度剔除**：长路径/长参数的项（如启动项 id = `reg|<path>|<name>`）被剔除后，
/// 禁用/删除/打开位置会永远回「不是最近一次扫描结果」，而重扫同样进不了快照 —— 用户被
/// 引导去做一件必然无效的事。右键菜单域另有 `normalize_ids` 把超长 id 换成稳定短哈希，
/// 同样不需要这里设长度闸。
pub fn by_id(items: &[Value]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for it in items {
        if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
            m.insert(id.to_string(), it.clone());
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// P2-2 回归：超长 id（中文注册表深路径）必须留在快照里。
    /// 右键菜单域曾按 160 字节静默剔除 —— 那些项界面看得到、点得动，但写操作恒被拒
    /// 「不是最近一次扫描结果」。去掉长度闸后这条必须过（把闸加回来即变红）。
    #[test]
    fn by_id_keeps_long_ids() {
        let long = format!("reg|HKCR\\{}|name", "A".repeat(300));
        let m = by_id(&[json!({ "id": long, "v": 1 })]);
        assert_eq!(m.len(), 1, "超长 id 不得被剔除");
        assert!(m.contains_key(&long));
    }

    /// 只有「id 是字符串」的项进快照；缺 id / 非字符串 id 一律跳过（不猜、不补）。
    #[test]
    fn by_id_skips_items_without_string_id() {
        let m = by_id(&[json!({ "v": 1 }), json!({ "id": 7 }), json!({ "id": "ok" })]);
        assert_eq!(m.len(), 1);
        assert!(m.contains_key("ok"));
    }

    /// 分槽隔离：清除 A 窗口的槽不得波及 B 窗口（跨窗口互不覆盖）。
    #[test]
    fn slots_are_isolated_and_clearable() {
        let (label_a, label_b) = ("snapshot-test-a", "snapshot-test-b");
        set(label_a, by_id(&[json!({ "id": "a1" })]));
        set(label_b, by_id(&[json!({ "id": "b1" })]));
        assert_eq!(get(label_a).map(|m| m.len()), Some(1));
        assert_eq!(get(label_b).map(|m| m.len()), Some(1));
        clear(label_a);
        assert!(get(label_a).is_none(), "清除后该槽应为空");
        assert_eq!(get(label_b).map(|m| m.len()), Some(1), "清除 A 不得影响 B");
        clear(label_b);
        assert!(get(label_b).is_none());
    }
}
