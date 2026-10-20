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

/// E10：偏好段（最近使用）。
///
/// ## 为什么放这里而不是新建一个文件
///
/// `optimization-state.json` 已经是「与优化项相关、跨会话存活」的落点，而最近使用
/// 正是同一类数据（引用优化项 id、随目录变化、需要容错）。新开一个文件就多一份
/// 「损坏隔离 + 原子写 + 版本迁移」的维护面，而收益是零。
///
/// ## 形状
///
/// ```text
/// prefs.favorites: [id, …]   已下线（2026-10-03），见下方说明；字段保留只因旧状态文件里有它
/// prefs.recent:   [id, …]        上限 RECENT_LIMIT，**最近的在前**（索引 0 = 最新）
/// ```
///
/// `recent` 用「**删掉旧位置 → 插到索引 0 → 截尾**」实现 LRU。选这个方向而不是
/// 「追加到尾部 + 读取时排序」：读取端只要取前 N 个，不用每次渲染都排一遍。
///
/// ## favorites 为什么整链下线（2026-10-03 用户裁定）
///
/// 优化列表每行末尾的收藏星标被删除：它既没有消费场景（没有「只看收藏」筛选、
/// 没有按收藏排序），又吃掉行尾最贵的一格横向空间，把长标题挤成竖排单字。
/// 与其留一个不产生任何决策的按钮，不如把 `favorites` 的**写侧**（`set_favorite`）
/// 与命令面（`optimizer:set-favorite` 通道）一并摘掉，避免留下永不被调用的死通道。
/// `favorites` 键在**旧状态文件里可能已存在**，读侧一律忽略、不迁移、不展示。
const RECENT_LIMIT: usize = 10;

/// 读偏好段。**孤儿 id 静默忽略**。
///
/// 为什么静默而不是报错：用户打开过某个优化项，之后目录把它退役了（`retired-optimizations.json`
/// 收编、或直接删掉）。那不是用户的错，也不是数据损坏 —— 报「记录项不存在」只会让用户
/// 以为应用坏了。调用方（渲染层）拿到的列表里不会有那些 id。
pub fn prefs_view() -> Vec<String> {
    let st = load();
    st.get("prefs")
        .and_then(|p| p.get("recent"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .filter(|id| !id.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// 记一次「最近使用」。LRU：移到最前 + 截尾到 RECENT_LIMIT。
pub fn touch_recent(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    // v4 P2-D 尾：写侧走 update_state（读失败拒写）
    //
    // 性能修复（P1 批次）：旧写法先 `load()` 预读一次算 LRU，再由 `update_state` 内部
    // 读第二次 = **2 读 1 写**；更糟的是两次读之间没有锁，并发 touch 各自按旧快照算表、
    // 后写的把先写的整段 `recent` 覆盖掉（AGENTS §5.28「读-改-写要问谁可能并行写它」）。
    // 现在「读旧表」挪进闭包：读与写同在 `security::update_json` 的串行化里 ⇒ 1 读 1 写，
    // 且不丢更新。
    update_state(|st| {
        if let Some(o) = st.as_object_mut() {
            let prefs = o.entry("prefs").or_insert_with(|| json!({}));
            if let Some(p) = prefs.as_object_mut() {
                let mut recent: Vec<String> = p
                    .get("recent")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                recent.retain(|x| x != id);
                recent.insert(0, id.to_string());
                recent.truncate(RECENT_LIMIT);
                p.insert("recent".into(), json!(recent));
            }
        }
        Ok(())
    })
}

fn load_state() -> (Value, bool) {
    let f = state_file();
    // v5-K01 批次 4（R7-M05）：三态读器——读失败（Corrupt，含 IO 失败）已在
    // read_json_state 内 warn 留痕，不再与「没有配置」同归静默空；这里降级空骨架
    // 只影响读侧预读，写侧 update_state 拒 Corrupt，不会把空骨架写出去。
    // A1-M12：把 Corrupt 位带回给回执，读失败与「确实没有状态」分开。
    let (v, degraded) = match security::read_json_state(&f) {
        security::JsonState::Ok(v) => (v, false),
        security::JsonState::Absent => (empty_state(), false),
        security::JsonState::Corrupt => (empty_state(), true),
    };
    let v = match v {
        Value::Object(m) if m.get("items").map(|x| x.is_object()).unwrap_or(false) => {
            let mut o = m;
            if !o.get("detected").map(|x| x.is_object()).unwrap_or(false) {
                o.insert("detected".into(), json!({}));
            }
            // E10：prefs 段缺失时补空骨架（老状态文件没有这段）。
            // 刻意**不校验内容**：recent 里的 id 可能在目录删项后变成孤儿，
            // 那是**预期内**的（见 prefs_view 的注释），不是损坏。
            // `favorites` 只在骨架里保留占位：旧状态文件里可能有它，读侧一律忽略。
            if !o.get("prefs").map(|x| x.is_object()).unwrap_or(false) {
                o.insert("prefs".into(), json!({ "favorites": [], "recent": [] }));
            }
            Value::Object(o)
        }
        _ => empty_state(),
    };
    (v, degraded)
}

fn load() -> Value {
    load_state().0
}

/// 三视图的**唯一提取口径**：一次 `load()` 的结果 → 各段的引用。
/// [`all`] / [`detected_all`] / [`dismissed_map`] 与 [`Snapshot`] 的三个访问器都走这里
/// （AGENTS §5.16：同一个判定不许有两份实现，否则合并读之后段名改名/挪层会出现
/// 「快照读到、旧函数读不到」的分叉）。
fn items_of(st: &Value) -> Option<&Map<String, Value>> {
    st.get("items").and_then(Value::as_object)
}

fn detected_of(st: &Value) -> Option<&Map<String, Value>> {
    st.get("detected").and_then(Value::as_object)
}

fn dismissed_of(st: &Value) -> Option<&Map<String, Value>> {
    st.get("prefs").and_then(|p| p.get("staleDismissed")).and_then(Value::as_object)
}

/// 段缺失时的**共享空表**：视图访问器返回引用，不为「这一层没有」再分配一份 Map。
fn empty_map() -> &'static Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(Map::new)
}

/// `optimization-state.json` 的**一次读盘快照**（三视图共用同一份解析结果）。
///
/// ## 为什么要有它
///
/// `optimizer:state-overview` 同时要 `items` / `staleDismissed` / `detected` 三段，
/// 而三个视图函数各自 `load()` ⇒ 同一个文件**全量读盘 + 解析三遍**。快照把「读」收成
/// 一次，视图只借引用（顺带省掉三段各自的深克隆）。
///
/// ## 约束
///
/// 快照**只读**：它不接任何写路径。写侧一律走 `update_state`，由
/// `security::update_json` 在自己的锁内**重新读**再改 —— 所以不存在「拿着旧快照写、
/// 覆盖别人的改动」这种形态，`Snapshot` 也就没暴露 `&mut`。
pub struct Snapshot {
    st: Value,
}

impl Snapshot {
    /// 记账段（`items`）；缺段按空表（与 [`all`] 的降级口径一致）
    pub fn items(&self) -> &Map<String, Value> {
        items_of(&self.st).unwrap_or(empty_map())
    }

    /// 检测结果段（`detected`）；缺段按空表（与 [`detected_all`] 一致）
    pub fn detected(&self) -> &Map<String, Value> {
        detected_of(&self.st).unwrap_or(empty_map())
    }

    /// 「不再提醒」名单（`prefs.staleDismissed`）；缺段按空表（与 [`dismissed_map`] 一致）
    pub fn dismissed(&self) -> &Map<String, Value> {
        dismissed_of(&self.st).unwrap_or(empty_map())
    }
}

/// 读一次状态文件并派生快照（走的是同一个 `load()`：三态读器 + 骨架补齐 + 损坏降级
/// 空骨架的口径与三个视图函数逐字相同）。
pub fn snapshot() -> Snapshot {
    snapshot_with_health().0
}

/// A1-M12：与 [`snapshot`] 同一份读盘，额外返回「本次读是否降级（Corrupt）」。
pub fn snapshot_with_health() -> (Snapshot, bool) {
    let (st, degraded) = load_state();
    (Snapshot { st }, degraded)
}

/// 写侧骨架校验（v4 P2-D 尾）：结构与 `load()` 的接受面**同判据**，但方向是拒写。
/// `{}` 视为「首写」（Absent 由 update_json 给空对象），从空骨架起步。
fn ensure_skeleton(st: &mut Value) -> Result<(), String> {
    if st.as_object().map(|o| o.is_empty()).unwrap_or(false) {
        *st = empty_state();
        return Ok(());
    }
    let Some(o) = st.as_object_mut() else {
        return Err("状态文件结构异常（非对象）".into());
    };
    if !o.get("items").map(|x| x.is_object()).unwrap_or(false) {
        return Err("状态文件结构不符（缺 items），已拒绝写入".into());
    }
    if !o.get("detected").map(|x| x.is_object()).unwrap_or(false) {
        o.insert("detected".into(), json!({}));
    }
    if !o.get("prefs").map(|x| x.is_object()).unwrap_or(false) {
        o.insert("prefs".into(), json!({ "favorites": [], "recent": [] }));
    }
    Ok(())
}

/// 读-改-写（v4 P2-D 尾 / R7-M01 同族）：**读失败绝不落到写**。所有记账入口都走它 ——
/// 旧链 `load()`（损坏 ⇒ 空骨架）→ 改 → `save()` 会把整本优化账（items/detected/prefs）
/// 清成「只剩这次改的一条」，且回执仍是普通成功/失败。
fn update_state(f: impl FnOnce(&mut Value) -> Result<(), String>) -> bool {
    match security::update_json(&state_file(), |st| {
        ensure_skeleton(st)?;
        f(st)
    }) {
        Ok(_) => true,
        Err(e) => {
            log::write_log("error", &format!("优化状态读取失败（已拒绝写入）: {e}"));
            false
        }
    }
}

fn iso_now() -> String {
    crate::engine::delete_manifest::iso_now()
}

/// 执行前记账（pending）。false = 写入失败，调用方必须中止（fail-closed）。
pub fn record_pending(id: &str, title: &str, kinds: &[String]) -> bool {
    record_pending_scoped(id, title, kinds, None)
}

/// [`record_pending`] 的完整形态：把「本次只施加了哪几个目标」一起记账。
///
/// 为什么必须落盘而不是只在内存里传（2026-10-05 真机反馈）：批量项支持逐项勾选后，
/// 回读判据要按**当时勾的那几个**收窄。执行链里拿得到 `RunParams`，而启动时的
/// `optimizer:state-overview` 只拿得到账本 —— 不记这一笔，子集用户每次开机都被
/// 按全量清单判成「未完成还原」（另外 62 个服务当然还是原值）。
///
/// `None` 或空 = 全选 ⇒ **删掉** `picked` 键（不写 null）：旧账本里残留的子集会
/// 把下一次全选的判定继续收窄，那是「做了 65 个只报 3 个」的反向谎报。
pub fn record_pending_scoped(
    id: &str,
    title: &str,
    kinds: &[String],
    picked: Option<&[String]>,
) -> bool {
    if id.is_empty() {
        return false;
    }
    let allowed: Vec<Value> = kinds
        .iter()
        .filter(|k| matches!(k.as_str(), "reg" | "cmd" | "service"))
        .map(|k| json!(k))
        .collect();
    // v4 P2-D 尾：写侧走 update_state（读失败拒写）
    update_state(|state| {
        if let Some(items) = state.get_mut("items").and_then(|v| v.as_object_mut()) {
            let mut rec = json!({
                "title": if title.is_empty() { id } else { title },
                "appliedAt": iso_now(),
                "kinds": allowed,
                "status": "pending",
                "lastVerify": Value::Null,
                "verifiedAt": Value::Null
            });
            if let Some(list) = picked.filter(|p| !p.is_empty()) {
                // R3-M06（v7.2 C04）：picked 记「净变化并集」而非「最后一次选择」。
                // 批量项先勾子集 A 再勾子集 B，两批写入都真实发生；旧实现整条 rec
                // 重建把 picked 覆盖成 B ⇒ A 的目标从此退出回读断言面（scope_checks
                // 只按 picked 收窄）。与 2026-10-09 用户裁定的「计数按净变化集合」
                // 同一口径。全选（None/空）仍删键 = 作用域回到全量（旧注释语义不变）。
                let mut union: Vec<String> = items
                    .get(id)
                    .and_then(|old| old.get("picked"))
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                for x in list {
                    if !union.iter().any(|u| u == x) {
                        union.push(x.clone());
                    }
                }
                rec["picked"] = json!(union);
            }
            items.insert(id.into(), rec);
        }
        // 重新执行 = 状态刚变过，用户之前的「不再提醒」失效（若又落 partial 应重新提醒）
        clear_stale_dismissed(state, id);
        Ok(())
    })
}

/// 执行后转正（applied）+ 回读验证三态
pub fn mark_applied(id: &str, verify: &str) -> bool {
    let v = normalize_verify(verify);
    let found = std::cell::Cell::new(false);
    // v4 P2-D 尾：写侧走 update_state（读失败拒写；账本条目不存在时如实回 false）
    let ok = update_state(|state| {
        if let Some(rec) = state
            .get_mut("items")
            .and_then(|i| i.as_object_mut())
            .and_then(|m| m.get_mut(id))
            .and_then(|r| r.as_object_mut())
        {
            found.set(true);
            rec.insert("status".into(), json!("applied"));
            rec.insert("lastVerify".into(), json!(v));
            rec.insert("verifiedAt".into(), json!(iso_now()));
            // 根治「未完成还原横幅每次都弹」（2026-10-03 用户拍板）：记账写入路径统一清忽略——
            // 该项状态刚被本轮执行改变，忽略记录代表的是「对上一轮结果的处置」，已失效。
            clear_stale_dismissed(state, id);
        }
        Ok(())
    });
    ok && found.get()
}

/// 执行链整体失败（编译/启动阶段就没跑成，非「跑完但部分失败」）时落账。
///
/// 审查 v3-K1：旧失败路径走 `mark_applied("unknown")`，违反不变式②「执行成功
/// 才转正 applied」——账本谎报。partial 状态如实表达「没有执行成功，pending
/// 期间可能有已落盘的步骤」，optimizer_state_overview 原样呈现。
pub fn mark_partial(id: &str) -> bool {
    mark_partial_with_reasons(id, &[])
}

/// mark_partial 的完整形态：带**失败子步原因明细**（根治「未完成还原横幅」第二只脚，
/// 2026-10-03 用户拍板）。此前 partial 只记状态不记原因，失败细节只在日志里——
/// 用户看到「状态不明」却无从判断该还原还是该重跑。reasons 截前 8 条防记账膨胀
/// （70+ 服务项可能有几十个失败步，横幅与详情只需要头部原因）。
pub fn mark_partial_with_reasons(id: &str, reasons: &[String]) -> bool {
    if id.is_empty() {
        return false;
    }
    let found = std::cell::Cell::new(false);
    // v4 P2-D 尾：写侧走 update_state（读失败拒写；账本条目不存在时如实回 false）
    let ok = update_state(|state| {
        if let Some(rec) = state
            .get_mut("items")
            .and_then(|i| i.as_object_mut())
            .and_then(|m| m.get_mut(id))
            .and_then(|r| r.as_object_mut())
        {
            found.set(true);
            rec.insert("status".into(), json!("partial"));
            rec.insert(
                "partialReasons".into(),
                json!(reasons.iter().take(8).cloned().collect::<Vec<_>>()),
            );
            clear_stale_dismissed(state, id);
        }
        Ok(())
    });
    ok && found.get()
}

/// 还原成功销账（本就不存在视为成功）
pub fn remove(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    let one = [id.to_string()];
    // 委托给批量实现：单条 = 长度为 1 的批次，判据只有一份（§5.16）
    remove_many(&one)
}

/// 批量销账：**一次**读-改-写删掉多个 id（连同各自的 stale 忽略记录）。
/// 空批次不落盘并返回 `true`（没有要删的东西 ≠ 写失败）。
///
/// 为什么要有它：`optimizer:state-overview` 在 `for (id, rec) in raw` 里对「动态项遗留
/// pending」逐条调 [`remove`] ⇒ 每条一次 `update_json` 全量重写（读 + 序列化 + fsync +
/// rename + 目录 flush），账本里这类条目数不定，最坏情况是启动一次把整本文件重写若干遍。
///
/// ⚠️ **行为变更（这里与逐条 remove 不等价）**：落盘次数 N → 1，语义由「逐条独立、
/// 中途 IO 失败会留下已删一半的状态」变成「**要么全删要么全不删**」。可接受的理由：
/// ① 待删的只是动态项的**遗留 pending 垃圾账**，本轮概览已在循环里把它们从响应里排除
/// （`continue`），删与不删都不改变用户看到的任何判定；② 写失败时 `update_state` 照旧
/// 如实返回 false 并 error 留痕，**不**降级成「基于空骨架写」（fail-closed 未放宽），
/// 垃圾账原样留着、下次概览再清；③ 单批走 `security::atomic_write_json`，
/// 撕裂态本来就不存在，而「前 k 条已落盘、第 k+1 条失败」恰恰是旧实现**唯一**会产生的
/// 中间态 —— 合并后反而消失了。
pub fn remove_many(ids: &[String]) -> bool {
    if ids.is_empty() {
        return true;
    }
    // v4 P2-D 尾：写侧走 update_state（读失败拒写；销账不存在的 id 是 no-op）
    update_state(|state| {
        for id in ids {
            remove_one_from_state(state, id);
        }
        Ok(())
    })
}

/// 销账的**单条动作**（[`remove`] 与 [`remove_many`] 共用，判据只有一份）
fn remove_one_from_state(state: &mut Value, id: &str) {
    // 销账 = 该项不再有 stale 状态，忽略记录一并清掉（留着是垃圾，还会在
    // 「重新执行 → 又 partial」时让第一次提醒被旧忽略错误吞掉）。
    clear_stale_dismissed(state, id);
    if let Some(items) = state.get_mut("items").and_then(|v| v.as_object_mut()) {
        items.remove(id);
    }
}

// ==================== 「未完成还原」横幅的 per-id 忽略（2026-10-03 根治） ====================
//
// 背景：v5 P2 让「非可检测项的 partial」也进启动横幅（修复「半成功不可见」），
// 但 cmd 类项每次重跑都必有失败子步（Edge 计划任务会被系统重建、服务里有禁不掉的），
// 记账停在 partial 永不自愈，横幅又没有忽略出口 ⇒ 每次启动都弹。根治方案：
// ① 横幅加「不再提醒」⇒ dismiss_stale；② 记账带失败原因 ⇒ mark_partial_with_reasons；
// ③ 该项重新执行/还原销账时自动移除忽略（clear_stale_dismissed）——状态刚变过，
// 若又 partial 应重新提醒，旧忽略不得吞掉新提示。

/// 记录「不再提醒」。幂等（重复 dismiss 更新时间戳）。
pub fn dismiss_stale(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    // v4 P2-D 尾：写侧走 update_state（读失败拒写）
    update_state(|state| {
        if let Some(p) = state.get_mut("prefs").and_then(|v| v.as_object_mut()) {
            let d = p.entry("staleDismissed").or_insert_with(|| json!({}));
            if let Some(m) = d.as_object_mut() {
                m.insert(id.into(), json!(iso_now()));
            }
        }
        Ok(())
    })
}

/// 读取忽略名单（overview 过滤 staleIds 用）
///
/// 单独调用仍是「一次读盘 + 一次深克隆」。同一个命令里还要读 items/detected 时，
/// 请用 [`snapshot`] —— 三个视图各自调本函数 = 同一个文件读三遍。
pub fn dismissed_map() -> Map<String, Value> {
    dismissed_of(&load()).cloned().unwrap_or_default()
}

/// 从忽略名单移除单项（无则静默成功）
fn clear_stale_dismissed(state: &mut Value, id: &str) {
    if let Some(d) = state
        .get_mut("prefs")
        .and_then(|p| p.get_mut("staleDismissed"))
        .and_then(Value::as_object_mut)
    {
        d.remove(id);
    }
}

/// 全部记账条目
///
/// 单独调用仍是「一次读盘 + 一次深克隆」。同一个命令里还要读 detected / 忽略名单时，
/// 请用 [`snapshot`]（三视图共用一次读取）。
pub fn all() -> Map<String, Value> {
    items_of(&load()).cloned().unwrap_or_default()
}

/// 单条记账（无则 null）
pub fn get(id: &str) -> Option<Value> {
    items_of(&load()).and_then(|m| m.get(id)).cloned()
}

/// 回写单条检测结果
pub fn set_detected_entry(id: &str, optimized: bool) -> bool {
    if id.is_empty() {
        return false;
    }
    // v4 P2-D 尾：写侧走 update_state（读失败拒写）
    update_state(|state| {
        if let Some(d) = state.get_mut("detected").and_then(|v| v.as_object_mut()) {
            d.insert(
                id.into(),
                json!({ "optimized": optimized, "at": iso_now() }),
            );
        }
        Ok(())
    })
}

/// 读取全部检测结果
///
/// 单独调用仍是「一次读盘 + 一次深克隆」。同一个命令里还要读 items / 忽略名单时，
/// 请用 [`snapshot`]。
pub fn detected_all() -> Map<String, Value> {
    detected_of(&load()).cloned().unwrap_or_default()
}

fn normalize_verify(v: &str) -> &'static str {
    match v {
        "pass" => "pass",
        "partial" => "partial",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// **本组用例共用一个真实状态文件**（`<数据目录>/optimization-state.json`），
    /// 而 `cargo test` 默认多线程跑 —— 两条用例各自 `load()` 出快照、改一处、
    /// `save()` 整个写回，就是**后写覆盖先写**。撞上时哪条都可能是输家：
    /// `touch_recent` 的清理夹具会把别人的 recent 条目挤出上限，
    /// `record_pending` 造的条目也会被对方的整份写回抹掉 ⇒
    /// `mark_partial_with_reasons` 因 `items` 里找不到 id 而返 false。
    ///
    /// **为什么用锁而不是「把两条并成一条」**（本条踩过两次）：
    /// 合并法只对**当时那两条**有效，2026-10-03 新增 `stale忽略与失败原因记账契约`
    /// 后又立刻复发（3 次连跑 2 红）。只要还有人往这个 mod 里加用例，合并就会被
    /// 推翻第三次。锁是**对新增用例自动生效**的方案 —— 规矩写在 mod 头，
    /// 下一条用例照抄一行 `_state_guard()` 即可，不必知道历史上撞过什么。
    ///
    /// 锁本身不解决「断言互相污染」（两人都往同一份文件里写），只保证**不并发交错**。
    /// 残留：顺序执行下 A 的清理夹具仍会留下 B 的 recent 条目，但 B 的断言只看
    /// **自己造的那部分**（见各用例注释），所以不构成失败。
    fn _state_guard() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            // 中毒（前一 panic 持锁退出）也要能跑，否则一次失败会连锁成整组红
            .unwrap_or_else(|e| e.into_inner())
    }

    /// E10：最近使用（recent）的行为契约（LRU / 幂等 / 空 id / 孤儿 id）+ 收藏已下线的反向断言。
    ///
    /// 三条要断的理由各不相同：
    /// · recent LRU：最近的在**最前**，超上限丢**最久远的**
    /// · 重复 touch 不产生重复项
    /// · 空 id 拒写（否则 prefs 里会出现空串项，渲染层会显示一个无名条目）
    /// · 孤儿 id 静默读出（不剔除）
    /// · 收藏链路**必须已经消失**（2026-10-03 用户裁定删星标）——反向断言防复活
    #[test]
    fn e10_recent契约与收藏下线() {
        let _guard = _state_guard();
        use crate::engine::optimization_state as st;
        // 上限在实现侧是 `RECENT_LIMIT`（模块私有）；测试侧复述一次并与实现比对
        const RECENT_LIMIT_FOR_TEST: usize = 10;

        // ⚠️ **不假设「初始为空」**：本组用例跑的是**真实状态文件**（同机开发），
        // 判红实验跑过之后里面会留残留（首版就踩过：判红实验把 tmp* 写进去，
        // 恢复后本条因「实际非空」而红 —— 看起来像实现坏了，其实是夹具脆弱）。
        // 正确做法：自己写自己清，且断言只看**自己造的那部分**。

        // ① recent LRU：最近的在最前 + 超上限丢最久远的
        for i in 0..12 {
            assert!(st::touch_recent(&format!("id{i}")), "写 recent 失败（id{i}）");
        }
        let r3 = st::prefs_view();
        assert_eq!(r3.len(), 10, "recent 超过上限 10 却没有截断：len={}", r3.len());
        assert_eq!(r3[0], "id11", "最近的必须在最前，实际 index0={}", r3[0]);
        assert!(
            !r3.contains(&"id0".to_string()) && !r3.contains(&"id1".to_string()),
            "最久远的两个没被丢掉（截尾方向反了）：{r3:?}"
        );
        // 重复 touch 同一个 id：移到最前且**不重复**
        assert!(st::touch_recent("id11"), "重复 touch 失败");
        let r4 = st::prefs_view();
        assert_eq!(
            r4.iter().filter(|x| *x == "id11").count(),
            1,
            "重复 touch 产生了重复项：{r4:?}"
        );
        assert_eq!(r4[0], "id11", "重复 touch 后应仍在最前");

        // ② 空 id 拒写
        assert!(!st::touch_recent(""), "空 id 的 recent 必须被拒");

        // ③ 收藏链路已下线：写侧函数与命令面都不该复活。
        //    判红点很实——把 stars 改回来就会在这里红。
        //
        //    **判据必须切出生产段**（本条踩过两次）：`include_str!` 读整个文件、含测试
        //    模块自身。判据字面量只要出现在注释或断言里，反向判据会匹配到自己 ⇒ 恒红；
        //    正向判据会匹配到自己的注释 ⇒ 假绿。substring 判据撞上同类代码就会这样，
        //    本仓已多次踩这族（R0-c / M2-B / aidesc 的 zhihu 头 / check-readme 的
        //    GROUP_ORDER）。**写判据时不要在注释里贴判据原文**，否则又匹配回去。
        //    锚点用带换行的 `#[cfg(test)`+`mod tests`：裸串在本文件的注释里也出现过，
        //    用它 split 会在注释处提前截断 ⇒ 生产段为空 ⇒ 恒红。
        let src = include_str!("optimization_state.rs");
        let prod = src.split("#[cfg(test)]\nmod tests").next().unwrap_or("");
        assert!(
            !prod.contains("pub fn set_favorite"),
            "收藏写侧函数又出现了 —— 收藏星标已于 2026-10-03 整链下线"
        );
        let ov = include_str!("../commands/optimizer/overview.rs");
        assert!(
            !ov.contains("pub async fn optimizer_set_favorite"),
            "收藏写侧命令又出现了 —— 通道已下线"
        );
        // 正向：recent 的生产段必须还在（防「反向判据通过是因为整段被删了」这种假绿）
        assert!(
            prod.contains("pub fn prefs_view") && prod.contains("pub fn touch_recent"),
            "recent 的读/写函数都不见了 —— 下线判据是因为代码被误删才通过的（假绿）"
        );

        // ③ 孤儿 id 静默忽略：目录删项后 recent 里的 id 仍能被读出，由渲染层决定
        //    不显示 —— 后端**不报错、不剔除**（剔除会让「这项被打开过」这个事实消失）。
        //
        //    **为什么这段并在本用例里、而不是单开一条**：本条历史上踩过 —— 单开那条
        //    写完夹具正要读时，本条的清理夹具正好 touch 了 20 个条目把它挤出上限，
        //    于是「孤儿 id 读不出」而红了。看起来像实现坏了，其实是夹具竞态。
        //    并进来只是当时的权宜之计；**根治是 mod 头的 `_state_guard()`**（本组
        //    全部用例持同一把锁，不并发交错）—— 合并只对当时那两条有效，新增第三条
        //    就会复发（`stale忽略与失败原因记账契约` 加进来时确实又红过）。
        assert!(st::touch_recent("__已退役的优化项__"), "写入夹具失败");
        let r5 = st::prefs_view();
        assert!(
            r5.contains(&"__已退役的优化项__".to_string()),
            "recent 里的孤儿 id 被后端悄悄剔除了 —— 语义应是「读出后由渲染层决定不显示」，             后端剔除会让「这项曾被打开过」这个事实消失（退役清单里仍可能想找回）：{r5:?}"
        );

        // 清理夹具：recent 无法逐条删除（只有 touch），用**超量 touch 把自己的条目挤出上限**。
        for i in 0..(RECENT_LIMIT_FOR_TEST * 2) {
            let _ = st::touch_recent(&format!("__cleanup{i}"));
        }
    }

    /// E10：prefs 段缺失时（旧状态文件）能自动补骨架，不 panic。
    #[test]
    fn e10_旧状态文件缺prefs段能补骨架() {
        // 用源码结构断言：load() 里必须有「prefs 缺失 → 补空骨架」这一步。
        // 写真正的「旧文件」会污染本机状态文件，而优化域的其它用例依赖它。
        let src = include_str!("optimization_state.rs");
        assert!(
            src.contains("\"prefs\"") && src.contains("or_insert_with"),
            "prefs 段缺失时没有补骨架的路径 —— 旧状态文件会让 touch_recent 静默失败"
        );
        assert!(
            src.contains("RECENT_LIMIT: usize = 10"),
            "recent 上限常量必须是 10（方案 §3.5 E10：recent 上限 10 + LRU）"
        );
    }

    /// 根治「未完成还原横幅每次都弹」（2026-10-03 用户拍板）的行为契约：
    /// dismiss 后进忽略名单；该项**重新记账/转正/销账**时忽略被自动清除；
    /// mark_partial_with_reasons 把失败原因写进条目。跑真实状态文件，
    /// 夹具「自己写自己清」，断言只看自己造的部分。
    #[test]
    fn stale忽略与失败原因记账契约() {
        let _guard = _state_guard();
        use crate::engine::optimization_state as st;
        let id = "__stale_dismiss_fixture__";
        // 造一条 pending 记账（record_pending 会清忽略——先 dismiss 再验证清除语义）
        let kinds = vec!["cmd".to_string()];
        assert!(st::record_pending(id, "夹具项", &kinds), "写 pending 失败");
        assert!(st::dismiss_stale(id), "写忽略失败");
        assert!(st::dismissed_map().contains_key(id), "dismiss 后必须在忽略名单里");

        // 重新记账（record_pending）= 状态变了，忽略必须被自动清除
        assert!(st::record_pending(id, "夹具项", &kinds), "重写 pending 失败");
        assert!(
            !st::dismissed_map().contains_key(id),
            "重新记账后旧忽略必须被自动清除 —— 否则新一轮 partial 会被旧忽略吞掉"
        );

        // partial + 失败原因：原因进条目（截 8 条）
        let reasons: Vec<String> = (1..12).map(|i| format!("步骤「t{i}」: 命令返回非零")).collect();
        assert!(st::mark_partial_with_reasons(id, &reasons), "写 partial 失败");
        let rec = st::get(id).expect("partial 记账消失");
        let got = rec.get("partialReasons").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        assert_eq!(got.len(), 8, "失败原因必须截前 8 条（防记账膨胀），实际 {}", got.len());
        assert!(got[0].as_str().unwrap_or("").contains("t1"), "截断方向反了（留下的不是头部原因）");

        // dismiss → 销账：条目与忽略记录一起消失
        assert!(st::dismiss_stale(id), "写忽略失败");
        assert!(st::remove(id), "销账失败");
        assert!(st::get(id).is_none(), "销账后条目应消失");
        assert!(
            !st::dismissed_map().contains_key(id),
            "销账后忽略记录必须一并清掉 —— 留着会在「重新执行 → 又 partial」时吞掉第一次提醒"
        );

        // 边界：空 id 拒绝
        assert!(!st::dismiss_stale(""), "空 id 必须被拒");
    }

    /// 合并读的**正向对照**（性能修复 P1）：`snapshot()` 的三个视图必须与三个独立视图
    /// 函数**同内容** —— 断的是「把三遍读收成一遍，没有另起一套段提取判据」。
    ///
    /// 判红实验（已实跑）：把 `Snapshot::dismissed()` 改读 `items_of`，本条立刻红；
    /// 把 `dismissed_of` 的段名 `staleDismissed` 改一个字母，本条与
    /// `stale忽略与失败原因记账契约` 一起红（两侧共用同一份提取，不分叉）。
    ///
    /// 为什么在本文件而不在 `tests/module_smoke.rs`：判据对象是模块私有的
    /// `items_of/detected_of/dismissed_of`，冒烟网够不着这一层。
    #[test]
    fn snapshot三视图与三个视图函数同内容() {
        let _guard = _state_guard();
        use crate::engine::optimization_state as st;
        let snap = st::snapshot();
        assert_eq!(*snap.items(), st::all(), "items 视图与 all() 分叉 —— 段提取出现两套判据");
        assert_eq!(*snap.detected(), st::detected_all(), "detected 视图与 detected_all() 分叉");
        assert_eq!(*snap.dismissed(), st::dismissed_map(), "dismissed 视图与 dismissed_map() 分叉");
    }

    /// 批量销账的行为契约（性能修复 P1 的**语义变更面**）：一批里每条都要删净，
    /// 且条目与忽略记录同删（与逐条 `remove` 同口径）；空批次不落盘但算成功。
    ///
    /// 判红实验（已实跑）：把 `remove_many` 的循环改成只删 `ids[0]`，本条因
    /// 「第 2、3 条销账后条目仍在」判红 —— 证明「要么全删」这条新语义真在守东西。
    /// 夹具自产自清：三条 id 的条目与忽略记录都由本条删掉。
    #[test]
    fn remove_many单批删净且连忽略记录一起清() {
        let _guard = _state_guard();
        use crate::engine::optimization_state as st;
        let ids: Vec<String> = ["__batch_a__", "__batch_b__", "__batch_c__"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        for id in &ids {
            let kinds = vec!["cmd".to_string()];
            assert!(st::record_pending(id, "批量夹具", &kinds), "{id} 写 pending 失败");
            assert!(st::dismiss_stale(id), "{id} 写忽略失败");
        }
        assert!(st::remove_many(&ids), "批量销账失败");
        for id in &ids {
            assert!(st::get(id).is_none(), "{id} 销账后条目仍在 —— 批量删除漏条目");
            assert!(!st::dismissed_map().contains_key(id), "{id} 销账后忽略记录仍在");
        }
        // 空批次：不写盘也算成功（「没有要删的」≠「写失败」）
        assert!(st::remove_many(&[]), "空批次必须视为成功");
    }

    /// R3-M06（v7.2 C04）判红点：picked 记「净变化并集」——先勾 A 再勾 B，账本
    /// 必须同时罩住两批目标（旧实现整条 rec 重建覆盖成 B ⇒ A 退出回读断言面）；
    /// 全选（None/空）仍删键回全量作用域。破坏形态 = 恢复「picked = 本次选择」
    /// 直写 ⇒ 中段的并集断言红。
    #[test]
    fn m06_picked_净变化并集() {
        let _guard = _state_guard();
        use crate::engine::optimization_state as st;
        let id = "__m06_probe";
        // 清场 + 只看自己造的条目（本组用例跑真实状态文件，见 mod 头注释）
        let _ = st::remove(id);
        let a: Vec<String> = ["svcA", "svcB"].iter().map(|s| s.to_string()).collect();
        let b: Vec<String> = ["svcB", "svcC"].iter().map(|s| s.to_string()).collect();
        assert!(st::record_pending_scoped(id, "m06", &["service".into()], Some(&a)));
        assert!(st::record_pending_scoped(id, "m06", &["service".into()], Some(&b)));
        let picked: Vec<String> = st::get(id)
            .and_then(|r| r.get("picked").and_then(|v| v.as_array()).cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        for name in ["svcA", "svcB", "svcC"] {
            assert!(
                picked.iter().any(|x| x == name),
                "picked 必须是两批的并集，缺 {name}：{picked:?}"
            );
        }
        assert_eq!(picked.len(), 3, "并集不得产生重复项：{picked:?}");
        // 全选重置：picked 键删除，作用域回全量
        assert!(st::record_pending_scoped(id, "m06", &["service".into()], None));
        let rec = st::get(id).expect("条目应存在");
        assert!(
            rec.get("picked").is_none(),
            "全选必须删掉 picked 键（残留会把全选判定收窄）：{:?}",
            rec.get("picked")
        );
        let _ = st::remove(id);
    }
}
