//! 优化项目录与判定表：`optimizer-runtime.json` 的运行时导出、生效粒度（applyScope）、
//! 退役账本（retired）与高危确认清单。
//!
//! **数据真源不在这里**：OPTIONS 数组的原始真源是上游 `optimizer-scripts.js`，
//! `src-tauri/data/optimizer-runtime.json` 是它的逐字节序列化，`check-data-parity` P2
//! 逐字段对拍两侧 —— 本文件只消费，不改写、不另立字段表。
//! 退役一条项必须两侧同删（只删产物会做出 908 处漂移）。

use serde_json::{Value, json};
use std::sync::OnceLock;
// ==================== 选项数据（运行时完整导出，含推理 restore） ====================
pub(super) const OPTIONS_JSON: &str = include_str!("../../../data/optimizer-runtime.json");

/// 哨兵步骤脚本（仅用于提取与 JS buildScript 完全一致的前置 preamble 段）
pub(super) const BUILD_SENTINEL: &str = include_str!("../../../ps/optimizer_build.ps1");

pub(super) fn options() -> &'static Vec<Value> {
    static OPTS: OnceLock<Vec<Value>> = OnceLock::new();
    OPTS.get_or_init(|| serde_json::from_str(OPTIONS_JSON).expect("optimizer-runtime.json 合法"))
}

pub(super) fn find_option(id: &str) -> Option<&'static Value> {
    options().iter().find(|o| o.get("id").and_then(|v| v.as_str()) == Some(id))
}

/// v2-M14 接线：退役优化项清单（项从目录移除后在此登记）。
///
/// 上游 Electron 轨靠 `version-migrations.js` 在启动时把这些项的注册表备份**静默写回**；
/// 本轨刻意不抄那一段——无人确认的 HKLM 写入与「危险操作先确认」的安全模型冲突。
/// 真正的缺陷在另一半：还原通道只认目录里的 id，于是退役项留下的备份**连手动出口都没有**。
/// 现在两半都补上：还原认得退役 id，概览把本机确有备份的那些列成待还原清单交用户点。
pub(super) const RETIRED_JSON: &str = include_str!("../../../data/retired-optimizations.json");

pub(super) fn retired_items() -> &'static [Value] {
    static CACHE: OnceLock<Vec<Value>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let parsed: Value =
                serde_json::from_str(RETIRED_JSON).expect("retired-optimizations.json 合法");
            parsed
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|i| !i["id"].as_str().unwrap_or("").is_empty())
                .collect()
        })
        .as_slice()
}

pub(super) fn is_retired_id(id: &str) -> bool {
    retired_items()
        .iter()
        .any(|i| i["id"].as_str() == Some(id))
}

// ==================== 生效粒度（applyScope）====================
//
// 借鉴 BoosterX §B2：它的顶层不是优化项列表而是「方案」，方案级决定生效时要哪种重启粒度。
// 本仓 114 项此前**完全没有**这一层 —— `optimizer.rs` 里 grep `重启|reboot|logoff|explorer`
// 零命中，用户勾完一批只能在各项 desc 的自然语言里自己找「需要重启」。
//
// 粒度刻意只留三档：`explorer` 有现成出口（`contextmenu_restart_explorer` 走同一套
// `cm_restart_explorer` 机制），`reboot` 是用户自己重启。BoosterX 的「重启显卡驱动」档
// 不抄 —— 它靠 `restart64.exe` 做 PnP 枚举级重启，而那份对标报告 §1 已把具体实现标为【C】
// 未取到，本仓也没有这个能力；没有执行原语的档位只是把猜测写进用户可见的建议里。
// 同理不做 `logoff`：没有登出原语，能登出解决的项归到 reboot 提示。
pub(super) const SCOPE_JSON: &str = include_str!("../../../data/optimizer-scope.json");

/// 档位序：取集合内最大值即整批的粒度（none 被 explorer 盖过，explorer 被 reboot 盖过）
pub(super) const SCOPE_RANK: &[(&str, u8)] = &[("none", 0), ("explorer", 1), ("reboot", 2)];

pub(super) fn scope_rank_of(label: &str) -> u8 {
    SCOPE_RANK
        .iter()
        .find(|(l, _)| *l == label)
        .map(|(_, r)| *r)
        .unwrap_or(0)
}

pub(super) fn scope_label_of(rank: u8) -> &'static str {
    SCOPE_RANK
        .iter()
        .find(|(_, r)| *r == rank)
        .map(|(l, _)| *l)
        .unwrap_or("none")
}

pub(super) fn scope_table() -> &'static std::collections::HashMap<String, u8> {
    static CACHE: OnceLock<std::collections::HashMap<String, u8>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let parsed: Value =
            serde_json::from_str(SCOPE_JSON).expect("optimizer-scope.json 合法");
        parsed
            .get("scope")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), scope_rank_of(v.as_str().unwrap_or("none"))))
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// 单项粒度；表里没有的按 none（= 不提示，与本轮之前的行为一致，漏标不会误报）
///
/// 「整批取最大粒度」刻意不在 Rust 侧：`optimizer_run` 一次只接一个 `option_id`，批次是
/// 前端逐条循环执行的，聚合与文案都落在 `optimizer.js`；Rust 只把每行的 `applyScope` 透出去。
/// 档位序与前端一致（`none` < `explorer` < `reboot`），这条一致性由
/// `tools/check-optimizer-dynamic.mjs` 对拍两侧表钉住。
pub(super) fn apply_scope(option_id: &str) -> &'static str {
    scope_label_of(scope_table().get(option_id).copied().unwrap_or(0))
}

// ==================== 安全降级侧表（RAINZ 对标 §4 R2）====================
//
// 与 applyScope 同一条路子：`optimizer-runtime.json` 与上游基线逐字段对拍，加字段必判红，
// 所以「哪些项降低安全基线」这个**本仓判定**只能落在侧表里、由响应侧注入。
//
// 判定的唯一实现在 `tools/check-optimizer-security.mjs`（看值不看名：`NoAutoUpdate=0`
// 是开更新、`EnableLUA=1` 是开 UAC，都不算降级）。这里**只读表、不重算** ——
// 同一判据两份实现必然漂移，那是本仓反复踩过的坑。
pub(super) const SECURITY_JSON: &str = include_str!("../../../data/optimizer-security.json");

/// 安全降级项的元信息（`level` / `why` / `writes` / `rules`）；不在表里 = 不是降级项
pub(super) fn security_degrade_of(option_id: &str) -> Option<Value> {
    static CACHE: OnceLock<std::collections::HashMap<String, Value>> = OnceLock::new();
    let map = CACHE.get_or_init(|| {
        let parsed: Value =
            serde_json::from_str(SECURITY_JSON).expect("optimizer-security.json 合法");
        parsed
            .get("items")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    });
    map.get(option_id).cloned()
}

/// 本机确有备份的退役项。备份结构异常或 `values` 为空的条目按「没有备份」处理——
/// 列出来只会给用户一个点了不会成功的按钮。
pub(super) fn retired_pending_backups(backup_map: &Value) -> Vec<Value> {
    retired_items()
        .iter()
        .filter_map(|i| {
            let id = i["id"].as_str()?;
            let n = backup_map
                .get(id)?
                .get("values")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .filter(|n| *n > 0)?;
            Some(json!({ "id": id, "title": i["title"].as_str().unwrap_or(id), "values": n }))
        })
        .collect()
}

/// OPT-1 高危清单。
/// 审查 v2-K3 后它的定位收窄为「比数据层 `risk:"high"` 更严的**例外集**」——真正的通用判据是
/// [`needs_high_risk_confirm`]。这里刻意保留手写项：有的项 risk 标的是 medium，但后果不可逆。
/// 集合差由 `tools/check-channel-map.mjs` 的门禁 F 第三条对拍钉住（Rust ⇄ JS ⇄ 数据层 risk=high）。
pub(super) const HAZARD_IDS: &[&str] = &[
    "disable_uac",
    "tf_defender",
    "perf_vbs_off",
    "perf_exploit_protection_off",
    "tf_svc_bulk",
    "tf_drv_disable",
    "perf_windows_update_off",
];

/// 高危确认闸门：手写清单 **或** 数据层自认 high。
/// 只认手写清单会漏掉数据层 `risk:"high"` 的 7 项——`tf_appx`（移除 25 个内置 UWP）、
/// `tf_onedrive`（彻底卸载 OneDrive）等都是 `restoreAvailable:false` 的不可逆操作，
/// 用户在单项执行时连红色确认都不会弹（批量路径反而有闸，因为它的判据取自 `risk`）。
/// 抽成纯函数是为了能对「数据层每一项 high」都断言，而不是只断言清单里那几项。
pub(super) fn needs_high_risk_confirm(opt: &Value, option_id: &str) -> bool {
    HAZARD_IDS.contains(&option_id) || opt.get("risk").and_then(|v| v.as_str()) == Some("high")
}

