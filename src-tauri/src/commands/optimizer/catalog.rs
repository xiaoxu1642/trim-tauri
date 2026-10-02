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

/// 优化项目录。**装载前先验 ed25519 签名**（M4）。
///
/// fail-closed：验签失败时返回**空 vec**（不是「返回未校验的数据」）。调用方看到
/// 的是「优化目录不可用」这一条明确事实，而不是「126 项都生效了但一个都没验过」。
/// 优化项是**会改用户系统**的目录 —— 未校验就装载等于把「数据文件被换掉」这件事
/// 变成静默生效的劫持面。
pub(super) fn options() -> &'static Vec<Value> {
    static OPTS: OnceLock<Vec<Value>> = OnceLock::new();
    OPTS.get_or_init(|| {
        if let Err(reason) = verify_optimizer_signature() {
            // 不 panic（panic 会把整个应用带崩，而「优化项不可用」不该阻断磁盘清理等
            // 无关域），也不放行（放行等于没验签）。
            crate::engine::log::write_log("error", &format!("优化目录签名校验失败，已拒绝装载: {reason}"));
            return Vec::new();
        }
        serde_json::from_str(OPTIONS_JSON).expect("optimizer-runtime.json 合法")
    })
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

// ==================== provenance 侧表（M4）====================
//
// 借 Winaero 的可识别诉求：**高危项在 UI 上要有一个可解释的标记**，而不是只靠
// `risk: "high"` 暗示「这个会改系统」。trim 不用竞品的功能名后缀做法，用数据字段：
// `sourceClass`（判据来源）+ `why`（凭什么这么判）+ `reviewedAt`（复核日期）。
//
// 姿势同 `optimizer-security.json`：按 id 挂、缺键宽松（缺 = 无 provenance，
// **不是**「没有依据」—— 覆盖率棘轮在 `check-optimizer-write-contract.mjs` 的 A5 组）。
pub(super) const PROVENANCE_JSON: &str = include_str!("../../../data/optimizer-provenance.json");

/// 某项的 provenance；不在表里 = None
pub(super) fn provenance_of(option_id: &str) -> Option<Value> {
    static CACHE: OnceLock<std::collections::HashMap<String, Value>> = OnceLock::new();
    let map = CACHE.get_or_init(|| {
        let parsed: Value =
            serde_json::from_str(PROVENANCE_JSON).expect("optimizer-provenance.json 合法");
        parsed
            .get("items")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    });
    map.get(option_id).cloned()
}

/// 优化目录的 ed25519 签名（M4）。**在装载期验一次**，不是每次读都验。
///
/// 为什么不每次读都验：签名的对象是**编译期内嵌的**那份 JSON
/// （`OPTIONS_JSON` 是 `include_str!`），运行期没人能改它 —— 验一次就够。
/// 真正的威胁是「构建产物里的数据文件被换掉」，那在 `include_str!` 的时点就定了。
///
/// ⚠️ **验签失败不许降级放行**：返回 `Err` 让 `options()` 走不到数据，
/// 调用方看到的是「优化目录不可用」而不是「126 项全都没校验过」。
pub(super) fn verify_optimizer_signature() -> Result<(), String> {
    static ONCE: OnceLock<Result<(), String>> = OnceLock::new();
    ONCE.get_or_init(|| {
        let side = include_str!("../../../data/optimizer-runtime.json.sig.json");
        crate::engine::rules_signature::verify_array_text(OPTIONS_JSON, side)
    })
    .clone()
}

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

// ==================== 写入坐标侧表（M2 · 检测断言的数据源）====================
//
// 为什么单独成表：这些项的 `steps` 全是 `pwsh` 文本，检测侧（`overview.rs` 的
// `collect_checks`）**不解析 pwsh**——它只认 `reg` / `service+disable` / `service+startType`
// 三种形态。于是 `tf_svc_bulk`（65 个服务）、`tf_drv_disable`（19 个）等项
// `collect_checks` 返回空 vec ⇒ 体检恒显示「未生效」⇒ 用户点详情看到的是
// 「立即执行」而不是「立即恢复」，会**重复施加同一批改动**。
//
// 为什么不写进 `optimizer-runtime.json`：那份与 `vendor/upstream-js/optimizer-scripts.js`
// 的 OPTIONS 逐字段对拍（`check-data-parity` P2），往里加字段必判红。姿势同
// `optimizer-scope.json` / `optimizer-security.json`：按 id 挂、缺键宽松、
// `include_str!` 编译内嵌。
//
// **本表是单源数据，不进 `check-data-parity` 双源体系**（`_comment` 里也写了）。
// 它是「执行侧写什么」的镜像，真源始终是 `optimizer-runtime.json` 的 pwsh 文本——
// `tools/check-optimizer-write-contract.mjs` 逐项对拍两侧，改一处忘另一处即红。
pub(super) const WRITES_JSON: &str = include_str!("../../../data/optimizer-writes.json");

/// 某项的写入坐标：期望的服务启动类型 + 服务清单。
///
/// `store_services` 单独返回而不是并进 `services`：那5 个商店服务由
/// `apply.rs::svc_bulk_append_store` **条件追加**（用户弹窗确认过才执行）。
/// 并进 `services` 会让「没勾商店的用户」永远判未生效 —— 那5 项本来就没被禁用过。
/// 某项的写入坐标：按「期望启动类型」分组的断言清单。
///
/// **为什么按组而不是一项一个 `expectStart`**：`tf_svc_bulk` 只有**一步** pwsh，
/// 里面却有三段不同期望值的写入 —— 基础 65 个服务 `Start=4`（禁用）、
/// `wuauserv` `Start=3`（手动，保持更新可用）。按「一项一个期望值」建模会把
/// 后一段判成错值（那正是门禁第一次跑就抓到的缺陷）。
///
/// `store_services` 单独返回而不是并进任何组：那 5 个商店服务由
/// `apply.rs::svc_bulk_append_store` **条件追加**（用户弹窗确认过才执行）。
/// 并进去会让「没勾商店的用户」永远判未生效 —— 那 5 项本来就没被禁用过。
#[derive(Clone)]
pub(super) struct WriteSpec {
    /// (期望Start, 服务清单)
    pub groups: &'static [(u32, &'static [String])],
    pub store_services: &'static [String],
    /// A 类（注册表可回读）断言。M2-B。
    ///
    /// 三种判据形态，**混起来会判错**：
    /// - `kind=dword` + `expect`：键存在且值等于期望（走 `read_reg_dword_opt`）
    /// - `kind=binary` + `expect`：键存在且字节序列等于期望（走 `read_reg_binary_opt`）
    /// - `absent=true`：**键必须不存在**才算已生效。`perf_wu_enable` 是删除语义
    ///   （`Remove-ItemProperty` 删掉 4 个 `Pause*` 键），判「值等于某个数」永远不可能
    ///   满足 —— 那是把「已生效」判成「未生效」，用户会点「立即执行」而执行侧只是在
    ///   重复删不存在的键。
    pub reg_writes: &'static [RegAssert],
}

/// 一条注册表断言。
#[derive(Clone)]
pub(super) struct RegAssert {
    pub hive: &'static str,
    pub subkey: &'static str,
    pub value: &'static str,
    /// 区间判据的**结束**键名（`kind == "timeWindow"` 时用，其余形态为空串）。
    ///
    /// 为什么单开一个字段而不是把两端塞进 `value`（如 `"A..B"`）：那会让
    /// `value` 同时承载两种语义，`probe_reg()` 的对拍断言（「值名要在 pwsh 里出现」）
    /// 就得跟着分叉。分开之后键名对拍逻辑完全不变。
    pub value2: &'static str,
    /// "dword" | "string" | "binary" | "enum" | "timeWindow"
    pub kind: &'static str,
    /// 期望值；`absent` 为 true 时忽略。
    /// `enum` 形态下是**逗号分隔的整数集合**（如 `"380000,4194304,…"`）。
    pub expect: &'static str,
    pub absent: bool,
}

fn writes_table() -> &'static std::collections::HashMap<String, Value> {
    static CACHE: OnceLock<std::collections::HashMap<String, Value>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let parsed: Value = serde_json::from_str(WRITES_JSON).expect("optimizer-writes.json 合法");
        parsed
            .get("items")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    })
}

/// 取某项的写入坐标；不在表里 = None（**不是**「没有写入」—— 是「检不出」，
/// 调用方据此跳过而不是判未生效，见 `overview.rs::collect_checks`）。
///
/// 生命周期说明：服务名池、断言池与本函数的结果都活在各自的 `OnceLock` 里（进程级），
/// 所以 `&'static [..]` 借用成立，**不需要 `Box::leak`**（那会让每次热路径调用
/// 都真正泄漏一份，虽然被 OnceLock 挡住只泄漏一次，但读代码的人会误以为有泄漏风险）。
pub(super) fn write_spec_of(option_id: &str) -> Option<WriteSpec> {
    static CACHE: OnceLock<std::collections::HashMap<String, WriteSpec>> = OnceLock::new();
    let map = CACHE.get_or_init(|| {
        let table = writes_table();
        // 服务名池：一次建好、按 "<id>\u{1}g<组序>" / "<id>\u{1}store" 取
        static POOL: OnceLock<std::collections::HashMap<String, Vec<String>>> = OnceLock::new();
        let pool: &'static std::collections::HashMap<String, Vec<String>> =
            POOL.get_or_init(|| {
                let mut m = std::collections::HashMap::new();
                for (pid, pv) in table.iter() {
                    if let Some(groups) = pv.get("groups").and_then(Value::as_array) {
                        for (gi, g) in groups.iter().enumerate() {
                            if let Some(arr) = g.get("services").and_then(Value::as_array) {
                                m.insert(
                                    format!("{pid}\u{1}g{gi}"),
                                    arr.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                                );
                            }
                        }
                    }
                    if let Some(arr) = pv.get("storeServices").and_then(Value::as_array) {
                        m.insert(
                            format!("{pid}\u{1}store"),
                            arr.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                        );
                    }
                }
                m
            });
        // groups 池同样进程级：借用的是 pool 里的 Vec，寿命与进程一致
        static GROUPS: OnceLock<std::collections::HashMap<String, Vec<(u32, &'static [String])>>> =
            OnceLock::new();
        let groups_map: &'static std::collections::HashMap<String, Vec<(u32, &'static [String])>> =
            GROUPS.get_or_init(|| {
                let mut m = std::collections::HashMap::new();
                for (id, v) in table.iter() {
                    let Some(arr) = v.get("groups").and_then(Value::as_array) else { continue };
                    let groups: Vec<(u32, &'static [String])> = arr
                        .iter()
                        .enumerate()
                        .filter_map(|(gi, g)| {
                            let expect = g.get("expectStart").and_then(Value::as_u64)? as u32;
                            let list: &'static [String] = pool
                                .get(&format!("{id}\u{1}g{gi}"))
                                .map(|v| v.as_slice())
                                .unwrap_or(&[]);
                            if list.is_empty() { return None; }
                            Some((expect, list))
                        })
                        .collect();
                    if !groups.is_empty() {
                        m.insert(id.clone(), groups);
                    }
                }
                m
            });
        // A 类断言池（M2-B）。`&'static str` 直接借用自 `WRITES_JSON`（`include_str!`
        // 的字面量是 `'static`），所以这里连字符串池都不用建。
        static REGS: OnceLock<std::collections::HashMap<String, Vec<RegAssert>>> = OnceLock::new();
        let regs_map: &'static std::collections::HashMap<String, Vec<RegAssert>> =
            REGS.get_or_init(|| {
                let mut m = std::collections::HashMap::new();
                for (id, v) in table.iter() {
                    let Some(arr) = v.get("regWrites").and_then(Value::as_array) else { continue };
                    let list: Vec<RegAssert> = arr
                        .iter()
                        .filter_map(|r| {
                            Some(RegAssert {
                                hive: r.get("hive")?.as_str()?,
                                subkey: r.get("subkey")?.as_str()?,
                                value: r.get("value")?.as_str()?,
                                value2: r.get("value2").and_then(Value::as_str).unwrap_or(""),
                                kind: r.get("kind").and_then(Value::as_str).unwrap_or("dword"),
                                expect: r.get("expect").and_then(Value::as_str).unwrap_or(""),
                                absent: r.get("absent").and_then(Value::as_bool).unwrap_or(false),
                            })
                        })
                        .collect();
                    if !list.is_empty() {
                        m.insert(id.clone(), list);
                    }
                }
                m
            });
        // 合并两域。**任一域非空才登记** —— 两域都空的项返回 None（=检不出），
        // 不能因为「groups 空」就把有 regWrites 的项丢掉（M2-B 踩过）。
        let mut ids: std::collections::HashSet<&String> = std::collections::HashSet::new();
        ids.extend(groups_map.keys());
        ids.extend(regs_map.keys());
        ids.into_iter()
            .map(|id| {
                let store: &'static [String] = pool
                    .get(&format!("{id}\u{1}store"))
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                (
                    id.clone(),
                    WriteSpec {
                        groups: groups_map.get(id).map(|v| v.as_slice()).unwrap_or(&[]),
                        store_services: store,
                        reg_writes: regs_map.get(id).map(|v| v.as_slice()).unwrap_or(&[]),
                    },
                )
            })
            .collect()
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

