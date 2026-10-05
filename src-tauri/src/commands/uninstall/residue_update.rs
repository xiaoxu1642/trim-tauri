//! 残留规则库：装载、语义校验（A2）、在线更新与版本检查（A3）+ uninstall_modify。
//!
//! 字段表/上限/允许 token 集的单一真源是 `tools/rule-schema.json`，不是本文件；
//! 更新侧必须复用装载侧的同一个校验器（validate_residue_package）与同一个
//! `assemble_sources`，避免出现第二套口径（AGENTS §9.2 的 https-only 约束同源）。
//! 内置副本 `include_str!` 在此，体积下限跟着它走。

use crate::engine::{guard, log, protect, rules_signature};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tauri::WebviewWindow;
use trim_finder::cleanup_scan;
use super::helpers::*;
use super::list_run::*;
use super::residue::*;
// ==================== 签名残留规则库（U-1） ====================
// 已知程序知识库：规则文件与 cleanup-rules.json 同款签名链（Ed25519 + 去掉 _sig 的
// 紧凑 JSON 规范化，rules_signature::verify_rules_text 验签）。数据目录规则优先于内置，
// 验签失败 / 版本低于防回滚下限一律 fail-closed 回退内置。
// 在线更新（A3，M3 批次）：cleanup 域的 HTTP 传输层（`engine::winhttp` + 验签 +
// 原子落盘 + 水位线）与残留库的在线更新通道均已落地——本文件下方实现
// `uninstall:update-residue-rules` / `uninstall:check-residue-version`（MAIN 档、
// 原子写 + 验签 + 防回滚），`lib.rs` 已注册、`module_smoke.rs` 有档位用例。
// 早期「尚未接入、未拍板前不得新增 `residue:update`」的说法只描述当时状态，
// 通道名也不是字面 `residue:update`；A1/A2 两道闸与验签前置条件不变。

/// 内置残留规则库（编译期嵌入，与 data/uninstall-residue-rules.json 逐字节一致）
pub(super) const BUILTIN_RESIDUE_RULES_JSON: &str = include_str!("../../../data/uninstall-residue-rules.json");

/// 残留规则根目录（**读**）：新根 `app_data_dir()\uninstall`（便携模式跟着 exe 走），
/// 老根 `%APPDATA%\Trim\uninstall` 只作只读兜底 —— 2026-09-28 决策清单 D1=A，
/// 与清理库同一口径（两库必须一起收口，否则便携模式只对一半成立）。
pub fn residue_rules_dir() -> PathBuf {
    crate::engine::paths::data_subdir_for_read("uninstall")
}

/// **写入**专用根：恒新根，避免两个根各自持有一份规则与水位线。
pub(super) fn residue_rules_write_dir() -> PathBuf {
    crate::engine::paths::data_subdir_for_write("uninstall")
}

pub(super) fn residue_rules_file() -> PathBuf {
    crate::engine::paths::data_file_for_read("uninstall/residue-rules.json")
}

pub(super) fn residue_watermark_file() -> PathBuf {
    crate::engine::paths::data_file_for_read("uninstall/residue-rules-watermark.json")
}

pub(super) fn residue_watermark_write_file() -> PathBuf {
    residue_rules_write_dir().join("residue-rules-watermark.json")
}

/// 防回滚水位线读取（损坏/不可读按 0；口径同 cleanup::rules_watermark）
pub fn residue_watermark() -> f64 {
    let Ok(text) = std::fs::read_to_string(residue_watermark_file()) else {
        return 0.0;
    };
    let Ok(v) = serde_json::from_str::<Value>(&text) else {
        return 0.0;
    };
    v.get("rulesVersion").and_then(|x| x.as_f64()).unwrap_or(0.0)
}

/// 防回滚水位线写入（只升不降；在线更新链路接入时调用）
pub fn set_residue_watermark(version: f64) -> bool {
    if !version.is_finite() || version <= 0.0 || version <= residue_watermark() {
        return false;
    }
    let file = residue_watermark_write_file();
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let payload = json!({ "rulesVersion": version, "at": crate::engine::now_ms() });
    crate::security::atomic_write_json(&file, &payload).is_ok()
}

// ==================== A2 残留规则库语义校验（方案 §6.1） ====================
//
// 为什么必须存在：`load_residue_rules` 此前只做「验签 → JSON → rules 是数组 → 版本水位线」，
// 也就是**只证明这份文件出自发布机私钥**，不证明内容安全。而规则里的 `reg_key` 目标会被
// `RegDeleteTreeW` 递归删、`folder` 目标会进回收站，所以一条 `HKLM\SOFTWARE` 就够出事故。
// 人审与私钥纪律不是代码约束，热更新一上就是放大面 —— 故整包语义校验先于上链。
//
// 口径约束（勿单侧改）：
// - 失败一律**整包拒绝**并回退上一份可用规则（Q2 拍板）。不做「坏条目剔除、其余生效」，
//   那会让审核记录与线上行为不一致。
// - 本函数是**唯一运行期真源**；`tools/check-residue-rule-contract.mjs` 用同一组夹具
//   (`tools/fixtures/residue-contract.json`) 独立实现同一套断言，不跨语言调用 Rust。
// - 清理域与残留域字段规则不同，只共享「外层流程」（尺寸/验签/版本），不共享白名单。

/// 签名残留规则库允许的 kind（Q8 拍板：`reg_value` / `shortcut` 不放行。一旦放行，
/// 校验器、执行侧保护判定、夹具与备份策略必须同时改，不得出现「校验器放行、执行器不支持」）

// v2-L4P-15（C-2）：残留域词汇与数值的**唯一真源** = tools/rule-schema.json（经
// engine::rule_schema 编译期嵌入，与 Node 门禁读同一份字节）。此前这里是硬编码第二真源
// ——改 schema 只动 Node 门禁、装载侧纹丝不动，AGENTS §5.16「同字节双读」在残留域只成立一半。
// 一次性解析成静态快照；表解析失败时全部取空/取 0，下方校验逻辑对空白名单/0 上限
// 天然整包拒绝，与 rule_schema 的 fail-closed 口径一致。
pub(super) struct ResidueContract {
    pub(super) rule_kinds: Vec<String>,
    pub(super) tokens: Vec<String>,
    pub(super) top_fields: Vec<String>,
    pub(super) prov_fields: Vec<String>,
    pub(super) rule_fields: Vec<String>,
    pub(super) entry_fields: Vec<String>,
    pub(super) match_groups: Vec<String>,
    pub(super) max_rules: usize,
    pub(super) max_residue: usize,
    pub(super) max_group_items: usize,
    pub(super) max_target_len: usize,
    pub(super) max_text_len: usize,
    pub(super) max_segments: usize,
}

pub(super) fn residue_contract() -> &'static ResidueContract {
    use crate::engine::rule_schema as rs;
    static CELL: OnceLock<ResidueContract> = OnceLock::new();
    CELL.get_or_init(|| {
        // 表不可用 → 空契约（空白名单 + 0 上限）⇒ 任何包都会被整包拒绝
        let mut c = ResidueContract {
            rule_kinds: Vec::new(),
            tokens: Vec::new(),
            top_fields: Vec::new(),
            prov_fields: Vec::new(),
            rule_fields: Vec::new(),
            entry_fields: Vec::new(),
            match_groups: Vec::new(),
            max_rules: 0,
            max_residue: 0,
            max_group_items: 0,
            max_target_len: 0,
            max_text_len: 0,
            max_segments: 0,
        };
        if let Some(v) = rs::list("residue", "ruleKinds") { c.rule_kinds = v; }
        if let Some((allowed, _ci)) = rs::tokens("residue") { c.tokens = allowed; }
        if let Some(v) = rs::list("residue", "topFields") { c.top_fields = v; }
        if let Some(v) = rs::list("residue", "provFields") { c.prov_fields = v; }
        if let Some(v) = rs::list("residue", "ruleFields") { c.rule_fields = v; }
        if let Some(v) = rs::list("residue", "entryFields") { c.entry_fields = v; }
        if let Some(v) = rs::list("residue", "matchGroups") { c.match_groups = v; }
        if let Some(v) = rs::number("residue", "maxRules") { c.max_rules = v; }
        if let Some(v) = rs::number("residue", "maxResiduePerRule") { c.max_residue = v; }
        if let Some(v) = rs::number("residue", "maxGroupItems") { c.max_group_items = v; }
        if let Some(v) = rs::number("residue", "maxTargetLen") { c.max_target_len = v; }
        if let Some(v) = rs::number("residue", "maxTextLen") { c.max_text_len = v; }
        if let Some(v) = rs::number("residue", "maxSegments") { c.max_segments = v; }
        c
    })
}

/// 未知字段白名单检查（A5）： serde 手取字段时未知字段会被静默忽略，
/// 那等于「规则库里有一执行侧根本不认的字段」，审核记录与线上行为不一致。
pub(super) fn unknown_fields<'a>(obj: &serde_json::Map<String, Value>, allow: &'a [String]) -> Option<String> {
    obj.keys()
        .find(|k| !allow.iter().any(|a| a == *k))
        .map(|k| format!("未知字段 {k}"))
}

/// 字符串数组字段：字段可缺失（视为空组，「至少两组非空」另有断言），但类型不符必须 Err
/// —— 不许把 `null` / 对象 / 数字静默当空数组，那会静默改变命中口径。
pub(super) fn str_array_field<'a>(obj: &'a Value, field: &str) -> Result<Vec<&'a str>, String> {
    let Some(v) = obj.get(field) else {
        return Ok(Vec::new());
    };
    let Some(arr) = v.as_array() else {
        return Err(format!("{field} 不是数组"));
    };
    if arr.len() > residue_contract().max_group_items {
        return Err(format!("{field} 条目数 {} 超上限 {}", arr.len(), residue_contract().max_group_items));
    }
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let Some(s) = v.as_str() else {
            return Err(format!("{field} 含非字符串元素"));
        };
        if s.trim().is_empty() || s.chars().count() > residue_contract().max_text_len {
            return Err(format!("{field} 含空白或超长条目"));
        }
        out.push(s.trim());
    }
    Ok(out)
}

pub(super) fn path_shape_problem(target: &str) -> Option<String> {
    if target.chars().count() > residue_contract().max_target_len {
        return Some("目标长度超过 260（MAX_PATH）".to_string());
    }
    if target.contains('*') || target.contains('?') {
        return Some("目标含通配符（残留规则只允许精确路径）".to_string());
    }
    if target.chars().any(|c| c == '\0' || c == '\n' || c == '\r' || c == '\t') {
        return Some("目标含控制字符".to_string());
    }
    None
}

/// 文件类目标形状：`%登记TOKEN%\非空子段` 或 盘符/UNC 绝对路径。
/// 禁 token 根（`%APPDATA%`）、尾随分隔符、`.`/`..` 段、路径中部二次变量替换。
pub(super) fn file_target_problem(target: &str) -> Option<String> {
    if let Some(reason) = path_shape_problem(target) {
        return Some(reason);
    }
    let body = if let Some(rest) = target.strip_prefix('%') {
        let Some(end) = rest.find('%') else {
            return Some("变量名未闭合".to_string());
        };
        let token = &rest[..end];
        if token.is_empty() || !residue_contract().tokens.iter().any(|t| t.eq_ignore_ascii_case(token)) {
            return Some(format!("变量 %{token}% 未登记（先确认展开器可解析再入白名单）"));
        }
        let tail = &rest[end + 1..];
        if tail.contains('%') {
            return Some("路径中不允许出现第二个变量替换".to_string());
        }
        if !tail.starts_with('\\') && !tail.starts_with('/') {
            return Some("变量后必须有分隔符与非空子段（禁止 token 根）".to_string());
        }
        tail[1..].to_string()
    } else {
        // 绝对路径两写法：`X:\...` 与 `\\server\share\...`
        let b = target.as_bytes();
        let drive_abs = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
        let unc_abs = target.starts_with("\\\\") && target.trim_start_matches('\\').contains('\\');
        if !drive_abs && !unc_abs {
            return Some("既不是登记变量的子路径，也不是绝对路径".to_string());
        }
        target.to_string()
    };
    let segs: Vec<&str> = body.split(|c| c == '\\' || c == '/').collect();
    if segs.iter().any(|s| s.is_empty() || *s == "." || *s == "..") {
        return Some("含空段、`.` 或 `..`（尾随分隔符同样命中）".to_string());
    }
    if segs.len() > residue_contract().max_segments {
        return Some(format!("路径段数 {} 超上限 {}", segs.len(), residue_contract().max_segments));
    }
    None
}

/// 注册表目标：hive 合法 + 过 A1 保护判定 + 不放 reg_value 形态（`::值名`）
pub(super) fn reg_target_problem(target: &str) -> Option<String> {
    if let Some(reason) = path_shape_problem(target) {
        return Some(reason);
    }
    if target.contains("::") || target.contains('%') {
        return Some("注册表目标不允许 `::值名` 或变量形态".to_string());
    }
    let Some((_, rest)) = parse_reg_target(target) else {
        return Some("hive 只支持 HKCU / HKLM".to_string());
    };
    let segs: Vec<&str> = rest.split('\\').collect();
    if segs.iter().any(|s| s.trim().is_empty()) {
        return Some("注册表路径含空段或尾随分隔符".to_string());
    }
    if segs.len() > residue_contract().max_segments {
        return Some(format!("注册表深度 {} 超上限 {}", segs.len(), residue_contract().max_segments));
    }
    protect::reg_target_block_reason(target)
}

/// 整包语义校验。`Err(原因)` = 调用方必须拒绝这份规则库。
pub(super) fn validate_residue_package(pkg: &Value) -> Result<(), String> {
    let c = residue_contract();
    let Some(top) = pkg.as_object() else {
        return Err("规则包不是 JSON 对象".to_string());
    };
    if let Some(reason) = unknown_fields(top, &c.top_fields) {
        return Err(format!("顶层 {reason}"));
    }
    let ver = pkg
        .get("rulesVersion")
        .and_then(Value::as_f64)
        .filter(|v| v.is_finite() && *v > 0.0)
        .ok_or_else(|| "rulesVersion 缺失、非数字或非正数".to_string())?;
    let prov = pkg
        .get("prov")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| "prov 缺失或为空（来源登记是审核链的一环）".to_string())?;
    for p in prov {
        let Some(obj) = p.as_object() else {
            return Err("prov 条目不是对象".to_string());
        };
        if let Some(reason) = unknown_fields(obj, &c.prov_fields) {
            return Err(format!("prov {reason}"));
        }
        for f in &c.prov_fields {
            let ok = obj
                .get(f)
                .and_then(Value::as_str)
                .map(|s| !s.trim().is_empty() && s.chars().count() <= c.max_text_len)
                .unwrap_or(false);
            if !ok {
                return Err(format!("prov.{f} 缺失、非字符串或为空白"));
            }
        }
    }
    let rule_list = pkg
        .get("rules")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| "rules 缺失或为空数组".to_string())?;
    if rule_list.len() > c.max_rules {
        return Err(format!("规则条数 {} 超上限 {}", rule_list.len(), c.max_rules));
    }
    let mut seen_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for rule in rule_list {
        let Some(obj) = rule.as_object() else {
            return Err("规则条目不是对象".to_string());
        };
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| {
                !s.is_empty()
                    && s.chars().count() <= c.max_text_len
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            })
            .ok_or_else(|| "规则 id 缺失、为空或含非 [A-Za-z0-9._-] 字符".to_string())?;
        if !seen_ids.insert(id) {
            return Err(format!("规则 id 重复: {id}"));
        }
        if let Some(reason) = unknown_fields(obj, &c.rule_fields) {
            return Err(format!("规则 {id}: {reason}"));
        }
        // 条目级版本戳必须与顶层一致（V2 P2-A1，与清理库同口径）：
        // 残留规则只有 6 条，但一旦开始按批补充，"这条是哪一版加的"必须能答
        match rule.get("ver").and_then(Value::as_f64) {
            None => {
                return Err(format!(
                    "规则 {id}: 缺条目级版本戳 ver（跑 tools/stamp-rule-ver.mjs --write 后重签）"
                ))
            }
            Some(vv) if (vv - ver).abs() > f64::EPSILON => {
                return Err(format!("规则 {id}: ver={vv} 与顶层 rulesVersion={ver} 不一致"))
            }
            Some(_) => {}
        }
        let mut hit_groups = 0;
        for g in &c.match_groups {
            let items = str_array_field(rule, g).map_err(|e| format!("规则 {id}: {e}"))?;
            if !items.is_empty() {
                hit_groups += 1;
            }
        }
        if hit_groups < 2 {
            return Err(format!(
                "规则 {id}: 三条件组只有 {hit_groups} 组非空，双条件命中是 U-1 拍板口径"
            ));
        }
        let Some(residue) = rule.get("residue").and_then(Value::as_array) else {
            return Err(format!("规则 {id}: residue 缺失或不是数组"));
        };
        if residue.is_empty() {
            return Err(format!("规则 {id}: residue 为空"));
        }
        if residue.len() > c.max_residue {
            return Err(format!(
                "规则 {id}: residue 条数 {} 超上限 {}",
                residue.len(),
                c.max_residue
            ));
        }
        for entry in residue {
            let Some(obj) = entry.as_object() else {
                return Err(format!("规则 {id}: residue 条目不是对象"));
            };
            if let Some(reason) = unknown_fields(obj, &c.entry_fields) {
                return Err(format!("规则 {id}: residue {reason}"));
            }
            let kind = entry
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("规则 {id}: residue.kind 缺失或非字符串"))?;
            if !c.rule_kinds.iter().any(|k| k == kind) {
                // 未知 kind 必须报错而不是静默跳过：静默跳过会让「执行侧不支持的字段」
                // 长期留在库里（方案 §6.1 三集合区分）
                return Err(format!("规则 {id}: 未知 kind {kind}（允许集 {:?}）", c.rule_kinds));
            }
            let raw_target = entry
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("规则 {id}: residue.target 缺失或非字符串"))?;
            let target = raw_target.trim();
            if target.is_empty() || target != raw_target {
                return Err(format!("规则 {id}: residue.target 为空白或首尾含空白"));
            }
            let problem = match kind {
                "folder" | "file" => file_target_problem(target),
                "reg_key" => reg_target_problem(target),
                _ => Some("kind 不在允许集".to_string()),
            };
            if let Some(reason) = problem {
                return Err(format!("规则 {id}: {kind} 目标 {target} 不合规 — {reason}"));
            }
            let note_ok = entry
                .get("note")
                .and_then(Value::as_str)
                .map(|s| !s.trim().is_empty() && s.chars().count() <= c.max_text_len)
                .unwrap_or(false);
            if !note_ok {
                return Err(format!("规则 {id}: residue.note 缺失或为空白（面板 reason 要展示）"));
            }
        }
    }
    Ok(())
}

/// 残留规则库加载：数据目录（验签 + 防回滚 + A2 语义校验）→ 内置。fail-closed。
pub(super) fn load_residue_rules() -> Option<Value> {
    let file = residue_rules_file();
    if file.is_file() {
        if let Ok(text) = std::fs::read_to_string(&file) {
            match rules_signature::verify_rules_text(&text) {
                Ok(()) => {
                    let parsed: Option<Value> = serde_json::from_str(&text).ok();
                    if let Some(v) = parsed {
                        let ver = v.get("rulesVersion").and_then(|x| x.as_f64()).unwrap_or(0.0);
                        let builtin_ver = serde_json::from_str::<Value>(BUILTIN_RESIDUE_RULES_JSON)
                            .ok()
                            .and_then(|b| b.get("rulesVersion").and_then(|x| x.as_f64()))
                            .unwrap_or(0.0);
                        let floor = builtin_ver.max(residue_watermark());
                        if floor > 0.0 && ver < floor {
                            log::write_log(
                                "warn",
                                &format!("数据目录残留规则版本({ver})低于防回滚下限({floor})，疑似旧签名文件重放，已回退内置规则库"),
                            );
                        } else if let Err(reason) = validate_residue_package(&v) {
                            // 验签通过但语义不合规：整包拒绝并隔离，避免每次扫描重复判同一份坏文件
                            log::write_log(
                                "error",
                                &format!("数据目录残留规则语义校验未通过，已整包拒绝并回退内置规则库: {reason}"),
                            );
                            crate::security::quarantine_file(&file, "residue-rules 语义校验未通过");
                        } else {
                            return Some(v);
                        }
                    } else {
                        log::write_log("warn", "数据目录残留规则 JSON 解析失败，已回退内置规则库");
                    }
                }
                Err(reason) => {
                    log::write_log(
                        "warn",
                        &format!("数据目录残留规则验签未通过，已回退内置规则库: {reason}"),
                    );
                }
            }
        }
    }
    let builtin: Value = match serde_json::from_str(BUILTIN_RESIDUE_RULES_JSON) {
        Ok(v) => v,
        Err(e) => {
            log::write_log("error", &format!("内置残留规则 JSON 解析失败: {e}"));
            return None;
        }
    };
    // 内置库同样过校验：数据文件由工具生成且发布前 `cargo test` 有对拍用例，
    // 这里失败说明仓库自身坏了，运行期只能停用规则（不给豁免通道）。
    if let Err(reason) = validate_residue_package(&builtin) {
        log::write_log("error", &format!("内置残留规则语义校验未通过，残留规则已停用: {reason}"));
        return None;
    }
    Some(builtin)
}

/// C4 贡献项：把「这一条为什么进候选」拆成离散因子，供渲染层逐条指认。
///
/// 借 BCU 的是**可解释性**，不是它的加权计分内核：浮点总分会让启发式看起来比实际更精确，
/// 而删除依据必须一条条数得出来。`code` 是稳定标识（单测与过滤按它寻址，不按文案寻址），
/// `text` 是给人看的那一句。纯展示字段——执行侧一律不消费它（方案 §6.3：展示/诊断字段
/// 不等于执行语义）。
pub(super) fn contribs(items: &[(&str, String)]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|(code, text)| json!({ "code": code, "text": text }))
            .collect(),
    )
}

/// 条件组命中判定（U-1「双条件」拍板）：displayName / publisher / uninstallKey 三组里
/// **至少两组命中**才视为同一程序，单一维度弱相似不触发（防「QQ」类短名误伤全家桶）。
/// 返回 (候选集, 被 A1 硬否决的目标) —— 否决原因只在这里收集，由命令边界落日志：
/// 纯函数不留写盘副作用，`cargo test` 才不会把测试规则 id 写进用户的应用日志。
///
/// `learned` 决定证据等级：同一套命中逻辑跑在两份库上（签名库 / 本机学习库），
/// 学习库不签名、没人审，所以候选一律 `medium` + **不自动勾选**，且 reason 要交代来源。
/// 做成参数而不是「产出后再改字段」，是因为后写进来的字段一旦与产出侧分叉就没人会发现
/// （签名库那条 `defaultChecked: true` 就是靠这条链默认勾上的）。
pub(super) fn residue_rules_hits(
    rules: &Value,
    display_name: &str,
    publisher: &str,
    key_path: &str,
    learned: bool,
) -> (Vec<Value>, Vec<String>) {
    let lib_label = if learned { "本机学习库" } else { "残留规则库" };
    let confidence = if learned { "medium" } else { "high" };
    let default_checked = !learned;
    let empty: Vec<Value> = Vec::new();
    let rule_list = rules.get("rules").and_then(|r| r.as_array()).unwrap_or(&empty);
    let name_norm = norm_name(display_name);
    let pub_lc = publisher.trim().to_lowercase();
    let key_lc = key_path.trim().to_lowercase();
    let mut out = Vec::new();
    let mut vetoed: Vec<String> = Vec::new();
    for rule in rule_list {
        let Some(id) = rule.get("id").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) else {
            continue;
        };
        // 双侧互含（沿用名称启发式的口径，但阈值放宽到 2：规则模式是人工维护的精确短词）
        let contains2 = |a: &str, b: &str| {
            let (a, b) = (a.trim(), b.trim());
            !a.is_empty() && !b.is_empty() && (a.contains(b) || b.contains(a))
        };
        let name_hit = rule
            .get("displayName")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter().filter_map(|p| p.as_str()).any(|p| {
                    let pn = norm_name(p);
                    pn.chars().count() >= NAME_MIN_RULE_WORD && contains2(&name_norm, &pn)
                })
            })
            .unwrap_or(false);
        let pub_hit = rule
            .get("publisher")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.as_str())
                    .any(|p| contains2(&pub_lc, &p.trim().to_lowercase()))
            })
            .unwrap_or(false);
        let key_hit = rule
            .get("uninstallKey")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter().filter_map(|p| p.as_str()).any(|p| {
                    let pl = p.trim().to_lowercase();
                    pl.chars().count() >= NAME_MIN_RULE_WORD && contains2(&key_lc, &pl)
                })
            })
            .unwrap_or(false);
        let hits = [name_hit, pub_hit, key_hit].iter().filter(|h| **h).count();
        if hits < 2 {
            continue;
        }
        // C4：把「哪几组条件命中」摊开成离散因子。双条件闸本身只说"够两组"，用户看不到
        // 是哪两组，就无法判断这条规则是不是靠「厂商名 + 一个短词」弱命中了自己别的产品。
        let mut why: Vec<(&str, String)> = Vec::new();
        if name_hit {
            why.push(("name", format!("程序名条件组命中：本机 DisplayName「{display_name}」")));
        }
        if pub_hit {
            why.push(("publisher", format!("发行商条件组命中：本机 Publisher「{publisher}」")));
        }
        if key_hit {
            why.push(("uninstallKey", format!("卸载键条件组命中：本机键路径「{key_path}」")));
        }
        // 条目级版本戳跟着候选走（V2 P2-A1）：反馈里能指认"这条候选是哪一版规则给的"，
        // 不必让用户去比对整库 rulesVersion。文案级改动，界面沿用既有 data-tip 位置。
        let rule_ver = rule.get("ver").and_then(Value::as_f64).unwrap_or(0.0);
        why.push((
            "ruleId",
            format!("来自{lib_label}规则 {id}（规则版本 {:.0}）", rule_ver),
        ));
        // 命中 → 展开 %VAR% 目标并做存在性判定：不存在的目标不出现在面板里
        for entry in rule.get("residue").and_then(|x| x.as_array()).unwrap_or(&empty) {
            let kind = entry.get("kind").and_then(|x| x.as_str()).unwrap_or("");
            let Some(target_raw) = entry.get("target").and_then(|x| x.as_str()) else {
                continue;
            };
            let note = entry.get("note").and_then(|x| x.as_str()).unwrap_or("");
            match kind {
                "folder" | "file" => {
                    let target = cleanup_scan::expand_env_path(target_raw);
                    // A4：变量没解析出来时，展开结果里还留着 `%X%`，这个路径必然不存在。
                    // 让它落到下面的「不存在」分支，等于把「本机没这个变量」说成
                    // 「程序没留这个目录」——清理链早就为这件事加了 first_unexpanded_token，
                    // 残留链此前一个调用点都没有，未展开目标就这么静默消失了。
                    if let Some(tok) = cleanup_scan::first_unexpanded_token(&target) {
                        vetoed.push(format!(
                            "规则 {id}: 目标 {target_raw} 含未解析变量 %{tok}%（本机取不到该变量），已跳过"
                        ));
                        continue;
                    }
                    let p = Path::new(&target);
                    let exists = if kind == "folder" { p.is_dir() } else { p.is_file() };
                    if !exists || protect::is_path_protected(&target) {
                        continue;
                    }
                    out.push(json!({
                        "kind": kind, "target": target,
                        "reason": format!("{lib_label}命中（{id}）：{note}"),
                        "confidence": confidence, "risk": "medium",
                        "defaultChecked": default_checked,
                        "ruleId": id, "ruleVer": rule_ver,
                        "contribs": contribs(&why),
                    }));
                }
                "reg_key" => {
                    let Some((hive, rest)) = parse_reg_target(target_raw) else {
                        continue;
                    };
                    // A1（方案 §4.1 实锤）：规则库里的 reg_key 目标此前只查「能不能解析 +
                    // 存不存在」，一条 `HKLM\SOFTWARE` 就能进候选列表并被默认勾选，执行侧
                    // 是 RegDeleteTreeW 递归删树。保护判定必须在产候选时就生效。
                    if let Some(reason) = protect::reg_target_block_reason(target_raw) {
                        vetoed.push(format!("残留规则 {id} 的注册表目标被硬否决（不入候选）: {reason}"));
                        continue;
                    }
                    if !crate::engine::native::reg_key_exists(hive, &rest) {
                        continue;
                    }
                    out.push(json!({
                        "kind": "reg_key", "target": target_raw,
                        "reason": format!("{lib_label}命中（{id}）：{note}"),
                        "confidence": confidence, "risk": "medium",
                        "defaultChecked": default_checked,
                        "ruleId": id, "ruleVer": rule_ver,
                        "contribs": contribs(&why),
                    }));
                }
                _ => continue,
            }
        }
    }
    (out, vetoed)
}

// ==================== A3 残留规则库在线更新（M3，决策清单 D3-D7） ====================
//
// 前置条件已由 M1 满足：A1 注册表硬否决 + A2 整包语义校验先落地，才允许把远程包接进分发。
// 顺序反过来（先上链再收口）等于让一条误签或私钥泄露后的坏规则自动扩散到所有装机。
//
// 与清理域的分工：**传输、验签、字节级原子落盘、水位线四段一律复用清理域已跑通的实现**
// （`cleanup::http_get_limited` / `rules_signature` / `security::atomic_write_file`），
// 只有「字段规则」和「尺寸量级」各留一份——两库内容量级不同，共用尺寸闸必然一边误拒、
// 一边放过。

/// 仓库内残留规则库路径（三条发布源共用清理域的同一拼装口，不抄第二份清单）
pub(super) const RESIDUE_REPO_PATH: &str = "src-tauri/data/uninstall-residue-rules.json";
pub(super) const RESIDUE_BUILTIN_LEN: usize = BUILTIN_RESIDUE_RULES_JSON.len();
/// 下限取「内置库一半」与 2048B 的较大者。刻意**不共用** `cleanup::RULES_MIN_SIZE = 4096`：
/// 残留库现在只有 6 条规则，删规则就可能掉到 4096B 以下，用清理域的下限会把合法包
/// 当成「异常响应」拒掉。下限的意义始终是探测截断/异常响应，不是质量线。
pub(super) const RESIDUE_RULES_MIN_SIZE: usize = if RESIDUE_BUILTIN_LEN / 2 > 2048 {
    RESIDUE_BUILTIN_LEN / 2
} else {
    2048
};
/// 上限给合法增长留一个数量级以上的余量（内置约 5 KB → 512 KB 封顶）：
/// 收太紧会在规则库长到几十上百条后自我拒更，放到清理域的 2 MiB 又失去先拦超大响应的意义。
pub(super) const RESIDUE_RULES_MAX_SIZE: usize = 512 * 1024;
pub(super) const RESIDUE_DOWNLOAD_TIMEOUT_MS: u64 = 15000;

pub(super) fn residue_source_urls() -> Vec<String> {
    crate::commands::cleanup::release_source_urls_for(RESIDUE_REPO_PATH)
}

/// 残留库更新源：用户覆盖源是**自己一份** `uninstall/update-source.json`（D6 拍板，
/// 不与清理库共用同名文件——两个同名文件长不同 schema 比多一个文件名更糟），
/// schema 与 headers 语义则完全共用清理域的解析器。
pub(super) fn residue_sources() -> Vec<(String, Vec<(String, String)>)> {
    let user_file = crate::engine::paths::data_file_for_read("uninstall/update-source.json");
    crate::commands::cleanup::assemble_sources(
        crate::commands::cleanup::load_update_override(&user_file),
        &residue_source_urls(),
    )
}

/// 本地生效版本（数据目录那份被接受则用它，否则内置）——检查版本与防降级下限都以此为准
pub(super) fn residue_local_version() -> f64 {
    let builtin = serde_json::from_str::<Value>(BUILTIN_RESIDUE_RULES_JSON)
        .ok()
        .and_then(|b| b.get("rulesVersion").and_then(|x| x.as_f64()))
        .unwrap_or(0.0);
    load_residue_rules()
        .and_then(|v| v.get("rulesVersion").and_then(|x| x.as_f64()))
        .unwrap_or(builtin)
}

/// 远程包校验（更新与「只查版本」共用同一条链）：尺寸 → 验签 → JSON → **语义** → 版本。
/// 语义校验调的就是装载侧那个 `validate_residue_package`——更新侧不写第二套字段规则，
/// 否则会出现「更新放行了、装载拒绝了」这种两头都自认正确的分叉。
/// 失败一律不落盘，因此这里不产生「半新半旧」的规则库状态。
pub(super) fn verify_residue_remote_text(text: &str, floor: f64) -> Result<f64, String> {
    let len = text.chars().count();
    if len < RESIDUE_RULES_MIN_SIZE {
        return Err("内容过小，疑似异常响应".to_string());
    }
    if len > RESIDUE_RULES_MAX_SIZE {
        return Err("内容过大，疑似异常响应".to_string());
    }
    rules_signature::verify_rules_text(text)?;
    let parsed: Value = serde_json::from_str(text).map_err(|_| "JSON 解析失败".to_string())?;
    validate_residue_package(&parsed)?;
    let version = parsed
        .get("rulesVersion")
        .and_then(Value::as_f64)
        .ok_or_else(|| "缺少 rulesVersion".to_string())?;
    if floor > 0.0 && version < floor {
        return Err(format!(
            "下载版本({version})低于防回滚下限({floor})，疑似旧签名文件重放，已拒绝"
        ));
    }
    Ok(version)
}

/// 逐源取包并校验。返回 (版本, 原文, 命中的源)；全部失败时报最后一个原因。
/// 刻意不在这里落盘——更新与查版本共用它，查版本只读。
pub(super) fn fetch_verified_residue_package() -> Result<(f64, String, String), String> {
    let floor = residue_local_version().max(residue_watermark());
    let sources = residue_sources();
    if sources.is_empty() {
        return Err("没有可用的更新源".to_string());
    }
    let mut last_err = String::new();
    let mut unreachable = 0;
    for (url, headers) in &sources {
        match crate::commands::cleanup::http_get_limited(
            url,
            headers,
            std::time::Duration::from_millis(RESIDUE_DOWNLOAD_TIMEOUT_MS),
            RESIDUE_RULES_MAX_SIZE,
            None,
        ) {
            Ok(text) => match verify_residue_remote_text(&text, floor) {
                Ok(version) => return Ok((version, text, url.clone())),
                Err(e) => last_err = e,
            },
            Err(e) => {
                unreachable += 1;
                last_err = e;
            }
        }
    }
    if unreachable == sources.len() {
        return Err(format!("所有发布源均不可达，最后一条: {last_err}"));
    }
    Err(format!("源可达但校验未通过，最后一条: {last_err}"))
}

/// uninstall:modify — 修改 / 修复入口（V2 P1-D6，2026-10-01；主窗档）
///
/// 与 uninstall_run 同一条纪律：app_id 只当寻址键，命令行**现读注册表**而不是信任
/// 渲染层早前传来的清单（那可能是旧快照）；NoModify/NoRepair 在执行时复判——
/// 清单说能改、键里已声明不能的场景以注册表为准。二者执行的都是 ModifyPath
/// （Windows「更改 / 修复」共用这一条命令行，MSI 产品会弹出维护对话框再分项），
/// mode 只影响拒绝文案与日志标签，不构造任何新命令行——「识别可以弱，执行不能猜」。
#[tauri::command]
pub async fn uninstall_modify<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    app_id: String,
    mode: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let Some((hive_str, key_path)) = app_id.split_once('|') else {
        return json!({ "success": false, "message": "app_id 格式错误" });
    };
    if !valid_uninstall_key_path(key_path) {
        return json!({ "success": false, "message": "app_id 不是合法的卸载键路径" });
    }
    let mode = match mode.as_deref() {
        Some("repair") => "repair",
        _ => "modify",
    };
    let hive_str = hive_str.to_string();
    let key_path = key_path.to_string();
    let res = tauri::async_runtime::spawn_blocking(move || unsafe {
        use windows::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
        };
        let (hive, _hive_name) = if hive_str.eq_ignore_ascii_case("HKCU") {
            (HKEY_CURRENT_USER, "HKCU")
        } else if hive_str.eq_ignore_ascii_case("HKLM") {
            (HKEY_LOCAL_MACHINE, "HKLM")
        } else {
            return Err("app_id hive 只支持 HKCU/HKLM".to_string());
        };
        let sk = to_wide(&key_path);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err()
        {
            return Err("卸载注册表键不存在（程序可能已被卸载）".to_string());
        }
        let display_name = reg_sz(hk, "DisplayName").unwrap_or_default();
        let modify_path = reg_sz(hk, "ModifyPath").unwrap_or_default();
        let no_modify = reg_dword(hk, "NoModify").unwrap_or(0);
        let no_repair = reg_dword(hk, "NoRepair").unwrap_or(0);
        let _ = RegCloseKey(hk);
        let label = if mode == "repair" { "修复" } else { "修改" };
        if modify_path.trim().is_empty() {
            return Err("该程序没有 ModifyPath，无法执行修改/修复".to_string());
        }
        if mode != "repair" && no_modify == 1 {
            return Err("该程序声明不支持更改（NoModify=1）".to_string());
        }
        if mode == "repair" && no_repair == 1 {
            return Err("该程序声明不支持修复（NoRepair=1）".to_string());
        }
        let (exe, args) = split_uninstall_cmd(&modify_path)
            .ok_or_else(|| "ModifyPath 无法解析出可执行文件".to_string())?;
        log::flush_sync();
        let code = shell_run_wait(&exe, &args).map_err(|e| {
            log::write_log(
                "error",
                &format!("uninstall_modify {display_name}: {label}启动失败: {e}"),
            );
            e
        })?;
        log::write_log(
            "info",
            &format!("uninstall_modify {display_name}: {label}完成，退出码 {code}"),
        );
        Ok(code)
    })
    .await;
    match res {
        Ok(Ok(code)) => json!({ "success": true, "data": { "exitCode": code, "mode": mode } }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("修改/修复执行异常: {e}") }),
    }
}

/// uninstall:check-residue-version — 只查版本，不写任何东西（主窗档）
#[tauri::command]
pub async fn uninstall_check_residue_version<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(|| match fetch_verified_residue_package() {
        Ok((version, _text, source)) => Ok((version, source)),
        Err(e) => Err(e),
    })
    .await;
    match res {
        Ok(Ok((version, source))) => {
            let current = residue_local_version();
            json!({ "success": true, "data": {
                "currentVersion": current, "remoteVersion": version,
                "newerAvailable": version > current, "source": source,
            }})
        }
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("检查残留规则版本异常: {e}") }),
    }
}

/// uninstall:update-residue-rules — 更新残留规则库（主窗档；显式动作，不做定时）。
/// 落盘必须是**字节级**原子写：重新序列化 JSON 会改键序/空白，而 `_sig` 是对原文本签的，
/// 重排就把合法包变成验签失败（清理域审查 M10 的同一条教训）。
#[tauri::command]
pub async fn uninstall_update_residue_rules<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(|| {
        let (version, text, source) = fetch_verified_residue_package()?;
        let dir = residue_rules_write_dir();
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建规则目录失败: {e}"))?;
        let target = residue_rules_write_dir().join("residue-rules.json");
        crate::security::atomic_write_file(&target, text.as_bytes())
            .map_err(|e| format!("写入残留规则失败: {e}"))?;
        // 水位线只在真的抬得动时记一笔；写失败不撤销本次更新（读取侧仍有验签与语义闸）
        let raised = set_residue_watermark(version);
        Ok::<(f64, String, bool), String>((version, source, raised))
    })
    .await;
    match res {
        Ok(Ok((version, source, raised))) => {
            log::write_log(
                "info",
                &format!(
                    "残留规则库已更新: rulesVersion={version} 源={source} 水位线={}",
                    if raised { "已抬升" } else { "未变(写入失败或不高于当前)" }
                ),
            );
            json!({ "success": true, "data": {
                "rulesVersion": version, "source": source,
                "message": format!("残留规则库已更新到 {version}"),
            }})
        }
        Ok(Err(e)) => {
            log::write_log("warn", &format!("残留规则库更新失败: {e}"));
            json!({ "success": false, "message": e })
        }
        Err(e) => json!({ "success": false, "message": format!("残留规则更新异常: {e}") }),
    }
}
