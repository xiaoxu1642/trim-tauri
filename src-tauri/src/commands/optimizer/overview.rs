//! 只读视图：optimizer:list / svc-mem-current / check-optimized / state-overview，
//! 以及支撑回读判定的 .reg 块解析（预期值 → Check 列表）。
//!
//! check_optimized 的判据来自规则库 .reg 文本的期望值，解析口径必须与还原侧
//! （backup_restore.rs 的写回）一致，否则会出现「显示已优化、还原写不回」的分叉。

use crate::engine::{guard, optimization_state as opt_state};
use serde_json::{Value, json};
use tauri::{Runtime, WebviewWindow};
use super::apply::*;
use super::backup_restore::*;
use super::catalog::*;
// ==================== .reg 块解析与回读检测 ====================

/// `.reg` 根键 → native hive 句柄（B11：检测不再经 PS，需要真实 hive）
pub(super) fn reg_hive(root: &str) -> Option<windows::Win32::System::Registry::HKEY> {
    use windows::Win32::System::Registry::{HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS};
    Some(match root {
        "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        "HKEY_USERS" => HKEY_USERS,
        "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
        _ => return None,
    })
}

#[derive(Clone)]
pub(super) struct Check {
    kind: &'static str, // "reg" | "svc"
    // reg（B11：检测改原生，直接带 hive + 子键，不再经 PS 路径字符串）
    hive: windows::Win32::System::Registry::HKEY,
    subkey: String,
    key: String,
    is_dword: bool,
    data: String,
    // svc
    name: String,
}

/// 解析一个 .reg 值的期望数据（dword:hex→十进制 / 引号串 / 原串）
pub(super) fn parse_reg_expected(raw: &str) -> Option<(bool, String)> {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("dword:") {
        let n = i64::from_str_radix(hex, 16).ok()?;
        return Some((true, n.to_string()));
    }
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        return Some((false, raw[1..raw.len() - 1].to_string()));
    }
    Some((false, raw.to_string()))
}

/// 解析 option.steps 中全部 reg 期望值 + service.disable
pub(super) fn collect_checks(opt: &Value) -> Vec<Check> {
    let mut checks = Vec::new();
    let steps = opt.get("steps").and_then(|v| v.as_array());
    let Some(steps) = steps else { return checks };
    for s in steps {
        if let Some(block) = s.get("reg").and_then(|v| v.as_str()) {
            for (full, body) in parse_reg_sections(block) {
                let root = full.split('\\').next().unwrap_or("");
                let Some(hive) = reg_hive(root) else { continue };
                // native 子键不含根键段（`full[root.len()..]`），并去掉前导反斜杠
                let subkey = full[root.len()..].trim_start_matches('\\').to_string();
                for (key, raw) in parse_reg_value_lines(&body) {
                    if raw.trim() == "-" {
                        continue; // 还原占位不参与检测
                    }
                    if let Some((is_dword, data)) = parse_reg_expected(&raw) {
                        checks.push(Check {
                            kind: "reg",
                            hive,
                            subkey: subkey.clone(),
                            key,
                            is_dword,
                            data,
                            name: String::new(),
                        });
                    }
                }
            }
        }
        if let (Some(name), Some(true)) = (
            s.get("service").and_then(|v| v.as_str()),
            s.get("disable").and_then(|v| v.as_bool()),
        ) {
            checks.push(Check {
                kind: "svc",
                hive: reg_hive("HKEY_LOCAL_MACHINE").unwrap(),
                subkey: String::new(),
                key: String::new(),
                is_dword: false,
                data: String::new(),
                name: name.to_string(),
            });
        }
    }
    checks
}

/// 切分 .reg 文本为 (段全名, 段内文本) 列表。
/// 段行为 `[xxx]`（trim 后首尾方括号），值体到下一段或末尾。
pub(super) fn parse_reg_sections(block: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cur_name: Option<String> = None;
    let mut cur_body = String::new();
    for line in block.split(['\n']) {
        let t = line.trim_end_matches('\r');
        let tt = t.trim();
        if tt.starts_with('[') && tt.ends_with(']') && tt.len() >= 2 {
            if let Some(name) = cur_name.take() {
                out.push((name, std::mem::take(&mut cur_body)));
            }
            cur_name = Some(tt[1..tt.len() - 1].trim().to_string());
        } else if cur_name.is_some() {
            cur_body.push_str(t);
            cur_body.push('\n');
        }
    }
    if let Some(name) = cur_name {
        out.push((name, cur_body));
    }
    out
}

/// 解析段内 `"键"=值` 行（键名不含引号字符，与 JS [^"]+ 同口径）
pub(super) fn parse_reg_value_lines(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix('"') else { continue };
        let Some(qend) = rest.find('"') else { continue };
        let key = &rest[..qend];
        let Some(eq) = rest[qend + 1..].strip_prefix('=') else { continue };
        out.push((key.to_string(), eq.trim().to_string()));
    }
    out
}

/// 只读检测多个选项，返回 id -> 是否全部期望生效
///
/// B11：原先这里生成一段 PS（`Test-One` / `Test-Svc` 两个函数 + 每个选项一行
/// `-and` 链）、落临时 `.ps1`、spawn pwsh、120s 超时、再从 stdout 抠 JSON ——
/// 就为了读一批注册表值和服务启动类型。现在直接走注册表 / SCM API：
/// 语义逐条对齐原 PS（缺值 / 类型不对 / 打不开键 / 服务不存在 都算「未生效」）。
///
/// 与原 PS 的**一处刻意差异**：DWORD 比较按无符号 32 位读出（`read_reg_dword_opt`），
/// 原 PS 的 `[int]$v -eq [int]$d` 是 32 位**有符号**，`dword:ffffffff` 这类值会判不上。
/// 优化项里没有 > 2^31-1 的期望值，此差异不改变现有行为，但让实现不再有这个坑。
pub(super) fn check_optimized(ids: &[String]) -> std::collections::HashMap<String, bool> {
    use crate::engine::native;
    let mut result = std::collections::HashMap::new();
    // id -> checks（保留请求顺序）
    let mut grouped: Vec<(String, Vec<Check>)> = Vec::new();
    for id in ids {
        let Some(opt) = find_option(id) else { continue };
        let checks = collect_checks(opt);
        if !checks.is_empty() {
            grouped.push((id.clone(), checks));
        }
    }
    if grouped.is_empty() {
        return result;
    }

    for (id, checks) in &grouped {
        // 全部 check 都生效才算生效（与原 PS 的 `$gv -and (...)` 链一致）；
        // 一条都解析不出来也按「未生效」处理，不给假阳性。
        let all_ok = !checks.is_empty()
            && checks.iter().all(|c| {
                if c.kind == "svc" {
                    native::service_start_type_is(&c.name, native::SVC_START_DISABLED)
                } else if c.is_dword {
                    match c.data.parse::<i64>() {
                        Ok(want) => native::read_reg_dword_opt(c.hive, &c.subkey, &c.key) == Some(want),
                        Err(_) => false,
                    }
                } else {
                    native::read_reg_string(c.hive, &c.subkey, &c.key).as_deref() == Some(c.data.as_str())
                }
            });
        result.insert(id.clone(), all_ok);
    }
    result
}

// ==================== IPC ====================

/// optimizer:list —— 完整选项目录（含 steps/restore）
///
/// 每行补一个 `applyScope`（生效粒度），值来自 [`SCOPE_JSON`] 侧表而非数据层本身 ——
/// `optimizer-runtime.json` 与上游基线是逐字段对拍的双源文件，加字段必判红。
/// 前端在「执行所选优化」的批次结束时按各行取最大粒度，**只提示一次**重启建议。
#[tauri::command]
pub async fn optimizer_list<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let rows: Vec<Value> = options()
        .iter()
        .map(|o| {
            let mut row = o.clone();
            if let Some(map) = row.as_object_mut() {
                map.insert(
                    "applyScope".into(),
                    json!(apply_scope(o.get("id").and_then(Value::as_str).unwrap_or(""))),
                );
            }
            row
        })
        .collect();
    json!({ "success": true, "data": rows })
}

/// optimizer:svc-mem-current —— 当前 SVCHost 拆分阈值档位
///
/// B11：原先这里落一个 4 行的临时 `.ps1`、spawn pwsh、60s 超时、再从 stdout 里抠
/// `KB|<n>` —— 为读一个 HKLM DWORD。现在直接 `read_hklm_dword`，同语义、零进程开销。
#[tauri::command]
pub async fn optimizer_svc_mem_current<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let Some(kb) = svc_mem_current_kb() else {
        // 值不存在（未设置过）→ 与原 PS 的 `NONE` 分支一致：报告成功但无档位
        return json!({ "success": true, "gb": Value::Null, "kb": Value::Null });
    };
    for (k, v) in MEMORY_KB {
        if *v == kb {
            return json!({ "success": true, "gb": k.parse::<i64>().ok().map(Value::from).unwrap_or(Value::Null), "kb": kb });
        }
    }
    if kb == MEMORY_KB_DEFAULT {
        return json!({ "success": true, "gb": "default", "kb": kb });
    }
    json!({ "success": true, "gb": Value::Null, "kb": kb })
}

/// optimizer:check-optimized —— 安全托底检测（id -> bool）
#[tauri::command]
pub async fn optimizer_check_optimized<R: Runtime>(
    window: WebviewWindow<R>,
    ids: Option<Vec<String>>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let ids = ids.unwrap_or_default();
    let results = check_optimized(&ids);
    json!({ "success": true, "results": results })
}

/// optimizer:state-overview —— 记账清单 + stale 判定 + detected
#[tauri::command]
pub async fn optimizer_state_overview<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let raw = opt_state::all();
    let mut items: Vec<Value> = Vec::new();
    let mut pending_ids: Vec<String> = Vec::new();
    let mut check_ids: Vec<String> = Vec::new();

    for (id, rec) in &raw {
        let opt = find_option(id);
        // 变量名刻意区别于 optimizer_run 里的同名变量：check-optimizer-dynamic A2
        // 靠字面前缀定位 4000 字符窗口，本处同名声明会抢走第一个命中
        let is_dyn_record = opt.and_then(|o| o.get("dynamic")).and_then(|v| v.as_bool()).unwrap_or(false);
        if is_dyn_record {
            // 动态项遗留 pending 无法可靠核对，直接清理
            if rec.get("status").and_then(|v| v.as_str()) == Some("pending") {
                opt_state::remove(id);
            }
            continue;
        }
        let checkable = opt
            .map(collect_checks)
            .map(|c| !c.is_empty())
            .unwrap_or(false);
        let title = opt
            .and_then(|o| o.get("title").cloned())
            .unwrap_or_else(|| rec.get("title").cloned().unwrap_or(json!(id)));
        items.push(json!({
            "id": id,
            "title": title,
            "appliedAt": rec.get("appliedAt"),
            "kinds": rec.get("kinds"),
            "status": rec.get("status"),
            "lastVerify": rec.get("lastVerify"),
            "checkable": checkable
        }));
        match rec.get("status").and_then(|v| v.as_str()) {
            Some("pending") => pending_ids.push(id.clone()),
            _ if checkable => check_ids.push(id.clone()),
            _ => {}
        }
    }

    let mut stale_ids = pending_ids;
    if !check_ids.is_empty() {
        let results = check_optimized(&check_ids);
        for id in &check_ids {
            if results.get(id) == Some(&false) {
                stale_ids.push(id.clone());
            }
        }
    }

    json!({
        "success": true,
        "items": items,
        "staleIds": stale_ids,
        // v2-M14：这里原先是 `{ "restored": [], "failed": [] }` 的字面空桩，渲染层据此弹
        // 「已自动还原 N 项」——那件事从没发生过。空桩删除后字段改成**待还原清单**：
        // 退役项在本机留有注册表备份的才出现，由用户点「按原值还原」走已提权的还原通道。
        "migration": { "pending": retired_pending_backups(&load_opt_backups()) },
        "detected": Value::Object(opt_state::detected_all())
    })
}

