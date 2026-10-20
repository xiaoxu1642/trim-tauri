//! netcheck 域（B 批）：netcheck:collect / netcheck:repair
//!
//! 需在 lib.rs 的 invoke_handler 中注册（本任务不改 lib.rs，请统一登记）：
//!   commands::netcheck::netcheck_collect,
//!   commands::netcheck::netcheck_repair,
//!
//! 实现体来源：main.js 7428-7498（含 runNetcheckCollect）。
//!
//! 安全红线（与 Electron 逐条对齐）：
//! - 只读采集单脚本单 JSON；修复动作是**白名单映射的固定命令模板**，
//!   唯一可变的两个参数（网卡名 / 接口索引）**全部来自主进程自己的检测快照**，
//!   渲染层只传 actionId（不接受渲染层拼接任何字符串）。
//! - 快照按**窗口 label + 域**分槽（Electron 用模块级全局 `netcheckSnapshot`，多窗口会互相覆盖；
//!   Tauri 侧按窗口隔离，行为更严格；槽键唯一真源 `snapshot::domain_key`）。
//! - 需管理员的动作：enable-adapter / start-dhcp / start-dnscache / reset-dns / reset-winhttp
//!   （disable-user-proxy 不改系统配置，不判管理员）。
//! - 修复后自动重跑一次 collect，把最新 items 一并回传（整页快照刷新）。

use std::collections::HashMap;

use serde_json::{json, Value};
use tauri::WebviewWindow;

use crate::engine::{guard, log, sysinfo};

/// 需要管理员权限的修复动作（照抄 main.js 7432）
const NETCHECK_ADMIN_ACTIONS: &[&str] = &[
    "enable-adapter",
    "start-dhcp",
    "start-dnscache",
    "reset-dns",
    "reset-winhttp",
];

// ==================== 快照（按窗口 label + 域分槽） ====================
use crate::commands::state::NETCHECK_SNAPSHOTS;

/// 本域槽键的唯一真源（v7.2 `R1d-L06`）：域内四张槽表原先两种分隔（本表裸 label、
/// fileclean 自拼 `label:type`），统一走 `snapshot::domain_key` 后槽键构造只剩一处实现。
/// 本域每窗只有一个域，裸 label 的基数今天是对的（无跨域顶账），改它是为了口径统一、
/// 不是为了修 bug；`check-native-hygiene` 的 N8 只吃 `snapshot::{set,get,clear}` 调用点，
/// 这张自建表仍在它射程外，键在位由 `u_r1d_command_contracts` 断言钉住。
const NETCHECK_DOMAIN: &str = "netcheck";

fn slot_key(label: &str) -> String {
    crate::engine::snapshot::domain_key(label, NETCHECK_DOMAIN)
}

fn snapshot_store(label: &str, items: Value) {
    let mut g = NETCHECK_SNAPSHOTS.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashMap::new)
        .insert(slot_key(label), items);
}

fn snapshot_get(label: &str) -> Option<Value> {
    NETCHECK_SNAPSHOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(&slot_key(label)).cloned())
}

/// 让本窗快照失效（v7.2 `R1d-M07`）：清不掉旧账，下一次修复就按修复前那次检测的
/// 网卡索引/适配器名执行——打错对象。
fn snapshot_remove(label: &str) {
    if let Some(g) = NETCHECK_SNAPSHOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
    {
        g.remove(&slot_key(label));
    }
}

/// 在本窗口快照中查找 actionId 对应的 repair 对象。
/// 匹配覆盖 `repair` 与 `repairs[]` 两个槽位（NT-2：残留用户代理与 WinHTTP 代理可同时呈现）。
fn find_repair(label: &str, action_id: &str) -> Option<Value> {
    let items = match snapshot_get(label) {
        Some(Value::Array(items)) => items,
        _ => return None,
    };
    let id_eq = |r: &Value| r.get("id").and_then(|v| v.as_str()) == Some(action_id);
    // 主槽 repair
    for it in &items {
        if let Some(r) = it.get("repair") {
            if id_eq(r) {
                return Some(r.clone());
            }
        }
    }
    // 副槽 repairs[]
    for it in &items {
        if let Some(arr) = it.get("repairs").and_then(|v| v.as_array()) {
            if let Some(r) = arr.iter().find(|r| id_eq(r)) {
                return Some(r.clone());
            }
        }
    }
    None
}

// ==================== 采集 / 修复 ====================
/// 跑一次网络检测，并落到本窗口快照槽。
/// S3：纯 Rust 原生，无 PS 回退。
///
/// v7.2 `R1d-M07`：旧写法只在 `items` 是数组时写槽，其它情况**原样留着旧槽** ⇒
/// 采集失败/形状不对时，快照仍是「上一次成功检测」的账，而修复按快照取网卡索引与
/// 适配器名——等于对着可能已经消失的网卡下命令。现在采不到就把本窗槽清掉（fail-closed），
/// 下一次修复会被 `find_repair` 判「不在快照内」并要求重检，而不是静默用旧目标。
fn run_netcheck_collect(label: &str) -> Result<Value, String> {
    match crate::engine::native::netcheck_status() {
        Ok(data) => {
            match data.get("items").filter(|v| v.is_array()).cloned() {
                Some(items) => snapshot_store(label, items),
                None => {
                    snapshot_remove(label);
                    log::write_log("warn", "网络检测回执缺 items 数组，本窗快照已作废");
                }
            }
            log::write_log("info", "网络检测原生完成");
            Ok(data)
        }
        Err(e) => {
            snapshot_remove(label);
            Err(format!("原生检测失败: {e}"))
        }
    }
}

/// netcheck:collect — 只读采集
#[tauri::command]
pub async fn netcheck_collect<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let label = window.label().to_string();
    let result = tauri::async_runtime::spawn_blocking(move || run_netcheck_collect(&label)).await;
    Ok(match result {
        Ok(Ok(data)) => json!({ "success": true, "data": data }),
        Ok(Err(message)) => json!({ "success": false, "message": message }),
        Err(e) => json!({ "success": false, "message": format!("检测任务异常: {e}") }),
    })
}

fn do_repair(action_id: &str, repair: &Value, label: &str) -> Value {
    log::flush_sync(); // 危险操作前刷盘：修复会改服务/网卡/代理配置
    log::write_log("info", &format!("网络检测修复开始: {action_id}"));

    // S3：纯 Rust 原生
    let fix = match crate::engine::native::netcheck_repair(action_id, repair) {
        Ok(f) => {
            if f.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                f
            } else {
                let msg = f.get("message").and_then(|v| v.as_str()).unwrap_or("");
                json!({"ok": false, "message": format!("原生修复未成功: {msg}")})
            }
        }
        Err(e) => json!({"ok": false, "message": format!("原生修复异常: {e}")}),
    };
    let fix_ok = fix.get("ok").and_then(|v| v.as_bool()) == Some(true);

    // 修复后自动重跑检测（整页快照刷新，其余项也随之更新）
    let collect = run_netcheck_collect(label);
    let items = match &collect {
        Ok(d) => d.get("items").cloned().unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    if fix_ok {
        log::write_log("info", &format!("网络检测修复完成: {action_id}"));
    } else {
        let msg = fix.get("message").and_then(|v| v.as_str()).unwrap_or("");
        log::write_log(
            "warn",
            &format!(
                "网络检测修复失败: {action_id} -> {}",
                msg.chars().take(120).collect::<String>()
            ),
        );
    }
    json!({
        "success": fix_ok,
        "fix": fix,
        "items": items,
        "message": fix.get("message").cloned().unwrap_or(Value::Null),
    })
}

/// netcheck:repair — 白名单动作修复（快照校验 + 管理员判定）
#[tauri::command]
pub async fn netcheck_repair<R: tauri::Runtime>(window: WebviewWindow<R>, action_id: String) -> Result<Value, String> {
    // 先闸后参：来源校验必须在参数校验之前（与本域其它命令同口径）。
    // 先校验参数会把「谁在调」这层挡在门外，越权调用者先拿到参数是否合法的信号。
    let label = guard::guard(&window, guard::MAIN)?;
    // v7.2 `R1d-L05`：长度闸按字符数计（`len()` 数 UTF-8 字节，非 ASCII 动作 id 会更早被拒）。
    if action_id.is_empty() || crate::engine::paths::exceeds_char_len(&action_id, 40) {
        return Ok(json!({ "success": false, "message": "参数不合法" }));
    }

    // 动作必须属于本窗口最近一次检测快照；参数只取快照里的值
    let repair = match find_repair(&label, &action_id) {
        Some(r) => r,
        None => {
            return Ok(json!({
                "success": false,
                "message": "该修复动作不在当前检测快照内，请先重新检测",
            }))
        }
    };
    if NETCHECK_ADMIN_ACTIONS.contains(&action_id.as_str()) && !sysinfo::is_admin() {
        return Ok(json!({
            "success": false,
            "needAdmin": true,
            "message": "该修复动作需要管理员权限",
        }));
    }

    let action = action_id.clone();
    let result =
        tauri::async_runtime::spawn_blocking(move || do_repair(&action, &repair, &label)).await;
    Ok(match result {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": format!("修复任务异常: {e}") }),
    })
}
