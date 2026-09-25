//! contextmenu 域（D 批）：右键菜单 10 条通道
//!
//! 对照 Electron main.js 2381-2823 + src/scripts-powershell/contextmenu-scripts.js。
//!
//! 安全模型（与 Electron 逐条对齐，CM-1/2/3/9/12/16 复核全部保留）：
//! - 扫描结果按「窗口 label」分槽（id -> 完整扫描项）；backup/remove/toggle/icons/open-regedit
//!   只接受快照内 id，且副作用参数（regPath/nativeRegPath/source/clsid/blockedBy/target/risk）
//!   一律取快照值，渲染层只能表达「选了哪些 id、目标 enabled 态」。
//! - nativeRegPath 是真实写入 hive（HKCR 是合并视图）；无该字段的旧缓存视为不可用（CM-9）。
//! - HKLM/HKCR/machine 屏蔽表写操作需管理员（CM-3）。
//! - 文件系统类（source=filesystem/winx，如「发送到」.lnk）不走 PS 注册表删除，
//!   由主进程回收站删除 + 删除清单（N1 删除红线）。
//! - toggle 后把 PS 回写的新路径/屏蔽态同步回快照与缓存（CM-12）。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{Runtime, WebviewWindow};

use crate::engine::{delete_manifest, guard, log, native, paths, protect, sysinfo};
use crate::pwsh;

// ==================== 外置 PS 脚本（编译期嵌入，禁止手写） ====================
const PS_SCAN: &str = include_str!("../../ps/cm_scan.ps1");
const PS_BACKUP: &str = include_str!("../../ps/cm_backup.ps1");
const PS_REMOVE: &str = include_str!("../../ps/cm_remove.ps1");
const PS_TOGGLE: &str = include_str!("../../ps/cm_toggle.ps1");
const PS_RESTORE: &str = include_str!("../../ps/cm_restore.ps1");
const PS_ICONS: &str = include_str!("../../ps/cm_icons.ps1");
const PS_RESTART_EXPLORER: &str = include_str!("../../ps/cm_restart_explorer.ps1");
const PS_WIN11_MODE: &str = include_str!("../../ps/cm_win11_mode.ps1");
const PS_BLOCKED_LIST: &str = include_str!("../../ps/cm_blocked_list.ps1");

/// 生成器以 `backup(["__TRIM_ITEMS_JSON__"])` 抽取，存活于脚本体内的字面量
/// 是 `["__TRIM_ITEMS_JSON__"]`（含数组括号），替换值本身即完整 JSON 数组。
const ITEMS_SENTINEL: &str = "[\"__TRIM_ITEMS_JSON__\"]";

/// 窗口快照：item.id -> 扫描项（完整字段）
static SNAPSHOTS: Mutex<Option<HashMap<String, HashMap<String, Value>>>> =
    Mutex::new(None);

fn snap_get(label: &str) -> Option<HashMap<String, Value>> {
    SNAPSHOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(label).cloned())
}

fn snap_set(label: &str, map: HashMap<String, Value>) {
    let mut g = SNAPSHOTS.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashMap::new).insert(label.to_string(), map);
}

fn snap_clear(label: &str) {
    if let Some(g) = SNAPSHOTS.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        g.remove(label);
    }
}

/// 扫描项数组 -> id Map（id 必须是 ≤160 字符的字符串）
fn snapshot_by_id(items: &[Value]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for it in items {
        if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
            if id.len() <= 160 {
                m.insert(id.to_string(), it.clone());
            }
        }
    }
    m
}

fn cache_file() -> std::path::PathBuf {
    paths::scan_cache_file("contextmenu-scan.json")
}

/// 读持久缓存；CM-9：所有项必须带 nativeRegPath 字符串才可用
fn load_cache() -> Option<Vec<Value>> {
    let v = crate::security::read_json_or_default(&cache_file());
    let obj = v.as_object()?;
    let data = obj.get("data")?;
    let arr = data.as_array()?;
    if arr.is_empty() {
        return None;
    }
    if arr
        .iter()
        .all(|it| it.get("nativeRegPath").and_then(|v| v.as_str()).is_some())
    {
        Some(arr.clone())
    } else {
        None
    }
}

fn save_cache(items: &[Value]) {
    let payload = json!({
        "timestamp": crate::engine::now_ms(),
        "data": items
    });
    if let Err(e) = crate::security::atomic_write_json(&cache_file(), &payload) {
        log::write_log("warn", &format!("右键菜单缓存写入失败: {e}"));
    }
}

/// 归一化 id：缺 id 时用 regPath|target（R7：ShellNew 共享 regPath 需复合键）
fn normalize_ids(items: Vec<Value>) -> Vec<Value> {
    items
        .into_iter()
        .enumerate()
        .map(|(index, mut it)| {
            let has_id = it.get("id").and_then(|v| v.as_str()).is_some();
            if !has_id {
                let target = it.get("target").and_then(|v| v.as_str()).unwrap_or("");
                let reg = it.get("regPath").and_then(|v| v.as_str()).unwrap_or("");
                let id = if !target.is_empty() && !reg.is_empty() {
                    format!("{reg}|{target}")
                } else if !reg.is_empty() {
                    reg.to_string()
                } else {
                    index.to_string()
                };
                if let Some(obj) = it.as_object_mut() {
                    obj.insert("id".into(), json!(id));
                }
            }
            it
        })
        .collect()
}

/// 校验调用方传入的 items 全部命中快照，返回**快照副本**（拒绝调用方篡改副作用参数）。
fn validate_snapshot_items(items: &[Value], snap: &HashMap<String, Value>) -> Option<Vec<Value>> {
    if items.is_empty() || items.len() > 500 {
        return None;
    }
    let mut result = Vec::with_capacity(items.len());
    for it in items {
        let id = it.get("id").and_then(|v| v.as_str())?;
        // 只认可快照里的 id；path 字段若双方都有也须一致（防替换路径）
        let known = snap.get(id)?;
        if let (Some(a), Some(b)) = (
            it.get("path").and_then(|v| v.as_str()),
            known.get("path").and_then(|v| v.as_str()),
        ) {
            if path_key(a) != path_key(b) {
                return None;
            }
        }
        result.push(known.clone());
    }
    Some(result)
}

fn path_key(p: &str) -> String {
    p.replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

/// CM-3/CM-9：写操作是否需要管理员（看真实 hive 路径 + machine 屏蔽表）
fn write_needs_admin(item: &Value) -> bool {
    if item.get("blockedBy").and_then(|v| v.as_str()) == Some("machine") {
        return true;
    }
    let p = item
        .get("nativeRegPath")
        .or_else(|| item.get("regPath"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let upper = p.to_uppercase();
    upper.starts_with("HKEY_LOCAL_MACHINE\\")
        || upper.starts_with("HKEY_CLASSES_ROOT\\")
        || upper.starts_with("HKLM\\")
        || upper.starts_with("HKCR\\")
}

/// N1：文件系统类来源（不走 PS 注册表删除）
fn is_file_source(item: &Value) -> bool {
    matches!(
        item.get("source").and_then(|v| v.as_str()),
        Some("filesystem") | Some("winx")
    )
}

/// 审查 v2-K1：恢复方向的提权闸门。抽成纯函数是为了让「提权 / 未提权」两种令牌态都能断言——
/// 命令体里直接调 `sysinfo::is_admin()` 测到的是测试进程自己的令牌态，等于在测运行环境。
fn restore_admin_gate(is_admin: bool) -> Option<Value> {
    (!is_admin).then(|| {
        json!({
            "success": false, "needAdmin": true,
            "message": "恢复右键菜单备份需要管理员权限（备份内可能含机器级项），请先提权再试",
        })
    })
}

fn run_ps(script: &str, timeout: Duration, diag: Option<&str>) -> Result<crate::pwsh::PsOutput, String> {
    let path = pwsh::write_temp_script(script, ".ps1")?;
    let r = pwsh::run_file(&path, timeout, diag);
    let _ = std::fs::remove_file(&path);
    r
}

/// 把 items 序列化进 PS 模板（与 JS serializeItems 同口径：JSON + 单引号翻倍）
fn inject_items(template: &str, items: &[Value]) -> String {
    let json = serde_json::to_string(items).unwrap_or_else(|_| "[]".into());
    let escaped = json.replace('\'', "''");
    template.replace(ITEMS_SENTINEL, &escaped)
}

fn parse_last_json(stdout: &str) -> Option<Value> {
    let line = stdout
        .trim()
        .lines()
        .map(|l| l.trim())
        .filter(|l| l.starts_with('{') || l.starts_with('['))
        .next_back()?;
    serde_json::from_str(line).ok()
}

// ==================== IPC ====================

/// contextmenu:scan（refresh=true 强制重扫；否则优先持久缓存）
#[tauri::command]
pub async fn contextmenu_scan<R: Runtime>(
    window: WebviewWindow<R>,
    refresh: Option<bool>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();

    if refresh != Some(true) {
        if let Some(cached) = load_cache() {
            let map = snapshot_by_id(&cached);
            snap_set(&label, map);
            if let Some(ts) = crate::security::read_json_or_default(&cache_file())
                .get("timestamp")
                .and_then(|v| v.as_i64())
            {
                return json!({ "success": true, "data": cached, "cached": true, "cachedAt": ts });
            }
        }
    }

    snap_clear(&label);
    log::write_log("info", "扫描右键菜单");

    // S1：原生优先，失败自动回退 PS
    let data: Vec<Value> = match crate::engine::native::cm_scan() {
        Ok(items) => {
            log::write_log("info", &format!("右键菜单原生扫描完成: {} 项", items.len()));
            items
        }
        Err(e) => {
            log::write_log("warn", &format!("右键菜单原生扫描失败，回退 PS: {e}"));
            let out = match run_ps(PS_SCAN, Duration::from_secs(60), None) {
                Ok(o) => o,
                Err(e) => return json!({ "success": false, "message": e }),
            };
            if out.timed_out {
                return json!({ "success": false, "message": "扫描超时（超过 60 秒），请稍后重试或关闭其他占用注册表的程序" });
            }
            if out.code != 0 {
                log::write_log("error", &format!("右键菜单扫描失败: {}", out.stderr));
                return json!({ "success": false, "message": if out.stderr.is_empty() { "扫描失败".into() } else { out.stderr } });
            }
            match parse_last_json(&out.stdout).and_then(|v| match v {
                Value::Array(a) => Some(a),
                _ => None,
            }) {
                Some(a) => a,
                None => return json!({ "success": false, "message": "解析失败" }),
            }
        }
    };
    let normalized = normalize_ids(data);
    log::write_log("info", &format!("扫描右键菜单完成: {} 项", normalized.len()));
    snap_set(&label, snapshot_by_id(&normalized));
    save_cache(&normalized);
    json!({ "success": true, "data": normalized })
}

/// contextmenu:backup —— 注册表 .reg 备份（整批成功才可用）
#[tauri::command]
pub async fn contextmenu_backup<R: Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let items = items.unwrap_or_default();
    let Some(snap) = snap_get(window.label()) else {
        return json!({ "success": false, "message": "备份项不是最近一次扫描结果，已拒绝执行" });
    };
    let Some(safe) = validate_snapshot_items(&items, &snap) else {
        return json!({ "success": false, "message": "备份项不是最近一次扫描结果，已拒绝执行" });
    };
    if safe.is_empty() {
        return json!({ "success": false, "message": "没有可备份的右键菜单项" });
    }
    if safe.iter().any(|it| it.get("regPath").and_then(|v| v.as_str()).is_none()) {
        return json!({ "success": false, "message": "备份项缺少注册表/文件路径，已停止" });
    }

    log::write_log("info", &format!("备份右键菜单: {} 项", safe.len()));
    let script = inject_items(PS_BACKUP, &safe);
    let out = match run_ps(&script, Duration::from_secs(60), None) {
        Ok(o) => o,
        Err(e) => return json!({ "success": false, "message": e }),
    };
    if out.code != 0 {
        return json!({ "success": false, "message": "备份失败" });
    }
    let Some(data) = parse_last_json(&out.stdout) else {
        return json!({ "success": false, "message": "解析备份结果失败" });
    };
    let count = data.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
    let failed = data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0);
    if data.get("backupDir").and_then(|v| v.as_str()).is_none() || count < 1 {
        return json!({ "success": false, "message": "备份未生成有效文件" });
    }
    if failed > 0 {
        log::write_log("error", &format!("右键菜单备份部分失败: {failed} 项未能导出"));
        return json!({
            "success": false,
            "message": format!("有 {failed} 项未能生成有效备份（无法归位到真实注册表 hive），已停止删除")
        });
    }
    json!({ "success": true, "data": data })
}

/// contextmenu:remove —— 注册表项 PS 删除 + 文件系统项回收站删除
#[tauri::command]
pub async fn contextmenu_remove<R: Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let items = items.unwrap_or_default();
    let Some(snap) = snap_get(window.label()) else {
        return json!({ "success": false, "message": "删除项不是最近一次扫描结果，已拒绝执行" });
    };
    let Some(safe) = validate_snapshot_items(&items, &snap) else {
        return json!({ "success": false, "message": "删除项不是最近一次扫描结果，已拒绝执行" });
    };
    if safe.is_empty() {
        return json!({ "success": false, "message": "没有可删除的右键菜单项" });
    }
    if safe.iter().any(write_needs_admin) && !sysinfo::is_admin() {
        return json!({
            "success": false, "needAdmin": true,
            "message": "涉及系统级右键菜单的操作需要管理员权限，请先提权"
        });
    }

    let fs_items: Vec<&Value> = safe.iter().filter(|it| is_file_source(it)).collect();
    let reg_items: Vec<Value> = safe.iter().filter(|it| !is_file_source(it)).cloned().collect();

    let mut data = json!({ "success": 0, "failed": 0, "results": [] });

    // 注册表类
    if !reg_items.is_empty() {
        log::write_log("warn", &format!("删除右键菜单: {} 项", reg_items.len()));
        let script = inject_items(PS_REMOVE, &reg_items);
        let parsed = run_ps(&script, Duration::from_secs(60), Some("contextmenu.remove"))
            .ok()
            .and_then(|o| if o.code == 0 { parse_last_json(&o.stdout) } else { None });
        let Some(d) = parsed else {
            return json!({ "success": false, "message": "删除失败" });
        };
        data = d;
    }
    if !data.get("results").map(|v| v.is_array()).unwrap_or(false) {
        data["results"] = json!([]);
    }

    // 文件系统类：回收站删除 + 清单
    if !fs_items.is_empty() {
        log::flush_sync();
        let mut manifest = Vec::new();
        for it in &fs_items {
            let p = it.get("regPath").and_then(|v| v.as_str()).unwrap_or("");
            let id = it.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let name = it.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if p.is_empty() {
                data["failed"] = json!(data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0) + 1);
                data["results"].as_array_mut().unwrap().push(json!({
                    "id": id, "name": name, "status": "error", "message": "缺少文件路径"
                }));
                continue;
            }
            // 审查 M12：AGENTS §3 把「删除前先过 protect」写成无条件红线，本出口此前是唯一
            // 没落的一处。目标其实已被两道闸收住（`validate_snapshot_items` 只认扫描快照里的
            // id/值、且 cm_scan.ps1 把来源限死在 SendTo/WinX 两个根），补 protect 是**纵深**：
            // 万一上游扫描脚本放宽了根目录，这里仍有一道兜底。SendTo/WinX 在 `exact` 语义下
            // 属后代路径，不会被误拦。
            if protect::is_path_protected(p) {
                data["failed"] = json!(data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0) + 1);
                data["results"].as_array_mut().unwrap().push(json!({
                    "id": id, "name": name, "status": "error", "message": "该路径受保护，已拒绝删除"
                }));
                continue;
            }
            match trim_finder::scan::recycle::send_to_trash(p) {
                Ok(()) => {
                    data["success"] = json!(data.get("success").and_then(|v| v.as_i64()).unwrap_or(0) + 1);
                    manifest.push(json!({
                        "path": p.replace('/', "\\"), "name": name, "recycled": true,
                        "deletedAt": delete_manifest::iso_now()
                    }));
                    data["results"].as_array_mut().unwrap().push(json!({
                        "id": id, "name": name, "status": "ok", "message": "已移入回收站"
                    }));
                }
                Err(e) => {
                    data["failed"] = json!(data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0) + 1);
                    data["results"].as_array_mut().unwrap().push(json!({
                        "id": id, "name": name, "status": "error", "message": e
                    }));
                }
            }
        }
        if !manifest.is_empty() {
            let batch = format!("ctxmenu-{}", crate::engine::now_ms());
            delete_manifest::save_delete_manifest(&batch, &manifest);
        }
    }

    // CM-12：从快照与缓存摘除已成功项
    let gone: std::collections::HashSet<String> = data
        .get("results")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter(|r| {
            r.get("status").and_then(|v| v.as_str()) == Some("ok")
                || r.get("message").and_then(|v| v.as_str()) == Some("路径不存在")
        })
        .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();
    if !gone.is_empty() {
        if let Some(mut s) = snap_get(window.label()) {
            for id in &gone {
                s.remove(id);
            }
            snap_set(window.label(), s);
        }
        if let Some(items) = load_cache() {
            let kept: Vec<Value> = items
                .into_iter()
                .filter(|it| !gone.contains(it.get("id").and_then(|v| v.as_str()).unwrap_or("")))
                .collect();
            save_cache(&kept);
        }
    }

    let failed = data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0);
    json!({ "success": failed == 0, "data": data })
}

/// contextmenu:toggle —— 可逆启停（渲染层只表达目标 enabled，其余取快照）
#[tauri::command]
pub async fn contextmenu_toggle<R: Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let items = items.unwrap_or_default();
    let Some(snap) = snap_get(window.label()) else {
        return json!({ "success": false, "message": "切换项不是最近一次扫描结果，已拒绝执行" });
    };
    let Some(safe) = validate_snapshot_items(&items, &snap) else {
        return json!({ "success": false, "message": "切换项不是最近一次扫描结果，已拒绝执行" });
    };

    // 调用方目标态（按 id）
    let mut wanted: HashMap<String, bool> = HashMap::new();
    for it in &items {
        if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
            wanted.insert(id.to_string(), it.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false));
        }
    }

    let mut toggle_items: Vec<Value> = Vec::new();
    for it in &safe {
        let reg_ok = it.get("regPath").and_then(|v| v.as_str()).is_some();
        let source_ok = it.get("source").and_then(|v| v.as_str()).is_some();
        if !reg_ok || !source_ok {
            continue;
        }
        let id = it.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let enabled = wanted.get(id).copied().unwrap_or_else(|| {
            it.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false)
        });
        let mut obj = serde_json::Map::new();
        obj.insert("id".into(), json!(id));
        obj.insert("name".into(), it.get("name").cloned().unwrap_or(json!("")));
        obj.insert(
            "regPath".into(),
            it.get("regPath").cloned().unwrap_or(json!("")),
        );
        obj.insert(
            "nativeRegPath".into(),
            it.get("nativeRegPath")
                .or_else(|| it.get("regPath"))
                .cloned()
                .unwrap_or(json!("")),
        );
        obj.insert("source".into(), it.get("source").cloned().unwrap_or(json!("")));
        obj.insert("clsid".into(), json!(it.get("clsid").and_then(|v| v.as_str()).unwrap_or("")));
        obj.insert(
            "blockedBy".into(),
            json!(it.get("blockedBy").and_then(|v| v.as_str()).unwrap_or("")),
        );
        obj.insert("target".into(), json!(it.get("target").and_then(|v| v.as_str()).unwrap_or("")));
        obj.insert("risk".into(), json!(it.get("risk").and_then(|v| v.as_str()).unwrap_or("")));
        obj.insert("enabled".into(), json!(enabled));
        toggle_items.push(Value::Object(obj));
    }
    if toggle_items.is_empty() {
        return json!({ "success": false, "message": "没有可切换的菜单项" });
    }
    if toggle_items.iter().any(write_needs_admin) && !sysinfo::is_admin() {
        return json!({
            "success": false, "needAdmin": true,
            "message": "涉及系统级右键菜单的操作需要管理员权限，请先提权"
        });
    }

    log::write_log("info", &format!("切换右键菜单启停: {} 项", toggle_items.len()));

    // S1：原生优先，失败自动回退 PS
    let data = match crate::engine::native::cm_toggle(&toggle_items) {
        Ok(d) => {
            log::write_log("info", "右键菜单切换原生完成");
            d
        }
        Err(e) => {
            log::write_log("warn", &format!("右键菜单切换原生失败，回退 PS: {e}"));
            let script = inject_items(PS_TOGGLE, &toggle_items);
            let out = match run_ps(&script, Duration::from_secs(60), None) {
                Ok(o) => o,
                Err(e) => return json!({ "success": false, "message": e }),
            };
            if out.timed_out {
                return json!({ "success": false, "message": "切换超时，请稍后重试" });
            }
            if out.code != 0 {
                return json!({ "success": false, "message": "切换失败" });
            }
            match parse_last_json(&out.stdout) {
                Some(d) => d,
                None => return json!({ "success": false, "message": "解析切换结果失败" }),
            }
        }
    };

    // CM-12：回写新路径/屏蔽态到快照 + 缓存
    if let Some(results) = data.get("results").and_then(|v| v.as_array()) {
        let mut touched = false;
        let mut snap2 = snap_get(window.label()).unwrap_or_default();
        let updates: Vec<&Value> = results
            .iter()
            .filter(|r| {
                r.get("status").and_then(|v| v.as_str()) == Some("ok")
                    && r.get("id").and_then(|v| v.as_str()).is_some()
            })
            .collect();
        for r in updates {
            let id = r.get("id").and_then(|v| v.as_str()).unwrap();
            if let Some(t) = snap2.get_mut(id) {
                if let Some(en) = wanted.get(id) {
                    t.as_object_mut().map(|o| o.insert("enabled".into(), json!(en)));
                }
                if let Some(np) = r.get("newRegPath").and_then(|v| v.as_str()) {
                    t.as_object_mut().map(|o| o.insert("regPath".into(), json!(np)));
                }
                if let Some(np) = r.get("newNativeRegPath").and_then(|v| v.as_str()) {
                    t.as_object_mut().map(|o| o.insert("nativeRegPath".into(), json!(np)));
                }
                if let Some(nb) = r.get("newBlockedBy").and_then(|v| v.as_str()) {
                    t.as_object_mut().map(|o| o.insert("blockedBy".into(), json!(nb)));
                }
                touched = true;
            }
        }
        if touched {
            let arr: Vec<Value> = snap2.values().cloned().collect();
            snap_set(window.label(), snap2);
            save_cache(&arr);
        }
    }

    let failed = data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0);
    if failed > 0 {
        let first_msg = data
            .get("results")
            .and_then(|v| v.as_array())
            .and_then(|a| a.iter().find(|r| r.get("status").and_then(|s| s.as_str()) == Some("error")))
            .and_then(|r| r.get("message").and_then(|v| v.as_str()))
            .unwrap_or("部分项切换失败（可能需要管理员权限）");
        log::write_log("warn", &format!("启停切换部分失败: {failed} 项"));
        return json!({ "success": false, "message": first_msg, "data": data });
    }
    json!({ "success": true, "data": data })
}

/// contextmenu:restore —— 从备份目录恢复
#[tauri::command]
pub async fn contextmenu_restore<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // 审查 v2-K1：恢复方向没有「本项是否需要提权」的信息可用——要导哪些 .reg 是脚本自己
    // 在备份目录里挑的，件里可能同时含 HKLM 与 HKCU 项。旧写法在非提权态直接跑，会让
    // HKLM 那部分静默失败并被 `success` 判成「已恢复」。这里显式要提权，让整次操作要么
    // 在管理员态完成、要么压根不开始。
    if let Some(deny) = restore_admin_gate(sysinfo::is_admin()) {
        return deny;
    }
    log::write_log("warn", "恢复右键菜单备份");
    let out = match run_ps(PS_RESTORE, Duration::from_secs(60), None) {
        Ok(o) => o,
        Err(e) => return json!({ "success": false, "message": e }),
    };
    if out.code != 0 {
        return json!({ "success": false, "message": "恢复失败" });
    }
    let Some(data) = parse_last_json(&out.stdout) else {
        return json!({ "success": false, "message": "解析恢复结果失败" });
    };
    let imported = data.get("imported").and_then(|v| v.as_i64()).unwrap_or(0)
        + data.get("restored").and_then(|v| v.as_i64()).unwrap_or(0);
    let success = data.get("success").and_then(|v| v.as_bool()).unwrap_or(false) && imported > 0;
    let skipped = data.get("skipped").and_then(|v| v.as_i64()).unwrap_or(0);
    if !success && skipped > 0 && imported == 0 {
        let reasons = data
            .get("skipReasons")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .take(3)
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join("；")
            })
            .unwrap_or_default();
        return json!({
            "success": false, "data": data,
            "message": format!(
                "{} 个备份被拒绝导入（备份头不是真实注册表分支，多为旧版本产生）{}",
                skipped,
                if reasons.is_empty() { String::new() } else { format!("：{reasons}") }
            )
        });
    }
    json!({ "success": success, "data": data })
}

/// contextmenu:icons —— CLSID 图标提取（只接受快照内 CLSID）
#[tauri::command]
pub async fn contextmenu_icons<R: Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let Some(snap) = snap_get(window.label()) else {
        return json!({ "success": true, "data": {} });
    };
    let known: std::collections::HashSet<String> = snap
        .values()
        .filter_map(|it| it.get("clsid").and_then(|v| v.as_str()).map(|s| s.trim().to_uppercase()))
        .filter(|s| !s.is_empty())
        .collect();
    let icon_items: Vec<Value> = items
        .unwrap_or_default()
        .into_iter()
        .filter(|it| {
            it.get("clsid")
                .and_then(|v| v.as_str())
                .map(|c| c.trim().starts_with('{') && known.contains(c.trim().to_uppercase().as_str()))
                .unwrap_or(false)
        })
        .filter_map(|it| {
            it.get("clsid").and_then(|v| v.as_str()).map(|c| json!({ "clsid": c.trim() }))
        })
        .collect();
    if icon_items.is_empty() {
        return json!({ "success": true, "data": {} });
    }
    let script = inject_items(PS_ICONS, &icon_items);
    // 图标提取失败不影响主流程，恒返回 success
    if let Ok(out) = run_ps(&script, Duration::from_secs(30), None) {
        if out.code == 0 {
            if let Some(data) = parse_last_json(&out.stdout) {
                if data.is_object() {
                    return json!({ "success": true, "data": data });
                }
            }
        }
    }
    json!({ "success": true, "data": {} })
}

fn canon_reg_key(s: &str) -> String {
    let mut s = s
        .trim()
        .trim_start_matches("Registry::")
        .trim_end_matches('\\')
        .to_lowercase();
    for (full, short) in [
        ("hkey_classes_root", "hkcr"),
        ("hkey_current_user", "hkcu"),
        ("hkey_local_machine", "hklm"),
        ("hkey_users", "hku"),
    ] {
        if s == full || s.starts_with(&format!("{full}\\")) {
            s = short.to_string() + &s[full.len()..];
            break;
        }
    }
    s
}

/// contextmenu:open-in-regedit —— LastKey 方案打开注册表编辑器（regPath 须在快照内）
#[tauri::command]
pub async fn contextmenu_open_in_regedit<R: Runtime>(
    window: WebviewWindow<R>,
    reg_path: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let mut p = reg_path.unwrap_or_default().trim().trim_end_matches('\\').to_string();
    if p.is_empty() {
        return json!({ "success": false, "message": "无效的注册表路径" });
    }
    let wanted = canon_reg_key(&p);
    let in_snap = snap_get(window.label())
        .map(|snap| {
            snap.values()
                .any(|it| it.get("regPath").map(|v| canon_reg_key(v.as_str().unwrap_or("")) == wanted).unwrap_or(false))
        })
        .unwrap_or(false);
    if !in_snap {
        return json!({ "success": false, "message": "路径不在最近一次扫描结果内，已拒绝打开" });
    }

    // 根键别名展开
    let aliases: HashMap<&str, &str> = HashMap::from([
        ("HKCR", "HKEY_CLASSES_ROOT"),
        ("HKCU", "HKEY_CURRENT_USER"),
        ("HKLM", "HKEY_LOCAL_MACHINE"),
        ("HKU", "HKEY_USERS"),
        ("HKCC", "HKEY_CURRENT_CONFIG"),
    ]);
    if let Some(rest) = p.split_once('\\') {
        if let Some(full) = aliases.get(rest.0.to_uppercase().as_str()) {
            p = format!("{full}\\{}", rest.1);
        }
    } else if let Some(full) = aliases.get(p.to_uppercase().as_str()) {
        p = full.to_string();
    }
    let escaped = p.replace('\'', "''");

    // 与 Electron 同一段内联脚本（无独立 .ps1 来源，直接固化——仅 LastKey + Start-Process）
    let script = format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
$key = '{escaped}'
$running = Get-Process regedit -ErrorAction SilentlyContinue
if ($running) {{
  foreach ($p in $running) {{ try {{ $null = $p.CloseMainWindow() }} catch {{}} }}
  Start-Sleep -Milliseconds 500
}}
try {{
  if (-not (Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit')) {{
    New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit' -Force | Out-Null
  }}
  Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit' -Name 'LastKey' -Value $key -ErrorAction Stop
}} catch {{}}
Start-Sleep -Milliseconds 200
$elevated = $false
try {{
  Start-Process regedit -ErrorAction Stop
}} catch {{
  try {{
    Start-Process regedit -Verb RunAs -ErrorAction Stop
    $elevated = $true
  }} catch {{
    Write-Output 'FAIL'
    exit 1
  }}
}}
if ($elevated) {{ Write-Output 'OK-ELEVATED' }} else {{ Write-Output 'OK' }}
"#
    );

    log::write_log("info", &format!("在注册表编辑器中定位: {p}"));
    let out = match run_ps(&script, Duration::from_secs(30), None) {
        Ok(o) => o,
        Err(e) => return json!({ "success": false, "message": e }),
    };
    let text = out.stdout.trim();
    if out.code == 0 && text.contains("OK") {
        json!({ "success": true, "elevated": text.contains("ELEVATED") })
    } else {
        json!({ "success": false, "message": "打开注册表编辑器失败" })
    }
}

/// contextmenu:restart-explorer
#[tauri::command]
pub async fn contextmenu_restart_explorer<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // B6 S1：原生重启优先
    match tauri::async_runtime::spawn_blocking(native::cm_restart_explorer).await {
        Ok(Ok(data)) => return json!({ "success": data.get("success").and_then(|v| v.as_bool()).unwrap_or(false), "data": data }),
        Ok(Err(e)) => { let _ = log::write_log("warn", &format!("restart-explorer 原生失败，回退 PS: {e}")); }
        Err(e) => { let _ = log::write_log("warn", &format!("restart-explorer 任务异常，回退 PS: {e}")); }
    }
    log::flush_sync();
    log::write_log("warn", "重启资源管理器（使右键菜单改动生效）");
    let out = match run_ps(PS_RESTART_EXPLORER, Duration::from_secs(30), Some("contextmenu.restart-explorer"))
    {
        Ok(o) => o,
        Err(e) => return json!({ "success": false, "message": e }),
    };
    if out.timed_out {
        return json!({ "success": false, "message": "重启超时，请手动结束并重新打开资源管理器" });
    }
    if out.code != 0 {
        return json!({ "success": false, "message": "重启资源管理器失败" });
    }
    let data = parse_last_json(&out.stdout).unwrap_or_else(|| json!({}));
    json!({ "success": data.get("success").and_then(|v| v.as_bool()).unwrap_or(false), "data": data })
}

/// contextmenu:win11-classic —— action 白名单 get/set-classic/set-modern
#[tauri::command]
pub async fn contextmenu_win11_classic<R: Runtime>(
    window: WebviewWindow<R>,
    action: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    const ALLOWED: [&str; 3] = ["get", "set-classic", "set-modern"];
    let act = action.unwrap_or_else(|| "get".into());
    let act = if ALLOWED.contains(&act.as_str()) { act } else { "get".to_string() };
    if act != "get" {
        log::write_log("warn", &format!("切换 Win11 右键菜单模式: {act}"));
    }
    // B6 S1：原生注册表操作优先
    let act_clone = act.clone();
    match tauri::async_runtime::spawn_blocking(move || native::cm_win11_mode(&act_clone)).await {
        Ok(Ok(data)) => return json!({ "success": data.get("success").and_then(|v| v.as_bool()).unwrap_or(false), "data": data }),
        Ok(Err(e)) => { let _ = log::write_log("warn", &format!("win11-mode 原生失败，回退 PS: {e}")); }
        Err(e) => { let _ = log::write_log("warn", &format!("win11-mode 任务异常，回退 PS: {e}")); }
    }
    let script = if act == "get" {
        PS_WIN11_MODE.to_string()
    } else {
        // 生成器抽取时哨兵被 JS 白名单退回 'get'，此处把 provenance 锁定的固定行
        // `$action = 'get'` 替换为白名单动作（act 已严格限定为 3 值之一）。
        PS_WIN11_MODE.replacen("$action = 'get'", &format!("$action = '{act}'"), 1)
    };
    let out = match run_ps(&script, Duration::from_secs(30), None) {
        Ok(o) => o,
        Err(e) => return json!({ "success": false, "message": e }),
    };
    if out.code != 0 {
        return json!({ "success": false, "message": "读取或切换 Win11 菜单模式失败" });
    }
    let data = parse_last_json(&out.stdout).unwrap_or_else(|| json!({}));
    json!({ "success": data.get("success").and_then(|v| v.as_bool()).unwrap_or(false), "data": data })
}

/// contextmenu:blocked-list —— Shell Extensions\Blocked 只读枚举（≤500，GUID 校验）
#[tauri::command]
pub async fn contextmenu_blocked_list<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    // B6 S1：原生注册表只读优先
    match tauri::async_runtime::spawn_blocking(native::cm_blocked_list).await {
        Ok(Ok(data)) => return json!({ "success": true, "data": data }),
        Ok(Err(e)) => { let _ = log::write_log("warn", &format!("blocked-list 原生失败，回退 PS: {e}")); }
        Err(e) => { let _ = log::write_log("warn", &format!("blocked-list 任务异常，回退 PS: {e}")); }
    }
    let out = match run_ps(PS_BLOCKED_LIST, Duration::from_secs(30), None) {
        Ok(o) => o,
        Err(e) => return json!({ "success": false, "message": e }),
    };
    if out.code != 0 {
        return json!({ "success": true, "data": { "entries": [] } });
    }
    let data = parse_last_json(&out.stdout).unwrap_or_else(|| json!({}));
    let entries: Vec<Value> = data
        .get("entries")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter(|e| {
                    e.get("guid")
                        .and_then(|g| g.as_str())
                        .map(|g| {
                            g.starts_with('{')
                                && g.len() == 38
                                && g[1..37].bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
                        })
                        .unwrap_or(false)
                })
                .map(|e| {
                    json!({
                        "guid": e.get("guid").unwrap(),
                        "scope": if e.get("scope").and_then(|s| s.as_str()) == Some("machine") { "machine" } else { "user" }
                    })
                })
                .take(500)
                .collect()
        })
        .unwrap_or_default();
    json!({ "success": true, "data": { "entries": entries } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_scope_uses_native_hive() {
        // CM-9：看 nativeRegPath（真实 hive），HKCR/HKLM 需提权
        assert!(write_needs_admin(&json!({ "nativeRegPath": "HKEY_LOCAL_MACHINE\\X" })));
        assert!(write_needs_admin(&json!({ "regPath": "HKCR\\X" })));
        assert!(write_needs_admin(&json!({ "blockedBy": "machine" })));
        // 纯 HKCU 用户级项不要求提权（本机实测 8 个 HKCU 侧项）
        assert!(!write_needs_admin(&json!({
            "regPath": "HKEY_CLASSES_ROOT\\merge",
            "nativeRegPath": "HKEY_CURRENT_USER\\Software\\Classes\\x"
        })));
        assert!(!write_needs_admin(&json!({ "nativeRegPath": "HKCU\\X" })));
    }

    #[test]
    fn file_sources_bypass_reg_delete() {
        assert!(is_file_source(&json!({ "source": "filesystem" })));
        assert!(is_file_source(&json!({ "source": "winx" })));
        assert!(!is_file_source(&json!({ "source": "registry" })));
    }

    #[test]
    fn restore_requires_elevation_both_ways() {
        // v2-K1：未提权必须回 needAdmin（不是失败、更不是硬跑），提权态闸门放行
        let deny = restore_admin_gate(false).expect("非提权态必须被闸门拦下");
        assert_eq!(deny["success"], false);
        assert_eq!(deny["needAdmin"], true);
        assert!(restore_admin_gate(true).is_none());
    }

    /// v2-K1 的防回退断言：闸门在编译期内嵌的脚本正文里，不在 Rust 侧，
    /// 所以只能这样钉——手改 `.ps1`、或上游 JS 被回退成「遍历目录内全部 *.reg」都会立刻红。
    /// 只断言「闸门存在且没收窄/放宽」，不复述其逻辑（逐字节对拍归 check-ps-extraction 管）。
    #[test]
    fn restore_script_keeps_trust_gates() {
        let s = PS_RESTORE;
        assert!(
            s.contains("manifest.registryFiles"),
            "还原方向丢了 manifest 登记校验，退回自选目录内任意 .reg"
        );
        assert!(
            s.contains("Test-RegKeyAllowedForRestore"),
            "还原方向丢了键路径白名单闸门"
        );
        assert!(
            s.contains("-Filter 'registry_*.reg'"),
            "还原范围从本工具生成的件放宽到全部 .reg"
        );
        // 白名单必须是 Software\Classes 两个 hive；被改宽（如整 hive 放行）即红
        assert!(
            s.contains(r"@('HKLM\SOFTWARE\Classes\', 'HKCU\SOFTWARE\Classes\')"),
            "键路径白名单前缀被改动"
        );
        // 恢复脚本里不该出现任何删除动作
        assert!(!s.contains("Remove-Item"), "恢复脚本出现删除");
    }

    #[test]
    fn canon_regkey_aliases() {
        assert_eq!(canon_reg_key("Registry::HKEY_CURRENT_USER\\Software\\"), "hkcu\\software");
        assert_eq!(canon_reg_key("HKEY_CLASSES_ROOT\\*"), "hkcr\\*");
        assert_eq!(canon_reg_key("HKEY_LOCAL_MACHINE\\X"), "hklm\\x");
    }

    #[test]
    fn snapshot_validation_takes_snapshot_copy() {
        let snap = snapshot_by_id(&[json!({ "id": "a", "regPath": "HKCU\\X" })]);
        // 未知 id 拒绝
        assert!(validate_snapshot_items(&[json!({ "id": "x" })], &snap).is_none());
        // 数量上限
        let many: Vec<Value> = (0..501).map(|_| json!({ "id": "a" })).collect();
        assert!(validate_snapshot_items(&many, &snap).is_none());
        // 命中返回快照副本
        let ok = validate_snapshot_items(&[json!({ "id": "a", "regPath": "HKCU\\EVIL" })], &snap).unwrap();
        // 副作用参数取快照值，调用方篡改不生效
        assert_eq!(ok[0].get("regPath").and_then(|v| v.as_str()), Some("HKCU\\X"));
    }
}
