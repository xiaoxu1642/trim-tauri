//! startup 域（D 批）：启动项管理 5 条通道
//!
//! 对照 Electron main.js 3883-4060 + src/scripts-powershell/startup-scripts.js。
//!
//! 安全/语义要点（SU-1/N1/SU-4 复核全部保留）：
//! - 扫描结果按「窗口 label」分槽；toggle/delete 只接受快照内 id，副作用参数取快照值。
//! - hive=HKLM/HKLM32 或 scope=HKLM（所有用户）写操作需管理员。
//! - delete：注册表/计划任务由 PS 备份后处理；PS 回传的 fsDelete 文件改由主进程
//!   回收站删除——startup-file 必须与快照 filePath 一致，backup-file 必须位于应用
//!   备份目录内（路径包含校验，防脚本输出被利用），并落删除清单。
//! - add：原生对话框选程序（白名单扩展名），写 HKCU Run 键；同名项 EXISTS 冲突不覆盖。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{Runtime, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::engine::{delete_manifest, guard, log, native, paths, sysinfo};
use crate::pwsh;

const PS_SCAN: &str = include_str!("../../ps/startup_scan.ps1");
const PS_ENABLE: &str = include_str!("../../ps/startup_enable.ps1");
const PS_DISABLE: &str = include_str!("../../ps/startup_disable.ps1");
const PS_REMOVE: &str = include_str!("../../ps/startup_remove.ps1");
const PS_ADD: &str = include_str!("../../ps/startup_add.ps1");

/// toggle 脚本外层多包了一层数组（生成器以 toggle([[sentinel]], bool) 抽取）
const TOGGLE_SENTINEL: &str = "[[\"__TRIM_ITEMS_JSON__\"]]";
const ITEMS_SENTINEL: &str = "[\"__TRIM_ITEMS_JSON__\"]";
const PATH_SENTINEL: &str = "__TRIM_STARTUP_PATH__";
const NAME_SENTINEL: &str = "__TRIM_STARTUP_NAME__";

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
    paths::scan_cache_file("startup-scan.json")
}

fn load_cache() -> Option<(Vec<Value>, i64)> {
    let v = crate::security::read_json_or_default(&cache_file());
    let obj = v.as_object()?;
    let data = obj.get("data")?.as_array()?.clone();
    let ts = obj.get("timestamp")?.as_i64()?;
    Some((data, ts))
}

fn save_cache(items: &[Value]) {
    let payload = json!({ "timestamp": crate::engine::now_ms(), "data": items });
    if let Err(e) = crate::security::atomic_write_json(&cache_file(), &payload) {
        log::write_log("warn", &format!("启动项缓存写入失败: {e}"));
    }
}

/// id 缺省回退链：id || regPath || filePath || taskName || index
fn normalize_ids(items: Vec<Value>) -> Vec<Value> {
    items
        .into_iter()
        .enumerate()
        .map(|(index, mut it)| {
            let has_id = it.get("id").and_then(|v| v.as_str()).is_some();
            if !has_id {
                let fallback = it
                    .get("regPath")
                    .or_else(|| it.get("filePath"))
                    .or_else(|| it.get("taskName"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| index.to_string());
                if let Some(o) = it.as_object_mut() {
                    o.insert("id".into(), json!(fallback));
                }
            }
            it
        })
        .collect()
}

fn path_key(p: &str) -> String {
    p.replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

/// 校验全部命中快照，返回快照副本（副作用参数不可由调用方篡改）。
fn validate_snapshot_items(items: &[Value], snap: &HashMap<String, Value>) -> Option<Vec<Value>> {
    if items.is_empty() || items.len() > 500 {
        return None;
    }
    let mut result = Vec::with_capacity(items.len());
    for it in items {
        let id = it.get("id").and_then(|v| v.as_str())?;
        let known = snap.get(id)?;
        if let (Some(a), Some(b)) = (
            it.get("filePath").and_then(|v| v.as_str()),
            known.get("filePath").and_then(|v| v.as_str()),
        ) {
            if path_key(a) != path_key(b) {
                return None;
            }
        }
        result.push(known.clone());
    }
    Some(result)
}

fn needs_hklm(item: &Value) -> bool {
    matches!(
        item.get("hive").and_then(|v| v.as_str()),
        Some("HKLM") | Some("HKLM32")
    ) || item.get("scope").and_then(|v| v.as_str()) == Some("HKLM")
}

fn run_ps(script: &str, timeout: Duration, diag: Option<&str>) -> Result<crate::pwsh::PsOutput, String> {
    let path = pwsh::write_temp_script(script, ".ps1")?;
    let r = pwsh::run_file(&path, timeout, diag);
    let _ = std::fs::remove_file(&path);
    r
}

fn parse_json(stdout: &str) -> Option<Value> {
    let t = stdout.trim();
    if t.is_empty() {
        return None;
    }
    serde_json::from_str(t).ok().or_else(|| {
        t.lines()
            .map(|l| l.trim())
            .filter(|l| l.starts_with('{') || l.starts_with('['))
            .next_back()
            .and_then(|l| serde_json::from_str(l).ok())
    })
}

fn inject_items(template: &str, sentinel: &str, items: &[Value]) -> String {
    let json = serde_json::to_string(items).unwrap_or_else(|_| "[]".into());
    template.replace(sentinel, &json.replace('\'', "''"))
}

// ==================== IPC ====================

/// startup:scan
#[tauri::command]
pub async fn startup_scan<R: Runtime>(window: WebviewWindow<R>, refresh: Option<bool>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();

    if refresh != Some(true) {
        if let Some((data, ts)) = load_cache() {
            snap_set(&label, snapshot_by_id(&data));
            return json!({ "success": true, "data": data, "cached": true, "cachedAt": ts });
        }
    }

    snap_set(&label, HashMap::new());

    // B5 S1：原生扫描优先，失败回退 PS
    let ps_fallback = || -> Vec<Value> {
        let out = match run_ps(PS_SCAN, Duration::from_secs(45), None) {
            Ok(o) => o,
            Err(e) => {
                log::write_log("warn", &format!("启动项扫描 PS 回退失败: {e}"));
                return Vec::new();
            }
        };
        parse_json(&out.stdout)
            .and_then(|v| match v { Value::Array(a) => Some(a), _ => None })
            .unwrap_or_default()
    };

    let data: Vec<Value> = match tauri::async_runtime::spawn_blocking(native::startup_scan).await {
        Ok(Ok(items)) => items,
        Ok(Err(e)) => {
            let _ = log::write_log("warn", &format!("startup:scan 原生失败，回退 PS: {e}"));
            ps_fallback()
        }
        Err(e) => {
            let _ = log::write_log("warn", &format!("startup:scan 任务异常，回退 PS: {e}"));
            ps_fallback()
        }
    };

    let normalized = normalize_ids(data);
    snap_set(&label, snapshot_by_id(&normalized));
    save_cache(&normalized);
    json!({ "success": true, "data": normalized })
}
/// startup:toggle（enable=true 启用 / false 禁用）
#[tauri::command]
pub async fn startup_toggle<R: Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
    enable: Option<bool>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let items = items.unwrap_or_default();
    if items.is_empty() {
        return json!({ "success": false, "message": "缺少启动项" });
    }
    let Some(snap) = snap_get(window.label()) else {
        return json!({ "success": false, "message": "启动项不是最近一次扫描结果，已拒绝执行" });
    };
    let Some(safe) = validate_snapshot_items(&items, &snap) else {
        return json!({ "success": false, "message": "启动项不是最近一次扫描结果，已拒绝执行" });
    };
    if safe.iter().any(needs_hklm) && !sysinfo::is_admin() {
        return json!({
            "success": false, "needAdmin": true,
            "message": "涉及「所有用户」的启动项需要管理员权限，请先提权"
        });
    }
    let enable = enable.unwrap_or(true);

    // B5 S2：默认原生，TRIM_LEGACY_STARTUP=1 回退 PS
    let legacy = std::env::var("TRIM_LEGACY_STARTUP").map(|v| v == "1").unwrap_or(false);
    let data = if legacy {
        let template = if enable { PS_ENABLE } else { PS_DISABLE };
        let script = inject_items(template, TOGGLE_SENTINEL, &safe);
        log::write_log("info", &format!("启动项{} {} 项（PS 回退）", if enable { "启用" } else { "禁用" }, safe.len()));
        let out = match run_ps(&script, Duration::from_secs(60), Some("startup.toggle")) {
            Ok(o) => o,
            Err(e) => return json!({ "success": false, "message": e }),
        };
        match parse_json(&out.stdout) {
            Some(d) => d,
            None => return json!({ "success": false, "message": "无法解析执行结果" }),
        }
    } else {
        match crate::engine::native::startup_toggle(&safe, enable) {
            Ok(d) => {
                log::write_log("info", &format!("启动项{}原生完成 {} 项", if enable { "启用" } else { "禁用" }, safe.len()));
                d
            }
            Err(e) => return json!({ "success": false, "message": format!("原生执行失败（设 TRIM_LEGACY_STARTUP=1 可回退 PS）: {e}") }),
        }
    };
    let failed = data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0);
    json!({ "success": failed == 0, "data": data })
}

/// startup:delete（PS 备份 + 注册表/计划任务删除；文件类由主进程回收站删除）
#[tauri::command]
pub async fn startup_delete<R: Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let items = items.unwrap_or_default();
    if items.is_empty() {
        return json!({ "success": false, "message": "缺少启动项" });
    }
    let Some(snap) = snap_get(window.label()) else {
        return json!({ "success": false, "message": "启动项不是最近一次扫描结果，已拒绝执行" });
    };
    let Some(safe) = validate_snapshot_items(&items, &snap) else {
        return json!({ "success": false, "message": "启动项不是最近一次扫描结果，已拒绝执行" });
    };
    if safe.iter().any(needs_hklm) && !sysinfo::is_admin() {
        return json!({
            "success": false, "needAdmin": true,
            "message": "涉及「所有用户」的启动项需要管理员权限，请先提权"
        });
    }

    log::write_log("info", &format!("启动项删除 {} 项", safe.len()));

    // B5 S2：默认原生，TRIM_LEGACY_STARTUP=1 回退 PS
    let legacy = std::env::var("TRIM_LEGACY_STARTUP").map(|v| v == "1").unwrap_or(false);
    let mut data = if legacy {
        let script = inject_items(PS_REMOVE, ITEMS_SENTINEL, &safe);
        let out = match run_ps(&script, Duration::from_secs(60), Some("startup.delete")) {
            Ok(o) => o,
            Err(e) => return json!({ "success": false, "message": e }),
        };
        match parse_json(&out.stdout) {
            Some(d) => d,
            None => return json!({ "success": false, "message": "无法解析执行结果" }),
        }
    } else {
        match crate::engine::native::startup_delete(&safe) {
            Ok(d) => {
                log::write_log("info", "启动项删除原生完成");
                d
            }
            Err(e) => return json!({ "success": false, "message": format!("原生删除失败（设 TRIM_LEGACY_STARTUP=1 可回退 PS）: {e}") }),
        }
    };

    // 文件类删除：白名单 containment 校验后回收站删除
    let fs_delete: Vec<Value> = data
        .get("fsDelete")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|v| !v.is_null())
        .collect();

    if !fs_delete.is_empty() {
        log::flush_sync();
        // 备份目录候选：%APPDATA%\Trim\startup-backup\deleted 与应用数据目录同名路径
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(appdata) = std::env::var("APPDATA") {
            candidates.push(
                std::path::PathBuf::from(appdata)
                    .join("Trim")
                    .join("startup-backup")
                    .join("deleted"),
            );
        }
        candidates.push(paths::app_data_dir().join("startup-backup").join("deleted"));

        let mut manifest: Vec<Value> = Vec::new();
        for fd in &fs_delete {
            let p = fd.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let id = fd.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let kind = fd.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let item = safe.iter().find(|it| it.get("id").and_then(|v| v.as_str()) == Some(id));

            let allowed = if !p.is_empty() && item.is_some() {
                match kind {
                    "startup-file" => item
                        .and_then(|it| it.get("filePath").and_then(|v| v.as_str()))
                        .map(|fp| path_key(p) == path_key(fp))
                        .unwrap_or(false),
                    "backup-file" => candidates.iter().any(|dir| {
                        let rel = std::path::Path::new(p).strip_prefix(dir);
                        matches!(rel, Ok(r) if !r.as_os_str().is_empty())
                    }),
                    _ => false,
                }
            } else {
                false
            };

            let (ok, msg) = if !allowed {
                (false, "删除路径与快照不符，已拒绝".to_string())
            } else {
                match trim_finder::scan::recycle::send_to_trash(p) {
                    Ok(()) => (true, "已移入回收站（已备份）".to_string()),
                    Err(e) => (false, e),
                }
            };

            if ok {
                let name = fd
                    .get("name")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .or_else(|| item.and_then(|it| it.get("name").and_then(|v| v.as_str())))
                    .unwrap_or("");
                manifest.push(json!({
                    "path": p.replace('/', "\\"),
                    "name": name,
                    "recycled": true,
                    "deletedAt": delete_manifest::iso_now()
                }));
                bump_counter(&mut data, "success");
                set_result_entry(&mut data, id, "ok", &msg);
            } else {
                bump_counter(&mut data, "failed");
                set_result_entry(&mut data, id, "error", &msg);
            }
        }
        if !manifest.is_empty() {
            let batch = format!("startup-{}", crate::engine::now_ms());
            delete_manifest::save_delete_manifest(&batch, &manifest);
        }
        if let Some(o) = data.as_object_mut() {
            o.remove("fsDelete");
        }
    }

    let failed = data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0);
    json!({ "success": failed == 0, "data": data })
}

fn bump_counter(data: &mut Value, key: &str) {
    if let Some(o) = data.as_object_mut() {
        let n = o.get(key).and_then(|v| v.as_i64()).unwrap_or(0) + 1;
        o.insert(key.into(), json!(n));
    }
}

fn set_result_entry(data: &mut Value, id: &str, status: &str, message: &str) {
    if let Some(results) = data.get_mut("results").and_then(|v| v.as_array_mut()) {
        for r in results.iter_mut() {
            if r.get("id").and_then(|v| v.as_str()) == Some(id) {
                if let Some(o) = r.as_object_mut() {
                    o.insert("status".into(), json!(status));
                    o.insert("message".into(), json!(message));
                }
                return;
            }
        }
    }
}

/// startup:openlocation —— 在资源管理器中定位并选中文件
#[tauri::command]
pub async fn startup_openlocation<R: Runtime>(
    window: WebviewWindow<R>,
    path: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let target = path.unwrap_or_default();
    if target.is_empty() || target.contains('\0') {
        return json!({ "success": false, "message": "缺少路径" });
    }
    // explorer /select,<path>：参数独立传递（不走 shell），无命令注入面
    let arg = format!("/select,{}", target.replace('/', "\\"));
    match std::process::Command::new("explorer.exe").arg(&arg).spawn() {
        Ok(_) => json!({ "success": true }),
        Err(e) => {
            log::write_log("error", &format!("打开所在位置异常: {e}"));
            json!({ "success": false, "message": e.to_string() })
        }
    }
}

/// startup:add —— 原生对话框选程序 → 写当前用户 Run 键（同名冲突不覆盖）
#[tauri::command]
pub async fn startup_add<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let picked = window
        .dialog()
        .file()
        .set_title("选择要添加为开机启动的程序")
        .add_filter("程序文件", &["exe", "lnk", "bat", "cmd", "com"])
        .add_filter("所有文件", &["*"])
        .blocking_pick_file();

    let Some(file_path) = picked else {
        return json!({ "success": false, "canceled": true });
    };
    let path_buf = match file_path.into_path() {
        Ok(p) => p,
        Err(e) => return json!({ "success": false, "message": format!("无效路径: {e}") }),
    };
    let file_path_str = path_buf.to_string_lossy().to_string();
    if file_path_str.contains('\0') {
        return json!({ "success": false, "canceled": true });
    }
    let name = path_buf
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    // S1：原生优先，失败自动回退 PS
    // B5 S2：默认原生，TRIM_LEGACY_STARTUP=1 回退 PS
    let legacy = std::env::var("TRIM_LEGACY_STARTUP").map(|v| v == "1").unwrap_or(false);
    if !legacy {
        match crate::engine::native::startup_add(&file_path_str, &name) {
            Ok(None) => {
                log::write_log("info", &format!("添加启动项（原生）: {file_path_str}"));
                return json!({ "success": true, "path": file_path_str, "name": name });
            }
            Ok(Some(existing)) => {
                log::write_log("warn", &format!("添加启动项冲突: {name} 已存在，未重复添加（{existing}）"));
                return json!({
                    "success": false, "exists": true, "name": name,
                    "message": "同名的开机启动项已存在，未重复添加"
                });
            }
            Err(e) => return json!({ "success": false, "message": format!("原生添加失败（设 TRIM_LEGACY_STARTUP=1 可回退 PS）: {e}") }),
        }
    }
    let script = PS_ADD
        .replace(PATH_SENTINEL, &file_path_str.replace('\'', "''"))
        .replace(NAME_SENTINEL, &name.replace('\'', "''"));
    let out = match run_ps(&script, Duration::from_secs(20), None) {
        Ok(o) => o,
        Err(e) => return json!({ "success": false, "message": e }),
    };
    if out.code != 0 {
        return json!({ "success": false, "message": if out.stderr.trim().is_empty() { "写入注册表失败".into() } else { out.stderr } });
    }
    let text = out.stdout.trim();
    if let Some(existing) = text.strip_prefix("EXISTS:") {
        log::write_log("warn", &format!("添加启动项冲突: {name} 已存在，未重复添加（{existing}）"));
        return json!({
            "success": false, "exists": true, "name": name,
            "message": "同名的开机启动项已存在，未重复添加"
        });
    }
    log::write_log("info", &format!("添加启动项: {file_path_str}"));
    json!({ "success": true, "path": file_path_str, "name": name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hklm_scope_requires_admin() {
        assert!(needs_hklm(&json!({ "hive": "HKLM" })));
        assert!(needs_hklm(&json!({ "hive": "HKLM32" })));
        assert!(needs_hklm(&json!({ "scope": "HKLM" })));
        assert!(!needs_hklm(&json!({ "hive": "HKCU" })));
        assert!(!needs_hklm(&json!({ "scope": "HKCU" })));
    }

    #[test]
    fn snapshot_items_only() {
        let snap = snapshot_by_id(&[json!({ "id": "r1", "filePath": "C:\\A\\x.lnk" })]);
        assert!(validate_snapshot_items(&[json!({ "id": "r1" })], &snap).is_some());
        assert!(validate_snapshot_items(&[json!({ "id": "nope" })], &snap).is_none());
        // filePath 与快照不一致即拒绝（防替换删除目标）
        assert!(validate_snapshot_items(
            &[json!({ "id": "r1", "filePath": "C:\\B\\evil.lnk" })],
            &snap
        )
        .is_none());
    }
}
