//! peripheral 域（D 批）：外设优化 5 条通道
//!
//! 对照 Electron main.js 6891-7040 + src/scripts-powershell/peripheral-scripts.js。
//!
//! 安全/语义（PE-3/PE-4/N1/N2/PE-5 全部保留）：
//! - 应用值白名单以主进程为唯一权威（win32/keyboard/mouse 三组固定取值集合），
//!   未命中不再静默跳过，而是整批拒绝（PE-3，防渲染层漏更导致假成功）。
//! - 三项全写 HKLM，apply/restore 恒需管理员（PE-4）。
//! - 缺省/-1 表示该组不改；三组都 -1 拒绝空应用。
//! - PS 写入前导出父键 .reg 备份；成功后主进程修剪备份目录（保留 10 份，旧的进回收站）。
//! - 「还原修改前的值」= 导入最新一份备份 .reg，与「恢复默认」语义分开（N1/PE-5）。

use serde_json::{json, Value};
use tauri::webview::PageLoadEvent;
use tauri::window::Color;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::engine::{guard, log, paths};
use crate::pwsh;

const LABEL: &str = "peripheral";
const PAGE: &str = "peripheral-window.html";
const TITLE: &str = "外设优化";

const PS_QUERY: &str = include_str!("../../ps/peripheral_query.ps1");
const PS_APPLY: &str = include_str!("../../ps/peripheral_apply.ps1");
const PS_RESTORE: &str = include_str!("../../ps/peripheral_restore.ps1");

const APPLY_SENTINEL: &str = "{\"__trim_sentinel__\":true}";

/// PE-3：主进程唯一权威合法值集合
const ALLOWED_WIN32: &[i64] = &[2, 26, 36, 38, 40];
const ALLOWED_KEYBOARD: &[i64] = &[16, 18, 20, 22, 100];
const ALLOWED_MOUSE: &[i64] = &[16, 18, 20, 22, 100];

fn allowed_for(key: &str) -> Option<&'static [i64]> {
    match key {
        "win32" => Some(ALLOWED_WIN32),
        "keyboard" => Some(ALLOWED_KEYBOARD),
        "mouse" => Some(ALLOWED_MOUSE),
        _ => None,
    }
}

/// peripheral:open-window —— 单例子窗口（已开则聚焦）
#[tauri::command]
pub async fn peripheral_open_window<R: tauri::Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Some(existing) = app.get_webview_window(LABEL) {
        crate::focus_window(&existing);
        return Ok(json!({ "success": true, "alreadyOpen": true }));
    }
    let builder = WebviewWindowBuilder::new(&app, LABEL, WebviewUrl::App(PAGE.into()))
        .title(TITLE)
        .inner_size(860.0, 760.0)
        .min_inner_size(680.0, 560.0)
        .background_color(Color(243, 243, 243, 255))
        .center()
        .visible(false)
        .on_page_load(|win, payload| {
            if payload.event() == PageLoadEvent::Finished {
                crate::activate_window(&win);
            }
        });
    match builder.parent(&window) {
        Ok(b) => match b.build() {
            Ok(_) => Ok(json!({ "success": true })),
            Err(e) => {
                log::write_log("error", &format!("创建「外设优化」窗口失败: {e}"));
                Ok(json!({ "success": false, "message": format!("创建「外设优化」窗口失败: {e}") }))
            }
        },
        Err(e) => {
            log::write_log("error", &format!("「外设优化」窗口挂靠主窗口失败: {e}"));
            Ok(json!({ "success": false, "message": format!("「外设优化」窗口挂靠主窗口失败: {e}") }))
        }
    }
}

/// peripheral:close-window —— 关闭发起调用的窗口
#[tauri::command]
pub fn peripheral_close_window<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Err(e) = window.close() {
        log::write_log("warn", &format!("关闭「外设优化」窗口失败: {e}"));
    }
    Ok(json!({ "success": true }))
}

fn run_ps(script: &str, timeout_secs: u64) -> Option<crate::pwsh::PsOutput> {
    let path = pwsh::write_temp_script(script, ".ps1").ok()?;
    let out = pwsh::run_file(&path, std::time::Duration::from_secs(timeout_secs), None);
    let _ = std::fs::remove_file(&path);
    out.ok()
}

fn find_prefixed<'a>(stdout: &'a str, prefix: &str) -> Option<&'a str> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .find(|l| l.starts_with(prefix))
        .map(|l| &l[prefix.len()..])
}

/// peripheral:query —— 读三组当前值
#[tauri::command]
pub async fn peripheral_query<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let Some(out) = run_ps(PS_QUERY, 20) else {
        return Ok(json!({ "success": false, "message": "读取当前外设设置失败" }));
    };
    if out.code != 0 {
        return Ok(json!({
            "success": false,
            "message": if out.stderr.trim().is_empty() { "读取当前外设设置失败".to_string() } else { out.stderr.trim().to_string() }
        }));
    }
    let Some(payload) = find_prefixed(&out.stdout, "@@PERIPHERAL@@") else {
        return Ok(json!({ "success": false, "message": "读取当前外设设置失败" }));
    };
    match serde_json::from_str::<Value>(payload) {
        Ok(data) => Ok(json!({ "success": true, "data": data })),
        Err(_) => Ok(json!({ "success": false, "message": "解析外设设置失败" })),
    }
}

#[derive(serde::Deserialize, Default)]
pub struct ApplyOptions {
    win32: Option<Value>,
    keyboard: Option<Value>,
    mouse: Option<Value>,
}

/// peripheral:apply —— 白名单校验后写 HKLM（成功修剪备份）
#[tauri::command]
pub async fn peripheral_apply<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    options: Option<ApplyOptions>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if !crate::engine::sysinfo::is_admin() {
        return Ok(json!({
            "success": false, "needAdmin": true,
            "message": "外设优化需要管理员权限，请先提权"
        }));
    }
    let opts = options.unwrap_or_default();

    // null/缺省 → -1（该组不改）；显式整数必须命中白名单，否则记下非法组
    let mut filtered = serde_json::Map::new();
    let mut invalid: Vec<&str> = Vec::new();
    for (key, raw) in [
        ("win32", opts.win32),
        ("keyboard", opts.keyboard),
        ("mouse", opts.mouse),
    ] {
        match normalize_option(raw) {
            None => {
                filtered.insert(key.into(), json!(-1));
            }
            Some(v) => {
                if allowed_for(key).is_some_and(|list| list.contains(&v)) {
                    filtered.insert(key.into(), json!(v));
                } else {
                    invalid.push(key);
                }
            }
        }
    }
    if !invalid.is_empty() {
        return Ok(json!({
            "success": false,
            "message": format!("包含未获允许的取值（{}），已拒绝本次修改", invalid.join("、"))
        }));
    }
    let all_skip = filtered.values().all(|v| v.as_i64() == Some(-1));
    if all_skip {
        return Ok(json!({ "success": false, "message": "没有需要应用的设置" }));
    }

    let payload = Value::Object(filtered).to_string();
    let script = PS_APPLY.replace(APPLY_SENTINEL, &payload);
    let Some(out) = run_ps(&script, 30) else {
        return Ok(json!({ "success": false, "message": "执行异常" }));
    };
    if out.code != 0 {
        log::write_log(
            "warn",
            &format!("外设优化应用失败 exit={}: {}", out.code, out.stderr.trim()),
        );
        return Ok(json!({
            "success": false,
            "message": "写入注册表失败，可能需要管理员权限"
        }));
    }
    prune_backups(10);
    Ok(json!({ "success": true, "message": "完成" }))
}

/// null/空串 → None（跳过）；整数 → Some；非整数 → 视为非法（给 0 以落进白名单不命中）
fn normalize_option(raw: Option<Value>) -> Option<i64> {
    match raw {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::Number(n)) => n.as_i64().or(Some(-9999)),
        _ => Some(-9999),
    }
}

/// 修剪外设备份目录：backup_YYYYMMDD_HHMMSS.reg 按名倒序保留 keep 份，更旧的进回收站
fn prune_backups(keep: usize) {
    let mut dirs = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        dirs.push(std::path::PathBuf::from(appdata).join("Trim").join("peripheral-backup"));
    }
    dirs.push(paths::app_data_dir().join("peripheral-backup"));

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        let mut files: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().to_string().into())
            .filter(|name| is_backup_name(name))
            .collect();
        files.sort();
        files.reverse();
        for name in files.into_iter().skip(keep) {
            let p = dir.join(&name);
            if let Err(e) = trim_finder::scan::recycle::send_to_trash(&p.to_string_lossy()) {
                log::write_log("warn", &format!("旧外设备份移入回收站失败: {name} -> {e}"));
            }
        }
    }
}

fn is_backup_name(name: &str) -> bool {
    // backup_YYYYMMDD_HHMMSS.reg
    let b = name.as_bytes();
    // backup_YYYYMMDD_HHMMSS.reg：7+8+1+6+4 = 26
    b.len() == 26
        && name.starts_with("backup_")
        && name.ends_with(".reg")
        && b[7..15].iter().all(|c| c.is_ascii_digit())
        && b[15] == b'_'
        && b[16..22].iter().all(|c| c.is_ascii_digit())
}

/// peripheral:restore-backup —— 导入最新一份备份 .reg
#[tauri::command]
pub async fn peripheral_restore_backup<R: tauri::Runtime>(
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if !crate::engine::sysinfo::is_admin() {
        return Ok(json!({
            "success": false, "needAdmin": true,
            "message": "外设优化需要管理员权限，请先提权"
        }));
    }
    let Some(out) = run_ps(PS_RESTORE, 30) else {
        return Ok(json!({ "success": false, "message": "还原备份失败" }));
    };
    if out.code != 0 {
        return Ok(json!({ "success": false, "message": "还原备份失败（reg import 返回非零）" }));
    }
    let Some(payload) = find_prefixed(&out.stdout, "@@PERIPHERAL_RESTORE@@") else {
        return Ok(json!({ "success": false, "message": "还原备份失败：无有效结果" }));
    };
    let Ok(v) = serde_json::from_str::<Value>(payload) else {
        return Ok(json!({ "success": false, "message": "还原备份失败" }));
    };
    if v.get("ok").and_then(|x| x.as_bool()) != Some(true) {
        let reason = v.get("reason").and_then(|x| x.as_str()).unwrap_or("");
        let msg = match reason {
            "no-backup" => "还没有可用的备份（先应用一次优化后会自动备份）",
            "import-failed" => "导入备份失败，备份文件可能已损坏",
            _ => "还原备份失败",
        };
        return Ok(json!({ "success": false, "message": msg }));
    }
    Ok(json!({ "success": true, "data": { "file": v.get("file") } }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_value_tables() {
        assert!(allowed_for("win32").unwrap().contains(&38));
        assert!(allowed_for("keyboard").unwrap().contains(&100));
        assert!(allowed_for("mouse").unwrap().contains(&16));
        // PE-3：白名单外取值不允许
        assert!(!allowed_for("win32").unwrap().contains(&99));
        assert!(allowed_for("unknown").is_none());
    }

    #[test]
    fn normalize_option_skips_and_rejects() {
        assert_eq!(normalize_option(None), None);
        assert_eq!(normalize_option(Some(Value::Null)), None);
        assert_eq!(normalize_option(Some(json!(""))), None);
        assert_eq!(normalize_option(Some(json!(38))), Some(38));
        // 非整数给哨兵值，白名单必不命中
        assert_eq!(normalize_option(Some(json!(1.5))), Some(-9999));
        assert_eq!(normalize_option(Some(json!("x"))), Some(-9999));
    }

    #[test]
    fn backup_filename_shape() {
        assert!(is_backup_name("backup_20260924_123000.reg"));
        assert!(!is_backup_name("backup_2026924_123000.reg")); // 年份 7 位
        assert!(!is_backup_name("backup_20260924_12300.reg")); // 秒 5 位
        assert!(!is_backup_name("evil.reg"));
    }
}
