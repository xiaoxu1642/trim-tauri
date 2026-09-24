//! processManager 窗口域（B 批）：processManager:open-window / close-window
//! ＋ send 通道 processManager:report
//!
//! 对照 main.js 6662-6715：
//! - **单例窗口**：已存在则只聚焦并返回 `{ success:true, alreadyOpen:true }`；
//! - 760×680、最小内容区 640×480、`parent: main`、`modal: false`、标题「应用进程管理」；
//! - **先隐藏、等页面加载完成再 show**（对齐 Electron 的 ready-to-show，避免打开瞬间黑/白闪一帧）；
//! - `processManager:report`（send，fire-and-forget）：把 `totalCount`（非整数则 null）与
//!   `updatedAt: Date.now()` 作为 `processManager:update` 事件推给**主窗口**，
//!   供内存清理页进程卡片回显。
//!
//! 窗口 label 固定 `"processManager"`（见 `LABEL`）。
//!
//! 需要加入 lib.rs `generate_handler!` 的完整行：
//!   commands::processmanager::process_manager_open_window,
//!   commands::processmanager::process_manager_close_window,
//!   commands::processmanager::process_manager_report,

use serde_json::{json, Value};
use tauri::webview::PageLoadEvent;
use tauri::window::Color;
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::engine::{guard, log};

/// 子窗口 label（与 Electron 的窗口角色同名，便于前端按 label 分支）
pub const LABEL: &str = "processManager";
/// 主窗口 label
const MAIN_LABEL: &str = "main";
/// 页面与标题
const PAGE: &str = "process-manager-window.html";
const TITLE: &str = "应用进程管理";
/// 事件名（主窗口 processManager.onUpdate 监听）
const EVENT_UPDATE: &str = "processManager:update";

/// `Date.now()` 口径的时间戳
fn now_ms() -> i64 {
    crate::engine::now_ms()
}

/// `Number.isInteger(v) ? v : null`
fn is_integer_value(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// processManager:open-window — 打开「应用进程管理」独立窗口（单例）
#[tauri::command]
pub async fn process_manager_open_window<R: tauri::Runtime>(
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
        .inner_size(760.0, 680.0)
        .min_inner_size(640.0, 480.0)
        // 与主窗同源的浅色底（Electron backgroundColor: '#f3f3f3'）
        .background_color(Color(243, 243, 243, 255))
        .center()
        // 先隐藏，等首帧渲染完成再显示（ready-to-show 等价物）
        .visible(false)
        .on_page_load(|window, payload| {
            if payload.event() == PageLoadEvent::Finished {
                // 开发期不抢前台（见 lib.rs::activate_window）
                crate::activate_window(&window);
            }
        });
    match builder.parent(&window) {
        Ok(builder) => match builder.build() {
            Ok(_) => Ok(json!({ "success": true })),
            Err(e) => {
                log::write_log("error", &format!("创建「应用进程管理」窗口失败: {e}"));
                Ok(json!({
                    "success": false,
                    "message": format!("创建「应用进程管理」窗口失败: {e}")
                }))
            }
        },
        Err(e) => {
            log::write_log("error", &format!("「应用进程管理」窗口挂靠主窗口失败: {e}"));
            Ok(json!({
                "success": false,
                "message": format!("「应用进程管理」窗口挂靠主窗口失败: {e}")
            }))
        }
    }
}

/// processManager:close-window — 窗口内「完成」按钮：关闭发起调用的窗口本身
#[tauri::command]
pub fn process_manager_close_window<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Err(e) = window.close() {
        log::write_log("warn", &format!("关闭「应用进程管理」窗口失败: {e}"));
    }
    Ok(json!({ "success": true }))
}

/// processManager:report（send）— 把最新统计转发给主窗口的同名事件
#[tauri::command]
pub fn process_manager_report<R: tauri::Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    total_count: Option<Value>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let payload = json!({
        "totalCount": total_count.as_ref().and_then(is_integer_value),
        "updatedAt": now_ms(),
    });
    if let Some(main) = app.get_webview_window(MAIN_LABEL) {
        let _ = main.emit(EVENT_UPDATE, payload);
    }
    Ok(json!({ "success": true }))
}