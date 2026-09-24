//! preview 窗口域（B 批）：preview:open-window / close-window
//! ＋ send 通道 preview:image-deleted
//!
//! 对照 main.js 6764-6817：
//! - **单例窗口**：已存在则聚焦，并把 payload **再发一次** `preview:data`；
//! - 900×700、最小内容区 600×480、`parent: main`、`modal: false`、标题「图片预览」、
//!   **背景纯黑**（看图对比场景刻意不加载 window-material.js）；
//! - 先隐藏、页面加载完成后 `show()`，并立刻经 `preview:data` 把 payload 发给该窗口
//!   （对齐 Electron 的 `did-finish-load` → `webContents.send`）；
//! - `preview:image-deleted`（send）：把**文件路径字符串**转给主窗口同名事件
//!   （cleanup.js 用 `f.path === filePath` 比对，必须是字符串而非对象）。
//!
//! 窗口 label 固定 `"preview"`（见 `LABEL`）。
//!
//! 需要加入 lib.rs `generate_handler!` 的完整行：
//!   commands::preview::preview_open_window,
//!   commands::preview::preview_close_window,
//!   commands::preview::preview_image_deleted,

use serde_json::{json, Value};
use tauri::webview::PageLoadEvent;
use tauri::window::Color;
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::engine::{guard, log};

/// 子窗口 label（与 Electron 的窗口角色同名，便于前端按 label 分支）
pub const LABEL: &str = "preview";
/// 主窗口 label
const MAIN_LABEL: &str = "main";
/// 页面与标题
const PAGE: &str = "preview-window.html";
const TITLE: &str = "图片预览";
/// 事件名
const EVENT_DATA: &str = "preview:data";
const EVENT_DELETED: &str = "preview:image-deleted";

/// preview:open-window — 打开「图片预览」独立窗口（单例）
///
/// payload: `{ images: [{ path, name, size }], index, itemName }`（由主窗口 cleanup.js 组装）
#[tauri::command]
pub async fn preview_open_window<R: tauri::Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: Option<Value>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let payload = payload.unwrap_or(Value::Null);
    if let Some(existing) = app.get_webview_window(LABEL) {
        crate::focus_window(&existing);
        let _ = existing.emit(EVENT_DATA, payload);
        return Ok(json!({ "success": true, "alreadyOpen": true }));
    }
    // on_page_load 的闭包是 Fn（可能多次触发），故 clone 一份载荷
    let data = payload;
    let builder = WebviewWindowBuilder::new(&app, LABEL, WebviewUrl::App(PAGE.into()))
        .title(TITLE)
        .inner_size(900.0, 700.0)
        .min_inner_size(600.0, 480.0)
        // 纯黑底（Electron backgroundColor: '#000000'），图片加载前不出现白闪
        .background_color(Color(0, 0, 0, 255))
        .center()
        // 先隐藏，等首帧渲染完成再显示（ready-to-show 等价物）
        .visible(false)
        .on_page_load(move |window, payload| {
            if payload.event() == PageLoadEvent::Finished {
                // 开发期不抢前台（见 lib.rs::activate_window）：调试期弹窗不打扰用户
                crate::activate_window(&window);
                // did-finish-load → preview:data
                let _ = window.emit(EVENT_DATA, data.clone());
            }
        });
    match builder.parent(&window) {
        Ok(builder) => match builder.build() {
            Ok(_) => Ok(json!({ "success": true })),
            Err(e) => {
                log::write_log("error", &format!("创建「图片预览」窗口失败: {e}"));
                Ok(json!({
                    "success": false,
                    "message": format!("创建「图片预览」窗口失败: {e}")
                }))
            }
        },
        Err(e) => {
            log::write_log("error", &format!("「图片预览」窗口挂靠主窗口失败: {e}"));
            Ok(json!({
                "success": false,
                "message": format!("「图片预览」窗口挂靠主窗口失败: {e}")
            }))
        }
    }
}

/// preview:close-window — 关闭发起调用的窗口本身（Esc / 全部删除后）
#[tauri::command]
pub fn preview_close_window<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Err(e) = window.close() {
        log::write_log("warn", &format!("关闭「图片预览」窗口失败: {e}"));
    }
    Ok(json!({ "success": true }))
}

/// preview:image-deleted（send）— 预览窗删图后通知主窗口刷新文件列表
///
/// 适配层整形后载荷为 `{ path: <filePath> }`；Electron 主进程转发的是**裸字符串**，
/// 故此处剥出 `path` 再发（主窗口侧 `f.path === filePath` 依赖字符串类型）。
#[tauri::command]
pub fn preview_image_deleted<R: tauri::Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    path: Option<Value>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let file_path = path.unwrap_or(Value::Null);
    if let Some(main) = app.get_webview_window(MAIN_LABEL) {
        let _ = main.emit(EVENT_DELETED, file_path);
    }
    Ok(json!({ "success": true }))
}