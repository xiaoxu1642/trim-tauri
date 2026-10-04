//! residue 域（v0.5.0）：残留扫描副窗口的开/关两个通道。
//!
//! 方案 §1 裁决 4：残留扫描与清理全部挪到新弹出的自绘窗口，主窗只留入口与导航。
//! v0.5.0 这一版副窗里**只有只读报告**（`uninstall:residue-deep-scan`），没有删除按钮，
//! 所以这里只建窗，不代理任何执行动作；第二阶段接删除链时再按 §4 的要求改档位并双向登记。
//!
//! 窗口参数照抄现有四个子窗的统一模板（models / peripheral / processManager / preview）：
//! - 建窗点必须过 `crate::with_browser_args`（K4：不透传浏览器参数时同一 WebView2
//!   user-data-folder 下第二个 core 建不出来，`build()` 照样返回 Ok 而 `hwnd=0x0`）；
//! - `visible(false)` + `on_page_load(Finished)` 才 activate（黑闪握手）；
//! - `parent(&window)` 挂主窗，label 固定 `"residue"`，
//!   必须同步在 `engine::guard::APP_WINDOWS` 与 `capabilities/subwindows.json` 登记，
//!   否则 `guard_readonly` 会把这个窗口的每一次调用都判成越权。
//!
//! 需要加入 lib.rs `generate_handler!` 的完整行：
//!   commands::residue::residue_open_window,
//!   commands::residue::residue_close_window,

use serde_json::{Value, json};
use tauri::webview::PageLoadEvent;
use tauri::window::Color;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::engine::{guard, log};

/// 子窗口 label（与 guard::APP_WINDOWS、capabilities 里的名字必须逐字一致）
pub const LABEL: &str = "residue";
/// 页面与标题
const PAGE: &str = "residue-window.html";
const TITLE: &str = "应用卸载残留扫描";

/// residue:open-window —— 打开「应用卸载残留扫描」独立窗口（单例，已开则聚焦）
///
/// 档位是 MAIN 而不是另外四个子窗同事的 readonly：`check-channel-map` 的 D5 判据是
/// 「放宽到只读档 ⇒ 必须真有子窗调用点」，而开窗这个动作只有主窗的入口按钮会调，
/// 副窗自己不调（副窗只调 close）。按档位以「谁真的需要调它」为准，这里收 MAIN。
#[tauri::command]
pub async fn residue_open_window<R: tauri::Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if let Some(existing) = app.get_webview_window(LABEL) {
        crate::focus_window(&existing);
        return Ok(json!({ "success": true, "alreadyOpen": true }));
    }
    let builder = WebviewWindowBuilder::new(&app, LABEL, WebviewUrl::App(PAGE.into()))
        .title(TITLE)
        // 1040×760：这轮报告是七个分组 × 长路径 + 证据行，比另外四个子窗宽一档才放得下
        // 一行完整注册表目标而不折成三行（窄窗会把「判定依据」挤到看不完）
        .inner_size(1040.0, 760.0)
        .min_inner_size(760.0, 520.0)
        .background_color(Color(243, 243, 243, 255))
        .center()
        .visible(false)
        .on_page_load(|win, payload| {
            if payload.event() == PageLoadEvent::Finished {
                // 开发期不抢前台（见 lib.rs::activate_window）
                crate::activate_window(&win);
            }
        });
    let builder = crate::with_browser_args(builder);
    match builder.parent(&window) {
        Ok(b) => match b.build() {
            Ok(_) => Ok(json!({ "success": true })),
            Err(e) => {
                log::write_log("error", &format!("创建「应用卸载残留扫描」窗口失败: {e}"));
                Ok(json!({ "success": false, "message": format!("创建「应用卸载残留扫描」窗口失败: {e}") }))
            }
        },
        Err(e) => {
            log::write_log("error", &format!("「应用卸载残留扫描」窗口挂靠主窗口失败: {e}"));
            Ok(json!({ "success": false, "message": format!("「应用卸载残留扫描」窗口挂靠主窗口失败: {e}") }))
        }
    }
}

/// residue:close-window —— 关闭发起调用的窗口本身
///
/// 关窗**不**打断后端任务（方案 §4）：扫描跑在 spawn_blocking 里，结果只落在
/// 这一轮的前端内存中，下一次开副窗重新扫。
#[tauri::command]
pub fn residue_close_window<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Err(e) = window.close() {
        log::write_log("warn", &format!("关闭「应用卸载残留扫描」窗口失败: {e}"));
    }
    Ok(json!({ "success": true }))
}
