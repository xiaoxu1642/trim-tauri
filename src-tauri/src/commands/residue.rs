//! residue 域（v0.5.0 建窗，v0.7.0 起成为残留扫描的**唯一**界面）：副窗开/关两个通道。
//!
//! v0.7.0 用户拍板：主窗那段内联残留面板（三链扫描 + 勾选 + 删除）整块搬进这扇副窗，
//! 卸载成功后弹的也是它 —— 同一件事不该有两个入口，两个入口迟早长得不一样。
//! 因此本轮同时把 8 条残留链命令的档位从 `MAIN` 换成窄窗口集 `guard::RESIDUE_WINDOWS`
//! （= 只有 `residue`），并同步 `check-guard-tiers` 的 E 组与 `check-channel-map` 的 D5。
//!
//! `app_id` 走 URL query 传给副窗，**传之前先过执行侧同一对取值闸**
//! （`valid_uninstall_key_path` / `valid_appx_fullname`，与 `uninstall_residue_scan` 里用的
//! 是同一份判据，§5.16/N6 不许写第二套）：非法形状一律不带进 URL，副窗那边按「未选中程序」
//! 处理。副窗读回来后仍会再判一次 —— 开窗口的校验不豁免执行链的校验。
//!
//! 窗口参数照抄现有子窗的统一模板（models / peripheral / processManager / preview）：
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
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::commands::uninstall::{valid_appx_fullname, valid_uninstall_key_path};
use crate::engine::{guard, log};

/// 子窗口 label（与 guard::APP_WINDOWS、capabilities 里的名字必须逐字一致）
pub const LABEL: &str = "residue";
/// 页面与标题
const PAGE: &str = "residue-window.html";
const TITLE: &str = "应用卸载残留扫描";

/// 把 app_id 编码成 URL query（`?app=…`）；不可编码集合之外的字节一律 `%XX`。
///
/// 保留字集 = RFC 3986 unreserved（A-Z a-z 0-9 - . _ ~）。注册表键里的 `\`、空格、
/// 中文全部走百分号编码，副窗侧 `URLSearchParams` 解码即还原。
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(*b as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// 校验并回带合法形状的 app_id；不过闸返回 None。
fn validated_app_id(app_id: Option<&str>) -> Option<String> {
    let raw = app_id.map(str::trim).filter(|s| !s.is_empty())?;
    let (hive, rest) = raw.split_once('|')?;
    let ok = if hive.eq_ignore_ascii_case("APPX") {
        valid_appx_fullname(rest)
    } else {
        (hive.eq_ignore_ascii_case("HKCU") || hive.eq_ignore_ascii_case("HKLM")) && valid_uninstall_key_path(rest)
    };
    ok.then(|| raw.to_string())
}

/// 计算带目标的页面 query。**判据与 `uninstall_residue_scan` 用的是同一对函数**
/// （§5.16/N6）：形状不过闸 ⇒ 返回 None，宁可不带目标，也不把未校验的串拼进 webview URL。
///
/// 只接受两种形状：`HKCU|<卸载键路径>` / `HKLM|<卸载键路径>` / `APPX|<包全名>`。
fn residue_page_for(app_id: Option<&str>) -> Option<String> {
    validated_app_id(app_id).map(|raw| format!("?app={}", pct_encode(&raw)))
}

/// residue:open-window —— 打开「应用卸载残留扫描」独立窗口（单例，已开则聚焦）
///
/// 档位是 MAIN 而不是其它子窗同事的 readonly：`check-channel-map` 的 D5 判据是
/// 「放宽到只读档 ⇒ 必须真有子窗调用点」，而开窗这个动作只有主窗的入口按钮会调，
/// 副窗自己不调（副窗只调 close）。按档位以「谁真的需要调它」为准，这里收 MAIN。
///
/// `app_id`：卸载成功后带进来的目标（形如 `HKLM|Software\...\Uninstall\<key>` 或
/// `APPX|<PFN>`）。**先过执行侧那对取值闸**再进 URL —— 把未校验的串塞进 webview URL
/// 等于让渲染层拿到一个可由外部影响的参数去二次拼接；闸门拒掉的直接当没带。
#[tauri::command]
pub async fn residue_open_window<R: tauri::Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    app_id: Option<String>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let page = match residue_page_for(app_id.as_deref()) {
        Some(qs) => format!("{PAGE}{qs}"),
        None => PAGE.to_string(),
    };
    if let Some(existing) = app.get_webview_window(LABEL) {
        crate::focus_window(&existing);
        // 副窗是单例：URL 不会变，所以新目标靠事件递进去（能力面已给 core:event:allow-listen）
        if let Some(id) = validated_app_id(app_id.as_deref()) {
            let _ = existing.emit("residue:target", id);
        }
        return Ok(json!({ "success": true, "alreadyOpen": true }));
    }
    let builder = WebviewWindowBuilder::new(&app, LABEL, WebviewUrl::App(page.into()))
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

#[cfg(test)]
mod tests {
    use super::*;

    const OK_HKLM: &str = r"HKLM|Software\Microsoft\Windows\CurrentVersion\Uninstall\Trim.Test";

    #[test]
    fn page_for_accepts_the_two_shipped_shapes_and_encodes_reserved_bytes() {
        let qs = residue_page_for(Some(OK_HKLM)).expect("合法 HKLM 卸载键必须过闸");
        assert!(qs.starts_with("?app="), "查询串前缀错了: {qs}");
        // `|` 与 `\` 在 URL 里是分字节语义的字符，必须被编码掉，
        // 否则副窗用 URLSearchParams 解出来的 app_id 会在第一个特殊字符处变形
        assert!(qs.contains("%7C") && qs.contains("%5C"), "保留字节没编码: {qs}");
        assert!(!qs.contains('\\') && !qs.contains('|'), "编码后不该再出现裸 \\ 或 |: {qs}");
        let appx = residue_page_for(Some("APPX|Trim.Test_1.0.0.0_x64__8wekyb3d8bbwe"));
        assert!(appx.is_some(), "合法包全名必须过闸: {appx:?}");
    }

    /// 负向集：形状不过闸的一律**不带进 URL**。断言点名被接受的那几条（`reached`），
    /// 并配正向对照 —— 只断「没有成功」会被「判定器整体坏成恒 None」顶绿（§4.1 纪律①）。
    #[test]
    fn page_for_rejects_every_unvalidated_shape() {
        let bad = [
            "",
            "   ",
            "没有分隔符",
            r"HKCR|Software\Microsoft\Windows\CurrentVersion\Uninstall\X",
            r"HKCU|Software\Microsoft\Windows\CurrentVersion\Uninstall\..\X",
            r"HKCU|Software\Microsoft\Windows\CurrentVersion\Uninstall\%ENV%",
            r"HKCU|Software\Classes\xxx",
            "APPX|",
            "APPX|evil\"; Remove-Item C:\\",
            "APPX|中文包名",
        ];
        let reached: Vec<&str> = bad
            .iter()
            .filter(|s| residue_page_for(Some(s)).is_some())
            .copied()
            .collect();
        assert!(reached.is_empty(), "这些形状本该被拒，却被接受了: {reached:?}");
        assert!(residue_page_for(Some(OK_HKLM)).is_some(), "正向对照没命中，判定器可能整体失效");
        assert!(residue_page_for(None).is_none(), "None 必须当没带目标");
    }

    #[test]
    fn pct_encode_keeps_unreserved_and_escapes_the_rest() {
        assert_eq!(pct_encode("aZ09-._~"), "aZ09-._~");
        assert_eq!(pct_encode("a b\\c|d"), "a%20b%5Cc%7Cd");
        // 非 ASCII 走 UTF-8 字节级编码，副窗 URLSearchParams 解回来必须等价
        assert_eq!(pct_encode("中"), "%E4%B8%AD");
    }
}
