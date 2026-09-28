//! log 域（批次 A）：log:write / log:read / log:export

use tauri::{AppHandle, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::engine::{guard, log};

/// 渲染层可控日志的清洗参数。level 白名单见 `sanitize_log_level` 的 match——
/// 那里是唯一真源，不再另立一份常量清单（两份必然漂移，且这份没人读）。
const LOG_MESSAGE_MAX: usize = 1000;

/// level 白名单：不在表里的一律按 `info` 记。
///
/// 为什么不报错：日志不该成为一个功能的失败点（渲染层上报异常时再抛错就是双重失败）；
/// 但也不能照抄——`write_log` 会把 level 大写后拼进 `[LEVEL]` 位，任意字符串等于让
/// 渲染层自造日志级别，日志页的级别筛选与人工排障都会被骗。
fn sanitize_log_level(level: &str) -> &'static str {
    let l = level.trim().to_ascii_lowercase();
    match l.as_str() {
        "warn" => "warn",
        "error" => "error",
        "info" => "info",
        _ => "info",
    }
}

/// 消息清洗：控制符（含换行）换成空格 + 折叠连续空白 + 截断。
///
/// 真正的洞在这里：`write_log` 把 message 原样插进 `[时间] [级别] 消息\n` 一行里，
/// 所以一条带 `\n` 的渲染层消息可以**伪造整行日志**——包括再编一个 `[ERROR]` 前缀，
/// 甚至把后面的真实内容挤到自己编的"行"里。日志是排障与审计的最后一层，
/// 它的行边界不能由被记录的一方决定。
fn sanitize_log_message(message: &str, limit: usize) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for ch in message.chars() {
        let is_space = ch.is_whitespace();
        if is_space {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(ch);
            prev_space = false;
        }
        if out.chars().count() >= limit {
            out.push_str("…（已截断）");
            break;
        }
    }
    out.trim().to_string()
}

/// log:write — 渲染层日志入口（五个窗都可调）。
///
/// 入参全部按不可信处理：清洗见 `sanitize_log_*`，并带上窗口 label —— 否则
/// 主窗与四个子窗的日志混在一起分不清是谁报的（子窗没有 logger.js，直连本通道）。
#[tauri::command]
pub fn log_write<R: tauri::Runtime>(window: WebviewWindow<R>, level: String, message: String) -> Result<String, String> {
    guard::guard_readonly(&window)?;
    let lvl = sanitize_log_level(&level);
    let msg = sanitize_log_message(&message, LOG_MESSAGE_MAX);
    Ok(log::write_log(lvl, &format!("[{}] {msg}", window.label())))
}

#[cfg(test)]
mod log_ipc_sanitizer_tests {
    use super::*;

    #[test]
    fn level_is_whitelisted_not_passed_through() {
        assert_eq!(sanitize_log_level("error"), "error");
        assert_eq!(sanitize_log_level(" WARN "), "warn");
        assert_eq!(sanitize_log_level("Info"), "info");
        // 任意字符串不得原样进 [LEVEL] 位
        assert_eq!(sanitize_log_level("CRITICAL] [2099-01-01"), "info");
        assert_eq!(sanitize_log_level(""), "info");
    }

    #[test]
    fn message_cannot_forge_extra_log_lines() {
        let evil = "真消息\n[2099-01-01 00:00:00] [ERROR] 伪造的一行\n[2099-01-01 00:00:01] [ERROR] 还有一行";
        let got = sanitize_log_message(evil, LOG_MESSAGE_MAX);
        assert!(!got.contains('\n'), "换行必须被吃掉，实测 {got:?}");
        assert_eq!(got.matches("[ERROR]").count(), 2, "内容里的字样保留，但不能因此多出行：{got:?}");
        // 行边界由 write_log 决定：整条消息只能占一行
        let line = log::write_log("error", &format!("[main] {got}"));
        assert_eq!(line.trim_end_matches('\n').matches('\n').count(), 0, "日志行内不得再有换行: {line:?}");
        assert!(line.starts_with('[') && line.ends_with('\n'), "格式仍是单行: {line:?}");
    }

    #[test]
    fn long_message_is_capped_and_whitespace_collapsed() {
        let big = "x".repeat(LOG_MESSAGE_MAX + 500);
        let got = sanitize_log_message(&big, LOG_MESSAGE_MAX);
        assert!(got.chars().count() <= LOG_MESSAGE_MAX + "…（已截断）".chars().count());
        assert!(got.ends_with("…（已截断）"), "截断要留下痕迹: {}", got.chars().rev().take(20).collect::<String>());
        assert_eq!(sanitize_log_message("  a\t\rb   c  ", 100), "a b c");
    }
}

/// log:read — 默认当天；日期格式白名单防路径穿越；只取末尾 512KB 并丢弃半行
#[tauri::command]
pub fn log_read<R: tauri::Runtime>(window: WebviewWindow<R>, date: Option<String>) -> Result<String, String> {
    guard::guard_readonly(&window)?;
    Ok(log::read_log(date.as_deref()))
}

/// log:export — 原生保存对话框选目标文件后复制当天日志
#[tauri::command]
pub async fn log_export<R: tauri::Runtime>(app: AppHandle<R>, window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let file = app
        .dialog()
        .file()
        .set_title("导出日志")
        .set_file_name(format!("Trim-log-{}.txt", crate::engine::now_ms()))
        .add_filter("文本文件", &["txt", "log"])
        .blocking_save_file();
    let Some(path) = file else {
        return Ok(serde_json::json!({ "success": false, "message": "已取消" }));
    };
    let dest = path
        .into_path()
        .map_err(|e| format!("无效的保存路径: {e}"))?;
    match log::export_log(&dest) {
        Ok(()) => Ok(serde_json::json!({
            "success": true,
            "path": dest.to_string_lossy(),
        })),
        Err(e) => Ok(serde_json::json!({ "success": false, "message": e })),
    }
}