//! log 域（批次 A）：log:write / log:read / log:export

use tauri::{AppHandle, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::engine::{guard, log};

/// 渲染层可控日志的长度上限（IPC 边界策略，不是行完整性判据）。
/// 清洗与 level 白名单的实现**只在 `engine::log` 那一份**（理由见 `log_write` 上方说明）：
/// 本文件曾各留一份私有实现且与真源不同义，§5.16/N6 明令禁止这种「两份恰好都不致命」。
const LOG_MESSAGE_MAX: usize = 1000;

/// log:write — 渲染层日志入口（五个窗都可调）。
///
/// 入参全部按不可信处理并带上窗口 label —— 否则主窗与四个子窗的日志混在一起分不清是谁
/// 报的（子窗没有 logger.js，直连本通道）。
/// 清洗**直调 `engine::log` 的单一真源**：本文件曾各留一份私有 `sanitize_log_level` /
/// `sanitize_log_message`，与真源不同义（只折 `is_whitespace` ⇒ NUL 等控制符原样进日志行；
/// 截断标记非幂等 ⇒ 两层各套一次上限会追加两个「…（已截断）」），今天靠 `write_log`
/// 二次清洗兜住，但那是「两份实现恰好都不致命」，不是合规格（AGENTS §5.16 / N6）。
#[tauri::command]
pub fn log_write<R: tauri::Runtime>(window: WebviewWindow<R>, level: String, message: String) -> Result<String, String> {
    guard::guard_readonly(&window)?;
    let lvl = log::sanitize_log_level(&level);
    let msg = log::sanitize_log_message(&message, LOG_MESSAGE_MAX);
    Ok(log::write_log(lvl, &format!("[{}] {msg}", window.label())))
}

#[cfg(test)]
mod log_ipc_sanitizer_tests {
    use super::*;

    #[test]
    fn level_is_whitelisted_not_passed_through() {
        assert_eq!(log::sanitize_log_level("error"), "error");
        assert_eq!(log::sanitize_log_level(" WARN "), "warn");
        assert_eq!(log::sanitize_log_level("Info"), "info");
        // 任意字符串不得原样进 [LEVEL] 位
        assert_eq!(log::sanitize_log_level("CRITICAL] [2099-01-01"), "info");
        assert_eq!(log::sanitize_log_level(""), "info");
    }

    /// 判据不许有第二份实现（AGENTS §5.16 / N6）：本文件曾各留一份私有清洗，
    /// 与 `engine::log` 的真源不同义——只折 `is_whitespace` ⇒ NUL/C0 控制符原样进日志行，
    /// 截断标记非幂等 ⇒ 命令层与 write_log 各套一次上限会追加两个「…（已截断）」。
    ///  needle 用拼接构造：本文件的注释与断言文案也算语料，写成字面量会被自己抓到（假红）。
    #[test]
    fn 命令层不得再起私有清洗实现() {
        let src = include_str!("log.rs");
        // 只认真正顶格起函数定义的形状（带前导换行），注释里复述这个名字不算语料
        let needle = ["\nfn ", "sanitize_log_"].concat();
        assert!(
            !src.contains(&needle),
            "commands/log.rs 里又出现了私有的清洗实现定义，真源在 engine/log.rs"
        );
        assert!(src.contains("log::sanitize_log_message("), "消息清洗必须直调引擎真源");
        assert!(src.contains("log::sanitize_log_level("), "level 白名单必须直调引擎真源");
    }

    #[test]
    fn message_cannot_forge_extra_log_lines() {
        let evil = "真消息\n[2099-01-01 00:00:00] [ERROR] 伪造的一行\n[2099-01-01 00:00:01] [ERROR] 还有一行";
        let got = log::sanitize_log_message(evil, LOG_MESSAGE_MAX);
        assert!(!got.contains('\n'), "换行必须被吃掉，实测 {got:?}");
        assert_eq!(got.matches("[ERROR]").count(), 2, "内容里的字样保留，但不能因此多出行：{got:?}");
        // 行边界由 write_log 决定：整条消息只能占一行
        let line = log::write_log("error", &format!("[main] {got}"));
        assert_eq!(line.trim_end_matches('\n').matches('\n').count(), 0, "日志行内不得再有换行: {line:?}");
        assert!(line.starts_with('[') && line.ends_with('\n'), "格式仍是单行: {line:?}");
    }

    /// 真源与旧私有实现的**分歧点**：NUL/C0 控制符与幂等性。旧形态把这两样留在日志行里，
    /// 本用例把它们钉成真源行为（把 `engine::log::sanitize_log_message` 改回只折
    /// `is_whitespace` ⇒ 第一条红；去掉截断标记的 ends_with 判据 ⇒ 第二条红）。
    #[test]
    fn 控制符不入行且截断幂等() {
        let nul = log::sanitize_log_message("a\u{0}b\u{1c}c", usize::MAX);
        assert!(!nul.chars().any(|c| c.is_control()), "NUL/C0 必须换成空格: {nul:?}");
        assert_eq!(nul, "a b c");
        let once = log::sanitize_log_message(&"y".repeat(2000), 64);
        let twice = log::sanitize_log_message(&once, 64);
        assert_eq!(once, twice, "两层各套一次上限不得追加第二个截断标记: {twice:?}");
        assert_eq!(once.matches("…（已截断）").count(), 1, "截断痕迹只能有一个");
    }

    #[test]
    fn long_message_is_capped_and_whitespace_collapsed() {
        let big = "x".repeat(LOG_MESSAGE_MAX + 500);
        let got = log::sanitize_log_message(&big, LOG_MESSAGE_MAX);
        assert!(got.chars().count() <= LOG_MESSAGE_MAX + "…（已截断）".chars().count());
        assert!(got.ends_with("…（已截断）"), "截断要留下痕迹: {}", got.chars().rev().take(20).collect::<String>());
        assert_eq!(log::sanitize_log_message("  a\t\rb   c  ", 100), "a b c");
    }
}

/// log:read — 默认当天；日期格式白名单防路径穿越；只取末尾 512KB 并丢弃半行
#[tauri::command]
pub fn log_read<R: tauri::Runtime>(window: WebviewWindow<R>, date: Option<String>) -> Result<String, String> {
    guard::guard(&window, guard::MAIN)?;
    Ok(log::read_log(date.as_deref()))
}

/// log:export — 原生保存对话框选目标文件后复制当天日志
#[tauri::command]
pub async fn log_export<R: tauri::Runtime>(app: AppHandle<R>, window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard(&window, guard::MAIN)?;
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