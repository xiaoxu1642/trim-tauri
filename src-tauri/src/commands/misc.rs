//! 小体量批次 A 域：diag / modal / window / shutdown / intro
//!
//! diag:dwm-conflict 的检测语义对照 main.js 4194-4204：
//! - 先 tasklist 查 DWMBlurGlass.exe 进程；
//! - 再 schtasks 查 DWMBlurGlass_Extend 计划任务；
//! - 完全启动 12s 后跑一次，**只提示不干预**（命中时设置页「系统信息」出现兼容性提示行）。

use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, WebviewWindow};

use crate::engine::{guard, log, paths};
// 审查 v2-F7：系统工具走绝对路径，不用裸进程名
use crate::engine::systembin::system_tool;
use crate::security;

/// DWM 注入工具检测结论（冷启动 12s 后回填）
static DWM_TOOL_HINT: Mutex<Option<String>> = Mutex::new(None);

/// 内置简介库（离线，随应用分发，不联网、不上传任何本机信息）
const ITEM_INTRO_JSON: &str = include_str!("../../data/item-intro.json");

/// diag:dwm-conflict — 第三方窗口美化工具痕迹（只读）
#[tauri::command]
pub fn diag_dwm_conflict<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let hint = DWM_TOOL_HINT.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(serde_json::json!({
        "detected": hint.is_some(),
        "kind": hint,
    }))
}

/// 启动 12s 后一次性检测（由 lib.rs setup 触发）
pub fn detect_dwm_inject_tools_async<R: tauri::Runtime>(app: AppHandle<R>) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(12));
        match detect_dwm_inject_tools() {
            Some(kind) => {
                log::write_log(
                    "warn",
                    &format!(
                        "检测到第三方窗口美化工具痕迹（{kind}）：旧版本可能导致 Chromium 系应用缩略图缺失甚至崩溃，建议将其更新到最新版本"
                    ),
                );
                *DWM_TOOL_HINT.lock().unwrap_or_else(|e| e.into_inner()) = Some(kind);
            }
            None => {}
        }
        drop(app);
    });
}

fn detect_dwm_inject_tools() -> Option<String> {
    // 进程痕迹：tasklist /FI "IMAGENAME eq DWMBlurGlass.exe" /FO CSV
    if let Ok(out) = std::process::Command::new(system_tool("tasklist"))
        .args(["/FI", "IMAGENAME eq DWMBlurGlass.exe", "/FO", "CSV"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
        if text.contains("dwmblurglass.exe") {
            return Some("dwm-blur-tool".into());
        }
    }
    // 计划任务痕迹：schtasks /Query /TN DWMBlurGlass_Extend
    if let Ok(status) = std::process::Command::new(system_tool("schtasks"))
        .args(["/Query", "/TN", "DWMBlurGlass_Extend"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        if status.success() {
            return Some("dwm-blur-task".into());
        }
    }
    None
}

/// modal:open — 统一弹窗通道：仅记录日志（DOM 由渲染层 modal.js 统一构建）
#[tauri::command]
pub fn modal_open<R: tauri::Runtime>(window: WebviewWindow<R>, info: Option<serde_json::Value>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    log::write_log("info", &format!("打开弹窗: {}", modal_id(info.as_ref())));
    Ok(serde_json::json!({ "success": true }))
}

/// modal:close — 同上，关闭侧记录
#[tauri::command]
pub fn modal_close<R: tauri::Runtime>(window: WebviewWindow<R>, info: Option<serde_json::Value>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    log::write_log("info", &format!("关闭弹窗: {}", modal_id(info.as_ref())));
    Ok(serde_json::json!({ "success": true }))
}

/// 弹窗 id 取 info.id → info.title → 'modal'，截断 40 字符（对齐 JS 侧）
fn modal_id(info: Option<&serde_json::Value>) -> String {
    let raw = info
        .and_then(|v| v.get("id").or_else(|| v.get("title")))
        .and_then(|v| v.as_str())
        .unwrap_or("modal");
    raw.chars().take(40).collect()
}

/// window:update-overlay — Tauri 无原生 titleBarOverlay；
/// 按钮配色改由自绘 caption 的 CSS 主题负责，此通道保留为 no-op 以满足契约。
#[tauri::command]
pub fn window_update_overlay<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<bool, String> {
    guard::guard_readonly(&window)?;
    Ok(true)
}

/// shutdown:begin — 预留扩展点（Electron 版同为未接线的空实现，勿当冗余删除）
#[tauri::command]
pub fn shutdown_begin<R: tauri::Runtime>(window: WebviewWindow<R>) {
    let _ = guard::guard_readonly(&window);
}

/// shutdown:complete — 渲染层宣告收尾完成，执行最终退出。
/// Phase 1 语义：走统一退出钩子（RunEvent::Exit → on_app_exit：刷盘日志 + 回收长驻
/// 子进程 + 清理临时脚本）；Phase 2 会在此之前插入「等删除类任务、断子进程」的静默收尾编排。
#[tauri::command]
pub fn shutdown_complete<R: tauri::Runtime>(app: AppHandle<R>, window: WebviewWindow<R>) {
    let _ = guard::guard_readonly(&window);
    log::write_log("info", "渲染层宣告关闭收尾完成，执行退出");
    crate::on_app_exit();
    app.exit(0);
}

/// intro:load — 本地内置简介库
#[tauri::command]
pub fn intro_load<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    match serde_json::from_str::<serde_json::Value>(ITEM_INTRO_JSON) {
        Ok(data) => Ok(serde_json::json!({ "success": true, "data": data })),
        Err(e) => {
            log::write_log("warn", &format!("读取本地简介库失败: {e}"));
            Ok(serde_json::json!({ "success": false, "message": "本地简介库读取失败" }))
        }
    }
}

/// 数据目录探针（Phase 1 排障用；Phase 5 随文档收敛时评估去留）
///
/// 审查 v2-T1 订正措辞：旧注释写「**只读**探针」，但它最后一项会**真写**
/// `.write-probe.json`（`secureWriteProbe`）。这不构成风险 —— 本命令不在
/// `CHANNEL_MAP`（`tauri-api.js` 全表 `debug:` 0 命中）且被 `check-channel-map.mjs`
/// 的 PROBES 豁免，渲染层根本调不到 —— 但注释与代码不符会误导下一个人去查「谁在写」。
#[tauri::command]
pub fn debug_data_dirs<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    Ok(serde_json::json!({
        "dataDir": paths::app_data_dir().to_string_lossy(),
        "legacyDir": paths::legacy_data_dir().to_string_lossy(),
        "portable": paths::is_portable(),
        "appearanceExists": paths::appearance_file().is_file(),
        "material": crate::engine::appearance::effective_material(),
        "localStateCandidates": paths::local_state_candidates()
            .iter().map(|p| format!("{}:{}", p.to_string_lossy(), p.is_file())).collect::<Vec<_>>(),
        "secureWriteProbe": security::atomic_write_json(
            &paths::join_data(".write-probe.json"),
            &serde_json::json!({ "at": crate::engine::now_ms() })
        ).is_ok(),
    }))
}