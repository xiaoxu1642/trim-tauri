//! app 域（批次 A）：app:get-info / app:get-theme / app:read-usage / app:open-external
//! 外加窗口生命周期握手 app:first-paint（原 onSafe send 通道，直连命令注册）

use tauri::{AppHandle, WebviewWindow};

use crate::engine::{appearance, guard, paths, sysinfo};

/// 使用说明数据源：根目录 readme.md（用户文档与应用内弹窗同源）
const README_MD: &str = include_str!("../../../readme.md");

/// app:get-info — 字段形状对齐 Electron 版；未迁移字段显式给 null（渲染层已有 N/A 兜底）
#[tauri::command]
pub fn app_get_info<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let build = sysinfo::windows_build();
    let username = std::env::var("USERNAME").unwrap_or_default();
    let homedir = std::env::var("USERPROFILE").unwrap_or_default();
    Ok(serde_json::json!({
        "name": "Trim",
        "version": env!("CARGO_PKG_VERSION"),
        // Electron/Node/Chrome 在 Tauri 下不存在，显式 null（渲染层显示 N/A）
        "electron": null,
        "node": null,
        "chrome": null,
        "runtime": "tauri",
        "platform": "win32",
        // 口径对齐 Node process.arch（'x64'/'arm64'），非 Rust 的 target 三元组（'x86_64'）。
        // 渲染层设置页直接展示该值，两者不一致会显示成 x86_64 而暴露迁移痕迹。
        "arch": node_arch(),
        "osVersion": sysinfo::os_version(),
        "osBuild": build,
        "fluentSupport": sysinfo::fluent_support_level(),
        "micaEnabled": sysinfo::fluent_support_level() != "none",
        "materialEnabled": appearance::material_enabled(),
        "isAdmin": sysinfo::is_admin(),
        "username": username,
        "homedir": homedir,
        "powerShell": "PowerShell 7",
        // v2.6.0（P2-9）：数据目录形态（设置页「系统信息」展示）
        "portable": paths::is_portable(),
        "dataDir": paths::app_data_dir().to_string_lossy(),
    }))
}

/// app:get-theme — v2.1 起应用固定浅色
#[tauri::command]
pub fn app_get_theme<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<String, String> {
    guard::guard_readonly(&window)?;
    Ok("light".into())
}

/// app:read-usage — 返回使用说明 Markdown 全文
#[tauri::command]
pub fn app_read_usage<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    if README_MD.trim().is_empty() {
        return Ok(serde_json::json!({ "success": false, "message": "使用说明文件不存在" }));
    }
    Ok(serde_json::json!({ "success": true, "content": README_MD }))
}

/// app:open-external — 受控外部链接出口：**只放行 https**，
/// 防 file: / javascript: / data: 等注入（渲染层导航已被 CSP 与窗口策略禁止）
#[tauri::command]
pub fn app_open_external<R: tauri::Runtime>(window: WebviewWindow<R>, url: String) -> serde_json::Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return serde_json::json!({ "ok": false, "reason": "forbidden", "message": msg });
    }
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return serde_json::json!({ "ok": false, "reason": "empty" });
    }
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("https://") {
        let scheme = trimmed.split(':').next().unwrap_or("");
        return serde_json::json!({ "ok": false, "reason": "scheme", "protocol": format!("{scheme}:") });
    }
    match open_https(trimmed) {
        Ok(()) => serde_json::json!({ "ok": true }),
        Err(e) => serde_json::json!({ "ok": false, "reason": "open-failed", "message": e }),
    }
}

/// 用系统默认浏览器打开 https（不经 shell 拼接命令，避免命令注入）
fn open_https(url: &str) -> Result<(), String> {
    let wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let op = unsafe {
        windows::Win32::UI::Shell::ShellExecuteW(
            None,
            windows::core::w!("open"),
            windows::core::PCWSTR(wide.as_ptr()),
            None,
            None,
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW 返回值 <= 32 表示失败
    if op.0 as usize > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecute 返回 {}", op.0 as usize))
    }
}

/// Node `process.arch` 口径（渲染层设置页直接展示该字段）
const fn node_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86") {
        "ia32"
    } else {
        std::env::consts::ARCH
    }
}

/// app:first-paint — 渲染层 DOMContentLoaded + 双 rAF 黑闪握手（只认首个通知）
///
/// 只认 `main` 的帧：`tauri-api.js` 在**每个**窗口里都会发这条，而闩锁是全局一次性的。
/// 若不按 label 判定，一个先渲染完的子窗（preview/models/…）会把主窗口提前 show 出来，
/// 主窗自己那帧还没画完 —— 正是这套握手要消灭的黑闪。子窗的首帧由各自的
/// `on_page_load(Finished)` 路径处理，不经过这里。
#[tauri::command]
pub fn app_first_paint<R: tauri::Runtime>(app: AppHandle<R>, window: WebviewWindow<R>) {
    if window.label() != "main" {
        return;
    }
    crate::show_main_window_when_ready(&app, "渲染层首帧握手");
}