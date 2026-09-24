//! pwsh 运行时域（B 批）：pwsh:status / pwsh:prepare（+ `pwsh:status` 事件）
//!
//! 需在 lib.rs 的 invoke_handler 中注册（本任务不改 lib.rs，请统一登记）：
//!   commands::pwshruntime::pwsh_status,
//!   commands::pwshruntime::pwsh_prepare,
//!
//! 实现体来源：main.js 4653-4667（IPC 壳）+ src/main/pwsh-runtime.js（状态机/解压）。
//! 候选链**直接复用** pwsh/mod.rs 的 `resolve_pwsh` / `is_version_ready` /
//! `latest_ready_exe_path`，不复制第二套解析逻辑。
//!
//! 与 Electron 的差异（如实记录，非缺陷）：
//! - Electron `ensurePwshRuntimeAsync` 在候选链全落空时会走 pwsh-runtime.js 的
//!   `extractBundledRuntime` 内置 zip 兜底（SHA-256 校验件 + 系统 tar.exe 解压 +
//!   zip-slip 符号链接全树扫描 + `.extracting` pid 锁 + 确定性进度）。该解压链**本批未移植**
//!   （Tauri 侧既无内置 zip 资产，也无对应的外置 PS 脚本）。
//!   因此**不存在 'extracting' 态**：prepare 只做一次候选链解析（命中即 ready，全落空即 error），
//!   状态机取值收敛为 'idle' | 'ready' | 'error'。解压兜底作为后续独立任务补齐。
//! - `pwsh:status` 事件为**单窗口 emit**（Electron 广播所有 BrowserWindow；当前仅 main 窗口，
//!   语义等价）。

use std::sync::Mutex;

use tauri::{Emitter, WebviewWindow};

use crate::engine::guard;
use crate::pwsh;

/// 运行时状态机（对齐 Electron 的 'idle' | 'extracting' | 'ready' | 'error'）
struct PwshState {
    status: &'static str,
    message: String,
    progress: u32,
    path: String,
}

static STATE: Mutex<Option<PwshState>> = Mutex::new(None);

fn with_state<T>(f: impl FnOnce(&mut Option<PwshState>) -> T) -> T {
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut g)
}

/// 状态快照（形状逐字段对齐 Electron getPwshStatusSnapshot：status/message/progress/version/path）
fn snapshot() -> serde_json::Value {
    let (status, message, progress, path) = with_state(|s| match s {
        Some(v) => (v.status, v.message.clone(), v.progress, v.path.clone()),
        None => ("idle", String::new(), 0, String::new()),
    });
    serde_json::json!({
        "status": status,
        "message": message,
        "progress": progress,
        "version": pwsh::PWSH_VERSION,
        "path": path,
    })
}

/// 解析候选链并回填状态（命中/失败均更新，供 pwsh:status 只读快照复用；
/// 候选链本身在 pwsh/mod.rs 内有进程内缓存，重复调用不再付探测成本）。
fn resolve_and_record() -> Result<String, String> {
    match pwsh::resolve_pwsh() {
        Ok(p) => {
            let path = p.to_string_lossy().to_string();
            with_state(|s| {
                *s = Some(PwshState {
                    status: "ready",
                    message: format!("PowerShell 7 就绪：{path}"),
                    progress: 100,
                    path: path.clone(),
                })
            });
            Ok(path)
        }
        Err((_code, msg)) => {
            with_state(|s| {
                *s = Some(PwshState {
                    status: "error",
                    message: msg.clone(),
                    progress: 0,
                    path: String::new(),
                })
            });
            Err(msg)
        }
    }
}

/// pwsh:status — 只读查询当前运行时状态（含路径、版本、进度）
#[tauri::command]
pub async fn pwsh_status<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    // 探测在阻塞线程执行（可能 spawnSync 探测候选），不占用 async 运行时
    let _ = tauri::async_runtime::spawn_blocking(resolve_and_record).await;
    Ok(serde_json::json!({ "success": true, "data": snapshot() }))
}

/// pwsh:prepare — 手动触发准备（设置页「立即准备」/ 启动期后台准备）
#[tauri::command]
pub async fn pwsh_prepare<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let result = tauri::async_runtime::spawn_blocking(resolve_and_record).await;
    let snap = snapshot();
    // 状态事件（渲染层 pwsh.onStatus 监听）
    let _ = window.emit("pwsh:status", snap.clone());
    match result {
        Ok(Ok(path)) => Ok(serde_json::json!({
            "success": true,
            "data": { "status": "ready", "path": path }
        })),
        Ok(Err(message)) => Ok(serde_json::json!({
            "success": false, "message": message, "data": snap
        })),
        Err(e) => Ok(serde_json::json!({
            "success": false, "message": format!("准备任务异常: {e}"), "data": snap
        })),
    }
}