//! pwsh 运行时域（B 批）：pwsh:status（v3 批原有 pwsh:prepare，已于 B11 摘除，见文件尾）
//!
//! 需在 lib.rs 的 invoke_handler 中注册（本任务不改 lib.rs，请统一登记）：
//!   commands::pwshruntime::pwsh_status,
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

use tauri::WebviewWindow;

use crate::engine::guard;
use crate::pwsh;

/// 运行时状态机（对齐 Electron 的 'idle' | 'extracting' | 'ready' | 'error'；
/// Tauri 轨无解压链，实际只会出现 'idle' | 'ready' | 'error'，见头部差异说明）
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

/// 状态快照（形状对齐 Electron getPwshStatusSnapshot 的 status/message/progress/path；
/// `version` 字段已随 B11 摘除 —— 它原样回传「内置运行时版本号」，而 Tauri 轨根本没有
/// 内置运行时，读它得到的是一个与实际执行的 pwsh 毫无关系的常量，比没有字段更误导）
fn snapshot() -> serde_json::Value {
    let (status, message, progress, path) = with_state(|s| match s {
        Some(v) => (v.status, v.message.clone(), v.progress, v.path.clone()),
        None => ("idle", String::new(), 0, String::new()),
    });
    serde_json::json!({
        "status": status,
        "message": message,
        "progress": progress,
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

// pwsh:prepare — 手动触发准备（设置页「立即准备」/ 启动期后台准备）
//
// **B11（2026-09-26）已整链摘除**（命令 + lib.rs 注册 + CHANNEL_MAP + `api.pwsh.prepare`）。
// 摘除判据三条：
//   1. 零调用方 —— 全仓 `pwsh.prepare(` 0 命中（v2 审查 D4 孤儿）；渲染层只订阅
//      `pwsh:status` 事件并调 `getStatus()`（`app.js` 的 `initPwshFeedback`）。
//   2. 无实际可准备的东西 —— Electron 侧它触发的是「内置 zip 运行时解压」，而本仓库
//      **没有任何内置 zip 资产**，也没有移植解压链（见本文件头部差异说明），
//      所以 Tauri 侧它只会把 `resolve_pwsh()` 这条候选链重跑一遍。
//   3. 与 `pwsh:status` 完全重复 —— `pwsh_status` 内部同样调 `resolve_and_record()`。
//
// 留着它的代价是「注册 = 已覆盖」的错觉（v2-M15 D4 门禁正是抓这类），
// 且给「设置页有个按钮能装上 PS7」的虚假预期。将来若真要移植解压链，
// 正确做法是新增一条语义明确的 `pwsh:install` 通道，而不是复活本条。