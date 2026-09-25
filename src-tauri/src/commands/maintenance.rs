//! maintenance 域（D 批）：maintenance:tasks / maintenance:run
//!
//! 对照 Electron main.js 7336-7425 + src/scripts-powershell/maintenance-scripts.js。
//! 任务清单与分类来自编译期嵌入的 maintenance-tasks.json（由 JS 模块 `list()/CATEGORY_ORDER`
//! 运行时值导出，单一数据源）。
//!
//! 安全/语义要点（逐条对齐 Electron）：
//! - 同一时刻仅允许一个维护任务（进程内 Mutex，Electron 用模块级 maintenanceRunning）。
//! - `admin:true` 的任务在非管理员下直接返回 `{success:false, needAdmin:true}`（MA-2）。
//! - 超时 30 分钟（SFC/DISM 耗时长）。
//! - S3：纯 Rust 原生实现，无 PS 回退。

use std::sync::Mutex;

use serde_json::{json, Value};
use tauri::{Emitter, Runtime, WebviewWindow};

use crate::engine::{guard, log, sysinfo};

// ==================== 任务元数据（编译期嵌入，JS 运行时值导出） ====================
const TASKS_JSON: &str = include_str!("../../data/maintenance-tasks.json");

#[derive(serde::Deserialize)]
struct TasksFile {
    tasks: Vec<Value>,
    categories: Vec<String>,
}

fn load_tasks() -> TasksFile {
    serde_json::from_str(TASKS_JSON).expect("maintenance-tasks.json 由生成器保证合法")
}

/// 运行锁：Some(taskId) 表示已有任务在跑
static RUNNING: Mutex<Option<String>> = Mutex::new(None);

fn is_running() -> Option<String> {
    RUNNING.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set_running(id: Option<String>) {
    *RUNNING.lock().unwrap_or_else(|e| e.into_inner()) = id;
}

// ==================== IPC ====================

/// maintenance:tasks —— 返回任务清单与分类顺序（纯数据，不跑脚本）
#[tauri::command]
pub async fn maintenance_tasks<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let f = load_tasks();
    json!({ "success": true, "data": f.tasks, "categories": f.categories })
}

/// maintenance:run —— 执行单个维护任务（串行；admin 任务需提权）
#[tauri::command]
pub async fn maintenance_run<R: Runtime>(
    window: WebviewWindow<R>,
    task_id: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let task_id = match task_id {
        Some(id) if !id.is_empty() => id,
        _ => return json!({ "success": false, "message": "缺少任务 ID" }),
    };

    // 串行锁
    if let Some(running) = is_running() {
        return json!({
            "success": false,
            "message": format!("已有维护任务在执行中（{running}），请等待完成")
        });
    }

    // 任务必须在清单内
    let tasks_file = load_tasks();
    let task_meta = tasks_file.tasks.iter().find(|t| {
        t.get("id").and_then(|v| v.as_str()) == Some(task_id.as_str())
    });
    let Some(task_meta) = task_meta else {
        return json!({ "success": false, "message": format!("未知的维护任务: {task_id}") });
    };

    // MA-2：admin 任务强制卡权限
    let need_admin = task_meta
        .get("admin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if need_admin && !sysinfo::is_admin() {
        return json!({
            "success": false,
            "needAdmin": true,
            "message": "该维护任务需要管理员权限，请先提权"
        });
    }

    set_running(Some(task_id.clone()));
    let result = run_one(&window, &task_id).await;
    set_running(None);
    result
}

async fn run_one<R: Runtime>(window: &WebviewWindow<R>, task_id: &str) -> Value {
    log::write_log("info", &format!("维护任务开始: {task_id}"));

    // S3：纯 Rust 原生，无 PS 回退
    match crate::engine::native::maint_run(task_id) {
        Ok((success, message)) => {
            if success {
                log::write_log("info", &format!("维护任务原生完成: {task_id}"));
                let _ = window.emit("maintenance:output", json!({ "taskId": task_id, "line": message }));
                json!({
                    "success": true,
                    "message": message,
                    "data": { "taskId": task_id, "result": "ok", "output": message }
                })
            } else {
                json!({
                    "success": false,
                    "message": format!("原生执行未成功: {message}"),
                    "data": { "taskId": task_id, "result": "fail", "output": message }
                })
            }
        }
        Err(e) => json!({
            "success": false,
            "message": format!("原生执行异常: {e}"),
            "data": { "taskId": task_id, "result": "error", "output": e }
        }),
    }
}
