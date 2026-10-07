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

use crate::commands::state::RUNNING;

/// **占位式**取锁：空则占上并回 None，非空则回正在跑的那个任务 id。
///
/// v5 S-4：旧写法是 `is_running()` 判空 + 后面 `set_running(Some)` 占位，两次独立 `lock()`
/// 中间还夹着 `load_tasks()` 与权限判定 —— 两个 IPC 可在不同 worker 线程同时越过判空，
/// 于是两条 sfc / DISM 真的并发跑（互相抢 CBS 锁，双双失败还看不出原因）。
fn try_claim_running(id: &str) -> Option<String> {
    let mut g = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_some() {
        g.clone()
    } else {
        *g = Some(id.to_string());
        None
    }
}

/// v2-L4P-37（F-6）：运行锁改 RAII——此前「占位」与「复位」两次调用夹着整条执行链，
/// 链上任何 panic 都会让 Some(taskId) 永久留锁，维护页从此
/// 「已有任务在执行中」直到重启。Drop 复位覆盖 panic/早退全部路径。
///
/// v5 S-4：guard 记住自己占的 id，只放开**自己那把** —— 无条件复位
/// 会让先完成的人把别人仍在跑的锁放开。
struct RunningGuard(Option<String>);
impl Drop for RunningGuard {
    fn drop(&mut self) {
        let mut g = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
        if self.0.is_some() && *g == self.0 {
            *g = None;
        }
    }
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
    // 串行锁：一次 lock() 内完成「判空 + 占位」（v5 S-4）。占到位就立刻挂上 RAII guard，
    // 后面任何早退（未知任务 / 缺权限）都会自动复位，不会留锁。
    let _guard = match try_claim_running(&task_id) {
        Some(busy) => {
            return json!({
                "success": false,
                "message": format!("已有维护任务在执行中（{busy}），请等待完成")
            });
        }
        None => RunningGuard(Some(task_id.clone())),
    };

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

    // v2-L4P-37（F-6）：阻塞链进 spawn_blocking。maint_run 内部是 sfc/DISM/sc 等长耗时
    // 子进程（run_cmd 有 30 分钟超时上限，见 MAINT_CMD_TIMEOUT），必须离开 async runtime
    // 线程。运行锁已在上面占好并由 `_guard` 的 Drop 复位。
    let wid = window.clone();
    let tid = task_id.clone();
    let result = tauri::async_runtime::spawn_blocking(move || run_one(&wid, &tid))
        .await
        .unwrap_or_else(|e| {
            log::write_log("error", &format!("维护任务线程异常: {e}"));
            json!({
                "success": false,
                "message": format!("维护任务异常退出: {e}"),
                "data": { "taskId": task_id, "result": "error", "output": format!("{e}") }
            })
        });
    result
}

fn run_one<R: Runtime>(window: &WebviewWindow<R>, task_id: &str) -> Value {
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
