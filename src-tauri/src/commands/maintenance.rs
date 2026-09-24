//! maintenance 域（D 批）：maintenance:tasks / maintenance:run
//!
//! 对照 Electron main.js 7336-7425 + src/scripts-powershell/maintenance-scripts.js。
//! 任务清单与分类来自编译期嵌入的 maintenance-tasks.json（由 JS 模块 `list()/CATEGORY_ORDER`
//! 运行时值导出，单一数据源）。
//!
//! 安全/语义要点（逐条对齐 Electron）：
//! - 同一时刻仅允许一个维护任务（进程内 Mutex，Electron 用模块级 maintenanceRunning）。
//! - `admin:true` 的任务在非管理员下直接返回 `{success:false, needAdmin:true}`（MA-2）。
//! - 输出协议：`@@RESULT@@ok|warn` 决定结果；`@@WU_OLD_BAK@@<path>` 收集 wu 旧缓存，
//!   执行后由主进程统一走回收站删除（N2 删除红线，严格名校验）。
//! - 超时 30 分钟（SFC/DISM 耗时长）。
//! - code!=0 且脚本未给结果时降为 warn（success 仍按 result==="ok" 判定，与 Electron 一致）。

use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{Emitter, Runtime, WebviewWindow};

use crate::engine::{guard, log, sysinfo};
use crate::pwsh;

// ==================== 任务元数据（编译期嵌入，JS 运行时值导出） ====================
const TASKS_JSON: &str = include_str!("../../data/maintenance-tasks.json");

// ==================== 18 个维护脚本（编译期嵌入，禁止手写） ====================
const PS_SFC: &str = include_str!("../../ps/maint_sfc.ps1");
const PS_DISM: &str = include_str!("../../ps/maint_dism.ps1");
const PS_WU: &str = include_str!("../../ps/maint_wu.ps1");
const PS_STORE: &str = include_str!("../../ps/maint_store.ps1");
const PS_AUDIO: &str = include_str!("../../ps/maint_audio.ps1");
const PS_PERFCOUNTERS: &str = include_str!("../../ps/maint_perfcounters.ps1");
const PS_SEARCH: &str = include_str!("../../ps/maint_search.ps1");
const PS_DNS: &str = include_str!("../../ps/maint_dns.ps1");
const PS_NETSTACK: &str = include_str!("../../ps/maint_netstack.ps1");
const PS_NET_RESPONSE: &str = include_str!("../../ps/maint_net_response.ps1");
const PS_TF_NET_TCP: &str = include_str!("../../ps/maint_tf_net_tcp.ps1");
const PS_TF_NET_TCPIP: &str = include_str!("../../ps/maint_tf_net_tcpip.ps1");
const PS_TF_NET_LANMAN: &str = include_str!("../../ps/maint_tf_net_lanman.ps1");
const PS_TF_NET_NIC: &str = include_str!("../../ps/maint_tf_net_nic.ps1");
const PS_TF_NET_WEAKHOST: &str = include_str!("../../ps/maint_tf_net_weakhost.ps1");
const PS_NET_QOS: &str = include_str!("../../ps/maint_net_qos_scheduler.ps1");
const PS_NET_NETBIOS: &str = include_str!("../../ps/maint_net_disable_netbios.ps1");
const PS_NET_LMHOSTS: &str = include_str!("../../ps/maint_net_disable_lmhosts.ps1");

/// taskId -> 脚本体（id 与 maintenance-scripts.js 的 TASKS 键一致）
fn script_for(task_id: &str) -> Option<&'static str> {
    Some(match task_id {
        "sfc" => PS_SFC,
        "dism" => PS_DISM,
        "wu" => PS_WU,
        "store" => PS_STORE,
        "audio" => PS_AUDIO,
        "perfcounters" => PS_PERFCOUNTERS,
        "search" => PS_SEARCH,
        "dns" => PS_DNS,
        "netstack" => PS_NETSTACK,
        "net_response" => PS_NET_RESPONSE,
        "tf_net_tcp" => PS_TF_NET_TCP,
        "tf_net_tcpip" => PS_TF_NET_TCPIP,
        "tf_net_lanman" => PS_TF_NET_LANMAN,
        "tf_net_nic" => PS_TF_NET_NIC,
        "tf_net_weakhost" => PS_TF_NET_WEAKHOST,
        "net_qos_scheduler" => PS_NET_QOS,
        "net_disable_netbios" => PS_NET_NETBIOS,
        "net_disable_lmhosts" => PS_NET_LMHOSTS,
        _ => return None,
    })
}

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

    let Some(script) = script_for(&task_id) else {
        return json!({ "success": false, "message": format!("维护任务 {task_id} 缺少脚本") });
    };

    set_running(Some(task_id.clone()));
    let result = run_one(&window, &task_id, script).await;
    set_running(None);
    result
}

async fn run_one<R: Runtime>(window: &WebviewWindow<R>, task_id: &str, script: &str) -> Value {
    let script_path = match pwsh::write_temp_script(script, ".ps1") {
        Ok(p) => p,
        Err(e) => return json!({ "success": false, "message": e }),
    };

    log::write_log("info", &format!("维护任务开始: {task_id}"));
    let out = pwsh::run_file(
        &script_path,
        Duration::from_secs(1800),
        Some(&format!("maintenance.{task_id}")),
    );
    let _ = std::fs::remove_file(&script_path);

    let out = match out {
        Ok(o) => o,
        Err(e) => {
            log::write_log("error", &format!("维护任务异常: {task_id} -> {e}"));
            return json!({
                "success": false,
                "message": e,
                "data": { "taskId": task_id, "result": "error", "output": "" }
            });
        }
    };

    // 解析行协议
    let mut lines: Vec<String> = Vec::new();
    let mut result = "ok".to_string();
    let mut wu_old_baks: Vec<String> = Vec::new();
    for raw in out.stdout.split(['\r', '\n']) {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some(v) = line.strip_prefix("@@RESULT@@") {
            let v = v.trim();
            if !v.is_empty() {
                result = v.to_string();
            }
            continue;
        }
        if line.starts_with("@@DIAG@@") {
            continue; // 已由 pwsh 层 extract_diag_lines 处理（理论上不会到这）
        }
        if let Some(p) = line.strip_prefix("@@WU_OLD_BAK@@") {
            wu_old_baks.push(p.trim().to_string());
            continue;
        }
        lines.push(line.to_string());
    }

    if out.code != 0 && result == "ok" {
        result = "warn".to_string();
    }

    // wu 旧缓存：严格名校验后回收站删除（N2 删除红线）
    if !wu_old_baks.is_empty() {
        let win_dir = std::env::var("WINDIR")
            .unwrap_or_else(|_| r"C:\Windows".to_string())
            .trim_end_matches(['\\', '/'])
            .to_lowercase();
        let mut cleaned = 0usize;
        for p in &wu_old_baks {
            let path = std::path::Path::new(p);
            let base = path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let parent = path
                .parent()
                .map(|s| s.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let ok_name = !base.is_empty()
                && parent == win_dir
                && regex_like_wu_backup(&base);
            if !ok_name {
                log::write_log("warn", &format!("忽略非常规 wu 旧备份路径: {p}"));
                continue;
            }
            match trim_finder::scan::recycle::send_to_trash(p) {
                Ok(_) => {
                    cleaned += 1;
                    log::write_log(
                        "info",
                        &format!("wu 旧缓存备份清理(回收站): {base} -> 成功"),
                    );
                }
                Err(e) => {
                    log::write_log("warn", &format!("wu 旧缓存备份清理: {base} -> {e}"));
                }
            }
        }
        let summary = format!(
            "旧缓存备份清理完成: {}/{} 个（回收站优先，失败见日志）",
            cleaned,
            wu_old_baks.len()
        );
        lines.push(summary.clone());
        let _ = window.emit("maintenance:output", json!({ "taskId": task_id, "line": summary }));
    }

    let success = result == "ok";
    log::write_log(
        if success { "info" } else { "warn" },
        &format!(
            "维护任务完成: {} result={} exit={}{}",
            task_id,
            result,
            out.code,
            if out.stderr.is_empty() {
                String::new()
            } else {
                format!(" stderr={}", out.stderr.trim().chars().take(200).collect::<String>())
            }
        ),
    );

    json!({
        "success": success,
        "data": {
            "taskId": task_id,
            "result": result,
            "output": lines.join("\n")
        }
    })
}

/// 严格匹配 SoftwareDistribution.old_YYYYMMDDHHMMSS / catroot2.old_*（14 位时间戳）
fn regex_like_wu_backup(base: &str) -> bool {
    let prefixes = ["SoftwareDistribution.old_", "catroot2.old_"];
    for pre in prefixes {
        if let Some(ts) = base.strip_prefix(pre) {
            if ts.len() == 14 && ts.bytes().all(|b| b.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::regex_like_wu_backup;

    #[test]
    fn wu_backup_strict_name() {
        assert!(regex_like_wu_backup("SoftwareDistribution.old_20260924123000"));
        assert!(regex_like_wu_backup("catroot2.old_20260924123000"));
        // 防伪装路径：层级/名称/时间戳任一不符即拒
        assert!(!regex_like_wu_backup("SoftwareDistribution.old_2026092412300"));
        assert!(!regex_like_wu_backup("SoftwareDistribution.old_202609241230000"));
        assert!(!regex_like_wu_backup("evil.old_20260924123000"));
        assert!(!regex_like_wu_backup("SoftwareDistribution.old_20260924abcd00"));
    }
}
