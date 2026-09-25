//! memory 域（B 批）：memory:info / clean / processes / kill / stubborn-kill / stubborn-block
//!
//! 语义对照 main.js 6094-6288（逐条复刻，踩过的坑不改）：
//! - 进程快照按**调用窗口 label 分槽**（Electron 的 `event.sender.id` 等价物）：
//!   `memory:kill` 的白名单只认本窗口最近一次 `memory:processes` 那一槽，多窗口并发不串台（M-4）；
//! - `memory:kill` 三重防线（PM-1 / N2）：自我防护（本进程 PID + **同 exe 路径**一律拒绝）
//!   → 快照命中 → 系统关键进程黑名单（前端只读态之外的最终防线）；
//! - `memory:clean` / `memory:stubborn-kill` / `memory:stubborn-block` 未提权一律
//!   `{ success:false, needAdmin:true }`（M-3），静默 no-op 会误导用户；
//! - `memory:stubborn-block` 单项失败（failedCount>0）不再无条件报绿，如实降级
//!   `{ success:false, partial:true, data }`（M-1）；
//! - 进程列表走 `@@PROC@@` 前缀协议解析（PM-7：裸 JSON.parse 会被脚本额外输出污染）。
//!
//! `memory:clean` 不走 PowerShell：Electron 侧本就「原生引擎优先」，Tauri 直调
//! `trim_finder::perf::mem_clean_json`（等价 finder.exe mem-clean），**无 PS 回落路径**。
//!
//! 需要加入 lib.rs `generate_handler!` 的完整行：
//!   commands::memory::memory_info,
//!   commands::memory::memory_clean,
//!   commands::memory::memory_processes,
//!   commands::memory::memory_kill,
//!   commands::memory::memory_stubborn_kill,
//!   commands::memory::memory_stubborn_block,

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};
use tauri::WebviewWindow;

use crate::engine::{guard, log, native, sysinfo};

/// 进程快照分槽（key = 调用窗口 label）。`Vec` 代替 `HashMap` 以支持 const 初始化。
static PROCESS_SNAPSHOTS: Mutex<Vec<(String, HashMap<i64, ProcInfo>)>> = Mutex::new(Vec::new());

#[derive(Clone)]
struct ProcInfo {
    process_name: String,
    path: String,
}

/// 系统关键进程黑名单（main.js 6186-6200 逐字搬运；比较时去掉 `.exe` 后缀、转小写）
const CRITICAL_PROCESS_NAMES: &[&str] = &[
    "system",
    "idle",
    "registry",
    "memory compression",
    "secure system",
    "smss",
    "csrss",
    "wininit",
    "winlogon",
    "services",
    "lsass",
    "lsaiso",
    "svchost",
    "fontdrvhost",
    "dwm",
    "sihost",
    "ctfmon",
    "explorer",
    "audiodg",
    "wudfhost",
    "spoolsv",
    "searchindexer",
    "shellexperiencehost",
    "startmenuexperiencehost",
    "taskhostw",
    "runtimebroker",
    "sppsvc",
    "wmiprvse",
    "dllhost",
    "securityhealthservice",
    "securityhealthsystray",
    "msmpeng",
    "nissrv",
    "systemsettings",
    "applicationframehost",
    "conhost",
    "logonui",
    "userinit",
    "msiexec",
    "trustedinstaller",
    "tiworker",
    "backgroundtaskhost",
    "textinputhost",
    "useroobebroker",
];

/// `String(name || '').toLowerCase().replace(/\.exe$/, '').trim()`（顺序与 JS 一致）
fn is_critical_process_name(name: &str) -> bool {
    let lowered = name.to_lowercase();
    let stripped = lowered.strip_suffix(".exe").unwrap_or(&lowered);
    CRITICAL_PROCESS_NAMES.contains(&stripped.trim())
}

/// `Number(v)` + `Number.isInteger` 口径的整数取值（数字 / 数字字符串都认，NaN/小数拒绝）
fn js_int(v: &Value) -> Option<i64> {
    let f = match v {
        Value::Number(n) => n.as_f64()?,
        Value::String(s) => s.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    if !f.is_finite() || f.fract() != 0.0 {
        return None;
    }
    Some(f as i64)
}

/// `String(v || '')` 的粗糙等价（缺字段/ null → 空串，数字/布尔按 JSON 文本）
fn js_string(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

// ==================== memory:info ====================

/// memory:info — 物理内存 / 页面文件 / 系统缓存（只读）
///
/// S3：纯 Rust 原生，无 PS 回退。
#[tauri::command]
pub async fn memory_info<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    match tauri::async_runtime::spawn_blocking(native::memory_info).await {
        Ok(Ok(data)) => Ok(json!({ "success": true, "data": data, "engine": "rust" })),
        Ok(Err(e)) => Ok(json!({ "success": false, "message": format!("原生采集失败: {e}") })),
        Err(e) => Ok(json!({ "success": false, "message": format!("采集任务异常: {e}") })),
    }
}

// ==================== memory:clean ====================

/// memory:clean — 按区域清理工作集/系统缓存/列表（需管理员；直调原生引擎，30s 超时）
///
/// 返回形状与 Electron 原生分支逐字段一致：`{ success, data, engine: 'rust' }`。
/// 差异：Electron 在原生不可用时回落 PowerShell，Tauri 侧**不回落**（失败即如实返回错误）。
#[tauri::command]
pub async fn memory_clean<R: tauri::Runtime>(window: WebviewWindow<R>, items: Option<Vec<Value>>) -> Result<Value, String> {
    // 审查 v2-L17：这条**会改系统状态**（清工作集/系统缓存），唯一调用方是主窗的
    // `memoryclean.js`（见 `app.js` 的页面表），四个子窗都不加载它 ⇒ 收 MAIN 档。
    // `guard_readonly` 放行全部五窗是历史命名造成的错位，不是它该有的档位。
    guard::guard(&window, guard::MAIN)?;
    // `Array.isArray(items) ? items.filter(i => typeof i === 'string') : []`
    let list: Vec<String> = items
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    if list.is_empty() {
        return Ok(json!({ "success": false, "message": "未选择要清理的内存区域" }));
    }
    // M-3：NtSetSystemInformation 需 SeProfileSingleProcess / SeIncreaseQuota 特权，
    // 非管理员必失败 —— 统一走 elevate 握手，避免「点了没反应」
    if !sysinfo::is_admin() {
        return Ok(json!({
            "success": false,
            "needAdmin": true,
            "message": "内存清理需要管理员权限，请先提权"
        }));
    }
    // 原生引擎优先（v3.7.1 R3）：双特权 + 5 区域逐字平移 PS 语义，含 82/84 黑名单
    let result = tauri::async_runtime::spawn_blocking(move || {
        let text = trim_finder::perf::mem_clean_json(&list);
        serde_json::from_str::<Value>(&text).map_err(|e| format!("原生清理结果解析失败: {e}"))
    })
    .await;
    Ok(match result {
        Ok(Ok(data)) => match data.get("results").and_then(|v| v.as_array()) {
            Some(results) => {
                // 部分成功语义：至少一项 ok=true 即 success=true；失败项由前端在 toast 里逐项列出
                // NTSTATUS。此前 failed==0 才 success 会把"部分区域被系统拒绝但其他区域已释放"
                // 整批判成失败，用户看到"清理失败"但内存确实降了——探测口径过严。
                let ok_count = results.iter()
                    .filter(|item| item.get("ok").and_then(|v| v.as_bool()) == Some(true))
                    .count();
                let failed = results.len() - ok_count;
                log::write_log("info", &format!(
                    "内存清理：释放 {}，成功 {} 项，失败 {} 项",
                    data.get("freed").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    ok_count, failed
                ));
                json!({ "success": ok_count > 0, "data": data, "engine": "rust" })
            }
            // 原生引擎的失败也用可解析 JSON 回执（`{"error":"…"}`，如区域 id 非法）：如实报出
            None => {
                let message = js_string(data.get("error"));
                let message = if message.is_empty() {
                    "原生内存清理返回格式异常".to_string()
                } else {
                    message
                };
                log::write_log("warn", &format!("原生内存清理失败: {message}"));
                json!({ "success": false, "message": message })
            }
        },
        Ok(Err(message)) => {
            log::write_log("warn", &format!("原生内存清理不可用: {message}"));
            json!({ "success": false, "message": "解析清理结果失败" })
        }
        Err(e) => json!({ "success": false, "message": format!("内存清理任务异常: {e}") }),
    })
}

// ==================== memory:processes ====================

/// 从脚本输出里取 `@@PROC@@` 前缀行（PM-7：裸 JSON.parse 会被额外输出污染）
/// `Array.isArray(data) ? data : (data ? [data] : [])`（含 JS 假值口径）
/// 落槽：仅收 `Number.isInteger(Number(Id)) && Id > 0` 的项
fn save_snapshot(label: &str, processes: &[Value]) {
    let mut slot: HashMap<i64, ProcInfo> = HashMap::new();
    for p in processes {
        let Some(id) = p.get("Id").and_then(js_int) else {
            continue;
        };
        if id <= 0 {
            continue;
        }
        slot.insert(
            id,
            ProcInfo {
                process_name: js_string(p.get("ProcessName")),
                path: js_string(p.get("Path")),
            },
        );
    }
    let mut snapshots = PROCESS_SNAPSHOTS.lock().unwrap_or_else(|e| e.into_inner());
    match snapshots.iter_mut().find(|(l, _)| l == label) {
        Some(entry) => entry.1 = slot,
        None => snapshots.push((label.to_string(), slot)),
    }
}

fn lookup_snapshot(label: &str, pid: i64) -> Option<ProcInfo> {
    let snapshots = PROCESS_SNAPSHOTS.lock().unwrap_or_else(|e| e.into_inner());
    snapshots
        .iter()
        .find(|(l, _)| l == label)
        .and_then(|(_, slot)| slot.get(&pid))
        .cloned()
}

/// memory:processes — 进程列表（只读），同时刷新本窗口的快照槽
///
/// S3：纯 Rust 原生，无 PS 回退。
#[tauri::command]
pub async fn memory_processes<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    let label = guard::guard_readonly(&window)?;
    match tauri::async_runtime::spawn_blocking(native::memory_processes).await {
        Ok(Ok(entries)) => {
            let processes: Vec<Value> = entries
                .into_iter()
                .map(|p| {
                    json!({
                        "Id": p.pid as i64,
                        "ProcessName": p.name,
                        "mem": p.working_set as i64,
                        "Path": p.path,
                    })
                })
                .collect();
            save_snapshot(&label, &processes);
            Ok(json!({ "success": true, "processes": processes, "engine": "rust" }))
        }
        Ok(Err(e)) => Ok(json!({ "success": false, "message": format!("原生采集失败: {e}") })),
        Err(e) => Ok(json!({ "success": false, "message": format!("采集任务异常: {e}") })),
    }
}

// ==================== memory:kill ====================

/// memory:kill — 结束指定进程（15s 超时）；PID 必为正整数且必须命中本窗口最近一次扫描
#[tauri::command]
pub async fn memory_kill<R: tauri::Runtime>(window: WebviewWindow<R>, pid: Option<Value>) -> Result<Value, String> {
    let label = guard::guard_readonly(&window)?;
    let Some(n) = pid.as_ref().and_then(js_int).filter(|n| *n > 0) else {
        return Ok(json!({ "success": false, "message": "无效的进程 ID" }));
    };
    // 自我防护：Trim 自身进程一律拒绝（无论渲染层怎么传）
    if n == std::process::id() as i64 {
        return Ok(json!({ "success": false, "message": "不能结束 Trim 自身进程" }));
    }
    let Some(known) = lookup_snapshot(&label, n) else {
        return Ok(json!({
            "success": false,
            "message": "进程不是最近一次扫描结果，已拒绝结束"
        }));
    };
    // 复核 N2：渲染/GPU helper 等子进程 PID 与主进程不同，靠**同 exe 路径**一并拦住
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let known_exe = known.path.to_lowercase();
    if !self_exe.is_empty() && !known_exe.is_empty() && known_exe == self_exe {
        return Ok(json!({
            "success": false,
            "message": "不能结束 Trim 自身进程（含渲染/GPU 等子进程）"
        }));
    }
    // 关键进程黑名单：系统核心进程禁止结束（前端只读态之外的最终防线）
    if is_critical_process_name(&known.process_name) {
        return Ok(json!({
            "success": false,
            "message": format!("系统关键进程 {} 已受保护，不能结束", known.process_name)
        }));
    }
    // S3：纯 Rust 原生
    match tauri::async_runtime::spawn_blocking({
        let name = known.process_name.clone();
        move || native::kill_process(n as u32, &name)
    }).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Ok(json!({ "success": false, "message": format!("原生结束进程失败: {e}") })),
        Err(e) => Ok(json!({ "success": false, "message": format!("结束进程任务异常: {e}") })),
    }
}

// ==================== memory:stubborn-kill ====================

/// memory:stubborn-kill — 顽固软件专杀（需管理员，30s 超时）
#[tauri::command]
pub async fn memory_stubborn_kill<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    // M-3：批量结束进程属特权操作，无权限直接返回 needAdmin，由渲染层触发提权
    if !sysinfo::is_admin() {
        return Ok(json!({
            "success": false,
            "needAdmin": true,
            "message": "顽固软件专杀需要管理员权限，请先提权"
        }));
    }
    // S3：纯 Rust 原生
    match tauri::async_runtime::spawn_blocking(native::stubborn_kill).await {
        Ok(Ok(data)) => Ok(json!({ "success": true, "data": data, "engine": "rust" })),
        Ok(Err(e)) => Ok(json!({ "success": false, "message": format!("原生专杀失败: {e}") })),
        Err(e) => Ok(json!({ "success": false, "message": format!("专杀任务异常: {e}") })),
    }
}

// ==================== memory:stubborn-block ====================

/// memory:stubborn-block — 顽固软件阻止开机自启（需管理员，60s 超时）
///
/// 持久化策略（改服务启动类型 / 删更新任务），不提供自动还原。
#[tauri::command]
pub async fn memory_stubborn_block<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if !sysinfo::is_admin() {
        return Ok(json!({
            "success": false,
            "needAdmin": true,
            "message": "顽固软件自启阻断需要管理员权限，请先提权"
        }));
    }
    // S3：纯 Rust 原生
    match tauri::async_runtime::spawn_blocking(native::stubborn_block).await {
        Ok(Ok(data)) => {
            let failed = data.get("failedCount").and_then(|v| v.as_f64()).unwrap_or(0.0);
            Ok(json!({ "success": failed == 0.0, "partial": failed > 0.0, "data": data }))
        }
        Ok(Err(e)) => Ok(json!({ "success": false, "message": format!("原生执行失败: {e}") })),
        Err(e) => Ok(json!({ "success": false, "message": format!("原生任务异常: {e}") })),
    }
}