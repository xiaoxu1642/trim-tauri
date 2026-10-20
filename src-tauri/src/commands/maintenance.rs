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

// ==================== D-04b 维护错误码人话表（P1-A，2026-10-16） ====================
//
// 维护任务原生执行失败时回给界面的是一句机器输出，里面躺着一串 0x 开头的 HRESULT。
// 本表把**维护任务实际会撞到的**码翻成人话，附在 IPC 汇总 message 之后；
// 流式输出（maintenance:output 事件）保持原样——注解只进汇总，不改机器原文。
//
// 真源 = tools/winerror-codes.source.mjs（人工策展，中文解释按微软公开文档重写；
// Dism++ MessageTable 只作码表指路），由 tools/gen-winerror-codes.mjs 生成本 JSON，
// check-data-parity 的 P4b 组对拍。表里没有的码**不注解**——宁可少说，不可说错。
const WINERROR_JSON: &str = include_str!("../../data/winerror-codes.json");

#[derive(serde::Deserialize)]
struct WinerrorFile {
    codes: Vec<WinerrorCode>,
}

#[derive(serde::Deserialize)]
struct WinerrorCode {
    code: String,
    title: String,
    detail: String,
}

/// 词内字符（ASCII 字母/数字/下划线）——错误码边界的判据。
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// 在 `message` 里找已知 Win32 错误码（`0x` + 8 位 hex，大小写不敏感）。
///
/// 边界规则（v3 §6 P1-6）：`0x800f081f` 不许被更长 hex 串截取（`0x1800f081f`
/// 不算命中），随机 8 位 hex 没有 `0x` 前缀不算命中；码必须整词独立（前面挨着
/// 字母/数字/下划线的不算，如 `x0x80070005`）。
fn find_known_error_codes<'a>(message: &str, file: &'a WinerrorFile) -> Vec<&'a WinerrorCode> {
    let b = message.as_bytes();
    let mut hits: Vec<&'a WinerrorCode> = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let prefix_ok = i + 10 <= b.len()
            && (i == 0 || !is_word_byte(b[i - 1]))
            && b[i] == b'0'
            && b[i + 1].eq_ignore_ascii_case(&b'x');
        if prefix_ok {
            // 到这 i/i+1 必是 ASCII '0'/'x'，i+10 <= len ⇒ 切片一定在字符边界上
            let hex = &message[i + 2..i + 10];
            let after_ok = i + 10 >= b.len() || !is_word_byte(b[i + 10]);
            if hex.bytes().all(|c| c.is_ascii_hexdigit()) && after_ok {
                let code = message[i..i + 10].to_ascii_lowercase();
                if let Some(c) = file.codes.iter().find(|c| c.code == code) {
                    if !hits.iter().any(|h| h.code == c.code) {
                        hits.push(c);
                    }
                }
                i += 10;
                continue;
            }
        }
        i += 1;
    }
    hits
}

/// 汇总 message 的错误码注解（D-04b）：命中已知码时在文末附「码 — 结论：根因与下一步」。
/// 原文一字不改（流式输出与机器日志都靠它）；表解析失败时不阻塞主链（编译期嵌入，坏不了）。
fn annotate_error_codes(message: &str) -> String {
    let Ok(file) = serde_json::from_str::<WinerrorFile>(WINERROR_JSON) else {
        return message.to_string();
    };
    let hits = find_known_error_codes(message, &file);
    if hits.is_empty() {
        return message.to_string();
    }
    let mut out = message.to_string();
    out.push_str("\n\n【错误码注解】");
    for c in hits {
        out.push_str(&format!("\n{} — {}：{}", c.code, c.title, c.detail));
    }
    out
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
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
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
            // D-04b（P1-A）：IPC 汇总 message 附错误码人话注解；流式 emit 与
            // data.output 保持机器原文（注解只进汇总，不改输出本身）
            let summary = annotate_error_codes(&message);
            if success {
                log::write_log("info", &format!("维护任务原生完成: {task_id}"));
                let _ = window.emit("maintenance:output", json!({ "taskId": task_id, "line": message }));
                json!({
                    "success": true,
                    "message": summary,
                    "data": { "taskId": task_id, "result": "ok", "output": message }
                })
            } else {
                json!({
                    "success": false,
                    "message": format!("原生执行未成功: {summary}"),
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

// ==================== D-04b 注解函数单测（纯函数，零副作用） ====================

#[cfg(test)]
mod winerror_annotation_tests {
    use super::*;

    /// 已知码命中：原文一字不改 + 文末附「码 — 结论：根因」。
    #[test]
    fn 已知码命中且原文保持原样() {
        let raw = "DISM 失败：Error 0x800f081f，详见日志";
        let out = annotate_error_codes(raw);
        assert!(out.starts_with(raw), "原句必须保持原样（流式输出与日志都靠它）: {out}");
        assert!(out.contains("【错误码注解】"), "命中必须带注解块: {out}");
        assert!(out.contains("0x800f081f — 找不到修复所需的源文件"), "注解必须带结论: {out}");
    }

    /// 边界（v3 §6 P1-6）：表内码被更长 hex 串包含时（后面多跟 hex 数字）
    /// 不许被截取命中——那正是「随机长 hex 串里躺着一段像码的数字」的形态。
    #[test]
    fn 更长hex串不截取命中() {
        let raw = "code 0x800f081ff end";
        assert_eq!(annotate_error_codes(raw), raw, "表内码被更长 hex 串包含时不得命中");
    }

    /// 随机 8 位 hex 没有 0x 前缀不得命中。
    #[test]
    fn 无前缀随机hex不命中() {
        let raw = "hash deadbeef done";
        assert_eq!(annotate_error_codes(raw), raw);
    }

    /// 表外码（形状合法但表里没有）不注解——宁可少说，不可说错。
    #[test]
    fn 表外码不注解() {
        let raw = "err 0xdeadbeef x";
        assert_eq!(annotate_error_codes(raw), raw);
    }

    /// 多个码逐条注解，同一码只出一条。
    #[test]
    fn 多码逐条注解且去重() {
        let out = annotate_error_codes("a 0x800f081f b 0x80073712 c 0x800f081f");
        assert_eq!(out.matches("【错误码注解】").count(), 1, "注解块只有一个");
        assert_eq!(out.matches("0x800f081f —").count(), 1, "同一码只注解一次");
        assert!(out.contains("0x80073712 — 组件存储损坏"), "第二个码也要注解: {out}");
    }

    /// 大小写与词边界：0X800F081F. 命中；括号贴脸命中；词内前缀不算。
    #[test]
    fn 大小写与词边界形态() {
        assert!(annotate_error_codes("0X800F081F.").contains("【错误码注解】"), "大写形态要命中");
        assert!(annotate_error_codes("(0x80070005)").contains("拒绝访问"), "括号贴脸要命中");
        assert!(
            !annotate_error_codes("x0x80070005").contains("【错误码注解】"),
            "词内 0x 不算独立码"
        );
    }
}
