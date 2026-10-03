//! cleanup:scan / cleanup:execute / 失败重试 / 条目明细 / 锁定进程检查与终止。
//!
//! 删除口径（改这里之前先读 AGENTS §3）：常规清理按 v3.3.0 用户裁定**固定永久删**，
//! `toRecycle` 恒 false —— 这是产品语义不是回归；除常规清理外一律回收站优先。
//! 扫描走 `trim_finder`，删前过 `engine::protect::is_path_protected`；
//! 计划上限（PLAN_CAP_* / EXECUTE_MAX_ITEMS）是防止一键盘爆掉的保护位。
//! 被占用的项走 check-locked / kill-locked-processes，终止进程只白名单内放行。

use crate::pwsh;
use crate::engine::{guard, log, protect};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tauri::Emitter;
use tauri::WebviewWindow;
use trim_finder::cleanup_scan;
use super::rules::*;
use super::state::*;
// ==================== cleanup:scan ====================

/// 扫描累积器（对照 cleanup:scan 的 data / planBuf / planTruncated / planTotalRows）
#[derive(Default)]
pub(super) struct ScanAccum {
    data: Vec<Value>,
    plan: HashMap<String, Vec<Value>>,
    plan_truncated: HashSet<String>,
    plan_total: usize,
    total: usize,
    /// v2-L4P-34（C-6）：畸形行计数——静默丢弃等于把「行协议被畸形输入打破」
    /// 伪装成「什么都没扫到」（与 finder.rs ScanTally 同口径）
    malformed: usize,
    /// 只留第一条畸形原因（畸形内容可能是任意长文本，不照抄进日志）
    first_malformed: Option<String>,
}

impl ScanAccum {
    fn count_malformed(&mut self, reason: &str) {
        self.malformed += 1;
        if self.first_malformed.is_none() {
            self.first_malformed = Some(reason.chars().take(200).collect());
        }
    }

    /// 按行解析（对照 `onEngineStdout`），返回本轮新增的 `@@ITEM@@`（用于推进度）
    fn ingest_line(&mut self, line: &str) -> Option<Value> {
        if let Some(rest) = line.strip_prefix("@@PLANFILE@@") {
            // 计划文件行只进主进程快照（渲染层不消费），受总量防呆上限约束
            if self.plan_total >= PLAN_CAP_TOTAL {
                return None;
            }
            let pf = match serde_json::from_str::<Value>(rest) {
                Ok(v) => v,
                Err(e) => {
                    self.count_malformed(&format!("@@PLANFILE@@ 行解析失败: {e}"));
                    return None;
                }
            };
            let id = pf.get("id").and_then(|v| v.as_str());
            let path = pf.get("path").and_then(|v| v.as_str());
            match (id, path) {
                (Some(id), Some(path)) => {
                    if id.chars().count() <= 160 && path.chars().count() <= 2000 {
                        let arr = self.plan.entry(id.to_string()).or_default();
                        if arr.len() < PLAN_CAP_PER_ITEM {
                            let size = js_num_or_zero(pf.get("size"));
                            arr.push(json!({ "path": path, "size": size as i64 }));
                            self.plan_total += 1;
                        } else if self.plan_truncated.insert(id.to_string()) {
                            log::write_log(
                                "warn",
                                &format!("可删文件清单超过 {PLAN_CAP_PER_ITEM} 条上限: {id}"),
                            );
                        }
                    } else {
                        // 2026-10-04 审计 §3.4：超长行原先**既不入清单也不计数、不告警**
                        // —— 与本函数上面 `count_malformed` 建立的「必须计数或告警」
                        // 基线（v2-L4P-34 C-6）矛盾。一条 >2000 字符的路径
                        // （`\\?\` + 深树，MAX_PATH 是 32767）就这么从「明细」列表和
                        // 占用检测候选集里消失，无任何痕迹。
                        self.count_malformed(&format!(
                            "@@PLANFILE@@ 行超长（id {} 字符 / path {} 字符，上限 160 / 2000）",
                            id.chars().count(),
                            path.chars().count()
                        ));
                    }
                }
                _ => self.count_malformed("@@PLANFILE@@ 行缺少 id 或 path 字段"),
            }
            return None;
        }
        let Some(rest) = line.strip_prefix("@@ITEM@@") else {
            return None;
        };
        let item = match serde_json::from_str::<Value>(rest) {
            Ok(v) => v,
            Err(e) => {
                self.count_malformed(&format!("@@ITEM@@ 行解析失败: {e}"));
                return None;
            }
        };
        let id_ok = item.get("id").map(js_truthy).unwrap_or(false);
        if !id_ok {
            self.count_malformed("@@ITEM@@ 行缺少 id 字段");
            return None;
        }
        self.data.push(item.clone());
        Some(item)
    }
}

/// 记账一行并按需推 `cleanup:scan-progress`（对照 sender.send('cleanup:scan-progress', …)）
pub(super) fn ingest_and_emit<R: tauri::Runtime>(accum: &Arc<Mutex<ScanAccum>>, window: &WebviewWindow<R>, line: &str) {
    let (item, done, total) = {
        let mut a = accum.lock().unwrap_or_else(|e| e.into_inner());
        let item = a.ingest_line(line);
        (item, a.data.len(), a.total)
    };
    if let Some(item) = item {
        let _ = window.emit(
            "cleanup:scan-progress",
            json!({ "done": done, "total": total, "item": item }),
        );
    }
}

/// 扫描主体（纯原生引擎；PS 回退已随 S3 删除，见 :11）
pub(super) fn do_cleanup_scan<R: tauri::Runtime>(window: &WebviewWindow<R>, label: &str, cats: Vec<String>) -> Value {
    let configured = load_paths_config();
    let rules = match rules_value() {
        Ok(r) => r,
        Err(e) => {
            log::write_log("error", &format!("扫描异常: {e}"));
            return json!({ "success": false, "message": e, "data": [] });
        }
    };
    let cats_json = json_text(&Value::from(cats.clone()));
    let cfg_json = json_text(&configured);
    let rules_json = json_text(&rules);
    let accum = Arc::new(Mutex::new(ScanAccum {
        total: cats.len(),
        ..Default::default()
    }));
    // 原生引擎：进程内直调 + 逐行回调推进度（不再 spawn finder.exe；B 批 sink 化后的数据入口）
    let hook_accum = accum.clone();
    let hook_window = window.clone();
    let hook: Option<Box<dyn FnMut(&str)>> = Some(Box::new(move |line: &str| {
        ingest_and_emit(&hook_accum, &hook_window, line);
    }));
    // S3：纯 Rust 原生
    //
    // 退出码非 0 的分支**就地 return**（下面没有第二个 `if code != 0`）：原实现
    // 在块外又判了一次 `code != 0`，而块内已经 return 了，那句恒假、且让 `code`
    // 在块外留一个看似有意义的绑定。2026-10-04 审计 §3.2 顺手删掉。
    let stderr = {
        let (code, _stdout, stderr) = cleanup_scan::run_json(&[cats_json, cfg_json], &rules_json, hook);
        if code != 0 {
            let msg = if stderr.trim().is_empty() { format!("退出码 {code}") } else { stderr.trim().to_string() };
            log::write_log("error", &format!("Rust 清理扫描失败: {msg}"));
            return json!({ "success": false, "message": format!("原生扫描失败: {msg}"), "data": [] });
        }
        stderr
    };
    // 2026-10-04 磁盘清理审计 §3.2：stderr 是扫描引擎**唯一**的 fail-closed 留痕通道，
    // 此前只在退出码非 0 时被读，成功路径直接丢弃 —— 而「扫描成功但某个条目空」
    // 恰恰只发生在成功路径（单条规则变量没解析 / pathPs 被拒 → 该条目 exists:false、
    // size:0，用户看到「有条目但一个文件都没扫到」）。引擎自己给的判据是
    // 「供『扫描命中、执行 0 删』类问题对账」，对账通道在对账最需要的时候是关的。
    //
    // 刻意记 `warn` 而不是 `error`：这些不是失败，是「已按规则降级并留痕」。
    // 空 stderr 是绝大多数扫描的常态，不要为它写一行日志。
    if !stderr.trim().is_empty() {
        log::write_log("warn", &format!("清理扫描留痕（已降级处理，非失败）:\n{}", stderr.trim()));
    }
    // 把可删文件清单并进条目（无清单的条目补空数组，执行/明细侧统一按数组消费）
    let (data, plan_total, malformed) = {
        let mut a = accum.lock().unwrap_or_else(|e| e.into_inner());
        let plan = std::mem::take(&mut a.plan);
        let truncated = std::mem::take(&mut a.plan_truncated);
        let mut data = std::mem::take(&mut a.data);
        for item in data.iter_mut() {
            let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let files = plan.get(&id).cloned().unwrap_or_default();
            if let Some(obj) = item.as_object_mut() {
                obj.insert("files".into(), Value::Array(files));
                if truncated.contains(&id) {
                    obj.insert("filesTruncated".into(), Value::Bool(true));
                }
            }
        }
        (data, a.plan_total, (a.malformed, a.first_malformed.take()))
    };
    // v2-L4P-34（C-6）：畸形行不再静默——计数进日志，UI 才能区分「真干净」与「协议被打破」
    if malformed.0 > 0 {
        log::write_log(
            "warn",
            &format!(
                "扫描行协议出现 {} 条畸形行（已丢弃），首因: {}",
                malformed.0,
                malformed.1.as_deref().unwrap_or("未知")
            ),
        );
    }
    log::write_log(
        "info",
        &format!(
            "扫描完成(rust): {} 项, 计划文件 {} 条",
            data.len(),
            plan_total
        ),
    );
    *snapshots().lock().unwrap_or_else(|e| e.into_inner()) =
        [(label.to_string(), snapshot_by_id(&data))].into_iter().collect();
    json!({ "success": true, "data": data })
}

/// cleanup:scan — 扫描可清理项（纯原生引擎；进度走 `cleanup:scan-progress`）
#[tauri::command]
pub async fn cleanup_scan<R: tauri::Runtime>(window: WebviewWindow<R>, categories: Option<Value>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg, "data": [] });
    }
    let cats: Option<Vec<String>> = categories.as_ref().and_then(|c| c.as_array()).and_then(|a| {
        if a.is_empty() || a.len() > 200 {
            return None;
        }
        let mut out = Vec::with_capacity(a.len());
        for v in a {
            let s = v.as_str()?;
            if s.chars().count() > 160 {
                return None;
            }
            out.push(s.to_string());
        }
        Some(out)
    });
    let Some(cats) = cats else {
        return json!({ "success": false, "message": "清理分类参数无效", "data": [] });
    };
    let label = window.label().to_string();
    // 审查 2-3：先置空桶，扫描成功后填充
    snapshots()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(label.clone(), HashMap::new());
    log::write_log("info", &format!("开始扫描: {}", cats.join(", ")));
    let win = window.clone();
    let task = tauri::async_runtime::spawn_blocking(move || do_cleanup_scan(&win, &label, cats));
    match task.await {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": e.to_string(), "data": [] }),
    }
}

// ==================== cleanup:execute ====================

/// 回收站失败项 → 本条目的统计（对照 perItem）
#[derive(Default, Clone)]
pub(super) struct RecycleStat {
    ok: usize,
    fail: usize,
    recycled_bytes: i64,
}

/// 把一个路径移入回收站（只进回收站，可还原）
///
/// 审查 v2-F1：形参收 `&Path` 而非 `&str` —— Windows 文件名是 UTF-16，`&str` 往返会让含
/// 孤立代理项的名字被 `to_string_lossy` 换成 U+FFFD，于是删不到真正那个文件。
pub(super) fn move_to_recycle_bin(path: &std::path::Path) -> Result<(), String> {
    trim_finder::scan::recycle::send_to_trash_os(path.as_os_str())
}

/// cleanup:execute — 执行清理（危险通道：快照校验 + 删除前刷盘 + **固定永久删**）
///
/// # `to_recycle` 为什么收下参数却恒为 false
///
/// v3.3.0 用户裁定：常规清理**固定永久删**，`toRecycle` 恒 false。此前这条裁定
/// 只在渲染层强制（`cleanup.js` 里 `const toRecycle = false;`），命令侧是
/// `to_recycle.unwrap_or(false)` —— 也就是**任何**传 `true` 的调用方都能翻转。
/// 审计 §3.6 把它钉到删除真正发生的地方。翻转的三个后果：
/// ① `TRASH_FAILURES` 被填充，而它是 `cleanup:retry-failed-delete`（**不可逆**的
///    永久删命令）的唯一来源；② 回收站模式下 `freed` 计的是「枚举到」而非
///    「删掉」的字节；③ 代码注释里「不可达」的说法只在 JS 层成立，下次重构
///    碰 IPC 签名就会继承一条活路径而不知情。
///
/// 参数**保留**是为了不破坏 `CHANNEL_MAP` 的载荷键（删字段会让渲染层与
/// `tauri-api.js` 两侧同时改，且旧版前端传了它会被静默吞掉）。收到 true 时
/// 如实回执并写日志，不静默改写 —— 让调用方知道自己的参数没生效。
#[tauri::command]
pub async fn cleanup_execute<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    items: Option<Value>,
    force: Option<bool>,
    to_recycle: Option<bool>,
    auto_rebuild: Option<bool>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let force = force.unwrap_or(false);
    if to_recycle == Some(true) {
        log::write_log(
            "warn",
            "cleanup:execute 收到 to_recycle=true，已按 v3.3.0 裁定忽略（常规清理固定永久删）",
        );
    }
    let to_recycle = false;
    let auto_rebuild = auto_rebuild.unwrap_or(false);
    let snapshot = snapshots()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&label)
        .cloned()
        .unwrap_or_default();
    let Some(safe_items) = validate_snapshot_items(items.as_ref(), &snapshot) else {
        return json!({ "success": false, "message": "清理项不是最近一次扫描结果，已拒绝执行" });
    };
    let rules = match rules_value() {
        Ok(r) => r,
        Err(e) => return json!({ "success": false, "message": e }),
    };
    log::write_log(
        "info",
        &format!(
            "开始清理: {} 项, force={force}, toRecycle={to_recycle}, autoRebuild={auto_rebuild}",
            safe_items.len()
        ),
    );
    log::flush_sync(); // 审查v4-L3：危险操作执行前强制刷盘

    let task = tauri::async_runtime::spawn_blocking(move || {
        // S3：纯 Rust 原生
        let out: Result<pwsh::PsOutput, String> = match crate::engine::native::cleanup_execute(&safe_items, &rules, to_recycle, auto_rebuild) {
            Ok(result) => {
                let mut stdout = String::new();
                for entry in &result.recycle_entries {
                    stdout.push_str(&format!("@@RECYCLE@@{}\n", serde_json::to_string(entry).unwrap_or_default()));
                }
                let data = json!({
                    "details": result.details,
                    "freed": result.freed,
                    "fileCount": result.file_count,
                });
                stdout.push_str(&serde_json::to_string(&data).unwrap_or_default());
                stdout.push('\n');
                Ok(pwsh::PsOutput { code: 0, stdout, stderr: String::new(), timed_out: false })
            }
            Err(e) => return json!({ "success": false, "message": format!("原生执行失败: {e}") }),
        };
        let ps = match out {
            Ok(p) => p,
            Err(e) => return json!({ "success": false, "message": e }),
        };
        if ps.code != 0 {
            log::write_log("error", &format!("清理失败: {}", ps.stderr.trim()));
            let msg = if ps.stderr.trim().is_empty() {
                "清理失败".to_string()
            } else {
                ps.stderr.trim().to_string()
            };
            return json!({ "success": false, "message": msg });
        }
        let raw = ps.stdout;
        let diag_stripped = crate::diag::extract_diag_lines(&raw, "cleanup.execute");
        let mut recycle_entries: Vec<Value> = Vec::new();
        let mut clean_lines: Vec<&str> = Vec::new();
        // 审查 L-22（2026-10-03 L4）：本段是 Electron 遗留协议的回环形状——原生结果被
        // 重新拼成 @@RECYCLE@@ 行再自己解析回来，等于「自己发的报文自己收」。畸形行若
        // 静默丢，删除结果行凭空消失且无任何痕迹，与 L-21 / apply.rs（M-1）同基线
        // 「必须计数或告警」。仅在 to_recycle=true（v2-M20 下死路径）被消费，所以只进
        // 日志、不改回执形状。空体行（to_string 失败的 unwrap_or_default 产物）同样计。
        let mut recycle_malformed = 0usize;
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("@@RECYCLE@@") {
                if rest.trim().is_empty() {
                    recycle_malformed += 1;
                    continue;
                }
                let Ok(entry) = serde_json::from_str::<Value>(rest) else {
                    recycle_malformed += 1;
                    continue;
                };
                let ok = entry
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(|p| !p.is_empty())
                    .unwrap_or(false);
                if ok {
                    recycle_entries.push(entry);
                } else {
                    recycle_malformed += 1;
                }
                continue;
            }
            clean_lines.push(line);
        }
        if recycle_malformed > 0 {
            log::write_log(
                "warn",
                &format!(
                    "清理回执含 {recycle_malformed} 条畸形 @@RECYCLE@@ 行，已跳过（原生结果回环协议异常）"
                ),
            );
        }
        let joined = clean_lines.join("\n");
        let body = if joined.trim().is_empty() {
            diag_stripped.trim().to_string()
        } else {
            joined.trim().to_string()
        };
        let Ok(mut data) = serde_json::from_str::<Value>(&body) else {
            return json!({ "success": false, "message": "解析结果失败", "raw": diag_stripped });
        };
        let mut failures: Vec<Value> = Vec::new();
        // 2026-10-04 审计 §3.6：`to_recycle` 已在上方钉成 `false`（`let to_recycle =
        // false;`），所以这个分支**恒不进入**。刻意保留而不是删掉，理由两条：
        // ① 「回收站优先」是本仓的红线口径（§3 除常规清理外一律回收站优先），
        //    万一将来某个域要复用这条链，闸门（`protect::is_path_protected` 逐条 +
        //    `TRASH_FAILURES` 记账）必须**已经在代码里**，不能等启用时再补；
        // ② 它是 `@@RECYCLE@@` 回环协议唯一的消费者，删掉会让那段解析变成纯死码，
        //    而协议形状的删除要单独一次有记录的改动（审计 §5.4 同族的谨慎）。
        // 但必须让它**看起来**是死的：下面那句 `debug_assert!(false)` 把「恒假」写进
        // 类型可验的位置 —— 有人日后把 `to_recycle` 改回变量时，debug 构建立刻响。
        debug_assert!(!to_recycle, "常规清理固定永久删（v3.3.0 裁定），回收站分支恒不可达");
        if to_recycle && !recycle_entries.is_empty() {
            let mut per_item: HashMap<String, RecycleStat> = HashMap::new();
            for entry in &recycle_entries {
                let path = entry.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let id = entry.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                // 审查 1-4：entry.path 来自脚本 stdout 解析，信任级别低于快照校验项
                if protect::is_path_protected(path) {
                    per_item.entry(id).or_default().fail += 1;
                    log::write_log("warn", &format!("拒绝移入回收站（受保护路径）: {path}"));
                    continue;
                }
                let st = per_item.entry(id).or_default();
                match move_to_recycle_bin(std::path::Path::new(path)) {
                    Ok(()) => {
                        st.recycled_bytes += js_num_or_zero(entry.get("size")) as i64;
                        st.ok += 1;
                        let is_dir = entry.get("isDir").and_then(|v| v.as_bool()).unwrap_or(false);
                        // 审查 v2-L15：这条重建支在当前产品语义下**不可达**——v2-M20 拍板常规清理
                        // 固定 toRecycle=false，于是清理走 `cleanup_execute.ps1`，而那条链自己会
                        // 重建目录（`$autoRebuild` → `Remove-PathSafely -AutoRebuild`，见 ps 的 :51/:800）。
                        // 留着它是因为「回收站优先」一旦重新启用就要在这里做同样的事，行为两边必须一致；
                        // 别把它当"忘了接线的功能"，也别据此删掉 PS 侧的那一份。
                        if is_dir && auto_rebuild {
                            let _ = std::fs::create_dir_all(path);
                        }
                    }
                    Err(e) => {
                        st.fail += 1;
                        failures.push(json!({
                            "id": entry.get("id").cloned().unwrap_or(Value::Null),
                            "path": path,
                            "size": js_num_or_zero(entry.get("size")) as i64,
                            "isDir": entry.get("isDir").and_then(|v| v.as_bool()).unwrap_or(false),
                        }));
                        log::write_log("warn", &format!("移入回收站失败: {path} -> {e}"));
                    }
                }
            }
            // J-1（S3）：写入本 label 分槽（Electron 用 sender.id），多窗口并发清理互不串台
            // v2-L4P-38（F-7）：**无条件覆盖**——只在本轮有失败时 insert 会让上一轮的
            // 失败路径留槽，下一轮全部成功时「重试失败项」仍重放旧路径（对已成功回收的
            // 目标二次操作）。本轮零失败即清槽，槽内永远是最近一轮的真实状态。
            if failures.is_empty() {
                trash_failures()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&label);
            } else {
                trash_failures()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(label.clone(), failures.clone());
            }
            let mut recycled_bytes = 0i64;
            let mut recycled_count = 0i64;
            let ids: Vec<String> = data
                .get("details")
                .and_then(|d| d.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|d| d.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string())
                        .collect()
                })
                .unwrap_or_default();
            if let Some(details) = data.get_mut("details").and_then(|d| d.as_array_mut()) {
                for (i, d) in details.iter_mut().enumerate() {
                    if d.get("status").and_then(|v| v.as_str()) != Some("recycle") {
                        continue;
                    }
                    let st = per_item.get(&ids[i]).cloned();
                    let Some(st) = st else {
                        if let Some(o) = d.as_object_mut() {
                            o.insert("status".into(), Value::from("ok"));
                            o.insert("freed".into(), Value::from(0));
                            o.insert("message".into(), Value::from("无可清理目标"));
                        }
                        continue;
                    };
                    recycled_bytes += st.recycled_bytes;
                    recycled_count += st.ok as i64;
                    let (status, message) = if st.fail == 0 {
                        ("ok", format!("已移入回收站（{} 项，可在系统回收站还原）", st.ok))
                    } else if st.ok > 0 {
                        (
                            "partial",
                            format!("已移入回收站 {} 项，{} 项失败（被占用）", st.ok, st.fail),
                        )
                    } else {
                        ("error", "移入回收站失败（可能被占用）".to_string())
                    };
                    if let Some(o) = d.as_object_mut() {
                        o.insert("freed".into(), Value::from(0)); // 审查 M-3：回收站不计入已释放空间
                        o.insert("recycledBytes".into(), Value::from(st.recycled_bytes));
                        o.insert("status".into(), Value::from(status));
                        o.insert("message".into(), Value::from(message));
                    }
                }
            }
            // v5 C-2：这里只回写「回收站专属」两项。totalFreed / success / partial / skipped
            // 曾在且只在这里写，而常规清理固定 toRecycle=false（AGENTS §3 v3.3.0 裁定）⇒
            // 这四个字段在永久删路径上**从不出现**，前端 `result.totalFreed || 0` 于是恒显
            // 「释放 0 B」。统一改由外层在 details 全部落定后无条件回写。
            if let Some(o) = data.as_object_mut() {
                o.insert("recycledBytes".into(), Value::from(recycled_bytes));
                o.insert("recycledCount".into(), Value::from(recycled_count));
            }
        }
        if let Some(o) = data.as_object_mut() {
            o.insert("trashFailures".into(), Value::Array(failures));
        }
        let (total_freed, success, n_partial, skipped) = summarize_details(&data);
        let n_residual = data
            .get("details")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|d| js_num_or_zero(d.get("residual")) > 0.0)
                    .count()
            })
            .unwrap_or(0);
        let failed = data
            .get("details")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    // v5 C-3：引擎侧的硬失败有**两种**写法 —— `"error"`（备份失败等前置中止）
                    // 与 `"fail"`（DISM 失败 / 注册表全失败 / 文件全被占用）。此前只数 error，
                    // 于是 `success: failed == 0` 把整批真失败渲染成成功提示。
                    .filter(|d| matches!(d.get("status").and_then(|v| v.as_str()), Some("error") | Some("fail")))
                    .count()
            })
            .unwrap_or(0);
        if let Some(o) = data.as_object_mut() {
            o.insert("failed".into(), Value::from(failed as i64));
            o.insert("partial".into(), Value::from(n_partial as i64));
            // v5 C-2：四个汇总字段一律无条件回写（永久删路径也要有 totalFreed / success /
            // skipped，否则前端恒显「释放 0 B」）
            o.insert("totalFreed".into(), Value::from(total_freed));
            o.insert("success".into(), Value::from(success));
            o.insert("skipped".into(), Value::from(skipped));
        }
        log::write_log(
            "info",
            &format!(
                "清理完成: 实测释放 {total_freed} 字节, 成功 {success}, 失败 {failed}, 部分成功 {n_partial}, 跳过 {skipped}, 有残留 {n_residual} 项"
            ),
        );
        if let Some(arr) = data.get("details").and_then(|d| d.as_array()) {
            for d in arr {
                let msg: String = d
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .chars()
                    .take(200)
                    .collect();
                let id = d.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let name = d
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| format!("（{}）", n.chars().take(60).collect::<String>()))
                    .unwrap_or_default();
                log::write_log(
                    "info",
                    &format!(
                        "  清理明细 [{}] {id}{name}: {msg}（释放 {} 字节, 残留 {}）",
                        d.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                        js_num_or_zero(d.get("freed")) as i64,
                        js_num_or_zero(d.get("residual")) as i64
                    ),
                );
            }
        }
        // 2026-10-04 审计 §4.3：确认清单（快照 files）与实际删除集（执行侧重遍历）
        // 的口径差逐条留痕 —— 不改语义（绑文件集是另一个裁定），只让「删了清单外
        // 的文件」这件事在日志里可对账。plan_delta_warnings 本体与断言在 state.rs。
        {
            let empty: Vec<Value> = Vec::new();
            let details = data.get("details").and_then(|d| d.as_array()).unwrap_or(&empty);
            for w in plan_delta_warnings(details, &snapshot) {
                log::write_log("warn", &w);
            }
        }
        // 成功判据：硬失败（error ∪ fail，见上面 v5 C-3）为 0 才算成功；
        // partial 属「部分成功」，由渲染层另行提示
        json!({ "success": failed == 0, "data": data })
    });
    match task.await {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": e.to_string() }),
    }
}

/// 按 details 汇总 (totalFreed, success, partial, skipped)（对照 main.js 1416-1423）
pub(super) fn summarize_details(data: &Value) -> (i64, usize, usize, usize) {
    let mut total = 0i64;
    let mut success = 0usize;
    let mut partial = 0usize;
    let mut skipped = 0usize;
    for d in data
        .get("details")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
    {
        total += js_num_or_zero(d.get("freed")) as i64;
        match d.get("status").and_then(|v| v.as_str()) {
            Some("ok") => success += 1,
            Some("partial") => partial += 1,
            Some("skip") => skipped += 1,
            _ => {}
        }
    }
    (total, success, partial, skipped)
}

// ==================== cleanup:retry-failed-delete ====================

/// cleanup:retry-failed-delete — 回收站失败项的永久删除重试（白名单只来自最近一次 execute）
///
/// 审查 L9：这条同步 `fn` 里对**任意**失败项跑 `remove_dir_all`。同步命令跑在主线程，
/// 一个大目录能让 UI 整段冻结（且用户此刻正盯着进度），故整体挪进 `spawn_blocking`。
/// 渲染层本来就是 `invoke` 拿 Promise，改异步对 JS 侧零影响。
#[tauri::command]
pub async fn cleanup_retry_failed_delete<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let targets = trash_failures()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&label)
        .unwrap_or_default();
    if targets.is_empty() {
        return json!({ "success": false, "message": "没有待重试的失败项" });
    }
    let task = tauri::async_runtime::spawn_blocking(move || {
        retry_failed_delete_blocking(targets)
    });
    match task.await {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": format!("删除任务异常终止: {e}") }),
    }
}

pub(super) fn retry_failed_delete_blocking(targets: Vec<Value>) -> Value {
    log::write_log("warn", &format!("开始永久删除回收站失败项: {} 项", targets.len()));
    log::flush_sync(); // 审查v4-L3：危险操作执行前强制刷盘
    let mut freed = 0i64;
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut details: Vec<Value> = Vec::new();
    for t in targets {
        let path = t.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let is_dir = t.get("isDir").and_then(|v| v.as_bool()).unwrap_or(false);
        if !Path::new(&path).exists() {
            details.push(json!({ "path": path, "status": "skip", "freed": 0, "message": "文件不存在" }));
            continue;
        }
        if protect::is_path_protected(&path) {
            failed += 1;
            log::write_log("warn", &format!("受保护路径，拒绝删除: {path}"));
            details.push(json!({ "path": path, "status": "error", "freed": 0, "message": "受保护路径，已拒绝" }));
            continue;
        }
        let size = std::fs::symlink_metadata(&path).map(|m| m.len() as i64).unwrap_or(0);
        let rm = if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match rm {
            Ok(()) => {
                freed += size;
                ok += 1;
                details.push(json!({ "path": path, "status": "ok", "freed": size }));
                log::write_log("warn", &format!("回收站失败项经用户确认后永久删除: {path}"));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // fs.rmSync(force:true) 忽略 ENOENT
                ok += 1;
                details.push(json!({ "path": path, "status": "ok", "freed": 0 }));
            }
            Err(e) => {
                failed += 1;
                details.push(json!({ "path": path, "status": "error", "freed": 0, "message": e.to_string() }));
            }
        }
    }
    json!({
        "success": failed == 0,
        "data": { "totalFreed": freed, "ok": ok, "failed": failed, "details": details }
    })
}

// ==================== cleanup:item-detail ====================

/// cleanup:item-detail — 枚举单个条目将删除的文件清单（只读）
#[tauri::command]
pub async fn cleanup_item_detail<R: tauri::Runtime>(window: WebviewWindow<R>, id: Option<String>, path: Option<String>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let id = match id {
        Some(s) if !s.is_empty() && s.chars().count() <= 160 => s,
        _ => return json!({ "success": false, "message": "参数无效" }),
    };
    let rules = rules_value().unwrap_or_else(|_| json!({}));
    // v2.2 第3批（D13）：fileKeys 条目明细直接读扫描快照里的可删文件清单——明细与执行同源
    let (known_files, has_known) = {
        let buckets = snapshots().lock().unwrap_or_else(|e| e.into_inner());
        let known = buckets
            .get(window.label())
            .and_then(|m| m.get(&id))
            .and_then(|it| it.get("files"))
            .and_then(|f| f.as_array())
            .cloned();
        match known {
            Some(f) => (f, true),
            None => (Vec::new(), false),
        }
    };
    let rule = find_cleanup_rule_by_id(&rules, &id);
    let rule_file_keys_non_empty = rule
        .as_ref()
        .and_then(|r| r.get("fileKeys"))
        .and_then(|f| f.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if rule_file_keys_non_empty && has_known {
        let cap = 600usize; // 与 DETAIL_SCRIPT 的明细上限一致
        let files: Vec<Value> = known_files
            .iter()
            .take(cap)
            .map(|f| {
                json!({
                    "path": f.get("path").cloned().unwrap_or(Value::Null),
                    "size": f.get("size").cloned().unwrap_or(Value::from(0)),
                })
            })
            .collect();
        return json!({
            "success": true,
            "data": {
                "kind": "files",
                "total": known_files.len(),
                "truncated": known_files.len() > cap,
                "files": files
            }
        });
    }
    let safe_path = match path {
        Some(p) if !p.is_empty() && p.chars().count() <= 600 => p,
        _ => String::new(),
    };
    // S3：纯 Rust 原生
    if let Some(rule) = find_cleanup_rule_by_id(&rules, &id) {
        match crate::engine::native::cleanup_detail(&rule, &safe_path) {
            Ok(detail) => return json!({ "success": true, "data": detail }),
            Err(e) => return json!({ "success": false, "message": format!("原生枚举失败: {e}") }),
        }
    }
    json!({ "success": false, "message": "未找到清理规则" })
}

// ==================== cleanup:check-locked / kill-locked-processes ====================

/// cleanup:check-locked — 清理前占用检测（只读；PID 白名单仅供紧随其后的结束进程使用）
#[tauri::command]
pub async fn cleanup_check_locked<R: tauri::Runtime>(window: WebviewWindow<R>, ids: Option<Value>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let snapshot = snapshots()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&label)
        .cloned()
        .unwrap_or_default();
    // 2026-10-04 磁盘清理审计 §3.5：候选装配已抽成纯函数 `collect_lock_candidates`
    // （state.rs），上限与去重在**装配过程中**生效 —— 原实现先把 ids 展开完再施加
    // PLAN_LOCK_CAP，而 ids 无长度限制、无去重，单条目 fileKeys 上限 10 万 ⇒
    // 渲染层一次 Array(200000).fill(<已扫 id>) 就能堆 2×10¹⁰ 个 Value 把主进程打爆。
    // 抽成纯函数也是因为这个形状**没法用集成测试验**（测它等于真 OOM 一次），
    // 只能在无盘无 IPC 的纯函数上钉住。口径与理由见该函数注释。
    let (files, truncated) = collect_lock_candidates(ids.as_ref(), &snapshot, PLAN_LOCK_CAP);
    if truncated {
        log::write_log(
            "warn",
            &format!("占用检测：候选装配被截断（上限 {PLAN_LOCK_CAP} 个文件），面板会标「已截断」"),
        );
    }
    lock_whitelist()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(label.clone(), Vec::new());
    // 截断信号由纯函数在装配过程中给出（见 collect_lock_candidates 的注释：
    // 装配后再比 len() 会让那句比较恒假、「被截断」永远报 false）
    if files.is_empty() {
        return json!({
            "success": true, "locked": [], "byApp": {}, "procs": [],
            "lockedByItem": {}, "scanned": 0, "truncated": truncated
        });
    }
    let list: Vec<Value> = files;
    let scanned = list.len();
    let payload = json_text(&json!({ "files": list }));
    let win = window.clone();
    let task = tauri::async_runtime::spawn_blocking(move || {
        let (code, stdout, stderr) = cleanup_scan::checklocked_json(&payload);
        if code != 0 {
            let msg = if stderr.trim().is_empty() {
                format!("占用检测退出码 {code}")
            } else {
                stderr.trim().to_string()
            };
            return (None, msg);
        }
        let mut locked: Vec<Value> = Vec::new();
        let mut locked_by_item: Map<String, Value> = Map::new();
        let mut by_app: Map<String, Value> = Map::new();
        let mut procs: Vec<Value> = Vec::new();
        let mut seen_pids: HashSet<i64> = HashSet::new();
        let self_pid = std::process::id() as i64;
        // 审查 L-21（2026-10-03 L4）：畸形行不许静默丢——与 ScanAccum（v2-L4P-34）、
        // apply.rs（M-1）同基线（「必须计数或告警」）。来源是进程内 native-scanner 自产
        // （checklocked_body 已走 jstr 转义），畸形仅可能意味着扫描器自身 bug，warn 留痕
        // 即可让审计可见，不必改回执形状。
        let mut malformed = 0usize;
        for line in stdout.lines() {
            // 前缀 '@@LOCKED@@' 恰 10 字符（勿与 '@@PLANFILE@@' 的 12 混淆）
            let Some(rest) = line.strip_prefix("@@LOCKED@@") else {
                continue;
            };
            let Ok(pf) = serde_json::from_str::<Value>(rest) else {
                malformed += 1;
                continue;
            };
            let Some(path) = pf.get("path").and_then(|v| v.as_str()) else {
                malformed += 1;
                continue;
            };
            if path.is_empty() {
                malformed += 1;
                continue;
            }
            let id = pf.get("id").and_then(|v| v.as_str()).unwrap_or("");
            locked.push(pf.clone());
            if !id.is_empty() {
                let n = locked_by_item.get(id).map(js_number).unwrap_or(0.0) + 1.0;
                locked_by_item.insert(id.to_string(), Value::from(n as i64));
            }
            for p in pf.get("procs").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
                let pid = match p.get("pid").and_then(|v| v.as_i64()) {
                    Some(v) => v,
                    None => continue,
                };
                let app = p.get("app").and_then(|v| v.as_str()).unwrap_or("");
                if app.is_empty() {
                    continue;
                }
                // v3.7.3 修复①：RM 总会把调用方列入占用者名单——剔除自身 PID
                if pid == self_pid {
                    continue;
                }
                // v3.7.3 修复②：explorer 命中即 critical（只展示、无结束入口）。
                // 2026-09-30 补：再并上扫描器按 RM ApplicationType 判出的 critical
                // （RmCritical=1000）——此前这个字段整条被丢掉，「系统关键进程」实际只认
                // explorer 一个名字，lsass/csrss 这类真关键进程会被列进可结束名单。
                // 名字规则仍要保留：实测 RM 对 explorer 报的是 Application 不是 RmCritical。
                let critical = p.get("critical").and_then(|v| v.as_bool()).unwrap_or(false)
                    || app.to_lowercase().contains("explorer")
                    || app.contains("资源管理器");
                let n = by_app.get(app).map(js_number).unwrap_or(0.0) + 1.0;
                by_app.insert(app.to_string(), Value::from(n as i64));
                if seen_pids.insert(pid) {
                    procs.push(json!({ "pid": pid, "app": app, "critical": critical }));
                }
            }
        }
        let whitelist: Vec<Value> = procs
            .iter()
            .filter(|p| p.get("critical").and_then(|v| v.as_bool()) == Some(false))
            .cloned()
            .collect();
        if malformed > 0 {
            log::write_log(
                "warn",
                &format!("占用检测输出含 {malformed} 条畸形 @@LOCKED@@ 行，已跳过（扫描器协议异常）"),
            );
        }
        (Some((locked, by_app, procs, locked_by_item, whitelist)), String::new())
    });
    let (payload, err) = match task.await {
        Ok(v) => v,
        Err(e) => return json!({ "success": false, "message": e.to_string() }),
    };
    let Some((locked, by_app, procs, locked_by_item, whitelist)) = payload else {
        return json!({ "success": false, "message": err });
    };
    // 白名单每次检测覆盖（防「检测 A 文件后延时结束 B 进程」的窗口）
    lock_whitelist()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(win.label().to_string(), whitelist);
    json!({
        "success": true,
        "locked": locked,
        "byApp": Value::Object(by_app),
        "procs": procs,
        "lockedByItem": Value::Object(locked_by_item),
        "scanned": scanned,
        "truncated": truncated
    })
}

/// 结束进程用的 kernel32 绑定（零依赖原则：手写 FFI，与 native-scanner 同风格）
#[cfg(windows)]
pub(super) mod kill_ffi {
    #[link(name = "kernel32")]
    extern "system" {
        pub fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> isize;
        pub fn TerminateProcess(process: isize, exit_code: u32) -> i32;
        pub fn CloseHandle(object: isize) -> i32;
    }
}

/// 结束进程（TerminateProcess；等价 Node `process.kill(pid)`）
#[cfg(windows)]
pub(super) fn terminate_process(pid: i64) -> Result<(), String> {
    if pid <= 0 || pid > u32::MAX as i64 {
        return Err("无效的进程 ID".to_string());
    }
    const PROCESS_TERMINATE: u32 = 0x0001;
    unsafe {
        let h = kill_ffi::OpenProcess(PROCESS_TERMINATE, 0, pid as u32);
        if h == 0 {
            return Err("无法打开目标进程（可能已退出或缺权限）".to_string());
        }
        let rc = kill_ffi::TerminateProcess(h, 1);
        kill_ffi::CloseHandle(h);
        if rc == 0 {
            return Err("结束进程失败".to_string());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn terminate_process(_pid: i64) -> Result<(), String> {
    Err("仅支持 Windows".to_string())
}

/// cleanup:kill-locked-processes — 结束最近一次占用检测确认过的非关键进程（一次性白名单）
#[tauri::command]
pub fn cleanup_kill_locked_processes<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let targets = lock_whitelist()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&label)
        .unwrap_or_default();
    if targets.is_empty() {
        return json!({ "success": true, "killed": [], "failed": [] });
    }
    let self_pid = std::process::id() as i64;
    let mut killed: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    for p in targets {
        let pid = p.get("pid").and_then(|v| v.as_i64()).unwrap_or(-1);
        // v3.7.3 兜底：检测侧已剔除自身 PID，这里再挡一道——任何路径下都不允许 kill 自己
        if pid == self_pid {
            continue;
        }
        match terminate_process(pid) {
            Ok(()) => killed.push(p),
            Err(e) => {
                let mut v = p.clone();
                if let Some(o) = v.as_object_mut() {
                    o.insert("message".into(), Value::from(e));
                }
                failed.push(v);
            }
        }
    }
    let fail_note = if failed.is_empty() {
        String::new()
    } else {
        format!(
            "，失败 {} 个（{}）",
            failed.len(),
            failed
                .iter()
                .map(|f| format!(
                    "{}#{}",
                    f.get("app").and_then(|v| v.as_str()).unwrap_or(""),
                    f.get("pid").and_then(|v| v.as_i64()).unwrap_or(0)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    log::write_log(
        "warn",
        &format!("结束占用进程（用户确认）: 成功 {} 个{fail_note}", killed.len()),
    );
    json!({ "success": true, "killed": killed, "failed": failed })
}

