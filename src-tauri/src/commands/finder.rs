//! finder 域（B 批）：finder:scan / finder:delete / finder:delete-manifest / finder:open-backup-dir
//!
//! 对照 Electron `main.js` 2044-2352（含 helper 1792-1919 / 2160-2218）。
//! 迁移要点：
//! - **扫描引擎改为进程内直调**（不再 spawn `finder.exe`）：`trim_finder::scan::*` +
//!   本文件的 `FinderSink`（输出汇聚器）。行协议仍是逐字一致的 `@@ITEM@@{json}`，故
//!   `item()` 只认 `@@ITEM@@` 行并 `serde_json` 收进 Vec，解析口径与 `runRustScanner` 对齐；
//!   `@@PROGRESS:n@@` / `@@SCANNED:n@@` 改由 `progress`/`scanned` 回调 **emit 调用方窗口** 的
//!   `finder:progress` 事件（载荷字段与现版逐字段一致：`{scanType, progress}` / `{scanType, scanned}`）。
//! - **扫描快照槽**：按 `window.label()` 分槽（Electron 按 `sender.id`），键 =
//!   `path.resolve(item.path).toLowerCase()`，删除只认本槽内的路径（跨窗口/跨页签互不覆盖）。
//! - **删除三端同源**：受保护路径判定走 `engine::protect`（`is_path_protected`），
//!   并把 `protected_roots_json()` 注入原生删除侧。
//! - 删除清单落 `engine::paths::app_data_dir()/fileclean-backup/deleted-<batchId>.json`
//!   （D5 后数据目录为 Tauri identifier 目录；原子写 + 只留最近 50 个批次）。
//!
//! 需在 `lib.rs` 的 `generate_handler!` 注册：
//! ```ignore
//! commands::finder::finder_scan,
//! commands::finder::finder_delete,
//! commands::finder::finder_delete_manifest,
//! commands::finder::finder_open_backup_dir,
//! ```
//!
//! 与 Electron 的差异（已在迁移方案登记）：
//! 1. 无 5 分钟超时兜底——进程内直调无法 kill 扫描线程，大盘扫描会一直跑到结束（不再出现
//!    「扫描超时」文案）；进度/心跳事件补偿了可观测性。
//! 2. 快照键的 `path.resolve` CWD 基准用 `std::env::current_dir()`；实际入参恒为绝对路径，
//!    相对路径场景与 Electron 同属「取决于进程 CWD」的未定义行为。
//! 3. `\\?\` 前缀：扫描输出经 `unix_path` 已剥离；本文件的键函数也剥（Node `path.resolve`
//!    保留原样），即带前缀的删除请求在不带前缀的快照里能命中——语义同一路径，属放宽而非放行。

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};
use tauri::{Emitter, WebviewWindow};
use trim_finder::scan::{self, Sink};

use crate::engine::delete_manifest;
use crate::engine::{guard, log, protect};

/// 合法扫描类型（对照 FINDER_SCAN_TYPES）
const FINDER_SCAN_TYPES: [&str; 4] = ["duplicates", "bigfiles", "empty", "appdata"];
/// 重复文件内置扫描目录：缺哪个跳哪个，全缺则报错（对照 FINDER_DEFAULT_DUP_DIRS）
const FINDER_DEFAULT_DUP_DIRS: [&str; 4] = [
    "%USERPROFILE%\\Downloads",
    "%USERPROFILE%\\Desktop",
    "%USERPROFILE%\\Documents",
    "%USERPROFILE%\\Pictures",
];
/// 单槽上限：防无界累积，超限按 ts 清掉最老的一半（对照 FINDER_SNAPSHOT_SLOT_MAX）
const FINDER_SNAPSHOT_SLOT_MAX: usize = 500_000;
/// 删除请求最多 500 项 / 扫描目录最多 50 个 / 单条路径最长 400 字符
const FINDER_DELETE_MAX: usize = 500;
const FINDER_PATHS_MAX: usize = 50;
const FINDER_PATH_MAX_LEN: usize = 400;
/// 清单读取最多扁平化 200 条（对照 finder:delete-manifest 的 200 上限）
const FINDER_MANIFEST_READ_MAX: usize = 200;

// ==================== 扫描快照槽（本窗口专属） ====================

#[derive(Clone)]
struct SnapEntry {
    /// 原始路径（保持扫描输出的正斜杠形态，删除详情与渲染层据此匹配）
    path: String,
    /// "dir" | "file"
    kind: String,
    /// 空目录标记（删除前需做「是否已不再为空」复检）
    empty: bool,
    ts: i64,
}

/// label -> (规范化小写路径 -> 条目)。Electron 用 Map（插入序 + 按 ts 清理）；
/// 这里用 HashMap，清理时显式按 ts 排序，语义等价且查找 O(1)。
static SNAPSHOTS: OnceLock<Mutex<HashMap<String, HashMap<String, SnapEntry>>>> = OnceLock::new();

fn snapshots() -> &'static Mutex<HashMap<String, HashMap<String, SnapEntry>>> {
    SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 结果写入本窗口快照槽（累积合并，不整体重置——对齐 FD-7）。返回槽内条目数。
fn store_snapshot(label: &str, items: &[Value], ts: i64) -> usize {
    let mut store = snapshots().lock().unwrap_or_else(|e| e.into_inner());
    let slot = store.entry(label.to_string()).or_default();
    for item in items {
        let Some(p) = item.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        // emptyfolder 与 appdata 类型算目录；仅 emptyfolder 带 empty 标记
        let t = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
        slot.insert(
            path_key(p),
            SnapEntry {
                path: p.to_string(),
                kind: if t == "emptyfolder" || t == "appdata" {
                    "dir".to_string()
                } else {
                    "file".to_string()
                },
                empty: t == "emptyfolder",
                ts,
            },
        );
    }
    if slot.len() > FINDER_SNAPSHOT_SLOT_MAX {
        let mut entries: Vec<(String, i64)> = slot.iter().map(|(k, v)| (k.clone(), v.ts)).collect();
        entries.sort_by_key(|(_, ts)| *ts);
        for (key, _) in entries.iter().take(entries.len() / 2) {
            slot.remove(key);
        }
    }
    slot.len()
}

/// 键函数：`path.resolve(p).toLowerCase()` 的等价物。
/// 仅字符串层折叠（不触盘）：剥 `\\?\` 前缀 → 相对路径拼 CWD → 拆盘符/UNC 前缀 →
/// 折叠 `.`/`..` → 统一分隔符 → 去尾斜杠 → 小写。
fn path_key(p: &str) -> String {
    let stripped = if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = p.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        p.to_string()
    };
    let mut text = stripped;
    let rooted = text.starts_with('\\')
        || text.starts_with('/')
        || text
            .as_bytes()
            .get(0..2)
            .map(|b| b[0].is_ascii_alphabetic() && b[1] == b':')
            .unwrap_or(false);
    if !rooted {
        // 相对路径按进程 CWD 解析（对照 Node path.resolve 的 CWD 基准）
        if let Ok(cwd) = std::env::current_dir() {
            text = format!("{}\\{}", cwd.to_string_lossy(), text);
        }
    }
    // 不可折叠的根前缀：盘符（X:）或 UNC（\\server\share）
    let bytes = text.as_bytes();
    let mut prefix_len = 0usize;
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        prefix_len = 2;
    } else if text.starts_with(r"\\") {
        let parts: Vec<&str> = text[2..]
            .split(|c| c == '\\' || c == '/')
            .filter(|c| !c.is_empty())
            .collect();
        if parts.len() >= 2 {
            prefix_len = 2 + parts[0].len() + 1 + parts[1].len();
        }
    }
    let (prefix, body) = text.split_at(prefix_len.min(text.len()));
    let mut segs: Vec<&str> = Vec::new();
    for c in body.split(|c| c == '\\' || c == '/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c == ".." {
            segs.pop();
            continue;
        }
        segs.push(c);
    }
    let joined = segs.join("\\");
    let full = if prefix.is_empty() {
        joined
    } else if joined.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}\\{joined}")
    };
    full.to_lowercase()
}

// ==================== 输出汇聚器（Sink） ====================

/// `trim_finder::scan` 的输出汇聚器实现体。
/// - `item`：只收 `@@ITEM@@` 行（剥前缀后解析），其余行忽略——与 `runRustScanner` 同口径
/// - `progress`/`scanned`：改走 `finder:progress` 事件（删除通道不发，对齐 Electron 未传回调）
/// - `warn`：写日志
struct FinderSink<R: tauri::Runtime> {
    window: WebviewWindow<R>,
    /// None = 不向前端发事件（删除通道）
    scan_type: Option<String>,
    items: Mutex<Vec<Value>>,
}

impl<R: tauri::Runtime> FinderSink<R> {
    fn for_scan(window: WebviewWindow<R>, scan_type: &str) -> Self {
        Self {
            window,
            scan_type: Some(scan_type.to_string()),
            items: Mutex::new(Vec::new()),
        }
    }

    fn for_delete(window: WebviewWindow<R>) -> Self {
        Self {
            window,
            scan_type: None,
            items: Mutex::new(Vec::new()),
        }
    }

    fn take_items(&self) -> Vec<Value> {
        std::mem::take(&mut *self.items.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn emit_progress(&self, payload: Value) {
        // 调用方窗口已销毁时 emit 失败，忽略（对齐 Electron 的 sender.isDestroyed() 判断）
        let _ = self.window.emit("finder:progress", payload);
    }
}

impl<R: tauri::Runtime> Sink for FinderSink<R> {
    fn item(&self, line: &str) {
        let Some(rest) = line.strip_prefix("@@ITEM@@") else {
            return;
        };
        if let Ok(v) = serde_json::from_str::<Value>(rest.trim()) {
            self.items.lock().unwrap_or_else(|e| e.into_inner()).push(v);
        }
    }

    fn progress(&self, n: u64) {
        if let Some(st) = self.scan_type.as_deref() {
            self.emit_progress(json!({ "scanType": st, "progress": n }));
        }
    }

    fn scanned(&self, n: u64) {
        if let Some(st) = self.scan_type.as_deref() {
            self.emit_progress(json!({ "scanType": st, "scanned": n }));
        }
    }

    fn warn(&self, msg: &str) {
        log::write_log("warn", msg);
    }
}

// ==================== finder:scan ====================

/// finder:scan — 四类扫描（duplicates/bigfiles/empty/appdata）。
/// 参数校验与默认值语义逐条对齐 Electron（`Math.max` / `Number(x) || default`）。
#[tauri::command]
pub async fn finder_scan<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    scan_type: String,
    paths: Option<Vec<Value>>,
    min_size: Option<Value>,
    count: Option<Value>,
    min_size_mb: Option<Value>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    if !FINDER_SCAN_TYPES.contains(&scan_type.as_str()) {
        return json!({ "success": false, "message": "未知扫描类型" });
    }
    // 路径归一：trim → 丢空串与超长 → 展开 %VAR% → 最多 50 个
    let mut plist: Vec<String> = paths
        .unwrap_or_default()
        .iter()
        .map(js_string)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.chars().count() <= FINDER_PATH_MAX_LEN)
        .map(|s| expand_env_path(&s))
        .take(FINDER_PATHS_MAX)
        .collect();

    // 默认值：--min-size 0 / --count 50 / --min-size-mb 10（对照 Math.max 语义）
    let mut min_size_arg = 0u64;
    let mut count_arg = 50usize;
    let mut min_size_mb_arg = 10u64;

    match scan_type.as_str() {
        "duplicates" => {
            if plist.is_empty() {
                // 输入为「默认」占位：解析内置目录，缺哪个跳哪个，全缺则报错
                let defaults: Vec<String> = FINDER_DEFAULT_DUP_DIRS.iter().map(|d| expand_env_path(d)).collect();
                let (found, missing) = resolve_existing_dirs(&defaults);
                if !missing.is_empty() {
                    log::write_log("info", &format!("finder 默认目录缺失跳过: {}", missing.join(", ")));
                }
                if found.is_empty() {
                    log::write_log("warn", "finder 默认扫描目录均不存在");
                    return json!({
                        "success": false,
                        "message": "默认扫描目录均不存在（Downloads/Desktop/Documents/Pictures），请在「扫描目录」中手动填写"
                    });
                }
                plist = found;
            } else {
                // 自填目录同样跳过不存在的，全部无效时报错
                let (found, missing) = resolve_existing_dirs(&plist);
                if !missing.is_empty() {
                    log::write_log("info", &format!("finder 指定目录缺失跳过: {}", missing.join(", ")));
                }
                if found.is_empty() {
                    return json!({ "success": false, "message": "指定的扫描目录均不存在，请检查路径" });
                }
                plist = found;
            }
            min_size_arg = num_or(min_size.as_ref(), 0.0).max(0.0) as u64;
        }
        "bigfiles" => {
            if plist.is_empty() {
                return json!({ "success": false, "message": "至少需要一个扫描目录" });
            }
            count_arg = num_or(count.as_ref(), 50.0).max(1.0) as usize;
        }
        "appdata" => {
            min_size_mb_arg = num_or(min_size_mb.as_ref(), 10.0).max(1.0) as u64;
        }
        _ => {
            // empty：无额外参数
            if plist.is_empty() {
                return json!({ "success": false, "message": "至少需要一个扫描目录" });
            }
        }
    }

    log::write_log(
        "info",
        &format!(
            "finder {} 开始扫描: {}",
            scan_type,
            if plist.is_empty() { "(AppData)".to_string() } else { plist.join(", ") }
        ),
    );

    // 大盘扫描是长时间阻塞任务：放进 spawn_blocking，事件从阻塞线程 emit
    let label = window.label().to_string();
    let sink = FinderSink::for_scan(window.clone(), &scan_type);
    let kind = scan_type.clone();
    let roots = plist.clone();
    let scanned = tauri::async_runtime::spawn_blocking(move || {
        match kind.as_str() {
            "duplicates" => scan::duplicates(&roots, min_size_arg, &sink),
            "bigfiles" => scan::bigfiles(&roots, count_arg, &sink),
            "empty" => scan::empty(&roots, &sink),
            _ => scan::appdata(min_size_mb_arg, &sink),
        }
        sink.take_items()
    })
    .await;

    let items = match scanned {
        Ok(v) => v,
        Err(e) => {
            log::write_log("error", &format!("finder {scan_type} 失败: {e}"));
            return json!({ "success": false, "message": format!("扫描失败: {e}") });
        }
    };

    let slot_size = store_snapshot(&label, &items, crate::engine::now_ms());
    log::write_log(
        "info",
        &format!("finder {scan_type} 完成: {} 项（快照槽 {} 条）", items.len(), slot_size),
    );
    json!({ "success": true, "data": items })
}

// ==================== finder:delete ====================

/// finder:delete — 危险通道：快照命中 + 受保护路径 + 删除前预检三重 Rust 侧权威校验。
#[tauri::command]
pub async fn finder_delete<R: tauri::Runtime>(window: WebviewWindow<R>, items: Option<Vec<Value>>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let requested: Vec<Value> = items
        .unwrap_or_default()
        .into_iter()
        .filter(|it| it.get("path").map(|p| p.is_string()).unwrap_or(false))
        .take(FINDER_DELETE_MAX)
        .collect();

    let label = window.label().to_string();
    // 只认本窗口快照槽内的路径（跨窗口/跨页签互不覆盖）
    let known: Vec<Option<SnapEntry>> = {
        let store = snapshots().lock().unwrap_or_else(|e| e.into_inner());
        let slot = store.get(&label);
        requested
            .iter()
            .map(|it| {
                let p = it.get("path").and_then(|v| v.as_str()).unwrap_or("");
                slot.and_then(|m| m.get(&path_key(p))).cloned()
            })
            .collect()
    };
    if known.iter().any(|k| k.is_none()) {
        return json!({ "success": false, "message": "删除目标已过期，请重新扫描后再试" });
    }
    let valid_safe: Vec<SnapEntry> = known.into_iter().flatten().collect();
    if valid_safe.is_empty() {
        return json!({ "success": false, "message": "没有可删除的项" });
    }
    // 受保护路径：命中即整批拒绝（与 Electron 文案一致）
    if let Some(hit) = valid_safe.iter().find(|it| protect::is_path_protected(&it.path)) {
        log::write_log("warn", &format!("finder 删除拒绝: 受保护路径 {}", hit.path));
        return json!({
            "success": false,
            "message": format!("包含受保护的系统路径，已拒绝：{}", hit.path)
        });
    }

    // 删除前预检（FD-4）：目标不存在/类型不符/空目录已非空 → 跳过
    let mut preflight: Vec<SnapEntry> = Vec::new();
    for it in &valid_safe {
        match std::fs::metadata(&it.path) {
            Ok(md) => {
                if it.kind == "dir" && !md.is_dir() {
                    continue; // 类型不符：跳过
                }
                if it.kind == "file" && !md.is_file() {
                    continue;
                }
                // TOCTOU 剩留场景：「扫描时空、删除时已非空」的目标跳过，
                // 防止把扫描后新放入的内容整棵连进回收站
                if it.empty && it.kind == "dir" {
                    let child_count = std::fs::read_dir(&it.path).map(|r| r.count()).unwrap_or(0);
                    if child_count > 0 {
                        log::write_log(
                            "warn",
                            &format!(
                                "finder 删除预检: 空目录已不再为空（{} 项），跳过 -> {}",
                                child_count, it.path
                            ),
                        );
                        continue;
                    }
                }
                preflight.push(it.clone());
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    log::write_log("warn", &format!("finder 删除预检: 目标已不存在，跳过 -> {}", it.path));
                } else {
                    log::write_log("warn", &format!("finder 删除预检失败: {} -> {e}", it.path));
                }
            }
        }
    }
    if preflight.is_empty() {
        return json!({
            "success": true,
            "data": {
                "totalFreed": 0, "success": 0, "failed": 0,
                "skipped": valid_safe.len(), "recycled": 0,
                "details": [], "manifestPath": null
            }
        });
    }

    log::write_log("info", &format!("finder 删除(原生): {} 项", preflight.len()));
    log::flush_sync(); // 危险操作执行前强制刷盘（审查v4-L3）

    let pairs: Vec<(String, OsString)> = preflight
        .iter()
        .map(|it| (if it.kind == "dir" { "dir".to_string() } else { "file".to_string() }, OsString::from(it.path.clone())))
        .collect();
    // 保护清单注入原生删除侧（三端同源：JS 判定 / 原生删除 / PS 执行）
    let protect_json = protect::protected_roots_json();
    let sink = FinderSink::for_delete(window.clone());
    let deleted = tauri::async_runtime::spawn_blocking(move || {
        scan::delete(&pairs, Some(protect_json.as_str()), &sink);
        sink.take_items()
    })
    .await;

    let rows = match deleted {
        Ok(v) => v,
        Err(e) => {
            log::write_log("error", &format!("finder 删除异常: {e}"));
            return json!({ "success": false, "message": format!("删除失败: {e}") });
        }
    };
    let details: Vec<Value> = rows
        .into_iter()
        .filter(|r| r.get("type").and_then(|t| t.as_str()) == Some("delresult"))
        .collect();

    let mut total_freed = 0u64;
    let mut success = 0usize;
    let mut failed = 0usize;
    let mut recycled = 0usize;
    for d in &details {
        total_freed += js_uint(d.get("freed"));
        if d.get("status").and_then(|s| s.as_str()) == Some("ok") {
            success += 1;
            if d.get("mode").and_then(|m| m.as_str()) == Some("recycled") {
                recycled += 1;
            }
        } else {
            failed += 1;
        }
    }
    // skipped = 未被原生侧处理（预检剔除 + 未出结果行）的数量
    let skipped = valid_safe.len().saturating_sub(success + failed);

    // 删除清单：成功项落盘（误删追溯的唯一凭据）
    let batch_id = delete_manifest::new_batch_id();
    let entries: Vec<Value> = details
        .iter()
        .filter(|d| d.get("status").and_then(|s| s.as_str()) == Some("ok"))
        .map(|d| {
            json!({
                "path": d.get("path").and_then(|p| p.as_str()).unwrap_or("").replace('/', "\\"),
                "kind": if d.get("kind").and_then(|k| k.as_str()) == Some("dir") { "dir" } else { "file" },
                "size": js_uint(d.get("freed")),
                "recycled": d.get("mode").and_then(|m| m.as_str()) == Some("recycled"),
            })
        })
        .collect();
    let manifest_pathbuf = delete_manifest::save_delete_manifest(&batch_id, &entries);
    let manifest_path = manifest_pathbuf
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let manifest_note = if manifest_path.is_empty() {
        String::new()
    } else {
        format!(" 清单 {}", Path::new(&manifest_path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())
    };
    log::write_log(
        "info",
        &format!(
            "finder 删除完成: 成功 {success}（回收站 {recycled}）失败 {failed} 释放 {total_freed} 字节{manifest_note}"
        ),
    );
    // success 语义 = 「通道执行成功」，不是「全部删除成功」（任一失败即丢整批会让 UI 错报）
    json!({
        "success": true,
        "data": {
            "totalFreed": total_freed,
            "success": success,
            "failed": failed,
            "skipped": skipped,
            "recycled": recycled,
            "details": details,
            "manifestPath": manifest_path
        }
    })
}

// ==================== 删除清单（共享存储见 engine::delete_manifest） ====================

/// finder:delete-manifest — 读最近批次清单（最多 200 条，最近批次在前）。
#[tauri::command]
pub fn finder_delete_manifest<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let (items, dir_text) = delete_manifest::list_manifest_items(FINDER_MANIFEST_READ_MAX);
    json!({ "success": true, "data": { "items": items, "dir": dir_text } })
}

/// finder:open-backup-dir — mkdir -p 后用系统 Shell 打开清单目录
/// （已进回收站的文件可在系统回收站中还原）
#[tauri::command]
pub fn finder_open_backup_dir<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    if let Err(e) = delete_manifest::ensure_backup_dir() {
        return json!({ "success": false, "message": e.to_string() });
    }
    let dir = delete_manifest::backup_dir();
    match open_folder(&dir) {
        Ok(()) => json!({ "success": true, "message": "" }),
        Err(msg) => json!({ "success": false, "message": msg }),
    }
}

/// 用 Explorer 打开目录（不经 shell 拼接命令，避免命令注入）
fn open_folder(dir: &Path) -> Result<(), String> {
    let target: Vec<u16> = dir
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let op = unsafe {
        windows::Win32::UI::Shell::ShellExecuteW(
            None,
            windows::core::w!("open"),
            windows::core::PCWSTR(target.as_ptr()),
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

// ==================== 入参归一化（对照 JS 语义） ====================

/// `String(p)`：非字符串入参先转字符串（路径数组理论上恒为字符串）
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// `Number(x)`：无法解析为数值时返回 NaN（由 `num_or` 落默认值）
fn js_number(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => s.trim().parse::<f64>().unwrap_or(f64::NAN),
        Value::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Value::Null => 0.0,
        _ => f64::NAN,
    }
}

/// `Number(x) || default`：NaN 与 0 都落默认值（0 视为「未提供」，与 JS 一致）
fn num_or(v: Option<&Value>, default: f64) -> f64 {
    match v.map(js_number) {
        Some(n) if n.is_finite() && n != 0.0 => n,
        _ => default,
    }
}

/// `Number(x) || 0` 的整数口径（用于字节数/条数统计，避免 JSON 里出现 `1024.0`）
fn js_uint(v: Option<&Value>) -> u64 {
    match v.map(js_number) {
        Some(n) if n > 0.0 => n as u64,
        _ => 0,
    }
}

/// 展开路径中的 `%VAR%` 环境变量（缺失时保留原样，对照 expandEnvPath）
fn expand_env_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut rest = p;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            Some(j) => {
                let name = &after[..j];
                match std::env::var(name) {
                    Ok(v) if !name.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[j + 1..];
            }
            None => {
                out.push_str(&rest[i..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// 存在性筛分：返回（存在且为目录, 缺失或不可用），对照 resolveExistingDirs
fn resolve_existing_dirs(list: &[String]) -> (Vec<String>, Vec<String>) {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for p in list {
        match std::fs::metadata(p) {
            Ok(md) if md.is_dir() => found.push(p.clone()),
            _ => missing.push(p.clone()),
        }
    }
    (found, missing)
}