//! finder 域（B 批）：finder:scan / delete / delete-manifest / open-backup-dir
//! + ignore-folder / ignore-list / ignore-remove（空目录忽略名单写侧）
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
//! 需在 `lib.rs` 的 `generate_handler!` 注册（下面这份清单就是本文件的全部实现，
//! v7.2 `R1d-L03`：原先只列 scan/delete/manifest/open-backup 四行、漏掉 ignore 三行。
//! 少列的症状不是编译失败，而是实现建在库里却没人注册 ⇒ 渲染层 invoke 报「命令不存在」，
//! 所以清单长度以本文件的 `#[tauri::command]` 现算为准、不手抄）：
//! ```text
//! commands::finder::finder_scan,
//! commands::finder::finder_delete,
//! commands::finder::finder_delete_manifest,
//! commands::finder::finder_open_backup_dir,
//! commands::finder::finder_ignore_folder,
//! commands::finder::finder_ignore_list,
//! commands::finder::finder_ignore_remove,
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
use std::sync::Mutex;

use serde_json::{json, Value};
use tauri::{Emitter, WebviewWindow};
use trim_finder::scan::{self, Sink};
// %VAR% 展开唯一真源；本文件此前的私有实现已随 v3 C-1 删除（旧版把「已定义但为空」
// 的变量展开成空串，与真源的「保持原文」口径不一致）。
use trim_finder::cleanup_scan::expand_env_path;

use crate::engine::delete_manifest;
// P2-1（审查 2026-10-07）：路径键统一走 engine 唯一实现，本文件不再自持一份
use crate::engine::paths::{exceeds_char_len, path_key};
use crate::engine::{guard, log, protect};

/// 合法扫描类型（对照 FINDER_SCAN_TYPES）。analyze = C-5 磁盘分析器（逐层下钻）
const FINDER_SCAN_TYPES: [&str; 5] = ["duplicates", "bigfiles", "empty", "appdata", "analyze"];
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
pub(crate) struct SnapEntry {
    /// 原始路径（保持扫描输出的正斜杠形态，删除详情与渲染层据此匹配）
    path: String,
    /// "dir" | "file"
    kind: String,
    /// 空目录标记（删除前需做「是否已不再为空」复检）
    empty: bool,
    ts: i64,
    /// 审查 v2-M5：**仅当**该条目的路径名无法无损表示成文本（含孤立代理项，
    /// `unix_path` 已把它换成 U+FFFD）时，登记原生侧交来的 `OsString` 真身。
    /// 正常机器上这张登记恒为 `None`，不额外占内存。
    raw: Option<OsString>,
}

impl SnapEntry {
    /// 删除/预检真正作用的目标。
    /// 根因：`path` 字段是 lossy 后的展示串，`OsString::from(path)` 得到的是
    /// **另一个**可能的路径 —— 既可能指向一个恰好用 U+FFFD 命名的真实文件（删错对象），
    /// 也可能谁都指不到（预检恒判 NotFound，却仍回 `success:true`）。
    fn target(&self) -> OsString {
        self.raw.clone().unwrap_or_else(|| OsString::from(self.path.as_str()))
    }

    /// 文本形态是否丢了信息（决定这一项能不能被安全删除）
    fn is_lossy(&self) -> bool {
        self.raw.is_some()
    }
}

use crate::commands::state::FINDER_SNAPSHOTS;

fn snapshots() -> &'static Mutex<HashMap<String, HashMap<String, SnapEntry>>> {
    FINDER_SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 结果写入本窗口**本扫描类型**的快照槽（累积合并，不整体重置——对齐 FD-7）。
/// `raws` = 原生侧登记的「展示串键 → 路径真身」，只装 lossy 的那批（见 `ScanTally::raws`）。
/// 槽键 = `domain_key(label, scan_type)`（v6-K09）：5 种扫描类型共用一张路径表时，
/// 后扫的类型会把先扫条目的 `empty` 标记顶掉——空目录的「删除前空树复检」闸整块失效
/// （AGENTS §5.25 同族：槽必须带域维）。返回本类型槽内条目数。
fn store_snapshot(
    label: &str,
    scan_type: &str,
    items: &[Value],
    raws: &HashMap<String, OsString>,
    ts: i64,
) -> usize {
    let slot_key = crate::engine::snapshot::domain_key(label, scan_type);
    let mut store = snapshots().lock().unwrap_or_else(|e| e.into_inner());
    {
        let slot = store.entry(slot_key.clone()).or_default();
        for item in items {
            let Some(p) = item.get("path").and_then(|v| v.as_str()) else {
                continue;
            };
            // emptyfolder 与 appdata 类型算目录；仅 emptyfolder 带 empty 标记。
            // analyzer（C-5）：kind=dir 有删除语义；2026-10-06 任务四起 kind=oldfile（老旧大文件）
            // 也有（file 粒度）；summary/ext/time 不入快照槽。
            let t = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let akind = item.get("kind").and_then(|v| v.as_str());
            if t == "analyzer" && !matches!(akind, Some("dir") | Some("oldfile")) {
                continue;
            }
            let key = path_key(p);
            // 审查 v2-M5：两条**不同**的原生路径 lossy 后可能塌成同一个展示串（不同的孤立
            // 代理项都被换成同一个 U+FFFD，或一条真名里就带 U+FFFD、另一条是被替换出来的）。
            // 展示串相同但真身不同就是无从区分 —— 保留先到的一条、不覆盖（覆盖等于把另一次
            // 删除的目标悄悄换掉），计数已在 `ScanTally::ingest` 里做过。
            let raw = raws.get(&key).cloned();
            if let Some(exist) = slot.get(&key) {
                if exist.raw != raw {
                    continue;
                }
            }
            let kind_dir = t == "emptyfolder"
                || t == "appdata"
                || (t == "analyzer" && akind == Some("dir"));
            slot.insert(
                key,
                SnapEntry {
                    path: p.to_string(),
                    kind: if kind_dir { "dir".to_string() } else { "file".to_string() },
                    empty: t == "emptyfolder",
                    ts,
                    raw,
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
    }
    store.get(&slot_key).map(|s| s.len()).unwrap_or(0)
}

/// K09：按路径在本窗口**所有扫描类型槽**里找条目（读侧唯一的跨类型查法）。
///
/// 同一路径可能同时出现在多个类型槽（如 emptyfolder 与 appdata 都扫到同一目录）：
/// 优先返回带 `empty` 标记的那条——空树复检闸的凭据不能被后扫类型顶掉；
/// 都没有标记时返回先命中的一条（kind/path 同源，取哪条语义相同）。
fn find_label_entry(
    store: &HashMap<String, HashMap<String, SnapEntry>>,
    label: &str,
    key: &str,
) -> Option<SnapEntry> {
    let prefix = format!("{label}|");
    let mut fallback: Option<SnapEntry> = None;
    for (slot_key, slot) in store.iter() {
        if !slot_key.starts_with(&prefix) {
            continue;
        }
        if let Some(e) = slot.get(key) {
            if e.empty {
                return Some(e.clone());
            }
            if fallback.is_none() {
                fallback = Some(e.clone());
            }
        }
    }
    fallback
}

// ==================== 输出汇聚器（Sink） ====================

/// 一次扫描的**接收端累加**（与窗口无关，所以能被 `cargo test` 直测；
/// `FinderSink` 只是给它套上 emit 的外壳）。
#[derive(Default)]
struct ScanTally {
    items: Mutex<Vec<Value>>,
    /// 审查 v2-M5：`path_key(展示串) → 原生路径真身`。
    /// 只登记「文本形态确实丢了信息」的条目（`trim_finder::util::has_lossy_path`），
    /// 正常机器上这张表恒空，不给快照另添一份内存开销。
    raws: Mutex<HashMap<String, OsString>>,
    /// 审查 M8：原生侧每有一条 `warn`（打不开的目录、被跳过的项…）与每一条**畸形行**计一次。
    /// 目的不是统计，而是让渲染层能区分「真的没有重复文件」与「没权限看所以什么都没列出来」——
    /// 旧实现两者都回 `success:true, data:[]`，用户完全无从判断。
    errors: std::sync::atomic::AtomicU64,
    /// 审查 M7：结果是否因条目上限被截断（原生侧 `Sink::truncated` 通知）
    truncated: std::sync::atomic::AtomicBool,
    /// 畸形行数（`errors` 的一部分，单独留出来只为写日志时说得清是哪类问题）
    malformed: std::sync::atomic::AtomicUsize,
    /// 只留第一条畸形原因：畸形内容本身可能是任意长文本，不照抄进日志
    first_malformed: Mutex<Option<String>>,
    /// 因文件名无法无损表示而**不能删**的条目数（审查 v2-M5，渲染层据此说人话）
    unhandled: std::sync::atomic::AtomicUsize,
}

impl ScanTally {
    /// 收一行 `@@ITEM@@{json}`。
    /// · 非 `@@ITEM@@` 前缀 → 按既有口径忽略（与 `runRustScanner` 对齐，CLI 才有别的行）
    /// · 前缀对但解析失败/缺 `path` → **计数**（审查 v2-M4：静默丢弃等于把「行协议被畸形
    ///   输入打破」伪装成「什么都没扫到」，两者在 UI 上必须是两句话）
    /// · 带原生路径 → lossy 条目登记真身，供删除时按它取目标（审查 v2-M5）
    fn ingest(&self, raw: Option<&std::path::Path>, line: &str) {
        let Some(rest) = line.strip_prefix("@@ITEM@@") else {
            return;
        };
        let v: Value = match serde_json::from_str(rest.trim()) {
            Ok(v) => v,
            Err(e) => return self.count_malformed(&format!("@@ITEM@@ 行解析失败: {e}")),
        };
        let Some(p) = v.get("path").and_then(|x| x.as_str()) else {
            return self.count_malformed("@@ITEM@@ 行缺少 path 字段");
        };
        if let Some(rp) = raw {
            if trim_finder::util::has_lossy_path(rp) {
                self.note_lossy(path_key(p), rp.as_os_str().to_os_string());
            }
        }
        self.items.lock().unwrap_or_else(|e| e.into_inner()).push(v);
    }

    /// 审查 v2-M5：登记一条「展示串已丢信息」的条目，并给出**去重后**的 unhandled 计数。
    /// · 同一个无法表示的路径被重复输出（duplicates 里既进 emptyfile 又进组）只算一项；
    /// · 两条不同真身塌进同一个展示串 ⇒ 后者永远定位不到，也算一项。
    fn note_lossy(&self, key: String, os: OsString) {
        use std::collections::hash_map::Entry;
        let mut g = self.raws.lock().unwrap_or_else(|e| e.into_inner());
        match g.entry(key) {
            Entry::Occupied(v) => {
                if v.get() != &os {
                    self.unhandled.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            Entry::Vacant(v) => {
                v.insert(os);
                self.unhandled.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn count_malformed(&self, reason: &str) {
        self.errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.malformed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
            *self.first_malformed.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(reason.chars().take(200).collect());
        }
    }

    fn take_items(&self) -> Vec<Value> {
        std::mem::take(&mut *self.items.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn take_raws(&self) -> HashMap<String, OsString> {
        std::mem::take(&mut *self.raws.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn snapshot(&self) -> TallyReport {
        TallyReport {
            errors: self.errors.load(std::sync::atomic::Ordering::Relaxed),
            truncated: self.truncated.load(std::sync::atomic::Ordering::Relaxed),
            malformed: self.malformed.load(std::sync::atomic::Ordering::Relaxed),
            first_malformed: self
                .first_malformed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            unhandled: self.unhandled.load(std::sync::atomic::Ordering::Relaxed) as u64,
        }
    }
}

/// `ScanTally` 的汇总回执（一次扫描结束后交给渲染层与日志的元数据）
struct TallyReport {
    errors: u64,
    truncated: bool,
    malformed: usize,
    first_malformed: Option<String>,
    unhandled: u64,
}

/// `trim_finder::scan` 的输出汇聚器实现体。
/// - `item`：收 `@@ITEM@@` 行并解析（含原生路径登记），其余行忽略——与 `runRustScanner` 同口径
/// - `progress`/`scanned`：改走 `finder:progress` 事件（删除通道不发，对齐 Electron 未传回调）
/// - `warn`：写日志
struct FinderSink<R: tauri::Runtime> {
    window: WebviewWindow<R>,
    /// None = 不向前端发事件（删除通道）
    scan_type: Option<String>,
    tally: ScanTally,
}

impl<R: tauri::Runtime> FinderSink<R> {
    fn for_scan(window: WebviewWindow<R>, scan_type: &str) -> Self {
        Self { window, scan_type: Some(scan_type.to_string()), tally: ScanTally::default() }
    }

    fn for_delete(window: WebviewWindow<R>) -> Self {
        Self { window, scan_type: None, tally: ScanTally::default() }
    }

    fn take_items(&self) -> Vec<Value> {
        self.tally.take_items()
    }

    fn emit_progress(&self, payload: Value) {
        // 调用方窗口已销毁时 emit 失败，忽略（对齐 Electron 的 sender.isDestroyed() 判断）
        let _ = self.window.emit("finder:progress", payload);
    }
}

impl<R: tauri::Runtime> Sink for FinderSink<R> {
    fn item(&self, path: &std::path::Path, line: &str) {
        self.tally.ingest(Some(path), line);
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
        self.tally.errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        log::write_log("warn", msg);
    }

    fn truncated(&self) {
        self.tally.truncated.store(true, std::sync::atomic::Ordering::Relaxed);
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
    min_size_mb: Option<Value>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    if !FINDER_SCAN_TYPES.contains(&scan_type.as_str()) {
        return json!({ "success": false, "message": "未知扫描类型" });
    }
    // 路径归一（v2-L4P-39 / F-8）：trim → 展开变量 → **展开后**再量长度 → 上限截断。
    // 三类丢弃都显式计数并回执，不再静默：静默丢弃 = 用户给的目录被偷偷缩小扫描面。
    let raw_inputs: Vec<String> = paths
        .unwrap_or_default()
        .iter()
        .map(js_string)
        .map(|s| s.trim().to_string())
        .collect();
    let provided = raw_inputs.iter().filter(|s| !s.is_empty()).count();
    let mut plist: Vec<String> = Vec::new();
    let mut dropped_roots: usize = 0;
    let mut roots_truncated = false;
    for s in &raw_inputs {
        if s.is_empty() {
            continue;
        }
        let expanded = expand_env_path(s);
        if exceeds_char_len(&expanded, FINDER_PATH_MAX_LEN) {
            // 长度在展开后量：`%LOCALAPPDATA%\…` 展开前看着短、展开后可能超限
            dropped_roots += 1;
            log::write_log("warn", &format!("finder 扫描根超长丢弃（展开后 > {FINDER_PATH_MAX_LEN} 字符）：{s}"));
            continue;
        }
        if plist.len() >= FINDER_PATHS_MAX {
            roots_truncated = true;
            log::write_log("warn", &format!("finder 扫描根超过 {FINDER_PATHS_MAX} 个上限，其余已丢弃"));
            break;
        }
        plist.push(expanded);
    }

    // 默认值：--min-size 0 / --count 50 / --min-size-mb 10（对照 Math.max 语义）
    let mut min_size_arg = 0u64;
    let mut count_arg = 50usize;
    let mut min_size_mb_arg = 10u64;

    match scan_type.as_str() {
        "duplicates" => {
            if plist.is_empty() {
                // v2-L4P-39（F-8）：只有「用户什么都没填」才回落默认根；填了但全部
                // 被丢弃/超限时不得回落——那等于把无效输入伪装成一次成功的默认扫描。
                if provided > 0 {
                    return json!({
                        "success": false,
                        "message": "提供的扫描目录全部无效（不存在/超长），未执行扫描；请修正后重试",
                        "droppedRoots": dropped_roots,
                        "rootsTruncated": roots_truncated
                    });
                }
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
            // 六轮拍板 2026-09-28：数量上限删除（固定 200）、大文件阈值固定 300MB——
            // 前端两处下拉已移除，这里作为唯一口径（CLI 侧 main.rs 同值）
            count_arg = 200;
        }
        "appdata" => {
            min_size_mb_arg = num_or(min_size_mb.as_ref(), 10.0).max(1.0) as u64;
        }
        "analyze" => {
            // C-5：paths 即待分析目录（盘符或下钻层），无额外参数
            if plist.is_empty() {
                return json!({ "success": false, "message": "至少需要一个分析目录" });
            }
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
            // 大文件阈值固定 300MB（六轮拍板 2026-09-28，前端下拉已删）
            "bigfiles" => scan::bigfiles(&roots, count_arg, 300 * 1024 * 1024, &sink),
            "empty" => scan::empty(&roots, &sink),
            "analyze" => scan::analyze(&roots, &sink),
            _ => scan::appdata(min_size_mb_arg, &sink),
        }
        // 审查 M8：把「受限结果」的元数据一并交回，别只交 items
        let report = sink.tally.snapshot();
        (sink.tally.take_items(), sink.tally.take_raws(), report)
    })
    .await;

    let (items, raws, report) = match scanned {
        Ok(v) => v,
        Err(e) => {
            log::write_log("error", &format!("finder {scan_type} 失败: {e}"));
            return json!({ "success": false, "message": format!("扫描失败: {e}") });
        }
    };

    let slot_size = store_snapshot(&label, &scan_type, &items, &raws, crate::engine::now_ms());
    let unhandled = report.unhandled;
    // 畸形行要在日志里单说一句：`errors` 同时装着「读不到的目录」和「解析不了的行」，
    // 这两类问题的处置方式完全不同（审查 v2-M4）
    if report.malformed > 0 {
        log::write_log(
            "warn",
            &format!(
                "finder {scan_type} 有 {} 行输出无法解析（未计入结果，首条原因：{}）",
                report.malformed,
                report.first_malformed.unwrap_or_default()
            ),
        );
    }
    log::write_log(
        "info",
        &format!(
            "finder {scan_type} 完成: {} 项（快照槽 {} 条，告警 {} 条{}{}）",
            items.len(),
            slot_size,
            report.errors,
            if report.truncated { "，已截断" } else { "" },
            if unhandled > 0 { format!("，{unhandled} 项文件名无法无损处理") } else { String::new() }
        ),
    );
    // `errors`/`truncated`/`unhandled` 是给渲染层的判据：空结果 + errors>0 要说「有 N 处没能读到」，
    // 而不是「没有重复文件」（B2 禁吞异常伪装空结果）；unhandled 则要说「N 项因文件名无法处理」。
    // v2-L4P-39（F-8）：扫描根丢弃/截断随回执透出。
    json!({
        "success": true,
        "data": items,
        "errors": report.errors,
        "truncated": report.truncated,
        "unhandled": unhandled,
        "droppedRoots": dropped_roots,
        "rootsTruncated": roots_truncated
    })
}

// ==================== finder:delete ====================

/// finder:delete — 危险通道：快照命中 + 受保护路径 + 删除前预检三重 Rust 侧权威校验。
///
#[tauri::command]
pub async fn finder_delete<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // v7.2 `R1d-M05`：入参归一的两处静默丢弃都要计数并回执（同文件扫描根侧已有
    // `droppedRoots`/`rootsTruncated`，删除侧却是「悄悄少删」）：
    // ① `path` 非字符串/缺失的项被 filter 掉；② 超出 FINDER_DELETE_MAX 的尾部被 take 掉。
    // 丢弃不改变放行集的语义（快照闸仍逐条判），但用户必须能看见「你以为给了 600 条、
    // 实际只处理了 500 条」，否则这是一条会吃掉删除范围的静默路径。
    let requested_raw: Vec<Value> = items.unwrap_or_default();
    let requested_raw_len = requested_raw.len();
    let dropped_typed = requested_raw
        .iter()
        .filter(|it| !it.get("path").map(|p| p.is_string()).unwrap_or(false))
        .count();
    let requested: Vec<Value> = requested_raw
        .into_iter()
        .filter(|it| it.get("path").map(|p| p.is_string()).unwrap_or(false))
        .take(FINDER_DELETE_MAX)
        .collect();
    let dropped_truncated = requested_raw_len.saturating_sub(requested.len() + dropped_typed);
    if dropped_typed > 0 || dropped_truncated > 0 {
        log::write_log(
            "warn",
            &format!(
                "finder 删除入参归一：收到 {requested_raw_len} 项，形状不合 {dropped_typed} 项、超单批上限 {FINDER_DELETE_MAX} 被丢弃 {dropped_truncated} 项"
            ),
        );
    }

    // 只认本窗口快照槽内的路径（跨窗口互不覆盖；同一窗口内任一扫描类型扫到即可删——
    // 槽键带类型后由 `find_label_entry` 跨类型查，优先带 empty 标记的那条）
    let label = window.label().to_string();
    let known: Vec<Option<SnapEntry>> = {
        let store = snapshots().lock().unwrap_or_else(|e| e.into_inner());
        requested
            .iter()
            .map(|it| {
                let p = it.get("path").and_then(|v| v.as_str()).unwrap_or("");
                find_label_entry(&store, &label, &path_key(p))
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
    // C01（v7.2 R1d-K01🔴）：受保护面/别名面/系统面/reparse 四道组合闸。
    // 此前只有 protect + 别名解析两道，`is_system_namespace` 缺席 ⇒ `%WINDIR%`
    // 子孙（Prefetch、WinSxS\Temp 等）能进回收站——protect 对 %WINDIR% 是 exact
    // 语义管不到子孙。拒因文案来自 `validate_mutation_target` 唯一真源；
    // 快照成员（作用域）闸在上面已判完，这里做纵深。单遍循环取第一个拒因，
    // 不对命中项二次调用（别名面一行 canonicalize 的 IO）。
    let mut reject: Option<String> = None;
    for it in &valid_safe {
        if let Err(why) = protect::validate_mutation_target(&it.path) {
            reject = Some(why);
            break;
        }
    }
    if let Some(why) = reject {
        log::write_log("warn", &format!("finder 删除拒绝: {why}"));
        return json!({
            "success": false,
            "message": format!("包含不可删除的目标，已整批拒绝：{why}")
        });
    }

    // 删除前预检（FD-4）：目标不存在/类型不符/空目录已非空 → 跳过
    // 审查 v2-M5：一律以 `it.target()`（原生侧交来的路径真身）为预检与删除对象，
    // 不再 `OsString::from(it.path)` —— 展示串是 lossy 后的文本，重建出来的可能是
    // 另一个真实存在的路径（删错对象），也可能谁都指不到（恒判 NotFound 却仍回 success:true）。
    let safe_total = valid_safe.len();
    // 性能优化 P1：预检逐条 `metadata` / 空树复检 / `read_dir` 全是磁盘 I/O（条目上限
    // 可达 FINDER_DELETE_MAX），整段搬进阻塞池，执行体见 `run_delete_preflight`。
    let (preflight, mut unhandled) =
        match tauri::async_runtime::spawn_blocking(move || run_delete_preflight(valid_safe)).await {
            Ok(v) => v,
            Err(e) => {
                log::write_log("error", &format!("finder 删除预检任务异常: {e}"));
                return json!({ "success": false, "message": format!("删除失败: {e}") });
            }
        };
    if preflight.is_empty() {
        return json!({
            "success": true,
            "data": {
                "totalFreed": 0, "success": 0, "failed": 0,
                "skipped": safe_total, "recycled": 0, "unhandled": unhandled,
                // R1d-M05：入参归一的丢弃数即使在这条早退路径上也要如实回传
                "requestedTotal": requested_raw_len, "droppedItems": dropped_typed + dropped_truncated,
                "details": [], "manifestPath": null
            }
        });
    }

    log::write_log("info", &format!("finder 删除(原生): {} 项", preflight.len()));
    log::flush_sync(); // 危险操作执行前强制刷盘（审查v4-L3）

    let pairs: Vec<(String, OsString)> = preflight
        .iter()
        .map(|it| (if it.kind == "dir" { "dir".to_string() } else { "file".to_string() }, it.target()))
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
    // R4（2026-10-15）：失败按因分档——受保护/链接拒绝（rejected）与文件名异常
    // （unrecoverable-name）不许再冒充「可能被占用」。子集计数：failed 仍是总失败数，
    // skipped 的口径（safe_total - success - failed）依赖它。
    let mut failed_busy = 0usize;
    let mut failed_refused = 0usize;
    let mut failed_name = 0usize;
    for d in &details {
        total_freed += js_uint(d.get("freed"));
        let mode = d.get("mode").and_then(|m| m.as_str()).unwrap_or("");
        if d.get("status").and_then(|s| s.as_str()) == Some("ok") {
            success += 1;
            if classify_delete_result_mode(mode) == "ok" {
                recycled += 1;
            }
        } else {
            failed += 1;
            match classify_delete_result_mode(mode) {
                "refused" => failed_refused += 1,
                "name" => {
                    // 原生删除侧也有一道同名闸门（文件名无法无损表示 ⇒ 保护清单判定不可靠）；
                    // 走到这里说明主侧漏判，仍要计进 unhandled 而不是只算「失败」
                    failed_name += 1;
                    unhandled += 1;
                }
                _ => failed_busy += 1,
            }
        }
    }
    // skipped = 未被原生侧处理（预检剔除 + 未出结果行）的数量；unhandled 是其中说得出
    // 原因的那部分（审查 v2-M5），渲染层据此讲「N 项因文件名无法处理而未删」。
    let skipped = safe_total.saturating_sub(success + failed);

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
    // v7.2 `R1d-L12`：`manifestPath` 只允许一种「没有清单」的写法。
    // 旧形态是同字段两态：清单落盘失败给 `""`、空批早退给 `null` ⇒ 渲染层要么判
    // `if (p)` 要么判 `p !== null`，两处消费口径必然分叉。空串统一归一成 null。
    let manifest_path_json = if manifest_path.is_empty() {
        Value::Null
    } else {
        json!(manifest_path)
    };
    let manifest_note = if manifest_path.is_empty() {
        String::new()
    } else {
        format!(" 清单 {}", Path::new(&manifest_path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())
    };
    log::write_log(
        "info",
        &format!(
            "finder 删除完成: 成功 {success}（回收站 {recycled}）失败 {failed} 跳过 {skipped}（其中 {unhandled} 项文件名无法无损处理）释放 {total_freed} 字节{manifest_note}"
        ),
    );
    // success 语义 = 「通道执行成功」，不是「全部删除成功」（任一失败即丢整批会让 UI 错报）
    json!({
        "success": true,
        "data": {
            "totalFreed": total_freed,
            "success": success,
            "failed": failed,
            // R4（2026-10-15）：失败分档子集（三者之和 = failed）；渲染层按档提示
            "failedBusy": failed_busy,
            "failedRefused": failed_refused,
            "failedName": failed_name,
            "skipped": skipped,
            "unhandled": unhandled,
            "recycled": recycled,
            // R1d-M05：入参归一计数（收到多少 / 因形状或单批上限丢了多少）
            "requestedTotal": requested_raw_len,
            "droppedItems": dropped_typed + dropped_truncated,
            "details": details,
            "manifestPath": manifest_path_json
        }
    })
}

/// 删除前预检的执行体（FD-4 与审查 v2-M5 的全部判据都在这里，一条没减）。
///
/// 性能优化 P1：这一段逐条做 `metadata` + 空目录树递归复检 + `read_dir`，全是磁盘 I/O
/// 且条目上限可达 `FINDER_DELETE_MAX`；抽成独立同步函数后由 `finder_delete` 整段丢进
/// 阻塞池，async 命令体不再占住 runtime worker。
fn run_delete_preflight(valid_safe: Vec<SnapEntry>) -> (Vec<SnapEntry>, usize) {
    let mut preflight: Vec<SnapEntry> = Vec::new();
    let mut unhandled = 0usize;
    for it in &valid_safe {
        // 文件名无法无损表示 ⇒ 保护清单判定（按字符串比对）不可靠，宁可不删也要明说
        if it.is_lossy() {
            unhandled += 1;
            log::write_log("warn", &format!("finder 删除预检: 文件名无法无损处理，未删除 -> {}", it.path));
            continue;
        }
        let target = it.target();
        match std::fs::metadata(&target) {
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
                    // 扫描侧的空目录是**折叠后**的最外层父目录：它体内恰是那些空子目录
                    // （或扫描认作空的 0 字节文件），`read_dir().count() > 0` 必然成立 ⇒
                    // 默认勾选的折叠父目录 100% 被跳过。判据与扫描侧同源
                    // （`prune_tree_effectively_empty`，AGENTS §5.16），按空树复检。
                    if !trim_finder::scan::prune_tree_effectively_empty(std::path::Path::new(&target)) {
                        let child_count = std::fs::read_dir(&target).map(|r| r.count()).unwrap_or(0);
                        log::write_log(
                            "warn",
                            &format!(
                                "finder 删除预检: 空目录树内已有实际内容（顶层 {} 项），跳过 -> {}",
                                child_count, it.path,
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
    (preflight, unhandled)
}

/// 原生删除结果行的 `mode` → 分档（R4，2026-10-15）。
/// 产出侧在 `native-scanner/src/scan.rs`（跨 crate，不能共享代码）——两级各读同一份
/// 夹具字节（`tools/fixtures/finder-delete-modes.json`），由两侧各自的测试独立对拍：
/// 产出侧断「delete() 写的字面量就是夹具登记的 mode」，消费侧断「本函数的档位与夹具
/// 一致」。判定实现不共享、样本共享（§4.1「形似不合」）。
fn classify_delete_result_mode(mode: &str) -> &'static str {
    match mode {
        "recycled" => "ok",
        "rejected" => "refused",
        // Kudu S2（2026-10-16）：路径祖先在执行前被换成链接/junction —— 与 rejected
        // 同族（安全拒绝，关程序没有出路；渲染层按「受保护/链接拒绝」提示）。
        "reparse-ancestor" => "refused",
        "unrecoverable-name" => "name",
        // "trash-failed" 及未来未知值：按回收站失败处理（最保守的叙述——不冒领
        // 「受保护拒绝」或「文件名问题」这两个有专门出路的档）
        _ => "busy",
    }
}

// ==================== 删除清单（共享存储见 engine::delete_manifest） ====================

/// finder:delete-manifest — 读最近批次清单（最多 200 条，最近批次在前）。
///
/// v7.2 `R1d-L11`：同步 `pub fn` 命令体里做 `read_dir` + 逐份清单整文件读，
/// 与本文件自己的 v2-F13 约定（同步=占主线程）不一致 ⇒ 改 async + `spawn_blocking`。
/// 返回类型保持 `Value`（渲染层口径不变），档位判定仍留在 async 体的最前面。
#[tauri::command]
pub async fn finder_delete_manifest<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let read = tauri::async_runtime::spawn_blocking(|| {
        delete_manifest::list_manifest_items(FINDER_MANIFEST_READ_MAX)
    })
    .await;
    match read {
        Ok((items, dir_text)) => json!({ "success": true, "data": { "items": items, "dir": dir_text } }),
        Err(e) => {
            log::write_log("error", &format!("finder 删除清单读取任务异常: {e}"));
            json!({ "success": false, "message": format!("读取删除清单失败: {e}") })
        }
    }
}

/// finder:open-backup-dir — mkdir -p 后用系统 Shell 打开清单目录
/// （已进回收站的文件可在系统回收站中还原）
///
/// v7.2 `R1d-L11`：建目录是磁盘 I/O、`ShellExecuteW` 是会阻塞的 Shell 调用，
/// 都不该留在同步命令体里（同 `delete-manifest` 的 v2-F13 口径）。
#[tauri::command]
pub async fn finder_open_backup_dir<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let opened = tauri::async_runtime::spawn_blocking(|| {
        delete_manifest::ensure_backup_dir().map(|_| {
            let dir = delete_manifest::backup_dir();
            open_folder(&dir)
        })
    })
    .await;
    match opened {
        Ok(Ok(Ok(()))) => json!({ "success": true, "message": "" }),
        Ok(Ok(Err(msg))) => json!({ "success": false, "message": msg }),
        Ok(Err(e)) => json!({ "success": false, "message": e.to_string() }),
        Err(e) => {
            log::write_log("error", &format!("finder 打开清单目录任务异常: {e}"));
            json!({ "success": false, "message": format!("打开目录失败: {e}") })
        }
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

// ==================== 空目录忽略名单（2026-10-06 任务四）====================
//
// 读侧在 native（`scan.rs::load_empty_ignore` → `<数据根>\empty-ignore.txt`，数据根由
// `engine::paths` 注入——便携模式感知，N2）；写侧必须与读侧**同落点同格式**：每行一个
// 绝对路径、UTF-8、CRLF 行尾（沿用既有文件的行尾风格；空文件用 CRLF）。写入走
// `security::atomic_write_file`（原子写，坏写不留半份名单）。
// 三条命令全 MAIN 档：写操作只有主窗调；list 放只读档会被 check-channel-map D5
// 判「只读档却没有子窗消费方」——它服务的是主窗的空目录页/名单弹窗。

const EMPTY_IGNORE_FILE: &str = "empty-ignore.txt";
const EMPTY_IGNORE_MAX: usize = 200;
// R1d-M04：忽略名单的 read→push→write 跨两次触盘，无锁会互相丢更新。
static EMPTY_IGNORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn empty_ignore_path() -> std::path::PathBuf {
    crate::engine::paths::app_data_dir().join(EMPTY_IGNORE_FILE)
}

/// 读忽略名单（v4 P2-D 尾）：IO 失败与「文件不存在」分开 —— 前者拒写（读空即写回
/// 会把整份名单覆成空），后者当空名单（首次使用）。
fn read_empty_ignore_lines() -> Result<Vec<String>, String> {
    match std::fs::read_to_string(empty_ignore_path()) {
        Ok(t) => Ok(t
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("忽略名单读取失败：{e}")),
    }
}

fn write_empty_ignore_lines(lines: &[String]) -> Result<(), String> {
    let body = if lines.is_empty() {
        String::new()
    } else {
        lines.join("\r\n") + "\r\n"
    };
    crate::security::atomic_write_file(&empty_ignore_path(), body.as_bytes())
}

/// finder:ignore-folder —— 把目录加入空目录忽略名单（重扫不再出现）。
#[tauri::command]
pub async fn finder_ignore_folder<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    path: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let _guard = EMPTY_IGNORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = path.unwrap_or_default();
    // 只收存在的绝对目录：忽略一个不存在/非目录的路径没有意义，且会把名单污染成
    // 无法复核的条目（list 的 exists 列与重扫的路径比对都依赖它是真实路径）。
    let p = Path::new(&path);
    if path.is_empty() || !p.is_absolute() || !p.is_dir() {
        return json!({ "success": false, "message": "只能忽略本机存在的文件夹" });
    }
    let mut lines = match read_empty_ignore_lines() {
        Ok(l) => l,
        Err(msg) => return json!({ "success": false, "message": format!("{msg}；为避免覆盖名单，本次操作已中止") }),
    };
    let lower = path.to_lowercase();
    if lines.iter().any(|l| l.to_lowercase() == lower) {
        return json!({ "success": true, "already": true, "count": lines.len() });
    }
    if lines.len() >= EMPTY_IGNORE_MAX {
        return json!({ "success": false, "message": format!("忽略名单已达上限（{EMPTY_IGNORE_MAX} 条），请先在「忽略名单」里移除一些") });
    }
    lines.push(path.clone());
    if let Err(e) = write_empty_ignore_lines(&lines) {
        log::write_log("warn", &format!("空目录忽略名单写入失败: {e}"));
        return json!({ "success": false, "message": format!("写入忽略名单失败: {e}") });
    }
    json!({ "success": true, "count": lines.len() })
}

/// finder:ignore-list —— 列出忽略名单（路径 + 当前是否仍存在，供名单弹窗展示）。
#[tauri::command]
pub async fn finder_ignore_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let items: Vec<Value> = match read_empty_ignore_lines() {
        Ok(l) => l,
        Err(msg) => return json!({ "success": false, "message": msg }),
    }
    .into_iter()
    .map(|l| {
        let exists = Path::new(&l).is_dir();
        json!({ "path": l, "exists": exists })
    })
    .collect();
    json!({ "success": true, "data": items })
}

/// finder:ignore-remove —— 从忽略名单移除一条（拿掉后该目录重扫会重新出现）。
#[tauri::command]
pub async fn finder_ignore_remove<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    path: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let _guard = EMPTY_IGNORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = path.unwrap_or_default();
    if path.is_empty() {
        return json!({ "success": false, "message": "参数缺失" });
    }
    let lower = path.to_lowercase();
    let lines = match read_empty_ignore_lines() {
        Ok(l) => l,
        Err(msg) => return json!({ "success": false, "message": format!("{msg}；为避免覆盖名单，本次操作已中止") }),
    };
    let kept: Vec<String> = lines
        .iter()
        .filter(|l| l.to_lowercase() != lower)
        .cloned()
        .collect();
    if kept.len() == lines.len() {
        return json!({ "success": false, "missing": true, "message": "该条目不在忽略名单里" });
    }
    if let Err(e) = write_empty_ignore_lines(&kept) {
        log::write_log("warn", &format!("空目录忽略名单写入失败: {e}"));
        return json!({ "success": false, "message": format!("写入忽略名单失败: {e}") });
    }
    json!({ "success": true, "count": kept.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// 构造一条 `@@ITEM@@` 行（`path` 字段按扫描输出的正斜杠形态）
    fn item_body(display_path: &str) -> String {
        format!("{{\"type\":\"emptyfile\",\"path\":\"{display_path}\",\"size\":0}}")
    }

    fn item_line(display_path: &str) -> String {
        format!("@@ITEM@@{body}\n", body = item_body(display_path))
    }

    /// 审查 v2-M4：畸形行**不得静默丢弃**。原实现 `if let Ok(v) = …` 没有 else 分支，
    /// 于是「行协议被畸形输入打破」在渲染层长成「什么都没扫到」——与 B2 直接冲突。
    #[test]
    fn tally_counts_malformed_lines_instead_of_dropping_them() {
        let t = ScanTally::default();
        t.ingest(None, "@@PROGRESS:50@@"); // 非 item 行：按既有口径忽略、不计数
        t.ingest(None, "@@ITEM@@{\"type\":\"bigfile\""); // 括号不完整
        t.ingest(None, "@@ITEM@@{\"type\":\"bigfile\",\"size\":1}"); // 缺 path
        t.ingest(None, &item_line("C:/ok/a.txt")); // 正常
        let items = t.take_items();
        assert_eq!(items.len(), 1, "只有合法行进结果");
        let r = t.snapshot();
        assert_eq!(r.malformed, 2, "两条畸形都要计数");
        assert_eq!(r.errors, 2, "畸形计数要并入 errors（渲染层已有那条提示）");
        assert!(r.first_malformed.is_some(), "日志里要留得下第一条原因");
        assert!(!r.truncated);
    }

    /// 审查 v2-M4 的另一半：缺 `path` 的行不能进结果集，但也不能无声消失。
    #[test]
    fn tally_keeps_the_first_malformed_reason_only() {
        let t = ScanTally::default();
        t.ingest(None, "@@ITEM@@[1,2,3]"); // 能解析但不是带 path 的对象 ⇒ 无法定位
        t.ingest(None, "@@ITEM@@{{{{");
        let r = t.snapshot();
        assert_eq!(r.malformed, 2);
        assert!(t.take_items().is_empty(), "坏行不得混进结果");
        assert!(r.first_malformed.unwrap().contains("path"), "第一条原因应是缺 path");
    }

    /// 审查 v2-M5：登记的是「文本形态确实丢了信息」的条目，且按展示串键去重。
    /// 正常机器上这张表必须恒空 —— 否则等于给每次扫描多养一份全量路径表。
    #[test]
    fn tally_registers_nothing_for_lossless_paths() {
        let t = ScanTally::default();
        let good = PathBuf::from(r"C:\Users\me\照片 🎯.txt");
        t.ingest(Some(&good), &item_line(&trim_finder::util::unix_path(&good)));
        assert!(t.take_raws().is_empty(), "无损名字不需要另登记真身");
        assert_eq!(t.snapshot().unhandled, 0, "也不该计入「无法处理」");
    }

    /// 审查 v2-M5：删除目标必须是原生侧交来的 `OsString`。
    /// 拿 lossy 展示串重建会得到**另一个**路径 —— 既可能删不到，也可能删掉一个
    /// 恰好用 U+FFFD 命名的无关文件。这里同时钉住「键位冲突不覆盖」与「去重计数」。
    #[cfg(windows)]
    #[test]
    fn lossy_paths_keep_their_native_target_and_do_not_clobber_each_other() {
        use std::os::windows::ffi::OsStringExt;
        // 两条不同的孤立代理项名字，lossy 后塌成同一个展示串
        let a = PathBuf::from(OsString::from_wide(&[0x43, 0x3A, 0x5C, 0xD800, 0x61]));
        let b = PathBuf::from(OsString::from_wide(&[0x43, 0x3A, 0x5C, 0xD801, 0x61]));
        let disp_a = trim_finder::util::unix_path(&a);
        let disp_b = trim_finder::util::unix_path(&b);
        assert_eq!(disp_a, disp_b, "用例前提：两条路径的展示串确实撞了");

        let t = ScanTally::default();
        t.ingest(Some(&a), &item_line(&disp_a));
        t.ingest(Some(&b), &item_line(&disp_b));
        let raws = t.take_raws();
        assert_eq!(
            raws.get(&path_key(&disp_a)),
            Some(&a.as_os_str().to_os_string()),
            "保留先到的一条真身（后到的无从定位，不得覆盖）"
        );
        assert_eq!(t.snapshot().unhandled, 2, "两条都得计入「无法处理」：一条登记、一条被冲突挤掉");

        let items = vec![
            // `item_line` 是**行协议**（带 `@@ITEM@@` 前缀与换行），JSON 解析要吃的是 `item_body`
            serde_json::from_str::<Value>(&item_body(&disp_a)).unwrap(),
            serde_json::from_str::<Value>(&item_body(&disp_b)).unwrap(),
        ];
        let label = "test-lossy-collision";
        let slot_size = store_snapshot(label, "duplicates", &items, &raws, 1);
        assert_eq!(slot_size, 1, "同一键位只留一条");
        let stored = snapshots().lock().unwrap_or_else(|e| e.into_inner());
        let entry = find_label_entry(&stored, label, &path_key(&disp_a)).expect("条目应在槽内");
        assert_eq!(entry.target(), a.as_os_str().to_os_string(), "预检/删除必须打到原生真身上");
        assert!(entry.is_lossy());
    }

    /// K09：快照槽必须带扫描类型第二维——先扫 emptyfolder、再扫 appdata（同一路径
    /// 两个类型都会报到），后扫的不得把 `empty` 标记顶掉（否则删除前的空树复检闸
    /// 整块失效）。判红自证：把 `store_snapshot` 的槽键改回裸 label ⇒ ② 红
    /// （同一槽里 appdata 条目直接覆盖 emptyfolder 条目）。
    #[test]
    fn 快照槽带类型第二维_empty标记不被后扫类型顶掉() {
        let label = format!("test-k09-{}", std::process::id());
        let dir = r"C:\Users\me\AppData\Local\Temp\trim-empty-probe";
        let empty_item = json!({ "path": dir, "type": "emptyfolder" });
        let appdata_item = json!({ "path": dir, "type": "appdata" });
        let raws = HashMap::new();
        // ① 先扫 emptyfolder：槽里是带 empty 标记的目录条目
        store_snapshot(&label, "empty", &[empty_item], &raws, 1);
        // ② 再扫 appdata（同路径）：两个类型各进各的槽
        store_snapshot(&label, "appdata", &[appdata_item], &raws, 2);
        let stored = snapshots().lock().unwrap_or_else(|e| e.into_inner());
        // 读侧跨类型查：必须拿到带 empty 标记的那条
        let hit = find_label_entry(&stored, &label, &path_key(dir)).expect("跨类型查找必须命中");
        assert!(hit.empty, "empty 标记被后扫类型顶掉了（K09 病灶）");
        assert_eq!(hit.kind, "dir");
        // 两个类型槽都在（第二维真的生效）
        let prefix = format!("{label}|");
        let slots: Vec<&String> = stored.keys().filter(|k| k.starts_with(&prefix)).collect();
        assert_eq!(slots.len(), 2, "emptyfolder 与 appdata 必须各占一槽: {slots:?}");
    }

    /// 快照命中判据（`path_key`）：分隔符、大小写、`\?\` 前缀、`.`/`..` 都要折叠掉，
    /// 但组件边界不能被吞（`C:\AB` 不是 `C:\A` 的子项）。
    #[test]
    fn path_key_folds_forms_but_keeps_component_bounds() {
        assert_eq!(path_key(r"\\?\C:\A\B"), path_key("c:/a/b"), "设备命名空间前缀要折掉");
        // 单反斜杠的 `\?\…` **不是**设备前缀：它是「当前盘根下一个名为 ? 的目录」。
        // 把它也当 `\\?\` 剥掉会让真实目录 `?\C:` 与设备路径互相别名 —— 快照键位是删除
        // 与预检的命中判据，别名等于给"删哪个"开了口子，所以这里断言二者**不等**。
        assert_ne!(path_key(r"\?\C:\A\B"), path_key(r"c:\a\b"));
        assert_eq!(path_key(r"C:\A\B\..\C"), path_key("C:/A/C"));
        assert_eq!(path_key("C:/A/B/"), path_key(r"c:\a\b"));
        assert_ne!(path_key(r"C:\AB"), path_key(r"C:\A\B"));
    }

    /// R4（2026-10-15）：失败分档必须与共享夹具一致（跨 crate 共享的是夹具**字节**，
    /// 判定两级各自独立实现），且三个分档字段真的被渲染层消费——字段名写错 =
    /// 「分档了但没人用」，静默回到「只报总失败数」。
    #[test]
    fn 删除失败分档_与共享夹具及渲染层消费面一致() {
        let fx = include_str!("../../../tools/fixtures/finder-delete-modes.json");
        let v: Value = serde_json::from_str(fx).expect("共享夹具解析失败");
        let modes = v.get("modes").and_then(|m| m.as_object()).expect("夹具缺 modes 表");
        // 5 = recycled / rejected / reparse-ancestor / unrecoverable-name / trash-failed
        // （Kudu S2 即 5073673 新增 reparse-ancestor，夹具已由 gen-finder-delete-modes 重生成为
        // 5 项，本计数当时没跟上——P0-B 全量跑首测暴露。改 modes 表必须同步改这里）
        assert_eq!(modes.len(), 5, "夹具登记的 mode 数与产出侧字面量数不符（改一侧必须两侧同改）");
        let mut ok_buckets = 0usize;
        for (mode, bucket) in modes {
            let expect = bucket.as_str().unwrap_or("");
            assert_eq!(
                classify_delete_result_mode(mode),
                expect,
                "mode「{mode}」的分档与共享夹具不一致"
            );
            if expect == "ok" {
                ok_buckets += 1;
            }
        }
        assert_eq!(ok_buckets, 1, "夹具必须恰好一个 ok 档（已移入回收站）");
        // 渲染层消费面：分档字段名必须与 finder.js 的取数一致（否则分档白做）
        let js = include_str!("../../../src/scripts/finder.js");
        for field in ["data.failedBusy", "data.failedRefused", "data.failedName"] {
            assert!(js.contains(field), "finder.js 没有消费分档字段 {field}");
        }
    }
}
