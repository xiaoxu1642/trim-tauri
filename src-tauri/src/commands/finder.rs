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
//! ```text
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

/// label -> (规范化小写路径 -> 条目)。Electron 用 Map（插入序 + 按 ts 清理）；
/// 这里用 HashMap，清理时显式按 ts 排序，语义等价且查找 O(1)。
static SNAPSHOTS: OnceLock<Mutex<HashMap<String, HashMap<String, SnapEntry>>>> = OnceLock::new();

fn snapshots() -> &'static Mutex<HashMap<String, HashMap<String, SnapEntry>>> {
    SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 结果写入本窗口快照槽（累积合并，不整体重置——对齐 FD-7）。
/// `raws` = 原生侧登记的「展示串键 → 路径真身」，只装 lossy 的那批（见 `ScanTally::raws`）。
/// 返回槽内条目数。
fn store_snapshot(
    label: &str,
    items: &[Value],
    raws: &HashMap<String, OsString>,
    ts: i64,
) -> usize {
    let mut store = snapshots().lock().unwrap_or_else(|e| e.into_inner());
    let slot = store.entry(label.to_string()).or_default();
    for item in items {
        let Some(p) = item.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        // emptyfolder 与 appdata 类型算目录；仅 emptyfolder 带 empty 标记
        let t = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
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
        slot.insert(
            key,
            SnapEntry {
                path: p.to_string(),
                kind: if t == "emptyfolder" || t == "appdata" {
                    "dir".to_string()
                } else {
                    "file".to_string()
                },
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

    let slot_size = store_snapshot(&label, &items, &raws, crate::engine::now_ms());
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
    json!({
        "success": true,
        "data": items,
        "errors": report.errors,
        "truncated": report.truncated,
        "unhandled": unhandled
    })
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
    // 审查 v2-M5：一律以 `it.target()`（原生侧交来的路径真身）为预检与删除对象，
    // 不再 `OsString::from(it.path)` —— 展示串是 lossy 后的文本，重建出来的可能是
    // 另一个真实存在的路径（删错对象），也可能谁都指不到（恒判 NotFound 却仍回 success:true）。
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
                    let child_count = std::fs::read_dir(&target).map(|r| r.count()).unwrap_or(0);
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
                "skipped": valid_safe.len(), "recycled": 0, "unhandled": unhandled,
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
    for d in &details {
        total_freed += js_uint(d.get("freed"));
        if d.get("status").and_then(|s| s.as_str()) == Some("ok") {
            success += 1;
            if d.get("mode").and_then(|m| m.as_str()) == Some("recycled") {
                recycled += 1;
            }
        } else {
            failed += 1;
            // 原生删除侧也有一道同名闸门（文件名无法无损表示 ⇒ 保护清单判定不可靠）；
            // 走到这里说明主侧漏判，仍要计进 unhandled 而不是只算「失败」
            if d.get("mode").and_then(|m| m.as_str()) == Some("unrecoverable-name") {
                unhandled += 1;
            }
        }
    }
    // skipped = 未被原生侧处理（预检剔除 + 未出结果行）的数量；unhandled 是其中说得出
    // 原因的那部分（审查 v2-M5），渲染层据此讲「N 项因文件名无法处理而未删」。
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
            "skipped": skipped,
            "unhandled": unhandled,
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
        let slot_size = store_snapshot(label, &items, &raws, 1);
        assert_eq!(slot_size, 1, "同一键位只留一条");
        let stored = snapshots().lock().unwrap_or_else(|e| e.into_inner());
        let entry = stored.get(label).and_then(|m| m.get(&path_key(&disp_a))).expect("条目应在槽内");
        assert_eq!(entry.target(), a.as_os_str().to_os_string(), "预检/删除必须打到原生真身上");
        assert!(entry.is_lossy());
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
}
