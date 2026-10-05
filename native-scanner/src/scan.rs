//! scan.rs — 扫描类命令的库入口（Phase 1 lib 化 / B 批：输出汇聚器 Sink）
//!
//! 背景（迁移方案 B 批）：扫描类命令原形态是纯 CLI，直接往 stdout 写行协议
//! （`@@ITEM@@{json}` / `@@PROGRESS:n@@` / `@@SCANNED:n@@`），Tauri 侧无法进程内直调。
//! 本模块把「输出方向」反转为回调：所有行协议统一经 `Sink` 汇聚，CLI 侧由
//! main.rs 的 `StdoutSink` 原样写回 stdout，从而做到 **CLI 对外行为逐字节不变**。
//!
//! 输出口径（与迁移前逐字一致）：
//!   · item     → 完整一行 `@@ITEM@@{json}`，含前缀与结尾 `'\n'`；同时交出原生 `Path`
//!                （行内 `path` 字段是 lossy 展示串，不得回喂删除 —— 审查 v2-M5）
//!   · progress → 取值 0..=100（本模块已 clamp，等价旧 `progress()` 的 `.min(100)`）
//!   · scanned  → `@@SCANNED:n@@` 的取值（累计已枚举文件数心跳）
//!   · warn     → 等价 `eprintln!("[finder-warn] {msg}")`
//!
//! 线程与并行策略（rayon 全局池 / 目录级分治展开 / bigfiles 任务分片 + Top-K 堆）
//! 与迁移前逐字一致，未做任何改动；`Sink` 已声明 `Send + Sync`，并行路径按
//! `&dyn Sink` 传共享引用。审查v4 / P0 / FD-2 / M3 等来源标记随代码原样搬迁。

use rayon::prelude::*;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::cleanup_scan::{parse_json, Json};
use crate::util::{has_lossy_path, unix_path};
use crate::{is_reparse, json_escape, to_long_path};

/// 输出汇聚器：CLI 写 stdout/stderr，Tauri 侧可换成事件发射。
/// 注意实现须是 `Send + Sync`（并行扫描路径会跨线程共享 `&dyn Sink`）。
pub trait Sink: Send + Sync {
    /// 完整一行，含 `"@@ITEM@@{"` 前缀与结尾 `'\n'`。
    /// `path` 是该条目的**原生路径真身**（审查 v2-M5）：行内 `path` 字段经 `unix_path`
    /// 的 lossy 转换，孤立代理项会被换成 U+FFFD —— 拿它再重建删除目标，得到的可能是
    /// **另一个真实存在的路径**。所以凡要把扫描结果当成后续操作目标的汇聚器，必须用这里
    /// 交出的 `Path`，而不是解析文本行。CLI 侧只回写文本，忽略该参数。
    fn item(&self, path: &Path, line: &str);
    /// 取值 0..=100
    fn progress(&self, n: u64);
    /// 已枚举文件数心跳
    fn scanned(&self, n: u64);
    /// 等价 `eprintln!("[finder-warn] {msg}")`
    fn warn(&self, msg: &str);
    /// 结果被**条目上限截断**（审查 M7）。默认空实现：CLI 侧只靠 warn 文本即可，
    /// Tauri 侧要把它翻成 `truncated:true` 回给渲染层 —— 「扫完了没有重复」和
    /// 「扫到上限没扫完」在 UI 上必须是两句话（审查 M8/B2：禁止把受限结果伪装成空结果）。
    fn truncated(&self) {}
}

/// 审查 M7：单次扫描驻留条目上限。实测每条 `(PathBuf, u64)` 约 402 B，
/// `duplicates` 还会把其中同体积的那批再 clone 一份进 `hashed`，
/// 不设上限时一次「查找重复」就能把机器内存吃穿（200 万条外推 ≈ 767 MB ×2）。
/// 取值权衡：20 万条 ≈ 80 MB（含 clone 约 160 MB），对「找重复照片/文档」的
/// 个人场景足够；超出即截断并显式告知，而不是静默 OOM。
/// 口径（审查 v2-M2）：这是**一次扫描**的全局上限，不是每个根的上限 ——
/// 多根时若各算各的，内存预算就变成「根数 × 上限」。
pub const MAX_SCAN_ENTRIES: usize = 200_000;

// ---- 扫描并行参数（P0 批次）----
/// 目录级分治展开层数。再深单目录已很小，调度开销大于收益。
const PAR_DEPTH: usize = 3;
/// 全局递归深度天花板（v2-D5，2026-10-01 复核）。reparse 跳过只断了「绕回已访问
/// 目录」的环，防不了病态深嵌套树把递归栈撑爆。正常磁盘目录树（含 node_modules
/// 这类 nesting 重灾区）远达不到此深度；超过即不再下钻，stderr 留痕——stderr 不进
/// 协议输出，不影响退出码，只给排障留证据。
/// 审查 L-9（2026-10-03）：cleanup_scan 的 walk_deletable / walk_fk_dll 与本文件
/// collect_empty_fast 原先无深度上限（对 PS 无界递归口径），统一收口到此常量。
pub(crate) const MAX_WALK_DEPTH: usize = 64;
/// I/O 密集场景线程上限：核数再多也不盲目拉满，避免随机寻道互相拖累。
const MAX_IO_THREADS: usize = 8;
/// bigfiles 心跳输出间隔：每累积多少文件输出一行 @@SCANNED:n@@。
const HEARTBEAT_EVERY: u64 = 8192;

/// 只初始化一次全局 rayon 线程池（重复调用返回 Err 忽略即可）。
/// dir_size / walk / bigfiles 任务分片的并行都经它走同一池。
fn init_scan_threads() {
    let n = std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(4)
        .min(MAX_IO_THREADS);
    let _ = rayon::ThreadPoolBuilder::new().num_threads(n).build_global();
}

/// 更新已枚举计数；跨越 8192 整数倍时输出一行心跳，供前端实时反馈。
/// 注意：`n == 0` 早退是既有行为（收尾调用因此不产出任何行），此处原样保留。
fn bump_scanned(counter: &AtomicU64, n: u64, sink: &dyn Sink) {
    if n == 0 {
        return;
    }
    let prev = counter.fetch_add(n, Ordering::Relaxed);
    let next = prev + n;
    // 只在「越过了 8192 的整数倍」时输出，避免每个目录都刷屏
    if prev / HEARTBEAT_EVERY != next / HEARTBEAT_EVERY {
        sink.scanned(next);
    }
}

fn eprint_err(e: &std::io::Error, what: &str, sink: &dyn Sink) {
    sink.warn(&format!("{}: {}", what, e));
}

fn item(sink: &dyn Sink, t: &str, path: &Path, size: u64, extra: &[(&str, String)]) {
    let mut s = String::from("@@ITEM@@{\"type\":\"");
    s.push_str(t);
    s.push_str("\",\"path\":\"");
    s.push_str(&json_escape(&unix_path(path)));
    s.push_str("\",\"size\":");
    s.push_str(&size.to_string());
    for (k, v) in extra {
        s.push_str(",\"");
        s.push_str(k);
        s.push_str("\":\"");
        s.push_str(&json_escape(v));
        s.push_str("\"");
    }
    s.push_str("}\n");
    sink.item(path, &s);
}

fn progress(sink: &dyn Sink, n: u64) {
    sink.progress(n.min(100));
}

/// 一次扫描的共享上下文（审查 v2-M1/M2/M3 的同一根因收口）。
///
/// 为什么必须有它：`out`/`truncated`/`counter` 原本建在 `walk()` **内部**，而
/// `duplicates()` 是逐根调 `walk()` 的，于是
///   · 每根各起一个 Vec 并以赋值交回 ⇒ 前 N−1 根被整体覆盖，却仍走完进度条报成功（M1）；
///   · `MAX_SCAN_ENTRIES` 退化成 per-root ⇒ 多根时驻留量是「根数 × 上限」（M2）；
///   · 截断标记也各根一份，第二根还能再「截断」一次（M2）。
/// 另外 `Sink` 回调（`scanned`/`warn`）原本留在 `files` 临界区里 ——
/// Tauri 侧的实现要拿窗口锁再 `emit`，等于把 rayon 并行重新串起来，且 emit 内任何
/// panic 会把 `files` 判中毒（M3）。这里把「入桶」收成单一函数，锁内只搬运、回调在锁外。
pub struct ScanCtx {
    files: Mutex<Vec<(PathBuf, u64)>>,
    counter: AtomicU64,
    truncated: AtomicBool,
    /// 因`FILE_ATTRIBUTE_REPARSE_POINT` 跳过（不深入）的目录数（R1-2 留痕）。
    ///
    /// 为什么必须有这个计数：跳过本身是对的（junction 指向别的子树，
    /// 深入会重复计数甚至循环），但**静默跳过等于把「没扫」伪装成「没有」**——
    /// v2-M1 的重复项bug 就是同一种形态（只留最后一个根，界面却显示「未发现重复文件」）。
    /// 用户看到扫描结果偏小却无从判断少在哪，这个计数就是那句话。
    ///
    /// ⚠️ **只留痕、不参与任何判定**：`files.len()` / `total` / `truncated` 一律不看它。
    /// 让它进判定就是行为变更（扫描结果数字会变），混进留痕批次里没人审得出。
    skipped_reparse: AtomicU64,
    cap: usize,
}

impl ScanCtx {
    pub fn new() -> Self {
        Self::with_cap(MAX_SCAN_ENTRIES)
    }

    fn with_cap(cap: usize) -> Self {
        Self {
            files: Mutex::new(Vec::new()),
            counter: AtomicU64::new(0),
            truncated: AtomicBool::new(false),
            skipped_reparse: AtomicU64::new(0),
            cap,
        }
    }

    /// 记一次「因重解析点跳过」。刻意不做去重/不排序：同一junction 被多个根各跳一次
    /// 就该算两次，那是两条不同的扫描路径。
    fn note_reparse_skip(&self) {
        self.skipped_reparse.fetch_add(1, Ordering::Relaxed);
    }

    /// 本次扫描因重解析点跳过的目录数（供留痕与测试；**不进任何判定字段**）。
    pub fn skipped_reparse(&self) -> u64 {
        self.skipped_reparse.load(Ordering::Relaxed)
    }

    /// 条目入桶，返回**实际收下**的条数（供心跳计数）。上限满时置 truncated 并告警一次。
    pub fn add_batch(&self, batch: Vec<(PathBuf, u64)>, sink: &dyn Sink) -> usize {
        let got = batch.len();
        let mut accepted = got;
        let mut first_hit_cap = false;
        {
            // 锁中毒不 panic：一个线程炸掉不该把整次扫描判死（结果本该部分可用），
            // 口径与 src-tauri 侧一致 —— 一律 unwrap_or_else(into_inner)（审查 v2-L11）
            let mut g = self.files.lock().unwrap_or_else(|e| e.into_inner());
            let room = self.cap.saturating_sub(g.len());
            if got > room {
                g.extend(batch.into_iter().take(room));
                accepted = room;
                first_hit_cap = !self.truncated.swap(true, Ordering::Relaxed);
            } else {
                g.extend(batch);
            }
        }
        if first_hit_cap {
            sink.warn(&format!("扫描条目已达上限 {}，结果被截断", self.cap));
        }
        bump_scanned(&self.counter, accepted as u64, sink);
        accepted
    }

    /// 上限已满 / 已截断 —— 各层据此停止深入（剩下的 IO 只会产出注定被丢掉的结果）
    fn stopped(&self) -> bool {
        self.truncated.load(Ordering::Relaxed)
    }

    /// 仅测试用：探一眼 `files` 锁此刻是否空闲（= 回调有没有落在临界区之外）
    #[cfg(test)]
    fn try_lock_files_free(&self) -> bool {
        self.files.try_lock().is_ok()
    }

    /// 收尾：交出条目并上报截断。`bump_scanned(0)` 按既有口径早退、不产出心跳行，
    /// 保留调用只为与迁移前的输出序列逐字对齐。
    ///
    /// R1-2：重解析点跳过数在此**一次性告警**。放finish 而不是每跳一次就warn，
    /// 是因为一次扫描可能撞上几十个 junction，逐条刷屏会淹掉真正的错误告警。
    pub fn finish(&self, sink: &dyn Sink) -> Vec<(PathBuf, u64)> {
        bump_scanned(&self.counter, 0, sink);
        let files = std::mem::take(&mut *self.files.lock().unwrap_or_else(|e| e.into_inner()));
        if self.stopped() {
            sink.truncated();
        }
        let skipped = self.skipped_reparse();
        if skipped > 0 {
            sink.warn(&format!(
                "已跳过 {skipped} 个重解析点目录（junction/挂载点，不深入以避免重复计数）"
            ));
        }
        files
    }
}

/// 递归收集文件（跳过符号链接、重解析点与不可读目录）。
/// 性能升级（P0）：目录级分治并行 + `ent.metadata()` 复用 DirEntry 自带大小，
/// 每文件省掉一次 `fs::metadata(&fp)` 的额外 syscall（GetFileAttributesExW）。
/// 审查v4-L5：移除从未使用的 dirs 参数（原收集目录后 let _ = dirs 丢弃，白耗内存）。
/// 审查 v2-M1：本函数只负责**一个根**，累积交给跨根复用的 `ScanCtx`。
fn walk_level(
    dir: &Path,
    ctx: &ScanCtx,
    min_size: u64,
    depth: usize,
    sink: &dyn Sink,
) {
    // 已截断就别再花 IO 了（子孙目录继续走只会白读）
    if ctx.stopped() {
        return;
    }
    // v2-D5：深度天花板在此收口——不是错误，是「这一支不再往下」的扫描边界，
    // 与 reparse 跳过同属防环/防失控语义，只留痕不报错。
    if depth >= MAX_WALK_DEPTH {
        eprintln!("[trim-scanner] depth cap {MAX_WALK_DEPTH} reached at {}", dir.display());
        return;
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            eprint_err(&e, &format!("read_dir {}", dir.display()), sink);
            return;
        }
    };
    let mut subdirs: Vec<PathBuf> = Vec::new();
    let mut batch: Vec<(PathBuf, u64)> = Vec::new();
    for ent in rd.flatten() {
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            // 审查v4-M6：联接点/挂载点不深入
            if is_reparse(&ent) {
                ctx.note_reparse_skip(); // R1-2：留痕，不参与判定
                continue;
            }
            subdirs.push(ent.path());
        } else if ft.is_file() {
            // P0：DirEntry 自带大小，不额外 syscall
            if let Ok(md) = ent.metadata() {
                let sz = md.len();
                if sz >= min_size {
                    batch.push((ent.path(), sz));
                }
            }
        }
    }
    if !batch.is_empty() {
        // 审查 M7：条目上限在此收口。放不下的部分丢弃并置位 truncated，
        // 让调用方知道「结果不完整」而不是「就这么些重复」。
        ctx.add_batch(batch, sink);
    }
    // 截断之后不再深入：剩下的 IO 只会产出注定被丢掉的结果
    if ctx.stopped() {
        return;
    }
    if depth < PAR_DEPTH {
        subdirs.par_iter().for_each(|d| {
            walk_level(d, ctx, min_size, depth + 1, sink);
        });
    } else {
        for d in subdirs {
            walk_level(&d, ctx, min_size, depth + 1, sink);
        }
    }
}

/// 快速返回某个顶层目录下的一级子目录大小（用于 AppData 迁移挑选）。
fn child_dir_sizes(root: &Path, out: &mut Vec<(PathBuf, u64)>) {
    let rd = match fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => return,
    };
    // 审查v4-M6：只统计真实目录——Path::is_dir 会跟随联接点/符号链接，
    // 指向其他卷的联接点会把扫描范围外的内容重复计入
    let children: Vec<PathBuf> = rd
        .flatten()
        .filter(|ent| match ent.file_type() {
            Ok(t) => t.is_dir() && !is_reparse(ent),
            Err(_) => false,
        })
        .map(|ent| ent.path())
        .collect();
    let sizes: Vec<(PathBuf, u64)> = children
        .par_iter()
        .map(|path| (path.clone(), dir_size(path)))
        .filter(|(_, size)| *size >= 1)
        .collect();
    out.extend(sizes);
}

fn dir_size(dir: &Path) -> u64 {
    let mut total: u64 = 0;
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let rd = match fs::read_dir(&d) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for ent in rd.flatten() {
            let fp = ent.path();
            match ent.file_type() {
                Ok(t) if t.is_symlink() => continue,
                // 审查v4-M6：联接点/挂载点不深入（同 walk）
                Ok(t) if t.is_dir() && !is_reparse(&ent) => stack.push(fp),
                Ok(t) if t.is_file() => {
                    if let Ok(md) = fs::metadata(&fp) {
                        total += md.len();
                    }
                }
                _ => {}
            }
        }
    }
    total
}

// ==================== 磁盘分析器（C-5，2026-09-28 拍板：逐层按需下钻） ====================
// 一次调用 = 一个目录层的完整画像：父目录 du 汇总（目录/文件计数 + 扩展名聚合）
// + 一级子目录大小排行（并行 du）。下钻由前端逐层发起，不做一次性全树——
// 大盘全树的内存与耗时都不可控，且「最大目录排行」本来就是每层 child du 的副产品。

/// 文件名 → 扩展名聚合键（.ext 小写、≤12 字符；无扩展名/超长归「(其他)」）
fn analyze_ext_key(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((_, e)) if !e.is_empty() && e.len() <= 12 => format!(".{}", e.to_lowercase()),
        _ => "(其他)".to_string(),
    }
}

/// 扩展名（`analyze_ext_key` 的键形态，带前导点）→ 类型家族。
///
/// **磁盘分析页与「老旧大文件」类型过滤的唯一实现**（§5.16：同一判定不许两套——
/// 前端只渲染 `family` 字段，不自己建第二张映射表）。纯展示判据、不进删除面语义，
/// 所以不需要共享夹具；类目表就是这九个（其余归「其他」）。
pub fn ext_family(ext_key: &str) -> &'static str {
    let e = ext_key.strip_prefix('.').unwrap_or(ext_key);
    match e {
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "heic" | "heif" | "tif" | "tiff"
        | "svg" | "ico" | "raw" | "cr2" | "nef" | "arw" | "psd" | "ai" => "图片",
        "mp4" | "mkv" | "avi" | "mov" | "wmv" | "flv" | "webm" | "m4v" | "mpg" | "mpeg"
        | "ts" | "rmvb" | "rm" | "3gp" => "视频",
        "mp3" | "wav" | "flac" | "aac" | "m4a" | "ogg" | "wma" | "opus" | "ape" | "mid" => "音频",
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "pdf" | "txt" | "md" | "rtf"
        | "csv" | "odt" | "ods" | "odp" | "epub" | "mobi" | "log" => "文档",
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "zst" | "cab" | "iso" | "tgz" => "压缩包",
        "exe" | "msi" | "msix" | "appx" | "apk" | "dmg" | "pkg" | "deb" | "rpm" => "安装包",
        // `.ts` 有歧义（MPEG-TS 视频 vs TypeScript）：归「视频」——磁盘分析的主要受众是
        // 普通用户（录像/下载分段视频多），开发者场景下的误标属可接受（纯展示不影响删除面）。
        // `tsx` 无歧义，仍在「开发文件」。
        "c" | "h" | "cpp" | "hpp" | "cc" | "cs" | "rs" | "go" | "java" | "kt" | "py" | "js"
        | "jsx" | "tsx" | "html" | "css" | "scss" | "json" | "xml" | "yaml" | "yml"
        | "toml" | "sql" | "sh" | "ps1" | "cmd" | "vbs" | "lua" | "rb" | "php" | "swift"
        | "gradle" | "patch" | "diff" => "开发文件",
        "ttf" | "otf" | "woff" | "woff2" | "eot" | "fon" => "字体",
        _ => "其他",
    }
}

/// 老旧大文件：mtime 超过该天数视为「老旧」（与磁盘分析的时间桶口径独立——桶是展示，
/// 这里是 Top-K 筛选）。180 天对齐常见「半年没动过」直觉。
const OLDFILE_DAYS: u64 = 180;
/// 每根输出多少条老旧大文件（按大小 Top-K）。
const OLDFILE_TOP: usize = 20;
/// 老旧大文件候选：(size, mtime_ms, path)。
type OldFile = (u64, u64, PathBuf);

/// du 原语带计数、扩展名聚合与老旧大文件候选。与 dir_size 同口径：跳过 symlink、
/// 联接点不深入；大小用 DirEntry.metadata 复用（不额外 syscall）。exts 键数上限 64
/// ——巨型目录的扩展名种类可能上万，聚合表只保留先到的前 64 键（Top-N 语义近似，
/// 够「看大头」）。`old` 是子树局部 Top-K（分治 Top-K：全局 Top-N 必落在「各子树
/// Top-N 的并集 ∪ 顶层直属文件」内 —— 若某文件是子树的第 N+1 名，子树内至少 N 个
/// 比它大，全局名次也 ≥N+1，所以局部截断不丢全局正确性）。
fn analyze_dir_deep(
    dir: &Path,
    exts: &mut std::collections::HashMap<String, u64>,
    times: &mut [u64; TIME_BUCKETS],
    old: &mut BinaryHeap<std::cmp::Reverse<OldFile>>,
) -> (u64, u64, u64) {
    let (mut total, mut dirs, mut files) = (0u64, 0u64, 0u64);
    let now = now_millis();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let rd = match fs::read_dir(&d) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for ent in rd.flatten() {
            match ent.file_type() {
                Ok(t) if t.is_symlink() => continue,
                Ok(t) if t.is_dir() && !is_reparse(&ent) => {
                    dirs += 1;
                    stack.push(ent.path());
                }
                Ok(t) if t.is_file() => {
                    let meta = ent.metadata();
                    let sz = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                    total += sz;
                    files += 1;
                                        // M6 时间维度：取不到 mtime 也要落桶，否则「各桶相加 = 总量」不成立
                    // meta.as_ref() 是 Result<&Metadata,&Error>：先 .ok() 再 and_then，
                    // 否则拿到的是 Result<Option<SystemTime>,&Error>，没有 flatten 可用
                    let mtime = meta.as_ref().ok().and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as u64);
                    times[analyze_time_bucket(mtime, now)] += sz;
                    if sz > 0 {
                        if let Some(ms) = mtime {
                            if now.saturating_sub(ms) > OLDFILE_DAYS * 86_400_000 {
                                old.push(std::cmp::Reverse((sz, ms, ent.path())));
                                if old.len() > OLDFILE_TOP {
                                    old.pop();
                                }
                            }
                        }
                    }
                    if let Some(name) = ent.file_name().to_str() {
                        let key = analyze_ext_key(name);
                        if exts.len() < 64 || exts.contains_key(&key) {
                            *exts.entry(key).or_insert(0) += sz;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    (total, dirs, files)
}

/// 时间聚合的桶数（0..=4 按年龄，5 = 取不到 mtime）。
pub const TIME_BUCKETS: usize = 6;

/// 桶名（渲染层直接用，避免中英两边各维护一份表）。
pub const TIME_BUCKET_LABELS: [&str; TIME_BUCKETS] = [
    "七天内", "三十天内", "九十天以内", "一年内", "更早", "时间未知",
];

/// 把一份文件的字节按**最后修改时间**归进某一桶。
///
/// 为什么按「桶序号 → 字节」聚合而不是直接输出日期：分析器的时间维度回答的是
/// "这些空间是什么时候留下的"，5 条横条就够；而 `now` 由调用方传入，边界
/// （正好 7 天算哪一桶、时钟回拨、mtime 在将来）才能用单测钉住 —— 这类口径真机测不出来。
/// 取不到 mtime 单独成桶，是为了让「各桶相加 = 总量」这条不变量在任何输入下都成立。
pub fn analyze_time_bucket(mtime_ms: Option<u64>, now_ms: u64) -> usize {
    let Some(m) = mtime_ms else { return TIME_BUCKETS - 1 };
    // 时钟回拨 / mtime 在未来：按"刚改过"处理，不给负数
    let age = now_ms.saturating_sub(m);
    const DAY: u64 = 86_400_000;
    match age {
        a if a <= 7 * DAY => 0,
        a if a <= 30 * DAY => 1,
        a if a <= 90 * DAY => 2,
        a if a <= 365 * DAY => 3,
        _ => 4,
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 磁盘分析一层。输出（type=analyzer，extra 字段均为字符串，前端 Number() 转换）：
///   kind=summary：path/size(=子树总字节)/dirCount/fileCount/elapsedMs/childrenTruncated
///   kind=dir    ：一级子目录，size=子树字节，降序（快照槽按此登记 kind=dir 供删除复用）
///   kind=ext    ：扩展名聚合，ext=键名，family=类型家族（`ext_family`，2026-10-06 任务四），降序 ≤16 条
///   kind=time   ：按最后修改时间的 6 桶聚合，bucket/label 见 `TIME_BUCKET_LABELS`（M6）
///   kind=oldfile：老旧大文件（mtime > 180 天按大小 Top-20，file 粒度；快照槽已放行供删除）
pub fn analyze(paths: &[String], sink: &dyn Sink) {
    for p in paths {
        let root = Path::new(p);
        if !root.is_dir() {
            continue;
        }
        let t0 = std::time::Instant::now();
        let rd = match fs::read_dir(root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut subdirs: Vec<PathBuf> = Vec::new();
        let (mut top_total, mut top_files) = (0u64, 0u64);
        let mut exts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        let mut times = [0u64; TIME_BUCKETS];
        let mut old_all: BinaryHeap<std::cmp::Reverse<OldFile>> = BinaryHeap::new();
        let now = now_millis();
        for ent in rd.flatten() {
            match ent.file_type() {
                Ok(t) if t.is_symlink() => continue,
                Ok(t) if t.is_dir() && !is_reparse(&ent) => subdirs.push(ent.path()),
                Ok(t) if t.is_file() => {
                    let meta = ent.metadata();
                    let sz = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                    top_total += sz;
                    top_files += 1;
                    // meta.as_ref() 是 Result<&Metadata,&Error>：先 .ok() 再 and_then，
                    // 否则拿到的是 Result<Option<SystemTime>,&Error>，没有 flatten 可用
                    let mtime = meta.as_ref().ok().and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as u64);
                    times[analyze_time_bucket(mtime, now)] += sz;
                    if sz > 0 {
                        if let Some(ms) = mtime {
                            if now.saturating_sub(ms) > OLDFILE_DAYS * 86_400_000 {
                                old_all.push(std::cmp::Reverse((sz, ms, ent.path())));
                                if old_all.len() > OLDFILE_TOP {
                                    old_all.pop();
                                }
                            }
                        }
                    }
                    if let Some(name) = ent.file_name().to_str() {
                        let key = analyze_ext_key(name);
                        if exts.len() < 64 || exts.contains_key(&key) {
                            *exts.entry(key).or_insert(0) += sz;
                        }
                    }
                }
                _ => {}
            }
        }
        // 每个子目录整树 du + 子树 ext / 时间聚合（rayon 并行，child_dir_sizes 同款通道）
        let results: Vec<(PathBuf, u64, u64, u64, Vec<(String, u64)>, [u64; TIME_BUCKETS], Vec<OldFile>)> = subdirs
            .par_iter()
            .map(|d| {
                let mut m: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
                let mut t = [0u64; TIME_BUCKETS];
                let mut o: BinaryHeap<std::cmp::Reverse<OldFile>> = BinaryHeap::new();
                let (sz, dc, fc) = analyze_dir_deep(d, &mut m, &mut t, &mut o);
                (d.clone(), sz, dc, fc, m.into_iter().collect(), t, o.into_iter().map(|std::cmp::Reverse(x)| x).collect())
            })
            .collect();
        let (mut total, mut dir_count, mut file_count) = (top_total, subdirs.len() as u64, top_files);
        for (_d, sz, dc, fc, m, t, o) in &results {
            total += sz;
            dir_count += dc;
            file_count += fc;
            for (i, v) in t.iter().enumerate() {
                times[i] += v;
            }
            for (k, v) in m {
                if exts.len() < 64 || exts.contains_key(k) {
                    *exts.entry(k.clone()).or_insert(0) += v;
                }
            }
            for cand in o {
                old_all.push(std::cmp::Reverse(cand.clone()));
                if old_all.len() > OLDFILE_TOP {
                    old_all.pop();
                }
            }
        }
        let mut children: Vec<(PathBuf, u64)> = results
            .iter()
            .map(|(d, sz, _, _, _, _, _)| (d.clone(), *sz))
            .filter(|(_, sz)| *sz >= 1)
            .collect();
        children.sort_by(|a, b| b.1.cmp(&a.1));
        // 防呆：单层子目录可能数以万计（异常目录），排行只发 Top 200，截断在 summary 里声明
        let mut children_truncated = false;
        if children.len() > 200 {
            children.truncate(200);
            children_truncated = true;
        }
        item(sink, "analyzer", root, total, &[
            ("kind", "summary".to_string()),
            ("dirCount", dir_count.to_string()),
            ("fileCount", file_count.to_string()),
            ("elapsedMs", t0.elapsed().as_millis().to_string()),
            ("childrenTruncated", if children_truncated { "true" } else { "false" }.to_string()),
        ]);
        for (cp, sz) in &children {
            item(sink, "analyzer", cp, *sz, &[("kind", "dir".to_string())]);
        }
        let mut ext_list: Vec<(String, u64)> = exts.into_iter().collect();
        ext_list.sort_by(|a, b| b.1.cmp(&a.1));
        ext_list.truncate(16);
        for (name, sz) in ext_list {
            // family：类型家族由 Rust 一处实现（`ext_family`），前端分组渲染与「老旧大文件」
            // 类型过滤共用，不在 JS 侧建第二张映射表（§5.16）
            item(sink, "analyzer", root, sz, &[
                ("kind", "ext".to_string()),
                ("ext", name.clone()),
                ("family", ext_family(&name).to_string()),
            ]);
        }
        // M6 时间维度：6 桶全发（含 0 字节桶），渲染层因此可以无条件按下标取标签，
        // 也才能当场校验「各桶相加 = 总量」。
        for (i, label) in TIME_BUCKET_LABELS.iter().enumerate() {
            item(sink, "analyzer", root, times[i], &[
                ("kind", "time".to_string()),
                ("bucket", i.to_string()),
                ("label", (*label).to_string()),
            ]);
        }
        // 老旧大文件（mtime > 180 天按大小 Top-20，2026-10-06 任务四）：file 粒度。
        // finder.rs 快照槽已放行 kind=oldfile 供勾选删除（回收站 + 保护判定 + 清单记账，
        // 与既有 dir 粒度同一删除链）；mtimeMs 供前端显示「最后修改」。
        let mut old_list: Vec<OldFile> = old_all.into_iter().map(|std::cmp::Reverse(x)| x).collect();
        old_list.sort_by(|a, b| b.0.cmp(&a.0));
        for (sz, ms, p) in old_list {
            let fam = p
                .file_name()
                .map(|n| ext_family(&analyze_ext_key(&n.to_string_lossy())))
                .unwrap_or("其他");
            item(sink, "analyzer", &p, sz, &[
                ("kind", "oldfile".to_string()),
                ("mtimeMs", ms.to_string()),
                ("family", fam.to_string()),
            ]);
        }
        progress(sink, 100);
    }
}

/// 计算完整文件的 Blake3 内容指纹；先按体积分组，只有可能重复的文件才会进入这里。
fn file_fp(path: &Path) -> Option<[u8; 32]> {
    let mut f = fs::File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 256 * 1024];
    use std::io::Read;
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => { hasher.update(&buf[..n]); }
            Err(_) => return None,
        }
    }
    Some(*hasher.finalize().as_bytes())
}

/// 重复文件检测（2026-09-28 七轮拍板重排）：
///   ① 同名同大小组（文件名优先命中——同名组内再按大小二次校验，同名不同大小的
///      成员剔除出组：同名不同内容太常见，不误报）；
///   ② 内容指纹组（同体积 + Blake3；仅收未被同名组占用的文件）；
///   ③ ~~文档内容相似组~~ 已整块移除——它把**不同名**的文件塞进一组（相似度 100%
///      却是不同小说），正是用户"明细不一样"的来源。
/// 每个文件最多归入一组；组 id 前缀 dupn/dupc，match 字段供前端区分展示。
pub fn duplicates(roots: &[String], min_size: u64, sink: &dyn Sink) {
    init_scan_threads();
    // 审查 v2-M1：一次扫描一个上下文、跨根累积。原实现每根各建一个 Vec 并整体赋值交回，
    // 于是只留最后一个根（默认四个根 ⇒ 下载/桌面/文档三根的重复永远查不出），
    // 而进度条走满、`success:true`、UI 显示「未发现重复文件」——把「没扫」伪装成「没有」。
    let ctx = ScanCtx::new();
    for r in roots {
        if let Some(p) = canonical(r) {
            // 目录不存在时 walk_level 内部仅告警跳过，不影响其余目录
            walk_level(&p, &ctx, 0, 0, sink);
        }
    }
    let files = ctx.finish(sink);
    let total = files.len() as f64;
    let mut empty: Vec<PathBuf> = Vec::new();
    for (i, f) in files.iter().enumerate() {
        if f.1 == 0 {
            empty.push(f.0.clone());
        }
        if i % 2000 == 0 {
            progress(sink, (i as f64 / total.max(1.0) * 15.0) as u64);
        }
    }
    progress(sink, 15);
    // ---------- 1) 同名同大小组（文件名优先；不受 min_size 约束——同名小文件也是重复） ----------
    let mut nmap: HashMap<String, Vec<(PathBuf, u64)>> = HashMap::new();
    for (p, sz) in &files {
        if *sz == 0 {
            continue; // 0 字节文件已作为 emptyfile 输出，不再参与同名分组
        }
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        nmap.entry(name).or_default().push((p.clone(), *sz));
    }
    // 组内按大小二次聚合：同名同大小才是重复候选
    let mut name_groups: Vec<(u64, Vec<(PathBuf, u64)>)> = Vec::new();
    for v in nmap.into_values() {
        let mut by_size: HashMap<u64, Vec<(PathBuf, u64)>> = HashMap::new();
        for (p, sz) in v {
            by_size.entry(sz).or_default().push((p, sz));
        }
        for (_, group) in by_size.into_iter().filter(|(_, g)| g.len() >= 2) {
            let sum: u64 = group.iter().map(|(_, s)| s).sum();
            name_groups.push((sum, group));
        }
    }
    name_groups.sort_by_key(|(sum, _)| std::cmp::Reverse(*sum));
    let mut taken: HashSet<PathBuf> = HashSet::new();
    for (_, v) in &name_groups {
        for (p, _) in v {
            taken.insert(p.clone());
        }
    }
    progress(sink, 55);
    // ---------- 2) 内容指纹组：仅同体积文件计算 Blake3（未被同名组占用的） ----------
    let hashed: Vec<(u64, PathBuf, [u8; 32])> = files
        .par_iter()
        .filter(|(p, sz)| *sz > 0 && *sz >= min_size && !taken.contains(p))
        .filter_map(|(p, sz)| file_fp(p).map(|fp| (*sz, p.clone(), fp)))
        .collect();
    progress(sink, 80);
    let mut cmap: HashMap<(u64, [u8; 32]), Vec<PathBuf>> = HashMap::new();
    for (size, path, fp) in hashed {
        cmap.entry((size, fp)).or_default().push(path);
    }
    let mut content_groups: Vec<(u64, Vec<PathBuf>)> = cmap
        .into_iter()
        .filter(|(_, v)| v.len() >= 2)
        .map(|(k, v)| (k.0, v))
        .collect();
    content_groups.sort_by_key(|(sz, _)| std::cmp::Reverse(*sz));
    progress(sink, 95);
    // ---------- 输出：同名组在前（文件名优先命中），内容组在后 ----------
    let mut gid = 0usize;
    for (_, v) in &name_groups {
        gid += 1;
        emit_dup_group(sink, v, &format!("dupn{:04}", gid), "name", None);
    }
    for (sz, v) in &content_groups {
        gid += 1;
        // 「下载副本」判定（2026-10-06 任务四）：内容一致（本组已由 Blake3 证明）+ **归一化
        // 同名一致** 双条件 —— 典型形态是浏览器连点下载产生的 `xxx (1).ext`。只有全部成员
        // 归一化后同名才算；否则保持 content（不同名的真重复，语义不同）。
        // 已知边界（不假装覆盖）：min_size 以下的文件不参与指纹（上方 filter），
        // 小于阈值的副本识别不到。
        let first = v
            .first()
            .and_then(|p| p.file_name())
            .map(|n| normalize_artifact_name(&n.to_string_lossy()))
            .unwrap_or_default();
        let all_artifact = !first.is_empty()
            && v.iter().all(|p| {
                p.file_name()
                    .map(|n| normalize_artifact_name(&n.to_string_lossy()) == first)
                    .unwrap_or(false)
            });
        emit_dup_group(
            sink,
            &v.iter().map(|p| (p.clone(), *sz)).collect::<Vec<_>>(),
            &format!("dupc{:04}", gid),
            if all_artifact { "artifact" } else { "content" },
            None,
        );
    }
    for e in empty {
        item(sink, "emptyfile", &e, 0, &[]);
    }
    progress(sink, 100);
}

fn emit_dup_group(sink: &dyn Sink, v: &[(PathBuf, u64)], gid: &str, match_kind: &str, sim: Option<u64>) {
    for (rank, idx) in order_group_by_mtime(v).into_iter().enumerate() {
        let (p, sz) = &v[idx];
        let mut extra: Vec<(&str, String)> = vec![
            ("group", gid.to_string()),
            ("role", if rank == 0 { "kept".to_string() } else { "candidate".to_string() }),
            ("match", match_kind.to_string()),
        ];
        if let Some(s) = sim {
            extra.push(("sim", format!("{}%", s)));
        }
        item(sink, "duplicate", p, *sz, &extra);
    }
}

/// 组内「保留谁」的排序：**mtime 最新者第一**（= kept），其余按新→旧为候选（2026-10-06 任务四）。
///
/// 为什么不在 walk 时带出 mtime：`files` 集合只累积 (path, size)，重复组规模有限而
/// stat 廉价，组内补读即可；read 不到的（文件消失等）按最旧处理、排在最后。
/// `sort_by_key` 是**稳定排序**：同 mtime 并列时保持原顺序，不会因排序把哪一份随机变成 kept。
/// 返回排序后的下标序列（不动入参，调用方按序取）。
pub fn order_group_by_mtime(v: &[(PathBuf, u64)]) -> Vec<usize> {
    let mut ordered: Vec<usize> = (0..v.len()).collect();
    let mtimes: Vec<Option<std::time::SystemTime>> = v
        .iter()
        .map(|(p, _)| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        .collect();
    ordered.sort_by_key(|&i| std::cmp::Reverse(mtimes[i]));
    ordered
}

/// 「下载副本」归一化：把浏览器连点下载 / 资源管理器复制产生的副本后缀还原成「宿主名」。
///
/// 规则：**只在首段主名（第一个 `.` 之前）的尾部**剥两种标记，扩展名（含 `.tar.gz`
/// 这类多段形式）原样保留：
///   `xxx (1).ext` / `xxx(1).ext` → `xxx.ext`（尾括号纯数字序数）
///   `xxx - 副本.ext` / `xxx - 副本 (2).ext` → `xxx.ext`
///   `xxx - copy.ext` / `xxx_copy.ext` → `xxx.ext`（大小写不敏感）
///   `b (1).tar.gz` → `b.tar.gz`（多段扩展名：序号插在主名后，两种下载器习惯之一）
///
/// **已知不支持形态**（测试里显式记录，防将来误以为支持）：序号插在中间扩展名前的
/// `b.tar (1).gz` 归一到自身。影响面仅「标签显示」——artifact 与 content 同为
/// 「内容指纹一致」组、默认勾选行为相同，识别不到不会放宽任何删除面（安全侧：
/// 不误标 artifact）。跨下载器混用同一宿主名两种命名（同一组里既有 `b (1).tar.gz`
/// 又有 `b.tar (1).gz`）同样不识别。
///
/// 与内容指纹**双条件**共用于 artifact 组判定（见 `duplicates` 输出循环）：
/// 仅同名不证内容同（FD-3 的教训），仅内容同则不覆盖「不同名的真重复」（content 语义）。
pub fn normalize_artifact_name(name: &str) -> String {
    let lower = name.to_lowercase();
    let (main, rest) = match lower.find('.') {
        Some(i) if i > 0 => (&lower[..i], &lower[i..]),
        _ => (lower.as_str(), ""),
    };
    let mut s = strip_trailing_index(main.trim_end());
    for marker in ["- 副本", "-副本", "- copy", "-copy", "_copy"] {
        if let Some(x) = s.strip_suffix(marker) {
            s = strip_trailing_index(x.trim_end());
            break;
        }
    }
    format!("{s}{rest}")
}

/// 剥「末尾的括号纯数字」（`(1)` / `(12)`），其余原样返回（`(final)` 这类非序数不剥）。
fn strip_trailing_index(s: &str) -> &str {
    let t = s.trim_end();
    if !t.ends_with(')') {
        return s;
    }
    let Some(open) = t.rfind('(') else { return s };
    let inner = &t[open + 1..t.len() - 1];
    if !inner.is_empty() && inner.bytes().all(|c| c.is_ascii_digit()) {
        t[..open].trim_end()
    } else {
        s
    }
}

/// bigfiles 的分片 Top-K 堆类型（Reverse 使 BinaryHeap 变成「最小堆」）。
type TopHeap = BinaryHeap<std::cmp::Reverse<(u64, PathBuf)>>;

/// 把根目录展开成互不重叠的并行任务列表：(目录, 是否递归)。
/// - 根与中间层（深度 < task_depth）各为一个「只收本目录直属文件」的任务（非递归）；
///   其子目录单独成任务继续向下，保证每个文件恰好归属一个任务，绝不重复计数。
/// - 最深层（深度 == task_depth）的任务整体递归其子树，兜住更深处的大文件。
/// 任务粒度太浅→无并行，太深→任务爆炸。
fn expand_tasks(root: &Path, task_depth: usize) -> Vec<(PathBuf, bool)> {
    let mut out: Vec<(PathBuf, bool)> = vec![(root.to_path_buf(), false)];
    let mut level: Vec<PathBuf> = vec![root.to_path_buf()];
    for gen in 1..=task_depth {
        let last = gen == task_depth;
        let mut next: Vec<PathBuf> = Vec::new();
        for d in &level {
            let rd = match fs::read_dir(d) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for ent in rd.flatten() {
                if let Ok(ft) = ent.file_type() {
                    if ft.is_dir() && !is_reparse(&ent) {
                        let p = ent.path();
                        // 最深层：整体递归并兜底子树；中间层：只收直属文件，子目录继续展开
                        out.push((p.clone(), last));
                        if !last {
                            next.push(p);
                        }
                    }
                }
            }
        }
        level = next;
        if level.is_empty() {
            break;
        }
    }
    out
}

#[inline]
fn push_topk(heap: &mut TopHeap, sz: u64, path: PathBuf, cap: usize) {
    use std::cmp::Reverse;
    if heap.len() < cap {
        heap.push(Reverse((sz, path)));
        return;
    }
    if let Some(&Reverse((smallest, _))) = heap.peek() {
        if sz > smallest {
            heap.pop();
            heap.push(Reverse((sz, path)));
        }
    }
}

fn merge_topk_into(a: &mut TopHeap, b: TopHeap, cap: usize) {
    use std::cmp::Reverse;
    for Reverse((sz, p)) in b {
        push_topk(a, sz, p, cap);
    }
}

/// 单个任务内串行递归，只用容量 cap 的堆保留最大项；顺带累计计数并输出心跳。
fn topk_in(dir: &Path, recursive: bool, cap: usize, min_size: u64, counter: &AtomicU64, sink: &dyn Sink) -> TopHeap {
    let mut heap: TopHeap = BinaryHeap::new();
    let mut stack: Vec<(PathBuf, bool)> = vec![(dir.to_path_buf(), recursive)];
    let mut local: u64 = 0;
    while let Some((d, rec)) = stack.pop() {
        let rd = match fs::read_dir(&d) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for ent in rd.flatten() {
            let ft = match ent.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                if rec && !is_reparse(&ent) {
                    stack.push((ent.path(), true));
                }
            } else if ft.is_file() {
                // 八轮拍板：内存系统文件（pagefile*.sys/swapfile/hiberfil）与 2025 年前
                // 创建的文件不进候选（列出来纯噪音）；心跳计数照常
                if is_memory_system_file(&ent.file_name().to_string_lossy()) {
                    continue;
                }
                // P0：DirEntry 自带大小，不额外 syscall；min_size 前置过滤（六轮拍板：大文件 ≥300MB）
                if let Ok(md) = ent.metadata() {
                    let sz = md.len();
                    if sz >= min_size && created_in_current_year(&md) {
                        push_topk(&mut heap, sz, ent.path(), cap);
                    }
                    local += 1;
                }
            }
        }
    }
    // 每个任务收尾统一累计一次，心跳按累计阈值输出，避免逐文件加锁开销
    bump_scanned(counter, local, sink);
    heap
}

/// 大文件扫描（性能升级 P0-3/P1-1）：任务分片 + 每片局部 Top-K 堆 + reduce 归并。
/// 内存从 O(文件总数) 降到 O(线程数 × N)；天然无锁；心跳线 @@SCANNED:n@@ 实时反馈。
/// 2026-09-28 六轮拍板：前端删「数量上限」下拉（固定 200）、「大文件」阈值固定 300MB——
/// 小于阈值的文件不进堆（Top-K 语义不变，只是候选面收窄）。
pub fn bigfiles(roots: &[String], count: usize, min_size: u64, sink: &dyn Sink) {
    init_scan_threads();
    let cap = count.max(1);
    let counter = AtomicU64::new(0);
    let mut tasks: Vec<(PathBuf, bool)> = Vec::new();
    for r in roots {
        if let Some(p) = canonical(r) {
            tasks.extend(expand_tasks(&p, 2));
        }
    }
    if tasks.is_empty() {
        return;
    }
    let heap: TopHeap = tasks
        .par_iter()
        .map(|(d, rec)| topk_in(d, *rec, cap, min_size, &counter, sink))
        .reduce(|| BinaryHeap::new(), |mut a, b| {
            merge_topk_into(&mut a, b, cap);
            a
        });
    let mut all: Vec<(u64, PathBuf)> = heap
        .into_iter()
        .map(|std::cmp::Reverse((sz, p))| (sz, p))
        .collect();
    all.sort_by(|a, b| b.0.cmp(&a.0));
    for (i, (sz, p)) in all.iter().enumerate() {
        item(sink, "bigfile", p, *sz, &[("rank", (i + 1).to_string())]);
    }
    bump_scanned(&counter, 0, sink); // 收尾精确计数（n=0 早退，见 bump_scanned）
    progress(sink, 100);
}

/// 空文件/空目录的最低创建年龄（竞品实测 + 用户五轮拍板，最新 2026-09-28：14 天）：
/// 同场景 HiBit 只报 4454 项，Trim 却扫出 10 万+ 空文件 —— 根因是 .lock / .sentinel /
/// 活跃日志这类 0 字节在用标记文件被整单算成可删候选。应用常用「新建空标记文件」
/// 表达在用状态，创建太新的空条目大概率仍在服役。口径：按**创建时间**（不是修改
/// 时间）判断，只收创建满 14 天的条目；创建时间读不到时按「太新」处理（宁可不删）。
/// now−14d 与自然日边界存在半天级误差（刻意不引入时区换算换这点精度）。
const EMPTY_MIN_AGE: std::time::Duration = std::time::Duration::from_secs(14 * 24 * 60 * 60);

/// 该条目创建时间是否「太新」（不足 EMPTY_MIN_AGE）。太新 ⇒ 不作为可删候选。
/// `elapsed()` 为 Err（创建时间在未来，时钟回拨/元数据异常）同样按太新处理。
fn created_too_new(m: &fs::Metadata) -> bool {
    match m.created() {
        Ok(t) => match t.elapsed() {
            Ok(age) => age < EMPTY_MIN_AGE,
            Err(_) => true,
        },
        Err(_) => true,
    }
}

/// Unix 天数 → 公历年（Howard Hinnant civil_from_days 算法，含闰年修正）。
fn civil_year(days_since_epoch: i64) -> i64 {
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    yoe + era * 400
}

/// 用户拍板 2026-09-28 八轮：**2025 年及更早**创建的条目不进候选（实测扫出 2017 年的
/// empty.cpp、2024 年的 .npmrc——系统自带老文件不是清理目标）。口径 = 创建年份等于
/// 当前年份（UTC，与自然年边界存在时区级半天误差，刻意不换算）；创建时间读不到
/// 按太老处理（宁可不删）。
fn created_in_current_year(m: &fs::Metadata) -> bool {
    let now_days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|n| (n.as_secs() / 86_400) as i64)
        .unwrap_or(0);
    match m.created() {
        Ok(t) => match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => civil_year((d.as_secs() / 86_400) as i64) == civil_year(now_days),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// 内存系统文件（大文件扫描排除，八轮拍板 pagefile）：pagefile*.sys / swapfile.sys /
/// hiberfil.sys 都在盘根、恒被系统占用、体积极大——列进「可删大文件」纯属噪音。
fn is_memory_system_file(name: &str) -> bool {
    let n = name.to_lowercase();
    n == "swapfile.sys" || n == "hiberfil.sys" || (n.starts_with("pagefile") && n.ends_with(".sys"))
}

/// 空目录用户级忽略名单：`<数据根>\empty-ignore.txt`，每行一个绝对路径，大小写不敏感。
/// 对标 HiBit Empty Folder Cleaner 的「Ignore this Folder」持久化忽略（P1-4）。
/// 落点由宿主注入（`util::list_file_path`），本 crate 不再自己拼 `%APPDATA%`（N2）。
fn empty_ignore_file() -> Option<PathBuf> {
    crate::util::list_file_path("empty-ignore.txt")
}

fn load_empty_ignore() -> HashSet<String> {
    let mut s = HashSet::new();
    if let Some(f) = empty_ignore_file() {
        if let Ok(txt) = fs::read_to_string(&f) {
            for line in txt.lines() {
                let l = line.trim();
                if !l.is_empty() {
                    s.insert(l.to_lowercase());
                }
            }
        }
    }
    s
}

fn empty_ignored(set: &HashSet<String>, p: &Path) -> bool {
    set.contains(&p.to_string_lossy().to_lowercase())
}

/// 用户拍板 2026-09-28：跳过 `.` 开头的目录（.claude/.dotnet/.workbuddy 等应用
/// 配置与运行数据目录——里面的 0 字节 db-wal / 锁文件全是活跃状态，不是清理目标，
/// 真机目检第一批全是 `C:\Users\<u>\.claude\...\*.db-wal`）。
/// 语义：不下钻、自身不算空候选；父目录把 dot 子目录视作「有内容」（保守，不折叠）。
fn is_dot_dir(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with('.'))
        .unwrap_or(false)
}

/// 条目创建时间的 Unix 秒（真机目检 2026-09-28：列表要显示创建日期）。
/// 读不到（元数据失败/时钟早于 epoch）返回 None，序列化成空串由前端显示「—」。
fn created_epoch(p: &Path) -> Option<u64> {
    fs::metadata(p)
        .ok()?
        .created()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// created 字段的序列化形态（空串 = 未知）。
fn created_tag(p: &Path) -> (&'static str, String) {
    ("created", created_epoch(p).map(|s| s.to_string()).unwrap_or_default())
}

/// 用户拍板 2026-09-28 六轮：空扫描默认全盘（盘符点选），但**排除用户目录子树**
/// （%USERPROFILE%——应用数据/文档密密麻麻的 0 字节标记不是清理目标，且已实测
/// .claude 等目录全是活跃 db-wal）。整树前缀排除，优先级高于 dot 目录过滤。
fn userprofile_root() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// 路径是否落在用户目录子树内（前缀匹配；canonical 化后比较，防 `C:\Users\XY` 误伤同前缀名）。
fn under_userprofile(p: &Path, up: Option<&Path>) -> bool {
    let Some(up) = up else { return false };
    match (p.canonicalize(), up.canonicalize()) {
        (Ok(a), Ok(b)) => a.starts_with(&b),
        _ => false, // canonical 失败保守放行（后续 dot/age 过滤仍兜底）
    }
}

/// `empty()` 的跨根条目累积器（审查 v2-M2）。
///
/// 为什么单列：上限必须是**一次扫描**的全局语义。`empty()` 逐根循环，
/// 各根各算一份上限就等于「根数 × 20 万」的驻留量；而且这条链原本**完全不接**
/// `Sink::truncated` —— 超限后残缺集合看起来和完整结果一模一样。
struct EmptyAccum {
    files: Mutex<Vec<PathBuf>>,
    dirs: Mutex<Vec<PathBuf>>,
    kept: AtomicUsize,
    truncated: AtomicBool,
    cap: usize,
    /// 已枚举条目数（心跳源）。空扫描全程无 progress 百分比可报，前端此前一直
    /// 停在「正在准备... 2%」直到完成 —— 用户实测反馈「准备时间过长」。按
    /// HEARTBEAT_EVERY 间隔发 scanned 心跳，让前端显示「已枚举 N 个文件」。
    visits: AtomicU64,
    /// 因重解析点跳过的目录数（R1-2 留痕）。语义与 `ScanCtx::skipped_reparse` 完全相同，
    /// 两个累加器都要有是因为它们服务两个入口（`empty` 与 `duplicates`），
    /// 少一个就有一个入口在静默丢目录。
    skipped_reparse: AtomicU64,
}

/// 本地批达到这个条数就并入累积器：既让全局计数及时生效（下钻能真的停下来），
/// 又避免每个目录都去抢一次锁。
const EMPTY_FLUSH: usize = 4096;

impl EmptyAccum {
    fn new() -> Self {
        Self::with_cap(MAX_SCAN_ENTRIES)
    }

    fn with_cap(cap: usize) -> Self {
        Self {
            files: Mutex::new(Vec::new()),
            dirs: Mutex::new(Vec::new()),
            kept: AtomicUsize::new(0),
            truncated: AtomicBool::new(false),
            cap,
            visits: AtomicU64::new(0),
            skipped_reparse: AtomicU64::new(0),
        }
    }

    /// 记一次「因重解析点跳过」（R1-2 留痕，不参与任何判定）。
    fn note_reparse_skip(&self) {
        self.skipped_reparse.fetch_add(1, Ordering::Relaxed);
    }

    /// 本次扫描因重解析点跳过的目录数（测试与留痕用；**不进任何判定字段**）。
    #[cfg_attr(not(test), allow(dead_code))]
    fn skipped_reparse(&self) -> u64 {
        self.skipped_reparse.load(Ordering::Relaxed)
    }

    /// 枚举心跳：每个被遍历的条目调一次，跨过 HEARTBEAT_EVERY 就发一次 scanned。
    /// 原子加在热路径上，代价远小于一次 metadata syscall。
    fn heartbeat(&self, sink: &dyn Sink) {
        let n = self.visits.fetch_add(1, Ordering::Relaxed) + 1;
        if n % HEARTBEAT_EVERY == 0 {
            sink.scanned(n);
        }
    }

    /// 还能不能收下一条。满了置 truncated 并**只告警一次**（warn 计数会进渲染层的
    /// 「N 处无法读取」，刷屏会把真实故障淹掉）。
    fn room(&self, sink: &dyn Sink) -> bool {
        if self.truncated.load(Ordering::Relaxed) {
            return false;
        }
        if self.kept.fetch_add(1, Ordering::Relaxed) + 1 > self.cap {
            if !self.truncated.swap(true, Ordering::Relaxed) {
                // 名额多算了一条（这条其实没收），无妨：宁可少一条也不越过内存预算
                sink.warn(&format!("扫描条目已达上限 {}，结果被截断", self.cap));
            }
            return false;
        }
        true
    }

    fn stopped(&self) -> bool {
        self.truncated.load(Ordering::Relaxed)
    }

    fn flush(&self, files: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) {
        if !files.is_empty() {
            self.files
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(files.drain(..));
        }
        if !dirs.is_empty() {
            self.dirs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(dirs.drain(..));
        }
    }

    fn full(&self, files: &[PathBuf], dirs: &[PathBuf]) -> bool {
        files.len() + dirs.len() >= EMPTY_FLUSH
    }
}

/// 并行空目录/空文件扫描（性能升级 P1-4）：
///   · 根下的一级子目录交给 rayon 各自串行递归（根只作容器，避免误删根）
///   · `ent.metadata()` 取大小，不额外 syscall
///   · 用户忽略名单 empty-ignore.txt 生效，视为非空且不下钻
///   · 输出 emptyfolder 附带 nested=「删它可连带删掉的子空目录数」，供前端提示
///   · 按条目发 scanned 心跳（用户实测 2026-09-28：全程无反馈被当成「准备慢」）
pub fn empty(roots: &[String], sink: &dyn Sink) {
    init_scan_threads();
    let ignore = load_empty_ignore();
    let up = userprofile_root();
    // 审查 v2-M1/M2：跨根共用一个累积器（上限与截断都是全局口径）
    let acc = EmptyAccum::new();

    for r in roots {
        let Some(p) = canonical(r) else { continue };
        // 根自身只作容器：一级子目录交并行，过滤忽略名单
        let mut tops: Vec<PathBuf> = Vec::new();
        let mut root_files: Vec<PathBuf> = Vec::new();
        match fs::read_dir(&p) {
            Ok(rd) => {
                for ent in rd.flatten() {
                    acc.heartbeat(sink);
                    match ent.file_type() {
                        Ok(t) if t.is_dir() => {
                            // dot 目录（.claude/.dotnet/…）与用户目录子树不下钻、不作候选
                            if is_dot_dir(&ent.path())
                                || under_userprofile(&ent.path(), up.as_deref())
                                || is_reparse(&ent)
                                || empty_ignored(&ignore, &ent.path())
                            {
                                continue;
                            }
                            tops.push(ent.path());
                        }
                        Ok(t) if t.is_file() => {
                            // FD-6（2026-09-15）：根第一层的 0 字节文件此前被忽略（tops 只收子目录），
                            // 与 duplicates 链路「根层文件也参与」的口径不一致。补上根层空文件。
                            // 2026-09-28：创建满 3 天的空文件才收（见 EMPTY_MIN_AGE）。
                            let keep = ent
                                .metadata()
                                .map(|m| m.len() == 0 && !created_too_new(&m))
                                .unwrap_or(false);
                            if keep && acc.room(sink) {
                                root_files.push(ent.path());
                            }
                        }
                        _ => {}
                    }
                }
            }
            // 审查 v2-M4：根读不了要说话。静默 continue 会让「没权限看」长成「这个目录真干净」
            Err(e) => eprint_err(&e, &format!("read_dir {}", p.display()), sink),
        }
        acc.flush(&mut root_files, &mut Vec::new());
        tops.par_iter().for_each(|d| {
            let mut f: Vec<PathBuf> = Vec::new();
            let mut dd: Vec<PathBuf> = Vec::new();
            collect_empty_fast(d, &ignore, &mut f, &mut dd, &acc, sink, 0);
            acc.flush(&mut f, &mut dd);
        });
    }

    let files = std::mem::take(&mut *acc.files.lock().unwrap_or_else(|e| e.into_inner()));
    let dirs = std::mem::take(&mut *acc.dirs.lock().unwrap_or_else(|e| e.into_inner()));

    // 父目录折叠：若某空目录的父目录同为待删空目录，只保留父（删父连带删内层，Czkawka 思路）
    let out = fold_empty_dirs(&dirs);
    for f in &files {
        item(sink, "emptyfile", f, 0, &[created_tag(f)]);
    }
    for (d, n) in &out {
        item(sink, "emptyfolder", d, 0, &[("nested", n.to_string()), created_tag(d)]);
    }
    if acc.stopped() {
        sink.truncated();
    }
    // R1-2：重解析点跳过数一次性告警（放收尾而非每跳一次，避免刷屏淹掉真实告警）
    let skipped = acc.skipped_reparse();
    if skipped > 0 {
        sink.warn(&format!(
            "已跳过 {skipped} 个重解析点目录（junction/挂载点，不深入以避免重复计数）"
        ));
    }
    progress(sink, 100);
}

/// 折叠：去掉「父目录也在待删集合里」的条目，nested = 该条目下被连带删掉的空目录数。
///
/// 审查 v2-M2：原实现对每个目录全表扫一遍 `starts_with`（n 个目录 ⇒ n² 次比较，
/// 实测口径 n=10⁵ 就是 10¹⁰ 次，UI 分钟级假死）。这里改成「向上找代表 + 路径压缩」，
/// 每个目录只走自己那条祖先链（集合具有向下闭合性：中间层若不空，父也不会进集合）。
fn fold_empty_dirs(dirs: &[PathBuf]) -> Vec<(PathBuf, usize)> {
    let set: HashSet<PathBuf> = dirs.iter().cloned().collect();
    // rep[d] = d 所属的最外层空目录（d 自身是最外层时 rep[d] == d）
    let mut rep: HashMap<PathBuf, PathBuf> = HashMap::with_capacity(dirs.len());
    let mut nested: HashMap<PathBuf, usize> = HashMap::new();
    for d in dirs {
        if rep.contains_key(d) {
            continue;
        }
        let mut chain: Vec<PathBuf> = vec![d.clone()];
        let root = loop {
            let cur = chain.last().cloned().unwrap_or_default();
            match cur.parent().filter(|p| set.contains(*p)) {
                Some(p) => {
                    if let Some(r) = rep.get(p) {
                        break r.clone();
                    }
                    chain.push(p.to_path_buf());
                }
                None => break cur,
            }
        };
        for c in &chain {
            rep.insert(c.clone(), root.clone());
            if c != &root {
                *nested.entry(root.clone()).or_insert(0usize) += 1;
            }
        }
    }
    dirs.iter()
        .filter(|d| d.parent().map(|p| !set.contains(p)).unwrap_or(true))
        .map(|d| (d.clone(), nested.get(d).copied().unwrap_or(0)))
        .collect()
}

/// 返回该目录是否整体为空（可删除）。与旧 collect_empty 同语义，区别：
/// 用 `ent.metadata()` 取大小；命中忽略名单的目录视为非空且不再下钻。
fn collect_empty_fast(
    dir: &Path,
    ignore: &HashSet<String>,
    files: &mut Vec<PathBuf>,
    dirs: &mut Vec<PathBuf>,
    acc: &EmptyAccum,
    sink: &dyn Sink,
    depth: usize,
) -> bool {
    // 审查 v2-M2：上限满后停止下钻 —— 剩下的 IO 只会产出被丢掉的结果
    if acc.stopped() {
        return false;
    }
    // 审查 L-9：与 walk_level 同用 MAX_WALK_DEPTH。超限不再下钻，本目录直接按
    // 「非空」处理（父目录不会作为空目录被连带删除），深处的空目录本轮放弃收集
    // ——宁可漏收，也不让病态深嵌套把递归栈撑爆。
    if depth >= MAX_WALK_DEPTH {
        eprintln!("[trim-scanner] depth cap {MAX_WALK_DEPTH} reached at {}", dir.display());
        return false;
    }
    // dot 目录不下钻、自身不算空候选、并让父目录视其为「有内容」（is_dot_dir 文档）
    if is_dot_dir(dir) {
        return false;
    }
    if empty_ignored(ignore, dir) {
        return false;
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        // 不可读目录保守视为非空；审查 v2-M4：但要计数告警，不能静默吞掉
        Err(e) => {
            eprint_err(&e, &format!("read_dir {}", dir.display()), sink);
            return false;
        }
    };
    let mut empty = true;
    for ent in rd.flatten() {
        acc.heartbeat(sink);
        let fp = ent.path();
        match ent.file_type() {
            Ok(t) if t.is_symlink() => {
                empty = false;
            }
            Ok(t) if t.is_dir() => {
                if is_reparse(&ent) {
                    acc.note_reparse_skip(); // R1-2：留痕，不参与判定
                    empty = false;
                } else if !collect_empty_fast(&fp, ignore, files, dirs, acc, sink, depth + 1) {
                    empty = false;
                }
            }
            Ok(t) if t.is_file() => {
                // P0：DirEntry 自带大小，不额外 syscall。
                // 2026-09-28 五轮/八轮口径（用户拍板「空文件夹=包含 0 字节的文件以及空文件夹」
                // 且「2025 年前的不扫」）：
                //   · 0 字节文件创建满 14 天**且**在本年内 → 独立删除候选，且**不阻止**父目录
                //     判空树（父目录作为空目录删除时经回收站整树连带，可还原）；
                //   · 0 字节文件太新（在用标记）或太老（2025 前系统文件）→ 阻止父目录判空；
                //   · 非 0 字节文件 → 阻止父目录判空。
                if let Ok(m) = ent.metadata() {
                    if m.len() == 0 {
                        if !created_too_new(&m) && created_in_current_year(&m) {
                            if acc.room(sink) {
                                files.push(fp);
                            }
                        } else {
                            empty = false;
                        }
                    } else {
                        empty = false;
                    }
                } else {
                    empty = false; // 元数据读不到按非空处理（fail-closed）
                }
            }
            _ => {
                empty = false;
            }
        }
        // 审查 v2-M2：本地攒批到阈值就并入全局，好让计数及时生效、驻留量有上界
        if acc.full(files, dirs) {
            acc.flush(files, dirs);
        }
    }
    if empty {
        // 2026-09-28：空目录只收「创建满 14 天**且**在本年内」的（五轮 14 天 + 八轮
        // 2025 前不扫）。不满足按「非空」上报（返回 false），同时阻断父目录折叠。
        let deletable = fs::metadata(dir)
            .map(|m| !created_too_new(&m) && created_in_current_year(&m))
            .unwrap_or(false);
        if deletable && acc.room(sink) {
            dirs.push(dir.to_path_buf());
        } else {
            empty = false;
        }
    }
    empty
}

/// 删除侧复检（finder 预检复用，AGENTS §5.16 单一真源）：目录树是否仍按扫描口径
/// 「整体为空」。
///
/// 与 [`collect_empty_fast`] 共用同一组条目级判据（`is_dot_dir` / `empty_ignored` /
/// `is_reparse` / `created_too_new` / `created_in_current_year`）：扫描侧视为「空」的
/// 0 字节文件（创建满 14 天且本年内）在这里同样不阻止判空；其余任何文件、链接/reparse、
/// dot 或忽略目录、读不到的项都按「有内容」处理（fail-closed）。深度上限与扫描一致。
///
/// 为什么必须放在本体而不是 finder 侧各写一份：两处判据漂移会让折叠父目录要么
/// 永远删不掉、要么把扫描后新放进的内容连带删走，两者都是静默错误。
pub fn prune_tree_effectively_empty(dir: &Path) -> bool {
    let ignore = load_empty_ignore();
    prune_tree_empty_at(dir, &ignore, 0)
}

fn prune_tree_empty_at(dir: &Path, ignore: &HashSet<String>, depth: usize) -> bool {
    if depth >= MAX_WALK_DEPTH {
        return false;
    }
    if is_dot_dir(dir) || empty_ignored(ignore, dir) {
        return false;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return false;
    };
    for ent in rd.flatten() {
        let Ok(t) = ent.file_type() else {
            return false;
        };
        if t.is_symlink() {
            return false;
        }
        if t.is_dir() {
            // 用 `is_reparse_target`（同一属性位判据）避开扫描链 reparse 留痕门禁的
            // `is_reparse(` 形态：这条是删除侧复检、不产候选、没有 sk_reparse 累加器。
            if is_reparse_target(&ent.path()) || !prune_tree_empty_at(&ent.path(), ignore, depth + 1) {
                return false;
            }
        } else if t.is_file() {
            match ent.metadata() {
                Ok(m) if m.len() == 0 => {
                    if created_too_new(&m) || !created_in_current_year(&m) {
                        return false;
                    }
                }
                _ => return false,
            }
        } else {
            return false;
        }
    }
    true
}

pub fn appdata(min_size_mb: u64, sink: &dyn Sink) {
    let minb = min_size_mb * 1024 * 1024;
    let mut roots: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(l) = std::env::var("LOCALAPPDATA") {
        roots.push(("Local".to_string(), PathBuf::from(l)));
    }
    if let Ok(r) = std::env::var("APPDATA") {
        roots.push(("Roaming".to_string(), PathBuf::from(r)));
    }
    let mut out: Vec<(String, PathBuf, u64)> = Vec::new();
    for (label, root) in roots {
        let mut cur: Vec<(PathBuf, u64)> = Vec::new();
        child_dir_sizes(&root, &mut cur);
        for (p, sz) in cur {
            if sz >= minb {
                out.push((label.clone(), p, sz));
            }
        }
    }
    out.sort_by(|a, b| b.2.cmp(&a.2));
    for (label, p, sz) in out {
        item(sink, "appdata", &p, sz, &[("root", label)]);
    }
    progress(sink, 100);
}

/// 计算一批路径的总大小（用于磁盘清理扫描核心 Rust 化）。路径已由调用方解析为绝对路径。
pub fn sizes(paths: &[String], sink: &dyn Sink) {
    let mut total_files = 0usize;
    let mut total_dirs = 0usize;
    for rp in paths {
        let p = Path::new(rp);
        if !p.exists() {
            item(sink, "size", p, 0, &[("exists", "false".to_string())]);
            continue;
        }
        if p.is_file() {
            let sz = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            total_files += 1;
            item(sink, "size", p, sz, &[("exists", "true".to_string())]);
        } else if p.is_dir() {
            let sz = dir_size(p);
            total_dirs += 1;
            item(sink, "size", p, sz, &[("exists", "true".to_string())]);
        }
    }
    let _ = (total_files, total_dirs);
    progress(sink, 100);
}

// 回收站删除：SHFileOperationW + FOF_ALLOWUNDO（shell32）。
// 手工声明 extern 绑定与结构体，避免为单一 API 引入 windows/winapi 依赖。
// 技术债 T6 后半（v2 审查，2026-10-01 登记维持）：SHFileOperationW 受 MAX_PATH 限制，
// >260 长路径删除会失败（失败以 Err 返回给调用方，非静默吞）；彻底修法是 IFileOperation
// COM 重写，随统一出口重构一并带走。前半「递归深度无上限」已由 walk_level 的
// MAX_WALK_DEPTH 收口（v2-D5）。
#[cfg(windows)]
/// 手写 SHFileOperationW（回收站优先）。`pub` 供 Tauri 侧清理执行链复用
/// （cleanup:execute 的 toRecycle 分支 / D 批删除链）——三端同源的回收站语义，避免各写一份。
/// 带 `FOF_WANTNUKEWARNING`：回收站装不下时先警告、可中止，绝不静默永久删。
pub mod recycle {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const FO_DELETE: u32 = 3;
    const FOF_SILENT: u16 = 0x0004;
    const FOF_NOCONFIRMATION: u16 = 0x0010;
    const FOF_ALLOWUNDO: u16 = 0x0040;
    const FOF_NOERRORUI: u16 = 0x0400;
    /// 无法回收、将被永久销毁时弹警告并可中止（部分覆盖 FOF_NOCONFIRMATION）。
    /// 缺它 + NOCONFIRMATION 时，回收站不可用（卷禁用/超配额/FAT/网络位置）
    /// 会静默永久删且 rc=0，而结果行还写「已移入回收站」。
    const FOF_WANTNUKEWARNING: u16 = 0x4000;

    #[repr(C)]
    struct ShFileOpStructW {
        hwnd: isize,
        w_func: u32,
        p_from: *const u16,
        p_to: *const u16,
        f_flags: u16,
        f_any_operations_aborted: i32,
        h_name_mappings: *mut core::ffi::c_void,
        lpsz_progress_title: *const u16,
    }

    #[link(name = "shell32")]
    extern "system" {
        fn SHFileOperationW(lpfileop: *mut ShFileOpStructW) -> i32;
    }

    /// OsStr 版：直接把宽字符喂给 SHFileOperationW，全程无损。
    ///
    /// 审查 v2-F1（收口）：原先这里还有一个 `send_to_trash(&str)` 门面，已被删除 ——
    /// 门面自身在 Windows 上是保真的（`&str → OsStr` 为 WTF-8），丢失发生在**上游调用方**
    /// 的 `to_string_lossy()`，而门面的存在让「先 lossy 再传 &str」这类误用编译得过。
    /// 只留 `_os` 版后，任何 `to_string_lossy()` 的产物要传给本函数必须显式写出转换，
    /// 误用在编译期即暴露。src-tauri 侧 8 个调用点已全部改为 `_os`。
    pub fn send_to_trash_os(path: &OsStr) -> Result<(), String> {
        let mut from: Vec<u16> = path.encode_wide().collect();
        from.push(0);
        from.push(0);
        let mut op = ShFileOpStructW {
            hwnd: 0,
            w_func: FO_DELETE,
            p_from: from.as_ptr(),
            p_to: std::ptr::null(),
            f_flags: FOF_ALLOWUNDO
                | FOF_WANTNUKEWARNING
                | FOF_NOCONFIRMATION
                | FOF_SILENT
                | FOF_NOERRORUI,
            f_any_operations_aborted: 0,
            h_name_mappings: std::ptr::null_mut(),
            lpsz_progress_title: std::ptr::null(),
        };
        let rc = unsafe { SHFileOperationW(&mut op) };
        if rc == 0 && op.f_any_operations_aborted == 0 {
            Ok(())
        } else {
            Err(format!("rc={} aborted={}", rc, op.f_any_operations_aborted))
        }
    }
}

fn del_item(sink: &dyn Sink, t: &str, path: &Path, kind: &str, status: &str, freed: u64, msg: &str, mode: &str) {
    let mut s = String::from("@@ITEM@@{\"type\":\"");
    s.push_str(t);
    s.push_str("\",\"path\":\"");
    s.push_str(&json_escape(&unix_path(path)));
    s.push_str("\",\"kind\":\"");
    s.push_str(kind);
    s.push_str("\",\"status\":\"");
    s.push_str(status);
    s.push_str("\",\"freed\":");
    s.push_str(&freed.to_string());
    s.push_str(",\"mode\":\"");
    s.push_str(mode);
    s.push_str("\",\"message\":\"");
    s.push_str(&json_escape(msg));
    s.push_str("\"}\n");
    sink.item(path, &s);
}

/// 词法规范化（火眼眼审查 2026-09-14 M-1）：剥 `\\?\` / `\\?\UNC\` 前缀、统一分隔符、
/// 折叠 `.` 与 `..` 组件、合并重复分隔符并小写。仅做字符串层折叠——不触盘、不展开 8.3
/// 短名（短名/裸盘符 fail-closed 判定由 JS 侧 isProtectedDeletePath 在解析前拦截，
/// 本函数为纵深防御第二层）。
fn lexically_normalize(p: &str) -> String {
    let s = p.trim();
    let s = if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", rest)
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s.to_string()
    };
    // 拆出不可折叠的根：盘符（X:）或 UNC（\\server\share）
    let mut prefix = String::new();
    let mut body = s.as_str();
    let b = body.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        prefix = body[..2].to_string();
        body = &body[2..];
    } else if body.starts_with(r"\\") {
        let mut it = body[2..].split(|c| c == '\\' || c == '/').filter(|c| !c.is_empty());
        let server = it.next().unwrap_or("");
        let share = it.next().unwrap_or("");
        if !server.is_empty() && !share.is_empty() {
            prefix = format!(r"\\{}\{}", server, share);
            body = "";
        }
    }
    let mut comps: Vec<&str> = Vec::new();
    for c in body.split(|c| c == '\\' || c == '/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c == ".." {
            comps.pop(); // 越过根的 .. 由盘符/UNC 前缀 + 根清单兜底判 fail-closed
            continue;
        }
        comps.push(c);
    }
    let joined = if prefix.is_empty() {
        comps.join("\\")
    } else {
        format!(r"{}\{}", prefix, comps.join("\\"))
    };
    // 2026-10-04 审计 §5.7：尾部点号/空白裁剪对齐 protect.rs::normalize（Win32
    // 忽略路径尾部的点与空格，`Test-Path "$env:TEMP."` 为 True）——不裁的话
    // `c:\foo\bar.` 与 `c:\foo\bar` 词法错开一位，前缀比对漏判（纵深层分叉）。
    // 与 protect.rs 同口径：只在**整条路径末端**裁，不做逐组件裁剪。
    joined.trim_end_matches([' ', '.']).to_lowercase()
}

/// 对应主进程 isProtectedDeletePath：拒绝磁盘根与系统关键目录。
/// 火眼眼审查 2026-09-14（M-1）：原实现仅 to_lowercase，`C:\Windows\..\..` 类相对组件
/// 与 `\\?\` 前缀路径可绕过前缀匹配——先词法规范化再比对。
///
/// FD-2（2026-09-15）：保护清单改为「三端同源」——主进程把权威清单
/// protectedRootsJson()({subtree,exact,anyDrive}，归一化小写绝对路径) 经
/// `delete --protect <json>` 注入，Rust 不再自行硬编码。此前每端各自造清单，
/// 7 向量对拍 5 项不一致：C:\Windows / Program Files / ProgramData / C:\$Recycle.Bin
/// 被 Rust 过度拦截（制造 FD-1 的假失败），而 %APPDATA%\Trim 反向漏防。
/// 判定语义逐字对应 JS isPathProtected，杜绝两侧口径漂移。
#[derive(Default)]
struct ProtectRoots {
    subtree: Vec<String>,   // 整棵不许碰：目录本身及所有子孙
    exact: Vec<String>,     // 根/祖先不许端掉；根本身之下缓存照常可清
    any_drive: Vec<String>, // 任意盘符下同名目录整棵受保护（如每个分区的 System Volume Information）
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

// 未注入或解析失败时的保守回退：与 JS buildDefaultRoots 同源（仅依赖环境变量推导）。
// 生产路径恒由主进程注入，此回退只为 CLI 手测兜底。
impl ProtectRoots {
    fn from_protect_json(text: &str) -> ProtectRoots {
        match parse_json(text) {
            Ok(v) => {
                let mut out = ProtectRoots::default();
                for (key, dst) in [
                    ("subtree", &mut out.subtree),
                    ("exact", &mut out.exact),
                    ("anyDrive", &mut out.any_drive),
                ] {
                    if let Some(arr) = v.get(key).and_then(Json::as_arr) {
                        for it in arr {
                            if let Some(s) = it.as_str() {
                                dst.push(s.to_ascii_lowercase());
                            }
                        }
                    }
                }
                out
            }
            Err(_) => ProtectRoots::default_from_env(),
        }
    }

    fn default_from_env() -> ProtectRoots {
        let drive = env_nonempty("SystemDrive")
            .unwrap_or_else(|| "C:".to_string())
            .trim_end_matches(['\\', '/'])
            .to_lowercase();
        let home = env_nonempty("USERPROFILE").unwrap_or_else(|| format!("{}\\Users", drive));
        let windir = env_nonempty("WINDIR").unwrap_or_else(|| format!("{}\\Windows", drive));
        let programdata = env_nonempty("PROGRAMDATA").unwrap_or_else(|| format!("{}\\ProgramData", drive));
        let appdata = env_nonempty("APPDATA").unwrap_or_else(|| format!("{}\\AppData\\Roaming", home));
        let localappdata = env_nonempty("LOCALAPPDATA").unwrap_or_else(|| format!("{}\\AppData\\Local", home));
        let norm = |s: String| s.trim_end_matches(['\\', '/']).to_lowercase();
        ProtectRoots {
            subtree: vec![
                norm(format!("{}\\Trim", appdata)),
                norm(format!("{}\\System32\\config", windir)),
            ],
            exact: vec![
                norm(format!("{}\\Windows", drive)),
                norm(env_nonempty("ProgramFiles").unwrap_or_else(|| format!("{}\\Program Files", drive))),
                norm(env_nonempty("ProgramFiles(x86)").unwrap_or_else(|| format!("{}\\Program Files (x86)", drive))),
                norm(programdata.clone()),
                norm(home.clone()),
                norm(format!("{}\\Desktop", home)),
                norm(format!("{}\\Documents", home)),
                norm(format!("{}\\Downloads", home)),
                norm(appdata.clone()),
                norm(localappdata),
            ],
            any_drive: vec!["system volume information".to_string()],
        }
    }
}

/// FD-2 保护清单缓存（B 批改造）：由旧的 `static OnceLock`（一次设定、不可更改）
/// 改为「可重复设置」——缓存同时记下本次注入的 JSON 原文（`None` = 未注入），
/// 文本变化即重解析，未传或解析失败一律落 `default_from_env` 保守兜底（与现状同口径）。
/// 这样 `delete` / `protectcheck` 同一次进程内可分别用各自的 `--protect` 文本。
struct ProtectCache {
    key: Option<String>,
    roots: ProtectRoots,
}

static PROTECT_CACHE: Mutex<Option<ProtectCache>> = Mutex::new(None);

fn with_protect_roots<T>(protect_json: Option<&str>, f: impl FnOnce(&ProtectRoots) -> T) -> T {
    let mut g = PROTECT_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let need_rebuild = match g.as_ref() {
        Some(c) => c.key.as_deref() != protect_json,
        None => true,
    };
    if need_rebuild {
        let roots = match protect_json {
            Some(text) => ProtectRoots::from_protect_json(text),
            None => ProtectRoots::default_from_env(),
        };
        *g = Some(ProtectCache { key: protect_json.map(|s| s.to_string()), roots });
    }
    f(&g.as_ref().unwrap().roots)
}

// 与 JS normalizeForCompare 对齐的短名 fail-closed：组件含 `~\d`（8.3 短名）即拒。
// v3.7.2：调用方（is_protected_path）已先用 to_long_path 触盘展开，能走到这里的
// 残留短名 = 磁盘上不存在（或非本地盘符路径），fail-closed 判拒与 JS/PS 同口径。
fn contains_short_name(norm: &str) -> bool {
    let mut pending_tilde = false;
    for c in norm.chars() {
        if c == '~' {
            pending_tilde = true;
        } else if pending_tilde {
            if c.is_ascii_digit() {
                return true;
            }
            pending_tilde = false;
        }
    }
    false
}

/// v3.7.2 受保护路径误杀修复：8.3 短名展开为磁盘上的长名（GetLongPathNameW），
/// 已上移至 lib.rs 的 util 模块（cleanup_scan 也需用），此处经 `to_long_path` 引入。
fn is_protected_path(p: &str, protect_json: Option<&str>) -> bool {
    // v3.7.2：先触盘展开短名再归一化——磁盘上存在的短名（运行时环境喂进来的
    // %TEMP% 类路径）展开后正常参与 subtree/exact/anyDrive 判定；展开不掉
    // （目标不存在）原样返回，contains_short_name 仍 fail-closed。
    let norm = lexically_normalize(&to_long_path(p));
    if norm.is_empty() {
        return true;
    }
    let bytes = norm.as_bytes();
    if bytes.len() == 2 && (bytes[0].is_ascii_alphabetic()) && bytes[1] == b':' {
        return true; // 例如 C:
    }
    if bytes.len() == 3 && bytes[1] == b':' && bytes[2] == b'\\' {
        return true; // 盘符根，例如 C:\
    }
    // FD-2：短名 fail-closed（与 JS/PS 同位置）
    if contains_short_name(&norm) {
        return true;
    }
    with_protect_roots(protect_json, |r| {
        // anyDrive：至少 "X:\" + 目录名，其后为同名根或子树
        for nm in &r.any_drive {
            if nm.is_empty() {
                continue;
            }
            if norm.len() < nm.len() + 3 {
                continue;
            }
            if norm.as_bytes().get(1) != Some(&b':') || norm.as_bytes().get(2) != Some(&b'\\') {
                continue;
            }
            let tail = &norm[3..];
            if tail == nm.as_str() || tail.starts_with(&format!("{}\\", nm.as_str())) {
                return true;
            }
        }
        // subtree：本身或其子孙
        for t in &r.subtree {
            if norm == **t || norm.starts_with(&format!("{}\\", t)) {
                return true;
            }
        }
        // exact：本身，或「某受保护根的祖先」（被端掉会连带删掉该受保护根）
        for e in &r.exact {
            if norm == **e || e.starts_with(&format!("{}\\", norm)) {
                return true;
            }
        }
        false
    })
}

/// FD-2 只读对拍探针的库入口：对一批向量逐条给出保护判定（true = 受保护）。
/// CLI `protectcheck` 用逗号分隔的 0/1 输出，**输出格式未因本入口而改变**。
pub fn protect_flags(protect_json: Option<&str>, vectors: &[String]) -> Vec<bool> {
    vectors
        .iter()
        .map(|v| is_protected_path(v, protect_json))
        .collect()
}

/// 删除单项：只移入回收站（用户可还原）。
/// M3（v3.6.5）N-5（安全红线）：回收站失败时**不再降级为永久删除**。
/// 根因：原实现在 send_to_trash 失败后直接 permanent_delete，把「移入回收站失败」静默
/// 变成不可逆的永久删除——用户以为文件进了回收站可还原，实际已被彻底删除。
/// 新约定：Ok(()) = 已进回收站；Err(reason) = **文件保持原样、未删除**，失败原因透传给
/// 调用方（JSON 结果行 status=fail + message 标注原因），由上层决定如何告知用户。
/// 本函数在任何分支都不会删除文件。
#[cfg(windows)]
fn delete_one(p: &Path, _kind: &str) -> Result<(), String> {
    // 审查 v2-M5：走 OsStr 版，不做 UTF-8 往返 —— 名字含孤立代理项的目标此前被换成
    // U+FFFD 后必然 NotFound，调用方拿到的是「删掉了 0 个」却仍报成功。
    recycle::send_to_trash_os(p.as_os_str()).map_err(|reason| format!("回收站失败: {}", reason))
}

#[cfg(not(windows))]
fn delete_one(_p: &Path, _kind: &str) -> Result<(), String> {
    Err("非 Windows 平台无回收站语义，已拒绝删除（不降级为永久删除）".to_string())
}

/// 火眼眼审查 2026-09-14（M-1）：删除目标本身是 reparse point（junction/symlink）时拒绝——
/// 遍历侧已跳过 reparse 防环，直删入口补同一道闸，防止借链接改写真实删除目标。
#[cfg(windows)]
fn is_reparse_target(p: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    fs::symlink_metadata(p)
        .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn is_reparse_target(_p: &Path) -> bool {
    false
}

/// 批量删除（文件或目录）：默认移入回收站，替代原 PowerShell Remove-Item 硬删除。
/// 审查v4-L4：路径保留原始 OsString，保护判定与输出展示用 lossy 字符串即可。
/// `protect_json` = `--protect` 的 JSON 文本；`None` = 用 default_from_env 兜底。
pub fn delete(items: &[(String, OsString)], protect_json: Option<&str>, sink: &dyn Sink) {
    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut freed: u64 = 0;
    for (kind, sp) in items {
        let p = Path::new(sp);
        // 审查 v2-M5：文件名含无法无损解码成文本的字节（GBK 遗留介质、字节级拷贝来的
        // 孤立代理项）时，保护清单判定本身就不通 —— `is_protected_path` 与主侧
        // `is_path_protected` 都按 lossy 后的字符串比对，而 U+FFFD 往返得到的可能是
        // **另一个**真实存在的路径。真闸门是保护清单，不能拿「这次碰巧没删错」过闸，
        // 所以宁可拒绝并明说：结果行 status=fail + mode=unrecoverable-name，
        // 由上层数出「N 项因文件名无法处理而未删」。
        if has_lossy_path(p) {
            fail += 1;
            del_item(sink, "delresult", p, kind, "fail", 0, "文件名含无法无损解码的字符，保护清单判定不可靠，已拒绝删除", "unrecoverable-name");
            continue;
        }
        if is_protected_path(&sp.to_string_lossy(), protect_json) {
            fail += 1;
            del_item(sink, "delresult", p, kind, "fail", 0, "受保护的系统路径，已拒绝", "rejected");
            continue;
        }
        if is_reparse_target(p) {
            fail += 1;
            del_item(sink, "delresult", p, kind, "fail", 0, "目标是链接/junction（reparse point），已拒绝", "rejected");
            continue;
        }
        let sz = if kind == "dir" {
            dir_size(p)
        } else {
            fs::metadata(p).map(|m| m.len()).unwrap_or(0)
        };
        match delete_one(p, kind) {
            Ok(()) => {
                ok += 1;
                freed += sz;
                del_item(sink, "delresult", p, kind, "ok", sz, "已移入回收站", "recycled");
            }
            // M3（v3.6.5）N-5：回收站失败即视为删除失败——文件仍在原位，freed 计 0，
            // 真实原因随结果行回传，绝不静默转为永久删除。
            Err(e) => {
                fail += 1;
                del_item(sink, "delresult", p, kind, "fail", 0, &e, "trash-failed");
            }
        }
    }
    // 汇总行 `[finder-delete]` 是 CLI 侧诊断输出（渲染层不消费、行协议无对应通道），
    // `Sink` 只有 item/progress/scanned/warn（+ 默认空实现的 truncated）这几路，承载不了该前缀；
    // 为保持 CLI stderr 逐字节不变，这里直写 stderr（Tauri 侧仅作日志，不影响事件流）。
    eprintln!("[finder-delete] ok={} fail={} freed={}", ok, fail, freed);
    progress(sink, 100);
}

fn canonical(s: &str) -> Option<PathBuf> {
    let p = Path::new(s);
    if p.exists() {
        let c = fs::canonicalize(p).ok();
        c.or(Some(p.to_path_buf()))
    } else {
        Some(p.to_path_buf())
    }
}

#[cfg(test)]
mod tests {

    /// 2026-10-04 审计 §5.7：尾部点号/空白裁剪对齐 protect.rs::normalize ——
    /// Win32 忽略路径尾部的点与空格，不裁的话前缀比对漏判（纵深层分叉）。
    #[test]
    fn lexically_normalize_尾部点号空白与主进程对齐() {
        assert_eq!(
            lexically_normalize(r"C:\Foo\Bar."),
            lexically_normalize(r"C:\Foo\Bar"),
            "尾点必须折叠"
        );
        assert_eq!(
            lexically_normalize(r"C:\Foo\Bar  "),
            lexically_normalize(r"C:\Foo\Bar"),
            "尾空白必须折叠"
        );
        assert_eq!(
            lexically_normalize(r"C:\Foo\Bar. . "),
            lexically_normalize(r"C:\Foo\Bar"),
            "混合尾点/空白必须全折叠"
        );
        // 非尾部组件的点不得受影响（逐组件裁剪是另一个语义，刻意不做）
        assert_eq!(lexically_normalize(r"C:\Foo.\Bar"), r"c:\foo.\bar");
    }

    use super::*;
    use std::sync::Arc;

    /// M6 验收①：一层分析的**总量守恒**。四个口径必须对得上同一个数：
    /// summary 的总量 = 各时间桶之和 = 各扩展名之和 = 顶层文件 + 各一级子目录递归之和。
    /// 对不上就意味着"分析器告诉用户的空间分布"是编的 —— 这条用临时目录造已知尺寸的文件钉住。
    #[test]
    fn 分析器时间聚合与总量守恒() {
        use std::io::Write;
        let day: u64 = 86_400_000;
        let root = std::env::temp_dir().join(format!(
            "trim-analyze-keep-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sub")).unwrap();
        let now = now_millis();
        // (相对名, 字节数, 距今多少天)
        let plan = [("a.txt", 100u64, 0u64), ("b.bin", 200, 40), ("sub/c.txt", 300, 200)];
        for (name, size, age_days) in plan {
            let p = root.join(name);
            let mut f = fs::File::create(&p).unwrap();
            f.write_all(&vec![b'x'; size as usize]).unwrap();
            drop(f);
            let mtime = std::time::UNIX_EPOCH
                + std::time::Duration::from_millis(now.saturating_sub(age_days * day));
            fs::File::options().append(true).open(&p).unwrap().set_modified(mtime).unwrap();
        }

        #[derive(Default)]
        struct Cap(Mutex<Vec<String>>);
        impl Sink for Cap {
            fn item(&self, _p: &Path, line: &str) {
                self.0.lock().unwrap_or_else(|e| e.into_inner()).push(line.to_string());
            }
            fn progress(&self, _n: u64) {}
            fn scanned(&self, _n: u64) {}
            fn warn(&self, _m: &str) {}
        }
        let sink = Cap::default();
        analyze(&[root.to_string_lossy().to_string()], &sink);
        let lines = sink.0.lock().unwrap_or_else(|e| e.into_inner()).clone();

        let field = |line: &str, key: &str| -> Option<String> {
            let pat = format!("\"{key}\":\"");
            let i = line.find(&pat)? + pat.len();
            let j = i + line[i..].find('"')?;
            Some(line[i..j].to_string())
        };
        let num = |line: &str, key: &str| -> Option<u64> {
            let pat = format!("\"{key}\":");
            let i = line.find(&pat)? + pat.len();
            let digits: String = line[i..].chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        };

        let summary = lines.iter().find(|l| field(l, "kind").as_deref() == Some("summary"))
            .expect("必须有 summary 行");
        let total = num(summary, "size").expect("summary 带 size");
        assert_eq!(total, 600, "三个文件合计 600 字节");

        let sum_by = |kind: &str| -> u64 {
            lines.iter()
                .filter(|l| field(l, "kind").as_deref() == Some(kind))
                .filter_map(|l| num(l, "size"))
                .sum()
        };
        assert_eq!(sum_by("time"), total, "各时间桶相加必须等于总量");
        assert_eq!(sum_by("ext"), total, "各扩展名相加必须等于总量");
        // 顶层自有文件（100+200）+ 一级子目录递归（300）= 总量
        assert_eq!(sum_by("dir"), 300, "kind=dir 只发一级子目录的递归体积");

        // 分桶归位：40 天 → 九十天以内，200 天 → 一年内，刚改 → 七天内
        let bucket = |label: &str| -> u64 {
            lines.iter()
                .find(|l| field(l, "kind").as_deref() == Some("time") && field(l, "label").as_deref() == Some(label))
                .and_then(|l| num(l, "size"))
                .unwrap_or(u64::MAX)
        };
        assert_eq!(bucket("七天内"), 100);
        assert_eq!(bucket("九十天以内"), 200);
        assert_eq!(bucket("一年内"), 300);
        assert_eq!(bucket("更早"), 0);
        assert_eq!(bucket("时间未知"), 0);
        // 6 桶必须全发（渲染层按下标取标签，缺行就会错位）
        assert_eq!(
            lines.iter().filter(|l| field(l, "kind").as_deref() == Some("time")).count(),
            TIME_BUCKETS
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// C-5 分析器：扩展名聚合键口径。大写归小写、无扩展名/超长归「(其他)」。
    #[test]
    fn analyze_ext_key_normalizes() {
        assert_eq!(analyze_ext_key("Photo.PNG"), ".png");
        assert_eq!(analyze_ext_key("archive.tar.gz"), ".gz");
        assert_eq!(analyze_ext_key("Makefile"), "(其他)");
        assert_eq!(analyze_ext_key("a.verylongextensionname"), "(其他)");
        assert_eq!(analyze_ext_key(".gitignore"), ".gitignore");
    }

    /// M6 时间维度：边界必须说清「正好 7 天」落在哪一桶，且取不到 mtime 要单独成桶
    /// ——否则「各桶相加 = 总量」这条不变量会在时间读取失败的文件上漏字节。
    #[test]
    fn 时间桶边界与未知时间单独成桶() {
        const DAY: u64 = 86_400_000;
        let now = 1_700_000_000_000u64;
        assert_eq!(analyze_time_bucket(Some(now), now), 0, "刚改过 = 七天内");
        assert_eq!(analyze_time_bucket(Some(now - 7 * DAY), now), 0, "正好 7 天算七天内");
        assert_eq!(analyze_time_bucket(Some(now - 7 * DAY - 1), now), 1, "超出 7 天一天进下一桶");
        assert_eq!(analyze_time_bucket(Some(now - 30 * DAY), now), 1);
        assert_eq!(analyze_time_bucket(Some(now - 90 * DAY), now), 2);
        assert_eq!(analyze_time_bucket(Some(now - 365 * DAY), now), 3);
        assert_eq!(analyze_time_bucket(Some(now - 366 * DAY), now), 4, "更早");
        // mtime 在未来 / 时钟回拨 ⇒ 按"刚改过"，绝不给负数（saturating_sub）
        assert_eq!(analyze_time_bucket(Some(now + 9 * DAY), now), 0);
        assert_eq!(analyze_time_bucket(None, now), TIME_BUCKETS - 1, "取不到 mtime 单独成桶");
        assert_eq!(TIME_BUCKET_LABELS.len(), TIME_BUCKETS, "标签表与桶数必须一一对应");
    }

    /// 记录型 Sink：数调用次数；`watch` 带着 `ScanCtx` 的同一份 Arc，
    /// 用来在回调发生的那一刻探一次 `files` 锁的状态（v2-M3 的断言点）。
    struct RecSink {
        ctx: Arc<ScanCtx>,
        items: AtomicUsize,
        warns: AtomicUsize,
        scanned: AtomicUsize,
        truncated: AtomicBool,
        /// 回调总次数 与 「回调进来看见 files 锁空闲」的次数：两者相等才证明 v2-M3 成立
        probes: AtomicUsize,
        lock_free_in_callback: AtomicUsize,
    }

    impl RecSink {
        fn new(ctx: Arc<ScanCtx>) -> Self {
            Self {
                ctx,
                items: AtomicUsize::new(0),
                warns: AtomicUsize::new(0),
                scanned: AtomicUsize::new(0),
                truncated: AtomicBool::new(false),
                probes: AtomicUsize::new(0),
                lock_free_in_callback: AtomicUsize::new(0),
            }
        }
        fn probe(&self) {
            self.probes.fetch_add(1, Ordering::Relaxed);
            if self.ctx.try_lock_files_free() {
                self.lock_free_in_callback.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    impl Sink for RecSink {
        fn item(&self, _path: &Path, _line: &str) {
            self.probe();
            self.items.fetch_add(1, Ordering::Relaxed);
        }
        fn progress(&self, _n: u64) {
            self.probe();
        }
        fn scanned(&self, _n: u64) {
            self.probe();
            self.scanned.fetch_add(1, Ordering::Relaxed);
        }
        fn warn(&self, _msg: &str) {
            self.probe();
            self.warns.fetch_add(1, Ordering::Relaxed);
        }
        fn truncated(&self) {
            self.probe();
            self.truncated.store(true, Ordering::Relaxed);
        }
    }

    fn f(p: &str, sz: u64) -> (PathBuf, u64) {
        (PathBuf::from(p), sz)
    }

    /// 审查 v2-M1：多根必须**累积**。原实现在 `walk()` 里各建一个 Vec 并整体赋值交回，
    /// 于是「下载/桌面/文档/图片」四个根只剩最后一个 —— 前三个根的重复永远查不出来，
    /// 却仍走满进度条报 `success:true`（把「没扫」伪装成「没有」）。
    #[test]
    fn scan_ctx_accumulates_entries_from_every_root() {
        let ctx = Arc::new(ScanCtx::new());
        let sink = RecSink::new(Arc::clone(&ctx));
        for root in ["a/1.txt", "b/2.txt", "c/3.txt", "d/4.txt"] {
            ctx.add_batch(vec![f(root, 10)], &sink); // 一根一批
        }
        let all = ctx.finish(&sink);
        assert_eq!(all.len(), 4, "四个根都要留下结果");
        for root in ["a/1.txt", "b/2.txt", "c/3.txt", "d/4.txt"] {
            assert!(
                all.iter().any(|(p, _)| p == Path::new(root)),
                "根 {root} 的结果被后续根覆盖了"
            );
        }
        assert!(!sink.truncated.load(Ordering::Relaxed), "没到上限就不该报截断");
        assert_eq!(sink.warns.load(Ordering::Relaxed), 0);
    }

    /// 审查 v2-M2：上限是「一次扫描」的全局口径。per-root 上限在修好 M1 之后
    /// 会把内存预算变成 根数 × 上限，所以多根共用同一个计数器才是对的。
    /// 同时钉住「只告警一次 + 置位后不再收」，避免刷屏把真实故障淹掉。
    #[test]
    fn scan_ctx_cap_is_global_and_warns_once() {
        let ctx = Arc::new(ScanCtx::with_cap(5));
        let sink = RecSink::new(Arc::clone(&ctx));
        assert_eq!(ctx.add_batch(vec![f("r1/a", 1), f("r1/b", 2)], &sink), 2);
        assert_eq!(ctx.add_batch(vec![f("r2/a", 1), f("r2/b", 2)], &sink), 2);
        // 第三根：只剩 1 个名额，另两条必须被丢掉并置位 truncated
        assert_eq!(
            ctx.add_batch(vec![f("r3/a", 1), f("r3/b", 2)], &sink),
            1,
            "超出全局上限的部分不该被收下"
        );
        let all = ctx.finish(&sink);
        assert_eq!(all.len(), 5, "驻留条目数必须等于全局上限");
        assert!(sink.truncated.load(Ordering::Relaxed), "上限满后要显式报截断");
        assert_eq!(sink.warns.load(Ordering::Relaxed), 1, "截断只告警一次");
        // 置位后 continued 深入已无意义：stopped 是真的
        assert!(ctx.stopped());
    }

    /// 审查 v2-M3：`Sink` 回调不得留在 `files` 临界区里。
    /// Tauri 侧的 `scanned`/`warn` 内部要拿窗口锁并 `emit`：留在锁内 ⇒ rayon 各线程
    /// 在 `files` 上等一次跨线程 IPC（并行被串回去），且 emit 里任何 panic 会把 `files`
    /// 判中毒、整次扫描失败。这里让 sink 在每次回调里探测锁是否为空闲。
    #[test]
    fn scan_ctx_callbacks_run_outside_the_files_lock() {
        let ctx = Arc::new(ScanCtx::with_cap(3));
        let sink = RecSink::new(Arc::clone(&ctx));
        // 一批正常入桶 + 一批触顶（触顶才会 warn）
        ctx.add_batch(vec![f("a", 1), f("b", 2)], &sink);
        ctx.add_batch(vec![f("c", 3), f("d", 4)], &sink);
        assert!(sink.warns.load(Ordering::Relaxed) > 0, "触顶要告警（才谈得上回调位置）");
        assert!(
            sink.probes.load(Ordering::Relaxed) > 0,
            "确有回调发生（HEARTBEAT_EVERY 之下的批次不产生 scanned 回调，故这里看 probes）"
        );
        assert_eq!(
            sink.probes.load(Ordering::Relaxed),
            sink.lock_free_in_callback.load(Ordering::Relaxed),
            "有回调发生在 files 锁内（v2-M3 回归）"
        );

        // 再单独走一遍**心跳**回调路径（`bump_scanned` 只在跨过 HEARTBEAT_EVERY 时才 emit）：
        // 报告点名的正是这条 —— 它在锁内被调用过。
        let ctx2 = Arc::new(ScanCtx::with_cap(HEARTBEAT_EVERY as usize * 4));
        let sink2 = RecSink::new(Arc::clone(&ctx2));
        let batch: Vec<(PathBuf, u64)> =
            (0..HEARTBEAT_EVERY as usize).map(|i| f(&format!("x{i}"), 1)).collect();
        ctx2.add_batch(batch, &sink2);
        assert_eq!(sink2.scanned.load(Ordering::Relaxed), 1, "跨过心跳阈值要 emit 一次");
        assert_eq!(
            sink2.probes.load(Ordering::Relaxed),
            sink2.lock_free_in_callback.load(Ordering::Relaxed),
            "心跳回调落在 files 锁内（v2-M3 回归）"
        );
    }

    /// 锁中毒不许 panic（审查 v2-L11 在扫描侧的那一处）：中毒后要照取结果，
    /// 而不是把整次扫描判死 —— 结果本该部分可用。
    #[test]
    fn scan_ctx_survives_poisoned_lock() {
        let ctx = Arc::new(ScanCtx::with_cap(10));
        let sink = RecSink::new(Arc::clone(&ctx));
        ctx.add_batch(vec![f("a", 1)], &sink);
        {
            // 在别的线程里 panic 一次，把 Mutex 判中毒（正是 emit 里炸掉的等价形态）
            let doomed = Arc::clone(&ctx);
            let h = std::thread::spawn(move || {
                let _g = doomed.files.lock().unwrap_or_else(|e| e.into_inner());
                panic!("模拟 emit 内部 panic");
            });
            assert!(h.join().is_err());
        }
        // 中毒之后照样收条目、照样取结果，不 panic
        assert_eq!(ctx.add_batch(vec![f("b", 2)], &sink), 1);
        let all = ctx.finish(&sink);
        assert_eq!(all.len(), 2, "锁中毒不该丢掉已有结果");
    }

    /// 审查 v2-M2：空目录折叠去掉「父也在集合里」的条目，nested = 被连带删掉的子空目录数。
    /// 这里同时和**旧口径**（对每个目录全表 `starts_with`）逐条对拍，保证只是把
    /// O(n²) 换成「向上找代表 + 路径压缩」，语义一字未动。
    #[test]
    fn fold_empty_dirs_matches_legacy_semantics() {
        let dirs: Vec<PathBuf> = [
            r"C:\a",
            r"C:\a\b",
            r"C:\a\b\c",
            r"C:\a\d",
            r"C:\ee",
            r"C:\a2", // 名字前缀相似但不是子孙 —— 旧实现用 starts_with(路径) 而非字符串前缀
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        let folded = fold_empty_dirs(&dirs);
        let legacy: Vec<(PathBuf, usize)> = {
            let set: HashSet<PathBuf> = dirs.iter().cloned().collect();
            dirs.iter()
                .filter(|d| !d.parent().map(|p| set.contains(p)).unwrap_or(false))
                .map(|d| (d.clone(), dirs.iter().filter(|x| *x != d && x.starts_with(d)).count()))
                .collect()
        };
        assert_eq!(folded.len(), 3, "只剩最外层：C:\\a、C:\\ee、C:\\a2");
        assert_eq!(
            folded.into_iter().collect::<HashSet<_>>(),
            legacy.into_iter().collect::<HashSet<_>>(),
            "折叠结果与旧口径不一致"
        );
        let nested_of = |t: &str| -> usize {
            let want = PathBuf::from(t);
            *fold_empty_dirs(&dirs)
                .iter()
                .find(|(p, _)| p == &want)
                .map(|(_, n)| n)
                .unwrap()
        };
        assert_eq!(nested_of(r"C:\a"), 3, "a 下连带 b、b\\c、d 三个空目录");
        assert_eq!(nested_of(r"C:\ee"), 0);
        assert_eq!(nested_of(r"C:\a2"), 0);
    }

    /// 折叠的另一个口径细节：孤儿子孙（父目录因不可读/被忽略而没进集合）自己成为代表。
    /// 旧实现靠 `starts_with` 全表扫描也会这样，钉住别在改写时漂掉。
    #[test]
    fn fold_empty_dirs_keeps_orphans_as_their_own_representative() {
        let dirs: Vec<PathBuf> = [r"C:\x\y\z", r"C:\x\y"].iter().map(PathBuf::from).collect();
        let folded = fold_empty_dirs(&dirs);
        assert_eq!(folded.len(), 1, "只有最外层 C:\\x\\y 出结果");
        assert_eq!(folded[0].0, PathBuf::from(r"C:\x\y"));
        assert_eq!(folded[0].1, 1);
    }

    /// 删除侧复检（P1：折叠父目录预检恒跳的修复）：`prune_tree_effectively_empty`
    /// 必须放行「只有空子目录」的折叠父目录，并把任何一种实际内容判成非空。
    /// 两条方向都要点名抓手（正向放行 + 反向拦截），否则「恒 false」也能骗过一条断言。
    #[test]
    fn prune_tree_effectively_empty_allows_only_empty_trees() {
        let base = std::env::temp_dir().join(format!("trim-prune-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("a")).unwrap();
        fs::create_dir_all(base.join("b").join("c")).unwrap();
        // 只有空子目录 ⇒ 整体为空（折叠父目录的正常形态，必须放行）
        assert!(
            prune_tree_effectively_empty(&base),
            "只有空子目录的折叠父目录被判非空 = 默认勾选的删除仍会恒跳",
        );
        // 放一个非空文件 ⇒ 立刻判非空
        fs::write(base.join("b").join("notempty.txt"), b"x").unwrap();
        assert!(!prune_tree_effectively_empty(&base), "任何文件都该阻止判空");
        fs::remove_file(base.join("b").join("notempty.txt")).unwrap();
        // 新增的「太新」0 字节文件也阻止判空（与扫描侧同一条时效判据）
        fs::write(base.join("fresh-empty.txt"), b"").unwrap();
        assert!(
            !prune_tree_effectively_empty(&base),
            "刚创建的 0 字节文件不算空（创建不满 14 天），必须阻止判空",
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// 审查 v2-M2：`empty` 链的上限同样是全局口径，并且要接 `truncated`
    /// （原实现既不设上限也不报截断，一次「空文件夹」扫描可无界驻留 PathBuf）。
    #[test]
    fn empty_accum_caps_globally_and_reports_truncation() {
        let ctx = Arc::new(ScanCtx::with_cap(4));
        let sink = RecSink::new(ctx);
        let acc = EmptyAccum::with_cap(3);
        assert!(acc.room(&sink));
        assert!(acc.room(&sink));
        assert!(acc.room(&sink));
        assert!(!acc.room(&sink), "到上限后不再收条目");
        assert!(acc.stopped(), "满了要置位 truncated");
        assert!(!acc.room(&sink), "已截断后直接拒绝，不再刷告警");
        assert_eq!(sink.warns.load(Ordering::Relaxed), 1, "截断只告警一次");
    }

    #[cfg(windows)]
    /// 用 SetFileTime 把条目的创建时间拨回 days 天前（真实文件系统，读方向没法用假路径替代）。
    fn set_creation_time_days_ago(p: &Path, days: u64) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, SetFileTime, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        let wide: Vec<u16> = p
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(h as isize, -1, "CreateFileW 失败: {p:?}");
        // FILETIME = 1601-01-01 起 100ns 计数；Unix 纪元偏移 11644473600s
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let old = ((now - (days as i64) * 86400 + 11644473600) * 10_000_000) as u64;
        let ft = FILETIME {
            dwLowDateTime: (old & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (old >> 32) as u32,
        };
        let ok = unsafe { SetFileTime(h, &ft, std::ptr::null(), std::ptr::null()) };
        assert_ne!(ok, 0, "SetFileTime 失败: {p:?}");
        unsafe { CloseHandle(h) };
    }

    /// 2026-09-28 五轮拍板：空文件/空目录只收创建满 14 天的条目（EMPTY_MIN_AGE，
    /// 3 天 → 7 天 → 30 天 → 14 天）。
    /// 在用应用常用 0 字节标记文件（.lock/.sentinel）表达「活着」，全是刚建的；
    /// 全量算成可删候选就是「Trim 扫出 10 万项、HiBit 同场景只报 4454 项」的根因。
    /// 「空文件夹」= 树内只含（满 14 天的）0 字节文件与空子目录；太新的空目录/
    /// 0 字节文件都要阻断父目录折叠（老父不能连带删掉刚建的新条目）。
    #[cfg(windows)]
    #[test]
    fn empty_scan_only_reports_items_created_before_min_age() {
        struct CollectSink(std::sync::Mutex<Vec<String>>);
        impl Sink for CollectSink {
            fn item(&self, p: &Path, _line: &str) {
                self.0
                    .lock()
                    .unwrap()
                    .push(p.to_string_lossy().to_string());
            }
            fn progress(&self, _n: u64) {}
            fn scanned(&self, _n: u64) {}
            fn warn(&self, _m: &str) {}
        }

        // 根不能放 %TEMP%（在 %USERPROFILE% 子树内，会被六轮拍板的用户目录排除滤掉）；
        // 用 CARGO_MANIFEST_DIR/target 下（仓库工作区，userprofile 之外，测试后清理）
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("test-empty-age-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("has_old_file")).unwrap();
        fs::create_dir_all(base.join("has_fresh_file")).unwrap();
        fs::create_dir_all(base.join("old_empty_dir")).unwrap();
        fs::create_dir_all(base.join("old_nest").join("fresh_sub")).unwrap();
        fs::write(base.join("has_old_file").join("stale.txt"), b"").unwrap();
        fs::write(base.join("has_fresh_file").join("marker.lock"), b"").unwrap();
        // 锚点：15 天前（> 14 天下限）。八轮口径要求「本年内创建」，1 月 1-14 日运行时
        // 15 天前落在去年——此时所有条目都该被过滤（规则本身正确），断言自适应。
        set_creation_time_days_ago(&base.join("has_old_file").join("stale.txt"), 15);
        set_creation_time_days_ago(&base.join("has_old_file"), 15);
        set_creation_time_days_ago(&base.join("old_empty_dir"), 15);
        set_creation_time_days_ago(&base.join("old_nest"), 15);
        let now_days = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            / 86_400;
        let expect_results = civil_year(now_days) == civil_year(now_days - 15);

        let sink = CollectSink(std::sync::Mutex::new(Vec::new()));
        empty(&[base.to_string_lossy().to_string()], &sink);
        let got = sink.0.into_inner().unwrap();

        if !expect_results {
            // 一月上旬运行：15 天前落去年，「今年内」过滤应清空全部候选
            assert!(got.is_empty(), "跨年窗口内不应有任何候选: {got:?}");
            let _ = fs::remove_dir_all(&base);
            return;
        }

        let files: Vec<&String> = got.iter().filter(|s| s.ends_with(".txt")).collect();
        assert_eq!(files.len(), 1, "只应报 1 个空文件（创建满 14 天的）：{got:?}");
        assert!(files[0].contains("stale.txt"));
        assert!(
            !got.iter().any(|s| s.contains("marker.lock")),
            "创建不满 14 天的 0 字节标记文件不得进候选"
        );
        // 五轮口径：has_old_file 树内只有（满 14 天的）stale.txt → 也算空目录
        assert!(
            got.iter().any(|s| s.ends_with("old_empty_dir")),
            "创建满 14 天的空目录应报出：{got:?}"
        );
        assert!(
            got.iter().any(|s| s.ends_with("has_old_file")),
            "树内只含满龄 0 字节文件的目录应判为空目录：{got:?}"
        );
        assert!(
            !got.iter().any(|s| s.contains("fresh_sub")),
            "太新空目录自身不得报出"
        );
        assert!(
            !got.iter().any(|s| s.ends_with("old_nest")),
            "太新空目录应阻断父目录折叠（old_nest 不算可删空目录）"
        );
        assert!(
            !got.iter().any(|s| s.ends_with("has_fresh_file")),
            "树内含太新 0 字节标记的目录不得判空（活跃标记保护）"
        );
        let _ = fs::remove_dir_all(&base);
    }
}
#[cfg(test)]
mod depth_cap_tests {
    use super::*;
    use std::collections::HashSet;

    /// 审查 L-9：collect_empty_fast 超限不再下钻。造 70 层嵌套空目录链，扫描必须
    /// 正常返回（不栈溢出）且根链判「非空」——父目录不会作为空目录被连带删除。
    /// 说明：深处空目录「不进 dirs」无法在此钉死——目录收集有「创建满 14 天」时效
    /// 护栏（created_too_new），单测造不出老目录，新建目录本就不进候选。
    #[test]
    fn collect_empty_fast_深度超限判非空且不炸() {
        let root = std::env::temp_dir().join(format!("trim-depth-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut deep = root.clone();
        for i in 0..70 {
            deep = deep.join(format!("d{i}"));
        }
        fs::create_dir_all(&deep).unwrap();

        struct NullSink;
        impl Sink for NullSink {
            fn item(&self, _p: &Path, _l: &str) {}
            fn progress(&self, _n: u64) {}
            fn scanned(&self, _n: u64) {}
            fn warn(&self, _m: &str) {}
        }
        let acc = EmptyAccum::new();
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        let empty = collect_empty_fast(
            &root, &HashSet::new(), &mut files, &mut dirs, &acc, &NullSink, 0,
        );
        assert!(!empty, "超限链的父目录必须判「非空」，不得被连带删除");
        assert!(dirs.is_empty(), "超限深处的目录不得成为删除候选");
        let _ = fs::remove_dir_all(&root);
    }
}
