//! scan.rs — 扫描类命令的库入口（Phase 1 lib 化 / B 批：输出汇聚器 Sink）
//!
//! 背景（迁移方案 B 批）：扫描类命令原形态是纯 CLI，直接往 stdout 写行协议
//! （`@@ITEM@@{json}` / `@@PROGRESS:n@@` / `@@SCANNED:n@@`），Tauri 侧无法进程内直调。
//! 本模块把「输出方向」反转为回调：所有行协议统一经 `Sink` 汇聚，CLI 侧由
//! main.rs 的 `StdoutSink` 原样写回 stdout，从而做到 **CLI 对外行为逐字节不变**。
//!
//! 输出口径（与迁移前逐字一致）：
//!   · item     → 完整一行 `@@ITEM@@{json}`，含前缀与结尾 `'\n'`
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use crate::cleanup_scan::{parse_json, Json};
use crate::util::unix_path;
use crate::{is_reparse, json_escape, to_long_path};

/// 输出汇聚器：CLI 写 stdout/stderr，Tauri 侧可换成事件发射。
/// 注意实现须是 `Send + Sync`（并行扫描路径会跨线程共享 `&dyn Sink`）。
pub trait Sink: Send + Sync {
    /// 完整一行，含 `"@@ITEM@@{"` 前缀与结尾 `'\n'`
    fn item(&self, line: &str);
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
pub const MAX_SCAN_ENTRIES: usize = 200_000;

// ---- 扫描并行参数（P0 批次）----
/// 目录级分治展开层数。再深单目录已很小，调度开销大于收益。
const PAR_DEPTH: usize = 3;
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
    sink.item(&s);
}

fn progress(sink: &dyn Sink, n: u64) {
    sink.progress(n.min(100));
}

/// 递归收集文件（跳过符号链接、重解析点与不可读目录）。
/// 性能升级（P0）：目录级分治并行 + `ent.metadata()` 复用 DirEntry 自带大小，
/// 每文件省掉一次 `fs::metadata(&fp)` 的额外 syscall（GetFileAttributesExW）。
/// 审查v4-L5：移除从未使用的 dirs 参数（原收集目录后 let _ = dirs 丢弃，白耗内存）。
fn walk(path: &Path, files: &mut Vec<(PathBuf, u64)>, min_size: u64, sink: &dyn Sink) {
    init_scan_threads();
    let counter = AtomicU64::new(0);
    // 审查 M7：截断标记要贯穿整棵递归（多根时由调用方共用同一个），一旦置位就不再深入
    let truncated = AtomicBool::new(false);
    // 用 Mutex 承接并发结果；对只需 Top-N 的调用方应改用 bigfiles 的任务分片（免全量驻留）。
    let out: Mutex<Vec<(PathBuf, u64)>> = Mutex::new(Vec::new());
    walk_level(&path.to_path_buf(), &out, min_size, &counter, 0, sink, &truncated);
    bump_scanned(&counter, 0, sink); // 收尾再输出一次精确的最终计数（n=0 早退，见 bump_scanned）
    *files = out.into_inner().unwrap();
    if truncated.load(Ordering::Relaxed) {
        sink.truncated();
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_level(
    dir: &PathBuf,
    files: &Mutex<Vec<(PathBuf, u64)>>,
    min_size: u64,
    counter: &AtomicU64,
    depth: usize,
    sink: &dyn Sink,
    truncated: &AtomicBool,
) {
    // 已截断就别再花 IO 了（子孙目录继续走只会白读）
    if truncated.load(Ordering::Relaxed) {
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
        let mut g = files.lock().unwrap_or_else(|e| e.into_inner());
        let room = MAX_SCAN_ENTRIES.saturating_sub(g.len());
        if batch.len() > room {
            g.extend(batch.into_iter().take(room));
            if !truncated.swap(true, Ordering::Relaxed) {
                sink.warn(&format!("扫描条目已达上限 {MAX_SCAN_ENTRIES}，结果被截断"));
            }
        } else {
            bump_scanned(counter, batch.len() as u64, sink);
            g.extend(batch);
        }
    }
    // 截断之后不再深入：剩下的 IO 只会产出注定被丢掉的结果
    if truncated.load(Ordering::Relaxed) {
        return;
    }
    if depth < PAR_DEPTH {
        subdirs.par_iter().for_each(|d| {
            walk_level(d, files, min_size, counter, depth + 1, sink, truncated);
        });
    } else {
        for d in subdirs {
            walk_level(&d, files, min_size, counter, depth + 1, sink, truncated);
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

/// 重复文件三级检测：内容指纹（体积+Blake3）> 文档内容相似 > 同名文件。
/// 每个文件最多归入一组；组 id 前缀 dupc/dups/dupn，match 字段供前端区分展示。
pub fn duplicates(roots: &[String], min_size: u64, sink: &dyn Sink) {
    let mut files: Vec<(PathBuf, u64)> = Vec::new();
    for r in roots {
        if let Some(p) = canonical(r) {
            // 目录不存在时 walk 内部仅告警跳过，不影响其余目录
            walk(&p, &mut files, 0, sink);
        }
    }
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
    // ---------- 1) 内容指纹组：仅同体积文件计算 Blake3 ----------
    let hashed: Vec<(u64, PathBuf, [u8; 32])> = files
        .par_iter()
        .filter(|(_, sz)| *sz > 0 && *sz >= min_size)
        .filter_map(|(p, sz)| file_fp(p).map(|fp| (*sz, p.clone(), fp)))
        .collect();
    progress(sink, 60);
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
    let mut taken: HashSet<PathBuf> = HashSet::new();
    for (_, v) in &content_groups {
        for p in v {
            taken.insert(p.clone());
        }
    }
    // ---------- 2) 文档内容相似组 ----------
    let similar_groups = find_similar_doc_groups(&files, &taken, sink);
    for (_, v) in &similar_groups {
        for (p, _) in v {
            taken.insert(p.clone());
        }
    }
    progress(sink, 85);
    // ---------- 3) 同名文件组（含扩展名一致，忽略大小写） ----------
    let mut nmap: HashMap<String, Vec<(PathBuf, u64)>> = HashMap::new();
    for (p, sz) in &files {
        if *sz == 0 || taken.contains(p) {
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
    let mut name_groups: Vec<(u64, Vec<(PathBuf, u64)>)> = nmap
        .into_values()
        .filter(|v| v.len() >= 2)
        .map(|v| {
            let sum: u64 = v.iter().map(|(_, s)| s).sum();
            (sum, v)
        })
        .collect();
    name_groups.sort_by_key(|(sum, _)| std::cmp::Reverse(*sum));
    progress(sink, 95);
    // ---------- 输出 ----------
    let mut gid = 0usize;
    for (sz, v) in &content_groups {
        gid += 1;
        emit_dup_group(
            sink,
            &v.iter().map(|p| (p.clone(), *sz)).collect::<Vec<_>>(),
            &format!("dupc{:04}", gid),
            "content",
            None,
        );
    }
    for (sim, v) in &similar_groups {
        gid += 1;
        emit_dup_group(sink, v, &format!("dups{:04}", gid), "similar", Some(*sim));
    }
    for (_, v) in &name_groups {
        gid += 1;
        emit_dup_group(sink, v, &format!("dupn{:04}", gid), "name", None);
    }
    for e in empty {
        item(sink, "emptyfile", &e, 0, &[]);
    }
    progress(sink, 100);
}

fn emit_dup_group(sink: &dyn Sink, v: &[(PathBuf, u64)], gid: &str, match_kind: &str, sim: Option<u64>) {
    for (idx, (p, sz)) in v.iter().enumerate() {
        let mut extra: Vec<(&str, String)> = vec![
            ("group", gid.to_string()),
            ("role", if idx == 0 { "kept".to_string() } else { "candidate".to_string() }),
            ("match", match_kind.to_string()),
        ];
        if let Some(s) = sim {
            extra.push(("sim", format!("{}%", s)));
        }
        item(sink, "duplicate", p, *sz, &extra);
    }
}

// ==================== 文档内容相似检测 ====================
const SIM_EXTS: [&str; 5] = ["txt", "md", "log", "csv", "docx"];
const SIM_MIN_BYTES: u64 = 256; // 过短文本 shingle 太少，不参与相似判定
const SIM_MAX_BYTES: u64 = 4 * 1024 * 1024;
const SIM_MIN_SHINGLES: usize = 24;
const SIM_THRESHOLD: f64 = 0.8;
const SIM_MAX_DOCS: usize = 2000; // 单扩展名参与上限，防极端目录拖垮扫描
const SIM_MAX_PAIRS: usize = 400_000; // 单扩展名两两比较上限

fn dsu_find(parent: &mut [usize], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
}

/// 归一化：小写、丢弃非字母数字、空白折叠为单空格。
fn normalize_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if ch.is_alphanumeric() {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            for lc in ch.to_lowercase() {
                out.push(lc);
            }
        } else {
            pending_space = false;
        }
    }
    out
}

/// 16 字符窗口 shingle + FNV-1a 哈希，1/3 采样降内存；返回排序去重的指纹集。
fn shingle_set(norm: &str) -> Option<Vec<u64>> {
    const W: usize = 16;
    const STRIDE: usize = 3;
    let chars: Vec<char> = norm.chars().collect();
    if chars.len() < W * 6 {
        return None;
    }
    let mut raw: Vec<u64> = Vec::with_capacity(chars.len() / STRIDE + 1);
    let mut i = 0usize;
    while i + W <= chars.len() {
        let mut h: u64 = 0xcbf29ce484222325;
        for ch in &chars[i..i + W] {
            let c = *ch as u32;
            h = (h ^ (c as u64)).wrapping_mul(0x100000001b3);
            h = (h ^ ((c >> 16) as u64)).wrapping_mul(0x100000001b3);
        }
        raw.push(h);
        i += STRIDE;
    }
    raw.sort_unstable();
    raw.dedup();
    if raw.len() < SIM_MIN_SHINGLES {
        return None;
    }
    Some(raw)
}

fn jaccard(a: &[u64], b: &[u64]) -> f64 {
    let (mut i, mut j) = (0usize, 0usize);
    let mut inter = 0usize;
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                inter += 1;
                i += 1;
                j += 1;
            }
        }
    }
    let uni = a.len() + b.len() - inter;
    if uni == 0 {
        0.0
    } else {
        inter as f64 / uni as f64
    }
}

fn doc_sketch(path: &Path) -> Option<Vec<u64>> {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let text = if ext == "docx" {
        extract_docx_text(path)?
    } else {
        let raw = fs::read(path).ok()?;
        String::from_utf8_lossy(&raw).into_owned()
    };
    shingle_set(&normalize_text(&text))
}

/// 文档相似检测：Jaccard ≥ 阈值的文档经并查集聚类；返回 (簇内最低相似度%, 成员)。
fn find_similar_doc_groups(
    files: &[(PathBuf, u64)],
    taken: &HashSet<PathBuf>,
    sink: &dyn Sink,
) -> Vec<(u64, Vec<(PathBuf, u64)>)> {
    let mut buckets: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, (p, sz)) in files.iter().enumerate() {
        if *sz < SIM_MIN_BYTES || *sz > SIM_MAX_BYTES || taken.contains(p) {
            continue;
        }
        let ext = p
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if SIM_EXTS.contains(&ext.as_str()) {
            buckets.entry(ext).or_default().push(i);
        }
    }
    let mut out: Vec<(u64, Vec<(PathBuf, u64)>)> = Vec::new();
    for (ext, mut idxs) in buckets {
        if idxs.len() > SIM_MAX_DOCS {
            sink.warn(&format!(
                ".{} 文档 {} 个超出相似检测上限，仅分析前 {} 个",
                ext,
                idxs.len(),
                SIM_MAX_DOCS
            ));
            idxs.truncate(SIM_MAX_DOCS);
        }
        let sketches: Vec<Option<Vec<u64>>> =
            idxs.par_iter().map(|i| doc_sketch(&files[*i].0)).collect();
        // (sketches 下标, 指纹长度)，按长度升序便于窗口剪枝：Jaccard ≤ 短集/长集
        let mut docs: Vec<(usize, usize)> = sketches
            .iter()
            .enumerate()
            .filter(|(_, s)| s.as_ref().map(|v| v.len()).unwrap_or(0) >= SIM_MIN_SHINGLES)
            .map(|(k, s)| (k, s.as_ref().map(|v| v.len()).unwrap_or(0)))
            .collect();
        docs.sort_by_key(|(_, l)| *l);
        let n = docs.len();
        if n < 2 {
            continue;
        }
        let mut parent: Vec<usize> = (0..n).collect();
        let mut min_edge: Vec<u64> = vec![100u64; n];
        let mut pairs = 0usize;
        let mut capped = false;
        for i in 0..n {
            let (ki, li) = docs[i];
            let si = sketches[ki].as_ref().unwrap();
            for j in i + 1..n {
                let (kj, lj) = docs[j];
                if (lj as f64) * SIM_THRESHOLD > li as f64 {
                    break; // 长度差过大，不可能达到阈值
                }
                pairs += 1;
                if pairs > SIM_MAX_PAIRS {
                    capped = true;
                    break;
                }
                let jac = jaccard(si, sketches[kj].as_ref().unwrap());
                if jac >= SIM_THRESHOLD {
                    let pct = (jac * 100.0).round().min(100.0) as u64;
                    let ri = dsu_find(&mut parent, i);
                    let rj = dsu_find(&mut parent, j);
                    if ri != rj {
                        parent[rj] = ri;
                        min_edge[ri] = min_edge[ri].min(min_edge[rj]).min(pct);
                    }
                }
            }
            if capped {
                sink.warn(&format!(".{} 相似比较次数达上限，部分文档未参与聚类", ext));
                break;
            }
        }
        let mut clusters: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..n {
            let r = dsu_find(&mut parent, i);
            clusters.entry(r).or_default().push(i);
        }
        let mut groups: Vec<(u64, Vec<(PathBuf, u64)>)> = clusters
            .into_values()
            .filter(|m| m.len() >= 2)
            .map(|m| {
                let root = dsu_find(&mut parent, m[0]);
                let sim = min_edge[root];
                let members: Vec<(PathBuf, u64)> = m
                    .iter()
                    .map(|k| {
                        let fi = idxs[docs[*k].0];
                        (files[fi].0.clone(), files[fi].1)
                    })
                    .collect();
                (sim, members)
            })
            .collect();
        groups.sort_by_key(|(_, v)| {
            let max: u64 = v.iter().map(|(_, s)| *s).max().unwrap_or(0);
            std::cmp::Reverse(max)
        });
        out.extend(groups);
    }
    out
}

// ==================== docx 正文抽取 ====================
/// 解压 docx（zip 容器）中的 word/document.xml 并转纯文本。
fn extract_docx_text(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    if data.len() > (SIM_MAX_BYTES as usize) * 2 {
        return None;
    }
    let xml = zip_read_entry(&data, b"word/document.xml")?;
    Some(xml_to_text(&xml))
}

/// 在 zip 字节流中按中央目录查找并解压单个条目（支持 stored 与 raw deflate）。
fn zip_read_entry(data: &[u8], want: &[u8]) -> Option<Vec<u8>> {
    const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const CDH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
    if data.len() < 22 {
        return None;
    }
    // 从尾部找 EOCD（zip 注释最长 65535 字节）
    let scan_start = data.len().saturating_sub(22 + 65535);
    let mut eocd = None;
    let mut i = data.len() - 22;
    loop {
        if data[i..i + 4] == EOCD_SIG {
            eocd = Some(i);
            break;
        }
        if i == scan_start {
            break;
        }
        i -= 1;
    }
    let eocd = eocd?;
    let entries = u16::from_le_bytes([data[eocd + 10], data[eocd + 11]]) as usize;
    let cd_off = u32::from_le_bytes([
        data[eocd + 16],
        data[eocd + 17],
        data[eocd + 18],
        data[eocd + 19],
    ]) as usize;
    let mut p = cd_off;
    for _ in 0..entries {
        if p + 46 > data.len() || data[p..p + 4] != CDH_SIG {
            return None;
        }
        let method = u16::from_le_bytes([data[p + 10], data[p + 11]]);
        let csize =
            u32::from_le_bytes([data[p + 20], data[p + 21], data[p + 22], data[p + 23]]) as usize;
        let name_len = u16::from_le_bytes([data[p + 28], data[p + 29]]) as usize;
        let extra_len = u16::from_le_bytes([data[p + 30], data[p + 31]]) as usize;
        let comment_len = u16::from_le_bytes([data[p + 32], data[p + 33]]) as usize;
        let lfh_off = u32::from_le_bytes([
            data[p + 42],
            data[p + 43],
            data[p + 44],
            data[p + 45],
        ]) as usize;
        let name = &data[p + 46..p + 46 + name_len];
        p += 46 + name_len + extra_len + comment_len;
        if name.eq_ignore_ascii_case(want) {
            if lfh_off + 30 > data.len() || data[lfh_off..lfh_off + 4] != LFH_SIG {
                return None;
            }
            let l_name = u16::from_le_bytes([data[lfh_off + 26], data[lfh_off + 27]]) as usize;
            let l_extra = u16::from_le_bytes([data[lfh_off + 28], data[lfh_off + 29]]) as usize;
            let start = lfh_off + 30 + l_name + l_extra;
            let comp = data.get(start..start + csize)?;
            return match method {
                0 => Some(comp.to_vec()),
                8 => miniz_oxide::inflate::decompress_to_vec(comp).ok(),
                _ => None,
            };
        }
    }
    None
}

/// document.xml 转纯文本：段落尾换行、去标签、解常见实体。
fn xml_to_text(xml: &[u8]) -> String {
    let s = String::from_utf8_lossy(xml);
    let mut out = String::with_capacity(s.len() / 2);
    let mut in_tag = false;
    let mut tag = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '<' => {
                in_tag = true;
                tag.clear();
            }
            '>' => {
                if tag.starts_with("/w:p") || tag.starts_with("/w:br") || tag == "w:br" {
                    out.push('\n');
                } else if tag.starts_with("w:tab") {
                    out.push(' ');
                }
                in_tag = false;
            }
            _ => {
                if in_tag {
                    tag.push(c);
                } else if c == '&' {
                    let mut ent = String::new();
                    for e in chars.by_ref() {
                        if e == ';' {
                            break;
                        }
                        ent.push(e);
                        if ent.len() > 10 {
                            break;
                        }
                    }
                    match ent.as_str() {
                        "amp" => out.push('&'),
                        "lt" => out.push('<'),
                        "gt" => out.push('>'),
                        "quot" => out.push('"'),
                        "apos" => out.push('\''),
                        _ => {
                            let cp = ent.strip_prefix('#').and_then(|num| {
                                num.strip_prefix('x')
                                    .or_else(|| num.strip_prefix('X'))
                                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                                    .or_else(|| num.parse::<u32>().ok())
                            });
                            if let Some(ch) = cp.and_then(char::from_u32) {
                                out.push(ch);
                            }
                        }
                    }
                } else {
                    out.push(c);
                }
            }
        }
    }
    out
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
fn topk_in(dir: &Path, recursive: bool, cap: usize, counter: &AtomicU64, sink: &dyn Sink) -> TopHeap {
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
                // P0：DirEntry 自带大小，不额外 syscall
                if let Ok(md) = ent.metadata() {
                    let sz = md.len();
                    push_topk(&mut heap, sz, ent.path(), cap);
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
pub fn bigfiles(roots: &[String], count: usize, sink: &dyn Sink) {
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
        .map(|(d, rec)| topk_in(d, *rec, cap, &counter, sink))
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

/// 空目录用户级忽略名单：%APPDATA%\Trim\empty-ignore.txt，每行一个绝对路径，大小写不敏感。
/// 对标 HiBit Empty Folder Cleaner 的「Ignore this Folder」持久化忽略（P1-4）。
fn empty_ignore_file() -> Option<PathBuf> {
    std::env::var("APPDATA")
        .ok()
        .map(|a| PathBuf::from(a).join("Trim").join("empty-ignore.txt"))
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

/// 并行空目录/空文件扫描（性能升级 P1-4）：
///   · 根下的一级子目录交给 rayon 各自串行递归（根只作容器，避免误删根）
///   · `ent.metadata()` 取大小，不额外 syscall
///   · 用户忽略名单 empty-ignore.txt 生效，视为非空且不下钻
///   · 输出 emptyfolder 附带 nested=「删它可连带删掉的子空目录数」，供前端提示
pub fn empty(roots: &[String], sink: &dyn Sink) {
    init_scan_threads();
    let ignore = load_empty_ignore();
    let empty_files: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    let empty_dirs: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    for r in roots {
        let Some(p) = canonical(r) else { continue };
        // 根自身只作容器：一级子目录交并行，过滤忽略名单
        let mut tops: Vec<PathBuf> = Vec::new();
        let mut root_files: Vec<PathBuf> = Vec::new();
        if let Ok(rd) = fs::read_dir(&p) {
            for ent in rd.flatten() {
                match ent.file_type() {
                    Ok(t) if t.is_dir() => {
                        if !is_reparse(&ent) && !empty_ignored(&ignore, &ent.path()) {
                            tops.push(ent.path());
                        }
                    }
                    Ok(t) if t.is_file() => {
                        // FD-6（2026-09-15）：根第一层的 0 字节文件此前被忽略（tops 只收子目录），
                        // 与 duplicates 链路「根层文件也参与」的口径不一致。补上根层空文件。
                        let sz = ent.metadata().map(|m| m.len()).unwrap_or(1);
                        if sz == 0 {
                            root_files.push(ent.path());
                        }
                    }
                    _ => {}
                }
            }
        }
        if !root_files.is_empty() {
            // 锁中毒不 panic：rayon 里一个线程炸掉会把别的线程一起带崩（结果本该部分可用）。
            // 口径与 src-tauri 侧 62 处一致 —— 一律 unwrap_or_else(into_inner)。
            empty_files
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(root_files);
        }
        tops.par_iter().for_each(|d| {
            let mut f: Vec<PathBuf> = Vec::new();
            let mut dd: Vec<PathBuf> = Vec::new();
            let _ = collect_empty_fast(d, &ignore, &mut f, &mut dd);
            if !f.is_empty() {
                empty_files
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .extend(f);
            }
            if !dd.is_empty() {
                empty_dirs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .extend(dd);
            }
        });
    }

    let files = empty_files.into_inner().unwrap_or_else(|e| e.into_inner());
    let dirs = empty_dirs.into_inner().unwrap_or_else(|e| e.into_inner());

    // 父目录折叠：若某空目录的父目录同为待删空目录，只保留父（删父连带删内层，Czkawka 思路）
    let set: HashSet<PathBuf> = dirs.iter().cloned().collect();
    let mut out: Vec<(PathBuf, usize)> = Vec::new();
    for d in &dirs {
        if d.parent().map(|pp| set.contains(pp)).unwrap_or(false) {
            continue; // 存在空父目录，跳过自己
        }
        let nested = dirs.iter().filter(|x| *x != d && x.starts_with(d)).count();
        out.push((d.clone(), nested));
    }
    for f in &files {
        item(sink, "emptyfile", f, 0, &[]);
    }
    for (d, n) in &out {
        item(sink, "emptyfolder", d, 0, &[("nested", n.to_string())]);
    }
    progress(sink, 100);
}

/// 返回该目录是否整体为空（可删除）。与旧 collect_empty 同语义，区别：
/// 用 `ent.metadata()` 取大小；命中忽略名单的目录视为非空且不再下钻。
fn collect_empty_fast(
    dir: &Path,
    ignore: &HashSet<String>,
    files: &mut Vec<PathBuf>,
    dirs: &mut Vec<PathBuf>,
) -> bool {
    if empty_ignored(ignore, dir) {
        return false;
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return false, // 不可读目录保守视为非空
    };
    let mut empty = true;
    for ent in rd.flatten() {
        let fp = ent.path();
        match ent.file_type() {
            Ok(t) if t.is_symlink() => {
                empty = false;
            }
            Ok(t) if t.is_dir() => {
                if is_reparse(&ent) {
                    empty = false;
                } else if !collect_empty_fast(&fp, ignore, files, dirs) {
                    empty = false;
                }
            }
            Ok(t) if t.is_file() => {
                // P0：DirEntry 自带大小，不额外 syscall
                let sz = ent.metadata().map(|m| m.len()).unwrap_or(1);
                if sz == 0 {
                    files.push(fp); // 空文件单独作为删除候选
                }
                empty = false; // 任何文件（含空文件）都使其父目录不算空文件夹
            }
            _ => {
                empty = false;
            }
        }
    }
    if empty {
        dirs.push(dir.to_path_buf());
    }
    empty
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
#[cfg(windows)]
/// 手写 SHFileOperationW（只进回收站）。`pub` 供 Tauri 侧清理执行链复用
/// （cleanup:execute 的 toRecycle 分支 / D 批删除链）——三端同源的回收站语义，避免各写一份。
pub mod recycle {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const FO_DELETE: u32 = 3;
    const FOF_SILENT: u16 = 0x0004;
    const FOF_NOCONFIRMATION: u16 = 0x0010;
    const FOF_ALLOWUNDO: u16 = 0x0040;
    const FOF_NOERRORUI: u16 = 0x0400;

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

    /// 将单个路径移入回收站。pFrom 要求双 NUL 结尾。
    pub fn send_to_trash(path: &str) -> Result<(), String> {
        let mut from: Vec<u16> = OsStr::new(path).encode_wide().collect();
        from.push(0);
        from.push(0);
        let mut op = ShFileOpStructW {
            hwnd: 0,
            w_func: FO_DELETE,
            p_from: from.as_ptr(),
            p_to: std::ptr::null(),
            f_flags: FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI,
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
    sink.item(&s);
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
    if prefix.is_empty() {
        comps.join("\\").to_lowercase()
    } else {
        format!(r"{}\{}", prefix, comps.join("\\")).to_lowercase()
    }
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
    recycle::send_to_trash(&p.to_string_lossy()).map_err(|reason| format!("回收站失败: {}", reason))
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
    // 冻结的 Sink 只有 item/progress/scanned/warn 四个方法，无法承载该前缀；
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