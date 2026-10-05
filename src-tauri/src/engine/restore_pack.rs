//! 卸载域自包含还原包（HiBit §H1 借鉴项，2026-09-29）
//!
//! 与 `delete_manifest` 的分工要说清：那份是**清单**（哪些路径被移进了回收站，事后无从取回
//! 内容），这份是**还原包**（内容本体在 `payload.zip` 里，能还原）。缺的是后者——HiBit 本机
//! 实物就是 `BackupFiles.zip + FileList.txt + Registry.ini` 三件套，这次第一次拿到格式。
//!
//! 三件套落 `<数据目录>/uninstall-restore-pack/<batch_id>/`：
//! - `payload.zip`　被移走的内容本体（deflate）
//! - `manifest.tsv`　`<zip键>\t<类型>\t<字节>\t<sha256>\t<原路径>`，zip 条目↔原位置的映射
//! - `registry/`　本批 `reg export` 产出的 .reg 副本（**还原仍走 `uninstall_reg_backup_restore`**，
//!   那里有四道闸：文件名准入 → 严格解析 → 从正文重取键路径复算禁删面 → 封条校验。
//!   复制到这里只为「一批一个去处」的可解释性，绝不再开第二条写注册表的通道）
//!
//! 三条与 HiBit 不同的刻意选择：
//! 1. **zip 条目名用「原路径 sha256 前 16 位」而不是 GUID**。它要解决的是同一件事
//!    （条目名不带中文、不受长度限制），但哈希可由路径重算，`list`/`restore` 两侧都能自检。
//! 2. **manifest 带 sha256**。HiBit 没有这一层，文件被移走后若又被别人改过它无从发现；
//!    还原时哈希不符一律**报错并停下**，不静默跳过——静默跳过会让用户以为还原成功了。
//! 3. **刻意不还原 mtime**：多一套 `SetFileTime` FFI 只服务观感，而还原的正确判据是内容哈希。
//!
//! 备份是**用户可选**的（默认关，2026-09-29 裁定）：整目录几百 MB 时静默打包既慢又占盘，
//! 而 HiBit 那份 104 MB 的备份 zip 长留 AppData 正是反面样本。所以这里同时有体积上限与
//! 批次保留数，且超限是「拒绝备份 ⇒ 该目标不删」，不是「备份一半继续删」。

use std::io::{Read, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::engine::{log, paths, protect};

/// 还原包目录名（备份类目录，写入恒走 `paths::backup_write_dir`，读取带老根兜底）
const SUB: &str = "uninstall-restore-pack";
const ZIP_NAME: &str = "payload.zip";
const MANIFEST_NAME: &str = "manifest.tsv";
const REG_DIR: &str = "registry";

/// 单批内容上限：超限拒绝备份（对齐「备份失败即不删」的 fail-closed 口径）
const MAX_BATCH_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// 单文件上限：单个超大文件不该整批失败，但也不许无界吃盘
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// 只保留最近 N 批（文件名 = batch_id，字典序即时序，与 delete_manifest 同一姿势）
const KEEP_BATCHES: usize = 20;
/// 复制进 registry/ 的 .reg 数量上限（正常一批远不到这个数，钉的是「异常清单不炸盘」）
const MAX_REG_FILES: usize = 200;
/// FILE_ATTRIBUTE_REPARSE_POINT：reparse/junction 一律拒绝备份与还原，不跟着穿到目录外
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// 一条内容映射。`kind` 只有 `file` 与 `dir` 两种（注册表不在这里，见模块头）。
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub zip_key: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
    pub orig_path: String,
}

/// zip 条目名：原路径（大写归一 + 反斜杠统一）的 sha256 前 16 位。
/// 同一目录在不同机器/不同大小写下必须得到同一个键，否则 list 与 restore 对不上。
pub fn zip_key_of(path: &str) -> String {
    let norm = path.replace('/', "\\").to_uppercase();
    let hex = hex_digest(&Sha256::digest(norm.as_bytes()));
    hex[..16].to_string()
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_root() -> PathBuf {
    paths::backup_write_dir(SUB)
}

/// 一个正在写入的还原包。`add` 失败 ⇒ 调用方**不得删除该目标**。
pub struct Pack {
    dir: PathBuf,
    batch_id: String,
    zip: ZipWriter<std::fs::File>,
    entries: Vec<Entry>,
    total: u64,
    reg_copied: usize,
}

impl Pack {
    pub fn begin(batch_id: &str) -> Result<Pack, String> {
        let dir = write_root().join(batch_id);
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建还原包目录失败: {e}"))?;
        let file = std::fs::File::create(dir.join(ZIP_NAME))
            .map_err(|e| format!("创建 payload.zip 失败: {e}"))?;
        Ok(Pack {
            dir,
            batch_id: batch_id.to_string(),
            zip: ZipWriter::new(file),
            entries: Vec::new(),
            total: 0,
            reg_copied: 0,
        })
    }

    /// 把一个文件读进 zip 并返回其映射条目（单趟：边读边算 sha256 边写，不整文件进内存）
    fn add_file(&mut self, src: &Path, orig_path: &str, size: u64) -> Result<Entry, String> {
        if size > MAX_FILE_BYTES {
            return Err(format!("单个文件超过 {MAX_FILE_BYTES} 字节上限，未备份"));
        }
        if self.total + size > MAX_BATCH_BYTES {
            return Err(format!("本批内容超过 {MAX_BATCH_BYTES} 字节上限，未备份"));
        }
        let key = zip_key_of(orig_path);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        self.zip
            .start_file(&key, opts)
            .map_err(|e| format!("写入 zip 条目失败: {e}"))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut written = 0u64;
        let mut f = std::fs::File::open(src).map_err(|e| format!("打开源文件失败: {e}"))?;
        loop {
            let n = f.read(&mut buf).map_err(|e| format!("读取源文件失败: {e}"))?;
            if n == 0 {
                break;
            }
            written += n as u64;
            // 声明尺寸与实际读到的不一致（竞态/稀疏文件）⇒ 报错而不是写个半截条目进包
            if written > MAX_FILE_BYTES {
                return Err("实际读取超过单文件上限，未备份".to_string());
            }
            hasher.update(&buf[..n]);
            self.zip
                .write_all(&buf[..n])
                .map_err(|e| format!("写入 zip 内容失败: {e}"))?;
        }
        self.total += written;
        Ok(Entry {
            zip_key: key,
            kind: "file".into(),
            size: written,
            sha256: hex_digest(&hasher.finalize()),
            orig_path: orig_path.to_string(),
        })
    }

    /// 备份一个删除目标：文件直接入包；目录先落一条 dir 记录再递归入包内文件。
    /// 任一步失败即 `Err` —— 调用方据此**不删该目标**，与注册表「备份失败不删」同口径。
    pub fn add_target(&mut self, path: &Path) -> Result<usize, String> {
        let meta = std::fs::symlink_metadata(path).map_err(|e| format!("读取目标信息失败: {e}"))?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("目标是 reparse point/联接，为避免写到目录外，未备份".to_string());
        }
        let orig = path.to_string_lossy().to_string();
        if !meta.is_dir() {
            let size = meta.len();
            let e = self.add_file(path, &orig, size)?;
            self.entries.push(e);
            return Ok(1);
        }
        // 目录本体记一条 zip 键为 `-` 的占位条目：还原时据此重建空目录
        self.entries.push(Entry {
            zip_key: "-".into(),
            kind: "dir".into(),
            size: 0,
            sha256: String::new(),
            orig_path: orig.clone(),
        });
        let mut added = 1usize;
        let mut stack = vec![path.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let rd = std::fs::read_dir(&dir).map_err(|e| format!("枚举目录失败: {e}"))?;
            for de in rd.flatten() {
                let child = de.path();
                let cm = child
                    .symlink_metadata()
                    .map_err(|e| format!("读取子项信息失败: {e}"))?;
                if cm.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(format!("目录内含 reparse point，未备份：{}", child.display()));
                }
                let cstr = child.to_string_lossy().to_string();
                if cm.is_dir() {
                    self.entries.push(Entry {
                        zip_key: "-".into(),
                        kind: "dir".into(),
                        size: 0,
                        sha256: String::new(),
                        orig_path: cstr,
                    });
                    added += 1;
                    stack.push(child);
                } else {
                    let e = self.add_file(&child, &cstr, cm.len())?;
                    self.entries.push(e);
                    added += 1;
                }
            }
        }
        Ok(added)
    }

    /// 把本批已写好的 .reg 备份复制进 `registry/`（副本，不是还原入口）
    pub fn include_reg_backup(&mut self, file: &Path) -> Result<(), String> {
        if self.reg_copied >= MAX_REG_FILES {
            return Err(format!("本批 .reg 副本超过 {MAX_REG_FILES} 份上限"));
        }
        let dir = self.dir.join(REG_DIR);
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建 registry 目录失败: {e}"))?;
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ".reg 文件名无法表示".to_string())?;
        std::fs::copy(file, dir.join(name)).map_err(|e| format!("复制 .reg 副本失败: {e}"))?;
        self.reg_copied += 1;
        Ok(())
    }

    /// 收尾：落 manifest.tsv 并把目录裁到最近 KEEP_BATCHES 批。
    /// manifest 是还原的唯一依据，写失败必须让调用方知道（内容已在 zip 里，但没了映射）。
    pub fn finish(self) -> Result<Value, String> {
        let Pack { dir, batch_id, zip, entries, total, reg_copied } = self;
        zip.finish().map_err(|e| format!("收尾 payload.zip 失败: {e}"))?;
        let body = render_manifest(&entries);
        // 审查 L-6/L-7b：manifest 是还原的唯一依据。原为手写 tmp+rename（无 fsync，
        // 断电可留半截），收敛到 security::atomic_write_file 单一出口（temp→fsync→rename，
        // 失败自动清临时件），与 reg_backup / cleanup 备份清单同口径。
        crate::security::atomic_write_file(&dir.join(MANIFEST_NAME), body.as_bytes())
            .map_err(|e| format!("写 manifest 失败: {e}"))?;
        prune(&write_root());
        Ok(json!({
            "id": batch_id,
            "dir": dir.to_string_lossy(),
            // 字段名与 `list()` 保持一致（files/dirs），否则界面上同一个概念会有两个键
            "files": entries.iter().filter(|e| e.kind == "file").count(),
            "dirs": entries.iter().filter(|e| e.kind == "dir").count(),
            "bytes": total,
            "regCopies": reg_copied,
        }))
    }
}

/// manifest 正文：每行 `<zip键>\t<类型>\t<字节>\t<sha256>\t<原路径>`。
/// 路径放最后一列且解析时只切四刀，这样路径里万一出现制表符也不会被截断成两个字段。
fn render_manifest(entries: &[Entry]) -> String {
    let mut s = String::from("trim-restore-pack\t1\n");
    for e in entries {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            e.zip_key, e.kind, e.size, e.sha256, e.orig_path
        ));
    }
    s
}

/// 解析 manifest。表头版本不认识 ⇒ 整包拒绝（宁可不还原，也不按猜的字段还原）。
pub fn parse_manifest(text: &str) -> Result<Vec<Entry>, String> {
    let mut lines = text.lines();
    match lines.next() {
        Some(h) if h.starts_with("trim-restore-pack\t1") => {}
        Some(other) => return Err(format!("manifest 表头无法识别: {other}")),
        None => return Err("manifest 为空".to_string()),
    }
    let mut out = Vec::new();
    for (i, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(5, '\t').collect();
        if parts.len() != 5 {
            return Err(format!("manifest 第 {} 行字段数异常", i + 2));
        }
        let size = parts[2]
            .parse::<u64>()
            .map_err(|_| format!("manifest 第 {} 行字节数非法", i + 2))?;
        out.push(Entry {
            zip_key: parts[0].to_string(),
            kind: parts[1].to_string(),
            size,
            sha256: parts[3].to_string(),
            orig_path: parts[4].to_string(),
        });
    }
    if out.is_empty() {
        return Err("manifest 没有任何条目".to_string());
    }
    Ok(out)
}

/// 条目路径准入。还原是**往磁盘写任意内容**，判据刻意比删除侧更严：
/// 绝对路径 + 不含 `..` + 不落盘根 + 不在 `is_path_protected` 面内 + **不在 %WINDIR% 整棵内**
/// + 父目录不是 reparse point。
///
/// 为什么不共用 `is_path_protected` 就够了：那份清单服务的是「清理别误删系统」，实测其
/// subtree 只有 `%WINDIR%\System32\config` 一棵（protect.rs:286），`System32\drivers` 这类
/// 并不在册。删除侧不碰它靠的是「规则库根本不会产出那种目标」，而还原侧的路径来自磁盘上
/// 一份可被改写的 manifest，不能拿「没人会那么写」当防线。
///
/// 返回 `None` = 放行；`Some(原因)` = 拒绝该条（逐项拒，不整批失败——一坏行不该夺走其余可还原项）。
pub fn restore_path_verdict(path: &str) -> Option<String> {
    if path.is_empty() {
        return Some("路径为空".into());
    }
    let p = Path::new(path);
    if !p.is_absolute() {
        return Some("路径不是绝对路径".into());
    }
    // 盘根（`C:\`）只有一个 component：还原不该有「整盘」这种目标
    if p.components().count() < 2 {
        return Some("盘根目录不可作为还原目标".into());
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Some("路径含 ..".into());
    }
    if protect::is_path_protected(path) {
        return Some("受保护路径".into());
    }
    // %WINDIR% 整棵补上：这是删除侧清单覆盖不到、但还原写进去就是改系统的那部分
    let windir = std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| r"C:\Windows".to_string());
    let low = path.replace('/', "\\").to_lowercase();
    let wlow = windir.replace('/', "\\").to_lowercase();
    if low == wlow || low.starts_with(&format!("{wlow}\\")) {
        return Some("位于系统目录（%WINDIR%）内，还原不提供写入系统目录的入口".into());
    }
    // 父目录是 reparse point 时，写进去会落到链接指向的另一处，等于绕过上面的路径判定
    if let Some(parent) = p.parent() {
        if let Ok(md) = parent.symlink_metadata() {
            if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Some("父目录是 reparse point，写入会落到链接目标外".into());
            }
        }
    }
    None
}

/// 列出本机还原包（按 batch_id 倒序，最多 limit 个）。老根只读兜底。
pub fn list(limit: usize) -> Vec<Value> {
    let mut rows: Vec<Value> = Vec::new();
    for root in paths::backup_read_dirs(SUB) {
        let Ok(rd) = std::fs::read_dir(&root) else { continue };
        for de in rd.flatten() {
            let name = de.file_name().to_string_lossy().to_string();
            if !de.path().is_dir() || name.starts_with('.') {
                continue;
            }
            let manifest = de.path().join(MANIFEST_NAME);
            let Ok(text) = std::fs::read_to_string(&manifest) else { continue };
            let entries = match parse_manifest(&text) {
                Ok(e) => e,
                Err(msg) => {
                    rows.push(json!({ "id": name, "broken": msg }));
                    continue;
                }
            };
            let bytes: u64 = entries.iter().map(|e| e.size).sum();
            rows.push(json!({
                "id": name,
                "dir": de.path().to_string_lossy(),
                "files": entries.iter().filter(|e| e.kind == "file").count(),
                "dirs": entries.iter().filter(|e| e.kind == "dir").count(),
                "bytes": bytes,
                "hasZip": de.path().join(ZIP_NAME).is_file(),
            }));
        }
    }
    rows.sort_by(|a, b| b["id"].as_str().unwrap_or("").cmp(a["id"].as_str().unwrap_or("")));
    rows.truncate(limit);
    rows
}

/// 还原一个批次。逐条自检：zip 里有没有、哈希对不对、路径准不准、目标是否已存在。
/// 任何一条不成立都记成失败原因，不静默跳过；返回体带 ok/failed/conflict/skipped 四档。
pub fn restore(batch_id: &str) -> Result<Value, String> {
    // batch_id 来自渲染层，先当「不可信文件名」处理：只允许既有生成器产出的形状
    if batch_id.is_empty()
        || batch_id.len() > 120
        || batch_id.contains("..")
        || batch_id.contains('/')
        || batch_id.contains('\\')
    {
        return Err("批次号格式不合法".to_string());
    }
    let root = paths::backup_read_dirs(SUB)
        .into_iter()
        .find(|d| d.join(batch_id).join(MANIFEST_NAME).is_file())
        .ok_or_else(|| "找不到该还原包（可能已被保留策略清掉）".to_string())?;
    let dir = root.join(batch_id);
    let text = std::fs::read_to_string(dir.join(MANIFEST_NAME))
        .map_err(|e| format!("读取 manifest 失败: {e}"))?;
    let entries = parse_manifest(&text)?;

    let zip_file = std::fs::File::open(dir.join(ZIP_NAME))
        .map_err(|e| format!("打开 payload.zip 失败: {e}"))?;
    let mut archive = ZipArchive::new(zip_file).map_err(|e| format!("payload.zip 打不开: {e}"))?;

    let mut ok = 0usize;
    let mut conflicts = 0usize;
    let mut failed: Vec<Value> = Vec::new();
    // 先目录后文件：文件写进还没建的目录里必然失败，顺序错了会把整批判成失败
    for pass in ["dir", "file"] {
        for e in entries.iter().filter(|e| e.kind == pass) {
            if let Some(reason) = restore_path_verdict(&e.orig_path) {
                failed.push(json!({ "path": e.orig_path, "reason": reason }));
                continue;
            }
            let target = Path::new(&e.orig_path);
            if e.kind == "dir" {
                if target.is_dir() {
                    conflicts += 1;
                    continue;
                }
                match std::fs::create_dir_all(target) {
                    Ok(_) => ok += 1,
                    Err(err) => failed.push(json!({ "path": e.orig_path, "reason": format!("建目录失败: {err}") })),
                }
                continue;
            }
            // 目标已存在：内容一致算幂等成功，不一致就是「卸完又装了」——不覆盖，交用户判
            if target.exists() {
                match file_sha256(target) {
                    Some(h) if h == e.sha256 => ok += 1,
                    _ => {
                        conflicts += 1;
                        failed.push(json!({ "path": e.orig_path, "reason": "目标已存在且内容与备份不同，未覆盖" }));
                        continue;
                    }
                }
                continue;
            }
            let mut rf = match archive.by_name(&e.zip_key) {
                Ok(rf) => rf,
                Err(_) => {
                    failed.push(json!({ "path": e.orig_path, "reason": "zip 里缺这个条目（还原包不完整）" }));
                    continue;
                }
            };
            if let Some(parent) = target.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // 先落到目标同目录的临时名，校验哈希后再改名就位：半途失败不留「半个文件」
            let tmp = target.with_extension(format!("trim-restore-{}", std::process::id()));
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 1 << 16];
            let mut wr = match std::fs::File::create(&tmp) {
                Ok(w) => w,
                Err(err) => {
                    failed.push(json!({ "path": e.orig_path, "reason": format!("创建文件失败: {err}") }));
                    continue;
                }
            };
            let mut io_err = None;
            let mut n_total = 0u64;
            loop {
                match rf.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        n_total += n as u64;
                        hasher.update(&buf[..n]);
                        if let Err(err) = wr.write_all(&buf[..n]) {
                            io_err = Some(format!("写入失败: {err}"));
                            break;
                        }
                    }
                    Err(err) => {
                        io_err = Some(format!("解包失败: {err}"));
                        break;
                    }
                }
            }
            drop(wr);
            drop(rf);
            let got = hex_digest(&hasher.finalize());
            let reason = io_err.or_else(|| {
                if got != e.sha256 {
                    Some(format!("哈希不符（备份后内容被人改过）: 期望 {} 实得 {}", e.sha256, got))
                } else if n_total != e.size {
                    Some(format!("字节数不符: 期望 {} 实得 {n_total}", e.size))
                } else {
                    None
                }
            });
            match reason {
                Some(r) => {
                    let _ = std::fs::remove_file(&tmp);
                    failed.push(json!({ "path": e.orig_path, "reason": r }));
                }
                None => match std::fs::rename(&tmp, target) {
                    Ok(_) => ok += 1,
                    Err(err) => {
                        let _ = std::fs::remove_file(&tmp);
                        failed.push(json!({ "path": e.orig_path, "reason": format!("就位失败: {err}") }));
                    }
                },
            }
        }
    }
    log::write_log(
        "info",
        &format!("还原包还原 {batch_id}: 成功 {ok} 冲突/失败 {} 项", failed.len()),
    );
    Ok(json!({
        "id": batch_id,
        "restored": ok,
        "conflicts": conflicts,
        "failed": failed,
    }))
}

fn file_sha256(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex_digest(&hasher.finalize()))
}

/// 只保留最近 KEEP_BATCHES 个批次目录（batch_id 字典序即时序，与 delete_manifest 同口径）。
/// 裁到上限是为了不让还原包变成 HiBit 那种长留 AppData 的 104 MB 包袱。
fn prune(root: &Path) {
    let Ok(rd) = std::fs::read_dir(root) else { return };
    let mut dirs: Vec<String> = rd
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| !n.starts_with('.'))
        .collect();
    dirs.sort();
    while dirs.len() > KEEP_BATCHES {
        let oldest = dirs.remove(0);
        let target = root.join(oldest);
        // 引擎级裁剪出口一律回收站优先（AGENTS §3，与 paths::prune_backups 同口径）：
        // 这是工具自产备份，但「超上限就永久删」会绕过回收站兜底。reparse 先拒，
        // 链接件进回收站等于把它指向的实体卷进来。
        let reparse = std::fs::symlink_metadata(&target)
            .map(|m| crate::engine::protect::is_reparse(&m))
            .unwrap_or(true);
        if !reparse {
            let _ = trim_finder::scan::recycle::send_to_trash_os(target.as_os_str());
        }
    }
}

/// 还原包总占用字节（界面要能看见「这里占了多少盘」，HiBit 那条教训的另一半）
pub fn total_bytes() -> u64 {
    let mut sum = 0u64;
    for root in paths::backup_read_dirs(SUB) {
        let Ok(rd) = std::fs::read_dir(&root) else { continue };
        for de in rd.flatten() {
            if !de.path().is_dir() {
                continue;
            }
            if let Ok(z) = std::fs::metadata(de.path().join(ZIP_NAME)) {
                sum += z.len();
            }
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trip_preserves_entries() {
        let entries = vec![
            Entry {
                zip_key: "abc123".into(),
                kind: "file".into(),
                size: 1234,
                sha256: "ff00".into(),
                orig_path: r"C:\Users\测 试\Program Files\我的 app\a b\t.txt".into(),
            },
            Entry {
                zip_key: "-".into(),
                kind: "dir".into(),
                size: 0,
                sha256: String::new(),
                orig_path: r"C:\x".into(),
            },
        ];
        let back = parse_manifest(&render_manifest(&entries)).expect("应可解析");
        assert_eq!(back, entries, "路径里的空格/中文/多级分隔必须原样往返");
    }

    /// manifest 是还原的唯一依据：表头不认识、字段数不对、字节数非法都必须整包拒绝，
    /// 不能「跳过坏行继续还原」——跳过坏行等于用户以为全恢复了，实际少了一批文件。
    #[test]
    fn manifest_rejects_malformed_lines() {
        assert!(parse_manifest("").is_err(), "空文本必须拒");
        assert!(parse_manifest("other-format\t1\n").is_err(), "表头版本不认识必须拒");
        assert!(parse_manifest("trim-restore-pack\t1\n").is_err(), "零条目必须拒（否则还原报 0 项成功）");
        assert!(
            parse_manifest("trim-restore-pack\t1\nk\tfile\t12\tab").is_err(),
            "字段数不足（少一列路径）必须拒"
        );
        assert!(
            parse_manifest("trim-restore-pack\t1\nk\tfile\t非数字\tab\tC:\\a").is_err(),
            "字节数非法必须拒"
        );
        // 路径里出现制表符不能被切成两个字段：输入与期望都用同一个串，别拿转义口径互相冒充
        let path_with_tab = format!("C:\\a{}b", '\t');
        let ok = parse_manifest(&format!(
            "trim-restore-pack\t1\nk\tfile\t12\tab\t{path_with_tab}"
        ))
        .expect("应可解析");
        assert_eq!(ok[0].orig_path, path_with_tab);
    }

    /// 条目键必须**只由路径决定**：大小写、分隔符写法不影响它，否则 list 与 restore 对不上；
    /// 而不同路径必须不同键，否则两个文件会互相覆盖。
    #[test]
    fn zip_key_is_path_derived_and_distinct() {
        assert_eq!(zip_key_of(r"C:\App\a.txt"), zip_key_of(r"c:\app\A.TXT"));
        assert_eq!(zip_key_of(r"C:\App\a.txt"), zip_key_of(r"C:/App/a.txt"));
        assert_ne!(zip_key_of(r"C:\App\a.txt"), zip_key_of(r"C:\App\b.txt"));
        assert_eq!(zip_key_of(r"C:\App\a.txt").len(), 16, "键长变了会撑爆 manifest 的可读性");
    }

    /// 还原是往磁盘写，准入判据必须与删除侧同源（`protect::is_path_protected`），
    /// 且不接受相对路径与 `..`——否则一个被改过的 manifest 能把文件写到任意位置。
    #[test]
    fn restore_path_verdict_blocks_escape_and_protected() {
        assert!(restore_path_verdict("").is_some(), "空路径必须拒");
        assert!(restore_path_verdict(r"App\a.txt").is_some(), "相对路径必须拒");
        assert!(restore_path_verdict(r"C:\Users\me\AppData\..\..\Windows\a.txt").is_some(), "含 .. 必须拒");
        assert!(restore_path_verdict(r"C:\").is_some(), "盘根必须拒");
        assert!(
            restore_path_verdict(r"C:\Windows\System32\drivers\x.sys").is_some(),
            "%WINDIR% 整棵必须拒——注意这条**不是**靠 is_path_protected 拿到的（它的 subtree 只含 System32\\config）"
        );
        // 断言对象必须是**真的在册**那条：`roots()` 默认 subtree 是 `%APPDATA%\Trim`（老根）
        // 与 `%WINDIR%\System32\config`（protect.rs:286），当前数据目录 `com.xiaoxu.trim`
        // 并不在其中——上一轮我按「应用自身数据目录在册」写断言，跑出来是放行，事实纠正于此。
        let legacy = format!(
            "{}\\Trim\\startup.json",
            std::env::var("APPDATA").unwrap_or_default()
        );
        assert!(
            restore_path_verdict(&legacy).is_some(),
            "is_path_protected 在册的老根必须拒，实得放行: {legacy}"
        );
        assert!(
            restore_path_verdict(&std::env::temp_dir().join("trim-rp-case").join("a.txt").to_string_lossy())
                .is_none(),
            "临时目录下的普通绝对路径应放行"
        );
    }

    /// 批次号来自渲染层，先当不可信文件名：任何路径分隔或 `..` 都必须拒，
    /// 否则 `batch_id` 会变成「选择任意目录作为还原来源」的入口。
    #[test]
    fn restore_rejects_hostile_batch_id() {
        for bad in ["", "..\\..\\x", "a/b", r"a\b", &"x".repeat(200)] {
            let e = restore(bad).unwrap_err();
            assert!(e.contains("格式不合法"), "{bad:?} 的拒绝理由异常: {e}");
        }
        // 合法但不存在的 id：报「找不到」而不是崩
        let miss = restore("2026-01-01T00-00-00-000Z").unwrap_err();
        assert!(miss.contains("找不到"), "理由应为找不到，实得 {miss}");
    }

    /// 真机端到端（发布前门禁跑）：打包 → 删除 → 还原 → 内容哈希与还原前一致，
    /// 并且**故意破坏 zip 条目**后还原必须点名失败，而不是静默少还一个文件。
    ///
    /// 判据写法照 AGENTS §4.1 纪律：断言「还原后逐字节相等」而不是「命令返回成功」——
    /// 后者对「什么都没还原」也成立。探针目录在应用私有 tmp 下，Drop 守卫整目录删除。
    #[test]
    #[ignore = "真写盘（应用私有 tmp 下的探针目录），发布前门禁跑"]
    fn pack_then_restore_restores_bytes_end_to_end() {
        let stamp = crate::engine::now_ms();
        let batch = format!("test-{stamp}");
        // 探针目录**不能**放在应用数据目录下：那条根在 is_path_protected 的 subtree 里，
        // 还原准入会逐条拒掉，用例红在设计而不是红在实现
        let root = std::env::temp_dir().join(format!("trim-rp-{stamp}"));
        struct Guard {
            probe: PathBuf,
            pack: PathBuf,
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.probe);
                // 断言 panic 也要把还原包收掉，否则一次失败的发布前门禁会在用户机器上留一堆假包
                let _ = std::fs::remove_dir_all(&self.pack);
            }
        }
        let _g = Guard { probe: root.clone(), pack: paths::backup_write_dir(SUB).join(&batch) };
        std::fs::create_dir_all(root.join("sub")).expect("建探针目录");
        std::fs::write(root.join("a.txt"), "AAA-中文内容".as_bytes().to_vec()).expect("写 a");
        std::fs::write(root.join("sub").join("b.bin"), vec![7u8; 4096]).expect("写 b");

        let mut pack = Pack::begin(&batch).expect("建包");
        let n = pack.add_target(&root).expect("整目录入包");
        assert!(n >= 3, "目录本体 + 2 个文件至少 3 条，实得 {n}");
        let summary = pack.finish().expect("收尾");
        assert_eq!(summary["files"].as_u64(), Some(2), "文件条目数");
        assert!(summary["dirs"].as_u64().unwrap_or(0) >= 2, "目录条目数（根 + sub）");

        // 删除（这里用 remove_dir_all 模拟回收站之后的结果，重点是还原能不能把字节找回来）
        let want_a = file_sha256(&root.join("a.txt")).expect("还原前哈希");
        let want_b = file_sha256(&root.join("sub").join("b.bin")).expect("还原前哈希");
        std::fs::remove_dir_all(&root).expect("删探针目录");
        assert!(!root.exists(), "前置条件：探针目录必须已消失");

        let out = restore(&batch).expect("还原应执行");
        assert_eq!(out["failed"].as_array().map(|a| a.len()), Some(0), "不得有失败项: {out}");
        assert!(out["restored"].as_u64().unwrap_or(0) >= 3, "还原条数异常: {out}");
        assert_eq!(file_sha256(&root.join("a.txt")).as_deref(), Some(want_a.as_str()), "内容必须逐字节回来");
        assert_eq!(file_sha256(&root.join("sub").join("b.bin")).as_deref(), Some(want_b.as_str()));

        // 破坏**第一条 file 条目的 zip_key**（改路径列没用：键还对得上，还原只是换个名字写成功）
        let dir = paths::backup_write_dir(SUB).join(&batch);
        let mpath = dir.join(MANIFEST_NAME);
        let text = std::fs::read_to_string(&mpath).expect("manifest 应在");
        let lines: Vec<String> = text.lines().map(String::from).collect();
        let mut rewritten: Vec<String> = vec![lines[0].clone()];
        let mut tampered = false;
        for l in &lines[1..] {
            let parts: Vec<&str> = l.splitn(5, '\t').collect();
            if !tampered && parts.len() == 5 && parts[1] == "file" {
                rewritten.push(format!(
                    "0000000000000000\t{}\t{}\t{}\t{}",
                    parts[1], parts[2], parts[3], parts[4]
                ));
                tampered = true;
            } else {
                rewritten.push(l.clone());
            }
        }
        assert!(tampered, "manifest 里必须至少有一条 file 条目可破坏");
        std::fs::write(&mpath, format!("{}\n", rewritten.join("\n"))).expect("改 manifest");
        std::fs::remove_dir_all(&root).expect("再删探针目录");
        let broken = restore(&batch).expect("整批不报错，但失败项要列出来");
        let fails = broken["failed"].as_array().cloned().unwrap_or_default();
        assert!(
            fails.iter().any(|f| f["reason"].as_str().unwrap_or("").contains("zip 里缺")),
            "manifest 指向 zip 里不存在的条目时必须逐项报失败，实得 {broken}"
        );
        // 而且不能因为一条坏行就把其余项一起放弃（逐项拒，不整批失败）
        assert!(
            broken["restored"].as_u64().unwrap_or(0) >= 1,
            "坏条目之外的项仍应还原，实得 {broken}"
        );
    }
}
