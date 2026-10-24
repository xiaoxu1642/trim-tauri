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
//!
//! 两条上限与两道清理是**还原侧也要走一遍**的（v7.2 P1-W2 · R6b-M04/M05）：
//! - manifest 是磁盘上一份可被改写的东西，所以还原按「条目声明字节数」逐块早退，
//!   并沿用同一条 `MAX_BATCH_BYTES` 做整批累计闸 —— 不看上限就会先把盘写满再报「字节数不符」。
//! - `Pack` 实现了 `Drop`：`begin` 之后、`finish` 之前返回 Err 的调用点很多，不清理就会
//!   留下「`list()` 看不见（缺 manifest）、`total_bytes()` 却按 payload.zip 计数」的半成品目录；
//!   但包里**已经有内容**时刻意不删——那可能是已删目标的唯一副本，删它等于删用户的还原依据。

use std::io::{Read, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::engine::{hash, log, paths, protect};

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
///
/// R6b-L01（v7.2 P1-W2）：摘要与 hex 编码**不再自持一份**（此前本文件有私有
/// `hex_digest` + 3 处 `Sha256` 用法，与 `engine::hash` 同判据两套实现，AGENTS §5.16）。
/// 全量摘要走 `hash::sha256_bytes`/`hash::sha256_file`；只有「边读源边写 zip 边算哈希」
/// 的单趟循环保留增量 `Sha256`，但其收尾编码同样走 `hash::to_hex`。
pub fn zip_key_of(path: &str) -> String {
    let norm = path.replace('/', "\\").to_uppercase();
    let hex = hash::sha256_bytes(norm.as_bytes());
    hex[..16].to_string()
}

/// 批次号形态判据的**唯一实现**（R6b-L10）：`begin` 与 `restore` 同一条闸门。
///
/// 此前只有 `restore` 校验（5 项形态判据），`begin` 拿到什么串就 `create_dir_all` +
/// `File::create` 什么目录 —— 现算唯一调用点传的是内部 `new_batch_id()`，今天不可达，
/// 但那是纵深缺口：一旦有调用方把渲染层给的串直接传进来，`begin` 就是「按任意名字建目录
/// 并写 payload.zip」的入口。两侧共用本函数，判据不会各写各的再漂移。
///
/// 长度闸按**字符数**（`paths::exceeds_char_len` 是唯一口径，不用 UTF-8 字节数）。
fn batch_id_reject_reason(id: &str) -> Option<&'static str> {
    if id.is_empty() {
        return Some("批次号为空");
    }
    if paths::exceeds_char_len(id, 120) {
        return Some("批次号超过 120 字符");
    }
    if id.contains("..") {
        return Some("批次号含 ..");
    }
    if id.contains('/') || id.contains('\\') {
        return Some("批次号含路径分隔符");
    }
    None
}

fn write_root() -> PathBuf {
    paths::backup_write_dir(SUB)
}

/// 一个正在写入的还原包。`add` 失败 ⇒ 调用方**不得删除该目标**。
pub struct Pack {
    dir: PathBuf,
    batch_id: String,
    /// `Option` 是为了给 `impl Drop`（R6b-M04）让路：`ZipWriter` 需要被 `take()` 出来
    /// 收尾，而实现了 `Drop` 的类型不允许把字段移出去。
    zip: Option<ZipWriter<std::fs::File>>,
    entries: Vec<Entry>,
    total: u64,
    reg_copied: usize,
    /// `finish` 成功落 manifest 后置位；未置位的 Pack 被丢弃 ⇒ 半成品目录要清掉
    finished: bool,
}

impl Drop for Pack {
    /// 异常路径（`begin` 之后、`finish` 之前返回 Err）不把半成品包目录留成不可见孤儿：
    /// `list()` 因缺 manifest 会 `continue` 掉（用户看不见），`total_bytes()` 却按
    /// `payload.zip` 计数（占用看得见、来源看不见），`prune()` 要等攒够
    /// `KEEP_BATCHES` 才清（可长留 20 个）。
    ///
    /// **只在包里还没有任何内容时删**：调用方是「先入包、后删除」的顺序，一旦
    /// `entries` 或 `.reg` 副本已经写进去，这个目录就可能是已删内容的唯一副本，
    /// 那时删它等于删用户的还原依据（AGENTS §2/§3 红线），宁可留残由 `prune` 兜。
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if !self.entries.is_empty() || self.reg_copied > 0 {
            return;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Pack {
    pub fn begin(batch_id: &str) -> Result<Pack, String> {
        if let Some(reason) = batch_id_reject_reason(batch_id) {
            return Err(format!("批次号格式不合法（{reason}），未建包"));
        }
        let dir = write_root().join(batch_id);
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建还原包目录失败: {e}"))?;
        let file = match std::fs::File::create(dir.join(ZIP_NAME)) {
            Ok(f) => f,
            Err(e) => {
                // 目录已建、文件没建起来 ⇒ 不留空目录（它同样不会被 list 看见）
                let _ = std::fs::remove_dir_all(&dir);
                return Err(format!("创建 payload.zip 失败: {e}"));
            }
        };
        Ok(Pack {
            dir,
            batch_id: batch_id.to_string(),
            zip: Some(ZipWriter::new(file)),
            entries: Vec::new(),
            total: 0,
            reg_copied: 0,
            finished: false,
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
            .as_mut()
            .ok_or_else(|| "还原包已收尾，拒绝继续写入".to_string())?
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
                .as_mut()
                .ok_or_else(|| "还原包已收尾，拒绝继续写入".to_string())?
                .write_all(&buf[..n])
                .map_err(|e| format!("写入 zip 内容失败: {e}"))?;
        }
        self.total += written;
        Ok(Entry {
            zip_key: key,
            kind: "file".into(),
            size: written,
            sha256: hash::to_hex(&hasher.finalize()),
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
    ///
    /// 参数是 `mut self` 而不是解构 `self`：`Pack` 实现了 `Drop`（R6b-M04），解构字段
    /// 会被编译器拒绝；`zip` 用 `take()` 取走收尾，其余字段全程只借不移。
    /// 只有 manifest **已经落盘**才把 `finished` 置位 —— 在那之前任何一步失败，
    /// `Drop` 都会把这个还没内容的半成品目录清掉（有内容时 `Drop` 刻意不删，见其注释）。
    pub fn finish(mut self) -> Result<Value, String> {
        let zip = self
            .zip
            .take()
            .ok_or_else(|| "还原包已收尾，不能重复 finish".to_string())?;
        zip.finish().map_err(|e| format!("收尾 payload.zip 失败: {e}"))?;
        let body = render_manifest(&self.entries);
        // 审查 L-6/L-7b：manifest 是还原的唯一依据。原为手写 tmp+rename（无 fsync，
        // 断电可留半截），收敛到 security::atomic_write_file 单一出口（temp→fsync→rename，
        // 失败自动清临时件），与 reg_backup / cleanup 备份清单同口径。
        crate::security::atomic_write_file(&self.dir.join(MANIFEST_NAME), body.as_bytes())
            .map_err(|e| format!("写 manifest 失败: {e}"))?;
        self.finished = true;
        prune(&write_root());
        Ok(json!({
            "id": self.batch_id,
            "dir": self.dir.to_string_lossy(),
            // 字段名与 `list()` 保持一致（files/dirs），否则界面上同一个概念会有两个键
            "files": self.entries.iter().filter(|e| e.kind == "file").count(),
            "dirs": self.entries.iter().filter(|e| e.kind == "dir").count(),
            "bytes": self.total,
            "regCopies": self.reg_copied,
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
///
/// R6b-M06：`kind` 必须是 `file`/`dir` 之一，字节数不得超过写侧的 `MAX_FILE_BYTES`，
/// 违者**整包拒绝**，与「字节数非法」同一判据。此前非 `file`/`dir` 的第三条值（半截写、
/// 手改、位翻）既不还原也不计失败：还原只按 `["dir","file"]` 两趟取值，那种条目会
/// 凭空消失，渲染层据此照样弹「已还原 N 项」——正是模块头「还原时哈希不符一律报错并停下，
/// 不静默跳过」这条自述禁止的事。
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
        if parts[1] != "file" && parts[1] != "dir" {
            return Err(format!("manifest 第 {} 行类型不是 file/dir: {}", i + 2, parts[1]));
        }
        let size = parts[2]
            .parse::<u64>()
            .map_err(|_| format!("manifest 第 {} 行字节数非法", i + 2))?;
        // 声明字节数与写侧上限对齐：写侧就不可能产出超过 MAX_FILE_BYTES 的条目，
        // 盘上出现更大的串只能是被改写过（R6b-M05 的第一道闸，restore 循环前就拦）
        if size > MAX_FILE_BYTES {
            return Err(format!(
                "manifest 第 {} 行声明字节数 {size} 超过单文件上限 {MAX_FILE_BYTES}",
                i + 2
            ));
        }
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
/// subtree 只有 `%WINDIR%\System32\config` 一棵（`protect.rs` 的 `ProtectRoots::subtree` 默认根），`System32\drivers` 这类
/// 并不在册。删除侧不碰它靠的是「规则库根本不会产出那种目标」，而还原侧的路径来自磁盘上
/// 一份可被改写的 manifest，不能拿「没人会那么写」当防线。
///
/// v5-K02 批次 1（R6b-01）：本函数此前私有一份「replace+lowercase」的 %WINDIR% 判据
/// ——仓内第三份同语义实现（N6 禁的正是这个形状），protect 侧「`\\?\` 必须剥掉」的
/// 收紧不会自动传到副本，`\\?\C:\Windows\System32\drivers\x.sys` 因此直接穿过
/// （rustc 探针实测：windir 字符串 guard 不触发、protect subtree 又不含
/// `System32\drivers`）。现删私有副本，入口统一过 `normalize_for_compare`，
/// %WINDIR% 判据改调 `protect::is_system_namespace`（内部已归一）。
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
    // 归一（与删除侧同一入口）：剥 `\\?\` / 还原 `\\?\UNC\`、设备路径 fail-closed、
    // 折叠 `.`/`..`、盘符相对按盘根拼、尾点尾空格与 8.3 一并无收口。
    let n = protect::normalize_for_compare(path);
    if !n.ok {
        return Some("路径形态无法判定（设备路径等无法判定的形态），已拒绝".into());
    }
    let low = n.low;
    let np = Path::new(&low);
    // 盘根复核：`\\?\C:\` 的 components() 是 2（verbatim 前缀 + 根），绕过上面那道
    // 判据；归一后是 `c:`（单 component）⇒ 在本步一并收口
    if np.components().count() < 2 {
        return Some("盘根目录不可作为还原目标".into());
    }
    if protect::is_path_protected(&low) {
        return Some("受保护路径".into());
    }
    if protect::is_system_namespace(&low) {
        return Some("位于系统目录（%WINDIR%）内，还原不提供写入系统目录的入口".into());
    }
    // 父目录是 reparse point 时，写进去会落到链接指向的另一处，等于绕过上面的路径判定
    if let Some(parent) = np.parent() {
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
/// 任何一条不成立都记成失败原因，不静默跳过。
///
/// 返回体三档：`restored` / `conflicts` / `failed`（逐项对象带 path+reason）。
/// 这里刻意**没有** skipped 档，也从未有过：此前本函数的自述写着「返回体带
/// ok/failed/conflict/skipped 四档」，那是一条与实现不符的承诺（R6b-M06 复核），
/// 而「有条目被跳过」这件事本身已经由 `parse_manifest` 的 kind 白名单堵死——
/// 形态不对的 manifest 整包拒绝，不会挑一条丢掉。
/// `conflicts`（目标已存在）同时也计入 `failed`：渲染层只读 `failed.length` 与 `restored`，
/// 冲突必须是用户看得见的东西，不能只藏在一个没有消费者的计数里。
pub fn restore(batch_id: &str) -> Result<Value, String> {
    // batch_id 来自渲染层，先当「不可信文件名」处理：判据与 `Pack::begin` 同一条（R6b-L10）
    if let Some(reason) = batch_id_reject_reason(batch_id) {
        return Err(format!("批次号格式不合法（{reason}）"));
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
    // 已解出的字节数（整批累计，用于 R6b-M05 的 `MAX_BATCH_BYTES` 早退闸）
    let mut restored_bytes: u64 = 0;
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
                // P0-4（R4-M09）：create_dir_all 沿字符串路径逐级建——最近的现存祖先
                // 是 junction 时，新建内容会落到链接另一头。写当场用同一判据复检父链
                // （判据唯一真源 protect::ancestor_reparse_block_reason，N6 不另造一套），
                // 失败项进逐项 failed 回执、其余项继续，不整批中断。
                // 残余风险：字符串路径检查与真实创建之间仍有 TOCTOU 窗口；在未改成
                // 句柄相对（CreateFile + 相对句柄）操作之前，回归测试只能证明「窗口缩窄」，
                // 不能宣称完全消除。
                if let Some(reason) = protect::ancestor_reparse_block_reason(&e.orig_path) {
                    failed.push(json!({ "path": e.orig_path, "reason": reason }));
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
            // P0-4（R4-M09）：写点（create_dir_all 与临时文件创建）之前逐级复检现存父链，
            // 判据与目录趟同源（TOCTOU 残余窗口说明见上趟注释与 protect 侧判据函数）。
            if let Some(reason) = protect::ancestor_reparse_block_reason(&e.orig_path) {
                failed.push(json!({ "path": e.orig_path, "reason": reason }));
                continue;
            }
            if let Some(parent) = target.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // 先落到目标同目录的临时名，校验哈希后再改名就位：半途失败不留「半个文件」
            let tmp = target.with_extension(format!("trim-restore-{}", std::process::id()));
            // P0-4（R4-M09）：临时名的 pid 形态可被猜到，可能已被人预建为联接——
            // File::create 前对 tmp 自身再观测一次（symlink_metadata 不跟随链接，判据复用
            // protect::is_reparse）；带 reparse 属性即拒且不碰它——那是别人预建的件，
            // 删除超出本函数职权；本进程写出的半截 tmp 仍由下方既有失败分支清理。
            if let Ok(md) = std::fs::symlink_metadata(&tmp) {
                if protect::is_reparse(&md) {
                    failed.push(json!({
                        "path": e.orig_path,
                        "reason": format!("临时目标已是 reparse 点，写入会落到链接另一头，已拒绝：{}", tmp.display()),
                    }));
                    continue;
                }
            }
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
            // R6b-M05：解包写盘必须有上限。模块头把 manifest 建模成「磁盘上一份可被改写的
            // 东西」，同一威胁模型下条目声明的 `size` 与 zip 实际
            // 解出来的字节不符时，写侧的两道上限（`MAX_FILE_BYTES`/`MAX_BATCH_BYTES`）
            // 在还原侧此前一道都没有 ⇒ 先把盘写满，再在循环**结束后**才报「字节数不符」。
            // 现在按「声明字节数」逐块早退（声明值本身又被 parse_manifest 卡在
            // `MAX_FILE_BYTES` 内），并给整批加与写侧同一条 `MAX_BATCH_BYTES` 累计闸。
            let entry_cap = e.size.min(MAX_FILE_BYTES);
            loop {
                match rf.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        n_total += n as u64;
                        if n_total > entry_cap || restored_bytes + n_total > MAX_BATCH_BYTES {
                            io_err = Some("解包字节数超过上限，已中止".to_string());
                            break;
                        }
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
            restored_bytes += n_total;
            let got = hash::to_hex(&hasher.finalize());
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

/// 文件摘要：**转接** `engine::hash::sha256_file`（R6b-L01，AGENTS §5.16）。
/// 保留这个本地名字只是因为还原侧要的是「读不到 = 当作不匹配」的 Option 口径，
/// 而不是又抄一份「读文件 + 增量哈希 + 转 hex」——那份实现已经在 `hash` 里。
fn file_sha256(path: &Path) -> Option<String> {
    hash::sha256_file(path).ok()
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
    ///
    /// R6b-M06 追加两档：`kind` 不是 `file`/`dir`、声明字节数超过 `MAX_FILE_BYTES`
    /// 同样必须整包拒绝。前者是「既不还原也不计失败」的静默消失面（还原只按
    /// `["dir","file"]` 两趟取值），后者是 R6b-M05 的第一道闸。
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
        // kind 白名单（R6b-M06）：第三条值必须点名拒掉，理由是错误串里要能看见是哪一行、哪个值
        for bad_kind in ["reg", "File", "link", "", "-"] {
            let e = parse_manifest(&format!(
                "trim-restore-pack\t1\nk\t{bad_kind}\t12\tab\tC:\\a"
            ))
            .expect_err("非 file/dir 的类型必须整包拒绝");
            assert!(
                e.contains("类型不是 file/dir") && e.contains("第 2 行"),
                "kind 拒绝必须点名行号与非法值，实得: {e}"
            );
        }
        // 声明字节数超过写侧单文件上限 ⇒ 盘上出现这种串只能是被改写过（R6b-M05 第一道闸）
        let tampered = format!(
            "trim-restore-pack\t1\nk\tfile\t{}\tab\tC:\\a",
            MAX_FILE_BYTES + 1
        );
        assert!(
            parse_manifest(&tampered)
                .err()
                .is_some_and(|e| e.contains("超过单文件上限")),
            "声明字节数超过 MAX_FILE_BYTES 必须整包拒绝"
        );
        // 边界：恰好等于上限不算篡改（写侧允许的最大条目）
        assert!(parse_manifest(&format!(
            "trim-restore-pack\t1\nk\tfile\t{}\tab\tC:\\a",
            MAX_FILE_BYTES
        ))
        .is_ok());
        // 路径里出现制表符不能被切成两个字段：输入与期望都用同一个串，别拿转义口径互相冒充
        let path_with_tab = format!("C:\\a{}b", '\t');
        let ok = parse_manifest(&format!(
            "trim-restore-pack\t1\nk\tfile\t12\tab\t{path_with_tab}"
        ))
        .expect("应可解析");
        assert_eq!(ok[0].orig_path, path_with_tab);
    }

    /// R6b-L10：批次号判据只有一份，`begin` 与 `restore` 都必须走它。
    /// 断言对象是**同一批串在两侧得到同一结论**（此前 begin 完全不校验，
    /// 传进渲染层串就是「按任意名字建目录并写 payload.zip」的入口）。
    #[test]
    fn 批次号判据在写入侧与还原侧同一份() {
        for bad in ["", "..\\..\\x", "a/b", r"a\b", &"x".repeat(200), "..", "a..b"] {
            let reason = batch_id_reject_reason(bad).expect("判据自身必须给出理由");
            let b = Pack::begin(bad)
                .err()
                .unwrap_or_else(|| panic!("begin 必须拒绝批次号 {bad:?}"));
            let r = restore(bad)
                .err()
                .unwrap_or_else(|| panic!("restore 必须拒绝批次号 {bad:?}"));
            // 两个入口都必须把**同一个理由**原样交出来：两套实现的典型症状就是理由分叉
            assert!(
                b.contains("批次号格式不合法") && b.contains(reason),
                "begin 对 {bad:?} 的拒绝理由异常: {b}"
            );
            assert!(
                r.contains("批次号格式不合法") && r.contains(reason),
                "restore 对 {bad:?} 的拒绝理由异常: {r}"
            );
        }
        // 生成器形态（new_batch_id 的 ISO 去 :/.）必须放行，否则 begin 与 restore 双双打死合法批次
        let shaped = crate::engine::delete_manifest::new_batch_id();
        assert!(
            batch_id_reject_reason(&shaped).is_none(),
            "既有生成器的形态不得被新闸打死: {shaped}"
        );
        // 中文/多字节批次名：长度闸按**字符数**口径（`paths::exceeds_char_len` 是唯一真源），
        // 120 个汉字 = 360 字节，按字节口径会被误拒
        let cjk = "批次".repeat(60);
        assert_eq!(
            cjk.len(),
            360,
            "样本自身的前提：字符数与字节数必须不同，否则这条断言没在测东西"
        );
        assert!(
            batch_id_reject_reason(&cjk).is_none(),
            "120 字符的中文批次名要按字符数放行（实得 {} 字符 / {} 字节）",
            cjk.chars().count(),
            cjk.len()
        );
        assert!(
            batch_id_reject_reason(&"批".repeat(121)).is_some(),
            "超过 120 字符必须拒"
        );
    }

    /// R6b-M04：`begin` 之后没有 `finish` 就被丢弃（调用方在 begin 与 finish 之间
    /// `return Err`）⇒ 目录必须被清掉，不能留成「list() 看不见、total_bytes() 却计数」的孤儿。
    /// 判红自证：删掉 `impl Drop for Pack` 里的 remove_dir_all ⇒ 第二条断言立刻红。
    #[test]
    fn 未收尾的还原包不留目录() {
        let batch = format!("drop-empty-{}", crate::engine::now_ms());
        let dir = paths::backup_write_dir(SUB).join(&batch);
        let _ = std::fs::remove_dir_all(&dir);
        {
            let pack = Pack::begin(&batch).expect("begin 应建包");
            assert!(dir.is_dir(), "前置条件：begin 必须已经把目录建出来");
            drop(pack);
        }
        assert!(
            !dir.exists(),
            "未 finish 且没有任何内容的半成品包必须被 Drop 清掉，实得目录仍在: {}",
            dir.display()
        );
    }

    /// R6b-M04 的反向半条：**已经有内容**的包绝不能被 Drop 顺手删掉。
    /// 调用顺序是「先入包、后删除」，包一旦有条目就可能是已删内容的唯一副本，
    /// 删它等于删用户的还原依据（AGENTS §2/§3）。判红自证：把 Drop 里的
    /// `entries.is_empty()` 前置条件去掉 ⇒ 本用例红。
    #[test]
    fn 已入包内容的还原包不被丢弃路径删掉() {
        let stamp = crate::engine::now_ms();
        let batch = format!("drop-kept-{stamp}");
        let dir = paths::backup_write_dir(SUB).join(&batch);
        let probe = paths::lib_test_data_root().join(format!("probe-{stamp}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&probe).expect("建探针目录");
        std::fs::write(probe.join("only.txt"), "唯一副本".as_bytes()).expect("写探针文件");
        {
            let mut pack = Pack::begin(&batch).expect("begin 应建包");
            let n = pack.add_target(&probe).expect("探针目录入包");
            assert!(n >= 2, "目录本体 + 1 个文件至少 2 条，实得 {n}");
            drop(pack); // 不调 finish
        }
        let kept = dir.is_dir();
        let manifest_absent = !dir.join(MANIFEST_NAME).exists();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&probe);
        assert!(
            kept && manifest_absent,
            "入过内容的包必须留在原处等 prune（Drop 不得删还原依据）；kept={kept} manifest_absent={manifest_absent}"
        );
    }

    /// R6b-L01：本模块的摘要判据必须**转接** `engine::hash`，不许留第二份实现。
    /// 断言写法是「与真源逐字节相等」，不是「看起来对」：一旦有人把私有 hex 编码抄回来，
    /// 这条会在某侧口径变化（大小写/补零）时红。
    #[test]
    fn 摘要判据转接_hash_真源() {
        for p in [r"C:\App\a.txt", r"c:\app\A.TXT", r"C:/中文目录/文件.bin"] {
            let norm = p.replace('/', "\\").to_uppercase();
            assert_eq!(
                zip_key_of(p),
                crate::engine::hash::sha256_bytes(norm.as_bytes())[..16],
                "zip_key_of 必须等于 hash 真源的前 16 位（{p}）"
            );
        }
        // file_sha256 只是 Option 口径的转接，不是另一份读+哈希实现
        let probe = paths::lib_test_data_root().join("digest-delegate.txt");
        std::fs::write(&probe, b"abc").expect("写样本");
        let local = file_sha256(&probe);
        let truth = crate::engine::hash::sha256_file(&probe).ok();
        let _ = std::fs::remove_dir_all(&probe);
        assert_eq!(
            local, truth,
            "file_sha256 必须与 hash::sha256_file 给同一个串（两侧各写一份迟早漂）"
        );
        assert_eq!(
            local.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            "已知向量必须命中，否则转接的是错的那一份"
        );
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
        // 与 `%WINDIR%\System32\config`（`protect.rs` 的 `ProtectRoots::subtree` 默认根），当前数据目录 `com.xiaoxu.trim`
        // 并不在其中——上一轮我按「应用自身数据目录在册」写断言，跑出来是放行，事实纠正于此。
        let legacy = format!(
            "{}\\Trim\\startup.json",
            std::env::var("APPDATA").unwrap_or_default()
        );
        assert!(
            restore_path_verdict(&legacy).is_some(),
            "is_path_protected 在册的老根必须拒，实得放行: {legacy}"
        );
        // v5-K02 批次 1（R6b-01）：verbatim 前缀不得穿过 %WINDIR% 判据。
        // 修前 rustc 探针实测：`\\?\C:\Windows\System32\drivers\x.sys` 的 windir
        // 字符串 guard 不触发、protect subtree 又不含 `System32\drivers` ⇒ 放行。
        assert!(
            restore_path_verdict(r"\\?\C:\Windows\System32\drivers\x.sys").is_some(),
            "verbatim 形态必须被系统目录判据拒（修前实测放行）"
        );
        // 同一根因：`\\?\C:\` 的 components() 是 2（verbatim 前缀 + 根），盘根判据
        // 对它整体失效；归一后是 `c:`（单 component）⇒ 归一后的盘根复核收口
        assert!(
            restore_path_verdict(r"\\?\C:\").is_some(),
            "verbatim 盘根必须拒（components()=2 绕过了原始盘根判据）"
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
    /// 后者对「什么都没还原」也成立。
    ///
    /// R6b-L09（措辞↔代码对齐）：探针目录**确实**在应用私有根下——C08 之后 `cfg(test)`
    /// 的 `paths::app_data_dir()` 就是 lib 单测隔离数据根，本用例取它的子目录，
    /// 不再用全局 `%TEMP%`（AGENTS §3 私有 tmp 口径）。Drop 守卫连探针目录带还原包
    /// 整批删除，断言 panic 也收。刻意**不用**老根 `%APPDATA%\Trim` 与 `%WINDIR%`：
    /// 那两棵在 protect 的 subtree 面里，还原准入会逐条拒掉，用例红在设计而不是红在实现。
    #[test]
    #[ignore = "真写盘（lib 单测隔离数据根下的探针目录），发布前门禁跑"]
    fn pack_then_restore_restores_bytes_end_to_end() {
        let stamp = crate::engine::now_ms();
        let batch = format!("test-{stamp}");
        let root = paths::lib_test_data_root().join(format!("probe-{stamp}"));
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

    /// R6b-M05 真机探针（真写盘 / 真打包）：manifest 声明 KB 级、zip 里实际是 MB 级时，
    /// 还原必须在**写盘阶段早退**，目标目录里不得出现按实际字节数写满的文件。
    ///
    /// 修前实现只在循环**结束后**比 `n_total != e.size` —— 同一威胁模型下（模块头把
    /// manifest 建模成「磁盘上一份可被改写的东西」）`payload.zip` 一样可改，于是
    /// 「先把盘写满，再报字节数不符，再删 tmp」。zip crate 不自带解压上限，闸只能设在这里。
    ///
    /// 判红自证：删掉循环里 `n_total > entry_cap` 那一条早退 ⇒ 最后一条断言红
    /// （tmp 被写成 1MB 才失败），或失败原因变成「哈希不符/字节数不符」而不是「超过上限」。
    ///
    /// 只跑档位：`cargo test --lib -- --ignored`（发布前门禁）。整批累计那条
    /// （`MAX_BATCH_BYTES`）需要 2GB 级样本，本探针不覆盖，如实记未验证。
    #[test]
    #[ignore = "真写盘 + 真打包（lib 单测隔离数据根下），发布前门禁跑"]
    fn 解包字节上限在写盘前早退() {
        let stamp = crate::engine::now_ms();
        let batch = format!("cap-{stamp}");
        let probe_root = paths::lib_test_data_root().join(format!("probe-cap-{stamp}"));
        let pack_dir = paths::backup_write_dir(SUB).join(&batch);
        struct G {
            a: PathBuf,
            b: PathBuf,
        }
        impl Drop for G {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.a);
                let _ = std::fs::remove_dir_all(&self.b);
            }
        }
        let _g = G { a: probe_root.clone(), b: pack_dir.clone() };

        std::fs::create_dir_all(&probe_root).expect("建探针目录");
        std::fs::write(probe_root.join("big.bin"), vec![0xA5u8; 1024 * 1024]).expect("写 1MB 样本");
        let mut pack = Pack::begin(&batch).expect("建包");
        pack.add_target(&probe_root).expect("探针目录入包");
        pack.finish().expect("收尾");
        std::fs::remove_dir_all(&probe_root).expect("删探针目录（制造只能靠还原找回的现场）");

        // 把第一条 file 条目的**声明字节数**改成 1024（zip 里实际 1MB），模拟被改写的 manifest
        let mpath = pack_dir.join(MANIFEST_NAME);
        let text = std::fs::read_to_string(&mpath).expect("manifest 应在");
        let lines: Vec<String> = text.lines().map(String::from).collect();
        let mut rewritten: Vec<String> = vec![lines[0].clone()];
        let mut tampered = false;
        for l in &lines[1..] {
            let p: Vec<&str> = l.splitn(5, '\t').collect();
            if !tampered && p.len() == 5 && p[1] == "file" {
                rewritten.push(format!("{}\t{}\t1024\t{}\t{}", p[0], p[1], p[3], p[4]));
                tampered = true;
            } else {
                rewritten.push(l.clone());
            }
        }
        assert!(tampered, "manifest 里必须有一条 file 条目可改写");
        std::fs::write(&mpath, format!("{}\n", rewritten.join("\n"))).expect("改写 manifest");

        let out = restore(&batch).expect("整批不报错，失败要逐项列出来");
        let fails = out["failed"].as_array().cloned().unwrap_or_default();
        assert!(
            fails
                .iter()
                .any(|f| f["reason"].as_str().unwrap_or("").contains("解包字节数超过上限")),
            "声明 1KB / 实际 1MB 的条目必须按声明数早退并点名，实得 {out}"
        );
        // 早退的**实物证据**：目标目录里不得出现按实际字节数（1MB）写出来的文件
        let oversize: Vec<String> = std::fs::read_dir(&probe_root)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        let p = e.path();
                        let len = std::fs::metadata(&p).ok()?.len();
                        (len > 1024).then(|| format!("{}={}", p.display(), len))
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            oversize.is_empty(),
            "早退必须发生在写盘**之前**，不得留下超过声明字节的半成品: {oversize:?}"
        );
    }

    /// P0-4（R4-M09）的 M3 判据半边：还原写回的目标**合法地可以不存在**（新建文件），
    /// 父链全是普通目录时不得因为「不存在」就被父链闸拒。用例做法是在 manifest 里追加
    /// 一条复用同一 zip 条目、原路径指向隔离根内「尚不存在的两层新目录」的行，要求它
    /// 照常还原并把字节写到新位置。
    ///
    /// 判红自证：把 `protect::ancestor_reparse_block_reason` 的 NotFound 分支从 `continue`
    /// 改成 `return Some(...)`（即「不存在一律拒」）⇒ 本用例的 failed 断言立刻红。
    #[test]
    fn 还原写回不误伤父链干净的合法新建() {
        let stamp = crate::engine::now_ms();
        let batch = format!("p04-ok-{stamp}");
        let root = paths::lib_test_data_root().join(format!("p04-ok-{stamp}"));
        let pack_dir = paths::backup_write_dir(SUB).join(&batch);
        struct G {
            a: PathBuf,
            b: PathBuf,
        }
        impl Drop for G {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.a);
                let _ = std::fs::remove_dir_all(&self.b);
            }
        }
        let _g = G { a: root.clone(), b: pack_dir.clone() };
        // 前置条件：测试根自身的父链必须干净。个别机器把 `target` 挂成 junction 时，
        // 「父级普通」这条前提在环境侧就不成立 —— 显式 SKIP 并声明未校验，
        // 既不假红也不假绿（AGENTS §5：用例不得依赖只在本机成立的形状）。
        let base = paths::lib_test_data_root().to_string_lossy().to_string();
        if let Some(why) = protect::ancestor_reparse_block_reason(&format!(r"{base}\precheck.txt")) {
            eprintln!("SKIP：测试根父链带 reparse（{why}），本用例的「普通父链」前提不成立");
            return;
        }
        std::fs::create_dir_all(&root).expect("建探针目录");
        std::fs::write(root.join("a.txt"), "新建放行样本".as_bytes()).expect("写探针文件");

        let mut pack = Pack::begin(&batch).expect("建包");
        pack.add_target(&root).expect("探针目录入包");
        pack.finish().expect("收尾");

        let fresh = root.join("brandnew").join("deeper").join("a.txt");
        let mpath = pack_dir.join(MANIFEST_NAME);
        let text = std::fs::read_to_string(&mpath).expect("manifest 应在");
        let first_file = text
            .lines()
            .skip(1)
            .find(|l| l.splitn(5, '\t').nth(1) == Some("file"))
            .expect("manifest 里必须有 file 条目")
            .to_string();
        let p: Vec<&str> = first_file.splitn(5, '\t').collect();
        std::fs::write(
            &mpath,
            format!("{}\n{}\tfile\t{}\t{}\t{}\n", text.trim_end(), p[0], p[2], p[3], fresh.display()),
        )
        .expect("改写 manifest");

        let out = restore(&batch).expect("整批不报错");
        assert!(
            out["failed"].as_array().map(|a| a.len()) == Some(0),
            "父链干净的合法新建不得被父链闸误拒，实得 {out}"
        );
        assert_eq!(
            std::fs::read_to_string(&fresh).ok().as_deref(),
            Some("新建放行样本"),
            "放行必须是真的把字节写进新建路径，不是空转"
        );
    }

    /// P0-4（R4-M09）真机 `#[ignore]` 探针（**本轮未执行**，归发布前门禁）：在 lib 单测
    /// 隔离数据根内自建 junction（`mklink /J` 免管理员），再往 manifest 追加一条指向
    /// 「junction 之下、尚不存在」的原路径。要求：该项进逐项 `failed` 且拒因点名 reparse、
    /// junction 另一头不得长出还原内容、同批其余项照常还原（逐项拒 ≠ 整批中止）。
    ///
    /// 判红自证：删掉 `restore` 里 file 趟 `create_dir_all` 之前的
    /// `ancestor_reparse_block_reason` 复检 ⇒ 第三条断言红（`<root>\real\ghostdir` 会被
    /// 真的建出来，字节落到链接另一头）。
    ///
    /// 只写本用例自己的隔离根子目录，不碰真实 `%APPDATA%` 与真实用户目录（C08 之后
    /// `cfg(test)` 的数据根就是 `target/test-data-root/lib`）；受限环境建不出 junction 时
    /// 显式 SKIP 并声明未校验，不假绿。
    #[test]
    #[ignore = "真写盘 + 需建 junction（lib 单测隔离数据根内），发布前门禁跑"]
    fn 还原写回链拒绝junction父目录的新建目标() {
        let stamp = crate::engine::now_ms();
        let batch = format!("p04-j-{stamp}");
        let root = paths::lib_test_data_root().join(format!("p04-j-{stamp}"));
        let pack_dir = paths::backup_write_dir(SUB).join(&batch);
        let real = root.join("real");
        let link = root.join("jlink");
        struct G {
            a: PathBuf,
            b: PathBuf,
            link: PathBuf,
        }
        impl Drop for G {
            fn drop(&mut self) {
                // junction 先按链接本体摘掉再清树：直接 remove_dir_all 一棵带链接的树，
                // 跟着链接走会把另一头的真实内容一起删掉
                if std::fs::symlink_metadata(&self.link).is_ok() {
                    let _ = std::fs::remove_dir(&self.link);
                }
                let _ = std::fs::remove_dir_all(&self.a);
                let _ = std::fs::remove_dir_all(&self.b);
            }
        }
        let _g = G { a: root.clone(), b: pack_dir.clone(), link: link.clone() };
        std::fs::create_dir_all(&real).expect("建探针目录");
        std::fs::write(real.join("a.txt"), "穿链样本".as_bytes()).expect("写探针文件");

        let mut pack = Pack::begin(&batch).expect("建包");
        pack.add_target(&real).expect("探针目录入包");
        pack.finish().expect("收尾");

        let made = std::process::Command::new("cmd")
            .args(["/C", &format!(r#"mklink /J "{}" "{}""#, link.display(), real.display())])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !made {
            eprintln!("SKIP：本机建不出 junction（受限环境），父链穿链分支未校验");
            return;
        }

        let ghost = link.join("ghostdir").join("a.txt").to_string_lossy().to_string();
        let mpath = pack_dir.join(MANIFEST_NAME);
        let text = std::fs::read_to_string(&mpath).expect("manifest 应在");
        let first_file = text
            .lines()
            .skip(1)
            .find(|l| l.splitn(5, '\t').nth(1) == Some("file"))
            .expect("manifest 里必须有 file 条目")
            .to_string();
        let p: Vec<&str> = first_file.splitn(5, '\t').collect();
        std::fs::write(
            &mpath,
            format!("{}\n{}\tfile\t{}\t{}\t{}\n", text.trim_end(), p[0], p[2], p[3], ghost),
        )
        .expect("改写 manifest");

        let out = restore(&batch).expect("整批不报错，失败要逐项列出来");
        let fails = out["failed"].as_array().cloned().unwrap_or_default();
        assert_eq!(fails.len(), 1, "只有穿链那一条该失败，其余项不得被牵连，实得 {out}");
        assert!(
            fails[0]["path"].as_str() == Some(ghost.as_str())
                && fails[0]["reason"].as_str().unwrap_or("").contains("reparse"),
            "穿链条目必须点名 reparse 拒因，实得 {out}"
        );
        assert!(
            !real.join("ghostdir").exists(),
            "junction 另一头不得长出还原内容——那正是本批要堵的实际落点"
        );
        assert!(
            out["restored"].as_u64().unwrap_or(0) >= 1,
            "坏条目之外的项仍应还原（逐项拒，不整批中止），实得 {out}"
        );
    }
}
