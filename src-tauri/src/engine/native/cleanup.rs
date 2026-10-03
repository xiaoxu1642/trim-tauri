//! B10 清理域：条目明细枚举（cleanup_detail）与清理执行（cleanup_execute）。
//!
//! 安全口径（改这里之前先读 AGENTS §3）：
//! - 删除先过 `engine::protect::is_path_protected`；
//! - 常规清理按 v3.3.0 用户裁定**固定永久删**（toRecycle 恒 false），不做永久删兜底；
//! - 文件备份按 `<规则id>/` 跨批次共享，保留裁剪走 `prune_file_backups`，只裁新根。
//! 规则库契约测试（P0）与文件备份保留测试随本实现放在同一文件。


use crate::engine::systembin::system_tool;
use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW};
use super::common::*;
use super::registry::*;

/// DISM /StartComponentCleanup /ResetBase 的超时上限（2026-10-04 审计 §4.4）。
/// 与 maintenance.rs 的 MAINT_CMD_TIMEOUT 同级（sfc/DISM/sc 属同级长耗时子进程，
/// 合法就要跑几十分钟）；登记在 `tools/check-ps-callsites.mjs` 的
/// TIMEOUT_SPAWN_SITES 表（F 组），秒数一致性由该门禁对拍。
const DISM_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1800);
// ==================== B10 cleanup_detail：条目明细枚举 ====================

/// 清理条目明细枚举（对应 cleanup_detail.ps1，S3）
///
/// 输入 rule JSON 和目标路径，返回 {kind, total, truncated, files}。
/// 复杂 glob/排除规则回退 PS（commands 层判定）。
pub fn cleanup_detail(rule: &Value, target_path: &str) -> Result<Value, String> {
    let cap = 600usize;

    // special=dism
    if rule.get("special").and_then(|v| v.as_str()) == Some("dism") {
        return Ok(json!({"kind": "dism", "total": 0, "truncated": false, "files": []}));
    }

    // regKeys 型
    if let Some(reg_keys) = rule.get("regKeys").and_then(|v| v.as_array()) {
        if !reg_keys.is_empty() {
            let mut count = 0usize;
            for rk in reg_keys {
                let path = rk.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if path.is_empty() { continue; }
                let expanded = expand_env(path);
                if let Some((hive, rest)) = parse_reg_path(&expanded) {
                    count += unsafe { reg_count_key(hive, &rest, rk.get("value").is_some()) };
                }
            }
            return Ok(json!({"kind": "reg", "total": count, "truncated": false, "files": []}));
        }
    }

    // fileKeys 型
    if let Some(file_keys) = rule.get("fileKeys").and_then(|v| v.as_array()) {
        if !file_keys.is_empty() {
            let mut files: Vec<Value> = Vec::new();
            let mut total = 0usize;
            let mut seen = std::collections::HashSet::new();
            for fk in file_keys {
                let path = fk.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if path.is_empty() { continue; }
                let pattern = fk.get("pattern").and_then(|v| v.as_str()).unwrap_or("*");
                let recurse = fk.get("recurse").and_then(|v| v.as_bool()).unwrap_or(true);
                let expanded = expand_env(path);
                // 段级 glob 展开（v0.1.6 真机修复：旧实现遇 `*` 直接 Err 且 PS 回退已删）
                for base in expand_glob_dirs(&expanded) {
                    if let Ok(meta) = std::fs::metadata(&base) {
                        if meta.is_file() {
                            if seen.insert(base.clone()) {
                                total += 1;
                                if files.len() < cap {
                                    files.push(json!({"path": base, "size": meta.len()}));
                                }
                            }
                            continue;
                        }
                    }
                    if !std::path::Path::new(&base).is_dir() { continue; }
                    enumerate_files(&base, pattern, recurse, &mut files, &mut total, &mut seen, cap);
                }
            }
            return Ok(json!({"kind": "files", "total": total, "truncated": total > cap, "files": files}));
        }
    }

    // 目录型
    if !target_path.is_empty() && std::path::Path::new(target_path).exists() {
        let mut files: Vec<Value> = Vec::new();
        let mut total = 0usize;
        let mut seen = std::collections::HashSet::new();
        enumerate_files(target_path, "*", true, &mut files, &mut total, &mut seen, cap);
        return Ok(json!({"kind": "files", "total": total, "truncated": total > cap, "files": files}));
    }

    Ok(json!({"kind": "files", "total": 0, "truncated": false, "files": []}))
}

/// 段级 glob 展开（规则库 `%...\*\...` 形态，真机 v0.1.6 反馈）：路径中含 `*`
/// 的段对子项名做通配匹配，返回展开后的具体路径（目录或文件）。跳过 reparse 项。
/// 只认 `*`（与 glob_match 同口径）；静态段直接拼接，开销可忽略。
fn expand_glob_dirs(pattern_path: &str) -> Vec<String> {
    let mut cur: Vec<String> = Vec::new();
    for seg in pattern_path.split('\\').filter(|s| !s.is_empty()) {
        if cur.is_empty() {
            cur.push(seg.to_string());
            continue;
        }
        let mut next = Vec::new();
        for base in &cur {
            if !seg.contains('*') {
                next.push(format!("{base}\\{seg}"));
                continue;
            }
            let Ok(rd) = std::fs::read_dir(base) else { continue };
            for entry in rd.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_string();
                if !glob_match(seg, &name) { continue; }
                // 同 enumerate_files 口径：跳过 reparse（v2-L4P-11/C-1：is_symlink 在
                // Windows 上只认 SYMLINK/MOUNT_POINT 两个 tag，云占位符那类
                // is_symlink=false && is_dir=true 的 reparse 会被放过去穿透进另一块存储）
                if let Ok(meta) = entry.metadata() {
                    if crate::engine::protect::is_reparse(&meta) { continue; }
                }
                next.push(format!("{base}\\{name}"));
            }
        }
        cur = next;
    }
    cur
}

/// 执行侧遍历深度上限（v2-L4P-11/C-1）：与 native-scanner 的 `MAX_WALK_DEPTH=64`
/// 同口径。此前 collect_files/enumerate_files 无上限，规则目标深处若有环状结构
/// （经普通目录绕开 reparse 判定构造不了，但超深目录树可以把删除清单撑爆）。
const ENGINE_WALK_MAX_DEPTH: usize = 64;

fn enumerate_files(
    dir: &str, pattern: &str, recurse: bool,
    files: &mut Vec<Value>, total: &mut usize,
    seen: &mut std::collections::HashSet<String>, cap: usize,
) {
    enumerate_files_at(dir, pattern, recurse, files, total, seen, cap, 0)
}

fn enumerate_files_at(
    dir: &str, pattern: &str, recurse: bool,
    files: &mut Vec<Value>, total: &mut usize,
    seen: &mut std::collections::HashSet<String>, cap: usize,
    depth: usize,
) {
    if depth >= ENGINE_WALK_MAX_DEPTH { return; }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        // 跳过 reparse 点（v2-L4P-11/C-1：0x400 属性位口径，见 expand_glob_dirs 注释）
        let Ok(meta) = entry.metadata() else { continue };
        if crate::engine::protect::is_reparse(&meta) { continue; }
        if meta.is_dir() {
            if recurse {
                enumerate_files_at(&path.to_string_lossy(), pattern, recurse, files, total, seen, cap, depth + 1);
            }
        } else if meta.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !glob_match(pattern, &name) { continue; }
            let full = path.to_string_lossy().to_string();
            if !seen.insert(full.clone()) { continue; }
            *total += 1;
            if files.len() < cap {
                files.push(json!({"path": full, "size": meta.len()}));
            }
        }
    }
}

fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" { return true; }
    // 简单 * 匹配
    if let Some(idx) = pattern.find('*') {
        let prefix = &pattern[..idx];
        let suffix = &pattern[idx+1..];
        return name.starts_with(prefix) && name.ends_with(suffix) && name.len() >= prefix.len() + suffix.len();
    }
    pattern == name
}

unsafe fn reg_count_key(hive: HKEY, path: &str, has_value: bool) -> usize {
    let sk = to_wide(path);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
        return 0;
    }
    let mut count = 1usize; // 键本身
    if !has_value {
        // 计数值 + 子键
        count += reg_count_values(hk);
        let mut index = 0u32;
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len = 256u32;
            if RegEnumKeyExW(hk, index, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None).is_err() { break; }
            count += 1;
            index += 1;
        }
    }
    let _ = RegCloseKey(hk);
    count
}
// ==================== B10 cleanup_execute：清理执行 ====================

/// 清理执行结果
pub struct CleanupExecuteResult {
    pub details: Vec<Value>,
    pub freed: i64,
    pub file_count: i64,
    pub recycle_entries: Vec<Value>,
}

/// 永久删副本的保留上限（N3，2026-09-29）。裁「最老批次」，但副本落在
/// `<规则id>\<序号>_<文件名>`（见本文件 C-4 写入处），**批次时间戳找不到对应目录**，
/// 所以只能照清单条目删——清单就是那批副本的唯一索引。删完顺手收掉空掉的规则目录，
/// 否则 `cleanup-files-backup` 里会留下一堆空壳，看起来"还有备份"其实一份都还原不了。
///
/// 只裁新根（调用方传 `backup_write_dir`）：老根那份是升级前的唯一还原依据。
/// 永久删副本的相对名：`<规则id>\<批次ms>_<序号>_<文件名>`。两段易变成分各有不可替代的理由：
///
/// - **批次段**：少了它 ⇒ 同一条规则第二次清理命中同名文件时 `rel` 逐字节相同，第二次
///   `copy` 原地覆盖第一次的副本，而两份 manifest 都还写着同一个 `file` ——「还原第 1 批」
///   静默拿回第 2 批的字节，且不报错（N10）。
/// - **序号段**：少了它 ⇒ 同一批次里两个不同目录下的同名 `.log` 互相覆盖。
///
/// 批次段是纯数字 ms，字符集不比原形状宽 ⇒ 还原侧那道穿越准入（拒 `..` / 绝对 / 盘符）不用动。
/// 读侧天然兼容：还原走的是 manifest 里存的 `rel`，老清单里的老形状照样能还原，
/// 所以这里不需要版本号、不需要搬迁、不需要双分支解析。
fn backup_rel_name(rule_id: &str, batch_ts: i64, seq: u32, fname: &str) -> String {
    format!("{rule_id}\\{batch_ts}_{seq}_{fname}")
}

/// 孤儿副本回收的冷静期（2026-10-04 审计 §4.5③）：清单落盘失败的那批副本要等
/// 24h 才回收——副本刚写完、清单还没落盘的瞬间窗口，以及「清单写失败但磁盘稍后
/// 可写」的重试窗口，都不允许被 GC 抢跑。生产用常量；测试经 `_with` 变体注入 0。
const ORPHAN_GC_MIN_AGE_MS: i64 = 24 * 3600 * 1000;

/// 备份根的包含性核验（2026-10-04 审计 §4.5①）。
///
/// 词法准入（拒 `..`/绝对/盘符）拦不住**根内的重解析段**：`rel = "sub\file"` 且
/// `sub` 是指向根外的 junction 时，`root.join(rel)` 解析到根外，而
/// `symlink_metadata` 报的是**目标**属性 ⇒ `is_reparse` 为 false ⇒ 旧实现照删。
/// 这里用 canonicalize 拿 victim 的真实落点：解析不出（不存在/悬空）或解析到
/// 备份根之外一律 fail-closed 拒删——裁剪是多删一份坏处有限的操作，删错根外
/// 文件的代价不对称。
fn backup_victim_within_root(root_canon: &std::path::Path, victim: &std::path::Path) -> bool {
    let Ok(real) = std::fs::canonicalize(victim) else {
        return false;
    };
    let real_low = real.to_string_lossy().to_lowercase();
    let root_low = root_canon.to_string_lossy().to_lowercase();
    let root_low = root_low.trim_end_matches('\\');
    real_low != root_low && real_low.starts_with(&format!("{root_low}\\"))
}

fn prune_file_backups(root: &std::path::Path, keep: usize) {
    prune_file_backups_with(root, keep, ORPHAN_GC_MIN_AGE_MS);
}

/// 同上，`min_orphan_age_ms` 可注入（测试传 0；见 ORPHAN_GC_MIN_AGE_MS 注释）。
fn prune_file_backups_with(root: &std::path::Path, keep: usize, min_orphan_age_ms: i64) {
    let Ok(rd) = std::fs::read_dir(root) else { return };
    let mut manifests: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| {
            n.strip_prefix("manifest-")
                .and_then(|s| s.strip_suffix(".json"))
                .is_some_and(|ts| !ts.is_empty() && ts.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    // §4.5③ 的真源：**现存全部清单**引用的 rel 集合。孤儿副本（清单写失败的那批）
    // 不在任何清单里，这是它们唯一可判定的「无人认领」口径。
    let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in &manifests {
        for rel in manifest_rels(&root.join(m)) {
            referenced.insert(rel.to_lowercase());
        }
    }
    // 裁剪失败计数（§4.5②）：回收站满/禁用时旧实现 `let _ =` 静默停摆，
    // BACKUP_KEEP 上限形同虚设且无人知晓——现在逐条 warn + 汇总。
    let mut prune_failed = 0usize;
    let root_canon = std::fs::canonicalize(root).ok();
    if manifests.len() > keep {
        manifests.sort(); // 时间戳升序：前面是最老的批次
        // 幸存者 = **最新的 keep 份** ⇒ 切点必须按长度算。写成 `split_off(keep)` 会留下
        // `len - keep` 份（3 份 keep=2 时只活 1 份），实测把我自己的用例当场判红才暴露。
        let survivors = manifests.split_off(manifests.len() - keep);
        // **幸存清单仍引用的 rel 一律不删**。批次段是 N10 才加进 `rel` 的，改名之前写的
        // 存量批次里 `rel` 可以跨批次相同 —— 那份物理文件同时属于两份清单，跟着老批次删掉
        // 就等于把幸存批次的还原凭据一起毁掉（症状与 N10 同源：还原静默拿回别的时间点的内容
        // 或干脆"备份文件已不存在"）。
        let mut kept_rels: std::collections::HashSet<String> = std::collections::HashSet::new();
        for m in &survivors {
            for rel in manifest_rels(&root.join(m)) {
                kept_rels.insert(rel.to_lowercase());
            }
        }
        for oldest in &manifests {
            let mpath = root.join(oldest);
            for rel in manifest_rels(&mpath) {
                // 与还原通道同一道准入：不含 .. / 不是绝对路径 / 不带盘符
                if rel.is_empty()
                    || rel.contains("..")
                    || rel.starts_with('\\')
                    || rel.starts_with('/')
                    || rel.contains(':')
                {
                    continue;
                }
                if kept_rels.contains(&rel.to_lowercase()) {
                    continue; // 还有幸存批次指着它，只删清单不删字节
                }
                // v2-L4P-33（C-5）：引擎级裁剪出口回收站优先；先拒 reparse，链接件不投
                let victim = root.join(&rel);
                let reparse = std::fs::symlink_metadata(&victim)
                    .map(|m| crate::engine::protect::is_reparse(&m))
                    .unwrap_or(true);
                if reparse {
                    continue;
                }
                // §4.5①：junction 段可把词法合法的 rel 重定向到备份根之外——
                // 真实落点必须在根内，且解析不出来就拒（包含性核验先行，见函数注释）
                if let Some(rc) = &root_canon {
                    if !backup_victim_within_root(rc, &victim) {
                        crate::engine::log::write_log(
                            "warn",
                            &format!("备份裁剪：副本 {rel} 的真实落点不在备份根内（根内含重解析段？），已拒删"),
                        );
                        continue;
                    }
                }
                if let Err(e) = trim_finder::scan::recycle::send_to_trash_os(victim.as_os_str()) {
                    prune_failed += 1;
                    crate::engine::log::write_log(
                        "warn",
                        &format!("备份裁剪：副本 {rel} 移入回收站失败: {e}"),
                    );
                }
            }
            let reparse_m = std::fs::symlink_metadata(&mpath)
                .map(|m| crate::engine::protect::is_reparse(&m))
                .unwrap_or(true);
            if !reparse_m {
                if let Err(e) = trim_finder::scan::recycle::send_to_trash_os(mpath.as_os_str()) {
                    prune_failed += 1;
                    crate::engine::log::write_log(
                        "warn",
                        &format!("备份裁剪：清单 {oldest} 移入回收站失败: {e}"),
                    );
                }
            }
        }
    }
    if prune_failed > 0 {
        crate::engine::log::write_log(
            "warn",
            &format!(
                "备份裁剪有 {prune_failed} 个对象移入回收站失败（回收站满/禁用？）， \
                 保留上限本轮超限；将在下次清理时重试裁剪"
            ),
        );
    }
    // §4.5③：孤儿副本回收——清单写失败时那批副本没有清单指向，按旧实现永不回收。
    // 判定口径 = 不被任何现存清单引用 + 已过冷静期 + 非 reparse。这里也是「自有
    // 数据根内的删除出口」：root 是 paths::backup_write_dir 自有备份根，protect
    // 清单整含 app_data_dir 对自有目录恒拒、无判定意义（同 realtime_report_delete 豁免理由）。
    let now = crate::engine::now_ms();
    if let Ok(rd) = std::fs::read_dir(root) {
        let mut orphan_count = 0usize;
        for ent in rd.flatten() {
            let rule_dir = ent.path();
            if !rule_dir.is_dir() {
                continue;
            }
            let Ok(files) = std::fs::read_dir(&rule_dir) else { continue };
            for f in files.flatten() {
                let fp = f.path();
                if !fp.is_file() {
                    continue; // 副本形状是 `<规则id>\` 下的平面文件，子目录非预期形态不动
                }
                let Some(rel) = fp
                    .strip_prefix(root)
                    .ok()
                    .map(|p| p.to_string_lossy().to_lowercase())
                else {
                    continue;
                };
                if referenced.contains(&rel) {
                    continue;
                }
                let Ok(md) = std::fs::symlink_metadata(&fp) else { continue };
                if crate::engine::protect::is_reparse(&md) {
                    continue;
                }
                let age_ok = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| (now - d.as_millis() as i64) >= min_orphan_age_ms)
                    .unwrap_or(false);
                if !age_ok {
                    continue; // 冷静期内可能是「清单还没落盘」的在途副本
                }
                if let Err(e) = trim_finder::scan::recycle::send_to_trash_os(fp.as_os_str()) {
                    crate::engine::log::write_log(
                        "warn",
                        &format!("孤儿备份副本回收失败（{rel}）: {e}"),
                    );
                    continue;
                }
                orphan_count += 1;
            }
        }
        if orphan_count > 0 {
            crate::engine::log::write_log(
                "warn",
                &format!("回收了 {orphan_count} 个孤儿备份副本（其清单曾写入失败，无还原依据）"),
            );
        }
    }
    // 空规则目录回收（副本按 `<规则id>\` 分目录，删空了才收，非目录自然跳过）
    if let Ok(rd) = std::fs::read_dir(root) {
        for ent in rd.flatten() {
            let p = ent.path();
            let Ok(mut sub) = std::fs::read_dir(&p) else { continue };
            if sub.next().is_none() {
                let _ = std::fs::remove_dir(&p);
            }
        }
    }
}

/// 读一份文件备份清单里所有 `entries[].file`（相对名）。读不动就当没有条目。
fn manifest_rels(manifest: &std::path::Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(manifest) else { return Vec::new() };
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| {
            v.get("entries")
                .and_then(|e| e.as_array())
                .map(|a| a.iter().filter_map(|x| x.get("file").and_then(|s| s.as_str()).map(String::from)).collect())
        })
        .unwrap_or_default()
}

/// 单条规则的执行结果计数（判定 status/message 的全部输入）。
///
/// 抽成结构体 + 纯函数 `classify_outcome` 的理由：这段判定原先内联在
/// `cleanup_execute` 的循环里，而它**无法在不碰全局 `protect::ROOTS` 的前提下
/// 被单测**（`is_path_protected` 读全局清单；`configure()` 一写就污染同进程里
/// 并发跑的保护断言，正是 protect.rs M13 注释里记的那个坑）。
/// 纯函数化之后，「受保护拒绝不许混进被占用」这条就能被直接钉住。
#[derive(Debug, Clone)]
struct OutcomeCounters {
    deleted: i64,
    /// 文件被占用（真·用户侧问题：关掉占用程序后可重试）
    failed: i64,
    /// 被保护清单拒绝（安全闸门正常工作；关任何程序都不会变可删）
    protected_blocked: i64,
    too_new: i64,
    excluded: i64,
    unresolved: Vec<String>,
    to_recycle: bool,
}

/// 由计数与三段后缀推出 `(status, message)`。
///
/// 判据的历史包袱都在这里，两条不可省：
/// - **P0 fail-closed（2026-09-27）**：存在未解析变量且一无所删时不得报「成功 0 删」——
///   那正是「扫描命中、执行 0 删」静默失效的形态。
/// - **P0-M5**：`too_new` 同理，「全都是太新文件」必须显式说成 skip。
/// - **§4.1（2026-10-04）**：`protected_blocked` 必须与 `failed` 分开。
///   两者混在一起会让这次拦截在界面上长得跟「文件被占用」一模一样，而渲染层的
///   toast（cleanup.js:1274）会据此提示「可关闭相关程序或重启后再试」——真因是
///   这些目标本来就在保护清单里，那个建议永远无效。
fn classify_outcome(
    c: &OutcomeCounters,
    too_new_suffix: &str,
    excl_suffix: &str,
    backup_suffix: &str,
) -> (&'static str, String) {
    if !c.unresolved.is_empty() && c.deleted == 0 && c.failed == 0 {
        return ("skip", format!("路径变量 {} 未解析，未执行清理", c.unresolved.join("、")));
    }
    let nothing_done = c.deleted == 0 && c.failed == 0;
    if nothing_done && c.protected_blocked > 0 {
        return (
            "skip",
            format!("{} 个文件位于受保护路径，已按保护清单拒绝删除", c.protected_blocked),
        );
    }
    if nothing_done && c.too_new > 0 {
        return ("skip", format!("{} 个文件修改时间不足 minAge（时效护栏），未执行清理", c.too_new));
    }
    if nothing_done && c.excluded > 0 {
        return ("skip", format!("{} 个文件在排除名单中，未执行清理", c.excluded));
    }
    let mut suffix = too_new_suffix.to_string();
    if !excl_suffix.is_empty() {
        suffix.push_str(excl_suffix);
    }
    if !backup_suffix.is_empty() {
        suffix.push_str(backup_suffix);
    }
    if !c.unresolved.is_empty() {
        suffix = format!("；{} 未解析已跳过{}", c.unresolved.join("、"), suffix);
    }
    if c.protected_blocked > 0 {
        // 部分被拒时要单独说一句，且**不许混进「被占用」那个数**。
        suffix = format!("{suffix}；{} 个位于受保护路径已拒绝", c.protected_blocked);
    }
    if c.to_recycle {
        ("recycle", format!("待移入回收站（{} 个文件）{suffix}", c.deleted))
    } else if c.failed == 0 {
        ("ok", format!("已清理 {} 个文件{suffix}", c.deleted))
    } else if c.deleted > 0 {
        ("partial", format!("已清理 {} 个文件，{} 个被占用{suffix}", c.deleted, c.failed))
    } else {
        ("fail", format!("已清理 0 个文件，{} 个被占用{suffix}", c.failed))
    }
}

/// 清理执行（对应 cleanup_execute.ps1，S3）
///
/// 三类目标模型全部原生化（v0.1.6 真机修复）：fileKeys（含段级 glob 展开）、
/// regKeys（先备份后删，fail-closed）、special=dism。to_recycle=true 时文件只
/// 枚举不删除，返回 recycle_entries 由主进程移入回收站；注册表/DISM 不进回收站。
pub fn cleanup_execute(
    items: &[Value],
    rules: &Value,
    to_recycle: bool,
    auto_rebuild: bool,
) -> Result<CleanupExecuteResult, String> {
    let mut details = Vec::new();
    let mut total_freed = 0i64;
    let mut total_files = 0i64;
    let mut recycle_entries = Vec::new();

    // C-4（2026-09-28 拍板）：永久删除链删前备份。批次目录懒创建，仅 to_recycle=false
    // 时生效（回收站模式可还原，无需副本）。上限护栏：单文件 64MB / 批次 256MB，
    // 超限的文件照常删除但**不留副本**（记账进 message——备份是语义增强不是删除前提，
    // 复制失败/超限都不阻塞删除，否则清理主链被备份故障绑架）。
    const FILE_BACKUP_MAX_FILE: u64 = 64 * 1024 * 1024;
    const FILE_BACKUP_MAX_BATCH: u64 = 256 * 1024 * 1024;
    let files_backup_root = crate::engine::paths::backup_write_dir("cleanup-files-backup");
    let backup_batch_ts = crate::engine::now_ms();
    let mut backup_entries: Vec<Value> = Vec::new();
    let mut backup_total: u64 = 0;

    for item in items {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let rule = find_rule_by_id(rules, id);
        let Some(rule) = rule else {
            details.push(json!({"id": id, "name": name, "status": "skip", "freed": 0, "message": "规则不存在", "fileCount": 0}));
            continue;
        };
        // 条目级版本戳随结果一起回传（V2 P2-A1）：用户报"上次清了这次没清"时，
        // 批次报告里能直接指认这一条当时是哪一版规则判的，不用去比对整库 rulesVersion
        let rule_ver = rule.get("ver").and_then(Value::as_f64).unwrap_or(0.0);

        // 注册表型：先逐键 reg.exe export 备份（任一失败整条不删，对齐 PS fail-closed
        // 语义——宁可少删，不可无备份地删），再按 value 语义删除（无 value=删整树）。
        // 注册表不进回收站，to_recycle 两种模式同径（对齐 PS）。
        if let Some(reg_keys) = rule.get("regKeys").and_then(|v| v.as_array()) {
            if !reg_keys.is_empty() {
                let backup_dir = crate::engine::paths::backup_write_dir("cleanup-reg-backup");
                let _ = std::fs::create_dir_all(&backup_dir);
                // 解析 + 存在性过滤（与 PS Measure-RegRule 同口径）
                let mut parsed: Vec<(HKEY, String, Option<String>)> = Vec::new();
                // P0 fail-closed：变量未解析的键不能混进「注册表项不存在」的 benign 结论
                let mut reg_unresolved: Vec<String> = Vec::new();
                // F-2（2026-09-28 拍板）：规则级 excludePaths 对注册表目标的排除
                // （整键 `HIVE\KEY` / 具名值 `HIVE\KEY::VALUE`，与扫描侧 measure_reg_rule 同一判定）
                let reg_excludes: Vec<String> = rule
                    .get("excludePaths")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();
                let mut reg_excluded = 0i64;
                // v5 C-1：删树 / 通配清值目标的禁删面拦截记录（判据见下面循环里的同名注释）
                let mut reg_blocked: Vec<String> = Vec::new();
                for rk in reg_keys {
                    let path = rk.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    if path.is_empty() { continue; }
                    let expanded = expand_env(path);
                    if let Some(tok) = first_unexpanded_token(&expanded) {
                        reg_unresolved.push(format!("%{tok}%"));
                        crate::engine::log::write_log(
                            "warn",
                            &format!(
                                "cleanup_execute 规则 {id}：注册表路径变量 %{tok}% 未解析，该键已跳过（原始模板 {path}）"
                            ),
                        );
                        continue;
                    }
                    let value = rk.get("value").and_then(|v| v.as_str()).map(|s| s.to_string());
                    // v5 C-1 第二道闸：删树 / 通配清值过禁删面，与装载侧**同一个函数同一判据**
                    // （见 rules.rs 的同名注释）。命中即判 fail 不判 ok —— 能走到这里说明规则库
                    // 绕过了装载校验（内置兜底副本 / 手工落盘），静默跳过会把事故做成"清理正常"。
                    let wipe_form = match value.as_deref() {
                        None => Some(false),
                        Some("*") => Some(true),
                        Some(_) => None,
                    };
                    if let Some(wipe) = wipe_form {
                        if let Some(reason) =
                            crate::engine::protect::cleanup_reg_wipe_block_reason(&expanded, wipe)
                        {
                            reg_blocked.push(format!("{expanded} —— {reason}"));
                            crate::engine::log::write_log(
                                "error",
                                &format!(
                                    "cleanup_execute 规则 {id}：注册表目标命中禁删面，已拒绝执行: {reason}"
                                ),
                            );
                            continue;
                        }
                    }
                    if trim_finder::cleanup_scan::reg_target_excluded(&reg_excludes, &expanded, value.as_deref()) {
                        reg_excluded += 1;
                        continue;
                    }
                    let Some((hive, rest)) = parse_reg_path(&expanded) else { continue; };
                    if !reg_key_exists(hive, &rest) { continue; }
                    parsed.push((hive, rest, value));
                }
                if parsed.is_empty() {
                    // 判据优先级：禁删面拦截（真异常，判 fail）> 变量未解析（skip）>
                    // 规则级排除 / 键不存在（都是 benign，判 ok）
                    let (status, message) = if !reg_blocked.is_empty() {
                        (
                            "fail",
                            format!("删树目标命中注册表禁删面，已拒绝执行：{}", reg_blocked.join("；")),
                        )
                    } else if !reg_unresolved.is_empty() {
                        (
                            "skip",
                            format!("路径变量 {} 未解析，未执行注册表清理", reg_unresolved.join("、")),
                        )
                    } else if reg_excluded > 0 {
                        (
                            "ok",
                            format!("注册表目标全部命中规则级排除（{reg_excluded} 项），无需清理"),
                        )
                    } else {
                        ("ok", "注册表项不存在，无需清理".to_string())
                    };
                    details.push(json!({"id": id, "name": name, "status": status, "freed": 0, "message": message, "fileCount": 0, "ruleVer": rule_ver}));
                    continue;
                }
                // 逐键 export 备份
                let stamp = crate::engine::now_ms();
                let mut backup_failed = false;
                for (i, (hive, rest, _)) in parsed.iter().enumerate() {
                    let file = backup_dir.join(format!("{stamp}_reg_{id}_{}.reg", i + 1));
                    // 备份路径由 app_data_dir + ASCII 段拼成，非 UTF-8 场景按 fail-closed 处理
                    let Some(file_str) = file.to_str() else { backup_failed = true; break; };
                    let hive_short = if *hive == HKEY_LOCAL_MACHINE { "HKLM" }
                        else if *hive == HKEY_CURRENT_USER { "HKCU" }
                        else if *hive == windows::Win32::System::Registry::HKEY_CLASSES_ROOT { "HKCR" }
                        else if *hive == windows::Win32::System::Registry::HKEY_USERS { "HKU" }
                        else { "HKCC" };
                    let export_path = format!("{hive_short}\\{rest}");
                    // v2-L4P-29（B-7）：备份类子进程统一走带超时入口
                    match crate::engine::systembin::quiet_cmd_timeout(
                        system_tool("reg.exe"),
                        &["export", &export_path, file_str, "/y"],
                        crate::engine::systembin::REG_EXPORT_TIMEOUT,
                    ) {
                        Ok(o) if o.status.success() && file.exists() => {
                            // N9：清理域此前**根本不产封条**，于是还原链那道"封条核对"对本域
                            // 永远只能走 missing 分支（等于没闸）。与卸载域同口径落一份，
                            // 半截写入与手工误改才有可发现性。写封条失败不阻断删除（增强而非前提）。
                            crate::engine::reg_backup::write_reg_backup_seal(&file, &export_path);
                        }
                        _ => { backup_failed = true; break; }
                    }
                }
                if backup_failed {
                    details.push(json!({"id": id, "name": name, "status": "error", "freed": 0, "message": "注册表备份失败，未执行删除", "fileCount": 0, "ruleVer": rule_ver}));
                    continue;
                }
                // N3：备份写完后裁一次保留上限（只裁新根，见 paths::prune_backups）
                crate::engine::paths::prune_backups(
                    &backup_dir,
                    crate::engine::paths::BACKUP_KEEP,
                );
                let mut removed = 0i64;
                let mut reg_failed = 0i64;
                for (hive, rest, value) in &parsed {
                    match value.as_deref() {
                        // F-1（2026-09-28 用户拍板）：value="*" = 清空该键全部值
                        // （shellMuiCache 等「清值不删键」规则的既定语义）。此前把 "*"
                        // 字面量喂给 RegDeleteValueW（删名为 * 的值、不存在按幂等报成功），
                        // 规则实际静默空转；现展开为逐值删除。整键 export 备份已在前一步
                        // 覆盖，删除顺序无保护语义差异。空键（无值）视为成功：目标状态已达成。
                        // 口径注：扫描侧对 value="*" 只计 1 项，执行侧按实际值数记账，
                        // 「清理数 ≥ 扫描数」属本规则的既定形态。
                        Some("*") => {
                            for name in reg_enum_value_names_pub(*hive, rest) {
                                if reg_restore_delete(*hive, rest, &name) {
                                    removed += 1;
                                } else {
                                    reg_failed += 1;
                                }
                            }
                        }
                        Some(v) => {
                            if reg_restore_delete(*hive, rest, v) {
                                removed += 1;
                            } else {
                                reg_failed += 1;
                            }
                        }
                        None => {
                            // v5 C-1：删树出口的第二道闸在解析阶段（`reg_target_block_reason`），
                            // 能进到这里说明目标已过禁删面；此处不再重复判定，避免两处口径漂移。
                            if reg_key_remove(*hive, rest, true) {
                                removed += 1;
                            } else {
                                reg_failed += 1;
                            }
                        }
                    }
                }
                total_files += removed;
                // 命中禁删面 = 规则缺陷，即使同规则别的键清成功也一律判 fail（v5 C-3 起
                // "fail" 计入 failed，界面不再给成功提示）。完整原因走上面的 log::error。
                let status = if !reg_blocked.is_empty() {
                    "fail"
                } else if reg_failed == 0 {
                    "ok"
                } else if removed > 0 {
                    "partial"
                } else {
                    "fail"
                };
                let excl_note = if reg_excluded > 0 {
                    format!("；{} 个注册表目标命中规则级排除已跳过", reg_excluded)
                } else {
                    String::new()
                };
                let block_note = if reg_blocked.is_empty() {
                    String::new()
                } else {
                    format!("；{} 个删树目标命中注册表禁删面被拒绝", reg_blocked.len())
                };
                let message = if reg_failed == 0 {
                    format!("已清理 {} 项注册表记录{excl_note}{block_note}", removed)
                } else {
                    format!("已清理 {} 项注册表记录，{} 项失败{excl_note}{block_note}", removed, reg_failed)
                };
                details.push(json!({
                    "id": id, "name": name, "status": status,
                    "freed": 0, "message": message, "fileCount": removed, "residual": reg_failed,
                    "ruleVer": rule_ver,
                }));
                continue;
            }
        }

        // special=dism：DISM /StartComponentCleanup /ResetBase（对齐 PS 执行语义；
        // 高危提示已在前端红色确认层，/ResetBase 后更新不可卸载）
        // 2026-10-04 审计 §4.4：必须带超时。/ResetBase 合法就要跑几十分钟，裸
        // .output() 等的是 stdout/stderr 管道关闭——DISM 前端进程把活交给 TiWorker
        // 等后代后若被占住管道，这里就永久挂住整条清理链（同文件 reg export 备份
        // 早在 v2-L4P-29 就为此走了 quiet_cmd_timeout，本处是漏改的同类）。
        // 到点 kill 的是 DISM 前端进程本身：CBS/TiWorker 的事务由组件栈自行回滚
        // 或续跑，中断是安全的，最坏结果是本条报失败、用户可重跑。
        if rule.get("special").and_then(|v| v.as_str()) == Some("dism") {
            let dism = crate::engine::systembin::quiet_cmd_timeout(
                system_tool("dism.exe"),
                &["/Online", "/Cleanup-Image", "/StartComponentCleanup", "/ResetBase"],
                DISM_CLEANUP_TIMEOUT,
            );
            let (status, message) = match &dism {
                Ok(o) if o.status.success() => (
                    "ok",
                    "DISM 组件存储清理完成（/ResetBase 已执行，更新将不可卸载）".to_string(),
                ),
                Ok(o) => {
                    // 超时收口时 quiet_cmd_timeout 把原因写进 stderr，必须带给用户，
                    // 否则「失败但不知道是超时还是 DISM 自己报错」又是一层雾
                    let note = String::from_utf8_lossy(&o.stderr);
                    let note = note.trim();
                    (
                        "fail",
                        if note.is_empty() {
                            format!("DISM 清理失败，退出码 {}", o.status.code().unwrap_or(-1))
                        } else {
                            format!("DISM 清理失败，退出码 {}：{note}", o.status.code().unwrap_or(-1))
                        },
                    )
                }
                Err(e) => ("fail", format!("DISM 执行失败: {e}")),
            };
            details.push(json!({
                "id": id, "name": name, "status": status,
                "freed": 0, "message": message, "fileCount": 0, "ruleVer": rule_ver,
            }));
            continue;
        }

        // 收集要删除的文件
        let mut files: Vec<(String, u64)> = Vec::new();
        // P0 fail-closed：本条规则里展开失败的 %TOKEN%（变量名）清单
        let mut unresolved: Vec<String> = Vec::new();
        // P0-M5 时效护栏：minAge 规则在执行侧**重新逐文件判定**修改时间，与扫描侧
        // 同口径（同一谓词）。扫描与执行之间有时间差，太新文件可能在两次枚举之间
        // 刚被应用写入——执行侧必须自己拒绝，不能只信扫描结果。
        let cutoff = rule_min_age_secs_json(&rule).map(trim_finder::cleanup_scan::min_age_cutoff);
        let mut too_new = 0i64;
        // 规则级 excludePaths（C-2，2026-09-28 开门）：与扫描侧同一判定/归一口径
        //（trim_finder 同源），执行侧再拦一次——规则可能换版本，执行时必须以当下为准。
        // U1-b（2026-10-01）：全局排除名单已整链下线，这里不再有任何全局种子。
        let mut excl_dirs: Vec<String> = Vec::new();
        let mut excl_files: Vec<String> = Vec::new();
        if let Some(arr) = rule.get("excludePaths").and_then(|v| v.as_array()) {
            for ep0 in arr.iter().filter_map(|v| v.as_str()) {
                let ep = trim_finder::cleanup_scan::expand_env_path(ep0)
                    .trim_end_matches('\\')
                    .to_lowercase();
                if ep.is_empty() || ep.starts_with('#') {
                    continue;
                }
                // 分类走 trim_finder 同一个函数（§4.9）：按磁盘实况分目录/文件，
                // 禁按扩展名推断——带点目录会误 routed 进文件表、排除静默失效
                trim_finder::cleanup_scan::classify_exclude_entry(&ep, &mut excl_dirs, &mut excl_files);
            }
        }
        let excluded;
        if let Some(file_keys) = rule.get("fileKeys").and_then(|v| v.as_array()) {
            if !file_keys.is_empty() {
                for fk in file_keys {
                    let path = fk.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    if path.is_empty() { continue; }
                    let pattern = fk.get("pattern").and_then(|v| v.as_str()).unwrap_or("*");
                    let recurse = fk.get("recurse").and_then(|v| v.as_bool()).unwrap_or(true);
                    let expanded = expand_env(path);
                    // P0 fail-closed（规则库最终优化方案 2026-09-27）：变量未解析的路径
                    // 不参与枚举，也不能伪装成「成功 0 删」——记账后在结果里显式报 skip。
                    if let Some(tok) = first_unexpanded_token(&expanded) {
                        unresolved.push(format!("%{tok}%"));
                        crate::engine::log::write_log(
                            "warn",
                            &format!(
                                "cleanup_execute 规则 {id}：路径变量 %{tok}% 未解析，fileKey 已跳过（原始模板 {path}）"
                            ),
                        );
                        continue;
                    }
                    // 段级 glob 展开（v0.1.6 真机修复：旧实现遇 `*` 直接 Err 且 PS 回退已删）；
                    // 展开后的每个实际目录仍过 reparse 判拒（双保险）
                    for base in expand_glob_dirs(&expanded) {
                        // 单文件目标要**先**分派、再判 reparse（2026-10-04 审计 §4.2）。
                        //
                        // 原顺序是「先 cleanup_root_ok（要求 is_dir）→ 再判 is_file」，
                        // 于是文件目标永远在第一道就 `continue` 了，下面那个 is_file
                        // 分支是**死代码**。后果不只是「单文件规则删不掉」：
                        // collect_files 一个都没收到，而失败计数也没加，条目落到
                        // 「deleted=0 && failed=0 && 无 too_new/excluded」的出口，
                        // 报出「已清理 0 个文件」+ success:true ⇒ UI 弹「清理完成！释放 0 B」。
                        // 那正是本文件 P0 纪律（见 classify_outcome 注释）禁止的形态。
                        //
                        // 为什么扫描侧也拦得住单文件、这里却不行：`cleanup_root_ok`
                        // 是**执行侧自己的**闸门，而 fileKey 直指单文件时
                        // `expand_glob_dirs` 的非通配快路径只回目录（is_container），
                        // 两处都不覆盖「这个 fileKey 指向一个文件」这个形态。
                        match std::fs::symlink_metadata(&base) {
                            Ok(md) if md.is_file() => {
                                if crate::engine::protect::is_reparse(&md) {
                                    continue; // 单文件也不接受重解析点（与 collect_files 同口径）
                                }
                                // 时效护栏与目录分支同款：太新不删、且**如实计数**
                                if cutoff
                                    .map(|c| !trim_finder::cleanup_scan::modified_before(&md, c))
                                    .unwrap_or(false)
                                {
                                    too_new += 1;
                                    continue;
                                }
                                files.push((base, md.len()));
                                continue;
                            }
                            Ok(md) if md.is_dir() => {
                                if crate::engine::protect::is_reparse(&md) {
                                    continue;
                                }
                                collect_files(&base, pattern, recurse, cutoff, &mut files, &mut too_new);
                            }
                            // 既非目录也非文件（已消失 / 不可访问 / 多形态设备）：
                            // 跳过。不记 failed —— 「读不到」与「被占用」不是一回事，
                            // 混进去又是一次理由错报（与 §4.1 同族）。
                            _ => {}
                        }
                    }
                }
            }
        } else {
            // 目录型：用 item 的 path 或 rule.pathPs
            let target = item.get("path").and_then(|v| v.as_str())
                .or_else(|| rule.get("pathPs").and_then(|v| v.as_str()))
                .unwrap_or("");
            if !target.is_empty() && cleanup_root_ok(target) {
                collect_files(target, "*", true, cutoff, &mut files, &mut too_new);
            } else if !target.is_empty() {
                // 「根不可用」必须留一个可见的痕迹（2026-10-04 审计 §4.2）。
                //
                // 缺口背景：根判不过时 `files` 空、`failed` 也没加，条目会落到
                // classify_outcome 的最后一个出口，报「已清理 0 个文件」+ success:true
                // —— 而 UI 会弹「清理完成！释放 0 B」。用户看到的是「我明明选了它、
                // 它也确实在列表里」，却被告知一切正常。
                //
                // 归到 unresolved 而不是新造一个计数器：语义就是「这条规则的目标
                // 此刻不可用/不存在」，与「变量未解析」同族（都是「没找到可删的东西」）。
                // `unresolved` 非空且 deleted==0 时 classify_outcome 会判 skip 并
                // 把原因带给前端，这正是我们要的出口。
                let why = if std::fs::symlink_metadata(target).is_ok() {
                    "目标是重解析点（不深入以避免重复枚举）"
                } else {
                    "目标不存在或不可访问"
                };
                unresolved.push(format!("{target}（{why}）"));
                crate::engine::log::write_log(
                    "warn",
                    &format!("规则 {id}：根目标不可用，已跳过 —— {target}（{why}）"),
                );
            }
        }

        // 去重
        files.sort_by(|a, b| a.0.cmp(&b.0));
        files.dedup_by(|a, b| a.0 == b.0);

        // 全局排除名单 + 规则级 excludePaths 过滤：显式记账，不混进「被占用」或「成功 0 删」
        let before_excl = files.len();
        files.retain(|(p, _)| {
            !trim_finder::cleanup_scan::path_excluded(&excl_dirs, &excl_files, &p.to_lowercase())
        });
        excluded = (before_excl - files.len()) as i64;

let mut freed = 0i64;
    let mut deleted = 0i64;
    let mut failed = 0i64;
    // 受保护路径的拒绝**单独计数**（2026-10-04 审计 §4.1）。
    //
    // 原先它与「文件被占用」共用 `failed`，后果全部是用户可见的错误信息：
    // 消息变成「N 个被占用」（**理由是假的**）、`residual` 触发渲染层的
    // 「关闭相关程序后重试」提示（用户会去关程序，而真因是保护清单）、且**一行日志都不打**。
    // 对照同文件里另外两处同类拒绝都记日志：注册表禁删面 :401（log::error + 独立
    // fail 状态）、回收站支 scan_execute.rs:384（log::warn）——唯独永久删这条不记。
    //
    // 为什么要紧：这是全仓唯一执行永久删除的链，而「被保护路径拒绝」恰恰是
    // AGENTS §3 明确要求**留痕**的那一类事件。把它混进「被占用」等于把安全闸门的
    // 一次正常拦截伪装成用户的操作问题。
    let mut protected_blocked = 0i64;
    let mut protected_samples: Vec<String> = Vec::new();
        let mut backup_skipped = 0usize;

        for (path, size) in &files {
            if to_recycle {
                // 回收站模式：只枚举，由主进程移入回收站
                recycle_entries.push(json!({"id": id, "path": path, "size": size, "isDir": false}));
                freed += *size as i64;
                deleted += 1;
            } else if crate::engine::protect::is_path_protected(path) {
                // 审查 v2-F3：常规清理豁免的是「回收站优先」，**没有**豁免保护路径判定。
                // 这是全仓唯一执行永久删除的链，保护清单在这里不能缺席 —— 同模块
                // `retry_failed_delete`（cleanup.rs:1170）与回收站支（:942）都有这道闸门。
                //
                // 单独计数而非并入 `failed`（审计 §4.1）：并进去会让这次拦截在界面上
                // 长得跟「文件被占用」一模一样，用户去关程序而真因是保护清单。
                protected_blocked += 1;
                // 前若干条逐条留痕，之后只留汇总：一条规则命中上万文件时
                // 逐条打会把真留痕淹掉（与扫描侧「首次翻转才留痕」同一取舍）。
                if protected_samples.len() < 5 {
                    protected_samples.push(path.clone());
                }
            } else {
                // C-4：删前备份（只对将真正删除的文件；复制失败不阻塞删除）
                if *size <= FILE_BACKUP_MAX_FILE
                    && backup_total + *size <= FILE_BACKUP_MAX_BATCH
                {
                    let seq = deleted as u32 + backup_skipped as u32 + failed as u32;
                    let fname = std::path::Path::new(path)
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| seq.to_string());
                    // rel 必须同时带**批次段**和**序号段**（N10），见 `backup_rel_name`
                    let rel = backup_rel_name(id, backup_batch_ts, seq, &fname);
                    let dst = files_backup_root.join(&rel);
                    if std::fs::create_dir_all(dst.parent().unwrap_or(&files_backup_root)).is_ok()
                        && std::fs::copy(path, &dst).map(|n| n == *size).unwrap_or(false)
                    {
                        backup_total += size;
                        backup_entries.push(json!({
                            "file": rel, "path": path.clone(), "size": size, "rule": id,
                        }));
                    } else {
                        let _ = std::fs::remove_file(&dst);
                        backup_skipped += 1;
                    }
                } else {
                    backup_skipped += 1;
                }
                // 永久删除
                match std::fs::remove_file(path) {
                    Ok(()) => {
                        freed += *size as i64;
                        deleted += 1;
                    }
                    Err(_) => {
                        failed += 1;
                    }
                }
            }
        }

        total_freed += freed;
        total_files += deleted;
        let outcome = OutcomeCounters {
            deleted,
            failed,
            protected_blocked,
            too_new,
            excluded,
            unresolved: unresolved.clone(),
            to_recycle,
        };

        // P0 fail-closed（规则库最终优化方案 2026-09-27）：存在未解析变量且一无所删时，
        // 不得报「已清理 0 个文件、状态成功」——这正是「扫描命中、执行 0 删」静默失效的
        // 结果形态，必须显式降为 skip 并把原因带给前端。部分成功时也要在 message 里留痕。
        // P0-M5：too_new 同理——「全都是太新文件」必须显式说成 skip，不许伪装成成功 0 删。
        let too_new_suffix = if too_new > 0 {
            format!("；{} 个文件修改时间不足 minAge 已跳过", too_new)
        } else {
            String::new()
        };
        let excl_suffix = if excluded > 0 {
            format!("；{} 个文件在排除名单中已跳过", excluded)
        } else {
            String::new()
        };
        let backup_suffix = if backup_skipped > 0 && !to_recycle {
            format!("；{} 个文件超备份上限未留副本", backup_skipped)
        } else {
            String::new()
        };
        let (status, message) = classify_outcome(
            &outcome,
            &too_new_suffix,
            &excl_suffix,
            &backup_suffix,
        );

        // 受保护路径的拦截必须留痕（审计 §4.1）。这是永久删除链的安全闸门在动作，
        // 不是用户的操作问题，日志里要与「被占用」区分得开。
        if protected_blocked > 0 {
            crate::engine::log::write_log(
                "warn",
                &format!(
                    "规则 {id}：{protected_blocked} 个目标位于受保护路径，已拒绝删除。样本：{}",
                    protected_samples.join("；")
                ),
            );
        }

        details.push(json!({
            "id": id, "name": name, "status": status,
            "freed": freed, "message": message, "fileCount": deleted, "residual": failed,
            // 受保护路径的拒绝**不进 residual**：residual 的语义是「文件被占用、
            // 清理后重试」，而这一类是「按保护清单拒绝」——混进去会让渲染层弹出
            // 「关闭相关程序后重试」的误导提示（审计 §4.1）。渲染层目前不消费这个
            // 字段，它先在数据层备着，等前端要单独呈现时不必再改引擎。
            "protectedBlocked": protected_blocked,
            "tooNew": too_new, "ruleVer": rule_ver,
        }));

        // auto_rebuild：重建目录
        if auto_rebuild && !to_recycle {
            if let Some(file_keys) = rule.get("fileKeys").and_then(|v| v.as_array()) {
                for fk in file_keys {
                    let path = fk.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let expanded = expand_env(path);
                    // P0 fail-closed：变量未解析时绝不 create_dir_all——否则会在进程
                    // 工作目录下造出形如 `%WINDIR%\...` 的字面量垃圾目录树
                    if first_unexpanded_token(&expanded).is_some() { continue; }
                    if !expanded.contains('*') && !expanded.is_empty() {
                        let _ = std::fs::create_dir_all(&expanded);
                    }
                }
            }
        }
    }

    // C-4：批次备份清单落盘（有副本才写；还原通道按清单逐条拷回）
    if !backup_entries.is_empty() {
        let manifest = json!({ "ts": backup_batch_ts, "entries": backup_entries });
        let mpath = files_backup_root.join(format!("manifest-{}.json", backup_batch_ts));
        if std::fs::create_dir_all(&files_backup_root).is_ok() {
            match serde_json::to_string_pretty(&manifest) {
                Ok(text) => {
                    // 审查 L-6：manifest 是该批还原的唯一依据，裸 std::fs::write 断电可留
                    // 半截 JSON，还原通道按清单失配。走 security 原子写（temp→fsync→rename）。
                    if let Err(e) = crate::security::atomic_write_file(&mpath, text.as_bytes()) {
                        // §4.5③：清单写失败 = 这批副本成为无人认领的孤儿（还原通道按清单
                        // 逐条拷回，没有清单就还原不了）。prune_file_backups 的孤儿回收会
                        // 按冷静期（24h）把这类副本清掉，这里把数量说清，别让「备份写了
                        // 多少」在日志里失明。
                        crate::engine::log::write_log(
                            "warn",
                            &format!(
                                "files 备份清单写入失败: {e}；本批 {} 个文件副本无还原依据，\
                                 24h 后由孤儿回收清理",
                                backup_entries.len()
                            ),
                        );
                    }
                }
                Err(_) => {
                    crate::engine::log::write_log(
                        "warn",
                        &format!(
                            "files 备份清单序列化失败；本批 {} 个文件副本无还原依据，\
                             24h 后由孤儿回收清理",
                            backup_entries.len()
                        ),
                    );
                }
            }
            // N3：副本按清单裁最老批次（副本目录是 `规则id\`，不能按批次时间戳找）
            prune_file_backups(&files_backup_root, crate::engine::paths::BACKUP_KEEP);
        }
    }

    Ok(CleanupExecuteResult { details, freed: total_freed, file_count: total_files, recycle_entries })
}

/// 时效护栏 minAge（P0-M5，竞品借鉴落地方案 §5）：解析规则的 minAgeHours/minAgeDays
/// 为秒数。与扫描侧（trim_finder::cleanup_scan::rule_min_age_secs）同口径：互斥由契约
/// 门禁 A9 钉死，双声明/非法值在这里按「无护栏」处理会静默放宽删除面——所以双声明时
/// 取**更严格**（更大）的那个，宁可少删。
fn rule_min_age_secs_json(rule: &Value) -> Option<u64> {
    let pos = |v: &Value| v.as_f64().filter(|n| *n > 0.0 && n.is_finite());
    let h = rule.get("minAgeHours").and_then(pos);
    let d = rule.get("minAgeDays").and_then(pos);
    let secs = match (h, d) {
        (Some(h), None) => h * 3600.0,
        (None, Some(d)) => d * 86400.0,
        (Some(h), Some(d)) => (h * 3600.0).max(d * 86400.0),
        (None, None) => return None,
    };
    Some(secs as u64)
}

fn find_rule_by_id(rules: &Value, id: &str) -> Option<Value> {
    let groups = rules.get("groups").and_then(|v| v.as_array())?;
    for g in groups {
        if let Some(subgroups) = g.get("subGroups").and_then(|v| v.as_array()) {
            for sg in subgroups {
                if let Some(items) = sg.get("items").and_then(|v| v.as_array()) {
                    for it in items {
                        if it.get("id").and_then(|v| v.as_str()) == Some(id) {
                            return Some(it.clone());
                        }
                    }
                }
            }
        }
        if let Some(items) = g.get("items").and_then(|v| v.as_array()) {
            for it in items {
                if it.get("id").and_then(|v| v.as_str()) == Some(id) {
                    return Some(it.clone());
                }
            }
        }
    }
    None
}

/// 清理根路径准入：必须是真实目录，且**不是** reparse（审查 v2-F3）
///
/// 判定必须在进 `collect_files` 之前做：后者对**子项**过滤 reparse（v2-L4P-11 起与
/// 根路径同口径、均为 0x400 属性位判定），根路径本身若被替换成指向他处的 junction，
/// `Path::is_dir()` 会跟随链接返回 true，于是链接目标整棵被枚举，并在永久删除分支下
/// 不可恢复地删掉。用 `protect::is_reparse` 的 0x400 属性位而非 `is_symlink()`：
/// 前者覆盖全部 reparse tag（云占位符 / NFS / WIM），严格更强。
fn cleanup_root_ok(dir: &str) -> bool {
    match std::fs::symlink_metadata(dir) {
        Ok(md) => md.is_dir() && !crate::engine::protect::is_reparse(&md),
        Err(_) => false,
    }
}

fn collect_files(
    dir: &str,
    pattern: &str,
    recurse: bool,
    cutoff: Option<std::time::SystemTime>,
    files: &mut Vec<(String, u64)>,
    too_new: &mut i64,
) {
    collect_files_at(dir, pattern, recurse, cutoff, files, too_new, 0)
}

fn collect_files_at(
    dir: &str,
    pattern: &str,
    recurse: bool,
    cutoff: Option<std::time::SystemTime>,
    files: &mut Vec<(String, u64)>,
    too_new: &mut i64,
    depth: usize,
) {
    if depth >= ENGINE_WALK_MAX_DEPTH { return; }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        // v2-L4P-11/C-1：子项判定从 is_symlink() 收紧为 protect::is_reparse（0x400
        // 属性位）。此处产物直接喂删除链，弱口径会把 OneDrive 云占位符 / NFS / WIM
        // 这类 reparse 目录当普通目录递归进去、在永久删除分支下不可恢复地删到另一块存储。
        if crate::engine::protect::is_reparse(&meta) { continue; }
        if meta.is_dir() {
            if recurse {
                collect_files_at(&path.to_string_lossy(), pattern, recurse, cutoff, files, too_new, depth + 1);
            }
        } else if meta.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !glob_match(pattern, &name) { continue; }
            // P0-M5 时效护栏：太新（mtime 不足 minAge 或读不到 mtime）不进删除清单
            if cutoff.map(|c| !trim_finder::cleanup_scan::modified_before(&meta, c)).unwrap_or(false) {
                *too_new += 1;
                continue;
            }
            files.push((path.to_string_lossy().to_string(), meta.len()));
        }
    }
}


// ==================== P0 规则库引擎契约测试（规则库最终优化方案 2026-09-27） ====================

#[cfg(test)]
mod cleanup_engine_contract_tests {
    use super::*;

    /// 执行侧展开必须与扫描侧同源且大小写不敏感：`%WINDIR%`（大写）在旧白名单
    /// 展开器下永远展不开（printSpoolCache 静默失效根因），统一实现后必须解析。
    #[test]
    fn expand_env_resolves_windir_case_insensitive() {
        let out = expand_env(r"%WINDIR%\System32\spool\PRINTERS");
        assert!(!out.contains('%'), "%WINDIR% 未展开: {out}");
        assert!(
            out.to_lowercase().ends_with(r"system32\spool\printers"),
            "展开结果异常: {out}"
        );
    }

    /// 方案 P0-2：内置规则可用的基础变量在展开器下必须可解析（有值时无残留）。
    /// TEMP/TMP/PROGRAMDATA/SystemDrive 是后续扩库的最小变量集。
    #[test]
    fn expand_env_covers_baseline_tokens() {
        for tok in ["TEMP", "TMP", "PROGRAMDATA", "SystemDrive", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "WINDIR"] {
            let out = expand_env(&format!(r"%{tok}%\probe"));
            // 变量在测试机上必然有值（Windows 基础环境）；即便被清空，残留也必须能被
            // first_unexpanded_token 显式识别，而不是静默当有效路径
            if out.contains('%') {
                assert!(
                    first_unexpanded_token(&out).is_some(),
                    "变量 {tok} 展开异常且未被发现: {out}"
                );
            }
        }
    }

    /// 残留检测：未解析 token 必须被识别，普通路径不得误报。
    #[test]
    fn first_unexpanded_token_detects_residual() {
        assert_eq!(
            first_unexpanded_token(r"C:\x\%FAKE_TOKEN%\y").as_deref(),
            Some("FAKE_TOKEN")
        );
        assert_eq!(first_unexpanded_token(r"C:\Windows\Temp"), None);
        assert_eq!(first_unexpanded_token(""), None);
        // 单个 % 不构成 token，不算残留
        assert_eq!(first_unexpanded_token(r"C:\100%done"), None);
    }

    /// v2-L4P-11（C-1）：执行侧遍历对 reparse 子项的判定必须用 0x400 属性位口径。
    /// junction 形态（is_symlink=false && is_dir=true 的前身是 MOUNT_POINT，is_symlink
    /// 在 Windows 上能认出 junction 但认不出云占位符；此处以 junction 做「链接不进
    /// 删除清单」的最小实证，语义与 protect::is_reparse 的强口径一致）。无建链权限的
    /// 环境跳过（与 E-11 同姿势：环境性跳过要显式留痕）。
    #[test]
    fn collect_files_skips_reparse_children() {
        let base = std::env::temp_dir().join(format!("trim-c1-junction-{}", std::process::id()));
        let target = base.join("real");
        let link = base.join("scan-root").join("linked");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&target).expect("建 real 目录");
        std::fs::create_dir_all(base.join("scan-root")).expect("建 scan-root 目录");
        std::fs::write(target.join("marker.txt"), b"x").expect("写标记文件");
        let linked = match std::os::windows::fs::symlink_dir(&target, &link) {
            Ok(()) => true,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&base);
                eprintln!("⚠ 跳过：本环境无建链权限（{e}）——reparse 子项用例需管理员或开发者模式");
                return;
            }
        };
        assert!(linked);
        let mut files = Vec::new();
        let mut too_new = 0i64;
        collect_files(
            &link.parent().unwrap().to_string_lossy(),
            "*.txt",
            true,
            None,
            &mut files,
            &mut too_new,
        );
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            !files.iter().any(|(p, _)| p.to_lowercase().contains("marker.txt")),
            "reparse 子目录内的文件不得进删除清单: {files:?}"
        );
    }

    /// v2-L4P-11（C-1）：执行侧遍历必须有深度上限（与扫描器 MAX_WALK_DEPTH=64 同口径）。
    /// 造一条 80 层目录链、底放标记文件，collect_files 不得抵达。
    #[test]
    fn collect_files_respects_depth_cap() {
        let base = std::env::temp_dir().join(format!("trim-c1-depth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let mut cur = base.clone();
        for i in 0..80 {
            cur = cur.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&cur).expect("建深目录链");
        std::fs::write(cur.join("deep-marker.txt"), b"x").expect("写深处标记");
        let mut files = Vec::new();
        let mut too_new = 0i64;
        collect_files(&base.to_string_lossy(), "*.txt", true, None, &mut files, &mut too_new);
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            !files.iter().any(|(p, _)| p.contains("deep-marker.txt")),
            "深度超过上限的文件不得进删除清单: {}",
            files.len()
        );
    }

    /// P0-M5 时效护栏：测试辅助——把文件 mtime 拨回 days 天前（SetFileTime，真实文件系统）。
    #[cfg(windows)]
    fn set_file_mtime_days_ago(p: &std::path::Path, days: i64) {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::{CloseHandle, FILETIME, GENERIC_WRITE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, SetFileTime, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_SHARE_MODE, OPEN_EXISTING,
        };
        use windows::core::PCWSTR;
        let wide: Vec<u16> = p.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let h = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_WRITE.0,
                FILE_SHARE_MODE(1 | 2), // READ | WRITE
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        }
        .expect("CreateFileW 失败");
        // FILETIME = 1601-01-01 起 100ns 计数；Unix 纪元偏移 11644473600s
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let old = ((now - days * 86400 + 11644473600) * 10_000_000) as u64;
        let ft = FILETIME {
            dwLowDateTime: (old & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (old >> 32) as u32,
        };
        // minAge 谓词按**修改时间**判定，创建/写入两个时间都要拨回
        unsafe { SetFileTime(h, Some(&ft), None, Some(&ft)) }.expect("SetFileTime 失败");
        unsafe { let _ = CloseHandle(h); }
    }

    /// P0-M5 时效护栏：执行侧必须**自己**按修改时间拒绝太新文件，不能只信扫描结果
    /// （扫描与执行之间有时间差，太新文件可能刚被应用写入）。用回收站模式
    /// （to_recycle=true，只枚举不删除）断言清单内容，测试零删除副作用。
    #[test]
    #[cfg(windows)]
    fn cleanup_execute_enforces_min_age() {
        let base = std::env::temp_dir().join(format!("trim-minage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("stale.txt"), b"old").unwrap();
        std::fs::write(base.join("fresh.lock"), b"new").unwrap();
        set_file_mtime_days_ago(&base.join("stale.txt"), 10);

        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"m5test","name":"M5测试",
            "fileKeys":[{"path": base.to_string_lossy(), "pattern":"*", "recurse":true}],
            "minAgeDays": 3
        }]}]});
        let items = vec![serde_json::json!({"id":"m5test","name":"M5测试","path": base.to_string_lossy()})];
        let res = cleanup_execute(&items, &rules, true, false).unwrap();
        let d = &res.details[0];
        assert_eq!(d["tooNew"], 1, "太新文件必须显式记账: {d}");
        let paths: Vec<&str> = res
            .recycle_entries
            .iter()
            .map(|e| e["path"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(paths.len(), 1, "只有 mtime 满 3 天的文件进清单: {paths:?}");
        assert!(paths[0].ends_with("stale.txt"), "清单内容异常: {paths:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 2026-10-04 审计 §4.1：受保护路径的拒绝必须**独立记账、独立措辞、不进 residual**。
    ///
    /// 修前它与「文件被占用」共用 `failed`，于是界面上是「N 个被占用」、
    /// `residual > 0` 触发渲染层 toast「可关闭相关程序或重启后再试」（cleanup.js:1274）
    /// ——而真因是这些目标本来就在保护清单里，**关任何程序都不会让它们变成可删**。
    ///
    /// 为什么测的是 `classify_outcome` 而不是 `cleanup_execute`：后者内部调
    /// `is_path_protected`，而那读全局 `protect::ROOTS`；用 `configure()` 注入就得
    /// 写全局状态，会污染同进程并发跑的保护断言（protect.rs M13 记的正是这个坑，
    /// 且本仓测试默认多线程）。纯函数化之后这条判据才可被直接钉住。
    #[test]
    fn 受保护路径的拒绝不混进被占用() {
        let base = |deleted, failed, protected| OutcomeCounters {
            deleted,
            failed,
            protected_blocked: protected,
            too_new: 0,
            excluded: 0,
            unresolved: Vec::new(),
            to_recycle: false,
        };

        // ① 全部候选都撞保护清单 ⇒ skip + 措辞指向保护清单
        let (st, msg) = classify_outcome(&base(0, 0, 2), "", "", "");
        assert_eq!(st, "skip", "全被拒时状态应是 skip（安全闸门正常工作，不是失败）");
        assert!(msg.contains("受保护路径"), "措辞必须指向保护清单: {msg}");
        assert!(!msg.contains("被占用"), "消息里出现「被占用」= 这次拦截被伪装成用户操作问题: {msg}");

        // ② 部分被拒（同时有成功清理）⇒ 消息里单独说一句，且**不带「被占用」字样**
        let (st, msg) = classify_outcome(&base(5, 0, 2), "", "", "");
        assert_eq!(st, "ok", "有成功清理就该是 ok");
        assert!(msg.contains("2 个位于受保护路径已拒绝"), "部分被拒必须单独留痕: {msg}");
        assert!(msg.contains("已清理 5 个文件"), "成功数必须在: {msg}");

        // ③ **部分被拒 + 真有被占用**：两个数必须分开出现，谁也不许吞掉谁
        let (st, msg) = classify_outcome(&base(5, 3, 2), "", "", "");
        assert_eq!(st, "partial", "有占用有成功 ⇒ partial");
        assert!(msg.contains("3 个被占用"), "被占用数必须如实出现: {msg}");
        assert!(msg.contains("2 个位于受保护路径已拒绝"), "受保护数必须独立出现: {msg}");

        // ④ 只有被占用、没有被保护 ⇒ 消息里**不许**出现「受保护」（反向：别误报）
        let (_, msg) = classify_outcome(&base(0, 4, 0), "", "", "");
        assert!(msg.contains("4 个被占用"), "被占用措辞不变: {msg}");
        assert!(!msg.contains("受保护"), "没有被保护拒绝时不得出现「受保护」字样: {msg}");

        // ⑤ 与既有两条 P0 的优先级关系：未解析变量仍压过受保护（它更根本——
        //    变量没解析时压根不知道目标是什么，谈不上「被保护拒绝」）
        let mut c = base(0, 0, 2);
        c.unresolved = vec!["%NOPE%".to_string()];
        let (_, msg) = classify_outcome(&c, "", "", "");
        assert!(msg.contains("未解析"), "未解析变量优先: {msg}");

        // ⑥ too_new / excluded 的 skip 判定不被 protected 抢走
        let mut c = base(0, 0, 0);
        c.too_new = 7;
        let (st, msg) = classify_outcome(&c, "", "", "");
        assert_eq!(st, "skip");
        assert!(msg.contains("minAge"), "too_new 的 skip 口径不变: {msg}");

        // ⑦ 全成功 ⇒ ok，且不出现任何拒绝字样
        let (st, msg) = classify_outcome(&base(9, 0, 0), "", "", "");
        assert_eq!(st, "ok");
        assert!(!msg.contains("受保护") && !msg.contains("被占用"), "成功时不得出现拒绝字样: {msg}");
    }

    /// 2026-10-04 审计 §4.2：`fileKeys` 直指**单个文件**时必须真能删掉。
    ///
    /// 修前的形态是「静默跳过 + 报成功 0 个」：执行侧先 `cleanup_root_ok`
    /// （要求 `is_dir`）再判 `is_file`，于是文件目标在第一道就 `continue`，
    /// 那个 `is_file` 分支是死代码；接着 `files` 空、`failed` 也没加，
    /// 条目落到「已清理 0 个文件」+ `success:true`，UI 弹「清理完成！释放 0 B」。
    ///
    /// 这条是**端到端**的（真造文件、真跑 `cleanup_execute`），因为要验的正是
    /// 「分派顺序对不对」——纯函数级的断言看不到 `cleanup_root_ok` 与 `is_file`
    /// 的先后。审查 §9.4 那条「纯函数钉不住接线」的教训在这里正好不适用：
    /// 分派本身就是可执行行为，不需要源码形态断言。
    #[test]
    fn 单文件_filekey_能删且不被报成成功零删() {
        let dir = std::env::temp_dir().join(format!("trim-singlefile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("only.log");
        std::fs::write(&target, b"0123456789").unwrap();

        // fileKey 直指该文件、recurse=true（规则里 recurse 是必填布尔）
        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"singlefile","name":"单文件探测",
            "fileKeys":[{"path": target.to_string_lossy(), "pattern":"*", "recurse":true}]
        }]}]});
        let items = vec![serde_json::json!({"id":"singlefile","name":"单文件探测","path": target.to_string_lossy()})];

        let res = cleanup_execute(&items, &rules, false, false).expect("执行应返回结果而不是 Err");
        let d = &res.details[0];

        assert!(
            !target.exists(),
            "单文件目标必须真被删掉（修前它活下来了，而回执说「已清理 0 个文件」）"
        );
        assert_eq!(
            d["fileCount"].as_i64(),
            Some(1),
            "fileCount 必须是 1 —— 收不到就是 §4.2 的分派顺序没修对: {d}"
        );
        // 删到了就是 ok（这是**正确**状态；修前那条路径压根收不到文件、也照样报 ok，
        // 但配的是 fileCount=0 /「已清理 0 个文件」）。所以判据落在计数与消息上，
        // 不落在 status 上——我第一版误写了 `assert_ne!(status,"ok")`，那是错的。
        assert_eq!(
            d["freed"].as_i64(),
            Some(10),
            "释放量必须等于文件真实字节数（10）: {d}"
        );
        let msg = d["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("已清理 1 个文件"),
            "消息必须如实报出删了 1 个: {msg}"
        );
        assert!(
            !msg.contains("已清理 0 个文件"),
            "消息宣称「已清理 0 个文件」= 假绿成功（P0 纪律明令禁止）: {msg}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 2026-10-04 审计 §4.2 配套：根目标不可用时必须**留痕并降为 skip**，
    /// 而不是报「已清理 0 个文件」。
    ///
    /// 与上一条同族：根判不过时 `files` 空、`failed` 也没加，条目落到
    /// 「deleted==0 && failed==0 且无 too_new/excluded」的出口 ⇒ success:true +
    /// 「已清理 0 个文件」，而 UI 会弹「清理完成！释放 0 B」。用户看到的是
    /// 「我明明选了它、它也确实在列表里」，却被告知一切正常。
    #[test]
    fn 根目标不可用时降为_skip_而不是报成功零删() {
        // 目录型条目（无 fileKeys），path 指向一个不存在的目录
        let missing = std::env::temp_dir().join(format!("trim-nosuchroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"noroot","name":"根不存在探测"
        }]}]});
        let items = vec![serde_json::json!({"id":"noroot","name":"根不存在探测","path": missing.to_string_lossy()})];

        let res = cleanup_execute(&items, &rules, false, false).expect("不应 Err");
        let d = &res.details[0];
        assert_eq!(
            d["status"], "skip",
            "根不可用必须降为 skip（安全闸门/前提不成立），不是 ok: {d}"
        );
        let msg = d["message"].as_str().unwrap_or("");
        assert!(
            !msg.contains("已清理 0 个文件"),
            "消息宣称「已清理 0 个文件」= 假绿成功: {msg}"
        );
        assert!(
            msg.contains("不存在") || msg.contains("不可用"),
            "消息必须说清根为什么不可用，否则用户无从判断: {msg}"
        );
    }

    /// 2026-10-04 审计 §4.9：带点目录（`Vendor.Tool`）必须按**目录前缀**排除，
    /// 子树不得被删。修前执行侧按 `extension().is_some()` 分类，带点目录被 routed
    /// 进文件表、精确匹配排不掉 ⇒ 排除静默失效、整个子树照删。执行侧与扫描侧
    /// 共用 `classify_exclude_entry`；扫描侧的接线由
    /// `native-scanner/tests/cleanup_scan_rule_diff.rs` 的差分用例钉住（本仓
    /// cargo test 跑不到那边，唯一自动入口是 check-scan-rule-diff 门禁）。
    #[test]
    fn 带点目录的排除按目录前缀生效() {
        let dir = std::env::temp_dir().join(format!("trim-dotdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Vendor.Tool")).unwrap();
        std::fs::write(dir.join("Vendor.Tool").join("inside.log"), b"xxxxxxxx").unwrap();
        std::fs::write(dir.join("a.log"), b"aa").unwrap();

        // fileKeys 扫整个根、excludePaths 指向其中的带点目录
        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"dotdir","name":"带点目录排除探测",
            "fileKeys":[{"path": dir.to_string_lossy(), "pattern":"*.log", "recurse":true}],
            "excludePaths":[dir.join("Vendor.Tool").to_string_lossy()]
        }]}]});
        let items = vec![serde_json::json!({"id":"dotdir","name":"带点目录排除探测","path": dir.to_string_lossy()})];

        let res = cleanup_execute(&items, &rules, false, false).expect("不应 Err");
        assert!(
            dir.join("Vendor.Tool").join("inside.log").exists(),
            "带点目录内的文件必须幸存 —— 排除被按扩展名误分类成文件时，它会随子树一起被删"
        );
        assert!(
            !dir.join("a.log").exists(),
            "排除面不得殃及无辜 —— 目录外的文件仍应被删"
        );
        let d = &res.details[0];
        assert_eq!(d["fileCount"].as_i64(), Some(1), "只应删 1 个: {d}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod file_backup_retention_tests {
    use super::*;

    fn sandbox(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("trim-filekeep-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 造一批：清单 + 指定 `rel` 的副本。rel 由入参给，是为了能刻意造出
    /// **N10 修复前的碰撞形状**（两份清单写着同一个 rel）来测幸存保护。
    fn make_batch(root: &std::path::Path, ts: u64, rels: &[&str]) {
        let entries: Vec<serde_json::Value> = rels
            .iter()
            .map(|rel| {
                // 父目录必须挂在 root 下：`Path::new(rel).parent()` 拿到的是相对段，
                // 直接对它 create_dir_all 会建到进程 CWD，随后 root.join(rel) 的写入就找不到路径
                let dst = root.join(rel);
                std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
                std::fs::write(&dst, b"payload").unwrap();
                json!({ "file": rel, "path": "C:\\orig\\x", "size": 7, "rule": "r" })
            })
            .collect();
        std::fs::write(
            root.join(format!("manifest-{ts}.json")),
            serde_json::to_vec(&json!({ "ts": ts, "entries": entries })).unwrap(),
        )
        .unwrap();
    }

    /// N10：副本名必须同时带批次段与序号段。少任一段都会让两份清单指向同一个物理文件，
    /// 于是「还原第 1 批」静默拿回第 2 批的字节，而且**不报错**。
    #[test]
    fn 副本名同时带批次段与序号段() {
        // 同规则、同文件名、不同批次 ⇒ 必须不同名
        assert_ne!(
            backup_rel_name("share_cache", 1_700_000_000_001, 0, "a.log"),
            backup_rel_name("share_cache", 1_700_000_000_002, 0, "a.log"),
            "第二次清理不得覆盖第一次的副本"
        );
        // 同批次、同文件名、不同序号 ⇒ 必须不同名（两个目录下的同一个 `a.log`）
        assert_ne!(
            backup_rel_name("thumb", 1_700_000_000_001, 0, "a.log"),
            backup_rel_name("thumb", 1_700_000_000_001, 1, "a.log")
        );
        // 不同规则仍然分目录存放（空目录回收与穿越准入都依赖这个形状）
        let rel = backup_rel_name("thumb", 1_700_000_000_001, 2, "a.log");
        assert_eq!(rel, "thumb\\1700000000001_2_a.log");
        assert!(!rel.contains(".."), "生成器不得产出穿越形态");
    }

    /// N3 + N10 交界：裁最老批次时，**幸存批次还在引用的副本不得删**。
    /// 存量数据（批次段加进 rel 之前写的）里两份清单可以写着同一个物理文件；
    /// 无脑照被裁清单的条目删，就把幸存批次的还原凭据一起毁了。
    #[test]
    fn 裁批次时保留幸存批次仍在引用的副本() {
        let root = sandbox("shared");
        // 老形状：两份清单写着完全相同的 rel
        make_batch(&root, 1_700_000_000_001, &["legacy_rule\\0_a.log"]);
        make_batch(&root, 1_700_000_000_002, &["legacy_rule\\0_a.log"]);
        make_batch(&root, 1_700_000_000_003, &["other_rule\\0_b.log"]);

        prune_file_backups(&root, 2);

        assert!(!root.join("manifest-1700000000001.json").exists(), "最老那份清单要裁掉");
        assert!(
            root.join("legacy_rule\\0_a.log").is_file(),
            "但它与幸存批次共用同一份副本，字节必须留下"
        );
        assert!(root.join("other_rule\\0_b.log").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// N3：文件副本的保留上限必须**照清单条目删**。副本落点是 `<规则id>\`、跨批次共享，
    /// 按批次时间戳找不到对应目录 —— 只删清单会留下无人认领的副本，反过来按目录删
    /// 会把别的批次一起带走。
    #[test]
    fn 裁最老批次时清单与副本同删并回收空规则目录() {
        let root = sandbox("prune");
        // 用生产形状（含批次段）造三批：第 1 批独占 share_cache，第 2/3 批共用 thumb
        let a0 = backup_rel_name("share_cache", 1_700_000_000_001, 0, "a.txt");
        let a1 = backup_rel_name("share_cache", 1_700_000_000_001, 1, "b.txt");
        let b0 = backup_rel_name("thumb", 1_700_000_000_002, 0, "c.txt");
        let c0 = backup_rel_name("thumb", 1_700_000_000_003, 0, "d.txt");
        make_batch(&root, 1_700_000_000_001, &[a0.as_str(), a1.as_str()]);
        make_batch(&root, 1_700_000_000_002, &[b0.as_str()]);
        make_batch(&root, 1_700_000_000_003, &[c0.as_str()]);

        prune_file_backups(&root, 2);

        let mut left: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "manifest-1700000000002.json".to_string(),
                "manifest-1700000000003.json".to_string(),
                "thumb".to_string()
            ],
            "只该裁最老那批，且它独占的规则目录要一起回收: {left:?}"
        );
        assert!(!root.join("share_cache").exists(), "该批副本目录已空并被回收");
        assert_eq!(
            std::fs::read_dir(root.join("thumb")).unwrap().flatten().count(),
            2,
            "后续批次的副本不得被牵连"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 清单条目里的 `rel` 走与还原通道同一道准入：`..` / 绝对路径 / 盘符一律不删。
    /// 少这道闸，一份被改写过的清单就能让"保留上限"变成任意路径删除。
    #[test]
    fn 保留上限不得跟着被改写的清单删到备份根之外() {
        let root = sandbox("evil");
        let outside = root.parent().unwrap().join(format!(
            "trim-filekeep-outside-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&outside);
        std::fs::write(&outside, b"must survive").unwrap();
        // 三批 keep=2 ⇒ 最老那份要被裁；它的条目却指向备份根之外
        for ts in [1_700_000_000_001u64, 1_700_000_000_002, 1_700_000_000_003] {
            std::fs::write(
                root.join(format!("manifest-{ts}.json")),
                serde_json::to_vec(&json!({
                    "ts": ts,
                    "entries": [{
                        "file": format!("..\\{}", outside.file_name().unwrap().to_string_lossy()),
                        "path": "C:\\orig\\x", "size": 1, "rule": "r"
                    }]
                }))
                .unwrap(),
            )
            .unwrap();
        }

        prune_file_backups(&root, 2);

        assert!(outside.is_file(), "越界 rel 必须被拒，保留上限裁不到备份根之外");
        assert!(
            !root.join("manifest-1700000000001.json").exists(),
            "清单自身仍按上限裁掉（拒删条目不等于放弃限额）"
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside);
    }

    /// 2026-10-04 审计 §4.5③：孤儿副本（清单写失败的那批，无任何清单指向）必须被
    /// 回收——旧实现里它们永不回收，最多堆 50×256MB。同时钉两条护栏：
    /// 清单**引用的**副本不得被牵连；冷静期内的副本不得抢跑（在途批次保护）。
    #[test]
    fn 孤儿副本按冷静期回收且不牵连清单引用的副本() {
        let root = sandbox("orphan");
        // 一份正常批次（keep=5，不触发裁剪——GC 与裁剪是两件独立的事）
        make_batch(&root, 1_700_000_000_010, &["keep_rule\\0_a.log"]);
        // 造孤儿：副本在规则目录里，但没有任何清单条目指向它
        let orphan_dir = root.join("orphan_rule");
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("0_lost.log"), b"payload").unwrap();

        // 冷静期 0：孤儿必须被回收，清单引用的副本必须幸存
        prune_file_backups_with(&root, 5, 0);
        assert!(
            !orphan_dir.join("0_lost.log").exists(),
            "无人认领的副本必须被孤儿回收清掉（§4.5③）"
        );
        assert!(
            root.join("keep_rule\\0_a.log").is_file(),
            "清单引用的副本不得被孤儿回收牵连"
        );

        // 冷静期未过：同形态孤儿必须幸存（清单可能还没落盘的在途批次）
        // 注：上一轮 GC 后空规则目录已被回收，这里先重建
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("1_fresh.log"), b"payload").unwrap();
        prune_file_backups_with(&root, 5, 3_600_000); // 1h 冷静期，副本 mtime 是现在
        assert!(
            orphan_dir.join("1_fresh.log").is_file(),
            "冷静期内的副本不得被回收（在途批次保护）"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 2026-10-04 审计 §4.5①：根内的重解析段可把词法合法的 rel 重定向到备份根外。
    /// `sub` 是指向根外的 junction 时，`sub\f.txt` 的真实落点在根外——旧实现只对
    /// victim 自身做 `is_reparse`（f.txt 是普通文件，判不出父段是链接），照删。
    /// canonicalize 拿真实落点后必须在根内，且解析失败一律拒。
    #[test]
    fn 根内重解析段重定向的副本拒删() {
        use std::os::windows::process::CommandExt;
        let root = sandbox("junction");
        // junction 目标在备份根之外，里面放着「将被裁清单」指向的文件
        let target = root
            .parent()
            .unwrap()
            .join(format!("trim-filekeep-jtarget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&target);
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("f.txt"), b"outside").unwrap();
        let sub = root.join("sub");
        let out = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&sub)
            .arg(&target)
            .creation_flags(0x0800_0000)
            .output();
        if !matches!(&out, Ok(o) if o.status.success()) {
            // 环境造不出 junction：显式登记跳过（造不出 ≠ 不会发生），与其他用例同口径
            eprintln!("[§4.5①] 本环境无法创建 junction，跳过断言");
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&target);
            return;
        }
        // 老批次独占 sub\f.txt（词法合法：无 ..、无盘符、非绝对），新批次引用别的文件
        // ——keep=1 ⇒ 老批次被裁，它的条目走删副本路径，撞上包含性核验
        make_batch(&root, 1_700_000_000_001, &["sub\\f.txt"]);
        make_batch(&root, 1_700_000_000_002, &["safe\\g.txt"]);

        prune_file_backups_with(&root, 1, 0);

        assert!(
            target.join("f.txt").is_file(),
            "重解析段重定向到备份根之外的落点必须拒删（§4.5①）"
        );
        assert!(
            !root.join("manifest-1700000000001.json").exists(),
            "清单自身仍按上限裁掉（拒删条目不等于放弃限额）"
        );
        assert!(
            root.join("safe\\g.txt").is_file(),
            "幸存批次的正常副本不得被牵连"
        );
        // 收尾：junction 要先拆再清树，remove_dir_all 不会跟进去，但目标目录独立清
        let _ = std::fs::remove_dir(&sub);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&target);
    }
}

