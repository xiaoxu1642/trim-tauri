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

fn prune_file_backups(root: &std::path::Path, keep: usize) {
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
    if manifests.len() <= keep {
        return;
    }
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
            if !reparse {
                let _ = trim_finder::scan::recycle::send_to_trash_os(victim.as_os_str());
            }
        }
        let reparse_m = std::fs::symlink_metadata(&mpath)
            .map(|m| crate::engine::protect::is_reparse(&m))
            .unwrap_or(true);
        if !reparse_m {
            let _ = trim_finder::scan::recycle::send_to_trash_os(mpath.as_os_str());
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
                    if trim_finder::cleanup_scan::reg_target_excluded(&reg_excludes, &expanded, value.as_deref()) {
                        reg_excluded += 1;
                        continue;
                    }
                    let Some((hive, rest)) = parse_reg_path(&expanded) else { continue; };
                    if !reg_key_exists(hive, &rest) { continue; }
                    parsed.push((hive, rest, value));
                }
                if parsed.is_empty() {
                    let message = if reg_unresolved.is_empty() {
                        if reg_excluded > 0 {
                            format!("注册表目标全部命中规则级排除（{reg_excluded} 项），无需清理")
                        } else {
                            "注册表项不存在，无需清理".to_string()
                        }
                    } else {
                        format!("路径变量 {} 未解析，未执行注册表清理", reg_unresolved.join("、"))
                    };
                    let status = if reg_unresolved.is_empty() { "ok" } else { "skip" };
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
                            if reg_key_remove(*hive, rest, true) {
                                removed += 1;
                            } else {
                                reg_failed += 1;
                            }
                        }
                    }
                }
                total_files += removed;
                let status = if reg_failed == 0 { "ok" } else if removed > 0 { "partial" } else { "fail" };
                let excl_note = if reg_excluded > 0 {
                    format!("；{} 个注册表目标命中规则级排除已跳过", reg_excluded)
                } else {
                    String::new()
                };
                let message = if reg_failed == 0 {
                    format!("已清理 {} 项注册表记录{excl_note}", removed)
                } else {
                    format!("已清理 {} 项注册表记录，{} 项失败{excl_note}", removed, reg_failed)
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
        if rule.get("special").and_then(|v| v.as_str()) == Some("dism") {
            let dism = crate::engine::systembin::quiet_cmd(system_tool("dism.exe"))
                .args(["/Online", "/Cleanup-Image", "/StartComponentCleanup", "/ResetBase"])
                .output();
            let (status, message) = match &dism {
                Ok(o) if o.status.success() => (
                    "ok",
                    "DISM 组件存储清理完成（/ResetBase 已执行，更新将不可卸载）".to_string(),
                ),
                Ok(o) => (
                    "fail",
                    format!("DISM 清理失败，退出码 {}", o.status.code().unwrap_or(-1)),
                ),
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
                if std::path::Path::new(&ep).extension().is_some() {
                    excl_files.push(ep);
                } else {
                    excl_dirs.push(ep);
                }
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
                    // 展开后的每个实际目录仍过 cleanup_root_ok（reparse 判拒，双保险）
                    for base in expand_glob_dirs(&expanded) {
                        if !cleanup_root_ok(&base) { continue; }
                        if let Ok(meta) = std::fs::metadata(&base) {
                            if meta.is_file() {
                                // fileKey 直指单文件：同样过时效护栏
                                if cutoff.map(|c| !trim_finder::cleanup_scan::modified_before(&meta, c)).unwrap_or(false) {
                                    too_new += 1;
                                    continue;
                                }
                                files.push((base, meta.len()));
                                continue;
                            }
                        }
                        collect_files(&base, pattern, recurse, cutoff, &mut files, &mut too_new);
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
                failed += 1;
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
        let (status, message) = if !unresolved.is_empty() && deleted == 0 && failed == 0 {
            ("skip", format!("路径变量 {} 未解析，未执行清理", unresolved.join("、")))
        } else if deleted == 0 && failed == 0 && too_new > 0 {
            ("skip", format!("{} 个文件修改时间不足 minAge（时效护栏），未执行清理", too_new))
        } else if deleted == 0 && failed == 0 && excluded > 0 {
            ("skip", format!("{} 个文件在排除名单中，未执行清理", excluded))
        } else {
            let mut suffix = too_new_suffix;
            if !excl_suffix.is_empty() {
                suffix.push_str(&excl_suffix);
            }
            if !backup_suffix.is_empty() {
                suffix.push_str(&backup_suffix);
            }
            if !unresolved.is_empty() {
                suffix = format!("；{} 未解析已跳过{}", unresolved.join("、"), suffix);
            }
            if to_recycle {
                ("recycle", format!("待移入回收站（{} 个文件）{suffix}", deleted))
            } else if failed == 0 {
                ("ok", format!("已清理 {} 个文件{suffix}", deleted))
            } else if deleted > 0 {
                ("partial", format!("已清理 {} 个文件，{} 个被占用{suffix}", deleted, failed))
            } else {
                ("fail", format!("已清理 0 个文件，{} 个被占用{suffix}", failed))
            }
        };

        details.push(json!({
            "id": id, "name": name, "status": status,
            "freed": freed, "message": message, "fileCount": deleted, "residual": failed,
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
                    if let Err(e) = std::fs::write(&mpath, text) {
                        crate::engine::log::write_log("warn", &format!("files 备份清单写入失败: {e}"));
                    }
                }
                Err(_) => {
                    crate::engine::log::write_log("warn", "files 备份清单序列化失败");
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
}

