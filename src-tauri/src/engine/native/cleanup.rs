//! B10 清理域：条目明细枚举（cleanup_detail）与清理执行（cleanup_execute）。
//!
//! 安全口径（改这里之前先读 AGENTS §3）：
//! - 删除先过 `engine::protect::is_path_protected`；
//! - 常规清理按 v3.3.0 用户裁定**固定永久删**（toRecycle 恒 false），不做永久删兜底；
//! - 文件备份按 `<规则id>/` 跨批次共享，保留裁剪走 `prune_file_backups`，只裁新根。
//! 规则库契约测试（P0）与文件备份保留测试随本实现放在同一文件。
//!
//! **P3 · N1a-U02 书面豁免（2026-10-22 用户裁定「维持不接 + 书面登记」）**：
//! 逐文件执行链**不接** `is_system_namespace`（系统命名空间）这一道闸，理由与复核条件如下——
//! ① 本链的目标不来自外部：全部来自扫描结果，且删除前已过 `is_path_protected` 的受保护面 /
//!    别名 / 父链 / 身份证四道闸（见下面「安全口径」）；
//! ② 盲接会**误拒正常功能**：现算规则库里有 26 条合法规则要写/清 `%WINDIR%` 下的内容
//!    （系统组件更新缓存一类），系统面闸一接上它们会被整批拒掉；
//! ③ 复核条件（满足任一条就必须重新裁决、不许沿用本豁免）：规则库新增「写系统目录」的条目、
//!    或本链的来源从扫描结果变成接受外部路径、或 §2 基线把系统面列为必接闸。
//! 登记位置：审查台账的 N1a-U02 条目（定性=需修未修，本轮按用户裁定以书面豁免结案）。


// v6-K01（P0-2）后本文件只以全路径形式调 system_tool，顶部短导入已死——删掉
// （留着就是每编一次报一次 unused）。
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

/// 明细（预览/计数）侧的未解析变量出口（A6-L01 / v7.2 C07）。
///
/// 与执行侧 `cleanup_execute` 用**同一道** fail-closed 判据：展开后仍残留 `%TOKEN%`
/// 的路径不参与枚举/计数，并把令牌显式记进 `unresolved` 带给调用方。旧实现只在
/// 计数侧 `expand_env`、不判残留 —— 未解析模板在这里塌成 `read_dir` 失败、条目
/// 报「0 项」，而同一模板在执行侧是「跳过并报 skip 原因」：同一道 P0 判据只长在
/// 链路一半上，用户看到「扫描 0 项 / 执行被跳过」两个互不解释的结论。
///
/// 返回 true = 已记残留、调用方必须 `continue`（不枚举、不计数）。
fn note_unexpanded_in_detail(expanded: &str, raw: &str, unresolved: &mut Vec<String>) -> bool {
    let Some(tok) = first_unexpanded_token(expanded) else {
        return false;
    };
    let tag = format!("%{tok}%");
    if !unresolved.iter().any(|u| *u == tag) {
        unresolved.push(tag.clone());
    }
    crate::engine::log::write_log(
        "warn",
        &format!("cleanup_detail 路径变量 {tag} 未解析，相关目标已跳过（原始模板 {raw}）"),
    );
    true
}

/// 清理条目明细枚举（原 PS 时代脚本 cleanup_detail.ps1，已退役；S3）
///
/// 输入 rule JSON 和目标路径，返回 {kind, total, truncated, files, unresolved}。
/// 复杂 glob/排除规则回退 PS（commands 层判定）。
pub fn cleanup_detail(rule: &Value, target_path: &str) -> Result<Value, String> {
    let cap = 600usize;
    // A6-L01：与 cleanup_execute 的 `unresolved` 同名字段、同语义（未解析的令牌）
    let mut unresolved: Vec<String> = Vec::new();

    // special=dism
    if rule.get("special").and_then(|v| v.as_str()) == Some("dism") {
        return Ok(json!({"kind": "dism", "total": 0, "truncated": false, "files": [], "unresolved": []}));
    }

    // regKeys 型
    if let Some(reg_keys) = rule.get("regKeys").and_then(|v| v.as_array()) {
        if !reg_keys.is_empty() {
            let mut count = 0usize;
            for rk in reg_keys {
                let path = rk.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if path.is_empty() { continue; }
                let expanded = expand_env(path);
                if note_unexpanded_in_detail(&expanded, path, &mut unresolved) { continue; }
                if let Some((hive, rest)) = parse_reg_path(&expanded) {
                    count += unsafe { reg_count_key(hive, &rest, rk.get("value").is_some()) };
                }
            }
            return Ok(json!({"kind": "reg", "total": count, "truncated": false, "files": [], "unresolved": unresolved}));
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
                if note_unexpanded_in_detail(&expanded, path, &mut unresolved) { continue; }
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
            return Ok(json!({"kind": "files", "total": total, "truncated": total > cap, "files": files, "unresolved": unresolved}));
        }
    }

    // 目录型
    if !target_path.is_empty() && std::path::Path::new(target_path).exists() {
        let mut files: Vec<Value> = Vec::new();
        let mut total = 0usize;
        let mut seen = std::collections::HashSet::new();
        enumerate_files(target_path, "*", true, &mut files, &mut total, &mut seen, cap);
        return Ok(json!({"kind": "files", "total": total, "truncated": total > cap, "files": files, "unresolved": unresolved}));
    }

    Ok(json!({"kind": "files", "total": 0, "truncated": false, "files": [], "unresolved": unresolved}))
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

/// 文件名 / 路径段通配判定（P0-A2 修法 A，2026-10-16）：薄包装，**委托**扫描侧
/// `trim_finder::cleanup_scan::wildcard_match`——匹配器归一后全仓只有一份实现。
///
/// 根因（交接 §2.4）：旧实现是执行侧自己的简单匹配——大小写敏感，且
/// `pattern.find('*')` 只认**第一个** `*`（`*Cache*` 的 suffix 变成字面量
/// `Cache*` ⇒ 段内多星恒不匹配）。后果是「扫描计体积、执行恒 0 展开」，
/// 恰好从 A2 装载校验不查路径段多星的那条缝漏过。
///
/// 参数顺序钉死（总方案 v2 §0 第 2 条）：扫描侧签名是 `wildcard_match(name,
/// pattern)`，与本侧三处调用点的 `glob_match(pattern, name)` **相反**——写反
/// 照样编译通过，会在要修的这条静默路径上再造同类缺陷。
fn glob_match(pattern: &str, name: &str) -> bool {
    trim_finder::cleanup_scan::wildcard_match(name, pattern)
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
    //
    // A1-M03（v7.2 C06）：任一份清单读不动就**整轮放弃裁剪**。旧实现把读失败当
    // 「这份清单没有条目」，于是它引用的副本全部落进「无人认领」→ 送回收站。
    let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut unreadable_manifests = 0usize;
    for m in &manifests {
        let Some(rels) = manifest_rels(&root.join(m)) else {
            unreadable_manifests += 1;
            continue;
        };
        for rel in rels {
            referenced.insert(rel.to_lowercase());
        }
    }
    if unreadable_manifests > 0 {
        crate::engine::log::write_log(
            "warn",
            &format!(
                "备份裁剪：{unreadable_manifests} 份清单读不动，引用集合不完整；本轮放弃裁剪与孤儿回收（避免误删仍被引用的副本）"
            ),
        );
        return;
    }
    // 裁剪失败计数（§4.5②）：回收站满/禁用时旧实现 `let _ =` 静默停摆，
    // BACKUP_KEEP 上限形同虚设且无人知晓——现在逐条 warn + 汇总。
    let mut prune_failed = 0usize;
    let root_canon = match std::fs::canonicalize(root) {
        Ok(rc) => Some(rc),
        Err(e) => {
            // 包含性核验的前提是根的真实落点可解析；解析不出 ⇒ 无法证明 victim
            // 在根内，本轮的裁剪删除必须整体放弃（fail-closed，不允许跳过核验继续删）
            crate::engine::log::write_log(
                "warn",
                &format!("备份裁剪：备份根真实路径解析失败（{e}），本轮放弃裁剪删除"),
            );
            None
        }
    };
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
            let Some(rels) = manifest_rels(&root.join(m)) else {
                crate::engine::log::write_log("warn", "备份裁剪：幸存清单在二次读取时读不动，本轮放弃裁剪");
                return;
            };
            for rel in rels {
                kept_rels.insert(rel.to_lowercase());
            }
        }
        for oldest in &manifests {
            let mpath = root.join(oldest);
            let Some(rels) = manifest_rels(&mpath) else {
                crate::engine::log::write_log("warn", "备份裁剪：清单在二次读取时读不动，本轮放弃裁剪");
                return;
            };
            for rel in rels {
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
                // 真实落点必须在根内；根不可解析时核验前提不成立，一律拒删
                if let Some(rc) = &root_canon {
                    if !backup_victim_within_root(rc, &victim) {
                        crate::engine::log::write_log(
                            "warn",
                            &format!("备份裁剪：副本 {rel} 的真实落点不在备份根内（根内含重解析段？），已拒删"),
                        );
                        continue;
                    }
                } else {
                    continue;
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
                // R5a-M04：孤儿出口补齐祖先/根内核验——与上面清单裁剪出口同一道
                // backup_victim_within_root（真实落点 canonicalize 后必须仍在根内）。
                // 旧写法只 reparse 判文件本体，规则目录段是 junction 时 lexical 的
                // strip_prefix 照样产出「根内 rel」，根外文件被当孤儿回收。
                // 根不可解析时核验前提不成立，本轮孤儿回收整体放弃（与裁剪出口同 fail-closed）。
                match &root_canon {
                    Some(rc) => {
                        if !backup_victim_within_root(rc, &fp) {
                            crate::engine::log::write_log(
                                "warn",
                                &format!("孤儿回收：副本 {rel} 的真实落点不在备份根内（根内含重解析段？），已拒删"),
                            );
                            continue;
                        }
                    }
                    None => continue,
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

/// 读一份文件备份清单里所有 `entries[].file`（相对名）。
/// 读/解析失败返回 `None`（A1-M03：不得把「读不动」当成「没有条目」）；合法但无条目
/// 返回 `Some(空)`。
fn manifest_rels(manifest: &std::path::Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(manifest).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some(
        v.get("entries")
            .and_then(|e| e.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.get("file").and_then(|s| s.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
    )
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
    /// 权限不足（ACCESS_DENIED）——R4（2026-10-15）从 `failed` 拆出：提权重试有意义的方向
    denied: i64,
    /// 删除时已不存在（NOT_FOUND）——R4（2026-10-15）从 `failed` 拆出：无需重试的方向
    gone: i64,
    /// 被保护清单拒绝（安全闸门正常工作；关任何程序都不会变可删）
    protected_blocked: i64,
    /// Kudu S2（2026-10-16）：路径祖先在执行前变成链接/junction 而拒
    /// （同 protected_blocked：安全闸门动作，不是用户侧问题）
    reparse_blocked: i64,
    /// Kudu S2（2026-10-16）：文件身份证与扫描时不符（被替换/改写）而拒（同族）
    identity_blocked: i64,
    too_new: i64,
    excluded: i64,
    /// 文件名含孤立代理项/无法无损解码（保护清单按 lossy 串比对不可靠）而拒删的数量
    lossy: i64,
    unresolved: Vec<String>,
    to_recycle: bool,
}

/// 由计数与三段后缀推出 `(status, message)`。
///
/// 判据的历史包袱都在这里，逐条不可省：
/// - **P0 fail-closed（2026-09-27）**：存在未解析变量且一无所删时不得报「成功 0 删」——
///   那正是「扫描命中、执行 0 删」静默失效的形态。
/// - **P0-M5**：`too_new` 同理，「全都是太新文件」必须显式说成 skip。
/// - **§4.1（2026-10-04）**：`protected_blocked` 必须与 `failed` 分开。
///   两者混在一起会让这次拦截在界面上长得跟「文件被占用」一模一样，而渲染层的
///   清理失败引导（`cleanup.js` 的 `offerCleanupRetryPanel`）会据此提示
///   「可关闭相关程序或重启后再试」——真因是这些目标本来就在保护清单里，那个建议永远无效。
/// - **R4（2026-10-15）**：`denied` / `gone` 同理拆出——权限不足的出路是提权、
///   「已不存在」根本无需处理，两者都不该被说成「被占用」。
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
    if nothing_done && c.reparse_blocked > 0 {
        return (
            "skip",
            format!(
                "{} 个目标的路径祖先在执行前变成链接/junction（疑似被替换），已拒绝删除",
                c.reparse_blocked
            ),
        );
    }
    if nothing_done && c.identity_blocked > 0 {
        return (
            "skip",
            format!("{} 个文件与扫描时不一致（已被替换/改写），已拒绝删除", c.identity_blocked),
        );
    }
    if nothing_done && c.too_new > 0 {
        return ("skip", format!("{} 个文件未达 minAge 年龄门槛（时效护栏），未执行清理", c.too_new));
    }
    if nothing_done && c.excluded > 0 {
        return ("skip", format!("{} 个文件在排除名单中，未执行清理", c.excluded));
    }
    if nothing_done && c.lossy > 0 {
        return ("skip", format!("{} 个文件名无法无损解码，保护判定不可靠，已拒绝删除", c.lossy));
    }
    // R4（2026-10-15）：权限不足与「已不存在」是两档独立的残留结局，都按 skip 出口
    // 说清自己的下一步（前者提权重试、后者无需处理），不许落回「N 个被占用」。
    if nothing_done && c.denied > 0 {
        return ("skip", format!("{} 个文件因权限不足（拒绝访问）未删，提权重试可能有效", c.denied));
    }
    if nothing_done && c.gone > 0 {
        return ("skip", format!("{} 个文件在删除时已不存在（无需处理）", c.gone));
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
    if c.reparse_blocked > 0 {
        // Kudu S2：同 protected_blocked 的姿势——独立出现、不许被「被占用」吞掉。
        suffix = format!("{suffix}；{} 个目标的路径祖先在执行前变成链接已拒绝", c.reparse_blocked);
    }
    if c.identity_blocked > 0 {
        suffix = format!("{suffix}；{} 个文件与扫描时不一致已拒绝", c.identity_blocked);
    }
    if c.lossy > 0 {
        suffix = format!("{suffix}；{} 个文件名无法无损解码已跳过", c.lossy);
    }
    // R4（2026-10-15）：两个新档的 partial 后缀（与 protected_blocked 同一姿势：
    // 独立出现、不许被「被占用」那个数吞掉）。
    if c.denied > 0 {
        suffix = format!("{suffix}；{} 个因权限不足未删（需管理员）", c.denied);
    }
    if c.gone > 0 {
        suffix = format!("{suffix}；{} 个在删除时已不存在", c.gone);
    }
    if c.to_recycle {
        ("recycle", format!("待移入回收站（{} 个文件）{suffix}", c.deleted))
    } else if c.failed == 0 && c.denied == 0 {
        ("ok", format!("已清理 {} 个文件{suffix}", c.deleted))
    } else if c.deleted > 0 {
        let busy = if c.failed > 0 { format!("，{} 个被占用", c.failed) } else { String::new() };
        ("partial", format!("已清理 {} 个文件{busy}{suffix}", c.deleted))
    } else {
        ("fail", format!("已清理 0 个文件，{} 个被占用{suffix}", c.failed))
    }
}

/// 清理执行（原 PS 时代脚本 cleanup_execute.ps1，已退役；S3）
///
/// 三类目标模型全部原生化（v0.1.6 真机修复）：fileKeys（含段级 glob 展开）、
/// regKeys（先备份后删，fail-closed）、special=dism。to_recycle=true 时文件只
/// 枚举不删除，返回 recycle_entries（当前仅测试在用；生产清理链按 2026-10-12
/// 用户裁定固定全量永久删，见 commands/cleanup/scan_execute.rs）。
///
/// `progress`：逐项开工回调 `(第 k 项, 总项数, 项名)`——放在每项处理**之前**，
/// 供渲染层把进度条按真实项数推进（清理大目录耗时长时不再假走到 90% 冻结）。
pub fn cleanup_execute(
    items: &[Value],
    rules: &Value,
    to_recycle: bool,
    auto_rebuild: bool,
    progress: Option<&dyn Fn(usize, usize, &str)>,
) -> Result<CleanupExecuteResult, String> {
    cleanup_execute_with_backup_root(items, rules, to_recycle, auto_rebuild, None, progress)
}

/// [`cleanup_execute`] 的实现体。`backup_root` 允许把「删前备份」定向到调用方给定的根——
/// 生产恒 None（= 数据目录新根，行为不变）；三个端到端用例传私有 tmp 沙箱。
///
/// X1-K01（v4-K09，2026-10-09）：那三个用例（单文件 fileKey / 带点目录排除 / 大小写去重）
/// 真跑删除链时，临时探针的备份副本会被写进**用户真实数据目录**的 `cleanup-files-backup\`
/// ——测试假件与用户真备份混居，进程被杀还会永久残留（发版前 #[ignore] 实跑还会读到假基线）。
/// DISM 在线组件清理的前置判死（2026-10-23 真机：末项空等 2 分 12 秒后退出码 5）。
///
/// 退出码 5 = 拒绝访问，最常见的成因不是「本程序没提权」，而是 Windows Modules
/// Installer（TrustedInstaller）被精简/禁用 —— DISM 起不了 servicing 会话。
/// 这种环境下重试多少次都一样，而且要空等同样长的时间；前置判死并给出可操作
/// 原因，比「等两分钟再看一句退出码」有用。返回 `Err(文案)` 表示本条应直接 skip。
fn dism_preflight() -> Result<(), &'static str> {
    dism_preflight_with(
        crate::engine::sysinfo::is_admin(),
        super::services::service_start_type("TrustedInstaller"),
    )
}

/// 纯判据（测试可注入）：`Ok` = 可以尝试 DISM；`Err(文案)` = 直接 skip。
fn dism_preflight_with(is_admin: bool, start_type: Option<u32>) -> Result<(), &'static str> {
    if !is_admin {
        return Err(
            "需要管理员权限：DISM 组件清理只能在以管理员身份运行时执行（可退出后右键 Trim，选择「以管理员身份运行」再重试）",
        );
    }
    match start_type {
        None => Err(
            "Windows Modules Installer（TrustedInstaller）服务不存在或无法读取，DISM 无法执行。请在 services.msc 确认该服务存在后再试",
        ),
        Some(super::services::SVC_START_DISABLED) => Err(
            "Windows Modules Installer（TrustedInstaller）服务已被禁用，DISM 无法执行。请在 services.msc 将「Windows Modules Installer」的启动类型改为「手动」后重试",
        ),
        Some(_) => Ok(()),
    }
}

/// DISM 失败时给一句可操作的原因（退出码本身对用户不可读）。
fn dism_failure_hint(code: i32) -> &'static str {
    match code {
        5 => "（拒绝访问：多为 Windows Modules Installer 被禁用/未启动，或系统更新正占用组件存储；可先重启再试）",
        740 => "（需要提升权限：请以管理员身份运行 Trim 后重试）",
        _ => "",
    }
}

/// 从 DISM 输出里挑一行最像错误的信息。
///
/// DISM 把真正的错误打在 **stdout**（进度百分比也在里面），旧实现只读 stderr ⇒
/// 用户永远只看到「退出码 5」。这里优先取含「错误 / Error / 代码」的行，取不到
/// 再用最后一条非空行，避免把整段进度条塞进界面。
fn dism_note(o: &std::process::Output) -> String {
    let err = crate::engine::systembin::decode_native_output(&o.stderr);
    let out = crate::engine::systembin::decode_native_output(&o.stdout);
    dism_note_text(&err, &out)
}

/// [`dism_note`] 的纯判据（测试可注入文本）。
fn dism_note_text(err: &str, out: &str) -> String {
    let pick = |text: &str| -> Option<String> {
        let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        lines
            .iter()
            .rev()
            .find(|l| l.contains("错误") || l.contains("Error") || l.contains("代码") || l.contains("code"))
            .map(|s| s.to_string())
            .or_else(|| lines.last().map(|s| s.to_string()))
    };
    pick(err).or_else(|| pick(out)).unwrap_or_default()
}

fn cleanup_execute_with_backup_root(
    items: &[Value],
    rules: &Value,
    to_recycle: bool,
    auto_rebuild: bool,
    backup_root: Option<&std::path::Path>,
    progress: Option<&dyn Fn(usize, usize, &str)>,
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
    // K12（v6）：逐文件失败明细的上限。登记面（PFRO 重启后永久删）从「条目目标
    // 路径全量」改为消费这个清单；一条规则可命中上万个文件，全量外发会把回执
    // 撑爆（前端还要按 32/批切）。超出部分只计数（failedFilesTotal），不静默——
    // 前端 toast 照实说登记了几个。
    const FAILED_FILES_CAP: usize = 500;
    let files_backup_root = backup_root
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| crate::engine::paths::backup_write_dir("cleanup-files-backup"));
    let backup_batch_ts = crate::engine::now_ms();
    let mut backup_entries: Vec<Value> = Vec::new();
    let mut backup_total: u64 = 0;

    // Kudu S2（2026-10-16）：扫描时记的「文件身份证」基线（路径小写 → (大小, birthtimeNs)）。
    // 执行侧重新遍历删文件，但比对基线只此一份：快照 items 的 files 条目（由扫描器
    // @@PLANFILE@@ 的 birthtimeNs 落地）。缺字段/0 = 无基线不拦（父链重解析复检仍兜底）。
    // 快照槽按 label 即可：本表（commands/cleanup/state.rs）是 cleanup 域私表、无双域共用
    // （§5.25 的槽键事故前提不成立），identity 存进该表内层，不引入第二套分桶。
    let mut identity: std::collections::HashMap<String, (u64, u64)> = std::collections::HashMap::new();
    for it in items {
        let Some(files) = it.get("files").and_then(Value::as_array) else {
            continue;
        };
        for f in files {
            let (Some(p), Some(sz), Some(bt)) = (
                f.get("path").and_then(Value::as_str),
                f.get("size").and_then(Value::as_i64),
                f.get("birthtimeNs").and_then(Value::as_i64),
            ) else {
                continue;
            };
            if p.is_empty() || bt <= 0 {
                continue;
            }
            identity.entry(crate::engine::paths::path_key(p)).or_insert((sz.max(0) as u64, bt as u64));
        }
    }

    let total_items = items.len();
    for (item_idx, item) in items.iter().enumerate() {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
        // 逐项进度回调：放在循环顶部而非各出口——循环体内有多个 continue，
        // 放出口必漏（2026-10-12 进度可见性修复的一部分）。
        if let Some(cb) = progress {
            cb(item_idx + 1, total_items, name);
        }
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
                    // v6-K01（P0-2）：解析失败并进 backup_failed 分支（备份不完整绝不删）
                    match crate::engine::systembin::system_tool("reg.exe")
                        .map_err(std::io::Error::other)
                        .and_then(|exe| {
                            crate::engine::systembin::quiet_cmd_timeout(
                                exe,
                                &["export", &export_path, file_str, "/y"],
                                crate::engine::systembin::REG_EXPORT_TIMEOUT,
                            )
                        }) {
                        Ok(o) if o.status.success() && file.exists() => {
                            // N9：清理域此前**根本不产封条**，于是还原链那道"封条核对"对本域
                            // 永远只能走 missing 分支（等于没闸）。与卸载域同口径落一份，
                            // 半截写入与手工误改才有可发现性。写封条失败不阻断删除（增强而非前提）。
                            crate::engine::reg_backup::write_reg_backup_seal(&file, &export_path);
                            // P0-01：提权执行窗口补 HKLM 管理员摘要；非提权写失败仅日志
                            crate::engine::reg_backup::write_admin_seal("cleanup", &file);
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
                // P0-01：裁剪后同步对账 HKLM 摘要，删孤立值
                crate::engine::reg_backup::reconcile_admin_seals("cleanup", &backup_dir);
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
            // 2026-10-23：先判环境。不能跑就秒级 skip，不空等（真机实测空等 2 分 12 秒
            // 后退出码 5，用户既不知道原因也不知道下一步）。
            if let Err(reason) = dism_preflight() {
                crate::engine::log::write_log(
                    "warn",
                    &format!("规则 {id}：DISM 前置检查未通过，已跳过 —— {reason}"),
                );
                details.push(json!({
                    "id": id, "name": name, "status": "skip",
                    "freed": 0, "message": reason, "fileCount": 0, "ruleVer": rule_ver,
                }));
                continue;
            }
            // v6-K01（P0-2）：解析失败并进 Err 臂（既有「DISM 执行失败」回执口径）
            let dism = crate::engine::systembin::system_tool("dism.exe")
                .map_err(std::io::Error::other)
                .and_then(|exe| {
                    crate::engine::systembin::quiet_cmd_timeout(
                        exe,
                        &["/Online", "/Cleanup-Image", "/StartComponentCleanup", "/ResetBase"],
                        DISM_CLEANUP_TIMEOUT,
                    )
                });
            let (status, message) = match &dism {
                Ok(o) if o.status.success() => (
                    "ok",
                    "DISM 组件存储清理完成（/ResetBase 已执行，更新将不可卸载）".to_string(),
                ),
                Ok(o) => {
                    // 超时收口时 quiet_cmd_timeout 把原因写进 stderr，必须带给用户，
                    // 否则「失败但不知道是超时还是 DISM 自己报错」又是一层雾。
                    let code = o.status.code().unwrap_or(-1);
                    let note = dism_note(o);
                    let hint = dism_failure_hint(code);
                    (
                        "fail",
                        if note.is_empty() {
                            format!("DISM 清理失败，退出码 {code}{hint}")
                        } else {
                            format!("DISM 清理失败，退出码 {code}{hint}：{note}")
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
        // P0-M5 时效护栏（G-1 收敛）：minAge 规则在执行侧**重新逐文件判定**，与扫描侧
        // 同一函数（trim_finder::cleanup_scan::rule_age_guard + AgeGuard::old_enough）。
        // 扫描与执行之间有时间差，太新文件可能在两次枚举之间刚被应用写入——执行侧必须自己
        // 拒绝，不能只信扫描结果。axis 缺省 = mtime；声明 ctime 时读创建时间。
        // G-2：全局年龄策略在工作线程内**现读一次**（与扫描侧同一次读法、同一个 tighten），
        // 并法 = max(规则阈值, 全局阈值)，只收紧不放宽。
        let guard = trim_finder::cleanup_scan::rule_age_guard(
            rule.get("minAgeHours").and_then(Value::as_f64),
            rule.get("minAgeDays").and_then(Value::as_f64),
            rule.get("ageAxis").and_then(Value::as_str),
        )
        .tighten(trim_finder::cleanup_scan::load_global_min_age_days());
        let mut too_new = 0i64;
        // finder 域已有 `has_lossy_path` 闸门，清理链此前漏了：孤立代理项经 U+FFFD
        // 往返可能指向另一个真实路径，而保护清单也按 lossy 串比对。收集阶段即拒收，
        // 失败不会降级成「可能被占用」的误导文案。
        let mut lossy = 0i64;
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
                    // §4.10：盘符相对形态不得进删除链——保护闸门（is_path_protected）
                    // 对它按 CWD 折叠，而枚举/删除按当前盘根解析，两侧比对对象不同。
                    // 记 unresolved 让条目显式 skip，不许伪装成「成功 0 删」。
                    if trim_finder::cleanup_scan::is_drive_relative(&expanded) {
                        unresolved.push(format!("{expanded}（盘符相对路径）"));
                        crate::engine::log::write_log(
                            "warn",
                            &format!(
                                "cleanup_execute 规则 {id}：fileKey 展开为盘符相对路径（{expanded}），已跳过（§4.10）"
                            ),
                        );
                        continue;
                    }
                    // 段级 glob 展开（v0.1.6 真机修复：旧实现遇 `*` 直接 Err 且 PS 回退已删）；
                    // 展开后的每个实际目录仍过 reparse 判拒（双保险）
                    let bases = expand_glob_dirs(&expanded);
                    // P0-A2（2026-10-16）假绿记账：通配展开为空（段无匹配 / 父目录
                    // 不存在）时，旧路径 files 与 failed 全零 ⇒ 条目落 classify_outcome
                    // 最后出口 ("ok","已清理 0 个文件")，UI 弹「清理完成！释放 0 B」。
                    // 与目录型分支（下文 else 支）同款记账：归 unresolved 显式 skip、
                    // 把原因带给前端——语义是「没找到可删的东西」，不是「成功 0 删」。
                    if bases.is_empty() {
                        unresolved.push(format!("{expanded}（通配段无匹配目录）"));
                        crate::engine::log::write_log(
                            "warn",
                            &format!(
                                "cleanup_execute 规则 {id}：fileKey 通配展开为空，已跳过 —— {expanded}"
                            ),
                        );
                        continue;
                    }
                    for base in bases {
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
                                if trim_finder::util::has_lossy_path(std::path::Path::new(&base)) {
                                    lossy += 1;
                                    continue;
                                }
                                if !guard.old_enough(&md) {
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
                                collect_files(&base, pattern, recurse, guard, &mut files, &mut too_new, &mut lossy);
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
            // §4.10：盘符相对形态（`\Foo`，多来自 `$env:UNDEF + '\Foo'`）在保护侧
            // 会被拼成 CWD 下的幽灵路径——保护闸门比对的路径 ≠ 实际删除的路径。
            // 刻意排在 cleanup_root_ok **之前**：后者用 fs 判存在性，会把当前盘根下
            // 真实存在的同名目录放进删除链（见 trim_finder::is_drive_relative 注释）。
            if !target.is_empty() && trim_finder::cleanup_scan::is_drive_relative(target) {
                unresolved.push(format!("{target}（盘符相对路径，无盘符语义，已拒绝枚举）"));
                crate::engine::log::write_log(
                    "warn",
                    &format!("规则 {id}：目标为盘符相对路径（{target}），已拒绝枚举（§4.10）"),
                );
            } else if !target.is_empty() && cleanup_root_ok(target) {
                collect_files(target, "*", true, guard, &mut files, &mut too_new, &mut lossy);
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
            } else {
                // 空串目标：上面三条判据都带 `!target.is_empty()`，空串会**一路什么都不记**，
                // 落进 classify_outcome 的最后一个出口报「已清理 0 个文件」+ ok ——
                // 与 §4.2 那条「假绿成功」是同一个形状，只是漏了空串这一格。
                // 来源是库里 `pathPs:"''"` 这类空位占位（扫描侧 detect 已于 2026-10-23
                // 改走候选回退，这里是不信任上游的执行侧兜底：载荷能到这儿就必须有可见结论）。
                unresolved.push("空目标（规则既无可用根，也无候选可自动发现）".to_string());
                crate::engine::log::write_log(
                    "warn",
                    &format!("规则 {id}：目标为空串，已拒绝执行（既无根也无候选）"),
                );
            }
        }

        // 去重（§5.3：与扫描侧同口径按大小写不敏感折叠——两条仅大小写不同的
        // 规则根会让同一文件收进两行，旧判据放行重复 ⇒ 释放量重复计数，且第二次
        // remove 返回 NotFound 被记成「1 个被占用」）
        // 2026-10-23：排序/去重按**预计算**的小写键。旧比较器每次比较都 to_lowercase()，
        // 1.5 万文件约 20 万次字符串分配（真机清理明细里 tencentQq 单条就 15,805 个文件）。
        let mut keyed: Vec<(String, (String, u64))> =
            files.into_iter().map(|f| (f.0.to_lowercase(), f)).collect();
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        keyed.dedup_by(|a, b| a.0 == b.0);
        let mut files: Vec<(String, u64)> = keyed.into_iter().map(|(_, f)| f).collect();

        // 全局排除名单 + 规则级 excludePaths 过滤：显式记账，不混进「被占用」或「成功 0 删」
        let before_excl = files.len();
        files.retain(|(p, _)| {
            !trim_finder::cleanup_scan::path_excluded(&excl_dirs, &excl_files, &p.to_lowercase())
        });
        excluded = (before_excl - files.len()) as i64;

let mut freed = 0i64;
    let mut deleted = 0i64;
    let mut failed = 0i64;
    // R4（2026-10-15）：失败按因分档 —— 权限不足与「删除时已不存在」不再并进 `failed`
    // （并进去会以「N 个被占用」报给用户：前者该提权、后者无需处理，两个下一步动作全错）。
    // 判据走共享函数 `classify_delete_error`（engine/native/common.rs，网速报告清空链同款）。
    let mut denied = 0i64;
    let mut gone = 0i64;
    // 受保护路径的拒绝**单独计数**（2026-10-04 审计 §4.1）。
    //
    // 原先它与「文件被占用」共用 `failed`，后果全部是用户可见的错误信息：
    // 消息变成「N 个被占用」（**理由是假的**）、`residual` 触发渲染层的
    // 「关闭相关程序后重试」提示（用户会去关程序，而真因是保护清单）、且**一行日志都不打**。
    // 对照同文件里注册表侧的同类拒绝都记日志（`log::error` + 独立 fail 状态）
    // ——唯独永久删这条不记。
    //
    // 为什么要紧：这是全仓唯一执行永久删除的链，而「被保护路径拒绝」恰恰是
    // AGENTS §3 明确要求**留痕**的那一类事件。把它混进「被占用」等于把安全闸门的
    // 一次正常拦截伪装成用户的操作问题。
    let mut protected_blocked = 0i64;
    let mut protected_samples: Vec<String> = Vec::new();
    // Kudu S2（2026-10-16）：删除瞬间父链变成链接的拒绝，独立计数（与 protected_blocked
    // 同口径：安全闸门动作要留痕、不许混进「被占用」）；按父目录 memo 避免逐文件重走链。
    let mut reparse_blocked = 0i64;
    let mut reparse_samples: Vec<String> = Vec::new();
    let mut ancestor_memo: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    // Kudu S2（2026-10-16）：身份证比对不通过的拒绝（同 protected/reparse 口径：独立计数、留痕）
    let mut identity_blocked = 0i64;
    let mut identity_samples: Vec<String> = Vec::new();
    // A6-M02（v7.2 C07）：本规则里「快照没有该路径基线」的文件数。键已归一（paths::path_key），
    // 所以 miss 只剩两种真实来源：条目被 CAP 截断、或扫描侧没给 birthtimeNs。这一档语义仍是
    // 「不拦」（W2：无基线不拦），但必须计数外发 —— 否则「键形态不同源」与「本来就没基线」
    // 在回执里长得一模一样，Kudu S2 的护栏一旦静默失效就再也无从察觉。
    let mut identity_unbaselined = 0i64;
    // K12（v6）：本规则逐文件失败明细（{path, reason}，reason = occupied/denied）——
    // 「登记到重启后删除」的登记面只认这个清单，不再拿条目目标路径全量顶替
    // （全量 = 把成功项也送去永久删）。只收可延期两档：被占用与权限不足；
    // gone（删时已不存在）无可删，protected/reparse/identity 是安全闸门的拒绝，
    // 都不进永久删出口。上限 FAILED_FILES_CAP，总数另计（failedFilesTotal）。
    let mut failed_files: Vec<Value> = Vec::new();
    // Kudu S2（2026-10-16）：别名解析（父目录 canonicalize）按父目录 memo——同目录下成千上万个文件只解析一次
    // R5a-L01 取舍声明：两条 memo（final_memo / ancestor_memo）按**父目录**缓存某一时刻的
    // 判定，同目录后续文件复用首个结果 ⇒「删除瞬间父链复检」对批内第 2..N 个文件退化为
    // 「批内一次」而非逐文件。这是性能换实时性的刻意取舍（逐文件 canonicalize 是批量
    // 清理的大头），接受的前提：① 批内时间窗极短；② identity 基线缺项（identity_unbaselined）
    // 没有第二道兜底，靠 C07 的计数外发保证失守可见——改并发/跨进程写同目录时必须重估。
    let mut final_memo: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
        let mut backup_skipped = 0usize;
        // 未留副本有两个成因，必须分开：① 超单文件/整批体积上限（本来就不打算留）；
        // ② 上限内但 `copy` 失败（占用/权限/IO 读不到）。旧形态合成一个数、文案统一
        // 说「超备份上限」——真机实测那次两档都是几十 KB 的小文件被占用导致复制失败，
        // 用户却被指去「文件太大」，与 §C06 回执诚实度同族。
        let mut backup_over_cap = 0usize;

        // 2026-10-23：同一条规则的所有副本 parent 恒为 `<备份根>\<规则id>`
        // （见 backup_rel_name），旧实现逐文件 create_dir_all ——1.5 万文件就是
        // 1.5 万次多余的 CreateDirectory。这里每规则建一次。
        let rule_backup_ready = !to_recycle
            && std::fs::create_dir_all(files_backup_root.join(id)).is_ok();

        for (path, size) in &files {
            if to_recycle {
                // 回收站模式：只枚举，由主进程移入回收站
                recycle_entries.push(json!({"id": id, "path": path, "size": size, "isDir": false}));
                freed += *size as i64;
                deleted += 1;
            } else if crate::engine::protect::is_path_protected(path) {
                // 审查 v2-F3：常规清理豁免的是「回收站优先」，**没有**豁免保护路径判定。
                // 这是全仓唯一执行永久删除的链，保护清单在这里不能缺席 —— 回收站/重试
                // 两条旧支已随 2026-10-12 整链退役，本行就是唯一的文件级闸门。
                //
                // 单独计数而非并入 `failed`（审计 §4.1）：并进去会让这次拦截在界面上
                // 长得跟「文件被占用」一模一样，用户去关程序而真因是保护清单。
                protected_blocked += 1;
                // 前若干条逐条留痕，之后只留汇总：一条规则命中上万文件时
                // 逐条打会把真留痕淹掉（与扫描侧「首次翻转才留痕」同一取舍）。
                if protected_samples.len() < 5 {
                    protected_samples.push(path.clone());
                }
            } else if final_path_protected_memoized(path, &mut final_memo) {
                // Kudu S2（2026-10-16）：字面判定过了、但父目录解析后指向受保护路径
                //（junction / 短名别名）——同受保护拒绝族（独立于字面命中，样本标注别名）。
                protected_blocked += 1;
                if protected_samples.len() < 5 {
                    protected_samples.push(format!("{path}（别名/解析后指向受保护路径）"));
                }
            } else if let Some(anc) = reparse_ancestor_memoized(path, &mut ancestor_memo) {
                // Kudu S2（2026-10-16）：删除瞬间父链复检——扫描 → 预览 → 执行的长窗口里，
                // 某一级祖先目录可能被外部程序换成 junction/symlink，删除会穿过它命中
                // 真实目标。进清单的路径其祖先链在扫描时必然是普通目录（遍历侧跳 reparse），
                // 此刻命中即「与扫描时状态不符」⇒ fail-closed 拒绝；不进 residual（非「被占用」）。
                reparse_blocked += 1;
                if reparse_samples.len() < 5 {
                    reparse_samples.push(format!("{path}（祖先 {anc}）"));
                }
            } else {
                // Kudu S2（2026-10-16）：身份证比对守卫——路径在扫描后指向了**另一个**文件
                //（被替换/重定向）时拒绝；size 一并对照（内容长大同样算不一致，fail-closed，
                // 用户看到的是明确计数而非不明所以的删除）。birthtimeNs=0 = 无基线不拦。
                //
                // A6-M02（v7.2 C07）：记账与查找必须走**同一份归一键**。记账侧（快照 JSON 的
                // items[].files[].path）与查找侧（执行侧重新遍历的 files）在旧实现里都只做
                // 裸 `to_lowercase()`，与全仓声明的 `paths::path_key`（折分隔符 / 折 `.`/`..` /
                // 去尾点尾空格 / verbatim 折回）不同源 ⇒ 尾分隔符、正斜杠、`..` 段、`\\?\`
                // 任一写法差异都让 get 落 None，然后**直落删除支**：Kudu S2「扫描后被替换」
                // 的护栏在该形态下静默失效且方向是放行。miss 一律计一档（见 identity_unbaselined）。
                match identity.get(&crate::engine::paths::path_key(path)) {
                    Some((base_size, base_bt)) => {
                        if let Ok(md) = std::fs::symlink_metadata(path) {
                            let now_bt = birthtime_ns_of(&md);
                            let now_size = md.len();
                            if now_bt != 0 && (now_bt != *base_bt || now_size != *base_size) {
                                identity_blocked += 1;
                                if identity_samples.len() < 5 {
                                    identity_samples.push(format!(
                                        "{path}（扫描时 {base_size} 字节/出生 {base_bt}，现状 {now_size} 字节/出生 {now_bt}）"
                                    ));
                                }
                                continue;
                            }
                        }
                        // 元数据读不到（已不存在等）：交给删除原语的 gone/失败档，不在守卫里吞
                    }
                    None => identity_unbaselined += 1,
                }
                // C-4：删前备份（只对将真正删除的文件；复制失败不阻塞删除）
                if *size <= FILE_BACKUP_MAX_FILE
                    && backup_total + *size <= FILE_BACKUP_MAX_BATCH
                {
                    // R5a-K01（v7.2 C11）：序号段必须覆盖**全部**会在本循环里推进的结局
                    // 计数（denied/gone 在本文件 :1288/:1296 增）。R4 拆档时漏并这两个：
                    // 落 denied/gone 的文件已产出副本却不推进 seq ⇒ 同规则同批次同名文件
                    // 算出逐字节相同的 rel，`copy` 原地顶替——gone 档的副本是该文件仅存
                    // 字节（本域不进回收站），顶替即永久丢失。
                    let seq = deleted as u32
                        + backup_skipped as u32
                        + failed as u32
                        + denied as u32
                        + gone as u32;
                    let fname = std::path::Path::new(path)
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| seq.to_string());
                    // rel 必须同时带**批次段**和**序号段**（N10），见 `backup_rel_name`
                    let rel = backup_rel_name(id, backup_batch_ts, seq, &fname);
                    let dst = files_backup_root.join(&rel);
                    if rule_backup_ready
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
                    backup_over_cap += 1;
                }
                // 永久删除。R3（2026-10-15）原方案「清只读位 + 重试」经**实测证伪**后退役：
                // 前提是「只读文件撞 PermissionDenied」，但 Rust std 的 remove_file 在
                // Windows 上自身会对 FILE_ATTRIBUTE_READONLY 清位重试（对齐 rm -f 语义；
                // 本机 1.99 实测：只读文件 remove_file ⇒ Ok，而 cmd del / DeleteFileW
                // 层对同一文件「拒绝访问」）——执行链从不产生「只读导致 PermissionDenied」，
                // 应用层清位是死代码，不留兜底。留痕见方案 v4 附录 C。
                match std::fs::remove_file(path) {
                    Ok(()) => {
                        freed += *size as i64;
                        deleted += 1;
                    }
                    Err(e) => {
                        // R4（2026-10-15）：失败按因分档（共享判据，5/32 分开说）。
                        match classify_delete_error(&e) {
                            DeleteFailureKind::Denied => {
                                denied += 1;
                                // K12：逐文件失败明细——只收**可延期**的两档（提权
                                // 在重启后由系统代劳）；gone 无可删、安全闸门的三档
                                // 不进永久删出口（理由见 failed_files 声明处）。
                                if failed_files.len() < FAILED_FILES_CAP {
                                    failed_files.push(json!({ "path": path, "reason": "denied" }));
                                }
                            }
                            DeleteFailureKind::Gone => gone += 1,
                            _ => {
                                failed += 1;
                                if failed_files.len() < FAILED_FILES_CAP {
                                    failed_files.push(json!({ "path": path, "reason": "occupied" }));
                                }
                            }
                        }
                    }
                }
            }
        }

        total_freed += freed;
        total_files += deleted;
        let outcome = OutcomeCounters {
            deleted,
            failed,
            denied,
            gone,
            protected_blocked,
            reparse_blocked,
            identity_blocked,
            too_new,
            excluded,
            lossy,
            unresolved: unresolved.clone(),
            to_recycle,
        };

        // P0 fail-closed（规则库最终优化方案 2026-09-27）：存在未解析变量且一无所删时，
        // 不得报「已清理 0 个文件、状态成功」——这正是「扫描命中、执行 0 删」静默失效的
        // 结果形态，必须显式降为 skip 并把原因带给前端。部分成功时也要在 message 里留痕。
        // P0-M5：too_new 同理——「全都是太新文件」必须显式说成 skip，不许伪装成成功 0 删。
        let too_new_suffix = if too_new > 0 {
            format!("；{} 个文件未达 minAge 年龄门槛已跳过", too_new)
        } else {
            String::new()
        };
        let excl_suffix = if excluded > 0 {
            format!("；{} 个文件在排除名单中已跳过", excluded)
        } else {
            String::new()
        };
        let backup_suffix = if backup_skipped > 0 && !to_recycle {
            let over = backup_over_cap;
            let failed_copy = backup_skipped - over;
            let mut s = String::new();
            if over > 0 {
                s.push_str(&format!("；{over} 个文件超备份上限未留副本"));
            }
            if failed_copy > 0 {
                s.push_str(&format!(
                    "；{failed_copy} 个文件副本复制失败未留副本（文件被占用或权限不足，与体积上限无关）"
                ));
            }
            s
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
        if reparse_blocked > 0 {
            crate::engine::log::write_log(
                "warn",
                &format!(
                    "规则 {id}：{reparse_blocked} 个目标的路径祖先在执行前变成链接/junction，已按状态不符拒绝删除。样本：{}",
                    reparse_samples.join("；")
                ),
            );
        }
        if identity_blocked > 0 {
            crate::engine::log::write_log(
                "warn",
                &format!(
                    "规则 {id}：{identity_blocked} 个文件与扫描时不一致（被替换/改写），已按状态不符拒绝删除。样本：{}",
                    identity_samples.join("；")
                ),
            );
        }

        details.push(json!({
            "id": id, "name": name, "status": status,
            "freed": freed, "message": message, "fileCount": deleted, "residual": failed,
            // K12：逐文件失败明细（登记「重启后删除」的唯一合法来源；拿不到明细的
            // 条目前端不得登记）。total = residual + denied（两档都可延期）；
            // 超出 CAP 的部分只进 total，清单本身截断——前端照实展示登记了几个。
            "failedFiles": failed_files,
            "failedFilesTotal": failed + denied,
            // 受保护路径的拒绝**不进 residual**：residual 的语义是「文件被占用、
            // 清理后重试」，而这一类是「按保护清单拒绝」——混进去会让渲染层弹出
            // 「关闭相关程序后重试」的误导提示（审计 §4.1）。渲染层目前不消费这个
            // 字段，它先在数据层备着，等前端要单独呈现时不必再改引擎。
            "protectedBlocked": protected_blocked,
            // Kudu S2（2026-10-16）：父链变成链接的拒绝同理独立外发、不进 residual
            //（不是「被占用」；渲染层要单独呈现时直接消费该字段）。
            "reparseBlocked": reparse_blocked,
            // Kudu S2：身份证不符的拒绝，同样独立外发。
            "identityChanged": identity_blocked,
            // A6-M02（v7.2 C07）：本次有多少文件**查不到快照基线**（无基线不拦，但要看得见）。
            // 与 identityChanged 成对：前者是「比对了且不一致」，本字段是「压根没得比」。
            "identityUnbaselined": identity_unbaselined,
            // R4（2026-10-15）：两个新档同样独立外发、不进 residual（denied 的出路是
            // 提权、gone 无需处理，都不是「重试」）；渲染层按字段分档提示。
            "denied": denied,
            "gone": gone,
            "lossySkipped": lossy,
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

/// 按 id 查规则条目（§5.4：全仓**唯一**真源）。
///
/// 遍历口径 = subGroups 条目优先、组内自有条目也扫（超集）——旧的双实现里命令侧
/// 用 `collect_group_items` 的互斥 else（有 subGroups 就不再看 g.items），同时带
/// 两者的组会出现「引擎按它动刀、命令侧报未找到清理规则」的口径分叉。命令侧
/// `find_cleanup_rule_by_id` 现在委托到这里，禁止再写第二份遍历。
pub fn find_rule_by_id(rules: &Value, id: &str) -> Option<Value> {
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

/// Kudu S2（2026-10-16）：删除瞬间父链复检的 memo 包装——判据本体在
/// `trim_finder::scan::reparse_ancestor`（finder 删除链与常规清理链共用，§5.16/N6 一份实现）。
/// 按**父目录**记忆：同一目录下成千上万个文件只走一次祖先链。
fn reparse_ancestor_memoized(
    path: &str,
    memo: &mut std::collections::HashMap<String, Option<String>>,
) -> Option<String> {
    let parent = std::path::Path::new(path)
        .parent()
        .map(|d| d.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if let Some(cached) = memo.get(&parent) {
        return cached.clone();
    }
    let hit = trim_finder::scan::reparse_ancestor(std::path::Path::new(path));
    memo.insert(parent, hit.clone());
    hit
}

/// Kudu S2（2026-10-16）：别名解析复检的 memo 包装（判据本体
/// `protect::final_path_protected`，解析的是父目录 ⇒ 按父目录 memo 恰好在正确的粒度上）。
fn final_path_protected_memoized(
    path: &str,
    memo: &mut std::collections::HashMap<String, bool>,
) -> bool {
    let parent = std::path::Path::new(path)
        .parent()
        .map(|d| d.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if let Some(hit) = memo.get(&parent) {
        return *hit;
    }
    let hit = crate::engine::protect::final_path_protected(path);
    memo.insert(parent, hit);
    hit
}

fn collect_files(
    dir: &str,
    pattern: &str,
    recurse: bool,
    guard: trim_finder::cleanup_scan::AgeGuard,
    files: &mut Vec<(String, u64)>,
    too_new: &mut i64,
    lossy: &mut i64,
) {
    collect_files_at(dir, pattern, recurse, guard, files, too_new, lossy, 0)
}

fn collect_files_at(
    dir: &str,
    pattern: &str,
    recurse: bool,
    guard: trim_finder::cleanup_scan::AgeGuard,
    files: &mut Vec<(String, u64)>,
    too_new: &mut i64,
    lossy: &mut i64,
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
            // 目录名无法无损表示时，`to_string_lossy()` 递进去的可能是另一个目录：
            // 宁可不深入，也不要把别处的文件带进永久删除清单。
            if trim_finder::util::has_lossy_path(&path) {
                *lossy += 1;
                continue;
            }
            if recurse {
                collect_files_at(&path.to_string_lossy(), pattern, recurse, guard, files, too_new, lossy, depth + 1);
            }
        } else if meta.is_file() {
            if trim_finder::util::has_lossy_path(&path) {
                *lossy += 1;
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if !glob_match(pattern, &name) { continue; }
            // P0-M5 时效护栏（G-1）：太新（轴时间戳不足 minAge、读不到、时间在未来）
            // 不进删除清单 —— 判定由共享 AgeGuard 给（扫描侧同一函数）
            if !guard.old_enough(&meta) {
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

    /// X1-K01（v4-K09）：端到端删除用例的「删前备份」重定向根——私有 tmp 下的 per-test
    /// 沙箱。构造先清残、Drop 清垃圾（断言 panic 也不留）；不进用户备份根。
    struct BackupSandbox(std::path::PathBuf);
    impl BackupSandbox {
        fn new(tag: &str) -> Self {
            let dir = crate::engine::paths::temp_script_dir()
                .expect("私有 tmp 应可用")
                .join(format!("test-cleanup-backup-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            Self(dir)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for BackupSandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

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

    /// P0-A2（2026-10-16 总方案 v2 §3）：执行侧 glob_match 委托扫描侧
    /// wildcard_match（修法 A）。这条钉两件事：① 委托接线（同输入同结果）；
    /// ② 具体样本的期望值（多星、大小写不敏感、?）——只写「两侧同结果」是
    /// 构造性恒绿（归一后本就是同一函数），必须配可手算的期望。
    ///
    /// 样本取自真实规则：slack `…\Service Worker\*Cache*`、intelGraphicsSoftware
    /// `…\EBWebView\*cache*`（段内多星），remoRepairPowerpoint `*.LOG`、
    /// oracleJava `*PATCH.ERR`（大小写形态，交接 §2.4 点名）。
    #[test]
    fn glob_match_委托扫描侧_多星与大小写不敏感() {
        let cases: [(&str, &str, bool); 10] = [
            // 段内多星：旧实现 suffix 变字面量 "Cache*" ⇒ 恒 false；归一后必须命中
            ("*Cache*", "CacheStorage", true),
            ("*Cache*", "Code Cache", true),
            ("*cache*", "Cache", true),
            ("*cache*", "GPUCache", true),
            // 大小写形态（pattern 大写、盘上小写）
            ("*.LOG", "app.log", true),
            ("*PATCH.ERR", "x.patch.err", true),
            // ? 恰一字符
            ("a?c", "abc", true),
            // 负样本：无 cache 子串不命中、? 不匹配空、后缀不合不命中
            ("*Cache*", "Logs", false),
            ("a?c", "ac", false),
            ("*.txt", "a.log", false),
        ];
        for (pattern, name, expected) in cases {
            assert_eq!(
                glob_match(pattern, name),
                expected,
                "glob_match({pattern:?}, {name:?}) 应为 {expected}"
            );
            assert_eq!(
                glob_match(pattern, name),
                trim_finder::cleanup_scan::wildcard_match(name, pattern),
                "glob_match 必须与 wildcard_match 同结果（委托接线）: {pattern:?} vs {name:?}"
            );
        }
    }

    /// P0-A2 验收（总方案 v2 §3）：执行侧段内多星能展开——以两条真实规则的
    /// fileKeys 形态造沙箱（slack `…\Service Worker\*Cache*`、intelGraphicsSoftware
    /// `…\EBWebView\*cache*`，pattern 均为 `*`），端到端跑删除链。
    /// 修前执行侧只认第一个 `*` ⇒ 展不开 ⇒ ok/0 文件假绿；归一后必须真删到文件。
    #[test]
    fn filekeys_段内多星在执行侧能展开并删除() {
        let base = std::env::temp_dir().join(format!("trim-a2-multistar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // 形态一：*Cache* 段命中混合大小写、名字中间还有内容的目录
        let sw = base.join("Service Worker");
        std::fs::create_dir_all(sw.join("CacheStorage")).expect("建 CacheStorage");
        std::fs::create_dir_all(sw.join("Code Cache")).expect("建 Code Cache");
        std::fs::write(sw.join("CacheStorage").join("a.bin"), b"xxxx").expect("写 a.bin");
        std::fs::write(sw.join("Code Cache").join("b.bin"), b"xxxx").expect("写 b.bin");
        // 形态二：小写 pattern *cache* 命中大写开头目录（大小写不敏感）
        let eb = base.join("EBWebView");
        std::fs::create_dir_all(eb.join("Cache")).expect("建 Cache");
        std::fs::write(eb.join("Cache").join("c.bin"), b"xxxx").expect("写 c.bin");

        let rules = serde_json::json!({"groups":[{"items":[
            {"id":"a2slack","name":"段内多星探测","fileKeys":[
                {"path": sw.join("*Cache*").to_string_lossy(), "pattern":"*", "recurse":true}]},
            {"id":"a2intel","name":"小写多星段探测","fileKeys":[
                {"path": eb.join("*cache*").to_string_lossy(), "pattern":"*", "recurse":true}]}
        ]}]});
        let items = vec![
            serde_json::json!({"id":"a2slack","name":"段内多星探测","path":""}),
            serde_json::json!({"id":"a2intel","name":"小写多星段探测","path":""}),
        ];

        let bk = BackupSandbox::new("a2multistar");
        let res = cleanup_execute_with_backup_root(&items, &rules, false, false, Some(bk.path()), None)
            .expect("不应 Err");
        let expect: [(usize, i64); 2] = [(0, 2), (1, 1)];
        for (idx, n) in expect {
            let d = &res.details[idx];
            assert_eq!(
                d["fileCount"].as_i64(),
                Some(n),
                "多星段必须展开并删到文件（修前恒 0 ⇒ ok/0 假绿）: {d}"
            );
            assert_ne!(d["status"], "skip", "删到文件不该降为 skip: {d}");
        }
        // 磁盘实证：三个目录里的文件都必须已经不在
        assert!(!sw.join("CacheStorage").join("a.bin").exists(), "CacheStorage\\a.bin 应已删");
        assert!(!sw.join("Code Cache").join("b.bin").exists(), "Code Cache\\b.bin 应已删");
        assert!(!eb.join("Cache").join("c.bin").exists(), "Cache\\c.bin 应已删");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// P0-A2（总方案 v2 §3）假绿记账：fileKeys 通配展开为空必须记 unresolved
    /// 显式 skip——堵 ("ok","已清理 0 个文件") 出口。目录型分支的同款记账见
    /// `根目标不可用时降为_skip_而不是报成功零删`，本条是 fileKeys 型对偶。
    #[test]
    fn filekeys_通配展开为空时降为_skip_而不是报成功零删() {
        // 通配段指向一个任何机器上都匹配不到的名字（pid 保证不撞真实目录）
        let nomatch = std::env::temp_dir()
            .join(format!("trim-a2-fkempty-{}", std::process::id()))
            .join("*NoSuchSegment*");
        let rules = serde_json::json!({"groups":[{"items":[
            {"id":"fkempty","name":"fileKeys 展开为空探测","fileKeys":[
                {"path": nomatch.to_string_lossy(), "pattern":"*", "recurse":true}]}
        ]}]});
        let items = vec![serde_json::json!({"id":"fkempty","name":"fileKeys 展开为空探测","path":""})];

        let res = cleanup_execute(&items, &rules, false, false, None).expect("不应 Err");
        let d = &res.details[0];
        assert_eq!(
            d["status"], "skip",
            "展开为空必须降为 skip，不是 ok: {d}"
        );
        let msg = d["message"].as_str().unwrap_or("");
        assert!(
            !msg.contains("已清理 0 个文件"),
            "消息宣称「已清理 0 个文件」= 假绿成功: {msg}"
        );
        assert!(
            msg.contains("无匹配") || msg.contains("展开"),
            "消息必须说清为什么没删，否则用户无从判断: {msg}"
        );
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
        let mut lossy = 0i64;
        collect_files(
            &link.parent().unwrap().to_string_lossy(),
            "*.txt",
            true,
            trim_finder::cleanup_scan::AgeGuard::Off,
            &mut files,
            &mut too_new,
            &mut lossy,
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
        let mut lossy = 0i64;
        collect_files(&base.to_string_lossy(), "*.txt", true, trim_finder::cleanup_scan::AgeGuard::Off, &mut files, &mut too_new, &mut lossy);
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            !files.iter().any(|(p, _)| p.contains("deep-marker.txt")),
            "深度超过上限的文件不得进删除清单: {}",
            files.len()
        );
    }

    /// P0-M5 时效护栏：测试辅助——把文件时间戳拨回 days 天前（SetFileTime，真实文件系统）。
    #[cfg(windows)]
    fn set_file_mtime_days_ago(p: &std::path::Path, days: i64) {
        set_file_times_days_ago(p, Some(days), Some(days))
    }

    /// G-1（2026-10-07）：创建时间与修改时间**分开**拨（SetFileTime 三个时间戳独立）。
    /// 传 None = 该时间戳保持原样 —— 年龄轴用例需要「ctime 旧而 mtime 新」这类不对称样本，
    /// 原来的 helper 把两者一起拨，造不出来。
    #[cfg(windows)]
    fn set_file_times_days_ago(p: &std::path::Path, ctime_days: Option<i64>, mtime_days: Option<i64>) {
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
        let ft_of = |days: i64| {
            let old = ((now - days * 86400 + 11644473600) * 10_000_000) as u64;
            FILETIME {
                dwLowDateTime: (old & 0xFFFF_FFFF) as u32,
                dwHighDateTime: (old >> 32) as u32,
            }
        };
        let creation = ctime_days.map(ft_of);
        let write = mtime_days.map(ft_of);
        // SetFileTime 要 `Option<*const FILETIME>`：`Option<&T>` 不会自动 coerce，得显式取指针
        let creation_ptr = creation.as_ref().map(|f| f as *const FILETIME);
        let write_ptr = write.as_ref().map(|f| f as *const FILETIME);
        unsafe { SetFileTime(h, creation_ptr, None, write_ptr) }.expect("SetFileTime 失败");
        unsafe { let _ = CloseHandle(h); }
    }

    /// 逐项进度回调：在每个条目处理**之前**发射、序列 1..N 覆盖全部条目
    /// （2026-10-12 进度可见性修复：回调放循环顶部，多个 continue 出口不漏发）。
    #[test]
    fn cleanup_execute_emits_progress_for_every_item() {
        let items = vec![
            serde_json::json!({"id":"p1","name":"甲"}),
            serde_json::json!({"id":"p2","name":"乙"}),
            serde_json::json!({"id":"p3","name":"丙"}),
        ];
        // 规则全找不到 → 每项走 skip 出口，但进度回调必须照发（回调在循环顶部）
        let rules = serde_json::json!({"groups":[]});
        let calls = std::cell::RefCell::new(Vec::<(usize, usize, String)>::new());
        let cb = |done: usize, total: usize, name: &str| {
            calls.borrow_mut().push((done, total, name.to_string()));
        };
        let res = cleanup_execute(&items, &rules, false, false, Some(&cb)).unwrap();
        assert_eq!(res.details.len(), 3, "三个条目都应产出明细");
        let got = calls.borrow().clone();
        assert_eq!(
            got,
            vec![
                (1, 3, "甲".to_string()),
                (2, 3, "乙".to_string()),
                (3, 3, "丙".to_string())
            ],
            "进度回调序列必须是 1..N 且逐项覆盖"
        );
    }

    /// P0-M5 时效护栏：执行侧必须**自己**按修改时间拒绝太新文件，不能只信扫描结果
    /// （扫描与执行之间有时间差，太新文件可能刚被应用写入）。用回收站模式
    /// （to_recycle=true，只枚举不删除）断言清单内容，测试零删除副作用。
    ///
    /// **样本年龄必须大于全局年龄阈值**（G-2 默认 14 天，见
    /// `cleanup_scan::DEFAULT_GLOBAL_MIN_AGE_DAYS`）：执行侧并的是
    /// `max(规则阈值, 全局阈值)`，样本若只有 10 天就会被全局阈值判成「太新」，
    /// 与「按规则 minAgeDays=3 应删」的意图相悖。这里取 30 天留出余量。
    #[test]
    #[cfg(windows)]
    fn cleanup_execute_enforces_min_age() {
        let base = std::env::temp_dir().join(format!("trim-minage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("stale.txt"), b"old").unwrap();
        std::fs::write(base.join("fresh.lock"), b"new").unwrap();
        set_file_mtime_days_ago(&base.join("stale.txt"), 30);

        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"m5test","name":"M5测试",
            "fileKeys":[{"path": base.to_string_lossy(), "pattern":"*", "recurse":true}],
            "minAgeDays": 3
        }]}]});
        let items = vec![serde_json::json!({"id":"m5test","name":"M5测试","path": base.to_string_lossy()})];
        let res = cleanup_execute(&items, &rules, true, false, None).unwrap();
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

    /// G-1 验收（2026-10-07）：**扫描命中集合与执行删除集合逐项一致** ——
    /// 两侧必须调同一个 `trim_finder::cleanup_scan::rule_age_guard` + `AgeGuard::old_enough`
    /// （AGENTS §5.16 N6；旧实现两侧各一份解析，双声明时结论不同）。
    ///
    /// 样本（真实文件系统 + SetFileTime 把两个时间戳拆开）：
    ///   · stale.txt      ：mtime/ctime 都拨回 30 天 ⇒ 两种轴都命中；
    ///   · ctime_only.txt ：ctime 拨回 30 天、mtime 留在现在 ⇒ 只有 ctime 轴命中；
    ///   · fresh.lock     ：两个时间戳都不动 ⇒ 两种轴都不命中。
    /// 年龄取 30 天是为了**越过全局年龄阈值**（G-2 默认 14 天）：执行侧并的是
    /// `max(规则阈值, 全局阈值)`，样本只要比全局阈值新就会被判「太新」，两侧集合
    /// 就不可比了。
    /// 第三类「元数据读不到」无法在真实文件系统上确定性造出（要读取失败，不是读到旧值），
    /// 由 native-scanner 的 `age_guard_判定本体_fail_closed` 在共享函数层钉住 ——
    /// 两侧调的是同一个函数，时间戳缺失的结论必然一致。
    ///
    /// 零删除副作用：执行侧走回收站模式（to_recycle=true，只枚举不删除）。
    #[test]
    #[cfg(windows)]
    fn age_axis_扫描命中集与执行删除集一致() {
        use trim_finder::cleanup_scan::{list_deletable, rule_age_guard};
        let base = std::env::temp_dir().join(format!("trim-ageaxis-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("stale.txt"), b"old").unwrap();
        std::fs::write(base.join("ctime_only.txt"), b"old").unwrap();
        std::fs::write(base.join("fresh.lock"), b"new").unwrap();
        set_file_times_days_ago(&base.join("stale.txt"), Some(30), Some(30));
        set_file_times_days_ago(&base.join("ctime_only.txt"), Some(30), None);

        let rule_json = |axis: Option<&str>| {
            let mut item = serde_json::json!({
                "id": "ageaxis", "name": "年龄轴",
                "fileKeys": [{ "path": base.to_string_lossy(), "pattern": "*", "recurse": true }],
                "minAgeDays": 3
            });
            if let Some(a) = axis {
                item["ageAxis"] = serde_json::json!(a);
            }
            serde_json::json!({ "groups": [{ "items": [item] }] })
        };
        let items = vec![serde_json::json!({ "id": "ageaxis", "name": "年龄轴", "path": base.to_string_lossy() })];

        let names = |paths: Vec<String>| -> Vec<String> {
            let mut v: Vec<String> = paths
                .iter()
                .filter_map(|p| std::path::Path::new(p).file_name().map(|n| n.to_string_lossy().to_string()))
                .collect();
            v.sort();
            v
        };
        // 扫描侧：生产路径由 `rule_age_guard_of` 抽字段后调同一函数；这里直接给字段值，
        // 测的是共享判定本身（字段抽取另有 native-scanner 的 `rule_age_guard_of_识别年龄轴三字段`）。
        let scan_hits = |axis: Option<&str>| -> Vec<String> {
            let guard = rule_age_guard(None, Some(3.0), axis);
            names(list_deletable(&base.to_string_lossy(), "*", guard, &[], &[], None).files.into_iter().map(|(p, _, _)| p).collect())
        };
        let exec_hits = |axis: Option<&str>| -> (Vec<String>, i64) {
            let res = cleanup_execute(&items, &rule_json(axis), true, false, None).unwrap();
            let hits = names(res.recycle_entries.iter().filter_map(|e| e["path"].as_str().map(String::from)).collect());
            (hits, res.details[0]["tooNew"].as_i64().unwrap_or(-1))
        };

        // ① 缺省轴（mtime）：ctime_only.txt 的 mtime 是现在 ⇒ 不该命中
        let mtime_hits = vec!["stale.txt".to_string()];
        assert_eq!(scan_hits(None), mtime_hits, "扫描侧 mtime 轴命中集");
        let (exec_mtime, too_new_mtime) = exec_hits(None);
        assert_eq!(exec_mtime, mtime_hits, "执行侧 mtime 轴删除集");
        assert_eq!(too_new_mtime, 2, "太新记账：ctime_only.txt 与 fresh.lock");

        // ② ctime 轴：ctime_only.txt 创建于 10 天前 ⇒ 两侧都该命中
        let ctime_hits = vec!["ctime_only.txt".to_string(), "stale.txt".to_string()];
        assert_eq!(scan_hits(Some("ctime")), ctime_hits, "扫描侧 ctime 轴命中集");
        let (exec_ctime, too_new_ctime) = exec_hits(Some("ctime"));
        assert_eq!(exec_ctime, ctime_hits, "执行侧 ctime 轴删除集");
        assert_eq!(too_new_ctime, 1, "太新记账：只剩 fresh.lock");

        // ③ 直接对拍两个轴的集合（这条才是「逐项一致」的主张）
        for axis in [None, Some("ctime")] {
            assert_eq!(scan_hits(axis), exec_hits(axis).0, "轴 {axis:?} 上扫描命中集与执行删除集必须逐项一致");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 2026-10-04 审计 §4.1：受保护路径的拒绝必须**独立记账、独立措辞、不进 residual**。
    ///
    /// 修前它与「文件被占用」共用 `failed`，于是界面上是「N 个被占用」、
    /// `residual > 0` 触发渲染层清理失败引导（`cleanup.js` 的 `offerCleanupRetryPanel`，
    /// 兜底 toast 写「可关闭相关程序或重启后再试」）
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
            denied: 0,
            gone: 0,
            protected_blocked: protected,
            reparse_blocked: 0,
            identity_blocked: 0,
            too_new: 0,
            excluded: 0,
            lossy: 0,
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

    /// R4（2026-10-15）：权限不足与「已不存在」不许再并回「被占用」——三者的下一步动作
    /// 都不同（权限→提权、占用→关程序、已消失→无需处理），混档会让界面给错建议。
    #[test]
    fn 权限与已不存在不与被占用混档() {
        let c = |deleted: i64, failed: i64, denied: i64, gone: i64| OutcomeCounters {
            deleted,
            failed,
            denied,
            gone,
            protected_blocked: 0,
            reparse_blocked: 0,
            identity_blocked: 0,
            too_new: 0,
            excluded: 0,
            lossy: 0,
            unresolved: Vec::new(),
            to_recycle: false,
        };
        // ① 全被权限拒绝 ⇒ skip，措辞指向权限（关程序没有出路，提权才有）
        let (st, msg) = classify_outcome(&c(0, 0, 3, 0), "", "", "");
        assert_eq!(st, "skip");
        assert!(msg.contains("权限不足"), "措辞必须指向权限问题: {msg}");
        assert!(!msg.contains("被占用"), "权限问题不得说成被占用: {msg}");
        // ② 全部已不存在 ⇒ skip 且明说无需处理
        let (st, msg) = classify_outcome(&c(0, 0, 0, 2), "", "", "");
        assert_eq!(st, "skip");
        assert!(msg.contains("已不存在"), "{msg}");
        assert!(!msg.contains("被占用"), "已消失不得说成被占用: {msg}");
        // ③ 部分成功 + 权限拒绝 ⇒ partial（有未删项就不许报 ok），权限数独立出现
        let (st, msg) = classify_outcome(&c(5, 0, 2, 0), "", "", "");
        assert_eq!(st, "partial", "有未删项时 ok 会把条目从列表里静默摘走: {msg}");
        assert!(msg.contains("2 个因权限不足未删"), "{msg}");
        // ④ 三因同现：三个数各自出现，谁也不吞谁
        let (st, msg) = classify_outcome(&c(5, 2, 1, 1), "", "", "");
        assert_eq!(st, "partial");
        assert!(msg.contains("2 个被占用"), "{msg}");
        assert!(msg.contains("1 个因权限不足未删"), "{msg}");
        assert!(msg.contains("1 个在删除时已不存在"), "{msg}");
        // ⑤ 已不存在不阻成功：gone 没有失败语义
        let (st, _) = classify_outcome(&c(7, 0, 0, 1), "", "", "");
        assert_eq!(st, "ok", "已不存在的项不是失败");
    }

    /// Kudu S2（2026-10-16）：父链变成链接 / 身份证不符两类拒绝各自单独成档——不许混进
    /// 「被占用」，全部被拒时状态是 skip 而不是「失败」（安全闸门正常工作）。
    #[test]
    fn kudu_s2_父链链接与身份证拒绝单独成档() {
        let c = |deleted: i64, reparse: i64, identity: i64| OutcomeCounters {
            deleted,
            failed: 0,
            denied: 0,
            gone: 0,
            protected_blocked: 0,
            reparse_blocked: reparse,
            identity_blocked: identity,
            too_new: 0,
            excluded: 0,
            lossy: 0,
            unresolved: Vec::new(),
            to_recycle: false,
        };
        // ① 全部因父链换链被拒 ⇒ skip + 措辞指向链接替换，不许出现「被占用」
        let (st, msg) = classify_outcome(&c(0, 3, 0), "", "", "");
        assert_eq!(st, "skip", "全被拒应是 skip（安全闸门动作，不是失败）");
        assert!(msg.contains("链接/junction"), "措辞必须指向链接替换: {msg}");
        assert!(!msg.contains("被占用"), "不得混进被占用: {msg}");
        // ② 部分被拒且有成功清理 ⇒ 单独说一句
        let (st, msg) = classify_outcome(&c(5, 2, 0), "", "", "");
        assert_eq!(st, "ok");
        assert!(msg.contains("2 个目标的路径祖先在执行前变成链接已拒绝"), "部分被拒必须单独留痕: {msg}");
        // ③ 身份证不符：全拒 ⇒ skip 且措辞指向「与扫描时不一致」
        let (st, msg) = classify_outcome(&c(0, 0, 4), "", "", "");
        assert_eq!(st, "skip");
        assert!(msg.contains("与扫描时不一致"), "措辞必须指向身份证口径: {msg}");
        assert!(!msg.contains("被占用"), "不得混进被占用: {msg}");
        // ④ 部分不符 ⇒ 独立留痕
        let (st, msg) = classify_outcome(&c(6, 0, 2), "", "", "");
        assert_eq!(st, "ok");
        assert!(msg.contains("2 个文件与扫描时不一致已拒绝"), "{msg}");
    }

    /// Kudu S2（2026-10-16）端到端：扫描后文件被换掉（birthtime 变）⇒ 执行跳过并计入
    /// identityChanged、目标不被删；未换的文件照常删除。
    #[test]
    fn kudu_s2_文件被换后删除被拒且计数() {
        let dir = std::env::temp_dir().join(format!("trim-s2-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let swapped = dir.join("swapped.log");
        let normal = dir.join("normal.log");
        std::fs::write(&swapped, b"original-content-1234").unwrap();
        std::fs::write(&normal, b"normal-content-5678").unwrap();

        // 基线身份证：被换文件用「旧出生时间」（比现状早一天）模拟「扫描时的旧文件」；
        // 正常文件用真实值（扫后未动）。
        let now_ns = |p: &std::path::Path| -> u64 {
            std::fs::symlink_metadata(p)
                .unwrap()
                .created()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        };
        let normal_size = std::fs::symlink_metadata(&normal).unwrap().len();
        let stale_bt = now_ns(&swapped).saturating_sub(86_400_000_000_000);

        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"s2identity","name":"身份证探测",
            "fileKeys":[{"path": dir.to_string_lossy(), "pattern":"*.log", "recurse":true}]
        }]}]});
        let items = vec![serde_json::json!({
            "id":"s2identity","name":"身份证探测","path": dir.to_string_lossy(),
            "files":[
                {"path": swapped.to_string_lossy(), "size": 21, "birthtimeNs": stale_bt as i64},
                {"path": normal.to_string_lossy(), "size": normal_size as i64, "birthtimeNs": now_ns(&normal) as i64},
            ],
        })];

        let bk = BackupSandbox::new("s2identity");
        let res = cleanup_execute_with_backup_root(&items, &rules, false, false, Some(bk.path()), None)
            .expect("执行应返回结果而不是 Err");
        let d = &res.details[0];
        assert_eq!(d["identityChanged"].as_i64(), Some(1), "被换文件必须计入身份证不符: {d}");
        assert!(swapped.exists(), "被换掉的文件必须原样保留（拒绝删除）");
        assert!(!normal.exists(), "未变的文件照常删除");
        assert_eq!(d["freed"].as_i64(), Some(normal_size as i64), "释放量只算真删掉的: {d}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 真机反向探针（2026-10-23）：身份证基线**由扫描器现算**，不用手搓数值。
    ///
    /// 与 `kudu_s2_文件被换后删除被拒且计数` 的分工：那条用合成基线钉判定逻辑，
    /// 本条钉「扫描器产出的基线 ⇄ 执行侧现读值」这条数值通道两端对得上——
    /// 2026-10-22 那次「459 条基线 454 条判不一致、报 976 MB 只清出 1.7 MB」的整批误拒
    /// 只要复发，本条第一条断言（未改的文件必须真被删）当场红。
    /// 判红自证：把 `birthtime_ns` 的量纲改成 100ns ticks（或任一端单位漂移）⇒ 第一条红。
    #[test]
    fn 反向探针_真实扫描基线下未改必删被改必拦() {
        let dir = std::env::temp_dir().join(format!("trim-s2-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keep = dir.join("keep.log");
        let swap = dir.join("swap.log");
        std::fs::write(&keep, b"keep-1234567890").unwrap();
        std::fs::write(&swap, b"swap-1234567890").unwrap();
        let keep_size = std::fs::metadata(&keep).unwrap().len();

        // 基线走扫描器的带预算收集模式（与 pathPs 生产链路同一入口）
        let scanned = trim_finder::cleanup_scan::list_deletable_capped(
            &dir.to_string_lossy(),
            "*.log",
            trim_finder::cleanup_scan::rule_age_guard(None, None, None),
            &[],
            &[],
            None,
            100,
        );
        assert_eq!(scanned.files.len(), 2, "扫描器必须收到两个文件: {:?}", scanned.files);
        let files: Vec<_> = scanned
            .files
            .iter()
            .map(|(p, s, bt)| serde_json::json!({"path": p, "size": *s as i64, "birthtimeNs": *bt as i64}))
            .collect();

        // 篡改：删掉重建并改大小 ⇒ 出生时间与字节双双变化
        std::fs::remove_file(&swap).unwrap();
        std::fs::write(&swap, b"swapped-content-much-longer-after-tamper").unwrap();

        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"s2e2e","name":"反向探针","pathPs": format!("'{}'", dir.to_string_lossy())
        }]}]});
        let items = vec![serde_json::json!({
            "id":"s2e2e","name":"反向探针","path": dir.to_string_lossy(), "files": files
        })];

        let bk = BackupSandbox::new("s2e2e");
        let res = cleanup_execute_with_backup_root(&items, &rules, false, false, Some(bk.path()), None)
            .expect("不应 Err");
        let d = &res.details[0];
        assert!(
            !keep.exists(),
            "扫描后未改动的文件必须真被删掉；它没被删就说明基线两端对不上（整批误拒那个形状）: {d}"
        );
        assert!(swap.exists(), "被换掉的文件必须原样保留（拒绝删除）");
        assert_eq!(d["identityChanged"].as_i64(), Some(1), "被换文件必须记一档身份证不符: {d}");
        assert_eq!(d["freed"].as_i64(), Some(keep_size as i64), "释放量只算真删掉那一个: {d}");
        assert!(
            d["message"].as_str().unwrap_or("").contains("与扫描时不一致"),
            "拒绝理由必须可见，不能只报「已清理 1 个文件」: {d}"
        );
        let _ = std::fs::remove_dir_all(&dir);
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

        let bk = BackupSandbox::new("singlefile");
        let res = cleanup_execute_with_backup_root(&items, &rules, false, false, Some(bk.path()), None)
            .expect("执行应返回结果而不是 Err");
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

    /// K12（v6，P0-4）：逐文件失败明细的**行为级**端到端用例——真文件、真跑
    /// cleanup_execute：一个正常文件、一个被独占句柄占着的文件（`share_mode(0)`
    /// ⇒ 删除撞 ERROR_SHARING_VIOLATION(32)）。断言失败明细里恰好是那个被占文件
    /// （reason=occupied），成功文件不进明细。
    ///
    /// 为什么必须是行为级：源码形态断言（include_str! + contains）抓不到
    /// 「代码在、但被 if false 包住」这类禁用；而这条明细是「登记到重启后删除」
    /// 登记面的唯一来源——假绿一次的后果是用户点登记时什么都没有。
    /// 判红自证：把 Err 分支的 failed_files.push 禁用/删掉 ⇒ 本用例红。
    #[cfg(windows)]
    #[test]
    fn 逐文件失败明细收占用项_真文件端到端() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!("trim-k12-failedfiles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        struct Clean(std::path::PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _clean = Clean(dir.clone());

        let ok_file = dir.join("ok.log");
        let busy_file = dir.join("busy.log");
        std::fs::write(&ok_file, b"0123456789").unwrap();
        std::fs::write(&busy_file, b"0123456789").unwrap();
        // share_mode(0) = 不向其他句柄开放读写/删除 ⇒ DeleteFile 撞共享冲突
        let hold = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&busy_file)
            .expect("打开占用样本");

        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"k12ff","name":"K12 明细探测",
            "fileKeys":[{"path": dir.to_string_lossy(), "pattern":"*.log", "recurse":true}]
        }]}]});
        let items = vec![serde_json::json!({"id":"k12ff","name":"K12 明细探测","path": dir.to_string_lossy()})];

        let bk = BackupSandbox::new("k12ff");
        let res = cleanup_execute_with_backup_root(&items, &rules, false, false, Some(bk.path()), None)
            .expect("执行应返回结果而不是 Err");
        let d = &res.details[0].clone();
        drop(hold);

        assert!(!ok_file.exists(), "未被占用的文件必须真删掉");
        assert!(busy_file.exists(), "被占用文件必须保留");
        let ff = d["failedFiles"].as_array().expect("failedFiles 必须是数组");
        let has_busy = ff.iter().any(|f| {
            f["reason"] == "occupied"
                && f["path"]
                    .as_str()
                    .map(|p| p.to_lowercase().ends_with("busy.log"))
                    .unwrap_or(false)
        });
        assert!(has_busy, "占用失败必须进 failedFiles（reason=occupied）: {d}");
        assert!(
            !ff.iter().any(|f| f["path"]
                .as_str()
                .map(|p| p.to_lowercase().ends_with("ok.log"))
                .unwrap_or(false)),
            "成功文件不得进 failedFiles: {d}"
        );
        assert_eq!(d["failedFilesTotal"].as_i64(), Some(1), "总数应与明细一致: {d}");
    }

    /// R3 前提复核（2026-10-15，实测证伪后重写）：原方案「清只读位 + 重试」的前提是
    /// 「只读文件撞 PermissionDenied」——**实测不成立**：Rust std 的 remove_file 在
    /// Windows 上自会清 FILE_ATTRIBUTE_READONLY 并重试（对齐 rm -f；对照实验：cmd del
    /// 对同一文件「拒绝访问」）。本用例把这条实证钉死：只读文件在链上直接可删且计数正确。
    /// 日后 std 行为回摆（只读重新变拒），这条会红，届时再评估应用层清位。
    #[cfg(windows)]
    #[test]
    fn 只读文件删除由std清位且链上计数正确() {
        let dir = std::env::temp_dir().join(format!("trim-readonly-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        struct Clean(std::path::PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
        }
        let _clean = Clean(dir.clone());

        // 前提（采集）：只读位真的设上了，且 std 的原始删除直接成功（证伪「只读⇒拒删」）
        let target = dir.join("readonly.log");
        std::fs::write(&target, b"0123456789").unwrap();
        let mut perm = std::fs::metadata(&target).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&target, perm).unwrap();
        assert!(
            std::fs::metadata(&target).unwrap().permissions().readonly(),
            "只读位在这台机器上没设上，用例前提不成立"
        );
        if let Err(e) = std::fs::remove_file(&target) {
            panic!("前提变了：本工具链 remove_file 对只读文件失败（{e:?}）——R3 应用层清位退役的依据消失，需重新评估");
        }

        // 判定：重建只读文件，跑完整链（fileKey 直指单文件，同 §4.2 用例形状）
        std::fs::write(&target, b"0123456789").unwrap();
        let mut perm = std::fs::metadata(&target).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&target, perm).unwrap();
        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"ro1","name":"只读探测",
            "fileKeys":[{"path": target.to_string_lossy(), "pattern":"*", "recurse":true}]
        }]}]});
        let items = vec![serde_json::json!({"id":"ro1","name":"只读探测","path": target.to_string_lossy()})];
        let bk = BackupSandbox::new("readonly");
        let res = cleanup_execute_with_backup_root(&items, &rules, false, false, Some(bk.path()), None)
            .expect("执行应返回结果而不是 Err");
        let d = &res.details[0];

        assert!(!target.exists(), "只读文件必须被删掉（std 清位行为变化会让它留下）");
        assert_eq!(d["fileCount"].as_i64(), Some(1), "fileCount 必须是 1: {d}");
        assert_eq!(d["residual"].as_i64(), Some(0), "不得计入残留（被占用）: {d}");
        assert_eq!(d["denied"].as_i64(), Some(0), "不该进 denied: {d}");
        assert_eq!(d["gone"].as_i64(), Some(0), "不该进 gone: {d}");
        let msg = d["message"].as_str().unwrap_or("");
        assert!(msg.contains("已清理 1 个文件"), "消息必须如实报删了 1 个: {msg}");
    }

    /// R3/R4 的真机探针（`#[ignore]`，发版前实跑）：真实 Win32 码与真实文件属性的
    /// 端到端结论。快速组管合成码（common.rs 单测）；这里补：
    /// ① 只读文件在链上直接可删（std 自清位——R3 前提的现场复证）；
    /// ② share_mode(0) 持句柄 → 真实共享冲突码（32/33）→ 归 residual（被占用档）
    ///    且不污染 denied/gone。
    /// denied 的真实码路径（ACL 拒绝）探针不造——造它要动 ACL，代价与风险不对等；
    /// denied 的分档实现由 common.rs 单测钉住。
    #[cfg(windows)]
    #[test]
    #[ignore = "真机探针：真实只读属性与文件句柄共享冲突"]
    fn 删除链_std清位与共享冲突分档_真机探针() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = std::env::temp_dir().join(format!("trim-delprobe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        struct Clean(std::path::PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
        }
        let _clean = Clean(dir.clone());

        // A：只读文件（属性在）—— 链上直接可删（std 清位，R3 前提的现场复证）
        let a = dir.join("ro-probe.log");
        std::fs::write(&a, b"readonly-0123456789").unwrap();
        let mut perm = std::fs::metadata(&a).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&a, perm).unwrap();
        assert!(
            std::fs::metadata(&a).unwrap().permissions().readonly(),
            "只读位在这台机器上没设上"
        );

        // B：共享冲突文件（share_mode(0) 持句柄）—— 原始删除的真实 Win32 码必须落在
        // 占用族（32/33）；若这台机器给出的码变了，分档前提就该复核
        let b = dir.join("busy-probe.log");
        std::fs::write(&b, b"busy-0123456789").unwrap();
        let held = std::fs::OpenOptions::new().read(true).share_mode(0).open(&b).unwrap();
        let raw_b = std::fs::remove_file(&b);
        let raw_code = raw_b.as_ref().err().and_then(|e| e.raw_os_error());
        assert!(
            matches!(raw_code, Some(32) | Some(33)),
            "占用形态在这台机器上不是 32/33（实际 {raw_code:?}）——分档前提变了"
        );

        // 链上：A 应真删、B 应进 residual（被占用档）且不污染 denied/gone
        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"probe","name":"删除链探针",
            "fileKeys":[
                {"path": a.to_string_lossy(), "pattern":"*", "recurse":true},
                {"path": b.to_string_lossy(), "pattern":"*", "recurse":true}
            ]
        }]}]});
        let items = vec![serde_json::json!({"id":"probe","name":"删除链探针","path": dir.to_string_lossy()})];
        let bk = BackupSandbox::new("delprobe");
        let res = cleanup_execute_with_backup_root(&items, &rules, false, false, Some(bk.path()), None)
            .expect("执行应返回结果而不是 Err");
        let d = &res.details[0];
        drop(held); // 句柄保活到链跑完

        assert!(!a.exists(), "只读探针文件必须被清位后删掉");
        assert!(b.exists(), "被占用的探针文件不该消失（句柄仍持有）");
        assert_eq!(d["fileCount"].as_i64(), Some(1), "只读那个应被计数: {d}");
        assert_eq!(d["residual"].as_i64(), Some(1), "占用那个应进被占用：{d}");
        assert_eq!(d["denied"].as_i64(), Some(0), "真实占用不得被归进 denied: {d}");
        assert_eq!(d["gone"].as_i64(), Some(0), "不得进 gone: {d}");
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

        let res = cleanup_execute(&items, &rules, false, false, None).expect("不应 Err");
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

        let bk = BackupSandbox::new("dotdir");
        let res = cleanup_execute_with_backup_root(&items, &rules, false, false, Some(bk.path()), None)
            .expect("不应 Err");
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

    /// 2026-10-04 审计 §4.10：盘符相对目标（`\Foo`）不得进删除链——保护闸门
    /// is_path_protected 对它按 CWD 折叠，而枚举/删除按「当前盘根」解析，两侧
    /// 比对对象不同（同一字符串两侧算出不同目标）。目录型与 fileKey 型都必须
    /// 记 unresolved 并显式 skip，不许伪装成「成功 0 删」。
    #[test]
    fn 盘符相对目标在执行侧被拒绝并降为skip() {
        // 目录型条目：path 直指盘符相对形态（刻意用不存在的名字，避免撞上
        // 当前盘根下的真实目录；判据是拒绝理由，不是存在性）
        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"drel","name":"盘符相对探测"
        }]}]});
        let items = vec![serde_json::json!({"id":"drel","name":"盘符相对探测","path": r"\trim-drel-exec-no-such-dir"})];

        let res = cleanup_execute(&items, &rules, false, false, None).expect("不应 Err");
        let d = &res.details[0];
        assert_eq!(
            d["status"], "skip",
            "盘符相对目标必须显式 skip（拒绝理由进消息），不是 ok: {d}"
        );
        let msg = d["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("盘符相对"),
            "拒绝理由必须带「盘符相对」，让 0 命中可对账（§4.10）: {msg}"
        );
        assert!(
            !msg.contains("已清理 0 个文件"),
            "「已清理 0 个文件」= 假绿成功（P0 纪律明令禁止）: {msg}"
        );

        // fileKey 型：同样的形态走同一判据（共用 trim_finder::is_drive_relative）
        let rules_fk = serde_json::json!({"groups":[{"items":[{
            "id":"drelfk","name":"盘符相对fileKey探测",
            "fileKeys":[{"path": r"\trim-drel-exec-no-such-dir", "pattern":"*", "recurse":true}]
        }]}]});
        let items_fk = vec![serde_json::json!({"id":"drelfk","name":"盘符相对fileKey探测","path": r"\trim-drel-exec-no-such-dir"})];
        let res_fk = cleanup_execute(&items_fk, &rules_fk, false, false, None).expect("不应 Err");
        let dfk = &res_fk.details[0];
        assert_eq!(dfk["status"], "skip", "fileKey 型盘符相对目标同样必须 skip: {dfk}");
        let msg_fk = dfk["message"].as_str().unwrap_or("");
        assert!(
            msg_fk.contains("盘符相对") || msg_fk.contains("未解析") || msg_fk.contains("不可用"),
            "fileKey 型拒绝理由必须可见: {msg_fk}"
        );
    }

    /// 空串目标在执行侧必须显式 skip（2026-10-23，与 §4.2「假绿成功」同形状的空格）。
    /// 三条判据都写 `!target.is_empty()` ⇒ 空串一路不记账，落进 classify_outcome 尾部
    /// 报「已清理 0 个文件」+ ok —— 用户明明选了它，却被告知一切正常。
    /// 判红自证：删掉 `else { unresolved.push(..) }` 那一格 ⇒ 本用例第一条红（退回 ok）。
    #[test]
    fn 空目标必须降为skip并给出理由() {
        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"empty-target","name":"空目标探测"
        }]}]});
        let items = vec![serde_json::json!({"id":"empty-target","name":"空目标探测","path": ""})];
        let res = cleanup_execute(&items, &rules, false, false, None).expect("不应 Err");
        let d = &res.details[0];
        assert_eq!(d["status"], "skip", "空串目标不得报 ok: {d}");
        let msg = d["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("无可用根") || msg.contains("未解析"),
            "拒绝理由必须可见，让「扫描命中、执行 0 删」可对账: {msg}"
        );
        assert!(!msg.contains("已清理 0 个文件"), "「已清理 0 个文件」= 假绿成功（P0 纪律明令禁止）: {msg}");
    }

    /// 2026-10-04 审计 §5.3：两条仅大小写不同的规则根指向同一目录时，同一文件
    /// 不得收进两行——旧去重是大小写敏感的精确比较，会释放量重复计数 + 第二次
    /// remove 返回 NotFound 被记成「1 个被占用」。
    #[test]
    fn 仅大小写不同的规则根去重后只算一次() {
        let dir = std::env::temp_dir().join(format!("trim-dedup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.log"), b"0123456789").unwrap();

        let lower = dir.to_string_lossy().to_string();
        // 整条路径翻大写：Windows 文件系统大小写不敏感，两条根展开出同一批文件
        let upper = lower.to_uppercase();
        let rules = serde_json::json!({"groups":[{"items":[{
            "id":"dedup","name":"大小写去重探测",
            "fileKeys":[
                {"path": lower, "pattern":"*.log", "recurse":true},
                {"path": upper, "pattern":"*.log", "recurse":true}
            ]
        }]}]});
        let items = vec![serde_json::json!({"id":"dedup","name":"大小写去重探测","path": lower})];

        let bk = BackupSandbox::new("dedup");
        let res = cleanup_execute_with_backup_root(&items, &rules, false, false, Some(bk.path()), None)
            .expect("不应 Err");
        let d = &res.details[0];
        assert_eq!(d["fileCount"].as_i64(), Some(1), "同一文件必须只删/只算一次: {d}");
        assert_eq!(d["freed"].as_i64(), Some(10), "释放量不得重复计数: {d}");
        let msg = d["message"].as_str().unwrap_or("");
        assert!(
            !msg.contains("被占用"),
            "重复行消除后不得残留 NotFound 误报的「被占用」: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A6-L01（v7.2 C07）：明细（预览/计数）侧的未解析变量必须显式记残留，
    /// 不许塌成「0 项」。反例模板在旧实现里只会让 `read_dir` 失败 ⇒ 条目报 0 项，
    /// 与执行侧「跳过并报 skip 原因」两个结论互不解释。
    #[test]
    fn 明细侧未解析变量必须显式记残留() {
        let rule = json!({
            "id": "detail-unresolved",
            "name": "明细残留探测",
            "fileKeys": [{"path": r"%TRIM_NO_SUCH_VAR_A6L01%\x", "pattern": "*", "recurse": true}]
        });
        let d = cleanup_detail(&rule, "").expect("明细枚举不该失败");
        assert_eq!(d["total"].as_i64(), Some(0), "未解析路径不得产出条目: {d}");
        let un = d["unresolved"]
            .as_array()
            .expect("明细必须带 unresolved 字段（与执行侧同名同语义）");
        assert_eq!(un.len(), 1, "未解析令牌必须显式记一档: {un:?}");
        assert_eq!(un[0], json!("%TRIM_NO_SUCH_VAR_A6L01%"));
    }

    /// A6-M02（v7.2 C07）：身份证的记账键与查找键必须同源（`paths::path_key`）。
    ///
    /// 反例形态：快照里记的是同一文件的**别名写法**（多一个 `..` 段 + 大写扩展名）。
    /// 旧实现两侧都只做裸 `to_lowercase()` ⇒ 键对不上 ⇒ `get` 落 None ⇒ 直落删除支，
    /// 「扫描后被替换」的护栏静默失效**且方向是放行**（这里的基线 size 故意写成 99，
    /// 真实文件是 10 字节）。归一之后必须命中基线并拒绝删除，且不得落「无基线」档。
    #[test]
    fn 身份证键_别名写法也必须命中基线() {
        let dir = std::env::temp_dir().join(format!("trim-identity-alias-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.log");
        std::fs::write(&f, b"0123456789").unwrap();
        let dir_s = dir.to_string_lossy().to_string();
        // 同一文件的别名：`<dir>\sub\..\A.LOG`（词法折叠后 = `<dir>\a.log`）
        let aliased = format!("{dir_s}\\sub\\..\\A.LOG");

        let rules = json!({"groups":[{"items":[{
            "id": "alias", "name": "身份证别名探测",
            "fileKeys": [{"path": dir_s, "pattern": "a.log", "recurse": false}]
        }]}]});
        let items = vec![json!({
            "id": "alias", "name": "身份证别名探测", "path": dir_s,
            "files": [{"path": aliased, "size": 99, "birthtimeNs": 1}]
        })];

        let bk = BackupSandbox::new("identity-alias");
        let res = cleanup_execute_with_backup_root(&items, &rules, false, false, Some(bk.path()), None)
            .expect("不应 Err");
        let d = &res.details[0];
        assert!(f.exists(), "基线 size 不符（99 vs 10）必须拒绝删除: {d}");
        assert_eq!(
            d["identityChanged"].as_i64(),
            Some(1),
            "别名写法必须命中同一条基线并判不一致: {d}"
        );
        assert_eq!(
            d["identityUnbaselined"].as_i64(),
            Some(0),
            "归一后不得落「无基线」档（落了说明键仍不同源）: {d}"
        );
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

    /// A1-M03（v7.2 C06）：任一份清单读不动 ⇒ 引用集合不完整 ⇒ 本轮不得回收任何孤儿。
    /// 旧实现把读失败当「该清单没有条目」，其引用副本全部变成「无人认领」送回收站。
    #[test]
    fn 清单读不动时放弃孤儿回收() {
        let root = sandbox("manifest-unreadable");
        make_batch(&root, 1_700_000_000_020, &["keep_rule\\0_a.log"]);
        let orphan_dir = root.join("orphan_rule");
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("0_lost.log"), b"payload").unwrap();
        // 一份清单变成非法 JSON（读/解析失败）
        std::fs::write(root.join("manifest-1700000000021.json"), b"{bad").unwrap();
        prune_file_backups_with(&root, 5, 0);
        assert!(
            orphan_dir.join("0_lost.log").is_file(),
            "引用集合不完整时不得回收任何孤儿（否则误删仍被引用的副本）"
        );
        assert!(root.join("keep_rule\\0_a.log").is_file(), "清单引用的副本必须保留");
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

    /// 真机探针（`#[ignore]`）：DISM 预检读的是真实 SCM，合成状态证明不了
    /// 「服务名写对、OpenService 在本机能读到」。发布前手动跑，核对输出。
    #[test]
    #[ignore = "真机探针：读真实 SCM 的 TrustedInstaller 服务状态"]
    fn dism_预检真机探针() {
        let st = super::super::services::service_start_type("TrustedInstaller");
        println!("TrustedInstaller start_type = {st:?}（禁用=4/手动=3/自动=2）");
        assert!(st.is_some(), "正常系统必须有 Windows Modules Installer（TrustedInstaller）服务");
        println!("dism_preflight = {:?}", super::dism_preflight());
    }

    /// 2026-10-23：DISM 前置判死必须按「管理员 / 服务不存在 / 服务禁用 / 可用」分四档，
    /// 不能把所有环境问题折成同一句失败。判红自证：把 `Some(_) => Ok(())` 改回
    /// 无条件 `Ok(())`，前三条立刻红。
    #[test]
    fn dism_预检按管理员与服务状态分档() {
        let denied = super::dism_preflight_with(false, Some(3));
        assert!(denied.is_err(), "非管理员必须直接拒绝");
        assert!(denied.unwrap_err().contains("管理员"), "非管理员的原因必须点名权限");

        let missing = super::dism_preflight_with(true, None);
        assert!(missing.is_err(), "服务读不到必须直接拒绝");
        assert!(missing.unwrap_err().contains("不存在"), "服务读不到必须点名服务缺失");

        let disabled = super::dism_preflight_with(true, Some(super::super::services::SVC_START_DISABLED));
        assert!(disabled.is_err(), "服务被禁用必须直接拒绝");
        assert!(disabled.unwrap_err().contains("禁用"), "服务禁用必须点名启动类型");

        assert!(
            super::dism_preflight_with(true, Some(super::super::services::SVC_START_MANUAL)).is_ok(),
            "管理员 + 手动启动的服务必须放行"
        );
    }

    /// DISM 的真实错误在 stdout，旧实现只读 stderr ⇒ 用户只看到「退出码 5」。
    /// 判红自证：把 `pick(err).or_else(|| pick(out))` 改回只读 err，本条红。
    #[test]
    fn dism_失败原因优先取错误行而不是整段进度() {
        let out = "部署映像服务和管理工具\n版本: 10.0.26100.1\n[== 12.3% ==]\n错误: 0x800f081f\n找不到源文件。\n";
        let note = super::dism_note_text("", out);
        assert_eq!(note, "错误: 0x800f081f", "必须挑出错误行而不是最后一行进度：{note}");
        // 反向对照：stderr 有内容时优先用它（超时收口把原因写在 stderr）
        let note2 = super::dism_note_text("执行超时（1800s）", out);
        assert_eq!(note2, "执行超时（1800s）", "stderr 有原因时不得被 stdout 顶掉");
        assert_eq!(super::dism_note_text("", ""), "", "两路都空必须给空串而不是乱猜");
    }

    /// 退出码 5 必须翻译成用户能动的下一步（改服务/重启），不许只报数字。
    /// 判红自证：把 `5 => ...` 删掉，本条红。
    #[test]
    fn dism_退出码5给出可操作提示() {
        let hint = super::dism_failure_hint(5);
        assert!(hint.contains("拒绝访问") && hint.contains("Windows Modules Installer"), "退出码 5 必须点名服务：{hint}");
        assert_eq!(super::dism_failure_hint(87), "", "未知退出码不许编原因");
    }
}
