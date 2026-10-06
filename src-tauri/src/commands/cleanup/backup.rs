//! cleanup:reg-backup-* 与 cleanup:file-backup-*（C-4 还原入口）。
//!
//! 备份文件名先过白名单校验才拼路径（防目录穿越）；跨根列表必须把「来自老根」标出来，
//! 且封条缺失也要列出——那是升级前唯一可还原的依据。
//! 副本按 `<规则id>/` 存放、跨批次共享，裁剪按清单条目删而不是按批次时间戳。

use crate::engine::{guard, log};
use serde_json::{Value, json};
use std::path::PathBuf;
use tauri::WebviewWindow;
// ==================== cleanup:reg-backup-*（C-4 注册表备份还原入口） ====================
// cleanup_execute 的 regKeys 分支在删除前 export 整键到 <数据根>\cleanup-reg-backup
// （文件名 {ms时间戳}_reg_{规则id}_{序号}.reg）。此前只有写没有读——「能清不能还」；
// 本节补列表与还原面。还原 = reg import 合并回系统（把备份时的键/值原样加回）。
//
// 落点口径（N1，2026-09-29）：**写恒新根**（`backup_write_dir`），**读跨两根**
// （`backup_read_entries` / `resolve_backup_file`）。上游 Electron 轨的 PS 写的是
// `%APPDATA%\Trim\cleanup-reg-backup`（`vendor/upstream-js` cleanup-scripts.js:1411），
// 只读新根会让升级用户的老批备份在列表里凭空消失，与「这台机器没做过可还原操作」无法区分。

/// 备份根标识：列表项要告诉用户这份来自当前数据目录还是升级前的老根
pub(super) const REG_BACKUP_SUB: &str = "cleanup-reg-backup";

/// 备份文件名准入：单段文件名、字符集 [A-Za-z0-9_- .]、.reg 结尾——防路径穿越与任意导入
pub(super) fn valid_backup_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name.to_lowercase().ends_with(".reg")
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

/// cleanup:reg-backup-list — 列出清理域注册表备份（只读；≤50 条按 mtime 倒序）
#[tauri::command]
pub fn cleanup_reg_backup_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    // N1：跨根列举（新根在前、同名只留新根那份）。老根那份必须标来源，否则用户会以为
    // 当前版本偷偷写了它；总数与总体积按**全量**算，列表只截最近 50 份。
    let mut items: Vec<Value> = Vec::new();
    let mut total_bytes: u64 = 0;
    for (p, from_legacy) in crate::engine::paths::backup_read_entries(REG_BACKUP_SUB) {
        let Some(name) = p.file_name().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        if !valid_backup_file_name(&name) || !p.is_file() {
            continue;
        }
        let Ok(meta) = p.metadata() else { continue };
        // stem 形如 {ms}_reg_{规则id}_{序号}；规则 id 取中段（宽容解析，解析失败也列出）
        let stem = name.trim_end_matches(".reg");
        let parts: Vec<&str> = stem.split('_').collect();
        let (stamp, rule_id, seq) = if parts.len() >= 4 && parts[1] == "reg" {
            (
                parts[0].to_string(),
                parts[2..parts.len() - 1].join("_"),
                parts[parts.len() - 1].to_string(),
            )
        } else {
            (String::new(), stem.to_string(), String::new())
        };
        total_bytes = total_bytes.saturating_add(meta.len());
        items.push(json!({
            "file": name,
            "stampMs": stamp.parse::<i64>().unwrap_or(0),
            "ruleId": rule_id,
            "seq": seq,
            "fromLegacy": from_legacy,
            "mtimeMs": meta.modified().ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
            "sizeBytes": meta.len(),
        }));
    }
    items.sort_by(|a, b| b["mtimeMs"].as_i64().cmp(&a["mtimeMs"].as_i64()));
    let total_count = items.len();
    items.truncate(crate::engine::paths::BACKUP_KEEP);
    json!({ "success": true, "data": {
        "backups": items,
        "totalCount": total_count,
        "totalBytes": total_bytes,
        "keep": crate::engine::paths::BACKUP_KEEP,
    } })
}

/// cleanup:reg-backup-restore — reg import 把单个备份合并回注册表（主窗专属）。
/// import 是「合并加回」不是「回滚快照」：只还原备份里存在的键/值，不删除此后产生的新数据。
#[tauri::command]
pub fn cleanup_reg_backup_restore<R: tauri::Runtime>(window: WebviewWindow<R>, file: String) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    if !valid_backup_file_name(file.trim()) {
        return json!({ "success": false, "message": "备份文件名非法" });
    }
    // 还原侧必须与列表侧共用同一套跨根解析：列表能列出老根那份，还原就只能从同一根取，
    // 否则"看得见、点不动"（N1）
    let Some(path) = crate::engine::paths::resolve_backup_file(REG_BACKUP_SUB, file.trim()) else {
        return json!({ "success": false, "message": "备份文件不存在" });
    };
    // N9：清理域此前"文件名白名单过了就直接 reg import"，而卸载域同一威胁模型下有四道闸。
    // 调同一个公共件 —— 一份被手工改成 `[HKEY_LOCAL_MACHINE\SOFTWARE]` 的 .reg，
    // 不该因为"它是备份文件"就被写进注册表；老根兜底纳进来的 Electron 轨文件形状更不可信。
    let crate::engine::reg_backup::RegBackupCheck { keys, seal: _ } =
        match crate::engine::reg_backup::reg_backup_restore_guards(
            &path,
            file.trim(),
            crate::engine::sysinfo::is_admin(),
        ) {
            Ok(c) => c,
            Err(msg) => {
                log::write_log("warn", &format!("cleanup 注册表备份还原被拒: {msg}"));
                return json!({ "success": false, "message": msg });
            }
        };
    log::flush_sync(); // 写注册表前刷盘
    // A6（v2-R4）：原生 `.reg` 写入替换 `reg.exe import`。四道闸（严格解析 / 受保护面 /
    // 封条核对 / HKLM 提权）原样在上游跑完，这里只换执行器；.reg 文本格式与封条链未动。
    let imported = crate::engine::reg_backup::reg_import_apply(&path);
    if let Ok(stat) = &imported {
        log::write_log(
            "info",
            &format!(
                "cleanup 注册表备份已还原: {file}（{} 个键，写入 {} 值、删除 {} 值、删键 {}）",
                keys.len(),
                stat.values_written,
                stat.values_deleted,
                stat.keys_deleted
            ),
        );
        json!({ "success": true, "data": { "restored": true, "keys": keys } })
    } else {
        let detail = imported.err().unwrap_or_default();
        log::write_log("error", &format!("cleanup 注册表备份还原失败: {file} {detail}"));
        json!({ "success": false, "message": format!("还原写入失败: {detail}") })
    }
}

// ==================== cleanup:file-backup-*（C-4 永久删批次备份还原） ====================
// 常规清理链是「永久删」产品语义（v3.3.0 拍板），2026-09-28 小旭拍板补删前备份：
// native::cleanup_execute 在永久删除前把文件复制到 cleanup-files-backup\<规则id>\ 下
// （文件名 `<批次ms>_<序号>_<原名>`，N10 补的批次段），
// 并落 manifest-<ts>.json（条目=备份相对名 ↔ 原始路径）。备份是语义增强不是删除
// 前提：复制失败/超上限照常删除并记账（native.rs 内有 64MB/文件、256MB/批次上限）。

pub(super) const FILES_BACKUP_SUB: &str = "cleanup-files-backup";

/// manifest 文件名准入：`manifest-<纯数字>.json`——防路径穿越
pub(super) fn valid_files_manifest_name(name: &str) -> bool {
    let Some(stem) = name.strip_prefix("manifest-").and_then(|s| s.strip_suffix(".json")) else {
        return false;
    };
    !stem.is_empty() && stem.len() <= 20 && stem.bytes().all(|b| b.is_ascii_digit())
}

/// 还原目标（清单 `path` 字段）准入 —— C-2（审查 2026-10-07）。
///
/// 与同域 `rel` 的穿越准入同源：两字段出自**同一份可被外部写入的清单 JSON**，
/// 副本侧的检查不能替代目标侧。判据（任一不满足即拒，fail-closed）：
/// - 非空、不含 NUL；
/// - 不含 `..` 组件（折叠后即穿越）；
/// - 不是设备/对象管理器路径（`\\.\` / `\??\`，Win32 会跳过常规路径解析）；
/// - 是绝对路径：盘符绝对形态（`X:\`）或 UNC（`\\server\share`）。
/// 不在此处判受保护面 —— 那由调用方的 `is_path_protected` 负责（两层职责分离）。
pub(super) fn valid_restore_target(p: &str) -> bool {
    let t = p.trim();
    if t.is_empty() || t.contains('\0') {
        return false;
    }
    if t.starts_with(r"\\.\") || t.starts_with(r"\??\") {
        return false;
    }
    if t.split(|c| c == '\\' || c == '/').any(|seg| seg == "..") {
        return false;
    }
    let bytes = t.as_bytes();
    let drive_abs = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    // UNC 要求至少 `\\server\share` 两段；`\\?\…` 形态允许（长路径），由保护面归一化剥前缀
    let unc_parts = if t.starts_with(r"\\") {
        t[2..]
            .split(|c| c == '\\' || c == '/')
            .filter(|s| !s.is_empty())
            .count()
    } else {
        0
    };
    drive_abs || unc_parts >= 2
}

/// cleanup:file-backup-list — 列出永久删批次的文件备份清单（只读；≤50 份按时间倒序）
#[tauri::command]
pub fn cleanup_file_backup_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let mut items: Vec<Value> = Vec::new();
    let mut total_bytes: i64 = 0;
    for (p, from_legacy) in crate::engine::paths::backup_read_entries(FILES_BACKUP_SUB) {
        let Some(name) = p.file_name().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        if !valid_files_manifest_name(&name) || !p.is_file() {
            continue;
        }
        let Ok(meta) = p.metadata() else { continue };
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        let entries = v.get("entries").and_then(|e| e.as_array()).cloned().unwrap_or_default();
        let total: i64 = entries
            .iter()
            .filter_map(|e| e.get("size").and_then(|s| s.as_i64()))
            .sum();
        total_bytes = total_bytes.saturating_add(total);
        items.push(json!({
            "file": name,
            "ts": v.get("ts").and_then(|t| t.as_i64()).unwrap_or(0),
            "count": entries.len(),
            "totalSize": total,
            "fromLegacy": from_legacy,
            "mtimeMs": meta.modified().ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
        }));
    }
    items.sort_by(|a, b| b["mtimeMs"].as_i64().cmp(&a["mtimeMs"].as_i64()));
    let total_count = items.len();
    items.truncate(crate::engine::paths::BACKUP_KEEP);
    json!({ "success": true, "data": {
        "manifests": items,
        "totalCount": total_count,
        "totalBytes": total_bytes,
        "keep": crate::engine::paths::BACKUP_KEEP,
    } })
}

/// cleanup:file-backup-restore — 把单个备份条目拷回原路径（主窗专属）。
/// 目标已存在时跳过（合并语义：只还原缺失文件，不覆盖现有数据）。
#[tauri::command]
pub fn cleanup_file_backup_restore<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    file: String,
    index: usize,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let fname = file.trim();
    if !valid_files_manifest_name(fname) {
        return json!({ "success": false, "message": "备份清单名非法" });
    }
    // 清单按跨根解析（N1）；后续取副本时必须用**同一根**，否则老根清单会去新根找文件
    let Some(mpath) = crate::engine::paths::resolve_backup_file(FILES_BACKUP_SUB, fname) else {
        return json!({ "success": false, "message": "备份清单不存在" });
    };
    let Ok(text) = std::fs::read_to_string(&mpath) else {
        return json!({ "success": false, "message": "备份清单不存在" });
    };
    let Ok(v) = serde_json::from_str::<Value>(&text) else {
        return json!({ "success": false, "message": "备份清单解析失败" });
    };
    let Some(entries) = v.get("entries").and_then(|e| e.as_array()) else {
        return json!({ "success": false, "message": "备份清单结构异常" });
    };
    let Some(entry) = entries.get(index) else {
        return json!({ "success": false, "message": "条目序号越界" });
    };
    // 备份相对名准入：不含 .. / 绝对路径形态 / 盘符——防穿越到备份根之外
    let Some(rel) = entry.get("file").and_then(|s| s.as_str()) else {
        return json!({ "success": false, "message": "条目缺少备份文件名" });
    };
    if rel.contains("..") || rel.starts_with('\\') || rel.starts_with('/') || rel.contains(':') {
        return json!({ "success": false, "message": "备份文件名非法" });
    }
    let Some(original) = entry.get("path").and_then(|s| s.as_str()) else {
        return json!({ "success": false, "message": "条目缺少原始路径" });
    };
    // C-2（审查 2026-10-07）：`original` 与 `rel` 来自同一份可被外部写入的清单 JSON，
    // 只对副本侧做穿越准入是不够的 —— 目标侧少了这道闸，篡改清单即可让备份落到
    // 任意**未被保护面覆盖**的位置（如启动目录）。与 `rel` 同口径收紧后再走保护面判定。
    if !valid_restore_target(original) {
        return json!({ "success": false, "message": "原始路径非法，已拒绝还原" });
    }
    if crate::engine::protect::is_path_protected(original) {
        return json!({ "success": false, "message": "原始路径现为受保护路径，已拒绝还原" });
    }
    // 副本必须与清单同根（老根清单的副本躺在老根），不能固定用新根拼（N1）
    let Some(root) = mpath.parent() else {
        return json!({ "success": false, "message": "备份清单路径异常" });
    };
    let src = root.join(rel);
    if !src.is_file() {
        return json!({ "success": false, "message": "备份文件已不存在" });
    }
    let dst = PathBuf::from(original);
    if dst.exists() {
        return json!({ "success": true, "data": { "restored": false, "reason": "目标已存在，未覆盖" } });
    }
    if let Some(parent) = dst.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return json!({ "success": false, "message": format!("原目录创建失败: {e}") });
        }
    }
    match std::fs::copy(&src, &dst) {
        Ok(_) => {
            log::write_log("info", &format!("cleanup 文件备份已还原: {original}"));
            json!({ "success": true, "data": { "restored": true } })
        }
        Err(e) => {
            log::write_log("error", &format!("cleanup 文件备份还原失败: {original} {e}"));
            json!({ "success": false, "message": format!("拷回失败: {e}") })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::valid_restore_target as ok;

    /// C-2（审查 2026-10-07）回归：还原目标准入必须拦住穿越与设备路径。
    /// 每条都对应一个「篡改清单后把备份落到别处」的具体形状 —— 去掉守卫这里就红。
    #[test]
    fn restore_target_rejects_traversal_and_device_paths() {
        // 相对/穿越：折叠后会落到备份根或系统目录之外
        assert!(!ok(r"..\..\Windows\System32\evil.dll"));
        assert!(!ok(r"C:\Users\me\..\..\Windows\evil.dll"));
        assert!(!ok(r"foo\bar.txt"), "盘符相对路径不是绝对路径，必须拒");
        assert!(!ok(r"C:foo\bar.txt"), "盘符相对（无根）必须拒");
        // 设备/对象管理器路径：Win32 会跳过常规解析，保护面归一化也拦不住
        assert!(!ok(r"\\.\C:\evil.dll"));
        assert!(!ok(r"\??\C:\evil.dll"));
        // 空与非法字符
        assert!(!ok("   "));
        assert!(!ok("C:\\a\0b"));
    }

    #[test]
    fn restore_target_accepts_absolute_paths() {
        // 正常落盘形态（cleanup.rs 写入清单的就是这两种）不能被误伤
        assert!(ok(r"C:\Program Files\App\cfg.ini"));
        assert!(ok(r"D:/data/file.log"), "正斜杠同为绝对形态");
        assert!(ok(r"\\server\share\dir\file.txt"), "UNC 至少要 server\\share 两段");
        assert!(!ok(r"\\server"), "UNC 只有一段不是合法共享路径");
    }
}

