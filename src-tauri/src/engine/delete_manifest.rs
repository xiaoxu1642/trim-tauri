//! 删除清单共享存储（D 批抽出：finder:delete 与 fileclean 共用同一份目录与格式）
//!
//! 对照 Electron main.js：`FILECLEAN_BACKUP_DIR = <数据目录>/fileclean-backup`、
//! `saveDeleteManifest`（原子写 + 只留最近 50 个批次）。清单是误删追溯的唯一凭据，
//! 必须 `atomic_write_json`（AGENTS.md 红线）。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::engine::{log, paths};
use crate::security;

/// 只保留最近 50 个批次（对照 FILECLEAN_MANIFEST_KEEP）
const MANIFEST_KEEP: usize = 50;

/// 删除清单目录
pub fn backup_dir() -> PathBuf {
    paths::app_data_dir().join("fileclean-backup")
}

/// 当前 UTC 时间 ISO 串（对照 `new Date().toISOString()`）
pub fn iso_now() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let secs = ms.div_euclid(1000);
    let milli = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days as i64);
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{milli:03}Z")
}

/// Howard Hinnant 天数 → 公历年月日
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

/// 新批次 id（ISO 去 `:`/`.`/`-`，对照 Electron `new Date().toISOString().replace(/[:.]/g,'-')`）
pub fn new_batch_id() -> String {
    iso_now().replace([':', '.'], "-")
}

/// 写删除清单：`{batchId, deletedAt, count, items[]}`，原子写 + 只留最近 50 个批次。
/// 失败/无条目返回 None（对照 saveDeleteManifest）。
pub fn save_delete_manifest(batch_id: &str, entries: &[Value]) -> Option<PathBuf> {
    if entries.is_empty() {
        return None;
    }
    let dir = backup_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log::write_log("error", &format!("写入删除清单失败: {e}"));
        return None;
    }
    let path = dir.join(format!("deleted-{batch_id}.json"));
    let payload = json!({
        "batchId": batch_id,
        "deletedAt": iso_now(),
        "count": entries.len(),
        "items": entries,
    });
    if let Err(e) = security::atomic_write_json(&path, &payload) {
        log::write_log("error", &format!("写入删除清单失败: {e}"));
        return None;
    }
    prune_manifests(&dir);
    Some(path)
}

/// 只保留最近 MANIFEST_KEEP 个批次（文件名 = deleted-<ISO>.json，字典序即时序）
fn prune_manifests(dir: &Path) {
    let mut files: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|f| f.starts_with("deleted-") && f.ends_with(".json"))
            .collect(),
        Err(_) => return,
    };
    files.sort();
    while files.len() > MANIFEST_KEEP {
        let oldest = files.remove(0);
        let _ = std::fs::remove_file(dir.join(oldest));
    }
}

/// 读最近批次清单并扁平化（最多 max 条，最近批次在前）。
/// 返回 `(items, dir)`；目录不存在时 items 为空（对照 finder:delete-manifest）。
pub fn list_manifest_items(max: usize) -> (Vec<Value>, String) {
    let dir = backup_dir();
    if !dir.is_dir() {
        return (Vec::new(), dir.to_string_lossy().to_string());
    }
    let mut files: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|f| f.starts_with("deleted-") && f.ends_with(".json"))
            .collect(),
        Err(_) => return (Vec::new(), dir.to_string_lossy().to_string()),
    };
    files.sort();
    files.reverse();

    let mut items: Vec<Value> = Vec::new();
    for f in files {
        if items.len() >= max {
            break;
        }
        let text = match std::fs::read_to_string(dir.join(&f)) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let obj: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let deleted_at = obj.get("deletedAt").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(arr) = obj.get("items").and_then(|v| v.as_array()) {
            for it in arr {
                if items.len() >= max {
                    break;
                }
                items.push(json!({
                    "path": it.get("path").and_then(|v| v.as_str()).unwrap_or(""),
                    "kind": it.get("kind").and_then(|v| v.as_str()).unwrap_or("file"),
                    "size": it.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                    "recycled": it.get("recycled").and_then(|v| v.as_bool()).unwrap_or(false),
                    "deletedAt": deleted_at,
                }));
            }
        }
    }
    (items, dir.to_string_lossy().to_string())
}

/// 确保清单目录存在（open-backup-dir 用）
pub fn ensure_backup_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(backup_dir())
}
