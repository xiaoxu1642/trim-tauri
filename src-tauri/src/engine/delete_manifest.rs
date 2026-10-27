//! 删除清单共享存储（D 批抽出：finder:delete 与 fileclean 共用同一份目录与格式）
//!
//! 对照 Electron main.js：`FILECLEAN_BACKUP_DIR = <数据目录>/fileclean-backup`、
//! `saveDeleteManifest`（原子写 + 只留最近 50 个批次）。清单是误删追溯的唯一凭据，
//! 必须 `atomic_write_json`（AGENTS.md 红线）。

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::engine::{civil_from_days, log, paths};
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
    let (y, m, d) = civil_from_days(days);
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{milli:03}Z")
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

/// 毫秒时刻 → `new_batch_id()` 的定宽形态（`YYYY-MM-DDTHH-MM-SS-mmmZ`）。
///
/// 只做「同一时序的另一种排版」：日历换算仍走引擎唯一的 `civil_from_days`，本函数
/// 不引入第二套历法判据（`restore_point::ms_to_iso` 用的是 `:`/`.` 分隔的 ISO，
/// 名字形态不同但同一换算真源）。
fn batch_key_from_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let milli = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}-{:02}-{:02}-{milli:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// 定宽 ISO-compact 形态校验（`2026-10-20T12-33-11-123Z`，24 字符、7 个分隔位固定）。
fn is_iso_compact(body: &str) -> bool {
    let b = body.as_bytes();
    b.len() == 24
        && matches!(
            (b[4], b[7], b[10], b[13], b[16], b[19], b[23]),
            (b'-', b'-', b'T', b'-', b'-', b'-', b'Z')
        )
        && b
            .iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19 | 23) || c.is_ascii_digit())
}

/// 批次号 → 可比时序键（定宽 ⇒ 字典序即时序）。
///
/// R6b-M02（v7.2 C07）：裁剪/读取此前直接拿文件名当时间序，而仓内**并存两个批次号
/// 生产者**——`new_batch_id()`（fileclean / finder / residue）与 `commands/startup.rs`
/// 的 `startup-<毫秒>`，写进同一个目录。`'2'(0x32) < 's'(0x73)` ⇒ 所有 `startup-*`
/// 恒排在所有 ISO 件之后：「最旧」判定永远先淘汰 ISO 件（刚写的清单可被旧启动项批次
/// 挤掉），读侧「最近批次在前」同理把启动项批次顶到头部。
///
/// 两种形态都必须认（startup 域是合法产出方，不许改成只认 ISO 把它判红）；
/// 解析不出返回 `None`，由调用方排到最后并计数告警——不许按名字序冒充时间序。
fn batch_time_key(name: &str) -> Option<String> {
    let body = name.strip_prefix("deleted-")?.strip_suffix(".json")?;
    if let Some(ms) = body.strip_prefix("startup-") {
        return ms.parse::<i64>().ok().map(batch_key_from_ms);
    }
    is_iso_compact(body).then(|| body.to_string())
}

/// 只保留最近 `MANIFEST_KEEP` 个批次。
///
/// R6b-M02（v7.2 C07）：排序键改为**解析出的批次时刻**（两种批次号形态都解析），
/// 文件名只作同刻兜底；解析不出的排到最后（优先保留）并计数告警。
fn prune_manifests(dir: &Path) {
    // P0-2A：删除清单是「误删追溯的唯一凭据」，把根换成 junction 后 read_dir 会在链接
    // 另一头按 `deleted-*.json` 形态挑最旧的投回收站 —— 恰好避开所有子项判据。
    let verdict = crate::engine::protect::inspect_root(dir, crate::engine::paths::data_root_base(dir).as_deref());
    if !verdict.is_trusted() {
        crate::engine::protect::note_root_skipped("删除清单裁剪", dir, &verdict);
        return;
    }
    let mut files: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|f| f.starts_with("deleted-") && f.ends_with(".json"))
            .collect(),
        Err(_) => return,
    };
    let unknown = files.iter().filter(|f| batch_time_key(f).is_none()).count();
    if unknown > 0 {
        log::write_log(
            "warn",
            &format!(
                "删除清单裁剪：{unknown} 个文件名不带可解析批次号（不是 new_batch_id / startup-<ms> 形态），按「最新」位序保留、不计入时间序"
            ),
        );
    }
    // 升序（最旧在前）+ 未知时刻排最后：裁剪从队头开始，未知件因此最后被裁
    files.sort_by(|a, b| match (batch_time_key(a), batch_time_key(b)) {
        (Some(ka), Some(kb)) => ka.cmp(&kb).then_with(|| a.cmp(b)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a.cmp(b),
    });
    while files.len() > MANIFEST_KEEP {
        let oldest = files.remove(0);
        let target = dir.join(oldest);
        // 引擎级裁剪出口一律回收站优先（AGENTS §3）：误删追溯凭据进回收站仍可找回，
        // 比永久删多一道兜底。reparse 先拒（清单目录受 backup_write_dir 约束，仍加一层）。
        let reparse = std::fs::symlink_metadata(&target)
            .map(|m| crate::engine::protect::is_reparse(&m))
            .unwrap_or(true);
        if !reparse {
            let _ = trim_finder::scan::recycle::send_to_trash_os(target.as_os_str());
        }
    }
}

/// 读最近批次清单并扁平化（最多 max 条，最近批次在前）。
/// 返回 `(items, dir)`；目录不存在时 items 为空（对照 finder:delete-manifest）。
///
/// R6b-M03（v7.2 C11）：读侧补老根兜底——本文件此前读写同指新根，违反
/// paths.rs 的三段口径（写只新根 / **读带老根兜底** / 裁只裁新根，restore_pack
/// 同单元已照做）；便携模式下老根 `%APPDATA%\Trim\fileclean-backup` 的误删追溯
/// 凭据整批不可见。同名批次清单只取新根那份；裁剪侧保持只裁新根不动。
/// 返回 `(条目, 主目录, broken 批次名)`：第三位是「文件在但读不出 / 不是合法 JSON」的批次
/// （R6b-M15）—— 把它折成「没条目」会让误删追溯凭据无声消失。
pub fn list_manifest_items(max: usize) -> (Vec<Value>, String, Vec<String>) {
    let primary = backup_dir();
    let dirs = crate::engine::paths::backup_read_dirs("fileclean-backup");
    // (完整路径, 文件名)：新根先扫，同名（同批次段）天然只留新根那份
    let mut files: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for dir in &dirs {
        let Ok(rd) = std::fs::read_dir(dir) else { continue };
        for e in rd.flatten() {
            let Some(name) = e.file_name().to_str().map(String::from) else { continue };
            if !(name.starts_with("deleted-") && name.ends_with(".json")) {
                continue;
            }
            let key = name.to_lowercase();
            if seen.iter().any(|s| *s == key) {
                continue;
            }
            seen.push(key);
            files.push((dir.join(&name), name));
        }
    }
    if files.is_empty() {
        return (Vec::new(), primary.to_string_lossy().to_string(), Vec::new());
    }
    // 最近批次在前：按**解析出的批次时刻**倒序（R6b-M02 同 delete_manifest 写侧），
    // 未知时刻排最后并计数告警——文件名序会让 `deleted-startup-*` 恒排在 `deleted-2026-*` 之后。
    let unknown = files.iter().filter(|(_, n)| batch_time_key(n).is_none()).count();
    if unknown > 0 {
        log::write_log(
            "warn",
            &format!("删除清单读取：{unknown} 个文件名不带可解析批次号，排在已知批次之后（不计入时间序）"),
        );
    }
    files.sort_by(|a, b| match (batch_time_key(&a.1), batch_time_key(&b.1)) {
        (Some(ka), Some(kb)) => kb.cmp(&ka).then_with(|| b.1.cmp(&a.1)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => b.1.cmp(&a.1),
    });

    let mut items: Vec<Value> = Vec::new();
    // R6b-M15：读不出 / 解析失败必须留痕 —— 本模块头把清单定义为「误删追溯的唯一凭据」，
    // 把「读不动」折成「这批没条目」等于凭据无声消失（同单元 restore_pack::list 对同一件事
    // 有 broken 档，两套口径必须并成一套）。点名批次名，不写清单内容（隐私纪律）。
    let mut broken_batches: Vec<String> = Vec::new();
    for (path, name) in files {
        if items.len() >= max {
            break;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                log::write_log("warn", &format!("删除清单读取：批次 {name} 读不出（{e}），该批条目缺席（broken）"));
                broken_batches.push(name);
                continue;
            }
        };
        let obj: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                log::write_log("warn", &format!("删除清单读取：批次 {name} 不是合法 JSON（{e}），该批条目缺席（broken）"));
                broken_batches.push(name);
                continue;
            }
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
    (items, primary.to_string_lossy().to_string(), broken_batches)
}

/// 确保清单目录存在（open-backup-dir 用）
pub fn ensure_backup_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(backup_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R6b-M02（v7.2 C07）：两种批次号形态必须落在**同一个时间轴**上。
    /// 反例取自盘上现存的真实文件名（审查 R6b 实测）：
    /// `deleted-2026-10-10T21-41-29-023Z.json` 与 `deleted-startup-1791300000000.json`
    /// （后者真实时刻 2026-10-06T15-20Z，比前者旧）。旧实现按名字排序 ⇒ `'2' < 's'`，
    /// 「最旧」恒判成 ISO 那条，把较新的清单裁掉、留下更旧的。
    #[test]
    fn batch_time_key_puts_both_forms_on_one_timeline() {
        let iso_newer = batch_time_key("deleted-2026-10-10T21-41-29-023Z.json").expect("ISO 形态应可解析");
        let startup_older = batch_time_key("deleted-startup-1791300000000.json").expect("startup-<ms> 形态应可解析");
        assert!(
            startup_older < iso_newer,
            "时间序错：startup-1791300000000(2026-10-06) 必须早于 2026-10-10，实际 {startup_older} vs {iso_newer}"
        );
        // 反证字典序：名字序恰好给出相反结论（这就是被修掉的那个缺陷本身）
        assert!("deleted-2026-10-10T21-41-29-023Z.json" < "deleted-startup-1791300000000.json");
    }

    /// 毫秒 → 定宽键必须与真实 UTC 时刻一致（换算真源 = engine::civil_from_days）。
    #[test]
    fn batch_key_from_ms_matches_utc() {
        assert_eq!(batch_key_from_ms(1_791_300_000_000), "2026-10-06T15-20-00-000Z");
        assert_eq!(batch_key_from_ms(1_791_740_787_893), "2026-10-11T17-46-27-893Z");
        // 定宽 24 字符保证字典序 = 时序（跨月/跨年不需要补零逻辑之外的特判）
        assert_eq!(batch_key_from_ms(0), "1970-01-01T00-00-00-000Z");
    }

    /// 解析不出的形态返回 None（调用方排最后并计数），不许猜。
    #[test]
    fn batch_time_key_rejects_unknown_forms() {
        assert_eq!(batch_time_key("deleted-legacy.json"), None);
        // 秒级 ISO（无毫秒段）不是 new_batch_id() 的产出形态
        assert_eq!(batch_time_key("deleted-2026-10-10T21-41-29Z.json"), None);
        assert_eq!(batch_time_key("deleted-startup-abc.json"), None);
        assert_eq!(batch_time_key("manifest-2026-10-10T21-41-29-023Z.json"), None);
    }
}

/// R1d 前半批（2026-10-28 P1-d）的形态钉。
///
/// `include_str!` 类断言：期望串用 `concat!` 拼两半、断言消息里也不许出现完整字面量
/// —— 任何一处出现，断言都会扫到自己那行，变成恒真的假绿（本仓 2026-10-27/28 两次实测踩坑）。
#[cfg(test)]
mod p1d_shape_tests {
    /// R6b-M15：清单读侧必须区分「没条目」与「读不出」（broken 计数与留痕在场）。
    #[test]
    fn 清单读侧broken机制在场() {
        let src = include_str!("delete_manifest.rs");
        assert!(
            src.contains(concat!("broken_bat", "ches")),
            "list_manifest_items 必须带出 broken 批次清单"
        );
        assert!(
            src.contains(concat!("该批条目缺席（", "broken）")),
            "读不出 / 解析失败必须各写一条 warn 留痕"
        );
    }

    /// R1a27-M02：背景图删除出口不得把「读不到」报成「已删除」（只 NotFound 才幂等成功）。
    #[test]
    fn 背景图删除不得吞全部读取错误() {
        let src = include_str!("../commands/appearance.rs");
        let bad = concat!("Err(_) => return Ok(json!({ \"success\": true", " }))");
        assert!(!src.contains(bad), "裸 Err 吞掉全部读取错误 = 假绿回执（删除出口）");
        assert!(
            src.contains(concat!("ErrorKind::Not", "Found")),
            "幂等成功必须显式限定 NotFound"
        );
    }

    /// R1d-M15：finder 扫描根「部分缺失且扫得下去」必须并入丢根计数（两个分支同形）。
    #[test]
    fn 扫描根部分缺失必须计数() {
        let src = include_str!("../commands/finder.rs");
        let needle = concat!("dropped_roots += missing.", "len()");
        assert_eq!(
            src.matches(needle).count(),
            2,
            "默认目录分支与自填目录分支都要把缺失并进丢根计数"
        );
    }

    /// R5a-M02：删除臂三处落点名必须带单调序号（同名项不得互相覆盖）。
    #[test]
    fn 删除臂落点名必须带序号() {
        let src = include_str!("native/startup.rs");
        for tag in ["reg", "folder", "task"] {
            let needle = format!(concat!("{{stamp}}_{{seq:04}}_", "{}_{{safe"), tag);
            assert!(
                src.contains(&needle),
                "落点名形态必须带单调序号（防同批同名备份互相覆盖）: {tag}"
            );
        }
    }
}
