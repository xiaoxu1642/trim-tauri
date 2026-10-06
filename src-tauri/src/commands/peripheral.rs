//! peripheral 域（D 批）：外设优化 3 条通道
//!
//! 对照 Electron main.js 6891-7040 + src/scripts-powershell/peripheral-scripts.js。
//!
//! 形态（2026-10-07）：外设优化从**独立子窗**改为**应用内自绘弹窗**（`src/scripts/peripheral.js`
//! 走主窗 `window.modal.create`），窗口 label `peripheral` 随之退役。三条通道的唯一调用方
//! 变成主窗，档位因此一律收紧为主窗档（`guard::MAIN`，原来放行全部应用窗口）。
//!
//! 安全/语义（PE-3/PE-4/N1/N2/PE-5 全部保留）：
//! - 应用值白名单以主进程为唯一权威（win32/mouse 两组固定取值集合），
//!   未命中不再静默跳过，而是整批拒绝（PE-3，防渲染层漏更导致假成功）。
//! - 两项全写 HKLM，apply/restore 恒需管理员（PE-4）。
//! - 缺省/-1 表示该组不改；两组都 -1 拒绝空应用。
//! - 原生写入前用 `reg.exe export` 导出父键 .reg 备份（`engine/native/peripheral.rs`，
//!   非 PowerShell）；成功后主进程修剪备份目录（保留 10 份，旧的进回收站）。
//! - 「还原修改前的值」= 导入最新一份备份 .reg，与「恢复默认」语义分开（N1/PE-5）。
//! - **2026-10-06 起本窗瘦身为两组**（win32 / mouse）：键盘队列深度与端口路由收编进
//!   优化中心 `tf_keyboard`（固定写 8 + 驱动默认端口档），`keyboard` / `kbdports`
//!   键不再受理 —— 白名单里它们随组件一并删除，旧渲染层（若有残留调用）必被整批拒绝。

use serde_json::{json, Value};
use tauri::WebviewWindow;

use crate::engine::{guard, log, native, paths};

/// PE-3：主进程唯一权威合法值集合
const ALLOWED_WIN32: &[i64] = &[2, 26, 36, 38, 40];
const ALLOWED_MOUSE: &[i64] = &[16, 18, 20, 22, 100];

fn allowed_for(key: &str) -> Option<&'static [i64]> {
    match key {
        "win32" => Some(ALLOWED_WIN32),
        "mouse" => Some(ALLOWED_MOUSE),
        _ => None,
    }
}

/// peripheral:query —— 读两组当前值
///
/// S3：纯 Rust 原生，无 PS 回退。
#[tauri::command]
pub async fn peripheral_query<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    match tauri::async_runtime::spawn_blocking(native::peripheral_query).await {
        Ok(Ok(data)) => Ok(json!({ "success": true, "data": data, "engine": "rust" })),
        Ok(Err(e)) => Ok(json!({ "success": false, "message": format!("原生读取失败: {e}") })),
        Err(e) => Ok(json!({ "success": false, "message": format!("读取任务异常: {e}") })),
    }
}

#[derive(serde::Deserialize, Default)]
pub struct ApplyOptions {
    win32: Option<Value>,
    mouse: Option<Value>,
}

/// peripheral:apply —— 白名单校验后写 HKLM（成功修剪备份）
///
/// 档位（2026-10-07）：外设优化改应用内弹窗后，唯一调用方是主窗，故用 `guard::MAIN`。
/// 真正的闸门始终是下面的 `is_admin()` + 取值白名单（PE-3/PE-4）。
#[tauri::command]
pub async fn peripheral_apply<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    options: Option<ApplyOptions>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if !crate::engine::sysinfo::is_admin() {
        return Ok(json!({
            "success": false, "needAdmin": true,
            "message": "外设优化需要管理员权限，请先提权"
        }));
    }
    let opts = options.unwrap_or_default();

    // null/缺省 → -1（该组不改）；显式整数必须命中白名单，否则记下非法组
    let mut filtered = serde_json::Map::new();
    let mut invalid: Vec<&str> = Vec::new();
    for (key, raw) in [("win32", opts.win32), ("mouse", opts.mouse)] {
        match normalize_option(raw) {
            None => {
                filtered.insert(key.into(), json!(-1));
            }
            Some(v) => {
                if allowed_for(key).is_some_and(|list| list.contains(&v)) {
                    filtered.insert(key.into(), json!(v));
                } else {
                    invalid.push(key);
                }
            }
        }
    }
    if !invalid.is_empty() {
        return Ok(json!({
            "success": false,
            "message": format!("包含未获允许的取值（{}），已拒绝本次修改", invalid.join("、"))
        }));
    }
    let all_skip = filtered.values().all(|v| v.as_i64() == Some(-1));
    if all_skip {
        return Ok(json!({ "success": false, "message": "没有需要应用的设置" }));
    }

    let payload = Value::Object(filtered).to_string();

    // S3：纯 Rust 原生
    let opts_val: Value = serde_json::from_str(&payload).unwrap_or(json!({}));
    match crate::engine::native::peripheral_apply(&opts_val) {
        Ok(()) => {
            log::write_log("info", "外设优化应用原生完成");
            prune_backups(10);
            Ok(json!({ "success": true, "message": "完成" }))
        }
        Err(e) => {
            log::write_log("warn", &format!("外设优化应用原生失败: {e}"));
            Ok(json!({ "success": false, "message": format!("写入注册表失败: {e}") }))
        }
    }
}

/// null/空串 → None（跳过）；整数 → Some；非整数 → 视为非法（给 0 以落进白名单不命中）
fn normalize_option(raw: Option<Value>) -> Option<i64> {
    match raw {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::Number(n)) => n.as_i64().or(Some(-9999)),
        _ => Some(-9999),
    }
}

/// 修剪外设备份目录：backup_YYYYMMDD_HHMMSS.reg 按名倒序保留 keep 份，更旧的进回收站
fn prune_backups(keep: usize) {
    // 裁根 = 写侧单根（v2-L4P-14，B-2/C-3 用户拍板 D-1）：老根是升级前备份的唯一还原
    // 依据，AGENTS §9.2① 冻结「老根只读不裁」。此前把 backup_read_dirs 的读兜底清单
    // 直接当裁根清单用，超额老根会被投回收站——文档与代码互相说谎（L4 B-2/C-3）。
    // 老根超额文件宁可留存，读取兜底仍可见、可还原。
    let dirs = vec![paths::backup_write_dir("peripheral-backup")];

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        let mut batches: Vec<(String, Vec<String>)> = Vec::new();
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            // v2-M12：修剪必须按**批次**算。一次 apply 产出同时间戳的 N 个分片，
            // 若按文件数保留 10 份，三键全选时只剩 3 批半、且会把某一批切成残缺组
            // （残缺组在还原侧就是「导入失败一部分」）。
            let Some(batch) = backup_batch_of(&name) else { continue };
            match batches.iter_mut().find(|(b, _)| *b == batch) {
                Some((_, list)) => list.push(name),
                None => batches.push((batch.to_string(), vec![name])),
            }
        }
        batches.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, names) in batches.into_iter().skip(keep) {
            for name in names {
                let p = dir.join(&name);
                if let Err(e) = trim_finder::scan::recycle::send_to_trash_os(p.as_os_str()) {
                    log::write_log("warn", &format!("旧外设备份移入回收站失败: {name} -> {e}"));
                }
            }
        }
    }
}

/// 外设备份文件名里的批次标记：`backup_YYYYMMDD_HHMMSS[_<分片号>].reg`，返回中段 15 位时间戳。
///
/// v2-M12：旧断言是「长度必须正好 26」的定长名，只认单份备份 ⇒ 分片名既不被 prune 承认
/// （于是永远不清理、无上限增长），也无法在还原侧归成一批。分片号只认纯数字，
/// 目的是让「用户自己放进这个目录的文件」不被当成备份去修剪或删除。
fn backup_batch_of(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("backup_")?.strip_suffix(".reg")?;
    let b = rest.as_bytes();
    // 8 位日期 + '_' + 6 位时间
    if b.len() < 15 || b[8] != b'_' || !b[..8].iter().all(|c| c.is_ascii_digit()) || !b[9..15].iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    match rest[15..].strip_prefix('_') {
        None if rest.len() == 15 => Some(&rest[..15]),
        Some(shard) if !shard.is_empty() && shard.as_bytes().iter().all(|c| c.is_ascii_digit()) => Some(&rest[..15]),
        _ => None,
    }
}

/// peripheral:restore-backup —— 导入**最新一批**备份 .reg（v2-M12 起同批可能含多个分片）
///
/// 档位同 `peripheral_apply`（2026-10-07）：唯一调用方是主窗弹窗，真正的闸门是 `is_admin()`
/// 与「文件名必须是 `backup_<15 位时间戳>[_<数字分片号>].reg` 且只在本应用备份目录内取件」
/// 的自产文件约束，不含任意路径入参。
#[tauri::command]
pub async fn peripheral_restore_backup<R: tauri::Runtime>(
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if !crate::engine::sysinfo::is_admin() {
        return Ok(json!({
            "success": false, "needAdmin": true,
            "message": "外设优化需要管理员权限，请先提权"
        }));
    }
    // S3：纯 Rust 原生
    let v = match crate::engine::native::peripheral_restore() {
        Ok(v) => {
            log::write_log("info", "外设恢复原生完成");
            v
        }
        Err(e) => {
            log::write_log("warn", &format!("外设恢复原生失败: {e}"));
            return Ok(json!({ "success": false, "message": format!("还原备份失败: {e}") }));
        }
    };
    if v.get("ok").and_then(|x| x.as_bool()) != Some(true) {
        let restored = v.get("restored").and_then(|x| x.as_i64()).unwrap_or(0);
        let total = v.get("total").and_then(|x| x.as_i64()).unwrap_or(0);
        let reason = v.get("reason").and_then(|x| x.as_str()).unwrap_or("");
        // v2-M12：`partial` 是本条的关键新分支——一批里有分片没导进去时，旧回执会把它
        // 算成 ok（或干脆只导一个分片就报成功），用户拿到绿色提示却仍有键没还原。
        let msg = match reason {
            "no-backup" => "还没有可用的备份（先应用一次优化后会自动备份）".to_string(),
            "import-failed" => "导入备份失败，备份文件可能已损坏".to_string(),
            "partial" => format!(
                "只导入了 {restored}/{total} 个备份分片，未导入的键仍停留在优化后的值；可重试一次"
            ),
            _ => "还原备份失败".to_string(),
        };
        return Ok(json!({
            "success": false,
            "partial": reason == "partial",
            "message": msg,
            "data": { "restored": restored, "total": total },
        }));
    }
    Ok(json!({
        "success": true,
        "data": {
            "file": v.get("file"),
            "restored": v.get("restored"),
            "total": v.get("total"),
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_value_tables() {
        assert!(allowed_for("win32").unwrap().contains(&38));
        assert!(allowed_for("mouse").unwrap().contains(&16));
        // PE-3：白名单外取值不允许
        assert!(!allowed_for("win32").unwrap().contains(&99));
        assert!(allowed_for("unknown").is_none());
        // 0.6.6：键盘组与端口组随「更多调优项」瘦身下线，白名单必须同步清空——
        // 一边留白名单、另一边删写入逻辑会造出「校验过、写不进」的静默假成功。
        assert!(allowed_for("keyboard").is_none(), "keyboard 组应已下线");
        assert!(allowed_for("kbdports").is_none(), "kbdports 组应已下线");
    }

    /// 键盘 / 端口组下线（2026-10-06）的两端一致性：白名单与 native 侧必须**同时**删干净。
    ///
    /// 反面形态（本测试正是为它写的）：只删一侧 —— 白名单留着而 native 不写 ⇒
    /// 「校验通过、写不进」的静默假成功；native 留着而白名单删了 ⇒ 残留死代码随时可能
    /// 被重新接线。两侧都断「已删除」，任一侧残留即红。
    /// 另：备份按父键去重的守卫**必须保留**（0.6.6 起虽无同父键多值场景，但它是
    /// 2026-10-03 为 kbdclass 引入的修复，删除会让未来同类写组静默重演多导 .reg）。
    #[test]
    fn 键盘与端口组在白名单与native两侧同步下线() {
        assert!(allowed_for("keyboard").is_none(), "keyboard 白名单应已删除");
        assert!(allowed_for("kbdports").is_none(), "kbdports 白名单应已删除");
        assert!(
            allowed_for("win32").is_some() && allowed_for("mouse").is_some(),
            "win32 / mouse 两组是本窗剩下的全部能力，不能跟着一起误删"
        );
        let native = include_str!("../engine/native/peripheral.rs");
        assert!(
            !native.contains("KBD_PORT_PRESETS"),
            "native 预设表应随端口组下线一并删除（残留即死代码）"
        );
        assert!(
            !native.contains("kbdConnectMultiple") && !native.contains("KeyboardDataQueueSize"),
            "native 查询 / 写入不应再引用键盘值"
        );
        assert!(
            native.contains("if backed_up.contains(subkey) { continue; }"),
            "按父键去重的备份守卫必须保留（kbdclass 时代引入，防未来同类写组重演）"
        );
    }

    #[test]
    fn normalize_option_skips_and_rejects() {
        assert_eq!(normalize_option(None), None);
        assert_eq!(normalize_option(Some(Value::Null)), None);
        assert_eq!(normalize_option(Some(json!(""))), None);
        assert_eq!(normalize_option(Some(json!(38))), Some(38));
        // 非整数给哨兵值，白名单必不命中
        assert_eq!(normalize_option(Some(json!(1.5))), Some(-9999));
        assert_eq!(normalize_option(Some(json!("x"))), Some(-9999));
    }

    /// v2-M12：备份名要能认出**批次**（同一次 apply 的多个分片共用时间戳），
    /// 且分片号只认纯数字——用户自己丢进备份目录的文件既不能被 prune 当备份删掉，
    /// 也不能在还原侧被归成一批。
    #[test]
    fn backup_batch_recognises_shards() {
        assert_eq!(
            backup_batch_of("backup_20260924_123000.reg"),
            Some("20260924_123000"),
            "旧版单份名必须仍然认得（否则历史备份永不修剪）"
        );
        assert_eq!(
            backup_batch_of("backup_20260924_123000_1.reg"),
            Some("20260924_123000")
        );
        assert_eq!(
            backup_batch_of("backup_20260924_123000_12.reg"),
            Some("20260924_123000")
        );
        assert_eq!(backup_batch_of("backup_2026924_123000.reg"), None); // 年份 7 位
        assert_eq!(backup_batch_of("backup_20260924_12300.reg"), None); // 秒 5 位
        assert_eq!(backup_batch_of("backup_20260924_123000_x.reg"), None); // 分片号非数字
        assert_eq!(backup_batch_of("backup_20260924_123000_.reg"), None); // 空分片号
        assert_eq!(backup_batch_of("backup_20260924_123000.reg.bak"), None);
        assert_eq!(backup_batch_of("evil.reg"), None);
        assert_eq!(backup_batch_of("notes.txt"), None);
    }
}
