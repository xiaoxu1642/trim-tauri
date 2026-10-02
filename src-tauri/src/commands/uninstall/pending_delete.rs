//! P1-B3 重启后删：PFRO 队列读写 + pending add/list/revoke。
//!
//! pending.xml 的形状与 PendingFileRenameOperations 的写法是重启后语义的一部分，
//! 改动等于改系统行为；本域只登记、不立即删文件。

use crate::engine::{guard, log, protect};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;
use tauri::WebviewWindow;
use super::helpers::*;
// ==================== P1-B3 重启后删（2026-10-01 拍板） ====================
// 回收站失败的「文件」项可以降级为「重启后删除」：MoveFileEx(DELAY_UNTIL_REBOOT)
// 写进系统 PendingFileRenameOperations（PFRO），下次重启由会话管理器删除。
//
// 四条硬约束（2026-10-01 拍板口径，缺一不可）：
//   · 明示 + 单独确认：只处理用户在确认框里点过头的批次，绝不静默登记；
//   · 只限回收站失败项：本模块不提供任何"直接登记"入口，调用方（渲染层）只能把
//     residueExecute 回执里 status != ok 的文件行送进来；
//   · 可撤回：登记项记进本机 state 文件，撤回 = 把 PFRO 里的对应条目摘掉（重启前有效）；
//   · 待删清单可见：pending_list 把「还挂着 / 已被重启消费 / 文件已不在」三种状态分清。
// 这是**永久删除**（不进回收站），与 AGENTS §3 回收站优先的红线冲突，属 2026-10-01
// 显式拍板的受控例外（类比 v3.3.0 常规清理永久删那次裁定）。

pub(super) const PENDING_DELETE_FILE: &str = "pending-delete.json";
pub(super) const PFRO_SUBKEY: &str = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";
pub(super) const PFRO_VALUE: &str = "PendingFileRenameOperations";

/// 登记 state 文件路径（数据目录下，含 legacy 迁移口径由 paths 统一管）
pub(super) fn pending_delete_path() -> std::path::PathBuf {
    crate::engine::paths::app_data_dir().join(PENDING_DELETE_FILE)
}

pub(super) fn pending_load() -> Value {
    let p = pending_delete_path();
    std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_str::<Value>(&String::from_utf8_lossy(&b)).ok())
        .filter(|v| v.get("version").and_then(Value::as_u64) == Some(1))
        .unwrap_or_else(|| json!({ "version": 1, "entries": [] }))
}

pub(super) fn pending_save(doc: &Value) -> Result<(), String> {
    crate::security::atomic_write_json(&pending_delete_path(), doc)
}

/// MOVEFILE 失败错误码 → 中文分档（纯函数，可测）。ACCESS_DENIED 与 SHARING_VIOLATION
/// 必须分开说：前者是权限问题（提权重试有意义），后者是占用问题（提权没用）。
pub(super) fn classify_pending_delete_error(win32_code: u32) -> &'static str {
    match win32_code {
        5 => "拒绝访问（权限不足，需管理员）",
        32 => "文件正被占用（共享冲突）",
        2 => "目标文件不存在",
        3 => "目标路径不存在",
        _ => "系统拒绝该操作",
    }
}

/// 读 PFRO（REG_MULTI_SZ）。缺失/为空按空表处理——首次登记时它经常还不存在。
pub(super) fn read_pfro() -> Result<Vec<String>, String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_VALUE_TYPE,
    };
    unsafe {
        let sk = to_wide(PFRO_SUBKEY);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        let opened = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(sk.as_ptr()),
            Some(0),
            KEY_READ,
            &mut hk,
        );
        if opened.is_err() {
            return Err(format!("打开 PFRO 键失败: {opened:?}"));
        }
        let nm = to_wide(PFRO_VALUE);
        let mut ty = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        let q = RegQueryValueExW(
            hk,
            windows::core::PCWSTR(nm.as_ptr()),
            None,
            Some(&mut ty),
            None,
            Some(&mut size),
        );
        if q.is_err() {
            let _ = RegCloseKey(hk);
            return Ok(Vec::new()); // 值不存在 = 没有待重启操作
        }
        if ty.0 != 7 || size == 0 {
            let _ = RegCloseKey(hk);
            if ty.0 != 7 {
                return Err("PFRO 值类型异常（不是 REG_MULTI_SZ），拒绝改写".to_string());
            }
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        let ok = RegQueryValueExW(
            hk,
            windows::core::PCWSTR(nm.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        );
        let _ = RegCloseKey(hk);
        if ok.is_err() {
            return Err("读取 PFRO 失败".to_string());
        }
        // MULTI_SZ 形态：str\0str\0…\0\0。空串项是"删除"对的第二个元素，必须保留语义。
        let mut out: Vec<String> = Vec::new();
        let mut cur: Vec<u16> = Vec::new();
        let words: Vec<u16> = buf[..size as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        for w in words {
            if w == 0 {
                if cur.is_empty() && out.last().map(|s: &String| s.is_empty()).unwrap_or(false) {
                    break; // 连续两个 \0 = 表结束
                }
                out.push(String::from_utf16_lossy(&cur));
                cur.clear();
            } else {
                cur.push(w);
            }
        }
        Ok(out)
    }
}

/// 写回 PFRO（REG_MULTI_SZ）。需要管理员（Session Manager 键的 DACL 只给管理员写）。
pub(super) fn write_pfro(entries: &[String]) -> Result<(), String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_MULTI_SZ,
    };
    let mut words: Vec<u16> = Vec::new();
    for e in entries {
        words.extend(to_wide(e)); // to_wide 自带结尾 NUL
    }
    if words.last() != Some(&0) {
        words.push(0);
    }
    words.push(0); // MULTI_SZ 以双 NUL 结束
    unsafe {
        let sk = to_wide(PFRO_SUBKEY);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        let opened = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(sk.as_ptr()),
            Some(0),
            KEY_SET_VALUE,
            &mut hk,
        );
        if opened.is_err() {
            // 5 = ERROR_ACCESS_DENIED：Session Manager 键的 DACL 只给管理员写
            let hint = if opened.0 == 5 {
                "（权限不足：登记/撤回重启后删除需要管理员权限，请以管理员身份运行 Trim）"
            } else {
                ""
            };
            return Err(format!("打开 PFRO 键失败: {opened:?}{hint}"));
        }
        let nm = to_wide(PFRO_VALUE);
            let r = RegSetValueExW(
            hk,
            windows::core::PCWSTR(nm.as_ptr()),
            None,
            REG_MULTI_SZ,
            Some(words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>().as_slice()),
        );
        let _ = RegCloseKey(hk);
        if r.is_err() {
            return Err(format!("写 PFRO 失败: {r:?}"));
        }
        Ok(())
    }
}

/// PFRO 里"删除 target"的登记形态：src=target、紧随其后的 dst 为空串。
pub(super) fn pfro_has_delete(entries: &[String], target: &str) -> bool {
    let t = target.trim_end_matches(['\\', '/']).to_lowercase();
    entries
        .windows(2)
        .any(|w| w[1].is_empty() && w[0].trim_end_matches(['\\', '/']).to_lowercase() == t)
}

/// 从 PFRO 里摘掉"删除 targets 中任一路径"的整对（src+dst 一起删）。
pub(super) fn pfro_strip_deletes(entries: Vec<String>, targets: &HashSet<String>) -> Vec<String> {
    let norm = |s: &str| s.trim_end_matches(['\\', '/']).to_lowercase();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < entries.len() {
        let is_ours = i + 1 < entries.len()
            && entries[i + 1].is_empty()
            && targets.contains(&norm(&entries[i]));
        if is_ours {
            i += 2; // 整对摘除
        } else {
            out.push(entries[i].clone());
            i += 1;
        }
    }
    out
}

/// 单批登记上限：口径对齐残留执行 `RESIDUE_MAX_GROUP_ITEMS=32`。PFRO 是系统级全局队列，
/// 登记逐条走 MoveFileExW，超大批次没有业务场景（可登记项天然来自「回收站删不掉」的少数派），
/// 只会拉长重启阶段会话管理器的消费时间（v2-B2，2026-10-01 复核）。
pub(super) const PENDING_ADD_MAX_ITEMS: usize = 32;

/// uninstall:pending-add — 把回收站失败的文件项登记为重启后删除（主窗档）。
/// 只接受**文件**路径（PFRO 对非空目录的延迟删除并不可靠，登记了也删不掉，
/// 与其制造"已登记=会删掉"的错觉，不如入口就拒）。
#[tauri::command]
pub async fn uninstall_pending_add<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    targets: Vec<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    if targets.is_empty() {
        return json!({ "success": false, "message": "没有要登记的目标" });
    }
    // v2-B2：单批上限在入口拦，进 spawn_blocking 之前就整批拒绝——
    // 不给「先读 PFRO 才发现超批」的无效往返，也不留半批登记的中间态。
    if targets.len() > PENDING_ADD_MAX_ITEMS {
        return json!({
            "success": false,
            "message": format!("单批登记 {} 项超上限 {PENDING_ADD_MAX_ITEMS}，请分批登记", targets.len())
        });
    }
    let res = tauri::async_runtime::spawn_blocking(move || {
        // 先读 PFRO：登记前必须确认能写（权限不足在这里就暴露，不要等到"登记完才发现撤不回"）
        let mut pfro = read_pfro()?;
        let mut doc = pending_load();
        let entries = doc["entries"].as_array_mut().ok_or("登记文件损坏")?;
        let batch = format!(
            "p{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        let mut rows: Vec<Value> = Vec::new();
        let mut added = 0usize;
        for t in &targets {
            // v2-B1（2026-10-01 复核）：PFRO 登记是**永久删**出口（不进回收站，重启后由
            // 会话管理器执行），受保护路径判定必须在命令体内前置——渲染层 confirmDanger
            // 只是第一层，命令体内再判一次才与其余删除链同口径。刻意放在 is_file 之前：
            // 空串 / 盘符根 / 受保护根下的路径无论当前存在与否都拒，不给「登记窗口期
            // 路径状态变化」留缝，也与 protect 判定的 fail-closed 语义一致。
            if protect::is_path_protected(t) {
                rows.push(json!({ "target": t, "status": "skip", "message": "目标位于受保护路径（或无法归一化），拒绝登记重启后删除" }));
                continue;
            }
            let path = Path::new(t);
            if t.trim().is_empty() || !path.is_file() {
                rows.push(json!({ "target": t, "status": "skip", "message": "目标不是存在的文件（目录不支持重启后删）" }));
                continue;
            }
            let already = pfro_has_delete(&pfro, t)
                || entries.iter().any(|e| {
                    e["target"].as_str().map(|s| s.eq_ignore_ascii_case(t)).unwrap_or(false)
                });
            if already {
                rows.push(json!({ "target": t, "status": "skip", "message": "已登记过，不重复登记" }));
                continue;
            }
            use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
            // DELAY_UNTIL_REBOOT 只登记、立即返回；删除动作发生在下次重启的会话管理器阶段
            let moved = unsafe {
                MoveFileExW(
                    windows::core::PCWSTR(to_wide(t).as_ptr()),
                    None,
                    MOVEFILE_DELAY_UNTIL_REBOOT,
                )
            };
            match moved {
                Ok(()) => {
                    pfro.push(t.clone());
                    pfro.push(String::new());
                    entries.push(json!({ "target": t, "batchId": batch, "addedAt": batch.trim_start_matches('p') }));
                    rows.push(json!({ "target": t, "status": "ok", "message": "已登记，下次重启时删除" }));
                    added += 1;
                }
                Err(e) => {
                    let code = e.code().0 as u32 & 0xFFFF;
                    rows.push(json!({ "target": t, "status": "fail", "message": format!("{}（错误码 {code}）", classify_pending_delete_error(code)) }));
                }
            }
        }
        if added > 0 {
            write_pfro(&pfro)?;
            pending_save(&doc)?;
            log::flush_sync();
            log::write_log("warn", &format!("重启后删除：本批登记 {added} 项（永久删除，不进回收站）"));
        }
        Ok::<Vec<Value>, String>(rows)
    })
    .await;
    match res {
        Ok(Ok(rows)) => {
            let ok = rows.iter().filter(|r| r["status"] == "ok").count();
            json!({ "success": true, "data": { "added": ok, "details": rows } })
        }
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("登记执行异常: {e}") }),
    }
}

/// uninstall:pending-list — 待删清单（主窗档，只读）。
/// 三个状态分开：pending（PFRO 还挂着）/ consumed（重启已消费）/ missing（文件已不在）。
#[tauri::command]
pub async fn uninstall_pending_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<Value, String> {
        let doc = pending_load();
        let pfro = read_pfro()?;
        let rows: Vec<Value> = doc["entries"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|e| {
                let t = e["target"].as_str().unwrap_or_default().to_string();
                let pending = pfro_has_delete(&pfro, &t);
                let exists = Path::new(&t).is_file();
                let status = if pending {
                    "pending"
                } else if !exists {
                    "missing"
                } else {
                    "consumed"
                };
                json!({
                    "target": t,
                    "batchId": e["batchId"],
                    "addedAt": e["addedAt"],
                    "status": status,
                })
            })
            .collect();
        Ok(json!({ "entries": rows, "pfroReadable": true }))
    })
    .await;
    match res {
        Ok(Ok(v)) => json!({ "success": true, "data": v }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("读取失败: {e}") }),
    }
}

/// uninstall:pending-revoke — 撤回（主窗档）。不传 batchId = 撤回本机全部登记项。
/// 撤回动作本身要写 PFRO（管理员权限），失败时明确报错且不动 state —— 两边必须一致。
#[tauri::command]
pub async fn uninstall_pending_revoke<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    batch_id: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<usize, String> {
        let mut doc = pending_load();
        let scoped: HashSet<String> = doc["entries"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter(|e| batch_id.as_deref().map(|b| e["batchId"].as_str() == Some(b)).unwrap_or(true))
            .filter_map(|e| e["target"].as_str().map(|s| s.trim_end_matches(['\\', '/']).to_lowercase()))
            .collect();
        if scoped.is_empty() {
            return Ok(0usize);
        }
        let pfro = read_pfro()?;
        let stripped = pfro_strip_deletes(pfro, &scoped);
        write_pfro(&stripped)?;
        let remaining: Vec<Value> = doc["entries"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter(|e| {
                let t = e["target"]
                    .as_str()
                    .map(|s| s.trim_end_matches(['\\', '/']).to_lowercase())
                    .unwrap_or_default();
                !scoped.contains(&t)
            })
            .cloned()
            .collect();
        doc["entries"] = Value::Array(remaining);
        pending_save(&doc)?;
        log::flush_sync();
        log::write_log("info", &format!("重启后删除：撤回 {} 项登记", scoped.len()));
        Ok(scoped.len())
    })
    .await;
    match res {
        Ok(Ok(n)) => json!({ "success": true, "data": { "revoked": n } }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("撤回执行异常: {e}") }),
    }
}

