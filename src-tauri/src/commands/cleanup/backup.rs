//! cleanup:reg-backup-* 与 cleanup:file-backup-*（C-4 还原入口）。
//!
//! 备份文件名先过白名单校验才拼路径（防目录穿越）；跨根列表必须把「来自老根」标出来，
//! 且封条缺失也要列出——那是升级前唯一可还原的依据。
//! 副本按 `<规则id>/` 存放、跨批次共享，裁剪按清单条目删而不是按批次时间戳。

use crate::engine::{guard, log};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tauri::WebviewWindow;
// ==================== cleanup:reg-backup-*（C-4 注册表备份还原入口） ====================
// cleanup_execute 的 regKeys 分支在删除前 export 整键到 <数据根>\cleanup-reg-backup
// （文件名 {ms时间戳}_reg_{规则id}_{序号}.reg）。此前只有写没有读——「能清不能还」；
// 本节补列表与还原面。还原 = reg import 合并回系统（把备份时的键/值原样加回）。
//
// 落点口径（N1，2026-09-29）：**写恒新根**（`backup_write_dir`），**读跨两根**
// （`backup_read_entries` / `resolve_backup_file`）。上游 Electron 轨的 PS 写的是
// `%APPDATA%\Trim\cleanup-reg-backup`（`vendor/upstream-js/src/scripts-powershell/cleanup-scripts.js:1411`），
// 只读新根会让升级用户的老批备份在列表里凭空消失，与「这台机器没做过可还原操作」无法区分。

/// 备份根标识：列表项要告诉用户这份来自当前数据目录还是升级前的老根
pub(super) const REG_BACKUP_SUB: &str = "cleanup-reg-backup";

/// 备份文件名准入：单段文件名、字符集 [A-Za-z0-9_- .]、.reg 结尾——防路径穿越与任意导入
pub(crate) fn valid_backup_file_name(name: &str) -> bool {
    // 判据真源在 engine::backup_purge：列表/还原/清除三处必须同一份，
    // 否则会出现「列表能看见、清除点不动」的两套口径。
    crate::engine::backup_purge::valid_reg_backup_name(name)
}

/// cleanup:reg-backup-list — 列出清理域注册表备份（只读；≤50 条按 mtime 倒序）
///
/// R4-L05：与姊妹命令 `cleanup_file_backup_list` 同形改 async + spawn_blocking ——
/// 该目录可写、条数没有硬上限，逐条 `metadata()` 曾是同步主线程 I/O。
#[tauri::command]
pub async fn cleanup_reg_backup_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    tauri::async_runtime::spawn_blocking(collect_reg_backup_list)
        .await
        .unwrap_or_else(|e| json!({ "success": false, "message": format!("备份清单读取任务异常: {e}") }))
}

fn collect_reg_backup_list() -> Value {
    // N1：跨根列举（新根在前、同名只留新根那份）。老根那份必须标来源，否则用户会以为
    // 当前版本偷偷写了它；总数与总体积按**全量**算，列表只截最近 50 份。
    let mut items: Vec<Value> = Vec::new();
    let mut total_bytes: u64 = 0;
    let (entries, unreadable) = crate::engine::paths::read_entries_across_roots_state(
        crate::engine::paths::backup_read_dirs(REG_BACKUP_SUB),
    );
    for (p, from_legacy) in entries {
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
        "unreadable": unreadable,
        "degraded": unreadable > 0,
        "degradedReason": if unreadable > 0 { Some("部分注册表备份目录/文件不可读，列表可能不完整") } else { None },
        "degradedSource": "cleanup.regBackupList",
    } })
}

/// cleanup:reg-backup-restore — reg import 把单个备份合并回注册表（主窗专属）。
/// import 是「合并加回」不是「回滚快照」：只还原备份里存在的键/值，不删除此后产生的新数据。
#[tauri::command]
pub async fn cleanup_reg_backup_restore<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    file: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    tauri::async_runtime::spawn_blocking(move || {
        cleanup_reg_backup_restore_blocking(
            file,
            crate::engine::reg_backup::reg_import_apply_sections,
        )
    })
        .await
        .unwrap_or_else(|e| {
            json!({ "success": false, "message": format!("注册表备份还原任务异常: {e}") })
        })
}

fn cleanup_reg_backup_restore_blocking(
    file: String,
    apply_sections: impl FnOnce(
        &crate::engine::reg_backup::AdmittedSections,
    ) -> Result<
        crate::engine::reg_backup::RegImportStat,
        crate::engine::reg_backup::RegImportFailure,
    >,
) -> Value {
    if !valid_backup_file_name(file.trim()) {
        return json!({ "success": false, "message": "备份文件名非法" });
    }
    // 还原侧必须与列表侧共用同一套跨根解析：列表能列出老根那份，还原就只能从同一根取，
    // 否则"看得见、点不动"（N1）
    let Some(path) = crate::engine::paths::resolve_backup_file(REG_BACKUP_SUB, file.trim()) else {
        return json!({ "success": false, "message": "备份文件不存在" });
    };
    // N9：清理域此前"文件名白名单过了就直接 reg import"，而卸载域同一威胁模型下有完整还原闸。
    // 调同一个公共件 —— 一份被手工改成 `[HKEY_LOCAL_MACHINE\SOFTWARE]` 的 .reg，
    // 不该因为"它是备份文件"就被写进注册表；老根兜底纳进来的 Electron 轨文件形状更不可信。
    // v5-K06 批次 3：闸侧与执行臂同一份解析产物（sections 直接进执行臂，不再二次读盘解析）；
    // R4-M03 收尾：seal 不再丢弃，回执带 sealWasRecorded（与卸载域同口径）。
    let crate::engine::reg_backup::RegBackupCheck { keys, seal, sections } =
        match crate::engine::reg_backup::reg_backup_restore_guards(
            &path,
            file.trim(),
            "cleanup",
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
    // 封条核对 / HKLM 提权）原样在上游跑完，执行臂吃闸侧同一份 sections；.reg 文本格式与封条链未动。
    let imported = apply_sections(&sections);
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
        json!({ "success": true, "data": {
            "restored": true,
            "keys": keys,
            "sealWasRecorded": seal == "ok",
        } })
    } else {
        // P2-05：失败回执带统计（已写入/已删除多少），文案只陈述已发生的事实 +
        // 失败原因 + 「已写入部分不会回滚」，不承诺「可直接重试」。
        let failure = imported.err().unwrap_or_default();
        let detail = failure.user_message();
        log::write_log("error", &format!("cleanup 注册表备份还原失败: {file} {detail}"));
        json!({ "success": false, "message": detail })
    }
}

// ==================== cleanup:file-backup-*（C-4 永久删批次备份还原） ====================
// 常规清理链是「永久删」产品语义（v3.3.0 拍板），2026-09-28 小旭拍板补删前备份：
// native::cleanup_execute 在永久删除前把文件复制到 cleanup-files-backup\<规则id>\ 下
// （文件名 `<批次ms>_<序号>_<原名>`，N10 补的批次段），
// 并落 manifest-<ts>.json（条目=备份相对名 ↔ 原始路径）。备份是语义增强不是删除
// 前提：复制失败/超上限照常删除并记账（上限常量见 `src-tauri/src/engine/native/cleanup.rs`
// 的 `FILE_BACKUP_MAX_FILE` / `FILE_BACKUP_MAX_BATCH`）。

pub(super) const FILES_BACKUP_SUB: &str = "cleanup-files-backup";

/// cleanup:backup-purge — 清除勾选的备份（主窗专属，备份还原页唯一入口）。
///
/// 删除动作收在 `engine::backup_purge`：四类备份（清理域注册表 / 文件批次 /
/// 卸载域注册表 / 卸载还原包）共用同一套「回收站优先 + 根判定 + 连带件同生同死」。
/// 这里只做来源校验与「一条失败不拖垮整批」的编排，不自己拼路径、不自己删文件。
///
/// 为什么是 MAIN 而不是 readonly：它删的是用户的还原依据，属不可逆动作，
/// 按 AGENTS §3「谁真的需要调它」——消费方只有主窗备份还原页，四个子窗零调用点。
#[tauri::command]
pub async fn cleanup_backup_purge<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    items: Vec<Value>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // 入参逐条过闸：kind 必须命中四种之一，name 必须非空且不含路径分隔符。
    // 名字的字符级准入仍在引擎侧（每类各有一份形状判据），这里挡的是明显越界形态。
    let mut targets: Vec<crate::engine::backup_purge::Target> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();
    for it in &items {
        let kind = it.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let name = it.get("name").and_then(|v| v.as_str()).unwrap_or("").trim();
        let Some(kind) = crate::engine::backup_purge::Kind::parse(kind) else {
            rejected.push(json!({ "name": name, "reason": "未知的备份种类" }));
            continue;
        };
        if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
            rejected.push(json!({ "name": name, "reason": "备份名非法" }));
            continue;
        }
        targets.push(crate::engine::backup_purge::Target {
            kind,
            name: name.to_string(),
        });
    }
    if targets.is_empty() {
        return json!({
            "success": false,
            "message": "没有可删除的备份项",
            "data": { "removed": 0, "failed": rejected, "items": [] }
        });
    }
    let resp = tauri::async_runtime::spawn_blocking(move || {
        crate::engine::backup_purge::purge(&targets)
    })
    .await
    .unwrap_or_else(|e| {
        // R4-M08-M02：JoinError 兜底必须补与 purge 失败项同 shape 的失败项——
        // failed 置空会让 success 位派生把任务异常误判成全成功，渲染层照常报「已清除」。
        let reason = format!("备份清除任务异常: {e}");
        json!({
            "removed": 0,
            "failed": [{ "name": "", "reason": reason }],
            "items": [],
            "message": reason,
        })
    });
    let mut data = resp;
    if !rejected.is_empty() {
        if let Some(failed) = data.get_mut("failed").and_then(|v| v.as_array_mut()) {
            failed.extend(rejected);
        }
    }
    backup_purge_receipt(data)
}

/// 备份清除回执组装（R4-M08-M02）：success 位按引擎回执派生，不硬编码 true。
fn backup_purge_receipt(data: Value) -> Value {
    // 整批失败（removed==0 且 failed 非空，含 JoinError 兜底补项）必须 success:false——
    // 命令层此前无条件 success:true，把根判定全失败降级成清除成功提示。
    // 部分失败（removed>0 且 failed 非空）保持 success:true，failed 明细交给渲染层
    // 既有 warning 分支如实告警；全成功自然为 true。removed 缺失按零处理（fail-closed）。
    let removed = data.get("removed").and_then(|v| v.as_u64()).unwrap_or(0);
    let failed_non_empty = data
        .get("failed")
        .and_then(|v| v.as_array())
        .map_or(false, |a| !a.is_empty());
    let success = !(failed_non_empty && removed == 0);
    json!({ "success": success, "data": data })
}

/// manifest 文件名准入：`manifest-<纯数字>.json`——防路径穿越
pub(crate) fn valid_files_manifest_name(name: &str) -> bool {
    crate::engine::backup_purge::valid_file_manifest_name(name)
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
///
/// R4-M11：改 async + spawn_blocking（读全部清单曾是同步主线程 I/O），entries 只借用
/// 遍历不再深克隆；回执字段与口径不变。
#[tauri::command]
pub async fn cleanup_file_backup_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    tauri::async_runtime::spawn_blocking(collect_file_backup_list)
        .await
        .unwrap_or_else(|e| json!({ "success": false, "message": format!("备份清单读取任务异常: {e}") }))
}

fn collect_file_backup_list() -> Value {
    let mut items: Vec<Value> = Vec::new();
    let mut total_bytes: i64 = 0;
    let (entries, unreadable) = crate::engine::paths::read_entries_across_roots_state(
        crate::engine::paths::backup_read_dirs(FILES_BACKUP_SUB),
    );
    for (p, from_legacy) in entries {
        let Some(name) = p.file_name().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        if !valid_files_manifest_name(&name) || !p.is_file() {
            continue;
        }
        let Ok(meta) = p.metadata() else { continue };
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        let entries = v.get("entries").and_then(|e| e.as_array());
        let total: i64 = entries
            .map(|arr| arr.iter().filter_map(|e| e.get("size").and_then(|s| s.as_i64())).sum())
            .unwrap_or(0);
        total_bytes = total_bytes.saturating_add(total);
        items.push(json!({
            "file": name,
            "ts": v.get("ts").and_then(|t| t.as_i64()).unwrap_or(0),
            "count": entries.map(|a| a.len()).unwrap_or(0),
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
        "unreadable": unreadable,
        "degraded": unreadable > 0,
        "degradedReason": if unreadable > 0 { Some("部分备份目录/清单不可读，列表可能不完整") } else { None },
        "degradedSource": "cleanup.fileBackupList",
    } })
}

/// 文件备份清单的共享解析段：定位清单 → 读盘 → 解析。批量还原整批只走这里一次——
/// 逐文件命令每条都重读重解析整份清单是 O(批次×清单)，大批次实测分钟级纯开销。
/// B1-批（2026-11-13）：单条 `cleanup:file-backup-restore` 整链摘除（D4 零调用方棘轮），
/// 前端整批还原改走 `cleanup:file-backup-restore-batch`（indexes=[i] 等价单条）。
fn parse_files_manifest(file: &str) -> Result<(PathBuf, Value), String> {
    let fname = file.trim();
    if !valid_files_manifest_name(fname) {
        return Err("备份清单名非法".into());
    }
    // 清单按跨根解析（N1）；后续取副本时必须用**同一根**，否则老根清单会去新根找文件
    let Some(mpath) = crate::engine::paths::resolve_backup_file(FILES_BACKUP_SUB, fname) else {
        return Err("备份清单不存在".into());
    };
    let Ok(text) = std::fs::read_to_string(&mpath) else {
        return Err("备份清单不存在".into());
    };
    let Ok(v) = serde_json::from_str::<Value>(&text) else {
        return Err("备份清单解析失败".into());
    };
    if v.get("entries").and_then(|e| e.as_array()).is_none() {
        return Err("备份清单结构异常".into());
    }
    Ok((mpath, v))
}

/// 批量条目数上限：防 IPC 侧一次塞入超大 indexes 数组把反序列化内存打爆；
/// 正常批次 = 单份清单条目数（备份创建侧自有批次大小上限），远低于此值。
const FILE_RESTORE_BATCH_MAX: usize = 50_000;

/// cleanup:file-backup-restore-batch — 整批把备份条目拷回原路径（主窗专属）。
/// 逐文件命令每条都重读并重解析整份清单（O(批次×清单)），大批次（上限内可达
/// 数千小文件）实测分钟级纯开销；批量版整批解析一次，逐条结果与单条命令
/// 同构回传，隔离语义不变（F4a1-L15）。
#[tauri::command]
pub async fn cleanup_file_backup_restore_batch<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    file: String,
    indexes: Vec<usize>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    tauri::async_runtime::spawn_blocking(move || {
        cleanup_file_backup_restore_batch_blocking(file, indexes)
    })
    .await
    .unwrap_or_else(|e| {
        json!({ "success": false, "message": format!("文件备份批量还原任务异常: {e}") })
    })
}

fn cleanup_file_backup_restore_batch_blocking(file: String, indexes: Vec<usize>) -> Value {
    if indexes.len() > FILE_RESTORE_BATCH_MAX {
        return json!({
            "success": false,
            "message": format!("批量条目数超上限（{FILE_RESTORE_BATCH_MAX}），请分批还原")
        });
    }
    let (mpath, v) = match parse_files_manifest(&file) {
        Ok(pair) => pair,
        Err(msg) => return json!({ "success": false, "message": msg }),
    };
    // 副本必须与清单同根（老根清单的副本躺在老根），不能固定用新根拼（N1）
    let Some(root) = mpath.parent() else {
        return json!({ "success": false, "message": "备份清单路径异常" });
    };
    let entries = v.get("entries").and_then(|e| e.as_array());
    let mut results = Vec::with_capacity(indexes.len());
    let mut restored = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    for index in indexes {
        // 逐条隔离：单条越界/拒绝只记账进 results，不中断整批（与逐条版语义一致）
        let result = match entries.and_then(|a| a.get(index)) {
            Some(entry) => restore_entry(root, entry),
            None => json!({ "success": false, "message": "条目序号越界" }),
        };
        if result.get("success").and_then(|s| s.as_bool()) != Some(true) {
            failed += 1;
        } else if result.pointer("/data/restored").and_then(|s| s.as_bool()) == Some(true) {
            restored += 1;
        } else {
            skipped += 1;
        }
        results.push(result);
    }
    json!({
        "success": true,
        "data": { "results": results, "restored": restored, "skipped": skipped, "failed": failed }
    })
}

/// 单条目还原体：从清单根目录把副本拷回原路径。批量还原逐条调用它，
/// 逐条错误隔离（一条拒绝不影响其余）由此天然成立（F4a1-L15）。
fn restore_entry(root: &Path, entry: &Value) -> Value {
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
    // C01（v7.2 R4-M01）：写回目标此前只判词法保护面——reparse/别名/系统命名空间
    // 三面全缺，篡改清单可把备份写到受保护面覆盖不到的位置。四道组合闸收口到
    // `validate_mutation_target`（不覆盖语义在下方 `dst.exists()` 早退，保持不变）。
    if let Err(why) = crate::engine::protect::validate_mutation_target(original) {
        return json!({ "success": false, "message": why });
    }
    let src = root.join(rel);
    if !src.is_file() {
        return json!({ "success": false, "message": "备份文件已不存在" });
    }
    let dst = PathBuf::from(original);
    if dst.exists() {
        return json!({
            "success": true,
            "data": {
                "restored": false,
                "skipped": true,
                "path": original,
                "reason": "目标已存在，未覆盖"
            }
        });
    }
    if let Some(parent) = dst.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return json!({ "success": false, "message": format!("原目录创建失败: {e}") });
        }
    }
    // A6-L06：`fs::copy` 会截断/覆盖既有目标；这里改用 `create_new(true)` 先占位
    // 再写副本，把「存在即不覆盖」变成系统级断言，封住检查后、写入前的并发窗口。
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&dst) {
        Ok(mut handle) => match std::fs::File::open(&src)
            .and_then(|mut reader| std::io::copy(&mut reader, &mut handle))
            .and_then(|_| handle.sync_all())
        {
            Ok(_) => {
                log::write_log("info", &format!("cleanup 文件备份已还原: {original}"));
                json!({ "success": true, "data": { "restored": true, "path": original } })
            }
            Err(e) => {
                let _ = std::fs::remove_file(&dst);
                log::write_log("error", &format!("cleanup 文件备份还原失败: {original} {e}"));
                json!({ "success": false, "message": format!("拷回失败: {e}") })
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            log::write_log("warn", &format!("cleanup 文件备份还原跳过既有目标: {original}"));
            json!({
                "success": true,
                "data": {
                    "restored": false,
                    "skipped": true,
                    "path": original,
                    "reason": "目标已存在，未覆盖"
                }
            })
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
    use super::{cleanup_file_backup_restore_batch_blocking, FILES_BACKUP_SUB};
    use serde_json::json;
    use std::fs;

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

    /// B1-批（2026-11-13）：批量还原必须 async + spawn_blocking + 主窗档，
    /// 且整批只解析一次清单、逐条走共享 restore_entry（隔离语义与逐条版一致）。
    /// 判红自证：改回 `pub fn` / 去掉 spawn_blocking / 在循环里重复解析 ⇒ 本用例红。
    #[test]
    fn 批量还原命令异步进阻塞池且整批单次解析() {
        let src = include_str!("backup.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        let cmd = src
            .split("pub async fn cleanup_file_backup_restore_batch")
            .nth(1)
            .and_then(|s| s.split("fn cleanup_file_backup_restore_batch_blocking").next())
            .expect("找不到批量还原命令");
        assert!(cmd.contains("spawn_blocking(move ||"), "批量还原没有进阻塞池");
        assert!(cmd.contains("guard::guard(&window, guard::MAIN)"), "批量还原必须是主窗档");
        let body = src
            .split("fn cleanup_file_backup_restore_batch_blocking")
            .nth(1)
            .expect("找不到批量还原 blocking 体");
        assert_eq!(body.matches("parse_files_manifest").count(), 1, "整批只允许解析一次清单");
        assert!(
            body.contains("restore_entry(root, entry)"),
            "逐条必须走共享 restore_entry，隔离语义与逐条版一致"
        );
    }

    /// restore_entry 回环（沙盒）：还原成功 → 再还原跳过既有目标（存在即不覆盖）。
    /// 判红自证：去掉 create_new 占位或 dst.exists() 早退 ⇒ 第二段断言红。
    #[test]
    fn restore_entry_tempdir_roundtrip() {
        let _sb = crate::testutil::Sandbox::new(&format!("restore-entry-{}", std::process::id()));
        let root = crate::engine::paths::backup_write_dir(FILES_BACKUP_SUB);
        fs::create_dir_all(&root).expect("备份根可创建");
        let dst = root.join("restore-entry-dst").join("a.txt");
        fs::write(root.join("a.txt"), b"hello").expect("备份副本可写");
        let entry = json!({ "file": "a.txt", "path": dst.to_string_lossy() });

        let r1 = super::restore_entry(&root, &entry);
        assert_eq!(r1.get("success").and_then(|s| s.as_bool()), Some(true), "首次还原应成功: {r1}");
        assert_eq!(r1.pointer("/data/restored").and_then(|s| s.as_bool()), Some(true));
        assert_eq!(fs::read(&dst).expect("还原产物可读"), b"hello");

        fs::write(&dst, b"CHANGED").unwrap();
        let r2 = super::restore_entry(&root, &entry);
        assert_eq!(r2.pointer("/data/skipped").and_then(|s| s.as_bool()), Some(true), "既有目标必须跳过: {r2}");
        assert_eq!(fs::read(&dst).expect("目标不得被覆盖"), b"CHANGED");
    }

    /// R4-M11：命令必须是 async + spawn_blocking，entries 不再深克隆。
    /// 判红自证：把 `pub async` 改回 `pub fn` 或把 `.cloned()` 粘回 ⇒ 断言红。
    #[test]
    fn 备份列表命令异步且不再深克隆() {
        let src = include_str!("backup.rs");
        assert!(src.contains(concat!("pub async fn ", "cleanup_file_backup_list")), "必须是 async 命令");
        assert!(src.contains(concat!("spawn_blocking(", "collect_file_backup_list)")), "读盘必须进阻塞池");
        assert!(!src.contains(concat!(".cloned()", ".unwrap_or_default()")), "entries 不得整棵深克隆");
    }

    /// R4-M01：两条还原命令必须在阻塞池里做文件/注册表 I/O。
    ///
    /// 判红自证：把任一命令改回同步 `pub fn`，或去掉对应的
    /// `spawn_blocking` 包装 ⇒ 本用例红。
    #[test]
    fn 还原命令异步且io进阻塞池() {
        let src = include_str!("backup.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        let reg = src
            .split("pub async fn cleanup_reg_backup_restore")
            .nth(1)
            .and_then(|s| s.split("fn cleanup_reg_backup_restore_blocking").next())
            .expect("找不到清理域注册表还原命令");
        assert!(reg.contains("spawn_blocking(move ||"), "注册表还原没有进阻塞池");
        assert!(
            reg.contains("cleanup_reg_backup_restore_blocking("),
            "注册表还原没有调用 blocking helper"
        );
        assert!(
            reg.contains("reg_import_apply_sections"),
            "命令体没有把真实注册表还原执行臂传给 blocking helper"
        );

        // B1-批（2026-11-13）：单条文件还原整链摘除（D4 零调用方棘轮），文件侧
        // 改为批量命令承载阻塞池与逐条隔离，本段随接口面同步改指批量命令。
        let file = src
            .split("pub async fn cleanup_file_backup_restore_batch")
            .nth(1)
            .and_then(|s| s.split("fn cleanup_file_backup_restore_batch_blocking").next())
            .expect("找不到清理域文件批量还原命令");
        assert!(file.contains("spawn_blocking(move ||"), "文件批量还原没有进阻塞池");
        assert!(
            file.contains("cleanup_file_backup_restore_batch_blocking(file, indexes)"),
            "文件批量还原没有调用 blocking helper"
        );
    }

    /// A6-L06：目标已存在时必须 skipped + path，且原字节不变；并发抢占窗口由
    /// `create_new(true)` 封住。修前 `fs::copy` 会覆盖，去掉独占创建即红。
    #[test]
    fn backup_restore_does_not_overwrite() {
        let _sb = crate::testutil::Sandbox::new(&format!("a6-l06-cleanup-{}", std::process::id()));
        let root = crate::engine::paths::backup_write_dir(FILES_BACKUP_SUB);
        fs::create_dir_all(&root).expect("备份根可创建");
        let name = format!("manifest-{}.json", crate::engine::now_ms());
        let rel = "a6-l06-copy.txt";
        let original = root.join("a6-l06-existing.txt");
        let src = root.join(rel);
        fs::write(&src, b"BACKUP").expect("备份副本可写");
        fs::write(&original, b"KEEP-ME").expect("既有目标可写");
        let manifest = json!({
            "entries": [{ "file": rel, "path": original.to_string_lossy(), "size": 6 }]
        });
        fs::write(root.join(&name), manifest.to_string()).expect("清单可写");

        // B1-批（2026-11-13）：单条 blocking 体随整链摘除改走批量 blocking；批内单条
        // 回执结构（results[i]）与旧单条回执同构，断言口径不变。
        let out = cleanup_file_backup_restore_batch_blocking(name.clone(), vec![0]);
        let out0 = out["data"]["results"][0].clone();
        assert_eq!(out["success"], json!(true), "整批成功: {out}");
        assert_eq!(out["data"]["skipped"], json!(1), "跳过计数: {out}");
        assert_eq!(out0["success"], json!(true), "跳过是幂等成功: {out0}");
        assert_eq!(out0["data"]["restored"], json!(false));
        assert_eq!(out0["data"]["skipped"], json!(true), "修前回执无 skipped: {out0}");
        assert_eq!(out0["data"]["path"], json!(original.to_string_lossy()), "回执须带路径: {out0}");
        assert_eq!(fs::read(&original).expect("目标仍可读"), b"KEEP-ME", "原字节不得被覆盖");

        fs::remove_file(&original).expect("清理既有目标");
        let restored = cleanup_file_backup_restore_batch_blocking(name, vec![0]);
        let r0 = restored["data"]["results"][0].clone();
        assert_eq!(r0["data"]["restored"], json!(true), "目标消失后应能还原: {r0}");
        assert_eq!(fs::read(&original).expect("目标应已还原"), b"BACKUP");
    }

    /// R4-M08-M02：回执 success 位四态判红——全成功 / 部分失败 / 整批失败 / JoinError 兜底
    /// 必须各自落到正确的 success 位。判红自证：派生改回无条件 success:true ⇒ 本用例红。
    #[test]
    fn 备份清除回执success位四态派生() {
        // 全成功：failed 空 ⇒ success:true
        let all_ok = json!({ "removed": 3, "failed": [], "items": [] });
        assert_eq!(
            super::backup_purge_receipt(all_ok)["success"],
            json!(true),
            "全成功不得误红"
        );
        // 部分失败：removed>0 且 failed 非空 ⇒ success:true，failed 明细原样透传
        let partial = json!({
            "removed": 2,
            "failed": [{ "name": "a", "reason": "文件被占用" }],
            "items": [],
        });
        let resp = super::backup_purge_receipt(partial);
        assert_eq!(resp["success"], json!(true), "部分失败走前端 warning 分支: {resp}");
        assert_eq!(
            resp["data"]["failed"].as_array().map(|a| a.len()),
            Some(1),
            "部分失败明细不得丢失: {resp}"
        );
        // 整批失败：removed==0 且 failed 非空 ⇒ success:false（根判定全失败不降级）
        let all_fail = json!({
            "removed": 0,
            "failed": [{ "name": "b", "reason": "备份目录未通过根判定" }],
            "items": [],
        });
        assert_eq!(
            super::backup_purge_receipt(all_fail)["success"],
            json!(false),
            "整批失败必须 success:false"
        );
        // JoinError 兜底：removed==0、failed 带补条目 ⇒ success:false
        let join_err = json!({
            "removed": 0,
            "failed": [{ "name": "", "reason": "备份清除任务异常: panicked" }],
            "items": [],
            "message": "备份清除任务异常: panicked",
        });
        assert_eq!(
            super::backup_purge_receipt(join_err)["success"],
            json!(false),
            "JoinError 兜底必须 success:false"
        );
    }

    /// R4-M08-M02：JoinError 兜底必须补失败项（failed 不得置空）且保留任务异常字样，
    /// 命令收尾必须走派生函数而非硬编码 success:true。判红自证：兜底改回 "failed": []
    /// 或收尾改回无条件 success:true ⇒ 本用例红。
    #[test]
    fn 备份清除joinerror兜底补失败项且success派生接线() {
        let src = include_str!("backup.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        let fallback = src
            .split("crate::engine::backup_purge::purge(&targets)")
            .nth(1)
            .and_then(|s| s.split("let mut data = resp;").next())
            .expect("找不到 purge 的 JoinError 兜底段");
        assert!(fallback.contains("备份清除任务异常"), "兜底必须保留任务异常字样");
        assert!(
            fallback.contains("\"failed\": [{"),
            "JoinError 兜底必须补一条失败项，failed 不得置空"
        );
        let tail = src
            .split("let mut data = resp;")
            .nth(1)
            .and_then(|s| s.split("/// manifest 文件名准入").next())
            .expect("找不到 purge 回执收尾段");
        assert!(
            tail.contains("backup_purge_receipt(data)"),
            "回执 success 位必须走派生函数"
        );
        assert!(
            !tail.contains("\"success\": true"),
            "purge 收尾不得硬编码 success:true"
        );
    }
}

