//! reg-backup-*（D1 还原入口 + D2 封条）、batch-*（还原包列表与整批还原）、report-*（批次报告）。
//!
//! 命令名与主窗 guard 档位不变；备份名与 batch_id 走白名单校验后才拼路径。
//! 还原点/整批还原是最后防线，默认不自动删旧（对齐 AGENTS §9.2 的「危险能力默认关」）。

use crate::engine::{guard, log};
use crate::engine::reg_backup::reg_backup_seal_state;
use serde_json::{Value, json};
use std::path::PathBuf;
use tauri::WebviewWindow;
// ==================== uninstall:reg-backup-*（D1 还原入口 + D2 封条） ====================
//
// 卸载残留的注册表删除一直是「先 export 再删」，但备份**只写不读**：删错了没有任何还原
// 入口，兜底承诺停在半路（方案 §5·D1）。这一节补列表与单项还原，并给每份备份加封条。
//
// 封条能做什么、不能做什么必须写清（Q3 拍板 + 方案 D2 的边界）：备份与封条同在
// **用户可写**的数据目录里，同一个用户（或以该用户身份跑的任意进程）可以同时改写两者，
// 所以封条只提升两类防护——半截写入/手工误改的**误污染检测**，和低权限单点篡改的**可发现性**。
// 真正的防伪需要 HKLM 侧常驻提权面，那是另一次拍板，不许在这里当成已经具备的能力。

/// 卸载域注册表备份目录：两处 export 与列表/还原共用同一入口，不再各拼一遍路径。
///
/// 写恒新根（`backup_write_dir`），**读跨两根**（`backup_read_entries` / `resolve_backup_file`）：
/// 卸载域的 `.reg` 是本仓新写的，老根理论上不该有；但 v0.2.6 之前该目录曾用
/// `app_data_dir().join(...)` 直拼，与 `backup_write_dir` 等价，故不影响实体。兜底读留着
/// 是为了与 cleanup 域同口径（那条域的旧批确实躺在 `%APPDATA%\Trim`，N1），
/// 别让"同一个还原界面"在两个域里对同一件事给出不同答案。
pub(super) const UNINSTALL_REG_BACKUP_SUB: &str = "uninstall-reg-backup";

pub(super) fn uninstall_reg_backup_dir() -> PathBuf {
    crate::engine::paths::backup_write_dir(UNINSTALL_REG_BACKUP_SUB)
}

/// 备份文件名准入：只认生成器产出的形状（`<毫秒>_<键末段>.reg`），
/// 路径穿越（`..` / `\` / `/`）与非 .reg 一律拒绝——还原是**写注册表**的通道
pub(super) fn valid_uninstall_backup_name(name: &str) -> bool {
    let n = name.trim();
    n.len() > 4
        && n.len() <= 120
        && n.ends_with(".reg")
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

// 封条与 `.reg` 严格解析的**实现已移到 `engine::reg_backup`**（N9）：清理域那条还原链
// 面对的是同一个威胁模型（用户可写目录里的一份 .reg 被拿去写注册表），复制一份正则或
// 一份切分只会让两域口径再次分叉。本文件按名字直接用，调用点与用例都不用改。

/// 把「跨根备份条目」渲染成列表项：文件名解析 + 封条核对 + 老根标记 + mtime 倒序。
///
/// 为什么单独成函数：这段逻辑决定"还原按钮有没有依据"，但它对着真实数据根测不准 ——
/// 本机有没有 `.reg` 备份会让用例变成"碰巧绿"（AGENTS §4.1 假绿教训）。拆出来才能拿
/// 临时目录当输入。
pub(super) fn render_reg_backups(entries: Vec<(PathBuf, bool)>) -> Vec<Value> {
    let mut items: Vec<Value> = Vec::new();
    for (p, from_legacy) in entries {
        let Some(name) = p.file_name().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        if !valid_uninstall_backup_name(&name) || !p.is_file() {
            continue;
        }
        let Ok(meta) = p.metadata() else { continue };
        let (seal, seal_meta) = reg_backup_seal_state(&p);
        // 文件名形如 `{毫秒}_{键末段}.reg`：时间戳直接取首段，取不到就以 mtime 为准
        let stamp = name.split('_').next().unwrap_or("").parse::<i64>().unwrap_or(0);
        items.push(json!({
            "file": name,
            "stampMs": stamp,
            "keyLeaf": name.trim_end_matches(".reg").split_once('_').map(|(_, r)| r.to_string()).unwrap_or_default(),
            "mtimeMs": meta.modified().ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
            "sizeBytes": meta.len(),
            "seal": seal,
            // 老根那份必须标来源：它是升级前的唯一还原依据，不是当前版本偷偷写的
            "fromLegacy": from_legacy,
            "target": seal_meta.get("target").and_then(Value::as_str).unwrap_or(""),
        }));
    }
    items.sort_by(|a, b| b["mtimeMs"].as_i64().cmp(&a["mtimeMs"].as_i64()));
    items
}

/// uninstall:reg-backup-list — 卸载域注册表备份列表（只读；跨新根+老根，≤50 条按 mtime 倒序）
#[tauri::command]
pub fn uninstall_reg_backup_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let mut items = render_reg_backups(crate::engine::paths::backup_read_entries(
        UNINSTALL_REG_BACKUP_SUB,
    ));
    let total_count = items.len();
    items.truncate(50);
    json!({ "success": true, "data": { "backups": items, "totalCount": total_count } })
}

/// uninstall:reg-backup-restore — 把单个备份 import 回注册表（主窗专属）。
/// import 是「合并加回」不是「回滚快照」：只还原备份里存在的键/值，不删除此后产生的新数据。
/// 四道前置闸：文件名白名单 → 严格解析目标键 → 封条核对 → 目标含 HKLM 时必须已提权。
#[tauri::command]
pub fn uninstall_reg_backup_restore<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    file: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let name = file.trim().to_string();
    if !valid_uninstall_backup_name(&name) {
        return json!({ "success": false, "message": "备份文件名非法" });
    }
    // 还原侧与列表侧必须共用同一套跨根解析：列表能列出老根那份，还原就只能从同一根取，
    // 否则"看得见、点不动"（N1）
    let Some(path) =
        crate::engine::paths::resolve_backup_file(UNINSTALL_REG_BACKUP_SUB, &name)
    else {
        return json!({ "success": false, "message": "备份文件不存在" });
    };
    // 四道闸走公共件（N9）：清理域那条链现在调的是同一个函数，两域不可能再各写一套口径
    let crate::engine::reg_backup::RegBackupCheck { keys, seal } =
        match crate::engine::reg_backup::reg_backup_restore_guards(
            &path,
            &name,
            crate::engine::sysinfo::is_admin(),
        ) {
            Ok(c) => c,
            Err(msg) => return json!({ "success": false, "message": msg }),
        };
    log::flush_sync(); // 写注册表前刷盘
    // A6（v2-R4）：原生 `.reg` 写入替换 `reg.exe import`。上面四道闸原样跑，
    // .reg 文本格式与封条链未动；原先「成功 / 非零退出 / 调用失败」三分支
    // 在原生侧塌成 Ok/Err 两分支（外部进程的退出码这一层信息本身已不存在）。
    match crate::engine::reg_backup::reg_import_apply(&path) {
        Ok(stat) => {
            log::write_log(
                "info",
                &format!(
                    "卸载域注册表备份已还原: {name}（{} 个键，写入 {} 值、删除 {} 值、删键 {}）",
                    keys.len(),
                    stat.values_written,
                    stat.values_deleted,
                    stat.keys_deleted
                ),
            );
            json!({ "success": true, "data": {
                "restored": true, "keys": keys, "sealWasRecorded": seal == "ok",
                "message": "已按备份合并回注册表（只加回备份里存在的键/值）"
            }})
        }
        Err(e) => {
            log::write_log("error", &format!("卸载域备份还原失败: {name} {e}"));
            json!({ "success": false, "message": format!("还原写入失败: {e}") })
        }
    }
}

// ==================== uninstall:batch-*（HiBit §H1 还原包列表与整批还原） ====================
//
// 与 `uninstall_reg-backup-*` 的分工必须写清，否则后来者会以为这里也能还原注册表：
// 本节的 restore **只往磁盘写文件**，注册表还原仍然只有 `uninstall_reg_backup_restore`
// 那一条通道（文件名准入 → 严格 .reg 解析 → 从正文重取键路径复算禁删面 → 封条校验）。
// 给同一个危险动作开第二个入口，等于让四道闸变成「挑一条走」。

/// uninstall:batch-list —— 本机还原包（**MAIN 档**，与同门 `uninstall_reg_backup_list` 一致：
/// 只有主窗的备份弹窗调它，四子窗没有消费方，按 readonly 放行等于白给一个目录列举面）。
/// 带体积与「zip 是否还在」的自检，界面据此能说清「这个包点还原到底会不会成功」，
/// 而不是等用户点下去才报错。
#[tauri::command]
pub fn uninstall_batch_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    json!({
        "success": true,
        "data": {
            "packs": crate::engine::restore_pack::list(50),
            "totalBytes": crate::engine::restore_pack::total_bytes(),
        }
    })
}

/// uninstall:batch-restore —— 按 manifest 把整批内容写回原位置。
///
/// 档位 MAIN：它写磁盘，且入口只在主窗的备份弹窗（与 `uninstall_batch_list` 同档）。
/// 逐条判定都在 restore_pack::restore 里：
/// 路径准入（绝对 + 不含 .. + 非受保护 + 不落 %WINDIR%）→ zip 缺条目即失败 →
/// 哈希/字节数不符即失败 → 目标已存在且内容不同则**不覆盖**（那是「卸完又装了」，
/// 覆盖等于抢掉用户现在的文件）。
#[tauri::command]
pub async fn uninstall_batch_restore<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    batch_id: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(move || {
        crate::engine::restore_pack::restore(&batch_id)
    })
    .await;
    match res {
        Ok(Ok(v)) => json!({ "success": true, "data": v }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("还原包还原异常: {e}") }),
    }
}

// ==================== uninstall:report-*（U-6 批次报告查看入口） ====================

pub(super) fn uninstall_reports_dir() -> PathBuf {
    crate::engine::paths::app_data_dir().join("uninstall-reports")
}

/// batch_id 准入：new_batch_id 形如 `2026-09-28T12-30-45-123Z`（ISO 去 :/.），
/// 字符集限定 [A-Za-z0-9-]（含 T/Z）——路径穿越（..、\、/）与非报告文件名一律拒绝。
pub(super) fn valid_batch_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// uninstall:report-list — 列出残留清理批次报告（主窗档；只读；上限 50 条按时间倒序）
#[tauri::command]
pub fn uninstall_report_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let Ok(rd) = std::fs::read_dir(uninstall_reports_dir()) else {
        return json!({ "success": true, "data": { "reports": [] } });
    };
    let mut items: Vec<Value> = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if !valid_batch_id(stem) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        // 损坏的个别报告跳过不阻断整表；details 计数在列表页就给全，点开再看明细
        let (mut ok, mut fail, mut skip) = (0i64, 0i64, 0i64);
        for d in v.get("details").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            match d.get("status").and_then(|s| s.as_str()) {
                Some("ok") => ok += 1,
                Some("fail") => fail += 1,
                _ => skip += 1,
            }
        }
        items.push(json!({
            "batchId": stem,
            "time": v.get("time").cloned().unwrap_or(Value::Null),
            "appId": v.get("appId").cloned().unwrap_or(Value::Null),
            "okCount": ok, "failCount": fail, "skipCount": skip,
        }));
    }
    // 文件名即 ISO 时间戳，倒序 = 最新在前。
    // N8：必须**先全量收集再排序再截断**。NTFS 枚举序≈文件名升序，在循环里 `break` 到 50
    // 截走的是**最旧** 50 份，随后那次排序只是在旧账里排座次 ⇒ 批次一过 50，用户刚做完
    // 的那次清理报告就不在列表里（与 N1 同症状、不同成因）。
    items.sort_by(|a, b| {
        let ka = a["batchId"].as_str().unwrap_or("");
        let kb = b["batchId"].as_str().unwrap_or("");
        kb.cmp(ka)
    });
    let total_count = items.len();
    items.truncate(50);
    json!({ "success": true, "data": { "reports": items, "totalCount": total_count } })
}

/// uninstall:report-get — 读取单个批次报告（主窗档；只读；batch_id 过字符集闸防穿越）
#[tauri::command]
pub fn uninstall_report_get<R: tauri::Runtime>(window: WebviewWindow<R>, batch_id: String) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    if !valid_batch_id(&batch_id) {
        return json!({ "success": false, "message": "batchId 非法" });
    }
    let p = uninstall_reports_dir().join(format!("{batch_id}.json"));
    let Ok(text) = std::fs::read_to_string(&p) else {
        return json!({ "success": false, "message": "报告不存在或不可读" });
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(v) => json!({ "success": true, "data": v }),
        Err(_) => json!({ "success": false, "message": "报告 JSON 解析失败" }),
    }
}

#[cfg(test)]
pub(super) mod backup_visibility_tests {
    use super::*;
    use crate::engine::reg_backup::write_reg_backup_seal;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    fn sandbox(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trim-backup-vis-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// mtime 必须显式设定：两个文件在同一毫秒内写完时，倒序断言会变成掷硬币，
    /// 于是"看起来稳定"的用例会在换机器时第一次红。
    fn touch(path: &Path, ms: u64) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_millis(ms)).unwrap();
    }

    /// N1：跨根列表必须把「来自老根」标出来，且**封条缺失也要列出**。
    /// 封条是 v0.2.6 才加的，升级前那批永远 missing —— 拒列就等于把用户唯一的
    /// 还原依据藏起来（这正是 v2-M14「已自动还原」空桩那一类：界面看不到 = 用户以为没有）。
    #[test]
    fn 跨根备份渲染标来源且缺封条仍列出() {
        let root = sandbox("render");
        let new = root.join("new");
        let legacy = root.join("legacy");
        std::fs::create_dir_all(&new).unwrap();
        std::fs::create_dir_all(&legacy).unwrap();
        let a = new.join("1700000000001_Alpha.reg");
        std::fs::write(&a, "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Alpha]\r\n\"X\"=dword:1\r\n").unwrap();
        write_reg_backup_seal(&a, "HKCU\\Software\\Alpha");
        touch(&a, 1_700_000_001_000);
        let b = legacy.join("1700000000002_Beta.reg");
        std::fs::write(&b, "Windows Registry Editor Version 5.00\r\n").unwrap();
        touch(&b, 1_700_000_002_000);
        // 杂项与非法名不得进列表（还原是按文件名找实体的通道）
        std::fs::write(legacy.join("readme.txt"), b"x").unwrap();

        let items = render_reg_backups(vec![(a.clone(), false), (b.clone(), true)]);
        assert_eq!(items.len(), 2, "两份都要列出，非法名那份被过滤: {items:?}");
        assert_eq!(items[0]["file"], "1700000000002_Beta.reg", "mtime 倒序");
        assert_eq!(items[0]["fromLegacy"], json!(true), "老根那份必须标来源");
        assert_eq!(items[0]["seal"], "missing", "无封条的老备份仍要可见");
        assert_eq!(items[1]["fromLegacy"], json!(false));
        assert_eq!(items[1]["seal"], "ok");
        assert_eq!(items[1]["target"], "HKCU\\Software\\Alpha");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 判红自测口径（AGENTS §4：只会打 ✓ 的不算验收）：
    /// 把 `from_legacy` 写死 false、或把 `!p.is_file()` 那道闸摘掉，本用例必须红。
    #[test]
    fn 渲染拒绝目录项与非文件条目() {
        let root = sandbox("reject");
        std::fs::create_dir_all(root.join("1700000000009_Dir.reg")).unwrap();
        let entries = vec![(root.join("1700000000009_Dir.reg"), false)];
        assert!(render_reg_backups(entries).is_empty(), "同名目录不得当备份列出——还原侧会按文件读它并失败");
        let _ = std::fs::remove_dir_all(&root);
    }
}



