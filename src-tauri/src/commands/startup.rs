//! startup 域（D 批）：启动项管理 5 条通道
//!
//! 对照 Electron main.js 3883-4060 + src/scripts-powershell/startup-scripts.js。
//!
//! 安全/语义要点（SU-1/N1/SU-4 复核全部保留）：
//! - 扫描结果按「窗口 label」分槽；toggle/delete 只接受快照内 id，副作用参数取快照值。
//! - v6-K04：HKLM 提权前置门按 **regPath 解析出的真实 hive** 判（registry 项）——
//!   台账行自带的 hive/scope 只作对账，同用户篡改 disabled.json 谎报 HKCU 骗不过这道门。
//! - delete：注册表/计划任务由 PS 备份后处理；PS 回传的 fsDelete 文件改由主进程
//!   回收站删除——startup-file 必须与快照 filePath 一致，backup-file 必须位于应用
//!   备份根内（含 files/ 与 deleted/：禁用臂的备份落 files/，v6-K04 修正旧白名单
//!   只认 deleted/ 导致「禁用后不重扫直接删」必拒的问题；路径包含校验防注入）。
//! - add：原生对话框选程序（白名单扩展名），写 HKCU Run 键；同名项 EXISTS 冲突不覆盖。

use std::collections::HashMap;

use serde_json::{json, Value};
use tauri::{Runtime, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::engine::paths::path_key;
use crate::engine::{delete_manifest, guard, log, native, paths, snapshot, sysinfo};

fn cache_file() -> std::path::PathBuf {
    paths::scan_cache_file("startup-scan.json")
}

fn load_cache() -> Option<(Vec<Value>, i64)> {
    let v = crate::security::read_json_or_default(&cache_file());
    let obj = v.as_object()?;
    let data = obj.get("data")?.as_array()?.clone();
    let ts = obj.get("timestamp")?.as_i64()?;
    Some((data, ts))
}

fn save_cache(items: &[Value]) {
    let payload = json!({ "timestamp": crate::engine::now_ms(), "data": items });
    if let Err(e) = crate::security::atomic_write_json(&cache_file(), &payload) {
        log::write_log("warn", &format!("启动项缓存写入失败: {e}"));
    }
}

/// id 缺省回退链：id || regPath || filePath || taskName || index
fn normalize_ids(items: Vec<Value>) -> Vec<Value> {
    items
        .into_iter()
        .enumerate()
        .map(|(index, mut it)| {
            let has_id = it.get("id").and_then(|v| v.as_str()).is_some();
            if !has_id {
                let fallback = it
                    .get("regPath")
                    .or_else(|| it.get("filePath"))
                    .or_else(|| it.get("taskName"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| index.to_string());
                if let Some(o) = it.as_object_mut() {
                    o.insert("id".into(), json!(fallback));
                }
            }
            it
        })
        .collect()
}

/// 校验全部命中快照，返回快照副本（副作用参数不可由调用方篡改）。
fn validate_snapshot_items(items: &[Value], snap: &HashMap<String, Value>) -> Option<Vec<Value>> {
    if items.is_empty() || items.len() > 500 {
        return None;
    }
    let mut result = Vec::with_capacity(items.len());
    for it in items {
        let id = it.get("id").and_then(|v| v.as_str())?;
        let known = snap.get(id)?;
        if let (Some(a), Some(b)) = (
            it.get("filePath").and_then(|v| v.as_str()),
            known.get("filePath").and_then(|v| v.as_str()),
        ) {
            if path_key(a) != path_key(b) {
                return None;
            }
        }
        result.push(known.clone());
    }
    Some(result)
}

fn needs_hklm(item: &Value) -> bool {
    // v6-K04：registry 项以 regPath 解析出的真实 hive 为准——台账行自带的 hive/scope
    // 只作对账、不作为授权。同用户篡改 disabled.json 把 HKLM 项标成 HKCU，即可骗过
    // 这道提权前置门（真正写入的 hive 由 regPath 决定，见 native::toggle_registry_item）。
    // 前缀口径与 parse_reg_path 一致（它认什么，这里就判什么）。
    // task 项无 regPath，仍按 scope 判（Tasks 目录恒机器级，禁用要提权）。
    if item.get("source").and_then(|v| v.as_str()) == Some("registry") {
        if let Some(rp) = item.get("regPath").and_then(|v| v.as_str()) {
            let up = rp.trim().to_ascii_uppercase();
            return up.starts_with("HKEY_LOCAL_MACHINE") || up.starts_with("HKLM");
        }
    }
    matches!(
        item.get("hive").and_then(|v| v.as_str()),
        Some("HKLM") | Some("HKLM32")
    ) || item.get("scope").and_then(|v| v.as_str()) == Some("HKLM")
}

// ==================== IPC ====================

/// startup:scan
#[tauri::command]
pub async fn startup_scan<R: Runtime>(window: WebviewWindow<R>, refresh: Option<bool>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();

    if refresh != Some(true) {
        if let Some((data, ts)) = load_cache() {
            snapshot::set(&snapshot::domain_key(&label, "startup"), snapshot::by_id(&data));
            return json!({ "success": true, "data": data, "cached": true, "cachedAt": ts });
        }
    }

    snapshot::set(&snapshot::domain_key(&label, "startup"), HashMap::new());

    // S3：纯 Rust 原生
    let data: Vec<Value> = match tauri::async_runtime::spawn_blocking(native::startup_scan).await {
        Ok(Ok(items)) => items,
        Ok(Err(e)) => {
            log::write_log("warn", &format!("startup:scan 原生失败: {e}"));
            Vec::new()
        }
        Err(e) => {
            log::write_log("warn", &format!("startup:scan 任务异常: {e}"));
            Vec::new()
        }
    };

    let normalized = normalize_ids(data);
    snapshot::set(&snapshot::domain_key(&label, "startup"), snapshot::by_id(&normalized));
    save_cache(&normalized);
    json!({ "success": true, "data": normalized })
}
/// startup:toggle（enable=true 启用 / false 禁用）
#[tauri::command]
pub async fn startup_toggle<R: Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
    enable: Option<bool>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let items = items.unwrap_or_default();
    if items.is_empty() {
        return json!({ "success": false, "message": "缺少启动项" });
    }
    let Some(snap) = snapshot::get(&snapshot::domain_key(window.label(), "startup")) else {
        return json!({ "success": false, "message": "启动项不是最近一次扫描结果，已拒绝执行" });
    };
    let Some(safe) = validate_snapshot_items(&items, &snap) else {
        return json!({ "success": false, "message": "启动项不是最近一次扫描结果，已拒绝执行" });
    };
    if safe.iter().any(needs_hklm) && !sysinfo::is_admin() {
        return json!({
            "success": false, "needAdmin": true,
            "message": "涉及「所有用户」的启动项需要管理员权限，请先提权"
        });
    }
    let enable = enable.unwrap_or(true);
    let safe_len = safe.len();

    // S3：纯 Rust 原生
    // 性能优化 P1：启停是对注册表 / 计划任务的同步原生调用，整段进阻塞池
    //（对照本文件 startup_scan 的既有写法 —— 它是同类命令里唯一漏掉的一条）。
    let toggled =
        tauri::async_runtime::spawn_blocking(move || crate::engine::native::startup_toggle(&safe, enable))
            .await;
    let data = match toggled {
        Ok(Ok(d)) => {
            log::write_log("info", &format!("启动项{}原生完成 {} 项", if enable { "启用" } else { "禁用" }, safe_len));
            d
        }
        Ok(Err(e)) => return json!({ "success": false, "message": format!("原生执行失败: {e}") }),
        Err(e) => return json!({ "success": false, "message": format!("原生执行任务异常: {e}") }),
    };
    let failed = data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0);
    json!({ "success": failed == 0, "data": data })
}

/// startup:delete（PS 备份 + 注册表/计划任务删除；文件类由主进程回收站删除）
#[tauri::command]
pub async fn startup_delete<R: Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let items = items.unwrap_or_default();
    if items.is_empty() {
        return json!({ "success": false, "message": "缺少启动项" });
    }
    let Some(snap) = snapshot::get(&snapshot::domain_key(window.label(), "startup")) else {
        return json!({ "success": false, "message": "启动项不是最近一次扫描结果，已拒绝执行" });
    };
    let Some(safe) = validate_snapshot_items(&items, &snap) else {
        return json!({ "success": false, "message": "启动项不是最近一次扫描结果，已拒绝执行" });
    };
    if safe.iter().any(needs_hklm) && !sysinfo::is_admin() {
        return json!({
            "success": false, "needAdmin": true,
            "message": "涉及「所有用户」的启动项需要管理员权限，请先提权"
        });
    }

    log::write_log("info", &format!("启动项删除 {} 项", safe.len()));

    // S3：纯 Rust 原生
    let mut data = match crate::engine::native::startup_delete(&safe) {
        Ok(d) => {
            log::write_log("info", "启动项删除原生完成");
            d
        }
        Err(e) => return json!({ "success": false, "message": format!("原生删除失败: {e}") }),
    };

    // 文件类删除：白名单 containment 校验后回收站删除
    let fs_delete: Vec<Value> = data
        .get("fsDelete")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|v| !v.is_null())
        .collect();

    if !fs_delete.is_empty() {
        log::flush_sync();
        // 备份目录候选：新根 `app_data_dir()/startup-backup` 与收口前的老根同名路径
        // （v2-M19 起两根都只从 `paths::backup_read_dirs` 出，不再各处自己拼 `%APPDATA%\Trim`）。
        // 这里是「删除范围白名单」而非写入目标，两根都要在册，否则历史备份删不掉。
        //
        // v6-K04：候选从 `<根>/deleted` 放宽到**备份根本体**——禁用臂把备份放在
        // `<根>/files`（startup_files_dir），从来不在 deleted/；旧白名单下「禁用后
        // 不重扫直接删」的合法备份文件被判「删除路径与快照不符」而拒删（真机 bug）。
        // 放宽后仍限应用自家备份根，native 侧 backup_in_root_verdict 同一判据。
        let candidates: Vec<std::path::PathBuf> = paths::backup_read_dirs("startup-backup");

        let mut manifest: Vec<Value> = Vec::new();
        for fd in &fs_delete {
            let p = fd.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let id = fd.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let kind = fd.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let item = safe.iter().find(|it| it.get("id").and_then(|v| v.as_str()) == Some(id));

            // E4：每项耗时（方案 §3.5 E4）。计时从进入本轮开始，覆盖路径校验与回收站调用；
            // 失败路径同样计时。⚠️ 只加字段，`success`/`failed` 两个计数不看它。
            let t_item = std::time::Instant::now();
            let allowed = if !p.is_empty() && item.is_some() {
                match kind {
                    "startup-file" => item
                        .and_then(|it| it.get("filePath").and_then(|v| v.as_str()))
                        .map(|fp| path_key(p) == path_key(fp))
                        .unwrap_or(false),
                    "backup-file" => candidates.iter().any(|dir| {
                        let rel = std::path::Path::new(p).strip_prefix(dir);
                        matches!(rel, Ok(r) if !r.as_os_str().is_empty())
                    }),
                    _ => false,
                }
            } else {
                false
            };

            let (ok, msg) = if !allowed {
                (false, "删除路径与快照不符，已拒绝".to_string())
            } else {
                // 审查 v2-F1：走 `_os` 版，避免非 UTF-8 文件名在 `&str` 往返中被改写。
                match trim_finder::scan::recycle::send_to_trash_os(std::path::Path::new(p).as_os_str()) {
                    Ok(()) => (true, "已移入回收站（已备份）".to_string()),
                    Err(e) => (false, e),
                }
            };

            if ok {
                let name = fd
                    .get("name")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .or_else(|| item.and_then(|it| it.get("name").and_then(|v| v.as_str())))
                    .unwrap_or("");
                manifest.push(json!({
                    "path": p.replace('/', "\\"),
                    "name": name,
                    "recycled": true,
                    "deletedAt": delete_manifest::iso_now()
                }));
                bump_counter(&mut data, "success");
                set_result_entry(&mut data, id, "ok", &msg, &t_item);
            } else {
                bump_counter(&mut data, "failed");
                set_result_entry(&mut data, id, "error", &msg, &t_item);
            }
        }
        if !manifest.is_empty() {
            let batch = format!("startup-{}", crate::engine::now_ms());
            delete_manifest::save_delete_manifest(&batch, &manifest);
        }
        if let Some(o) = data.as_object_mut() {
            o.remove("fsDelete");
        }
    }

    let failed = data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0);
    json!({ "success": failed == 0, "data": data })
}

fn bump_counter(data: &mut Value, key: &str) {
    if let Some(o) = data.as_object_mut() {
        let n = o.get(key).and_then(|v| v.as_i64()).unwrap_or(0) + 1;
        o.insert(key.into(), json!(n));
    }
}

/// E4：写回某一项的结果，并带上**本项耗时**（`elapsedMs`）。
///
/// ⚠️ 只加字段。`success` / `failed` 由 `bump_counter` 各自累加，不看耗时；
/// 耗时为 0 或负值（时钟回拨）也不影响任何判定 —— E4 的「零风险」前提就是这个。
fn set_result_entry(
    data: &mut Value,
    id: &str,
    status: &str,
    message: &str,
    started: &std::time::Instant,
) {
    if let Some(results) = data.get_mut("results").and_then(|v| v.as_array_mut()) {
        for r in results.iter_mut() {
            if r.get("id").and_then(|v| v.as_str()) == Some(id) {
                if let Some(o) = r.as_object_mut() {
                    o.insert("status".into(), json!(status));
                    o.insert("message".into(), json!(message));
                    o.insert(
                        "elapsedMs".into(),
                        json!(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
                    );
                }
                return;
            }
        }
    }
}

/// 「打开位置」的落点锚（纯函数，可测）。
///
/// ① 目标本身在 → 选它；② 目标不在（卸载残留 / 目标已被换掉）→ 退到**最深的
/// 现存上级目录**，用户至少能开到它原来躺着的那层；③ 连一层都不在 → `None`，
/// 由调用方如实报失败，绝不静默交给系统默认目录。
fn location_anchor(target: &str) -> Option<(std::path::PathBuf, bool)> {
    let t = target.trim().trim_matches('"').replace('/', "\\");
    if t.is_empty() {
        return None;
    }
    let p = std::path::PathBuf::from(&t);
    if p.exists() {
        return Some((p, false));
    }
    let mut cur = p.parent()?.to_path_buf();
    loop {
        if cur.is_dir() {
            return Some((cur, true));
        }
        if !cur.pop() {
            return None;
        }
    }
}

/// startup:openlocation —— 在资源管理器中定位并选中目标
///
/// 2026-10-13 修复（目检 B-6）：此前用 `Command::arg("/select,…")`，Rust 会给含
/// 空格的参数套一对引号，explorer 解析不了就**静默回退到默认目录**（实测开在
/// Documents）。现在三处一起改：① 落点先过 [`location_anchor`]；② 走
/// `shell_select_in_explorer`（ShellExecuteW 原样传参，无引号坑，也不经 shell）；
/// ③ 回执带 `opened` / `fellBack`，失败有明确文案，不再「spawn 成功即 success」。
#[tauri::command]
pub async fn startup_openlocation<R: Runtime>(
    window: WebviewWindow<R>,
    path: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let target = path.unwrap_or_default();
    if target.is_empty() || target.contains('\0') {
        return json!({ "success": false, "message": "缺少路径" });
    }
    let Some((anchor, fell_back)) = location_anchor(&target) else {
        return json!({
            "success": false,
            "message": "这个路径连同它的上级目录都不存在了，没法定位到文件夹"
        });
    };
    let opened = anchor.to_string_lossy().replace('/', "\\");
    match crate::engine::systembin::shell_select_in_explorer(&opened) {
        Ok(()) => json!({ "success": true, "opened": opened, "fellBack": fell_back }),
        Err(e) => {
            log::write_log("error", &format!("打开所在位置异常: {e}"));
            json!({ "success": false, "message": e })
        }
    }
}

/// 计划任务 XML 文件的落盘位置（任务计划程序库的物理形态）。
const TASKS_DIR: &str = r"C:\Windows\System32\Tasks";

/// 「打开来源位置」的坐标白名单：任务路径/任务名来自 IPC 参数，不能拿来拼文件路径。
/// 只放行文件名合法字符；`..` 段单独拒（防穿越出 Tasks 目录）。
fn task_coordinate_problem(s: &str) -> Option<&'static str> {
    if s.is_empty() {
        return Some("为空");
    }
    if s.split(['\\', '/']).any(|seg| seg == "..") {
        return Some("含 .. 段（路径穿越）");
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-' | '(' | ')' | '\\' | '/'))
    {
        return Some("含白名单外字符");
    }
    None
}

/// regedit 的 LastKey 期望「计算机\HKEY_…」全形态；只认四个 hive 根，防拼任意串。
fn regedit_last_key(reg_path: &str) -> Option<String> {
    let p = reg_path.trim().replace('/', "\\");
    let roots = ["HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_CLASSES_ROOT", "HKEY_USERS"];
    let hit = roots.iter().any(|r| {
        p.len() > r.len() + 1 && p[..r.len()].eq_ignore_ascii_case(r) && p.as_bytes()[r.len()] == b'\\'
    });
    if !hit {
        return None;
    }
    Some(format!("计算机\\{p}"))
}

/// 把 LastKey 写进 HKCU 的 regedit 记忆位，再拉起 regedit（2026-10-15 起公用实现在
/// `engine::systembin::open_regedit_at`，本域不再自带一份）。
fn open_regedit_at(last_key: &str) -> Result<(), String> {
    crate::engine::systembin::open_regedit_at(last_key)
}

/// startup:open-source —— 打开启动项的「来源位置」（B-6 增强，2026-10-13 用户裁定）
///
/// 点「位置」除了打开目标软件所在文件夹，还要把它登记在哪一并露出来：
/// · 注册表项 → 先写 regedit 的 LastKey 再拉起 regedit（定位到登记键）；
/// · 计划任务项 → explorer /select 任务 XML 的落盘文件（System32\Tasks 下）；
/// · 启动文件夹项 → 没有独立来源位置，folder 字段如实说明。
/// 两个动作互相独立：软件位置失败不阻断来源定位，反之亦然，回执分字段如实报。
#[tauri::command]
pub async fn startup_open_source<R: Runtime>(
    window: WebviewWindow<R>,
    path: Option<String>,
    source: Option<String>,
    reg_path: Option<String>,
    task_path: Option<String>,
    task_name: Option<String>,
) -> Value {
    // 主窗档：位置按钮只在主窗启动项页（guard-tiers D5 禁「只读档无子窗消费方」的白给放宽）
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let target = path.unwrap_or_default();

    // ① 软件所在文件夹（与 startup:openlocation 同一份锚定与拉起逻辑）
    let folder = match location_anchor(&target) {
        Some((anchor, fell_back)) => {
            let opened = anchor.to_string_lossy().replace('/', "\\");
            match crate::engine::systembin::shell_select_in_explorer(&opened) {
                Ok(()) => json!({ "success": true, "opened": opened, "fellBack": fell_back }),
                Err(e) => json!({ "success": false, "message": e }),
            }
        }
        None => json!({ "success": false, "message": "目标路径连同上级目录都不存在" }),
    };

    // ② 来源位置
    let src = match source.as_deref() {
        Some("registry") => match reg_path.as_deref().and_then(regedit_last_key) {
            Some(lk) => match open_regedit_at(&lk) {
                Ok(()) => json!({ "success": true, "kind": "registry", "opened": lk }),
                Err(e) => json!({ "success": false, "kind": "registry", "message": e }),
            },
            None => json!({ "success": false, "kind": "registry", "message": "注册表路径不是四个根键之一的子键" }),
        },
        Some("task") => {
            let tp = task_path.unwrap_or_default();
            let tn = task_name.unwrap_or_default();
            if let Some(why) = task_coordinate_problem(&tp).or_else(|| task_coordinate_problem(&tn)) {
                json!({ "success": false, "kind": "task", "message": format!("任务坐标不合法（{why}），已拒绝定位") })
            } else {
                let file = format!(
                    "{}{}\\{}",
                    TASKS_DIR,
                    tp.replace('/', "\\").trim_end_matches('\\'),
                    tn.replace('/', "\\")
                );
                match crate::engine::systembin::shell_select_in_explorer(&file) {
                    Ok(()) => json!({ "success": true, "kind": "task", "opened": file }),
                    Err(e) => json!({ "success": false, "kind": "task", "message": e }),
                }
            }
        }
        Some("folder") => json!({ "success": true, "kind": "folder", "note": "启动文件夹项没有独立的来源位置（它本身就是登记）" }),
        _ => json!({ "success": false, "kind": "unknown", "message": "未知的启动项来源" }),
    };

    let ok = folder.get("success").and_then(|v| v.as_bool()).unwrap_or(false)
        || src.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    json!({ "success": ok, "folder": folder, "source": src })
}

/// startup:add —— 原生对话框选程序 → 写当前用户 Run 键（同名冲突不覆盖）
#[tauri::command]
pub async fn startup_add<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let picked = window
        .dialog()
        .file()
        .set_title("选择要添加为开机启动的程序")
        .add_filter("程序文件", &["exe", "lnk", "bat", "cmd", "com"])
        .add_filter("所有文件", &["*"])
        .blocking_pick_file();

    let Some(file_path) = picked else {
        return json!({ "success": false, "canceled": true });
    };
    let path_buf = match file_path.into_path() {
        Ok(p) => p,
        Err(e) => return json!({ "success": false, "message": format!("无效路径: {e}") }),
    };
    let file_path_str = path_buf.to_string_lossy().to_string();
    if file_path_str.contains('\0') {
        return json!({ "success": false, "canceled": true });
    }
    let name = path_buf
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    // S3：纯 Rust 原生
    match crate::engine::native::startup_add(&file_path_str, &name) {
        Ok(None) => {
            log::write_log("info", &format!("添加启动项（原生）: {file_path_str}"));
            json!({ "success": true, "path": file_path_str, "name": name })
        }
        Ok(Some(existing)) => {
            log::write_log("warn", &format!("添加启动项冲突: {name} 已存在，未重复添加（{existing}）"));
            json!({
                "success": false, "exists": true, "name": name,
                "message": "同名的开机启动项已存在，未重复添加"
            })
        }
        Err(e) => json!({ "success": false, "message": format!("原生添加失败: {e}") }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hklm_scope_requires_admin() {
        assert!(needs_hklm(&json!({ "hive": "HKLM" })));
        assert!(needs_hklm(&json!({ "hive": "HKLM32" })));
        assert!(needs_hklm(&json!({ "scope": "HKLM" })));
        assert!(!needs_hklm(&json!({ "hive": "HKCU" })));
        assert!(!needs_hklm(&json!({ "scope": "HKCU" })));
    }

    /// v6-K04：提权前置门按 regPath 解析出的真实 hive 判——台账行自带的 hive/scope
    /// 只作对账。同用户篡改 disabled.json 把 HKLM 项谎报成 HKCU，旧判法会跳过提权
    /// 门（真正写入的 hive 由 regPath 决定，见 native::toggle_registry_item）。
    /// 判红自证：把 needs_hklm 里的 regPath 分支删掉 ⇒ 第 1、3 条红。
    #[test]
    fn hklm前置门按regpath判而非台账hive字段() {
        assert!(needs_hklm(&json!({
            "source": "registry",
            "hive": "HKCU",
            "scope": "HKCU",
            "regPath": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        })), "台账谎报 HKCU 但 regPath 在 HKLM 下必须判需提权");
        assert!(!needs_hklm(&json!({
            "source": "registry",
            "hive": "HKCU",
            "regPath": r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        })), "真实 HKCU 项不得误判提权");
        // HKLM 缩写形态同样认（与 parse_reg_path 的前缀口径一致）
        assert!(needs_hklm(&json!({
            "source": "registry",
            "regPath": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        })), "HKLM 缩写形态必须判需提权");
        // folder/task 项无 regPath，仍按 hive/scope 判（ Tasks 目录恒机器级）
        assert!(needs_hklm(&json!({ "source": "folder", "hive": "HKLM", "filePath": r"C:\x.lnk" })));
    }

    #[test]
    fn snapshot_items_only() {
        let snap = snapshot::by_id(&[json!({ "id": "r1", "filePath": "C:\\A\\x.lnk" })]);
        assert!(validate_snapshot_items(&[json!({ "id": "r1" })], &snap).is_some());
        assert!(validate_snapshot_items(&[json!({ "id": "nope" })], &snap).is_none());
        // filePath 与快照不一致即拒绝（防替换删除目标）
        assert!(validate_snapshot_items(
            &[json!({ "id": "r1", "filePath": "C:\\B\\evil.lnk" })],
            &snap
        )
        .is_none());
    }

    /// B-6：落点锚的三种结局。刻意**不写盘**——用肯定存在的临时目录本身当「目标在」
    /// 的样本，用其下不存在的子孙当「目标没了」的样本，测试无副作用也不留垃圾。
    #[test]
    fn 定位锚_目标在选目标_不在退最深现存目录_全无则拒() {
        let root = std::env::temp_dir();
        // ① 目标在：原样返回，不算回退
        let (anchor, fell) = location_anchor(&root.to_string_lossy()).expect("临时目录应存在");
        assert_eq!(anchor, root);
        assert!(!fell, "目录本身存在不该判成回退");

        // ② 目标没了：退到最深的现存上级（这里就是临时目录本身）
        let gone = root.join("trim-b6-absent").join("deep").join("a.exe");
        let (anchor, fell) = location_anchor(&gone.to_string_lossy()).expect("上级应存在");
        assert_eq!(anchor, root, "应退到最深的现存上级目录");
        assert!(fell, "目标不在必须标记回退，供前端如实提示");

        // ③ 连一层都不在（裸文件名，parent 为空）：不下结论，交调用方报错
        assert!(location_anchor("trim-b6-bare-name.exe").is_none());
        assert!(location_anchor("").is_none());
    }

    /// B-6 的根因：参数串**必须不加引号**，否则 explorer 静默回退到默认目录。
    #[test]
    fn select参数_含空格也不加引号() {
        let with_space = crate::engine::systembin::explorer_select_arg(
            r"C:\Program Files (x86)\Steam\steam.exe",
        );
        assert_eq!(with_space, r"/select,C:\Program Files (x86)\Steam\steam.exe");
        assert!(!with_space.contains('"'), "一旦出现引号，explorer 就会开到默认目录");
        // 正斜杠统一成反斜杠（IPC 侧两种形态都可能进来）
        assert_eq!(
            crate::engine::systembin::explorer_select_arg("C:/KaiFa/a.exe"),
            r"/select,C:\KaiFa\a.exe"
        );
    }

    /// 正向对照：若有人把 `explorer_select_arg` 改回「给整参加引号」的写法，
    /// 上面的用例必须红（防恒绿）。
    #[test]
    fn select参数不是恒等拼接() {
        assert!(crate::engine::systembin::explorer_select_arg("C:\\A B\\c.exe").contains("A B"));
        assert_ne!(
            crate::engine::systembin::explorer_select_arg("C:\\A B\\c.exe"),
            format!("\"/select,{}\"", "C:\\A B\\c.exe")
        );
    }

    /// B-6 增强：任务坐标白名单。`..` 段单独拒（穿越出 Tasks 目录就是任意文件定位），
    /// 白名单外字符（引号/分号/环境变量展开等）同样拒。
    #[test]
    fn 任务坐标_穿越与非法字符必须拒() {
        assert!(task_coordinate_problem("Microsoft\\Windows\\..\\evil").is_some(), ".. 段必须拒");
        assert!(task_coordinate_problem("..\\evil").is_some());
        assert!(task_coordinate_problem("Microsoft\\Windows\\System32\\...").is_none(), "三个点不是 .. 段");
        assert!(task_coordinate_problem("Micro\"soft").is_some(), "引号必须拒");
        assert!(task_coordinate_problem("微软任务").is_some(), "非 ASCII 任务名不在白名单（现网任务名均为 ASCII）");
        assert!(task_coordinate_problem("").is_some());
        assert!(task_coordinate_problem("\\Microsoft\\Windows\\Maps").is_none());
        assert!(task_coordinate_problem("OneDrive Startup Task-1 (x64)").is_none());
    }

    /// B-6 增强：regedit LastKey 只认四个 hive 根的子键（防拼任意串写进记忆位）。
    #[test]
    fn lastkey_只认四根的子键() {
        assert_eq!(
            regedit_last_key(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run").as_deref(),
            Some(r"计算机\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run")
        );
        assert_eq!(
            regedit_last_key(r"hkey_local_machine\SOFTWARE\X").as_deref(),
            Some(r"计算机\hkey_local_machine\SOFTWARE\X"),
            "hive 根大小写不敏感，大小写原样保留"
        );
        assert!(regedit_last_key("Software\\Foo").is_none(), "缺 hive 根必须拒");
        assert!(regedit_last_key("HKEY_CURRENT_USER").is_none(), "裸根键（无子键）拒：regedit 打开根没有定位意义");
        assert!(regedit_last_key("HKEY_CURRENT_USERX\\A").is_none(), "前缀相同的根名不算命中");
    }

    /// 正向对照：把白名单里的 `..` 段判定删掉，上面的穿越用例必须红（防恒绿）。
    #[test]
    fn 任务坐标不是恒放行() {
        let probes = ["..\\evil", "a\\..\\b", "Micro\"soft"];
        assert!(probes.iter().all(|p| task_coordinate_problem(p).is_some()));
    }
}
