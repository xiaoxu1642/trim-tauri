//! contextmenu 域（D 批）：右键菜单 10 条通道
//!
//! 对照 Electron main.js 2381-2823 + src/scripts-powershell/contextmenu-scripts.js。
//!
//! 安全模型（与 Electron 逐条对齐，CM-1/2/3/9/12/16 复核全部保留）：
//! - 扫描结果按「窗口 label」分槽（id -> 完整扫描项）；backup/remove/toggle/icons/open-regedit
//!   只接受快照内 id，且副作用参数（regPath/nativeRegPath/source/clsid/blockedBy/target/risk）
//!   一律取快照值，渲染层只能表达「选了哪些 id、目标 enabled 态」。
//! - nativeRegPath 是真实写入 hive（HKCR 是合并视图）；无该字段的旧缓存视为不可用（CM-9）。
//! - HKLM/HKCR/machine 屏蔽表写操作需管理员（CM-3）。
//! - 文件系统类（source=filesystem/winx，如「发送到」.lnk）不走 PS 注册表删除，
//!   由主进程回收站删除 + 删除清单（N1 删除红线）。
//! - toggle 后把 PS 回写的新路径/屏蔽态同步回快照与缓存（CM-12）。

use std::collections::HashMap;

use serde_json::{json, Value};
use tauri::{Runtime, WebviewWindow};

use crate::engine::{guard, log, native, paths, shellicon, snapshot, sysinfo};
// v3 C-1：宽字符串转换统一走 engine 唯一实现（原 to_wide16 已删）。
use crate::engine::native::to_wide;

// open-in-regedit 纯原生实现所需（审计 F-05：原内联 PS 改 Win32 等价，见 open_regedit_native）
use windows::core::{BOOL, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, IsWindowVisible, PostMessageW, SW_SHOWNORMAL, WM_CLOSE,
};

fn cache_file() -> std::path::PathBuf {
    paths::scan_cache_file("contextmenu-scan.json")
}

/// 读持久缓存；CM-9：所有项必须带 nativeRegPath 字符串才可用。
///
/// 同一条判据再加 `ownerSource`（2026-10-05 按软件分组）：升级前留下的缓存里没有这个键，
/// 直接拿来用会让整页 172 项全落进「未识别」组 —— 那不是"缓存能用"，那是把新功能显示成坏了。
/// 判据缺失就当没有缓存、走一次真实扫描，代价是首次进页面慢几秒，比静默错分组划算。
fn load_cache() -> Option<Vec<Value>> {
    let v = crate::security::read_json_or_default(&cache_file());
    let obj = v.as_object()?;
    let data = obj.get("data")?;
    let arr = data.as_array()?;
    if arr.is_empty() {
        return None;
    }
    if arr.iter().all(|it| {
        it.get("nativeRegPath").and_then(|v| v.as_str()).is_some()
            && it.get("ownerSource").and_then(|v| v.as_str()).is_some()
    }) {
        Some(arr.clone())
    } else {
        None
    }
}

fn save_cache(items: &[Value]) {
    let payload = json!({
        "timestamp": crate::engine::now_ms(),
        "data": items
    });
    if let Err(e) = crate::security::atomic_write_json(&cache_file(), &payload) {
        log::write_log("warn", &format!("右键菜单缓存写入失败: {e}"));
    }
}

/// 归一化 id：缺 id 时用 regPath|target（R7：ShellNew 共享 regPath 需复合键）
fn normalize_ids(items: Vec<Value>) -> Vec<Value> {
    // 快照是 `id -> 项` 的 Map：**同 id 的两条里后一条会静默覆盖前一条**，
    // 于是界面上两行都能点，而 toggle/remove 拿到的永远是同一个坐标（写错项）。
    // 扫描端当前不产重复 id，但去重键（category|name|clsid|enabled）比 id 的构成更宽，
    // 这个覆盖只隔着「上游改一次去重规则」的距离 —— 唯一性在这里就地上锁，不指望上游。
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    items
        .into_iter()
        .enumerate()
        .map(|(index, mut it)| {
            let has_id = it.get("id").and_then(|v| v.as_str()).is_some();
            let base = if has_id {
                it.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string()
            } else {
                let target = it.get("target").and_then(|v| v.as_str()).unwrap_or("");
                let reg = it.get("regPath").and_then(|v| v.as_str()).unwrap_or("");
                if !target.is_empty() && !reg.is_empty() {
                    format!("{reg}|{target}")
                } else if !reg.is_empty() {
                    reg.to_string()
                } else {
                    index.to_string()
                }
            };
            // 审计 P2-12：id 就是整条注册表路径，中文键名 3 字节/字，深路径会很长。
            // 超长就换成稳定哈希（同一轮扫描内 id 与快照键仍然一致，且不可能撞车：
            // 哈希前缀带序号）。P2-2 起快照侧（`engine::snapshot::by_id`）已不再按长度
            // 剔除长 id，这里保留短哈希是为了 id 在日志/缓存里可读，并避免长注册表路径
            // 被下游误当成路径处理。
            let mut id = if base.len() > 160 { format!("id{index}-{:x}", fnv1a(base.as_bytes())) } else { base };
            if !used.insert(id.clone()) {
                id = format!("{id}#{index}");
                used.insert(id.clone());
            }
            if let Some(obj) = it.as_object_mut() {
                obj.insert("id".into(), json!(id));
            }
            it
        })
        .collect()
}

/// FNV-1a 64 位：只用来给超长 id 生成稳定短键，不涉安全（不是签名、不是防篡改）。
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// 校验调用方传入的 items 全部命中快照，返回**快照副本**（拒绝调用方篡改副作用参数）。
fn validate_snapshot_items(items: &[Value], snap: &HashMap<String, Value>) -> Option<Vec<Value>> {
    if items.is_empty() || items.len() > 500 {
        return None;
    }
    let mut result = Vec::with_capacity(items.len());
    for it in items {
        let id = it.get("id").and_then(|v| v.as_str())?;
        let known = snap.get(id)?;
        // 真正的防篡改是「返回快照副本」：调用方带的 regPath/target/source 等一律不被采信。
        // 审计 P2-13：原先这里比的是 `path` 字段，而扫描产出根本没有 `path` ⇒ 那段判断恒不生效，
        // 注释却写着"防替换路径"。删掉死分支，别留一条看起来在防其实没防的判据。
        result.push(known.clone());
    }
    Some(result)
}

/// CM-3/CM-9：写操作是否需要管理员（看真实 hive 路径 + machine 屏蔽表）
fn write_needs_admin(item: &Value) -> bool {
    if item.get("blockedBy").and_then(|v| v.as_str()) == Some("machine") {
        return true;
    }
    let p = item
        .get("nativeRegPath")
        .or_else(|| item.get("regPath"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let upper = p.to_uppercase();
    upper.starts_with("HKEY_LOCAL_MACHINE\\")
        || upper.starts_with("HKEY_CLASSES_ROOT\\")
        || upper.starts_with("HKLM\\")
        || upper.starts_with("HKCR\\")
}

/// CLSID → `InprocServer32` 默认值指向的 dll/exe（R1 去 PS 化，2026-10-01）。
///
/// 三个视图与旧 `cm_icons.ps1` 同一批次、同一次序，差别只有一处且是放宽：旧脚本一旦读到
/// 非空值就 `break`，路径不存在则该 CLSID 直接无图标；这里继续试下一个视图。
/// 环境变量展开走 `cleanup_scan::expand_env_path`（扫描/执行侧共用的那一份，不再各自实现）。
fn clsid_inproc_server(clsid: &str) -> Option<std::path::PathBuf> {
    let hkcr = native::hive_hkcr();
    let hklm = native::hive_hklm();
    let views = [
        (hkcr, format!(r"CLSID\{clsid}\InprocServer32")),
        (hkcr, format!(r"WOW6432Node\CLSID\{clsid}\InprocServer32")),
        (
            hklm,
            format!(r"SOFTWARE\Classes\Wow6432Node\CLSID\{clsid}\InprocServer32"),
        ),
    ];
    for (hive, subkey) in views {
        // 默认值名是空串；EXPAND_SZ 由 read_reg_value_text 的展平口径给出
        let Some((_, raw)) = native::read_reg_value_text(hive, &subkey, "") else {
            continue;
        };
        // 旧脚本口径：Trim 再去掉首尾成对引号（`%ProgramFiles%\x.dll` 常被带引号写入）
        let dll = raw.trim().trim_matches('"');
        if dll.is_empty() {
            continue;
        }
        let expanded = trim_finder::cleanup_scan::expand_env_path(dll);
        let path = std::path::PathBuf::from(expanded.trim());
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

// ==================== IPC ====================

/// contextmenu:scan（refresh=true 强制重扫；否则优先持久缓存）
#[tauri::command]
pub async fn contextmenu_scan<R: Runtime>(
    window: WebviewWindow<R>,
    refresh: Option<bool>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();

    if refresh != Some(true) {
        if let Some(cached) = load_cache() {
            let map = snapshot::by_id(&cached);
            snapshot::set(&label, map);
            if let Some(ts) = crate::security::read_json_or_default(&cache_file())
                .get("timestamp")
                .and_then(|v| v.as_i64())
            {
                return json!({ "success": true, "data": cached, "cached": true, "cachedAt": ts });
            }
        }
    }

    snapshot::clear(&label);
    log::write_log("info", "扫描右键菜单");

    // S3：纯 Rust 原生
    let data: Vec<Value> = match crate::engine::native::cm_scan() {
        Ok(items) => {
            log::write_log("info", &format!("右键菜单原生扫描完成: {} 项", items.len()));
            items
        }
        Err(e) => return json!({ "success": false, "message": format!("原生扫描失败: {e}") }),
    };
    let normalized = normalize_ids(data);
    log::write_log("info", &format!("扫描右键菜单完成: {} 项", normalized.len()));
    snapshot::set(&label, snapshot::by_id(&normalized));
    save_cache(&normalized);
    json!({ "success": true, "data": normalized })
}

/// contextmenu:toggle —— 可逆启停（渲染层只表达目标 enabled，其余取快照）
#[tauri::command]
pub async fn contextmenu_toggle<R: Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let items = items.unwrap_or_default();
    let Some(snap) = snapshot::get(window.label()) else {
        return json!({ "success": false, "message": "切换项不是最近一次扫描结果，已拒绝执行" });
    };
    let Some(safe) = validate_snapshot_items(&items, &snap) else {
        return json!({ "success": false, "message": "切换项不是最近一次扫描结果，已拒绝执行" });
    };

    // 调用方目标态（按 id）
    let mut wanted: HashMap<String, bool> = HashMap::new();
    for it in &items {
        if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
            wanted.insert(id.to_string(), it.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false));
        }
    }

    let mut toggle_items: Vec<Value> = Vec::new();
    for it in &safe {
        let reg_ok = it.get("regPath").and_then(|v| v.as_str()).is_some();
        let source_ok = it.get("source").and_then(|v| v.as_str()).is_some();
        if !reg_ok || !source_ok {
            continue;
        }
        let id = it.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let enabled = wanted.get(id).copied().unwrap_or_else(|| {
            it.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false)
        });
        let mut obj = serde_json::Map::new();
        obj.insert("id".into(), json!(id));
        obj.insert("name".into(), it.get("name").cloned().unwrap_or(json!("")));
        obj.insert(
            "regPath".into(),
            it.get("regPath").cloned().unwrap_or(json!("")),
        );
        obj.insert(
            "nativeRegPath".into(),
            it.get("nativeRegPath")
                .or_else(|| it.get("regPath"))
                .cloned()
                .unwrap_or(json!("")),
        );
        obj.insert("source".into(), it.get("source").cloned().unwrap_or(json!("")));
        obj.insert("clsid".into(), json!(it.get("clsid").and_then(|v| v.as_str()).unwrap_or("")));
        obj.insert(
            "blockedBy".into(),
            json!(it.get("blockedBy").and_then(|v| v.as_str()).unwrap_or("")),
        );
        obj.insert("target".into(), json!(it.get("target").and_then(|v| v.as_str()).unwrap_or("")));
        obj.insert("risk".into(), json!(it.get("risk").and_then(|v| v.as_str()).unwrap_or("")));
        obj.insert("enabled".into(), json!(enabled));
        toggle_items.push(Value::Object(obj));
    }
    if toggle_items.is_empty() {
        return json!({ "success": false, "message": "没有可切换的菜单项" });
    }
    if toggle_items.iter().any(write_needs_admin) && !sysinfo::is_admin() {
        return json!({
            "success": false, "needAdmin": true,
            "message": "涉及系统级右键菜单的操作需要管理员权限，请先提权"
        });
    }

    log::write_log("info", &format!("切换右键菜单启停: {} 项", toggle_items.len()));

    // S3：纯 Rust 原生
    let data = match crate::engine::native::cm_toggle(&toggle_items) {
        Ok(d) => {
            log::write_log("info", "右键菜单切换原生完成");
            d
        }
        Err(e) => return json!({ "success": false, "message": format!("原生切换失败: {e}") }),
    };

    // CM-12：回写新路径/屏蔽态到快照 + 缓存
    if let Some(results) = data.get("results").and_then(|v| v.as_array()) {
        let mut touched = false;
        let mut snap2 = snapshot::get(window.label()).unwrap_or_default();
        let updates: Vec<&Value> = results
            .iter()
            .filter(|r| {
                r.get("status").and_then(|v| v.as_str()) == Some("ok")
                    && r.get("id").and_then(|v| v.as_str()).is_some()
            })
            .collect();
        for r in updates {
            let id = r.get("id").and_then(|v| v.as_str()).unwrap();
            if let Some(t) = snap2.get_mut(id) {
                if let Some(en) = wanted.get(id) {
                    t.as_object_mut().map(|o| o.insert("enabled".into(), json!(en)));
                }
                if let Some(np) = r.get("newRegPath").and_then(|v| v.as_str()) {
                    t.as_object_mut().map(|o| o.insert("regPath".into(), json!(np)));
                }
                if let Some(np) = r.get("newNativeRegPath").and_then(|v| v.as_str()) {
                    t.as_object_mut().map(|o| o.insert("nativeRegPath".into(), json!(np)));
                }
                if let Some(nb) = r.get("newBlockedBy").and_then(|v| v.as_str()) {
                    t.as_object_mut().map(|o| o.insert("blockedBy".into(), json!(nb)));
                }
                touched = true;
            }
        }
        if touched {
            let arr: Vec<Value> = snap2.values().cloned().collect();
            snapshot::set(window.label(), snap2);
            save_cache(&arr);
        }
    }

    let failed = data.get("failed").and_then(|v| v.as_i64()).unwrap_or(0);
    // skip 与 fail 一样是「没切成」：系统保护项/缺目标的 skip 若只统计 failed，
    // 整次操作会回 success:true，UI 上那些行被当成已切换。
    let skipped = data.get("skipped").and_then(|v| v.as_i64()).unwrap_or(0);
    if failed > 0 || skipped > 0 {
        let first_msg = data
            .get("results")
            .and_then(|v| v.as_array())
            .and_then(|a| a.iter().find(|r| r.get("status").and_then(|s| s.as_str()) != Some("ok")))
            .and_then(|r| r.get("message").and_then(|v| v.as_str()))
            .unwrap_or("部分项切换失败（可能需要管理员权限）");
        log::write_log("warn", &format!("启停切换未全部生效: failed={failed} skipped={skipped}"));
        return json!({ "success": false, "message": first_msg, "data": data });
    }
    json!({ "success": true, "data": data })
}

/// contextmenu:icons —— CLSID 图标提取（只接受快照内 CLSID）
#[tauri::command]
pub async fn contextmenu_icons<R: Runtime>(
    window: WebviewWindow<R>,
    items: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let Some(snap) = snapshot::get(window.label()) else {
        return json!({ "success": true, "data": {} });
    };
    let known: std::collections::HashSet<String> = snap
        .values()
        .filter_map(|it| it.get("clsid").and_then(|v| v.as_str()).map(|s| s.trim().to_uppercase()))
        .filter(|s| !s.is_empty())
        .collect();
    let icon_items: Vec<Value> = items
        .unwrap_or_default()
        .into_iter()
        .filter(|it| {
            it.get("clsid")
                .and_then(|v| v.as_str())
                .map(|c| c.trim().starts_with('{') && known.contains(c.trim().to_uppercase().as_str()))
                .unwrap_or(false)
        })
        .filter_map(|it| {
            it.get("clsid").and_then(|v| v.as_str()).map(|c| json!({ "clsid": c.trim() }))
        })
        .collect();
    if icon_items.is_empty() {
        return json!({ "success": true, "data": {} });
    }
    // R1（2026-10-01）：原走 cm_icons.ps1 + `[System.Drawing.Icon]::ExtractAssociatedIcon`，
    // 那是本域最后一个外部 PowerShell 入口。换成原生 `ExtractIconExW` 索引 0 ——
    // 三件系统 PE 实机对拍像素和与 .NET 完全相等（见 shellicon 的 live_probe 注释）。
    // 图标提取失败不影响主流程，恒返回 success（与旧行为一致：缺图只是没图）。
    let mut data = serde_json::Map::new();
    for it in &icon_items {
        let Some(clsid) = it.get("clsid").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(server) = clsid_inproc_server(clsid) else {
            continue;
        };
        if let Ok(url) = shellicon::first_icon_data_url(&server) {
            data.insert(clsid.to_string(), json!(url));
        }
    }
    json!({ "success": true, "data": Value::Object(data) })
}

fn canon_reg_key(s: &str) -> String {
    let mut s = s
        .trim()
        .trim_start_matches("Registry::")
        .trim_end_matches('\\')
        .to_lowercase();
    for (full, short) in [
        ("hkey_classes_root", "hkcr"),
        ("hkey_current_user", "hkcu"),
        ("hkey_local_machine", "hklm"),
        ("hkey_users", "hku"),
    ] {
        if s == full || s.starts_with(&format!("{full}\\")) {
            s = short.to_string() + &s[full.len()..];
            break;
        }
    }
    s
}

/// contextmenu:open-in-regedit —— LastKey 方案打开注册表编辑器（regPath 须在快照内）
#[tauri::command]
pub async fn contextmenu_open_in_regedit<R: Runtime>(
    window: WebviewWindow<R>,
    reg_path: Option<String>,
) -> Value {
    // 审查 v2-F6：本命令体内会写 HKCU（`Regedit\LastKey`）并在普通拉起失败时以 `runas`
    // 弹 UAC，具备提权能力；唯一调用方在主窗（`contextmenu.js` 详情弹窗的 regJump 分支）。
    // 挂 `guard_readonly` 等于让所有子窗都能触发它 —— 按「谁真的需要调它」判档，这里必须收回主窗。
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let mut p = reg_path.unwrap_or_default().trim().trim_end_matches('\\').to_string();
    if p.is_empty() {
        return json!({ "success": false, "message": "无效的注册表路径" });
    }
    let wanted = canon_reg_key(&p);
    let in_snap = snapshot::get(window.label())
        .map(|snap| {
            snap.values()
                .any(|it| it.get("regPath").map(|v| canon_reg_key(v.as_str().unwrap_or("")) == wanted).unwrap_or(false))
        })
        .unwrap_or(false);
    if !in_snap {
        return json!({ "success": false, "message": "路径不在最近一次扫描结果内，已拒绝打开" });
    }

    // 根键别名展开
    let aliases: HashMap<&str, &str> = HashMap::from([
        ("HKCR", "HKEY_CLASSES_ROOT"),
        ("HKCU", "HKEY_CURRENT_USER"),
        ("HKLM", "HKEY_LOCAL_MACHINE"),
        ("HKU", "HKEY_USERS"),
        ("HKCC", "HKEY_CURRENT_CONFIG"),
    ]);
    if let Some(rest) = p.split_once('\\') {
        if let Some(full) = aliases.get(rest.0.to_uppercase().as_str()) {
            p = format!("{full}\\{}", rest.1);
        }
    } else if let Some(full) = aliases.get(p.to_uppercase().as_str()) {
        p = full.to_string();
    }
    log::write_log("info", &format!("在注册表编辑器中定位: {p}"));
    // 审计 F-05 修复（2026-09-25）：原实现是 B6 九脚本清单**之外**的内联 PowerShell
    // （CloseMainWindow + 写 LastKey + Start-Process regedit），无 pwsh 机器上该功能必挂。
    // 改为纯 Win32 等价实现，语义逐条对齐（见 open_regedit_native 注释）。
    let spawned = tauri::async_runtime::spawn_blocking(move || open_regedit_native(&p))
        .await
        .unwrap_or_else(|e| Err(format!("后台任务异常: {e}")));
    match spawned {
        Ok(elevated) => json!({ "success": true, "elevated": elevated }),
        Err(e) => {
            log::write_log("warn", &format!("打开注册表编辑器失败: {e}"));
            json!({ "success": false, "message": "打开注册表编辑器失败" })
        }
    }
}

// ==================== open-in-regedit 纯原生实现（审计 F-05） ====================
//
// 语义对齐原内联 PS 脚本：
//   1) CloseMainWindow ≈ 对 regedit.exe 的**可见**顶层窗口投递 WM_CLOSE（隐藏/消息窗不动）；
//   2) 必须先关窗再写 LastKey —— regedit 退出时会覆写 LastKey，顺序反了定位即失效；
//   3) 写 LastKey 失败不阻断拉起（对齐原脚本 catch{}），只留日志；
//   4) Start-Process 失败（ShellExecuteW 返回 ≤32）转 "runas" 弹 UAC，并如实上报 elevated。

/// 枚举回调：把属于 regedit.exe 的可见顶层窗口关掉
struct RegEditCloseCtx {
    pids: Vec<u32>,
    hits: usize,
}

/// EnumWindows 回调：把属于 regedit.exe 的可见顶层窗口关掉。
///
/// `lparam` 是 Win32 裸指针，没有类型保证：目前唯一调用者传的是栈上局部变量的地址
/// 且 EnumWindows 同步回调（生命周期覆盖整个调用），现行路径安全。这里加空值防御是
/// 为了**将来的复用**——这是 `unsafe extern "system"` 的公共回调签名，若被挂到别的
/// 枚举场景而 lparam 不是本结构体地址，裸解引用就是立即 UB。
unsafe extern "system" fn close_regedit_wndproc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    if lparam.0 == 0 {
        // 回调约定：返回非 0 表示「继续枚举」。这里没有 ctx 可用，直接让枚举跑完。
        return BOOL(1);
    }
    let ctx = &mut *(lparam.0 as *mut RegEditCloseCtx);
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid != 0 && ctx.pids.contains(&pid) && IsWindowVisible(hwnd).as_bool() {
        let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
        ctx.hits += 1;
    }
    BOOL(1) // 继续枚举
}

/// 关旧 regedit → 写 LastKey → 拉起 regedit（失败转 RunAs）。
/// 返回 Ok(elevated)；Err 表示两次拉起均失败。
fn open_regedit_native(last_key: &str) -> Result<bool, String> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE,
        REG_CREATE_KEY_DISPOSITION, REG_OPTION_NON_VOLATILE, REG_SZ,
    };
    use windows::Win32::UI::Shell::ShellExecuteW;

    // 1. 找 regedit.exe 的 PID（对齐原脚本 Get-Process regedit）
    let mut pids: Vec<u32> = Vec::new();
    unsafe {
        // 审查 v2-F12：快照句柄必须在离开本块前释放。同 bundle 另 6 处
        // `CreateToolhelp32Snapshot` 均成对 `CloseHandle`（`native.rs:109/159` 等），此处是漏网。
        let snap_res = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let snap = match snap_res {
            Ok(s) => s,
            Err(_) => return Err("无法枚举系统进程".to_string()),
        };
        // 之后只有一条退出路径（枚举结束即 break），故在块尾统一释放。
        let mut entry: PROCESSENTRY32W = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..std::mem::zeroed()
        };
        let mut first = true;
        loop {
            let ok = if first {
                first = false;
                Process32FirstW(snap, &mut entry)
            } else {
                Process32NextW(snap, &mut entry)
            };
            if ok.is_err() {
                break;
            }
            let name = String::from_utf16_lossy(&entry.szExeFile);
            if name.trim_end_matches('\0').eq_ignore_ascii_case("regedit.exe") {
                pids.push(entry.th32ProcessID);
            }
        }
        let _ = CloseHandle(snap);
    }

    // 2. 关旧 regedit 主窗（有进程才需要；对齐原脚本只在 $running 非空时关+睡）
    if !pids.is_empty() {
        let mut ctx = RegEditCloseCtx { pids, hits: 0 };
        unsafe {
            let _ = EnumWindows(
                Some(close_regedit_wndproc),
                LPARAM(&mut ctx as *mut RegEditCloseCtx as isize),
            );
        }
        if ctx.hits > 0 {
            // 给 regedit 一点退出时间，避免它退出时把 LastKey 覆写回去
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    // 3. 写 LastKey（键不存在则创建；写失败不阻断——对齐原脚本 catch{}）
    unsafe {
        let path = to_wide(r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit");
        let mut hk = HKEY::default();
        let mut disp = REG_CREATE_KEY_DISPOSITION::default();
        if RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path.as_ptr()),
            None,
            PCWSTR::default(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hk,
            Some(&mut disp),
        )
        .is_ok()
        {
            let val = to_wide(last_key);
            let bytes: Vec<u8> = val.iter().flat_map(|&w| w.to_le_bytes()).collect();
            // 审查 v2-F16：值名先落到局部变量再取裸指针。原先写
            // `PCWSTR(to_wide("LastKey").as_ptr())` —— 临时值当前能活到语句结束因而不算 UB，
            // 但只要有人把这条语句拆开、或在中间插入 `.await`/提前返回，指针立刻悬垂，
            // 而 FFI 路径上不会有任何编译错误。同函数里其余几处 FFI 取值都已用局部变量写法。
            let name = to_wide("LastKey");
            let r = RegSetValueExW(
                hk,
                PCWSTR(name.as_ptr()),
                Some(0),
                REG_SZ,
                Some(&bytes),
            );
            let _ = RegCloseKey(hk);
            if r.is_err() {
                log::write_log("warn", "写 Regedit LastKey 失败，仍尝试打开注册表编辑器");
            }
        } else {
            log::write_log("warn", "打开 Regedit Applets 注册表键失败，仍尝试打开注册表编辑器");
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(200));

    // 4. 拉起 regedit；普通拉起失败（返回 ≤32）转 RunAs 弹 UAC
    // 审查 v3-L6：用 System32 绝对路径，不走 ShellExecute 的 App Paths/搜索顺序解析，
    // 口径与 systembin::system_tool 一致（裸名解析路径里用户可写目录优先于 System32）
    let regedit = std::env::var("SystemRoot")
        .map(|r| format!(r"{r}\System32\regedit.exe"))
        .unwrap_or_else(|_| r"C:\Windows\System32\regedit.exe".to_string());
    let exe = to_wide(&regedit);
    let open = unsafe {
        ShellExecuteW(
            None,
            windows::core::w!("open"),
            PCWSTR(exe.as_ptr()),
            None,
            None,
            SW_SHOWNORMAL,
        )
    };
    if open.0 as usize > 32 {
        return Ok(false);
    }
    let runas = unsafe {
        ShellExecuteW(
            None,
            windows::core::w!("runas"),
            PCWSTR(exe.as_ptr()),
            None,
            None,
            SW_SHOWNORMAL,
        )
    };
    if runas.0 as usize > 32 {
        return Ok(true);
    }
    Err(format!(
        "ShellExecuteW 两次拉起均失败（open={}, runas={}）",
        open.0 as usize,
        runas.0 as usize
    ))
}

/// contextmenu:restart-explorer
#[tauri::command]
pub async fn contextmenu_restart_explorer<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // S3：纯 Rust 原生
    match tauri::async_runtime::spawn_blocking(native::cm_restart_explorer).await {
        Ok(Ok(data)) => json!({ "success": data.get("success").and_then(|v| v.as_bool()).unwrap_or(false), "data": data }),
        Ok(Err(e)) => json!({ "success": false, "message": format!("原生重启失败: {e}") }),
        Err(e) => json!({ "success": false, "message": format!("重启任务异常: {e}") }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_scope_uses_native_hive() {
        // CM-9：看 nativeRegPath（真实 hive），HKCR/HKLM 需提权
        assert!(write_needs_admin(&json!({ "nativeRegPath": "HKEY_LOCAL_MACHINE\\X" })));
        assert!(write_needs_admin(&json!({ "regPath": "HKCR\\X" })));
        assert!(write_needs_admin(&json!({ "blockedBy": "machine" })));
        // 纯 HKCU 用户级项不要求提权（本机实测 8 个 HKCU 侧项）
        assert!(!write_needs_admin(&json!({
            "regPath": "HKEY_CLASSES_ROOT\\merge",
            "nativeRegPath": "HKEY_CURRENT_USER\\Software\\Classes\\x"
        })));
        assert!(!write_needs_admin(&json!({ "nativeRegPath": "HKCU\\X" })));
    }

    #[test]
    fn canon_regkey_aliases() {
        assert_eq!(canon_reg_key("Registry::HKEY_CURRENT_USER\\Software\\"), "hkcu\\software");
        assert_eq!(canon_reg_key("HKEY_CLASSES_ROOT\\*"), "hkcr\\*");
        assert_eq!(canon_reg_key("HKEY_LOCAL_MACHINE\\X"), "hklm\\x");
    }

    #[test]
    fn snapshot_validation_takes_snapshot_copy() {
        let snap = snapshot::by_id(&[json!({ "id": "a", "regPath": "HKCU\\X" })]);
        // 未知 id 拒绝
        assert!(validate_snapshot_items(&[json!({ "id": "x" })], &snap).is_none());
        // 数量上限
        let many: Vec<Value> = (0..501).map(|_| json!({ "id": "a" })).collect();
        assert!(validate_snapshot_items(&many, &snap).is_none());
        // 命中返回快照副本
        let ok = validate_snapshot_items(&[json!({ "id": "a", "regPath": "HKCU\\EVIL" })], &snap).unwrap();
        // 副作用参数取快照值，调用方篡改不生效
        assert_eq!(ok[0].get("regPath").and_then(|v| v.as_str()), Some("HKCU\\X"));
    }

    /// 快照按 id 存，重复 id 会互相覆盖 ⇒ 每轮扫描的 id 必须两两不同。
    #[test]
    fn normalize_ids_is_unique_per_round() {
        let long = format!("HKCU\\Software\\Classes\\{}\\shell\\open", "深".repeat(60));
        let out = normalize_ids(vec![
            json!({ "regPath": "HKCU\\A", "target": "t1" }),
            json!({ "regPath": "HKCU\\A", "target": "t1" }), // 与上一条同坐标不同名（上游去重放宽的形状）
            json!({ "regPath": "HKCU\\A", "target": "t2" }),
            json!({ "regPath": long.clone(), "target": "" }),
            json!({ "regPath": long, "target": "" }),
            json!({}),
        ]);
        let ids: Vec<&str> = out.iter().filter_map(|v| v.get("id").and_then(|x| x.as_str())).collect();
        assert_eq!(ids.len(), 6, "每条都必须拿到 id：{ids:?}");
        let uniq: std::collections::HashSet<&str> = ids.iter().copied().collect();
        assert_eq!(uniq.len(), 6, "id 必须唯一，实得 {ids:?}");
        // 超长路径要换成短哈希（id 保持短形态；快照侧 P2-2 起已不按长度剔除）
        for id in &ids {
            assert!(id.len() <= 160, "id 超过短哈希上限（{id}）");
        }
        // 快照必须真收进 6 条（丢件的表现就是这里少一条）
        assert_eq!(snapshot::by_id(&out).len(), 6);
    }
}
