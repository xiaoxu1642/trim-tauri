//! paths 域（批次 A）：paths:scan / load / save / browse / validate
//!
//! 白名单必须与渲染层 pathbinding.js 的 GROUPS 保持同源（键集合以两边文件现算为准，
//! 注释不记条数）。（审查 SET-1：原实现漏了 4 个「安装路径」key，导致设置页可编辑却静默保存失败）。
//! P3 顺手修（2026-10-09）：`scannedAt` 从白名单移除 —— 前端那处冗余回写已删
//! （后端 paths_scan 落盘时自带时间戳），写面收紧到用户真正可编辑的 10 个键。
//!
//! A 批落 load/save/validate/browse（纯 fs + 原生对话框）与
//! app-icon/file-icon（Shell 图标提取）；C 批追补 `paths:scan`
//! （PS 扫描 + 当前生效规则库注入，超时 120s，结果即时落盘并统一写 scannedAt）。


use tauri::WebviewWindow;
use tauri_plugin_dialog::DialogExt;

use crate::engine::{guard, log, paths};
use crate::security;

/// paths:save 的值形态闸（2026-10-04 磁盘清理审计 §3.1）。
///
/// **为什么这里必须查**：这是本条绕过链的**实际入口**。存进配置的路径会被
/// 清理扫描原样采纳成条目 `path`，再经 `engine/native/cleanup.rs` 枚举并
/// **永久删除**——唯一闸门是 `is_path_protected`。而 `\\.\C:\Users\<me>\Documents`
/// 与不带前缀的同一路径在保护判定上结论相反（`protect.rs` 同批收紧）。
/// 也就是说：一个纯设备路径前缀就能把「永久删除 + 保护清单」这两道设计同时绕过。
///
/// 判 fail-closed 的形状（任一命中即拒存）：
/// - 设备路径前缀 `\\.\` / `\??\`：Win32 跳过路径解析，无法判定保护归属
/// - 裸盘符相对（`C:foo`）：Node 会拼 CWD、Rust 会拼 current_dir，两侧口径不同
/// - 纯相对路径：同样存在 CWD 歧义，且用户从对话框选不出这种形态
/// - 控制字符：`\0` 已被原校验拦下；这里补 `\r` `\n`（会让「一份配置」
///   在文本工具里裂成两行，且与 protect 侧 `normalize_for_compare` 的空值口径不一致）
///
/// UNC（`\\server\share`）**刻意放行**：企业环境合法存在，且 `protect.rs`
/// 另有独立的 share-root 判定（审计 §4.10 记的 m-10 是那道判定自身的缺口，
/// 不在「配置值不该长什么样」这一层解决）。
fn path_value_problem(value: &str) -> Option<&'static str> {
    let v = value.trim();
    if v.is_empty() {
        return None; // 空串 = 清空该配置项，既有语义
    }
    if v.starts_with("\\\\.\\") || v.starts_with("\\??\\") {
        return Some("路径是设备路径形式，无法判定保护归属");
    }
    if v.contains(['\r', '\n']) {
        return Some("路径含控制字符");
    }
    // `C:` 与 `C:foo` 都是驱动器相对路径：会按「当前目录」解析，
    // 同一份配置在不同 cwd 下指向不同目标。
    let b = v.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b.len() == 2 || (b[2] != b'\\' && b[2] != b'/')) {
        return Some("路径是驱动器相对形式（会按当前目录解析）");
    }
    if !(b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':') && !v.starts_with("\\\\") {
        return Some("路径不是绝对路径");
    }
    None
}

/// 可写 key 白名单（与渲染层 GROUPS 同源）
const ALLOWED_KEYS: &[&str] = &[
    // QQ
    "qqInstallPath",
    "qqFileDir",
    "qqCacheDir",
    // 微信
    "wechatInstallPath",
    "wechatFileDir",
    "wechatCacheDir",
    // 抖音
    "douyinInstallPath",
    "douyinCacheDir",
    // 网易云音乐
    "neteaseMusicInstallPath",
    "neteaseCacheDir",
];

/// 读取路径配置（剥离历史遗留的软件清单字段）。
///
/// v5-K01 批次 4（R7-M05）：三态读器——读失败（Corrupt）已在 read_json_state 内
/// warn 留痕，不再与「没有配置」同归静默空；只读展示降级空对象，写侧 update_json 拒写。
fn load_paths_config_state() -> (serde_json::Value, bool) {
    let (v, degraded) = match security::read_json_state(&paths::paths_config_file()) {
        security::JsonState::Ok(v) => (v, false),
        security::JsonState::Absent => (serde_json::json!({}), false),
        security::JsonState::Corrupt => (serde_json::json!({}), true),
    };
    let v = match v {
        serde_json::Value::Object(mut m) => {
            m.remove("softwareInventory");
            serde_json::Value::Object(m)
        }
        other => other,
    };
    (v, degraded)
}

/// paths:load — 读取已保存的路径配置
#[tauri::command]
pub fn paths_load<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard(&window, guard::MAIN)?;
    // A1-M12：Corrupt 与 Absent 不再同归空对象——回执带 degraded，渲染层可区分。
    let (data, degraded) = load_paths_config_state();
    Ok(serde_json::json!({ "success": true, "data": data, "degraded": degraded }))
}

/// paths:save — 保存单个路径（key 白名单 + 长度/空字节校验 + 存在性回执）
#[tauri::command]
pub fn paths_save<R: tauri::Runtime>(window: WebviewWindow<R>, key: String, value: String) -> Result<serde_json::Value, String> {
    // R1a-M01：本命令写入的路径会被清理扫描原样采纳并永久删除，只在主窗配置页调用。
    guard::guard(&window, guard::MAIN)?;
    if !ALLOWED_KEYS.contains(&key.as_str()) || value.len() > 1024 || value.contains('\0') {
        return Ok(serde_json::json!({ "success": false, "message": "路径配置无效" }));
    }
    if let Some(why) = path_value_problem(&value) {
        // 理由必须原样回给渲染层：用户是自己粘进来/手输的，不说清是哪一条会被当
        // 成「保存功能坏了」。渲染层 pathbinding.js 直接展示 message。
        log::write_log(
            "warn",
            &format!("拒绝保存路径配置 {key}: {why}（值形态不安全，可能绕过保护清单）"),
        );
        return Ok(serde_json::json!({ "success": false, "message": why }));
    }
    // v4 P2-D 尾（R7-M01 同族）：读-改-写收口 —— 旧链 `load_paths_config()`（损坏时
    // 已隔离但返回 `{}`）→ 插入单键 → `save_paths_config()` 把整份路径配置覆成只剩
    // 这一次写的键（其余绑定与 scannedAt 静默丢失，回执仍是 success）。现在读失败拒写。
    let exists = !value.is_empty() && std::path::Path::new(&value).exists();
    let saved = match security::update_json(&paths::paths_config_file(), |config| {
        let Some(obj) = config.as_object_mut() else {
            return Err("路径配置结构异常（非对象）".into());
        };
        obj.remove("softwareInventory"); // 软件清单不落盘（与 load_paths_config 同口径）
        obj.insert(key.clone(), serde_json::json!(value.clone()));
        Ok(())
    }) {
        Ok(_) => true,
        Err(e) => {
            log::write_log("error", &format!("保存路径配置失败: {e}"));
            false
        }
    };
    Ok(serde_json::json!({ "success": saved, "exists": exists }))}

/// paths:browse — 原生选择文件夹对话框
#[tauri::command]
pub async fn paths_browse<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    title: Option<String>,
    default_path: Option<String>,
) -> Result<serde_json::Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let mut builder = window
        .dialog()
        .file()
        .set_title(title.unwrap_or_else(|| "选择文件夹".into()));
    if let Some(d) = default_path.filter(|d| !d.trim().is_empty()) {
        builder = builder.set_directory(d);
    }
    match builder.blocking_pick_folder() {
        Some(path) => match path.into_path() {
            Ok(p) => Ok(serde_json::json!({ "success": true, "path": p.to_string_lossy() })),
            Err(e) => Ok(serde_json::json!({ "success": false, "message": format!("无效路径: {e}") })),
        },
        None => Ok(serde_json::json!({ "success": false, "canceled": true })),
    }
}

/// 图标来源的**域内命名空间白名单**（R6b-M11 调用点那一半；`contextmenu` 的 CLSID
/// `InprocServer32` 展平值共用本函数，同一判据不留第二份，AGENTS §5.16）。
///
/// `engine::shellicon` 只守「这条串能不能当文件系统路径交给外壳」，并在模块头写明
/// **域内白名单归调用方** —— 本函数就是那一半的落点。
///
/// 白名单按**来源命名空间**给，不按扩展名给（上一轮刻意不在 shellicon 里按扩展名硬拒，
/// 理由是该文件模块头写的：图标链的合法来源本来就在 `%WINDIR%` 与 `.ico/.exe/.dll/目录`
/// 四个面之内，按「非白名单扩展名一律拒」会在自己的调用点上打断功能）。收进来的只有一族：
/// **本机盘符根下的绝对路径**（`X:\…`，含 `\\?\X:\…` 长路径写法 —— 归一后同形）。
///
/// 拒 UNC（`\\server\share\…` 与 `\\?\UNC\…`）的理由不是「越权读文件」，而是**取图标这个
/// 动作自身的副作用**：`SHGetFileInfoW` 会为远程形态目标发起名解析，等于把本机凭据递到
/// 渲染层指定的主机上（SMB/WebDAV 都可能），死共享还会把 IPC 线程挂到超时。本域图标串
/// 全部来自渲染层原文（进程列表 / 启动项 / 卸载列表 / 路径绑定固定图标），合法来源恒是
/// 本机路径；网络位置上的条目拿不到图标时由 `src/scripts/icon-fallback.js` 兜 Trim.ico，
/// 属刻意的降级，不是漏网。
///
/// 设备路径 / `::` 外壳命名空间 / 相对路径由 `shellicon::guard_icon_source` 先拒；本函数
/// 复用 `protect::normalize_for_compare` 的同一份归一，**不另立路径分类**（§5.16），
/// 归一判不出形态（`\\?\Volume{…}` / `\\?\GLOBALROOT\…` / 展不掉的短名）按 fail-closed 拒。
pub(crate) fn icon_source_reject_reason(path: &std::path::Path) -> Option<&'static str> {
    if let Some(reason) = crate::engine::shellicon::guard_icon_source(path) {
        return Some(reason);
    }
    // 与 guard 各调一次归一：本函数的结论不该依赖「guard 内部已经判过 ok」这个实现细节
    let n = crate::engine::protect::normalize_for_compare(&path.to_string_lossy());
    if !n.ok {
        return Some("路径形态无法判定（设备 / 不可折回命名空间），已拒绝");
    }
    // 折回后的小写形态：`x:\…` 才是本机盘符根下；`n.drive_root` 是裸盘符（`C:\` 去掉尾
    // 分隔符的结果），外壳取的是那个盘根目录的图标，同属本机命名空间，不收它等于拒
    // 「整盘的文件夹图标」这种合法请求
    let b = n.low.as_bytes();
    let drive_rooted = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    if drive_rooted || n.drive_root {
        return None;
    }
    Some("图标来源必须落在本机盘符命名空间（UNC / 远程共享形态不收）")
}

/// paths:app-icon — 提取安装目录下主程序 exe 的图标（供路径绑定弹窗分组标题头）
/// 按 exeCandidates 顺序取第一个存在的；都不存在时退回安装目录本身的图标。
#[tauri::command]
pub async fn paths_app_icon<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    install_path: Option<String>,
    exe_candidates: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let install = install_path.unwrap_or_default();
    let candidates = exe_candidates.unwrap_or_default();
    // 命名空间闸必须排在 exists() 之前：UNC 形态的 `Path::exists()` 自身就会发起远程名
    // 解析，先判存在性等于把本闸要防的那个副作用做掉了。
    if let Some(reason) = icon_source_reject_reason(std::path::Path::new(&install)) {
        log::write_log("warn", &format!("拒绝提取应用图标（安装目录来源不受信）: {reason}"));
        return Ok(serde_json::json!({ "success": false, "dataUrl": null, "message": reason }));
    }
    if install.is_empty() || !std::path::Path::new(&install).exists() {
        return Ok(serde_json::json!({ "success": false, "dataUrl": null }));
    }
    let picked = candidates
        .iter()
        .filter(|c| !c.is_empty())
        .map(|c| std::path::Path::new(&install).join(c))
        .find(|p| p.exists());
    let target = picked.unwrap_or_else(|| std::path::PathBuf::from(&install));
    // 交给外壳之前再过一次域内白名单（候选是渲染层给的相对串，拼接后可以带 `..` 逃逸）
    if let Some(reason) = icon_source_reject_reason(&target) {
        log::write_log("warn", &format!("拒绝提取应用图标（拼出的目标来源不受信）: {reason}"));
        return Ok(serde_json::json!({ "success": false, "dataUrl": null, "message": reason }));
    }
    Ok(match crate::engine::shellicon::file_icon_data_url(&target) {
        Ok(url) => serde_json::json!({ "success": true, "dataUrl": url }),
        Err(_) => serde_json::json!({ "success": false, "dataUrl": null }),
    })
}

// ==================== paths:scan（C 批追补） ====================

/// 需加入 lib.rs `generate_handler!` 的完整行（A 批 6 条见各自实现，本条为 C 批追补）：
///   commands::paths::paths_scan,
///
/// paths:scan — 自动扫描安装路径（注入当前生效规则库）
#[tauri::command]
pub async fn paths_scan<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard(&window, guard::MAIN)?;
    match tauri::async_runtime::spawn_blocking(scan_install_paths).await {
        Ok(v) => Ok(v),
        Err(e) => Ok(serde_json::json!({
            "success": false,
            "message": format!("扫描任务异常: {e}"),
            "data": {}
        })),
    }
}

/// 跑一次安装路径扫描并落盘（同步阻塞，调用方已放入 spawn_blocking）
fn scan_install_paths() -> serde_json::Value {
    // 任务3：注入当前生效规则库（数据目录覆盖 / 自定义合并 / 验签后的版本）——
    // 规则库在线更新后，路径绑定扫描的应用候选目录自动同步；规则不可用时
    // pathscan 内部的候选逻辑自行兜底（规则串传空）。
    let rules_json = match crate::commands::cleanup::rules_value_arc() {
        Ok(v) => serde_json::to_string(&*v).unwrap_or_default(),
        Err(e) => {
            log::write_log("warn", &format!("规则库不可用，路径扫描按内置候选兜底: {e}"));
            String::new()
        }
    };

    // S3：纯 Rust 原生
    let mut data: serde_json::Value = match crate::engine::native::paths_scan(&rules_json) {
        Ok(d) => {
            log::write_log("info", "安装路径原生扫描完成");
            d
        }
        Err(e) => return serde_json::json!({
            "success": false,
            "message": format!("原生扫描失败: {e}"),
            "data": {}
        }),
    };
    // 标准化：去除首尾空白与包裹引号（注册表 InstallLocation 常带引号）
    if let Some(map) = data.as_object_mut() {
        for value in map.values_mut() {
            if let Some(s) = value.as_str() {
                *value = serde_json::Value::String(s.trim().trim_matches('"').trim().to_string());
            }
        }
    }
    // 软件清单不落盘：仅扫描进程内部用于路径匹配，UI 已不再展示
    if let Some(map) = data.as_object_mut() {
        map.remove("softwareInventory");
    }
    // 自动扫描结果立即落盘；设置页只展示其中的常用路径
    // v4 P2-D 尾（R7-M01 同族）：改走 update_json —— 旧链 `load_paths_config()` 在
    // 损坏/读失败时（已隔离但）拿到 `{}`，合并后整份覆写 ⇒「扫描一次把用户的
    // 路径绑定清成只剩本次扫出的键」；R1-M04 只补了失败回执，没堵住读侧的源头。
    // SET-5（2026-09-15）：时间戳统一写 scannedAt。原写 lastScanAt，而渲染层/
    // paths:load 只读 scannedAt → 重启后页脚恒显「尚未扫描」（键名两侧不一致）。
    // 2026-10-07 修：时间戳改由本层**唯一**产生（ISO-8601 UTC）并回填进回执。
    // 此前上游 `paths_scan` 自己塞 `format!("{:?}", SystemTime::now())` 的 Debug 形态，
    // JS `new Date()` 解析不了 → 页脚恒显 "Invalid Date"（用户反馈）。渲染层拿到的
    // 就是可解析值，落盘与回执同源，不会再有第二份口径。
    let scanned_at = crate::commands::settings::iso_utc_now();
    let dmap_snapshot = data.as_object().cloned().unwrap_or_default();
    if let Some(dmap) = data.as_object_mut() {
        dmap.insert("scannedAt".into(), serde_json::Value::String(scanned_at.clone()));
    }
    let persisted = security::update_json(&paths::paths_config_file(), |persisted| {
        let Some(pmap) = persisted.as_object_mut() else {
            return Err("路径配置结构异常（非对象）".into());
        };
        pmap.remove("softwareInventory"); // 软件清单不落盘（同 load_paths_config 口径）
        for (key, value) in &dmap_snapshot {
            let keep = match value {
                serde_json::Value::String(s) => !s.is_empty(),
                serde_json::Value::Array(_) => true,
                _ => false,
            };
            if keep {
                pmap.insert(key.clone(), value.clone());
            }
        }
        pmap.insert("scannedAt".into(), serde_json::Value::String(scanned_at.clone()));
        Ok(())
    });
    // v4 组 1（R1-M04）：写失败不得被吞 —— 旧实现丢返回值、无条件 success:true，
    // 于是「扫描完成」的落盘记录（scannedAt + 路径配置合并）写失败后用户完全不知情，
    // 重启后页脚又显「尚未扫描」、路径配置可能回退。
    if let Err(msg) = persisted {
        log::write_log("error", &format!("路径扫描：扫描记录落盘失败，已如实回失败（{msg}）"));
        return serde_json::json!({ "success": false, "message": format!("扫描记录写入失败（{msg}），本次结果未保存，请检查数据目录可写性") });
    }
    log::write_log("info", "路径扫描完成");
    serde_json::json!({ "success": true, "data": data })
}

/// paths:file-icon — 按绝对路径提取图标（.ico/.exe/.dll），供固定图标路径兜底
#[tauri::command]
pub async fn paths_file_icon<R: tauri::Runtime>(window: WebviewWindow<R>, file_path: Option<String>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let path = file_path.unwrap_or_default();
    if path.is_empty() {
        return Ok(serde_json::json!({ "success": false, "dataUrl": null }));
    }
    // R6b-M11：本通道的入参是渲染层原文（进程列表 / 启动项 / 卸载列表 / 固定图标都在用它），
    // 先过域内命名空间白名单再交给外壳 —— shellicon 只判「能不能当文件系统路径」，
    // 「该不该由图标链去驱动外壳解析它」归这里。
    if let Some(reason) = icon_source_reject_reason(std::path::Path::new(&path)) {
        log::write_log("warn", &format!("拒绝提取文件图标（来源不受信）: {reason}"));
        return Ok(serde_json::json!({ "success": false, "dataUrl": null, "message": reason }));
    }
    Ok(match crate::engine::shellicon::file_icon_data_url(std::path::Path::new(&path)) {
        Ok(url) => serde_json::json!({ "success": true, "dataUrl": url }),
        Err(_) => serde_json::json!({ "success": false, "dataUrl": null }),
    })
}

#[cfg(test)]
mod tests {
    use super::{icon_source_reject_reason, path_value_problem};
    use std::path::Path;

    /// R6b-M11：图标来源的域内白名单**只按来源命名空间收放**，不按扩展名收放。
    ///
    /// 两侧都要断：拒侧点名「三类理由各自命中过」（少一类 = 那条分支没被走到，
    /// 用例在测空气）；放侧点名「合法本机来源不许被误拒」——上一轮刻意留了「不按
    /// 扩展名硬拒」的口子（依据写在 `engine/shellicon.rs` 模块头），把 `.pdf` 这类
    /// 本机路径拒掉就是把那个口子当缺陷收紧，本用例会把这种改法判红。
    #[test]
    fn 图标来源白名单只按命名空间收放() {
        // ① 拒侧：UNC / 外壳命名空间 / 设备与不可折回形态 / 空与相对
        let mut reasons: Vec<&str> = Vec::new();
        for bad in [
            r"\\srv\share\app\tool.exe",
            r"\\srv\pub",
            r"\\?\UNC\srv\share\a.dll",
            r"::{42aedc87-2188-41fd-b9a3-0c966feabec1}",
            r"\\.\C:\Windows\System32\shell32.dll",
            r"\\?\Volume{00000000-0000-0000-0000-000000000000}\dir\a.ico",
            r"Users\tester\AppData\a.exe",
            "C:",
            r"C:Users\tester\a.exe",
            "",
        ] {
            let reason = icon_source_reject_reason(Path::new(bad))
                .unwrap_or_else(|| panic!("不受信来源 `{bad}` 竟被放行进图标链"));
            reasons.push(reason);
        }
        let unc = reasons
            .iter()
            .filter(|r| r.starts_with("图标来源必须落在本机盘符命名空间"))
            .count();
        assert_eq!(unc, 3, "UNC 三向量应各自命中同一条命名空间理由，实到 {unc} 条");
        assert!(
            reasons.iter().any(|r| r.contains(":: 前缀")),
            "外壳命名空间形态没被 guard 拒掉"
        );
        assert!(
            reasons.iter().any(|r| r.contains("形态无法判定")),
            "设备 / 不可折回形态没被 fail-closed 拒掉"
        );
        assert!(
            reasons.iter().any(|r| r.contains("绝对路径")),
            "相对与盘符相对形态没被拒掉"
        );
        assert!(
            reasons.iter().any(|r| r.contains("路径为空")),
            "空串没被拒掉"
        );

        // ② 放侧：本机盘符命名空间内的各种形状必须放行（含目录、含长路径写法、
        //    含映射盘符、含「非图标扩展名」的本机文件）
        for good in [
            r"C:\Windows\System32\shell32.dll",
            r"D:\Program Files\App\a.exe",
            r"\\?\C:\Users\tester\AppData\Roaming\com.xiaoxu.trim\backgrounds\a.jpg",
            r"C:\Program Files",
            r"C:\",
            r"Z:\mapped\tool.exe",
            r"C:\Users\tester\Downloads\report.pdf",
        ] {
            assert!(
                icon_source_reject_reason(Path::new(good)).is_none(),
                "合法本机来源 `{good}` 被图标白名单误拒（收紧过头会打死进程/启动/卸载三处图标）"
            );
        }
    }

    /// 2026-10-04 磁盘清理审计 §3.1：`paths_save` 是设备路径绕过的**实际入口**。
    ///
    /// 判据的形状是「与 `is_path_protected` 的结论必须一致」：凡是在
    /// `engine/protect.rs` 被按 fail-closed 拒绝的形态，这里都不许存进去 ——
    /// 存进去就等于把一个纯前缀变成了「永久删除 + 保护清单」两道设计的共同绕过。
    #[test]
    fn 路径配置值不许是设备路径或歧义形态() {
        // ① 设备路径两形态（`\\.\` 与 `\??\`）—— 本条闸门存在的理由
        for bad in [
            r"\\.\C:\Users\Administrator",
            r"\??\C:\Users\Administrator",
            r"\\.\PIPE\foo",
            r"\\.\PhysicalDrive0",
        ] {
            assert_eq!(
                path_value_problem(bad),
                Some("路径是设备路径形式，无法判定保护归属"),
                "设备路径 `{bad}` 竟被放行"
            );
        }
        // ② 驱动器相对（`C:` / `C:foo`）：按当前目录解析，同一份配置在不同 cwd 下指向不同目标
        assert!(path_value_problem("C:").is_some(), "裸盘符 `C:` 必须拒");
        assert!(path_value_problem(r"C:Users\tester").is_some(), "驱动器相对 `C:Users\\tester` 必须拒");
        // ③ 纯相对路径：用户从对话框选不出这种形态，而它带 CWD 歧义
        assert!(path_value_problem(r"Users\tester\AppData").is_some(), "相对路径必须拒");
        assert!(path_value_problem("AppData\\Local").is_some(), "相对路径必须拒");
        // ④ 控制字符
        assert!(path_value_problem("C:\\Temp\r\nX").is_some(), "含换行的路径必须拒");
        // ⑤ 正向对照：合法形态必须放行 —— 收紧过头会把设置页的正常保存打死
        for good in [
            r"C:\Users\Administrator\AppData\Local\Temp",
            r"D:\Program Files\App",
            r"\\server\share\appdata",
            r"C:\Users\Administrator\AppData\Local\带 空格 的目录",
        ] {
            assert!(path_value_problem(good).is_none(), "合法路径 `{good}` 被误拒");
        }
        // ⑥ 空串 = 清空该项，既有语义必须保留
        assert!(path_value_problem("").is_none(), "空串（清空配置项）必须放行");
        assert!(path_value_problem("   ").is_none(), "全空白（清空配置项）必须放行");
    }

    /// 反向对齐：`\\?\` **不**在 paths_save 的拒列表里。
    ///
    /// 刻意与规则侧 `file_path_form_problem` 分道扬镳：`\\?\` 是**合法**的 Win32
    /// 长路径前缀（用户从资源管理器地址栏就能复制到），protect 侧也已归一化处理。
    /// 规则侧拒它是因为执行侧不还原长路径（会「扫描命中、执行漏删」），
    /// 而这里的值直接进 protect 判定、那条链能正确处理 ⇒ 拒了只会误伤用户。
    ///
    /// 这条断言的作用是防止有人把两侧形态闸「顺手对齐」成一个列表 ——
    /// 那会把长路径配置场景打死，而两侧的**理由**根本不同。
    #[test]
    fn 长路径前缀在配置侧放行_与规则侧的理由不同() {
        assert!(
            path_value_problem(r"\\?\C:\Users\Administrator\AppData\Local\Temp").is_none(),
            "paths_save 拒了 \\\\?\\ 长路径前缀 —— 规则侧拒它的理由是执行侧不还原长路径，\
             与本处（值直接进 protect 判定，那条链能处理）不同，不该照抄"
        );
    }
}