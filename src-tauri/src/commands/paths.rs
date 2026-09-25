//! paths 域（批次 A）：paths:scan / load / save / browse / validate
//!
//! 白名单必须与渲染层 pathbinding.js 的 GROUPS 全集（4 组 10 项）+ scannedAt 保持同源
//! （审查 SET-1：原实现漏了 4 个「安装路径」key，导致设置页可编辑却静默保存失败）。
//!
//! A 批落 load/save/validate/browse（纯 fs + 原生对话框）与
//! app-icon/file-icon（Shell 图标提取）；C 批追补 `paths:scan`
//! （PS 扫描 + 当前生效规则库注入，超时 120s，结果即时落盘并统一写 scannedAt）。

use std::time::Duration;

use tauri::WebviewWindow;
use tauri_plugin_dialog::DialogExt;

use crate::engine::{guard, log, paths};
use crate::pwsh;
use crate::security;

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
    // 自动扫描时间戳（pathbinding.autoScan 回写）
    "scannedAt",
];

/// 读取路径配置（剥离历史遗留的软件清单字段）
fn load_paths_config() -> serde_json::Value {
    let v = security::read_json_or_quarantine(&paths::paths_config_file());
    match v {
        serde_json::Value::Object(mut m) => {
            m.remove("softwareInventory");
            serde_json::Value::Object(m)
        }
        other => other,
    }
}

fn save_paths_config(config: &serde_json::Value) -> bool {
    match security::atomic_write_json(&paths::paths_config_file(), config) {
        Ok(()) => {
            log::write_log("info", "路径配置已保存");
            true
        }
        Err(e) => {
            log::write_log("error", &format!("保存路径配置失败: {e}"));
            false
        }
    }
}

/// paths:load — 读取已保存的路径配置
#[tauri::command]
pub fn paths_load<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    Ok(serde_json::json!({ "success": true, "data": load_paths_config() }))
}

/// paths:save — 保存单个路径（key 白名单 + 长度/空字节校验 + 存在性回执）
#[tauri::command]
pub fn paths_save<R: tauri::Runtime>(window: WebviewWindow<R>, key: String, value: String) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    if !ALLOWED_KEYS.contains(&key.as_str()) || value.len() > 1024 || value.contains('\0') {
        return Ok(serde_json::json!({ "success": false, "message": "路径配置无效" }));
    }
    let mut config = load_paths_config();
    if let Some(obj) = config.as_object_mut() {
        obj.insert(key, serde_json::json!(value));
    }
    let exists = !value.is_empty() && std::path::Path::new(&value).exists();
    let saved = save_paths_config(&config);
    Ok(serde_json::json!({ "success": saved, "exists": exists }))
}

/// paths:browse — 原生选择文件夹对话框
#[tauri::command]
pub async fn paths_browse<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    title: Option<String>,
    default_path: Option<String>,
) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
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

/// paths:validate — 校验路径是否存在
#[tauri::command]
pub fn paths_validate<R: tauri::Runtime>(window: WebviewWindow<R>, path: Option<String>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let exists = path
        .filter(|p| !p.is_empty())
        .map(|p| std::path::Path::new(&p).exists())
        .unwrap_or(false);
    Ok(serde_json::json!({ "success": true, "exists": exists }))
}

/// paths:app-icon — 提取安装目录下主程序 exe 的图标（供路径绑定弹窗分组标题头）
/// 按 exeCandidates 顺序取第一个存在的；都不存在时退回安装目录本身的图标。
#[tauri::command]
pub async fn paths_app_icon<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    install_path: Option<String>,
    exe_candidates: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let install = install_path.unwrap_or_default();
    let candidates = exe_candidates.unwrap_or_default();
    if install.is_empty() || !std::path::Path::new(&install).exists() {
        return Ok(serde_json::json!({ "success": false, "dataUrl": null }));
    }
    let picked = candidates
        .iter()
        .filter(|c| !c.is_empty())
        .map(|c| std::path::Path::new(&install).join(c))
        .find(|p| p.exists());
    let target = picked.unwrap_or_else(|| std::path::PathBuf::from(&install));
    Ok(match crate::engine::shellicon::file_icon_data_url(&target) {
        Ok(url) => serde_json::json!({ "success": true, "dataUrl": url }),
        Err(_) => serde_json::json!({ "success": false, "dataUrl": null }),
    })
}

// ==================== paths:scan（C 批追补） ====================

/// 外置 PS 模板（源 `src/scripts-powershell/pathscan-scripts.js` → `scan(哨兵)`，
/// 由 `tools/sync-ps-from-js.mjs` 生成；**禁止手写/手改 PS 文本**）。
/// 哨兵 `__TRIM_RULES_JSON__` 出现在 `$rulesJson = '...'` 的单引号内，
/// 运行前替换为真实规则库 JSON（按 JS `psEscapeSingle` 同口径转义）。
const PATHS_SCAN_PS: &str = include_str!("../../ps/paths_scan.ps1");
/// 规则库 JSON 哨兵（见 tools/ps-map/paths.mjs）
const RULES_SENTINEL: &str = "__TRIM_RULES_JSON__";
/// 扫描超时（与 Electron 同值 120s）
const SCAN_TIMEOUT_SECS: u64 = 120;

/// 需加入 lib.rs `generate_handler!` 的完整行（A 批 6 条见各自实现，本条为 C 批追补）：
///   commands::paths::paths_scan,
///
/// JS `psEscapeSingle`：单引号加倍（PowerShell 单引号字符串的唯一转义规则）
fn ps_escape_single(s: &str) -> String {
    s.replace('\'', "''")
}

/// paths:scan — 自动扫描安装路径（注入当前生效规则库）
#[tauri::command]
pub async fn paths_scan<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
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
    let rules_json = match crate::commands::cleanup::rules_value() {
        Ok(v) => serde_json::to_string(&v).unwrap_or_default(),
        Err(e) => {
            log::write_log("warn", &format!("规则库不可用，路径扫描按内置候选兜底: {e}"));
            String::new()
        }
    };

    // S1：原生优先，失败自动回退 PS
    let native_result = crate::engine::native::paths_scan(&rules_json);
    let mut data: serde_json::Value = match native_result {
        Ok(d) => {
            log::write_log("info", "安装路径原生扫描完成");
            d
        }
        Err(e) => {
            log::write_log("warn", &format!("安装路径原生扫描失败，回退 PS: {e}"));
            let script_text = PATHS_SCAN_PS.replace(RULES_SENTINEL, &ps_escape_single(&rules_json));
    // 哨兵必须消失：残留即模板与替换口径漂移，宁可失败也不跑半成品脚本
    if script_text.contains(RULES_SENTINEL) {
        log::write_log("error", "路径扫描脚本哨兵替换失败，已拒绝执行（模板与注入口径不一致）");
        return serde_json::json!({ "success": false, "message": "扫描失败", "data": {} });
    }
    let script = match pwsh::write_temp_script(&script_text, ".ps1") {
        Ok(p) => p,
        Err(e) => {
            log::write_log("error", &format!("路径扫描失败: {e}"));
            return serde_json::json!({ "success": false, "message": e, "data": {} });
        }
    };
    log::write_log("info", "开始扫描安装路径");
    let result = pwsh::run_file(
        &script,
        Duration::from_secs(SCAN_TIMEOUT_SECS),
        Some("paths:scan"),
    );
    let _ = std::fs::remove_file(&script);
    let out = match result {
        Ok(o) => o,
        Err(e) => {
            log::write_log("error", &format!("路径扫描失败: {e}"));
            return serde_json::json!({ "success": false, "message": e, "data": {} });
        }
    };
    if out.code != 0 {
        let message = if out.stderr.trim().is_empty() {
            "扫描失败".to_string()
        } else {
            out.stderr.trim().to_string()
        };
        log::write_log("error", &format!("路径扫描失败: {message}"));
        return serde_json::json!({ "success": false, "message": message, "data": {} });
    }
            match serde_json::from_str(out.stdout.trim()) {
                Ok(v) => v,
                Err(_) => {
                    return serde_json::json!({
                        "success": false,
                        "message": "解析结果失败",
                        "raw": out.stdout
                    })
                }
            }
        }
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
    let mut persisted = load_paths_config();
    if let (Some(pmap), Some(dmap)) = (persisted.as_object_mut(), data.as_object()) {
        for (key, value) in dmap {
            let keep = match value {
                serde_json::Value::String(s) => !s.is_empty(),
                serde_json::Value::Array(_) => true,
                _ => false,
            };
            if keep {
                pmap.insert(key.clone(), value.clone());
            }
        }
    }
    // SET-5（2026-09-15）：时间戳统一写 scannedAt。原写 lastScanAt，而渲染层/
    // paths:load 只读 scannedAt → 重启后页脚恒显「尚未扫描」（键名两侧不一致）。
    let scanned_at = data
        .get("scannedAt")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(crate::commands::settings::iso_utc_now);
    if let Some(pmap) = persisted.as_object_mut() {
        pmap.insert("scannedAt".into(), serde_json::Value::String(scanned_at));
    }
    save_paths_config(&persisted);
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
    Ok(match crate::engine::shellicon::file_icon_data_url(std::path::Path::new(&path)) {
        Ok(url) => serde_json::json!({ "success": true, "dataUrl": url }),
        Err(_) => serde_json::json!({ "success": false, "dataUrl": null }),
    })
}