//! fonts 域（C 批）：fonts:list / fonts:import / fonts:remove-imported / fonts:save-config
//!
//! 对照 main.js 6499-6657（FONT_* 常量、loadFontState、isFontFileValid 与四条通道）。
//!
//! # 要点
//!
//! - 配置真源仍是 `settings.json` 的 `font` / `fontImported` 字段（经 settings 域的
//!   密钥存储链读写；本域不碰密钥，但必须走同一读写入口以免覆盖别处的字段）；
//! - **单字体约束**：只保留 1 款导入字体，再次导入替换（删旧副本 + 覆盖记录）；
//! - 导入前做魔数校验（TTF/OTF/TTC/旧式 true/WOFF/WOFF2），阻止损坏文件注入无效 @font-face；
//! - `fonts:save-config` 在 Rust 侧权威钳制 weight ∈ [100,1000]、size ∈ [12,24]，
//!   并剥离 family 中的 `'` 与 `\`（防止 CSS 注入与路径误用）。
//!
//! # 已知差异（登记，需双跑确认）
//!
//! `copyUrl` 与 Electron 同为 `pathToFileURL(copyPath).href`（`file:///...`）。
//! Tauri 页面源是 `http://tauri.localhost`，Chromium 会拦截从 web 源加载 `file:` 子资源，
//! 因此该 URL 上的 `@font-face` 可能加载失败（Electron 页面是 file: 源，不受此限）。
//! 处置与 B3 记载一致：待 asset 协议（`asset:`/`http://asset.localhost`）启用时，
//! 由 `fileclean:read-image` 等通道一并改造（需同步调整 index.html 的 CSP 与
//! tauri.conf.json 的 assetProtocol scope）。当前契约字段不变，先如实登记。
//!
//! 需要加入 lib.rs `generate_handler!` 的完整行：
//!   commands::fonts::fonts_list,
//!   commands::fonts::fonts_import,
//!   commands::fonts::fonts_remove_imported,
//!   commands::fonts::fonts_save_config,

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tauri::WebviewWindow;
use tauri_plugin_dialog::DialogExt;

use crate::engine::{guard, log, paths};

use super::settings::{self, js_number, truthy_string};

/// 导入字体副本目录（`<数据目录>/fonts`）
fn fonts_dir() -> PathBuf {
    paths::join_data("fonts")
}

/// 导入字体固定副本名（单字体约束：同名覆盖，不留历史副本）
const IMPORTED_BASE: &str = "imported";

/// 5 款系统字体（文件存在性探测，无需管理员权限）
const FONT_SYSTEM_FAMILIES: &[(&str, &str, &[&str])] = &[
    (
        "微软雅黑",
        "'微软雅黑', 'Microsoft YaHei', sans-serif",
        &["C:\\Windows\\Fonts\\msyh.ttc", "C:\\Windows\\Fonts\\msyh.ttf"],
    ),
    (
        "黑体",
        "'黑体', SimHei, sans-serif",
        &["C:\\Windows\\Fonts\\simhei.ttf"],
    ),
    (
        "宋体",
        "'宋体', SimSun, serif",
        &["C:\\Windows\\Fonts\\simsun.ttc"],
    ),
    (
        "楷体",
        "'楷体', KaiTi, serif",
        &["C:\\Windows\\Fonts\\simkai.ttf"],
    ),
    (
        "Times New Roman",
        "'Times New Roman', Times, serif",
        &["C:\\Windows\\Fonts\\times.ttf"],
    ),
];

/// 内嵌 MiSans 可变字体（随应用分发，恒可用）
const FONT_MISANS_FAMILY: &str = "MiSans";
const FONT_MISANS_CSS: &str = "'MiSans', '微软雅黑', 'Microsoft YaHei', sans-serif";
const FONT_DEFAULT_FAMILY: &str = "MiSans";
const FONT_DEFAULT_WEIGHT: i64 = 400;
const FONT_DEFAULT_SIZE: i64 = 16;

/// 剥离 family 中的 `'` 与 `\`（CSS 注入与路径误用防护，与 JS 正则同口径）
fn sanitize_family(raw: &str) -> String {
    raw.chars().filter(|c| *c != '\'' && *c != '\\').collect()
}

/// `fontCssStackFor`：导入字体在字体栈中的首选，其后回落系统字体
fn font_css_stack_for(family: &str) -> String {
    format!("'{}', '微软雅黑', 'Microsoft YaHei', sans-serif", sanitize_family(family))
}

/// `loadFontState`：settings 合并出厂默认后的字体设置 + 导入记录
fn load_font_state() -> (Value, Option<Value>) {
    let s = settings::load_settings();
    let mut font = json!({
        "family": FONT_DEFAULT_FAMILY,
        "weight": FONT_DEFAULT_WEIGHT,
        "size": FONT_DEFAULT_SIZE,
    });
    if let (Some(base), Some(stored)) = (font.as_object_mut(), s.get("font").and_then(|v| v.as_object())) {
        for (k, v) in stored {
            base.insert(k.clone(), v.clone());
        }
    }
    let imported = s
        .get("fontImported")
        .filter(|v| v.is_object())
        .cloned();
    (font, imported)
}

/// `isFontFileValid`：读前 4 字节做魔数校验
fn is_font_file_valid(file: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(file) else {
        return false;
    };
    let mut buf = [0u8; 4];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    if buf == [0x00, 0x01, 0x00, 0x00] {
        return true; // TTF
    }
    let tag = &buf[..];
    if tag == b"OTTO" || tag == b"ttcf" || tag == b"true" {
        return true; // OTF / TTC 集合 / 旧式 TTF
    }
    tag.starts_with(b"wOF") // WOFF / WOFF2
}

/// `url.pathToFileURL(p).href`（供渲染层注入 @font-face）
fn path_to_file_url(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let mut out = String::from("file:///");
    for byte in normalized.bytes() {
        let c = byte as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '/' | ':') {
            out.push(c);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// 文件名字符串（JS `path.basename` 等价）
fn file_name_of(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// `path.extname(p).toLowerCase()`（带点；无扩展名返回空串）
fn ext_name_of(path: &str) -> String {
    Path::new(path)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()))
        .unwrap_or_default()
}

/// fonts:list — 系统字体可用性 + MiSans + 导入字体
#[tauri::command]
pub fn fonts_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let (settings, imported) = load_font_state();
    let mut list: Vec<Value> = FONT_SYSTEM_FAMILIES
        .iter()
        .map(|(family, css, files)| {
            json!({
                "family": family,
                "cssStack": css,
                "available": files.iter().any(|p| Path::new(p).exists()),
                "builtin": false,
                "imported": false,
            })
        })
        .collect();
    list.push(json!({
        "family": FONT_MISANS_FAMILY,
        "cssStack": FONT_MISANS_CSS,
        "available": true,
        "builtin": true,
        "imported": false,
    }));
    let imported_summary = match &imported {
        Some(record) => {
            let family = truthy_string(record.get("family")).unwrap_or_default();
            let copy_path = truthy_string(record.get("copyPath")).unwrap_or_default();
            let available = !copy_path.is_empty() && Path::new(&copy_path).exists();
            list.push(json!({
                "family": family,
                "cssStack": font_css_stack_for(&family),
                "available": available,
                "builtin": false,
                "imported": true,
                "copyUrl": if available { path_to_file_url(&copy_path) } else { String::new() },
                "sourcePath": truthy_string(record.get("sourcePath")).unwrap_or_default(),
            }));
            json!({
                "family": family,
                "sourcePath": truthy_string(record.get("sourcePath")).unwrap_or_default(),
                "copyPath": copy_path,
            })
        }
        None => Value::Null,
    };
    Ok(json!({
        "success": true,
        "data": {
            "list": list,
            "settings": settings,
            "imported": imported_summary,
        }
    }))
}

/// fonts:import — 原生对话框选字体 → 魔数校验 → 复制副本 → 记录到 settings.json
#[tauri::command]
pub async fn fonts_import<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let picked = window
        .dialog()
        .file()
        .set_title("导入字体文件（将替换当前已导入字体）")
        .add_filter("字体文件", &["ttf", "otf", "woff", "woff2"])
        .blocking_pick_file();
    let Some(picked) = picked else {
        return Ok(json!({ "success": false, "canceled": true }));
    };
    let src = match picked.into_path() {
        Ok(p) => p,
        Err(e) => return Ok(json!({ "success": false, "message": format!("无效路径: {e}") })),
    };
    let src_str = src.to_string_lossy().to_string();
    if !src.exists() {
        return Ok(json!({ "success": false, "message": "字体文件不存在或不可访问" }));
    }
    let meta = match std::fs::metadata(&src) {
        Ok(m) => m,
        Err(_) => return Ok(json!({ "success": false, "message": "字体文件为空或不可读取" })),
    };
    if !meta.is_file() || meta.len() == 0 {
        return Ok(json!({ "success": false, "message": "字体文件为空或不可读取" }));
    }
    if !is_font_file_valid(&src) {
        return Ok(json!({
            "success": false,
            "message": "该文件不是有效的字体文件（支持 .ttf / .otf / .woff / .woff2），请检查文件是否损坏"
        }));
    }

    let dir = fonts_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log::write_log("error", &format!("导入字体失败: 创建字体目录失败 {e}"));
        return Ok(json!({ "success": false, "message": format!("导入失败：{e}") }));
    }
    let s = settings::load_settings();
    let prev = s.get("fontImported").filter(|v| v.is_object()).cloned();
    let family = {
        let base = file_name_of(&src_str);
        let stripped = strip_font_ext(&base);
        let cleaned = sanitize_family(&stripped).trim().to_string();
        if cleaned.is_empty() {
            "导入字体".to_string()
        } else {
            cleaned
        }
    };
    let ext = {
        let e = ext_name_of(&src_str);
        if e.is_empty() {
            ".ttf".to_string()
        } else {
            e
        }
    };
    let copy_path = dir.join(format!("{IMPORTED_BASE}{ext}"));
    let copy_str = copy_path.to_string_lossy().to_string();
    if let Err(e) = std::fs::copy(&src, &copy_path) {
        log::write_log("error", &format!("导入字体失败: {e}"));
        return Ok(json!({ "success": false, "message": format!("导入失败：{e}") }));
    }
    // 替换旧导入：删除旧副本（路径不同才删，相同则已被覆盖）
    if let Some(prev) = &prev {
        if let Some(prev_copy) = truthy_string(prev.get("copyPath")) {
            if !prev_copy.is_empty() && !same_path(&prev_copy, &copy_str) {
                if let Err(e) = std::fs::remove_file(&prev_copy) {
                    log::write_log("warn", &format!("旧导入字体副本删除失败: {e}"));
                }
            }
        }
    }
    let record = json!({
        "family": family,
        "sourcePath": src_str,
        "copyPath": copy_str,
        "importedAt": settings::iso_utc_now(),
    });
    let mut next = s.clone();
    if let Some(map) = next.as_object_mut() {
        map.insert("fontImported".into(), record);
    }
    settings::save_settings(&next);
    log::write_log("info", &format!("导入字体: {family}（副本已复制到 {copy_str}）"));
    Ok(json!({
        "success": true,
        "data": { "family": family, "copyUrl": path_to_file_url(&copy_str) }
    }))
}

/// `path.resolve(a) !== path.resolve(b)` 等价（大小写不敏感比较 + 规范化）
fn same_path(a: &str, b: &str) -> bool {
    let norm = |p: &str| -> String {
        let pb = PathBuf::from(p);
        let full = std::fs::canonicalize(&pb).unwrap_or(pb);
        full.to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .to_ascii_lowercase()
    };
    norm(a) == norm(b)
}

/// `basename.replace(/\.(ttf|otf|woff2?)$/i, '')`
fn strip_font_ext(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for ext in [".ttf", ".otf", ".woff2", ".woff"] {
        if lower.ends_with(ext) {
            return name[..name.len() - ext.len()].to_string();
        }
    }
    name.to_string()
}

/// fonts:remove-imported — 移除记录 + 删除本地副本（不触碰用户原始文件）
#[tauri::command]
pub fn fonts_remove_imported<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let s = settings::load_settings();
    let Some(prev) = s.get("fontImported").filter(|v| v.is_object()).cloned() else {
        return Ok(json!({ "success": true, "data": { "removed": false } }));
    };
    let mut next = s.clone();
    if let Some(map) = next.as_object_mut() {
        map.remove("fontImported");
        // 若当前选中字体正是被删除的导入字体，回退默认 MiSans
        let current_family = map
            .get("font")
            .and_then(|f| f.get("family"))
            .map(settings::js_string)
            .unwrap_or_default();
        let prev_family = truthy_string(prev.get("family")).unwrap_or_default();
        if current_family == prev_family {
            let mut font = map.get("font").cloned().unwrap_or_else(|| json!({}));
            if let Some(fm) = font.as_object_mut() {
                fm.insert("family".into(), json!(FONT_DEFAULT_FAMILY));
            }
            map.insert("font".into(), font);
        }
    }
    settings::save_settings(&next);
    let mut file_deleted = true;
    if let Some(copy_path) = truthy_string(prev.get("copyPath")) {
        if !copy_path.is_empty() {
            if let Err(e) = std::fs::remove_file(&copy_path) {
                file_deleted = false;
                log::write_log("warn", &format!("导入字体副本删除失败: {e}"));
            }
        }
    }
    log::write_log(
        "info",
        &format!(
            "删除导入字体: {}{}",
            truthy_string(prev.get("family")).unwrap_or_default(),
            if file_deleted { "" } else { "（副本文件删除失败，记录已移除）" }
        ),
    );
    Ok(json!({
        "success": true,
        "data": { "removed": true, "fileDeleted": file_deleted }
    }))
}

/// fonts:save-config — 保存 family / weight / size（Rust 侧权威钳制）
#[tauri::command]
pub fn fonts_save_config<R: tauri::Runtime>(window: WebviewWindow<R>, config: Option<Value>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let cfg = config.unwrap_or_else(|| json!({}));
    let s = settings::load_settings();
    let prev = s.get("font").filter(|v| v.is_object()).cloned().unwrap_or_else(|| json!({}));

    let size = {
        let n = cfg.get("size").map(js_number).unwrap_or(f64::NAN);
        let n = if n.is_finite() && n != 0.0 { n } else { FONT_DEFAULT_SIZE as f64 };
        n.max(12.0).min(24.0)
    };
    let weight = {
        let n = cfg.get("weight").map(js_number).unwrap_or(f64::NAN);
        let n = if n.is_finite() && n != 0.0 { n } else { FONT_DEFAULT_WEIGHT as f64 };
        n.max(100.0).min(1000.0)
    };
    let family = {
        let submitted = truthy_string(cfg.get("family"))
            .or_else(|| truthy_string(prev.get("family")))
            .unwrap_or_else(|| FONT_DEFAULT_FAMILY.to_string());
        sanitize_family(&submitted)
    };
    let font = json!({
        "family": family,
        "weight": if weight.fract() == 0.0 { json!(weight as i64) } else { json!(weight) },
        "size": if size.fract() == 0.0 { json!(size as i64) } else { json!(size) },
    });
    let mut next = s.clone();
    if let Some(map) = next.as_object_mut() {
        map.insert("font".into(), font.clone());
    }
    settings::save_settings(&next);
    Ok(json!({ "success": true, "data": font }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_url_matches_node_shape() {
        assert_eq!(
            path_to_file_url("C:\\Users\\Admin\\AppData\\Roaming\\Trim\\fonts\\imported.ttf"),
            "file:///C:/Users/Admin/AppData/Roaming/Trim/fonts/imported.ttf"
        );
        assert_eq!(path_to_file_url("C:\\a b\\x.ttf"), "file:///C:/a%20b/x.ttf");
    }

    #[test]
    fn family_sanitized_and_ext_stripped() {
        assert_eq!(sanitize_family("My'Font\\X"), "MyFontX");
        assert_eq!(strip_font_ext("MyFont.WOFF2"), "MyFont");
        assert_eq!(strip_font_ext("MyFont"), "MyFont");
    }

    #[test]
    fn magic_check_rejects_garbage() {
        let dir = std::env::temp_dir().join("trim-fonts-test");
        let _ = std::fs::create_dir_all(&dir);
        let bad = dir.join("bad.ttf");
        std::fs::write(&bad, b"not a font").unwrap();
        assert!(!is_font_file_valid(&bad));
        let good = dir.join("good.ttf");
        std::fs::write(&good, [0x00u8, 0x01, 0x00, 0x00, 0xAA]).unwrap();
        assert!(is_font_file_valid(&good));
        let woff = dir.join("good.woff2");
        std::fs::write(&woff, b"wOF2xxxx").unwrap();
        assert!(is_font_file_valid(&woff));
        let _ = std::fs::remove_file(&bad);
        let _ = std::fs::remove_file(&good);
        let _ = std::fs::remove_file(&woff);
    }
}