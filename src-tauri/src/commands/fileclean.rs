//! fileclean 域（D 批）：fileclean:scan / read-image / delete-file / execute
//!
//! 对照 Electron main.js 7086-7334。QQ/微信文件清理：
//! 扫描选定目录（深度 ≤4、上限 2000 项）→ 分类 image/video/cache/data →
//! 只允许删除本窗口本次扫描结果内的文件；删除一律回收站优先 + 删除清单落盘。
//!
//! 关键安全/语义（与 Electron 逐条对齐）：
//! - 扫描根只能来自已保存的路径配置（qqFileDir / wechatFileDir），
//!   customPath 必须与解析后的配置一致——防止借扫描读任意目录。
//! - BFS 跳过符号链接/junction；depth 0 根层不收文件；depth<2 不深入
//!   recv*/msg* 目录（FC-2：根层 .dat 是账号数据库，.db 永不归 data，FC-3）。
//! - 扫描结果按「窗口 label + type」分槽；读图/删文件/批量删全部过本槽白名单。
//! - data 类只收 `.dat`（排除 .db/.adb/.aes 等数据库/密钥文件）。
//! - read-image 仅图片扩展名 + ≤10MB，base64 dataURL。
//! - 危险操作前 flush_sync；success 语义=通道执行成功（失败明细随 data 返回）。

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use base64::Engine;
use serde_json::{json, Value};
use tauri::{Emitter, Runtime, WebviewWindow};

use crate::engine::{delete_manifest, guard, log, paths};
use crate::security;

const MAX_FILES: usize = 2000;
const MAX_DEPTH: usize = 4;
const MAX_PATH_LEN: usize = 400;
const IMAGE_MAX_BYTES: u64 = 10 * 1024 * 1024;

const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "gif", "bmp", "webp", "svg"];
const VIDEO_EXTS: &[&str] = &["mp4", "avi", "mov", "mkv", "flv"];
const CACHE_EXTS: &[&str] = &["tmp", "log", "bak", "cache"];

#[derive(Clone)]
struct Scope {
    root: String,
    files: HashSet<String>,
}

static SCOPES: Mutex<Option<HashMap<String, Scope>>> = Mutex::new(None);

fn slot_key(label: &str, ty: &str) -> String {
    format!("{label}:{ty}")
}

fn scope_store(label: &str, ty: &str, root: String, files: HashSet<String>) {
    let mut g = SCOPES.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashMap::new)
        .insert(slot_key(label, ty), Scope { root, files });
}

fn scope_get(label: &str, ty: &str) -> Option<Scope> {
    SCOPES.lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(&slot_key(label, ty)).cloned())
}

/// 词法规范化（不触盘）：折叠 . / .. 组件、统一反斜杠、小写、去尾部分隔符。
fn path_key(p: &str) -> String {
    let mut s: String = String::new();
    for c in Path::new(p).components() {
        match c {
            Component::Prefix(pre) => s.push_str(&pre.as_os_str().to_string_lossy()),
            Component::RootDir => s.push('\\'),
            Component::CurDir => {}
            Component::ParentDir => {
                // 绝对路径回退：弹掉末段（盘符/根保留）
                if let Some(pos) = s.rfind('\\').filter(|&i| i > 2) {
                    s.truncate(pos);
                }
            }
            Component::Normal(n) => {
                if !s.ends_with('\\') && !s.is_empty() {
                    s.push('\\');
                }
                s.push_str(&n.to_string_lossy());
            }
        }
    }
    s.trim_end_matches('\\').to_lowercase()
}

fn config_key(ty: &str) -> &'static str {
    if ty == "qq" {
        "qqFileDir"
    } else {
        "wechatFileDir"
    }
}

fn default_dirs(ty: &str) -> Vec<PathBuf> {
    let home = std::env::var("USERPROFILE").map(PathBuf::from).unwrap_or_default();
    let docs = home.join("Documents");
    if ty == "qq" {
        vec![docs.join("Tencent Files")]
    } else {
        vec![docs.join("xwechat_files")]
    }
}

fn configured_dir(ty: &str, custom: &Option<String>) -> Option<PathBuf> {
    if let Some(c) = custom {
        if !c.is_empty() {
            return Some(PathBuf::from(c));
        }
    }
    let cfg = security::read_json_or_quarantine(&paths::paths_config_file());
    if let Some(v) = cfg.get(config_key(ty)).and_then(|v| v.as_str()) {
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    default_dirs(ty).into_iter().find(|p| p.is_dir())
}

fn ext_of(name: &str) -> String {
    Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

fn classify(ext: &str) -> Option<&'static str> {
    if IMAGE_EXTS.contains(&ext) {
        Some("image")
    } else if VIDEO_EXTS.contains(&ext) {
        Some("video")
    } else if CACHE_EXTS.contains(&ext) {
        Some("cache")
    } else if ext == "dat" {
        Some("data") // FC-3：仅 .dat；.db/.adb/.aes 等排除
    } else {
        None
    }
}

/// BFS 扫描（不跟随符号链接）。返回 (items, scanned_count)。
fn scan_root(root: &Path) -> (Vec<Value>, usize) {
    let mut items: Vec<Value> = Vec::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((root.to_path_buf(), 0));
    let mut scanned = 0usize;

    while let Some((dir, depth)) = queue.pop_front() {
        if items.len() >= MAX_FILES || depth > MAX_DEPTH {
            continue;
        }
        let rd = match std::fs::symlink_metadata(&dir) {
            Ok(m) => {
                if m.file_type().is_symlink() {
                    continue;
                }
                match std::fs::read_dir(&dir) {
                    Ok(rd) => rd,
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        };
        let mut subdirs: Vec<PathBuf> = Vec::new();
        for ent in rd.flatten() {
            if items.len() >= MAX_FILES {
                break;
            }
            let name = ent.file_name().to_string_lossy().to_string();
            let full = ent.path();
            let md = match ent.metadata() {
                // DirEntry::metadata 不跟随符号链接（Windows 上跟随；用 symlink_metadata 复核）
                Ok(m) => m,
                Err(_) => continue,
            };
            let sym = std::fs::symlink_metadata(&full)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(true);
            if sym {
                continue;
            }
            if md.is_dir() {
                let lname = name.to_lowercase();
                // depth<2 不深入 recv*/msg*（FC-2）
                let is_msgish =
                    lname.starts_with("recv") || lname == "msg" || lname.starts_with("msg");
                if depth < 2 && is_msgish {
                    continue;
                }
                subdirs.push(full);
            } else if md.is_file() {
                // 根层文件不收
                if depth == 0 {
                    continue;
                }
                scanned += 1;
                let cat = match classify(&ext_of(&name)) {
                    Some(c) => c,
                    None => continue,
                };
                let size = md.len();
                let mtime = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let path_str = full.to_string_lossy().replace('/', "\\");
                items.push(json!({
                    "path": path_str,
                    "name": name,
                    "size": size,
                    "mtime": mtime.to_string(),
                    "ext": ext_of(&name),
                    "category": cat,
                }));
            }
        }
        if depth < MAX_DEPTH {
            for d in subdirs {
                queue.push_back((d, depth + 1));
            }
        }
    }
    (items, scanned)
}

/// fileclean:scan
#[tauri::command]
pub async fn fileclean_scan<R: Runtime>(
    window: WebviewWindow<R>,
    scan_type: Option<String>,
    custom_path: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "data": [], "message": msg });
    }
    let ty = match scan_type.as_deref() {
        Some("qq") | Some("wechat") => scan_type.unwrap(),
        _ => return json!({ "success": false, "data": [], "message": "未知类型" }),
    };

    let Some(scan_path) = configured_dir(&ty, &custom_path) else {
        return json!({
            "success": false,
            "data": [],
            "message": "路径不存在，请在设置中配置文件目录"
        });
    };

    // 存在 + 普通目录 + 非链接
    let md = match std::fs::symlink_metadata(&scan_path) {
        Ok(m) => m,
        Err(_) => {
            return json!({
                "success": false, "data": [],
                "message": "路径不存在，请在设置中配置文件目录"
            });
        }
    };
    if !md.is_dir() || md.file_type().is_symlink() {
        return json!({ "success": false, "data": [], "message": "扫描路径必须是普通目录" });
    }
    let resolved = scan_path
        .canonicalize()
        .unwrap_or_else(|_| scan_path.clone())
        .to_string_lossy()
        .replace('/', "\\");

    // customPath 必须等于已保存配置（防借扫描读任意目录）
    if let Some(c) = custom_path.as_ref() {
        if !c.is_empty() && path_key(c) != path_key(&resolved) {
            return json!({
                "success": false, "data": [],
                "message": "扫描路径必须来自已保存的路径配置，请先在设置中保存该路径"
            });
        }
    }
    if resolved.len() > MAX_PATH_LEN {
        return json!({ "success": false, "data": [], "message": "扫描路径过长" });
    }

    let label = window.label().to_string();
    let ty2 = ty.clone();
    let root2 = resolved.clone();
    let heavy = scan_path.to_string_lossy().contains("tencent")
        || resolved.to_lowercase().contains("xwechat");
    let result = tauri::async_runtime::spawn_blocking(move || scan_root(Path::new(&root2)))
        .await;
    let (items, scanned) = match result {
        Ok(v) => v,
        Err(e) => {
            log::write_log("error", &format!("文件清理扫描任务异常: {e}"));
            return json!({ "success": false, "data": [], "message": e.to_string() });
        }
    };

    let total_size: u64 = items
        .iter()
        .map(|f| f.get("size").and_then(|v| v.as_u64()).unwrap_or(0))
        .sum();

    // 分槽：root + 文件路径集合
    let files: HashSet<String> = items
        .iter()
        .filter_map(|f| f.get("path").and_then(|v| v.as_str()).map(|s| path_key(s)))
        .collect();
    scope_store(&label, &ty2, path_key(&resolved), files);

    log::write_log(
        "info",
        &format!(
            "文件清理扫描完成: {} -> {} 项，{} 字节，枚举 {} 个文件{}",
            ty2,
            items.len(),
            total_size,
            scanned,
            if heavy { "（大目录）" } else { "" }
        ),
    );
    let _ = window.emit(
        "cleanup:scan-progress",
        json!({ "scanType": ty2, "done": items.len(), "total": items.len() }),
    );

    json!({
        "success": true,
        "data": {
            "files": items,
            "totalSize": total_size.to_string(),
            "scanPath": resolved
        }
    })
}

fn in_scope(scope: &Scope, file_path: &str) -> bool {
    let k = path_key(file_path);
    k.starts_with(&scope.root) && scope.files.contains(&k)
}

fn image_mime(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        _ => return None,
    })
}

/// fileclean:read-image —— 仅扫描范围内的图片，≤10MB，返回 dataURL
///
/// 为什么**不**改走 asset 协议（与 backgrounds/fonts 不同处置）：本通道的图源是用户在
/// paths.json 里自选的 QQ / 微信目录，位置任意且运行时才知道；asset 协议的 scope 只能是
/// `tauri.conf.json` 里的静态 glob，要覆盖它们就得放开整个用户目录 —— 那是把「webview 可读
/// 全盘」当成省一次 base64 的代价，不划算。dataURL 路径本就可用，且有 ≤10MB 上界兜着。
#[tauri::command]
pub async fn fileclean_read_image<R: Runtime>(
    window: WebviewWindow<R>,
    file_path: String,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    if file_path.is_empty() || file_path.len() > MAX_PATH_LEN {
        return json!({ "success": false, "message": "文件不存在" });
    }
    // 找到包含该文件的槽（qq/wechat 任一）
    let scope = ["qq", "wechat"]
        .iter()
        .find_map(|t| scope_get(window.label(), t).filter(|s| in_scope(s, &file_path)));
    let Some(scope) = scope else {
        return json!({ "success": false, "message": "路径不在扫描范围内，已拒绝访问" });
    };
    let _ = scope;

    let md = match std::fs::metadata(&file_path) {
        Ok(m) if m.is_file() => m,
        _ => return json!({ "success": false, "message": "文件不存在" }),
    };
    if md.len() > IMAGE_MAX_BYTES {
        return json!({ "success": false, "message": "文件过大，不支持预览" });
    }
    let ext = ext_of(&file_path);
    let Some(mime) = image_mime(&ext) else {
        return json!({ "success": false, "message": "仅支持预览图片文件（jpg/png/gif/bmp/webp/svg）" });
    };
    let bytes = match std::fs::read(&file_path) {
        Ok(b) => b,
        Err(_) => return json!({ "success": false, "message": "文件不存在" }),
    };
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    json!({ "success": true, "data": format!("data:{mime};base64,{b64}"), "size": md.len() })
}

/// 回收站删除单个文件（供 delete-file / execute 共用），返回 (ok, recycled, message)
fn recycle_one(file_path: &str) -> (bool, bool, String) {
    match trim_finder::scan::recycle::send_to_trash(file_path) {
        Ok(()) => (true, true, String::new()),
        Err(e1) => {
            // 回收站失败仅在明确失败时才永久删除（与 Electron trashOrUnlink 不同：
            // D 批统一安全口径，回收站失败直接报错，不做永久删除兜底）
            (false, false, e1)
        }
    }
}

/// fileclean:delete-file —— 预览窗删除当前图片
#[tauri::command]
pub async fn fileclean_delete_file<R: Runtime>(
    window: WebviewWindow<R>,
    file_path: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    if file_path.is_empty() || file_path.len() > MAX_PATH_LEN {
        return json!({ "success": false, "message": "文件不存在" });
    }
    let ty = ["qq", "wechat"]
        .iter()
        .find_map(|t| scope_get(window.label(), t).filter(|s| in_scope(s, &file_path)).map(|_| *t));
    let Some(ty) = ty else {
        return json!({ "success": false, "message": "路径不在扫描范围内，已拒绝删除" });
    };

    let is_file = std::fs::metadata(&file_path)
        .map(|m| m.is_file())
        .unwrap_or(false);
    if !is_file {
        return json!({ "success": false, "message": "目标不是普通文件，已拒绝删除" });
    }

    crate::engine::log::flush_sync();
    let size = std::fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);
    let (ok, recycled, msg) = recycle_one(&file_path);
    if ok {
        let batch = delete_manifest::new_batch_id();
        let entry = json!({
            "path": file_path.replace('/', "\\"),
            "kind": "file",
            "size": size,
            "recycled": recycled
        });
        delete_manifest::save_delete_manifest(&batch, &[entry]);
        // 从槽中移除
        if let Some(mut s) = scope_get(window.label(), ty) {
            s.files.remove(&path_key(&file_path));
            let mut g = SCOPES.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(m) = g.as_mut() {
                m.insert(slot_key(window.label(), ty), s);
            }
        }
        log::write_log(
            "info",
            &format!("删除预览图片（回收站）: {file_path}"),
        );
        json!({ "success": true, "recycled": recycled, "manifestPath": format!("deleted-{batch}.json") })
    } else {
        json!({ "success": false, "message": msg })
    }
}

/// fileclean:execute —— 批量删除选中文件（全部必须在本槽扫描范围内）
#[tauri::command]
pub async fn fileclean_execute<R: Runtime>(
    window: WebviewWindow<R>,
    files: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let files = files.unwrap_or_default();
    if files.is_empty() {
        return json!({ "success": false, "message": "没有选中文件" });
    }

    // 确定槽：用第一项反查（一次 execute 只扫一个 type 的结果）
    let first_path = files
        .first()
        .and_then(|f| f.get("path").and_then(|v| v.as_str()))
        .unwrap_or("");
    let ty = ["qq", "wechat"]
        .iter()
        .find_map(|t| scope_get(window.label(), t).filter(|s| in_scope(s, first_path)).map(|_| *t));
    let Some(ty) = ty else {
        return json!({ "success": false, "message": "至少一个文件不在扫描范围内，已拒绝整批" });
    };
    let scope = scope_get(window.label(), ty).unwrap();

    // 全部命中本槽才放行
    for f in &files {
        let p = f.get("path").and_then(|v| v.as_str()).unwrap_or("");
        if !in_scope(&scope, p) {
            return json!({ "success": false, "message": "包含不在扫描范围内的路径，已拒绝整批" });
        }
        if std::fs::metadata(p).map(|m| !m.is_file()).unwrap_or(true) {
            return json!({ "success": false, "message": "包含非普通文件，已拒绝整批" });
        }
    }

    crate::engine::log::flush_sync();
    let mut freed = 0u64;
    let mut success_n = 0usize;
    let mut failed = 0usize;
    let mut recycled_n = 0usize;
    let mut details: Vec<Value> = Vec::new();
    let mut manifest_entries: Vec<Value> = Vec::new();
    let mut removed_keys: HashSet<String> = HashSet::new();

    for f in &files {
        let p = f.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        let (ok, recycled, message) = recycle_one(&p);
        if ok {
            freed += size;
            success_n += 1;
            if recycled {
                recycled_n += 1;
            }
            manifest_entries.push(json!({
                "path": p.replace('/', "\\"),
                "kind": "file",
                "freed": size,
                "recycled": recycled
            }));
            removed_keys.insert(path_key(&p));
        } else {
            failed += 1;
        }
        details.push(json!({
            "path": p,
            "status": if ok { "ok" } else { "error" },
            "freed": if ok { size } else { 0 },
            "message": if ok { Value::Null } else { json!(message) }
        }));
    }

    if !manifest_entries.is_empty() {
        let batch = delete_manifest::new_batch_id();
        delete_manifest::save_delete_manifest(&batch, &manifest_entries);
    }
    // 更新槽
    if !removed_keys.is_empty() {
        if let Some(mut s) = scope_get(window.label(), ty) {
            for k in &removed_keys {
                s.files.remove(k);
            }
            let mut g = SCOPES.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(m) = g.as_mut() {
                m.insert(slot_key(window.label(), ty), s);
            }
        }
    }

    log::write_log(
        "info",
        &format!(
            "文件清理完成: 成功 {}（回收站 {}）失败 {} 释放 {}",
            success_n, recycled_n, failed, freed
        ),
    );

    json!({
        "success": true,
        "data": {
            "totalFreed": freed.to_string(),
            "success": success_n,
            "failed": failed,
            "recycled": recycled_n,
            "details": details
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_extensions() {
        assert_eq!(classify("jpg"), Some("image"));
        assert_eq!(classify("JPG"), None); // ext_of 已小写化，入参应为小写
        assert_eq!(classify("mp4"), Some("video"));
        assert_eq!(classify("tmp"), Some("cache"));
        assert_eq!(classify("dat"), Some("data"));
        // FC-3：数据库/密钥类绝不归入 data
        assert_eq!(classify("db"), None);
        assert_eq!(classify("adb"), None);
        assert_eq!(classify("aes"), None);
        assert_eq!(classify("exe"), None);
    }

    #[test]
    fn ext_lowercased() {
        assert_eq!(ext_of("PHOTO.JPG"), "jpg");
        assert_eq!(ext_of("noext"), "");
    }

    #[test]
    fn path_key_normalizes_sep_case_trailing() {
        assert_eq!(path_key("C:/A/B/"), "c:\\a\\b");
        assert_eq!(path_key("c:\\A\\b"), "c:\\a\\b");
    }
}
