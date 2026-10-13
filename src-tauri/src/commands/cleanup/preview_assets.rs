//! 清理域图片预览的 asset 放行（preview 子窗退役后的承接件）
//!
//! 背景：图片预览从「独立子窗 + base64 dataURL」改为「主窗内 LiteBox 灯箱 + asset
//! 协议磁盘直连」。asset 协议的静态 scope（tauri.conf.json）只放行 backgrounds/fonts，
//! 而图片缓存目录是用户配置的动态路径，静态写死等于把任意用户目录常开给前端。
//!
//! 所以口径是**运行时按需放行**：用户点开某组预览时，只把这一组图片路径逐个
//! `allow_file` 进 asset scope —— 暴露面从「整个扫描目录常开」收紧到「你点开看的
//! 那几张图」。本次没点开的文件，前端拿不到 asset URL 的读取授权。

use serde_json::{json, Value};
use tauri::{AppHandle, Manager, Runtime, WebviewWindow};

use crate::engine::guard;

/// 单次放行条数上限：预览列表本身有量级控制，这里只挡「把整个扫描结果灌进来」的滥用。
const MAX_PATHS: usize = 500;

/// cleanup:allow-preview-assets — 把本次预览的图片路径逐个放行进 asset 协议 scope
///
/// 主窗专属（`MAIN`）：预览入口只在主窗，子窗没有理由申请文件读取授权。
#[tauri::command]
pub async fn cleanup_allow_preview_assets<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    paths: Option<Value>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let Some(arr) = paths.as_ref().and_then(|v| v.as_array()) else {
        return json!({ "success": false, "message": "缺少路径清单" });
    };
    if arr.len() > MAX_PATHS {
        return json!({ "success": false, "message": format!("路径清单超过上限 {MAX_PATHS}") });
    }
    let scope = app.asset_protocol_scope();
    let mut allowed = 0usize;
    let mut skipped = 0usize;
    for v in arr {
        let Some(p) = v.as_str() else { skipped += 1; continue };
        if p.is_empty() || p.len() > 260 || p.contains('\0') {
            skipped += 1;
            continue;
        }
        match scope.allow_file(std::path::Path::new(p)) {
            Ok(()) => allowed += 1,
            Err(_) => skipped += 1,
        }
    }
    json!({ "success": true, "allowed": allowed, "skipped": skipped })
}
