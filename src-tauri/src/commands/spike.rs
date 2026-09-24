//! Phase 0 遗留的 CDP 探针命令（非 preload 契约面）
//!
//! 仅用于真机调试期的链路验证；Phase 1 收尾时删除，不进 CHANNEL_MAP。
//! 渲染层入口挂 `window.__trimSpike`（见 src/scripts/tauri-api.js）。

use tauri::{AppHandle, Emitter, WebviewWindow};

use crate::engine::sysinfo;

/// 事件链路往返：渲染层 listen('spike:pong') 后 invoke('spike_ping')
#[tauri::command]
pub fn spike_ping<R: tauri::Runtime>(app: AppHandle<R>) -> bool {
    app.emit(
        "spike:pong",
        serde_json::json!({ "ok": true, "source": "rust", "build": sysinfo::windows_build() }),
    )
    .is_ok()
}

/// 材质切换实测入口（不写盘、不广播，仅改当前窗口原生材质）
#[tauri::command]
pub fn spike_apply_material<R: tauri::Runtime>(window: WebviewWindow<R>, material: String) -> String {
    crate::apply_material(&window, &material)
}