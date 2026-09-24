// 发布构建隐藏控制台窗口；调试构建保留，方便 Phase 0 CDP 观察日志
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    trim_tauri_lib::run()
}
