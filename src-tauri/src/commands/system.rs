//! system 域（批次 A）：system:disk-type —— 系统盘介质类型（SSD/HDD）探测
//!
//! 供「电脑优化中心」与「磁盘清理」按硬件显隐预读相关选项：判定失败一律返回
//! success:false，渲染层按 unknown 处理（两边都不隐藏）——绝不让探测失败
//! 反而藏掉用户要用的选项。系统盘介质不会变化，进程内缓存一次即可。
//! S3：已删除 PS 回退，纯 Rust 原生实现。

use tauri::WebviewWindow;

use crate::engine::guard;

use crate::commands::state::SYSTEM_DISK_CACHE;

#[tauri::command]
pub async fn system_disk_type<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    refresh: Option<bool>,
) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let refresh = refresh.unwrap_or(false);
    if !refresh {
        if let Some(cached) = SYSTEM_DISK_CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Ok(serde_json::json!({ "success": true, "data": cached, "cached": true }));
        }
    }
    let result = tauri::async_runtime::spawn_blocking(|| {
        match crate::engine::native::sysdisk() {
            Ok(data) => Ok(data),
            Err(e) => Err(format!("原生探测失败: {e}")),
        }
    })
    .await;

    match result {
        Ok(Ok(data)) => {
            *SYSTEM_DISK_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some(data.clone());
            Ok(serde_json::json!({ "success": true, "data": data, "cached": false }))
        }
        Ok(Err(message)) => Ok(serde_json::json!({ "success": false, "message": message })),
        Err(e) => Ok(serde_json::json!({ "success": false, "message": format!("探测任务异常: {e}") })),
    }
}

/// system:disk-list — 枚举本机**固定磁盘**盘符（finder 大文件/空文件页的盘符点选器用，
/// 2026-09-28 六轮拍板：扫描目录从文本输入改为 C/D 盘点选）。
/// GetLogicalDriveStringsW + GetDriveTypeW，只放行 DRIVE_FIXED（可移动/网络盘
/// 拔插会让扫描中途失效，不进候选）。
#[tauri::command]
pub fn system_disk_list<R: tauri::Runtime>(
    window: WebviewWindow<R>,
) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDriveStringsW};
    // DRIVE_FIXED = 3（winnt.h 宏；windows 0.61 把它收在 WindowsProgramming 小模块，
    // 为不引入 Win32_System_WindowsProgramming feature 就地按 SDK 原值声明）
    const DRIVE_FIXED: u32 = 3;
    let mut buf = [0u16; 512];
    let len = unsafe { GetLogicalDriveStringsW(Some(&mut buf)) } as usize;
    if len == 0 || len > buf.len() {
        return Ok(serde_json::json!({ "success": false, "message": "枚举盘符失败", "data": [] }));
    }
    let mut drives: Vec<String> = Vec::new();
    // 缓冲区形态：`C:\<0>D:\<0>...<0>`（双 NUL 结尾的逐段串）
    let mut seg = &buf[..len];
    while let Some(pos) = seg.iter().position(|&c| c == 0) {
        let s = String::from_utf16_lossy(&seg[..pos]);
        seg = &seg[pos + 1..];
        if s.is_empty() {
            break;
        }
        let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
        let fixed = unsafe { GetDriveTypeW(windows::core::PCWSTR(wide.as_ptr())) } == DRIVE_FIXED;
        if !fixed {
            continue;
        }
        // "C:\" → "C:"（UI 点选标签）
        let letter = s.trim_end_matches('\\').to_uppercase();
        if !letter.is_empty() {
            drives.push(letter);
        }
    }
    drives.sort();
    Ok(serde_json::json!({ "success": true, "data": drives }))
}
