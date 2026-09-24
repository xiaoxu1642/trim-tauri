//! Windows 版本与权限判定（对照 main.js 787-802 / 386-400 段）
//!
//! `RtlGetVersion` 取真实内部版本号：manifest 无关，比 GetVersion/GetVersionEx
//! 的兼容性谎言可靠（后者在未声明支持 Win10 的进程里会谎报 6.2）。
//! 权限判定用 `IsUserAnAdmin`（等价 Electron 版 `net session` 探测的结论，
//! 但无外部进程、无网络依赖）。

use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows::Wdk::System::SystemServices::RtlGetVersion;

/// Windows 内部版本号（如 26200）
pub fn windows_build() -> u32 {
    unsafe {
        let mut info = OSVERSIONINFOW::default();
        info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
        if RtlGetVersion(&mut info).is_ok() {
            info.dwBuildNumber
        } else {
            0
        }
    }
}

/// Windows 版本字符串（对齐 Node `os.release()` 的 "10.0.<build>" 形态）
pub fn os_version() -> String {
    format!("10.0.{}", windows_build())
}

/// Fluent（DWM 材质）支持级别：
/// full>=22621（Mica+Acrylic+DWM 圆角）/ partial>=22000（基础 Mica）/ none（Win10）
pub fn fluent_support_level() -> &'static str {
    let build = windows_build();
    if build >= 22621 {
        "full"
    } else if build >= 22000 {
        "partial"
    } else {
        "none"
    }
}

/// 当前进程是否以管理员身份运行
pub fn is_admin() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}