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

/// README 承诺的最低版本：**Windows 11 22H2**（build 22621）。
///
/// 审查 v2-C-002：这句此前只是 README 的环境承诺、代码里没有任何断言，静态无法证伪。
/// 现在把它落成常量 + `meets_minimum`，启动日志里如实记录实测 build 与判定结果 ——
/// 「22H2 及以上」从一句宣传语变成一条可复核的运行时事实。
pub const MIN_SUPPORTED_BUILD: u32 = 22621;

/// 实测 build 是否达到 README 承诺的最低版本。
///
/// `RtlGetVersion` 拿不到（返回 0）时按**不满足**处理：对不支持的环境宁可多提示一句，
/// 也不在版本未知时装作支持。
pub fn meets_minimum(build: u32) -> bool {
    build >= MIN_SUPPORTED_BUILD
}

/// 当前系统是否达到最低支持版本（`windows_build()` 失败即 false，理由见上）
pub fn supported() -> bool {
    meets_minimum(windows_build())
}

/// 当前进程是否以管理员身份运行
pub fn is_admin() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 22H2 = 22621。边界两侧都要钉住，别让人把 `>` 与 `>=` 混淆。
    #[test]
    fn minimum_build_boundary() {
        assert!(!meets_minimum(0), "RtlGetVersion 失败（0）必须判不支持");
        assert!(!meets_minimum(21999), "21H2 (22000) 之前的 build 不支持");
        assert!(!meets_minimum(22000), "21H2 是 partial，不满足 22H2 承诺");
        assert!(!meets_minimum(22620));
        assert!(meets_minimum(22621), "22H2 正是承诺的下限");
        assert!(meets_minimum(22631), "23H2");
        assert!(meets_minimum(26100), "24H2");
        assert!(meets_minimum(u32::MAX), "更高版本一律支持");
    }

    #[test]
    fn min_constant_matches_readme_claim() {
        // README 写的是 22H2；若有人改这个常量，必须同步改 README ——
        // 这条断言让「改数字不改文档」在编译期之外的测试层先红一次。
        assert_eq!(MIN_SUPPORTED_BUILD, 22621);
    }
}