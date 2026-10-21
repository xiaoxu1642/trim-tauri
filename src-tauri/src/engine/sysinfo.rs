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
    version_parts().map(|(_, _, build)| build).unwrap_or(0)
}

/// `RtlGetVersion` 的三元组：`(major, minor, build)`；取不到返回 `None`。
///
/// 为什么要单独返回 `None` 而不是压成 0：0 与「真的读到了 0.0.0」在下游不可区分。
/// `meets_minimum`/`supported` 需要的是「不支持」这个结论，压 0 是对的；
/// 而**展示串**不能跟着压 0——把读不到的版本交成 `10.0.0` 就是让界面陈述一件
/// 没发生过的事实（R6b-L05，`osVersion` 会直接上屏）。
fn version_parts() -> Option<(u32, u32, u32)> {
    unsafe {
        let mut info = OSVERSIONINFOW::default();
        info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
        if RtlGetVersion(&mut info).is_ok() {
            Some((
                info.dwMajorVersion,
                info.dwMinorVersion,
                info.dwBuildNumber,
            ))
        } else {
            None
        }
    }
}

/// Windows 版本字符串（对齐 Node `os.release()` 的 "<major>.<minor>.<build>" 形态）
///
/// R6b-L05 两处收口：
/// 1. 此前硬编码 `10.0.{build}`，`dwMajorVersion`/`dwMinorVersion` 根本没读——
///    非 10.0 的机器（以及 RtlGetVersion 谎报形态）会被写成错的版本号；
/// 2. 此前读不到版本时交出 `10.0.0`，把「不知道」说成一个具体的号。
///    现在交「版本未知」，与同一面板里 `Build 未知` 的口径一致（渲染层
///    `app.js` 那行本就是 `${info.osBuild || '未知'}`）。
pub fn os_version() -> String {
    format_os_version(version_parts())
}

/// 展示串的组装（纯函数，便于判红断言把三种形态钉住）
fn format_os_version(parts: Option<(u32, u32, u32)>) -> String {
    match parts {
        Some((major, minor, build)) => format!("{major}.{minor}.{build}"),
        None => "版本未知".to_string(),
    }
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

    /// R6b-L05：展示串不得把「读不到」陈述成一个具体版本号，也不得硬编码 `10.0.` 前缀。
    /// 判红自证：把 `format_os_version` 改回 `format!("10.0.{}", build)` ⇒ 第二条红；
    /// 改回读不到时交 `10.0.0` ⇒ 第一条红。
    #[test]
    fn 版本展示串按真实三元组组装() {
        // 取不到版本：交「未知」，而且串里不得出现任何数字（数字=在陈述一个具体版本）
        let unknown = format_os_version(None);
        assert_eq!(unknown, "版本未知");
        assert!(
            !unknown.chars().any(|c| c.is_ascii_digit()),
            "未知形态里出现了数字，等于又在编造版本号: {unknown}"
        );
        // major/minor 是读出来的，不是写死的 10.0
        assert_eq!(format_os_version(Some((10, 0, 26100))), "10.0.26100");
        assert_eq!(format_os_version(Some((11, 0, 22621))), "11.0.22621");
        assert_eq!(format_os_version(Some((6, 3, 9600))), "6.3.9600");
        assert_ne!(
            format_os_version(Some((11, 0, 22621))),
            format!("10.0.{}", 22621),
            "又退回硬编码前缀了"
        );
        // 三段形态（对齐 Node os.release()）：两个点、三段数字
        let s = format_os_version(Some((10, 0, 1)));
        assert_eq!(s.split('.').count(), 3, "{s}");
    }

    /// 真机一致性探针（只读 FFI，无副作用）：`os_version()` 的第三段必须等于
    /// `windows_build()`，且本机版本已知时整串必须能被解析成三段数字。
    /// 这一条钉的是「组装函数与取号函数读的是同一次 `RtlGetVersion`」——
    /// 旧实现靠 `format!("10.0.{}", windows_build())` 天然一致，改成三元组后
    /// 一旦两侧各读各的、或某侧再压一次 0，这里就会红。
    /// 只跑档位：`cargo test --lib -- --ignored`（发布前门禁）。
    #[test]
    #[ignore = "真实调用 RtlGetVersion（只读），发布前门禁跑"]
    fn 展示串与实测版本三元组同源() {
        let build = windows_build();
        let s = os_version();
        assert!(build > 0, "本机 RtlGetVersion 读不到 build（0），下面的分段断言无从谈起");
        let parts: Vec<&str> = s.split('.').collect();
        assert_eq!(parts.len(), 3, "展示串必须是 major.minor.build 三段: {s}");
        assert_eq!(
            parts[2].parse::<u32>().ok(),
            Some(build),
            "展示串的 build 段必须等于 windows_build() 实测值: {s} vs {build}"
        );
        assert_ne!(s, "版本未知", "本机读得到版本却交出未知串");
        println!("实测三元组: {s}（major={} minor={} build={build}）", parts[0], parts[1]);
    }
}