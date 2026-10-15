//! native 跨域助手（v3 D1）
//!
//! 只放**多模块共享**的东西：宽字符串编解码、环境变量展开、注册表路径解析、
//! 文件名片名化、备份目录枚举。单域 helper 留在所属文件，不为「看着像工具」搬进来。
//! 可见性用 `pub(super)`：对外仍由 `native/mod.rs` 的 `pub use` 决定，模块树内自由调用。


use std::ffi::OsStr;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use std::os::windows::ffi::OsStrExt;
/// C 字符串解码的硬上限（元素数）。Win32 结构体未初始化/无 NUL 终止符时，原实现
/// 的 `take_while` 会一直读到相邻内存的越界位置 —— UB/崩溃。加上限后最坏只是截断，
/// 不再越界。32768 个 u16 = 64 KiB，远大于任何真实路径/键名/设备名（Win32 上限 32K）。
const MAX_C_STR_UNITS: isize = 32_768;

/// 从 `*const u16` 以 null 结尾宽字符串构造 String（null 指针返回空串）
/// 从 `*const u16` 以 null 结尾宽字符串构造 String（NUL 截断真源，v4 审查统一入口）。
/// 定长 UTF-16 数组（如 `PROCESSENTRY32W.szExeFile: [u16; 260]`）也走这里传 `.as_ptr()`——
/// 整体 `from_utf16_lossy(&array)` 会把尾部填充的 NUL 带进字符串，比较判据必然不命中。
pub unsafe fn wide_str(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let len = (0isize..MAX_C_STR_UNITS).take_while(|&i| *ptr.offset(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// 从 `*const u8` 以 null 结尾 ANSI 字符串构造 String
pub(super) unsafe fn pstr_to_string(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let len = (0isize..MAX_C_STR_UNITS).take_while(|&i| *ptr.offset(i) != 0).count();
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).to_string()
}

/// Rust str → null 结尾宽字符串（全仓唯一实现：v3 C-1 把 `wide_str_from_str`、
/// `uninstall::helpers::to_wide`、原 `contextmenu::to_wide16` 与 elevate/aidesc 的
/// 内联 `wide` 全部收敛到此；禁止再写第二份）
pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// 展开环境变量（%VAR%）——委托给原生扫描器的唯一实现
/// `trim_finder::cleanup_scan::expand_env_path`（P0 统一，规则库最终优化方案 2026-09-27）。
///
/// 为什么不再自己展开：旧白名单版按**字面大小写**做字符串替换，规则库里的
/// `%WINDIR%`（大写）匹配不上白名单的 `"windir"` → 执行侧永远展不开，
/// `expand_glob_dirs` 拿字面量路径去 read_dir → 0 文件、状态 ok，正是
/// 「扫描命中、执行 0 删」的根因（printSpoolCache 实锤）。扫描侧用
/// `env::var_os`，Windows 语义下大小写不敏感，从未出过这个问题。
pub(super) fn expand_env(s: &str) -> String {
    trim_finder::cleanup_scan::expand_env_path(s)
}

/// P0 fail-closed 判据：展开结果里残留 %TOKEN% 即路径无效。
/// 统一走扫描器实现，避免执行侧再造一份残留检测（与 expand_env 同理）。
pub(super) fn first_unexpanded_token(s: &str) -> Option<String> {
    trim_finder::cleanup_scan::first_unexpanded_token(s)
}

/// 解析注册表路径为 (hive, subkey)
pub(super) fn parse_reg_path(reg_path: &str) -> Option<(HKEY, String)> {
    let rp = reg_path.trim();
    if rp.starts_with("HKEY_CURRENT_USER") || rp.starts_with("HKCU") {
        let rest = rp.splitn(2, '\\').nth(1).unwrap_or("");
        Some((HKEY_CURRENT_USER, rest.to_string()))
    } else if rp.starts_with("HKEY_LOCAL_MACHINE") || rp.starts_with("HKLM") {
        let rest = rp.splitn(2, '\\').nth(1).unwrap_or("");
        Some((HKEY_LOCAL_MACHINE, rest.to_string()))
    } else {
        None
    }
}

pub(super) fn safe_name(name: &str) -> String {
    name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

/// 跨候选根收集外设备份分片（`backup_<stamp>_*.reg`），按修改时间倒序。
///
/// 单独成函数只为让「新老两根都要收、且一起排时间」这条能被单测钉住：真正的还原要跑
/// `reg.exe import`，快速组碰不得。只认一根会出现「老根有三月那批、新根有今天那批，
/// 还原挑错一批」的错账（v2-M19 收口后两根都可能有条目）。
pub(super) fn collect_peripheral_backup_files(dirs: &[std::path::PathBuf]) -> Vec<std::path::PathBuf> {
    let mut files: Vec<std::path::PathBuf> = dirs
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("backup_") && n.ends_with(".reg"))
                    .unwrap_or(false)
        })
        .collect();
    files.sort_by(|a, b| {
        let ta = a.metadata().and_then(|m| m.modified()).ok();
        let tb = b.metadata().and_then(|m| m.modified()).ok();
        tb.cmp(&ta)
    });
    files
}

/// 删除失败原因分档（R4，2026-10-15）——把 io::Error 折成四档，供清理执行链与网速报告
/// 清空链共用（§5.16/N6：判据只此一份，调用点各写一遍 match 就是第二份实现）。
///
/// 分码口径与 `pending_delete.rs::classify_pending_delete_error` 同源（那边的注释写明
/// 「ACCESS_DENIED 与 SHARING_VIOLATION 必须分开说：前者提权重试有意义，后者提权没用」）。
/// 注意**不能只看 `ErrorKind`**：Windows 上 SHARING_VIOLATION(32) 与 ACCESS_DENIED(5)
/// 都被 std 折成 `PermissionDenied`，只按 kind 判会把两者混回去——必须读 raw code。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeleteFailureKind {
    /// ERROR_ACCESS_DENIED(5)：权限不足（提权重试可能有效）
    Denied,
    /// ERROR_SHARING_VIOLATION(32)/ERROR_LOCK_VIOLATION(33)：被占用（关程序后重试）
    Busy,
    /// ERROR_FILE_NOT_FOUND(2)/ERROR_PATH_NOT_FOUND(3)：删除时已消失（无需重试）
    Gone,
    /// 其余：不猜（计数进「失败」总账）
    Other,
}

pub(crate) fn classify_delete_error(e: &std::io::Error) -> DeleteFailureKind {
    match e.raw_os_error() {
        Some(5) => DeleteFailureKind::Denied,
        Some(32) | Some(33) => DeleteFailureKind::Busy,
        Some(2) | Some(3) => DeleteFailureKind::Gone,
        // Windows 文件操作错误恒带 raw code，这里只是拿不到 code 时的近似：
        // 宁可把权限/不存在分开，也别再混回「被占用」。
        _ => match e.kind() {
            std::io::ErrorKind::PermissionDenied => DeleteFailureKind::Denied,
            std::io::ErrorKind::NotFound => DeleteFailureKind::Gone,
            _ => DeleteFailureKind::Other,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v4/P2-2（R5-M01 根因形态）：定长 UTF-16 数组必须按 NUL 截断 —— 整体
    /// `from_utf16_lossy(&[u16; 260])` 会把尾部填充的 NUL 一起带进字符串，与
    /// "explorer.exe" 的等值比较恒不命中（重启资源管理器 100% 失效还谎报「没有运行中的」）。
    #[test]
    fn wide_str_truncates_fixed_array_at_nul() {
        let mut buf = [0u16; 260];
        for (i, c) in "explorer.exe".encode_utf16().enumerate() {
            buf[i] = c;
        }
        assert_eq!(unsafe { wide_str(buf.as_ptr()) }, "explorer.exe");
        // 反向对照：旧写法确实带 NUL（本用例为它而立；若旧写法也相等，对照就失效了）
        let old = String::from_utf16_lossy(&buf);
        assert_ne!(old, "explorer.exe", "旧写法若也相等，本用例失去对照意义");
        assert!(old.starts_with("explorer.exe\u{0}"));
    }

    /// R4（2026-10-15）：删除失败分档把「权限 / 占用 / 已消失」分开 —— 关键是 5 与 32
    /// 必须分开（提权对前者有用、对后者没用）；而 std 把两者的 kind 都折成 PermissionDenied，
    /// 所以先钉「只看 kind 判不出差异」这个前提，再钉 raw code 分档。
    #[test]
    fn delete_error_classification_splits_denied_from_busy() {
        use super::DeleteFailureKind::*;
        let w = |code: i32| classify_delete_error(&std::io::Error::from_raw_os_error(code));
        // 前提（采集）：32 与 5 的 kind 相同 —— 只看 kind 的实现必然把两者混回去
        assert_eq!(
            std::io::Error::from_raw_os_error(32).kind(),
            std::io::Error::from_raw_os_error(5).kind(),
            "前提变了：32 的 kind 不再等于 5，本判据的存在理由需要复核"
        );
        // 判定：四个码各归各档
        assert_eq!(w(5), Denied, "ACCESS_DENIED 是权限不足");
        assert_eq!(w(32), Busy, "SHARING_VIOLATION 是占用（不是权限）");
        assert_eq!(w(33), Busy, "LOCK_VIOLATION 与共享冲突同族");
        assert_eq!(w(2), Gone, "FILE_NOT_FOUND：删除时已消失");
        assert_eq!(w(3), Gone, "PATH_NOT_FOUND：删除时已消失");
        assert_eq!(w(145), Other, "未映射码不猜");
        // 兜底近似（raw code 拿不到时；Windows 上实际不可达）
        assert_eq!(classify_delete_error(&std::io::Error::new(std::io::ErrorKind::PermissionDenied, "x")), Denied);
        assert_eq!(classify_delete_error(&std::io::Error::new(std::io::ErrorKind::NotFound, "x")), Gone);
        assert_eq!(classify_delete_error(&std::io::Error::new(std::io::ErrorKind::TimedOut, "x")), Other);
    }
}
