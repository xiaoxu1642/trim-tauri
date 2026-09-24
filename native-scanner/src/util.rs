//! 跨模块共用助手（原散在 main.rs，lib 化时上移以被 perf / cleanup_scan 共用）
//!
//! 搬迁原则：**代码逐字搬运**，仅把可见性从 `pub(crate)`/私有提升为 `pub`，
//! 且保持 CLI 输出与判定语义完全不变（回归基线见 tools/ 与本方案附录 D）。

use std::fs;

/// JSON 字符串转义（手写，避免为单点需求引入 serde——与既有"零额外依赖"取向一致）
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// 路径统一为 `/` 分隔并剥掉 `\\?\` 长路径前缀（输出口径，跨平台一致）
pub fn unix_path(p: &std::path::Path) -> String {
    let mut s = p.to_string_lossy().to_string();
    if s.starts_with(r"\\?\") {
        s = s[4..].to_string();
    }
    s.replace('\\', "/")
}

/// 审查v4-M6：是否重解析点（junction/挂载点）。Windows 目录联接点不是 symlink
/// （file_type().is_symlink()==false），须按 FILE_ATTRIBUTE_REPARSE_POINT (0x400) 判定；
/// 否则自引用联接点（如「Application Data」历史环）会逐层加深重复遍历，扫描卡到超时。
#[cfg(windows)]
pub fn is_reparse(ent: &fs::DirEntry) -> bool {
    use std::os::windows::fs::MetadataExt;
    ent.metadata()
        .map(|m| (m.file_attributes() & 0x400) != 0)
        .unwrap_or(false)
}

#[cfg(not(windows))]
pub fn is_reparse(_ent: &fs::DirEntry) -> bool {
    false
}

/// v3.7.2 受保护路径误杀修复：8.3 短名展开为磁盘上的长名（GetLongPathNameW）。
/// 与 PS 侧 [IO.Path]::GetFullPath / JS 侧 fs.realpathSync.native 同语义：
/// 路径（或其已存在前缀）在磁盘上存在 → 返回长名；目标不存在（API 返回 0）→
/// 原样返回，由调用方保留「~数字 fail-closed」判定。
/// 注意 std::fs::canonicalize 会追加 \\?\ 前缀，与 P3 字符串口径冲突，不能直接用。
#[cfg(windows)]
pub fn to_long_path(p: &str) -> String {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    #[allow(non_snake_case)]
    extern "system" {
        fn GetLongPathNameW(lpszShortPath: *const u16, lpszLongPath: *mut u16, cchBuffer: u32) -> u32;
    }
    let wide: Vec<u16> = OsStr::new(p).encode_wide().chain(std::iter::once(0)).collect();
    let mut buf: Vec<u16> = vec![0u16; wide.len().max(1024)];
    loop {
        let n = unsafe { GetLongPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            return p.to_string(); // 不存在/无权限 → 原样返回（短名组件由 fail-closed 兜底）
        }
        if (n as usize) <= buf.len() {
            buf.truncate(n as usize);
            while buf.last() == Some(&0) {
                buf.pop();
            }
            return String::from_utf16_lossy(&buf);
        }
        buf.resize(n as usize, 0); // 缓冲不足，按返回长度重试
    }
}

#[cfg(not(windows))]
pub fn to_long_path(p: &str) -> String {
    p.to_string()
}