//! 跨模块共用助手（原散在 main.rs，lib 化时上移以被 perf / cleanup_scan 共用）
//!
//! 搬迁原则：**代码逐字搬运**，仅把可见性从 `pub(crate)`/私有提升为 `pub`，
//! 且保持 CLI 输出与判定语义完全不变（回归基线见 tools/ 与本方案附录 D）。

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

/// 宿主注入的数据根：`(当前数据根, 升级前的老数据根)`。
///
/// 为什么不在这里自己拼 `%APPDATA%\<产品名>`（N2，2026-09-29）：
/// - 便携模式下那是**宿主机**的漫游目录，标准实例与便携实例会共写同一份排除/忽略名单，
///   便携版"状态全留在 exe 同级 `data/`"的承诺当场不成立；
/// - 主 crate 有 `paths::app_data_dir()` 这个唯一真源，扫描器再拼一遍就是第二个口径，
///   而两边一旦分叉，用户看到的现象是"我明明排除了它，下次还是被列出来"。
///
/// 没注入时名单按**空**处理（而不是猜一个路径）：猜出来的路径会把删除面缩小或放大，
/// 两种都错。注入点在 `src-tauri/src/engine/paths.rs` 的 `app_data_dir()` 初始化里，
/// 由 `tools/check-fail-closed.mjs` 的 D 段钉住（把注入调用摘掉就判红）。
static DATA_ROOTS: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();

pub fn set_data_roots(current: PathBuf, legacy: PathBuf) {
    let _ = DATA_ROOTS.set((current, legacy));
}

pub fn data_roots() -> Option<(PathBuf, PathBuf)> {
    DATA_ROOTS.get().cloned()
}

/// 名单类文件（每行一条路径的 txt）的落点：
/// 当前根已有 ⇒ 当前根；只有老根有 ⇒ 老根（兜底读，保证升级后旧名单继续生效）；
/// 两处都没有 ⇒ 当前根（写入落点）。
///
/// 刻意**只选一个文件**而不是把两份并起来读：并集会让"删除一条排除项"永远删不干净
/// （老根那行还在，下次扫描又生效）。真正的合并由主 crate 在启动时一次性搬文件完成。
pub fn list_file_path(name: &str) -> Option<PathBuf> {
    let (current, legacy) = DATA_ROOTS.get()?;
    let cur = current.join(name);
    if cur.is_file() {
        return Some(cur);
    }
    let old = legacy.join(name);
    if old.is_file() {
        return Some(old);
    }
    Some(cur)
}

/// CLI 独立调试入口专用的数据根（Electron 轨 `%APPDATA%\<产品名>`）。
///
/// 全仓**唯一**允许在扫描器里拼这个老根的地方就是本函数 —— `tools/check-fail-closed.mjs`
/// C 段把 `native-scanner/src/util.rs` 钉成 ROOT_OWNER 之一，别处再拼就判红。
/// 之所以要留着：CLI 没有宿主注入，而它的名单行为必须与迁移前逐字一致（crate 的搬迁原则）。
pub fn legacy_cli_root() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(|a| PathBuf::from(a).join("Trim"))
}

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
///
/// 审查 v2-M5：`to_string_lossy` 是**有损**的（孤立代理项 → U+FFFD），所以这个字符串
/// 只能用于展示与匹配键，不能反过来当删除目标 —— 需要保真时用 `has_lossy_path` 判一眼，
/// 并把原生 `Path`/`OsString` 交给删除侧（`Sink::item` 因此带上了原始路径）。
pub fn unix_path(p: &std::path::Path) -> String {
    let mut s = p.to_string_lossy().to_string();
    if s.starts_with(r"\\?\") {
        s = s[4..].to_string();
    }
    s.replace('\\', "/")
}

/// 该路径的文本形态是否已经丢了信息（`to_string_lossy` 拿 U+FFFD 顶掉了非良构序列）。
/// Windows 上 OsString 内部是 UTF-16/WTF-8，`to_str()` 返回 None 即「含孤立代理项」，
/// 这正是 GBK 遗留介质与字节级拷贝名字的形态：此时 lossy 串既可能删不到目标、
/// 也可能撞上另一个恰好含 U+FFFD 的真实文件。
pub fn has_lossy_path(p: &std::path::Path) -> bool {
    p.as_os_str().to_str().is_none()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// 审查 v2-M5：lossy 判据必须是「文本形态丢了信息」，而不是「看起来有怪字符」。
    /// 孤立代理项（GBK 遗留介质/字节级拷贝的名字）→ `to_str()` None；
    /// 而合法的多字节 Unicode 名字（中文、emoji）→ 无损，不能被误判成要特殊处理的目标。
    #[test]
    fn has_lossy_path_flags_unpaired_surrogates_only() {
        assert!(!has_lossy_path(Path::new("C:\\Users\\me\\报告 🎯.txt")));
    }

    #[cfg(windows)]
    #[test]
    fn has_lossy_path_detects_unpaired_surrogate() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        // 0xD800 是前导代理项却没有后继 —— 真实磁盘上就长这样（字节级拷来的 GBK 名字）
        let weird = Path::new(&OsString::from_wide(&[0x43, 0x3A, 0x5C, 0xD800, 0x61])).to_path_buf();
        assert!(has_lossy_path(&weird), "孤立代理项必须判为 lossy");
        // 配对代理项（emoji）是合法 UTF-16，不得误判
        let ok = Path::new(&OsString::from_wide(&[0x43, 0x3A, 0x5C, 0xD83C, 0xDFAF])).to_path_buf();
        assert!(!has_lossy_path(&ok), "配对代理项是无损的");
    }

    /// `unix_path` 是展示口径：剥 `\\?\`、分隔符统一，且对 lossy 输入必须仍产出可解析文本
    #[test]
    fn unix_path_strips_prefix_and_normalizes_sep() {
        assert_eq!(unix_path(Path::new(r"\\?\C:\a\b")), "C:/a/b");
        assert_eq!(unix_path(Path::new(r"C:\x\y.txt")), "C:/x/y.txt");
    }

    /// 行协议的前提：控制字符必须被转义，否则一条名字里带制表符的路径就能伪造 `@@ITEM@@` 行
    #[test]
    fn json_escape_covers_control_chars() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("x\ny\rz\tw"), "x\\ny\\rz\\tw");
        assert_eq!(json_escape("\u{1}"), "\\u0001");
    }
}

#[cfg(test)]
mod data_roots_tests {
    use super::*;

    /// 名单落点的三种情形必须在**同一个用例**里跑完：根对是进程级 `OnceLock`，
    /// 只能设置一次，拆成多个 test 会让第二个用例读到第一个的根。
    #[test]
    fn 名单落点当前根优先老根兜底两处都无则指当前根() {
        let root = std::env::temp_dir().join(format!(
            "trim-roots-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let cur = root.join("cur");
        let old = root.join("old");
        std::fs::create_dir_all(&cur).unwrap();
        std::fs::create_dir_all(&old).unwrap();
        set_data_roots(cur.clone(), old.clone());

        // ① 两处都没有 ⇒ 返回当前根（写入落点，绝不返回老根，否则便携实例写宿主机）
        assert_eq!(
            list_file_path("cleanup-exclude.txt").as_deref(),
            Some(cur.join("cleanup-exclude.txt").as_path()),
            "无名单时写入落点必须是当前根"
        );
        // ② 只有老根有 ⇒ 兜底读老根（升级用户的既有排除项不能突然失效）
        std::fs::write(old.join("empty-ignore.txt"), b"x\r\n").unwrap();
        assert_eq!(
            list_file_path("empty-ignore.txt").as_deref(),
            Some(old.join("empty-ignore.txt").as_path())
        );
        // ③ 当前根也有了 ⇒ 立刻改口当前根（主 crate 启动搬完就是这个状态；
        //    继续读老根会造成"删掉一条排除项、下轮又生效"的两份真相）
        std::fs::write(cur.join("empty-ignore.txt"), b"x\r\ny\r\n").unwrap();
        assert_eq!(
            list_file_path("empty-ignore.txt").as_deref(),
            Some(cur.join("empty-ignore.txt").as_path())
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}