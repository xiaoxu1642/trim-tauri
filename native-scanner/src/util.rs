//! 跨模块共用助手（原散在 main.rs，lib 化时上移以被 perf / cleanup_scan 共用）
//!
//! 搬迁原则：**代码逐字搬运**，仅把可见性从 `pub(crate)`/私有提升为 `pub`，
//! 且保持 CLI 输出与判定语义完全不变（回归基线见 tools/ 与本方案附录 D）。

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Rust str → null 结尾宽字符串（本 crate 唯一实现；原 perf 与 cleanup_scan 里的三份本地
/// 副本已随 v3 C-1 删除。native-scanner 是独立 crate，与 src-tauri 侧各留一份，刻意不跨 crate 共享）。
pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ==================== Win32 FFI 声明集中区（v3 C-3） ====================
// 本 crate 手写的 `extern "system"` 声明与配套结构体集中在此、按 DLL 分组；
// perf / scan::recycle / cleanup_scan 只 `use crate::util::ffi::…`，不再自建 extern 块
//（历史上 RegOpenKeyExW / RegCloseKey 等曾被分散声明多份）。
//
// 纪律（沿用各处原注）：
// - 不为此新开 windows-sys feature（零新增依赖面）；**签名与结构体布局逐字保持**。
// - L6（2026-09-19）：Win32 结构体字段名与 SDK 原名逐字一致 —— 重命名既不改变内存布局，
//   也破坏 #[repr(C)] 的可读性契约；故整体豁免 non_snake_case，改动字段名属高危改动。
// - 本模块不加 cfg：extern 声明跨目标可编译；调用点原有的 #[cfg(windows)] 维持原样。
#[allow(non_snake_case)]
pub(crate) mod ffi {
    #[repr(C)]
    pub struct PROCESSENTRY32W {
        pub dwSize: u32,
        pub cntUsage: u32,
        pub th32ProcessID: u32,
        pub th32DefaultHeapID: usize,
        pub th32ModuleID: u32,
        pub cntThreads: u32,
        pub th32ParentProcessID: u32,
        pub pcPriClassBase: i32, // Win32 LONG（32 位）——误用 isize 会使 dwSize 多 4 字节，Process32FirstW 报 BAD_LENGTH
        pub dwFlags: u32,
        pub szExeFile: [u16; 260],
    }

    #[repr(C)]
    pub struct ShFileOpStructW {
        pub hwnd: isize,
        pub w_func: u32,
        pub p_from: *const u16,
        pub p_to: *const u16,
        pub f_flags: u16,
        pub f_any_operations_aborted: i32,
        pub h_name_mappings: *mut core::ffi::c_void,
        pub lpsz_progress_title: *const u16,
    }

    /// FILETIME 本体是 { DWORD low, DWORD high }，4 字节对齐、共 8 字节——
    /// 用 u64 会引入 8 字节对齐 pad，使 strAppName 错位 4 字节（实测应用名丢首 2 字符）。
    #[repr(C)]
    pub struct RM_UNIQUE_PROCESS {
        pub dwProcessId: u32,
        pub ProcessStartTimeLow: u32,
        pub ProcessStartTimeHigh: u32,
    }

    // 2026-09-30 实测：Windows 按 **668 字节**步长写这条记录，SDK 头文件那六个成员只推出 664。
    // 少这 4 字节的后果不是「显示难看」而是三件实事：① 第 i 条记录整体前移 4×i 字节，
    // 应用名前多出 2i 个乱码字符（用户看到的「偁aWindows 资源管理器」）；② `pid` 与
    // `ApplicationType` 跟着错位 ⇒ 结束进程拿的是错 PID、critical 判错；③ 按 664 申请的
    // 缓冲区被按 668 写满 ⇒ 越界写（72 条时越界 288 字节）。
    // 字段位置同样实测钉住：strAppName@12、strServiceShortName@524（服务短名干净）、
    // ApplicationType@652（lsass 读出 1000=RmCritical）、bRestartable@660。
    // 这个尾巴 DWORD 是什么微软没写进头文件，本模块不消费它，只负责让步长对齐。
    #[repr(C)]
    pub struct RM_PROCESS_INFO {
        pub Process: RM_UNIQUE_PROCESS,
        pub strAppName: [u16; 255 + 1],         // CCH_RM_MAX_APP_NAME + 1
        pub strServiceShortName: [u16; 63 + 1], // CCH_RM_MAX_SERVICE_NAME_SHORT + 1
        pub ApplicationType: u32,
        pub TSSessionId: u32,
        pub bRestartable: i32,
        pub _reserved: u32,
    }

    impl Clone for RM_PROCESS_INFO {
        fn clone(&self) -> Self {
            unsafe { std::ptr::read(self) } // POD 结构体逐位复制（含数组字段，无堆所有权）
        }
    }

    // 布局不变式放编译期而不是 #[test]：native-scanner 是 path 依赖、非 workspace 成员，
    // 它的单测只有显式 --manifest-path 才跑，靠测试兜不住「有人改回六个成员」这种回归。
    const _: () = {
        if std::mem::size_of::<RM_PROCESS_INFO>() != 668 {
            panic!("RM_PROCESS_INFO 步长必须 668 字节：Windows 就按这个宽度写，错了会错位读名/pid 并越界写");
        }
        if std::mem::offset_of!(RM_PROCESS_INFO, strAppName) != 12 {
            panic!("strAppName 偏移必须是 12：RM_UNIQUE_PROCESS 是 DWORD+FILETIME 共 12 字节而非 16");
        }
        if std::mem::offset_of!(RM_PROCESS_INFO, ApplicationType) != 652 {
            panic!("ApplicationType 偏移必须是 652：critical 判定（==1000 RmCritical）按它读");
        }
    };

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetLongPathNameW(lpszShortPath: *const u16, lpszLongPath: *mut u16, cchBuffer: u32) -> u32;
        pub fn QueryPerformanceCounter(lpPerformanceCount: *mut i64) -> i32;
        pub fn QueryPerformanceFrequency(lpFrequency: *mut i64) -> i32;
        pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> isize;
        pub fn Process32FirstW(hSnapshot: isize, lppe: *mut PROCESSENTRY32W) -> i32;
        pub fn Process32NextW(hSnapshot: isize, lppe: *mut PROCESSENTRY32W) -> i32;
        pub fn CloseHandle(hObject: isize) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        pub fn NtQuerySystemInformation(class: u32, info: *mut u8, len: u32, return_len: *mut u32) -> i32;
        pub fn NtSetSystemInformation(class: u32, info: *mut u8, len: u32) -> i32;
        pub fn RtlGetVersion(info: *mut u8) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn RegOpenKeyExW(hKey: isize, lpSubKey: *const u16, ulOptions: u32, samDesired: u32, phkResult: *mut isize) -> i32;
        pub fn RegQueryValueExW(key: isize, name: *const u16, res: *mut u32, typ: *mut u32, data: *mut u8, len: *mut u32) -> i32;
        pub fn RegQueryInfoKeyW(
            hKey: isize, lpClass: *mut u16, lpcchClass: *mut u32, lpReserved: *mut u32,
            lpcSubKeys: *mut u32, lpcchMaxSubKeyLen: *mut u32, lpcchMaxClassLen: *mut u32,
            lpcValues: *mut u32, lpcchMaxValueNameLen: *mut u32, lpcbMaxValueLen: *mut u32,
            lpcbSecurityDescriptor: *mut u32, lpftLastWriteTime: *mut u64,
        ) -> i32;
        pub fn RegCloseKey(hKey: isize) -> i32;
    }

    #[link(name = "shell32")]
    extern "system" {
        pub fn SHFileOperationW(lpfileop: *mut ShFileOpStructW) -> i32;
    }

    #[link(name = "rstrtmgr")]
    extern "system" {
        pub fn RmStartSession(pSessionHandle: *mut u32, dwSessionFlags: u32, strSessionKey: *mut u16) -> i32;
        pub fn RmRegisterResources(
            dwSessionHandle: u32, nFiles: u32, rgsFileNames: *const *const u16,
            nApplications: u32, rgApplications: *const RM_PROCESS_INFO,
            nServices: u32, rgsServiceNames: *const *const u16,
        ) -> i32;
        pub fn RmGetList(
            dwSessionHandle: u32, pnProcInfoNeeded: *mut u32, pnProcInfo: *mut u32,
            rgAffectedApps: *mut RM_PROCESS_INFO, lpdwRebootReasons: *mut u32,
        ) -> i32;
        pub fn RmEndSession(dwSessionHandle: u32) -> i32;
    }
}

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
    let wide: Vec<u16> = OsStr::new(p).encode_wide().chain(std::iter::once(0)).collect();
    let mut buf: Vec<u16> = vec![0u16; wide.len().max(1024)];
    loop {
        let n = unsafe { ffi::GetLongPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
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