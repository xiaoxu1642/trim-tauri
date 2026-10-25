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

    /// `OSVERSIONINFOW`（RtlGetVersion 的出参）。本 crate 过去用 `[0u8; 276]` + 手写
    /// 字节偏移读它（`rd(4)/rd(8)/rd(12)`），**没有任何编译期布局断言** —— 而同文件对
    /// `RM_PROCESS_INFO` 恰有 `const _` 断言（标准不一，N1b-L01）。改成有名字的结构体，
    /// 尺寸与偏移由编译期钉住，读法不再靠魔数。
    #[repr(C)]
    pub struct OSVERSIONINFOW {
        pub dwOSVersionInfoSize: u32,
        pub dwMajorVersion: u32,
        pub dwMinorVersion: u32,
        pub dwBuildNumber: u32,
        pub dwPlatformId: u32,
        pub szCSDVersion: [u16; 128],
    }

    // 布局不变式放编译期（同 RM_PROCESS_INFO 的理由：native-scanner 是 path 依赖、
    // 非 workspace 成员，它的单测只有显式 --manifest-path 才跑，靠测试兜不住回归）。
    // 276 = 5×DWORD + 128×WCHAR；尺寸填错时 RtlGetVersion 直接返回 STATUS_INVALID_INFO_CLASS，
    // 旧实现不查返回码 ⇒ 把失败当成「版本 0.0.0」报给用户。
    const _: () = {
        if std::mem::size_of::<OSVERSIONINFOW>() != 276 {
            panic!("OSVERSIONINFOW 必须是 276 字节：RtlGetVersion 按 dwOSVersionInfoSize 校验尺寸");
        }
        if std::mem::offset_of!(OSVERSIONINFOW, dwMajorVersion) != 4 {
            panic!("dwMajorVersion 偏移必须是 4");
        }
        if std::mem::offset_of!(OSVERSIONINFOW, dwBuildNumber) != 12 {
            panic!("dwBuildNumber 偏移必须是 12：version/build 两个对外字段按它读");
        }
    };

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
    escape_chars(s, true)
}

/// 诊断/留痕行里嵌「外部原文」（规则 id、磁盘路径、未解析 token、io::Error 文本）的
/// 单行化包装。
///
/// 为什么必须包（N1a-L05）：stderr 不是指令通道（只有 `@@ITEM@@` / `@@PLANFILE@@` 是），
/// 所以路径里带引号不构成注入；但原文自带 `\n` 时，一条留痕会被拆成两行 —— 等于凭空
/// 多出一条不存在的诊断，人工对账与「按行数判定」的机检都会被带偏。
///
/// 与 [`json_escape`] **共用同一份转义实现**（§5.16：同一判定不许两份实现，两处各写
/// 一份控制字符表迟早漂），差别只在 `quotes` 这一档：留痕不是 JSON 通道，把路径里的
/// `\` 双写成 `\\`、引号写成 `\"` 只伤可读性、不带来任何安全收益。
pub fn diag_text(s: &str) -> String {
    escape_chars(s, false)
}

/// 转义实现本体。`quotes = true` 时额外处理 `"` 与 `\`（JSON 字符串内必需）。
fn escape_chars(s: &str, quotes: bool) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' if quotes => out.push_str("\\\""),
            '\\' if quotes => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// 定长 UTF-16 缓冲 → String：**刻意不用 `from_utf16_lossy`**（N1b-M07）。
///
/// lossy 把孤立代理项换成 U+FFFD，而 U+FFFD 本身是合法的 Windows 文件名字符，
/// 于是「GBK 遗留介质拷来的怪名字」与「另一个真叫 `…\u{FFFD}…` 的路径」在字符串层面
/// 同键 —— 拿它去比保护清单，撞的是别人。解不开就返回 `None`（=「读不到」），
/// 与「成功但结果与输入相同」分开（[`to_long_path_opt`] 的三态口径）。
pub fn decode_wide_exact(buf: &[u16]) -> Option<String> {
    String::from_utf16(buf).ok()
}

/// 文本形态里是否出现 U+FFFD（lossy 解码的产物标记，N1b-M07）。
///
/// 与 [`has_lossy_path`] 是**两条不同的判据**，不要合并：后者问「原生 OsString 是否
/// 含无法无损解码成 `str` 的字节」，需要原生句柄；前者问「传给我的这个 `str` 是不是
/// 已经被人 lossy 过一遍」——`is_protected_path` 只拿到 `&str`，够不着原生形态，
/// 只能靠这个标记判。二者指向同一个结论：文本形态已丢信息 ⇒ 判定不可靠 ⇒ fail-closed。
pub fn has_lossy_marker(s: &str) -> bool {
    s.contains('\u{FFFD}')
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
///
/// `to_long_path_opt`：区分成败的版本——成功返回长名（**可能与输入相同**：输入本身
/// 已是长名、无 8.3 组件），失败（不存在 / 无权限 / API 报错/**名字解不出无损文本**）
/// 返回 None。
/// [`to_long_path`] 是展示口径，把失败折叠成「原样返回」，无法区分
/// 「成功但无短名」与「失败」；短名判定的两个后果相反（前者应把波浪号当字面名
/// 采信，后者必须 fail-closed），故 protect.rs 改用它（2026-10-12）。
/// N1b-M07：解码走 [`decode_wide_exact`]，非良构 UTF-16 判「读不到」而不是产出
/// 一个含 U+FFFD 的假名字（旧实现 `from_utf16_lossy` 会让它去撞另一个真实路径）。
#[cfg(windows)]
pub fn to_long_path_opt(p: &str) -> Option<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = OsStr::new(p).encode_wide().chain(std::iter::once(0)).collect();
    let mut buf: Vec<u16> = vec![0u16; wide.len().max(1024)];
    loop {
        let n = unsafe { ffi::GetLongPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            return None;
        }
        if (n as usize) <= buf.len() {
            buf.truncate(n as usize);
            while buf.last() == Some(&0) {
                buf.pop();
            }
            return decode_wide_exact(&buf);
        }
        buf.resize(n as usize, 0); // 缓冲不足，按返回长度重试
    }
}

#[cfg(not(windows))]
pub fn to_long_path_opt(p: &str) -> Option<String> {
    Some(p.to_string())
}

#[cfg(windows)]
pub fn to_long_path(p: &str) -> String {
    to_long_path_opt(p).unwrap_or_else(|| p.to_string())
}

#[cfg(not(windows))]
pub fn to_long_path(p: &str) -> String {
    p.to_string()
}

/// 8.3 短名判定：任一组件出现 `~` 紧跟数字即真。与 JS `normalizeForCompare` 的
/// fail-closed 口径同源，故**判据只有这一份**（AGENTS §5.16：同判定不许两套实现）。
///
/// 原先它是 `scan.rs` 里的私有 fn。2026-10-14 提到 util 并 pub，是为了让
/// `cleanup_scan.rs` 的枚举出口能用它给 [`to_long_path`] 做前置短路
/// （每个可删文件都付一次 `GetLongPathNameW` + ≥2 KB 缓冲分配，而规则库里
/// 现算 0 条根声明含短名 ⇒ 绝大多数调用是恒等却贵）。
///
/// 保守方向：字面量真含 `~1` 的普通文件名会被判 true ⇒ 多做一次展开，
/// 只损失性能、不损失正确性。**它只回答「要不要试着展开」，不回答「是否短名」**——
/// 后者必须由 [`expand_short_path`] 触盘判定：Windows 更新缓存里
/// `Package_for_RollupFix~~amd64~~26100.…` 这类合法长名也命中本判据
/// （`~~2`），旧实现把「已展开成功但结果仍含 `~数字`」当成短名展不掉，
/// 整棵子树判受保护（2026-10-23 真机实测 48,033 个文件 / 4.4 GB 被静默排除）。
pub fn contains_short_name(norm: &str) -> bool {
    let mut pending_tilde = false;
    for c in norm.chars() {
        if c == '~' {
            pending_tilde = true;
        } else if pending_tilde {
            if c.is_ascii_digit() {
                return true;
            }
            pending_tilde = false;
        }
    }
    false
}

/// 组件是否**可能是** 8.3 短名（保守的必要条件）：主干（首个 `.` 之前）≤ 8 字符，
/// 且以 `~` + 1~6 位数字结尾，波浪号前至少 1 个字符。
///
/// 为什么需要它：`contains_short_name` 只管「要不要怀疑」，而真正触盘展开
/// （`GetLongPathNameW`）的成本很高。Windows 更新缓存的
/// `Package_for_RollupFix~~amd64~~26100.9711.1.30` 这类长合成名会被宽松判据怀疑，
/// 但它的主干远超 8 字符，**不可能是 8.3 短名** —— 2026-10-23 真机实测，一次扫描
/// 有 4.8 万个文件落在这个形态上，白白付 4.8 万次 GetLongPathNameW（该项 13s 的大头）。
///
/// 保守方向：真实 8.3 短名的冲突后缀固定落在主干末尾且总长 ≤ 8 ⇒ 本判据对它恒为真；
/// 字面名 `Song~1.mp3`（主干 7 字符）会被误判为「可能是短名」，只是多付一次展开，
/// 展开成功即采信，不影响正确性。
fn is_short_name_component(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg);
    let b = stem.as_bytes();
    if b.is_empty() || b.len() > 8 {
        return false;
    }
    let mut i = b.len();
    while i > 0 && b[i - 1].is_ascii_digit() {
        i -= 1;
    }
    if i == b.len() || i == 0 || b[i - 1] != b'~' {
        return false;
    }
    let base = i - 1;
    (1..=6).contains(&base)
}

/// 路径是否有任一组件可能是 8.3 短名（`is_short_name_component` 的整路径版）。
pub fn has_short_name_component(p: &str) -> bool {
    p.split(|c| c == '\\' || c == '/').any(is_short_name_component)
}

/// 8.3 短名展开的**唯一判据实现**（主工程 `engine::protect::expand_short_path` 委托到
/// 这里，扫描器 `scan::is_protected_path` 也调它——两侧不许各写一份，AGENTS N6）。
///
/// 返回 `Some(路径)` = 整条展开成功；**结果允许与输入逐字节相同**——那说明波浪号是
/// 字面名而不是短名（`GetLongPathNameW` 对合法长名原样返回）。返回 `None` = 无法证伪：
/// 非本地盘符路径，或只有祖先能展开、剩余段仍带 `~数字`。
///
/// 这条「整条成功即采信」的口径是 2026-10-12 主工程真机修出来的：旧实现把
/// 「结果与输入相同」当失败，`windowsDownloadCache` 的 `~~26100` 合成名整批误拒。
/// 2026-10-23 扫描器侧按同一口径对齐（此前只有扫描侧还是旧判据，实测同一目录
/// 48,033 个文件被排除）。
pub fn expand_short_path(p: &str) -> Option<String> {
    let b = p.as_bytes();
    if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) {
        return None; // 仅处理本地盘符路径，UNC/相对一律不展开（宁可多拦）
    }
    // 没有「像 8.3 短名」的组件 ⇒ 无需触盘：调用方是**怀疑**才进来的（宽松判据），
    // 这里用必要条件把 `~~26100` 这类长合成名直接按字面采信（2026-10-23）。
    if !has_short_name_component(p) {
        return Some(p.to_string());
    }
    if let Some(full) = to_long_path_opt(p) {
        return Some(full);
    }
    let segs: Vec<&str> = p.split(|c| c == '\\' || c == '/').filter(|c| !c.is_empty()).collect();
    if segs.len() < 2 {
        return None;
    }
    for i in (1..=segs.len() - 1).rev() {
        let head = segs[..i].join("\\");
        let head_has_drive = head.as_bytes().get(1) == Some(&b':');
        let probe = if head_has_drive { head.clone() } else { format!("{}\\{}", segs[0], head) };
        let Some(long) = to_long_path_opt(&probe) else { continue };
        let rest = &segs[i..];
        if rest.is_empty() {
            return Some(long);
        }
        let rest_joined = rest.join("\\");
        // 未展开的剩余段带波浪号数字 ⇒ 可能是短名 ⇒ 无法证伪，fail-closed
        if contains_short_name(&rest_joined) {
            return None;
        }
        return Some(format!("{}\\{}", long.trim_end_matches(['\\', '/']), rest_joined));
    }
    None
}

// ==================== 测试沙箱（唯一入口） ====================
// 为什么要它：清理条目 `tempFiles` 的扫描根**就是用户 %TEMP%**（`cleanup-rules.json`
// 里 `pathPs: "$env:TEMP"`），而本仓测试一直在同一个地方建沙箱。旧写法把
// `remove_dir_all` 手写在用例最后一行，于是**任何一次断言失败 / panic / 早退都在盘上
// 留一份**：本机实测攒了 224 个 `trim-*` 目录，其中两条深度上限用例留下的是 70 层嵌套，
// 结果清理扫描常年在这种垃圾上命中 `MAX_WALK_DEPTH` 并打 depth cap 留痕 ——
// 测试垃圾反过来污染了被测产品看到的世界。
// 口径：Drop 兜底（离开作用域就删，失败路径一样删）；`Deref<Target=Path>` 让
// `root.join(...)` / `root.display()` / `&root` 全部照旧，用例正文不必为守卫改一行。
#[cfg(test)]
pub struct Sandbox(std::path::PathBuf);

#[cfg(test)]
impl Sandbox {
    pub fn path(&self) -> &std::path::Path { &self.0 }
}

#[cfg(test)]
impl std::ops::Deref for Sandbox {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[cfg(test)]
impl AsRef<std::path::Path> for Sandbox {
    fn as_ref(&self) -> &std::path::Path { &self.0 }
}

#[cfg(test)]
impl Drop for Sandbox {
    fn drop(&mut self) {
        // 删失败不改判：测试结论已经由断言给出，收尾再 panic 会把一条红变成两条噪声
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 在 `%TEMP%\trim-<tag>` 建一个自删沙箱。`tag` 由调用方带上 pid（并行用例互不撞名）。
/// 只给 `#[cfg(test)]` 用；集成测试链的是不含 test 配置的 lib，那里另立同款。
#[cfg(test)]
pub fn sandbox(tag: &str) -> Sandbox {
    let dir = std::env::temp_dir().join(format!("trim-{tag}"));
    // 同一 pid 被复用、或上一次被强杀留下的同名目录：先清干净再建，保证用例从空盘开始
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("测试沙箱可创建");
    Sandbox(dir)
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

    /// 2026-10-23：短名展开的**必要形状**。真实短名的冲突后缀固定落在主干末尾且总长 ≤ 8；
    /// Windows 更新缓存的 `~~26100` 长合成名主干远超 8，不可能是短名 ⇒ 不该触盘。
    /// 判红自证：把 `is_short_name_component` 改回 `contains_short_name` 的宽松口径，
    /// 第三条断言立刻红（又会把 4.8 万个长合成名送去 GetLongPathNameW）。
    #[test]
    fn 短名必要条件只认真实8dot3形状() {
        for ok in [
            r"C:\PROGRA~1\Common Files",
            r"C:\Users\ADMINI~1\AppData",
            r"D:\MYFIL~10.TXT",
        ] {
            assert!(has_short_name_component(ok), "真实短名形态必须命中：{ok}");
        }
        for no in [
            r"C:\Windows\SoftwareDistribution\Download\b2cbcbeef\Package_for_RollupFix~~amd64~~26100.9711.1.30\x.cab",
            r"C:\data\long~name.txt",
            r"C:\data\~1.txt",
        ] {
            assert!(!has_short_name_component(no), "长合成名/非短名不得触发展开：{no}");
        }
    }

    /// 2026-10-23：字面名里的 `~~数字` 不是 8.3 短名。旧判据把展开成功但结果仍含
    /// `~数字` 的路径判成「展不掉」，Windows 更新缓存的
    /// `Package_for_RollupFix~~amd64~~26100.…` 整棵子树因此被静默排除。
    /// 判红自证：把 `expand_short_path` 的「整条成功即采信」改回「结果与输入相同即失败」，本条红。
    #[cfg(windows)]
    #[test]
    fn expand_short_path_字面波浪号采信而真短名展不开才拒绝() {
        let _sb = sandbox(&format!("expand-~~26100-{}", std::process::id()));
        let dir = _sb.path().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("a.txt");
        std::fs::write(&real, b"x").unwrap();
        let real_s = real.to_string_lossy().to_string();
        let got = expand_short_path(&real_s).expect("存在的字面 ~~26100 路径必须整条采信（波浪号不是短名标记）");
        // 祖先可能是 8.3 短名（本机 TEMP=…\ADMINI~1\…），展开成哪个长名不重要；
        // 关键是**没有拒绝**，且含字面 `~~26100` 的段原样保留。
        assert!(got.ends_with("a.txt"), "展开结果必须仍指向该文件：{got}");
        assert!(got.contains("trim-expand-~~26100-"), "字面波浪号段不得被丢弃：{got}");
        // 反向对照：不存在的 `~1` 段无法证伪 ⇒ None（fail-closed 仍然保留）
        let ghost = dir.join("no~1dir").join("x.txt").to_string_lossy().to_string();
        assert!(expand_short_path(&ghost).is_none(), "展不开的 ~数字 段必须拒绝");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 行协议的前提：控制字符必须被转义，否则一条名字里带制表符的路径就能伪造 `@@ITEM@@` 行
    #[test]
    fn json_escape_covers_control_chars() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("x\ny\rz\tw"), "x\\ny\\rz\\tw");
        assert_eq!(json_escape("\u{1}"), "\\u0001");
    }

    /// N1a-L05：诊断包装后必须是**单行**——路径自带换行不得凭空多出一条留痕。
    /// 正向点名：命中的是「行数 == 1」与「`\n` 变成字面 `\n` 两字符」，不是「没报错」；
    /// 同时钉住两档的分工（同一实现、只差 quotes 一档）：留痕不双写反斜杠，
    /// JSON 通道必须双写 —— 有人把 `diag_text` 改回 `json_escape(s)` 就会在这里判红。
    #[test]
    fn diag_text_把外部原文压成单行() {
        let forged = "C:\\a\\b\n[cleanup-scan] 致命: 我伪造了一行";
        let one = diag_text(forged);
        assert_eq!(one.lines().count(), 1, "留痕被路径里的换行拆成多行：{one}");
        assert!(one.contains("\\n"), "换行必须转义成字面 \\\\n：{one}");
        assert!(!one.contains('\n'), "包装结果不得再含裸换行");
        assert!(
            one.contains(r"C:\a\b"),
            "留痕档位不该把反斜杠双写成 \\\\（只中性化控制字符）：{one}"
        );
        // 对照：JSON 档位必须双写（行协议的逐字节口径不许被诊断档位带跑）
        assert_eq!(json_escape(r"C:\a"), r"C:\\a", "JSON 档位必须转义反斜杠");
        // NUL 也必须压掉（Windows 文件名不含 NUL，但规则串/求值原文来自解析错误，
        // 一旦带控制字符同样破坏行边界）
        assert_eq!(diag_text("a\u{0}b").lines().count(), 1);
        assert!(diag_text("a\u{0}b").contains("\\u0000"));
    }

    /// N1b-M07：定长 UTF-16 的解码判据是「能不能无损解」，不是「先解了再说」。
    #[test]
    fn decode_wide_exact_拒绝非良构而不是替换成_fffd() {
        // 配对代理项（emoji）是合法 UTF-16 ⇒ 正常解出（🎯 = D83C DFAF，U+1F3AF 超出 u16）
        let ok = decode_wide_exact(&[0xD83C, 0xDFAF]);
        assert_eq!(ok.as_deref(), Some("🎯"), "配对代理项必须无损解出");
        // 前导代理项没有后继 ⇒ 非良构 ⇒ None（旧实现给的是 "a\u{FFFD}b"）
        let lone = decode_wide_exact(&[0x61, 0xD800, 0x62]);
        assert!(lone.is_none(), "孤立代理项必须判「读不到」，不得给出 lossy 串：{lone:?}");
        // 尾代理项没有前导，同样判读不到
        assert!(decode_wide_exact(&[0x61, 0xDCAF]).is_none());
    }

    /// N1b-M07：U+FFFD 是合法文件名字符，所以「文本里出现 U+FFFD」只能判「不可信」，
    /// 不能判「一定被 lossy 过」——正反向各点名一次，避免把判据放宽成「含怪字符就放行」。
    #[test]
    fn has_lossy_marker_只对_fffd_为真() {
        assert!(has_lossy_marker("C:\\a\u{FFFD}b"));
        assert!(!has_lossy_marker("C:\\a\\b"), "普通路径不得被误判");
        assert!(!has_lossy_marker("C:\\报告 🎯.txt"), "合法 Unicode 名字不得被误判");
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