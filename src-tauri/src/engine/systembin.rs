//! 系统工具的绝对路径解析（审查 v2-F7）
//!
//! ## 为什么不能直接写进程名
//!
//! `Command::new("reg.exe")` 落到 `CreateProcessW(lpApplicationName = NULL)`，
//! 其搜索顺序是「**调用方 exe 所在目录** → **父进程 CWD** → System32 → …」，
//! 前两位**优先于 System32**。于是：
//! - 便携版放在用户可写目录（桌面 / U 盘）时，同目录植入同名 `reg.exe`/`sc.exe`
//!   即会被优先加载；
//! - 提权实例由 `elevate.rs` 以 `runas` 拉起，且工作目录被设为 `exe.parent()`
//!   —— 该目录同时占住第一与第二搜索位。
//!
//! 两者叠加的结果：条件成熟时以管理员权限执行植入的同名工具（本地提权）。
//! 这是**条件性风险**，不夸大为「当前已被利用」，但修起来只是一次路径解析。
//!
//! ## 口径
//!
//! 白名单内的工具强制解析到 `%SystemRoot%\System32\`（其次 `%SystemRoot%\`）；
//! 两个目录都不存在时退回裸名 —— 极端环境（系统目录被改名）不至于直接不可用，
//! 但也**不要**为「退回」加更多分支，退回即意味着本函数在这台机器上没起作用。
//! 白名单外的程序（安装包路径、`git` 等可选工具）原样返回，不由本模块处理。

/// 固定到系统目录的工具白名单（大小写不敏感）
///
/// 只收**随 Windows 分发、位于 System32（或系统根）**的工具。用户可自行安装的
/// 工具（如 `git`）不进这张表 —— 它们的真实位置不在系统目录，硬解析反而会把它弄坏。
const PINNED: &[&str] = &[
    "appwiz.cpl",
    "calc.exe",
    "charmap.exe",
    "cleanmgr.exe",
    "cmd.exe",
    "control.exe",
    "desk.cpl",
    "devmgmt.msc",
    "dfrgui.exe",
    "dism.exe",
    "diskmgmt.msc",
    "dxdiag.exe",
    "eventvwr.msc",
    "explorer.exe", // 注意：在系统根而非 System32，靠第二个候选目录命中
    "fltmc.exe", // v0.5.0 残留扫描：过滤管理器实时状态（minifilter 挂载判定）
    "ipconfig.exe",
    "lodctr.exe",
    "main.cpl",
    "mmsys.cpl",
    "msconfig.exe",
    "msinfo32.exe",
    "mspaint.exe",
    "msra.exe",
    "mstsc.exe",
    "narrator.exe",
    "ncpa.cpl",
    "netsh.exe",
    "netsh",
    "notepad.exe",
    "optionalfeatures.exe",
    "osk.exe",
    "perfmon.exe",
    "perfmon.msc",
    "powercfg.exe",
    "powercfg.cpl",
    "powershell.exe", // 注意：在 System32\WindowsPowerShell\v1.0 子目录，见下方专属候选
    "psr.exe",
    "reg.exe",
    "reg",
    "regedit.exe",
    "resmon.exe",
    "rstrui.exe",
    "rundll32.exe",
    "sc.exe",
    "sc",
    "schtasks.exe",
    "schtasks",
    "sdclt.exe",
    "services.msc",
    "sfc.exe",
    "snippingtool.exe",
    "sysdm.cpl",
    "tasklist.exe",
    "taskmgr.exe",
    "taskschd.msc",
    "typeperf.exe", // P1-01：计数器重建后的采样验证
    "utilman.exe",
    "where.exe",
    "wf.msc",
    "winmgmt.exe", // P1-01：/resyncperf 同步 WMI 计数器
    "winver.exe",
    "wsreset.exe",
];

/// 进程名 → 可交给 `Command::new` 的路径。
///
/// 白名单外的名字原样返回（用 `PathBuf` 包一层只是为了统一类型）。
pub fn system_tool(program: &str) -> std::path::PathBuf {    if !PINNED.iter().any(|p| p.eq_ignore_ascii_case(program)) {
        return std::path::PathBuf::from(program);
    }
    let root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));

    // 调用点写法不统一（有带 `.exe` 的也有不带的），两种都试。
    let mut names: Vec<String> = vec![program.to_string()];
    if !program.to_ascii_lowercase().ends_with(".exe") {
        names.push(format!("{program}.exe"));
    }
    // powershell.exe（inbox 5.1，v3-K1 的 PsInline 执行器用）不在 System32 根，
    // 而在 WindowsPowerShell\v1.0 子目录 —— 该工具专属候选排在最前。
    let ps_dir = root.join(r"System32\WindowsPowerShell\v1.0");
    let dirs: Vec<std::path::PathBuf> = if program.eq_ignore_ascii_case("powershell.exe") {
        vec![ps_dir, root.join("System32"), root.clone()]
    } else {
        vec![root.join("System32"), root.clone()]
    };
    for dir in &dirs {
        for n in &names {
            let p = dir.join(n);
            if p.is_file() {
                return p;
            }
        }
    }
    std::path::PathBuf::from(program)
}

// ==================== 原生子进程输出统一解码（P0-02，2026-10-10） ====================

/// 启发式判定无 BOM 字节是否为 UTF-16LE 文本。
///
/// 双向可靠性的关键门槛是「字节流中存在 NUL」：UTF-8 与 GBK 等 ANSI 文本都不会含
/// NUL 字节，而真实控制台 UTF-16 输出必有换行/空格/ASCII（其编码含 NUL 高位）。
/// 在含 NUL 的前提下再按 u16LE 验证可判读比例，防止把含 NUL 的二进制误判。
fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || !bytes.contains(&0) {
        return false;
    }
    let pair_len = bytes.len() / 2;
    let units: Vec<u16> = bytes[..pair_len * 2]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let sample = units.len().min(512);
    let mut ok = 0usize;
    let mut nul_mid = 0usize;
    for (i, u) in units[..sample].iter().enumerate() {
        match u {
            0x09 | 0x0A | 0x0D => ok += 1,
            0x20..=0x7E => ok += 1,
            // CJK 与中文标点/全角（sfc 中文输出的真实范围）
            0x3400..=0x9FFF | 0x3000..=0x303F | 0xFF00..=0xFFEF | 0x2000..=0x206F => ok += 1,
            // 末尾 NUL（UTF-16 结尾）允许；中间 NUL 不允许
            0 if i + 1 < sample => nul_mid += 1,
            _ => {}
        }
    }
    ok * 100 >= sample * 98 && nul_mid == 0
}

/// OEM 代码页解码（中文系统 CP_OEMCP=936 即 GBK）。
#[cfg(windows)]
fn decode_oemcp(bytes: &[u8]) -> Option<String> {
    use windows::Win32::Globalization::{MultiByteToWideChar, CP_OEMCP};
    unsafe {
        // windows 0.61 直接返回 i32：0 = 失败，正数 = 长度/写入数
        let len = MultiByteToWideChar(CP_OEMCP, Default::default(), bytes, None);
        if len <= 0 {
            return None;
        }
        let mut wide = vec![0u16; len as usize];
        let got = MultiByteToWideChar(CP_OEMCP, Default::default(), bytes, Some(&mut wide));
        if got <= 0 {
            return None;
        }
        wide.truncate(got as usize);
        Some(String::from_utf16_lossy(&wide))
    }
}

#[cfg(not(windows))]
fn decode_oemcp(_bytes: &[u8]) -> Option<String> {
    None
}

/// 原生子进程输出的统一解码口径（P0-02，Kudu S3 + Dism++ D-04a）。
///
/// 为什么需要：`sfc.exe` 无视 chcp、恒写 UTF-16LE（常无 BOM），按 UTF-8 lossy 解
/// 得到 NUL 交错串，维护任务的失败诊断失真且 NUL 会弄坏日志查看器；中文系统上部分
/// 控制台工具按 OEM(GBK) 输出，lossy 解把中文糊成替换符。
///
/// 口径顺序（不允许在调用点写第二份）：
/// ① UTF-16LE：BOM 或启发式嗅探
/// ② 合法 UTF-8（含纯 ASCII）原样
/// ③ 非合法 UTF-8 → OEM 代码页
/// ④ 都失败 → UTF-8 lossy 兜底
pub fn decode_native_output(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if bytes.starts_with(&[0xFF, 0xFE]) || looks_like_utf16le(bytes) {
        let body = if bytes.starts_with(&[0xFF, 0xFE]) { &bytes[2..] } else { bytes };
        let pair_len = body.len() / 2;
        let units: Vec<u16> = body[..pair_len * 2]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        // 只去尾 NUL（UTF-16 结尾），其余空白保留
        return String::from_utf16_lossy(&units).trim_end_matches('\0').to_string();
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    if let Some(text) = decode_oemcp(bytes) {
        return text;
    }
    String::from_utf8_lossy(bytes).to_string()
}

/// 后台静默 spawn 的统一入口（真机 v0.1.6 反馈：右键/启动项扫描时 schtasks 等
/// 控制台程序弹出可见 cmd 窗口）——GUI 进程拉起控制台程序时，不带
/// CREATE_NO_WINDOW 会让 Windows 新建控制台并前台显示。所有**后台**系统工具
/// 调用必须经此构造；两个例外不走这里：quickcmds 的可见控制台（产品功能，
/// CREATE_NEW_CONSOLE）与 pwsh 执行层（自带同款 flags）。
pub fn quiet_cmd(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let mut c = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}

/// 资源管理器「打开并选中」的参数串（纯函数，可测）。
///
/// ⚠️ 刻意**不加引号** —— 理由见 [`shell_select_in_explorer`] 的根因注释。
pub fn explorer_select_arg(target: &str) -> String {
    format!("/select,{}", target.replace('/', "\\"))
}

/// ShellExecuteW 拉起的共用底座：lpFile/lpParameters 原样透传（不经 shell 拼接、
/// 无 Rust `Command::arg` 的引号坑，见上）。返回值 >32 为成功（ShellExecute 约定）。
fn shell_execute(file: &str, params: Option<&str>) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let exe_w: Vec<u16> = std::ffi::OsStr::new(file)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let params_w: Option<Vec<u16>> = params.map(|p| {
            std::ffi::OsStr::new(p).encode_wide().chain(std::iter::once(0)).collect()
        });
        let r = unsafe {
            ShellExecuteW(
                None,
                windows::core::w!("open"),
                windows::core::PCWSTR(exe_w.as_ptr()),
                params_w
                    .as_ref()
                    .map(|p| windows::core::PCWSTR(p.as_ptr()))
                    .unwrap_or(windows::core::PCWSTR::null()),
                None,
                SW_SHOWNORMAL,
            )
        };
        if r.0 as usize > 32 {
            Ok(())
        } else {
            Err(format!("ShellExecute 返回 {}", r.0 as isize))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (file, params);
        Err("仅 Windows 支持该操作".into())
    }
}

/// 启动一个白名单内的可执行程序（无参数形态）。典型用例：写好 regedit 的 LastKey
/// 记忆位后拉起 regedit，让它直接定位到启动项的登记键。
pub fn shell_execute_open(program: &str) -> Result<(), String> {
    if program.is_empty() || program.contains('\0') || program.contains('"') {
        return Err("程序路径不可用".into());
    }
    shell_execute(program, None)
}

/// 把 LastKey 写进 HKCU 的 regedit 记忆位，再拉起 regedit —— Windows 没有「打开注册
/// 表并跳到某键」的命令行参数，业界通用做法就是先写 Applets\Regedit\LastKey 再启动。
/// （2026-10-15 从 startup 域提升为公用：syspanel 的「在注册表中查看」是同款需求；
/// contextmenu 域有自己的内嵌变体（流程耦合），新调用方一律走本函数。）
pub fn open_regedit_at(last_key: &str) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ};
    use std::os::windows::ffi::OsStrExt;

    const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit";
    unsafe {
        let sub_w: Vec<u16> = std::ffi::OsStr::new(SUBKEY).encode_wide().chain(std::iter::once(0)).collect();
        let mut hk = HKEY::default();
        // windows 0.61：RegOpenKeyExW 返回 WIN32_ERROR（非 Result），0 = ERROR_SUCCESS
        let opened = RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sub_w.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk);
        if opened.is_err() {
            return Err(format!("打开 regedit 记忆键失败（win32 {}）", opened.0));
        }
        let val_w: Vec<u16> = std::ffi::OsStr::new("LastKey").encode_wide().chain(std::iter::once(0)).collect();
        // REG_SZ 载荷按字节传（含收尾 NUL 的 u16 序列），与 contextmenu/uninstall 域同款
        let mut bytes: Vec<u8> = Vec::with_capacity(last_key.len() * 2 + 2);
        for w in std::ffi::OsStr::new(last_key).encode_wide().chain(std::iter::once(0)) {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let r = RegSetValueExW(hk, PCWSTR(val_w.as_ptr()), Some(0), REG_SZ, Some(&bytes));
        let _ = RegCloseKey(hk);
        if r.is_err() {
            return Err(format!("写入 regedit 记忆键失败（win32 {}）", r.0));
        }
    }
    // regedit 启动时读 LastKey；先写后启，顺序不能反
    let exe = system_tool("regedit.exe");
    shell_execute_open(exe.to_string_lossy().as_ref())
}

/// 在资源管理器里定位（打开并选中）一个已存在的文件或目录。
///
/// ## 为什么不用 `Command::arg`
///
/// `std::process::Command` 在 Windows 上会把**含空格**的参数用一对 `"` 包起来再
/// 拼进命令行，实际执行的是：
///
/// ```text
/// explorer.exe "/select,C:\Program Files (x86)\Steam\steam.exe"
/// ```
///
/// explorer 自己解析命令行时吃不下这对引号，于是**静默回退到默认目录**。
/// 本机实测（2026-10-13，启动项「位置」按钮）：9 项里路径含空格的 3 项
/// （Steam / TranslucentTB / WPS Office）一律开在 Documents，不含空格的 6 项正常；
/// 同一条路径改用 ShellExecuteW 传参则正确落在目标目录。
///
/// `ShellExecuteW` 的 `lpParameters` 原样透传、不做二次转义，所以没有这个坑；
/// 它同样不经 shell 拼接命令行，因此也没有命令注入面。
///
/// 返回值 >32 为成功（ShellExecute 约定），≤32 是错误码。
pub fn shell_select_in_explorer(target: &str) -> Result<(), String> {
    if target.is_empty() || target.contains('\u{0000}') || target.contains('"') {
        return Err("路径不可用于定位".into());
    }
    #[cfg(windows)]
    {
        let exe = system_tool("explorer.exe");
        shell_execute(exe.to_string_lossy().as_ref(), Some(&explorer_select_arg(target)))
    }
    #[cfg(not(windows))]
    {
        Err("仅 Windows 支持资源管理器定位".into())
    }
}

/// reg.exe export 备份类调用的统一超时（v2-L4P-29）：正常毫秒级，15s 已是宽限上界。
/// 登记在 `tools/check-ps-callsites.mjs` 的 REG_EXPORT 表，与源码实参一致性由门禁对拍。
pub const REG_EXPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// `fltmc filters` 的超时（v0.5.0 残留扫描）：正常毫秒级，10s 已覆盖杀软钩住的宽限上界。
/// 与 `REG_EXPORT_TIMEOUT` 同理由收在这里：本模块是后台子进程的咽喉，超时常量的真源必须
/// 只有一处可查（`tools/check-ps-callsites.mjs` 的 F 组就是按 systembin.rs + native/ 找定义的）。
pub const FLTMC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// bcdedit /enum 只读枚举的超时（2026-10-11 C3）：bcdedit 本机枚举通常 <1s，给 15s 宽限防卡死。
/// 登记在 `tools/check-ps-callsites.mjs` F 组，与源码实参一致性由门禁对拍。
pub const BCDEDIT_ENUM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// 计划任务查询/修改/删除（schtasks）的超时。挂在启动项扫描主链与删除链上，
/// 平时毫秒级；任务计划服务被拖住时不能让它永久锁住 IPC。30s 是宽限上界。
pub const SCHTASKS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 只读探测类短命令（tasklist / netsh show / reg query 等）的统一超时（v4 R5-M07）：
/// 正常毫秒级；这类命令挂在扫描/体检/外观查询的同步链上，挂住即锁 IPC。10s 宽限上界。
pub const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `netsh` 设置类操作（winhttp reset / interface set / dns set）的超时（v4 R5-M07）：
/// 正常秒级；网络栈被占用时可能拖住，30s 宽限上界（与 SCHTASKS_TIMEOUT 同档）。
pub const NETSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `sc start` 服务操作的超时（v4 R5-M07）：服务进入 pending 时 `sc` 会一直等，
/// 30s 宽限上界（更长的服务启动由维护链的 MAINT_CMD_TIMEOUT 单独兜）。
pub const SC_CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 电源计划编辑器导出用的 `powercfg` 子进程超时（v5 P0 起为唯一调用点；
/// 原 pssteps 的 Spawn 算子已随 P0-1 电源写面收敛移除）：
/// 正常秒级，30s 宽限上界。
pub const POWERCFG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 优化项 cmd 步骤的超时（P3-5 补收 R5-G-4 漏网的一处）：正常毫秒级～秒级；
/// cmd 步骤不带交互，60s 之外的等待只可能是挂了（等输入 / 被钩住），到点杀。
pub const CMD_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// 带超时的静默子进程执行（v2-L4P-29 / B-7）。
///
/// 为什么必须有它：6 处 `reg.exe export` 备份点此前都是裸 `.output()`——平时毫秒级，
/// 但被杀软钩住/句柄异常时 reg.exe 会永远不退出，删除链就在「备份这一步」整条挂死
/// 且没有任何超时收口。轮询 `try_wait` 到点 `kill()+wait()`；刻意不上 Job Object：
/// reg.exe 是单进程工具、不再 spawn 子孙（需要收整棵树的执行链走 pwsh 层的
/// ProcessJob），裸 kill 已覆盖其威胁模型。超时按失败返回（status 非 0 + stderr 注记），
/// 调用方的 fail-closed 逻辑原样生效。
pub fn quiet_cmd_timeout(
    program: impl AsRef<std::ffi::OsStr>,
    args: &[&str],
    timeout: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    spawn_and_wait_with_timeout(quiet_cmd(program).args(args), timeout)
}

/// 同 [`quiet_cmd_timeout`]，但命令行以 `raw_arg` **原样**传入 —— cmd.exe 的
/// `/s /c "…"` 引号形状必须逐字保留，`args()` 的转义规则会弄坏它（optimizer 的
/// cmd 步骤链是唯一使用方，见 `optimizer::apply::cmd_line_of` 的根因注释）。
/// 超时与终止语义与 args 版共用同一实现，不存在第二套等待逻辑。
pub fn quiet_cmd_timeout_raw(
    program: impl AsRef<std::ffi::OsStr>,
    raw_arg: &str,
    timeout: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    spawn_and_wait_with_timeout(quiet_cmd(program).raw_arg(raw_arg), timeout)
}

/// 子进程退出后收口两条读线程的宽限期。
///
/// 为什么必须有它：管道写端可能被**子孙**继续握持（见 AGENTS §5.13 记过的同一形状），
/// 此时 EOF 不会到来。旧写法在 `Some(status)` 分支直接 `wait_with_output()`，而它会读到
/// EOF 才返回 —— 于是**已经跳出 deadline 检查之后照样无限挂住，不受登记超时保护**
/// （`pwsh` 层记录过实测：进程已 `code=0` 退出，函数仍挂 19.7s，被一个 20s 的 ping 拖住）。
const PIPE_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// 起一条线程读尽管道，结果送进 channel。
///
/// 刻意不用 `join()`：`join` 不可中断，只要还有子孙握着写端就无限期挂住；
/// 只有 channel 能做到「等一段，等不到就放弃」。与 `pwsh` 层同一姿势（审查 v3 P0-1）。
fn spawn_pipe_reader<R>(pipe: Option<R>) -> std::sync::mpsc::Receiver<Vec<u8>>
where
    R: std::io::Read + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let Some(mut pipe) = pipe else {
        let _ = tx.send(Vec::new());
        return rx;
    };
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

/// 收一条管道的读结果。宽限内没读完就交**空串**，不交「半条」：
/// 上层有按前缀判成功的判据（如 `engine::native::process` 对 `schtasks /Query /XML` 的
/// `<?xml` 检查），交出截断内容会把「备份不完整」伪装成「备份成功」，比空串更危险。
fn drain_pipe(rx: std::sync::mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    rx.recv_timeout(PIPE_DRAIN_GRACE).unwrap_or_default()
}

fn spawn_and_wait_with_timeout(
    cmd: &mut std::process::Command,
    timeout: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    use std::process::{Output, Stdio};
    use std::time::Instant;

    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // 必须在等退出**之前**把两条管道 take 走并立刻起线程读尽（审查 v3 P0-1）。
    // 旧实现只轮询 `try_wait()`、一条都不读，于是子进程写满匿名管道缓冲（Windows 默认
    // 4 KB 量级）就阻塞在 write、永不退出，`try_wait()` 恒 None，一路走到登记超时，
    // 最后交出「status=1 + 空 stdout + 一句执行超时」。`schtasks /Query /TN x /XML`
    // （XML 常 >4 KB）、`sfc /scannow`、`dism /StartComponentCleanup` 都落在这个形状上，
    // 最坏被放大成登记的 1800s，还把大输出工具统一伪装成「超时」。
    let rx_out = spawn_pipe_reader(child.stdout.take());
    let rx_err = spawn_pipe_reader(child.stderr.take());
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => {
                return Ok(Output {
                    status,
                    stdout: drain_pipe(rx_out),
                    stderr: drain_pipe(rx_err),
                });
            }
            None => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(Output {
                        status: {
                            #[cfg(windows)]
                            {
                                use std::os::windows::process::ExitStatusExt;
                                std::process::ExitStatus::from_raw(1)
                            }
                            #[cfg(not(windows))]
                            {
                                std::process::ExitStatus::default()
                            }
                        },
                        // 超时按失败处理，刻意交空 stdout（fail-closed）：调用方据此判
                        // 「没拿到结果」，不许拿部分输出去过后缀/前缀判据。
                        stdout: Vec::new(),
                        stderr: format!("执行超时（>{}ms），已终止", timeout.as_millis()).into_bytes(),
                    });
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_tools_resolve_under_system_root() {
        for name in ["reg.exe", "sc", "netsh.exe", "schtasks", "sfc.exe"] {
            let p = system_tool(name);
            let s = p.to_string_lossy().to_lowercase();
            assert!(
                s.contains("system32") || s.contains("windows"),
                "{name} 未解析到系统目录：{s}"
            );
            assert!(s.ends_with(".exe"), "{name} 解析结果缺少扩展名：{s}");
        }
    }

    #[test]
    fn unpinned_names_pass_through() {
        // 安装包路径与可选工具不能被改写
        assert_eq!(system_tool("git").to_str(), Some("git"));
        assert_eq!(
            system_tool(r"D:\dl\vc_redist.x64.exe").to_str(),
            Some(r"D:\dl\vc_redist.x64.exe")
        );
    }

    #[test]
    fn explorer_resolves_to_system_root() {
        // explorer.exe 在系统根，不在 System32 —— 命中不了时应退回裸名而非拼错路径
        let p = system_tool("explorer.exe");
        let s = p.to_string_lossy().to_lowercase();
        assert!(s.ends_with("explorer.exe"), "{s}");
    }

    /// P0-02：UTF-16LE（无 BOM，sfc 的真实形态）必须正确解码，无 NUL、中文可判读
    #[test]
    fn utf16le_无bom_解码无nul且中文可判读() {
        let text = "系统检查完成\r\nSystem check complete.\r\n";
        let bytes: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        // 前置：夹具确实含 NUL 且不是合法 UTF-8 文本（含真 NUL 字符）
        assert!(bytes.contains(&0));
        let got = decode_native_output(&bytes);
        assert_eq!(got, text, "无 BOM UTF-16LE 应逐字还原");
        assert!(!got.contains('\0'), "解码结果不得含 NUL");
        assert!(got.contains("系统检查完成"), "中文尾行必须可判读");
    }

    /// P0-02：UTF-16LE BOM（部分工具形态）
    #[test]
    fn utf16le_bom_解码正确() {
        let text = "组件存储修复完成。";
        let mut bytes = vec![0xFF, 0xFE];
        text.encode_utf16().for_each(|u| bytes.extend_from_slice(&u.to_le_bytes()));
        assert_eq!(decode_native_output(&bytes), text);
    }

    /// P0-02：合法 UTF-8（含中文、无 NUL）绝不允许被嗅探成 UTF-16
    #[test]
    fn utf8_中文不被误判为utf16() {
        let text = "维护任务诊断：sfc 与 DISM 的输出应可判读，换行正常。";
        let got = decode_native_output(text.as_bytes());
        assert_eq!(got, text, "UTF-8 中文必须原样返回，误判 UTF-16 会整句变码");
    }

    /// P0-02：非合法 UTF-8 的 GBK 字节走 OEM 分支。
    /// 非中文代码页系统（CP_OEMCP≠936）不满足前提，skip 并说明（AGENTS §2 用例纪律）。
    #[test]
    #[allow(invalid_from_utf8)] // 夹具字节编译期已知非法 UTF-8，断言属文档性质
    fn gbk_字节走oem分支() {
        #[cfg(windows)]
        {
            use windows::Win32::Globalization::GetOEMCP;
            if unsafe { GetOEMCP() } != 936 {
                eprintln!("SKIP：本机 OEM 代码页非 936（GBK），OEM 分支中文用例未校验");
                return;
            }
        }
        // 「中文」GBK = D6 D0 CE C4，且这四字节不是合法 UTF-8（D0/C4 非续字节）
        let bytes = [0xD6u8, 0xD0, 0xCE, 0xC4];
        assert!(std::str::from_utf8(&bytes).is_err(), "夹具必须确定非法 UTF-8");
        let got = decode_native_output(&bytes);
        assert_eq!(got, "中文", "OEM(GBK) 分支应解出中文，实际 {got:?}");
    }

    /// 审查 v3 P0-1：子进程输出远超匿名管道缓冲（4 KB 量级）时，**必须边跑边读**。
    ///
    /// 旧实现只轮询 `try_wait()`、一条管道都不读，于是写满缓冲的子进程永远阻塞在 write、
    /// 永不退出 → 走到登记超时 → 交出「status=1 + 空 stdout」。`schtasks /Query /XML`、
    /// `sfc`、`dism` 全在这个形状上。本用例让 `cmd.exe` 打到 stdout 的输出**远超管道缓冲量级**，
    /// **零副作用**（不写盘、不起子进程树、不碰注册表），所以进常规组而不 `#[ignore]`：
    /// 判红条件是「拿不到全部字节」——旧实现在此处必然是 0 字节 + 非 0 退出码。
    /// 反向验证已做过：逐字退回旧实现后本用例 FAILED，现象是跑满登记超时并拿到 0 字节。
    #[test]
    fn 大输出子进程的管道必须边跑边读() {
        let line = "0123456789012345678901234567890123456789"; // 单行 40 字节
        let n = 2_000usize; // 累计约百 KB 量级，两个数量级地超出管道缓冲
        // 走 raw_arg 版：cmd.exe 的 `/c "…"` 引号形状必须逐字保留（见 quiet_cmd_timeout_raw 注释）
        let raw = format!("/c \"for /L %n in (1,1,{n}) do @echo {line}\"");
        let out = quiet_cmd_timeout_raw(system_tool("cmd.exe"), &raw, PROBE_TIMEOUT)
            .expect("cmd.exe 应能启动");
        let got = out.stdout.len();
        assert!(
            got >= 60_000,
            "应读尽大输出，实际拿到 {got} 字节 —— 若为 0 说明又回到「不读管道、等子进程自己退出」的旧形状"
        );
        assert!(out.status.success(), "退出码应成功，实际 {:?}", out.status);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !err.contains("执行超时"),
            "不该走超时分支（超时即说明管道没被读）：{err}"
        );
    }

    /// P0-02 真机探针：sfc /verifyonly（非破坏）经同一管道采集，解码后无 NUL。
    /// 耗时数分钟，仅发布前人工 `cargo test -- --ignored` 跑。
    #[test]
    #[ignore = "真机：sfc /verifyonly 非破坏但耗时数分钟，发布前人工跑"]
    fn live_sfc_verifyonly_解码无nul() {
        let out = crate::engine::systembin::quiet_cmd_timeout(
            crate::engine::systembin::system_tool("sfc.exe"),
            &["/verifyonly"],
            crate::engine::native::MAINT_CMD_TIMEOUT,
        )
        .expect("sfc 应能启动");
        let text = decode_native_output(&out.stdout);
        if text.trim().is_empty() {
            // 审查 v3 P0-1：旧写法在这里**无条件**打 SKIP 并返回，于是「超时交出空 stdout」
            // 也被念成「本机未取证」——探针的 SKIP 分支恰好盖住了「不读管道」这个缺陷本身，
            // 等于一条永不判红的断言。现在只有「进程确实成功退出却没写东西」才算未取证，
            // 非 0 退出（含超时）一律判红。
            assert!(
                out.status.success(),
                "sfc 退出码非 0 且 stdout 为空：先排除「管道未被读尽」，不许当未取证放行。stderr={:?}",
                String::from_utf8_lossy(&out.stderr)
            );
            eprintln!("SKIP：sfc 已向重定向 stdout 写空内容（本机未取证，非缺陷）");
            return;
        }
        assert!(!text.contains('\0'), "sfc 输出解码后不得含 NUL: {text:?}");
        assert!(
            text.chars().any(|c| !c.is_whitespace()),
            "应含可判读文本: {text:?}"
        );
    }

    /// 审查 v3 P0-1 的正向对照：确证**真实调用路径的输出确实超过匿名管道缓冲（4 KB 量级）**，
    /// 即旧形状在本机可触发，不是理论推演。`schtasks /Query` 只读、不改任务。
    ///
    /// 取样纪律（AGENTS §2：用例不得依赖本机恰好有的数据）：**遍历**若干任务取最大者，
    /// 而不是取第一个——首版就踩了这坑，第一个任务只有 1151 字节，判据被误判成红。
    /// 本机全部样本都不到 4 KB 时显式 SKIP 并声明「本节未校验」，不 expect 炸。
    /// 但「查询成功却拿到空串」始终判红——那正是 P0-1 的症状本身。
    #[test]
    #[ignore = "真机：依赖本机计划任务样本，发布前人工 cargo test -- --ignored 跑"]
    fn live_schtasks_xml_输出确实超过管道缓冲() {
        const SAMPLE_TASKS: usize = 60;
        let listed = quiet_cmd_timeout(
            system_tool("schtasks.exe"),
            &["/Query", "/FO", "CSV", "/NH"],
            SCHTASKS_TIMEOUT,
        )
        .expect("schtasks 应能启动");
        let names = decode_native_output(&listed.stdout);
        let mut tasks: Vec<String> = Vec::new();
        for line in names.lines() {
            let head = line
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string();
            if head.starts_with('\\') {
                tasks.push(head);
                if tasks.len() >= SAMPLE_TASKS {
                    break;
                }
            }
        }
        if tasks.is_empty() {
            eprintln!("SKIP：本机未取到形如 \\… 的计划任务名，本探针未取证");
            return;
        }
        let mut queried = 0usize;
        let mut biggest_len = 0usize;
        let mut biggest = String::new();
        for t in &tasks {
            let Ok(out) = quiet_cmd_timeout(
                system_tool("schtasks.exe"),
                &["/Query", "/TN", t, "/XML"],
                SCHTASKS_TIMEOUT,
            ) else {
                continue;
            };
            if !out.status.success() {
                continue;
            }
            queried += 1;
            let xml = decode_native_output(&out.stdout);
            assert!(
                !xml.trim().is_empty(),
                "{t} 查询成功却拿到空 stdout——即「管道未被读尽」的旧症状"
            );
            assert!(
                xml.contains("<?xml"),
                "{t} 应拿到 XML 主体，实际前 80 字：{:?}",
                xml.chars().take(80).collect::<String>()
            );
            if xml.len() > biggest_len {
                biggest_len = xml.len();
                biggest = t.clone();
            }
        }
        assert!(queried > 0, "本机 {SAMPLE_TASKS} 个任务样本全部查询失败，探针未取证");
        if biggest_len <= 4096 {
            eprintln!(
                "SKIP：本机 {queried} 个任务的 /XML 最大只有 {biggest_len} 字节（{biggest}），\
                 未覆盖「超过 4 KB 管道缓冲」这一形状 ⇒ 该形状的确证由常规用例\
                 「大输出子进程的管道必须边跑边读」承担，本探针只补真实工具侧"
            );
            return;
        }
        println!(
            "确证：{biggest} 的 /XML 输出 {biggest_len} 字节 > 4096 ⇒ 旧形状（运行期不读管道）在该尺寸上必假超时"
        );
    }
}
