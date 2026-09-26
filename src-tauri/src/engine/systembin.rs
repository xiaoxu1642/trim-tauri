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
    "cmd.exe",
    "dism.exe",
    "explorer.exe", // 注意：在系统根而非 System32，靠第二个候选目录命中
    "ipconfig.exe",
    "lodctr.exe",
    "netsh.exe",
    "netsh",
    "powercfg.exe",
    "powershell.exe", // 注意：在 System32\WindowsPowerShell\v1.0 子目录，见下方专属候选
    "reg.exe",
    "reg",
    "sc.exe",
    "sc",
    "schtasks.exe",
    "schtasks",
    "sfc.exe",
    "tasklist.exe",
    "where.exe",
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
}
