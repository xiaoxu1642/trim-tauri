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
    "utilman.exe",
    "where.exe",
    "wf.msc",
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

/// reg.exe export 备份类调用的统一超时（v2-L4P-29）：正常毫秒级，15s 已是宽限上界。
/// 登记在 `tools/check-ps-callsites.mjs` 的 REG_EXPORT 表，与源码实参一致性由门禁对拍。
pub const REG_EXPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// `fltmc filters` 的超时（v0.5.0 残留扫描）：正常毫秒级，10s 已覆盖杀软钩住的宽限上界。
/// 与 `REG_EXPORT_TIMEOUT` 同理由收在这里：本模块是后台子进程的咽喉，超时常量的真源必须
/// 只有一处可查（`tools/check-ps-callsites.mjs` 的 F 组就是按 systembin.rs + native/ 找定义的）。
pub const FLTMC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// 计划任务查询/修改/删除（schtasks）的超时。挂在启动项扫描主链与删除链上，
/// 平时毫秒级；任务计划服务被拖住时不能让它永久锁住 IPC。30s 是宽限上界。
pub const SCHTASKS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
    use std::process::{Output, Stdio};
    use std::time::Instant;

    let mut child = quiet_cmd(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(_status) => {
                // 进程已退出，管道缓冲（reg.exe stdout 仅数行）不会死锁，正常收尾
                return child.wait_with_output();
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
}
