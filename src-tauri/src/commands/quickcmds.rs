//! quickcmds 域（C 批）：quickcmds:run
//!
//! 对照 main.js 6830-6889（QUICKCMDS 白名单 + tokenize/expand/runQuickCmd +
//! quickcmds:run）与 `src/scripts/quickcmds-data.js`（63 条 / 8 分类）。
//!
//! # 安全模型（QC-1，2026-09-15）
//!
//! 渲染层**只传 id**，命令原文从本文件的编译期白名单查询，绝不接受用户拼接输入；
//! 任何 shell 元字符（`; & | > < ^ ` ( ) [ ] { } $`）在启动前即被拒绝，绝不进 cmd.exe。
//! **禁止任意命令执行**：白名单外的 id 一律 `{success:false, message:'未知指令'}`。
//!
//! 启动原语按执行物形态分流（与 JS 逐条对应）：
//! ① URI（`ms-settings:` 等，仅无参数时）→ ShellExecute「open」（= shell.openExternal）；
//! ② `.msc` / `.cpl` → ShellExecute（CreateProcess 无法直接执行）；
//! ③ 其余裸应用名 / `.exe` / 带参系统工具 → **参数数组** spawn（无字符串拼接）。
//!
//! # 与 Electron 的差异（已登记）
//!
//! - ③ 的参数仍是数组传递，但创建标志用 `CREATE_NEW_CONSOLE`：Electron 走
//!   Node `spawn(...,{detached:true})`（stdio 管道），控制台类工具（`cmd /k ipconfig`）
//!   需要独立可见控制台才能看到输出——这是该功能的产品意图；
//! - JS 的 `spawn` 错误经 `'error'` 事件**异步**上报，同步回执仍是 `{ok:true}`；
//!   本实现同样把 spawn 失败只记 warn 日志、回执保持 `{success:true}`（契约逐字段一致）。
//!
//! 本域无 PowerShell 脚本（Electron 侧即 JS 的 spawn/ShellExecute 逻辑），
//! 故 `tools/ps-map/quickcmds*.mjs` 无需条目。
//!
//! 需要加入 lib.rs `generate_handler!` 的完整行：
//!   commands::quickcmds::quickcmds_run,

use std::process::Command;

use serde_json::{json, Value};
use tauri::WebviewWindow;

use crate::engine::{guard, log};

/// 被拒 shell 元字符（QC-1：逐字对齐 JS 的 `[;&|><^`()\[\]{}$]`）
const QUICKCMD_METACHAR: &[char] = &[
    ';', '&', '|', '>', '<', '^', '`', '(', ')', '[', ']', '{', '}', '$',
];

/// 编译期白名单：(id, name, cmd)——逐条照抄 `quickcmds-data.js` 的 CMDS（63 条）。
/// `name` 仅用于日志（与 Electron 的日志文本同形），`cmd` 才是执行真源。
const QUICKCMDS: &[(&str, &str, &str)] = &[
    // 系统工具
    ("sys-cmd", "命令提示符", "cmd"),
    ("sys-cmd-admin", "管理员CMD", "powershell -Command \"Start-Process cmd -Verb RunAs\""),
    ("sys-powershell", "PowerShell", "powershell"),
    ("sys-regedit", "注册表编辑器", "regedit"),
    ("sys-msconfig", "系统配置", "msconfig"),
    ("sys-msinfo32", "系统信息", "msinfo32"),
    ("sys-sysdm", "系统属性(综合)", "sysdm.cpl"),
    ("sys-winver", "Windows版本", "winver"),
    ("sys-rstrui", "系统还原", "rstrui"),
    ("sys-envvar", "环境变量编辑", "rundll32.exe sysdm.cpl,EditEnvironmentVariables"),
    ("sys-winupdate", "Windows更新(综合)", "control /name Microsoft.WindowsUpdate"),
    ("sys-sdclt", "备份还原", "sdclt"),
    ("sys-eventvwr", "事件查看器", "eventvwr.msc"),
    ("sys-perfmon-rel", "可靠性蓝屏记录", "perfmon /rel"),
    // 硬件与设备
    ("hw-devmgmt", "设备管理器(综合)", "devmgmt.msc"),
    ("hw-diskmgmt", "磁盘管理", "diskmgmt.msc"),
    ("hw-desk", "显示设置", "desk.cpl"),
    ("hw-main", "鼠标属性", "main.cpl"),
    ("hw-keyboard", "键盘属性", "control keyboard"),
    ("hw-powercfg", "电源选项", "powercfg.cpl"),
    ("hw-printers", "设备和打印机", "control printers"),
    ("hw-mmsys", "声音设置", "mmsys.cpl"),
    ("hw-autoplay", "自动播放设置", "control /name Microsoft.AutoPlay"),
    // 服务与进程
    ("svc-services", "系统服务", "services.msc"),
    ("svc-taskmgr", "任务管理器", "taskmgr"),
    ("svc-perfmon", "性能监视器", "perfmon.msc"),
    ("svc-resmon", "资源监视器", "resmon"),
    ("svc-taskschd", "计划任务", "taskschd.msc"),
    // 网络
    ("net-ncpa", "网络连接", "ncpa.cpl"),
    ("net-wf", "防火墙设置", "wf.msc"),
    ("net-ipconfig", "本机IP地址", "cmd /k ipconfig /all"),
    ("net-mstsc", "远程桌面", "mstsc"),
    ("net-msra", "远程协助", "msra"),
    ("net-nasc", "网络和共享中心", "control /name Microsoft.NetworkAndSharingCenter"),
    // 程序和功能
    ("app-appwiz", "程序和功能", "appwiz.cpl"),
    ("app-default", "默认程序", "control /name Microsoft.DefaultPrograms"),
    ("app-startup", "启动文件夹", "explorer shell:startup"),
    ("app-fonts", "字体文件夹", "explorer shell:fonts"),
    ("app-optional", "管理可选功能", "optionalfeatures"),
    // 辅助工具
    ("util-calc", "计算器", "calc"),
    ("util-mspaint", "画图", "mspaint"),
    ("util-notepad", "记事本", "notepad"),
    ("util-osk", "屏幕键盘", "osk"),
    ("util-charmap", "字符映射表", "charmap"),
    ("util-cleanmgr", "磁盘清理", "cleanmgr"),
    ("util-snipping", "截图工具", "snippingtool"),
    ("util-psr", "步骤记录器", "psr"),
    ("util-utilman", "辅助功能", "utilman"),
    ("util-narrator", "讲述人", "narrator"),
    ("util-lock", "锁屏", "rundll32.exe user32.dll,LockWorkStation"),
    // 维护与诊断
    ("diag-recent", "最近文件", "explorer shell:recent"),
    ("diag-downloads", "下载文件夹", "explorer shell:downloads"),
    ("diag-temp", "临时文件夹", "explorer %temp%"),
    ("diag-desktop", "桌面文件夹", "explorer shell:desktop"),
    ("diag-appdata", "AppData文件夹", "explorer %appdata%"),
    ("diag-dxdiag", "DirectX诊断", "dxdiag"),
    ("diag-dfrgui", "磁盘碎片整理", "dfrgui"),
    ("diag-slmgr", "系统激活状态", "cmd /k slmgr.vbs /xpr"),
    ("diag-storagesense", "存储感知", "ms-settings:storagesense"),
    ("diag-documents", "文档目录", "explorer %userprofile%\\Documents"),
    // 休眠唤醒排查
    ("power-lastwake", "上次唤醒设备", "cmd /k powercfg -lastwake"),
    ("power-wake-armed", "可唤醒设备列表", "cmd /k powercfg -devicequery wake_armed"),
    ("power-wake-any", "所有唤醒设备详情", "cmd /k powercfg -devicequery wake_from_any"),
];

/// JS `replace(/^["']|["']$/g, '')`（各去掉一个首/尾引号）
fn strip_surrounding_quotes(s: &str) -> String {
    let mut out = s.to_string();
    if out.starts_with('"') || out.starts_with('\'') {
        out.remove(0);
    }
    if out.ends_with('"') || out.ends_with('\'') {
        out.pop();
    }
    out
}

/// `tokenizeQuickCmd`：`/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+/g`
fn tokenize_quick_cmd(cmd: &str) -> Vec<String> {
    let chars: Vec<char> = cmd.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            // 带引号 token：支持 `\` 转义；未闭合时回退到 `\S+` 分支（与正则第三支路一致）
            let mut j = i + 1;
            let mut buf = String::new();
            buf.push(c);
            let mut closed = false;
            while j < chars.len() {
                let ch = chars[j];
                buf.push(ch);
                if ch == '\\' && j + 1 < chars.len() {
                    buf.push(chars[j + 1]);
                    j += 2;
                    continue;
                }
                if ch == c {
                    closed = true;
                    j += 1;
                    break;
                }
                j += 1;
            }
            if closed {
                out.push(strip_surrounding_quotes(&buf));
                i = j;
                continue;
            }
        }
        // `\S+`
        let mut buf = String::new();
        while i < chars.len() && !chars[i].is_whitespace() {
            buf.push(chars[i]);
            i += 1;
        }
        out.push(strip_surrounding_quotes(&buf));
    }
    out
}

/// 大小写不敏感替换（JS `String.replace(/%temp%/gi, ...)`）
fn replace_ci(input: &str, needle: &str, value: &str) -> String {
    let needle_lower = needle.to_lowercase();
    let chars: Vec<char> = input.chars().collect();
    let n = needle.chars().count();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if n > 0 && i + n <= chars.len() {
            let window: String = chars[i..i + n].iter().collect();
            if window.to_lowercase() == needle_lower {
                out.push_str(value);
                i += n;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// `expandQuickEnv`：%temp% → os.tmpdir()、%appdata% → APPDATA、%userprofile% → os.homedir()
fn expand_quick_env(t: &str) -> String {
    let tmp = std::env::temp_dir()
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_string();
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| {
        let drive = std::env::var("HOMEDRIVE").unwrap_or_default();
        let path = std::env::var("HOMEPATH").unwrap_or_default();
        format!("{drive}{path}")
    });
    let out = replace_ci(t, "%temp%", &tmp);
    let out = replace_ci(&out, "%appdata%", &appdata);
    replace_ci(&out, "%userprofile%", &home)
}

/// `/^[a-z][a-z0-9+.-]*:/i`（URI scheme 判定，仅无参数时走 openExternal）
fn is_uri(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    for c in chars {
        if c == ':' {
            return true;
        }
        if !(c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')) {
            return false;
        }
    }
    false
}

/// ShellExecute「open」（= Electron `shell.openExternal` / `shell.openPath`）。
/// HINSTANCE ≤ 32 视为失败（Win32 约定），只记日志、不影响同步回执。
fn shell_open(target: &str, id: &str, stage: &str) {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_NORMAL;

    let wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
    let result = unsafe {
        ShellExecuteW(
            None,
            windows::core::w!("open"),
            PCWSTR(wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_NORMAL,
        )
    };
    if result.0 as isize <= 32 {
        log::write_log(
            "warn",
            &format!("快捷指令 {stage} 失败 {id}: ShellExecute 返回 {}", result.0 as isize),
        );
    }
}

/// 参数数组 spawn（`CREATE_NEW_CONSOLE`：控制台类工具需独立可见控制台）
fn spawn_detached(exe: &str, args: &[String]) -> std::io::Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map(|_| ())
}

/// `runQuickCmd`：返回 (ok, message)
fn run_quick_cmd(id: &str, cmd: &str) -> (bool, String) {
    let toks: Vec<String> = tokenize_quick_cmd(cmd)
        .into_iter()
        .map(|t| expand_quick_env(&t))
        .collect();
    let Some(exe) = toks.first().cloned() else {
        return (false, "空指令".into());
    };
    if exe.is_empty() {
        return (false, "空指令".into());
    }
    if toks
        .iter()
        .any(|t| t.chars().any(|c| QUICKCMD_METACHAR.contains(&c)))
    {
        log::write_log("error", &format!("快捷指令含被拒元字符，拒绝执行: {id}"));
        return (false, "指令包含不允许的字符".into());
    }
    let args = &toks[1..];
    // URI（ms-settings: 等）：仅无参数时识别
    if args.is_empty() && is_uri(&exe) {
        shell_open(&exe, id, "openExternal");
        return (true, String::new());
    }
    // .msc / .cpl：ShellExecute 解析
    let lower = exe.to_ascii_lowercase();
    if lower.ends_with(".msc") || lower.ends_with(".cpl") {
        let target = if args.is_empty() {
            exe.clone()
        } else {
            toks.join(" ")
        };
        shell_open(&target, id, "openPath");
        return (true, String::new());
    }
    // 其余裸应用名 / .exe / 带参系统工具（control/explorer/cmd/powershell/perfmon 等）：spawn
    if let Err(e) = spawn_detached(&exe, args) {
        // 与 Electron 同回执：JS 的 spawn 错误走 'error' 事件异步记日志，同步仍返回 ok:true
        log::write_log("warn", &format!("快捷指令 spawn 失败 {id}: {e}"));
    }
    (true, String::new())
}

/// quickcmds:run — 按 id 执行白名单快捷指令（渲染层只传 id）
#[tauri::command]
pub fn quickcmds_run<R: tauri::Runtime>(window: WebviewWindow<R>, id: Option<String>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let id = id.unwrap_or_default();
    let Some((_, name, cmd)) = QUICKCMDS.iter().find(|(cid, _, _)| *cid == id) else {
        return Ok(json!({ "success": false, "message": "未知指令" }));
    };
    let (ok, message) = run_quick_cmd(&id, cmd);
    log::write_log(
        "info",
        &format!(
            "快捷指令: {name} ({cmd}) {}",
            if ok {
                String::new()
            } else {
                format!("→ {message}")
            }
        ),
    );
    // 成功时与 Electron 同形：只有 success（不附加空 message 字段）
    if ok {
        Ok(json!({ "success": true }))
    } else {
        Ok(json!({ "success": false, "message": message }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_matches_js_regex() {
        assert_eq!(
            tokenize_quick_cmd("cmd /k ipconfig /all"),
            vec!["cmd", "/k", "ipconfig", "/all"]
        );
        // 引号包裹：整段作为一个 token，引号被剥掉
        assert_eq!(
            tokenize_quick_cmd("powershell -Command \"Start-Process cmd -Verb RunAs\""),
            vec!["powershell", "-Command", "Start-Process cmd -Verb RunAs"]
        );
        // 未闭合引号：回退到 \S+（与正则第三支路一致）
        assert_eq!(tokenize_quick_cmd("\"abc"), vec!["abc"]);
    }

    #[test]
    fn metachar_gate_blocks_shell_operators() {
        for bad in ["cmd & del x", "cmd; rm", "cmd | more", "cmd > out", "cmd $(x)", "cmd `x`"] {
            let toks: Vec<String> = tokenize_quick_cmd(bad);
            assert!(
                toks.iter()
                    .any(|t| t.chars().any(|c| QUICKCMD_METACHAR.contains(&c))),
                "应被元字符闸门拒绝: {bad}"
            );
        }
    }

    /// 白名单是编译期的：63 条、id 唯一、无 shell 元字符
    #[test]
    fn whitelist_is_wellformed() {
        assert_eq!(QUICKCMDS.len(), 63);
        let mut ids: Vec<&str> = QUICKCMDS.iter().map(|(id, _, _)| *id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 63, "id 必须唯一");
        for (id, _, cmd) in QUICKCMDS {
            let toks: Vec<String> = tokenize_quick_cmd(cmd);
            assert!(!toks.is_empty() && !toks[0].is_empty(), "{id} 空指令");
            assert!(
                !toks
                    .iter()
                    .any(|t| t.chars().any(|c| QUICKCMD_METACHAR.contains(&c))),
                "{id} 含被拒元字符"
            );
        }
    }

    #[test]
    fn env_expansion_matches_js() {
        assert_eq!(replace_ci("explorer %TEMP%", "%temp%", "C:\\T"), "explorer C:\\T");
        assert_eq!(
            replace_ci("explorer %userprofile%\\Documents", "%userprofile%", "C:\\U"),
            "explorer C:\\U\\Documents"
        );
    }
}