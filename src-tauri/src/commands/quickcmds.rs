//! quickcmds 域（C 批）：quickcmds:run
//!
//! 对照 main.js 6830-6889（QUICKCMDS 白名单 + tokenize/expand/runQuickCmd +
//! quickcmds:run）与 `src/scripts/quickcmds-data.js`（69 条 / 8 分类）。
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
//! - JS 的 `spawn` 错误经 `'error'` 事件**异步**上报；本实现 spawn 失败会记 warn 并
//!   返回 `{success:false, "启动失败…"}`，不再保持 `{success:true}`（R1b-L02）。
//!
//! 本域无 PowerShell 脚本（Electron 侧即 JS 的 spawn/ShellExecute 逻辑），
//! ps-mapping 无需条目。
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

/// 编译期白名单：(id, name, cmd)——逐条照抄 `quickcmds-data.js` 的 CMDS（条数由测试与 JS 那份对拍，不手抄）。
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
    // WinUtil 借鉴 V3（2026-10-11）补齐旧版面板：计算机管理 / 控制面板 / 区域
    ("sys-compmgmt", "计算机管理", "compmgmt.msc"),
    ("sys-control", "控制面板", "control"),
    ("sys-intl", "区域设置", "intl.cpl"),
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
    // WinUtil 借鉴 V3（2026-10-11）：日期和时间旧版面板
    ("hw-timedate", "日期和时间", "timedate.cpl"),
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
    // 安全中心入口：启动项「目标文件已不存在」那条链的出口之一（用户自己去查，Trim 不代扫描、
    // 也不替用户判定是不是恶意）。URI 由微软文档给定：ms-settings:windowsdefender = Windows Security。
    ("sec-defender", "Windows 安全中心", "ms-settings:windowsdefender"),
    // WinUtil 借鉴 V3（2026-10-11）：旧版「安全和维护」面板（与上面 Win11 设置页不同）
    ("sec-wscui", "安全和维护", "wscui.cpl"),
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

/// 快捷指令里的 `%VAR%` 展开：**直接委托扫描器的唯一实现**（A6-M01 / §5.16 N6）。
///
/// 历史形态是本文件自带一份 `expandQuickEnv`（链式三趟 `replace_ci`：%temp%、%appdata%、
/// %userprofile% 各跑一遍）——同一条链上于是有三份展开器（本处 / `uninstall/dead.rs`
/// 的 `expand_pct` / 扫描器 `expand_env_path`），对「变量取不到」分别给出 空串 /
/// `None` / 保留原文 三种结论。收敛后失败语义只由 `expand_env_path` 定义：**保留原文**，
/// 由调用方用 `first_unexpanded_token` 显式识别（见 `run_quick_cmd` 的元字符闸旁）。
/// 链式改成单趟也顺带修掉旧行为：前一轮插入的值（例如 `TEMP` 里恰好含 `%APPDATA%`）
/// 会被后一轮再扫描一次，占位符只该替换一次。
///
/// QUICKCMDS 里现算只用到 `%temp%` / `%appdata%` / `%userprofile%` 三个令牌，
/// 都是本机常驻环境变量；缺失时按上面的口径保留原文而不是塌成空串（空串会被拼成
/// 盘符相对路径再交给 explorer，症状比「打不开」更隐蔽）。
fn expand_quick_env(t: &str) -> String {
    trim_finder::cleanup_scan::expand_env_path(t)
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

/// ShellExecute「open」带参数版（= 双击快捷方式语义）。
///
/// `params` = lpParameters 原文；控制台系命令（cmd /k xxx）必须走本通道（2026-10-11 真机修复）：
/// `Command::spawn + CREATE_NEW_CONSOLE` 在「父进程带标准句柄」的环境（cargo/终端启动的实例）
/// 会把**旧控制台句柄**经 STARTF_USESTDHANDLES 传给子进程，与 CREATE_NEW_CONSOLE 叠加后
/// cmd 实际挂在旧控制台上、新控制台无人认领 —— 症状 = 窗口一闪而过（Windows Terminal 交接
/// 闪现后即收），命令本体不可见。ShellExecute 由 shell 新建独立控制台，与父进程句柄解耦。
///
/// HINSTANCE ≤ 32 视为失败（Win32 约定）；**1223（ERROR_CANCELLED，用户取消
/// 安全/UAC 提示）同样判失败**——它 > 32，只看 ≤32 会把「用户拒了」播成「已打开」
/// （E1，2026-10-16）。失败必须如实回 false。
fn shell_open_params(target: &str, params: Option<&str>, id: &str, stage: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_NORMAL;

    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let w_target = wide(target);
    let w_params = params.map(wide);
    let params_ptr = w_params.as_deref().map(|v| PCWSTR(v.as_ptr()));
    let result = unsafe {
        ShellExecuteW(
            None,
            windows::core::w!("open"),
            PCWSTR(w_target.as_ptr()),
            params_ptr.unwrap_or(PCWSTR::null()),
            PCWSTR::null(),
            SW_NORMAL,
        )
    };
    if !shell_open_verdict(result.0 as isize) {
        log::write_log(
            "warn",
            &format!("快捷指令 {stage} 失败 {id}: ShellExecute 返回 {}", result.0 as isize),
        );
        return false;
    }
    true
}

/// ShellExecute 返回值判读（纯函数，E1 的可注入桩落点）：≤32 是 SE_ERR_* 错误码；
/// 1223（ERROR_CANCELLED，用户取消安全/UAC 提示）同样判失败——只看 ≤32 会把
/// 「用户拒了」播成「已打开」。
fn shell_open_verdict(code: isize) -> bool {
    code > 32 && code != 1223
}

/// ShellExecute「open」（无参数；= Electron `shell.openExternal` / `shell.openPath`）。
/// HINSTANCE ≤ 32 视为失败；失败必须如实回 false，
/// 否则目标缺失的环境（如家庭版无 gpedit.msc）会弹「已打开」假成功。
fn shell_open(target: &str, id: &str, stage: &str) -> bool {
    shell_open_params(target, None, id, stage)
}

/// 参数数组 spawn（`CREATE_NEW_CONSOLE`）。
///
/// ⚠️ 只用于**GUI 工具**（calc/notepad/taskmgr 等自绘窗口的程序）。控制台系
/// （cmd/powershell/pwsh）不走这里 —— 见 [`shell_open_params`] 的修复说明
/// （2026-10-11：该组合在父进程带标准句柄时会让窗口一闪而过）。
///
/// 程序名先经 `systembin::system_tool` 解析：`CreateProcess` 的搜索顺序是
/// 「exe 目录 → 父 CWD → System32」，便携版/提权实例的 exe 目录可写，
/// 同目录植入同名 `notepad.exe` 之类会被优先执行。白名单外的程序原样返回。
fn spawn_detached(exe: &str, args: &[String]) -> std::io::Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    // v6-K01（P0-2）：解析失败（白名单外/系统异常）映射 io::Error，
    // 与 spawn 失败同走调用方既有的「无法打开」回执，不再裸名回退。
    let program = crate::engine::systembin::system_tool(exe)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
    Command::new(program)
        .args(args)
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map(|_| ())
}

/// 元字符闸（A6-L02）：判据只此一份，任何要交给 shell 的字节都必须先过它。
fn has_rejected_metachar(s: &str) -> bool {
    s.chars().any(|c| QUICKCMD_METACHAR.contains(&c))
}

/// `runQuickCmd`：返回 (ok, message)
fn run_quick_cmd(id: &str, cmd: &str) -> (bool, String) {
    let raw_toks = tokenize_quick_cmd(cmd);
    // R1b-L05：元字符闸必须在展开**之前**——用户目录名含 Windows 合法字符 ( ) $ 时，
    // 展开后的路径不应被误判成指令注入。
    if raw_toks.iter().any(|t| has_rejected_metachar(t)) {
        log::write_log("error", &format!("快捷指令含被拒元字符，拒绝执行: {id}"));
        return (false, "指令包含不允许的字符".into());
    }
    let toks: Vec<String> = raw_toks.into_iter().map(|t| expand_quick_env(&t)).collect();
    let Some(exe) = toks.first().cloned() else {
        return (false, "空指令".into());
    };
    if exe.is_empty() {
        return (false, "空指令".into());
    }
    let args = &toks[1..];
    // URI（ms-settings: 等）：仅无参数时识别
    if args.is_empty() && is_uri(&exe) {
        if shell_open(&exe, id, "openExternal") {
            return (true, String::new());
        }
        return (false, format!("无法打开「{exe}」"));
    }
    // .msc / .cpl：ShellExecute 解析
    let lower = exe.to_ascii_lowercase();
    if lower.ends_with(".msc") || lower.ends_with(".cpl") {
        // 先落到 System32 的绝对路径，避免 ShellExecute 先命中 exe 同目录的同名件。
        // v6-K01（P0-2）：解析失败（面板不在 PINNED/系统缺失）如实回执，不裸名回退
        let resolved = match crate::engine::systembin::system_tool(&exe) {
            Ok(p) => p,
            Err(e) => return (false, format!("无法解析系统面板「{exe}」：{e}")),
        };
        let first = resolved.to_string_lossy().to_string();
        let target = if args.is_empty() {
            first
        } else {
            std::iter::once(first).chain(toks[1..].iter().cloned()).collect::<Vec<_>>().join(" ")
        };
        if shell_open(&target, id, "openPath") {
            return (true, String::new());
        }
        return (false, format!("无法打开「{exe}」"));
    }
    // 控制台系首令牌（cmd / powershell）：走 ShellExecute 带参启动（见 shell_open_params）。
    // 参数取「首个 token 之后的原始子串」而不是重排 toks：tokenize 会剥引号，重新 join 会把
    // `-Command "Start-Process cmd -Verb RunAs"` 的引号语义破坏。白名单内这些命令的首 token
    // 均不带引号（有单测钉住整表形态），切分安全；环境变量（%temp% 等）按原语义展开。
    // v6-K01（P0-2）：pwsh 从本分支移除（用户拍板）——pwsh.exe 不随 Windows 分发、
    // 不在 PINNED，白名单未来也不得加回 pwsh 条目走这里；用户自装 PowerShell 7
    // 的打开需求应经显式外部工具入口，不属于快捷指令系统面板域。
    let base = lower.strip_suffix(".exe").unwrap_or(&lower);
    if matches!(base, "cmd" | "powershell") {
        // 加固：先解析到 System32（防 exe 同目录植入同名 cmd 被 ShellExecute 的
        // 搜索顺序优先命中）；解析失败（系统异常）如实回执，不裸名回退。
        let resolved = match crate::engine::systembin::system_tool(&format!("{base}.exe")) {
            Ok(p) => p,
            Err(e) => return (false, format!("无法解析「{exe}」：{e}")),
        };
        let target = resolved.to_string_lossy().to_string();
        let raw = cmd.trim_start();
        let params = match raw.split_once(char::is_whitespace) {
            Some((_, rest)) => expand_quick_env(rest.trim_start()),
            None => String::new(),
        };
        // A6-L02：上面那道元字符闸跑在 `toks`（切分+剥引号+展开）上，而这里交给
        // `shell_open_params` 的 `params` 是从原始串重切、再展开一次的另一份字节 ——
        // 两份不同源时会出现「判定的字节 ≠ 执行的字节」（AGENTS §5.16 的横向反模式）。
        // 判据对**即将下发的 params 本身**再跑一遍，两份字节就都被覆盖了。
        if has_rejected_metachar(&params) {
            log::write_log("error", &format!("快捷指令参数含被拒元字符，拒绝执行: {id}"));
            return (false, "指令包含不允许的字符".into());
        }
        if shell_open_params(&target, (!params.is_empty()).then_some(params.as_str()), id, "consoleOpen") {
            return (true, String::new());
        }
        return (false, format!("无法打开「{exe}」"));
    }
    // 其余裸应用名 / .exe / 带参系统工具（control/explorer/perfmon 等 GUI 工具）：spawn
    if let Err(e) = spawn_detached(&exe, args) {
        log::write_log("warn", &format!("快捷指令 spawn 失败 {id}: {e}"));
        return (false, format!("启动失败：{e}"));
    }
    (true, String::new())
}

/// quickcmds:run — 按 id 执行白名单快捷指令（渲染层只传 id）
///
/// v4-K04（2026-10-09）：档位从 `guard_readonly` 升 `guard::MAIN` —— 白名单里含
/// `sys-cmd-admin`（`Start-Process cmd -Verb RunAs`）：挂在 readonly 档等于让四个子窗
/// 任一渲染层失陷就能弹 UAC，用户点「是」后拿到管理员令牌的交互式 cmd，绕过 elevate 链
/// 的全部配套（MAIN 档 / 防重入 / nonce 握手 / 日志）。子窗消费面实测为 0（四份子窗
/// HTML 均未挂 quickcmds.js），改档零功能代价。
#[tauri::command]
pub fn quickcmds_run<R: tauri::Runtime>(window: WebviewWindow<R>, id: Option<String>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
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

    /// E1（2026-10-16）：1223（用户取消安全/UAC 提示）必须判失败——它 **>32**，
    /// 旧判据 `>32 ⇒ 已打开` 会把它播成假成功。桩直接把壳的返回值喂给判据本体。
    #[test]
    fn shell_open_拒绝码_1223_必须判失败() {
        assert!(1223 > 32, "前提钉：1223 大于 32（旧判据放行它的原因）");
        assert!(!shell_open_verdict(1223), "1223 判失败");
        assert!(!shell_open_verdict(5), "SE_ERR_ACCESSDENIED 判失败");
        assert!(!shell_open_verdict(0), "0 判失败");
        assert!(shell_open_verdict(42), "正常发起（>32 且 ≠1223）判成功");
    }

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

    /// 渲染层那份清单（`src/scripts/quickcmds-data.js`）与本表必须**同集合**。
    /// 靠手写数字对拍迟早会漂（本次加 `sec-defender` 就是靠 include_str 直接读同一份字节抓齐的），
    /// 所以判据只留一份：解析 JS 里的 `{ id: '…'` 序列，与 QUICKCMDS 逐字比。
    const JS_CMDS: &str = include_str!("../../../src/scripts/quickcmds-data.js");

    fn js_ids() -> Vec<String> {
        JS_CMDS
            .split("{ id: '")
            .skip(1)
            .map(|seg| seg.split('\'').next().unwrap_or("").to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// 渲染层那份 (id, cmd) 对。展示与复制取 JS 文本，执行取 Rust 表 ——
    /// 只对拍 id 会让两条 cmd 文本各自漂移而测试恒绿（用户看到/复制的命令
    /// 与真实执行的不是同一条）。
    fn js_cmds() -> Vec<(String, String)> {
        JS_CMDS
            .split("{ id: '")
            .skip(1)
            .filter_map(|seg| {
                let id = seg.split('\'').next()?.to_string();
                let at = seg.find("cmd: '")? + "cmd: '".len();
                // JS 单引号字符串里的 `\\` 是运行时的一个反斜杠（`\\'` 是转义单引号）——
                // 不解这一步会把源码字面量与 Rust 的运行时值错比对（diag-documents 曾误红）。
                let cmd = seg[at..]
                    .split('\'')
                    .next()?
                    .replace("\\'", "'")
                    .replace("\\\\", "\\");
                Some((id, cmd))
            })
            .collect()
    }

    #[test]
    fn whitelist_is_wellformed() {
        let js = js_ids();
        assert!(!js.is_empty(), "JS 清单解析结果为空 = 解析器写坏了，这条会退化成恒真");
        assert_eq!(QUICKCMDS.len(), js.len(), "两张表的条数不一致（Rust 执行真源 ⇄ JS 界面清单）");
        let mut ids: Vec<&str> = QUICKCMDS.iter().map(|(id, _, _)| *id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "id 必须唯一");
        let mut js_sorted = js.clone();
        js_sorted.sort();
        js_sorted.dedup();
        assert_eq!(ids, js_sorted, "id 集合与渲染层清单不一致（左边缺=界面上点了报未知指令，右边多=界面没有却能被调起）");
        let js_cmds = js_cmds();
        assert_eq!(js_cmds.len(), js.len(), "JS 清单里 cmd 解析结果为空 = 解析器写坏了");
        for (id, _, cmd) in QUICKCMDS {
            let js_cmd = js_cmds
                .iter()
                .find(|(jid, _)| jid == id)
                .map(|(_, c)| c.as_str())
                .unwrap_or("");
            assert_eq!(*cmd, js_cmd, "{id} 的 cmd 原文与渲染层不一致（展示/复制取 JS，执行取 Rust）");
        }
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

    /// A6-M01（v7.2 C07）：`%VAR%` 展开必须委托扫描器的唯一实现，
    /// 失败语义只由那一份定义（取不到 ⇒ **保留原文**），并由调用方用
    /// `first_unexpanded_token` 显式识别——本文件不再自带链式替换器。
    #[test]
    fn quick_env_delegates_to_scanner_expander() {
        for (raw, var) in [
            ("explorer %temp%", "temp"),
            ("explorer %appdata%", "appdata"),
            (r"explorer %userprofile%\Documents", "userprofile"),
        ] {
            let out = expand_quick_env(raw);
            assert_eq!(
                out,
                trim_finder::cleanup_scan::expand_env_path(raw),
                "{var}：快捷指令的展开与扫描器不同源"
            );
            if std::env::var_os(var).is_some() {
                assert_eq!(
                    trim_finder::cleanup_scan::first_unexpanded_token(&out),
                    None,
                    "{var} 本机存在却没展开：{out}"
                );
            }
        }
        // 取不到的变量：保留原文，且残留检测能点名——不许塌成空串（旧实现的三趟替换
        // 会把 unknown 令牌原样留下、却把**空值变量**塌成空段，两种失败语义不一致）。
        let kept = expand_quick_env(r"explorer %TRIM_NO_SUCH_VAR_9F%\x");
        assert_eq!(kept, r"explorer %TRIM_NO_SUCH_VAR_9F%\x");
        assert_eq!(
            trim_finder::cleanup_scan::first_unexpanded_token(&kept).as_deref(),
            Some("TRIM_NO_SUCH_VAR_9F")
        );
    }

    /// 2026-10-11 修复的静态前提：控制台系命令（cmd/powershell 首 token）的**首 token 无引号**
    /// —— run_quick_cmd 的参数切分（首个空白之后的原始子串）依赖这一点。
    /// 同时钉住覆盖面：命中数不得少于 8（cmd 系 6 + powershell 系 2），清单形态变了会在这里红。
    /// v6-K01（P0-2）：pwsh 已从控制台分支移除（不在 PINNED，用户自装物不走系统面板域），
    /// 本测试同步不再把 pwsh 视作覆盖对象——白名单加回 pwsh 条目会因 n 计数与分支脱钩
    /// 而在 run_quick_cmd 落到 spawn_detached（GUI 路径），形态漂移在这里可见。
    #[test]
    fn console_first_token_is_bare() {
        let mut n = 0;
        for (id, _, cmd) in QUICKCMDS {
            let first = cmd.split_whitespace().next().unwrap_or("");
            let lb = first.to_ascii_lowercase();
            let base = lb.strip_suffix(".exe").unwrap_or(&lb).to_string();
            if matches!(base.as_str(), "cmd" | "powershell") {
                assert!(
                    !first.starts_with('"') && !first.starts_with('\''),
                    "{id} 首 token 带引号，shell_open_params 的参数切分会错"
                );
                n += 1;
            }
        }
        assert!(n >= 8, "控制台系命令数异常（{n}，预期 >=8）：切分逻辑的覆盖对象变了");
    }

    /// `#[ignore]` 真机探针（AGENTS §1.6 第二问）：ShellExecute 带参启动回执成功。
    /// 会弹出真实 cmd 窗口 —— 人工目检「窗口保持、不闪退」后手动关闭。
    /// 2026-10-11 闪退修复的验收探针；普通快速组不跑（有窗口副作用）。
    #[ignore = "真机探针：弹真实 cmd 窗口，人工目检后手动关闭"]
    #[test]
    fn console_shell_probe() {
        let ok = shell_open_params("cmd", Some("/k title TrimShellProbe"), "probe", "probe");
        assert!(ok, "ShellExecute 带参启动应返回成功（HINSTANCE>32）");
    }
}
