//! B2 进程控制 + 顽固软件专杀/阻断。
//!
//! 有副作用域：TerminateProcess、删自启文件、禁服务与计划任务（stubborn_block）。
//! 专杀白名单判据（`stubborn_install_roots` / `stubborn_denied_roots` / `stubborn_path_allowed`）
//! 与选择器测试同在本文件，避免「实现搬走、测试留在原地变死码」。


use crate::engine::systembin::system_tool;
use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess};
use super::common::*;
use super::services::*;
// ==================== B2：进程控制 ====================






pub fn kill_process(pid: u32, expected_name: &str) -> Result<Value, String> {
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return Ok(json!({"success": false, "message": "进程不存在或已退出"})),
        };
        let mut name_buf = [0u16; 260];
        let mut name_len = name_buf.len() as u32;
        let exe_name = if QueryFullProcessImageNameW(h, windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0), windows::core::PWSTR(name_buf.as_mut_ptr()), &mut name_len).is_ok() {
            let path = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            std::path::Path::new(&path).file_stem().and_then(|s| s.to_str()).unwrap_or("").to_lowercase()
        } else { String::new() };
        let _ = CloseHandle(h);
        let expected_lower = expected_name.to_lowercase();
        // v2-L4P-55（C-10）：镜像名**取不到即拒**（调用方给了期望名时）。旧口径
        // `!exe_name.is_empty()` 才比对——QueryFullProcessImageNameW 失败 = 比对整体
        // 跳过，剩下的 PID 复用窗口（旧 PID 已死、新进程顶上）会被直接 Terminate。
        if !expected_name.is_empty() {
            if exe_name.is_empty() {
                return Ok(json!({"success": false, "message": "无法读取进程镜像名，已拒绝结束（防 PID 复用误杀）"}));
            }
            if exe_name != expected_lower {
                return Ok(json!({"success": false, "message": "进程 ID 已被系统复用，已拒绝结束"}));
            }
        }
        let h_term = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|_| "无法打开进程（权限不足）".to_string())?;
        let name_display = if exe_name.is_empty() { format!("PID {pid}") } else { exe_name.clone() };
        // 先接住结果再关句柄：`?` 早退会让 CloseHandle 被跳过，反复对受保护进程
        // 点「结束」就每次泄漏一个内核句柄。
        let terminated = TerminateProcess(h_term, 1);
        let _ = CloseHandle(h_term);
        terminated.map_err(|_| "结束进程失败".to_string())?;
        std::thread::sleep(std::time::Duration::from_millis(300));
        // v4 R5-M06：同 `h_term` 的纪律 —— `is_ok()` 直接丢弃句柄，反复对同名进程
        // 点「结束」每次泄漏一个内核句柄（本判据就在结束链的收尾回读里）。
        let still_alive = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        };
        if still_alive {
            Ok(json!({"success": false, "message": format!("无法结束进程 {name_display} (PID {pid})，可能需要管理员权限")}))
        } else {
            Ok(json!({"success": true, "message": format!("已结束进程 {name_display} (PID {pid})")}))
        }
    }
}

/// 顽固软件专杀的目标进程名（小写，不含 .exe）
///
/// ⚠️ 这张表**只做初筛**：命中名字之后还必须过 `stubborn_path_allowed` 的镜像路径判定，
/// 名字本身不构成「可以杀」的充分条件（审查 v2-M1）。
pub(crate) const STUBBORN_TARGETS: &[&str] = &[
    "edrservice","douyin_guard","douyin","douyin_tray",
    "gameviewer","gameviewerservice","gameviewerserver","gameviewerhealthd",
    "mumunxmain","mumunxservice","mumuremoteservice","mumuremotebackend",
    "mumuremotehealthd","vedetector","jianyingpro","jianyingprotray",
    "wps","et","wpp","wpspdf","wpscloudsvr",
    "mscpcmanager","mscpcmanagercore","mscpcmanagerservice",
];

/// 目录前缀归一：小写 + 以 `\` 结尾（否则 `C:\Program Files` 会误配 `C:\Program FilesX`）
fn stubborn_norm_dir(p: &str) -> String {
    let lower = p.trim().to_lowercase().replace('/', "\\");
    if lower.is_empty() {
        return String::new();
    }
    if lower.ends_with('\\') { lower } else { format!("{lower}\\") }
}

/// 专杀认可的「正规安装目录」根集合（小写、带尾部分隔符）
///
/// 为什么需要它：审查 v2-M1 —— 原实现只比对 `szExeFile` 的 exe stem，任何同名进程
/// （用户自己在下载/桌面跑的绿色版、便携版、同名木马，甚至另一个正版前台实例）都会被
/// `TerminateProcess` 干掉，未保存的文档、渲染工程与游戏进度直接丢失。
/// 这里是 fail-closed：镜像路径读不到或不在集合内 → 跳过并记原因，**不退回按名杀**。
pub(crate) fn stubborn_install_roots() -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    for key in [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "LOCALAPPDATA",
        "APPDATA",
        "ProgramData",
    ] {
        if let Ok(v) = std::env::var(key) {
            let r = stubborn_norm_dir(&v);
            if !r.is_empty() {
                roots.push(r);
            }
        }
    }
    // 装在非系统盘「Program Files」的软件（MuMu/剪映装在 D 盘很常见）：逐个盘符补齐，
    // 只认 `X:\Program Files` 与 `X:\Program Files (x86)` 两档，不放开整个盘符。
    for d in 'A'..='Z' {
        let drive = format!("{d}:\\");
        if std::path::Path::new(&drive).exists() {
            roots.push(format!("{drive}Program Files\\").to_lowercase());
            roots.push(format!("{drive}Program Files (x86)\\").to_lowercase());
        }
    }
    roots
}

/// 明确拒绝的目录：即便名字命中，落在用户内容 / 临时 / 系统目录下的进程一律不杀
pub(crate) fn stubborn_denied_roots() -> Vec<String> {
    let mut denied: Vec<String> = Vec::new();
    for key in ["TEMP", "TMP", "WINDIR", "SystemRoot"] {
        if let Ok(v) = std::env::var(key) {
            let r = stubborn_norm_dir(&v);
            if !r.is_empty() {
                denied.push(r);
            }
        }
    }
    let content_dirs = [
        "desktop", "downloads", "documents", "pictures", "videos", "music", "onedrive",
    ];
    for profile_key in ["USERPROFILE", "PUBLIC"] {
        if let Ok(profile) = std::env::var(profile_key) {
            let base = stubborn_norm_dir(&profile);
            if base.is_empty() { continue; }
            for seg in content_dirs {
                denied.push(format!("{base}{seg}\\"));
            }
        }
    }
    denied
}

/// 镜像路径判定：允许安装目录内 且 不在拒绝目录内。
///
/// 纯函数（不碰 Win32），便于单测直接钉死「同名但路径不对的前台进程不被选中」。
pub(crate) fn stubborn_path_allowed(
    image_path: &str,
    install_roots: &[String],
    denied_roots: &[String],
) -> bool {
    let p = image_path.trim().to_lowercase().replace('/', "\\");
    if p.is_empty() {
        return false;
    }
    if denied_roots.iter().any(|r| !r.is_empty() && p.starts_with(r.as_str())) {
        return false;
    }
    install_roots
        .iter()
        .any(|r| !r.is_empty() && p.starts_with(r.as_str()))
}

/// 取进程镜像全路径；取不到返回 `None`（受保护进程/权限不足/已退出）。
///
/// 调用方必须按 `None` → 跳过处理：拿不到路径就不得凭进程名下判断（审查 v2-M1）。
fn query_process_image_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            h,
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(h);
        if !ok {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

pub fn stubborn_kill() -> Result<Value, String> {
    let install_roots = stubborn_install_roots();
    let denied_roots = stubborn_denied_roots();
    let self_pid = std::process::id();
    let mut killed = 0u32;
    let mut failed = 0u32;
    let mut skipped: Vec<String> = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|_| "无法枚举进程".to_string())?;
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..std::mem::zeroed() };
        let mut first = true;
        while (if first { first = false; Process32FirstW(snap, &mut entry) } else { Process32NextW(snap, &mut entry) }).is_ok() {
            let end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let exe = String::from_utf16_lossy(&entry.szExeFile[..end]);
            let stem = exe.to_lowercase();
            let stem = stem.strip_suffix(".exe").unwrap_or(&stem).to_string();
            if !STUBBORN_TARGETS.contains(&stem.as_str()) { continue; }
            let pid = entry.th32ProcessID;
            if pid == 0 || pid == self_pid { continue; }
            // 审查 v2-M1：只比进程名会把任何同名进程一并杀掉。先取镜像全路径——
            // 取不到（受保护/权限不足）就跳过，绝不允许凭名字兜底。
            let Some(image) = query_process_image_path(pid) else {
                skipped.push(format!("{stem}.exe（PID {pid}）无法读取镜像路径，已跳过"));
                continue;
            };
            // 镜像文件名必须与快照一致：防 PID 复用 / 进程已退出后名字被顶替
            let img_stem = std::path::Path::new(&image)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if img_stem != stem {
                skipped.push(format!("{stem}.exe（PID {pid}）镜像名与快照不一致（{image}），已跳过"));
                continue;
            }
            if !stubborn_path_allowed(&image, &install_roots, &denied_roots) {
                skipped.push(format!("{stem}.exe（PID {pid}）不在预期安装目录（{image}），已跳过"));
                continue;
            }
            if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                if TerminateProcess(h, 1).is_ok() { killed += 1; } else { failed += 1; }
                let _ = CloseHandle(h);
            } else { failed += 1; }
        }
        let _ = CloseHandle(snap);
    }
    let mut leftover: Vec<String> = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|_| "无法枚举进程".to_string())?;
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..std::mem::zeroed() };
        let mut first = true;
        let mut seen = std::collections::HashSet::new();
        while (if first { first = false; Process32FirstW(snap, &mut entry) } else { Process32NextW(snap, &mut entry) }).is_ok() {
            let end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let exe = String::from_utf16_lossy(&entry.szExeFile[..end]);
            let stem = exe.to_lowercase();
            let stem = stem.strip_suffix(".exe").unwrap_or(&stem).to_string();
            if !STUBBORN_TARGETS.contains(&stem.as_str()) { continue; }
            let pid = entry.th32ProcessID;
            if pid == 0 || pid == self_pid { continue; }
            // 与执行侧同一口径：只统计「确认在预期安装目录内」的残留，
            // 避免把用户自己放在下载目录的同名进程报成「顽固软件清不掉」。
            let Some(image) = query_process_image_path(pid) else { continue; };
            if !stubborn_path_allowed(&image, &install_roots, &denied_roots) { continue; }
            if seen.insert(stem.clone()) { leftover.push(stem); }
        }
        let _ = CloseHandle(snap);
    }
    Ok(json!({
        "killed": killed,
        "failed": failed,
        "skipped": skipped.len(),
        "skippedDetail": skipped,
        "leftover": leftover
    }))
}


// ==================== 顽固软件专杀选择器测试（审查 v2-M1 回归网） ====================

#[cfg(test)]
mod stubborn_kill_selector_tests {
    use super::*;

    fn roots() -> Vec<String> {
        vec![
            "c:\\program files\\".to_string(),
            "c:\\program files (x86)\\".to_string(),
            "d:\\program files\\".to_string(),
            "c:\\users\\x\\appdata\\local\\".to_string(),
        ]
    }

    fn denied() -> Vec<String> {
        vec![
            "c:\\windows\\".to_string(),
            "c:\\users\\x\\downloads\\".to_string(),
            "c:\\users\\x\\desktop\\".to_string(),
            "c:\\users\\x\\appdata\\local\\temp\\".to_string(),
        ]
    }

    /// 同名但躺在下载目录 / 桌面的绿色版、便携版（前台进程）必须被排除。
    /// 这是 v2-M1 的核心危害：旧实现只看进程名，这种进程会被无条件 TerminateProcess。
    #[test]
    fn rejects_same_name_outside_install_root() {
        for p in [
            r"C:\Users\x\Downloads\wps.exe",
            r"C:\Users\x\Desktop\portable\jianyingpro.exe",
            r"D:\绿色版\douyin.exe",
            r"C:\Windows\Temp\mumunxmain.exe",
        ] {
            assert!(
                !stubborn_path_allowed(p, &roots(), &denied()),
                "同名但路径不在安装目录，必须跳过: {p}"
            );
        }
    }

    /// 装在正规安装目录的目标进程必须仍然被选中（不能为了防误杀把功能整体废掉）。
    #[test]
    fn accepts_real_install_paths() {
        for p in [
            r"C:\Program Files\Kingsoft\WPS Office\ksomisc\wps.exe",
            r"C:\Program Files (x86)\Microsoft PC Manager\MSPCManager.exe",
            r"D:\Program Files\Netease\MuMuPlayer-12.0\MuMuNxMain.exe",
            r"C:\Users\x\AppData\Local\JianyingPro\JianyingPro.exe",
        ] {
            assert!(
                stubborn_path_allowed(p, &roots(), &denied()),
                "正规安装目录内的目标必须命中: {p}"
            );
        }
    }

    /// 空路径 / 取不到镜像路径 → false（fail-closed，不许按名兜底）。
    #[test]
    fn empty_path_is_rejected() {
        assert!(!stubborn_path_allowed("", &roots(), &denied()));
        assert!(!stubborn_path_allowed("   ", &roots(), &denied()));
    }

    /// 拒绝目录优先级高于允许目录：`%LOCALAPPDATA%\Temp` 也在允许根内，仍须拒绝。
    #[test]
    fn denied_root_wins_over_install_root() {
        assert!(!stubborn_path_allowed(
            r"C:\Users\x\AppData\Local\Temp\wps.exe",
            &roots(),
            &denied()
        ));
    }

    /// 目标清单只认声明过的名字，防止后人随手加名把 `explorer` 之类拖进来。
    #[test]
    fn target_list_is_declared_only() {
        for n in ["wps", "jianyingpro", "mumunxmain", "mscpcmanager", "douyin"] {
            assert!(STUBBORN_TARGETS.contains(&n), "目标清单应含 {n}");
        }
        for n in ["explorer", "cmd", "notepad", "trim"] {
            assert!(!STUBBORN_TARGETS.contains(&n), "目标清单不得含 {n}");
        }
    }
}



// ==================== 顽固软件自启阻断：目标现算（2026-10-06 扩抖音/夸克） ====================

/// 夸克网盘更新服务的名字规则：名字带版本号（`QuarkCloudDriveUpdaterService1.0.0.11`、
/// `QuarkCloudDriveUpdaterInternalService1.0.0.11`，图二实测），升级后版本号会变，
/// 按升级器命名前缀现算。核心同步服务（不以 Updater 命名）不受影响。
fn is_quark_updater_service(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("quarkclouddriveupdater")
}

/// 顽固软件治理的目标任务规则（对相对 Tasks 根的任务路径判定，ASCII 大小写不敏感）。
///
/// 为什么不用固定全名：WPS 更新任务带**用户名后缀**（用户机器实测
/// `WpsUpdateTask_Administrator`），历史实现写死 `_CHENG`（开发机用户名），在别的
/// 机器上恒不命中、任务永远删不掉；夸克更新任务带**版本号与 GUID 后缀**、落在两级
/// 文件夹下；抖音守护任务落在 `\DouyinUser\DouyinGuard\` 命名空间内（任务名
/// `LaunchDouyinGuard`，图二的 `DouyinUser_DouyinGuard_LaunchDouyinGuard` 是它的显示
/// 形态）。都改按规则现算；schtasks 侧删不到的进失败清单如实报出，不静默。
fn stubborn_task_rel_matches(rel: &str) -> bool {
    let r = rel.trim().to_ascii_lowercase().replace('/', "\\");
    let name = r.rsplit('\\').next().unwrap_or(&r);
    name == "wpswakewnslogontask"                     // WPS 消息推送中心（登录触发）
        || name.starts_with("wpsupdatetask_")         // WPS 定时更新检查（带用户名后缀）
        || name.starts_with("wpsupdatelogontask_")    // WPS 登录更新检查（带用户名后缀）
        || name.starts_with("quarkclouddriveupdater") // 夸克网盘更新任务（版本号+GUID 后缀）
        // 抖音守护：只在 DouyinUser 命名空间内认这个名字，防同名的其他任务被误删
        || (name == "launchdouyinguard" && r.starts_with("douyinuser\\"))
}

/// 任务全名 → 备份文件名（`\Folder\Name` 形态不能直接当文件名）。
fn stubborn_task_backup_name(task: &str) -> String {
    task.trim_start_matches('\\').replace('\\', "_")
}

/// 从磁盘任务库现算目标任务（返回任务全名：根下任务 `\Name`，文件夹任务 `\Folder\Name`）。
///
/// 直读 `C:\Windows\System32\Tasks`（启动项域同款做法，毫秒级）；跳过 `Microsoft\`
/// 子树（系统任务区）。根目录读不到时记 warn 并返回空——「这些软件一个都没装」
/// 与「目录根本读不了」在日志上可区分。
fn stubborn_enum_tasks() -> Vec<String> {
    let root = std::path::Path::new(r"C:\Windows\System32\Tasks");
    let mut out: Vec<String> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            if dir.as_path() == root {
                crate::engine::log::write_log(
                    "warn",
                    &format!("顽固软件治理：计划任务目录读取失败（{}），本轮跳过任务清理", dir.display()),
                );
            }
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let Ok(rel) = p.strip_prefix(root) else { continue };
            let rel_str = rel.to_string_lossy().replace('/', "\\");
            let lower = rel_str.to_ascii_lowercase();
            if lower == "microsoft" || lower.starts_with("microsoft\\") {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if stubborn_task_rel_matches(&rel_str) {
                out.push(format!("\\{rel_str}"));
            }
        }
    }
    out.sort();
    out
}

/// 顽固软件自启阻断（对应 memory_stubborn_block.ps1，S3）
///
/// 2026-10-06 范围扩展（用户拍板）：目标从 MuMu / 网易 UU 远程 / 微软电脑管家 / WPS
/// 扩到抖音与夸克网盘的全链（服务 / 计划任务 / Run 自启项），见各段注释。
///
/// 1. 停止并设为手动：固定名单（MuMu / 网易 UU 远程 / 微软电脑管家）+ 抖音两个服务
///    + 夸克网盘更新服务（名字带版本号，按前缀现算）
/// 2. 停止 wpscloudsvr 服务
/// 3. 备份并删除目标任务（schtasks.exe；任务名带用户名 / 版本号，从 Tasks 目录现算）
/// 4. 设置 WPS 更新注册表 UpdateMode=close
/// 5. 删除抖音托盘 Run 自启项（备份整个 Run 键后删值）
pub fn stubborn_block() -> Result<Value, String> {
    let mut changed_services: Vec<String> = Vec::new();
    let mut fail_services: Vec<String> = Vec::new();
    let mut changed_tasks: Vec<String> = Vec::new();
    let mut fail_tasks: Vec<String> = Vec::new();
    let mut changed_run: Vec<String> = Vec::new();
    let mut fail_run: Vec<String> = Vec::new();
    let mut failed = 0i64;

    // 1. 停止并禁用服务（设为 Manual）
    //    固定名单之外，夸克网盘的更新服务名字带版本号（`…UpdaterService1.0.0.11`），
    //    升级后版本号会变，从服务注册表按前缀现算（图二实测的两个即由此命中）。
    let mut block_services: Vec<String> = [
        "Edrservice",
        "GameViewerService",
        "MuMuRemoteService",
        "PCManager Service Store",
        "DouyinElevationService",
        "douyin_performance_service",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for name in crate::engine::native::reg_enum_subkeys_pub(
        crate::engine::native::hive_hklm(),
        r"SYSTEM\CurrentControlSet\Services",
    ) {
        if is_quark_updater_service(&name) {
            block_services.push(name);
        }
    }
    block_services.sort();
    block_services.dedup();
    for svc in &block_services {
        unsafe {
            // 先检查服务是否存在
            if service_status(svc).is_none() { continue; }
            // v5 M-P2：停止失败不再 `let _ =` 吞掉 —— 这条是「阻止开机自启」的持久策略，
            // 停不动的进程下次开机照样起来，必须进失败清单。
            let stopped = service_stop_pub(svc).is_ok();
            // SERVICE_DEMAND_START = 3 (Manual)
            let retyped = service_set_start_type(svc, 3).is_ok();
            if stopped && retyped {
                changed_services.push(svc.to_string());
            } else {
                fail_services.push(svc.to_string());
                failed += 1;
            }
        }
    }

    // 2. 停止 wpscloudsvr（不改变启动类型）
    unsafe {
        // v5 M-P2：先判运行态再停。上游 PS 有 `if ($wc.Status -eq 'Running')` 前置，平移丢了
        // 之后「服务本已停止」会被算成失败（1062），于是重复执行同一条持久策略反而报部分失败。
        let running = service_status("wpscloudsvr").map(|(s, _)| s == 4).unwrap_or(false);
        if running {
            if service_stop_pub("wpscloudsvr").is_ok() {
                changed_services.push("wpscloudsvr".to_string());
            } else {
                fail_services.push("wpscloudsvr".to_string());
                failed += 1;
            }
        }
    }

    // 3. 备份并删除计划任务（用 schtasks.exe）
    // v2-M19：导出件是「当时任务长什么样」的凭据，写新根才随便携盘走；老根那份
    // 只是历史留痕（本函数不再读它，也没有还原入口），因此不进 MIGRATION_DIRS 的必需清单。
    // 任务清单从 Tasks 目录现算（见 stubborn_enum_tasks）：历史实现把任务名写死成
    // `WpsUpdateTask_CHENG`（开发机用户名），在别的机器上恒不命中、任务永远删不掉。
    let backup_dir = crate::engine::paths::backup_write_dir("backup").join("tasks");
    if !backup_dir.as_os_str().is_empty() {
        let _ = std::fs::create_dir_all(&backup_dir);
    }
    let block_tasks = stubborn_enum_tasks();
    for task in &block_tasks {
        // 检查任务是否存在
        let exists = match crate::engine::systembin::quiet_cmd_timeout(
            system_tool("schtasks"),
            &["/Query", "/TN", task, "/NH"],
            crate::engine::systembin::REG_EXPORT_TIMEOUT,
        ) {
            Ok(o) => o.status.success(),
            Err(_) => false,
        };
        if !exists { continue; }

        // 备份：导出件是「当时任务长什么样」的唯一凭据 —— 拿不到 / 空 / 不像 XML /
        // 写盘失败，一律**不删任务**（v5 M-1：此前 `let _ = …status()` 把成败全丢，兜底
        // `File::open("NUL")` 又是只读句柄当 stdout、还带可 panic 的 unwrap，于是
        // 「备份没做成」与「备份做成了」在回执里长得一模一样）。
        if backup_dir.as_os_str().is_empty() {
            fail_tasks.push(format!("{task}（备份目录不可用，未删除）"));
            failed += 1;
            continue;
        }
        let xml_path = backup_dir.join(format!("{}.xml", stubborn_task_backup_name(task)));
        let xml = match crate::engine::systembin::quiet_cmd_timeout(
            system_tool("schtasks"),
            &["/Query", "/TN", task, "/XML"],
            crate::engine::systembin::REG_EXPORT_TIMEOUT,
        ) {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr).trim().chars().take(120).collect::<String>();
                crate::engine::log::write_log(
                    "warn",
                    &format!("顽固软件治理：{task} 导出失败 exit={:?}，已放弃删除。stderr={err}", o.status.code().unwrap_or(-1)),
                );
                fail_tasks.push(format!("{task}（导出失败，未删除）"));
                failed += 1;
                continue;
            }
            Err(e) => {
                crate::engine::log::write_log("warn", &format!("顽固软件治理：{task} 无法执行 schtasks: {e}，已放弃删除"));
                fail_tasks.push(format!("{task}（schtasks 无法执行，未删除）"));
                failed += 1;
                continue;
            }
        };
        // /Query /XML 的产物以 `<?xml` 开头；长度下限挡掉「只剩 BOM/空行」这种假成功
        if !xml.starts_with('<') || xml.len() < 64 {
            crate::engine::log::write_log(
                "warn",
                &format!("顽固软件治理：{task} 导出内容不像任务 XML（{} 字节），已放弃删除", xml.len()),
            );
            fail_tasks.push(format!("{task}（导出 XML 形态异常，未删除）"));
            failed += 1;
            continue;
        }
        if let Err(e) = std::fs::write(&xml_path, xml.as_bytes()) {
            crate::engine::log::write_log(
                "warn",
                &format!("顽固软件治理：{task} 备份落盘失败: {e}（{}），已放弃删除", xml_path.display()),
            );
            fail_tasks.push(format!("{task}（备份写盘失败，未删除）"));
            failed += 1;
            continue;
        }

        // 删除（只有备份已确认落盘才会走到这一行）
        let deleted = match crate::engine::systembin::quiet_cmd_timeout(
            system_tool("schtasks"),
            &["/Delete", "/TN", task, "/F"],
            crate::engine::systembin::REG_EXPORT_TIMEOUT,
        ) {
            Ok(o) => o.status.success(),
            Err(_) => false,
        };
        if deleted {
            changed_tasks.push(task.to_string());
        } else {
            fail_tasks.push(task.to_string());
            failed += 1;
        }
    }

    // 4. 设置 WPS 更新注册表
    unsafe {
        use windows::Win32::System::Registry::{
            RegOpenKeyExW, RegSetValueExW, RegCloseKey, HKEY_CURRENT_USER, KEY_WRITE, REG_SZ,
        };
        let key_path = to_wide(r"Software\Kingsoft\Office\6.0\Common\updateinfo");
        let mut hkey = HKEY_CURRENT_USER;
        if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(key_path.as_ptr()), Some(0), KEY_WRITE, &mut hkey).is_ok() {
            let val = to_wide("close");
            let bytes: Vec<u8> = val.iter().flat_map(|&w| w.to_le_bytes()).collect();
            let _ = RegSetValueExW(hkey, PCWSTR(to_wide("UpdateMode").as_ptr()), Some(0), REG_SZ, Some(&bytes));
            let _ = RegCloseKey(hkey);
        }
    }

    // 5. 清理抖音托盘 Run 自启项：`HKCU\...\Run\douyinTray`（图二实测残留
    //    `douyin.exe --start_type=autorun`，任务管理器里已显示禁用但键值还在）。
    //    与启动项域同一口径：先 reg export 备份整个 Run 键，备份拿不到就不删；
    //    删除后回读确认，防「发过删除请求就算成功」的假绿。
    unsafe {
        use windows::Win32::System::Registry::{
            RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, HKEY,
            HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_VALUE_TYPE,
        };
        const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
        const RUN_VALUE: &str = "douyinTray";
        let sk = to_wide(RUN_KEY);
        let mut hk = HKEY::default();
        let mut exists = false;
        if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
            let nm = to_wide(RUN_VALUE);
            let mut ty = REG_VALUE_TYPE::default();
            let mut size = 0u32;
            exists = RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_ok();
            let _ = RegCloseKey(hk);
        }
        if exists {
            let run_backup_dir = crate::engine::paths::backup_write_dir("backup").join("run");
            let _ = std::fs::create_dir_all(&run_backup_dir);
            // 同名覆写（与任务 XML 备份同取舍）：值被删后不会再次执行备份，保最近一份即可
            let reg_file = run_backup_dir.join("douyinTray.reg");
            let mut exported = false;
            if let Some(reg_file_str) = reg_file.to_str() {
                let run_reg_path = format!("HKCU\\{RUN_KEY}");
                exported = crate::engine::systembin::quiet_cmd_timeout(
                    system_tool("reg.exe"),
                    &["export", &run_reg_path, reg_file_str, "/y"],
                    crate::engine::systembin::REG_EXPORT_TIMEOUT,
                )
                .is_ok() && reg_file.exists();
            }
            if !exported {
                fail_run.push(format!("{RUN_VALUE}（注册表备份失败，未删除）"));
                failed += 1;
            } else {
                let mut hk2 = HKEY::default();
                if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk2).is_err() {
                    fail_run.push(format!("{RUN_VALUE}（无法打开注册表键）"));
                    failed += 1;
                } else {
                    let nm2 = to_wide(RUN_VALUE);
                    let _ = RegDeleteValueW(hk2, PCWSTR(nm2.as_ptr()));
                    let _ = RegCloseKey(hk2);
                    let mut still = false;
                    let mut hk3 = HKEY::default();
                    if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk3).is_ok() {
                        let nm3 = to_wide(RUN_VALUE);
                        let mut ty3 = REG_VALUE_TYPE::default();
                        let mut size3 = 0u32;
                        still = RegQueryValueExW(hk3, PCWSTR(nm3.as_ptr()), None, Some(&mut ty3), None, Some(&mut size3)).is_ok();
                        let _ = RegCloseKey(hk3);
                    }
                    if still {
                        fail_run.push(format!("{RUN_VALUE}（删除未生效）"));
                        failed += 1;
                    } else {
                        changed_run.push(RUN_VALUE.to_string());
                    }
                }
            }
        }
    }

    Ok(json!({
        "services": changed_services,
        "tasks": changed_tasks,
        "runValues": changed_run,
        "failedServices": fail_services,
        "failedTasks": fail_tasks,
        "failedRunValues": fail_run,
        "failedCount": failed,
    }))
}

// ==================== 顽固软件自启阻断选择器测试（2026-10-06 扩链回归网） ====================

#[cfg(test)]
mod stubborn_block_selector_tests {
    use super::*;

    /// 任务规则：命中用户机器实测形态（2026-10-06 直读 Tasks 目录核实）与大小写变体；
    /// 不误伤邻近名。
    #[test]
    fn 任务规则命中实测形态且不误伤() {
        for rel in [
            "WpsUpdateTask_Administrator",       // 根下，带用户名后缀
            "wpsupdatelogontask_Administrator",  // 大小写变体
            "wpsupdatetask_张三",                 // 用户名可含非 ASCII
            "WpsWakeWnsLogonTask",
            "QuarkCloudDriveUpdaterSystem\\QuarkCloudDriveUpdater\\QuarkCloudDriveUpdaterTaskSystem1.0.0.11{A9677C45-ACB3-4282-B254-1097A7494758}",
            "DouyinUser\\DouyinGuard\\LaunchDouyinGuard", // 抖音守护的真实层级
            "douyinuser\\douyinguard\\launchdouyinguard",
        ] {
            assert!(stubborn_task_rel_matches(rel), "应命中目标任务: {rel}");
        }
        for rel in [
            "WpsUpdateTask",                        // 缺 `_用户名` 后缀（规则要求下划线分隔）
            "WpsUpdateTaskX",                       // 同上，紧贴后缀不算
            "MicrosoftEdgeUpdateTaskMachineCore",   // 别家的更新任务
            "OneDriveStandaloneUpdater",
            "QuarkCloudDriveSync",                  // 夸克的非升级器命名
            "LaunchDouyinGuard",                    // 同名但不在 DouyinUser 命名空间内
            "DouyinUser\\DouyinGuard\\SomethingElse", // 在抖音命名空间但不是守护任务
            "explorer",
        ] {
            assert!(!stubborn_task_rel_matches(rel), "不得误伤: {rel}");
        }
    }

    /// 服务前缀规则：夸克两个更新服务命中（与版本号无关）；核心/系统服务不误伤。
    #[test]
    fn 夸克服务前缀命中更新器且不误伤() {
        for n in [
            "QuarkCloudDriveUpdaterService1.0.0.11",
            "QuarkCloudDriveUpdaterInternalService1.0.0.11",
            "quarkclouddriveupdater", // 前缀裸名（大小写不敏感）
        ] {
            assert!(is_quark_updater_service(n), "应命中: {n}");
        }
        for n in [
            "QuarkCloudDriveSync",
            "QuarkCloudDrive",
            "wuauserv",
            "PCManager Service Store",
            "DouyinElevationService",
        ] {
            assert!(!is_quark_updater_service(n), "不得误伤: {n}");
        }
    }

    /// 任务全名 → 备份文件名：文件夹路径要拍平成文件名（`\` 不能留在文件名里）。
    #[test]
    fn 任务备份名把路径拍平() {
        assert_eq!(
            stubborn_task_backup_name("\\WpsUpdateTask_Administrator"),
            "WpsUpdateTask_Administrator"
        );
        assert_eq!(
            stubborn_task_backup_name("\\QuarkCloudDriveUpdaterSystem\\QuarkCloudDriveUpdaterTaskSystem1.0.0.11"),
            "QuarkCloudDriveUpdaterSystem_QuarkCloudDriveUpdaterTaskSystem1.0.0.11"
        );
    }
}
