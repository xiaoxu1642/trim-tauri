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
        TerminateProcess(h_term, 1).map_err(|_| "结束进程失败".to_string())?;
        let _ = CloseHandle(h_term);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let still_alive = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).is_ok();
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



/// 顽固软件自启阻断（对应 memory_stubborn_block.ps1，S3）
///
/// 1. 停止并禁用 4 个服务（设为 Manual）
/// 2. 停止 wpscloudsvr 服务
/// 3. 备份并删除 2 个计划任务（schtasks.exe）
/// 4. 设置 WPS 更新注册表 UpdateMode=close
pub fn stubborn_block() -> Result<Value, String> {
    let mut changed_services: Vec<String> = Vec::new();
    let mut fail_services: Vec<String> = Vec::new();
    let mut changed_tasks: Vec<String> = Vec::new();
    let mut fail_tasks: Vec<String> = Vec::new();
    let mut failed = 0i64;

    // 1. 停止并禁用服务（设为 Manual）
    let block_services = ["Edrservice", "GameViewerService", "MuMuRemoteService", "PCManager Service Store"];
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
    let backup_dir = crate::engine::paths::backup_write_dir("backup").join("tasks");
    if !backup_dir.as_os_str().is_empty() {
        let _ = std::fs::create_dir_all(&backup_dir);
    }
    let block_tasks = ["WpsUpdateTask_CHENG", "WpsUpdateLogonTask_CHENG"];
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
        let xml_path = backup_dir.join(format!("{task}.xml"));
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

    Ok(json!({
        "services": changed_services,
        "tasks": changed_tasks,
        "failedServices": fail_services,
        "failedTasks": fail_tasks,
        "failedCount": failed,
    }))
}
