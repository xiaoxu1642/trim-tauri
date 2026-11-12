//! B2 进程控制 + 顽固软件专杀/阻断。
//!
//! 有副作用域：TerminateProcess、删自启文件、禁服务与计划任务（stubborn_block）。
//! 专杀白名单判据（`stubborn_install_roots` / `stubborn_denied_roots` / `stubborn_path_allowed`）
//! 与选择器测试同在本文件，避免「实现搬走、测试留在原地变死码」。


// v6-K01（P0-2）后本文件只以全路径形式调 system_tool，顶部短导入已死——删掉
// （留着就是每编一次报一次 unused）。
use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess};
use windows::Win32::Storage::FileSystem::GetLogicalDrives;
use super::common::*;
use super::registry::reg_read_string;
use super::services::*;
// ==================== B2：进程控制 ====================

/// 镜像名校验：`Ok(())` = 通过；`Err` = 拒绝终止的原因。
///
/// R5e-L06：镜像名取不到或与期望不符都必须拒绝终止——这是防 PID 复用的最后一道闸，
/// 独立成纯函数便于单测钉住「PID 被复用成别的进程时不得终止」。
fn verify_process_image(exe_name: &str, expected_name: &str) -> Result<(), &'static str> {
    if expected_name.is_empty() {
        return Ok(());
    }
    if exe_name.is_empty() {
        return Err("无法读取进程镜像名，已拒绝结束（防 PID 复用误杀）");
    }
    if exe_name.to_lowercase() != expected_name.to_lowercase() {
        return Err("进程 ID 已被系统复用，已拒绝结束");
    }
    Ok(())
}






pub fn kill_process(pid: u32, expected_name: &str) -> Result<Value, String> {
    unsafe {
        // R5e-L06：只开一次带 PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
        // 权限的句柄，镜像校验与 TerminateProcess 共用同一句柄。旧实现先开查询句柄
        // 校验镜像、关闭，再开终止句柄——两次打开之间进程可退出、PID 被复用，
        // 新进程顶替后仍可能被终止。
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, false, pid) {
            Ok(h) => h,
            Err(_) => return Ok(json!({"success": false, "message": "进程不存在或已退出"})),
        };
        let mut name_buf = [0u16; 260];
        let mut name_len = name_buf.len() as u32;
        let exe_name = if QueryFullProcessImageNameW(h, windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0), windows::core::PWSTR(name_buf.as_mut_ptr()), &mut name_len).is_ok() {
            let path = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            std::path::Path::new(&path).file_stem().and_then(|s| s.to_str()).unwrap_or("").to_lowercase()
        } else { String::new() };
        // v2-L4P-55（C-10）：镜像名校验与 TerminateProcess 共用同一句柄（R5e-L06）。
        if let Err(reason) = verify_process_image(&exe_name, expected_name) {
            let _ = CloseHandle(h);
            return Ok(json!({"success": false, "message": reason}));
        }
        let name_display = if exe_name.is_empty() { format!("PID {pid}") } else { exe_name.clone() };
        // 先接住结果再关句柄：`?` 早退会让 CloseHandle 被跳过，反复对受保护进程
        // 点「结束」就每次泄漏一个内核句柄。
        let terminated = TerminateProcess(h, 1);
        let _ = CloseHandle(h);
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
    // 装在非系统盘「Program Files」的软件（MuMu/剪映装在 D 盘很常见）：按位图补齐，
    // 只认 `X:\Program Files` 与 `X:\Program Files (x86)` 两档，不放开整个盘符。
    // 不用逐盘符 `Path::exists()` 探测：空光驱/离线映射盘会把命令线程阻塞住。
    let mask = unsafe { GetLogicalDrives() };
    roots.extend(roots_from_drive_mask(mask));
    roots
}

/// 盘符位图 → 每置位盘符两条 Program Files 根（纯函数，单测注入位图）。
fn roots_from_drive_mask(mask: u32) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..26u32 {
        if mask & (1 << i) != 0 {
            let d = (b'A' + i as u8) as char;
            out.push(format!("{d}:\\Program Files\\").to_lowercase());
            out.push(format!("{d}:\\Program Files (x86)\\").to_lowercase());
        }
    }
    out
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

/// 残留账的一行：允许集内 / 允许集外 / 镜像路径读不到（无法确认）。
/// 「读不到」必须单独计数：它与「确实没有残留」在界面上不能同形。
#[derive(Debug)]
enum ResidualRow {
    Keep(String),
    Outside,
    Unreadable,
}

fn account_leftover(rows: Vec<ResidualRow>) -> (Vec<String>, usize) {
    let mut seen = std::collections::HashSet::new();
    let mut names = Vec::new();
    let mut unreadable = 0usize;
    for row in rows {
        match row {
            ResidualRow::Keep(stem) => {
                if seen.insert(stem.clone()) {
                    names.push(stem);
                }
            }
            ResidualRow::Outside => {}
            ResidualRow::Unreadable => unreadable += 1,
        }
    }
    (names, unreadable)
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
            let end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
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
    let mut rows: Vec<ResidualRow> = Vec::new();
    unsafe {
        // R5b-L02：第二趟只用于「确认残留」，失败时第一趟的战果已经发生；整体 Err 会把
        // 已击杀/失败/跳过数一并吞掉。改为把三项计数写进错误文案并明确「残留未知」，
        // 渲染层按失败展示时仍能看到实际完成了多少。
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(e) => {
                return Err(format!(
                    "清理后无法枚举进程以确认残留（本次已结束 {killed} 个 / 失败 {failed} 个 / 跳过 {} 个；残留情况未知）: {e}",
                    skipped.len()
                ));
            }
        };
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..std::mem::zeroed() };
        let mut first = true;
        while (if first { first = false; Process32FirstW(snap, &mut entry) } else { Process32NextW(snap, &mut entry) }).is_ok() {
            let end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let exe = String::from_utf16_lossy(&entry.szExeFile[..end]);
            let stem = exe.to_lowercase();
            let stem = stem.strip_suffix(".exe").unwrap_or(&stem).to_string();
            if !STUBBORN_TARGETS.contains(&stem.as_str()) { continue; }
            let pid = entry.th32ProcessID;
            if pid == 0 || pid == self_pid { continue; }
            // 与执行侧同一口径：只统计「确认在预期安装目录内」的残留，
            // 避免把用户自己放在下载目录的同名进程报成「顽固软件清不掉」。
            let Some(image) = query_process_image_path(pid) else {
                rows.push(ResidualRow::Unreadable);
                continue;
            };
            if !stubborn_path_allowed(&image, &install_roots, &denied_roots) {
                rows.push(ResidualRow::Outside);
                continue;
            }
            rows.push(ResidualRow::Keep(stem));
        }
        let _ = CloseHandle(snap);
    }
    let (leftover, leftover_unreadable) = account_leftover(rows);
    Ok(json!({
        "killed": killed,
        "failed": failed,
        "skipped": skipped.len(),
        "skippedDetail": skipped,
        "leftover": leftover,
        "leftoverUnreadable": leftover_unreadable
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
///
/// R5e-L02：扁平化只替换 `\`，`\A\B` 与 `\A_B` 会碰撞成同一个文件名，后写覆盖先写，
/// 两个任务的还原凭据只剩一份。追加原任务路径的 8 位哈希后缀，保证不同任务路径
/// 落盘为不同文件（Windows 文件名不允许 `\`，哈希只来自路径本身，稳定且无状态）。
fn stubborn_task_backup_name(task: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    task.hash(&mut hasher);
    let suffix = format!("{:08x}", hasher.finish() & 0xFFFF_FFFF);
    format!("{}_{}", task.trim_start_matches('\\').replace('\\', "_"), suffix)
}

/// 计划任务库遍历的深度上限（R5b-M13）：与 `cleanup::ENGINE_WALK_MAX_DEPTH` /
/// native-scanner `MAX_WALK_DEPTH` 同档。这里之前是唯一没有上限的 `stack` 递归。
const STUBBORN_TASKS_MAX_DEPTH: usize = 64;

// ==================== 任务 XML 备份的落盘形态（R5b-M01） ====================

/// 计划任务存在性查询的判读：只有「任务确实不存在」映射 `Ok(false)`，
/// 其他错误（system_tool 解析失败 / 命令超时 / 非「不存在」的退出码）返回 `Err`。
///
/// R5e-L03：旧实现 `.unwrap_or(false)` 把超时、解析失败、权限错误全部当成
/// 「任务不存在」——schtasks 工具链整体不可用时所有任务都被静默跳过，
/// 回执显示「成功但什么都没改」。调用方拿到 `Err` 必须记入 `fail_tasks`。
fn task_exists_verdict(query: Result<std::process::Output, std::io::Error>) -> Result<bool, String> {
    match query {
        Ok(o) if o.status.success() => Ok(true),
        Ok(o) => {
            let stderr = crate::engine::systembin::decode_native_output(&o.stderr).to_lowercase();
            let stdout = crate::engine::systembin::decode_native_output(&o.stdout).to_lowercase();
            let not_found = stderr.contains("does not exist")
                || stderr.contains("找不到指定的任务")
                || stderr.contains("找不到")
                || stdout.contains("does not exist")
                || stdout.contains("找不到指定的任务")
                || stdout.contains("找不到");
            if not_found {
                Ok(false)
            } else {
                Err(format!(
                    "schtasks 查询失败 exit={:?}，无法确认任务状态",
                    o.status.code()
                ))
            }
        }
        Err(e) => Err(format!("schtasks 无法执行: {e}")),
    }
}

/// 从 XML 文本里取声明中 `encoding` **属性值**的字节区间（`None` = 没声明 / 声明里没这项）。
///
/// 归一（写侧改值）与自检（验侧读值）共用这一份解析：各写一套必然分叉，
/// 而这里的判据恰恰是「声明与实际字节一致」。
fn xml_decl_encoding_span(xml: &str) -> Option<(usize, usize)> {
    let decl_end = xml.find("?>")?;
    let head = &xml[..decl_end];
    if !head.trim_start().starts_with("<?xml") {
        return None;
    }
    // `to_ascii_lowercase` 只改 ASCII 字节、长度不变，所以下标可直接回用在 `head` 上。
    let enc_at = head.to_ascii_lowercase().find("encoding")?;
    let after = &head[enc_at + "encoding".len()..];
    let eq_at = after.find('=')?;
    let value_zone = &after[eq_at + 1..];
    let lead = value_zone.len() - value_zone.trim_start().len();
    let value_start = enc_at + "encoding".len() + eq_at + 1 + lead;
    let rest = &xml[value_start..];
    let quote = rest.chars().next()?;
    if quote == '"' || quote == '\'' {
        let close = rest[1..].find(quote)?;
        Some((value_start + 1, value_start + 1 + close))
    } else {
        // 未加引号的畸形声明：取值到下一个空白 / 声明结束符
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '?' || c == '>')
            .unwrap_or(rest.len());
        if end == 0 { None } else { Some((value_start, value_start + end)) }
    }
}

/// 声明里写的编码名（取不到返回空串）。
fn declared_xml_encoding(xml: &str) -> String {
    xml_decl_encoding_span(xml)
        .map(|(s, e)| xml[s..e].to_string())
        .unwrap_or_default()
}

/// 把 XML 声明的 `encoding` 值归一成 `UTF-16`（与实际字节一致）；声明缺这项时补上。
///
/// 只改声明属性值、不动正文：正文由 [`task_xml_backup_bytes`] 整体转码成 UTF-16LE。
fn force_utf16_declaration(xml: &str) -> String {
    if let Some((start, end)) = xml_decl_encoding_span(xml) {
        return format!("{}{}{}", &xml[..start], "UTF-16", &xml[end..]);
    }
    // 声明里没有 encoding（XML 缺省按 UTF-8 解释）⇒ 补一项，否则声明仍与字节不一致。
    let Some(decl_end) = xml.find("?>") else { return xml.to_string() };
    let head = &xml[..decl_end];
    if !head.trim_start().starts_with("<?xml") {
        return xml.to_string();
    }
    format!("{head} encoding=\"UTF-16\"{}", &xml[decl_end..])
}

/// 任务 XML 备份的落盘字节：UTF-16LE + BOM，声明同步写成 `encoding="UTF-16"`（R5b-M01）。
///
/// 病根：`schtasks /Query /XML` 的产物是**单字节流**（经 `decode_native_output` 解成
/// `String`），声明却写着 `encoding="UTF-16"`。旧实现按 UTF-8 落盘 ⇒ 声明与实际编码
/// 不一致：实测 `System.Xml.XmlDocument.Load` 直接拒（`There is no Unicode byte order
/// mark`），转成 UTF-16LE+BOM 才 `Load OK` —— 这份「删除前唯一还原凭据」因此不可解析。
/// 任务 XML 备份落盘字节（R5b-M01 / R5d-M04-02）：UTF-16LE+BOM + 声明归一 `UTF-16`，
/// 与 `verify_task_xml_backup` 配对使用。`startup.rs` 的任务臂备份复用同一修法。
pub(crate) fn task_xml_backup_bytes(xml: &str) -> Vec<u8> {
    let body = force_utf16_declaration(xml);
    let mut bytes = Vec::with_capacity(2 + body.len() * 2);
    bytes.extend_from_slice(&[0xFF, 0xFE]);
    bytes.extend(body.encode_utf16().flat_map(|u| u.to_le_bytes()));
    bytes
}

/// 落盘件回读自检（R5b-M01）：BOM、字节编码与 XML 声明三者必须自洽，且根元素在。
///
/// 本仓没有 XML 解析依赖（不新增依赖），所以判的正是实测里让 `System.Xml` 拒收的那几项
/// ——BOM 在不在、字节是不是 UTF-16LE、声明写的是不是 UTF-16——再叠一道「任务根元素
/// `<Task` 在不在」的通形状判据，挡掉「转码把正文弄丢」。
/// 任一项不过 ⇒ 调用方必须放弃删除任务：宁可这次不删，也不留一份不可还原的凭据。
/// 落盘件回读自检（R5b-M01 / R5d-M04-02）：BOM、字节编码与 XML 声明三者自洽且根元素在。
/// 任一不过 ⇒ 调用方放弃删除任务（宁可这次不删，也不留不可还原凭据）。
pub(crate) fn verify_task_xml_backup(bytes: &[u8]) -> Result<(), String> {
    if !bytes.starts_with(&[0xFF, 0xFE]) {
        return Err("缺少 UTF-16LE BOM（按声明解析的读取器会拒）".to_string());
    }
    let body = &bytes[2..];
    if body.len() % 2 != 0 {
        return Err("UTF-16 字节数不是偶数（落盘件被截断？）".to_string());
    }
    let units: Vec<u16> = body
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16(&units).map_err(|e| format!("UTF-16LE 解码失败: {e}"))?;
    if !text.starts_with("<?xml") {
        return Err("落盘件不以 XML 声明开头".to_string());
    }
    if !text.contains("?>") {
        return Err("XML 声明没有结束标记".to_string());
    }
    let declared = declared_xml_encoding(&text);
    if !declared.eq_ignore_ascii_case("UTF-16") {
        return Err(format!("声明的编码是 {declared:?}，与实际 UTF-16LE+BOM 不一致"));
    }
    if !text.contains("<Task") {
        return Err("落盘件里找不到任务根元素 `<Task`".to_string());
    }
    Ok(())
}

// ==================== 任务库根：必须由系统根派生（R5b-M02） ====================

/// 任务库相对系统根的子路径。
const SYSTEM_TASKS_SUBDIR: &str = r"System32\Tasks";

/// 系统根 → 任务库根（纯函数：`sysroot` 取 `%SystemRoot%` 的值，单测直接注入）。
///
/// 病根：旧实现写死 C: 下的任务库，系统装在 D:/E: 的机器上 `read_dir` 直接失败，
/// 清单恒空而回执报「成功但什么都没改」。同域启动项早已按 `%SystemRoot%` 取根，本域漏改。
fn system_tasks_root_from(sysroot: Option<&str>) -> Option<std::path::PathBuf> {
    let root = sysroot?.trim().trim_end_matches(|c| c == '\\' || c == '/');
    if root.is_empty() {
        return None;
    }
    Some(std::path::Path::new(root).join(SYSTEM_TASKS_SUBDIR))
}

/// 本机任务库根：`%SystemRoot%` → `%WINDIR%`。
///
/// 两个变量都取不到时返回**原因**，不退回某个写死的盘符：读不到 ≠ 没有任务，
/// 调用方必须能把「系统根未解析」如实报进回执（R5b-M02）。
fn system_tasks_root() -> Result<std::path::PathBuf, String> {
    let sysroot = std::env::var("SystemRoot")
        .ok()
        .or_else(|| std::env::var("WINDIR").ok());
    system_tasks_root_from(sysroot.as_deref())
        .ok_or_else(|| "系统根未解析（%SystemRoot% / %WINDIR% 均缺失或为空）".to_string())
}

/// 任务库枚举结果（R5b-M02）：「读不到」与「确实没有任务」必须可区分。
///
/// 旧实现两者都是空 `Vec`，只有一条日志能分辨 ⇒ 根目录读不到时回执是 `tasks: []` +
/// `failedCount: 0`，用户看到的是「执行成功、什么都没改」（与本仓「失败不得伪装成
/// 空结果」口径冲突）。
struct TaskEnum {
    tasks: Vec<String>,
    /// `Some(原因)` ⇒ 本轮清单不可信，调用方不得当成「没有任务」。
    root_error: Option<String>,
}

/// 从本机任务库现算目标任务（根由 [`system_tasks_root`] 派生）。
fn stubborn_enum_tasks() -> TaskEnum {
    match system_tasks_root() {
        Ok(root) => stubborn_enum_tasks_at(&root),
        Err(e) => TaskEnum { tasks: Vec::new(), root_error: Some(e) },
    }
}

/// 在给定任务库根下现算目标任务（返回任务全名：根下任务 `\Name`，文件夹任务
/// `\Folder\Name`）；根由调用方注入，单测可指向任意盘符的临时目录。
///
/// 直读 %SystemRoot%\System32\Tasks（启动项域同款做法，毫秒级）；跳过 `Microsoft\`
/// 子树（系统任务区）。根目录读不到时 `root_error` 带原因返回（不是「没有任务」）。
///
/// R5b-M13（v7.2 C06）：补深度上限、重解析点拒绝与非根目录读失败计数。
fn stubborn_enum_tasks_at(root: &std::path::Path) -> TaskEnum {
    let mut out: Vec<String> = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut unreadable = 0usize;
    let mut root_error: Option<String> = None;
    while let Some((dir, depth)) = stack.pop() {
        if depth >= STUBBORN_TASKS_MAX_DEPTH {
            crate::engine::log::write_log(
                "warn",
                &format!(
                    "顽固软件治理：计划任务目录超过深度上限 {STUBBORN_TASKS_MAX_DEPTH}，已跳过 {}",
                    dir.display()
                ),
            );
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                // 根读不到 ⇒ 清单整体不可信，带原因返回；子目录读不到只记不完整（同旧口径）。
                if dir.as_path() == root {
                    root_error = Some(format!("计划任务目录读取失败（{}）: {e}", dir.display()));
                } else {
                    unreadable += 1;
                }
                continue;
            }
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                unreadable += 1;
                continue;
            };
            // 跟随 junction 会把别的子树算进来（甚至成环）；与清理域同一口径拒绝。
            if crate::engine::protect::is_reparse(&meta) {
                continue;
            }
            let Ok(rel) = p.strip_prefix(root) else { continue };
            let rel_str = rel.to_string_lossy().replace('/', "\\");
            let lower = rel_str.to_ascii_lowercase();
            if lower == "microsoft" || lower.starts_with("microsoft\\") {
                continue;
            }
            if meta.is_dir() {
                stack.push((p, depth + 1));
                continue;
            }
            if meta.is_file() && stubborn_task_rel_matches(&rel_str) {
                out.push(format!("\\{rel_str}"));
            }
        }
    }
    if unreadable > 0 {
        crate::engine::log::write_log(
            "warn",
            &format!("顽固软件治理：计划任务目录有 {unreadable} 个子项不可读，任务清单可能不完整"),
        );
    }
    out.sort();
    TaskEnum { tasks: out, root_error }
}

/// 顽固软件自启阻断（原 PS 时代脚本 memory_stubborn_block.ps1，已退役；S3）
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
            match service_status_query(svc) {
                ServiceQuery::NotFound => continue,
                ServiceQuery::Unknown => {
                    fail_services.push(svc.to_string());
                    failed += 1;
                    continue;
                }
                ServiceQuery::State(_) => {}
            }
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
        let running = service_status("wpscloudsvr")
            .map(|s| s == super::services::SVC_RUNNING)
            .unwrap_or(false);
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
    // R5b-L10：`backup_write_dir` 恒返回非空路径，旧的 `as_os_str().is_empty()` 是死守卫；
    // 真正的失败点是建目录。建不出来时该批任务一律不删，并逐个记进 fail_tasks。
    let backup_dir_ok = std::fs::create_dir_all(&backup_dir).is_ok();
    if !backup_dir_ok {
        crate::engine::log::write_log(
            "warn",
            &format!("顽固软件治理：任务备份目录创建失败（{}），相关任务将不删除", backup_dir.display()),
        );
    }
    let task_enum = stubborn_enum_tasks();
    if let Some(reason) = task_enum.root_error {
        // R5b-M02：读不到 ≠ 没有任务。清单不可信时必须进失败清单——旧实现只写一条日志，
        // 回执仍是 `tasks: []` + `failedCount: 0`，用户看到的是「成功但什么都没改」。
        crate::engine::log::write_log(
            "warn",
            &format!("顽固软件治理：{reason}，本轮跳过任务清理"),
        );
        fail_tasks.push(format!("计划任务清单（{reason}）"));
        failed += 1;
    }
    for task in &task_enum.tasks {
        // 检查任务是否存在
        // R5e-L03：只有「任务确实不存在」映射 false（跳过）；工具解析失败/命令超时/
        // 非「不存在」的退出码都返回 Err，必须记入 fail_tasks，不得静默跳过。
        let query = crate::engine::systembin::system_tool("schtasks")
            .map_err(std::io::Error::other)
            .and_then(|exe| {
                crate::engine::systembin::quiet_cmd_timeout(
                    exe,
                    &["/Query", "/TN", task, "/NH"],
                    crate::engine::systembin::SCHTASKS_TIMEOUT,
                )
            });
        let exists = match task_exists_verdict(query) {
            Ok(exists) => exists,
            Err(e) => {
                crate::engine::log::write_log(
                    "warn",
                    &format!("顽固软件治理：{task} 存在性查询失败: {e}，已放弃删除"),
                );
                fail_tasks.push(format!("{task}（存在性查询失败，未删除）"));
                failed += 1;
                continue;
            }
        };
        if !exists { continue; }

        // 备份：导出件是「当时任务长什么样」的唯一凭据 —— 拿不到 / 空 / 不像 XML /
        // 写盘失败，一律**不删任务**（v5 M-1：此前 `let _ = …status()` 把成败全丢，兜底
        // `File::open("NUL")` 又是只读句柄当 stdout、还带可 panic 的 unwrap，于是
        // 「备份没做成」与「备份做成了」在回执里长得一模一样）。
        if !backup_dir_ok {
            fail_tasks.push(format!("{task}（备份目录不可用，未删除）"));
            failed += 1;
            continue;
        }
        let xml_path = backup_dir.join(format!("{}.xml", stubborn_task_backup_name(task)));
        // v6-K01（P0-2）：解析失败并进既有 Err 臂（「schtasks 无法执行」口径）
        let xml = match crate::engine::systembin::system_tool("schtasks")
            .map_err(std::io::Error::other)
            .and_then(|exe| {
                crate::engine::systembin::quiet_cmd_timeout(
                    exe,
                    &["/Query", "/TN", task, "/XML"],
                    crate::engine::systembin::SCHTASKS_TIMEOUT,
                )
            }) {
            Ok(o) if o.status.success() => crate::engine::systembin::decode_native_output(&o.stdout).trim().to_string(),
            Ok(o) => {
                let err = crate::engine::systembin::decode_native_output(&o.stderr).trim().chars().take(120).collect::<String>();
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
        // /Query /XML 的产物以 `<?xml` 开头；这里只做粗筛（`<` 开头 + 长度下限，挡掉
        // 「只剩 BOM/空行」这种假成功）——「声明在不在、编码对不对」由落盘前的回读自检判
        // （R5b-M01，见 verify_task_xml_backup）。
        if !xml.starts_with('<') || xml.len() < 64 {
            crate::engine::log::write_log(
                "warn",
                &format!("顽固软件治理：{task} 导出内容不像任务 XML（{} 字节），已放弃删除", xml.len()),
            );
            fail_tasks.push(format!("{task}（导出 XML 形态异常，未删除）"));
            failed += 1;
            continue;
        }
        // B2-2：备份走「私有 tmp 产出 → 判目标根 → 同卷 rename 落位」。
        // 旧实现是 `fs::write(&xml_path, …)` 直写目标 —— 备份根被换成 junction 时，
        // 「删除前唯一还原依据」就落在链接另一头，而调用方完全看不出来。
        // R5b-M01：按 XML 声明落盘（UTF-16LE+BOM）并**立即回读自检**——落一份声明与实际
        // 编码不符的凭据等于没备份，自检不过就走与写盘失败同一条「未删除」臂。
        let xml_bytes = task_xml_backup_bytes(&xml);
        if let Err(e) =
            crate::engine::backup_write::land_backup(&backup_dir, &xml_path, |stage| {
                std::fs::write(stage, &xml_bytes).map_err(|e| format!("写中转件失败: {e}"))?;
                let back = std::fs::read(stage).map_err(|e| format!("回读中转件失败: {e}"))?;
                verify_task_xml_backup(&back)
            })
        {
            crate::engine::log::write_log(
                "warn",
                &format!("顽固软件治理：{task} 备份落盘失败: {e}（{}），已放弃删除", xml_path.display()),
            );
            fail_tasks.push(format!("{task}（备份写盘失败，未删除）"));
            failed += 1;
            continue;
        }

        // 删除（只有备份已确认落盘才会走到这一行）
        // R5e-L03：删除命令的工具解析失败/超时同样不得折成「删除失败」的假象——
        // 统一返回 Err 由调用方记入 fail_tasks（旧 `unwrap_or(false)` 与「任务不存在」
        // 同形，掩盖工具链故障）。
        let deleted = match crate::engine::systembin::system_tool("schtasks")
            .map_err(std::io::Error::other)
            .and_then(|exe| {
                crate::engine::systembin::quiet_cmd_timeout(
                    exe,
                    &["/Delete", "/TN", task, "/F"],
                    crate::engine::systembin::SCHTASKS_TIMEOUT,
                )
            })
            .map(|o| o.status.success())
        {
            Ok(v) => v,
            Err(e) => {
                crate::engine::log::write_log(
                    "warn",
                    &format!("顽固软件治理：{task} 删除命令无法执行: {e}，已放弃删除"),
                );
                fail_tasks.push(format!("{task}（删除命令无法执行，未删除）"));
                failed += 1;
                continue;
            }
        };
        if deleted {
            changed_tasks.push(task.to_string());
        } else {
            fail_tasks.push(task.to_string());
            failed += 1;
        }
    }

    // 4. 设置 WPS 更新注册表
    {
        use windows::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_CURRENT_USER,
            KEY_READ, KEY_WRITE, REG_SZ,
        };
        let key_path = to_wide(r"Software\Kingsoft\Office\6.0\Common\updateinfo");
        let value_name = to_wide("UpdateMode");
        let mut hkey = HKEY_CURRENT_USER;
        let mut wrote = false;
        unsafe {
            // R5b-L01：回读要查询值内容，句柄必须带 KEY_READ（KEY_WRITE 不含 KEY_QUERY_VALUE）。
            if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(key_path.as_ptr()), Some(0), KEY_READ | KEY_WRITE, &mut hkey).is_ok() {
                let val = to_wide("close");
                let bytes: Vec<u8> = val.iter().flat_map(|&w| w.to_le_bytes()).collect();
                // U-A5-L01：写值结果不再 `let _ =` 吞掉，且写完回读确认（同函数第 3/5 步口径）。
                if RegSetValueExW(hkey, PCWSTR(value_name.as_ptr()), Some(0), REG_SZ, Some(&bytes)).is_ok() {
                    // R5b-L01：回读必须比对**内容**——旧实现只证明「值可查询」，
                    // 写入被策略/安全软件改回或写成别的值同样能过，回执却报成功。
                    wrote = matches!(reg_read_string(hkey, "UpdateMode"), Some(v) if v == "close");
                }
                let _ = RegCloseKey(hkey);
            }
        }
        if !wrote {
            crate::engine::log::write_log(
                "warn",
                "顽固软件治理：WPS 更新注册表 UpdateMode 写入或回读失败",
            );
            fail_tasks.push("WPS 更新注册表（UpdateMode 写入失败）".to_string());
            failed += 1;
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
            let run_reg_path = format!("HKCU\\{RUN_KEY}");
            // B2-2：导出写到**中转件**，落位由 land_backup 判根后 rename 完成。
            // R5b-M08（v7.2 C06）的三判口径不变：退出码成功 + 文件在 + 内容非空，
            // 只是后两判现在由 land_backup 判中转件，缺一不删值。
            let exported = match crate::engine::backup_write::land_backup(
                &run_backup_dir,
                &reg_file,
                |stage| {
                    let stage_str = stage
                        .to_str()
                        .ok_or_else(|| "备份路径无法编码".to_string())?;
                    let ok = crate::engine::systembin::system_tool("reg.exe")
                        .map_err(std::io::Error::other)
                        .and_then(|exe| {
                            crate::engine::systembin::quiet_cmd_timeout(
                                exe,
                                &["export", &run_reg_path, stage_str, "/y"],
                                crate::engine::systembin::REG_EXPORT_TIMEOUT,
                            )
                        })
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    if ok {
                        Ok(())
                    } else {
                        Err("reg.exe export 未成功".to_string())
                    }
                },
            ) {
                Ok(_) => true,
                Err(e) => {
                    crate::engine::log::write_log(
                        "warn",
                        &format!("顽固软件治理：{RUN_VALUE} 备份未做成: {e}"),
                    );
                    false
                }
            };
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

    /// 任务全名 → 备份文件名：文件夹路径要拍平成文件名（`\` 不能留在文件名里），
    /// 并追加 8 位哈希后缀（R5e-L02）。
    #[test]
    fn 任务备份名把路径拍平() {
        let a = stubborn_task_backup_name("\\WpsUpdateTask_Administrator");
        assert!(a.starts_with("WpsUpdateTask_Administrator_"), "{a}");
        assert_eq!(a.len(), "WpsUpdateTask_Administrator_".len() + 8, "{a}");

        let b = stubborn_task_backup_name(
            "\\QuarkCloudDriveUpdaterSystem\\QuarkCloudDriveUpdaterTaskSystem1.0.0.11",
        );
        assert!(
            b.starts_with("QuarkCloudDriveUpdaterSystem_QuarkCloudDriveUpdaterTaskSystem1.0.0.11_"),
            "{b}"
        );
    }

    /// R5e-L02：`\A\B` 与 `\A_B` 扁平化后不再碰撞——两个任务必须落成两个不同文件。
    /// 判红自证：把 `stubborn_task_backup_name` 恢复成裸 `replace('\\', "_")` ⇒
    /// 两个名字相同，第二个文件写盘后第一个被覆盖，断言红。
    #[test]
    fn r5e_backup_names_do_not_collide() {
        let task_a = r"\A\B";
        let task_b = r"\A_B";
        let name_a = stubborn_task_backup_name(task_a);
        let name_b = stubborn_task_backup_name(task_b);
        assert_ne!(name_a, name_b, "扁平化后不得碰撞：{name_a} == {name_b}");

        let sb = crate::testutil::Sandbox::new(&format!("r5el02-{}", std::process::id()));
        let pa = sb.join(format!("{name_a}.xml"));
        let pb = sb.join(format!("{name_b}.xml"));
        std::fs::write(&pa, "<Task/>").expect("写 A");
        std::fs::write(&pb, "<Task/>").expect("写 B");
        assert!(pa.is_file(), "任务 A 的备份文件必须存在");
        assert!(pb.is_file(), "任务 B 的备份文件必须存在");
    }

    /// R5e-L03：`system_tool` 解析失败/命令超时不得折成「任务不存在」。
    /// 只有「任务确实不存在」映射 `Ok(false)`，其余一律 `Err`。
    /// 判红自证：把 `task_exists_verdict` 恢复成 `.unwrap_or(false)` ⇒ 超时返回
    /// `Ok(false)`，本条 Err 断言红。
    #[test]
    fn r5e_system_tool_failure_is_not_false() {
        use std::io::{Error, ErrorKind};
        use std::process::Output;
        #[cfg(windows)]
        use std::os::windows::process::ExitStatusExt;

        // 退出码用 `ExitStatus::from_raw` 直接构造：不 spawn 子进程，
        // 也不引入裸 `Command::new`（后台 spawn 必须走 quiet_cmd，见 check-system-bin）。
        let status_with = |code: i32| {
            #[cfg(windows)]
            {
                std::process::ExitStatus::from_raw((code & 0xff) as u32)
            }
            #[cfg(not(windows))]
            {
                std::process::ExitStatus::from_raw((code & 0xff) << 24)
            }
        };

        // 命令超时（io::Error）→ 必须 Err，不能是 Ok(false)。
        let timeout = Err(Error::new(ErrorKind::TimedOut, "模拟超时"));
        assert!(
            task_exists_verdict(timeout).is_err(),
            "命令超时必须返回 Err，不得伪装成「任务不存在」"
        );

        // system_tool 解析失败（io::Error::other）→ 必须 Err。
        let parse_fail = Err(Error::new(ErrorKind::NotFound, "schtasks 不在系统目录"));
        assert!(task_exists_verdict(parse_fail).is_err());

        // 任务确实不存在（退出码非 0 + stderr 含 does not exist）→ Ok(false)。
        let not_found = Output {
            status: status_with(1),
            stdout: Vec::new(),
            stderr: b"ERROR: The specified task name \"X\" does not exist.\r\n".to_vec(),
        };
        assert_eq!(
            task_exists_verdict(Ok(not_found)),
            Ok(false),
            "任务确实不存在才允许映射 false"
        );

        // 非「不存在」的退出码（如权限不足）→ Err，不得伪装成不存在。
        let other_err = Output {
            status: status_with(5),
            stdout: Vec::new(),
            stderr: b"ERROR: Access is denied.\r\n".to_vec(),
        };
        assert!(task_exists_verdict(Ok(other_err)).is_err());

        // 查询成功 → Ok(true)。
        let ok = Output {
            status: status_with(0),
            stdout: b"Task: X\r\n".to_vec(),
            stderr: Vec::new(),
        };
        assert_eq!(task_exists_verdict(Ok(ok)), Ok(true));
    }

    /// R5e-L06：PID 被复用成别的进程时，镜像校验必须拒绝终止。
    /// 判红自证：把 `verify_process_image` 的镜像比对改回「镜像名取不到才拒」⇒
    /// 复用场景返回 Ok，本条红。
    #[test]
    fn r5e_terminate_uses_verified_handle() {
        // 模拟 PID 复用：期望 notepad.exe，实际镜像已是别的进程 → 拒绝。
        assert_eq!(
            verify_process_image("other.exe", "notepad.exe"),
            Err("进程 ID 已被系统复用，已拒绝结束"),
            "PID 复用成别的进程必须拒绝终止"
        );
        // 镜像名取不到 → 拒绝。
        assert_eq!(
            verify_process_image("", "notepad.exe"),
            Err("无法读取进程镜像名，已拒绝结束（防 PID 复用误杀）")
        );
        // 镜像名匹配（大小写不敏感）→ 放行。
        assert_eq!(verify_process_image("NOTEPAD.EXE", "notepad.exe"), Ok(()));
        // 调用方没给期望名 → 放行。
        assert_eq!(verify_process_image("anything.exe", ""), Ok(()));

        // 源码形态：kill_process 必须只开一次句柄，且权限同时含 TERMINATE 与 QUERY。
        let src = include_str!("process.rs");
        let body = {
            let start = src.find("pub fn kill_process").expect("找到 kill_process");
            let tail = &src[start..];
            let cut = tail.find("\nfn ").or_else(|| tail.find("\n/// ")).unwrap_or(tail.len());
            &tail[..cut]
        };
        assert_eq!(
            body.matches("OpenProcess(").count(),
            2,
            "kill_process 应只有一次打开（另一次是终止后的存活回读）：\n{body}"
        );
        assert!(
            body.contains("PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE"),
            "单次打开必须同时带查询与终止权限（R5e-L06）"
        );
    }

    /// 盘符位图不得产生未置位盘符的候选根（R5b-M19）。
    /// 判红自证：把 mask 判定改成恒 true ⇒ 未置位盘符断言红。
    #[test]
    fn 盘符位图不得产生未置位盘符的候选根() {
        let roots = roots_from_drive_mask((1 << 2) | (1 << 3)); // C: + D:
        assert_eq!(roots.len(), 4, "两个盘符应各两条根：{roots:?}");
        assert!(roots.iter().all(|r| r.starts_with("c:") || r.starts_with("d:")));
        assert!(!roots.iter().any(|r| r.starts_with("a:")), "A: 未置位却出现候选根");
        assert!(roots_from_drive_mask(0).is_empty());
    }

    /// 残留账：镜像路径读不到必须单独计数（R5b-M23）。
    /// 判红自证：把 Unreadable 分支并回 Outside ⇒ 计数断言红。
    #[test]
    fn 残留账_镜像读不到必须计数() {
        let (names, unreadable) = account_leftover(vec![
            ResidualRow::Keep("a".to_string()),
            ResidualRow::Keep("a".to_string()),
            ResidualRow::Outside,
            ResidualRow::Unreadable,
        ]);
        assert_eq!(names, vec!["a".to_string()], "同名只记一次");
        assert_eq!(unreadable, 1, "读不到必须单独计数");
    }

    // ==================== R5b-M01：任务 XML 备份的编码与声明一致 ====================

    /// 写 → 读 → 解析：落盘件必须是 UTF-16LE+BOM，且声明写的编码与字节一致。
    ///
    /// 判红自证：把 `task_xml_backup_bytes` 换回 `xml.as_bytes()`（旧实现）⇒ 本条红
    /// （无 BOM、声明写 UTF-16 而字节是 UTF-8，回读自检直接失败）。
    #[test]
    fn 任务xml备份写读解析一条龙() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\">\r\n  <RegistrationInfo><Author>WPS</Author></RegistrationInfo>\r\n  <Actions />\r\n</Task>";
        let bytes = task_xml_backup_bytes(xml);
        let sb = crate::testutil::Sandbox::new(&format!("r5bm01-{}", std::process::id()));
        let path = sb.join("WpsUpdateTask_someone.xml");
        std::fs::write(&path, &bytes).expect("写盘");
        let back = std::fs::read(&path).expect("回读");
        verify_task_xml_backup(&back).expect("落盘件必须按声明可解析");
        assert_eq!(&back[..2], &[0xFF, 0xFE], "必须带 UTF-16LE BOM");
        assert!((back.len() - 2) % 2 == 0, "UTF-16 字节数必须是偶数");
        assert!(
            std::str::from_utf8(&back).is_err(),
            "落盘件不得是 UTF-8（那正是旧实现不可解析的形态）"
        );
        let units: Vec<u16> = back[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let text = String::from_utf16(&units).expect("落盘件必须是合法 UTF-16");
        assert_eq!(declared_xml_encoding(&text), "UTF-16", "声明必须与字节编码一致");
        assert!(text.contains("<Task") && text.contains("</Task>"), "正文不得被转码弄丢");
    }

    /// 声明写别的编码 / 干脆没有 encoding 时，落盘前必须归一成 UTF-16——否则声明与字节
    /// 仍不一致，等于没修。
    #[test]
    fn 声明里的编码被归一成utf16() {
        for xml in [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Task />",
            "<?xml version='1.0' encoding='utf-16'?><Task />",
            "<?xml version=\"1.0\"?><Task />",
        ] {
            let normalized = force_utf16_declaration(xml);
            assert_eq!(declared_xml_encoding(&normalized), "UTF-16", "未归一：{normalized}");
            verify_task_xml_backup(&task_xml_backup_bytes(xml)).expect("归一后必须可解析");
        }
    }

    /// 破坏自证：声明与实际编码不一致的落盘件必须被判红（不落一份坏凭据）。
    #[test]
    fn 声明与字节不一致必须被判红() {
        // ① 旧实现：解码后的 String 直接按 UTF-8 落盘（无 BOM，声明却写 UTF-16）
        assert!(
            verify_task_xml_backup("<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task />".as_bytes()).is_err(),
            "旧 UTF-8 落盘件必须拒"
        );
        // ② 字节是 UTF-16LE+BOM，声明却写 UTF-8
        let mut wrong_decl = vec![0xFF, 0xFE];
        wrong_decl.extend(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Task />"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes()),
        );
        assert!(verify_task_xml_backup(&wrong_decl).is_err(), "声明与实际编码不一致必须拒");
        // ③ 无 BOM 的 UTF-16LE（实测 System.Xml 同样拒）
        let no_bom: Vec<u8> = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task />"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert!(verify_task_xml_backup(&no_bom).is_err(), "缺 BOM 必须拒");
    }

    // ==================== R5b-M02：任务库根由系统根派生 ====================

    /// 纯函数：任务库根必须跟着 `%SystemRoot%` 走，不能钉在 C:。
    ///
    /// 判红自证：把 `system_tasks_root_from` 改回写死 C: 路径 ⇒ 本条红。
    #[test]
    fn 任务库根跟着系统根走() {
        assert_eq!(
            system_tasks_root_from(Some(r"D:\Windows")),
            Some(std::path::PathBuf::from(r"D:\Windows\System32\Tasks"))
        );
        assert_eq!(
            system_tasks_root_from(Some("E:\\Windows\\")),
            Some(std::path::PathBuf::from(r"E:\Windows\System32\Tasks")),
            "尾部分隔符不得产生双反斜杠"
        );
        assert_eq!(
            system_tasks_root_from(Some(r"C:\Windows")),
            Some(std::path::PathBuf::from(r"C:\Windows\System32\Tasks"))
        );
        assert_eq!(system_tasks_root_from(None), None, "系统根缺失不得猜一个盘符");
        assert_eq!(system_tasks_root_from(Some("   ")), None, "空系统根不得当成合法根");
    }

    /// 枚举根是注入的：同一套目录结构放在任意盘符下（非系统盘样本）同样命中。
    ///
    /// 本机装不出 D: 系统盘，故用沙箱模拟「根不是写死的那一个」这一形态。
    #[test]
    fn 注入根下的任务样本同样命中() {
        let sb = crate::testutil::Sandbox::new(&format!("r5bm02-{}", std::process::id()));
        std::fs::create_dir_all(sb.join("Vendor")).expect("建样本目录");
        std::fs::create_dir_all(sb.join("Microsoft")).expect("建系统任务区样本");
        std::fs::write(sb.join("WpsUpdateTask_someone"), b"xml").expect("写根下样本任务");
        std::fs::write(sb.join("Vendor").join("WpsUpdateLogonTask_someone"), b"xml")
            .expect("写子目录样本任务");
        std::fs::write(sb.join("Microsoft").join("WpsUpdateTask_system"), b"xml")
            .expect("写系统任务区样本");
        let got = stubborn_enum_tasks_at(&sb);
        assert_eq!(got.root_error, None, "样本根必须可读");
        assert_eq!(
            got.tasks,
            vec![
                "\\Vendor\\WpsUpdateLogonTask_someone".to_string(),
                "\\WpsUpdateTask_someone".to_string(),
            ],
            "注入根下的目标任务必须全部命中，Microsoft 子树必须跳过：{:?}",
            got.tasks
        );
    }

    /// 「根读不到」与「确实没有任务」必须可区分（旧实现两者都是空表 + 一条日志）。
    ///
    /// 判红自证：把 `read_dir` 的 `Err` 分支改回「只记日志、不留原因」⇒ 后半段红。
    #[test]
    fn 任务库读不到必须与没有任务区分() {
        let sb = crate::testutil::Sandbox::new(&format!("r5bm02-empty-{}", std::process::id()));
        let empty = stubborn_enum_tasks_at(&sb);
        assert_eq!(empty.root_error, None, "空但可读 ≠ 读不到");
        assert!(empty.tasks.is_empty(), "确实没有任务");

        let missing = stubborn_enum_tasks_at(&sb.join("NoSuchTasksRoot"));
        assert!(missing.tasks.is_empty());
        assert!(missing.root_error.is_some(), "读不到必须带原因返回，不得伪装成空清单");
    }

    /// 取 `marker` 起点到下一个顶层项（或文档注释）之前的片段（本文件顶层项都在第 0 列）。
    ///
    /// 不用「按首个 `#[cfg(test)]` 截生产段」：本文件的生产代码被前面的单测模块切成两段，
    /// 一刀切会漏掉后半段（`stubborn_block` 与这些助手都排在第一段单测之后）。
    fn block_of<'a>(src: &'a str, marker: &str) -> &'a str {
        let start = src.find(marker).unwrap_or_else(|| panic!("找不到 {marker}"));
        let tail = &src[start + marker.len()..];
        let mut cut = tail.len();
        for anchor in ["\nfn ", "\nunsafe fn ", "\npub fn ", "\nstruct ", "\nimpl ", "\n///"] {
            if let Some(i) = tail.find(anchor) {
                cut = cut.min(i);
            }
        }
        &src[start..start + marker.len() + cut]
    }

    /// 源码形态断言：任务库根必须由系统根派生（R5b-M02）。
    ///
    /// 判红自证：把 `stubborn_enum_tasks` 的根换回写死的那一行
    /// `Path::new(<盘符>:\Windows\System32\Tasks)` ⇒ 第一条与第三条断言同时红。
    #[test]
    fn 生产段不得写死任务库根() {
        let src = include_str!("process.rs");
        let entry = block_of(src, "fn stubborn_enum_tasks()");
        assert!(entry.contains("system_tasks_root()"), "任务库根必须经系统根派生：{entry}");
        let derive = block_of(src, "fn system_tasks_root_from(");
        assert!(
            derive.contains("SYSTEM_TASKS_SUBDIR"),
            "任务库根必须是「系统根 + 相对子路径」拼出来的：{derive}"
        );
        assert!(
            !derive.to_ascii_uppercase().contains("C:"),
            "派生函数里不得出现任何盘符字面量：{derive}"
        );
        assert!(
            !src.contains("Path::new(r\"C:\\Windows"),
            "写死的任务库根不得回潮（必须走 system_tasks_root）"
        );
    }
}
