//! B2 进程控制 + 顽固软件专杀。
//!
//! 有副作用域：TerminateProcess。
//! 专杀白名单判据（`stubborn_install_roots` / `stubborn_denied_roots` / `stubborn_path_allowed`）
//! 与共享助手、选择器测试同在本文件，避免「实现搬走、测试留在原地变死码」。


// v6-K01（P0-2）后本文件只以全路径形式调 system_tool，顶部短导入已死——删掉
// （留着就是每编一次报一次 unused）。
use serde_json::{Value, json};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess};
use windows::Win32::Storage::FileSystem::GetLogicalDrives;
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
    let exe = exe_name.to_lowercase();
    let expected = expected_name.to_lowercase();
    let expected_stem = std::path::Path::new(&expected)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&expected)
        .to_lowercase();
    if exe != expected && exe != expected_stem {
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
        Ok(json!({
            "success": true,
            "message": format!("已结束进程 {name_display} (PID {pid})"),
            "stillAliveProbe": still_alive,
        }))
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



// ==================== 任务 XML 备份的落盘形态（R5b-M01） ====================

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

// ==================== 进程控制 / 残留账 / XML 备份选择器测试 ====================

// 原「顽固软件自启阻断选择器测试」的 block 专属用例随 2026-11-16 整链退役一并摘除；
// 保留的用例覆盖 kill / 盘符位图 / 残留账 / XML 备份这四条共享助手。
#[cfg(test)]
mod process_selector_tests {
    use super::*;

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
}
