//! B6 右键菜单全链：深度扫描、启停（toggle）、CLSID 图标、open-in-regedit、explorer 重启。
//!
//! 本域是 native 里最大的一块，写侧副作用真实（RegRenameKey 改 Verbs、写 LastKey、
//! 杀 explorer）。COM 类名与厂商判定表（PROTECTED_CLASSES / KNOWN_SYSTEM）是本域
//! 判据真源，改动等于改判定结果。注册表底层枚举/读取在 `registry.rs`；本文件只做业务组装。
//!
//! 2026-10-09（用户裁定 D3）：删除/备份/恢复（cm_remove/cm_backup/cm_restore）整链退役。


use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
use windows::Win32::System::LibraryLoader::{LoadLibraryExW, LOAD_LIBRARY_AS_DATAFILE};
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_CREATED_NEW_KEY, REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegRenameKey, RegSetValueExW};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
use windows::Win32::UI::WindowsAndMessaging::LoadStringW;
use super::common::*;
use super::registry::*;
// ==================== B6：右键菜单 ====================


/// 重启资源管理器（对应 cm_restart_explorer.ps1）
pub fn cm_restart_explorer() -> Result<Value, String> {
    unsafe {
        // 当前会话 ID
        let mut my_session = 0u32;
        let _ = ProcessIdToSessionId(std::process::id(), &mut my_session);

        // 枚举所有 explorer.exe 进程，匹配当前会话
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| format!("创建进程快照失败: {e}"))?;
        if snapshot == INVALID_HANDLE_VALUE {
            return Err("创建进程快照失败".into());
        }
        let mut pe = PROCESSENTRY32W::default();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut targets: Vec<(u32, String)> = Vec::new();

        if Process32FirstW(snapshot, &mut pe).is_ok() {
            loop {
                // v4-K(UTF-16 定长数组)：szExeFile 是 [u16;260]，整体 lossy 解码会把尾部
                // 填充的 NUL 一并带进字符串——eq_ignore_ascii_case 恒不命中（重启资源管理器
                // 100% 失效并谎报「没有运行中的资源管理器」）。走 common::wide_str（NUL 截断真源）。
                let name = wide_str(pe.szExeFile.as_ptr());
                if name.eq_ignore_ascii_case("explorer.exe") {
                    let pid = pe.th32ProcessID;
                    let mut session = 0u32;
                    if ProcessIdToSessionId(pid, &mut session).is_ok() && session == my_session {
                        // 取进程路径
                        let path = get_process_path(pid).unwrap_or_default();
                        targets.push((pid, path));
                    }
                }
                if Process32NextW(snapshot, &mut pe).is_err() { break; }
            }
        }
        let _ = CloseHandle(snapshot);

        if targets.is_empty() {
            return Ok(json!({
                "success": false, "killed": 0, "restarted": 0, "alive": 0,
                "message": "当前会话没有运行中的资源管理器"
            }));
        }

        // 逐个杀。`killed` 数的是**真的终止成功**的个数，不是「打算杀的个数」：
        // OpenProcess/TerminateProcess 失败原先被 `let _ =` 吞掉，界面照样报「已结束 N 个资源管理器」
        // （AGENTS §4.1 纪律①：断言要点名做到了什么）。
        let mut killed = 0usize;
        // 记录唯一路径
        let paths: Vec<String> = targets.iter().map(|(_, p)| p.clone())
            .filter(|p| !p.is_empty()).collect::<std::collections::HashSet<_>>()
            .into_iter().collect();

        for (pid, _) in &targets {
            if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, *pid) {
                if TerminateProcess(h, 1).is_ok() { killed += 1; }
                let _ = CloseHandle(h);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(700));
        // 一个都没结束成就不要往下走：旧资源管理器还在，再拉起一个 explorer 只会让
        // 「重启后才生效」的判据（下面的 alive>0）在什么都没发生的情况下报成功。
        if killed == 0 {
            return Ok(json!({
                "success": false, "killed": 0, "restarted": 0, "alive": targets.len(),
                "message": "未能结束现有资源管理器进程（权限不足或被占用），未执行重启"
            }));
        }

        // 重新启动
        let mut started = 0;
        for p in &paths {
            if std::path::Path::new(p).exists() {
                if crate::engine::systembin::quiet_cmd(p).spawn().is_ok() { started += 1; }
            }
        }
        if started == 0 {
            let fallback = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            let fp = format!("{fallback}\\explorer.exe");
            if crate::engine::systembin::quiet_cmd(&fp).spawn().is_ok() { started = 1; }
        }
        std::thread::sleep(std::time::Duration::from_millis(900));

        // 检查存活
        let mut alive = 0;
        let snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if let Ok(snap2) = snap2 {
            let mut pe2 = PROCESSENTRY32W::default();
            pe2.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap2, &mut pe2).is_ok() {
                loop {
                    let name = wide_str(pe2.szExeFile.as_ptr());
                    if name.eq_ignore_ascii_case("explorer.exe") {
                        let mut session = 0u32;
                        if ProcessIdToSessionId(pe2.th32ProcessID, &mut session).is_ok() && session == my_session {
                            alive += 1;
                        }
                    }
                    if Process32NextW(snap2, &mut pe2).is_err() { break; }
                }
            }
            let _ = CloseHandle(snap2);
        }

        Ok(json!({
            "success": alive > 0,
            "killed": killed,
            "restarted": started,
            "alive": alive,
            "message": if alive > 0 { "已重启资源管理器" } else { "资源管理器未能自动拉起，请手动启动 explorer.exe" },
        }))
    }
}

/// 取进程完整路径（QueryFullProcessImageNameW）
unsafe fn get_process_path(pid: u32) -> Option<String> {
    use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_NAME_FORMAT};
    let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    let r = QueryFullProcessImageNameW(h, PROCESS_NAME_FORMAT(0), windows::core::PWSTR(buf.as_mut_ptr()), &mut len);
    let _ = CloseHandle(h);
    if r.is_ok() { Some(String::from_utf16_lossy(&buf[..len as usize])) } else { None }
}
// ==================== B6 cm_scan：右键菜单深度扫描 ====================




/// 检查注册表值是否存在
unsafe fn reg_value_exists(hk: HKEY, name: &str) -> bool {
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_ok()
}

/// 解析 @dll,-id 形式的间接资源串
unsafe fn resolve_resource_string(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('@') { return None; }
    // 格式：@"C:\path\to.dll",-12345 或 @shell32.dll,-30345
    let rest = &trimmed[1..];
    let comma = rest.find(',')?;
    let dll_part = rest[..comma].trim().trim_matches('"').trim().to_string();
    let id_part = rest[comma+1..].trim().trim_start_matches('-');
    let id: i32 = id_part.parse().ok()?;
    let dll_path = if dll_path_needs_system(&dll_part) {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        format!("{windir}\\System32\\{dll_part}")
    } else {
        let p = expand_env(&dll_part);
        // 审查 v4-K01（2026-10-09）：HKCU 下的 MUIVerb / LocalizedString / FriendlyAppName
        // 对当前用户可写 —— 绝对路径分支此前只判 exists() 就 LoadLibraryW，等于给出
        // 「medium 进程写注册表 → Trim（可提权）进程加载任意 DLL」的代码执行原语
        // （DllMain 会被执行）。资源串的绝对路径只放行系统 DLL 的规范落点
        // （System32 / SysWOW64 且非链接），其余一律 None ⇒ direct_string 回退空串
        // ⇒ 用键名当标签（功能降级，不丢）。
        if !resource_dll_allowed(&p) { return None; }
        p
    };
    if !std::path::Path::new(&dll_path).exists() { return None; }
    let dll_w = to_wide(&dll_path);
    // v4-K01：LOAD_LIBRARY_AS_DATAFILE = 只把 DLL 映射为数据文件读字符串资源，
    // **不执行 DllMain** —— 这是读资源的正确姿势（LoadStringW 对 datafile 句柄照常可用）。
    let Ok(hmod) = LoadLibraryExW(PCWSTR(dll_w.as_ptr()), Some(HANDLE::default()), LOAD_LIBRARY_AS_DATAFILE) else { return None; };
    if hmod == HMODULE::default() { return None; }
    let mut buf = [0u16; 1024];
    let len = LoadStringW(Some(windows::Win32::Foundation::HINSTANCE(hmod.0)), id as u32, windows::core::PWSTR(buf.as_mut_ptr()), buf.len() as i32);
    let _ = FreeLibrary(hmod);
    if len <= 0 { return None; }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

fn dll_path_needs_system(dll: &str) -> bool {
    !dll.contains('\\') && !dll.contains('/')
}

/// v4-K01：`@<绝对路径 dll>,<id>` 的落点白名单 —— 只放行 `%SystemRoot%\System32` 与
/// `%SystemRoot%\SysWOW64` 之下（报告口径：SystemRoot 根与其可写子目录如 Temp 均不放行）。
/// 判据三条任一不满足即拒：前缀在允许根之下（带分隔符，`…\System32x` 不算子树）、
/// 路径不含 `..` 组件（防 `System32\..\Temp\x.dll` 折叠穿越）、目标非重解析点；
/// 元数据读不到也拒（回退 = 用键名当标签，不损失功能面）。
fn resource_dll_allowed(p: &str) -> bool {
    let n = p.trim().replace('/', "\\");
    if n.is_empty() || n.contains("..") {
        return false;
    }
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let windir = windir.trim_end_matches('\\').replace('/', "\\").to_ascii_lowercase();
    if windir.is_empty() {
        return false;
    }
    let low = n.to_ascii_lowercase();
    let allowed = [format!("{windir}\\system32\\"), format!("{windir}\\syswow64\\")];
    if !allowed.iter().any(|r| low.starts_with(r)) {
        return false;
    }
    match std::fs::symlink_metadata(&n) {
        Ok(md) => !crate::engine::protect::is_reparse(&md),
        Err(_) => false,
    }
}

/// 直接字符串：@ 引用串优先走资源解析，解析失败回退空串
unsafe fn direct_string(raw: &str) -> String {
    if raw.is_empty() { return String::new(); }
    let v = raw.trim();
    if v.starts_with('@') {
        if let Some(resolved) = resolve_resource_string(v) { return resolved; }
        return String::new();
    }
    v.to_string()
}

/// GUID 格式校验
fn is_guid(s: &str) -> bool {
    let s = s.trim();
    if s.len() != 38 { return false; }
    if !s.starts_with('{') || !s.ends_with('}') { return false; }
    let inner = &s[1..37];
    let parts: Vec<&str> = inner.split('-').collect();
    if parts.len() != 5 { return false; }
    let lens = [8usize, 4, 4, 4, 12];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != lens[i] || !p.chars().all(|c| c.is_ascii_hexdigit()) { return false; }
    }
    true
}

/// 清洗字符串：移除控制字符、孤立代理、非字符
fn clean_str(s: &str) -> String {
    s.chars().filter(|&c| {
        let cp = c as u32;
        cp >= 0x20 && cp != 0x7f && !(0xD800..=0xDFFF).contains(&cp) && cp != 0xFFFE && cp != 0xFFFF
    }).collect()
}

fn swap_last_segment(path: &str, new_leaf: &str) -> String {
    match path.rfind('\\') {
        Some(pos) => format!("{}{}", &path[..=pos], new_leaf),
        None => new_leaf.to_string(),
    }
}

/// 动词隐藏判据（四值模型）
unsafe fn verb_hidden(hk: HKEY) -> bool {
    for vn in ["LegacyDisable", "Blocked", "ProgrammaticAccessOnly"] {
        if reg_value_exists(hk, vn) { return true; }
    }
    if let Some(v) = reg_read_dword_val(hk, "HideBasedOnVelocityId") {
        if v == 0x639bc8 { return true; }
    }
    if let Some(v) = reg_read_dword_val(hk, "CommandFlags") {
        if (v % 16) >= 8 { return true; }
    }
    false
}

/// 受保护 CLSID 列表
const PROTECTED_CLASSES: &[&str] = &[
    "{20D04FE0-3AEA-1069-A2D8-08002B30309D}",
    "{450D8FBA-AD25-11D0-98A8-0800361B1103}",
    "{208D2C60-3AEA-1069-A2D2-08002B30309D}",
    "{1F4DE370-D627-11D1-BA4F-00A0C91EEDBA}",
    "{59031A47-3F72-35A7-89EC-6E8B9A8A5B5E}",
    "{59BE1D4E-E3A4-4D8A-91A3-69D69F66A4AC}",
    "{645FF040-5081-101B-9F08-00AA002F954E}",
];

/// 已知系统动词列表（简化版）
const KNOWN_SYSTEM: &[&str] = &[
    "Open", "Explore", "open", "explore", "find", "printto", "Properties",
    "RunAs", "RunAsUser", "New", "Delete", "Cut", "Copy", "Paste", "Rename",
    "edit", "print", "play", "Share", "Preview", "OpenWith", "Compatibility",
    "PinToStart", "PinToTaskbar", "PreviousVersions", "ScanWithWindowsDefender",
    "EmptyRecycleBin", "Restore", "Personalize", "Display",
];

/// 第三方判定
///
/// `company` 传的是「CLSID 键的 Company 值，缺省时退回 PE 的 CompanyName」（见 cm_scan 的
/// P1-9 注释）—— 只认注册表那一个值会把大批条目当成"没有厂商信息"。
fn is_third_party(name: &str, company: &str, source: &str, file_path: &str) -> bool {
    let cl = company.to_lowercase();
    if cl.contains("microsoft") || cl.contains("windows corporation") { return false; }
    let fl = file_path.to_lowercase();
    // 「文件在 Windows 目录下」只是**弱**依据：DriverStore\FileRepository 是第三方驱动包
    // 的落点（NVIDIA 的壳扩展 dll 就在那），WinSxS 同理混装 —— 拿它当"系统原生"会把
    // 最该标第三方的那批压成绿色。这两个存储目录不算。
    let in_driver_store = fl.contains(r"\driverstore\filerepository\") || fl.contains(r"\winsxs\");
    if company.is_empty() && fl.starts_with(r"c:\windows") && !in_driver_store { return false; }
    if KNOWN_SYSTEM.contains(&name) { return false; }
    if source == "shell" {
        let nl = name.to_lowercase();
        if nl.contains("windows") || nl.contains("system32") || nl.contains("shell32") { return false; }
    }
    true
}

/// CLSID 信息（名称/厂商/文件路径）
struct ClsidInfo { name: String, company: String, file_path: String }

// ==================== 软件归属（右键管理「按软件分组」的地基） ====================
//
// 为什么必须新加这一层，而不是直接拿现成的 `company` 分组：本机 172 条候选里 `company`
// 只有 27 条有值，且那 27 条全是 `Microsoft Corporation`（它来自 CLSID 键的 `Company` 值，
// 绝大多数 shell/verb/Win+X 条目根本没有这个键）。按它分组 = 84% 落进「未识别」，
// 用户要的「一个软件下有哪些位置」根本不成立。真正的归属只能从**文件本体**读。
//
// `startup.rs` 当年留的就是这个坑（注释原文：「简化实现：不实现 GetFileVersionInfoW，留空」），
// 本模块把它补上并只用于展示分组——分组不参与任何删除/禁用判据，判据仍逐条按 item 自己算。

/// 一个 PE 文件能拿到的三段版本信息。三段都要取：不同厂商只填其中一两段是常态
/// （很多壳扩展只有 `FileDescription`），所以「先用哪段」本身就是判据，见 [`owner_of`]。
#[derive(Clone, Default, Debug)]
pub struct PeInfo {
    pub product: String,
    pub company: String,
    pub description: String,
}

/// 从命令行里取可执行文件名/路径。注册表里三种写法都常见，且**引号会套在裸名上**：
/// `"C:\...\x.exe" "%1"`、目录含空格的裸路径 `C:\Program Files\Git\git-bash.exe --cd`、
/// 裸名 `cmd.exe /s /k pushd "%V"` 与带引号的裸名 `"cmd.exe" /s /k pushd "%V"`
/// （最后这两种是未识别里的大头）。
///
/// **纯函数**：不碰文件系统，所以能在没装对应软件的环境里测（AGENTS §4.1 纪律①）。
/// 取不到就返回 `None` 而不是猜 —— `"%1" %*` 这种压根没有 exe 的条目，硬猜一个名字出来
/// 会把「打开」这种系统 verb 算成某个真实软件，那比不分组更糟。
pub fn exe_from_command(cmd: &str) -> Option<String> {
    let s = cmd.trim();
    if s.is_empty() {
        return None;
    }
    // 第一步只干一件事：取出「命令名」候选。带引号取引号内；不带引号就逐段累加，
    // 每加一段先看整体像不像路径 —— 像就立刻收口。晚一步判断会把参数拼进路径
    // （`C:\...\bdeunlock.exe %1` 与 `"cmd.exe" /s /k ...` 早先都因此整条落进未识别）。
    let cand = if let Some(rest) = s.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").trim().to_string()
    } else {
        let mut acc = String::new();
        let mut done: Option<String> = None;
        for tok in s.split_whitespace() {
            if is_path_like(&acc) {
                done = Some(std::mem::take(&mut acc));
                break;
            }
            if !acc.is_empty() {
                acc.push(' ');
            }
            acc.push_str(tok);
        }
        done.unwrap_or(acc)
    };
    if is_path_like(&cand) {
        return Some(cand);
    }
    // 第二步：裸名。判断必须落在**第一个 token** 上，不能用第一步拼过参数的整串
    // （`cmd.exe /s /k pushd "%V"` 整串里有 `%`，按整串判会被当参数丢掉）。
    let first = if s.starts_with('"') {
        cand.clone()
    } else {
        s.split_whitespace().next().unwrap_or("").to_string()
    };
    if first.is_empty() || first.contains('\\') || first.contains('/') || first.contains('%') {
        return None;
    }
    if first.starts_with('-') || first.contains('"') {
        return None;
    }
    let bare_ok = match first.rsplit_once('.') {
        Some((stem, ext)) => !stem.is_empty() && matches!(ext.to_ascii_lowercase().as_str(), "exe" | "com"),
        None => !first.contains('-'),
    };
    bare_ok.then_some(first)
}

/// 只判形状：盘符开头 + 有反斜杠 + 扩展名是 exe/com/dll。
fn is_path_like(p: &str) -> bool {
    let b = p.as_bytes();
    p.len() > 4 && b.len() > 3 && b[1] == b':' && matches!(b[0], b'A'..=b'Z' | b'a'..=b'z')
        && p.contains('\\')
        && {
            let name = p.rsplit('\\').next().unwrap_or("");
            let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
            matches!(ext.as_str(), "exe" | "com" | "dll")
        }
}

/// [`resolve_exe_for_owner`] 的带缓存版：同一次扫描里同一个裸名只查一遍
/// （App Paths 是三次注册表打开 + PATH 是几十次 stat，172 条候选不做缓存会明显拖慢扫描）。
/// 缓存键取小写：Windows 文件名大小写不敏感。解析不到的名字也要缓存（存 `None`），
/// 否则每条未识别项都会把整条 PATH 重扫一遍。
fn resolve_cached(
    cache: &mut std::collections::HashMap<String, Option<String>>,
    raw: &str,
) -> Option<String> {
    cache
        .entry(raw.to_ascii_lowercase())
        .or_insert_with_key(|k| resolve_exe_for_owner(k))
        .clone()
}

/// 把命令行里取到的 exe 名解析成**真实存在的路径**，好去读 PE。
///
/// 为什么必须这一级：注册表里大量 shell 命令写的是裸名 —— `cmd.exe /s /k pushd "%V"`、
/// `powershell.exe -noexit ...`、`wps.exe`。只按形状判会全部落空：真机实测未识别 50/171
/// 里绝大多数就是这一类。解析顺序（都是只读）：
/// ① 本来就是存在的路径 ⇒ 原样；② `App Paths`（先 HKCU 再 HKLM，与系统自己的查找顺序一致）；
/// ③ `%SystemRoot%\System32\<名>`。三处都不中 ⇒ `None` —— **不猜路径**，
/// 归属就退到未识别，也不能把「同名的某个文件」当结论。
fn resolve_exe_for_owner(raw: &str) -> Option<String> {
    let name = raw.trim().trim_matches('"').to_string();
    if name.is_empty() {
        return None;
    }
    if std::path::Path::new(&name).exists() {
        return Some(name);
    }
    // 已经是个带目录的路径但不存在（卸载遗留）：不再去 App Paths 碰运气，交给上层退判据
    if name.contains('\\') {
        return None;
    }
    // 注册表里 `notepad %1` 这种连扩展名都不写的确实存在（系统就这么登记的），
    // 所以每个候选名都试两次：原名与补 `.exe`。两次都不中才算解析不到。
    let mut cands: Vec<String> = vec![name.clone()];
    if !name.contains('.') {
        cands.push(format!("{name}.exe"));
    }
    for cand in &cands {
        let sub = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{cand}");
        for hive in [
            windows::Win32::System::Registry::HKEY_CURRENT_USER,
            windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
        ] {
            if let Some(v) = crate::engine::native::read_reg_string(hive, &sub, "") {
                let p = v.trim().trim_matches('"').to_string();
                if !p.is_empty() && std::path::Path::new(&p).exists() {
                    return Some(p);
                }
            }
        }
        let root = std::env::var("SystemRoot").unwrap_or_default();
        if !root.is_empty() {
            let p = format!(r"{root}\System32\{cand}");
            if std::path::Path::new(&p).exists() {
                return Some(p);
            }
        }
        // ④ PATH 里逐目录找：`powershell.exe` 这类既不在 System32 根下、也没登记 App Paths，
        // 但系统解析裸名时走的就是 PATH —— 不补这一级，「在此处打开 PowerShell 窗口」永远未识别。
        // 只对**写了 .exe 扩展名**的裸名扫 PATH：打开方式列表里的 command 常是 verb 串（open / edit），
        // 而 npm、Git 之流会在 PATH 里放无扩展名垫片，拿 verb 去撞会撞出一个假归属。
        if cand.to_ascii_lowercase().ends_with(".exe") {
            if let Some(path) = std::env::var_os("PATH") {
                for dir in std::env::split_paths(&path) {
                    let p = dir.join(cand);
                    if p.is_file() {
                        return Some(p.to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    None
}

/// 算软件归属：`(标签, 判据来源)`。标签为空 = **拿不准就不分组**，
/// 前端把它归进「未识别厂商 / 系统组件」组并如实标注，不硬猜一个名字糊上去。
///
/// 优先级就是判据本身，改动要连带改单测：
/// 1. `system`：文件在系统根目录下 **且** 厂商/产品名指向微软 —— 这两条同时成立才敢并组，
///    否则 `C:\Windows\Temp` 下某个第三方 dll 会被错并进「Windows 系统组件」；
/// 2. `pe-product`：PE 的 `ProductName`，最贴近用户心里的「那个软件」；
/// 3. `pe-desc`：`FileDescription`，常是「WinRAR Shell Extension」这种比厂商更具体的名字；
/// 4. `registry`：CLSID 键的 `Company` 值（只有厂商名，退而求其次）；
/// 5. `pe-company`：PE 的 `CompanyName`；
/// 6. `dir`：安装目录名兜底（`C:\Program Files\WinRAR\...` → `WinRAR`）—— 这是**推断**，
///    所以来源要一路带到界面，组头上写「按安装目录识别」，不装作是权威结论。
pub fn owner_of(pe: &PeInfo, reg_company: &str, file_path: &str, system_root: &str) -> (String, String) {
    let f = file_path.to_ascii_lowercase();
    let root = system_root.trim_end_matches('\\').to_ascii_lowercase();
    let has_file = !f.is_empty();
    // 带分隔符比：`C:\Windows.old\...` 不是系统目录，不能因为前缀相同就被并进「Windows 系统组件」
    let in_system_root = !root.is_empty() && has_file && f.starts_with(&format!("{root}\\"));
    let ms = |s: &str| {
        let l = s.to_ascii_lowercase();
        l.contains("microsoft") || l.contains("windows corporation")
    };
    // 审计 P1-6：系统组件有两种形态，都必须落到 `system`，否则它们会以「Microsoft Corporation」
    // 之名按第三方权重排进第一屏，还把组头标成"按注册表厂商"：
    // ① 文件确实在系统根下且厂商是微软；
    // ② **压根没有文件线索**（Win+X、新建菜单、系统发送到那 100 多条：扫描器给它们硬编了
    //    company，file_path 与 command 都是空的）—— 这类就是 Windows 自己的菜单项。
    // 有文件且文件不在系统根下（Office / Edge 之类）不走这里，交给 PE 判产品名。
    if (ms(&pe.company) || ms(&pe.product) || ms(reg_company)) && (!has_file || in_system_root) {
        return ("Windows 系统组件".to_string(), "system".to_string());
    }
    for (label, src) in [
        (pe.product.as_str(), "pe-product"),
        (pe.description.as_str(), "pe-desc"),
        (reg_company, "registry"),
        (pe.company.as_str(), "pe-company"),
    ] {
        let t = label.trim();
        if !t.is_empty() {
            return (t.to_string(), src.to_string());
        }
    }
    if let Some(dir) = install_dir_name(file_path) {
        return (dir, "dir".to_string());
    }
    (String::new(), String::new())
}

/// 从文件路径里取「安装目录名」：往上找到 `Program Files` / `Program Files (x86)` /
/// `ProgramData` 之后的那一段（那才是产品目录），没有这些锚点时退回直接父目录名。
/// 纯函数，形状不对一律 `None`。
///
/// 三条「宁可不分组」的边界：① 文件直接躺在容器目录里（`C:\Program Files\x.dll`）时，
/// 容器名当组名毫无意义；② 父目录本身就是系统/容器目录（`System32`、`WindowsApps`）——
/// 那类条目该走 `system` 判据或落进未识别，不该被目录名兜底糊成一个"软件"；
/// ③ 锚点下面套的还是容器（`Program Files\WindowsApps\...`）同样不算产品名。
pub fn install_dir_name(path: &str) -> Option<String> {
    /// 容器锚点：它后面的那一段才是产品目录
    const ANCHORS: &[&str] = &["program files", "program files (x86)", "program files (arm64)", "programdata"];
    /// 出现在结果里一律判为「这不是产品名」的目录（锚点本身 + 系统/包容器目录）
    const NOT_A_PRODUCT: &[&str] = &[
        "program files", "program files (x86)", "program files (arm64)", "programdata",
        "windows", "system32", "syswow64", "winnt", "windowsapps", "common files",
    ];
    let is_in = |list: &[&str], s: &str| list.iter().any(|g| s.eq_ignore_ascii_case(g));
    if path.is_empty() {
        return None;
    }
    let parts: Vec<&str> = path.split('\\').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return None;
    }
    for (i, seg) in parts.iter().enumerate() {
        // i+1 必须是产品目录：i+1 == len-1 说明那一段已经是文件名本身 ⇒ 文件躺在容器里
        if is_in(ANCHORS, seg) && i + 1 < parts.len() - 1 && !is_in(NOT_A_PRODUCT, parts[i + 1]) {
            return Some(parts[i + 1].to_string());
        }
    }
    let parent = parts[parts.len() - 2];
    if parent.is_empty() || is_in(NOT_A_PRODUCT, parent) {
        return None;
    }
    Some(parent.to_string())
}

/// 读 PE 的 StringFileInfo 三段。走 `version.dll` 的 `GetFileVersionInfo*` / `VerQueryValueW`，
/// 它们在 `windows` crate 里归 `Win32_Storage_FileSystem`（本仓已开该 feature，不新增依赖）。
///
/// 语言/代码页对必须从 `\\VarFileInfo\\Translation` 现读再拼成 8 位十六进制：
/// 硬写 `000004b0`（中性英文）在只有本地化资源块的文件上会取到空，
/// 于是国产壳扩展全被判成「未识别」。
/// 失败（文件不存在/无版本资源/非 PE）一律回空 `PeInfo` —— 归属是展示层信息，
/// 读不到就退回下一级判据，绝不为它报错打断整轮扫描。
unsafe fn pe_info_of(path: &str) -> PeInfo {
    use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
    let mut info = PeInfo::default();
    if path.trim().is_empty() || !std::path::Path::new(path).exists() {
        return info;
    }
    let pw = to_wide(path);
    let size = GetFileVersionInfoSizeW(PCWSTR(pw.as_ptr()), None);
    if size == 0 || size > 1 << 20 {
        return info;
    }
    let mut buf = vec![0u8; size as usize];
    if GetFileVersionInfoW(PCWSTR(pw.as_ptr()), None, size, buf.as_mut_ptr() as *mut core::ffi::c_void).is_err() {
        return info;
    }
    let base = buf.as_ptr() as *const core::ffi::c_void;
    let read_str = |key: &str| -> Option<String> {
        let kw = to_wide(key);
        let mut val: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        if !VerQueryValueW(base, PCWSTR(kw.as_ptr()), &mut val, &mut len).as_bool() || val.is_null() {
            return None;
        }
        let units = std::slice::from_raw_parts(val as *const u16, len as usize);
        // 只取**第一个 NUL 之前**的内容：VerQueryValue 给的长度含结尾 NUL，而版本资源里
        // 常见「值后面紧跟下一段数据的字节」，按尾部裁会把这些垃圾读进标签
        // （真机实测见过 `NVIDIA App<Product` 这种串味，2026-10-05）。
        let s = String::from_utf16_lossy(units)
            .split('\0')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        (!s.is_empty()).then_some(s)
    };
    // 先拿 Translation 对，再按对去取三段字符串
    let mut tp: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut tl = 0u32;
    let sub = to_wide(r"\VarFileInfo\Translation");
    if !VerQueryValueW(base, PCWSTR(sub.as_ptr()), &mut tp, &mut tl).as_bool() || tp.is_null() {
        return info;
    }
    let words = std::slice::from_raw_parts(tp as *const u16, (tl as usize) / 2);
    // chunks_exact：长度不是 4 的倍数（畸形资源）时丢掉尾巴，不能让 pair[1] 越界 panic ——
    // 这条扫描跑在 spawn_blocking 里，panic 会把整轮扫描变成「扫描线程未返回」
    for pair in words.chunks_exact(2) {
        let (lang, cp) = (pair[0], pair[1]);
        let got = [
            read_str(&format!(r"\StringFileInfo\{lang:04x}{cp:04x}\ProductName")),
            read_str(&format!(r"\StringFileInfo\{lang:04x}{cp:04x}\CompanyName")),
            read_str(&format!(r"\StringFileInfo\{lang:04x}{cp:04x}\FileDescription")),
        ];
        if got.iter().any(|g| g.is_some()) {
            info.product = got[0].clone().unwrap_or_default();
            info.company = got[1].clone().unwrap_or_default();
            info.description = got[2].clone().unwrap_or_default();
            break;
        }
    }
    info
}

/// 同一次扫描里同一个文件只读一次 PE（172 条候选去重后通常只剩几十个文件）。
/// 缓存按小写路径键：Windows 路径大小写不敏感，`...\WinRAR\` 与 `...\winrar\` 必须命中同一条。
fn pe_info_cached(path: &str, cache: &mut std::collections::HashMap<String, PeInfo>) -> PeInfo {
    let key = path.to_ascii_lowercase();
    if key.is_empty() {
        return PeInfo::default();
    }
    if let Some(hit) = cache.get(&key) {
        return hit.clone();
    }
    let got = unsafe { pe_info_of(path) };
    cache.insert(key, got.clone());
    got
}

/// 解析 CLSID 信息（简化版：只读注册表，不做文件版本信息）
unsafe fn get_clsid_info(guid: &str, clsid_views: &[(HKEY, &str)]) -> ClsidInfo {
    let mut info = ClsidInfo { name: String::new(), company: String::new(), file_path: String::new() };
    if !is_guid(guid) { return info; }
    for (hive, base) in clsid_views {
        let sub = format!("{base}\\{guid}");
        let sk = to_wide(&sub);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(*hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { continue; }
        // 名称：LocalizedString > InfoTip > 默认值
        for vn in ["LocalizedString", "InfoTip", ""] {
            if let Some(raw) = reg_read_string(hk, vn) {
                let resolved = direct_string(&raw);
                if !resolved.is_empty() { info.name = resolved; break; }
            }
        }
        // 厂商
        if let Some(c) = reg_read_string(hk, "Company") {
            if !c.is_empty() { info.company = c; }
        }
        // 文件路径：InprocServer32 > LocalServer32
        for sub2 in ["InprocServer32", "LocalServer32"] {
            let s2 = format!("{sub}\\{sub2}");
            let sk2 = to_wide(&s2);
            let mut hk2 = HKEY::default();
            if RegOpenKeyExW(*hive, PCWSTR(sk2.as_ptr()), Some(0), KEY_READ, &mut hk2).is_err() { continue; }
            let mut candidate = String::new();
            if let Some(cb) = reg_read_string(hk2, "CodeBase") {
                candidate = cb.replace("file:///", "").replace('/', "\\");
            }
            if candidate.is_empty() {
                if let Some(def) = reg_read_string(hk2, "") {
                    candidate = def.trim().trim_matches('"').to_string();
                }
            }
            let _ = RegCloseKey(hk2);
            if !candidate.is_empty() && std::path::Path::new(&candidate).exists() {
                info.file_path = candidate;
                break;
            }
        }
        let _ = RegCloseKey(hk);
        if !info.name.is_empty() || !info.company.is_empty() || !info.file_path.is_empty() { break; }
    }
    info
}

/// 扫描结果项
struct CmItem {
    name: String, clsid: String, reg_path: String, native_reg_path: String,
    company: String, location: String, category: String, source: String,
    file_path: String, command: String, enabled: bool,
    confirm_required: bool, confirm_reason: String, unknown_convention: bool,
    blocked_by: String, target: String, orphan: bool, orphan_reason: String,
}

/// HKCR -> 真实 hive 路径（HKCU 优先，否则 HKLM）
unsafe fn resolve_native_reg_path(std_path: &str) -> String {
    if !std_path.starts_with("HKEY_CLASSES_ROOT") { return std_path.to_string(); }
    let rest = std_path.trim_start_matches("HKEY_CLASSES_ROOT").trim_start_matches('\\');
    let cu = format!("HKEY_CURRENT_USER\\Software\\Classes\\{rest}");
    // 检查 HKCU 是否存在
    let cu_sub = format!("Software\\Classes\\{rest}");
    let sk = to_wide(&cu_sub);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
        let _ = RegCloseKey(hk);
        return cu;
    }
    format!("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\{rest}")
}

/// 右键菜单扫描（对应 cm_scan.ps1，S3 简化版）
///
/// 覆盖：Shell 项 + ShellEx 项（13 场景 × 3 视图）、发送到、Win+X、
/// 新建菜单、打开方式。UWP/PackagedCom 暂未实现（S2 完善）。
pub fn cm_scan() -> Result<Vec<Value>, String> {
    unsafe {
        // ---- Blocked GUID 表 ----
        let mut blocked: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for (hive, sub, scope) in [
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked", "machine"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked", "user"),
        ] {
            let sk = to_wide(sub);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { continue; }
            for vn in reg_enum_values(hk) {
                if is_guid(&vn) {
                    blocked.insert(vn.to_uppercase(), scope.to_string());
                }
            }
            let _ = RegCloseKey(hk);
        }

        // CLSID 视图
        let clsid_views: Vec<(HKEY, String)> = vec![
            (HKEY_CURRENT_USER, r"Software\Classes\CLSID".to_string()),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\CLSID".to_string()),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\Wow6432Node\CLSID".to_string()),
        ];
        let clsid_views_ref: Vec<(HKEY, &str)> = clsid_views.iter().map(|(h, s)| (*h, s.as_str())).collect();

        // 场景注册表视图根
        let scene_views: Vec<(HKEY, String)> = vec![
            (HKEY_CURRENT_USER, r"Software\Classes".to_string()),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes".to_string()),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\Wow6432Node".to_string()),
        ];

        let mut items: Vec<CmItem> = Vec::new();
        let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

        // ---- 场景扫描 ----
        let scenes: &[(&str, &[&str])] = &[
            ("文件", &["*", "AllFilesystemObjects"]),
            ("EXE文件", &["exefile", r"SystemFileAssociations\.exe"]),
            ("LNK文件", &["lnkfile", r"SystemFileAssociations\.lnk"]),
            ("目录", &["Directory"]),
            ("文件夹", &["Folder"]),
            ("驱动器", &["Drive"]),
            ("目录背景", &[r"Directory\Background"]),
            ("桌面背景", &["DesktopBackground"]),
            ("回收站", &[r"CLSID\{645FF040-5081-101B-9F08-00AA002F954E}", "RecycleBinFolder"]),
            ("此电脑", &[r"CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"]),
            ("库", &["LibraryFolder", r"LibraryFolder\Background", "UserLibraryFolder"]),
        ];

        for (category, suffixes) in scenes {
            for suffix in *suffixes {
                for (hive, base) in &scene_views {
                    let scene_path = format!("{base}\\{suffix}");
                    // shell 子键
                    scan_shell_items(&scene_path, *hive, category, &clsid_views_ref, &blocked, &mut items, &mut seen_keys);
                    // ShellEx\ContextMenuHandlers
                    scan_shellex_handlers(&scene_path, *hive, "ContextMenuHandlers", category, &clsid_views_ref, &blocked, &mut items, &mut seen_keys);
                    // ShellEx\-ContextMenuHandlers（整组禁用）
                    scan_shellex_handlers(&scene_path, *hive, "-ContextMenuHandlers", category, &clsid_views_ref, &blocked, &mut items, &mut seen_keys);
                }
            }
        }

        // ---- 发送到 ----
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let programdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        for sendto_dir in [format!("{appdata}\\Microsoft\\Windows\\SendTo"), format!("{programdata}\\Microsoft\\Windows\\SendTo")] {
            let Ok(entries) = std::fs::read_dir(&sendto_dir) else { continue; };
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.eq_ignore_ascii_case("desktop.ini") { continue; }
                let full = entry.path().to_string_lossy().to_string();
                let ext = entry.path().extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                let company = if [".desklink", ".mapimail", ".zfsendtotarget", ".mydocs"].contains(&ext.as_str()) {
                    "Microsoft Corporation".to_string()
                } else { String::new() };
                let name = entry.path().file_stem().and_then(|s| s.to_str()).unwrap_or(&fname).to_string();
                // 审计 P2-18：「发送到」的启停是用**隐藏属性**表达的（见 toggle_cm_item 的
                // filesystem 分支），而这里原先把 enabled 写死成 true —— 已被隐藏的项目在界面上
                // 显示为「启用」，取消勾选时报「已禁用」再勾回来又显示启用，用户看不出任何变化。
                // 状态必须由同一条判据读出来，否则显示与写入不是同一件事。
                use windows::Win32::Storage::FileSystem::{GetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};
                let aw = to_wide(&full);
                let attrs = GetFileAttributesW(PCWSTR(aw.as_ptr()));
                let hidden = attrs != 0xFFFFFFFF && attrs & FILE_ATTRIBUTE_HIDDEN.0 != 0;
                items.push(CmItem {
                    name, clsid: String::new(), reg_path: full.clone(), native_reg_path: full.clone(),
                    company, location: sendto_dir.clone(), category: "发送到".to_string(),
                    source: "filesystem".to_string(), file_path: String::new(), command: String::new(),
                    enabled: !hidden, confirm_required: false, confirm_reason: String::new(),
                    unknown_convention: false, blocked_by: String::new(), target: String::new(),
                    orphan: false, orphan_reason: String::new(),
                });
            }
        }

        // ---- Win+X ----
        let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        for group in ["Group1", "Group2", "Group3"] {
            let gdir = format!("{localappdata}\\Microsoft\\Windows\\WinX\\{group}");
            let Ok(entries) = std::fs::read_dir(&gdir) else { continue; };
            for entry in entries.flatten() {
                if entry.path().is_dir() { continue; }
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.eq_ignore_ascii_case("desktop.ini") { continue; }
                let full = entry.path().to_string_lossy().to_string();
                let ext = entry.path().extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                let is_off = ext == "disabled";
                let label_raw = entry.path().file_stem().and_then(|s| s.to_str()).unwrap_or(&fname).to_string();
                let label = if is_off { label_raw.trim_end_matches(".lnk").to_string() } else { label_raw };
                if label.is_empty() { continue; }
                items.push(CmItem {
                    name: label, clsid: String::new(), reg_path: full.clone(), native_reg_path: full.clone(),
                    company: "Microsoft Corporation".to_string(), location: gdir.clone(),
                    category: "Win+X".to_string(), source: "winx".to_string(),
                    file_path: String::new(), command: String::new(),
                    enabled: !is_off, confirm_required: false, confirm_reason: String::new(),
                    unknown_convention: false, blocked_by: String::new(), target: String::new(),
                    orphan: false, orphan_reason: String::new(),
                });
            }
        }

        // ---- 新建菜单 ----
        let ps_sub = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Discardable\PostSetup\ShellNew";
        let sk = to_wide(ps_sub);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
            if let Some((_ty, buf)) = reg_query_value(hk, "Classes") {
                // REG_MULTI_SZ
                let wide: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                let mut start = 0;
                for i in 0..wide.len() {
                    if wide[i] == 0 {
                        if i > start {
                            let cls = String::from_utf16_lossy(&wide[start..i]);
                            if !cls.trim().is_empty() {
                                // 检查是否有 ShellNew 键
                                let mut has_shellnew = false;
                                for (hive, base) in &scene_views {
                                    let check = format!("{base}\\{cls}\\ShellNew");
                                    let csk = to_wide(&check);
                                    let mut chk = HKEY::default();
                                    if RegOpenKeyExW(*hive, PCWSTR(csk.as_ptr()), Some(0), KEY_READ, &mut chk).is_ok() {
                                        let _ = RegCloseKey(chk);
                                        has_shellnew = true;
                                        break;
                                    }
                                }
                                let std_path = format!("HKEY_CURRENT_USER\\{ps_sub}");
                                let (nm, orphan) = if has_shellnew {
                                    (format!("新建 {cls}"), false)
                                } else {
                                    (format!("新建 {cls}（残留：无 ShellNew 键）"), true)
                                };
                                items.push(CmItem {
                                    name: nm, clsid: String::new(), reg_path: std_path.clone(),
                                    native_reg_path: std_path.clone(),
                                    company: "Microsoft Corporation".to_string(),
                                    location: std_path.clone(), category: "新建菜单".to_string(),
                                    source: "shellnew".to_string(), file_path: String::new(),
                                    command: String::new(), enabled: true,
                                    confirm_required: false, confirm_reason: String::new(),
                                    unknown_convention: false, blocked_by: String::new(),
                                    target: cls, orphan,
                                    orphan_reason: if orphan { "列表里还挂着这个类型，但对应的 ShellNew 键已不存在".to_string() } else { String::new() },
                                });
                            }
                        }
                        start = i + 1;
                    }
                }
            }
            let _ = RegCloseKey(hk);
        }

        // ---- 打开方式（Applications） ----
        for (hive, base) in &scene_views {
            let app_root = format!("{base}\\Applications");
            let ask = to_wide(&app_root);
            let mut ahk = HKEY::default();
            if RegOpenKeyExW(*hive, PCWSTR(ask.as_ptr()), Some(0), KEY_READ, &mut ahk).is_err() { continue; }
            for app in reg_enum_subkeys(ahk) {
                let app_path = format!("{app_root}\\{app}");
                let shell_path = format!("{app_path}\\shell");
                let ssk = to_wide(&shell_path);
                let mut shk = HKEY::default();
                if RegOpenKeyExW(*hive, PCWSTR(ssk.as_ptr()), Some(0), KEY_READ, &mut shk).is_err() { continue; }
                let verbs = reg_enum_subkeys(shk);
                let _ = RegCloseKey(shk);
                if verbs.is_empty() { continue; }
                let apk = to_wide(&app_path);
                let mut aphk = HKEY::default();
                let mut friendly = app.clone();
                let mut no_open = false;
                let mut app_path_val = String::new();
                let mut cmd_line = String::new();
                if RegOpenKeyExW(*hive, PCWSTR(apk.as_ptr()), Some(0), KEY_READ, &mut aphk).is_ok() {
                    if let Some(f) = reg_read_string(aphk, "FriendlyAppName") {
                        if !f.trim().is_empty() { friendly = direct_string(&f); }
                    }
                    if friendly.is_empty() { friendly = app.clone(); }
                    no_open = reg_value_exists(aphk, "NoOpenWith");
                    // `AppPath` 是这个应用 exe 的绝对路径，归属判据的第一选择
                    if let Some(p) = reg_read_string(aphk, "AppPath") {
                        app_path_val = direct_string(&p).trim().trim_matches('"').to_string();
                    }
                    let _ = RegCloseKey(aphk);
                }
                // 拿不到 AppPath 时，从第一个 verb 的 command 默认值里取 exe：
                // 「打开方式」的条目名常是 FriendlyAppName（「抖音」「Trae CN」），
                // 按软件分组时猜不出归属，真机 27 条未识别里 13 条卡在这。
                if app_path_val.is_empty() {
                    for v in &verbs {
                        let ckey = format!(r"{app_path}\shell\{v}\command");
                        let csk = to_wide(&ckey);
                        let mut chk = HKEY::default();
                        if RegOpenKeyExW(*hive, PCWSTR(csk.as_ptr()), Some(0), KEY_READ, &mut chk).is_err() {
                            continue;
                        }
                        if let Some(c) = reg_read_string(chk, "") {
                            let c = direct_string(&c);
                            if !c.trim().is_empty() { cmd_line = c; }
                        }
                        let _ = RegCloseKey(chk);
                        if !cmd_line.is_empty() { break; }
                    }
                }
                let std_path = if *hive == HKEY_CURRENT_USER {
                    format!("HKEY_CURRENT_USER\\{app_path}")
                } else {
                    format!("HKEY_LOCAL_MACHINE\\{app_path}")
                };
                items.push(CmItem {
                    name: friendly, clsid: String::new(), reg_path: std_path.clone(),
                    native_reg_path: resolve_native_reg_path(&std_path),
                    company: String::new(), location: app_root.clone(),
                    category: "打开方式".to_string(), source: "openwith".to_string(),
                    // 组件路径只在**文件确实存在**时给：归属段会直接读它的 PE 版本资源；
                    // 路径已失效（软件被删但 Applications 键还在）就不填，让它落到「未识别」
                    // 而不是按一个不存在的目录猜个厂商。
                    file_path: if !app_path_val.is_empty() && std::path::Path::new(&app_path_val).is_file() {
                        app_path_val.clone()
                    } else { String::new() },
                    // 命令串要么给真实命令行，要么退回 verb 清单（两者给的是不同信息：
                    // 前者能给归属与「执行命令」一行，后者只是 verb 名单）
                    enabled: !no_open, confirm_required: false, confirm_reason: String::new(),
                    unknown_convention: false, blocked_by: String::new(), target: String::new(),
                    orphan: false, orphan_reason: String::new(),
                    command: if cmd_line.is_empty() { verbs.join(", ") } else { cmd_line.clone() },
                });
            }
            let _ = RegCloseKey(ahk);
        }

        // ---- 去重 ----
        let mut dedup: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut result: Vec<Value> = Vec::new();
        // 归属解析的三份共享输入：PE 读缓存 + 裸名 exe 的解析缓存 + 系统根目录（判「Windows 系统组件」用）
        let mut pe_cache: std::collections::HashMap<String, PeInfo> = std::collections::HashMap::new();
        let mut exe_cache: std::collections::HashMap<String, Option<String>> = std::collections::HashMap::new();
        let system_root = std::env::var_os("SystemRoot")
            .map(|v| v.to_string_lossy().to_string())
            .unwrap_or_default();
        for item in items {
            let enabled_text = if item.enabled { "1" } else { "0" };
            let key = if item.clsid.is_empty() {
                format!("{}|{}|{}|{}|{}", item.category, item.name, item.source, item.native_reg_path, enabled_text)
            } else {
                format!("{}|{}|{}|{}", item.category, item.name, item.clsid, enabled_text)
            };
            if !dedup.insert(key) { continue; }

            let is_protected = PROTECTED_CLASSES.contains(&item.clsid.as_str());

            // 软件归属：CLSID 有处理程序文件就按它读 PE；没有（shell/verb/Win+X 那 109 条）
            // 就从命令行里取 exe，裸名再走 App Paths / System32 / PATH 解析成真实路径。
            // 打开方式列表特殊：它的**条目名就是 exe 名**（`wps.exe`），而命令行里只有 verb
            // （`open`）。所以退路挂在「解析结果为空」上，而不是挂在「取不到命令」上 ——
            // `open` 会被当成裸名取出来，却解析不到文件，那时必须继续试条目名。
            let owner_file = if !item.file_path.is_empty() {
                item.file_path.clone()
            } else {
                let mut hit = exe_from_command(&item.command)
                    .and_then(|raw| resolve_cached(&mut exe_cache, &raw));
                if hit.is_none() && item.source == "openwith" && !item.name.is_empty() {
                    hit = resolve_cached(&mut exe_cache, &item.name);
                }
                hit.unwrap_or_default()
            };
            let pe = pe_info_cached(&owner_file, &mut pe_cache);
            let (owner, owner_source) = owner_of(&pe, &item.company, &owner_file, &system_root);

            // 审计 P1-9（真机坐实）：「第三方 / 系统原生」这维过去只看 CLSID 键的 `Company`
            // 值，而本机 171 条里只有 27 条有那个值 —— 于是 PE 明明写着 Microsoft Corporation
            // 的「旧版 Windows Media Player」被判成第三方（虚高警告），而躺在
            // `C:\Windows\System32\DriverStore\FileRepository\nv_*.dll` 的 NVIDIA 壳扩展
            // 因为「路径在 Windows 目录下 + 没有 Company」被算成系统原生（**该警惕的反而被压低**）。
            // DriverStore 是第三方驱动包的存放处，那条捷径在这里恰好判反。
            // 修法是把 PE 的厂商与解析出的真实文件路径喂进同一条判据，不另起一套。
            let company_eff = if item.company.trim().is_empty() { pe.company.as_str() } else { &item.company };
            let path_eff = if item.file_path.is_empty() { owner_file.as_str() } else { &item.file_path };
            let is_tp = is_third_party(&item.name, company_eff, &item.source, path_eff);
            let risk = if is_protected { "protected" } else if is_tp { "high" } else { "low" };
            let component_missing = is_guid(&item.clsid) && !item.file_path.is_empty()
                && !std::path::Path::new(&item.file_path).exists();
            let orphan = item.orphan || component_missing;
            let orphan_reason = if component_missing {
                format!("登记的处理程序文件已不存在（{}）", item.file_path)
            } else { item.orphan_reason };

            result.push(json!({
                "name": clean_str(&item.name),
                "clsid": clean_str(&item.clsid),
                "regPath": clean_str(&item.reg_path),
                "nativeRegPath": clean_str(&item.native_reg_path),
                "company": clean_str(&item.company),
                // 分组键与它的判据来源（pe-product / pe-desc / registry / pe-company / dir /
                // system / 空=未识别）。界面上「按安装目录识别」这类推断必须能看出来，
                // 不装作权威结论（AGENTS §9.3：没有证据的主张不进文案）。
                "owner": clean_str(&owner),
                "ownerSource": clean_str(&owner_source),
                "location": clean_str(&item.location),
                "category": clean_str(&item.category),
                "source": clean_str(&item.source),
                "filePath": clean_str(&item.file_path),
                "command": clean_str(&item.command),
                "isThirdParty": is_tp,
                "isProtected": is_protected,
                "risk": risk,
                "enabled": item.enabled,
                "confirmRequired": item.confirm_required,
                "confirmReason": clean_str(&item.confirm_reason),
                "unknownConvention": item.unknown_convention,
                "orphan": orphan,
                "orphanReason": clean_str(&orphan_reason),
                "blockedBy": clean_str(&item.blocked_by),
                "target": clean_str(&item.target),
            }));
        }
        Ok(result)
    }
}

/// 扫描 shell 子键项
unsafe fn scan_shell_items(
    scene_path: &str, hive: HKEY, category: &str,
    clsid_views: &[(HKEY, &str)], blocked: &std::collections::HashMap<String, String>,
    items: &mut Vec<CmItem>, seen_keys: &mut std::collections::HashSet<String>,
) {
    let shell_path = format!("{scene_path}\\shell");
    let sk = to_wide(&shell_path);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { return; }
    for child in reg_enum_subkeys(hk) {
        let seen_key = format!("{shell_path}|{child}");
        if !seen_keys.insert(seen_key) { continue; }
        let key_path = format!("{shell_path}\\{child}");
        let ksk = to_wide(&key_path);
        let mut chk = HKEY::default();
        if RegOpenKeyExW(hive, PCWSTR(ksk.as_ptr()), Some(0), KEY_READ, &mut chk).is_err() { continue; }
        // 名称：MUIVerb > 默认值（非多级菜单）> 键名
        let mut name = String::new();
        if let Some(mui) = reg_read_string(chk, "MUIVerb") {
            name = direct_string(&mui);
        }
        if name.is_empty() {
            let has_sub = reg_value_exists(chk, "SubCommands") || reg_value_exists(chk, "ExtendedSubCommandsKey");
            if !has_sub {
                if let Some(def) = reg_read_string(chk, "") {
                    name = direct_string(&def);
                }
            }
        }
        if name.is_empty() { name = child.clone(); }
        // GUID：command\DelegateExecute > DropTarget\CLSID > ExplorerCommandHandler
        let mut clsid = String::new();
        let cmd_path = format!("{key_path}\\command");
        let csk = to_wide(&cmd_path);
        let mut chk_cmd = HKEY::default();
        let mut command = String::new();
        if RegOpenKeyExW(hive, PCWSTR(csk.as_ptr()), Some(0), KEY_READ, &mut chk_cmd).is_ok() {
            if let Some(de) = reg_read_string(chk_cmd, "DelegateExecute") {
                if is_guid(&de) { clsid = de.trim().to_string(); }
            }
            if let Some(c) = reg_read_string(chk_cmd, "") {
                command = direct_string(&c);
            }
            let _ = RegCloseKey(chk_cmd);
        }
        if clsid.is_empty() {
            let dt_path = format!("{key_path}\\DropTarget");
            let dsk = to_wide(&dt_path);
            let mut chk_dt = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(dsk.as_ptr()), Some(0), KEY_READ, &mut chk_dt).is_ok() {
                if let Some(c) = reg_read_string(chk_dt, "CLSID") {
                    if is_guid(&c) { clsid = c.trim().to_string(); }
                }
                let _ = RegCloseKey(chk_dt);
            }
        }
        if clsid.is_empty() {
            if let Some(eh) = reg_read_string(chk, "ExplorerCommandHandler") {
                if is_guid(&eh) { clsid = eh.trim().to_string(); }
            }
        }
        // 启用状态
        let mut enabled = !verb_hidden(chk);
        let mut unknown_conv = false;
        if child.to_lowercase().starts_with("autorunsdisabled") {
            enabled = false;
            unknown_conv = true;
            name = format!("{name}（未识别的禁用约定）");
        }
        // 确认保护
        let (confirm_req, confirm_reason) = {
            let v = child.to_lowercase();
            if v == "open" || v == "explore" {
                (true, "该项是对象的基础「打开/浏览」动词，禁用或删除后双击与默认打开行为可能改变".to_string())
            } else if clsid.eq_ignore_ascii_case("{00021401-0000-0000-C000-000000000046}") {
                (true, "该项承载快捷方式的「打开」行为，禁用后 .lnk 双击可能失效".to_string())
            } else {
                (false, String::new())
            }
        };
        // CLSID 信息
        let mut company = String::new();
        let mut file_path = String::new();
        if is_guid(&clsid) {
            let info = get_clsid_info(&clsid, clsid_views);
            company = info.company;
            file_path = info.file_path;
        }
        // Blocked
        let mut blocked_by = String::new();
        if !clsid.is_empty() {
            if let Some(scope) = blocked.get(&clsid.to_uppercase()) {
                blocked_by = scope.clone();
                enabled = false;
            }
        }
        let std_path = if hive == HKEY_CURRENT_USER {
            // key_path 本身就是 `Software\Classes\...` 相对路径，直接拼 hive 全名即可。
            // 审计 P2-14：这里原来还套了 `.trim_start_matches(r"Software\\")`，而原始串里是
            // **两个**反斜杠、真实路径只有一个 ⇒ 恒不匹配的死代码；谁哪天把它"修对"，
            // 反而会削掉 Software 前缀让 HKCU 写侧全灭。删掉，不留陷阱。
            format!("HKEY_CURRENT_USER\\{key_path}")
        } else {
format!("HKEY_LOCAL_MACHINE\\{key_path}")
        };
        // 幽灵项过滤
        if name.trim().is_empty() { let _ = RegCloseKey(chk); continue; }
        items.push(CmItem {
            name, clsid, reg_path: std_path.clone(),
            native_reg_path: resolve_native_reg_path(&std_path),
            company, location: shell_path.clone(), category: category.to_string(),
            source: "shell".to_string(), file_path, command,
            enabled, confirm_required: confirm_req, confirm_reason,
            unknown_convention: unknown_conv, blocked_by, target: String::new(),
            orphan: false, orphan_reason: String::new(),
        });
        let _ = RegCloseKey(chk);
    }
    let _ = RegCloseKey(hk);
}

/// 扫描 ShellEx\ContextMenuHandlers 项
unsafe fn scan_shellex_handlers(
    scene_path: &str, hive: HKEY, handlers_dir: &str, category: &str,
    clsid_views: &[(HKEY, &str)], blocked: &std::collections::HashMap<String, String>,
    items: &mut Vec<CmItem>, seen_keys: &mut std::collections::HashSet<String>,
) {
    let cm_path = format!("{scene_path}\\ShellEx\\{handlers_dir}");
    let sk = to_wide(&cm_path);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { return; }
    let group_disabled = handlers_dir.starts_with('-');
    for child in reg_enum_subkeys(hk) {
        let seen_key = format!("{cm_path}|{child}");
        if !seen_keys.insert(seen_key) { continue; }
        let mut enabled = !group_disabled;
        let mut real_name = child.clone();
        if real_name.starts_with('-') {
            enabled = false;
            real_name = real_name[1..].to_string();
        }
        if real_name.is_empty() { continue; }
        let key_path = format!("{cm_path}\\{child}");
        let ksk = to_wide(&key_path);
        let mut chk = HKEY::default();
        if RegOpenKeyExW(hive, PCWSTR(ksk.as_ptr()), Some(0), KEY_READ, &mut chk).is_err() { continue; }
        let default_val = reg_read_string(chk, "").unwrap_or_default();
        let _ = RegCloseKey(chk);
        // GUID：默认值优先，回退键名
        let mut guid = default_val.clone();
        if !is_guid(&guid) { guid = real_name.clone(); }
        if !is_guid(&guid) {
            // Autoruns 约定
            if real_name.to_lowercase().starts_with("autorunsdisabled") {
                let std_path = if hive == HKEY_CURRENT_USER {
                    // key_path 本身就是 `Software\Classes\...` 相对路径，直接拼 hive 全名即可。
            // 审计 P2-14：这里原来还套了 `.trim_start_matches(r"Software\\")`，而原始串里是
            // **两个**反斜杠、真实路径只有一个 ⇒ 恒不匹配的死代码；谁哪天把它"修对"，
            // 反而会削掉 Software 前缀让 HKCU 写侧全灭。删掉，不留陷阱。
            format!("HKEY_CURRENT_USER\\{key_path}")
                } else {
        format!("HKEY_LOCAL_MACHINE\\{key_path}")
                };
                items.push(CmItem {
                    name: format!("未识别的禁用项（{real_name}）"), clsid: String::new(),
                    reg_path: std_path.clone(), native_reg_path: std_path,
                    company: String::new(), location: cm_path.clone(),
                    category: category.to_string(), source: "shellex".to_string(),
                    file_path: String::new(), command: String::new(),
                    enabled: false, confirm_required: false, confirm_reason: String::new(),
                    unknown_convention: true, blocked_by: String::new(), target: String::new(),
                    orphan: false, orphan_reason: String::new(),
                });
            }
            continue;
        }
        guid = guid.trim().to_string();
        let info = get_clsid_info(&guid, clsid_views);
        // 名称：CLSID 友好名 > 键名为 GUID 时用默认值 > 键名
        let name = if !info.name.is_empty() {
            info.name.clone()
        } else if is_guid(&real_name) && !default_val.is_empty() && !is_guid(&default_val) {
            default_val
        } else {
            real_name
        };
        let mut blocked_by = String::new();
        if let Some(scope) = blocked.get(&guid.to_uppercase()) {
            blocked_by = scope.clone();
            enabled = false;
        }
        let std_path = if hive == HKEY_CURRENT_USER {
            // key_path 本身就是 `Software\Classes\...` 相对路径，直接拼 hive 全名即可。
            // 审计 P2-14：这里原来还套了 `.trim_start_matches(r"Software\\")`，而原始串里是
            // **两个**反斜杠、真实路径只有一个 ⇒ 恒不匹配的死代码；谁哪天把它"修对"，
            // 反而会削掉 Software 前缀让 HKCU 写侧全灭。删掉，不留陷阱。
            format!("HKEY_CURRENT_USER\\{key_path}")
        } else {
format!("HKEY_LOCAL_MACHINE\\{key_path}")
        };
        if name.trim().is_empty() { continue; }
        items.push(CmItem {
            name, clsid: guid, reg_path: std_path.clone(),
            native_reg_path: resolve_native_reg_path(&std_path),
            company: info.company, location: cm_path.clone(),
            category: category.to_string(), source: "shellex".to_string(),
            file_path: info.file_path, command: String::new(),
            enabled, confirm_required: false, confirm_reason: String::new(),
            unknown_convention: false, blocked_by, target: String::new(),
            orphan: false, orphan_reason: String::new(),
        });
    }
    let _ = RegCloseKey(hk);
}

// ==================== B6 cm_toggle：右键菜单启用/禁用 ====================


/// 检查 CLSID 是否为系统内置 COM 服务器（文件在 SystemRoot 下）
unsafe fn is_system_com_server(guid: &str) -> bool {
    if !is_guid(guid) { return false; }
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()).to_lowercase();
    for view in [
        r"SOFTWARE\Classes\CLSID",
        r"SOFTWARE\Classes\Wow6432Node\CLSID",
    ] {
        for sub in ["InprocServer32", "LocalServer32"] {
            let key = format!("{view}\\{guid}\\{sub}");
            let sk = to_wide(&key);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { continue; }
            let mut raw = reg_read_string(hk, "").unwrap_or_default();
            if raw.is_empty() { raw = reg_read_string(hk, "CodeBase").unwrap_or_default(); }
            let _ = RegCloseKey(hk);
            if raw.is_empty() { continue; }
            let expanded = expand_env(raw.trim().trim_matches('"')).to_lowercase();
            if expanded.starts_with(&sysroot) { return true; }
        }
    }
    false
}

/// 右键菜单启用/禁用（对应 cm_toggle.ps1，S3）
///
/// 覆盖 7 种 source：shell（四值模型）、shellex（'-' 前缀重命名）、
/// winx（.lnk.disabled 重命名）、filesystem（Hidden 属性）、
/// shellnew（Classes MULTI_SZ）、openwith（NoOpenWith）、
/// packagedcom/uwp-contract/blockedBy（Shell Extensions\Blocked 屏蔽表）。
pub fn cm_toggle(items: &[Value]) -> Result<Value, String> {
    unsafe {
        let mut results: Vec<Value> = Vec::new();
        let mut success = 0i64;
        let mut failed = 0i64;
        let mut skipped = 0i64;

        for item in items {
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let source = item.get("source").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let display_path = item.get("regPath").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut target = item.get("nativeRegPath").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if target.is_empty() { target = display_path.clone(); }
            let want_enabled = item.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let risk = item.get("risk").and_then(|v| v.as_str()).unwrap_or("");

            // 系统保护项拒绝
            if risk == "protected" {
                skipped += 1;
                results.push(json!({"id": id, "name": name, "regPath": display_path, "status": "skip", "message": "系统保护项"}));
                continue;
            }
            if target.is_empty() {
                skipped += 1;
                results.push(json!({"name": name, "regPath": "", "status": "skip", "message": "缺少目标路径"}));
                continue;
            }

            let result = toggle_cm_item(item, &source, &target, &display_path, want_enabled, &id, &name);
            match result {
                Ok(mut res) => {
                    success += 1;
                    res["id"] = json!(id);
                    res["name"] = json!(name);
                    res["regPath"] = json!(display_path);
                    results.push(res);
                }
                Err(e) => {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "regPath": display_path, "status": "error", "message": e}));
                }
            }
        }

        Ok(json!({"success": success, "failed": failed, "skipped": skipped, "results": results}))
    }
}

unsafe fn toggle_cm_item(
    item: &Value, source: &str, target: &str, display_path: &str,
    want_enabled: bool, _id: &str, _name: &str,
) -> Result<Value, String> {
    let blocked_by = item.get("blockedBy").and_then(|v| v.as_str()).unwrap_or("");
    let clsid = item.get("clsid").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();

    // ---- 屏蔽表（packagedcom/uwp-contract/已有 blockedBy）----
    if source == "packagedcom" || source == "uwp-contract" || !blocked_by.is_empty() {
        if !is_guid(&clsid) {
            return Err("缺少有效 CLSID，无法用屏蔽表启停".into());
        }
        if is_system_com_server(&clsid) {
            return Err("系统内置扩展不允许加入屏蔽表（可能导致整个新式右键菜单失效）".into());
        }
        let scope = if blocked_by == "machine" { "machine" } else { "user" };
        let (hive, key) = if scope == "machine" {
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked")
        } else {
            (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked")
        };
        let sk = to_wide(key);
        let mut hk = HKEY::default();
        let mut disp = REG_CREATED_NEW_KEY;
        if RegCreateKeyExW(hive, PCWSTR(sk.as_ptr()), None, PCWSTR::default(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut hk, Some(&mut disp)).is_err() {
            return Err("无法打开屏蔽表键".into());
        }
        if want_enabled {
            let nm = to_wide(&clsid);
            let _ = RegDeleteValueW(hk, PCWSTR(nm.as_ptr()));
        } else {
            let nm = to_wide(&clsid);
            let _ = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_SZ, Some(&[0u8, 0]));
        }
        let _ = RegCloseKey(hk);
        // 回读
        let still_blocked = {
            let sk2 = to_wide(key);
            let mut hk2 = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(sk2.as_ptr()), Some(0), KEY_READ, &mut hk2).is_err() { false }
            else {
                let nm = to_wide(&clsid);
                let mut ty = REG_VALUE_TYPE::default();
                let mut size = 0u32;
                let exists = RegQueryValueExW(hk2, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_ok();
                let _ = RegCloseKey(hk2);
                exists
            }
        };
        if still_blocked == !want_enabled {
            let new_blocked = if want_enabled { "" } else { scope };
            let msg = if want_enabled { "已解除屏蔽" } else { "已屏蔽（不加载该扩展）" };
            return Ok(json!({"status": "ok", "newBlockedBy": new_blocked, "message": msg}));
        } else {
            let msg = if scope == "machine" { "屏蔽表写入未生效（机器级需要管理员权限）" } else { "屏蔽表写入未生效" }; return Err(msg.into());
        }
    }

    // ---- Win+X：.lnk ⇄ .lnk.disabled ----
    if source == "winx" {
        if !std::path::Path::new(target).exists() {
            return Err("文件不存在".into());
        }
        let leaf = std::path::Path::new(target).file_name().and_then(|n| n.to_str()).unwrap_or("");
        let is_off = leaf.to_lowercase().ends_with(".disabled");
        if want_enabled && !is_off {
            return Ok(json!({"status": "ok", "message": "已处于启用状态"}));
        }
        if !want_enabled && is_off {
            return Ok(json!({"status": "ok", "message": "已处于禁用状态"}));
        }
        let new_leaf = if want_enabled {
            // 按小写判据反切固定 9 字节，不用 trim_end_matches（它区分大小写，两次调用仍漏
            // `.Disabled` 这种混合大小写 —— NTFS 大小写不敏感，摘掉大小写之一就会截出空名或错名）。
            // 后缀能小写匹配上 `.disabled` 就必然是 ASCII 的 9 个字节，切片不会落在字符中间。
            leaf[..leaf.len() - 9].to_string()
        } else {
            format!("{leaf}.disabled")
        };
        // 审计 P2-11：写侧唯一的裸 unwrap。上面的 exists() 判据让它在真实路径上取不到 None，
        // 但"当前不可达"不是留着 panic 的理由 —— 盘符根（`D:\`）这类输入 parent() 就是 None。
        let Some(parent) = std::path::Path::new(target).parent() else {
            return Err("发送到项路径无法定位所在目录".into());
        };
        let new_path = parent.join(&new_leaf);
        std::fs::rename(target, &new_path).map_err(|e| format!("重命名失败: {e}"))?;
        if new_path.exists() && !std::path::Path::new(target).exists() {
            let np = new_path.to_string_lossy().to_string();
            return Ok(json!({"status": "ok", "newRegPath": np, "newNativeRegPath": np, "message": if want_enabled { "已启用" } else { "已禁用" }}));
        } else {
            return Err("重命名未生效".into());
        }
    }

    // ---- 发送到：Hidden 属性切换 ----
    if source == "filesystem" {
        if !std::path::Path::new(target).exists() {
            return Err("文件不存在".into());
        }
        use windows::Win32::Storage::FileSystem::{GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};
        let target_w = to_wide(target);
        let cur_attrs = GetFileAttributesW(PCWSTR(target_w.as_ptr()));
        if cur_attrs == 0xFFFFFFFF { return Err("读取文件属性失败".into()); }
        let new_attrs = if want_enabled { cur_attrs & !FILE_ATTRIBUTE_HIDDEN.0 } else { cur_attrs | FILE_ATTRIBUTE_HIDDEN.0 };
        if SetFileAttributesW(PCWSTR(target_w.as_ptr()), windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(new_attrs)).is_err() {
            return Err("设置文件属性失败".into());
        }
        // 回读
        let now_hidden = GetFileAttributesW(PCWSTR(target_w.as_ptr())) & FILE_ATTRIBUTE_HIDDEN.0 != 0;
        if now_hidden == !want_enabled {
            return Ok(json!({"status": "ok", "message": if want_enabled { "已启用" } else { "已禁用" }}));
        } else {
            return Err("切换未生效".into());
        }
    }

    // 解析注册表路径
    let (hive, subkey) = parse_reg_path(target).ok_or("注册表路径格式错误")?;

    // ---- 新建菜单：Classes MULTI_SZ ----
    if source == "shellnew" {
        let cls = item.get("target").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        if cls.is_empty() { return Err("缺少类名（target）".into()); }
        let sk = to_wide(&subkey);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return Err("注册表路径不存在".into());
        }
        // 读当前 Classes
        let mut cur: Vec<String> = Vec::new();
        if let Some((ty, buf)) = reg_read_value_typed(hive, &subkey, "Classes") {
            if ty == REG_MULTI_SZ {
                let wide: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                let mut start = 0;
                for i in 0..wide.len() {
                    if wide[i] == 0 {
                        if i > start {
                            let s = String::from_utf16_lossy(&wide[start..i]);
                            if !s.trim().is_empty() { cur.push(s); }
                        }
                        start = i + 1;
                    }
                }
            }
        }
        let _ = RegCloseKey(hk);
        let has = cur.iter().any(|c| c.eq_ignore_ascii_case(&cls));
        if want_enabled && has {
            return Ok(json!({"status": "ok", "message": "已处于启用状态"}));
        }
        if !want_enabled && !has {
            return Ok(json!({"status": "ok", "message": "已处于禁用状态"}));
        }
        let new_list: Vec<String> = if want_enabled {
            let mut v = cur.clone(); v.push(cls.clone()); v
        } else {
            cur.into_iter().filter(|c| !c.eq_ignore_ascii_case(&cls)).collect()
        };
        // 写回
        let sk2 = to_wide(&subkey);
        let mut hk2 = HKEY::default();
        if RegOpenKeyExW(hive, PCWSTR(sk2.as_ptr()), Some(0), KEY_WRITE, &mut hk2).is_err() {
            return Err("无法写入注册表".into());
        }
        if new_list.is_empty() {
            let nm = to_wide("Classes");
            let _ = RegDeleteValueW(hk2, PCWSTR(nm.as_ptr()));
        } else {
            let mut bytes = Vec::new();
            for s in &new_list {
                let wide: Vec<u16> = s.encode_utf16().collect();
                for w in &wide { bytes.extend_from_slice(&w.to_le_bytes()); }
                bytes.extend_from_slice(&[0, 0]);
            }
            bytes.extend_from_slice(&[0, 0]);
            let nm = to_wide("Classes");
            if RegSetValueExW(hk2, PCWSTR(nm.as_ptr()), Some(0), REG_MULTI_SZ, Some(&bytes)).is_err() {
                return Err("写 Classes 失败".into());
            }
        }
        let _ = RegCloseKey(hk2);
        return Ok(json!({"status": "ok", "message": if want_enabled { "已启用" } else { "已禁用" }}));
    }

    // ---- 打开方式：NoOpenWith ----
    if source == "openwith" {
        let sk = to_wide(&subkey);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_WRITE, &mut hk).is_err() {
            return Err("注册表路径不存在".into());
        }
        if want_enabled {
            let nm = to_wide("NoOpenWith");
            let _ = RegDeleteValueW(hk, PCWSTR(nm.as_ptr()));
        } else {
            let nm = to_wide("NoOpenWith");
            let _ = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_SZ, Some(&[0u8, 0]));
        }
        let _ = RegCloseKey(hk);
        // 回读
        let sk2 = to_wide(&subkey);
        let mut hk2 = HKEY::default();
        let now_off = if RegOpenKeyExW(hive, PCWSTR(sk2.as_ptr()), Some(0), KEY_READ, &mut hk2).is_ok() {
            let nm = to_wide("NoOpenWith");
            let mut ty = REG_VALUE_TYPE::default();
            let mut size = 0u32;
            let exists = RegQueryValueExW(hk2, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_ok();
            let _ = RegCloseKey(hk2);
            exists
        } else { false };
        if now_off == !want_enabled {
            return Ok(json!({"status": "ok", "message": if want_enabled { "已启用" } else { "已禁用" }}));
        } else {
            return Err("切换未生效（可能需要管理员权限）".into());
        }
    }

    // ---- shell：四值可见性模型 ----
    if source == "shell" {
        let leaf = subkey.rsplit('\\').next().unwrap_or(&subkey).to_string();
        let parent = if let Some(pos) = subkey.rfind('\\') { &subkey[..pos] } else { "" };
        let mut reg_path = subkey.to_string();
        let mut renamed_to = String::new();

        if want_enabled {
            // AutorunsDisabled 重命名还原
            let lower_leaf = leaf.to_lowercase();
            if lower_leaf.starts_with("autorunsdisabled") {
                let rest = if lower_leaf.starts_with("autorunsdisabled_") { &leaf[17..] } else { &leaf[16..] };
                if !rest.is_empty() {
                    renamed_to = rest.to_string();
                    let old_sk = to_wide(&reg_path);
                    let mut old_hk = HKEY::default();
                    if RegOpenKeyExW(hive, PCWSTR(old_sk.as_ptr()), Some(0), KEY_READ, &mut old_hk).is_ok() {
                        let _ = RegCloseKey(old_hk);
                        // 重命名。**改名失败绝不能继续**：下面按新路径回读，键其实还叫旧名，
                        // 打不开 ⇒ now_hidden=false ⇒ 与 want_enabled=true 相等 ⇒ 报「已启用」，
                        // 并把不存在的新路径写回快照与缓存（真机审计 P1-1）。
                        let new_name = to_wide(&renamed_to);
                        let parent_sk = to_wide(parent);
                        let mut parent_hk = HKEY::default();
                        if RegOpenKeyExW(hive, PCWSTR(parent_sk.as_ptr()), Some(0), KEY_WRITE, &mut parent_hk).is_err() {
                            return Err("无法打开父键以重命名（权限不足或键被占用）".into());
                        }
                        let rn = RegRenameKey(parent_hk, PCWSTR(to_wide(&leaf).as_ptr()), PCWSTR(new_name.as_ptr()));
                        let _ = RegCloseKey(parent_hk);
                        if rn.is_err() {
                            return Err(format!("重命名 {leaf} → {renamed_to} 被拒（可能需要管理员权限）"));
                        }
                        reg_path = format!("{parent}\\{renamed_to}");
                    }
                }
            }
            // 删除四值
            let sk = to_wide(&reg_path);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_WRITE, &mut hk).is_ok() {
                for vn in ["LegacyDisable", "Blocked", "ProgrammaticAccessOnly", "HideBasedOnVelocityId"] {
                    let nm = to_wide(vn);
                    let _ = RegDeleteValueW(hk, PCWSTR(nm.as_ptr()));
                }
                // CommandFlags 清 0x8 位
                if let Some(cf) = reg_read_dword_val(hk, "CommandFlags") {
                    let cleared = cf & !0x8;
                    if cleared == 0 {
                        let nm = to_wide("CommandFlags");
                        let _ = RegDeleteValueW(hk, PCWSTR(nm.as_ptr()));
                    } else {
                        let nm = to_wide("CommandFlags");
                        let _ = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&cleared.to_le_bytes()));
                    }
                }
                let _ = RegCloseKey(hk);
            }
        } else {
            // 禁用：写 ProgrammaticAccessOnly + HideBasedOnVelocityId，opennewwindow 不写 LegacyDisable
            let sk = to_wide(&reg_path);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_WRITE, &mut hk).is_err() {
                return Err("注册表路径不存在".into());
            }
            let nm1 = to_wide("ProgrammaticAccessOnly");
            let _ = RegSetValueExW(hk, PCWSTR(nm1.as_ptr()), Some(0), REG_SZ, Some(&[0u8, 0]));
            let nm2 = to_wide("HideBasedOnVelocityId");
            let velocity = 0x639bc8u32;
            let _ = RegSetValueExW(hk, PCWSTR(nm2.as_ptr()), Some(0), REG_DWORD, Some(&velocity.to_le_bytes()));
            // opennewwindow 硬特判
            if !reg_path.to_lowercase().ends_with(r"\folder\shell\opennewwindow") {
                let nm3 = to_wide("LegacyDisable");
                let _ = RegSetValueExW(hk, PCWSTR(nm3.as_ptr()), Some(0), REG_SZ, Some(&[0u8, 0]));
            }
            let _ = RegCloseKey(hk);
        }
        // 回读：四值隐藏判据
        let sk2 = to_wide(&reg_path);
        let mut hk2 = HKEY::default();
        let now_hidden = if RegOpenKeyExW(hive, PCWSTR(sk2.as_ptr()), Some(0), KEY_READ, &mut hk2).is_ok() {
            let h = verb_hidden(hk2);
            let _ = RegCloseKey(hk2);
            h
        } else { false };
        if now_hidden == !want_enabled {
            let mut res = json!({"status": "ok", "message": if want_enabled { "已启用" } else { "已禁用" }});
            if !renamed_to.is_empty() {
                res["newNativeRegPath"] = json!(swap_last_segment(target, &renamed_to));
                res["newRegPath"] = json!(swap_last_segment(display_path, &renamed_to));
            }
            return Ok(res);
        } else {
            return Err("切换未生效（可能需要管理员权限）".into());
        }
    }

    // ---- shellex：'-' 前缀重命名 ----
    if source == "shellex" {
        let leaf = subkey.rsplit('\\').next().unwrap_or(&subkey).to_string();
        let parent = if let Some(pos) = subkey.rfind('\\') { &subkey[..pos] } else { "" };
        if want_enabled && !leaf.starts_with('-') {
            return Ok(json!({"status": "ok", "message": "已处于启用状态"}));
        }
        if !want_enabled && leaf.starts_with('-') {
            return Ok(json!({"status": "ok", "message": "已处于禁用状态"}));
        }
        let new_name = if want_enabled { leaf[1..].to_string() } else { format!("-{leaf}") };
        // 重命名注册表键
        let parent_sk = to_wide(parent);
        let mut parent_hk = HKEY::default();
        if RegOpenKeyExW(hive, PCWSTR(parent_sk.as_ptr()), Some(0), KEY_WRITE, &mut parent_hk).is_err() {
            return Err("无法打开父键".into());
        }
        let old_nm = to_wide(&leaf);
        let new_nm = to_wide(&new_name);
        let r = RegRenameKey(parent_hk, PCWSTR(old_nm.as_ptr()), PCWSTR(new_nm.as_ptr()));
        let _ = RegCloseKey(parent_hk);
        if r.is_err() {
            return Err("重命名未生效（可能需要管理员权限）".into());
        }
        let std_new = swap_last_segment(target, &new_name);
        let new_display = swap_last_segment(display_path, &new_name);
        return Ok(json!({"status": "ok", "newRegPath": new_display, "newNativeRegPath": std_new, "message": if want_enabled { "已启用" } else { "已禁用" }}));
    }

    Err(format!("未知 source 类型: {source}"))
}

#[cfg(test)]
mod resource_dll_tests {
    use super::*;

    /// v4-K01：资源串绝对路径白名单 —— 只放行 System32 / SysWOW64 下的真实非链接文件。
    /// 判红自证：把 resource_dll_allowed 改成恒 true ⇒ 第 2~5 条断言全红。
    #[test]
    fn resource_dll_whitelist_gates_system32_only() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let sysdll = format!("{windir}\\System32\\shell32.dll");
        assert!(resource_dll_allowed(&sysdll), "System32 下的真实 DLL 必须放行: {sysdll}");
        // 字符串前缀命中但 `..` 折叠后实际不在白名单内（穿越）
        let escape = format!("{windir}\\System32\\..\\Temp\\evil.dll");
        assert!(!resource_dll_allowed(&escape), "含 `..` 的路径必须拒: {escape}");
        // SystemRoot 下但用户可写的位置
        let temp = format!("{windir}\\Temp\\evil.dll");
        assert!(!resource_dll_allowed(&temp), "SystemRoot\\Temp 不在白名单: {temp}");
        assert!(!resource_dll_allowed(r"C:\Apps\Foo\x.dll"));
        assert!(!resource_dll_allowed(""));
        // 元数据读不到（文件不存在）⇒ 拒（后面还有 exists 闸，早退不损失功能面）
        let ghost = format!("{windir}\\System32\\trim-no-such-dll-9f3a.dll");
        assert!(!resource_dll_allowed(&ghost), "不存在的文件必须拒: {ghost}");
    }
}

#[cfg(test)]
mod owner_tests {
    use super::*;

    /// 命令行取 exe：注册表里两种写法都常见，取错等于归属判错
    #[test]
    fn exe_from_command_covers_quoted_and_bare_forms() {
        assert_eq!(
            exe_from_command(r#""C:\Program Files\WinRAR\WinRAR.exe" "%1""#).as_deref(),
            Some(r"C:\Program Files\WinRAR\WinRAR.exe")
        );
        // 裸路径 + 目录名带空格：要一路拼到整体像路径为止，不能只取第一个 token
        assert_eq!(
            exe_from_command(r"C:\Program Files\Git\git-bash.exe --cd-to-home").as_deref(),
            Some(r"C:\Program Files\Git\git-bash.exe")
        );
        // 裸路径后面跟参数：整体已经像路径时必须立刻收口，不能把 " -pw %1" 拼进路径
        assert_eq!(
            exe_from_command(r"C:\Windows\System32\bdechangepin.exe -pw %1").as_deref(),
            Some(r"C:\Windows\System32\bdechangepin.exe")
        );
        // 裸名（未识别里的大头）：cmd.exe / powershell.exe 要交出去给解析层
        assert_eq!(
            exe_from_command(r#"cmd.exe /s /k pushd "%V""#).as_deref(),
            Some("cmd.exe")
        );
        // 引号套在裸名上（注册表就这么写的）：必须和上面等价，早先这里直接判 None
        assert_eq!(
            exe_from_command(r#""cmd.exe" /s /k pushd "%V""#).as_deref(),
            Some("cmd.exe")
        );
        assert_eq!(
            exe_from_command(r#""powershell.exe" -noexit -WorkingDirectory "%V""#).as_deref(),
            Some("powershell.exe")
        );
        assert_eq!(
            exe_from_command(r#"powershell.exe -noexit -WorkingDirectory "%V""#).as_deref(),
            Some("powershell.exe")
        );
        // 连扩展名都不写的（`notepad %1`）也认，由解析层补 .exe
        assert_eq!(exe_from_command("notepad %1").as_deref(), Some("notepad"));
        // 不是 exe 的开头必须 None：`"%1" %*` 这种系统 verb 压根没有可执行文件
        assert_eq!(exe_from_command(r#""%1" %*"#), None);
        assert_eq!(exe_from_command("-flag.exe"), None);
        assert_eq!(exe_from_command(""), None);
        assert_eq!(exe_from_command("   "), None);
    }

    /// 安装目录名：Program Files 系锚点优先，没有锚点才退父目录，系统目录不退
    #[test]
    fn install_dir_name_prefers_the_product_segment() {
        assert_eq!(
            install_dir_name(r"C:\Program Files\Tencent\WeChat\WeChatExt.dll").as_deref(),
            Some("Tencent")
        );
        assert_eq!(
            install_dir_name(r"C:\Program Files (x86)\WinRAR\ContextMenu.dll").as_deref(),
            Some("WinRAR")
        );
        // 文件直接躺在 Program Files 下：那一层不是「产品目录」，退到父目录名会得出
        // "Program Files" 这种没意义的组名 ⇒ 宁可不分组
        assert_eq!(install_dir_name(r"C:\Program Files\x.dll"), None);
        // 没有 Program Files 锚点 ⇒ 退一层父目录，但系统目录不退（会被并进「系统组件」误判）
        assert_eq!(install_dir_name(r"D:\Tools\Foo\bar.dll").as_deref(), Some("Foo"));
        assert_eq!(install_dir_name(r"C:\Windows\System32\shell32.dll"), None);
        // 商店包的容器目录不是产品名
        assert_eq!(install_dir_name(r"C:\Program Files\WindowsApps\x.dll"), None);
        assert_eq!(install_dir_name(""), None);
    }

    /// 归属优先级与「不猜」边界：判据顺序就是这条用例，改顺序必须连带改这里
    #[test]
    fn owner_of_priority_and_refusal_to_guess() {
        let sys = r"C:\WINDOWS";
        // 1) 系统组件要两条同时成立：文件在系统根下 **且** 厂商指向微软
        let ms = PeInfo { product: "Microsoft Windows".into(), company: "Microsoft Corporation".into(), description: String::new() };
        let (label, src) = owner_of(&ms, "", r"C:\Windows\System32\shell32.dll", sys);
        assert_eq!((label.as_str(), src.as_str()), ("Windows 系统组件", "system"));
        // 第三方 dll 恰好躺在系统目录下：绝不能并进「Windows 系统组件」
        let third = PeInfo { product: "某播放器壳".into(), company: "SomeVendor Inc.".into(), description: String::new() };
        let (label, src) = owner_of(&third, "", r"C:\Windows\Temp\v.dll", sys);
        assert_eq!((label.as_str(), src.as_str()), ("某播放器壳", "pe-product"));
        // 微软厂商但文件不在系统根下（Office 之类）⇒ 按产品名分组，不算系统组件
        let (label, src) = owner_of(&ms, "", r"C:\Program Files\Microsoft Office\root\OIS.dll", sys);
        assert_eq!((label.as_str(), src.as_str()), ("Microsoft Windows", "pe-product"));
        // 2) ProductName 缺失时用 FileDescription（国产壳扩展常只有这一段）
        let desc_only = PeInfo { description: "WinRAR Shell Extension".into(), ..Default::default() };
        let (label, src) = owner_of(&desc_only, "", r"C:\Program Files\WinRAR\c.dll", sys);
        assert_eq!((label.as_str(), src.as_str()), ("WinRAR Shell Extension", "pe-desc"));
        // 3) PE 全空 ⇒ 退注册表厂商；再空 ⇒ 退安装目录名
        let (label, src) = owner_of(&PeInfo::default(), "EagleGet", r"C:\Program Files\EagleGet\a.dll", sys);
        assert_eq!((label.as_str(), src.as_str()), ("EagleGet", "registry"));
        let (label, src) = owner_of(&PeInfo::default(), "", r"C:\Program Files\Bandizip\bz.dll", sys);
        assert_eq!((label.as_str(), src.as_str()), ("Bandizip", "dir"));
        // 4) 什么都不知道 ⇒ 空标签，让前端归进「未识别」，不硬造一个组名
        let (label, src) = owner_of(&PeInfo::default(), "", "", sys);
        assert!(label.is_empty() && src.is_empty(), "拿不准时必须不分组，实际得到 {label:?}/{src:?}");
    }

    /// 真读一个系统 DLL：纯函数测不到 Win32 那条链（Translation 对拼键名最容易错）。
    /// 缺文件时按 §2 显式跳过并说明，不 expect 炸。
    #[test]
    fn pe_info_of_reads_a_real_system_file() {
        let root = std::env::var("SystemRoot").unwrap_or_default();
        let path = format!(r"{root}\System32\shell32.dll");
        if !std::path::Path::new(&path).exists() {
            eprintln!("skip：本机没有 {path}，PE 读取这条未校验");
            return;
        }
        let info = unsafe { pe_info_of(&path) };
        assert!(
            !info.product.is_empty() || !info.description.is_empty(),
            "shell32.dll 必然带版本资源，三段全空说明 VerQueryValue 的键名拼错了（Translation 对没现读？）"
        );
        let (label, src) = owner_of(&info, "", &path, &root);
        assert_eq!(src, "system", "系统 DLL 的归属必须是「Windows 系统组件」，实际判成 {src} / {label}");
        assert_eq!(label, "Windows 系统组件");
    }

    /// 「第三方 / 系统原生」判据（真机审计 P1-9 换来的三条）：
    /// 看 PE 厂商，且不被 DriverStore/WinSxS 的存放位置骗到。
    #[test]
    fn third_party_verdict_uses_pe_company_and_not_the_windows_prefix() {
        // PE 厂商是微软 → 系统原生。真机原状：「旧版 Windows Media Player」被标成第三方
        assert!(!is_third_party("旧版 Windows Media Player", "Microsoft Corporation", "openwith", ""));
        // DriverStore 是第三方驱动包的落点，不能因「在 C:\Windows 下」就压成绿色
        assert!(is_third_party("NvAppShExt Class", "", "shellex",
            r"C:\Windows\System32\DriverStore\FileRepository\nv_dispsi.inf_amd64_d95662815b9b13a8\nv3dappshext.dll"));
        assert!(is_third_party("某组件", "", "shellex", r"C:\Windows\WinSxS\amd64_x\some.dll"));
        // 而真正躺在 System32 根下的系统文件仍算系统原生（这条不许被上面两条带坏）
        assert!(!is_third_party("库项", "", "shellex", r"C:\Windows\System32\shell32.dll"));
        // 已知系统动词名一律不标第三方
        assert!(!is_third_party("Open", "", "shell", ""));
        // 普通第三方
        assert!(is_third_party("WinRAR 压缩", "win.rar GmbH", "shellex", r"C:\Program Files\WinRAR\rarext.dll"));
    }

    /// 真机只读：跑一次完整扫描，打印「按软件分组」的分布。    ///
    /// 为什么要这条：分组质量只能拿真数据判 —— 未识别占比过高就说明这套判据在白做，
    /// 而这在纯函数用例里看不出来。`#[ignore]` 进发布前门禁组（它读全机注册表，慢且环境相关）。
    #[test]
    #[ignore = "真机只读扫描：读全机 shell 键与 PE，秒级到十几秒，发布前人工跑"]
    fn real_scan_owner_distribution() {
        // 裸名解析（真机才有这些文件）：`cmd.exe` 必须经 App Paths / System32 落到系统目录下，
        // 而不存在的名字必须返回 None —— 猜一个同路径出来会把归属算错
        let cmd = resolve_exe_for_owner("cmd.exe");
        assert!(
            cmd.as_deref().is_some_and(|p| p.to_ascii_lowercase().ends_with("cmd.exe")),
            "cmd.exe 应能解析到真实路径，实际 {cmd:?}"
        );
        assert_eq!(resolve_exe_for_owner("no-such-tool-trim-test.exe"), None, "不存在的裸名不许猜路径");
        // 带目录但不存在（卸载遗留）：不去 App Paths 碰运气
        assert_eq!(resolve_exe_for_owner(r"C:\gone\x.exe"), None);

        let items = cm_scan().expect("扫描失败");
        let mut by_src: std::collections::BTreeMap<String, usize> = Default::default();
        let mut groups: std::collections::BTreeMap<String, usize> = Default::default();
        for it in &items {
            let owner = it["owner"].as_str().unwrap_or("").to_string();
            let src = it["ownerSource"].as_str().unwrap_or("").to_string();
            *by_src.entry(if src.is_empty() { "(未识别)".into() } else { src }).or_default() += 1;
            *groups.entry(if owner.is_empty() { "(未识别)".into() } else { owner }).or_default() += 1;
        }
        println!("条目总数 {}，分组数 {}", items.len(), groups.len());
        println!("按判据来源：{by_src:?}");
        for (k, v) in groups.iter().rev().take(25) {
            println!("  {v:>3}  {k}");
        }
        let unknown = *by_src.get("(未识别)").unwrap_or(&0);
        // 未识别的都要能看见是为什么未识别（判据缺哪一级，看这条就知道）
        for it in items.iter().filter(|i| i["owner"].as_str().unwrap_or("").is_empty()).take(60) {
            let cmd = it["command"].as_str().unwrap_or("");
            println!(
                "  未识别: {} | {} | {} | cmd={:?} → exe={:?} → 解析={:?} | file={:?}",
                it["name"].as_str().unwrap_or(""),
                it["category"].as_str().unwrap_or(""),
                it["source"].as_str().unwrap_or(""),
                cmd,
                exe_from_command(cmd),
                exe_from_command(cmd).and_then(|r| resolve_exe_for_owner(&r)),
                it["filePath"].as_str().unwrap_or(""),
            );
        }
        assert!(
            items.len() < 2 || unknown * 2 < items.len(),
            "未识别占比过半（{unknown}/{}），这套判据不足以支撑按软件分组，得回炉",
            items.len()
        );
    }
}

#[cfg(test)]
mod path_edit_tests {
    use super::*;

    /// 重命名类切换回写的新路径：换叶子必须保留原来的根，且只换最后一段。
    #[test]
    fn swap_last_segment_keeps_root() {
        assert_eq!(
            swap_last_segment(r"HKEY_CURRENT_USER\Software\Classes\*\shellex\ContextMenuHandlers\-Foo", "Foo"),
            r"HKEY_CURRENT_USER\Software\Classes\*\shellex\ContextMenuHandlers\Foo"
        );
        // 二分到「非 HKCU 就是 HKLM」会把 HKCR/HKU 写回一个不存在的坐标（真机审计 P2-16）
        assert_eq!(
            swap_last_segment(r"HKEY_USERS\.DEFAULT\Software\Classes\-A", "A"),
            r"HKEY_USERS\.DEFAULT\Software\Classes\A"
        );
        assert_eq!(swap_last_segment("NoBackslashHere", "Leaf"), "Leaf");
    }
}
