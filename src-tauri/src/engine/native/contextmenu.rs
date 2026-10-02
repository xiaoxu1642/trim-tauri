//! B6 右键菜单全链：win11 模式、屏蔽清单、深度扫描、启停、删除、备份、防篡改恢复、explorer 重启。
//!
//! 本域是 native 里最大的一块（约 2.4k 行），写侧副作用真实（RegRenameKey 改 Verbs、
//! 删 clsid、导入 .reg 还原、杀 explorer）。COM 类名与厂商判定表（PROTECTED_CLASSES /
//! KNOWN_SYSTEM）是本域判据真源，改动等于改判定结果。
//! 注册表底层枚举/读取在 `registry.rs`；本文件只做业务组装。


use crate::engine::systembin::system_tool;
use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, FreeLibrary, HMODULE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_CREATED_NEW_KEY, REG_CREATE_KEY_DISPOSITION, REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegRenameKey, RegSetValueExW};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
use windows::Win32::UI::WindowsAndMessaging::LoadStringW;
use super::common::*;
use super::registry::*;
// ==================== B6：右键菜单 ====================


/// Win11 经典/现代右键菜单切换（对应 cm_win11_mode.ps1）
///
/// action: "get" / "set-classic" / "set-modern"
pub fn cm_win11_mode(action: &str) -> Result<Value, String> {
    const CLSID_PATH: &str = r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}";
    const INPROC_PATH: &str = r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32";

    unsafe {
        // 读当前模式
        let get_mode = || -> &'static str {
            let sk = to_wide(INPROC_PATH);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
                return "modern";
            }
            // 读默认值（空名）
            let empty = to_wide("");
            let mut ty = REG_VALUE_TYPE::default();
            let mut size = 0u32;
            let r = RegQueryValueExW(hk, PCWSTR(empty.as_ptr()), None, Some(&mut ty), None, Some(&mut size));
            let _ = RegCloseKey(hk);
            if r.is_err() { return "modern"; }
            // 默认值存在且为空字符串 → classic
            "classic"
        };

        let before = get_mode();
        if action == "get" {
            return Ok(json!({ "success": true, "mode": before, "changed": false, "requireRestart": false }));
        }

        let target_mode = if action == "set-classic" { "classic" }
            else if action == "set-modern" { "modern" }
            else { return Ok(json!({ "success": false, "mode": before, "changed": false, "message": "未知动作" })); };

        if action == "set-classic" {
            let sk = to_wide(INPROC_PATH);
            let mut hk = HKEY::default();
            let mut disposition = REG_CREATE_KEY_DISPOSITION(0);
            let r = RegCreateKeyExW(
                HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), None,
                REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut hk, Some(&mut disposition),
            );
            if r.is_err() { return Err(format!("创建注册表键失败: 错误码 {}", r.0)); }
            // 写空字符串默认值（必须存在，不是不写）；一个 null u16 = 4 字节
            let empty = to_wide("");
            let data: [u8; 4] = [0, 0, 0, 0];
            let r2 = RegSetValueExW(
                hk, PCWSTR(empty.as_ptr()), Some(0), REG_SZ, Some(&data),
            );
            if r2.is_err() { return Err(format!("写入默认值失败: 错误码 {}", r2.0)); }
            let _ = RegCloseKey(hk);
        } else {
            // set-modern：删除整个 CLSID 键树
            let sk = to_wide(CLSID_PATH);
            let r = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()));
            if r.is_err() { return Err(format!("删除注册表键失败: 错误码 {}", r.0)); }
        }

        let after = get_mode();
        let success = after == target_mode;
        Ok(json!({
            "success": success,
            "mode": after,
            "changed": after != before,
            "requireRestart": true,
            "message": if success { "已切换，重启资源管理器后生效" } else { "切换未生效" },
        }))
    }
}

/// 被拦截的右键项清单（对应 cm_blocked_list.ps1，只读）
pub fn cm_blocked_list() -> Result<Value, String> {
    let roots: &[(HKEY, &str, &str)] = &[
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked", "machine"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked", "user"),
    ];
    let mut entries: Vec<Value> = Vec::new();
    unsafe {
        for (hive, subkey, scope) in roots {
            let sk = to_wide(&subkey);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(*hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
                continue;
            }
            let names = reg_enum_values(hk);
            for name in names {
                let g = name.trim();
                // GUID 格式：{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
                if g.len() == 38
                    && g.starts_with('{') && g.ends_with('}')
                    && g.as_bytes().iter().skip(1).take(8).all(|b| b.is_ascii_hexdigit())
                {
                    entries.push(json!({ "guid": g, "scope": scope }));
                }
            }
            let _ = RegCloseKey(hk);
        }
    }
    Ok(json!({ "success": true, "entries": entries }))
}

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
                let name = String::from_utf16_lossy(&pe.szExeFile);
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

        let killed = targets.len();
        // 记录唯一路径
        let paths: Vec<String> = targets.iter().map(|(_, p)| p.clone())
            .filter(|p| !p.is_empty()).collect::<std::collections::HashSet<_>>()
            .into_iter().collect();

        // 逐个杀
        for (pid, _) in &targets {
            if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, *pid) {
                let _ = TerminateProcess(h, 1);
                let _ = CloseHandle(h);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(700));

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
                    let name = String::from_utf16_lossy(&pe2.szExeFile);
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
        expand_env(&dll_part)
    };
    if !std::path::Path::new(&dll_path).exists() { return None; }
    let dll_w = to_wide(&dll_path);
    let Ok(hmod) = LoadLibraryW(PCWSTR(dll_w.as_ptr())) else { return None; };
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
fn is_third_party(name: &str, company: &str, source: &str, file_path: &str) -> bool {
    let cl = company.to_lowercase();
    if cl.contains("microsoft") || cl.contains("windows corporation") { return false; }
    if company.is_empty() && file_path.to_lowercase().starts_with(r"c:\windows") { return false; }
    if KNOWN_SYSTEM.contains(&name) { return false; }
    if source == "shell" {
        let nl = name.to_lowercase();
        if nl.contains("windows") || nl.contains("system32") || nl.contains("shell32") { return false; }
    }
    true
}

/// CLSID 信息（名称/厂商/文件路径）
struct ClsidInfo { name: String, company: String, file_path: String }

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
                items.push(CmItem {
                    name, clsid: String::new(), reg_path: full.clone(), native_reg_path: full.clone(),
                    company, location: sendto_dir.clone(), category: "发送到".to_string(),
                    source: "filesystem".to_string(), file_path: String::new(), command: String::new(),
                    enabled: true, confirm_required: false, confirm_reason: String::new(),
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
                if RegOpenKeyExW(*hive, PCWSTR(apk.as_ptr()), Some(0), KEY_READ, &mut aphk).is_ok() {
                    if let Some(f) = reg_read_string(aphk, "FriendlyAppName") {
                        if !f.trim().is_empty() { friendly = direct_string(&f); }
                    }
                    if friendly.is_empty() { friendly = app.clone(); }
                    no_open = reg_value_exists(aphk, "NoOpenWith");
                    let _ = RegCloseKey(aphk);
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
                    file_path: String::new(), command: verbs.join(", "),
                    enabled: !no_open, confirm_required: false, confirm_reason: String::new(),
                    unknown_convention: false, blocked_by: String::new(), target: String::new(),
                    orphan: false, orphan_reason: String::new(),
                });
            }
            let _ = RegCloseKey(ahk);
        }

        // ---- 去重 ----
        let mut dedup: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut result: Vec<Value> = Vec::new();
        for item in items {
            let enabled_text = if item.enabled { "1" } else { "0" };
            let key = if item.clsid.is_empty() {
                format!("{}|{}|{}|{}|{}", item.category, item.name, item.source, item.native_reg_path, enabled_text)
            } else {
                format!("{}|{}|{}|{}", item.category, item.name, item.clsid, enabled_text)
            };
            if !dedup.insert(key) { continue; }

            let is_protected = PROTECTED_CLASSES.contains(&item.clsid.as_str());
            let is_tp = is_third_party(&item.name, &item.company, &item.source, &item.file_path);
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
            format!("HKEY_CURRENT_USER\\{}", key_path.trim_start_matches(r"Software\\"))
        } else {
            format!("HKEY_LOCAL_MACHINE\\{}", key_path.trim_start_matches(r"SOFTWARE\\"))
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
                    format!("HKEY_CURRENT_USER\\{}", key_path.trim_start_matches(r"Software\\"))
                } else {
                    format!("HKEY_LOCAL_MACHINE\\{}", key_path.trim_start_matches(r"SOFTWARE\\"))
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
            format!("HKEY_CURRENT_USER\\{}", key_path.trim_start_matches(r"Software\\"))
        } else {
            format!("HKEY_LOCAL_MACHINE\\{}", key_path.trim_start_matches(r"SOFTWARE\\"))
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
                results.push(json!({"id": id, "name": name, "regPath": display_path, "status": "skip", "message": "系统保护项"}));
                continue;
            }
            if target.is_empty() {
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

        Ok(json!({"success": success, "failed": failed, "results": results}))
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
            leaf.trim_end_matches(".disabled").trim_end_matches(".DISABLED").to_string()
        } else {
            format!("{leaf}.disabled")
        };
        let parent = std::path::Path::new(target).parent().unwrap();
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
                        // 重命名
                        let new_name = to_wide(&renamed_to);
                        let parent_sk = to_wide(parent);
                        let mut parent_hk = HKEY::default();
                        if RegOpenKeyExW(hive, PCWSTR(parent_sk.as_ptr()), Some(0), KEY_WRITE, &mut parent_hk).is_ok() {
                            let _ = RegRenameKey(parent_hk, PCWSTR(to_wide(&leaf).as_ptr()), PCWSTR(new_name.as_ptr()));
                            let _ = RegCloseKey(parent_hk);
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
                let std_new = if hive == HKEY_CURRENT_USER { format!("HKEY_CURRENT_USER\\{reg_path}") } else { format!("HKEY_LOCAL_MACHINE\\{reg_path}") };
                res["newNativeRegPath"] = json!(std_new);
                if let Some(dpos) = display_path.rfind('\\') {
                    res["newRegPath"] = json!(format!("{}{}", &display_path[..=dpos], renamed_to));
                }
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
        let new_path = format!("{parent}\\{new_name}");
        let std_new = if hive == HKEY_CURRENT_USER { format!("HKEY_CURRENT_USER\\{new_path}") } else { format!("HKEY_LOCAL_MACHINE\\{new_path}") };
        let new_display = if let Some(dpos) = display_path.rfind('\\') {
            format!("{}{}", &display_path[..=dpos], new_name)
        } else { new_name.clone() };
        return Ok(json!({"status": "ok", "newRegPath": new_display, "newNativeRegPath": std_new, "message": if want_enabled { "已启用" } else { "已禁用" }}));
    }

    Err(format!("未知 source 类型: {source}"))
}

// ==================== B6 cm_remove：右键菜单删除 ====================

/// 右键菜单删除（对应 cm_remove.ps1，S3）
///
/// 删除注册表键（RegDeleteTreeW 递归删除）。文件系统项由主进程回收站删除，
/// shellnew 项通过启停管理（禁止整键删除），系统保护项拒绝。
pub fn cm_remove(items: &[Value]) -> Result<Value, String> {
    unsafe {
        let mut results: Vec<Value> = Vec::new();
        let mut success = 0i64;
        let mut failed = 0i64;

        for item in items {
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let source = item.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let risk = item.get("risk").and_then(|v| v.as_str()).unwrap_or("");

            if risk == "protected" {
                results.push(json!({"id": id, "name": name, "status": "skip", "message": "系统保护项"}));
                continue;
            }
            // 文件系统项由主进程回收站删除
            if source == "filesystem" || source == "winx" {
                results.push(json!({"id": id, "name": name, "status": "skip", "message": "文件系统项由主进程回收站删除"}));
                continue;
            }
            // shellnew 禁止整键删除
            if source == "shellnew" {
                results.push(json!({"id": id, "name": name, "status": "skip", "message": "新建菜单项请通过启停操作管理，禁止整键删除"}));
                continue;
            }

            let mut target = item.get("nativeRegPath").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if target.is_empty() { target = item.get("regPath").and_then(|v| v.as_str()).unwrap_or("").to_string(); }
            if target.is_empty() {
                results.push(json!({"id": id, "name": name, "status": "skip", "message": "无效或过宽路径"}));
                continue;
            }
            // 路径校验：不能是根键
            let lower = target.to_lowercase();
            if lower == "hkey_classes_root" || lower == "hkey_local_machine" || lower == "hkey_current_user"
                || lower == "hkey_users" || lower == "hkey_current_config"
                || lower.starts_with("hkey_classes_root\\") && !lower.contains("\\") {
                results.push(json!({"id": id, "name": name, "status": "skip", "message": "无效或过宽路径"}));
                continue;
            }

            let (hive, subkey) = match parse_reg_path(&target) {
                Some(v) => v,
                None => { results.push(json!({"id": id, "name": name, "status": "skip", "message": "注册表路径格式错误"})); continue; }
            };

            // 检查键是否存在
            let sk = to_wide(&subkey);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
                results.push(json!({"id": id, "name": name, "status": "skip", "message": "路径不存在"}));
                continue;
            }
            let _ = RegCloseKey(hk);

            // 删除键（需要父键的 DELETE 权限）
            if let Some(pos) = subkey.rfind('\\') {
                let parent = &subkey[..pos];
                let leaf = &subkey[pos+1..];
                let parent_sk = to_wide(parent);
                let mut parent_hk = HKEY::default();
                if RegOpenKeyExW(hive, PCWSTR(parent_sk.as_ptr()), Some(0), KEY_WRITE, &mut parent_hk).is_err() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "无法打开父键（可能需要管理员权限）"}));
                    continue;
                }
                let leaf_nm = to_wide(leaf);
                let r = RegDeleteTreeW(parent_hk, PCWSTR(leaf_nm.as_ptr()));
                let _ = RegCloseKey(parent_hk);
                if r.is_err() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "删除失败（可能需要管理员权限）"}));
                } else {
                    // 回读确认
                    let sk2 = to_wide(&subkey);
                    let mut hk2 = HKEY::default();
                    let still_exists = RegOpenKeyExW(hive, PCWSTR(sk2.as_ptr()), Some(0), KEY_READ, &mut hk2).is_ok();
                    if still_exists { let _ = RegCloseKey(hk2); }
                    if still_exists {
                        failed += 1;
                        results.push(json!({"id": id, "name": name, "status": "error", "message": "删除后键仍存在（可能被占用或权限不足）"}));
                    } else {
                        success += 1;
                        results.push(json!({"id": id, "name": name, "status": "ok", "message": "已删除"}));
                    }
                }
            } else {
                // 直接是根键下的一级键，用 RegDeleteTreeW(hive, leaf)
                let leaf_nm = to_wide(&subkey);
                let r = RegDeleteTreeW(hive, PCWSTR(leaf_nm.as_ptr()));
                if r.is_err() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "删除失败（可能需要管理员权限）"}));
                } else {
                    success += 1;
                    results.push(json!({"id": id, "name": name, "status": "ok", "message": "已删除"}));
                }
            }
        }

        Ok(json!({"success": success, "failed": failed, "results": results}))
    }
}
// ==================== B6 cm_backup：右键菜单备份 ====================

fn desktop_dir() -> std::path::PathBuf {
    if let Ok(desktop) = std::env::var("USERPROFILE") {
        let p = std::path::PathBuf::from(desktop).join("Desktop");
        if p.exists() { return p; }
    }
    std::path::PathBuf::from(r"C:\Users\Public\Desktop")
}

fn reg_file_header_hive(file: &std::path::Path) -> Option<String> {
    let content = std::fs::read_to_string(file).ok()?;
    for line in content.lines().take(8) {
        let t = line.trim();
        if t.starts_with('[') {
            let h = &t[1..];
            for root in ["HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_USERS"] {
                if h.starts_with(root) { return Some(root.to_string()); }
            }
            return Some("OTHER".to_string());
        }
    }
    None
}

/// 右键菜单备份（对应 cm_backup.ps1，S3）
///
/// 在桌面创建「右键菜单备份_时间戳」目录，注册表项用 reg.exe export 导出 .reg，
/// 文件项复制到 files/ 子目录，生成 manifest.json。
pub fn cm_backup(items: &[Value]) -> Result<Value, String> {
    let now_ms = crate::engine::now_ms();
    let stamp = format!("{}", now_ms);
    let backup_dir = desktop_dir().join(format!("右键菜单备份_{stamp}"));
    let files_dir = backup_dir.join("files");
    std::fs::create_dir_all(&files_dir).map_err(|e| format!("创建备份目录失败: {e}"))?;

    let mut backup_files: Vec<String> = Vec::new();
    let mut file_records: Vec<Value> = Vec::new();
    let mut reg_records: Vec<Value> = Vec::new();
    let mut exported = 0i64;
    let mut copied = 0i64;
    let mut failed = 0i64;

    for (index, item) in items.iter().enumerate() {
        let idx = index + 1;
        let source = item.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let reg_path = item.get("regPath").and_then(|v| v.as_str()).unwrap_or("");

        // 文件类来源：复制备份
        if source == "filesystem" || source == "winx" {
            if !std::path::Path::new(reg_path).exists() { continue; }
            let file_name = std::path::Path::new(reg_path).file_name().and_then(|n| n.to_str()).unwrap_or("file");
            let stem = std::path::Path::new(file_name).file_stem().and_then(|s| s.to_str()).unwrap_or("file");
            let ext = std::path::Path::new(file_name).extension().and_then(|e| e.to_str()).unwrap_or("");
            let dest_name = format!("file_{idx}_{stem}_{ext}");
            let dest = files_dir.join(&dest_name);
            if std::fs::copy(reg_path, &dest).is_ok() {
                let dest_str = dest.to_string_lossy().to_string();
                file_records.push(json!({"source": reg_path, "backup": dest_str}));
                backup_files.push(dest_str);
                copied += 1;
            } else {
                failed += 1;
            }
            continue;
        }

        // 注册表类：reg.exe export
        let mut write_path = item.get("nativeRegPath").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if write_path.is_empty() { write_path = reg_path.to_string(); }
        if write_path.is_empty() { failed += 1; continue; }
        // 拒绝 HKCR 头
        if write_path.starts_with("HKEY_CLASSES_ROOT\\") || write_path == "HKEY_CLASSES_ROOT" {
            failed += 1;
            continue;
        }
        // 转换为 reg.exe 短路径
        let native_path = write_path
            .replace("HKEY_CURRENT_USER", "HKCU")
            .replace("HKEY_LOCAL_MACHINE", "HKLM")
            .replace("HKEY_USERS", "HKU")
            .replace("HKEY_CLASSES_ROOT", "HKCR");
        // 安全文件名
        let mut safe_name = native_path.clone();
        safe_name = safe_name.replace('\\', "_").replace('/', "_").replace(':', "_").replace('*', "_")
            .replace('?', "_").replace('"', "_").replace('<', "_").replace('>', "_").replace('|', "_");
        // v2-L4P-32（C-4）：按字符截断——`safe_name[高字节切片]` 在含中文键名时
        // 会切在 UTF-8 多字节序列中间直接 panic（同族已修过、此处是漏网点）。
        if safe_name.chars().count() > 120 {
            let keep: String = safe_name.chars().rev().take(120).collect::<Vec<_>>()
                .into_iter().rev().collect();
            safe_name = keep;
        }
        let reg_file = backup_dir.join(format!("registry_{idx}_{safe_name}.reg"));

        // reg.exe export
        // 审查 v3-L7：非 UTF-8 路径上 to_str() 为 None，记失败跳过而不是 panic
        let Some(reg_file_str) = reg_file.to_str() else { failed += 1; continue; };
        // v2-L4P-29（B-7）：备份类子进程统一走带超时入口
        let out = crate::engine::systembin::quiet_cmd_timeout(
            system_tool("reg.exe"),
            &["export", &write_path, reg_file_str, "/y"],
            crate::engine::systembin::REG_EXPORT_TIMEOUT,
        );
        let success = out.map(|o| o.status.success()).unwrap_or(false);
        let header_hive = reg_file_header_hive(&reg_file);
        let hive_ok = header_hive.as_ref()
            .map(|h| h != "HKEY_CLASSES_ROOT" && write_path.starts_with(h))
            .unwrap_or(false);

        if success && hive_ok {
            let reg_str = reg_file.to_string_lossy().to_string();
            backup_files.push(reg_str.clone());
            reg_records.push(json!({"source": write_path, "backup": reg_str, "hive": header_hive.unwrap_or_default()}));
            exported += 1;
        } else {
            let _ = std::fs::remove_file(&reg_file);
            failed += 1;
        }
    }

    // 生成 manifest.json
    let manifest = json!({
        "version": 2,
        "created": now_ms,
        "items": items,
        "files": file_records,
        "registryFiles": reg_records,
    });
    let manifest_path = backup_dir.join("manifest.json");
    // 审查 v3-L1：manifest 是还原侧 fail-closed 的判据（缺失/不可解析即拒绝导入），
    // 直写崩溃会留下半截 JSON 让整份备份变废纸 —— 走原子写，失败要如实记账
    let manifest_ok = crate::security::atomic_write_json(&manifest_path, &manifest).is_ok();

    Ok(json!({
        "backupDir": backup_dir.to_string_lossy().to_string(),
        "files": backup_files,
        "count": exported + copied,
        "exported": exported,
        "copied": copied,
        "failed": failed,
        "manifestOk": manifest_ok,
    }))
}
// ==================== B6 cm_restore：右键菜单防篡改恢复 ====================

fn reg_file_all_keys(file: &std::path::Path) -> Vec<String> {
    let mut keys = Vec::new();
    if let Ok(content) = std::fs::read_to_string(file) {
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with('[') && t.ends_with(']') {
                let key = &t[1..t.len()-1];
                keys.push(key.trim_end_matches('\\').to_string());
            }
        }
    }
    keys
}

fn reg_key_allowed_for_restore(key: &str) -> bool {
    let p = key.trim();
    // 转换长 hive 为短名
    let p = p
        .replace("HKEY_LOCAL_MACHINE", "HKLM")
        .replace("HKEY_CURRENT_USER", "HKCU")
        .replace("HKEY_USERS", "HKU")
        .replace("HKEY_CLASSES_ROOT", "HKCR")
        .replace("HKEY_CURRENT_CONFIG", "HKCC");
    p.starts_with("HKLM\\SOFTWARE\\Classes\\") || p.starts_with("HKCU\\SOFTWARE\\Classes\\")
}

/// 右键菜单防篡改恢复（对应 cm_restore.ps1，S3）
///
/// 从桌面最新「右键菜单备份_*」目录恢复，三道安全闸门：
/// ① .reg 必须在 manifest.registryFiles 登记且在备份目录内
/// ② .reg 正文每条键路径都过白名单（HKLM/HKCU\SOFTWARE\Classes\）
/// ③ 文件项 source 必须在 SendTo/WinX 合法目录内
pub fn cm_restore() -> Result<Value, String> {
    let desktop = desktop_dir();
    // 找最新备份目录
    let mut backup_dirs: Vec<std::path::PathBuf> = std::fs::read_dir(&desktop)
        .map_err(|e| format!("读取桌面失败: {e}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("右键菜单备份_")).unwrap_or(false))
        .collect();
    backup_dirs.sort_by(|a, b| {
        let ta = a.metadata().and_then(|m| m.modified()).ok();
        let tb = b.metadata().and_then(|m| m.modified()).ok();
        tb.cmp(&ta)
    });
    let Some(latest_backup) = backup_dirs.first() else {
        return Ok(json!({"success": false, "message": "未找到备份目录"}));
    };
    let backup_prefix = latest_backup.to_string_lossy().to_string() + "\\";

    // 读 manifest
    let manifest_path = latest_backup.join("manifest.json");
    let manifest: Value = std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);

    let mut listed_backups: Vec<String> = Vec::new();
    if let Some(regs) = manifest.get("registryFiles").and_then(|v| v.as_array()) {
        for rec in regs {
            if let Some(b) = rec.get("backup").and_then(|v| v.as_str()) {
                if let Ok(full) = std::fs::canonicalize(b) {
                    listed_backups.push(full.to_string_lossy().to_string());
                } else {
                    listed_backups.push(b.to_string());
                }
            }
        }
    }

    let mut imported = 0i64;
    let mut failed = 0i64;
    let mut skipped = 0i64;
    let mut skip_reasons: Vec<String> = Vec::new();

    if manifest.is_null() {
        skip_reasons.push("manifest.json 缺失或不可解析：本次拒绝导入任何 .reg".into());
    }

    // 处理 registry_*.reg
    if let Ok(entries) = std::fs::read_dir(latest_backup) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with("registry_") || !name.ends_with(".reg") { continue; }

            let full = match std::fs::canonicalize(&path) {
                Ok(f) => f.to_string_lossy().to_string(),
                Err(_) => { skipped += 1; skip_reasons.push(format!("{name}（无法解析路径）")); continue; }
            };
            // ① 在备份目录内
            if !full.starts_with(&backup_prefix) && !full.starts_with(&latest_backup.to_string_lossy().to_string()) {
                skipped += 1;
                skip_reasons.push(format!("{name}（不在本次选中的备份目录内，已拒绝导入）"));
                continue;
            }
            // ① 在 manifest 登记
            let listed = listed_backups.iter().any(|b| b.eq_ignore_ascii_case(&full) || b.eq_ignore_ascii_case(&path.to_string_lossy()));
            if !listed {
                skipped += 1;
                skip_reasons.push(format!("{name}（未在 manifest.registryFiles 登记，已拒绝导入）"));
                continue;
            }
            // ② 头部 hive 校验
            let hdr = reg_file_header_hive(&path);
            if hdr.is_none() || hdr.as_deref() == Some("HKEY_CLASSES_ROOT") || hdr.as_deref() == Some("OTHER") {
                skipped += 1;
                let hdr_text = hdr.unwrap_or_else(|| "无法识别".into());
                skip_reasons.push(format!("{name}（备份头为 {hdr_text}，非真实 hive，已拒绝导入）"));
                continue;
            }
            // ② 逐条键路径白名单
            let keys = reg_file_all_keys(&path);
            let mut bad_key = String::new();
            if keys.is_empty() { bad_key = "正文里没有可识别的键行".into(); }
            for k in &keys {
                if !reg_key_allowed_for_restore(k) { bad_key = k.clone(); break; }
            }
            if !bad_key.is_empty() {
                skipped += 1;
                skip_reasons.push(format!("{name}（键路径不在右键菜单合法范围内，已拒绝导入：{bad_key}）"));
                continue;
            }
            // A6（v2-R4）：原生 `.reg` 写入，替换 `reg.exe import`。
            // 备份是 reg.exe export 产的 UTF-16LE，编码感知收在
            // `reg_backup::read_reg_text_file` 一处，不在这里各解一遍。
            // 原来那档「路径 to_str() 为 None 就跳过」（审查 v3-L7）随 reg.exe 一起消失 ——
            // 那是外部进程需要字符串参数才有的限制，原生拿 &Path 不受影响。
            // 失败原因现在进 skip_reasons（旧实现只 failed += 1，用户看不到为什么没还原上）。
            if let Err(e) = crate::engine::reg_backup::reg_import_apply(&path) {
                failed += 1;
                skip_reasons.push(format!("{name}（还原写入失败：{e}）"));
                continue;
            }
            // 导入后回读
            let first_key = keys.first().cloned().unwrap_or_default();
            if !first_key.is_empty() {
                if let Some((hive, subkey)) = parse_reg_path(&first_key) {
                    let sk = to_wide(&subkey);
                    let mut hk = HKEY::default();
                    let exists = unsafe { RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() };
                    if exists { unsafe { let _ = RegCloseKey(hk); } }
                    if !exists {
                        failed += 1;
                        skip_reasons.push(format!("{name}（reg import 报成功但键未出现）"));
                        continue;
                    }
                }
            }
            imported += 1;
        }
    }

    // 文件项恢复
    let mut restored = 0i64;
    if let Some(files) = manifest.get("files").and_then(|v| v.as_array()) {
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let programdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let allowed_roots = [
            format!("{appdata}\\Microsoft\\Windows\\SendTo"),
            format!("{programdata}\\Microsoft\\Windows\\SendTo"),
            format!("{localappdata}\\Microsoft\\Windows\\WinX"),
        ];
        for record in files {
            let b = record.get("backup").and_then(|v| v.as_str()).unwrap_or("");
            let s = record.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let b_full = std::fs::canonicalize(b).unwrap_or_else(|_| std::path::PathBuf::from(b)).to_string_lossy().to_string();
            let ok_backup = b_full.starts_with(&backup_prefix) || b_full.starts_with(&latest_backup.to_string_lossy().to_string());
            let ok_source = allowed_roots.iter().any(|r| s.starts_with(&format!("{r}\\")));
            if !ok_backup || !ok_source {
                skipped += 1;
                skip_reasons.push(format!("文件项（来源不在发送到/Win+X 合法目录内，已拒绝还原：{s}）"));
                continue;
            }
            if std::path::Path::new(b).exists() && !s.is_empty() {
                if let Some(parent) = std::path::Path::new(s).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if std::fs::copy(b, s).is_ok() {
                    restored += 1;
                } else {
                    failed += 1;
                }
            }
        }
    }

    Ok(json!({
        "success": (imported + restored) > 0 && failed == 0,
        "backupDir": latest_backup.to_string_lossy().to_string(),
        "imported": imported,
        "restored": restored,
        "skipped": skipped,
        "skipReasons": skip_reasons,
        "failed": failed,
    }))
}
