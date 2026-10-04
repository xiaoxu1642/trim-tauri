//! 卸载域自含的注册表读取助手与「本次会话残留快照」台账（v3 D2）。
//!
//! 刻意**不**改用 `engine::native` 的私有层：本域的 hive 准入只放行 HKCU/HKLM
//! （残留清理面不覆盖 HKCR/HKU/HKCC），收紧的口径写在 parse_reg_target 里，
//! 与 native 那份宽口径不是同一个契约。
//! RESIDUE_SNAPSHOTS 是「执行只认快照」这条安全前置的唯一载体，故与取它的函数同文件。

use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
/// 残留扫描快照：label -> (时间戳, findings)。执行只认快照内的 kind+target 组合。
pub(super) static RESIDUE_SNAPSHOTS: OnceLock<Mutex<HashMap<String, (i64, Vec<Value>)>>> = OnceLock::new();

pub(super) fn residue_snapshots() -> &'static Mutex<HashMap<String, (i64, Vec<Value>)>> {
    RESIDUE_SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ==================== 注册表读取助手（本文件自含，不动 native.rs 私有层） ====================

pub(super) unsafe fn reg_sz(hk: windows::Win32::System::Registry::HKEY, name: &str) -> Option<String> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        return None;
    }
    if ty.0 != 1 && ty.0 != 2 {
        return None; // 只读 REG_SZ / REG_EXPAND_SZ
    }
    let mut buf = vec![0u8; size as usize];
    let ok = RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size)).is_ok();
    if !ok || size == 0 {
        return None;
    }
    let words: Vec<u16> = buf[..size as usize]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    Some(String::from_utf16_lossy(&words).trim().to_string())
}

pub(super) unsafe fn reg_dword(hk: windows::Win32::System::Registry::HKEY, name: &str) -> Option<u32> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        return None;
    }
    if ty.0 != 4 || size < 4 {
        return None; // 只认 REG_DWORD
    }
    let mut buf = [0u8; 4];
    let ok = RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size)).is_ok();
    if !ok {
        return None;
    }
    Some(u32::from_le_bytes(buf))
}

/// REG_MULTI_SZ → 非空字符串段集合（`\0\0` 结尾，段内 `\0` 分隔）。
/// 服务表的 `DependOnService` / `Group` 就是这个类型，`reg_sz` 会直接判类型不符返回 None。
pub(super) unsafe fn reg_multi_sz(hk: windows::Win32::System::Registry::HKEY, name: &str) -> Vec<String> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        return Vec::new();
    }
    if ty.0 != 7 || size < 4 {
        return Vec::new(); // 只认 REG_MULTI_SZ（至少要两个 NUL 才是合法空表）
    }
    let mut buf = vec![0u8; size as usize];
    let mut got = size;
    if RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut got)).is_err() {
        return Vec::new();
    }
    buf[..got as usize]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect::<Vec<u16>>()
        .split(|&w| w == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf16_lossy(s))
        .collect()
}

/// 以 KEY_READ 打开一个键；打不开返回 None（读不到 = 无证据，不是「不存在」）。
/// 调用方用完必须 `RegCloseKey`，本函数不接管生命周期以免出现两条关闭路径。
pub(super) unsafe fn open_key_read(
    hive: windows::Win32::System::Registry::HKEY,
    subkey: &str,
) -> Option<windows::Win32::System::Registry::HKEY> {
    use windows::Win32::System::Registry::{KEY_READ, RegOpenKeyExW};
    let sk = to_wide(subkey);
    let mut hk = windows::Win32::System::Registry::HKEY::default();
    if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
        Some(hk)
    } else {
        None
    }
}

/// 枚举键下的**全部值名**（不取数据、不看类型）。
///
/// 与 `residue::reg_enum_sz_values` 的分工：那个只收 REG_SZ/REG_EXPAND_SZ 且带数据，
/// 适合「拿值内容去匹配路径」；这里要的是「这个键下一共有哪些值、叫什么」，
/// DWORD 值也必须算进来（IFEO 的 PerfOptions、ConsentStore 的允许位都是 DWORD）。
pub(super) unsafe fn reg_value_names(hk: windows::Win32::System::Registry::HKEY, cap: usize) -> Vec<String> {
    use windows::Win32::System::Registry::RegEnumValueW;
    let mut out = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        if RegEnumValueW(hk, index, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None).is_err() {
            break;
        }
        index += 1;
        let n = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        if !n.is_empty() {
            out.push(n);
        }
        if out.len() >= cap {
            break;
        }
    }
    out.sort();
    out
}

/// 解析 "HKCU\..." / "HKLM\..." 前缀（与 engine::native::parse_reg_path 同口径，
/// 但只放行 HKCU/HKLM 两个 hive —— 残留清理面不覆盖 HKCR/HKU/HKCC）。
pub(super) fn parse_reg_target(target: &str) -> Option<(windows::Win32::System::Registry::HKEY, String)> {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let t = target.trim();
    for (prefix, hive) in [
        ("HKEY_CURRENT_USER\\", HKEY_CURRENT_USER),
        ("HKCU\\", HKEY_CURRENT_USER),
        ("HKEY_LOCAL_MACHINE\\", HKEY_LOCAL_MACHINE),
        ("HKLM\\", HKEY_LOCAL_MACHINE),
    ] {
        if t.len() > prefix.len()
            && t[..prefix.len()].eq_ignore_ascii_case(prefix)
        {
            return Some((hive, t[prefix.len()..].trim_start_matches('\\').to_string()));
        }
    }
    None
}

/// Appx 包全名准入：只允许 `[A-Za-z0-9._-]`（PackageFullName 的合法字符集），
/// 喂给 PowerShell 前必须过这道闸（防引号/换行注入命令串）。

pub(super) fn valid_uninstall_key_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.starts_with("software\\")
        && p.contains("microsoft\\windows\\currentversion\\uninstall\\")
        && !p.contains("..")
        && !p.contains('%')
}

