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

/// 字符串类注册表值的字节上限（M-13，审查 2026-10-07）。
///
/// `RegQueryValueExW` 首次查询回报的 `size` 直接来自注册表数据，随后被用来
/// `vec![0u8; size as usize]`。损坏或恶意写入的值可回报一个超大 size 让分配直接 OOM/panic。
/// 正常 REG_SZ / REG_MULTI_SZ 远小于此（注册表值本身有 1MB 量级上限），超限一律按
/// 「读不到」处理（fail-closed），绝不按报告的长度去分配。
const MAX_REG_STR_BYTES: u32 = 4 * 1024 * 1024;

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
    if size == 0 || size > MAX_REG_STR_BYTES {
        return None; // M-13：空值无需读；超限视为不可信，不按报告长度分配
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

/// 值的类型码（`REG_VALUE_TYPE.0`）。`None` = 值不存在**或**查询失败。
///
/// R-2（2026-10-07）现读复检要分开「值已不存在」（幂等，无需删）与「值在但不是字符串类型」
/// （无法证明是残留 ⇒ 拒绝）—— `reg_sz` 把这两种情况都折叠成 None，分不出来。
pub(super) unsafe fn reg_value_type_of(
    hk: windows::Win32::System::Registry::HKEY,
    name: &str,
) -> Option<u32> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        return None;
    }
    Some(ty.0)
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
    if size > MAX_REG_STR_BYTES {
        return Vec::new(); // M-13：超限视为不可信，不按报告长度分配
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

pub(crate) fn valid_uninstall_key_path(path: &str) -> bool {
    let p = path.to_lowercase();
    if p.contains("..") || p.contains('%') {
        return false;
    }
    // 锚定真实枚举根，且只认「根下的直接子键」——`contains` 形式连
    // `HKCU\Software\Evil\Microsoft\...\Uninstall\x` 也放行，等于把形状闸写成摆设。
    const ROOTS: [&str; 2] = [
        "software\\microsoft\\windows\\currentversion\\uninstall\\",
        "software\\wow6432node\\microsoft\\windows\\currentversion\\uninstall\\",
    ];
    ROOTS.iter().any(|root| {
        p.strip_prefix(root)
            .map(|rest| !rest.is_empty() && !rest.contains('\\'))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 卸载键形状闸必须**锚定**真实枚举根：`contains` 形式连
    /// `Software\Evil\Microsoft\...\Uninstall\x` 也放行（2026-10-05 复核）。
    #[test]
    fn 卸载键路径必须是真实枚举根下的直接子键() {
        // 三条真实根（HKCU/HKLM/HKLM32）都要放行
        assert!(valid_uninstall_key_path(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Foo"));
        assert!(valid_uninstall_key_path(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{guid}"));
        assert!(valid_uninstall_key_path(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Bar"));
        // 夹带路径必须被拒（原 contains 口径会放行第一条）
        assert!(!valid_uninstall_key_path(r"Software\Evil\Microsoft\Windows\CurrentVersion\Uninstall\x"));
        // 穿越 / 变量 / 根下多层子键都不许
        assert!(!valid_uninstall_key_path(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\..\x"));
        assert!(!valid_uninstall_key_path(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\%TEMP%"));
        assert!(!valid_uninstall_key_path(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\a\b"));
        assert!(!valid_uninstall_key_path(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\"));
    }
}
