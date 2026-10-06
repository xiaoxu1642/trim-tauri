//! B11 注册表读写/枚举/还原原语 + 原本散落在各业务分节里的注册表底层 reader。
//!
//! 切割纪律（v3 D1）：这些函数物理上原先分在 B3/B5/B6/B10 各节里，但它们是高扇入底层
//! （pssteps、reg_backup、commands 两侧都在调），留在业务文件会造出「cleanup 依赖
//! contextmenu」这种反向依赖方向。hive 取值与 file_ads_bytes（ADS 读取）同属本域。
//!
//! 写侧（reg_key_ensure / reg_key_remove / reg_restore_write / reg_restore_delete）的取值
//! 白名单由调用方把守；本文件不做业务判断。



use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, REG_QWORD, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW};
use super::common::*;
/// 读注册表 DWORD，失败返回 -1（保持 unsafe 签名，调用方维持既有 unsafe 块）
pub(super) unsafe fn read_reg_dword(hkey: HKEY, subkey: &str, value: &str) -> i32 {
    read_reg_dword_opt(hkey, subkey, value).map(|v| v as i32).unwrap_or(-1)
}

/// 读注册表 DWORD 的可判空版本（B11：原 PS 实现靠 `Get-ItemProperty` + `$null` 判缺，
/// 这里用 `Option` 表达同一语义 —— 值不存在 / 类型不对 / 打不开键都算 `None`）。
///
/// 返回值按**无符号**读出再转 i64：DWORD 本就是 32 位无符号，按 i32 读会把
/// `0xFFFFFFFF` 这类阈值变成 -1，而调用方（如 SVCHost 拆分阈值）拿它做数值比较。
pub fn read_reg_dword_opt(hive: HKEY, subkey: &str, value: &str) -> Option<i64> {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return None;
        }
        let vn = to_wide(value);
        let mut ty = REG_VALUE_TYPE::default();
        let mut buf = [0u8; 4];
        let mut size = 4u32;
        let r = RegQueryValueExW(
            hk, PCWSTR(vn.as_ptr()), None, Some(&mut ty),
            Some(buf.as_mut_ptr()), Some(&mut size),
        );
        let _ = RegCloseKey(hk);
        if r.is_err() || ty != REG_DWORD || size != 4 {
            return None;
        }
        Some(u32::from_le_bytes(buf) as i64)
    }
}

/// 读 `HKLM\<subkey>\<value>` 的 DWORD 快捷入口（B11：optimizer 三处 PS 读值改原生用）
pub fn read_hklm_dword(subkey: &str, value: &str) -> Option<i64> {
    read_reg_dword_opt(HKEY_LOCAL_MACHINE, subkey, value)
}

/// 读注册表 QWORD 值（REG_QWORD → i64）—— M2-C 检测断言用。
///
/// **为什么需要**（`read_reg_dword_opt` / `read_reg_string` / `read_reg_binary_opt`
/// 都覆盖不到它）：`perf_wu_pause` 把暂停起止时间写成 **FILETIME**（100ns 计数
/// 的 QWORD，`[DateTime]::UtcNow.ToFileTimeUtc()`），那是 64 位值 ——
/// 用 dword 原语读会拿到低 32 位（截断到 1950~2042 年之间的随机日期），
/// 用 string 原语读会因为类型不是 REG_SZ 而返回 `None`。
///
/// **返回 `i64` 而不是 `u64`**：FILETIME 的实际取值在 1.3e17 上下（远小于
/// `i64::MAX` ≈ 9.2e18），符号位一直是 0。但用 `i64` 是为了和
/// [`read_reg_dword_opt`] 的返回类型一致（上层算区间时不必到处转换），
/// 真出现 ≥2^63 的写入（不可能，来自 `FILETIME` 或别处的 QWORD）时它会是负数，
/// 由调用方的区间判定自然排除。
///
/// 类型不是 `REG_QWORD` 一律 `None`（fail-closed，不拿别的类型凑）。
pub fn read_reg_qword_opt(hive: HKEY, subkey: &str, value: &str) -> Option<i64> {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return None;
        }
        let vn = to_wide(value);
        let mut ty = REG_VALUE_TYPE::default();
        let mut buf = [0u8; 8];
        let mut size = 8u32;
        let r = RegQueryValueExW(
            hk,
            PCWSTR(vn.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        );
        let _ = RegCloseKey(hk);
        if r.is_err() || ty != REG_QWORD || size != 8 {
            return None;
        }
        Some(i64::from_le_bytes(buf))
    }
}


/// 读注册表值（返回类型+数据）
pub(super) unsafe fn reg_query_value(hk: HKEY, name: &str) -> Option<(REG_VALUE_TYPE, Vec<u8>)> {
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size)).is_err() {
        return None;
    }
    buf.truncate(size as usize);
    Some((ty, buf))
}

/// 枚举注册表键的所有值名。
///
/// 审查 M-2（2026-10-07）：原实现把**任何**错误都当「枚举结束」—— 权限不足等情况下
/// 静默返回空集，上层把「读不到」当成「没有」，扫描结果不完整且无从察觉。现在只把
/// `ERROR_NO_MORE_ITEMS`(259) 认作正常结束；其余错误记一条 warn 后再终止（不中断
/// 调用方，但留下痕迹）。键/值名长度受 Windows 限制（≤255 字符），260 缓冲足够。
pub(super) unsafe fn reg_enum_values(hk: HKEY) -> Vec<String> {
    let mut names = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name_buf = [0u16; 260];
        let mut name_len = name_buf.len() as u32;
        let r = RegEnumValueW(
            hk, index,
            Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            None, None, None, None,
        );
        // RegEnumValueW 直接返回 LSTATUS（WIN32_ERROR）
        if r == ERROR_NO_MORE_ITEMS {
            break;
        }
        if r.is_err() {
            crate::engine::log::write_log("warn", &format!("注册表值枚举非正常结束（index={index}, err={}）", r.0));
            break;
        }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        if !name.is_empty() { names.push(name); }
        index += 1;
    }
    names
}

/// 枚举注册表键的所有子键名。错误处置同 [`reg_enum_values`]（M-2）。
pub(super) unsafe fn reg_enum_subkeys(hk: HKEY) -> Vec<String> {
    let mut names = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name_buf = [0u16; 260];
        let mut name_len = name_buf.len() as u32;
        let r = RegEnumKeyExW(
            hk, index,
            Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            None, None, None, None,
        );
        if r == ERROR_NO_MORE_ITEMS {
            break;
        }
        if r.is_err() {
            crate::engine::log::write_log("warn", &format!("注册表子键枚举非正常结束（index={index}, err={}）", r.0));
            break;
        }
        names.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
        index += 1;
    }
    names
}

/// 读注册表字符串值（默认值或命名值），返回 Option<String>
pub(super) unsafe fn reg_read_string(hk: HKEY, name: &str) -> Option<String> {
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        return None;
    }
    if ty != REG_SZ && ty != REG_EXPAND_SZ { return None; }
    let mut buf = vec![0u8; size as usize];
    if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size)).is_err() {
        return None;
    }
    let wide: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    let s = String::from_utf16_lossy(&wide[..end]);
    if ty == REG_EXPAND_SZ { Some(expand_env(&s)) } else { Some(s) }
}

/// 读注册表 DWORD 值
pub(super) unsafe fn reg_read_dword_val(hk: HKEY, name: &str) -> Option<u32> {
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut buf = [0u8; 4];
    let mut size = 4u32;
    if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size)).is_err() {
        return None;
    }
    if ty != REG_DWORD { return None; }
    Some(u32::from_le_bytes(buf))
}

// ==================== B11：pwsh 步骤原生解释器的执行出口 ====================

/// 键存在性（对应 PS `Test-Path HKxx:\…`）
pub fn reg_key_exists(hive: HKEY, subkey: &str) -> bool {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        let ok = RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok();
        if ok {
            let _ = RegCloseKey(hk);
        }
        ok
    }
}

/// 确保键存在（对应 PS `New-Item -Path … -Force`）
///
/// `-Force` 的语义是「有就用、没有才建」，所以创建被拒时还要判一次「键是否已存在」：
/// 父键只授读权而子键早已存在的情况下，RegCreateKeyExW 会返回拒绝访问，但目标状态
/// 其实已经满足——报失败就是假失败。
pub fn reg_key_ensure(hive: HKEY, subkey: &str) -> bool {
    reg_key_ensure_checked(hive, subkey).is_ok()
}

/// 同 `reg_key_ensure`，但把 win32 错误码交回调用方渲染成人话（5 = 拒绝访问等）。
pub fn reg_key_ensure_checked(hive: HKEY, subkey: &str) -> Result<(), u32> {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        let r = RegCreateKeyExW(hive, PCWSTR(sk.as_ptr()), None, PCWSTR::default(), REG_OPTION_NON_VOLATILE, KEY_READ, None, &mut hk, None);
        if r.is_ok() {
            let _ = RegCloseKey(hk);
            return Ok(());
        }
        // 建不了，但键本来就在 —— `-Force` 的目标状态已达成
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
            let _ = RegCloseKey(hk);
            return Ok(());
        }
        Err(r.0)
    }
}

/// 删除键（对应 PS `Remove-Item`；`recurse` 走 `RegDeleteTreeW`，含全部子键与值）
pub fn reg_key_remove(hive: HKEY, subkey: &str, recurse: bool) -> bool {
    use windows::Win32::System::Registry::{RegDeleteTreeW, RegDeleteKeyW};
    let sk = to_wide(subkey);
    unsafe {
        if recurse {
            // RegDeleteTreeW 可直接作用于父 hive + 子键路径
            RegDeleteTreeW(hive, PCWSTR(sk.as_ptr())).is_ok()
        } else {
            // 非递归删除只对**最末段**有效：拆出父键与末段
            let Some((parent, last)) = subkey.rsplit_once('\\') else {
                return RegDeleteKeyW(hive, PCWSTR(sk.as_ptr())).is_ok();
            };
            let mut hk = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(to_wide(parent).as_ptr()), Some(0), KEY_SET_VALUE, &mut hk).is_err() {
                return false;
            }
            let r = RegDeleteKeyW(hk, PCWSTR(to_wide(last).as_ptr()));
            let _ = RegCloseKey(hk);
            r.is_ok()
        }
    }
}

/// 枚举子键名（v3-K1：`Get-ChildItem <注册表键>` 的等价物）。
/// 键不存在 → 空集（对齐 PS `-ErrorAction SilentlyContinue`：无迭代即无操作）。
pub fn reg_enum_subkeys_pub(hive: HKEY, subkey: &str) -> Vec<String> {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return Vec::new();
        }
        let names = reg_enum_subkeys(hk);
        let _ = RegCloseKey(hk);
        names
    }
}

/// 枚举 `Enum\PCI` 下实例 `Class` 值等于 `class` 的设备（v3-K1）。
///
/// 等价性：Win32_VideoController 的成员即「Display」安装类设备、Win32_USBController
/// 即「USB」类；数据层再以 `PNPDeviceID -like "PCI*"` 过滤到 PCI 总线 —— 与本函数
/// 在两级子键上按 Class 过滤的成员集一致，且不依赖 WMI 服务在运行。
/// 返回 PNPDeviceID（`PCI\VEN_x…\实例串` 形式）。
pub fn reg_enum_dev_ids(class: &str) -> Vec<String> {
    const BASE: &str = r"SYSTEM\CurrentControlSet\Enum\PCI";
    let mut out = Vec::new();
    let mut root = HKEY::default();
    unsafe {
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(to_wide(BASE).as_ptr()), Some(0), KEY_READ, &mut root)
            .is_err()
        {
            return out;
        }
        for dev in reg_enum_subkeys(root) {
            let dev_path = format!("{BASE}\\{dev}");
            let mut dev_hk = HKEY::default();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(to_wide(&dev_path).as_ptr()), Some(0), KEY_READ, &mut dev_hk)
                .is_err()
            {
                continue;
            }
            for inst in reg_enum_subkeys(dev_hk) {
                let inst_path = format!("{dev_path}\\{inst}");
                let mut inst_hk = HKEY::default();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(to_wide(&inst_path).as_ptr()), Some(0), KEY_READ, &mut inst_hk)
                    .is_err()
                {
                    continue;
                }
                let hit = reg_read_string(inst_hk, "Class")
                    .map(|c| c.eq_ignore_ascii_case(class))
                    .unwrap_or(false);
                let _ = RegCloseKey(inst_hk);
                if hit {
                    out.push(format!("PCI\\{dev}\\{inst}"));
                }
            }
            let _ = RegCloseKey(dev_hk);
        }
        let _ = RegCloseKey(root);
    }
    out
}

/// 键的最后写入时间（Unix 毫秒）—— 失效残留扫描的「沉睡多久」展示用。
///
/// 取不到一律返回 `None`：调用方按「不知道」渲染。返回 0 等于在 UI 上写
/// 「1970 年起没动过」，那是把"读不到"伪装成"很古老"，会让判定看起来比实际有把握。
pub fn reg_key_last_write_ms(hive: HKEY, subkey: &str) -> Option<i64> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, RegQueryInfoKeyW, KEY_READ};
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return None;
        }
        let mut ft = FILETIME::default();
        let err = RegQueryInfoKeyW(
            hk, None, None, None, None, None, None, None, None, None, None, Some(&mut ft),
        );
        let _ = RegCloseKey(hk);
        if err.0 != 0 {
            return None;
        }
        let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
        // FILETIME 自 1601-01-01 起的 100ns 计数，与 Unix 纪元差 11644473600 秒
        const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
        if ticks < EPOCH_DIFF_100NS {
            return None;
        }
        Some(((ticks - EPOCH_DIFF_100NS) / 10_000) as i64)
    }
}

/// 读注册表字符串值（REG_SZ；B11：optimizer 回读检测的非 DWORD 分支用）
///
/// 刻意**不展开** `REG_EXPAND_SZ`：PS 的 `Get-ItemProperty` 会展开它，但 optimizer 的
/// 期望值来自 `.reg` 文本解析（`parse_reg_expected`），那里只会产生 `dword:` 与
/// 引号串（REG_SZ）两种 —— 遇到 `hex(2):` 等其它类型直接 `None`（fail-closed），
/// 与「检测失败」的语义一致，而不是拿一个展开后的串去对一个错误的期望值。
pub fn read_reg_string(hive: HKEY, subkey: &str, value: &str) -> Option<String> {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return None;
        }
        let vn = to_wide(value);
        let mut ty = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        if RegQueryValueExW(hk, PCWSTR(vn.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
            let _ = RegCloseKey(hk);
            return None;
        }
        if ty != REG_SZ || size == 0 {
            let _ = RegCloseKey(hk);
            return None;
        }
        // size 含结尾 NUL 的字节数
        let mut buf = vec![0u8; size as usize];
        let r = RegQueryValueExW(hk, PCWSTR(vn.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size));
        let _ = RegCloseKey(hk);
        if r.is_err() {
            return None;
        }
        // 去掉结尾 NUL，按 UTF-16 解码
        let bytes = &buf[..buf.len().saturating_sub(2)];
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&units))
    }
}

/// 读注册表二进制值（REG_BINARY）—— M2 检测断言用。
///
/// 为什么需要（与既有原语的关系）：
/// - [`read_reg_dword_opt`] 只认 `REG_DWORD`（4 字节）；
/// - [`read_reg_string`] 只认 `REG_SZ`（UTF-16，且**不**展开 `REG_EXPAND_SZ`）；
/// - 而优化项里有两类真实写入是二进制：`MitigationOptions`（内核缓解位图，
///   `perf_exploit_protection_off`）与 `Scancode Map`（键盘扫描码重映射，
///   `peripheral_winkey_off`）。这两项原先因此完全检不出。
///
/// **口径**：
/// - 类型不是 `REG_BINARY` 一律 `None`（fail-closed，不拿别的类型凑 —— `read_reg_string`
///   拒绝 `REG_EXPAND_SZ` 是同一个理由）；
/// - 返回小写 hex 连写（无分隔符），与 [`read_reg_value_text`] 的 BINARY 展平口径一致，
///   所以 `check_optimized` 那侧比较时两侧格式相同；
/// - 空值返回 `Some("")`（长度 0 是合法状态，与「键不存在」`None` 区分开）。
///   `MitigationOptions` 全零字节就属于这一类 —— 判成「读不到」会把「已清零」说成「未知」。
pub fn read_reg_binary_opt(hive: HKEY, subkey: &str, value: &str) -> Option<String> {
    const REG_BINARY: u32 = 3;
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return None;
        }
        let vn = to_wide(value);
        let mut ty = REG_VALUE_TYPE::default();
        let mut size: u32 = 0;
        if RegQueryValueExW(hk, PCWSTR(vn.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
            let _ = RegCloseKey(hk);
            return None;
        }
        if ty.0 != REG_BINARY {
            let _ = RegCloseKey(hk);
            return None; // 类型不符 ⇒ 检不出（不猜）
        }
        if size == 0 {
            let _ = RegCloseKey(hk);
            return Some(String::new()); // 存在但为空 ≠ 不存在
        }
        // 上限防御：优化项里的二进制值最大 24 字节（MEMORY_COMBINE_INFORMATION_EX）。
        // 1 MiB 是「读不出来就是异常」与「内存被无界分配」之间的折中，且远大于任何真实值。
        const MAX_BINARY: u32 = 1024 * 1024;
        if size > MAX_BINARY {
            let _ = RegCloseKey(hk);
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let r = RegQueryValueExW(
            hk,
            PCWSTR(vn.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        );
        let _ = RegCloseKey(hk);
        if r.is_err() {
            return None;
        }
        Some(buf[..size as usize].iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// 读注册表值，返回 (类型标签, 字符串化数据) —— **显示/回读链**用的展平口径。
///
/// 口径逐条对齐 .NET `GetValue` 与 PS `[string]$v`（`READ_ONE_HEADER`，main.js 3481-3502 的移植）：
/// `REG_EXPAND_SZ` **展开后**按 `REG_SZ` 回报、`REG_MULTI_SZ` 空格连接按 `REG_SZ` 回报。
/// 这两个展平是有意的：卸载项的 `UninstallString` 给人看就该是展开后的真实路径。
/// DWORD 按**有符号 i32**、QWORD 按 i64、BINARY 按小写 hex 连写 —— 读写两侧必须同一套规则，
/// 否则 `0xFFFFFFFF` 这类值会在「备份→还原」之间变形。
///
/// **备份/还原链不要用这里**，用 [`read_reg_value_faithful`] —— 展开过的 EXPAND_SZ 写回去
/// 会把 `%VAR%` 永久变成字面量，那正是「还原后反而变了」那一类疑难的根因。
pub fn read_reg_value_text(hive: HKEY, subkey: &str, name: &str) -> Option<(&'static str, String)> {
    read_reg_value_mode(hive, subkey, name, true)
}

/// 读注册表值，返回 (**真实**类型标签, 未加工内容) —— **备份/还原链**专用。
///
/// 与 [`read_reg_value_text`] 的唯一差别是不展平：
/// - `REG_EXPAND_SZ` → 原样（不展开环境变量）
/// - `REG_MULTI_SZ` → 各元素以 `\u{0}` 连接。选 NUL 作分隔是因为它**不可能**出现在元素里
///   （NUL 本身就是注册表里的元素分隔符），所以连接是可逆的；备份文件的 `data` 只有一个
///   真源，不必再加数组字段。渲染层只读备份的**条数**、不读 `data`，串里的 NUL 不会上屏。
///   元素中间的空串会被丢弃（注册表保留用法，实际写入方极少），其余字节原样往返。
pub fn read_reg_value_faithful(hive: HKEY, subkey: &str, name: &str) -> Option<(&'static str, String)> {
    read_reg_value_mode(hive, subkey, name, false)
}

pub(super) fn read_reg_value_mode(
    hive: HKEY,
    subkey: &str,
    name: &str,
    flatten: bool,
) -> Option<(&'static str, String)> {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return None;
        }
        let vn = to_wide(name);
        let mut ty = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        if RegQueryValueExW(hk, PCWSTR(vn.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
            let _ = RegCloseKey(hk);
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let r = RegQueryValueExW(hk, PCWSTR(vn.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size));
        let _ = RegCloseKey(hk);
        if r.is_err() {
            return None;
        }
        // 两次查询之间值被改小时 size < buf.len()：按第二次报的实际长度截断，
        // 否则多出来的补零会参与解码（DWORD 长度闸门就是这么被打穿的）
        let actual = (size as usize).min(buf.len());
        decode_reg_value_bytes(ty, &buf[..actual], flatten)
    }
}

/// 值字节 → (类型标签, 字符串)。两条口径的唯一解码处，不碰注册表句柄，
/// 因此能与 `optimizer::restore_write_bytes` 成对钉在单测里（读写两端同一条链）。
pub fn decode_reg_value_bytes(
    ty: REG_VALUE_TYPE,
    buf: &[u8],
    flatten: bool,
) -> Option<(&'static str, String)> {
    use windows::Win32::System::Registry::{REG_EXPAND_SZ, REG_MULTI_SZ};
    use windows::Win32::System::Environment::ExpandEnvironmentStringsW;

    let units = |b: &[u8]| -> Vec<u16> {
        b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
    };
    match ty {
        REG_DWORD if buf.len() >= 4 => {
            let raw = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            // .NET 把 DWORD 读成 int（有符号），`[int]$v` 再转字符串 —— 保留该口径
            Some(("REG_DWORD", (raw as i32).to_string()))
        }
        REG_QWORD if buf.len() >= 8 => {
            let raw = u64::from_le_bytes(buf[..8].try_into().ok()?);
            Some(("REG_QWORD", (raw as i64).to_string()))
        }
        REG_BINARY => {
            Some(("REG_BINARY", buf.iter().map(|b| format!("{b:02x}")).collect()))
        }
        REG_SZ => {
            let u = units(buf);
            Some(("REG_SZ", String::from_utf16_lossy(&u).trim_end_matches('\0').to_string()))
        }
        REG_EXPAND_SZ => {
            let u = units(buf);
            let raw = String::from_utf16_lossy(&u);
            let raw = raw.trim_end_matches('\0');
            if !flatten {
                return Some(("REG_EXPAND_SZ", raw.to_string()));
            }
            // 展开环境变量（对齐 .NET GetValue）；展开结果以 NUL 结尾
            let mut out = [0u16; 1024];
            let src = to_wide(raw);
            let n = unsafe { ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), Some(&mut out[..])) };
            let s = if n == 0 || n as usize > out.len() {
                raw.to_string() // 展开失败/过长 → 原样保留，不造一个错值
            } else {
                let u16s = &out[..(n as usize - 1).max(0)];
                String::from_utf16_lossy(u16s)
            };
            Some(("REG_SZ", s))
        }
        REG_MULTI_SZ => {
            let u = units(buf);
            let text = String::from_utf16_lossy(&u);
            let parts: Vec<&str> = text
                .trim_end_matches('\0')
                .split('\0')
                .filter(|s| !s.is_empty())
                .collect();
            if flatten {
                // PS `[string]$v` 对字符串数组是空格连接
                Some(("REG_SZ", parts.join(" ")))
            } else {
                Some(("REG_MULTI_SZ", parts.join("\u{0}")))
            }
        }
        _ => None,
    }
}

/// hive 句柄的跨 crate 出口（命令层不 import windows crate）
pub fn hive_hklm() -> HKEY { HKEY_LOCAL_MACHINE }
pub fn hive_hkcu() -> HKEY { HKEY_CURRENT_USER }
pub fn hive_hkcr() -> HKEY {
    windows::Win32::System::Registry::HKEY_CLASSES_ROOT
}
pub fn hive_hku() -> HKEY {
    windows::Win32::System::Registry::HKEY_USERS
}
pub fn hive_hkcc() -> HKEY {
    windows::Win32::System::Registry::HKEY_CURRENT_CONFIG
}

/// 写注册表值（B11：optimizer「按备份回写」的原生出口，替代 `reg.exe add` 子进程）
///
/// `kind` 与 `data` 由调用方编码（见 optimizer 的 `restore_write_bytes`），
/// 这里只负责打开键、写入、关闭 —— 与内部既有的 `reg_write_value` 同一套姿势。
pub fn reg_restore_write(hive: HKEY, subkey: &str, value_name: &str, kind: REG_VALUE_TYPE, data: &[u8]) -> bool {
    unsafe { reg_write_value(hive, subkey, value_name, kind, data) }
}

/// 带 win32 错误码的写值出口（原生解释器用它区分「拒绝访问」与「键不存在」）。
pub fn reg_restore_write_checked(hive: HKEY, subkey: &str, value_name: &str, kind: REG_VALUE_TYPE, data: &[u8]) -> Result<(), u32> {
    unsafe { reg_write_value_checked(hive, subkey, value_name, kind, data) }
}

/// 枚举文件的命名数据流（NTFS ADS）字节数与条数（HiBit §H5，2026-09-29）。
///
/// **用的是 `FindFirstStreamW` / `FindNextStreamW`**。对标报告按 HiBit 的导入表
/// （`FindFirstFileNameW`/`FindNextFileNameW`）推断它在做 ADS，那个推断错了一半：
/// `FindFirstFileNameW` 枚举的是同一文件记录上的**硬链接名**，不是数据流。
/// 这里要的是数据流，所以按 API 的真实语义取，而不是照抄被推断的那对。
///
/// 默认流 `::$DATA` 不计入（它就是文件本体，已由 `metadata().len()` 算过）。
/// 失败一律返回 (0,0)：ADS 属于"解释体积为什么比表面大"的附加信息，
/// 不该让一次体积估算整体失败。
pub fn file_ads_bytes(path: &std::path::Path) -> (u64, usize) {
    use windows::Win32::Storage::FileSystem::{
        FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, WIN32_FIND_STREAM_DATA,
    };
    use windows::Win32::Foundation::CloseHandle;

    let mut buf = WIN32_FIND_STREAM_DATA::default();
    let wide = to_wide(&path.to_string_lossy());
    let mut bytes = 0u64;
    let mut count = 0usize;
    unsafe {
        let Ok(handle) = FindFirstStreamW(
            windows::core::PCWSTR(wide.as_ptr()),
            FindStreamInfoStandard,
            &mut buf as *mut _ as *mut core::ffi::c_void,
            None,
        ) else {
            return (0, 0);
        };
        loop {
            let units: Vec<u16> = buf.cStreamName.iter().copied().take_while(|u| *u != 0).collect();
            let name = String::from_utf16_lossy(&units);
            // 形如 `::<名字>:$DATA`；默认流是 `::$DATA`
            if !name.eq_ignore_ascii_case("::$DATA") {
                bytes = bytes.saturating_add(buf.StreamSize.max(0) as u64);
                count += 1;
            }
            if FindNextStreamW(handle, &mut buf as *mut _ as *mut core::ffi::c_void).is_err() {
                break;
            }
        }
        let _ = CloseHandle(handle);
    }
    (bytes, count)
}

/// 枚举指定键的全部值名（F-1：regKeys `value:"*"` 展开用）。键打不开 → 空集。
pub fn reg_enum_value_names_pub(hive: HKEY, subkey: &str) -> Vec<String> {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return Vec::new();
        }
        let names = reg_enum_values(hk);
        let _ = RegCloseKey(hk);
        names
    }
}

/// 删注册表值；**值本来就不存在 = 成功**（B11：optimizer「按备份删除」的原生出口）
///
/// 语义对齐原 PS `reg delete … ; if ($LASTEXITCODE -ne 0) { reg query …; if (0) { failed++ } }`
/// —— reg.exe 删不存在的值会报错，但随后 query 不到，于是不计失败。原生等价是
/// `RegDeleteValueW` 返回 `ERROR_FILE_NOT_FOUND`(2) 视为幂等成功。
pub fn reg_restore_delete(hive: HKEY, subkey: &str, value_name: &str) -> bool {
    use windows::Win32::Foundation::WIN32_ERROR;
    const ERROR_FILE_NOT_FOUND: WIN32_ERROR = WIN32_ERROR(2);
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk).is_err() {
            // 键都不存在 → 值必然不存在 → 幂等成功
            return true;
        }
        let nm = to_wide(value_name);
        let r = RegDeleteValueW(hk, PCWSTR(nm.as_ptr()));
        let _ = RegCloseKey(hk);
        r.is_ok() || r == ERROR_FILE_NOT_FOUND
    }
}

/// 读注册表值（返回**真实**类型标签 + 原始字节，不做任何解码/展平）。
///
/// `pub` 的唯一新消费者是 `pssteps` 的写值终态判定（写被拒时读回现值，逐字节比对目标）：
/// 那里要的是「与 `RegSetValueExW` 同一条口径」的字节，所以不能复用
/// [`read_reg_value_faithful`]（它给的是解码后的字符串，DWORD 会变成十进制文本）。
pub unsafe fn reg_read_value_typed(hive: HKEY, subkey: &str, value_name: &str) -> Option<(REG_VALUE_TYPE, Vec<u8>)> {
    let sk = to_wide(&subkey);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { return None; }
    let nm = to_wide(value_name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        let _ = RegCloseKey(hk); return None;
    }
    let mut buf = vec![0u8; size as usize];
    let r = RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size));
    let _ = RegCloseKey(hk);
    if r.is_err() { None } else { Some((ty, buf)) }
}

/// 删除注册表值
pub(super) unsafe fn reg_delete_value(hive: HKEY, subkey: &str, value_name: &str) -> bool {
    let sk = to_wide(&subkey);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk).is_err() { return false; }
    let nm = to_wide(value_name);
    let r = RegDeleteValueW(hk, PCWSTR(nm.as_ptr()));
    let _ = RegCloseKey(hk);
    r.is_ok()
}

/// 写注册表值（恢复用）
/// 写注册表值（原生解释器与还原链共用）。
///
/// **权限掩码只要 `KEY_SET_VALUE`，不要 `KEY_WRITE`**。`KEY_WRITE` 里含
/// `KEY_CREATE_SUB_KEY`，而 `HKLM\…\MMDevices\Audio\Render\{…}\FxProperties` 这类键的 DACL
/// 给 Administrators 的只有 `SetValue, ReadKey`（本机实测：`KEY_WRITE` 打开返回 win32=5
/// 拒绝访问，`KEY_SET_VALUE` 打开成功）。多要那一项权限会把**本来写得进去的值**报成失败——
/// 「关闭音频增强 / 关闭空间音效」就是这么被误判成执行失败的。
/// 顺序：先按写值权打开已存在的键 → 打不开再创建（键不存在时才需要父键给 CreateSubKey）。
pub(super) unsafe fn reg_write_value(hive: HKEY, subkey: &str, value_name: &str, kind: REG_VALUE_TYPE, data: &[u8]) -> bool {
    reg_write_value_checked(hive, subkey, value_name, kind, data).is_ok()
}

/// 同 `reg_write_value`，但把 win32 错误码交回调用方（pssteps 用它渲染可诊断的失败原因）。
pub(super) unsafe fn reg_write_value_checked(hive: HKEY, subkey: &str, value_name: &str, kind: REG_VALUE_TYPE, data: &[u8]) -> Result<(), u32> {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk).is_err() {
        // 键不存在才需要创建（这一步才真正要求父键给 KEY_CREATE_SUB_KEY）
        let r = RegCreateKeyExW(hive, PCWSTR(sk.as_ptr()), None, PCWSTR::default(), REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, None, &mut hk, None);
        if r.is_err() {
            return Err(r.0);
        }
    }
    let nm = to_wide(value_name);
    let r = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), kind, Some(data));
    let _ = RegCloseKey(hk);
    if r.is_ok() {
        Ok(())
    } else {
        Err(r.0)
    }
}

pub(super) unsafe fn reg_count_values(hk: HKEY) -> usize {
    // 用 RegEnumValueW 枚举计数
    let mut count = 0usize;
    let mut index = 0u32;
    loop {
        let mut name_buf = [0u16; 260];
        let mut name_len = 260u32;
        if RegEnumValueW(hk, index, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None).is_err() { break; }
        count += 1;
        index += 1;
    }
    count
}
