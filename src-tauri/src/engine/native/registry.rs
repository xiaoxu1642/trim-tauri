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
/// `ERROR_NO_MORE_ITEMS`(259) 认作正常结束；其余错误记一条 warn 后再终止。
///
/// P1-6G：`incomplete` 位交回调用方 —— **截断的清单不得再被当成完整清单**。旧注释写
/// 「值名 ≤255 字符、260 缓冲足够」是错的：Win32 值名上限是 `KEY_MAX_VALUE_NAME_LEN`
/// = 16367 字符，缓冲区不足时 `RegEnumValueW` 报 `ERROR_MORE_DATA` 并回填所需长度，
/// 旧写法把它当普通错误 break（或按 260 截断），于是超常长的值名被静默截/丢。
/// 现在按需增长缓冲重试同一条目（有界，见 `ENUM_NAME_CAP`），只有真·正常结束才 `false`。
pub(super) unsafe fn reg_enum_values_scan(hk: HKEY) -> (Vec<String>, bool) {
    // RegEnumValueW 的 pcchName 入参是「缓冲区长度」、出参是「含尾 NUL 的所需长度」；
    // 值名合法上界即 KEY_MAX_VALUE_NAME_LEN（16367），再加 NUL 一位。以此为硬上限，
    // 既不再按 260 截断，也不给畸形返回值开无界分配。
    const ENUM_NAME_CAP: usize = 16367 + 1;
    const ERROR_MORE_DATA: u32 = 234;
    let mut names = Vec::new();
    let mut index = 0u32;
    let mut cap = 260usize;
    loop {
        let mut name_buf = vec![0u16; cap];
        let mut name_len = name_buf.len() as u32;
        let r = RegEnumValueW(
            hk, index,
            Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            None, None, None, None,
        );
        // RegEnumValueW 直接返回 LSTATUS（WIN32_ERROR）
        if r == ERROR_NO_MORE_ITEMS {
            return (names, false);
        }
        if r.0 == ERROR_MORE_DATA {
            // 出参写回所需长度：按它放大缓冲后**重试同一条**（不 ++index，否则这条被跳过）。
            // 用 max/min 而不是 clamp —— clamp 在 min>max 时 panic，而 cap 顶到上限后
            // `cap + 1` 恰好会大于上界，那正是要走「清单不完整」分支的时刻。
            let want = (name_len as usize).max(cap + 1).min(ENUM_NAME_CAP);
            if want > cap { cap = want; continue; }
            crate::engine::log::write_log("warn", &format!("注册表值枚举缓冲已达上限仍不足（index={index}），清单不完整"));
            return (names, true);
        }
        if r.is_err() {
            crate::engine::log::write_log("warn", &format!("注册表值枚举非正常结束（index={index}, err={}）", r.0));
            return (names, true);
        }
        let name = decode_name_lossy_with_warn(&name_buf[..name_len as usize]);
        if !name.is_empty() { names.push(name); }
        index += 1;
    }
}

/// 只读枚举出口（右键菜单、路径扫描等「少一条只是显示不全」的调用方）。
/// 需要区分「没有」与「没枚举完」的调用方一律走 [`reg_enum_values_scan`]。
pub(super) unsafe fn reg_enum_values(hk: HKEY) -> Vec<String> {
    reg_enum_values_scan(hk).0
}

/// 枚举注册表键的所有子键名，**并区分「这个键没有子键」与「没枚举完」**。
///
/// 与值名侧的 [`reg_enum_values_scan`] 同一口径（P1-6G 只补了值名那一半，子键侧原封不动）：
/// 开键失败与枚举中途报错都**不是**「没有子键」，而是「读不动」—— 两者在调用方同形时，
/// 「少迭代」会被念成「跑完了」，回执仍像完整。
///
/// 返回 `(names, incomplete)`：`incomplete = true` 表示清单可能不全（开键失败 / 中途报错）。
///
/// 缓冲仍用定长 260：`RegEnumKeyExW` 的子键名上限确实是 255 字符（Win32 硬限制），
/// 260 缓冲够用；**值名**的上限是 `KEY_MAX_VALUE_NAME_LEN` = 16367，所以只有值名枚举
/// 需要按需增长缓冲，这里不照抄那一套。
pub(super) unsafe fn reg_enum_subkeys_scan(hk: HKEY) -> (Vec<String>, bool) {
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
            return (names, false);
        }
        if r.is_err() {
            crate::engine::log::write_log("warn", &format!("注册表子键枚举非正常结束（index={index}, err={}）", r.0));
            return (names, true);
        }
        names.push(decode_name_lossy_with_warn(&name_buf[..name_len as usize]));
        index += 1;
    }
}

/// 只读枚举出口（右键菜单、路径扫描等「少一条只是显示不全」的调用方）。
/// 需要区分「没有」与「没枚举完」的调用方一律走 [`reg_enum_subkeys_scan`]。
pub(super) unsafe fn reg_enum_subkeys(hk: HKEY) -> Vec<String> {
    reg_enum_subkeys_scan(hk).0
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
    let s = decode_utf16_strict(&wide[..end])?;
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
///
/// **建面吃名字形态闸**（R5c-M01 / A6-M05）：`subkey` 含 NUL/控制字符 ⇒ `Err(87)`。
/// `PCWSTR` 以第一个 NUL 为串尾，形态非法的名字交给 Win32 的是它的**前缀**，
/// 判定的键与实际建的键不是同一个（红线⑨）。
pub fn reg_key_ensure_checked(hive: HKEY, subkey: &str) -> Result<(), u32> {
    let sk = to_wide_checked(subkey)?;
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

/// 注册表删除目标的**形态**闸（R5c-M02，红线①②）。
///
/// 判据：`subkey` 去掉首尾空白后为空、或只剩反斜杠 ⇒ 拒。
///
/// 为什么必须拒（这是 R5c-M02 的实锤）：
/// - `RegDeleteTreeW(hive, "")` 的口径是「以 `hKey` 本身为根」⇒ 目标从「某个产品叶键」
///   变成「整个 HKCU 子树」；
/// - `RegDeleteKeyW(hive, "")` 同样把空路径落到 hive 根。
///
/// 两种口径都是**删整棵树**，不是删一个键。原先这道闸只存在于调用方（谁先把路径交给
/// `protect::reg_target_block_reason`），而 pssteps 这条链一道都没有 ⇒ 空子键可达。
/// 红线①要求「空段 fail-closed」落在**被执行的那一层**，不能只写在模块头一句自述里。
fn reg_delete_subkey_shape_is_malformed(subkey: &str) -> bool {
    let t = subkey.trim();
    t.is_empty() || t.chars().all(|c| c == '\\')
}

/// 删除键的带因版本：返回 Win32 错误码（0 不当错误），供回执点名失败原因。
///
/// **形态闸在入口**（R5c-M02）：`subkey` 空 / 仅空白 / 仅反斜杠 ⇒ `Err(87)`；
/// 含 NUL 或控制字符 ⇒ `Err(87)`（`to_wide_checked`，红线⑨）。
/// 两者都发生在**任何 Win32 调用之前** —— `RegDeleteTreeW` 的空路径口径会把目标
/// 从「一个键」换成「整棵子树」，闸必须落在调用之前而不是之后。
pub fn reg_key_remove_checked(hive: HKEY, subkey: &str, recurse: bool) -> Result<(), u32> {
    use windows::Win32::System::Registry::{RegDeleteTreeW, RegDeleteKeyW};
    if reg_delete_subkey_shape_is_malformed(subkey) {
        return Err(87);
    }
    let sk = to_wide_checked(subkey)?;
    unsafe {
        if recurse {
            // RegDeleteTreeW 可直接作用于父 hive + 子键路径
            let e = RegDeleteTreeW(hive, PCWSTR(sk.as_ptr()));
            return if e.is_ok() { Ok(()) } else { Err(e.0) };
        }
        // 非递归删除只对**最末段**有效：拆出父键与末段
        let Some((parent, last)) = subkey.rsplit_once('\\') else {
            let e = RegDeleteKeyW(hive, PCWSTR(sk.as_ptr()));
            return if e.is_ok() { Ok(()) } else { Err(e.0) };
        };
        let mut hk = HKEY::default();
        let open = RegOpenKeyExW(hive, PCWSTR(to_wide_checked(parent)?.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk);
        if open.is_err() {
            return Err(open.0);
        }
        let r = RegDeleteKeyW(hk, PCWSTR(to_wide_checked(last)?.as_ptr()));
        let _ = RegCloseKey(hk);
        if r.is_ok() { Ok(()) } else { Err(r.0) }
    }
}

/// 删除键的失败原因人话（纯函数，单测钉住「四种因不折成一句」）。
pub fn remove_cause_label(code: u32) -> String {
    match code {
        5 => "拒绝访问(5)：父键不允许删除子键".to_string(),
        1018 => "键仍有子键(1018)：非递归删除前需先清空".to_string(),
        2 | 3 => "键不存在(2)".to_string(),
        87 => "目标名非法(87)：含 NUL 或控制字符，或子键路径为空/畸形（已按红线①fail-closed 拒绝，未执行任何 Win32 调用）".to_string(),
        other => format!("win32={other}"),
    }
}

/// 删除键（对应 PS `Remove-Item`；`recurse` 走 `RegDeleteTreeW`，含全部子键与值）
pub fn reg_key_remove(hive: HKEY, subkey: &str, recurse: bool) -> bool {
    reg_key_remove_checked(hive, subkey, recurse).is_ok()
}

/// 枚举子键名（v3-K1：`Get-ChildItem <注册表键>` 的等价物）。
/// 键不存在 → 空集（对齐 PS `-ErrorAction SilentlyContinue`：无迭代即无操作）。
///
/// ⚠ 这个出口**丢掉了「没枚举完」这一位**：调用方拿到空集时分不出「这个键没有子键」与
/// 「键打不开 / 枚举中途报错」。执行链（`ForSubKey`）一律走 [`reg_enum_subkeys_pub_scan`]。
pub fn reg_enum_subkeys_pub(hive: HKEY, subkey: &str) -> Vec<String> {
    reg_enum_subkeys_pub_scan(hive, subkey).0
}

/// 枚举子键名，**并区分「没有子键」与「没枚举完」**（与值名侧 `reg_enum_value_names_pub` 同口径）。
///
/// 开键失败同样算 `incomplete`（它不是「这个键没有子键」）；枚举中途报错也算。
pub fn reg_enum_subkeys_pub_scan(hive: HKEY, subkey: &str) -> (Vec<String>, bool) {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return (Vec::new(), true);
        }
        let (names, incomplete) = reg_enum_subkeys_scan(hk);
        let _ = RegCloseKey(hk);
        (names, incomplete)
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
        // 按 UTF-16 严格解码，尾部 NUL 用字符级裁剪（不再按字节削两字节 ——
        // 那样遇到奇数字节的畸形值会把半个字符削掉）
        let units: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let s = decode_utf16_strict(&units)?;
        Some(s.trim_end_matches('\0').to_string())
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

/// 注册表值读取的三态结果 —— **备份/还原链的权威口径**（P0-3）。
///
/// 「确认不存在」与「读不出来」是两个不同的事实：塌成同一个 `None` 会让还原链
/// 把一次访问拒绝/解码失败当成「值本来就不存在」，进而生成 Delete —— 永久删除
/// 本来存在的注册表值。两者在这里分成 `Absent` 与 `Unknown`。
#[derive(Debug)]
pub enum RegReadState {
    /// 键路径或值名**确认**不存在（只认「找不到」那两个 Win32 码，判据同
    /// [`open_key_missing_is_idempotent`]）
    Absent,
    /// 读出成功：(类型标签, 字符串化数据)，口径由 `flatten` 决定（同旧 Option 链）
    Value(&'static str, String),
    /// 读不出来（访问拒绝 / 其它 Win32 错误 / 尺寸或数据查询失败 / 解码失败）。
    /// 载荷是**错误码名**，可直接落日志与回执；不得携带路径、键名或值内容。
    Unknown(String),
}

/// win32 错误码 → 可落日志的错误名（P0-3 隐私纪律：回执链只许出现码名，
/// 未收录的码退化为纯数字——数字同样不带任何路径/值信息）。
fn win_reg_err_label(code: u32) -> String {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_MORE_DATA: u32 = 234;
    match code {
        ERROR_FILE_NOT_FOUND => "ERROR_FILE_NOT_FOUND".to_string(),
        ERROR_PATH_NOT_FOUND => "ERROR_PATH_NOT_FOUND".to_string(),
        ERROR_ACCESS_DENIED => "ERROR_ACCESS_DENIED".to_string(),
        ERROR_MORE_DATA => "ERROR_MORE_DATA".to_string(),
        c => format!("WIN32_ERROR({c})"),
    }
}

/// 读注册表值的**唯一新内核**（三态）。备份/还原链必须直接消费本函数；
/// [`read_reg_value_text`] / [`read_reg_value_faithful`] 只是它上面保留旧 `Option` 外观的外壳。
///
/// 状态映射口径（P0-3）：
/// - `RegOpenKeyExW` 失败：码为「找不到」(2/3) → `Absent`；其余（含访问拒绝 5）→ `Unknown`；
/// - `RegQueryValueExW` 尺寸查询失败：码为 2 → `Absent`；其余 → `Unknown`；
/// - 数据查询出现 `ERROR_MORE_DATA`，或尺寸在两次查询之间增长 → 有限重试；
///   重试打满仍不稳定 → `Unknown`（读写竞争时读器不猜快照）；其它失败 → `Unknown`；
/// - 解码失败（类型不认识 / 字节长度不足类型闸门）→ `Unknown`：读不出的值不等于不存在的值。
pub fn read_reg_value_state(hive: HKEY, subkey: &str, name: &str, flatten: bool) -> RegReadState {
    // 重试上限与施工口径一致：竞争窗口在微秒级，有限次后仍变化说明有并发写方，
    // 继续读只会给出一份没人见过的假快照。
    const MAX_REREAD: u32 = 2;
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_MORE_DATA: u32 = 234;
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        let opened = RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk);
        if opened.is_err() {
            return if open_key_missing_is_idempotent(opened.0) {
                RegReadState::Absent
            } else {
                RegReadState::Unknown(win_reg_err_label(opened.0))
            };
        }
        let vn = to_wide(name);
        let mut ty = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        let q1 = RegQueryValueExW(hk, PCWSTR(vn.as_ptr()), None, Some(&mut ty), None, Some(&mut size));
        if q1.is_err() {
            let _ = RegCloseKey(hk);
            return if q1.0 == ERROR_FILE_NOT_FOUND {
                // 键在而值名不在：确认不存在
                RegReadState::Absent
            } else {
                RegReadState::Unknown(win_reg_err_label(q1.0))
            };
        }
        let mut reread = 0u32;
        loop {
            let mut buf = vec![0u8; size as usize];
            let mut got = size;
            let q2 = RegQueryValueExW(hk, PCWSTR(vn.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut got));
            if (q2.0 == ERROR_MORE_DATA || got > size) && reread < MAX_REREAD {
                // 值在两次查询之间长大了：按回报的实际尺寸重建缓冲再读，有限重试
                reread += 1;
                size = got.max(size);
                continue;
            }
            if q2.is_err() {
                let _ = RegCloseKey(hk);
                return RegReadState::Unknown(win_reg_err_label(q2.0));
            }
            let _ = RegCloseKey(hk);
            // 两次查询之间值被改小时 got < buf.len()：按第二次报的实际长度截断，
            // 否则多出来的补零会参与解码（DWORD 长度闸门就是这么被打穿的）
            let actual = (got as usize).min(buf.len());
            return match decode_reg_value_bytes(ty, &buf[..actual], flatten) {
                Some((t, d)) => RegReadState::Value(t, d),
                None => RegReadState::Unknown("decode_failed".to_string()),
            };
        }
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
/// **备份/还原链不要用这里**，用 [`read_reg_value_state`] —— 本外壳把 `Absent` 与 `Unknown`
/// 一并塌回 `None`：显示链没有破坏性动作，「读不出」与「不存在」同样是不展示；
/// 还原链不能接受这个塌合，否则一次读失败就会生成 Delete。
pub fn read_reg_value_text(hive: HKEY, subkey: &str, name: &str) -> Option<(&'static str, String)> {
    match read_reg_value_state(hive, subkey, name, true) {
        RegReadState::Value(t, d) => Some((t, d)),
        _ => None,
    }
}

/// 读注册表值，返回 (**真实**类型标签, 未加工内容) —— 与 [`read_reg_value_text`] 的
/// 唯一差别是不展平（口径见 [`read_reg_value_state`]）。
///
/// `Option` 外观保留给存量调用方（`reg_backup` 导入回读等**非删除**路径）；
/// 新的备份台账写入与还原比对一律直接用 [`read_reg_value_state`]，
/// 因为这里 `None` 分不出「不存在」还是「读不出来」。
/// 不展平的理由不变：展开过的 EXPAND_SZ 写回去会把 `%VAR%` 永久变成字面量，
/// MULTI_SZ 的 NUL 连接可逆（NUL 不可能出现在元素里），其余字节原样往返。
pub fn read_reg_value_faithful(hive: HKEY, subkey: &str, name: &str) -> Option<(&'static str, String)> {
    match read_reg_value_state(hive, subkey, name, false) {
        RegReadState::Value(t, d) => Some((t, d)),
        _ => None,
    }
}

/// UTF-16 **严格**解码：非法序列（孤立代理项）不做有损替换。
///
/// 为什么不能有损：`from_utf16_lossy` 会把孤立代理项换成 U+FFFD，而这条链的输出会
/// **写回注册表**（备份 → 还原）⇒ 有损替换等于把原值永久改成另一个值，回执却说「已还原」。
/// 解不出来就判 `None`（上层落 `Unknown("decode_failed")`），让「读不出」保持可辨。
fn decode_utf16_strict(units: &[u16]) -> Option<String> {
    match String::from_utf16(units) {
        Ok(s) => Some(s),
        Err(_) => {
            crate::engine::log::write_log("warn", "注册表值含非法 UTF-16 序列（孤立代理项），本次解码判失败（不写回任何替换字符）");
            None
        }
    }
}

/// 名称（键名 / 值名）的 UTF-16 解码：**畸形不吞掉名字**。
///
/// 名称路径与值内容路径的取舍不同：值内容解码失败会被写回注册表（有损即永久变形），
/// 而名称解码失败若直接跳过就等于「这一项凭空消失」。所以这里退回有损读法，
/// 但必须留一条告警（红线：畸形必须计数或告警）。
fn decode_name_lossy_with_warn(units: &[u16]) -> String {
    match String::from_utf16(units) {
        Ok(s) => s,
        Err(_) => {
            crate::engine::log::write_log("warn", "注册表名称含非法 UTF-16 序列，已按有损方式读取（该名称可能无法精确定位）");
            String::from_utf16_lossy(units)
        }
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
    // 奇数字节的畸形值：`chunks_exact(2)` 会静默丢掉末字节 ⇒ 先计数告警再解码
    if buf.len() % 2 != 0 {
        crate::engine::log::write_log("warn", &format!("注册表值字节长度为奇数（{} 字节），末字节不参与 UTF-16 解码", buf.len()));
    }
    match ty {
        // 长度闸是**严格相等**：短的一侧判 decode_failed 是 P0-3 立的那道闸，
        // 长的一侧同样判失败 —— 放行长值会让还原按短字节写回，原值的高位永久消失，
        // 而回执说「已还原」（交叉形态按 Corrupt 口径，两侧必须同形）。
        REG_DWORD if buf.len() == 4 => {
            let raw = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            // .NET 把 DWORD 读成 int（有符号），`[int]$v` 再转字符串 —— 保留该口径
            Some(("REG_DWORD", (raw as i32).to_string()))
        }
        REG_QWORD if buf.len() == 8 => {
            let raw = u64::from_le_bytes(buf[..8].try_into().ok()?);
            Some(("REG_QWORD", (raw as i64).to_string()))
        }
        REG_BINARY => {
            Some(("REG_BINARY", buf.iter().map(|b| format!("{b:02x}")).collect()))
        }
        REG_SZ => {
            let u = units(buf);
            let s = decode_utf16_strict(&u)?;
            Some(("REG_SZ", s.trim_end_matches('\0').to_string()))
        }
        REG_EXPAND_SZ => {
            let u = units(buf);
            let raw = decode_utf16_strict(&u)?;
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
                // 展开结果由系统拼出，理论上合法；万一非法也不造替换字符，退回原值
                decode_utf16_strict(u16s).unwrap_or_else(|| raw.to_string())
            };
            Some(("REG_SZ", s))
        }
        REG_MULTI_SZ => {
            let u = units(buf);
            let text = decode_utf16_strict(&u)?;
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

/// 枚举指定键的全部值名（F-1：regKeys `value:"*"` 展开、管理摘要对账用）。
///
/// P1-6G：返回 `(names, incomplete)`。旧签名只给 `Vec`，于是**两种完全不同的事实**
/// 在调用方同形：「这个键确实没有值」与「键打不开 / 枚举中途报错 / 值名长过缓冲上限」。
/// 前者展开成 0 条删除是正确行为，后者展开成 0 条则是「静默空转 + 回执报成功」——
/// 正是 `value:"*"` 那条链最怕的形状。开键失败同样算 `incomplete`（它不是「无值」）。
pub fn reg_enum_value_names_pub(hive: HKEY, subkey: &str) -> (Vec<String>, bool) {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return (Vec::new(), true);
        }
        let (names, incomplete) = reg_enum_values_scan(hk);
        let _ = RegCloseKey(hk);
        (names, incomplete)
    }
}

/// 删注册表值；**值本来就不存在 = 成功**（B11：optimizer「按备份删除」的原生出口）
///
/// 语义对齐原 PS `reg delete … ; if ($LASTEXITCODE -ne 0) { reg query …; if (0) { failed++ } }`
/// —— reg.exe 删不存在的值会报错，但随后 query 不到，于是不计失败。原生等价是
/// `RegDeleteValueW` 返回 `ERROR_FILE_NOT_FOUND`(2) 视为幂等成功。
/// R5b-M01（v7.2 C06）：打开键失败时，只有「键/路径不存在」算幂等成功；
/// ACCESS_DENIED(5)、1008 等其余失败必须判失败——旧实现一律 true，回执说删了、值还在。
/// R5c-M01（v7.2 B1-2）：**名字形态闸在开键之前**。`PCWSTR` 以第一个 NUL 为串尾，
/// 形态非法的值名交给 Win32 的是它的前缀 —— 删的是「另一个值」而回执说删的是「这个值」
/// （红线⑨）。形态非法一律判**失败**（不是幂等成功）：判不出「本来就不存在」，
/// 按「可能存在但拒绝动它」记账才是诚实的。
fn open_key_missing_is_idempotent(code: u32) -> bool {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    matches!(code, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
}

pub fn reg_restore_delete(hive: HKEY, subkey: &str, value_name: &str) -> bool {
    use windows::Win32::Foundation::WIN32_ERROR;
    const ERROR_FILE_NOT_FOUND: WIN32_ERROR = WIN32_ERROR(2);
    // 形态闸先于任何 Win32 调用（红线⑨：判定字节 ≠ 执行字节）
    let (Ok(sk), Ok(nm)) = (to_wide_checked(subkey), to_wide_checked(value_name)) else {
        return false;
    };
    let mut hk = HKEY::default();
    unsafe {
        let opened = RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk);
        if opened.is_err() {
            // R5b-M01（v7.2 C06）：只有「键不存在」才是幂等成功。
            return open_key_missing_is_idempotent(opened.0);
        }
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
    // 形态闸先于任何 Win32 调用（R5c-M01 / A6-M05，红线⑨）
    let (Ok(sk), Ok(nm)) = (to_wide_checked(&subkey), to_wide_checked(value_name)) else {
        return false;
    };
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk).is_err() { return false; }
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
///
/// **写面吃名字形态闸**（R5c-M01 / A6-M05）：键路径与值名含 NUL/控制字符 ⇒ `Err(87)`。
/// 闸在开键之前：`PCWSTR` 以第一个 NUL 为串尾，形态非法的名字交给 Win32 的是前缀，
/// 写进去的是「另一个键/另一个值」（红线⑨）。
pub(super) unsafe fn reg_write_value_checked(hive: HKEY, subkey: &str, value_name: &str, kind: REG_VALUE_TYPE, data: &[u8]) -> Result<(), u32> {
    let sk = to_wide_checked(subkey)?;
    let nm = to_wide_checked(value_name)?;
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk).is_err() {
        // 键不存在才需要创建（这一步才真正要求父键给 KEY_CREATE_SUB_KEY）
        let r = RegCreateKeyExW(hive, PCWSTR(sk.as_ptr()), None, PCWSTR::default(), REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, None, &mut hk, None);
        if r.is_err() {
            return Err(r.0);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{
        open_key_missing_is_idempotent, win_reg_err_label, read_reg_value_state, reg_key_remove,
        reg_restore_write, reg_enum_value_names_pub, to_wide, RegReadState, remove_cause_label,
        decode_reg_value_bytes, reg_enum_subkeys_pub_scan, hive_hklm,
    };

    /// R5c-M01（B1-2）：**判定字节 = 执行字节**（红线⑨）—— 名字形态闸的真机验收。
    ///
    /// 验收形态（方案 §4.1 B1-2 明列）：目标 `"a\0b"` ⇒ **必须拒**，且盘上那个
    /// 叫 `a` 的键**不得被删**。后者是这条断言的核心：`PCWSTR` 以第一个 NUL 为串尾，
    /// 所以旧实现（`to_wide` 不滤 NUL）会把 `"a\0b"` 当成 `"a"` 交给 Win32 ——
    /// 删掉的是「另一个键」，而回执/调用方以为动的是「`a\0b`」。
    ///
    /// 卫生口径照本文件既有真机探针：只碰自己的 scratch 键，`Drop` 里删干净。
    /// 判红自证：把 `reg_key_remove_checked` 的 `to_wide_checked(subkey)?` 换回
    /// `to_wide(subkey)` ⇒ 第②条红（`a` 那个键会被真删掉）。
    #[test]
    #[ignore = "真实写注册表（HKCU scratch 键 + Drop 清理），发布前门禁跑"]
    fn r5c_m01_含nul的目标必须被拒且同名真键不被删() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ};
        const SUB: &str = r"Software\TrimNulNameProbe";
        // 盘上真键叫 `a`（子键名就是单字符 `a`）
        const REAL: &str = r"Software\TrimNulNameProbe\a";
        struct Probe;
        impl Drop for Probe {
            fn drop(&mut self) {
                let _ = reg_key_remove(HKEY_CURRENT_USER, SUB, true);
            }
        }
        let _probe = Probe;

        // ① 先把「叫 a 的键」建出来并写一个值，确认它在盘上
        assert!(
            reg_restore_write(HKEY_CURRENT_USER, REAL, "v", REG_SZ, b"x\0"),
            "scratch 键写入应成功"
        );
        assert!(
            super::reg_key_exists(HKEY_CURRENT_USER, REAL),
            "前置：叫 a 的键必须在盘上"
        );

        // ② 用「a\0b」去删 —— 形态闸必须拒（Err 87），且盘上那个 `a` **必须还在**
        let evil = format!("{REAL}\0b");
        let r = super::reg_key_remove_checked(HKEY_CURRENT_USER, &evil, true);
        assert_eq!(r, Err(87), "含 NUL 的目标必须判 87 拒绝，实得 {r:?}");
        assert!(
            super::reg_key_exists(HKEY_CURRENT_USER, REAL),
            "含 NUL 的目标被拒后，盘上同名真键不得被删（这正是旧实现会踩的坑）"
        );

        // ③ 值名方向同样：含 NUL 的值名必须拒，且那个真值不得被删
        assert!(
            super::reg_restore_delete(HKEY_CURRENT_USER, REAL, &"v\0x".to_string()),
            "含 NUL 的值名必须被拒（拒 = false = 没删）"
        );
        assert!(
            unsafe { super::reg_read_value_typed(HKEY_CURRENT_USER, REAL, "v") }.is_some(),
            "含 NUL 的值名被拒后，盘上同名真值不得被删"
        );

        // ④ 空 / 仅空白 / 仅反斜杠的子键 ⇒ 同样 Err(87)（空路径口径 = 删整棵子树）
        for bad in ["", "   ", "\\", "\\\\"] {
            assert_eq!(
                super::reg_key_remove_checked(HKEY_CURRENT_USER, bad, true),
                Err(87),
                "畸形子键 {bad:?} 必须判 87 拒绝"
            );
        }
    }

    /// R5c-M01（B1-2）：名字形态闸的**纯逻辑**侧 —— 不碰注册表，四种形态各自判红。
    ///
    /// 为什么要有这一条（真机那条被 `#[ignore]`）：真机探针是发布前门禁跑的，
    /// 日常 `cargo test` 不执行 ⇒ 形态闸的活性在日常轮次里**无人看守**。
    /// 这一条把判据本体（`to_wide_checked` 拒 NUL 与控制字符）变成日常可跑的断言。
    ///
    /// 判红自证：把 `to_wide_checked` 的 `name_has_control_chars` 判据去掉
    /// ⇒ 第①②条红。
    #[test]
    fn r5c_m01_名字形态闸拒nul与控制字符() {
        use super::super::common::to_wide_checked;
        // ① NUL ⇒ Err(87)
        assert_eq!(to_wide_checked("a\0b"), Err(87), "含 NUL 必须拒");
        assert_eq!(to_wide_checked("\0abc"), Err(87), "开头 NUL 也必须拒");
        // ② 控制字符（\r \n \t）⇒ Err(87)
        assert_eq!(to_wide_checked("a\rb"), Err(87), "含 \\r 必须拒");
        assert_eq!(to_wide_checked("a\nb"), Err(87), "含 \\n 必须拒");
        assert_eq!(to_wide_checked("a\tb"), Err(87), "含 \\t 必须拒");
        // ③ 正常名字 ⇒ 放行，且得到的宽串与 to_wide 逐字一致
        assert!(to_wide_checked("Normal_Name.1").is_ok(), "正常名字必须放行");
        assert!(to_wide_checked("").is_ok(), "空值名合法（= 默认值），不得误拒");
        assert_eq!(
            to_wide_checked("Normal_Name.1").unwrap(),
            to_wide("Normal_Name.1"),
            "放行时宽串必须与 os 语义逐字一致"
        );
    }

    /// R5c-M02（B1-1）：删树原语的**空子键形态闸**（红线①②）。
    ///
    /// `RegDeleteTreeW(hive, "")` 的口径是「以 hKey 本身为根」⇒ 目标从「某个产品叶键」
    /// 变成「整棵 HKCU 子树」。闸必须在**任何 Win32 调用之前**。
    ///
    /// 判红自证：把 `reg_delete_subkey_shape_is_malformed` 的判据去掉（或让
    /// `reg_key_remove_checked` 不调它）⇒ 第①②条红。
    #[test]
    fn r5c_m02_空子键形态闸拒畸形路径() {
        use super::super::common::to_wide_checked;
        // ① 纯逻辑侧：空 / 仅空白 / 仅反斜杠 ⇒ 拒
        for bad in ["", "   ", "\\", "\\\\", " \t "] {
            assert_eq!(
                super::reg_delete_subkey_shape_is_malformed(bad),
                true,
                "畸形子键 {bad:?} 必须判为畸形"
            );
        }
        // ② 正常子键 ⇒ 不判畸形
        assert!(!super::reg_delete_subkey_shape_is_malformed("Software\\Foo"));
        assert!(!super::reg_delete_subkey_shape_is_malformed("Foo"));
        // ③ 名字形态闸独立生效（两闸覆盖面不同：形态闸管空/反斜杠，名字闸管 NUL）
        assert_eq!(to_wide_checked("a\0b"), Err(87), "名字闸必须独立拒 NUL");
    }

    /// R5c-M01（B1-2）：**写/删/建面必须吃名字形态闸** —— 源码形态断言。
    ///
    /// 为什么需要这一条：上面两条测的是**闸本体**（`to_wide_checked` 拒 NUL、
    /// `reg_delete_subkey_shape_is_malformed` 拒畸形），但它们**不保证原语真的调了它**。
    /// 把 `reg_key_remove_checked` 里的 `to_wide_checked(subkey)?` 换回 `to_wide(subkey)`
    /// 时，前两条仍然全绿 —— 而原语已经退回「判定字节 ≠ 执行字节」的老形态
    /// （`PCWSTR` 以第一个 NUL 为串尾 ⇒ `"a\0b"` 执行的是 `"a"`）。
    ///
    /// 这正是方案 §4.1 B1-2 的破坏自证原文：「`checked` 换回 `to_wide` ⇒ 该用例必红」。
    /// 本条就是那个「该用例」：它把「原语调了闸」这件事本身变成可判红的断言。
    ///
    /// 判定口径：切掉 `mod tests` 之后的测试面，只判**生产段**；在生产段里逐个
    /// 写/删/建出口找「用了 `to_wide` 而不是 `to_wide_checked`」的形态。
    /// 允许 `to_wide` 出现的只有**读面**（枚举/查询/读值）—— 读到一个截断名不产生
    /// 破坏性副作用（口径见 `common::to_wide_checked` 的文档注释）。
    #[test]
    fn r5c_m01_写删建面必须吃名字形态闸() {
        let src = include_str!("registry.rs");
        let prod = &src[..src.find("mod tests").expect("找不到单测段起点")];

        /// 取「从标记起、到该函数体花括号配平处」的**函数体**片段（不含签名行与 `use` 行）。
        ///
        /// 三个坑（都踩过）：
        /// ① 结束锚不能用「下一个函数声明」——会撞上函数体内部的嵌套 `fn`/闭包，把片段截短；
        /// ② 函数体起点不能取「标记后的第一个 `{`」——签名下一行的
        /// `use windows::…::{RegDeleteTreeW, RegDeleteKeyW};` 里也有花括号；
        /// ③ **片段必须不含 `use` 行**——`use` 里出现的 `RegDeleteTreeW` 是「导入这个名字」，
        ///    不是「调用它」；把它算进位置比较，形态闸（真正的前置判定）就会显得
        ///    「排在 Win32 调用之后」⇒ 顺序断言假红。
        ///
        /// 所以：从标记起**逐行跳过 `use ` 开头的行**，找到的第一个带 `{` 的行是函数体起点；
        /// 返回的片段从该行开始（`use` 行已被跳过，不会进片段）。
        fn body_of(prod: &str, marker: &str) -> String {
            let start = prod.find(marker).unwrap_or_else(|| panic!("找不到 {marker}"));
            let mut open = None;
            let mut cursor = start;
            for line in prod[start..].lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("use ") {
                    cursor += line.len() + 1;
                    continue;
                }
                if let Some(i) = line.find('{') {
                    open = Some(cursor + i);
                    break;
                }
                cursor += line.len() + 1;
            }
            let open = open.unwrap_or_else(|| panic!("{marker} 之后找不到函数体的 {{"));
            let mut depth = 0usize;
            let mut end = prod.len();
            for (i, ch) in prod[open..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            // 片段起点取**函数体 `{` 所在行**的开头。`use` 行已在上面被跳过，
            // 但 `use …::{A, B};` 里的 `{` 落在 use 行本身 ⇒ 该行仍会被 rfind 命中，
            // 所以这里显式判一次：起点行含 "use " ⇒ 从 `{` 之后开始。
            let body_start = prod[..open].rfind('\n').map(|i| i + 1).unwrap_or(start);
            let body_start = if prod[body_start..open].contains("use ") {
                open
            } else {
                body_start
            };
            prod[body_start..end].to_string()
        }

        // ① 删树原语：入口必须是 checked，且形态闸必须在任何 Win32 调用之前
        let remove_fn = body_of(prod, "pub fn reg_key_remove_checked");
        assert!(
            remove_fn.contains("to_wide_checked(subkey)"),
            "删树原语入口必须吃 to_wide_checked（换回 to_wide ⇒ 判定字节≠执行字节，红线⑨）"
        );
        assert!(
            remove_fn.contains("reg_delete_subkey_shape_is_malformed(subkey)"),
            "删树原语入口必须过空子键形态闸（RegDeleteTreeW 的空路径口径 = 删整棵子树，红线①②）"
        );
        let shape_at = remove_fn
            .find("reg_delete_subkey_shape_is_malformed(subkey)")
            .expect("找不到形态闸调用");
        // 找**调用形态** `RegDeleteTreeW(`（带左括号）——注释里提到这个名字时不带括号，
        // 那是「说明」不是「调用」，算进位置比较会让顺序断言假红。
        let first_win32 = remove_fn
            .find("RegDeleteTreeW(")
            .expect("找不到 RegDeleteTreeW 调用");
        assert!(
            shape_at < first_win32,
            "形态闸必须排在任何 Win32 调用之前（RegDeleteTreeW 之后判就晚了）"
        );

        // ② 建面原语
        let ensure_fn = body_of(prod, "pub fn reg_key_ensure_checked");
        assert!(
            ensure_fn.contains("to_wide_checked(subkey)"),
            "建面原语（reg_key_ensure_checked）必须吃 to_wide_checked"
        );

        // ③ 写值面：键路径与值名**都要**过闸
        let write_fn = body_of(prod, "pub(super) unsafe fn reg_write_value_checked");
        assert!(
            write_fn.contains("to_wide_checked(subkey)"),
            "写值面（reg_write_value_checked）的键路径必须吃 to_wide_checked"
        );
        assert!(
            write_fn.contains("to_wide_checked(value_name)"),
            "写值面（reg_write_value_checked）的值名必须吃 to_wide_checked（值名方向此前全仓零闸）"
        );

        // ④ 删值面：键路径与值名都要过闸（两个出口各钉一次）
        let restore_del = body_of(prod, "pub fn reg_restore_delete");
        assert!(
            restore_del.contains("to_wide_checked(subkey)")
                && restore_del.contains("to_wide_checked(value_name)"),
            "删值面（reg_restore_delete）必须对键路径与值名都吃 to_wide_checked"
        );
        let del_value = body_of(prod, "pub(super) unsafe fn reg_delete_value");
        assert!(
            del_value.contains("to_wide_checked(&subkey)")
                && del_value.contains("to_wide_checked(value_name)"),
            "删值面（reg_delete_value）必须对键路径与值名都吃 to_wide_checked"
        );
    }

    /// R5b-M01：删值入口的「键不存在」判定必须只认 2/3，其余失败码一律判失败。
    #[test]
    fn 删值_只把键不存在当幂等成功() {
        assert!(open_key_missing_is_idempotent(2), "ERROR_FILE_NOT_FOUND = 键不存在");
        assert!(open_key_missing_is_idempotent(3), "ERROR_PATH_NOT_FOUND = 路径不存在");
        assert!(!open_key_missing_is_idempotent(5), "ACCESS_DENIED 必须判失败（旧实现报成功）");
        assert!(!open_key_missing_is_idempotent(1008), "其它失败码必须判失败");
    }

    /// P0-3：三态读器 `Unknown` 的载荷是错误码名 —— 标签函数是它落日志/回执的唯一出处，
    /// 未收录的码必须退化为纯数字而不是报错 panic（读器本身不能因记原因而二次失败）。
    #[test]
    fn 三态读器_错误码标签只含码名() {
        assert_eq!(win_reg_err_label(2), "ERROR_FILE_NOT_FOUND");
        assert_eq!(win_reg_err_label(3), "ERROR_PATH_NOT_FOUND");
        assert_eq!(win_reg_err_label(5), "ERROR_ACCESS_DENIED");
        assert_eq!(win_reg_err_label(234), "ERROR_MORE_DATA");
        assert_eq!(win_reg_err_label(1008), "WIN32_ERROR(1008)");
    }

    /// P0-3 真机 `#[ignore]` 探针（**本轮未执行**，归发布前门禁）：HKCU 专用 scratch 键上
    /// 把三态的三条腿各钉一次。旧实现三条腿全塌成同一个 `None`，而 `build_restore_ops`
    /// 把 `None` 读成「确认不存在」并生成 Delete —— 一次解码失败就会永久删掉本来存在的值。
    ///
    /// 卫生口径照 `engine::reg_backup::live_roundtrip_原生import_类型不降级`：只碰自己的
    /// scratch 键，`Drop` 里删干净（含断言提前返回的路径）。
    ///
    /// 判红自证：把 `read_reg_value_state` 的「尺寸查询失败且码非 2」分支从 `Unknown`
    /// 折回 `Absent` ⇒ 第③条红；把第②b 条的 `q1.0 == ERROR_FILE_NOT_FOUND` 判据去掉
    /// ⇒ 第②b 条红（键在、值名不在被误报成 Unknown）。
    #[test]
    #[ignore = "真实写注册表（HKCU scratch 键 + Drop 清理），发布前门禁跑"]
    fn 三态读器_真机_absent_value_unknown_三条腿() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_DWORD};
        const SUB: &str = r"Software\TrimRegTriStateProbe";
        struct Probe;
        impl Drop for Probe {
            fn drop(&mut self) {
                let _ = reg_key_remove(HKEY_CURRENT_USER, SUB, true);
            }
        }
        let _probe = Probe;

        // ① 键本体不存在 → RegOpenKeyExW 报「找不到」，必须是 Absent（不是 Unknown）
        assert!(
            matches!(read_reg_value_state(HKEY_CURRENT_USER, SUB, "whatever", false), RegReadState::Absent),
            "键不存在必须是 Absent"
        );

        // ② 写入并读回 → Value，且类型/字节口径与旧 faithful 链一致
        assert!(
            reg_restore_write(HKEY_CURRENT_USER, SUB, "dw", REG_DWORD, &42u32.to_le_bytes()),
            "scratch 键写入应成功"
        );
        match read_reg_value_state(HKEY_CURRENT_USER, SUB, "dw", false) {
            RegReadState::Value(t, d) => assert_eq!((t, d.as_str()), ("REG_DWORD", "42")),
            other => panic!("读成功必须是 Value，实得 {other:?}"),
        }

        // ②b 键在而值名不存在 → 仍是 Absent（开了键不等于读成功）
        match read_reg_value_state(HKEY_CURRENT_USER, SUB, "nope", false) {
            RegReadState::Absent => {}
            other => panic!("键在、值名缺必须是 Absent，实得 {other:?}"),
        }

        // ③ 类型闸门打不通（REG_DWORD 只落 2 字节）→ Unknown。
        //    这条就是 P0-3 的病根本体：旧实现返回 None，还原链读成「不存在」→ Delete。
        assert!(
            reg_restore_write(HKEY_CURRENT_USER, SUB, "bad", REG_DWORD, &[1, 2]),
            "畸形 REG_DWORD 写入应被注册表接受（API 不校验长度，正因如此读侧必须有闸门）"
        );
        match read_reg_value_state(HKEY_CURRENT_USER, SUB, "bad", false) {
            RegReadState::Unknown(r) => {
                assert_eq!(r, "decode_failed", "Unknown 载荷必须是错误码名，实得 {r}");
            }
            other => panic!("REG_DWORD 长度不足必须呈报 Unknown，实得 {other:?}"),
        }
    }

    /// P1-6G 真机 `#[ignore]` 探针（**本轮未执行**，归发布前门禁）：超长**值名**必须能枚举到。
    ///
    /// 旧写法 `[0u16; 260]` 定长缓冲 + 把 `ERROR_MORE_DATA` 当普通错误 `break`，
    /// 于是 300 字符的值名既不截断上报、也不计入不完整 —— 调用方（`value:"*"` 通配展开、
    /// 管理摘要对账）拿到的是一份「看起来枚举完了」的短清单。
    /// 值名合法上界是 `KEY_MAX_VALUE_NAME_LEN` = 16367，300 完全合法。
    ///
    /// 判红自证：把 `reg_enum_values_scan` 的 `ERROR_MORE_DATA` 支并回 `r.is_err()`
    /// ⇒ 第一条红（长名消失）；把 `(names, true)` 改成 `(names, false)` ⇒ 第二条红。
    /// 卫生口径照三态探针：只碰自己的 scratch 键，`Drop` 里删干净。
    #[test]
    #[ignore = "真实写注册表（HKCU scratch 键 + Drop 清理），发布前门禁跑"]
    fn 超长值名必须枚举到且清单不得谎报完整() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ};
        const SUB: &str = r"Software\TrimEnumProbe";
        struct Probe;
        impl Drop for Probe {
            fn drop(&mut self) {
                let _ = reg_key_remove(HKEY_CURRENT_USER, SUB, true);
            }
        }
        let _probe = Probe;
        let long = "x".repeat(300);
        let payload: Vec<u8> = to_wide("探针").into_iter().flat_map(|u| u.to_le_bytes()).collect();
        assert!(
            reg_restore_write(HKEY_CURRENT_USER, SUB, &long, REG_SZ, &payload),
            "300 字符值名应可写入（上界 16367）"
        );
        let (names, incomplete) = reg_enum_value_names_pub(HKEY_CURRENT_USER, SUB);
        assert!(names.iter().any(|n| *n == long), "超长值名必须枚举到，实得 {names:?}");
        assert!(!incomplete, "正常结束不得报「清单不完整」");
    }

    /// R5b-M21：删键失败原因必须四分，不许折回一句「失败」。
    ///
    /// R5c-M01（v7.2 B1-1/B1-2）：**87 升格为专属码** —— 它现在是「目标名非法」
    /// （含 NUL/控制字符，或子键路径为空/畸形）的专用错误码，回执必须能说清
    /// 为什么被拒，不能落回 `win32=87` 让用户自己猜。
    /// 通用兜底路径另用一个未登记的码验（`12345`）—— 兜底行为没消失，
    /// 只是不再拿 87 来代表它。
    #[test]
    fn 删键失败原因四种不折成一句() {
        let denied = remove_cause_label(5);
        let has_children = remove_cause_label(1018);
        let missing = remove_cause_label(2);
        assert!(denied.contains('5'), "{denied}");
        assert!(has_children.contains("1018"), "{has_children}");
        assert!(missing.contains('2'), "{missing}");
        assert_ne!(denied, has_children);
        assert_ne!(has_children, missing);
        // 87 = 目标名非法（专属文案，必须点名形态问题，不能与通用兜底同形）
        let malformed = remove_cause_label(87);
        assert!(malformed.contains("87"), "87 必须点名错误码: {malformed}");
        assert!(malformed.contains("NUL") || malformed.contains("畸形"), "87 必须说清形态问题: {malformed}");
        assert_ne!(malformed, remove_cause_label(12345), "87 不得与通用兜底折成同一句");
        // 通用兜底仍在（未登记的码走 win32=N 形态）
        assert_eq!(remove_cause_label(12345), "win32=12345");
    }

    /// R5c-M04 回归钉：类型长度闸必须**严格相等** —— 长值同样判失败。
    ///
    /// 旧写法 `buf.len() >= 4` 只把「短」挡成 decode_failed，「长」的一侧放行并静默丢尾字节：
    /// 八个字节的 REG_DWORD 会解码成前四字节的 Value，还原时按四字节写回 ⇒ 原值高位永久消失，
    /// 而回执说「已还原」。
    #[test]
    fn 定长类型的长度闸必须严格相等() {
        use windows::Win32::System::Registry::{REG_DWORD, REG_QWORD};
        assert_eq!(
            decode_reg_value_bytes(REG_DWORD, &[0u8; 4], true).map(|(t, d)| (t, d)),
            Some(("REG_DWORD", "0".to_string())),
            "四字节 DWORD 必须正常解码"
        );
        assert!(
            decode_reg_value_bytes(REG_DWORD, &[0u8; 8], true).is_none(),
            "八字节 DWORD 必须判 decode_failed（不能按前四字节解码）"
        );
        assert!(
            decode_reg_value_bytes(REG_DWORD, &[0u8; 2], true).is_none(),
            "两字节 DWORD 必须判 decode_failed"
        );
        assert_eq!(
            decode_reg_value_bytes(REG_QWORD, &[0u8; 8], true).map(|(t, d)| (t, d)),
            Some(("REG_QWORD", "0".to_string())),
            "八字节 QWORD 必须正常解码"
        );
        assert!(
            decode_reg_value_bytes(REG_QWORD, &[0u8; 16], true).is_none(),
            "十六字节 QWORD 必须判 decode_failed（不能按前八字节解码）"
        );
    }

    /// R5c-M06 回归钉：UTF-16 **严格**解码 —— 孤立代理项判失败，不做有损替换。
    ///
    /// `from_utf16_lossy` 会把孤立代理项换成 U+FFFD，而这条链的输出会写回注册表
    /// （备份 → 还原）⇒ 有损替换等于把原值永久改成另一个值，回执却说「已还原」。
    #[test]
    fn 非法utf16序列必须判解码失败() {
        use windows::Win32::System::Registry::REG_SZ;
        // U+D800（孤立高代理项）+ 结尾 NUL
        let lone_surrogate: Vec<u8> = [0x00u8, 0xD8, 0x00, 0x00].to_vec();
        assert!(
            decode_reg_value_bytes(REG_SZ, &lone_surrogate, true).is_none(),
            "孤立代理项必须判解码失败（不得替换成 U+FFFD）"
        );
        // 正常中文串必须照旧解出
        let ok: Vec<u8> = "中".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(
            decode_reg_value_bytes(REG_SZ, &ok, true).map(|(t, d)| (t, d)),
            Some(("REG_SZ", "中".to_string())),
            "合法 UTF-16 必须照旧解码"
        );
    }

    /// R5c-M05 回归钉：子键枚举必须区分「没有子键」与「没枚举完」。
    ///
    /// 开键失败不是「这个键没有子键」—— 两者在调用方同形时，「少迭代」会被念成「跑完了」。
    #[test]
    fn 子键枚举必须报出没枚举完() {
        let (names, incomplete) = reg_enum_subkeys_pub_scan(hive_hklm(), r"Software\Trim不存在的键_枚举探针");
        assert!(names.is_empty(), "不存在的键不应枚举出子键");
        assert!(incomplete, "开键失败必须算 incomplete（不是「没有子键」）");
    }
}
