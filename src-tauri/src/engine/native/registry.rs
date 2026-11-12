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

/// 所有「按注册表回报长度分配」的读值入口共用的 1 MiB 上限（R5c-v8-L09）。
///
/// 注册表值本身可以到 MB 量级，但本仓消费的真实值（字符串/二进制/多字符串）远小于
/// 1 MiB；损坏或恶意写入的值可以回报一个超大 size 让 `vec![0u8; size]` 直接 OOM。
/// 超限一律判读失败并 warn，不再只给部分读器加闸。
pub const MAX_REG_VALUE_BYTES: u32 = 1024 * 1024;

/// 读值长度闸（纯函数，单测直接喂 >1 MiB）。
fn value_size_ok(size: u32) -> bool {
    if size > MAX_REG_VALUE_BYTES {
        crate::engine::log::write_log(
            "warn",
            &format!("注册表值读取超过 {MAX_REG_VALUE_BYTES} 字节上限（回报 {size} 字节），已拒绝分配"),
        );
        false
    } else {
        true
    }
}

/// 读注册表 DWORD 的可判空版本（B11：原 PS 实现靠 `Get-ItemProperty` + `$null` 判缺，
/// 这里用 `Option` 表达同一语义 —— 值不存在 / 类型不对 / 打不开键都算 `None`）。
///
/// 返回值按**无符号**读出再转 i64：DWORD 本就是 32 位无符号，按 i32 读会把
/// `0xFFFFFFFF` 这类阈值变成 -1，而调用方（如 SVCHost 拆分阈值）拿它做数值比较。
///
/// B03（方案 R5c-v8-L01）：函数名带上**数值口径** —— `_u32_as_i64`。
/// 同一件事在本文件有三种口径（u32 提升为 i64 / 纯 u32 / 按 i32 解读），
/// 名字不写口径时，调用方只能靠读实现才知道拿到的是哪一种；
/// `0xFFFFFFFF` 在三种口径下分别是 4294967295 / 4294967295 / -1。
pub fn read_reg_dword_u32_as_i64(hive: HKEY, subkey: &str, value: &str) -> Option<i64> {
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
    read_reg_dword_u32_as_i64(HKEY_LOCAL_MACHINE, subkey, value)
}

/// 读注册表 QWORD 值（REG_QWORD → i64）—— M2-C 检测断言用。
///
/// **为什么需要**（`read_reg_dword_u32_as_i64` / `read_reg_string` / `read_reg_binary_opt`
/// 都覆盖不到它）：`perf_wu_pause` 把暂停起止时间写成 **FILETIME**（100ns 计数
/// 的 QWORD，`[DateTime]::UtcNow.ToFileTimeUtc()`），那是 64 位值 ——
/// 用 dword 原语读会拿到低 32 位（截断到 1950~2042 年之间的随机日期），
/// 用 string 原语读会因为类型不是 REG_SZ 而返回 `None`。
///
/// **返回 `i64` 而不是 `u64`**：FILETIME 的实际取值在 1.3e17 上下（远小于
/// `i64::MAX` ≈ 9.2e18），符号位一直是 0。但用 `i64` 是为了和
/// [`read_reg_dword_u32_as_i64`] 的返回类型一致（上层算区间时不必到处转换），
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
    if !value_size_ok(size) {
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
pub(super) unsafe fn reg_enum_values_scan_tagged(hk: HKEY) -> (Vec<(String, bool)>, bool) {
    // RegEnumValueW 的 pcchName 入参是「缓冲区长度」、出参是「含尾 NUL 的所需长度」；
    // 值名合法上界即 KEY_MAX_VALUE_NAME_LEN（16367），再加 NUL 一位。以此为硬上限，
    // 既不再按 260 截断，也不给畸形返回值开无界分配。
    const ENUM_NAME_CAP: usize = 16367 + 1;
    const ERROR_MORE_DATA: u32 = 234;
    let mut names: Vec<(String, bool)> = Vec::new();
    let mut index = 0u32;
    let mut cap = 260usize;
    // R5c-M04-02（2026-11-13）：缓冲提到循环外按需放大——旧写法每个值名一次堆分配，
    // 通配展开对多值键枚举时分配次数 = 值数；`resize` 只在 cap 增长后补零，其余迭代零分配。
    let mut name_buf: Vec<u16> = Vec::with_capacity(260);
    loop {
        if name_buf.len() < cap {
            name_buf.resize(cap, 0);
        }
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
        let units = &name_buf[..name_len as usize];
        // A6-M01：有损名（U+FFFD / 未配对代理项）可以展示，但绝不能作为删除目标。
        // 这里保留「是否 lossy」这一位，调用方按用途决定丢弃还是计数。
        let lossy = String::from_utf16(units).is_err();
        let name = decode_name_lossy_with_warn(units);
        // R5c-M03：**空名是默认值，它是合法值名** —— `RegEnumValueW` 把默认值以空名列出，
        // 删除面 `to_wide_checked("")` 也放行（见单测「空值名合法（= 默认值）」）。
        // 旧实现 `if !name.is_empty()` 在这里丢掉它，`incomplete` 仍是 false ⇒「有值」被
        // 报成「没有值」：`value:"*"` 会漏删默认值，展开结果为空还会被当成「空键 = 目标状态
        // 已达成」记成功。过滤只许留在只读展示包装 [`reg_enum_values`]；本函数的清单契约
        // 是「一个都不丢」，调用方自己按需筛。
        names.push((name, lossy));
        index += 1;
    }
}

/// 兼容旧调用方：返回名字（含 lossy 名）与「枚举是否完整」。
pub(super) unsafe fn reg_enum_values_scan(hk: HKEY) -> (Vec<String>, bool) {
    let (tagged, incomplete) = reg_enum_values_scan_tagged(hk);
    (tagged.into_iter().map(|(name, _)| name).collect(), incomplete)
}

/// 只读枚举出口（右键菜单、路径扫描等「少一条只是显示不全」的调用方）。
/// 需要区分「没有」与「没枚举完」的调用方一律走 [`reg_enum_values_scan`]。
///
/// R5c-M03：空名（= 默认值）在这里被过滤 —— 展示链没有一行「无名值」可显示
/// （`cm_scan` 的 GUID 判定、`startup_scan` 的 `if vp.is_empty()` 本来就跳过它）。
/// 过滤**只许留在这里**：枚举层若也过滤，调用方就会把「有默认值」读成「这个键没有值」。
pub(super) unsafe fn reg_enum_values(hk: HKEY) -> Vec<String> {
    reg_enum_values_scan(hk)
        .0
        .into_iter()
        .filter(|name| !name.is_empty())
        .collect()
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
    if !value_size_ok(size) { return None; }
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
///
/// B03（方案 R5c-v8-L01）：函数名带上数值口径 —— `_u32`。
/// 与 [`read_reg_dword_u32_as_i64`]（同值、提升为 i64）区分开：
/// 两者的**值**相同但**类型**不同，调用方按类型决定后续运算。
pub(super) unsafe fn reg_read_dword_u32(hk: HKEY, name: &str) -> Option<u32> {
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut buf = [0u8; 4];
    let mut size = 4u32;
    if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size)).is_err() {
        return None;
    }
    // R5c-L02：长度闸必须严格等于 DWORD 宽度。短一截的畸形 DWORD 会让缓冲区尾部保持 0，
    // 读出一个假数值而不是「读不出」。
    if ty != REG_DWORD || size != 4 { return None; }
    Some(u32::from_le_bytes(buf))
}

/// DWORD 按 **i32（有符号）** 解读并转成字符串 —— 展示/备份链的口径。
///
/// B03（方案 R5c-v8-L01）：这一档原先是 `read_reg_value_state` 里的一行内联
/// `(raw as i32).to_string()`，读者无从判断它与另两档（u32 / u32→i64）的区别。
/// 抽成有名字的函数后，三档口径在本文件里各自有名：
/// - [`read_reg_dword_u32_as_i64`]：u32 提升为 i64（`0xFFFFFFFF` = 4294967295）；
/// - [`reg_read_dword_u32`]：纯 u32；
/// - 本函数：i32（`0xFFFFFFFF` = -1，对齐 .NET `GetValue` / PS `[string]$v`）。
pub(super) fn reg_dword_as_i32_text(raw: u32) -> String {
    // .NET 把 DWORD 读成 int（有符号），`[int]$v` 再转字符串 —— 保留该口径
    (raw as i32).to_string()
}

// ==================== B11：pwsh 步骤原生解释器的执行出口 ====================

/// 键存在性三态（R5c-v8-L04）：`5/拒绝访问` 不得折成「不存在」。
///
/// 旧 `bool` 出口把 `RegOpenKeyExW` 的任何失败都当 `false`，调用方于是把
/// 「权限不足/IO 错」读成「功能没装」——卸载列表、残留判定、启动项摘要都会因此
/// 少报一条而不留任何痕迹。三态把「确认不存在」与「读不出来」分开。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Exists,
    /// 只认「找不到」两个码（2/3），与删值幂等判据同源。
    Missing,
    /// 读不出来（访问拒绝等），载荷是 Win32 码。
    Unknown(u32),
}

/// 开键结果码 → 三态（纯函数，单测可直接喂 5）。
fn key_state_from_open_code(code: u32) -> KeyState {
    if code == 0 {
        KeyState::Exists
    } else if open_key_missing_is_idempotent(code) {
        KeyState::Missing
    } else {
        KeyState::Unknown(code)
    }
}

#[cfg(test)]
thread_local! {
    /// 测试钩子：把「开键结果码」钉成指定值，用来在无权限样本的机器上验证
    /// `5/拒绝访问 ⇒ Unknown`。线程局部，测试并行互不污染。
    static FORCED_EXISTS_CODE: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// 键存在性（对应 PS `Test-Path HKxx:\…`）的三态版本。
pub fn reg_key_exists_state(hive: HKEY, subkey: &str) -> KeyState {
    #[cfg(test)]
    if let Some(code) = FORCED_EXISTS_CODE.with(|c| c.get()) {
        return key_state_from_open_code(code);
    }
    // 读面不过名字形态闸（pssteps 的读/写分工注释）：只读存在性查询没有破坏性副作用，
    // 控制字符键名不应被误报成 Unknown；写/删面仍走 `to_wide_checked`。
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        let r = RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk);
        if r.is_ok() {
            let _ = RegCloseKey(hk);
            KeyState::Exists
        } else {
            key_state_from_open_code(r.0)
        }
    }
}

/// 键存在性（bool 外观）—— 只读展示链与无法消费三态的旧调用方保留此入口；
/// **有「不完整」语义的调用方必须用 [`reg_key_exists_state`]**。
pub fn reg_key_exists(hive: HKEY, subkey: &str) -> bool {
    matches!(reg_key_exists_state(hive, subkey), KeyState::Exists)
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
    // 首段为空（`\Foo`）、尾分隔符、连续分隔符都会让 `rsplit_once` 把父键落到
    // hive 本身或造出空段。判据必须覆盖**任何空段**，不能只拒空串/纯反斜杠：
    // `\Foo` 的父键是 `""`，`RegOpenKeyExW(hive, "")` 打开的就是 hive 根。
    t.is_empty() || t.split('\\').any(|seg| seg.is_empty())
}

/// 删除键的带因版本：返回 Win32 错误码（0 不当错误），供回执点名失败原因。
///
/// **形态闸在入口**（R5c-M02）：`subkey` 空 / 仅空白 / 仅反斜杠 ⇒ `Err(87)`；
/// 含 NUL 或控制字符 ⇒ `Err(87)`（`to_wide_checked`，红线⑨）。
/// 两者都发生在**任何 Win32 调用之前** —— `RegDeleteTreeW` 的空路径口径会把目标
/// 从「一个键」换成「整棵子树」，闸必须落在调用之前而不是之后。
///
/// 与 PS `Remove-Item` 的**有意差异**（R5c-v8-L06）：键本来就不存在（2/3）按幂等成功，
/// 与删值侧对齐；PS 对不存在的键会报错。不要把这层包装宣传成「与 PS 完全等价」。
pub fn reg_key_remove_checked(hive: HKEY, subkey: &str, recurse: bool) -> Result<(), u32> {
    use windows::Win32::System::Registry::{RegDeleteTreeW, RegDeleteKeyW};
    use windows::Win32::Foundation::ERROR_REGISTRY_IO_FAILED;
    if reg_delete_subkey_shape_is_malformed(subkey) {
        return Err(87);
    }
    let sk = to_wide_checked(subkey)?;
    unsafe {
        if recurse {
            // RegDeleteTreeW 只清子键/值；键本身必须再调 RegDeleteKeyW。
            // 两步都把 2/3（不存在）视为幂等成功，其余错误原样回传。
            let tree = RegDeleteTreeW(hive, PCWSTR(sk.as_ptr()));
            if tree.is_err() && !open_key_missing_is_idempotent(tree.0) {
                return Err(tree.0);
            }
            if tree.is_ok() {
                let key = RegDeleteKeyW(hive, PCWSTR(sk.as_ptr()));
                if key.is_err() && !open_key_missing_is_idempotent(key.0) {
                    return Err(key.0);
                }
            }
            // Win32 的 Ok 不等于“键已消失”：删后现读是回执唯一可采信的判据。
            // 读不出来也不能算成功（R5c-v8-L04：三态不得折回 bool）。
            return match reg_key_exists_state(hive, subkey) {
                KeyState::Missing => Ok(()),
                KeyState::Exists => Err(ERROR_REGISTRY_IO_FAILED.0),
                KeyState::Unknown(code) => Err(code),
            };
        }
        // 非递归删除只对**最末段**有效：拆出父键与末段
        let Some((parent, last)) = subkey.rsplit_once('\\') else {
            let e = RegDeleteKeyW(hive, PCWSTR(sk.as_ptr()));
            // R5c-v8-L06：删键的「已不存在」幂等口径与删值对齐（2/3 都算成功）。
            return if e.is_ok() || open_key_missing_is_idempotent(e.0) { Ok(()) } else { Err(e.0) };
        };
        if last.is_empty() {
            // R5c-L07：尾分隔符会让 `last` 为空段，而 `RegDeleteKeyW(h, L"")` 的语义
            // 本仓未真机核验（Wine/ReactOS 按「删句柄自身的键」实现）——两种口径都会把
            // 删除对象悄悄换成父键。按畸形 fail-closed 拒绝，不让多一个反斜杠改变目标。
            return Err(87);
        }
        // R5c-v8-L03：末段转换提前到**任何开键之前**。旧顺序先开父键再转末段，
        // 末段含 NUL/控制字符时 `?` 直接早退，父键句柄泄漏。
        let parent_w = to_wide_checked(parent)?;
        let last_w = to_wide_checked(last)?;
        let mut hk = HKEY::default();
        // 父键句柄只作路径锚点：文档明确 RegDeleteKeyW 的 hKey 访问权限不影响删除操作，
        // 旧实现用 KEY_SET_VALUE（删值面的掩码）属于误导，最小权限取 KEY_READ。
        let open = RegOpenKeyExW(hive, PCWSTR(parent_w.as_ptr()), Some(0), KEY_READ, &mut hk);
        if open.is_err() {
            return Err(open.0);
        }
        #[cfg(test)]
        OPEN_OPENS.with(|c| c.set(c.get() + 1));
        // RAII：开键后的任何早退（含测试钩子/未来新增分支）都必须关句柄。
        let guard = ScopedRegKey(hk);
        #[cfg(test)]
        if FORCE_EARLY_RETURN_AFTER_OPEN.with(|c| c.get()) {
            return Err(87);
        }
        let r = RegDeleteKeyW(guard.0, PCWSTR(last_w.as_ptr()));
        if r.is_ok() || open_key_missing_is_idempotent(r.0) { Ok(()) } else { Err(r.0) }
    }
}

/// 开键句柄的 RAII 守卫（R5c-v8-L03）。
struct ScopedRegKey(HKEY);

impl Drop for ScopedRegKey {
    fn drop(&mut self) {
        #[cfg(test)]
        OPEN_CLOSES.with(|c| c.set(c.get() + 1));
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

#[cfg(test)]
thread_local! {
    static OPEN_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static OPEN_CLOSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// 测试钩子：模拟「开键之后才发现末段非法」的早退路径，验证 RAII 关句柄。
    static FORCE_EARLY_RETURN_AFTER_OPEN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
    let sk = match to_wide_checked(subkey) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), true),
    };
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
///
/// R5c-L10：返回 `(ids, incomplete)` —— 开键失败与枚举中途报错都不是「没有设备」，
/// 调用方必须能把「读不动」与「空集」分开回执。
pub fn reg_enum_dev_ids(class: &str) -> (Vec<String>, bool) {
    const BASE: &str = r"SYSTEM\CurrentControlSet\Enum\PCI";
    let mut out = Vec::new();
    let mut incomplete = false;
    let mut root = HKEY::default();
    unsafe {
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(to_wide(BASE).as_ptr()), Some(0), KEY_READ, &mut root)
            .is_err()
        {
            return (out, true);
        }
        let (devs, root_incomplete) = reg_enum_subkeys_scan(root);
        incomplete |= root_incomplete;
        for dev in devs {
            let dev_path = format!("{BASE}\\{dev}");
            let mut dev_hk = HKEY::default();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(to_wide(&dev_path).as_ptr()), Some(0), KEY_READ, &mut dev_hk)
                .is_err()
            {
                incomplete = true;
                continue;
            }
            let (insts, dev_incomplete) = reg_enum_subkeys_scan(dev_hk);
            incomplete |= dev_incomplete;
            for inst in insts {
                let inst_path = format!("{dev_path}\\{inst}");
                let mut inst_hk = HKEY::default();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(to_wide(&inst_path).as_ptr()), Some(0), KEY_READ, &mut inst_hk)
                    .is_err()
                {
                    incomplete = true;
                    continue;
                }
                let (hit, class_incomplete) = class_read_matches(class, reg_read_string(inst_hk, "Class"));
                incomplete |= class_incomplete;
                let _ = RegCloseKey(inst_hk);
                if hit {
                    out.push(format!("PCI\\{dev}\\{inst}"));
                }
            }
            let _ = RegCloseKey(dev_hk);
        }
        let _ = RegCloseKey(root);
    }
    (out, incomplete)
}

/// `Class` 值读取结果 → (是否命中, 是否因读失败而不完整)。
///
/// R5c-v8-L05：旧写法 `.unwrap_or(false)` 把「读不出来」静默折成「不是这个类」——
/// 权限/IO 失败的设备从清单里消失，`incomplete` 仍是 false。读失败必须与开键失败同口径。
fn class_read_matches(class: &str, read: Option<String>) -> (bool, bool) {
    match read {
        Some(c) => (c.eq_ignore_ascii_case(class), false),
        None => (false, true),
    }
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
        // R5c-v8-L09：所有读值入口共用同一道 1 MiB 上限。
        if !value_size_ok(size) {
            let _ = RegCloseKey(hk);
            return None;
        }
        if ty != REG_SZ {
            let _ = RegCloseKey(hk);
            return None;
        }
        if size == 0 {
            // R5c-L03：存在但为空 ⇒ `Some("")`，与 `read_reg_binary_opt` 同口径。
            // 旧实现把 `size == 0` 判成「不存在」，同一个空值在两读器上结论相反。
            let _ = RegCloseKey(hk);
            return Some(String::new());
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
/// - [`read_reg_dword_u32_as_i64`] 只认 `REG_DWORD`（4 字节）；
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
        // 上限防御：与所有读值入口共用 [`MAX_REG_VALUE_BYTES`]（R5c-v8-L09）。
        if !value_size_ok(size) {
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
        // R5c-v8-L09：值状态读器同样受 1 MiB 上限约束；超限是「读不出来」，不是「不存在」。
        if !value_size_ok(size) {
            let _ = RegCloseKey(hk);
            return RegReadState::Unknown("value_too_large".to_string());
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
                // R5c-M04-01：重试路径同样要复检 1 MiB 闸。入口闸只覆盖首次查询的尺寸，
                // 并发写方可在两次查询之间把值涨到任意大，按增长后的 size 分配会 OOM。
                if !value_size_ok(size) {
                    let _ = RegCloseKey(hk);
                    return RegReadState::Unknown("value_too_large".to_string());
                }
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
/// `REG_EXPAND_SZ` **展开后**按 `REG_SZ` 回报、`REG_MULTI_SZ` 空格连接按 `REG_SZ` 回报；
/// `REG_EXPAND_SZ` 展开失败或超过 64K UTF-16 单元时保留原文并如实回报 `REG_EXPAND_SZ`
/// （R5c-v8-L08：不得把未展开的原文标成 `REG_SZ`，否则写回会永久固化 `%VAR%`）。
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
/// MULTI_SZ 的 NUL 连接可逆（NUL 不可能出现在元素里，**空元素也逐项保留**，见
/// [`decode_reg_value_bytes`] 的 R5c-M02 注释；末尾空元素与终止符同形是固有边界），
/// 其余字节原样往返。
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
        // R5c-L05：奇数字节只对 UTF-16 字符串类型是畸形；REG_BINARY 奇数长度完全合法。
        // 告警放在真正做 `chunks_exact(2)` 的闭包里，不再对所有类型无差别告警。
        if b.len() % 2 != 0 {
            crate::engine::log::write_log("warn", &format!("注册表字符串值字节长度为奇数（{} 字节），末字节不参与 UTF-16 解码", b.len()));
        }
        b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
    };
    match ty {
        // 长度闸是**严格相等**：短的一侧判 decode_failed 是 P0-3 立的那道闸，
        // 长的一侧同样判失败 —— 放行长值会让还原按短字节写回，原值的高位永久消失，
        // 而回执说「已还原」（交叉形态按 Corrupt 口径，两侧必须同形）。
        REG_DWORD if buf.len() == 4 => {
            let raw = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            Some(("REG_DWORD", reg_dword_as_i32_text(raw)))
        }
        REG_QWORD if buf.len() == 8 => {
            let raw = u64::from_le_bytes(buf[..8].try_into().ok()?);
            Some(("REG_QWORD", (raw as i64).to_string()))
        }
        REG_BINARY => {
            Some(("REG_BINARY", buf.iter().map(|b| format!("{b:02x}")).collect()))
        }
        REG_SZ => {
            // R5c-v8-L10：保真链遇到奇数字节/多余尾 NUL 必须判 decode_failed。
            // 旧写法先 `chunks_exact(2)` 丢尾字节、再 `trim_end_matches('\0')` 归一，
            // 写回后自比对走同一个解码器 ⇒ 恒相等，用户拿到「已还原」但边界已变形。
            // 展示链（flatten=true）继续归一，不影响面板显示。
            if !flatten {
                if buf.len() % 2 != 0 {
                    crate::engine::log::write_log(
                        "warn",
                        &format!("保真读注册表 REG_SZ 遇到奇数字节（{} 字节），判 decode_failed", buf.len()),
                    );
                    return None;
                }
                let trailing_nul = buf
                    .chunks_exact(2)
                    .rev()
                    .take_while(|c| c[0] == 0 && c[1] == 0)
                    .count();
                if trailing_nul > 1 {
                    crate::engine::log::write_log(
                        "warn",
                        &format!("保真读注册表 REG_SZ 遇到 {trailing_nul} 个尾 NUL（只允许一个终止符），判 decode_failed"),
                    );
                    return None;
                }
            }
            let u = units(buf);
            let s = decode_utf16_strict(&u)?;
            // 保真分支已在上面把「多于一个尾 NUL」拒掉，这里至多削掉终止符；
            // 展示分支维持旧的归一语义。
            Some(("REG_SZ", s.trim_end_matches('\0').to_string()))
        }
        REG_EXPAND_SZ => {
            let u = units(buf);
            let raw = decode_utf16_strict(&u)?;
            let raw = raw.trim_end_matches('\0');
            if !flatten {
                return Some(("REG_EXPAND_SZ", raw.to_string()));
            }
            // 展开环境变量（对齐 .NET GetValue）。R5c-v8-L08：两段式 —— 先取所需长度，
            // 再按长度分配；固定 1024 缓冲会把超长展开结果截成「展开失败」，旧代码
            // 仍标成 REG_SZ，写回时 `%VAR%` 永久变成字面量。
            const EXPAND_SZ_MAX_UNITS: usize = 64 * 1024;
            let src = to_wide(raw);
            let need = unsafe { ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), None) };
            if need == 0 || need as usize > EXPAND_SZ_MAX_UNITS {
                crate::engine::log::write_log(
                    "warn",
                    &format!(
                        "REG_EXPAND_SZ 展开需要 {need} 个 UTF-16 单元，超过上限 {EXPAND_SZ_MAX_UNITS} 或调用失败，保留原文与 REG_EXPAND_SZ 类型"
                    ),
                );
                return Some(("REG_EXPAND_SZ", raw.to_string()));
            }
            let mut out = vec![0u16; need as usize];
            let got = unsafe { ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), Some(&mut out[..])) };
            if got == 0 || got > need {
                crate::engine::log::write_log(
                    "warn",
                    &format!("REG_EXPAND_SZ 二次展开失败（需要 {need}，实得 {got}），保留原文与 REG_EXPAND_SZ 类型"),
                );
                return Some(("REG_EXPAND_SZ", raw.to_string()));
            }
            let u16s = &out[..(got as usize - 1).max(0)];
            // 展开结果由系统拼出，理论上合法；万一非法也不造替换字符，退回原值与真实类型
            match decode_utf16_strict(u16s) {
                Some(s) => Some(("REG_SZ", s)),
                None => Some(("REG_EXPAND_SZ", raw.to_string())),
            }
        }
        REG_MULTI_SZ => {
            let u = units(buf);
            let text = decode_utf16_strict(&u)?;
            // R5c-M02：只剥掉**终止** NUL，**不过滤空元素**。`a\0\0b\0\0` 是 `["a","","b"]`；
            // 旧写法 `.filter(|s| !s.is_empty())` 把它解成 `["a","b"]`，写侧按元素重新编码
            // 就写回 `a\0b\0\0` —— 那是**另一个值**，而回读自比对走同一个解码器 ⇒ 恒相等，
            // 用户拿到「已还原」但内容已变形。元素内不可能含 NUL，所以「按 NUL 拆」在保留
            // 空元素时才真的可逆（末尾的空元素与终止符同形，那是本表示法的固有边界，
            // 彻底解法是 faithful 分支不走字符串往返）。
            let elements: Vec<&str> = text.trim_end_matches('\0').split('\0').collect();
            if flatten {
                // PS `[string]$v` 对字符串数组是空格连接：空元素照样占位（连写两个空格），
                // 否则「有元素被吞」在显示链上也看不出来
                Some(("REG_SZ", elements.join(" ")))
            } else {
                Some(("REG_MULTI_SZ", elements.join("\u{0}")))
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
        FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
        WIN32_FIND_STREAM_DATA,
    };

    let mut buf = WIN32_FIND_STREAM_DATA::default();
    // R5c-L08：`to_string_lossy()` 会把非 Unicode 文件名替换成 U+FFFD ⇒ 枚举到别的路径
    // 或直接 (0,0)。按 OS 字符串逐字转宽，探测的就是调用方给的那条路径。
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
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
        // 搜索句柄的收尾 API 是 `FindClose`，不是 `CloseHandle`：后者能释放对象，
        // 但不会拆掉内核侧这次枚举挂的 change-notification 上下文 ⇒ 与 Win32 契约不符。
        let _ = FindClose(handle);
    }
    (bytes, count)
}

/// 枚举指定键的全部值名（F-1：regKeys `value:"*"` 展开、管理摘要对账用）。
///
/// P1-6G：返回 `(names, incomplete)`。旧签名只给 `Vec`，于是**两种完全不同的事实**
/// 在调用方同形：「这个键确实没有值」与「键打不开 / 枚举中途报错 / 值名长过缓冲上限」。
/// 前者展开成 0 条删除是正确行为，后者展开成 0 条则是「静默空转 + 回执报成功」——
/// 正是 `value:"*"` 那条链最怕的形状。开键失败同样算 `incomplete`（它不是「无值」）。
///
/// R5c-M03：清单里**可能出现空名 `""`**（= 默认值）。它是合法值名，删除面同样接受，
/// 调用方不得把它当「没有值」跳过 —— 跳过就等于对一个「数据放默认值」的键漏删并记成功。
pub fn reg_enum_value_names_pub(hive: HKEY, subkey: &str) -> (Vec<String>, bool) {
    let (names, lossy, incomplete) = reg_enum_value_names_pub_with_lossy(hive, subkey);
    // 有损名不能精确回写/删除；对「需要完整清单」的调用方按不完整上报，避免静默丢名。
    (names, incomplete || lossy > 0)
}

/// A6-M01：值名枚举的删除面版本 —— 额外返回「有损解码名数量」。
/// 有损名只能展示，不能作为 `RegDeleteValueW` 的目标；调用方必须把它计入 skipped_lossy。
pub fn reg_enum_value_names_pub_with_lossy(hive: HKEY, subkey: &str) -> (Vec<String>, usize, bool) {
    let sk = match to_wide_checked(subkey) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), 0, true),
    };
    let mut hk = HKEY::default();
    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return (Vec::new(), 0, true);
        }
        let (tagged, incomplete) = reg_enum_values_scan_tagged(hk);
        let _ = RegCloseKey(hk);
        let mut names = Vec::new();
        let mut lossy = 0usize;
        for (name, bad) in tagged {
            if bad {
                lossy += 1;
                crate::engine::log::write_log(
                    "warn",
                    &format!("注册表值名含损坏 UTF-16（U+FFFD/未配对代理项），已从删除目标中跳过：{hive:?}\\{subkey}"),
                );
            } else {
                names.push(name);
            }
        }
        (names, lossy, incomplete)
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
    reg_restore_delete_checked(hive, subkey, value_name).is_ok()
}

/// 同 [`reg_restore_delete`]，但把失败码交给调用方渲染成人话（R6c-12）。
///
/// 删值失败的原因（拒绝访问 / 长度不符）此前在 pssteps 侧只能报一句「删注册表值失败」，
/// 用户拿不到可行动信息。语义与 bool 版本完全一致：键不存在仍是幂等成功。
pub fn reg_restore_delete_checked(hive: HKEY, subkey: &str, value_name: &str) -> Result<(), u32> {
    use windows::Win32::Foundation::WIN32_ERROR;
    const ERROR_FILE_NOT_FOUND: WIN32_ERROR = WIN32_ERROR(2);
    // 形态闸先于任何 Win32 调用（红线⑨：判定字节 ≠ 执行字节）；123 = ERROR_INVALID_NAME
    let (sk, nm) = match (to_wide_checked(subkey), to_wide_checked(value_name)) {
        (Ok(sk), Ok(nm)) => (sk, nm),
        _ => return Err(123),
    };
    let mut hk = HKEY::default();
    unsafe {
        let opened = RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk);
        if opened.is_err() {
            let code = opened.0;
            return if open_key_missing_is_idempotent(code) { Ok(()) } else { Err(code) };
        }
        let r = RegDeleteValueW(hk, PCWSTR(nm.as_ptr()));
        let _ = RegCloseKey(hk);
        if r.is_ok() || r == ERROR_FILE_NOT_FOUND { Ok(()) } else { Err(r.0) }
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
    if !value_size_ok(size) {
        let _ = RegCloseKey(hk); return None;
    }
    let mut buf = vec![0u8; size as usize];
    let r = RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size));
    let _ = RegCloseKey(hk);
    if r.is_err() {
        return None;
    }
    // R5c-L06：按第二次查询回报的实际长度截断。值在两次查询之间缩小时，
    // 多出来的补零会参与逐字节比对（同文件另三处同构读器都已截断）。
    buf.truncate(size as usize);
    Some((ty, buf))
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
        let r = RegEnumValueW(hk, index, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None);
        if r == ERROR_NO_MORE_ITEMS {
            break; // 正常结束
        }
        if r.is_err() {
            // R5c-L01：任何非正常结束（含超 260 的值名回 ERROR_MORE_DATA）都必须留痕，
            // 否则计数少算而调用方无痕。此处只作显示计数，不重试增长缓冲（scan 版本负责）。
            crate::engine::log::write_log(
                "warn",
                &format!("注册表值计数非正常结束（index={index}, err={}），本次计数不完整", r.0),
            );
            break;
        }
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

        // ③ 值名方向同样：含 NUL 的值名必须拒，且那个真值不得被删。
        // R5c-M01（本轮）：原断言极性反了 —— 旧写法 `assert!(reg_restore_delete(…))` 要求
        // 「被拒」返回 **true**，而 `reg_restore_delete` = `reg_restore_delete_checked(..).is_ok()`，
        // 形态闸一律 `Err(123)` ⇒ `is_ok()` 恒 false，这条断言只可能失败（发布前 `--ignored`
        // 批次必红）。更坏的是它诱导「为了让用例过」把形态非法的删值改成幂等成功 ——
        // 那正好推翻「判不出本来存不存在就不许记成功」。现在按真实语义断言：
        // false（没删）+ Err(123)（拒的原因可判）。
        assert!(
            !super::reg_restore_delete(HKEY_CURRENT_USER, REAL, &"v\0x".to_string()),
            "含 NUL 的值名必须被拒（拒 = false = 没删；旧断言在此处要求 true，极性反了）"
        );
        assert_eq!(
            super::reg_restore_delete_checked(HKEY_CURRENT_USER, REAL, &"v\0x".to_string()),
            Err(123),
            "含 NUL 的值名必须判 ERROR_INVALID_NAME(123)，不得折成幂等成功"
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

    /// R5c-M01 真机验收：递归删空键与非空键后，键本身都必须不存在。
    ///
    /// 判红自证：删掉递归分支里的 `RegDeleteKeyW` ⇒ 两次 `reg_key_exists`
    /// 都仍为 true，本用例红；只删子键的旧实现会在非空样本上复现同一失败。
    #[test]
    #[ignore = "真实写注册表（HKCU scratch 键 + Drop 清理），发布前门禁跑"]
    fn r5c_m01_递归删除后键必须消失() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ};
        // RegDeleteTreeW 在本机叶键上可能顺手让键消失，单看回读无法稳定区分
        // 「清树」和「删键本身」。契约要求递归分支显式再删键，故把这一行同时钉进真机用例。
        // 生产段边界用 `mod tests` 而不是首个 `#[cfg(test)]`：
        // 上方很早就有 `#[cfg(test)] thread_local!` 测试钩子，用后者截断会把
        // `reg_key_remove_checked` 一起切掉（真机组实测「找不到」）。
        let src = include_str!("registry.rs");
        let prod = &src[..src.find("mod tests").expect("找不到单测段起点")];
        let remove = prod
            .split("pub fn reg_key_remove_checked")
            .nth(1)
            .and_then(|s| s.split("pub fn reg_key_remove(").next())
            .expect("找不到 reg_key_remove_checked");
        let recurse = remove
            .split("if recurse {")
            .nth(1)
            .and_then(|s| s.split("// 非递归删除").next())
            .expect("找不到递归删除分支");
        assert!(
            recurse.contains("RegDeleteKeyW(hive"),
            "递归删除缺少 RegDeleteKeyW —— 只清树不能证明键本身被删"
        );
        const EMPTY: &str = r"Software\TrimRecursiveDeleteEmptyProbe";
        const NONEMPTY: &str = r"Software\TrimRecursiveDeleteTreeProbe";
        struct Probe;
        impl Drop for Probe {
            fn drop(&mut self) {
                let _ = reg_key_remove(HKEY_CURRENT_USER, EMPTY, true);
                let _ = reg_key_remove(HKEY_CURRENT_USER, NONEMPTY, true);
            }
        }
        let _probe = Probe;

        assert!(
            super::reg_key_ensure_checked(HKEY_CURRENT_USER, EMPTY).is_ok(),
            "空键应可创建"
        );
        assert_eq!(
            super::reg_key_remove_checked(HKEY_CURRENT_USER, EMPTY, true),
            Ok(()),
            "空键递归删除应收口成功"
        );
        assert!(
            !super::reg_key_exists(HKEY_CURRENT_USER, EMPTY),
            "递归删除后空键本身必须消失（旧实现只清子项，会留下空键）"
        );

        let child = format!(r"{NONEMPTY}\Child");
        assert!(
            super::reg_key_ensure_checked(HKEY_CURRENT_USER, NONEMPTY).is_ok(),
            "非空样本父键应可创建"
        );
        assert!(
            reg_restore_write(HKEY_CURRENT_USER, &child, "v", REG_SZ, b"x\0"),
            "非空样本文应该写入成功"
        );
        assert_eq!(
            super::reg_key_remove_checked(HKEY_CURRENT_USER, NONEMPTY, true),
            Ok(()),
            "非空键递归删除应收口成功"
        );
        assert!(
            !super::reg_key_exists(HKEY_CURRENT_USER, NONEMPTY),
            "递归删除后非空键本身必须消失"
        );
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
        let delete_key = remove_fn
            .find("RegDeleteKeyW(hive")
            .expect("递归分支缺少 RegDeleteKeyW —— 只清子项会留下键本身");
        let readback = remove_fn
            .find("reg_key_exists_state(hive, subkey)")
            .expect("递归删除缺少删后现读，Win32 Ok 不能证明键已消失");
        assert!(
            first_win32 < delete_key && delete_key < readback,
            "递归删除顺序必须是：清树 → 删键本身 → 回读键不存在"
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
        let restore_del = body_of(prod, "pub fn reg_restore_delete_checked");
        assert!(
            restore_del.contains("to_wide_checked(subkey)")
                && restore_del.contains("to_wide_checked(value_name)"),
            "删值面（reg_restore_delete_checked）必须对键路径与值名都吃 to_wide_checked"
        );
        let del_value = body_of(prod, "pub(super) unsafe fn reg_delete_value");
        assert!(
            del_value.contains("to_wide_checked(&subkey)")
                && del_value.contains("to_wide_checked(value_name)"),
            "删值面（reg_delete_value）必须对键路径与值名都吃 to_wide_checked"
        );

        // R5c-L09：只断言「出现过」不够——`to_wide_checked(x).unwrap_or_else(|_| to_wide(x))?`
        // 这种「过闸又吞闸」的写法同样能让上面四处全绿。闸调用所在的同一表达式行内
        // 不得出现 unwrap_or 系列或 `.ok()`（它们会把 Err 折成默认值/Option）。
        for (label, body) in [
            ("删树原语", &remove_fn),
            ("建面原语", &ensure_fn),
            ("写值面", &write_fn),
            ("删值面-restore", &restore_del),
            ("删值面-delete", &del_value),
        ] {
            for line in body.lines().filter(|l| l.contains("to_wide_checked(")) {
                assert!(
                    !line.contains("unwrap_or") && !line.contains(".ok()"),
                    "{label}：to_wide_checked 不得被 unwrap_or 系列/.ok() 吞掉（{line}）"
                );
            }
        }
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

    /// R5c-M02 回归钉：`REG_MULTI_SZ` 的 faithful 解码**必须保留空元素**。
    ///
    /// 旧实现 `text.trim_end_matches('\0').split('\0').filter(|s| !s.is_empty())` 在
    /// faithful（`flatten=false`）下同样过滤 ⇒ `a\0\0b\0\0`（= `["a","","b"]`）被解成
    /// `a\0b`（= `["a","b"]`）。写侧按元素重新编码就写回 `a\0b\0\0` —— **另一个值**；
    /// 而还原回读自比对（`verify_restore_ops`）走同一个解码器 ⇒ 两侧一起丢、恒相等，
    /// 用户拿到「已还原」但内容已变形。
    ///
    /// 判红自证：把 faithful 分支的 `.split('\0').collect()` 换回带
    /// `.filter(|s| !s.is_empty())` 的旧写法 ⇒ 本文第①②③④条红（第⑤条是空串回归钉，
    /// 两条写法同结论，故不参与判红）。
    #[test]
    fn r5c_m02_multi_sz空元素必须保真往返() {
        use windows::Win32::System::Registry::REG_MULTI_SZ;

        /// 元素列表 → MULTI_SZ 字节：元素间单 NUL，末尾双 NUL。
        /// 空元素就是「两个相邻分隔符」，正是旧过滤会吞掉的那一项。
        ///
        /// 为什么不用生产写侧 `optimizer::restore_write_bytes` 来做这一步：那条链今天仍带
        /// `.filter(|s| !s.is_empty())`（`backup_restore.rs`，本轮改动范围之外），用它编码
        /// 会把空元素再吞一次 —— 那条链要补齐才谈得上端到端可逆，本文件只钉解码端的可逆性。
        fn encode(elements: &[&str]) -> Vec<u8> {
            let mut units: Vec<u16> = Vec::new();
            for (i, e) in elements.iter().enumerate() {
                if i > 0 {
                    units.push(0);
                }
                units.extend(e.encode_utf16());
            }
            units.push(0);
            units.push(0);
            units.iter().flat_map(|u| u.to_le_bytes()).collect()
        }

        // ① 中间空元素：`a\0\0b\0\0` = ["a","","b"]，解码必须逐元素保留
        let raw = encode(&["a", "", "b"]);
        // 逐元素字节：a\0 + \0(空元素) + b\0 + 终止 \0（元素间单 NUL、末尾双 NUL）
        assert_eq!(
            raw,
            vec![0x61, 0, 0, 0, 0, 0, 0x62, 0, 0, 0, 0, 0],
            "夹具字节形态自检（空元素必须占位）"
        );
        let (ty, data) =
            decode_reg_value_bytes(REG_MULTI_SZ, &raw, false).expect("faithful 解码不得失败");
        assert_eq!(ty, "REG_MULTI_SZ", "faithful 口径不得把类型降级成 REG_SZ");
        assert_eq!(
            data.split('\0').collect::<Vec<_>>(),
            vec!["a", "", "b"],
            "空元素被吞掉 ⇒ 还原会写回另一个值（实得 {data:?}）"
        );

        // ② 开头空元素：`\0b\0\0`
        let lead = encode(&["", "b"]);
        let (_, lead_data) = decode_reg_value_bytes(REG_MULTI_SZ, &lead, false).unwrap();
        assert_eq!(
            lead_data.split('\0').collect::<Vec<_>>(),
            vec!["", "b"],
            "开头空元素同样不得被丢（实得 {lead_data:?}）"
        );

        // ③ 往返：解码 → 按元素编码 → 与原始字节逐字节一致
        assert_eq!(encode(&data.split('\0').collect::<Vec<_>>()), raw, "含空元素的 MULTI_SZ 往返必须字节一致");
        assert_eq!(encode(&lead_data.split('\0').collect::<Vec<_>>()), lead);

        // ④ 展平口径：空元素照样占位（PS `[string]$v` 按空格连接），显示链也不得「少一条」
        assert_eq!(
            decode_reg_value_bytes(REG_MULTI_SZ, &raw, true),
            Some(("REG_SZ", "a  b".to_string())),
            "展平口径下空元素必须占位（两个空格），不得静默合并成一个"
        );

        // ⑤ 空 MULTI_SZ（只有终止 NUL）仍是空串，不是「一个空元素」
        assert_eq!(
            decode_reg_value_bytes(REG_MULTI_SZ, &[0, 0], false),
            Some(("REG_MULTI_SZ", String::new())),
            "空 MULTI_SZ 必须解成空串"
        );
    }

    /// R5c-M03 回归钉（纯逻辑侧）：**值名枚举层不得过滤空名**。
    ///
    /// 空名就是「默认值」，它是合法值名（删除面 `to_wide_checked("")` 放行）；枚举层过滤
    /// 它会把「有值」报成「没有值」，`value:"*"` 于是漏删默认值、展开为空还记成功。
    /// 只含默认值的键只能靠真写注册表造出来（见下面那条 `#[ignore]` 真机用例），所以这里
    /// 用源码形态守住「过滤只许出现在只读展示包装」。
    ///
    /// 判红自证：把 `reg_enum_values_scan` 的 `names.push(name)` 换回
    /// `if !name.is_empty() { names.push(name); }` ⇒ 第①条红。
    #[test]
    fn r5c_m03_值名枚举层不得丢弃默认值() {
        let src = include_str!("registry.rs");
        let prod = &src[..src.find("mod tests").expect("找不到单测段起点")];

        /// 取某个函数从声明行到首个顶格 `}` 的片段（本文件函数体花括号一律缩进，
        /// 首个顶格 `}` 就是函数结束行）。
        fn body_of<'a>(prod: &'a str, marker: &str) -> &'a str {
            let start = prod.find(marker).unwrap_or_else(|| panic!("找不到 {marker}"));
            let rest = &prod[start..];
            let end = rest.find("\n}\n").unwrap_or_else(|| panic!("{marker} 之后找不到顶格 }}"));
            &rest[..end]
        }

        // ① 枚举原语：无条件收进值名，不按空名筛。
        // 只判**代码行**：本函数体的注释里为了说明旧实现会写出 `is_empty` 这个词，
        // 「注释里提到的写法」不是「代码里做的事」（同 `check-registry-delete-guard` 的
        // 正向对照口径），把它算进来会让否定断言假红。
        let scan = body_of(prod, "pub(super) unsafe fn reg_enum_values_scan_tagged");
        let scan_code: String = scan
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            scan_code.contains("names.push((name, lossy))"),
            "值名枚举层必须把每个值名都收进清单"
        );
        assert!(
            !scan_code.contains("is_empty"),
            "值名枚举层不得按空名过滤 —— 空名 = 默认值，是合法值名（R5c-M03）"
        );

        // ② 只读展示包装：空名的去留必须显式写在这里（这里是唯一允许过滤的地方）
        let disp = body_of(prod, "pub(super) unsafe fn reg_enum_values(");
        assert!(
            disp.contains("is_empty"),
            "空名过滤只许留在只读展示包装 reg_enum_values（枚举层一个都不丢）"
        );
    }

    /// R5c-M03 回归钉（日常可跑）：键打不开 ⇒ `incomplete=true`，不是「这个键没有值」。
    #[test]
    fn r5c_m03_值名枚举失败必须报不完整() {
        let (names, incomplete) = reg_enum_value_names_pub(hive_hklm(), r"Software\Trim不存在的键_值名枚举探针");
        assert!(names.is_empty(), "不存在的键不应枚举出值名");
        assert!(incomplete, "开键失败必须算 incomplete（不是「这个键没有值」）");
    }

    /// R5c-M03 真机 `#[ignore]` 探针（发布前门禁跑）：**只含默认值的键**必须枚举出空名，
    /// 且清单不得谎报不完整；空名还必须能被删除面接受。
    ///
    /// 旧实现 `if !name.is_empty()` 把默认值静默丢掉、`incomplete` 仍是 false ⇒ 对这样的键
    /// 执行 `value:"*"` 会漏删默认值，展开为空还被当成「空键 = 目标状态已达成」记成功。
    /// 只读探针实测参照：`HKLM\SOFTWARE\Classes\.txt` 的 `GetValueNames()` 含空名。
    ///
    /// 判红自证：把 `reg_enum_values_scan` 的 `names.push(name)` 换回带空名过滤的旧写法
    /// ⇒ 第②条红（清单为空）。卫生口径照本文件既有真机探针：只碰 HKCU scratch 键，
    /// `Drop` 里删干净（含断言提前 panic 的路径）。
    #[test]
    #[ignore = "真实写注册表（HKCU scratch 键 + Drop 清理），发布前门禁跑"]
    fn r5c_m03_真机_默认值必须枚举到且清单完整() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ};
        const SUB: &str = r"Software\TrimEnumDefaultProbe";
        struct Probe;
        impl Drop for Probe {
            fn drop(&mut self) {
                let _ = reg_key_remove(HKEY_CURRENT_USER, SUB, true);
            }
        }
        let _probe = Probe;

        // ① 只写默认值（空名），键里没有别的值
        let payload: Vec<u8> = to_wide("默认值探针").into_iter().flat_map(|u| u.to_le_bytes()).collect();
        assert!(
            reg_restore_write(HKEY_CURRENT_USER, SUB, "", REG_SZ, &payload),
            "空值名（= 默认值）应可写入"
        );

        // ② 枚举必须报出空名，且不得谎报「清单不完整」
        let (names, incomplete) = reg_enum_value_names_pub(HKEY_CURRENT_USER, SUB);
        assert!(!incomplete, "正常结束不得报「清单不完整」");
        assert_eq!(
            names,
            vec![String::new()],
            "只含默认值的键必须枚举出空名，实得 {names:?}"
        );

        // ③ 空名必须能被删除面接受（漏删默认值那条链的末端）
        assert!(
            super::reg_restore_delete(HKEY_CURRENT_USER, SUB, ""),
            "空值名（默认值）必须可删"
        );
        let (after, after_incomplete) = reg_enum_value_names_pub(HKEY_CURRENT_USER, SUB);
        assert!(!after_incomplete, "删除后枚举仍须完整");
        assert!(after.is_empty(), "默认值删掉后清单应为空，实得 {after:?}");
    }

    // ==================== P2 B-15 · 注册表原语边界 ====================

    /// R5c-v8-L02：首段为空/任何空段都必须是 `Err(87)`，不得让 `rsplit_once`
    /// 把父键落到 hive 本身（`\Foo` 的父键是 `""`）。
    #[test]
    fn r5c_leading_backslash_is_rejected() {
        use windows::Win32::System::Registry::HKEY_CURRENT_USER;
        for bad in [r"\Foo", r"Foo\", r"Foo\\Bar", r"\\Foo"] {
            assert!(
                super::reg_delete_subkey_shape_is_malformed(bad),
                "{bad:?} 必须判畸形（任何空段都拒）"
            );
            assert_eq!(
                super::reg_key_remove_checked(HKEY_CURRENT_USER, bad, false),
                Err(87),
                "{bad:?} 必须在任何 Win32 调用之前判 87"
            );
        }
        assert!(!super::reg_delete_subkey_shape_is_malformed(r"Software\Foo"));
    }

    /// R5c-v8-L03：开键之后的任何早退都必须关句柄；末段转换必须提前到开键之前。
    ///
    /// 测试钩子模拟「开键后才发现末段非法」的路径（真实路径已被入口形态闸拦下，
    /// 无法在无权限样本机器上自然触发）——RAII 守卫必须在早退时关句柄。
    #[test]
    fn r5c_invalid_last_does_not_leak() {
        use windows::Win32::System::Registry::HKEY_CURRENT_USER;
        let opens = || super::OPEN_OPENS.with(|c| c.get());
        let closes = || super::OPEN_CLOSES.with(|c| c.get());
        let before = (opens(), closes());
        super::FORCE_EARLY_RETURN_AFTER_OPEN.with(|c| c.set(true));
        let r = super::reg_key_remove_checked(HKEY_CURRENT_USER, r"Software\TrimLeakProbeNeverExists", false);
        super::FORCE_EARLY_RETURN_AFTER_OPEN.with(|c| c.set(false));
        let after = (opens(), closes());
        assert_eq!(r, Err(87), "钩子必须让开键后的早退路径返回 87");
        assert_eq!(after.0 - before.0, 1, "前置：早退前必须真的开过一次父键");
        assert_eq!(after.0, after.1, "开键后的早退必须关句柄（开 {} / 关 {}）", after.0, after.1);
    }

    /// R5c-v8-L04：`5/拒绝访问` 必须是 Unknown，不能折成「不存在」。
    #[test]
    fn r5c_key_exists_unknown_on_access_denied() {
        use windows::Win32::System::Registry::HKEY_CURRENT_USER;
        super::FORCED_EXISTS_CODE.with(|c| c.set(Some(5)));
        let state = super::reg_key_exists_state(HKEY_CURRENT_USER, r"Software");
        let bool_view = super::reg_key_exists(HKEY_CURRENT_USER, r"Software");
        super::FORCED_EXISTS_CODE.with(|c| c.set(None));
        assert_eq!(state, super::KeyState::Unknown(5), "权限拒绝必须保留为 Unknown(5)，实得 {state:?}");
        assert!(!bool_view, "bool 外观不得把 Unknown 当存在");
        assert_eq!(super::key_state_from_open_code(2), super::KeyState::Missing);
        assert_eq!(super::key_state_from_open_code(3), super::KeyState::Missing);
        assert_eq!(super::key_state_from_open_code(0), super::KeyState::Exists);
    }

    /// R5c-v8-L05：`Class` 值读失败必须置 incomplete，不再 `unwrap_or(false)` 静默排除。
    #[test]
    fn r5c_class_read_failure_sets_incomplete() {
        assert_eq!(super::class_read_matches("Display", None), (false, true), "读失败必须报不完整");
        assert_eq!(super::class_read_matches("Display", Some("display".to_string())), (true, false));
        assert_eq!(super::class_read_matches("Display", Some("USB".to_string())), (false, false));
    }

    /// R5c-v8-L06：删不存在的键与删值同口径 —— 2/3 视为幂等成功。
    #[test]
    fn r5c_delete_key_missing_is_idempotent() {
        use windows::Win32::System::Registry::HKEY_CURRENT_USER;
        let missing = format!(r"Software\TrimMissingKeyProbe_{}", std::process::id());
        assert_eq!(
            super::reg_key_remove_checked(HKEY_CURRENT_USER, &missing, false),
            Ok(()),
            "非递归删不存在的键必须幂等成功"
        );
        assert_eq!(
            super::reg_key_remove_checked(HKEY_CURRENT_USER, &missing, true),
            Ok(()),
            "递归删不存在的键必须幂等成功"
        );
    }

    /// R5c-v8-L08：超长 EXPAND_SZ 保留原文与真实类型，不得标成 REG_SZ。
    #[test]
    fn r5c_expand_sz_keeps_type_when_too_long() {
        use windows::Win32::System::Registry::REG_EXPAND_SZ;
        let raw = "x".repeat(70_000);
        let bytes: Vec<u8> = raw.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let (ty, data) = super::decode_reg_value_bytes(REG_EXPAND_SZ, &bytes, true)
            .expect("超长 EXPAND_SZ 必须退化为原文而非 decode_failed");
        assert_eq!(ty, "REG_EXPAND_SZ", "超长展开必须保留 REG_EXPAND_SZ 类型（旧实现标成 REG_SZ）");
        assert_eq!(data, raw, "原文必须逐字保留");
    }

    /// R5c-v8-L09：所有按回报长度分配的读值入口共用 1 MiB 上限。
    #[test]
    fn r5c_all_readers_have_value_cap() {
        assert!(super::value_size_ok(super::MAX_REG_VALUE_BYTES), "恰好 1 MiB 必须放行");
        assert!(!super::value_size_ok(super::MAX_REG_VALUE_BYTES + 1), "超过 1 MiB 必须拒绝");
        let src = include_str!("registry.rs");
        let prod = &src[..src.find("mod tests").expect("找不到单测段起点")];
        fn body_of<'a>(prod: &'a str, marker: &str) -> &'a str {
            let start = prod.find(marker).unwrap_or_else(|| panic!("找不到 {marker}"));
            let rest = &prod[start..];
            let end = rest.find("\n}\n").unwrap_or_else(|| panic!("{marker} 之后找不到顶格 }}"));
            &rest[..end]
        }
        for marker in [
            "unsafe fn reg_query_value",
            "unsafe fn reg_read_string",
            "pub fn read_reg_string",
            "pub fn read_reg_binary_opt",
            "pub fn read_reg_value_state",
            "pub unsafe fn reg_read_value_typed",
        ] {
            assert!(
                body_of(prod, marker).contains("value_size_ok("),
                "{marker} 缺少 1 MiB 长度闸（删任一处 ⇒ 本用例红）"
            );
        }
    }

    /// R5c-v8-L10：保真链遇到奇数字节/多余尾 NUL 必须判失败；展示链可继续归一。
    #[test]
    fn r5c_faithful_reg_sz_preserves_odd_tail() {
        use windows::Win32::System::Registry::REG_SZ;
        assert!(
            super::decode_reg_value_bytes(REG_SZ, &[0x41, 0, 0], false).is_none(),
            "3 字节 REG_SZ 在保真链必须判 decode_failed"
        );
        assert!(
            super::decode_reg_value_bytes(REG_SZ, b"A\0\0\0\0\0", false).is_none(),
            "多于一个尾 NUL 在保真链必须判 decode_failed"
        );
        assert_eq!(
            super::decode_reg_value_bytes(REG_SZ, b"A\0", false).map(|(t, d)| (t, d)),
            Some(("REG_SZ", "A".to_string())),
            "正常单终止符必须照旧保真解码"
        );
        assert_eq!(
            super::decode_reg_value_bytes(REG_SZ, &[0x41, 0, 0], true).map(|(t, d)| (t, d)),
            Some(("REG_SZ", "A".to_string())),
            "展示链继续归一（3 字节也能显示）"
        );
    }

    /// B03（方案 R5c-v8-L01）：三套 DWORD 数值口径必须在名字与行为上都可区分。
    ///
    /// `0xFFFFFFFF` 是分水岭：u32 口径下它是 4294967295，i32 口径下是 -1。
    /// 三套口径混用时，调用方会拿 -1 去和「阈值」比较（SVCHost 拆分阈值就是这一类），
    /// 于是「等于阈值」变成「小于阈值」，判断整个反过来。
    #[test]
    fn b03_dword_three_numeric_conventions_are_distinguishable() {
        // ① u32 → i64（无符号提升）：0xFFFFFFFF = 4294967295
        assert_eq!(
            0xFFFF_FFFF_u32 as i64,
            4_294_967_295_i64,
            "u32 提升为 i64 的口径必须是无符号值"
        );
        // ② 纯 u32
        assert_eq!(0xFFFF_FFFF_u32, 4_294_967_295_u32, "纯 u32 口径必须是 4294967295");
        // ③ i32（.NET / PS 口径）
        assert_eq!(
            super::reg_dword_as_i32_text(0xFFFF_FFFF),
            "-1",
            "i32 口径必须是有符号 -1"
        );
        assert_eq!(super::reg_dword_as_i32_text(0), "0", "i32 口径的 0 不受影响");
        assert_eq!(
            super::reg_dword_as_i32_text(2_147_483_647),
            "2147483647",
            "i32 口径的正数上界"
        );
    }
}
