//! B10/B3 只读诊断域：系统盘介质探测（sysdisk）、设备信息（device_info）。
//!
//! 本域刻意保持只读，且**返回形状即前端消费口径**：字段名与嵌套结构改动会直接打到
//! 设备信息页，动之前对照 src/scripts/deviceinfo.js。
//! 原第三员 overview_checkup（系统体检）已于 2026-10-12 随首页「体检结论」区块全链路退役。


use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW};
use super::common::*;
// ==================== B10 sysdisk：系统盘介质探测 ====================

/// 系统盘介质类型探测（原 PS 时代脚本 sysdisk.ps1，已退役；S3）
///
/// 通过注册表 SCSI 设备信息 + 型号关键字判断 SSD/HDD。
/// 返回 {letter, media, busType, model, isSsd, known, detector}。
pub fn sysdisk() -> Result<Value, String> {
    let letter = std::env::var("SystemDrive")
        .unwrap_or_else(|_| "C:".into())
        .trim_end_matches(':')
        .to_string();

    let mut model = String::new();
    let mut media = String::new();
    let mut bus = String::new();
    let mut detector = String::new();

    // 从注册表 SCSI 设备映射获取磁盘型号
    unsafe {
        let base = r"SYSTEM\CurrentControlSet\Services\Disk\Enum";
        let sk = to_wide(base);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
            // 读 0 号磁盘的设备实例 ID
            let mut buf = [0u16; 256];
            let mut size = (buf.len() * 2) as u32;
            let nm = to_wide("0");
            if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, None, Some(buf.as_mut_ptr() as *mut u8), Some(&mut size)).is_ok() {
                let instance = String::from_utf16_lossy(&buf[..(size/2) as usize]).trim_matches('\0').to_string();
                // 从设备实例 ID 解析型号
                if let Some(m) = extract_model_from_instance(&instance) {
                    model = m;
                }
            }
            let _ = RegCloseKey(hk);
        }

        // 兜底：从 SCSI 设备映射直接读 Identifier
        if model.is_empty() {
            for port in 0..4 {
                for bus_idx in 0..2 {
                    for target in 0..4 {
                        let key = format!(r"HARDWARE\DEVICEMAP\Scsi\Scsi Port {port}\Scsi Bus {bus_idx}\Target Id {target}\Logical Unit Id 0");
                        let sk = to_wide(&key);
                        let mut hk2 = HKEY::default();
                        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk2).is_ok() {
                            let mut ibuf = [0u16; 256];
                            let mut isize = (ibuf.len() * 2) as u32;
                            let inm = to_wide("Identifier");
                            if RegQueryValueExW(hk2, PCWSTR(inm.as_ptr()), None, None, Some(ibuf.as_mut_ptr() as *mut u8), Some(&mut isize)).is_ok() {
                                let id = String::from_utf16_lossy(&ibuf[..(isize/2) as usize]).trim_matches('\0').trim().to_string();
                                if !id.is_empty() {
                                    model = id;
                                    break;
                                }
                            }
                            let _ = RegCloseKey(hk2);
                        }
                    }
                    if !model.is_empty() { break; }
                }
                if !model.is_empty() { break; }
            }
        }
    }

    // 型号关键字判断 SSD/HDD
    let model_lower = model.to_lowercase();
    if model_lower.contains("ssd") || model_lower.contains("nvme") || model.contains("固态") {
        media = "SSD".into();
        detector = "Model 关键字".into();
    } else if !model.is_empty() {
        media = "HDD".into();
        detector = "Model 未见 SSD 关键字（推断）".into();
    }

    // NVMe 总线判断
    if model_lower.contains("nvme") {
        bus = "NVMe".into();
        if media.is_empty() {
            media = "SSD".into();
            detector = "BusType=NVMe".into();
        }
    }

    let is_ssd = media == "SSD";
    let known = media == "SSD" || media == "HDD";

    Ok(json!({
        "letter": letter,
        "media": media,
        "busType": bus,
        "model": model,
        "isSsd": is_ssd,
        "known": known,
        "detector": detector,
    }))
}

fn extract_model_from_instance(instance: &str) -> Option<String> {
    // 设备实例 ID 格式：SCSI\Disk&Ven_XXX&Prod_YYY\...
    let parts: Vec<&str> = instance.split('\\').collect();
    if parts.len() >= 2 {
        let ven_prod = parts[1];
        if let Some(prod_start) = ven_prod.find("&Prod_") {
            let prod = &ven_prod[prod_start + 6..];
            return Some(prod.replace('_', " "));
        }
    }
    None
}

// ==================== B3 device_info：设备信息采集 ====================

/// 设备信息采集（原 PS 时代脚本 device_info.ps1，已退役；S3）
///
/// 从注册表和系统 API 读取：系统版本、CPU、GPU、主板、磁盘、显示器、内存。
/// WMI 专有字段（如显存精确值、显示器 EDID）尽量从注册表读取，缺失字段留空。
pub fn device_info() -> Result<Value, String> {
    {
        use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
        use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

        // 辅助：从注册表读字符串值
        fn reg_read_string(hive: windows::Win32::System::Registry::HKEY, path: &str, name: &str) -> Option<String> {
            unsafe {
                use windows::Win32::System::Registry::{RegOpenKeyExW, RegQueryValueExW, RegCloseKey, KEY_READ, REG_VALUE_TYPE};
                let sk = to_wide(path);
                let mut hk = windows::Win32::System::Registry::HKEY::default();
                if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { return None; }
                let nm = to_wide(name);
                let mut ty = REG_VALUE_TYPE::default();
                let mut size = 0u32;
                if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
                    let _ = RegCloseKey(hk); return None;
                }
                let mut buf = vec![0u8; size as usize];
                let ok = RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size)).is_ok();
                let _ = RegCloseKey(hk);
                if !ok || size == 0 { return None; }
                // REG_SZ / REG_EXPAND_SZ: UTF-16
                if ty.0 == 1 || ty.0 == 2 {
                    let words: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&w| w != 0).collect();
                    Some(String::from_utf16_lossy(&words).trim().to_string())
                } else {
                    None
                }
            }
        }

        // 辅助：从注册表读 DWORD
        fn reg_read_dword(hive: windows::Win32::System::Registry::HKEY, path: &str, name: &str) -> Option<u32> {
            unsafe {
                use windows::Win32::System::Registry::{RegOpenKeyExW, RegQueryValueExW, RegCloseKey, KEY_READ, REG_VALUE_TYPE};
                let sk = to_wide(path);
                let mut hk = windows::Win32::System::Registry::HKEY::default();
                if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { return None; }
                let nm = to_wide(name);
                let mut ty = REG_VALUE_TYPE::default();
                let mut val = 0u32;
                let mut size = std::mem::size_of::<u32>() as u32;
                let ok = RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(&mut val as *mut u32 as *mut u8), Some(&mut size)).is_ok();
                let _ = RegCloseKey(hk);
                if ok && ty.0 == 4 { Some(val) } else { None }
            }
        }

        // 1. 系统信息
        let system = {
            let caption = reg_read_string(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName").unwrap_or_default();
            let version = reg_read_string(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion").unwrap_or_default();
            let build = reg_read_string(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild").unwrap_or_default();
            let arch = if cfg!(target_arch = "x86_64") { "64 位" } else { "32 位" };
            json!({ "caption": caption, "architecture": arch, "version": version, "build": build })
        };

        // 2. CPU
        let processor = {
            let name = reg_read_string(HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString").unwrap_or_default();
            let mut si = SYSTEM_INFO::default();
            unsafe { GetSystemInfo(&mut si); }
            json!({ "name": name.trim(), "cores": si.dwNumberOfProcessors, "threads": si.dwNumberOfProcessors, "process": "" })
        };

        // 3. GPU（从显示类注册表读取）
        let mut graphics: Vec<Value> = Vec::new();
        for i in 0..10 {
            let path = format!(r"SYSTEM\CurrentControlSet\Control\Class\{{4d36e968-e325-11ce-bfc1-08002be10318}}\{:04}", i);
            let name = reg_read_string(HKEY_LOCAL_MACHINE, &path, "DriverDesc");
            if let Some(n) = name {
                if n.is_empty() || n.contains("Basic Display") || n.contains("Remote Display") { continue; }
                let driver = reg_read_string(HKEY_LOCAL_MACHINE, &path, "DriverVersion").unwrap_or_default();
                // 显存：HardwareInformation.qwMemorySize（QWORD）
                let vram = reg_read_dword(HKEY_LOCAL_MACHINE, &path, "HardwareInformation.qwMemorySize").unwrap_or(0) as u64;
                let vram_gb = if vram > 0 { format!("{:.1} GB", vram as f64 / (1024.0 * 1024.0 * 1024.0)) } else { String::new() };
                graphics.push(json!({ "name": n, "memory": vram_gb, "driver": driver }));
            }
        }

        // 4. 主板（SMBIOS 优先，注册表兜底）
        //    为什么不能只读注册表：26H2 实机实测 `HKLM\HARDWARE\DESCRIPTION\System\BIOS`
        //    键**存在但零值**（GetValueNames 为空），旧实现只读 BaseBoardProduct/
        //    BaseBoardManufacturer 于是恒空、界面显示「--」。SMBIOS（固件原始表）是
        //    权威来源：GetSystemFirmwareTable('RSMB') 拿 Type 2 基板结构。
        let motherboard = {
            let (product, manufacturer) = smbios_baseboard()
                .or_else(|| {
                    let p = reg_read_string(HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardProduct").unwrap_or_default();
                    let m = reg_read_string(HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardManufacturer").unwrap_or_default();
                    if p.is_empty() && m.is_empty() { None } else { Some((p, m)) }
                })
                .unwrap_or_default();
            json!({ "product": product, "manufacturer": manufacturer, "chipset": "" })
        };

        // 5. 磁盘（从 SCSI 注册表读取）
        let mut disks: Vec<Value> = Vec::new();
        for port in 0..8 {
            for bus in 0..4 {
                for target in 0..8 {
                    let path = format!(r"HARDWARE\DEVICEMAP\Scsi\Scsi Port {port}\Scsi Bus {bus}\Target Id {target}\Logical Unit Id 0");
                    let model = reg_read_string(HKEY_LOCAL_MACHINE, &path, "Identifier");
                    if let Some(m) = model {
                        if m.is_empty() { continue; }
                        let media = if m.contains("SSD") || m.contains("NVMe") || m.contains("固态") { "SSD" } else { "硬盘" };
                        disks.push(json!({ "name": m.trim(), "capacity": "", "media": media }));
                    }
                }
            }
        }

        // 6. 内存（GetPhysicallyInstalledSystemMemory）
        let mut memory: Vec<Value> = Vec::new();
        {
            use windows::Win32::System::SystemInformation::GetPhysicallyInstalledSystemMemory;
            let mut kb = 0u64;
            unsafe {
                if GetPhysicallyInstalledSystemMemory(&mut kb).is_ok() {
                    let gb = kb / (1024 * 1024);
                    memory.push(json!({ "manufacturer": "", "part": "", "capacity": format!("{gb} GB"), "speed": 0, "locator": "" }));
                }
            }
        }

        // 7. 显示器（2026-10-11 落地，原为显式留空 TODO）
        //    EnumDisplayDevices 枚举"接在桌面上"的适配器与监视器（活动态才算），
        //    分辨率/刷新率走 EnumDisplaySettings 当前模式，名称/物理尺寸解析监视器
        //    EDID（Enum 键的 Device Parameters\EDID 二进制值）。
        let monitors = monitors_info();

        Ok(json!({
            "system": system,
            "processor": processor,
            "graphics": graphics,
            "motherboard": motherboard,
            "disks": disks,
            "monitors": monitors,
            "memory": memory,
        }))
    }
}

// ==================== 硬件补全原语（2026-10-11：主板 SMBIOS / 显示器 EDID） ====================

/// 读注册表 REG_BINARY 值（EDID 用）。读不到返回 None。
fn reg_read_binary(
    hive: windows::Win32::System::Registry::HKEY,
    path: &str,
    name: &str,
) -> Option<Vec<u8>> {
    use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, RegQueryValueExW, KEY_READ, REG_VALUE_TYPE};
    unsafe {
        let sk = to_wide(path);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return None;
        }
        let nm = to_wide(name);
        let mut ty = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err()
            || size == 0
            || size > 64 * 1024
        {
            let _ = RegCloseKey(hk);
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let ok = RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size)).is_ok();
        let _ = RegCloseKey(hk);
        if ok && ty.0 == 3 {
            buf.truncate(size as usize);
            Some(buf)
        } else {
            None
        }
    }
}

/// 从 SMBIOS 原始表（`GetSystemFirmwareTable('RSMB')`）解析 Type 2「基板信息」的
/// 产品名与厂商。找不到/解析失败返回 None（调用方回退注册表）。
///
/// RSMB 返回缓冲布局：8 字节头（Used20CallingMethod/Major/Minor/DmiRevision + DWORD Length），
/// SMBIOS 结构表从偏移 8 起。结构头 = `{type u8, len u8, handle u16}`（**handle 这 2 字节
/// 最容易被漏**，本机 dump 实测：漏掉它会把 mfg/product 读成 handle 与 version），
/// 格式化区从 `pos+4` 起，字符串区从 `pos+len` 起直到双 NUL；Type 2 的制造商/产品是
/// 字符串索引、分别位于 `pos+4` / `pos+5`，1 起数。
fn smbios_baseboard() -> Option<(String, String)> {
    use windows::Win32::System::SystemInformation::{GetSystemFirmwareTable, FIRMWARE_TABLE_PROVIDER};
    const RSMB: u32 = 0x5253_4D42; // 'RSMB'
    unsafe {
        let size = GetSystemFirmwareTable(FIRMWARE_TABLE_PROVIDER(RSMB), 0, None);
        // 上界防呆：SMBIOS 表本身是 KB 量级；异常值（0 / 超大）直接放弃
        if size == 0 || size > 4 * 1024 * 1024 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let written = GetSystemFirmwareTable(FIRMWARE_TABLE_PROVIDER(RSMB), 0, Some(&mut buf[..]));
        if written == 0 || (written as usize) > buf.len() || buf.len() <= 8 {
            return None;
        }
        let table = &buf[8..written as usize];
        let mut pos = 0usize;
        while pos + 4 <= table.len() {
            let ty = table[pos];
            let len = table[pos + 1] as usize;
            if len < 4 || pos + len > table.len() {
                break;
            }
            // 字符串区：格式化区之后，双 NUL 结束（SMBIOS 规范）
            let mut str_end = pos + len;
            while str_end + 1 < table.len()
                && !(table[str_end] == 0 && table[str_end + 1] == 0)
            {
                str_end += 1;
            }
            if ty == 2 {
                let strings: Vec<&[u8]> = table[pos + len..str_end].split(|&b| b == 0).collect();
                let get = |idx: u8| -> String {
                    if idx == 0 {
                        return String::new();
                    }
                    strings
                        .get(idx as usize - 1)
                        .map(|s| String::from_utf8_lossy(s).trim().to_string())
                        .unwrap_or_default()
                };
                let manufacturer = get(table[pos + 4]);
                let product = get(table[pos + 5]);
                if manufacturer.is_empty() && product.is_empty() {
                    return None;
                }
                return Some((product, manufacturer));
            }
            if ty == 127 {
                break; // End-of-table
            }
            pos = str_end + 2;
        }
        None
    }
}

/// `DISPLAY_DEVICEW` 的定长 u16 数组 → String（截到首个 NUL，去空白）。
fn wide_field(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end]).trim().to_string()
}

/// 枚举「接在桌面上且活动」的显示器：适配器 → 监视器两级 `EnumDisplayDevices`，
/// 分辨率/刷新率取适配器当前模式（`EnumDisplaySettings`），名称/物理尺寸从监视器
/// EDID 解析。输出形状对齐 `deviceinfo.js::normalize` 的消费口径：
/// `[{name, width, height, refresh, size}]`（refresh=0 / size 空串时前端自行省略）。
fn monitors_info() -> Vec<Value> {
    use windows::Win32::Graphics::Gdi::{
        EnumDisplayDevicesW, EnumDisplaySettingsW, DISPLAY_DEVICEW, DISPLAY_DEVICE_ATTACHED_TO_DESKTOP,
        DEVMODEW, ENUM_CURRENT_SETTINGS,
    };
    let mut out: Vec<Value> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut adapter_idx = 0u32;
    loop {
        let mut dd = DISPLAY_DEVICEW {
            cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32,
            ..Default::default()
        };
        if !unsafe { EnumDisplayDevicesW(PCWSTR::null(), adapter_idx, &mut dd, 0) }.as_bool() {
            break;
        }
        adapter_idx += 1;
        if dd.StateFlags.0 & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP.0 == 0 {
            continue;
        }
        // 该适配器当前模式：分辨率 + 刷新率
        let (mut width, mut height, mut refresh) = (0u32, 0u32, 0u32);
        let mut dm = DEVMODEW {
            dmSize: std::mem::size_of::<DEVMODEW>() as u16,
            ..Default::default()
        };
        if unsafe { EnumDisplaySettingsW(PCWSTR(dd.DeviceName.as_ptr()), ENUM_CURRENT_SETTINGS, &mut dm) }.as_bool() {
            width = dm.dmPelsWidth;
            height = dm.dmPelsHeight;
            refresh = dm.dmDisplayFrequency;
        }
        // 挂在适配器上的监视器（克隆/扩展模式下每适配器一条；非活动跳过）
        let mut mon_idx = 0u32;
        loop {
            let mut md = DISPLAY_DEVICEW {
                cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32,
                ..Default::default()
            };
            if !unsafe { EnumDisplayDevicesW(PCWSTR(dd.DeviceName.as_ptr()), mon_idx, &mut md, 0) }.as_bool() {
                break;
            }
            mon_idx += 1;
            if md.StateFlags.0 & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP.0 == 0 {
                continue;
            }
            let device_id = wide_field(&md.DeviceID);
            if device_id.is_empty() || !seen.insert(device_id.clone()) {
                continue; // 同型号双接口（UID0/UID4353）去重
            }
            let (edid_name, edid_mfg, edid_size) = edid_of(&device_id);
            let name = match (edid_mfg.is_empty(), edid_name.is_empty()) {
                (false, false) => format!("{edid_mfg} {edid_name}"),
                (true, false) => edid_name,
                _ => wide_field(&md.DeviceString), // 解析不到 EDID 才回落驱动描述
            };
            out.push(json!({
                "name": name,
                "width": width,
                "height": height,
                "refresh": refresh,
                "size": edid_size,
            }));
        }
    }
    out
}

/// 从监视器 `DeviceID`（`MONITOR\SAC2563\{GUID}\0002`）读 EDID 并解析：
/// 厂商代码（字节 8-9 大端 3×5bit）/ 名称描述符（0xFC 块正文）/ 物理尺寸（cm→英寸 对角线）。
/// 任一解析不出给空串（调用方回落），不谎报。
///
/// ⚠️ 实例定位方式（本机 dump 实测钉死）：DeviceID 里的 `{GUID}\0002` **不能**直接拼成
/// 注册表路径（`Enum\MONITOR\...` 与 `Enum\DISPLAY\...\{GUID}` 均不存在）。可靠做法：
/// 取第二段 PnP ID（`SAC2563`）在 `Enum\DISPLAY\<PnPId>\` 下枚举实例子键
/// （本机为 `5&1620cf28&0&UID0` / `UID4353`），取第一个能读到 EDID 的实例 ——
/// 同型号多实例是同一台显示器的不同接口，EDID 一致/兼容。
fn edid_of(device_id: &str) -> (String, String, String) {
    let pnp = device_id.split('\\').nth(1).unwrap_or("");
    if pnp.is_empty() {
        return (String::new(), String::new(), String::new());
    }
    let base = format!(r"SYSTEM\CurrentControlSet\Enum\DISPLAY\{pnp}");
    let mut edid: Option<Vec<u8>> = None;
    unsafe {
        let sk = to_wide(&base);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
            let mut index = 0u32;
            loop {
                let mut name_buf = [0u16; 256];
                let mut name_len = name_buf.len() as u32;
                if RegEnumKeyExW(hk, index, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None).is_err() {
                    break;
                }
                index += 1;
                let inst = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let p = format!(r"{base}\{inst}\Device Parameters");
                if let Some(b) = reg_read_binary(HKEY_LOCAL_MACHINE, &p, "EDID") {
                    if b.len() >= 128 {
                        edid = Some(b);
                        break;
                    }
                }
            }
            let _ = RegCloseKey(hk);
        }
    }
    let Some(edid) = edid else {
        return (String::new(), String::new(), String::new());
    };
    // 厂商：字节 8-9 大端；三段 5-bit，1=A..26=Z
    let raw = ((edid[8] as u16) << 8) | edid[9] as u16;
    let ch = |v: u16| -> char { char::from(b'A' + ((v & 0x1F) as u8).wrapping_sub(1).min(25)) };
    let mfg: String = [ch(raw >> 10), ch(raw >> 5), ch(raw)].iter().collect();
    // 名称：描述符块 54/72/90/108；0xFC 块正文 = 偏移 +5..+18（13 字节，0x0A/0x00 截断）
    let mut name = String::new();
    for off in [54usize, 72, 90, 108] {
        if off + 18 <= edid.len()
            && edid[off] == 0
            && edid[off + 1] == 0
            && edid[off + 2] == 0
            && edid[off + 3] == 0xFC
        {
            let body = &edid[off + 5..off + 18];
            let end = body.iter().position(|&b| b == 0x0A || b == 0).unwrap_or(body.len());
            name = String::from_utf8_lossy(&body[..end]).trim().to_string();
            if !name.is_empty() {
                break;
            }
        }
    }
    // 物理尺寸：厘米 → 对角线英寸（两轴都 >0 才算，否则空串）
    let size = if edid[21] > 0 && edid[22] > 0 {
        let (w, h) = (edid[21] as f64, edid[22] as f64);
        format!("{:.1}英寸", (w * w + h * h).sqrt() / 2.54)
    } else {
        String::new()
    };
    (name, mfg, size)
}


#[cfg(test)]
mod tests {
    use super::*;

    /// `#[ignore]` 真机探针（AGENTS §1.6 第二问，2026-10-11 硬件补全）：
    /// 主板（本机 26H2 的 BIOS 注册表键零值，只能靠 SMBIOS）与显示器（EnumDisplayDevices
    /// + EDID）必须给非空结果。运行：cargo test --lib -- --ignored --nocapture hardware_probe
    #[ignore = "真机探针：读真实 SMBIOS/EDID"]
    #[test]
    fn hardware_probe() {
        let v = device_info().expect("device_info 应成功");
        let product = v["motherboard"]["product"].as_str().unwrap_or("");
        let mfg = v["motherboard"]["manufacturer"].as_str().unwrap_or("");
        println!("主板: 厂商={mfg} 型号={product}");
        let monitors = v["monitors"].as_array().cloned().unwrap_or_default();
        for m in &monitors {
            println!("显示器: {m}");
        }
        assert!(
            !product.is_empty() || !mfg.is_empty(),
            "主板厂商/型号全空（SMBIOS 与注册表兜底都失败）"
        );
        assert!(!monitors.is_empty(), "显示器列表为空（至少应有一台活动显示器）");
    }
}
