//! B10/B3 只读诊断域：系统盘介质探测（sysdisk）、系统体检（overview_checkup）、设备信息（device_info）。
//!
//! 本域刻意保持只读，且**返回形状即前端消费口径**：字段名与嵌套结构改动会直接打到
//! 概览页与设备信息页，动之前对照 src/scripts/overview.js 与 deviceinfo.js。


use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW};
use super::common::*;
use super::registry::*;
use super::services::*;
// ==================== B10 sysdisk：系统盘介质探测 ====================

/// 系统盘介质类型探测（对应 sysdisk.ps1，S3）
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
// ==================== B10 overview_checkup：系统体检 ====================

fn check_item(id: &str, title: &str, status: &str, value: &str, detail: &str, evidence: &str) -> Value {
    json!({
        "id": id, "title": title, "status": status,
        "value": value, "detail": detail, "evidence": evidence,
    })
}

/// 系统体检（对应 overview_checkup.ps1，S3）
///
/// 9 个检查项。WMI 相关（内存通道/磁盘健康/刷新率）返回 unknown，
/// commands 层检测到 unknown 时回退 PS 获取完整结果。
pub fn overview_checkup() -> Result<Value, String> {
    let mut checks = Vec::new();

    // 1. CPU 拓扑（GetSystemInfo + 注册表 EfficiencyClass）
    unsafe {
        use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
        let mut si = SYSTEM_INFO::default();
        GetSystemInfo(&mut si);
        let logical = si.dwNumberOfProcessors;
        // 核数从注册表读
        let mut cores = 0u32;
        let base = r"HARDWARE\DESCRIPTION\System\CentralProcessor";
        let sk = to_wide(base);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
            let mut index = 0u32;
            loop {
                let mut name_buf = [0u16; 256];
                let mut name_len = 256u32;
                if RegEnumKeyExW(hk, index, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None).is_err() { break; }
                cores += 1;
                index += 1;
            }
            let _ = RegCloseKey(hk);
        }
        if cores == 0 { cores = logical; }

        // 混合架构判定：EfficiencyClass 分级存在即为 P/E 混合
        let mut ec_vals = std::collections::HashSet::new();
        let base2 = r"HARDWARE\DESCRIPTION\System\CentralProcessor";
        let sk2 = to_wide(base2);
        let mut hk2 = HKEY::default();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk2.as_ptr()), Some(0), KEY_READ, &mut hk2).is_ok() {
            let mut index = 0u32;
            loop {
                let mut name_buf = [0u16; 256];
                let mut name_len = 256u32;
                if RegEnumKeyExW(hk2, index, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None).is_err() { break; }
                let proc_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let proc_key = format!("{base2}\\{proc_name}");
                let psk = to_wide(&proc_key);
                let mut phk = HKEY::default();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(psk.as_ptr()), Some(0), KEY_READ, &mut phk).is_ok() {
                    let mut ec = 0u32;
                    let mut esize = 4u32;
                    let enm = to_wide("EfficiencyClass");
                    if RegQueryValueExW(phk, PCWSTR(enm.as_ptr()), None, None, Some(&mut ec as *mut u32 as *mut u8), Some(&mut esize)).is_ok() {
                        ec_vals.insert(ec);
                    }
                    let _ = RegCloseKey(phk);
                }
                index += 1;
            }
            let _ = RegCloseKey(hk2);
        }

        if cores > 0 {
            if ec_vals.len() > 1 {
                checks.push(check_item("cpu_topology", "CPU 拓扑", "ok",
                    &format!("{cores} 核 {logical} 线程（P/E 混合架构）"),
                    "检测到效率类分级，游戏场景建议绑定性能核", "机制明确"));
            } else {
                checks.push(check_item("cpu_topology", "CPU 拓扑", "ok",
                    &format!("{cores} 核 {logical} 线程"),
                    "同构多核架构，无需区分核类型调度", "本机实测"));
            }
        } else {
            checks.push(check_item("cpu_topology", "CPU 拓扑", "unknown", "无法读取", "未读取到处理器信息", "未验证"));
        }
    }

    // 2. 内存通道（WMI，返回 unknown 触发回退）
    checks.push(check_item("memory_channels", "内存通道", "unknown", "无法读取", "SMBIOS 未返回内存条信息", "未验证"));

    // 3. 电源计划（v4 R5-M09：删 powercfg 文本判据，改调 syspanel 的 Power API 实现）
    //
    // 旧实现拉 `powercfg /getactivescheme` 再 `from_utf8_lossy` 解析括号里的方案名 ——
    // 中文系统该输出不是 UTF-8：lossy 后整段乱码，「节能」判不出（告警永不触发）、
    // 「高性能」也判不出，任何方案都掉进 else 报「平衡（系统默认）」，还标称「本机实测」。
    // syspanel 侧已**书面废弃**这条姿势（改走 powrprof.dll 的 Power API、UTF-16 直出），
    // 体检项直接复用同一实现 —— 口径唯一，也不再引入 systembin 目录之外的进程调用。
    {
        let st = super::power_plan_state();
        let name = st.get("activeName").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let name_lower = name.to_lowercase();
        let cjk_hit = |needles: &[&str]| needles.iter().any(|n| name_lower.contains(n));
        if name.trim().is_empty() {
            checks.push(check_item("power_plan", "电源计划", "unknown", "无法读取", "Power API 未返回活动方案名", "未验证"));
        } else if cjk_hit(&["节能", "power saver"]) {
            checks.push(check_item("power_plan", "电源计划", "warn", &name, "节能计划会限制性能释放，建议切换平衡或高性能", "本机实测"));
        } else if cjk_hit(&["高性能", "卓越", "high", "ultimate"]) {
            checks.push(check_item("power_plan", "电源计划", "ok", &name, "高性能计划已启用", "本机实测"));
        } else {
            checks.push(check_item("power_plan", "电源计划", "ok", &name, "平衡计划（系统默认）；追求极限响应可切换高性能", "本机实测"));
        }
    }

    // 4. 开机自启数量（注册表 Run/RunOnce + 启动文件夹）
    let mut startup_count = 0;
    let run_keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ];
    for key in &run_keys {
        // HKCU
        let sk = to_wide(key);
        let mut hk = HKEY::default();
        unsafe {
            if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
                startup_count += reg_count_values(hk);
                let _ = RegCloseKey(hk);
            }
            // HKLM
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
                startup_count += reg_count_values(hk);
                let _ = RegCloseKey(hk);
            }
        }
    }
    // 启动文件夹
    if let Ok(appdata) = std::env::var("APPDATA") {
        let folder = format!("{appdata}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        if let Ok(rd) = std::fs::read_dir(&folder) {
            startup_count += rd.filter_map(|e| e.ok()).filter(|e| e.path().is_file()).count();
        }
    }
    if let Ok(progdata) = std::env::var("ProgramData") {
        let folder = format!("{progdata}\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp");
        if let Ok(rd) = std::fs::read_dir(&folder) {
            startup_count += rd.filter_map(|e| e.ok()).filter(|e| e.path().is_file()).count();
        }
    }
    if startup_count > 15 {
        checks.push(check_item("startup_count", "开机自启", "warn", &format!("{startup_count} 项"), "自启项偏多，建议在「启动项管理」中精简", "本机实测"));
    } else {
        checks.push(check_item("startup_count", "开机自启", "ok", &format!("{startup_count} 项"), "自启数量正常（注册表 Run/RunOnce + 启动文件夹）", "本机实测"));
    }

    // 5. 磁盘健康（WMI，返回 unknown 触发回退）
    checks.push(check_item("disk_health", "磁盘健康", "unknown", "无法读取", "未获取到磁盘状态", "未验证"));

    // 6. 可精简服务（SCM）
    let nonessential = ["DiagTrack","dmwappushservice","MapsBroker","Fax","RemoteRegistry","RetailDemo","SharedAccess","WMPNetworkSvc","WerSvc","WalletService","PhoneSvc","TapiSrv","SCardSvr","SCPolicySvc","PcaSvc","SensrSvc"];
    let mut svc_on = 0;
    for svc in &nonessential {
        if let Some((state, _)) = unsafe { service_status(svc) } {
            // state 4=Running；startType 简化为 0，只判运行态
            if state == 4 {
                svc_on += 1;
            }
        }
    }
    if svc_on > 0 {
        checks.push(check_item("nonessential_services", "可精简服务", "warn", &format!("{svc_on} 个仍在启用"), "遥测/传真/远程注册表等可精简服务未禁用，可在「电脑优化中心-系统服务」按需处理", "机制明确"));
    } else {
        checks.push(check_item("nonessential_services", "可精简服务", "ok", "无", "公认可精简的服务均已禁用或未安装", "机制明确"));
    }

    // 7. 显示器刷新率（WMI，返回 unknown 触发回退）
    checks.push(check_item("refresh_rate", "显示器刷新率", "unknown", "无法读取", "未获取到当前刷新率", "未验证"));

    // 8. Defender 实时防护（SCM WinDefend + 注册表）
    let defender_running = unsafe { service_status("WinDefend") }.map(|(state, _)| state == 4).unwrap_or(false);
    if defender_running {
        checks.push(check_item("defender_status", "实时防护", "ok", "服务运行中", "防护状态明细不可读（可能被安全软件接管），Defender 服务正常", "本机实测"));
    } else {
        checks.push(check_item("defender_status", "实时防护", "warn", "服务未运行", "可能已由第三方安全软件接管防护，请确认防护来源", "本机实测"));
    }

    // 9. 系统盘剩余空间（GetDiskFreeSpaceExW）
    unsafe {
        use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let mut free_bytes = 0u64;
        let mut total_bytes = 0u64;
        let root = to_wide("C:\\");
        if GetDiskFreeSpaceExW(PCWSTR(root.as_ptr()), Some(&mut free_bytes), Some(&mut total_bytes), None).is_ok() && total_bytes > 0 {
            let free_pct = (free_bytes as f64 * 100.0 / total_bytes as f64 * 10.0).round() / 10.0;
            let free_gb = (free_bytes as f64 / (1024.0 * 1024.0 * 1024.0) * 10.0).round() / 10.0;
            if free_pct < 10.0 {
                checks.push(check_item("sys_drive_free", "系统盘空间", "bad", &format!("剩余 {free_gb} GB（{free_pct}%）"), "系统盘空间严重不足，会影响系统更新与虚拟内存", "本机实测"));
            } else if free_pct < 20.0 {
                checks.push(check_item("sys_drive_free", "系统盘空间", "warn", &format!("剩余 {free_gb} GB（{free_pct}%）"), "系统盘空间偏紧，建议前往「磁盘清理」释放空间", "本机实测"));
            } else {
                checks.push(check_item("sys_drive_free", "系统盘空间", "ok", &format!("剩余 {free_gb} GB（{free_pct}%）"), "系统盘空间充足", "本机实测"));
            }
        } else {
            checks.push(check_item("sys_drive_free", "系统盘空间", "unknown", "无法读取", "未获取到系统盘信息", "未验证"));
        }
    }

    // 10. 蓝屏（BugCheck）历史 + 转储策略（对标 RAINZ bsod.ps1，**只读**）
    //     只读是刻意的：改 CrashControl\CrashDumpEnabled 会改变系统崩溃时的行为，
    //     属写侧，不在诊断域范围内（对标报告 §3 B2 的「不建议收」那条）。
    {
        let hist = super::bsod::crash_history();
        let cc = &hist.control;
        if let Some(e) = hist.read_error.as_deref() {
            checks.push(check_item("crash_history", "蓝屏记录", "unknown", "无法读取", e, "未验证"));
        } else if let Some(newest) = hist.records.first() {
            // 短码串：优先带官方名，未收录时只给十六进制（不编造名字）
            let code_short = newest
                .bugcheck
                .map(|c| match super::bsod::bugcheck_detail(c) {
                    Some(d) => format!("0x{c:08X} {}", d.name),
                    None => format!("0x{c:08X}"),
                })
                .unwrap_or_else(|| "码未读出（转储头部形态异常）".to_string());
            let when = super::bsod::age_text(newest.mtime_ms, crate::engine::now_ms());
            // 参数 1 常指向出错的驱动对象/地址，是排查的入口；为 0 时不占字数
            let p0 = if newest.params[0] != 0 {
                format!("，参数1 0x{:016X}", newest.params[0])
            } else {
                String::new()
            };
            let reboot = match cc.auto_reboot {
                Some(v) if v != 0 => "，崩溃后自动重启已开",
                Some(_) => "，崩溃后不自动重启",
                None => "",
            };
            let head = format!(
                "最近一次 {code_short}{p0}；转储 {}（{} KB）{reboot}。文件保持原样未动。",
                newest.path,
                newest.size / 1024
            );
            // v0.4.9 起（RAINZ 对标 §3.1）：detail 追加三段「含义 / 常见成因 / 建议」，
            // 未收录的码走 classify_fallback 给分类方向（不编造 causes）。
            // 换行分隔靠前端 CSS 的 white-space: pre-line 生效，与 §3.1 落法 4
            // 「复用 checks 通道、零新增 IPC」的定位一致。
            let body = match newest.bugcheck {
                Some(c) => match super::bsod::bugcheck_detail(c) {
                    Some(d) => super::bsod::render_detail(d),
                    None => {
                        let hit = super::bsod::classify_fallback(c);
                        super::bsod::render_fallback(c, &hit)
                    }
                },
                None => String::new(),
            };
            // v0.4.9 起（RAINZ 对标 §3.2）：崩溃模块定位。四个参数里第一个能落到
            // 某个模块 [base, base+size) 区间内的地址就是"疑似出错模块"；不命中就不写这段
            // （不猜"最近的模块"）。全内存转储本轮不解模块（要内核符号），也走这条无路径。
            let module_line = match (&newest.crash_module, newest.crash_addr) {
                (Some(name), Some(addr)) => format!("\n出错模块：{name}（0x{addr:016X}）"),
                _ => String::new(),
            };
            let mut detail = head;
            if !body.is_empty() {
                detail.push_str("\n\n");
                detail.push_str(&body);
            }
            detail.push_str(&module_line);
            // v0.4.9 起（RAINZ 对标 §3.3）：崩溃事件时间线（近 30 天 Kernel-Power 41 /
            // EventLog 6008 / WER-BugCheck 1001）。放最后一段，让用户能核对
            // 「文件 mtime 的近似时间」与「事件里的权威时间」是否对得上。
            // 事件为空（本机没崩过 / 权限不足 / 日志被裁）时不写这段。
            {
                let events = super::bsod::event_timeline(30);
                if !events.is_empty() {
                    let now = crate::engine::now_ms();
                    let lines: Vec<String> = events
                        .iter()
                        .take(3)
                        .map(|e| {
                            let code = e
                                .bugcheck
                                .map(|c| format!(" · 0x{c:08X}"))
                                .unwrap_or_default();
                            format!(
                                "· {}（EventID={}）{}",
                                super::bsod::age_text(e.time_ms, now),
                                e.event_id,
                                code
                            )
                        })
                        .collect();
                    detail.push_str("\n\n事件时间线（近 30 天，最多 3 条）：\n");
                    detail.push_str(&lines.join("\n"));
                }
            }
            checks.push(check_item(
                "crash_history",
                "蓝屏记录",
                "warn",
                &format!("{} 个转储，最近 {when}", hist.records.len()),
                &detail,
                "本机实测",
            ));
        } else if cc.dump_enabled() {
            checks.push(check_item(
                "crash_history",
                "蓝屏记录",
                "ok",
                "无转储",
                &format!(
                    "未发现转储文件（转储策略：{}）—— 若确实蓝屏过却没有转储，检查 {} 是否可写",
                    cc.mode_text(),
                    cc.minidump_dir.as_deref().unwrap_or("%SystemRoot%\\Minidump")
                ),
                "本机实测",
            ));
        } else {
            checks.push(check_item(
                "crash_history",
                "蓝屏记录",
                "warn",
                "转储未启用",
                "系统未启用崩溃转储：一旦蓝屏将不会留下可分析的证据。可在「系统属性 → 高级 → 启动和故障恢复」里开启",
                "机制明确",
            ));
        }
    }

    Ok(json!({ "checks": checks }))
}


// ==================== B3 device_info：设备信息采集 ====================

/// 设备信息采集（对应 device_info.ps1，S3）
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

        // 4. 主板
        let motherboard = {
            let product = reg_read_string(HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardProduct").unwrap_or_default();
            let manufacturer = reg_read_string(HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardManufacturer").unwrap_or_default();
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

        // 7. 显示器（从 EDID 注册表读取，简化版）
        let monitors: Vec<Value> = Vec::new(); // EDID 解析复杂，暂留空

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


#[cfg(test)]
mod tests {
    use super::*;

    /// 系统体检的**形状与接线**（此前该函数只有 IPC 路径、零单测覆盖）。
    /// 钉两件事：① 每个 check 都带前端 `renderCheckup` 直接消费的六个字段，且 status
    /// 落在前端枚举内；② 本批新增的「蓝屏记录」项确实在列 —— 它是只读诊断，
    /// 任何机器上都应给出结论，最差也该是 unknown，不许缺席。
    #[test]
    fn 体检输出形状与蓝屏项接线() {
        let v = overview_checkup().expect("体检应成功");
        let checks = v
            .get("checks")
            .and_then(|c| c.as_array())
            .expect("checks 必须是数组");
        assert!(checks.len() >= 10, "体检项数异常偏少: {}", checks.len());
        let mut ids: Vec<String> = Vec::new();
        for c in checks {
            for f in ["id", "title", "status", "value", "detail", "evidence"] {
                assert!(c.get(f).and_then(|x| x.as_str()).is_some(), "体检项缺字段 {f}: {c}");
            }
            let st = c["status"].as_str().unwrap_or("");
            assert!(
                matches!(st, "ok" | "warn" | "bad" | "unknown"),
                "未预期的 status「{st}」（前端按枚举取样式）: {c}"
            );
            ids.push(c["id"].as_str().unwrap_or("").to_string());
        }
        assert!(
            ids.contains(&"crash_history".to_string()),
            "蓝屏记录项缺席，实收: {ids:?}"
        );
    }
}
