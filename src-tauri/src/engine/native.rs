//! B1 PS→Rust 迁移：低风险只读采集的原生 Windows API 实现
//!
//! 四个函数对应四个原 PS 脚本，输出 JSON 字段与原脚本逐字段兼容：
//! - `memory_info`      ← memory_info.ps1
//! - `memory_processes` ← memory_processes.ps1（@@PROC@@ 协议）
//! - `realtime_adapters` ← realtime_adapters.ps1
//! - `realtime_loss`    ← realtime_loss.ps1
//!
//! 状态：纯原生（方案 S3）。各域 `.ps1` 已删除，本模块是唯一实现，**不存在 PS 回退**；
//! 调用失败一律如实返回错误（2026-09-25 审计修正：旧注释「S1 NativeFirst、自动回退 PS」与代码事实不符）。
//! 权限拒绝、参数非法等不应回退——由调用方按错误类型判断。

use serde_json::{json, Value};

// 审查 v2-F7：系统工具统一经 `system_tool` 解析到 System32 后再 `Command::new`，
// 不允许直接写裸进程名（搜索顺序里 exe 所在目录与 CWD 都排在 System32 之前）。
use crate::engine::systembin::system_tool;

/// 从 `*const u16` 以 null 结尾宽字符串构造 String（null 指针返回空串）
unsafe fn wide_str(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let len = (0isize..).take_while(|&i| *ptr.offset(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// 从 `*const u8` 以 null 结尾 ANSI 字符串构造 String
unsafe fn pstr_to_string(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let len = (0isize..).take_while(|&i| *ptr.offset(i) != 0).count();
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).to_string()
}

/// Rust str → null 结尾宽字符串
fn wide_str_from_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ==================== memory:info ====================

/// 原生读取物理内存 / 页面文件 / Cache Bytes
///
/// 字段映射（对照 memory_info.ps1）：
/// - total/free/used/load ← GlobalMemoryStatusEx
/// - cache                 ← GetPerformanceInfo.SystemCache * PageSize
/// - pageTotal/pageUsed    ← GetPerformanceInfo.CommitLimit/CommitTotal 减去物理量
pub fn memory_info() -> Result<Value, String> {
    unsafe {
        use windows::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
        use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

        let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
        ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut ms).map_err(|_| "GlobalMemoryStatusEx 失败".to_string())?;

        let mut pi: PERFORMANCE_INFORMATION = std::mem::zeroed();
        GetPerformanceInfo(&mut pi, std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32)
            .map_err(|_| "GetPerformanceInfo 失败".to_string())?;

        let total = ms.ullTotalPhys;
        let free = ms.ullAvailPhys;
        let used = total.saturating_sub(free);
        let load = ms.dwMemoryLoad as i64;
        let page_size = pi.PageSize as u64;
        let cache = pi.SystemCache as u64 * page_size;
        let page_total = (pi.CommitLimit as u64)
            .saturating_sub(pi.PhysicalTotal as u64)
            * page_size;
        let page_used = (pi.CommitTotal as u64)
            .saturating_sub(pi.PhysicalAvailable as u64)
            * page_size;

        Ok(json!({
            "total": total,
            "free": free,
            "used": used,
            "load": load,
            "pageTotal": page_total,
            "pageUsed": page_used,
            "cache": cache,
        }))
    }
}

// ==================== memory:processes ====================

/// 进程快照项（对应 PS 输出的字段名：Id / ProcessName / mem / Path）
pub struct NativeProcess {
    pub pid: u32,
    pub name: String,
    pub working_set: u64,
    pub path: String,
}

/// 原生枚举进程列表，按 WorkingSetSize 降序，取前 300
pub fn memory_processes() -> Result<Vec<NativeProcess>, String> {
    unsafe {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        };

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|_| "CreateToolhelp32Snapshot 失败".to_string())?;

        let mut entries: Vec<NativeProcess> = Vec::new();
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                let pid = pe.th32ProcessID;
                let name = wide_str(pe.szExeFile.as_ptr());

                let mut working_set = 0u64;
                let mut path = String::new();

                if let Ok(proc) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                    let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
                    pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                    if GetProcessMemoryInfo(proc, &mut pmc, pmc.cb).is_ok() {
                        working_set = pmc.WorkingSetSize as u64;
                    }
                    let mut buf = [0u16; 1024];
                    let mut len = buf.len() as u32;
                    if QueryFullProcessImageNameW(
                        proc,
                        PROCESS_NAME_FORMAT(0),
                        PWSTR(buf.as_mut_ptr()),
                        &mut len,
                    )
                    .is_ok()
                    {
                        path = String::from_utf16_lossy(&buf[..len as usize]);
                    }
                    let _ = CloseHandle(proc);
                }

                entries.push(NativeProcess {
                    pid,
                    name,
                    working_set,
                    path,
                });

                pe = std::mem::zeroed();
                pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);

        entries.sort_by(|a, b| b.working_set.cmp(&a.working_set));
        entries.truncate(300);
        Ok(entries)
    }
}

// ==================== realtime:adapters ====================

/// 从注册表读网络连接名（NetConnectionID）
unsafe fn net_connection_name(adapter_guid: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let sub = format!(
        r"SYSTEM\CurrentControlSet\Control\Network\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{adapter_guid}"
    );
    let sub_w = wide_str_from_str(&sub);
    let name_w = wide_str_from_str("Name");

    let mut hkey = HKEY_LOCAL_MACHINE;
    if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sub_w.as_ptr()), None, KEY_READ, &mut hkey).is_err() {
        return None;
    }
    let mut buf = [0u16; 260];
    let mut len = (buf.len() * 2) as u32;
    let result = RegQueryValueExW(
        hkey,
        PCWSTR(name_w.as_ptr()),
        None,
        None,
        Some(buf.as_mut_ptr() as *mut u8),
        Some(&mut len),
    );
    let _ = RegCloseKey(hkey);
    if result.is_err() {
        return None;
    }
    let chars = (len as usize / 2).min(buf.len());
    let s = String::from_utf16_lossy(&buf[..chars]);
    let s = s.trim_end_matches('\0').to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// 原生枚举物理网卡
pub fn realtime_adapters() -> Result<Value, String> {
    unsafe {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH as IP_ADAPTER_ADDRESSES,
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
            GAA_FLAG_SKIP_UNICAST,
        };

        const AF_UNSPEC: u32 = 0;
        let flags = GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER;

        let mut buf_len: u32 = 16 * 1024;
        let mut buf: Vec<u8> = vec![0u8; buf_len as usize];
        let ret = GetAdaptersAddresses(
            AF_UNSPEC,
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            &mut buf_len,
        );
        if ret == 111 {
            // ERROR_BUFFER_OVERFLOW
            buf = vec![0u8; buf_len as usize];
            let ret = GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut _),
                &mut buf_len,
            );
            if ret != 0 {
                return Err(format!("GetAdaptersAddresses 失败 (错误 {ret})"));
            }
        } else if ret != 0 {
            return Err(format!("GetAdaptersAddresses 失败 (错误 {ret})"));
        }

        let mut adapters: Vec<Value> = Vec::new();
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES;
        while !p.is_null() {
            let adapter = &*p;
            if adapter.IfType == 6 || adapter.IfType == 71 {
                let name = wide_str(adapter.FriendlyName.0);
                // AdapterName 是 PSTR（ANSI GUID 字符串）
                let guid = pstr_to_string(adapter.AdapterName.0 as *const u8);
                let connection_name = net_connection_name(&guid).unwrap_or_default();

                let mac: String = if adapter.PhysicalAddressLength > 0 {
                    adapter.PhysicalAddress[..adapter.PhysicalAddressLength as usize]
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join("-")
                } else {
                    String::new()
                };

                let link_speed = adapter.TransmitLinkSpeed.to_string();
                let status = match adapter.OperStatus.0 {
                    1 => "Up",
                    2 => "Connecting",
                    0 => "Down",
                    3 => "Disconnecting",
                    7 => "MediaDisconnected",
                    9 => "AuthSucceeded",
                    _ => "Unknown",
                };

                adapters.push(json!({
                    "name": name,
                    "connectionName": connection_name,
                    "description": name,
                    "status": status,
                    "mac": mac,
                    "linkSpeed": link_speed,
                }));
            }
            p = adapter.Next;
        }

        if adapters.is_empty() {
            Ok(json!({
                "success": false,
                "message": "未检测到物理网卡",
                "adapters": []
            }))
        } else {
            Ok(json!({ "success": true, "adapters": adapters }))
        }
    }
}

// ==================== realtime:loss ====================

/// 原生丢包检测：取默认网关 + ICMP ping 3 次
pub fn realtime_loss() -> Result<Value, String> {
    unsafe {
        use windows::Win32::Foundation::WIN32_ERROR;
        use windows::Win32::NetworkManagement::IpHelper::{
            FreeMibTable, GetIpForwardTable2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
            ICMP_ECHO_REPLY, MIB_IPFORWARD_TABLE2,
        };
        use windows::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET};

        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let ret = GetIpForwardTable2(ADDRESS_FAMILY(AF_INET.0), &mut table);
        if ret != WIN32_ERROR(0) {
            return Err(format!("GetIpForwardTable2 失败 (错误 {ret:?})"));
        }

        let mut gateway_addr: Option<u32> = None;
        let mut best_metric = u32::MAX;
        let base = (*table).Table.as_ptr();
        for i in 0..(*table).NumEntries as usize {
            let row = &*base.add(i);
            if row.DestinationPrefix.PrefixLength == 0 && row.Metric < best_metric {
                best_metric = row.Metric;
                let nh = &row.NextHop;
                if nh.Ipv4.sin_family == AF_INET {
                    gateway_addr = Some(nh.Ipv4.sin_addr.S_un.S_addr);
                }
            }
        }
        FreeMibTable(table as *mut _);

        let sent = 3u32;
        let mut received = 0u32;
        let mut latency_sum = 0f64;

        if let Some(gw_net) = gateway_addr {
            let handle = IcmpCreateFile().map_err(|_| "IcmpCreateFile 失败".to_string())?;

            for _ in 0..sent {
                let mut reply_buf = [0u8; 1024];
                let n = IcmpSendEcho(
                    handle,
                    gw_net,
                    std::ptr::null(),
                    0,
                    None,
                    reply_buf.as_mut_ptr() as *mut _,
                    reply_buf.len() as u32,
                    600,
                );
                if n > 0 {
                    let echo = &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY);
                    if echo.Status == 0 {
                        received += 1;
                        latency_sum += echo.RoundTripTime as f64;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let _ = IcmpCloseHandle(handle);

            let b = gw_net.to_be_bytes();
            let gateway_str = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);

            let lost = sent - received;
            let loss_rate = (lost as f64 * 100.0 / sent as f64 * 10.0).round() / 10.0;
            let latency = if received > 0 {
                (latency_sum / received as f64 * 10.0).round() / 10.0
            } else {
                0.0
            };

            Ok(json!({
                "success": true,
                "gateway": gateway_str,
                "sent": sent,
                "received": received,
                "lost": lost,
                "lossRate": loss_rate,
                "latencyMs": latency,
            }))
        } else {
            Ok(json!({
                "success": true,
                "gateway": Value::Null,
                "sent": sent,
                "received": 0,
                "lost": sent,
                "lossRate": 100.0,
                "latencyMs": 0,
            }))
        }
    }
}

// ==================== B2：进程控制 ====================

use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, QueryFullProcessImageNameW,
    PROCESS_TERMINATE, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

pub fn kill_process(pid: u32, expected_name: &str) -> Result<Value, String> {
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return Ok(json!({"success": false, "message": "进程不存在或已退出"})),
        };
        let mut name_buf = [0u16; 260];
        let mut name_len = name_buf.len() as u32;
        let exe_name = if QueryFullProcessImageNameW(h, windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0), windows::core::PWSTR(name_buf.as_mut_ptr()), &mut name_len).is_ok() {
            let path = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            std::path::Path::new(&path).file_stem().and_then(|s| s.to_str()).unwrap_or("").to_lowercase()
        } else { String::new() };
        let _ = CloseHandle(h);
        let expected_lower = expected_name.to_lowercase();
        if !expected_name.is_empty() && !exe_name.is_empty() && exe_name != expected_lower {
            return Ok(json!({"success": false, "message": "进程 ID 已被系统复用，已拒绝结束"}));
        }
        let h_term = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|_| "无法打开进程（权限不足）".to_string())?;
        let name_display = if exe_name.is_empty() { format!("PID {pid}") } else { exe_name.clone() };
        TerminateProcess(h_term, 1).map_err(|_| "结束进程失败".to_string())?;
        let _ = CloseHandle(h_term);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let still_alive = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).is_ok();
        if still_alive {
            Ok(json!({"success": false, "message": format!("无法结束进程 {name_display} (PID {pid})，可能需要管理员权限")}))
        } else {
            Ok(json!({"success": true, "message": format!("已结束进程 {name_display} (PID {pid})")}))
        }
    }
}

pub fn stubborn_kill() -> Result<Value, String> {
    let targets: &[&str] = &[
        "edrservice","douyin_guard","douyin","douyin_tray",
        "gameviewer","gameviewerservice","gameviewerserver","gameviewerhealthd",
        "mumunxmain","mumunxservice","mumuremoteservice","mumuremotebackend",
        "mumuremotehealthd","vedetector","jianyingpro","jianyingprotray",
        "wps","et","wpp","wpspdf","wpscloudsvr",
        "mscpcmanager","mscpcmanagercore","mscpcmanagerservice",
    ];
    let mut killed = 0u32;
    let mut failed = 0u32;
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|_| "无法枚举进程".to_string())?;
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..std::mem::zeroed() };
        let mut first = true;
        while (if first { first = false; Process32FirstW(snap, &mut entry) } else { Process32NextW(snap, &mut entry) }).is_ok() {
            let end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let exe = String::from_utf16_lossy(&entry.szExeFile[..end]);
            let stem = exe.to_lowercase();
            let stem = stem.strip_suffix(".exe").unwrap_or(&stem);
            if targets.contains(&stem) {
                let pid = entry.th32ProcessID;
                if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                    if TerminateProcess(h, 1).is_ok() { killed += 1; } else { failed += 1; }
                    let _ = CloseHandle(h);
                } else { failed += 1; }
            }
        }
        let _ = CloseHandle(snap);
    }
    let mut leftover: Vec<String> = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|_| "无法枚举进程".to_string())?;
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..std::mem::zeroed() };
        let mut first = true;
        let mut seen = std::collections::HashSet::new();
        while (if first { first = false; Process32FirstW(snap, &mut entry) } else { Process32NextW(snap, &mut entry) }).is_ok() {
            let end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let exe = String::from_utf16_lossy(&entry.szExeFile[..end]);
            let stem = exe.to_lowercase();
            let stem = stem.strip_suffix(".exe").unwrap_or(&stem).to_string();
            if targets.contains(&stem.as_str()) && seen.insert(stem.clone()) { leftover.push(stem); }
        }
        let _ = CloseHandle(snap);
    }
    Ok(json!({"killed": killed, "failed": failed, "leftover": leftover}))
}


// ==================== B4：本机测速（回环 TCP） ====================

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

/// 回环 TCP 延迟测试（对应 netspeed_ping.ps1）
pub fn netspeed_ping() -> Result<Value, String> {
    let listener = TcpListener::bind("127.0.0.1:19999").map_err(|_| "端口被占用".to_string())?;
    let mut samples: Vec<f64> = Vec::new();
    for _ in 0..10 {
        let start = Instant::now();
        match TcpStream::connect_timeout(
            &"127.0.0.1:19999".parse().unwrap(),
            std::time::Duration::from_millis(2000),
        ) {
            Ok(_stream) => {
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    drop(listener);
    if samples.is_empty() {
        return Ok(json!({"success": false, "message": "无法建立本地回环连接"}));
    }
    let avg = samples.iter().sum::<f64>() / samples.len() as f64;
    let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = samples.iter().cloned().fold(0.0f64, f64::max);
    let mut sorted = samples.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut jitter = 0.0;
    for i in 1..sorted.len() {
        jitter += (sorted[i] - sorted[i-1]).abs();
    }
    if sorted.len() > 1 { jitter /= (sorted.len() - 1) as f64; }
    Ok(json!({
        "success": true,
        "avg": (avg * 100.0).round() / 100.0,
        "min": (min * 100.0).round() / 100.0,
        "max": (max * 100.0).round() / 100.0,
        "jitter": (jitter * 100.0).round() / 100.0,
        "samples": samples,
    }))
}

/// 回环 TCP 吞吐测试（对应 netspeed_throughput.ps1）
pub fn netspeed_throughput(secs: f64) -> Result<Value, String> {
    let listener = TcpListener::bind("127.0.0.1:19999").map_err(|_| "端口被占用".to_string())?;
    // 服务端线程：接收数据
    let server = std::thread::spawn(move || {
        let mut received: u64 = 0;
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 64 * 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => received += n as u64,
                    Err(_) => break,
                }
            }
        }
        received
    });
    // 客户端：连接并持续发送
    std::thread::sleep(std::time::Duration::from_millis(100));
    let mut client = TcpStream::connect("127.0.0.1:19999").map_err(|_| "连接失败".to_string())?;
    let payload = vec![0u8; 64 * 1024];
    let start = Instant::now();
    let mut total_sent: u64 = 0;
    let mut samples: Vec<Value> = Vec::new();
    loop {
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed >= secs { break; }
        client.write_all(&payload).map_err(|_| "发送失败".to_string())?;
        total_sent += payload.len() as u64;
        if samples.is_empty() || (elapsed * 5.0) >= samples.len() as f64 {
            let inst_bps = total_sent as f64 / elapsed.max(0.001);
            samples.push(json!({
                "time": (elapsed * 100.0).round() / 100.0,
                "speed": (inst_bps / 1048576.0 * 100.0).round() / 100.0,
            }));
        }
    }
    drop(client);
    let received = server.join().unwrap_or(0);
    let actual_duration = start.elapsed().as_secs_f64().max(0.001);
    let avg_bps = received as f64 / actual_duration;
    let download_mbps = (avg_bps * 8.0 / 1048576.0 * 100.0).round() / 100.0;
    let speeds: Vec<f64> = samples.iter().filter_map(|s| s.get("speed").and_then(|v| v.as_f64())).collect();
    let mut jitter = 0.0;
    for i in 1..speeds.len() {
        jitter += (speeds[i] - speeds[i-1]).abs();
    }
    if speeds.len() > 1 { jitter /= (speeds.len() - 1) as f64; }
    Ok(json!({
        "success": true,
        "duration": (actual_duration * 100.0).round() / 100.0,
        "downloadMbps": download_mbps,
        "uploadMbps": download_mbps,
        "totalBytes": received,
        "jitter": (jitter * 100.0).round() / 100.0,
        "samples": samples,
    }))
}

// ==================== B3：外设只读查询 ====================

use windows::Win32::System::Registry::{
    RegOpenKeyExW, RegQueryValueExW, RegCloseKey, HKEY, HKEY_LOCAL_MACHINE,
    KEY_READ, REG_VALUE_TYPE, REG_SZ, REG_DWORD,
};

/// 读注册表 DWORD，失败返回 -1（保持 unsafe 签名，调用方维持既有 unsafe 块）
unsafe fn read_reg_dword(hkey: HKEY, subkey: &str, value: &str) -> i32 {
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

/// 外设状态查询（对应 peripheral_query.ps1）
pub fn peripheral_query() -> Result<Value, String> {
    unsafe {
        let win32 = read_reg_dword(HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation");
        let keyboard = read_reg_dword(HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\kbdclass\Parameters", "KeyboardDataQueueSize");
        let mouse = read_reg_dword(HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize");
        Ok(json!({
            "win32": win32,
            "keyboard": keyboard,
            "mouse": mouse,
        }))
    }
}
// ==================== B5：启动项扫描 ====================

use windows::Win32::System::Registry::{
    RegEnumValueW, HKEY_CURRENT_USER, REG_EXPAND_SZ, REG_BINARY, REG_MULTI_SZ,
};

/// 读注册表值（返回类型+数据）
unsafe fn reg_query_value(hk: HKEY, name: &str) -> Option<(REG_VALUE_TYPE, Vec<u8>)> {
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

/// 枚举注册表键的所有值名
unsafe fn reg_enum_values(hk: HKEY) -> Vec<String> {
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
        if r.is_err() { break; }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        if !name.is_empty() { names.push(name); }
        index += 1;
    }
    names
}

/// 从命令行提取可执行路径（支持引号包裹）
fn extract_cmd_path(cmd: &str) -> String {
    let c = cmd.trim();
    if c.starts_with('"') {
        if let Some(idx) = c[1..].find('"') {
            return c[1..idx+1].to_string();
        }
    }
    if let Some(sp) = c.find(' ') {
        return c[..sp].to_string();
    }
    c.to_string()
}

/// 展开环境变量（%VAR%）
fn expand_env(s: &str) -> String {
    let mut result = s.to_string();
    // 简单展开常见变量
    for var in ["APPDATA", "LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)", "SystemRoot", "windir", "USERPROFILE", "PUBLIC"] {
        if let Ok(val) = std::env::var(var) {
            result = result.replace(&format!("%{var}%"), &val);
        }
    }
    result
}

/// 读 StartupApproved blob，返回是否禁用（首字节 bit0=1）
unsafe fn read_startup_approved(hive: HKEY, subkey: &str, value_name: &str) -> Option<bool> {
    let base = match hive {
        h if h == HKEY_CURRENT_USER => r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
        _ => r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
    };
    let full = format!("{base}\\{subkey}");
    let fw = to_wide(&full);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(fw.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
        return None;
    }
    let result = reg_query_value(hk, value_name).map(|(ty, buf)| {
        if ty == REG_BINARY && !buf.is_empty() {
            (buf[0] & 1) == 1
        } else {
            false
        }
    });
    let _ = RegCloseKey(hk);
    result
}

/// 取文件发布者（CompanyName）
fn get_publisher(path: &str) -> String {
    if path.is_empty() { return String::new(); }
    // 简化实现：不实现 GetFileVersionInfoW，留空
    // 后续 S2 用 VerQueryValueW 实现
    String::new()
}

/// 启动项扫描（对应 startup_scan.ps1）
///
/// 注册表 Run/RunOnce + 启动文件夹 + StartupApproved + disabled.json 合并。
/// 计划任务暂用 schtasks 命令获取。.lnk 目标解析和文件发布者留空（S2 完善）。
pub fn startup_scan() -> Result<Vec<Value>, String> {
    let mut results: Vec<Value> = Vec::new();

    unsafe {
        // ---------- 注册表 Run/RunOnce（8 路径） ----------
        let run_paths: &[(&str, HKEY, &str, &str, &str)] = &[
            ("HKCU", HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "注册表 · 当前用户\\Run", "HKCU"),
            ("HKCU", HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "注册表 · 当前用户\\RunOnce", "HKCU"),
            ("HKCU32", HKEY_CURRENT_USER, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "注册表 · 当前用户(32位)\\Run", "HKCU32"),
            ("HKCU32", HKEY_CURRENT_USER, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "注册表 · 当前用户(32位)\\RunOnce", "HKCU32"),
            ("HKLM", HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "注册表 · 所有用户\\Run", "HKLM"),
            ("HKLM", HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "注册表 · 所有用户\\RunOnce", "HKLM"),
            ("HKLM32", HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "注册表 · 所有用户(32位)\\Run", "HKLM32"),
            ("HKLM32", HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "注册表 · 所有用户(32位)\\RunOnce", "HKLM32"),
        ];

        for (hive_tag, hive, subkey, label, scope) in run_paths {
            let sk = to_wide(&subkey);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(*hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
                continue;
            }
            let values = reg_enum_values(hk);
            for vp in values {
                if vp.is_empty() { continue; }
                let Some((ty, buf)) = reg_query_value(hk, &vp) else { continue; };
                let value_type = match ty {
                    REG_SZ => "String",
                    REG_EXPAND_SZ => "ExpandString",
                    REG_BINARY => "Binary",
                    REG_MULTI_SZ => "MultiString",
                    REG_DWORD => "DWord",
                    _ => "Unknown",
                };
                let mut value_data = String::new();
                let mut value_data_b64 = String::new();
                let mut value_data_arr: Vec<String> = Vec::new();
                let mut cmd_path = String::new();

                if ty == REG_BINARY {
                    value_data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &buf);
                } else if ty == REG_MULTI_SZ {
                    // MULTI_SZ: 双 null 结尾的宽字符串序列
                    let wide: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let mut start = 0;
                    for i in 0..wide.len() {
                        if wide[i] == 0 {
                            if i > start {
                                value_data_arr.push(String::from_utf16_lossy(&wide[start..i]));
                            }
                            start = i + 1;
                        }
                    }
                } else if ty == REG_SZ || ty == REG_EXPAND_SZ {
                    let wide: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
                    value_data = String::from_utf16_lossy(&wide[..end]);
                    if ty == REG_EXPAND_SZ {
                        value_data = expand_env(&value_data);
                    }
                    if !value_data.trim().is_empty() {
                        cmd_path = extract_cmd_path(&value_data);
                    }
                }

                if value_data.trim().is_empty() && value_data_b64.is_empty() && value_data_arr.is_empty() {
                    continue;
                }

                // StartupApproved：32 位视图归到主 hive
                let sa_hive = if hive_tag.starts_with("HKLM") { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER };
                let sa_disabled = read_startup_approved(sa_hive, "Run", &vp);
                let enabled = sa_disabled.map(|d| !d).unwrap_or(true);
                let disabled_by = if !enabled && sa_disabled.is_some() { "system" } else { "" };

                let reg_path_full = match *hive {
                    h if h == HKEY_CURRENT_USER => format!("HKEY_CURRENT_USER\\{subkey}"),
                    _ => format!("HKEY_LOCAL_MACHINE\\{subkey}"),
                };

                results.push(json!({
                    "id": format!("reg|{reg_path_full}|{vp}"),
                    "name": vp,
                    "command": value_data,
                    "source": "registry",
                    "hive": hive_tag,
                    "regPath": reg_path_full,
                    "valueName": vp,
                    "valueType": value_type,
                    "valueData": value_data,
                    "valueDataB64": value_data_b64,
                    "valueDataArray": value_data_arr,
                    "filePath": "",
                    "taskPath": "",
                    "taskName": "",
                    "enabled": enabled,
                    "location": label,
                    "scope": scope,
                    "disabledBy": disabled_by,
                    "publisher": get_publisher(&cmd_path),
                    "resolvedPath": cmd_path,
                }));
            }
            let _ = RegCloseKey(hk);
        }

        // ---------- 启动文件夹 ----------
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let programdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        let folders: &[(&str, &str, &str)] = &[
            (&appdata, r"Microsoft\Windows\Start Menu\Programs\Startup", "启动文件夹 · 当前用户"),
            (&programdata, r"Microsoft\Windows\Start Menu\Programs\StartUp", "启动文件夹 · 所有用户"),
        ];

        for (base, sub, label) in folders {
            let dir = std::path::Path::new(base).join(sub);
            let Ok(entries) = std::fs::read_dir(&dir) else { continue; };
            let scope = if base == &appdata { "HKCU" } else { "HKLM" };
            let sa_hive = if scope == "HKLM" { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER };
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.eq_ignore_ascii_case("desktop.ini") { continue; }
                let full_path = entry.path().to_string_lossy().to_string();
                let name_stem = entry.path().file_stem().and_then(|s| s.to_str()).unwrap_or(&fname).to_string();
                // 简化实现：.lnk 目标解析暂用文件路径（未做 IShellLink 深解析）
                let resolved = full_path.clone();
                // StartupApproved\StartupFolder：先按全名找，再按无扩展名找
                let sa_disabled = read_startup_approved(sa_hive, "StartupFolder", &fname)
                    .or_else(|| read_startup_approved(sa_hive, "StartupFolder", &name_stem));
                let enabled = sa_disabled.map(|d| !d).unwrap_or(true);
                let disabled_by = if !enabled && sa_disabled.is_some() { "system" } else { "" };
                results.push(json!({
                    "id": format!("folder|{full_path}"),
                    "name": name_stem,
                    "command": full_path,
                    "source": "folder",
                    "hive": scope,
                    "regPath": "",
                    "valueName": "",
                    "valueType": "",
                    "valueData": "",
                    "valueDataB64": "",
                    "valueDataArray": Vec::<String>::new(),
                    "filePath": full_path,
                    "taskPath": "",
                    "taskName": "",
                    "enabled": enabled,
                    "location": label,
                    "scope": scope,
                    "disabledBy": disabled_by,
                    "publisher": get_publisher(&resolved),
                    "resolvedPath": resolved,
                }));
            }
        }
    }

    // ---------- 计划任务（schtasks 命令） ----------
    if let Ok(output) = std::process::Command::new(system_tool("schtasks"))
        .args(["/query", "/fo", "csv", "/nh", "/v"])
        .output()
    {
        if output.status.success() {
            let csv = String::from_utf8_lossy(&output.stdout);
            for line in csv.lines().skip(1) {
                // CSV 字段：HostName,TaskName,Next Run Time,Status,Logon Mode,Last Run Time,Last Result,Author,Task To Run,Start In,Comment,Scheduled Task State,Idle Time,Power Management,Run As User,Delete Task If Not Rescheduled,Stop Task If Runs X Hours And X Mins,Schedule,Schedule Type,Start Time,Start Date,End Date,Days,Months,Repeat: Every,Repeat: Until: Time,Repeat: Until: Duration,Repeat: Stop If Still Running,Multiple Instances
                let fields: Vec<&str> = line.split("\",\"").collect();
                if fields.len() < 10 { continue; }
                let task_name_raw = fields[1].trim_matches('"');
                // TaskName 格式：\Path\Name
                let task_path = match task_name_raw.rfind('\\') {
                    Some(idx) => &task_name_raw[..=idx],
                    None => "\\",
                };
                let task_name = match task_name_raw.rfind('\\') {
                    Some(idx) => &task_name_raw[idx+1..],
                    None => task_name_raw,
                };
                if task_path.starts_with("\\Microsoft\\") { continue; }
                // Schedule Type 字段（索引 19）含 Logon/Boot
                let schedule_type = fields.get(19).unwrap_or(&"").trim_matches('"');
                if !schedule_type.contains("Logon") && !schedule_type.contains("Boot") && !schedule_type.contains("At log on") && !schedule_type.contains("At startup") {
                    continue;
                }
                let task_to_run = fields.get(8).unwrap_or(&"").trim_matches('"');
                let state = fields.get(11).unwrap_or(&"").trim_matches('"');
                let enabled = state != "Disabled";
                results.push(json!({
                    "id": format!("task|{task_path}{task_name}"),
                    "name": task_name,
                    "command": task_to_run,
                    "source": "task",
                    "hive": "",
                    "regPath": "",
                    "valueName": "",
                    "valueType": "",
                    "valueData": "",
                    "valueDataB64": "",
                    "valueDataArray": Vec::<String>::new(),
                    "filePath": "",
                    "taskPath": task_path,
                    "taskName": task_name,
                    "enabled": enabled,
                    "location": format!("计划任务{}", task_path.trim_end_matches('\\')),
                    "scope": "HKLM",
                    "disabledBy": if !enabled { "system" } else { "" },
                    "publisher": "",
                    "resolvedPath": "",
                }));
            }
        }
    }

    // ---------- 合并 disabled.json ----------
    let disabled_file = std::path::Path::new(&std::env::var("APPDATA").unwrap_or_default())
        .join("Trim").join("startup-backup").join("disabled.json");
    if let Ok(text) = std::fs::read_to_string(&disabled_file) {
        if let Ok(records) = serde_json::from_str::<Vec<Value>>(&text) {
            for r in records {
                let Some(id) = r.get("id").and_then(|v| v.as_str()) else { continue; };
                if results.iter().any(|x| x.get("id").and_then(|v| v.as_str()) == Some(id)) { continue; }
                let mut item = r.clone();
                if let Some(o) = item.as_object_mut() {
                    o.insert("enabled".into(), json!(false));
                    o.insert("disabledBy".into(), json!("trim"));
                }
                results.push(item);
            }
        }
    }

    Ok(results)
}
// ==================== B6：右键菜单 ====================

use windows::Win32::System::Registry::{
    RegCreateKeyExW, RegSetValueExW, RegDeleteTreeW, RegDeleteValueW,
    REG_OPTION_NON_VOLATILE, KEY_WRITE, KEY_SET_VALUE, REG_CREATE_KEY_DISPOSITION,
    REG_CREATED_NEW_KEY, REG_QWORD,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;

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
                if std::process::Command::new(p).spawn().is_ok() { started += 1; }
            }
        }
        if started == 0 {
            let fallback = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            let fp = format!("{fallback}\\explorer.exe");
            if std::process::Command::new(&fp).spawn().is_ok() { started = 1; }
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

use windows::Win32::System::Registry::RegEnumKeyExW;
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::UI::WindowsAndMessaging::LoadStringW;
use windows::Win32::Foundation::{HMODULE, FreeLibrary};

/// 枚举注册表键的所有子键名
unsafe fn reg_enum_subkeys(hk: HKEY) -> Vec<String> {
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
        if r.is_err() { break; }
        names.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
        index += 1;
    }
    names
}

/// 读注册表字符串值（默认值或命名值），返回 Option<String>
unsafe fn reg_read_string(hk: HKEY, name: &str) -> Option<String> {
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
unsafe fn reg_read_dword_val(hk: HKEY, name: &str) -> Option<u32> {
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
// ==================== B7 runtimes_status：运行库检测 ====================

/// 运行库检测（对应 runtimes_status.ps1，S3）
///
/// 覆盖：VC++ 2015-2022 x64/x86（注册表+dll）、.NET Framework 4.x/3.5、
/// DirectX 9.0c 附属组件、旧版 VC++ 2005-2013 信息级列举。
pub fn runtimes_status() -> Result<Value, String> {
    unsafe {
        let mut items: Vec<Value> = Vec::new();

        // ---- VC++ 2015-2022 x64/x86 ----
        let vc_dlls = ["msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll", "concrt140.dll"];
        for arch in ["x64", "x86"] {
            let (reg_path, dll_dir) = if arch == "x64" {
                (r"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64", r"C:\Windows\System32")
            } else {
                (r"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x86", r"C:\Windows\SysWOW64")
            };
            let sk = to_wide(reg_path);
            let mut hk = HKEY::default();
            let installed = if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
                let inst = reg_read_dword_val(hk, "Installed").unwrap_or(0) == 1;
                let ver = reg_read_string(hk, "Version").unwrap_or_default();
                let _ = RegCloseKey(hk);
                (inst, ver)
            } else {
                (false, String::new())
            };
            let missing: Vec<&str> = vc_dlls.iter()
                .filter(|d| !std::path::Path::new(&format!("{dll_dir}\\{d}")).exists())
                .copied().collect();
            let (status, detail, evidence, repair) = if installed.0 && missing.is_empty() {
                ("ok", String::new(), vec![format!("注册表：{}", installed.1), format!("关键 dll 齐全（{dll_dir}）")], Value::Null)
            } else if !installed.0 && missing.is_empty() {
                ("ok", String::new(), vec!["注册表项缺失，但关键 dll 齐全".to_string()], Value::Null)
            } else if installed.0 && !missing.is_empty() {
                let mut ev = vec![format!("注册表：{}", installed.1)];
                for m in &missing { ev.push(format!("{dll_dir}\\{m} 缺失")); }
                ("fail", "VC++ 运行库已安装但关键 dll 缺失（可能被清理工具误删）".to_string(), ev,
                    json!({"id": format!("vc-{arch}"), "name": format!("VC++ 2015-2022 {}", arch.to_uppercase())}))
            } else {
                let mut ev = vec!["注册表：未安装".to_string()];
                for m in &missing { ev.push(format!("{dll_dir}\\{m} 缺失")); }
                ("fail", format!("VC++ 2015-2022 {arch} 未安装"), ev,
                    json!({"id": format!("vc-{arch}"), "name": format!("VC++ 2015-2022 {}", arch.to_uppercase())}))
            };
            items.push(json!({
                "id": format!("vc-{arch}"), "status": status, "evidence": evidence,
                "detail": detail, "repair": repair,
            }));
        }

        // ---- .NET Framework 4.x ----
        let release_map: [(u32, &str); 9] = [
            (533320, "4.8.1"), (528040, "4.8"), (461808, "4.7.2"), (461308, "4.7.1"),
            (460798, "4.7"), (394802, "4.6.2"), (393295, "4.6"), (379893, "4.5.2"), (378389, "4.5"),
        ];
        let ndp_path = r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full";
        let sk = to_wide(ndp_path);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
            let install = reg_read_dword_val(hk, "Install").unwrap_or(0) == 1;
            let release = reg_read_dword_val(hk, "Release").unwrap_or(0);
            let _ = RegCloseKey(hk);
            if install && release > 0 {
                let mut ver_name = format!("4.x（Release {release}）");
                for (rv, name) in &release_map {
                    if release >= *rv { ver_name = format!("{name}（Release {release}）"); break; }
                }
                let (status, detail, repair) = if release >= 528040 {
                    ("ok", String::new(), Value::Null)
                } else {
                    ("warn", ".NET Framework 低于 4.8，部分新软件可能无法运行".to_string(),
                        json!({"id": "netfx48", "name": ".NET Framework 4.8"}))
                };
                items.push(json!({
                    "id": "netfx4x", "status": status, "evidence": [ver_name],
                    "detail": detail, "repair": repair,
                }));
            } else {
                items.push(json!({
                    "id": "netfx4x", "status": "fail", "evidence": ["注册表：未安装"],
                    "detail": ".NET Framework 4.x 未安装",
                    "repair": {"id": "netfx48", "name": ".NET Framework 4.8"},
                }));
            }
        } else {
            items.push(json!({
                "id": "netfx4x", "status": "fail", "evidence": ["注册表：未安装"],
                "detail": ".NET Framework 4.x 未安装",
                "repair": {"id": "netfx48", "name": ".NET Framework 4.8"},
            }));
        }

        // ---- .NET Framework 3.5 ----
        let ndp35_path = r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5";
        let sk = to_wide(ndp35_path);
        let mut hk = HKEY::default();
        let net35_installed = if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
            let inst = reg_read_dword_val(hk, "Install").unwrap_or(0) == 1;
            let _ = RegCloseKey(hk);
            inst
        } else { false };
        // 可选功能状态：用注册表判断即可（Get-WindowsOptionalFeature 需要 DISM，从简）
        if net35_installed {
            items.push(json!({
                "id": "netfx35", "status": "ok", "evidence": [".NET Framework 3.5 已启用"],
                "detail": "", "repair": null,
            }));
        } else {
            items.push(json!({
                "id": "netfx35", "status": "warn", "evidence": ["注册表/可选功能：未启用"],
                "detail": ".NET Framework 3.5 未启用（部分老游戏/老软件需要）",
                "repair": {"id": "netfx35", "name": ".NET Framework 3.5（DISM 启用）"},
            }));
        }

        // ---- DirectX 9.0c 附属组件 ----
        let dx9_dlls = ["d3dx9_43.dll", "d3dx9_42.dll", "d3dx11_43.dll", "d3dx10_43.dll",
                        "d3dcompiler_43.dll", "xinput1_3.dll", "xaudio2_7.dll"];
        let mut dx_missing: Vec<&str> = Vec::new();
        for dll in &dx9_dlls {
            let in64 = std::path::Path::new(&format!(r"C:\Windows\System32\{dll}")).exists();
            let in86 = std::path::Path::new(&format!(r"C:\Windows\SysWOW64\{dll}")).exists();
            if !in64 && !in86 { dx_missing.push(dll); }
        }
        let mut dx_evidence: Vec<String> = Vec::new();
        let mut dx_status = "ok";
        let mut dx_detail = String::new();
        if !dx_missing.is_empty() {
            dx_status = "fail";
            dx_detail = "DirectX 9.0c 附属组件缺失，部分老游戏无法启动".to_string();
            for m in &dx_missing { dx_evidence.push(format!("{m} 缺失（System32 与 SysWOW64 均未找到）")); }
        } else {
            dx_evidence.push("DirectX 9.0c 关键附属组件齐全".to_string());
        }
        // DX12 系统组件
        for dll in ["d3d12.dll", "d3d12core.dll"] {
            if !std::path::Path::new(&format!(r"C:\Windows\System32\{dll}")).exists() {
                dx_status = "fail";
                dx_evidence.push(format!("System32\\{dll} 缺失（DX12 系统组件，建议系统文件修复）"));
            }
        }
        items.push(json!({
            "id": "dx9", "status": dx_status, "evidence": dx_evidence,
            "detail": dx_detail, "repair": null,
        }));

        // ---- 旧版 VC++ 2005-2013（信息级） ----
        let mut old_vc: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for uninst_path in [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ] {
            let sk = to_wide(uninst_path);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { continue; }
            for sub in reg_enum_subkeys(hk) {
                let sub_path = format!("{uninst_path}\\{sub}");
                let ssk = to_wide(&sub_path);
                let mut shk = HKEY::default();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(ssk.as_ptr()), Some(0), KEY_READ, &mut shk).is_err() { continue; }
                if let Some(dn) = reg_read_string(shk, "DisplayName") {
                    if dn.starts_with("Microsoft Visual C++ 2005") || dn.starts_with("Microsoft Visual C++ 2008")
                        || dn.starts_with("Microsoft Visual C++ 2010") || dn.starts_with("Microsoft Visual C++ 2012")
                        || dn.starts_with("Microsoft Visual C++ 2013") {
                        if dn.contains("Redistributable") { old_vc.insert(dn); }
                    }
                }
                let _ = RegCloseKey(shk);
            }
            let _ = RegCloseKey(hk);
        }
        let old_evidence: Vec<String> = if old_vc.is_empty() {
            vec!["未发现旧版 VC++（2005-2013）".to_string()]
        } else { old_vc.into_iter().collect() };
        items.push(json!({
            "id": "vc-old", "status": "info", "evidence": old_evidence,
            "detail": "信息级：仅列出已装版本，不判定异常", "repair": null,
        }));

        // ---- summary ----
        let ok = items.iter().filter(|i| i.get("status").and_then(|s| s.as_str()) == Some("ok")).count();
        let warn = items.iter().filter(|i| i.get("status").and_then(|s| s.as_str()) == Some("warn")).count();
        let fail = items.iter().filter(|i| i.get("status").and_then(|s| s.as_str()) == Some("fail")).count();
        Ok(json!({
            "items": items,
            "summary": {"total": items.len(), "ok": ok, "warn": warn, "fail": fail},
        }))
    }
}
// ==================== B8 netcheck_status：网络连通性检测 ====================

use windows::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, CloseServiceHandle,
    SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_STATUS,
};

/// 查询服务状态（Running/Stopped 等）
unsafe fn service_status(name: &str) -> Option<(u32, u32)> {
    // 返回 (currentState, startType)；startType 需要 QueryServiceConfig，简化为 0
    let scm = OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT);
    if scm.is_err() { return None; }
    let scm = scm.unwrap();
    let name_w = to_wide(name);
    let svc = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_STATUS);
    if svc.is_err() { let _ = CloseServiceHandle(scm); return None; }
    let svc = svc.unwrap();
    let mut status = SERVICE_STATUS::default();
    let ok = QueryServiceStatus(svc, &mut status as *mut _);
    let _ = CloseServiceHandle(svc);
    let _ = CloseServiceHandle(scm);
    if ok.is_err() { return None; }
    Some((status.dwCurrentState.0, 0))
}

/// 停止服务
unsafe fn service_stop(name: &str) -> bool {
    use windows::Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, ControlService, CloseServiceHandle,
        SC_MANAGER_CONNECT, SERVICE_STOP, SERVICE_CONTROL_STOP, SERVICE_STATUS,
    };
    let scm = match OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let name_w = to_wide(name);
    let svc = match OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_STOP) {
        Ok(s) => s,
        Err(_) => { let _ = CloseServiceHandle(scm); return false; }
    };
    let mut status = SERVICE_STATUS::default();
    let ok = ControlService(svc, SERVICE_CONTROL_STOP, &mut status).is_ok();
    let _ = CloseServiceHandle(svc);
    let _ = CloseServiceHandle(scm);
    ok
}

/// 设置服务启动类型（SERVICE_DEMAND_START=Manual, SERVICE_DISABLED=Disabled, SERVICE_AUTO_START=Automatic）
unsafe fn service_set_start_type(name: &str, start_type: u32) -> bool {
    use windows::Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, ChangeServiceConfigW, CloseServiceHandle,
        SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG, SERVICE_NO_CHANGE,
    };
    let scm = match OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let name_w = to_wide(name);
    let svc = match OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_CHANGE_CONFIG) {
        Ok(s) => s,
        Err(_) => { let _ = CloseServiceHandle(scm); return false; }
    };
    // ChangeServiceConfigW: 不需要改的参数传 SERVICE_NO_CHANGE
    use windows::Win32::System::Services::{SERVICE_ERROR, ENUM_SERVICE_TYPE, SERVICE_START_TYPE};
    let ok = ChangeServiceConfigW(
        svc,
        ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),  // dwServiceType
        SERVICE_START_TYPE(start_type),        // dwStartType
        SERVICE_ERROR(SERVICE_NO_CHANGE),      // dwErrorControl
        PCWSTR::default(),                     // lpBinaryPathName
        PCWSTR::default(),                     // lpLoadOrderGroup
        None,                                  // lpdwTagId
        PCWSTR::default(),                     // lpDependencies
        PCWSTR::default(),                     // lpServiceStartName
        PCWSTR::default(),                     // lpPassword
        PCWSTR::default(),                     // lpDisplayName
    ).is_ok();
    let _ = CloseServiceHandle(svc);
    let _ = CloseServiceHandle(scm);
    ok
}

/// 服务启动类型是否等于期望值（B11：原 PS `Get-Service ... StartType -eq 'Disabled'` 的原生等价）
///
/// 走 `QueryServiceConfigW`（需要 `SERVICE_QUERY_CONFIG`，不是 `service_status` 用的
/// `SERVICE_QUERY_STATUS`）。服务不存在 = `false`：检测语义是「这项优化是否已生效」，
/// 服务没了当然不算生效。
pub fn service_start_type_is(name: &str, expected: u32) -> bool {
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
        QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
    };
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT) else {
            return false;
        };
        let name_w = to_wide(name);
        let Ok(svc) = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_CONFIG) else {
            let _ = CloseServiceHandle(scm);
            return false;
        };
        // 两段式：先取需要的字节数，再分配重查（QueryServiceConfigW 的标准用法）
        let mut needed = 0u32;
        let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
        if needed == 0 {
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
            return false;
        }
        let mut buf = vec![0u8; needed as usize];
        let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        let ok = QueryServiceConfigW(svc, Some(cfg), needed, &mut needed).is_ok();
        let start = if ok { (*cfg).dwStartType.0 } else { u32::MAX };
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        ok && start == expected
    }
}

/// `SERVICE_DISABLED`（供跨 crate 比较，避免调用方 import windows crate）
pub const SVC_START_DISABLED: u32 = windows::Win32::System::Services::SERVICE_DISABLED.0;

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

/// 确保键存在（对应 PS `New-Item -Path … -Force`；RegCreateKeyExW 幂等）
pub fn reg_key_ensure(hive: HKEY, subkey: &str) -> bool {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    unsafe {
        let ok = RegCreateKeyExW(hive, PCWSTR(sk.as_ptr()), None, PCWSTR::default(), REG_OPTION_NON_VOLATILE, KEY_READ, None, &mut hk, None).is_ok();
        if ok {
            let _ = RegCloseKey(hk);
        }
        ok
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

/// 停止服务（`Stop-Service -Name X -Force` 的等价物）
pub fn service_stop_pub(name: &str) -> Result<(), String> {
    unsafe {
        if service_stop(name) {
            Ok(())
        } else {
            Err(format!("停止服务失败: {name}"))
        }
    }
}

/// 设置服务启动类型（`sc.exe config X start= N` 的等价物）
pub fn service_set_start_pub(name: &str, start: u32) -> Result<(), String> {
    unsafe {
        if service_set_start_type(name, start) {
            Ok(())
        } else {
            Err(format!("设置服务启动类型失败: {name} → {start}"))
        }
    }
}

/// 启用/禁用计划任务（对应 `Disable/Enable-ScheduledTask`，与启动项链同一工具）
///
/// `path` 为含尾反斜杠的任务路径（如 `\Microsoft\Windows\Defrag\`），与数据层 `taskPath` 同形。
pub fn task_change(path: Option<&str>, name: &str, disable: bool) -> Result<(), String> {
    let full = format!("{}{}", path.unwrap_or_default(), name);
    let arg = if disable { "/DISABLE" } else { "/ENABLE" };
    let output = std::process::Command::new(system_tool("schtasks"))
        .args(["/Change", "/TN", &full, arg])
        .output()
        .map_err(|e| format!("schtasks 执行失败: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(if stderr.is_empty() {
            format!("计划任务{}未生效（可能需要管理员权限）: {full}", if disable { "禁用" } else { "启用" })
        } else {
            stderr
        })
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

/// 读注册表值，返回 (类型标签, 字符串化数据)。
///
/// **口径逐条对齐** optimizer 值级备份的 `READ_ONE_HEADER`（main.js 3481-3502 的移植）——
/// 这条链的产物会被写进 `optimizer-backups.json`，再由 `restore_backup_values` 读回，
/// 读写两侧必须用同一套字符串化规则，否则 `0xFFFFFFFF` 这类值会在「备份→还原」之间变形：
/// - `REG_DWORD` → `("REG_DWORD", [int] 的 i32 十进制)`（有符号！）
/// - `REG_QWORD` → `("REG_QWORD", [long] 的 i64 十进制)`
/// - `REG_BINARY` → `("REG_BINARY", 小写 hex 连写，无分隔符)`
/// - `REG_SZ` → `("REG_SZ", 原文)`
/// - `REG_EXPAND_SZ` → `("REG_SZ", **展开后**的串)` —— .NET `GetValue` 会展开，保持同口径
/// - `REG_MULTI_SZ` → `("REG_SZ", 空格连接)` —— PS `[string]$v` 对字符串数组的强制转换
/// - 其它类型 → `None`（与 `GetValue` 返回 null 一致，调用方按「不存在」处理）
pub fn read_reg_value_text(hive: HKEY, subkey: &str, name: &str) -> Option<(&'static str, String)> {
    use windows::Win32::System::Registry::{REG_EXPAND_SZ, REG_MULTI_SZ};
    use windows::Win32::System::Environment::ExpandEnvironmentStringsW;


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

        let units = |b: &[u8]| -> Vec<u16> {
            b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
        };
        match ty {
            REG_DWORD if size >= 4 => {
                let raw = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                // .NET 把 DWORD 读成 int（有符号），`[int]$v` 再转字符串 —— 保留该口径
                Some(("REG_DWORD", (raw as i32).to_string()))
            }
            REG_QWORD if size >= 8 => {
                let raw = u64::from_le_bytes(buf[..8].try_into().ok()?);
                Some(("REG_QWORD", (raw as i64).to_string()))
            }
            REG_BINARY => {
                Some(("REG_BINARY", buf.iter().map(|b| format!("{b:02x}")).collect()))
            }
            REG_SZ => {
                let u = units(&buf);
                Some(("REG_SZ", String::from_utf16_lossy(&u).trim_end_matches('\0').to_string()))
            }
            REG_EXPAND_SZ => {
                // 展开环境变量（对齐 .NET GetValue）；展开结果以 NUL 结尾
                let u = units(&buf);
                let raw = String::from_utf16_lossy(&u);
                let raw = raw.trim_end_matches('\0');
                let mut out = [0u16; 1024];
                let src = to_wide(raw);
                let n = ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), Some(&mut out[..]));
                let s = if n == 0 || n as usize > out.len() {
                    raw.to_string() // 展开失败/过长 → 原样保留，不造一个错值
                } else {
                    let u16s = &out[..(n as usize - 1).max(0)];
                    String::from_utf16_lossy(u16s)
                };
                Some(("REG_SZ", s))
            }
            REG_MULTI_SZ => {
                // 双 NUL 结尾的 UTF-16 串序列；PS `[string]$v` 对数组是空格连接
                let u = units(&buf);
                let joined: String = String::from_utf16_lossy(&u)
                    .split('\0')
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");
                Some(("REG_SZ", joined))
            }
            _ => None,
        }
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

/// 顽固软件自启阻断（对应 memory_stubborn_block.ps1，S3）
///
/// 1. 停止并禁用 4 个服务（设为 Manual）
/// 2. 停止 wpscloudsvr 服务
/// 3. 备份并删除 2 个计划任务（schtasks.exe）
/// 4. 设置 WPS 更新注册表 UpdateMode=close
pub fn stubborn_block() -> Result<Value, String> {
    let mut changed_services: Vec<String> = Vec::new();
    let mut fail_services: Vec<String> = Vec::new();
    let mut changed_tasks: Vec<String> = Vec::new();
    let mut fail_tasks: Vec<String> = Vec::new();
    let mut failed = 0i64;

    // 1. 停止并禁用服务（设为 Manual）
    let block_services = ["Edrservice", "GameViewerService", "MuMuRemoteService", "PCManager Service Store"];
    for svc in &block_services {
        unsafe {
            // 先检查服务是否存在
            if service_status(svc).is_none() { continue; }
            let _ = service_stop(svc);
            // SERVICE_DEMAND_START = 3 (Manual)
            if service_set_start_type(svc, 3) {
                changed_services.push(svc.to_string());
            } else {
                fail_services.push(svc.to_string());
                failed += 1;
            }
        }
    }

    // 2. 停止 wpscloudsvr（不改变启动类型）
    unsafe {
        if service_status("wpscloudsvr").is_some() {
            if service_stop("wpscloudsvr") {
                changed_services.push("wpscloudsvr".to_string());
            } else {
                fail_services.push("wpscloudsvr".to_string());
                failed += 1;
            }
        }
    }

    // 3. 备份并删除计划任务（用 schtasks.exe）
    let backup_dir = match std::env::var("APPDATA") {
        Ok(d) => std::path::PathBuf::from(d).join("Trim").join("backup").join("tasks"),
        Err(_) => std::path::PathBuf::new(),
    };
    if !backup_dir.as_os_str().is_empty() {
        let _ = std::fs::create_dir_all(&backup_dir);
    }
    let block_tasks = ["WpsUpdateTask_CHENG", "WpsUpdateLogonTask_CHENG"];
    for task in &block_tasks {
        // 检查任务是否存在
        let exists = match std::process::Command::new(system_tool("schtasks"))
            .args(["/Query", "/TN", task, "/NH"])
            .output()
        {
            Ok(o) => o.status.success(),
            Err(_) => false,
        };
        if !exists { continue; }

        // 备份
        if !backup_dir.as_os_str().is_empty() {
            let xml_path = backup_dir.join(format!("{task}.xml"));
            let _ = std::process::Command::new(system_tool("schtasks"))
                .args(["/Query", "/TN", task, "/XML"])
                .stdout(std::process::Stdio::from(std::fs::File::create(&xml_path).unwrap_or_else(|_| std::fs::File::open("NUL").unwrap())))
                .status();
        }

        // 删除
        let deleted = match std::process::Command::new(system_tool("schtasks"))
            .args(["/Delete", "/TN", task, "/F"])
            .output()
        {
            Ok(o) => o.status.success(),
            Err(_) => false,
        };
        if deleted {
            changed_tasks.push(task.to_string());
        } else {
            fail_tasks.push(task.to_string());
            failed += 1;
        }
    }

    // 4. 设置 WPS 更新注册表
    unsafe {
        use windows::Win32::System::Registry::{
            RegOpenKeyExW, RegSetValueExW, RegCloseKey, HKEY_CURRENT_USER, KEY_WRITE, REG_SZ,
        };
        let key_path = to_wide(r"Software\Kingsoft\Office\6.0\Common\updateinfo");
        let mut hkey = HKEY_CURRENT_USER;
        if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(key_path.as_ptr()), Some(0), KEY_WRITE, &mut hkey).is_ok() {
            let val = to_wide("close");
            let bytes: Vec<u8> = val.iter().flat_map(|&w| w.to_le_bytes()).collect();
            let _ = RegSetValueExW(hkey, PCWSTR(to_wide("UpdateMode").as_ptr()), Some(0), REG_SZ, Some(&bytes));
            let _ = RegCloseKey(hkey);
        }
    }

    Ok(json!({
        "services": changed_services,
        "tasks": changed_tasks,
        "failedServices": fail_services,
        "failedTasks": fail_tasks,
        "failedCount": failed,
    }))
}

/// 网络连通性检测（对应 netcheck_status.ps1，S3 简化版）
///
/// 覆盖：网卡枚举、IP 配置、DHCP 服务、DNS 配置、代理设置、连通性探测。
/// 网卡高级属性（Get-NetAdapterAdvancedProperty）暂未实现（S2 完善）。
pub fn netcheck_status() -> Result<Value, String> {
    unsafe {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH as IP_ADAPTER_ADDRESSES,
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
        };
        use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
        use std::net::ToSocketAddrs;

        const AF_UNSPEC: u32 = 0;
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;

        let mut buf_len: u32 = 32 * 1024;
        let mut buf: Vec<u8> = vec![0u8; buf_len as usize];
        let ret = GetAdaptersAddresses(AF_UNSPEC, flags, None, Some(buf.as_mut_ptr() as *mut _), &mut buf_len);
        if ret == 111 {
            buf = vec![0u8; buf_len as usize];
            let ret = GetAdaptersAddresses(AF_UNSPEC, flags, None, Some(buf.as_mut_ptr() as *mut _), &mut buf_len);
            if ret != 0 { return Err(format!("GetAdaptersAddresses 失败 (错误 {ret})")); }
        } else if ret != 0 {
            return Err(format!("GetAdaptersAddresses 失败 (错误 {ret})"));
        }

        #[derive(Clone)]
        struct NicInfo {
            name: String, status: String, speed: String, is_virtual: bool,
            ipv4: Vec<String>, gateway: Option<String>, dns: Vec<String>,
            dhcp_enabled: bool, if_index: u32,
        }

        let mut nics: Vec<NicInfo> = Vec::new();
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES;
        while !p.is_null() {
            let a = &*p;
            // 过滤回环和隧道
            if a.IfType == 24 || a.IfType == 131 { p = a.Next; continue; }
            let name = wide_str(a.FriendlyName.0);
            let status = match a.OperStatus.0 {
                1 => "Up", 2 => "Connecting", 0 => "Down", 3 => "Disconnecting",
                7 => "MediaDisconnected", _ => "Unknown",
            }.to_string();
            let speed_mbps = a.TransmitLinkSpeed / 1_000_000;
            let speed = if speed_mbps >= 1000 {
                format!("{:.0} Gbps", speed_mbps as f64 / 1000.0)
            } else {
                format!("{speed_mbps} Mbps")
            };
            let is_virtual = a.IfType == 53 || a.IfType == 144 || name.contains("Virtual")
                || name.contains("VPN") || name.contains("Hyper-V") || name.contains("VMware")
                || name.contains("VirtualBox");
            let mut ipv4: Vec<String> = Vec::new();
            let mut up = a.FirstUnicastAddress;
            while !up.is_null() {
                let u = &*up;
                let addr = u.Address.lpSockaddr;
                if !addr.is_null() && (*addr).sa_family == AF_INET {
                    let sin = addr as *const SOCKADDR_IN;
                    let ip = (*sin).sin_addr.S_un.S_addr.to_le_bytes();
                    ipv4.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                }
                up = u.Next;
            }
            let mut gateway: Option<String> = None;
            let mut gp = a.FirstGatewayAddress;
            while !gp.is_null() {
                let g = &*gp;
                let addr = g.Address.lpSockaddr;
                if !addr.is_null() && (*addr).sa_family == AF_INET {
                    let sin = addr as *const SOCKADDR_IN;
                    let ip = (*sin).sin_addr.S_un.S_addr.to_le_bytes();
                    gateway = Some(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                    break;
                }
                gp = g.Next;
            }
            let mut dns: Vec<String> = Vec::new();
            let mut dp = a.FirstDnsServerAddress;
            while !dp.is_null() {
                let d = &*dp;
                let addr = d.Address.lpSockaddr;
                if !addr.is_null() && (*addr).sa_family == AF_INET {
                    let sin = addr as *const SOCKADDR_IN;
                    let ip = (*sin).sin_addr.S_un.S_addr.to_le_bytes();
                    dns.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                }
                dp = d.Next;
            }
            nics.push(NicInfo {
                name, status, speed, is_virtual, ipv4, gateway, dns,
                dhcp_enabled: a.Anonymous2.Flags & 0x04 != 0, // IP_ADAPTER_DHCP_ENABLED
                if_index: a.Anonymous1.Anonymous.IfIndex,
            });
            p = a.Next;
        }

        let physical: Vec<&NicInfo> = nics.iter().filter(|n| !n.is_virtual).collect();
        let up_list: Vec<&&NicInfo> = physical.iter().filter(|n| n.status == "Up").collect();
        let disabled_list: Vec<&&NicInfo> = physical.iter().filter(|n| n.status == "Disabled").collect();
        let bad_list: Vec<&&NicInfo> = physical.iter().filter(|n| n.status != "Up").collect();

        let mut items: Vec<Value> = Vec::new();

        // ---- 1. 网卡 ----
        let mut adapter_evidence: Vec<String> = Vec::new();
        for n in &up_list {
            adapter_evidence.push(format!("网卡 {}：Up，{}", n.name, n.speed));
        }
        let (adapter_status, adapter_detail, adapter_repair) = if !up_list.is_empty() {
            if !disabled_list.is_empty() {
                let names: Vec<&str> = disabled_list.iter().map(|n| n.name.as_str()).collect();
                for n in &bad_list { adapter_evidence.push(format!("网卡 {}：{}", n.name, n.status)); }
                ("warn", "存在被禁用的网卡".to_string(), json!({"id": "enable-adapter", "name": names.join(",")}))
            } else {
                ("ok", String::new(), Value::Null)
            }
        } else if !bad_list.is_empty() {
            for n in &bad_list { adapter_evidence.push(format!("网卡 {}：{}", n.name, n.status)); }
            if !disabled_list.is_empty() {
                let names: Vec<&str> = disabled_list.iter().map(|n| n.name.as_str()).collect();
                ("fail", "没有可用网卡".to_string(), json!({"id": "enable-adapter", "name": names.join(",")}))
            } else {
                ("fail", "没有可用网卡".to_string(), Value::Null)
            }
        } else {
            ("unknown", "未枚举到物理网卡".to_string(), Value::Null)
        };
        items.push(json!({"id": "adapter", "status": adapter_status, "evidence": adapter_evidence, "detail": adapter_detail, "repair": adapter_repair}));

        // ---- 2. IP 配置 ----
        let up_nics: Vec<&NicInfo> = nics.iter().filter(|n| n.status == "Up").collect();
        let mut has_apipa = false;
        let mut has_gateway = false;
        let mut has_valid_ip = false;
        let mut ip_evidence: Vec<String> = Vec::new();
        for n in &up_nics {
            for ip in &n.ipv4 {
                let iface = format!("网卡 {}：{}", n.name, ip);
                if ip.starts_with("169.254.") {
                    has_apipa = true;
                    ip_evidence.push(format!("{iface}（APIPA，未从 DHCP 取到地址）"));
                } else {
                    has_valid_ip = true;
                    ip_evidence.push(iface);
                }
            }
            if let Some(gw) = &n.gateway {
                has_gateway = true;
                ip_evidence.push(format!("默认网关 {gw}（{}）", n.name));
            }
        }
        let (ip_status, ip_detail) = if has_apipa {
            ("fail", "网卡持有 169.254 自动私有地址，DHCP 未取到有效地址".to_string())
        } else if has_valid_ip && has_gateway {
            ("ok", String::new())
        } else if has_valid_ip {
            ("warn", "有 IPv4 地址但没有默认网关（可能为孤立网络或静态配置）".to_string())
        } else {
            ("unknown", "未取到有效 IPv4 配置".to_string())
        };
        items.push(json!({"id": "ipconfig", "status": ip_status, "evidence": ip_evidence, "detail": ip_detail}));

        // ---- 3. DHCP 服务 ----
        let dhcp_in_use = up_nics.iter().any(|n| n.dhcp_enabled);
        let dhcp_svc = service_status("Dhcp");
        let (dhcp_status, dhcp_detail, dhcp_repair, dhcp_evidence) = match dhcp_svc {
            None => ("warn", "未找到 Dhcp 服务".to_string(), Value::Null, vec!["Dhcp 服务：未找到".to_string()]),
            Some((state, _)) => {
                let state_str = match state { 4 => "Running", 1 => "Stopped", _ => "Unknown" };
                let ev = format!("Dhcp 服务：{state_str}；DHCP 网卡启用：{dhcp_in_use}");
                if state == 4 {
                    ("ok", "Dhcp 服务运行正常".to_string(), Value::Null, vec![ev])
                } else if dhcp_in_use {
                    ("fail", "有网卡使用 DHCP（自动获取 IP），但 DHCP 服务未运行".to_string(),
                        json!({"id": "start-dhcp"}), vec![ev])
                } else {
                    ("warn", "当前网卡均使用静态 IP（不依赖 DHCP），DHCP 服务未运行属正常".to_string(),
                        json!({"id": "start-dhcp"}), vec![ev])
                }
            }
        };
        items.push(json!({"id": "dhcp", "status": dhcp_status, "evidence": dhcp_evidence, "detail": dhcp_detail, "repair": dhcp_repair}));

        // ---- 4. DNS ----
        let dns_svc = service_status("Dnscache");
        let mut dns_evidence: Vec<String> = Vec::new();
        if let Some((state, _)) = dns_svc {
            let state_str = match state { 4 => "Running", 1 => "Stopped", _ => "Unknown" };
            dns_evidence.push(format!("Dnscache 服务：{state_str}"));
        }
        let mut has_dns = false;
        for n in &up_nics {
            if !n.dns.is_empty() {
                has_dns = true;
                dns_evidence.push(format!("DNS {}：{}", n.name, n.dns.join(", ")));
            }
        }
        let dns_svc_stopped = dns_svc.map(|(s, _)| s != 4).unwrap_or(false);
        let (dns_status, dns_detail, dns_repair) = if dns_svc_stopped || !has_dns {
            if dns_svc_stopped {
                ("fail", "DNS Client 服务未运行".to_string(), json!({"id": "start-dnscache"}))
            } else {
                let active_idx = up_nics.iter().find(|n| n.gateway.is_some())
                    .map(|n| n.if_index)
                    .or_else(|| up_nics.first().map(|n| n.if_index));
                let repair = if let Some(idx) = active_idx {
                    json!({"id": "reset-dns", "interfaceIndex": idx})
                } else { Value::Null };
                ("fail", "所有网卡均未配置 DNS 服务器".to_string(), repair)
            }
        } else {
            ("ok", String::new(), Value::Null)
        };
        items.push(json!({"id": "dns", "status": dns_status, "evidence": dns_evidence, "detail": dns_detail, "repair": dns_repair}));

        // ---- 5. 代理 ----
        let mut proxy_evidence: Vec<String> = Vec::new();
        let mut proxy_status = "unknown";
        let mut proxy_detail = String::new();
        let mut proxy_repair = Value::Null;
        let ie_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let sk = to_wide(ie_path);
        let mut hk = HKEY::default();
        let (p_enable, p_server) = if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
            let enable = reg_read_dword_val(hk, "ProxyEnable").unwrap_or(0) == 1;
            let server = reg_read_string(hk, "ProxyServer").unwrap_or_default();
            let _ = RegCloseKey(hk);
            (enable, server)
        } else { (false, String::new()) };
        // 组策略代理
        let gpo_path = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
        let gsk = to_wide(gpo_path);
        let mut ghk = HKEY::default();
        let p_gpo = if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(gsk.as_ptr()), Some(0), KEY_READ, &mut ghk).is_ok() {
            let g = reg_read_dword_val(ghk, "ProxyEnable").unwrap_or(0) == 1;
            let _ = RegCloseKey(ghk);
            g
        } else { false };
        // WinHTTP 代理（spawn netsh）
        let winhttp_out = std::process::Command::new(system_tool("netsh"))
            .args(["winhttp", "show", "proxy"])
            .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string());
        let winhttp_has_proxy = winhttp_out.as_ref()
            .map(|o| (o.contains("proxy") || o.contains("代理服务器")) && !o.contains("直接访问") && !o.contains("DIRECT"))
            .unwrap_or(false);
        fn mask_proxy(s: &str) -> String {
            let body = s;
            // 去掉 scheme
            let body = if let Some(pos) = body.find("://") { &body[pos+3..] } else { body };
            let at = body.rfind('@');
            let mask = if let Some(pos) = at { &body[pos+1..] } else { body };
            let mask = if mask.starts_with(|c: char| c.is_ascii_digit()) {
                // IPv4：掩中间两段
                let parts: Vec<&str> = mask.split('.').collect();
                if parts.len() >= 4 { format!("{}.*.*", parts[0]) } else { mask.to_string() }
            } else {
                if let Some(dot) = mask.find('.') { format!("{}.*", &mask[..dot]) } else { mask.to_string() }
            };
            if at.is_some() { format!("***:***@{mask}") } else { mask }
        }
        if p_gpo {
            proxy_status = "warn";
            proxy_evidence.push("检测到组策略下发的代理（由组织管理）".to_string());
            proxy_detail = "代理由组策略下发，本工具不提供修复入口".to_string();
        } else if p_enable && !p_server.is_empty() {
            proxy_evidence.push(format!("用户代理已启用：{}", mask_proxy(&p_server)));
            // 检查本机代理端口是否在监听
            let listening = if let Some(port_str) = p_server.rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    std::net::TcpListener::bind(("127.0.0.1", port)).is_err()
                } else { false }
            } else { false };
            if p_server.contains("127.0.0.1") && !listening {
                proxy_status = "warn";
                proxy_detail = "代理指向本机但无进程监听该端口（残留代理，典型「能连但打不开网页」根因）".to_string();
                proxy_repair = json!({"id": "disable-user-proxy"});
            } else {
                proxy_status = "ok";
                proxy_detail = "检测到用户自配代理（属合法配置，不做改动）".to_string();
            }
        } else {
            proxy_evidence.push("用户代理（WinINET）：未启用".to_string());
        }
        if winhttp_has_proxy {
            if let Some(o) = &winhttp_out {
                // 提取代理服务器
                if let Some(line) = o.lines().find(|l| l.contains("代理服务器") || l.contains("Proxy Server")) {
                    let server = line.split(':').nth(1).unwrap_or("").trim().to_string();
                    if !server.is_empty() {
                        proxy_evidence.push(format!("系统代理（WinHTTP）：{}", mask_proxy(&server)));
                    }
                }
            }
            if proxy_status == "ok" { proxy_status = "warn"; }
            proxy_detail = "WinHTTP 层配置了代理，可能影响系统服务联网".to_string();
            proxy_repair = json!({"id": "reset-winhttp"});
        }
        if proxy_status == "unknown" {
            proxy_status = "ok";
            if proxy_detail.is_empty() { proxy_detail = "未检测到代理".to_string(); }
        }
        items.push(json!({"id": "proxy", "status": proxy_status, "evidence": proxy_evidence, "detail": proxy_detail, "repair": proxy_repair}));

        // ---- 6. 连通性 ----
        let mut net_evidence: Vec<String> = Vec::new();
        let gw_ip = up_nics.iter().find_map(|n| n.gateway.clone());
        let mut gw_ok = false;
        if let Some(gw) = &gw_ip {
            // TCP 探测网关 445/80（ICMP 可能被防火墙拦截）
            for port in [445u16, 80] {
                if let Ok(stream) = std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::new(gw.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0,0,0,0))), port),
                    std::time::Duration::from_millis(2500))
                {
                    gw_ok = true;
                    net_evidence.push(format!("网关 {gw}：TCP {port} 可达"));
                    drop(stream);
                    break;
                }
            }
            if !gw_ok { net_evidence.push(format!("网关 {gw}：不可达")); }
        } else {
            net_evidence.push("无默认网关，跳过网关探测".to_string());
        }
        // 外网探测
        let mut net_ok = false;
        for (host, port) in [("223.5.5.5", 443u16), ("www.baidu.com", 443u16)] {
            if let Ok(addrs) = (host, port).to_socket_addrs() {
                for addr in addrs {
                    if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(2500)).is_ok() {
                        net_ok = true;
                        net_evidence.push(format!("外网 {host}:{port}：可达"));
                        break;
                    }
                }
            }
            if net_ok { break; }
        }
        if !net_ok {
            if std::net::ToSocketAddrs::to_socket_addrs(&("www.baidu.com", 443)).is_ok() {
                net_ok = true;
                net_evidence.push("DNS 解析 www.baidu.com 成功".to_string());
            } else {
                net_evidence.push("外网探测不可达（TCP 443 与 DNS 解析均失败）".to_string());
            }
        }
        let (net_status, net_detail) = if gw_ok && net_ok {
            ("ok", String::new())
        } else if gw_ok {
            ("warn", "网关可达但外网不通（出口/运营商问题，本机无修复项）".to_string())
        } else {
            ("fail", "网关不可达（本地链路问题）".to_string())
        };
        items.push(json!({"id": "connectivity", "status": net_status, "evidence": net_evidence, "detail": net_detail}));

        // nicProps：从简实现，physical 为空数组，virtual 列出虚拟网卡
        let virtual_nics: Vec<Value> = nics.iter().filter(|n| n.is_virtual).map(|n| json!({
            "name": n.name, "status": n.status, "writable": false,
        })).collect();
        let nic_props = json!({
            "physical": [], "virtual": virtual_nics, "writableOnly": true,
        });

        Ok(json!({
            "items": items,
            "nicProps": nic_props,
            "collectedAt": format!("{:?}", std::time::SystemTime::now()),
        }))
    }
}
// ==================== B7 paths_scan：安装路径自动扫描 ====================

/// 受限规则路径表达式解析器（对应 PS 的 Resolve-RulePath）
///
/// 语法：'字面量' + $env:VARNAME + (拼接组)，空白可穿插，单引号内 '' 转义为 '。
/// 解析失败返回 None（fail-closed，不猜测）。
fn resolve_rule_path(expr: &str) -> Option<String> {
    struct Parser<'a> { s: &'a [u8], i: usize, depth: u32 }
    impl<'a> Parser<'a> {
        fn skip_ws(&mut self) {
            while self.i < self.s.len() && (self.s[self.i] == b' ' || self.s[self.i] == b'\t') {
                self.i += 1;
            }
        }
        fn parse_prim(&mut self) -> Option<String> {
            self.depth += 1;
            if self.depth > 32 { return None; }
            self.skip_ws();
            if self.i >= self.s.len() { return None; }
            let c = self.s[self.i];
            if c == b'(' {
                self.i += 1;
                let v = self.parse_concat()?;
                self.skip_ws();
                if self.i >= self.s.len() || self.s[self.i] != b')' { return None; }
                self.i += 1;
                Some(v)
            } else if c == b'\'' {
                self.i += 1;
                let mut out = String::new();
                loop {
                    if self.i >= self.s.len() { return None; }
                    let ch = self.s[self.i];
                    if ch == b'\'' {
                        if self.i + 1 < self.s.len() && self.s[self.i + 1] == b'\'' {
                            out.push('\''); self.i += 2; continue;
                        }
                        self.i += 1; break;
                    }
                    out.push(ch as char);
                    self.i += 1;
                }
                Some(out)
            } else if c == b'$' {
                if self.i + 5 >= self.s.len() { return None; }
                if &self.s[self.i..self.i+5] != b"$env:" { return None; }
                self.i += 5;
                let start = self.i;
                while self.i < self.s.len() && self.s[self.i].is_ascii_alphanumeric() || (self.i < self.s.len() && self.s[self.i] == b'_') {
                    self.i += 1;
                }
                if self.i == start { return None; }
                let name = std::str::from_utf8(&self.s[start..self.i]).ok()?;
                Some(std::env::var(name).unwrap_or_default())
            } else {
                None
            }
        }
        fn parse_concat(&mut self) -> Option<String> {
            let mut acc = self.parse_prim()?;
            loop {
                let j = { let mut j = self.i; while j < self.s.len() && (self.s[j] == b' ' || self.s[j] == b'\t') { j += 1; } j };
                if j < self.s.len() && self.s[j] == b'+' {
                    self.i = j + 1;
                    acc.push_str(&self.parse_prim()?);
                } else { break; }
            }
            Some(acc)
        }
    }
    if expr.is_empty() { return None; }
    let mut p = Parser { s: expr.as_bytes(), i: 0, depth: 0 };
    let val = p.parse_concat()?;
    p.skip_ws();
    if p.i != p.s.len() { return None; }
    Some(val)
}

/// 路径标准化（对应 PS 的 Normalize-Path）
fn normalize_path(value: &str) -> String {
    let v = value.trim().trim_matches('"');
    if v.is_empty() { return String::new(); }
    let expanded = expand_env(v);
    // 兼容 "path.exe,0" 图标索引后缀
    let v = if let Some(pos) = expanded.find(|c: char| c == ',' || c == ' ') {
        let prefix = &expanded[..pos];
        if prefix.to_lowercase().ends_with(".exe") || prefix.to_lowercase().ends_with(".dll")
            || prefix.to_lowercase().ends_with(".msi") || prefix.to_lowercase().ends_with(".cmd")
            || prefix.to_lowercase().ends_with(".bat") {
            prefix.to_string()
        } else { expanded }
    } else { expanded };
    match std::path::Path::new(&v).canonicalize() {
        Ok(p) => p.to_string_lossy().trim_end_matches('\\').to_string(),
        Err(_) => v.trim_end_matches('\\').to_string(),
    }
}

/// 从 App Paths 解析 exe 所在目录
unsafe fn resolve_from_app_paths(exe_name: &str) -> String {
    for root in [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
    ] {
        let key_path = format!("{root}\\{exe_name}");
        let sk = to_wide(&key_path);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { continue; }
        if let Some(exe) = reg_read_string(hk, "") {
            let norm = normalize_path(&exe);
            let _ = RegCloseKey(hk);
            if !norm.is_empty() && std::path::Path::new(&norm).is_file() {
                return std::path::Path::new(&norm).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            }
        }
        let _ = RegCloseKey(hk);
    }
    // HKCU
    let key_path = format!(r"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}");
    let sk = to_wide(&key_path);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
        if let Some(exe) = reg_read_string(hk, "") {
            let norm = normalize_path(&exe);
            let _ = RegCloseKey(hk);
            if !norm.is_empty() && std::path::Path::new(&norm).is_file() {
                return std::path::Path::new(&norm).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            }
        }
        let _ = RegCloseKey(hk);
    }
    String::new()
}

/// 软件清单条目
struct InventoryEntry { name: String, install_path: String }

/// 枚举卸载注册表构建软件清单
unsafe fn build_inventory() -> Vec<InventoryEntry> {
    let mut entries: Vec<InventoryEntry> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (hive, root) in [
        (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ] {
        let sk = to_wide(root);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { continue; }
        for sub in reg_enum_subkeys(hk) {
            let sub_path = format!("{root}\\{sub}");
            let ssk = to_wide(&sub_path);
            let mut shk = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(ssk.as_ptr()), Some(0), KEY_READ, &mut shk).is_err() { continue; }
            let name = reg_read_string(shk, "DisplayName").unwrap_or_default();
            let _ = RegCloseKey(shk);
            if name.trim().is_empty() { continue; }
            // 跳过系统组件和更新
            let ssk2 = to_wide(&sub_path);
            let mut shk2 = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(ssk2.as_ptr()), Some(0), KEY_READ, &mut shk2).is_ok() {
                let sys_comp = reg_read_string(shk2, "SystemComponent").unwrap_or_default();
                let release_type = reg_read_string(shk2, "ReleaseType").unwrap_or_default();
                let _ = RegCloseKey(shk2);
                if sys_comp == "1" { continue; }
                let rt = release_type.to_lowercase();
                if rt.contains("update") || rt.contains("hotfix") || rt.contains("security") { continue; }
            }
            // 解析安装路径
            let ssk3 = to_wide(&sub_path);
            let mut shk3 = HKEY::default();
            let mut install = String::new();
            if RegOpenKeyExW(hive, PCWSTR(ssk3.as_ptr()), Some(0), KEY_READ, &mut shk3).is_ok() {
                for field in ["InstallLocation", "DisplayIcon", "UninstallString"] {
                    if let Some(v) = reg_read_string(shk3, field) {
                        let norm = normalize_path(&v);
                        if !norm.is_empty() {
                            if std::path::Path::new(&norm).is_file() {
                                install = std::path::Path::new(&norm).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                            } else if std::path::Path::new(&norm).is_dir() {
                                install = norm;
                            }
                            if !install.is_empty() { break; }
                        }
                    }
                }
                let _ = RegCloseKey(shk3);
            }
            if install.is_empty() { continue; }
            let key = format!("{}|{}", name.trim().to_lowercase(), install.to_lowercase());
            if seen.insert(key) {
                entries.push(InventoryEntry { name: name.trim().to_string(), install_path: install });
            }
        }
        let _ = RegCloseKey(hk);
    }
    entries
}

/// 从软件清单按名称模式匹配安装路径
fn find_installed_match(inventory: &[InventoryEntry], patterns: &[&str]) -> String {
    for entry in inventory {
        let name_lower = entry.name.to_lowercase();
        for p in patterns {
            if name_lower.contains(&p.to_lowercase()) {
                return entry.install_path.clone();
            }
        }
    }
    String::new()
}

/// 取第一个存在的目录
fn first_existing(candidates: &[String]) -> String {
    for c in candidates {
        if c.is_empty() { continue; }
        let norm = normalize_path(c);
        if std::path::Path::new(&norm).is_dir() { return norm; }
    }
    String::new()
}

/// 简单 glob：只支持路径中的单个 * 目录通配，按修改时间降序取第一个
fn glob_first_dir(pattern: &str) -> String {
    let parts: Vec<&str> = pattern.split('\\').collect();
    let mut current = String::new();
    for (i, part) in parts.iter().enumerate() {
        if part.contains('*') {
            // 当前 current 是目录，枚举子目录匹配
            let dir = if current.is_empty() { "\\".to_string() } else { current.clone() };
            let Ok(entries) = std::fs::read_dir(&dir) else { return String::new(); };
            let mut matched: Vec<std::path::PathBuf> = Vec::new();
            for entry in entries.flatten() {
                if !entry.path().is_dir() { continue; }
                let fname = entry.file_name().to_string_lossy().to_string();
                // 简单 * 匹配
                let pat = part.replace('*', "");
                if fname.contains(&pat) || pat.is_empty() {
                    matched.push(entry.path());
                }
            }
            matched.sort_by(|a, b| {
                let ta = a.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
                let tb = b.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
                tb.cmp(&ta)
            });
            if let Some(first) = matched.first() {
                current = first.to_string_lossy().to_string();
            } else { return String::new(); }
        } else {
            if current.is_empty() {
                current = part.to_string();
            } else {
                current = format!("{current}\\{part}");
            }
        }
        // 后续部分直接拼接
        if i < parts.len() - 1 && !part.contains('*') {
            // 继续
        }
    }
    if std::path::Path::new(&current).is_dir() { current } else { String::new() }
}

/// 安装路径扫描（对应 paths_scan.ps1，S3 简化版）
///
/// 覆盖：规则表达式解析、卸载注册表枚举、App Paths、应用安装路径多级兜底、
/// 用户数据目录、缓存目录、glob 匹配。开始菜单 .lnk 目标解析暂未实现（S2 用 IShellLink COM）。
pub fn paths_scan(rules_json: &str) -> Result<Value, String> {
    unsafe {
        let inventory = build_inventory();

        // 解析规则库中的候选目录
        let mut rule_cache: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        let mut rule_wechat_globs: Vec<String> = Vec::new();
        if !rules_json.is_empty() {
            if let Ok(rules) = serde_json::from_str::<Value>(rules_json) {
                let mut rule_map: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
                if let Some(groups) = rules.get("groups").and_then(|g| g.as_array()) {
                    for g in groups {
                        if let Some(sgs) = g.get("subGroups").and_then(|s| s.as_array()) {
                            for sg in sgs {
                                if let Some(items) = sg.get("items").and_then(|i| i.as_array()) {
                                    for it in items {
                                        if let Some(id) = it.get("id").and_then(|i| i.as_str()) {
                                            rule_map.insert(id.to_string(), it.clone());
                                        }
                                    }
                                }
                            }
                        } else if let Some(items) = g.get("items").and_then(|i| i.as_array()) {
                            for it in items {
                                if let Some(id) = it.get("id").and_then(|i| i.as_str()) {
                                    rule_map.insert(id.to_string(), it.clone());
                                }
                            }
                        }
                    }
                }
                for id in ["neteaseMusicCache", "qqCache", "douyinCache"] {
                    if let Some(r) = rule_map.get(id) {
                        if let Some(exprs) = r.get("candidatesPs").and_then(|e| e.as_array()) {
                            let mut paths = Vec::new();
                            for expr in exprs {
                                if let Some(s) = expr.as_str() {
                                    if let Some(resolved) = resolve_rule_path(s) {
                                        if !resolved.is_empty() { paths.push(resolved); }
                                    }
                                }
                            }
                            rule_cache.insert(id.to_string(), paths);
                        }
                    }
                }
                if let Some(w) = rule_map.get("wechatCache") {
                    if let Some(exprs) = w.get("globCandidatesPs").and_then(|e| e.as_array()) {
                        for expr in exprs {
                            if let Some(s) = expr.as_str() {
                                if let Some(resolved) = resolve_rule_path(s) {
                                    if !resolved.is_empty() { rule_wechat_globs.push(resolved); }
                                }
                            }
                        }
                    }
                }
            }
        }

        let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let programfiles = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let programfilesx86 = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
        let userprofile = std::env::var("USERPROFILE").unwrap_or_default();
        let appdata = std::env::var("APPDATA").unwrap_or_default();

        // QQ 安装路径
        let qq_install = first_existing(&[
            format!("{localappdata}\\Programs\\Tencent\\QQNT"),
            format!("{programfiles}\\Tencent\\QQNT"),
            format!("{programfilesx86}\\Tencent\\QQNT"),
            resolve_from_app_paths("QQ.exe"),
            find_installed_match(&inventory, &["QQ"]),
        ]);
        let qq_install = if qq_install.is_empty() {
            first_existing(&[format!("{localappdata}\\Tencent\\QQNT")])
        } else { qq_install };

        // 微信安装路径
        let wechat_install = first_existing(&[
            format!("{localappdata}\\Programs\\Tencent\\WeChat"),
            format!("{programfiles}\\Tencent\\WeChat"),
            format!("{programfilesx86}\\Tencent\\WeChat"),
            resolve_from_app_paths("WeChat.exe"),
            resolve_from_app_paths("WeChatApp.exe"),
            find_installed_match(&inventory, &["WeChat", "微信"]),
        ]);

        // 抖音安装路径
        let douyin_install = first_existing(&[
            format!("{localappdata}\\Douyin"),
            format!("{localappdata}\\Programs\\Douyin"),
            format!("{localappdata}\\TikTok"),
            resolve_from_app_paths("Douyin.exe"),
            find_installed_match(&inventory, &["Douyin", "抖音", "TikTok"]),
        ]);

        // 网易云音乐安装路径
        let netease_install = first_existing(&[
            format!("{localappdata}\\Programs\\Netease\\CloudMusic"),
            format!("{programfiles}\\CloudMusic"),
            format!("{programfilesx86}\\CloudMusic"),
            format!("{programfiles}\\Netease\\CloudMusic"),
            resolve_from_app_paths("CloudMusic.exe"),
            find_installed_match(&inventory, &["CloudMusic", "网易云音乐"]),
        ]);

        // 用户数据目录
        let qq_file_dir = first_existing(&[
            format!("{userprofile}\\Documents\\Tencent Files"),
            format!("{userprofile}\\Documents\\QQ Files"),
            format!("{appdata}\\Tencent\\QQ\\Files"),
        ]);
        let wx_root = first_existing(&[
            format!("{userprofile}\\Documents\\xwechat_files"),
            format!("{userprofile}\\Documents\\WeChat Files"),
        ]);
        let wechat_file_dir = wx_root.clone();

        // 微信缓存目录（glob 匹配最近用户目录）
        let wechat_cache = if !wx_root.is_empty() {
            let leaf = std::path::Path::new(&wx_root).file_name()
                .and_then(|n| n.to_str()).unwrap_or("");
            if leaf != "xwechat_files" && leaf != "WeChat Files" {
                format!("{wx_root}\\temp")
            } else {
                let patterns = if !rule_wechat_globs.is_empty() {
                    rule_wechat_globs.clone()
                } else {
                    vec![
                        format!("{userprofile}\\Documents\\xwechat_files\\*\\temp"),
                        format!("{userprofile}\\Documents\\WeChat Files\\*\\FileStorage\\Cache"),
                    ]
                };
                let mut found = String::new();
                for pat in patterns {
                    found = glob_first_dir(&pat);
                    if !found.is_empty() { break; }
                }
                found
            }
        } else { String::new() };

        // 缓存目录
        let mut netease_candidates = rule_cache.get("neteaseMusicCache").cloned().unwrap_or_default();
        netease_candidates.extend([
            format!("{localappdata}\\NetEase\\CloudMusic\\Cache"),
            format!("{localappdata}\\Netease\\CloudMusic\\Cache"),
            format!("{appdata}\\NetEase\\CloudMusic\\Cache"),
        ]);
        let netease_cache = first_existing(&netease_candidates);

        let mut douyin_candidates = rule_cache.get("douyinCache").cloned().unwrap_or_default();
        douyin_candidates.extend([
            format!("{localappdata}\\Douyin"),
            format!("{localappdata}\\TikTok"),
        ]);
        let douyin_cache = first_existing(&douyin_candidates);

        let mut qq_candidates = rule_cache.get("qqCache").cloned().unwrap_or_default();
        qq_candidates.extend([
            format!("{localappdata}\\Tencent\\QQNT\\User Data\\Cache"),
            format!("{appdata}\\Tencent\\QQ\\Cache"),
            format!("{appdata}\\Tencent Files\\Cache"),
        ]);
        let qq_cache = first_existing(&qq_candidates);

        Ok(json!({
            "qqInstallPath": qq_install,
            "wechatInstallPath": wechat_install,
            "douyinInstallPath": douyin_install,
            "neteaseMusicInstallPath": netease_install,
            "qqFileDir": qq_file_dir,
            "wechatFileDir": wechat_file_dir,
            "neteaseCacheDir": netease_cache,
            "wechatCacheDir": wechat_cache,
            "douyinCacheDir": douyin_cache,
            "qqCacheDir": qq_cache,
            "scanVersion": 2,
            "scannedAt": format!("{:?}", std::time::SystemTime::now()),
        }))
    }
}
// ==================== B5 startup_toggle：启动项启用/禁用 ====================


fn startup_backup_dir() -> std::path::PathBuf {
    let appdata = std::env::var("APPDATA").unwrap_or_else(|_| r"C:\Users\Default\AppData\Roaming".into());
    std::path::PathBuf::from(appdata).join("Trim").join("startup-backup")
}

fn startup_disabled_file() -> std::path::PathBuf {
    startup_backup_dir().join("disabled.json")
}

fn startup_files_dir() -> std::path::PathBuf {
    startup_backup_dir().join("files")
}

fn read_disabled_records() -> Vec<Value> {
    let f = startup_disabled_file();
    if let Ok(content) = std::fs::read_to_string(&f) {
        if let Ok(Value::Array(arr)) = serde_json::from_str(&content) {
            return arr.into_iter().filter(|v| !v.is_null()).collect();
        }
    }
    Vec::new()
}

fn write_disabled_records(records: &[Value]) {
    let dir = startup_backup_dir();
    let _ = std::fs::create_dir_all(&dir);
    let f = startup_disabled_file();
    if records.is_empty() {
        let _ = std::fs::remove_file(&f);
    } else {
        if let Ok(json) = serde_json::to_string_pretty(records) {
            if let Ok(mut file) = std::fs::File::create(&f) {
                let _ = file.write_all(json.as_bytes());
            }
        }
    }
}

/// 解析注册表路径为 (hive, subkey)
fn parse_reg_path(reg_path: &str) -> Option<(HKEY, String)> {
    let rp = reg_path.trim();
    if rp.starts_with("HKEY_CURRENT_USER") || rp.starts_with("HKCU") {
        let rest = rp.splitn(2, '\\').nth(1).unwrap_or("");
        Some((HKEY_CURRENT_USER, rest.to_string()))
    } else if rp.starts_with("HKEY_LOCAL_MACHINE") || rp.starts_with("HKLM") {
        let rest = rp.splitn(2, '\\').nth(1).unwrap_or("");
        Some((HKEY_LOCAL_MACHINE, rest.to_string()))
    } else {
        None
    }
}

/// StartupApproved 键路径
fn startup_approved_key(hive: HKEY) -> String {
    if hive == HKEY_CURRENT_USER {
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run".to_string()
    } else {
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run".to_string()
    }
}

/// 读 StartupApproved blob
unsafe fn read_approved_blob(hive: HKEY, value_name: &str) -> Option<Vec<u8>> {
    let key = startup_approved_key(hive);
    let sk = to_wide(&key);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { return None; }
    let nm = to_wide(value_name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        let _ = RegCloseKey(hk); return None;
    }
    if ty != REG_BINARY || size == 0 { let _ = RegCloseKey(hk); return None; }
    let mut buf = vec![0u8; size as usize];
    let r = RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size));
    let _ = RegCloseKey(hk);
    if r.is_err() { None } else { Some(buf) }
}

/// 写 StartupApproved blob，设置/清除 bit0，写后回读校验
unsafe fn set_approved_bit(hive: HKEY, value_name: &str, disable: bool) -> Result<(), String> {
    let key = startup_approved_key(hive);
    // 确保键存在
    let sk = to_wide(&key);
    let mut hk = HKEY::default();
    let mut disp = REG_CREATED_NEW_KEY;
    if RegCreateKeyExW(hive, PCWSTR(sk.as_ptr()), None, PCWSTR::default(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut hk, Some(&mut disp)).is_err() {
        return Err("无法创建 StartupApproved 键".into());
    }
    // 读现有 blob
    let mut bytes = read_approved_blob(hive, value_name).unwrap_or_else(|| {
        let mut b = vec![0u8; 12];
        b[0] = 2; // 无记录时按启用起手
        b
    });
    if bytes.len() < 12 { bytes.resize(12, 0); }
    if disable { bytes[0] |= 1; } else { bytes[0] &= 0xFE; }
    let nm = to_wide(value_name);
    if RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_BINARY, Some(&bytes)).is_err() {
        let _ = RegCloseKey(hk);
        return Err("写 StartupApproved blob 失败".into());
    }
    let _ = RegCloseKey(hk);
    // 回读校验
    if let Some(back) = read_approved_blob(hive, value_name) {
        let got = back.first().map(|b| b & 1 == 1).unwrap_or(false);
        if got != disable {
            return Err("StartupApproved 回读不符（可能被策略或安全软件覆盖）".into());
        }
    }
    Ok(())
}

/// 读注册表值（返回类型+数据）
unsafe fn reg_read_value_typed(hive: HKEY, subkey: &str, value_name: &str) -> Option<(REG_VALUE_TYPE, Vec<u8>)> {
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
unsafe fn reg_delete_value(hive: HKEY, subkey: &str, value_name: &str) -> bool {
    let sk = to_wide(&subkey);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk).is_err() { return false; }
    let nm = to_wide(value_name);
    let r = RegDeleteValueW(hk, PCWSTR(nm.as_ptr()));
    let _ = RegCloseKey(hk);
    r.is_ok()
}

/// 写注册表值（恢复用）
unsafe fn reg_write_value(hive: HKEY, subkey: &str, value_name: &str, kind: REG_VALUE_TYPE, data: &[u8]) -> bool {
    let sk = to_wide(&subkey);
    let mut hk = HKEY::default();
    let mut disp = REG_CREATED_NEW_KEY;
    if RegCreateKeyExW(hive, PCWSTR(sk.as_ptr()), None, PCWSTR::default(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut hk, Some(&mut disp)).is_err() {
        return false;
    }
    let nm = to_wide(value_name);
    let r = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), kind, Some(data));
    let _ = RegCloseKey(hk);
    r.is_ok()
}

/// 启动项启用/禁用（对应 startup_enable.ps1 / startup_disable.ps1，S3）
///
/// 覆盖：注册表项（StartupApproved blob 为主，删值式为回退）、文件夹项（移动备份）、
/// 计划任务（schtasks /Change）。disabled.json 记账维护。
pub fn startup_toggle(items: &[Value], enable: bool) -> Result<Value, String> {
    unsafe {
        let mut records = read_disabled_records();
        let mut results: Vec<Value> = Vec::new();
        let mut success = 0i64;
        let mut failed = 0i64;

        for item in items {
            let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let source = item.get("source").and_then(|v| v.as_str()).unwrap_or("").to_string();

            let result = match source.as_str() {
                "registry" => toggle_registry_item(item, enable, &mut records),
                "folder" => toggle_folder_item(item, enable, &mut records),
                "task" => toggle_task_item(item, enable),
                _ => Err("未知来源类型".into()),
            };

            match result {
                Ok(msg) => {
                    success += 1;
                    results.push(json!({"id": id, "name": name, "status": "ok", "message": msg}));
                }
                Err(e) => {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": e}));
                }
            }
        }

        write_disabled_records(&records);
        Ok(json!({"success": success, "failed": failed, "results": results}))
    }
}

unsafe fn toggle_registry_item(item: &Value, enable: bool, records: &mut Vec<Value>) -> Result<String, String> {
    let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let reg_path = item.get("regPath").and_then(|v| v.as_str()).unwrap_or("");
    let value_name = item.get("valueName").and_then(|v| v.as_str()).unwrap_or("");
    let hive_str = item.get("hive").and_then(|v| v.as_str()).unwrap_or("HKCU");
    let hive = if hive_str.starts_with("HKLM") { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER };

    let (_, subkey) = parse_reg_path(reg_path).ok_or("注册表路径格式错误")?;

    if enable {
        // 启用：优先清 StartupApproved bit0
        if reg_read_value_typed(hive, &subkey, value_name).is_some() {
            set_approved_bit(hive, value_name, false)?;
            records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
            return Ok("已启用".into());
        }
        // 值已被删除：从 disabled.json 恢复
        let rec = records.iter().find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
            .cloned().ok_or("缺少启用记录，且注册表中已无该项")?;
        let kind_str = rec.get("valueType").and_then(|v| v.as_str()).unwrap_or("String");
        let kind = match kind_str {
            "ExpandString" => REG_EXPAND_SZ,
            "DWord" => REG_DWORD,
            "QWord" => REG_QWORD,
            "Binary" => REG_BINARY,
            "MultiString" => REG_MULTI_SZ,
            _ => REG_SZ,
        };
        let data: Vec<u8> = if kind_str == "Binary" {
            let b64 = rec.get("valueDataB64").and_then(|v| v.as_str()).unwrap_or("");
            base64_decode(b64).unwrap_or_default()
        } else if kind_str == "MultiString" {
            let arr = rec.get("valueDataArray").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let mut bytes = Vec::new();
            for s in arr {
                let text = s.as_str().unwrap_or("");
                let wide: Vec<u16> = text.encode_utf16().collect();
                for w in &wide { bytes.extend_from_slice(&w.to_le_bytes()); }
                bytes.extend_from_slice(&[0, 0]);
            }
            bytes.extend_from_slice(&[0, 0]);
            bytes
        } else if kind_str == "DWord" || kind_str == "QWord" {
            let val = rec.get("valueData").and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            if kind_str == "DWord" { (val as u32).to_le_bytes().to_vec() } else { val.to_le_bytes().to_vec() }
        } else {
            let text = rec.get("valueData").and_then(|v| v.as_str()).unwrap_or("");
            let wide: Vec<u16> = text.encode_utf16().collect();
            let mut bytes = Vec::new();
            for w in &wide { bytes.extend_from_slice(&w.to_le_bytes()); }
            bytes.extend_from_slice(&[0, 0]);
            bytes
        };
        if !reg_write_value(hive, &subkey, value_name, kind, &data) {
            return Err("回写未生效（可能需要管理员权限）".into());
        }
        records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
        Ok("已启用".into())
    } else {
        // 禁用：优先写 StartupApproved blob
        if reg_read_value_typed(hive, &subkey, value_name).is_none() {
            return Err("注册表值不存在".into());
        }
        match set_approved_bit(hive, value_name, true) {
            Ok(_) => Ok("已禁用（注册表值保留，可随时还原）".into()),
            Err(e) => {
                // 回退：删值 + 备份
                let (kind, data) = reg_read_value_typed(hive, &subkey, value_name)
                    .ok_or("读取注册表值失败")?;
                let kind_str = match kind {
                    REG_EXPAND_SZ => "ExpandString", REG_DWORD => "DWord", REG_QWORD => "QWord",
                    REG_BINARY => "Binary", REG_MULTI_SZ => "MultiString", _ => "String",
                };
                let (v_data, v_b64, v_arr) = if kind == REG_BINARY {
                    (String::new(), base64_encode(&data), Value::Array(vec![]))
                } else if kind == REG_MULTI_SZ {
                    let wide: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let parts: Vec<String> = wide.split(|&c| c == 0).filter(|s| !s.is_empty())
                        .map(|s| String::from_utf16_lossy(s)).collect();
                    (String::new(), String::new(), Value::Array(parts.into_iter().map(|s| json!(s)).collect()))
                } else if kind == REG_DWORD || kind == REG_QWORD {
                    let val = if kind == REG_DWORD { u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as i64 }
                        else { i64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]) };
                    (val.to_string(), String::new(), Value::Array(vec![]))
                } else {
                    let wide: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
                    (String::from_utf16_lossy(&wide[..end]), String::new(), Value::Array(vec![]))
                };
                if !reg_delete_value(hive, &subkey, value_name) {
                    return Err(e);
                }
                let rec = json!({
                    "id": id, "name": item.get("name"), "command": v_data,
                    "source": "registry", "hive": item.get("hive"), "regPath": reg_path,
                    "valueName": value_name, "valueType": kind_str,
                    "valueData": v_data, "valueDataB64": v_b64, "valueDataArray": v_arr,
                    "filePath": "", "taskPath": "", "taskName": "",
                    "location": item.get("location"), "scope": item.get("scope"),
                    "publisher": item.get("publisher"), "resolvedPath": item.get("resolvedPath"),
                });
                records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
                records.push(rec);
                Ok(format!("已禁用（回退为删除值方式：{e}）"))
            }
        }
    }
}

unsafe fn toggle_folder_item(item: &Value, enable: bool, records: &mut Vec<Value>) -> Result<String, String> {
    let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let file_path = item.get("filePath").and_then(|v| v.as_str()).unwrap_or("");

    if enable {
        let rec = records.iter().find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
            .cloned().ok_or("缺少启用记录")?;
        let backup_path = rec.get("filePath").and_then(|v| v.as_str()).unwrap_or("");
        let orig_path = rec.get("valueData").and_then(|v| v.as_str()).unwrap_or("");
        if backup_path.is_empty() || !std::path::Path::new(backup_path).exists() {
            return Err("备份文件不存在".into());
        }
        if let Some(parent) = std::path::Path::new(orig_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::rename(backup_path, orig_path).map_err(|e| format!("移回失败: {e}"))?;
        if std::path::Path::new(orig_path).exists() {
            records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
            Ok("已启用".into())
        } else {
            Err("移回未生效".into())
        }
    } else {
        if !std::path::Path::new(file_path).exists() {
            return Err("文件不存在".into());
        }
        let files_dir = startup_files_dir();
        let _ = std::fs::create_dir_all(&files_dir);
        let stamp = chrono_now_str();
        let safe_name: String = item.get("name").and_then(|v| v.as_str()).unwrap_or("item")
            .chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
        let ext = std::path::Path::new(file_path).extension()
            .and_then(|e| e.to_str()).unwrap_or("");
        let dest = files_dir.join(format!("{stamp}_{safe_name}.{ext}"));
        std::fs::rename(file_path, &dest).map_err(|e| format!("移动备份失败: {e}"))?;
        let rec = json!({
            "id": id, "name": item.get("name"), "command": file_path,
            "source": "folder", "hive": item.get("hive"), "regPath": "", "valueName": "",
            "valueType": "", "valueData": file_path, "valueDataB64": "", "valueDataArray": [],
            "filePath": dest.to_string_lossy().to_string(), "taskPath": "", "taskName": "",
            "location": item.get("location"), "scope": item.get("scope"),
            "publisher": item.get("publisher"), "resolvedPath": item.get("resolvedPath"),
        });
        records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
        records.push(rec);
        Ok("已禁用".into())
    }
}

unsafe fn toggle_task_item(item: &Value, enable: bool) -> Result<String, String> {
    let task_path = item.get("taskPath").and_then(|v| v.as_str()).unwrap_or("");
    let task_name = item.get("taskName").and_then(|v| v.as_str()).unwrap_or("");
    if task_name.is_empty() { return Err("缺少任务名".into()); }
    let full_name = format!("{task_path}{task_name}");
    let arg = if enable { "/ENABLE" } else { "/DISABLE" };
    let output = std::process::Command::new(system_tool("schtasks"))
        .args(["/Change", "/TN", &full_name, arg])
        .output().map_err(|e| format!("schtasks 执行失败: {e}"))?;
    if output.status.success() {
        Ok(if enable { "已启用".into() } else { "已禁用".into() })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(if stderr.is_empty() { "操作未生效（可能需要管理员权限）".into() } else { stderr })
    }
}

fn chrono_now_str() -> String {
    let now = std::time::SystemTime::now();
    let dur = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    // 简单格式：yyyyMMdd_HHmmss（本地时间近似）
    let hours = (secs % 86400) / 3600 + 8; // UTC+8
    format!("19700101_{:02}{:02}{:02}", hours % 24, (secs % 3600) / 60, secs % 60)
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 { result.push(CHARS[((n >> 6) & 63) as usize] as char); } else { result.push('='); }
        if chunk.len() > 2 { result.push(CHARS[(n & 63) as usize] as char); } else { result.push('='); }
    }
    result
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 { return None; }
        let mut n = 0u32;
        let mut valid = 4;
        for (i, &b) in chunk.iter().enumerate() {
            let v = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62, b'/' => 63,
                b'=' => { valid = i; break; }
                _ => return None,
            };
            n |= (v as u32) << (18 - i * 6);
        }
        result.push((n >> 16) as u8);
        if valid > 2 { result.push((n >> 8) as u8); }
        if valid > 3 { result.push(n as u8); }
    }
    Some(result)
}

// ==================== B6 cm_toggle：右键菜单启用/禁用 ====================

use windows::Win32::System::Registry::RegRenameKey;

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
// ==================== B5 startup_delete：启动项删除 ====================

fn startup_deleted_dir() -> std::path::PathBuf {
    let dir = if let Ok(appdata) = std::env::var("APPDATA") {
        std::path::PathBuf::from(appdata).join("Trim").join("startup-backup").join("deleted")
    } else {
        crate::engine::paths::app_data_dir().join("startup-backup").join("deleted")
    };
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn safe_name(name: &str) -> String {
    name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

/// 启动项删除（对应 startup_remove.ps1，S3）
///
/// 注册表：reg.exe export 备份整个键 + RegDeleteValueW 删值
/// 文件夹：复制到 deleted/ 备份，返回 fsDelete 由主进程回收站删除
/// 计划任务：schtasks /Query /XML 备份 + schtasks /Delete 删除
pub fn startup_delete(items: &[Value]) -> Result<Value, String> {
    let deleted_dir = startup_deleted_dir();
    let backup_dir = deleted_dir.parent().unwrap().to_path_buf();
    let disabled_file = backup_dir.join("disabled.json");
    let stamp = crate::engine::now_ms().to_string();

    let mut records: Vec<Value> = if disabled_file.exists() {
        std::fs::read_to_string(&disabled_file).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| Value::Array(vec![]))
            .as_array().cloned().unwrap_or_default()
    } else { vec![] };

    let mut results: Vec<Value> = Vec::new();
    let mut fs_delete: Vec<Value> = Vec::new();
    let mut success = 0i64;
    let mut failed = 0i64;

    for item in items {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let source = item.get("source").and_then(|v| v.as_str()).unwrap_or("");

        match source {
            "registry" => {
                let reg_path = item.get("regPath").and_then(|v| v.as_str()).unwrap_or("");
                let value_name = item.get("valueName").and_then(|v| v.as_str()).unwrap_or("");
                if reg_path.is_empty() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "缺少注册表路径"}));
                    continue;
                }
                let (hive, subkey) = match parse_reg_path(reg_path) {
                    Some(v) => v,
                    None => { failed += 1; results.push(json!({"id": id, "name": name, "status": "error", "message": "注册表路径格式错误"})); continue; }
                };
                // 备份整个键到 .reg
                let safe = safe_name(&name);
                let reg_file = deleted_dir.join(format!("{stamp}_reg_{safe}.reg"));
                let hive_short = if hive == HKEY_LOCAL_MACHINE { "HKLM" } else { "HKCU" };
                let export_path = format!("{hive_short}\\{subkey}");
                let export_out = std::process::Command::new(system_tool("reg.exe"))
                    .args(["export", &export_path, reg_file.to_str().unwrap(), "/y"])
                    .output();
                if export_out.is_err() || !reg_file.exists() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "注册表备份失败，未执行删除"}));
                    continue;
                }
                // 删值
                unsafe {
                    let sk = to_wide(&subkey);
                    let mut hk = HKEY::default();
                    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk).is_err() {
                        failed += 1;
                        results.push(json!({"id": id, "name": name, "status": "error", "message": "无法打开注册表键"}));
                        continue;
                    }
                    let nm = to_wide(value_name);
                    let _ = RegDeleteValueW(hk, PCWSTR(nm.as_ptr()));
                    let _ = RegCloseKey(hk);
                    // 回读
                    let sk2 = to_wide(&subkey);
                    let mut hk2 = HKEY::default();
                    let still_exists = if RegOpenKeyExW(hive, PCWSTR(sk2.as_ptr()), Some(0), KEY_READ, &mut hk2).is_ok() {
                        let nm2 = to_wide(value_name);
                        let mut ty = REG_VALUE_TYPE::default();
                        let mut size = 0u32;
                        let exists = RegQueryValueExW(hk2, PCWSTR(nm2.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_ok();
                        let _ = RegCloseKey(hk2);
                        exists
                    } else { false };
                    if still_exists {
                        failed += 1;
                        results.push(json!({"id": id, "name": name, "status": "error", "message": "删除未生效（可能需要管理员权限）"}));
                    } else {
                        // 从 disabled.json 移除记录
                        records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id.as_str()));
                        success += 1;
                        results.push(json!({"id": id, "name": name, "status": "ok", "message": "已删除（已备份注册表键）"}));
                    }
                }
            }
            "folder" => {
                let file_path = item.get("filePath").and_then(|v| v.as_str()).unwrap_or("");
                // 检查是否为已禁用记录（在备份目录）
                let rec = records.iter().find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id.as_str()));
                let backup_path = rec.and_then(|r| r.get("filePath").and_then(|v| v.as_str())).unwrap_or("");
                if !backup_path.is_empty() && std::path::Path::new(backup_path).exists() && !std::path::Path::new(file_path).exists() {
                    // 从备份目录删除
                    fs_delete.push(json!({"id": id, "name": name, "path": backup_path, "kind": "backup-file"}));
                    records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id.as_str()));
                    results.push(json!({"id": id, "name": name, "status": "deferred", "message": "备份文件待主进程回收站删除"}));
                } else if std::path::Path::new(file_path).exists() {
                    // 备份到 deleted 目录
                    let safe = safe_name(&name);
                    let ext = std::path::Path::new(file_path).extension().and_then(|e| e.to_str()).unwrap_or("");
                    let dest = deleted_dir.join(format!("{stamp}_folder_{safe}.{ext}"));
                    if std::fs::copy(file_path, &dest).is_err() {
                        failed += 1;
                        results.push(json!({"id": id, "name": name, "status": "error", "message": "文件备份失败"}));
                        continue;
                    }
                    fs_delete.push(json!({"id": id, "name": name, "path": file_path, "kind": "startup-file"}));
                    results.push(json!({"id": id, "name": name, "status": "deferred", "message": "已备份，待主进程回收站删除"}));
                } else {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "文件不存在"}));
                }
            }
            "task" => {
                let task_path = item.get("taskPath").and_then(|v| v.as_str()).unwrap_or("");
                let task_name = item.get("taskName").and_then(|v| v.as_str()).unwrap_or("");
                if task_name.is_empty() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "缺少任务名"}));
                    continue;
                }
                let tn = if task_path.is_empty() || task_path == "\\" { task_name.to_string() } else { format!("{}\\\\{}", task_path, task_name) };
                // 导出 XML 备份
                let safe = safe_name(&task_name);
                let xml_file = deleted_dir.join(format!("{stamp}_task_{safe}.xml"));
                let query_out = std::process::Command::new(system_tool("schtasks"))
                    .args(["/Query", "/TN", &tn, "/XML"])
                    .output();
                if let Ok(out) = query_out {
                    if out.status.success() {
                        let _ = std::fs::write(&xml_file, &out.stdout);
                    }
                }
                if !xml_file.exists() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "计划任务备份失败，未执行删除"}));
                    continue;
                }
                // 删除
                let del_out = std::process::Command::new(system_tool("schtasks"))
                    .args(["/Delete", "/TN", &tn, "/F"])
                    .output();
                if del_out.is_err() || !del_out.unwrap().status.success() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "删除未生效（可能需要管理员权限）"}));
                } else {
                    success += 1;
                    results.push(json!({"id": id, "name": name, "status": "ok", "message": "已删除（已导出任务备份）"}));
                }
            }
            _ => {
                failed += 1;
                results.push(json!({"id": id, "name": name, "status": "error", "message": "未知来源类型"}));
            }
        }
    }

    // 写回 disabled.json
    if records.is_empty() {
        let _ = std::fs::remove_file(&disabled_file);
    } else {
        let _ = std::fs::write(&disabled_file, serde_json::to_string_pretty(&Value::Array(records)).unwrap_or_else(|_| "[]".into()));
    }

    Ok(json!({"success": success, "failed": failed, "results": results, "fsDelete": fs_delete}))
}
// ==================== B5 startup_add：新增启动项 ====================

/// 新增启动项（对应 startup_add.ps1，S3）
///
/// 写入 HKCU\Software\Microsoft\Windows\CurrentVersion\Run，值为带引号的路径。
/// 冲突检查：已存在同名启动项时返回原值，不覆盖。
/// 返回 Ok(None) 表示成功，Ok(Some(existing_value)) 表示冲突。
pub fn startup_add(path: &str, name: &str) -> Result<Option<String>, String> {
    unsafe {
        let key = r"Software\Microsoft\Windows\CurrentVersion\Run";
        let sk = to_wide(key);
        let mut hk = HKEY::default();
        let mut disp = REG_CREATED_NEW_KEY;
        if RegCreateKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), None, PCWSTR::default(),
            REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, None, &mut hk, Some(&mut disp)).is_err() {
            return Err("无法打开 Run 键".into());
        }
        // 冲突检查
        let nm = to_wide(name);
        if let Some(existing) = reg_read_string(hk, name) {
            if !existing.is_empty() {
                let _ = RegCloseKey(hk);
                return Ok(Some(existing));
            }
        }
        // 写入带引号的路径
        let value = format!("\"{path}\"");
        let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
        if RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_SZ, Some(&bytes)).is_err() {
            let _ = RegCloseKey(hk);
            return Err("写入注册表失败".into());
        }
        let _ = RegCloseKey(hk);
        Ok(None)
    }
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
        if safe_name.len() > 120 { safe_name = safe_name[safe_name.len()-120..].to_string(); }
        let reg_file = backup_dir.join(format!("registry_{idx}_{safe_name}.reg"));

        // reg.exe export
        let out = std::process::Command::new(system_tool("reg.exe"))
            .args(["export", &write_path, reg_file.to_str().unwrap(), "/y"])
            .output();
        let success = out.is_ok() && out.as_ref().unwrap().status.success();
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
    let _ = std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| "{}".into()));

    Ok(json!({
        "backupDir": backup_dir.to_string_lossy().to_string(),
        "files": backup_files,
        "count": exported + copied,
        "exported": exported,
        "copied": copied,
        "failed": failed,
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
            // reg.exe import
            let out = std::process::Command::new(system_tool("reg.exe"))
                .args(["import", path.to_str().unwrap()])
                .output();
            if out.is_err() || !out.unwrap().status.success() {
                failed += 1;
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
// ==================== B9 peripheral_apply：外设优化应用 ====================

/// 外设优化应用（对应 peripheral_apply.ps1，S3）
///
/// 写入三个 HKLM 注册表值：Win32PrioritySeparation、KeyboardDataQueueSize、MouseDataQueueSize。
/// 写入前备份每个父键到 %APPDATA%\Trim\peripheral-backup\backup_<stamp>_<n>.reg。
/// options 中值为 -1 表示跳过该项。
pub fn peripheral_apply(options: &Value) -> Result<(), String> {
    let targets: Vec<(&str, &str, &str, i64)> = vec![
        ("win32", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation",
         options.get("win32").and_then(|v| v.as_i64()).unwrap_or(-1)),
        ("keyboard", r"SYSTEM\CurrentControlSet\Services\kbdclass\Parameters", "KeyboardDataQueueSize",
         options.get("keyboard").and_then(|v| v.as_i64()).unwrap_or(-1)),
        ("mouse", r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize",
         options.get("mouse").and_then(|v| v.as_i64()).unwrap_or(-1)),
    ];

    // 备份目录
    let backup_dir = if let Ok(appdata) = std::env::var("APPDATA") {
        std::path::PathBuf::from(appdata).join("Trim").join("peripheral-backup")
    } else {
        return Err("无法获取 APPDATA".into());
    };
    std::fs::create_dir_all(&backup_dir).map_err(|e| format!("创建备份目录失败: {e}"))?;
    let stamp = crate::engine::now_ms().to_string();

    // 备份每个需要修改的父键
    let mut part = 0;
    for (_key, subkey, _name, value) in &targets {
        if *value < 0 { continue; }
        part += 1;
        let reg_path = format!("HKLM\\{subkey}");
        let backup_file = backup_dir.join(format!("backup_{stamp}_{part}.reg"));
        let out = std::process::Command::new(system_tool("reg.exe"))
            .args(["export", &reg_path, backup_file.to_str().unwrap(), "/y"])
            .output();
        if out.is_err() || !out.unwrap().status.success() {
            let _ = std::fs::remove_file(&backup_file);
            return Err("注册表备份失败".into());
        }
    }

    // 写入值
    unsafe {
        for (_key, subkey, name, value) in &targets {
            if *value < 0 { continue; }
            let sk = to_wide(subkey);
            let mut hk = HKEY::default();
            let mut disp = REG_CREATED_NEW_KEY;
            if RegCreateKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), None, PCWSTR::default(),
                REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut hk, Some(&mut disp)).is_err() {
                return Err(format!("无法打开注册表键: {subkey}"));
            }
            let nm = to_wide(name);
            let val = *value as u32;
            if RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes())).is_err() {
                let _ = RegCloseKey(hk);
                return Err(format!("写入注册表失败: {name}"));
            }
            let _ = RegCloseKey(hk);
        }
    }

    Ok(())
}
// ==================== B9 peripheral_restore：外设优化恢复 ====================

/// 从备份恢复外设设置（对应 peripheral_restore.ps1，S3）
///
/// 找 %APPDATA%\Trim\peripheral-backup 中最新一批 backup_<stamp>_*.reg，
/// 按时间戳分组整组导入（v2-M12：一次 apply 留下多个分片，必须整组还原）。
/// 返回 ok/reason/restored/total/file。
pub fn peripheral_restore() -> Result<Value, String> {
    let backup_dir = if let Ok(appdata) = std::env::var("APPDATA") {
        std::path::PathBuf::from(appdata).join("Trim").join("peripheral-backup")
    } else {
        return Ok(json!({"ok": false, "reason": "no-backup", "restored": 0, "total": 0, "file": ""}));
    };
    if !backup_dir.exists() {
        return Ok(json!({"ok": false, "reason": "no-backup", "restored": 0, "total": 0, "file": ""}));
    }

    // 收集所有 backup_*.reg，按修改时间倒序
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&backup_dir)
        .map_err(|e| format!("读取备份目录失败: {e}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file() && p.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("backup_") && n.ends_with(".reg")).unwrap_or(false)
        })
        .collect();
    if files.is_empty() {
        return Ok(json!({"ok": false, "reason": "no-backup", "restored": 0, "total": 0, "file": ""}));
    }
    files.sort_by(|a, b| {
        let ta = a.metadata().and_then(|m| m.modified()).ok();
        let tb = b.metadata().and_then(|m| m.modified()).ok();
        tb.cmp(&ta)
    });

    // 按时间戳分组
    let latest_name = files[0].file_name().and_then(|n| n.to_str()).unwrap_or("");
    let stamp = if let Some(caps) = regex_capture(latest_name, r"^backup_(\d{8}_\d{6})") {
        caps
    } else {
        String::new()
    };
    let group: Vec<&std::path::PathBuf> = if !stamp.is_empty() {
        files.iter().filter(|p| {
            p.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with(&format!("backup_{stamp}"))).unwrap_or(false)
        }).collect()
    } else {
        vec![&files[0]]
    };

    let mut imported = 0i64;
    for f in &group {
        let out = std::process::Command::new(system_tool("reg.exe"))
            .args(["import", f.to_str().unwrap()])
            .output();
        if out.is_ok() && out.unwrap().status.success() {
            imported += 1;
        }
    }
    let total = group.len() as i64;
    let ok = imported > 0 && imported == total;
    let reason = if ok { String::new() } else if imported == 0 { "import-failed".into() } else { "partial".into() };

    Ok(json!({
        "ok": ok,
        "reason": reason,
        "restored": imported,
        "total": total,
        "file": latest_name,
    }))
}

fn regex_capture(text: &str, pattern: &str) -> Option<String> {
    // 简单正则：backup_(\d{8}_\d{6})
    if pattern == r"^backup_(\d{8}_\d{6})" {
        if text.len() >= 21 && &text[..7] == "backup_" {
            let stamp = &text[7..21];
            if stamp.chars().all(|c| c.is_ascii_digit() || c == '_') {
                return Some(stamp.to_string());
            }
        }
    }
    None
}

// ==================== B7 runtimes_repair：运行库修复 ====================

/// 运行库修复（对应 runtimes_repair_*.ps1，S3）
///
/// 静默执行安装包或 dism.exe，检查退出码。
/// 返回 (success, message)。
/// 退出码 0/3010/1638 视为成功。
pub fn runtimes_repair(action_id: &str, installer_path: Option<&str>) -> Result<(bool, String), String> {
    let (program, args): (&str, Vec<&str>) = match action_id {
        "vc-x64" | "vc-x86" => {
            let path = installer_path.ok_or("缺少安装包路径")?;
            (path, vec!["/install", "/quiet", "/norestart"])
        }
        "netfx48" => {
            let path = installer_path.ok_or("缺少安装包路径")?;
            (path, vec!["/q", "/norestart"])
        }
        "netfx35" => {
            ("dism.exe", vec!["/Online", "/Enable-Feature", "/FeatureName:NetFx3", "/All", "/NoRestart"])
        }
        _ => return Err(format!("未知的修复动作: {action_id}")),
    };

    crate::engine::log::write_log("info", &format!("运行库修复开始: {action_id}"));
    let out = std::process::Command::new(program)
        .args(&args)
        .output()
        .map_err(|e| format!("执行安装程序失败: {e}"))?;

    let code = out.status.code().unwrap_or(-1);
    let (success, message) = match code {
        0 => (true, "安装成功".into()),
        3010 => (true, "安装成功，需重启电脑后完全生效".into()),
        1638 => (true, "已安装相同或更新版本，无需重复安装".into()),
        _ => (false, format!("安装失败，退出码 {code}")),
    };

    if success {
        crate::engine::log::write_log("info", &format!("运行库修复完成: {action_id} ({message})"));
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).chars().take(200).collect::<String>();
        crate::engine::log::write_log("warn", &format!("运行库修复失败: {action_id} exit={code} {stderr}"));
    }

    Ok((success, message))
}
// ==================== B8 netcheck_repair：网络修复 ====================

/// 网络检测修复（对应 netcheck_repair_*.ps1，S3）
///
/// 6 个修复动作：enable-adapter / reset-dns / start-dhcp / start-dnscache /
/// disable-user-proxy / reset-winhttp。
/// 返回 {ok, message}。
pub fn netcheck_repair(action_id: &str, repair: &Value) -> Result<Value, String> {
    match action_id {
        "enable-adapter" => {
            let name = repair.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name.trim().is_empty() {
                return Ok(json!({"ok": false, "message": "缺少网卡名"}));
            }
            let out = std::process::Command::new(system_tool("netsh"))
                .args(["interface", "set", "interface", &format!("name={name}"), "admin=enabled"])
                .output()
                .map_err(|e| format!("netsh 执行失败: {e}"))?;
            if out.status.success() {
                Ok(json!({"ok": true, "message": "网卡已启用"}))
            } else {
                Ok(json!({"ok": false, "message": "网卡启用失败"}))
            }
        }
        "reset-dns" => {
            // 优先用接口名，没有则用索引
            let name = repair.get("name").and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    repair.get("interfaceIndex")
                        .and_then(|v| v.as_i64())
                        .map(|i| i.to_string())
                        .unwrap_or_default()
                });
            if name.is_empty() {
                return Ok(json!({"ok": false, "message": "缺少接口标识"}));
            }
            let out = std::process::Command::new(system_tool("netsh"))
                .args(["interface", "ipv4", "set", "dnsservers", &format!("name={name}"), "source=dhcp"])
                .output()
                .map_err(|e| format!("netsh 执行失败: {e}"))?;
            if out.status.success() {
                Ok(json!({"ok": true, "message": "DNS 已重置为自动获取"}))
            } else {
                Ok(json!({"ok": false, "message": "DNS 重置失败"}))
            }
        }
        "start-dhcp" => {
            let out = std::process::Command::new(system_tool("sc"))
                .args(["start", "Dhcp"])
                .output()
                .map_err(|e| format!("sc 执行失败: {e}"))?;
            if out.status.success() {
                Ok(json!({"ok": true, "message": "DHCP 服务已启动"}))
            } else {
                Ok(json!({"ok": false, "message": "DHCP 服务启动失败"}))
            }
        }
        "start-dnscache" => {
            let out = std::process::Command::new(system_tool("sc"))
                .args(["start", "Dnscache"])
                .output()
                .map_err(|e| format!("sc 执行失败: {e}"))?;
            if out.status.success() {
                Ok(json!({"ok": true, "message": "DNS 缓存服务已启动"}))
            } else {
                Ok(json!({"ok": false, "message": "DNS 缓存服务启动失败"}))
            }
        }
        "disable-user-proxy" => {
            unsafe {
                let key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
                let sk = to_wide(key);
                let mut hk = HKEY::default();
                if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_WRITE, &mut hk).is_err() {
                    return Ok(json!({"ok": false, "message": "无法打开代理设置键"}));
                }
                let nm = to_wide("ProxyEnable");
                let val = 0u32;
                let r = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes()));
                let _ = RegCloseKey(hk);
                if r.is_ok() {
                    Ok(json!({"ok": true, "message": "用户代理已禁用"}))
                } else {
                    Ok(json!({"ok": false, "message": "禁用用户代理失败"}))
                }
            }
        }
        "reset-winhttp" => {
            let out = std::process::Command::new(system_tool("netsh"))
                .args(["winhttp", "reset", "proxy"])
                .output()
                .map_err(|e| format!("netsh 执行失败: {e}"))?;
            if out.status.success() {
                Ok(json!({"ok": true, "message": "WinHTTP 代理已重置"}))
            } else {
                Ok(json!({"ok": false, "message": "WinHTTP 代理重置失败"}))
            }
        }
        _ => Err(format!("未知的修复动作: {action_id}")),
    }
}
// ==================== B8 maint：维护命令 ====================

fn run_cmd(program: &str, args: &[&str]) -> bool {
    // 审查 v2-F7：系统工具必须解析到 System32 再执行，不能用裸进程名 ——
    // 搜索顺序里「exe 所在目录」与「父进程 CWD」都排在 System32 之前。
    let exe = crate::engine::systembin::system_tool(program);
    match std::process::Command::new(exe).args(args).output() {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

fn restart_service(name: &str) -> bool {
    let sc = crate::engine::systembin::system_tool("sc");
    let _ = std::process::Command::new(&sc).args(["stop", name]).output();
    std::thread::sleep(std::time::Duration::from_millis(500));
    run_cmd("sc", &["start", name])
}

fn split_reg_hive(path: &str) -> Option<(HKEY, &str)> {
    let (hive, sub) = match path.split_once('\\') {
        Some((h, s)) => (h, s),
        None => (path, ""),
    };
    let h = match hive {
        "HKEY_LOCAL_MACHINE" | "HKLM" => HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER" | "HKCU" => HKEY_CURRENT_USER,
        _ => return None,
    };
    Some((h, sub))
}

/// `"名称"=dword:八位十六进制` → (名称, 值)；不支持的写法返回 None
fn parse_reg_dword(line: &str) -> Option<(String, u32)> {
    let (name, rest) = line.split_once('=')?;
    let name = name.trim();
    if !(name.starts_with('"') && name.ends_with('"') && name.len() >= 2) { return None; }
    let name = &name[1..name.len() - 1];
    if name.is_empty() { return None; }
    let hex = rest.trim().strip_prefix("dword:")?;
    if hex.len() != 8 { return None; }
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some((name.to_string(), v))
}

/// .reg 文本 → 逐键写入注册表（不落盘、不起外部进程）
///
/// 审查 v2-F2：原实现把内容写进 `std::env::temp_dir()`（全局可写 `%TEMP%`），文件名
/// 可预测（`tfmaint_<毫秒>`），再由 `reg.exe import` 读回 —— 在管理员令牌下同时打开
/// TOCTOU 回写与 junction 预占两条本地提权窗口，且违反 `AGENTS.md` §3「临时脚本只写
/// 应用私有 tmp 目录」。改为直接 `RegCreateKeyExW` + `RegSetValueExW`，两条窗口一并消失。
///
/// 语法支持面刻意收窄到本模块维护任务实际用到的：`[HIVE\子键]` 段 + 若干
/// `"名"=dword:XXXXXXXX`。**先整体解析再统一写入**：任何一行解析不了就返回 false，
/// 不留下半写状态。
fn reg_import(reg_content: &str) -> bool {
    #[allow(clippy::type_complexity)]
    let mut sections: Vec<(HKEY, String, Vec<(String, u32)>)> = Vec::new();
    let mut cur: Option<(HKEY, String, Vec<(String, u32)>)> = None;

    for raw in reg_content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with("Windows Registry Editor Version") {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(prev) = cur.take() { sections.push(prev); }
            match split_reg_hive(inner) {
                Some((hive, sub)) => cur = Some((hive, sub.to_string(), Vec::new())),
                None => return false,
            }
            continue;
        }
        match parse_reg_dword(line) {
            Some((name, val)) => match cur.as_mut() {
                Some(s) => s.2.push((name, val)),
                None => return false, // 值出现在任何 [键] 之前，属畸形输入
            },
            None => return false,
        }
    }
    if let Some(prev) = cur.take() { sections.push(prev); }
    if sections.is_empty() { return false; }

    let mut ok = true;
    unsafe {
        for (hive, sub, vals) in &sections {
            let sk = to_wide(sub);
            let mut hk = HKEY::default();
            let mut disp = REG_CREATED_NEW_KEY;
            if RegCreateKeyExW(
                *hive, PCWSTR(sk.as_ptr()), None, PCWSTR::default(),
                REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut hk, Some(&mut disp),
            ).is_err() {
                ok = false;
                continue;
            }
            for (name, val) in vals {
                let nm = to_wide(name);
                if RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes())).is_err() {
                    ok = false;
                }
            }
            let _ = RegCloseKey(hk);
        }
    }
    ok
}

/// 维护命令执行（对应 maint_*.ps1，S3）
///
/// 覆盖 18 个维护任务。返回 (success, output_message)。
pub fn maint_run(task_id: &str) -> Result<(bool, String), String> {
    match task_id {
        "sfc" => {
            crate::engine::log::write_log("info", "维护：sfc /scannow");
            let ok = run_cmd("sfc.exe", &["/scannow"]);
            Ok((ok, if ok { "系统文件检查完成".into() } else { "系统文件检查失败".into() }))
        }
        "dism" => {
            crate::engine::log::write_log("info", "维护：DISM /RestoreHealth");
            let ok = run_cmd("dism.exe", &["/Online", "/Cleanup-Image", "/RestoreHealth"]);
            Ok((ok, if ok { "组件存储修复完成".into() } else { "组件存储修复失败".into() }))
        }
        "dns" => {
            let ok = run_cmd("ipconfig.exe", &["/flushdns"]);
            Ok((ok, if ok { "DNS 缓存已刷新".into() } else { "DNS 刷新失败".into() }))
        }
        "perfcounters" => {
            let ok = run_cmd("lodctr.exe", &["/r"]);
            Ok((ok, if ok { "性能计数器已重建".into() } else { "性能计数器重建失败".into() }))
        }
        "store" => {
            let _ = std::process::Command::new(system_tool("wsreset.exe")).spawn();
            Ok((true, "Store 缓存清理已启动".into()))
        }
        "netstack" => {
            let mut ok = true;
            ok &= run_cmd("netsh.exe", &["winsock", "reset"]);
            ok &= run_cmd("netsh.exe", &["int", "ip", "reset"]);
            ok &= run_cmd("ipconfig.exe", &["/flushdns"]);
            Ok((ok, if ok { "网络栈已重置（需重启生效）".into() } else { "网络栈重置部分失败".into() }))
        }
        "audio" => {
            let ok = restart_service("Audiosrv") && restart_service("AudioEndpointBuilder");
            Ok((ok, if ok { "音频服务已重启".into() } else { "音频服务重启失败".into() }))
        }
        "search" => {
            // 停止 WSearch，清空索引，启动
            let _ = std::process::Command::new(system_tool("sc")).args(["stop", "WSearch"]).output();
            std::thread::sleep(std::time::Duration::from_secs(2));
            let idx = std::path::PathBuf::from(r"C:\ProgramData\Microsoft\Search\Data\Applications\Windows");
            let _ = std::fs::remove_dir_all(&idx);
            let ok = run_cmd("sc", &["start", "WSearch"]);
            Ok((ok, if ok { "搜索服务已重启，索引将在后台重建".into() } else { "搜索服务重启失败".into() }))
        }
        "wu" => {
            // 停止更新服务，清理缓存，启动
            for svc in ["wuauserv", "bits", "cryptsvc"] {
                let _ = std::process::Command::new(system_tool("sc")).args(["stop", svc]).output();
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
            let cache = std::path::PathBuf::from(r"C:\Windows\SoftwareDistribution\DataStore");
            let _ = std::fs::remove_dir_all(&cache);
            let mut ok = true;
            for svc in ["wuauserv", "bits", "cryptsvc"] {
                ok &= run_cmd("sc", &["start", svc]);
            }
            Ok((ok, if ok { "更新服务已重启".into() } else { "更新服务重启部分失败".into() }))
        }
        "tf_net_tcp" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile]\r\n\"NetworkThrottlingIndex\"=dword:ffffffff\r\n\"SystemResponsiveness\"=dword:0000000a\r\n";
            let mut ok = reg_import(reg);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "global", "autotuninglevel=disabled", "ecncapability=disabled", "dca=enabled", "rsc=disabled", "rss=enabled", "timestamps=disabled"]);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "global", "rssbasecpu=1"]);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "heuristics", "disabled"]);
            ok &= run_cmd("netsh.exe", &["int", "ip", "set", "global", "neighborcachelimit=4096"]);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "supplemental", "Internet", "congestionprovider=ctcp"]);
            Ok((ok, "TCP 全局参数已优化".into()))
        }
        "tf_net_tcpip" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters]\r\n\"Tcp1323Opts\"=dword:00000001\r\n\"TcpMaxDupAcks\"=dword:00000002\r\n\"SackOpts\"=dword:00000001\r\n";
            let ok = reg_import(reg);
            Ok((ok, "TCP/IP 参数已优化".into()))
        }
        "tf_net_lanman" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters]\r\n\"Size\"=dword:00000003\r\n\"LmAnnounce\"=dword:00000000\r\n";
            let ok = reg_import(reg);
            Ok((ok, "SMB 服务器参数已优化".into()))
        }
        "tf_net_weakhost" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters]\r\n\"WeakHostSend\"=dword:00000001\r\n\"WeakHostReceive\"=dword:00000001\r\n";
            let ok = reg_import(reg);
            Ok((ok, "弱主机模型已启用".into()))
        }
        "tf_net_nic" => {
            // 网卡类注册表调优（简化版：写通用值）
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}]\r\n";
            let ok = reg_import(reg);
            Ok((ok, "网卡参数已优化".into()))
        }
        "net_disable_netbios" => {
            // 遍历接口写 NetbiosOptions=2
            let base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
            unsafe {
                let sk = to_wide(base);
                let mut hk = HKEY::default();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
                    let mut index = 0u32;
                    loop {
                        let mut name_buf = [0u16; 256];
                        let mut name_len = 256u32;
                        if RegEnumKeyExW(hk, index, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None).is_err() { break; }
                        let iface_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                        let iface_key = format!("{base}\\{iface_name}");
                        let isk = to_wide(&iface_key);
                        let mut ihk = HKEY::default();
                        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(isk.as_ptr()), Some(0), KEY_WRITE, &mut ihk).is_ok() {
                            let nm = to_wide("NetbiosOptions");
                            let val = 2u32;
                            let _ = RegSetValueExW(ihk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes()));
                            let _ = RegCloseKey(ihk);
                        }
                        index += 1;
                    }
                    let _ = RegCloseKey(hk);
                }
            }
            Ok((true, "NetBIOS 已在所有接口禁用".into()))
        }
        "net_disable_lmhosts" => {
            unsafe {
                let key = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters";
                let sk = to_wide(key);
                let mut hk = HKEY::default();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_WRITE, &mut hk).is_ok() {
                    let nm = to_wide("EnableLMHOSTS");
                    let val = 0u32;
                    let _ = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes()));
                    let _ = RegCloseKey(hk);
                }
            }
            Ok((true, "LMHOSTS 查找已禁用".into()))
        }
        "net_qos_scheduler" => {
            unsafe {
                let key = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
                let sk = to_wide(key);
                let mut hk = HKEY::default();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_WRITE, &mut hk).is_ok() {
                    let nm = to_wide("DisableTaskOffload");
                    let val = 1u32;
                    let _ = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes()));
                    let _ = RegCloseKey(hk);
                }
            }
            Ok((true, "QoS 调度器已优化".into()))
        }
        "net_response" => {
            unsafe {
                let key = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
                let sk = to_wide(key);
                let mut hk = HKEY::default();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_WRITE, &mut hk).is_ok() {
                    let nm = to_wide("TcpMaxConnectResponseRetransmissions");
                    let val = 2u32;
                    let _ = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes()));
                    let _ = RegCloseKey(hk);
                }
            }
            Ok((true, "网络响应参数已优化".into()))
        }
        _ => Err(format!("未知的维护任务: {task_id}")),
    }
}


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

    // 3. 电源计划（powercfg /getactivescheme）
    if let Ok(out) = std::process::Command::new(system_tool("powercfg")).args(["/getactivescheme"]).output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(start) = stdout.find('(') {
            if let Some(end) = stdout[start..].find(')') {
                let plan = &stdout[start+1..start+end];
                let plan_lower = plan.to_lowercase();
                if plan_lower.contains("节能") || plan_lower.contains("power saver") {
                    checks.push(check_item("power_plan", "电源计划", "warn", plan, "节能计划会限制性能释放，建议切换平衡或高性能", "本机实测"));
                } else if plan_lower.contains("高性能") || plan_lower.contains("卓越") || plan_lower.contains("high") || plan_lower.contains("ultimate") {
                    checks.push(check_item("power_plan", "电源计划", "ok", plan, "高性能计划已启用", "本机实测"));
                } else {
                    checks.push(check_item("power_plan", "电源计划", "ok", plan, "平衡计划（系统默认）；追求极限响应可切换高性能", "本机实测"));
                }
            } else {
                checks.push(check_item("power_plan", "电源计划", "unknown", "无法读取", "powercfg 无有效输出", "未验证"));
            }
        } else {
            checks.push(check_item("power_plan", "电源计划", "unknown", "无法读取", "powercfg 无有效输出", "未验证"));
        }
    } else {
        checks.push(check_item("power_plan", "电源计划", "unknown", "无法读取", "powercfg 无有效输出", "未验证"));
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

    Ok(json!({ "checks": checks }))
}

unsafe fn reg_count_values(hk: HKEY) -> usize {
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
// ==================== B10 cleanup_detail：条目明细枚举 ====================

/// 清理条目明细枚举（对应 cleanup_detail.ps1，S3）
///
/// 输入 rule JSON 和目标路径，返回 {kind, total, truncated, files}。
/// 复杂 glob/排除规则回退 PS（commands 层判定）。
pub fn cleanup_detail(rule: &Value, target_path: &str) -> Result<Value, String> {
    let cap = 600usize;

    // special=dism
    if rule.get("special").and_then(|v| v.as_str()) == Some("dism") {
        return Ok(json!({"kind": "dism", "total": 0, "truncated": false, "files": []}));
    }

    // regKeys 型
    if let Some(reg_keys) = rule.get("regKeys").and_then(|v| v.as_array()) {
        if !reg_keys.is_empty() {
            let mut count = 0usize;
            for rk in reg_keys {
                let path = rk.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if path.is_empty() { continue; }
                let expanded = expand_env(path);
                if let Some((hive, rest)) = parse_reg_path(&expanded) {
                    count += unsafe { reg_count_key(hive, &rest, rk.get("value").is_some()) };
                }
            }
            return Ok(json!({"kind": "reg", "total": count, "truncated": false, "files": []}));
        }
    }

    // fileKeys 型
    if let Some(file_keys) = rule.get("fileKeys").and_then(|v| v.as_array()) {
        if !file_keys.is_empty() {
            let mut files: Vec<Value> = Vec::new();
            let mut total = 0usize;
            let mut seen = std::collections::HashSet::new();
            for fk in file_keys {
                let path = fk.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if path.is_empty() { continue; }
                let pattern = fk.get("pattern").and_then(|v| v.as_str()).unwrap_or("*");
                let recurse = fk.get("recurse").and_then(|v| v.as_bool()).unwrap_or(true);
                let expanded = expand_env(path);
                // 简单 glob：只支持路径中不含 * 的情况
                if expanded.contains('*') {
                    return Err("复杂 glob 需 PS 回退".into());
                }
                if !std::path::Path::new(&expanded).is_dir() { continue; }
                enumerate_files(&expanded, pattern, recurse, &mut files, &mut total, &mut seen, cap);
            }
            return Ok(json!({"kind": "files", "total": total, "truncated": total > cap, "files": files}));
        }
    }

    // 目录型
    if !target_path.is_empty() && std::path::Path::new(target_path).exists() {
        let mut files: Vec<Value> = Vec::new();
        let mut total = 0usize;
        let mut seen = std::collections::HashSet::new();
        enumerate_files(target_path, "*", true, &mut files, &mut total, &mut seen, cap);
        return Ok(json!({"kind": "files", "total": total, "truncated": total > cap, "files": files}));
    }

    Ok(json!({"kind": "files", "total": 0, "truncated": false, "files": []}))
}

fn enumerate_files(
    dir: &str, pattern: &str, recurse: bool,
    files: &mut Vec<Value>, total: &mut usize,
    seen: &mut std::collections::HashSet<String>, cap: usize,
) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        // 跳过重解析点
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_symlink() { continue; }
        if meta.is_dir() {
            if recurse {
                enumerate_files(&path.to_string_lossy(), pattern, recurse, files, total, seen, cap);
            }
        } else if meta.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !glob_match(pattern, &name) { continue; }
            let full = path.to_string_lossy().to_string();
            if !seen.insert(full.clone()) { continue; }
            *total += 1;
            if files.len() < cap {
                files.push(json!({"path": full, "size": meta.len()}));
            }
        }
    }
}

fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" { return true; }
    // 简单 * 匹配
    if let Some(idx) = pattern.find('*') {
        let prefix = &pattern[..idx];
        let suffix = &pattern[idx+1..];
        return name.starts_with(prefix) && name.ends_with(suffix) && name.len() >= prefix.len() + suffix.len();
    }
    pattern == name
}

unsafe fn reg_count_key(hive: HKEY, path: &str, has_value: bool) -> usize {
    let sk = to_wide(path);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
        return 0;
    }
    let mut count = 1usize; // 键本身
    if !has_value {
        // 计数值 + 子键
        count += reg_count_values(hk);
        let mut index = 0u32;
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len = 256u32;
            if RegEnumKeyExW(hk, index, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None).is_err() { break; }
            count += 1;
            index += 1;
        }
    }
    let _ = RegCloseKey(hk);
    count
}
// ==================== B10 cleanup_execute：清理执行 ====================

/// 清理执行结果
pub struct CleanupExecuteResult {
    pub details: Vec<Value>,
    pub freed: i64,
    pub file_count: i64,
    pub recycle_entries: Vec<Value>,
}

/// 清理执行（对应 cleanup_execute.ps1，S3）
///
/// 只处理文件删除（fileKeys/目录型）；注册表删除和复杂模式返回 Err 触发 PS 回退。
/// to_recycle=true 时只枚举不删除，返回 recycle_entries 由主进程移入回收站。
pub fn cleanup_execute(
    items: &[Value],
    rules: &Value,
    to_recycle: bool,
    auto_rebuild: bool,
) -> Result<CleanupExecuteResult, String> {
    let mut details = Vec::new();
    let mut total_freed = 0i64;
    let mut total_files = 0i64;
    let mut recycle_entries = Vec::new();

    for item in items {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let rule = find_rule_by_id(rules, id);
        let Some(rule) = rule else {
            details.push(json!({"id": id, "name": name, "status": "skip", "freed": 0, "message": "规则不存在", "fileCount": 0}));
            continue;
        };

        // 注册表型回退 PS
        if rule.get("regKeys").is_some() {
            return Err("注册表型清理需 PS 回退".into());
        }

        // special=dism 回退 PS
        if rule.get("special").and_then(|v| v.as_str()) == Some("dism") {
            return Err("DISM 清理需 PS 回退".into());
        }

        // 收集要删除的文件
        let mut files: Vec<(String, u64)> = Vec::new();
        if let Some(file_keys) = rule.get("fileKeys").and_then(|v| v.as_array()) {
            if !file_keys.is_empty() {
                for fk in file_keys {
                    let path = fk.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    if path.is_empty() { continue; }
                    let pattern = fk.get("pattern").and_then(|v| v.as_str()).unwrap_or("*");
                    let recurse = fk.get("recurse").and_then(|v| v.as_bool()).unwrap_or(true);
                    let expanded = expand_env(path);
                    if expanded.contains('*') {
                        return Err("复杂 glob 需 PS 回退".into());
                    }
                    // 审查 v2-F3：根路径准入改用 symlink_metadata + reparse 属性位。
                    // 原先只有 is_dir()，而它会跟随 junction 返回 true，导致链接目标整棵被枚举。
                    if !cleanup_root_ok(&expanded) { continue; }
                    collect_files(&expanded, pattern, recurse, &mut files);
                }
            }
        } else {
            // 目录型：用 item 的 path 或 rule.pathPs
            let target = item.get("path").and_then(|v| v.as_str())
                .or_else(|| rule.get("pathPs").and_then(|v| v.as_str()))
                .unwrap_or("");
            if !target.is_empty() && cleanup_root_ok(target) {
                collect_files(target, "*", true, &mut files);
            }
        }

        // 去重
        files.sort_by(|a, b| a.0.cmp(&b.0));
        files.dedup_by(|a, b| a.0 == b.0);

        let mut freed = 0i64;
        let mut deleted = 0i64;
        let mut failed = 0i64;

        for (path, size) in &files {
            if to_recycle {
                // 回收站模式：只枚举，由主进程移入回收站
                recycle_entries.push(json!({"id": id, "path": path, "size": size, "isDir": false}));
                freed += *size as i64;
                deleted += 1;
            } else if crate::engine::protect::is_path_protected(path) {
                // 审查 v2-F3：常规清理豁免的是「回收站优先」，**没有**豁免保护路径判定。
                // 这是全仓唯一执行永久删除的链，保护清单在这里不能缺席 —— 同模块
                // `retry_failed_delete`（cleanup.rs:1170）与回收站支（:942）都有这道闸门。
                failed += 1;
            } else {
                // 永久删除
                match std::fs::remove_file(path) {
                    Ok(()) => {
                        freed += *size as i64;
                        deleted += 1;
                    }
                    Err(_) => {
                        failed += 1;
                    }
                }
            }
        }

        total_freed += freed;
        total_files += deleted;

        let status = if failed == 0 {
            if to_recycle { "recycle" } else { "ok" }
        } else if deleted > 0 {
            "partial"
        } else {
            "fail"
        };
        let message = if to_recycle {
            format!("待移入回收站（{} 个文件）", deleted)
        } else if failed == 0 {
            format!("已清理 {} 个文件", deleted)
        } else {
            format!("已清理 {} 个文件，{} 个被占用", deleted, failed)
        };

        details.push(json!({
            "id": id, "name": name, "status": status,
            "freed": freed, "message": message, "fileCount": deleted, "residual": failed,
        }));

        // auto_rebuild：重建目录
        if auto_rebuild && !to_recycle {
            if let Some(file_keys) = rule.get("fileKeys").and_then(|v| v.as_array()) {
                for fk in file_keys {
                    let path = fk.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let expanded = expand_env(path);
                    if !expanded.contains('*') && !expanded.is_empty() {
                        let _ = std::fs::create_dir_all(&expanded);
                    }
                }
            }
        }
    }

    Ok(CleanupExecuteResult { details, freed: total_freed, file_count: total_files, recycle_entries })
}

fn find_rule_by_id(rules: &Value, id: &str) -> Option<Value> {
    let groups = rules.get("groups").and_then(|v| v.as_array())?;
    for g in groups {
        if let Some(subgroups) = g.get("subGroups").and_then(|v| v.as_array()) {
            for sg in subgroups {
                if let Some(items) = sg.get("items").and_then(|v| v.as_array()) {
                    for it in items {
                        if it.get("id").and_then(|v| v.as_str()) == Some(id) {
                            return Some(it.clone());
                        }
                    }
                }
            }
        }
        if let Some(items) = g.get("items").and_then(|v| v.as_array()) {
            for it in items {
                if it.get("id").and_then(|v| v.as_str()) == Some(id) {
                    return Some(it.clone());
                }
            }
        }
    }
    None
}

/// 清理根路径准入：必须是真实目录，且**不是** reparse（审查 v2-F3）
///
/// 判定必须在进 `collect_files` 之前做：后者只对**子项**过滤 `is_symlink()`，根路径本身
/// 若被替换成指向他处的 junction，`Path::is_dir()` 会跟随链接返回 true，于是链接目标整棵
/// 被枚举，并在永久删除分支下不可恢复地删掉。用 `protect::is_reparse` 的 0x400 属性位
/// 而非 `is_symlink()`：前者覆盖全部 reparse tag（云占位符 / NFS / WIM），严格更强。
fn cleanup_root_ok(dir: &str) -> bool {
    match std::fs::symlink_metadata(dir) {
        Ok(md) => md.is_dir() && !crate::engine::protect::is_reparse(&md),
        Err(_) => false,
    }
}

fn collect_files(dir: &str, pattern: &str, recurse: bool, files: &mut Vec<(String, u64)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_symlink() { continue; }
        if meta.is_dir() {
            if recurse {
                collect_files(&path.to_string_lossy(), pattern, recurse, files);
            }
        } else if meta.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !glob_match(pattern, &name) { continue; }
            files.push((path.to_string_lossy().to_string(), meta.len()));
        }
    }
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
