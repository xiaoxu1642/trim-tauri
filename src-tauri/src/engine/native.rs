//! B1 PS→Rust 迁移：低风险只读采集的原生 Windows API 实现
//!
//! 四个函数对应四个原 PS 脚本，输出 JSON 字段与原脚本逐字段兼容：
//! - `memory_info`      ← memory_info.ps1
//! - `memory_processes` ← memory_processes.ps1（@@PROC@@ 协议）
//! - `realtime_adapters` ← realtime_adapters.ps1
//! - `realtime_loss`    ← realtime_loss.ps1
//!
//! 状态：S1（NativeFirst）。调用方先试本模块，失败自动回退 PS。
//! 权限拒绝、参数非法等不应回退——由调用方按错误类型判断。

use serde_json::{json, Value};

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

pub fn stubborn_block() -> Result<Value, String> {
    // S1：服务/注册表/计划任务的原生实现待 S2 完善。
    // 当前直接返回错误，由调用方回退 PS 完整执行。
    Err("stubborn_block 原生路径待实现（S2）".to_string())
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

/// 读注册表 DWORD，失败返回 -1
unsafe fn read_reg_dword(hkey: HKEY, subkey: &str, value: &str) -> i32 {
    let sk = to_wide(subkey);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hkey, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
        return -1;
    }
    let vn = to_wide(value);
    let mut ty = REG_VALUE_TYPE::default();
    let mut buf = [0u8; 4];
    let mut size = 4u32;
    let r = RegQueryValueExW(
        hk, PCWSTR(vn.as_ptr()), None, Some(&mut ty),
        Some(buf.as_mut_ptr()), Some(&mut size),
    );
    RegCloseKey(hk);
    if r.is_err() || ty != REG_DWORD { return -1; }
    i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
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
    // S1 简化：不实现 GetFileVersionInfoW，留空
    // 后续 S2 用 VerQueryValueW 实现
    String::new()
}

/// 启动项扫描（对应 startup_scan.ps1）
///
/// S1：注册表 Run/RunOnce + 启动文件夹 + StartupApproved + disabled.json 合并。
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
            let sk = to_wide(subkey);
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
                // .lnk 目标解析 S2 实现，S1 用文件路径
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
    if let Ok(output) = std::process::Command::new("schtasks")
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
    RegCreateKeyExW, RegSetValueExW, RegDeleteTreeW,
    REG_OPTION_NON_VOLATILE, KEY_WRITE, REG_CREATE_KEY_DISPOSITION,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::Foundation::{INVALID_HANDLE_VALUE, WIN32_ERROR};

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
            let sk = to_wide(subkey);
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
        ProcessIdToSessionId(std::process::id(), &mut my_session);

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
use windows::Win32::Foundation::{HMODULE, HANDLE, FreeLibrary};

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

/// 右键菜单扫描（对应 cm_scan.ps1，S1 简化版）
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