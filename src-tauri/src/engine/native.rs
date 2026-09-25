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