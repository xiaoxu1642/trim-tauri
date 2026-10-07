//! realtime:adapters / realtime:loss —— 网卡枚举与丢包统计（只读采集）。
//! 纯原生（S3）：失败如实返回错误，**不存在 PS 回退**。


use serde_json::{Value, json};
use super::common::*;
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
    let sub_w = to_wide(&sub);
    let name_w = to_wide("Name");

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

            // 审查 2026-09-27 M1：S_un.S_addr 本身已是网络字节序（WinSock 语义），
            // 直接 to_be_bytes() 会二次反转成反序地址（192.168.31.1 → 1.31.168.192）。
            // 先按网络序语义还原成主机序数值，再序列化回网络序，跨平台口径自洽。
            let b = u32::from_be(gw_net).to_be_bytes();
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
                // 无默认网关 = 没有可探测的下一跳，不构成「100% 丢包」这个结论。
                // 回 null 让渲染层显示 `--` 并收起风险徽标（旧写法与同卡详情
                // 「暂无法检测丢包」直接矛盾）。
                "lossRate": Value::Null,
                "latencyMs": 0,
            }))
        }
    }
}
