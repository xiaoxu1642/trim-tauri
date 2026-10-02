//! B7 运行库检测/修复 + B8 网络连通性检测/修复。
//!
//! status 两个是只读采集（注册表 + API 枚举），repair 会跑系统命令，一律经 `system_tool`
//! 解析到 System32（v2-F7 红线，禁裸进程名）。


use crate::engine::systembin::system_tool;
use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, RegCloseKey, RegOpenKeyExW, RegSetValueExW};
use super::common::*;
use super::registry::*;
use super::services::*;
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
        let winhttp_out = crate::engine::systembin::quiet_cmd(system_tool("netsh"))
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
    // 审查 v3-M1：dism.exe 是 PINNED 裸名，必须经 system_tool 解析到 System32 ——
    // 便携版/提权实例场景下，CreateProcessW 的搜索顺序里 exe 所在目录与 CWD 都排在
    // System32 之前，裸名会以管理员权限执行植入的同名工具。安装包路径不在 PINNED，
    // system_tool 原样放行，不受影响。
    let out = crate::engine::systembin::quiet_cmd(system_tool(program))
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
            let out = crate::engine::systembin::quiet_cmd(system_tool("netsh"))
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
            let out = crate::engine::systembin::quiet_cmd(system_tool("netsh"))
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
            let out = crate::engine::systembin::quiet_cmd(system_tool("sc"))
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
            let out = crate::engine::systembin::quiet_cmd(system_tool("sc"))
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
            let out = crate::engine::systembin::quiet_cmd(system_tool("netsh"))
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
