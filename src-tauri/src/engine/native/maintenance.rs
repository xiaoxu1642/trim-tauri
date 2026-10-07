//! B8 维护任务 + 计划任务变更出口 + 「删目录前是否被阻挡」判定。
//!
//! `dir_delete_blocked` 是跨命令复用的公判据（diskbench / uninstall 都在用），
//! maint_reparse_tests 与实现同在本文件。maint_run 内跑子进程一律走 `system_tool`，
//! 且有 `MAINT_CMD_TIMEOUT` 上限。


use crate::engine::systembin::system_tool;
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_CREATED_NEW_KEY, REG_DWORD, REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegEnumKeyExW, RegOpenKeyExW, RegSetValueExW};
use super::common::*;
// ==================== 维护任务删目录前校验测试（审查 v2-L1 回归网） ====================

#[cfg(test)]
mod maint_reparse_tests {
    use super::*;
    use std::path::Path;

    /// 真实系统目录（及其到盘符根的整条链）必须放行 —— 防「为了防误删把功能废掉」。
    /// search / wu 清理的目标目录正是这类固定系统路径。
    #[test]
    fn real_system_dirs_pass() {
        for p in [
            r"C:\Windows\System32",
            r"C:\Windows\SoftwareDistribution",
        ] {
            assert!(
                dir_delete_blocked(Path::new(p)).is_none(),
                "真实系统目录不得被阻断: {p} — {:?}",
                dir_delete_blocked(Path::new(p))
            );
        }
    }

    /// 属性读不到的路径（不存在 / 无权限）必须按拒绝处理：
    /// 「查不到」不许等价于「安全」（fail-closed）。
    #[test]
    fn unreadable_path_is_refused() {
        let r = dir_delete_blocked(Path::new(r"C:\TrimNoSuchDir-9f3a\DataStore"));
        assert!(r.is_some(), "不存在的路径必须拒绝删除，实测: {r:?}");
    }
}


/// 启用/禁用计划任务（对应 `Disable/Enable-ScheduledTask`，与启动项链同一工具）
///
/// `path` 为含尾反斜杠的任务路径（如 `\Microsoft\Windows\Defrag\`），与数据层 `taskPath` 同形。
pub fn task_change(path: Option<&str>, name: &str, disable: bool) -> Result<(), String> {
    let full = format!("{}{}", path.unwrap_or_default(), name);
    let arg = if disable { "/DISABLE" } else { "/ENABLE" };
    let output = crate::engine::systembin::quiet_cmd(system_tool("schtasks"))
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

// ==================== B8 maint：维护命令 ====================

/// 维护任务子进程超时上限（v2-L4P-37 / F-6）：sfc /scannow 与 DISM RestoreHealth
/// 合法耗时可达数十分钟，30 分钟取模块文档的既有上限；sc/wsreset 等快命令被同一
/// 上限兜住（正常毫秒级，永到不了）。此前 run_cmd 无超时——挂住的 sfc 会把维护
/// 页永久锁死。登记于 check-ps-callsites 的 F 组（quiet_cmd_timeout 调用点）。
pub const MAINT_CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// wsreset.exe 的超时上限（v5 S-1）：它自己会拉起商店窗口并清缓存，正常几秒自退；
/// 60s 是宽限上界。刻意不复用 MAINT_CMD_TIMEOUT —— 那是 sfc/DISM 的量级，
/// 拿 30 分钟兜一个恒挂的 wsreset 等于把维护锁占死半小时。
pub const WSRESET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn run_cmd(program: &str, args: &[&str]) -> bool {
    // 审查 v2-F7：系统工具必须解析到 System32 再执行，不能用裸进程名 ——
    // 搜索顺序里「exe 所在目录」与「父进程 CWD」都排在 System32 之前。
    let exe = crate::engine::systembin::system_tool(program);
    match crate::engine::systembin::quiet_cmd_timeout(exe, args, MAINT_CMD_TIMEOUT) {
        Ok(out) if out.status.success() => true,
        // v5 S-4：失败必须留痕。旧写法把 stdout/stderr 全丢，于是 sfc /scannow 的三态结论
        // （未发现问题 / 已修复 / 无法修复）与 30 分钟超时被折叠成同一句「检查失败」，
        // 用户无从判断该不该再跑一次。只留尾 400 字，避免整份 CBS 报告灌进日志文件。
        Ok(out) => {
            let clip = |s: &str| -> String {
                s.trim().chars().rev().take(400).collect::<Vec<_>>().into_iter().rev().collect()
            };
            crate::engine::log::write_log(
                "warn",
                &format!(
                    "维护命令未成功: {program} {args:?} exit={:?} stdout=「{}」stderr=「{}」",
                    out.status.code().unwrap_or(-1),
                    clip(&String::from_utf8_lossy(&out.stdout)),
                    clip(&String::from_utf8_lossy(&out.stderr)),
                ),
            );
            false
        }
        Err(e) => {
            crate::engine::log::write_log("warn", &format!("维护命令无法执行: {program} — {e}"));
            false
        }
    }
}

/// 当前服务状态码（`SERVICE_STOPPED`=1 / `SERVICE_RUNNING`=4）；查不到返回 None。
fn service_state(name: &str) -> Option<u32> {
    unsafe { super::services::service_status(name).map(|(s, _)| s) }
}

/// 请求停止服务并**轮询到 STOPPED**（v5 S-2 / S-3）。
///
/// `sc stop` 是异步的：返回 0 只代表停止请求被受理。旧写法固定睡 2s（search/wu）或 500ms
/// （restart_service）就当停稳，于是索引库文件仍被占用时 `remove_dir_all` 必然失败，
/// 而结果又被 `let _ =` 吞掉。
fn stop_service_wait(name: &str, budget: std::time::Duration) -> bool {
    let sc = crate::engine::systembin::system_tool("sc");
    let _ = crate::engine::systembin::quiet_cmd_timeout(&sc, &["stop", name], MAINT_CMD_TIMEOUT);
    let deadline = std::time::Instant::now() + budget;
    loop {
        if service_state(name) == Some(1) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// 请求启动服务并轮询到 RUNNING（同上：`sc start` 返回 0 时服务可能还在 START_PENDING）
fn start_service_wait(name: &str) -> bool {
    if !run_cmd("sc", &["start", name]) {
        return false;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if service_state(name) == Some(4) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn restart_service(name: &str) -> bool {
    // v5 S-3：旧写法 `let _ = quiet_cmd_timeout(..).is_ok()` 把停止结果丢掉（写了等于没写），
    // 服务仍在运行时紧接着 `sc start` 会返回 1056（已在运行）→ 在**正常机器**上恒报
    // 「音频服务重启失败」。改成按终态走：在跑就先停稳再启，本就停着则直接启。
    match service_state(name) {
        None => false, // 服务不存在：不谎报「重启成功」
        Some(4) => {
            stop_service_wait(name, std::time::Duration::from_secs(15)) && start_service_wait(name)
        }
        Some(_) => start_service_wait(name),
    }
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

/// 删除固定目录前的重解析点（junction / 符号链接）校验
///
/// 审查 v2-L1：`maint_run` 的 search / wu 两条会对**固定系统目录**做 `remove_dir_all`，
/// 此前不查属性位。若目标或其任一上级被换成指向别处的 junction（误操作、软件搬家、
/// 恶意替换都可能），`remove_dir_all` 会顺着链接把目标位置的内容删掉——「清缓存」
/// 变成删数据。因此删前从自身到盘符根逐层查 `FILE_ATTRIBUTE_REPARSE_POINT`。
///
/// 返回 `Some(原因)` = 拒绝删除（含属性读不到：fail-closed，不许「查不到就当安全」）。
pub(crate) fn dir_delete_blocked(path: &std::path::Path) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT};
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
    // Path::ancestors() 自带「自身 → 逐级父目录 → 根」，正是要逐层查的链
    for level in path.ancestors() {
        let wide = to_wide(&level.to_string_lossy());
        let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            return Some(format!("无法读取目录属性（{}），按拒绝处理", level.display()));
        }
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Some(format!("{} 是重解析点（junction/符号链接），删除会波及链接目标", level.display()));
        }
    }
    None
}

/// 维护命令执行（对应 maint_*.ps1，S3）
///
/// 覆盖任务数以 data/maintenance-tasks.json 现算为准（v2-L4P-55/C-10：注释计数必须与数据同源，散文数字已删）。返回 (success, output_message)。
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
            // v5 S-1：旧写法 `let _ = …spawn(); Ok((true, …))` 是**恒真回执** —— wsreset 缺失、
            // 被组策略拦、启动即崩，都照样报「已完成」；且 spawn 不 wait：子进程无人收、无超时、
            // 不在任何登记表。改成等退出码（wsreset 正常几秒内自退，60s 是宽限上界）。
            match crate::engine::systembin::quiet_cmd_timeout(
                system_tool("wsreset.exe"),
                &[],
                WSRESET_TIMEOUT,
            ) {
                Ok(o) if o.status.success() => Ok((true, "Store 缓存已清理".into())),
                Ok(o) => Ok((false, format!(
                    "wsreset 未成功（exit={}）",
                    o.status.code().unwrap_or(-1)
                ))),
                Err(e) => Ok((false, format!("wsreset 无法执行: {e}"))),
            }
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
            // 审查 v2-L1：删前校验放在**停服务之前** —— 校验不通过就整条不执行，
            // 免得服务停了却什么也没清（用户只看到「搜索服务重启失败」）。
            let idx = std::path::PathBuf::from(r"C:\ProgramData\Microsoft\Search\Data\Applications\Windows");
            if let Some(reason) = dir_delete_blocked(&idx) {
                crate::engine::log::write_log("warn", &format!("维护：search 索引目录删除被拒 — {reason}"));
                return Ok((false, format!("搜索索引目录未通过删除前校验，已取消：{reason}")));
            }
            // 停止 WSearch → 删索引 → 启动。三步各按终态判，删除结果必须进回执（v5 S-2）。
            // 停不稳就**不删**：半途删一个被占用的索引库只会留下更坏的状态。
            if !stop_service_wait("WSearch", std::time::Duration::from_secs(20)) {
                return Ok((false, "WSearch 未能在时限内停止，已取消删除（避免删半个索引库），请稍后重试".into()));
            }
            let removed = std::fs::remove_dir_all(&idx);
            let started = start_service_wait("WSearch");
            let ok = removed.is_ok() && started;
            let rm_msg = match &removed {
                Ok(()) => "索引已清空，将在后台重建".to_string(),
                Err(e) => format!("索引删除失败: {e}"),
            };
            Ok((ok, format!("{rm_msg}；服务{}", if started { "已重启" } else { "重启失败" })))
        }
        "wu" => {
            let cache = std::path::PathBuf::from(r"C:\Windows\SoftwareDistribution\DataStore");
            if let Some(reason) = dir_delete_blocked(&cache) {
                crate::engine::log::write_log("warn", &format!("维护：wu 缓存目录删除被拒 — {reason}"));
                return Ok((false, format!("更新缓存目录未通过删除前校验，已取消：{reason}")));
            }
            // 停止更新服务，清理缓存，启动（v5 S-2：同上，逐个轮询到 STOPPED 再删）
            for svc in ["wuauserv", "bits", "cryptsvc"] {
                if !stop_service_wait(svc, std::time::Duration::from_secs(20)) {
                    // 已经停掉的几个要恢复启动，别把它们留在停止态
                    for done in ["wuauserv", "bits", "cryptsvc"] {
                        if done == svc { break; }
                        let _ = start_service_wait(done);
                    }
                    return Ok((false, format!("{svc} 未能在时限内停止，已取消删除更新缓存").into()));
                }
            }
            let removed = std::fs::remove_dir_all(&cache);
            let mut ok = removed.is_ok();
            for svc in ["wuauserv", "bits", "cryptsvc"] {
                ok &= start_service_wait(svc);
            }
            let rm_msg = match &removed {
                Ok(()) => "更新缓存已清空".to_string(),
                Err(e) => format!("更新缓存删除失败: {e}"),
            };
            Ok((ok, format!("{rm_msg}；服务{}", if ok { "已重启" } else { "重启部分失败" })))
        }
        "tf_net_tcp" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile]\r\n\"NetworkThrottlingIndex\"=dword:ffffffff\r\n\"SystemResponsiveness\"=dword:0000000a\r\n";
            let mut ok = reg_import(reg);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "global", "autotuninglevel=disabled", "ecncapability=disabled", "dca=enabled", "rsc=disabled", "rss=enabled", "timestamps=disabled"]);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "global", "rssbasecpu=1"]);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "heuristics", "disabled"]);
            ok &= run_cmd("netsh.exe", &["int", "ip", "set", "global", "neighborcachelimit=4096"]);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "supplemental", "Internet", "congestionprovider=ctcp"]);
            Ok((ok, if ok { "TCP 全局参数已优化".into() } else { "TCP 全局参数部分命令未成功（详见操作日志）".into() }))
        }
        "tf_net_tcpip" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters]\r\n\"Tcp1323Opts\"=dword:00000001\r\n\"TcpMaxDupAcks\"=dword:00000002\r\n\"SackOpts\"=dword:00000001\r\n";
            let ok = reg_import(reg);
            Ok((ok, if ok { "TCP/IP 参数已优化".into() } else { "TCP/IP 参数写入未成功（详见操作日志）".into() }))
        }
        "tf_net_lanman" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters]\r\n\"Size\"=dword:00000003\r\n\"LmAnnounce\"=dword:00000000\r\n";
            let ok = reg_import(reg);
            Ok((ok, if ok { "SMB 服务器参数已优化".into() } else { "SMB 服务器参数写入未成功（详见操作日志）".into() }))
        }
        "tf_net_weakhost" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters]\r\n\"WeakHostSend\"=dword:00000001\r\n\"WeakHostReceive\"=dword:00000001\r\n";
            let ok = reg_import(reg);
            Ok((ok, if ok { "弱主机模型已启用".into() } else { "弱主机模型启用未成功（详见操作日志）".into() }))
        }
        // 审查 2026-09-27 M5：本分支此前是「空操作假成功」——.reg 只有节头零值行，
        // reg_import 只会建空类键却报「网卡参数已优化」。真正的网卡级调优需要遍历
        // 每个网卡实例子键（PnP 路径），误写通用键有断网风险，故整任务下线而非补实现。
        "net_disable_netbios" => {
            // 遍历接口写 NetbiosOptions=2；审查 2026-09-27 M7：写失败不再静默吞掉，
            // 按成功写入数如实回传，0 个接口写入成功即为失败
            let base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
            let mut written = 0u32;
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
                            if RegSetValueExW(ihk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes())).is_ok() {
                                written += 1;
                            }
                            let _ = RegCloseKey(ihk);
                        }
                        index += 1;
                    }
                    let _ = RegCloseKey(hk);
                }
            }
            if written > 0 {
                Ok((true, format!("NetBIOS 已在 {written} 个接口禁用")))
            } else {
                Ok((false, "未能禁用任何接口的 NetBIOS（注册表写入失败）".into()))
            }
        }
        "net_disable_lmhosts" => {
            // 审查 2026-09-27 M7：RegSetValueExW 失败不再被 let _ 吞掉后谎报成功
            let ok = unsafe {
                let key = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters";
                let sk = to_wide(key);
                let mut hk = HKEY::default();
                let opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_WRITE, &mut hk);
                if opened.is_ok() {
                    let nm = to_wide("EnableLMHOSTS");
                    let val = 0u32;
                    let set = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes()));
                    let _ = RegCloseKey(hk);
                    set.is_ok()
                } else {
                    false
                }
            };
            Ok((ok, if ok { "LMHOSTS 查找已禁用".into() } else { "LMHOSTS 注册表写入失败（键不存在或被策略保护）".into() }))
        }
        "net_qos_scheduler" => {
            // 审查 2026-09-27 M6：补文案承诺的 NonBestEffortLimit=0（PSched 策略键）；
            // DisableTaskOffload=1 是本任务实际写入的另一参数（关闭 TCP 任务卸载），
            // 统一走 reg_import 并检查结果，不再「打开键失败也报成功」
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Psched]\r\n\"NonBestEffortLimit\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters]\r\n\"DisableTaskOffload\"=dword:00000001\r\n";
            let ok = reg_import(reg);
            Ok((ok, if ok { "QoS 保留带宽已取消，TCP 任务卸载已关闭".into() } else { "QoS 参数写入失败".into() }))
        }
        "net_response" => {
            // 审查 2026-09-27 M6：补文案承诺的网络节流键（NetworkThrottlingIndex 拉满
            // = 禁用多媒体播放时的网络节流）；SystemResponsiveness 不在此处写——
            // tf_net_tcp 已按其文案写 10，两任务对该键取值不同，避免隐式互相覆盖
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile]\r\n\"NetworkThrottlingIndex\"=dword:ffffffff\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters]\r\n\"TcpMaxConnectResponseRetransmissions\"=dword:00000002\r\n";
            let ok = reg_import(reg);
            Ok((ok, if ok { "网络节流已关闭，连接响应重传已收紧".into() } else { "网络响应参数写入失败".into() }))
        }
        _ => Err(format!("未知的维护任务: {task_id}")),
    }
}

