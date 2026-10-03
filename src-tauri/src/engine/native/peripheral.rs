//! B3 外设只读查询 + B9 外设优化 apply / restore。
//!
//! 写侧（apply/restore）的备份落点仍走 `engine::paths`，恢复只认自己备份目录里的文件。


use crate::engine::systembin::system_tool;
use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_CREATED_NEW_KEY, REG_DWORD, REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegSetValueExW};
use super::common::*;
use super::registry::*;

/// 键盘类驱动参数父键（队列深度 + 端口路由三值共用）。
pub(super) const KBD_PARAMS: &str =
    r"SYSTEM\CurrentControlSet\Services\kbdclass\Parameters";

// ==================== B3：外设只读查询 ====================


/// 外设状态查询（对应 peripheral_query.ps1）
pub fn peripheral_query() -> Result<Value, String> {
    unsafe {
        let win32 = read_reg_dword(HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation");
        let keyboard = read_reg_dword(HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\kbdclass\Parameters", "KeyboardDataQueueSize");
        let mouse = read_reg_dword(HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize");
        // 2026-10-03：键盘端口路由三值（同一父键 kbdclass\Parameters）。
        // 为什么单独读：它们决定「一次按键事件往几个端口广播、识别几个设备」，
        // 与队列深度是两件事，却共用一个父键 —— 拆分读才能在界面上分开讲清。
        let kbd_connect_multiple = read_reg_dword(HKEY_LOCAL_MACHINE,
            KBD_PARAMS, "ConnectMultiplePorts");
        let kbd_max_ports = read_reg_dword(HKEY_LOCAL_MACHINE,
            KBD_PARAMS, "MaximumPortsServed");
        let kbd_send_all = read_reg_dword(HKEY_LOCAL_MACHINE,
            KBD_PARAMS, "SendOutputToAllPorts");
        Ok(json!({
            "win32": win32,
            "keyboard": keyboard,
            "mouse": mouse,
            "kbdConnectMultiple": kbd_connect_multiple,
            "kbdMaxPorts": kbd_max_ports,
            "kbdSendAll": kbd_send_all,
        }))
    }
}

// ==================== B9 peripheral_apply：外设优化应用 ====================

/// 外设优化应用（对应 peripheral_apply.ps1，S3）
///
/// 写入 HKLM 注册表值：Win32PrioritySeparation、KeyboardDataQueueSize、MouseDataQueueSize，
/// 以及 2026-10-03 新增的键盘端口路由三值（`kbdports` 一组三值，按预设档位成组写入）。
/// 写入前备份每个父键到 `%APPDATA%\Trim\peripheral-backup\backup_<stamp>_<n>.reg`。
/// options 中值为 -1 表示跳过该项。
pub fn peripheral_apply(options: &Value) -> Result<(), String> {
    // 端口路由预设：(档位, ConnectMultiplePorts, MaximumPortsServed, SendOutputToAllPorts)
    //
    // 为什么成组而不是三个独立单选：这三值描述的是**同一件事**（一次按键往几个端口发），
    // 拆成三组单选会让用户拼出「不合并 + 只服务 1 端口 + 不广播」这类无意义组合，
    // 而且每个值都偏离驱动默认时行为不可预测。按预设成组写，语义才闭合。
    //
    // 档 1 = Windows 驱动默认（kbdclass 出厂即 ConnectMultiplePorts=0 / MaxPorts=3 /
    // SendAll=1），也是本机当前值；档 2 关闭多端口合并与全端口广播（单键鼠精简）；
    // 档 3 拉高服务端口数（多键盘/带扩展坞的机型）。
    const KBD_PORT_PRESETS: &[(i64, i64, i64, i64)] = &[
        (1, 0, 3, 1),
        (2, 0, 1, 0),
        (3, 1, 6, 1),
    ];
    let kbd_ports = options
        .get("kbdports")
        .and_then(|v| v.as_i64())
        .unwrap_or(-1);
    let kbd_preset = KBD_PORT_PRESETS.iter().find(|(g, ..)| *g == kbd_ports).copied();

    let mut targets: Vec<(&str, &str, &str, i64)> = vec![
        ("win32", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation",
         options.get("win32").and_then(|v| v.as_i64()).unwrap_or(-1)),
        ("keyboard", KBD_PARAMS, "KeyboardDataQueueSize",
         options.get("keyboard").and_then(|v| v.as_i64()).unwrap_or(-1)),
        ("mouse", r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize",
         options.get("mouse").and_then(|v| v.as_i64()).unwrap_or(-1)),
    ];
    if let Some((_, connect, max_ports, send_all)) = kbd_preset {
        // 三值同父键 ⇒ 备份只导一次（见下方「按父键去重」），否则会产出三份同内容分片，
        // 还原时白白多导两次。
        targets.push(("kbd_connect", KBD_PARAMS, "ConnectMultiplePorts", connect));
        targets.push(("kbd_maxports", KBD_PARAMS, "MaximumPortsServed", max_ports));
        targets.push(("kbd_sendall", KBD_PARAMS, "SendOutputToAllPorts", send_all));
    }

    // 备份目录（v2-M19：写入恒新根，还原侧按新老两根找最新一批）
    let backup_dir = crate::engine::paths::backup_write_dir("peripheral-backup");
    std::fs::create_dir_all(&backup_dir).map_err(|e| format!("创建备份目录失败: {e}"))?;
    let stamp = crate::engine::now_ms().to_string();

    // 备份每个需要修改的父键
    //
    // **按父键去重**（2026-10-03）：`keyboard` 与三个 `kbd_*` 值共用 kbdclass\Parameters，
    // 不去重就会对同一个键连导三份内容完全相同的 .reg —— 还原时白白多跑两次 reg import，
    // 备份目录还多占两份空间。判据是「本次要写的父键集合」，不是「要写的值个数」。
    let mut part = 0;
    let mut backed_up: Vec<&str> = Vec::new();
    for (_key, subkey, _name, value) in &targets {
        if *value < 0 { continue; }
        if backed_up.contains(subkey) { continue; }
        backed_up.push(subkey);
        part += 1;
        let reg_path = format!("HKLM\\{subkey}");
        let backup_file = backup_dir.join(format!("backup_{stamp}_{part}.reg"));
        // 审查 v3-L7：非 UTF-8 路径上 to_str() 为 None，整批中止（备份不完整绝不能继续写入）
        let Some(backup_file_str) = backup_file.to_str() else { return Err("备份路径无法编码".into()); };
        // v2-L4P-29（B-7）：备份类子进程统一走带超时入口
        let out = crate::engine::systembin::quiet_cmd_timeout(
            system_tool("reg.exe"),
            &["export", &reg_path, backup_file_str, "/y"],
            crate::engine::systembin::REG_EXPORT_TIMEOUT,
        );
        if !out.map(|o| o.status.success()).unwrap_or(false) {
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
/// 找数据目录（含收口前的老根 `%APPDATA%\Trim\peripheral-backup`）里最新一批
/// `backup_<stamp>_*.reg`，按时间戳分组整组导入（v2-M12：一次 apply 留下多个分片，必须整组还原）。
/// 返回 ok/reason/restored/total/file。
pub fn peripheral_restore() -> Result<Value, String> {
    let files = collect_peripheral_backup_files(&crate::engine::paths::backup_read_dirs("peripheral-backup"));
    if files.is_empty() {
        return Ok(json!({"ok": false, "reason": "no-backup", "restored": 0, "total": 0, "file": ""}));
    }

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
        // A6（v2-R4）：原生 import。原先「路径非 UTF-8 就跳过」（审查 v3-L7）随 reg.exe
        // 一起消失 —— 那档跳过会让 imported 少计、回执变成 partial，而原因用户看不见。
        if crate::engine::reg_backup::reg_import_apply(f).is_ok() {
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

