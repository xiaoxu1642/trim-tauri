//! B3 外设只读查询 + B9 外设优化 apply / restore。
//!
//! 写侧（apply/restore）的备份落点仍走 `engine::paths`，恢复只认自己备份目录里的文件。


use crate::engine::systembin::system_tool;
use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_CREATED_NEW_KEY, REG_DWORD, REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegSetValueExW};
use super::common::*;
use super::registry::*;

// ==================== B3：外设只读查询 ====================


/// 外设状态查询（对应 peripheral_query.ps1）
///
/// 只读两组：Win32PrioritySeparation 与 MouseDataQueueSize。键盘队列深度与端口路由
/// 已于 0.6.6 从本窗下线（收编进优化中心 tf_keyboard），不再读取。
pub fn peripheral_query() -> Result<Value, String> {
    unsafe {
        let win32 = read_reg_dword(HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation");
        let mouse = read_reg_dword(HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize");
        Ok(json!({
            "win32": win32,
            "mouse": mouse,
        }))
    }
}

// ==================== B9 peripheral_apply：外设优化应用 ====================

/// 外设优化应用（对应 peripheral_apply.ps1，S3）
///
/// 写入 HKLM 注册表值：Win32PrioritySeparation、MouseDataQueueSize。
/// 键盘队列深度与端口路由已于 0.6.6 从本窗下线（收编进优化中心 tf_keyboard，
/// 固定写 8 + 驱动默认端口档）——本函数不再受理 `keyboard` / `kbdports` 键，
/// commands/peripheral.rs 的白名单同步删除，旧调用里多带这两个键会被静默忽略。
/// 写入前备份每个父键到 `%APPDATA%\Trim\peripheral-backup\backup_<stamp>_<n>.reg`。
/// options 中值为 -1 表示跳过该项。
pub fn peripheral_apply(options: &Value) -> Result<(), String> {
    let targets: Vec<(&str, &str, &str, i64)> = vec![
        ("win32", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation",
         options.get("win32").and_then(|v| v.as_i64()).unwrap_or(-1)),
        ("mouse", r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize",
         options.get("mouse").and_then(|v| v.as_i64()).unwrap_or(-1)),
    ];

    // 备份目录（v2-M19：写入恒新根，还原侧按新老两根找最新一批）
    let backup_dir = crate::engine::paths::backup_write_dir("peripheral-backup");
    std::fs::create_dir_all(&backup_dir).map_err(|e| format!("创建备份目录失败: {e}"))?;
    let stamp = crate::engine::now_ms().to_string();

    // 备份每个需要修改的父键
    //
    // **按父键去重**：判据是「本次要写的父键集合」，不是「要写的值个数」——同一父键有多个
    // 待写值时只导一次。0.6.6 起 targets 仅剩两个不同父键的单值，本守卫暂无触发场景；
    // 保留它是因为「同父键多值」在本域出现过（kbdclass 的队列深度 + 端口三值，2026-10-03
    // 为它引入去重），删掉会让未来再引入同类写组时静默重演「同一键连导多份 .reg」。
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
        // v6-K01（P0-2）：解析失败走既有 Err 回执（备份不完整绝不写入）
        let exe = system_tool("reg.exe")?;
        let out = crate::engine::systembin::quiet_cmd_timeout(
            exe,
            &["export", &reg_path, backup_file_str, "/y"],
            crate::engine::systembin::REG_EXPORT_TIMEOUT,
        );
        if !out.map(|o| o.status.success()).unwrap_or(false) {
            let _ = std::fs::remove_file(&backup_file);
            return Err("注册表备份失败".into());
        }
        // K11（v6）：**新生成的备份必须写边车封条**（同目录 `<file>.reg.meta.json`，
        // SHA-256 + 目标键）。还原侧只接受封条 `ok` 的备份——同用户往备份目录投放
        // 一份自制 .reg（哪怕不含删除段，也能覆盖任意键值）不再是可导入形态。
        // 封条写失败不阻断本次 apply（备份本体已写成；还原侧会按 fail-closed 拒），
        // 但要在日志里留下「这份备份将不可还原」的线索（write_reg_backup_seal 内部留痕）。
        crate::engine::reg_backup::write_reg_backup_seal(&backup_file, &reg_path);
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



/// K11（v6）：单份外设备份的还原准入（两条判据，全过才交给执行臂）。
///
/// ① **边车封条必须 `ok`**：`write_reg_backup_seal` 在备份生成时记 SHA-256；`missing`
///    意味着文件不是 Trim 生成（旧版本备份或同用户投放），按 D4 拍板默认拒导——
///    备份目录是用户可写的，没有封条时「还原」等价于「把任意 .reg 写进 HKLM」。
/// ② **解析产物不得含 `[-HKEY…]` 删除段**：Trim 的导出从不含删除段；出现即外来/被改，
///    整键删除的后果不可逆（这就是 K11 点名的「导入备份可能含删除段」）。
///
/// 返回**同一份**解析产物给 `reg_import_apply_sections`——闸与执行臂吃一次解析，
/// 不重演「校验一套、执行另一套」（v5-K06 A6-K01 的教训）。
fn peripheral_restore_admit(
    f: &std::path::Path,
) -> Result<Vec<crate::engine::reg_backup::RegSection>, String> {
    let (seal, _) = crate::engine::reg_backup::reg_backup_seal_state(f);
    if seal != "ok" {
        return Err(match seal {
            "missing" => "该备份不是 Trim 可验证备份（无封条：可能来自旧版本或外部投放），已拒绝导入".to_string(),
            "mismatch" => "备份内容与封条哈希不符（生成后被改动），已拒绝导入".to_string(),
            "corrupt" | "unreadable" => "备份封条损坏或不可读，已拒绝导入".to_string(),
            other => format!("备份封条状态异常（{other}），已拒绝导入"),
        });
    }
    let text = crate::engine::reg_backup::read_reg_text_file(f)
        .map_err(|_| "备份文件不是合法的 .reg（读不到或编码不可识别）".to_string())?;
    let sections = crate::engine::reg_backup::parse_reg_text(&text)
        .map_err(|_| "备份文件不是合法的 .reg（缺版本头或没有任何键段）".to_string())?;
    if let Some(sec) = sections.iter().find(|s| s.delete_key) {
        return Err(format!("备份含删除键段（[-{}]），已拒绝导入", sec.full_key()));
    }
    Ok(sections)
}

/// 从备份恢复外设设置（对应 peripheral_restore.ps1，S3）
///
/// 找数据目录（含收口前的老根 `%APPDATA%\Trim\peripheral-backup`）里最新一批
/// `backup_<stamp>_*.reg`，按时间戳分组整组导入（v2-M12：一次 apply 留下多个分片，必须整组还原）。
/// 返回 ok/reason/restored/total/file；K11 起另带 `rejected`（逐份拒绝原因）。
pub fn peripheral_restore() -> Result<Value, String> {
    let files = collect_peripheral_backup_files(&crate::engine::paths::backup_read_dirs("peripheral-backup"));
    if files.is_empty() {
        return Ok(json!({"ok": false, "reason": "no-backup", "restored": 0, "total": 0, "file": "", "rejected": []}));
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
    let mut rejected: Vec<Value> = Vec::new();
    for f in &group {
        // K11：先过准入（封条 + 删除段），闸的解析产物直接交给执行臂
        let sections = match peripheral_restore_admit(f) {
            Ok(s) => s,
            Err(reason) => {
                let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                crate::engine::log::write_log("warn", &format!("外设备份拒绝导入: {name} -> {reason}"));
                rejected.push(json!({ "file": name, "reason": reason }));
                continue;
            }
        };
        // A6（v2-R4）：原生 import。原先「路径非 UTF-8 就跳过」（审查 v3-L7）随 reg.exe
        // 一起消失 —— 那档跳过会让 imported 少计、回执变成 partial，而原因用户看不见。
        if crate::engine::reg_backup::reg_import_apply_sections(&sections).is_ok() {
            imported += 1;
        }
    }
    let total = group.len() as i64;
    let ok = imported > 0 && imported == total;
    // 全部被拒且拒因都是「不可验证/含删除段」⇒ 单独一档，回执能说清是"备份不可信"
    // 而不是"导入失败/文件损坏"（两者的处置完全不同：前者找 Trim 生成的备份，
    // 后者重试）。部分导入成功仍走 partial（既有文案）。
    let reason = if ok {
        String::new()
    } else if imported == 0 && !rejected.is_empty() {
        "unverifiable".to_string()
    } else if imported == 0 {
        "import-failed".into()
    } else {
        "partial".into()
    };

    Ok(json!({
        "ok": ok,
        "reason": reason,
        "restored": imported,
        "total": total,
        "file": latest_name,
        "rejected": rejected,
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

#[cfg(test)]
mod k11_restore_admit_tests {
    use super::*;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("trim-k11-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const HDR: &str = "Windows Registry Editor Version 5.00\r\n\r\n";
    const LEGIT: &str = "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl]\r\n\"Win32PrioritySeparation\"=dword:00000002\r\n";
    const EVIL_DELETE: &str = "[-HKEY_LOCAL_MACHINE\\SOFTWARE\\TrimFakeTarget]\r\n";

    #[test]
    fn 无封条备份必须拒导_内容合法也不放行() {
        let d = TempDir::new("noseal");
        let f = d.0.join("backup_20261018_203000_1.reg");
        std::fs::write(&f, format!("{HDR}{LEGIT}")).unwrap();
        let err = peripheral_restore_admit(&f).unwrap_err();
        assert!(err.contains("不是 Trim 可验证备份"), "拒因必须点明不可验证: {err}");
    }

    /// K11 判据本体：同用户投放的 .reg（`[-HKEY]` 整键删除段）在无封条时必拒。
    #[test]
    fn 无封条含删除段的假备份必拒() {
        let d = TempDir::new("fakedel");
        let f = d.0.join("backup_20261018_203000_1.reg");
        std::fs::write(&f, format!("{HDR}{EVIL_DELETE}")).unwrap();
        let err = peripheral_restore_admit(&f).unwrap_err();
        assert!(err.contains("不是 Trim 可验证备份"), "无封条先于内容判: {err}");
    }

    /// K11 判据：有封条且完整匹配的合法备份**放行到解析层**（返回同一份 sections）。
    #[test]
    fn 封条匹配的合法备份放行到解析层() {
        let d = TempDir::new("legit");
        let f = d.0.join("backup_20261018_203000_1.reg");
        std::fs::write(&f, format!("{HDR}{LEGIT}")).unwrap();
        crate::engine::reg_backup::write_reg_backup_seal(&f, r"HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl");
        let sections = peripheral_restore_admit(&f).expect("封条匹配必须放行");
        assert_eq!(sections.len(), 1);
        assert!(!sections[0].delete_key, "合法备份无删除段");
        assert!(sections[0].full_key().contains("PriorityControl"));
    }

    /// 封条匹配但内容含 `[-HKEY…]` 删除段 ⇒ 仍拒（Trim 的导出从不含删除段，
    /// 这种形态只能是外来/被改；整键删除不可逆）。
    #[test]
    fn 封条匹配但含删除段仍拒() {
        let d = TempDir::new("sealeddel");
        let f = d.0.join("backup_20261018_203000_1.reg");
        std::fs::write(&f, format!("{HDR}{EVIL_DELETE}")).unwrap();
        crate::engine::reg_backup::write_reg_backup_seal(&f, r"HKLM\SOFTWARE\TrimFakeTarget");
        let err = peripheral_restore_admit(&f).unwrap_err();
        assert!(err.contains("删除键段"), "删除段必须拒: {err}");
    }

    /// 封条不符（生成后被改动）⇒ 拒，且拒因说「已被改动」而不是笼统失败。
    #[test]
    fn 封条不符内容被改后必须拒() {
        let d = TempDir::new("mismatch");
        let f = d.0.join("backup_20261018_203000_1.reg");
        std::fs::write(&f, format!("{HDR}{LEGIT}")).unwrap();
        crate::engine::reg_backup::write_reg_backup_seal(&f, r"HKLM\x");
        // 封条写入后追加内容（模拟同用户改写备份）
        std::fs::write(&f, format!("{HDR}{LEGIT}\"Extra\"=dword:00000001\r\n")).unwrap();
        let err = peripheral_restore_admit(&f).unwrap_err();
        assert!(err.contains("与封条哈希不符"), "改后必须点明哈希不符: {err}");
    }
}

