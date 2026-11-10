//! B3 外设只读查询 + B9 外设优化 apply / restore。
//!
//! 写侧（apply/restore）的备份落点仍走 `engine::paths`，恢复只认自己备份目录里的文件。


use crate::engine::systembin::system_tool;
use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_CREATED_NEW_KEY, REG_DWORD, REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegSetValueExW};
use windows::Win32::Foundation::SYSTEMTIME;
use windows::Win32::System::SystemInformation::GetLocalTime;
use super::common::*;
use super::registry::*;

// ==================== B3：外设只读查询 ====================


/// 外设状态查询（原 PS 时代脚本 peripheral_query.ps1，已退役）
///
/// 只读两组：Win32PrioritySeparation 与 MouseDataQueueSize。键盘队列深度与端口路由
/// 已于 0.6.6 从本窗下线（收编进优化中心 tf_keyboard），不再读取。
pub fn peripheral_query() -> Result<Value, String> {
    // R5c-L04：旧入口用 -1 表示失败，而 0xFFFFFFFF 转 i32 也是 -1（哨兵与合法值撞车）。
    // 改用 Option 口径：读不到 ⇒ null，前端按「未知」显示，不再把假值当数据。
    let win32 = read_reg_dword_u32_as_i64(HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation");
    let mouse = read_reg_dword_u32_as_i64(HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize");
    Ok(json!({
        "win32": win32,
        "mouse": mouse,
    }))
}

// ==================== B9 peripheral_apply：外设优化应用 ====================

/// 备份文件名时间戳：`YYYYMMDD_HHMMSS`（本地时间）。
///
/// R5e-L01：解析侧 `commands::peripheral::backup_batch_of` 只认 15 位 `YYYYMMDD_HHMMSS`，
/// 而旧生成侧用 `now_ms()` 的 13 位毫秒串——生成的备份永远无法被 prune/restore 识别，
/// 既不修剪也无上限增长。生成侧改为与解析侧同一格式，roundtrip 成立。
pub(crate) fn backup_stamp() -> String {
    let t: SYSTEMTIME = unsafe { GetLocalTime() };
    format!(
        "{:04}{:02}{:02}_{:02}{:02}{:02}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
    )
}

/// 顺序写入一组 HKLM 值；后续键失败时回滚已写键，并返回带 win32 码与
/// `admin_required` 提示的错误。
///
/// `write_one(subkey, name, value)` 返回 `Err(win32 错误码)`；`read_one` 返回原值
/// （`None` = 原本不存在）；`restore_one(subkey, name, original)` 把值恢复原状。
///
/// R5e-L07：旧实现第一个键写成功后第二个键失败，直接返回 Err——第一个键的修改
/// 已落盘却不回滚，回执也没有 win32 码/权限提示，用户看到的是含糊的「写入失败」。
fn write_peripheral_values(
    targets: &[(&str, &str, &str, i64)],
    mut write_one: impl FnMut(&str, &str, u32) -> Result<(), u32>,
    mut read_one: impl FnMut(&str, &str) -> Option<i64>,
    mut restore_one: impl FnMut(&str, &str, Option<i64>) -> Result<(), u32>,
) -> Result<(), String> {
    // (subkey, name, 原值)
    let mut written: Vec<(&str, &str, Option<i64>)> = Vec::new();
    for (_key, subkey, name, value) in targets {
        if *value < 0 { continue; }
        let original = read_one(subkey, name);
        if let Err(code) = write_one(subkey, name, *value as u32) {
            // 回滚已写键（逆序），任一回滚失败都要如实报告。
            for (w_sub, w_name, orig) in written.iter().rev() {
                if let Err(rollback_code) = restore_one(w_sub, w_name, *orig) {
                    return Err(format!(
                        "写入 {name} 失败（win32 {code}），且回滚 {w_sub}\\{w_name} 也失败（win32 {rollback_code}）"
                    ));
                }
            }
            let admin_hint = if code == 5 { "，需要管理员权限" } else { "" };
            return Err(format!(
                "写入 {name} 失败（win32 错误 {code}{admin_hint}）"
            ));
        }
        written.push((subkey, name, original));
    }
    Ok(())
}

/// 外设优化应用（原 PS 时代脚本 peripheral_apply.ps1，已退役；S3）
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
    let stamp = backup_stamp();

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
        // v2-L4P-29（B-7）：备份类子进程统一走带超时入口
        // v6-K01（P0-2）：解析失败走既有 Err 回执（备份不完整绝不写入）
        // B2-2：导出写到**中转件**，落位由 land_backup 判根后 rename 完成 ——
        // 旧实现把 reg.exe 直接指到目标路径，备份根被换成 junction 时会落在链接另一头。
        // 原来那条「backup_file.to_str() 为 None 就整批中止」（v3-L7）现在由中转件路径承担，
        // 语义不变：编码不出来就报错、绝不继续写入。
        crate::engine::backup_write::land_backup(&backup_dir, &backup_file, |stage| {
            let stage_str = stage
                .to_str()
                .ok_or_else(|| "备份路径无法编码".to_string())?;
            let exe = system_tool("reg.exe")?;
            let ok = crate::engine::systembin::quiet_cmd_timeout(
                exe,
                &["export", &reg_path, stage_str, "/y"],
                crate::engine::systembin::REG_EXPORT_TIMEOUT,
            )
            .map(|o| o.status.success())
            .unwrap_or(false);
            if ok {
                Ok(())
            } else {
                Err("注册表备份失败".into())
            }
        })?;
        // K11（v6）/ R5b-K01：新生成的备份必须写**两份锚**（HKLM）：边车封条 +
        // HKLM 管理员摘要（`write_reg_backup_seals` 按目标根分流，只有 HKLM 才写后者；
        // 摘要存非提权进程写不了的键，是系统级备份的防伪根）。还原侧与 cleanup/uninstall
        // 共用同一个强化闸（`reg_backup_restore_guards`）——同用户往备份目录投放自制
        // `.reg` + 自算边车不再能通过：缺管理员摘要的 HKLM 备份一律拒。
        // 写失败不阻断本次 apply（备份本体已写成；还原侧会按 fail-closed 拒），
        // 日志留痕由 write_reg_backup_seals 内部完成。
        crate::engine::reg_backup::write_reg_backup_seals("peripheral", &backup_file, &reg_path);
    }

    // 写入值（R5e-L07：顺序写 + 失败回滚 + win32 码/admin_required 提示）
    write_peripheral_values(
        &targets,
        |subkey, name, val| {
            unsafe {
                let sk = to_wide(subkey);
                let mut hk = HKEY::default();
                let mut disp = REG_CREATED_NEW_KEY;
                let cr = RegCreateKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), None,
                    PCWSTR::default(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut hk, Some(&mut disp));
                if cr.is_err() {
                    return Err(cr.0);
                }
                let nm = to_wide(name);
                let r = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes()));
                let _ = RegCloseKey(hk);
                if r.is_err() {
                    return Err(r.0);
                }
                // R5e-M01：写后回读——策略/重定向可能把值改成别的数，不能凭 Set 返回成功就报绿。
                let actual = read_reg_dword_u32_as_i64(HKEY_LOCAL_MACHINE, subkey, name);
                if actual != Some(val as i64) {
                    // 用非权限错误码（1 = ERROR_INVALID_FUNCTION）表示回读不一致。
                    return Err(1);
                }
                Ok(())
            }
        },
            |subkey, name| read_reg_dword_u32_as_i64(HKEY_LOCAL_MACHINE, subkey, name),
        |subkey, name, original| {
            unsafe {
                let sk = to_wide(subkey);
                let mut hk = HKEY::default();
                let mut disp = REG_CREATED_NEW_KEY;
                let cr = RegCreateKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), None,
                    PCWSTR::default(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut hk, Some(&mut disp));
                if cr.is_err() {
                    return Err(cr.0);
                }
                let nm = to_wide(name);
                let r = match original {
                    Some(v) => RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&(v as u32).to_le_bytes())),
                    None => RegDeleteValueW(hk, PCWSTR(nm.as_ptr())),
                };
                let _ = RegCloseKey(hk);
                if r.is_err() { Err(r.0) } else { Ok(()) }
            }
        },
    )
}
// ==================== B9 peripheral_restore：外设优化恢复 ====================



/// 外设还原准入（R5b-K01）：与 cleanup/uninstall 共用同一个强化闸
/// [`crate::engine::reg_backup::reg_backup_restore_guards`]（域 = `"peripheral"`）。
///
/// 此前这里只有两条手写判据（边车封条 + 拒 `[-HKEY…]` 段），而同仓强化闸还有：
/// 只允许 HKLM/HKCU 根、逐键目标判定（外设域是两条真实父键及其子键的精确白名单，
/// 比通用受保护容器判据更窄）、`is_admin`、HKLM 管理员摘要核对。
/// 外设备份目录是用户可写目录，同一用户可同时投放自制 `.reg` 并自算边车 ⇒ 缺了
/// 管理员摘要这道信任根，提权实例会把任意 HKLM 值写进注册表（user→admin 提权）。
/// 现在本地一条判据都不重写：闸的回执 `sections`
/// （[`crate::engine::reg_backup::AdmittedSections`]）直接交给执行臂。
///
/// 本次改造前生成、没有管理员摘要的旧备份会按「没有管理员摘要」被拒——fail-closed 是
/// 刻意的：请先应用一次优化生成新备份，或重装目标软件后重新应用。
fn peripheral_restore_admit(
    f: &std::path::Path,
    name: &str,
) -> Result<crate::engine::reg_backup::AdmittedSections, String> {
    peripheral_restore_admit_with(f, name, crate::engine::sysinfo::is_admin())
}

/// 与 [`peripheral_restore_admit`] 同一判据；`is_admin` 由调用方给，
/// 让闸能拿临时目录静默测（与 `reg_backup_restore_guards` 的同名参数同一理由）。
fn peripheral_restore_admit_with(
    f: &std::path::Path,
    name: &str,
    is_admin: bool,
) -> Result<crate::engine::reg_backup::AdmittedSections, String> {
    crate::engine::reg_backup::reg_backup_restore_guards(f, name, "peripheral", is_admin)
        .map(|chk| chk.sections)
}

/// 从备份恢复外设设置（原 PS 时代脚本 peripheral_restore.ps1，已退役；S3）
///
/// 找数据目录（含收口前的老根 `%APPDATA%\Trim\peripheral-backup`）里最新一批
/// `backup_<stamp>_*.reg`，按时间戳分组整组导入（v2-M12：一次 apply 留下多个分片，必须整组还原）。
/// 返回 ok/reason/restored/total/file；K11 起另带 `rejected`（逐份拒绝原因）。
pub fn peripheral_restore() -> Result<Value, String> {
    let (files, unreadable_dirs) =
        collect_peripheral_backup_files(&crate::engine::paths::backup_read_dirs("peripheral-backup"));
    if files.is_empty() {
        // A1-M05：「备份目录读不动」≠「还没有备份」——前者要用户去查权限/IO，
        // 后者是正常首用状态。旧实现把两者一起报成 no-backup。
        let reason = if unreadable_dirs > 0 { "unreadable" } else { "no-backup" };
        return Ok(json!({
            "ok": false, "reason": reason, "restored": 0, "total": 0,
            "file": "", "rejected": [], "unreadableDirs": unreadable_dirs,
        }));
    }

    // 按时间戳分组
    let latest_name = files[0].file_name().and_then(|n| n.to_str()).unwrap_or("");
    let stamp = if let Some(caps) = regex_capture(latest_name, r"^backup_(\d{8}_\d{6})") {
        caps
    } else {
        // R5e-M02：文件名时间戳不是 ASCII `YYYYMMDD_HHMMSS` 时不能按字节切片猜；
        // 记日志并按「不可识别」返回，不做半批导入。
        crate::engine::log::write_log("warn", &format!("外设备份文件名时间戳无法解析，已跳过: {latest_name}"));
        return Ok(json!({
            "ok": false, "reason": "unreadable-name", "restored": 0,
            "total": files.len(), "file": latest_name, "rejected": [],
            "unreadableDirs": unreadable_dirs,
        }));
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
    for &f in &group {
        let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // K11 / R5b-K01：先过与 cleanup/uninstall 同一套强化闸，闸的解析产物直接交给执行臂
        let sections = match peripheral_restore_admit(f, name) {
            Ok(s) => s,
            Err(reason) => {
                crate::engine::log::write_log("warn", &format!("外设备份拒绝导入: {name} -> {reason}"));
                rejected.push(json!({ "file": name, "reason": reason }));
                continue;
            }
        };
        // A6（v2-R4）：原生 import。原先「路径非 UTF-8 就跳过」（审查 v3-L7）随 reg.exe
        // 一起消失 —— 那档跳过会让 imported 少计、回执变成 partial，而原因用户看不见。
        // P2-05：导入失败也要带统计与原因（部分写入后失败，用户得知道动了多少）。
        match crate::engine::reg_backup::reg_import_apply_sections(&sections) {
            Ok(_) => imported += 1,
            Err(e) => {
                let file_name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
                crate::engine::log::write_log(
                    "warn",
                    &format!("外设备份导入失败: {file_name} -> {}", e.user_message()),
                );
            }
        }
    }
    let total = group.len() as i64;
    let ok = imported > 0 && imported == total;
    // 全部被拒且拒因都是「不可验证/含删除段」⇒ 单独一档，回执能说清是"备份不可信"
    // 而不是"导入失败/文件损坏"（两者的处置完全不同：前者找 Trim 生成的备份，
    // 后者重试）。部分导入成功仍走 partial（既有文案）。
    let reason = peripheral_restore_reason(imported, total, rejected.len(), unreadable_dirs);

    Ok(json!({
        "ok": ok,
        "reason": reason,
        "restored": imported,
        "total": total,
        "file": latest_name,
        "rejected": rejected,
        "unreadableDirs": unreadable_dirs,
    }))
}

/// 还原回执的 reason 判定（纯函数 —— 文件系统那部分难在单测里复现，判定本身不该依赖它）。
///
/// `ok` 为真但另有备份根**读不动** ⇒ `partial-unknown`：外设备份按父键分片
/// （新根可读、老根读不动 ⇒ 同批次的另一片消失），而 `total` 会跟着变小 ⇒
/// 「已还原 1/1」是假完整（回归条 R5b-M26）。
pub(super) fn peripheral_restore_reason(
    imported: i64,
    total: i64,
    rejected: usize,
    unreadable_dirs: usize,
) -> &'static str {
    if !(imported > 0 && imported == total) {
        if imported == 0 && rejected > 0 { return "unverifiable"; }
        if imported == 0 { return "import-failed"; }
        return "partial";
    }
    if unreadable_dirs > 0 { return "partial-unknown"; }
    ""
}

fn regex_capture(text: &str, pattern: &str) -> Option<String> {
    // 简单正则：backup_(\d{8}_\d{6})；只用字符串切分，避免非 ASCII 名字上的字节切片 panic。
    if pattern == r"^backup_(\d{8}_\d{6})" {
        let rest = text.strip_prefix("backup_")?;
        let (date, rest) = rest.split_once('_')?;
        let (time, _tail) = rest.split_once('_')?;
        if date.len() == 8
            && time.len() == 6
            && date.chars().all(|c| c.is_ascii_digit())
            && time.chars().all(|c| c.is_ascii_digit())
        {
            return Some(format!("{date}_{time}"));
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
        let err =
            peripheral_restore_admit_with(&f, "backup_20261018_203000_1.reg", true).unwrap_err();
        assert!(
            err.contains("缺少边车封条"),
            "HKLM 备份无封条必须拒（封条 missing 对 HKLM 不放行）: {err}"
        );
    }

    /// R5b-K01 判据本体：同用户可同时改写「备份 + 边车」，**自算边车的自制 `.reg`
    /// 在读入阶段就被 HKLM 管理员摘要闸拒**——边车自洽不再是通行证。
    ///
    /// 零写入：准入返回 Err 时执行臂 `reg_import_apply_sections` 从未被调用，
    /// 不存在任何写注册表的动作（本用例不写真实 HKLM，管理员摘要只读）。
    ///
    /// 判红自证：把 admit 退回「只比边车 + 拒删除段」的手写实现 ⇒ 本用例两条断言全红
    /// （自洽边车会被放行，只剩提权白名单一条路可拦）。
    #[test]
    fn 自算边车的伪造备份必拒_未提权或缺管理员摘要() {
        let d = TempDir::new("forged");
        let f = d.0.join("backup_20261018_203000_1.reg");
        std::fs::write(&f, format!("{HDR}{LEGIT}")).unwrap();
        // 攻击者自算边车：内容与封条完全自洽（seal = ok）
        crate::engine::reg_backup::write_reg_backup_seal(
            &f,
            r"HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl",
        );
        let err = peripheral_restore_admit_with(&f, "backup_20261018_203000_1.reg", false)
            .unwrap_err();
        assert!(err.contains("管理员"), "非提权实例必须拒: {err}");
        let err =
            peripheral_restore_admit_with(&f, "backup_20261018_203000_1.reg", true).unwrap_err();
        assert!(
            err.contains("管理员摘要"),
            "提权但缺管理员摘要必须拒（自算边车不算信任根）: {err}"
        );
    }

    /// 外设域的合法目标（Trim 真实导出的两个父键）必须过目标白名单，只停在提权/摘要闸上；
    /// 目标面之外的键（哪怕边车自洽）一律在准入阶段拒 —— 外设还原只能写回自己动过的两个键。
    ///
    /// 「合法（Trim 提权生成、有管理员摘要）⇒ 可还原」的放行判据需要真机 HKLM 管理员摘要
    /// （单测写不出，如实标未验证）；同一判据由 `reg_backup` 的单测
    /// `伪造自洽边车的hklm备份仍被管理员摘要拒` 第 ④ 段以注入摘要覆盖。
    #[test]
    fn 合法目标不被白名单误伤_面外目标一律拒() {
        let d = TempDir::new("scope");
        // ① 合法目标：非提权 ⇒ 停在提权闸（而不是「外设还原面之外」）
        let legit = d.0.join("backup_20261018_203000_1.reg");
        std::fs::write(&legit, format!("{HDR}{LEGIT}")).unwrap();
        crate::engine::reg_backup::write_reg_backup_seal(
            &legit,
            r"HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl",
        );
        let err = peripheral_restore_admit_with(&legit, "backup_20261018_203000_1.reg", false)
            .unwrap_err();
        assert!(
            err.contains("需要以管理员身份运行"),
            "合法目标必须过目标白名单，停在提权闸: {err}"
        );
        assert!(!err.contains("外设还原面之外"), "合法目标不得被白名单误伤: {err}");
        // ② 面外目标：HKLM 任意键 / 任意 HKCU 段，即使边车自洽也拒
        for (tag, section, target) in [
            (
                "out-hklm.reg",
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\TrimK01OutOfScope]\r\n\"X\"=dword:00000001\r\n",
                r"HKLM\SOFTWARE\TrimK01OutOfScope",
            ),
            (
                "out-hkcu.reg",
                "[HKEY_CURRENT_USER\\Software\\TrimK01OutOfScope]\r\n\"X\"=dword:00000001\r\n",
                r"HKCU\Software\TrimK01OutOfScope",
            ),
        ] {
            let f = d.0.join(tag);
            std::fs::write(&f, format!("{HDR}{section}")).unwrap();
            crate::engine::reg_backup::write_reg_backup_seal(&f, target);
            let err = peripheral_restore_admit_with(&f, tag, true).unwrap_err();
            assert!(err.contains("外设还原面之外"), "{tag} 必须被目标白名单拒: {err}");
        }
    }

    /// 删除段先于封条判定：`[-HKEY…]` 段即使边车自洽也整份拒（Trim 的导出从不含
    /// 删除段；整键删除不可逆）。
    #[test]
    fn 含删除段的备份仍被拒() {
        let d = TempDir::new("sealeddel");
        let f = d.0.join("backup_20261018_203000_1.reg");
        std::fs::write(&f, format!("{HDR}{EVIL_DELETE}")).unwrap();
        crate::engine::reg_backup::write_reg_backup_seal(&f, r"HKLM\SOFTWARE\TrimFakeTarget");
        let err =
            peripheral_restore_admit_with(&f, "backup_20261018_203000_1.reg", true).unwrap_err();
        assert!(err.contains("删除键段"), "删除段必须拒: {err}");
    }

    /// 无封条 + 删除段：删除段判据在封条之前，拒因仍点名删除段（不是笼统「不可验证」）。
    #[test]
    fn 无封条含删除段的假备份必拒() {
        let d = TempDir::new("fakedel");
        let f = d.0.join("backup_20261018_203000_1.reg");
        std::fs::write(&f, format!("{HDR}{EVIL_DELETE}")).unwrap();
        let err =
            peripheral_restore_admit_with(&f, "backup_20261018_203000_1.reg", true).unwrap_err();
        assert!(err.contains("删除键段"), "删除段必须拒: {err}");
    }

    /// 封条不符（生成后被改动）⇒ 拒，且拒因点名封条（不是笼统失败）。
    #[test]
    fn 封条不符内容被改后必须拒() {
        let d = TempDir::new("mismatch");
        let f = d.0.join("backup_20261018_203000_1.reg");
        std::fs::write(&f, format!("{HDR}{LEGIT}")).unwrap();
        crate::engine::reg_backup::write_reg_backup_seal(&f, r"HKLM\x");
        // 封条写入后追加内容（模拟同用户改写备份）
        std::fs::write(&f, format!("{HDR}{LEGIT}\"Extra\"=dword:00000001\r\n")).unwrap();
        let err =
            peripheral_restore_admit_with(&f, "backup_20261018_203000_1.reg", true).unwrap_err();
        assert!(err.contains("封条"), "改后必须点明封条不符: {err}");
    }

    /// R5b-K01 静态钉：生成侧必须写两份锚（HKLM 还要写管理员摘要），不能退回单锚
    /// `write_reg_backup_seal` —— 单锚备份在还原闸里会按「缺管理员摘要」被拒，
    /// 表现成「Trim 自己生成的备份也还原不了」。
    /// 判红自证：把调用改回单锚 ⇒ 本断言红。
    #[test]
    fn 生成侧必须写管理员摘要() {
        let src = include_str!("peripheral.rs");
        let needle = concat!("write_reg_backup_", "seals(\"peripheral\"");
        assert!(
            src.contains(needle),
            "外设备份生成侧必须走 write_reg_backup_seals（HKLM 目标要写管理员摘要）"
        );
    }

    /// R5b-M26 回归钉：`ok` 为真但另有备份根读不动 ⇒ reason 必须是 partial-unknown，
    /// 否则回执把「只还原了一部分」说成「已全部还原」。
    #[test]
    fn 另有备份根读不动时回执不得说全部还原() {
        assert_eq!(peripheral_restore_reason(1, 1, 0, 0), "", "一切正常时无 reason");
        assert_eq!(peripheral_restore_reason(1, 1, 0, 2), "partial-unknown", "有读不动的根必须标不完整");
        assert_eq!(peripheral_restore_reason(1, 2, 0, 0), "partial", "只导进一部分仍是 partial");
        assert_eq!(peripheral_restore_reason(0, 2, 1, 0), "unverifiable", "全部被拒且有拒因");
        assert_eq!(peripheral_restore_reason(0, 2, 0, 0), "import-failed", "全部失败且无拒因");
    }
}

#[cfg(test)]
mod r5e_l07_tests {
    use super::*;

    /// R5e-L07：第二个键写失败时，第一个键必须被回滚，且错误带 win32 码与
    /// `admin_required` 提示。
    /// 判红自证：把 `write_peripheral_values` 的失败分支恢复成直接 `Err`
    /// （不回滚、不带 win32 码）⇒ 回滚断言与 win32 断言都红。
    #[test]
    fn r5e_peripheral_two_key_failure_is_partial() {
        let targets: Vec<(&str, &str, &str, i64)> = vec![
            ("win32", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", 38),
            ("mouse", r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize", 16),
        ];

        // 记录写操作与回滚操作。
        let mut writes: Vec<String> = Vec::new();
        let mut restores: Vec<String> = Vec::new();
        let write_one = |subkey: &str, name: &str, _val: u32| -> Result<(), u32> {
            writes.push(format!("{subkey}\\{name}"));
            if name == "MouseDataQueueSize" {
                Err(5) // 第二键失败：ERROR_ACCESS_DENIED
            } else {
                Ok(())
            }
        };
        let read_one = |_subkey: &str, _name: &str| -> Option<i64> { Some(2) };
        let restore_one = |subkey: &str, name: &str, original: Option<i64>| -> Result<(), u32> {
            restores.push(format!("{subkey}\\{name}={original:?}"));
            Ok(())
        };

        let err = write_peripheral_values(&targets, write_one, read_one, restore_one).unwrap_err();
        assert!(
            err.contains("win32 错误 5"),
            "错误必须带 win32 码：{err}"
        );
        assert!(
            err.contains("需要管理员权限"),
            "权限拒绝必须提示 admin_required：{err}"
        );
        assert_eq!(
            writes,
            vec![
                r"SYSTEM\CurrentControlSet\Control\PriorityControl\Win32PrioritySeparation",
                r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters\MouseDataQueueSize",
            ],
            "两个键都要尝试写"
        );
        assert_eq!(
            restores,
            vec![
                r"SYSTEM\CurrentControlSet\Control\PriorityControl\Win32PrioritySeparation=Some(2)",
            ],
            "第二键失败后第一键必须回滚到原值：{restores:?}"
        );
    }

    /// R5e-L07 正向对照：全部写成功时不得回滚。
    #[test]
    fn r5e_peripheral_all_keys_ok_no_rollback() {
        let targets: Vec<(&str, &str, &str, i64)> = vec![
            ("win32", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", 38),
            ("mouse", r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize", 16),
        ];
        let mut writes = 0;
        let mut restores = 0;
        let result = write_peripheral_values(
            &targets,
            |_, _, _| { writes += 1; Ok(()) },
            |_, _| Some(2),
            |_, _, _| { restores += 1; Ok(()) },
        );
        assert!(result.is_ok());
        assert_eq!(writes, 2);
        assert_eq!(restores, 0, "全部成功不得回滚");
    }
}

