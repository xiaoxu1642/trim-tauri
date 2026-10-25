//! 注册表 `.reg` 备份的**公共件**（N9，2026-09-29 抽自 `commands/uninstall.rs`）。
//!
//! 为什么要抽：清理域与卸载域各有一条「把备份 `.reg` import 回系统」的链，威胁模型逐字相同
//! ——都是"用户可写目录里的一份文件，被拿去写注册表"。此前只有卸载域收了口（严格解析 +
//! 逐键过禁删面 + 封条核对 + HKLM 要求已提权），清理域四道一道没有。同一模型两套口径，
//! 弱的那套就是入口。
//!
//! 更要紧的是 N1 之后清理域列表会**跨根**列出 Electron 轨写的 `.reg`（无封条、形状更不可信），
//! 弱链的输入面因此同步扩大 ⇒ 闸必须先补齐。
//!
//! 封条有两层（P0-01，2026-10-10）：边车封条与备份同在用户可写目录，同一用户可同时
//! 改写两者，所以它只提升「半截写入/手工误改」的误污染检测，不是防伪凭证；HKLM 备份
//! 另有管理员摘要（存 HKLM 下非提权进程写不了的键），还原时由提权实例自行重算哈希
//! 比对，这才是系统级备份的防伪闸门。非提权实例只允许还原 HKCU。
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// `a_1.reg` → `a_1.reg.meta.json`（同目录放封条，便于人工核对；列表按 .reg 收尾过滤，不会自纳）
pub fn reg_seal_path_for(file: &Path) -> PathBuf {
    let mut s = file.as_os_str().to_os_string();
    s.push(".meta.json");
    PathBuf::from(s)
}

/// 写封条：目标键 + SHA-256 + 时间。失败只在日志留痕，**不阻断删除**——
/// 封条是备份的增强，不是删除的前提（备份本身已写成，这时回滚删除反而更糟）。
pub fn write_reg_backup_seal(file: &Path, target: &str) {
    let sum = match crate::engine::hash::sha256_file(file) {
        Ok(s) => s,
        Err(e) => {
            crate::engine::log::write_log("warn", &format!("注册表备份封条计算失败（不阻断删除）: {e}"));
            return;
        }
    };
    let payload = json!({
        "file": file.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
        "target": target,
        "sha256": sum,
        "createdAt": crate::engine::now_ms(),
    });
    if let Err(e) = crate::security::atomic_write_json(&reg_seal_path_for(file), &payload) {
        crate::engine::log::write_log("warn", &format!("注册表备份封条写入失败（不阻断删除）: {e}"));
    }
}

/// 封条核对：ok / missing（旧备份没封条）/ mismatch（内容与封条不符）/ corrupt / unreadable
pub fn reg_backup_seal_state(file: &Path) -> (&'static str, Value) {
    let meta_path = reg_seal_path_for(file);
    let Ok(text) = std::fs::read_to_string(&meta_path) else {
        return ("missing", Value::Null);
    };
    let Ok(meta) = serde_json::from_str::<Value>(&text) else {
        return ("corrupt", Value::Null);
    };
    let want = meta.get("sha256").and_then(Value::as_str).unwrap_or("");
    if want.is_empty() {
        return ("corrupt", meta);
    }
    match crate::engine::hash::sha256_file(file) {
        Ok(got) if got.eq_ignore_ascii_case(want) => ("ok", meta),
        Ok(_) => ("mismatch", meta),
        Err(_) => ("unreadable", meta),
    }
}

// ==================== P0-01：HKLM 管理员摘要（2026-10-10） ====================
//
// 为什么需要它：边车封条与备份同在用户可写目录，同一用户可同时改写两者并自算哈希，
// 形状合法的毒备份因此能在管理员还原上下文写入注册表（user→admin 提权）；删边车让
// 状态变 `missing` 更是原样放行。闭合条件是摘要必须存放在「非提权进程写不了」的位置
// ⇒ HKLM 下默认仅 Administrators/SYSTEM 可写的键，且只能在已提权执行窗口内补写；
// HKLM 还原整体收进提权实例，由提权实例自行重算哈希与该摘要比对。
// 非提权实例只允许还原 HKCU（攻击者本就持有 HKCU 写权限，不构成提权）。

/// 管理员摘要存放键（HKLM）：默认 ACL 下仅 Administrators/SYSTEM 可写。
const ADMIN_SEAL_SUBKEY: &str = r"SOFTWARE\Trim\RegBackupSeals";

/// 摘要值名 = 域前缀/备份文件名：两域分开记账（cleanup / uninstall），防同名互顶。
fn admin_seal_value_name(domain: &str, file: &Path) -> Option<String> {
    let leaf = file.file_name()?.to_str()?;
    Some(format!("{domain}/{leaf}"))
}

/// 在已提权执行窗口补写管理员摘要。非提权时写 HKLM 失败：只留日志、不影响删除主链，
/// 但这份 HKLM 备份此后不能通过还原闸（fail-closed 是刻意的）。
pub fn write_admin_seal(domain: &str, file: &Path) {
    let Some(value_name) = admin_seal_value_name(domain, file) else { return };
    let Ok(sum) = crate::engine::hash::sha256_file(file) else { return };
    let ok = crate::engine::native::reg_restore_write(
        crate::engine::native::hive_hklm(),
        ADMIN_SEAL_SUBKEY,
        &value_name,
        REG_VALUE_TYPE(RK_SZ),
        &utf16_with_nul(&sum),
    );
    if !ok {
        crate::engine::log::write_log(
            "warn",
            &format!(
                "管理员摘要写入失败（当前可能非管理员会话，该 HKLM 备份将不能用于还原）: {value_name}"
            ),
        );
    }
}

/// 读管理员摘要；无记录返回 None（备份生成于非提权会话，或早于本安全版本）。
pub fn read_admin_seal(domain: &str, file: &Path) -> Option<String> {
    let value_name = admin_seal_value_name(domain, file)?;
    crate::engine::native::read_reg_string(
        crate::engine::native::hive_hklm(),
        ADMIN_SEAL_SUBKEY,
        &value_name,
    )
}

/// 对账纯判据：现存备份文件名集合 vs HKLM 摘要值名集合，返回应删除的孤立值名。
/// 拆成纯函数：真实 HKLM 读写归 #[ignore] 探针，此处逻辑在无窗单测覆盖。
fn stale_admin_seal_value_names(
    domain: &str,
    existing_files: &std::collections::HashSet<String>,
    value_names: &[String],
) -> Vec<String> {
    let prefix = format!("{domain}/");
    value_names
        .iter()
        .filter_map(|vn| {
            // 非本域值名不参与；本域但备份已不存在 ⇒ 待删
            vn.strip_prefix(&prefix)
                .filter(|leaf| !existing_files.contains(*leaf))
                .map(|_| vn.clone())
        })
        .collect()
}

/// 备份裁剪（prune_backups）之后对账：删除 HKLM 下指向已不存在备份的摘要，避免无限累积。
/// 必须在提权实例执行才真正删除；非提权静默跳过。
pub fn reconcile_admin_seals(domain: &str, dir: &Path) {
    let mut existing = std::collections::HashSet::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            if let Some(n) = ent.file_name().to_str() {
                if n.to_lowercase().ends_with(".reg") {
                    existing.insert(n.to_string());
                }
            }
        }
    }
    let hklm = crate::engine::native::hive_hklm();
    let (value_names, incomplete) = crate::engine::native::reg_enum_value_names_pub(hklm, ADMIN_SEAL_SUBKEY);
    if incomplete {
        // P1-6G：枚举不完整 ⇒ 「盘上还有哪些摘要」这个集合不可信。本轮放弃对账：
        // 拿一份被截断的「现存清单」去算孤立摘要，会把仍被引用的摘要当孤立件删掉。
        crate::engine::log::write_log("warn", "管理摘要对账：值名枚举不完整，本轮跳过（不删任何摘要）");
        return;
    }
    for vn in stale_admin_seal_value_names(domain, &existing, &value_names) {
        let _ = crate::engine::native::reg_restore_delete(hklm, ADMIN_SEAL_SUBKEY, &vn);
    }
}

/// 排除名单/备份等 `.reg` 文件的**编码感知**读取。
///
/// 为什么必须有这条：`reg.exe export` 的默认产物是 **UTF-16LE + BOM**（本机实测：
/// `startup-backup\deleted\1790707622496_reg_360safeuninst.reg` 前 2 字节 `FF FE`），
/// 而本应用自己的写入器（`native.rs` 的 `f.write_all(b"Windows Registry Editor...")`）
/// 和优化器步骤体产出的是**裸 UTF-8/ASCII**。此前 `parse_reg_backup` 用
/// `fs::read_to_string` 读，对 UTF-16 那份直接 `Err` → 严格解析判 None →
/// **还原闸把 `reg.exe export` 产的备份一律拒成「不是合法的 .reg」**。
/// 也就是说「先备份后删」里凡走 export 的那批，备份写得出、还原点不动。
///
/// 解码失败一律 Err 而不是 lossy 兜底：这份内容接下来要被写进注册表，
/// 半截乱码写进去比拒绝更坏。
pub fn decode_reg_bytes(bytes: &[u8]) -> Result<String, String> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let body = &bytes[2..];
        if body.len() % 2 != 0 {
            return Err(".reg 是 UTF-16 但字节数为奇数（文件被截断）".into());
        }
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).map_err(|e| format!(".reg UTF-16 解码失败: {e}"))
    } else if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8(bytes[3..].to_vec()).map_err(|e| format!(".reg UTF-8 解码失败: {e}"))
    } else {
        String::from_utf8(bytes.to_vec()).map_err(|e| format!(".reg 编码不可识别且非合法 UTF-8: {e}"))
    }
}

/// 读文件并按编码解码（闸侧与原生 import 共用同一份，避免两套口径）。
///
/// v5-K06 批次 3（A6-K01）：本文件此前的第二份键枚举（`parse_reg_backup` /
/// `parse_reg_backup_text`，按**物理行**扫 `[`…`]`）已删除——它与执行侧
/// `parse_reg_text` 对同一份 `.reg` 的键集存在续行合并差（`[-HKEY…\Cla\` +
/// `sses]`：闸侧只看到良性行、执行侧合并出 `SOFTWARE\Classes` 删除臂，探针三样本
/// 实测），还原四道闸因此建在键子集上。现在闸与执行臂同吃 `parse_reg_text` 一份。
pub fn read_reg_text_file(file: &Path) -> Result<String, String> {
    let bytes = std::fs::read(file).map_err(|e| format!("读取 .reg 失败: {e}"))?;
    decode_reg_bytes(&bytes)
}

/// 过了四道闸后带回来的信息：会写到哪些键 + 封条当时是什么状态 + **闸侧解析出的
/// 键段全量**（`sections`）。
/// `seal` 要带出去，因为还原成功的回执会告诉用户"这份有没有封条可对"（`sealWasRecorded`），
/// 那是用户判断"要不要再还原更早一份"的依据，不该在闸里丢掉。
/// `sections` 要带出去，是因为 v5-K06 批次 3（A6-K01）：执行臂 `reg_import_apply_sections`
/// 与四道闸必须吃**同一份**解析产物——此前闸侧按物理行枚举键、执行侧另读另解析，
/// 续行折行的删除臂对闸不可见、对执行器可见，禁删面/提权/摘要全部建在键子集上。
#[derive(Debug)]
pub struct RegBackupCheck {
    pub keys: Vec<String>,
    pub seal: &'static str,
    pub sections: Vec<RegSection>,
}

/// 还原前的**公共闸**，两域共用同一顺序与同一回执口径：
/// ① 严格 `.reg` 解析（形状不对直接拒）② 解析出的每个键都要仍在允许删除的面上
/// ③ 边车封条核对（`mismatch`/`corrupt`/`unreadable` 拒；`missing` 放行 —— 封条是 v0.2.6
/// 才加的，早期备份与 Electron 轨老备份都没有，拒 HKCU 老备份等于把还原依据扔掉）
/// ④ 目标含 HKLM 时必须已提权（不提权就让 `reg.exe` 自己失败是**假绿**：用户看到的是
/// "还原失败"，实际是权限不够，两者处置方式完全不同）
/// ⑤ P0-01：HKLM 备份还必须与 HKLM 管理员摘要核对（摘要存非提权进程写不了的位置，
/// 由本提权实例自行重算哈希）；无摘要/摘要不符一律拒绝。HKCU 不要求管理员摘要。
///
/// v5-K06 批次 3（A6-K01）：① 与执行臂**共用同一解析器**（`parse_reg_text`，一次读盘
/// 一次解析），闸侧键枚举 = 执行侧键枚举。此前闸侧另有一份按物理行扫的键枚举
/// （已删），`[-HKEY_LOCAL_MACHINE\SOFTWARE\Cla\` + `sses]` 这类续行折行的删除臂
/// 对它不可见 ⇒ 四道闸建在键子集上，执行臂却按合并后的完整键集直删（探针三样本实测）。
/// 回执 `sections` 即执行臂要写的那一份，调用方直接传给 `reg_import_apply_sections`。
///
/// `domain`（"cleanup"/"uninstall"）决定管理员摘要值名的域前缀；`is_admin` 由调用方
/// 传入而不是在这里查系统，是为了让这几道闸能拿临时目录静默测；真机端到端归
/// `#[ignore]` 的发布前用例。
pub fn reg_backup_restore_guards(
    file: &Path,
    name: &str,
    domain: &str,
    is_admin: bool,
) -> Result<RegBackupCheck, String> {
    let text = read_reg_text_file(file).map_err(|_| {
        "备份文件不是合法的 .reg（读不到或编码不可识别），已拒绝还原".to_string()
    })?;
    let sections = parse_reg_text(&text).map_err(|_| {
        "备份文件不是合法的 .reg（缺版本头或没有任何键段），已拒绝还原".to_string()
    })?;
    // 键枚举（回执/日志用）从 sections 推导——与执行臂同一份解析产物，不可能再分叉
    let mut keys: Vec<String> = Vec::new();
    for sec in &sections {
        let full = sec.full_key();
        if !keys.iter().any(|x| x.eq_ignore_ascii_case(&full)) {
            keys.push(full);
        }
    }
    for sec in &sections {
        // `[-HKEY...]` 是「删除键段」（parse_reg_text 的 delete_key 标记）。它既不是
        // Trim 的导出形态，也没有对应的保护面判定。单独报「不支持删除段」，别让用户从
        // 「含受保护的注册表容器」这句误以为是自己导错了键。
        if sec.delete_key {
            crate::engine::log::write_log(
                "warn",
                &format!("备份 {name} 含删除键段（[-{}]），已拒绝还原", sec.full_key()),
            );
            return Err("备份内含删除键段（[-HKEY…]），本工具不支持导入该形态，已拒绝还原".to_string());
        }
        if let Some(reason) = crate::engine::protect::reg_target_block_reason(&sec.full_key()) {
            crate::engine::log::write_log(
                "warn",
                &format!("备份 {name} 含受保护目标，已拒绝还原: {reason}"),
            );
            return Err(format!(
                "备份内含受保护的注册表容器，已拒绝还原：{reason}"
            ));
        }
    }
    let (seal, _) = reg_backup_seal_state(file);
    // v5-S1 批次 6（①）：目标含 HKLM 时边车封条 **missing 也拒**——只有 ok 放行。
    // HKLM 备份的两份锚里，管理员摘要（HKLM 受限键）本就不可被同用户改写（⑤ 兜底），
    // 但「边车缺失」若放行，内容核验就只剩摘要一路；拍板裁定 HKLM 目标必须两份交叉
    // 都在且都过（深度防御 + 简化推理），边车被删/损坏一律拒并说明。HKCU 目标维持
    // 现状：攻击者本就持有 HKCU 写权限，边车不构成提权边界，missing 放行保住
    // Electron 轨老备份的还原依据。
    let needs_admin = sections.iter().any(|s| s.hive == "HKEY_LOCAL_MACHINE");
    if matches!(seal, "mismatch" | "corrupt" | "unreadable") {
        crate::engine::log::write_log("warn", &format!("备份 {name} 封条核对未通过（{seal}），已拒绝还原"));
        return Err(format!(
            "备份内容与封条不符或不可读（{seal}），已拒绝还原——请改用导出时间的更早一份，或重新安装该程序"
        ));
    }
    if needs_admin && seal == "missing" {
        crate::engine::log::write_log(
            "warn",
            &format!("备份 {name} 为系统级（HKLM）目标但缺少边车封条，已拒绝还原"),
        );
        return Err(
            "该系统级（HKLM）备份缺少边车封条，无法交叉核验内容，已拒绝还原——请改用带封条的更早一份，或重新安装该程序"
                .to_string(),
        );
    }
    if needs_admin && !is_admin {
        return Err(
            "该备份指向 HKLM 下的键，需要以管理员身份运行后再还原（HKCU 下的备份不需要）".to_string(),
        );
    }
    if needs_admin {
        // P0-01：HKLM 还原的信任根是 HKLM 管理员摘要（非提权进程写不了的位置），
        // 边车封条只作第二意见；由本提权实例自行重算当前文件哈希与其比对。
        let Some(want) = read_admin_seal(domain, file) else {
            return Err(
                "该系统级（HKLM）备份没有管理员摘要：它生成于非管理员会话或早于安全版本，\
                 无法验证内容完整性，已拒绝还原（HKCU 备份不受此限）".to_string(),
            );
        };
        match crate::engine::hash::sha256_file(file) {
            Ok(got) if got.eq_ignore_ascii_case(&want) => {}
            Ok(_) => {
                crate::engine::log::write_log(
                    "warn",
                    &format!("备份 {name} 与管理员摘要不一致，已拒绝还原"),
                );
                return Err(
                    "备份内容与管理员摘要不符，已拒绝还原——请改用导出时间更早的一份，或重新安装该程序"
                        .to_string(),
                );
            }
            Err(e) => return Err(format!("备份不可读，已拒绝还原：{e}")),
        }
    }
    Ok(RegBackupCheck { keys, seal, sections })
}

#[cfg(test)]
mod reg_backup_common_tests {
    use super::*;

    fn sandbox(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("trim-regbackup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 缺版本头 / 半截写入 / 根本没有键段：三类形状都必须拒，且回执说清是哪一类
    #[test]
    fn 非法形状一律拒还原() {
        let root = sandbox("shape");
        let cases = [
            ("noheader.reg", "[HKEY_CURRENT_USER\\Software\\Acme]\r\n\"X\"=dword:1\r\n"),
            ("headeronly.reg", "Windows Registry Editor Version 5.00\r\n"),
            ("half.reg", "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Soft"),
        ];
        for (name, body) in cases {
            let p = root.join(name);
            std::fs::write(&p, body.as_bytes()).unwrap();
            let err = reg_backup_restore_guards(&p, name, "cleanup", true).unwrap_err();
            assert!(err.contains("合法的 .reg"), "{name} 的回执应是形状问题: {err}");
        }
        let ok = root.join("good.reg");
        std::fs::write(&ok, "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Acme]\r\n\"X\"=dword:1\r\n").unwrap();
        let passed = reg_backup_restore_guards(&ok, "good.reg", "cleanup", true).unwrap();
        assert_eq!(passed.keys, vec!["HKEY_CURRENT_USER\\Software\\Acme".to_string()]);
        assert_eq!(
            passed.seal, "missing",
            "合法 HKCU 备份在无封条时也必须放行（missing 不是拒的理由）"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `[-HKEY...]` 删除段（外来/手改 .reg）此前被当成普通键名 → `normalize_reg_target`
    /// 判不出 → 整份被「含受保护的注册表容器」误报拒。2026-10-05 复核：改成点名
    /// 「不支持删除键段」，既不误报成因，也不放行（fail-closed）。
    #[test]
    fn 删除键段单独报不支持而不是误报受保护容器() {
        let root = sandbox("delseg");
        let p = root.join("del.reg");
        std::fs::write(
            &p,
            "Windows Registry Editor Version 5.00\r\n\r\n[-HKEY_CURRENT_USER\\Software\\Acme]\r\n",
        )
        .unwrap();
        let err = reg_backup_restore_guards(&p, "del.reg", "cleanup", true).unwrap_err();
        assert!(
            err.contains("删除键段"),
            "删除段应点名「删除键段」而不是误报受保护容器: {err}",
        );
        assert!(
            !err.contains("受保护"),
            "删除段不是受保护容器问题，文案不许误导: {err}",
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// v5-S1 批次 6（①）：目标含 HKLM 时边车封条 missing 也拒（只有 ok 放行）；
    /// HKCU 目标 missing 维持放行（Electron 轨老备份的还原依据）。
    /// 判红自证：把闸里「needs_admin && missing 拒」分支删掉 ⇒ ② 红。
    #[test]
    fn hklm缺边车封条拒还原_hkcu维持放行() {
        let root = sandbox("s1a");
        let body = |hive: &str| {
            format!("Windows Registry Editor Version 5.00\r\n\r\n[{hive}\\Software\\TrimS1Probe]\r\n\"a\"=dword:1\r\n")
        };
        let hklm = root.join("hklm.reg");
        std::fs::write(&hklm, body("HKEY_LOCAL_MACHINE")).unwrap();
        // is_admin=true：让封条检查（在提权闸之前）先触发，沙箱不触真实 HKLM
        let err = reg_backup_restore_guards(&hklm, "hklm.reg", "cleanup", true).unwrap_err();
        assert!(err.contains("缺少边车封条"), "HKLM + missing 边车必须拒: {err}");
        let hkcu = root.join("hkcu.reg");
        std::fs::write(&hkcu, body("HKEY_CURRENT_USER")).unwrap();
        assert!(
            reg_backup_restore_guards(&hkcu, "hkcu.reg", "cleanup", true).is_ok(),
            "HKCU + missing 边车维持放行（老备份还原依据）"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// v5-S1 批次 6 真机探针（需提权窗口写 HKLM 管理员摘要，发布前人工跑）。
    /// 篡改矩阵：两份都在 ⇒ 放行；非提权进程删边车 ⇒ 拒（①）；非提权进程改边车 ⇒
    /// mismatch 拒；改备份内容重签边车 ⇒ 与 HKLM 管理员摘要不符 ⇒ 拒。
    /// 全程自建自清（HKLM 摘要值用后即删）。判红自证：删掉闸 ① 的 missing 拒分支 ⇒
    /// 删边车场景红；删掉闸 ⑤ 摘要比对 ⇒ 内容篡改场景红。
    #[test]
    #[ignore = "真机：需提权窗口写 HKLM 管理员摘要（发布前人工跑）"]
    fn live_hklm双封条篡改矩阵() {
        let root = sandbox("s1-live");
        let f = root.join("live-s1.reg");
        std::fs::write(
            &f,
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\TrimS1LiveProbe]\r\n\"a\"=dword:1\r\n",
        )
        .unwrap();
        write_reg_backup_seal(&f, r"HKLM\Software\TrimS1LiveProbe");
        write_admin_seal("cleanup", &f);
        // 基线：两份都在且匹配 ⇒ 放行（摘要写入失败时这里先红，探针前置条件不满足）
        assert!(
            reg_backup_restore_guards(&f, "live-s1.reg", "cleanup", true).is_ok(),
            "两份封条都在且匹配必须放行（先确认 HKLM 管理员摘要写入成功）"
        );
        // ① 非提权进程删边车 ⇒ missing ⇒ 拒
        let seal = reg_seal_path_for(&f);
        std::fs::remove_file(&seal).unwrap();
        assert!(
            reg_backup_restore_guards(&f, "live-s1.reg", "cleanup", true)
                .unwrap_err()
                .contains("缺少边车封条"),
            "HKLM + missing 边车必须拒"
        );
        // ② 非提权进程改边车（写假哈希）⇒ mismatch ⇒ 拒
        std::fs::write(&seal, r#"{"sha256":"deadbeefdeadbeef"}"#).unwrap();
        assert!(
            reg_backup_restore_guards(&f, "live-s1.reg", "cleanup", true)
                .unwrap_err()
                .contains("封条"),
            "篡改边车必须拒"
        );
        // ③ 改备份内容 + 重签一致边车 ⇒ 与 HKLM 管理员摘要不符 ⇒ 拒（⑤ 兜底）
        std::fs::write(
            &f,
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\TrimS1LiveProbe]\r\n\"a\"=dword:2\r\n",
        )
        .unwrap();
        std::fs::remove_file(&seal).unwrap();
        write_reg_backup_seal(&f, r"HKLM\Software\TrimS1LiveProbe");
        assert!(
            reg_backup_restore_guards(&f, "live-s1.reg", "cleanup", true)
                .unwrap_err()
                .contains("管理员摘要"),
            "内容改后与 HKLM 管理员摘要不符必须拒"
        );
        // 清理：HKLM 摘要值 + 沙箱
        assert!(
            crate::engine::native::reg_restore_delete(
                crate::engine::native::hive_hklm(),
                ADMIN_SEAL_SUBKEY,
                &admin_seal_value_name("cleanup", &f).unwrap(),
            ),
            "清理 HKLM 摘要失败（确认在提权窗口跑）"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 手工改成受保护容器（整棵 SOFTWARE）必须被禁删面挡住 —— 这是"是备份文件就能 import"
    /// 这个错误假设的正解，两域同一口径
    #[test]
    fn 备份内容指向受保护容器时拒还原() {
        let root = sandbox("deny");
        let p = root.join("evil.reg");
        std::fs::write(&p, "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE]\r\n\"X\"=dword:1\r\n").unwrap();
        let err = reg_backup_restore_guards(&p, "evil.reg", "cleanup", true).unwrap_err();
        assert!(err.contains("受保护"), "回执应写明是禁删面拦下的: {err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// HKLM 目标：未提权 = 明确拒绝（不丢给 reg.exe 撞"还原失败"）；
    /// 已提权但无管理员摘要同样拒绝（P0-01：无法证明内容完整性）。
    /// 摘要一致放行的分支写真实 HKLM，归 #[ignore] 真机探针。
    /// v5-S1 批次 6：样本补写边车封条——闸 ①（HKLM + missing 拒）在本闸之前，
    /// 无封条样本现在会先撞 ① 而到不了这里（变红原因，2026-10-13）。
    #[test]
    fn hklm_未提权或无管理员摘要时拒还原() {
        let root = sandbox("admin");
        let p = root.join("hklm.reg");
        std::fs::write(&p, "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\Acme\\App]\r\n\"X\"=dword:1\r\n").unwrap();
        write_reg_backup_seal(&p, r"HKLM\Software\Acme\App");
        assert!(reg_backup_restore_guards(&p, "hklm.reg", "cleanup", false)
            .unwrap_err().contains("管理员"));
        // 无副作用：独特文件名在真实 HKLM 摘要键下必然无记录
        let err = reg_backup_restore_guards(&p, "hklm.reg", "cleanup", true).unwrap_err();
        assert!(err.contains("管理员摘要"), "提权但无摘要必须拒绝：{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// P0-01 对账纯判据：只清本域、且只清备份已不存在的值名
    #[test]
    fn 孤立管理员摘要值名识别() {
        let files: std::collections::HashSet<String> =
            ["a.reg".to_string()].into_iter().collect();
        let names = [
            "cleanup/a.reg".to_string(),   // 备份仍在 → 保留
            "cleanup/b.reg".to_string(), // 备份已删 → 待删
            "uninstall/a.reg".to_string(), // 他域 → 不动
        ];
        let stale = stale_admin_seal_value_names("cleanup", &files, &names);
        assert_eq!(stale, vec!["cleanup/b.reg".to_string()], "{stale:?}");
        assert!(stale_admin_seal_value_names(
            "cleanup",
            &["a.reg".to_string(), "b.reg".to_string()].into_iter().collect(),
            &names,
        ).is_empty());
    }

    /// 封条三种失败态都要拒；`missing` 要放行（早期与 Electron 轨备份都没有封条）
    #[test]
    fn 封条状态决定放行与否() {
        let root = sandbox("seal");
        let p = root.join("1_acme.reg");
        let body = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Acme]\r\n\"X\"=dword:1\r\n";
        std::fs::write(&p, body).unwrap();
        write_reg_backup_seal(&p, "HKCU\\Software\\Acme");
        assert_eq!(reg_backup_seal_state(&p).0, "ok");
        assert!(reg_backup_restore_guards(&p, "1_acme.reg", "cleanup", true).is_ok());
        // 改写内容 ⇒ mismatch ⇒ 拒
        std::fs::write(&p, format!("{body}\r\n[HKEY_CURRENT_USER\\Software\\Other]\r\n\"Y\"=dword:2\r\n")).unwrap();
        assert_eq!(reg_backup_seal_state(&p).0, "mismatch");
        assert!(reg_backup_restore_guards(&p, "1_acme.reg", "cleanup", true).unwrap_err().contains("封条"));
        // 封条本身坏了 ⇒ corrupt ⇒ 拒
        std::fs::write(reg_seal_path_for(&p), "{不是 json").unwrap();
        assert_eq!(reg_backup_seal_state(&p).0, "corrupt");
        assert!(reg_backup_restore_guards(&p, "1_acme.reg", "cleanup", true).unwrap_err().contains("封条"));
        // 封条文件没了 ⇒ missing ⇒ 放行
        std::fs::remove_file(reg_seal_path_for(&p)).unwrap();
        assert_eq!(reg_backup_seal_state(&p).0, "missing");
        assert!(reg_backup_restore_guards(&p, "1_acme.reg", "cleanup", true).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// D2：严格 `.reg` 解析。还原前必须知道"这份文件会往哪些键里写"，    /// 所以宁可拒也不能宽松 —— 半截写入的备份尤其要拦。
    /// v5-K06 批次 3：闸与执行臂同吃 `parse_reg_text`（原物理行键枚举 `parse_reg_backup_text`
    /// 已删，它与本解析器存在续行合并差 = A6-K01），本用例改断同一解析器的键枚举语义。
    #[test]
    fn reg_backup_parser_requires_header_and_keys() {
        let ok = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\ESET]\r\n\"a\"=dword:00000001\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\ESET\\b]\r\n";
        let sections = parse_reg_text(ok).expect("合法 .reg 必须解析通过");
        assert_eq!(sections.len(), 2, "键段应有两条: {:?}", sections.iter().map(|s| s.full_key()).collect::<Vec<_>>());
        // BOM 与前后空白是 reg.exe export 的实际形态，不能被当成非法
        assert!(parse_reg_text(&format!("\u{feff} {ok}")).is_ok());
        for bad in [
            "",
            "Windows Registry Editor Version 5.00\r\n",              // 有头无键
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\ESET]\r\n\"a\"=dword:1", // 缺版本头
            "Windows Registry Editor Version 5.00\r\n[HKEY_",        // 半截写入
            "Windows Registry Editor Version 5.00\r\n[]\r\n",         // 空键名
        ] {
            assert!(parse_reg_text(bad).is_err(), "这类 .reg 不该通过解析: {bad:?}");
        }
    }

    /// v5-K06 批次 3（A6-K01）：续行折行的删除臂对闸必须可见。样本
    /// `[-HKEY_LOCAL_MACHINE\SOFTWARE\Cla\` + `sses]`——修前闸侧按物理行枚举键，
    /// 两行都不完整 ⇒ 键集为空 ⇒ 闸拒「不是合法的 .reg」（良性 HKCU 形态同样被误拒）；
    /// 对含 HKLM 的同类样本，闸侧若只看到良性键就会放行、执行侧却按合并后的
    /// `SOFTWARE\Classes` 删除臂直删（探针三样本实测）。判红自证：闸侧换回
    /// 物理行枚举 ⇒ 本用例与下一条同源断言红。
    #[test]
    fn 续行删除臂对闸可见且两侧键集全等() {
        // ① 删除臂样本：合并后续行 ⇒ 闸点「删除键段」拒（fail-closed）
        let del = "Windows Registry Editor Version 5.00\r\n\r\n[-HKEY_LOCAL_MACHINE\\SOFTWARE\\Cla\\\r\nsses]\r\n";
        let sections = parse_reg_text(del).expect("执行侧解析器应合并出删除段");
        assert_eq!(sections.len(), 1);
        assert!(sections[0].delete_key, "续行合并后必须识别为删除臂");
        assert_eq!(sections[0].full_key(), r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes");
        let root = sandbox("k06-del");
        let p = root.join("folded-del.reg");
        std::fs::write(&p, del).unwrap();
        // is_admin=true：让删除段检查（在提权闸之前）先触发，回执必须点名删除键段
        let err = reg_backup_restore_guards(&p, "folded-del.reg", "cleanup", true).unwrap_err();
        assert!(err.contains("删除键段"), "续行删除臂必须被闸拒: {err}");
        // ② 良性 HKCU 续行样本（与恶意样本同形：行尾 `\` 被合并吃掉，两半拼出键名）：
        // `Software\Tri` + `mProbe` ⇒ `Software\TrimProbe`。修前物理行枚举两行都不完整
        // ⇒ 键集空 ⇒ 闸误拒；修后合并 ⇒ 闸放行且与执行侧同源。
        let ok = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Tri\\\r\nmProbe]\r\n\"a\"=dword:1\r\n";
        let p2 = root.join("folded-ok.reg");
        std::fs::write(&p2, ok).unwrap();
        let chk = reg_backup_restore_guards(&p2, "folded-ok.reg", "cleanup", false)
            .expect("良性续行样本（修前被物理行枚举误拒）应过闸");
        assert_eq!(chk.keys, vec![r"HKEY_CURRENT_USER\Software\TrimProbe".to_string()]);
        assert_eq!(chk.sections.len(), 1);
        assert_eq!(chk.sections[0].full_key(), chk.keys[0], "闸回执的键枚举必须与执行臂 sections 同源");
        assert!(!chk.sections[0].delete_key);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// D2 封条状态机：列表按状态决定给不给还原入口、还原按状态硬拒，所以这四态必须可区分。
    /// `unreadable` 要的是「文本读得动但摘要算不出」的窗口，单测造不出来，如实留作未验证。
    #[test]
    fn reg_backup_seal_states_are_distinguishable() {
        let dir = std::env::temp_dir().join(format!("trim-seal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("临时目录应可建");
        let bak = dir.join("1790561031234_Acme.reg");
        std::fs::write(
            &bak,
            b"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Acme]\r\n",
        )
        .expect("备份应可写");
        // 旧备份没有封条：仍可还原，但界面不许显示成"相符"
        assert_eq!(reg_backup_seal_state(&bak).0, "missing");
        write_reg_backup_seal(&bak, "HKCU\\Software\\Acme");
        let (state, meta) = reg_backup_seal_state(&bak);
        assert_eq!(state, "ok");
        assert_eq!(
            meta.get("target").and_then(Value::as_str),
            Some("HKCU\\Software\\Acme"),
            "列表行的目标列取封条里的 target，丢了就没法核对是哪一键"
        );
        // 内容被改（半截写入 / 手工编辑）→ mismatch，还原链要据此硬拒
        std::fs::write(
            &bak,
            b"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE]\r\n",
        )
        .expect("备份应可重写");
        assert_eq!(reg_backup_seal_state(&bak).0, "mismatch");
        // 封条不是 JSON → corrupt
        std::fs::write(reg_seal_path_for(&bak), b"not json").expect("封条应可写");
        assert_eq!(reg_backup_seal_state(&bak).0, "corrupt");
        // 封条是 JSON 却缺 sha256：等同于没核对过，不许降级成 missing 放行
        std::fs::write(reg_seal_path_for(&bak), br#"{"target":"x"}"#).expect("封条应可写");
        assert_eq!(reg_backup_seal_state(&bak).0, "corrupt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P0-01 真机探针（必须在管理员实例下跑）：HKLM 摘要写入 → 还原闸放行
    /// → 改字节拒绝 → 对账删孤立摘要。断言逐项点名 reached 对象。
    #[test]
    #[ignore = "真机写 HKLM 管理员摘要键（Drop 清理），发布前人工在管理员会话跑"]
    fn live_管理员摘要_还原闸与对账闭环() {
        if !crate::engine::sysinfo::is_admin() {
            eprintln!("SKIP：探针需在管理员会话运行，当前非提权，未校验");
            return;
        }
        let root = sandbox("liveadmin");
        let p = root.join("liveprobe.reg");
        let value_name = String::from("cleanup/liveprobe.reg");
        // 兜底清理：断言失败提前返回时也删掉 HKLM 值
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = crate::engine::native::reg_restore_delete(
                    crate::engine::native::hive_hklm(),
                    ADMIN_SEAL_SUBKEY,
                    &self.0,
                );
            }
        }
        let _cleanup = Cleanup(value_name.clone());

        let body = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\TrimProbe\\App]\r\n\"X\"=dword:1\r\n";
        std::fs::write(&p, body).unwrap();
        write_reg_backup_seal(&p, r"HKLM\Software\TrimProbe\App");
        // 摘要写入前：提权也拒
        assert!(reg_backup_restore_guards(&p, "liveprobe.reg", "cleanup", true)
            .unwrap_err().contains("管理员摘要"));
        write_admin_seal("cleanup", &p);
        let sum = read_admin_seal("cleanup", &p).expect("管理员摘要应可读");
        assert_eq!(sum.len(), 64, "SHA-256 摘要长度应为 64: {sum}");
        // 摘要一致：放行（正向点名 reached 键）
        let passed = reg_backup_restore_guards(&p, "liveprobe.reg", "cleanup", true)
            .expect("摘要一致应放行");
        assert_eq!(passed.keys, vec![r"HKEY_LOCAL_MACHINE\Software\TrimProbe\App".to_string()]);
        // 改一字节 + 边车封条同步重写（只留管理员摘要过期）⇒ 必须由管理员摘要拒。
        // 边车不动时封条会先拦下（那是另一条闸），这条要专门测摘要这条信任根。
        std::fs::write(&p, format!("{body}\r\n[HKEY_LOCAL_MACHINE\\Software\\TrimProbe\\Other]\r\n")).unwrap();
        write_reg_backup_seal(&p, r"HKLM\Software\TrimProbe\App");
        assert!(reg_backup_restore_guards(&p, "liveprobe.reg", "cleanup", true)
            .unwrap_err().contains("管理员摘要"));
        std::fs::write(&p, body).unwrap();

        // 对账：第二个备份写摘要后删文件，reconcile 只删孤立那份
        let q = root.join("liveprobe2.reg");
        std::fs::write(&q, body.replace("TrimProbe", "TrimProbe2")).unwrap();
        write_admin_seal("cleanup", &q);
        std::fs::remove_file(&q).unwrap();
        reconcile_admin_seals("cleanup", &root);
        let (names, incomplete) = crate::engine::native::reg_enum_value_names_pub(
            crate::engine::native::hive_hklm(),
            ADMIN_SEAL_SUBKEY,
        );
        assert!(!incomplete, "P1-6G：该键可写且刚被本用例枚举过，不该报「清单不完整」");
        assert!(!names.contains(&String::from("cleanup/liveprobe2.reg")), "孤立摘要应被删：{names:?}");
        assert!(names.contains(&String::from("cleanup/liveprobe.reg")), "现存备份摘要应保留：{names:?}");

        let _ = std::fs::remove_dir_all(&root);
    }
}

// ==================== A6：.reg 值级解析 + 原生写入（v2-R4，2026-10-01） ====================
//
// 替换的是**执行器**：`reg.exe import <file>` → 自己解析 + 自己写。
// 刻意不动的两样东西（v2 R4 明令）：`.reg` 文本格式、封条链
// （`reg_backup_seal_state` / `reg_backup_restore_guards` 还原闸原样保留，
//  本模块只在闸**之后**接手）。
//
// v5-K06 批次 3（A6-K01，2026-10-12）：此处原注释写「继续吃同一份 parse_reg_backup
// 的形状判定」——**与执行代码不符**（实际吃的是 `parse_reg_text`，与闸侧的物理行
// 键枚举是两份）。现已名副实归：闸侧改吃 `parse_reg_text`，`parse_reg_backup`
// （物理行键枚举）整份删除，闸⇄执行臂同一解析产物（见 reg_backup_restore_guards
// 与 reg_import_apply_sections 的注释）。
//
// 为什么要值级解析而不是只校验形状：还原要字节忠实。备份是 `reg.exe export` 产的，
// 里面非 DWORD 一律写成 `hex(2):...` / `hex(7):...` 的 UTF-16 形态，
// 按「字符串」直接写会把 `REG_EXPAND_SZ` 降级成 `REG_SZ`（丢掉 `%VAR%` 语义）、
// 把 `REG_MULTI_SZ` 的分隔结构写坏 —— 那正是 `read_reg_value_faithful`
// 在读取侧专门避开的那一类变形。
//
// 编码口径与 `optimizer::restore_write_bytes` 完全一致（同一个写入器不能收两种布局）：
// DWORD/QWORD 小端；SZ/EXPAND_SZ 为 UTF-16LE + 单个尾 NUL；MULTI_SZ 为各元素
// UTF-16LE + NUL、末尾再补一个双 NUL。

use windows::Win32::System::Registry::REG_VALUE_TYPE;

/// 一条 `.reg` 值写入。`data` 已按 `kind` 编码好，交给 `native::reg_restore_write`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegWrite {
    Set { name: String, kind: u32, data: Vec<u8> },
    /// `"name"=-` / `@=-`：删这一个值（键保留）
    DeleteValue { name: String },
}

/// 一个键段。`delete_key` 对应 `[-HKLM\...]` 形态 —— 整键删除。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegSection {
    /// 原始 hive 名（大写，如 `HKEY_LOCAL_MACHINE`），由执行器解析成句柄
    pub hive: String,
    pub subkey: String,
    pub delete_key: bool,
    pub writes: Vec<RegWrite>,
}

impl RegSection {
    /// 供受保护面校验用的全名（与 `reg_target_block_reason` 吃的形状一致）
    pub fn full_key(&self) -> String {
        format!("{}\\{}", self.hive, self.subkey)
    }
}

/// 值类型常量（`REG_*`），解析器与执行器共用，避免到处写字面量。
pub const RK_SZ: u32 = 1;
pub const RK_EXPAND_SZ: u32 = 2;
pub const RK_BINARY: u32 = 3;
pub const RK_DWORD: u32 = 4;
pub const RK_MULTI_SZ: u32 = 7;
pub const RK_QWORD: u32 = 11;

/// 严格值级解析。任何看不懂的行都是 Err —— **不做宽松兼容**：
/// 这份内容接下来会被直接写进注册表，"猜一个最像的解释"是本项目最忌讳的假绿形态。
pub fn parse_reg_text(text: &str) -> Result<Vec<RegSection>, String> {
    // 1) 版本头（复用既有严格判定；顺带吃掉 BOM —— 本模块自己写的备份带 BOM）
    let first = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| ".reg 为空".to_string())?
        .trim_start_matches('\u{feff}')
        .trim()
        .to_string();
    if !first.eq_ignore_ascii_case("Windows Registry Editor Version 5.00") {
        return Err(".reg 缺版本头".into());
    }

    // 2) 折行合并：行尾单个 `\` 表示续行（reg.exe 的长 hex 就是这么折的）。
    // 版本头在这里一并跳过 —— 它上面已经严格校验过了，留在这条循环里会被当成
    // 「键段之前的值行」而把整份合法备份判死。trim 链与上方头判定同口径：
    // BOM 与头之间夹空白（手工编辑过的备份实测形态）也要能识别成头行。
    const HEADER: &str = "Windows Registry Editor Version 5.00";
    let mut logical: Vec<String> = Vec::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let t = raw.trim_end_matches('\r').trim();
        if t.is_empty() || t.starts_with(';') {
            continue;
        }
        if t.trim_start_matches('\u{feff}').trim().eq_ignore_ascii_case(HEADER) {
            continue;
        }
        if let Some(cont) = t.strip_suffix('\\') {
            pending.push_str(cont.trim_end());
            continue;
        }
        if pending.is_empty() {
            logical.push(t.to_string());
        } else {
            pending.push_str(t);
            logical.push(std::mem::take(&mut pending));
        }
    }
    // 末尾悬空的续行标记 = 文件被截断
    if !pending.is_empty() {
        return Err(".reg 以续行符结尾（文件被截断）".into());
    }

    let mut sections: Vec<RegSection> = Vec::new();
    for t in logical {
        if t.starts_with('[') {
            let inner = t
                .strip_suffix(']')
                .ok_or_else(|| format!("键段行不完整: {t}"))?
                .strip_prefix('[')
                .ok_or_else(|| format!("键段行不完整: {t}"))?
                .trim()
                .trim_matches('"')
                .to_string();
            if inner.is_empty() {
                return Err("键段为空".into());
            }
            let (body, delete_key) = match inner.strip_prefix('-') {
                Some(rest) => (rest.to_string(), true),
                None => (inner.clone(), false),
            };
            let (hive, subkey) = split_hive(&body)?;
            sections.push(RegSection { hive, subkey, delete_key, writes: Vec::new() });
            continue;
        }
        let Some(sec) = sections.last_mut() else {
            return Err(format!("值行出现在任何键段之前: {t}"));
        };
        sec.writes.push(parse_value_line(&t)?);
    }
    if sections.is_empty() {
        return Err(".reg 没有任何键段".into());
    }
    Ok(sections)
}

fn split_hive(body: &str) -> Result<(String, String), String> {
    let (hive, rest) = body
        .split_once('\\')
        .ok_or_else(|| format!("键名缺少子键部分: {body}"))?;
    let hive_up = hive.to_uppercase();
    if !matches!(
        hive_up.as_str(),
        "HKEY_LOCAL_MACHINE"
            | "HKLM"
            | "HKEY_CURRENT_USER"
            | "HKCU"
            | "HKEY_CLASSES_ROOT"
            | "HKCR"
            | "HKEY_USERS"
            | "HKU"
            | "HKEY_PERFORMANCE_DATA"
            | "HKEY_DYN_DATA"
    ) {
        return Err(format!("未知注册表根: {hive}"));
    }
    let subkey = rest.trim_matches('\\').to_string();
    Ok((normalize_hive_name(&hive_up), subkey))
}

/// 别名统一成全名，让受保护面判定只面对一种写法
/// （`reg_target_block_reason` 按前缀比，`HKLM\...` 与 `HKEY_LOCAL_MACHINE\...` 必须同一口径）。
fn normalize_hive_name(hive_up: &str) -> String {
    match hive_up {
        "HKLM" => "HKEY_LOCAL_MACHINE".to_string(),
        "HKCU" => "HKEY_CURRENT_USER".to_string(),
        "HKCR" => "HKEY_CLASSES_ROOT".to_string(),
        "HKU" => "HKEY_USERS".to_string(),
        other => other.to_string(),
    }
}

fn parse_value_line(t: &str) -> Result<RegWrite, String> {
    let (lhs, rhs) = t
        .split_once('=')
        .ok_or_else(|| format!("值行缺 '=': {t}"))?;
    let name = if lhs.trim() == "@" {
        String::new() // 默认值
    } else {
        unquote_reg(lhs.trim()).ok_or_else(|| format!("值名不是带引号字符串: {lhs}"))?
    };
    let rhs = rhs.trim();
    if rhs == "-" {
        return Ok(RegWrite::DeleteValue { name });
    }
    if let Some(hexpart) = rhs.strip_prefix("dword:") {
        let v = u32::from_str_radix(hexpart.trim(), 16)
            .map_err(|_| format!("dword 非 hex: {hexpart}"))?;
        return Ok(RegWrite::Set { name, kind: RK_DWORD, data: v.to_le_bytes().to_vec() });
    }
    if let Some(hexpart) = rhs.strip_prefix("qword:") {
        let v = u64::from_str_radix(hexpart.trim().replace(',', "").as_str(), 16)
            .map_err(|_| format!("qword 非 hex: {hexpart}"))?;
        return Ok(RegWrite::Set { name, kind: RK_QWORD, data: v.to_le_bytes().to_vec() });
    }
    if let Some(rest) = rhs.strip_prefix("hex") {
        // `hex:` / `hex(2):` / `hex(b):` —— 括号里是**十六进制**的类型号
        let (kind, bytes) = if let Some(paren) = rest.strip_prefix('(') {
            let (code, tail) = paren
                .split_once(')')
                .ok_or_else(|| format!("hex(...) 括号不完整: {rhs}"))?;
            let k = u32::from_str_radix(code.trim(), 16)
                .map_err(|_| format!("hex(...) 类型号非 hex: {code}"))?;
            (k, tail.strip_prefix(':').unwrap_or(tail))
        } else {
            (RK_BINARY, rest.strip_prefix(':').unwrap_or(rest))
        };
        let clean = bytes.trim();
        let data: Vec<u8> = if clean.is_empty() {
            Vec::new()
        } else {
            clean
                .split(',')
                .map(|b| {
                    let b = b.trim();
                    u8::from_str_radix(b, 16).map_err(|_| format!("hex 字节非法: {b:?}"))
                })
                .collect::<Result<_, String>>()?
        };
        // 类型白名单：`hex` 分支会吃掉 `hex(a):` / `hex(8):` 这类**资源型**值，
        // 它们不是「一段字节」而是结构化的资源描述符（ResourceRequested 等），
        // 照字节写进去会得到一个类型对、内容错的值，比失败更难发现。
        if !matches!(kind, RK_SZ | RK_EXPAND_SZ | RK_BINARY | RK_DWORD | RK_MULTI_SZ | RK_QWORD) {
            return Err(format!("未支持的注册表类型: hex({kind:x})"));
        }
        return Ok(RegWrite::Set { name, kind, data });
    }
    // 普通字符串 → REG_SZ
    let s = unquote_reg(rhs).ok_or_else(|| format!("未支持的值形态: {rhs}"))?;
    Ok(RegWrite::Set { name, kind: RK_SZ, data: utf16_with_nul(&s) })
}

/// `.reg` 里的带引号字符串：`\"` 与 `\\` 是两个转义，其余按字面。
fn unquote_reg(t: &str) -> Option<String> {
    let inner = t.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let mut it = inner.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => return None, // 结尾裸反斜杠 = 形状不对
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn utf16_with_nul(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

/// 一次原生 import 的统计，供回执如实写「写了多少值、删了多少项」。
#[derive(Debug, Default, Clone, Copy)]
pub struct RegImportStat {
    pub values_written: usize,
    pub values_deleted: usize,
    pub keys_deleted: usize,
    pub keys_created: usize,
}

/// 把一份已通过四道闸的 `.reg` 原生写进注册表（**执行臂本体，不做任何 IO**）。
///
/// v5-K06 批次 3（A6-K01）：入参就是 `reg_backup_restore_guards` 回执里的
/// `sections`——四道闸与执行臂吃同一份解析产物。此前本函数自己二次读盘+二次解析
/// （执行侧解析器与闸侧按物理行的键枚举存在续行合并差），闸看不见的 `[-HKEY…]`
/// 段会被直接执行；现在那种「校验一套、执行另一套」的形态在类型上就不存在了。
/// 失败即停并带着「第几段/哪个值」的原因返回 —— 不做"跳过坏行继续写"，
/// 那会把一次还原变成半截状态而回执仍然像成功。
pub fn reg_import_apply_sections(sections: &[RegSection]) -> Result<RegImportStat, String> {
    let mut stat = RegImportStat::default();
    for sec in sections {
        let hive = hive_of(&sec.hive)?;
        let full = sec.full_key();
        if sec.delete_key {
            if crate::engine::native::reg_key_remove(hive, &sec.subkey, true) {
                stat.keys_deleted += 1;
            } else {
                return Err(format!("删除键失败: {full}"));
            }
            continue;
        }
        // 只有值要写、或段本身要存在时才建键（reg.exe 对空段也会建键，这里保持同形）
        if crate::engine::native::reg_key_ensure(hive, &sec.subkey) {
            stat.keys_created += 1;
        } else if !sec.writes.is_empty() {
            return Err(format!("打开/创建键失败: {full}"));
        }
        for w in &sec.writes {
            match w {
                RegWrite::Set { name, kind, data } => {
                    let ok = crate::engine::native::reg_restore_write(
                        hive,
                        &sec.subkey,
                        name,
                        REG_VALUE_TYPE(*kind),
                        data,
                    );
                    if !ok {
                        let shown = if name.is_empty() { "@（默认值）".to_string() } else { name.clone() };
                        return Err(format!("写入值失败: {full} → {shown} (type={kind})"));
                    }
                    stat.values_written += 1;
                }
                RegWrite::DeleteValue { name } => {
                    if crate::engine::native::reg_restore_delete(hive, &sec.subkey, name) {
                        stat.values_deleted += 1;
                    } else if crate::engine::native::read_reg_value_faithful(hive, &sec.subkey, name)
                        .is_none()
                    {
                        // 本来就没有这个值 = 目标态已达成。让一次还原因为"没东西可删"而失败，
                        // 会把用户推向"那我不还原了"，方向更坏。
                    } else {
                        let shown = if name.is_empty() { "@（默认值）".to_string() } else { name.clone() };
                        return Err(format!("删除值失败: {full} → {shown}"));
                    }
                }
            }
        }
    }
    Ok(stat)
}

/// 非闸链域的 `.reg` 导入便捷件：自己读盘 + 自己解析 + 执行。
///
/// **只有不经四道闸的域用它**（外设备份还原、优化器步骤体还原——两者按 R5-W-1/W-2
/// 白名单不套公共四道闸，也没有第二份判据可对拍）。还原闸链（cleanup/uninstall 的
/// 备份还原）**不要**走本函数：那会退回「闸侧一套键枚举、执行侧另一套」的旧形态，
/// 应改用 `reg_backup_restore_guards` 回执的 `sections` + [`reg_import_apply_sections`]。
pub fn reg_import_apply(path: &std::path::Path) -> Result<RegImportStat, String> {
    let text = read_reg_text_file(path)?;
    let sections = parse_reg_text(&text)?;
    reg_import_apply_sections(&sections)
}

fn hive_of(name: &str) -> Result<windows::Win32::System::Registry::HKEY, String> {
    let n = normalize_hive_name(&name.to_uppercase());
    Ok(match n.as_str() {
        "HKEY_LOCAL_MACHINE" => crate::engine::native::hive_hklm(),
        "HKEY_CURRENT_USER" => crate::engine::native::hive_hkcu(),
        "HKEY_CLASSES_ROOT" => crate::engine::native::hive_hkcr(),
        "HKEY_USERS" => crate::engine::native::hive_hku(),
        // 这两个根应用不写；显式拒，而不是给一个能用的句柄让上层"看起来支持"
        "HKEY_PERFORMANCE_DATA" | "HKEY_DYN_DATA" => {
            return Err(format!("本应用不写该注册表根: {name}"))
        }
        _ => return Err(format!("未知注册表根: {name}")),
    })
}

#[cfg(test)]
mod reg_import_tests {
    use super::*;

    const HDR: &str = "Windows Registry Editor Version 5.00\r\n\r\n";

    #[test]
    fn 解析_dword_与_字符串_与_删除值() {
        let text = format!(
            "{HDR}[HKEY_LOCAL_MACHINE\\SOFTWARE\\TrimTest]\r\n\"a\"=dword:00000002\r\n\"b\"=\"x 值\"\r\n\"c\"=-\r\n"
        );
        let secs = parse_reg_text(&text).expect("应解析成功");
        assert_eq!(secs.len(), 1);
        let s = &secs[0];
        assert_eq!(s.hive, "HKEY_LOCAL_MACHINE");
        assert_eq!(s.subkey, "SOFTWARE\\TrimTest");
        assert!(!s.delete_key);
        assert_eq!(s.writes[0], RegWrite::Set { name: "a".into(), kind: RK_DWORD, data: 2u32.to_le_bytes().to_vec() });
        assert_eq!(
            s.writes[1],
            RegWrite::Set { name: "b".into(), kind: RK_SZ, data: utf16_with_nul("x 值") }
        );
        assert_eq!(s.writes[2], RegWrite::DeleteValue { name: "c".into() });
    }

    /// 备份忠实性：`reg.exe export` 把 EXPAND_SZ / MULTI_SZ 写成 `hex(2)` / `hex(7)`，
    /// 类型号必须原样带过去，否则还原时 `REG_EXPAND_SZ` 会被降级成 `REG_SZ`、
    /// `%VAR%` 永久变成字面量 —— 读取侧的 `read_reg_value_faithful` 专门在防这一类。
    #[test]
    fn 还原保留_expand_sz_与_multi_sz_类型() {
        // %WINDIR% 的 UTF-16LE hex
        let text = format!(
            "{HDR}[HKEY_CURRENT_USER\\Environment]\r\n\"p\"=hex(2):25,00,57,00,49,00,4e,00,44,00,49,00,52,00,25,00,00,00\r\n\
             \"m\"=hex(7):41,00,00,00,42,00,00,00,00,00\r\n"
        );
        let secs = parse_reg_text(&text).unwrap();
        assert_eq!(secs[0].writes[0], RegWrite::Set {
            name: "p".into(), kind: RK_EXPAND_SZ,
            data: vec![0x25, 0, 0x57, 0, 0x49, 0, 0x4e, 0, 0x44, 0, 0x49, 0, 0x52, 0, 0x25, 0, 0, 0],
        });
        assert_eq!(secs[0].writes[1].kind_of().unwrap(), RK_MULTI_SZ);
    }

    /// 长 hex 折行：`reg.exe export` 每 ~80 列折一次，行尾单个 `\`。
    /// 不合并就会把 `00,41,` 后半截当独立值行解析，然后整份还原失败或写错。
    #[test]
    fn 合并折行的长_hex() {
        let text = format!(
            "{HDR}[HKEY_CURRENT_USER\\Fold]\r\n\"big\"=hex:41,42,43,\\\r\n44,45,46\r\n"
        );
        let secs = parse_reg_text(&text).unwrap();
        assert_eq!(
            secs[0].writes[0],
            RegWrite::Set { name: "big".into(), kind: RK_BINARY, data: vec![0x41, 0x42, 0x43, 0x44, 0x45, 0x46] }
        );
    }

    #[test]
    fn 别名根归一为全名且_整键删除可辨() {
        let text = format!("{HDR}[-HKLM\\SOFTWARE\\TrimGone]\r\n");
        let secs = parse_reg_text(&text).unwrap();
        assert_eq!(secs[0].hive, "HKEY_LOCAL_MACHINE");
        assert_eq!(secs[0].subkey, "SOFTWARE\\TrimGone");
        assert!(secs[0].delete_key);
    }

    /// 形状不对必须 Err（不是"部分接受"）。四类都要红：缺头 / 无键段 / 值行在段前 / 截断。
    ///
    /// **末尾的正向对照不是凑数**：本用例第一次跑的时候解析器是坏的（版本头没跳过、
    /// 续行合并逻辑自己判不到），结果这六条 `is_err()` 断言**全绿**——因为一个
    /// 「把任何输入都拒掉」的解析器恰好完美满足它们。所以这里必须钉一条
    /// 「同一份输入去掉坏因素后能解析成功」，否则本用例证明不了任何东西。
    #[test]
    fn 四类坏形状一律拒绝() {
        assert!(parse_reg_text("[HKEY_LOCAL_MACHINE\\SOFTWARE]\r\n\"a\"=dword:1\r\n").is_err());
        assert!(parse_reg_text("Windows Registry Editor Version 5.00\r\n").is_err());
        assert!(parse_reg_text("Windows Registry Editor Version 5.00\r\n\"a\"=dword:1\r\n").is_err());
        assert!(parse_reg_text(
            "Windows Registry Editor Version 5.00\r\n[HKEY_LOCAL_MACHINE\\A]\r\n\"a\"=hex:41,\\"
        )
        .is_err());
        // 未知根与未支持形态
        assert!(parse_reg_text("Windows Registry Editor Version 5.00\r\n[HKEY_WEIRD\\A]\r\n").is_err());
        assert!(parse_reg_text(
            "Windows Registry Editor Version 5.00\r\n[HKEY_LOCAL_MACHINE\\A]\r\n\"a\"=hex(a):41\r\n"
        )
        .is_err());

        // ---- 正向对照：上面每一条的"去掉坏因素"版本都必须成功 ----
        assert!(parse_reg_text(
            "Windows Registry Editor Version 5.00\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE]\r\n\"a\"=dword:1\r\n"
        )
        .is_ok());
        assert!(parse_reg_text(
            "Windows Registry Editor Version 5.00\r\n[HKEY_LOCAL_MACHINE\\A]\r\n\"a\"=hex:41,42\r\n"
        )
        .is_ok());
        assert!(parse_reg_text("Windows Registry Editor Version 5.00\r\n[HKLM\\A]\r\n").is_ok());
        // QWORD 走 `hex(b):`（reg.exe export 的真实形态：逗号分隔）。
        // 这里断言到具体 kind + 字节，而不是只 is_ok()——否则"解析成功但类型解析错"
        // 这一整类失败模式测不到，而那正是 A6 唯一真正在改的东西。
        let q = parse_reg_text(
            "Windows Registry Editor Version 5.00\r\n[HKEY_LOCAL_MACHINE\\A]\r\n\"a\"=hex(b):01,00,00,00,00,00,00,00\r\n",
        )
        .expect("hex(b) 应能解析");
        assert_eq!(q[0].writes[0], RegWrite::Set {
            name: "a".into(),
            kind: RK_QWORD,
            data: 1u64.to_le_bytes().to_vec(),
        });
    }

    /// R-3（P0 约束条款，2026-10-07）：零长度值必须能被 `.reg` 表达、解析并原样还原 ——
    /// 「先备份后删」的还原依据得装得下空字符串值与零长度二进制值，否则那类值一旦删掉就回不来。
    /// 输入形态就是 `reg.exe export` 对两者的写法（`""` 与 `hex:`）。
    #[test]
    fn 零长度值_空串与空二进制可表达可还原() {
        let text = format!("{HDR}[HKEY_CURRENT_USER\\Zero]\r\n\"empty\"=\"\"\r\n\"bin\"=hex:\r\n@=\"\"\r\n");
        let secs = parse_reg_text(&text).expect("含零长度值的 .reg 必须能解析");
        let w = &secs[0].writes;
        assert_eq!(w.len(), 3, "三条值行都要解析出来: {w:?}");
        assert_eq!(
            w[0],
            RegWrite::Set { name: "empty".into(), kind: RK_SZ, data: utf16_with_nul("") },
            "空字符串值必须是 REG_SZ + 单个尾 NUL（不是被拒、也不是 0 字节）"
        );
        assert_eq!(
            w[1],
            RegWrite::Set { name: "bin".into(), kind: RK_BINARY, data: Vec::new() },
            "零长度二进制必须解析成 0 字节 REG_BINARY"
        );
        assert_eq!(
            w[2],
            RegWrite::Set { name: String::new(), kind: RK_SZ, data: utf16_with_nul("") },
            "默认值也要能表达空串"
        );
    }

    /// 默认值 `@=` 的名字必须是空串，而不是字面量 "@"。
    /// 写错会得到一个叫 "@" 的值，而真正的默认值没被还原 —— 回执却像成功。
    #[test]
    fn 默认值名是空串而非_at() {
        let text = format!("{HDR}[HKEY_CURRENT_USER\\Def]\r\n@=\"hello\"\r\n");
        let secs = parse_reg_text(&text).unwrap();
        assert_eq!(
            secs[0].writes[0],
            RegWrite::Set { name: String::new(), kind: RK_SZ, data: utf16_with_nul("hello") }
        );
    }

    /// 编码回归（A6 顺带挖出的既有缺陷）：`reg.exe export` 的默认产物是 UTF-16LE+BOM，
    /// 而改造前 `parse_reg_backup` 用 `fs::read_to_string` 读它 —— 那不是合法 UTF-8，
    /// 于是**凡走 export 的备份都过不了本应用自己的还原闸**，被拒成「不是合法的 .reg」。
    ///
    /// 三条断言各管一头：UTF-16 能解、UTF-8 能解、旧的 read_to_string 确实会在 UTF-16 上失败
    /// （最后一条是"为什么必须有这个函数"的证据；没有它，本用例可能被一个
    ///  「恰好把两种编码都当二进制塞过去」的实现蒙过）。
    #[test]
    fn utf16le_bom_备份能读_且旧口径确实读不了() {
        let text = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Demo]\r\n\"a\"=dword:00000001\r\n";
        let mut bytes: Vec<u8> = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let decoded = decode_reg_bytes(&bytes).expect("UTF-16LE+BOM 应能解码");
        assert!(decoded.starts_with("Windows Registry Editor Version 5.00"));
        let secs = parse_reg_text(&decoded).expect("解码后应能值级解析");
        assert_eq!(secs[0].writes[0], RegWrite::Set {
            name: "a".into(), kind: RK_DWORD, data: 1u32.to_le_bytes().to_vec()
        });

        // UTF-8（本应用自己的写入器与数据层步骤体的形态）同样要能读
        let utf8 = text.as_bytes().to_vec();
        assert!(decode_reg_bytes(&utf8).is_ok());
        let utf8_bom = [&[0xEFu8, 0xBB, 0xBF][..], text.as_bytes()].concat();
        assert!(decode_reg_bytes(&utf8_bom).is_ok());

        // 旧口径的证据：同一份 UTF-16 字节，read_to_string 必失败
        assert!(std::str::from_utf8(&bytes).is_err(), "若这条红了，说明 UTF-16 已是合法 UTF-8，本用例失去意义");

        // 截断的 UTF-16（BOM 后奇数字节）必须 Err，不能默默丢掉最后半个码元
        assert!(
            decode_reg_bytes(&[0xFFu8, 0xFE, 0x41]).is_err(),
            "BOM 后奇数字节的 UTF-16 必须被拒"
        );
    }

    impl RegWrite {
        fn kind_of(&self) -> Option<u32> {
            match self {
                RegWrite::Set { kind, .. } => Some(*kind),
                RegWrite::DeleteValue { .. } => None,
            }
        }
    }

    /// A6 端到端：原生 import 真的把一份 UTF-16LE `.reg` 写进注册表，且**类型不降级**。
    ///
    /// 为什么必须有这条实跑：单元层只能证明解析器自洽，证明不了 `reg_restore_write`
    /// 收到的字节布局与 `reg.exe import` 一致 —— 而 A6 换掉的正是这一层。
    /// 特别是 `hex(2)` 必须落回 `REG_EXPAND_SZ`：写成 `REG_SZ` 的话 `%USERPROFILE%`
    /// 会永久变成字面量，而界面上一切看起来都正常。
    ///
    /// 卫生口径照 `optimizer::value_level_backup_restore_keeps_types_on_real_registry`：
    /// 只碰自己的 scratch 键，`Drop` 里删干净（含断言失败时提前返回的路径）。
    #[test]
    #[ignore = "真实写注册表（scratch 键 + Drop 清理），发布前门禁跑"]
    fn live_roundtrip_原生import_类型不降级() {
        const SUB: &str = r"Software\TrimRegImportProbe";
        struct Probe;
        impl Drop for Probe {
            fn drop(&mut self) {
                let _ = crate::engine::native::reg_key_remove(
                    crate::engine::native::hive_hkcu(),
                    SUB,
                    true,
                );
            }
        }
        let _probe = Probe;
        // 先塞一个待删值，验证 `"gone"=-` 真能把它删掉
        let h = crate::engine::native::hive_hkcu();
        assert!(crate::engine::native::reg_restore_write(
            h, SUB, "gone", REG_VALUE_TYPE(RK_SZ), &utf16_with_nul("还在")
        ));

        // hex 串由目标字符串生成，不手抄字节 —— 手抄时我漏掉过一个 `%`，
        // 结果测试把"内容不对"报成"实现不对"，白查一轮。
        let hex_of = |s: &str| -> String {
            s.encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .chain(std::iter::once(0))
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let text = "Windows Registry Editor Version 5.00\r\n\r\n".to_string()
            + &format!("[HKEY_CURRENT_USER\\{SUB}]\r\n")
            + "\"dw\"=dword:ffffffff\r\n"
            + &format!("\"expand\"=hex(2):{}\r\n", hex_of(r"%USERPROFILE%\App"))
            + &format!("\"multi\"=hex(7):{}\r\n", hex_of("A\u{0}B"))
            + "\"cn\"=\"中文 值\"\r\n"
            + "\"gone\"=-\r\n";
        // 按 reg.exe export 的真实形态写盘：UTF-16LE + BOM
        let mut bytes: Vec<u8> = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let file = std::env::temp_dir().join(format!("trim-a6-probe-{}.reg", crate::engine::now_ms()));
        std::fs::write(&file, &bytes).expect("临时 .reg 应可写");

        let stat = reg_import_apply(&file).expect("原生 import 应成功");
        let _ = std::fs::remove_file(&file);
        assert!(stat.values_written >= 4, "应至少写入 4 个值: {stat:?}");
        assert_eq!(stat.values_deleted, 1, "`\"gone\"=-` 应删掉一个值: {stat:?}");

        let back = |name: &str| crate::engine::native::read_reg_value_faithful(h, SUB, name);
        // faithful 口径对字符串是**带引号**回报的（与 .reg 里的写法同形），比对前先剥掉
        let bare = |s: String| s.trim_matches('"').to_string();
        let (dw_t, dw_v) = back("dw").expect("dw 应在");
        assert_eq!(dw_t, "REG_DWORD");
        assert_eq!(dw_v.trim(), "-1", "0xFFFFFFFF 按有符号回读应为 -1，实际 {dw_v:?}");
        // 关键断言：EXPAND_SZ 没有被降级成 SZ
        let (ex_t, ex_v) = back("expand").expect("expand 应在");
        assert_eq!(ex_t, "REG_EXPAND_SZ", "EXPAND_SZ 降级成 SZ 会让 %VAR% 永久变字面量");
        assert_eq!(bare(ex_v), r"%USERPROFILE%\App", "内容必须原样往返");
        let (mu_t, mu_v) = back("multi").expect("multi 应在");
        assert_eq!(mu_t, "REG_MULTI_SZ");
        assert!(mu_v.contains('A') && mu_v.contains('B'), "MULTI_SZ 两个元素都要在: {mu_v:?}");
        let (cn_t, cn_v) = back("cn").expect("cn 应在");
        assert_eq!(cn_t, "REG_SZ");
        assert_eq!(bare(cn_v), "中文 值", "中文值在 UTF-16 往返后必须原样");
        assert!(back("gone").is_none(), "`\"gone\"=-` 没删掉那个值");
    }
}
