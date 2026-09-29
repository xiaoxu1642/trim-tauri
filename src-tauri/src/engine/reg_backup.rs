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
//! 封条的边界照 v0.2.6 的裁定不变：备份与封条同在用户可写目录，同一用户可同时改写两者，
//! 所以封条只提升「半截写入/手工误改」的误污染检测与低权限单点篡改的可发现性，
//! **不是防伪凭证**。真防伪要 HKLM 侧常驻提权面，那是另一次拍板。
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
    let sum = match crate::commands::runtimes::sha256_file(file) {
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
    match crate::commands::runtimes::sha256_file(file) {
        Ok(got) if got.eq_ignore_ascii_case(want) => ("ok", meta),
        Ok(_) => ("mismatch", meta),
        Err(_) => ("unreadable", meta),
    }
}

/// 严格 `.reg` 解析：要求版本头 + 至少一个顶层键段，返回去重后的键列表。
/// `None` = 形状不对（半截写入、被截断、或根本不是 .reg），这类文件**不许** import。
/// 刻意不做宽松兼容：还原前必须知道"这份文件会往哪些键里写"，否则等于把未知来源的内容
/// 灌进注册表（v2 时代还原链的教训就是"校验自己解析出来的东西"）。
pub fn parse_reg_backup(file: &Path) -> Option<Vec<String>> {
    parse_reg_backup_text(&std::fs::read_to_string(file).ok()?)
}

/// 同上，输入是文本 —— 拆成纯函数是为了单测能覆盖"半截 .reg / 缺版本头 / 无键段"这三类
/// 形状，不必往数据目录造文件。
pub fn parse_reg_backup_text(text: &str) -> Option<Vec<String>> {
    let first = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())?
        .trim_start_matches('\u{feff}')
        .trim()
        .to_string();
    if !first.eq_ignore_ascii_case("Windows Registry Editor Version 5.00") {
        return None;
    }
    let mut keys: Vec<String> = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix('[') else { continue };
        let Some(inner) = rest.strip_suffix(']') else { continue };
        let k = inner.trim().trim_matches('"').to_string();
        if k.is_empty() {
            continue;
        }
        if !keys.iter().any(|x| x.eq_ignore_ascii_case(&k)) {
            keys.push(k);
        }
    }
    (!keys.is_empty()).then_some(keys)
}

/// 过了四道闸后带回来的信息：会写到哪些键 + 封条当时是什么状态。
/// `seal` 要带出去，因为还原成功的回执会告诉用户"这份有没有封条可对"（`sealWasRecorded`），
/// 那是用户判断"要不要再还原更早一份"的依据，不该在闸里丢掉。
#[derive(Debug)]
pub struct RegBackupCheck {
    pub keys: Vec<String>,
    pub seal: &'static str,
}

/// 还原前的**四道公共闸**，两域共用同一顺序与同一回执口径：
/// ① 严格 `.reg` 解析（形状不对直接拒）② 解析出的每个键都要仍在允许删除的面上
/// ③ 封条核对（`mismatch`/`corrupt`/`unreadable` 拒；`missing` 放行 —— 封条是 v0.2.6
/// 才加的，早期备份与 Electron 轨老备份都没有，拒它们等于把还原依据自己扔掉）
/// ④ 目标含 HKLM 时必须已提权（不提权就让 `reg.exe` 自己失败是**假绿**：用户看到的是
/// "还原失败"，实际是权限不够，两者处置方式完全不同）。
///
/// `is_admin` 由调用方传入而不是在这里查系统，是为了让这四道闸能拿临时目录静默测；
/// 真机那条 `reg import` 端到端仍归 `#[ignore]` 的发布前用例。
pub fn reg_backup_restore_guards(
    file: &Path,
    name: &str,
    is_admin: bool,
) -> Result<RegBackupCheck, String> {
    let Some(keys) = parse_reg_backup(file) else {
        return Err("备份文件不是合法的 .reg（缺版本头或没有任何键段），已拒绝还原".to_string());
    };
    for k in &keys {
        if let Some(reason) = crate::engine::protect::reg_target_block_reason(k) {
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
    if matches!(seal, "mismatch" | "corrupt" | "unreadable") {
        crate::engine::log::write_log("warn", &format!("备份 {name} 封条核对未通过（{seal}），已拒绝还原"));
        return Err(format!(
            "备份内容与封条不符或不可读（{seal}），已拒绝还原——请改用导出时间的更早一份，或重新安装该程序"
        ));
    }
    let needs_admin = keys.iter().any(|k| {
        let u = k.to_uppercase();
        u.starts_with("HKEY_LOCAL_MACHINE") || u.starts_with("HKLM")
    });
    if needs_admin && !is_admin {
        return Err(
            "该备份指向 HKLM 下的键，需要以管理员身份运行后再还原（HKCU 下的备份不需要）".to_string(),
        );
    }
    Ok(RegBackupCheck { keys, seal })
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
            let err = reg_backup_restore_guards(&p, name, true).unwrap_err();
            assert!(err.contains("合法的 .reg"), "{name} 的回执应是形状问题: {err}");
        }
        let ok = root.join("good.reg");
        std::fs::write(&ok, "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Acme]\r\n\"X\"=dword:1\r\n").unwrap();
        let passed = reg_backup_restore_guards(&ok, "good.reg", true).unwrap();
        assert_eq!(passed.keys, vec!["HKEY_CURRENT_USER\\Software\\Acme".to_string()]);
        assert_eq!(
            passed.seal, "missing",
            "合法 HKCU 备份在无封条时也必须放行（missing 不是拒的理由）"
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
        let err = reg_backup_restore_guards(&p, "evil.reg", true).unwrap_err();
        assert!(err.contains("受保护"), "回执应写明是禁删面拦下的: {err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// HKLM 目标 + 未提权 = 明确拒绝，而不是丢给 reg.exe 撞一次"还原失败"
    #[test]
    fn hklm_目标未提权时拒还原() {
        let root = sandbox("admin");
        let p = root.join("hklm.reg");
        std::fs::write(&p, "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\Acme\\App]\r\n\"X\"=dword:1\r\n").unwrap();
        assert!(reg_backup_restore_guards(&p, "hklm.reg", false).unwrap_err().contains("管理员"));
        assert!(reg_backup_restore_guards(&p, "hklm.reg", true).is_ok(), "已提权则放行");
        let _ = std::fs::remove_dir_all(&root);
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
        assert!(reg_backup_restore_guards(&p, "1_acme.reg", true).is_ok());
        // 改写内容 ⇒ mismatch ⇒ 拒
        std::fs::write(&p, format!("{body}\r\n[HKEY_CURRENT_USER\\Software\\Other]\r\n\"Y\"=dword:2\r\n")).unwrap();
        assert_eq!(reg_backup_seal_state(&p).0, "mismatch");
        assert!(reg_backup_restore_guards(&p, "1_acme.reg", true).unwrap_err().contains("封条"));
        // 封条本身坏了 ⇒ corrupt ⇒ 拒
        std::fs::write(reg_seal_path_for(&p), "{不是 json").unwrap();
        assert_eq!(reg_backup_seal_state(&p).0, "corrupt");
        assert!(reg_backup_restore_guards(&p, "1_acme.reg", true).unwrap_err().contains("封条"));
        // 封条文件没了 ⇒ missing ⇒ 放行
        std::fs::remove_file(reg_seal_path_for(&p)).unwrap();
        assert_eq!(reg_backup_seal_state(&p).0, "missing");
        assert!(reg_backup_restore_guards(&p, "1_acme.reg", true).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// D2：严格 `.reg` 解析。还原前必须知道"这份文件会往哪些键里写"，
    /// 所以宁可拒也不能宽松 —— 半截写入的备份尤其要拦。
    #[test]
    fn reg_backup_parser_requires_header_and_keys() {
        let ok = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\ESET]\r\n\"a\"=dword:00000001\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\ESET\\b]\r\n";
        let keys = parse_reg_backup_text(ok).expect("合法 .reg 必须解析通过");
        assert_eq!(keys.len(), 2, "键段去重后应有两条: {keys:?}");
        // BOM 与前后空白是 reg.exe export 的实际形态，不能被当成非法
        assert!(parse_reg_backup_text(&format!("\u{feff} {ok}")).is_some());
        for bad in [
            "",
            "Windows Registry Editor Version 5.00\r\n",              // 有头无键
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\ESET]\r\n\"a\"=dword:1", // 缺版本头
            "Windows Registry Editor Version 5.00\r\n[HKEY_",        // 半截写入
            "Windows Registry Editor Version 5.00\r\n[]\r\n",         // 空键名
        ] {
            assert!(parse_reg_backup_text(bad).is_none(), "这类 .reg 不该通过解析: {bad:?}");
        }
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
}
