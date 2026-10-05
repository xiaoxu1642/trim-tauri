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

/// 读文件并按编码解码（`parse_reg_backup` 与原生 import 共用同一份，避免两套口径）。
pub fn read_reg_text_file(file: &Path) -> Result<String, String> {
    let bytes = std::fs::read(file).map_err(|e| format!("读取 .reg 失败: {e}"))?;
    decode_reg_bytes(&bytes)
}

/// 严格 `.reg` 解析：要求版本头 + 至少一个顶层键段，返回去重后的键列表。
/// `None` = 形状不对（半截写入、被截断、或根本不是 .reg），这类文件**不许** import。
/// 刻意不做宽松兼容：还原前必须知道"这份文件会往哪些键里写"，否则等于把未知来源的内容
/// 灌进注册表（v2 时代还原链的教训就是"校验自己解析出来的东西"）。
pub fn parse_reg_backup(file: &Path) -> Option<Vec<String>> {
    parse_reg_backup_text(&read_reg_text_file(file).ok()?)
}

/// 同上，输入是文本 —— 拆成纯函数是为了单测能覆盖"半截 .reg / 缺版本头 / 无键段"这三类
/// 形状，不必往数据目录造文件。
pub fn parse_reg_backup_text(text: &str) -> Option<Vec<String>> {    let first = text
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
        // `[-HKEY...]` 是「删除键段」，解析器保留前导 `-`；它既不是 Trim 的导出形态，
        // 也没有对应的保护面判定。单独报「不支持删除段」，别让用户从
        // 「含受保护的注册表容器」这句误以为是自己导错了键。
        if k.trim_start().starts_with('-') {
            crate::engine::log::write_log(
                "warn",
                &format!("备份 {name} 含删除键段（{k}），已拒绝还原"),
            );
            return Err("备份内含删除键段（[-HKEY…]），本工具不支持导入该形态，已拒绝还原".to_string());
        }
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
        let err = reg_backup_restore_guards(&p, "del.reg", true).unwrap_err();
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

// ==================== A6：.reg 值级解析 + 原生写入（v2-R4，2026-10-01） ====================
//
// 替换的是**执行器**：`reg.exe import <file>` → 自己解析 + 自己写。
// 刻意不动的两样东西（v2 R4 明令）：`.reg` 文本格式、封条链
// （`reg_backup_seal_state` / `reg_backup_restore_guards` 四道闸原样保留，
//  本模块只在闸**之后**接手，且继续吃同一份 `parse_reg_backup` 的形状判定）。
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
    // 「键段之前的值行」而把整份合法备份判死。
    const HEADER: &str = "Windows Registry Editor Version 5.00";
    let mut logical: Vec<String> = Vec::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let t = raw.trim_end_matches('\r').trim();
        if t.is_empty() || t.starts_with(';') {
            continue;
        }
        if t.trim_start_matches('\u{feff}').eq_ignore_ascii_case(HEADER) {
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

/// 把一份已通过四道闸的 `.reg` 原生写进注册表。
///
/// 失败即停并带着「第几段/哪个值」的原因返回 —— 不做"跳过坏行继续写"，
/// 那会把一次还原变成半截状态而回执仍然像成功。
pub fn reg_import_apply(path: &std::path::Path) -> Result<RegImportStat, String> {
    // 编码感知：备份是 reg.exe export 产的（UTF-16LE），数据层步骤体是本应用写的（UTF-8），
    // 两种都要能读 —— 用 read_to_string 会在第一种上直接失败。
    let text = read_reg_text_file(path)?;
    let sections = parse_reg_text(&text)?;
    let mut stat = RegImportStat::default();
    for sec in &sections {
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
