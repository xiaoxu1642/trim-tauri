//! ConsentStore `NonPackaged` 落点核对（v0.5.0 只读，方案 §3 `capability_orphan`）。
//!
//! 这棵树记的是「非打包（win32）程序的能力授权」—— 程序卸载后授权还留着，
//! 值名里带的可执行文件路径也就成了指向不存在文件的死条目。
//!
//! 判据只有一条，而且是保守的那一条：**值名解码出的落点不存在，才报告**。
//! 解不出来（值名不是路径形态、变量展开失败）一律不判 —— 这条树里混着系统自己写的
//! 多种格式，猜错一次就会把仍在用的程序的授权列成残留。
//!
//! 落点存在时完全不打扰用户：那是仍在用的程序的正常授权。

use serde_json::{Value, json};
use std::path::Path;
use super::residue_update::contribs;

/// 能力授权树（HKLM 32/64 两种视图都读，HKCU 作为回退）。
///
/// 各 Windows 版本这棵树的位置不完全一致，所以「一根都没打开」时按读不到处理，
/// 按 `no_data` 而不是「这台机器没有残留授权」上报（方案 §6：真机没样本也要能自证扫过）。
pub(super) const CONSENT_SUBKEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ConsentStore\NonPackaged";

/// 32 位视图根。**不能**用 `format!(r"SOFTWARE\WOW6432Node\{}", CONSENT_SUBKEY)` 拼：
/// `CONSENT_SUBKEY` 自己已经带 `SOFTWARE\`，拼出来是
/// `SOFTWARE\WOW6432Node\SOFTWARE\Microsoft\…` 这棵**不存在的键**（`open_key_read` 恒失败，
/// 那一根静默不采集，`readable_roots` 还照常 +1 的前提是它被打开过）。
/// R2b-L09 的用例顺带把它现算出来了：该串归一后既不等于也不落在 `REG_MICROSOFT_ROOTS`
/// 任一条之下，`reg_value_gate` 会给 `NotGoverned` 而不是 `Denied` —— 双 `SOFTWARE` 的形态
/// 连「Microsoft 树内」这一层都判不出来，留着就是给将来的执行面留一个判据盲区。
pub(super) const CONSENT_SUBKEY_WOW6432: &str =
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ConsentStore\NonPackaged";

/// 单根枚举值上限（授权条目随程序数量线性增长，给足但设限）
const CONSENT_VALUE_CAP: usize = 1024;
pub(super) const CAPABILITY_FINDING_CAP: usize = 80;

/// 解码 `NonPackaged` 的值名 → 它记着的那个可执行文件路径。
///
/// 认识的形态（按 `#` 切第一段，再剥内核路径前缀）：
///
/// - `C:\Dir\App.exe#InternetClient`
/// - `\??\C:\Dir\App.exe#-#-#`
/// - `\\?\C:\Dir\App.exe#cap`
///
/// 大小写与 verbatim 前缀的两种写法（`\??\` 内核形式、`\\?\` Win32 形式）都要认，
/// 因为同一条目在不同 Windows 版本里两种都出现过。
/// 返回 None = 判不出来（相对名、没有盘符、空段），调用方按无证据处理。
pub(super) fn decode_nonpackaged_name(name: &str) -> Option<String> {
    let head = name.split('#').next().unwrap_or("").trim();
    let head = head.strip_prefix(r"\??\").or_else(|| head.strip_prefix(r"\\?\")).unwrap_or(head);
    if head.is_empty() {
        return None;
    }
    let b = head.as_bytes();
    let drive_abs = b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
    if drive_abs || head.starts_with(r"\\") {
        Some(head.to_string())
    } else {
        None
    }
}

/// 值名 → 报告里的键前缀（保留原 hive 写法，与执行侧 `HKLM\<子路径>` 口径一致）。
///
/// **这棵树的目标此刻一律不可执行，且这不是本模块的疏漏而是已钉住的口径**
/// （R2b-L09）：`kind` 是 `reg_value`、target 形如 `HKLM\<CONSENT_SUBKEY>::值名`，
/// 而执行侧唯一的 `reg_value` 形状/准入判据是 [`super::run_keys::reg_value_gate`]——
/// 它只给六条 Run/RunOnce 根开窄口子，其余落在 Microsoft 树内的父键按 A1 整棵拒删。
/// ConsentStore 恰好在 `SOFTWARE\Microsoft\` 之下，所以二阶段把本组接进执行链时**必然**
/// 整组判 `Denied`。两个模块此前对「第二阶段」的假设互不知情，现在由
/// `capability_targets_are_currently_unexecutable` 用例把这一事实钉住：
/// 谁将来给 ConsentStore 开闸，就必须同时改那条用例（不许静默留坑）。
pub(super) fn capability_target(hive_label: &str, subkey: &str, value_name: &str) -> String {
    format!("{hive_label}\\{subkey}::{value_name}")
}

/// 纯判定：`exists` 注入落点存在性（单测因此不碰注册表与磁盘）。
///
/// 返回 (候选, 解不出条数, notes)。
pub(super) fn capability_findings(
    hive_label: &str,
    subkey: &str,
    value_names: &[String],
    exists: &dyn Fn(&str) -> bool,
    cap: usize,
) -> (Vec<Value>, usize, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let mut undecodable = 0usize;
    for name in value_names {
        let Some(path) = decode_nonpackaged_name(name) else {
            undecodable += 1;
            continue;
        };
        if exists(&path) {
            continue;
        }
        if out.len() >= cap {
            // R2b-L03：`cap` 是「本根剩余额度」，用户要看的却是「本组全局上限」。
            // 只写剩余额度时，额度用尽那一轮会渲染成「已达上限 0 条」这种自相矛盾的话。
            notes.push(format!(
                "能力授权残留候选已达上限 {CAPABILITY_FINDING_CAP} 条（本轮剩余额度 {cap}），其余省略（本组结果不完整）"
            ));
            break;
        }
        out.push(json!({
            "kind": "reg_value", "target": capability_target(hive_label, subkey, name),
            "class": "capability_consent_dead_landing",
            "reason": "非打包程序的能力授权还留着，但它记的可执行文件已不存在",
            "confidence": "medium", "risk": "low",
            "readonly": true, "defaultChecked": false,
            "details": json!({ "decodedPath": path, "hive": hive_label }),
            "contribs": contribs(&[
                ("valueNameDecoded", format!("值名按 `#` 切第一段得到：{path}")),
                ("landingMissing", "该路径当前不存在（授权随程序一起失去了对象）".to_string()),
            ]),
        }));
    }
    if undecodable > 0 {
        notes.push(format!("{undecodable} 条授权值名解不出可执行文件路径，本轮不判（这棵树里混着多种非路径格式）"));
    }
    (out, undecodable, notes)
}

/// 采集：逐根读值名并判落点。返回 (候选, notes)。
///
/// 三根里只要有一根读到，就用那根出结果；全都读不到时写一条明确的 note，
/// 不把「没读到」渲染成「本机无残留」。
pub(super) unsafe fn collect_capability_findings() -> (Vec<Value>, Vec<String>) {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RegCloseKey};
    let mut notes = Vec::new();
    let mut all: Vec<Value> = Vec::new();
    let mut readable_roots = 0usize;
    let mut total_undecodable = 0usize;
    for (label, hive, sub) in [
        ("HKLM", HKEY_LOCAL_MACHINE, CONSENT_SUBKEY.to_string()),
        ("HKLM", HKEY_LOCAL_MACHINE, CONSENT_SUBKEY_WOW6432.to_string()),
        ("HKCU", HKEY_CURRENT_USER, CONSENT_SUBKEY.to_string()),
    ] {
        let Some(hk) = super::helpers::open_key_read(hive, &sub) else { continue };
        // R2b-L01：多问一条才能把「恰好读满」与「被上限截断」分开（同 com_orphan 的姿势）
        let names = super::helpers::reg_value_names(hk, CONSENT_VALUE_CAP + 1);
        let truncated = names.len() > CONSENT_VALUE_CAP;
        let _ = RegCloseKey(hk);
        let names: Vec<String> = names.into_iter().take(CONSENT_VALUE_CAP).collect();
        readable_roots += 1;
        if truncated {
            notes.push(format!("根 {sub} 的值名数达到枚举上限 {CONSENT_VALUE_CAP}，本轮只判前 {CONSENT_VALUE_CAP} 条（本组结果不完整）"));
        }
        if all.len() >= CAPABILITY_FINDING_CAP {
            // R2b-L03：全局额度已用尽 —— 本根整批不采，但必须留痕，
            // 否则用户读到的是「前面几根的 80 条就是全部残留」。
            notes.push(format!("能力授权候选已达全局上限 {CAPABILITY_FINDING_CAP} 条，根 {sub} 本轮未纳入采集（本组结果不完整）"));
            continue;
        }
        let (items, undec, inner_notes) =
            capability_findings(label, &sub, &names, &|p: &str| Path::new(p).exists(), CAPABILITY_FINDING_CAP.saturating_sub(all.len()));
        total_undecodable += undec;
        // R2b-L03：内层 notes 此前被 `_n` 丢掉 ⇒ 截断只发生在采集侧、渲染层看不见。
        // 三根共用一份注集，同措辞去重（合并后仍各算一次，不会把一个上限报成三条）
        for n in inner_notes {
            if !notes.contains(&n) {
                notes.push(n);
            }
        }
        all.extend(items);
    }
    if readable_roots == 0 {
        notes.push(format!("能力授权树读不到（{CONSENT_SUBKEY} 三处根都打不开，或本机 Windows 版本没有这棵树），本组未采集"));
    } else if total_undecodable > 0 {
        notes.push(format!("{total_undecodable} 条能力授权值名解不出可执行文件路径，本轮不判"));
    }
    if all.is_empty() && readable_roots > 0 {
        notes.push("能力授权树读到过，但没有落点已失踪的条目".to_string());
    }
    (all, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_the_capability_delimiter() {
        assert_eq!(decode_nonpackaged_name(r"C:\Apps\Foo\foo.exe#InternetClient").as_deref(), Some(r"C:\Apps\Foo\foo.exe"));
        assert_eq!(decode_nonpackaged_name(r"C:\Apps\Foo\foo.exe#-#-#").as_deref(), Some(r"C:\Apps\Foo\foo.exe"));
    }

    #[test]
    fn both_verbatim_prefix_forms_are_stripped() {
        // 内核形式与 Win32 形式在不同 Windows 版本里都出现过，认漏一种就会把
        // `\??\C:\...` 当成不存在的相对路径报出去
        assert_eq!(decode_nonpackaged_name(r"\??\C:\Apps\Foo\foo.exe#cap").as_deref(), Some(r"C:\Apps\Foo\foo.exe"));
        assert_eq!(decode_nonpackaged_name(r"\\?\C:\Apps\Foo\foo.exe#cap").as_deref(), Some(r"C:\Apps\Foo\foo.exe"));
    }

    #[test]
    fn non_path_and_relative_value_names_are_no_evidence() {
        for n in ["", "#InternetClient", r"foo.exe#cap", r"Relative\Dir\foo.exe#cap", "AllUserFeature"] {
            assert_eq!(decode_nonpackaged_name(n), None, "{n} 不该被解成路径");
        }
    }

    #[test]
    fn only_missing_landings_are_reported() {
        let names = [
            r"C:\Apps\Gone\g.exe#InternetClient".to_string(),
            r"C:\Apps\Alive\a.exe#InternetClient".to_string(),
            "NotAPath#cap".to_string(),
        ];
        let (out, undec, notes) =
            capability_findings("HKLM", CONSENT_SUBKEY, &names, &|p: &str| p.contains("Alive"), 80);
        assert_eq!(out.len(), 1);
        assert_eq!(undec, 1);
        assert!(out[0]["target"].as_str().unwrap_or("").starts_with("HKLM\\") && out[0]["target"].as_str().unwrap_or("").ends_with("#InternetClient"));
        assert_eq!(out[0]["class"], "capability_consent_dead_landing");
        assert_eq!(out[0]["readonly"], true);
        assert_eq!(out[0]["defaultChecked"], false);
        // 解不出的那 1 条必须留下可见的痕迹，而不是静默少一列
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("解不出可执行文件路径"));
    }

    #[test]
    fn target_keeps_the_parent_and_value_split_the_executor_expects() {
        // `classify_residue_op("reg_value")` 按 `rsplit_once("::")` 拆键与值名，
        // 本组产出的串必须是同一个形状，否则第二阶段接上时会整条判「格式错误」
        let t = capability_target("HKLM", CONSENT_SUBKEY, r"C:\A\b.exe#cap");
        let (key_part, value_name) = t.rsplit_once("::").expect("必须能按 :: 拆");
        assert_eq!(key_part, format!("HKLM\\{CONSENT_SUBKEY}"));
        assert_eq!(value_name, r"C:\A\b.exe#cap");
        assert!(super::super::helpers::parse_reg_target(key_part).is_some());
    }

    #[test]
    fn cap_leaves_a_note_and_undecodable_count_is_visible() {
        let names: Vec<String> = (0..5).map(|i| format!(r"C:\Apps\Gone{i}\g.exe#cap")).collect();
        let (out, _u, notes) = capability_findings("HKLM", CONSENT_SUBKEY, &names, &|_: &str| false, 2);
        assert_eq!(out.len(), 2);
        assert!(notes.iter().any(|n| n.contains("已达上限") && n.contains("本组结果不完整")));
        // R2b-L03：注记里的数字必须是**全局上限**，不是剩余额度（旧写法在额度用尽时
        // 会渲染成「已达上限 0 条」）
        let used_up = capability_findings("HKLM", CONSENT_SUBKEY, &names, &|_: &str| false, 0);
        assert!(used_up.0.is_empty());
        assert!(
            used_up.2.iter().any(|n| n.contains(&format!("已达上限 {CAPABILITY_FINDING_CAP} 条"))),
            "剩余额度为 0 时注记仍要点名全局上限: {:?}",
            used_up.2
        );
    }

    /// R2b-L09：本组产出的 `reg_value` 目标此刻**整组不可执行**（执行侧判据拒），
    /// 这条用例是两模块之间唯一的知情渠道。哪天 ConsentStore 开闸，本用例必红，
    /// 就必须同时改 `capability_target` 的注释与二阶段方案。
    #[test]
    fn capability_targets_are_currently_unexecutable() {
        for (label, sub) in [
            ("HKLM", CONSENT_SUBKEY.to_string()),
            ("HKLM", CONSENT_SUBKEY_WOW6432.to_string()),
            ("HKCU", CONSENT_SUBKEY.to_string()),
        ] {
            let t = capability_target(label, &sub, r"C:\Apps\Gone\g.exe#InternetClient");
            match super::super::run_keys::reg_value_gate(&t) {
                super::super::run_keys::RegValueGate::Denied(reason) => assert!(
                    reason.contains("Microsoft"),
                    "拒因应点名 Microsoft 系统命名空间，实际: {reason}"
                ),
                // RegValueGate 没有 Debug，只能把两种「不该出现」的结论分开点名
                super::super::run_keys::RegValueGate::Allowed => {
                    panic!("ConsentStore 目标被判成 Allowed —— 开闸了请同步 capability_target 注释与本用例")
                }
                super::super::run_keys::RegValueGate::NotGoverned => {
                    panic!("reg_value_gate 不再管辖 ConsentStore 目标 —— 口径已变，请同步本注释")
                }
            }
        }
        // 正对照：六条 Run 根之一的具名值必须放行 —— 否则上面只是「什么都拒」的假绿
        let run_t = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run::Acme";
        assert!(
            matches!(super::super::run_keys::reg_value_gate(run_t), super::super::run_keys::RegValueGate::Allowed),
            "Run 根的具名值应放行（正对照失效说明判据被整体改坏）"
        );
    }
}
