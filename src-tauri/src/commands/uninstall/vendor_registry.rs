//! 厂商注册表键残留扫描（v0.5.0 只读，方案 §3 `vendor_registry`）。
//!
//! 收口口径是这一组的核心，也是方案点名要纠正的写法：**不能只按 Publisher 互含**。
//! 「Publisher 里含 ACME」既认不出哪个产品键属于哪个已卸载的程序，也挡不住
//! `HKLM\SOFTWARE\ACME\Shared` 这种还在用的公共键。本文件的判据是：
//! 1. 候选粒度到**产品子键**（`HKLM\SOFTWARE\<厂商>\<产品>`），不到厂商顶层；
//! 2. 该键下必须能解析出**具体落点**（`InstallLocation` / 安装目录 / 主 exe 这类路径值）；
//! 3. 全部落点都不存在 ⇒ 才进候选；只要有一个落点还在 ⇒ 不报；
//! 4. 卸载列表里还活着同名/同厂商记录 ⇒ 不报（程序还在，键当然该在）。
//!
//! 一条都没有就意味着「这个键里没有可核对的路径线索」，那种键本轮**不判**，
//! 而不是判成残留 —— 注册表键里绝大多数是配置值，不是安装落点。

use serde_json::{Value, json};
use std::collections::HashSet;
use super::dead::dead_landing;
use super::helpers::{open_key_read, reg_sz};
use super::ownership::footprint;
use super::residue::{reg_enum_subkeys, reg_enum_sz_values};
use super::residue_update::contribs;
use crate::engine::protect;

/// 三个软件根（与 `collect_vendor_keys` / 所有权链同一套根，不另立口径）
const VENDOR_ROOTS: [(&str, windows::Win32::System::Registry::HKEY, &str); 3] = {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    [
        ("HKCU", HKEY_CURRENT_USER, r"Software"),
        ("HKLM", HKEY_LOCAL_MACHINE, r"SOFTWARE"),
        ("HKLM", HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node"),
    ]
};

/// 每个厂商根下枚举多少个厂商键（与所有权链共用 `footprint::MAX_KEYS_PER_OWNER`）
/// 每个厂商键下枚举多少个产品子键
const PRODUCT_SUBKEY_CAP: usize = 40;
/// 单个产品键下解析落点用的值上限
const PRODUCT_VALUE_CAP: usize = 64;
pub(super) const VENDOR_FINDING_CAP: usize = 60;

/// 一个厂商产品键的只读采集结果
#[derive(Debug, Clone)]
pub(super) struct VendorProductRaw {
    /// 完整目标串（与执行侧口径一致：`HKCU\<子路径>` / `HKLM\<子路径>`）
    pub(super) target: String,
    pub(super) vendor: String,
    pub(super) product: String,
    /// 该键下路径型值解析出的落点（`InstallLocation` / `InstallDir` / exe 形态值）
    pub(super) landings: Vec<String>,
}

/// 名字是否与某个仍在卸载列表里的程序对得上（小写互含，阈值走本域 `NAME_MIN_EXACT` 那档：
/// 这是「拿表里的名字撞表里的名字」，不是自由猜测）。
fn matches_alive(name: &str, alive_names: &HashSet<String>) -> bool {
    let n = name.trim().to_lowercase();
    if n.len() < super::residue::NAME_MIN_EXACT {
        return false;
    }
    alive_names.iter().any(|d| d.contains(&n) || n.contains(d.as_str()))
}

/// 纯判定：产品键是否可作为「厂商键残留」报告出来。
///
/// 返回 (候选, notes)。`exists` 注入落点存在性，单测因此不碰注册表与磁盘。
pub(super) fn vendor_findings(
    raws: &[VendorProductRaw],
    alive_names: &HashSet<String>,
    exists: &dyn Fn(&str) -> bool,
    cap: usize,
) -> (Vec<Value>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let (mut no_landing, mut alive_skipped) = (0usize, 0usize);
    for raw in raws {
        if matches_alive(&raw.product, alive_names) || matches_alive(&raw.vendor, alive_names) {
            alive_skipped += 1;
            continue;
        }
        if raw.landings.is_empty() {
            no_landing += 1;
            continue;
        }
        if raw.landings.iter().any(|l| exists(l)) {
            continue;
        }
        if out.len() >= cap {
            notes.push(format!("厂商键候选已达上限 {cap} 条，其余省略"));
            break;
        }
        // 只读阶段不拦，但把 A1 判定写进证据：这条键将来能不能删，此处先留痕
        let blocked = protect::reg_target_block_reason(&raw.target);
        out.push(json!({
            "kind": "reg_key", "target": raw.target,
            "class": "vendor_product_key_no_landing",
            "reason": "厂商产品键记着的安装落点与主程序全部已不存在，且卸载列表里没有同名程序",
            "confidence": "medium", "risk": "high",
            "readonly": true, "defaultChecked": false,
            "details": json!({ "vendor": raw.vendor, "product": raw.product, "landings": raw.landings, "denyFaceKeepsIt": blocked.is_some() }),
            "contribs": contribs(&[
                ("productSubkeyScope", format!("判定粒度到产品子键：{}\\{}", raw.vendor, raw.product)),
                ("allLandingsMissing", format!("键内 {} 条路径线索全部落空：{}", raw.landings.len(), raw.landings.join("；"))),
                ("denyFace", blocked.unwrap_or_else(|| "当前禁删面未拦这条".to_string())),
            ]),
        }));
    }
    if no_landing > 0 {
        notes.push(format!("{no_landing} 个厂商产品键里解析不出任何路径线索，本轮不判（配置值不是安装落点）"));
    }
    if alive_skipped > 0 {
        notes.push(format!("{alive_skipped} 个厂商产品键因卸载列表里仍有同名程序而被保护"));
    }
    (out, notes)
}

/// 采集：三根 → 厂商键 → 产品子键 → 键内路径型值的落点。
///
/// 只读一层产品子键（`<厂商>\<产品>`）是刻意的：再往下走就成了遍历整棵厂商树，
/// 成本与误报面一起涨，而方案要的收口就是这一层。
pub(super) unsafe fn collect_vendor_raws() -> (Vec<VendorProductRaw>, bool) {
    let mut out = Vec::new();
    let mut enumerated_roots = 0usize;
    for (label, hive, sub) in VENDOR_ROOTS {
        let vendors = reg_enum_subkeys(hive, sub, footprint::MAX_KEYS_PER_OWNER);
        if vendors.is_empty() {
            continue;
        }
        enumerated_roots += 1;
        for vendor in vendors {
            if !footprint::is_vendor_key(&vendor) {
                continue;
            }
            let vendor_path = format!("{sub}\\{vendor}");
            for product in reg_enum_subkeys(hive, &vendor_path, PRODUCT_SUBKEY_CAP) {
                if out.len() >= VENDOR_FINDING_CAP * 4 {
                    break;
                }
                let product_path = format!("{vendor_path}\\{product}");
                let landings = landing_values(hive, &product_path);
                out.push(VendorProductRaw {
                    target: format!("{label}\\{product_path}"),
                    vendor: vendor.clone(),
                    product,
                    landings,
                });
            }
        }
    }
    (out, enumerated_roots > 0)
}

/// 从一个键里取出「看起来是安装落点」的值并解析成文件路径。
///
/// 取三类值名（InstallLocation / InstallDir / Path 之外的一律不猜）+ 任意值的
/// 数据里能按 `dead_landing` 解析出绝对 `.exe`/`.dll`/`.sys` 的那些。
/// 用同一个解析器是有意的：`dead_landing` 已经处理了 `\??\`、`\SystemRoot`、`%VAR%`、
/// 带引号带参数这几种注册表写法，自己再切一遍只会造出第二套口径。
unsafe fn landing_values(hive: windows::Win32::System::Registry::HKEY, subkey: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let push = |raw: &str, out: &mut Vec<String>| {
        if let Some(l) = dead_landing(raw) {
            if !out.iter().any(|o| o == &l) {
                out.push(l);
            }
        } else {
            // 目录形态（InstallLocation 常是纯目录，没有 exe 后缀，dead_landing 会拒）
            let t = raw.trim().trim_matches('"').trim_end_matches('\\');
            if t.len() > 3 && t.as_bytes()[1] == b':' && !t.contains('%') && !out.iter().any(|o| o == t) {
                out.push(t.to_string());
            }
        }
    };
    if let Some(hk) = open_key_read(hive, subkey) {
        use windows::Win32::System::Registry::RegCloseKey;
        for name in ["InstallLocation", "InstallDir", "Path", "InstallPath"] {
            if let Some(v) = reg_sz(hk, name) {
                push(&v, &mut out);
            }
        }
        let _ = RegCloseKey(hk);
    }
    for (_n, data) in reg_enum_sz_values(hive, subkey, PRODUCT_VALUE_CAP) {
        push(&data, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(target: &str, vendor: &str, product: &str, landings: &[&str]) -> VendorProductRaw {
        VendorProductRaw {
            target: target.to_string(),
            vendor: vendor.to_string(),
            product: product.to_string(),
            landings: landings.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn alive(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_lowercase()).collect()
    }

    #[test]
    fn all_landings_missing_and_no_live_record_is_a_candidate() {
        let raws = [raw(r"HKLM\SOFTWARE\ACME\OldApp", "ACME", "OldApp", &[r"C:\Program Files\ACME\Old\app.exe"])];
        let (out, notes) = vendor_findings(&raws, &alive(&[]), &|_: &str| false, 60);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["class"], "vendor_product_key_no_landing");
        assert_eq!(out[0]["readonly"], true);
        assert_eq!(out[0]["defaultChecked"], false);
        assert!(notes.is_empty());
    }

    #[test]
    /// 收口第 3 条：只要有一个落点还在就不报 —— 这是与「只按 Publisher 互含」最实质的差别
    fn any_alive_landing_vetoes_the_candidate() {
        let r = [raw(r"HKLM\SOFTWARE\ACME\App", "ACME", "App", &[r"C:\Program Files\ACME\App\a.exe", r"C:\Program Files\ACME\App\gone.dll"])];
        let (out, _) = vendor_findings(&r, &alive(&[]), &|p: &str| p.ends_with("a.exe"), 60);
        assert!(out.is_empty());
    }

    #[test]
    /// 收口第 4 条：卸载列表里还有同名程序 ⇒ 键该留着，一条都不报
    fn live_uninstall_record_protects_the_key() {
        let r = [raw(r"HKLM\SOFTWARE\ACME\App", "ACME", "App", &[r"C:\Program Files\ACME\App\a.exe"])];
        let (out, notes) = vendor_findings(&r, &alive(&["App 2.1 中文版"]), &|_: &str| false, 60);
        assert!(out.is_empty());
        assert!(notes.iter().any(|n| n.contains("被保护")));
    }

    #[test]
    /// 收口第 2 条：解析不出任何路径线索的键**不判**，而不是判成残留
    fn key_without_any_landing_is_not_judged() {
        let r = [raw(r"HKLM\SOFTWARE\ACME\Settings", "ACME", "Settings", &[])];
        let (out, notes) = vendor_findings(&r, &alive(&[]), &|_: &str| false, 60);
        assert!(out.is_empty());
        assert!(notes.iter().any(|n| n.contains("本轮不判")));
    }

    #[test]
    fn matches_alive_requires_a_meaningful_name() {
        // 1 字符的名字不许去撞卸载列表（会命中一大片），阈值与本域 NAME_MIN_EXACT 同源
        assert!(!matches_alive("a", &alive(&["abc"])));
        assert!(matches_alive("ab", &alive(&["abc"])));
        assert!(matches_alive("ACME", &alive(&["acme viewer"])));
    }

    #[test]
    fn candidate_cap_leaves_a_note() {
        let raws: Vec<VendorProductRaw> =
            (0..5).map(|i| raw(&format!(r"HKLM\SOFTWARE\ACME\P{i}"), "ACME", &format!("P{i}"), &[r"C:\gone\x.exe"])).collect();
        let (out, notes) = vendor_findings(&raws, &alive(&[]), &|_: &str| false, 2);
        assert_eq!(out.len(), 2);
        assert!(notes.iter().any(|n| n.contains("已达上限")));
    }

    #[test]
    fn vendor_roots_match_the_ownership_chain_roots() {
        // 与所有权链/失效残留同一套三根；改这里必须同步改那两处，否则三组扫描面会各扫一半
        let labels: Vec<String> = VENDOR_ROOTS.iter().map(|(l, _, s)| format!("{l}\\{s}")).collect();
        assert_eq!(labels, vec![r"HKCU\Software", r"HKLM\SOFTWARE", r"HKLM\SOFTWARE\WOW6432Node"]);
    }

    #[test]
    fn product_leaf_is_the_only_shape_that_passes_the_deny_face() {
        // 厂商顶层键（`HKLM\SOFTWARE\ACME`）在 A1 里是「容器本身还是产品叶」的边界样本；
        // 产品子键应当放行 —— 这条断言钉住「将来第二阶段能删的粒度」与本阶段报告的粒度一致
        assert!(protect::reg_target_block_reason(r"HKLM\SOFTWARE\ACME\OldApp").is_none());
        assert!(protect::reg_target_block_reason(r"HKLM\SOFTWARE").is_some());
    }
}
