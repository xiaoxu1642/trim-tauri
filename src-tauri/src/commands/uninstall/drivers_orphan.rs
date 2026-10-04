//! 驱动目录孤儿扫描（v0.5.0 只读，方案 §3 `drivers_orphan`）。
//!
//! 判据方向与 `services_orphan` 相反：那边是「键在，二进制还不在」，这边是
//! 「`.sys` 文件还在磁盘上，但没有任何服务键引用它」。
//!
//! 刻意**不**在这里重复报 stale live：方案 §3 的表把「有服务引用 + 游戏已卸载」也归到
//! `drivers_orphan`，但同一条残留如果在两个分组里各出现一次，用户会读成「有两处要处理」，
//! 而第二阶段接上删除链后更是两个分组指向同一个键。`§2.1` 的「三类互不混报」优先于
//! 文件分工，所以那一条只由 `services_orphan` 出，本组只出「没有任何服务引用」的孤儿。
//!
//! 微软签名件一律不进候选：`System32\drivers` 下绝大多数是系统组件，
//! 少这道闸等于把 Windows 自带的驱动列成残留。签名读不出同样不进候选 ——
//! 「读不出」是证据缺失，不是「确认非微软」。

use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use super::authenticode;
use super::residue_update::contribs;
use super::services_orphan::referenced_landings;

/// 单目录枚举上限（本机 drivers 常规定在几百个量级）
const DRIVER_FILE_CAP: usize = 1200;
/// 候选上限
pub(super) const DRIVER_FINDING_CAP: usize = 60;

/// `%SystemRoot%\System32\drivers\*.sys`（只读列目录，不跟随重解析点）。
pub(super) fn driver_files() -> Vec<PathBuf> {
    let root = match std::env::var_os("SystemRoot") {
        Some(r) => Path::new(&r).join("System32").join("drivers"),
        None => return Vec::new(),
    };
    let Ok(rd) = std::fs::read_dir(&root) else { return Vec::new() };
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("sys")).unwrap_or(false)
        })
        .collect();
    out.sort();
    out.truncate(DRIVER_FILE_CAP);
    out
}

/// 纯判定：`signer` 注入（真实实现读 Authenticode，单测注入一张表）。
///
/// 返回 (候选, 已保护项, notes)。`signer` 返回 None = 读不出证据 ⇒ 既不判孤儿也不判微软，
/// 计入 note 的数量，让用户看得见「这组里有 N 个我没能力判断」。
pub(super) fn driver_findings(
    files: &[PathBuf],
    referenced: &HashSet<String>,
    signer: &dyn Fn(&str) -> Option<String>,
    cap: usize,
) -> (Vec<Value>, Vec<Value>, Vec<String>) {
    let mut candidates = Vec::new();
    let mut protected = Vec::new();
    let mut notes = Vec::new();
    let mut unknown_signer = 0usize;
    for f in files {
        let shown = f.to_string_lossy().to_string();
        let key = shown.replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase();
        if referenced.contains(&key) {
            continue;
        }
        let Some(subject) = signer(&shown) else {
            unknown_signer += 1;
            continue;
        };
        let lower = subject.to_lowercase();
        let is_microsoft = lower.starts_with("microsoft windows")
            || lower.starts_with("microsoft corporation")
            || lower.starts_with("msringsdk");
        if is_microsoft {
            protected.push(json!({
                "kind": "file", "target": shown,
                "class": "microsoft_component",
                "reason": "没有服务引用，但由微软签名 —— 按系统组件保护，不作为残留",
                "readonly": true,
            }));
            continue;
        }
        if candidates.len() >= cap {
            notes.push(format!("驱动孤儿候选已达上限 {cap} 条，其余省略"));
            break;
        }
        candidates.push(json!({
            "kind": "file", "target": shown,
            "class": "orphan_sys_file",
            "reason": "没有任何服务键引用这个 .sys（服务表已反查全部 ImagePath），且签名主体不是微软",
            "confidence": "medium", "risk": "high",
            "readonly": true, "defaultChecked": false,
            "details": json!({ "signer": subject }),
            "contribs": contribs(&[
                ("noServiceReference", format!("服务表 ImagePath 反查未命中：{key}")),
                ("signerSubject", format!("签名主体：{subject}")),
            ]),
        }));
    }
    if unknown_signer > 0 {
        notes.push(format!("{unknown_signer} 个无服务引用的 .sys 读不出签名主体，本轮不作判定（读不出≠未签名）"));
    }
    if files.is_empty() {
        notes.push("drivers 目录列不到（SystemRoot 取不到或目录打不开），本组结果不完整".to_string());
    }
    (candidates, protected, notes)
}

/// 真实采集：读目录 + 逐个问签名。返回 (候选, 已保护, notes, 本次列到的文件数)。
///
/// 只对「没有服务引用」的文件问签名，顺序是有意的：`System32\drivers` 常态有几百个文件，
/// 其中无引用的通常只有几个，把便宜的集合运算放在前面，Authenticode 的开销就只有几毫秒级。
pub(super) unsafe fn collect_driver_findings(
    service_entries: &[super::services_orphan::ServiceEntry],
) -> (Vec<Value>, Vec<Value>, Vec<String>, usize) {
    let files = driver_files();
    let count = files.len();
    let referenced = referenced_landings(service_entries);
    let (c, p, n) = driver_findings(&files, &referenced, &|p: &str| authenticode::signer_subject(p), DRIVER_FINDING_CAP);
    (c, p, n, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn referenced_set(paths: &[&str]) -> HashSet<String> {
        paths.iter().map(|p| p.to_ascii_lowercase()).collect()
    }

    fn files(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn unreferenced_third_party_driver_is_an_orphan() {
        let (cand, prot, notes) = driver_findings(
            &files(&[r"C:\Windows\System32\drivers\GameGuard.sys"]),
            &referenced_set(&[]),
            &|_| Some("ACME Games Ltd.".to_string()),
            60,
        );
        assert_eq!(cand.len(), 1);
        assert_eq!(cand[0]["class"], "orphan_sys_file");
        assert_eq!(cand[0]["readonly"], true);
        assert_eq!(cand[0]["defaultChecked"], false);
        assert!(prot.is_empty());
        assert!(notes.is_empty());
    }

    #[test]
    /// 有服务引用的文件一条都不出 —— 那类归 `services_orphan`，两组不得混报
    fn referenced_driver_is_never_reported_here() {
        let p = r"C:\Windows\System32\DRIVERS\NeacSafe.sys";
        let mut refd = HashSet::new();
        refd.insert(p.to_ascii_lowercase());
        let (cand, prot, _) = driver_findings(&files(&[p]), &refd, &|_| Some("NETEASE".to_string()), 60);
        assert!(cand.is_empty() && prot.is_empty());
    }

    #[test]
    fn microsoft_signed_unreferenced_is_protected_not_orphan() {
        let (cand, prot, _) = driver_findings(
            &files(&[r"C:\Windows\System32\drivers\WdFilter.sys"]),
            &referenced_set(&[]),
            &|_| Some("Microsoft Windows".to_string()),
            60,
        );
        assert!(cand.is_empty());
        assert_eq!(prot.len(), 1);
        assert_eq!(prot[0]["class"], "microsoft_component");
    }

    #[test]
    /// 读不出签名 = 无证据，不得被当成「非微软」而混进候选
    fn unreadable_signer_yields_no_candidate_but_a_visible_note() {
        let (cand, prot, notes) =
            driver_findings(&files(&[r"C:\Windows\System32\drivers\Xyz.sys"]), &referenced_set(&[]), &|_| None, 60);
        assert!(cand.is_empty() && prot.is_empty());
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("读不出签名主体"));
    }

    #[test]
    fn matching_is_case_insensitive_across_reference_forms() {
        // 服务表里写 `C:\Windows\System32\DRIVERS\a.sys`，目录枚举回来是 `...\drivers\A.SYS`
        let (cand, _, _) = driver_findings(
            &files(&[r"C:\Windows\System32\drivers\A.SYS"]),
            &referenced_set(&[r"C:\Windows\System32\DRIVERS\a.sys"]),
            &|_| Some("ACME".to_string()),
            60,
        );
        assert!(cand.is_empty());
    }

    #[test]
    fn candidate_cap_leaves_a_visible_note() {
        let many: Vec<String> = (0..5).map(|i| format!(r"C:\Windows\System32\drivers\D{i}.sys")).collect();
        let many_refs: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
        let (cand, _, notes) = driver_findings(&files(&many_refs), &referenced_set(&[]), &|_p: &str| Some("ACME".to_string()), 3);
        assert_eq!(cand.len(), 3);
        assert!(notes.iter().any(|n| n.contains("已达上限")));
    }

    #[test]
    fn empty_listing_is_reported_as_incomplete_not_clean() {
        let (_, _, notes) = driver_findings(&[], &referenced_set(&[]), &|_p: &str| None, 60);
        assert!(notes.iter().any(|n| n.contains("本组结果不完整")));
    }
}
