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
use crate::engine::protect;

/// 单目录枚举上限（本机 drivers 常规定在几百个量级）
const DRIVER_FILE_CAP: usize = 1200;
/// 候选上限
pub(super) const DRIVER_FINDING_CAP: usize = 60;

/// `%SystemRoot%\System32\drivers` 下的 `.sys` 文件清单（只读列目录）。
///
/// 返回 (文件, 残缺注记)。R2b-L01：枚举上限此前是**静默**截断（`sort()` 后 `truncate()`），
/// 用户看到的是「这台机器的 drivers 就这么几个」；现在触顶即出注记。
/// R2b-L04：文件头与旧注释都写着「不跟随重解析点」，但旧实现用 `Path::is_file()` —— 那是
/// `metadata()`（**跟随** reparse）的包装，一个指向别处的 `.sys` 链接会被当成本机驱动文件
/// 送去读签名并参与孤儿判定。现按 `list_run.rs::bounded_dir_size_in` 的既有正解改口径：
/// `DirEntry::file_type()`（不跟随）先筛，再用 `symlink_metadata` + [`protect::is_reparse`]
/// 的属性位复核（与删除出口的 reparse 判据同一份实现，§5.16/N6 禁止在这里再写一份）。
pub(super) fn driver_files() -> (Vec<PathBuf>, Vec<String>) {
    let root = match std::env::var_os("SystemRoot") {
        Some(r) => Path::new(&r).join("System32").join("drivers"),
        None => return (Vec::new(), vec!["读不到 SystemRoot，drivers 目录未采集，本组结果不完整".to_string()]),
    };
    driver_files_in(&root)
}

/// 同上，但根目录可注入 —— 真机反例用例需要一个可写的根（System32 不能拿来造样本）。
pub(super) fn driver_files_in(root: &Path) -> (Vec<PathBuf>, Vec<String>) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return (Vec::new(), vec![format!("列不到目录 {}，本组结果不完整", root.display())]);
    };
    let mut notes = Vec::new();
    let mut out: Vec<PathBuf> = Vec::new();
    let mut skipped_reparse = 0usize;
    for ent in rd.flatten() {
        let Ok(ft) = ent.file_type() else { continue };
        if ft.is_symlink() {
            skipped_reparse += 1;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let path = ent.path();
        let Ok(md) = std::fs::symlink_metadata(&path) else { continue };
        if protect::is_reparse(&md) {
            // 目录项报不出 reparse 位、但 OS 仍按重解析点解释的形态（云占位符等）走这里
            skipped_reparse += 1;
            continue;
        }
        if path.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("sys")).unwrap_or(false) {
            out.push(path);
        }
    }
    if skipped_reparse > 0 {
        notes.push(format!("{skipped_reparse} 个 reparse/链接形态的目录项已排除（它们不是本机 drivers 目录下的实体文件，跟随过去判等于判到别处）"));
    }
    out.sort();
    if out.len() > DRIVER_FILE_CAP {
        notes.push(format!("drivers 目录的 .sys 数超过枚举上限 {DRIVER_FILE_CAP}（实际列到 {}），本轮只判前 {DRIVER_FILE_CAP} 个 —— 本组结果不完整", out.len()));
        out.truncate(DRIVER_FILE_CAP);
    }
    (out, notes)
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
    let (files, mut notes) = driver_files();
    let count = files.len();
    let referenced = referenced_landings(service_entries);
    let (c, p, mut n) = driver_findings(&files, &referenced, &|p: &str| authenticode::signer_subject(p), DRIVER_FINDING_CAP);
    // 采集侧的残缺注记（截断/排除的 reparse/列不到目录）与判定侧的注记合并，
    // 同一句话不因来自哪一侧而重复（R2b-L01）
    for note in notes.drain(..) {
        if !n.contains(&note) {
            n.push(note);
        }
    }
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

    /// R2b-L01：列不到目录时采集侧也要出残缺注记（旧实现只把 `Vec::new()` 交回去，
    /// 渲染层读成「本机 drivers 干净」）。只读、不写盘，故可留在快速组。
    #[test]
    fn unopenable_root_yields_incomplete_note() {
        let (files, notes) = driver_files_in(Path::new(r"\\\trims-probe-no-such-root-9f3a\nope"));
        assert!(files.is_empty());
        assert!(notes.iter().any(|n| n.contains("本组结果不完整")), "{notes:?}");
    }

    /// R2b-L04 真机反例（**触盘 ⇒ #[ignore]**，AGENTS §4.2 纪律②）：
    /// 同目录下「真实 .sys」与「指向它的 .sys 符号链接」并存时，链接必须被排除并留注记。
    /// 旧实现用 `Path::is_file()`（跟随 reparse）会把链接也列成驱动文件。
    #[test]
    #[ignore = "真机建符号链接（依赖本机开发者模式/权限），只在发版前 --ignored 取证"]
    fn real_symlink_sys_is_not_collected_as_driver_file() {
        let base = crate::engine::paths::temp_script_dir().expect("应用私有 tmp 目录");
        let root = base.join("trim-driver-probe");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("建样本目录");
        let real = root.join("zz_probe_real.sys");
        std::fs::write(&real, b"MZ").expect("写样本 .sys");
        let link = root.join("zz_probe_link.sys");
        if let Err(e) = std::os::windows::fs::symlink_file(&real, &link) {
            let _ = std::fs::remove_dir_all(&root);
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("SKIP real_symlink_sys_is_not_collected_as_driver_file: 本机不允许创建符号链接（未开开发者模式），该反例未取证");
                return;
            }
            panic!("建符号链接失败（非权限原因，需排查）: {e}");
        }
        let (files, notes) = driver_files_in(&root);
        let names: Vec<String> = files
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()))
            .collect();
        let _ = std::fs::remove_dir_all(&root);
        assert!(names.iter().any(|n| n == "zz_probe_real.sys"), "真实 .sys 应被列到: {names:?}");
        assert!(!names.iter().any(|n| n == "zz_probe_link.sys"), "符号链接被当成本机驱动文件（R2b-L04 复发）: {names:?}");
        assert!(notes.iter().any(|n| n.contains("reparse") || n.contains("链接")), "排除的链接必须留可见注记: {notes:?}");
    }
}
