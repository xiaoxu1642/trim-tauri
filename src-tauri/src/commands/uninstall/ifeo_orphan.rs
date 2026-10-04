//! IFEO（Image File Execution Options）残留扫描（v0.5.0 只读，方案 §3 `ifeo_orphan`）。
//!
//! 分级按方案给的两条：
//! - 有 `Debugger` ⇒ high。IFEO 的 Debugger 是「任何人点开这个 exe 都会被转到别处」的
//!   机制，卸载器通常不会清它；但它也可能是开发者**主动**装的调试件（Visual Studio、
//!   进程缓解策略工具），所以只报告、不默认任何处置。
//! - 只有 `PerfOptions` 之类性能/全局标记，且该镜像在本机已经不存在的 ⇒ low。
//!   镜像还在就完全不用打扰用户 —— 那是仍在用的程序的正常配置。
//!
//! 与 A1 禁删面的关系：IFEO 整棵落在 `HKLM\SOFTWARE\Microsoft` 系统命名空间内
//! （`protect.rs` 的 `REG_MICROSOFT_ROOTS`，注释里点名过它），本阶段只读不删，
//! 所以不需要为它开任何口子。

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use super::helpers::{open_key_read, reg_sz};
use super::residue::reg_enum_subkeys;
use super::residue_update::contribs;
use crate::engine::protect;

pub(super) const IFEO_ROOT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

/// 单键枚举上限（IFEO 下常态几十到几百条）
const IFEO_ENUM_CAP: usize = 800;

/// 一个 IFEO 子键的只读采集结果
#[derive(Debug, Clone)]
pub(super) struct IfeoRaw {
    /// 子键名（镜像名 `foo.exe`，或全路径形态 `\Device\HarddiskVolume...\foo.exe`）
    pub(super) name: String,
    pub(super) debugger: Option<String>,
    /// 键下**全部**值名（小写）—— 判「只有 PerfOptions」必须看完整集合，
    /// 只看某几个已知名会把「还有别的关键配置」误读成「只剩标记」
    pub(super) value_names: Vec<String>,
    pub(super) subkey_count: u32,
}

/// PerfOptions 一档允许的伴生值名（超出即视为「不止性能标记」）
const PERF_ONLY_VALUES: &[&str] = &["perfoptions", "useperfcounter"];

impl IfeoRaw {
    /// 镜像文件名（小写）：全路径形态取最后一段，裸镜像名原样取。
    pub(super) fn image_name_lc(&self) -> String {
        let trimmed = self.name.trim_start_matches('\\');
        Path::new(trimmed)
            .file_name()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_else(|| trimmed.to_ascii_lowercase())
    }

    /// 「只有性能标记」：没有任何子键（`00`/`01` 调试槽、`CFG` 都算子键），
    /// 且值名全部落在 PERF_ONLY_VALUES 里、至少有一个。
    pub(super) fn is_perf_only(&self) -> bool {
        self.subkey_count == 0 && !self.value_names.is_empty() && self.value_names.iter().all(|v| PERF_ONLY_VALUES.contains(&v.as_str()))
    }
}

/// 分类（纯函数）。返回 (class, confidence, reason)。
///
/// 顺序即优先级：`Debugger` 存在就出 high，不再看镜像在不在 —— 因为调试器指向的 exe
/// 消失了才是真问题，而这一条在 v0.5.0 只报不删，宁可多报一屏也不能漏报这一类劫持。
pub(super) fn classify_ifeo(raw: &IfeoRaw, image_present: bool) -> Option<(&'static str, &'static str, &'static str)> {
    if let Some(d) = raw.debugger.as_deref() {
        if !d.trim().is_empty() {
            return Some(("ifeo_debugger", "high", "IFEO 里给这个镜像配了 Debugger 重定向（程序已卸载时它会一直拦在那里）"));
        }
    }
    if raw.is_perf_only() && !image_present {
        return Some(("ifeo_stale_options", "low", "IFEO 只剩性能/全局标记，且这个镜像在本机已不存在"));
    }
    None
}

/// 镜像是否在本机的常规落点里存在（System32 / SysWOW64 / Windows 目录 / App Paths）。
///
/// 刻意不搜 PATH 也不搜全盘：这条判据只用来**否决**「低置信的过期标记」，
/// 判不准时最多多列一条 low，不会造成删除动作。
pub(super) unsafe fn image_executable_present(name_lc: &str) -> bool {
    if name_lc.is_empty() || name_lc.contains(['/', '\\']) {
        return false;
    }
    let root = match std::env::var_os("SystemRoot") {
        Some(r) => PathBuf::from(r),
        None => return false,
    };
    for dir in [root.join("System32"), root.join("SysWOW64"), root.clone()] {
        if dir.join(name_lc).is_file() {
            return true;
        }
    }
    // App Paths 里登记过也算「镜像还在」—— 它比文件枚举更贴近「系统认得这个 exe」
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    for hive_sub in [format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{name_lc}"), format!(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\{name_lc}")] {
        if crate::engine::native::reg_key_exists(HKEY_LOCAL_MACHINE, &hive_sub) {
            return true;
        }
    }
    false
}

/// 采集 IFEO 子键（只读）。返回 (条目, 是否至少枚举到)。
pub(super) unsafe fn collect_ifeo_raws() -> (Vec<IfeoRaw>, bool) {
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RegCloseKey};
    let names = reg_enum_subkeys(HKEY_LOCAL_MACHINE, IFEO_ROOT, IFEO_ENUM_CAP);
    if names.is_empty() {
        return (Vec::new(), false);
    }
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let Some(hk) = open_key_read(HKEY_LOCAL_MACHINE, &format!("{IFEO_ROOT}\\{name}")) else { continue };
        let debugger = reg_sz(hk, "Debugger");
        let value_names = super::helpers::reg_value_names(hk, 32).into_iter().map(|v| v.to_lowercase()).collect();
        let subkey_count = key_counts(&hk).0;
        out.push(IfeoRaw { name, debugger, value_names, subkey_count });
        let _ = RegCloseKey(hk);
    }
    (out, true)
}

/// (子键数, 值数)；读不到按 (0, 0) —— 调用方会把「一个值都没有」判成不是 perf-only，
/// 也就是往「不报」的方向失败，不会凭空造候选。
unsafe fn key_counts(hk: &windows::Win32::System::Registry::HKEY) -> (u32, u32) {
    use windows::Win32::System::Registry::RegQueryInfoKeyW;
    let (mut subkeys, mut values) = (0u32, 0u32);
    if RegQueryInfoKeyW(*hk, None, None, None, Some(&mut subkeys), None, None, Some(&mut values), None, None, None, None).is_err() {
        return (0, 0);
    }
    (subkeys, values)
}

/// 产出 IFEO 候选（`image_present` 注入，单测不碰磁盘与注册表）。
pub(super) fn ifeo_findings(raws: &[IfeoRaw], image_present: &dyn Fn(&str) -> bool, cap: usize) -> (Vec<Value>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    for raw in raws {
        let image = raw.image_name_lc();
        let present = image_present(&image);
        let Some((class, confidence, reason)) = classify_ifeo(raw, present) else {
            continue;
        };
        if out.len() >= cap {
            notes.push(format!("IFEO 候选已达上限 {cap} 条，其余省略"));
            break;
        }
        let target = format!("HKLM\\{IFEO_ROOT}\\{}", raw.name);
        // 受保护面在只读阶段不拦（我们什么都不删），但把判定写进证据里：
        // 第二阶段真要动它时，这一列就是「为什么这条不能直接给删除按钮」的记录。
        let blocked = protect::reg_target_block_reason(&target);
        out.push(json!({
            "kind": "reg_key", "target": target,
            "class": class,
            "reason": reason,
            "confidence": confidence, "risk": if confidence == "high" { "high" } else { "low" },
            "readonly": true, "defaultChecked": false,
            "details": json!({
                "image": image,
                "debugger": raw.debugger,
                "denyFaceKeepsIt": blocked.is_some(),
            }),
            "contribs": contribs(&[
                ("ifeoKeyAlive", format!("{IFEO_ROOT}\\{} 仍可打开", raw.name)),
                ("imageState", if present { "镜像在本机常规落点仍在".to_string() } else { "镜像在 System32 / SysWOW64 / Windows / App Paths 都查不到".to_string() }),
                ("denyFace", blocked.unwrap_or_else(|| "当前禁删面未拦这条".to_string())),
            ]),
        }));
    }
    (out, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(f: impl FnOnce(&mut IfeoRaw)) -> IfeoRaw {
        let mut r = IfeoRaw { name: "notepad.exe".to_string(), debugger: None, value_names: Vec::new(), subkey_count: 0 };
        f(&mut r);
        r
    }

    fn perf_only(r: &mut IfeoRaw) {
        r.value_names = vec!["perfoptions".to_string()];
    }

    #[test]
    fn debugger_present_is_high_even_if_image_alive() {
        let r = raw(|x| x.debugger = Some(r"C:\Tools\debugger.exe".to_string()));
        let (class, confidence, _) = classify_ifeo(&r, true).unwrap();
        assert_eq!(class, "ifeo_debugger");
        assert_eq!(confidence, "high");
    }

    #[test]
    fn empty_debugger_does_not_count_as_hijack() {
        let r = raw(|x| x.debugger = Some("   ".to_string()));
        assert!(classify_ifeo(&r, true).is_none());
    }

    #[test]
    fn perf_only_and_image_gone_is_low() {
        let r = raw(perf_only);
        let (class, confidence, _) = classify_ifeo(&r, false).unwrap();
        assert_eq!(class, "ifeo_stale_options");
        assert_eq!(confidence, "low");
    }

    #[test]
    /// 镜像还在 ⇒ 那是仍在用的程序的正常配置，一条都不报
    fn perf_only_with_alive_image_is_not_reported() {
        let r = raw(perf_only);
        assert!(classify_ifeo(&r, true).is_none());
    }

    #[test]
    /// 「只剩性能标记」必须看**全部**值名：混进别的值（PageCompound / DebugFilter）就不能算
    fn any_other_value_defeats_perf_only() {
        let mut r = raw(perf_only);
        r.value_names.push("pagecompound".to_string());
        assert!(!r.is_perf_only());
        assert!(classify_ifeo(&r, false).is_none());
    }

    #[test]
    /// `00`/`01` 调试槽与 `CFG` 都是子键：有子键就不是「只剩标记」
    fn subkeys_defeat_perf_only() {
        let mut r = raw(perf_only);
        r.subkey_count = 1;
        assert!(!r.is_perf_only());
    }

    #[test]
    fn empty_value_set_is_not_perf_only() {
        // 一个值都没有 = 读不到证据，不能当成「只剩标记」
        let r = raw(|_: &mut IfeoRaw| {});
        assert!(!r.is_perf_only());
    }

    #[test]
    fn full_path_key_forms_yield_the_bare_image_name() {
        assert_eq!(raw(|x| x.name = r"\Device\HarddiskVolume3\Dir\Foo.EXE".to_string()).image_name_lc(), "foo.exe");
        assert_eq!(raw(|x| x.name = "Bar.exe".to_string()).image_name_lc(), "bar.exe");
        assert_eq!(raw(|x| x.name = r"\FooBar".to_string()).image_name_lc(), "foobar");
    }

    #[test]
    fn findings_target_is_readonly_and_capped() {
        let raws: Vec<IfeoRaw> = (0..5).map(|i| raw(|x| {
            x.name = format!("app{i}.exe");
            x.value_names = vec!["perfoptions".to_string()];
        }))
        .collect();
        let (items, notes) = ifeo_findings(&raws, &|_: &str| false, 2);
        assert_eq!(items.len(), 2);
        assert!(notes.iter().any(|n| n.contains("已达上限")));
        for it in &items {
            assert_eq!(it["readonly"], true);
            assert_eq!(it["defaultChecked"], false);
            assert_eq!(it["class"], "ifeo_stale_options");
        }
    }

    #[test]
    fn deny_face_still_covers_ifeo_in_readonly_phase() {
        // 方案 §2.3：这一阶段不开任何 HKLM\SYSTEM / Microsoft 树口子；
        // IFEO 属 Microsoft 树，禁删面必须仍然判它「拦得住」，否则第二阶段的口子就被提前打开了
        let target = format!("HKLM\\{IFEO_ROOT}\\notepad.exe");
        assert!(protect::reg_target_block_reason(&target).is_some(), "IFEO 目标应被 A1 禁删面拦住");
    }
}
