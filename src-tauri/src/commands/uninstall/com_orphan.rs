//! COM/CLSID 与 File Types / Applications 残留可见面
//! （R-1 后续阶段，2026-10-07，**只读**）。
//!
//! 缺口背景（方案 §2.3 R-1 后续阶段按成本排序）：卸载残留主链看的是「已卸载程序的
//! 落点」，看不到**注册表里指向已消失文件的登记项**。本模块补两组只读可见面：
//!
//! 1. **COM/CLSID 孤儿**：`HKLM\SOFTWARE\Classes\CLSID\{…}` 下
//!    `InprocServer32` / `LocalServer32` 指向的 DLL / EXE 已经不在了。
//!    竞品把它排在第一（价值最高），但爆炸半径也最大（删错一个 CLSID 可能让某类
//!    文件打不开），所以本阶段**只报不删**：`readonly:true` + 不进执行快照
//!    （`deep_executable_candidates` 的类白名单里没有它，见 residue_deep.rs）。
//! 2. **File Types / Applications**：两类悬空登记 ——
//!    ① 文件扩展名键的默认值 ProgID 指向一个**已不存在的 ProgID 键**；
//!    ② `…\Classes\Applications\<exe>` 登记的程序在本机常规落点找不到。
//!
//! 三条纪律（与 `ifeo_orphan.rs` / `run_keys.rs` 同一套）：
//! - **视图分开列项**：CLSID 有 64 位 / WOW6432Node / HKCU 三份，同名 GUID 可能只挂在
//!   其中一份上，合并会丢证据（IFEO R-1a 是同一个坑）。
//! - **只报「证据确凿」的**：路径取不出来（含无法展开的变量）、或指向的不是
//!   可执行/DLL 文件的，一律**不报**。判不准的方向必须是「少报」——多报只会让用户
//!   在一个纯只读列表里翻屏，但一旦将来开了执行面，那就是多删。
//! - **只读、不进执行快照**：类白名单不含本模块的两个类（有断言钉着）。
//!
//! 与 A1 禁删面的关系：`HKLM\SOFTWARE\Classes` 与 `HKCU\SOFTWARE\Classes` **整棵**
//! 在 `protect.rs::REG_SUBTREE_DENY` 里；`…\Classes\WOW6432Node` 与
//! `HKCU\SOFTWARE\Classes` 同理。本阶段只读，所以不需要为它开口子；已把
//! `denyFaceKeepsIt` 写进证据，第二阶段真要动它时那是「为什么不能直接给删除按钮」的记录。

use serde_json::{Value, json};
use std::path::Path;
use super::helpers::{open_key_read, reg_sz};
use super::residue::reg_enum_subkeys;
use super::residue_update::contribs;
use crate::engine::protect;

/// 单根子键枚举上限。
///
/// `HKLM\SOFTWARE\Classes` 是注册表里最大的几棵树之一（真机上万条），全量枚举 + 逐条
/// 读默认值会让一次深扫多花数秒。这里给的是「够用且可控」的上限，触发时由 notes 如实
/// 说明本轮只看了前 N 条 —— 残缺必须可见，不能渲染成「本机干净」。
const CLASSES_ENUM_CAP: usize = 4000;

// ==================== COM / CLSID ====================

/// CLSID 所在视图。**必须分开列项**（见文件头纪律 1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ComView {
    /// `HKLM\SOFTWARE\Classes\CLSID`（64 位进程看到的）
    HklmX64,
    /// `HKLM\SOFTWARE\Classes\WOW6432Node\CLSID`（32 位进程看到的）
    HklmWow6432,
    /// `HKCU\SOFTWARE\Classes\CLSID`（每用户注册）
    Hkcu,
}

impl ComView {
    /// 该视图的 CLSID 根（`target` 与证据都从这里拼，别在别处写字面量）
    pub(super) fn root(self) -> &'static str {
        match self {
            ComView::HklmX64 => r"SOFTWARE\Classes\CLSID",
            ComView::HklmWow6432 => r"SOFTWARE\Classes\WOW6432Node\CLSID",
            ComView::Hkcu => r"Software\Classes\CLSID",
        }
    }

    /// 报告里的 hive 写法
    fn hive_label(self) -> &'static str {
        match self {
            ComView::Hkcu => "HKCU",
            _ => "HKLM",
        }
    }

    /// 给渲染层看的人话标签
    pub(super) fn label(self) -> &'static str {
        match self {
            ComView::HklmX64 => "64 位视图",
            ComView::HklmWow6432 => "32 位视图（WOW6432Node）",
            ComView::Hkcu => "当前用户",
        }
    }
}

/// 一个 CLSID 子键的只读采集结果
#[derive(Debug, Clone)]
pub(super) struct ComRaw {
    pub(super) view: ComView,
    /// `{GUID}` 形态的 CLSID 名
    pub(super) clsid: String,
    /// `InprocServer32` 的默认值（原始字符串）
    pub(super) inproc: Option<String>,
    /// `LocalServer32` 的默认值（原始字符串）
    pub(super) local: Option<String>,
}

impl ComRaw {
    /// 本条目标的完整注册表路径（**带实际视图根**）
    pub(super) fn target(&self) -> String {
        format!("{}\\{}\\{}", self.view.hive_label(), self.view.root(), self.clsid)
    }
}

/// 从 COM 服务器值里取出**文件路径**（纯函数）。
///
/// 形态保守到「取不准就不给」：带引号取引号内；未加引号切到 ` /` 或 ` -` 参数分隔之前；
/// 展开环境变量后仍含未解析 `%TOKEN%` 的直接放弃（不猜）；末尾不是
/// `.dll/.exe/.ocx` 的不认（`LocalServer32` 里出现过纯命令行）。
pub(super) fn server_path(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let head = if let Some(rest) = s.strip_prefix('"') {
        match rest.find('"') {
            Some(i) => rest[..i].trim(),
            None => return None, // 引号未闭合：形态坏，不猜
        }
    } else {
        let cut = s.find(" /").or_else(|| s.find(" -")).unwrap_or(s.len());
        s[..cut].trim()
    };
    if head.is_empty() {
        return None;
    }
    let expanded = trim_finder::cleanup_scan::expand_env_path(head);
    if trim_finder::cleanup_scan::first_unexpanded_token(&expanded).is_some() {
        return None;
    }
    let lower = expanded.to_ascii_lowercase();
    if !(lower.ends_with(".dll") || lower.ends_with(".exe") || lower.ends_with(".ocx")) {
        return None;
    }
    Some(expanded)
}

/// 采集三个视图的 CLSID 子键（只读）。返回 (条目, 是否有任一根枚举到内容)。
pub(super) unsafe fn collect_com_raws() -> (Vec<ComRaw>, bool) {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RegCloseKey};
    let mut out = Vec::new();
    let mut any = false;
    for view in [ComView::HklmX64, ComView::HklmWow6432, ComView::Hkcu] {
        let hive = if view == ComView::Hkcu { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE };
        let names = reg_enum_subkeys(hive, view.root(), CLASSES_ENUM_CAP);
        if !names.is_empty() {
            any = true;
        }
        for clsid in names {
            // 只看 `{GUID}` 形态：`Classes\CLSID` 下偶尔混进非 GUID 名（安装器的临时项），
            // 那些不属于「COM 注册」，报了只是噪音。
            if !clsid.starts_with('{') || !clsid.ends_with('}') {
                continue;
            }
            let base = format!("{}\\{clsid}", view.root());
            let mut inproc = None;
            let mut local = None;
            if let Some(hk) = open_key_read(hive, &format!("{base}\\InprocServer32")) {
                inproc = reg_sz(hk, "");
                let _ = RegCloseKey(hk);
            }
            if let Some(hk) = open_key_read(hive, &format!("{base}\\LocalServer32")) {
                local = reg_sz(hk, "");
                let _ = RegCloseKey(hk);
            }
            out.push(ComRaw { view, clsid, inproc, local });
        }
    }
    (out, any)
}

/// 纯判定：`present` 注入「这个路径在本机存在吗」（单测因此不碰磁盘）。
///
/// `InprocServer32` 与 `LocalServer32` 都读不到 ⇒ 不报：这类 CLSID 多半是
/// `TypeLib` / `ProgID` / `TreatAs` 之类的注册形态，没有服务器路径，判不了就不猜。
pub(super) fn classify_com(raw: &ComRaw, present: &dyn Fn(&str) -> bool) -> Option<(&'static str, &'static str, String)> {
    let inproc = raw.inproc.as_deref().and_then(server_path);
    let local = raw.local.as_deref().and_then(server_path);
    match (inproc, local) {
        (Some(p), _) if !present(&p) => Some(("com_inproc_missing", "InprocServer32 指向的组件在本机已不存在", p)),
        (None, Some(p)) if !present(&p) => Some(("com_local_missing", "LocalServer32 指向的程序在本机已不存在", p)),
        _ => None,
    }
}

/// 产出 COM 候选。`present` 注入存在性判定，单测不碰磁盘。
pub(super) fn com_findings(raws: &[ComRaw], present: &dyn Fn(&str) -> bool, cap: usize) -> (Vec<Value>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let mut no_server = 0usize;
    for raw in raws {
        let Some((class, reason, path)) = classify_com(raw, present) else {
            no_server += 1;
            continue;
        };
        if out.len() >= cap {
            notes.push(format!("COM/CLSID 候选已达上限 {cap} 条，其余省略"));
            break;
        }
        let target = raw.target();
        // 只读阶段不拦（我们什么都不删），但把禁删面判定写进证据：第二阶段真要动它时，
        // 这就是「为什么这条不能直接给删除按钮」的记录（`HKLM\SOFTWARE\Classes` 整棵在
        // `REG_SUBTREE_DENY` 里，32 位与 HKCU 两份同样在）。
        let blocked = protect::reg_target_block_reason(&target);
        out.push(json!({
            "kind": "reg_key", "target": target,
            "class": class,
            "reason": format!("{reason}（{path}）"),
            // 只读阶段一律 low：这不是「危险项」，是「指向已消失文件的登记项」
            "confidence": "low", "risk": "low",
            "readonly": true, "defaultChecked": false,
            "details": json!({
                "clsid": raw.clsid,
                "view": raw.view.label(),
                "root": raw.view.root(),
                "inprocServer32": raw.inproc,
                "localServer32": raw.local,
                "missingPath": path,
                "denyFaceKeepsIt": blocked.is_some(),
            }),
            "contribs": contribs(&[
                ("clsidKeyAlive", format!("{}\\{} 仍可打开（{}）", raw.view.root(), raw.clsid, raw.view.label())),
                ("serverState", format!("登记的可执行组件在本机查不到：{path}")),
                ("denyFace", blocked.unwrap_or_else(|| "当前禁删面未拦这条".to_string())),
            ]),
        }));
    }
    if no_server > 0 {
        notes.push(format!("{no_server} 条 CLSID 没有可取出的服务器路径（可能是 TypeLib/ProgID 等注册形态），已按不可判定跳过"));
    }
    (out, notes)
}

// ==================== File Types / Applications ====================

/// 文件类型键的一级 hive（`Classes` 是合并视图，但写入方分 HKLM / HKCU 两处）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClassesHive {
    Hklm,
    Hkcu,
}

impl ClassesHive {
    fn hive_label(self) -> &'static str {
        match self {
            ClassesHive::Hklm => "HKLM",
            ClassesHive::Hkcu => "HKCU",
        }
    }

    fn classes_root(self) -> &'static str {
        match self {
            ClassesHive::Hklm => r"SOFTWARE\Classes",
            ClassesHive::Hkcu => r"Software\Classes",
        }
    }
}

/// 一条扩展名登记：`.ext` 的默认值指向的 ProgID
#[derive(Debug, Clone)]
pub(super) struct FileTypeRaw {
    pub(super) hive: ClassesHive,
    pub(super) ext: String,
    pub(super) progid: String,
}

impl FileTypeRaw {
    pub(super) fn target(&self) -> String {
        format!("{}\\{}\\{}", self.hive.hive_label(), self.hive.classes_root(), self.ext)
    }
}

/// 一条 `Applications\<exe>` 登记
#[derive(Debug, Clone)]
pub(super) struct AppRegRaw {
    pub(super) hive: ClassesHive,
    /// `Applications` 下的子键名（通常是裸 exe 名）
    pub(super) name: String,
}

impl AppRegRaw {
    pub(super) fn target(&self) -> String {
        format!("{}\\{}\\Applications\\{}", self.hive.hive_label(), self.hive.classes_root(), self.name)
    }
}

/// 文件类型 / 应用登记采集结果
pub(super) struct FileTypeRaws {
    pub(super) file_types: Vec<FileTypeRaw>,
    pub(super) apps: Vec<AppRegRaw>,
    /// 是否有任一根枚举到内容
    pub(super) any: bool,
}

/// 采集扩展名键与 Applications 子键（只读）。
///
/// 两个 hive 都采：`HKLM\SOFTWARE\Classes` 是机器级，`HKCU\SOFTWARE\Classes` 是每用户
/// 覆盖（后者优先级更高，缺了会漏掉「用户级装了、机器级没登记」那一类悬空）。
pub(super) unsafe fn collect_filetype_raws() -> FileTypeRaws {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RegCloseKey};
    let mut file_types = Vec::new();
    let mut apps = Vec::new();
    let mut any = false;
    for hive_kind in [ClassesHive::Hklm, ClassesHive::Hkcu] {
        let hive = if hive_kind == ClassesHive::Hkcu { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE };
        let root = hive_kind.classes_root();
        let names = reg_enum_subkeys(hive, root, CLASSES_ENUM_CAP);
        if !names.is_empty() {
            any = true;
        }
        for name in names {
            if name.starts_with('.') && name.len() > 1 {
                let Some(hk) = open_key_read(hive, &format!("{root}\\{name}")) else { continue };
                let progid = reg_sz(hk, "").unwrap_or_default();
                let _ = RegCloseKey(hk);
                if !progid.trim().is_empty() {
                    file_types.push(FileTypeRaw { hive: hive_kind, ext: name, progid: progid.trim().to_string() });
                }
                continue;
            }
            if name.eq_ignore_ascii_case("Applications") {
                let app_names = reg_enum_subkeys(hive, &format!("{root}\\Applications"), CLASSES_ENUM_CAP);
                for app in app_names {
                    apps.push(AppRegRaw { hive: hive_kind, name: app });
                }
            }
        }
    }
    FileTypeRaws { file_types, apps, any }
}

/// 产出文件类型候选：默认值 ProgID 指向的 `Classes\<ProgID>` 键**此刻不存在**。
///
/// `progid_exists` 注入判定（单测不碰注册表）。刻意只报「默认值有 ProgID 但它没了」：
/// 扩展名键的默认值为空是常态（靠 `OpenWithProgids` 多路选择），那不是残留。
pub(super) fn filetype_findings(raws: &[FileTypeRaw], progid_exists: &dyn Fn(&str) -> bool, cap: usize) -> (Vec<Value>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    for raw in raws {
        if progid_exists(&raw.progid) {
            continue;
        }
        if out.len() >= cap {
            notes.push(format!("文件类型候选已达上限 {cap} 条，其余省略"));
            break;
        }
        let target = raw.target();
        let blocked = protect::reg_target_block_reason(&target);
        out.push(json!({
            "kind": "reg_key", "target": target,
            "class": "fileext_progid_missing",
            "reason": format!("扩展名 {} 的默认 ProgID「{}」在 Classes 下已不存在（悬空的打开方式登记）", raw.ext, raw.progid),
            "confidence": "low", "risk": "low",
            "readonly": true, "defaultChecked": false,
            "details": json!({
                "ext": raw.ext,
                "progid": raw.progid,
                "hive": raw.hive.hive_label(),
                "denyFaceKeepsIt": blocked.is_some(),
            }),
            "contribs": contribs(&[
                ("extKeyAlive", format!("{}\\Classes\\{} 仍可打开，默认值为「{}」", raw.hive.hive_label(), raw.ext, raw.progid)),
                ("progidState", format!("Classes\\{} 此刻查不到", raw.progid)),
                ("denyFace", blocked.unwrap_or_else(|| "当前禁删面未拦这条".to_string())),
            ]),
        }));
    }
    (out, notes)
}

/// 产出 Applications 候选项：登记的 exe 在本机常规落点找不到。
///
/// 复用 IFEO 那条 `image_executable_present`（System32 / SysWOW64 / Windows / App Paths）
/// —— 一处实现两个域共用，别在这里再写一份（§5.16/N6）。
pub(super) fn app_reg_findings(raws: &[AppRegRaw], exe_present: &dyn Fn(&str) -> bool, cap: usize) -> (Vec<Value>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    for raw in raws {
        // 只认裸 exe 名形态：`Applications` 下的名字本该是 `foo.exe`，其它形态（带路径、
        // 带参数）判不了「它到底指谁」，不猜。
        let name_lc = raw.name.to_ascii_lowercase();
        if !name_lc.ends_with(".exe") || name_lc.contains(['\\', '/']) {
            continue;
        }
        if exe_present(&name_lc) {
            continue;
        }
        if out.len() >= cap {
            notes.push(format!("Applications 候选已达上限 {cap} 条，其余省略"));
            break;
        }
        let target = raw.target();
        let blocked = protect::reg_target_block_reason(&target);
        out.push(json!({
            "kind": "reg_key", "target": target,
            "class": "appreg_exe_missing",
            "reason": format!("Applications 登记的 {} 在本机常规落点找不到", raw.name),
            "confidence": "low", "risk": "low",
            "readonly": true, "defaultChecked": false,
            "details": json!({
                "appName": raw.name,
                "hive": raw.hive.hive_label(),
                "denyFaceKeepsIt": blocked.is_some(),
            }),
            "contribs": contribs(&[
                ("appRegKeyAlive", format!("{}\\Classes\\Applications\\{} 仍可打开", raw.hive.hive_label(), raw.name)),
                ("exeState", "System32 / SysWOW64 / Windows / App Paths 都查不到该 exe".to_string()),
                ("denyFace", blocked.unwrap_or_else(|| "当前禁删面未拦这条".to_string())),
            ]),
        }));
    }
    (out, notes)
}

/// `Classes\<ProgID>` 键此刻是否存在（真机谓词；单测用注入替身）。
///
/// 两个 hive 都查：`Classes` 是合并视图（HKCR 语义），同一 ProgID 可能只登记在
/// HKCU（用户级安装）或只登记在 HKLM（机器级）。只查 HKLM 会把用户级安装的
/// 正常关联误报成悬空。
pub(super) unsafe fn progid_key_exists_any(progid: &str) -> bool {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER].iter().any(|hk| {
        let root = if *hk == HKEY_CURRENT_USER { r"Software\Classes" } else { r"SOFTWARE\Classes" };
        crate::engine::native::reg_key_exists(*hk, &format!("{root}\\{progid}"))
    })
}

/// 路径是否存在（真机谓词）。
pub(super) fn path_file_exists(p: &str) -> bool {
    Path::new(p).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn com(clsid: &str, inproc: Option<&str>, local: Option<&str>) -> ComRaw {
        ComRaw {
            view: ComView::HklmX64,
            clsid: clsid.to_string(),
            inproc: inproc.map(str::to_string),
            local: local.map(str::to_string),
        }
    }

    // ==================== 服务器路径解析（正负样本） ====================

    #[test]
    fn server_path_recognizes_real_world_shapes() {
        assert_eq!(server_path(r"C:\Apps\acme.dll"), Some(r"C:\Apps\acme.dll".to_string()));
        assert_eq!(server_path(r#""C:\Program Files\Acme\acme.dll""#), Some(r"C:\Program Files\Acme\acme.dll".to_string()));
        assert_eq!(server_path(r#""C:\Apps\acme.exe" /Automation"#), Some(r"C:\Apps\acme.exe".to_string()));
        // 未加引号 + 参数分隔：切到 ` /` 之前（含空格的路径这一形态只能靠引号，不猜）
        assert_eq!(server_path(r"C:\Apps\acme.exe /Automation"), Some(r"C:\Apps\acme.exe".to_string()));
        // 环境变量先展开
        let expanded = server_path(r"%SystemRoot%\System32\acme.dll").unwrap();
        assert!(expanded.to_lowercase().ends_with(r"\system32\acme.dll"), "应展开 %SystemRoot%: {expanded}");
    }

    #[test]
    fn server_path_refuses_unprovable_shapes() {
        assert_eq!(server_path(""), None);
        assert_eq!(server_path("   "), None);
        assert_eq!(server_path(r#""C:\unterminated"#), None, "引号未闭合不得猜");
        assert_eq!(server_path(r"%NO_SUCH_TOKEN_XYZ%\acme.dll"), None, "未登记变量展开不了 ⇒ 不认");
        assert_eq!(server_path(r"C:\Apps\acme.txt"), None, "不认识的后缀不当作服务器路径");
        assert_eq!(server_path(r"C:\Windows\System32\rundll32.exe"), Some(r"C:\Windows\System32\rundll32.exe".to_string()));
    }

    // ==================== CLSID 判定 ====================

    #[test]
    fn missing_inproc_is_reported_and_alive_is_not() {
        let raws = vec![
            com("{11111111-1111-1111-1111-111111111111}", Some(r"C:\Gone\a.dll"), None),
            com("{22222222-2222-2222-2222-222222222222}", Some(r"C:\Live\b.dll"), None),
            // 两个服务器值都取不出来 ⇒ 不报（TypeLib / ProgID 等注册形态）
            com("{33333333-3333-3333-3333-333333333333}", None, None),
        ];
        let (items, notes) = com_findings(&raws, &|p: &str| p.starts_with(r"C:\Live"), 10);
        assert_eq!(items.len(), 1, "只有指向已消失文件的那条该报: {items:?}");
        assert_eq!(items[0]["class"], "com_inproc_missing");
        assert_eq!(items[0]["readonly"], true);
        assert_eq!(items[0]["defaultChecked"], false);
        assert!(items[0]["target"].as_str().unwrap().ends_with("}") , "target 必须带完整视图根与 GUID");
        assert!(notes.iter().any(|n| n.contains("没有可取出的服务器路径")), "不可判定的条数要如实说明: {notes:?}");
    }

    #[test]
    fn only_local_server_falls_back_to_local_check() {
        let raws = vec![com("{44444444-4444-4444-4444-444444444444}", None, Some(r"C:\Gone\srv.exe"))];
        let (items, _) = com_findings(&raws, &|_: &str| false, 10);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["class"], "com_local_missing");
        // InprocServer32 存在且存活时，LocalServer32 缺不缺席都不报（Inproc 优先）
        let raws2 = vec![com("{55555555-5555-5555-5555-555555555555}", Some(r"C:\Live\a.dll"), Some(r"C:\Gone\srv.exe"))];
        let (items2, _) = com_findings(&raws2, &|p: &str| p.starts_with(r"C:\Live"), 10);
        assert!(items2.is_empty(), "Inproc 存活时不得因为 LocalServer32 缺席而报: {items2:?}");
    }

    /// 三个视图分别列项，`target` 各带自己的根（合并会丢证据）。
    #[test]
    fn com_views_are_listed_separately_with_view_scoped_targets() {
        let mut a = com("{66666666-6666-6666-6666-666666666666}", Some(r"C:\Gone\a.dll"), None);
        a.view = ComView::Hkcu;
        let mut b = com("{66666666-6666-6666-6666-666666666666}", Some(r"C:\Gone\a.dll"), None);
        b.view = ComView::HklmWow6432;
        let (items, _) = com_findings(&[a, b], &|_: &str| false, 10);
        assert_eq!(items.len(), 2, "同名 GUID 挂在不同视图上必须各是一条: {items:?}");
        let targets: Vec<&str> = items.iter().map(|i| i["target"].as_str().unwrap_or("")).collect();
        assert!(targets.iter().any(|t| t.starts_with(r"HKCU\Software\Classes\CLSID\")), "{targets:?}");
        assert!(targets.iter().any(|t| t.starts_with(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\")), "{targets:?}");
    }

    /// 三个 CLSID 根都落在 A1 禁删面内（只读阶段不许提前开口子），且普通产品键是正对照。
    #[test]
    fn all_clsid_roots_stay_behind_the_deny_face() {
        for view in [ComView::HklmX64, ComView::HklmWow6432, ComView::Hkcu] {
            let target = format!("{}\\{}\\{{AAAA}}", view.hive_label(), view.root());
            assert!(
                protect::reg_target_block_reason(&target).is_some(),
                "CLSID 目标必须被 A1 禁删面拦住: {target}"
            );
        }
        assert!(
            protect::reg_target_block_reason(r"HKLM\SOFTWARE\AcmeProduct").is_none(),
            "非 Classes 的产品键应放行 —— 否则上面只是「什么都拒」的假绿"
        );
    }

    // ==================== File Types / Applications ====================

    #[test]
    fn filetype_reports_only_dangling_progid() {
        let raws = vec![
            FileTypeRaw { hive: ClassesHive::Hklm, ext: ".acme".to_string(), progid: "Acme.Doc".to_string() },
            FileTypeRaw { hive: ClassesHive::Hkcu, ext: ".ok".to_string(), progid: "Live.Doc".to_string() },
        ];
        let (items, _) = filetype_findings(&raws, &|p: &str| p == "Live.Doc", 10);
        assert_eq!(items.len(), 1, "只报 ProgID 键已不存在的那条: {items:?}");
        assert_eq!(items[0]["class"], "fileext_progid_missing");
        assert_eq!(items[0]["readonly"], true);
        assert!(items[0]["target"].as_str().unwrap().contains(r"\Classes\.acme"));
    }

    #[test]
    fn appreg_reports_only_bare_missing_exe() {
        let raws = vec![
            AppRegRaw { hive: ClassesHive::Hklm, name: "gone.exe".to_string() },
            AppRegRaw { hive: ClassesHive::Hklm, name: "live.exe".to_string() },
            // 非裸 exe 名形态（带路径）判不了「它到底指谁」⇒ 不猜
            AppRegRaw { hive: ClassesHive::Hklm, name: r"C:\X\weird.exe".to_string() },
            AppRegRaw { hive: ClassesHive::Hklm, name: "notAnExe".to_string() },
        ];
        let (items, _) = app_reg_findings(&raws, &|n: &str| n == "live.exe", 10);
        assert_eq!(items.len(), 1, "只有裸 exe 名且找不到的那条该报: {items:?}");
        assert_eq!(items[0]["class"], "appreg_exe_missing");
        assert!(items[0]["target"].as_str().unwrap().ends_with(r"Applications\gone.exe"));
    }

    #[test]
    fn findings_are_capped_and_readonly() {
        let raws: Vec<ComRaw> = (0..5)
            .map(|i| com(&format!("{{00000000-0000-0000-0000-00000000000{i}}}"), Some(r"C:\Gone\a.dll"), None))
            .collect();
        let (items, notes) = com_findings(&raws, &|_: &str| false, 2);
        assert_eq!(items.len(), 2);
        assert!(notes.iter().any(|n| n.contains("已达上限")));
        for it in &items {
            assert_eq!(it["readonly"], true);
            assert_eq!(it["defaultChecked"], false);
            assert_eq!(it["kind"], "reg_key");
        }
    }
}
