//! 失效残留扫描（M6）：落地路径全失踪的注册表项、休眠差量与 dead uninstall/app-paths。
//!
//! 快照标签与 residue 扫描共用 RESIDUE_SNAPSHOTS，但**判据不同**：本域只报「指向的东西
//! 已经不在」，不得与正常残留扫描的清理面混为一谈，快照 label 前缀因此保持不变。

use crate::engine::guard;
use serde_json::{Value, json};
use tauri::WebviewWindow;
use super::helpers::*;
use super::residue::*;
use super::residue_update::*;
use super::ownership::*;
// ==================== 失效残留扫描（M6，用户拍板 2026-09-28） ====================
//
// 与 M4 的所有权链分工不同，两条链共用一个「残留扫描」面板但证据来源不同：
// - 程序残留（规则库）：知道是哪个程序，按签名规则找它的痕；
// - 失效残留（本模块）：不要求本机有卸载记录，判据只有一条 ——
//   注册表里记着的落点文件已经不存在**（程序不在了、键还留着指着一个不存在的东西）。
// - 应用数据遗留（所有权链）：仍然要「本机确实卸载过它」这条事实，
//   因为同名目录匹配本身不是证据；档案取不到时这一组自己说明取不到，
//   不再让整次扫描失败（那是把一条链的缺证据当成三条链的结论）。
//
// 三条硬约束（不随需求变）：
// 1. 一律 `defaultChecked: false`、置信度封顶 medium —— 落点缺失也可能是
//    移动盘/网络盘没插、程序被手工搬过位置，这些只有用户知道；
// 2. 候选必须过既有 `classify_residue_op`（快照闸 + A1 禁删面 + 先 export 备份 + 封条）。
//    **服务与设备两类已按用户裁定 2026-09-28 摘掉**：判据虽然也成立（二进制文件已丢失 /
//    设备当前不在场），但删除要提权走 SCM 与 SetupAPI，我们没有这块的实操经验，
//    误删一个服务或设备实例的代价远高于"多列出两类候选"的收益。要做也得先有
//    真机样本与回滚路径，不要在这里留半条通道。
// 3. 「沉睡多久」只展示不参与判定：键的 LastWriteTime 读不到就留空，
//    拿 0 当"很久没动过"会把读不到伪装成有把握。

/// 快照槽按 origin 分桶替换。
///
/// 为什么不能整槽覆盖：面板现在同时展示多组候选，先扫的那组会在后一次扫描后被
/// 快照闸判成「不在本次扫描快照中」，用户看到的勾选项点下去就报错。
/// M4 的应用数据遗留链其实已经有这个坑（它覆盖掉单程序残留的快照），一并收口。
pub(super) fn residue_snapshot_put(label: &str, origin: &str, findings: Vec<Value>) {
    const SNAPSHOT_CAP: usize = 400;
    let mut store = residue_snapshots().lock().unwrap_or_else(|e| e.into_inner());
    let mut merged: Vec<Value> = store
        .get(label)
        .map(|(_, f)| {
            f.iter()
                .filter(|x| x.get("origin").and_then(Value::as_str) != Some(origin))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    merged.extend(findings);
    if merged.len() > SNAPSHOT_CAP {
        merged.truncate(SNAPSHOT_CAP);
    }
    store.insert(label.to_string(), (crate::engine::now_ms(), merged));
}

/// `%VAR%` 展开。**任一变量取不到就返回 None**：把没展开的串继续往下判，等于
/// 拿一个本机根本不存在的路径去判"落点已消失"，那是自己造出来的假阳性。
pub(super) fn expand_pct(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        match tail.find('%') {
            Some(j) => {
                let name = &tail[..j];
                if name.is_empty() {
                    out.push('%');
                } else {
                    out.push_str(&std::env::var(name).ok()?);
                }
                rest = &tail[j + 1..];
            }
            None => {
                out.push('%');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    Some(out)
}

/// 从 `UninstallString` / 服务 `ImagePath` / App Paths 默认值里取出「它记着哪个文件」。
///
/// `None` = 判不出来（相对名、无扩展名、`Device\` 形态、变量展开不了），
/// 调用方必须把 None 当**无证据**而不是"不存在"。
/// 截参数的口径：带引号取引号内；不带引号就在第一个 `.exe/.dll/.sys` 之后切断
/// （注册表里没引号的路径只能靠扩展名边界分参数），且结果必须以这三种扩展名结尾。
pub(super) fn dead_landing(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let s = s.strip_prefix(r"\??\").unwrap_or(s);
    // `\SystemRoot\system32\...` 是服务表里的常见写法（不是 %SystemRoot%）
    let rewritten;
    let s = if s
        .get(..11)
        .map(|p| p.eq_ignore_ascii_case(r"\SystemRoot"))
        .unwrap_or(false)
    {
        rewritten = format!("{}{}", std::env::var("SystemRoot").ok()?, &s[11..]);
        rewritten.as_str()
    } else {
        s
    };
    let expanded = expand_pct(s)?;
    let head = match expanded.strip_prefix('"') {
        Some(q) => q.split('"').next().unwrap_or("").to_string(),
        None => {
            let low = expanded.to_lowercase();
            let cut = [".exe", ".dll", ".sys"]
                .iter()
                .filter_map(|e| low.find(e).map(|i| i + e.len()))
                .min();
            match cut {
                Some(end) => expanded.chars().take(end).collect(),
                None => expanded.clone(),
            }
        }
    };
    let head = head.trim().to_string();
    if head.is_empty() {
        return None;
    }
    let b = head.as_bytes();
    let is_abs = (b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\')
        || head.starts_with(r"\\");
    if !is_abs {
        return None;
    }
    let low = head.to_lowercase();
    if !(low.ends_with(".exe") || low.ends_with(".dll") || low.ends_with(".sys")) {
        return None;
    }
    Some(head)
}

/// 落点集合是否「全部缺失」。空集合返回 false —— 没有落点就没有证据，不产候选。
pub(super) fn landings_all_missing(lands: &[String], exists: &dyn Fn(&str) -> bool) -> bool {
    !lands.is_empty() && lands.iter().all(|p| !exists(p))
}

/// MSI 产品码形态的键名（`{GUID}`）：它的 `InstallLocation` 经常是空或错的，
/// 单靠一条落点判"程序已不在"不够，要求至少两条落点全部缺失。
pub(super) fn is_msi_product_code(key_tail: &str) -> bool {
    let t = key_tail.trim_matches('{').trim_matches('}');
    t.len() == 36
        && t.matches('-').count() == 4
        && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// 卸载键候选（纯函数，单测注入存在性判定）
pub(super) fn dead_uninstall_findings(
    raws: &[DeadUninstallRaw],
    exists: &dyn Fn(&str) -> bool,
    now: i64,
) -> Vec<Value> {
    let mut out = Vec::new();
    for r in raws {
        if r.name.trim().is_empty() {
            continue; // 没有显示名的条目用户无法判断是什么，不产候选
        }
        let mut lands: Vec<String> = Vec::new();
        let loc = r.install.trim().trim_end_matches(['\\', '/']);
        if !loc.is_empty() {
            lands.push(loc.to_string());
        }
        for raw in [&r.uninstall, &r.quiet] {
            if let Some(p) = dead_landing(raw) {
                if !lands.iter().any(|x| x.eq_ignore_ascii_case(&p)) {
                    lands.push(p);
                }
            }
        }
        let needed = if is_msi_product_code(&r.key) { 2 } else { 1 };
        if lands.len() < needed || !landings_all_missing(&lands, exists) {
            continue;
        }
        let dormant = dormant_delta(r.last_write_ms, now);
        // C4：证据一条条列出来。落点是这条判定的全部依据，只给一句「落点已全部不存在」
        // 用户既不知道查了哪几个路径，也无从发现「InstallLocation 本来就写错了」。
        let mut why: Vec<(&str, String)> =
            vec![("entry", format!("卸载登记仍在 {}\\{}", r.hive, r.path))];
        for p in &lands {
            why.push(("landingMissing", format!("落点已不存在：{p}")));
        }
        if needed > 1 {
            why.push((
                "msiRule",
                "MSI 产品码键：要求两条及以上落点全部缺失才入候选".to_string(),
            ));
        }
        match dormant.as_i64() {
            Some(ms) => why.push((
                "dormant",
                format!("键最后写入距今 {} 天（沉睡只展示，不参与判定）", ms / 86_400_000),
            )),
            None => why.push((
                "dormantUnknown",
                "读不到键最后写入时间，因此不显示沉睡时长".to_string(),
            )),
        }
        out.push(json!({
            "kind": "reg_key",
            "target": format!("{}\\{}", r.hive, r.path),
            "reason": format!("卸载项「{}」记着的落点已全部不存在（{}）", r.name, lands.join("；")),
            "confidence": if lands.len() >= 2 { "medium" } else { "low" },
            "risk": "medium",
            "defaultChecked": false,
            "origin": "dead",
            "deadClass": "uninstall",
            "deleteCapable": true,
            "testedPaths": lands,
            "contribs": contribs(&why),
            "dormantMs": dormant,
        }));
    }
    out
}

/// App Paths 候选：默认值指向的文件已不存在 → 该 `App Paths\<x.exe>` 子键是失效登记
pub(super) fn dead_app_paths_findings(
    raws: &[DeadAppPathRaw],
    exists: &dyn Fn(&str) -> bool,
    now: i64,
) -> Vec<Value> {
    let mut out = Vec::new();
    for r in raws {
        let Some(p) = dead_landing(&r.value) else { continue };
        if exists(&p) {
            continue;
        }
        let dormant = dormant_delta(r.last_write_ms, now);
        let mut why: Vec<(&str, String)> = vec![
            ("entry", format!("App Paths 登记仍在 {}\\{}", r.hive, r.path)),
            ("targetMissing", format!("默认值指向的文件已不存在：{p}")),
        ];
        match dormant.as_i64() {
            Some(ms) => why.push((
                "dormant",
                format!("键最后写入距今 {} 天（沉睡只展示，不参与判定）", ms / 86_400_000),
            )),
            None => why.push((
                "dormantUnknown",
                "读不到键最后写入时间，因此不显示沉睡时长".to_string(),
            )),
        }
        out.push(json!({
            "kind": "reg_key",
            "target": format!("{}\\{}", r.hive, r.path),
            "reason": format!("App Paths「{}」指向 {}，该文件已不存在", r.key, p),
            "confidence": "low",
            "risk": "low",
            "defaultChecked": false,
            "origin": "dead",
            "deadClass": "appPaths",
            "deleteCapable": true,
            "testedPaths": [p],
            "contribs": contribs(&why),
            "dormantMs": dormant,
        }));
    }
    out
}
/// 沉睡时长（毫秒差）。读不到写入时间就返回 `None`，前端显示「未知」而不是"很久"。
pub(super) fn dormant_delta(last_write_ms: Option<i64>, now: i64) -> Value {
    match last_write_ms {
        Some(t) if t > 0 && now > t => json!(now - t),
        _ => Value::Null,
    }
}

pub(super) const DEAD_REG_CAP: usize = 120;

/// 卸载键原始行（枚举与判定分开，判定是纯函数）
pub(super) struct DeadUninstallRaw {
    pub(super) hive:String,
    pub(super) key:String,
    pub(super) path:String,
    pub(super) name:String,
    pub(super) install:String,
    pub(super) uninstall:String,
    pub(super) quiet:String,
    pub(super) last_write_ms:Option<i64>,
}

pub(super) struct DeadAppPathRaw {
    pub(super) hive:String,
    pub(super) key:String,
    pub(super) path:String,
    pub(super) value:String,
    pub(super) last_write_ms:Option<i64>,
}

pub(super) fn hive_of(label: &str) -> windows::Win32::System::Registry::HKEY {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    if label == "HKCU" {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    }
}

/// 采集三根下的卸载键原始字段（只读，不判定）
/// 三个根下的厂商顶层键（完整目标串，与执行侧 `HKCU\<子路径>` 的口径一致）。
///
/// 返回空 = 连根都枚举不到，调用方必须当成"读不到"而不是"这台机器没有厂商键"：
/// 拿空清单去做差分，会把所有现存键算成"卸载后才出现的新键"，那是凭空造出一批删除候选。
pub(super) unsafe fn collect_vendor_keys() -> Vec<String> {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let mut out = Vec::new();
    for (label, hive, sub) in [
        ("HKCU", HKEY_CURRENT_USER, r"Software"),
        ("HKLM", HKEY_LOCAL_MACHINE, r"SOFTWARE"),
        ("HKLM", HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node"),
    ] {
        for name in reg_enum_subkeys(hive, sub, footprint::MAX_KEYS_PER_OWNER) {
            if !footprint::is_vendor_key(&name) {
                continue;
            }
            out.push(format!("{label}\\{sub}\\{name}"));
        }
    }
    out
}

pub(super) unsafe fn collect_dead_uninstall_raws() -> Vec<DeadUninstallRaw> {
    const ROOTS: &[(&str, &str)] = &[
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ];
    let mut out = Vec::new();
    for (hive_label, root) in ROOTS {
        let hive = hive_of(hive_label);
        for sub in crate::engine::native::reg_enum_subkeys_pub(hive, root) {
            let path = format!("{root}\\{sub}");
            let rd = |v: &str| {
                crate::engine::native::read_reg_value_text(hive, &path, v)
                    .map(|(_, s)| s)
                    .unwrap_or_default()
            };
            let name = rd("DisplayName");
            let install = rd("InstallLocation");
            let uninstall = rd("UninstallString");
            let quiet = rd("QuietUninstallString");
            if name.is_empty() && install.is_empty() && uninstall.is_empty() {
                continue;
            }
            let last_write_ms = crate::engine::native::reg_key_last_write_ms(hive, &path);
            out.push(DeadUninstallRaw {
                hive: hive_label.to_string(),
                key: sub,
                path,
                name,
                install,
                uninstall,
                quiet,
                last_write_ms,
            });
        }
    }
    out
}

/// 采集 App Paths 默认值
pub(super) unsafe fn collect_dead_app_path_raws() -> Vec<DeadAppPathRaw> {
    const ROOTS: &[(&str, &str)] = &[
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\App Paths"),
    ];
    let mut out = Vec::new();
    for (hive_label, root) in ROOTS {
        let hive = hive_of(hive_label);
        for sub in crate::engine::native::reg_enum_subkeys_pub(hive, root) {
            let path = format!("{root}\\{sub}");
            let value = crate::engine::native::read_reg_value_text(hive, &path, "")
                .map(|(_, s)| s)
                .unwrap_or_default();
            if value.trim().is_empty() {
                continue;
            }
            let last_write_ms = crate::engine::native::reg_key_last_write_ms(hive, &path);
            out.push(DeadAppPathRaw {
                hive: hive_label.to_string(),
                key: sub,
                path,
                value,
                last_write_ms,
            });
        }
    }
    out
}

/// uninstall:dead-scan — 失效残留扫描（主窗档；不依赖卸载事实，只产候选）
#[tauri::command]
pub async fn uninstall_dead_scan<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let res = tauri::async_runtime::spawn_blocking(move || unsafe {
        let now = crate::engine::now_ms();
        let exists = |p: &str| std::path::Path::new(p).exists();
        let mut notes: Vec<String> = Vec::new();

        let u_raws = collect_dead_uninstall_raws();
        let mut u = dead_uninstall_findings(&u_raws, &exists, now);
        if u_raws.is_empty() {
            notes.push("卸载项清单读取失败（注册表三根都打不开），本组结果不完整".to_string());
        }
        u.sort_by(|a, b| b["dormantMs"].as_i64().cmp(&a["dormantMs"].as_i64()));
        u.truncate(DEAD_REG_CAP);

        let a_raws = collect_dead_app_path_raws();
        let mut ap = dead_app_paths_findings(&a_raws, &exists, now);
        ap.sort_by(|a, b| b["dormantMs"].as_i64().cmp(&a["dormantMs"].as_i64()));
        ap.truncate(DEAD_REG_CAP);

        if a_raws.is_empty() {
            notes.push("App Paths 清单读取失败（三根都打不开或一条都没有），本组结果不完整".to_string());
        }
        // 采集计数单独回传：候选为 0 在干净机器上是合法结果，但「扫过多少条」为 0 一定是
        // 枚举链断了。真机用例靠这两个数判"扫过但确实没有"还是"根本没扫"。
        let scanned = json!({ "uninstallKeys": u_raws.len(), "appPathsKeys": a_raws.len() });
        let findings = u.into_iter().chain(ap).collect::<Vec<_>>();
        (findings, notes, scanned)
    })
    .await;
    match res {
        Ok((findings, notes, scanned)) => {
            residue_snapshot_put(&label, "dead", findings.clone());
            json!({ "success": true, "data": {
                "appName": "失效残留",
                "findings": findings,
                "notes": notes,
                "scanned": scanned,
            }})
        }
        Err(e) => json!({ "success": false, "message": format!("失效残留扫描异常: {e}") }),
    }
}

