//! uninstall:list / uninstall:run —— 列表装配、体积兜底、静默命令构造、退出码分类、
//! 卸载进程监视与占用只读自检。
//!
//! 本文件是「命令串由后端现读注册表 + 构造器裁决」这条红线的落点：
//! build_silent_cmd 只放行 msi/inno/nsis 模板，其余明确 Err（竞品静默透传 UninstallString
//! 的反例）；渲染层回传的任何命令文本都不信任。
//! 与 appx.rs 有跨文件调用（枚举与卸载入口），故对彼此 `pub(super)` 开放。

use crate::engine::{guard, log};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tauri::WebviewWindow;
use super::helpers::*;
use super::appx::*;
use super::residue::*;
use super::ownership::*;
use super::dead::*;
// ==================== uninstall:list ====================

/// 安装器类型判定（方案 §4.2 installerKind）：
/// msi（UninstallString 走 msiexec）> inno（键名 _is1 / unins000.exe）>
/// nsis（卸载器名含 uninst/uninstall）> unknown。同时抽出 MSI 产品码 {GUID}。
pub(super) fn detect_installer(key_name: &str, uninstall_string: &str) -> (&'static str, Option<String>) {
    let us = uninstall_string.to_lowercase();
    if us.contains("msiexec") {
        let guid = uninstall_string
            .find('{')
            .and_then(|s| uninstall_string[s..].find('}').map(|e| uninstall_string[s..=s + e].to_string()));
        return ("msi", guid);
    }
    if key_name.to_lowercase().ends_with("_is1") || us.contains("unins000.exe") {
        return ("inno", None);
    }
    let base = us.rsplit(['\\', '/']).next().unwrap_or("");
    if base.contains("uninst") || base.contains("uninstall") {
        return ("nsis", None);
    }
    ("unknown", None)
}

/// 注册表键最后写入时间（LastWriteTime）→ "YYYY-MM-DD"，失败/异常年份返回空串。
/// U-5 安装日期列的兜底口径：卸载键的 LastWriteTime 常发生在安装/更新写入时
/// （卸载键值自带 InstallDate 的程序极少），与 HiBit 同为近似值，UI 文案注明「约」。
pub(super) unsafe fn reg_key_last_write_date(hk: windows::Win32::System::Registry::HKEY) -> String {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Registry::RegQueryInfoKeyW;
    use windows::Win32::System::Time::FileTimeToSystemTime;
    let mut ft = FILETIME::default();
    if RegQueryInfoKeyW(hk, None, None, None, None, None, None, None, None, None, None, Some(&mut ft)).is_err() {
        return String::new();
    }
    let mut st = windows::Win32::Foundation::SYSTEMTIME::default();
    if FileTimeToSystemTime(&ft, &mut st).is_err() || st.wYear < 1990 || st.wYear > 2100 {
        return String::new();
    }
    format!("{:04}-{:02}-{:02}", st.wYear, st.wMonth, st.wDay)
}

/// Unix 秒（卸载键 `InstallDate` 的存储口径）→ "YYYY-MM-DD"，不可信返回 None。
///
/// 装成纯函数是为了可测：`InstallDate` 由安装器自填，**0 与越界值是常态**（MSI 的
/// 某些壳、以及"字段存在但从没写过"的情况都会留 0），一旦直接信它，列表会显示
/// 1970-01-01 这种一眼假的日子；越界值（>2100）同样按不可信处理，让调用方退回
/// 键 LastWriteTime 那一档并照旧标「约」。
pub(super) fn install_date_from_epoch(secs: u32) -> Option<String> {
    if secs == 0 {
        return None;
    }
    // Howard Hinnant 的 civil_from_days：不引时区库、不加依赖（AGENTS §2 零新增依赖）
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let mut y = yoe as i64 + era * 400;
    if m <= 2 {
        y += 1;
    }
    if !(1990..=2100).contains(&y) {
        return None;
    }
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

/// 枚举一个 hive 根下的卸载条目。root 不存在 → 空集。
/// 过滤口径（与 build_inventory 同源）：空 DisplayName / SystemComponent=1 /
/// ReleaseType 含 update|hotfix|security 的跳过（系统组件与更新不是「已安装程序」）。
pub(super) unsafe fn enum_uninstall_root(hive: windows::Win32::System::Registry::HKEY, root: &str) -> Vec<Value> {
    use windows::Win32::System::Registry::{RegOpenKeyExW, RegCloseKey, KEY_READ};
    let mut out = Vec::new();
    for sub in crate::engine::native::reg_enum_subkeys_pub(hive, root) {
        let sub_path = format!("{root}\\{sub}");
        let sk = to_wide(&sub_path);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            continue;
        }
        let display_name = reg_sz(hk, "DisplayName").unwrap_or_default();
        let system_component = reg_dword(hk, "SystemComponent").unwrap_or(0);
        let release_type = reg_sz(hk, "ReleaseType").unwrap_or_default().to_lowercase();
        let display_version = reg_sz(hk, "DisplayVersion").unwrap_or_default();
        let publisher = reg_sz(hk, "Publisher").unwrap_or_default();
        let install_location = reg_sz(hk, "InstallLocation").unwrap_or_default();
        let display_icon = reg_sz(hk, "DisplayIcon").unwrap_or_default();
        let uninstall_string = reg_sz(hk, "UninstallString").unwrap_or_default();
        let quiet_uninstall_string = reg_sz(hk, "QuietUninstallString").unwrap_or_default();
        let estimated_size_kb = reg_dword(hk, "EstimatedSize").unwrap_or(0);
        // P1-D6（2026-10-01）：修改/修复入口判据与不可卸载声明。布尔一律按
        // 「值存在且 ==1」算 true（ARP 口径：声明缺失 = 不限制），缺失不丢条目。
        let modify_path = reg_sz(hk, "ModifyPath").unwrap_or_default();
        let no_modify = reg_dword(hk, "NoModify").unwrap_or(0) == 1;
        let no_repair = reg_dword(hk, "NoRepair").unwrap_or(0) == 1;
        let no_remove = reg_dword(hk, "NoRemove").unwrap_or(0) == 1;
        // 安装日期两档（V2 P1-D3）：装过 `InstallDate` 就按它报（安装器写下的值，不是猜的），
        // 缺失/为 0/越界才退回卸载键 LastWriteTime 那一档 —— 兜底口径与 U-5 一致，
        // 「约」标注沿用前端现状（前端不加精确/近似区分不影响正确性，只是少一分信息）
        let install_date_exact = reg_dword(hk, "InstallDate").and_then(install_date_from_epoch);
        let install_date = install_date_exact
            .clone()
            .unwrap_or_else(|| unsafe { reg_key_last_write_date(hk) });
        let _ = RegCloseKey(hk);

        if display_name.trim().is_empty() {
            continue;
        }
        if system_component == 1 {
            continue;
        }
        if release_type.contains("update") || release_type.contains("hotfix") || release_type.contains("security") {
            continue;
        }
        let (installer_kind, product_code) = detect_installer(&sub, &uninstall_string);
        out.push(json!({
            "id": format!("{}|{}", if hive == windows::Win32::System::Registry::HKEY_CURRENT_USER { "HKCU" } else { "HKLM" }, sub_path),
            "displayName": display_name,
            "publisher": publisher,
            "displayVersion": display_version,
            "installLocation": install_location,
            "displayIcon": display_icon,
            "uninstallString": uninstall_string,
            "quietUninstallString": quiet_uninstall_string,
            "modifyPath": modify_path,
            "noModify": no_modify,
            "noRepair": no_repair,
            "noRemove": no_remove,
            "estimatedSizeKb": estimated_size_kb,
            "installDate": install_date,
            "installDateExact": install_date_exact.is_some(),
            "productCode": product_code,
            "installerKind": installer_kind,
        }));
    }
    out
}

// ==================== B6 / B7：体积兜底与最近运行（2026-09-29，借鉴方案 P2） ====================

/// 有界目录体积扫描的上限。刻意有界：卸载清单里缺 `EstimatedSize` 的程序可能正装着
/// 整个游戏库，无界递归会把"打开页面"变成一次磁盘扫描。
pub(super) const DIR_SIZE_FILE_CAP: usize = 20_000;
pub(super) const DIR_SIZE_DEPTH_CAP: usize = 8;

/// 有界目录体积：返回 (字节数, 已访问文件数, 是否被上限截断)。
///
/// 三条不变量：
/// - 用 `symlink_metadata` 且跳过任何重解析点 —— 跟链接走会把别的目录算进来，
///   甚至在环上永不收敛（同一原因见 `dir_delete_blocked`）；
/// - 只统计文件字节，不折算目录项与簇对齐 —— 这是"估算"，UI 上也这么写；
/// - 触顶就返回 `partial=true`，绝不把截断值当成完整值。
pub(super) fn bounded_dir_size(root: &Path) -> DirSize {
    bounded_dir_size_in(root, DIR_SIZE_FILE_CAP, DIR_SIZE_DEPTH_CAP)
}

/// 一次有界目录遍历的产出。`ads_*` 单列而不并进 `bytes`：ADS 是否真的额外占盘取决于
/// 簇对齐与压缩，混进本体就说不清"估"的是哪一个数。
#[derive(Debug, Default, PartialEq)]
pub(super) struct DirSize {
    pub(super) bytes: u64,
    pub(super) files: usize,
    pub(super) partial: bool,
    pub(super) ads_bytes: u64,
    pub(super) ads_streams: usize,
}

/// 上限抽成入参：真机阈值（2 万文件 / 8 层）在单测里跑不起，但截断语义必须能判红。
pub(super) fn bounded_dir_size_in(root: &Path, file_cap: usize, depth_cap: usize) -> DirSize {
    let mut out = DirSize::default();
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for ent in rd.flatten() {
            let Ok(md) = ent.file_type() else { continue };
            if md.is_symlink() {
                continue;
            }
            let path = ent.path();
            if md.is_dir() {
                if depth + 1 >= depth_cap {
                    out.partial = true;
                    continue;
                }
                stack.push((path, depth + 1));
                continue;
            }
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_file() => {
                    // 触顶即整体收工：只跳出当前目录会留下一栈子目录继续 read_dir，
                    // 在 target/ 这种目录数巨大的树上等于没设上限。
                    if out.files >= file_cap {
                        out.partial = true;
                        return out;
                    }
                    out.bytes = out.bytes.saturating_add(m.len());
                    out.files += 1;
                    // HiBit §H5：一并累计命名数据流（下载来源标记 Zone.Identifier 之类）。
                    // 每个文件一次 FindFirstStreamW，量级被 file_cap 天然限制住。
                    let (ab, ac) = crate::engine::native::file_ads_bytes(&path);
                    out.ads_bytes = out.ads_bytes.saturating_add(ab);
                    out.ads_streams += ac;
                }
                _ => {}
            }
        }
    }
    out
}

/// uninstall:dir-size — 体积二级兜底（B6）。清单里 `EstimatedSize` 缺失时按安装目录估。
///
/// 档位取 MAIN：唯一调用方是主窗卸载页（与 `uninstall_list` 同档）。
/// 只读、不跟随重解析点、有界，因此不写日志也不建快照。
/// v2-L4P-18（F-2）：上限 2 万文件 + 每文件 ADS 枚举是纯阻塞面，同步命令会在主线程
/// 响应点原地执行 ⇒ 大目录整段冻结 UI。改 async + spawn_blocking（与 `report_save` 同形）。
#[tauri::command]
pub async fn uninstall_dir_size<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    path: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let root = PathBuf::from(path.trim());
    // 只接受绝对路径且真实存在的目录：其余一律不扫（也不报错给攻击面探测者额外信息）
    if path.trim().is_empty() || !root.is_absolute() || !root.is_dir() {
        return json!({ "success": false, "message": "路径不可用" });
    }
    let ds = tauri::async_runtime::spawn_blocking(move || bounded_dir_size(&root))
        .await
        .unwrap_or(DirSize::default());
    json!({
        "success": true,
        "data": {
            "sizeKb": ds.bytes / 1024,
            "files": ds.files,
            "partial": ds.partial,
            // HiBit §H5：命名数据流单独回传。前端只在有条目时多讲一句，
            // 它解释的是「为什么删完释放的比显示的多/少」，不是本体体积
            "adsBytes": ds.ads_bytes,
            "adsStreams": ds.ads_streams,
        }
    })
}

/// 从 Prefetch 文件名解出主程序名（`OBS64.EXE-2F3A1B4C.pf` → `OBS64.EXE`）。
/// 认不出（无 8 位十六进制后缀、非 .pf）返回 None —— 宁可不显示也不猜。
pub(super) fn prefetch_entry_exe(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".pf")?;
    let (exe, hash) = stem.rsplit_once('-')?;
    if exe.is_empty() || hash.len() != 8 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(exe.to_ascii_uppercase())
}

/// 建 Prefetch 索引：主程序名（大写）→ 最后运行时间（Unix 毫秒，取文件 mtime）。
///
/// 回空表有两种**都不代表"程序从未运行"**：非提权时 `C:\Windows\Prefetch` 读不到（ACL
/// 限制），以及本机干脆关掉了 Prefetch（`EnablePrefetcher=0` / SysMain 禁用 —— 开发机实测
/// 就是这种，目录只剩一个 ReadyBoot）。所以调用方只在拿得到时渲染，拿不到就什么都不显示。
pub(super) fn prefetch_last_run_index() -> std::collections::HashMap<String, i64> {
    let mut out = std::collections::HashMap::new();
    let Some(windir) = std::env::var("SystemRoot").ok() else { return out };
    let dir = Path::new(&windir).join("Prefetch");
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for ent in rd.flatten() {
        let Some(exe) = prefetch_entry_exe(&ent.file_name().to_string_lossy()) else { continue };
        let Ok(md) = ent.metadata() else { continue };
        let Ok(modified) = md.modified() else { continue };
        let Ok(d) = modified.duration_since(std::time::UNIX_EPOCH) else { continue };
        let ms = d.as_millis() as i64;
        let e = out.entry(exe).or_insert(0i64);
        if ms > *e {
            *e = ms;
        }
    }
    out
}

/// 从 DisplayIcon 里取主程序 exe 名（`C:\Apps\Foo\foo.exe,0` → `FOO.EXE`）。
/// 取不到（无扩展名、指向 dll/ico）返回 None。
pub(super) fn exe_name_from_display_icon(icon: &str) -> Option<String> {
    let head = icon.split(',').next().unwrap_or("").trim();
    if head.is_empty() {
        return None;
    }
    let base = Path::new(head).file_name()?.to_string_lossy().to_string();
    if !base.to_ascii_lowercase().ends_with(".exe") {
        return None;
    }
    Some(base.to_ascii_uppercase())
}


/// 桌面与开始菜单的 `.lnk` 索引：文件名主干（小写）→ 首个命中的完整路径。
///
/// 为什么要有第四图标源：不少程序在注册表 `DisplayIcon` 里留的是安装时那台机器上的路径
/// （或被搬过、或干脆指向一个通用 dll 的索引），前端拿它取不到图；真正带着正确图标的
/// 东西是桌面/开始菜单那个快捷方式 —— `SHGetFileInfoW` 会顺着 .lnk 解析到目标图标。
/// 只按**精确同名**匹配，不做相似度：图标是锦上添花，把别家程序的图标配到这一行上，
/// 比留一个占位方块更糟。
pub(super) fn shortcut_icon_index() -> std::collections::HashMap<String, String> {
    fn walk(dir: &std::path::Path, depth: usize, out: &mut std::collections::HashMap<String, String>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(mt) = e.metadata() else { continue };
            if mt.is_dir() {
                if depth > 0 {
                    walk(&p, depth - 1, out);
                }
                continue;
            }
            let is_lnk = p
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("lnk"))
                .unwrap_or(false);
            if !is_lnk {
                continue;
            }
            let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else { continue };
            let key = stem.trim().to_lowercase();
            if !key.is_empty() {
                out.entry(key).or_insert_with(|| p.to_string_lossy().to_string());
            }
        }
    }
    let joined = |var: &str, tail: &str| -> Option<(std::path::PathBuf, usize)> {
        std::env::var(var)
            .ok()
            .map(|v| (std::path::PathBuf::from(v).join(tail), if tail.contains("Start Menu") { 4 } else { 0 }))
    };
    let mut roots: Vec<(std::path::PathBuf, usize)> = Vec::new();
    for spec in [
        joined("USERPROFILE", "Desktop"),
        joined("PUBLIC", "Desktop"),
        joined("APPDATA", r"Microsoft\Windows\Start Menu\Programs"),
        joined("PROGRAMDATA", r"Microsoft\Windows\Start Menu\Programs"),
    ] {
        if let Some(r) = spec {
            roots.push(r);
        }
    }
    let mut out = std::collections::HashMap::new();
    for (root, depth) in roots {
        walk(&root, depth, &mut out);
    }
    out
}

/// 卸载域·列表（方案 M1 + 用户拍板 2026-09-28）。
/// scope：user=传统 Win32 程序（HKLM 64+32 与 HKCU 三根合并去重，HiBit「程序名」83 项的口径）；
/// windows=Appx 商店应用（Get-AppxPackage，当前用户，分第三方/Windows 应用两组）。
#[tauri::command]
pub async fn uninstall_list<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    scope: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let scope = scope.to_lowercase();
    if !matches!(scope.as_str(), "user" | "windows") {
        return json!({ "success": false, "message": "未知范围：只支持 user / windows" });
    }
    // 注册表枚举 / Appx 枚举都是纯阻塞 IO，丢 blocking 池，避免占住 async worker。
    // 枚举失败显式上抛（空数组会被当成「没有程序」伪装成功）。
    let apps = tauri::async_runtime::spawn_blocking(move || -> Result<Vec<Value>, String> {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        if scope == "windows" {
            let mut rows = enum_appx_packages()?;
            // 未注册到当前用户的两类（staged / 全用户预配）补在同一列表里，
            // 但 removable=false ⇒ 前端不给卸载按钮（HiBit §H6：覆盖面不顺手放大执行面）
            let seen: std::collections::HashSet<String> = rows
                .iter()
                .filter_map(|r| {
                    r["id"].as_str().and_then(|s| s.strip_prefix("APPX|")).map(String::from)
                })
                .collect();
            rows.extend(enum_appx_store_extras(&seen));
            return Ok(rows);
        }
        let mut apps: Vec<Value> = Vec::new();
        unsafe {
            apps.extend(enum_uninstall_root(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"));
            apps.extend(enum_uninstall_root(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"));
            apps.extend(enum_uninstall_root(HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"));
        }
        // 跨根去重（HiBit 同口径）：同一程序常同时出现在 HKLM 64 位与 WOW6432Node 键下。
        // 键 = 显示名+版本+发布者（小写）；保留先出现者（HKCU 优先，用户级条目更贴近当前用户）。
        // 带上 publisher 是为了不再把「同名同版本的两家产品」静默折叠成一行（id 本身无碰撞）。
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        apps.retain(|a| {
            let key = format!(
                "{}|{}|{}",
                a["displayName"].as_str().unwrap_or("").to_lowercase(),
                a["displayVersion"].as_str().unwrap_or(""),
                a["publisher"].as_str().unwrap_or("").to_lowercase()
            );
            seen.insert(key)
        });
        // B7：主程序最近运行时间（Prefetch 文件 mtime）。非提权时那个目录读不到，
        // 回空表即可 —— 前端按「没有这个信息」渲染，**不能**把空当成「从未运行」。
        let runs = prefetch_last_run_index();
        if !runs.is_empty() {
            for a in apps.iter_mut() {
                if let Some(exe) = a["displayIcon"].as_str().and_then(exe_name_from_display_icon) {
                    if let Some(ms) = runs.get(&exe) {
                        a["lastRunMs"] = json!(ms);
                    }
                }
            }
        }
        // 图标第四源挂到行上（前端按优先级尝试，取不到仍回退占位，不新增 IPC 通道）
        let links = shortcut_icon_index();
        for a in apps.iter_mut() {
            let name = a["displayName"].as_str().unwrap_or("").trim().to_lowercase();
            if let Some(p) = links.get(&name) {
                a["shortcutPath"] = json!(p);
            }
        }
        apps.sort_by(|a, b| {
            let an = a["displayName"].as_str().unwrap_or("").to_lowercase();
            let bn = b["displayName"].as_str().unwrap_or("").to_lowercase();
            an.cmp(&bn)
        });
        Ok(apps)
    })
    .await
    .unwrap_or_else(|e| Err(format!("枚举异常: {e}")));
    match apps {
        Ok(list) => json!({ "success": true, "data": { "apps": list } }),
        Err(e) => json!({ "success": false, "message": e }),
    }
}

// ==================== uninstall:run ====================

/// 把原厂卸载命令行拆成 (exe, args)。
/// 带引号取首段引号；msiexec 直接归一；其余在「首个 .exe」处切开（卸载串的 exe
/// 路径几乎总以 .exe 结尾，比按首个空格切更稳），都失败再退回首空格。
pub(super) fn split_uninstall_cmd(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some((rest[..end].to_string(), rest[end + 1..].trim().to_string()));
    }
    let low = s.to_lowercase();
    if low.starts_with("msiexec") {
        let rest = s.get(7..).unwrap_or_default().trim().to_string();
        return Some(("msiexec.exe".to_string(), rest));
    }
    if let Some(idx) = low.find(".exe") {
        let exe = s[..idx + 4].to_string();
        let args = s[idx + 4..].trim().to_string();
        return Some((exe, args));
    }
    let sp = s.find(' ')?;
    Some((s[..sp].to_string(), s[sp + 1..].trim().to_string()))
}

/// 静默卸载只认白名单模板（方案 §4.3）：msi → msiexec /X{GUID} /qn /norestart；
/// inno → /VERYSILENT /SUPPRESSMSGBOXES /NORESTART；nsis → /S。其余一律拒绝。
pub(super) fn build_silent_cmd(kind: &str, product_code: Option<&str>, exe: &str, raw_args: &str) -> Result<(String, String), String> {
    match kind {
        "msi" => {
            let Some(guid) = product_code else {
                return Err("MSI 产品码缺失，无法构造静默卸载".to_string());
            };
            if !guid.starts_with('{') || !guid.ends_with('}') || guid.contains('"') {
                return Err("MSI 产品码格式异常，拒绝执行".to_string());
            }
            Ok(("msiexec.exe".to_string(), format!("/X{guid} /qn /norestart")))
        }
        "inno" => Ok((exe.to_string(), "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART".to_string())),
        "nsis" => Ok((exe.to_string(), "/S".to_string())),
        _ => {
            let _ = raw_args;
            Err("该安装器类型不受静默白名单支持，请使用原厂卸载界面".to_string())
        }
    }
}

/// 直接当卸载目标就危险的宿主：这些进程会把自己收到的参数再解释一遍，参数里的
/// `|` `&` `$` 就不再是字面量。而静默串来自注册表，是**软件自己能写**的字段。
pub(super) const QUIET_DENY_HOSTS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "reg.exe",
    "regsvr32.exe",
    "sc.exe",
    "conhost.exe",
];

/// 静默命令候选（方案 §6.4）：执行层只接受这个结构，**不接受未解析的注册表原文**。
pub(super) struct SilentCandidate {
    pub(super) exe: String,
    pub(super) args: String,
    /// `vendor` = 厂商 QuietUninstallString；`whitelist` = 本地白名单模板派生
    pub(super) source: &'static str,
    /// 厂商串被拒的原因（进日志，说明为什么退回白名单派生；None = 没试过或试通）
    pub(super) vendor_reject: Option<String>,
}

/// 厂商静默串准入闸（B1 强约束）：只放行「单一绝对路径 exe + 字面参数」。
/// 返回 `Some(原因)` = 拒绝该串（调用方回退白名单派生，不是放弃静默）。
/// 存在性判定注入化：闸本身保持纯函数，单测不必造真文件。
pub(super) fn quiet_string_reject_reason(
    exe: &str,
    args: &str,
    file_exists: &dyn Fn(&Path) -> bool,
) -> Option<String> {
    let exe_low = exe.to_lowercase();
    let name = exe_low.rsplit(['\\', '/']).next().unwrap_or("");
    if QUIET_DENY_HOSTS.contains(&name) {
        return Some(format!("{name} 是 shell/脚本宿主，参数会被二次解释"));
    }
    if !name.ends_with(".exe") {
        return Some("目标不是 .exe（.msi/.msp 一律走 msiexec 白名单派生）".to_string());
    }
    let b = exe.as_bytes();
    let abs = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
    if !abs {
        return Some("可执行文件不是绝对路径".to_string());
    }
    if exe.contains('"') || exe.contains('\'') {
        return Some("可执行文件路径含引号".to_string());
    }
    for c in ['<', '>', '|', '&', ';', '$', '`', '\n', '\r', '\0'] {
        if args.contains(c) {
            return Some(format!("参数含 {:?} 形态（重定向/管道/复合命令/变量替换）", c));
        }
    }
    // `%` 成对出现按变量替换处理：ShellExecuteEx 不会展开它，留着只会把「没展开的字面量」
    // 交给卸载器，行为不可证明；单个 % 属于合法文件名（如 100% 目录名）则放行。
    if args.matches('%').count() >= 2 {
        return Some("参数含 %VAR% 变量替换形态".to_string());
    }
    if args.matches('"').count() % 2 != 0 {
        return Some("参数引号未闭合".to_string());
    }
    if !file_exists(Path::new(exe)) {
        return Some("可执行文件不存在".to_string());
    }
    None
}

/// 静默命令裁决（B1）：厂商静默串优先于本地拼参数，但必须先过构造闸；
/// 构造失败或语义不明 → 记录原因并回退现有白名单派生（不永久放弃该程序的静默能力）。
pub(super) fn pick_silent_candidate(
    kind: &str,
    product_code: Option<&str>,
    original: &(String, String),
    quiet: Option<&str>,
    file_exists: &dyn Fn(&Path) -> bool,
) -> Option<SilentCandidate> {
    let mut vendor_reject: Option<String> = None;
    if let Some(q) = quiet.map(str::trim).filter(|s| !s.is_empty()) {
        match split_uninstall_cmd(q) {
            None => vendor_reject = Some("厂商静默串解析不出可执行文件".to_string()),
            Some((qe, qa)) => match quiet_string_reject_reason(&qe, &qa, file_exists) {
                Some(reason) => vendor_reject = Some(reason),
                None => {
                    return Some(SilentCandidate { exe: qe, args: qa, source: "vendor", vendor_reject: None })
                }
            },
        }
    }
    build_silent_cmd(kind, product_code, &original.0, &original.1)
        .ok()
        .map(|(exe, args)| SilentCandidate { exe, args, source: "whitelist", vendor_reject })
}

/// 卸载器退出码语义分档（B2）：返回 (中文语义, 是否回退原厂卸载界面)。
///
/// 口径来源要分清：`0 / 3010 / 1605` 是 Trim 此前已特判的三档；`1602 / 1618 / 1603`
/// 的语义取自 MSI 官方错误码（`1602` 用户取消、`1618` 另一安装进行中、`1603` 内部错误），
/// **本机未用真实 MSI/NSIS 样本复现过**。因此：取消与并发**不再**自动重弹原厂界面
/// （用户既然取消就不再替他决定，自动重弹等于无视取消）；`1618` 只做提示、
/// 不做有界重试（重试策略要真机证据才定，方案 §5·B2 证据边界）。
/// NSIS 的 `1/2` 不特判：与通用码空间重叠，未确认前按「其它」走原回退路径。
///
/// 2026-10-05 复核收口：这张表只在 `installerKind == "msi"` 时决定「是否回退原厂界面」；
/// Inno/NSIS 的退出码空间与 MSI 重叠但语义不同（NSIS 1/2 = 用户取消/错误），
/// 按 MSI「其它 ⇒ 自动重弹」会让用户刚点的取消被无视。未取到真机样本前，
/// 非 MSI 安装器只在**启动失败**时回退，不按退出码回退（`list_run` 调用点按 kind 判）。
pub(super) fn classify_exit(code: u32) -> (&'static str, bool) {
    match code {
        0 => ("卸载成功", false),
        3010 => ("卸载成功，需重启完成", false),
        1605 => ("产品未安装（该卸载键已无对应产品）", false),
        1602 => ("用户取消", false),
        1618 => ("另一个安装或卸载正在进行，请稍后再试", false),
        1603 => ("安装器内部错误", true),
        _ => ("其它退出码", true),
    }
}

/// 安装器识别的第二条证据（B4）：仅在纯字符串判定为 `unknown` 时调用，且只探
/// Inno / NSIS 的**独有文件名**（固定候选、顶层不递归、不枚举目录，所以没有
/// 「目录太大」「枚举超时」这类成本面）。
///
/// 刻意**不把 `uninstall.exe` 认成 NSIS**：那名字太通用，认了就是把 `/S` 发给一个
/// 未知卸载器——识别可以弱，执行不能猜。存在性判定由调用方注入，便于单测不触盘。
pub(super) fn second_evidence_kind(install_location: &str, file_exists: &dyn Fn(&Path) -> bool) -> Option<&'static str> {
    let loc = install_location.trim().trim_end_matches(['\\', '/']).to_string();
    if loc.is_empty() || loc.chars().count() > 260 || !loc.contains(':') {
        return None;
    }
    let base = Path::new(&loc);
    for (name, kind) in [("unins000.exe", "inno"), ("nsisunins.exe", "nsis")] {
        if file_exists(&base.join(name)) {
            return Some(kind);
        }
    }
    None
}

/// ShellExecuteEx 启动卸载器并等待退出。返回 (exitCode, 是否拿到进程句柄)。
/// 不加 RUNAS verb：卸载器自带 manifest 会按需弹 UAC（对齐 Trim 按需提权模型）。
pub(super) unsafe fn shell_run_wait(exe: &str, args: &str) -> Result<u32, String> {
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::core::PCWSTR;

    let file = to_wide(exe);
    let params = if args.is_empty() { None } else { Some(to_wide(args)) };
    let mut sei: SHELLEXECUTEINFOW = core::mem::zeroed();
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile = PCWSTR(file.as_ptr());
    if let Some(p) = &params {
        sei.lpParameters = PCWSTR(p.as_ptr());
    }
    sei.nShow = 1; // SW_SHOWNORMAL
    ShellExecuteExW(&mut sei).map_err(|e| format!("启动卸载器失败: {e}"))?;
    let h = sei.hProcess;
    if h.is_invalid() {
        // 拿不到句柄（目标拒绝 NOCLOSEPROCESS 等）：无法等待，如实上报
        return Err("卸载器已启动但无法等待其完成（未返回进程句柄）".to_string());
    }
    WaitForSingleObject(h, INFINITE);
    let mut code: u32 = 0;
    let _ = GetExitCodeProcess(h, &mut code);
    let _ = windows::Win32::Foundation::CloseHandle(h);
    Ok(code)
}

// ==================== 卸载进程监视（2026-09-28 用户拍板） ====================
// Inno/NSIS 卸载器会把自身复制到临时目录后由副本继续（unins000.exe → au_.exe /
// un_a.exe），或经 UAC 提权拉起新进程——「启动句柄退出」≠「卸载结束」。原实现
// wait 提前返回，残留扫描在卸载器还在跑时就执行，只扫出一条“卸载键还在”。
// 口径：先等句柄退出，再 1s 间隔轮询（上限 15 分钟）：
//   · 卸载键消失 → 卸载完成；
//   · 卸载器家族进程全部退出且连续 3 轮稳定 → 结束（用户取消 / 静默完成）；
//   · 超时 → 如实返回键的现状。

/// 当前全系统进程名快照（小写；Toolhelp32，与 native-scanner ffi 同口径）
pub(super) fn process_names_snapshot() -> std::collections::HashSet<String> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut out = std::collections::HashSet::new();
    unsafe {
        // windows 0.61 返回 Result<HANDLE>；失败按空快照处理（调用方走 3 轮稳定判定）
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                let len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
                out.insert(String::from_utf16_lossy(&pe.szExeFile[..len]).to_lowercase());
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snap);
    }
    out
}

/// 卸载器家族进程判定：启动的 exe 本名 + Inno/NSIS 临时副本/提权副本/MSI 引擎
pub(super) fn is_uninstaller_process(name: &str, launched: &str) -> bool {
    if name == launched {
        return true;
    }
    name == "msiexec.exe"
        || name == "au_.exe"
        || name == "un_a.exe"
        || name.starts_with("unins")
        || name.starts_with("un_a")
}

// ==================== P2-D4 占用进程与第三方模块只读自检（2026-10-01） ====================
// Geek 的对应行为：撞上被安全软件注入的进程时明说「XX 与 avcuf64.dll 不兼容，请退出该
// 应用或禁用插件」。Trim 口径刻意收窄成只报事实：谁把目标文件当模块加载着、它还加载了
// 哪些非 Windows 目录的第三方模块。不判恶意、不自动结束任何进程——「注入」这个词本身
// 带指控味，文案统一说「第三方模块」，解释方向只点名安全软件这一种常见可能。
// 纯句柄占用（数据文件被打开读）模块枚举看不见，找不到时回退原有「可能被占用」文案。

/// 模块路径是否「第三方」：不在 Windows 目录、不在本应用自身目录。
/// 排除自身目录的理由：应用自己的 DLL 占着自己的卸载目标是常态，报出来是噪声。
pub(super) fn is_third_party_module(module_path: &str) -> bool {
    fn under(dir_lower: &str, root: &str) -> bool {
        let r = root.trim_end_matches(['\\', '/']).to_lowercase();
        if r.is_empty() {
            return false;
        }
        // 完全相等也算在内：self_dir 场景里目录本身就可能直接等于根（模块文件
        // 就躺在这层目录），只认「下一个字符是分隔符」会把这层漏掉；
        // C:\Windows.old 这类跨段前缀仍由「下一个字符必须是分隔符」挡住。
        dir_lower.starts_with(&r)
            && matches!(
                dir_lower.as_bytes().get(r.len()),
                Some(b'\\') | Some(b'/') | None
            )
    }
    let lower = module_path.to_lowercase();
    let Some(dir) = lower.rsplit_once('\\').map(|(d, _)| d) else {
        return false;
    };
    if under(
        dir,
        &std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()),
    ) {
        return false;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(self_dir) = exe.parent().and_then(|p| p.to_str()) {
            if under(dir, self_dir) {
                return false;
            }
        }
    }
    true
}

/// 找出把 `target` 当模块加载着的进程（只读：ToolHelp 进程快照 + EnumProcessModulesEx）。
/// 返回 (pid, 进程名, 该进程加载的第三方模块名样例)。打不开的进程直接跳过——系统进程
/// 读不到模块是常态，不能因此把检查变成报错。单进程模块数截 512、样例截 8 个：这条
/// 检查只为拼一条提示文案，量再大也用不上。
pub(super) fn module_lockers(target: &Path) -> Vec<(u32, String, Vec<String>)> {
    use windows::Win32::Foundation::{CloseHandle, HMODULE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    const MODULE_CAP: usize = 512;
    const SAMPLE_CAP: usize = 8;

    let want = target.to_string_lossy().to_lowercase();
    let mut out: Vec<(u32, String, Vec<String>)> = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snap, &mut pe).is_ok();
        while more {
            let pid = pe.th32ProcessID;
            let len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let exe = String::from_utf16_lossy(&pe.szExeFile[..len]);
            more = Process32NextW(snap, &mut pe).is_ok();
            if pid == 0 {
                continue;
            }
            let Ok(h) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) else {
                continue;
            };
            let mut locker = false;
            let mut third: Vec<String> = Vec::new();
            let mut needed = 0u32;
            // 两段式：先传空指针只取 cbNeeded（文档允许），再按实际模块数取一遍
            if EnumProcessModulesEx(h, std::ptr::null_mut(), 0, &mut needed, LIST_MODULES_ALL)
                .is_ok()
                && needed > 0
            {
                let size_of_hmodule = std::mem::size_of::<HMODULE>();
                let count = ((needed as usize) / size_of_hmodule).min(MODULE_CAP);
                let mut mods = vec![HMODULE::default(); count];
                let mut got = 0u32;
                if EnumProcessModulesEx(
                    h,
                    mods.as_mut_ptr(),
                    (count * size_of_hmodule) as u32,
                    &mut got,
                    LIST_MODULES_ALL,
                )
                .is_ok()
                {
                    let n = ((got as usize) / size_of_hmodule).min(mods.len());
                    let mut buf = [0u16; 1024];
                    for m in &mods[..n] {
                        let l = GetModuleFileNameExW(Some(h), Some(*m), &mut buf) as usize;
                        if l == 0 {
                            continue;
                        }
                        let path = String::from_utf16_lossy(&buf[..l]).to_lowercase();
                        if path == want {
                            locker = true;
                        }
                        if third.len() < SAMPLE_CAP && is_third_party_module(&path) {
                            let name = path.rsplit(['\\', '/']).next().unwrap_or(&path);
                            third.push(name.to_string());
                        }
                    }
                }
            }
            let _ = CloseHandle(h);
            if locker {
                out.push((pid, exe, third));
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// 删除失败行的占用说明：查得到模块级占用就点名进程与第三方模块样例，查不到回退原句。
pub(super) fn occupancy_note(target: &Path) -> String {
    let Some((pid, exe, third)) = module_lockers(target).into_iter().next() else {
        return "删除失败（可能被占用）".to_string();
    };
    if third.is_empty() {
        return format!("删除失败：文件被 {exe}（PID {pid}）加载占用，可尝试退出该程序后重试");
    }
    format!(
        "删除失败：文件被 {exe}（PID {pid}）加载占用，该进程还加载了 {} 个非系统目录的第三方模块（{} 等，常见于安全软件）——可尝试退出该程序或暂时关闭其防护后重试",
        third.len(),
        third.join("、")
    )
}

/// 句柄退出后继续监视：返回 (stillListed, 是否超时放弃)。
pub(super) fn watch_uninstaller(
    hive: windows::Win32::System::Registry::HKEY,
    key_path: &str,
    launched_exe: &str,
) -> (bool, bool) {
    let launched = launched_exe
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_lowercase();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15 * 60);
    let mut stable = 0u32;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        // 键消失 = 卸载完成（最早、最可靠的完成信号）
        if !crate::engine::native::reg_key_exists(hive, key_path) {
            return (false, false);
        }
        let any = process_names_snapshot()
            .iter()
            .any(|n| is_uninstaller_process(n, &launched));
        if any {
            stable = 0;
        } else {
            stable += 1;
            if stable >= 3 {
                // 卸载器家族进程已连续 3 秒绝迹：卸载结束（含用户取消）
                break;
            }
        }
        if std::time::Instant::now() > deadline {
            return (crate::engine::native::reg_key_exists(hive, key_path), true);
        }
    }
    (crate::engine::native::reg_key_exists(hive, key_path), false)
}

/// 卸载域·执行原厂卸载（方案 M2 + 用户拍板 2026-09-28）。
/// app_id 只当**寻址键**用：Win32 命令串一律现读注册表，不信任渲染层回传；
/// APPX 前缀走 Remove-AppxPackage（包全名过字符集白名单后内插，防注入）。
#[tauri::command]
pub async fn uninstall_run<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    app_id: String,
    // 已废弃（2026-09-28 二轮拍板）：静默勾选框删除，静默优先成为默认行为；参数保留兼容旧调用
    silent: Option<bool>,
) -> Value {
    let _ = silent;
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // ---- Windows 应用（Appx）：Remove-AppxPackage，无静默/原厂 UI 之分 ----
    if let Some(fullname) = app_id.strip_prefix("APPX|") {
        if !valid_appx_fullname(fullname) {
            return json!({ "success": false, "message": "包全名格式非法" });
        }
        let fullname = fullname.to_string();
        let res = tauri::async_runtime::spawn_blocking(move || {
            log::flush_sync();
            remove_appx(&fullname)
        })
        .await;
        return match res {
            Ok(Ok(())) => json!({ "success": true, "data": {
                "exitCode": 0, "stillListed": false, "installerKind": "appx",
                "message": "已从当前用户移除该 Windows 应用",
            }}),
            Ok(Err(e)) => json!({ "success": false, "message": e }),
            Err(e) => json!({ "success": false, "message": format!("卸载执行异常: {e}") }),
        };
    }
    let Some((hive_str, key_path)) = app_id.split_once('|') else {
        return json!({ "success": false, "message": "app_id 格式错误" });
    };
    if !valid_uninstall_key_path(key_path) {
        return json!({ "success": false, "message": "app_id 不是合法的卸载键路径" });
    }
    let hive_str = hive_str.to_string();
    let key_path = key_path.to_string();
    let res = tauri::async_runtime::spawn_blocking(move || unsafe {
        use windows::Win32::System::Registry::{RegOpenKeyExW, RegCloseKey, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
        let (hive, hive_name) = if hive_str.eq_ignore_ascii_case("HKCU") {
            (HKEY_CURRENT_USER, "HKCU")
        } else if hive_str.eq_ignore_ascii_case("HKLM") {
            (HKEY_LOCAL_MACHINE, "HKLM")
        } else {
            return Err("app_id hive 只支持 HKCU/HKLM".to_string());
        };
        let sk = to_wide(&key_path);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return Err("卸载注册表键不存在（程序可能已被卸载）".to_string());
        }
        let display_name = reg_sz(hk, "DisplayName").unwrap_or_default();
        let uninstall_string = reg_sz(hk, "UninstallString").unwrap_or_default();
        let quiet_string = reg_sz(hk, "QuietUninstallString").unwrap_or_default();
        let install_location = reg_sz(hk, "InstallLocation").unwrap_or_default();
        let publisher = reg_sz(hk, "Publisher").unwrap_or_default();
        let key_name = key_path.rsplit('\\').next().unwrap_or("").to_string();
        let (mut kind, product_code) = detect_installer(&key_name, &uninstall_string);
        let _ = RegCloseKey(hk);
        // B4 第二证据：只在字符串判定不出类型时探测，且只认独有文件名（不猜通用名）
        if kind == "unknown" {
            if let Some(ev) = second_evidence_kind(&install_location, &|p| p.is_file()) {
                log::write_log(
                    "info",
                    &format!("uninstall_run {display_name}: 字符串判定 unknown，InstallLocation 第二证据判为 {ev}"),
                );
                kind = ev;
            }
        }

        if uninstall_string.trim().is_empty() {
            return Err("该程序没有 UninstallString，无法调用原厂卸载器".to_string());
        }
        // 静默优先（2026-09-28 二轮拍板，勾选框已删）：先厂商 QuietUninstallString
        // （必须过 B1 构造闸），再本地白名单派生；退出码按 B2 分档决定是否回退原厂界面。
        let original = split_uninstall_cmd(&uninstall_string)
            .ok_or_else(|| "UninstallString 无法解析出可执行文件".to_string())?;
        let candidate =
            pick_silent_candidate(kind, product_code.as_deref(), &original, Some(&quiet_string), &|p| p.is_file());
        let (mut exe, args, used_silent, silent_source) = match &candidate {
            Some(c) => (c.exe.clone(), c.args.clone(), true, c.source),
            None => (original.0.clone(), original.1.clone(), false, "none"),
        };
        if let Some(reason) = candidate.as_ref().and_then(|c| c.vendor_reject.as_ref()) {
            log::write_log(
                "info",
                &format!("uninstall_run {display_name}: 厂商 QuietUninstallString 被构造闸拒绝（{reason}），改用白名单派生"),
            );
        }
        let run_original_ui = || -> Result<u32, String> {
            log::flush_sync();
            shell_run_wait(&original.0, &original.1).map_err(|e| {
                log::write_log("error", &format!("uninstall_run {display_name}: 回退原厂卸载界面启动失败: {e}"));
                e
            })
        };
        // C2 所有权事件：在启动卸载器**之前**记 pending —— 此刻还不知道卸载会不会成功，
        // 所以只登记「用户打算卸它」这一事实。应用数据遗留判定要等复扫确认程序已消失、且原安装目录
        // ENOENT，才升级为 historical（Q9 拍板：取消/失败不回滚成"已卸载"，交给稳定期回收）。
        let mut owned_paths: Vec<String> = Vec::new();
        if !install_location.trim().is_empty() {
            owned_paths.push(install_location.trim().trim_end_matches('\\').to_string());
        }
        if let Some(parent) = Path::new(&original.0).parent() {
            let p = parent.to_string_lossy().to_string();
            if !p.is_empty() && !owned_paths.iter().any(|x| x.eq_ignore_ascii_case(&p)) {
                owned_paths.push(p);
            }
        }
        {
            let mut own_doc = ownership::load();
            let app_id = format!("{hive_name}|{key_path}");
            let recorded = ownership::record_pending(
                &mut own_doc,
                &app_id,
                &display_name,
                &publisher,
                install_location.trim(),
                &owned_paths,
                crate::engine::now_ms(),
                norm_name,
            );
            // HiBit §9.1 那条基线：卸载**之前**取一次厂商顶层键集合。之后扫描时
            // 「卸载前没有、现在有了」的键才可能是这程序自己写的配置键（卸载器不认的那批）。
            // 一个根都没枚举到就**不写基线**：空集合不是"这台机器没有厂商键"，写成基线会让
            // 下一轮差分把全部现存键算成新键。没有基线时那一类候选整段不出，目录候选不受影响。
            let footprinted = if recorded {
                let vendor = collect_vendor_keys();
                if vendor.is_empty() {
                    log::write_log(
                        "warn",
                        "卸载前厂商键基线未记录：三个 Software 根都枚举不到（不写空基线，否则下轮差分全是假候选）",
                    );
                    false
                } else {
                    ownership::set_footprint(&mut own_doc, &app_id, &vendor, crate::engine::now_ms())
                }
            } else {
                false
            };
            if recorded || footprinted {
                if let Err(e) = ownership::save(&own_doc) {
                    log::write_log("warn", &format!("所有权事件落盘失败（不影响卸载）: {e}"));
                }
            }
        }
        log::flush_sync(); // 危险操作前刷盘
        let mut fell_back = false;
        let mut exit_code = match shell_run_wait(&exe, &args) {
            Ok(code) => code,
            Err(e) if used_silent => {
                log::write_log(
                    "info",
                    &format!("uninstall_run {display_name}: 静默卸载启动失败（{e}），自动回退原厂卸载界面"),
                );
                fell_back = true;
                exe = original.0.clone();
                run_original_ui()?
            }
            Err(e) => {
                // 非白名单且厂商串不可用时本来就走原厂界面，启动失败即如实报错（原行为）
                log::write_log("error", &format!("uninstall_run {display_name}: {e}"));
                return Err(e);
            }
        };
        if used_silent && !fell_back {
            let (meaning, fall_back) = classify_exit(exit_code);
            // 码表语义只对 MSI 成立；Inno/NSIS 的退出码不套这张表（见 classify_exit 注释）。
            let by_exit_code = fall_back && kind == "msi";
            if by_exit_code {
                log::write_log(
                    "info",
                    &format!("uninstall_run {display_name}: 静默卸载退出码 {exit_code}（{meaning}），自动回退原厂卸载界面"),
                );
                fell_back = true;
                exe = original.0.clone();
                exit_code = run_original_ui()?;
            } else {
                log::write_log(
                    "info",
                    &format!(
                        "uninstall_run {display_name}: 静默卸载退出码 {exit_code}（{meaning}），安装器 {kind} 不按退出码回退原厂界面"
                    ),
                );
            }
        }
        let (exit_meaning, _) = classify_exit(exit_code);

        // 进程监视（2026-09-28 用户拍板）：句柄退出 ≠ 卸载结束——继续轮询卸载键与
        // 卸载器家族进程，直到键消失或进程绝迹（上限 15 分钟）
        let (still_listed, timed_out) = watch_uninstaller(hive, &key_path, &exe);
        if still_listed {
            log::write_log(
                "warn",
                &format!(
                    "uninstall_run {display_name}: 卸载器退出（码 {exit_code}，监视{}）但卸载键仍在，原厂卸载可能未完成",
                    if timed_out { "超时" } else { "结束" }
                ),
            );
        } else {
            log::write_log("info", &format!("uninstall_run {display_name}: 卸载完成（码 {exit_code}）"));
        }
        Ok(json!({
            "exitCode": exit_code,
            "exitMeaning": exit_meaning,
            "silentSource": silent_source,
            "stillListed": still_listed,
            "installerKind": kind,
            "usedSilent": used_silent,
            "fellBack": fell_back,
            "message": if still_listed {
                if fell_back {
                    "静默卸载未完成，已回退原厂卸载界面；卸载器已退出但该程序仍在卸载列表中（可能未完成或已取消）".to_string()
                } else {
                    "卸载进程已结束，但该程序仍出现在卸载列表中（可能未完成或已取消）".to_string()
                }
            } else if fell_back {
                "静默卸载未完成，已自动回退原厂卸载界面并执行完毕".to_string()
            } else {
                format!("「{display_name}」的卸载器已执行完毕")
            },
            "_hive": hive_name,
        }))
    })
    .await;
    match res {
        Ok(Ok(data)) => json!({ "success": true, "data": data }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("卸载执行异常: {e}") }),
    }
}


#[cfg(test)]
pub(super) mod install_date_tier_tests {
    use super::install_date_from_epoch;

    /// 期望值全部用 `new Date(secs*1000).toISOString()` 独立算过一遍（不拿实现反推实现）
    #[test]
    fn epoch_换算与标准库一致() {
        let cases = [
            (1_609_459_200u32, "2021-01-01"),
            (1_000_000_000, "2001-09-09"),
            (1_582_934_400, "2020-02-29"), // 闰日
            (946_684_800, "2000-01-01"), // 千禧年
            (788_918_400, "1995-01-01"),
            (631_152_000, "1990-01-01"), // 下界含
        ];
        for (secs, want) in cases {
            assert_eq!(install_date_from_epoch(secs).as_deref(), Some(want), "secs={secs}");
        }
    }

    /// 「不可信」必须是 None，不能退成 1970-01-01 —— 那会被列表当成真实安装日期显示，
    /// 比空值更糟（用户会拿它判断"这程序多久没动了"）
    #[test]
    fn 不可信取值一律返回_none() {
        for secs in [0u32, 1, 86_399, 631_065_600 /* 1989-12-31 */, 4_133_980_800 /* 2101-01-01 */] {
            assert_eq!(install_date_from_epoch(secs), None, "secs={secs} 应判不可信");
        }
    }

    #[test]
    fn 两档顺序_装了安装日期值就不该退到键时间() {
        // 纯函数层能钉的只有这一半：调用方（enum_uninstall_root）先取本函数、
        // 拿不到才退 reg_key_last_write_date，且 installDateExact 反映来源。
        // 真机两档差异要看的证据是列表里同一程序「安装日期」与注册表键时间不一致时取前者。
        assert_eq!(install_date_from_epoch(1_609_459_200).as_deref(), Some("2021-01-01"));
        assert_eq!(install_date_from_epoch(0), None, "0 必须退回兜底档，否则 exact 标志会撒谎");
    }
}
