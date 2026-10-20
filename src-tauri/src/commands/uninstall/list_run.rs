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
    // civil_from_days 走 engine 唯一实现（P2-3 去重）：不引时区库、不加依赖（AGENTS §2 零新增依赖）
    let days = (secs / 86_400) as i64;
    let (y, m, d) = crate::engine::civil_from_days(days);
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
///
/// R2b-M01：折叠大小写只用 `to_ascii_lowercase`——`to_lowercase` 是 full mapping，
/// 会改变字节长度（`İ` U+0130 → `i`+U+0307，2→3 字节），它的索引拿去切原串会越界 panic。
pub(super) fn split_uninstall_cmd(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some((rest[..end].to_string(), rest[end + 1..].trim().to_string()));
    }
    let low = s.to_ascii_lowercase();
    if low.starts_with("msiexec") {
        // 前缀长度必须按实际命中的形态取：`MsiExec.exe /X{GUID}` 的 ".exe" 属于
        // 可执行文件名，不能漏进参数（旧实现固定切 7 字节，msiexec 会收到 ".exe /X…"）。
        let consumed = if low.starts_with("msiexec.exe") { "msiexec.exe".len() } else { "msiexec".len() };
        let rest = s.get(consumed..).unwrap_or_default().trim().to_string();
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

/// 卸载/修改执行面的统一准入（R2b-K01 + R2b-M02，v7.2 C05）。
///
/// 返回**解析后的绝对路径**，把「注册表原文 → ShellExecuteEx」之间的三种错误形态
/// 挡在执行之前（三条支路共用：正常静默 / 回退原厂界面 / 候选为 None 的原厂路径）：
/// 1. 宿主拒绝：cmd/powershell/mshta 等会把参数再解释一遍（复用 `QUIET_DENY_HOSTS`）；
/// 2. 路径形态：绝对路径原样放行；裸名只允许 `system_tool` 解析成功（msiexec → System32
///    真身）；相对路径/带目录名的裸名一律拒 —— 它们会落进 ShellExecute 的搜索序
///    （R2b-U01 真机探针裁决：**调用方 CWD 参与搜索序**，lpDirectory 只钉子进程 cwd）；
/// 3. 参数注入字符：`| & ; $ \` < >` 与换行在 ShellExecuteEx 下仍可能被目标二次解释。
///
/// 刻意**不**把 vendor 静默档的 `%VAR%` 成对规则平移过来：原厂串不做 shell 展开，
/// 且 `100%` 这类目录名会被误伤（R2b-M02 方案边界）。
pub(super) fn admit_uninstaller_exec(exe: &str, args: &str) -> Result<String, String> {
    let exe = exe.trim();
    if exe.is_empty() {
        return Err("卸载器路径为空".to_string());
    }
    let name = exe.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase();
    if QUIET_DENY_HOSTS.contains(&name.as_str()) {
        return Err(format!("{name} 是 shell/脚本宿主，参数会被二次解释，拒绝执行注册表原文"));
    }
    // 单引号是合法路径字符（Assassin's Creed 这类目录名），对 ShellExecuteEx 没有
    // 语法含义，不跟着 vendor 静默档一起拒——那一档的 `'` 检查保持原样。
    if exe.contains('"') || exe.contains('\0') {
        return Err("卸载器路径含引号或 NUL".to_string());
    }
    for c in ['<', '>', '|', '&', ';', '$', '`', '\n', '\r', '\0'] {
        if args.contains(c) {
            return Err(format!("参数含 {:?} 形态（重定向/管道/复合命令/变量替换）", c));
        }
    }
    let path = Path::new(exe);
    if path.is_absolute() {
        return Ok(exe.to_string());
    }
    if exe.contains('\\') || exe.contains('/') {
        return Err(format!("卸载器路径「{exe}」不是绝对路径，拒绝执行"));
    }
    crate::engine::systembin::system_tool(&name)
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| format!("卸载器「{name}」无法解析为系统工具：{e}"))
}

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

/// Inno vendor 串的 /SILENT 升级（HiBit 借鉴 v2 §2.4·选项②，2026-10-06 拍板）：
/// `/SILENT` → `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`，保留其余参数原序。
/// 只认独立的 `/SILENT` token（大小写不敏感，对齐 Inno 命令行语义）；
/// `/VERYSILENT` 里没有 `/S` 相邻序列，不会被再次命中，天然不重复升级。
/// 升级后**执行**失败仍走既有 fell_back → 原厂卸载界面，不在本函数处理；
/// 条件不满足（非 inno / 无该 token）→ 原样返回，即「退回选项①保持 vendor 原文」。
fn upgrade_inno_silent(kind: &str, exe: String, args: String) -> (String, String) {
    if !kind.eq_ignore_ascii_case("inno") {
        return (exe, args);
    }
    let mut upgraded = false;
    let tokens: Vec<String> = args
        .split_whitespace()
        .map(|t| {
            if t.eq_ignore_ascii_case("/SILENT") {
                upgraded = true;
                "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART".to_string()
            } else {
                t.to_string()
            }
        })
        .collect();
    if upgraded { (exe, tokens.join(" ")) } else { (exe, args) }
}

/// 静默命令裁决（B1）：厂商静默串优先于本地拼参数，但必须先过构造闸；
/// 构造失败或语义不明 → 记录原因并回退现有白名单派生（不永久放弃该程序的静默能力）。
/// vendor 串过闸后若为 Inno 且含 /SILENT，按 §2.4 升级为全静默（与白名单模板同级，
/// 补齐「vendor 优先」带来的静默档位降级口子）。
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
                    let (exe, args) = upgrade_inno_silent(kind, qe, qa);
                    return Some(SilentCandidate { exe, args, source: "vendor", vendor_reject: None })
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

/// 硬等待上界（毫秒）。审查 M-03：原实现 `INFINITE`，卸载器挂起（等 UAC 交互 /
/// 安装器自身卡死）会把 `spawn_blocking` 的 worker **永久**占住——而
/// `watch_uninstaller` 要等本函数返回才启动（调用点顺序），INFINITE 等于让监视永不开始。
pub(super) const UNINSTALLER_WAIT_TIMEOUT_MS: u32 = 10 * 60 * 1000;

/// 一次卸载从开始执行到监视结束的**总预算**（硬等待 + 监视 = 25 分钟）。
///
/// R2b-M04：两条上界各自正确不等于总上界被说出来——硬等待用满 10 分钟后若监视再给
/// 15 分钟，用户看到的是 25 分钟遮挡。监视 deadline 取「总预算 − 已耗时」，用尽立即
/// 返回并把真实耗时写进日志，不再让两个独立上界相乘成不可见的长尾。
pub(super) const UNINSTALL_TOTAL_BUDGET: std::time::Duration =
    std::time::Duration::from_millis(UNINSTALLER_WAIT_TIMEOUT_MS as u64 + 15 * 60 * 1000);

/// 监视剩余额度：总预算扣掉已耗时（> 总预算时为 0）。抽成纯函数便于直接断言。
fn watch_budget_remaining(waited: std::time::Duration) -> std::time::Duration {
    UNINSTALL_TOTAL_BUDGET.saturating_sub(waited)
}

/// `shell_run_wait` 的三种正常结局。
///
/// 为什么不用 `Err` 表达超时：调用点的 `Err(e) if used_silent` 分支语义是
/// 「静默卸载**启动失败** → 回退原厂卸载界面」。超时若也走 `Err`，会在卸载器其实
/// 还在跑的时候**重拉一遍界面**（对 NSIS/Inno 等于把用户刚点的取消/等待无视掉），
/// 比阻塞更糟。所以超时必须是独立信号，由上层转入 `watch_uninstaller` 轮询口径。
///
/// R9（2026-10-15）：`ElevationDeclined`（用户拒了 UAC）同理独立——它既不是
/// 「启动失败」（重拉界面 = 无视用户的拒绝），也不落「可能还在跑」的超时口径，
/// 而是「卸载器**从未启动**」。
pub(super) enum UninstallerWait {
    /// 拿到退出码。
    Exited(u32),
    /// 硬等待超时，**进程未被终止**——退出码未知，卸载是否完成未知。
    TimedOut,
    /// 用户在 UAC 上拒绝了提权（`ERROR_CANCELLED`）：卸载器从未启动（R9，2026-10-15）。
    ElevationDeclined,
}

/// 一次 `shell_run_wait` 的落地信息：启动到的进程 pid + 结局。
///
/// pid 是 R2b-M04 家族判定的输入——监视循环只把「本次启动的进程或其子孙」算作
/// 自己的卸载器，系统里别的 msiexec.exe 不算。
pub(super) struct ShellRunResult {
    pub(super) pid: u32,
    pub(super) outcome: UninstallerWait,
}

/// 该启动错误是不是「用户拒了 UAC」（`ERROR_CANCELLED` = 1223）——R9（2026-10-15）。
/// 单独成函数是为了可被合成 HRESULT 直测（真弹 UAC 无法自动化）。
/// HRESULT→win32 的折叠引 `engine::native::win32_of` 为口径真源（`0x800704C7` → 1223）。
fn is_elevation_declined(e: &windows::core::Error) -> bool {
    crate::engine::native::win32_of(e) == windows::Win32::Foundation::ERROR_CANCELLED.0
}

/// ShellExecuteEx 启动卸载器并等待退出，最长等 `UNINSTALLER_WAIT_TIMEOUT_MS`。
/// 不加 RUNAS verb：卸载器自带 manifest 会按需弹 UAC（对齐 Trim 按需提权模型）。
///
/// 超时后**不** `TerminateProcess`：厂商卸载器被强杀会留下半卸载状态（注册表键已删、
/// 文件没删干净），比「如实报未知」更难恢复。此时只关句柄放行，上层继续走
/// `watch_uninstaller` 轮询卸载键与卸载器进程家族，由它给出真实结论。
pub(super) unsafe fn shell_run_wait(exe: &str, args: &str) -> Result<ShellRunResult, String> {
    use windows::Win32::Foundation::WAIT_TIMEOUT;
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::core::PCWSTR;

    // R2b-K01 第二道（fail-closed 单一咽喉）：只接受绝对路径。裸名会落进 ShellExecute
    // 的「调用方 CWD → Windows → System32 → PATH」搜索序，而便携档 exe 同级目录可写、
    // 且常是调用方 CWD。生产调用点必须先把 exe 过 `admit_uninstaller_exec`；这里再拦一道，
    // 防未来新增调用点直接传注册表原文。
    if !Path::new(exe).is_absolute() {
        return Err(format!("拒绝以非绝对路径启动卸载器：{exe}"));
    }
    let file = to_wide(exe);
    let params = if args.is_empty() { None } else { Some(to_wide(args)) };
    // R5（2026-10-15）→ R2b-K01（v7.2 C05）修正：工作目录钉到系统目录。
    // R2b-U01 真机探针裁决：lpDirectory **不参与裸名文件解析**（只钉子进程 cwd），
    // 旧注释「同时是相对 lpFile 的解析基准」与实测矛盾，已删。真正要防的是：
    // ① 子进程以可写目录为 cwd（相对路径读写会落进用户可写区）；
    // ② 便携档 exe 同级目录常是调用方 CWD，而 CWD 参与 ShellExecute 的裸名搜索序。
    // 钉到 SystemRoot 同时收口这两条；裸名本身由上面的 fail-closed 闸拒绝。
    let workdir = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    let dir_w = to_wide(&workdir.to_string_lossy());
    let mut sei: SHELLEXECUTEINFOW = core::mem::zeroed();
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile = PCWSTR(file.as_ptr());
    if let Some(p) = &params {
        sei.lpParameters = PCWSTR(p.as_ptr());
    }
    sei.lpDirectory = PCWSTR(dir_w.as_ptr());
    sei.nShow = 1; // SW_SHOWNORMAL
    if let Err(e) = ShellExecuteExW(&mut sei) {
        // R9（2026-10-15）：用户在 UAC 上点「否」时 ShellExecuteExW 以
        // ERROR_CANCELLED（1223，折成 0x800704C7）失败。这是**独立结局**不是启动失败：
        // 走 Err 会被上层 `Err(e) if used_silent` 接去重拉原厂界面（用户拒一次又被弹一次）。
        // 判据必须落在任何 map_err 之前（之后只剩格式化文本）。
        if is_elevation_declined(&e) {
            return Ok(ShellRunResult { pid: 0, outcome: UninstallerWait::ElevationDeclined });
        }
        return Err(format!("启动卸载器失败: {e}"));
    }
    let h = sei.hProcess;
    if h.is_invalid() {
        // 拿不到句柄（目标拒绝 NOCLOSEPROCESS 等）：无法等待，如实上报
        return Err("卸载器已启动但无法等待其完成（未返回进程句柄）".to_string());
    }
    let pid = windows::Win32::System::Threading::GetProcessId(h);
    let r = WaitForSingleObject(h, UNINSTALLER_WAIT_TIMEOUT_MS);
    if r == WAIT_TIMEOUT {
        // 只关句柄，不杀进程（见函数注释「超时后不 TerminateProcess」的理由）
        let _ = windows::Win32::Foundation::CloseHandle(h);
        return Ok(ShellRunResult { pid, outcome: UninstallerWait::TimedOut });
    }
    let mut code: u32 = 0;
    let _ = GetExitCodeProcess(h, &mut code);
    let _ = windows::Win32::Foundation::CloseHandle(h);
    Ok(ShellRunResult { pid, outcome: UninstallerWait::Exited(code) })
}

// ==================== 卸载进程监视（2026-09-28 用户拍板） ====================
// Inno/NSIS 卸载器会把自身复制到临时目录后由副本继续（unins000.exe → au_.exe /
// un_a.exe），或经 UAC 提权拉起新进程——「启动句柄退出」≠「卸载结束」。原实现
// wait 提前返回，残留扫描在卸载器还在跑时就执行，只扫出一条“卸载键还在”。
// 口径：先等句柄退出，再 1s 间隔轮询（上限 15 分钟）：
//   · 卸载键消失 → 卸载完成；
//   · 卸载器家族进程全部退出且连续 3 轮稳定 → 结束（用户取消 / 静默完成）；
//   · 超时 → 如实返回键的现状。

/// 全系统进程快照（名称小写 + 父子 pid；Toolhelp32，与 native-scanner ffi 同口径）。
///
/// 补 `th32ParentProcessID` 是 R2b-M04 的家族判定输入：`msiexec.exe` 之类通用引擎
/// 只有能沿父链走到本次启动的 pid 才算「自己的卸载器」。
pub(super) struct ProcEntry {
    pub(super) pid: u32,
    pub(super) ppid: u32,
    pub(super) name: String,
}

pub(super) fn process_snapshot() -> Vec<ProcEntry> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut out = Vec::new();
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
                out.push(ProcEntry {
                    pid: pe.th32ProcessID,
                    ppid: pe.th32ParentProcessID,
                    name: String::from_utf16_lossy(&pe.szExeFile[..len]).to_ascii_lowercase(),
                });
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snap);
    }
    out
}

/// 该 pid 是否属于本次卸载器家族：等于 launched pid，或沿父链能走到它。
/// 上界 32 层 + 自环/零父兜底，防止异常快照把监视循环拖死。
fn in_uninstaller_family(pid: u32, launched_pid: u32, parents: &std::collections::HashMap<u32, u32>) -> bool {
    if launched_pid == 0 {
        return false;
    }
    if pid == launched_pid {
        return true;
    }
    let mut cur = pid;
    for _ in 0..32 {
        let Some(&ppid) = parents.get(&cur) else { return false };
        if ppid == launched_pid {
            return true;
        }
        if ppid == 0 || ppid == cur {
            return false;
        }
        cur = ppid;
    }
    false
}

/// 卸载器家族进程判定：启动的 exe 本名 + Inno/NSIS 临时副本；MSI 引擎只在同家族时算。
///
/// R2b-M04：旧实现把系统里**任何** `msiexec.exe` 都当成自己的卸载器——Windows 更新
/// 之类同时跑着的另一个 msiexec 会让监视永不结束（假「仍在运行」）。家族关系由调用方
/// 从 Toolhelp 父链算好注入，本函数保持纯函数（可直接单测，不读系统状态）。
pub(super) fn is_uninstaller_process(name: &str, launched: &str, in_family: bool) -> bool {
    if name == launched {
        // 同名进程也要有家族关系：另一款程序恰好也叫 unins000.exe 不算我们这条链
        return in_family;
    }
    (name == "msiexec.exe" && in_family)
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
///
/// `launched_pid` = 本次真正启动的卸载器 pid（`ShellRunResult` 回传）；家族进程必须
/// 能从它（或它已退出的子孙）沿父链走到，才认作「自己的卸载器」（R2b-M04）。
/// `waited` = 从开始执行到此刻的已耗时，用于把总预算显式化。
pub(super) fn watch_uninstaller(
    hive: windows::Win32::System::Registry::HKEY,
    key_path: &str,
    launched_exe: &str,
    launched_pid: u32,
    waited: std::time::Duration,
) -> (bool, bool) {
    let launched = launched_exe
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let remaining = watch_budget_remaining(waited);
    if remaining.is_zero() {
        // 总预算已在硬等待（含回退）里用尽：不再进入轮询，如实报「超时」。
        log::write_log(
            "warn",
            &format!(
                "卸载监视未启动：已耗时 {} ms，超出总预算 {} ms",
                waited.as_millis(),
                UNINSTALL_TOTAL_BUDGET.as_millis()
            ),
        );
        return (crate::engine::native::reg_key_exists(hive, key_path), true);
    }
    let deadline = std::time::Instant::now() + remaining;
    let mut stable = 0u32;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        // 键消失 = 卸载完成（最早、最可靠的完成信号）
        if !crate::engine::native::reg_key_exists(hive, key_path) {
            return (false, false);
        }
        let snap = process_snapshot();
        let parents: std::collections::HashMap<u32, u32> =
            snap.iter().map(|e| (e.pid, e.ppid)).collect();
        let any = snap.iter().any(|e| {
            is_uninstaller_process(&e.name, &launched, in_uninstaller_family(e.pid, launched_pid, &parents))
        });
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
        let run_started = std::time::Instant::now();
        let run_original_ui = || -> Result<(Option<u32>, u32), String> {
            log::flush_sync();
            // R2b-M02：原厂界面支路同样执行注册表原文，必须与静默支路共用同一准入函数。
            // 被拒时不执行、如实报错并指路系统「已安装的应用」，不静默跳过当成功。
            let admitted = admit_uninstaller_exec(&original.0, &original.1).map_err(|e| {
                let msg = format!(
                    "uninstall_run {display_name}: 原厂卸载命令被准入闸拒绝（{e}），未执行；请改用系统「已安装的应用」卸载"
                );
                log::write_log("warn", &msg);
                msg
            })?;
            shell_run_wait(&admitted, &original.1)
                .map_err(|e| {
                    log::write_log("error", &format!("uninstall_run {display_name}: 回退原厂卸载界面启动失败: {e}"));
                    e
                })
                .and_then(|r| match r.outcome {
                    UninstallerWait::Exited(code) => Ok((Some(code), r.pid)),
                    // 回退界面同样等不到：退出码未知，不能伪造成 0（会被当成卸载成功）
                    UninstallerWait::TimedOut => Ok((None, r.pid)),
                    // R9（2026-10-15）：用户在回退界面的 UAC 上拒绝 = 卸载器从未启动。
                    // **绝不能映成 None**（None 的下游是「超时 / 可能还在跑」）。用 Err
                    // 让整条命令如实判失败——与「超时不用 Err」的裁定不冲突：那条的理由
                    // 是 Err 会被主 match 接去重拉界面，而这里已经在界面路径上、无界面可再拉。
                    UninstallerWait::ElevationDeclined => {
                        let msg = format!("uninstall_run {display_name}: 用户取消了权限请求（原厂卸载界面未启动）");
                        log::write_log("warn", &msg);
                        Err(msg)
                    }
                })
        };
        // 原「卸载前写所有权档案 / 厂商键足迹基线」已随「机-wide 扫描整条退役」删除：
        // 那是应用数据遗留链（uninstall:orphan-scan）的唯一写入点，档案已无读者。
        log::flush_sync(); // 危险操作前刷盘
        let mut fell_back = false;
        // 三条支路（正常静默 / 回退原厂界面 / 候选=None 的原厂路径）共用
        // `admit_uninstaller_exec`：注册表原文一律先解析/过闸，再进 ShellExecuteEx 咽喉。
        let primary_exe = exe.clone();
        let primary_args = args.clone();
        let run_primary = || -> Result<ShellRunResult, String> {
            let admitted = admit_uninstaller_exec(&primary_exe, &primary_args).map_err(|e| {
                let msg = format!("卸载命令被准入闸拒绝（{e}），未执行");
                log::write_log("warn", &format!("uninstall_run {display_name}: {msg}"));
                msg
            })?;
            // 本闭包整体位于 spawn_blocking 的 unsafe 块内，无需再包一层
            shell_run_wait(&admitted, &primary_args)
        };
        // `exit_code` 是 Option：硬等待超时时退出码未知（UninstallerWait::TimedOut），
        // 此时不套 classify_exit 码表、也不触发按码回退——直接转入 watch_uninstaller
        // 如实判定。前端 `uninstall.js` 已能安全消费 null（`?? '未知'`）。
        // launched_pid = 本次真正启动的 pid（家族判定与总预算都要用它）。
        let (mut exit_code, mut launched_pid): (Option<u32>, u32) = match run_primary() {
            Ok(r) => {
                let code = match r.outcome {
                    UninstallerWait::Exited(code) => Some(code),
                    UninstallerWait::TimedOut => {
                        // 超时不是「启动失败」：绝不重拉原厂界面，交给下面的进程监视收尾。
                        log::write_log(
                            "warn",
                            &format!(
                                "uninstall_run {display_name}: 等待卸载器 {UNINSTALLER_WAIT_TIMEOUT_MS} ms 仍未退出（未强杀），退出码未知，转入进程监视"
                            ),
                        );
                        None
                    }
                    // R9（2026-10-15）：用户在 UAC 上拒绝了权限请求——卸载器**从未启动**。
                    // 独立回执（exitCode 与超时同为 null，靠 `elevationDeclined` 区分，前端必须
                    // 在该 null 分支之前认领它——J6）。三条硬约束：① 早退，不得走到
                    // watch_uninstaller（「用户自己拒了」会被说成「卸载器还在跑」）；② 不落回
                    // 超时口径；③ fellBack 保持 false（前端会据此播「已回退原厂卸载界面并执行完毕」）。
                    UninstallerWait::ElevationDeclined => {
                        log::write_log(
                            "warn",
                            &format!("uninstall_run {display_name}: 用户取消了权限请求（卸载器未启动）"),
                        );
                        return Ok(json!({
                            "exitCode": null,
                            "exitMeaning": "用户取消了权限请求",
                            "silentSource": silent_source,
                            "stillListed": true,
                            "installerKind": kind,
                            "usedSilent": used_silent,
                            "fellBack": false,
                            "elevationDeclined": true,
                            "message": "卸载已取消：系统权限请求被拒绝，卸载器没有启动。",
                        }));
                    }
                };
                (code, r.pid)
            }
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
                // 非白名单且厂商串不可用时本来就走原厂界面，启动失败即如实报错；
                // 准入拒绝也落这里（不执行），并指路系统卸载入口。
                let msg = format!("{e}；可改用系统「已安装的应用」卸载");
                log::write_log("error", &format!("uninstall_run {display_name}: {msg}"));
                return Err(msg);
            }
        };
        if used_silent && !fell_back {
            let (meaning, fall_back) = exit_code.map(classify_exit).unwrap_or(("", false));
            // 码表语义只对 MSI 成立；Inno/NSIS 的退出码不套这张表（见 classify_exit 注释）。
            let by_exit_code = fall_back && kind == "msi";
            if by_exit_code {
                let code = exit_code.unwrap_or(0);
                log::write_log(
                    "info",
                    &format!("uninstall_run {display_name}: 静默卸载退出码 {code}（{meaning}），自动回退原厂卸载界面"),
                );
                fell_back = true;
                exe = original.0.clone();
                let (fallback_code, pid) = run_original_ui()?;
                launched_pid = pid;
                exit_code = fallback_code;
            } else {
                log::write_log(
                    "info",
                    &format!(
                        "uninstall_run {display_name}: 静默卸载退出码 {}（{meaning}），安装器 {kind} 不按退出码回退原厂界面",
                        exit_code.map(|c| c.to_string()).unwrap_or_else(|| "未知".into())
                    ),
                );
            }
        }
        // 超时（exit_code == None）时不给伪语义：空串让前端 `d.exitMeaning ? ... : ''` 走空分支
        let (exit_meaning, _) = exit_code.map(classify_exit).unwrap_or(("", false));

        // 进程监视（2026-09-28 用户拍板）：句柄退出 ≠ 卸载结束——继续轮询卸载键与
        // 卸载器家族进程，直到键消失或进程绝迹（总预算扣除已耗时后剩余部分）
        let waited = run_started.elapsed();
        let watch_started = std::time::Instant::now();
        let (still_listed, timed_out) = watch_uninstaller(hive, &key_path, &exe, launched_pid, waited);
        let watch_ms = watch_started.elapsed().as_millis();
        let total_ms = run_started.elapsed().as_millis();
        log::write_log(
            "info",
            &format!(
                "uninstall_run {display_name}: 进程监视{}（监视 {watch_ms} ms / 本次卸载总计 {total_ms} ms，总预算 {} ms）",
                if timed_out { "超时结束" } else { "结束" },
                UNINSTALL_TOTAL_BUDGET.as_millis()
            ),
        );
        let code_txt = exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "未知".to_string());
        if still_listed {
            log::write_log(
                "warn",
                &format!(
                    "uninstall_run {display_name}: 卸载器退出（码 {code_txt}，监视{}）但卸载键仍在，原厂卸载可能未完成",
                    if timed_out { "超时" } else { "结束" }
                ),
            );
        } else {
            log::write_log("info", &format!("uninstall_run {display_name}: 卸载完成（码 {code_txt}）"));
        }
        Ok(json!({
            "exitCode": exit_code,
            "exitMeaning": exit_meaning,
            "silentSource": silent_source,
            "stillListed": still_listed,
            "installerKind": kind,
            "usedSilent": used_silent,
            "fellBack": fell_back,
            "message": if exit_code.is_none() {
                // 硬等待超时的口径：卸载器**可能仍在运行**，不能报「已结束」也不能报「已完成」
                if still_listed {
                    "等待卸载器超时（未强制终止），卸载器可能仍在运行；该程序仍在卸载列表中，卸载状态未知".to_string()
                } else {
                    "等待卸载器超时（未强制终止），卸载键已消失但未能确认卸载器退出码".to_string()
                }
            } else if still_listed {
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

#[cfg(test)]
mod wait_outcome_tests {
    use super::*;

    /// R9（2026-10-15）：`ERROR_CANCELLED` 的折叠判据 —— `HRESULT_FROM_WIN32(1223)` =
    /// `0x800704C7`，低位段必须还原成 1223。合成 HRESULT 直测，不需要真弹 UAC（无法自动化）。
    #[test]
    fn 拒权判据_合成_hresult_低位折叠正确() {
        let declined = windows::core::Error::from_hresult(windows::core::HRESULT(0x8007_04C7_u32 as i32));
        assert!(is_elevation_declined(&declined), "0x800704C7（ERROR_CANCELLED=1223）必须判成用户取消");
        // 反向：别的启动失败码不许误判（0x80070005 = ERROR_ACCESS_DENIED）
        let denied = windows::core::Error::from_hresult(windows::core::HRESULT(0x8007_0005_u32 as i32));
        assert!(!is_elevation_declined(&denied), "ACCESS_DENIED 不是用户取消——它仍要走原有的启动失败路径");
    }

    /// R9/J6（2026-10-15）接线钉桩：拒权必须在**三个 match 臂**与**前端认领顺序**里
    /// 同时落地——臂缺一个 = 编译器红（枚举非穷尽）；顺序错一个 = 「用户拒了」被播成
    /// 「还在跑」或「已回退并执行完毕」。真机 UAC 交互无法自动化，这里断源码形态。
    #[test]
    fn 拒权回执的三个臂与前端认领顺序() {
        let code = include_str!("list_run.rs");
        // ① 主 match：declined 臂必须早退（return Ok）且回执带独立标记。
        // 锚点用 concat! 拼：本测试源码也会被 include_str! 扫进去，整串字面量会自命中。
        let decl_anchor = concat!("UninstallerWait", "::ElevationDeclined => {");
        let used_silent_anchor = concat!("Err(e) if ", "used_silent");
        let marker = concat!("\"elevationDeclined\"", ": true");
        // 主 match 的 declined 臂在回退闭包之后（rfind 取到它）；两处同名臂因此可区分
        let at = code
            .rfind(decl_anchor)
            .expect("主 match 缺 declined 臂（枚举非穷尽本会编译红，这里防「补了臂却让它往下走」）");
        let marker_at = code[at..].find(marker).expect("回执缺 elevationDeclined 标记（前端无从认领）");
        let body = &code[at..at + marker_at + marker.len()];
        assert!(body.contains("return Ok(json!"), "declined 臂必须早退（不得落到 watch_uninstaller）");
        assert!(!body.contains("fell_back = true"), "declined 臂不得置 fell_back");
        assert!(
            code[at..].find(used_silent_anchor).map(|i| i > marker_at).unwrap_or(false),
            "declined 臂必须排在 used_silent 臂之前（早退，不许被「启动失败→回退界面」接走）"
        );
        // ② 回退闭包：declined 必须映成 Err —— 映成 None 会把「用户拒了」播成「超时了」
        assert!(
            code.contains(decl_anchor) && code.contains("用户取消了权限请求（原厂卸载界面未启动）"),
            "回退闭包的 declined 臂不见了（或没映成 Err）"
        );
        // ③ uninstall_modify 第三臂
        let ru = include_str!("residue_update.rs");
        assert!(
            ru.contains("用户取消了权限请求（{label}未启动）"),
            "uninstall_modify 缺 declined 臂（跑进 TimedOut 口径会报「状态未知」）"
        );
        // ④ 前端：认领分支必须排在 exitCode==null 分支之前（新回执 exitCode 同为 null）
        let js = include_str!("../../../../src/scripts/uninstall.js");
        let decl = js.find("d.elevationDeclined").expect("uninstall.js 没认领 elevationDeclined");
        let nullb = js.find("d.exitCode == null").expect("找不到 null 分支");
        assert!(decl < nullb, "拒权分支必须排在 null 分支之前，否则被「等待卸载器超时」吞掉");
    }

    /// R5（2026-10-15）真机探针（`#[ignore]`，发版前实跑）：`shell_run_wait` 设的
    /// `lpDirectory` 必须真的生效——用 cmd 把自身工作目录打到临时文件里读回。
    /// C05 起 `shell_run_wait` 只收绝对路径（fail-closed），探针按生产形态经 system_tool。
    /// 反向对照：若结果恰好等于测试进程的 cwd，说明钉根没生效（继承的就是调用者 cwd）。
    #[cfg(windows)]
    #[test]
    #[ignore = "真机探针：真实启动一个子进程观察工作目录"]
    fn lpdirectory_钉根_真机探针() {
        let probe = std::env::temp_dir().join(format!("trim-cwd-probe-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&probe);
        let args = format!("/c cd > \"{}\"", probe.display());
        let cmd = crate::engine::systembin::system_tool("cmd.exe").expect("cmd.exe 必须解析成功");
        let r = unsafe { shell_run_wait(cmd.to_string_lossy().as_ref(), &args) }.expect("cmd 必须能启动");
        assert!(matches!(r.outcome, UninstallerWait::Exited(0)), "cmd /c 应正常退出");
        let got = std::fs::read_to_string(&probe).expect("cmd 没写出 cwd —— lpDirectory 可能没生效");
        let _ = std::fs::remove_file(&probe);
        let got = got.trim().trim_end_matches('\\').to_lowercase();
        // C08 双轨后 app_data_dir() 在 lib 单测态是 `/` 分隔的构造路径，而子进程报回的
        // cwd 恒为 `\` 形态——两边都归一到 `\` 再比（真实数据根天然就是 `\`，不受影响）
        let got = got.replace('/', "\\");
        // C05/R2b-K01：工作目录已从数据目录改钉 %SystemRoot%（可写目录不得成为 cwd）
        let want = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let want = want.replace('/', "\\");
        let want = want.trim_end_matches('\\').to_lowercase();
        assert_eq!(got, want, "子进程工作目录必须等于 %SystemRoot%（C05：可写目录不得成为 cwd）");
        // 反向对照：若没设 lpDirectory，子进程会继承本测试进程的 cwd——两者不同才有对照意义
        let here = std::env::current_dir().unwrap_or_default();
        assert_ne!(
            want,
            here.to_string_lossy().trim_end_matches('\\').to_lowercase(),
            "%SystemRoot% 与测试进程 cwd 恰好相同，本探针失去对照意义（换一台机器复核）"
        );
    }

    /// R2b-U01（2026-10-20 取证；2026-10-21 C05 修复后降格为**回归哨兵**）真机探针：
    /// 产品层不再产裸名之后，本探针只钉两件事：
    /// 1. 绕开准入直接给咽喉裸名 ⇒ fail-closed 拒绝（新增调用点若传注册表原文会当场失败）；
    /// 2. 准入把 `msiexec.exe` 解析到 `%SystemRoot%\System32` 真身，数据根里的同名替身
    ///    **不得被选中**（R2b-K01 的危害通道已被绝对路径收口）。
    /// 2026-10-20 首轮实测已裁决：lpDirectory 只钉工作目录、不参与裸名文件解析，
    /// ShellExecute 的裸名搜索序里**调用方 CWD 参与**——这正是 K01 改走 PINNED 的理由。
    /// 不真实启动 msiexec：真身会触发提权决策，探针不该在人工执行时弹 UAC。
    #[cfg(windows)]
    #[test]
    #[ignore = "真机探针：检查准入解析结果与数据根同名替身的相对位置"]
    fn r2b_u01_裸名解析序_真机探针() {
        let workdir = crate::engine::paths::app_data_dir();
        std::fs::create_dir_all(&workdir).expect("建测试数据根失败");
        let standin = workdir.join("msiexec.exe");
        std::fs::write(&standin, b"r2b-u01-standin").expect("写数据根替身失败");
        let args = "/x {00000000-0000-0000-0000-000000000000} /qn";

        // 负向样本走变量绑定：I 组门禁禁的是「直接拿字面量进咽喉」，这里要证明的正是
        // 裸名（即使只经变量绕一圈）也必须在 fail-closed 闸前被拒。
        let bare_name = "msiexec.exe";
        let bare = unsafe { shell_run_wait(bare_name, args) };
        assert!(
            bare.is_err(),
            "裸名必须被 fail-closed 咽喉拒绝（产品层不得再产裸名；数据根替身更不许有机会被解析）"
        );

        let resolved = admit_uninstaller_exec("msiexec.exe", args).expect("PINNED 内的 msiexec 必须解析成功");
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let sys32 = std::path::Path::new(&sysroot).join("System32");
        assert!(
            std::path::Path::new(&resolved).starts_with(&sys32),
            "msiexec 必须解析到 %SystemRoot%\\System32 真身，实得 {resolved}"
        );
        assert_ne!(
            std::path::Path::new(&resolved),
            standin.as_path(),
            "数据根同名替身不得被选中（R2b-K01 回归）"
        );
        println!("裁决：裸名被拒；msiexec 解析到 {resolved}（数据根替身未被选中）");

        // 清场（尽力而为；lib 测试根在 target/ 内，漏网也会随 cargo clean 消失）
        let _ = std::fs::remove_file(&standin);
    }
}

#[cfg(test)]
mod exec_surface_tests {
    use super::*;

    /// R2b-M01：`to_lowercase` 是 full mapping（`İ` U+0130 → i+U+0307，2→3 字节），
    /// 它的索引拿去切原串会越界。ASCII-only 折叠保持字节长度，索引与 `s` 同源。
    #[test]
    fn m01_大小写折叠不改变字节下标() {
        assert_eq!(
            split_uninstall_cmd("İ.exe /S"),
            Some(("İ.exe".to_string(), "/S".to_string())),
            "全大写映射改变长度时不得 panic，且 exe 段必须切对"
        );
        assert_eq!(
            split_uninstall_cmd(r"C:\İ\myapp.exe /S"),
            Some((r"C:\İ\myapp.exe".to_string(), "/S".to_string())),
            "非 ASCII 字符出现在 .exe 之前同样不得错位"
        );
    }

    /// K01 坐标之一：msi 分支的 ".exe" 属于可执行文件名，不能漏进参数。
    #[test]
    fn k01_msiexec_exe_不得漏进参数() {
        assert_eq!(
            split_uninstall_cmd("MsiExec.exe /X{1D180B6A-C6AE-4D6E-A2A8-000000001001}"),
            Some(("msiexec.exe".to_string(), "/X{1D180B6A-C6AE-4D6E-A2A8-000000001001}".to_string()))
        );
        assert_eq!(
            split_uninstall_cmd("msiexec /I{Foo}"),
            Some(("msiexec.exe".to_string(), "/I{Foo}".to_string())),
            "不带 .exe 的写法也应只剥掉工具名"
        );
    }

    /// K01：裸名只允许落在 PINNED 白名单里（msiexec → System32 真身），返回绝对路径。
    #[test]
    fn k01_准入把_msiexec_解析到_system32() {
        let p = admit_uninstaller_exec("msiexec.exe", "/x {00000000-0000-0000-0000-000000000000} /qn")
            .expect("PINNED 内的 msiexec 必须能解析");
        assert!(Path::new(&p).is_absolute(), "准入必须返回绝对路径：{p}");
        let low = p.to_ascii_lowercase();
        assert!(low.contains("system32") && low.ends_with("msiexec.exe"), "必须落到 System32 真身：{p}");
    }

    /// K01：绝对路径原样放行；裸名未登记 / 带目录名的相对路径一律拒。
    #[test]
    fn k01_裸名与相对路径一律拒绝() {
        assert_eq!(
            admit_uninstaller_exec(r"C:\Program Files\App\unins000.exe", "/S").unwrap(),
            r"C:\Program Files\App\unins000.exe",
            "绝对路径原样放行（存在性由执行失败如实回执，准入不越权预检）"
        );
        assert!(admit_uninstaller_exec("evil-uninstaller.exe", "").is_err(), "未登记者不得解析");
        assert!(admit_uninstaller_exec(r"subdir\unins000.exe", "").is_err(), "带目录名的相对路径会落进搜索序");
        assert!(admit_uninstaller_exec(r".\unins000.exe", "").is_err(), ".\\ 形态同样不是绝对路径");
    }

    /// M02：原厂/厂商串来自可写注册表，宿主机与注入字符必须在执行前拒。
    #[test]
    fn m02_宿主与注入字符一律拒绝() {
        let e = admit_uninstaller_exec("cmd.exe", "/c calc.exe").unwrap_err();
        assert!(e.contains("宿主"), "拒因要点名宿主风险：{e}");
        assert!(
            admit_uninstaller_exec(r"C:\Windows\System32\cmd.exe", "/c calc.exe").is_err(),
            "绝对路径形态的宿主机同样拒（判据看基名）"
        );
        for args in ["/S & calc.exe", "/S | calc", "/S > out.txt", "/S ; calc", "/S $x", "/S `calc`"] {
            assert!(admit_uninstaller_exec(r"C:\Apps\unins000.exe", args).is_err(), "注入形态必须拒：{args}");
        }
        // 反向对照：普通参数不得被误伤（这是原厂界面支路的主要流量）
        assert!(admit_uninstaller_exec(r"C:\Apps\unins000.exe", "/SILENT /LANG=zh /NOICONS").is_ok());
        // 单引号路径是合法文件名，不得跟着 vendor 静默档一起误伤
        assert!(admit_uninstaller_exec(r"C:\Program Files\Assassin's Creed\uninstall.exe", "/S").is_ok());
    }

    /// M04：系统里别的 msiexec.exe 不算自己的卸载器；Inno/NSIS 临时副本保留。
    #[test]
    fn m04_微软安装引擎只认本家族() {
        assert!(
            !is_uninstaller_process("msiexec.exe", "unins000.exe", false),
            "系统里任何 msiexec 都算自己的卸载器 = 监视永不结束（R2b-M04）"
        );
        assert!(is_uninstaller_process("msiexec.exe", "unins000.exe", true));
        assert!(is_uninstaller_process("unins000.exe", "unins000.exe", true), "本次启动的进程自己算");
        assert!(!is_uninstaller_process("unins000.exe", "unins000.exe", false), "同名但无家族关系不算");
        assert!(is_uninstaller_process("au_.exe", "unins000.exe", false), "Inno 临时副本保留无条件");
    }

    /// M04：父链遍历识别子孙、对环/自环/零父有界收敛。
    #[test]
    fn m04_父链遍历识别子孙且有界() {
        use std::collections::HashMap;
        let mut p: HashMap<u32, u32> = HashMap::new();
        p.insert(100, 1); // launched → explorer
        p.insert(200, 100); // 子
        p.insert(300, 200); // 孙
        p.insert(400, 1); // 无关进程
        assert!(in_uninstaller_family(100, 100, &p));
        assert!(in_uninstaller_family(200, 100, &p));
        assert!(in_uninstaller_family(300, 100, &p));
        assert!(!in_uninstaller_family(400, 100, &p));
        assert!(!in_uninstaller_family(999, 100, &p), "快照里没有的 pid 直接 false");
        assert!(!in_uninstaller_family(7, 0, &p), "launched_pid=0（未启动成功）不得把任何进程算进家族");

        let mut cyc: HashMap<u32, u32> = HashMap::new();
        cyc.insert(1, 2);
        cyc.insert(2, 1);
        cyc.insert(3, 3);
        assert!(!in_uninstaller_family(1, 99, &cyc), "父链成环不得死循环");
        assert!(!in_uninstaller_family(3, 99, &cyc), "自环不得死循环");
    }

    /// M04：总预算 = 硬等待 + 监视；监视额度 = 总预算 − 已耗时，用尽为 0。
    #[test]
    fn m04_总预算等于两段上界之和且扣减已耗时() {
        assert_eq!(
            UNINSTALL_TOTAL_BUDGET.as_millis(),
            UNINSTALLER_WAIT_TIMEOUT_MS as u128 + 15 * 60 * 1000,
            "总预算必须显式等于两段上界之和（25 分钟），不得只存在于注释里"
        );
        assert_eq!(
            watch_budget_remaining(std::time::Duration::from_secs(600)),
            std::time::Duration::from_secs(900),
            "硬等待用满 10 分钟后，监视只剩 15 分钟"
        );
        assert!(watch_budget_remaining(std::time::Duration::from_secs(1500)).is_zero());
        assert!(watch_budget_remaining(std::time::Duration::from_secs(1600)).is_zero(), "超预算饱和为 0");
    }
}
