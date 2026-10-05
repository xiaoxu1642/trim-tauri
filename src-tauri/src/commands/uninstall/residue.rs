//! 残留扫描与残留执行（uninstall:residue-scan / :residue-execute）。
//!
//! 名称阈值表（NAME_MIN_*）与产出上限是本域判据；固定系统侧痕反查（U-2）只读。
//! 执行侧安全口径：只认本次会话快照里的 kind+target 组，删除一律
//! 先过 `engine::protect::is_path_protected` + 回收站优先，**不做永久删除兜底**；
//! 注册表先 export 备份再删，备份失败整项跳过。

use crate::engine::{delete_manifest, guard, log, protect, sysinfo};
use crate::engine::reg_backup::write_reg_backup_seal;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::WebviewWindow;
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use super::helpers::*;
use super::appx::*;
use super::list_run::*;
// A1 服务键窄口子：判据只在 services_orphan 那一处实现，这里只调它（§5.16/N6）
use super::services_orphan;
use super::residue_update::*;
use super::ownership::*;
use super::dead::*;
use super::backup_report::*;
// ==================== uninstall:residue-scan ====================

/// 应用名 → 归一化串（小写 + 折叠空白）。用于启发式目录匹配。
pub(super) fn norm_name(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

// ==================== C3 名称阈值与产出上限（2026-09-28 收口） ====================
//
// 这些数字此前散在八九处（5 / 4 / 2 / 20 / 16），同一个"名字够不够长、能出多少条"的问题
// 在不同代码路径上答案不同，改一处忘一处就会让候选集自相矛盾。收在这张表里，每条写清判据。
//
// **刻意不做成"一个全局阈值"**：门槛高低应该跟"猜错的代价"绑定，所以按风险分三档。
// - `NAME_MIN_SIMILAR`：目录名互含。5 是实测经验值——短于此（如「QQ」「微信」）会命中
//   大量无关目录，而目录是整棵删（回收站可还原但仍是数据），误报不可接受。
// - `NAME_MIN_SHORTCUT`：快捷方式 stem 互含。比目录宽一档，因为删一个 .lnk 只影响开始菜单
//   入口，程序本体不动。
// - `NAME_MIN_RULE_WORD`：签名规则库条件组里的短词门槛。这是**人工维护的精确词表**，
//   与自由文本猜测不同风险面；配套的「三条件组至少两组」是 U-1 拍板口径（见 `RESIDUE_MATCH_GROUPS`），
//   那是条件组数不是字符数，不许并进这两档。
pub(super) const NAME_MIN_SIMILAR: usize = 5;
pub(super) const NAME_MIN_SHORTCUT: usize = 4;
pub(super) const NAME_MIN_RULE_WORD: usize = 2;
/// 所有权链的**精确同名**门槛。2 而不是 5：那条链是 HashMap 精确查表（目录名归一后
/// 必须等于 owner 名），不是互含猜测，猜错代价与 `NAME_MIN_SIMILAR` 完全不同量级。
/// 沿用 5 的实际后果是中文产品名全军覆没 —— 「网易大神」4 字、「豆包」2 字、
/// 「永劫无间」4 字，全部被当成"名字太短"丢掉，档案里有 historical 记录却报
/// "没有已确认卸载完成的程序"（2026-09-28 真机实测暴露）。
pub(super) const NAME_MIN_EXACT: usize = 2;
/// 名称类命中上限（目录与快捷方式共用）：启发式只是提示，膨胀会把用户判断力淹掉
pub(super) const NAME_HIT_CAP: usize = 20;
/// 系统侧痕反查上限（MuiCache / BAM / 防火墙 / Tracing / JumpList 各自一条）
pub(super) const SIDE_TRACE_CAP: usize = 20;
/// 参与反查的程序 exe 数量上限（collect_program_objects 的产出面）
pub(super) const PROGRAM_EXE_CAP: usize = 16;

/// 同名多候选降级（C3 的后半）：同一归一化名字在**不同父目录**下命中多个结果时，
/// 无法判定哪一条才是这个程序自己的东西，整组降 low 并默认不勾。
pub(super) fn name_is_ambiguous(hits: &[String]) -> bool {
    let mut parents: HashSet<String> = HashSet::new();
    for h in hits {
        if let Some(p) = Path::new(h).parent() {
            parents.insert(p.to_string_lossy().to_ascii_lowercase());
        }
    }
    parents.len() > 1
}

/// 启发式残留：应用名与 AppData/LocalAppData/ProgramData 一级目录名互含（双侧 ≥5 字符）。
/// 方案 §4.4：名称启发式置信度 low，默认不勾选，只作候选提示。
pub(super) unsafe fn heuristic_dir_hits(app_name: &str) -> Vec<String> {
    let norm = norm_name(app_name);
    if norm.chars().count() < NAME_MIN_SIMILAR {
        return Vec::new(); // 名字太短误报率爆炸（如「QQ」会命中一堆目录）
    }
    let mut hits = Vec::new();
    for root in ["APPDATA", "LOCALAPPDATA", "PROGRAMDATA"] {
        let Ok(base) = std::env::var(root) else { continue };
        let Ok(rd) = std::fs::read_dir(&base) else { continue };
        for ent in rd.flatten() {
            if !ent.path().is_dir() {
                continue;
            }
            let dnorm = norm_name(&ent.file_name().to_string_lossy());
            if dnorm.chars().count() < NAME_MIN_SIMILAR {
                continue;
            }
            if dnorm == norm || (dnorm.contains(&norm) || norm.contains(&dnorm)) {
                hits.push(ent.path().to_string_lossy().to_string());
            }
            if hits.len() >= NAME_HIT_CAP {
                return hits; // 上限：启发式只是提示，不该膨胀
            }
        }
    }
    hits
}

/// 开始菜单快捷方式命中（用户拍板 2026-09-28：残留面板要有可清理项）：
/// 递归扫全体/当前用户两级开始菜单，.lnk 文件名含程序名即命中。上限 20 条。
pub(super) fn start_menu_shortcut_hits(app_name: &str) -> Vec<String> {
    let norm = norm_name(app_name);
    if norm.chars().count() < 3 {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let roots: Vec<PathBuf> = [
        std::env::var_os("PROGRAMDATA").map(|p| PathBuf::from(p).join(r"Microsoft\Windows\Start Menu")),
        std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join(r"Microsoft\Windows\Start Menu")),
    ]
    .into_iter()
    .flatten()
    .collect();
    for root in roots {
        if hits.len() >= NAME_HIT_CAP {
            break;
        }
        // 迭代下钻，深度 ≤ 5（开始菜单层级浅，防符号链接打穿用 is_symlink 挡）
        let mut stack = vec![(root, 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for ent in rd.flatten() {
                let p = ent.path();
                if p.is_symlink() {
                    continue;
                }
                if p.is_dir() {
                    if depth < 5 {
                        stack.push((p, depth + 1));
                    }
                    continue;
                }
                if p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("lnk")) != Some(true) {
                    continue;
                }
                let stem = norm_name(&p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default());
                if stem.contains(&norm) || (norm.contains(&stem) && stem.chars().count() >= NAME_MIN_SHORTCUT) {
                    hits.push(p.to_string_lossy().to_string());
                    if hits.len() >= NAME_HIT_CAP {
                        return hits;
                    }
                }
            }
        }
    }
    hits
}

// ==================== 固定系统侧痕反查（U-2） ====================
// 原则：按「系统对象里记录的程序路径」反查，不按程序名猜。已知线索 = 卸载键的
// InstallLocation / UninstallString / DisplayIcon 推出的 exe 路径与安装目录。
// 全部来源置信度 medium、默认不勾（拍板口径见 uninstall_residue_scan 的文档注释）。


/// 从卸载键线索收集「程序对象」：(exe 全路径集合, 安装目录)。
/// exe 来源 = UninstallString / DisplayIcon 解析 + 安装目录一级 *.exe 直查（上限 16）。
pub(super) fn collect_program_objects(loc: &str, uninstall_string: &str, display_icon_src: &str) -> (Vec<String>, Option<String>) {
    let mut exes: Vec<String> = Vec::new();
    for src in [uninstall_string, display_icon_src] {
        if let Some((exe, _)) = split_uninstall_cmd(src) {
            let exe = exe.trim().to_string();
            // msiexec.exe 是系统组件：MSI 卸载走它不代表程序装在 System32，反查它只会误伤
            if !exe.is_empty()
                && exe.to_ascii_lowercase().ends_with(".exe")
                && !exe.to_ascii_lowercase().ends_with("\\msiexec.exe")
            {
                exes.push(exe);
            }
        }
    }
    let mut dir: Option<String> = None;
    if !loc.is_empty() && Path::new(loc).is_dir() {
        dir = Some(loc.to_string());
        if let Ok(rd) = std::fs::read_dir(loc) {
            for ent in rd.flatten().take(64) {
                let p = ent.path();
                if p.is_file()
                    && p.extension().map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false)
                {
                    exes.push(p.to_string_lossy().to_string());
                    if exes.len() >= PROGRAM_EXE_CAP {
                        break;
                    }
                }
            }
        }
    }
    (exes, dir)
}

/// 路径前缀命中：值名以已知 exe 开头（MuiCache 值名形如 `<exe>.FriendlyAppName`、
/// BAM 值名即完整 exe 路径），或落在安装目录整棵前缀下
pub(super) fn trace_prefix_hit(name_lc: &str, exes_lc: &[String], dir_lc: &str) -> bool {
    exes_lc.iter().any(|e| name_lc.starts_with(e.as_str()))
        || (!dir_lc.is_empty() && name_lc.starts_with(&format!("{dir_lc}\\")))
}

/// 枚举注册表键的全部值（只收 REG_SZ / REG_EXPAND_SZ，返回 (值名, 数据)）。
/// 上限 cap 防爆（MuiCache/BAM 可上千条；枚举到 cap 即截断返回）。
pub(super) unsafe fn reg_enum_sz_values(
    hive: windows::Win32::System::Registry::HKEY,
    subkey: &str,
    cap: usize,
) -> Vec<(String, String)> {
    use windows::Win32::System::Registry::{RegCloseKey, RegEnumValueW, RegOpenKeyExW, KEY_READ};
    if cap == 0 {
        return Vec::new();
    }
    let sk = to_wide(subkey);
    let mut hk = windows::Win32::System::Registry::HKEY::default();
    if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
        return Vec::new();
    }
    let mut out: Vec<(String, String)> = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name_buf = [0u16; 1024];
        let mut name_len = name_buf.len() as u32;
        let mut ty = 0u32; // windows 0.61 的 lptype 是 *mut u32：1=REG_SZ 2=REG_EXPAND_SZ
        let mut data_len = 0u32;
        // 先探类型与尺寸（lpData=None），只收字符串类；二进制/DWORD 值直接跳过
        let r = RegEnumValueW(
            hk, index,
            Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            None,
            Some(&mut ty),
            None,
            Some(&mut data_len),
        );
        if r.is_err() {
            break; // ERROR_NO_MORE_ITEMS 或访问异常都按枚举结束处理
        }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        index += 1;
        if name.is_empty() {
            continue;
        }
        if ty != 1 && ty != 2 {
            continue;
        }
        // 再取数据（data_len 为字节数，含终止 NUL）
        let mut buf = vec![0u8; data_len.max(2) as usize];
        let mut got = buf.len() as u32;
        let ok = RegEnumValueW(
            hk, index - 1,
            Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut got),
        )
        .is_ok();
        if !ok {
            continue;
        }
        let words: Vec<u16> = buf[..got as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&w| w != 0)
            .collect();
        out.push((name, String::from_utf16_lossy(&words)));
        if out.len() >= cap {
            break;
        }
    }
    let _ = RegCloseKey(hk);
    out
}

/// 枚举注册表键的全部子键名（上限 cap）
pub(super) unsafe fn reg_enum_subkeys(
    hive: windows::Win32::System::Registry::HKEY,
    subkey: &str,
    cap: usize,
) -> Vec<String> {
    use windows::Win32::System::Registry::{RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, KEY_READ};
    if cap == 0 {
        return Vec::new();
    }
    let sk = to_wide(subkey);
    let mut hk = windows::Win32::System::Registry::HKEY::default();
    if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name_buf = [0u16; 260];
        let mut name_len = name_buf.len() as u32;
        let r = RegEnumKeyExW(
            hk, index,
            Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            None, None, None, None,
        );
        if r.is_err() {
            break;
        }
        index += 1;
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        if !name.is_empty() {
            out.push(name);
        }
        if out.len() >= cap {
            break;
        }
    }
    let _ = RegCloseKey(hk);
    out
}

/// MuiCache 残留值反查。目标格式 `HKCU\<键路径>::<值名>`（执行侧按 rsplit_once("::") 拆）。
pub(super) unsafe fn muicache_hits(exes_lc: &[String], dir_lc: &str, cap: usize) -> Vec<String> {
    const SUBKEY: &str = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
    let mut out = Vec::new();
    for (name, _) in reg_enum_sz_values(HKEY_CURRENT_USER, SUBKEY, 4096) {
        if trace_prefix_hit(&name.to_ascii_lowercase(), exes_lc, dir_lc) {
            out.push(format!("HKCU\\{SUBKEY}::{name}"));
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

/// 防火墙规则反查：规则值数据形如 `...|App=C:\path\app.exe|...`，数据里含已知 exe/安装目录即命中。
pub(super) unsafe fn firewall_hits(exes_lc: &[String], dir_lc: &str, cap: usize) -> Vec<String> {
    const SUBKEY: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    let mut out = Vec::new();
    for (name, data) in reg_enum_sz_values(HKEY_LOCAL_MACHINE, SUBKEY, 4096) {
        let dl = data.to_ascii_lowercase();
        let hit = exes_lc.iter().any(|e| dl.contains(e.as_str()))
            || (!dir_lc.is_empty() && dl.contains(&format!("{dir_lc}\\")));
        if hit {
            out.push(format!("HKLM\\{SUBKEY}::{name}"));
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

/// BAM（后台活动记录）反查：`bam\State\UserSettings\<SID>` 下值名 = 完整 exe 路径
/// （数据是执行序号 DWORD，不参与匹配）。
pub(super) unsafe fn bam_hits(exes_lc: &[String], dir_lc: &str, cap: usize) -> Vec<String> {
    const ROOT: &str = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";
    let mut out = Vec::new();
    'outer: for sid in reg_enum_subkeys(HKEY_LOCAL_MACHINE, ROOT, 64) {
        for (name, _) in reg_enum_sz_values(HKEY_LOCAL_MACHINE, &format!("{ROOT}\\{sid}"), 256) {
            if trace_prefix_hit(&name.to_ascii_lowercase(), exes_lc, dir_lc) {
                out.push(format!("HKLM\\{ROOT}\\{sid}::{name}"));
                if out.len() >= cap {
                    break 'outer;
                }
            }
        }
    }
    out
}

/// Tracing 诊断跟踪项反查：`HKLM\SOFTWARE\Microsoft\Tracing\<exe 文件名>` 子键
/// （常见形如 `App.EXE`），按已知 exe 的文件名 stem 反查。
pub(super) unsafe fn tracing_hits(exes_lc: &[String], cap: usize) -> Vec<String> {
    const ROOT: &str = r"SOFTWARE\Microsoft\Tracing";
    let mut stems: Vec<String> = exes_lc
        .iter()
        .filter_map(|e| {
            Path::new(e)
                .file_stem()
                .map(|s| s.to_string_lossy().to_ascii_lowercase())
        })
        .collect();
    stems.sort();
    stems.dedup();
    if stems.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for name in reg_enum_subkeys(HKEY_LOCAL_MACHINE, ROOT, 512) {
        let nl = name.to_ascii_lowercase();
        let stem = Path::new(&nl)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| nl.clone());
        if stems.contains(&nl) || stems.contains(&stem) {
            out.push(format!("HKLM\\{ROOT}\\{name}"));
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

/// JumpList 自动目标反查（对象级）：`.destinations-ms` 文件是 OLE 复合文档，
/// AppID 为不可逆哈希，无法按应用名映射——改为字节级包含判定：文件原始字节里
/// 出现安装目录 / exe 路径的 UTF-16LE 编码即命中（同前缀目录树的程序会共享命中，
/// 因此保持 medium + 默认不勾）。
pub(super) fn jumplist_hits(exes_lc: &[String], dir_lc: &str, cap: usize) -> Vec<String> {
    let Some(base) = std::env::var_os("APPDATA") else {
        return Vec::new();
    };
    let root = PathBuf::from(base).join(r"Microsoft\Windows\Recent\AutomaticDestinations");
    let Ok(rd) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut needles: Vec<Vec<u8>> = Vec::new();
    let push_needle = |s: &str, needles: &mut Vec<Vec<u8>>| {
        if s.is_empty() {
            return;
        }
        needles.push(s.encode_utf16().flat_map(u16::to_le_bytes).collect());
    };
    push_needle(dir_lc, &mut needles);
    for e in exes_lc {
        push_needle(e, &mut needles);
    }
    if needles.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        let is_dest = p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase().ends_with("destinations-ms"))
            .unwrap_or(false);
        if !is_dest {
            continue;
        }
        // 正常目标文件 <1MB；超 4MB 视为异常直接跳过（防把巨型文件读进内存）
        let Ok(bytes) = std::fs::read(&p) else { continue };
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            continue;
        }
        if needles.iter().any(|n| {
            bytes
                .windows(n.len())
                .any(|w| w == n.as_slice())
        }) {
            out.push(p.to_string_lossy().to_string());
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}


/// 卸载域·残留扫描（方案 M3 MVP + U-2 固定系统侧痕）。
/// 来源与置信度：卸载键仍在=high（reg_key）；InstallLocation 仍在=high（folder）；
/// 名称启发式=low（folder，默认不勾）；开始菜单快捷方式=medium（默认勾）；
/// 固定系统侧痕（U-2）=medium 全默认不勾（拍板口径 2026-09-28：侧痕删除无原厂依据，
/// 只作候选交用户逐项决定）。签名残留规则库按方案后置接入（U-1）。
#[tauri::command]
pub async fn uninstall_residue_scan<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    app_id: String,
) -> Value {
    // v0.7.0 面板整体搬进 residue 副窗 ⇒ 档位从 MAIN 改为窄窗口集（见 guard::RESIDUE_WINDOWS）
    if let Err(msg) = guard::guard(&window, guard::RESIDUE_WINDOWS) {
        return json!({ "success": false, "message": msg });
    }
    let Some((hive_str, key_path)) = app_id.split_once('|') else {
        return json!({ "success": false, "message": "app_id 格式错误" });
    };
    // U-4（拍板 2026-09-28）：Appx 也参与残留扫描（Packages 应用数据遗留数据），先用包全名闸
    if hive_str.eq_ignore_ascii_case("APPX") {
        if !valid_appx_fullname(key_path) {
            return json!({ "success": false, "message": "app_id 不是合法的包全名" });
        }
    } else if !valid_uninstall_key_path(key_path) {
        return json!({ "success": false, "message": "app_id 不是合法的卸载键路径" });
    }
    let hive_str = hive_str.to_string();
    let key_path = key_path.to_string();
    let findings = tauri::async_runtime::spawn_blocking(move || unsafe {
        use windows::Win32::System::Registry::{RegOpenKeyExW, RegCloseKey, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
        // U-4（拍板 2026-09-28）：Appx 残留口径=Remove-AppxPackage 后
        // %LOCALAPPDATA%\Packages\<PFN> 的应用数据遗留应用数据。此前「不参与残留扫描」，
        // 小旭拍板并入：目录存在才入候选，进回收站（可还原），先过 is_path_protected。
        if hive_str.eq_ignore_ascii_case("APPX") {
            let Some(pfn) = package_family_name(&key_path) else {
                return (Vec::new(), "Windows 应用".to_string());
            };
            let base = std::env::var("LOCALAPPDATA").unwrap_or_default();
            if base.is_empty() {
                return (Vec::new(), "Windows 应用".to_string());
            }
            let dir = PathBuf::from(&base).join("Packages").join(&pfn);
            let mut findings: Vec<Value> = Vec::new();
            if dir.is_dir() && !protect::is_path_protected(&dir.to_string_lossy()) {
                findings.push(json!({
                    "kind": "folder", "target": dir.to_string_lossy(),
                    "reason": "Windows 应用已移除，其 %LOCALAPPDATA%\\Packages\\<包名> 应用数据成为应用数据遗留（进回收站，可还原）",
                    "confidence": "high", "risk": "low", "defaultChecked": true,
                    "contribs": contribs(&[
                        ("appxRemoved", format!("包 {pfn} 已从当前用户移除（清单里查不到）")),
                        ("pkgDataDir", format!("遗留位置由包名唯一确定：{}", dir.to_string_lossy())),
                    ]),
                }));
            }
            return (findings, pfn);
        }
        let (hive, full_target) = if hive_str.eq_ignore_ascii_case("HKCU") {
            (HKEY_CURRENT_USER, format!("HKCU\\{key_path}"))
        } else if hive_str.eq_ignore_ascii_case("HKLM") {
            (HKEY_LOCAL_MACHINE, format!("HKLM\\{key_path}"))
        } else {
            return (Vec::new(), String::new());
        };
        let sk = to_wide(&key_path);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return (Vec::new(), String::new());
        }
        let display_name = reg_sz(hk, "DisplayName").unwrap_or_default();
        let publisher = reg_sz(hk, "Publisher").unwrap_or_default();
        let install_location = reg_sz(hk, "InstallLocation").unwrap_or_default();
        let display_icon_src = reg_sz(hk, "DisplayIcon").unwrap_or_default();
        let uninstall_string = reg_sz(hk, "UninstallString").unwrap_or_default();
        let _ = RegCloseKey(hk);

        let mut findings: Vec<Value> = Vec::new();
        // 高置信：卸载键仍在（原厂卸载未完成/已取消的直接证据）
        if crate::engine::native::reg_key_exists(hive, &key_path) {
            let why = contribs(&[
                ("uninstallKeyAlive", format!("本次卸载后复查：{full_target} 仍能打开")),
            ]);
            findings.push(json!({
                "kind": "reg_key", "target": full_target,
                "reason": "卸载注册表项仍存在（原厂卸载可能未完成或已取消）",
                "confidence": "high", "risk": "medium", "defaultChecked": true,
                "contribs": why,
            }));
        }
        // 高置信：安装目录仍在
        let loc = install_location.trim().trim_end_matches('\\').to_string();
        if !loc.is_empty()
            && Path::new(&loc).is_dir()
            && !protect::is_path_protected(&loc)
        {
            let why = contribs(&[("installLocationAlive", format!("厂商写的安装目录仍在磁盘上：{loc}"))]);
            findings.push(json!({
                "kind": "folder", "target": loc,
                "reason": "InstallLocation 指向的安装目录仍存在",
                "confidence": "high", "risk": "medium", "defaultChecked": true,
                "contribs": why,
            }));
        }
        // 低置信：名称启发式（默认不勾，交用户判断）
        for p in heuristic_dir_hits(&display_name) {
            if protect::is_path_protected(&p) {
                continue;
            }
            let why = contribs(&[(
                "nameHeuristic",
                format!("目录名与「{display_name}」互含且长度达阈值（阈值 {NAME_MIN_SIMILAR} 字）"),
            )]);
            findings.push(json!({
                "kind": "folder", "target": p,
                "reason": format!("目录名与「{display_name}」高度相似（启发式，请人工确认后再删）"),
                "confidence": "low", "risk": "high", "defaultChecked": false,
                "contribs": why,
            }));
        }
        // 高置信补充：卸载器/图标指向的目录仍存在（InstallLocation 缺失时的主线索）
        for (from_value, src) in [("UninstallString", &uninstall_string), ("DisplayIcon", &display_icon_src)] {
            if src.trim().is_empty() {
                continue;
            }
            if let Some((exe, _)) = split_uninstall_cmd(src) {
                if let Some(parent) = Path::new(&exe).parent() {
                    let pd = parent.to_path_buf();
                    if pd.as_os_str().is_empty()
                        || !pd.is_dir()
                        || protect::is_path_protected(&pd.to_string_lossy())
                        || findings.iter().any(|f| {
                            f["kind"] == "folder"
                                && f["target"].as_str().map(|s| s.eq_ignore_ascii_case(&pd.to_string_lossy())).unwrap_or(false)
                        })
                    {
                        continue;
                    }
                    let why = contribs(&[(
                        "exeParent",
                        format!("{from_value} 指向的 exe 落在这家目录里：{}", pd.to_string_lossy()),
                    )]);
                    findings.push(json!({
                        "kind": "folder", "target": pd.to_string_lossy(),
                        "reason": "卸载器/图标指向的程序目录仍存在",
                        "confidence": "high", "risk": "medium", "defaultChecked": true,
                        "contribs": why,
                    }));
                }
            }
        }
        // 中置信：开始菜单快捷方式（文件名含程序名；删 .lnk 无害，默认勾选）
        // C3 同名多候选降级：同名快捷方式出现在多个父目录时无法判定哪条属于本程序，
        // 整组降 low 且不默认勾选（目录类启发式本来就是 low，不受这条影响）
        let shortcuts = start_menu_shortcut_hits(&display_name);
        let shortcut_ambiguous = name_is_ambiguous(&shortcuts);
        // C4：歧义降级要能把「到底是哪几个父目录各有同名快捷方式」指出来，否则用户只看到
        // 一句"出现在多个目录"，仍然不知道该信哪条。
        let shortcut_parents = {
            let mut v: Vec<String> = shortcuts
                .iter()
                .filter_map(|s| Path::new(s).parent().map(|p| p.to_string_lossy().to_string()))
                .collect();
            v.sort();
            v.dedup();
            v
        };
        for lnk in shortcuts {
            let mut items: Vec<(&str, String)> = vec![(
                "shortcutNameMatch",
                format!("快捷方式文件名与「{display_name}」同名（阈值 {NAME_MIN_SHORTCUT} 字）"),
            )];
            if shortcut_ambiguous {
                items.push((
                    "ambiguousParents",
                    format!("同名快捷方式分布在多个父目录，无法指认哪条属于本程序：{}", shortcut_parents.join("；")),
                ));
            }
            findings.push(json!({
                "kind": "shortcut", "target": lnk,
                "reason": format!("开始菜单快捷方式与「{display_name}」同名{}",
                    if shortcut_ambiguous { "（同名快捷方式出现在多个目录，请人工确认后再删）" } else { "" }),
                "confidence": if shortcut_ambiguous { "low" } else { "medium" },
                "risk": "low",
                "defaultChecked": !shortcut_ambiguous,
                "contribs": contribs(&items),
            }));
        }
        // 中置信（默认不勾）：固定系统侧痕反查（U-2）。按系统对象里记录的程序路径反查，
        // 不按程序名猜——已知线索只有卸载键推出的 exe 路径与安装目录。
        let (prog_exes, prog_dir) = collect_program_objects(&loc, &uninstall_string, &display_icon_src);
        let dir_lc = prog_dir
            .as_ref()
            .map(|d| d.trim_end_matches('\\').to_ascii_lowercase())
            .unwrap_or_default();
        let exes_lc: Vec<String> = prog_exes
            .iter()
            .map(|e| e.trim_end_matches('\\').to_ascii_lowercase())
            .collect();
        if !exes_lc.is_empty() || !dir_lc.is_empty() {
            // C4：侧痕反查的线索来源（安装目录 / exe 路径）比"命中了某个系统登记"更有用——
            // 用户要判断的是这条线索是不是这个程序留下的。
            let mut trace_src: Vec<(&str, String)> = Vec::new();
            if !dir_lc.is_empty() {
                trace_src.push(("traceByInstallDir", format!("按安装目录反查系统登记：{dir_lc}")));
            }
            if !exes_lc.is_empty() {
                trace_src.push((
                    "traceByExe",
                    format!("按 {} 条已知 exe 路径反查（取自卸载器/图标）", exes_lc.len()),
                ));
            }
            // 外层闭包整体处于 unsafe 块内，直接调用即可（内层再包 unsafe 会告警冗余）
            for target in muicache_hits(&exes_lc, &dir_lc, SIDE_TRACE_CAP) {
                let mut items = trace_src.clone();
                items.push(("muicacheHit", "MuiCache 里缓存了这个程序路径的友好名称".to_string()));
                findings.push(json!({
                    "kind": "reg_value", "target": target,
                    "reason": "MuiCache 残留值（系统缓存了此程序路径的友好名称）",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                    "contribs": contribs(&items),
                }));
            }
            for target in firewall_hits(&exes_lc, &dir_lc, SIDE_TRACE_CAP) {
                let mut items = trace_src.clone();
                items.push(("firewallHit", "防火墙规则里记着这个程序路径，规则已随程序失效".to_string()));
                findings.push(json!({
                    "kind": "reg_value", "target": target,
                    "reason": "防火墙规则引用此程序路径（程序已卸载，规则已失效）",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                    "contribs": contribs(&items),
                }));
            }
            for target in bam_hits(&exes_lc, &dir_lc, SIDE_TRACE_CAP) {
                let mut items = trace_src.clone();
                items.push(("bamHit", "BAM 后台执行管理里留着这个程序路径的执行记录".to_string()));
                findings.push(json!({
                    "kind": "reg_value", "target": target,
                    "reason": "BAM 后台执行记录引用此程序路径",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                    "contribs": contribs(&items),
                }));
            }
            for target in tracing_hits(&exes_lc, SIDE_TRACE_CAP) {
                let mut items = trace_src.clone();
                items.push(("tracingHit", "诊断跟踪子键以此程序的 exe 文件名命名".to_string()));
                findings.push(json!({
                    "kind": "reg_key", "target": target,
                    "reason": "Tracing 诊断跟踪项以此程序的 exe 命名",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                    "contribs": contribs(&items),
                }));
            }
            for target in jumplist_hits(&exes_lc, &dir_lc, SIDE_TRACE_CAP) {
                let mut items = trace_src.clone();
                items.push(("jumplistHit", "JumpList 自动目标缓存里留着这个程序的 exe 条目".to_string()));
                findings.push(json!({
                    "kind": "file", "target": target,
                    "reason": "JumpList 自动目标缓存引用此程序路径",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                    "contribs": contribs(&items),
                }));
            }
        }
        // 高置信：签名残留规则库命中（U-1）——已知程序知识库，双条件命中 +
        // 目标存在性判定后才出现；reg_key 删除走执行侧同款「先备份后删」
        if let Some(rules) = load_residue_rules() {
            let (rule_hits, vetoed) = residue_rules_hits(&rules, &display_name, &publisher, &key_path, false);
            findings.extend(rule_hits);
            // 硬否决在命令边界留痕：真机跑到这一行就说明签名规则库里躺着一处系统容器
            // （误签、私钥泄露或规则生成漏检），属异常而非常态，必须能在日志里查到。
            for line in vetoed {
                log::write_log("warn", &line);
            }
        }
        // 第二层：本机学习库（HiBit §H3）。同一套命中判定 + 同一个语义校验器，差别只在
        // 证据等级（不签名 ⇒ medium + 不自动勾选）。**签名库命中的同一目标不再出第二次**——
        // 重复行会把用户推向「勾两次才删得掉」的错觉，而面板里没有去重就等于两条独立证据。
        if let Some(learned_doc) = learned::load() {
            let (hits, vetoed) =
                residue_rules_hits(&learned_doc, &display_name, &publisher, &key_path, true);
            for line in vetoed {
                log::write_log("warn", &line);
            }
            for h in hits {
                let k = h["kind"].as_str().unwrap_or("").to_lowercase();
                let t = h["target"].as_str().unwrap_or("").to_lowercase();
                let dup = findings.iter().any(|f| {
                    f["kind"].as_str().unwrap_or("").to_lowercase() == k
                        && f["target"].as_str().unwrap_or("").to_lowercase() == t
                });
                if !dup {
                    findings.push(h);
                }
            }
        }
        (findings, display_name)
    })
    .await
    .unwrap_or((Vec::new(), String::new()));

    // 快照落槽：执行只认这份集合
    let (finding_list, app_name) = findings;
    let label = window.label().to_string();
    residue_snapshot_put(&label, "app", finding_list.clone());
    json!({ "success": true, "data": { "appName": app_name, "findings": finding_list } })
}

// ==================== uninstall:residue-execute ====================

/// 残留执行结果明细行
pub(super) fn detail(kind: &str, target: &str, status: &str, message: &str) -> Value {
    json!({ "kind": kind, "target": target, "status": status, "message": message })
}

/// HiBit §H3 的回写侧：把这一轮用户**实际删掉**的落点沉淀进本机学习库。
///
/// 只学 status=="ok" 的行 —— 失败行学进去会让下一轮把「这台机器上删不掉的路径」
/// 当成已知残留反复推荐。归属身份（displayName / publisher / 卸载键末段）一律
/// **现读注册表**，不从渲染层回传：与 `uninstall_run` 同一条纪律（app_id 只当寻址键）。
/// 学不到（合成 MACHINE id、APPX 包、键已不存在、没有一条落点过得了归属判定）就整条不写，
/// 而不是写一份"大概是这样"的记录 —— 学习库是下一轮的删除建议来源。
pub(super) fn learn_from_deletions(app_id: &str, details: &[Value]) -> usize {
    let Some((hive_str, key_path)) = app_id.split_once('|') else {
        return 0; // APPX|… 与 MACHINE|all 都没有卸载键身份，学不了
    };
    let reg_full = format!("{hive_str}\\{key_path}");
    let Some((hive, rest)) = parse_reg_target(&reg_full) else {
        return 0;
    };
    let read_sz = |name: &str| -> String {
        crate::engine::native::read_reg_value_text(hive, rest.as_str(), name)
            .map(|(_, v)| v)
            .unwrap_or_default()
    };
    let display_name = read_sz("DisplayName");
    let publisher = read_sz("Publisher");
    if display_name.trim().is_empty() {
        return 0; // 没有程序名就当双条件组的另一半也凑不齐，校验器会整包拒
    }
    // kind 口径对齐：执行明细里的目录行写作 `dir`（原生删除侧的回执），学习库 schema 要 `folder`
    let mut entries: Vec<(&str, String)> = Vec::new();
    for d in details {
        if d["status"].as_str() != Some("ok") {
            continue;
        }
        let raw_kind = d["kind"].as_str().unwrap_or("");
        let mapped = match raw_kind {
            "dir" | "folder" => "folder",
            "file" => "file",
            "reg_key" => "reg_key",
            _ => continue, // 学习库只收扫描器产出的三类落点；shortcut/reg_value 是签名库独有的 kind（Q8 2026-10-06 放行），学习库允许集维持不变
        };
        let Some(t) = d["target"].as_str() else { continue };
        entries.push((mapped, t.to_string()));
    }
    if entries.is_empty() {
        return 0;
    }
    let mut doc = learned::load().unwrap_or_else(learned::empty_doc);
    let added = learned::learn(&mut doc, &display_name, &publisher, key_path, &entries, crate::engine::now_ms());
    if added == 0 {
        return 0;
    }
    match learned::save(&doc) {
        Ok(_) => added,
        Err(e) => {
            // 学习是附加价值：写失败只降级成「这次没学到」，绝不能把已经成功的清理判成失败
            log::write_log("warn", &format!("学习库回写失败（本轮清理结果不受影响）: {e}"));
            0
        }
    }
}

/// 残留执行的**单一变更入口**（D3）：变更阶段拿到的就是已判定完的目标。
pub(super) enum ResidueOp {
    RegKey {
        target: String,
        hive: windows::Win32::System::Registry::HKEY,
        rest: String,
    },
    RegValue {
        target: String,
        key_part: String,
        hive: windows::Win32::System::Registry::HKEY,
        rest: String,
        value_name: String,
    },
    Path { kind: String, target: OsString },
}

/// 单个目标的只读判定结果。`Abort` = 整批拒绝（受保护路径的既有语义，不降级成单项跳过）。
pub(super) enum OpVerdict {
    Ready(ResidueOp),
    Skip(String),
    Abort(String),
}

/// 残留执行链上**所有只读闸门的唯一落点**（D3）。
///
/// 为什么要收：`uninstall_residue_execute` 原本三段各写各的判定（reg_key 查 hive 解析 +
/// A1 硬否决 + 存在性；reg_value 查 `::` 形状；文件目录查保护路径 + 存在性 + C1 重解析），
/// 「谁查了哪几道闸」只能靠通读三段来确认 —— 这正是漏闸的形态。收进一个函数后，
/// 判定顺序 = 这一个函数的行序，变更代码里不再有 if 保护判断。
///
/// 方案 §5·D3 原文还有个 `mode="plan"`（干跑不落变更）。这里刻意**不做**成参数：
/// 现在没有任何调用方会传 plan，加了就是死分支；"判定与变更分离"这个目的已经由本函数达成，
/// UI 真需要预览时再显式加 mode，届时这条函数就是它的实现。
pub(super) fn classify_residue_op(kind: &str, target: &str) -> OpVerdict {
    let skip = |m: &str| OpVerdict::Skip(m.to_string());
    match kind {
        "reg_key" => {
            let Some((hive, rest)) = parse_reg_target(target) else {
                return skip("注册表目标无法解析（只支持 HKCU/HKLM）");
            };
            // A1 执行侧硬闸（与扫描侧同一判定）：快照闸只证明「来自上次扫描」，
            // 证明不了「这个目标不该删」—— 危险候选本来就是扫描器按规则产出的。
            if let Some(reason) = protect::reg_target_block_reason(target) {
                // 唯一的例外：服务键窄口子（方案 §5）。三条同时成立才放行 ——
                // 形状合格、**此刻**现读八道排除式判据全过、且已提权（HKLM 写不进去的
                // 话删了也是假成功）。判据本体在 `services_orphan::service_key_delete_block_reason`，
                // 装载侧调的是同一个函数，所以「UI 说能删」与「执行侧肯删」不可能各判一次。
                let narrow = services_orphan::looks_like_service_key(target)
                    && sysinfo::is_admin()
                    && unsafe { services_orphan::service_key_delete_block_reason(target) }.is_none();
                if !narrow {
                    log::write_log("warn", &format!("uninstall_residue_execute 拒绝注册表目标: {reason}"));
                    // 状态只用既有的 skip：报告明细按 ok/fail/skip 三态渲染中文标签，
                    // 新增 status 会在前端漏出英文字面量（uninstall.js:487）
                    return OpVerdict::Skip(format!("已拒绝删除：{reason}"));
                }
                // 放行必须留痕：这条是本仓唯一一处「A1 让路」，事后要能在日志里数出来
                log::write_log("warn", &format!("A1 服务键窄口子放行（八道判据现读全过 + 已提权）: {target}"));
            }
            if !crate::engine::native::reg_key_exists(hive, &rest) {
                return skip("注册表项已不存在");
            }
            OpVerdict::Ready(ResidueOp::RegKey { target: target.to_string(), hive, rest })
        }
        // 注册表值：删单值前先整父键备份（U-2 侧痕面 MuiCache/防火墙/BAM）。
        // 值已不存在的幂等语义留给 `reg_restore_delete`（对齐 B11），这里不重复判存在性。
        "reg_value" => {
            let Some((key_part, value_name)) = target.rsplit_once("::") else {
                return skip("注册表值目标格式错误（缺 :: 值名分隔）");
            };
            if value_name.trim().is_empty() {
                return skip("注册表值名为空");
            }
            let Some((hive, rest)) = parse_reg_target(key_part) else {
                return skip("注册表目标无法解析（只支持 HKCU/HKLM）");
            };
            OpVerdict::Ready(ResidueOp::RegValue {
                target: target.to_string(),
                key_part: key_part.to_string(),
                hive,
                rest,
                value_name: value_name.to_string(),
            })
        }
        "folder" | "file" | "shortcut" => {
            let shown = target.to_string();
            if protect::is_path_protected(&shown) {
                log::write_log("warn", &format!("uninstall_residue_execute 拒绝: 受保护路径 {shown}"));
                return OpVerdict::Abort(format!("包含受保护的系统路径，已拒绝：{shown}"));
            }
            if std::fs::symlink_metadata(target).is_err() {
                // 原本这里是被静默滤掉（报告里连一行都没有），现按 skip 记因：
                // 「没删」与「不需要删」必须在批次报告里可区分
                return OpVerdict::Skip("目标已不存在（未执行删除）".to_string());
            }
            // C1（方案 §5·C1）：目录送删前过「自身→盘符根」逐层重解析点校验，与维护任务
            // (`native::maint_run`)、diskbench 同口径。上级被换成 junction 时回收站会顺着链接
            // 把链接目标整棵搬走。file / shortcut 不查：单文件删除只删链接本身，不递归。
            if kind == "folder" {
                if let Some(reason) = crate::engine::native::dir_delete_blocked(Path::new(target)) {
                    log::write_log("warn", &format!("uninstall_residue_execute 跳过目录 {shown}: {reason}"));
                    return OpVerdict::Skip(format!("已拒绝删除：{reason}"));
                }
            }
            OpVerdict::Ready(ResidueOp::Path { kind: kind.to_string(), target: OsString::from(target) })
        }
        other => OpVerdict::Skip(format!("未知残留类型 {other}，未执行")),
    }
}

/// 卸载域·残留执行（方案 M4）。
/// 硬约束：目标必须命中本会话快照（防伪造请求）；文件/目录回收站优先且
/// `is_path_protected` 前置、失败不永久删除兜底；注册表先 export 备份再删，
/// 备份失败该项拒绝；`reg_key` 删树前必须过 `protect::reg_target_block_reason`（A1，
/// 与扫描侧同判定）；`folder` 送删前必须过上级链重解析校验（C1）。
/// 批次报告落 uninstall-reports/<batch>.json。
#[tauri::command]
pub async fn uninstall_residue_execute<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    app_id: String,
    targets: Vec<Value>,
    // HiBit §H1：删前是否先把内容打进还原包。**默认关**（2026-09-29 用户裁定不做默认备份），
    // 由残留面板上的开关逐项决定；勾了却建包失败则整批不删（见下面 closure 开头）。
    backup: Option<bool>,
) -> Value {
    // v0.7.0 唯一调用方是 residue 副窗的「删除选中残留」；档位从 MAIN 换成窄窗口集，
    // 既不让副窗判越权（§3 M1~M3），也不外放到 APP_WINDOWS 全集（删残留是写侧能力）。
    if let Err(msg) = guard::guard(&window, guard::RESIDUE_WINDOWS) {
        return json!({ "success": false, "message": msg });
    }
    if targets.is_empty() || targets.len() > 200 {
        return json!({ "success": false, "message": "targets 为空或超过 200 项上限" });
    }
    let label = window.label().to_string();
    // 快照校验：kind+target 逐一命中（方案 M4 验收「任意单项不得绕过快照」）
    let snap: Vec<Value> = {
        let store = residue_snapshots().lock().unwrap_or_else(|e| e.into_inner());
        store.get(&label).map(|(_, f)| f.clone()).unwrap_or_default()
    };
    let wanted: Vec<(String, String)> = targets
        .iter()
        .map(|t| {
            (
                t.get("kind").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                t.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            )
        })
        .collect();
    if wanted.iter().any(|(k, t)| k.is_empty() || t.is_empty()) {
        return json!({ "success": false, "message": "targets 存在缺失 kind/target 的项" });
    }
    let known = |k: &str, t: &str| {
        snap.iter().any(|f| {
            f["kind"].as_str() == Some(k)
                && f["target"].as_str().map(|s| s.eq_ignore_ascii_case(t)).unwrap_or(false)
        })
    };
    let stale: Vec<&(String, String)> = wanted.iter().filter(|(k, t)| !known(k, t)).collect();
    if !stale.is_empty() {
        return json!({ "success": false, "message": format!("{} 项不在本次扫描快照中（目标已过期或请求被篡改），请重新扫描后再试", stale.len()) });
    }

    log::flush_sync(); // 危险操作前刷盘
    // 批次号在这里就定：还原包目录、批次报告、回执必须共用同一个 id，事后补生成会对不上
    let batch_id = delete_manifest::new_batch_id();
    let batch_for_pack = batch_id.clone();
    let want_backup = backup.unwrap_or(false);
    let app_id = app_id.clone();
    let report = tauri::async_runtime::spawn_blocking(move || {
        // 勾了备份却建包失败 ⇒ 整批不删。静默降级成「只删不备」是把用户的决定改成她没选的那件事
        let mut pack = match want_backup {
            true => match crate::engine::restore_pack::Pack::begin(&batch_for_pack) {
                Ok(p) => Some(p),
                Err(e) => return Err(format!("创建还原包失败，未执行任何删除: {e}")),
            },
            false => None,
        };
        let mut details: Vec<Value> = Vec::new();
        // D3：只读闸门先一次跑完（判定顺序集中在 classify_residue_op），下面的变更代码里
        // 不再出现任何保护判断 —— 「谁查了哪几道闸」从"通读三段"变成"看一个函数的行序"。
        let mut ops: Vec<ResidueOp> = Vec::new();
        for (kind, target) in &wanted {
            match classify_residue_op(kind, target) {
                OpVerdict::Ready(op) => ops.push(op),
                OpVerdict::Skip(msg) => details.push(detail(kind, target, "skip", &msg)),
                OpVerdict::Abort(msg) => return Err(msg),
            }
        }
        // 注册表项：先备份后删（与 cleanup 同一 export 通道，fail-closed）
        for op in &ops {
            let ResidueOp::RegKey { target, hive, rest } = op else { continue };
            let (kind, target, hive, rest) = ("reg_key", target.as_str(), *hive, rest.as_str());
            let backup_dir = uninstall_reg_backup_dir();
            let _ = std::fs::create_dir_all(&backup_dir);
            let file = backup_dir.join(format!("{}_{}.reg", crate::engine::now_ms(), rest.rsplit('\\').next().unwrap_or("key")));
            let Some(file_str) = file.to_str() else {
                details.push(detail(kind, target, "fail", "备份路径无法表示为文本，拒绝删除"));
                continue;
            };
            let export_path = format!("{}\\{rest}", target.split('\\').next().unwrap_or(""));
            // v2-L4P-29（B-7）：备份类子进程统一走带超时入口，reg.exe 被拖住不再永久挂死
            let backup_ok = crate::engine::systembin::quiet_cmd_timeout(
                crate::engine::systembin::system_tool("reg.exe"),
                &["export", &export_path, file_str, "/y"],
                crate::engine::systembin::REG_EXPORT_TIMEOUT,
            )
            .map(|o| o.status.success() && file.exists())
            .unwrap_or(false);
            if !backup_ok {
                details.push(detail(kind, target, "fail", "注册表备份失败，未执行删除（fail-closed）"));
                continue;
            }
            // D2：备份写成后落封条（此后列表/还原才对得上这份文件）
            write_reg_backup_seal(&file, target);
            // N3：写完裁一次保留上限。只裁新根，封条随主文件同删（paths::prune_backups）；
            // 刚写的这份是最新项，不会被自己裁掉。
            crate::engine::paths::prune_backups(&backup_dir, crate::engine::paths::BACKUP_KEEP);
            if let Some(p) = pack.as_mut() {
                let _ = p.include_reg_backup(&file);
            }
            if crate::engine::native::reg_key_remove(hive, rest, true) {
                details.push(detail(kind, target, "ok", "已删除（备份已留存）"));
            } else {
                details.push(detail(kind, target, "fail", "注册表删除失败"));
            }
        }

        // 注册表值：先备份整个父键再删单值（U-2 侧痕面：MuiCache/防火墙规则/BAM）。
        // 目标格式 `HKCU\<键路径>::<值名>`；删值复用 reg_restore_delete
        // （值已不存在 = 幂等成功，对齐 B11 语义）。
        for op in &ops {
            let ResidueOp::RegValue { target, key_part, hive, rest, value_name } = op else { continue };
            let (kind, target, hive, rest, value_name) =
                ("reg_value", target.as_str(), *hive, rest.as_str(), value_name.as_str());
            let backup_dir = uninstall_reg_backup_dir();
            let _ = std::fs::create_dir_all(&backup_dir);
            let leaf = rest.rsplit('\\').next().unwrap_or("key");
            let file = backup_dir.join(format!("{}_{}.reg", crate::engine::now_ms(), leaf));
            let Some(file_str) = file.to_str() else {
                details.push(detail(kind, target, "fail", "备份路径无法表示为文本，拒绝删除"));
                continue;
            };
            // v2-L4P-29（B-7）：备份类子进程统一走带超时入口
            let backup_ok = crate::engine::systembin::quiet_cmd_timeout(
                crate::engine::systembin::system_tool("reg.exe"),
                &["export", key_part, file_str, "/y"],
                crate::engine::systembin::REG_EXPORT_TIMEOUT,
            )
            .map(|o| o.status.success() && file.exists())
            .unwrap_or(false);
            if !backup_ok {
                details.push(detail(kind, target, "fail", "注册表备份失败，未执行删除（fail-closed）"));
                continue;
            }
            // D2：封条记的是**被备份的父键**（删单值前整父键导出，还原粒度也是父键）
            write_reg_backup_seal(&file, key_part);
            // N3：与 reg_key 分支同一口径裁保留上限（同一目录，两处都要裁，漏一处
            // 就等于"删值的备份不参与限额"，盘上照样无限涨）
            crate::engine::paths::prune_backups(&backup_dir, crate::engine::paths::BACKUP_KEEP);
            if let Some(p) = pack.as_mut() {
                // 副本只为「一批一个去处」；写注册表的还原入口仍然只有 uninstall_reg_backup_restore
                if let Err(e) = p.include_reg_backup(&file) {
                    details.push(detail(kind, target, "skip", &format!("{e}（.reg 原件仍在，可用原还原入口）")));
                }
            }
            if crate::engine::native::reg_restore_delete(hive, rest, value_name) {
                details.push(detail(kind, target, "ok", "已删除（备份已留存）"));
            } else {
                details.push(detail(kind, target, "fail", "注册表值删除失败"));
            }
        }

        // 文件/目录/快捷方式：回收站批量（trim_finder 三端同源删除，含 protect 注入）
        let paths: Vec<(String, OsString)> = ops
            .iter()
            .filter_map(|o| match o {
                ResidueOp::Path { kind, target } => Some((kind.clone(), target.clone())),
                _ => None,
            })
            .collect();
        // 勾了备份：先逐个入包，**入包失败的那一项不删**（与注册表「备份失败不删」同口径）。
        // 顺序很关键——先打包后删除，反过来就可能出现「文件已进回收站、包里没这条」
        let paths: Vec<(String, OsString)> = match pack.as_mut() {
            None => paths,
            Some(p) => {
                let mut keep: Vec<(String, OsString)> = Vec::new();
                for (k, t) in paths {
                    match p.add_target(Path::new(&t)) {
                        Ok(_) => keep.push((k, t)),
                        Err(e) => {
                            let s = t.to_string_lossy().to_string();
                            details.push(detail(&k, &s, "skip", &format!("还原包写入失败，未删除: {e}")));
                        }
                    }
                }
                keep
            }
        };
        if !paths.is_empty() {
            if let Some((_, target)) = paths
                .iter()
                .find(|(_, t)| protect::is_path_protected(&t.to_string_lossy()))
            {
                // 兜底重复检查：分类阶段已 Abort 过，这里再挡一次是为了让"整批拒绝"
                // 不依赖 classify 的实现细节（受保护路径出现即整批不动，语义不变）
                log::write_log("warn", &format!("uninstall_residue_execute 拒绝: 受保护路径 {}", target.to_string_lossy()));
                return Err(format!("包含受保护的系统路径，已拒绝：{}", target.to_string_lossy()));
            }
            let protect_json = protect::protected_roots_json();
            // 删除结果行解析 Sink：只收 @@ITEM@@ 行里的 delresult（对齐 finder 的 FinderSink 口径）
            //
            // 审查 L-23（2026-10-03 L4）：解析失败原本是**静默 return**，且 `warn` 是
            // 显式空实现 —— 也就是说删除结果行凭空消失时**一点痕迹都不留**，用户看到的
            // 回执里那一条就是「没删也没记录」。与 L-21（@@LOCKED@@）、L-22（@@RECYCLE@@）、
            // apply.rs（M-1）同基线「畸形行必须计数或告警」。这里改成：解析失败即计数，
            // 扫描结束后统一 warn 一次（warn 是热路径，逐行打日志会淹掉日志）。
            struct RowSink {
                rows: Mutex<Vec<Value>>,
                malformed: Mutex<usize>,
            }
            impl RowSink {
                fn count_malformed(&self) {
                    *self.malformed.lock().unwrap_or_else(|e| e.into_inner()) += 1;
                }
                fn malformed(&self) -> usize {
                    *self.malformed.lock().unwrap_or_else(|e| e.into_inner())
                }
            }
            impl trim_finder::scan::Sink for RowSink {
                fn item(&self, _p: &Path, line: &str) {
                    let Some(body) = line.strip_prefix("@@ITEM@@") else { return };
                    // 空体行是 @@ITEM@@{ 之后的续行被拆行时的产物，与 JSON 解析失败同口径
                    if body.trim().is_empty() {
                        self.count_malformed();
                        return;
                    }
                    let Ok(v) = trim_finder::cleanup_scan::parse_json(body) else {
                        self.count_malformed();
                        return;
                    };
                    if v.get("type").and_then(|t| t.as_str()) != Some("delresult") {
                        // 非 delresult 行是协议内的正常行（进度/目录项等），不算畸形
                        return;
                    }
                    let jnum = |j: Option<&trim_finder::cleanup_scan::Json>| -> u64 {
                        match j {
                            Some(trim_finder::cleanup_scan::Json::Num(n)) => *n as u64,
                            _ => 0,
                        }
                    };
                    let path = v.get("path").and_then(|p| p.as_str()).unwrap_or("");
                    if path.is_empty() {
                        // delresult 行却没有 path：回执里会挂一条空路径的 detail，
                        // 形状上无法与真实删除结果区分 —— 计畸形，不进 details
                        self.count_malformed();
                        return;
                    }
                    self.rows.lock().unwrap_or_else(|e| e.into_inner()).push(json!({
                        "kind": match v.get("kind").and_then(|k| k.as_str()) {
                            Some("dir") => "dir",
                            _ => "file",
                        },
                        "path": path,
                        "status": v.get("status").and_then(|s| s.as_str()).unwrap_or(""),
                        "freed": jnum(v.get("freed")),
                    }));
                }
                fn progress(&self, _n: u64) {}
                fn scanned(&self, _n: u64) {}
                fn warn(&self, m: &str) {
                    // 扫描器自己发的告警不能吞：它是「部分失败」的唯一线索
                    log::write_log("warn", &format!("残留删除扫描器告警: {m}"));
                }
                fn truncated(&self) {}
            }
            let sink = RowSink {
                rows: Mutex::new(Vec::new()),
                malformed: Mutex::new(0),
            };
            let _ = trim_finder::scan::delete(&paths, Some(protect_json.as_str()), &sink);
            if sink.malformed() > 0 {
                log::write_log(
                    "warn",
                    &format!(
                        "残留删除回执含 {} 条畸形 @@ITEM@@ delresult 行，已跳过（扫描器协议异常）",
                        sink.malformed()
                    ),
                );
            }
            // P2-D4：只读占用自检只花在真正失败的文件行上，且最多查 3 个——模块枚举是
            // 全进程开销，为拼提示文案不值得在整批全败时查几十次；目录行不查（目录不是
            // 可加载模块，占用的也是里面的文件，逐个查反而把消息拉长）。
            let mut probe_budget = 3usize;
            for row in sink.rows.into_inner().unwrap_or_default() {
                let ok = row["status"] == "ok";
                let message = if ok {
                    "已移入回收站".to_string()
                } else {
                    match row["kind"].as_str() {
                        Some("file") if probe_budget > 0 => {
                            probe_budget -= 1;
                            row["path"]
                                .as_str()
                                .map(|p| occupancy_note(Path::new(p)))
                                .unwrap_or_else(|| "删除失败".to_string())
                        }
                        _ => row["path"]
                            .as_str()
                            .map(|_| "删除失败（可能被占用）".to_string())
                            .unwrap_or_else(|| "删除失败".to_string()),
                    }
                };
                details.push(detail(
                    row["kind"].as_str().unwrap_or("file"),
                    row["path"].as_str().unwrap_or(""),
                    if ok { "ok" } else { "fail" },
                    &message,
                ));
            }
        }
        // 收尾：包要落 manifest 才算成。内容已删而包没写成 ⇒ 回执必须带 error，
        // 不能让用户以为「备份好了」
        let pack_out = match pack {
            Some(p) => match p.finish() {
                Ok(v) => Some(v),
                Err(e) => {
                    log::write_log("error", &format!("还原包收尾失败（文件已删，内容不可还原）: {e}"));
                    Some(json!({ "error": e }))
                }
            },
            None => None,
        };
        Ok((details, pack_out))
    })
    .await;

    match report {
        Ok(Ok((details, pack_out))) => {
            let ok_count = details.iter().filter(|d| d["status"] == "ok").count();
            let fail_count = details.iter().filter(|d| d["status"] == "fail").count();
            // 批次报告（方案 M4）：动作级明细落盘，失败如实呈现
            let report_path = crate::engine::paths::app_data_dir()
                .join("uninstall-reports")
                .join(format!("{batch_id}.json"));
            let _ = std::fs::create_dir_all(report_path.parent().unwrap_or(Path::new(".")));
            let _ = crate::security::atomic_write_json(
                &report_path,
                &json!({
                    "batchId": batch_id, "appId": app_id,
                    "time": delete_manifest::iso_now(),
                    "details": details,
                    // 报告里留一笔：还原包被保留策略裁掉后，报告仍能说明「当时备过什么」
                    "restorePack": pack_out,
                }),
            );
            log::write_log("info", &format!("uninstall_residue_execute {app_id}: 成功 {ok_count} 失败 {fail_count}（报告 {batch_id}）"));
            // HiBit §H3 回写：学到几条就记几条，0 条不写文件也不报错（学习是附加价值）。
            // 放在报告落盘之后：报告是「删了什么」的凭据，不能被学习链的不确定性挡住。
            let learned_added = learn_from_deletions(&app_id, &details);
            if learned_added > 0 {
                log::write_log("info", &format!("本机学习库新增 {learned_added} 条落点（下轮同程序残留直接命中）"));
            }
            json!({ "success": true, "data": {
                "details": details, "okCount": ok_count, "failCount": fail_count,
                "reportPath": report_path.to_string_lossy(),
                "restorePack": pack_out,
                "learnedAdded": learned_added,
            } })
        }
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("残留清理异常: {e}") }),
    }
}

