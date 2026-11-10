//! B7 paths_scan：按规则表达式扫描已安装软件路径。
//!
//! `normalize_path` / InventoryEntry 只服务本域的扫描语义，不与 `engine::paths`（应用数据
//! 目录与迁移）混为一谈 —— 两者同名易混，故独立成文件。
//!
//! 规则表达式求值（`resolve_rule_path`）自 2026-10-16（E5）起**委托唯一实现**
//! `trim_finder::cleanup_scan::resolve_rule_path`：此前本文件另有一份字节级手写解析器，
//! 与 native-scanner 的字符级实现语义相同、两侧又都无直测——同一判定两份实现正是
//! §5.16/N6 禁止的形态（形似而实异迟早分叉），收敛掉。

use trim_finder::cleanup_scan::resolve_rule_path;
use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW};
use super::common::*;
use super::registry::*;
// ==================== B7 paths_scan：安装路径自动扫描 ====================
/// 路径出口（v5-K02 批次 1，R5b-M09）：本域所有「把路径交给下游 / 落盘」的值都过这里。
///
/// `canonicalize` 成功时返回 verbatim 形态（实测 `C:\Windows\System32 →
/// \\?\C:\Windows\System32`、`C:\Program Files → \\?\C:\Program Files`），而 glob 分支
/// 的值来自 `read_dir` 的 `entry.path()`（无前缀）⇒ 同一份 `paths-config.json` 两种形状，
/// UI 输入框也会把未剥前缀的路径直接显示给用户（placeholder 写的是 `C:\Program Files\…`）。
/// 盘符根更糟：`C:\` canonicalize 成 `\\?\C:`，旧代码无差别 `trim_end_matches('\\')`
/// 会把根削成驱动器相对形态。
///
/// 口径：剥 `\\?\UNC\`（还原成 `\\server\share`）与 `\\?\`；盘符根（`C:`）补回尾杠
/// 保持根语义，其余去尾杠。删除/还原侧的判定归一口径在 `protect::normalize_for_compare`
/// （verbatim 在那里被剥掉后比较），此处管的是**落盘与展示形状**，两边同源不同层。
fn emit_path(p: &std::path::Path) -> String {
    let s = p.to_string_lossy().to_string();
    let stripped = if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s
    };
    let b = stripped.as_bytes();
    if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        // 盘符根：`C:` 是驱动器相对、`C:\` 才是根——补回尾杠，不削
        return format!("{stripped}\\");
    }
    if b.len() == 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
        // R5b-M04：`\\?\C:\` 剥前缀后是 `C:\`——保留尾杠，不能再 trim 成 `C:`
        //（`C:` 是驱动器相对，删除/展示目标会变）。
        return stripped;
    }
    stripped.trim_end_matches('\\').to_string()
}

/// 路径标准化（对应 PS 的 Normalize-Path）
fn strip_icon_suffix(s: &str) -> String {
    let Some(pos) = s.rfind(',') else { return s.to_string() };
    let (prefix, suffix) = s.split_at(pos);
    let idx = suffix[1..].trim();
    let lower = prefix.trim().to_lowercase();
    let exe_like = [".exe", ".dll", ".msi", ".cmd", ".bat"].iter().any(|e| lower.ends_with(e));
    if exe_like && !idx.is_empty() && idx.parse::<i32>().is_ok() {
        prefix.trim().to_string()
    } else {
        s.to_string()
    }
}

fn normalize_path(value: &str) -> String {
    let trimmed = value.trim();
    // R5b-L01：带引号的 DisplayIcon 形如 `"C:\...\notepad.exe",0`。必须先在
    // `",` 处切掉图标序号，再剥外层引号；反过来会先吃掉路径尾引号，把 `,0`
    // 留在路径里，canonicalize 失败后整串被当成安装路径展示。
    let unquoted = if let Some(rest) = trimmed.strip_prefix('"') {
        match rest.find("\",") {
            Some(end) => &rest[..end],
            None => trimmed.trim_matches('"'),
        }
    } else {
        trimmed.trim_matches('"')
    };
    let v = unquoted.trim();
    if v.is_empty() { return String::new(); }
    let expanded = expand_env(v);
    // R5b-M02：先剥末尾 `,<数字>` 图标索引（`C:\Program Files\App\app.exe,0` 的首个空格
    // 在 Program Files 里，旧「首个逗号或空格」判法永远剥不掉）。
    let v = strip_icon_suffix(&expanded);
    match std::path::Path::new(&v).canonicalize() {
        // v5-K02 批次 1（R5b-M09）：过统一出口剥 verbatim，与 glob 分支同形状
        Ok(p) => emit_path(&p),
        Err(_) => v.trim_end_matches('\\').to_string(),
    }
}

/// 从 App Paths 解析 exe 所在目录
///
/// R5b-M03：一次 `RegOpenKeyExW` 只配一次 `RegCloseKey`。旧写法在 `if let Some(exe)` 里先关
/// 一次、分支尾再关一次——「值读到了但路径不是文件」（陈旧 App Paths、卸载残留，常态）时
/// 同一句柄被关两次；第一次关闭后该句柄值可被其它线程复用，第二次关闭落在谁身上不确定
/// （`NtClose` 语义），而被 `let _ =` 吞掉后永远看不见。故把关闭收敛到分支外一次。
unsafe fn resolve_from_app_paths(exe_name: &str) -> String {
    for root in [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
    ] {
        let key_path = format!("{root}\\{exe_name}");
        let sk = to_wide(&key_path);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { continue; }
        let mut hit = String::new();
        if let Some(exe) = reg_read_string(hk, "") {
            let norm = normalize_path(&exe);
            if !norm.is_empty() && std::path::Path::new(&norm).is_file() {
                hit = std::path::Path::new(&norm).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            }
        }
        let _ = RegCloseKey(hk);
        if !hit.is_empty() { return hit; }
    }
    // HKCU：同口径（开一次、关一次）
    let key_path = format!(r"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}");
    let sk = to_wide(&key_path);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
        let mut hit = String::new();
        if let Some(exe) = reg_read_string(hk, "") {
            let norm = normalize_path(&exe);
            if !norm.is_empty() && std::path::Path::new(&norm).is_file() {
                hit = std::path::Path::new(&norm).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            }
        }
        let _ = RegCloseKey(hk);
        if !hit.is_empty() { return hit; }
    }
    String::new()
}

/// 软件清单条目
#[derive(Debug)]
struct InventoryEntry { name: String, install_path: String }

/// 枚举卸载注册表构建软件清单（可注入闭包，便于单测模拟权限拒绝）。
///
/// `open_root(hive, root)` 返回子键名列表；`None` = 根键打不开（权限/IO）。
/// `read_sub(hive, root, sub)` 返回 `Ok((name, install_path))`；`Err(())` = 子键打不开。
///
/// 返回 `(entries, skipped)`，`skipped` 是根键/子键打开失败的次数。
/// R5b-L04：旧实现根键/子键 `RegOpenKeyExW` 失败时直接 `continue`，回执既不报 skipped
/// 也不判 partial，卸载清单被静默截断却长得像「完整枚举」。这里与 glob 分支同口径：
/// 读不动必须在日志留痕，并把 skipped 数带回给命令层。
fn inventory_scan(
    roots: &[(HKEY, &str)],
    open_root: &dyn Fn(HKEY, &str) -> Option<Vec<String>>,
    read_sub: &dyn Fn(HKEY, &str, &str) -> Result<(String, String), ()>,
) -> (Vec<InventoryEntry>, usize) {
    let mut entries: Vec<InventoryEntry> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut skipped = 0usize;
    for (hive, root) in roots {
        let Some(subs) = open_root(*hive, root) else {
            skipped += 1;
            crate::engine::log::write_log(
                "warn",
                &format!("路径扫描：卸载注册表根键打开失败（{root}），该根已跳过"),
            );
            continue;
        };
        for sub in subs {
            let (name, install) = match read_sub(*hive, root, &sub) {
                Ok(v) => v,
                Err(()) => {
                    skipped += 1;
                    crate::engine::log::write_log(
                        "warn",
                        &format!("路径扫描：卸载子键读取失败（{root}\\{sub}），已跳过"),
                    );
                    continue;
                }
            };
            if name.trim().is_empty() || install.is_empty() { continue; }
            let key = format!("{}|{}", name.trim().to_lowercase(), install.to_lowercase());
            if seen.insert(key) {
                entries.push(InventoryEntry { name: name.trim().to_string(), install_path: install });
            }
        }
    }
    (entries, skipped)
}

/// 生产路径：真实注册表枚举卸载项。
unsafe fn build_inventory() -> (Vec<InventoryEntry>, usize) {
    let roots = [
        (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ];
    inventory_scan(
        &roots,
        &|hive, root| {
            let sk = to_wide(root);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
                return None;
            }
            let subs = reg_enum_subkeys(hk);
            let _ = RegCloseKey(hk);
            Some(subs)
        },
        &|hive, root, sub| {
            let sub_path = format!("{root}\\{sub}");
            let ssk = to_wide(&sub_path);
            let mut shk = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(ssk.as_ptr()), Some(0), KEY_READ, &mut shk).is_err() {
                return Err(());
            }
            let name = reg_read_string(shk, "DisplayName").unwrap_or_default();
            // 跳过系统组件和更新（SystemComponent 是 DWORD；ReleaseType 是字符串）
              let sys_comp = reg_read_dword_u32(shk, "SystemComponent").unwrap_or(0);
            let release_type = reg_read_string(shk, "ReleaseType").unwrap_or_default();
            let mut install = String::new();
            for field in ["InstallLocation", "DisplayIcon", "UninstallString"] {
                if let Some(v) = reg_read_string(shk, field) {
                    let norm = normalize_path(&v);
                    if !norm.is_empty() {
                        if std::path::Path::new(&norm).is_file() {
                            install = std::path::Path::new(&norm).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                        } else if std::path::Path::new(&norm).is_dir() {
                            install = norm;
                        }
                        if !install.is_empty() { break; }
                    }
                }
            }
            let _ = RegCloseKey(shk);
            if uninstall_entry_is_hidden(sys_comp, &release_type) {
                return Ok((String::new(), String::new()));
            }
            Ok((name, install))
        },
    )
}

/// 从软件清单按名称模式匹配安装路径
fn find_installed_match(inventory: &[InventoryEntry], patterns: &[&str]) -> String {
    for entry in inventory {
        let name_lower = entry.name.to_lowercase();
        for p in patterns {
            if name_lower.contains(&p.to_lowercase()) {
                return entry.install_path.clone();
            }
        }
    }
    String::new()
}

/// 取第一个存在的目录
fn first_existing(candidates: &[String]) -> String {
    for c in candidates {
        if c.is_empty() { continue; }
        let norm = normalize_path(c);
        if std::path::Path::new(&norm).is_dir() { return norm; }
    }
    String::new()
}

/// 简单 glob：只支持路径中的单个 * 目录通配，按修改时间降序取第一个
fn glob_first_dir(pattern: &str) -> String {
    let parts: Vec<&str> = pattern.split('\\').collect();
    let mut current = String::new();
    for (i, part) in parts.iter().enumerate() {
        if part.contains('*') {
            // 当前 current 是目录，枚举子目录匹配
            let dir = if current.is_empty() { "\\".to_string() } else { current.clone() };
            // R5b-L04：读不动 ≠ 没找到。glob 只是候选发现，仍返回空串（回执三态需要
            // 命令层/持久化契约变更，不在本单元范围），但失败必须在日志里留痕。
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    crate::engine::log::write_log(
                        "warn",
                        &format!("路径扫描：glob 目录枚举失败（{dir}）: {e}"),
                    );
                    return String::new();
                }
            };
            let mut matched: Vec<std::path::PathBuf> = Vec::new();
            for entry in entries.flatten() {
                if !entry.path().is_dir() { continue; }
                let fname = entry.file_name().to_string_lossy().to_string();
                // 简单 * 匹配
                let pat = part.replace('*', "");
                if fname.contains(&pat) || pat.is_empty() {
                    matched.push(entry.path());
                }
            }
            if let Some(first) = pick_newest_file(&matched) {
                current = first.to_string_lossy().to_string();
            } else { return String::new(); }
        } else {
            if current.is_empty() {
                current = part.to_string();
            } else {
                current = format!("{current}\\{part}");
            }
        }
        // 后续部分直接拼接
        if i < parts.len() - 1 && !part.contains('*') {
            // 继续
        }
    }
    if std::path::Path::new(&current).is_dir() {
        // v5-K02 批次 1（R5b-M09）：与 canonicalize 分支走同一出口，保证一函数一形状
        emit_path(std::path::Path::new(&current))
    } else {
        String::new()
    }
}

/// 安装路径扫描（原 PS 时代脚本 paths_scan.ps1，已退役；S3 简化版）
///
/// 覆盖：规则表达式解析、卸载注册表枚举、App Paths、应用安装路径多级兜底、
/// 用户数据目录、缓存目录、glob 匹配。开始菜单 .lnk 目标解析暂未实现（S2 用 IShellLink COM）。
pub fn paths_scan(rules_json: &str) -> Result<Value, String> {
    unsafe {
        let (inventory, skipped) = build_inventory();

        // 解析规则库中的候选目录
        let mut rule_cache: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        let mut rule_wechat_globs: Vec<String> = Vec::new();
        if !rules_json.is_empty() {
            if let Ok(rules) = serde_json::from_str::<Value>(rules_json) {
                let mut rule_map: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
                if let Some(groups) = rules.get("groups").and_then(|g| g.as_array()) {
                    for g in groups {
                        if let Some(sgs) = g.get("subGroups").and_then(|s| s.as_array()) {
                            for sg in sgs {
                                if let Some(items) = sg.get("items").and_then(|i| i.as_array()) {
                                    for it in items {
                                        if let Some(id) = it.get("id").and_then(|i| i.as_str()) {
                                            rule_map.insert(id.to_string(), it.clone());
                                        }
                                    }
                                }
                            }
                        } else if let Some(items) = g.get("items").and_then(|i| i.as_array()) {
                            for it in items {
                                if let Some(id) = it.get("id").and_then(|i| i.as_str()) {
                                    rule_map.insert(id.to_string(), it.clone());
                                }
                            }
                        }
                    }
                }
                for id in ["neteaseMusicCache", "qqCache", "douyinCache"] {
                    if let Some(r) = rule_map.get(id) {
                        if let Some(exprs) = r.get("candidatesPs").and_then(|e| e.as_array()) {
                            let mut paths = Vec::new();
                            for expr in exprs {
                                if let Some(s) = expr.as_str() {
                                    if let Some(resolved) = resolve_rule_path(s) {
                                        if !resolved.is_empty() { paths.push(resolved); }
                                    }
                                }
                            }
                            rule_cache.insert(id.to_string(), paths);
                        }
                    }
                }
                if let Some(w) = rule_map.get("wechatCache") {
                    if let Some(exprs) = w.get("globCandidatesPs").and_then(|e| e.as_array()) {
                        for expr in exprs {
                            if let Some(s) = expr.as_str() {
                                if let Some(resolved) = resolve_rule_path(s) {
                                    if !resolved.is_empty() { rule_wechat_globs.push(resolved); }
                                }
                            }
                        }
                    }
                }
            }
        }

        let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let programfiles = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let programfilesx86 = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
        let userprofile = std::env::var("USERPROFILE").unwrap_or_default();
        let appdata = std::env::var("APPDATA").unwrap_or_default();

        // QQ 安装路径
        let qq_install = first_existing(&[
            format!("{localappdata}\\Programs\\Tencent\\QQNT"),
            format!("{programfiles}\\Tencent\\QQNT"),
            format!("{programfilesx86}\\Tencent\\QQNT"),
            resolve_from_app_paths("QQ.exe"),
            find_installed_match(&inventory, &["QQ"]),
        ]);
        let qq_install = if qq_install.is_empty() {
            first_existing(&[format!("{localappdata}\\Tencent\\QQNT")])
        } else { qq_install };

        // 微信安装路径
        let wechat_install = first_existing(&[
            format!("{localappdata}\\Programs\\Tencent\\WeChat"),
            format!("{programfiles}\\Tencent\\WeChat"),
            format!("{programfilesx86}\\Tencent\\WeChat"),
            resolve_from_app_paths("WeChat.exe"),
            resolve_from_app_paths("WeChatApp.exe"),
            find_installed_match(&inventory, &["WeChat", "微信"]),
        ]);

        // 抖音安装路径
        let douyin_install = first_existing(&[
            format!("{localappdata}\\Douyin"),
            format!("{localappdata}\\Programs\\Douyin"),
            format!("{localappdata}\\TikTok"),
            resolve_from_app_paths("Douyin.exe"),
            find_installed_match(&inventory, &["Douyin", "抖音", "TikTok"]),
        ]);

        // 网易云音乐安装路径
        let netease_install = first_existing(&[
            format!("{localappdata}\\Programs\\Netease\\CloudMusic"),
            format!("{programfiles}\\CloudMusic"),
            format!("{programfilesx86}\\CloudMusic"),
            format!("{programfiles}\\Netease\\CloudMusic"),
            resolve_from_app_paths("CloudMusic.exe"),
            find_installed_match(&inventory, &["CloudMusic", "网易云音乐"]),
        ]);

        // 用户数据目录
        let qq_file_dir = first_existing(&[
            format!("{userprofile}\\Documents\\Tencent Files"),
            format!("{userprofile}\\Documents\\QQ Files"),
            format!("{appdata}\\Tencent\\QQ\\Files"),
        ]);
        let wx_root = first_existing(&[
            format!("{userprofile}\\Documents\\xwechat_files"),
            format!("{userprofile}\\Documents\\WeChat Files"),
        ]);
        let wechat_file_dir = wx_root.clone();

        // 微信缓存目录（glob 匹配最近用户目录）
        let wechat_cache = if !wx_root.is_empty() {
            let leaf = std::path::Path::new(&wx_root).file_name()
                .and_then(|n| n.to_str()).unwrap_or("");
            if leaf != "xwechat_files" && leaf != "WeChat Files" {
                format!("{wx_root}\\temp")
            } else {
                let patterns = if !rule_wechat_globs.is_empty() {
                    rule_wechat_globs.clone()
                } else {
                    vec![
                        format!("{userprofile}\\Documents\\xwechat_files\\*\\temp"),
                        format!("{userprofile}\\Documents\\WeChat Files\\*\\FileStorage\\Cache"),
                    ]
                };
                let mut found = String::new();
                for pat in patterns {
                    found = glob_first_dir(&pat);
                    if !found.is_empty() { break; }
                }
                found
            }
        } else { String::new() };

        // 缓存目录
        let mut netease_candidates = rule_cache.get("neteaseMusicCache").cloned().unwrap_or_default();
        netease_candidates.extend([
            format!("{localappdata}\\NetEase\\CloudMusic\\Cache"),
            format!("{localappdata}\\Netease\\CloudMusic\\Cache"),
            format!("{appdata}\\NetEase\\CloudMusic\\Cache"),
        ]);
        let netease_cache = first_existing(&netease_candidates);

        let mut douyin_candidates = rule_cache.get("douyinCache").cloned().unwrap_or_default();
        douyin_candidates.extend([
            format!("{localappdata}\\Douyin"),
            format!("{localappdata}\\TikTok"),
        ]);
        let douyin_cache = first_existing(&douyin_candidates);

        let mut qq_candidates = rule_cache.get("qqCache").cloned().unwrap_or_default();
        qq_candidates.extend([
            format!("{localappdata}\\Tencent\\QQNT\\User Data\\Cache"),
            format!("{appdata}\\Tencent\\QQ\\Cache"),
            format!("{appdata}\\Tencent Files\\Cache"),
        ]);
        let qq_cache = first_existing(&qq_candidates);

        Ok(json!({
            "qqInstallPath": qq_install,
            "wechatInstallPath": wechat_install,
            "douyinInstallPath": douyin_install,
            "neteaseMusicInstallPath": netease_install,
            "qqFileDir": qq_file_dir,
            "wechatFileDir": wechat_file_dir,
            "neteaseCacheDir": netease_cache,
            "wechatCacheDir": wechat_cache,
            "douyinCacheDir": douyin_cache,
            "qqCacheDir": qq_cache,
            // R5b-L04：根键/子键读不动时必须如实上报——卸载清单被静默截断却长得像
            // 「完整枚举」会让路径匹配静默漏掉目标。skipped > 0 即 partial。
            "skipped": skipped,
            "partial": skipped > 0,
            "scanVersion": 2,
            // 时间戳**不在这里产生**：本函数只负责找路径。扫描时间由命令层
            // （`commands::paths`）统一以 ISO-8601 写入 —— 此前这里塞的是
                // `format!("{:?}", SystemTime::now())` 的 Debug 形态，JS `new Date()`
                // 解析不了，页脚恒显 "Invalid Date"（用户 2026-10-07 反馈）。
        }))
    }
}

// ==================== 卸载条目可见性判据（纯函数） ====================

/// 卸载条目的「不可见」判据（纯函数 —— 不依赖真实注册表，才能在单测里钉住）。
///
/// `SystemComponent` 是 **DWORD**（值 `1` = 系统组件）：原先按字符串读，类型闸恒不过 ⇒
/// `"" == "1"` 恒假 ⇒ 「跳过系统组件」这道过滤器从来没生效过（回归条 R5b-M15），
/// 卸载清单被系统组件条目放大。`ReleaseType` 是字符串，含 update / hotfix / security
/// 的同样属系统侧条目。
pub(super) fn uninstall_entry_is_hidden(sys_comp: u32, release_type: &str) -> bool {
    if sys_comp == 1 { return true; }
    let rt = release_type.to_lowercase();
    rt.contains("update") || rt.contains("hotfix") || rt.contains("security")
}

#[cfg(test)]
mod tests {
    use super::{inventory_scan, normalize_path, uninstall_entry_is_hidden};
    use windows::Win32::System::Registry::HKEY;

    /// R5b-M15 回归钉：`SystemComponent` 是 DWORD，按字符串读时判据恒假 ⇒ 过滤器失效。
    #[test]
    fn 系统组件过滤器必须认dword值() {
        assert!(uninstall_entry_is_hidden(1, ""), "DWORD 值 1 必须判为系统组件");
        assert!(!uninstall_entry_is_hidden(0, ""), "DWORD 值 0 不是系统组件");
        assert!(!uninstall_entry_is_hidden(2, ""), "其它 DWORD 值不是系统组件");
    }

    #[test]
    fn 发布类型过滤器保持原口径() {
        assert!(uninstall_entry_is_hidden(0, "Security Update"));
        assert!(uninstall_entry_is_hidden(0, "hotfix"));
        assert!(!uninstall_entry_is_hidden(0, "Full Application"));
    }

    // ==================== R5b-M03：注册表句柄开合一对一 ====================

    /// 取 `marker` 起点到下一个顶层声明之前的片段（本文件顶层 `fn` / `struct` 都在第 0 列）。
    ///
    /// 不用花括号配平：函数体里 `format!("{root}\\{exe_name}")` 这类字符串字面量本身带
    /// 花括号，配平版会在字面量上算错深度。
    fn prod_fn_body<'a>(src: &'a str, marker: &str) -> &'a str {
        let start = src.find(marker).unwrap_or_else(|| panic!("找不到 {marker}"));
        let tail = &src[start + marker.len()..];
        let mut cut = tail.len();
        for anchor in ["\nfn ", "\nunsafe fn ", "\nstruct ", "\n// ===================="] {
            if let Some(i) = tail.find(anchor) {
                cut = cut.min(i);
            }
        }
        &src[start..start + marker.len() + cut]
    }

    /// R5b-M03 回归钉：`resolve_from_app_paths` 里每次 `RegOpenKeyExW` 只允许配一次
    /// `RegCloseKey`，且关闭不得下沉到内层 `if let`。
    ///
    /// 为什么用源码形态断言：旧缺陷只有「值读到但路径不是文件」（陈旧 App Paths /
    /// 卸载残留）这一条运行时分支可达，本仓的单测不真开注册表、改不了 App Paths，
    /// 行为用例钉不住它；而「同一句柄关两次」是**源码形态**。
    ///
    /// 判红自证：把 `if let Some(exe)` 块里那条 `let _ = RegCloseKey(hk);` 加回去
    /// （即退回旧写法）⇒ 关闭数 3 > 打开数 2，且该行缩进 12 > 8，本条红。
    #[test]
    fn 句柄开合必须一一配对() {
        let src = include_str!("paths_scan.rs");
        let prod = &src[..src.find("mod tests").expect("找不到单测段起点")];
        let body = prod_fn_body(prod, "fn resolve_from_app_paths");
        let opens = body.matches("RegOpenKeyExW(").count();
        let closes = body.matches("RegCloseKey(").count();
        assert_eq!(opens, 2, "函数体应只剩 HKLM 循环与 HKCU 两支：{opens}");
        assert_eq!(
            closes, opens,
            "每个 RegOpenKeyExW 只允许配一次 RegCloseKey（旧写法对同一句柄关两次）：\n{body}"
        );
        for line in body.lines().filter(|l| l.contains("RegCloseKey(")) {
            let indent = line.len() - line.trim_start().len();
            assert!(
                indent <= 8,
                "关闭不得出现在内层 if / if let 里（会与分支外的关闭重复）：{line}"
            );
        }
    }

    /// R5b-L01：带引号的 DisplayIcon 必须先切图标序号再剥引号。
    ///
    /// 判红自证：把 `normalize_path` 首行恢复成 `value.trim().trim_matches('"')`，
    /// `",0` 会留在路径尾部，`is_file` 断言红。
    #[test]
    fn r5b_quoted_display_icon_parses() {
        let exe = std::env::current_exe().expect("取当前测试程序路径");
        let raw = format!("\"{}\",0", exe.display());
        let parsed = normalize_path(&raw);
        assert!(
            std::path::Path::new(&parsed).is_file(),
            "带引号且带图标序号的 DisplayIcon 必须解析回真实 exe：{raw} -> {parsed}"
        );
        // 反向对照：不带图标序号的引号形态仍必须剥干净。
        let plain = normalize_path(&format!("\"{}\"", exe.display()));
        assert!(std::path::Path::new(&plain).is_file(), "{plain}");
    }

    /// R5b-L04：根键/子键打开失败时，回执必须带 `skipped` 并判 `partial`。
    /// 判红自证：把 `inventory_scan` 的失败分支恢复成静默 `continue` ⇒ skipped 恒 0，
    /// 本条断言红。
    #[test]
    fn r5b_inventory_reports_unreadable_root() {
        use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

        // 第一个根键权限拒绝（open_root 返回 None），其余根正常。
        let roots = [
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ];
        let open_root = |_hive: HKEY, root: &str| -> Option<Vec<String>> {
            if root.contains("WOW6432Node") {
                Some(vec!["AppA".to_string(), "AppB".to_string()])
            } else {
                None // 权限拒绝
            }
        };
        let read_sub = |_: HKEY, _: &str, sub: &str| -> Result<(String, String), ()> {
            match sub {
                "AppA" => Ok(("AppA".to_string(), r"C:\Program Files\AppA".to_string())),
                "AppB" => Ok(("AppB".to_string(), r"C:\Program Files\AppB".to_string())),
                _ => Err(()),
            }
        };
        let (entries, skipped) = inventory_scan(&roots, &open_root, &read_sub);
        assert_eq!(skipped, 1, "权限拒绝的根键必须计数 skipped");
        assert_eq!(entries.len(), 2, "可读根键的条目必须正常枚举：{entries:?}");
        assert!(
            entries.iter().all(|e| !e.name.is_empty() && !e.install_path.is_empty()),
            "{entries:?}"
        );

        // 子键打不开也要计数。
        let single_root = [(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")];
        let open_root2 = |_: HKEY, _: &str| -> Option<Vec<String>> {
            Some(vec!["AppA".to_string(), "Broken".to_string()])
        };
        let read_sub2 = |_: HKEY, _: &str, sub: &str| -> Result<(String, String), ()> {
            if sub == "Broken" { Err(()) } else { Ok(("AppA".to_string(), r"C:\Program Files\AppA".to_string())) }
        };
        let (entries, skipped) = inventory_scan(&single_root, &open_root2, &read_sub2);
        assert_eq!(skipped, 1, "打不开的子键必须计数 skipped");
        assert_eq!(entries.len(), 1, "能读的子键必须保留：{entries:?}");
    }

    /// R5b-L04 正向对照：全部根键可读时 skipped 必须为 0（不误报 partial）。
    #[test]
    fn r5b_inventory_all_readable_has_zero_skipped() {
        use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
        let roots = [(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")];
        let open_root = |_: HKEY, _: &str| -> Option<Vec<String>> { Some(vec!["AppA".to_string()]) };
        let read_sub = |_: HKEY, _: &str, sub: &str| -> Result<(String, String), ()> {
            if sub == "AppA" { Ok(("AppA".to_string(), r"C:\Program Files\AppA".to_string())) } else { Err(()) }
        };
        let (entries, skipped) = inventory_scan(&roots, &open_root, &read_sub);
        assert_eq!(skipped, 0, "全部可读时不得误报 skipped");
        assert_eq!(entries.len(), 1);
    }
}
