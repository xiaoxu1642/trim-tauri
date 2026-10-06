//! B7 paths_scan：按规则表达式扫描已安装软件路径。
//!
//! `resolve_rule_path` / `normalize_path` / InventoryEntry 只服务本域的扫描语义，
//! 不与 `engine::paths`（应用数据目录与迁移）混为一谈 —— 两者同名易混，故独立成文件。


use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW};
use super::common::*;
use super::registry::*;
// ==================== B7 paths_scan：安装路径自动扫描 ====================

/// 受限规则路径表达式解析器（对应 PS 的 Resolve-RulePath）
///
/// 语法：'字面量' + $env:VARNAME + (拼接组)，空白可穿插，单引号内 '' 转义为 '。
/// 解析失败返回 None（fail-closed，不猜测）。
fn resolve_rule_path(expr: &str) -> Option<String> {
    struct Parser<'a> { s: &'a [u8], i: usize, depth: u32 }
    impl<'a> Parser<'a> {
        fn skip_ws(&mut self) {
            while self.i < self.s.len() && (self.s[self.i] == b' ' || self.s[self.i] == b'\t') {
                self.i += 1;
            }
        }
        fn parse_prim(&mut self) -> Option<String> {
            self.depth += 1;
            if self.depth > 32 { return None; }
            self.skip_ws();
            if self.i >= self.s.len() { return None; }
            let c = self.s[self.i];
            if c == b'(' {
                self.i += 1;
                let v = self.parse_concat()?;
                self.skip_ws();
                if self.i >= self.s.len() || self.s[self.i] != b')' { return None; }
                self.i += 1;
                Some(v)
            } else if c == b'\'' {
                self.i += 1;
                let mut out = String::new();
                loop {
                    if self.i >= self.s.len() { return None; }
                    let ch = self.s[self.i];
                    if ch == b'\'' {
                        if self.i + 1 < self.s.len() && self.s[self.i + 1] == b'\'' {
                            out.push('\''); self.i += 2; continue;
                        }
                        self.i += 1; break;
                    }
                    out.push(ch as char);
                    self.i += 1;
                }
                Some(out)
            } else if c == b'$' {
                if self.i + 5 >= self.s.len() { return None; }
                if &self.s[self.i..self.i+5] != b"$env:" { return None; }
                self.i += 5;
                let start = self.i;
                while self.i < self.s.len() && self.s[self.i].is_ascii_alphanumeric() || (self.i < self.s.len() && self.s[self.i] == b'_') {
                    self.i += 1;
                }
                if self.i == start { return None; }
                let name = std::str::from_utf8(&self.s[start..self.i]).ok()?;
                Some(std::env::var(name).unwrap_or_default())
            } else {
                None
            }
        }
        fn parse_concat(&mut self) -> Option<String> {
            let mut acc = self.parse_prim()?;
            loop {
                let j = { let mut j = self.i; while j < self.s.len() && (self.s[j] == b' ' || self.s[j] == b'\t') { j += 1; } j };
                if j < self.s.len() && self.s[j] == b'+' {
                    self.i = j + 1;
                    acc.push_str(&self.parse_prim()?);
                } else { break; }
            }
            Some(acc)
        }
    }
    if expr.is_empty() { return None; }
    let mut p = Parser { s: expr.as_bytes(), i: 0, depth: 0 };
    let val = p.parse_concat()?;
    p.skip_ws();
    if p.i != p.s.len() { return None; }
    Some(val)
}

/// 路径标准化（对应 PS 的 Normalize-Path）
fn normalize_path(value: &str) -> String {
    let v = value.trim().trim_matches('"');
    if v.is_empty() { return String::new(); }
    let expanded = expand_env(v);
    // 兼容 "path.exe,0" 图标索引后缀
    let v = if let Some(pos) = expanded.find(|c: char| c == ',' || c == ' ') {
        let prefix = &expanded[..pos];
        if prefix.to_lowercase().ends_with(".exe") || prefix.to_lowercase().ends_with(".dll")
            || prefix.to_lowercase().ends_with(".msi") || prefix.to_lowercase().ends_with(".cmd")
            || prefix.to_lowercase().ends_with(".bat") {
            prefix.to_string()
        } else { expanded }
    } else { expanded };
    match std::path::Path::new(&v).canonicalize() {
        Ok(p) => p.to_string_lossy().trim_end_matches('\\').to_string(),
        Err(_) => v.trim_end_matches('\\').to_string(),
    }
}

/// 从 App Paths 解析 exe 所在目录
unsafe fn resolve_from_app_paths(exe_name: &str) -> String {
    for root in [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
    ] {
        let key_path = format!("{root}\\{exe_name}");
        let sk = to_wide(&key_path);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { continue; }
        if let Some(exe) = reg_read_string(hk, "") {
            let norm = normalize_path(&exe);
            let _ = RegCloseKey(hk);
            if !norm.is_empty() && std::path::Path::new(&norm).is_file() {
                return std::path::Path::new(&norm).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            }
        }
        let _ = RegCloseKey(hk);
    }
    // HKCU
    let key_path = format!(r"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}");
    let sk = to_wide(&key_path);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
        if let Some(exe) = reg_read_string(hk, "") {
            let norm = normalize_path(&exe);
            let _ = RegCloseKey(hk);
            if !norm.is_empty() && std::path::Path::new(&norm).is_file() {
                return std::path::Path::new(&norm).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            }
        }
        let _ = RegCloseKey(hk);
    }
    String::new()
}

/// 软件清单条目
struct InventoryEntry { name: String, install_path: String }

/// 枚举卸载注册表构建软件清单
unsafe fn build_inventory() -> Vec<InventoryEntry> {
    let mut entries: Vec<InventoryEntry> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (hive, root) in [
        (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ] {
        let sk = to_wide(root);
        let mut hk = HKEY::default();
        if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { continue; }
        for sub in reg_enum_subkeys(hk) {
            let sub_path = format!("{root}\\{sub}");
            let ssk = to_wide(&sub_path);
            let mut shk = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(ssk.as_ptr()), Some(0), KEY_READ, &mut shk).is_err() { continue; }
            let name = reg_read_string(shk, "DisplayName").unwrap_or_default();
            let _ = RegCloseKey(shk);
            if name.trim().is_empty() { continue; }
            // 跳过系统组件和更新
            let ssk2 = to_wide(&sub_path);
            let mut shk2 = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(ssk2.as_ptr()), Some(0), KEY_READ, &mut shk2).is_ok() {
                let sys_comp = reg_read_string(shk2, "SystemComponent").unwrap_or_default();
                let release_type = reg_read_string(shk2, "ReleaseType").unwrap_or_default();
                let _ = RegCloseKey(shk2);
                if sys_comp == "1" { continue; }
                let rt = release_type.to_lowercase();
                if rt.contains("update") || rt.contains("hotfix") || rt.contains("security") { continue; }
            }
            // 解析安装路径
            let ssk3 = to_wide(&sub_path);
            let mut shk3 = HKEY::default();
            let mut install = String::new();
            if RegOpenKeyExW(hive, PCWSTR(ssk3.as_ptr()), Some(0), KEY_READ, &mut shk3).is_ok() {
                for field in ["InstallLocation", "DisplayIcon", "UninstallString"] {
                    if let Some(v) = reg_read_string(shk3, field) {
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
                let _ = RegCloseKey(shk3);
            }
            if install.is_empty() { continue; }
            let key = format!("{}|{}", name.trim().to_lowercase(), install.to_lowercase());
            if seen.insert(key) {
                entries.push(InventoryEntry { name: name.trim().to_string(), install_path: install });
            }
        }
        let _ = RegCloseKey(hk);
    }
    entries
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
            let Ok(entries) = std::fs::read_dir(&dir) else { return String::new(); };
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
            matched.sort_by(|a, b| {
                let ta = a.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
                let tb = b.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
                tb.cmp(&ta)
            });
            if let Some(first) = matched.first() {
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
    if std::path::Path::new(&current).is_dir() { current } else { String::new() }
}

/// 安装路径扫描（对应 paths_scan.ps1，S3 简化版）
///
/// 覆盖：规则表达式解析、卸载注册表枚举、App Paths、应用安装路径多级兜底、
/// 用户数据目录、缓存目录、glob 匹配。开始菜单 .lnk 目标解析暂未实现（S2 用 IShellLink COM）。
pub fn paths_scan(rules_json: &str) -> Result<Value, String> {
    unsafe {
        let inventory = build_inventory();

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
            "scanVersion": 2,
            // 时间戳**不在这里产生**：本函数只负责找路径。扫描时间由命令层
            // （`commands::paths`）统一以 ISO-8601 写入 —— 此前这里塞的是
            // `format!("{:?}", SystemTime::now())` 的 Debug 形态，JS `new Date()`
            // 解析不了，页脚恒显 "Invalid Date"（用户 2026-10-07 反馈）。
        }))
    }
}
