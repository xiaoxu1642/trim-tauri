//! 游戏平台库清单（Steam / Epic / WeGame / Origin(EA) / Battle.net / Uplay / GOG）与
//! 「目录还在、清单里已没有」的游戏残留（v0.5.0 只读扫描器之一，方案 §3
//! `game_platform_orphan`；C 类二期 2026-10-16 扩四平台，机制源 = cankao/5 §3.2）。
//!
//! 这份索引同时是**反作弊条件保护**（方案 §2.2）的唯一判据来源：
//! 「游戏仍在库」= 平台清单里查得到它的安装目录。
//!
//! 两条口径上的硬规矩：
//! 1. 「读不到清单」不等于「不在库」。平台装着却读不出清单时进 `unreadable`，
//!    调用方必须降级成「无法判定」，不得据此把仍在用的反作弊驱动报成候选；
//!    平台根本没装才算合法的「不在库」。
//! 2. Steam 的库成员只认 `steamapps/appmanifest_<id>.acf` + `libraryfolders.vdf` 的
//!    `path` 拼 `installdir`。`libraryfolders.vdf` 里的 `apps` 字典只有体积与局部状态，
//!    **不含 installdir**，拿它拼路径会拼出一片不存在的目录（方案 §3 点名纠正的写法）。

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use super::dead::expand_pct;
use super::helpers::{reg_sz, to_wide};
use super::residue::reg_enum_subkeys;
use super::residue_update::contribs;

/// 单平台清单读取失败时写进 notes 的措辞（调用方共用，避免三种说法）
pub(crate) const UNREADABLE_SUFFIX: &str = "清单读取失败，本轮不参与「在库/已卸载」判定";

/// 一台机器上游戏记录的上限（Steam 单库常见 50~200 个，留足余量防爆）。
/// C 类二期起这是**全局公平配额**的额度：超限由 `fair_trim` 从最多平台逐条扣，
/// 不按 collector 顺序让后跑的平台饿死（截断计数逐平台外发 notes）。
const RECORD_CAP: usize = 600;
/// 采集期噪声护栏（C 类二期）：单平台读到这个量级即停读，防病态机器把采集拖死；
/// 它只管安全上界，对外可见的截断注记由 `fair_trim` 按全局配额给出。
const COLLECT_HARD_CAP: usize = 2400;
/// 每个库根下 `steamapps/common` 的目录枚举上限。
/// allow(dead_code)：仅被下方 list_game_dirs 消费，而该族是「未跟踪游戏目录发现」
/// 预留能力（单测覆盖、生产侧尚未接线），接线后随该族一起移除 allow。
#[allow(dead_code)]
const COMMON_DIR_CAP: usize = 400;
/// 一个 Steam 安装根下 `appmanifest_*.acf` 的读取上限
const ACF_CAP: usize = 400;

/// 一条「这个游戏在本机有安装记录」的证据
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LibRecord {
    pub(crate) platform: &'static str,
    pub(crate) name: String,
    /// 安装目录（原始大小写，供展示与遍历；P2-02 新增第二消费方 gameclean）
    pub(crate) dir: String,
    /// 安装目录（已归一：小写、去尾部 `\`），用于路径前缀匹配
    pub(crate) dir_lc: String,
}

/// 平台库索引。`records` 是正向清单，`roots_lc` 是库根（用于「根还在但清单里没了」），
/// `unreadable` 是「装着却没读到」的平台 —— 三者语义互不相同，不可合并。
#[derive(Debug, Default)]
pub(crate) struct PlatformIndex {
    pub(crate) records: Vec<LibRecord>,
    pub(crate) roots_lc: Vec<String>,
    pub(crate) unreadable: Vec<&'static str>,
}

impl PlatformIndex {
    /// 路径归一（小写 + 去尾分隔符 + 统一 `\`），与 `path_key` 不同源：
    /// 这里只用于前缀比较，不碰任何文件操作路径。
    pub(crate) fn norm(p: &str) -> String {
        p.replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase()
    }

    /// 该路径是否落在某个**在库**游戏的安装目录里（含其子树）。
    /// 命中即「游戏仍在库」—— 方案 §2.2：ACE / NEAC / BattlEye / EAC 一律不进候选。
    pub(crate) fn owner_of(&self, path: &str) -> Option<&LibRecord> {
        let pl = Self::norm(path);
        // 取最长匹配：`.../common/Game` 与 `.../common/Game/Bin` 同时在册时，
        // 短前缀会把归属指到父游戏目录上，长前缀才是真正装它的那个库条目
        self.records
            .iter()
            .filter(|r| !r.dir_lc.is_empty() && (pl == r.dir_lc || pl.starts_with(&format!("{}\\", r.dir_lc))))
            .max_by_key(|r| r.dir_lc.len())
    }

    /// 该路径是否落在某个平台**库根**下（库根还在，但未必在清单里）。
    pub(super) fn under_library_root(&self, path: &str) -> bool {
        let pl = Self::norm(path);
        self.roots_lc.iter().any(|r| !r.is_empty() && (pl == *r || pl.starts_with(&format!("{}\\", r))))
    }

    /// 平台清单里是否存在名字可指认的游戏（按互含，阈值走本域 `NAME_MIN_RULE_WORD` 口径：
    /// 这是「拿已知产品名去撞清单」，不是自由文本猜测，短名也允许）。
    pub(super) fn has_game_named(&self, name: &str) -> bool {
        let n = name.trim().to_lowercase();
        if n.is_empty() {
            return false;
        }
        self.records.iter().any(|r| {
            let rl = r.name.to_lowercase();
            !rl.is_empty() && (rl.contains(&n) || n.contains(&rl))
        })
    }

    /// 追加一条「目录候选」记录（目录名作展示名；登记库根；同路径去重、忽略大小写）。
    /// 供 C 类二期各 collector 共用（Steam 走 acf 结构化解析，不用它）。
    fn try_add_dir(&mut self, platform: &'static str, dir: &str) -> bool {
        let norm = Self::norm(dir);
        if norm.is_empty() || self.records.iter().any(|r| r.dir_lc == norm) {
            return false;
        }
        let stem = Path::new(&norm)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        if !self.roots_lc.contains(&norm) {
            self.roots_lc.push(norm.clone());
        }
        self.records.push(LibRecord {
            platform,
            name: stem,
            dir: dir.trim_end_matches(['\\', '/']).to_string(),
            dir_lc: norm,
        });
        true
    }

    /// 各平台是否都读到了清单。false = 有平台装着却没读到，
    /// 此时「不在库」这个结论本身不成立，调用方只能报告不能判定。
    pub(super) fn complete(&self) -> bool {
        self.unreadable.is_empty()
    }
}

// ==================== 纯解析函数（单测覆盖，不碰磁盘与注册表） ====================

/// VDF 里的双反斜杠还原（`"D:\\SteamLibrary"` → `D:\SteamLibrary`）。
/// VDF 的引号内字符串是转义写法，不还原会得到带 `\\` 的死路径。
fn vdf_unescape(s: &str) -> String {
    s.replace("\\\\", "\\")
}

/// 从一行 VDF `"key"    "value"` 里取 (key, value)。只认引号包起来的两段。
fn vdf_pair(line: &str) -> Option<(String, String)> {
    let mut parts: Vec<String> = Vec::new();
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == '"' {
            let mut j = i + 1;
            let mut buf = String::new();
            while j < bytes.len() && bytes[j] != '"' {
                buf.push(bytes[j]);
                j += 1;
            }
            parts.push(buf);
            i = j + 1;
        } else {
            i += 1;
        }
        if parts.len() == 2 {
            break;
        }
    }
    if parts.len() == 2 {
        let value = parts.remove(1);
        Some((parts.remove(0).to_lowercase(), value))
    } else {
        None
    }
}

/// `libraryfolders.vdf` → 库根路径清单。
///
/// 新版（Steam ≥ 2021）形如 `"1" { "path" "D:\\SteamLibrary" ... }`，
/// 旧版顶层直接有 `"username" "C:\\Program Files (x86)\\Steam"` 之类的 path 键 ——
/// 两种都靠「凡是键名为 path 的值就是一个库根」收，不依赖外层编号。
pub(super) fn steam_library_paths(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some((k, v)) = vdf_pair(line) {
            if k == "path" {
                let p = vdf_unescape(&v);
                if !p.is_empty() && !out.contains(&p) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// `.acf` / VDF 文本里取一个具名字段的值（首个命中即返回）。
pub(super) fn vdf_field(text: &str, key: &str) -> Option<String> {
    let want = key.to_lowercase();
    for line in text.lines() {
        if let Some((k, v)) = vdf_pair(line) {
            if k == want {
                let v = vdf_unescape(&v);
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Epic 的 `*.item` 清单是 JSON。字段名跨版本不一致：
/// 现行写 `InstallLocation`，早期写 `Location`，个别构建写 `Path`。
/// 按此顺序取第一个能用值；取不到返回 None（= 无证据，不当成「不在库」）。
pub(super) fn epic_install_dir(item: &Value) -> Option<String> {
    ["InstallLocation", "Location", "Path"]
        .iter()
        .find_map(|k| item.get(*k).and_then(Value::as_str))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Epic `.item` 里的展示名，缺失时退回 AppName（清单名，不是产品名，只用于展示）。
pub(super) fn epic_display_name(item: &Value) -> String {
    ["DisplayName", "AppName", "CatalogNamespace"]
        .iter()
        .find_map(|k| item.get(*k).and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_string()
}

/// WeGame 的 `config.ini` 风格文本 → 其中的绝对目录候选。
///
/// 刻意不猜键名（WeGame 各版本键名不同、且没有公开契约）：取「值形如绝对路径」的行。
/// 认不出任何路径时返回空 —— 调用方按「读不到」处理，不按「没有游戏」处理。
pub(super) fn wegame_dirs_from_ini(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('[') || t.starts_with(';') || t.starts_with('#') {
            continue;
        }
        let Some((_, val)) = t.split_once('=') else { continue };
        let v = val.trim().trim_matches('"');
        // 绝对路径形态：`X:\...` 或 `\\server\share\...`
        let abs = (v.len() > 3
            && v.as_bytes()[0].is_ascii_alphabetic()
            && v.as_bytes()[1] == b':'
            && v.as_bytes()[2] == b'\\')
            || v.starts_with(r"\\");
        if abs && !out.iter().any(|o| o == v) {
            out.push(v.to_string());
        }
    }
    out
}

/// 「安装目录」注册表值的清洗（Origin `Install Dir` / Uplay `InstallDir` / GOG `PATH` 共用）：
/// 去空白与包裹引号、去尾部路径分隔符；只接受绝对路径形态（盘符 `X:\`/`X:/` 或 UNC `\\`），
/// 其余返回 None（脏值不静默变成一条记录）。
pub(super) fn clean_install_dir_value(raw: &str) -> Option<String> {
    let v = raw.trim().trim_matches('"').trim().trim_end_matches(['\\', '/']);
    let b = v.as_bytes();
    let drive_abs = b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
    if v.is_empty() || !(drive_abs || v.starts_with(r"\\")) {
        return None;
    }
    Some(v.to_string())
}

/// Battle.net `Agent\product.db` 文本 → 安装目录候选。
/// 该文件是文本非 sqlite（上游实现事实，cankao/5 §3.2）：以控制字符为分隔切段，
/// 取形如绝对路径的段（`X:/…` 或 UNC），去重保序、忽略大小写。
/// 刻意**不**按「非 ASCII 全切」（上游写法）：中文安装目录是合法路径，切碎会把它一起丢掉。
pub(super) fn battlenet_dirs_from_db(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for seg in text.split(|c: char| (c as u32) < 0x20 || c as u32 == 0x7F) {
        let t = seg.trim().trim_matches('"').trim();
        let b = t.as_bytes();
        let drive_abs = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/';
        if !(drive_abs || t.starts_with(r"\\")) {
            continue;
        }
        if !out.iter().any(|o| o.eq_ignore_ascii_case(t)) {
            out.push(t.to_string());
        }
    }
    out
}

/// Steam 库根 + acf 的 `installdir` 拼出游戏目录（方案 §3 指定的拼法）。
pub(super) fn steam_game_dir(library: &str, installdir: &str) -> PathBuf {
    Path::new(library)
        .join("steamapps")
        .join("common")
        .join(installdir)
}

// ==================== 采集（只读：注册表 + 目录清单） ====================

/// Steam 安装根（`HKCU\Software\Valve\Steam` 的 `SteamPath`，退回 32 位视图的 InstallPath）。
unsafe fn steam_root() -> Option<String> {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW};
    let read = |hive: windows::Win32::System::Registry::HKEY, sub: &str, name: &str| -> Option<String> {
        let sk = to_wide(sub);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return None;
        }
        let v = reg_sz(hk, name);
        let _ = RegCloseKey(hk);
        v
    };
    for v in [
        read(HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
        read(HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", "InstallPath"),
        read(HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath"),
    ]
    .into_iter()
    .flatten()
    {
        let p = v.trim().trim_matches('"').trim_end_matches('\\').to_string();
        if !p.is_empty() && Path::new(&p).is_dir() {
            return Some(p);
        }
    }
    None
}

/// 一个库根下的 `appmanifest_*.acf` → 游戏记录（acf 里 `installdir` 是 common 下的目录名）。
fn steam_records_of_library(library: &str) -> Vec<LibRecord> {
    let mut out = Vec::new();
    let apps = Path::new(library).join("steamapps");
    let Ok(rd) = std::fs::read_dir(&apps) else {
        return out;
    };
    let mut acfs: Vec<PathBuf> = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        let is_acf = p
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("appmanifest_") && n.ends_with(".acf"))
            .unwrap_or(false);
        if is_acf {
            acfs.push(p);
        }
    }
    // 稳定序：候选顺序随文件系统枚举抖动会让两次扫描结果难以对拍
    acfs.sort();
    for p in acfs.into_iter().take(ACF_CAP) {
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let Some(installdir) = vdf_field(&text, "installdir") else { continue };
        let name = vdf_field(&text, "name").unwrap_or_else(|| installdir.clone());
        let dir = steam_game_dir(library, &installdir);
        let dir_s = dir.to_string_lossy().to_string();
        out.push(LibRecord {
            platform: "Steam",
            name,
            dir: dir_s.trim_end_matches('\\').to_string(),
            dir_lc: PlatformIndex::norm(&dir_s),
        });
    }
    out
}

/// Steam：库根来自 `libraryfolders.vdf`（新路径优先，退回 `config/`），
/// 成员来自各库根的 acf。
unsafe fn collect_steam(index: &mut PlatformIndex, notes: &mut Vec<String>) {
    let Some(root) = steam_root() else {
        // 没装 Steam 是合法的「该平台没有游戏」，不进 unreadable
        return;
    };
    index.roots_lc.push(PlatformIndex::norm(&root));
    let mut vdf_text: Option<String> = None;
    for rel in [
        PathBuf::from("steamapps").join("libraryfolders.vdf"),
        PathBuf::from("config").join("libraryfolders.vdf"),
    ] {
        if let Ok(t) = std::fs::read_to_string(Path::new(&root).join(rel)) {
            vdf_text = Some(t);
            break;
        }
    }
    let mut libs: Vec<String> = Vec::new();
    if let Some(t) = vdf_text.as_deref() {
        libs = steam_library_paths(t);
    }
    if libs.is_empty() {
        // 读不到 vdf 时至少把 Steam 自身当库根：单库机器的 acf 就在这棵下面
        libs.push(root.clone());
    }
    let mut listed = 0usize;
    let mut failed = 0usize;
    for lib in libs {
        let norm = PlatformIndex::norm(&lib);
        if !index.roots_lc.contains(&norm) {
            index.roots_lc.push(norm);
        }
        let apps_dir = Path::new(&lib).join("steamapps");
        if !apps_dir.is_dir() {
            continue;
        }
        match std::fs::read_dir(&apps_dir) {
            Ok(_) => {
                listed += 1;
                index.records.extend(steam_records_of_library(&lib));
            }
            Err(_) => failed += 1,
        }
    }
    // 「一个库根都没列成」与「列到了但都没有安装记录」是两回事：前者是读失败，
    // 后者是这台机器确实没装游戏。只有前者进 unreadable。
    if failed > 0 || listed == 0 {
        index.unreadable.push("Steam");
        notes.push(format!("Steam {UNREADABLE_SUFFIX}（库根 {failed} 个读失败 / {listed} 个读到）"));
    }
}

/// Epic：清单在 `%PROGRAMDATA%\Epic\EpicInstaller\Manifests\*.item`（每台机器一份安装记录，
/// 与启动器装在哪无关）。没这个目录 = 没装 Epic 或从未装游戏。
fn collect_epic(index: &mut PlatformIndex, notes: &mut Vec<String>) {
    let Some(pd) = std::env::var_os("PROGRAMDATA") else {
        index.unreadable.push("Epic");
        notes.push(format!("Epic 环境变量 PROGRAMDATA 读不到，{UNREADABLE_SUFFIX}"));
        return;
    };
    let manifests = Path::new(&pd).join(r"Epic\EpicInstaller\Manifests");
    if !manifests.is_dir() {
        return;
    }
    let Ok(rd) = std::fs::read_dir(&manifests) else {
        index.unreadable.push("Epic");
        notes.push(format!("Epic {UNREADABLE_SUFFIX}"));
        return;
    };
    let mut files: Vec<PathBuf> = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("item")).unwrap_or(false) {
            files.push(p);
        }
    }
    files.sort();
    let mut parsed_any = false;
    for p in &files {
        if index.records.len() >= COLLECT_HARD_CAP {
            break;
        }
        let Ok(text) = std::fs::read_to_string(p) else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        parsed_any = true;
        let Some(dir) = epic_install_dir(&v) else { continue };
        let expanded = expand_pct(&dir).unwrap_or(dir);
        let norm = PlatformIndex::norm(&expanded);
        if !index.roots_lc.contains(&norm) {
            index.roots_lc.push(norm.clone());
        }
        index.records.push(LibRecord {
            platform: "Epic",
            name: epic_display_name(&v),
            dir: expanded.trim_end_matches('\\').to_string(),
            dir_lc: norm,
        });
    }
    if !parsed_any && !files.is_empty() {
        index.unreadable.push("Epic");
        notes.push(format!("Epic {UNREADABLE_SUFFIX}（{}.item 全部解析失败）", files.len()));
    }
}

/// WeGame：先从卸载键找到它的安装目录，再在有限候选位置找 `config.ini`。
///
/// 刻意不把「找不到 config.ini」当「读到了空清单」：WeGame 装过游戏就必然有本地记录，
/// 判不出来的那批游戏会被误报成「已卸载」。所以没定位到清单文件时进 `unreadable`。
unsafe fn collect_wegame(index: &mut PlatformIndex, notes: &mut Vec<String>) {
    let mut installs: Vec<String> = Vec::new();
    for (hive, sub) in [
        (
            windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            windows::Win32::System::Registry::HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ] {
        for key in reg_enum_subkeys(hive, sub, 800) {
            let sk = to_wide(&format!("{sub}\\{key}"));
            use windows::Win32::System::Registry::{KEY_READ, RegCloseKey, RegOpenKeyExW};
            let mut hk = windows::Win32::System::Registry::HKEY::default();
            if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
                continue;
            }
            let name = reg_sz(hk, "DisplayName").unwrap_or_default();
            let pubr = reg_sz(hk, "Publisher").unwrap_or_default();
            let loc = reg_sz(hk, "InstallLocation").unwrap_or_default();
            let _ = RegCloseKey(hk);
            let owned = name.to_lowercase().contains("wegame")
                || name.to_lowercase().contains("we 游戏")
                || pubr.to_lowercase().contains("wegame");
            if owned {
                let l = loc.trim().trim_end_matches('\\').to_string();
                if !l.is_empty() && !installs.iter().any(|i| i.eq_ignore_ascii_case(&l)) {
                    installs.push(l);
                }
            }
        }
    }
    if installs.is_empty() {
        // WeGame 本体不在本机（或没写过卸载键）：合法的「该平台无游戏」
        return;
    }
    let mut found_ini = false;
    for install in installs {
        for cand in [
            Path::new(&install).join("config.ini"),
            Path::new(&install).join("System32").join("config.ini"),
        ] {
            let Ok(text) = std::fs::read_to_string(&cand) else { continue };
            found_ini = true;
            for dir in wegame_dirs_from_ini(&text) {
                if index.records.len() >= COLLECT_HARD_CAP {
                    break;
                }
                let norm = PlatformIndex::norm(&dir);
                let stem = Path::new(&norm)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                index.records.push(LibRecord {
                    platform: "WeGame",
                    name: stem,
                    dir: dir.trim_end_matches('\\').to_string(),
                    dir_lc: norm.clone(),
                });
                if !index.roots_lc.contains(&norm) {
                    index.roots_lc.push(norm);
                }
            }
        }
    }
    if !found_ini {
        index.unreadable.push("WeGame");
        notes.push(format!("WeGame {UNREADABLE_SUFFIX}（已装 WeGame，未定位到 config.ini）"));
    }
}

// ==================== C 类二期采集（Origin / Battle.net / Uplay / GOG，2026-10-16） ====================
//
// 机制源 = cankao/5 §3.2 平台发现表（事实层），按本仓纪律重写：不逐平台装软件验证
// （缺平台即 skip），真机覆盖以 `live_new_platform_collectors_readable` 探针为准。
// 注册表侧统一探「两份视图」：32 位视图（Wow6432Node）与 64 位视图都看
// （与 steam_root / WeGame 既有多视图姿势一致）。

/// 打开 `<hive>\<sub>` 并读一个字符串值；键/值不存在或读失败 → None。
unsafe fn read_key_value(hive: windows::Win32::System::Registry::HKEY, sub: &str, name: &str) -> Option<String> {
    use windows::Win32::System::Registry::{KEY_READ, RegCloseKey, RegOpenKeyExW};
    let sk = to_wide(sub);
    let mut hk = windows::Win32::System::Registry::HKEY::default();
    if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
        return None;
    }
    let v = reg_sz(hk, name);
    let _ = RegCloseKey(hk);
    v
}

/// 打开键的三态（硬规矩①「读不到 ≠ 不在库」在注册表侧的可区分形态）：
/// `Missing` = 键不存在（合法的「该平台没有游戏」）；`Denied` = 存在但打不开（读失败，进 unreadable）。
#[derive(Debug, PartialEq, Eq)]
enum KeyState {
    Ok,
    Missing,
    Denied,
}

unsafe fn open_state(hive: windows::Win32::System::Registry::HKEY, sub: &str) -> KeyState {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::System::Registry::{KEY_READ, RegCloseKey, RegOpenKeyExW};
    let sk = to_wide(sub);
    let mut hk = windows::Win32::System::Registry::HKEY::default();
    // RegOpenKeyExW 返回 WIN32_ERROR 而非 Result（本仓锁存的 windows crate 口径，
    // 其余 90 处调用点都用 .is_ok()/.is_err()；P1-1 落笔时写成 match Ok/Err 从未编过）
    let rc = RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk);
    if rc.is_ok() {
        let _ = RegCloseKey(hk);
        KeyState::Ok
    } else if rc == WIN32_ERROR(2) {
        // ERROR_FILE_NOT_FOUND(2) = 键不存在；其余（ACCESS_DENIED 等）= 读失败
        KeyState::Missing
    } else {
        KeyState::Denied
    }
}

/// 枚举 `<root>` 子键、读每键 `value_name` 字符串值 → 清洗后的目录候选（去重保序）。
/// 返回 `hit_guard` = 子键数触到采集护栏（截断注记由调用方给）。
unsafe fn subkey_dir_values(
    hive: windows::Win32::System::Registry::HKEY,
    root: &str,
    value_name: &str,
) -> (Vec<String>, bool) {
    let subs = reg_enum_subkeys(hive, root, COLLECT_HARD_CAP + 1);
    let hit_guard = subs.len() > COLLECT_HARD_CAP;
    let mut out: Vec<String> = Vec::new();
    for key in subs.into_iter().take(COLLECT_HARD_CAP) {
        let Some(raw) = read_key_value(hive, &format!("{root}\\{key}"), value_name) else {
            continue;
        };
        let Some(d) = clean_install_dir_value(&raw) else { continue };
        if !out.iter().any(|o| o.eq_ignore_ascii_case(&d)) {
            out.push(d);
        }
    }
    (out, hit_guard)
}

/// Origin / EA App：存在性 = `Software\[WOW6432Node\]Origin` 的 `ClientPath`；
/// 安装目录 = `SOFTWARE\[WOW6432Node\]{Electronic Arts, EA Games}\*\Install Dir`（两视图都探）。
unsafe fn collect_origin(index: &mut PlatformIndex, notes: &mut Vec<String>) {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE as HKLM;
    const BASES: [&str; 2] = [r"SOFTWARE\WOW6432Node", r"SOFTWARE"];
    let installed = BASES
        .iter()
        .any(|b| read_key_value(HKLM, &format!(r"{b}\Origin"), "ClientPath").is_some());
    if !installed {
        return; // 没装 Origin / EA App 是合法的「该平台没有游戏」
    }
    let mut unreadable = false;
    for base in BASES {
        for rel in ["Electronic Arts", "EA Games"] {
            let root = format!(r"{base}\{rel}");
            match open_state(HKLM, &root) {
                KeyState::Missing => continue, // 该视图没写过游戏记录：合法的空
                KeyState::Denied => {
                    unreadable = true;
                    continue;
                }
                KeyState::Ok => {}
            }
            let (dirs, hit_guard) = subkey_dir_values(HKLM, &root, "Install Dir");
            for d in dirs {
                index.try_add_dir("Origin", &d);
            }
            if hit_guard {
                notes.push(format!("Origin 安装记录超过采集护栏 {COLLECT_HARD_CAP} 条，已截断"));
            }
        }
    }
    if unreadable {
        index.unreadable.push("Origin");
        notes.push(format!("Origin {UNREADABLE_SUFFIX}（已装 Origin/EA，游戏键部分不可读）"));
    }
}

/// Uplay / Ubisoft Connect：存在性 = `Software\[WOW6432Node\]Ubisoft\Launcher` 的 `InstallDir`；
/// 安装目录 = `…\Launcher\Installs\*\InstallDir`。
unsafe fn collect_uplay(index: &mut PlatformIndex, notes: &mut Vec<String>) {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE as HKLM;
    const BASES: [&str; 2] = [r"Software\WOW6432Node\Ubisoft\Launcher", r"Software\Ubisoft\Launcher"];
    let installed = BASES.iter().any(|b| read_key_value(HKLM, b, "InstallDir").is_some());
    if !installed {
        return;
    }
    let mut unreadable = false;
    for base in BASES {
        let root = format!(r"{base}\Installs");
        match open_state(HKLM, &root) {
            KeyState::Missing => continue,
            KeyState::Denied => {
                unreadable = true;
                continue;
            }
            KeyState::Ok => {}
        }
        let (dirs, hit_guard) = subkey_dir_values(HKLM, &root, "InstallDir");
        for d in dirs {
            index.try_add_dir("Uplay", &d);
        }
        if hit_guard {
            notes.push(format!("Uplay 安装记录超过采集护栏 {COLLECT_HARD_CAP} 条，已截断"));
        }
    }
    if unreadable {
        index.unreadable.push("Uplay");
        notes.push(format!("Uplay {UNREADABLE_SUFFIX}（已装 Ubisoft Connect，Installs 键不可读）"));
    }
}

/// GOG Galaxy：存在性 = `SOFTWARE\[WOW6432Node\]GOG.com\Games` 键存在；
/// 安装目录 = `Games\*\PATH`。
unsafe fn collect_gog(index: &mut PlatformIndex, notes: &mut Vec<String>) {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE as HKLM;
    const BASES: [&str; 2] = [r"SOFTWARE\WOW6432Node\GOG.com\Games", r"SOFTWARE\GOG.com\Games"];
    let mut unreadable = false;
    for root in BASES {
        match open_state(HKLM, root) {
            KeyState::Missing => continue, // 没装 GOG 或不在此视图
            KeyState::Denied => {
                unreadable = true;
                continue;
            }
            KeyState::Ok => {}
        }
        let (dirs, hit_guard) = subkey_dir_values(HKLM, root, "PATH");
        for d in dirs {
            index.try_add_dir("GOG", &d);
        }
        if hit_guard {
            notes.push(format!("GOG 安装记录超过采集护栏 {COLLECT_HARD_CAP} 条，已截断"));
        }
    }
    if unreadable {
        index.unreadable.push("GOG");
        notes.push(format!("GOG {UNREADABLE_SUFFIX}（Games 键存在但不可读）"));
    }
}

/// Battle.net：`%ProgramData%\Battle.net` 目录判存在；目录候选来自 `Agent\product.db` 文本行。
/// 「目录在但 product.db 缺/不可读」= 装了却读不到清单 → unreadable（硬规矩①，与 WeGame
/// 找不到 config.ini 同口径）。
fn collect_battlenet(index: &mut PlatformIndex, notes: &mut Vec<String>) {
    let Some(pd) = std::env::var_os("PROGRAMDATA") else {
        index.unreadable.push("Battle.net");
        notes.push(format!("Battle.net 环境变量 PROGRAMDATA 读不到，{UNREADABLE_SUFFIX}"));
        return;
    };
    let root = Path::new(&pd).join("Battle.net");
    if !root.is_dir() {
        return;
    }
    let db = root.join(r"Agent\product.db");
    let Ok(bytes) = std::fs::read(&db) else {
        index.unreadable.push("Battle.net");
        notes.push(format!("Battle.net {UNREADABLE_SUFFIX}（已装 Battle.net，product.db 缺失或不可读）"));
        return;
    };
    let dirs = battlenet_dirs_from_db(&String::from_utf8_lossy(&bytes));
    if dirs.len() > COLLECT_HARD_CAP {
        notes.push(format!("Battle.net 安装记录超过采集护栏 {COLLECT_HARD_CAP} 条，已截断"));
    }
    for d in dirs.into_iter().take(COLLECT_HARD_CAP) {
        index.try_add_dir("Battle.net", &d);
    }
}

/// 全局上限的**公平配额**截断（C 类二期）：从当前记录最多的平台逐条扣到总量 ≤ RECORD_CAP。
/// 效果 = 后跑的平台不再被 collector 顺序饿死（极端输入下各平台尽量保到均等份额），
/// 且逐平台外发截断计数（notes 可见，不静默）。
fn fair_trim(records: &mut Vec<LibRecord>, notes: &mut Vec<String>) {
    if records.len() <= RECORD_CAP {
        return;
    }
    let mut order: Vec<&'static str> = Vec::new();
    for r in records.iter() {
        if !order.contains(&r.platform) {
            order.push(r.platform);
        }
    }
    let mut counts: Vec<usize> = order
        .iter()
        .map(|p| records.iter().filter(|r| r.platform == *p).count())
        .collect();
    let mut dropped = vec![0usize; order.len()];
    let mut total: usize = counts.iter().sum();
    while total > RECORD_CAP {
        // 扣当前条数最多的平台；并列取首现序靠前者（确定性——同级分数时 max_by_key 取最后一个，
        // 故用 Reverse(i) 把「更小的序」抬成更大）
        let i = counts
            .iter()
            .enumerate()
            .max_by_key(|(i, c)| (**c, std::cmp::Reverse(*i)))
            .map(|(i, _)| i)
            .expect("counts 非空");
        counts[i] -= 1;
        dropped[i] += 1;
        total -= 1;
    }
    let mut taken = vec![0usize; order.len()];
    let mut kept: Vec<LibRecord> = Vec::with_capacity(RECORD_CAP);
    for r in records.drain(..) {
        let i = order.iter().position(|p| *p == r.platform).expect("平台来自 order");
        if taken[i] < counts[i] {
            taken[i] += 1;
            kept.push(r);
        }
    }
    *records = kept;
    for (i, p) in order.iter().enumerate() {
        if dropped[i] > 0 {
            notes.push(format!(
                "{p} 安装记录超出全局上限 {RECORD_CAP}，按公平配额截断 {} 条（仅影响残留判定覆盖面）",
                dropped[i]
            ));
        }
    }
}

/// 采集各平台清单（Steam / Epic / WeGame + C 类二期 Origin / Battle.net / Uplay / GOG）。
/// 任何一处失败都只影响该平台的判定力，不让整轮扫描失败
/// （与残留扫描的 notes 口径一致：残缺要可见，不能装成干净）。
pub(crate) unsafe fn collect_platform_index() -> (PlatformIndex, Vec<String>) {
    let mut index = PlatformIndex::default();
    let mut notes = Vec::new();
    collect_steam(&mut index, &mut notes);
    collect_epic(&mut index, &mut notes);
    collect_wegame(&mut index, &mut notes);
    collect_origin(&mut index, &mut notes);
    collect_battlenet(&mut index, &mut notes);
    collect_uplay(&mut index, &mut notes);
    collect_gog(&mut index, &mut notes);
    fair_trim(&mut index.records, &mut notes);
    index.records.sort_by(|a, b| a.dir_lc.cmp(&b.dir_lc));
    index.records.dedup_by(|a, b| a.dir_lc == b.dir_lc);
    (index, notes)
}

// ==================== 游戏目录残留（平台扫描器自身的产出） ====================
//
// 本节（LibraryListing / list_game_dirs / UNTRACKED_CAP / untracked_dir_findings）
// 是「库根还在、清单已无」的未跟踪游戏目录发现能力：采集/判定已分离且有单测，
// 生产扫描链尚未接线，故逐项 allow(dead_code)（原先靠模块级整体 allow 压住；
// P2-02 为 gameclean 放开第二消费方后模块级 allow 移除，警告才浮出水面）。
// 接线到残留扫描时逐项摘掉 allow，不要删实现。

/// 「库根 + 该根下实际存在的游戏目录」采集结果（把只读列目录与判定分开，
/// 判定因此可在单测里注入目录清单，不碰磁盘 —— 与本域其余扫描器的「采集/判定分离」同构）。
#[allow(dead_code)]
pub(super) struct LibraryListing {
    #[allow(dead_code)]
    pub(super) root: String,
    #[allow(dead_code)]
    pub(super) game_dirs: Vec<String>,
}

/// 只读列出一个库根下的游戏目录：优先 `steamapps\common\*`（Steam 形态），
/// 退回库根一级目录（Epic / WeGame 形态）。
#[allow(dead_code)]
pub(super) fn list_game_dirs(root: &str) -> Vec<String> {
    let common = Path::new(root).join("steamapps").join("common");
    let base = if common.is_dir() { common.to_path_buf() } else { PathBuf::from(root) };
    let mut out: Vec<String> = match std::fs::read_dir(&base) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        Err(_) => return Vec::new(),
    };
    out.sort();
    out.truncate(COMMON_DIR_CAP);
    out
}

/// 一个库里最多出多少条目录候选（防某台机器上 common 目录异常膨胀淹掉判断面）。
/// allow(dead_code)：同属本节未接线的未跟踪目录发现族。
#[allow(dead_code)]
const UNTRACKED_CAP: usize = 80;

/// 「目录还在、清单里已没有」的游戏目录候选。
///
/// 置信度封顶 medium：`unreadable` 那一档已经在调用侧排除，但「acf 被手工删过 /
/// 库没在 Steam 里挂载 / 用第三方工具搬过目录」同样是合法解释，只有用户知道。
#[allow(dead_code)]
pub(super) fn untracked_dir_findings(index: &PlatformIndex, listings: &[LibraryListing]) -> Vec<Value> {
    if !index.complete() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for listing in listings {
        for dir in &listing.game_dirs {
            if index.owner_of(dir).is_some() {
                continue;
            }
            if out.len() >= UNTRACKED_CAP {
                return out;
            }
            out.push(json!({
                "kind": "folder", "target": dir,
                "class": "untracked_game_dir",
                "reason": "游戏库目录还在，但当前各平台清单里查不到对应安装记录",
                "confidence": "medium", "risk": "high",
                "readonly": true, "defaultChecked": false,
                "contribs": contribs(&[
                    ("platformIndexMissing", format!("库根 {} 下的一级目录，未匹配到任何安装记录", listing.root)),
                    ("indexComplete", "各平台清单本轮都读到了，不是读不到清单造成的缺口".to_string()),
                ]),
            }));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn index_with(dirs: &[(&str, &str)]) -> PlatformIndex {
        PlatformIndex {
            records: dirs
                .iter()
                .map(|(name, dir)| LibRecord {
                    platform: "Steam",
                    name: name.to_string(),
                    dir: dir.trim_end_matches('\\').to_string(),
                    dir_lc: PlatformIndex::norm(dir),
                })
                .collect(),
            roots_lc: dirs.iter().map(|(_, d)| PlatformIndex::norm(d)).collect(),
            unreadable: Vec::new(),
        }
    }

    #[test]
    fn steam_library_paths_only_uses_path_keys() {
        // 现行 libraryfolders.vdf：编号块里的 path；apps 字典里只有 appid（旧版是体积），
        // 不贡献库根 —— 方案 §3 点名「apps 字典不含 installdir」的那条纠正。
        let vdf = "\"LibraryFolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"D:\\\\SteamLibrary\"\n\t\t\"label\"\t\t\"\"\n\t\t\"mounted\"\t\t\"1\"\n\t\t\"apps\"\n\t\t{\n\t\t\t\"440\"\n\t\t\t{\n\t\t\t\t\"appid\"\t\t\"440\"\n\t\t\t}\n\t\t\t\"730\"\n\t\t\t{\n\t\t\t\t\"appid\"\t\t\"730\"\n\t\t\t}\n\t\t}\n\t}\n\t\"1\"\n\t{\n\t\t\"path\"\t\t\"C:\\\\Program Files (x86)\\\\Steam\"\n\t\t\"apps\"\n\t\t{\n\t\t\t\"228980\"\t\t\"1073741824\"\n\t\t}\n\t}\n}\n";
        assert_eq!(steam_library_paths(vdf), vec!["D:\\SteamLibrary", "C:\\Program Files (x86)\\Steam"]);
    }

    #[test]
    fn acf_installdir_joins_library_not_apps_dict() {
        // 方案 §3 点名的坑：apps 字典里没有 installdir，拼路径必须用 acf
        let acf = "\"AppState\" \"4\"\n\"installed\" \"1\"\n\"name\" \"Lost Ark\"\n\"installdir\" \"LostArk\"\n\"UserConfig\" \"\"\n";
        assert_eq!(vdf_field(acf, "installdir").as_deref(), Some("LostArk"));
        assert_eq!(vdf_field(acf, "name").as_deref(), Some("Lost Ark"));
        let joined = steam_game_dir("D:\\SteamLibrary", "LostArk");
        assert_eq!(joined, PathBuf::from(r"D:\SteamLibrary\steamapps\common\LostArk"));
    }

    #[test]
    fn vdf_unescape_collapses_double_backslash_only() {
        assert_eq!(vdf_unescape(r"D:\\SteamLibrary\\steamapps"), "D:\\SteamLibrary\\steamapps");
        assert_eq!(vdf_unescape("no-escape"), "no-escape");
    }

    #[test]
    fn owner_of_picks_longest_matching_install_dir() {
        let idx = index_with(&[
            ("Parent", "D:\\SteamLibrary\\steamapps\\common\\Parent"),
            ("Child", "D:\\SteamLibrary\\steamapps\\common\\Parent\\Child"),
        ]);
        let hit = idx.owner_of(r"D:\SteamLibrary\steamapps\common\Parent\Child\Bin\Game.exe").unwrap();
        assert_eq!(hit.name, "Child");
        // 大小写不敏感（Windows 路径语义）
        assert_eq!(idx.owner_of("d:\\steamlibrary\\steamapps\\common\\parent").unwrap().name, "Parent");
        // 前缀像但不是目录边界（`Parentics` 不是 `Parent` 的子项）不得命中
        assert!(idx.owner_of(r"D:\SteamLibrary\steamapps\common\Parentics\a.exe").is_none());
    }

    #[test]
    fn incomplete_index_yields_no_candidates() {
        let mut idx = index_with(&[("X", "D:\\SteamLibrary\\steamapps\\common\\X")]);
        idx.unreadable.push("Epic");
        assert!(!idx.complete());
        // 清单不全时不得产出「目录没在清单里」候选，否则会把手工挂载的库报成残留
        let listings = [LibraryListing {
            root: "D:\\SteamLibrary".to_string(),
            game_dirs: vec!["D:\\SteamLibrary\\steamapps\\common\\Y".to_string()],
        }];
        assert!(untracked_dir_findings(&idx, &listings).is_empty());
    }

    #[test]
    fn untracked_dirs_report_only_dirs_absent_from_index() {
        let idx = index_with(&[("Kept", "D:\\SteamLibrary\\steamapps\\common\\Kept")]);
        let listings = [LibraryListing {
            root: "D:\\SteamLibrary".to_string(),
            game_dirs: vec![
                "D:\\SteamLibrary\\steamapps\\common\\Kept".to_string(),
                "D:\\SteamLibrary\\steamapps\\common\\Gone".to_string(),
            ],
        }];
        let items = untracked_dir_findings(&idx, &listings);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["target"], "D:\\SteamLibrary\\steamapps\\common\\Gone");
        // 只读阶段：既不给勾选，也不给删除口径
        assert_eq!(items[0]["readonly"], true);
        assert_eq!(items[0]["defaultChecked"], false);
        assert_eq!(items[0]["class"], "untracked_game_dir");
    }

    #[test]
    fn has_game_named_matches_both_directions() {
        let idx = index_with(&[("永劫无间", "D:\\SteamLibrary\\steamapps\\common\\naraka")]);
        assert!(idx.has_game_named("永劫无间"));
        assert!(idx.has_game_named("NARAKA: Bladepoint 永劫无间"));
        assert!(!idx.has_game_named(""));
        assert!(!idx.has_game_named("Lost Ark"));
    }

    #[test]
    fn epic_item_falls_back_across_field_names() {
        assert_eq!(epic_install_dir(&json!({ "InstallLocation": "C:\\Games\\A" })).as_deref(), Some("C:\\Games\\A"));
        assert_eq!(epic_install_dir(&json!({ "Location": "C:/Games/B" })).as_deref(), Some("C:/Games/B"));
        assert_eq!(epic_install_dir(&json!({ "Path": "C:\\Games\\C" })).as_deref(), Some("C:\\Games\\C"));
        assert_eq!(epic_install_dir(&json!({ "AppName": "Fortnite" })), None);
        assert_eq!(epic_display_name(&json!({ "AppName": "FN" })), "FN");
    }

    #[test]
    fn wegame_ini_only_accepts_absolute_dirs() {
        let ini = "; comment\n[Install]\nGamePath=D:\\WeGame\\apps\\lol\nSmall=12\nBad=relative\\path\nOther=\"C:\\WeGame\\apps\\dk\"\n[UI]\n";
        assert_eq!(wegame_dirs_from_ini(ini), vec!["D:\\WeGame\\apps\\lol", "C:\\WeGame\\apps\\dk"]);
    }

    #[test]
    fn list_game_dirs_on_missing_root_is_empty_not_a_guess() {
        // 读不到就是空（调用方不得据此判「库里没有游戏」）
        assert!(list_game_dirs(r"Z:\definitely\not\here\9f3a").is_empty());
    }

    #[test]
    fn clean_install_dir_value_only_accepts_absolute_paths() {
        assert_eq!(clean_install_dir_value("\"D:\\Games\\A\"").as_deref(), Some("D:\\Games\\A"));
        assert_eq!(clean_install_dir_value("  C:/Games/B  ").as_deref(), Some("C:/Games/B"));
        assert_eq!(clean_install_dir_value("D:\\Games\\A\\\\\\  ").as_deref(), Some("D:\\Games\\A"));
        assert_eq!(clean_install_dir_value(r"\\NAS\share\games").as_deref(), Some(r"\\NAS\share\games"));
        assert_eq!(clean_install_dir_value(""), None);
        assert_eq!(clean_install_dir_value("relative\\path"), None);
        assert_eq!(clean_install_dir_value("C:/"), None); // 尾部裁剪后只剩盘符 = 非法路径值
        assert_eq!(clean_install_dir_value("\"\" "), None);
    }

    #[test]
    fn battlenet_product_db_keeps_only_absolute_slash_paths() {
        // 控制字符分段 + 引号包裹 + 各式噪声（URL / 相对路径 / 反斜杠路径 / 重复）
        let db = "\u{0}C:/Program Files (x86)/Overwatch\u{0}\"D:/Games/暗黑破坏神 IV\"\u{1}https://example.com/x\u{2}relative/y\u{3}C:\\Backslash\\No\u{0}c:/program files (x86)/overwatch\u{4}\\\\NAS\\share\\games\u{5}";
        assert_eq!(
            battlenet_dirs_from_db(db),
            vec!["C:/Program Files (x86)/Overwatch", "D:/Games/暗黑破坏神 IV", r"\\NAS\share\games"]
        );
        assert!(battlenet_dirs_from_db("").is_empty());
    }

    #[test]
    fn fair_trim_protects_late_platforms() {
        let rec = |p: &'static str, i: usize| LibRecord {
            platform: p,
            name: format!("g{i}"),
            dir: format!("D:\\{p}\\{i}"),
            dir_lc: PlatformIndex::norm(&format!("D:\\{p}\\{i}")),
        };
        let mut records: Vec<LibRecord> = Vec::new();
        for i in 0..600 {
            records.push(rec("Steam", i));
        }
        for i in 0..80 {
            records.push(rec("Epic", i));
        }
        for i in 0..20 {
            records.push(rec("WeGame", i));
        }
        let mut notes = Vec::new();
        fair_trim(&mut records, &mut notes);
        assert_eq!(records.len(), RECORD_CAP, "超限后必须压回全局上限");
        let count = |p: &str| records.iter().filter(|r| r.platform == p).count();
        // 公平配额：小平台不再被先跑的大平台挤掉（旧实现会让 Steam 先吃满 600）
        assert_eq!(count("WeGame"), 20);
        assert_eq!(count("Epic"), 80);
        assert_eq!(count("Steam"), 500);
        assert!(
            notes.iter().any(|n| n.contains("Steam") && n.contains("截断 100 条")),
            "截断计数须逐平台外发：{notes:?}"
        );
        // 未超限则一字不动、零注记
        let mut small: Vec<LibRecord> = (0..10).map(|i| rec("Steam", i)).collect();
        let mut n2 = Vec::new();
        fair_trim(&mut small, &mut n2);
        assert_eq!(small.len(), 10);
        assert!(n2.is_empty());
    }

    /// 真机探针（发布前实跑，只读）：七个平台的注册表/文件读取在本机的实际覆盖。
    /// 缺平台的每一项显式 SKIP 说明，不静默；unreadable 与 notes 逐项列出。
    #[test]
    #[ignore]
    fn live_new_platform_collectors_readable() {
        let (index, notes) = unsafe { collect_platform_index() };
        for p in ["Steam", "Epic", "WeGame", "Origin", "Battle.net", "Uplay", "GOG"] {
            let n = index.records.iter().filter(|r| r.platform == p).count();
            if n == 0 {
                println!("[SKIP] {p}: 本机 0 条安装记录（未装该平台 / 没有游戏）");
            } else {
                println!("[OK] {p}: {n} 条安装记录");
            }
        }
        println!("unreadable = {:?}", index.unreadable);
        for n in &notes {
            println!("note: {n}");
        }
    }
}
