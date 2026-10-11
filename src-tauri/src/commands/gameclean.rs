//! gameclean：游戏安装目录内「运行库安装包残留」扫描（批次 A 砍 Ren'Py，仅剩 redist 类）。
//!
//! 清的不是启动器缓存（`steamCache` 已覆盖），而是游戏目录里的 DirectX/VC++/XNA/.NET
//! 运行库安装包（`.exe/.msi/.cab`）。
//!
//! 数据源只走 `uninstall::game_platform_orphan::collect_platform_index()`（Steam/Epic/WeGame
//! 在库游戏），本文件不重写 vdf/acf 解析（§5.16/N6）。
//!
//! 本文件同时扮演两个角色：
//!  1. **库模块**（批次 B 新主路径）：`collect_redist_by_platform` 供 `scan_execute.rs`
//!     在常规清理扫描后回填 `steamRedistCache/epicRedistCache/wegameRedistCache` 三条规则
//!     的 size 与 plan；scan_execute 消费返回的 `GameRedistResult`。
//!  2. **命令壳**（P2-02 旧视图，批次 B 拆除中）：`gameclean_scan` 与 finder 外部槽闭环
//!     保留至 cleanup 扫描回填链完全通电。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::commands::uninstall::game_platform_orphan;
use crate::engine::protect;

// ==================== 判定规则（纯函数，单测覆盖） ====================

/// A 类目录名 token（小写后「包含」即命中）。刻意只取具名词，不取
/// SteamCleaner 的泛词 support / 裸 installer（其 2.4 四条例外的根因）。
const DIR_TOKENS: &[&str] = &[
    "redist",
    "directx",
    "dxsetup",
    "dotnetfx",
    "prereq",
    "xnafx",
    "__installer",
];

/// A 类候选文件扩展名白名单（精确、大小写不敏感）。不含 `.so`
/// （SteamCleaner 的 `so` 子串会误伤 `sounds.ogg`）。
const FILE_EXTS: &[&str] = &["exe", "msi", "cab"];

/// 排除表：路径片段（互含、大小写不敏感）→ 理由。命中不收集，且进 notes 可见。
const EXCLUDED_FRAGMENTS: &[(&str, &str)] = &[(
    r"Penumbra Overture\redist",
    "上游 2.4 排除先例：该目录含非安装器内容",
)];

/// BFS 上限（house 风格，触顶记 notes）
const MAX_DEPTH: usize = 8;
const MAX_DIRS_PER_GAME: usize = 5000;
const MAX_CANDIDATES_GLOBAL: usize = 2000;

/// 目录名是否命中 A 类 token。
pub(crate) fn dir_name_hits(dir_name: &str) -> Option<&'static str> {
    let low = dir_name.to_ascii_lowercase();
    DIR_TOKENS.iter().copied().find(|tok| {
        low.contains(tok)
            // redistribution 是独立英文词（redist 仅词干），不是运行库目录，
            // 裸 contains 会把它误收成候选区
            && !(*tok == "redist" && low.contains("redistribution"))
    })
}

/// 文件名扩展名是否在白名单。
pub(crate) fn file_ext_allowed(file_name: &str) -> bool {
    Path::new(file_name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            let el = e.to_ascii_lowercase();
            FILE_EXTS.contains(&el.as_str())
        })
        .unwrap_or(false)
}

/// 路径是否命中排除表。
fn excluded(path_lc: &str) -> Option<&'static str> {
    EXCLUDED_FRAGMENTS
        .iter()
        .find(|(frag, _)| path_lc.contains(&frag.to_lowercase().replace('/', "\\")))
        .map(|(_, reason)| *reason)
}

/// 单条候选（批次 A 砍 Ren'Py 后仅剩 redist 类）
#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub(crate) path: String,
    pub(crate) lossy: bool,
}

/// 对一个游戏目录做 BFS，收集候选。
pub(crate) fn scan_game_dir(
    game_dir: &Path,
    sink: &mut Vec<Candidate>,
    notes: &mut Vec<String>,
    global_cap: &mut usize,
) {
    let mut queue: std::collections::VecDeque<(PathBuf, usize, Option<(String, String)>)> =
        std::collections::VecDeque::new();
    queue.push_back((game_dir.to_path_buf(), 0, None));
    let mut dirs_seen = 0usize;
    let mut truncated = false;
    let mut excluded_reported: HashSet<&str> = HashSet::new();

    while let Some((dir, depth, open_zone)) = queue.pop_front() {
        if dirs_seen >= MAX_DIRS_PER_GAME || depth > MAX_DEPTH {
            truncated = true;
            continue;
        }
        dirs_seen += 1;

        let dir_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let zone = match dir_name_hits(dir_name) {
            Some(tok) => Some((dir.to_string_lossy().to_string(), tok.to_string())),
            None => open_zone,
        };

        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for ent in rd.flatten() {
            let path = ent.path();
            let md = match std::fs::symlink_metadata(&path) {
                Ok(md) => md,
                Err(_) => continue,
            };
            if protect::is_reparse(&md) {
                continue;
            }
            let ft = md.file_type();
            let path_lc = path.to_string_lossy().to_ascii_lowercase();

            if ft.is_dir() {
                if depth + 1 <= MAX_DEPTH {
                    queue.push_back((path, depth + 1, zone.clone()));
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            if let Some(reason) = excluded(&path_lc) {
                if excluded_reported.insert(reason) {
                    let parent = path
                        .parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    notes.push(format!("目录「{parent}」命中排除表已跳过：{reason}"));
                }
                continue;
            }
            if zone.is_some() {
                let fname = ent.file_name().to_string_lossy().to_string();
                if file_ext_allowed(&fname) {
                    if *global_cap == 0 {
                        notes.push("候选达全局上限，后续安装包未收集".into());
                        return;
                    }
                    sink.push(Candidate {
                        path: path.to_string_lossy().replace('\\', "/"),
                        lossy: trim_finder::util::has_lossy_path(&path),
                    });
                    *global_cap -= 1;
                }
            }
        }
    }

    if truncated {
        notes.push(format!(
            "游戏「{}」目录遍历触顶（目录数 {} / 深度 {}），深层未扫",
            game_dir.display(),
            MAX_DIRS_PER_GAME,
            MAX_DEPTH
        ));
    }
}

// ==================== 库模块（批次 B 新主路径） ====================

/// 三平台各自的 redist 候选收集结果
#[derive(Debug, Default, Clone)]
pub(crate) struct PlatformRedist {
    pub(crate) total_size: u64,
    pub(crate) files: Vec<(String, u64)>, // (path, size)，路径正斜杠
    pub(crate) lossy_count: usize,
}

/// collect_redist_by_platform 的完整结果
#[derive(Debug, Default, Clone)]
pub(crate) struct GameRedistResult {
    pub(crate) steam: PlatformRedist,
    pub(crate) epic: PlatformRedist,
    pub(crate) wegame: PlatformRedist,
    pub(crate) notes: Vec<String>,
}

/// 扫描三平台在库游戏的 redist 候选，按平台分桶返回。
///
/// 本函数是批次 B 新增的**主路径**：`scan_execute.rs` 在常规清理扫描完成后
/// 调用它，把结果回填到 `steamRedistCache/epicRedistCache/wegameRedistCache`
/// 三条 gameRedist 规则的 size 与 files 清单。扫描全程只读、纯内存，不写盘、
/// 不注册 finder 快照槽（旧路径由命令壳 gameclean_scan 保留，批次 B 末尾拆除）。
///
/// 数据源：`game_platform_orphan::collect_platform_index()`（Steam/Epic/WeGame
/// 平台索引，vdf/acf 解析由 uninstall 域负责）。
pub(crate) fn collect_redist_by_platform() -> GameRedistResult {
    let (index, mut notes) = unsafe { game_platform_orphan::collect_platform_index() };

    let mut by_platform: HashMap<&str, Vec<Candidate>> = HashMap::new();
    let mut global_cap = MAX_CANDIDATES_GLOBAL;

    for rec in &index.records {
        let game_dir = PathBuf::from(&rec.dir);
        if !game_dir.is_dir() {
            continue;
        }
        let mut found: Vec<Candidate> = Vec::new();
        scan_game_dir(&game_dir, &mut found, &mut notes, &mut global_cap);
        if !found.is_empty() {
            by_platform.entry(rec.platform).or_default().extend(found);
        }
        if global_cap == 0 {
            break;
        }
    }

    // lossy 项在下面按平台分桶时直接计入 lossy_count（不进文件清单），无需中间表。

    // 每个平台：stat 路径得真实大小，组装文件清单
    let mut result = GameRedistResult {
        notes,
        ..Default::default()
    };
    let targets: [(&str, &mut PlatformRedist); 3] = [
        ("Steam", &mut result.steam),
        ("Epic", &mut result.epic),
        ("WeGame", &mut result.wegame),
    ];
    for (platform, bucket) in targets {
        if let Some(cands) = by_platform.get(platform) {
            for c in cands {
                if c.lossy {
                    bucket.lossy_count += 1;
                    continue; // lossy 不进文件清单（无法安全删除）
                }
                let size = std::fs::metadata(&c.path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                bucket.total_size += size;
                bucket.files.push((c.path.replace('\\', "/"), size));
            }
        }
    }

    result
}

// ==================== 单测 ====================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_dir_positives() {
        for (name, want) in [
            ("Redist", "redist"),
            ("_CommonRedist", "redist"),
            ("vcredist", "redist"),
            ("DirectX", "directx"),
            ("DirectX9", "directx"),
            ("DXSETUP", "dxsetup"),
            ("DotNetFX", "dotnetfx"),
            ("dotnetfx35", "dotnetfx"),
            ("UE4PrereqSetup", "prereq"),
            ("Prerequisites", "prereq"),
            ("xnafx40", "xnafx"),
            ("__Installer", "__installer"),
        ] {
            assert_eq!(dir_name_hits(name), Some(want),
                "目录 {name} 应命中 {want}");
        }
    }

    #[test]
    fn token_dir_sentinels_must_not_hit() {
        for name in [
            "Support", "support", "Installer", "installer", "Mono", "miles",
            "Content", "Engine", "libraries", "Sounds", "Redistribution",
        ] {
            assert!(dir_name_hits(name).is_none(), "目录 {name} 不该命中任何 token");
        }
        assert!(dir_name_hits("Installer").is_none());
    }

    #[test]
    fn token_redist_extra_still_hits() {
        assert_eq!(dir_name_hits("RedistExtra"), Some("redist"));
    }

    #[test]
    fn ext_whitelist() {
        assert!(file_ext_allowed("a.exe"));
        assert!(file_ext_allowed("A.MSI"));
        assert!(file_ext_allowed("x.Cab"));
        for name in ["a.dll", "a.so", "a.ini", "a.txt", "a", "exe", "a.exe.txt"] {
            assert!(!file_ext_allowed(name), "{name} 不该命中扩展名白名单");
        }
    }

    #[test]
    fn excluded_fragment_penumbra() {
        let p = r"c:\games\penumbra overture\redist\x.exe";
        assert!(excluded(&p.to_lowercase()).is_some());
        assert!(excluded(r"c:\games\other\redist\x.exe").is_none());
    }

    /// 真机探针：redist 目录里真实创建一个含孤立代理项文件名的安装包，
    /// 验证它被 lossy 标记、不进文件清单；同目录正常文件仍可删。
    #[test]
    #[ignore = "需 NTFS 真实创建孤立代理项文件名，发布前门禁跑"]
    fn lossy_redist_file_marked_undeletable() {
        use std::ffi::OsString;
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        let root = std::env::temp_dir().join(format!("trim-gc-lossy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let game = root.join("GameL");
        let redist = game.join("_CommonRedist");
        std::fs::create_dir_all(&redist).unwrap();
        let ok = redist.join("ok.exe");
        std::fs::write(&ok, b"ok").unwrap();
        // dx<D800>.exe：0xD800 是孤立高代理项
        let mut wide: Vec<u16> = redist.as_os_str().encode_wide().collect();
        wide.push(b'\\' as u16);
        wide.extend([0x64, 0x78, 0xD800, 0x2E, 0x65, 0x78, 0x65]);
        let lossy_path = PathBuf::from(OsString::from_wide(&wide));
        std::fs::write(&lossy_path, b"lossy").unwrap();

        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
        }
        let _guard = Cleanup(root.clone());

        // 直接调用 scan_game_dir，构造 records 进 collect_redist_by_platform 需要索引，
        // 单测直接测 BFS 输出更直接（不需要游戏平台索引桩）
        let mut notes = vec![];
        let mut cap = 2000;
        let mut found: Vec<Candidate> = Vec::new();
        scan_game_dir(&game, &mut found, &mut notes, &mut cap);

        let normal = found.iter().filter(|c| !c.lossy).count();
        let lossy = found.iter().filter(|c| c.lossy).count();
        assert_eq!(normal, 1, "正常文件应收集到 1 条");
        assert_eq!(lossy, 1, "lossy 文件应收集到 1 条并标 lossy");
    }

    #[test]
    fn stub_dir_scan_contract() {
        let root = std::env::temp_dir().join(format!("trim-gc-stub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let game_a = root.join("GameA");
        let mk = |rel: &str, bytes: &[u8]| {
            let p = game_a.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, bytes).unwrap();
            p
        };
        let dx = mk("_CommonRedist/DirectX/DXSETUP.exe", b"dxsetup-12345");
        let cab = mk("_CommonRedist/DirectX/Jun2010/cab1.cab", b"cab-678901");
        let vc = mk("_CommonRedist/vcredist.msi", b"vc-msi");
        let _keep = mk("lib/py3-windows-x86_64/keep.dll", b"keep");
        let _keep2 = mk("lib/py3-darwin/renpy/script.rpy", b"renpy-darwin");
        let _notes = mk("Redistribution/notes.exe", b"notes");

        let mut notes = vec![];
        let mut cap = 2000;
        let mut found: Vec<Candidate> = Vec::new();
        scan_game_dir(&game_a, &mut found, &mut notes, &mut cap);

        // 命中路径集合逐字节相等
        let paths: std::collections::BTreeSet<String> = found
            .iter()
            .map(|c| c.path.clone().to_ascii_lowercase())
            .collect();
        let want: std::collections::BTreeSet<String> = [&dx, &cab, &vc]
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/").to_ascii_lowercase())
            .collect();
        assert_eq!(paths, want, "命中集合必须逐路径相等");
        assert_eq!(found.len(), 3);

        // 反例防线：正常路径一条都不许被误标成不可删
        let all_capable = found.iter().all(|c| !c.lossy);
        assert!(all_capable, "正常路径必须全部非 lossy");

        // 大小 = 三个文件实际字节和
        let expected: u64 = [&dx, &cab, &vc]
            .iter()
            .map(|p| std::fs::metadata(p).unwrap().len())
            .sum();
        let actual: u64 = found
            .iter()
            .filter(|c| !c.lossy)
            .map(|c| std::fs::metadata(&c.path).map(|m| m.len()).unwrap_or(0))
            .sum();
        assert_eq!(actual, expected);

        std::fs::remove_dir_all(&root).ok();
    }
}
