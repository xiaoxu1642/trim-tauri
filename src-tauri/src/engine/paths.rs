//! 数据目录解析与遗留数据迁移（迁移方案 D5 / R15）
//!
//! 目录口径（与 Electron 版逐条对齐）：
//! - 便携模式：<exe 目录>\Trim.portable 存在 → 数据目录 <exe 目录>\data
//! - 标准模式：%APPDATA%\com.xiaoxu.trim（Tauri identifier 目录；Electron 版为 %APPDATA%\Trim）
//! - 更早版本：%APPDATA%\CleanTool（Electron 版启动时也做同样迁移）
//!
//! Phase 1 起新目录与旧目录并存：启动时做一次性搬迁（旧目录保留、可重跑），
//! 搬迁清单含 `Local State`——Electron safeStorage 的 OSCrypt 主密钥在那里，
//! 不搬走则 settings.json 的 dpapi:v1: 密钥无法解密（Phase 0 第 6 项实测结论）。

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const APP_NAME: &str = "Trim";
/// 与 tauri.conf.json identifier 一致（升级链不断，D5）
pub const IDENTIFIER: &str = "com.xiaoxu.trim";
const PORTABLE_MARKER: &str = "Trim.portable";

/// 从旧数据目录一次性搬迁的文件清单。
/// 判据只有一条：**丢了用户就恢复不了 / 要重做** 的才进这里。
/// - 前 7 项是 D5 原有清单（含 `Local State` = OSCrypt 主密钥载体）
/// - `update-mirror.json` = E 批 updater 的线路偏好
/// - `optimizer-backups.json` = 优化项的**值级注册表备份**；不搬过去，「还原」就只能
///   退化成反向判据，原来那个具体值再也回不来了（用户改完 Defender/UAC 想还原会失败）
/// - `bench-history.json` = 用户的历史测速/测速记录，重跑成本高且属个人数据
/// 不进清单的：`checkup.json` 之类扫描缓存（可重扫，见下方 `scan_cache_file`）、`cache`（可再生）、
/// `redist`（可重下）、`logs`/`tmp`（运行期产物）。
const MIGRATION_FILES: &[&str] = &[
    "appearance.json",
    "settings.json",
    "optimization-state.json",
    // 审查 M15：`checkup.json` 原先在本清单里，而同一个文件块下方（`scan_cache_file`）
    // 就把体检结果定义为「可重扫的扫描缓存」—— 与上面「丢了就恢复不了」的判据自相矛盾。
    // 按判据移出：首次启动不带旧体检结果，用户重跑一次体检即可（只读、秒级）。
    "system-info.json",
    "paths.json",
    "Local State",
    "update-mirror.json",
    "optimizer-backups.json",
    "bench-history.json",
];

/// 需整体搬迁的**目录**清单（逐文件、缺失才复制）。同上加判据。
/// - `backgrounds`    用户手工导入的背景图
/// - `fonts`          用户导入字体的副本（不搬则字体设置里的"导入字体"整条失效）
/// - `startup-backup`     禁用启动项的原文件备份，「恢复」依赖它
/// - `peripheral-backup`  外设设置的 .reg 备份，「还原」依赖它
/// - `fileclean-backup`   删除清单（哪些文件被移进了回收站的凭据），丢了就无从交代删了什么
///
/// 不在列：contextmenu 的注册表备份 —— 实测 `ps/cm_backup.ps1` 写的是
/// `%USERPROFILE%\Desktop\右键菜单备份_<时间戳>`，本来就在桌面、不随数据目录迁移。
const MIGRATION_DIRS: &[&str] = &[
    "backgrounds",
    "fonts",
    "startup-backup",
    "peripheral-backup",
    "fileclean-backup",
];

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// 便携判定。开发期恒标准模式（对齐 Electron 的 `!app.isPackaged`），
/// 否则 target/debug 会被误判为便携盘。
pub fn is_portable() -> bool {
    !cfg!(debug_assertions) && exe_dir().join(PORTABLE_MARKER).is_file()
}

fn appdata_dir() -> PathBuf {
    PathBuf::from(std::env::var("APPDATA").unwrap_or_default())
}

/// 本应用数据目录（便携模式为 exe 目录 data 子目录）
pub fn app_data_dir() -> &'static PathBuf {
    DATA_DIR.get_or_init(|| {
        if is_portable() {
            return exe_dir().join("data");
        }
        appdata_dir().join(IDENTIFIER)
    })
}

/// Electron 版数据目录（迁移来源）
pub fn legacy_data_dir() -> PathBuf {
    appdata_dir().join(APP_NAME)
}

/// 更早版本数据目录（CleanTool → Trim 迁移来源）
pub fn older_legacy_data_dir() -> PathBuf {
    appdata_dir().join("CleanTool")
}

pub fn join_data(name: &str) -> PathBuf {
    app_data_dir().join(name)
}

pub fn log_dir() -> PathBuf {
    app_data_dir().join("logs")
}

pub fn appearance_file() -> PathBuf {
    join_data("appearance.json")
}

pub fn paths_config_file() -> PathBuf {
    join_data("paths.json")
}

pub fn system_info_file() -> PathBuf {
    join_data("system-info.json")
}

/// 扫描结果缓存文件（checkup.json / contextmenu-scan.json 等）
pub fn scan_cache_file(name: &str) -> PathBuf {
    join_data(name)
}

/// 实时网速记录报告目录（cache/realtime-reports，7 天自动清理）
pub fn realtime_report_dir() -> PathBuf {
    app_data_dir().join("cache").join("realtime-reports")
}

/// OSCrypt 主密钥候选来源：先新目录（搬迁副本），后旧目录（未搬迁/搬迁失败时兜底）
pub fn local_state_candidates() -> Vec<PathBuf> {
    vec![
        app_data_dir().join("Local State"),
        legacy_data_dir().join("Local State"),
    ]
}

/// 临时脚本目录：%APPDATA%\<id>\tmp（当前用户 ACL 保护）。
/// 不用 %TEMP%：那是全局可写目录，提权后执行脚本存在 TOCTOU 本地提权窗口（审查 A1）。
pub fn temp_script_dir() -> Result<PathBuf, String> {
    let dir = app_data_dir().join("tmp");
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建临时脚本目录失败: {e}"))?;
    }
    // 目录若被替换为符号链接/联接点，脚本内容可能被导向任意位置。
    // 审查 L12：判 reparse 属性位而不是 is_symlink —— 后者漏掉非 mount-point 类 tag
    // （云占位符/其它 reparse），而这里被穿透的后果是提权脚本写到别处。
    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        if super::protect::is_reparse(&meta) {
            return Err("临时脚本目录已被替换（符号链接/联接点），已拒绝写入".into());
        }
    }
    Ok(dir)
}

/// 启动迁移：CleanTool → Trim → com.xiaoxu.trim 两段式，均为「仅在目标不存在时复制」。
/// 返回写日志用的说明行；失败一律不阻塞启动（D5）。
pub fn migrate_legacy_once() -> Option<String> {
    let target = app_data_dir().to_path_buf();
    let mut notes: Vec<String> = Vec::new();

    // 第一段：CleanTool → Trim（仅在 Trim 目录整体缺失时）
    let legacy = legacy_data_dir();
    let older = older_legacy_data_dir();
    if !legacy.exists() && older.exists() {
        if copy_dir_missing_only(&older, &legacy).is_ok() {
            notes.push("已迁移历史数据目录 CleanTool → Trim".into());
        }
    }

    // 第二段：Trim → com.xiaoxu.trim（D5：仅当新目录无 appearance.json 时执行，可重跑）
    if legacy.exists() && !target.join("appearance.json").exists() {
        let mut copied = 0usize;
        for name in MIGRATION_FILES {
            let src = legacy.join(name);
            let dst = target.join(name);
            if !src.is_file() || dst.exists() {
                continue;
            }
            if std::fs::create_dir_all(&target).is_err() {
                break;
            }
            if std::fs::copy(&src, &dst).is_ok() {
                copied += 1;
            }
        }
        if copied > 0 {
            notes.push(format!(
                "已从旧数据目录迁移 {copied} 个文件（含 Local State 密钥载体）；旧目录保留可重跑"
            ));
        }
        // 目录类：同样「缺失才复制」，失败不阻塞启动。
        // 注意这是**首次启动同步执行**的一次性开销（仅当新目录无 appearance.json 时），
        // fonts/ 可能几十 MB；日志带上目录名与文件数，便于日后排查首启动耗时。
        let mut moved_dirs: Vec<String> = Vec::new();
        for name in MIGRATION_DIRS {
            let src = legacy.join(name);
            if !src.is_dir() {
                continue;
            }
            let n = std::fs::read_dir(&src).map(|r| r.count()).unwrap_or(0);
            if copy_dir_missing_only(&src, &target.join(name)).is_ok() {
                moved_dirs.push(format!("{name}({n} 项)"));
            }
        }
        if !moved_dirs.is_empty() {
            notes.push(format!("已迁移数据子目录：{}", moved_dirs.join("、")));
        }
    }

    if notes.is_empty() {
        None
    } else {
        Some(notes.join("；"))
    }
}

/// 目录级「缺失才复制」：逐文件递归，已存在的一律跳过（防覆盖用户新数据）
fn copy_dir_missing_only(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_missing_only(&from, &to)?;
        } else if !to.exists() {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一个唯一命名的临时根，测试结束自行删除（不依赖 tempfile crate）
    fn sandbox(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trim-paths-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn 迁移清单覆盖不可再生与还原依赖的数据() {
        // 判据：丢了用户就恢复不了 / 要重做的，必须在此列。
        // 这几项被移出清单不会有任何编译或测试失败，只会静默丢数据，故用断言钉住。
        for f in [
            "appearance.json",
            "settings.json",
            "paths.json",
            "Local State",
            "update-mirror.json",
            "optimizer-backups.json",
            "bench-history.json",
        ] {
            assert!(MIGRATION_FILES.contains(&f), "{f} 不在迁移文件清单");
        }
        for d in [
            "backgrounds",
            "fonts",
            "startup-backup",
            "peripheral-backup",
            "fileclean-backup",
        ] {
            assert!(MIGRATION_DIRS.contains(&d), "{d} 不在迁移目录清单");
        }
        // 反向断言：可再生内容不该混进来（会让首次启动做无谓的大量复制）
        for junk in ["cache", "redist", "logs", "tmp"] {
            assert!(!MIGRATION_DIRS.contains(&junk), "{junk} 可再生，不该整体搬迁");
        }
    }

    #[test]
    fn 目录搬迁绝不覆盖目标已有文件() {
        let root = sandbox("noclobber");
        let src = root.join("src");
        let dst = root.join("dst");
        std::fs::create_dir_all(src.join("nested")).unwrap();
        std::fs::write(src.join("a.txt"), b"old-from-legacy").unwrap();
        std::fs::write(src.join("nested/b.txt"), b"deep").unwrap();
        // 目标已存在同名文件（用户在新版里重新导入过）—— 必须保留新数据
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(dst.join("a.txt"), b"new-user-data").unwrap();

        copy_dir_missing_only(&src, &dst).unwrap();

        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"new-user-data", "旧目录覆盖了用户新数据");
        assert_eq!(std::fs::read(dst.join("nested/b.txt")).unwrap(), b"deep", "递归子目录未搬迁");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn 便携判定在开发构建下恒为标准模式() {
        // 防回归：dev 下 exe 位于 target/debug，若真按 Trim.portable 判定会把
        // 构建目录当数据盘。当前实现用 cfg!(debug_assertions) 短路，测试必然跑在 dev。
        assert!(!is_portable(), "调试构建不得判为便携模式");
    }
}