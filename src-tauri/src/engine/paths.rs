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

/// 从旧数据目录一次性搬迁的文件清单（D5 七个数据文件 + Local State 密钥载体）
const MIGRATION_FILES: &[&str] = &[
    "appearance.json",
    "settings.json",
    "optimization-state.json",
    "checkup.json",
    "system-info.json",
    "paths.json",
    "Local State",
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
    // 目录若被替换为符号链接/联接点，脚本内容可能被导向任意位置
    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        if meta.file_type().is_symlink() {
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