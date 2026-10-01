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
/// - 前 6 项是 D5 原有清单（含 `Local State` = OSCrypt 主密钥载体）—— 审查 v2-L10 订正计数：
///   `checkup.json` 按判据移出后（M15），"前 7 项"这个数字就已经不对了，注释一直没跟着改
/// - `update-mirror.json` = E 批 updater 的线路偏好
/// - `optimizer-backups.json` = 优化项的**值级注册表备份**；不搬过去，「还原」就只能
///   退化成反向判据，原来那个具体值再也回不来了（用户改完 Defender/UAC 想还原会失败）
/// - `bench-history.json` = 用户的历史测速/测速记录，重跑成本高且属个人数据
/// 不进清单的：`checkup.json` 之类扫描缓存（可重扫，见下方 `scan_cache_file`）、
/// `system-info.json`（同为缓存：`overview.rs` 首部就写明"首扫落盘、之后读缓存、
/// `refresh=true` 强扫"，与刚移出的 `checkup.json` 同一判据）、`cache`（可再生）、
/// `redist`（可重下）、`logs`/`tmp`（运行期产物）。
const MIGRATION_FILES: &[&str] = &[
    "appearance.json",
    "settings.json",
    "optimization-state.json",
    // 审查 M15：`checkup.json` 原先在本清单里，而同一个文件块下方（`scan_cache_file`）
    // 就把体检结果定义为「可重扫的扫描缓存」—— 与上面「丢了就恢复不了」的判据自相矛盾。
    // 按判据移出：首次启动不带旧体检结果，用户重跑一次体检即可（只读、秒级）。
    // 审查 v2-L10：`system-info.json` 与它同判据（可 `refresh=true` 重采），一并移出。
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
///
/// ⚠️ 审查 v2-M19（备份根分叉，2026-09-29 已收口）：这几处写侧原先硬编码
/// `%APPDATA%\Trim\*-backup`，于是便携模式下新产生的备份仍落在宿主机漫游目录、带不走，
/// 标准与便携实例还共写同一批目录。现在写入恒走 `app_data_dir()`，读取保留「新根 + 老根」
/// 双候选，唯一寻址口是 [`backup_write_dir`] / [`backup_read_dirs`]。
///
/// 但**同一本账有两份副本时不能按"新根优先"取**：迁移只是按名复制一次，而收口前所有写入都
/// 落老根，于是老根那份往往更新。新根优先会把用户后来禁用的启动项从界面里抹掉，而系统里它们
/// 还禁用着——台账取本口径见 `engine::native::startup_ledger_file`（取最近修改的那本）。
///
/// 这条注释原先还把写侧算到 PowerShell 头上（`startup_*.ps1`、`peripheral_apply.ps1`、
/// `cleanup_execute.ps1:706`、`memory_stubborn_block.ps1:40`）——那是 S3 退役前的旧轨坐标，
/// 现在 `src-tauri/ps/` 只剩 2 个脚本、`grep -i appdata` 零命中，写侧全在 Rust
/// （`engine/native.rs` 的启动项与外设备份、`commands/cleanup.rs` 的注册表备份）。
/// 留着错坐标比不留更坏：下一个人会去改一个不存在的文件。
const MIGRATION_DIRS: &[&str] = &[
    "backgrounds",
    "fonts",
    "startup-backup",
    "peripheral-backup",
    "fileclean-backup",
    // 规则库目录（决策清单 D1=A）：里面是用户下载的签名规则包、更新源覆盖与
    // 防回滚水位线——重做要重新联网取包并重新验签，按「丢了要重做」判据必须搬。
    // `uninstall` 同批进来是因为两个规则库必须同一口径，留一半会让便携模式只对半成立。
    "cleanup",
    "uninstall",
];

// N1（2026-09-29）**刻意不把 `cleanup-reg-backup` / `cleanup-files-backup` /
// `uninstall-reg-backup` 加进 MIGRATION_DIRS**，改走 `backup_read_entries` 兜底读，理由两条：
// ① 第二段迁移的闸门是「新根没有 appearance.json 才跑」，存量用户的新根早就有了 ⇒ 补清单
//   对他们一次都不会执行，等于修了个不生效的开关；兜底读对他们立刻生效。
// ② 便携模式的迁移目标在 U 盘上（`exe/data/`），把宿主机 `%APPDATA%\Trim` 里的历史备份
//   整批复制过去既拖慢首启动（这批可能有几百 MB），又把用户的本机路径带上共享介质。
// 结论：备份的"看得见 + 还能还原"由读取兜底负责，搬迁不是必要环节。

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
        let dir = if is_portable() {
            exe_dir().join("data")
        } else {
            appdata_dir().join(IDENTIFIER)
        };
        // N2（2026-09-29）：数据根一旦确定就把根注入原生扫描器。放在这里而不是各处记得调，
        // 理由是「谁能拿到数据根，谁就顺手把scanner 的名单根定下来」——漏注入的后果是
        // 排除/忽略名单按空处理，删除面**变大**（用户明确排除过的东西重新进候选），
        // 那比多排除更危险。`tools/check-fail-closed.mjs` D 段钉住这条注入。
        trim_finder::util::set_data_roots(dir.clone(), legacy_data_dir());
        dir
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

/// 备份类目录的**写入**根（v2-M19 收口）。
///
/// 只允许新根：双写会让两个根长期分叉，出现「还原时看到 A 根、写入落在 B 根」这种
/// 两边都自认正确的状态。规则库收口（决策清单 D1）用的就是同一条纪律。
pub fn backup_write_dir(sub: &str) -> PathBuf {
    app_data_dir().join(sub)
}

/// 备份类目录的**读取**候选，新根在前、取到即用。
///
/// 老根兜底不能删：启动搬迁是一次性「只补不覆盖」，磁盘满、权限异常、或便携盘插过别的
/// 机器，都可能让新根没有那份备份——而备份是「恢复 / 还原」按钮唯一的依据。
pub fn backup_read_dirs(sub: &str) -> Vec<PathBuf> {
    let mut dirs = vec![app_data_dir().join(sub)];
    let legacy = legacy_data_dir().join(sub);
    if legacy != dirs[0] {
        dirs.push(legacy);
    }
    dirs
}

/// 备份类的保留上限（N3，2026-09-29）：与 `delete_manifest::MANIFEST_KEEP`、还原包
/// `KEEP_BATCHES` 同一口径，不新造数字。
pub const BACKUP_KEEP: usize = 50;

/// 跨根列出备份条目：`(路径, 是否来自老根)`，新根在前、**按小写文件名去重**。
///
/// 为什么同名只留新根那份：还原入口是按文件名找实体的（`file` 参数来自渲染层），
/// 同一个名字挂两根会让"还原哪一个"变成掷硬币，而两根同名几乎只可能是搬迁残留的副本。
/// 老根兜底的意义是**让升级前的备份看得见、还能还原**，不是把它们再抄一份进来。
pub fn backup_read_entries(sub: &str) -> Vec<(PathBuf, bool)> {
    read_entries_across_roots(backup_read_dirs(sub))
}

/// `backup_read_entries` 的可注入内核：入参就是"根清单"（第一个算新根，其余算老根），
/// 单测才能拿临时目录测跨根去重与来源标记 —— 直接测上面那个只能对着真实数据根跑，
/// 本机有没有备份会让用例变成"碰巧绿"。
///
/// **只上报文件**：`cleanup-files-backup` 的根里混着 `<规则id>\` 目录，把它们当条目会让
/// "同名以新根为准"变成"新根一个目录屏蔽老根一份真备份"。目录过滤留在这一层，
/// 调用方就不必各写一遍 `is_file()`。
pub fn read_entries_across_roots(dirs: Vec<PathBuf>) -> Vec<(PathBuf, bool)> {
    let mut out: Vec<(PathBuf, bool)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (i, dir) in dirs.into_iter().enumerate() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for ent in rd.flatten() {
            let path = ent.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = ent.file_name().to_str().map(str::to_string) else { continue };
            let key = name.to_lowercase();
            if seen.iter().any(|s| *s == key) {
                continue;
            }
            seen.push(key);
            out.push((path, i > 0));
        }
    }
    out
}

/// 按文件名定位备份实体（新根优先）。还原侧**唯一**的路径解析入口——渲染层只给文件名，
/// 拼路径的权力留在这里，别让调用方各写一遍 `join` 而漏掉老根兜底。
pub fn resolve_backup_file(sub: &str, name: &str) -> Option<PathBuf> {
    backup_read_dirs(sub)
        .into_iter()
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// 只保留最近 `keep` 份备份（名字里的毫秒时间戳是定宽 13 位 ⇒ 字典序即时序，与
/// delete_manifest / restore_pack 同姿势）。
///
/// **只管新根**：老根那份是用户升级前的唯一还原依据，删它等于替用户丢掉最后的退路；
/// 读取兜底负责"看得见"，这里负责"我们自己写的地方不无限涨"（N3）。
///
/// 形状 `RegSealed` = 主文件 `<ms>_..._.reg` + 同目录封条 `<该文件名>.meta.json`。
/// 两者必须同生同死：只删主文件会留下孤儿封条，而封条本身也以 `.reg` 结尾……不，封条名是
/// `x.reg.meta.json`，不以 `.reg` 结尾，所以不会被当主文件计数；反过来若只删封条，主文件
/// 就变成"无据可查"，还原侧会按 `missing` 拒 —— 那比留下孤儿更糟。
pub fn prune_backups(dir: &Path, keep: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut names: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| n.ends_with(".reg") && !n.starts_with('.'))
        .collect();
    names.sort();
    while names.len() > keep {
        let oldest = names.remove(0);
        // v2-L4P-33（C-5）：引擎级裁剪出口一律回收站优先（AGENTS §3）。目录受 v2-M19
        // 寻址口约束（backup_write_dir 单根、非外部输入），再加一层 reparse 拒——
        // 链接件进回收站等于把它指向的实体卷进来。
        let main = dir.join(&oldest);
        let mut seal = oldest;
        seal.push_str(".meta.json");
        let seal_path = dir.join(&seal);
        let reparse = |p: &Path| {
            std::fs::symlink_metadata(p)
                .map(|m| crate::engine::protect::is_reparse(&m))
                .unwrap_or(true) // 读不到元数据按 reparse 处理（宁可不清，不误投）
        };
        if !reparse(&main) {
            let _ = trim_finder::scan::recycle::send_to_trash_os(main.as_os_str());
        }
        if !reparse(&seal_path) {
            let _ = trim_finder::scan::recycle::send_to_trash_os(seal_path.as_os_str());
        }
    }
}

/// 规则库目录收口（2026-09-28 决策清单 D1=A）用的三个入口。
///
/// 为什么要这三个而不是各处自己拼路径：清理/残留规则库长期写死 `%APPDATA%\Trim\{cleanup,uninstall}`
/// （Electron 时代的口径），于是便携模式下用户下载的更新落在宿主机漫游目录、带不走；
/// 标准实例与便携实例还共写同一个文件、互相覆盖水位线。收口到 `app_data_dir()` 后
/// 便携模式自动获得「规则随盘走」语义，AGENTS §7.3 的清缓存步骤也能真正覆盖规则。
///
/// 收口必须带**只读兜底**：启动搬迁是一次性「只补不覆盖」，磁盘满/权限异常时新根可能仍空，
/// 此时功能不能断。反过来**写入恒走新根**——双写会让两个根长期分叉，那正是 v2-M19 记下的旧病。

/// 写入用子目录（永远是新根；不存在时由调用方 create_dir_all）
pub fn data_subdir_for_write(rel: &str) -> PathBuf {
    app_data_dir().join(rel)
}

/// 读取用子目录：新根存在 → 新根，否则老根兜底
pub fn data_subdir_for_read(rel: &str) -> PathBuf {
    let fresh = app_data_dir().join(rel);
    if fresh.is_dir() {
        return fresh;
    }
    legacy_data_dir().join(rel)
}

/// 读取用文件：新根有这份 → 新根，否则老根兜底
/// （新根目录已存在但没有这份文件时，也必须回老根——那是搬迁没跑成的典型形态）
pub fn data_file_for_read(rel: &str) -> PathBuf {
    let fresh = app_data_dir().join(rel);
    if fresh.is_file() {
        return fresh;
    }
    legacy_data_dir().join(rel)
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

/// 临时脚本目录：%APPDATA%\<id>\tmp。
///
/// 审查 v2-L2 订正措辞：隔离度**不是本函数施加的** —— 全仓没有任何 ACL API 调用
/// （`SetNamedSecurityInfo`/`CreateSecurityDescriptor` 实测 0 命中，`set_permissions`
/// 在 Windows 上只能改只读位），实际保护来自 `%APPDATA%` 的**每用户默认 DACL**
/// （只有当前用户与 SYSTEM 可写）。本函数只做两件事：建目录、拒把脚本写进被
/// reparse（符号链接/联接点）替换过的目录。
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

/// 名单类文件（每行一条路径）的一次性搬迁（N2）。
///
/// 为什么单独一条、且**不走** `MIGRATION_FILES` 那条闸门：那份迁移只在「新根没有
/// appearance.json」时执行，存量用户永远碰不到；而名单是扫描器每轮都要读的活性文件，
/// 不搬就会出现"读取走老根、写入落新根"的两份真相 —— 用户删掉一条排除项，下轮又生效。
/// 搬完只留新根一份可写实体；老根那份原样保留（可重跑、也可人工回退）。合并细则见
/// `migrate_list_files_into`（逐行并集，不是二选一）。
pub fn migrate_list_files_once() -> Option<String> {
    migrate_list_files_into(app_data_dir().as_ref(), &legacy_data_dir())
}

/// 同上，但两个根由入参给 —— 名单合并的判定必须能拿临时目录测，对着真实数据根跑会变成
/// "这台机器恰好没有老名单"式的假绿。
///
/// 合并口径是**逐行并集**，不是"存在即用某一侧"（v2 报告 N2 第 3 条，纠正本仓初版）：
/// 名单是行集合，二选一会让用户在新根加了第一条排除项之后、老根那几十条**整批静默失效**，
/// 而"排除失效"的方向是**多删**，比"看不见备份"更坏。
/// 归一行 = trim → 去尾 `\` → 小写（与 `load_empty_ignore` 同口径），所以只差大小写
/// 或尾斜杠的同一行不会被重复追加 ⇒ 幂等。
///
/// U1-b（2026-10-01）：`cleanup-exclude.txt` 随「排除名单」、`cleanup-custom.txt` 随
/// 「自定义目录」整链下线，均已从本清单摘除。
fn migrate_list_files_into(target: &Path, legacy: &Path) -> Option<String> {
    const LIST_FILES: &[&str] = &["empty-ignore.txt"];
    let normalize = |raw: &str| -> String { raw.trim().trim_end_matches('\\').to_lowercase() };
    let mut moved: Vec<String> = Vec::new();
    for name in LIST_FILES {
        let src = legacy.join(name);
        if !src.is_file() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&src) else { continue };
        let dst = target.join(name);
        if !dst.is_file() {
            // 新根还没有：整份搬过去（老根原件保留，可重跑、也可人工回退）
            if std::fs::create_dir_all(target).is_err() {
                break;
            }
            if std::fs::copy(&src, &dst).is_ok() {
                moved.push(format!("{name}(整份)"));
            }
            continue;
        }
        // 两边都有：只把新根缺的行并进去
        let Ok(cur_text) = std::fs::read_to_string(&dst) else { continue };
        let have: std::collections::HashSet<String> = cur_text
            .lines()
            .map(&normalize)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let mut missing: Vec<String> = Vec::new();
        let mut queued: std::collections::HashSet<String> = std::collections::HashSet::new();
        for line in text.lines() {
            let key = normalize(line);
            if key.is_empty() || key.starts_with('#') || have.contains(&key) || !queued.insert(key) {
                continue;
            }
            missing.push(line.trim().to_string());
        }
        if missing.is_empty() {
            continue;
        }
        let mut merged = cur_text;
        if !merged.ends_with('\n') {
            merged.push('\n');
        }
        merged.push_str(&missing.join("\n"));
        merged.push('\n');
        // 写走原子写：名单是保护面，半截写入会让后面的行整批读不到（= 多删）
        if crate::security::atomic_write_file(&dst, merged.as_bytes()).is_ok() {
            moved.push(format!("{name}(并 {n} 行)", n = missing.len()));
        }
    }
    if moved.is_empty() {
        return None;
    }
    Some(format!("已把名单文件迁入当前数据目录：{}", moved.join("、")))
}

/// 启动迁移：CleanTool → Trim → com.xiaoxu.trim 两段式，均为「仅在目标不存在时复制」。
/// 返回写日志用的说明行；失败一律不阻塞启动（D5）。
pub fn migrate_legacy_once() -> Option<String> {
    let target = app_data_dir().to_path_buf();
    let mut notes: Vec<String> = Vec::new();

    // 第一段：CleanTool → Trim（仅在 Trim 目录整体缺失时）
    // 审查 v2-L10：这一段刻意**不走** MIGRATION_FILES/DIRS 白名单，与第二段口径不同，
    // 不是漏改。判据是风险不对称：白名单漏一项 = 用户数据静默丢失且无法补救，
    // 而整树多带几份 cache/logs 只多占空间、且都是可再生内容。
    // 真正的搬迁闸门在第二段（往**在用的**数据目录里写），那里逐名走清单、有断言守着。
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

    /// 审查 v2-M13：Tauri v2 的 `$APPDATA` **已经含 identifier**
    /// （crate `path/desktop.rs` 的 `app_data_dir()` = `dirs::data_dir().join(identifier)`，
    /// `path/mod.rs` 又把 `BaseDirectory::AppData` 映射到它）。当初按「`%APPDATA%` 根」的直觉
    /// 写成 `$APPDATA/com.xiaoxu.trim/backgrounds/**`，展开成双份目录 ⇒ 背景图与导入字体
    /// 的 URL 永不命中，也就是 P1 那个「已修好」实际没生效。这条断言钉住「别再多写一层」，
    /// 并顺手确认两个目录仍在白名单里（去掉整条 allow 会让同一个功能以另一种方式坏掉）。
    #[test]
    fn asset_scope_does_not_repeat_identifier() {
        let conf = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tauri.conf.json"))
            .expect("读不到 tauri.conf.json");
        let v: serde_json::Value =
            serde_json::from_str(&conf).expect("tauri.conf.json 不是合法 JSON");
        assert!(
            v["app"]["security"]["assetProtocol"]["enable"] == true,
            "asset 协议未启用，本断言的口径需要先同步"
        );
        let allow = v["app"]["security"]["assetProtocol"]["scope"]["allow"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(!allow.is_empty(), "asset 协议启用但 allow 清单为空");
        let mut seen = Vec::new();
        for item in &allow {
            let s = item.as_str().unwrap_or("");
            let rest = s
                .strip_prefix("$APPDATA/")
                .unwrap_or_else(|| panic!("asset scope 只能用 $APPDATA 根（当前：{s}）"));
            assert!(
                !rest.starts_with(&format!("{IDENTIFIER}/")),
                "asset scope 多写了一层 identifier，会展开成双份目录：{s}"
            );
            seen.push(rest);
        }
        assert!(
            seen.iter().any(|r| r.ends_with("backgrounds/**")),
            "背景图目录被移出 asset 白名单"
        );
        assert!(
            seen.iter().any(|r| r.ends_with("fonts/**")),
            "字体目录被移出 asset 白名单"
        );
        // 白名单只能是静态 glob，且必须收在应用私有目录内（不得出现 .. 或绝对盘符）
        for r in &seen {
            assert!(!r.contains("..") && !r.contains(':'), "asset scope 越界：{r}");
        }
    }

    /// v2-M19 备份根收口的口径：写入恒新根，读取第一位=写入根、后面挂老根兜底。
    /// 两根在开发/标准形态下必然不同（`com.xiaoxu.trim` vs `Trim`），所以候选是 2 条；
    /// 断言写成"包含老根"而不是"第二条就是老根"，是为了让以后加第三本历史根（CleanTool）
    /// 时不必改这条测试。
    #[test]
    fn backup_root_writes_new_and_reads_with_legacy_fallback() {
        let sub = "startup-backup";
        let write = backup_write_dir(sub);
        assert_eq!(write, app_data_dir().join(sub), "备份写入必须落当前数据目录");
        assert!(
            !write.starts_with(legacy_data_dir()),
            "写入又回到老根，v2-M19 的分叉就没被收掉：{write:?}"
        );
        let dirs = backup_read_dirs(sub);
        assert_eq!(dirs[0], write, "读取候选的第一位就是写入根");
        assert!(
            dirs.iter().any(|d| d.starts_with(legacy_data_dir())),
            "老根兜底被删：收口前留下的备份将读不到，而它是「恢复」按钮唯一的依据：{dirs:?}"
        );
        assert_eq!(
            dirs.len(),
            dirs.iter().collect::<std::collections::HashSet<_>>().len(),
            "候选里有重复根"
        );
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
            // 规则库目录进了写入路径：漏掉这两项 = 收口后老根的规则文件不再被读到
            // （用户已下载的更新静默失效，且没有任何报错），与备份目录同一条判据。
            "cleanup",
            "uninstall",
        ] {
            assert!(MIGRATION_DIRS.contains(&d), "{d} 不在迁移目录清单");
        }
        // 反向断言：可再生内容不该混进来（会让首次启动做无谓的大量复制）
        for junk in ["cache", "redist", "logs", "tmp"] {
            assert!(!MIGRATION_DIRS.contains(&junk), "{junk} 可再生，不该整体搬迁");
        }
        // 审查 v2-L10：文件侧同样反向钉。`checkup.json`(M15) 与 `system-info.json`(L10)
        // 都是「可重扫/可重采」的缓存，一旦被"顺手"加回清单，判据就又自相矛盾了——
        // 而那正是本清单唯一的一条线。
        for cache in ["checkup.json", "system-info.json"] {
            assert!(
                !MIGRATION_FILES.contains(&cache),
                "{cache} 是可重扫缓存，按判据不得进迁移清单（移出后重扫/重采即可）"
            );
        }
    }

    /// 规则库目录收口（D1=A）的两个入口不许互换语义：
    /// 写入恒新根 —— 若写成「看哪边存在就写哪边」，两个根会各自持有一份规则与水位线，
    /// 读取侧 `max(内置版本, 水位线)` 的口径当场失效（v2-M19 记的同一类病不能重犯）；
    /// 读取在两边都没有时回落老根 —— 一次性搬迁没跑成（磁盘满/权限）时功能不能断。
    #[test]
    fn 规则目录写入口不随存在性漂移() {
        let ghost = "trim-nonexistent-9f3a";
        assert_eq!(data_subdir_for_write(ghost), app_data_dir().join(ghost));
        assert_eq!(data_subdir_for_write("cleanup"), app_data_dir().join("cleanup"));
        assert_ne!(
            data_subdir_for_write("cleanup"),
            legacy_data_dir().join("cleanup"),
            "写入入口落到老根 = 双根分叉"
        );
        assert_eq!(data_subdir_for_read(ghost), legacy_data_dir().join(ghost));
        assert_eq!(data_file_for_read(ghost), legacy_data_dir().join(ghost));
        // 便携模式下新根随 exe 走（规则随盘携带是本次收口的目的）
        assert!(data_subdir_for_write("cleanup").starts_with(app_data_dir().as_path()));
    }

    /// N1：跨根列举必须是「新根同名优先 + 老根标来源」。
    /// 同名挂两根时还原按文件名找实体，两条同名等于让用户掷硬币。
    #[test]
    fn 跨根列举_新根优先且老根标来源() {
        let root = sandbox("cross-root");
        let new = root.join("new");
        let legacy = root.join("legacy");
        std::fs::create_dir_all(&new).unwrap();
        std::fs::create_dir_all(legacy.join("sub")).unwrap();
        std::fs::write(new.join("a.reg"), b"new-a").unwrap();
        std::fs::write(legacy.join("a.reg"), b"legacy-a").unwrap(); // 与新根同名
        std::fs::write(legacy.join("b.reg"), b"legacy-b").unwrap();
        std::fs::write(legacy.join("sub/c.txt"), b"x").unwrap(); // 子目录不得被当条目上报

        let got = read_entries_across_roots(vec![new.clone(), legacy.clone()]);
        let mut by_name: Vec<(String, bool)> = got
            .iter()
            .map(|(p, legacy_flag)| {
                (p.file_name().unwrap().to_string_lossy().to_string(), *legacy_flag)
            })
            .collect();
        by_name.sort();
        assert_eq!(
            by_name,
            vec![("a.reg".to_string(), false), ("b.reg".to_string(), true)],
            "同名必须以新根为准且只留一条，老根独有项要标 fromLegacy"
        );

        // 判红自测口径：去掉去重 ⇒ 两条 a.reg；去掉 i>0 ⇒ b.reg 不再标老根
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 新根的**同名目录**不得屏蔽老根的真备份（本轮实测到旧写法就会这样：目录被当条目
    /// 上报并占掉去重名，结果列表里没有那份能还原的 .reg）
    #[test]
    fn 新根同名目录不屏蔽老根实体() {
        let root = sandbox("shadow");
        let new = root.join("new");
        let legacy = root.join("legacy");
        std::fs::create_dir_all(new.join("1700000000007_Alpha.reg")).unwrap();
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("1700000000007_Alpha.reg"), b"Windows Registry Editor").unwrap();
        let got = read_entries_across_roots(vec![new, legacy]);
        assert_eq!(got.len(), 1, "目录不是备份条目: {got:?}");
        assert!(got[0].1, "唯一那份来自老根，要标 fromLegacy");
        assert!(got[0].0.is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// N3：保留上限裁最老批次，并让封条与主文件同生同死。
    /// 只管新根由调用方保证（`backup_write_dir`），老根那份是升级前唯一还原依据。
    #[test]
    fn 备份保留上限裁最老份且连封条一起删() {
        let root = sandbox("prune");
        let dir = root.join("cleanup-reg-backup");
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..5u64 {
            let name = format!("170000000{i}_key_{i}.reg");
            std::fs::write(dir.join(&name), b"Windows Registry Editor").unwrap();
            let mut seal = name;
            seal.push_str(".meta.json");
            std::fs::write(dir.join(seal), b"{}").unwrap();
        }
        prune_backups(&dir, 3);
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "1700000002_key_2.reg".to_string(),
                "1700000002_key_2.reg.meta.json".to_string(),
                "1700000003_key_3.reg".to_string(),
                "1700000003_key_3.reg.meta.json".to_string(),
                "1700000004_key_4.reg".to_string(),
                "1700000004_key_4.reg.meta.json".to_string(),
            ],
            "必须裁掉最老两份，且它们的封条一起消失"
        );

        // 孤儿封条（主文件已被用户删掉）不得占保留额度：只数 .reg
        std::fs::write(dir.join("1700000009_orphan.reg.meta.json"), b"{}").unwrap();
        prune_backups(&dir, 3);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().flatten().count(),
            7,
            "三份主文件 + 三份封条 + 一份孤儿封条，孤儿不参与计数"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 还原侧的跨根定位：新根优先，新根缺失才回老根；两处都没有 ⇒ None（不得凭空缺路径 import）
    #[test]
    fn 备份实体定位新根优先且缺文件返回空() {
        let root = sandbox("resolve");
        let new = root.join("new");
        let legacy = root.join("legacy");
        std::fs::create_dir_all(&new).unwrap();
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("only_legacy.reg"), b"l").unwrap();
        std::fs::write(new.join("both.reg"), b"n").unwrap();
        std::fs::write(legacy.join("both.reg"), b"l").unwrap();
        let dirs = vec![new.clone(), legacy.clone()];
        let pick = |name: &str| -> Option<PathBuf> {
            dirs.iter().map(|d| d.join(name)).find(|p| p.is_file())
        };
        assert_eq!(pick("only_legacy.reg"), Some(legacy.join("only_legacy.reg")));
        assert_eq!(pick("both.reg"), Some(new.join("both.reg")));
        assert_eq!(pick("missing.reg"), None);
        let _ = std::fs::remove_dir_all(&root);
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

    /// N2：名单搬迁必须是**逐行并集**。老根那本有 2 条、用户在新版里又加了 1 条 ⇒ 新根
    /// 文件已存在；"二选一"会让老根那 2 条整批静默失效，而忽略名单失效的方向是**多删**。
    /// 夹具用 empty-ignore.txt —— U1-b 之后本清单里唯一还活着的名单，性质必须仍然被钉住。
    /// 同时守住：新根原有行不动、只差大小写或尾斜杠的同一行不重复追加、重跑幂等。
    #[test]
    fn 名单搬迁逐行合并而非二选一() {
        let root = sandbox("lists");
        let cur = root.join("cur");
        let old = root.join("old");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&cur).unwrap();
        std::fs::write(
            old.join("empty-ignore.txt"),
            "# 旧版注释\r\nC:\\Users\\me\\Keep\\\r\nC:\\Users\\me\\AlsoKeep\r\n".as_bytes(),
        )
        .unwrap();
        std::fs::write(cur.join("empty-ignore.txt"), b"C:\\Users\\me\\NewOne\r\n").unwrap();

        let note = migrate_list_files_into(&cur, &old).expect("应合并出缺失行");
        assert!(note.contains("2 行"), "老根两条都该并进来: {note}");
        let text = std::fs::read_to_string(cur.join("empty-ignore.txt")).unwrap();
        assert!(text.contains("NewOne"), "新根原有行不得丢: {text}");
        assert!(text.contains("me\\Keep"), "尾斜杠行要并入（写入保持原样）: {text}");
        assert!(text.contains("AlsoKeep"), "另一条老行同样要并入: {text}");
        assert!(!text.contains('#'), "注释不是路径，不并入: {text}");
        assert!(old.join("empty-ignore.txt").is_file(), "老根原件保留（可人工回退）");

        // 幂等：再跑一次既不得重复追加，也不得产生搬迁日志（启动每次都调这条）
        let again_note = migrate_list_files_into(&cur, &old);
        assert!(again_note.is_none(), "已合并完不得再改写名单: {again_note:?}");
        assert_eq!(
            std::fs::read_to_string(cur.join("empty-ignore.txt")).unwrap(),
            text,
            "第二次运行必须逐字节不变"
        );

        // 只差大小写 = 同一行，不得当成缺失行追加（否则名单越跑越长）
        std::fs::write(old.join("empty-ignore.txt"), b"C:\\Users\\me\\X\r\n").unwrap();
        std::fs::write(cur.join("empty-ignore.txt"), b"c:\\users\\me\\x\r\n").unwrap();
        assert!(migrate_list_files_into(&cur, &old).is_none(), "大小写差异不得被当成新行");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 新根完全没有名单时才走"整份搬"（启动只调一次的机会不会重来）
    #[test]
    fn 新根无名单时整份搬迁() {
        let root = sandbox("lists-copy");
        let cur = root.join("cur");
        let old = root.join("old");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("empty-ignore.txt"), b"C:\\b\r\n").unwrap();
        let note = migrate_list_files_into(&cur, &old).expect("名单该整份搬过来");
        assert!(note.contains("empty-ignore.txt(整份)"), "{note}");
        assert_eq!(std::fs::read(cur.join("empty-ignore.txt")).unwrap(), b"C:\\b\r\n");
        let _ = std::fs::remove_dir_all(&root);
    }
}