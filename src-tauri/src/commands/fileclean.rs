//! fileclean 域（D 批）：fileclean:scan / delete-file / execute
//!
//! 对照 Electron `vendor/upstream-js/main.js` 7086-7334。QQ/微信文件清理：
//! 扫描**内容根**（见 `QQ_CONTENT_RELS` / `WECHAT_CONTENT_RELS`：每个根深度 ≤`MAX_DEPTH`、
//! 输出 ≤`MAX_FILES` 项）→ 分类 image/video/cache/data →
//! 只允许删除本窗口本次扫描结果内的文件；删除一律回收站优先 + 删除清单落盘。
//!
//! 为什么不再从配置根递归整棵：QQ NT / 微信 4.0 把可清理内容埋在账号目录的数据子目录里
//! （配置根下 4-9 层），整根 BFS 的深度预算全花在账号/容器目录上——本机实测旧口径 QQ
//! 命中 0 项、微信只命中 38 项，同时回执照报 truncated（提示「结果可能不完整」）。
//! 现在按「清理项声明的路径」分路扫描，每路独立计数/计深，互不顶账。
//!
//! 关键安全/语义（与 Electron 逐条对齐）：
//! - 扫描根只能来自已保存的路径配置（qqFileDir / wechatFileDir），
//!   customPath 必须与解析后的配置一致——防止借扫描读任意目录。
//! - BFS 跳过符号链接/junction；depth 0 根层不收文件；depth<2 不深入
//!   recv*/msg* 目录（FC-2：根层 .dat 是账号数据库，.db 永不归 data，FC-3）。
//! - 扫描结果按「窗口 label + 清理类型」分槽（槽键走 `snapshot::domain_key`，与
//!   finder/netcheck/memory 同口径）；删文件/批量删全部过本槽白名单。
//! - data 类只收 `.dat`（排除 .db/.adb/.aes 等数据库/密钥文件）。
//! - 读图通道 `fileclean:read-image` 已随预览链退役（`IMAGE_MAX_BYTES` 同批删除），
//!   现注册面只有 scan / delete-file / execute 三条。
//! - 危险操作前 flush_sync；success 语义=通道执行成功（失败明细随 data 返回）。
//!   删除**只进回收站**：回收站失败即如实报错，不做永久删除兜底（AGENTS §3）。

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tauri::{Emitter, Runtime, WebviewWindow};

// P2-1（审查 2026-10-07）：路径键统一走 engine 唯一实现（原先本文件另有一份
// strip_verbatim + Path::components 折叠版，与 finder/startup/appearance 口径不一）
use crate::engine::paths::{exceeds_char_len, path_key};
use crate::engine::{delete_manifest, guard, log, paths, protect, snapshot};
use crate::security;

/// 结果集上限（**输出**口径）：`scan_root` 只往 `items` 里收这么多条。
///
/// P1-③ 的裁定：这里刻意**不**再加一条「遍历预算」（`MAX_SCAN_ENTRIES` 那种同思路常量）。
/// 本函数的真实成本不是「条目多」而是「每个条目多付一次 `symlink_metadata`」——
/// 不匹配后缀的条目 `continue` 不入 `items`，于是 20 万文件的信箱目录会整棵走完、
/// 把上限的语义从「输出封到 2000」变成「遍历也封在 2000」。加遍历预算会把截断点
/// 从「攒满 2000 条命中」挪到「看过 N 个条目」，落在预算之后才出现的合法命中因此
/// 消失 —— 那是改命中集，属最高风险面（AGENTS §5.1 的同一根因）。
/// 改法换成把逐条 syscall 去掉（见 `scan_root` 里的 reparse 复核），
/// 遍历面与判定面一字未动：命中集、先到先得的行序、截断点全部照旧。
const MAX_FILES: usize = 2000;
/// 一次扫描的**全局**输出上限（R1d-M12）：单根有上限，但内容根随账号数放大；
/// 按 5× 单根取 10,000（2026-10-26 小旭拍板，上界现算见 P2-E 卡）。
const MAX_FILES_TOTAL: usize = 10_000;
/// 单个内容根的深度闸。**不是**「内容在第几层」的判据（那由内容根决定），只是防病态树的
/// 兜底；取 24 与常规清理域 `FK_SNAPSHOT_MAX_DEPTH` 同口径。
///
/// 旧值 4 是相对**配置根**计数的，而实测内容在配置根下 4-9 层、在内容根下最多 7 层
/// （QQ `nt_data\ams\...` 的 Chromium 缓存链），旧口径必然截断主内容（Emoji 就在
/// 数据根下第 5 层）——所以深度预算必须改挂在内容根上并按实测覆盖，不是「调大上限消提示」。
const MAX_DEPTH: usize = 24;
const MAX_PATH_LEN: usize = 400;

/// 每种清理类型的「内容根」相对路径：先按配置根本身试一次，再按配置根的一级子目录
/// （账号目录）各试一次（见 `expand_content_roots`）。用户既可能把路径配到
/// `Tencent Files` / `xwechat_files` 这一层，也可能配到单个账号目录。
///
/// QQ 的两条对应账号库之外的聊天数据目录（与常规清理规则 `tencentQq` 收窄后的
/// `nt_data` 口径一致）；微信取账号目录下的缓存/消息/临时/业务子目录。
/// `all_users` 是微信共享目录：旧整根口径会收 `all_users\whatsnew.dat`，把它保留为内容根
/// 是为了不让这次收窄**静默缩小**可删集合。
const QQ_CONTENT_RELS: &[&str] = &[r"nt_qq\nt_data", r"nt_qq\global\nt_data"];
const WECHAT_CONTENT_RELS: &[&str] = &["cache", "msg", "temp", "business", "all_users"];

fn content_rels(ty: &str) -> &'static [&'static str] {
    if ty == "qq" {
        QQ_CONTENT_RELS
    } else {
        WECHAT_CONTENT_RELS
    }
}

/// 批量删除的单批上限（v7.2 `R1d-L04`）：与 `MAX_FILES` 同值是**基线**，实际闸取
/// `max(本常量, 槽大小)`（见 `fileclean_execute`）——扫描按内容根分路后单条目可超过 2000，
/// 固定值会把完整清单整批拒掉。`finder` 侧同类闸叫 `FINDER_DELETE_MAX`，
/// 两边都显式命名才谈得上对账（跨域批量上限口径不一是本条的根因）。
const FILECLEAN_DELETE_MAX: usize = 2000;
// IMAGE_MAX_BYTES 随 fileclean:read-image（base64 dataURL 通道）退役删除：
// 图片改走 asset 协议磁盘直连（cleanup/preview_assets.rs 按需放行），不再整文件进内存。

const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "gif", "bmp", "webp", "svg"];
const VIDEO_EXTS: &[&str] = &["mp4", "avi", "mov", "mkv", "flv"];
const CACHE_EXTS: &[&str] = &["tmp", "log", "bak", "cache"];

#[derive(Clone)]
pub(crate) struct Scope {
    root: String,
    files: HashSet<String>,
}

use crate::commands::state::FILECLEAN_SCOPES;

fn slot_key(label: &str, ty: &str) -> String {
    // v7.2 `R1d-L06`：域内四张槽表原先两种分隔（本表 `:`、finder `|`）、两种容器。
    // 分隔符不同不影响正确性（各表基数都成立、没有跨窗顶账），改它是为了让**槽键构造
    // 只剩一处实现**；本域的键在位与否由 `u_r1d_command_contracts` 断言钉住。
    // 注意：`check-native-hygiene` 的 N8 只吃 `snapshot::{set,get,clear}` 调用点，
    // 本表这类自建容器仍在它射程外（要覆盖得扩 N8c，属门禁候选，别以为已覆盖）。
    snapshot::domain_key(label, ty)
}

fn scope_store(label: &str, ty: &str, root: String, files: HashSet<String>) {
    let mut g = FILECLEAN_SCOPES.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashMap::new)
        .insert(slot_key(label, ty), Scope { root, files });
}

fn scope_get(label: &str, ty: &str) -> Option<Scope> {
    FILECLEAN_SCOPES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(&slot_key(label, ty)).cloned())
}

/// 删图槽归属：槽按「发起扫描的窗口 label」存，删除请求只认自己 label 的槽。
/// （曾有的「preview 子窗 → main」映射随预览子窗退役删除——图片预览已改主窗内嵌
/// LiteBox，不再有子窗跨槽读图的场景；`in_scope` 才是真闸门。）
fn scope_owner(label: &str) -> &str {
    label
}

/// 「大目录」判据（仅影响日志后缀，不参与扫描/删除判定）。
///
/// R1d-U04：旧实现直接对路径做大小写敏感的 `contains("tencent")`，而 QQ 默认目录是
/// `Tencent Files`（大写 T）⇒ 默认路径恒判 false；同时子串匹配会把 `...\notencent\...`
/// 这类同名片段误命中。这里统一走 `path_key` 归一（小写 + 反斜杠 + 去尾分隔符），再按
/// **目录段**比较：段等于 `tencent` / `tencent files`，或以 `xwechat` 开头。
fn is_large_qq_dir(resolved: &str) -> bool {
    path_key(resolved)
        .split('\\')
        .any(|seg| seg == "tencent" || seg == "tencent files" || seg.starts_with("xwechat"))
}

fn config_key(ty: &str) -> &'static str {
    if ty == "qq" {
        "qqFileDir"
    } else {
        "wechatFileDir"
    }
}

fn default_dirs(ty: &str) -> Vec<PathBuf> {
    let home = std::env::var("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_default();
    let docs = home.join("Documents");
    if ty == "qq" {
        vec![docs.join("Tencent Files")]
    } else {
        vec![docs.join("xwechat_files")]
    }
}

/// 读已保存的路径配置。读不到 / 解析失败 / 空串都返回 None，调用方 fail-closed。
///
/// v5-K01 批次 4（R7-M05）：三态读器——读失败（Corrupt）已在 read_json_state 内
/// warn 留痕；fail-closed 语义不变（None ⇒ 默认目录），写侧 update_json 拒写。
fn saved_dir(ty: &str) -> Option<String> {
    let cfg = match security::read_json_state(&paths::paths_config_file()) {
        security::JsonState::Ok(v) => v,
        _ => serde_json::json!({}),
    };
    cfg.get(config_key(ty))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// 解析实际扫描目录。
///
/// v2 口径（2026-10-04 用户裁决 1）：`customPath` 只能是对已保存路径的确认，
/// 不能作为覆盖值。这样渲染层即使被注入，也不能借 `customPath` 让扫描读任意目录。
/// 实际文件操作仍用配置里的值，不用渲染层回传的字符串。
fn resolve_dir(
    ty: &str,
    custom: &Option<String>,
    saved: Option<String>,
) -> Result<PathBuf, String> {
    let gate_msg = "扫描路径必须来自已保存的路径配置，请先在设置中保存该路径";
    if let Some(c) = custom.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        let Some(saved) = saved.as_deref() else {
            return Err(gate_msg.to_string());
        };
        if path_key(c) != path_key(saved) {
            return Err(gate_msg.to_string());
        }
        return Ok(PathBuf::from(saved));
    }
    if let Some(saved) = saved {
        return Ok(PathBuf::from(saved));
    }
    default_dirs(ty)
        .into_iter()
        .find(|p| p.is_dir())
        .ok_or_else(|| "路径不存在，请在设置中配置文件目录".to_string())
}

fn configured_dir(ty: &str, custom: &Option<String>) -> Result<PathBuf, String> {
    resolve_dir(ty, custom, saved_dir(ty))
}

fn ext_of(name: &str) -> String {
    Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// 审查 v2-M5：该路径能不能作为「可预览/可删除条目」进入扫描槽。
/// 判据是「名字能否无损地表示成 Rust `String`」——本域的 `items[].path` 与槽键都由
/// `to_string_lossy()` 产出，而删除用的是**渲染层回传的那个字符串**：
/// 名字含孤立代理项时往返得到的是另一个路径，轻则删不到、重则删掉一个恰好
/// 用 U+FFFD 命名的无关文件。所以这类条目根本不收录（不可预览也不可删），并计数上报。
fn deletable_name(p: &Path) -> bool {
    !trim_finder::util::has_lossy_path(p)
}

fn classify(ext: &str) -> Option<&'static str> {
    if IMAGE_EXTS.contains(&ext) {
        Some("image")
    } else if VIDEO_EXTS.contains(&ext) {
        Some("video")
    } else if CACHE_EXTS.contains(&ext) {
        Some("cache")
    } else if ext == "dat" {
        Some("data") // FC-3：仅 .dat；.db/.adb/.aes 等排除
    } else {
        None
    }
}

/// 扫配置根整棵（旧口径，仅在展开不出任何内容根时兜底），根层文件不收。
fn scan_root(root: &Path) -> (Vec<Value>, usize, usize, bool) {
    scan_dir(root, false, MAX_DEPTH, MAX_FILES)
}

/// 多个内容根合并：各路独立计数、独立计深，任一路触顶即整体 `truncated`。
/// 内容根之间天然不相交（账号目录下的不同子目录），不做跨路去重。
fn scan_lanes(lanes: &[PathBuf]) -> (Vec<Value>, usize, usize, bool) {
    scan_lanes_capped(lanes, MAX_FILES, MAX_FILES_TOTAL)
}

/// 多路合并 + 全局总量闸（R1d-M12）：每路仍按 `per_lane` 计深/截断；
/// 全局满额即停，尚有余路时把 `truncated` 置真（恰好收满且已无余路不算截断）。
fn scan_lanes_capped(lanes: &[PathBuf], per_lane: usize, total_cap: usize) -> (Vec<Value>, usize, usize, bool) {
    let mut items: Vec<Value> = Vec::new();
    let mut scanned = 0usize;
    let mut unhandled = 0usize;
    let mut truncated = false;
    for (i, lane) in lanes.iter().enumerate() {
        if items.len() >= total_cap {
            truncated = true;
            break;
        }
        let (mut it, s, u, t) = scan_dir(lane, true, MAX_DEPTH, per_lane);
        let room = total_cap.saturating_sub(items.len());
        if it.len() > room {
            it.truncate(room);
            truncated = true;
        }
        items.append(&mut it);
        scanned += s;
        unhandled += u;
        truncated |= t;
        if items.len() == total_cap && i + 1 < lanes.len() {
            truncated = true;
            break;
        }
    }
    (items, scanned, unhandled, truncated)
}

/// 展开内容根：按「配置根本身 + 它的一级子目录」各试一次相对路径，只认存在的普通目录
/// （reparse 不跟随，与扫描入口同一判据）。结果排序保证同一份盘上结果的扫描顺序与
/// 截断点稳定，不随 `read_dir` 的枚举顺序漂移。
fn expand_content_roots(root: &Path, rels: &[&str]) -> Vec<PathBuf> {
    let mut bases: Vec<PathBuf> = vec![root.to_path_buf()];
    if let Ok(rd) = std::fs::read_dir(root) {
        for ent in rd.flatten() {
            let p = ent.path();
            if let Ok(m) = std::fs::symlink_metadata(&p) {
                if m.is_dir() && !protect::is_reparse(&m) {
                    bases.push(p);
                }
            }
        }
    }
    bases.sort();
    let mut out: Vec<PathBuf> = Vec::new();
    for base in &bases {
        for rel in rels {
            let p = base.join(rel);
            if let Ok(m) = std::fs::symlink_metadata(&p) {
                if m.is_dir() && !protect::is_reparse(&m) {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    // 去掉被其它内容根包含的路径（例如 `all_users` 与 `all_users\cache` 同时存在）：
    // 同一文件被两路各收一次会让项数与总体积翻倍，删除侧也会重复尝试。
    let mut kept: Vec<PathBuf> = Vec::new();
    for p in out {
        if kept.iter().any(|k| p != *k && p.starts_with(k)) {
            continue;
        }
        kept.push(p);
    }
    kept
}

/// BFS 扫描（不跟随符号链接），单个根的预算由调用方决定。
/// 返回 (items, 已归类的文件数, 因文件名无法无损表示而未收录的条目数, 是否截断)。
///
/// 审查 v2-M5（与 finder 域同源）：本域的删除目标是**渲染层回传的字符串**重建的，
/// 而 `items[].path` 来自 `to_string_lossy()`。名字里有孤立代理项（GBK 遗留介质、
/// 字节级拷贝）时，lossy 往返得到的是另一个路径 —— 轻则删不到，重则删掉一个恰好
/// 用 U+FFFD 命名的无关文件。所以这类条目**根本不收录**（不进槽、不可删），
/// 并把数量回给上层：不静默丢（v2-M4 同口径）。
///
/// 预算作为参数传入，是为了让「旧口径（整根 + 4 层）」在测试里有一份可复现的对照，
/// 而不是把常量抄进用例。
fn scan_dir(
    root: &Path,
    collect_root_files: bool,
    max_depth: usize,
    max_files: usize,
) -> (Vec<Value>, usize, usize, bool) {
    let mut items: Vec<Value> = Vec::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((root.to_path_buf(), 0));
    let mut scanned = 0usize;
    let mut unhandled = 0usize;
    let mut truncated = false;

    while let Some((dir, depth)) = queue.pop_front() {
        // v4 P2-E（R1-M05）：截断必须留痕 —— 旧实现静默跳过超深/超限分支，
        // 回执与 UI 都不知道「结果可能不完整」，用户以为扫完了。
        if items.len() >= max_files {
            truncated = true;
            continue;
        }
        // v7.2 `R1d-M02`：这里原先写「出队 depth 大于 MAX_DEPTH 才记 truncated」，但入队
        // 只发生在 `depth < MAX_DEPTH`（见函数尾），出队的 depth 最大恰为 MAX_DEPTH ⇒ 条件
        // 恒假、深度截断**从来没被记过账**，回执与日志照报「结果完整」。真正的截断点在
        // 出队处「还想再深入却没有入队」的那一刻，已挪到函数尾。
        let rd = match std::fs::symlink_metadata(&dir) {
            Ok(m) => {
                if crate::engine::protect::is_reparse(&m) {
                    continue;
                }
                match std::fs::read_dir(&dir) {
                    Ok(rd) => rd,
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        };
        let mut subdirs: Vec<PathBuf> = Vec::new();
        for ent in rd.flatten() {
            if items.len() >= max_files {
                truncated = true;
                break;
            }
            let full = ent.path();
            if !deletable_name(&full) {
                unhandled += 1;
                continue;
            }
            let name = ent.file_name().to_string_lossy().to_string();
            let md = match ent.metadata() {
                // P1-③：Windows 上 `DirEntry::metadata()` 取的是枚举时 `FindNextFileW`
                // 填好的那份 `WIN32_FIND_DATAW`（内存拷贝、不跟随链接、不是 syscall）；
                // 旧注释写的「Windows 上跟随」不成立（native-scanner 2026-10-12 探针实测
                // 报的是链接本相属性位），所以 reparse 复核不必再另付一次 syscall。
                Ok(m) => m,
                Err(_) => continue,
            };
            // 审查 L12：判 reparse 属性位而非 is_symlink —— 云占位符/NFS/LX 这类
            // is_symlink=false 的 reparse 否则会被当成普通目录深入。判据仍用主侧唯一真源
            // `engine::protect::is_reparse`（属性位 0x400），只是来源换成上面那份快照：
            // `symlink_metadata(整条路径)` 走 `FindFirstFileW`，读的是同一个结构体的同一个
            // 字段 ⇒ 对未变动的条目逐位同值（native-scanner 的 `util::is_reparse(&ent)` 就是
            // 这个形态，且它已被与 PS 侧逐字节对拍的命中集检验覆盖）。
            // 非 Windows 例外：那里 `DirEntry::metadata()` 会跟随链接，属性位判据判不出，
            // 补一条不跟随的 `file_type()`（Windows 上 is_symlink 为真者必带 0x400，
            // 并集不额外命中任何条目 ⇒ 两平台都不放宽「哪些条目进结果集」）。
            let sym = if crate::engine::protect::is_reparse(&md) {
                true
            } else {
                ent.file_type().map(|t| t.is_symlink()).unwrap_or(true)
            };
            if sym {
                continue;
            }
            if md.is_dir() {
                let lname = name.to_lowercase();
                // depth<2 不深入 recv*/msg*（FC-2）
                let is_msgish =
                    lname.starts_with("recv") || lname == "msg" || lname.starts_with("msg");
                if depth < 2 && is_msgish {
                    continue;
                }
                subdirs.push(full);
            } else if md.is_file() {
                // 配置根的根层文件不收（账号数据库就在这一层）；内容根的根层文件照收
                if depth == 0 && !collect_root_files {
                    continue;
                }
                scanned += 1;
                let cat = match classify(&ext_of(&name)) {
                    Some(c) => c,
                    None => continue,
                };
                let size = md.len();
                let mtime = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let path_str = full.to_string_lossy().replace('/', "\\");
                items.push(json!({
                    "path": path_str,
                    "name": name,
                    "size": size,
                    "mtime": mtime.to_string(),
                    "ext": ext_of(&name),
                    "category": cat,
                }));
            }
        }
        if depth < max_depth {
            for d in subdirs {
                queue.push_back((d, depth + 1));
            }
        } else if !subdirs.is_empty() {
            // v7.2 `R1d-M02`：深度闸真正生效的地方——本层还有一堆子目录，但已达 MAX_DEPTH、
            // 不再入队。必须记入 truncated，否则「扫到 30 项就停」与「扫全了」在回执上同形。
            truncated = true;
        }
    }
    (items, scanned, unhandled, truncated)
}

/// fileclean:scan
#[tauri::command]
pub async fn fileclean_scan<R: Runtime>(
    window: WebviewWindow<R>,
    scan_type: Option<String>,
    custom_path: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "data": [], "message": msg });
    }
    // v6-P2（R5/A5 panic 族）：`Some("qq") | Some("wechat") => scan_type.unwrap()`
    // 的 unwrap 是「匹配臂保证 Some」的约定式不变量；改成绑定臂内值，unwrap 从
    // 生产面消失（语义不变）。
    let ty = match scan_type.as_deref() {
        Some(t @ ("qq" | "wechat")) => t.to_string(),
        _ => return json!({ "success": false, "data": [], "message": "未知类型" }),
    };
    // A1-M12：先记录路径配置读取健康度（Corrupt 与 Absent 分开），
    // 再进入 configured_dir（那里仍按 fail-closed 决定默认目录）。
    let degraded = matches!(
        crate::security::read_json_state(&crate::engine::paths::paths_config_file()),
        crate::security::JsonState::Corrupt
    );

    let scan_path = match configured_dir(&ty, &custom_path) {
        Ok(path) => path,
        Err(message) => {
            return json!({
                "success": false,
                "data": [],
                "message": message
            });
        }
    };

    // 存在 + 普通目录 + 非链接
    let md = match std::fs::symlink_metadata(&scan_path) {
        Ok(m) => m,
        Err(_) => {
            return json!({
                "success": false, "data": [],
                "message": "路径不存在，请在设置中配置文件目录"
            });
        }
    };
    if !md.is_dir() || crate::engine::protect::is_reparse(&md) {
        return json!({ "success": false, "data": [], "message": "扫描路径必须是普通目录" });
    }
    // v7.2 `R1d-L05`：长度闸量在**规范化之前**的那个串上，并按字符数计。
    // 旧写法 `resolved.len() > MAX_PATH_LEN` 有两个偏差：① `len()` 数 UTF-8 字节，
    // 中文目录名一个字占 3 字节，用户数不出「超长」却被告知路径过长；② canonicalize
    // 补上的 `\\?\` 前缀是内部形态，白占 4 个字符预算（同一目录加不加前缀结论不同）。
    if exceeds_char_len(&scan_path.to_string_lossy(), MAX_PATH_LEN) {
        return json!({ "success": false, "data": [], "message": "扫描路径过长" });
    }
    let resolved = scan_path
        .canonicalize()
        .unwrap_or_else(|_| scan_path.clone())
        .to_string_lossy()
        .replace('/', "\\");

    let label = window.label().to_string();
    let ty2 = ty.clone();
    let root2 = resolved.clone();
    let heavy = is_large_qq_dir(&resolved);
    let rels = content_rels(&ty);
    // 内容根必须从**规范化之后**的根展开（`resolved`）：扫描结果要落在同一个根前缀下，
    // 删除时的 `in_scope` 才认得出这些路径（8.3 短名/大小写/verbatim 前缀都会让裸配置串
    // 与规范化串对不上 ⇒ 整批拒绝删除）。
    let result = tauri::async_runtime::spawn_blocking(move || {
        let root = Path::new(&root2);
        let lanes = expand_content_roots(root, rels);
        if lanes.is_empty() {
            // 旧版布局 / 完全自定义的目录：一路内容根都展开不出来时退回整根扫描。
            // 这条兜底保住的是「换布局之前的目录仍能扫出文件」，不能让收窄变成静默 0 项。
            (scan_root(root), 0usize)
        } else {
            let n = lanes.len();
            (scan_lanes(&lanes), n)
        }
    })
    .await;
    let ((items, scanned, unhandled, truncated), lane_count) = match result {
        Ok(v) => v,
        Err(e) => {
            log::write_log("error", &format!("文件清理扫描任务异常: {e}"));
            return json!({ "success": false, "data": [], "message": e.to_string() });
        }
    };

    let total_size: u64 = items
        .iter()
        .map(|f| f.get("size").and_then(|v| v.as_u64()).unwrap_or(0))
        .sum();

    // 分槽：root + 文件路径集合
    let files: HashSet<String> = items
        .iter()
        .filter_map(|f| f.get("path").and_then(|v| v.as_str()).map(path_key))
        .collect();
    scope_store(&label, &ty2, path_key(&resolved), files);

    log::write_log(
        "info",
        &format!(
            "文件清理扫描完成: {} -> {} 项，{} 字节，枚举 {} 个文件{}{}（{}）",
            ty2,
            items.len(),
            total_size,
            scanned,
            if unhandled > 0 {
                format!("，{unhandled} 项文件名无法无损处理已跳过")
            } else {
                String::new()
            },
            if heavy { "（大目录）" } else { "" },
            if lane_count > 0 {
                format!("{lane_count} 个内容根")
            } else {
                "整根兜底".to_string()
            },
        ),
    );
    if truncated {
        log::write_log(
            "warn",
            &format!("文件清理扫描达上限（每根 {MAX_FILES} 项 / 深度 {MAX_DEPTH}），结果可能不完整: {ty2}"),
        );
    }
    let _ = window.emit(
        "cleanup:scan-progress",
        // v4 P2-E（R1-M05）：total 旧为 items.len() 自指（进度条恒 100%）——那次改成
        // 恒 `MAX_FILES`，于是「正常扫完 30 项」也报 `done=30/total=2000`（v7.2 `R1d-M08`）。
        // `scan_root` 没有逐条 sink，本场扫描确实只有这一帧，那就把它如实说清：
        // done==total==条目数、`progressComplete` 标收尾、被截断时 `truncated` 才是
        // 「结果可能不完整」的唯一凭据（不再用 total 冒充「还有多少没扫」）。
        json!({
            "scanType": ty2,
            "done": items.len(),
            "total": items.len(),
            "progressComplete": true,
            "truncated": truncated,
        }),
    );

    let mut resp = scan_response(items, total_size, resolved, unhandled, truncated);
    if let Some(o) = resp.as_object_mut() {
        o.insert("degraded".into(), json!(degraded));
    }
    resp
}

/// `fileclean:scan` 的成功回执形状。
///
/// `totalSize` 必须是 JSON 数字：渲染层把它直接参与 `+` 求和，字符串会让
/// 累加器退化成拼接（v2 的 22.7 TB / NaN undefined 根因）。抽成纯函数是为了
/// 让这条形状约束能在不触盘的单元测试里直接判红。
fn scan_response(items: Vec<Value>, total_size: u64, resolved: String, unhandled: usize, truncated: bool) -> Value {
    json!({
        "success": true,
        "data": {
            "files": items,
            "totalSize": total_size,
            "scanPath": resolved,
            // 审查 v2-M5：名字无法无损表示的条目**没有**进扫描槽（不可预览也不可删），
            // 数量回给渲染层说清楚，而不是让它们静默消失
            "unhandled": unhandled,
            // v4 P2-E（R1-M05）：达上限/超深度时 true —— 渲染层据此提示「结果可能不完整」
            "truncated": truncated
        }
    })
}

fn in_scope(scope: &Scope, file_path: &str) -> bool {
    let k = path_key(file_path);
    k.starts_with(&scope.root) && scope.files.contains(&k)
}

/// 回收站删除单个文件（供 delete-file / execute 共用），返回 (ok, recycled, message)
fn recycle_one(file_path: &str) -> (bool, bool, String) {
    // 审查 v2-F1：走 `_os` 版。`has_lossy_path` 是第二道闸，这里不重复做名称转换。
    match trim_finder::scan::recycle::send_to_trash_os(std::path::Path::new(file_path).as_os_str())
    {
        Ok(()) => (true, true, String::new()),
        Err(e1) => {
            // 回收站失败**如实报错**，不回退成永久删除（v7.2 `R1d-L02`：旧注释声称回退会
            // 兜底删除，与本函数实际行为相反——失败时它什么都不删）。
            // 口径来自 AGENTS §3：除常规清理项外一律回收站优先、不做永久删除兜底。
            (false, false, e1)
        }
    }
}

/// fileclean:delete-file —— 主窗内嵌 LiteBox 删除当前图片
///
/// 档位 = **`guard::MAIN`**（v7.2 `R1d-L02` 校正此前两处互相矛盾的注释：预览子窗已退役、
/// 删除入口只剩主窗，档位随之收紧；「维持 APP_WINDOWS」那句是自然语言状态腐烂，别再信）。
/// 收紧档位不等于放宽删除面，出口上的闸门一条没少：
/// ① 只能删**发起扫描那次结果内**的路径（`in_scope` + `scope_owner`）；
/// ② `protect::validate_mutation_target` 四道组合闸（受保护面/别名面/系统面/reparse，C01）；
/// ③ 只进回收站（`recycle_one` 失败即报错，无永久删除兜底）；④ 渲染层红色二次确认
/// （`cleanup.js` 的 `modal.confirm({danger:true})`）；⑤ 删除前 `flush_sync()` + 落 delete-manifest。
#[tauri::command]
pub async fn fileclean_delete_file<R: Runtime>(
    window: WebviewWindow<R>,
    file_path: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // v7.2 `R1d-L05`：与扫描根同一口径（字符数），别再用 UTF-8 字节数当长度。
    if file_path.is_empty() || exceeds_char_len(&file_path, MAX_PATH_LEN) {
        return json!({ "success": false, "message": "文件不存在" });
    }
    let ty = ["qq", "wechat"].iter().find_map(|t| {
        scope_get(scope_owner(window.label()), t)
            .filter(|s| in_scope(s, &file_path))
            .map(|_| *t)
    });
    let Some(ty) = ty else {
        return json!({ "success": false, "message": "路径不在扫描范围内，已拒绝删除" });
    };

    // 审查 v2-L2：此前只有 `in_scope`（扫描槽）一道闸，缺 AGENTS §3 要求的
    // `is_path_protected` 纵深。扫描槽是「主窗那次扫到了什么」，受保护目录是「系统/用户
    // 关键目录」——两者判定面不同（用户把扫描根指到受保护目录时，槽里也会装满这些路径），
    // 因此不能互相替代。放在 in_scope 之后、删除之前。
    // C01（v7.2 R1d-K01🔴）：四道组合闸收口到 validate_mutation_target——补上
    // `is_system_namespace`（%WINDIR% 子孙此前会穿过 exact 语义的保护面）与 reparse。
    if let Err(why) = protect::validate_mutation_target(&file_path) {
        log::write_log("warn", &format!("拒绝删除: {why}"));
        return json!({ "success": false, "message": why });
    }

    let is_file = std::fs::metadata(&file_path)
        .map(|m| m.is_file())
        .unwrap_or(false);
    if !is_file {
        return json!({ "success": false, "message": "目标不是普通文件，已拒绝删除" });
    }

    crate::engine::log::flush_sync();
    let size = std::fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);
    let (ok, recycled, msg) = recycle_one(&file_path);
    if ok {
        let batch = delete_manifest::new_batch_id();
        let entry = json!({
            "path": file_path.replace('/', "\\"),
            "kind": "file",
            "size": size,
            "recycled": recycled
        });
        let manifest_path = delete_manifest::save_delete_manifest(&batch, &[entry]);
        // 从槽中移除（槽归发起扫描的窗口所有，见 `scope_owner`：删完必须让
        // in_scope 集合同步收缩，否则同一次扫描里可以再「删」一次不存在的路径）
        let owner = scope_owner(window.label());
        {
            // R1d-M04：同一次加锁内 get_mut 就地改，避免 get→clone→insert 丢并发写入。
            let mut g = FILECLEAN_SCOPES.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(m) = g.as_mut() {
                if let Some(s) = m.get_mut(&slot_key(owner, ty)) {
                    s.files.remove(&path_key(&file_path));
                }
            }
        }
        log::write_log("info", &format!("删除预览图片（回收站）: {file_path}"));
        json!({ "success": true, "recycled": recycled,
            "manifestPath": manifest_path.as_ref().map(|p| p.to_string_lossy().to_string()) })
    } else {
        json!({ "success": false, "message": msg })
    }
}

/// fileclean:execute —— 批量删除选中文件（全部必须在本槽扫描范围内）
#[tauri::command]
pub async fn fileclean_execute<R: Runtime>(
    window: WebviewWindow<R>,
    files: Option<Vec<Value>>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let files = files.unwrap_or_default();
    if files.is_empty() {
        return json!({ "success": false, "message": "没有选中文件" });
    }
    // v7.2 `R1d-L04` 的闸保留，但上限口径随扫描侧改：扫描按内容根分路后单条目可产出数千条
    // （本机实测 QQ 2910 / 微信 2259），而渲染层一次执行只发该条目的整份清单 ⇒ 固定 2000 会把
    // 「完整扫描」变成「整批拒绝」。上限改成 max(固定闸, 槽大小)：槽本身已被扫描侧按每个内容根
    // `MAX_FILES` 封顶，仍是一道显式闸（送超过槽大小的批量一律整批拒）。
    // 判红方向保持**整批拒**而不是截断：静默少删与 M05（输入被静默丢弃）同罪。
    // 检查必须在取到槽之后（槽大小是上限的一半）。

    // 确定槽：用第一项反查（一次 execute 只扫一个 type 的结果）
    let first_path = files
        .first()
        .and_then(|f| f.get("path").and_then(|v| v.as_str()))
        .unwrap_or("");
    let ty = ["qq", "wechat"].iter().find_map(|t| {
        scope_get(window.label(), t)
            .filter(|s| in_scope(s, first_path))
            .map(|_| *t)
    });
    let Some(ty) = ty else {
        return json!({ "success": false, "message": "至少一个文件不在扫描范围内，已拒绝整批" });
    };
    let Some(scope) = scope_get(window.label(), ty) else {
        // 反查（上面 `find_map` 那轮）命中与这里取槽之间无 await，但 FILECLEAN_SCOPES 是全局槽，可能被并发
        // 重扫清空。旧实现直接 unwrap：理论 panic 会被 Tauri command 包装兜住，但与其
        // 让渲染层吃一个未分类错误，不如显式报「会话已过期」（审查 L1）。
        return json!({ "success": false, "message": "扫描会话已过期，请重新扫描后再删除" });
    };

    let batch_max = FILECLEAN_DELETE_MAX.max(scope.files.len()).min(MAX_FILES_TOTAL);
    if files.len() > batch_max {
        log::write_log(
            "warn",
            &format!("文件清理单批 {} 项超上限（{batch_max}），已整批拒绝", files.len()),
        );
        return json!({
            "success": false,
            "message": format!("单批最多删除 {batch_max} 项，请减少选择后分批执行")
        });
    }

    // 全部命中本槽才放行
    for f in &files {
        let p = f.get("path").and_then(|v| v.as_str()).unwrap_or("");
        if !in_scope(&scope, p) {
            return json!({ "success": false, "message": "包含不在扫描范围内的路径，已拒绝整批" });
        }
        // 审查 v2-L2：与 delete-file 同一口径，批量删除同样要过保护纵深。
        // C01（v7.2 R1d-K01🔴）：四道组合闸（含 %WINDIR% 子孙的系统面与 reparse）。
        if let Err(why) = protect::validate_mutation_target(p) {
            log::write_log("warn", &format!("批量删除拒绝整批: {why}"));
            return json!({ "success": false, "message": format!("包含不可删除的目标，已拒绝整批：{why}") });
        }
        if std::fs::metadata(p).map(|m| !m.is_file()).unwrap_or(true) {
            return json!({ "success": false, "message": "包含非普通文件，已拒绝整批" });
        }
    }

    crate::engine::log::flush_sync();
    let mut freed = 0u64;
    let mut success_n = 0usize;
    let mut failed = 0usize;
    let mut recycled_n = 0usize;
    let mut details: Vec<Value> = Vec::new();
    let mut manifest_entries: Vec<Value> = Vec::new();
    let mut removed_keys: HashSet<String> = HashSet::new();

    for f in &files {
        let p = f
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        let (ok, recycled, message) = recycle_one(&p);
        if ok {
            freed += size;
            success_n += 1;
            if recycled {
                recycled_n += 1;
            }
            manifest_entries.push(json!({
                "path": p.replace('/', "\\"),
                "kind": "file",
                // R1d-M03：清单读侧只认 size；旧实现写 freed ⇒ 该批每条体积恒 0。
                "size": size,
                "recycled": recycled
            }));
            removed_keys.insert(path_key(&p));
        } else {
            failed += 1;
        }
        details.push(json!({
            "path": p,
            "status": if ok { "ok" } else { "error" },
            "freed": if ok { size } else { 0 },
            "message": if ok { Value::Null } else { json!(message) }
        }));
    }

    // R2a-M03：文件清理链的**回收站失败**项记进命令体侧的删除失败回执台账 ——
    // 「登记重启后删除」的第一道约束（只收删除失败项）从此有命令体判据，不再只由
    // 渲染层（cleanup.js 的 collectFailedPaths）维持。与常规清理链同域（DOMAIN_CLEANUP）：
    // 两者是 cleanup.js 那条链的两段，回执并进同一槽。
    crate::engine::delete_failed::record(
        window.label(),
        crate::engine::delete_failed::DOMAIN_CLEANUP,
        details
            .iter()
            .filter(|d| d.get("status").and_then(|v| v.as_str()) != Some("ok"))
            .filter_map(|d| d.get("path").and_then(|v| v.as_str()).map(str::to_string))
            .collect(),
        // B2-8：本链走回收站 ⇒ 失败项可以在「重启后删除」里重试（那一步也是永久删，
        // 但用户已经在回收站界面上确认过一次，语义是「已同意删掉这个文件」）
        true,
    );

    if !manifest_entries.is_empty() {
        let batch = delete_manifest::new_batch_id();
        delete_manifest::save_delete_manifest(&batch, &manifest_entries);
    }
    // 更新槽
    if !removed_keys.is_empty() {
        let mut g = FILECLEAN_SCOPES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = g.as_mut() {
            if let Some(s) = m.get_mut(&slot_key(window.label(), ty)) {
                for k in &removed_keys {
                    s.files.remove(k);
                }
            }
        }
    }

    log::write_log(
        "info",
        &format!(
            "文件清理完成: 成功 {}（回收站 {}）失败 {} 释放 {}",
            success_n, recycled_n, failed, freed
        ),
    );

    json!({
        "success": true,
        "data": {
            "totalFreed": freed,
            "success": success_n,
            "failed": failed,
            "recycled": recycled_n,
            "details": details
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_extensions() {
        assert_eq!(classify("jpg"), Some("image"));
        assert_eq!(classify("JPG"), None); // ext_of 已小写化，入参应为小写
        assert_eq!(classify("mp4"), Some("video"));
        assert_eq!(classify("tmp"), Some("cache"));
        assert_eq!(classify("dat"), Some("data"));
        // FC-3：数据库/密钥类绝不归入 data
        assert_eq!(classify("db"), None);
        assert_eq!(classify("adb"), None);
        assert_eq!(classify("aes"), None);
        assert_eq!(classify("exe"), None);
    }

    #[test]
    fn ext_lowercased() {
        assert_eq!(ext_of("PHOTO.JPG"), "jpg");
        assert_eq!(ext_of("noext"), "");
    }

    /// R1d-U04：默认 QQ 目录是 `Tencent Files`（大写 T），旧的大小写敏感子串匹配恒 false；
    /// 同时子串匹配会把 `notencent` 之类同名片段误判成大目录。按目录段比较后两条都钉住。
    #[test]
    fn large_dir_matches_by_component_case_insensitively() {
        assert!(is_large_qq_dir(r"C:\Users\x\Documents\Tencent Files"));
        assert!(is_large_qq_dir(r"C:\Users\x\Documents\xwechat_files\wxid_1"));
        assert!(is_large_qq_dir(r"D:\Tencent\QQ\Users"));
        assert!(!is_large_qq_dir(r"C:\Users\x\notencent\data"));
        assert!(!is_large_qq_dir(r"C:\Users\x\Documents\Tencent Files Backup2"));
    }

    #[test]
    fn path_key_normalizes_sep_case_trailing() {
        assert_eq!(path_key("C:/A/B/"), "c:\\a\\b");
        assert_eq!(path_key("c:\\a\\b"), "c:\\a\\b");
    }

    /// v2 审计的独立隐患 D：canonicalize 产的 `\\?\` 前缀与用户保存的普通路径
    /// 必须在比较口径上等价；剥前缀只影响比较，不影响实际扫描仍是 verbatim。
    #[test]
    fn path_key_strips_verbatim_prefix() {
        assert_eq!(path_key(r"\\?\C:\A\B"), path_key(r"C:\A\B"));
        assert_eq!(path_key(r"\\?\C:\A\B\"), path_key(r"C:\A\B"));
        assert_eq!(
            path_key(r"\\?\UNC\server\share\A\B"),
            path_key(r"\\server\share\A\B")
        );
        assert_ne!(path_key(r"C:\A\B"), path_key(r"C:\A\C"));
    }

    /// v2 用户裁决 1：customPath 只能确认已保存值，不能覆盖它。
    /// 正向：普通/verbatim 两种拼法都能确认；反向：另一目录、缺配置都必须拒。
    #[test]
    fn custom_path_must_equal_saved_value() {
        let saved = Some(r"C:\Users\me\Documents\Tencent Files".to_string());
        let ok = Some(r"C:\Users\me\Documents\Tencent Files".to_string());
        assert!(resolve_dir("qq", &ok, saved.clone()).is_ok());

        let verbatim = Some(r"\\?\C:\Users\me\Documents\Tencent Files".to_string());
        assert!(
            resolve_dir("qq", &verbatim, saved.clone()).is_ok(),
            "verbatim 拼写应视为同一个已保存目录"
        );

        let other = Some(r"C:\Windows".to_string());
        assert!(
            resolve_dir("qq", &other, saved.clone()).is_err(),
            "非已保存目录必须拒绝"
        );
        assert!(
            resolve_dir("qq", &ok, None).is_err(),
            "没有已保存值时必须拒绝 customPath"
        );

        // 不传 customPath 时仍走已保存值 / 默认目录；空串等同不传。
        let empty = Some(String::new());
        assert!(resolve_dir("qq", &empty, saved.clone()).is_ok());
        assert_eq!(
            resolve_dir("qq", &empty, saved).unwrap(),
            PathBuf::from(r"C:\Users\me\Documents\Tencent Files")
        );
    }

    /// 回归根因：`totalSize` 必须是 JSON 数字，字符串会让前端 `+` 退化成拼接。
    /// v4 P2-E（R1-M05）：`truncated` 也必须显式回给渲染层（截断留痕），这里顺带钉住字段存在。
    #[test]
    fn scan_response_serializes_total_size_as_number() {
        let res = scan_response(
            vec![json!({ "path": r"C:\probe\imgs\a.jpg", "size": 4096 })],
            4096,
            r"\\?\C:\probe".to_string(),
            0,
            false,
        );
        assert_eq!(res["data"]["totalSize"], json!(4096));
        assert!(
            res["data"]["totalSize"].is_u64(),
            "totalSize 必须是 JSON number，不能是 \"4096\""
        );
        assert_eq!(res["data"]["truncated"], json!(false), "truncated 必须显式存在: {res}");
    }

    /// 审查 v2-M5：只有能无损往返于 `String` 的名字才允许进扫描槽（进槽=可预览、可删）。
    /// 合法的多字节 Unicode 名字（中文/emoji）必须照常放行 —— 判错方向就等于把功能关掉。
    #[test]
    fn only_lossless_names_are_admissible() {
        assert!(deletable_name(Path::new(
            r"C:\Users\me\Documents\微信聊天记录 1.jpg"
        )));
        assert!(
            deletable_name(Path::new("")),
            "空串本身是合法文本，不该被误判成 lossy"
        );
        #[cfg(windows)]
        {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;
            // 孤立代理项：字节级拷来的 GBK 名字在 NTFS 上的真实形态
            let broken =
                OsString::from_wide(&[0x43, 0x3A, 0x5C, 0xD800, 0x61, 0x2E, 0x6A, 0x70, 0x67]);
            assert!(
                !deletable_name(Path::new(&broken)),
                "含孤立代理项的名字不得进槽"
            );
            // 配对代理项（合法 emoji）不是问题
            let fine =
                OsString::from_wide(&[0x43, 0x3A, 0x5C, 0xD83C, 0xDFAF, 0x2E, 0x6A, 0x70, 0x67]);
            assert!(deletable_name(Path::new(&fine)));
        }
    }

    /// 槽归属是恒等映射（预览子窗退役后无跨窗读槽场景），但「未登记的 label 拿不到
    /// 主窗集合」这条底线要钉住：范围外路径不得因映射缺失而误放行。
    #[test]
    fn unknown_label_gets_no_slot() {
        // 唯一 label：槽是全局表，固定 "main" 会与别的用例（含本文件新加的那条）互相顶
        let label = &format!("unknown-label-{}", std::process::id());
        let root = path_key(r"C:\FakeQqRoot");
        let file = path_key(r"C:\FakeQqRoot\photo.jpg");
        scope_store(label, "qq", root, [file].into_iter().collect());

        assert_eq!(scope_owner(label.as_str()), label.as_str());
        let shared = scope_get(scope_owner(label), "qq").expect("主窗应读到自己的槽");
        assert!(
            in_scope(&shared, r"C:\FakeQqRoot\photo.jpg"),
            "大小写/分隔符归一后仍须在范围内"
        );
        assert!(
            !in_scope(&shared, r"C:\Windows\x.jpg"),
            "范围外路径不得放行"
        );

        let attacker = format!("attacker-{}", std::process::id());
        assert_eq!(scope_owner(attacker.as_str()), attacker.as_str());
        assert!(scope_get(scope_owner(attacker.as_str()), "qq").is_none());
    }

    /// v7.2 `R1d-M02`：深度截断必须记入 `truncated`。
    /// 旧实现把账记在「出队 depth 大于 MAX_DEPTH」上，而入队只发生在 `depth < MAX_DEPTH`
    /// ⇒ 出队 depth 最大恰为 MAX_DEPTH、条件恒假 ⇒ 超深的子树整片消失却回 `truncated:false`。
    /// 正向样本（深到 MAX_DEPTH+1 层）判 true、反向对照（浅沙箱）判 false：
    /// 两条一起才证明这个位是**扫出来的**，不是碰巧没置上。
    #[test]
    fn 深度截断必须记入truncated() {
        let base = std::env::temp_dir().join(format!(
            "trim-fileclean-depth-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);

        // 正向：root\l1\l2\l3\l4\l5，每层一个 .jpg
        let deep = base.join("deep");
        let mut cur = deep.clone();
        for i in 1..=(MAX_DEPTH + 1) {
            cur = cur.join(format!("l{i}"));
            std::fs::create_dir_all(&cur).expect("建深层目录");
            std::fs::write(cur.join("a.jpg"), b"x").expect("写样本");
        }
        let (items, _scanned, _unhandled, truncated) = scan_root(&deep);
        assert!(truncated, "MAX_DEPTH 之外的子树被丢弃时必须记入 truncated");
        // 命中集口径不变：depth 1..=MAX_DEPTH 各一个文件（depth 0 是根、不收）
        assert_eq!(
            items.len(),
            MAX_DEPTH,
            "命中集只应是 depth 1..={MAX_DEPTH} 的 {MAX_DEPTH} 个文件（多收/少收都算命中集变了）"
        );

        // 反向对照：浅沙箱（depth 2、无更深层）必须 truncated=false
        let shallow = base.join("shallow");
        std::fs::create_dir_all(shallow.join("l1/l2")).expect("建浅层目录");
        std::fs::write(shallow.join("l1/a.jpg"), b"x").expect("写样本");
        std::fs::write(shallow.join("l1/l2/a.jpg"), b"x").expect("写样本");
        let (s_items, _s_scanned, _s_unhandled, s_truncated) = scan_root(&shallow);
        assert_eq!(s_items.len(), 2, "浅沙箱两个 depth>0 文件都应入表");
        assert!(
            !s_truncated,
            "没触到深度/条目上限的沙箱必须回 false（否则这条断言恒真、不算验收）"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// 内容根展开：账号目录与全局数据目录各成一路，账号库（`nt_db`）不得被当成内容根；
    /// 配置根直接指向账号目录时也要能展开出 `\nt_qq\nt_data`。
    #[test]
    fn 内容根按账号与全局展开且不碰账号库() {
        let root = std::env::temp_dir().join(format!("trim-fc-lanes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let acc = root.join("1607").join("nt_qq").join("nt_data");
        let glob = root.join("nt_qq").join("global").join("nt_data");
        std::fs::create_dir_all(&acc).expect("建账号数据根");
        std::fs::create_dir_all(&glob).expect("建全局数据根");
        std::fs::create_dir_all(root.join("nt_qq").join("nt_db")).expect("建账号库");

        let lanes = expand_content_roots(&root, QQ_CONTENT_RELS);
        let got: Vec<String> = lanes.iter().map(|p| p.to_string_lossy().to_string()).collect();
        assert_eq!(lanes.len(), 2, "账号与全局各一路、nt_db 不得入选: {got:?}");
        assert!(got.iter().any(|p| p.ends_with(r"1607\nt_qq\nt_data")), "{got:?}");
        assert!(got.iter().any(|p| p.ends_with(r"nt_qq\global\nt_data")), "{got:?}");
        assert!(!got.iter().any(|p| p.contains("nt_db")), "{got:?}");

        let lanes2 = expand_content_roots(&root.join("1607"), QQ_CONTENT_RELS);
        assert_eq!(lanes2.len(), 1, "配置根=账号目录时应展开出它自己的数据根: {lanes2:?}");
        let _ = std::fs::remove_dir_all(&root);

        // 嵌套内容根只留外层：否则同一批文件会被两路各收一次（项数/体积翻倍）
        let wroot = std::env::temp_dir().join(format!("trim-fc-wc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&wroot);
        std::fs::create_dir_all(wroot.join("all_users").join("cache")).expect("建嵌套内容根");
        let wl = expand_content_roots(&wroot, WECHAT_CONTENT_RELS);
        assert_eq!(wl.len(), 1, "all_users 覆盖 all_users\\cache，只应留外层: {wl:?}");
        assert!(wl[0].ends_with("all_users"), "{wl:?}");
        let _ = std::fs::remove_dir_all(&wroot);
    }

    /// NT 布局的形状：内容在配置根下 4-6 层、数据根下 3-4 层。
    /// 旧口径（整根 + 4 层）在这里命中 0 项并把「根本没扫到」报成 truncated；
    /// 新口径按内容根展开后全收且不截断。两条一起才证明修复不是「调大深度消提示」。
    #[test]
    fn nt布局深内容_旧口径零命中_新口径全收() {
        let root = std::env::temp_dir().join(format!("trim-fc-nt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let acc = root.join("1607").join("nt_qq").join("nt_data");
        let glob = root.join("nt_qq").join("global").join("nt_data");
        std::fs::create_dir_all(acc.join("Emoji").join("p1").join("res").join("images").join("sub"))
            .expect("建账号深目录");
        std::fs::create_dir_all(glob.join("PokeFace").join("2011").join("res").join("view").join("sub"))
            .expect("建全局深目录");
        std::fs::write(acc.join("Emoji").join("p1").join("res").join("images").join("sub").join("a.png"), b"x")
            .expect("写样本");
        std::fs::write(glob.join("PokeFace").join("2011").join("res").join("view").join("sub").join("b.png"), b"x")
            .expect("写样本");
        // 账号库旁的文件：内容根口径不得把它带进来（旧口径的整根递归从这里穿过去）
        let db = root.join("1607").join("nt_qq").join("nt_db");
        std::fs::create_dir_all(&db).expect("建账号库");
        std::fs::write(db.join("keep.dat"), b"x").expect("写样本");

        let (old, _s, _u, old_trunc) = scan_dir(&root, false, 4, MAX_FILES);
        assert!(
            old.iter().all(|v| v["name"] != "a.png" && v["name"] != "b.png"),
            "旧口径（整根 + 4 层）应命不中 NT 布局的内容: {old:?}"
        );
        assert!(old_trunc, "旧口径把「没扫到」报成 truncated——提示的直接成因");

        let lanes = expand_content_roots(&root, QQ_CONTENT_RELS);
        let (new, _s, _u, trunc) = scan_lanes(&lanes);
        let mut names: Vec<&str> = new
            .iter()
            .map(|v| v["name"].as_str().unwrap_or(""))
            .collect();
        names.sort();
        assert_eq!(names, vec!["a.png", "b.png"], "新口径必须收全两处内容: {names:?}");
        assert!(!trunc, "内容根下 4 层远不到 {MAX_DEPTH}，不得再报截断");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 一路内容根都展开不出来（旧版扁平布局 / 用户自定义目录）⇒ 退回整根扫描，不得静默 0 项。
    #[test]
    fn 无内容根时退回整根扫描() {
        let root = std::env::temp_dir().join(format!("trim-fc-flat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("123").join("Image")).expect("建扁平布局");
        std::fs::write(root.join("123").join("Image").join("a.jpg"), b"x").expect("写样本");

        assert!(
            expand_content_roots(&root, QQ_CONTENT_RELS).is_empty(),
            "扁平布局不得凭空长出内容根"
        );
        let (items, _s, _u, tr) = scan_root(&root);
        assert_eq!(items.len(), 1, "兜底整根扫描必须仍能收到旧布局文件: {items:?}");
        assert!(!tr);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 超限样本 ⇒ truncated；不超限 ⇒ false。用的是生产常量本身（写满 `MAX_FILES` + 1 个文件），
    /// 不是把预算改小后自证。
    #[test]
    fn 超限样本触发truncated_不超限不触发() {
        let base = std::env::temp_dir().join(format!("trim-fc-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let big = base.join("big");
        std::fs::create_dir_all(&big).expect("建超限根");
        for i in 0..=MAX_FILES {
            std::fs::write(big.join(format!("{i}.log")), b"x").expect("写超限样本");
        }
        let (items, _s, _u, tr) = scan_lanes(std::slice::from_ref(&big));
        assert_eq!(items.len(), MAX_FILES, "输出必须封在 {MAX_FILES}");
        assert!(tr, "超限必须报 truncated（提示的唯一凭据）");

        let small = base.join("small");
        std::fs::create_dir_all(&small).expect("建小根");
        for i in 0..10 {
            std::fs::write(small.join(format!("{i}.log")), b"x").expect("写小样本");
        }
        let (items2, _s, _u, tr2) = scan_lanes(std::slice::from_ref(&small));
        assert_eq!(items2.len(), 10);
        assert!(!tr2, "没触顶的根必须回 false（否则提示恒亮）");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 真机探针（只读）：用本机真实 QQ/微信目录跑「旧口径 vs 内容根口径」，点名两端项数。
    /// 没有目录就 SKIP —— 用例本身不依赖本机样本，但「内容根够不够深、还会不会截断」
    /// 只能拿真实布局验，沙箱里造不出 NT / 微信 4.0 的完整形状。
    #[test]
    #[ignore = "真机：读取本机 Documents 下的 QQ/微信目录（只读），复核内容根口径的命中数与截断位"]
    fn 真机_qq微信内容根口径命中数与截断() {
        let home = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_default();
        let cases = [
            ("qq", home.join("Documents").join("Tencent Files"), QQ_CONTENT_RELS),
            ("wechat", home.join("Documents").join("xwechat_files"), WECHAT_CONTENT_RELS),
        ];
        for (ty, root, rels) in cases {
            if !root.is_dir() {
                println!("SKIP：本机没有 {ty} 目录 {}", root.display());
                continue;
            }
            let (old, _s, _u, old_tr) = scan_dir(&root, false, 4, MAX_FILES);
            let lanes = expand_content_roots(&root, rels);
            let (new, _s, _u, new_tr) = scan_lanes(&lanes);
            println!(
                "{ty}: 内容根 {} 路；旧口径 {} 项/truncated={old_tr}；新口径 {} 项/truncated={new_tr}",
                lanes.len(),
                old.len(),
                new.len()
            );
            assert!(!lanes.is_empty(), "{ty}：真实目录必须能展开出内容根");
            assert!(
                new.len() >= old.len(),
                "{ty}：新口径不得比旧口径少收（新 {}/旧 {}）",
                new.len(),
                old.len()
            );
        }
    }

    /// v7.2 `R1d-L06`：本域槽键的唯一真源是 `snapshot::domain_key`。
    /// 判据取源码形态（`concat!` 拆词防自指）+ 功能面「同窗不同类型不塌并」。
    /// 为什么两条都要：只断源码形态防不住换成另一串拼接；只断功能防不住分隔符漂移。
    /// （N8 机检看不见自建表，所以这条契约测试就是本域键构造的唯一防线。）
    #[test]
    fn 槽键走domain_key且同窗两类型不塌并() {
        let src = include_str!("fileclean.rs");
        let want = concat!("snapshot::", "domain_key(label, ty)");
        assert!(
            src.contains(want),
            "slot_key 必须走 snapshot::domain_key（域内四张槽表统一口径）"
        );
        let old = concat!("format!(\"{label}", ":{ty}\")");
        assert!(!src.contains(old), "槽键拼接不得退回本域私有分隔符（两套口径必然漂移）");

        // 用例之间共用同一张全局槽表 ⇒ label 必须每条用例唯一（同测试底座的快照纪律）
        let main = format!("slot-main-{}", std::process::id());
        let root_qq = path_key(r"C:\FakeQqRoot");
        let root_wc = path_key(r"C:\FakeWechatRoot");
        scope_store(&main, "qq", root_qq.clone(), [path_key(r"C:\FakeQqRoot\a.jpg")].into_iter().collect());
        scope_store(&main, "wechat", root_wc, [path_key(r"C:\FakeWechatRoot\b.dat")].into_iter().collect());
        let qq = scope_get(&main, "qq").expect("qq 槽必须在");
        assert!(
            in_scope(&qq, r"C:\FakeQqRoot\a.jpg") && !in_scope(&qq, r"C:\FakeWechatRoot\b.dat"),
            "同窗两类型的槽必须各自独立（塌并即后写顶掉前写）"
        );
        assert_eq!(qq.root, root_qq, "qq 槽的 root 不得被 wechat 槽顶掉");
    }

    /// P2-1（v4-R1-M01）：`fileclean_execute` 回执的 totalFreed 必须是 **JSON 数字** ——
    /// 渲染层 cleanup.js 直接 `fcFreed += resp.data.totalFreed`，字符串会变成拼接
    /// （`0 + "1048576"`），界面上「释放空间」必现错乱（同片区的 totalSize 早是数字）。
    /// 真跑要触盘，这里用源码形态钉住产出类型。
    /// 字面量用 concat! 拆词：`include_str!` 会把本测试自身也当语料，整串写会自指恒真/恒假。
    #[test]
    fn execute_total_freed_is_json_number() {
        let src = include_str!("fileclean.rs");
        let want = concat!("\"totalFreed\": freed", ",");
        let bad = concat!("\"totalFreed\": freed", ".to_string()");
        assert!(src.contains(want), "totalFreed 必须以 JSON 数字产出（v4-R1-M01 修复锚点）");
        assert!(!src.contains(bad), "totalFreed 退回字符串 ⇒ 渲染层「释放空间」数字拼接回归");
    }

    /// §5.3 第三条（P2-E/P1-③）的**等价性对拍 + 命中集对照**：reparse 复核从「每访问一个
    /// 条目按路径名再 `symlink_metadata` 一次」改成「吃枚举期那份 `ent.metadata()`」，两个前提都要钉：
    ///   ① 同一份 `FILE_ATTRIBUTE_REPARSE_POINT` 属性位 ⇒ 两形态**逐条目同值**（否则命中集会变）；
    ///   ② 命中集不变。**样本形状是选过的**：文件链接放在 `imgs\` 里（depth=1），
    ///      因为根层文件本就 `depth==0 continue` 不收，拦在它前面的是那条而不是条目级复核 ——
    ///      撤掉条目级复核时，只有 depth≥1 的 file 型 reparse（云占位符就是这个形状）会漏进表。
    ///      目录链接（`linked\`）则由出队时的逐目录复核兜住，两条闸各司其职、都在这儿留着。
    /// 符号链接造不出来（无权限/未开开发者模式）时**明说 SKIP**，不许拿「没报错」当对拍过。
    #[test]
    fn 条目reparse复核与按路径stat同值且命中集不变() {
        #[cfg(windows)]
        {
            use std::os::windows::fs::{symlink_dir, symlink_file};
            let root = std::env::temp_dir()
                .join(format!("trim-fileclean-reparse-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("imgs")).expect("建沙箱目录");
            std::fs::write(root.join("imgs/a.jpg"), b"x").expect("写样本");
            // 根层文件按 FC 口径本就不收（depth==0 continue），它只是等价性对拍的一个条目
            std::fs::write(root.join("plain.png"), b"x").expect("写根层样本");

            let mut links_made = 0usize;
            // depth=1 的 file 型 reparse：条目级复核是唯一拦它进表的闸
            if symlink_file(root.join("imgs/a.jpg"), root.join("imgs/link.dat")).is_ok() {
                links_made += 1;
            }
            // depth=0 的 dir 型 reparse：拦在条目级，也拦在出队级（两道闸都要成立）
            if symlink_dir(root.join("imgs"), root.join("linked")).is_ok() {
                links_made += 1;
            }

            // ① 逐条目等价：枚举快照口径 == 按路径名口径（`.ok()` 后比 Option：
            //    io::Error 没有 PartialEq，而「两边都读不到」也是等价的一种，必须同判）
            let mut checked = 0usize;
            for ent in std::fs::read_dir(&root).expect("read_dir 沙箱根").flatten() {
                let p = ent.path();
                let cached = ent.metadata().map(|m| protect::is_reparse(&m)).ok();
                let bypath = std::fs::symlink_metadata(&p).map(|m| protect::is_reparse(&m)).ok();
                assert_eq!(
                    cached, bypath,
                    "reparse 判定必须与按路径名 stat 同值: {}",
                    p.display()
                );
                checked += 1;
            }
            // 条目级对拍也要覆盖 depth=1 那个文件链接本体（它才是本轮换数据源的那个形状）
            for ent in std::fs::read_dir(root.join("imgs")).expect("read_dir imgs").flatten() {
                let p = ent.path();
                assert_eq!(
                    ent.metadata().map(|m| protect::is_reparse(&m)).ok(),
                    std::fs::symlink_metadata(&p).map(|m| protect::is_reparse(&m)).ok(),
                    "depth=1 条目的两口径必须同值: {}",
                    p.display()
                );
                checked += 1;
            }
            // 对拍条数点名到「真的跑过」：根层恒有 `imgs` + `plain.png`，`imgs` 里恒有 `a.jpg`
            // ⇒ 下限 3；每成一个符号链接多一个条目（根层 `linked` / `imgs\link.dat`）。
            // 断成等式而不是 `>=`：任一轮 `read_dir` 空转或提前 break 都要能判红。
            assert_eq!(
                checked,
                3 + links_made,
                "等价性对拍的条目数与沙箱形状不符（少跑一轮即红）: 实跑 {checked}，期望 {}",
                3 + links_made
            );

            // ② 命中集：只收真实目录里的普通文件
            let (items, scanned, unhandled, truncated) = scan_root(&root);
            let mut names: Vec<String> = items
                .iter()
                .map(|v| v["name"].as_str().unwrap_or_default().to_string())
                .collect();
            names.sort();
            assert_eq!(names, vec!["a.jpg".to_string()], "命中集只应是 imgs/a.jpg: {names:?}");
            assert_eq!(scanned, 1, "归类计数只算 depth>0 的真实文件");
            assert_eq!(unhandled, 0, "沙箱名字都可无损表示");
            assert!(!truncated, "五个条目远不到 MAX_FILES");
            if links_made < 2 {
                println!(
                    "SKIP：本机只能构造 {links_made}/2 个符号链接（权限/开发者模式），\
                     「链接不进表、不深入」这一面未校验（等价性对拍已跑 {checked} 条）"
                );
            }
            let _ = std::fs::remove_dir_all(&root);
        }
        #[cfg(not(windows))]
        {
            // 本域的 reparse 判据与符号链接构造都是 Windows 口径，非目标平台如实说没校验
            println!("SKIP：本用例只在 Windows 上有意义（FILE_ATTRIBUTE_REPARSE_POINT + symlink_*）");
        }
    }

    /// §5.3 第三条的**性能面**源码形态判据：真机 syscall 次数在单测里测不出来，
    /// 但「条目循环里再按路径名解析一次」这个形状必须能被判红 —— 它是这次改动的本体。
    /// 锚点按 §5.19 取 `file + 判别性锚点子串`（不写行号），字面量用 `concat!` 拆词防自指
    /// （`include_str!` 会把本测试自己也算成语料）。
    #[test]
    fn 条目循环内不得再按路径名复核reparse() {
        let src = include_str!("fileclean.rs");
        let count = |needle: &str| src.matches(needle).count();
        let bad = concat!("symlink_metadata(&", "full)");
        assert_eq!(
            count(bad),
            0,
            "scan_root 的条目循环又出现逐条按路径名 stat（§5.3 第三条锚点，每访问条目一次 syscall）"
        );
        let good = concat!("let sym = if crate::engine::protect::is_reparse(&", "md)");
        assert_eq!(
            count(good),
            1,
            "reparse 复核必须以枚举期那份 `md` 为源、判据仍走主侧唯一真源 `protect::is_reparse`（命中数≠1 即形状变了）"
        );
    }

    /// §5.3 第三条的真机探针（§1.6②：判据走真实磁盘 ⇒ 不能只靠沙箱里那种「一造就成功」的样本）。
    ///
    /// 覆盖两个沙箱拿不到的形状，各自如实声明覆盖到没有：
    ///   ① junction（`is_symlink()==false` 却带 0x400）：两口径**同值**这条等价前提对它成立。
    ///      注意深不深入这件事在 junction 上由**出队级**复核（`symlink_metadata(&dir)`）兜住，
    ///      条目级复核撤掉也照样拦得住 —— 所以这条只钉等价性，不冒充「命中集对照」。
    ///   ② **file 型 reparse**（OneDrive 云占位符那一类，`mklink` 造不出来、is_symlink 也是 false）：
    ///      这才是条目级复核唯一的靶面。本机存在这样的文件就拿它的父目录当扫描根，
    ///      断言它不进命中集（进了就是把占位符的逻辑大小当普通文件报给用户删）；
    ///      不存在就 SKIP 并明说未校验 —— 沙箱里的 `symlink_file` 是 is_symlink()==true 那一类，
    ///      顶不了这个位置。
    /// 造不出 junction（权限）同样如实 SKIP，不假绿。
    #[test]
    #[ignore = "真机：需要 mklink /J 造 junction 与本机真实云占位符样本（权限/环境相关），复核该判据时手动跑"]
    fn 真机_junction与文件型reparse条目按枚举快照判reparse() {
        let root = std::env::temp_dir().join(format!("trim-fileclean-junction-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("imgs")).expect("建沙箱目录");
        std::fs::write(root.join("imgs/a.jpg"), b"x").expect("写样本");

        let made = |flag: &str, link: &str, target: &str| -> bool {
            std::process::Command::new("cmd")
                .args(["/C", &format!(r#"mklink {flag} "{}" "{}""#, root.join(link).display(), root.join(target).display())])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        let mut expect = 0usize;
        if made("/J", "junc", "imgs") { expect += 1; }
        if made("/J", "self-junc", ".") { expect += 1; }
        if expect > 0 {
            // ① 等价性：对每个条目两口径同值（junction 是 is_symlink()==false 的那一类）
            for ent in std::fs::read_dir(&root).expect("read_dir").flatten() {
                let p = ent.path();
                assert_eq!(
                    ent.metadata().map(|m| protect::is_reparse(&m)).ok(),
                    std::fs::symlink_metadata(&p).map(|m| protect::is_reparse(&m)).ok(),
                    "junction 条目的两口径必须同值: {}",
                    p.display()
                );
                // 留一条自证：属性位判据确实抓到了这个 is_symlink 抓不到的形状
                if p.file_name().map(|n| n == "junc").unwrap_or(false) {
                    let ft = ent.file_type().expect("file_type");
                    assert!(protect::is_reparse(&ent.metadata().expect("metadata")), "junction 必须被属性位判据拦住");
                    assert!(!ft.is_symlink(), "本机 junction 的 is_symlink() 形态与假设不符（std 版本变了就要重审这条判据）");
                }
            }
        } else {
            println!("SKIP：本机 mklink /J 全部失败（权限/策略），junction 等价性一面未校验");
        }

        // ①' 命中集：自引用 junction 让「深度上限」也拦不住重复计数，只剩这两道 reparse 闸
        //（条目级 + 出队级）在拦 —— 两道都撤掉时这里必红；只撤条目级时由出队级兜住，
        // 所以这条**不**充当条目级复核的靶面（靶面见下面的 ②）。
        let (items, scanned, _unhandled, truncated) = scan_root(&root);
        let names: Vec<String> = items
            .iter()
            .map(|v| v["name"].as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(names, vec!["a.jpg".to_string()], "junction 不得把同一文件再贡献一份: {names:?}");
        assert_eq!(scanned, 1, "只应统计真实 imgs 目录里的那一个文件");
        assert!(!truncated, "沙箱远不到 MAX_FILES");
        let _ = std::fs::remove_dir_all(&root);

        // ② 条目级复核唯一的靶面：file 型 reparse（is_symlink()==false 的云占位符那一类）。
        // 样本只能到真实机上找（`mklink` 造不出这个形状）；找不到就如实说未校验。
        fn find_file_reparse(p: &Path, depth: u32) -> Option<std::path::PathBuf> {
            if depth > 3 { return None; }
            for ent in std::fs::read_dir(p).ok()?.flatten() {
                let ep = ent.path();
                let Ok(ft) = ent.file_type() else { continue };
                if ft.is_dir() {
                    if let Some(f) = find_file_reparse(&ep, depth + 1) { return Some(f); }
                } else if !ft.is_symlink() {
                    // 只看属性位（跟随链接的 fs::metadata 会把这个形状读没）
                    let reparse = ent.metadata().map(|m| protect::is_reparse(&m)).unwrap_or(false);
                    if reparse { return Some(ep); }
                }
            }
            None
        }
        let home = std::env::var_os("USERPROFILE").map(PathBuf::from);
        let sample = home.as_deref().and_then(|h| find_file_reparse(h, 0));
        match sample {
            Some(ph) => {
                let parent = ph.parent().expect("样本必有父目录");
                let (items2, _scanned, _unhandled, _truncated) = scan_root(parent);
                let bad = ph.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                assert!(
                    !items2.iter().any(|v| v["name"].as_str() == Some(bad.as_str())),
                    "file 型 reparse（{}）被当普通文件收进命中集 = 报的是逻辑大小而非占盘大小",
                    ph.display()
                );
                println!("现算：已用真实 file 型 reparse 样本判过一次（{}）", ph.display());
            }
            None => println!(
                "SKIP：本机用户目录浅层没有 file 型 reparse 样本（云占位符一类），条目级复核的靶面未校验"
            ),
        }
    }

    /// R1d-M12：多路合并受全局总量闸约束，收满且有余额路时置 truncated。
    #[test]
    fn 扫描总量封顶且收满时置截断() {
        let sb = crate::testutil::Sandbox::new("p2e-m12");
        let mut lanes = Vec::new();
        for i in 0..3 {
            let d = sb.path().join(format!("lane{i}"));
            std::fs::create_dir_all(&d).unwrap();
            for j in 0..51 {
                std::fs::write(d.join(format!("f{j}.log")), b"x").unwrap();
            }
            lanes.push(d);
        }
        let (items, _s, _u, truncated) = scan_lanes_capped(&lanes, 200, 100);
        assert_eq!(items.len(), 100, "全局闸应把三路 153 项截到 100");
        assert!(truncated, "截断必须置位");
        let (exact, _s, _u, t_exact) = scan_lanes_capped(&lanes[..1], 200, 51);
        assert_eq!(exact.len(), 51);
        assert!(!t_exact, "恰好收满且已无余路不算截断");
        let (fit, _s, _u, t_fit) = scan_lanes_capped(&lanes[..1], 200, 100);
        assert_eq!(fit.len(), 51);
        assert!(!t_fit);
    }

}
