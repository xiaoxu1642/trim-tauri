//! 清理规则库：常量与体积闸、内置/本地装载、语义校验（A2）、`cleanup:rules` 出口。
//!
//! 字段表 / 上限 / 允许 token 集 / 版本下限的**单一真源是 `tools/rule-schema.json`**
//! （Rust 侧 include_str! 读同一份字节），本文件只实现判定，不再维护第二份字段名清单。
//! 内置副本 `BUILTIN_RULES_JSON` 走 include_str!，改规则库必须重签后重新生成兜底副本，
//! 否则 check-cleanup-rule-contract / check-data-parity 会红。
//! 校验器 `validate_cleanup_package` 被装载与在线更新两处共用（留一处校验等于留豁免通道）。

use crate::security;
use crate::engine::{guard, log, paths, rule_schema, rules_signature};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::WebviewWindow;
use super::state::*;
// ==================== 常量（对照 main.js 1170-1577 / 71-72 / 1944） ====================

/// 内置规则库（gen 产物，与上游 `src/data/cleanup-rules.json` 逐字节一致；本仓副本已移出 frontendDist（审查 M14），故编译期从 `src-tauri/data/` 取）
pub(super) const BUILTIN_RULES_JSON: &str = include_str!("../../../data/cleanup-rules.json");
/// 内容下限/上限（审查 1-1：先拦超大响应再解析，防 OOM）
pub(super) const RULES_MIN_SIZE: usize = 4096;
pub(super) const RULES_MAX_SIZE: usize = 2 * 1024 * 1024;
/// 单源超时（毫秒）
pub(super) const RULES_DOWNLOAD_TIMEOUT_MS: u64 = 15000;
/// 发布源按序回退：GitHub raw → jsDelivr → gh-proxy
///
/// 审查 v2-C1：这三条原本全指向 `xiaoxu1642/Trim`（Electron 轨）的 `src/data/…`，实测该路径
/// 在 `main`/`HEAD` 两个 ref 上都 **404**（同仓库的 `readme.md` 是 200，所以不是仓库或分支问题，
/// 是这个文件根本没在那边发布）；而规则库的真源现在在本仓库 `src-tauri/data/`，同三条源的
/// 新路径实测 `jsDelivr` 与 `gh-proxy` 均 **200**。指向不存在的源意味着**在线规则更新一直是
/// 全源失败**、只能靠内置副本，而这条回退链看起来"配好了"——正是最容易被忽略的形态。
pub(super) const RULES_UPDATE_URLS: [&str; 3] = [
    "https://raw.githubusercontent.com/xiaoxu1642/trim-tauri/main/src-tauri/data/cleanup-rules.json",
    "https://cdn.jsdelivr.net/gh/xiaoxu1642/trim-tauri@main/src-tauri/data/cleanup-rules.json",
    "https://gh-proxy.com/https://raw.githubusercontent.com/xiaoxu1642/trim-tauri/main/src-tauri/data/cleanup-rules.json",
];

/// 三条发布源对**仓库内路径**的 URL 形态。清理库与残留库共用这一个函数而不是各写一份清单：
/// 镜像的路径结构各不相同（raw 走 `/main/<路径>`、jsDelivr 走 `/gh/<仓库>@main/<路径>`、
/// gh-proxy 是前缀套娃），两份常量抄下来必然漂移（决策清单 D6）。
/// 漂移由测试 `三条源与仓库内路径的拼装必须同源` 钉住。
pub(crate) fn release_source_urls_for(rel_path: &str) -> Vec<String> {
    vec![
        format!("https://raw.githubusercontent.com/xiaoxu1642/trim-tauri/main/{rel_path}"),
        format!("https://cdn.jsdelivr.net/gh/xiaoxu1642/trim-tauri@main/{rel_path}"),
        format!(
            "https://gh-proxy.com/https://raw.githubusercontent.com/xiaoxu1642/trim-tauri/main/{rel_path}"
        ),
    ]
}
/// 可删文件清单防呆上限（D13）
pub(super) const PLAN_CAP_PER_ITEM: usize = 100_000;
pub(super) const PLAN_CAP_TOTAL: usize = 1_000_000;
/// 执行侧清理项条数硬上限（审查 v2-L3）
///
/// 结论先说：执行链**不是无界**的 —— `cleanup_execute` 只认最近一次扫描快照里的项，
/// 而扫描侧已有 `PLAN_CAP_PER_ITEM` / `PLAN_CAP_TOTAL` 防呆；这里再卡一道条数上限，
/// 于是「一次能删多少」的边界是**显式常量**而不是埋在判断里的 500。
/// 未做的事：总字节数上限**没有加**——那会拒绝合法的大清理（几十 GB 缓存一次清完是
/// 正常用法），属产品取舍，需拍板后再动；当前靠 `RULES_MAX_SIZE` 拦的是**规则文件**体积，
/// 与被清理内容的体积不是一回事，别混为一谈。
pub(super) const EXECUTE_MAX_ITEMS: usize = 500;

/// 占用检测防呆上限
pub(super) const PLAN_LOCK_CAP: usize = 20_000;
/// 执行/明细的 PS 超时（对照 main.js 1357 / 1531）
/// 对照 JS `JSON.stringify`（紧凑、非 ASCII 原样输出；键序依赖 serde_json 的 preserve_order）
pub(super) fn json_text(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
}


// ==================== 规则库加载（对照 cleanup-scripts.js 44-195） ====================

/// 规则库根目录（**读**）。收口后新根 = `app_data_dir()\cleanup`
/// （标准模式 `%APPDATA%\com.xiaoxu.trim\cleanup`，便携模式 exe 同级 `data\cleanup`），
/// 老根 `%APPDATA%\Trim\cleanup` 只作只读兜底——2026-09-28 决策清单 D1=A。
///
/// 本函数原注释写的是「与 Electron 逐字一致，便携模式同样落 Roaming」，那是收口前的口径：
/// 它造成便携实例下载的规则带不走、标准与便携两实例互相覆盖 `rules.json` 与水位线、
/// AGENTS §7.3 的清缓存步骤够不着规则文件。老根仍在 `MIGRATION_DIRS` 里做一次性搬迁，
/// 兜底读只服务于「搬迁没跑成」的场景。
pub fn data_rules_dir() -> PathBuf {
    paths::data_subdir_for_read("cleanup")
}

/// **写入**专用规则根：恒新根。双写会让两个根长期分叉（v2-M19 记的同一类病）。
pub(super) fn data_rules_write_dir() -> PathBuf {
    paths::data_subdir_for_write("cleanup")
}

pub(super) fn data_rules_file() -> PathBuf {
    paths::data_file_for_read("cleanup/rules.json")
}

pub(super) fn data_rules_write_file() -> PathBuf {
    data_rules_write_dir().join("rules.json")
}

pub(super) fn custom_rules_dir() -> PathBuf {
    paths::data_subdir_for_read("cleanup/custom")
}

pub(super) fn watermark_file() -> PathBuf {
    paths::data_file_for_read("cleanup/rules-watermark.json")
}

pub(super) fn watermark_write_file() -> PathBuf {
    data_rules_write_dir().join("rules-watermark.json")
}

/// 规则缓存（键 = 数据 mtime|size|custom 数量|各 custom mtime；对照 RULES_CACHE_SIG）
pub(super) static RULES_CACHE: Mutex<Option<(String, Value)>> = Mutex::new(None);

/// `safeReadJson`：只接受「能解析且 `groups` 是数组」的 JSON 对象
pub(super) fn safe_read_json(file: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(file).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    if v.get("groups").map(|g| g.is_array()).unwrap_or(false) {
        Some(v)
    } else {
        None
    }
}

/// 组内条目（`subGroups` 优先，否则 `items`）
pub(super) fn collect_group_items(group: &Value) -> Vec<Value> {
    if let Some(sgs) = group.get("subGroups").and_then(|v| v.as_array()) {
        let mut out = Vec::new();
        for sg in sgs {
            if let Some(items) = sg.get("items").and_then(|v| v.as_array()) {
                out.extend(items.iter().cloned());
            }
        }
        out
    } else {
        group
            .get("items")
            .and_then(|v| v.as_array())
            .map(|a| a.to_vec())
            .unwrap_or_default()
    }
}

/// 进程内防回滚高水位（2026-10-04 审计 §4.7）：磁盘上的水位线文件是「可被删的」
/// ——用户手工清理、第三方「垃圾清理」工具都可能把 data 目录当缓存扫掉。文件一旦
/// 消失，只读文件的地板就回落到 `builtin_version`，任何**合法签名**且
/// rulesVersion >= 内置版本的旧包都会被接受（下方 :954 的比较是 `v < floor`，相等
/// 通过）。把本进程记录过的最高 rulesVersion 存在进程内并折进地板：删文件丢的是
/// 跨进程记忆，丢不掉本进程的记忆。AtomicU64 存 f64 bits（版本恒为正数日期戳）。
pub(super) static WATERMARK_HIGH: AtomicU64 = AtomicU64::new(0);

/// 读进程内高水位（f64 bits 还原）
pub(super) fn watermark_high_get() -> f64 {
    f64::from_bits(WATERMARK_HIGH.load(Ordering::Relaxed))
}

/// 抬进程内高水位：只升不降，非法值（非有限/非正）忽略（CAS 循环防并发丢更新）
pub(super) fn watermark_high_raise(v: f64) {
    if !v.is_finite() || v <= 0.0 {
        return;
    }
    let mut cur = WATERMARK_HIGH.load(Ordering::Relaxed);
    loop {
        if v <= f64::from_bits(cur) {
            return;
        }
        match WATERMARK_HIGH.compare_exchange_weak(cur, v.to_bits(), Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => cur = actual,
        }
    }
}

/// 防回滚水位线读取（对照 getRulesWatermark；损坏/不可读按 0）。
///
/// §4.7：返回值 = max(磁盘水位线, 进程内高水位)。首次调用会把磁盘值抬进进程内
/// 高水位，此后即使磁盘文件被删（本进程运行期间），地板也不会回落。
pub fn rules_watermark() -> f64 {
    let disk = match std::fs::read_to_string(watermark_file()) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => match v.get("rulesVersion").map(js_number) {
                Some(n) if n.is_finite() && n > 0.0 => n,
                _ => 0.0,
            },
            Err(_) => 0.0,
        },
        Err(_) => 0.0,
    };
    watermark_high_raise(disk);
    let high = watermark_high_get();
    if disk > high {
        disk
    } else {
        high
    }
}

/// 防回滚水位线写入（只升不降；写失败不阻断本次更新）。
///
/// §4.7：先抬进程内高水位再写盘 —— 原先写盘失败只 warn，这个版本的防回滚记忆
/// 就**整条丢失**（「更新成功 + 水位线没写上」的组合）；现在本进程至少记得它。
pub fn set_rules_watermark(version: f64) -> bool {
    if !version.is_finite() || version <= 0.0 || version <= rules_watermark() {
        return false;
    }
    watermark_high_raise(version);
    // 水位线只写新根：写老根会让两个根各自记住一个版本，读取侧的口径就分叉了
    let file = watermark_write_file();
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let payload = json!({ "rulesVersion": version, "at": iso_now() });
    match security::atomic_write_json(&file, &payload) {
        Ok(()) => true,
        Err(e) => {
            log::write_log("warn", &format!("写规则版本水位线失败: {e}"));
            false
        }
    }
}


// ==================== A2 清理规则库语义校验（V2 P1-B0，2026-09-30） ====================
//
// 为什么必须存在：本文件此前的装载链只做「验签 → JSON → `groups` 是数组 → 版本下限」，
// 也就是只证明**这份文件出自发布机私钥**，不证明内容合法。而清理条目直接驱动删除面
// （`fileKeys.path` / `regKeys.path` / `pathPs` / `excludePaths`）：一条 `risk:"deluxe"`、
// 一个含 `/` 的路径、或一个执行侧根本不认的字段，都会变成「扫描命中、执行 0 删、状态成功」
// 那类事故（本域真实前科：printSpoolCache 的 `%WINDIR%` 大写形态）。残留库早在 U-1 就补了
// 这一层（uninstall.rs A2 段），清理库一直是缺的 —— 两库共用一条更新链，强度却不对称。
//
// 口径约束（勿单侧改）：
// - 词汇表与上限来自 `engine::rule_schema`（真源 `tools/rule-schema.json`，Node 门禁读同一份字节）；
//   **判定逻辑仍是两份独立实现**（本函数与 `tools/check-cleanup-rule-contract.mjs`），
//   靠 `tools/fixtures/cleanup-contract.json` 钉住 —— 不跨语言调用，也不让 JS 反过来生成 Rust。
// - 失败一律**整包拒绝** + 隔离现场 + 回退内置，不做「坏条目剔除、其余生效」：那会让
//   审核记录与线上行为不一致（残留域 Q2 同口径）。
// - **注册表禁删面套用范围 = 删树形态**（无 `value` 的 `regKeys` 条目）：装载侧与执行侧
//   各查一次 `engine::protect::reg_target_block_reason`，同一函数同一口径（AGENTS §5.16/N6
//   禁的是"另接一套判定"，不是"少接一处"）。清值形态（`value` 具名或 `"*"`）不在该函数
//   的管辖语义内（它自述"必须拒绝递归删除"），故不套 —— 但删树会端掉整棵子树，且备份是
//   事后可失败的，必须拦。审查 v5 C-1：此前注释声称执行侧有闸，实际清理域零调用。

/// 递归收集一个值里所有 `%TOKEN%`（按出现顺序，不去重 ⇒ 报错能指到具体位置）
pub(super) fn collect_rule_tokens(value: &Value) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => {
                let bytes = s.as_bytes();
                let mut i = 0usize;
                while i < bytes.len() {
                    if bytes[i] == b'%' {
                        if let Some(end) = s[i + 1..].find('%') {
                            let tok = &s[i + 1..i + 1 + end];
                            if !tok.is_empty() && !tok.chars().any(|c| c.is_whitespace()) {
                                out.push(tok.to_string());
                            }
                            i = i + 1 + end + 1;
                            continue;
                        }
                    }
                    i += 1;
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, out);
                }
            }
            Value::Object(o) => {
                for v in o.values() {
                    walk(v, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

/// 未知字段检查：手取字段时未知字段会被静默忽略，那等于「规则库里有一执行侧根本不认的
/// 字段」，审核记录与线上行为不一致。返回 `Some(字段名)` = 拒载原因。
pub(super) fn unknown_rule_field(obj: &Map<String, Value>, allow: &[String]) -> Option<String> {
    obj.keys()
        .find(|k| !allow.iter().any(|a| a == k.as_str()))
        .cloned()
}

/// 必填非空字符串字段
pub(super) fn require_rule_str(obj: &Map<String, Value>, field: &str, max_len: usize) -> Option<String> {
    match obj.get(field).and_then(Value::as_str) {
        None => Some(format!("缺必填字段 {field}")),
        Some(s) => {
            if s.trim().is_empty() {
                Some(format!("{field} 为空白"))
            } else if s.chars().count() > max_len {
                Some(format!("{field} 超长（{} > {max_len}）", s.chars().count()))
            } else {
                None
            }
        }
    }
}

/// verbatim / 设备路径前缀闸（2026-10-04 审计 §3.1，§4.11 扩面）。
///
/// 抽成独立函数是因为除 `fileKeys[].path` 外还有两个字段也是**文件路径**：
/// `detect[].path`（安装检测的判据，直接喂 `path_exists`）与 `excludePaths[]`
/// （排除名单，按目录前缀匹配）。三处都必须是同一条判据 —— 各自写一遍的形态就是
/// §3.1 那个「只关一个入口、另一个仍能重开」的老问题。
///
/// 只判前缀，不判 `/`、`?`、长度：那两项各有各的理由（执行侧只按 `\` 切分、
/// glob 只支持单星），由调用方各自补，`excludePaths` 已经有自己的一套。
pub(super) fn path_prefix_problem(path: &str) -> Option<String> {
    let t = path.trim();
    // 设备路径：Win32 跳过路径解析，`\\.\C:\…` 与 `C:\…` 同树但保护判定结论相反
    //（`engine/protect.rs` 同批收紧为 fail-closed 拒绝）。
    if t.starts_with("\\\\.\\") || t.starts_with("\\??\\") {
        return Some(format!("是设备路径（Win32 跳过路径解析，无法判定保护归属）: {path}"));
    }
    // `\\?\` 是**合法**的 Win32 长路径前缀，不是安全问题；但执行侧
    // `expand_glob_dirs` 只按 `\` 切分、不还原长路径，会「扫描命中、执行漏删」。
    if t.starts_with("\\\\?\\") {
        return Some(format!(
            "是 \\\\?\\ 长路径前缀（执行侧 expand_glob_dirs 不还原长路径，会扫描命中但执行漏删）: {path}"
        ));
    }
    None
}

/// 路径形态：执行侧 `expand_glob_dirs` 只认 `*`、`glob_match` 只支持单星、分隔符只认 `\`；
/// 扫描侧支持 `?` 与 `/` —— 规则里出现这些形态就是「扫描命中、执行漏删」。
///
/// 2026-10-04 磁盘清理审计 §3.1 增 verbatim 前缀一节（判定本体在 [`path_prefix_problem`]，
/// §4.11 把同一道闸扩到 `detect[].path` 与 `excludePaths[]`）。`\\.\` / `\??\` 之所以要在
/// 装载端拦（而不是只靠 `engine::protect` 判保护）：那两条目标在扫描侧会被当成合法
/// 路径枚举并计入体积，在执行侧又永远过不了 `is_path_protected` ⇒ 呈现成
/// 「有条目、体积报出来了，清理完什么都没释放」，用户无从判断是哪一层出的问题。
/// 而 `engine/protect.rs` 侧的收紧（把这两个前缀按 fail-closed 拒绝）是**另一端**：
/// 「配置与运行时输入不许绕过」。两端都要在 —— 只关一端，下一个入口会重新打开。
pub(super) fn file_path_form_problem(path: &str, max_len: usize) -> Option<String> {
    if path.trim().is_empty() {
        return Some("path 为空白".to_string());
    }
    if path.chars().count() > max_len {
        return Some(format!("path 超长（{} > {max_len}）", path.chars().count()));
    }
    // **设备/verbatim 前缀必须在 `?` 检查之前判**（判定本体在 `path_prefix_problem`，
    // §4.11 把同一道闸扩到 `detect[].path` 与 `excludePaths[]`）。
    // 顺序理由：`\??\` 与 `\\?\` 自身含 `?`，若让通配检查先命中，拒绝理由会变成
    // 「含 ? 通配」——把一个安全语义问题报成能力问题，排查时会去查 glob 实现、
    // 找不到真正的防线。
    if let Some(why) = path_prefix_problem(path) {
        return Some(format!("path {why}"));
    }
    if path.contains('/') {
        return Some(format!("path 含 / 分隔符（执行侧只按 \\ 切分）: {path}"));
    }
    if path.contains('?') {
        return Some(format!("path 含 ? 通配（执行侧 expand_glob_dirs 不支持）: {path}"));
    }
    None
}

/// 整包语义校验。`Err(原因)` = 调用方必须拒绝这份规则库（与 Node 门禁同口径）。
pub(super) fn validate_cleanup_package(pkg: &Value) -> Result<(), String> {
    let top = pkg
        .as_object()
        .ok_or_else(|| "规则包不是 JSON 对象".to_string())?;
    // 契约表查询一律走这两个 helper，**不写 `unwrap_or(empty)`**（2026-10-04 审计 §4.6）。
    //
    // 契约表自己在 `engine/rule_schema.rs` 头上声明的是 fail-closed：
    // 「所有校验器拿到 `None` 都必须整包拒绝，不许回退到『跳过语义校验只验签』」。
    // 而原实现 19 处查询里有 17 处是 `unwrap_or(empty.clone())`、`evidenceWeightMax`
    // 是硬编码的 `3` —— 声明与实现相反。
    //
    // 为什么这不是纯洁癖：多数默认值**碰巧**也是 fail-closed（空 `itemFields`
    // 会让未知字段检查拒掉每一条；`maxItems` 默认 0 会拒掉一切），所以「表坏了」
    // 时看起来仍然安全。但两条不是：
    //   · `positiveIntFields` 变空 ⇒ `minAgeHours/minAgeDays` 不再要求正整数，
    //     而扫描侧把 `minAgeHours: -5` 当作「未声明」⇒ **minAge 护栏静默消失**，
    //     刚创建的文件变可删；
    //   · `exclusiveNumericFields` 变空 ⇒ 两个字段可同时声明，扫描侧按「未声明」
    //     处理（完全没有护栏），执行侧按 `max()` 取 —— 正是代码注释警告的分叉。
    // `evidenceWeightMax` 的 `3` 与 `maxTextLen/maxTargetLen` 的 `0` 更是第二份真源
    // （AGENTS §5.16：数值表的唯一真源是 tools/rule-schema.json）。
    let top_fields = req_list("cleanup", "topFields")?;
    let top_required = req_list("cleanup", "topRequired")?;
    let group_fields = req_list("cleanup", "groupFields")?;
    let group_required = req_list("cleanup", "groupRequired")?;
    let sub_fields = req_list("cleanup", "subGroupFields")?;
    let sub_required = req_list("cleanup", "subGroupRequired")?;
    let item_fields = req_list("cleanup", "itemFields")?;
    let item_required = req_list("cleanup", "itemRequired")?;
    let banned = req_list("cleanup", "itemBannedKeys")?;
    let fk_fields = req_list("cleanup", "fileKeyFields")?;
    let fk_required = req_list("cleanup", "fileKeyRequired")?;
    let rk_fields = req_list("cleanup", "regKeyFields")?;
    let rk_required = req_list("cleanup", "regKeyRequired")?;
    let prov_fields = req_list("cleanup", "provFields")?;
    let prov_required = req_list("cleanup", "provRequired")?;
    let risk_levels = req_list("cleanup", "riskLevels")?;
    let source_classes = req_list("cleanup", "sourceClasses")?;
    let non_empty_arrays = req_list("cleanup", "nonEmptyArrayFields")?;
    let positive_ints = req_list("cleanup", "positiveIntFields")?;
    let exclusive = req_list("cleanup", "exclusiveNumericFields")?;
    let ev_fields = req_list("cleanup", "evidenceItemFields")?;
    let ev_weight_max = req_number("cleanup", "evidenceWeightMax")? as f64;
    let (token_allowed, token_ci) =
        rule_schema::tokens("cleanup").ok_or_else(|| SCHEMA_UNAVAILABLE.to_string())?;
    let max_text = req_number("cleanup", "maxTextLen")?;
    let max_target = req_number("cleanup", "maxTargetLen")?;

    if let Some(k) = unknown_rule_field(top, &top_fields) {
        return Err(format!("顶层未知字段 {k}"));
    }
    for k in &top_required {
        if !top.contains_key(k) {
            return Err(format!("顶层缺必填字段 {k}"));
        }
    }
    // 严格数字：不套用本域 `js_number` 的 JS 宽松 coercion（字符串 "20260928" 会被它吞掉）。
    // 契约口径必须与 Node 门禁的 `typeof === 'number'` 一致，否则两侧对同一个包给不同结论
    // （残留域同口径：uninstall.rs 用 `as_f64` 而非宽松解析）。
    let ver = top.get("rulesVersion").and_then(Value::as_f64).unwrap_or(0.0);
    if !(ver.is_finite() && ver > 0.0) {
        return Err("rulesVersion 缺失、非数字或非正数".to_string());
    }
    let groups = top
        .get("groups")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| "groups 缺失或为空数组".to_string())?;
    if groups.len() > req_number("cleanup", "maxGroups")? {
        return Err(format!("组数 {} 超上限", groups.len()));
    }

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut seen_targets: HashMap<String, String> = HashMap::new();
    let mut item_count = 0usize;

    for g in groups {
        let Some(go) = g.as_object() else {
            return Err("groups 条目不是对象".to_string());
        };
        if let Some(k) = unknown_rule_field(go, &group_fields) {
            return Err(format!("组未知字段 {k}"));
        }
        for f in &group_required {
            if let Some(why) = require_rule_str(go, f, max_text) {
                return Err(format!("groups.{why}"));
            }
        }
        let owned_items = go.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
        let owned_subs = go.get("subGroups").and_then(Value::as_array).cloned().unwrap_or_default();
        if owned_subs.len() > req_number("cleanup", "maxSubGroupsPerGroup")? {
            return Err("subGroups 数量超上限".to_string());
        }
        for io in owned_items.iter().filter_map(Value::as_object) {
            check_cleanup_item(io, &mut item_count, &mut seen_ids, &mut seen_targets, Ctx {
                item_fields: &item_fields,
                item_required: &item_required,
                banned: &banned,
                fk_fields: &fk_fields,
                fk_required: &fk_required,
                rk_fields: &rk_fields,
                rk_required: &rk_required,
                prov_fields: &prov_fields,
                prov_required: &prov_required,
                risk_levels: &risk_levels,
                source_classes: &source_classes,
                non_empty_arrays: &non_empty_arrays,
                positive_ints: &positive_ints,
                exclusive: &exclusive,
                ev_fields: &ev_fields,
                ev_weight_max,
                max_text,
                max_target,
                pkg_ver: ver,
            })?;
        }
        for sg in owned_subs.iter().filter_map(Value::as_object) {
            if let Some(k) = unknown_rule_field(sg, &sub_fields) {
                return Err(format!("子组未知字段 {k}"));
            }
            for f in &sub_required {
                if let Some(why) = require_rule_str(sg, f, max_text) {
                    return Err(format!("subGroups.{why}"));
                }
            }
            let sg_items = sg.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
            for io in sg_items.iter().filter_map(Value::as_object) {
                check_cleanup_item(io, &mut item_count, &mut seen_ids, &mut seen_targets, Ctx {
                    item_fields: &item_fields,
                    item_required: &item_required,
                    banned: &banned,
                    fk_fields: &fk_fields,
                    fk_required: &fk_required,
                    rk_fields: &rk_fields,
                    rk_required: &rk_required,
                    prov_fields: &prov_fields,
                    prov_required: &prov_required,
                    risk_levels: &risk_levels,
                    source_classes: &source_classes,
                    non_empty_arrays: &non_empty_arrays,
                    positive_ints: &positive_ints,
                    exclusive: &exclusive,
                    ev_fields: &ev_fields,
                    ev_weight_max,
                    max_text,
                    max_target,
                    pkg_ver: ver,
                })?;
            }
        }
    }
    if item_count > req_number("cleanup", "maxItems")? {
        return Err(format!("条目数 {item_count} 超上限"));
    }
    // token 登记集：规则库是签名发布物，未登记变量混进来会造成跨机器行为漂移
    for tok in collect_rule_tokens(pkg) {
        let hit = if token_ci {
            token_allowed.iter().any(|a| a.eq_ignore_ascii_case(&tok))
        } else {
            token_allowed.iter().any(|a| *a == tok)
        };
        if !hit {
            return Err(format!(
                "变量 %{tok}% 未登记（先确认展开器可解析，再登记进契约表 cleanup.tokens）"
            ));
        }
    }
    Ok(())
}

pub(super) const SCHEMA_UNAVAILABLE: &str = "规则契约表不可用（tools/rule-schema.json 解析失败），已按 fail-closed 拒绝";

/// 契约表字符串数组查询，**取不到即整包拒绝**（审计 §4.6）。
///
/// 与 `rule_schema::list` 的区别只有一个：把 `None` 从「调用方随便选个默认值」
/// 变成「调用方必须处理」。契约表头声明的是 fail-closed，这里就是那句话的落点。
fn req_list(domain: &str, key: &str) -> Result<Vec<String>, String> {
    rule_schema::list(domain, key).ok_or_else(|| format!("{SCHEMA_UNAVAILABLE}（缺 {domain}.{key}）"))
}

/// 契约表数值查询，**取不到即整包拒绝**（审计 §4.6）。
///
/// 原实现对上限类用 `unwrap_or(0)`。那个默认值**方向上是 fail-closed**（0 会拒掉
/// 一切），但错误原因是假的：用户/维护者看到的是「条数超上限」，而真实原因是
/// 契约表缺这个键 —— 排查会跑去数条目数，找不到问题。
fn req_number(domain: &str, key: &str) -> Result<usize, String> {
    rule_schema::number(domain, key).ok_or_else(|| format!("{SCHEMA_UNAVAILABLE}（缺 {domain}.{key}）"))
}

/// 一条规则的检查参数（避免 20 个位置参数）
pub(super) struct Ctx<'a> {
    item_fields: &'a Vec<String>,
    item_required: &'a Vec<String>,
    banned: &'a Vec<String>,
    fk_fields: &'a Vec<String>,
    fk_required: &'a Vec<String>,
    rk_fields: &'a Vec<String>,
    rk_required: &'a Vec<String>,
    prov_fields: &'a Vec<String>,
    prov_required: &'a Vec<String>,
    risk_levels: &'a Vec<String>,
    source_classes: &'a Vec<String>,
    non_empty_arrays: &'a Vec<String>,
    positive_ints: &'a Vec<String>,
    exclusive: &'a Vec<String>,
    /// 贡献项字段白名单与权重上限（V2 P1-A3）
    ev_fields: &'a Vec<String>,
    ev_weight_max: f64,
    max_text: usize,
    max_target: usize,
    /// 顶层 rulesVersion：条目级 `ver` 必须与它相等（V2 P2-A1）
    pkg_ver: f64,
}

pub(super) fn check_cleanup_item(
    it: &Map<String, Value>,
    item_count: &mut usize,
    seen_ids: &mut HashSet<String>,
    seen_targets: &mut HashMap<String, String>,
    c: Ctx<'_>,
) -> Result<(), String> {
    *item_count += 1;
    let id = it
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "条目缺 id".to_string())?
        .to_string();
    if let Some(k) = unknown_rule_field(it, c.item_fields) {
        // 先查"已裁决移除"再报"未知字段"：前者才是可执行的结论（回潮字段要点名裁决，
        // 而不是诱导人去契约表里把它加回来）。与 Node 门禁 A4/A2 的报错口径对齐。
        for b in c.banned {
            if it.contains_key(b) {
                return Err(format!("规则 {id}: 出现已裁决移除的字段 {b}"));
            }
        }
        return Err(format!("规则 {id}: 未知字段 {k}（新增字段要先接执行侧，再进契约表）"));
    }
    for f in c.item_required {
        if !it.contains_key(f) {
            return Err(format!("规则 {id}: 缺必填字段 {f}"));
        }
    }
    if !id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(format!("规则 {id}: id 含非 [A-Za-z0-9._-] 字符"));
    }
    if !seen_ids.insert(id.clone()) {
        return Err(format!("规则 id 重复: {id}"));
    }
    // 活路径来源（V2 P2-D7；D19 键名缺陷已于 2026-10-01 修复，活键清单见契约表
    // crossTrack.liveSourceKeys）：一条来源都没有的规则等于配了却永远 0 命中——
    // 不报错比报错坏，装载侧直接拒
    {
        let live = rule_schema::cross("liveSourceKeys").and_then(|v| v.as_array().cloned()).unwrap_or_default();
        let dead = rule_schema::cross("deadSourceKeys").and_then(|v| v.as_array().cloned()).unwrap_or_default();
        let handlers = rule_schema::cross("specialHandlers").and_then(|v| v.as_array().cloned()).unwrap_or_default();
        let has_live = live.iter().any(|k| {
            let k = match k.as_str() {
                Some(s) => s,
                None => return false,
            };
            match it.get(k) {
                None => false,
                Some(Value::Array(a)) => !a.is_empty(),
                Some(v) => !v.is_null(),
            }
        });
        let handled = handlers.iter().find_map(|h| {
            let key = h.get("key").and_then(Value::as_str)?;
            let v = it.get(key).and_then(Value::as_str)?;
            let vals: Vec<&str> = h.get("values").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            // 键存在但取值没登记 → 同样拒（"我以为是专用通道，其实没人认这个值"）
            if vals.is_empty() || vals.contains(&v) {
                Some(vals.contains(&v))
            } else {
                Some(false)
            }
        });
        if let Some(false) = handled {
            return Err(format!("规则 {id}: 专用分流取值未在契约表 crossTrack.specialHandlers 登记"));
        }
        if !has_live && handled.is_none() {
            let dead_used: Vec<String> = dead
                .iter()
                .filter_map(Value::as_str)
                .filter(|k| it.get(*k).and_then(Value::as_array).map(|a| !a.is_empty()).unwrap_or(false))
                .map(String::from)
                .collect();
            return Err(if dead_used.is_empty() {
                format!("规则 {id}: 没有任何活路径来源（{:?} 全缺）", live.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            } else {
                format!(
                    "规则 {id}: 只有 {} 作为路径来源，清理域引擎不消费它（登记表见契约表 crossTrack），等于静默失效",
                    dead_used.join("/")
                )
            });
        }
    }
    // 条目级版本戳必须与顶层一致：混着一版旧条目 = 「上次报这次没报」无从对齐（V2 P2-A1）
    match it.get("ver").and_then(Value::as_f64) {
        None => return Err(format!("规则 {id}: 缺条目级版本戳 ver（跑 tools/stamp-rule-ver.mjs --write 后重签）")),
        Some(vv) if (vv - c.pkg_ver).abs() > f64::EPSILON => {
            return Err(format!("规则 {id}: ver={vv} 与顶层 rulesVersion={} 不一致", c.pkg_ver));
        }
        Some(_) => {}
    }
    // A14（V2 P1-A3）：可选贡献项数组。0 分解释项允许存在（BCU 口径：不进求和、只解释），
    // 但至少要有一个正分事实项——否则这条规则的"建议"没有任何事实支撑。
    // 与 Node 门禁 A14 同文案同口径，任一侧放宽另一侧红。
    if let Some(evs) = it.get("evidenceItems") {
        let arr = evs
            .as_array()
            .ok_or_else(|| format!("规则 {id}: evidenceItems 必须是数组"))?;
        if arr.is_empty() {
            return Err(format!(
                "规则 {id}: evidenceItems 不能是空数组（没有贡献项就删掉该字段，用 evidence 单句）"
            ));
        }
        let mut positive = 0usize;
        for (i, ev) in arr.iter().enumerate() {
            let obj = ev
                .as_object()
                .ok_or_else(|| format!("规则 {id}: evidenceItems[{i}] 必须是对象"))?;
            if let Some(k) = unknown_rule_field(obj, c.ev_fields) {
                return Err(format!("规则 {id}: evidenceItems[{i}] 未知字段 {k}"));
            }
            let text = obj.get("text").and_then(Value::as_str).unwrap_or_default();
            if text.trim().is_empty() {
                return Err(format!("规则 {id}: evidenceItems[{i}] 缺 text 或为空白"));
            }
            if text.chars().count() > c.max_text {
                return Err(format!("规则 {id}: evidenceItems[{i}] text 超长（上限 {}）", c.max_text));
            }
            match obj.get("weight").and_then(Value::as_f64) {
                None => return Err(format!("规则 {id}: evidenceItems[{i}] 缺 weight 或不是数字")),
                Some(w) if !(0.0..=c.ev_weight_max).contains(&w) => {
                    return Err(format!(
                        "规则 {id}: evidenceItems[{i}] weight={w} 超出 0..={}",
                        c.ev_weight_max
                    ));
                }
                Some(w) if w > 0.0 => positive += 1,
                Some(_) => {}
            }
        }
        if positive == 0 {
            return Err(format!(
                "规则 {id}: evidenceItems 全是 0 分解释项——0 分项只解释不进求和，至少要有一个正分事实支撑这条建议"
            ));
        }
    }
    let risk = it.get("risk").and_then(Value::as_str).unwrap_or_default();
    if !c.risk_levels.iter().any(|r| r == risk) {
        return Err(format!("规则 {id}: risk「{risk}」不在 {:?} 之内", c.risk_levels));
    }
    for f in ["evidence", "domain", "group", "nature", "name"] {
        if let Some(why) = require_rule_str(it, f, c.max_text) {
            return Err(format!("规则 {id}: {why}"));
        }
    }
    for f in ["recommended", "regenerable"] {
        if !it.get(f).map(|v| v.is_boolean()).unwrap_or(false) {
            return Err(format!("规则 {id}: {f} 必须是布尔（缺省即静默改变默认口径）"));
        }
    }
    for f in c.non_empty_arrays {
        if let Some(v) = it.get(f) {
            if !v.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
                return Err(format!("规则 {id}: {f} 存在但不是非空数组（有约束却写空 = 静默失效）"));
            }
        }
    }
    let declared = c.exclusive.iter().filter(|f| it.contains_key(f.as_str())).count();
    if declared > 1 {
        return Err(format!("规则 {id}: minAgeHours 与 minAgeDays 互斥，不得同时声明"));
    }
    for f in c.positive_ints {
        if let Some(v) = it.get(f) {
            let ok = v.as_f64().map(|n| n.is_finite() && n.fract() == 0.0 && n > 0.0).unwrap_or(false);
            if !ok {
                return Err(format!("规则 {id}: {f} 必须是正整数"));
            }
        }
    }
    let prov = it
        .get("prov")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("规则 {id}: prov 缺失或不是对象"))?;
    if let Some(k) = unknown_rule_field(prov, c.prov_fields) {
        return Err(format!("规则 {id}: prov 未知字段 {k}"));
    }
    for f in c.prov_required {
        if let Some(why) = require_rule_str(prov, f, c.max_text) {
            return Err(format!("规则 {id}: prov.{why}"));
        }
    }
    let sc = prov.get("sourceClass").and_then(Value::as_str).unwrap_or_default();
    if !c.source_classes.iter().any(|s| s == sc) {
        return Err(format!("规则 {id}: prov.sourceClass「{sc}」不在 {:?} 之内", c.source_classes));
    }
    let fk_list = it.get("fileKeys").and_then(Value::as_array).cloned().unwrap_or_default();
    if fk_list.len() > req_number("cleanup", "maxFileKeysPerItem")? {
        return Err(format!("规则 {id}: fileKeys 条数超上限"));
    }
    for fk in fk_list.iter().filter_map(Value::as_object) {
        if let Some(k) = unknown_rule_field(fk, c.fk_fields) {
            return Err(format!("规则 {id}: fileKeys 未知字段 {k}"));
        }
        for f in c.fk_required {
            if !fk.contains_key(f) {
                return Err(format!("规则 {id}: fileKeys 缺必填字段 {f}（recurse 不得依赖缺省值）"));
            }
        }
        let path = fk.get("path").and_then(Value::as_str).unwrap_or_default();
        if let Some(why) = file_path_form_problem(path, c.max_target) {
            return Err(format!("规则 {id}: fileKeys.{why}"));
        }
        if !fk.get("recurse").map(|v| v.is_boolean()).unwrap_or(false) {
            return Err(format!("规则 {id}: fileKeys.path「{path}」缺显式布尔 recurse"));
        }
        let pat = fk.get("pattern").and_then(Value::as_str).unwrap_or("*");
        let stars = pat.matches('*').count();
        if pat != "*" && (stars != 1 || pat.contains('?')) {
            return Err(format!(
                "规则 {id}: pattern「{pat}」超出执行侧 glob_match 的单星能力（只支持 * / 前缀* / *后缀 / 前缀*后缀）"
            ));
        }
        let fp = format!(
            "file|{}|{}|{}",
            path.to_lowercase(),
            pat,
            if fk.get("recurse").and_then(Value::as_bool) == Some(false) { "false" } else { "true" }
        );
        if let Some(prev) = seen_targets.get(&fp) {
            return Err(format!("规则 {id}: 与 {prev} 精确重复（{fp}）"));
        }
        seen_targets.insert(fp, id.clone());
    }
    let rk_list = it.get("regKeys").and_then(Value::as_array).cloned().unwrap_or_default();
    if rk_list.len() > req_number("cleanup", "maxRegKeysPerItem")? {
        return Err(format!("规则 {id}: regKeys 条数超上限"));
    }
    for rk in rk_list.iter().filter_map(Value::as_object) {
        if let Some(k) = unknown_rule_field(rk, c.rk_fields) {
            return Err(format!("规则 {id}: regKeys 未知字段 {k}"));
        }
        for f in c.rk_required {
            if let Some(why) = require_rule_str(rk, f, c.max_target) {
                return Err(format!("规则 {id}: regKeys.{why}"));
            }
        }
        let path = rk.get("path").and_then(Value::as_str).unwrap_or_default();
        let value = rk.get("value").and_then(Value::as_str).unwrap_or("");
        // v5 C-1：删树（无 `value`）与通配清值（`value:"*"`）过注册表禁删面 —— 两者都是
        // 「该键下全部没掉」，爆炸半径同族（本文件 excludePaths 那段就把两者并称原子操作）。
        // 具名单值删除不在 `reg_target_block_reason` 的管辖语义内，不套。
        // 带 `%TOKEN%` 的目标装载侧判不出落点，一并拒 —— 展开后落在哪棵树是审核看不见的盲区。
        let wipe_form = match rk.get("value").and_then(Value::as_str) {
            None => Some(false),
            Some("*") => Some(true),
            Some(_) => None,
        };
        if let Some(wipe_all_values) = wipe_form {
            let form = if wipe_all_values { "通配清值" } else { "删树" };
            if path.contains('%') {
                return Err(format!(
                    "规则 {id}: {form}型 regKeys 目标含变量，装载侧无法判定禁删面: {path}"
                ));
            }
            if let Some(reason) =
                crate::engine::protect::cleanup_reg_wipe_block_reason(path, wipe_all_values)
            {
                return Err(format!(
                    "规则 {id}: {form}型 regKeys 目标命中注册表禁删面 —— {reason}"
                ));
            }
        }
        let fp = format!("reg|{}|{}", path.to_lowercase(), value);
        if let Some(prev) = seen_targets.get(&fp) {
            return Err(format!("规则 {id}: 与 {prev} 精确重复（{fp}）"));
        }
        seen_targets.insert(fp, id.clone());
    }

    // detect（2026-10-04 审计 §4.11）：安装检测判据，扫描侧 `test_rule_detect`
    // 直接把 `path` 喂给 `path_exists` / `reg_key_exists`。
    //
    // 此前这个字段**完全不过任何形态校验** —— 它在 `itemFields` 白名单里（不是
    // 未知字段），于是设备路径能从这里进库：`\\.\C:\Users\<me>` 在扫描侧会被
    // 当合法路径判存在、在执行侧又永远过不了 `is_path_protected`，净效果是
    // 「条目恒显示存在、清理时一条不删」。§3.1 只给 `fileKeys[].path` 装了闸，
    // 这里就是那个「另一个入口」。
    //
    // 上限复用 `maxFileKeysPerItem` 而不新增契约键：detect 的语义是 fileKeys 的
    // 前置判据、量级同档，且新增键要同时动 schema + 两处计数棘轮，不值当。
    if let Some(det) = it.get("detect") {
        let arr = det
            .as_array()
            .ok_or_else(|| format!("规则 {id}: detect 必须是数组"))?;
        if arr.len() > req_number("cleanup", "maxFileKeysPerItem")? {
            return Err(format!("规则 {id}: detect 条数超上限"));
        }
        for (i, entry) in arr.iter().enumerate() {
            let Some(o) = entry.as_object() else {
                return Err(format!("规则 {id}: detect[{i}] 必须是对象"));
            };
            for k in o.keys() {
                if k != "type" && k != "path" {
                    return Err(format!("规则 {id}: detect[{i}] 未知字段 {k}"));
                }
            }
            let path = o
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("规则 {id}: detect[{i}] 缺 path 或不是字符串"))?;
            if path.trim().is_empty() {
                return Err(format!("规则 {id}: detect[{i}].path 为空白"));
            }
            // type 缺省 = file（对齐扫描侧 `c.get("type") == Some("reg")` 的判定）。
            let is_reg = o.get("type").and_then(|v| v.as_str()) == Some("reg");
            if is_reg {
                // 注册表形态：套文件闸是错的（它按盘符路径的形态判）。
                // 这里只做最小口径 —— hive 前缀 + 不含变量（变量会让装载侧
                // 无法判定注册表禁删面，与 regKeys 同理由）。
                let head = path.trim().to_uppercase();
                if !(head.starts_with("HKLM\\") || head.starts_with("HKCU\\") || head.starts_with("HKCR\\")) {
                    return Err(format!(
                        "规则 {id}: detect[{i}] type=reg 的 path 必须以 HKLM\\ / HKCU\\ / HKCR\\ 开头: {path}"
                    ));
                }
                if path.contains('%') {
                    return Err(format!(
                        "规则 {id}: detect[{i}].path 是注册表目标却含变量，装载侧无法判定: {path}"
                    ));
                }
            } else if let Some(why) = file_path_form_problem(path, c.max_target) {
                return Err(format!("规则 {id}: detect[{i}].{why}"));
            }
        }
    }
    if let Some(ep) = it.get("excludePaths") {
        let arr = ep
            .as_array()
            .ok_or_else(|| format!("规则 {id}: excludePaths 必须是数组"))?;
        if arr.len() > req_number("cleanup", "maxExcludePathsPerItem")? {
            return Err(format!("规则 {id}: excludePaths 条数超上限"));
        }
        let mut has_named_value_exclude = false;
        for v in arr {
            let Some(s) = v.as_str() else {
                return Err(format!("规则 {id}: excludePaths 含非字符串项"));
            };
            if s.trim().is_empty() {
                return Err(format!("规则 {id}: excludePaths 含空白项"));
            }
            // §4.11：excludePaths 是**文件路径**（按目录前缀 / 全路径匹配），
            // 与 fileKeys[].path 同属一个家族，必须过同一道 verbatim 前缀闸。
            //
            // 顺序要点（与 file_path_form_problem 同款）：**前缀闸必须在 `?` 检查
            // 之前**。`\??\` 与 `\\?\` 自身含 `?`，让禁 `?` 那条先命中的话，理由会
            // 变成「形态非法（禁 / 与 ?）」——把安全语义问题报成格式问题。
            if s.contains("::") {
                // 具名值形态是**注册表面**（`键路径::值名`），不是文件路径，
                // 不得套文件闸；它自己的口径在下面那段「与 regKeys 冲突」检查里。
                has_named_value_exclude = true;
            } else if let Some(why) = path_prefix_problem(s) {
                return Err(format!("规则 {id}: excludePaths {why}"));
            } else if s.contains('/') || s.contains('?') {
                return Err(format!("规则 {id}: excludePaths 形态非法（禁 / 与 ?）: {s}"));
            }
        }
        if has_named_value_exclude {
            // 删树（无 value）与 value:"*"（清全部值）是原子操作，删的过程中保不住个别值
            let bad = rk_list.iter().filter_map(Value::as_object).any(|rk| {
                let v = rk.get("value").and_then(Value::as_str);
                v.is_none() || v == Some("*")
            });
            if bad {
                return Err(format!(
                    "规则 {id}: excludePaths 含具名值排除（::），但 regKeys 存在删树/通配形态（无法保留个别值）"
                ));
            }
        }
    }
    Ok(())
}

/// 内置副本读取：与数据目录同一套校验。这里失败说明**仓库自身坏了**（生成器产物没跑门禁），
/// 运行期只能停用规则 —— 给内置副本开豁免通道等于整条链白做。
pub(super) fn read_builtin_rules() -> Option<Value> {
    let v = safe_read_json_from_str(BUILTIN_RULES_JSON)?;
    if let Err(reason) = validate_cleanup_package(&v) {
        log::write_log("error", &format!("内置清理规则语义校验未通过，清理规则已停用: {reason}"));
        return None;
    }
    Some(v)
}

/// 数据目录规则读取（验签 + 防回滚 + 语义校验，fail-closed 回退内置）
pub(super) fn read_verified_data_rules() -> Option<Value> {
    let file = data_rules_file();
    if !file.is_file() {
        return None;
    }
    let Ok(text) = std::fs::read_to_string(&file) else {
        return None;
    };
    if let Err(reason) = rules_signature::verify_rules_text(&text) {
        log::write_log(
            "warn",
            &format!("数据目录规则验签未通过，已回退内置规则: {reason}"),
        );
        return None;
    }
    let Ok(parsed) = serde_json::from_str::<Value>(&text) else {
        return None;
    };
    if !parsed.get("groups").map(|g| g.is_array()).unwrap_or(false) {
        return None;
    }
    let v = parsed.get("rulesVersion").map(js_number).unwrap_or(0.0);
    let builtin_version = safe_read_json_from_str(BUILTIN_RULES_JSON)
        .and_then(|b| b.get("rulesVersion").map(js_number))
        .unwrap_or(0.0);
    let floor = builtin_version.max(rules_watermark());
    if floor > 0.0 && v < floor {
        log::write_log(
            "warn",
            &format!("数据目录规则版本({v})低于防回滚下限({floor})，疑似旧签名文件重放，已回退内置规则"),
        );
        return None;
    }
    // 验签通过但语义不合规：整包拒绝并隔离，避免每次扫描都重复判同一份坏文件
    // （与残留域 load_residue_rules 同一处置，Q2 拍板口径）
    if let Err(reason) = validate_cleanup_package(&parsed) {
        log::write_log(
            "error",
            &format!("数据目录规则语义校验未通过，已整包拒绝并回退内置规则: {reason}"),
        );
        security::quarantine_file(&file, "cleanup-rules 语义校验未通过");
        return None;
    }
    Some(parsed)
}

pub(super) fn safe_read_json_from_str(text: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(text).ok()?;
    if v.get("groups").map(|g| g.is_array()).unwrap_or(false) {
        Some(v)
    } else {
        None
    }
}

/// 自定义开关合并（对照 applyCustomToggles，审查 B-3 fail-closed）
pub(super) fn apply_custom_toggles(rules: &mut Value, parsed: &Value, file_label: &str) -> bool {
    let allowed: [&str; 2] = ["id", "enabled"];
    let mut by_id: HashMap<String, usize> = HashMap::new();
    // 内置条目 id → (组下标, 条目下标)
    let groups_len = rules
        .get("groups")
        .and_then(|g| g.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    for gi in 0..groups_len {
        let items = rules
            .get("groups")
            .and_then(|g| g.as_array())
            .and_then(|a| a.get(gi))
            .map(collect_group_items)
            .unwrap_or_default();
        for (ii, it) in items.iter().enumerate() {
            if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
                by_id.insert(id.to_string(), gi * 100_000 + ii);
            }
        }
    }
    let parsed_groups = parsed
        .get("groups")
        .and_then(|g| g.as_array())
        .cloned()
        .unwrap_or_default();
    // 第一遍：白名单外字段 → 整文件拒载
    for g in &parsed_groups {
        for it in collect_group_items(g) {
            let Some(obj) = it.as_object() else { continue };
            let extra: Vec<&str> = obj
                .keys()
                .filter(|k| !allowed.contains(&k.as_str()))
                .map(|k| k.as_str())
                .collect();
            if !extra.is_empty() {
                log::write_log(
                    "warn",
                    &format!(
                        "[cleanup] 自定义规则 {file_label} 条目 {} 携带禁止字段（{}），整文件拒载（审查 B-3：custom 目录仅允许 {{id, enabled}} 开关内置条目）",
                        it.get("id").and_then(|v| v.as_str()).unwrap_or("(缺 id)"),
                        extra.join("、")
                    ),
                );
                return false;
            }
        }
    }
    // 第二遍：逐条应用开关；未知 id 只忽略该条
    for g in &parsed_groups {
        for it in collect_group_items(g) {
            let Some(id) = it.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(idx) = by_id.get(id).copied() else {
                log::write_log(
                    "warn",
                    &format!("[cleanup] 自定义规则 {file_label} 引用未知条目 id: {id}，已忽略"),
                );
                continue;
            };
            let Some(enabled) = it.get("enabled").and_then(|v| v.as_bool()) else {
                continue;
            };
            let gi = idx / 100_000;
            let ii = idx % 100_000;
            if let Some(target) = rules
                .get_mut("groups")
                .and_then(|g| g.as_array_mut())
                .and_then(|a| a.get_mut(gi))
            {
                let is_sub = target.get("subGroups").is_some();
                if is_sub {
                    if let Some(sgs) = target.get_mut("subGroups").and_then(|v| v.as_array_mut()) {
                        let mut n = 0usize;
                        for sg in sgs.iter_mut() {
                            let len = sg
                                .get("items")
                                .and_then(|v| v.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            if ii < n + len {
                                if let Some(itm) = sg
                                    .get_mut("items")
                                    .and_then(|v| v.as_array_mut())
                                    .and_then(|a| a.get_mut(ii - n))
                                {
                                    itm["enabled"] = Value::Bool(enabled);
                                }
                                break;
                            }
                            n += len;
                        }
                    }
                } else if let Some(itm) = target
                    .get_mut("items")
                    .and_then(|v| v.as_array_mut())
                    .and_then(|a| a.get_mut(ii))
                {
                    itm["enabled"] = Value::Bool(enabled);
                }
            }
        }
    }
    true
}

/// 清理规则原始数据（对照 `CLEANUP_SCRIPT.rules()`）：
/// 数据目录（验签 + 防回滚）> 内置；再套 custom 开关。任何异常都不会抛——恒有结果。
pub fn rules_value() -> Result<Value, String> {
    // 缓存签名：数据文件 mtime|size + custom 文件数|各 mtime（size 一并入键，防「保留 mtime 的篡改」）
    let mut custom: Vec<(PathBuf, f64)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(custom_rules_dir()) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.to_lowercase().ends_with(".json") {
                continue;
            }
            let mtime = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as f64)
                .unwrap_or(0.0);
            custom.push((e.path(), mtime));
        }
    }
    let (data_mtime, data_size) = std::fs::metadata(data_rules_file())
        .map(|m| {
            let mt = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as f64)
                .unwrap_or(0.0);
            (mt, m.len())
        })
        .unwrap_or((0.0, 0));
    let sig = format!(
        "{data_mtime}|{data_size}|{}|{}",
        custom.len(),
        custom.iter().map(|(_, m)| m.to_string()).collect::<Vec<_>>().join(",")
    );
    {
        let cache = RULES_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cached_sig, value)) = cache.as_ref() {
            if *cached_sig == sig {
                return Ok(value.clone());
            }
        }
    }

    // 来源要记进日志（V2 P2-A1）：用户反馈"上次报了这次没报"时，第一句要能回答
    // 「当时吃的是哪一版、是数据目录那份还是内置那份」—— 整库 rulesVersion 相同但来源不同，
    // 结论完全不同
    let (mut rules, rules_source) = match read_verified_data_rules() {
        Some(v) => (v, "数据目录"),
        None => match read_builtin_rules() {
            Some(v) => (v, "内置副本"),
            // 两条路都不通就是空规则集，装载侧不猜、不静默沿用上一版缓存
            None => (json!({ "version": 0, "rulesVersion": 0, "groups": [] }), "无可用规则"),
        },
    };
    for (path, _) in &custom {
        let Some(parsed) = safe_read_json(path) else {
            continue;
        };
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if !apply_custom_toggles(&mut rules, &parsed, &label) {
            log::write_log("warn", &format!("[cleanup] 自定义规则文件已拒载: {}", path.display()));
        }
    }
    let rules_version = rules.get("rulesVersion").map(js_number).unwrap_or(0.0);
    let mut rule_items = 0usize;
    for g in rules.get("groups").and_then(Value::as_array).cloned().unwrap_or_default() {
        rule_items += g.get("items").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
        for sg in g.get("subGroups").and_then(Value::as_array).cloned().unwrap_or_default() {
            rule_items += sg.get("items").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
        }
    }
    // 只在缓存刷新时打一条，扫描/执行/明细都复用这条记录
    log::write_log(
        "info",
        &format!(
            "清理规则库已装载: 来源={rules_source} rulesVersion={rules_version} 条目={rule_items}"
        ),
    );
    *RULES_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((sig, rules.clone()));
    Ok(rules)
}

/// 按 id 定位规则条目（groups→subGroups→items 与 groups→items 并存，需通用遍历）
pub(super) fn find_cleanup_rule_by_id(rules: &Value, id: &str) -> Option<Value> {
    for g in rules.get("groups").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        for it in collect_group_items(&g) {
            if it.get("id").and_then(|v| v.as_str()) == Some(id) {
                return Some(it);
            }
        }
    }
    None
}


// ==================== cleanup:rules ====================

/// cleanup:rules — 向渲染层暴露清理规则唯一数据源（P1-9）
#[tauri::command]
pub fn cleanup_rules<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    match rules_value() {
        Ok(data) => json!({ "success": true, "data": data }),
        Err(e) => {
            log::write_log("warn", &format!("读取清理规则失败: {e}"));
            json!({ "success": false, "message": "清理规则读取失败" })
        }
    }
}

