//! cleanup 域（C 批）：cleanup 9 条通道（规则库 / 扫描 / 执行 / 占用检测 / 明细）
//!
//! 对照 Electron `main.js` 1188-2042（含规则在线更新 1560-1786）。
//!
//! 迁移要点：
//! - **规则库**：内置规则编译期嵌入（`include_str!`，与 Electron `src/data/cleanup-rules.json`
//!   逐字节一致）；数据目录规则必须过 `engine::rules_signature` 验签 + 防回滚水位线
//!   `<数据目录>\cleanup\rules-watermark.json`（只升不降），不通过一律回退内置。
//!   `custom\*.json` 只允许 `{id, enabled}` 开关内置条目（白名单外字段整文件拒载）。
//! - **扫描引擎**：原生引擎优先（`trim_finder::cleanup_scan::run_json` 进程内直调，逐行回调
//!   驱动 `cleanup:scan-progress`），失败/非 0 退出回退 PS 引擎（`ps/cleanup_scan.ps1` 模板替换后执行）。
//! - **PS 模板**：`src-tauri/ps/*.ps1` 是「模板模式」产物（保留 `${X_PLACEHOLDER}`，
//!   真实插值已在生成期求值）。替换口径与 JS `CLEANUP_SCRIPT.scan/execute/detail` 逐条对齐，
//!   由 `tools/check-ps-substitution.mjs` 对拍（同一合成输入，JS 生成 vs Rust 生成逐字节比较）。
//! - **快照槽**：扫描快照 / 回收站失败项 / 占用检测 PID 白名单全部按 `window.label()` 分槽
//!   （Electron 按 `event.sender.id`），执行与结束进程只认本槽内容。
//! - **删除安全**：受保护路径判定统一走 `engine::protect`（三端同源）；危险操作前
//!   `log::flush_sync()`；回收站优先（`trim_finder::scan::recycle::send_to_trash`），
//!   回收站失败项留槽等渲染层红色确认后再永久删除。
//! - **HTTP 未接入**：`cleanup:update-rules` / `cleanup:check-rules-version` 的传输层
//!   留作单一 TODO 点（本批不新增 Cargo 依赖，与 `commands/runtimes.rs::download_to` 同处置），
//!   其余全链（来源清单 / 尺寸闸 / 验签 / 结构校验 / 版本防降级 / 原子落盘 / 水位线 / git 回退）
//!   均已实现，接入 HTTP 后即生效。
//!
//! 需在 `lib.rs` 的 `generate_handler!` 注册：
//! ```text
//! // ---- C 批：cleanup ----
//! commands::cleanup::cleanup_rules,
//! commands::cleanup::cleanup_scan,
//! commands::cleanup::cleanup_execute,
//! commands::cleanup::cleanup_retry_failed_delete,
//! commands::cleanup::cleanup_item_detail,
//! commands::cleanup::cleanup_update_rules,
//! commands::cleanup::cleanup_check_rules_version,
//! commands::cleanup::cleanup_check_locked,
//! commands::cleanup::cleanup_kill_locked_processes,
//! ```
//!
//! 与 Electron 的已知差异（如实登记，供双跑对照时豁免）：
//! 1. **在途清理计数**：Electron 的 `activeCleanupRuns` 供「关窗后台静默退出等删除任务归零」用，
//!    属 Phase 2 的关闭编排，本批未引入（清理命令本身的返回语义一致）。
//! 2. **无 60s 占用检测超时**：原生 `checklocked` 进程内直调不可 kill，故不返回
//!    「占用检测超时」（与 B 批 finder 扫描同一处置，见 commands/finder.rs 差异 1）。
//! 3. **PS 回退路径不流式**：`cleanup:scan` 原生占优路径边扫边发 `cleanup:scan-progress`；
//!    仅当原生不可用回退 PS 时才改为一次性解析（进度事件仍在结果落定时成批发出，终态一致）。
//! 4. **快照回收**：Electron 在 webContents destroy 时删桶；这里按 `window.label()` 分槽
//!    且 `guard` 只放行 main（唯一槽），未注册 destroy 钩子。
//! 5. **结束进程失败文案**：Node `process.kill` 抛 errno 文案（ESRCH/EPERM），
//!    Rust 侧用 TerminateProcess 的可读文案（`{...p, message}` 字段形状一致）。
//! 6. **HTTP 传输层未接入**（见下），`update-rules` / `check-rules-version` 当前恒失败。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Map, Value};
use tauri::{Emitter, WebviewWindow};
use trim_finder::cleanup_scan;

use crate::engine::{guard, log, paths, protect, rules_signature, winhttp};
use crate::pwsh;
use crate::security;

// ==================== 常量（对照 main.js 1170-1577 / 71-72 / 1944） ====================

/// 内置规则库（gen 产物，与上游 `src/data/cleanup-rules.json` 逐字节一致；本仓副本已移出 frontendDist（审查 M14），故编译期从 `src-tauri/data/` 取）
const BUILTIN_RULES_JSON: &str = include_str!("../../data/cleanup-rules.json");
/// 内容下限/上限（审查 1-1：先拦超大响应再解析，防 OOM）
const RULES_MIN_SIZE: usize = 4096;
const RULES_MAX_SIZE: usize = 2 * 1024 * 1024;
/// 单源超时（毫秒）
const RULES_DOWNLOAD_TIMEOUT_MS: u64 = 15000;
/// 发布源按序回退：GitHub raw → jsDelivr → gh-proxy
const RULES_UPDATE_URLS: [&str; 3] = [
    "https://raw.githubusercontent.com/xiaoxu1642/Trim/main/src/data/cleanup-rules.json",
    "https://cdn.jsdelivr.net/gh/xiaoxu1642/Trim@main/src/data/cleanup-rules.json",
    "https://gh-proxy.com/https://raw.githubusercontent.com/xiaoxu1642/Trim/main/src/data/cleanup-rules.json",
];
/// 可删文件清单防呆上限（D13）
const PLAN_CAP_PER_ITEM: usize = 100_000;
const PLAN_CAP_TOTAL: usize = 1_000_000;
/// 占用检测防呆上限
const PLAN_LOCK_CAP: usize = 20_000;
/// 执行/明细的 PS 超时（对照 main.js 1357 / 1531）
const EXECUTE_TIMEOUT: Duration = Duration::from_secs(600);
const DETAIL_TIMEOUT: Duration = Duration::from_secs(120);
const SCAN_TIMEOUT: Duration = Duration::from_secs(300);

// ==================== PS 模板替换（对照 cleanup-scripts.js 1720-1764） ====================

const SCAN_TEMPLATE: &str = include_str!("../../ps/cleanup_scan.ps1");
const EXECUTE_TEMPLATE: &str = include_str!("../../ps/cleanup_execute.ps1");
const DETAIL_TEMPLATE: &str = include_str!("../../ps/cleanup_detail.ps1");
/// 生成器写入的来源说明块结束标记；Rust 侧剥掉它，得到与 JS 运行时字符串**逐字节相同**的模板
const PROVENANCE_END: &str = "# PROVENANCE>>>";

/// 取模板正文（剥掉顶部 `# <<<PROVENANCE … # PROVENANCE>>>` 说明块）
fn template_body(raw: &str) -> &str {
    let rest = match raw.find(PROVENANCE_END) {
        Some(i) => &raw[i + PROVENANCE_END.len()..],
        None => raw,
    };
    // 生成器写的是 `<来源块>\n<正文>`，而 JS 模板字面量本身以 '\n' 开头，
    // 故正文前会多出一个换行——剥掉它才与 JS 运行时字符串**逐字节**相同。
    rest.strip_prefix('\n').unwrap_or(rest)
}

/// 对照 JS `psEscapeSingle`：`String(s).replace(/'/g, "''")`
fn ps_escape_single(s: &str) -> String {
    s.replace('\'', "''")
}

/// 对照 JS `JSON.stringify`（紧凑、非 ASCII 原样输出；键序依赖 serde_json 的 preserve_order）
fn json_text(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
}

/// 对照 JS `String.prototype.replace(str, val)`：**只替换首次出现**
fn sub_once(text: &str, token: &str, value: &str) -> String {
    text.replacen(token, value, 1)
}

/// TrimFastSize.dll 绝对路径（对照 main.js `resolveFastSizeDll`；缺失返回空串 → 脚本自动降级）
///
/// Electron：`process.resourcesPath/fastsize/` → 开发期 `<__dirname>/scripts/`。
/// Tauri：exe 同级 `fastsize/`（resources 落位语义）→ 开发期仓库 `scripts/`（双轨期取兄弟仓库）。
fn fastsize_dll() -> String {
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("TRIM_FASTSIZE_DLL") {
        if !p.trim().is_empty() {
            cands.push(PathBuf::from(p));
        }
    }
    let exe_dir = paths::exe_dir();
    cands.push(exe_dir.join("fastsize").join("TrimFastSize.dll"));
    cands.push(exe_dir.join("resources").join("fastsize").join("TrimFastSize.dll"));
    // 开发期（cargo run）：target/debug → 上溯到 nanoid 同级仓库 scripts/
    cands.push(exe_dir.join("..").join("..").join("..").join("..").join("Trim").join("scripts").join("TrimFastSize.dll"));
    for c in cands {
        if c.is_file() {
            return c.to_string_lossy().to_string();
        }
    }
    String::new()
}

/// 扫描脚本（对照 `CLEANUP_SCRIPT.scan(categories, configuredPaths, rules)`）
pub fn build_scan_script(categories: &[String], configured: &Value, rules: &Value, dll: &str) -> String {
    let cats = ps_escape_single(&json_text(&Value::from(categories.to_vec())));
    let paths_json = ps_escape_single(&json_text(configured));
    let rules_json = ps_escape_single(&json_text(rules));
    let dll_esc = ps_escape_single(dll);
    let t = template_body(SCAN_TEMPLATE);
    let t = sub_once(t, "${CATEGORIES_PLACEHOLDER}", &cats);
    let t = sub_once(&t, "${CONFIGURED_PATHS_PLACEHOLDER}", &paths_json);
    let t = sub_once(&t, "${RULES_JSON_PLACEHOLDER}", &rules_json);
    sub_once(&t, "${FASTSIZE_DLL_PLACEHOLDER}", &dll_esc)
}

/// 执行脚本（对照 `CLEANUP_SCRIPT.execute(items, force, toRecycle, autoRebuild)`）
pub fn build_execute_script(
    items: &[Value],
    force: bool,
    to_recycle: bool,
    auto_rebuild: bool,
    rules: &Value,
    protected_json: &str,
    dll: &str,
) -> String {
    let items_json = ps_escape_single(&json_text(&Value::from(items.to_vec())));
    let rules_json = ps_escape_single(&json_text(rules));
    let protected = ps_escape_single(protected_json);
    let dll_esc = ps_escape_single(dll);
    let t = template_body(EXECUTE_TEMPLATE);
    let t = sub_once(t, "${FORCE_PLACEHOLDER}", if force { "$true" } else { "$false" });
    let t = sub_once(&t, "${RECYCLE_PLACEHOLDER}", if to_recycle { "$true" } else { "$false" });
    let t = sub_once(&t, "${AUTO_REBUILD_PLACEHOLDER}", if auto_rebuild { "$true" } else { "$false" });
    let t = sub_once(&t, "${ITEMS_PLACEHOLDER}", &items_json);
    let t = sub_once(&t, "${RULES_JSON_PLACEHOLDER}", &rules_json);
    let t = sub_once(&t, "${PROTECTED_JSON_PLACEHOLDER}", &protected);
    sub_once(&t, "${FASTSIZE_DLL_PLACEHOLDER}", &dll_esc)
}

/// 明细脚本（对照 `CLEANUP_SCRIPT.detail(id, resolvedPath)`）
pub fn build_detail_script(id: &str, resolved_path: &str, rules: &Value) -> String {
    let rules_json = ps_escape_single(&json_text(rules));
    let t = template_body(DETAIL_TEMPLATE);
    let t = sub_once(t, "${DETAIL_ID_PLACEHOLDER}", &ps_escape_single(id));
    let t = sub_once(&t, "${DETAIL_PATH_PLACEHOLDER}", &ps_escape_single(resolved_path));
    sub_once(&t, "${DETAIL_RULES_JSON_PLACEHOLDER}", &rules_json)
}

// ==================== 规则库加载（对照 cleanup-scripts.js 44-195） ====================

/// 数据目录规则目录。**与 Electron 逐字一致**：`%APPDATA%\Trim\cleanup`
/// （cleanup-scripts.js 硬编码 'Trim'，便携模式同样落 Roaming——保持文件路径全一致）
pub fn data_rules_dir() -> PathBuf {
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let base = if appdata.trim().is_empty() {
        PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default())
            .join("AppData")
            .join("Roaming")
    } else {
        PathBuf::from(appdata)
    };
    base.join("Trim").join("cleanup")
}

fn data_rules_file() -> PathBuf {
    data_rules_dir().join("rules.json")
}

fn custom_rules_dir() -> PathBuf {
    data_rules_dir().join("custom")
}

fn watermark_file() -> PathBuf {
    data_rules_dir().join("rules-watermark.json")
}

/// 规则缓存（键 = 数据 mtime|size|custom 数量|各 custom mtime；对照 RULES_CACHE_SIG）
static RULES_CACHE: Mutex<Option<(String, Value)>> = Mutex::new(None);

/// `safeReadJson`：只接受「能解析且 `groups` 是数组」的 JSON 对象
fn safe_read_json(file: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(file).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    if v.get("groups").map(|g| g.is_array()).unwrap_or(false) {
        Some(v)
    } else {
        None
    }
}

/// 组内条目（`subGroups` 优先，否则 `items`）
fn collect_group_items(group: &Value) -> Vec<Value> {
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

/// 防回滚水位线读取（对照 getRulesWatermark；损坏/不可读按 0）
pub fn rules_watermark() -> f64 {
    let Ok(text) = std::fs::read_to_string(watermark_file()) else {
        return 0.0;
    };
    let Ok(v) = serde_json::from_str::<Value>(&text) else {
        return 0.0;
    };
    match v.get("rulesVersion").map(js_number) {
        Some(n) if n.is_finite() && n > 0.0 => n,
        _ => 0.0,
    }
}

/// 防回滚水位线写入（只升不降；写失败不阻断本次更新）
pub fn set_rules_watermark(version: f64) -> bool {
    if !version.is_finite() || version <= 0.0 || version <= rules_watermark() {
        return false;
    }
    let file = watermark_file();
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

/// 数据目录规则读取（验签 + 防回滚，fail-closed 回退内置）
fn read_verified_data_rules() -> Option<Value> {
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
    Some(parsed)
}

fn safe_read_json_from_str(text: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(text).ok()?;
    if v.get("groups").map(|g| g.is_array()).unwrap_or(false) {
        Some(v)
    } else {
        None
    }
}

/// 自定义开关合并（对照 applyCustomToggles，审查 B-3 fail-closed）
fn apply_custom_toggles(rules: &mut Value, parsed: &Value, file_label: &str) -> bool {
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

    let mut rules = read_verified_data_rules()
        .or_else(|| safe_read_json_from_str(BUILTIN_RULES_JSON))
        .unwrap_or_else(|| json!({ "version": 0, "rulesVersion": 0, "groups": [] }));
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
    *RULES_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((sig, rules.clone()));
    Ok(rules)
}

/// 按 id 定位规则条目（groups→subGroups→items 与 groups→items 并存，需通用遍历）
fn find_cleanup_rule_by_id(rules: &Value, id: &str) -> Option<Value> {
    for g in rules.get("groups").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        for it in collect_group_items(&g) {
            if it.get("id").and_then(|v| v.as_str()) == Some(id) {
                return Some(it);
            }
        }
    }
    None
}

// ==================== 路径绑定配置（对照 loadPathsConfig） ====================

fn load_paths_config() -> Value {
    let file = paths::paths_config_file();
    match std::fs::read_to_string(&file) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(mut v) => {
                // 剥离历史版本遗留的软件清单（不再展示与维护）
                if let Some(obj) = v.as_object_mut() {
                    obj.remove("softwareInventory");
                }
                if v.is_object() {
                    v
                } else {
                    json!({})
                }
            }
            Err(_) => json!({}),
        },
        Err(_) => json!({}),
    }
}

// ==================== 分槽快照（对照 cleanupSnapshots / trashFailureSlots / lastLockCheckProcs） ====================

static CLEANUP_SNAPSHOTS: OnceLock<Mutex<HashMap<String, HashMap<String, Value>>>> = OnceLock::new();
static TRASH_FAILURES: OnceLock<Mutex<HashMap<String, Vec<Value>>>> = OnceLock::new();
static LOCK_WHITELIST: OnceLock<Mutex<HashMap<String, Vec<Value>>>> = OnceLock::new();

fn snapshots() -> &'static Mutex<HashMap<String, HashMap<String, Value>>> {
    CLEANUP_SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn trash_failures() -> &'static Mutex<HashMap<String, Vec<Value>>> {
    TRASH_FAILURES.get_or_init(|| Mutex::new(HashMap::new()))
}
fn lock_whitelist() -> &'static Mutex<HashMap<String, Vec<Value>>> {
    LOCK_WHITELIST.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 对照 `snapshotById`
fn snapshot_by_id(items: &[Value]) -> HashMap<String, Value> {
    let mut map = HashMap::new();
    for item in items {
        let Some(id) = item.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        if id.chars().count() <= 160 {
            map.insert(id.to_string(), item.clone());
        }
    }
    map
}

/// `path.resolve` 的词法折叠等价物（不触盘；用于快照 path 比对）
fn path_resolve(p: &str) -> String {
    let text = if Path::new(p).is_absolute() {
        p.to_string()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => format!("{}\\{}", cwd.to_string_lossy(), p),
            Err(_) => p.to_string(),
        }
    };
    let bytes = text.as_bytes();
    let prefix_len = if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        2
    } else if text.starts_with(r"\\") {
        let parts: Vec<&str> = text[2..]
            .split(|c| c == '\\' || c == '/')
            .filter(|c| !c.is_empty())
            .collect();
        if parts.len() >= 2 {
            2 + parts[0].len() + 1 + parts[1].len()
        } else {
            0
        }
    } else {
        0
    };
    let (prefix, body) = text.split_at(prefix_len.min(text.len()));
    let mut segs: Vec<&str> = Vec::new();
    for c in body.split(|c| c == '\\' || c == '/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c == ".." {
            segs.pop();
            continue;
        }
        segs.push(c);
    }
    let joined = segs.join("\\");
    if prefix.is_empty() {
        joined
    } else if joined.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}\\{joined}")
    }
}

/// 对照 `validateSnapshotItems`：全部命中本窗口快照且 path 未被改写才放行
fn validate_snapshot_items(items: Option<&Value>, snapshot: &HashMap<String, Value>) -> Option<Vec<Value>> {
    let arr = items?.as_array()?;
    if arr.is_empty() || arr.len() > 500 {
        return None;
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        if !item.is_object() {
            return None;
        }
        let id = item.get("id").and_then(|v| v.as_str())?;
        let known = snapshot.get(id)?;
        if let (Some(a), Some(b)) = (
            item.get("path").and_then(|v| v.as_str()),
            known.get("path").and_then(|v| v.as_str()),
        ) {
            if !a.is_empty() && !b.is_empty() && path_resolve(a) != path_resolve(b) {
                return None;
            }
        }
        out.push(known.clone());
    }
    Some(out)
}

// ==================== 数值/字符串的 JS 口径 ====================

/// `Number(x)`：不可解析为 NaN
fn js_number(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => s.trim().parse::<f64>().unwrap_or(f64::NAN),
        Value::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Value::Null => 0.0,
        _ => f64::NAN,
    }
}

/// `Number(x) || 0`
fn js_num_or_zero(v: Option<&Value>) -> f64 {
    match v.map(js_number) {
        Some(n) if n.is_finite() => n,
        _ => 0.0,
    }
}

fn js_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// 数字按 JS `String(n)` 呈现（整数不带 `.0`）
fn js_num_str(n: f64) -> String {
    if !n.is_finite() {
        return "NaN".to_string();
    }
    if n.fract() == 0.0 && n.abs() < 9e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// `new Date().toISOString()`
fn iso_now() -> String {
    let ms = crate::engine::now_ms();
    let secs = ms.div_euclid(1000);
    let milli = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milli:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
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

// ==================== cleanup:scan ====================

/// 扫描累积器（对照 cleanup:scan 的 data / planBuf / planTruncated / planTotalRows）
#[derive(Default)]
struct ScanAccum {
    data: Vec<Value>,
    plan: HashMap<String, Vec<Value>>,
    plan_truncated: HashSet<String>,
    plan_total: usize,
    total: usize,
}

impl ScanAccum {
    /// 按行解析（对照 `onEngineStdout`），返回本轮新增的 `@@ITEM@@`（用于推进度）
    fn ingest_line(&mut self, line: &str) -> Option<Value> {
        if let Some(rest) = line.strip_prefix("@@PLANFILE@@") {
            // 计划文件行只进主进程快照（渲染层不消费），受总量防呆上限约束
            if self.plan_total >= PLAN_CAP_TOTAL {
                return None;
            }
            if let Ok(pf) = serde_json::from_str::<Value>(rest) {
                let id = pf.get("id").and_then(|v| v.as_str());
                let path = pf.get("path").and_then(|v| v.as_str());
                if let (Some(id), Some(path)) = (id, path) {
                    if id.chars().count() <= 160 && path.chars().count() <= 2000 {
                        let arr = self.plan.entry(id.to_string()).or_default();
                        if arr.len() < PLAN_CAP_PER_ITEM {
                            let size = js_num_or_zero(pf.get("size"));
                            arr.push(json!({ "path": path, "size": size as i64 }));
                            self.plan_total += 1;
                        } else if self.plan_truncated.insert(id.to_string()) {
                            log::write_log(
                                "warn",
                                &format!("可删文件清单超过 {PLAN_CAP_PER_ITEM} 条上限: {id}"),
                            );
                        }
                    }
                }
            }
            return None;
        }
        let rest = line.strip_prefix("@@ITEM@@")?;
        let item: Value = serde_json::from_str(rest).ok()?;
        let id = item.get("id")?;
        if !js_truthy(id) {
            return None;
        }
        self.data.push(item.clone());
        Some(item)
    }
}

/// 记账一行并按需推 `cleanup:scan-progress`（对照 sender.send('cleanup:scan-progress', …)）
fn ingest_and_emit<R: tauri::Runtime>(accum: &Arc<Mutex<ScanAccum>>, window: &WebviewWindow<R>, line: &str) {
    let (item, done, total) = {
        let mut a = accum.lock().unwrap_or_else(|e| e.into_inner());
        let item = a.ingest_line(line);
        (item, a.data.len(), a.total)
    };
    if let Some(item) = item {
        let _ = window.emit(
            "cleanup:scan-progress",
            json!({ "done": done, "total": total, "item": item }),
        );
    }
}

/// 扫描主体（原生引擎优先，失败回退 PS）
fn do_cleanup_scan<R: tauri::Runtime>(window: &WebviewWindow<R>, label: &str, cats: Vec<String>) -> Value {
    let configured = load_paths_config();
    let rules = match rules_value() {
        Ok(r) => r,
        Err(e) => {
            log::write_log("error", &format!("扫描异常: {e}"));
            return json!({ "success": false, "message": e, "data": [] });
        }
    };
    let cats_json = json_text(&Value::from(cats.clone()));
    let cfg_json = json_text(&configured);
    let rules_json = json_text(&rules);
    let accum = Arc::new(Mutex::new(ScanAccum {
        total: cats.len(),
        ..Default::default()
    }));
    // 原生引擎：进程内直调 + 逐行回调推进度（不再 spawn finder.exe；B 批 sink 化后的数据入口）
    let hook_accum = accum.clone();
    let hook_window = window.clone();
    let hook: Option<Box<dyn FnMut(&str)>> = Some(Box::new(move |line: &str| {
        ingest_and_emit(&hook_accum, &hook_window, line);
    }));
    let (mut code, _stdout, mut stderr) =
        cleanup_scan::run_json(&[cats_json, cfg_json], &rules_json, hook);
    let mut used_ps = false;
    if code != 0 {
        log::write_log(
            "warn",
            &format!(
                "Rust 清理扫描不可用，回退 PS 引擎: {}",
                if stderr.trim().is_empty() {
                    format!("退出码 {code}")
                } else {
                    stderr.trim().to_string()
                }
            ),
        );
        // 回退前清空 Rust 引擎的半程输出，防止条目/清单混入 PS 结果
        {
            let mut a = accum.lock().unwrap_or_else(|e| e.into_inner());
            a.data.clear();
            a.plan.clear();
            a.plan_truncated.clear();
            a.plan_total = 0;
        }
        used_ps = true;
        let script = build_scan_script(&cats, &configured, &rules, &fastsize_dll());
        let out = (|| -> Result<pwsh::PsOutput, String> {
            let path = pwsh::write_temp_script(&script, ".ps1")?;
            let r = pwsh::run_file(&path, SCAN_TIMEOUT, Some("cleanup.scan"));
            let _ = std::fs::remove_file(&path);
            r
        })();
        match out {
            Ok(ps) => {
                for line in ps.stdout.lines() {
                    ingest_and_emit(&accum, window, line);
                }
                code = ps.code;
                stderr = ps.stderr;
            }
            Err(e) => {
                log::write_log("error", &format!("扫描失败: {e}"));
                return json!({ "success": false, "message": e, "data": [] });
            }
        }
    }
    if code != 0 {
        log::write_log("error", &format!("扫描失败: {}", stderr.trim()));
        let msg = if stderr.trim().is_empty() {
            "扫描失败".to_string()
        } else {
            stderr.trim().to_string()
        };
        return json!({ "success": false, "message": msg, "data": [] });
    }
    // 把可删文件清单并进条目（无清单的条目补空数组，执行/明细侧统一按数组消费）
    let (data, plan_total) = {
        let mut a = accum.lock().unwrap_or_else(|e| e.into_inner());
        let plan = std::mem::take(&mut a.plan);
        let truncated = std::mem::take(&mut a.plan_truncated);
        let mut data = std::mem::take(&mut a.data);
        for item in data.iter_mut() {
            let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let files = plan.get(&id).cloned().unwrap_or_default();
            if let Some(obj) = item.as_object_mut() {
                obj.insert("files".into(), Value::Array(files));
                if truncated.contains(&id) {
                    obj.insert("filesTruncated".into(), Value::Bool(true));
                }
            }
        }
        (data, a.plan_total)
    };
    let engine = if used_ps { "powershell" } else { "rust" };
    log::write_log(
        "info",
        &format!(
            "扫描完成({engine}): {} 项, 计划文件 {} 条",
            data.len(),
            plan_total
        ),
    );
    *snapshots().lock().unwrap_or_else(|e| e.into_inner()) =
        [(label.to_string(), snapshot_by_id(&data))].into_iter().collect();
    json!({ "success": true, "data": data })
}

/// cleanup:scan — 扫描可清理项（原生引擎优先，PS 回退；进度走 `cleanup:scan-progress`）
#[tauri::command]
pub async fn cleanup_scan<R: tauri::Runtime>(window: WebviewWindow<R>, categories: Option<Value>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg, "data": [] });
    }
    let cats: Option<Vec<String>> = categories.as_ref().and_then(|c| c.as_array()).and_then(|a| {
        if a.is_empty() || a.len() > 200 {
            return None;
        }
        let mut out = Vec::with_capacity(a.len());
        for v in a {
            let s = v.as_str()?;
            if s.chars().count() > 160 {
                return None;
            }
            out.push(s.to_string());
        }
        Some(out)
    });
    let Some(cats) = cats else {
        return json!({ "success": false, "message": "清理分类参数无效", "data": [] });
    };
    let label = window.label().to_string();
    // 审查 2-3：先置空桶，扫描成功后填充
    snapshots()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(label.clone(), HashMap::new());
    log::write_log("info", &format!("开始扫描: {}", cats.join(", ")));
    let win = window.clone();
    let task = tauri::async_runtime::spawn_blocking(move || do_cleanup_scan(&win, &label, cats));
    match task.await {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": e.to_string(), "data": [] }),
    }
}

// ==================== cleanup:execute ====================

/// 回收站失败项 → 本条目的统计（对照 perItem）
#[derive(Default, Clone)]
struct RecycleStat {
    ok: usize,
    fail: usize,
    recycled_bytes: i64,
}

/// 把一个路径移入回收站（只进回收站，可还原）
fn move_to_recycle_bin(path: &str) -> Result<(), String> {
    trim_finder::scan::recycle::send_to_trash(path)
}

/// cleanup:execute — 执行清理（危险通道：快照校验 + 删除前刷盘 + 回收站优先）
#[tauri::command]
pub async fn cleanup_execute<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    items: Option<Value>,
    force: Option<bool>,
    to_recycle: Option<bool>,
    auto_rebuild: Option<bool>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let force = force.unwrap_or(false);
    let to_recycle = to_recycle.unwrap_or(false);
    let auto_rebuild = auto_rebuild.unwrap_or(false);
    let snapshot = snapshots()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&label)
        .cloned()
        .unwrap_or_default();
    let Some(safe_items) = validate_snapshot_items(items.as_ref(), &snapshot) else {
        return json!({ "success": false, "message": "清理项不是最近一次扫描结果，已拒绝执行" });
    };
    let rules = match rules_value() {
        Ok(r) => r,
        Err(e) => return json!({ "success": false, "message": e }),
    };
    let script = build_execute_script(
        &safe_items,
        force,
        to_recycle,
        auto_rebuild,
        &rules,
        &protect::protected_roots_json(),
        &fastsize_dll(),
    );
    log::write_log(
        "info",
        &format!(
            "开始清理: {} 项, force={force}, toRecycle={to_recycle}, autoRebuild={auto_rebuild}",
            safe_items.len()
        ),
    );
    log::flush_sync(); // 审查v4-L3：危险操作执行前强制刷盘

    let task = tauri::async_runtime::spawn_blocking(move || {
        let out = (|| -> Result<pwsh::PsOutput, String> {
            let path = pwsh::write_temp_script(&script, ".ps1")?;
            // 不在此层剥 @@DIAG@@：JS 的 cleanLines 取的是**未剥**的行，
            // 剥掉的 stdout 只作为 join 为空时的兜底（逐字对齐 main.js 1364）
            let r = pwsh::run_file(&path, EXECUTE_TIMEOUT, None);
            let _ = std::fs::remove_file(&path);
            r
        })();
        let ps = match out {
            Ok(p) => p,
            Err(e) => return json!({ "success": false, "message": e }),
        };
        if ps.code != 0 {
            log::write_log("error", &format!("清理失败: {}", ps.stderr.trim()));
            let msg = if ps.stderr.trim().is_empty() {
                "清理失败".to_string()
            } else {
                ps.stderr.trim().to_string()
            };
            return json!({ "success": false, "message": msg });
        }
        let raw = ps.stdout;
        let diag_stripped = crate::diag::extract_diag_lines(&raw, "cleanup.execute");
        let mut recycle_entries: Vec<Value> = Vec::new();
        let mut clean_lines: Vec<&str> = Vec::new();
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("@@RECYCLE@@") {
                if let Ok(entry) = serde_json::from_str::<Value>(rest) {
                    let ok = entry
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|p| !p.is_empty())
                        .unwrap_or(false);
                    if ok {
                        recycle_entries.push(entry);
                    }
                }
                continue;
            }
            clean_lines.push(line);
        }
        let joined = clean_lines.join("\n");
        let body = if joined.trim().is_empty() {
            diag_stripped.trim().to_string()
        } else {
            joined.trim().to_string()
        };
        let Ok(mut data) = serde_json::from_str::<Value>(&body) else {
            return json!({ "success": false, "message": "解析结果失败", "raw": diag_stripped });
        };
        let mut failures: Vec<Value> = Vec::new();
        if to_recycle && !recycle_entries.is_empty() {
            let mut per_item: HashMap<String, RecycleStat> = HashMap::new();
            for entry in &recycle_entries {
                let path = entry.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let id = entry.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                // 审查 1-4：entry.path 来自脚本 stdout 解析，信任级别低于快照校验项
                if protect::is_path_protected(path) {
                    per_item.entry(id).or_default().fail += 1;
                    log::write_log("warn", &format!("拒绝移入回收站（受保护路径）: {path}"));
                    continue;
                }
                let st = per_item.entry(id).or_default();
                match move_to_recycle_bin(path) {
                    Ok(()) => {
                        st.recycled_bytes += js_num_or_zero(entry.get("size")) as i64;
                        st.ok += 1;
                        let is_dir = entry.get("isDir").and_then(|v| v.as_bool()).unwrap_or(false);
                        if is_dir && auto_rebuild {
                            let _ = std::fs::create_dir_all(path);
                        }
                    }
                    Err(e) => {
                        st.fail += 1;
                        failures.push(json!({
                            "id": entry.get("id").cloned().unwrap_or(Value::Null),
                            "path": path,
                            "size": js_num_or_zero(entry.get("size")) as i64,
                            "isDir": entry.get("isDir").and_then(|v| v.as_bool()).unwrap_or(false),
                        }));
                        log::write_log("warn", &format!("移入回收站失败: {path} -> {e}"));
                    }
                }
            }
            // J-1（S3）：写入本 label 分槽（Electron 用 sender.id），多窗口并发清理互不串台
            if !failures.is_empty() {
                trash_failures()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(label.clone(), failures.clone());
            }
            let mut recycled_bytes = 0i64;
            let mut recycled_count = 0i64;
            let ids: Vec<String> = data
                .get("details")
                .and_then(|d| d.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|d| d.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string())
                        .collect()
                })
                .unwrap_or_default();
            if let Some(details) = data.get_mut("details").and_then(|d| d.as_array_mut()) {
                for (i, d) in details.iter_mut().enumerate() {
                    if d.get("status").and_then(|v| v.as_str()) != Some("recycle") {
                        continue;
                    }
                    let st = per_item.get(&ids[i]).cloned();
                    let Some(st) = st else {
                        if let Some(o) = d.as_object_mut() {
                            o.insert("status".into(), Value::from("ok"));
                            o.insert("freed".into(), Value::from(0));
                            o.insert("message".into(), Value::from("无可清理目标"));
                        }
                        continue;
                    };
                    recycled_bytes += st.recycled_bytes;
                    recycled_count += st.ok as i64;
                    let (status, message) = if st.fail == 0 {
                        ("ok", format!("已移入回收站（{} 项，可在系统回收站还原）", st.ok))
                    } else if st.ok > 0 {
                        (
                            "partial",
                            format!("已移入回收站 {} 项，{} 项失败（被占用）", st.ok, st.fail),
                        )
                    } else {
                        ("error", "移入回收站失败（可能被占用）".to_string())
                    };
                    if let Some(o) = d.as_object_mut() {
                        o.insert("freed".into(), Value::from(0)); // 审查 M-3：回收站不计入已释放空间
                        o.insert("recycledBytes".into(), Value::from(st.recycled_bytes));
                        o.insert("status".into(), Value::from(status));
                        o.insert("message".into(), Value::from(message));
                    }
                }
            }
            let (total_freed, success, partial, skipped) = summarize_details(&data);
            if let Some(o) = data.as_object_mut() {
                o.insert("totalFreed".into(), Value::from(total_freed));
                o.insert("recycledBytes".into(), Value::from(recycled_bytes));
                o.insert("recycledCount".into(), Value::from(recycled_count));
                o.insert("success".into(), Value::from(success));
                o.insert("partial".into(), Value::from(partial));
                o.insert("skipped".into(), Value::from(skipped));
            }
        }
        if let Some(o) = data.as_object_mut() {
            o.insert("trashFailures".into(), Value::Array(failures));
        }
        let (total_freed, success, n_partial, skipped) = summarize_details(&data);
        let n_residual = data
            .get("details")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|d| js_num_or_zero(d.get("residual")) > 0.0)
                    .count()
            })
            .unwrap_or(0);
        let failed = data
            .get("details")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|d| d.get("status").and_then(|v| v.as_str()) == Some("error"))
                    .count()
            })
            .unwrap_or(0);
        if let Some(o) = data.as_object_mut() {
            o.insert("failed".into(), Value::from(failed as i64));
            o.insert("partial".into(), Value::from(n_partial as i64));
        }
        log::write_log(
            "info",
            &format!(
                "清理完成: 实测释放 {total_freed} 字节, 成功 {success}, 失败 {failed}, 部分成功 {n_partial}, 跳过 {skipped}, 有残留 {n_residual} 项"
            ),
        );
        if let Some(arr) = data.get("details").and_then(|d| d.as_array()) {
            for d in arr {
                let msg: String = d
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .chars()
                    .take(200)
                    .collect();
                let id = d.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let name = d
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| format!("（{}）", n.chars().take(60).collect::<String>()))
                    .unwrap_or_default();
                log::write_log(
                    "info",
                    &format!(
                        "  清理明细 [{}] {id}{name}: {msg}（释放 {} 字节, 残留 {}）",
                        d.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                        js_num_or_zero(d.get("freed")) as i64,
                        js_num_or_zero(d.get("residual")) as i64
                    ),
                );
            }
        }
        // 成功判据：硬失败（error）为 0 即算成功；partial 属「部分成功」，由渲染层另行提示
        json!({ "success": failed == 0, "data": data })
    });
    match task.await {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": e.to_string() }),
    }
}

/// 按 details 汇总 (totalFreed, success, partial, skipped)（对照 main.js 1416-1423）
fn summarize_details(data: &Value) -> (i64, usize, usize, usize) {
    let mut total = 0i64;
    let mut success = 0usize;
    let mut partial = 0usize;
    let mut skipped = 0usize;
    for d in data
        .get("details")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
    {
        total += js_num_or_zero(d.get("freed")) as i64;
        match d.get("status").and_then(|v| v.as_str()) {
            Some("ok") => success += 1,
            Some("partial") => partial += 1,
            Some("skip") => skipped += 1,
            _ => {}
        }
    }
    (total, success, partial, skipped)
}

// ==================== cleanup:retry-failed-delete ====================

/// cleanup:retry-failed-delete — 回收站失败项的永久删除重试（白名单只来自最近一次 execute）
///
/// 审查 L9：这条同步 `fn` 里对**任意**失败项跑 `remove_dir_all`。同步命令跑在主线程，
/// 一个大目录能让 UI 整段冻结（且用户此刻正盯着进度），故整体挪进 `spawn_blocking`。
/// 渲染层本来就是 `invoke` 拿 Promise，改异步对 JS 侧零影响。
#[tauri::command]
pub async fn cleanup_retry_failed_delete<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let targets = trash_failures()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&label)
        .unwrap_or_default();
    if targets.is_empty() {
        return json!({ "success": false, "message": "没有待重试的失败项" });
    }
    let task = tauri::async_runtime::spawn_blocking(move || {
        retry_failed_delete_blocking(targets)
    });
    match task.await {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": format!("删除任务异常终止: {e}") }),
    }
}

fn retry_failed_delete_blocking(targets: Vec<Value>) -> Value {
    log::write_log("warn", &format!("开始永久删除回收站失败项: {} 项", targets.len()));
    log::flush_sync(); // 审查v4-L3：危险操作执行前强制刷盘
    let mut freed = 0i64;
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut details: Vec<Value> = Vec::new();
    for t in targets {
        let path = t.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let is_dir = t.get("isDir").and_then(|v| v.as_bool()).unwrap_or(false);
        if !Path::new(&path).exists() {
            details.push(json!({ "path": path, "status": "skip", "freed": 0, "message": "文件不存在" }));
            continue;
        }
        if protect::is_path_protected(&path) {
            failed += 1;
            log::write_log("warn", &format!("受保护路径，拒绝删除: {path}"));
            details.push(json!({ "path": path, "status": "error", "freed": 0, "message": "受保护路径，已拒绝" }));
            continue;
        }
        let size = std::fs::symlink_metadata(&path).map(|m| m.len() as i64).unwrap_or(0);
        let rm = if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match rm {
            Ok(()) => {
                freed += size;
                ok += 1;
                details.push(json!({ "path": path, "status": "ok", "freed": size }));
                log::write_log("warn", &format!("回收站失败项经用户确认后永久删除: {path}"));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // fs.rmSync(force:true) 忽略 ENOENT
                ok += 1;
                details.push(json!({ "path": path, "status": "ok", "freed": 0 }));
            }
            Err(e) => {
                failed += 1;
                details.push(json!({ "path": path, "status": "error", "freed": 0, "message": e.to_string() }));
            }
        }
    }
    json!({
        "success": failed == 0,
        "data": { "totalFreed": freed, "ok": ok, "failed": failed, "details": details }
    })
}

// ==================== cleanup:item-detail ====================

/// cleanup:item-detail — 枚举单个条目将删除的文件清单（只读）
#[tauri::command]
pub async fn cleanup_item_detail<R: tauri::Runtime>(window: WebviewWindow<R>, id: Option<String>, path: Option<String>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let id = match id {
        Some(s) if !s.is_empty() && s.chars().count() <= 160 => s,
        _ => return json!({ "success": false, "message": "参数无效" }),
    };
    let rules = rules_value().unwrap_or_else(|_| json!({}));
    // v2.2 第3批（D13）：fileKeys 条目明细直接读扫描快照里的可删文件清单——明细与执行同源
    let (known_files, has_known) = {
        let buckets = snapshots().lock().unwrap_or_else(|e| e.into_inner());
        let known = buckets
            .get(window.label())
            .and_then(|m| m.get(&id))
            .and_then(|it| it.get("files"))
            .and_then(|f| f.as_array())
            .cloned();
        match known {
            Some(f) => (f, true),
            None => (Vec::new(), false),
        }
    };
    let rule = find_cleanup_rule_by_id(&rules, &id);
    let rule_file_keys_non_empty = rule
        .as_ref()
        .and_then(|r| r.get("fileKeys"))
        .and_then(|f| f.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if rule_file_keys_non_empty && has_known {
        let cap = 600usize; // 与 DETAIL_SCRIPT 的明细上限一致
        let files: Vec<Value> = known_files
            .iter()
            .take(cap)
            .map(|f| {
                json!({
                    "path": f.get("path").cloned().unwrap_or(Value::Null),
                    "size": f.get("size").cloned().unwrap_or(Value::from(0)),
                })
            })
            .collect();
        return json!({
            "success": true,
            "data": {
                "kind": "files",
                "total": known_files.len(),
                "truncated": known_files.len() > cap,
                "files": files
            }
        });
    }
    let safe_path = match path {
        Some(p) if !p.is_empty() && p.chars().count() <= 600 => p,
        _ => String::new(),
    };
    let script = build_detail_script(&id, &safe_path, &rules);
    let files = Mutex::new(Vec::<Value>::new());
    let meta = Mutex::new(Option::<Value>::None);
    let body = (|| -> Result<(), String> {
        let script_path = pwsh::write_temp_script(&script, ".ps1")?;
        let out = pwsh::run_file(&script_path, DETAIL_TIMEOUT, Some("cleanup.detail"));
        let _ = std::fs::remove_file(&script_path);
        let out = out?;
        if out.code != 0 {
            return Err(if out.stderr.trim().is_empty() {
                "明细枚举失败".to_string()
            } else {
                out.stderr.trim().to_string()
            });
        }
        for line in out.stdout.lines() {
            if let Some(rest) = line.strip_prefix("@@ITEMFILE@@") {
                if let Ok(f) = serde_json::from_str::<Value>(rest) {
                    if f.get("path").map(|p| p.is_string()).unwrap_or(false) {
                        files.lock().unwrap_or_else(|e| e.into_inner()).push(f);
                    }
                }
            } else if let Some(rest) = line.strip_prefix("@@DETAIL@@") {
                if let Ok(m) = serde_json::from_str::<Value>(rest) {
                    *meta.lock().unwrap_or_else(|e| e.into_inner()) = Some(m);
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = body {
        log::write_log("error", &format!("条目明细枚举失败: {e}"));
        return json!({ "success": false, "message": e });
    }
    let files = files.into_inner().unwrap_or_else(|e| e.into_inner());
    let meta = meta.into_inner().unwrap_or_else(|e| e.into_inner());
    let kind = meta
        .as_ref()
        .and_then(|m| m.get("kind"))
        .and_then(|v| v.as_str())
        .unwrap_or("files");
    let total = match meta.as_ref().and_then(|m| m.get("total")) {
        Some(v) if !v.is_null() => v.clone(),
        _ => Value::from(files.len()),
    };
    let truncated = meta
        .as_ref()
        .and_then(|m| m.get("truncated"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    json!({ "success": true, "data": { "kind": kind, "total": total, "truncated": truncated, "files": files } })
}

// ==================== cleanup:check-locked / kill-locked-processes ====================

/// cleanup:check-locked — 清理前占用检测（只读；PID 白名单仅供紧随其后的结束进程使用）
#[tauri::command]
pub async fn cleanup_check_locked<R: tauri::Runtime>(window: WebviewWindow<R>, ids: Option<Value>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let snapshot = snapshots()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&label)
        .cloned()
        .unwrap_or_default();
    let mut files: Vec<Value> = Vec::new();
    if let Some(arr) = ids.as_ref().and_then(|v| v.as_array()) {
        for s in arr {
            let Some(id) = s.as_str() else { continue };
            let Some(it) = snapshot.get(id) else { continue };
            if let Some(list) = it.get("files").and_then(|f| f.as_array()) {
                for f in list {
                    if let Some(p) = f.get("path").and_then(|v| v.as_str()) {
                        if !p.is_empty() {
                            files.push(json!({ "path": p, "id": id }));
                        }
                    }
                }
            }
        }
    }
    lock_whitelist()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(label.clone(), Vec::new());
    if files.is_empty() {
        return json!({
            "success": true, "locked": [], "byApp": {}, "procs": [],
            "lockedByItem": {}, "scanned": 0, "truncated": false
        });
    }
    let truncated = files.len() > PLAN_LOCK_CAP;
    let list: Vec<Value> = files.into_iter().take(PLAN_LOCK_CAP).collect();
    let scanned = list.len();
    let payload = json_text(&json!({ "files": list }));
    let win = window.clone();
    let task = tauri::async_runtime::spawn_blocking(move || {
        let (code, stdout, stderr) = cleanup_scan::checklocked_json(&payload);
        if code != 0 {
            let msg = if stderr.trim().is_empty() {
                format!("占用检测退出码 {code}")
            } else {
                stderr.trim().to_string()
            };
            return (None, msg);
        }
        let mut locked: Vec<Value> = Vec::new();
        let mut locked_by_item: Map<String, Value> = Map::new();
        let mut by_app: Map<String, Value> = Map::new();
        let mut procs: Vec<Value> = Vec::new();
        let mut seen_pids: HashSet<i64> = HashSet::new();
        let self_pid = std::process::id() as i64;
        for line in stdout.lines() {
            // 前缀 '@@LOCKED@@' 恰 10 字符（勿与 '@@PLANFILE@@' 的 12 混淆）
            let Some(rest) = line.strip_prefix("@@LOCKED@@") else {
                continue;
            };
            let Ok(pf) = serde_json::from_str::<Value>(rest) else {
                continue;
            };
            let Some(path) = pf.get("path").and_then(|v| v.as_str()) else {
                continue;
            };
            if path.is_empty() {
                continue;
            }
            let id = pf.get("id").and_then(|v| v.as_str()).unwrap_or("");
            locked.push(pf.clone());
            if !id.is_empty() {
                let n = locked_by_item.get(id).map(js_number).unwrap_or(0.0) + 1.0;
                locked_by_item.insert(id.to_string(), Value::from(n as i64));
            }
            for p in pf.get("procs").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
                let pid = match p.get("pid").and_then(|v| v.as_i64()) {
                    Some(v) => v,
                    None => continue,
                };
                let app = p.get("app").and_then(|v| v.as_str()).unwrap_or("");
                if app.is_empty() {
                    continue;
                }
                // v3.7.3 修复①：RM 总会把调用方列入占用者名单——剔除自身 PID
                if pid == self_pid {
                    continue;
                }
                // v3.7.3 修复②：explorer 命中即 critical（只展示、无结束入口）
                let critical = app.to_lowercase().contains("explorer") || app.contains("资源管理器");
                let n = by_app.get(app).map(js_number).unwrap_or(0.0) + 1.0;
                by_app.insert(app.to_string(), Value::from(n as i64));
                if seen_pids.insert(pid) {
                    procs.push(json!({ "pid": pid, "app": app, "critical": critical }));
                }
            }
        }
        let whitelist: Vec<Value> = procs
            .iter()
            .filter(|p| p.get("critical").and_then(|v| v.as_bool()) == Some(false))
            .cloned()
            .collect();
        (Some((locked, by_app, procs, locked_by_item, whitelist)), String::new())
    });
    let (payload, err) = match task.await {
        Ok(v) => v,
        Err(e) => return json!({ "success": false, "message": e.to_string() }),
    };
    let Some((locked, by_app, procs, locked_by_item, whitelist)) = payload else {
        return json!({ "success": false, "message": err });
    };
    // 白名单每次检测覆盖（防「检测 A 文件后延时结束 B 进程」的窗口）
    lock_whitelist()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(win.label().to_string(), whitelist);
    json!({
        "success": true,
        "locked": locked,
        "byApp": Value::Object(by_app),
        "procs": procs,
        "lockedByItem": Value::Object(locked_by_item),
        "scanned": scanned,
        "truncated": truncated
    })
}

/// 结束进程用的 kernel32 绑定（零依赖原则：手写 FFI，与 native-scanner 同风格）
#[cfg(windows)]
mod kill_ffi {
    #[link(name = "kernel32")]
    extern "system" {
        pub fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> isize;
        pub fn TerminateProcess(process: isize, exit_code: u32) -> i32;
        pub fn CloseHandle(object: isize) -> i32;
    }
}

/// 结束进程（TerminateProcess；等价 Node `process.kill(pid)`）
#[cfg(windows)]
fn terminate_process(pid: i64) -> Result<(), String> {
    if pid <= 0 || pid > u32::MAX as i64 {
        return Err("无效的进程 ID".to_string());
    }
    const PROCESS_TERMINATE: u32 = 0x0001;
    unsafe {
        let h = kill_ffi::OpenProcess(PROCESS_TERMINATE, 0, pid as u32);
        if h == 0 {
            return Err("无法打开目标进程（可能已退出或缺权限）".to_string());
        }
        let rc = kill_ffi::TerminateProcess(h, 1);
        kill_ffi::CloseHandle(h);
        if rc == 0 {
            return Err("结束进程失败".to_string());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn terminate_process(_pid: i64) -> Result<(), String> {
    Err("仅支持 Windows".to_string())
}

/// cleanup:kill-locked-processes — 结束最近一次占用检测确认过的非关键进程（一次性白名单）
#[tauri::command]
pub fn cleanup_kill_locked_processes<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let targets = lock_whitelist()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&label)
        .unwrap_or_default();
    if targets.is_empty() {
        return json!({ "success": true, "killed": [], "failed": [] });
    }
    let self_pid = std::process::id() as i64;
    let mut killed: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    for p in targets {
        let pid = p.get("pid").and_then(|v| v.as_i64()).unwrap_or(-1);
        // v3.7.3 兜底：检测侧已剔除自身 PID，这里再挡一道——任何路径下都不允许 kill 自己
        if pid == self_pid {
            continue;
        }
        match terminate_process(pid) {
            Ok(()) => killed.push(p),
            Err(e) => {
                let mut v = p.clone();
                if let Some(o) = v.as_object_mut() {
                    o.insert("message".into(), Value::from(e));
                }
                failed.push(v);
            }
        }
    }
    let fail_note = if failed.is_empty() {
        String::new()
    } else {
        format!(
            "，失败 {} 个（{}）",
            failed.len(),
            failed
                .iter()
                .map(|f| format!(
                    "{}#{}",
                    f.get("app").and_then(|v| v.as_str()).unwrap_or(""),
                    f.get("pid").and_then(|v| v.as_i64()).unwrap_or(0)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    log::write_log(
        "warn",
        &format!("结束占用进程（用户确认）: 成功 {} 个{fail_note}", killed.len()),
    );
    json!({ "success": true, "killed": killed, "failed": failed })
}

// ==================== 规则在线更新（HTTP 传输层为唯一 TODO 点） ====================

/// 更新源覆盖配置（对照 loadRulesUpdateOverride）：数据目录 `update-source.json`
fn load_rules_update_override() -> Option<(Vec<String>, Vec<(String, String)>)> {
    let file = data_rules_dir().join("update-source.json");
    let text = std::fs::read_to_string(&file).ok()?;
    let cfg: Value = serde_json::from_str(&text).ok()?;
    if !cfg.is_object() {
        return None;
    }
    let urls: Vec<String> = cfg
        .get("urls")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|u| u.as_str())
                .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
                .take(10)
                .map(|u| u.to_string())
                .collect()
        })
        .unwrap_or_default();
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(obj) = cfg.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if k.chars().count() <= 128 {
                if let Some(s) = v.as_str() {
                    if s.chars().count() <= 1024 {
                        headers.push((k.clone(), s.to_string()));
                    }
                }
            }
        }
    }
    Some((urls, headers))
}

/// 更新源清单（update / check-version 共用；对照 buildRulesSources）
fn build_rules_sources() -> Vec<(String, Vec<(String, String)>)> {
    let override_cfg = load_rules_update_override();
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    if let Some((urls, headers)) = override_cfg.as_ref() {
        for u in urls {
            out.push((u.clone(), headers.clone()));
        }
    }
    let headers = override_cfg.map(|(_, h)| h).unwrap_or_default();
    for url in RULES_UPDATE_URLS {
        out.push((url.to_string(), headers.clone()));
    }
    out.truncate(16);
    out
}

/// HTTP 传输层（复用 `engine::winhttp`，与 runtimes 安装包下载共用同一实现）。
///
/// 规则库更新源可由用户在数据目录 `update-source.json` 覆盖（**用户自选源**），
/// 故此处 `allow_host = None`——**不套宿主白名单**；这条链路的安全性由 `validate_remote_rules`
/// 的 **ed25519 验签 + JSON 结构校验 + 条目形状 + 版本防降级**兜底
/// （传输可去任意源，但内容必须凭内置公钥签名通过才算数）。
/// 尺寸上限 RULES_MAX_SIZE 经 `max_bytes` 传入：content-length 声明值或流式累计超限均中止
/// （先拦超大响应再解析，防 OOM）；全程在内存完成，任何失败都不落盘。
fn http_get(
    url: &str,
    headers: &[(String, String)],
    timeout: Duration,
    on_progress: Option<&dyn Fn(f64)>,
) -> Result<String, String> {
    // 进度：按「已收字节 / 声明总长」折算为 0..99（100 由更新/落盘成功时另行表达）；
    // 总长未知则不打点（不误报进度），且单调不倒退。
    let mut last = -1.0f64;
    let mut cb = |got: u64, total: u64| {
        let Some(report) = on_progress else {
            return;
        };
        if total == 0 {
            return;
        }
        let pct = ((got as f64 / total as f64) * 100.0).min(99.0);
        if pct > last {
            last = pct;
            report(pct);
        }
    };
    winhttp::get_text(url, headers, timeout, RULES_MAX_SIZE as u64, None, &mut cb)
}

/// 内容校验器（对照 makeRulesValidator：尺寸 → 验签 → JSON 结构 → 条目形状 → 版本防降级）
fn validate_remote_rules(text: &str, current_version: f64) -> Result<(f64, String), String> {
    let len = text.chars().count();
    if len < RULES_MIN_SIZE {
        return Err("内容过小，疑似异常响应".to_string());
    }
    if len > RULES_MAX_SIZE {
        return Err("内容过大，疑似异常响应".to_string());
    }
    rules_signature::verify_rules_text(text)?;
    let parsed: Value = serde_json::from_str(text).map_err(|_| "JSON 解析失败".to_string())?;
    let groups = parsed
        .get("groups")
        .and_then(|g| g.as_array())
        .filter(|a| !a.is_empty());
    let Some(groups) = groups else {
        return Err("缺少 groups 结构".to_string());
    };
    let mut sample: Vec<Value> = Vec::new();
    for g in groups {
        sample.extend(collect_group_items(g));
    }
    let shape_ok = !sample.is_empty()
        && sample.iter().all(|it| {
            it.get("id").map(|v| v.is_string()).unwrap_or(false)
                && it.get("name").map(|v| v.is_string()).unwrap_or(false)
        });
    if !shape_ok {
        return Err("条目缺少 id/name 字段".to_string());
    }
    let version = js_num_or_zero(parsed.get("rulesVersion"));
    if version < current_version {
        return Err(format!(
            "下载版本({})低于当前版本({})，已拒绝（防降级）",
            js_num_str(version),
            js_num_str(current_version)
        ));
    }
    Ok((version, text.to_string()))
}

struct FetchResult {
    ok: bool,
    text: String,
    version: f64,
    source: String,
    error: String,
}

/// git 回退（开发机）：经本机凭据深拉远程 main 取规则文件；不可用返回 None
fn git_fetch_rules_file() -> Option<String> {
    // Electron 用 __dirname（dev = 仓库根）；Tauri 用 current_exe() 目录——
    // 常规开发/打包布局下无 .git，与 Electron「打包后自然跳过」同语义
    let repo_dir = paths::exe_dir();
    if !repo_dir.join(".git").exists() {
        return None;
    }
    let cwd = repo_dir.to_string_lossy().to_string();
    if run_git(&cwd, &["fetch", "--depth=1", "origin", "main"], 60).is_none() {
        return None;
    }
    run_git(&cwd, &["show", "FETCH_HEAD:src/data/cleanup-rules.json"], 15)
}

/// 带超时的 git 调用（对照 exec 的 timeout；超时 kill 并返回 None）
fn run_git(cwd: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
    let out = child.wait_with_output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// 拉取远端规则文本（含 git 回退）；on_progress 可选（0..99）
fn fetch_remote_rules_text(
    current_version: f64,
    on_progress: Option<&dyn Fn(f64)>,
) -> FetchResult {
    let mut seen: HashSet<String> = HashSet::new();
    let mut last_error = String::new();
    for (url, headers) in build_rules_sources() {
        if url.is_empty() || !seen.insert(url.clone()) {
            continue;
        }
        match http_get(
            &url,
            &headers,
            Duration::from_millis(RULES_DOWNLOAD_TIMEOUT_MS),
            on_progress,
        ) {
            Err(e) => last_error = e,
            Ok(text) => {
                match validate_remote_rules(&text, current_version) {
                    Ok((version, text)) => {
                        return FetchResult {
                            ok: true,
                            text,
                            version,
                            source: url,
                            error: String::new(),
                        }
                    }
                    Err(e) => last_error = e,
                }
            }
        }
    }
    // git 回退：HTTP 全部失败时，开发机经本机凭据拉取远程
    if let Some(git_text) = git_fetch_rules_file() {
        match validate_remote_rules(&git_text, current_version) {
            Ok((version, text)) => {
                return FetchResult {
                    ok: true,
                    text,
                    version,
                    source: "git:origin/main".to_string(),
                    error: String::new(),
                }
            }
            Err(e) => {
                return FetchResult {
                    ok: false,
                    text: String::new(),
                    version: 0.0,
                    source: "git".to_string(),
                    error: format!("{e}（本机 git 已取到远程规则）"),
                }
            }
        }
    }
    FetchResult {
        ok: false,
        text: String::new(),
        version: 0.0,
        source: String::new(),
        error: last_error,
    }
}

/// cleanup:update-rules — 拉取 → 校验 → 原子落盘 → 抬升防回滚水位线
#[tauri::command]
pub async fn cleanup_update_rules<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let rules = rules_value().unwrap_or_else(|_| json!({}));
    let current_version = js_num_or_zero(rules.get("rulesVersion")).max(rules_watermark());
    let _ = window.emit("cleanup:rules-download-progress", json!({ "percent": 0 }));
    let win = window.clone();
    let task = tauri::async_runtime::spawn_blocking(move || {
        let progress = |pct: f64| {
            let _ = win.emit("cleanup:rules-download-progress", json!({ "percent": pct }));
        };
        fetch_remote_rules_text(current_version, Some(&progress))
    });
    let result = match task.await {
        Ok(r) => r,
        Err(e) => return json!({ "success": false, "message": e.to_string() }),
    };
    if !result.ok {
        let revertible = result.error.contains("版本") || result.error.contains("防降级");
        let hint = if paths::exe_dir().join(".git").exists() {
            if revertible {
                "（远程规则版本未更新或低于本地，请先在源仓库发布新规则）"
            } else {
                "（已尝试本机 git 回退仍失败，请检查网络或远程分支）"
            }
        } else {
            "（HTTP 发布源不可达；私有仓库请先公开仓库，或在数据目录 update-source.json 配置可访问源）"
        };
        log::write_log("warn", &format!("清理规则库更新失败: {}", result.error));
        return json!({
            "success": false,
            "message": format!("所有发布源均不可用或校验未通过：{}{hint}", result.error)
        });
    }
    let dir = data_rules_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return json!({ "success": false, "message": format!("写入规则失败: {e}") });
    }
    // 审查 M10：改走 `security::atomic_write_file`。原来的 `fs::write` + `fs::rename`
    // 缺 `sync_all` —— 断电/蓝屏时 rename 可能先落、内容后落，规则文件会变成 0 字节或半截；
    // 用字节级入口（不是 atomic_write_json）是刻意的：重新序列化 JSON 会改动键序/空白，
    // 而 `_sig` 是对**原文本**签的，一旦重排就把合法规则变成验签失败。
    let target = data_rules_file();
    if let Err(e) = security::atomic_write_file(&target, result.text.as_bytes()) {
        return json!({ "success": false, "message": format!("写入规则失败: {e}") });
    }
    // 落盘成功即抬升水位线（只升不降）；写失败不阻断本次更新，读取侧仍有验签兜底
    set_rules_watermark(result.version);
    log::write_log(
        "info",
        &format!("清理规则库已更新: rulesVersion={}", js_num_str(result.version)),
    );
    let winapp2_version = serde_json::from_str::<Value>(&result.text)
        .ok()
        .and_then(|v| v.get("winapp2Version").cloned())
        .unwrap_or(Value::Null);
    json!({
        "success": true,
        "rulesVersion": result.version,
        "winapp2Version": winapp2_version,
        "source": result.source
    })
}

/// cleanup:check-rules-version — 轻量只读版本检测（拉远端验签后只读版本号，不写盘）
#[tauri::command]
pub async fn cleanup_check_rules_version<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let rules = rules_value().unwrap_or_else(|_| json!({}));
    let current_version = js_num_or_zero(rules.get("rulesVersion")).max(rules_watermark());
    let current_winapp2 = match rules.get("winapp2Version") {
        Some(v) if !v.is_null() => v.clone(),
        _ => Value::Null,
    };
    let task = tauri::async_runtime::spawn_blocking(move || fetch_remote_rules_text(current_version, None));
    let result = match task.await {
        Ok(r) => r,
        Err(e) => return json!({ "success": false, "message": e.to_string() }),
    };
    if !result.ok {
        let msg = if result.error.is_empty() {
            "检测失败".to_string()
        } else {
            result.error
        };
        return json!({
            "success": false,
            "currentVersion": current_version,
            "currentWinapp2Version": current_winapp2,
            "message": msg
        });
    }
    let remote_winapp2 = serde_json::from_str::<Value>(&result.text)
        .ok()
        .and_then(|v| v.get("winapp2Version").cloned())
        .unwrap_or(Value::Null);
    json!({
        "success": true,
        "currentVersion": current_version,
        "currentWinapp2Version": current_winapp2,
        "remoteVersion": result.version,
        "remoteWinapp2Version": remote_winapp2,
        "hasUpdate": result.version > current_version,
        "source": result.source
    })
}

// ==================== 验证（D6 验收三件套第 1 条） ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 首个差异的定位信息（行号 + 两侧原文片段）
    fn first_diff(a: &str, b: &str) -> String {
        let la: Vec<&str> = a.split('\n').collect();
        let lb: Vec<&str> = b.split('\n').collect();
        for i in 0..la.len().max(lb.len()) {
            let x = la.get(i).copied().unwrap_or("<无>");
            let y = lb.get(i).copied().unwrap_or("<无>");
            if x != y {
                let clip = |s: &str| s.chars().take(200).collect::<String>();
                return format!(
                    "首个差异 @行 {}\n   JS  : {}\n   Rust: {}",
                    i + 1,
                    clip(x),
                    clip(y)
                );
            }
        }
        "长度相同但内容不等（不可达）".to_string()
    }

    /// PS 模板替换对拍：同一合成输入，JS 生成 vs Rust 生成**逐字节**比较。
    ///
    /// 夹具由 `node tools/check-ps-substitution.mjs` 生成到临时目录并经
    /// `TRIM_PS_SUBST_DIR` 传入。
    ///
    /// 审查 M13：这条曾经是普通 `#[test]`，没有夹具时打印「跳过」然后 **计入 passed**
    /// —— 单跑 `cargo test` 时它其实什么都没做，绿灯却是真的（门禁文档还把它算进通过数）。
    /// 改成 `#[ignore]` 让它在默认跑里显式显示为 ignored，由 node 侧带 `--ignored` + 夹具驱动，
    /// 「没跑」与「跑过且通过」从此可区分。
    #[test]
    #[ignore = "需 tools/check-ps-substitution.mjs 注入 TRIM_PS_SUBST_DIR 夹具，随该门禁一起跑"]
    fn ps_substitution_matches_js() {
        let Ok(dir) = std::env::var("TRIM_PS_SUBST_DIR") else {
            panic!("被 --ignored 点名执行却没设 TRIM_PS_SUBST_DIR：请通过 node tools/check-ps-substitution.mjs 跑");
        };
        let dir = std::path::PathBuf::from(dir);
        let inputs_path = dir.join("inputs.json");
        if !inputs_path.is_file() {
            panic!("缺少夹具 {}", inputs_path.display());
        }
        let inputs: Value =
            serde_json::from_str(&std::fs::read_to_string(&inputs_path).unwrap()).unwrap();
        let dll = inputs.get("dll").and_then(|v| v.as_str()).unwrap_or("");
        let categories: Vec<String> = inputs
            .get("categories")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).map(String::from).collect())
            .unwrap_or_default();
        let configured = inputs.get("configured").cloned().unwrap_or_else(|| json!({}));
        let rules = inputs.get("rules").cloned().unwrap_or_else(|| json!({}));
        let protected = inputs.get("protectedJson").and_then(|v| v.as_str()).unwrap_or("");
        let items = inputs
            .get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let force = inputs.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
        let to_recycle = inputs.get("toRecycle").and_then(|v| v.as_bool()).unwrap_or(false);
        let auto_rebuild = inputs.get("autoRebuild").and_then(|v| v.as_bool()).unwrap_or(false);
        let detail = inputs.get("detail").cloned().unwrap_or_else(|| json!({}));
        let id = detail.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let path = detail.get("path").and_then(|v| v.as_str()).unwrap_or("");

        let cases: [(&str, String); 3] = [
            ("scan", build_scan_script(&categories, &configured, &rules, dll)),
            (
                "execute",
                build_execute_script(&items, force, to_recycle, auto_rebuild, &rules, protected, dll),
            ),
            ("detail", build_detail_script(id, path, &rules)),
        ];
        let mut compared = 0usize;
        for (name, rust) in cases {
            let js_path = dir.join(format!("js.{name}.ps1"));
            // 审查 v2-M16①：缺夹具绝不能 `eprintln! + continue`。那是把「跑了 1/3」报成
            // 「3/3 通过」的静默假绿，而上游 `check-ps-substitution.mjs:129` 只匹配
            // `\b1 passed\b` 字样 ⇒ 少两份夹具它照样打印「门禁通过」。fail-loud 才算数。
            let js = std::fs::read_to_string(&js_path)
                .unwrap_or_else(|_| panic!("[ps-subst] 缺少 {name} 的 JS 夹具 {}", js_path.display()));
            compared += 1;
            if js == rust {
                eprintln!(
                    "[ps-subst] ✓ {name} 逐字节一致（JS {} 字符 / Rust {} 字符）",
                    js.chars().count(),
                    rust.chars().count()
                );
                continue;
            }
            let rust_path = dir.join(format!("rust.{name}.ps1"));
            let _ = std::fs::write(&rust_path, &rust);
            panic!(
                "[ps-subst] ✗ {name} 替换口径与 JS 不一致\n{}\n（Rust 产物已写 {}）",
                first_diff(&js, &rust),
                rust_path.display()
            );
        }
        assert_eq!(compared, 3, "三份夹具必须逐一比对过，缺任何一份都不算通过");
    }

    /// 模板正文必须已剥离生成器来源块（否则与 JS 运行时字符串不等）
    #[test]
    fn template_bodies_are_stripped() {
        for (name, raw) in [
            ("scan", SCAN_TEMPLATE),
            ("execute", EXECUTE_TEMPLATE),
            ("detail", DETAIL_TEMPLATE),
        ] {
            let body = template_body(raw);
            assert!(!body.contains(PROVENANCE_END), "{name} 未剥离来源块");
            assert!(
                !body.contains("<<<PROVENANCE"),
                "{name} 未剥离来源块"
            );
            assert!(
                body.contains("${FASTSIZE_DLL_PLACEHOLDER}")
                    || body.contains("${DETAIL_RULES_JSON_PLACEHOLDER}"),
                "{name} 模板正文异常（占位符缺失）"
            );
        }
    }

    /// 替换只认首次出现（对照 JS `String.replace(str, val)`），且单引号转义为 `''`
    #[test]
    fn substitution_semantics() {
        assert_eq!(ps_escape_single("a'b"), "a''b");
        assert_eq!(ps_escape_single("no-quote"), "no-quote");
        assert_eq!(
            sub_once("${X}${X}", "${X}", "v"),
            "v${X}",
            "JS 的 replace(str,val) 只替换首处"
        );
    }

    /// 版本号文案（`Number(x)||0` 与 JS String(n) 同口径）
    #[test]
    fn version_text() {
        assert_eq!(js_num_str(js_num_or_zero(Some(&json!("42")))), "42");
        assert_eq!(js_num_str(js_num_or_zero(Some(&json!(0)))), "0");
    }

    /// 规则更新链路真实网络验证（默认 `#[ignore]`，发布前手动跑）：
    /// 真拉内置发布源 → `http_get`（`allow_host = None`，用户自选源链路）→
    /// `validate_remote_rules`（尺寸 → **ed25519 验签** → JSON 结构 → 条目形状 → 版本防降级）
    /// → `rulesVersion` 可解析、原文可 JSON 解析。
    ///
    /// 该链路的信任边界是「验签 + 防降级」而非宿主白名单，本用例正是验证这一点。
    /// 源不可达（无网络/私有仓库未公开）时打印原因并跳过——改用 git 回退路径的结论代替。
    /// 执行：`cargo test -- --ignored rules_update`
    #[test]
    #[ignore = "需要网络；发布前手动执行"]
    fn rules_update_chain_verify() {
        let mut last_err = String::new();
        let mut fetched: Option<(&str, String)> = None;
        for url in RULES_UPDATE_URLS {
            match http_get(url, &[], Duration::from_millis(RULES_DOWNLOAD_TIMEOUT_MS), None) {
                Ok(t) => {
                    fetched = Some((url, t));
                    break;
                }
                Err(e) => last_err = format!("{url} -> {e}"),
            }
        }
        let Some((source, text)) = fetched else {
            // 审查 M13：这里原本 `return` —— 断网时这条发布前门禁**绿灯通过**，
            // 而它是唯一真跑过网络 + 真验签的链路用例，"跑过了" 与 "没网" 无法区分。
            // 发布前门禁的语义是「必须真验成」，所以拿不到源就失败，让人去处理网络/源。
            panic!(
                "所有发布源均不可达，规则库更新链未被真正验证（最后错误：{last_err}）。\
                 本用例是发布前门禁：请联网后重跑 `cargo test rules_update_chain_verify -- --ignored --nocapture`，\
                 不许把跳过状态计入通过。"
            );
        };
        // current_version 传 0：只验签名/结构/形状，不做降级比较（本地版本无关）
        let (version, ok_text) =
            validate_remote_rules(&text, 0.0).expect("远端规则未通过 ed25519 验签/结构校验");
        assert_eq!(ok_text, text, "校验通过时返回文本应与原文一致");
        let parsed: Value = serde_json::from_str(&ok_text).expect("验签通过的文本必须可 JSON 解析");
        assert!(
            parsed.get("rulesVersion").is_some(),
            "规则缺少 rulesVersion 字段"
        );
        assert!(version > 0.0, "rulesVersion 无法解析为正数（得到 {}）", version);
        eprintln!(
            "[rules-update] ✓ 源 {} 验签通过，rulesVersion={}",
            source,
            js_num_str(version)
        );
    }
}