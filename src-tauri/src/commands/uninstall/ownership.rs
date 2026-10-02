//! C2 卸载所有权历史：ownership / footprint / learned 三个内部模块 + 孤儿目录扫描与忽略。
//!
//! 三个内部模块是既有结构，切割时整体随行（学库复用同一份契约校验）。
//! 只读判定 + 台账写入，不删任何用户文件；忽略清单改动只影响下次扫描。

use crate::engine::{delete_manifest, guard, log, protect};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;
use tauri::WebviewWindow;
use super::helpers::*;
use super::list_run::*;
use super::residue::*;
use super::residue_update::*;
use super::dead::*;
// ==================== C2 卸载所有权历史（方案 §6.3） ====================
///
/// 目标不是"把所有没人认领的目录都列出来"，而是**只在证据链闭合时**把一个精确同名目录（或其中
/// 明确可弃的子目录）升级为候选。所以这里是一条单向状态机，不是一个缓存：
///
/// ```text
/// 用户确认卸载、执行卸载器之前  →  写 pending（此刻还不知道卸载会不会成功）
/// 应用数据遗留扫描时复扫当前程序清单     →  程序已消失且原 InstallLocation ENOENT  → historical
///                                  程序仍在清单                          → 继续 pending
///                                  pending 超稳定期（30 天）             → 移除
///                                  historical 的程序又回到清单（重装）   → 移除该记录
/// ```
///
/// 为什么不把"点击卸载"直接当成所有权事实：卸载会取消、会失败、会只删一半；
/// 把一次点击当成"这台机器上的这个目录属于它"会让后面所有判定建立在猜测上。
/// `leftover-owners` 类实现（Kudu）也是跨轮保存、合并后再确认的，不是一条即用即弃的记录。
pub(super) mod ownership {
    use crate::commands::uninstall::ownership::footprint;
    use serde_json::{json, Value};
    use std::collections::HashSet;
    use std::path::Path;

    /// 数据文件 schema 版本（结构变化时递增；旧版本文件按损坏处理走隔离，不做兼容层）
    pub const SCHEMA_VERSION: u64 = 1;
    /// 记录上限：所有权历史只服务应用数据遗留判定，不该无限增长（每条记录都要参与复扫与匹配）
    pub const MAX_RECORDS: usize = 400;
    /// pending 稳定期：超过就按"卸载没继续/用户放弃了"回收。刻意**不做**成永久保留——
    /// 一条永远悬着的 pending 会让后面每次复扫都重跑判定，却没有产出候选的资格。
    pub const PENDING_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

    pub const STATE_PENDING: &str = "pending";
    pub const STATE_HISTORICAL: &str = "historical";

    pub fn empty_doc() -> Value {
        json!({ "schemaVersion": SCHEMA_VERSION, "owners": [], "ignored": [] })
    }

    pub fn file() -> std::path::PathBuf {
        crate::engine::paths::app_data_dir().join("uninstall-ownership.json")
    }

    /// 载入：文件缺失 = 空档（正常首次使用）；解析失败或结构不对 = 按损坏隔离后回空档。
    /// 隔离而不是"尽力解析"是因为这份数据会**驱动删除候选**，半损坏状态下的猜测不可接受。
    pub fn load() -> Value {
        let path = file();
        let Ok(text) = std::fs::read_to_string(&path) else {
            return empty_doc();
        };
        let parsed: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                crate::engine::log::write_log("warn", &format!("所有权历史解析失败，已隔离: {e}"));
                crate::security::quarantine_file(&path, "ownership JSON 解析失败");
                return empty_doc();
            }
        };
        if parsed.get("owners").and_then(Value::as_array).is_none()
            || parsed.get("schemaVersion").and_then(Value::as_u64) != Some(SCHEMA_VERSION)
        {
            crate::engine::log::write_log("warn", "所有权历史结构或 schema 版本不符，已隔离并重建空档");
            crate::security::quarantine_file(&path, "ownership 结构/版本不符");
            return empty_doc();
        }
        parsed
    }

    pub fn save(doc: &Value) -> Result<(), String> {
        crate::security::atomic_write_json(&file(), doc).map_err(|e| e.to_string())
    }

    fn owners_of_mut<'a>(doc: &'a mut Value) -> &'a mut Vec<Value> {
        doc["owners"].as_array_mut().expect("owners 必须是数组（load 已校验）")
    }

    pub fn is_ignored(doc: &Value, app_id: &str, display_name_norm: &str) -> bool {
        let Some(list) = doc.get("ignored").and_then(Value::as_array) else {
            return false;
        };
        list.iter().any(|i| {
            let id = i.get("appId").and_then(Value::as_str).unwrap_or("");
            let name = i.get("displayName").and_then(Value::as_str).unwrap_or("");
            (!id.is_empty() && id.eq_ignore_ascii_case(app_id))
                || (!name.is_empty() && !display_name_norm.is_empty() && name == display_name_norm)
        })
    }

    /// 卸载执行前写 pending 事件。已存在同 appId 时**刷新**而不是新增（重装/多次尝试是同一事实）；
    /// 命中忽略清单则完全不记（否则用户忽略了又被重新采纳）。
    pub fn record_pending(
        doc: &mut Value,
        app_id: &str,
        display_name: &str,
        publisher: &str,
        install_location: &str,
        owned_paths: &[String],
        now_ms: i64,
        name_norm: impl Fn(&str) -> String,
    ) -> bool {
        if app_id.is_empty() || is_ignored(doc, app_id, &name_norm(display_name)) {
            return false;
        }
        let owners = owners_of_mut(doc);
        if let Some(hit) = owners.iter_mut().find(|o| {
            o.get("appId").and_then(Value::as_str) == Some(app_id)
        }) {
            hit["displayName"] = json!(display_name);
            hit["publisher"] = json!(publisher);
            hit["installLocation"] = json!(install_location);
            hit["ownedPaths"] = json!(owned_paths);
            hit["state"] = json!(STATE_PENDING);
            hit["recordedAt"] = json!(now_ms);
            // 刷新即重新开始稳定期计时；上一轮的确认时间不再有意义
            hit.as_object_mut().map(|o| o.remove("confirmedAt"));
            return true;
        }
        owners.push(json!({
            "appId": app_id,
            "displayName": display_name,
            "publisher": publisher,
            "installLocation": install_location,
            "ownedPaths": owned_paths,
            "recordedAt": now_ms,
            "state": STATE_PENDING,
        }));
        true
    }

    /// 记/刷新某 owner 的**卸载前足迹基线**（HiBit §9.1 那条思路的落地位置）。
    ///
    /// 存的是卸载动作发生时 `HKCU\Software` / `HKLM\SOFTWARE` 下的厂商顶层键名集合。
    /// 卸载后复扫时，"清单里没了、但顶层多出一个厂商键且基线里没有"才是厂商自己写的配置键——
    /// 名称相似度那条路实测会把 `netease`（网易云音乐仍在装）这类共享厂商段误判成残留。
    ///
    /// `SCHEMA_VERSION` 刻意**不升**：这是纯增字段，老档案里没有 footprint 就当"没有基线"，
    /// 而升版本会触发 `load()` 的隔离重建，把用户本机已有的卸载记录一起丢掉。
    pub fn set_footprint(doc: &mut Value, app_id: &str, keys: &[String], now_ms: i64) -> bool {
        // 空基线一律不写：空集合不是"这台机器没有厂商键"，写成基线下一轮差分就会把
        // 全部现存键算成"卸载后才出现的新键"。调用方（uninstall_run）拿 false 去记日志。
        if keys.is_empty() {
            return false;
        }
        let Some(list) = doc.get_mut("owners").and_then(Value::as_array_mut) else {
            return false;
        };
        let Some(hit) = list.iter_mut().find(|o| {
            o.get("appId").and_then(Value::as_str) == Some(app_id)
        }) else {
            return false;
        };
        let capped = keys.len() > footprint::MAX_KEYS_PER_OWNER;
        let keep: Vec<String> = keys.iter().take(footprint::MAX_KEYS_PER_OWNER).cloned().collect();
        hit["footprint"] = json!({ "at": now_ms, "keys": keep, "capped": capped });
        true
    }

    /// 复扫：pending → historical、过期回收、重装的 historical 撤销。
    /// `install_exists` 注入探测（测试不碰盘）；返回 (升级为 historical 数, 移除数)。
    pub fn rescan(
        doc: &mut Value,
        current_app_ids: &HashSet<String>,
        now_ms: i64,
        install_exists: &dyn Fn(&Path) -> bool,
    ) -> (usize, usize) {
        let mut promoted = 0;
        let mut removed = 0;
        let owners = owners_of_mut(doc);
        owners.retain_mut(|o| {
            let app_id = o.get("appId").and_then(Value::as_str).unwrap_or("").to_string();
            let state = o.get("state").and_then(Value::as_str).unwrap_or("").to_string();
            let listed = current_app_ids.contains(&app_id);
            if state == STATE_HISTORICAL {
                if listed {
                    // 程序又回到清单 = 用户重装了它，这条"已卸载"事实不再成立
                    removed += 1;
                    return false;
                }
                return true;
            }
            if listed {
                return true; // 还在清单里：卸载没完成，继续 pending
            }
            let loc = o.get("installLocation").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let gone = loc.is_empty() || !install_exists(Path::new(&loc));
            if !gone {
                // 程序不在清单但安装目录还在：可能是卸载器半途退出，也可能是别的软件复用同目录。
                // 不升级、也不删事实，交给稳定期回收。
                return true;
            }
            let recorded = o.get("recordedAt").and_then(Value::as_i64).unwrap_or(now_ms);
            if now_ms - recorded > PENDING_TTL_MS {
                removed += 1;
                return false;
            }
            o["state"] = json!(STATE_HISTORICAL);
            o["confirmedAt"] = json!(now_ms);
            promoted += 1;
            true
        });
        // 上限裁剪：pending 有生命周期意义，优先裁最旧的 historical；
        // 全是 pending 仍超限时才动 pending（宁可丢历史也不无界增长）。
        let owners = owners_of_mut(doc);
        if owners.len() > MAX_RECORDS {
            let mut oldest_h: Option<(usize, i64)> = None;
            for (idx, o) in owners.iter().enumerate() {
                if o.get("state").and_then(Value::as_str) == Some(STATE_HISTORICAL) {
                    let at = o.get("confirmedAt").and_then(Value::as_i64).unwrap_or(0);
                    if oldest_h.map(|(_, c)| at < c).unwrap_or(true) {
                        oldest_h = Some((idx, at));
                    }
                }
            }
            if let Some((idx, _)) = oldest_h {
                owners.remove(idx);
            } else {
                owners.sort_by_key(|o| o.get("recordedAt").and_then(Value::as_i64).unwrap_or(0));
                while owners.len() > MAX_RECORDS {
                    owners.remove(0);
                }
            }
        }
        (promoted, removed)
    }

    /// 用户忽略某个 owner：移出 owners 并写进 ignored（按 appId 与归一化显示名双记，
    /// 因为同一款程序可能以不同 hive/子键再次出现在卸载清单里）。
    pub fn ignore(doc: &mut Value, app_id: &str, display_name: &str, now_ms: i64, name_norm: impl Fn(&str) -> String) {
        let name = name_norm(display_name);
        {
            let owners = owners_of_mut(doc);
            owners.retain(|o| o.get("appId").and_then(Value::as_str) != Some(app_id));
        }
        let list = doc["ignored"].as_array_mut().expect("ignored 必须是数组");
        if !list.iter().any(|i| i.get("appId").and_then(Value::as_str) == Some(app_id)) {
            list.push(json!({ "appId": app_id, "displayName": name, "addedAt": now_ms }));
        }
    }

    pub fn historical_owners(doc: &Value) -> Vec<Value> {
        doc.get("owners")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter(|o| o.get("state").and_then(Value::as_str) == Some(STATE_HISTORICAL)).cloned().collect())
            .unwrap_or_default()
    }
}

/// 应用数据遗留候选的判定与产出（C2-3）。
///
/// 三条硬约束，缺一条都不许出候选：
/// 1. **精确同名**（不是相似度）——目录末段归一后等于某 historical owner 的显示名或
///    其 installLocation 的 basename；
/// 2. **owner 唯一**——同一目录名被两个 historical owner 命中时无法判定归属，直接丢；
/// 3. **原安装目录必须 ENOENT**——还在就说明程序没卸完，不是应用数据遗留。
/// 另外再过三道环境闸：受保护路径、上级链重解析点（`dir_delete_blocked`）、
/// 运行中进程所在目录（与候选互为祖先或子孙即视为在用，正被使用的目录绝不提示删除）。
/// 产出默认只列**可弃子目录**（cache / logs 这类），且一律不勾选、置信度封顶 medium。
pub(super) const ORPHAN_DISPOSABLE_SUBDIRS: &[&str] = &[
    "cache", "caches", "code cache", "gpucache", "gpu cache", "logs", "log", "tmp", "temp",
];
/// 应用数据遗留扫描的目录根：与启发式目录命中同三个根，只扫一层（不递归，成本可控）
pub(super) const ORPHAN_SCAN_ROOTS: &[&str] = &["APPDATA", "LOCALAPPDATA", "PROGRAMDATA"];
pub(super) const ORPHAN_MAX_CANDIDATES: usize = 40;

/// 当前全系统进程的可执行路径（小写全路径），用于「候选目录是否在运行进程祖先链上」。
/// 拿不到就返回空集 —— 但这条判定是**保护用户**的，取不到时按「全部拒绝出候选」处理更稳妥，
/// 所以调用方用 Option：None = 取不到快照，直接不产出该组候选。
pub(super) fn running_process_dirs() -> Option<HashSet<String>> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut out = HashSet::new();
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pe.th32ProcessID).ok();
                if let Some(h) = h {
                    let mut buf: Vec<u16> = vec![0; 1024];
                    let mut len: u32 = buf.len() as u32;
                    let name = QueryFullProcessImageNameW(
                        h,
                        PROCESS_NAME_FORMAT(0),
                        windows::core::PWSTR(buf.as_mut_ptr()),
                        &mut len,
                    )
                    .map(|_| String::from_utf16_lossy(&buf[..len as usize]));
                    let _ = windows::Win32::Foundation::CloseHandle(h);
                    if let Ok(p) = name {
                        if let Some(parent) = Path::new(&p).parent() {
                            out.insert(parent.to_string_lossy().to_ascii_lowercase());
                        }
                    }
                }
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = snap;
        Some(out)
    }
}

/// 卸载前足迹基线的判据（HiBit §9.1「轻量安装监视」落到本应用能承受的形态）。
///
/// HiBit 在安装前记基线、安装后差分；本应用没有安装钩子，能拿到的同价证据是
/// **卸载动作那一刻**的顶层厂商键集合：卸载后程序不在了、清单里没有它、安装目录也没了，
/// 而某个厂商键是卸载前不存在、卸载后才出现的——那就是它自己写、卸载器不认的登记。
/// 名称相似度那条路实测不可用（本机 `NeteaseGodLike` 与仍在装的网易云音乐共享 `Netease` 段）。
pub(super) mod footprint {
    use serde_json::Value;
    use std::collections::HashSet;

    /// 一条基线保留的顶层键上限（本机实测三根共 135 个名字，留一倍余量）。
    pub const MAX_KEYS_PER_OWNER: usize = 300;
    /// 单次扫描最多产出的厂商键候选，防止某台机器上出现异常膨胀。
    pub const MAX_CANDIDATES: usize = 40;

    /// 结构性容器：这些顶层键不是任何第三方程序的落点，出现在差集里也只可能是系统或
    /// 别的软件在这两次读之间动过手。判"残留"不值得为它们打扰用户。
    const DENY_ROOTS: &[&str] = &[
        "microsoft",
        "classes",
        "clients",
        "policies",
        "registeredapplications",
        "wow6432node",
        "khronos",
        "odbc",
        "oem",
        "setup",
        "volatile",
        "defaultuserenvironment",
        "appdatalow",
        "deviceinfo",
        "changetracker",
        "contextmenumgr",
        "roamingdevice",
        "capabilities",
    ];

    /// 顶层键名是否可能是某个程序的厂商键。
    ///
    /// GUID 形态（`14d8c5cd-3d3a-…`）在本机是 WebView2/Chromium 组件键，且系统随时可能新增，
    /// 一并挡掉：宁可漏一条厂商残留，不要把系统键列成"可删的残留"。
    pub fn is_vendor_key(name: &str) -> bool {
        let n = name.trim().to_ascii_lowercase();
        if n.chars().count() < 2 {
            return false;
        }
        if DENY_ROOTS.iter().any(|d| n.starts_with(d)) {
            return false;
        }
        let guid_shape = n.len() == 36
            && n.matches('-').count() == 4
            && n.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        !guid_shape
    }

    /// 卸载后才新出现的厂商键（大小写不敏感差集，顺序跟"当前"读到的顺序）。
    pub fn new_keys_since(baseline: &[String], current: &[String]) -> Vec<String> {
        let seen: HashSet<String> = baseline.iter().map(|k| k.to_ascii_lowercase()).collect();
        current
            .iter()
            .filter(|k| !seen.contains(&k.to_ascii_lowercase()))
            .cloned()
            .collect()
    }

    /// 归属判定用的 token：显示名、发布商、安装目录末段里能取到的短词。
    ///
    /// 只做**互含**、不做相似度：足迹差分已经证明"这键是卸完才出现的"，token 只回答
    /// "它是不是这个程序写的"；再加上模糊匹配就等于把猜测请回删除依据里（C3 同一口径）。
    pub fn tokens_of(owner: &Value) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut add = |raw: &str| {
            let s = raw.trim().to_ascii_lowercase();
            if s.chars().count() >= 2 && !out.contains(&s) {
                out.push(s);
            }
        };
        for field in ["displayName", "publisher"] {
            if let Some(v) = owner.get(field).and_then(Value::as_str) {
                add(v);
            }
        }
        if let Some(loc) = owner.get("installLocation").and_then(Value::as_str) {
            if let Some(base) = loc.trim().trim_end_matches(['\\', '/']).rsplit('\\').next() {
                add(base);
            }
        }
        if let Some(paths) = owner.get("ownedPaths").and_then(Value::as_array) {
            for p in paths.iter().filter_map(Value::as_str) {
                if let Some(base) = p.trim().trim_end_matches(['\\', '/']).rsplit('\\').next() {
                    add(base);
                }
            }
        }
        out
    }

    /// 键的末段是否与某程序的 token 互含（两侧都小写）。
    pub fn key_belongs_to(key: &str, tokens: &[String]) -> bool {
        let leaf = key.rsplit('\\').next().unwrap_or("").to_ascii_lowercase();
        if leaf.chars().count() < 2 {
            return false;
        }
        tokens.iter().any(|t| {
            t.chars().count() >= 2 && (leaf.contains(t.as_str()) || t.contains(leaf.as_str()))
        })
    }

    /// 从 owner 记录里取基线。**缺字段或被截断（capped）都当"没有可信基线"**：
    /// 基线不全时差集会把本来早就存在的键算成新键，那是把老键当残留删，代价不可接受。
    pub fn baseline_of(owner: &Value) -> Option<Vec<String>> {
        let fp = owner.get("footprint")?;
        if fp.get("capped").and_then(Value::as_bool).unwrap_or(true) {
            return None;
        }
        let keys = fp.get("keys").and_then(Value::as_array)?;
        Some(
            keys.iter()
                .filter_map(|k| k.as_str().map(String::from))
                .collect(),
        )
    }
}

/// 本机学习型残留库（HiBit §H3 借鉴项，2026-09-29）。
///
/// HiBit 的 `LocalDB.ini` 是「出厂内置 + 用户增量」两层：exe 里嵌一份出厂默认，
/// AppData 那份随使用增长。Trim 只有前者（`uninstall-residue-rules.json`：人工评审 +
/// 签名 + `prov.reviewedAt` 溯源），缺的就是第二层——同一台机器上卸载过一次的程序，
/// 下次再装再卸仍然要从头启发。本模块补那半层。
///
/// **schema 与签名库逐字段相同，因此运行期复用同一个 `validate_residue_package`**。
/// 这不是偷懒，是这批唯一的安全支点：学习库不签名、由本机自采，若给它一套自己的校验器，
/// 就等于开了「绕过人审与私钥也能进候选」的旁路——M1 批次封的正是同类洞
/// （一条签名规则 `reg_key: HKLM\SOFTWARE` 当时能过所有闸门并被默认勾选）。
/// 复用同一校验器 ⇒ 字段白名单、kind 允许集、目标形状、深度上限、双条件组、注册表禁删面
/// 一个都不少。代价是学不到 `learnedAt`/命中次数这类元数据（白名单不放）——
/// 淘汰改用「数组顺序即新旧」，不值得为一条统计字段把校验器分叉。
///
/// 与签名库不同的三处刻意收紧（因为证据等级更低）：
/// 1. `defaultChecked = false`、`confidence` 上限 `medium`（与 M4/M6 对本机自推候选的裁定一致）；
/// 2. 目标必须**可按归属核对**——路径里至少有一段与该程序的显示名/发行商/卸载键末段互含，
///    沿用 `footprint` 那条口径（只做互含、不做相似度）。没有归属判据时，
///    `%APPDATA%\Microsoft\Windows\Recent` 这类共享容器会被当成"这程序的残留"学进去；
/// 3. 注册表目标额外要求 hive 之下 ≥3 段（`HKCU\Software\Foo` 这种厂商顶层键不学）——
///    本机实测过共享厂商段误判（`Netease` 同时被网易云音乐命中）。
pub(super) mod learned {
    use serde_json::{json, Value};
    use std::path::Path;

    use super::{footprint, norm_name, parse_reg_target, protect, validate_residue_package};

    /// 学习库条数上限：一台机器不会装几百个待卸载程序，超了按新旧淘汰
    pub const MAX_RULES: usize = 120;
    /// 单程序记录的落点数上限（有些程序散落十几个目录，记满只会淹没面板）
    pub const MAX_RESIDUE_PER_RULE: usize = 16;
    /// 注册表学习深度下限：hive 之下至少三段。`HKCU\Software\Foo` 是厂商顶层键，
    /// 一个键名下可能住着全家桶，不给进学习库
    pub const REG_MIN_DEPTH: usize = 3;

    pub const LEARNED_SOURCE_CLASS: &str = "本机自采（未签名、未经人工评审）";

    fn file_write() -> std::path::PathBuf {
        super::residue_rules_write_dir().join("residue-learned.json")
    }

    /// 读取根：与规则库同一口径（新根优先，老根只读兜底）
    fn file_read() -> std::path::PathBuf {
        crate::engine::paths::data_file_for_read("uninstall/residue-learned.json")
    }

    pub fn empty_doc() -> Value {
        json!({
            "rulesVersion": 1.0,
            "prov": [{ "sourceClass": LEARNED_SOURCE_CLASS, "reviewedAt": "" }],
            "rules": []
        })
    }

    /// 纯函数：解析 + 复用签名库校验器。**任何一步失败都返回 Err**，由调用方决定隔离。
    /// 刻意不碰文件——这份数据驱动删除候选，测试里留写盘副作用会把用户本机档案判坏。
    pub fn from_text(text: &str) -> Result<Value, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("JSON 解析失败: {e}"))?;
        validate_residue_package(&v).map_err(|e| format!("学习库语义校验未通过: {e}"))?;
        Ok(v)
    }

    /// 载入。文件缺失 = 空（首次使用）；解析或语义不过 = 隔离后回空档。
    ///
    /// 与 `ownership::load` 同一立场：驱动删除候选的数据在半损坏状态下必须**停用**，
    /// 而不是尽力解析——「猜出来的残留」比「这一轮没提示」危险得多。
    pub fn load() -> Option<Value> {
        let path = file_read();
        let Ok(text) = std::fs::read_to_string(&path) else {
            return None;
        };
        match from_text(&text) {
            Ok(v) => Some(v),
            Err(reason) => {
                crate::engine::log::write_log("warn", &format!("{reason}，学习库已隔离停用: {:?}", path.file_name()));
                crate::security::quarantine_file(&path, "residue-learned 语义校验未通过");
                None
            }
        }
    }

    /// 落盘前先自校验：写入侧不把一份「装载时会被隔离」的文件留给下一轮扫描。
    /// 两头都判才是闭环——只判读侧的话，本函数的一个 bug 会直接毁掉用户本机全部学习记录。
    pub fn save(doc: &Value) -> Result<(), String> {
        validate_residue_package(doc).map_err(|e| format!("学习库落盘前校验未通过（已放弃写入）: {e}"))?;
        let path = file_write();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("创建学习库目录失败: {e}"))?;
        }
        crate::security::atomic_write_json(&path, doc).map_err(|e| e.to_string())
    }

    /// 学习库规则的稳定 id：`learned-` + (归一化程序名 + 卸载键末段) 的 sha256 前 12 位。
    /// 必须是纯 [a-z0-9-] —— 签名库校验器对 id 字符集有白名单，中文程序名不能直接当 id。
    pub fn rule_id(display_name: &str, key_path: &str) -> String {
        use sha2::{Digest as _, Sha256};
        let leaf = key_path.rsplit('\\').next().unwrap_or("").to_lowercase();
        let base = format!("{}|{}", norm_name(display_name), leaf);
        let hex: String = Sha256::digest(base.as_bytes())
            .iter()
            .take(6)
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("learned-{hex}")
    }

    /// 目标是否值得学。返回 `Some(原因)` = 拒学（不写进库，下一轮也不会再出这条候选）。
    ///
    /// 判据顺序有讲究：先看保护面（最硬），再看归属（学习库特有），最后看深度。
    /// 归属这一步是学习库与签名库的实质差别：签名库是人写「这个程序确实有这目录」，
    /// 学习库没人审，只能靠路径里有没有这程序的名字来自己交代。
    pub fn target_reject_reason(kind: &str, target: &str, tokens: &[String]) -> Option<String> {
        if target.trim().is_empty() || target.len() > 260 {
            return Some("目标为空或超过 MAX_PATH".to_string());
        }
        match kind {
            "reg_key" => {
                if let Some(r) = protect::reg_target_block_reason(target) {
                    return Some(format!("注册表禁删面: {r}"));
                }
                let Some((_, rest)) = parse_reg_target(target) else {
                    return Some("注册表目标无法解析".to_string());
                };
                let depth = rest.split('\\').filter(|s| !s.trim().is_empty()).count();
                if depth < REG_MIN_DEPTH {
                    return Some(format!("注册表深度 {depth} 低于下限 {REG_MIN_DEPTH}（厂商顶层键不学）"));
                }
            }
            "folder" | "file" => {
                if protect::is_path_protected(target) {
                    return Some("受保护路径".to_string());
                }
                let p = Path::new(target);
                // 盘根/父根一律不学：一旦学错，下一轮是整棵目录树进候选
                if p.parent().map(|x| x.parent().is_none()).unwrap_or(true) {
                    return Some("路径层级过浅".to_string());
                }
            }
            other => return Some(format!("不支持学习的 kind: {other}")),
        }
        // 归属核对：任一段与该程序 token 互含（与 footprint 同口径，不做相似度）
        let segs: Vec<String> = target
            .split(['\\', '/'])
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| s.chars().count() >= 2)
            .collect();
        if segs.is_empty() {
            return Some("路径没有可比对的段".to_string());
        }
        let owned = tokens.iter().any(|t| {
            let tl = t.trim().to_ascii_lowercase();
            tl.chars().count() >= 2 && segs.iter().any(|s| s.contains(&tl) || tl.contains(s.as_str()))
        });
        if !owned {
            return Some("路径里没有任何一段属于这程序（共享容器不学）".to_string());
        }
        None
    }

    /// 把「用户实际删掉的落点」并入库。返回新增条数。
    ///
    /// 三组条件必须同时给得出（`displayName` + `uninstallKey` 至少两组非空是签名库的
    /// U-1 口径，校验器会整包拒），拿不到归属身份就不学——宁可这条不沉淀。
    pub fn learn(
        doc: &mut Value,
        display_name: &str,
        publisher: &str,
        key_path: &str,
        entries: &[(&str, String)],
        now_ms: i64,
    ) -> usize {
        if entries.is_empty() || display_name.trim().is_empty() || key_path.trim().is_empty() {
            return 0;
        }
        // 归属 token 只能来自**程序身份**（显示名 / 发行商 / 卸载键末段）。刻意不喂 ownedPaths：
        // 那等于把候选路径自己的末段当成「属于这程序」的证据，任何目标都会命中自己，
        // 归属判定当场失效（写第一版时就踩在这里，被单测抓出来）。
        let key_leaf = key_path.rsplit('\\').next().unwrap_or(key_path).to_string();
        // 归属 token 只能来自**程序身份**（显示名 / 发行商 / 卸载键末段）。刻意不喂 ownedPaths：
        // 那等于把候选路径自己的末段当成「属于这程序」的证据，任何目标都会命中自己，
        // 归属判定当场失效（写第一版时踩在这里，判红自测已把这条缺陷装回去验证过会被抓到）。
        let tokens = footprint::tokens_of(&json!({
            "displayName": display_name,
            "publisher": publisher,
            "installLocation": format!("C:\\x\\{key_leaf}"),
        }));
        let id = rule_id(display_name, key_path);
        // 只留 kind 与目标形状都合规的落点
        let keep: Vec<(&str, String)> = entries
            .iter()
            .filter(|(k, t)| target_reject_reason(k, t, &tokens).is_none())
            .cloned()
            .collect();
        if keep.is_empty() {
            return 0;
        }
        // 先取库版本再可变借用 rules：条目级 ver 必须等于顶层 rulesVersion（V2 P2-A1）
        let doc_ver = doc
            .get("rulesVersion")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let Some(rules) = doc.get_mut("rules").and_then(Value::as_array_mut) else {
            return 0;
        };
        let stamp = super::delete_manifest::iso_now();
        let mut added = 0usize;
        let hit = rules.iter_mut().find(|r| r.get("id").and_then(Value::as_str) == Some(id.as_str()));
        match hit {
            Some(r) => {
                let Some(list) = r.get_mut("residue").and_then(Value::as_array_mut) else {
                    return 0;
                };
                for (k, t) in keep {
                    let dup = list.iter().any(|e| {
                        e.get("kind").and_then(Value::as_str) == Some(k)
                            && e.get("target").and_then(Value::as_str)
                                .map(|x| x.eq_ignore_ascii_case(&t))
                                .unwrap_or(false)
                    });
                    if dup {
                        continue;
                    }
                    list.push(json!({ "kind": k, "target": t, "note": learn_note(display_name, &stamp) }));
                    added += 1;
                }
                // 单程序上限按「先记的先出」裁，与整库淘汰同一策略，不引入时间戳字段
                while list.len() > MAX_RESIDUE_PER_RULE {
                    list.remove(0);
                }
            }
            None => {
                let residue: Vec<Value> = keep
                    .iter()
                    .map(|(k, t)| json!({ "kind": *k, "target": t.clone(), "note": learn_note(display_name, &stamp) }))
                    .collect();
                let mut pubarr: Vec<Value> = Vec::new();
                if !publisher.trim().is_empty() {
                    pubarr.push(json!(publisher.trim()));
                }
                // 条目级版本戳跟随本库这一版（V2 P2-A1 同口径）：学习库的 rulesVersion 固定 1.0，
                // 但签名库校验器要求每条都带着它，缺一条就整包拒 —— 这里不补就等于
                // 「学出来的规则永远装不回去」
                rules.push(json!({
                    "id": id,
                    "ver": doc_ver,
                    "displayName": [display_name.trim()],
                    "publisher": pubarr,
                    "uninstallKey": [key_leaf],
                    "residue": residue,
                }));
                added = residue.len();
                while rules.len() > MAX_RULES {
                    rules.remove(0);
                }
            }
        }
        // prov.reviewedAt 用「最近一次学习」当时间戳：校验器要求它非空且是字符串，
        // 而学习库没有人工评审事件可登记，如实写成本机自采时间比留个假评审日期诚实
        if let Some(prov) = doc.get_mut("prov").and_then(Value::as_array_mut) {
            prov.insert(
                0,
                json!({ "sourceClass": LEARNED_SOURCE_CLASS, "reviewedAt": format!("本机自采 {stamp}") }),
            );
            prov.truncate(1);
        }
        let _ = now_ms;
        added
    }

    fn learn_note(name: &str, stamp: &str) -> String {
        // v2-L4P-15：上限走 residue_contract()（真源 rule-schema.json），不再引用本文件常量
        let max_text = super::residue_contract().max_text_len;
        let mut s = format!("本机于 {stamp} 清理「{name}」时删掉的落点");
        if s.chars().count() > max_text {
            s = s.chars().take(max_text).collect();
        }
        s
    }
}

/// 候选目录是否与某个运行中进程的可执行路径在同一条链上。
/// **两个方向都要查**：候选是进程目录的祖先（端掉父目录会带走正在跑的程序）
/// 或候选就在进程目录里面（正被使用的子目录）——只查一边会漏掉另一半（Y5 实测）。
pub(super) fn under_running_process(dir: &Path, procs: &HashSet<String>) -> bool {
    let cand = dir.to_string_lossy().to_ascii_lowercase();
    procs.iter().any(|p| path_within(p, &cand) || path_within(&cand, p))
}

/// `inner` 是否等于 `outer` 或位于其目录树内。**按路径段**比，不按裸前缀比：
/// `C:\Foo\bar` 与 `C:\Foobar` 都不算在 `C:\Foo` 里面，否则同级兄弟目录会被误判成在用。
pub(super) fn path_within(inner: &str, outer: &str) -> bool {
    let i = inner.trim_end_matches(['\\', '/']);
    let o = outer.trim_end_matches(['\\', '/']);
    i == o || (i.starts_with(o) && matches!(i.as_bytes().get(o.len()), Some(b'\\') | Some(b'/')))
}

/// uninstall:orphan-scan — 卸载遗留扫描（应用数据目录 + 卸载后新增的厂商配置键；
/// 主窗档，只产候选，删除仍走 residue-execute）
#[tauri::command]
pub async fn uninstall_orphan_scan<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let res = tauri::async_runtime::spawn_blocking(move || unsafe {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        let now = crate::engine::now_ms();
        let mut doc = ownership::load();
        // ① 所有权档案为空 → 能力没被喂过事实，直接拒绝而不是伪装「没有应用数据遗留」
        if doc
            .get("owners")
            .and_then(Value::as_array)
            .map(|a| a.is_empty())
            .unwrap_or(true)
        {
            return (
                Vec::new(),
                "还没有卸载记录：应用数据遗留判定要靠「本机确实卸载过某程序」这条事实链，先卸载一次再来扫描".to_string(),
            );
        }
        // ② 复扫当前程序清单（获取失败必须拒扫，不能拿空清单把所有 pending 都升级成 historical）
        let mut current: Vec<Value> = Vec::new();
        for (hive, sub) in [
            (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ] {
            let rows = enum_uninstall_root(hive, sub);
            if rows.is_empty() && sub.contains("WOW6432Node") {
                continue; // 32 位视图在本机可能不存在，不算失败
            }
            if rows.is_empty() && sub.contains("Software\\Microsoft") && !sub.starts_with("SOFTWARE") {
                // HKCU 下没有用户级安装项是常见形态，同样不算取数失败
                continue;
            }
            current.extend(rows);
        }
        if current.is_empty() {
            return (Vec::new(), "当前程序清单获取失败，本次不做应用数据遗留判定（拿空清单去比对会把所有记录误判成已卸载）".to_string());
        }
        let ids: HashSet<String> = current
            .iter()
            .filter_map(|a| a.get("id").and_then(Value::as_str).map(String::from))
            .collect();
        // ③ pending → historical、过期回收、重装撤销（就地改档并落盘）
        let (promoted, removed) = ownership::rescan(&mut doc, &ids, now, &|p: &Path| p.exists());
        if promoted > 0 || removed > 0 {
            if let Err(e) = ownership::save(&doc) {
                crate::engine::log::write_log("warn", &format!("所有权历史写回失败: {e}"));
            }
        }
        // ④ 运行进程祖先链：取不到快照就不产出候选（这条是保护用户的判定，宁可不出）
        let Some(procs) = running_process_dirs() else {
            return (Vec::new(), "进程快照获取失败，本次不做应用数据遗留判定（无法确认候选目录是否正在被使用）".to_string());
        };
        // historical owner 的精确名 → owner 列表（同名多 owner 时用于「唯一归属」判定）
        let mut by_name: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();
        for o in ownership::historical_owners(&doc) {
            let mut keys: Vec<String> = Vec::new();
            if let Some(n) = o.get("displayName").and_then(Value::as_str) {
                let nn = norm_name(n);
                if nn.chars().count() >= NAME_MIN_EXACT {
                    keys.push(nn);
                }
            }
            if let Some(loc) = o.get("installLocation").and_then(Value::as_str) {
                if let Some(base) = loc.trim().trim_end_matches(['\\', '/']).rsplit('\\').next() {
                    let bn = norm_name(base);
                    if bn.chars().count() >= NAME_MIN_EXACT {
                        keys.push(bn);
                    }
                }
            }
            for k in keys {
                by_name.entry(k).or_default().push(o.clone());
            }
        }
        if by_name.is_empty() {
            return (Vec::new(), "还没有已确认卸载完成的程序（pending 尚未满足升级条件）".to_string());
        }

        let mut findings: Vec<Value> = Vec::new();
        for root in ORPHAN_SCAN_ROOTS {
            let Ok(base_raw) = std::env::var(root) else { continue };
            let Ok(rd) = std::fs::read_dir(&base_raw) else { continue };
            for ent in rd.flatten() {
                let dir = ent.path();
                if !dir.is_dir() {
                    continue;
                }
                let dname = norm_name(&ent.file_name().to_string_lossy());
                if dname.chars().count() < NAME_MIN_EXACT {
                    continue;
                }
                let Some(owners) = by_name.get(&dname) else { continue };
                // ⑤ 归属唯一：两个 historical owner 精确同名时无法判定这个目录归谁
                if owners.len() != 1 {
                    continue;
                }
                let owner = &owners[0];
                let owner_name = owner.get("displayName").and_then(Value::as_str).unwrap_or("").to_string();
                // ⑥ 原安装目录必须已不存在
                if let Some(loc) = owner.get("installLocation").and_then(Value::as_str) {
                    if !loc.trim().is_empty() && Path::new(loc.trim()).exists() {
                        continue;
                    }
                }
                let shown = dir.to_string_lossy().to_string();
                if protect::is_path_protected(&shown) || under_running_process(&dir, &procs) {
                    continue;
                }
                if let Some(reason) = crate::engine::native::dir_delete_blocked(&dir) {
                    crate::engine::log::write_log("info", &format!("应用数据遗留候选跳过 {shown}: {reason}"));
                    continue;
                }
                // ⑦ 默认只列可弃子目录，不端整个 profile
                let Ok(sub_rd) = std::fs::read_dir(&dir) else { continue };
                for sub in sub_rd.flatten() {
                    if !sub.path().is_dir() {
                        continue;
                    }
                    let sub_norm = norm_name(&sub.file_name().to_string_lossy());
                    if !ORPHAN_DISPOSABLE_SUBDIRS.contains(&sub_norm.as_str()) {
                        continue;
                    }
                    let sub_path = sub.path().to_string_lossy().to_string();
                    if protect::is_path_protected(&sub_path)
                        || under_running_process(&sub.path(), &procs)
                        || crate::engine::native::dir_delete_blocked(&sub.path()).is_some()
                    {
                        continue;
                    }
                    let why = contribs(&[
                        ("ownerUninstalled", format!(
                            "卸载记录「{owner_name}」已复扫确认：程序不在当前清单，且原安装目录已不存在",
                        )),
                        ("disposableSubdir", format!(
                            "子目录「{sub_norm}」属于可弃类别（cache / logs 一类），不是用户资料",
                        )),
                        ("envGates", "已通过保护路径、目录重解析点、运行进程同链三道环境闸".to_string()),
                    ]);
                    findings.push(json!({
                        "kind": "folder",
                        "target": sub_path,
                        "reason": format!("「{owner_name}」已确认卸载完成，其遗留可弃目录（所有权判定，不自动勾选）"),
                        "confidence": "medium",
                        "risk": "medium",
                        "defaultChecked": false,
                        "origin": "orphan",
                        "ownerName": owner_name,
                        // 忽略操作要按 owner 的卸载键寻址，前端从这字段取
                        "ownerAppId": owner.get("appId").and_then(Value::as_str).unwrap_or(""),
                        // C4：所有权链的证据是「一条闭合推理」，不写出来用户只能选择信或不信。
                        "contribs": why,
                    }));
                    if findings.len() >= ORPHAN_MAX_CANDIDATES {
                        break;
                    }
                }
            }
        }
        // ⑥ 厂商配置键足迹差分（HiBit §9.1 的落地形态）：卸载前基线里没有、现在出现、
        //    且键名对得上这个程序 token 的顶层键。三条同时成立才入候选——差集给**时序**证据，
        //    token 给**归属**证据；只靠名字猜会把仍在装的别家程序键端出来（本机 `Netease` 段实测）。
        //    这一类不成立时只跳过、不报错：目录候选已经产出，而收口前建的档案本来就没有基线字段。
        let vendor_now = collect_vendor_keys();
        let mut vendor_added = 0usize;
        if vendor_now.is_empty() {
            crate::engine::log::write_log(
                "warn",
                "厂商键足迹差分跳过：三个 Software 根都枚举不到（拿空清单差分等于凭空造候选）",
            );
        } else {
            for o in ownership::historical_owners(&doc) {
                let Some(base) = footprint::baseline_of(&o) else { continue };
                let tokens = footprint::tokens_of(&o);
                if tokens.is_empty() {
                    continue;
                }
                let owner_name = o.get("displayName").and_then(Value::as_str).unwrap_or("").to_string();
                let owner_app_id = o.get("appId").and_then(Value::as_str).unwrap_or("").to_string();
                for target in footprint::new_keys_since(&base, &vendor_now) {
                    if !footprint::key_belongs_to(&target, &tokens) {
                        continue;
                    }
                    if findings.len() >= ORPHAN_MAX_CANDIDATES || vendor_added >= footprint::MAX_CANDIDATES {
                        break;
                    }
                    // 与规则库链同一道硬闸：落在注册表禁删面的目标连原因都不给过（A1）
                    if let Some(reason) = protect::reg_target_block_reason(&target) {
                        crate::engine::log::write_log(
                            "warn",
                            &format!("厂商键足迹候选被硬否决（不入候选）: {target} — {reason}"),
                        );
                        continue;
                    }
                    let Some((hive, rest)) = parse_reg_target(&target) else { continue };
                    if !crate::engine::native::reg_key_exists(hive, &rest) {
                        continue; // 差分到候选之间键消失了：不列一条已经不存在的东西
                    }
                    vendor_added += 1;
                    let why = contribs(&[
                        (
                            "footprintBaseline",
                            format!("卸载动作发生前记下的 {} 个厂商顶层键里没有它", base.len()),
                        ),
                        (
                            "appearedAfterUninstall",
                            "本次复扫它仍存在，而该程序的卸载登记与原安装目录都已消失".to_string(),
                        ),
                        (
                            "ownerToken",
                            format!("键名与这程序的显示名/发行商/安装目录名互含：{}", tokens.join("、")),
                        ),
                    ]);
                    findings.push(json!({
                        "kind": "reg_key",
                        "target": target,
                        "reason": format!("「{owner_name}」卸载后新出现的厂商配置键（卸载前基线里没有，不自动勾选）"),
                        "confidence": "medium",
                        "risk": "medium",
                        "defaultChecked": false,
                        "origin": "orphan",
                        "ownerName": owner_name,
                        "ownerAppId": owner_app_id,
                        "contribs": why,
                    }));
                }
            }
        }
        (findings, String::new())
    })
    .await;
    match res {
        Ok((findings, note)) => {
            if !note.is_empty() {
                return json!({ "success": false, "message": note });
            }
            // 落进与本会话残留扫描同一个快照槽：执行侧的快照闸、A1 硬否决、
            // 目录重解析校验、回收站优先一律复用，不给应用数据遗留候选开第二条删除通道
            residue_snapshot_put(&label, "orphan", findings.clone());
            json!({ "success": true, "data": { "appName": "卸载遗留（应用数据与厂商配置键）", "findings": findings } })
        }
        Err(e) => json!({ "success": false, "message": format!("应用数据遗留扫描异常: {e}") }),
    }
}

/// uninstall:orphan-ignore — 用户判定某个历史 owner 不再提示（主窗档）
#[tauri::command]
pub async fn uninstall_orphan_ignore<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    app_id: String,
    display_name: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let Some((hive_str, key_path)) = app_id.split_once('|') else {
        return json!({ "success": false, "message": "app_id 格式错误" });
    };
    if !(hive_str.eq_ignore_ascii_case("HKCU") || hive_str.eq_ignore_ascii_case("HKLM")) {
        return json!({ "success": false, "message": "app_id hive 只支持 HKCU/HKLM" });
    }
    if !valid_uninstall_key_path(key_path) {
        return json!({ "success": false, "message": "app_id 不是合法的卸载键路径" });
    }
    let mut doc = ownership::load();
    ownership::ignore(&mut doc, &app_id, &display_name, crate::engine::now_ms(), |s| norm_name(s));
    match ownership::save(&doc) {
        Ok(()) => {
            log::write_log("info", &format!("应用数据遗留判定已忽略历史 owner: {display_name}（{app_id}）"));
            json!({ "success": true, "data": { "message": format!("已不再提示「{display_name}」的遗留数据") } })
        }
        Err(e) => json!({ "success": false, "message": format!("忽略记录写入失败: {e}") }),
    }
}

