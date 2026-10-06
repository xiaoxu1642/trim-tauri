//! 残留链的内部支撑件：本机学习库（`learned`）+ 厂商键判据（`footprint`）+ 运行进程目录快照。
//!
//! 原 `ownership`（卸载所有权档案状态机）与 `uninstall:orphan-scan` / `uninstall:orphan-ignore`
//! 已随「机-wide 扫描整条退役」删除。仍然保留的三件各有在用的消费者：
//! - `learned`：`residue.rs` 的残留执行链在删完一项后把落点沉淀进本机学习库、下轮扫描再命中；
//! - `footprint`：`vendor_registry.rs`（保留为内部代码的深扫器）复用它的 `is_vendor_key` /
//!   `MAX_KEYS_PER_OWNER`，`learned` 复用它的 `tokens_of`；
//! - `running_process_dirs`：保留为内部工具（当前无生产调用方，见其上的 `allow(dead_code)`）。
//!
//! 只读判定 + 台账写入，不删任何用户文件。

use crate::engine::{delete_manifest, protect};
use std::collections::HashSet;
use std::path::Path;
use super::helpers::*;
use super::residue::*;
use super::residue_update::*;

/// 当前全系统进程的可执行路径的父目录（小写全路径）。
/// 保留为内部工具：原「应用数据遗留」链用它判候选目录是否正在被使用，那条链已退役。
/// 拿不到就返回 None —— 这条判定是**保护用户**的，取不到时按「全部拒绝出候选」处理更稳妥。
#[allow(dead_code)] // 随孤儿扫描退役后暂无生产调用方；保留以备后续内部判定复用（AGENTS §4 零警告线）
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

/// 卸载前足迹（厂商键）基线的**判据**模块。
///
/// HiBit §9.1 对照：卸载前拍一次厂商键集合，之后对比找「卸载后新增」的键。原「应用数据遗留」
/// 链（`uninstall:orphan-scan`）已退役，但本模块仍有在用消费者：`vendor_registry.rs` 复用
/// `is_vendor_key` / `MAX_KEYS_PER_OWNER` 的键名判据，`learned` 复用 `tokens_of` 的归属判据。
/// 判据只做**互含**、不做相似度：足迹差分给时序证据，token 只回答「它是不是这个程序写的」；
/// 再加上模糊匹配就等于把猜测请回删除依据里。
pub(super) mod footprint {
    use serde_json::Value;

    /// 一条基线保留的顶层键上限（本机实测三根共 135 个名字，留一倍余量）。
    pub const MAX_KEYS_PER_OWNER: usize = 300;

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

    /// 归属判定用的 token：显示名、发布商、安装目录末段里能取到的短词。
    ///
    /// 只做**互含**、不做相似度（C3 同一口径）。`learned` 用它判「这条落点是不是属于这程序」。
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
    /// 立场与本域「驱动删除候选的数据在半损坏状态下必须**停用**」一致：
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
