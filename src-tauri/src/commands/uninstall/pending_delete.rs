//! P1-B3 重启后删：PFRO 队列读取 + pending list/revoke。
//!
//! pending.xml 的形状与 PendingFileRenameOperations 的写法是重启后语义的一部分，
//! 改动等于改系统行为；本域现在只**读**系统队列与台账、并为「撤回」摘除本账条目，
//! 不再登记任何新的删除。
//!
//! 2026-11-02 用户裁定：「登记到重启后删除」的注册入口全应用退役（命令
//! `uninstall_pending_add` 与两窗的登记 UI 同撤），**保留**待删清单的查看与撤回。
//! 退役理由：登记面是 PFRO 这条永久删出口的唯一写侧，而清理失败引导已能通过
//! 「重启资源管理器并重试」覆盖同一场景；少一条写永久删队列的入口，就少一处
//! 「只收删除失败项」这类准入约束需要长期维护的地方。
//!
//! v6-K06（P0-4）：本域的并发口径。PFRO 是**系统级全局队列**（HKLM，安装器与 OS
//! 自己也往里写——本机实测 4 对第三方 `*1\??\` 形态条目），因此：
//!   · 撤回的整次命令（PFRO 读-改-写 + 台账写）在 `PENDING_DELETE_LOCK` 域锁内；
//!   · 对系统队列的任何改写都**写前重读**（`pfro_remove_deletes`），只摘本账目标的
//!     整对，第三方条目原样保留——旧整值覆写会抹掉读入之后他人追加的条目
//!     （重启照删却撤不回）。

use crate::engine::{guard, log};
use crate::security;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;
use tauri::WebviewWindow;
use super::helpers::*;
// ==================== P1-B3 重启后删（2026-10-01 拍板；2026-11-02 收窄为查看/撤回） ====================
// 历史沿革：回收站失败的「文件」项曾可降级为「重启后删除」——MoveFileEx(DELAY_UNTIL_REBOOT)
// 写进系统 PendingFileRenameOperations（PFRO），下次重启由会话管理器删除。该注册入口
// 已于 2026-11-02 用户裁定全应用退役（见文件头）；系统队列里既有的条目与台账凭据仍要
// 「可见、可撤回」，故本模块保留读侧与撤回侧。
//
// 保留的两条硬约束（缺一不可）：
//   · 可撤回：台账里每条登记都能在重启前把 PFRO 对应条目摘掉（重启后系统已消费则失效）；
//   · 待删清单可见：pending_list 把「还挂着 / 已被重启消费 / 文件已不在」三种状态分清。
// 这类条目是**永久删除**（不进回收站），与 AGENTS §3 回收站优先的红线冲突，属 2026-10-01
// 显式拍板的受控例外（类比 v3.3.0 常规清理永久删那次裁定）。

pub(super) const PENDING_DELETE_FILE: &str = "pending-delete.json";
pub(super) const PFRO_SUBKEY: &str = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";
pub(super) const PFRO_VALUE: &str = "PendingFileRenameOperations";

/// K06：本域（待删台账 + 系统 PFRO 队列）的进程级域锁。
///
/// 为什么 `security::update_json` 的全局锁不够：它只串行化 JSON 文件的读-改-写，
/// 管不到「读 PFRO → 改 → 写 PFRO」与「读台账 → 改 → 写台账」组成的整次命令——
/// 同进程两次撤回仍可各拿一份旧 PFRO、后写覆盖前写。锁粒度为整次命令
/// （毫秒~百毫秒级；PFRO 写入要管理员，未提权时整次命令在摘除前即失败）。
static PENDING_DELETE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 待删台账文件路径（数据目录下，含 legacy 迁移口径由 paths 统一管）
pub(super) fn pending_delete_path() -> std::path::PathBuf {
    crate::engine::paths::app_data_dir().join(PENDING_DELETE_FILE)
}

pub(super) fn pending_load() -> Value {
    // R2a-L04（2026-11-01 重审）：本函数**会隔离**损坏台账 —— 只给 list 的显式展示用。
    // （登记入口退役后本域已无写入判定路径需要「不隔离的快照」；撤回走 pending_update，
    // 它对损坏/版本不符是拒绝写入，不会拿空表覆盖旧凭据。）
    let p = pending_delete_path();
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        // 文件不存在 = 首次使用，正常空表（不隔离不告警）
        Err(_) => return json!({ "version": 1, "entries": [] }),
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) if v.get("version").and_then(Value::as_u64) == Some(1) => v,
        Ok(_) | Err(_) => {
            // M-6（2026-10-03 L3）：这是**用户已确认的永久删除清单**（PFRO 撤回凭据），
            // 不是可重扫缓存。损坏时不能静默返回空 entries —— 那会让撤回按钮隐藏、
            // 而 PFRO 里的条目仍在，重启照样删。改走配置损坏的标准隔离路径：
            // 留现场（.corrupt-<ts>）+ 回执带 degraded 标记，前端据此明示用户。
            let reason = match bytes.first() {
                Some(_) => "JSON 解析失败或版本不符",
                None => "空文件",
            };
            security::quarantine_file(&p, reason);
            log::write_log("error", &format!("重启后删台账损坏，已隔离并降级: {reason}"));
            json!({ "version": 1, "entries": [], "degraded": true })
        }
    }
}

/// K06：pending-delete.json 的读-改-写**唯一入口**——收进 `security::update_json`
/// （本仓 RMW 原语：全局串行 + 读失败绝不落到写 + 原子落盘）。
///
/// 与旧 `pending_load`+`pending_save` 成对路径的差别：损坏/版本不符时**拒绝写入**
/// （不再「隔离后拿空表继续跑」——那会把用户已确认的永久删清单静默换掉），
/// 首次使用（Absent）由本函数补 version/entries 形状。只读方（list）仍走
/// `pending_load` 的 degraded 口径。
fn pending_update<F>(f: F) -> Result<Value, String>
where
    F: FnOnce(&mut Vec<Value>) -> Result<(), String>,
{
    security::update_json(&pending_delete_path(), |doc| {
        // 形状不变式：version 1 + entries 数组。Absent（首次）补形状；
        // 版本不符按拒——不静默升级/降级一个永久删凭据文件的形状。
        if doc.get("version").is_none() && doc.get("entries").is_none() {
            doc["version"] = json!(1);
            doc["entries"] = json!([]);
        }
        if doc.get("version").and_then(Value::as_u64) != Some(1) {
            return Err("待删台账版本不符（version != 1），拒绝写入".into());
        }
        let entries = doc
            .get_mut("entries")
            .and_then(Value::as_array_mut)
            .ok_or("待删台账形状损坏（缺 entries 数组）")?;
        f(entries)
    })
}

/// 读 PFRO（REG_MULTI_SZ）。缺失/为空按空表处理——没有待重启操作时它经常还不存在。
pub(super) fn read_pfro() -> Result<Vec<String>, String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_VALUE_TYPE,
    };
    unsafe {
        let sk = to_wide(PFRO_SUBKEY);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        let opened = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(sk.as_ptr()),
            Some(0),
            KEY_READ,
            &mut hk,
        );
        if opened.is_err() {
            return Err(format!("打开 PFRO 键失败: {opened:?}"));
        }
        let nm = to_wide(PFRO_VALUE);
        let mut ty = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        let q = RegQueryValueExW(
            hk,
            windows::core::PCWSTR(nm.as_ptr()),
            None,
            Some(&mut ty),
            None,
            Some(&mut size),
        );
        if q.is_err() {
            let _ = RegCloseKey(hk);
            return Ok(Vec::new()); // 值不存在 = 没有待重启操作
        }
        if ty.0 != 7 || size == 0 {
            let _ = RegCloseKey(hk);
            if ty.0 != 7 {
                return Err("PFRO 值类型异常（不是 REG_MULTI_SZ），拒绝改写".to_string());
            }
            return Ok(Vec::new());
        }
        // R2a-L11（§5.16/N6）：按注册表回报的 size 直接分配之前，必须先过 helpers 那份
        // `MAX_REG_STR_BYTES` fail-closed 上限 —— `reg_sz` / `reg_multi_sz` 都有这道，
        // 唯独 PFRO 这条没有，同单元两份「按回报长度分配」只剩一份有护栏。PFRO 只有
        // 管理员可写 ⇒ 不是攻击面，但「读-改-写整值」的入口一旦 OOM 就是整个域丢撤回凭据。
        if size > MAX_REG_STR_BYTES {
            let _ = RegCloseKey(hk);
            return Err(format!(
                "PFRO 回报长度 {size} 超过单值上限 {MAX_REG_STR_BYTES}，拒绝读取（更不得改写）"
            ));
        }
        let mut buf = vec![0u8; size as usize];
        let ok = RegQueryValueExW(
            hk,
            windows::core::PCWSTR(nm.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        );
        let _ = RegCloseKey(hk);
        if ok.is_err() {
            return Err("读取 PFRO 失败".to_string());
        }
        // MULTI_SZ 形态：str\0str\0…\0\0。空串项是"删除"对的第二个元素，必须保留语义。
        let mut out: Vec<String> = Vec::new();
        let mut cur: Vec<u16> = Vec::new();
        let words: Vec<u16> = buf[..size as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        for w in words {
            if w == 0 {
                if cur.is_empty() && out.last().map(|s: &String| s.is_empty()).unwrap_or(false) {
                    break; // 连续两个 \0 = 表结束
                }
                out.push(String::from_utf16_lossy(&cur));
                cur.clear();
            } else {
                cur.push(w);
            }
        }
        Ok(out)
    }
}

/// PFRO 条目 → 可比对的目标路径（纯函数，可测）。
///
/// 为什么要归一：同一个文件在 PFRO 里有多种字面形态——普通/verbatim Win32 路径
/// （Trim 台账与直接注册表写）、`\??\` 设备路径、**会话前缀** `*<会话号>\??\`
/// （未提权进程 MoveFileExW 登记时系统写的就是这一形态；本机现存 4 对第三方条目
/// 全是它），以及其中两种前缀的 UNC 变体（`\\?\UNC\` / `\??\UNC\`，R2a-L06，
/// 2026-11-01 重审）。不剥这几层，MoveFileExW 登记的条目在「已登记过」检查、
/// list 三态、撤回摘除里全部失配——用户看着「未登记」再登记一次，或撤不回（K06 同族病）。
/// 只做**同实体归并**（这些前缀是同一路径的不同写法），不与任何保护判据耦合。
/// PFRO 里"删除 target"的登记形态：src=target、紧随其后的 dst 为空串。
/// 匹配走 [`pfro_norm`]（会话前缀/设备路径/verbatim 及 UNC 变体同实体）。
pub(super) fn pfro_has_delete(entries: &[String], target: &str) -> bool {
    let t = pfro_norm(target);
    if t.is_empty() {
        return false;
    }
    entries
        .windows(2)
        .any(|w| w[1].is_empty() && pfro_norm(&w[0]) == t)
}

/// 从 PFRO 里摘掉"删除 targets 中任一路径"的整对（src+dst 一起删）。
/// targets 与条目都过 [`pfro_norm`]；第三方条目（含 `*N\??\` 形态）路径不匹配
/// 即原样保留——这是 K06「只摘本账对」的判据本体。
pub(super) fn pfro_strip_deletes(entries: Vec<String>, targets: &HashSet<String>) -> Vec<String> {
    let norm: HashSet<String> = targets.iter().map(|s| pfro_norm(s)).filter(|s| !s.is_empty()).collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < entries.len() {
        let is_ours = i + 1 < entries.len()
            && entries[i + 1].is_empty()
            && norm.contains(&pfro_norm(&entries[i]));
        if is_ours {
            i += 2; // 整对摘除
        } else {
            out.push(entries[i].clone());
            i += 1;
        }
    }
    out
}

/// 写回 PFRO（REG_MULTI_SZ）。需要管理员（Session Manager 键的 DACL 只给管理员写）——
/// 唯一的写侧是**撤回**（摘除本账登记的整对，第三方条目原样写回）。
fn pfro_write_all(entries: &[String]) -> Result<(), String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_MULTI_SZ,
    };
    let mut words: Vec<u16> = Vec::new();
    for e in entries {
        words.extend(to_wide(e)); // to_wide 自带结尾 NUL
    }
    if words.last() != Some(&0) {
        words.push(0);
    }
    words.push(0); // MULTI_SZ 以双 NUL 结束
    unsafe {
        let sk = to_wide(PFRO_SUBKEY);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        let opened = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(sk.as_ptr()),
            Some(0),
            KEY_SET_VALUE,
            &mut hk,
        );
        if opened.is_err() {
            // 5 = ERROR_ACCESS_DENIED：Session Manager 键的 DACL 只给管理员写
            let hint = if opened.0 == 5 {
                "（权限不足：撤回重启后删除需要管理员权限，请以管理员身份运行 Trim）"
            } else {
                ""
            };
            return Err(format!("打开 PFRO 键失败: {opened:?}{hint}"));
        }
        let nm = to_wide(PFRO_VALUE);
            let r = RegSetValueExW(
            hk,
            windows::core::PCWSTR(nm.as_ptr()),
            None,
            REG_MULTI_SZ,
            Some(words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>().as_slice()),
        );
        let _ = RegCloseKey(hk);
        if r.is_err() {
            return Err(format!("写 PFRO 失败: {r:?}"));
        }
        Ok(())
    }
}

/// K06：撤回的写入口——**写前重读**当前 PFRO，只摘 targets 的整对，第三方条目
/// （读入之后他人追加的也一样）原样写回。旧口径「读→剥离→整值覆写」会把读入
/// 之后新增的条目抹掉（重启照删却撤不回），本函数把那个窗口关掉。
/// 需要管理员；失败时调用方不得动台账（两边必须一致）。
pub(super) fn pfro_remove_deletes(targets: &HashSet<String>) -> Result<(), String> {
    let current = read_pfro()?;
    let stripped = pfro_strip_deletes(current, targets);
    pfro_write_all(&stripped)
}

// 2026-11-02：「登记重启后删除」注册入口退役后，台账不再增长；原「30 天 / 20 批」
// 裁剪逻辑（PENDING_KEEP_BATCHES / PENDING_MAX_AGE_DAYS / prune_pending_entries）
// 随登记写入面一并删除。历史条目保留撤回能力，不做自动裁剪。

/// 剥 PFRO 条目的会话/设备前缀，保留原大小写（显示用）。[`pfro_norm`] 的剥前缀
/// 段与之共用同一份实现（§5.16）：norm 只在 display 之上多做「盘符前导斜杠折叠 +
/// 去尾分隔符 + 小写」——两处判据永远同步，不留第二份前缀清单。
fn pfro_strip_prefixes(entry: &str) -> String {
    let mut s = entry.trim();
    // `*<数字>\` 会话前缀：未提权 MoveFileExW 登记时系统写的形态
    if let Some(rest) = s.strip_prefix('*') {
        if let Some(idx) = rest.find('\\') {
            if !rest.is_empty() && rest[..idx].chars().all(|c| c.is_ascii_digit()) {
                // 注意：`*N\??\path` 里 N 后面那个 `\` 正是 `\??\` 的第一个字符——
                // 从 idx 处切（不是 idx+1），否则设备路径前缀被啃掉一口、永远剥不掉
                s = &rest[idx..];
            }
        }
    }
    // R2a-L06（2026-11-01 重审）：UNC 两形态先于单前缀判定——`\\?\UNC\srv\share\x` /
    // `\??\UNC\srv\share\x` 与台账里的 `\\srv\share\x` 是同一实体。若先剥 `\\?\` /
    // `\??\`，剩下的是 `UNC\…`，与 `\\srv\…` 永不相等（判重 / list 三态 / 撤回三处失配，
    // 撤不回）。UNC 没有盘符段，直接返回归一结果，跳过下面的盘符前导斜杠折叠。
    for pre in [r"\\?\UNC\", r"\??\UNC\"] {
        if let Some(rest) = s.strip_prefix(pre) {
            return format!(r"\\{rest}");
        }
    }
    // `\\?\` / `\??\` 两种设备/verbatim 前缀（长的在前，避免 `\\?\` 被 `\??\` 分支吃掉）
    for pre in [r"\\?\", r"\??\"] {
        if let Some(rest) = s.strip_prefix(pre) {
            s = rest;
            break;
        }
    }
    s.to_string()
}

fn pfro_norm(entry: &str) -> String {
    let s = pfro_strip_prefixes(entry);
    // 会话前缀 + 普通盘符（`*N\C:\...`）：前导分隔符去掉，`C:` 与 `\C:` 同一实体
    let b = s.as_bytes();
    let s = if b.len() > 2 && b[0] == b'\\' && b[1].is_ascii_alphabetic() && b[2] == b':' {
        &s[1..]
    } else {
        &s[..]
    };
    s.trim_end_matches(['\\', '/']).to_lowercase()
}

/// R2a-U01（B 方案）对补腿：PFRO 里「src + 空 dst」形态挂着、但台账（归一后）没有
/// 的条目，合成 `status:"pending"` + `orphanSource:true` 的补行——「系统挂着、界面
/// 看不见」从根上消灭。归属**诚实标注**：PFRO 是系统全局队列，无法区分这条登记
/// 来自 Trim 早期被裁批次还是第三方软件，故补行不进「撤回全部」的摘除集合
/// （revoke 按台账 scoped 摘，天然不碰补行），前端显示「来源不明·不可撤回」。
/// 纯函数：rows 由调用方从台账构造，本函数只做补行（可测）。
pub(super) fn reconcile_pfro_orphans(mut rows: Vec<Value>, pfro: &[String]) -> Vec<Value> {
    let known: HashSet<String> = rows
        .iter()
        .filter_map(|r| r["target"].as_str().map(pfro_norm))
        .filter(|s| !s.is_empty())
        .collect();
    let mut orphans: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for w in pfro.windows(2) {
        if !w[1].is_empty() {
            continue;
        }
        let key = pfro_norm(&w[0]);
        if key.is_empty() || known.contains(&key) || !seen.insert(key) {
            continue;
        }
        orphans.push(json!({
            "target": pfro_strip_prefixes(&w[0]),
            "batchId": Value::Null,
            "addedAt": Value::Null,
            "status": "pending",
            "orphanSource": true,
        }));
    }
    rows.extend(orphans);
    rows
}

/// uninstall:pending-list — 待删清单（只读）。
/// 三个状态分开：pending（PFRO 还挂着）/ consumed（重启已消费）/ missing（文件已不在）。
///
/// v6-K13：档位从 `RESIDUE_WINDOWS`（残留独占）移到 `PENDING_DELETE_WINDOWS`
/// （main+residue）——已登记的条目对主窗也要「可见可撤回」，否则在残留窗以外的
/// 路径上看不见、撤不回（K13 缺口本体）。只读不改任何状态。
#[tauri::command]
pub async fn uninstall_pending_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::PENDING_DELETE_WINDOWS) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<Value, String> {
        let doc = pending_load();
        let pfro = read_pfro()?;
        let rows: Vec<Value> = doc["entries"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|e| {
                let t = e["target"].as_str().unwrap_or_default().to_string();
                let pending = pfro_has_delete(&pfro, &t);
                let exists = Path::new(&t).is_file();
                let status = if pending {
                    "pending"
                } else if !exists {
                    "missing"
                } else {
                    "consumed"
                };
                json!({
                    "target": t,
                    "addedAt": e["addedAt"],
                    "status": status,
                })
            })
            .collect();
        // R2a-U01（B 方案）对补腿：PFRO 挂着但台账没有的条目补进清单（orphanSource 标记），
        // 「系统挂着、界面看不见」从根上消灭；补行不进撤回集合（归属不可信，撤回只摘台账对）。
        let rows = reconcile_pfro_orphans(rows, &pfro);
        let degraded = doc.get("degraded").and_then(Value::as_bool).unwrap_or(false);
        Ok(json!({
            "entries": rows,
            // M-6：台账损坏时前端不能把撤回按钮隐藏 —— 要置灰并显示提示
            "degraded": degraded,
        }))
    })
    .await;
    match res {
        Ok(Ok(v)) => json!({ "success": true, "data": v }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("读取失败: {e}") }),
    }
}

/// uninstall:pending-revoke — 撤回本机全部登记项。
///
/// v6-K06/K13：档位同 list（`PENDING_DELETE_WINDOWS`，主窗 + 残留副窗）。
/// X0-6 S1：原 `batchId` 可选参数没有任何调用方传值（「按批撤回」UI 从未落地），
/// 已删除；台账内部仍保留 batchId 用于摘账与保留期裁剪。
/// 执行序（域锁内）：**先摘系统队列、后动台账**——摘除失败（未提权：Session
/// Manager 键只有管理员可写）时明确报错且**不动台账**，两边必须一致；反向
/// （账没了、系统还在删）才是不可逆的。系统队列侧走 `pfro_remove_deletes`
/// （写前重读、只摘本账对、第三方条目原样保留）。
#[tauri::command]
pub async fn uninstall_pending_revoke<R: tauri::Runtime>(
    window: WebviewWindow<R>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::PENDING_DELETE_WINDOWS) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<usize, String> {
        // K06：域锁内做完整 RMW（登记入口退役后，本域只剩这一条 RMW 路径；
        // 锁保留，防止同进程两次撤回交错读写系统队列与台账）
        let _lock = PENDING_DELETE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let doc = pending_load();
        let scoped: HashSet<String> = doc["entries"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|e| e["target"].as_str().map(|s| pfro_norm(s)))
            .filter(|s| !s.is_empty())
            .collect();
        if scoped.is_empty() {
            return Ok(0usize);
        }
        // 先断系统队列（写前重读 + 只摘本账对）；失败即整体失败，台账不动
        pfro_remove_deletes(&scoped)?;
        // 再摘台账（update_json 串行 RMW）
        pending_update(|entries| {
            entries.retain(|e| {
                let t = e["target"].as_str().map(pfro_norm).unwrap_or_default();
                !scoped.contains(&t)
            });
            Ok(())
        })?;
        log::flush_sync();
        log::write_log("info", &format!("重启后删除：撤回 {} 项登记", scoped.len()));
        Ok(scoped.len())
    })
    .await;
    match res {
        Ok(Ok(n)) => json!({ "success": true, "data": { "revoked": n } }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("撤回执行异常: {e}") }),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// R2a-U01（B 方案）对补腿：PFRO 挂着、台账没有 ⇒ 合成 pending + orphanSource 补行；
    /// 台账已有的不重复补；PFRO 里非删除对（dst 非空的重命名对）不补。
    #[test]
    fn pfro孤儿对补且台账已有不重复() {
        let pfro = vec![
            r"\??\C:\gone\a.tmp".to_string(),
            String::new(),                                 // 删除对（挂起）
            r"\??\C:\gone\b.tmp".to_string(),
            r"C:\gone\b_new.tmp".to_string(),              // 重命名对（dst 非空，不补）
        ];
        let rows = vec![json!({ "target": r"C:\gone\known.tmp", "status": "pending" })];
        // PFRO 第一对与台账 known.tmp 无关 ⇒ 补行含 a.tmp；b.tmp 是重命名对 ⇒ 不补
        let out = reconcile_pfro_orphans(rows.clone(), &pfro);
        assert_eq!(out.len(), 2, "补行恰一条（a.tmp）");
        assert_eq!(out[1]["status"], json!("pending"));
        assert_eq!(out[1]["orphanSource"], json!(true));
        assert_eq!(out[1]["target"], json!(r"C:\gone\a.tmp"), "补行 target 保留原大小写、剥设备前缀");
        // 台账已有该对 ⇒ 零补行（归一判重）
        let known_rows = vec![json!({ "target": r"C:\GONE\A.TMP", "status": "pending" })];
        let out2 = reconcile_pfro_orphans(known_rows, &pfro);
        assert_eq!(out2.len(), 1, "台账已有（大小写不敏感归一）不得重复补");
        // 同一对重复出现只补一条
        let dup = vec![r"\??\C:\gone\a.tmp".to_string(), String::new(), r"C:\gone\a.tmp".to_string(), String::new()];
        let out3 = reconcile_pfro_orphans(Vec::new(), &dup);
        assert_eq!(out3.len(), 1, "同对重复出现不得重复补行");
    }

    /// K06：域锁必须罩住 revoke 的整次 RMW（2026-11-02 登记入口退役后，本域只剩
    /// 这一条读-改-写路径；漏掉锁 = 同进程两次撤回可交错读写系统队列与台账）。
    /// 源码形态断言（判红：删掉那处 lock 即红）。只数生产段（`#[cfg(test)]` 之前），
    /// 否则本测试自己的锚点字面量会被数进去。
    #[test]
    fn pending_domain_lock_covers_revoke_rmw() {
        let src = include_str!("pending_delete.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        let n = prod.matches("PENDING_DELETE_LOCK.lock()").count();
        assert_eq!(n, 1, "revoke 必须在 PENDING_DELETE_LOCK 内做 RMW，实得上锁点 {n} 处");
    }

    /// K06：PFRO 条目三形态归一——普通/verbatim Win32、`\??\` 设备路径、以及
    /// `*<会话号>\??\` 会话前缀（未提权 MoveFileExW 登记时系统写的正是这一形态，
    /// 本机现存 4 对第三方条目全是它）。不归一 = MoveFileExW 登记的条目在
    /// 「已登记过」/ list 三态 / 撤回摘除里全部失配（撤不回）。
    /// 判红自证：把 pfro_norm 的前缀剥离线删掉 ⇒ ②③④ 红。
    #[test]
    fn pfro_norm_folds_session_prefix_and_device_forms() {
        let plain = r"C:\Users\me\AppData\Local\Temp\x.tmp";
        assert_eq!(pfro_norm(plain), r"c:\users\me\appdata\local\temp\x.tmp");
        // ① verbatim 与普通路径同一实体
        assert_eq!(pfro_norm(r"\\?\C:\Users\me\x.tmp"), pfro_norm(r"C:\Users\me\x.tmp"));
        // ② 设备路径形态
        assert_eq!(pfro_norm(r"\??\C:\Users\me\x.tmp"), pfro_norm(r"C:\Users\me\x.tmp"));
        // ③ 会话前缀 + 设备路径（第三方/未提权登记的真实形态）
        assert_eq!(
            pfro_norm(r"*1\??\C:\Users\me\x.tmp"),
            pfro_norm(r"C:\Users\me\x.tmp"),
            "会话前缀形态必须归并到同一目标"
        );
        // ④ 尾分隔符不敏感；非数字会话号不误剥
        assert_eq!(pfro_norm(r"*1\??\C:\Users\me\x.tmp\"), pfro_norm(r"C:\Users\me\x.tmp"));
        assert_ne!(pfro_norm(r"*x\C:\a"), pfro_norm(r"C:\a"), "会话号必须是数字，*x\\ 不是会话前缀");
        // ⑤ R2a-L06（2026-11-01 重审）：UNC 两形态与台账的 `\\srv\share\…` 同一实体；
        // 判红自证：删掉 pfro_strip_prefixes 的 UNC 分支 ⇒ 这三条当场红
        assert_eq!(pfro_norm(r"\\?\UNC\srv\share\x.tmp"), pfro_norm(r"\\srv\share\x.tmp"));
        assert_eq!(pfro_norm(r"\??\UNC\srv\share\x.tmp"), pfro_norm(r"\\srv\share\x.tmp"));
        assert_eq!(
            pfro_norm(r"*1\??\UNC\srv\share\x.tmp"),
            pfro_norm(r"\\srv\share\x.tmp"),
            "会话前缀 + UNC 设备路径必须归并到同一目标"
        );
        // 空串归一后为空 ⇒ 匹配侧必须拒（pfro_has_delete 的空串闸）
        assert!(pfro_norm("").is_empty());
    }

    /// K06：撤回只摘本账目标的整对，第三方条目（含 `*N\??\` 形态）原样保留。
    /// 样本取本机 PFRO 实测形状（第三方 tbus/nsu 对 + Trim 三种形态的台账对）。
    /// 判红自证：把 pfro_strip_deletes 的成对判定改成「按 src 单摘」⇒ 空串 dst
    /// 残留、后续对错位，本用例红。
    #[test]
    fn pfro_strip_keeps_third_party_pairs_intact() {
        let entries: Vec<String> = [
            r"*1\??\C:\Windows\tbus_1400064837", "",
            r"*1\??\C:\Users\me\AppData\Local\Temp\nsu1FB7.tmp", "",
            r"C:\Users\me\a.tmp", "",       // Trim 台账对（普通形态）
            r"\\?\C:\Users\me\b.tmp", "",   // Trim 台账对（verbatim 形态）
            r"*1\??\C:\Users\me\c.tmp", "", // Trim 台账对（会话前缀形态）
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let targets: HashSet<String> = [r"C:\Users\me\a.tmp", r"\\?\C:\Users\me\b.tmp", r"C:\Users\me\c.tmp"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = pfro_strip_deletes(entries, &targets);
        // 三条 Trim 对整对消失；两条第三方对逐字保留
        assert_eq!(
            out,
            vec![
                r"*1\??\C:\Windows\tbus_1400064837".to_string(),
                String::new(),
                r"*1\??\C:\Users\me\AppData\Local\Temp\nsu1FB7.tmp".to_string(),
                String::new(),
            ],
            "只许摘本账对，第三方条目必须逐字保留"
        );
    }

    /// K06 判据①：RMW 收进 `security::update_json` 后，两个并发写不再互抹——
    /// 各线程读到同一份旧值、各改各的，落盘结果必须同时含所有线程的条目。
    /// （域锁罩住整次命令；update_json 的全局串行是文件侧的第二道。）
    #[test]
    fn concurrent_rmw_on_pending_json_does_not_clobber() {
        use std::sync::Arc;
        use std::thread;
        let dir = std::env::temp_dir().join(format!("trim-k06-rmw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("pending-delete.json");
        // 初值：version 1 + 一条既有条目（模拟别人的登记）
        std::fs::write(
            &file,
            br#"{"version":1,"entries":[{"target":"C:\\base.tmp","batchId":"p1","addedAt":"1"}]}"#,
        )
        .unwrap();
        let file = Arc::new(file);
        let mut handles = Vec::new();
        for k in 0..4u8 {
            let f = Arc::clone(&file);
            handles.push(thread::spawn(move || {
                for r in 0..4u8 {
                    security::update_json(&f, |doc| {
                        let entries = doc["entries"].as_array_mut().expect("entries 数组");
                        entries.push(json!({ "target": format!(r"C:\t{k}-{r}.tmp"), "batchId": format!("p{k}"), "addedAt": "2" }));
                        Ok(())
                    })
                    .expect("update_json 失败");
                }
            }));
        }
        for h in handles {
            h.join().expect("线程不得 panic");
        }
        let doc: Value = serde_json::from_slice(&std::fs::read(&*file).unwrap()).unwrap();
        let targets: Vec<&str> = doc["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["target"].as_str())
            .collect();
        // 既有条目 + 4 线程 × 4 轮 = 17 条，一条都不许被互抹掉
        assert_eq!(targets.len(), 17, "并发 RMW 互抹了条目: {targets:?}");
        assert!(targets.contains(&r"C:\base.tmp"), "既有条目被抹: {targets:?}");
        for k in 0..4u8 {
            for r in 0..4u8 {
                let want = format!(r"C:\t{k}-{r}.tmp");
                assert!(targets.contains(&want.as_str()), "缺 {want}: {targets:?}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

