//! P1-B3 重启后删：PFRO 队列读写 + pending add/list/revoke。
//!
//! pending.xml 的形状与 PendingFileRenameOperations 的写法是重启后语义的一部分，
//! 改动等于改系统行为；本域只登记、不立即删文件。
//!
//! v6-K06（P0-4）：本域的并发口径。PFRO 是**系统级全局队列**（HKLM，安装器与 OS
//! 自己也往里写——本机实测 4 对第三方 `*1\??\` 形态条目），因此：
//!   · 整次命令（PFRO 读-改-写 + 台账写）在 `PENDING_DELETE_LOCK` 域锁内，Trim 自身
//!     的 add/revoke 不再交错读-改-写窗口；
//!   · 对系统队列的任何改写都**写前重读**（`pfro_remove_deletes`），只摘本账目标的
//!     整对，第三方条目原样保留——旧 `write_pfro` 整值覆写会抹掉读入之后他人追加的
//!     条目（重启照删却撤不回）；
//!   · add 的批次级整值写已删：MoveFileExW 本身就是登记机制（且未提权可用），那次
//!     RegSetValueExW 只有管理员能过——未提权 Trim 上它必败并回滚凭据，而
//!     MoveFileExW 早已把删除登记进系统队列 ⇒「删了撤不回」，正是 K06 要堵的形态。

use crate::engine::{guard, log, protect};
use crate::security;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;
use tauri::WebviewWindow;
use super::helpers::*;
// ==================== P1-B3 重启后删（2026-10-01 拍板） ====================
// 回收站失败的「文件」项可以降级为「重启后删除」：MoveFileEx(DELAY_UNTIL_REBOOT)
// 写进系统 PendingFileRenameOperations（PFRO），下次重启由会话管理器删除。
//
// 四条硬约束（2026-10-01 拍板口径，缺一不可）：
//   · 明示 + 单独确认：只处理用户在确认框里点过头的批次，绝不静默登记；
//   · 只限回收站失败项：本模块不提供任何"直接登记"入口，调用方（渲染层）只能把
//     residueExecute 回执里 status != ok 的文件行送进来；
//   · 可撤回：登记项记进本机 state 文件，撤回 = 把 PFRO 里的对应条目摘掉（重启前有效）；
//   · 待删清单可见：pending_list 把「还挂着 / 已被重启消费 / 文件已不在」三种状态分清。
// 这是**永久删除**（不进回收站），与 AGENTS §3 回收站优先的红线冲突，属 2026-10-01
// 显式拍板的受控例外（类比 v3.3.0 常规清理永久删那次裁定）。

pub(super) const PENDING_DELETE_FILE: &str = "pending-delete.json";
pub(super) const PFRO_SUBKEY: &str = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";
pub(super) const PFRO_VALUE: &str = "PendingFileRenameOperations";

/// K06：本域（待删台账 + 系统 PFRO 队列）的进程级域锁。
///
/// 为什么 `security::update_json` 的全局锁不够：它只串行化 JSON 文件的读-改-写，
/// 管不到「读 PFRO → 改 → 写 PFRO」与「读台账 → 改 → 写台账」组成的整次命令——
/// 两个并发 add/revoke 仍可各拿一份旧 PFRO、后写覆盖前写。锁粒度为整次命令
/// （毫秒~百毫秒级；PFRO 写入要管理员，未提权时在 MoveFileExW 之后无第二段写）。
static PENDING_DELETE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 登记 state 文件路径（数据目录下，含 legacy 迁移口径由 paths 统一管）
pub(super) fn pending_delete_path() -> std::path::PathBuf {
    crate::engine::paths::app_data_dir().join(PENDING_DELETE_FILE)
}

pub(super) fn pending_load() -> Value {
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

/// MOVEFILE 失败错误码 → 中文分档（纯函数，可测）。ACCESS_DENIED 与 SHARING_VIOLATION
/// 必须分开说：前者是权限问题（提权重试有意义），后者是占用问题（提权没用）。
pub(super) fn classify_pending_delete_error(win32_code: u32) -> &'static str {
    match win32_code {
        5 => "拒绝访问（权限不足，需管理员）",
        32 => "文件正被占用（共享冲突）",
        2 => "目标文件不存在",
        3 => "目标路径不存在",
        _ => "系统拒绝该操作",
    }
}

/// 读 PFRO（REG_MULTI_SZ）。缺失/为空按空表处理——首次登记时它经常还不存在。
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
/// 为什么要归一：同一个文件在 PFRO 里有三种字面形态——普通/verbatim Win32 路径
/// （Trim 台账与直接注册表写）、`\??\` 设备路径、以及**会话前缀** `*<会话号>\??\`
/// （未提权进程 MoveFileExW 登记时系统写的就是这一形态；本机现存 4 对第三方条目
/// 全是它）。不剥这三层，MoveFileExW 登记的条目在「已登记过」检查、list 三态、
/// 撤回摘除里全部失配——用户看着「未登记」再登记一次，或撤不回（K06 同族病）。
/// 只做**同实体归并**（三种前缀是同一路径的三种写法），不与任何保护判据耦合。
/// PFRO 里"删除 target"的登记形态：src=target、紧随其后的 dst 为空串。
/// 匹配走 [`pfro_norm`]（会话前缀/设备路径/verbatim 三形态同实体）。
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

/// K06：把本批 targets 的 delete 对合并进 PFRO 现值（纯函数，可测）。
/// 只追加**尚不存在**的对（重复 target 不双登：重启时第二对必然失败，白拉长消费
/// 阶段）；现值里的一切——第三方条目、非 delete 对、别的形状——原样保留。
/// 与旧「整值覆写」的差别就在这句：覆写会抹掉读入之后他人追加的条目。
pub(super) fn pfro_merge_pairs(current: Vec<String>, targets: &[String]) -> Vec<String> {
    let mut out = current;
    for t in targets {
        if pfro_norm(t).is_empty() || pfro_has_delete(&out, t) {
            continue;
        }
        out.push(t.clone());
        out.push(String::new());
    }
    out
}

/// 写回 PFRO（REG_MULTI_SZ）。需要管理员（Session Manager 键的 DACL 只给管理员写）——
/// 本函数只被**撤回**路径调用（摘除第三方之外的条目）；登记走 MoveFileExW，
/// 不需要这个权限（v6-K06：见文件头）。
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

/// K06：把本批 targets 的 delete 对合并进 PFRO **现值**（写前重读）。
/// 只追加缺失的对；第三方条目原样保留（判据本体 [`pfro_merge_pairs`] 是纯函数）。
/// 需要管理员；只被 add 的「登记对账补写」安全网调用（正常路径不需要它——
/// MoveFileExW 已登记，且未提权可用）。
pub(super) fn pfro_merge_deletes(targets: &[String]) -> Result<(), String> {
    let current = read_pfro()?;
    let merged = pfro_merge_pairs(current, targets);
    pfro_write_all(&merged)
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

/// 单批登记上限：口径对齐残留执行侧的 200 项目标上限（`residue.rs` 的 execute 闸）。PFRO 是系统级全局队列，
/// 登记逐条走 MoveFileExW，超大批次没有业务场景（可登记项天然来自「回收站删不掉」的少数派），
/// 只会拉长重启阶段会话管理器的消费时间（v2-B2，2026-10-01 复核）。
pub(super) const PENDING_ADD_MAX_ITEMS: usize = 32;

/// 台账保留窗口（审查 L-10，2026-10-03）：entries 原先只增不减——单批 32 有上限、
/// 累计无界、永不过期，只有用户手动撤回才减。口径对齐备份类保留策略（还原包
/// KEEP_BATCHES=20）：最近 20 批 / 30 天内的登记保留撤回能力。
/// R2a-U01（2026-10-28 拍板 B 方案）：裁剪必须先看 PFRO 现值——系统队列仍挂着的
/// 条目**永不裁**（红线「待删清单可见且重启前可撤回」无「到期即失明」例外），
/// 打 `expiredWindow` 标记；只裁「超窗 且 PFRO 已不挂」的条目。
pub(super) const PENDING_KEEP_BATCHES: usize = 20;
pub(super) const PENDING_MAX_AGE_DAYS: u64 = 30;

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

/// 按「30 天 + 最近 N 批」裁剪 entries，返回剔除条数（纯函数，可测）。
/// addedAt 缺失/不可解析的条目按最老处理（裁掉）——无法判年龄的撤回凭据不可信。
/// R2a-U01（B 方案）：裁剪判据必须在「超窗」之外再加「PFRO 现值已不挂」——
/// 系统队列仍挂着的撤回凭据无论多老都保留并打 `expiredWindow` 标记，否则
/// 「30 天不重启」的机器上会出现「系统挂着、界面看不见、撤不回」的失明子集。
pub(super) fn prune_pending_entries(entries: &mut Vec<Value>, now_secs: u64, pfro: &[String]) -> usize {
    let before = entries.len();
    let cutoff = now_secs.saturating_sub(PENDING_MAX_AGE_DAYS * 86_400);
    entries.retain_mut(|e| {
        let aged_out = e["addedAt"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|t| t < cutoff)
            .unwrap_or(true);
        if !aged_out {
            return true;
        }
        // 超窗但系统队列仍挂 ⇒ 撤回凭据保留（界面标「窗口已过」），不裁
        let still_held = e["target"].as_str().map(|t| pfro_has_delete(pfro, t)).unwrap_or(false);
        if still_held {
            if let Some(obj) = e.as_object_mut() {
                obj.insert("expiredWindow".into(), json!(true));
            }
            return true;
        }
        false
    });
    // 同一秒内可能有多批/多批同秒：按批次 secs 排序去重后保最近 N 批
    if entries.len() > PENDING_KEEP_BATCHES {
        let batch_secs = |e: &Value| -> Option<u64> {
            e["batchId"]
                .as_str()
                .and_then(|b| b.strip_prefix('p'))
                .and_then(|s| s.parse::<u64>().ok())
        };
        let mut batches: Vec<u64> = entries.iter().filter_map(batch_secs).collect();
        batches.sort_unstable();
        batches.dedup();
        if batches.len() > PENDING_KEEP_BATCHES {
            let keep_from = batches[batches.len() - PENDING_KEEP_BATCHES];
            entries.retain_mut(|e| match batch_secs(e) {
                Some(t) if t >= keep_from => true,
                Some(_) => {
                    // 批次超窗的同一套 PFRO 判据：系统仍挂的不裁，打标记
                    let still_held =
                        e["target"].as_str().map(|t| pfro_has_delete(pfro, t)).unwrap_or(false);
                    if still_held {
                        if let Some(obj) = e.as_object_mut() {
                            obj.insert("expiredWindow".into(), json!(true));
                        }
                        true
                    } else {
                        false
                    }
                }
                None => false,
            });
        }
    }
    before - entries.len()
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

/// v6-K05：PFRO 登记前的**新增两道**只读闸（纯函数，可测）——系统命名空间 + 别名复检。
///
/// PFRO 是**永久删**出口（不进回收站、重启后由会话管理器执行），登记面此前只有
/// `is_path_protected` 一道（v2-B1，`check-delete-exits` 的 MUST_PROTECT 正向棘轮钉在
/// 命令体内，不并进来）：
/// ① `is_system_namespace`——`%WINDIR%` 在 protect 里是 exact 语义、管不到 System32
///    子孙，residue 执行侧（`classify_residue_op` 的 file 分支）同位置已有这道；
/// ② `final_path_protected`（别名复检）——字面判定拦不住「父目录被换成 junction /
///    短名指向受保护根」（同一实体两条路径，literal 比对只认其中一条），
///    canonicalize 父目录后重跑同一套判据（Kudu S2，清理删除链与 finder 同函数）。
///
/// 返回 `Some(原因)` = 拒绝登记。存在性不在这里判（调用方按 is_file 判，PFRO 只收文件）。
pub(super) fn pending_delete_sysns_alias_reason(target: &str) -> Option<&'static str> {
    if protect::is_system_namespace(target) {
        return Some("目标位于系统目录（Windows/System32 等），拒绝登记重启后删除");
    }
    if protect::final_path_protected(target) {
        return Some("目标经别名解析后位于受保护路径，拒绝登记重启后删除");
    }
    None
}

/// uninstall:pending-add — 把回收站失败的文件项登记为重启后删除（主窗档）。
/// 只接受**文件**路径（PFRO 对非空目录的延迟删除并不可靠，登记了也删不掉，
/// 与其制造"已登记=会删掉"的错觉，不如入口就拒）。
///
/// v6-K06 执行序（域锁 `PENDING_DELETE_LOCK` 内）：
/// ① 读 PFRO 现值（类型异常在这里暴露，不进半登记状态）+ 读台账快照（只读）；
/// ② 纯判定得出本批计划（闸 + 去重），零写入；
/// ③ **先落撤回凭据**（`pending_update`）——v4 P2-F：反序会让「系统已登记、凭据
///    不存在」= 删了撤不回；
/// ④ 再逐条 `MoveFileExW` 登记（DELAY_UNTIL_REBOOT 只登记、立即返回；这就是
///    系统队列的写入机制，未提权可用——批次级 RegSetValueExW 已删，见文件头）；
/// ⑤ 单条失败的目标当场从账上摘掉，不留「凭据在、系统没登记」的幽灵条目。
#[tauri::command]
pub async fn uninstall_pending_add<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    targets: Vec<String>,
) -> Value {
    // v0.7.0 「重启后删除失败项」的入口随残留面板一起搬进 residue 副窗
    // 消费方：残留副窗（原有入口）+ 主窗清理域的失败引导（2026-10-13 裁定，
    // 见 guard::PENDING_DELETE_WINDOWS）。v6-K13 起 list/revoke 同集放行
    // （待删清单对主窗可见可撤回），models/processManager 无消费场景不放。
    if let Err(msg) = guard::guard(&window, guard::PENDING_DELETE_WINDOWS) {
        return json!({ "success": false, "message": msg });
    }
    if targets.is_empty() {
        return json!({ "success": false, "message": "没有要登记的目标" });
    }
    // v2-B2：单批上限在入口拦，进 spawn_blocking 之前就整批拒绝——
    // 不给「先读 PFRO 才发现超批」的无效往返，也不留半批登记的中间态。
    if targets.len() > PENDING_ADD_MAX_ITEMS {
        return json!({
            "success": false,
            "message": format!("单批登记 {} 项超上限 {PENDING_ADD_MAX_ITEMS}，请分批登记", targets.len())
        });
    }
    let res = tauri::async_runtime::spawn_blocking(move || {
        // K06：整次命令在域锁内——add/revoke 彼此并发不再交错读-改-写窗口
        let _lock = PENDING_DELETE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // ① PFRO 现值：类型异常（非 REG_MULTI_SZ）在这里就失败，不进半登记状态
        let pfro = read_pfro()?;
        // 台账快照（只读）：判「已登记过」用；写路径走 pending_update
        let doc = pending_load();
        let known = doc["entries"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
        let batch = format!(
            "p{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );

        // ② 纯判定：闸 + 去重（PFRO 现值 / 本批重复 / 台账在册），得出计划
        let mut rows: Vec<Value> = Vec::new();
        let mut plan: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for t in &targets {
            // v2-B1（2026-10-01 复核）：PFRO 登记是**永久删**出口（不进回收站，重启后由
            // 会话管理器执行），受保护路径判定必须在命令体内前置——渲染层 confirmDanger
            // 只是第一层，命令体内再判一次才与其余删除链同口径。刻意放在 is_file 之前：
            // 空串 / 盘符根 / 受保护根下的路径无论当前存在与否都拒，不给「登记窗口期
            // 路径状态变化」留缝，也与 protect 判定的 fail-closed 语义一致。
            // 这行同时是 check-delete-exits MUST_PROTECT 正向棘轮的钉住点，不许挪进 helper。
            if protect::is_path_protected(t) {
                rows.push(json!({ "target": t, "status": "skip", "message": "目标位于受保护路径（或无法归一化），拒绝登记重启后删除" }));
                continue;
            }
            // R2a-M03：五道约束的第一道「只收回收站失败项」的命令体判据 ——
            // 目标必须命中本会话某个删除域的**删除失败回执**（残留链与清理链的
            // 命令体在删除失败时各自登记，见 engine::delete_failed）。命中不了就拒。
            // 这道闸此前只存在于渲染层（cleanup.js 的 collectFailedPaths 与
            // residue-window.js 的失败文件筛选各筛一遍），命令体里零判据 ⇒ 换一个
            // 消费方、或渲染层被改一句，任意文件都能进 PFRO 这个**永久删**出口
            // （不进回收站、不可还原）。
            if !crate::engine::delete_failed::is_failed_in_session(t) {
                rows.push(json!({ "target": t, "status": "skip", "message": "不是本次删除失败回执里的文件，拒绝登记重启后删除" }));
                continue;
            }
            // v6-K05：系统命名空间 + 别名复检（与 residue 执行侧同口径）
            if let Some(reason) = pending_delete_sysns_alias_reason(t) {
                rows.push(json!({ "target": t, "status": "skip", "message": reason }));
                continue;
            }
            let path = Path::new(t);
            if t.trim().is_empty() || !path.is_file() {
                rows.push(json!({ "target": t, "status": "skip", "message": "目标不是存在的文件（目录不支持重启后删）" }));
                continue;
            }
            let key = pfro_norm(t);
            if !seen.insert(key) {
                rows.push(json!({ "target": t, "status": "skip", "message": "本批内重复，不重复登记" }));
                continue;
            }
            let already = pfro_has_delete(&pfro, t)
                || known.iter().any(|e| {
                    e["target"].as_str().map(|s| pfro_norm(s) == pfro_norm(t)).unwrap_or(false)
                });
            if already {
                rows.push(json!({ "target": t, "status": "skip", "message": "已登记过，不重复登记" }));
                continue;
            }
            plan.push(t.clone());
        }
        if plan.is_empty() {
            // 全 skip / 全失败：零写入（不碰账、不碰系统队列）
            return Ok::<Vec<Value>, String>(rows);
        }

        // ③ 先落撤回凭据（v4 P2-F：凭据先于系统队列；K06：收进 update_json 的
        // 全局串行 RMW，Corrupt/版本不符拒绝落盘——不再「隔离后拿空表继续跑」）
        pending_update(|entries| {
            for t in &plan {
                entries.push(json!({ "target": t, "batchId": batch, "addedAt": batch.trim_start_matches('p') }));
            }
            // 审查 L-10：写回前按保留窗口裁剪（最近 20 批 / 30 天）；R2a-U01（B 方案）：
            // 裁剪看 PFRO 现值——系统仍挂着的凭据不裁（pfro 即本函数入口 ① 读的现值）。
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let pruned = prune_pending_entries(entries, now_secs, &pfro);
            if pruned > 0 {
                log::write_log("info", &format!("重启后删除台账：按保留窗口裁剪 {pruned} 条过期登记（系统队列已不挂、撤回凭据一并清除）"));
            }
            Ok(())
        })?;

        // ④ 系统队列：MoveFileExW 逐条登记（DELAY_UNTIL_REBOOT 只登记、立即返回；
        // 这就是 PFRO 的写入机制，未提权可用）
        let mut registered: Vec<String> = Vec::new();
        let mut failed: Vec<(String, String)> = Vec::new();
        for t in &plan {
            use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
            let moved = unsafe {
                MoveFileExW(
                    windows::core::PCWSTR(to_wide(t).as_ptr()),
                    None,
                    MOVEFILE_DELAY_UNTIL_REBOOT,
                )
            };
            match moved {
                Ok(()) => registered.push(t.clone()),
                Err(e) => {
                    let code = e.code().0 as u32 & 0xFFFF;
                    failed.push((t.clone(), format!("{}（错误码 {code}）", classify_pending_delete_error(code))));
                }
            }
        }

        // ④b 登记对账（K06）：MoveFileExW 返回 Ok ≠ 系统队列里一定有**可匹配**的
        // 条目——第三方条目在本机是 `*1\??\` 会话前缀形态，匹配虽走 pfro_norm 三形态
        // 归一，真出现未知形态时这里补写一对普通形态（会话管理器两种都消费）。
        // 补写要管理员；补写也失败 ⇒ 该目标的「已登记」不可信，改判 fail 并摘账，
        // 不拿「已登记」糊弄（永久删出口的回执必须诚实）。
        if !registered.is_empty() {
            let unconfirmed: Vec<String> = match read_pfro() {
                Ok(after) => registered
                    .iter()
                    .filter(|t| !pfro_has_delete(&after, t))
                    .cloned()
                    .collect(),
                Err(e) => {
                    log::write_log("warn", &format!("重启后删除：登记后重读 PFRO 失败（{e}），跳过对账"));
                    Vec::new()
                }
            };
            if !unconfirmed.is_empty() {
                match pfro_merge_deletes(&unconfirmed) {
                    Ok(()) => {
                        log::write_log(
                            "warn",
                            &format!("重启后删除：{} 个目标的登记形态不在已知三形态内，已补写普通形态对", unconfirmed.len()),
                        );
                    }
                    Err(e) => {
                        let msg = format!("系统未确认登记生效且无法补写（{e}），未登记；请以管理员身份运行 Trim 后重试");
                        for t in &unconfirmed {
                            failed.push((t.clone(), msg.clone()));
                        }
                        registered.retain(|r| !unconfirmed.iter().any(|u| u == r));
                    }
                }
            }
        }

        // 回执（计划序：ok 行 → fail 行；skip 行已在规划阶段按序入列）
        for t in &registered {
            rows.push(json!({ "target": t, "status": "ok", "message": "已登记，下次重启时删除" }));
        }
        for (t, msg) in &failed {
            rows.push(json!({ "target": t, "status": "fail", "message": msg }));
        }

        // ⑤ 失败（含对账补写失败）的目标当场从账上摘掉（同一把域锁内的第二次 RMW），
        // 不留「凭据在、系统没登记」的幽灵条目（list 会把它显示成 consumed）
        if !failed.is_empty() {
            let failed_norm: Vec<String> = failed.iter().map(|(t, _)| pfro_norm(t)).collect();
            if let Err(e) = pending_update(|entries| {
                entries.retain(|en| {
                    let hit = en["target"]
                        .as_str()
                        .map(|s| failed_norm.contains(&pfro_norm(s)))
                        .unwrap_or(false);
                    en["batchId"].as_str() != Some(batch.as_str()) || !hit
                });
                Ok(())
            }) {
                // 摘账失败：凭据留着并如实留痕——list 会把它们显示成「已消费/文件不在」，
                // 用户能看见并手动撤回；比静默丢账诚实。
                log::write_log(
                    "error",
                    &format!("重启后删除：{} 个失败目标的摘账未生效（{e}），幽灵凭据保留待用户撤回", failed.len()),
                );
            }
        }
        if !registered.is_empty() {
            log::flush_sync();
            log::write_log("warn", &format!("重启后删除：本批登记 {} 项（永久删除，不进回收站）", registered.len()));
        }
        Ok::<Vec<Value>, String>(rows)
    })
    .await;
    match res {
        Ok(Ok(rows)) => {
            let ok = rows.iter().filter(|r| r["status"] == "ok").count();
            json!({ "success": true, "data": { "added": ok, "details": rows } })
        }
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("登记执行异常: {e}") }),
    }
}

/// uninstall:pending-list — 待删清单（只读）。
/// 三个状态分开：pending（PFRO 还挂着）/ consumed（重启已消费）/ missing（文件已不在）。
///
/// v6-K13：档位从 `RESIDUE_WINDOWS`（残留独占）移到 `PENDING_DELETE_WINDOWS`
/// （main+residue）——登记项对主窗清理域也要「可见可撤回」，否则主窗登记的条目
/// 在残留窗以外的路径上看不见、撤不回（K13 缺口本体）。只读不改任何状态。
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
/// v6-K06/K13：档位同 add/list（`PENDING_DELETE_WINDOWS`，主窗 + 残留副窗）。
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
        // K06：域锁内做完整 RMW（与 add 互斥）
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

    fn entry(batch_secs: u64) -> Value {
        // target 用真实登记形态（反斜杠）：prune 的 PFRO 对拍不折叠正反斜杠
        json!({
            "target": format!(r"C:\f{batch_secs}.tmp"),
            "batchId": format!("p{batch_secs}"),
            "addedAt": batch_secs.to_string(),
        })
    }

    /// 审查 L-10：超 30 天的登记裁掉，窗口内的保留。
    #[test]
    fn 超期条目被裁剪() {
        let now = 1_800_000_000u64;
        let mut v = vec![entry(now - 31 * 86_400), entry(now - 29 * 86_400)];
        let n = prune_pending_entries(&mut v, now, &[]);
        assert_eq!(n, 1);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["addedAt"], (now - 29 * 86_400).to_string());
    }

    /// R2a-U01（B 方案）：超窗但 PFRO 仍挂着 ⇒ 不裁，打 expiredWindow 标记；
    /// 超窗且 PFRO 已不挂 ⇒ 照裁。PFRO 对形态 = src 后跟空 dst（windows(2)）。
    #[test]
    fn 超期但系统仍挂的不裁只打标() {
        let now = 1_800_000_000u64;
        let held = entry(now - 40 * 86_400); // 超窗
        let held_target = held["target"].as_str().unwrap_or_default().replace('/', "\\");
        let mut v = vec![held, entry(now - 35 * 86_400)];
        // PFRO 现值：一条挂着（\??\ 设备形态，覆盖归一）、一条没有
        let pfro = vec![format!(r"\??\{held_target}"), String::new()];
        let n = prune_pending_entries(&mut v, now, &pfro);
        assert_eq!(n, 1, "仍挂系统队列的条目不得被裁");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["expiredWindow"], json!(true), "保留的条目必须打「窗口已过」标记");
    }

    /// 审查 L-10：全部未超期但批次超量时，只保留最近 N 批。
    #[test]
    fn 批次超量只留最近批() {
        let now = 1_800_000_000u64;
        let mut v: Vec<Value> = (0..25).map(|i| entry(now - (25 - i) * 3_600)).collect();
        let n = prune_pending_entries(&mut v, now, &[]);
        assert_eq!(n, 5);
        assert_eq!(v.len(), PENDING_KEEP_BATCHES);
        assert!(!v.iter().any(|e| e["batchId"] == format!("p{}", now - 25 * 3_600)), "最老一批必须被裁");
        assert!(v.iter().any(|e| e["batchId"] == format!("p{}", now - 3_600)), "最近一批必须保留");
    }

    /// R2a-U01（B 方案）：批次超窗 + PFRO 仍挂 ⇒ 同样不裁（批裁剪腿也看现值）。
    #[test]
    fn 批次超量但系统仍挂的不裁() {
        let now = 1_800_000_000u64;
        let mut v: Vec<Value> = (0..25).map(|i| entry(now - (25 - i) * 3_600)).collect();
        let oldest = v[0]["target"].as_str().unwrap_or_default().replace('/', "\\");
        let pfro = vec![format!(r"\??\{oldest}"), String::new()];
        let n = prune_pending_entries(&mut v, now, &pfro);
        assert_eq!(n, 4, "最老一批有一条仍挂 ⇒ 只裁其余四条");
        assert!(v.iter().any(|e| e["batchId"] == format!("p{}", now - 25 * 3_600) && e["expiredWindow"] == json!(true)));
    }

    /// 审查 L-10：addedAt 缺失/不可解析的条目按最老处理——无法判年龄的撤回凭据不可信。
    #[test]
    fn addedat缺失视为过期裁掉() {
        let now = 1_800_000_000u64;
        let mut v = vec![json!({ "target": "C:/x.tmp", "batchId": "p1" })];
        let n = prune_pending_entries(&mut v, now, &[]);
        assert_eq!(n, 1);
        assert!(v.is_empty());
    }

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

    /// v4 P2-F（R2-M03/M04）+ v6-K06：**撤回凭据先于系统队列**——旧反序里系统已登记
    /// （重启必删）而凭据不存在 = 删了撤不回。真跑要写系统 PendingFileRenameOperations，
    /// 这里用源码顺序形态钉住（判红：把凭据落账挪到 MoveFileExW 循环之后即红）。
    #[test]
    fn pending_add_saves_credentials_before_system_queue() {
        let src = include_str!("pending_delete.rs");
        let i_save = src.find("pending_update(|entries|").expect("找不到凭据落账调用");
        let i_pfro = src.find("let moved = unsafe {").expect("找不到 MoveFileExW 登记调用");
        assert!(
            i_save < i_pfro,
            "撤回凭据必须先落账再动系统 PFRO 队列（旧反序：系统已登记、凭据缺失 ⇒ 删了撤不回）"
        );
    }

    /// K06：域锁必须同时罩住 add 与 revoke 两条 RMW 路径（漏一条 = 并发批次可互抹）。
    /// 源码形态断言（判红：删掉任一处 lock 即红）。只数生产段（`#[cfg(test)]` 之前），
    /// 否则本测试自己的锚点字面量会被数进去。
    #[test]
    fn pending_domain_lock_covers_both_rmw_paths() {
        let src = include_str!("pending_delete.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        let n = prod.matches("PENDING_DELETE_LOCK.lock()").count();
        assert_eq!(n, 2, "add 与 revoke 都必须在 PENDING_DELETE_LOCK 内做 RMW，实得上锁点 {n} 处");
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

    /// K06：合并只追加缺失的本账对，不双登、不碰现值任何条目。
    /// 判红自证：把 pfro_merge_pairs 的去重删掉 ⇒ 长度断言红。
    #[test]
    fn pfro_merge_appends_only_missing_pairs() {
        let current: Vec<String> = [
            r"*1\??\C:\Windows\tbus_1400064837", "",
            r"C:\Users\me\a.tmp", "",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // a.tmp 已在对里（普通形态）⇒ 不双登；b.tmp 新 ⇒ 追加一对
        let out = pfro_merge_pairs(
            current,
            &[r"C:\Users\me\a.tmp".to_string(), r"C:\Users\me\b.tmp".to_string()],
        );
        assert_eq!(out.len(), 6, "只应新增一对: {out:?}");
        assert_eq!(out[4], r"C:\Users\me\b.tmp");
        assert_eq!(out[5], "");
        // 第三方对仍在原位
        assert_eq!(out[0], r"*1\??\C:\Windows\tbus_1400064837");
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

    /// K06 真机探针（#[ignore]，发布前人工跑）：真写系统 PFRO——本机 Session Manager
    /// 的 DACL 只给 Administrators/SYSTEM 写，**必须以管理员身份运行**。验证三件事：
    /// ① `pfro_merge_deletes` 登记后能被 `read_pfro` + `pfro_has_delete` 读回
    ///    （形态归一在真实注册表值上成立）；
    /// ② 合并写是**纯追加**：结果 == 进入快照 + 本对（既有条目逐字逐序保留）；
    /// ③ `pfro_remove_deletes` 只摘本对：结果 == 进入快照（第三方条目原样）。
    /// 自建自清：探针结束 PFRO 恢复到进入时的形态；中途 panic 最多留一条指向
    /// %TEMP% 探针文件的删除对（下次重启删一个临时文件，无副作用）。
    #[test]
    #[ignore = "真机写 PFRO（需管理员）：登记→读回→摘除 闭环 + 既有条目原样保留"]
    fn live_pfro_merge_and_remove_roundtrip() {
        let before = read_pfro().expect("读 PFRO 失败（本探针需管理员身份）");
        let target = std::env::temp_dir().join(format!("trim-k06-live-{}.tmp", std::process::id()));
        std::fs::write(&target, b"x").expect("写探针文件");
        let t = target.to_string_lossy().to_string();
        // ① 登记（写前重读合并）
        pfro_merge_deletes(std::slice::from_ref(&t)).expect("merge 失败（需管理员）");
        let after_merge = read_pfro().expect("读回 PFRO");
        assert!(
            pfro_has_delete(&after_merge, &t),
            "登记后必须能按三形态归一读回: {t}\nPFRO={after_merge:?}"
        );
        // ② 纯追加：进入快照是本值的前缀，尾部恰好多出 [t, ""]
        let mut want_merge = before.clone();
        want_merge.push(t.clone());
        want_merge.push(String::new());
        assert_eq!(after_merge, want_merge, "合并写不是纯追加（既有条目被改动）");
        // ③ 摘除本对 ⇒ 精确回到进入快照
        let mut scoped = HashSet::new();
        scoped.insert(t.clone());
        pfro_remove_deletes(&scoped).expect("strip 失败（需管理员）");
        let after_strip = read_pfro().expect("读回 PFRO");
        assert!(
            !pfro_has_delete(&after_strip, &t),
            "摘除后不得再命中: {after_strip:?}"
        );
        assert_eq!(after_strip, before, "摘除写破坏了第三方/既有条目");
        let _ = std::fs::remove_file(&target);
        eprintln!("探针通过：PFRO 登记→读回→摘除闭环，进入/退出快照逐字一致（{} 项）", before.len());
    }

    /// v6-K05：PFRO 登记闸三层——① is_path_protected（v2-B1 既有，门禁 MUST_PROTECT
    /// 钉在命令体内）② is_system_namespace ③ final_path_protected，普通文件放行。
    /// 判红自证：把 pending_delete_sysns_alias_reason 改成恒 None ⇒ ② 红（System32
    /// 子孙不在 protect 的 exact 语义内，只有这道拦得住）。
    #[test]
    fn pfro登记闸_三拒一放() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        // ① 受保护路径：System32\config 是 protect 的 subtree 根（命令体内那道）
        let protected = format!(r"{windir}\System32\config\SAM");
        assert!(
            protect::is_path_protected(&protected),
            "受保护路径必须由命令体内那道拦下: {protected}"
        );
        // ② 系统命名空间：System32 子孙不在 protect 的 exact 语义内，靠新闸拦
        let sysns = format!(r"{windir}\System32\drivers\etc\hosts");
        assert!(
            !protect::is_path_protected(&sysns),
            "前置断言：hosts 不在 protect 判据内（否则测的不是新闸）: {sysns}"
        );
        assert!(
            pending_delete_sysns_alias_reason(&sysns).is_some(),
            "系统命名空间必须拒: {sysns}"
        );
        // ③ 不可折回 verbatim 形态：第一道就 fail-closed（P0-1 契约），新闸同样拒
        let vol = r"\\?\Volume{61aed058-0000-0000-0000-000000000000}\Windows\System32\x.dll";
        assert!(
            protect::is_path_protected(vol),
            "Volume GUID 形态必须由第一道 fail-closed 拦下: {vol}"
        );
        assert!(
            pending_delete_sysns_alias_reason(vol).is_some(),
            "新闸对不可折回形态同样 fail-closed: {vol}"
        );
        // 放行：普通临时文件（不在任何保护根、不在系统命名空间、父目录可解析）
        let legit = std::env::temp_dir().join(format!("trim-k05-{}.tmp", std::process::id()));
        assert!(
            pending_delete_sysns_alias_reason(&legit.to_string_lossy()).is_none(),
            "普通临时文件必须放行: {}",
            legit.display()
        );
    }

    /// v6-K05：别名复检——父目录被换成指向受保护子树的链接（junction/符号链接）时，
    /// 字面路径不在任何保护根下，必须靠 final_path_protected 拦在登记闸外（PFRO 是
    /// 永久删出口，字面判据放过它 = 重启后删掉受保护目录里的文件）。
    /// 样本双通道：符号链接（开发者模式/提权态免 cmd 依赖）优先，junction
    /// （mklink /J 免管理员）回退；两者都建不出来（受限环境）显式 SKIP，不假绿。
    #[test]
    fn pfro登记闸_别名解析后受保护必须拒() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let target = format!(r"{windir}\System32\config");
        let dir = std::env::temp_dir().join(format!("trim-k05-jlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let alias = dir.join("alias");
        // 通道①：目录符号链接（canonicalize 同样跟随，判据等价的别名样本）
        let made = std::os::windows::fs::symlink_dir(&target, &alias).is_ok();
        // 通道②：junction 回退（mklink /J 免管理员；symlink_dir 需开发者模式/提权）
        let made = made || {
            std::process::Command::new("cmd")
                .args(["/C", &format!(r#"mklink /J "{}" "{}""#, alias.display(), target)])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        if !made {
            eprintln!("SKIP：符号链接与 junction 都建不出来（受限环境），别名样本未校验");
            return;
        }
        // 字面路径在 %TEMP% 下（不在任何保护根），父目录是指向 System32\config 的链接
        let probe = alias.join("trim-k05-probe.txt");
        assert!(
            pending_delete_sysns_alias_reason(&probe.to_string_lossy()).is_some(),
            "链接别名穿透登记闸: {}",
            probe.display()
        );
    }
}
