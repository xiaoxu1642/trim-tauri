//! 值级注册表备份与还原：备份台账（opt-backups.json）、RegTarget 解析、
//! 读值/写回/删除的备份-还原对称编码，以及 optimizer:backup-reg / :restore-reg。
//!
//! 这是「一项不兼容也能单项还原」的地基（BoosterX 只有整批还原的反例）：
//! 未受信的值按原字节保留（restore_ops_keep_untrusted_values_verbatim），
//! DWORD 往返按有符号 32 位处理，备份读取与还原编码互为逆运算。

use crate::engine::{guard, log, optimization_state as opt_state, sysinfo};
use serde_json::{Value, json};
use tauri::{Runtime, WebviewWindow};
use super::catalog::*;
use super::overview::*;
// ==================== 值级注册表备份与还原 ====================

pub(super) fn opt_backup_file() -> std::path::PathBuf {
    crate::engine::paths::app_data_dir().join("optimizer-backups.json")
}

pub(super) fn load_opt_backups() -> Value {
    let v = crate::security::read_json_or_quarantine(&opt_backup_file());
    if v.is_object() {
        v
    } else {
        json!({})
    }
}

pub(super) fn save_opt_backups(map: &Value) -> bool {
    match crate::security::atomic_write_json(&opt_backup_file(), map) {
        Ok(()) => true,
        Err(e) => {
            log::write_log("error", &format!("写入优化备份失败: {e}"));
            false
        }
    }
}

/// .reg 根键 → [Microsoft.Win32.Registry] 静态属性名（Read-One 用）
pub(super) fn dotnet_hive(root: &str) -> &'static str {
    match root {
        "HKEY_CURRENT_USER" => "CurrentUser",
        "HKEY_CLASSES_ROOT" => "ClassesRoot",
        "HKEY_USERS" => "Users",
        "HKEY_CURRENT_CONFIG" => "CurrentConfig",
        _ => "LocalMachine",
    }
}

#[derive(Clone)]
pub(super) struct RegTarget {
    pub(super) root:String, // HKEY_* 全称
    pub(super) sub:String,
    pub(super) key:String,
}

pub(super) fn parse_reg_targets(block: &str) -> Vec<RegTarget> {
    let mut out = Vec::new();
    for (full, body) in parse_reg_sections(block) {
        let root = full.split('\\').next().unwrap_or("").to_string();
        let sub = full
            .split_once('\\')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default();
        for (key, raw) in parse_reg_value_lines(&body) {
            if raw.trim().starts_with('-') {
                continue;
            }
            out.push(RegTarget {
                root: root.clone(),
                sub: sub.clone(),
                key,
            });
        }
    }
    out
}

/// 读取一组 (hive, sub, key) 当前值；任一目标读取失败返回 None
///
/// B11：原先这里生成 `Read-One` PS 函数 + 逐目标调用行，spawn pwsh、60s 超时、
/// 再解析 stdout 里的 JSON —— 就为了读几个注册表值。现在直接走注册表 API。
///
/// 口径用 `native::read_reg_value_faithful`（**不展平**）：备份的目的是还原，
/// 展平口径会把 `REG_EXPAND_SZ` 展开成字面量、把 `REG_MULTI_SZ` 压成空格串并谎报为
/// `REG_SZ`，于是「还原」把类型和内容一起改错 —— 用户看到的正是「还原后反而变了」。
/// DWORD/QWORD/BINARY 的字符串化规则与展平口径相同，所以既有备份文件不受影响。
///
/// 输出形状与旧 PS 逐字段一致：`exists=false` 时**不带** `type`/`data` 键
/// （旧 `ConvertTo-Json` 也不会输出它们），下游 `build_restore_ops` 据此走删除分支。
pub(super) fn read_reg_values(targets: &[RegTarget]) -> Option<Vec<Value>> {
    use crate::engine::native;
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let Some(hive) = reg_hive(&t.root) else { return None };
        let mut item = json!({
            "hive": dotnet_hive(&t.root),
            "sub": t.sub,
            "key": t.key,
            "exists": false,
        });
        if let Some((ty, data)) = native::read_reg_value_faithful(hive, &t.sub, &t.key) {
            item["exists"] = json!(true);
            item["type"] = json!(ty);
            item["data"] = json!(data);
        }
        out.push(item);
    }
    Some(out)
}

pub(super) fn option_targets(option_id: &str) -> Option<Vec<RegTarget>> {
    if option_id == "svc_mem_gb" {
        return Some(vec![RegTarget {
            root: "HKEY_LOCAL_MACHINE".into(),
            sub: "SYSTEM\\ControlSet001\\Control".into(),
            key: "SvcHostSplitThresholdInKB".into(),
        }]);
    }
    let opt = find_option(option_id)?;
    let mut targets = Vec::new();
    if let Some(steps) = opt.get("steps").and_then(|v| v.as_array()) {
        for s in steps {
            if let Some(block) = s.get("reg").and_then(|v| v.as_str()) {
                targets.extend(parse_reg_targets(block));
            }
        }
        collect_service_start_targets(steps, &mut targets);
    }
    // 去重（root\sub::key）
    let mut seen = std::collections::HashSet::new();
    targets.retain(|t| seen.insert(format!("{}\\{}::{}", t.root, t.sub, t.key)));
    Some(targets)
}

/// 服务启动类型注册表位置（`sc config X start= N` 与 `New-ItemProperty … -Name Start` 的落点）
fn svc_start_target(name: &str) -> RegTarget {
    RegTarget {
        root: "HKEY_LOCAL_MACHINE".into(),
        sub: format!("SYSTEM\\CurrentControlSet\\Services\\{name}"),
        key: "Start".into(),
    }
}

/// v5 O-4：`pwsh` / `cmd` / `service` 三种步骤改的「服务启动类型」也要进值级备份基线。
///
/// 此前 `option_targets` 只解析 `s.reg`，于是 pwsh 步骤里的
/// `New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\X -Name Start -Value 4`
/// 与 `sc.exe config X start= disabled` **没有基线**：还原只能靠数据层硬编码的
/// 「猜的原值」（`tf_svc_extra5.restore` 就写着 `SensrSvc=3; StorSvc=2`），
/// 用户改前的实际值永久丢失。
fn collect_service_start_targets(steps: &[Value], out: &mut Vec<RegTarget>) {
    for s in steps {
        // ① service 步骤型：改启动类型就要进基线，两种形态都收（R0-a）
        //
        //   { "service": "X", "disable": true }        → sc config start= disabled
        //   { "service": "X", "startType": "manual" }  → sc config start= demand
        //
        // v0.5.0 只收前者，于是 `svc_*_manual` 四项**没有值级备份基线** —— 用户改前的
        // 实际 Start 值永久丢失，还原只能靠数据层硬编码的猜值。这与 AGENTS 的
        // 「值级备份 → 执行 → 回读 → fail-closed」三不变式直接冲突：基线缺失时
        // 还原链的「还原后回读校验」校验的是一个从未被记录的值。
        if let Some(name) = s.get("service").and_then(|v| v.as_str()) {
            let has_disable = s.get("disable").and_then(|v| v.as_bool()).unwrap_or(false);
            // startType 走 native 解析（fail-closed）：未知取值不猜，也不收基线，
            // 免得把一个解析不了的步骤记成「已备份」而实际没记。
            let has_start = match s.get("startType").and_then(|v| v.as_str()) {
                Some(l) => crate::engine::native::start_type_from_label(l).is_ok(),
                None => false,
            };
            if has_disable || has_start {
                // D0-BACKUP-SIDE: startType 基线收集（D0-COVERAGE-ANCHOR 契约表的一行）
                out.push(svc_start_target(name));
            }
        }
        // ② pwsh 步骤：交给原生解释器拿**结构化** op 列表，不猜正则
        if let Some(pwsh) = s.get("pwsh").and_then(|v| v.as_str()) {
            if let Ok(ops) = crate::engine::pssteps::compile(pwsh) {
                walk_ps_ops_for_start(&ops, out);
            }
        }
        // ③ cmd 步骤：`reg add "…\Services\X" /v Start …` 与 `sc config X start= N`
        if let Some(cmd) = s.get("cmd").and_then(|v| v.as_str()) {
            for name in svc_names_writing_start(cmd) {
                out.push(svc_start_target(&name));
            }
        }
    }
}

/// 递归收集 pwsh op 列表里会改 `Start` 的落点（含 `if (Test-Path …)` 守卫的内层）
fn walk_ps_ops_for_start(ops: &[crate::engine::pssteps::PsOp], out: &mut Vec<RegTarget>) {
    use crate::engine::pssteps::{Hive, PsOp};
    for op in ops {
        match op {
            PsOp::ValueWrite { hive, subkey, name, .. } if name == "Start" => {
                let root = match hive {
                    Hive::Lm => "HKEY_LOCAL_MACHINE",
                    Hive::Cu => "HKEY_CURRENT_USER",
                    // 其余 hive 上没有 Services 树，收进来只会读不到值
                    _ => continue,
                };
                out.push(RegTarget { root: root.into(), sub: subkey.clone(), key: "Start".into() });
            }
            PsOp::SvcSetStart { name, .. } => out.push(svc_start_target(name)),
            PsOp::GuardedKeyExists { ops, .. } => walk_ps_ops_for_start(ops, out),
            _ => {}
        }
    }
}

/// 从 cmd 文本里挑出「被写了 Start 的服务名」。两种形态分别认：
///
/// - A：`reg add "HKLM\SYSTEM\CurrentControlSet\Services\X" /v Start /t REG_DWORD /d 4 /f`
/// - B：`sc config X start= disabled`（**不含** `Services\` 段，名字跟在 `config` 后面）
///
/// 判据要求"确实写了 Start"，否则不收 —— 宁可漏收（少一条基线）也不要把无关命令
/// 当成改启动类型收进来。大小写一律走 `to_ascii_lowercase`：它按字节小写化、
/// **不改变字节长度**，所以偏移量可以安全回切到原串（`to_lowercase` 遇非 ASCII 会变长）。
pub(super) fn svc_names_writing_start(cmd: &str) -> Vec<String> {
    let is_name_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.');
    let mut names = Vec::new();

    // A：注册表路径形态
    if cmd.to_ascii_lowercase().contains("/v start") {
        let mut from = 0usize;
        while let Some(p) = cmd[from..].find("Services\\") {
            let at = from + p + "Services\\".len();
            let rest = &cmd[at..];
            let end = at
                + rest
                    .char_indices()
                    .find(|(_, c)| !is_name_char(*c))
                    .map(|(i, _)| i)
                    .unwrap_or(rest.len());
            let name = &cmd[at..end];
            if !name.is_empty() && name.len() <= 64 {
                names.push(name.to_string());
            }
            from = if end > at { end } else { at + 1 };
        }
    }

    // B：sc config 形态
    let low = cmd.to_ascii_lowercase();
    if low.contains("start=") {
        if let Some(pos) = low.find("config") {
            let rest = cmd[pos + "config".len()..].trim_start();
            let name: String = rest.chars().take_while(|c| is_name_char(*c)).collect();
            if !name.is_empty() && name.len() <= 64 {
                names.push(name);
            }
        }
    }

    names.sort();
    names.dedup();
    names
}

/// [`insert_backup_baseline`] 的三种结果，第三态携带**已存在基线**的项数。
#[derive(Debug)]
pub(super) enum BackupInsert {
    Inserted,
    KeptExisting(usize),
    MapNotObject,
}

/// 登记值级备份：**已有记录就保留首份，绝不覆盖**。刻意保持纯函数（不打日志）——
/// `log::write_log` 会排写入队并起后台 flush 线程，那样这条断言就得靠真实日志目录才能跑。
///
/// 审查 v2-M9：旧写法是 `map[id] = 当前值`，而渲染层每次执行前都会先调 `backup-reg`
/// （`optimizer.js` 的 backupReg）⇒ 同一项**第二次**应用（改参数重跑、失败重试、批量再跑）
/// 时，基线被「已优化后的值」覆盖，此后「还原」只能回到上一次优化的状态、**出厂原值永久丢失**；
/// 更糟的是还原成功后还要 `remove` 掉那唯一一条记录。干净基线只有第一份，后续快照必须丢。
pub(super) fn insert_backup_baseline(map: &mut Value, option_id: &str, values: Vec<Value>) -> BackupInsert {
    let Some(o) = map.as_object_mut() else {
        return BackupInsert::MapNotObject;
    };
    if let Some(existing) = o.get(option_id) {
        let n = existing
            .get("values")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        return BackupInsert::KeptExisting(n);
    }
    o.insert(
        option_id.to_string(),
        json!({ "at": crate::engine::delete_manifest::iso_now(), "values": values }),
    );
    BackupInsert::Inserted
}

/// optimizer:backup-reg —— 执行前读取目标键值并存档
#[tauri::command]
pub async fn optimizer_backup_reg<R: Runtime>(
    window: WebviewWindow<R>,
    option_id: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let option_id = option_id.unwrap_or_default();
    if find_option(&option_id).is_none() {
        return json!({ "success": false, "message": "未知的优化选项" });
    }
    let Some(targets) = option_targets(&option_id) else {
        return json!({ "success": false, "message": "未知的优化选项" });
    };
    if targets.is_empty() {
        return json!({ "success": true, "count": 0 });
    }
    let Some(values) = read_reg_values(&targets) else {
        log::write_log("error", "优化项注册表备份异常: 读取/解析失败");
        return json!({ "success": false, "message": "读取当前注册表值失败" });
    };
    let mut map = load_opt_backups();
    let (count, kept) = match insert_backup_baseline(&mut map, &option_id, values.clone()) {
        BackupInsert::Inserted => (values.len(), false),
        // 已有基线：返回**首份**的项数并如实标注，且不重新落盘（内容没变）
        BackupInsert::KeptExisting(n) => (n, true),
        BackupInsert::MapNotObject => {
            return json!({ "success": false, "message": "注册表备份文件结构异常" });
        }
    };
    if !kept && !save_opt_backups(&map) {
        return json!({ "success": false, "message": "注册表备份文件写入失败" });
    }
    log::write_log(
        "info",
        &format!(
            "优化项注册表{}: {option_id}（{count} 项）",
            if kept { "已保留首份基线，未覆盖" } else { "备份完成" }
        ),
    );
    json!({ "success": true, "count": count, "baselineKept": kept })
}

/// optimizer:restore-reg —— 按备份回写原值（不存在的键删除）
#[tauri::command]
pub async fn optimizer_restore_reg<R: Runtime>(
    window: WebviewWindow<R>,
    option_id: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let option_id = option_id.unwrap_or_default();
    // 退役项已不在目录里，但它们的备份必须还能还原（v2-M14）；两份清单都不认的 id 仍然拒。
    if find_option(&option_id).is_none() && !is_retired_id(&option_id) {
        return json!({ "success": false, "message": "未知的优化选项" });
    }
    // 审查 2026-09-27 M3：值级还原要写回 HKLM/HKCU 备份值，非管理员必然写失败且
    // 此前无任何提示（与 optimizer_run 的提权门槛对齐，needAdmin 走前端提权链）
    if !sysinfo::is_admin() {
        return json!({ "success": false, "needAdmin": true, "message": "还原优化需要管理员权限，请先提权" });
    }
    let mut map = load_opt_backups();
    let entry = map.get(&option_id).cloned();
    let Some(entry) = entry else {
        return json!({ "success": false, "missing": true, "message": "无备份记录" });
    };
    let values = entry.get("values").and_then(|v| v.as_array()).cloned();
    let Some(values) = values.filter(|a| !a.is_empty()) else {
        return json!({ "success": false, "missing": true, "message": "无备份记录" });
    };
    let restored = values.len();

    // 先看能不能构造出还原操作（构造失败即无可核对项，直接拒）
    let Ok(ops) = build_restore_ops(&values) else {
        return json!({ "success": false, "message": "备份数据无法解析成还原操作" });
    };
    if !restore_backup_values(&values) {
        return json!({ "success": false, "message": "还原脚本执行失败" });
    }
    // M3：写完**独立回读**验证。RegSetValueExW 返回成功不等于「值写对了」——
    // 类型标签映射错、字节序错、REG_MULTI_SZ 的双 NUL 终止漏一个都会让 API 成功
    // 而值是错的。改过的 optimizer_run 有执行后回读校验，还原侧此前一直缺这一环。
    //
    // fail-closed：回读不一致时**保留备份记录**并报失败，让用户能再试一次 ——
    // 清掉记录就等于删掉了唯一的还原依据。
    let (checked, mismatched) = verify_restore_ops(&ops);
    if mismatched > 0 {
        log::write_log(
            "error",
            &format!("优化项还原后回读不一致: {option_id}（核对 {checked} 条 / 不一致 {mismatched} 条），已保留备份供重试"),
        );
        return json!({
            "success": false,
            "verifyFailed": mismatched,
            "verified": checked,
            "message": format!("还原后回读校验不一致（{mismatched}/{checked} 条），已保留备份记录，可重试或查看日志"),
        });
    }
    if let Some(o) = map.as_object_mut() {
        o.remove(&option_id);
    }
    if !save_opt_backups(&map) {
        return json!({ "success": false, "message": "还原完成但备份记录清理失败" });
    }
    let _ = opt_state::remove(&option_id);
    let _ = opt_state::set_detected_entry(&option_id, false);
    log::write_log("info", &format!("优化项注册表已按备份还原: {option_id}（{restored} 项）"));
    json!({ "success": true, "restored": restored })
}

/// 还原操作（B11：不再生成「交给 pwsh 的脚本正文」，而是生成结构化操作，
/// 由 Rust 直接调注册表 API —— 原先 v2-K2 防的那类注入在**没有 shell** 时不成立）
#[derive(Debug, PartialEq)]
pub(super) enum RestoreOp {
    /// 回写值：data 已编码为 API 就绪字节
    Write { hive: String, sub: String, key: String, typ: String, bytes: Vec<u8> },
    /// 删除值（不存在 = 幂等成功）
    Delete { hive: String, sub: String, key: String },
}

/// dotnet hive 名 → native hive
pub(super) fn restore_hive(name: &str) -> Option<windows::Win32::System::Registry::HKEY> {
    use crate::engine::native;
    Some(match name {
        "LocalMachine" | "HKEY_LOCAL_MACHINE" => native::hive_hklm(),
        "CurrentUser" | "HKEY_CURRENT_USER" => native::hive_hkcu(),
        "ClassesRoot" | "HKEY_CLASSES_ROOT" => native::hive_hkcr(),
        "Users" | "HKEY_USERS" => native::hive_hku(),
        "CurrentConfig" | "HKEY_CURRENT_CONFIG" => native::hive_hkcc(),
        _ => return None,
    })
}

/// 把备份条目的 `data` 字符串编码为 API 就绪字节。
///
/// 编码口径**逐条对齐**读值侧 `native::decode_reg_value_bytes(.., flatten=false)`：
/// - `REG_DWORD` → `[string]([int]$v)`，是**有符号 i32** 的十进制串；
///   还原时按 i32 解析再按 u32 写回，`0xFFFFFFFF` 才能原样往返。
/// - `REG_QWORD` → `[string]([long]$v)`，i64 十进制。
/// - `REG_BINARY` → 小写 hex 连写（无分隔符）。
/// - `REG_SZ` / `REG_EXPAND_SZ` → UTF-16LE + 单个终止 NUL（两者字节布局相同，
///   区别只在类型标签，标签在 `restore_backup_values` 的 kind 映射里保住）。
/// - `REG_MULTI_SZ` → 元素以 `\u{0}` 连接（读侧的可逆分隔），写回时每个元素补一个
///   NUL、整个串再补一个 NUL（注册表的双 NUL 终止约定）。
/// - 其余标签按 REG_SZ 兜底 —— 只服务**升级前生成**的老备份（那批数据里 EXPAND_SZ/
///   MULTI_SZ 当年就是按 REG_SZ 记的，照老语义还原比猜一个新语义诚实）。
///
/// 返回 `Err` = 备份数据畸形（非法十进制 / 奇数位或非 hex 的 BINARY）。
/// 刻意**fail-closed 而不是像旧 PS 那样把非 hex 字符剥掉**：这是还原路径，
/// 静默剥字符可能把错的数据写回去还报成功；备份是我们自己生成的，畸形即文件损坏。
pub(super) fn restore_write_bytes(typ: &str, data: &str) -> Result<Vec<u8>, String> {
    match typ {
        "REG_DWORD" => {
            let v: i32 = data.trim().parse().map_err(|_| format!("REG_DWORD 值畸形: {data:?}"))?;
            Ok(v.to_le_bytes().to_vec())
        }
        "REG_QWORD" => {
            let v: i64 = data.trim().parse().map_err(|_| format!("REG_QWORD 值畸形: {data:?}"))?;
            Ok(v.to_le_bytes().to_vec())
        }
        "REG_BINARY" => {
            let hex = data.trim();
            if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("REG_BINARY 值畸形（非 hex 或奇数位）: {data:?}"));
            }
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
                .collect()
        }
        "REG_MULTI_SZ" => {
            let mut v: Vec<u8> = Vec::new();
            for part in data.split('\0').filter(|s| !s.is_empty()) {
                v.extend(part.encode_utf16().flat_map(|w| w.to_le_bytes()));
                v.extend_from_slice(&[0, 0]);
            }
            v.extend_from_slice(&[0, 0]); // 双 NUL 收尾；零个元素时这就是「空 MULTI_SZ」
            Ok(v)
        }
        _ => {
            let mut v: Vec<u8> = data.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
            v.extend_from_slice(&[0, 0]); // REG_SZ 以 UTF-16 NUL 结尾
            Ok(v)
        }
    }
}

/// 把备份条目转成结构化还原操作；任一条畸形即整体 `Err`（不产生半套操作）。
///
/// 旧实现（`backup_restore_lines`）在这里生成 PS 命令行，靠单引号串 + `''` 转义把
/// 不可信值锁住（v2-K2，有 3 条回归测试钉着）。改原生后那个攻击面整个消失 ——
/// 值不再经过任何解析器，`A$(whoami)` 就是要写进注册表的字面字节。
pub(super) fn build_restore_ops(values: &[Value]) -> Result<Vec<RestoreOp>, String> {
    let mut ops = Vec::with_capacity(values.len());
    for v in values {
        let hive = v.get("hive").and_then(|x| x.as_str()).unwrap_or("LocalMachine").to_string();
        if restore_hive(&hive).is_none() {
            return Err(format!("未知 hive: {hive}"));
        }
        let sub = v.get("sub").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let key = v.get("key").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let exists = v.get("exists").and_then(|x| x.as_bool()).unwrap_or(false);
        if !exists {
            ops.push(RestoreOp::Delete { hive, sub, key });
            continue;
        }
        let typ = v.get("type").and_then(|x| x.as_str()).unwrap_or("REG_SZ").to_string();
        let data = v.get("data").and_then(|x| x.as_str()).unwrap_or("");
        let bytes = restore_write_bytes(&typ, data)?;
        ops.push(RestoreOp::Write { hive, sub, key, typ, bytes });
    }
    Ok(ops)
}

/// 备份里的类型标签 → 写注册表用的 `REG_VALUE_TYPE`。
///
/// 单独成函数是因为这条映射**看不见失败**：字节编码正确但标签塌成 `REG_SZ`，
/// `RegSetValueExW` 照样返回成功、还原回读也确实读得出一个串，只有下一个用这个值的
/// 程序会发现 `%VAR%` 变成了字面路径、多值串变成了单串。抽出来才能被单测判红。
/// 未知标签按 `REG_SZ` 兜底，只服务升级前生成的老备份（那批里 EXPAND_SZ/MULTI_SZ
/// 当年就是按 `REG_SZ` 记的，照老语义还原比猜一个新语义诚实）。
pub(super) fn restore_reg_kind(typ: &str) -> windows::Win32::System::Registry::REG_VALUE_TYPE {
    use windows::Win32::System::Registry::{
        REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ,
    };
    match typ {
        "REG_DWORD" => REG_DWORD,
        "REG_QWORD" => REG_QWORD,
        "REG_BINARY" => REG_BINARY,
        "REG_EXPAND_SZ" => REG_EXPAND_SZ,
        "REG_MULTI_SZ" => REG_MULTI_SZ,
        _ => REG_SZ,
    }
}

/// 还原**后**回读验证（M3）：逐条检查「注册表里现在真的有我们写进去的东西」。
///
/// ## 为什么必须有这一步
///
/// B11 把「生成 pwsh 脚本」换成「Rust 直调注册表 API」之后，`restore_backup_values`
/// 只看 `RegSetValueExW` 的返回值 —— 那是「API 调用成功」，**不是「值写对了」**。
/// 类型标签映射错、字节序错、`REG_MULTI_SZ` 的双 NUL 终止漏一个，都会让 API 成功
/// 而值是错的。改过的 `optimizer_run` 有执行后回读校验（`verify == 'partial'` 分支），
/// **还原侧一直没有** —— 这是 M3 要补的纵深。
///
/// ## 为什么不能靠备份数据自证
///
/// 备份里的 `data` 与写回用的 `data` 是同一份字符串，自证恒成立。必须**独立回读
/// 注册表**。这里用 `read_reg_value_faithful`（不展开 `REG_EXPAND_SZ`）—— 它与写侧的
/// 编码是**同口径反函数**：展开过的 EXPAND_SZ 写回去会把 `%VAR%` 永久变成字面量，
/// 那正是「还原后反而变了」的根因。
///
/// ## 三种判据
///
/// - `Write` → 回读的（类型标签, 数据）必须与写回时**类型标签一致**，且数据相等
/// - `Delete` → 回读必须是 `None`（键已不存在）
/// - 类型标签对不上（备份写的是 `REG_SZ`、注册表里现在是 `REG_DWORD`）⇒ 判失败。
///   宁可报「还原不一致」也不要放过：那说明别的程序动了这个值，而用户的预期是
///   「回到备份时的样子」。
///
/// ## 返回值
///
/// `(已核对条数, 不一致条数)`。调用方据此 fail-closed 报错。
pub(super) fn verify_restore_ops(ops: &[RestoreOp]) -> (usize, usize) {
    use crate::engine::native;
    let mut checked = 0usize;
    let mut mismatched = 0usize;
    for op in ops {
        match op {
            RestoreOp::Write { hive, sub, key, typ, bytes } => {
                let Some(h) = restore_hive(hive) else {
                    mismatched += 1;
                    continue;
                };
                checked += 1;
                let want_kind = restore_reg_kind(typ);
                let Some((got_type, got_data)) = native::read_reg_value_faithful(h, sub, key) else {
                    mismatched += 1; // 写完读不到 ⇒ 还原没生效
                    continue;
                };
                if got_type != canonical_type_label(want_kind) {
                    mismatched += 1; // 类型变了（别的程序改过）
                    continue;
                }
                let want_data = native::decode_reg_value_bytes(want_kind, bytes, false)
                    .map(|(_, d)| d)
                    .unwrap_or_default();
                if got_data != want_data {
                    mismatched += 1;
                }
            }
            RestoreOp::Delete { hive, sub, key } => {
                let Some(h) = restore_hive(hive) else {
                    mismatched += 1;
                    continue;
                };
                checked += 1;
                if native::read_reg_value_faithful(h, sub, key).is_some() {
                    mismatched += 1; // 该删的还在
                }
            }
        }
    }
    (checked, mismatched)
}

/// win32 `REG_VALUE_TYPE` → 本仓备份里用的类型标签。
///
/// 为什么需要这层映射：读侧 `decode_reg_value_bytes` 返回的标签域与
/// `restore_reg_kind` 吃的是同一个，但备份里可能存着**升级前的老标签**
/// （当年把 EXPAND_SZ / MULTI_SZ 按 REG_SZ 记的历史数据），所以比对前先归一。
fn canonical_type_label(kind: windows::Win32::System::Registry::REG_VALUE_TYPE) -> &'static str {
    use windows::Win32::System::Registry::{
        REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD,
    };
    if kind == REG_DWORD {
        "REG_DWORD"
    } else if kind == REG_QWORD {
        "REG_QWORD"
    } else if kind == REG_BINARY {
        "REG_BINARY"
    } else if kind == REG_MULTI_SZ {
        "REG_MULTI_SZ"
    } else if kind == REG_EXPAND_SZ {
        // 备份里存的是 REG_SZ（老数据的记法）⇒ 归到 REG_SZ 才与读侧标签一致
        "REG_SZ"
    } else {
        "REG_SZ"
    }
}

/// 按备份条目回写（任一失败即返回 false；调用方据此报「还原不完整」）
pub(super) fn restore_backup_values(values: &[Value]) -> bool {
    use crate::engine::native;
    let Ok(ops) = build_restore_ops(values) else {
        return false;
    };
    let mut failed = 0usize;
    for op in ops {
        let ok = match op {
            RestoreOp::Write { hive, sub, key, typ, bytes } => {
                let Some(h) = restore_hive(&hive) else {
                    failed += 1;
                    continue;
                };
                native::reg_restore_write(h, &sub, &key, restore_reg_kind(&typ), &bytes)
            }
            RestoreOp::Delete { hive, sub, key } => match restore_hive(&hive) {
                Some(h) => native::reg_restore_delete(h, &sub, &key),
                None => false,
            },
        };
        if !ok {
            failed += 1;
        }
    }
    failed == 0
}

