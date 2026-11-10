//! 值级注册表备份与还原：备份台账（opt-backups.json）、RegTarget 解析、
//! 读值/写回/删除的备份-还原对称编码，以及 optimizer:backup-reg / :restore-reg。
//!
//! 这是「一项不兼容也能单项还原」的地基（BoosterX 只有整批还原的反例）：
//! 未受信的值按原字节保留（restore_ops_keep_untrusted_values_verbatim），
//! DWORD 往返按有符号 32 位处理，备份读取与还原编码互为逆运算。

use crate::engine::{guard, log, optimization_state as opt_state, sysinfo};
use serde_json::{Value, json};
use std::sync::OnceLock;
use tauri::{Runtime, WebviewWindow};
use super::apply::ledger_note;
use super::catalog::*;
use super::overview::*;
// ==================== 值级注册表备份与还原 ====================

pub(super) fn opt_backup_file() -> std::path::PathBuf {
    crate::engine::paths::app_data_dir().join("optimizer-backups.json")
}

/// 台账文件**确定不存在**（R3-K01：只有 `NotFound` 才算；权限/IO 异常必须落到摘要闸
/// 的 `unreadable`，不能被折叠成「没有备份」—— 那会让用户以为从来没备份过）。
pub(super) fn opt_backup_absent(path: &std::path::Path) -> bool {
    matches!(std::fs::metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// 备份台账只读消费（列表 / 详情 / 迁移提示）。
///
/// v5-K01 批次 4（R7-M05）：三态读器——读失败（Corrupt，含 IO 失败）已在
/// read_json_state 内 warn 留痕，不再与「没有配置」同归静默空；只读展示降级空表。
/// **写链一律走 [`update_opt_backups`]**（读失败绝不落到写），不许 load→改→save。
pub(super) fn load_opt_backups() -> Value {
    match crate::security::read_json_state(&opt_backup_file()) {
        crate::security::JsonState::Ok(v) => v,
        _ => json!({}),
    }
}

/// 还原入口专用的三态读取（A1-M04，v7.2 C06）：台账读不动时不能回「无备份记录」——
/// 那会让用户以为从来没备份过，而真相是「不知道有没有」。`Absent` 才是确无台账。
///
/// 还原点频率回收链也走这条（R3-L03）：两条值级还原链共用同一个读器，`Err` 不再被
/// 宽松读器折叠成空表。
pub(super) fn load_opt_backups_state() -> Result<Value, String> {
    match crate::security::read_json_state(&opt_backup_file()) {
        crate::security::JsonState::Ok(v) => Ok(v),
        crate::security::JsonState::Absent => Ok(json!({})),
        crate::security::JsonState::Corrupt => Err(
            "优化项备份台账读取失败（现场已保留/见日志），无法确认是否存在备份记录；请先修复该文件或从其它批次还原"
                .to_string(),
        ),
    }
}

/// v5-K01 批次 4（R7-M05 / R3-M07 同链收口）：optimizer-backups.json 的**读-改-写
/// 唯一入口**。这份台账是用户值级注册表备份的唯一还原依据——旧链 load（IO 失败 ⇒
/// 空表）→ 改 → save（`atomic_write_json` 直调）会在读失败瞬间把整本台账覆写成
/// 只剩本次改动，回执仍是 success。走 `security::update_json`：Corrupt 拒写、
/// `UPDATE_JSON_LOCK` 全局串行（此前三条写链各自 load/save 手工配对、无域锁）。
///
/// R3-K01（2026-11-01）：落盘后立刻为该文件补管理员摘要。台账在用户可写目录、明文、
/// 无签名时，「同用户改台账 → 用户点一次还原」就是一条提权任意写；摘要键在 HKLM
/// （非提权进程写不了），还原前由提权实例重算比对（见 [`restore_preflight`]）。
/// 本函数是全仓唯一写入口，所以所有写路径都带摘要，不存在「漏签」的分叉。
/// R3-M01（2026-11-08）：摘要失败必须显式回错；不能再留下“内容已写、封条没写”
/// 的静默台账。
pub(super) fn update_opt_backups<F>(f: F) -> Result<Value, String>
where
    F: FnOnce(&mut Value) -> Result<(), String>,
{
    let path = opt_backup_file();
    // R3-M02：写前先核对整本封条；整本 mismatch 时拒绝写入，避免「合法写 B
    // 把被篡改的 A 一起重新签真」。旧台账（整本封条 ok/缺失）先给现有条目补逐条封条。
    if path.exists() {
        let digest = crate::engine::hash::sha256_file(&path).ok();
        let state = crate::engine::reg_backup::reg_backup_admin_seal_state("optimizer", &path, digest.as_deref());
        if state == "mismatch" || state == "unreadable" || state == "corrupt" {
            return Err(format!("优化项备份台账整本封条异常（{state}），拒绝写入；请先核实台账是否被改动"));
        }
        if let Ok(old) = load_opt_backups_state() {
            if let Some(obj) = old.as_object() {
                for (id, entry) in obj {
                    match entry_seal_state(id, entry) {
                        "ok" => {}
                        "missing" => {
                            if !seal_entry(id, entry) {
                                return Err(format!("旧台账条目「{id}」逐条封条写入失败，拒绝继续写入"));
                            }
                        }
                        other => {
                            return Err(format!("优化项备份台账条目「{id}」封条异常（{other}），拒绝写入"));
                        }
                    }
                }
            }
        }
    }
    let out = crate::security::update_json(&path, f)?;
    // 只签本次实际写入/变更的条目；删除条目的旧封条不影响剩余条目的完整性。
    if let Ok(new) = load_opt_backups_state() {
        if let Some(obj) = new.as_object() {
            for (id, entry) in obj {
                if entry_seal_state(id, entry) != "ok" && !seal_entry(id, entry) {
                    return Err(format!("台账已写入，但条目「{id}」的管理员摘要写入失败；本次台账不能用于还原"));
                }
            }
        }
    }
    if !seal_opt_backup_ledger(&path) {
        return Err(
            "台账已写入，但管理员摘要写入失败；本次台账未封条，不能用于还原，请在提权后重试"
                .to_string(),
        );
    }
    Ok(out)
}

/// R3-M02：逐条条目的管理员摘要（HKLM，域 `optimizer-entry`）。
fn entry_digest(entry: &Value) -> String {
    let bytes = serde_json::to_vec(entry).unwrap_or_default();
    crate::engine::hash::sha256_bytes(&bytes)
}

fn entry_seal_path(option_id: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{option_id}.entry.json"))
}

fn seal_entry(option_id: &str, entry: &Value) -> bool {
    crate::engine::reg_backup::write_admin_seal_with_digest(
        "optimizer-entry",
        &entry_seal_path(option_id),
        &entry_digest(entry),
    )
}

fn entry_seal_state(option_id: &str, entry: &Value) -> &'static str {
    crate::engine::reg_backup::reg_backup_admin_seal_state(
        "optimizer-entry",
        &entry_seal_path(option_id),
        Some(&entry_digest(entry)),
    )
}

/// R3-M01：非提权执行前的值级备份不写台账，返回可继续执行链的 deferred 回执。
/// 提权重试会再次调用本命令，由管理员会话完成真正的备份与封条。
fn backup_reg_deferred_receipt(is_admin: bool) -> Option<Value> {
    (!is_admin).then(|| {
        json!({
            "success": true,
            "count": 0,
            "deferred": true,
            "message": "需提权后执行，届时自动补做备份"
        })
    })
}

/// 落盘后补写管理员摘要（R3-K01）。摘要来源可注入：单测据此钉住「签的是刚写下去
/// 的那份字节」，而不是另一条路径重新拼出来的内容。
///
/// 并发/竞态口径：`update_json` 的读-改-写有全局锁，但补摘要发生在锁外。同一用户的
/// 中完整性进程若恰在「落盘 → 重算」这毫秒级窗口内改写台账，摘要会覆盖其内容 ——
/// 这是本闸承认的窄窗口，也正是**第二道闸**（目标准入）必须同时存在的原因：即便摘要
/// 覆盖了对手内容，越界坐标仍然写不进去，能做的只有该项声明面内的写/删。
fn seal_opt_backup_ledger_with<H, S>(path: &std::path::Path, hash_of: H, mut seal_of: S) -> bool
where
    H: FnOnce(&std::path::Path) -> Result<String, String>,
    S: FnMut(&str) -> bool,
{
    let sum = match hash_of(path) {
        Ok(s) => s,
        Err(e) => {
            crate::engine::log::write_log(
                "warn",
                &format!("优化项备份台账摘要计算失败（本次未写管理员摘要，该台账将不能用于还原）: {e}"),
            );
            return false;
        }
    };
    seal_of(&sum)
}

fn seal_opt_backup_ledger(path: &std::path::Path) -> bool {
    seal_opt_backup_ledger_with(path, crate::engine::hash::sha256_file, |sum| {
        crate::engine::reg_backup::write_admin_seal_with_digest("optimizer", path, sum)
    })
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

/// 读取一组 (hive, sub, key) 当前值；hive 解析失败返回 None
///
/// B11：原先这里生成 `Read-One` PS 函数 + 逐目标调用行，spawn pwsh、60s 超时、
/// 再解析 stdout 里的 JSON —— 就为了读几个注册表值。现在直接走注册表 API。
///
/// 口径用三态内核 `native::read_reg_value_state`（**不展平**，与旧
/// `read_reg_value_faithful` 同一套字节规则，既有备份文件的 `type`/`data` 不受影响）：
/// 备份的目的是还原，展平口径会把 `REG_EXPAND_SZ` 展开成字面量、把 `REG_MULTI_SZ`
/// 压成空格串并谎报为 `REG_SZ`，于是「还原」把类型和内容一起改错 —— 用户看到的正是
/// 「还原后反而变了」。
///
/// P0-3：条目权威状态字段是 `presence`（"absent" | "value" | "unknown"），
/// 「确认不存在」与「读不出来」分开入账；`exists=false` 时**不带** `type`/`data` 键
/// （旧形状不变），但 `build_restore_ops` 只认 `presence=absent` 才生成 Delete。
pub(super) fn read_reg_values(targets: &[RegTarget]) -> Option<Vec<Value>> {
    use crate::engine::native;
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let Some(hive) = reg_hive(&t.root) else { return None };
        let state = native::read_reg_value_state(hive, &t.sub, &t.key, false);
        out.push(backup_entry_from_state(dotnet_hive(&t.root), &t.sub, &t.key, state));
    }
    Some(out)
}

/// 值级备份条目的**唯一构造处**：`presence` 是真源，兼容字段 `exists` 由它派生 ——
/// 两个字段必须同源，否则台账里会出现自相矛盾的条目（P0-3 明令禁止手写两份真相）。
/// `unknown` 时随条目落一条 `unknownReason`（只含错误码名，见
/// `engine::native::read_reg_value_state` 的隐私纪律；不含路径、键名、值内容）。
pub(super) fn backup_entry_from_state(
    hive: &str,
    sub: &str,
    key: &str,
    state: crate::engine::native::RegReadState,
) -> Value {
    use crate::engine::native::RegReadState;
    let presence = match &state {
        RegReadState::Value(..) => "value",
        RegReadState::Absent => "absent",
        RegReadState::Unknown(..) => "unknown",
    };
    let mut item = json!({
        "hive": hive,
        "sub": sub,
        "key": key,
        "presence": presence,
        "exists": presence == "value",
    });
    match state {
        RegReadState::Value(ty, data) => {
            item["type"] = json!(ty);
            item["data"] = json!(data);
        }
        RegReadState::Unknown(reason) => {
            item["unknownReason"] = json!(reason);
        }
        RegReadState::Absent => {}
    }
    item
}

/// 读取备份条目的权威 `presence`。返回 `None` = P0-3 之前生成的旧记录（没有该字段）：
/// 其 `exists=false` 只是「当年没读到」，**不得**当作「确认不存在」；其 `exists=true`
/// 仍可信（读成功过才会有 `type`/`data`）。无法识别的 presence 取值同样按旧记录处理，
/// 让下游走保守分支。
pub(super) fn backup_presence(entry: &Value) -> Option<&str> {
    match entry.get("presence").and_then(|v| v.as_str()) {
        Some(p @ ("absent" | "value" | "unknown")) => Some(p),
        _ => None,
    }
}

/// `perf_wu_pause` 的写入面（R3-M03，2026-11-01）：动态项的步骤由
/// `commands::optimizer::apply::wu_pause_steps` 在运行时生成（数据层 `steps` 为空），
/// 本表的值名与那个生成器的 pwsh 原文**逐字对齐** —— 单测
/// `perf_wu_pause基线对齐生成器与检测侧表` 用生成出来的脚本反查本表，漂了就红。
const WU_PAUSE_SUBKEY: &str = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate";
const WU_PAUSE_VALUES: &[&str] = &[
    "PauseFeatureUpdatesStartTime",
    "PauseQualityUpdatesStartTime",
    "PauseUpdatesStartTime",
    "PauseFeatureUpdatesEndTime",
    "PauseQualityUpdatesEndTime",
    "PauseUpdatesExpiryTime",
];

pub(super) fn option_targets(option_id: &str) -> Option<Vec<RegTarget>> {
    if option_id == "svc_mem_gb" {
        return Some(vec![RegTarget {
            root: "HKEY_LOCAL_MACHINE".into(),
            sub: "SYSTEM\\ControlSet001\\Control".into(),
            key: "SvcHostSplitThresholdInKB".into(),
        }]);
    }
    // R3-M03（2026-11-01）：`perf_wu_pause` 与 `svc_mem_gb` 同属 dynamic —— 数据层
    // `steps` 为空，走下面 `find_option` 那条分支只能得到空 targets ⇒
    // `optimizer_backup_reg` 命中 `targets.is_empty()` 直接回 `count:0` 且**不落记录**，
    // `preflight_reason` 又因无 restore 段拒还原 ⇒「暂停更新」写进 HKLM 的那组
    // QWord 在应用内**没有任何还原出口**（唯一出路是用户自己去执行另一项
    // `perf_wu_enable`，界面不做任何提示）。原值不存在时基线记 `presence=absent`，
    // 还原走 Delete，语义正好。
    if option_id == "perf_wu_pause" {
        return Some(
            WU_PAUSE_VALUES
                .iter()
                .map(|name| RegTarget {
                    root: "HKEY_LOCAL_MACHINE".into(),
                    sub: WU_PAUSE_SUBKEY.into(),
                    key: (*name).to_string(),
                })
                .collect(),
        );
    }
    let opt = find_option(option_id)?;
    let empty: &[Value] = &[];
    let mut targets = targets_from_steps(opt.get("steps").and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(empty));
    // R3-M03（v4，与 R3-M02 同批）：`tf_svc_bulk` 勾了 includeStore 时
    // `svc_bulk_append_store` 会在**执行期**追加 5 个商店服务的 Start=4 写入 ——
    // 那一步不在数据层 steps 里，基线必须把它们的 Start 一并纳入；否则还原按旧基线
    // remove() + 摘灰、回 restored:N，**被改的 Start 原值永久丢失**（勾商店即中招）。
    // 枚举复用 apply.rs 的 STORE_SERVICES（不新建第三份清单；它与
    // optimizer-writes.json 的 storeServices 由 check-optimizer-write-contract 钉一致）。
    if option_id == "tf_svc_bulk" {
        for name in super::apply::STORE_SERVICES {
            targets.push(svc_start_target(name));
        }
    }
    // R3-M02（2026-11-01）：子项**附带开关**（extras）的写面与上面商店服务同一种形态
    // —— 步骤在执行期才由 `commands::optimizer::subitems::extra_steps` 生成，数据层
    // `steps` 里没有，基线必须无条件并入（备份在执行前，勾选在执行时，备份侧判不出
    // 用户这一次勾了哪个）。不并入的后果：`tf_svc_bulk` 的 `lfsvc_status` /
    // `edge_prelaunch`、`tf_appx` 的 `onedrive_full_uninstall` 改的那些值不在回读范围，
    // 用户点「还原」拿到 `success:true, restored:N` 而那几个值一直是改过的 —— 两项
    // 在数据层都没有 restore 段，值级备份就是唯一还原出口。
    // 生成器只经 subitems 那一份（不在这里重抄坐标），执行侧与基线侧结构上同源。
    targets.extend(targets_from_steps(&super::subitems::all_extra_steps(option_id)));
    dedupe_targets(&mut targets);
    Some(targets)
}

/// 从数据层 steps 抽值级备份目标：`reg` 块 + pwsh 步骤里的**全部值写入**
/// + cmd/service 步骤的启动类型写点（R3-M01：pwsh 不再只收 `Start`）。
///
/// 在册项（[`option_targets`]）与退役项（[`retired_restore_surface`]）共用这一份解析 ——
/// 还原侧的「声明面」与当年备份侧的「目标集」必须是同一套口径，否则要么误拒合法备份、
/// 要么放行台账里凭空多出来的坐标。
fn targets_from_steps(steps: &[Value]) -> Vec<RegTarget> {
    let mut targets = Vec::new();
    for s in steps {
        if let Some(block) = s.get("reg").and_then(|v| v.as_str()) {
            targets.extend(parse_reg_targets(block));
        }
    }
    collect_service_start_targets(steps, &mut targets);
    dedupe_targets(&mut targets);
    targets
}

/// 去重（`root\sub::key`，按字面量；大小写归一发生在对拍那一侧）
fn dedupe_targets(targets: &mut Vec<RegTarget>) {
    let mut seen = std::collections::HashSet::new();
    targets.retain(|t| seen.insert(format!("{}\\{}::{}", t.root, t.sub, t.key)));
}

/// 退役优化项的**历史声明面**（R3-K01，2026-11-01）。
///
/// 为什么必须有这张表：退役 id 已不在目录里，`option_targets` 返回 `None`。还原入口
/// 若因此跳过目标核对，「台账里写什么就还原什么」等于把任意 HKLM 写权限交还给一个
/// 用户可写文件。表里每一行都是**当年数据层 steps 的逐字快照**，运行时用与在册项
/// 完全相同的解析函数现算坐标（不另写「当年写过哪些键」的第二套口径）。
///
/// 数据来源（可复核）：`git log --all -S '<id>' -- src-tauri/data` 找到移除提交，
/// 再 `git show <提交>^:src-tauri/data/optimizer-options.json`（更名后的
/// `optimizer-runtime.json` 同理）取当年 steps。当前两处提交：`a329a8a`（整批迁移）、
/// `2fd9490`（电源写面收敛的 nara 两项）。
///
/// 收录口径：只保留**可能进值级基线**的步骤（`reg`、`service`、含 `Start` 写点的
/// `pwsh`/`cmd`）；空数组 = 当年没有注册表写点（纯 pwsh 设备枚举 / powercfg /
/// AppX 等），因此不可能留下值级备份，任何值级记录都不予还原。
///
/// **不在这张表里的退役 id = 历史定义早于 git 基线，无法恢复**（`maps_off`、
/// `clear_recent_docs_on_exit` 等，清单见 [`RETIRED_SURFACE_UNRECOVERABLE`]）
/// ⇒ [`build_restore_ops`] fail-closed 拒绝并
/// 点名「退役项无可核对目标」，提示按退役说明手动回退。绝不因为「查不到」就放行任意目标。
const RETIRED_RESTORE_STEPS_JSON: &str = r##"{
  "mmcss_optimize": [{"label":"MMCSS Games 任务优先级 + 低延迟标记","reg":"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games]\r\n\"Affinity\"=dword:00000000\r\n\"Background Only\"=\"False\"\r\n\"Clock Rate\"=dword:00002710\r\n\"Scheduling Category\"=\"High\"\r\n\"SFIO Priority\"=\"High\"\r\n\"GPU Priority\"=dword:00000008\r\n\"Priority\"=dword:00000006\r\n\"Latency Sensitive\"=\"True\"\r\n"},{"label":"MMCSS 系统级增强（NoLazyMode/AlwaysOn/Reliability）","reg":"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile]\r\n\"NoLazyMode\"=dword:00000001\r\n\"AlwaysOn\"=dword:00000001\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Reliability]\r\n\"TimeStampInterval\"=dword:00000001\r\n\"IoPriority\"=dword:00000003\r\n"}],
  "explorer_foreground_speed": [{"label":"ForegroundLockTimeout=0","reg":"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Control Panel\\Desktop]\r\n\"ForegroundLockTimeout\"=dword:00000000\r\n"}],
  "perf_shutdown_fast": [{"label":"WaitToKillAppTimeout=2000","reg":"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Control Panel\\Desktop]\r\n\"WaitToKillAppTimeout\"=\"2000\"\r\n"}],
  "perf_service_shutdown_fast": [{"label":"WaitToKillServiceTimeout=2000","reg":"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control]\r\n\"WaitToKillServiceTimeout\"=\"2000\"\r\n"}],
  "tf_fso": [{"label":"FSO GameConfigStore","reg":"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\System\\GameConfigStore]\r\n\"GameDVR_DSEBehavior\"=dword:00000000\r\n\"GameDVR_FSEBehaviorMode\"=dword:00000000\r\n\"GameDVR_EFSEFeatureFlags\"=dword:00000000\r\n\"GameDVR_DXGIHonorFSEWindowsCompatible\"=dword:00000000\r\n\"GameDVR_HonorUserFSEBehaviorMode\"=dword:00000001\r\n"}],
  "svc_fax_disable": [{"label":"Fax Start=4","pwsh":"$p = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Fax\"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 4 -PropertyType DWord -Force | Out-Null; Stop-Service -Name Fax -Force -ErrorAction SilentlyContinue }"}],
  "tf_ifeo_perf": [{"label":"IFEO PerfOptions（双蜂巢）","reg":"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\dwm.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000004\r\n\"IoPriority\"=dword:00000003\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ntoskrnl.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000004\r\n\"IoPriority\"=dword:00000003\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\csrss.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000004\r\n\"IoPriority\"=dword:00000003\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\"IoPriority\"=dword:00000000\r\n\"PagePriority\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SearchIndexer.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\"IoPriority\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\TrustedInstaller.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\"IoPriority\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wuauclt.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\"IoPriority\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MsMpEng.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MsMpEngCP.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\r\n[HKEY_LOCAL_MACHINE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\dwm.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000004\r\n\"IoPriority\"=dword:00000003\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ntoskrnl.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000004\r\n\"IoPriority\"=dword:00000003\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\csrss.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000004\r\n\"IoPriority\"=dword:00000003\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\"IoPriority\"=dword:00000000\r\n\"PagePriority\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SearchIndexer.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\"IoPriority\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\TrustedInstaller.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\"IoPriority\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wuauclt.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000001\r\n\"IoPriority\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\audiodg.exe\\PerfOptions]\r\n\"CpuPriorityClass\"=dword:00000002\r\n"}],
  "tf_onedrive": [{"label":"OneDrive 入口 / 策略","reg":"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CLASSES_ROOT\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\ShellFolder]\r\n\"Attributes\"=dword:00000000\r\n\r\n[HKEY_CLASSES_ROOT\\Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\ShellFolder]\r\n\"Attributes\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive]\r\n\"DisableFileSync\"=dword:00000001\r\n\"DisableFileSyncNGSC\"=dword:00000001\r\n\"DisableMeteredNetworkFileSync\"=dword:00000000\r\n\"DisableLibrariesDefaultSaveToOneDrive\"=dword:00000000\r\n"}],
  "tf_hibern_off": [{"label":"快速启动 / 休眠 / 睡眠诊断注册表","reg":"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power]\r\n\"HiberbootEnabled\"=dword:00000000\r\n\"HibernateEnabled\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SleepReliability]\r\n\"SleepReliabilityDetailedDiagnostics\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SleepStudy]\r\n\"SleepStudyDisabled\"=dword:00000001\r\n"}],
  "power_off": [{"label":"关闭节能与休眠默认值","reg":"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power]\r\n\"HibernateEnabledDefault\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling]\r\n\"PowerThrottlingOff\"=dword:00000001\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching]\r\n\"SearchOrderConfig\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\943c8cb6-6f93-4227-ad87-e9a3feec08d1]\r\n\"Attributes\"=dword:00000002\r\n"}],
  "tf_oosu": [],
  "tf_gpu_msi": [],
  "tf_usb_msi": [],
  "audio_disable_voice_activation": [],
  "audio_disable_voice_activation_last_used": [],
  "tf_ifeo_wipe": [],
  "tf_dev_audio": [],
  "tf_dev_printer": [],
  "perf_exploit_protection_off": [],
  "tf_mmagent": [],
  "power_aspm_off": [],
  "nara_throttle_off": [],
  "nara_usb3_lpm_off": []
}"##;

/// 历史定义**不可恢复**的退役 id（早于 git 基线，仓内已无当年 steps）。
///
/// 显式列出而不是「表里没有就算了」：一是拒因要能区分「确知不可恢复」与「新退役项
/// 忘了补表」，二是让「退役账本每个 id 都有结论」可机检（见 `r3_k01_gate_tests`）。
pub(super) const RETIRED_SURFACE_UNRECOVERABLE: &[&str] = &[
    "tf_pccleaner",
    "clear_recent_docs_on_exit",
    "always_unload_dll",
    "ssd_opt",
    "services_off",
    "maps_off",
    "mem_compress",
    "tasks_disable_ceip",
    "tasks_disable_usb_ceip",
    "tasks_disable_disk_diag",
    "tasks_disable_office_telemetry",
    "edge_game_assistant_overlay_off",
    "tasks_stubborn_strategy",
];

/// 退役 id 的当年 steps；`None` = 历史定义不可恢复（不是「没有写点」）。
fn retired_restore_steps(option_id: &str) -> Option<&'static [Value]> {
    static CACHE: OnceLock<Option<std::collections::HashMap<String, Vec<Value>>>> = OnceLock::new();
    let map = CACHE.get_or_init(|| {
        // 内嵌 JSON 损坏时 fail-closed：返回 None，所有退役项按「声明面不可恢复」拒绝，
        // 不在还原链上 panic（那会把「拒绝」变成整进程崩溃）。
        let parsed: Value = match serde_json::from_str(RETIRED_RESTORE_STEPS_JSON) {
            Ok(v) => v,
            Err(e) => {
                crate::engine::log::write_log(
                    "error",
                    &format!("退役项历史步骤表损坏，退役项还原一律拒绝: {e}"),
                );
                return None;
            }
        };
        Some(
            parsed
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| Some((k.clone(), v.as_array()?.clone())))
                        .collect()
                })
                .unwrap_or_default(),
        )
    });
    map.as_ref()?.get(option_id).map(|v| v.as_slice())
}

/// 退役项的历史声明面。只有仍登记在退役账本里的 id 才认（表与账本双保险）。
fn retired_restore_surface(option_id: &str) -> Option<Vec<RegTarget>> {
    if !is_retired_id(option_id) {
        return None;
    }
    let steps = retired_restore_steps(option_id)?;
    Some(targets_from_steps(steps))
}

/// 某项还原时的**声明面**（R3-K01 第二道闸的唯一判据来源）。
///
/// - 在册项：`option_targets`（与备份侧同源）；
/// - `tf_restore_point`：历史备份 id 的窄口子，坐标硬编码在
///   `super::restore_point::restore_freq_target`（写入侧与还原侧共用同一函数）；
/// - 退役项：[`retired_restore_surface`] 的静态历史表；不可恢复 ⇒ `None`（拒绝）。
fn declared_restore_surface(option_id: &str) -> Option<Vec<RegTarget>> {
    if let Some(t) = option_targets(option_id) {
        return Some(t);
    }
    if option_id == "tf_restore_point" {
        return Some(vec![super::restore_point::restore_freq_target()]);
    }
    retired_restore_surface(option_id)
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
///
/// R3-M01（2026-11-01）：② 不再只收 `-Name Start` —— 同一脚本里改的**所有**值都要进
/// 基线，见 [`walk_ps_ops_for_start`] 的新语义。函数名保留历史叫法：`overview.rs` 的
/// D0 三侧覆盖矩阵按名字引用它，改名要同步那个文件。
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

/// 递归收集 pwsh op 列表里**全部值写入**的落点（含 `if (Test-Path …)` 守卫的内层）。
///
/// R3-M01（2026-11-01）：此前只收 `name == "Start"`，于是同一脚本里改的其它值拿不到
/// 基线（`Keyboard Layout::Scancode Map`、`SmoothMouseXCurve`、`CommDucking`、
/// `NOC_GLOBAL_SETTING_TOASTS_ENABLED`、`DelayedAutoStart`… 清单见 R3 分报告的探针输出）。
/// 危害不是「少记几个值」：还原按旧基线写回 → 回读只验那几条 → 销账摘灰 →
/// 回执 `success:true, restored:N`，被改的原值**永久丢失**；`peripheral_winkey_off`
/// 更狠，它的 restore 段是 `Remove-ItemProperty "Scancode Map"`，本来有键盘重映射的
/// 用户「还原」一下等于删掉自己的配置。
///
/// 基线与声明面共用本函数，所以「执行写什么」与「能还原什么」结构上不可能再漂：
/// 每个 `PsOp::ValueWrite` 都是一个可读可写回的 (hive, subkey, name)。
fn walk_ps_ops_for_start(ops: &[crate::engine::pssteps::PsOp], out: &mut Vec<RegTarget>) {
    use crate::engine::pssteps::{Hive, PsOp};
    // 五个 hive 全部可读可写（`overview::reg_hive` 认这五个长名）；
    // 旧实现只映射 Lm/Cu 是因为它只收 Services 树下的 Start，与 hive 无关。
    let root_of = |h: Hive| -> &'static str {
        match h {
            Hive::Lm => "HKEY_LOCAL_MACHINE",
            Hive::Cu => "HKEY_CURRENT_USER",
            Hive::Cr => "HKEY_CLASSES_ROOT",
            Hive::U => "HKEY_USERS",
            Hive::Cc => "HKEY_CURRENT_CONFIG",
        }
    };
    for op in ops {
        match op {
            PsOp::ValueWrite { hive, subkey, name, .. } => {
                out.push(RegTarget { root: root_of(*hive).into(), sub: subkey.clone(), key: name.clone() });
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
    let low = cmd.to_ascii_lowercase();
    let start_with_value = low.contains("/v start") || low.contains("/v \"start\"");

    // A：注册表路径形态
    if start_with_value {
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

    // B：sc config 形态。
    // 审查 M-09：原先只取**第一个** `config`，一条 cmd 串多个
    // `sc config A start= disabled & sc config B start= demand` 时只有 A 进基线，
    // 而 A 分支（上面）是循环 —— 两侧覆盖能力不对称。这里改成遍历全部出现位置。
    //
    // 边界：仍然要求这一步**确实写了 start=**（外层前置门），否则不收 ——
    // 宁可漏收（少一条基线）也不要把无关命令当成改启动类型收进来。
    if low.contains("start=") {
        let mut from = 0usize;
        while let Some(rel) = low[from..].find("config") {
            let at = from + rel;
            // `config` 必须是独立的词，左右两侧都得有边界：
            //   右侧（下面判）—— `configure` / `configuration` 的子串后面紧跟服务名字符；
            //   左侧 —— `autoconfig` / `reconfig` 这类更长单词的前半段。
            // （原先取首个 find 时这两侧同样会误收；循环化后命中面变大，词边界必须钉住。）
            let left_ok = at == 0 || cmd[..at].ends_with(char::is_whitespace);
            if !left_ok {
                from = at + "config".len();
                continue;
            }
            let after = &cmd[at + "config".len()..];
            if !after.starts_with(char::is_whitespace) {
                from = at + "config".len();
                continue;
            }
            let rest = after.trim_start();
            let name: String = rest.chars().take_while(|c| is_name_char(*c)).collect();
            if !name.is_empty() && name.len() <= 64 {
                names.push(name);
            }
            // 推进量恒 ≥1：find 命中必然 from 严格增大，不会死循环。
            from = at + "config".len();
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
    let Some(_write_guard) = super::apply::OptWriteGuard::acquire() else {
        return json!({ "success": false, "message": "另一个优化写入正在进行" });
    };
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
    if let Some(receipt) = backup_reg_deferred_receipt(sysinfo::is_admin()) {
        return receipt;
    }
    let Some(values) = read_reg_values(&targets) else {
        log::write_log("error", "优化项注册表备份异常: 读取/解析失败");
        return json!({ "success": false, "message": "读取当前注册表值失败" });
    };
    // v5-K01 批次 4（R7-M05）：读-改-写收进 update_opt_backups——读失败（Corrupt）
    // 拒写并如实回执，不再把基于空表的「新基线」覆写出去。KeptExisting 时内容不变，
    // update_json 落盘的是等价内容（旧链此分支刻意不落盘，语义等价）。
    let mut count = 0usize;
    let mut kept = false;
    let res = update_opt_backups(|map| match insert_backup_baseline(map, &option_id, values.clone()) {
        BackupInsert::Inserted => {
            count = values.len();
            Ok(())
        }
        BackupInsert::KeptExisting(n) => {
            count = n;
            kept = true;
            Ok(())
        }
        BackupInsert::MapNotObject => Err("注册表备份文件结构异常".into()),
    });
    if let Err(e) = res {
        log::write_log("error", &format!("优化项注册表备份失败: {option_id} {e}"));
        return json!({ "success": false, "message": format!("注册表备份写入失败: {e}") });
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

/// 台账管理员摘要的拒因码（R3-K01）：`None` = `ok` 放行。
///
/// 不可识别的状态同样拒（fail-closed）：`reg_backup_admin_seal_state` 以后若新增
/// 状态，必须先在这里表态，不能因为「没写分支」就落到放行。
pub(super) fn seal_refusal_reason(state: &str) -> Option<&'static str> {
    match state {
        "ok" => None,
        "missing" => Some("sealMissing"),
        "mismatch" => Some("sealMismatch"),
        "unreadable" => Some("sealUnreadable"),
        "corrupt" => Some("sealCorrupt"),
        _ => Some("sealUnknown"),
    }
}

/// 摘要非 `ok` 时的用户可见理由（与拒因码一一对应，不复用「无备份记录」那套文案）。
pub(super) fn seal_refusal_message(state: &str) -> &'static str {
    match state {
        "missing" => {
            "优化项备份台账未封条：没有可用的管理员摘要（旧版本生成的台账，或摘要已被清除）。这不是内容被改动的结论；请先重新执行一次该项优化（执行前的自动备份会重新为台账加摘要），再点还原"
        }
        "mismatch" => {
            "优化项备份台账的摘要与管理员记录不一致（台账内容被改动过），已拒绝还原；请检查该台账是否被其它程序修改"
        }
        "unreadable" => "优化项备份台账或其摘要不可读，无法核对完整性，已拒绝还原",
        "corrupt" => "优化项备份台账的摘要记录损坏，无法核对完整性，已拒绝还原",
        _ => "优化项备份台账的摘要状态异常，无法核对完整性，已拒绝还原",
    }
}

/// 「需要管理员」回执（非提权实例的**唯一**出口文案，R3-K01 前后不变）。
fn need_admin_receipt() -> Value {
    json!({ "success": false, "needAdmin": true, "message": "还原优化需要管理员权限，请先提权" })
}

/// 还原入口的前置闸（R3-K01）：**guard 之后、读台账之前**，先过管理员门槛再过台账摘要。
///
/// 纯判据、不读写任何状态 —— 返回 `Err(回执)` 的调用点结构上没有任何注册表写入，
/// 所以「非管理员 / 摘要非 ok」两类拒绝都是零写入。
fn restore_preflight(is_admin: bool, seal_state: &str) -> Result<(), Value> {
    if !is_admin {
        return Err(need_admin_receipt());
    }
    if let Some(reason) = seal_refusal_reason(seal_state) {
        return Err(json!({
            "success": false,
            "restoreRefused": true,
            "ledgerSeal": seal_state,
            "reason": reason,
            "message": seal_refusal_message(seal_state),
        }));
    }
    Ok(())
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
    let Some(_write_guard) = super::apply::OptWriteGuard::acquire() else {
        return json!({ "success": false, "message": "另一个优化写入正在进行" });
    };
    let option_id = option_id.unwrap_or_default();
    // 退役项已不在目录里，但它们的备份必须还能还原（v2-M14）；两份清单都不认的 id 仍然拒。
    if find_option(&option_id).is_none() && !is_retired_id(&option_id) {
        return json!({ "success": false, "message": "未知的优化选项" });
    }
    // 审查 2026-09-27 M3：值级还原要写回 HKLM/HKCU 备份值，非管理员必然写失败且
    // 此前无任何提示（与 optimizer_run 的提权门槛对齐，needAdmin 走前端提权链）。
    // R3-K01（2026-11-01）：台账是用户可写明文，必须在**读它之前**先核对管理员摘要
    // —— 「同用户改台账 → 用户点一次还原」否则就是一条提权任意写。摘要只对提权实例
    // 可读（HKLM），非提权一律先拒，不读摘要也不读台账内容。
    if !sysinfo::is_admin() {
        return need_admin_receipt();
    }
    let ledger_path = opt_backup_file();
    // 台账不存在 = 确无备份记录：保持既有回执形状（missing/absent），
    // 不冒充「摘要不可读」（后者会把用户指向「台账被改过」的结论）。
    if opt_backup_absent(&ledger_path) {
        return json!({ "success": false, "missing": true, "reason": "absent", "message": "无备份记录" });
    }
    let digest = crate::engine::hash::sha256_file(&ledger_path).ok();
    let seal_state =
        crate::engine::reg_backup::reg_backup_admin_seal_state("optimizer", &ledger_path, digest.as_deref());
    if let Err(resp) = restore_preflight(true, seal_state) {
        log::write_log("warn", &format!("优化项还原被拒（台账摘要 {seal_state}）: {option_id}"));
        return resp;
    }
    // v5-K01 批次 4：只读查 entry。A1-M04：台账读不动必须与「无备份记录」分开。
    let map = match load_opt_backups_state() {
        Ok(m) => m,
        Err(e) => {
            return json!({
                "success": false,
                "missing": false,
                "ledgerUnreadable": true,
                "reason": "unreadable",
                "message": e,
            });
        }
    };
    let entry = map.get(&option_id).cloned();
    let Some(entry) = entry else {
        return json!({ "success": false, "missing": true, "reason": "absent", "message": "无备份记录" });
    };
    // R3-M02：逐条封条——整本封条 ok 只证明「上次整本写后没人改过」，
    // 合法写 B 会重签整本；这条才是 A 条被篡改后仍能拒绝的依据。
    match entry_seal_state(&option_id, &entry) {
        "ok" => {}
        "missing" => {
            // 整本封条已由 restore_preflight 判 ok：这是升级前的旧条目，补签后继续。
            if !seal_entry(&option_id, &entry) {
                return json!({
                    "success": false,
                    "restoreRefused": true,
                    "message": "备份条目逐条封条缺失且补签失败，已拒绝还原"
                });
            }
        }
        other => {
            log::write_log("warn", &format!("优化项还原被拒（条目封条 {other}）: {option_id}"));
            return json!({
                "success": false,
                "restoreRefused": true,
                "ledgerSeal": other,
                "message": "备份条目与管理员记录不一致（可能被改动），已拒绝还原"
            });
        }
    }
    let values = entry.get("values").and_then(|v| v.as_array()).cloned();
    let Some(values) = values.filter(|a| !a.is_empty()) else {
        return json!({
            "success": false,
            "missing": true,
            "reason": "empty",
            "message": "备份记录为空（可能上次备份未写入完整），无法还原"
        });
    };
    let restored = values.len();

    // 先看能不能构造出还原操作（构造失败即无可核对项，直接拒）。
    // P0-3：拒因逐项如实上屏（只含序号与错误码名）并落日志；备份记录保留，
    // 用户可查日志后重试 —— 这条链永远不靠猜着删。
    let ops = match build_restore_ops(&option_id, &values) {
        Ok(o) => o,
        Err(e) => {
            log::write_log("warn", &format!("优化项还原被拒: {option_id}（{e}）"));
            return json!({
                "success": false,
                "restoreRefused": true,
                "message": format!("{e}；已保留备份记录，可查日志后重试"),
            });
        }
    };
    // R3-M02（v7.2 C04，AGENTS §3）：值级还原马上要写回 HKLM/HKCU 备份值——
    // 动手前把日志强制落盘，防尾部日志丢失（与 optimizer_run 执行链同口径）。
    log::flush_sync();
    let restore_failures = restore_backup_values_with_report(&ops);
    if !restore_failures.is_empty() {
        let first = &restore_failures[0];
        return json!({
            "success": false,
            "message": format!(
                "还原失败 {} 项，首个坐标 {}\\{}::{}（{}）",
                restore_failures.len(), first.hive, first.key, first.value, first.code
            ),
        });
    }
    // M3：写完**独立回读**验证。RegSetValueExW 返回成功不等于「值写对了」——
    // 类型标签映射错、字节序错、REG_MULTI_SZ 的双 NUL 终止漏一个都会让 API 成功
    // 而值是错的。改过的 optimizer_run 有执行后回读校验，还原侧此前一直缺这一环。
    //
    // fail-closed：回读不一致时**保留备份记录**并报失败，让用户能再试一次 ——
    // 清掉记录就等于删掉了唯一的还原依据。
    let (checked, mismatched) = verify_restore_ops(ops.as_slice());
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
    // v5-K01 批次 4（R7-M05）：清理备份记录走 update_opt_backups——回读校验已通过，
    // 台账清理失败必须如实回执（记录留下可重试），不许静默。
    if let Err(e) = update_opt_backups(|m| {
        if let Some(o) = m.as_object_mut() {
            o.remove(&option_id);
        }
        Ok(())
    }) {
        log::write_log("error", &format!("优化项还原后清理备份记录失败: {option_id} {e}"));
        return json!({ "success": false, "message": format!("还原完成但备份记录清理失败: {e}") });
    }
    // R3-L07：销账与摘灰写不进去时不静默 —— 成功回执里点名「界面状态可能滞后」。
    let note = format!(
        "{}{}",
        ledger_note("还原销账", opt_state::remove(&option_id)),
        ledger_note("摘灰", opt_state::set_detected_entry(&option_id, false)),
    );
    log::write_log("info", &format!("优化项注册表已按备份还原: {option_id}（{restored} 项）"));
    json!({ "success": true, "restored": restored, "message": format!("已按备份还原{note}") })
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
            // R5c-M02：空元素必须逐项保留（读侧已保真）——过滤掉再写回会得到不同的值，
            // 而回读自比对又看不出来。末尾空元素与双 NUL 终止同形，属字符串表示法的固有边界。
            if !data.is_empty() {
                for part in data.split('\0') {
                    v.extend(part.encode_utf16().flat_map(|w| w.to_le_bytes()));
                    v.extend_from_slice(&[0, 0]);
                }
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

/// 已按**声明面**（在册项 `option_targets` / 退役项历史表 / 频率覆写硬编码坐标）
/// 对拍过的还原操作集合（R3-K01，2026-11-01）。
///
/// 为什么需要 newtype：旧实现的 `build_restore_ops` 只校验 hive 名，`RestoreOp` 可以
/// 自由构造 —— 任何调用点（或改错顺序的旧调用点）都能绕开目标核对直接写 HKLM。
/// 字段私有 + [`restore_backup_values`] 只收本类型之后，「没经过目标准入的还原操作」
/// 在类型上就不存在写出口。
#[derive(Debug, PartialEq)]
pub(super) struct AdmittedRestoreOps(Vec<RestoreOp>);

impl AdmittedRestoreOps {
    pub(super) fn as_slice(&self) -> &[RestoreOp] {
        &self.0
    }

    /// 真机探针专用（`HKCU` 临时探针键不在任何优化项的声明面内）。只在测试构建里
    /// 存在，生产二进制没有这条路径 —— 「唯一构造点」不靠自觉。
    #[cfg(test)]
    pub(super) fn for_test(ops: Vec<RestoreOp>) -> Self {
        Self(ops)
    }
}

/// 把备份条目转成**已准入**的还原操作（R3-K01 第二道闸）。
///
/// 两道校验都在这里落：
/// 1. 条目自身形态（[`encode_restore_ops`]：presence 三态、hive 合法、值编码可逆）；
/// 2. 每个 `(hive, sub, key)` 必须落在该 id 的**声明面**内（大小写 / 分隔符归一后全等）。
///
/// 任一条不满足即整批 `Err`（不产生半套操作）。声明面来源见
/// [`declared_restore_surface`]；退役项无历史表时 fail-closed —— 绝不因为「查不到当年
/// 写过什么」就放行任意目标。
pub(super) fn build_restore_ops(option_id: &str, values: &[Value]) -> Result<AdmittedRestoreOps, String> {
    let declared = declared_restore_surface(option_id).ok_or_else(|| {
        if is_retired_id(option_id) {
            if RETIRED_SURFACE_UNRECOVERABLE.contains(&option_id) {
                format!(
                    "退役项「{option_id}」没有可核对的还原目标（历史定义早于 git 基线，无法恢复），已拒绝还原；请按该项退役说明手动回退"
                )
            } else {
                format!(
                    "退役项「{option_id}」没有登记历史还原目标表（需补录后才能按备份还原），已拒绝还原"
                )
            }
        } else {
            format!("「{option_id}」没有可核对的还原目标声明面，已拒绝还原")
        }
    })?;
    Ok(AdmittedRestoreOps(encode_restore_ops(values, Some(declared.as_slice()))?))
}

/// 测试构建专用：跳过目标准入的编码入口（真机探针键 / 纯编码单测）。
///
/// `#[cfg(test)]` —— 生产构建里不存在，所以「写入必须已经目标准入」有类型兜底，
/// 不是靠调用方自觉。
#[cfg(test)]
pub(super) fn build_restore_ops_unadmitted(values: &[Value]) -> Result<Vec<RestoreOp>, String> {
    encode_restore_ops(values, None)
}

/// 还原操作的编码本体；`declared = None` 只给测试构建用（见
/// [`build_restore_ops_unadmitted`]），生产路径一律经 [`build_restore_ops`] 传入声明面。
///
/// 旧实现（`backup_restore_lines`）在这里生成 PS 命令行，靠单引号串 + `''` 转义把
/// 不可信值锁住（v2-K2，有 3 条回归测试钉着）。改原生后那个攻击面整个消失 ——
/// 值不再经过任何解析器，`A$(whoami)` 就是要写进注册表的字面字节。
///
/// P0-3 的删除闸门：**只有 `presence=absent` 才生成 Delete**。
/// - `presence=unknown`（当年读不出来）与「旧记录无 presence 且 exists=false」
///   （legacyUnknown，P0-3 之前的备份分不清两种含义）→ 逐项收集拒因，整批 `Err`；
///   绝不产出半套操作 —— 写一半删一半比全不还原更难对账，且拒因里只允许出现
///   逐项序号与错误码名（`unknownReason` 由读侧生成，不含路径/键名/值）。
/// - 旧记录无 presence 但 exists=true：读成功过才会带 type/data，可信，照常写回。
///
/// R3-K01：目标核对放在 presence 判定之后、值编码之前 —— 状态存疑的条目先按 P0-3
/// 口径拒，不为越界目标做无谓解码；越界条目按序号点名后整批拒。
fn encode_restore_ops(values: &[Value], declared: Option<&[RegTarget]>) -> Result<Vec<RestoreOp>, String> {
    let mut ops = Vec::with_capacity(values.len());
    let mut refusals: Vec<String> = Vec::new();
    for (idx, v) in values.iter().enumerate() {
        let hive = v.get("hive").and_then(|x| x.as_str()).unwrap_or("LocalMachine").to_string();
        if restore_hive(&hive).is_none() {
            return Err(format!("未知 hive: {hive}"));
        }
        let sub = v.get("sub").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let key = v.get("key").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let presence = match backup_presence(v) {
            Some(p) => p,
            None if v.get("exists").and_then(|x| x.as_bool()).unwrap_or(false) => "value",
            None => {
                refusals.push(format!("第 {idx} 项：旧备份无 presence 且 exists=false（legacyUnknown，无法确认不存在）"));
                continue;
            }
        };
        if presence == "unknown" {
            let reason = v.get("unknownReason").and_then(|x| x.as_str()).unwrap_or("未记录");
            refusals.push(format!("第 {idx} 项：presence=unknown（拒因: {reason}）"));
            continue;
        }
        // R3-K01 第二道闸：目标必须在本项声明的还原面内。
        if let Some(declared) = declared {
            if !coord_in_surface(declared, &hive, &sub, &key) {
                refusals.push(format!(
                    "第 {idx} 项：还原目标 {hive}\\{sub}::{key} 不在本项声明的还原面内（拒绝写入/删除）"
                ));
                continue;
            }
        }
        match presence {
            "absent" => ops.push(RestoreOp::Delete { hive, sub, key }),
            _ => {
                let typ = v.get("type").and_then(|x| x.as_str()).unwrap_or("REG_SZ").to_string();
                let data = v.get("data").and_then(|x| x.as_str()).unwrap_or("");
                let bytes = restore_write_bytes(&typ, data)?;
                ops.push(RestoreOp::Write { hive, sub, key, typ, bytes });
            }
        }
    }
    if !refusals.is_empty() {
        return Err(format!("注册表备份存在无法确认状态或越界的条目，拒绝还原（不产生删除）：{}", refusals.join("；")));
    }
    Ok(ops)
}

/// 目标是否落在声明面内（大小写 / `\`↔`/` / 首尾分隔符归一后全等）。
///
/// 只服务**对拍**：真正写入用的 `hive`/`sub`/`key` 仍是台账原值（`restore_hive`
/// 按别名表解析），归一不改变任何被写下的字节。
fn coord_in_surface(declared: &[RegTarget], hive: &str, sub: &str, key: &str) -> bool {
    let Some(h) = norm_hive(hive) else {
        return false;
    };
    let s = norm_sub(sub);
    let k = norm_key(key);
    declared
        .iter()
        .any(|t| norm_hive(&t.root) == Some(h) && norm_sub(&t.sub) == s && norm_key(&t.key) == k)
}

/// hive 别名归一（`LocalMachine` / `HKEY_LOCAL_MACHINE` 等价）；不认识的一律 `None`。
fn norm_hive(name: &str) -> Option<&'static str> {
    let n = name.trim();
    let eq = |a: &str| n.eq_ignore_ascii_case(a);
    Some(if eq("LocalMachine") || eq("HKEY_LOCAL_MACHINE") {
        "HKEY_LOCAL_MACHINE"
    } else if eq("CurrentUser") || eq("HKEY_CURRENT_USER") {
        "HKEY_CURRENT_USER"
    } else if eq("ClassesRoot") || eq("HKEY_CLASSES_ROOT") {
        "HKEY_CLASSES_ROOT"
    } else if eq("Users") || eq("HKEY_USERS") {
        "HKEY_USERS"
    } else if eq("CurrentConfig") || eq("HKEY_CURRENT_CONFIG") {
        "HKEY_CURRENT_CONFIG"
    } else {
        return None;
    })
}

/// 子键归一：`\` 与 `/` 等价、大小写不敏感、首尾分隔符忽略（注册表路径本身大小写不敏感）。
fn norm_sub(sub: &str) -> String {
    let t = sub.trim().replace('/', "\\");
    t.trim_matches('\\').to_ascii_lowercase()
}

/// 值名归一（大小写不敏感）
fn norm_key(key: &str) -> String {
    key.trim().to_ascii_lowercase()
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
        // R3-M01（v7.2 C04）：faithful 读侧（decode_reg_value_bytes flatten=false）
        // 对真 EXPAND_SZ 值回的标签就是 "REG_EXPAND_SZ" —— 旧实现把它归成
        // "REG_SZ"，新式备份（faithful 读、typ=REG_EXPAND_SZ）的值级还原**恒判
        // 不一致**：明明还原成功却永久报失败、备份记录永远清不掉（fail-closed
        // 保留重试 = 永远重试）。老备份（typ=REG_SZ 记法）走 REG_SZ 分支，
        // 写侧本就按 REG_SZ 写回、读侧标签也回 REG_SZ，不受影响。
        "REG_EXPAND_SZ"
    } else {
        "REG_SZ"
    }
}

/// 按**已准入**的还原操作回写（任一失败即返回 false；调用方据此报「还原不完整」）。
///
/// M-11（审查 2026-10-07）：原签名收 `&[Value]`，内部再 `build_restore_ops` 一次 ——
/// 调用方（`optimizer_restore_reg` / `recycle_freq_override`）为了先判可构造性已经建过
/// 一遍 ops，等于同一份备份解析两次，且写失败时无法定位到具体条目。改成收 ops，
/// 构造只发生一次，回读校验（`verify_restore_ops`）也复用同一份 ops。
///
/// R3-K01：只收 [`AdmittedRestoreOps`] —— 这是「写入必须已经过目标准入」的类型级闸门。
pub(super) fn restore_backup_values_with_report(ops: &AdmittedRestoreOps) -> Vec<ValueRestoreFailure> {
    use crate::engine::native;
    let mut failures: Vec<ValueRestoreFailure> = Vec::new();
    for op in ops.as_slice() {
        let ok = match op {
            RestoreOp::Write { hive, sub, key, typ, bytes } => {
                if let Some(h) = restore_hive(&hive) {
                    native::reg_restore_write(h, &sub, &key, restore_reg_kind(&typ), &bytes)
                } else {
                    false
                }
            }
            RestoreOp::Delete { hive, sub, key } => match restore_hive(&hive) {
                Some(h) => !h.is_invalid() && native::reg_restore_delete(h, &sub, &key),
                None => false,
            },
        };
        if !ok {
            failures.push(match op {
                RestoreOp::Write { hive, sub, key, .. } => ValueRestoreFailure {
                    hive: hive.clone(),
                    key: sub.clone(),
                    value: key.clone(),
                    code: "writeFailed".into(),
                },
                RestoreOp::Delete { hive, sub, key } => ValueRestoreFailure {
                    hive: hive.clone(),
                    key: sub.clone(),
                    value: key.clone(),
                    code: "deleteFailed".into(),
                },
            });
        }
    }
    if !failures.is_empty() {
        let first = &failures[0];
        crate::engine::log::write_log(
            "error",
            &format!(
                "值级还原失败 {} 项，首个坐标 {}\\{}::{}（{}）",
                failures.len(), first.hive, first.key, first.value, first.code
            ),
        );
    }
    failures
}

pub(super) fn restore_backup_values(ops: &AdmittedRestoreOps) -> bool {
    restore_backup_values_with_report(ops).is_empty()
}

#[derive(Debug, Clone)]
pub(super) struct ValueRestoreFailure {
    hive: String,
    key: String,
    value: String,
    code: String,
}

#[cfg(test)]
mod svc_names_tests {
    use super::svc_names_writing_start;

    /// B 分支单发形态（回归护栏：循环化后单条仍要收得到）。
    #[test]
    fn sc_config_单条() {
        assert_eq!(
            svc_names_writing_start("sc config Spooler start= disabled"),
            vec!["Spooler".to_string()]
        );
    }

    /// 审查 M-09 的正向断言：**一条 cmd 串多个 `sc config` 时必须全部收齐**。
    /// 修复前只取第一个 `config`，SvcB 会整条漏掉基线 ⇒ 优化后再「还原」时
    /// SvcB 的启动类型永远回不去出厂值。
    #[test]
    fn sc_config_一条串多个要收齐() {
        let got = svc_names_writing_start(
            "sc config Spooler start= disabled & sc config Schedule start= demand",
        );
        assert_eq!(
            got,
            vec!["Schedule".to_string(), "Spooler".to_string()],
            "两个服务名都必须进基线（结果已排序去重）"
        );
    }

    /// 三个及以上 + 大小写混写：确认循环推进量不会漏掉靠后的命中。
    #[test]
    fn sc_config_三个且大小写混写() {
        let got = svc_names_writing_start(
            "SC CONFIG Alpha start= disabled; sc config Beta start= demand; Sc Config Gamma start= delayed-auto",
        );
        assert_eq!(
            got,
            vec!["Alpha".to_string(), "Beta".to_string(), "Gamma".to_string()]
        );
    }

    /// 没写 `start=` 就不收（沿用既有前置门：宁可漏收也不收无关命令）。
    #[test]
    fn 只改别的参数不收() {
        assert!(svc_names_writing_start("sc config Spooler binPath= \"C:\\x.exe\"").is_empty());
    }

    /// `config` 前后没有词边界时不得误命中：右侧挡住 `configure`，
    /// 左侧挡住 `autoconfig`。修复前两边都会凭空收出一条垃圾服务名。
    #[test]
    fn config_缺词边界不收() {
        // 右侧：`configure` 的前缀
        assert!(svc_names_writing_start("set CONFIGURE=1 & echo start= x").is_empty());
        // 左侧：`autoconfig` 的后半段
        assert!(svc_names_writing_start("set AUTOCONFIG=1 & echo start= x").is_empty());
    }

    /// A 分支（注册表形态）循环能力不受影响。
    #[test]
    fn reg_add_多条也收齐() {
        let got = svc_names_writing_start(
            r#"reg add "HKLM\SYSTEM\CurrentControlSet\Services\Alpha" /v Start /t REG_DWORD /d 4 /f & reg add "HKLM\SYSTEM\CurrentControlSet\Services\Beta" /v Start /t REG_DWORD /d 4 /f"#,
        );
        assert_eq!(got, vec!["Alpha".to_string(), "Beta".to_string()]);
    }
}


#[cfg(test)]
mod m01_type_label_tests {
    use super::*;

    /// R3-M01（v7.2 C04）判红点：备份 typ=REG_EXPAND_SZ ⇒ want_kind=REG_EXPAND_SZ
    /// ⇒ canonical 标签必须等于 faithful 读侧的 "REG_EXPAND_SZ"。旧实现归成
    /// "REG_SZ" ⇒ 值级还原恒判不一致（还原成功却永久报失败、备份清不掉）。
    #[test]
    fn expand_sz_回读标签不再恒判不一致() {
        assert_eq!(
            canonical_type_label(restore_reg_kind("REG_EXPAND_SZ")),
            "REG_EXPAND_SZ"
        );
        // 其余标签口径不变（回归护栏）
        assert_eq!(canonical_type_label(restore_reg_kind("REG_SZ")), "REG_SZ");
        assert_eq!(canonical_type_label(restore_reg_kind("REG_DWORD")), "REG_DWORD");
        assert_eq!(canonical_type_label(restore_reg_kind("REG_BINARY")), "REG_BINARY");
    }

    /// R5c-M02：写侧同样必须保留空元素 —— 读侧保真 + 写侧过滤，等于还原写回另一个值。
    #[test]
    fn multi_sz_写侧保留空元素_空值仍是空多串() {
        // "a\0\0b" = ["a", "", "b"]：元素间单 NUL、末尾双 NUL
        let bytes = restore_write_bytes("REG_MULTI_SZ", "a\u{0}\u{0}b").unwrap();
        assert_eq!(
            bytes,
            vec![0x61, 0, 0, 0, 0, 0, 0x62, 0, 0, 0, 0, 0],
            "空元素必须在写回字节里占位（否则还原写回不同的值）"
        );
        assert_eq!(
            restore_write_bytes("REG_MULTI_SZ", "").unwrap(),
            vec![0, 0],
            "零元素仍是双 NUL 终止的空 MULTI_SZ"
        );
    }

    /// R3-U02 配套真机探针：真实 HKCU 探针键上做 EXPAND_SZ 值级还原往返 ——
    /// 写入（restore_backup_values）→ 独立回读（verify_restore_ops）必须判一致。
    /// 旧实现在这条链上恒 mismatched=1（标签口径分叉），本探针一发就红。
    #[test]
    #[ignore = "真机探针：写真实 HKCU 探针键并回读（复核 R3-M01 读写同链），发布前人工 --ignored 跑"]
    fn expand_sz_真机往返回读一致() {
        use crate::engine::native;
        const SUB: &str = "SOFTWARE\\TrimProbeM01";
        const NAME: &str = "probe_expand";
        let ops = vec![RestoreOp::Write {
            hive: "CurrentUser".into(),
            sub: SUB.into(),
            key: NAME.into(),
            typ: "REG_EXPAND_SZ".into(),
            bytes: restore_write_bytes("REG_EXPAND_SZ", "%SystemRoot%\\Temp").unwrap(),
        }];
        // 起手先清一次（上轮残留会让首写撞非预期旧值）
        let _ = native::reg_key_remove(native::hive_hkcu(), SUB, true);
        // R3-K01：探针键不在任何优化项的声明面内，测试构建走准入旁路（`for_test`）。
        let admitted = AdmittedRestoreOps::for_test(ops);
        assert!(restore_backup_values(&admitted), "EXPAND_SZ 值写回必须成功");
        let (checked, mismatched) = verify_restore_ops(admitted.as_slice());
        let _ = native::reg_key_remove(native::hive_hkcu(), SUB, true);
        assert_eq!(
            (checked, mismatched),
            (1, 0),
            "EXPAND_SZ 值级还原回读必须判一致（mismatched>0 = M01 病灶复发）"
        );
    }
}

#[cfg(test)]
mod p0_3_presence_tests {
    use super::*;

    /// 单测 1（P0-3 主病灶）：`presence=unknown` 的条目 ⇒ 编码层整批拒绝、
    /// 回执逐项点名拒因；同批里的合法 absent 条目也不得被带着产出半套操作 ——
    /// 写一半删一半比全不还原更难对账。
    /// （目标准入另由 `r3_k01_gate_tests` 覆盖；本模块只锁 presence 语义，
    /// 所以走 `build_restore_ops_unadmitted` 这条测试构建专用入口。）
    #[test]
    fn unknown_只回拒因不产删除() {
        let batch = vec![
            json!({ "hive": "LocalMachine", "sub": "S", "key": "K1",
                "presence": "value", "exists": true, "type": "REG_DWORD", "data": "1" }),
            json!({ "hive": "LocalMachine", "sub": "S", "key": "K2",
                "presence": "unknown", "exists": false, "unknownReason": "ERROR_ACCESS_DENIED" }),
            json!({ "hive": "LocalMachine", "sub": "S", "key": "K3",
                "presence": "absent", "exists": false }),
        ];
        let Err(msg) = build_restore_ops_unadmitted(&batch) else {
            panic!("unknown 条目必须整批拒绝（旧实现在这里生成 Delete，一次访问拒绝就删掉本来存在的值）");
        };
        assert!(msg.contains("拒绝还原"), "回执必须点名这是拒删: {msg}");
        assert!(msg.contains("ERROR_ACCESS_DENIED"), "回执必须逐项携带拒因（错误码名）: {msg}");
    }

    /// 单测 2：确认不存在的 `presence=absent` 仍照常生成 Delete（合法还原能力不削弱）。
    #[test]
    fn absent_仍产删除() {
        let ops = build_restore_ops_unadmitted(&[
            json!({ "hive": "LocalMachine", "sub": "S", "key": "K", "presence": "absent", "exists": false }),
        ])
        .expect("absent 应可构造");
        assert_eq!(ops, vec![RestoreOp::Delete {
            hive: "LocalMachine".into(), sub: "S".into(), key: "K".into(),
        }]);
    }

    /// 单测 3：P0-3 之前的旧记录（无 `presence` 且 `exists=false`）＝ legacyUnknown ——
    /// 当年分不清「不存在」还是「读不出来」，一律拒删并回传拒因；同类的 exists=true
    /// 旧记录仍可信（读成功过才会带 type/data）。
    #[test]
    fn 旧记录无presence且existsfalse_按存疑拒删() {
        let Err(msg) = build_restore_ops_unadmitted(&[
            json!({ "hive": "LocalMachine", "sub": "S", "key": "K", "exists": false }),
        ]) else { panic!("legacyUnknown 必须拒绝（旧实现把它当确认不存在直接生成 Delete）") };
        assert!(msg.contains("legacyUnknown"), "回执必须点名 legacyUnknown: {msg}");

        let ops = build_restore_ops_unadmitted(&[
            json!({ "hive": "LocalMachine", "sub": "S", "key": "K", "exists": true, "type": "REG_DWORD", "data": "4" }),
        ])
        .expect("旧记录 exists=true 仍按值写回");
        assert!(matches!(&ops[..], [RestoreOp::Write { .. }]), "应为一条 Write: {ops:?}");
    }

    /// `presence` 与 `exists` 的同源派生：条目构造器是唯一真源（P0-3 明令不得手写两份）。
    /// `unknown` 条目带错误码名、不带 type/data；`absent` 两者都不带（旧形状兼容）。
    #[test]
    fn 备份条目_presence唯一真源_exists为其派生() {
        use crate::engine::native::RegReadState;
        let e = backup_entry_from_state("CurrentUser", "S", "K", RegReadState::Absent);
        assert_eq!(e["presence"], "absent");
        assert_eq!(e["exists"], false);
        assert!(e.get("type").is_none() && e.get("data").is_none());

        let e = backup_entry_from_state(
            "CurrentUser", "S", "K",
            RegReadState::Unknown("ERROR_ACCESS_DENIED".into()),
        );
        assert_eq!(e["presence"], "unknown");
        assert_eq!(e["exists"], false);
        assert_eq!(e["unknownReason"], "ERROR_ACCESS_DENIED");
        assert!(e.get("type").is_none() && e.get("data").is_none());

        let e = backup_entry_from_state("CurrentUser", "S", "K", RegReadState::Value("REG_DWORD", "7".into()));
        assert_eq!(e["presence"], "value");
        assert_eq!(e["exists"], true);
        assert_eq!(e["type"], "REG_DWORD");
        assert_eq!(e["data"], "7");
    }

    /// 无法识别的 presence 取值按旧记录处理（fail-closed 进 legacyUnknown 拒删分支），
    /// 而不是猜一个新语义。
    #[test]
    fn 非法presence取值_按旧记录保守处理() {
        let Err(msg) = build_restore_ops_unadmitted(&[
            json!({ "hive": "LocalMachine", "sub": "S", "key": "K", "presence": "yes", "exists": false }),
        ]) else { panic!("不可识别 presence + exists=false 必须拒删") };
        assert!(msg.contains("legacyUnknown"), "{msg}");
    }
}

/// R3-K01（P0-2，2026-11-01）：优化还原的两道闸 —— 台账管理员摘要 + 目标收窄。
///
/// 判红对照（每条都能被以下改动打红）：
/// - 让 `seal_refusal_reason("missing")` 返回 `None` ⇒ `台账摘要状态_只有ok放行…` 红；
/// - 把 `restore_preflight` 的 is_admin 分支删掉 ⇒ `前置闸_未提权…` 红；
/// - 把补签从 `update_opt_backups` 摘掉 ⇒ `台账写入口必须补管理员摘要` 红；
/// - 把摘要闸挪到读台账之后 ⇒ `还原命令_摘要闸在读台账之前` 红；
/// - 把 `encode_restore_ops` 里的 `coord_in_surface` 判断删掉 ⇒
///   `在册项_声明面内放行_面外拒绝…` 与 `退役项_…` 红。
#[cfg(test)]
mod r3_k01_gate_tests {
    use super::*;

    /// R3-M02：逐条摘要必须对条目内容敏感（篡改任一条即换摘要）。
    #[test]
    fn r3_m02_entry_digest_changes_on_tamper() {
        let a = json!({ "at": "t", "values": [1, 2] });
        let b = json!({ "at": "t", "values": [1, 3] });
        assert_ne!(entry_digest(&a), entry_digest(&b));
        assert_eq!(entry_digest(&a), entry_digest(&a.clone()));
    }

    /// 摘要闸的纯判据：只有 `ok` 放行，其余（含不可识别状态）一律拒且拒因可辨。
    #[test]
    fn 台账摘要状态_只有ok放行且拒因可辨() {
        assert!(seal_refusal_reason("ok").is_none(), "ok 必须放行");
        for state in ["missing", "mismatch", "unreadable", "corrupt"] {
            let reason = seal_refusal_reason(state).unwrap_or_else(|| panic!("{state} 必须拒"));
            assert!(reason.starts_with("seal"), "{state} 的拒因码不可辨: {reason}");
            assert!(!seal_refusal_message(state).is_empty(), "{state} 没有用户可见理由");
        }
        // 拒因码必须两两不同 —— 折叠成同一个码，用户与日志就分不清「缺摘要」与「摘要不符」
        let codes: std::collections::HashSet<_> =
            ["missing", "mismatch", "unreadable", "corrupt", "未来新状态"]
                .iter()
                .map(|s| seal_refusal_reason(s).unwrap())
                .collect();
        assert_eq!(codes.len(), 5, "非 ok 状态的拒因码出现重复: {codes:?}");
        // 不可识别状态必须 fail-closed（新增状态不许因为「没写分支」而落到放行）
        assert!(seal_refusal_reason("some_future_state").is_some());
    }

    /// 「未提权」与「摘要异常」两类前置拒绝：回执可辨，且判据本身不读写任何状态
    /// （能在这条路径上跑到 `Ok`/`Err` 即证明它没有注册表写入）。
    #[test]
    fn 前置闸_未提权与摘要异常都必须拒() {
        let Err(resp) = restore_preflight(false, "ok") else { panic!("非管理员必须拒") };
        assert_eq!(resp["needAdmin"], true, "{resp}");

        let Err(resp) = restore_preflight(true, "mismatch") else { panic!("摘要不符必须拒") };
        assert_eq!(resp["restoreRefused"], true, "{resp}");
        assert_eq!(resp["reason"], "sealMismatch", "{resp}");
        assert_eq!(resp["ledgerSeal"], "mismatch", "{resp}");

        assert!(restore_preflight(true, "ok").is_ok(), "管理员 + 摘要 ok 必须放行");
        // 非管理员优先于摘要状态（用户先看到「请提权」，而不是一条他无力处理的摘要错）
        let Err(resp) = restore_preflight(false, "missing") else { panic!("非管理员必须拒") };
        assert_eq!(resp["needAdmin"], true, "{resp}");
    }

    /// R3-M01：未提权备份必须 deferred 且零写入；摘要失败必须显式失败。
    ///
    /// 判红自证：
    /// - 把 `backup_reg_deferred_receipt(false)` 改成恒 `None` ⇒ 前两条红；
    /// - 把 `update_opt_backups` 的摘要失败分支改回继续 `Ok(out)` ⇒ 结构断言红。
    #[test]
    fn 非提权备份延后且摘要失败不得静默() {
        let deferred = backup_reg_deferred_receipt(false).expect("非提权必须返回 deferred");
        assert_eq!(deferred["success"], true, "{deferred}");
        assert_eq!(deferred["deferred"], true, "{deferred}");
        assert_eq!(deferred["count"], 0, "{deferred}");
        assert!(
            backup_reg_deferred_receipt(true).is_none(),
            "管理员会话不得被 deferred 短路"
        );

        let missing = seal_refusal_message("missing");
        assert!(missing.contains("未封条"), "未封条必须与篡改分文案: {missing}");
        assert!(
            !missing.contains("内容被改动过"),
            "未封条不得被指认成内容被篡改: {missing}"
        );
        assert!(
            seal_refusal_message("mismatch").contains("内容被改动过"),
            "真正 mismatch 仍必须明确指认摘要不符"
        );

        let prod = include_str!("backup_restore.rs")
            .split("#[cfg(test)]\nmod r3_k01_gate_tests")
            .next()
            .unwrap_or_default();
        let update = prod
            .split("pub(super) fn update_opt_backups")
            .nth(1)
            .and_then(|s| s.split("\n}\n").next())
            .expect("找不到 update_opt_backups");
        assert!(
            update.contains("if !seal_opt_backup_ledger(&path)")
                && update.contains("台账未封条"),
            "摘要失败又退回静默成功：调用方会拿到 unusable 台账"
        );
        let command = prod
            .split("pub async fn optimizer_backup_reg")
            .nth(1)
            .and_then(|s| s.split("/// 台账管理员摘要的拒因码").next())
            .expect("找不到 optimizer_backup_reg");
        assert!(
            command.contains("backup_reg_deferred_receipt(sysinfo::is_admin())"),
            "optimizer_backup_reg 没有拦住非提权台账写入"
        );
    }

    /// 篡改台账 / 旧台账无摘要：摘要状态不可能为 `ok`，闸必须拒（零写入由结构保证）。
    #[test]
    fn 篡改或缺失摘要的台账_摘要状态不可能为ok() {
        struct SampleDir(std::path::PathBuf);
        impl Drop for SampleDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir = SampleDir(
            crate::engine::paths::lib_test_data_root()
                .join(format!("opt-seal-{}", std::process::id())),
        );
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).expect("建样本目录");
        let path = dir.0.join("optimizer-backups.json");
        std::fs::write(&path, br#"{"tf_fso":{"values":[]}}"#).unwrap();
        let before = crate::engine::hash::sha256_file(&path).expect("哈希失败");
        // 篡改（同用户可写目录里的另一份内容）
        std::fs::write(
            &path,
            br#"{"tf_fso":{"values":[{"hive":"LocalMachine","sub":"S","key":"K","presence":"value","exists":true,"type":"REG_SZ","data":"x"}]}}"#,
        )
        .unwrap();
        let after = crate::engine::hash::sha256_file(&path).expect("哈希失败");
        assert_ne!(before, after, "内容变了摘要必须变（否则摘要闸形同虚设）");
        // 该文件从未写过管理员摘要 ⇒ 任何摘要都比对不出 ok（旧无摘要文件必须拒）
        for digest in [&before, &after] {
            let state = crate::engine::reg_backup::reg_backup_admin_seal_state(
                "optimizer-p02-test",
                &path,
                Some(digest),
            );
            assert_ne!(state, "ok", "无摘要的台账不可能通过摘要闸（state={state}）");
            assert!(seal_refusal_reason(state).is_some(), "状态 {state} 必须被拒");
        }
        // 文件读不到（= 摘要无从比对）同样按 unreadable 拒，不许落到放行
        assert_eq!(
            crate::engine::reg_backup::reg_backup_admin_seal_state("optimizer-p02-test", &path, None),
            "unreadable"
        );
    }

    /// 落盘后补摘要：签的必须是**刚写下去的那份字节**；哈希失败时不盲签。
    #[test]
    fn 补摘要_签的是落盘字节_哈希失败不签() {
        struct SampleDir(std::path::PathBuf);
        impl Drop for SampleDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir = SampleDir(
            crate::engine::paths::lib_test_data_root()
                .join(format!("opt-seal-write-{}", std::process::id())),
        );
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).expect("建样本目录");
        let path = dir.0.join("optimizer-backups.json");
        let body = br#"{"tf_fso":{"values":[]}}"#;
        std::fs::write(&path, body).unwrap();

        let mut sealed: Vec<String> = Vec::new();
        assert!(
            seal_opt_backup_ledger_with(&path, crate::engine::hash::sha256_file, |sum| {
                sealed.push(sum.to_string());
                true
            }),
            "正常路径应报成功"
        );
        assert_eq!(
            sealed,
            vec![crate::engine::hash::sha256_bytes(body)],
            "签的不是落盘字节 ⇒ 还原闸会把合法台账判成 mismatch"
        );

        // 哈希失败 ⇒ 一次都不许调摘要写入（宁可让还原 fail-closed，也不签不知道内容的摘要）
        sealed.clear();
        assert!(!seal_opt_backup_ledger_with(
            &path,
            |_| Err("读不到".to_string()),
            |sum| {
                sealed.push(sum.to_string());
                true
            }
        ));
        assert!(sealed.is_empty(), "哈希失败时不得调用摘要写入");
    }

    /// 在册项：声明面内放行（hive 别名 / 分隔符 / 大小写归一后全等），面外整批拒并点名序号。
    #[test]
    fn 在册项_声明面内放行_面外拒绝并点名序号() {
        // `svc_mem_gb` 的声明面是硬编码单目标（不经目录数据）：HKLM\SYSTEM\ControlSet001\Control::SvcHostSplitThresholdInKB
        let ok = build_restore_ops(
            "svc_mem_gb",
            &[json!({
                "hive": "HKEY_LOCAL_MACHINE",
                "sub": "system/controlset001/control/",
                "key": "svchostsplitthresholdinkb",
                "presence": "value", "exists": true, "type": "REG_QWORD", "data": "8388608"
            })],
        )
        .expect("声明面内的目标必须放行（别名 / 分隔符 / 大小写归一后等价）");
        assert_eq!(ok.as_slice().len(), 1);
        assert_eq!(
            ok.as_slice()[0],
            RestoreOp::Write {
                hive: "HKEY_LOCAL_MACHINE".into(),
                sub: "system/controlset001/control/".into(),
                key: "svchostsplitthresholdinkb".into(),
                typ: "REG_QWORD".into(),
                bytes: 8388608i64.to_le_bytes().to_vec(),
            },
            "准入只做对拍，不得改写写入用的原值"
        );

        // 第二条越界（Run 键）⇒ 整批拒，回执点名越界项序号（0 基）
        let Err(msg) = build_restore_ops(
            "svc_mem_gb",
            &[
                json!({ "hive": "LocalMachine", "sub": "SYSTEM\\ControlSet001\\Control", "key": "SvcHostSplitThresholdInKB", "presence": "absent", "exists": false }),
                json!({ "hive": "LocalMachine", "sub": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "key": "TrimUpdate", "presence": "value", "exists": true, "type": "REG_SZ", "data": "C:\\x.exe" }),
            ],
        ) else { panic!("未声明目标必须整批拒绝（这正是 R3-K01 的反例形状）") };
        assert!(msg.contains("第 1 项"), "越界项必须点名序号: {msg}");
        assert!(msg.contains("不在本项声明的还原面内"), "{msg}");
    }

    /// 退役项：历史表内放行、越界拒绝；不可恢复的退役 id 与空声明面都 fail-closed。
    #[test]
    fn 退役项_历史目标放行_越界拒绝_不可恢复拒绝() {
        // tf_fso：当年 reg 块写 HKCU\System\GameConfigStore 的一组值（git 历史恢复）
        let ok = build_restore_ops(
            "tf_fso",
            &[json!({
                "hive": "CurrentUser", "sub": "System\\GameConfigStore", "key": "GameDVR_DSEBehavior",
                "presence": "absent", "exists": false
            })],
        )
        .expect("退役项的当年目标必须放行");
        assert_eq!(ok.as_slice().len(), 1);

        let Err(msg) = build_restore_ops(
            "tf_fso",
            &[
                json!({ "hive": "CurrentUser", "sub": "System\\GameConfigStore", "key": "GameDVR_DSEBehavior", "presence": "absent", "exists": false }),
                json!({ "hive": "LocalMachine", "sub": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "key": "TrimUpdate", "presence": "value", "exists": true, "type": "REG_SZ", "data": "C:\\x.exe" }),
            ],
        ) else { panic!("退役项越界目标必须拒绝（退役 id 是攻击面最大的入口）") };
        assert!(msg.contains("第 1 项"), "{msg}");

        // 历史定义早于 git 基线（maps_off）：无表 ⇒ 拒绝且理由可读，绝不放行任意目标
        let Err(msg) = build_restore_ops(
            "maps_off",
            &[json!({
                "hive": "LocalMachine", "sub": "SYSTEM\\CurrentControlSet\\Services\\MapsBroker", "key": "Start",
                "presence": "value", "exists": true, "type": "REG_DWORD", "data": "3"
            })],
        ) else { panic!("不可恢复的退役项必须 fail-closed") };
        assert!(msg.contains("退役项") && msg.contains("无法恢复"), "{msg}");

        // 当年只有 pwsh 设备写入（无注册表写点）的项：声明面为空 ⇒ 任何值级记录都不予还原
        let Err(msg) = build_restore_ops(
            "tf_gpu_msi",
            &[json!({
                "hive": "LocalMachine", "sub": "SYSTEM\\CurrentControlSet\\Enum\\PCI\\X", "key": "MSISupported",
                "presence": "value", "exists": true, "type": "REG_DWORD", "data": "1"
            })],
        ) else { panic!("空声明面的退役项必须拒绝") };
        assert!(msg.contains("不在本项声明的还原面内"), "{msg}");
    }

    /// 退役历史表与退役账本不许漂移：表里的 id 必须都还在账本里登记。
    #[test]
    fn 退役历史表_只含退役账本里的id() {
        let parsed: Value =
            serde_json::from_str(RETIRED_RESTORE_STEPS_JSON).expect("历史步骤表必须是合法 JSON");
        let map = parsed.as_object().expect("历史步骤表必须是对象");
        assert!(!map.is_empty(), "历史步骤表为空 ⇒ 退役项的合法还原全部被误拒");
        for id in map.keys() {
            assert!(is_retired_id(id), "历史步骤表里的 {id} 不在退役账本里 —— 表与账本漂移");
        }
        // 正向对照：能恢复的、不能恢复的都在预期状态（防整表被误删/误清空）
        for id in ["tf_fso", "power_off", "tf_hibern_off", "svc_fax_disable"] {
            assert!(retired_restore_steps(id).is_some(), "{id} 的历史定义必须可恢复");
            assert!(retired_restore_surface(id).is_some(), "{id} 必须产出声明面函数");
        }
        for id in ["maps_off", "clear_recent_docs_on_exit"] {
            assert!(retired_restore_steps(id).is_none(), "{id} 不该有历史定义（当年早于 git 基线）");
        }
    }

    /// 退役账本里的**每个** id 都必须有结论：要么有历史表，要么在不可恢复清单里。
    /// 新退役一条项却两处都不登记时本条红 —— 否则它会静默落进「需补录」拒因，
    /// 用户拿不到可操作的解释，审阅者也看不见这个缺口。
    #[test]
    fn 退役账本每个id都要有结论() {
        let parsed: Value =
            serde_json::from_str(RETIRED_RESTORE_STEPS_JSON).expect("历史步骤表必须是合法 JSON");
        let table = parsed.as_object().expect("历史步骤表必须是对象");
        for item in retired_items() {
            let id = item["id"].as_str().unwrap_or("");
            let has_table = table.contains_key(id);
            let known_unrecoverable = RETIRED_SURFACE_UNRECOVERABLE.contains(&id);
            assert!(
                has_table != known_unrecoverable,
                "{id}: 历史表与不可恢复清单必须恰好命中一个（hasTable={has_table}, unrecoverable={known_unrecoverable}）—— 新退役项必须先在这里表态"
            );
        }
        for id in RETIRED_SURFACE_UNRECOVERABLE {
            assert!(!table.contains_key(*id), "{id} 同时出现在历史表与不可恢复清单里");
            assert!(is_retired_id(id), "{id} 已不在退役账本里（清单该删行）");
        }
        // 反向对照：白名单没被顺手清空（清空后所有退役项都会落进「需补录」）
        assert!(!RETIRED_SURFACE_UNRECOVERABLE.is_empty());
    }

    /// 还原点频率覆写窄口子：只认硬编码坐标（`restore_freq_target`），其它 HKLM 目标一律拒。
    #[test]
    fn 还原点频率窄口子_只认硬编码坐标() {
        let target = super::super::restore_point::restore_freq_target();
        let ok = build_restore_ops(
            "tf_restore_point",
            &[json!({
                "hive": target.root, "sub": target.sub, "key": target.key,
                "presence": "absent", "exists": false
            })],
        )
        .expect("频率覆写的硬编码坐标必须放行");
        assert_eq!(ok.as_slice().len(), 1);

        let Err(msg) = build_restore_ops(
            "tf_restore_point",
            &[json!({
                "hive": "LocalMachine", "sub": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "key": "TrimUpdate",
                "presence": "absent", "exists": false
            })],
        ) else { panic!("窄口子之外的任何目标必须拒绝") };
        assert!(msg.contains("不在本项声明的还原面内"), "{msg}");
    }

    /// 结构护栏：写入口必须补管理员摘要（判红实验：摘掉补签调用，本条必须红）。
    #[test]
    fn 台账写入口必须补管理员摘要() {
        let src = include_str!("backup_restore.rs");
        let at = src
            .find("pub(super) fn update_opt_backups")
            .expect("找不到台账写入口");
        let rest = &src[at..];
        let end = rest.find("\n}\n").expect("update_opt_backups 函数体没闭合");
        let body = &rest[..end];
        assert!(body.contains("update_json"), "写入口没有走 security::update_json");
        assert!(
            body.contains("seal_opt_backup_ledger"),
            "update_opt_backups 没有补写管理员摘要 —— 台账无封条，还原闸会拒掉全部合法备份"
        );
    }

    /// 结构护栏：摘要闸必须在读台账之前（判红实验：把闸挪到 load 之后，本条必须红）。
    #[test]
    fn 还原命令_摘要闸在读台账之前() {
        let src = include_str!("backup_restore.rs");
        let at = src
            .find("pub async fn optimizer_restore_reg")
            .expect("找不到 optimizer_restore_reg");
        let rest = &src[at..];
        let seal = rest
            .find("reg_backup_admin_seal_state")
            .expect("optimizer_restore_reg 没有调 reg_backup_admin_seal_state —— 摘要闸缺失");
        let pre = rest.find("restore_preflight").expect("没有经过前置闸");
        let load = rest.find("load_opt_backups_state").expect("找不到读台账调用");
        assert!(seal < load, "摘要闸被挪到了读台账之后（{seal} vs {load}）—— 先信内容再验签等于没验");
        assert!(pre < load, "前置闸必须在读台账之前（{pre} vs {load}）");
    }
}

/// R3-M01 / R3-M02 / R3-M03（2026-11-01）：基线完整性三连。
///
/// 三者的共同形态是「写了但没记」：值级备份是没有 restore 段那一批项的唯一还原出口，
/// 基线漏一个写点，还原就按旧基线写回、回读只验那几条、销账摘灰、回 `restored:N`，
/// 被改的原值永久丢失且回执与账本里都不存在这件事。
///
/// 判红对照（每条都能被以下改动打红）：
/// - 把 `walk_ps_ops_for_start` 的 `ValueWrite` 分支改回 `if name == "Start"`
///   ⇒ `pwsh全部值写入都进基线` / `附带开关写面进基线与回读范围` 红；
/// - 把 `option_targets` 里的 extras 并入删掉 ⇒ `附带开关写面进基线与回读范围` 红；
/// - 把 `perf_wu_pause` 分支删掉 ⇒ `perf_wu_pause基线对齐生成器与检测侧表` 红；
/// - 把 `WU_PAUSE_VALUES` 少登记一个值 ⇒ 同上（与生成器/侧表三向对拍）；
/// - 把声明面收窄到空 ⇒ `新增基线目标能过还原闸_面外仍拒` 红（还原被自己拒掉）。
#[cfg(test)]
mod r3_m01_m03_baseline_tests {
    use super::*;

    /// 规范化成 `root\sub::key`（全小写）—— 注册表路径本身大小写不敏感，按字面量比会假红。
    fn surface_of(option_id: &str) -> Vec<String> {
        option_targets(option_id)
            .unwrap_or_default()
            .iter()
            .map(|t| format!("{}\\{}::{}", t.root, t.sub, t.key).to_ascii_lowercase())
            .collect()
    }

    fn assert_in_surface(option_id: &str, coord: &str) {
        let want = coord.to_ascii_lowercase();
        let got = surface_of(option_id);
        assert!(
            got.iter().any(|c| *c == want),
            "{option_id} 的基线/声明面里没有 {coord} —— 该写点改了值却拿不到基线，\
             还原后原值永久丢失（R3-M01 回归）；实收 {got:?}"
        );
    }

    fn admits(option_id: &str, entries: &[Value]) -> Result<usize, String> {
        build_restore_ops(option_id, entries).map(|ops| ops.as_slice().len())
    }

    /// 把 `root\sub::key` 拆回三个字段（测试里的坐标写法与 RegTarget 的拼法互为逆运算）。
    fn coord_parts(coord: &str) -> (String, String, String) {
        let (path, key) = coord.split_once("::").expect("坐标格式应为 root\\sub::key");
        let (root, sub) = path.split_once('\\').expect("坐标格式应为 root\\sub::key");
        (root.to_string(), sub.to_string(), key.to_string())
    }

    /// 断言该坐标既在基线/声明面内，也**过了第二道闸**（声明面内放行）。
    ///
    /// 两道都要：只断言「在列表里」时，声明面与准入判据若被改成两套口径（或准入被
    /// 收窄），基线记下了却还原不回去，回执会是一条「目标不在声明面内」的拒绝。
    fn assert_target_in_surface_and_admitted(option_id: &str, coord: &str) {
        assert_in_surface(option_id, coord);
        let (hive, sub, key) = coord_parts(coord);
        let got = admits(
            option_id,
            &[json!({
                "hive": hive, "sub": sub, "key": key,
                "presence": "absent", "exists": false
            })],
        );
        assert_eq!(got, Ok(1), "{option_id} 的 {coord} 过不了还原闸（基线记下了却还原不回去）");
    }

    /// R3-M01 主病灶：pwsh 步骤里**非 Start 的值写入**拿不到基线（清单取自分报告的探针输出）。
    ///
    /// 判红点唯一：`walk_ps_ops_for_start` 一旦退回「只收 Start」，下面每一条都找不到。
    #[test]
    fn pwsh全部值写入都进基线() {
        // tf_svc_bulk 的 extras 写点（lfsvc / Edge 两条策略）见下一条用例
        for (id, coord) in [
            (
                "tf_privacy",
                r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings::NOC_GLOBAL_SETTING_TOASTS_ENABLED",
            ),
            (
                "tf_privacy",
                r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules::NumberOfSIUFInPeriod",
            ),
            (
                "tf_privacy",
                r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules::PeriodInNanoSeconds",
            ),
            ("mouse_optimize", r"HKEY_CURRENT_USER\Control Panel\Mouse::SmoothMouseXCurve"),
            ("mouse_optimize", r"HKEY_CURRENT_USER\Control Panel\Mouse::SmoothMouseYCurve"),
            (
                "tf_usb_power",
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USB::DisableSelectiveSuspend",
            ),
            (
                "peripheral_winkey_off",
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layout::Scancode Map",
            ),
            (
                "audio_disable_comm_ducking",
                r"HKEY_CURRENT_USER\Software\Microsoft\Multimedia\Audio::CommDucking",
            ),
            (
                "audio_disable_comm_ducking",
                r"HKEY_CURRENT_USER\Software\Microsoft\Multimedia\Audio\User::CommDucking",
            ),
            (
                "audio_disable_comm_ducking",
                r"HKEY_CURRENT_USER\Software\Microsoft\Multimedia\Audio\Ducking\Mode::Default",
            ),
            (
                "audio_disable_service_restart",
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Audiosrv::DelayedAutoStart",
            ),
            (
                "audio_disable_narrator_ducking",
                r"HKEY_CURRENT_USER\Software\Microsoft\Narrator\NoRoam::DuckAudio",
            ),
            (
                "audio_disable_narrator_ducking",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Narrator\NoRoam::DuckAudio",
            ),
        ] {
            assert_target_in_surface_and_admitted(id, coord);
        }
        // 反向对照：只收真实值写入 —— 纯 cmd 项（fsutil 一族）基线必须为空。
        // 若哪天开始写注册表值，这条会红，提醒把写点纳入核对。
        assert_eq!(
            option_targets("tf_ntfs").map(|t| t.len()),
            Some(0),
            "纯 cmd 项不该凭空多出基线目标（收的不是值写入 → 会写出没动过的值）"
        );
    }

    /// R3-M02：子项**附带开关**（extras）的写面必须与主清单一起进基线、可准入。
    ///
    /// 判红点：`option_targets` 里的 `all_extra_steps` 并入被删 ⇒ 下面每一条都找不到；
    /// `tf_appx` 会退回「基线为空 ⇒ 备份 count:0 不落记录」的旧形态。
    #[test]
    fn 附带开关写面进基线与回读范围() {
        // tf_svc_bulk：lfsvc_status（Status=0）+ edge_prelaunch（两条 Edge 策略）
        assert_target_in_surface_and_admitted(
            "tf_svc_bulk",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration::Status",
        );
        assert_target_in_surface_and_admitted(
            "tf_svc_bulk",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main::AllowPrelaunch",
        );
        assert_target_in_surface_and_admitted(
            "tf_svc_bulk",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader::AllowTabPreloading",
        );
        // tf_appx：onedrive_full_uninstall 的 CLSID 入口两条 + 同步策略四条
        assert_target_in_surface_and_admitted(
            "tf_appx",
            r"HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder::Attributes",
        );
        assert_target_in_surface_and_admitted(
            "tf_appx",
            r"HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder::Attributes",
        );
        for key in [
            "DisableFileSync",
            "DisableFileSyncNGSC",
            "DisableMeteredNetworkFileSync",
            "DisableLibrariesDefaultSaveToOneDrive",
        ] {
            assert_target_in_surface_and_admitted(
                "tf_appx",
                &format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive::{key}"),
            );
        }
        // 与生成器同源：extras 现算出的**每一个**写点都在基线/声明面内 ——
        // 少一个就是「执行写了、还原回读不到」，而这批值级备份是唯一还原出口。
        for id in ["tf_svc_bulk", "tf_appx"] {
            let extra = targets_from_steps(&super::super::subitems::all_extra_steps(id));
            assert!(!extra.is_empty(), "{id} 的 extras 一个写点都没解析出来（生成器或解析链断了）");
            let surface = surface_of(id);
            for t in extra {
                let c = format!("{}\\{}::{}", t.root, t.sub, t.key).to_ascii_lowercase();
                assert!(surface.contains(&c), "{id} 的 extras 写点 {c} 不在基线/声明面内");
            }
        }
    }

    /// R3-M02 的还原侧：extras 目标必须过得了第二道闸（台账摘要之外的目标准入），
    /// 且**面外仍拒** —— 它们进还原操作集之后，`verify_restore_ops` 的回读范围
    /// 就是这份操作集，所以「回读覆盖 extras」由准入等价保证（可测的那一半）。
    #[test]
    fn extras目标能过还原闸_面外仍拒() {
        // HKCR 坐标（OneDrive 资源管理器入口）必须准入：写入用 ClassesRoot 别名也对得上
        let ok = admits(
            "tf_appx",
            &[json!({
                "hive": "ClassesRoot",
                "sub": r"CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder",
                "key": "Attributes",
                "presence": "value", "exists": true, "type": "REG_DWORD", "data": "0"
            })],
        );
        assert_eq!(ok, Ok(1), "tf_appx 的 OneDrive CLSID 写点必须准入（否则还原被自己拒掉）");
        // 面外仍拒：tf_appx 不该凭空获得写任意 HKLM 值的能力（R3-K01 的第二道闸不许被撬开）
        let Err(msg) = admits(
            "tf_appx",
            &[json!({
                "hive": "LocalMachine",
                "sub": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "key": "TrimUpdate",
                "presence": "absent", "exists": false
            })],
        ) else {
            panic!("tf_appx 的面外目标必须拒绝")
        };
        assert!(msg.contains("不在本项声明的还原面内"), "{msg}");
    }

    /// R3-M03：动态项 `perf_wu_pause` 的那组 QWord 必须进基线/声明面，
    /// 且与**写入生成器**、**检测侧表**三向对齐。
    #[test]
    fn perf_wu_pause基线对齐生成器与检测侧表() {
        let got = surface_of("perf_wu_pause");
        assert_eq!(got.len(), 6, "perf_wu_pause 的声明面应为 6 个值（3 组起止），实收 {got:?}");

        // ① 与写入生成器同源：wu_pause_steps 的 pwsh 原文里被写的值名与本表逐字相等。
        //    生成器多写一个值 / 改一个名字而本表没跟 ⇒ 这里红。
        let steps = super::super::apply::wu_pause_steps(7);
        let pwsh = steps[0].get("pwsh").and_then(|v| v.as_str()).unwrap_or_default();
        assert!(pwsh.contains(WU_PAUSE_SUBKEY), "生成器写的键与本表登记的键不一致: {pwsh}");
        let mut from_gen: Vec<String> = pwsh
            .split('"')
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, s)| s.to_string())
            .filter(|s| s.starts_with("Pause"))
            .collect();
        from_gen.sort();
        from_gen.dedup();
        let mut from_table: Vec<String> = WU_PAUSE_VALUES.iter().map(|s| s.to_string()).collect();
        from_table.sort();
        assert_eq!(from_gen, from_table, "基线的 6 个值名与 wu_pause_steps 的写入值名漂移");

        // ② 与检测侧表同源（overview 的 regTimeWindow 判据也读这张表）
        let spec = super::super::catalog::write_spec_of("perf_wu_pause")
            .expect("检测侧表应登记 perf_wu_pause");
        let mut from_spec: Vec<String> = Vec::new();
        for r in spec.reg_writes {
            from_spec.push(r.value.to_string());
            if !r.value2.is_empty() {
                from_spec.push(r.value2.to_string());
            }
            assert_eq!(r.subkey, WU_PAUSE_SUBKEY, "检测侧表的键与本表登记不一致");
        }
        from_spec.sort();
        assert_eq!(from_spec, from_table, "基线的 6 个值名与检测侧表漂移");
    }

    /// R3-M03 的还原侧：这些基线必须过得了第二道闸（否则「暂停更新」依旧无从还原），
    /// 同键下未声明的值仍被拒。
    #[test]
    fn perf_wu_pause基线能过还原闸_面外仍拒() {
        let entries: Vec<Value> = WU_PAUSE_VALUES
            .iter()
            .map(|v| {
                json!({
                    "hive": "LocalMachine", "sub": WU_PAUSE_SUBKEY, "key": v,
                    "presence": "absent", "exists": false
                })
            })
            .collect();
        assert_eq!(admits("perf_wu_pause", &entries), Ok(6), "6 条基线必须全部准入");
        let mut bad = entries;
        bad.push(json!({
            "hive": "LocalMachine", "sub": WU_PAUSE_SUBKEY, "key": "PauseWhatever",
            "presence": "absent", "exists": false
        }));
        let Err(msg) = admits("perf_wu_pause", &bad) else {
            panic!("同键下未声明的值也必须拒绝（收窄不许被同键前缀打通）")
        };
        assert!(msg.contains("不在本项声明的还原面内"), "{msg}");
    }
}

