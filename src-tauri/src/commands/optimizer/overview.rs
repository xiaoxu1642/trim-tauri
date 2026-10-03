//! 只读视图：optimizer:list / svc-mem-current / check-optimized / state-overview，
//! 以及支撑回读判定的 .reg 块解析（预期值 → Check 列表）。
//!
//! check_optimized 的判据来自规则库 .reg 文本的期望值，解析口径必须与还原侧
//! （backup_restore.rs 的写回）一致，否则会出现「显示已优化、还原写不回」的分叉。
//!
//! ==================== D0 三侧覆盖契约（D0-COVERAGE-ANCHOR） ====================
//! 数据层每个 `steps[]` 字段必须被**三个侧**同时消费，缺一侧即门禁红
//! （`tools/check-optimizer-dynamic.mjs` 的 A8 断言按本段锚点静态对拍）：
//!
//! ```text
//! 字段        执行(apply.rs)      检测(overview.rs)   备份(backup_restore.rs)
//! reg         ✅ 写 .reg+import     ✅ kind="reg"        ✅ parse_reg_targets
//! service     ✅ 三分态分支        ✅ kind="svc"        ✅ svc_start_target
//! startType   ✅ 三分态分支        ✅ kind="svcStart"   ✅ svc_start_target
//! disable     ✅ 三分态分支        ✅ 与 service 同判     ✅ svc_start_target
//! cmd         ✅ run_cmd_step      ⬜ 白名单(见下)      ✅ svc_names_writing_start
//! pwsh        ✅ pssteps 解释器    ⬜ 白名单(见下)      ✅ walk_ps_ops_for_start
//! label       ⬜ 白名单(纯展示)     ⬜ 白名单            ⬜ 白名单
//! ```
//!
//! **为什么是三侧而不是只查检测侧**：v0.5.0 的 `startType` 三侧全缺，而报告
//! （§5.2）判定它是「检测盲区」并写明「执行链已走 Set-Service 解释器分支、
//! 是好的」—— 只查检测侧的门禁会把这个真缺陷放过去。实测 `grep startType
//! src-tauri/src/` 全仓 3 处命中**全是注释**，执行链根本没读这个字段。
//!
//! `cmd` / `pwsh` 仍列白名单：它们的「已生效判定」要按脚本语义推（例如一条
//! pwsh 步骤可能改 3 个键也可能只改 1 个），强行按字段名对拍会误红。白名单
//! 本身要写明理由，新增字段时**不许顺手加进来** —— 要加必须同时给出检测原语。

use crate::engine::{guard, optimization_state as opt_state};
use serde_json::{Value, json};
use tauri::{Runtime, WebviewWindow};
use super::apply::*;
use super::backup_restore::*;
use super::catalog::*;

/// D0 三侧覆盖契约锚点：门禁按本常量与本文件下述各侧 anchor 做静态对拍。
///
/// 门禁能判红的前提是「锚点存在且唯一」：改这里的字符串而不同步门禁，门禁会红
/// （说明两侧脱节）；删掉整段，门禁也会红（说明契约被整体删除）。
///
/// `allow(dead_code)` 的理由：它被 `tools/check-optimizer-dynamic.mjs` 当作**文本**
/// 锚点静态对拍读取，Rust 侧没有运行期消费者。非测试构建下 rustc 看不到那个消费者，
/// 于是报 dead_code —— 这是「跨语言契约锚点」的固有形态，不是死代码。
#[allow(dead_code)]
pub(super) const D0_COVERAGE_ANCHOR: &str = "D0-COVERAGE-ANCHOR";

// ==================== .reg 块解析与回读检测 ====================

/// `.reg` 根键 → native hive 句柄（B11：检测不再经 PS，需要真实 hive）
pub(super) fn reg_hive(root: &str) -> Option<windows::Win32::System::Registry::HKEY> {
    use windows::Win32::System::Registry::{HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS};
    Some(match root {
        "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        "HKEY_USERS" => HKEY_USERS,
        "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
        _ => return None,
    })
}

#[derive(Clone)]
pub(super) struct Check {
    /// "reg" | "svc" | "svcStart" | "regBinary" | "regAbsent"
    ///
    /// `svcStart` 与 `svc` 必须分开：`svc` 判「是不是 disabled」，`svcStart` 判
    /// 「启动类型是不是某个具体值」。合成一个 kind 就得把期望值塞进 `data` 再在
    /// 判定处反解，判据会散到两处。
    ///
    /// M2-B 新增两个（都来自 `optimizer-writes.json` 的 `regWrites[]`）：
    /// - `regBinary`：REG_BINARY 值逐字节相等（`MitigationOptions` / `Scancode Map`）。
    ///   不并进 `reg` 是因为 `reg` 分支按 `is_dword` 二分（dword / string），
    ///   加第三种类型要么多一个标志位、要么在判定处按值猜类型 —— 两种都更容易判错。
    /// - `regAbsent`：**键必须不存在**才算已生效。`perf_wu_enable` 是删除语义
    ///   （`Remove-ItemProperty`），判「值等于某个数」永远不可能满足。
    kind: &'static str,
    // reg（B11：检测改原生，直接带 hive + 子键，不再经 PS 路径字符串）
    hive: windows::Win32::System::Registry::HKEY,
    subkey: String,
    key: String,
    is_dword: bool,
    /// reg：期望值原文。svcStart：期望的 `dwStartType` 十进制字符串。
    data: String,
    // svc / svcStart
    name: String,
}

impl Check {
    /// 断言判据（kind + 期望值 + 目标名）—— 供 `contract_tests` 做形状对拍。
    ///
    /// 为什么不把字段直接改成 `pub`：`Check` 只在 `check_optimized` 一处被消费，
    /// 字段公开等于把「谁能改判定」的范围扩大到全 crate，形状回归就拦不住了。
    ///
    /// `allow(dead_code)`：消费者是 `contract_tests`（cfg(test)），非测试构建下
    /// 没有调用点。方法本身带真实断言逻辑，不是死代码。
    #[allow(dead_code)]
    pub(super) fn probe(&self) -> (&'static str, &str, &str) {
        (self.kind, self.data.as_str(), self.name.as_str())
    }

    /// 形状对拍的第二组：注册表坐标 + 类型标志（M2-B）。
    ///
    /// 为什么单独一个而不是把 `probe` 扩成四元组：`probe` 的三个返回值已被
    /// 十几处断言在用（改它要动全部调用点），而「键路径对不对」「binary 会不会被
    /// 误标 is_dword」这两件事**只在新分支上有意义**。两个访问器各管一域，
    /// 加新判据形态时不会把旧调用点全拖下水。
    ///
    /// ⚠️ 只给测试/门禁用，不开 `pub` 字段 —— 理由同 [`Check::probe`]。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn probe_reg(&self) -> (&str, &str, bool) {
        (self.subkey.as_str(), self.key.as_str(), self.is_dword)
    }

    /// 区间判据（`regTimeWindow`）的**结束**坐标 —— M2-C。
    ///
    /// 单独一个访问器而不是把它塞进 `probe_reg`：那个返回 `(subkey, key, is_dword)`，
    /// 是给「等值类」断言做形状对拍的。区间类多一个坐标，混进去会让那个访问器的
    /// 返回值语义变成「有时第三个是 flag 有时是键名」—— 那是判据自己都认不出来的形态。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn probe_reg_name(&self) -> &str {
        self.name.as_str()
    }

    /// 造一条**坐标被改写过**的断言副本（仅测试用）。
    ///
    /// 为什么需要它：`regEnum` / `regTimeWindow` 的真机往返必须在**测试自己的键**上做
    /// —— `svc_mem_gb` / `perf_wu_pause` 的真键都在 HKLM 下（改系统状态，快速组不许）。
    /// 而 `collect_checks` 产出的 `Check` 字段是私有的，测试改不了坐标就会
    /// 真的去动系统键。
    ///
    /// ⚠️ 只在 `cfg(test)` 下存在。非测试构建里「构造一条坐标与数据面无关的断言」
    /// 这件事没有合法用途 —— 它能让 `judge_check` 被喂任意坐标，是判据被绕过的口子。
    #[cfg(test)]
    pub(super) fn with_coords(
        mut self,
        hive: windows::Win32::System::Registry::HKEY,
        subkey: &str,
        key: &str,
        name: &str,
    ) -> Self {
        self.hive = hive;
        self.subkey = subkey.to_string();
        self.key = key.to_string();
        self.name = name.to_string();
        self
    }
}

/// 解析一个 .reg 值的期望数据（dword:hex→十进制 / 引号串 / 原串）
pub(super) fn parse_reg_expected(raw: &str) -> Option<(bool, String)> {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("dword:") {
        let n = i64::from_str_radix(hex, 16).ok()?;
        return Some((true, n.to_string()));
    }
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        return Some((false, raw[1..raw.len() - 1].to_string()));
    }
    Some((false, raw.to_string()))
}

/// 解析 option.steps 中全部 reg 期望值 + service.disable
pub(super) fn collect_checks(opt: &Value) -> Vec<Check> {
    let mut checks = Vec::new();
    // ⚠️ **`steps` 缺失/为空时要走侧表分支，不能直接 return**（M2-C踩过）：
    // `svc_mem_gb` 在数据层里**连 `steps` 键都没有**（`dynamic: true`，真实步骤由
    // `apply.rs::memory_steps(gb)` 按用户选的 GB 在运行时生成）。
    // 早退会让后面的「写入坐标侧表」两条分支**永远到不了** ——
    // 症状与 v0.5.0 的缺陷一模一样（体检恒「未生效」），但看起来像侧表没登记。
    // 所以改成`unwrap_or_default()`：缺失与空数组都走「零轮次」的 for 循环，
    // 循环结束后自然落到侧表分支。
    let steps: Vec<Value> = opt
        .get("steps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for s in &steps {
        if let Some(block) = s.get("reg").and_then(|v| v.as_str()) {
            for (full, body) in parse_reg_sections(block) {
                let root = full.split('\\').next().unwrap_or("");
                let Some(hive) = reg_hive(root) else { continue };
                // native 子键不含根键段（`full[root.len()..]`），并去掉前导反斜杠
                let subkey = full[root.len()..].trim_start_matches('\\').to_string();
                for (key, raw) in parse_reg_value_lines(&body) {
                    if raw.trim() == "-" {
                        continue; // 还原占位不参与检测
                    }
                    if let Some((is_dword, data)) = parse_reg_expected(&raw) {
                        checks.push(Check {
                            kind: "reg",
                            hive,
                            subkey: subkey.clone(),
                            key,
                            is_dword,
                            data,
                            name: String::new(),
                        });
                    }
                }
            }
        }
        if let (Some(name), Some(true)) = (
            s.get("service").and_then(|v| v.as_str()),
            s.get("disable").and_then(|v| v.as_bool()),
        ) {
            checks.push(Check {
                kind: "svc",
                hive: reg_hive("HKEY_LOCAL_MACHINE").unwrap(),
                subkey: String::new(),
                key: String::new(),
                is_dword: false,
                data: String::new(),
                name: name.to_string(),
            });
        }
        // 第三条分支：startType（R0-b）。v0.5.0 之前这里**完全没有** svcStart 形态，
        // 于是 `svc_*_manual` 四项 collect_checks 返回空 vec ⇒ 上游
        // `if !checks.is_empty()` 直接跳过 ⇒ 体检恒显示「未生效」，而执行链其实
        // 已经（错误地）动过服务。执行侧与检测侧的失配就是从这里来的。
        // D0-EXEC-SIDE / D0-CHECK-SIDE / D0-BACKUP-SIDE 三个锚点见文件头契约表。
        if let (Some(name), Some(raw)) = (
            s.get("service").and_then(|v| v.as_str()),
            s.get("startType").and_then(|v| v.as_str()),
        ) {
            // 未知取值 fail-closed：记一条恒 false 的 check，等价于「判未生效」。
            // 不静默跳过 —— 跳过的后果是「collect_checks 空 ⇒ 体检显示无法检测」，
            // 而数据显示这步确实该有个判据；那条空 vec 正是 v0.5.0 的病根形态。
            // 真正的硬拦在 D0 门禁（未知取值会同时让门禁红），这里只保证不谎报。
            let data = match crate::engine::native::start_type_from_label(raw) {
                Ok(v) => v.to_string(),
                Err(reason) => {
                    crate::engine::log::write_log(
                        "warn",
                        &format!("优化项 startType 取值无法解析: {reason}，按未生效记账"),
                    );
                    u32::MAX.to_string()
                }
            };
            checks.push(Check {
                kind: "svcStart", // D0-CHECK-SIDE: startType 检测分支（R0-b 新增）
                hive: reg_hive("HKEY_LOCAL_MACHINE").unwrap(),
                subkey: String::new(),
                key: String::new(),
                is_dword: false,
                data,
                name: name.to_string(),
            });
        }
    }

    // 第四条分支：写入坐标侧表（M2 · B类「服务可回读」）。
    //
    // 为什么需要：v0.5.0 时`tf_svc_bulk`（65 个服务）/ `tf_drv_disable`（19 个）
    // / `svc_bluetooth_disable` 等6 项的 steps 全是 `pwsh` 文本，`collect_checks`
    // 不解析 pwsh ⇒ 返回空 vec ⇒ 上游 `if !checks.is_empty()` 跳过 ⇒ 体检恒显示
    // 「未生效」⇒ 用户看到「立即执行」而不是「立即恢复」，会**重复施加同一批改动**。
    // 这与 v2-M1 那个重复项 bug 是同一种形态：把「没检到」显示成「没有」。
    //
    // 原语零新增：R0-b 已建`service_start_type_is(name, expected)`，这里只是
    // 把「服务名清单」从 pwsh 文本搬到侧表（`optimizer-writes.json`）让检测侧能读。
    // 数据真源仍是 pwsh 文本 —— `tools/check-optimizer-write-contract.mjs` 逐项对拍两侧。
    let opt_id = opt.get("id").and_then(Value::as_str).unwrap_or("");
    if !opt_id.is_empty() && checks.is_empty() {
        if let Some(spec) = write_spec_of(opt_id) {
            for (expect, services) in spec.groups {
                for svc in *services {
                    checks.push(Check {
                        kind: "svcStart",
                        hive: reg_hive("HKEY_LOCAL_MACHINE").unwrap(),
                        subkey: String::new(),
                        key: String::new(),
                        is_dword: false,
                        data: expect.to_string(),
                        name: svc.clone(),
                    });
                }
            }
            // 商店那 5 项由 `svc_bulk_append_store` 条件追加（RunParams.includeStore，
            // 用户弹窗确认过才执行）。这里**刻意不生成断言** ——
            // `check_optimized` 只知道「当前启动类型」，不知道「用户当时勾没勾商店」。
            // 判成未生效会让没勾商店的用户永远看到「立即执行」，
            // 判成已生效会让勾了商店的用户看不到还原入口。**两者都是谎报**。
            //
            // 正确形态是让它们显示为「部分生效」，那需要把 `check_optimized`
            // 的返回从 `bool` 扩成三态（影响 4 个调用方 + 前端三处消费），
            // 属 M2 的独立一批。清单本身在这里取出来**只为了不漂移**：
            // 见 `check-optimizer-write-contract.mjs` 的「storeServices 必须与
            // apply.rs 的 STORE_SERVICES 逐项一致」—— 清单烂掉时门禁会红。
            let _ = spec.store_services;
            //
            // 为什么不静默：这里刻意留注释说明「为什么不判」，避免下一个读代码的
            // 人以为这里漏了。
        }
    }
    // 第五条分支：注册表写入坐标（M2-B · A 类「注册表可回读」）。
    //
    // 与第四条（服务）**并列而不合并**：两类断言的读取原语、失败语义都不同
    // （服务走 SCM，失败 = 服务不存在；注册表走 RegQuery，失败 = 类型不符 / 无权限），
    // 合成一条会让「判不出来」这个结果无法区分成因。
    //
    // 这 6 项原先同样是 `pwsh` 文本 ⇒ `collect_checks` 返回空 vec ⇒ 体检恒「未生效」
    // ⇒ 用户点「立即执行」重复施加。形态与 B 类完全同构，只是原语不同。
    let opt_id2 = opt.get("id").and_then(Value::as_str).unwrap_or("");
    if !opt_id2.is_empty() && checks.is_empty() {
        if let Some(spec) = write_spec_of(opt_id2) {
            for r in spec.reg_writes {
                // ⚠️ 侧表里写的是**短名**（HKLM/HKCU/…）而 [`reg_hive`] 认的是
                // **长名**（HKEY_LOCAL_MACHINE/…）—— 两者不匹配会让每个断言都走
                // 「未知 hive」分支被 skip，`collect_checks` 仍返回空 vec，
                // 症状与 v0.5.0 的缺陷**完全一样**（体检恒「未生效」）。
                // 这个 bug 是单测抓出来的：报「只产出 0 条断言」，而侧表自洽测试
                // 是绿的（它只查「项在表里」，不查「hive 认不认」）。
                let hive_name = match r.hive {
                    "HKLM" => "HKEY_LOCAL_MACHINE",
                    "HKCU" => "HKEY_CURRENT_USER",
                    "HKCR" => "HKEY_CLASSES_ROOT",
                    "HKU" => "HKEY_USERS",
                    "HKCC" => "HKEY_CURRENT_CONFIG",
                    other => other,
                };
                let Some(hive) = reg_hive(hive_name) else {
                    // 未知 hive：产不出断言。**不记一条恒 false** —— 那样会让整个项
                    // 恒判「未生效」，用户点详情看到「立即执行」而实际什么也没做。
                    crate::engine::log::write_log(
                        "warn",
                        &format!(
                            "写入坐标侧表里 {} 的 hive {:?} 无法识别，该断言已跳过",
                            opt_id2, r.hive
                        ),
                    );
                    continue;
                };
                checks.push(Check {
                    kind: if r.absent {
                        "regAbsent"
                    } else if r.kind == "binary" {
                        "regBinary"
                    } else if r.kind == "enum" {
                        // M2-C：dynamic 项的「值 ∈ 合法档位集合」判据。
                        // 不用等值：检测时不知道用户当初选的哪个 GB（那信息只在
                        // 记账里，记账可被清）。落在集合内 ⇒ 有人配过合法档位。
                        "regEnum"
                    } else if r.kind == "timeWindow" {
                        // M2-C：dynamic 项的「现在 ∈ [start, end)」区间判据。
                        "regTimeWindow"
                    } else {
                        "reg"
                    },
                    hive,
                    subkey: r.subkey.to_string(),
                    key: r.value.to_string(),
                    // 区间判据的结束键名复用 `name`字段：它是这条断言的
                    // 第二个坐标，不是服务名。判定链按 kind 分派，不会串味。
                    name: r.value2.to_string(),
                    // binary 绝不能标 is_dword：判定链靠这个标志二分 dword/string，
                    // 标错会把 24 字节的 Scancode Map 当 4 字节整数比。
                    is_dword: r.kind == "dword" && !r.absent,
                    data: r.expect.to_string(),
                });
            }
        }
    }
    checks
}

/// 切分 .reg 文本为 (段全名, 段内文本) 列表。
/// 段行为 `[xxx]`（trim 后首尾方括号），值体到下一段或末尾。
pub(super) fn parse_reg_sections(block: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cur_name: Option<String> = None;
    let mut cur_body = String::new();
    for line in block.split(['\n']) {
        let t = line.trim_end_matches('\r');
        let tt = t.trim();
        if tt.starts_with('[') && tt.ends_with(']') && tt.len() >= 2 {
            if let Some(name) = cur_name.take() {
                out.push((name, std::mem::take(&mut cur_body)));
            }
            cur_name = Some(tt[1..tt.len() - 1].trim().to_string());
        } else if cur_name.is_some() {
            cur_body.push_str(t);
            cur_body.push('\n');
        }
    }
    if let Some(name) = cur_name {
        out.push((name, cur_body));
    }
    out
}

/// 解析段内 `"键"=值` 行（键名不含引号字符，与 JS [^"]+ 同口径）
pub(super) fn parse_reg_value_lines(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix('"') else { continue };
        let Some(qend) = rest.find('"') else { continue };
        let key = &rest[..qend];
        let Some(eq) = rest[qend + 1..].strip_prefix('=') else { continue };
        out.push((key.to_string(), eq.trim().to_string()));
    }
    out
}

/// 只读检测多个选项，返回 id -> 是否全部期望生效
///
/// B11：原先这里生成一段 PS（`Test-One` / `Test-Svc` 两个函数 + 每个选项一行
/// `-and` 链）、落临时 `.ps1`、spawn pwsh、120s 超时、再从 stdout 抠 JSON ——
/// 就为了读一批注册表值和服务启动类型。现在直接走注册表 / SCM API：
/// 语义逐条对齐原 PS（缺值 / 类型不对 / 打不开键 / 服务不存在 都算「未生效」）。
///
/// 与原 PS 的**一处刻意差异**：DWORD 比较按无符号 32 位读出（`read_reg_dword_opt`），
/// 原 PS 的 `[int]$v -eq [int]$d` 是 32 位**有符号**，`dword:ffffffff` 这类值会判不上。
/// 优化项里没有 > 2^31-1 的期望值，此差异不改变现有行为，但让实现不再有这个坑。
/// 判定单条断言（M2-C 抽出）。
///
/// 抽出前它是 `check_optimized` 里的一个闭包。抽出来的原因不是「好看」：
/// - `regEnum` / `regTimeWindow` 两种新形态需要**真机往返**验证三态
///   （在集合内/不在集合内/键不存在），而 `check_optimized` 只能按 id走侧表，
///   测试改不了坐标就会测到别的键上。
/// - 六个分支的顺序是契约：`svc` / `svcStart` / `regBinary` / `regAbsent` /
///   `regEnum` / `regTimeWindow` 都必须在 `c.is_dword` 那个二分**之前**判掉，
///   落下去会被当成 dword 或 string 比，症状是「恒判未生效」。
pub(super) fn judge_check(c: &Check) -> bool {
    use crate::engine::native;
            if c.kind == "svc" {
                native::service_start_type_is(&c.name, native::SVC_START_DISABLED)
            } else if c.kind == "regBinary" {
                // M2-B：REG_BINARY 逐字节相等。`read_reg_binary_opt` 返回小写
                // hex 连写（与侧表的 expect 同格式），所以直接字符串比。
                //
                // 读不到（None）判 false —— 与整条链的既有口径一致（fail-closed）。
                // `Some("")`（存在但空）与 `None`（读不到）**必须**分清：前者是
                // 「值被清空了」，后者是「读不出来」。把前者当后者会让「已清零」
                // 显示成「未生效」。
                native::read_reg_binary_opt(c.hive, &c.subkey, &c.key).as_deref() == Some(c.data.as_str())
            } else if c.kind == "regEnum" {
                // M2-C：dynamic 项 svc_mem_gb 的判据 —— **值 ∈ 合法档位集合**。
                //
                // 为什么不是等值判据：这项是 `dynamic: true`，`steps` 在数据层是空的，
                // 真实步骤由 `apply.rs::memory_steps(gb)` 按用户选的 GB 生成。
                // 检测时**不知道用户当初选的是 8 还是 16** —— 那信息只在
                // `optimization_state` 的记账里，而记账可以被 `clearAllApplied` 清掉。
                // 所以判据只能是「当前值是某个合法档位」：在集合内 ⇒ 有人配过；
                // 不在 ⇒ 一定是没配过的（或者是被组策略改了）。
                //
                // 语义方向与灰态一致（宁可多灰不可漏灰）：宁可把「用户配了 8GB
                // 但组策略又改了」判成未生效，也不要判成已生效让用户以为生效了。
                match native::read_reg_dword_opt(c.hive, &c.subkey, &c.key) {
                    None => false, // 读不到 ⇒ 未生效（fail-closed）
                    Some(v) => c
                        .data
                        .split(',')
                        .filter_map(|x| x.trim().parse::<i64>().ok())
                        .any(|allowed| allowed == v),
                }
            } else if c.kind == "regTimeWindow" {
                // M2-C：dynamic 项 perf_wu_pause 的判据 —— **现在 ∈ [start, end)**。
                //
                // 这项的步骤由 `apply.rs::wu_pause_steps(days)` 生成：3 个 StartTime
                // 写成执行时刻的 FILETIME，3 个 EndTime 写成 now + days 的 FILETIME。
                // 暂停期是用户当时选的，检测时不知道选了多少天 ⇒ 只能判区间。
                //
                // 三个 `&&` 的语义：开始时刻已过 且 尚未到结束时刻。任一不满足就
                // 说明「没暂停过」或「暂停期已过」⇒ 两种都该显示「立即执行」而不是
                // 「立即恢复」—— 已过期的暂停项恢复它没有意义。
                //
                // 两侧任一读不到都判 false：FILETIME 缺失意味着这条链没跑过。
                // 刻意用 if-else 而不是 `return false` —— `return` 在 `all()` 的
                // 闭包里虽语义正确（从闭包返回），但读代码的人会误以为它返回的是
                // 整个 `check_optimized`，从而以为「一个区间读不到就跳过其余断言」。
                let verdict = match (
                    native::read_reg_qword_opt(c.hive, &c.subkey, &c.key),
                    native::read_reg_qword_opt(c.hive, &c.subkey, &c.name),
                ) {
                    (Some(start), Some(end)) => {
                        // FILETIME → Unix 毫秒。与 `registry.rs::reg_key_last_write_ms`
                        // 用同一个 `EPOCH_DIFF_100NS` 口径（100ns 计数、自 1601-01-01 起）。
                        const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
                        // `now_ms` 取系统时钟：FILETIME 是 UTC，Unix 纪元也是 UTC，无时区差。
                        let now_ms = crate::engine::now_ms();
                        // 化到同一量纲再比（FILETIME 是 100ns，now_ms 是毫秒，差 10000 倍）。
                        let to_ms = |ft: i64| (ft - EPOCH_DIFF_100NS) / 10_000;
                        to_ms(start) <= now_ms && now_ms < to_ms(end)
                    }
                    _ => false,
                };
                verdict
            } else if c.kind == "regAbsent" {
                // M2-B：删除语义判据 —— **键必须不存在**才算已生效。
                //
                // 为什么方向是「不存在 = 已生效」：perf_wu_enable 的执行侧是
                // `Remove-ItemProperty`（删掉 4 个 `Pause*` 键与 `NoAutoUpdate` 策略），
                // 已执行的效果就是那些键**消失**。若判「键存在且等于某值」，它永远
                // 不成立 ⇒ 体检恒显示「未生效」⇒ 用户点「立即执行」，而执行侧只是在
                // 重复删不存在的键 —— 「谎报未生效 + 重复施加」的组合比检不出更糟。
                //
                // 读侧用 `read_reg_value_text`（任意类型都读得到）而不是
                // `read_reg_dword_opt`：判据是「这个键还在不在」，与值类型无关。
                //
                // ⚠️ **已知简化**：`None` 同时覆盖「值不存在」与「键打不开
                // （无权限 / 父键缺失）」。本判据不区分 —— 对 `WindowsUpdate`
                // 那个父键而言，非管理员读它本来就该失败，而「读不到」判未生效是
                // 安全的默认方向（灰态宁可多灰不可漏灰）。要区分需要一个
                // 「键存在但值不存在」的专用原语（按 `RegQueryValueEx` 的
                // ERROR_FILE_NOT_FOUND 与其它错误码分流），本批不做。
                native::read_reg_value_text(c.hive, &c.subkey, &c.key).is_none()
            } else if c.kind == "svcStart" {
                // `data` 是 collect_checks 存进去的十进制期望值。解析失败即判 false：
                // 宁可说「未生效」也不给假阳性（与整条链的既有口径一致）。
                match c.data.parse::<u32>() {
                    Ok(want) => native::service_start_type_is(&c.name, want),
                    Err(_) => false,
                }
            } else if c.is_dword {
                match c.data.parse::<i64>() {
                    Ok(want) => native::read_reg_dword_opt(c.hive, &c.subkey, &c.key) == Some(want),
                    Err(_) => false,
                }
            } else {
                native::read_reg_string(c.hive, &c.subkey, &c.key).as_deref() == Some(c.data.as_str())
            }
}

pub(super) fn check_optimized(ids: &[String]) -> std::collections::HashMap<String, bool> {
    let mut result = std::collections::HashMap::new();
    // id -> checks（保留请求顺序）
    let mut grouped: Vec<(String, Vec<Check>)> = Vec::new();
    for id in ids {
        let Some(opt) = find_option(id) else { continue };
        let checks = collect_checks(opt);
        if !checks.is_empty() {
            grouped.push((id.clone(), checks));
        }
    }
    if grouped.is_empty() {
        return result;
    }

    for (id, checks) in &grouped {
        // 全部 check 都生效才算生效（与原 PS 的 `$gv -and (...)` 链一致）；
        // 一条都解析不出来也按「未生效」处理，不给假阳性。
        let all_ok = !checks.is_empty() && checks.iter().all(judge_check);
        result.insert(id.clone(), all_ok);
    }
    result
}

/// 这一步**实际由谁执行**：`native`（主进程原生解释器）/ `inbox-ps`（收件箱 Windows
/// PowerShell 5.1，系统自带）/ `proc`（直接起进程）/ `unsupported`（编译不出来）。
///
/// 为什么要在后端算并随 `optimizer:list` 下发：数据层里标 `pwsh` 的 56 个步骤，实测有
/// 45 个走的是原生解释器（`cargo test --lib data_layer_coverage_report -- --nocapture`
/// 现算），前端却一律显示「执行 PowerShell 内联脚本」——那是在谎报执行引擎，用户据此
/// 认为本应用依赖 PowerShell（并以为要装 PowerShell 7）。判据只有一份：直接问编译器。
pub(super) fn step_exec_mode(s: &Value) -> Option<&'static str> {
    if let Some(ps) = s.get("pwsh").and_then(Value::as_str) {
        return Some(match crate::engine::pssteps::compile(ps) {
            Ok(ops) if ops.iter().any(|o| matches!(o, crate::engine::pssteps::PsOp::PsInline { .. })) => "inbox-ps",
            Ok(_) => "native",
            Err(_) => "unsupported",
        });
    }
    if s.get("cmd").is_some() {
        return Some("proc");
    }
    if s.get("reg").is_some() || s.get("service").is_some() {
        return Some("native");
    }
    None
}

/// 给一行选项的 steps[] / restore[] 每项补 `execMode`（响应侧字段，不进数据层文件）。
pub(super) fn tag_exec_modes(row: &mut Value) {
    for key in ["steps", "restore"] {
        if let Some(arr) = row.get_mut(key).and_then(|v| v.as_array_mut()) {
            for s in arr.iter_mut() {
                if let (Some(mode), Some(map)) = (step_exec_mode(s), s.as_object_mut()) {
                    map.insert("execMode".into(), json!(mode));
                }
            }
        }
    }
}

// ==================== IPC ====================

/// optimizer:list —— 完整选项目录（含 steps/restore）
///
/// 每行补一个 `applyScope`（生效粒度），值来自 [`SCOPE_JSON`] 侧表而非数据层本身 ——
/// `optimizer-runtime.json` 与上游基线是逐字段对拍的双源文件，加字段必判红。
/// 前端在「执行所选优化」的批次结束时按各行取最大粒度，**只提示一次**重启建议。
/// 另给每个步骤补 `execMode`（见 [`step_exec_mode`]），同样是响应侧字段。
#[tauri::command]
pub async fn optimizer_list<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    // B4：备份表读**一次**（126 项循环里每项读一次会重复解 34KB JSON ×126）
    let backups = load_opt_backups();
    let rows: Vec<Value> = options()
        .iter()
        .map(|o| {
            let mut row = o.clone();
            if let Some(map) = row.as_object_mut() {
                map.insert(
                    "applyScope".into(),
                    json!(apply_scope(o.get("id").and_then(Value::as_str).unwrap_or(""))),
                );
                // 安全降级标签（RAINZ 对标 §4 R2）：同一条侧表注入路径。前端据此在
                // 高危确认与详情里点名「这一项会降低安全基线」，而不是只靠 risk:high 暗示。
                let sid = o.get("id").and_then(Value::as_str).unwrap_or("");
                if let Some(sd) = security_degrade_of(sid) {
                    map.insert("securityDegrade".into(), sd);
                }
                // provenance 标签（M4）：判据来源 + 一句话依据。前端在高危项详情里
                // 展示「为什么这条被判定为高危」，而不是让用户自己猜。
                if let Some(pv) = provenance_of(sid) {
                    map.insert("provenance".into(), pv);
                }
                // C1：出厂默认值 / 产品建议（正交）。defaultKnown=false 时前端
                // 必须显示「出厂默认值未知」而不是留空 —— 留空会被读成「不需要偏离」。
                if let Some(dv) = defaults_of(sid) {
                    map.insert("defaults".into(), dv);
                }
                // B4：本项能否**逐项还原**（值级备份里有它，且 values 非空）。
                // 前端据此决定「立即恢复」是可用还是置灰 + 说明原因 ——
                // 没有这个字段时前端只能二选一：显示一个点了会失败的按钮，
                // 或者对所有项都置灰（后者把能还原的也堵了）。
                if let Some(n) = is_restorable(&backups, sid) {
                    map.insert("restorable".into(), json!(n));
                }
                // 批量项的**可自选目标**（2026-10-03 用户裁定）：这三项此前只有
                // 「一键全选 / 一键全还原」两个出口，用户看到的是「禁用 70 个服务」
                // 这种不可拆的黑箱（里面有 CryptSvc 这种禁不得的，也有 RetailDemo
                // 这种一眼可弃的）。前端据此在详情里渲染逐项勾选。
                // 不在表里 = 不注入该字段，而不是注入空数组 ——
                // 空数组会被前端读成「支持自选但一个目标都没有」。
                if let Some(sub) = super::subitems::subitems_of(sid) {
                    map.insert("subitems".into(), sub);
                }
            }
            tag_exec_modes(&mut row);
            row
        })
        .collect();
    json!({ "success": true, "data": rows })
}

/// optimizer:touch-recent —— 记一次「最近使用」（E10）
///
/// 写侧失败**不报错**：最近使用是「顺手记一下」的辅助信息，不是用户主动操作，
/// 写不进去不该打断流程。返回 `recorded: false` 供日志/排查，前端不弹提示。
#[tauri::command]
pub async fn optimizer_touch_recent<R: Runtime>(
    window: WebviewWindow<R>,
    option_id: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let option_id = option_id.unwrap_or_default();
    if option_id.is_empty() {
        return json!({ "success": false, "recorded": false, "message": "缺少优化项 id" });
    }
    let recorded = opt_state::touch_recent(&option_id);
    json!({ "success": true, "recorded": recorded })
}

/// optimizer:list-groups —— 分类两层结构（E7）
///
/// 形状 = `optimizer-groups.json` 的 `groups` 字段（`{default[], custom:{}}`）。
///
/// **档位 `MAIN` 而不是 `guard_readonly`**（由 check-guard-tiers 的 D5 组判出来的）：
/// 本命令**只读侧表**，但只有**主窗的优化页**消费它（`optimizer.js::init` 调
/// `applyGroupSidecar`）。四个子窗（预览 / 模型 / 进程管理 / 外设）都不加载
/// `optimizer.js`、也不渲染分类导航 —— 给它 readonly 档就是 D5 说的「白给放宽」：
/// 放行了全部五个窗口 label，却没有任何子窗消费方。
/// 判档依据是 AGENTS §3「以谁真的需要调它为准」，不是「它只读」。
#[tauri::command]
pub async fn optimizer_list_groups<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    json!({ "success": true, "data": groups_sidecar() })
}

/// optimizer:svc-mem-current —— 当前 SVCHost 拆分阈值档位
///
/// B11：原先这里落一个 4 行的临时 `.ps1`、spawn pwsh、60s 超时、再从 stdout 里抠
/// `KB|<n>` —— 为读一个 HKLM DWORD。现在直接 `read_hklm_dword`，同语义、零进程开销。
#[tauri::command]
pub async fn optimizer_svc_mem_current<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let Some(kb) = svc_mem_current_kb() else {
        // 值不存在（未设置过）→ 与原 PS 的 `NONE` 分支一致：报告成功但无档位
        return json!({ "success": true, "gb": Value::Null, "kb": Value::Null });
    };
    for (k, v) in MEMORY_KB {
        if *v == kb {
            return json!({ "success": true, "gb": k.parse::<i64>().ok().map(Value::from).unwrap_or(Value::Null), "kb": kb });
        }
    }
    if kb == MEMORY_KB_DEFAULT {
        return json!({ "success": true, "gb": "default", "kb": kb });
    }
    json!({ "success": true, "gb": Value::Null, "kb": kb })
}

/// optimizer:check-optimized —— 安全托底检测（id -> bool）
#[tauri::command]
pub async fn optimizer_check_optimized<R: Runtime>(
    window: WebviewWindow<R>,
    ids: Option<Vec<String>>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let ids = ids.unwrap_or_default();
    let results = check_optimized(&ids);
    json!({ "success": true, "results": results })
}

/// optimizer:batch-preflight —— 批量执行前的整批准入预检（M1）
///
/// **为什么要有这条**：单项闸门一直很严（`apply.rs` 的 `optimizer_run` 逐层
/// `guard(MAIN)` → `OptRunGuard` → `find_option` → `is_admin` → 高危确认），但前端
/// 批量是逐条 `await optimizer_run`，第 5 项失败时前 4 项**已经落盘**。预检把
/// 「哪几项会被拦、为什么」提前到整批动手之前告知用户。
///
/// **判据唯一真源** = [`preflight_reason`]，与单条执行链同一个函数。两处各判一份
/// 是本任务最容易犯的错：漂移后单条执行仍绿，只有预检错，而预检正是给用户看的那层。
///
/// **档位 `guard_readonly`（不是 MAIN）**：纯只读判定（只读 `is_admin` 与数据层
/// steps），不改任何系统状态。它与 `optimizer_check_optimized` 同域同档。判档依据是
/// AGENTS §3「以谁真的需要调它为准」—— 预检放在批量的确认弹窗之前，而确认弹窗由主窗
/// 发起，但子窗（如设置页若将来内嵌批量入口）预检本身无害。
///
/// **空 `ids` 的语义**：返回 `runnable: []` + `rejected: []`，**不**回「全部可执行」。
/// 空入参若被当成「没有要拒的」会让前端走进「零项全部通过」的确认弹窗，那是乐观放行。
#[tauri::command]
pub async fn optimizer_batch_preflight<R: Runtime>(
    window: WebviewWindow<R>,
    ids: Option<Vec<String>>,
    restore: Option<bool>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let ids = ids.unwrap_or_default();
    let restore = restore.unwrap_or(false);
    let mut runnable: Vec<String> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();
    for id in &ids {
        // 未知 id 记「未知选项」而不是跳过：跳过等于把它算进 runnable，
        // 前端会对一个不存在的项发 run 并拿到「未知的优化选项」—— 预检形同虚设。
        let Some(opt) = find_option(id) else {
            rejected.push(json!({ "id": id, "reason": "未知选项" }));
            continue;
        };
        match preflight_reason(opt, id, restore) {
            Some(r) => rejected.push(json!({ "id": id, "reason": r.message() })),
            None => runnable.push(id.clone()),
        }
    }
    json!({ "success": true, "runnable": runnable, "rejected": rejected })
}

/// optimizer:state-overview —— 记账清单 + stale 判定 + detected
#[tauri::command]
pub async fn optimizer_state_overview<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let raw = opt_state::all();
    // B4：备份表与可还原清单各读一次（原来同一份 34KB JSON 要解三次）
    let backups_mig = load_opt_backups();
    let restorable_mig = restorable_items(&backups_mig);
    let mut items: Vec<Value> = Vec::new();
    let mut pending_ids: Vec<String> = Vec::new();
    let mut check_ids: Vec<String> = Vec::new();

    for (id, rec) in &raw {
        let opt = find_option(id);
        // 变量名刻意区别于 optimizer_run 里的同名变量：check-optimizer-dynamic A2
        // 靠字面前缀定位 4000 字符窗口，本处同名声明会抢走第一个命中
        let is_dyn_record = opt.and_then(|o| o.get("dynamic")).and_then(|v| v.as_bool()).unwrap_or(false);
        if is_dyn_record {
            // 动态项遗留 pending 无法可靠核对，直接清理
            if rec.get("status").and_then(|v| v.as_str()) == Some("pending") {
                opt_state::remove(id);
            }
            continue;
        }
        let checkable = opt
            .map(collect_checks)
            .map(|c| !c.is_empty())
            .unwrap_or(false);
        let title = opt
            .and_then(|o| o.get("title").cloned())
            .unwrap_or_else(|| rec.get("title").cloned().unwrap_or(json!(id)));
        items.push(json!({
            "id": id,
            "title": title,
            "appliedAt": rec.get("appliedAt"),
            "kinds": rec.get("kinds"),
            "status": rec.get("status"),
            "lastVerify": rec.get("lastVerify"),
            // 根治（2026-10-03）：失败子步原因随条目下发——横幅与详情能显示「剩哪步失败」
            "partialReasons": rec.get("partialReasons").cloned().unwrap_or(Value::Null),
            "checkable": checkable
        }));
        match rec.get("status").and_then(|v| v.as_str()) {
            Some("pending") => pending_ids.push(id.clone()),
            // v5 P2：非 checkable（纯 pwsh / cmd 项）的 partial 此前两个分支都不进 ⇒
            // 界面永远看不到"这项只应用了一半"，用户只能从日志页发现（本次审计的起因就是这样）。
            Some("partial") if !checkable => pending_ids.push(id.clone()),
            _ if checkable => check_ids.push(id.clone()),
            _ => {}
        }
    }

    let mut stale_ids = pending_ids;
    if !check_ids.is_empty() {
        let results = check_optimized(&check_ids);
        for id in &check_ids {
            if results.get(id) == Some(&false) {
                stale_ids.push(id.clone());
            }
        }
    }
    // 根治（2026-10-03 用户拍板）：用户点过「不再提醒」的 id 不再进 staleIds。
    // 忽略记录在该项重新执行（record_pending / mark_applied / mark_partial）或
    // 还原销账时自动清除——状态刚变过，若又 partial 应重新提醒。
    let dismissed = opt_state::dismissed_map();
    stale_ids.retain(|id| !dismissed.contains_key(id));

    json!({
        "success": true,
        "items": items,
        "staleIds": stale_ids,
        // v2-M14：这里原先是 `{ "restored": [], "failed": [] }` 的字面空桩，渲染层据此弹
        // 「已自动还原 N 项」——那件事从没发生过。空桩删除后字段改成**待还原清单**：
        // 退役项在本机留有注册表备份的才出现，由用户点「按原值还原」走已提权的还原通道。
        // B4：可逐项还原的清单。改写前只有 `pending`（**只**含退役项），
        // 而本机实测 34 项备份里绝大多数是在用项 —— 能力在、入口找不到。
        // 两个字段分开返回：active= 在用项的，retired= 退役待还原（概览既有位置）。
        "migration": {
            "pending": retired_pending_backups(&backups_mig),
            "restorableActive": restorable_mig.0,
            "restorableRetired": restorable_mig.1,
        },
        "detected": Value::Object(opt_state::detected_all())
    })
}

/// optimizer:stale-dismiss —— 「未完成还原」横幅的 per-id 忽略（主窗档）。
///
/// 根治「横幅每次启动都弹」（2026-10-03 用户拍板）：用户点「不再提醒」把 id 记进
/// prefs.staleDismissed，state_overview 不再把它们判进 staleIds。写侧是记账文件的
/// prefs 段（与优化项状态同文件原子写），不是前端 localStorage——「重新执行自动
/// 清除」的语义在 Rust 记账路径上才能保证（record_pending / mark_applied /
/// mark_partial / remove 统一清忽略），跨进程边界的前端自持名单做不到。
///
/// 档位按「谁真的需要调它」判：优化页只在主窗，dismiss 是写操作 → MAIN。
#[tauri::command]
pub async fn optimizer_stale_dismiss<R: Runtime>(window: WebviewWindow<R>, ids: Vec<String>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // 上限取「优化目录规模 × 2」的量级：防渲染层异常批量塞垃圾写爆记账文件
    const DISMISS_MAX: usize = 300;
    let mut n = 0usize;
    for id in ids.into_iter().take(DISMISS_MAX) {
        if opt_state::dismiss_stale(&id) {
            n += 1;
        }
    }
    json!({ "success": true, "data": { "dismissed": n } })
}

