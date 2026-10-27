//! B8 维护任务 + 计划任务变更出口 + 「删目录前是否被阻挡」判定。
//!
//! `dir_delete_blocked` 是跨命令复用的公判据（diskbench / uninstall 都在用），
//! maint_reparse_tests 与实现同在本文件。maint_run 内跑子进程一律走 `system_tool`，
//! 且有 `MAINT_CMD_TIMEOUT` 上限。
//!
//! B2-7（2026-10-27）：`maint_run` 的 `search` / `wu` 两支**不再**用 `dir_delete_blocked`
//! —— 删前判定换成 `protect::validate_mutation_target`（四道组合闸），删除动作换成
//! `trim_finder::scan::recycle::send_to_trash_os`（回收站优先、失败不回退永久删）。
//! `dir_delete_blocked` 只剩 diskbench / uninstall 两个消费方，与维护链已非同口径，
//! 别再拿它当「维护任务怎么判」的依据。


use crate::engine::systembin::system_tool;
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_CREATED_NEW_KEY, REG_DWORD, REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegEnumKeyExW, RegOpenKeyExW, RegSetValueExW};
use super::common::*;
// ==================== 维护任务删目录前校验测试（审查 v2-L1 回归网） ====================

#[cfg(test)]
mod maint_reparse_tests {
    use super::*;
    use std::path::Path;

    /// 真实系统目录（及其到盘符根的整条链）必须放行 —— 防「为了防误删把功能废掉」。
    /// search / wu 清理的目标目录正是这类固定系统路径。
    #[test]
    fn real_system_dirs_pass() {
        for p in [
            r"C:\Windows\System32",
            r"C:\Windows\SoftwareDistribution",
        ] {
            assert!(
                dir_delete_blocked(Path::new(p)).is_none(),
                "真实系统目录不得被阻断: {p} — {:?}",
                dir_delete_blocked(Path::new(p))
            );
        }
    }

    /// 属性读不到的路径（不存在 / 无权限）必须按拒绝处理：
    /// 「查不到」不许等价于「安全」（fail-closed）。
    #[test]
    fn unreadable_path_is_refused() {
        let r = dir_delete_blocked(Path::new(r"C:\TrimNoSuchDir-9f3a\DataStore"));
        assert!(r.is_some(), "不存在的路径必须拒绝删除，实测: {r:?}");
    }

    // ==================== B2-7：维护链删前判定 + 回收站 ====================

    /// B2-7 验收：`wu` 支必须回「系统区域拒绝」，**不许**回「已清空」。
    ///
    /// 判红自证：把 `cache_delete_blocked` 换成裸 `is_path_protected` ⇒ 该判据对
    /// `SoftwareDistribution\DataStore` 恒放行 ⇒ 回执退化成兜底措辞（不含「系统命名空间」）
    /// ⇒ 本用例红。这一条同时证明「它不是一条永不触发的断言」。
    #[test]
    fn b2_7_wu_支回系统区域拒绝而不是已清空() {
        let (ok, msg) = maint_run("wu").expect("maint_run 必须返回回执");
        assert!(!ok, "wu 支的功能已下线，不许报成功: {msg}");
        assert!(msg.contains("系统区域"), "回执必须点名「属系统区域」: {msg}");
        assert!(msg.contains("系统命名空间"), "拒因必须来自组合闸（不是兜底文本）: {msg}");
        assert!(!msg.contains("已清空"), "下线支不许出现「已清空」这种恒真措辞: {msg}");
    }

    /// B2-7：两支的目标都来自**注入的基目录**，不再硬编码 `C:\ProgramData` / `C:\Windows`。
    ///
    /// 判红自证：把 `cache_dir_in` 改成 `Path::new(r"C:\ProgramData").join(...)` ⇒ 第一条红。
    #[test]
    fn b2_7_维护目标由基目录注入而非硬编码() {
        let pd = cache_dir_in(r"D:\AltProgramData", "search").expect("search 目标应可拼出");
        assert_eq!(
            pd,
            std::path::PathBuf::from(r"D:\AltProgramData\Microsoft\Search\Data\Applications\Windows"),
            "search 目标必须跟随 PROGRAMDATA 基目录（非系统盘机器才不会指错位）"
        );
        let win = cache_dir_in(r"E:\AltWindows", "wu").expect("wu 目标应可拼出");
        assert_eq!(
            win,
            std::path::PathBuf::from(r"E:\AltWindows\SoftwareDistribution\DataStore")
        );
        // 基目录为空 / 未知目标一律拒绝 —— 不退回硬编码
        assert!(cache_dir_in("", "search").is_err());
        assert!(cache_dir_in("  ", "wu").is_err());
        assert!(cache_dir_in(r"C:\x", "no_such_task").is_err());
        // 现算：真实环境取到的就是 env 下那一条（同时钉住变量名没写错）
        let real = maintenance_cache_dir("search").expect("本机应有 PROGRAMDATA");
        let pd_env = std::env::var("PROGRAMDATA").expect("本机应有 PROGRAMDATA");
        assert_eq!(
            real,
            std::path::PathBuf::from(&pd_env).join(r"Microsoft\Search\Data\Applications\Windows")
        );
    }

    /// B2-7 验收：删除目标本身被换成链接 ⇒ 必拒（组合闸的 reparse 面），且链接另一头零改动。
    /// 正向对照：普通目录必须放行 —— 否则「恒拒」也能让上面那条绿。
    #[test]
    fn b2_7_目标被换成链接时判据必拒() {
        let sb = crate::testutil::Sandbox::new(&format!("maint-b27-{}", std::process::id()));
        let real = sb.path().join("idx");
        std::fs::create_dir_all(&real).unwrap();
        assert!(cache_delete_blocked(&real).is_ok(), "普通目录必须放行（正对照）");
        let link = sb.path().join("idx_link");
        if std::os::windows::fs::symlink_dir(&real, &link).is_err() {
            println!("SKIP：本机 symlink_dir 失败（需开发者模式/提权），reparse 一面未校验");
            return;
        }
        let why = cache_delete_blocked(&link).expect_err("链接必须被拒");
        assert!(
            why.contains("reparse") || why.contains("链接"),
            "拒因必须点名 reparse: {why}"
        );
        // 判定只判定不删：链接另一头还在
        assert!(real.is_dir(), "判定期不得动链接另一头");
    }

    /// B2-7：维护链只走回收站，本文件不许再出现永久删目录（失败也不回退）。
    ///
    /// 判红自证：把 `send_to_trash_os` 换回 `fs::remove_dir_all` ⇒ 两条断言都红。
    #[test]
    fn b2_7_维护链只走回收站不永久删() {
        let src = include_str!("maintenance.rs");
        assert!(
            src.contains("trim_finder::scan::recycle::send_to_trash_os("),
            "search 支必须走回收站原语"
        );
        // needle 必须**拼接**构造：本断言自身就在被扫的源码里，写字面量会让它自指恒红
        let needle = concat!("std::fs::", "remove_dir_all");
        assert!(
            !src.contains(needle),
            "本文件不许再有永久删目录的调用（B2-7：改回收站、失败不回退永久删）"
        );
    }

    /// P1-01 真机探针：管理员会话实跑完整计数器链，断言成功路径（rc 分档）。
    #[test]
    #[ignore = "真机：性能计数器三步链 + 验证（管理员，数十秒），发布前人工跑"]
    fn live_perfcounters_real_flow() {
        if !crate::engine::sysinfo::is_admin() {
            eprintln!("SKIP：需管理员会话，当前非提权，未校验");
            return;
        }
        let (ok, msg) = maint_run("perfcounters").expect("maint_run 应返回");
        assert!(ok, "完整成功路径实测失败：{msg}");
        assert!(msg.contains("验证通过"), "回执应点名验证通过：{msg}");
    }

    /// P1-04 真机探针：写 wuauserv Start=4 → 触发 WaaSMedic PerformRemediation
    /// → 轮询回读是否被复位。原值由 Drop 守卫还原（AGENTS §1.6：判据走真实注册表必配探针）。
    #[test]
    #[ignore = "真机：观察 WaaSMedic 是否复位 wuauserv（管理员，约 5 分钟）"]
    fn live_waasmedic_reset_probe() {
        use windows::Win32::System::Registry::REG_VALUE_TYPE;
        if !crate::engine::sysinfo::is_admin() {
            eprintln!("SKIP：需管理员会话，当前非提权，未校验");
            return;
        }
        const SVC_SUB: &str = r"SYSTEM\CurrentControlSet\Services\wuauserv";
        let orig = crate::engine::native::read_hklm_dword(SVC_SUB, "Start");
        // 兜底还原（含 panic 提前返回）
        struct Restore(Option<i64>);
        impl Drop for Restore {
            fn drop(&mut self) {
                if let Some(v) = self.0 {
                    let bytes = (v as u32).to_le_bytes();
                    let _ = crate::engine::native::reg_restore_write(
                        crate::engine::native::hive_hklm(),
                        SVC_SUB, "Start", REG_VALUE_TYPE(4), &bytes,
                    );
                }
            }
        }
        let _restore = Restore(orig);

        let task = r"\Microsoft\Windows\WaaSMedic\PerformRemediation";
        // 探针前置：任务不存在则 skip（系统版本差异）
        let q = crate::engine::systembin::quiet_cmd_timeout(crate::engine::systembin::system_tool("schtasks").expect("schtasks 必须解析成功"), &["/query", "/TN", task], MAINT_FAST_TIMEOUT);
        if !q.as_ref().is_ok_and(|o| o.status.success()) {
            eprintln!("SKIP：WaaSMedic PerformRemediation 任务不存在，本探针未校验");
            return;
        }
        // 探针前置二：任务处于禁用态时 /run 必失败（优化工具禁用 WaaSMedic 是常见状态，
        // 本机实测即如此）；如实按 skip 标注未校验，不误判成判红。
        // A6-L04：改读任务 XML 的 <Enabled>，不再匹配 schtasks 列的本地化 "Disabled/已禁用"
        // （非中英系统上会漏判，把本当 skip 的情况当判红）。
        let ql = crate::engine::systembin::quiet_cmd_timeout(crate::engine::systembin::system_tool("schtasks").expect("schtasks 必须解析成功"), &["/query", "/TN", task, "/XML"], MAINT_FAST_TIMEOUT);
        let task_xml = ql.as_ref().map(|o| crate::engine::systembin::decode_native_output(&o.stdout)).unwrap_or_default();
        let compact_xml: String = task_xml.chars().filter(|c| !c.is_whitespace()).collect();
        if compact_xml.contains("<Enabled>false</Enabled>") {
            eprintln!("SKIP：WaaSMedic PerformRemediation 任务在本机处于禁用状态，触发不了，本探针未校验");
            return;
        }

        // 写 Start=4
        let wrote = crate::engine::native::reg_restore_write(
            crate::engine::native::hive_hklm(),
            SVC_SUB, "Start", REG_VALUE_TYPE(4), &4u32.to_le_bytes(),
        );
        assert!(wrote, "wuauserv Start=4 写入应成功");

        // 触发修复任务
        let run = crate::engine::systembin::quiet_cmd_timeout(crate::engine::systembin::system_tool("schtasks").expect("schtasks 必须解析成功"), &["/run", "/TN", task], MAINT_FAST_TIMEOUT);
        assert!(run.as_ref().is_ok_and(|o| o.status.success()),
            "PerformRemediation 触发失败");

        // 轮询 5 分钟：每 10s 回读
        let mut final_val = 4i64;
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_secs(10));
            final_val = crate::engine::native::read_hklm_dword(SVC_SUB, "Start").unwrap_or(-1);
            if final_val != 4 { break; }
        }
        eprintln!("探针结果：wuauserv Start 最终 = {final_val}（4=未被复位；2/3=被 Medic 复位）");
        // reached 断言：写入与触发均已执行；结论值落日志供第 3 步决策
        assert!(final_val >= 0, "回读异常");
    }
}


/// 计划任务变更的执行结果分类（P1-01）。
///
/// 三类必须分开，不能共用一个 `Result<(), String>`：
/// - [`TaskRun::Succeeded`]：命令成功；
/// - [`TaskRun::RanFailed`]：命令**确实启动**并返回了非零退出码（任务不存在、
///   权限不足等）；
/// - [`TaskRun::NotRan`]：命令**根本没跑起来**（系统工具解析失败、spawn 失败、超时）。
///
/// 只有第二类才允许按源脚本的静默语义降级成警告：把第三类也降级，等于把
/// 「执行器不可用」谎报成「已完成」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRun {
    Succeeded,
    /// 命令跑起来了但返回非零退出码
    RanFailed { exit_code: Option<i32>, message: String },
    /// 命令没跑起来（解析失败 / spawn 失败 / 超时）
    NotRan { reason: String },
}

/// 启用/禁用计划任务（对应 `Disable/Enable-ScheduledTask`，与启动项链同一工具）
///
/// `path` 为含尾反斜杠的任务路径（如 `\Microsoft\Windows\Defrag\`），与数据层 `taskPath` 同形。
///
/// 返回值是**执行分类**而不是 `Result`：调用方要能分辨「任务改不动」与「命令没跑起来」，
/// 前者可按源脚本的静默语义降级，后者一律是失败。
pub fn task_change(path: Option<&str>, name: &str, disable: bool) -> TaskRun {
    let full = format!("{}{}", path.unwrap_or_default(), name);
    let arg = if disable { "/DISABLE" } else { "/ENABLE" };
    // v4 R5-M07：裸 .output() 改带超时（任务计划服务被拖住时不能永久锁 IPC）
    // v6-K01（P0-2）：解析失败与 spawn 失败同报错口径
    let exe = match crate::engine::systembin::system_tool("schtasks") {
        Ok(p) => p,
        Err(e) => {
            return TaskRun::NotRan {
                reason: format!("schtasks 无法定位（命令未运行）: {e}"),
            }
        }
    };
    let output = match crate::engine::systembin::quiet_cmd_timeout(
        &exe,
        &["/Change", "/TN", &full, arg],
        crate::engine::systembin::SCHTASKS_TIMEOUT,
    ) {
        Ok(o) => o,
        Err(e) => {
            return TaskRun::NotRan {
                reason: format!("schtasks 未运行（命令未启动或超时）: {e}"),
            }
        }
    };
    if output.status.success() {
        TaskRun::Succeeded
    } else {
        let stderr = crate::engine::systembin::decode_native_output(&output.stderr);
        let message = if stderr.is_empty() {
            format!(
                "计划任务{}未生效（可能需要管理员权限）: {full}",
                if disable { "禁用" } else { "启用" }
            )
        } else {
            stderr
        };
        TaskRun::RanFailed {
            exit_code: output.status.code(),
            message,
        }
    }
}

// ==================== B8 maint：维护命令 ====================

/// 维护任务子进程超时上限（v2-L4P-37 / F-6）：sfc /scannow 与 DISM RestoreHealth
/// 合法耗时可达数十分钟，30 分钟取模块文档的既有上限；sc/wsreset 等快命令被同一
/// 上限兜住（正常毫秒级，永到不了）。此前 run_cmd 无超时——挂住的 sfc 会把维护
/// 页永久锁死。登记于 check-ps-callsites 的 F 组（quiet_cmd_timeout 调用点）。
pub const MAINT_CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// wsreset.exe 的超时上限（v5 S-1）：它自己会拉起商店窗口并清缓存，正常几秒自退；
/// 60s 是宽限上界。刻意不复用 MAINT_CMD_TIMEOUT —— 那是 sfc/DISM 的量级，
/// 拿 30 分钟兜一个恒挂的 wsreset 等于把维护锁占死半小时。
pub const WSRESET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// P1-01：性能计数器三步链（lodctr / winmgmt / typeperf）统一 60s 上限。
/// 用户裁定命令与验证统一按 60 秒做；均秒级，恒挂场景不占满维护锁。
pub const MAINT_FAST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn run_cmd(program: &str, args: &[&str]) -> bool {
    // 审查 v2-F7：系统工具必须解析到 System32 再执行，不能用裸进程名 ——
    // 搜索顺序里「exe 所在目录」与「父进程 CWD」都排在 System32 之前。
    // v6-K01（P0-2）：解析失败留痕并按失败回（白名单内解析不到 = 系统异常，不裸名回退）
    let exe = match crate::engine::systembin::system_tool(program) {
        Ok(p) => p,
        Err(e) => {
            crate::engine::log::write_log("error", &format!("维护命令系统工具解析失败: {program} — {e}"));
            return false;
        }
    };
    match crate::engine::systembin::quiet_cmd_timeout(exe, args, MAINT_CMD_TIMEOUT) {
        Ok(out) if out.status.success() => true,
        // v5 S-4：失败必须留痕。旧写法把 stdout/stderr 全丢，于是 sfc /scannow 的三态结论
        // （未发现问题 / 已修复 / 无法修复）与 30 分钟超时被折叠成同一句「检查失败」，
        // 用户无从判断该不该再跑一次。只留尾 400 字，避免整份 CBS 报告灌进日志文件。
        Ok(out) => {
            let clip = |s: &str| -> String {
                s.trim().chars().rev().take(400).collect::<Vec<_>>().into_iter().rev().collect()
            };
            crate::engine::log::write_log(
                "warn",
                &format!(
                    "维护命令未成功: {program} {args:?} exit={:?} stdout=「{}」stderr=「{}」",
                    out.status.code().unwrap_or(-1),
                    clip(&crate::engine::systembin::decode_native_output(&out.stdout)),
                    clip(&crate::engine::systembin::decode_native_output(&out.stderr)),
                ),
            );
            false
        }
        Err(e) => {
            crate::engine::log::write_log("warn", &format!("维护命令无法执行: {program} — {e}"));
            false
        }
    }
}

/// 当前服务状态码（`SERVICE_STOPPED`=1 / `SERVICE_RUNNING`=4）；查不到返回 None。
fn service_state(name: &str) -> Option<u32> {
    unsafe { super::services::service_status(name).map(|(s, _)| s) }
}

/// 请求停止服务并**轮询到 STOPPED**（v5 S-2 / S-3）。
///
/// `sc stop` 是异步的：返回 0 只代表停止请求被受理。旧写法固定睡 2s（search/wu）或 500ms
/// （restart_service）就当停稳，于是索引库文件仍被占用时 `remove_dir_all` 必然失败，
/// 而结果又被 `let _ =` 吞掉。
fn stop_service_wait(name: &str, budget: std::time::Duration) -> bool {
    // v6-K01（P0-2）：解析失败按「停服务失败」处理（返回 false 由调用方如实回执）
    let Ok(sc) = crate::engine::systembin::system_tool("sc") else { return false };
    // R5b-M09：sc stop 是短命令（30s 档），不能用维护链的 1800s 总超时。
    let _ = crate::engine::systembin::quiet_cmd_timeout(
        &sc,
        &["stop", name],
        crate::engine::systembin::SC_CMD_TIMEOUT,
    );
    let deadline = std::time::Instant::now() + budget;
    loop {
        if service_state(name) == Some(1) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// 请求启动服务并轮询到 RUNNING（同上：`sc start` 返回 0 时服务可能还在 START_PENDING）
fn start_service_wait(name: &str) -> bool {
    // R5b-M09：sc start 同样是短命令（30s 档）；run_cmd 用的是 1800s 维护总超时。
    let Ok(sc) = crate::engine::systembin::system_tool("sc") else { return false };
    match crate::engine::systembin::quiet_cmd_timeout(
        &sc,
        &["start", name],
        crate::engine::systembin::SC_CMD_TIMEOUT,
    ) {
        Ok(out) if out.status.success() => {}
        _ => return false,
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if service_state(name) == Some(4) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn restart_service(name: &str) -> bool {
    // v5 S-3：旧写法 `let _ = quiet_cmd_timeout(..).is_ok()` 把停止结果丢掉（写了等于没写），
    // 服务仍在运行时紧接着 `sc start` 会返回 1056（已在运行）→ 在**正常机器**上恒报
    // 「音频服务重启失败」。改成按终态走：在跑就先停稳再启，本就停着则直接启。
    match service_state(name) {
        None => false, // 服务不存在：不谎报「重启成功」
        Some(4) => {
            stop_service_wait(name, std::time::Duration::from_secs(15)) && start_service_wait(name)
        }
        Some(_) => start_service_wait(name),
    }
}

fn split_reg_hive(path: &str) -> Option<(HKEY, &str)> {
    let (hive, sub) = match path.split_once('\\') {
        Some((h, s)) => (h, s),
        None => (path, ""),
    };
    let h = match hive {
        "HKEY_LOCAL_MACHINE" | "HKLM" => HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER" | "HKCU" => HKEY_CURRENT_USER,
        _ => return None,
    };
    Some((h, sub))
}

/// `"名称"=dword:八位十六进制` → (名称, 值)；不支持的写法返回 None
fn parse_reg_dword(line: &str) -> Option<(String, u32)> {
    let (name, rest) = line.split_once('=')?;
    let name = name.trim();
    if !(name.starts_with('"') && name.ends_with('"') && name.len() >= 2) { return None; }
    let name = &name[1..name.len() - 1];
    if name.is_empty() { return None; }
    let hex = rest.trim().strip_prefix("dword:")?;
    if hex.len() != 8 { return None; }
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some((name.to_string(), v))
}

/// .reg 文本 → 逐键写入注册表（不落盘、不起外部进程）
///
/// 审查 v2-F2：原实现把内容写进 `std::env::temp_dir()`（全局可写 `%TEMP%`），文件名
/// 可预测（`tfmaint_<毫秒>`），再由 `reg.exe import` 读回 —— 在管理员令牌下同时打开
/// TOCTOU 回写与 junction 预占两条本地提权窗口，且违反 `AGENTS.md` §3「临时脚本只写
/// 应用私有 tmp 目录」。改为直接 `RegCreateKeyExW` + `RegSetValueExW`，两条窗口一并消失。
///
/// 语法支持面刻意收窄到本模块维护任务实际用到的：`[HIVE\子键]` 段 + 若干
/// `"名"=dword:XXXXXXXX`。**先整体解析再统一写入**：任何一行解析不了就返回 false，
/// 不留下半写状态。
fn reg_import(reg_content: &str) -> bool {
    #[allow(clippy::type_complexity)]
    let mut sections: Vec<(HKEY, String, Vec<(String, u32)>)> = Vec::new();
    let mut cur: Option<(HKEY, String, Vec<(String, u32)>)> = None;

    for raw in reg_content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with("Windows Registry Editor Version") {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(prev) = cur.take() { sections.push(prev); }
            match split_reg_hive(inner) {
                Some((hive, sub)) => cur = Some((hive, sub.to_string(), Vec::new())),
                None => return false,
            }
            continue;
        }
        match parse_reg_dword(line) {
            Some((name, val)) => match cur.as_mut() {
                Some(s) => s.2.push((name, val)),
                None => return false, // 值出现在任何 [键] 之前，属畸形输入
            },
            None => return false,
        }
    }
    if let Some(prev) = cur.take() { sections.push(prev); }
    if sections.is_empty() { return false; }

    let mut ok = true;
    unsafe {
        for (hive, sub, vals) in &sections {
            let sk = to_wide(sub);
            let mut hk = HKEY::default();
            let mut disp = REG_CREATED_NEW_KEY;
            if RegCreateKeyExW(
                *hive, PCWSTR(sk.as_ptr()), None, PCWSTR::default(),
                REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut hk, Some(&mut disp),
            ).is_err() {
                ok = false;
                continue;
            }
            for (name, val) in vals {
                let nm = to_wide(name);
                if RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes())).is_err() {
                    ok = false;
                }
            }
            let _ = RegCloseKey(hk);
        }
    }
    ok
}

/// 维护链两支的删除目标（**路径取源唯一出口**）。
///
/// B2-7：旧写法把 `C:\ProgramData` / `C:\Windows` 硬编码在两个分支里 —— 非系统盘、或改过
/// `PROGRAMDATA` 的机器会指到错位置（同名目录在别的盘上，删的是不相干的东西）。
/// 现在只认环境变量；取不到就**拒绝执行**，不退回硬编码 —— 猜一个系统目录去删，
/// 猜错的方向就是删数据。
fn maintenance_cache_dir(which: &str) -> Result<std::path::PathBuf, String> {
    let var = match which {
        "search" => "PROGRAMDATA",
        "wu" => "WINDIR",
        other => return Err(format!("未知维护目标 {other}")),
    };
    let base = std::env::var(var)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("环境变量 {var} 取不到，不猜系统目录位置"))?;
    cache_dir_in(&base, which)
}

/// 目标拼接的纯函数部分（基目录由调用方给），单测因此能证明「基目录是注入的、不是硬编码」。
fn cache_dir_in(base: &str, which: &str) -> Result<std::path::PathBuf, String> {
    let tail = match which {
        "search" => r"Microsoft\Search\Data\Applications\Windows",
        "wu" => r"SoftwareDistribution\DataStore",
        other => return Err(format!("未知维护目标 {other}")),
    };
    if base.trim().is_empty() {
        return Err("基目录为空，不猜系统目录位置".to_string());
    }
    Ok(std::path::Path::new(base).join(tail))
}

/// 维护链「删前判定」的唯一出口（B2-7）：与 fileclean 删除走**同一个**组合闸。
///
/// 为什么不再用 `dir_delete_blocked`：它只查 reparse（本仓的第三套判定），既不判受保护面
/// 也不判系统命名空间 —— `%WINDIR%` 子孙直接穿过去，这正是「清空更新缓存」这一支的现状。
/// 也**不许**在这里写裸 `is_path_protected`：受保护清单的 `subtree` 只有 `{APPDATA}\Trim`
/// 与 `{WINDIR}\System32\config` 两棵，对 `SoftwareDistribution\DataStore` 恒假，
/// 加它等于加一条永不触发的断言（假绿）。
fn cache_delete_blocked(dir: &std::path::Path) -> Result<(), String> {
    crate::engine::protect::validate_mutation_target(&dir.to_string_lossy())
}

/// 删除固定目录前的重解析点（junction / 符号链接）校验
///
/// 审查 v2-L1：`maint_run` 的 search / wu 两条会对**固定系统目录**做 `remove_dir_all`，
/// 此前不查属性位。若目标或其任一上级被换成指向别处的 junction（误操作、软件搬家、
/// 恶意替换都可能），`remove_dir_all` 会顺着链接把目标位置的内容删掉——「清缓存」
/// 变成删数据。因此删前从自身到盘符根逐层查 `FILE_ATTRIBUTE_REPARSE_POINT`。
///
/// **B2-7 起 `maint_run` 不再调用本函数**：维护链改走 `cache_delete_blocked` →
/// `protect::validate_mutation_target`（四道闸，其中已含 reparse 与父链闸）。
/// 本函数保留是因为 diskbench 与 uninstall 残留链还在用（两处各自有独立口径），
/// 但「维护任务怎么判」请只看 `cache_delete_blocked`。
///
/// 返回 `Some(原因)` = 拒绝删除（含属性读不到：fail-closed，不许「查不到就当安全」）。
pub(crate) fn dir_delete_blocked(path: &std::path::Path) -> Option<String> {
    if let Some(r) = level_reparse_reason(path) {
        return Some(r);
    }
    ancestor_reparse_blocked(path)
}

/// 单级重解析点判定（属性读不到按拒：fail-closed，不许「查不到就当安全」）。
fn level_reparse_reason(level: &std::path::Path) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT};
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
    let wide = to_wide(&level.to_string_lossy());
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Some(format!("无法读取目录属性（{}），按拒绝处理", level.display()));
    }
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Some(format!("{} 是重解析点（junction/符号链接），删除会波及链接目标", level.display()));
    }
    None
}

/// J12（2026-10-16）：只查**自身以外**的上级链——自身是断链重解析点的形态由调用方
/// 先过 `trim_finder::scan::broken_reparse_link` 放行（删链接本体不波及目标），
/// 但「上级是链接」这条必须照旧拒（借目录树删别处的形态没变）。
pub(crate) fn ancestor_reparse_blocked(path: &std::path::Path) -> Option<String> {
    // Path::ancestors() 自带「自身 → 逐级父目录 → 根」，skip(1) 跳过自身
    for level in path.ancestors().skip(1) {
        if let Some(r) = level_reparse_reason(level) {
            return Some(r);
        }
    }
    None
}

/// 维护命令执行（对应 maint_*.ps1，S3）
///
/// 覆盖任务数以 data/maintenance-tasks.json 现算为准（v2-L4P-55/C-10：注释计数必须与数据同源，散文数字已删）。返回 (success, output_message)。
pub fn maint_run(task_id: &str) -> Result<(bool, String), String> {
    match task_id {
        "sfc" => {
            crate::engine::log::write_log("info", "维护：sfc /scannow");
            let ok = run_cmd("sfc.exe", &["/scannow"]);
            Ok((ok, if ok { "系统文件检查完成".into() } else { "系统文件检查失败".into() }))
        }
        "dism" => {
            crate::engine::log::write_log("info", "维护：DISM /RestoreHealth");
            let ok = run_cmd("dism.exe", &["/Online", "/Cleanup-Image", "/RestoreHealth"]);
            Ok((ok, if ok { "组件存储修复完成".into() } else { "组件存储修复失败".into() }))
        }
        "dns" => {
            let ok = run_cmd("ipconfig.exe", &["/flushdns"]);
            Ok((ok, if ok { "DNS 缓存已刷新".into() } else { "DNS 刷新失败".into() }))
        }
        "perfcounters" => {
            // P1-01：官方修复链 —— ① lodctr /R（64 位）② 存在时 SysWOW64\lodctr /R
            // ③ winmgmt /resyncperf ④ typeperf 采样验证；60s 统一上限，回执按档如实分。
            // v6-K01（P0-2）：解析失败并进既有 Err 消费（「无法执行」口径）
            let r1 = match system_tool("lodctr.exe") {
                Ok(exe) => crate::engine::systembin::quiet_cmd_timeout(exe, &["/R"], MAINT_FAST_TIMEOUT),
                Err(e) => Err(std::io::Error::other(e)),
            };
            let ok64 = r1.as_ref().is_ok_and(|o| o.status.success());
            if !ok64 {
                let note = match &r1 {
                    Ok(o) => crate::engine::systembin::decode_native_output(&o.stdout),
                    Err(e) => format!("无法执行: {e}"),
                };
                let msg = format!(
                    "64 位性能计数器重建失败（lodctr /R），后续步骤未执行：{}",
                    note.trim()
                );
                crate::engine::log::write_log("warn", &format!("维护：{msg}"));
                return Ok((false, msg));
            }
            let mut faults: Vec<String> = Vec::new();
            // 失败原因提取（exit + 输出尾段）：三/四步对齐第一步，不回固定串（L3）
            let brief = |r: &std::result::Result<std::process::Output, std::io::Error>| -> String {
                match r {
                    Ok(o) => {
                        let raw = if !o.stdout.is_empty() { &o.stdout } else { &o.stderr };
                        let tail: String =
                            crate::engine::systembin::decode_native_output(raw)
                                .trim()
                                .chars()
                                .take(120)
                                .collect();
                        let mut s = format!("exit={}", o.status.code().unwrap_or(-1));
                        if !tail.is_empty() {
                            s.push_str("：");
                            s.push_str(&tail);
                        }
                        s
                    }
                    Err(e) => format!("无法执行: {e}"),
                }
            };
            // ② SysWOW64（绝对路径，第三目录 system_tool 不覆盖）：存在才执行
            let wow = std::env::var_os("SystemRoot")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
                .join(r"SysWOW64\lodctr.exe");
            let mut has32 = false;
            if wow.is_file() {
                has32 = true;
                let r2 = crate::engine::systembin::quiet_cmd_timeout(&wow, &["/R"], MAINT_FAST_TIMEOUT);
                if !r2.as_ref().is_ok_and(|o| o.status.success()) {
                    faults.push(format!("32 位计数器重建失败（SysWOW64 lodctr /R，{}）", brief(&r2)));
                }
            }
            // ③ winmgmt /resyncperf
            let r3 = match system_tool("winmgmt.exe") {
                Ok(exe) => crate::engine::systembin::quiet_cmd_timeout(exe, &["/resyncperf"], MAINT_FAST_TIMEOUT),
                Err(e) => Err(std::io::Error::other(e)),
            };
            if !r3.as_ref().is_ok_and(|o| o.status.success()) {
                faults.push(format!("WMI 计数器同步未成功（winmgmt /resyncperf，{}）", brief(&r3)));
            }
            // ④ 验证：typeperf 采样一次，rc=0 才算通过
            let r4 = match system_tool("typeperf.exe") {
                Ok(exe) => crate::engine::systembin::quiet_cmd_timeout(
                    exe,
                    &[r"\Processor(_Total)\% Processor Time", "-sc", "1"],
                    MAINT_FAST_TIMEOUT,
                ),
                Err(e) => Err(std::io::Error::other(e)),
            };
            let verified = r4.as_ref().is_ok_and(|o| o.status.success());

            if verified && faults.is_empty() {
                let scope = if has32 { "64 位 + 32 位" } else { "64 位" };
                Ok((true, format!("性能计数器已重建（{scope}），WMI 已同步，验证通过")))
            } else if !verified {
                // L1：只陈述「重建步骤已执行」，不谎称同步完成（faults 可能含同步失败）
                let mut details = faults.clone();
                details.push(format!("采样验证未通过（typeperf，{}）", brief(&r4)));
                Ok((false, format!(
                    "重建步骤已执行，但验证未通过；建议重启后复查，仍异常请运行 sfc/DISM。{}",
                    details.join("；")
                )))
            } else {
                // 验证已过但个别步骤失败：点名，不混成「全成」
                Ok((false, format!(
                    "验证通过，但部分步骤未成功：{}", faults.join("；")
                )))
            }
        }
        "store" => {
            // v5 S-1：旧写法 `let _ = …spawn(); Ok((true, …))` 是**恒真回执** —— wsreset 缺失、
            // 被组策略拦、启动即崩，都照样报「已完成」；且 spawn 不 wait：子进程无人收、无超时、
            // 不在任何登记表。改成等退出码（wsreset 正常几秒内自退，60s 是宽限上界）。
            // v6-K01（P0-2）：解析失败并进既有 Err 臂（「wsreset 无法执行」口径）
            match system_tool("wsreset.exe")
                .map_err(std::io::Error::other)
                .and_then(|exe| crate::engine::systembin::quiet_cmd_timeout(exe, &[], WSRESET_TIMEOUT))
            {
                Ok(o) if o.status.success() => Ok((true, "Store 缓存已清理".into())),
                Ok(o) => Ok((false, format!(
                    "wsreset 未成功（exit={}）",
                    o.status.code().unwrap_or(-1)
                ))),
                Err(e) => Ok((false, format!("wsreset 无法执行: {e}"))),
            }
        }
        "netstack" => {
            let mut ok = true;
            ok &= run_cmd("netsh.exe", &["winsock", "reset"]);
            ok &= run_cmd("netsh.exe", &["int", "ip", "reset"]);
            ok &= run_cmd("ipconfig.exe", &["/flushdns"]);
            Ok((ok, if ok { "网络栈已重置（需重启生效）".into() } else { "网络栈重置部分失败".into() }))
        }
        "audio" => {
            let ok = restart_service("Audiosrv") && restart_service("AudioEndpointBuilder");
            Ok((ok, if ok { "音频服务已重启".into() } else { "音频服务重启失败".into() }))
        }
        "search" => {
            // 审查 v2-L1：删前校验放在**停服务之前** —— 校验不通过就整条不执行，
            // 免得服务停了却什么也没清（用户只看到「搜索服务重启失败」）。
            // B2-7：判据换成 `protect::validate_mutation_target`（受保护面 / 别名面 /
            // is_system_namespace / reparse 四道闸），路径取源换成环境变量。
            let idx = maintenance_cache_dir("search")?;
            if let Err(reason) = cache_delete_blocked(&idx) {
                crate::engine::log::write_log("warn", &format!("维护：search 索引目录删除被拒 — {reason}"));
                return Ok((false, format!("搜索索引目录未通过删除前校验，已取消：{reason}")));
            }
            // 停止 WSearch → 删索引 → 启动。三步各按终态判，删除结果必须进回执（v5 S-2）。
            // 停不稳就**不删**：半途删一个被占用的索引库只会留下更坏的状态。
            if !stop_service_wait("WSearch", std::time::Duration::from_secs(20)) {
                return Ok((false, "WSearch 未能在时限内停止，已取消删除（避免删半个索引库），请稍后重试".into()));
            }
            // B2-7：改**回收站**（`SHFileOperationW` + `FOF_ALLOWUNDO`，与 fileclean 同一个原语）。
            // 失败如实报错、**不回退永久删**（v7.2 `R1d-L02` 口径）：索引目录动辄数 GB，
            // 回收站放不下时它会失败 —— 那时盘上文件仍在，回执说「没清成」，不许谎称已清空。
            let removed = trim_finder::scan::recycle::send_to_trash_os(idx.as_os_str());
            let started = start_service_wait("WSearch");
            let ok = removed.is_ok() && started;
            let rm_msg = match &removed {
                Ok(()) => "索引已移入回收站，将在后台重建".to_string(),
                Err(e) => format!("索引移入回收站失败（未回退永久删除，盘上文件仍在）: {e}"),
            };
            Ok((ok, format!("{rm_msg}；服务{}", if started { "已重启" } else { "重启失败" })))
        }
        "wu" => {
            // B2-7（D-1 裁定）：这一支**功能下线**。目标
            // `%WINDIR%\SoftwareDistribution\DataStore` 是 `%WINDIR%` 子孙 ⇒
            // `validate_mutation_target` 的 `is_system_namespace` **永久拒绝**，而 D-1 已
            // 明确否掉「受控例外」。所以这里不再有任何删除动作，只回一句说得清为什么的回执：
            // 不许表现为「点了没反应」，更不许回「已清空」（v5 S-1 治过同一形状的恒真回执）。
            let cache = maintenance_cache_dir("wu")?;
            let reason = cache_delete_blocked(&cache)
                .err()
                .unwrap_or_else(|| "目标位于系统区域".to_string());
            crate::engine::log::write_log("warn", &format!("维护：wu 支已下线（系统区域不清理）— {reason}"));
            Ok((false, format!("更新缓存目录属系统区域，本工具不再清理：{reason}")))
        }
        "tf_net_tcp" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile]\r\n\"NetworkThrottlingIndex\"=dword:ffffffff\r\n\"SystemResponsiveness\"=dword:0000000a\r\n";
            let mut ok = reg_import(reg);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "global", "autotuninglevel=disabled", "ecncapability=disabled", "dca=enabled", "rsc=disabled", "rss=enabled", "timestamps=disabled"]);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "global", "rssbasecpu=1"]);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "heuristics", "disabled"]);
            ok &= run_cmd("netsh.exe", &["int", "ip", "set", "global", "neighborcachelimit=4096"]);
            ok &= run_cmd("netsh.exe", &["int", "tcp", "set", "supplemental", "Internet", "congestionprovider=ctcp"]);
            Ok((ok, if ok { "TCP 全局参数已优化".into() } else { "TCP 全局参数部分命令未成功（详见操作日志）".into() }))
        }
        "tf_net_tcpip" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters]\r\n\"Tcp1323Opts\"=dword:00000001\r\n\"TcpMaxDupAcks\"=dword:00000002\r\n\"SackOpts\"=dword:00000001\r\n";
            let ok = reg_import(reg);
            Ok((ok, if ok { "TCP/IP 参数已优化".into() } else { "TCP/IP 参数写入未成功（详见操作日志）".into() }))
        }
        "tf_net_lanman" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters]\r\n\"Size\"=dword:00000003\r\n\"LmAnnounce\"=dword:00000000\r\n";
            let ok = reg_import(reg);
            Ok((ok, if ok { "SMB 服务器参数已优化".into() } else { "SMB 服务器参数写入未成功（详见操作日志）".into() }))
        }
        "tf_net_weakhost" => {
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters]\r\n\"WeakHostSend\"=dword:00000001\r\n\"WeakHostReceive\"=dword:00000001\r\n";
            let ok = reg_import(reg);
            Ok((ok, if ok { "弱主机模型已启用".into() } else { "弱主机模型启用未成功（详见操作日志）".into() }))
        }
        // 审查 2026-09-27 M5：本分支此前是「空操作假成功」——.reg 只有节头零值行，
        // reg_import 只会建空类键却报「网卡参数已优化」。真正的网卡级调优需要遍历
        // 每个网卡实例子键（PnP 路径），误写通用键有断网风险，故整任务下线而非补实现。
        "net_disable_netbios" => {
            // 遍历接口写 NetbiosOptions=2；审查 2026-09-27 M7：写失败不再静默吞掉，
            // 按成功写入数如实回传，0 个接口写入成功即为失败
            let base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
            let mut written = 0u32;
            unsafe {
                let sk = to_wide(base);
                let mut hk = HKEY::default();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_ok() {
                    let mut index = 0u32;
                    loop {
                        let mut name_buf = [0u16; 256];
                        let mut name_len = 256u32;
                        if RegEnumKeyExW(hk, index, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None).is_err() { break; }
                        let iface_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                        let iface_key = format!("{base}\\{iface_name}");
                        let isk = to_wide(&iface_key);
                        let mut ihk = HKEY::default();
                        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(isk.as_ptr()), Some(0), KEY_WRITE, &mut ihk).is_ok() {
                            let nm = to_wide("NetbiosOptions");
                            let val = 2u32;
                            if RegSetValueExW(ihk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes())).is_ok() {
                                written += 1;
                            }
                            let _ = RegCloseKey(ihk);
                        }
                        index += 1;
                    }
                    let _ = RegCloseKey(hk);
                }
            }
            if written > 0 {
                Ok((true, format!("NetBIOS 已在 {written} 个接口禁用")))
            } else {
                Ok((false, "未能禁用任何接口的 NetBIOS（注册表写入失败）".into()))
            }
        }
        "net_disable_lmhosts" => {
            // 审查 2026-09-27 M7：RegSetValueExW 失败不再被 let _ 吞掉后谎报成功
            let ok = unsafe {
                let key = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters";
                let sk = to_wide(key);
                let mut hk = HKEY::default();
                let opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sk.as_ptr()), Some(0), KEY_WRITE, &mut hk);
                if opened.is_ok() {
                    let nm = to_wide("EnableLMHOSTS");
                    let val = 0u32;
                    let set = RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_DWORD, Some(&val.to_le_bytes()));
                    let _ = RegCloseKey(hk);
                    set.is_ok()
                } else {
                    false
                }
            };
            Ok((ok, if ok { "LMHOSTS 查找已禁用".into() } else { "LMHOSTS 注册表写入失败（键不存在或被策略保护）".into() }))
        }
        "net_qos_scheduler" => {
            // 审查 2026-09-27 M6：补文案承诺的 NonBestEffortLimit=0（PSched 策略键）；
            // DisableTaskOffload=1 是本任务实际写入的另一参数（关闭 TCP 任务卸载），
            // 统一走 reg_import 并检查结果，不再「打开键失败也报成功」
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Psched]\r\n\"NonBestEffortLimit\"=dword:00000000\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters]\r\n\"DisableTaskOffload\"=dword:00000001\r\n";
            let ok = reg_import(reg);
            Ok((ok, if ok { "QoS 保留带宽已取消，TCP 任务卸载已关闭".into() } else { "QoS 参数写入失败".into() }))
        }
        "net_response" => {
            // 审查 2026-09-27 M6：补文案承诺的网络节流键（NetworkThrottlingIndex 拉满
            // = 禁用多媒体播放时的网络节流）；SystemResponsiveness 不在此处写——
            // tf_net_tcp 已按其文案写 10，两任务对该键取值不同，避免隐式互相覆盖
            let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile]\r\n\"NetworkThrottlingIndex\"=dword:ffffffff\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters]\r\n\"TcpMaxConnectResponseRetransmissions\"=dword:00000002\r\n";
            let ok = reg_import(reg);
            Ok((ok, if ok { "网络节流已关闭，连接响应重传已收紧".into() } else { "网络响应参数写入失败".into() }))
        }
        _ => Err(format!("未知的维护任务: {task_id}")),
    }
}

