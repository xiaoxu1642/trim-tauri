//! 应用侧：PS 脚本构建（对照 buildScript）、动态步骤、原生步骤、`optimizer_run` 与
//! 应用/还原回读验证、运行互斥 guard、`RunParams` 共享类型。
//!
//! PS 执行只走 `pwsh::run_inbox_script` 单一入口（v2 R0/R1），超时登记在
//! tools/check-ps-callsites.mjs；build_script 产出的协议行（@@PROC@@ 等）与
//! `src-tauri/ps/optimizer_build.ps1` 哨兵模板由 check-ps-extraction 逐字节对拍。
//! OptRunGuard / OPT_RUN_INFLIGHT 是「同一时刻只跑一次优化」的闩锁，Drop 里释放。
//!
//! **PS 轨现状（2026-10-06）**：`build_script` 链（build_preamble / ps_quote /
//! BUILD_SENTINEL）已无生产调用 —— 最后一个生产用户 `tf_restore_point` 随条目摘除、
//! 改走内联脚本（`restore_point.rs`）。本链保留并标 `#[cfg(test)]`，继续服务契约测试
//! 对「数据层步骤能被完整编译」的校验；哪天要恢复 PS 轨生产使用，去掉 cfg(test)，
//! 并先读 cmd/service 两分支里的引号陷阱批注。

use crate::pwsh;
use crate::engine::{guard, log, optimization_state as opt_state, protect, sysinfo};
use crate::engine::systembin::system_tool;
use serde_json::{Value, json};
#[cfg(test)] use std::sync::OnceLock; // 仅 build_preamble（PS 轨链，cfg(test)）使用
use tauri::{Runtime, WebviewWindow};
use tauri::Emitter;
use super::backup_restore::*;
use super::catalog::*;
use super::overview::*;
/// svc_mem_gb 档位表（KB）
pub(super) const MEMORY_KB: &[(&str, i64)] = &[
    ("4", 4_194_304),
    ("6", 6_291_456),
    ("8", 8_388_608),
    ("12", 12_582_912),
    ("16", 16_777_216),
    ("20", 20_971_520),
    ("24", 25_165_824),
    ("32", 33_554_432),
];
pub(super) const MEMORY_KB_DEFAULT: i64 = 380_000;
pub(super) const WU_PAUSE_MAX_DAYS: i64 = 35;
pub(super) const STORE_SERVICES: &[&str] =
    &["ClipSVC", "InstallService", "PushToInstall", "wuauserv", "DoSvc"];

// ==================== PS 脚本生成器（对照 buildScript） ====================

/// 从生成器抽取的哨兵脚本中切出 provenance 之后、`# step 1:` 之前的固定前置，
/// 与 JS buildScript 前 4 个 push（三行设置 + DIAG.PS_PREAMBLE.trim()）逐字一致。
///
/// 2026-10-06 起仅契约测试使用（见文件头「PS 轨现状」）。
#[cfg(test)]
pub(super) fn build_preamble() -> &'static str {
    static P: OnceLock<String> = OnceLock::new();
    P.get_or_init(|| {
        let body = BUILD_SENTINEL
            .split("# PROVENANCE>>>")
            .nth(1)
            .unwrap_or(BUILD_SENTINEL);
        let preamble = body.split("# step 1:").next().unwrap_or(body);
        preamble.trim_end().to_string()
    })
}

#[cfg(test)]
pub(super) fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// steps JSON 数组 → PowerShell 脚本（与 JS buildScript 同口径）。
///
/// 2026-10-06 起仅契约测试使用（见文件头「PS 轨现状」；生产唯一用户 tf_restore_point
/// 已改内联脚本，本函数保留是为继续校验数据层步骤的可编译性）。
#[cfg(test)]
pub(super) fn build_script(steps: &[Value]) -> String {
    let total = steps.len();
    let mut l: Vec<String> = vec![build_preamble().to_string()];
    for (i, s) in steps.iter().enumerate() {
        let pct = (((i + 1) as f64 / total as f64) * 100.0).round() as i64;
        let raw_label = s
            .get("label")
            .and_then(|v| v.as_str())
            .map(|x| x.replace(['\r', '\n'], " "))
            .unwrap_or_else(|| format!("第 {} 步", i + 1));
        let label_ps = ps_quote(&raw_label);
        let idx1 = i + 1;
        l.push(format!("# step {idx1}: {raw_label}"));

        if let Some(reg) = s.get("reg").and_then(|v| v.as_str()) {
            l.push("$___tmpDir = if ($env:TRIM_TMP) { $env:TRIM_TMP } else { Join-Path $env:APPDATA \"Trim\\tmp\" }".into());
            l.push("if (-not (Test-Path -LiteralPath $___tmpDir)) { New-Item -ItemType Directory -Path $___tmpDir -Force | Out-Null }".into());
            l.push("$___rf = Join-Path $___tmpDir (\"wcopt_\" + [guid]::NewGuid().ToString(\"N\") + \".reg\")".into());
            l.push("$___rc = @'".into());
            l.push(reg.to_string());
            l.push("'@".into());
            l.push("Set-Content -Path $___rf -Value $___rc -Encoding Unicode".into());
            l.push("& reg.exe import $___rf *> $null".into());
            l.push(format!("if ($LASTEXITCODE -ne 0) {{ $failedSteps++; Write-TFDiag -Stage 'optimizer.reg' -Mutation 'rolled_back' -Detail ('step ' + ({i} + 1) + ' [' + {label_ps} + '] reg import exit=' + $LASTEXITCODE) }}"));
            l.push("Remove-Item $___rf -Force -ErrorAction SilentlyContinue".into());
        } else if let Some(cmd) = s.get("cmd").and_then(|v| v.as_str()) {
            // 注意：PS 轨这条 `& $env:ComSpec /c $___cmd` 与已修的 `run_cmd_step` 是同一类
            // 引号陷阱（PS 也会把内嵌引号重写成子进程不认的形状）。历史上不可达（唯一生产
            // 用户 tf_restore_point 只有 reg + pwsh 步骤，2026-10-06 已摘）；现仅测试用例
            // 走到这里。若哪天恢复 PS 轨生产使用或加 cmd 步骤用例，先照 run_cmd_step 的
            // 实测结论改这条，别等回读校验报不符再查。
            let safe = cmd.replace('\'', "''");
            l.push(format!("$___cmd='{safe}'"));
            l.push("& $env:ComSpec /c $___cmd *> $null".into());
            l.push(format!("if ($LASTEXITCODE -ne 0) {{ $failedSteps++; Write-TFDiag -Stage 'optimizer.cmd' -Mutation 'partial' -Detail ('step ' + ({i} + 1) + ' [' + {label_ps} + '] exit=' + $LASTEXITCODE) }}"));
        } else if let Some(service) = s.get("service").and_then(|v| v.as_str()) {
            // 与 `native_execute_steps` 的 service 分支**同口径**（R0-a）。这里原来只认
            // `disable`，startType 形态在 PS 轨上同样会退化成「只停服」。两条轨的分歧不是
            // 美观问题（当时 tf_restore_point 走 build_script，而备份/回读按 native 轨的
            // 语义记账，两轨对同一份 steps 给出不同解释 = 备份与实际写入不匹配）；PS 轨
            // 停用后此分支仍须与 native 轨一致，供契约测试逐项断言两轨语义不漂移。
            let svc_ps = ps_quote(service);
            let start_label = s.get("startType").and_then(|v| v.as_str());
            let want_disable = s.get("disable").and_then(|v| v.as_bool()).unwrap_or(false);
            // 未知 startType 同样 fail-closed：生成不出合法脚本就别生成。
            // 注意 `raw` 是数据层原值、`verb` 是已解析的合法档位，二者都要 ps_quote —
            // 错误文案里带数据层原串，不转义会把引号带进脚本。
            let mut start_ps = match start_label {
                Some(raw) => match crate::engine::native::start_type_from_label(raw) {
                    Ok(_) => Some(ps_quote(match raw {
                        "manual" => "Manual",
                        "automatic" => "Automatic",
                        _ => "Disabled",
                    })),
                    Err(reason) => {
                        l.push(format!("Write-TFDiag -Stage 'optimizer.service' -Mutation 'failed' -Detail {}", ps_quote(&reason)));
                        l.push("$failedSteps++".into());
                        None
                    }
                },
                None => None,
            };
            if want_disable && start_ps.is_none() {
                start_ps = Some(ps_quote("Disabled"));
            }
            // 显式 startType 且非 Disabled ⇒ 不停服（对齐「不立即停止」文案）
            if want_disable || start_ps.is_none() {
                l.push(format!("Stop-Service -Name {svc_ps} -Force -ErrorAction SilentlyContinue"));
            }
            if let Some(st) = start_ps {
                l.push(format!("Set-Service -Name {svc_ps} -StartupType {st} -ErrorAction SilentlyContinue"));
            }
            l.push(format!("if (-not (Get-Service -Name {svc_ps} -ErrorAction SilentlyContinue)) {{ $failedSteps++; Write-TFDiag -Stage 'optimizer.service' -Mutation 'rolled_back' -Detail ('step ' + ({i} + 1) + ' [' + {label_ps} + '] 服务不存在: ' + {svc_ps}) }}"));
        } else if let Some(pwsh) = s.get("pwsh").and_then(|v| v.as_str()) {
            l.push("$___eap = $ErrorActionPreference".into());
            l.push("try {".into());
            l.push("  $ErrorActionPreference = 'Stop'".into());
            l.push(pwsh.to_string());
            l.push("} catch {".into());
            l.push(format!("  $failedSteps++; Write-TFDiag -Stage 'optimizer.pwsh' -Mutation 'failed' -Detail ('step ' + ({i} + 1) + ' [' + {label_ps} + '] ' + $_.Exception.Message)"));
            l.push("} finally {".into());
            l.push("  $ErrorActionPreference = $___eap".into());
            l.push("}".into());
        }
        l.push(format!("Write-Output \"@@PROGRESS:{pct}@@\""));
    }
    l.push("Write-Output (\"@@FAILED:\" + $failedSteps + \"@@\")".into());
    l.push("Write-Output \"@@DONE@@\"".into());
    l.join("\n")
}

/// cmd.exe 的命令行参数：`/s /c "<整条命令行>"`。
///
/// `/s` 是关键：cmd 见到首字符是引号时按「剥掉首尾那对引号、其余逐字保留」处理，内层引号
/// 才能原样抵达 reg.exe；不带 `/s` 时 cmd 的引号规则会吃掉转义。
pub(super) fn cmd_line_of(cmd: &str) -> String {
    format!("/s /c \"{cmd}\"")
}

/// 用 cmd.exe 跑一条优化步骤命令。**生产与回归测试都必须走这里**：测试若自己拼一遍
/// 命令行形状，生产改回 `args(["/c", cmd])` 就测不出来了（而那条形状是错的，见下）。
/// 完整根因与实测证据见 `native_execute_steps` 的 cmd 分支注释。
pub(super) fn run_cmd_step(cmd: &str) -> std::io::Result<std::process::Output> {
    // P3-5（R5-G-4 漏网的一处）：原为裸 `.output()` 无超时 —— 挂死的 cmd 步骤
    // 会永久锁住整批执行（optimizer_run 在 async 链上等它 = 界面假死）。
    // 走 raw 版超时入口：`/s /c` 引号形状由 cmd_line_of 逐字保留、等待/终止语义
    // 与其余 quiet_cmd_timeout 调用点共用同一实现（超时常量登记见 check-ps-callsites F 组）。
    // v6-K01（P0-2）：解析失败映射成 io::Error，与 spawn 失败同走「失败计数继续」语义。
    let exe = system_tool("cmd")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
    crate::engine::systembin::quiet_cmd_timeout_raw(
        exe,
        &cmd_line_of(cmd),
        crate::engine::systembin::CMD_STEP_TIMEOUT,
    )
}

/// 这一步有没有带上四个引擎字段（reg / cmd / service / pwsh）之一。
///
/// 为什么单独成函数而不是只在分发链里各写一遍：R3-L01 之后，链尾有两个**有名字**的
/// 兜底分支（字段存在却没被接住 / 一个字段都没有），两者都以本谓词为分界。契约测试
/// 直接喂合成 step 判红，不必起窗跑整条执行链。
/// 判据与预检侧的 [`step_exec_mode`] 同结论（那条把「pwsh 编译不出来」也算 unsupported，
/// 本谓词只看字段存在性，所以预检拦得住的形态这里只会更多、不会更少）。
pub(super) fn step_has_engine_field(s: &Value) -> bool {
    s.get("reg").and_then(Value::as_str).is_some()
        || s.get("cmd").and_then(Value::as_str).is_some()
        || s.get("service").is_some()
        || s.get("pwsh").and_then(Value::as_str).is_some()
}

/// 「形态未识别」步骤的失败原因文案（执行链末尾 else 与契约测试共用同一份措辞）。
/// 点名 label 是硬要求：回执里说不出是哪一步，用户与审计者都无从下手。
pub(super) fn unrecognized_step_reason(label: &str) -> String {
    format!("步骤「{label}」: 步骤形态未识别（reg/cmd/service/pwsh 四个引擎字段均缺失）")
}

/// 一行 `@@RECYCLE@@` 协议体的分类结果（只判形状，落地前的四道闸在调用方）。
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RecycleLine {
    /// 形状不合法（解析失败 / 缺 path / path 为空）。携带中文拒因进日志与计数。
    Malformed(&'static str),
    /// 同一路径已在本批出现过 —— 去重是正常收敛，不算畸形。
    Duplicate,
    /// 形状合法的路径。
    Path(String),
}

/// 协议体形状判定。抽成纯函数是给 R3-L07 留判据面：`"path": ""` 与「缺 path」
/// 必须同口径进畸形计数，而整条 `@@RECYCLE@@` 循环要真起回收站操作，测不动。
pub(super) fn classify_recycle_line(rest: &str, seen: &mut std::collections::HashSet<String>) -> RecycleLine {
    let Ok(entry) = serde_json::from_str::<Value>(rest) else {
        return RecycleLine::Malformed("解析失败");
    };
    let Some(p) = entry.get("path").and_then(Value::as_str) else {
        return RecycleLine::Malformed("缺少 path 字段");
    };
    if p.is_empty() {
        return RecycleLine::Malformed("path 为空字符串");
    }
    if !seen.insert(p.to_string()) {
        return RecycleLine::Duplicate;
    }
    RecycleLine::Path(p.to_string())
}

/// 原生执行优化步骤（对应 optimizer_build.ps1 模板，S1）
///
/// 支持 reg/cmd/service 三种 step 类型；pwsh 类型交给 pssteps 解释器
/// （原生可编译 → 原生执行；白名单内不可编译 → 收件箱 PS 逐字执行，v3-K1）。
/// 实时推送 optimizer:progress 事件，返回 (failed_steps, PsInline stdout 累积, 失败原因明细)。
/// 审查 2026-09-27 M2/M4：pwsh 编译/执行失败不再中止整批（与 reg/cmd/service 的
/// 「失败计数继续」语义一致，避免前置已落盘、后置永不执行的批量断裂）；每步失败的
/// label 与原因收集进返回值，由调用方随回执下发前端，不再只回「部分步骤可能失败」。
pub(super) fn native_execute_steps<R: tauri::Runtime>(
    window: &WebviewWindow<R>,
    steps: &[Value],
    option_id: &str,
) -> Result<(i64, String, Vec<String>), String> {
    let total = steps.len();
    let mut failed = 0i64;
    let mut inline_stdout = String::new();
    let mut failed_reasons: Vec<String> = Vec::new();
    // 审查 v3-M2：私有 tmp 被替换成 junction 时 temp_script_dir 返回 Err，这里绝不能
    // 降级到全局可写的 %TEMP% —— 那会把「拒绝写入」翻译成「换个更危险的目录写」，
    // 提权实例在 %TEMP% 写可预测路径的 .reg 再以管理员 reg import，是经典 TOCTOU 窗口。
    // 与 pwsh/mod.rs 同口径：Err 直接失败。
    let tmp_dir = crate::engine::paths::temp_script_dir()?;
    // P1-6（审查 2026-10-07）：原为 `let _ = create_dir_all(...)` —— 建目录失败被静默吞掉，
    // 执行链会在一个写不进去的私有 tmp 下继续跑（reparse 点/权限异常时）。与 temp_script_dir
    // 的 Err 语义一致：建不出来就直接失败，绝不降级、不继续。
    std::fs::create_dir_all(&tmp_dir).map_err(|e| format!("临时脚本目录不可用: {e}"))?;

    for (i, s) in steps.iter().enumerate() {
        let pct = (((i + 1) as f64 / total as f64) * 100.0).round() as u32;
        let label = s.get("label").and_then(|v| v.as_str()).unwrap_or("");

        if let Some(reg) = s.get("reg").and_then(|v| v.as_str()) {
            // reg 类型：写 .reg 临时文件 + 原生 import（A6，v2-R4）
            // 审查 M-5（2026-10-03 L3）：旧文件名为 `wcopt_{ms}.reg`，毫秒时间戳可预测，
            // 同用户低权限进程可预先在 %APPDATA%\<id>\tmp 下创建指向任意目标的 reparse 点，
            // 管理员实例随后以 UTF-16LE 覆写 ⇒ 任意文件写。随机 token 让文件名不可预测。
            // 审查 L-19（2026-10-03 L4）：再进一步用独占创建（CREATE_NEW）——即便攻击者
            // 碰中名字，预置的 reparse 点会让写入直接报错重取，而不是跟随已有文件覆写；
            // 与 pwsh::write_temp_script 同口径（random_token 内含原子序号，重试必得新名）。
            // 审查 2026-09-27 L1：.reg 临时文件为 UTF-16LE + BOM（.reg 的 Unicode 格式），
            // 与 `reg.exe export` 的产物同编码。原先「路径非 UTF-8 就跳过该步」（v3-L7）
            // 是 reg.exe 需要字符串参数才有的限制，原生拿 &Path 后随 reg.exe 一起删除。
            // 中文值数据在旧 UTF-8 无 BOM 形态下会被按 ANSI 误读，那一条现在由读侧的
            // 编码感知（reg_backup::read_reg_text_file）兜住。
            let mut reg_bytes = vec![0xFFu8, 0xFEu8];
            reg_bytes.extend(reg.encode_utf16().flat_map(|u| u.to_le_bytes()));
            let mut reg_path: Option<std::path::PathBuf> = None;
            let mut write_err: Option<String> = None;
            for _ in 0..3 {
                // B2-1：名字由 `engine::tmpnames` 的形态声明拼出，与清扫白名单共用同一份
                // （此前这里与白名单各写一份字面量，改名会让另一侧静默失效）。
                let candidate = tmp_dir.join(crate::engine::tmpnames::OPTIMIZER_REG.build(
                    crate::engine::now_ms(),
                    &crate::pwsh::random_token(),
                ));
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&candidate)
                {
                    Ok(mut f) => {
                        use std::io::Write;
                        match f.write_all(&reg_bytes) {
                            Ok(_) => {
                                reg_path = Some(candidate);
                                break;
                            }
                            Err(e) => {
                                write_err = Some(e.to_string());
                                break;
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => {
                        write_err = Some(e.to_string());
                        break;
                    }
                }
            }
            match (reg_path, write_err) {
                (Some(reg_path), _) => {
                    // A6（v2-R4）：原生 `.reg` 写入替换 `reg.exe import`。
                    // 文件仍按 UTF-16LE+BOM 写（那是这份 .reg 文本格式既有的约定，v2 明令不动），
                    // 读侧的编码感知在 reg_backup::read_reg_text_file。
                    // 失败原因现在进 failed_reasons —— 旧实现只说"返回非零"，用户看不到为什么。
                    match crate::engine::reg_backup::reg_import_apply(std::path::Path::new(&reg_path)) {
                        Ok(_) => {}
                        Err(e) => {
                            // P2-05：失败回执带统计（已写入/已删除多少），
                            // 文案只陈述事实，不承诺「可直接重试」。
                            failed += 1;
                            failed_reasons.push(format!("步骤「{label}」: {}", e.user_message()));
                        }
                    }
                    let _ = std::fs::remove_file(&reg_path);
                }
                (_, Some(e)) => {
                    failed += 1;
                    failed_reasons.push(format!("步骤「{label}」: .reg 临时文件写入失败: {e}"));
                }
                (None, None) => {
                    failed += 1;
                    failed_reasons.push(format!("步骤「{label}」: .reg 临时文件写入失败: 文件名连续碰撞"));
                }
            }
        } else if let Some(cmd) = s.get("cmd").and_then(|v| v.as_str()) {
            // cmd 类型：spawn cmd /c。形状必须是 raw_arg("/s /c \"…\"")，不能用 args(["/c", cmd])。
            // 根因（2026-09-30 用户机实测）：std 的 args() 把内嵌 " 转义成 \"，而 cmd.exe 不认 \"，
            // 它只按「剥掉首尾那对引号」的规则处理 ⇒ \" 原样进子进程命令行，reg.exe 于是把
            // "HKLM\SYSTEM\ControlSet001\Control" 解析成键名 Control"（尾随一个引号），
            // 值写进这个当场新建的垃圾键、真键一个字没改，而 reg 返回 0 ⇒ 步骤记成功、
            // 回读必然报「校验不符」。/s 让 cmd 只剥首尾引号、内层逐字透传。
            let ok = match run_cmd_step(cmd) {
                Ok(o) => o.status.success(),
                Err(_) => false,
            };
            if !ok {
                failed += 1;
                failed_reasons.push(format!("步骤「{label}」: 命令返回非零"));
            }
        } else if let Some(service) = s.get("service").and_then(|v| v.as_str()) {
            // service 类型。三种形态，语义各不相同（R0-a 起）：
            //
            //   {service, disable:true}      → 停服 + 改启动类型为 disabled（隐私权限停用类）
            //   {service, startType:"..."}   → **只**改启动类型，不停服
            //   {service} 单独出现            → 只停服
            //
            // v0.5.0 的缺陷就在第二形态：startType 既不被这里读取、也不被 build_script
            // 读取，于是 `{service, startType:"manual"}` 落进「只停服」分支 —— 服务被停、
            // 启动类型原封不动，而回执报成功。数据层 label/desc 写的却是「不立即停止」，
            // 三条文案与实际行为全部相反。
            //
            // D0-EXEC-SIDE: startType 执行分支（D0-COVERAGE-ANCHOR 契约表的一行）。
            let start_label = s.get("startType").and_then(|v| v.as_str());
            let want_disable = s.get("disable").and_then(|v| v.as_bool()).unwrap_or(false);

            // 启动类型期望值。未知取值 fail-closed（native 侧解析，绝不猜默认值）。
            let mut expected_start = match start_label {
                Some(l) => match crate::engine::native::start_type_from_label(l) {
                    Ok(v) => Some(v),
                    Err(reason) => {
                        failed += 1;
                        failed_reasons.push(format!("步骤「{label}」: {reason}"));
                        None
                    }
                },
                None => None,
            };
            if want_disable && expected_start.is_none() {
                expected_start = Some(crate::engine::native::SVC_START_DISABLED);
            }

            // 是否需要停服：只有「要 disabled」或「没指定启动类型」才停。
            // 显式 startType 且非 disabled ⇒ 用户要的是「下次开机别自动起」，
            // 停服是副作用，不做（对齐 label「不立即停止」与 desc「当前运行不受影响」）。
            let need_stop = want_disable || expected_start.is_none();

            if need_stop {
                // 终态语义走 native 原语（v5 O-1）：1062 本就未启动 / 1060 本机没装
                // 都等于目标达成，判 Ok。旧的 `sc stop` 直调把退出码非零一律当失败。
                if let Err(reason) = crate::engine::native::service_stop_pub(service) {
                    failed += 1;
                    failed_reasons.push(format!("服务「{service}」: {reason}"));
                }
            }
            if let Some(want) = expected_start {
                // 审查 2026-09-27 L5 的等价物：被策略拒绝不再静默，计入失败原因。
                if let Err(reason) = crate::engine::native::service_set_start_pub(service, want) {
                    failed += 1;
                    failed_reasons.push(format!(
                        "服务「{service}」: {reason}（可能被组策略锁定）"
                    ));
                }
            }
            // 存在性回读。判据用「服务在不在」而不是「停没停」：startType 形态刻意
            // 不停服，拿运行态当判据会把它误判成失败。
            if !crate::engine::native::service_exists(service) {
                failed += 1;
                failed_reasons.push(format!("服务「{service}」不存在（可能已被卸载或精简）"));
            }
        } else if let Some(pwsh) = s.get("pwsh").and_then(|v| v.as_str()) {
            // pwsh 类型：交给解释器（v3-K1）。原生可编译 → 原生执行；白名单内
            // 不可编译 → PsInline（收件箱 Windows PowerShell 逐字执行，语义零改写）；
            // 白名单外 → Err（fail-closed，由 data_layer_coverage_report 在测试期拦）。
            match crate::engine::pssteps::compile(pwsh).and_then(|ops| crate::engine::pssteps::execute(&ops)) {
                Ok(stdout) => inline_stdout.push_str(&stdout),
                Err(reason) => {
                    // 审查 2026-09-27 M2：与 reg/cmd/service 同口径——失败计数继续，
                    // 不再 return Err 中止整批（此前前置步骤已落盘、后置永不执行）
                    failed += 1;
                    failed_reasons.push(format!("pwsh 步骤「{label}」: {reason}"));
                }
            }
        } else if step_has_engine_field(s) {
            // 走到这里 = 四个引擎字段之一存在却没被上面任何分支接住 ⇒ 分发链与
            // `step_has_engine_field` 分叉了（新增字段只改了一边）。同样计失败，
            // 不静默跳过——静默是 R3-L01 那条缺陷的成因，不是解决方案。
            failed += 1;
            failed_reasons.push(format!(
                "步骤「{label}」: 步骤字段形状异常（引擎字段存在但未进入任何执行分支）"
            ));
        } else {
            // R3-L01（v7.2 C04）：四个引擎字段全都不匹配的形态**必须计入失败**。旧链没有
            // 末尾 else ⇒ 这一步既没执行也不计数，进度照发、回执照报成功，用户看到的是
            // 「做完了」，事实是「一个字没改」。与 reg/cmd/service/pwsh 各分支的
            // 「失败计数继续」语义对齐，不再让未知形态享受静默待遇。
            // 现算盘上 301 个步骤全部单字段合法 ⇒ 本分支暂不可达；不可达不等于不修，
            // 数据层一旦增补漏字段的步骤就会落在这里（判据面见 contract_tests 的合成用例）。
            failed += 1;
            failed_reasons.push(unrecognized_step_reason(label));
        }

        // 推送进度
        let _ = window.emit(
            "optimizer:progress",
            json!({ "optionId": option_id, "percent": pct }),
        );
    }
    Ok((failed, inline_stdout, failed_reasons))
}

// ==================== 动态步骤 ====================

/// SVCHost 拆分阈值步骤。**档位合法性只由本函数判**（未知档位 → `Err`）。
///
/// R3-L06（v7.2 C04）：旧实现在档位不在 `MEMORY_KB` 时**静默写 8GB**，只在 label 里自陈
/// 「已回退」。label 既不进回执 `message`、也不进优化状态记账，回读又判 partial ——
/// 用户选了一个不存在的档位却拿到「执行成功」，是回执好看但事实失真。
/// 现在与同域 `perf_wu_pause` 的越界姿势统一为**当场拒绝、不动系统**（见 [`dynamic_steps`]）。
pub(super) fn memory_steps(gb: &Value) -> Result<Vec<Value>, String> {
    // 入参可能是数字或字符串（"default"）
    let key = match gb {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let (kb, name) = if key == "default" {
        (MEMORY_KB_DEFAULT, "重置为默认值".to_string())
    } else if let Some((_, v)) = MEMORY_KB.iter().find(|(k, _)| *k == key.as_str()) {
        (*v, format!("{key}GB"))
    } else if key.is_empty() {
        return Err("缺少 SVCHost 阈值档位参数".into());
    } else {
        let mut tiers: Vec<&str> = MEMORY_KB.iter().map(|(k, _)| *k).collect();
        tiers.push("default");
        return Err(format!(
            "SVCHost 阈值档位「{key}」不在登记档位里（可选：{}）",
            tiers.join(" / ")
        ));
    };
    Ok(vec![json!({
        "label": format!("SVCHost 拆分阈值 {name}"),
        "cmd": format!("reg add \"HKLM\\SYSTEM\\ControlSet001\\Control\" /v SvcHostSplitThresholdInKB /t REG_DWORD /d {kb} /f")
    })])
}

pub(super) fn wu_pause_steps(days: i64) -> Vec<Value> {
    let d = days.clamp(1, WU_PAUSE_MAX_DAYS);
    let pwsh = format!(
        "$days = {d}\n\
$base = \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\"\n\
New-Item -Path $base -Force -ErrorAction SilentlyContinue | Out-Null\n\
$ft = [DateTime]::UtcNow.AddDays($days).ToFileTimeUtc()\n\
$nowFt = [DateTime]::UtcNow.ToFileTimeUtc()\n\
foreach ($n in @(\"PauseFeatureUpdatesStartTime\",\"PauseQualityUpdatesStartTime\",\"PauseUpdatesStartTime\")) {{ New-ItemProperty -Path $base -Name $n -Value $nowFt -PropertyType QWord -Force | Out-Null }}\n\
foreach ($n in @(\"PauseFeatureUpdatesEndTime\",\"PauseQualityUpdatesEndTime\",\"PauseUpdatesExpiryTime\")) {{ New-ItemProperty -Path $base -Name $n -Value $ft -PropertyType QWord -Force | Out-Null }}"
    );
    vec![json!({ "label": format!("暂停 Windows 更新 {d} 天"), "pwsh": pwsh })]
}

/// 动态项的「参数 → 步骤链」唯一入口。
///
/// R3-L06（v7.2 C04）：两条动态项过去在 `assemble_steps` 里各写一套参数口径 ——
/// `perf_wu_pause` 越界直接拒，`svc_mem_gb` 未知档位静默写 8GB。同一个域、同一类
/// 「用户给的参数不在登记档位/区间里」，一个拒一个改，改的那个还把痕迹藏在 label 里。
/// 判据收拢到本函数一处（AGENTS §5.16）：动态项参数不合法一律**当场拒、不动系统**，
/// 回执点名原因；调用方拿 `Err` 直接出回执，不再走执行链。
///
/// 兜底分支同样拒：目录里 `dynamic=true` 但这里没有解析器的项，旧形态返回空步骤 ⇒
/// 整条链跑 0 步、退出码 0、回执仍报成功。
pub(super) fn dynamic_steps(option_id: &str, p: &RunParams) -> Result<Vec<Value>, String> {
    match option_id {
        "svc_mem_gb" => memory_steps(&p.gb.clone().unwrap_or(Value::Null)),
        "perf_wu_pause" => {
            let Some(d) = p.days else {
                return Err("缺少暂停天数参数".into());
            };
            if !d.is_finite() {
                // 与非数字入参的措辞分开：报「缺少参数」会让排查方向错到前端漏传上，
                // 而 NaN/Infinity 是参数传了但值不可用。
                return Err("暂停天数参数不是有效数字".into());
            }
            let days = d.trunc() as i64;
            if !(1..=WU_PAUSE_MAX_DAYS).contains(&days) {
                return Err(format!("暂停天数需在 1~{WU_PAUSE_MAX_DAYS} 天之间"));
            }
            Ok(wu_pause_steps(days))
        }
        other => Err(format!("动态优化项「{other}」没有登记的参数解析器，已拒绝执行")),
    }
}

pub(super) fn svc_bulk_append_store(mut base: Vec<Value>) -> Vec<Value> {
    let list = STORE_SERVICES.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(",");
    let pwsh = format!(
        "$storeSvc = @({list})\n\
foreach ($n in $storeSvc) {{ $p = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n\"; if (Test-Path $p) {{ New-ItemProperty -Path $p -Name Start -Value 4 -PropertyType DWord -Force | Out-Null; Stop-Service -Name $n -Force -ErrorAction SilentlyContinue }} }}"
    );
    base.push(json!({
        "label": "禁用商店相关服务（ClipSVC/InstallService/PushToInstall/wuauserv/DoSvc，经用户弹窗确认）",
        "pwsh": pwsh
    }));
    base
}

pub(super) fn classify_step_kinds(steps: &[Value]) -> Vec<String> {
    let mut kinds: Vec<String> = Vec::new();
    let mut push = |k: &str| {
        if !kinds.iter().any(|x| x == k) {
            kinds.push(k.to_string());
        }
    };
    for s in steps {
        if s.get("reg").and_then(|v| v.as_str()).is_some() {
            push("reg");
        }
        if s.get("service").is_some() {
            push("service");
        }
        if s.get("cmd").is_some() || s.get("pwsh").is_some() {
            push("cmd");
        }
    }
    kinds
}


#[derive(serde::Deserialize, Default)]
pub struct RunParams {
    #[serde(default)]
    restore: bool,
    #[serde(default, rename = "confirmedHighRisk")]
    confirmed_high_risk: bool,
    gb: Option<Value>,
    days: Option<f64>,
    #[serde(default, rename = "includeStore")]
    include_store: bool,
    /// 批量项里用户**勾选**的目标（2026-10-03）。缺省 / 空数组 = 全选（保持旧行为）。
    ///
    /// 刻意不让「全选」与「未选」共用一个值：全选要跑**数据层原脚本**（不重建），
    /// 未选要跑**重建脚本**。共用一个值的话，两者只能二选一，而二选一里必有一个
    /// 是错的形态（要么把未选当全选越权写入，要么把全选当未选什么都不做）。
    #[serde(default, rename = "pickedTargets")]
    picked_targets: Option<Vec<String>>,
    /// 批量项里用户勾选的附带开关（形状与目标不同，故分开一个字段）
    #[serde(default, rename = "pickedExtras")]
    picked_extras: Option<Vec<String>>,
}

/// optimizer:run —— 执行单个优化项（正向/还原）
///
/// 审查 2026-09-27 L4：执行链含状态文件的 read-modify-write 且非幂等，并发触发同一
/// 项会互相覆盖记账。整条执行链持全局互斥（Drop 复位，覆盖全部早退路径）——前端
/// 批量本就是串行 await，此锁只拦「重复点击/双入口并发」，不影响正常吞吐。
pub(super) static OPT_RUN_INFLIGHT: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

pub(super) struct OptRunGuard;
impl OptRunGuard {
    fn acquire() -> Option<Self> {
        let mut slot = OPT_RUN_INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        if *slot { None } else { *slot = true; Some(Self) }
    }
}
impl Drop for OptRunGuard {
    fn drop(&mut self) {
        *OPT_RUN_INFLIGHT.lock().unwrap_or_else(|e| e.into_inner()) = false;
    }
}

/// M1 预检拒绝理由（方案 §5.3）。刻意做成枚举而不是裸 `String`：
/// 调用方要按理由给不同的回执字段（`needAdmin` / `needConfirm` / 普通 message），
/// 用字符串比的话新增一条理由就得去改三处 match，而漏改的那处会静默走进通用分支。
#[derive(Debug, PartialEq, Eq)]
pub(super) enum PreflightReject {
    NeedAdmin,
    NeedHighRiskConfirm,
    /// 本机执行不了的步骤（`step_exec_mode` 判为 `unsupported`）。`String` 是**步骤 label**，
    /// 文案要点名到底哪一步执行不了 —— 只报「本机不支持」用户无从下手。
    /// R3-L01（v7.2 C04）：判据扩到覆盖「四个引擎字段全缺失」的畸形步骤（此前那类返回
    /// `None`、预检只看 `Some("unsupported")` ⇒ 放行）；本枚举一支覆盖两种「没人能执行」。
    UnsupportedStep(String),
    /// 目标状态已满足（2026-10-11 裁定 7：Defender 已卸载/已禁用时再执行只会往
    /// 缺失的服务键写幽灵 Start、给用户假动作）。String 是给用户看的中文原因。
    AlreadySatisfied(String),
    /// R3-K01（v7.2 C04）：restore 请求但目录项没有可执行的 restore 段。旧实现
    /// 对这类项在批量预检里全回 runnable（`if let Some(arr)` 跳过缺失键），
    /// 用户点了才拿到失败。
    NoRestorePath,
}

impl PreflightReject {
    /// 给渲染层看的文案。**中文、单一真源**：preflight 的 `rejected[].reason`
    /// 与单条执行的 `message` 都从这里取，两处不许各写一份。
    pub(super) fn message(&self) -> String {
        match self {
            Self::NeedAdmin => "需要管理员权限".to_string(),
            Self::NeedHighRiskConfirm => "需高危确认".to_string(),
            Self::UnsupportedStep(m) => format!("本机不支持（{m}）"),
            Self::AlreadySatisfied(m) => m.clone(),
            Self::NoRestorePath => "该优化项暂不支持一键还原，请手动恢复或使用系统还原点".to_string(),
        }
    }
}

/// M1（R1-1.3）**批量预检与单条执行链的唯一判据真源**。
///
/// 为什么必须是同一个函数：批量路径的价值就是「提前告诉用户哪几项会被拦」。
/// 如果预检自己抄一份判据，将来单条执行新增/放宽了闸门而预检没跟上，用户看到的
/// 就是「预检说能跑、点了却失败」—— 预检反而成了谎报源。
///
/// `restore` 方向必须传进来：高危确认在还原方向是**豁免**的（审查 2026-09-27 H1，
/// 见 `optimizer_run` 处的完整注释）。漏传 `true` 会让无值级备份的高危项在
/// 预检里被判「需高危确认」，而还原通道根本不弹那个确认框 ⇒ 又是整体死锁。
///
/// ⚠️ 本函数**只读**、不改任何系统状态，所以 `optimizer_batch_preflight` 用
/// `guard_readonly` 档（不是 MAIN）。档位判据见 AGENTS §3「以谁真的需要调它为准」。
pub(super) fn preflight_reason(
    opt: &Value,
    option_id: &str,
    restore: bool,
) -> Option<PreflightReject> {
    if !sysinfo::is_admin() {
        return Some(PreflightReject::NeedAdmin);
    }
    // 方向豁免：还原不是高危写入（审查 2026-09-27 H1）
    if !restore && needs_high_risk_confirm(opt, option_id) {
        return Some(PreflightReject::NeedHighRiskConfirm);
    }
    // 已满足拦截（仅正向）：tf_defender 在 Defender 已卸载/已禁用的机器上再执行，
    // 只会给不存在的服务键写幽灵 Start、对已不存在的防护做假动作。与体检同一个
    // special_item_verdict 钩子，判据不许在这里抄第二份（AGENTS §5.16）。
    if !restore {
        if let Some(true) = special_item_verdict(option_id) {
            return Some(PreflightReject::AlreadySatisfied(
                "Microsoft Defender 已卸载或已禁用，无需再关闭".to_string(),
            ));
        }
    }
    // 步骤不可执行预检：只查 restore 侧还是正向侧，按方向取对应数组。
    // 判据复用 [`step_exec_mode`]，那是 execMode 的唯一真源 —— 预检自己判一次
    // 「这一步能不能编译」就是第二份口径。
    // R3-K01（v7.2 C04）：还原方向必须先有可还原步骤——旧实现 restore=true 时
    // 对无 restore 段的项直接放行（缺失键被 `if let` 跳过），批量还原预检对
    // 23 个 restoreAvailable=false 的项全回 runnable。
    if restore {
        let has_restore = opt
            .get("restore")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        if !has_restore {
            return Some(PreflightReject::NoRestorePath);
        }
    }
    let steps_key = if restore { "restore" } else { "steps" };
    if let Some(arr) = opt.get(steps_key).and_then(|v| v.as_array()) {
        if !arr.is_empty() {
            if let Some(bad) = arr
                .iter()
                .find(|s| step_exec_mode(s) == "unsupported")
                // R3-L01：label 缺失也要拒。旧写法用 `and_then` 取 label，取不到就整条
                // 不拒 —— 等于「越畸形的步骤越容易通过预检」，与补 else 的初衷相反。
                .map(|s| s.get("label").and_then(|v| v.as_str()).unwrap_or("未命名步骤").to_string())
            {
                return Some(PreflightReject::UnsupportedStep(bad));
            }
        }
    }
    None
}

/// 组装执行步骤链 + 生效子集（R3-K01，v7.2 C04）。
///
/// **方向单次分流**：`restore` 判据放在组装链**最前**。旧链里 `is_dynamic` 分支
/// 无条件走 `memory_steps` / `wu_pause_steps`（`{restore:true}` 还原请求会写 HKLM /
/// 改服务）、`include_store` 分支不看 `p.restore`（`{restore:true, includeStore:true}`
/// 取正向 65 服务步再追加商店 5 项）——还原请求可以执行正向写入，还免掉红色确认
///（preflight 对 restore 方向豁免高危确认，审查 2026-09-27 H1 的善意被参数组合借道）。
/// 修复后 restore 请求只认 `restore` 数组：`includeStore` / `pickedTargets` /
/// 动态参数在还原方向一概不生效；无可还原步骤的项由 preflight（NoRestorePath）
/// 与本函数双处同拒，判据同一份。
///
/// 抽成纯函数是给**方向串台契约测试**留判据面（R3-U01 取证结论：「apply/restore
/// 方向串台」在旧形态下无法判红——不抽出目录级枚举判据，契约测试无从谈起）。
///
/// `Err(message)` = 组装即拒（无可还原步骤 / 动态参数缺失或越界），调用方直接回执。
pub(super) fn assemble_steps(
    opt: &Value,
    option_id: &str,
    p: &RunParams,
) -> Result<(Vec<Value>, Option<Vec<String>>), String> {
    let is_dynamic = opt.get("dynamic").and_then(|v| v.as_bool()).unwrap_or(false);

    // includeStore 与子集选择是**正交**参数：早期实现里子集分支优先，把 includeStore
    // 整个吞掉（勾了商店段却不写、回执仍成功）。把商店服务并进子集清单，让
    // `rebuild_steps` 一并重建；全选路径保持原样（append 在后面的分支里）。
    let picked_targets_effective: Option<Vec<String>> =
        match (p.picked_targets.as_ref(), option_id, p.include_store) {
            (Some(list), "tf_svc_bulk", true) if !list.is_empty() => {
                let mut v = list.clone();
                for s in STORE_SERVICES {
                    if !v.iter().any(|x| x.eq_ignore_ascii_case(s)) {
                        v.push((*s).to_string());
                    }
                }
                Some(v)
            }
            _ => p.picked_targets.clone(),
        };

    // 组装步骤。restore 在最前：还原请求不接受任何正向参数的改道。
    let steps: Vec<Value> = if p.restore {
        let Some(restore) = opt.get("restore").and_then(|v| v.as_array()) else {
            log::write_log("warn", &format!("优化项 {option_id} 无还原步骤定义，已拒绝还原请求"));
            return Err("该优化项暂不支持一键还原，请手动恢复或使用系统还原点".into());
        };
        if restore.is_empty() {
            return Err("该优化项暂不支持一键还原，请手动恢复或使用系统还原点".into());
        }
        restore.clone()
    } else if is_dynamic {
        // R3-L06：参数校验不在这里各写一份，见 [`dynamic_steps`]。
        dynamic_steps(option_id, p)?
    } else if super::subitems::supports_subitems(option_id) {
        // 批量项的子集执行（2026-10-03）。优先级高于 includeStore 分支：
        // 勾了子集就是「我只要这几个」，此时再自动追加商店 5 项是越权。
        // 勾了商店（include_store）却被子集分支吃掉的话，用户会拿到一份
        // 「没禁成商店服务却报了成功」的假回执。
        // （restore 已在最前分流，本分支只会被正向请求走到。）
        match super::subitems::rebuild_steps(
            option_id,
            picked_targets_effective.as_deref(),
            p.picked_extras.as_deref(),
        ) {
            Some(rebuilt) if rebuilt.is_empty() => {
                return Err("一个目标都没勾选，请至少勾选一项再执行".into());
            }
            Some(rebuilt) if option_id == "tf_svc_bulk" && p.include_store => {
                // R3-M02（v4）与 R3-M03 同批：子集分支同样要追加商店服务 ——
                // picked_targets_effective 虽已并入 5 个商店服务名，但 rebuild_steps 按侧表
                // 做交集会把它们**静默滤掉**（侧表 65 条里没有这五个名字），于是「用户经
                // 弹窗确认过的写入没有发生、回执仍为成功」。基线侧（option_targets）已同步
                // 纳入这 5 个 Start，两处必须同批上线，单修一处会把危害升级为「写了但还原不回来」。
                svc_bulk_append_store(rebuilt)
            }
            Some(rebuilt) => rebuilt,
            // None = 全选 ⇒ 走下面原有的原脚本路径（含 includeStore 的条件追加）
            None if option_id == "tf_svc_bulk" && p.include_store => {
                let base = opt
                    .get("steps")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                svc_bulk_append_store(base)
            }
            None => opt.get("steps").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
        }
    } else if option_id == "tf_svc_bulk" && p.include_store {
        let base = opt
            .get("steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        svc_bulk_append_store(base)
    } else {
        opt.get("steps").and_then(|v| v.as_array()).cloned().unwrap_or_default()
    };
    Ok((steps, picked_targets_effective))
}

/// R3-M04（v7.2 C04）：@@RECYCLE@@ 计数的回执/记账摘要。`None` = 本轮没有回收站
/// 动作，不附加任何文案。抽成纯函数是给「失败时计数不消失」留判据面。
pub(super) fn recycle_summary(rec_ok: i64, rec_fail: i64, rec_malformed: i64) -> Option<String> {
    if rec_ok == 0 && rec_fail == 0 && rec_malformed == 0 {
        return None;
    }
    let mut s = format!("另有 {rec_ok} 个目录已移入回收站");
    if rec_fail > 0 {
        s.push_str(&format!("，{rec_fail} 个移入失败"));
    }
    if rec_malformed > 0 {
        s.push_str(&format!("，{rec_malformed} 条协议畸形行已跳过"));
    }
    Some(s)
}

#[tauri::command]
pub async fn optimizer_run<R: Runtime>(
    window: WebviewWindow<R>,
    option_id: Option<String>,
    params: Option<RunParams>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let Some(_inflight) = OptRunGuard::acquire() else {
        return json!({ "success": false, "message": "已有优化项正在执行，请稍候" });
    };
    let option_id = option_id.unwrap_or_default();
    let Some(opt) = find_option(&option_id) else {
        return json!({ "success": false, "message": "未知的优化选项" });
    };
    let p = params.unwrap_or_default();

    // M1（R1-1.3）：判据只有这一份，`optimizer_batch_preflight` 与本函数同源调用。
    // 以前这里是三段内联的 early-return，preflight 若另抄一份，漂移后单条执行仍绿、
    // 只有批量预检错 —— 属于最难发现的一类 bug（preflight 就是给用户看的那一层）。
    //
    // ⚠️ `restore` 方向豁免高危确认是**刻意**的（审查 2026-09-27 H1）：还原只把改动
    // 回退到原值，不属于高危写入。此前闸门不分方向地拒绝，而前端约定 restore 不带
    // confirmedHighRisk 且不处理 needConfirm，导致无值级备份的高危项走预置脚本还原时
    // **整体死锁**（4 条还原入口全部命中）。preflight 必须复刻这个豁免，否则把死锁重造一遍。
    match preflight_reason(&opt, &option_id, p.restore) {
        Some(PreflightReject::NeedAdmin) => {
            return json!({
                "success": false, "needAdmin": true,
                "message": "优化操作需要管理员权限，请先提权"
            });
        }
        Some(PreflightReject::NeedHighRiskConfirm) if !p.confirmed_high_risk => {
            log::write_log(
                "warn",
                &format!("高危优化缺少确认回执，已拒绝: {option_id} (restore={})", p.restore),
            );
            return json!({
                "success": false, "needConfirm": true,
                "message": "高危操作缺少红色确认回执，请在界面重新确认后执行"
            });
        }
        // 步骤在本机编译不出来时预先拒绝：原先这条只在执行中段才暴露（apply.rs 的
        // pwsh 分支 `failed += 1`），用户看到的是「第 5 项失败」而前 4 项已落盘。
        Some(PreflightReject::UnsupportedStep(reason)) => {
            log::write_log("warn", &format!("优化项步骤不可执行，已预先拒绝: {option_id} ({reason})"));
            return json!({ "success": false, "message": format!("本机不支持该优化项的某一步：{reason}") });
        }
        // 目标状态已满足（Defender 已卸载/已禁用）：不当失败处理，明确告知无需执行
        Some(PreflightReject::AlreadySatisfied(reason)) => {
            log::write_log("info", &format!("优化项目标状态已满足，跳过执行: {option_id} ({reason})"));
            return json!({ "success": false, "alreadySatisfied": true, "message": reason });
        }
        // R3-K01（v7.2 C04）：无可还原步骤的还原请求点名拒因（与批量预检同一份判据）
        Some(r @ PreflightReject::NoRestorePath) => {
            log::write_log("warn", &format!("优化项无可还原步骤，已拒绝还原请求: {option_id}"));
            return json!({ "success": false, "message": r.message() });
        }
        _ => {}
    }

    // （is_dynamic 已收进 assemble_steps——组装链单次分流后命令体不再需要它）
    let title = super::subitems::display_title(
        &option_id,
        opt.get("title").and_then(|v| v.as_str()).unwrap_or(&option_id),
    );

    // 组装步骤 + 生效子集（R3-K01：restore 方向在 assemble_steps 内单次分流）
    let (steps, picked_targets_effective) = match assemble_steps(&opt, &option_id, &p) {
        Ok(v) => v,
        Err(message) => {
            log::write_log("warn", &format!("优化项组装即拒: {option_id}（{message}）"));
            return json!({ "success": false, "message": message });
        }
    };
    if steps.is_empty() {
        return json!({ "success": false, "message": "选项无可执行步骤" });
    }

    // P1-02（G-02）：用 SCM 核对本次涉及的服务/驱动，收集本机不存在（执行 foreach
    // 里被 Test-Path 静默跳过）的目标。全量=侧表全名单，子集=picked∩名单（同 rebuild 口径）。
    // 纯 Rust 判定：不依赖 PS 输出协议，全量/子集路径都覆盖；跳过不影响成功，但必须可见。
    let mut skipped: Vec<String> = Vec::new();
    {
        let kind_label = match option_id.as_str() {
            "tf_svc_bulk" => Some("服务"),
            "tf_drv_disable" => Some("驱动"),
            _ => None,
        };
        if let Some(kl) = kind_label {
            let all = super::subitems::targets_of(&option_id);
            let using_subset = !p.restore && super::subitems::supports_subitems(&option_id);
            let names: Vec<String> = if using_subset {
                match picked_targets_effective.as_deref() {
                    Some(list) if !list.is_empty() => all
                        .iter()
                        .filter(|t| list.iter().any(|x| x == *t))
                        .cloned()
                        .collect(),
                    _ => all,
                }
            } else {
                all
            };
            for n in names {
                if !crate::engine::native::service_exists(&n) {
                    skipped.push(format!("{kl} {n}"));
                }
            }
            if !skipped.is_empty() {
                log::write_log(
                    "info",
                    &format!(
                        "优化项 {option_id} 跳过 {} 个本机不存在的目标：{}",
                        skipped.len(),
                        skipped.join("；")
                    ),
                );
            }
        }
    }

    let is_restore_run = p.restore
        && opt.get("restore").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false);

    // fail-closed ①：执行前记账
    if !is_restore_run {
        let kinds = classify_step_kinds(&steps);
        if !opt_state::record_pending_scoped(
            &option_id,
            &title,
            &kinds,
            picked_targets_effective.as_deref(),
        ) {
            log::write_log("error", &format!("优化状态记账失败，已按 fail-closed 中止执行: {title}"));
            return json!({
                "success": false,
                "message": "优化状态记录写入失败，已中止执行（避免产生无法追溯的系统更改）"
            });
        }
    }

    log::write_log(
        "info",
        &format!("优化电脑执行: {title}{}", if p.restore { " (还原)" } else { "" }),
    );
    // R3-M02（v7.2 C04，AGENTS §3）：危险操作前置刷盘——本链接下来写注册表/服务/
    // 电源（正向与还原两个方向都是），动手前先把执行日志强制落盘，防尾部日志丢失。
    log::flush_sync();
    // S3：纯 Rust 原生
    // 性能优化 P1-A（v3 §4.3）：整条步骤链是同步原生调用——PsInline 步骤登记 300s、
    // cmd 步骤登记 60s，过去直接跑在 async 命令体里 ⇒ 占住 runtime worker，
    // 批量执行时一条慢优化项就能把共享池的 worker 按住几分钟。
    // 本文件此前只有 `commands::optimizer::restore_point` 一处进了阻塞池，这条是那批修复的漏网。
    // join 异常并入下面的失败分支（措辞点名「阻塞池任务异常」），不静默吞成成功。
    let win_blk = window.clone();
    let steps_blk = steps.clone();
    let oid_blk = option_id.clone();
    let native = tauri::async_runtime::spawn_blocking(move || {
        native_execute_steps(&win_blk, &steps_blk, &oid_blk)
    })
    .await
    .unwrap_or_else(|e| Err(format!("阻塞池任务异常（执行未起跑或未跑完）: {e}")));
    let (run, failed_reasons): (Result<pwsh::PsOutput, String>, Vec<String>) = match native {
            Ok((failed_steps, inline_stdout, reasons)) => {
                let code = if failed_steps == 0 { 0 } else { 1 };
                let mut stdout = String::new();
                // PsInline 的 stdout（@@RECYCLE@@ 协议行）必须先于收尾标记
                if !inline_stdout.is_empty() {
                    stdout.push_str(&inline_stdout);
                    if !inline_stdout.ends_with('\n') {
                        stdout.push('\n');
                    }
                }
                stdout.push_str(&format!("@@PROGRESS:100@@\n@@FAILED:{failed_steps}@@\n@@DONE@@\n"));
                (Ok(pwsh::PsOutput { code, stdout, stderr: String::new(), timed_out: false, tree_terminate_failed: false }), reasons)
            }
            Err(e) => (Err(format!("原生执行失败: {e}")), Vec::new()),
        };
    let Ok(out) = run else {
        let e = run.err().unwrap_or_else(|| "执行异常".into());
        log::write_log("error", &format!("优化电脑执行异常: {e}"));
        if !is_restore_run {
            // 审查 v3-K1：执行链整体失败（没跑成）≠ 执行成功但验证不了。
            // 旧代码在这里 mark_applied("unknown") 谎报 applied，违反记账不变式②；
            // 改落 partial，由 optimizer_state_overview 如实呈现。
            // 根治（2026-10-03）：失败原因一并记账，横幅/详情里能看出败在哪。
            let _ = opt_state::mark_partial_with_reasons(
                &option_id,
                &[format!("执行链整体失败: {e}")],
            );
        }
        return json!({ "success": false, "message": e });
    };

    let stdout = out.stdout.clone();
    let failed_steps = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("@@FAILED:").and_then(|x| x.strip_suffix("@@")))
        .and_then(|x| x.parse::<i64>().ok())
        .unwrap_or(0);
    let ok = out.code == 0 && stdout.contains("@@DONE@@") && failed_steps == 0;
    if !ok {
        log::write_log("warn", &format!("优化电脑命令退出码 {}: {title}", out.code));
    }

    // B-2：@@RECYCLE@@ 协议——受保护路径拒绝，其余进回收站（PS 侧只枚举不删除）
    let (mut rec_ok, mut rec_fail, mut rec_malformed) = (0i64, 0i64, 0i64);
    // R3-M03（v7.2 C01）：@@RECYCLE@@ 出口的单批上限（口径对齐 FINDER_DELETE_MAX）。
    const RECYCLE_EXIT_MAX_ITEMS: i64 = 500;
    let mut rec_seen: i64 = 0;
    {
        let mut seen = std::collections::HashSet::new();
        for raw in stdout.lines() {
            let line = raw.trim();
            let Some(rest) = line.strip_prefix("@@RECYCLE@@") else { continue };
            // 审查 M-1（2026-10-03 L3）：畸形行**必须计数并告警**，不能静默丢。
            // 与 cleanup/scan_execute.rs 的 count_malformed 同口径：否则 PS 输出被
            // 截断/掺噪声时，用户与审计者都无从知道有目录漏进回收站。
            // R3-L07（v7.2 C04）：形状判定收进 `classify_recycle_line` 一处 ——
            // `"path": ""` 过去与「重复行」共用一个 `continue`，既不计数也不告警，
            // 与本条自述相反；现在它和「缺 path」「解析失败」同归畸形。
            let p = match classify_recycle_line(rest, &mut seen) {
                RecycleLine::Malformed(why) => {
                    rec_malformed += 1;
                    log::write_log("warn", &format!("优化回收站协议畸形行（{why}）: {rest}"));
                    continue;
                }
                // 重复行按「同一个目录只投一次」去重，属正常收敛，不计畸形。
                RecycleLine::Duplicate => continue,
                RecycleLine::Path(p) => p,
            };
            // R3-M03（v7.2 C01）：单批上限——PS 输出被截断/掺噪声/失控时，回收站出口
            // 不能无界吞路径。口径对齐 finder 的 FINDER_DELETE_MAX(500)。
            if rec_seen >= RECYCLE_EXIT_MAX_ITEMS {
                rec_fail += 1;
                log::write_log("warn", &format!("优化回收站协议超出单批上限 {RECYCLE_EXIT_MAX_ITEMS}，已拒: {p}"));
                continue;
            }
            rec_seen += 1;
            // C01（v7.2 R3-M03）：此前只过 `is_path_protected` 第一道闸——
            // %WINDIR% 子孙（exact 语义管不到）与 reparse 件都会进回收站。
            // 四道组合闸收口到 validate_mutation_target（拒因唯一真源）。
            if let Err(why) = protect::validate_mutation_target(&p) {
                rec_fail += 1;
                log::write_log("warn", &format!("优化回收站协议拒绝: {why}"));
                continue;
            }
            // 审查 v2-F1：走 `_os` 版。路径来自 PS stdout 的 @@RECYCLE@@ 协议，
            // 含孤立代理项的名字经 `&str` 往返会被改写，导致删错或删不到。
            match trim_finder::scan::recycle::send_to_trash_os(std::path::Path::new(&p).as_os_str()) {
                Ok(()) => rec_ok += 1,
                Err(e) => {
                    rec_fail += 1;
                    log::write_log("warn", &format!("优化项目标移入回收站失败: {p} -> {e}"));
                }
            }
        }
        if rec_malformed > 0 {
            log::write_log("warn", &format!("优化回收站协议共 {rec_malformed} 条畸形行已跳过"));
        }
    }
    // 审查 2026-09-27 M4：失败不再只报「部分步骤可能失败」——携带逐步原因（label +
    // 失败方式），前端 toast 与日志按此呈现，排障不再两眼一抹黑。
    // R3-M04（v7.2 C04）：步骤链判失败时，「已移入回收站的 N 个目录」不得从回执
    // 与记账双双消失——那些目录**真的已经离开原位**，只报失败会让用户以为什么
    // 都没发生而去做别的操作。
    let rec_summary = recycle_summary(rec_ok, rec_fail, rec_malformed);
    let ok_message = if !ok {
        let mut m = if failed_reasons.is_empty() {
            "部分步骤可能失败".to_string()
        } else {
            format!("{} 项步骤失败：{}", failed_reasons.len(), failed_reasons.join("；"))
        };
        if let Some(s) = &rec_summary {
            m.push_str(&format!("；{s}"));
        }
        m
    } else if rec_ok > 0 || rec_fail > 0 || rec_malformed > 0 {
        let mut suffix = String::new();
        if rec_fail > 0 {
            suffix.push_str(&format!("，{rec_fail} 个失败"));
        }
        if rec_malformed > 0 {
            // M-1（2026-10-03 L3）：畸形行不再静默 —— 用户与审计者要能看到有目录漏掉了
            suffix.push_str(&format!("，{rec_malformed} 条畸形行已跳过"));
        }
        if rec_fail > 0 || rec_malformed > 0 {
            format!("完成（{rec_ok} 个目录已移入回收站{suffix}）")
        } else {
            format!("完成（{rec_ok} 个目录已移入回收站，可在系统回收站还原）")
        }
    } else {
        "完成".to_string()
    };

    // 进度收尾：脚本自己最后一行就是 @@PROGRESS:100@@，正常路径已由上面的流式回调发过；
    // 这里再兜一次，保证脚本在 9x% 处异常中断时进度条不会永久停在半路。
    if ok {
        let _ = window.emit("optimizer:progress", json!({ "optionId": option_id, "percent": 100 }));
    }

    // 记账收尾 + 回读
    if is_restore_run {
        if ok {
            // 首选值级备份逐项比对（原值不存在则当前必须不存在）；无备份/读不到再走反向判据
            let verify = verify_option_restored(&option_id, opt);
            if verify == "partial" {
                log::write_log("warn", &format!("还原后回读校验不符（可能被组策略/安全软件覆盖）: {title}"));
                let _ = opt_state::set_detected_entry(&option_id, true);
                return json!({
                    "success": true,
                    "message": "还原已执行但未完全生效（回读不符），可重试",
                    "verify": verify
                });
            }
            // v5 P2：`unknown` = 既没有值级备份可比、反向判据也给不出结论。此时**销账**等于
            // 抹掉用户唯一的重试依据（「未完成还原」横幅靠这条记录才提示），界面上却写着"已恢复"。
            // 只有拿到 pass 证据才销账；unknown 保留记录并如实说明。
            if verify == "unknown" {
                log::write_log("warn", &format!("还原后无法回读校验（无备份且反向判据不适用），账本保留: {title}"));
                return json!({
                    "success": true,
                    "message": "还原命令已执行，但无法验证是否生效，请在详情里复核（该记录已保留，可重试）",
                    "verify": verify
                });
            }
            let _ = opt_state::remove(&option_id);
            let _ = opt_state::set_detected_entry(&option_id, false);
            return json!({ "success": true, "message": ok_message, "verify": verify });
        }
    } else if ok {
        let mut verify = verify_applied(&option_id, opt, &p);
        // 审查 2026-09-27 L7：@@RECYCLE@@ 目录删除失败不计入步骤失败（主要写入已成功），
        // 但「回读全部命中」时不应记 pass——降档 partial 并如实提示，避免假绿
        if rec_fail > 0 && verify == "pass" {
            verify = "partial";
            log::write_log("warn", &format!("优化项有 {rec_fail} 个目标目录移入回收站失败，回读降档为 partial: {title}"));
        }
        if verify == "partial" {
            log::write_log("warn", &format!("执行后回读校验不符（可能被组策略/安全软件覆盖）: {title}"));
        }
        let _ = opt_state::mark_applied(&option_id, verify);
        if verify != "unknown" {
            let _ = opt_state::set_detected_entry(&option_id, verify == "pass");
        }
        // P1-02：成功时若有本机不存在而被跳过的目标，message 点名数量、完整名单随 skipped 下发
        let final_message = if skipped.is_empty() {
            ok_message
        } else {
            format!("{ok_message}（{} 个本机不存在，已跳过，完整名单见操作日志）", skipped.len())
        };
        return json!({
            "success": true,
            "message": final_message,
            "verify": verify,
            "skipped": skipped
        });
    } else {
        // 审查 2026-09-27 M1：部分步骤失败（failed>0 但链路跑完）不再 mark_applied("unknown")
        // 转正为「已应用」——违反记账不变式②「执行成功才转正」，且纯 cmd/pwsh 项不可回读、
        // 错误状态永无纠正机会。改落 partial，由 optimizer_state_overview 如实呈现（可重试）。
        // 根治（2026-10-03）：失败子步原因随记账落盘——此前只在日志里，用户看到
        // 「状态不明」却无从判断该还原还是该重跑。
        // R3-M04（v7.2 C04）：已移入回收站的目录数一并记账——只记失败原因会把
        // 「部分目标已经离开原位」这个事实从账本上抹掉。
        let mut ledger_reasons = failed_reasons.clone();
        if let Some(s) = &rec_summary {
            ledger_reasons.push(s.clone());
        }
        let _ = opt_state::mark_partial_with_reasons(&option_id, &ledger_reasons);
        log::write_log(
            "warn",
            &format!("优化项部分步骤失败（{} 项），已记账为 partial: {title}", failed_reasons.len()),
        );
        return json!({
            "success": false,
            "message": ok_message,
            "failedSteps": failed_reasons
        });
    }
    json!({ "success": ok, "message": ok_message })
}

/// 正向执行后回读：动态 svc_mem_gb 比对档位；可检测项走 check_optimized；否则 unknown
pub(super) fn verify_applied(option_id: &str, opt: &Value, p: &RunParams) -> &'static str {
    if option_id == "svc_mem_gb" {
        let target = match &p.gb {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Number(n)) => Some(n.to_string()),
            _ => None,
        };
        let Some(target) = target else { return "unknown" };
        return match svc_mem_current_kb() {
            Some(kb) => {
                let hit = MEMORY_KB.iter().any(|(k, v)| *v == kb && *k == target.as_str())
                    || (target == "default" && kb == MEMORY_KB_DEFAULT);
                if hit {
                    "pass"
                } else {
                    "partial"
                }
            }
            None => "unknown",
        };
    }
    let checks = collect_checks(opt);
    if checks.is_empty() {
        return "unknown";
    }
    // 条目级特例（tf_defender 卸载/禁用判据）：与启动回读 check_optimized 走同一个钩子，
    // 不在这里另写判据（AGENTS §5.16）。卸载机执行策略写键不会重建服务，回读仍由
    // WinDefend 服务存在性/启动类型一锤定音。
    if let Some(v) = special_item_verdict(option_id) {
        return if v { "pass" } else { "partial" };
    }
    // 子集执行时**只断言真正下过写的目标**（2026-10-05 真机反馈的根因）：
    // 用户在 65 个服务里勾了 3 个，另外 62 个的启动类型当然还是原值 —— 拿全量清单
    // 判 `all()` 就是把「按我的选择做完了」报成「未生效」，还会每次启动都挂上
    // 「未完成还原」横幅。收窄规则与启动回读共用 [`scope_checks`]（同一份判据，
    // AGENTS §5.16）；同一份 `picked` 也已写进账本，两条路径不会分叉。
    let scoped = scope_checks(&checks, p.picked_targets.as_deref());
    // 勾的子集在这份清单里一条断言都没有（例如只选了 pwsh-only 的目标）⇒ 无从回读，
    // 如实 unknown，不许落到「未生效」
    if scoped.is_empty() {
        return "unknown";
    }
    if scoped.iter().all(|c| judge_check(c)) {
        "pass"
    } else {
        "partial"
    }
}

/// 还原回读：① 按值级备份逐项比对（原值确认不存在则当前必须确认不存在）；
/// ② 无备份或读取失败时退回反向判据（可检测项 check_optimized 应为 false）。
///
/// P0-3：逐项比对优先读 `presence`（权威三态）。want 侧旧记录无 presence 且
/// `exists=false` = legacyUnknown，**不得**解释成「确认不存在」——既不能据此给
/// pass（当年可能只是没读到），也不硬判 partial（无从证实不符），如实 unknown；
/// got 侧此刻读不出来同样呈报 unknown，不冒充「不存在」或「不一致」。
pub(super) fn verify_option_restored(option_id: &str, opt: &Value) -> &'static str {
    // 分支 1：值级备份
    let map = load_opt_backups();
    if let Some(entry) = map.get(option_id) {
        if let Some(want_values) = entry.get("values").and_then(|v| v.as_array()) {
            if !want_values.is_empty() {
                if let Some(got) = read_values_by_backup(want_values) {
                    if got.len() == want_values.len() {
                        for (want, got) in want_values.iter().zip(got.iter()) {
                            // want 侧：旧记录只在 exists=true 时可信为「值存在过」
                            // （读成功过才会带 type/data）；无 presence 且 exists=false
                            // 是 legacyUnknown，下不了任何结论。
                            let want_p = match backup_presence(want) {
                                Some(p) => p,
                                None if want.get("exists").and_then(|v| v.as_bool()).unwrap_or(false) => "value",
                                None => return "unknown",
                            };
                            if want_p == "unknown" {
                                return "unknown"; // 备份时就没确认状态，回读没有比对基准
                            }
                            // got 侧由 read_values_by_backup 现造，必带 presence；
                            // 万一结构意外，宁可 unknown 也不猜
                            let Some(got_p) = backup_presence(got) else { return "unknown" };
                            if got_p == "unknown" {
                                return "unknown"; // 此刻读不到：不能拿「不知道」冒充「不符」
                            }
                            if want_p != got_p {
                                return "partial"; // 一边确认缺、一边确认在，还原没落到
                            }
                            if want_p == "absent" {
                                continue; // 原本确认不存在 + 当前确认不存在 = 已恢复
                            }
                            if want.get("type").and_then(|v| v.as_str())
                                != got.get("type").and_then(|v| v.as_str())
                            {
                                return "partial";
                            }
                            if want.get("data").and_then(|v| v.as_str())
                                != got.get("data").and_then(|v| v.as_str())
                            {
                                return "partial";
                            }
                        }
                        return "pass";
                    }
                }
                return "unknown"; // 备份在但读不到/数量不符：不下结论
            }
        }
    }
    // 分支 2：反向判据
    if collect_checks(opt).is_empty() {
        return "unknown";
    }
    match check_optimized(Some(&[option_id.to_string()])).get(option_id) {
        Some(false) => "pass",
        Some(true) => "partial",
        None => "unknown",
    }
}

/// 按备份条目（hive 为 .NET 静态属性名）读当前值
///
/// B11：与 `read_reg_values` 同一条 PS 模板的另一处调用 —— 备份条目的 `hive` 已是
/// .NET 名（LocalMachine/CurrentUser…），这里换用 `restore_hive` 解析，其余口径一致。
///
/// **必须与 `read_reg_values` 同一口径（faithful）**：产物是给 `verify_option_restored`
/// 逐项比对 `type`/`data` 用的。一侧展平、一侧不展平，会让每个 EXPAND_SZ/MULTI_SZ
/// 备份项永远比出不一致，还原明明成功却报「部分还原」。
///
/// P0-3：同样走三态内核 + 同源条目构造 —— got 侧带 `presence`，「此刻读不到」
/// 呈报为 unknown，不得冒充 absent 让回读把「不确定」误判成「已恢复/不一致」。
pub(super) fn read_values_by_backup(want: &[Value]) -> Option<Vec<Value>> {
    use crate::engine::native;
    let mut out = Vec::with_capacity(want.len());
    for v in want {
        let hive = v.get("hive").and_then(|x| x.as_str()).unwrap_or("LocalMachine");
        let sub = v.get("sub").and_then(|x| x.as_str()).unwrap_or("");
        let key = v.get("key").and_then(|x| x.as_str()).unwrap_or("");
        let Some(h) = restore_hive(hive) else { return None };
        let state = native::read_reg_value_state(h, sub, key, false);
        out.push(backup_entry_from_state(hive, sub, key, state));
    }
    Some(out)
}

/// 读当前 SVCHost 阈值 KB（供动态项回读；失败 None）
///
/// B11：原先这里生成 4 行 PS 去读一个 HKLM DWORD，起一个 pwsh 子进程、等它退出、
/// 再解析 stdout 里的 `KB|<n>` —— 换成直接走注册表 API，语义不变（值缺失/类型不对
/// 都按 None 处理）。键路径**保持 `ControlSet001` 字面量**：原 PS 与写入侧（本文件
/// `commands::optimizer::apply::memory_steps` 产的 `reg add`）都指它，不换 `CurrentControlSet`，
/// 避免「读到活动集、写到 001」的口径分裂。
pub(super) fn svc_mem_current_kb() -> Option<i64> {
    crate::engine::native::read_hklm_dword(
        r"SYSTEM\ControlSet001\Control",
        "SvcHostSplitThresholdInKB",
    )
}
