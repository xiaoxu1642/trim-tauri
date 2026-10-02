//! 应用侧：PS 脚本构建（对照 buildScript）、动态步骤、原生步骤、`optimizer_run` 与
//! 应用/还原回读验证、运行互斥 guard、`RunParams` 共享类型。
//!
//! PS 执行只走 `pwsh::run_inbox_script` 单一入口（v2 R0/R1），超时登记在
//! tools/check-ps-callsites.mjs；build_script 产出的协议行（@@PROC@@ 等）与
//! `src-tauri/ps/optimizer_build.ps1` 哨兵模板由 check-ps-extraction 逐字节对拍。
//! OptRunGuard / OPT_RUN_INFLIGHT 是「同一时刻只跑一次优化」的闩锁，Drop 里释放。

use crate::pwsh;
use crate::engine::{guard, log, optimization_state as opt_state, protect, sysinfo};
use crate::engine::systembin::system_tool;
use serde_json::{Value, json};
use std::sync::OnceLock;
use tauri::{Runtime, WebviewWindow};
use tauri::Emitter;
use std::os::windows::process::CommandExt;
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

pub(super) fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// steps JSON 数组 → PowerShell 脚本（与 JS buildScript 同口径）
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
            // 引号陷阱（PS 也会把内嵌引号重写成子进程不认的形状）。今天不可达——唯一调用
            // build_script 的 tf_restore_point 只有 reg + pwsh 两种步骤。若哪天有 cmd 步骤
            // 走到这里，先照 run_cmd_step 的实测结论改这条，别等回读校验报不符再查。
            let safe = cmd.replace('\'', "''");
            l.push(format!("$___cmd='{safe}'"));
            l.push("& $env:ComSpec /c $___cmd *> $null".into());
            l.push(format!("if ($LASTEXITCODE -ne 0) {{ $failedSteps++; Write-TFDiag -Stage 'optimizer.cmd' -Mutation 'partial' -Detail ('step ' + ({i} + 1) + ' [' + {label_ps} + '] exit=' + $LASTEXITCODE) }}"));
        } else if let Some(service) = s.get("service").and_then(|v| v.as_str()) {
            // 与 `native_execute_steps` 的 service 分支**同口径**（R0-a）。这里原来只认
            // `disable`，startType 形态在 PS 轨上同样会退化成「只停服」。两条轨的分歧不是
            // 美观问题：tf_restore_point 这类项走 build_script，而备份/回读按 native 轨的
            // 语义记账，两轨对同一份 steps 给出不同解释 = 备份与实际写入不匹配。
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
    crate::engine::systembin::quiet_cmd(system_tool("cmd"))
        .raw_arg(cmd_line_of(cmd))
        .output()
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
    let _ = std::fs::create_dir_all(&tmp_dir);

    for (i, s) in steps.iter().enumerate() {
        let pct = (((i + 1) as f64 / total as f64) * 100.0).round() as u32;
        let label = s.get("label").and_then(|v| v.as_str()).unwrap_or("");

        if let Some(reg) = s.get("reg").and_then(|v| v.as_str()) {
            // reg 类型：写 .reg 临时文件 + 原生 import（A6，v2-R4）
            let reg_path = tmp_dir.join(format!("wcopt_{}.reg", crate::engine::now_ms()));
            // 审查 2026-09-27 L1：.reg 临时文件为 UTF-16LE + BOM（.reg 的 Unicode 格式），
            // 与 `reg.exe export` 的产物同编码。原先「路径非 UTF-8 就跳过该步」（v3-L7）
            // 是 reg.exe 需要字符串参数才有的限制，原生拿 &Path 后随 reg.exe 一起删除。
            // 中文值数据在旧 UTF-8 无 BOM 形态下会被按 ANSI 误读，那一条现在由读侧的
            // 编码感知（reg_backup::read_reg_text_file）兜住。
            let mut reg_bytes = vec![0xFFu8, 0xFEu8];
            reg_bytes.extend(reg.encode_utf16().flat_map(|u| u.to_le_bytes()));
            if std::fs::write(&reg_path, &reg_bytes).is_err() {
                failed += 1;
                failed_reasons.push(format!("步骤「{label}」: .reg 临时文件写入失败"));
            } else {
                // A6（v2-R4）：原生 `.reg` 写入替换 `reg.exe import`。
                // 文件仍按 UTF-16LE+BOM 写（那是这份 .reg 文本格式既有的约定，v2 明令不动），
                // 读侧的编码感知在 reg_backup::read_reg_text_file。
                // 失败原因现在进 failed_reasons —— 旧实现只说"返回非零"，用户看不到为什么。
                match crate::engine::reg_backup::reg_import_apply(std::path::Path::new(&reg_path)) {
                    Ok(_) => {}
                    Err(e) => {
                        failed += 1;
                        failed_reasons.push(format!("步骤「{label}」: {e}"));
                    }
                }
                let _ = std::fs::remove_file(&reg_path);
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

pub(super) fn memory_steps(gb: &Value) -> Vec<Value> {
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
    } else {
        (8_388_608, "8GB（请求值异常，已回退到 8GB 阈值）".to_string())
    };
    vec![json!({
        "label": format!("SVCHost 拆分阈值 {name}"),
        "cmd": format!("reg add \"HKLM\\SYSTEM\\ControlSet001\\Control\" /v SvcHostSplitThresholdInKB /t REG_DWORD /d {kb} /f")
    })]
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
    /// 本机编译不出来的 pwsh 步骤。`String` 是 `step_exec_mode` 判出的 execMode。
    UnsupportedStep(String),
}

impl PreflightReject {
    /// 给渲染层看的文案。**中文、单一真源**：preflight 的 `rejected[].reason`
    /// 与单条执行的 `message` 都从这里取，两处不许各写一份。
    pub(super) fn message(&self) -> String {
        match self {
            Self::NeedAdmin => "需要管理员权限".to_string(),
            Self::NeedHighRiskConfirm => "需高危确认".to_string(),
            Self::UnsupportedStep(m) => format!("本机不支持（{m}）"),
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
    // 步骤不可执行预检：只查 restore 侧还是正向侧，按方向取对应数组。
    // 判据复用 [`step_exec_mode`]，那是 execMode 的唯一真源 —— 预检自己判一次
    // 「这一步能不能编译」就是第二份口径。
    let steps_key = if restore { "restore" } else { "steps" };
    if let Some(arr) = opt.get(steps_key).and_then(|v| v.as_array()) {
        if !arr.is_empty() {
            if let Some(bad) = arr
                .iter()
                .find(|s| step_exec_mode(s) == Some("unsupported"))
                .and_then(|s| s.get("label").and_then(|v| v.as_str()).map(|l| l.to_string()))
            {
                return Some(PreflightReject::UnsupportedStep(bad));
            }
        }
    }
    None
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
        _ => {}
    }

    let is_dynamic = opt.get("dynamic").and_then(|v| v.as_bool()).unwrap_or(false);
    let title = opt.get("title").and_then(|v| v.as_str()).unwrap_or(&option_id).to_string();

    // 组装步骤
    let steps: Vec<Value> = if is_dynamic {
        if option_id == "svc_mem_gb" {
            memory_steps(&p.gb.clone().unwrap_or(Value::Null))
        } else if option_id == "perf_wu_pause" {
            let Some(d) = p.days else {
                return json!({ "success": false, "message": "缺少暂停天数参数" });
            };
            if !d.is_finite() {
                return json!({ "success": false, "message": "缺少暂停天数参数" });
            }
            let days = d.trunc() as i64;
            if !(1..=WU_PAUSE_MAX_DAYS).contains(&days) {
                return json!({ "success": false, "message": format!("暂停天数需在 1~{WU_PAUSE_MAX_DAYS} 天之间") });
            }
            wu_pause_steps(days)
        } else {
            Vec::new()
        }
    } else if option_id == "tf_svc_bulk" && p.include_store {
        let base = opt
            .get("steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        svc_bulk_append_store(base)
    } else if p.restore {
        let Some(restore) = opt.get("restore").and_then(|v| v.as_array()) else {
            log::write_log("warn", &format!("优化项 {option_id} 无还原步骤定义，已拒绝还原请求"));
            return json!({ "success": false, "message": "该优化项暂不支持一键还原，请手动恢复或使用系统还原点" });
        };
        if restore.is_empty() {
            return json!({ "success": false, "message": "该优化项暂不支持一键还原，请手动恢复或使用系统还原点" });
        }
        restore.clone()
    } else {
        opt.get("steps").and_then(|v| v.as_array()).cloned().unwrap_or_default()
    };
    if steps.is_empty() {
        return json!({ "success": false, "message": "选项无可执行步骤" });
    }

    let is_restore_run = p.restore
        && opt.get("restore").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false);

    // fail-closed ①：执行前记账
    if !is_restore_run {
        let kinds = classify_step_kinds(&steps);
        if !opt_state::record_pending(&option_id, &title, &kinds) {
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
    // S3：纯 Rust 原生
    let (run, failed_reasons): (Result<pwsh::PsOutput, String>, Vec<String>) =
        match native_execute_steps(&window, &steps, &option_id) {
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
                (Ok(pwsh::PsOutput { code, stdout, stderr: String::new(), timed_out: false }), reasons)
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
            let _ = opt_state::mark_partial(&option_id);
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
    let (mut rec_ok, mut rec_fail) = (0i64, 0i64);
    {
        let mut seen = std::collections::HashSet::new();
        for raw in stdout.lines() {
            let line = raw.trim();
            let Some(rest) = line.strip_prefix("@@RECYCLE@@") else { continue };
            let Ok(entry) = serde_json::from_str::<Value>(rest) else { continue };
            let Some(p) = entry.get("path").and_then(|v| v.as_str()) else { continue };
            if p.is_empty() || !seen.insert(p.to_string()) {
                continue;
            }
            if protect::is_path_protected(p) {
                rec_fail += 1;
                log::write_log("warn", &format!("优化回收站协议拒绝受保护路径: {p}"));
                continue;
            }
            // 审查 v2-F1：走 `_os` 版。路径来自 PS stdout 的 @@RECYCLE@@ 协议，
            // 含孤立代理项的名字经 `&str` 往返会被改写，导致删错或删不到。
            match trim_finder::scan::recycle::send_to_trash_os(std::path::Path::new(p).as_os_str()) {
                Ok(()) => rec_ok += 1,
                Err(e) => {
                    rec_fail += 1;
                    log::write_log("warn", &format!("优化项目标移入回收站失败: {p} -> {e}"));
                }
            }
        }
    }
    // 审查 2026-09-27 M4：失败不再只报「部分步骤可能失败」——携带逐步原因（label +
    // 失败方式），前端 toast 与日志按此呈现，排障不再两眼一抹黑
    let ok_message = if !ok {
        if failed_reasons.is_empty() {
            "部分步骤可能失败".to_string()
        } else {
            format!("{} 项步骤失败：{}", failed_reasons.len(), failed_reasons.join("；"))
        }
    } else if rec_ok > 0 || rec_fail > 0 {
        if rec_fail > 0 {
            format!("完成（{rec_ok} 个目录已移入回收站，{rec_fail} 个失败）")
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
        return json!({ "success": true, "message": ok_message, "verify": verify });
    } else {
        // 审查 2026-09-27 M1：部分步骤失败（failed>0 但链路跑完）不再 mark_applied("unknown")
        // 转正为「已应用」——违反记账不变式②「执行成功才转正」，且纯 cmd/pwsh 项不可回读、
        // 错误状态永无纠正机会。改落 partial，由 optimizer_state_overview 如实呈现（可重试）。
        let _ = opt_state::mark_partial(&option_id);
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
    if collect_checks(opt).is_empty() {
        return "unknown";
    }
    match check_optimized(&[option_id.to_string()]).get(option_id) {
        Some(true) => "pass",
        Some(false) => "partial",
        None => "unknown",
    }
}

/// 还原回读：① 按值级备份逐项比对（原值不存在则当前必须不存在）；
/// ② 无备份或读取失败时退回反向判据（可检测项 check_optimized 应为 false）。
pub(super) fn verify_option_restored(option_id: &str, opt: &Value) -> &'static str {
    // 分支 1：值级备份
    let map = load_opt_backups();
    if let Some(entry) = map.get(option_id) {
        if let Some(want_values) = entry.get("values").and_then(|v| v.as_array()) {
            if !want_values.is_empty() {
                if let Some(got) = read_values_by_backup(want_values) {
                    if got.len() == want_values.len() {
                        for (want, got) in want_values.iter().zip(got.iter()) {
                            let want_exists = want.get("exists").and_then(|v| v.as_bool()).unwrap_or(false);
                            let got_exists = got.get("exists").and_then(|v| v.as_bool()).unwrap_or(false);
                            if want_exists != got_exists {
                                return "partial";
                            }
                            if !want_exists {
                                continue; // 原本不存在 + 当前不存在 = 已恢复
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
    match check_optimized(&[option_id.to_string()]).get(option_id) {
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
pub(super) fn read_values_by_backup(want: &[Value]) -> Option<Vec<Value>> {
    use crate::engine::native;
    let mut out = Vec::with_capacity(want.len());
    for v in want {
        let hive = v.get("hive").and_then(|x| x.as_str()).unwrap_or("LocalMachine");
        let sub = v.get("sub").and_then(|x| x.as_str()).unwrap_or("");
        let key = v.get("key").and_then(|x| x.as_str()).unwrap_or("");
        let Some(h) = restore_hive(hive) else { return None };
        let mut item = json!({ "hive": hive, "sub": sub, "key": key, "exists": false });
        if let Some((ty, data)) = native::read_reg_value_faithful(h, sub, key) {
            item["exists"] = json!(true);
            item["type"] = json!(ty);
            item["data"] = json!(data);
        }
        out.push(item);
    }
    Some(out)
}

/// 读当前 SVCHost 阈值 KB（供动态项回读；失败 None）
///
/// B11：原先这里生成 4 行 PS 去读一个 HKLM DWORD，起一个 pwsh 子进程、等它退出、
/// 再解析 stdout 里的 `KB|<n>` —— 换成直接走注册表 API，语义不变（值缺失/类型不对
/// 都按 None 处理）。键路径**保持 `ControlSet001` 字面量**：原 PS 与写入侧（`:245` 的
/// `reg add`）都指它，不换 `CurrentControlSet`，避免「读到活动集、写到 001」的口径分裂。
pub(super) fn svc_mem_current_kb() -> Option<i64> {
    crate::engine::native::read_hklm_dword(
        r"SYSTEM\ControlSet001\Control",
        "SvcHostSplitThresholdInKB",
    )
}

