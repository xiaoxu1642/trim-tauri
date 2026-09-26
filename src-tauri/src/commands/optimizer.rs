//! optimizer 域（D 批）：优化中心 11 条通道
//!
//! 对照 Electron main.js 2825-3875、5145-5174 + src/scripts-powershell/optimizer-scripts.js。
//!
//! 本文件第一批：list / run / check-optimized / state-overview / svc-mem-current，
//! 外加 PS 脚本生成器 build_script、动态步骤、fail-closed 记账（engine::optimization_state）。
//!
//! 关键安全/语义（OPT-1/R1/R2/OPT-3/OPT-5/B-2 全部保留）：
//! - run 恒需管理员；高危 id 需渲染层红色确认回执（正向与还原方向都卡，R2）。
//! - 还原方向必须有专属 restore 步骤，禁止回落正向步骤（R2）。
//! - 执行前先记账 pending（写不进就不改系统）；成功后回读校验再 markApplied。
//! - reg 临时文件写 TRIM_TMP 加固目录、Unicode 编码（OPT-3）；服务名/标签单引号字面量。
//! - @@RECYCLE@@ 协议：删除目标回主进程，受保护路径拒绝、其余进回收站（B-2）。
//! - WU 暂停天数服务端钳制 1~35，FILETIME 在 PS 内算（渲染层不参与）。

use std::sync::OnceLock;

use serde_json::{json, Value};
use tauri::{Emitter, Runtime, WebviewWindow};

use crate::engine::{guard, log, optimization_state as opt_state, protect, sysinfo};
// 审查 v2-F7：系统工具走绝对路径，不用裸进程名（搜索顺序前两位优先于 System32）
use crate::engine::systembin::system_tool;
use crate::pwsh;

// ==================== 选项数据（运行时完整导出，含推理 restore） ====================
const OPTIONS_JSON: &str = include_str!("../../data/optimizer-runtime.json");

/// 哨兵步骤脚本（仅用于提取与 JS buildScript 完全一致的前置 preamble 段）
const BUILD_SENTINEL: &str = include_str!("../../ps/optimizer_build.ps1");

fn options() -> &'static Vec<Value> {
    static OPTS: OnceLock<Vec<Value>> = OnceLock::new();
    OPTS.get_or_init(|| serde_json::from_str(OPTIONS_JSON).expect("optimizer-runtime.json 合法"))
}

fn find_option(id: &str) -> Option<&'static Value> {
    options().iter().find(|o| o.get("id").and_then(|v| v.as_str()) == Some(id))
}

/// OPT-1 高危清单。
/// 审查 v2-K3 后它的定位收窄为「比数据层 `risk:"high"` 更严的**例外集**」——真正的通用判据是
/// [`needs_high_risk_confirm`]。这里刻意保留手写项：有的项 risk 标的是 medium，但后果不可逆。
/// 集合差由 `tools/check-channel-map.mjs` 的门禁 F 第三条对拍钉住（Rust ⇄ JS ⇄ 数据层 risk=high）。
const HAZARD_IDS: &[&str] = &[
    "disable_uac",
    "tf_defender",
    "perf_vbs_off",
    "perf_exploit_protection_off",
    "tf_svc_bulk",
    "tf_drv_disable",
    "perf_windows_update_off",
];

/// 高危确认闸门：手写清单 **或** 数据层自认 high。
/// 只认手写清单会漏掉数据层 `risk:"high"` 的 7 项——`tf_appx`（移除 25 个内置 UWP）、
/// `tf_onedrive`（彻底卸载 OneDrive）等都是 `restoreAvailable:false` 的不可逆操作，
/// 用户在单项执行时连红色确认都不会弹（批量路径反而有闸，因为它的判据取自 `risk`）。
/// 抽成纯函数是为了能对「数据层每一项 high」都断言，而不是只断言清单里那几项。
fn needs_high_risk_confirm(opt: &Value, option_id: &str) -> bool {
    HAZARD_IDS.contains(&option_id) || opt.get("risk").and_then(|v| v.as_str()) == Some("high")
}

/// svc_mem_gb 档位表（KB）
const MEMORY_KB: &[(&str, i64)] = &[
    ("4", 4_194_304),
    ("6", 6_291_456),
    ("8", 8_388_608),
    ("12", 12_582_912),
    ("16", 16_777_216),
    ("20", 20_971_520),
    ("24", 25_165_824),
    ("32", 33_554_432),
];
const MEMORY_KB_DEFAULT: i64 = 380_000;
const WU_PAUSE_MAX_DAYS: i64 = 35;
const STORE_SERVICES: &[&str] =
    &["ClipSVC", "InstallService", "PushToInstall", "wuauserv", "DoSvc"];

// ==================== PS 脚本生成器（对照 buildScript） ====================

/// 从生成器抽取的哨兵脚本中切出 provenance 之后、`# step 1:` 之前的固定前置，
/// 与 JS buildScript 前 4 个 push（三行设置 + DIAG.PS_PREAMBLE.trim()）逐字一致。
fn build_preamble() -> &'static str {
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

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// steps JSON 数组 → PowerShell 脚本（与 JS buildScript 同口径）
fn build_script(steps: &[Value]) -> String {
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
            let safe = cmd.replace('\'', "''");
            l.push(format!("$___cmd='{safe}'"));
            l.push("& $env:ComSpec /c $___cmd *> $null".into());
            l.push(format!("if ($LASTEXITCODE -ne 0) {{ $failedSteps++; Write-TFDiag -Stage 'optimizer.cmd' -Mutation 'partial' -Detail ('step ' + ({i} + 1) + ' [' + {label_ps} + '] exit=' + $LASTEXITCODE) }}"));
        } else if let Some(service) = s.get("service").and_then(|v| v.as_str()) {
            let svc_ps = ps_quote(service);
            l.push(format!("Stop-Service -Name {svc_ps} -Force -ErrorAction SilentlyContinue"));
            if s.get("disable").and_then(|v| v.as_bool()).unwrap_or(false) {
                l.push(format!("Set-Service -Name {svc_ps} -StartupType Disabled -ErrorAction SilentlyContinue"));
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

/// 原生执行优化步骤（对应 optimizer_build.ps1 模板，S1）
///
/// 支持 reg/cmd/service 三种 step 类型；pwsh 类型交给 pssteps 解释器
/// （原生可编译 → 原生执行；白名单内不可编译 → 收件箱 PS 逐字执行，v3-K1）。
/// 实时推送 optimizer:progress 事件，返回 (failed_steps, PsInline stdout 累积)。
fn native_execute_steps<R: tauri::Runtime>(
    window: &WebviewWindow<R>,
    steps: &[Value],
    option_id: &str,
) -> Result<(i64, String), String> {
    let total = steps.len();
    let mut failed = 0i64;
    let mut inline_stdout = String::new();
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
            // reg 类型：写 .reg 临时文件 + reg.exe import
            let reg_path = tmp_dir.join(format!("wcopt_{}.reg", crate::engine::now_ms()));
            // 审查 v3-L7：非 UTF-8 路径（孤立代理项）上 to_str() 为 None，跳过该步而不是 panic
            let Some(reg_path_str) = reg_path.to_str() else { failed += 1; continue; };
            if std::fs::write(&reg_path, reg.as_bytes()).is_err() {
                failed += 1;
            } else {
                let ok = match crate::engine::systembin::quiet_cmd(system_tool("reg.exe"))
                    .args(["import", reg_path_str])
                    .output()
                {
                    Ok(o) => o.status.success(),
                    Err(_) => false,
                };
                let _ = std::fs::remove_file(&reg_path);
                if !ok { failed += 1; }
            }
        } else if let Some(cmd) = s.get("cmd").and_then(|v| v.as_str()) {
            // cmd 类型：spawn cmd /c
            let ok = match crate::engine::systembin::quiet_cmd(system_tool("cmd"))
                .args(["/c", cmd])
                .output()
            {
                Ok(o) => o.status.success(),
                Err(_) => false,
            };
            if !ok { failed += 1; }
        } else if let Some(service) = s.get("service").and_then(|v| v.as_str()) {
            // service 类型：sc stop + 可选 sc config disabled
            let _ = crate::engine::systembin::quiet_cmd(system_tool("sc")).args(["stop", service]).output();
            if s.get("disable").and_then(|v| v.as_bool()).unwrap_or(false) {
                let _ = crate::engine::systembin::quiet_cmd(system_tool("sc")).args(["config", service, "start=", "disabled"]).output();
            }
            // 检查服务是否存在
            let exists = match crate::engine::systembin::quiet_cmd(system_tool("sc")).args(["query", service]).output() {
                Ok(o) => o.status.success(),
                Err(_) => false,
            };
            if !exists { failed += 1; }
        } else if let Some(pwsh) = s.get("pwsh").and_then(|v| v.as_str()) {
            // pwsh 类型：交给解释器（v3-K1）。原生可编译 → 原生执行；白名单内
            // 不可编译 → PsInline（收件箱 Windows PowerShell 逐字执行，语义零改写）；
            // 白名单外 → Err（fail-closed，由 data_layer_coverage_report 在测试期拦）。
            match crate::engine::pssteps::compile(pwsh).and_then(|ops| crate::engine::pssteps::execute(&ops)) {
                Ok(stdout) => inline_stdout.push_str(&stdout),
                Err(reason) => {
                    return Err(format!("pwsh step 编译失败（{}）", reason));
                }
            }
        }

        // 推送进度
        let _ = window.emit(
            "optimizer:progress",
            json!({ "optionId": option_id, "percent": pct }),
        );
        let _ = label; // label 用于日志，暂不记录
    }
    Ok((failed, inline_stdout))
}

// ==================== 动态步骤 ====================

fn memory_steps(gb: &Value) -> Vec<Value> {
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

fn wu_pause_steps(days: i64) -> Vec<Value> {
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

fn svc_bulk_append_store(mut base: Vec<Value>) -> Vec<Value> {
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

fn classify_step_kinds(steps: &[Value]) -> Vec<String> {
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

// ==================== .reg 块解析与回读检测 ====================

/// `.reg` 根键 → native hive 句柄（B11：检测不再经 PS，需要真实 hive）
fn reg_hive(root: &str) -> Option<windows::Win32::System::Registry::HKEY> {
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
struct Check {
    kind: &'static str, // "reg" | "svc"
    // reg（B11：检测改原生，直接带 hive + 子键，不再经 PS 路径字符串）
    hive: windows::Win32::System::Registry::HKEY,
    subkey: String,
    key: String,
    is_dword: bool,
    data: String,
    // svc
    name: String,
}

/// 解析一个 .reg 值的期望数据（dword:hex→十进制 / 引号串 / 原串）
fn parse_reg_expected(raw: &str) -> Option<(bool, String)> {
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
fn collect_checks(opt: &Value) -> Vec<Check> {
    let mut checks = Vec::new();
    let steps = opt.get("steps").and_then(|v| v.as_array());
    let Some(steps) = steps else { return checks };
    for s in steps {
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
    }
    checks
}

/// 切分 .reg 文本为 (段全名, 段内文本) 列表。
/// 段行为 `[xxx]`（trim 后首尾方括号），值体到下一段或末尾。
fn parse_reg_sections(block: &str) -> Vec<(String, String)> {
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
fn parse_reg_value_lines(body: &str) -> Vec<(String, String)> {
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
fn check_optimized(ids: &[String]) -> std::collections::HashMap<String, bool> {
    use crate::engine::native;
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
        let all_ok = !checks.is_empty()
            && checks.iter().all(|c| {
                if c.kind == "svc" {
                    native::service_start_type_is(&c.name, native::SVC_START_DISABLED)
                } else if c.is_dword {
                    match c.data.parse::<i64>() {
                        Ok(want) => native::read_reg_dword_opt(c.hive, &c.subkey, &c.key) == Some(want),
                        Err(_) => false,
                    }
                } else {
                    native::read_reg_string(c.hive, &c.subkey, &c.key).as_deref() == Some(c.data.as_str())
                }
            });
        result.insert(id.clone(), all_ok);
    }
    result
}

// ==================== IPC ====================

/// optimizer:list —— 完整选项目录（含 steps/restore）
#[tauri::command]
pub async fn optimizer_list<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    json!({ "success": true, "data": options().as_slice() })
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

/// optimizer:state-overview —— 记账清单 + stale 判定 + detected
#[tauri::command]
pub async fn optimizer_state_overview<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let raw = opt_state::all();
    let mut items: Vec<Value> = Vec::new();
    let mut pending_ids: Vec<String> = Vec::new();
    let mut check_ids: Vec<String> = Vec::new();

    for (id, rec) in &raw {
        let opt = find_option(id);
        let is_dynamic = opt.and_then(|o| o.get("dynamic")).and_then(|v| v.as_bool()).unwrap_or(false);
        if is_dynamic {
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
            "checkable": checkable
        }));
        match rec.get("status").and_then(|v| v.as_str()) {
            Some("pending") => pending_ids.push(id.clone()),
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

    json!({
        "success": true,
        "items": items,
        "staleIds": stale_ids,
        // 审查 v2-M14：**这是未移植的空桩**，不是"本轮没有需要还原的退役项"。
        // Electron 轨靠 `version-migrations.js` 的 `runMigrations` 在启动时把已退役优化项
        // （`src-tauri/data/retired-optimizations.json` 的 13 项）按 `optimizer-backups.json`
        // 里的原值自动还原并清账；本轨 `grep retired` 实测 0 命中，所以从旧轨带来的备份记录
        // 里属于退役项的那批**永不还原**、也无日志。字段留着是为了契约不破（渲染层按此弹 toast），
        // 一旦移植就必须填真数据，别把空数组当"已实现"。彻底改法见审查报告 v2-M14。
        "migration": { "restored": [], "failed": [] },
        "detected": Value::Object(opt_state::detected_all())
    })
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
#[tauri::command]
pub async fn optimizer_run<R: Runtime>(
    window: WebviewWindow<R>,
    option_id: Option<String>,
    params: Option<RunParams>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let option_id = option_id.unwrap_or_default();
    let Some(opt) = find_option(&option_id) else {
        return json!({ "success": false, "message": "未知的优化选项" });
    };
    let p = params.unwrap_or_default();

    if !sysinfo::is_admin() {
        return json!({
            "success": false, "needAdmin": true,
            "message": "优化操作需要管理员权限，请先提权"
        });
    }
    if needs_high_risk_confirm(&opt, &option_id) && !p.confirmed_high_risk {
        log::write_log(
            "warn",
            &format!("高危优化缺少确认回执，已拒绝: {option_id} (restore={})", p.restore),
        );
        return json!({
            "success": false, "needConfirm": true,
            "message": "高危操作缺少红色确认回执，请在界面重新确认后执行"
        });
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
    let run: Result<pwsh::PsOutput, String> = match native_execute_steps(&window, &steps, &option_id) {
        Ok((failed_steps, inline_stdout)) => {
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
            Ok(pwsh::PsOutput { code, stdout, stderr: String::new(), timed_out: false })
        }
        Err(e) => Err(format!("原生执行失败: {e}")),
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
    let ok_message = if !ok {
        "部分步骤可能失败".to_string()
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
            let _ = opt_state::remove(&option_id);
            let _ = opt_state::set_detected_entry(&option_id, false);
            return json!({ "success": true, "message": ok_message, "verify": verify });
        }
    } else if ok {
        let verify = verify_applied(&option_id, opt, &p);
        if verify == "partial" {
            log::write_log("warn", &format!("执行后回读校验不符（可能被组策略/安全软件覆盖）: {title}"));
        }
        let _ = opt_state::mark_applied(&option_id, verify);
        if verify != "unknown" {
            let _ = opt_state::set_detected_entry(&option_id, verify == "pass");
        }
        return json!({ "success": true, "message": ok_message, "verify": verify });
    } else {
        let _ = opt_state::mark_applied(&option_id, "unknown");
    }

    json!({ "success": ok, "message": ok_message })
}

/// 正向执行后回读：动态 svc_mem_gb 比对档位；可检测项走 check_optimized；否则 unknown
fn verify_applied(option_id: &str, opt: &Value, p: &RunParams) -> &'static str {
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
fn verify_option_restored(option_id: &str, opt: &Value) -> &'static str {
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
fn read_values_by_backup(want: &[Value]) -> Option<Vec<Value>> {
    use crate::engine::native;
    let mut out = Vec::with_capacity(want.len());
    for v in want {
        let hive = v.get("hive").and_then(|x| x.as_str()).unwrap_or("LocalMachine");
        let sub = v.get("sub").and_then(|x| x.as_str()).unwrap_or("");
        let key = v.get("key").and_then(|x| x.as_str()).unwrap_or("");
        let Some(h) = restore_hive(hive) else { return None };
        let mut item = json!({ "hive": hive, "sub": sub, "key": key, "exists": false });
        if let Some((ty, data)) = native::read_reg_value_text(h, sub, key) {
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
fn svc_mem_current_kb() -> Option<i64> {
    crate::engine::native::read_hklm_dword(
        r"SYSTEM\ControlSet001\Control",
        "SvcHostSplitThresholdInKB",
    )
}

// ==================== 值级注册表备份与还原 ====================

fn opt_backup_file() -> std::path::PathBuf {
    crate::engine::paths::app_data_dir().join("optimizer-backups.json")
}

fn load_opt_backups() -> Value {
    let v = crate::security::read_json_or_quarantine(&opt_backup_file());
    if v.is_object() {
        v
    } else {
        json!({})
    }
}

fn save_opt_backups(map: &Value) -> bool {
    match crate::security::atomic_write_json(&opt_backup_file(), map) {
        Ok(()) => true,
        Err(e) => {
            log::write_log("error", &format!("写入优化备份失败: {e}"));
            false
        }
    }
}

/// .reg 根键 → [Microsoft.Win32.Registry] 静态属性名（Read-One 用）
fn dotnet_hive(root: &str) -> &'static str {
    match root {
        "HKEY_CURRENT_USER" => "CurrentUser",
        "HKEY_CLASSES_ROOT" => "ClassesRoot",
        "HKEY_USERS" => "Users",
        "HKEY_CURRENT_CONFIG" => "CurrentConfig",
        _ => "LocalMachine",
    }
}

#[derive(Clone)]
struct RegTarget {
    root: String, // HKEY_* 全称
    sub: String,
    key: String,
}

fn parse_reg_targets(block: &str) -> Vec<RegTarget> {
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
/// 再解析 stdout 里的 JSON —— 就为了读几个注册表值。现在直接走注册表 API，
/// 字符串化口径逐条对齐原 `READ_ONE_HEADER`（见 `native::read_reg_value_text`），
/// 保证「备份 → 还原」两侧对同一值的表述完全一致。
///
/// 输出形状与旧 PS 逐字段一致：`exists=false` 时**不带** `type`/`data` 键
/// （旧 `ConvertTo-Json` 也不会输出它们），下游 `build_restore_ops` 据此走删除分支。
fn read_reg_values(targets: &[RegTarget]) -> Option<Vec<Value>> {
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
        if let Some((ty, data)) = native::read_reg_value_text(hive, &t.sub, &t.key) {
            item["exists"] = json!(true);
            item["type"] = json!(ty);
            item["data"] = json!(data);
        }
        out.push(item);
    }
    Some(out)
}

fn option_targets(option_id: &str) -> Option<Vec<RegTarget>> {
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
    }
    // 去重（root\sub::key）
    let mut seen = std::collections::HashSet::new();
    targets.retain(|t| seen.insert(format!("{}\\{}::{}", t.root, t.sub, t.key)));
    Some(targets)
}

/// [`insert_backup_baseline`] 的三种结果，第三态携带**已存在基线**的项数。
#[derive(Debug)]
enum BackupInsert {
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
fn insert_backup_baseline(map: &mut Value, option_id: &str, values: Vec<Value>) -> BackupInsert {
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
    if find_option(&option_id).is_none() {
        return json!({ "success": false, "message": "未知的优化选项" });
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

    if !restore_backup_values(&values) {
        return json!({ "success": false, "message": "还原脚本执行失败" });
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
enum RestoreOp {
    /// 回写值：data 已编码为 API 就绪字节
    Write { hive: String, sub: String, key: String, typ: String, bytes: Vec<u8> },
    /// 删除值（不存在 = 幂等成功）
    Delete { hive: String, sub: String, key: String },
}

/// dotnet hive 名 → native hive
fn restore_hive(name: &str) -> Option<windows::Win32::System::Registry::HKEY> {
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
/// 编码口径**逐条对齐**读值侧 `READ_ONE_HEADER`（main.js 3481-3502 的移植）：
/// - `REG_DWORD` → `[string]([int]$v)`，是**有符号 i32** 的十进制串；
///   还原时按 i32 解析再按 u32 写回，`0xFFFFFFFF` 才能原样往返。
/// - `REG_QWORD` → `[string]([long]$v)`，i64 十进制。
/// - `REG_BINARY` → 小写 hex 连写（无分隔符）。
/// - 其余一律按 REG_SZ。
///
/// 返回 `Err` = 备份数据畸形（非法十进制 / 奇数位或非 hex 的 BINARY）。
/// 刻意**fail-closed 而不是像旧 PS 那样把非 hex 字符剥掉**：这是还原路径，
/// 静默剥字符可能把错的数据写回去还报成功；备份是我们自己生成的，畸形即文件损坏。
fn restore_write_bytes(typ: &str, data: &str) -> Result<Vec<u8>, String> {
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
fn build_restore_ops(values: &[Value]) -> Result<Vec<RestoreOp>, String> {
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

/// 按备份条目回写（任一失败即返回 false；调用方据此报「还原不完整」）
fn restore_backup_values(values: &[Value]) -> bool {
    use crate::engine::native;
    let Ok(ops) = build_restore_ops(values) else {
        return false;
    };
    let mut failed = 0usize;
    for op in ops {
        let ok = match op {
            RestoreOp::Write { hive, sub, key, typ, bytes } => {
                use windows::Win32::System::Registry::{REG_BINARY, REG_DWORD, REG_QWORD, REG_SZ};
                let Some(h) = restore_hive(&hive) else {
                    failed += 1;
                    continue;
                };
                let kind = match typ.as_str() {
                    "REG_DWORD" => REG_DWORD,
                    "REG_QWORD" => REG_QWORD,
                    "REG_BINARY" => REG_BINARY,
                    _ => REG_SZ,
                };
                native::reg_restore_write(h, &sub, &key, kind, &bytes)
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

// ==================== 系统还原点 ====================

/// 解析 WMI DMTF（yyyymmddHHMMSS.mmmmmm±UUU）。SR-5：偏移 000 按本地时间构造。
fn parse_dmtf(raw: &str) -> Option<String> {
    let s = raw.trim();
    // yyyy mm dd HH MM SS . mmmmmm ± UUU
    if s.len() != 25 || s.as_bytes()[14] != b'.' {
        return None;
    }
    let b = |a: usize, z: usize| -> Option<i64> { s[a..z].parse().ok() };
    let (y, mo, d, hh, mi, ss) = (
        b(0, 4)?,
        b(4, 6)?,
        b(6, 8)?,
        b(8, 10)?,
        b(10, 12)?,
        b(12, 14)?,
    );
    let sign = s.as_bytes()[21] as char;
    let off: i64 = s[22..25].parse().ok()?;
    let offset_minutes = if sign == '-' { -off } else { off };

    // 本地墙钟（公历分量）→ unix ms
    let local_ms = civil_to_ms(y, mo as u32, d as u32, hh, mi, ss);
    let utc_ms = if offset_minutes == 0 {
        // DMTF ±000 = 本地时间、时区未知：用系统 Bias 换算（UTC = 本地 + Bias）
        local_ms + local_tz_bias_minutes() * 60_000
    } else {
        local_ms - offset_minutes * 60_000
    };
    Some(ms_to_iso(utc_ms))
}

/// Windows 本地时区 Bias（分钟；UTC = 本地 + Bias）
fn local_tz_bias_minutes() -> i64 {
    use windows::Win32::System::Time::GetTimeZoneInformation;
    unsafe {
        let mut tz = windows::Win32::System::Time::TIME_ZONE_INFORMATION::default();
        // 返回 TIME_ZONE_ID_*(0/1/2)；0xFFFFFFFF 才是失败。ID_UNKNOWN(0) 时 Bias 仍有效。
        if GetTimeZoneInformation(&mut tz) != u32::MAX {
            tz.Bias as i64
        } else {
            0
        }
    }
}

fn civil_to_ms(y: i64, mo: u32, d: u32, hh: i64, mi: i64, ss: i64) -> i64 {
    let days = days_from_civil(y, mo, d);
    days * 86_400_000 + (hh * 3600 + mi * 60 + ss) * 1000
}

/// Howard Hinnant 公历年月日 → 1970 前天数
fn days_from_civil(y_in: i64, m_in: u32, d: u32) -> i64 {
    let y = if m_in <= 2 { y_in - 1 } else { y_in };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m_in > 2 { m_in as i64 - 3 } else { m_in as i64 + 9 };
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn ms_to_iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let milli = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // days_from_civil 的逆（复用 delete_manifest 同源算法）：借用 civil_from_days
    let (y, m, d) = civil_from_days_pub(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milli:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days_pub(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

fn run_inline_ps(ps: &str, timeout_secs: u64, _diag: Option<&str>) -> Option<crate::pwsh::PsOutput> {
    // v3-K1：还原点查询属 WMI 面，交给收件箱 Windows PowerShell（System32 自带），
    // 优化中心从此不再依赖用户安装 PowerShell 7
    let path = pwsh::write_temp_script(ps, ".ps1").ok()?;
    let out = crate::pwsh::run_inbox_ps(&path, std::time::Duration::from_secs(timeout_secs));
    let _ = std::fs::remove_file(&path);
    out.ok()
}

/// optimizer:check-restore —— 最近一次还原点（三态错误码）
#[tauri::command]
pub async fn optimizer_check_restore<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "exists": false, "message": msg });
    }
    let ps = "$ErrorActionPreference = \"Stop\"\n\
try {\n\
  $rp = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 1\n\
  if ($rp) { Write-Output (\"RPEXISTS|\" + $rp.CreationTime) } else { Write-Output \"RPNONE\" }\n\
} catch {\n\
  Write-Output (\"RPERROR|\" + $_.Exception.Message)\n\
}";
    let Some(out) = run_inline_ps(ps, 30, None) else {
        return json!({ "success": false, "exists": false, "message": "查询失败" });
    };
    let line = out
        .stdout
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("RPEXISTS|") || *l == "RPNONE" || l.starts_with("RPERROR|"));
    match line {
        Some(l) if l.starts_with("RPEXISTS|") => {
            let raw = &l["RPEXISTS|".len()..];
            match parse_dmtf(raw) {
                Some(created) => json!({ "success": true, "exists": true, "created": created }),
                None => {
                    log::write_log("warn", &format!("还原点时间解析失败: {raw}"));
                    json!({ "success": false, "exists": false, "message": "还原点时间解析失败" })
                }
            }
        }
        Some(l) if l.starts_with("RPERROR|") => {
            let msg = &l["RPERROR|".len()..];
            log::write_log("warn", &format!("还原点查询失败: {msg}"));
            json!({ "success": false, "exists": false, "message": msg })
        }
        Some(_) => json!({ "success": true, "exists": false }), // RPNONE
        None => json!({ "success": false, "exists": false, "message": "查询无有效输出" }),
    }
}

fn count_restore_points() -> Option<i64> {
    let ps = "$ErrorActionPreference = \"Stop\"\n\
try {\n\
  $rp = @(Get-ComputerRestorePoint)\n\
  Write-Output (\"RPCOUNT|\" + $rp.Count)\n\
} catch {\n\
  Write-Output (\"RPERROR|\" + $_.Exception.Message)\n\
}";
    let out = run_inline_ps(ps, 30, None)?;
    out.stdout
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("RPCOUNT|")?.trim().parse::<i64>().ok())
}

static RESTORE_INFLIGHT: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

/// optimizer:create-restore —— 创建系统还原点（预检 + 记账 + 创建后回读数量增长）
#[tauri::command]
pub async fn optimizer_create_restore<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    if !sysinfo::is_admin() {
        return json!({
            "success": false, "needAdmin": true,
            "message": "创建系统还原点需要管理员权限，请先提权"
        });
    }
    let mut guard_inflight = RESTORE_INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
    if *guard_inflight {
        return json!({ "success": false, "message": "正在创建还原点，请勿重复提交" });
    }
    *guard_inflight = true;
    let result = create_restore_inner();
    *RESTORE_INFLIGHT.lock().unwrap_or_else(|e| e.into_inner()) = false;
    result
}

fn create_restore_inner() -> Value {
    let Some(opt) = find_option("tf_restore_point") else {
        return json!({ "success": false, "message": "缺少还原点脚本" });
    };
    let steps = opt.get("steps").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if steps.is_empty() {
        return json!({ "success": false, "message": "缺少还原点脚本" });
    }

    // 预检：系统保护全局开关 + 受保护卷
    let pre = "$ErrorActionPreference = \"SilentlyContinue\"\n\
$srKey = Get-ItemProperty \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\"\n\
$gd = ($srKey -and $null -ne $srKey.DisableSR -and [int]$srKey.DisableSR -eq 1)\n\
$vol = @(Get-CimInstance Win32_ShadowStorage -ErrorAction SilentlyContinue)\n\
Write-Output ('@@SRPRE@@' + ({ globalDisabled = $gd; protectedVolumes = $vol.Count } | ConvertTo-Json -Compress))";
    if let Some(out) = run_inline_ps(pre, 20, None) {
        if let Some(line) = out.stdout.lines().map(str::trim).find(|l| l.starts_with("@@SRPRE@@")) {
            if let Ok(v) = serde_json::from_str::<Value>(&line["@@SRPRE@@".len()..]) {
                if v.get("globalDisabled").and_then(|x| x.as_bool()).unwrap_or(false) {
                    return json!({ "success": false, "message": "系统保护已被全局关闭（DisableSR=1），请先在「系统 → 关于 → 系统保护」中开启后再创建还原点" });
                }
                if v.get("protectedVolumes").and_then(|x| x.as_i64()).unwrap_or(0) == 0 {
                    return json!({ "success": false, "message": "没有任何卷开启系统保护，请先在「系统 → 关于 → 系统保护」中为系统盘开启保护" });
                }
            }
        }
    }

    // 频率覆写值级备份 + 记账（失败仅 warn，不阻断）
    let targets = option_targets("tf_restore_point").unwrap_or_default();
    if !targets.is_empty() {
        match read_reg_values(&targets) {
            Some(values) => {
                let mut map = load_opt_backups();
                // v2-M9：这条也走「首份不覆盖」——同一项重复应用时不得把基线刷成已优化值
                let inserted =
                    matches!(insert_backup_baseline(&mut map, "tf_restore_point", values), BackupInsert::Inserted);
                if !inserted {
                    log::write_log("warn", "还原点频率覆写值级备份未写入（基线已存在或结构异常）");
                } else if !save_opt_backups(&map) {
                    log::write_log("warn", "还原点频率覆写值级备份失败");
                }
            }
            None => {
                log::write_log("warn", "还原点频率覆写值级备份失败");
            }
        }
    }
    let title = opt.get("title").and_then(|v| v.as_str()).unwrap_or("tf_restore_point");
    let _ = opt_state::record_pending(
        "tf_restore_point",
        title,
        &classify_step_kinds(&steps),
    );

    let before = count_restore_points();
    let script = build_script(&steps);
    let Some(out) = run_inline_ps(&script, 120, Some("optimizer.create-restore")) else {
        let _ = opt_state::remove("tf_restore_point");
        return json!({ "success": false, "message": "创建还原点执行异常" });
    };
    let failed_steps = out
        .stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("@@FAILED:").and_then(|x| x.strip_suffix("@@")))
        .and_then(|x| x.parse::<i64>().ok())
        .unwrap_or(0);
    let ok = out.code == 0 && out.stdout.contains("@@DONE@@") && failed_steps == 0;
    if ok {
        let _ = opt_state::mark_applied("tf_restore_point", "pass");
    } else {
        let _ = opt_state::remove("tf_restore_point");
        log::write_log("warn", &format!("创建系统还原点未成功: code={} failedSteps={failed_steps}", out.code));
        return json!({ "success": false, "message": "系统还原点创建失败，请手动创建（需管理员权限，且至少一个卷已开启系统保护）" });
    }

    // 回读：数量必须增长（轮询 ≤15s，每 1.5s）
    let mut last = before;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        match count_restore_points() {
            Some(n) => {
                last = Some(n);
                if let Some(b) = before {
                    if n > b {
                        break;
                    }
                } else {
                    break;
                }
            }
            None => break,
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
    }
    if let (Some(b), Some(a)) = (before, last) {
        if a <= b {
            log::write_log("warn", &format!("创建还原点回读未增长: {b} -> {a}"));
            return json!({ "success": false, "message": "未检测到新还原点，创建可能被系统限制或仍在进行，请稍后在「系统还原点管理」核对" });
        }
    }
    let btxt = before.map(|b| b.to_string()).unwrap_or_else(|| "?".into());
    let atxt = last.map(|a| a.to_string()).unwrap_or_else(|| "?".into());
    log::write_log("info", &format!("已创建系统还原点 ({btxt} -> {atxt})"));
    json!({ "success": true, "message": "已创建系统还原点" })
}

/// optimizer:list-restore —— 还原点列表 + 各卷保护状态
#[tauri::command]
pub async fn optimizer_list_restore<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let ps = "$ErrorActionPreference = \"Stop\"\n\
$out = @{}\n\
try {\n\
  $rps = @(Get-ComputerRestorePoint)\n\
  $out.restorePoints = @($rps | Sort-Object CreationTime -Descending | ForEach-Object {\n\
    [pscustomobject]@{\n\
      seq = $_.SequenceNumber;\n\
      desc = $_.Description;\n\
      created = $_.CreationTime;\n\
      type = $_.RestorePointType\n\
    }\n\
  })\n\
} catch {\n\
  Write-Output (\"RPFAIL|\" + $_.Exception.Message)\n\
  exit 0\n\
}\n\
$globalDisable = 0\n\
$srKey = Get-ItemProperty \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" -ErrorAction SilentlyContinue\n\
if ($srKey -and $null -ne $srKey.DisableSR) { $globalDisable = [int]$srKey.DisableSR }\n\
$out.globalDisabled = ($globalDisable -eq 1)\n\
$vols = @{}\n\
Get-CimInstance Win32_Volume -ErrorAction SilentlyContinue | ForEach-Object { $vols[$_.DeviceID] = $_.DriveLetter }\n\
$out.protection = @(Get-CimInstance Win32_ShadowStorage -ErrorAction SilentlyContinue | ForEach-Object {\n\
  $dev = $_.Volume.DeviceID\n\
  $dl = $vols[$dev]\n\
  if (-not $dl) { return }\n\
  [pscustomobject]@{ drive = $dl; allocated = [double]$_.AllocatedSpace }\n\
})\n\
Write-Output ('@@RESTORE@@' + ($out | ConvertTo-Json -Depth 4 -Compress))";
    let Some(out) = run_inline_ps(ps, 30, None) else {
        return json!({ "success": false, "message": "查询异常" });
    };
    if let Some(fail) = out.stdout.lines().map(str::trim).find(|l| l.starts_with("RPFAIL|")) {
        let msg = &fail["RPFAIL|".len()..];
        log::write_log("warn", &format!("列出还原点失败: {msg}"));
        return json!({ "success": false, "message": msg });
    }
    let res_line = out
        .stdout
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("@@RESTORE@@"));
    let Some(line) = res_line else {
        return json!({ "success": false, "message": "无法解析还原点数据" });
    };
    let Ok(mut data) = serde_json::from_str::<Value>(&line["@@RESTORE@@".len()..]) else {
        return json!({ "success": false, "message": "无法解析还原点数据" });
    };
    if let Some(points) = data.get_mut("restorePoints").and_then(|v| v.as_array_mut()) {
        for rp in points.iter_mut() {
            let created = rp
                .get("created")
                .and_then(|v| v.as_str())
                .and_then(parse_dmtf)
                .unwrap_or_default();
            if let Some(o) = rp.as_object_mut() {
                o.insert("created".into(), json!(created));
            }
        }
    }
    json!({ "success": true, "data": data })
}

// ==================== AI 优缺点生成（optimizer:genadvice） ====================

const ADVICE_SYSTEM: &str = "你是专业的 Windows 系统优化助手。请用简洁客观的中文，针对给定优化项分别说明优点与缺点，语言精炼、不说空话和营销话术，不要输出思考过程，只输出最终结果。";

/// optimizer:genadvice —— 按作用域首选模型生成优缺点，失败按已启用模型依次尝试
#[tauri::command]
pub async fn optimizer_genadvice<R: Runtime>(
    window: WebviewWindow<R>,
    option_id: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let option_id = option_id.unwrap_or_default();
    let Some(opt) = find_option(&option_id) else {
        return json!({ "success": false, "message": "未知的优化选项" });
    };
    let title = opt.get("title").and_then(|v| v.as_str()).unwrap_or(&option_id);
    let desc = opt.get("desc").and_then(|v| v.as_str()).unwrap_or("");

    let models = crate::commands::settings::models_config();
    let scopes = crate::commands::settings::scope_engines();
    let preferred = scopes
        .get("optimizer")
        .and_then(|v| v.as_str())
        .unwrap_or("metaso")
        .to_string();

    // [首选] + 其余已启用模型，保序去重
    let keys = crate::commands::settings::AI_MODEL_KEYS;
    let mut order: Vec<&str> = Vec::new();
    order.push(preferred.as_str());
    for k in keys {
        if *k != preferred.as_str() {
            order.push(k);
        }
    }
    order.retain(|k| {
        models
            .get(k)
            .and_then(|c| c.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    });
    if order.is_empty() {
        return json!({
            "success": false,
            "message": "当前没有已启用的模型，请在「设置 - 大模型管理」中启用并保存至少一个模型"
        });
    }

    let query = format!(
        "优化项名称：{title}\n优化项说明：{desc}\n\
请分别给出该优化项的「优点」和「缺点」，各用一到三句话，并严格按下面两行格式输出：\n\
优点：...\n缺点：..."
    );
    let message = format!("{ADVICE_SYSTEM}\n{query}");

    let mut text: Option<String> = None;
    let mut used_engine = "";
    for eng in order {
        if let Some(cfg) = models.get(eng) {
            if let Some(t) = crate::commands::aidesc::call_model_text(eng, cfg, &message) {
                if !t.trim().is_empty() {
                    text = Some(t);
                    used_engine = eng;
                    break;
                }
            }
        }
    }
    let Some(text) = text else {
        log::write_log("warn", &format!("优化项优缺点生成失败: {title}"));
        return json!({
            "success": false,
            "message": "所选模型未返回结果，请在「设置 - 大模型管理」中检查地址、密钥与模型名称（或确认网络）"
        });
    };

    let (pros, cons) = parse_pros_cons(&text);
    let cfg = models.get(used_engine);
    let source = crate::commands::settings::model_display_name(used_engine, cfg);
    log::write_log("info", &format!("优化项优缺点生成成功 ({source}): {title}"));
    json!({ "success": true, "data": { "pros": pros, "cons": cons, "raw": text, "source": source } })
}

/// 解析「优点：…/缺点：…」两行格式（对照 parseProsCons）
fn parse_pros_cons(text: &str) -> (String, String) {
    let t = text.replace("\r\n", "\n");
    let t = t.trim();

    let content_after_label = |label: &str, search_from: usize| -> Option<usize> {
        let idx = t[search_from..].find(label)? + search_from;
        let mut it = t[idx + label.len()..].char_indices();
        let (_, c) = it.next()?;
        if c != ':' && c != '：' {
            return None;
        }
        Some(idx + label.len() + c.len_utf8())
    };

    let pros_start = content_after_label("优点", 0);
    // 缺点标签需在行首（允许前导空白），与 JS 前瞻 `\n\s*缺点` 同口径
    let cons_label = {
        let mut found = None;
        if let Some(ps) = pros_start {
            let tail = &t[ps..];
            if let Some(rel) = tail.find("\n") {
                let mut from = ps + rel;
                while from < t.len() {
                    let rest = &t[from..];
                    let trimmed = rest.trim_start_matches([' ', '\t', '\n']);
                    let skipped = rest.len() - trimmed.len();
                    if trimmed.starts_with("缺点") {
                        let label_abs = from + skipped;
                        if let Some(cs) = content_after_label("缺点", label_abs) {
                            found = Some((label_abs, cs));
                            break;
                        }
                    }
                    // 继续找下一个换行
                    match t[from + 1..].find('\n') {
                        Some(rel) => from = from + 1 + rel,
                        None => break,
                    }
                }
            }
        }
        found
    };

    let clean = |s: &str| -> String {
        s.trim()
            .trim_matches([' ', '\t', '\n', '-', '—', '*', '·'])
            .trim()
            .to_string()
    };

    match (pros_start, cons_label) {
        (Some(ps), Some((cl, cs))) => {
            let pros = clean(&t[ps..cl]);
            let cons = clean(&t[cs..]);
            if pros.is_empty() && cons.is_empty() {
                (t.to_string(), String::new())
            } else {
                (pros, cons)
            }
        }
        _ => (t.to_string(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_expected_dword_and_string() {
        assert_eq!(parse_reg_expected("dword:00000001"), Some((true, "1".to_string())));
        assert_eq!(parse_reg_expected("dword:0000000a"), Some((true, "10".to_string())));
        assert_eq!(parse_reg_expected("\"hello\""), Some((false, "hello".to_string())));
        assert_eq!(parse_reg_expected("foo"), Some((false, "foo".to_string())));
    }

    #[test]
    fn reg_sections_and_value_lines() {
        let block = "Windows Registry Editor Version 5.00\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SOFTWARE\\A]\r\n\
\"X\"=dword:00000001\r\n\
\"Y\"=-\r\n\r\n\
[HKEY_CURRENT_USER\\SOFTWARE\\B]\r\n\
\"Z\"=\"v\"\r\n";
        let secs = parse_reg_sections(block);
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0].0, "HKEY_LOCAL_MACHINE\\SOFTWARE\\A");
        let a_lines = parse_reg_value_lines(&secs[0].1);
        assert!(a_lines.iter().any(|(k, _)| k == "X"));
        // 删除占位 Y 由调用方跳过，解析层仍可见
        assert!(a_lines.iter().any(|(k, r)| k == "Y" && r == "-"));
        assert_eq!(secs[1].0, "HKEY_CURRENT_USER\\SOFTWARE\\B");
    }

    #[test]
    fn memory_steps_table_and_fallback() {
        let cmd_of = |gb: Value| {
            let s = memory_steps(&gb);
            s[0].get("cmd").and_then(|v| v.as_str()).unwrap_or_default().to_string()
        };
        assert!(cmd_of(json!("default")).contains(&MEMORY_KB_DEFAULT.to_string()));
        assert!(cmd_of(json!("8")).contains("8388608"));
        // 异常档位回退 8GB 阈值，且文案如实标注
        let steps = memory_steps(&json!(99));
        assert!(steps[0].get("cmd").unwrap().as_str().unwrap().contains("8388608"));
        assert!(steps[0].get("label").unwrap().as_str().unwrap().contains("回退"));
    }

    #[test]
    fn wu_pause_clamps_days() {
        for (input, want) in [(0i64, 1i64), (7, 7), (99, 35)] {
            let s = wu_pause_steps(input);
            let pwsh = s[0].get("pwsh").and_then(|v| v.as_str()).unwrap_or_default();
            assert!(pwsh.contains(&format!("$days = {want}")), "input={input}");
        }
    }

    #[test]
    fn dmtf_offset_converts_to_utc() {
        // 12:30 本地、东八区(+480) → 04:30 UTC
        let iso = parse_dmtf("20260924123000.000000+480").expect("parse");
        assert_eq!(iso, "2026-09-24T04:30:00.000Z");
        assert!(parse_dmtf("garbage").is_none());
        assert!(parse_dmtf("20260924123000.000+480").is_none());
    }

    #[test]
    fn build_script_emits_protocol_and_uses_tmp_dir() {
        let steps = vec![
            json!({ "label": "c", "cmd": "echo hi" }),
            json!({ "label": "r", "reg": "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\X]\r\n\"K\"=dword:00000001\r\n" }),
            json!({ "label": "s", "service": "SvcX", "disable": true }),
        ];
        let ps = build_script(&steps);
        assert!(ps.contains("Write-TFDiag")); // preamble 从哨兵脚本切出
        assert!(ps.contains("@@DONE@@"));
        assert!(ps.contains("@@FAILED:"));
        assert!(ps.contains("@@PROGRESS:100@@"));
        assert!(ps.contains("TRIM_TMP")); // OPT-3/A1：reg 临时文件加固目录
        assert!(ps.contains("-Encoding Unicode")); // OPT-3
        assert!(ps.contains("Stop-Service -Name 'SvcX'"));
        // 标签单引号被安全包裹
        assert!(ps.contains("'c'"));
    }

    #[test]
    fn pros_cons_parse_and_fallback() {
        let (p, c) = parse_pros_cons("优点：提升速度\n缺点：增加耗电");
        assert_eq!(p, "提升速度");
        assert_eq!(c, "增加耗电");
        let (p2, c2) = parse_pros_cons("无格式文本");
        assert_eq!(p2, "无格式文本");
        assert_eq!(c2, "");
    }

    #[test]
    fn runtime_options_load() {
        assert!(options().len() >= 100);
        assert!(find_option("tf_defender").is_some());
        assert!(find_option("not_exist").is_none());
        // 78 项带还原步骤
        assert!(options().iter().filter(|o| {
            o.get("restore").and_then(|v| v.as_array()).is_some_and(|a| !a.is_empty())
        }).count() >= 70);
    }

    /// v2-K2（B11 重写）：还原方向原先生成「交给 pwsh 执行的脚本正文」，不可信值必须锁在
    /// 单引号串里。**现在不再有任何 shell**，攻击面从「值会被求值」变成「值被当成什么」——
    /// 断言改为钉「不可信值逐字节原样进编码结果，不做任何解释/求值/剥除」。
    #[test]
    fn restore_ops_keep_untrusted_values_verbatim() {
        let payload = "A$(whoami)`id`\"B'c";
        let ops = build_restore_ops(&[json!({
            "hive": "CurrentUser", "sub": "Software\\X", "key": "Y",
            "exists": true, "type": "REG_SZ", "data": payload
        })])
        .expect("合法条目不应报畸形");
        let [RestoreOp::Write { ref key, ref bytes, .. }] = ops[..] else {
            panic!("应为一条 Write: {ops:?}");
        };
        assert_eq!(key, "Y");
        // 期望字节 = UTF-16LE(含 NUL)；关键字段是「没有任何字符被吃掉或改写」
        let mut want: Vec<u8> = payload.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
        want.extend_from_slice(&[0, 0]);
        assert_eq!(bytes, &want, "REG_SZ 数据被改写 ⇒ 注入防护已退化为碰运气");

        // hive/sub/key 同样只是数据，不是代码
        let ops = build_restore_ops(&[json!({
            "hive": "LocalMachine", "sub": "S", "key": "K'$(p)", "exists": false
        })])
        .unwrap();
        assert_eq!(
            ops,
            vec![RestoreOp::Delete { hive: "LocalMachine".into(), sub: "S".into(), key: "K'$(p)".into() }]
        );
    }

    /// B11：畸形备份值必须 **fail-closed**（整批拒绝），而不是像旧 PS 版那样把
    /// 非 hex 字符剥掉再写 —— 还原路径上「写错数据还报成功」比「报失败」更糟。
    #[test]
    fn restore_rejects_malformed_backup_data() {
        // BINARY：旧测试喂 `41;42`$(x)43\n` 并断言剥成 `414243`；现在必须整体拒绝
        for bad in ["41;42`$(x)43\n", "4", "zz", "4142g"] {
            assert!(
                build_restore_ops(&[json!({
                    "hive": "LocalMachine", "sub": "S", "key": "K",
                    "exists": true, "type": "REG_BINARY", "data": bad
                })])
                .is_err(),
                "畸形 REG_BINARY 应拒绝: {bad:?}"
            );
        }
        // DWORD / QWORD：非十进制整数同样拒绝
        for bad in ["abc", "", "1.5"] {
            assert!(
                build_restore_ops(&[json!({
                    "hive": "LocalMachine", "sub": "S", "key": "K",
                    "exists": true, "type": "REG_DWORD", "data": bad
                })])
                .is_err(),
                "畸形 REG_DWORD 应拒绝: {bad:?}"
            );
        }
        // 未知 hive 也不放行
        assert!(
            build_restore_ops(&[json!({
                "hive": "NoSuchHive", "sub": "S", "key": "K", "exists": false
            })])
            .is_err()
        );
    }

    /// DWORD 编码口径对齐读值侧 `[string]([int]$v)`：有符号 i32 十进制，
    /// 这样 `0xFFFFFFFF` 才能以 `-1` 的形式原样往返（reg.exe 同口径）。
    #[test]
    fn restore_dword_roundtrip_is_signed32() {
        let ops = build_restore_ops(&[json!({
            "hive": "LocalMachine", "sub": "S", "key": "K",
            "exists": true, "type": "REG_DWORD", "data": "-1"
        })])
        .unwrap();
        let Some(RestoreOp::Write { bytes, .. }) = ops.first() else { panic!("{ops:?}") };
        assert_eq!(bytes.as_slice(), &[0xFFu8, 0xFF, 0xFF, 0xFF]);
        // 正常值
        let ops = build_restore_ops(&[json!({
            "hive": "LocalMachine", "sub": "S", "key": "K",
            "exists": true, "type": "REG_DWORD", "data": "4096"
        })])
        .unwrap();
        let Some(RestoreOp::Write { bytes, .. }) = ops.first() else { panic!("{ops:?}") };
        assert_eq!(bytes.as_slice(), 4096i32.to_le_bytes().as_slice());
    }

    /// B11：`restore_write_bytes` 与 `native::read_reg_value_text` 是**同一条链的两端** ——
    /// 读出来的字符串必须能被编码器原样写回。这里用固定样例钉住两侧口径不漂移
    /// （真正的注册表往返由 `restore_backup_values` 在真机执行，单测只锁纯函数）。
    #[test]
    fn backup_read_and_restore_encode_are_inverse() {
        // DWORD：读侧产出有符号 i32 十进制；编码器按 i32 解析再写回 LE
        assert_eq!(restore_write_bytes("REG_DWORD", "-1").unwrap(), vec![0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(restore_write_bytes("REG_DWORD", "0").unwrap(), vec![0, 0, 0, 0]);
        // QWORD：i64 十进制
        assert_eq!(
            restore_write_bytes("REG_QWORD", "-1").unwrap(),
            (-1i64).to_le_bytes().to_vec()
        );
        // BINARY：小写 hex 连写（读侧 `-join ''` 的产物）逐字节还原
        assert_eq!(restore_write_bytes("REG_BINARY", "deadbeef").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        // SZ：UTF-16LE + NUL；还原路径写回后读侧 `[string]$v` 得到同一串
        let sz = restore_write_bytes("REG_SZ", "中文 & punctuation").unwrap();
        let units: Vec<u16> = sz.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        assert_eq!(String::from_utf16_lossy(&units), "中文 & punctuation\0");
        // 未知类型标签一律按 REG_SZ 编码（与旧 `reg add` 不带 /t 的兜底一致）
        assert_eq!(
            restore_write_bytes("REG_WHATEVER", "x").unwrap(),
            restore_write_bytes("REG_SZ", "x").unwrap()
        );
    }

    /// REG_BINARY 的 hex 串只允许 hex 数字与分隔逗号：畸形备份里的 `$`、反引号、换行
    /// 不得有变成语句的机会。
    /// v2-M9：值级基线**只有第一份是干净的**。渲染层每次执行前都会先 backup-reg，
    /// 所以「连拍两次（中间注册表已被改成优化值）」这条序列在真实使用中必然出现；
    /// 旧写法无条件 insert 会让第二次快照覆盖出厂值，之后「还原」回到上一次优化状态。
    #[test]
    fn backup_baseline_never_overwritten() {
        let mut map = json!({});
        let factory = vec![json!({ "key": "X", "data": "出厂值" })];
        assert!(matches!(
            insert_backup_baseline(&mut map, "svc_mem_gb", factory.clone()),
            BackupInsert::Inserted
        ));

        let optimized = vec![json!({ "key": "X", "data": "已优化值" })];
        let again = insert_backup_baseline(&mut map, "svc_mem_gb", optimized);
        assert!(matches!(again, BackupInsert::KeptExisting(1)), "{again:?}");
        let stored = map["svc_mem_gb"]["values"].as_array().cloned().unwrap_or_default();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0]["data"], "出厂值",
            "基线被第二次快照覆盖 ⇒ 出厂原值永久丢失"
        );

        // 不同项各自独立登记，互不干扰
        assert!(matches!(
            insert_backup_baseline(&mut map, "tf_defender", factory.clone()),
            BackupInsert::Inserted
        ));
        // map 不是对象时不得静默当成「已登记」
        let mut broken = json!([]);
        assert!(matches!(
            insert_backup_baseline(&mut broken, "x", factory),
            BackupInsert::MapNotObject
        ));
    }

    /// v2-K3：闸门必须覆盖数据层自认 high 的**每一项**，而不是只覆盖手写清单登记的那几项。
    /// 断言写成「遍历数据层」，这样以后新增 risk=high 项而不进清单也不会漏。
    #[test]
    fn hazard_gate_covers_every_data_layer_high() {
        let mut n_high = 0;
        for o in options().iter() {
            if o.get("risk").and_then(|v| v.as_str()) != Some("high") {
                continue;
            }
            n_high += 1;
            let id = o.get("id").and_then(|v| v.as_str()).unwrap_or("");
            assert!(needs_high_risk_confirm(o, id), "risk=high 的 {id} 未被高危闸门覆盖");
        }
        assert!(n_high >= 5, "数据层 high 项数异常（{n_high}）——是否被批量降级");

        // v2-K3 实际漏掉的那 7 项：现在由 risk 覆盖，且刻意不进手写清单
        for id in [
            "tf_ifeo_perf",
            "tf_ifeo_wipe",
            "tf_dev_disable",
            "tf_dev_audio",
            "tf_dev_printer",
            "tf_appx",
            "tf_onedrive",
        ] {
            let o = find_option(id).unwrap_or_else(|| panic!("{id} 应存在于数据层"));
            assert!(needs_high_risk_confirm(o, id), "{id} 单项执行仍不弹红色确认");
            assert!(!HAZARD_IDS.contains(&id), "{id} 应由 risk 覆盖，不必回手写清单");
        }

        // 反向：low/medium 项不得被误拦，否则等于把所有优化都锁死在红确认后面
        let low = options()
            .iter()
            .find(|o| o.get("risk").and_then(|v| v.as_str()) == Some("low"))
            .expect("数据层应有 low 项");
        let low_id = low.get("id").and_then(|v| v.as_str()).unwrap_or("");
        assert!(!needs_high_risk_confirm(low, low_id), "low 项 {low_id} 被误判高危");

        // 死条目（数据层不存在）已从清单移除；对拍另有门禁 F2 兜着
        assert!(!HAZARD_IDS.contains(&"tf_microcode_del"));
        assert!(!HAZARD_IDS.contains(&"spectre_off"));
    }

    #[test]
    fn restore_binary_hex_is_strict() {
        // 合法 hex 连写（读值侧 `-join ''` 的产物）必须按字节对解码
        let ops = build_restore_ops(&[json!({
            "hive": "LocalMachine", "sub": "S", "key": "K",
            "exists": true, "type": "REG_BINARY", "data": "414243"
        })])
        .unwrap();
        let Some(RestoreOp::Write { bytes, .. }) = ops.first() else { panic!("{ops:?}") };
        assert_eq!(bytes.as_slice(), &[0x41u8, 0x42, 0x43]);
    }
}
