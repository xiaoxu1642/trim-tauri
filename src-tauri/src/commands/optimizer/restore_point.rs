//! 系统还原点：WMI/DMTF 时间解析、计数、创建（含超时与在途互斥）、列表。
//!
//! `run_inline_ps` 是本域唯一的内联 PS 出口，必须走 pwsh 层单入口并带超时
//! （登记在 check-ps-callsites 的 D 表）；创建还原点是最后防线的兜底，默认不自动删旧。
//! InflightGuard 在 Drop 里释放在途标记，异常路径也要放行下一次创建。

use crate::engine::{guard, log, optimization_state as opt_state, sysinfo};
use serde_json::{Value, json};
use tauri::{Runtime, WebviewWindow};
use super::apply::*;
use super::backup_restore::*;
use super::catalog::*;
// ==================== 系统还原点 ====================

/// 解析 WMI DMTF（yyyymmddHHMMSS.mmmmmm±UUU）。SR-5：偏移 000 按本地时间构造。
pub(super) fn parse_dmtf(raw: &str) -> Option<String> {
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
pub(super) fn local_tz_bias_minutes() -> i64 {
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

pub(super) fn civil_to_ms(y: i64, mo: u32, d: u32, hh: i64, mi: i64, ss: i64) -> i64 {
    let days = days_from_civil(y, mo, d);
    days * 86_400_000 + (hh * 3600 + mi * 60 + ss) * 1000
}

/// Howard Hinnant 公历年月日 → 1970 前天数
pub(super) fn days_from_civil(y_in: i64, m_in: u32, d: u32) -> i64 {
    let y = if m_in <= 2 { y_in - 1 } else { y_in };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m_in > 2 { m_in as i64 - 3 } else { m_in as i64 + 9 };
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub(super) fn ms_to_iso(ms: i64) -> String {
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

pub(super) fn civil_from_days_pub(days: i64) -> (i64, u32, u32) {
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

/// 命令层直调收件箱 PS 的薄封装（v3-K1：还原点查询属 WMI 面，交给 System32 自带的
/// Windows PowerShell，优化中心不再依赖用户安装 PowerShell 7）。
///
/// R0（2026-10-01）：临时脚本与进程树纪律全部下沉到 `pwsh::run_inbox_script`，这里只做
/// `Option` 收敛。原实现自己 `write_temp_script` + `run_inbox_ps`，是「第三种裸调」的形态
/// —— 台账与判红见 `tools/check-ps-callsites.mjs`。`diag` 此前被静默丢弃，现在真的传给
/// 执行层：`optimizer.create-restore` 的 `@@DIAG@@` 行会落日志并从 stdout 剔除。
pub(super) fn run_inline_ps(ps: &str, timeout_secs: u64, diag: Option<&str>) -> Option<crate::pwsh::PsOutput> {
    crate::pwsh::run_inbox_script(ps, std::time::Duration::from_secs(timeout_secs), diag).ok()
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
        // 2026-09-30：前端不再替这条记日志（同事件双行会把真实的一条挤下去），所以每个
        // 失败出口都必须在这里落一行，否则「查询失败」会变成无声失败。
        log::write_log("warn", "还原点查询失败: 查询脚本未跑成（临时脚本写入或 pwsh 启动失败）");
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
        None => {
            log::write_log("warn", "还原点查询失败: 查询无有效输出");
            json!({ "success": false, "exists": false, "message": "查询无有效输出" })
        }
    }
}

pub(super) fn count_restore_points() -> Option<i64> {
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

pub(super) static RESTORE_INFLIGHT: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

/// v2-L4P-10（F-1，P0）：泛型 inflight RAII guard。原实现在函数体里取 `MutexGuard`
/// 并活到函数尾，又在同线程对同一个 `std` futex mutex 二次 `lock()` 复位——std 互斥量
/// 不可重入，等价于自死锁：还原点已建成、回执永挂、async worker 永久泄漏。
/// 刻意不复用 `OptRunGuard`（RPT-07）：那管的是 `OPT_RUN_INFLIGHT`，字面复用会让
/// 「创建还原点」与「跑优化项」互相排斥。Drop 复位覆盖全部早退路径。
pub(super) struct InflightGuard<'a>(&'a std::sync::Mutex<bool>);
impl InflightGuard<'_> {
    fn acquire(flag: &std::sync::Mutex<bool>) -> Option<InflightGuard<'_>> {
        let mut slot = flag.lock().unwrap_or_else(|e| e.into_inner());
        if *slot { None } else { *slot = true; Some(InflightGuard(flag)) }
    }
}
impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = false;
    }
}

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
    let Some(_inflight) = InflightGuard::acquire(&RESTORE_INFLIGHT) else {
        return json!({ "success": false, "message": "正在创建还原点，请勿重复提交" });
    };
    // create_restore_inner 全程是阻塞面（收件箱 PS 预检/创建 + WMI 回读 + 注册表记账），
    // 命令体是 async fn，必须搬进 spawn_blocking，不能占 runtime worker（v2-L4P-10）。
    let result = tauri::async_runtime::spawn_blocking(create_restore_inner)
        .await
        .unwrap_or_else(|_| json!({ "success": false, "message": "创建还原点任务异常退出，请重试" }));
    result
}

pub(super) fn create_restore_inner() -> Value {
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

