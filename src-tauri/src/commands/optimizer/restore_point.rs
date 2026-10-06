//! 系统还原点：WMI/DMTF 时间解析、计数、创建（含超时与在途互斥）、列表。
//!
//! `run_inline_ps` 是本域唯一的内联 PS 出口，必须走 pwsh 层单入口并带超时
//! （登记在 check-ps-callsites 的 D 表）；创建还原点是最后防线的兜底，默认不自动删旧。
//! InflightGuard 在 Drop 里释放在途标记，异常路径也要放行下一次创建。

use crate::engine::{civil_from_days, guard, log, optimization_state as opt_state, sysinfo};
use serde_json::{Value, json};
use tauri::{Runtime, WebviewWindow};
use super::backup_restore::*;
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

/// Windows 本地时区 Bias（分钟；UTC = 本地 + Bias）。
///
/// M-10（审查 2026-10-07）：原实现只取 `Bias`（标准时间档），夏令时生效期间漏加
/// `DaylightBias` —— 会把 DMTF `+000`（本地时间）换算成差一小时的 UTC，还原点创建
/// 时间显示偏一小时。`GetTimeZoneInformation` 的返回值就标明当前处于标准档还是夏令档
/// （TIME_ZONE_ID_DAYLIGHT=2），据此补 `DaylightBias`。
pub(super) fn local_tz_bias_minutes() -> i64 {
    use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
    unsafe {
        let mut tz = TIME_ZONE_INFORMATION::default();
        // 返回 TIME_ZONE_ID_*(0/1/2)；0xFFFFFFFF 才是失败。ID_UNKNOWN(0) 时 Bias 仍有效。
        let id = GetTimeZoneInformation(&mut tz);
        if id == u32::MAX {
            return 0;
        }
        let daylight = if id == TIME_ZONE_ID_DAYLIGHT {
            tz.DaylightBias as i64
        } else {
            0
        };
        tz.Bias as i64 + daylight
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
    // days_from_civil 的逆（engine 唯一实现，P2-3 去重）
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milli:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
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

/// 频率覆写值的注册表坐标（能力已搬进「系统还原点」弹窗；`tf_restore_point` 仅作
/// **历史备份 id** 沿用 —— 写入侧与还原侧共用本函数，§5.16 一处定义）。
/// 先例：`backup_restore.rs::option_targets` 的 `svc_mem_gb` 硬编码分支。
/// 要改这个坐标时把「弹窗命令 / 创建流程 / 备份 id」三处一起对——它们是同一条链。
pub(super) fn restore_freq_target() -> RegTarget {
    RegTarget {
        root: "HKEY_LOCAL_MACHINE".into(),
        sub: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore".into(),
        key: "SystemRestorePointCreationFrequency".into(),
    }
}

/// 把频率覆写值恢复为修改前的原值；原值不存在（备份 `exists=false`）则删除该值
/// （= 恢复系统默认的 24 小时限制）。`Ok(描述)` = 干了什么；`Err(原因)` = 失败原因。
///
/// 创建流程（无论成败）与弹窗「恢复默认创建频率」命令**共用这一处实现**（§5.16：
/// 同一判定只许一处定义）——两个调用方各写一份「写回/删值」逻辑，漂移时谁也发现不了。
pub(super) fn recycle_freq_override() -> Result<String, String> {
    let map = load_opt_backups();
    let some_values = map
        .get("tf_restore_point")
        .and_then(|e| e.get("values"))
        .and_then(|v| v.as_array())
        .cloned();
    let Some(values) = some_values.filter(|a| !a.is_empty()) else {
        return Err("没有可用于恢复的备份记录".to_string());
    };
    // M-11：构造还原操作只做一次，写回与（调用方后续）回读核对共用同一份 ops。
    let Ok(ops) = build_restore_ops(&values) else {
        return Err("备份数据无法解析成还原操作".to_string());
    };
    if !restore_backup_values(&ops) {
        return Err("写回注册表失败".to_string());
    }
    let any_exists = values
        .iter()
        .any(|v| v.get("exists").and_then(|x| x.as_bool()).unwrap_or(false));
    Ok(if any_exists {
        "已写回修改前的创建频率值".to_string()
    } else {
        "已删除创建频率覆写值（恢复系统默认的 24 小时限制）".to_string()
    })
}

/// 失败回执 + 频率覆写回收结果（D2：无论成败都回收；回收失败如实报出口，不谎报已回收）。
fn fail_with_recycle(base: &str, rec: Result<String, String>) -> Value {
    let tail = match rec {
        Ok(d) => format!("；创建频率覆写已还原（{d}）"),
        Err(e) => format!(
            "；但创建频率覆写值回收失败（{e}），请打开「系统还原点」弹窗点「恢复默认创建频率」手动回收"
        ),
    };
    json!({ "success": false, "message": format!("{base}{tail}") })
}

pub(super) fn create_restore_inner() -> Value {
    // 预检：fail-closed（**拿不到确定结论 ⇒ 中止**，绝不往下写覆写值）+ 分级报因。
    // 旧实现是三层 fail-open（脚本没跑成 / 标记缺失 / JSON 坏 —— 任一层落空都跳过预检
    // 继续创建）；本机日志里「protectedVolumes=0 却仍走到 Invoke-CimMethod」与它一致。
    let pre = "$ErrorActionPreference = \"SilentlyContinue\"\n\
$out = @{ globalDisabled = $false; protectedVolumes = 0; srDriver = $false; srService = $false; providerOk = $false }\n\
$srKey = Get-ItemProperty \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\"\n\
if ($srKey -and $null -ne $srKey.DisableSR -and [int]$srKey.DisableSR -eq 1) { $out.globalDisabled = $true }\n\
$out.protectedVolumes = @(Get-CimInstance Win32_ShadowStorage).Count\n\
$out.srDriver = Test-Path \"$env:SystemRoot\\System32\\drivers\\sr.sys\"\n\
$out.srService = ($null -ne (Get-Service -Name SRService -ErrorAction SilentlyContinue))\n\
try { $null = Get-CimInstance -Namespace 'root/default' -ClassName SystemRestore -ErrorAction Stop; $out.providerOk = $true } catch { $out.providerOk = $false }\n\
Write-Output ('@@SRPRE@@' + ($out | ConvertTo-Json -Compress))";
    let Some(out) = run_inline_ps(pre, 20, None) else {
        log::write_log("warn", "还原点预检未能完成：预检脚本未跑成");
        return json!({ "success": false, "message": "预检未能完成（查询脚本未执行），已中止创建；可稍后重试，或到「系统 → 关于 → 系统保护」手动创建还原点" });
    };
    let Some(line) = out.stdout.lines().map(str::trim).find(|l| l.starts_with("@@SRPRE@@")) else {
        log::write_log("warn", "还原点预检未能完成：无 @@SRPRE@@ 输出");
        return json!({ "success": false, "message": "预检未能完成（无有效输出），已中止创建；可稍后重试，或到「系统 → 关于 → 系统保护」手动创建还原点" });
    };
    let Ok(v) = serde_json::from_str::<Value>(&line["@@SRPRE@@".len()..]) else {
        log::write_log("warn", "还原点预检未能完成：输出不是合法 JSON");
        return json!({ "success": false, "message": "预检未能完成（输出解析失败），已中止创建；可稍后重试，或到「系统 → 关于 → 系统保护」手动创建还原点" });
    };
    // 分级报因，判定顺序：全局关闭 → 组件缺失 → 无受保护卷。
    // 「组件缺失」必须先于「0 个受保护卷」判 —— 组件缺失时 0 卷是伪因，照实报到
    // 「需修复系统组件」才对得上本机实况（sr.sys / SRService / 提供程序三者任一缺）。
    if v.get("globalDisabled").and_then(|x| x.as_bool()).unwrap_or(false) {
        return json!({ "success": false, "message": "系统保护已被全局关闭（DisableSR=1），请先在「系统 → 关于 → 系统保护」中开启后再创建还原点" });
    }
    let provider_ok = v.get("providerOk").and_then(|x| x.as_bool()).unwrap_or(false);
    let sr_driver = v.get("srDriver").and_then(|x| x.as_bool()).unwrap_or(false);
    let sr_service = v.get("srService").and_then(|x| x.as_bool()).unwrap_or(false);
    if !provider_ok || !sr_driver || !sr_service {
        log::write_log(
            "warn",
            &format!("还原点预检：系统还原组件缺失（provider={provider_ok} driver={sr_driver} service={sr_service}）"),
        );
        return json!({ "success": false, "message": "系统还原组件缺失或未安装（还原驱动 / 服务 / 还原点提供程序不可用）。可在「系统 → 关于 → 系统保护」查看状态；或用 sfc /scannow 与 DISM /Online /Cleanup-Image /RestoreHealth 尝试修复系统组件（不保证修复成功），修复后再回来创建" });
    }
    if v.get("protectedVolumes").and_then(|x| x.as_i64()).unwrap_or(0) == 0 {
        return json!({ "success": false, "message": "没有任何卷开启系统保护，请先在「系统 → 关于 → 系统保护」中为系统盘开启保护" });
    }

    // 频率覆写值的原值备份（**必须在写入前**读）。两条失败路径都中止创建：
    // 回收依赖备份，没有备份就留一台「覆写值写了、原值找不回」的机器
    // —— 本机残留的 `SystemRestorePointCreationFrequency=0x0` 正是这个形态的历史证据。
    let targets = vec![restore_freq_target()];
    let Some(values) = read_reg_values(&targets) else {
        log::write_log("warn", "还原点频率覆写值备份失败（读取原值失败），已中止创建");
        return json!({ "success": false, "message": "频率覆写值备份失败，已中止创建（不留无法回收的中间状态）" });
    };
    {
        let mut map = load_opt_backups();
        // v2-M9：这条也走「首份不覆盖」——同一项重复创建时不得把基线刷成已覆写值。
        // 不覆盖是安全的：新逻辑下每次创建结束都回收，当前值必等于原值，旧基线依然正确。
        let inserted =
            matches!(insert_backup_baseline(&mut map, "tf_restore_point", values), BackupInsert::Inserted);
        if !inserted {
            log::write_log("warn", "还原点频率覆写值级备份未写入（基线已存在或结构异常）");
        } else if !save_opt_backups(&map) {
            log::write_log("warn", "还原点频率覆写值级备份保存失败，已中止创建");
            return json!({ "success": false, "message": "频率覆写值备份保存失败，已中止创建（不留无法回收的中间状态）" });
        }
    }
    // v5 P2：`record_pending` 的契约明写着「false = 写入失败，调用方必须中止」
    // （optimization_state.rs:53）。这条路径会真的创建还原点（改系统），账留不下就等于
    // "改了系统但没有任何记录"—— 崩溃后连「未完成还原」横幅都不会提示。
    // kinds 与内联前数据层两步（reg + pwsh）等价，概览展示口径不变。
    if !opt_state::record_pending(
        "tf_restore_point",
        "创建系统还原点",
        &["reg".to_string(), "pwsh".to_string()],
    ) {
        log::write_log("error", "创建还原点前 pending 记账失败，已中止（不改系统）");
        return json!({ "success": false, "message": "优化状态写入失败，已取消创建还原点" });
    }

    // 创建脚本：先写频率覆写值（解除 24h 限制），再经 root\default SystemRestore 的
    // WMI 静态方法创建（PS7 没有 Checkpoint-Computer）。原为数据层两步（reg + pwsh）
    // 经 build_script 生成；条目摘除后内联，文本与原步骤逐语义等价
    // （EventType 100 = BEGIN_SYSTEM_CHANGE，RestorePointType 0 = APPLICATION_INSTALL）。
    let create_ps = "$ErrorActionPreference = \"Stop\"\n\
New-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" -Name \"SystemRestorePointCreationFrequency\" -Value 0 -PropertyType DWord -Force | Out-Null\n\
$null = Invoke-CimMethod -Namespace 'root/default' -ClassName 'SystemRestore' -MethodName 'CreateRestorePoint' -Arguments @{ Description = 'Trim 优化前还原点'; EventType = [uint32]100; RestorePointType = [uint32]0 }\n\
Write-Output \"@@DONE@@\"";
    let before = count_restore_points();
    let Some(out) = run_inline_ps(create_ps, 120, Some("optimizer.create-restore")) else {
        let _ = opt_state::remove("tf_restore_point");
        let rec = recycle_freq_override();
        return fail_with_recycle("创建还原点执行异常", rec);
    };
    let ok = out.code == 0 && out.stdout.contains("@@DONE@@");
    if !ok {
        let _ = opt_state::remove("tf_restore_point");
        log::write_log("warn", &format!("创建系统还原点未成功: code={}", out.code));
        let rec = recycle_freq_override();
        return fail_with_recycle("系统还原点创建失败，请手动创建（需管理员权限，且至少一个卷已开启系统保护）", rec);
    }
    // v5 O-5：账本改到**回读之后**再记。旧写法在这里就 mark_applied("pass")，而下面的回读
    // 判失败时只 return、不改账 ⇒ 命令回执 success:false 与账本 applied/pass 同时存在；
    // 更糟的是 applied 项不进 staleIds（overview.rs 的判据），界面永远看不到这条失败。

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
            // 回读判失败必须改账（v5 O-5）：partial 项由 optimizer_state_overview 如实呈现
            let _ = opt_state::mark_partial("tf_restore_point");
            log::write_log("warn", &format!("创建还原点回读未增长: {b} -> {a}，已记账为 partial"));
            let rec = recycle_freq_override();
            return fail_with_recycle(
                "未检测到新还原点，创建可能被系统限制或仍在进行，请稍后在「系统还原点管理」核对",
                rec,
            );
        }
    }
    let btxt = before.map(|b| b.to_string()).unwrap_or_else(|| "?".into());
    let atxt = last.map(|a| a.to_string()).unwrap_or_else(|| "?".into());
    // 结论强度 = 证据强度（v5 O-5）：基线计数取不到（WMI 抖动、本机 SR provider 坏）时
    // 没有"数量增长"这回事，只能记 unknown，不许冒充已验证的 pass。
    let (verify, msg) = if before.is_some() {
        ("pass", "已创建系统还原点")
    } else {
        log::write_log("warn", "创建还原点：基线计数取不到，无法比对数量增长，按 unknown 记账");
        ("unknown", "创建命令已完成，但未能比对还原点数量（基线计数不可读），请到「系统还原点管理」核对")
    };
    let _ = opt_state::mark_applied("tf_restore_point", verify);
    // 无论成败都回收频率覆写值（D2）：成功也要收 —— 别把「解除 24h 限制」留在机器上。
    let rec = recycle_freq_override();
    let tail = match rec {
        Ok(d) => format!("；创建频率覆写已还原（{d}）"),
        Err(e) => format!(
            "；但创建频率覆写值回收失败（{e}），请打开「系统还原点」弹窗点「恢复默认创建频率」手动回收"
        ),
    };
    log::write_log("info", &format!("已创建系统还原点 ({btxt} -> {atxt}) verify={verify}{tail}"));
    json!({ "success": true, "message": format!("{msg}{tail}"), "verify": verify })
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

/// optimizer:restore-frequency —— 把还原点创建频率限制恢复为修改前的值（弹窗窄口子）
///
/// 只服务「系统还原点」弹窗的一个按钮：**无入参**、只认历史备份 id `tf_restore_point`。
/// 刻意**不放宽** `optimizer_restore_reg` 的 `find_option || is_retired_id` 白名单
/// （那条是通用入口，放宽会削弱「未知 id 一律拒」的守卫）；走自己的窄口子即够。
#[tauri::command]
pub async fn optimizer_restore_frequency<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    if !sysinfo::is_admin() {
        return json!({
            "success": false, "needAdmin": true,
            "message": "恢复创建频率需要管理员权限，请先提权"
        });
    }
    match recycle_freq_override() {
        Ok(desc) => json!({ "success": true, "message": desc }),
        Err(e) => {
            let missing = e.contains("没有可用于恢复");
            json!({ "success": false, "missing": missing, "message": format!("恢复创建频率失败：{e}") })
        }
    }
}

