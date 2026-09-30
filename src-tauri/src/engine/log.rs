//! 操作日志系统（对照 main.js 403-503 / 453-481 段）
//!
//! 语义逐条对齐：
//! - 文件名 `app-YYYY-MM-DD.log`，**本地时间**（避免 UTC 与东八区差 8 小时误判时序）；
//! - 行格式 `[YYYY-MM-DD HH:MM:SS] [LEVEL] message`；
//! - 内存队列 + 后台批量落盘（日志对实时性不敏感，避免同步 I/O 叠加到 IPC 路径）；
//! - 危险操作前/退出前 `flush_sync()` 强制刷盘，防尾部日志丢失；
//! - 启动时清理 30 天前日志（应用自产诊断数据，直接删除不进回收站；当天文件不受影响）；
//! - level/message 强制转字符串（log:write 直接透传渲染层入参，未知上游可传任意值）。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use super::paths;

const LOG_RETENTION_DAYS: u64 = 30;
/// 读取日志时只取末尾（最大 512KB），避免大日志整文件载入内存
pub const LOG_READ_MAX_BYTES: u64 = 512 * 1024;

struct LogState {
    queue: Vec<(PathBuf, String)>,
}

static STATE: Mutex<Option<LogState>> = Mutex::new(None);

fn with_state<T>(f: impl FnOnce(&mut LogState) -> T) -> T {
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.get_or_insert_with(|| LogState { queue: Vec::new() });
    f(state)
}

fn pad2(n: u32) -> String {
    format!("{n:02}")
}

/// 本地日期（写日志 / log:read 默认 / log:export 三处共用，杜绝 UTC 口径漂移）
pub fn local_date_str(t: SystemTime) -> String {
    let (y, m, d, _, _, _) = local_parts(t);
    format!("{y}-{}-{}", pad2(m), pad2(d))
}

fn local_parts(t: SystemTime) -> (i32, u32, u32, u32, u32, u32) {
    // 不引入 chrono：用 std 的 UNIX 纪元 + 本地时区偏移换算成本地日历时间
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let offset = local_utc_offset_secs();
    let local = secs + offset;
    let days = local.div_euclid(86_400);
    let rem = local.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    (y, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32)
}

/// 由 days since 1970-01-01 求公历年月日（Howard Hinnant 的 civil_from_days 算法）
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((y + if m <= 2 { 1 } else { 0 }) as i32, m, d)
}

/// 本机相对于 UTC 的偏移秒数（本地 SYSTEMTIME 与 UTC SYSTEMTIME 各自转 FILETIME 后相减）。
///
/// 【根因记录】上一版用「wDay 之差 × 86400」近似跨日偏移，只在同月内成立——
/// 月初/月末本地与 UTC 落在不同月时（如 UTC 9-30 晚 vs 本地 10-1 凌晨），day 差会算出
/// -29/30 天级别的垃圾偏移，日志日期整体跑偏（实测本地 10-01 被写成 09-02）。改为
/// FILETIME 相减，跨月/跨年都精确；换算失败按 UTC 处理（宁可时区差 8 小时，不写坏日期）。
fn local_utc_offset_secs() -> i64 {
    use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows::Win32::System::SystemInformation::{GetLocalTime, GetSystemTime};
    use windows::Win32::System::Time::SystemTimeToFileTime;
    unsafe {
        let local: SYSTEMTIME = GetLocalTime();
        let sys: SYSTEMTIME = GetSystemTime();
        let to_filetime = |st: SYSTEMTIME| -> Option<i64> {
            let mut ft = FILETIME::default();
            SystemTimeToFileTime(&st, &mut ft).ok()?;
            let v = ((ft.dwHighDateTime as i64) << 32) | ft.dwLowDateTime as i64;
            Some(v / 10_000_000) // 100ns 粒度 -> 秒
        };
        match (to_filetime(local), to_filetime(sys)) {
            (Some(l), Some(s)) => l - s,
            _ => 0,
        }
    }
}

/// 写日志。返回完整日志行（对齐 Electron 版 writeLog 返回值）。
pub fn write_log(level: &str, message: &str) -> String {
    let level = if level.is_empty() { "info" } else { level };
    let now = SystemTime::now();
    let (y, mo, d, h, mi, s) = local_parts(now);
    let line = format!(
        "[{y}-{}-{} {}:{}:{}] [{}] {}\n",
        pad2(mo),
        pad2(d),
        pad2(h),
        pad2(mi),
        pad2(s),
        level.to_uppercase(),
        message
    );
    let file = paths::log_dir().join(format!("app-{}.log", local_date_str(now)));
    with_state(|st| st.queue.push((file, line.clone())));
    // 异步批量落盘：由 flush_async 在后台线程执行（等价 Electron 的 setImmediate 合并写）
    schedule_async_flush();
    line
}

static FLUSH_SCHEDULED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn schedule_async_flush() {
    use std::sync::atomic::Ordering;
    if FLUSH_SCHEDULED.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(60)); // 合并窗口
        FLUSH_SCHEDULED.store(false, Ordering::SeqCst);
        flush_inner();
    });
}

fn flush_inner() {
    let drained = with_state(|st| std::mem::take(&mut st.queue));
    if drained.is_empty() {
        return;
    }
    if fs::create_dir_all(paths::log_dir()).is_err() {
        return;
    }
    for (file, line) in drained {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&file) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// 同步强制刷盘：危险操作前 / 退出前调用（对齐 flushLogSync）
pub fn flush_sync() {
    flush_inner();
}

/// 读取指定日期日志末尾内容（对齐 log:read 语义，含 512KB 截断与半行丢弃）
pub fn read_log(date: Option<&str>) -> String {
    let date = match date {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => local_date_str(SystemTime::now()),
    };
    // 日期格式白名单：防路径穿越（../../）
    let valid = date.len() == 10
        && date.as_bytes()[4] == b'-'
        && date.as_bytes()[7] == b'-'
        && date
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    if !valid {
        return "读取日志失败: 日期格式无效".into();
    }
    let file = paths::log_dir().join(format!("app-{date}.log"));
    let meta = match fs::metadata(&file) {
        Ok(m) => m,
        Err(_) => return String::new(),
    };
    let size = meta.len();
    match fs::read(&file) {
        Ok(bytes) => {
            if size <= LOG_READ_MAX_BYTES {
                return String::from_utf8_lossy(&bytes).to_string();
            }
            let tail = &bytes[bytes.len() - LOG_READ_MAX_BYTES as usize..];
            let text = String::from_utf8_lossy(tail).to_string();
            // 丢弃被截断的半行
            match text.find('\n') {
                Some(idx) => text[idx + 1..].to_string(),
                None => text,
            }
        }
        Err(e) => format!("读取日志失败: {e}"),
    }
}

/// 日志导出：把当天日志复制到目标路径（对话框由命令层负责）
pub fn export_log(dest: &std::path::Path) -> Result<(), String> {
    let src = paths::log_dir().join(format!("app-{}.log", local_date_str(SystemTime::now())));
    if !src.is_file() {
        return Err("日志不存在".into());
    }
    fs::copy(&src, dest).map_err(|e| e.to_string())?;
    Ok(())
}

/// 启动清理 30 天前日志（当天与文件名不合日期模式的文件不受影响）
pub fn prune_old_logs() {
    let dir = paths::log_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let cutoff = SystemTime::now() - Duration::from_secs(LOG_RETENTION_DAYS * 86_400);
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_log_file_name(&name) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let mtime = meta.modified().unwrap_or(SystemTime::now());
        if mtime < cutoff && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        write_log(
            "info",
            &format!("日志清理: 已删除 {removed} 个超过 {LOG_RETENTION_DAYS} 天的旧日志文件"),
        );
    }
}

fn is_log_file_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("app-") else {
        return false;
    };
    let Some(date) = rest.strip_suffix(".log") else {
        return false;
    };
    date.len() == 10
        && date.as_bytes()[4] == b'-'
        && date.as_bytes()[7] == b'-'
        && date
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
}
#[cfg(test)]
mod tests {
    use super::*;

    /// civil_from_days 的锚点：不校验它，local_date_str 的所有日期都是"看着对"而已。
    /// 这里钉住 1970-01-01、闰年 2 月末、以及跨月 anchor（正是上一版 wDay 差值法的
    /// 翻车点：UTC 9-30 晚 vs 本地 10-1 凌晨会把日志日期写成 09-02，实测发生过）。
    #[test]
    fn civil_from_days_anchors() {
        let (y, m, d) = civil_from_days(0);
        assert_eq!((y, m, d), (1970, 1, 1));
        // 2026-09-30 = 20726 天（UTC），2026-10-01 = 20727 天
        let (y, m, d) = civil_from_days(20_726);
        assert_eq!((y, m, d), (2026, 9, 30));
        let (y, m, d) = civil_from_days(20_727);
        assert_eq!((y, m, d), (2026, 10, 1));
        // 闰日：2024-02-29 = 19723（2024-01-01）+ 31 + 29 - 1 = 19782 天
        let (y, m, d) = civil_from_days(19_782);
        assert_eq!((y, m, d), (2024, 2, 29));
    }

    /// 本机偏移必须是分钟级粒度、±14 小时内（时区 + 整分 DST），否则算出的
    /// 本地日期不可信。机器相关，但这两条不变量在任何正常系统上都成立。
    #[test]
    fn local_offset_is_minute_granular_and_bounded() {
        let off = local_utc_offset_secs();
        assert!(off % 60 == 0, "偏移应有分钟粒度: {off}");
        assert!((-50_400..=50_400).contains(&off), "偏移超出 ±14h: {off}");
    }

    /// 日期串格式不变量（文件名分档依赖它）：YYYY-MM-DD、数字位、横杠位固定。
    #[test]
    fn local_date_str_shape() {
        let s = local_date_str(std::time::SystemTime::now());
        assert_eq!(s.len(), 10);
        let bytes = s.as_bytes();
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
    }
}
