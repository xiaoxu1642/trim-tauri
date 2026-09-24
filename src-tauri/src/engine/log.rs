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

/// 本机相对于 UTC 的偏移秒数（Win32 本地时钟与 UTC 时钟同刻差值，分钟精度足够日志分档）
fn local_utc_offset_secs() -> i64 {
    use windows::Win32::System::SystemInformation::{GetLocalTime, GetSystemTime};
    unsafe {
        let local = GetLocalTime();
        let sys = GetSystemTime();
        let l = local.wHour as i64 * 3600 + local.wMinute as i64 * 60;
        let s = sys.wHour as i64 * 3600 + sys.wMinute as i64 * 60;
        let day_diff = local.wDay as i64 - sys.wDay as i64;
        let mut diff = l - s + day_diff * 86_400;
        // 归一到 ±12 小时内（跨日时差值会跑出一天）
        if diff > 43_200 {
            diff -= 86_400;
        } else if diff < -43_200 {
            diff += 86_400;
        }
        diff
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