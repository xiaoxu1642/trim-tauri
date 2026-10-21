//! 操作日志系统（对照 main.js 403-503 / 453-481 段）
//!
//! 语义逐条对齐：
//! - 文件名 `app-YYYY-MM-DD.log`，**本地时间**（避免 UTC 与东八区差 8 小时误判时序）；
//! - 行格式 `[YYYY-MM-DD HH:MM:SS] [LEVEL] message`；
//! - 内存队列 + 后台批量落盘（日志对实时性不敏感，避免同步 I/O 叠加到 IPC 路径）；
//! - 危险操作前/退出前 `flush_sync()` 强制刷盘，防尾部日志丢失；
//! - 启动时清理 30 天前日志（应用自产诊断数据，回收站优先，见 `prune_old_logs`；当天文件不受影响）；
//! - **入口清洗在 `write_log` 里做**（R6b-M07）：`level` 走 [`sanitize_log_level`] 白名单、
//!   `message` 走 [`sanitize_log_message`]（控制符含 CR/LF/NUL → 空格 + 折叠连续空白）。
//!   这两个函数是**全仓唯一真源**，命令层 `log:write` 只是多套一层长度上限——
//!   此前清洗只存在于 `commands/log.rs`，而 `write_log` 的直调点远多于那条通道，
//!   其中插值外部文本的消息（远端模型返回的错误体、子进程输出）能把 `\n[时间] [ERROR] …`
//!   原样拼进日志**伪造整行**，日志的行边界不能由被记录的一方决定；
//! - 读取只取末尾窗口（[`LOG_READ_MAX_BYTES`]）并丢弃被截断的半行，实现是**定位后读**，
//!   不把整份大日志读进内存。

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use super::civil_from_days;
use super::paths;

const LOG_RETENTION_DAYS: u64 = 30;
/// 读取日志的**末尾窗口**上限：`read_log` 先按这个宽度定位再读，
/// 所以「读今天的日志」的内存占用与日志文件多大无关（R6b-L03：实现与此口径现在是一致的，
/// 旧版是先 `fs::read` 整文件再切尾，注释说的「避免大日志整文件载入内存」当时是假的）
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
    (y as i32, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32)
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

/// 当前进程是不是「测试进程」——是则**不落盘**（返回行照旧，见 [`log_sink_enabled`]）。
///
/// 为什么要这个闸门：`cargo test` 会把测试夹具的日志写进**应用真正的日志目录**
/// （`%APPDATA%\<identifier>\logs\app-YYYY-MM-DD.log`），而那正是「操作日志」页面读的同一份。
/// 后果是用户在自己的日志里看到 `evil.reg 含受保护目标，已拒绝还原`、
/// `拒绝：受保护路径 C:\Windows`、`[ERROR] 伪造的一行` 这类**测试产物**，看上去像应用在报错
/// —— 2026-10-02 用户就是拿这条日志截图来问的。
///
/// 判据两条，覆盖两种测试形态：
///  ① 单元测试：lib 内部 `#[cfg(test)]` 编译 → `cfg!(test)`；
///  ② 集成/文档测试：产物落在 `target\<profile>\deps\<name>-<hash>.exe`。**应用本体不在此目录**
///     （dev 是 `target\debug\trim-tauri.exe`，发布版是 `Trim.exe`），所以不会误伤真机运行。
fn is_test_process() -> bool {
    if cfg!(test) {
        return true;
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.file_name().map(|n| n == "deps").unwrap_or(false)))
        .unwrap_or(false)
}

/// 日志是否落盘。**真机运行为 true；任何测试进程为 false。**
///
/// 暴露出来是为了能被断言（`tests/` 里有一条用例钉它），否则这个闸门被人误删时是静默的：
/// 测试又开始往用户日志里灌垃圾，而所有用例依旧全绿。
pub fn log_sink_enabled() -> bool {
    !is_test_process()
}

/// level 白名单（**唯一真源**，R6b-M07 与命令层合并到这一处）。
///
/// 为什么不报错：日志不该成为一个功能的失败点（渲染层上报异常时再抛错就是双重失败）；
/// 但也不能照抄——`write_log` 把 level 大写后拼进 `[LEVEL]` 位，任意字符串等于让
/// 调用方自造日志级别，日志页的级别筛选与人工排障都会被骗。
pub fn sanitize_log_level(level: &str) -> &'static str {
    let l = level.trim().to_ascii_lowercase();
    match l.as_str() {
        "warn" => "warn",
        "error" => "error",
        "info" => "info",
        _ => "info",
    }
}

/// 消息清洗（**唯一真源**）：控制符（含 CR/LF/NUL）换成空格 + 折叠连续空白 + 可选截断。
///
/// `limit` 传 `usize::MAX` 即只清洗不定长——长度上限是 **IPC 边界**的策略（渲染层可控串），
/// 不是行完整性的判据，内部调用点的诊断消息不该被它砍掉。
/// 截断标记只在还没带上时追加一次，所以本函数**幂等**：`sanitize(sanitize(x)) == sanitize(x)`，
/// 命令层多套一层上限不会出现「…（已截断）…（已截断）」。
pub fn sanitize_log_message(message: &str, limit: usize) -> String {
    const TRUNC_MARK: &str = "…（已截断）";
    let mut out = String::with_capacity(message.len().min(limit.min(1 << 16)));
    let mut chars = 0usize;
    let mut prev_space = false;
    for ch in message.chars() {
        // 控制符（NUL、\x01..\x1f、\x7f 等）先归成空格再参与折叠：它们不进日志行是行
        // 完整性的前提，混进去还会让终端/日志页把一行看成多行
        let c = if ch.is_control() { ' ' } else { ch };
        let is_space = c.is_whitespace();
        if is_space {
            if !prev_space {
                out.push(' ');
                chars += 1;
            }
            prev_space = true;
        } else {
            out.push(c);
            chars += 1;
            prev_space = false;
        }
        if chars >= limit {
            if !out.ends_with(TRUNC_MARK) {
                out.push_str(TRUNC_MARK);
            }
            break;
        }
    }
    out.trim().to_string()
}

/// 写日志。返回完整日志行（对齐 Electron 版 writeLog 返回值）。
///
/// 测试进程只返回行、不入队（见 [`is_test_process`]）—— 既有用例断言的都是**返回值**
/// （行格式、换行注入、长度截断），所以这条闸门不影响它们，也不需要给测试另开日志目录。
///
/// 清洗在**这里**做（R6b-M07）：本函数是全仓唯一的日志行生产者，行边界只能由它决定；
/// 把清洗放在某一条通道上（此前只有 `log:write`）等于给其余直调点留旁路。
pub fn write_log(level: &str, message: &str) -> String {
    let level = sanitize_log_level(level);
    let message = sanitize_log_message(message, usize::MAX);
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
    if !log_sink_enabled() {
        return line;
    }
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

/// 刷盘失败时允许回队的行数上限（钉的是「磁盘满时不无限攒」，正常路径碰不到）。
/// 超限裁最旧，并把丢弃条数一次性告警出去——审计尾部不能**静默**消失（R6b-M08）。
const FLUSH_REQUEUE_MAX: usize = 8192;

/// 把没落成的行并回队列，返回被裁掉的行数。
///
/// 做成**纯函数**（入参就是要改的 Vec）是为了能被判红断言直接命中：`flush_inner` 的失败
/// 分支要造「目录建不了 / 文件打不开」才走得进去，那种夹具在测试里不可靠；回队与裁剪
/// 本身才是 M08 的缺陷面（旧实现是 `return` 丢掉整批），所以把它抽出来测。
fn merge_queue_capped(q: &mut Vec<(PathBuf, String)>, rows: Vec<(PathBuf, String)>) -> usize {
    q.extend(rows);
    let over = q.len().saturating_sub(FLUSH_REQUEUE_MAX);
    if over > 0 {
        q.drain(0..over);
    }
    over
}

/// 把未落成的行放回队列；超过上限时裁最旧并 `eprintln!` 一条降级告警（stderr 不落日志，
/// 免得「日志写不进去」这件事本身又变成一条写不进去的日志）。
fn requeue(rows: Vec<(PathBuf, String)>) {
    let dropped = with_state(|st| merge_queue_capped(&mut st.queue, rows));
    if dropped > 0 {
        eprintln!("[trim] 日志刷盘持续失败，积压超过 {FLUSH_REQUEUE_MAX} 行，已丢弃最旧 {dropped} 行");
    }
}

fn flush_inner() {
    let drained = with_state(|st| std::mem::take(&mut st.queue));
    if drained.is_empty() {
        return;
    }
    // R6b-M08：`drained` 已经出队，旧实现在这里 `return` ⇒ 整批审计行凭空消失。
    // 目录建不起来（磁盘满/权限/只读盘）与单行写不进去是同一种后果，一律回队，
    // 等下一次写入或退出前的 `flush_sync` 再试。
    if fs::create_dir_all(paths::log_dir()).is_err() {
        requeue(drained);
        return;
    }
    let mut failed: Vec<(PathBuf, String)> = Vec::new();
    for (file, line) in drained {
        let written = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file)
            .and_then(|mut f| f.write_all(line.as_bytes()));
        if written.is_err() {
            failed.push((file, line));
        }
    }
    if !failed.is_empty() {
        requeue(failed);
    }
}

/// 同步强制刷盘：危险操作前 / 退出前调用（对齐 flushLogSync）
pub fn flush_sync() {
    flush_inner();
}

/// 末尾窗口的起点（纯算术，抽出来是为了能判红）。
///
/// `saturating_sub` 不是随手写的：旧实现是 `bytes.len() - LOG_READ_MAX_BYTES` 的**索引减法**，
/// 而大小判据取的是 `metadata().len()` —— 两次取值之间文件被外部截短（轮动、手工清空）
/// 就得到负偏移，切片当场 panic，日志页把整个读取打挂（R6b-L03）。
/// 现在窗口起点只由这一个 `size` 决定，算不满窗口就是 0，读多少按实际字节走。
fn read_window_start(size: u64) -> u64 {
    size.saturating_sub(LOG_READ_MAX_BYTES)
}

/// 读取指定日期日志末尾内容（对齐 log:read 语义，含末尾窗口与半行丢弃）
///
/// R6b-L03 的两处收口：
/// 1. **只读末尾窗口**：先按 `LOG_READ_MAX_BYTES` 算出起点再 `seek`，不再是「`fs::read`
///    整文件读进来后切尾」——注释与实现现在才是同一件事。
/// 2. **一次取值、一处判据**：旧实现拿 `metadata().len()` 判大小、拿 `bytes.len()` 做切片，
///    两次取值之间文件被外部截短（轮动/手工删）时 `bytes.len() - 524288` 直接**下溢 panic**；
///    现在窗口起点由同一个 `size` 用 `saturating_sub` 算出，读多少都按实际字节处理。
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
    // 「没有这份日志」不是错误：交空串（命令层/日志页按空内容呈现）
    let mut f = match fs::File::open(&file) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let size = match f.metadata() {
        Ok(m) => m.len(),
        Err(_) => return String::new(),
    };
    let start = read_window_start(size);
    if start > 0 && f.seek(SeekFrom::Start(start)).is_err() {
        return format!("读取日志失败: 无法定位到末尾窗口 {start}");
    }
    let want = ((size - start) as usize).min(LOG_READ_MAX_BYTES as usize);
    let mut buf = Vec::with_capacity(want);
    if let Err(e) = f.read_to_end(&mut buf) {
        return format!("读取日志失败: {e}");
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    if start == 0 {
        return text;
    }
    // 窗口切在行中间时丢掉那一截：交出去半行会让日志页第一行看着像乱码
    match text.find('\n') {
        Some(idx) => text[idx + 1..].to_string(),
        None => text,
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
        // R6b-L02（v7.2 C11）：引擎级裁剪一律回收站优先（AGENTS §3，与
        // delete_manifest / restore_pack 同口径）；reparse 件跳过——链接件进
        // 回收站等于把它指向的实体卷进来。回收站失败不回退永久删。
        if mtime < cutoff {
            let safe = fs::symlink_metadata(entry.path())
                .map(|m| m.is_file() && !crate::engine::protect::is_reparse(&m))
                .unwrap_or(false);
            if safe && trim_finder::scan::recycle::send_to_trash_os(entry.path().as_os_str()).is_ok() {
                removed += 1;
            }
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

    /// 测试进程**不许**落盘（2026-10-02 用户拿日志页截图来问的那个问题：测试夹具
    /// `evil.reg` / `C:\Windows` / `伪造的一行` 全灌进了应用真正的日志里）。
    ///
    /// 这条用例钉的是闸门本身：谁把 `log_sink_enabled` 的判据删了或反转了，这里立刻红 ——
    /// 否则污染会**静默**回来（所有用例照样全绿，用户那边日志又脏了）。
    #[test]
    fn 测试进程不落盘() {
        assert!(cfg!(test), "本用例自身就该在测试构建里");
        assert!(!log_sink_enabled(), "测试进程打开了生产日志落盘");
        // 返回行照旧（既有用例全靠返回值断言格式/截断/换行注入）
        let line = write_log("error", "闸门自检");
        assert!(line.starts_with('[') && line.ends_with('\n') && line.contains("闸门自检"));
    }

    /// R6b-M07：清洗必须在 `write_log` 这个**唯一行生产者**里做，而不是只在某条通道上。
    /// 判红自证：把 write_log 头部的 `sanitize_log_message` 去掉 ⇒ 第一、二条断言红
    /// （伪造行穿过去）；把 `sanitize_log_level` 去掉 ⇒ 第三条红（级别位被自造）。
    #[test]
    fn 原始入口清洗封住伪造日志行() {
        // ① 换行注入：一条消息想冒充三行
        let evil = "真消息\n[2099-01-01 00:00:00] [ERROR] 伪造的一行\n[2099-01-01 00:00:01] [ERROR] 还有一行";
        let line = write_log("error", evil);
        assert_eq!(
            line.matches('\n').count(),
            1,
            "一条日志必须只有一个结尾换行，实得 {line:?}"
        );
        assert!(line.ends_with('\n') && !line[..line.len() - 1].contains('\n'), "行内不得再有换行: {line:?}");
        // 内容里的 [ERROR] 字样只是文本：它可以留着，但不得因此多出一行
        assert_eq!(line.matches("\n[").count(), 0, "不得出现被拆出来的第二行: {line:?}");

        // ② NUL / C0 控制符同样不得进日志行
        let nulled = write_log("warn", "前\x00中\x01后\r\n尾巴");
        assert!(!nulled.contains('\0') && !nulled.contains('\x01'), "控制符必须被换成空格: {nulled:?}");
        assert_eq!(nulled.matches('\n').count(), 1, "CR/LF 组合也不得多出行: {nulled:?}");

        // ③ level 白名单：任意串不得原样进 [LEVEL] 位
        let forged = write_log("CRITICAL] [2099-01-01", "x");
        assert!(forged.contains("[INFO] "), "非白名单 level 必须回落 INFO，实得 {forged:?}");
        assert_eq!(forged.matches('[').count(), 2, "只该有「时间」与「级别」两个方括号: {forged:?}");
        assert_eq!(forged.matches('\n').count(), 1, "级别位里的 ] [ 也不得多出行: {forged:?}");

        // ④ 三个合法级别原样通过（现算全仓直调点只用这三个，白名单不改变既有行为）
        for (lvl, want) in [("info", "[INFO]"), ("warn", "[WARN]"), ("error", "[ERROR]")] {
            let l = write_log(lvl, "内容");
            assert!(l.contains(want), "{lvl} 必须原样进级别位，实得 {l}");
        }
    }

    /// 清洗函数的两条硬性质：幂等（命令层再套一层上限不会重复追加截断标记）、
    /// 上限只在越界时留一次痕迹。
    #[test]
    fn 清洗幂等且长度上限留一次痕迹() {
        let big = "x".repeat(1500);
        let once = sanitize_log_message(&big, 1000);
        assert!(once.ends_with("…（已截断）"), "截断要留痕迹");
        assert_eq!(once.chars().count(), 1006, "1000 字符 + 6 字符标记，多一位少一位都算口径变了");
        let twice = sanitize_log_message(&once, 1000);
        assert_eq!(once, twice, "清洗必须幂等：命令层与 write_log 各套一次不得出现两个截断标记");
        // usize::MAX = 只清洗不定长（内部诊断消息不砍长度）
        let long = "路径 ".repeat(5000);
        assert!(sanitize_log_message(&long, usize::MAX).chars().count() > 1000, "内部调用点不得被边界上限砍掉");
        // 折叠与去空白口径与既有通道一致（这两条向量来自命令层用例，两侧同判据）
        assert_eq!(sanitize_log_message("  a\t\rb   c  ", 100), "a b c");
        assert_eq!(sanitize_log_level(" WARN "), "warn");
        assert_eq!(sanitize_log_level("whatever"), "info");
    }

    /// R6b-M08：刷盘失败的行必须**回到队列**而不是整批蒸发；回队有上限、超限裁最旧。
    /// 判红自证：把 `merge_queue_capped` 改成 `*q = rows`（丢旧）或 `q.extend` 不裁
    /// （无上限）都会红；旧实现是失败即 `return` 丢弃，第一条断言就红。
    #[test]
    fn 刷盘失败的行回到队列且不无界堆积() {
        let row = |tag: &str, i: usize| (PathBuf::from("app-x.log"), format!("{tag}{i}"));
        let mut q: Vec<(PathBuf, String)> = Vec::new();
        // 未超上限：整批回队，一条都不许少
        let dropped = merge_queue_capped(&mut q, (0..3).map(|i| row("A", i)).collect());
        assert_eq!(dropped, 0, "未超上限不得丢弃任何行");
        assert_eq!(
            q.iter().map(|r| r.1.as_str()).collect::<Vec<_>>(),
            vec!["A0", "A1", "A2"],
            "失败的行必须原样回到队列，实得 {q:?}"
        );
        // 逼近上限：再灌满一组 ⇒ 裁掉最旧的 A 组三行，保住最新尾部
        let dropped = merge_queue_capped(&mut q, (0..FLUSH_REQUEUE_MAX).map(|i| row("B", i)).collect());
        assert_eq!(q.len(), FLUSH_REQUEUE_MAX, "回队后总长必须钉在上限");
        assert_eq!(dropped, 3, "被裁掉的必须是超出的最旧 3 行，实得 {dropped}");
        assert_eq!(q.first().unwrap().1, "B0", "被丢的必须是最旧那批（A 组），不是最新那批");
        assert_eq!(
            q.last().unwrap().1,
            format!("B{}", FLUSH_REQUEUE_MAX - 1),
            "审计尾部必须保住"
        );
        assert!(!q.iter().any(|r| r.1.starts_with('A')), "被丢弃的行不得仍留在队列里");
    }

    /// R6b-L03 之一：窗口起点的算术。旧形状是 `bytes.len() - 524288` 的索引减法，
    /// 这里把同一件事改成 saturating 后必须由用例钉住边界——把 `saturating_sub`
    /// 换回 `-` 会让第一条断言在 debug 构建里直接 panic（判红，而不是打印 ✓）。
    #[test]
    fn 读取窗口起点在下溢边界取零() {
        assert_eq!(read_window_start(0), 0, "空文件不得算出负偏移");
        assert_eq!(read_window_start(LOG_READ_MAX_BYTES - 1), 0, "差一字节也在一窗之内");
        assert_eq!(read_window_start(LOG_READ_MAX_BYTES), 0, "恰好一窗：不截");
        assert_eq!(read_window_start(LOG_READ_MAX_BYTES + 1), 1, "超一字节就从 1 起步");
        assert_eq!(
            read_window_start(LOG_READ_MAX_BYTES * 3),
            LOG_READ_MAX_BYTES * 2,
            "多窗文件只留最后 512KB"
        );
    }

    /// R6b-L03 之二：真把一份超过窗口的日志写进 **lib 单测隔离数据根**（C08 的
    /// `app_data_dir()`），读回来的必须只是末尾窗口——头部哨兵不许出现、尾部最后一行
    /// 必须完整、返回值不超过 `LOG_READ_MAX_BYTES`。
    /// 判红自证：把实现改回「整文件读入但不过滤头部」⇒ 第二条断言红；改回索引减法 ⇒
    /// 样本小于窗口时 panic（这里另有一条「缺文件交空串」覆盖 Err 分支）。
    #[test]
    fn 读取只交末尾窗口且丢弃半行() {
        let date = "2000-01-02";
        let dir = paths::log_dir();
        std::fs::create_dir_all(&dir).expect("建日志目录");
        let file = dir.join(format!("app-{date}.log"));
        let _g = RemoveOnDrop(file.clone());
        let filler = "FILLER-line-to-pad-the-window-out\n";
        let body = format!(
            "HEAD-Sentinel\n{}TAIL-LAST-LINE\n",
            filler.repeat(40_000usize)
        );
        assert!(
            body.len() as u64 > LOG_READ_MAX_BYTES * 2,
            "样本必须明显超过两个窗口才测得到截断，实得 {} 字节",
            body.len()
        );
        std::fs::write(&file, body.as_bytes()).expect("写日志");

        let got = read_log(Some(date));
        assert!(!got.contains("HEAD-Sentinel"), "头部哨兵被交出来了 ⇒ 读的是整文件而非窗口");
        assert!(got.ends_with("TAIL-LAST-LINE\n"), "尾部最后一行必须完整");
        assert!(
            (got.len() as u64) <= LOG_READ_MAX_BYTES,
            "返回值必须落在一窗之内，实得 {} 字节",
            got.len()
        );
        assert!(
            got.starts_with(filler.trim_end_matches('\n')),
            "窗口起点切在行中间时半行要被丢掉，第一行必须是整行: {:?}",
            got.chars().take(40).collect::<String>()
        );

        // 小文件（不足一窗）必须整份交出，且不得被当成截断而吃掉首行
        let small = dir.join("app-2000-01-03.log");
        let _gs = RemoveOnDrop(small.clone());
        std::fs::write(&small, "第一行\n第二行\n").expect("写小日志");
        assert_eq!(read_log(Some("2000-01-03")), "第一行\n第二行\n", "一窗之内不截不丢行");

        // 没有这份日志不是错误：交空串（旧口径如此，命令层/日志页按空内容呈现）
        assert_eq!(read_log(Some("1999-12-31")), "", "缺文件必须交空串而不是错误串");
        // 日期形态白名单先于任何磁盘访问
        assert!(read_log(Some("../../app-x")).starts_with("读取日志失败"), "路径穿越日期必须拒");
    }

    /// 用例夹具自清理守卫：断言 panic 也要把写出去的日志文件收掉。
    struct RemoveOnDrop(PathBuf);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
}
