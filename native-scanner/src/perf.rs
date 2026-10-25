//! perf.rs — v3.7.1 Rust 化批次（方案：update history/9.23/Trim-Rust化方案-R1R2R3-v2-2026-09-23.md）
//!
//! 四个子命令（契约以现有渲染层读取字段为准，v2 铁律）：
//!   diskbench   磁盘测速（nobuf 默认，QD=每线程在途上限，OVERLAPPED event 等待）
//!   ov-metrics  系统概览高频指标（字段与 `vendor/upstream-js/src/scripts-powershell/overview-scripts.js:60-74` 一一对应）
//!   net-sample  实时网速采样（--daemon 常驻，每秒一行 JSON，差分在 Rust）
//!   mem-clean   内存清理（NtSetSystemInformation 逐字平移，双特权，82/84 黑名单继承）
//!
//! 通用：argv 传参；stdout 逐行；进度行 + 最终单行 JSON；单项失败不中断；fail-closed 不假成功。

use crate::json_escape;
use std::io::Write as _;

// 手写 ntdll / kernel32 / advapi32 补充声明已集中到 `crate::util::ffi`（v3 C-3）；
// 本文件不再自建 extern 块（windows-sys 覆盖不到或类型 Hunt 成本高的少量函数）。
use crate::util::ffi::{
    NtQuerySystemInformation, NtSetSystemInformation, QueryPerformanceCounter,
    QueryPerformanceFrequency, RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RtlGetVersion,
};

const SYS_PROCESSOR_PERFORMANCE_INFORMATION: u32 = 8;
/// `SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION` 单结构体字节数（按逻辑处理器数返回 N 份）
const CPU_ITEM_LEN: usize = 48;
/// 缓冲不够大（Nt* 的「先给我长度」回执）
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;

/// 输出一行到 stdout；管道断裂（父进程退出）返回 Err
fn out_line(s: &str) -> std::io::Result<()> {
    let mut o = std::io::stdout().lock();
    o.write_all(s.as_bytes())?;
    o.write_all(b"\n")?;
    o.flush()
}

fn arg_value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    let k = format!("--{}", key);
    args.iter().position(|a| a == &k).and_then(|i| args.get(i + 1)).map(|s| s.as_str())
}

/// 墙钟毫秒：**只用于对外输出的时间戳**（`net-sample` 的 `t` 字段，渲染层按 epoch ms 展示）
fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

// ---- 单调时钟（审查 v2-L18）----
// 原来测速的阶段截止、收尾硬限、耗时统计全用墙钟 `SystemTime::now()`：
// NTP 前跳会让「4 秒阶段」瞬间收尾、后跳会让 `now >= deadline` 长期不成立，
// 而结果照样标 `measured:true` —— 计时口径必须与系统时间解耦，所以走 QPC。
// 手写 kernel32 声明：windows-sys 的 `Win32_System_Performance` feature 本 crate 未开
// （红线：不新开 feature），且这两个函数无类型负担。
// 声明已上移 crate::util::ffi（v3 C-3）。

/// (起点计数, 频率)，进程内只取一次；`None` = QPC 不可用（理论不发生，留回落）
static QPC_BASE: std::sync::OnceLock<Option<(i64, i64)>> = std::sync::OnceLock::new();

fn qpc_base() -> Option<(i64, i64)> {
    *QPC_BASE.get_or_init(|| unsafe {
        let mut freq: i64 = 0;
        let mut cnt: i64 = 0;
        if QueryPerformanceFrequency(&mut freq) == 0 || freq <= 0 {
            return None;
        }
        if QueryPerformanceCounter(&mut cnt) == 0 {
            return None;
        }
        Some((cnt, freq))
    })
}

/// 单调纳秒（自进程首次取值起算）
fn mono_ns() -> u128 {
    match qpc_base() {
        Some((base, freq)) => unsafe {
            let mut cnt: i64 = 0;
            if QueryPerformanceCounter(&mut cnt) == 0 {
                return now_ms() as u128 * 1_000_000; // 回落墙钟：宁可退化，不 panic
            }
            (cnt - base).max(0) as u128 * 1_000_000_000 / freq as u128
        },
        // QPC 不可用时退回墙钟（不影响正确性判断，只丢掉「不受调时影响」这一条）
        None => now_ms() as u128 * 1_000_000,
    }
}

/// 单调毫秒：所有「截止/耗时」判定用它，不用 `now_ms()`
fn mono_ms() -> u64 {
    (mono_ns() / 1_000_000) as u64
}
// v3 C-1：宽字符串转换统一走 crate::util::to_wide（原本文件副本已删）。
use crate::util::to_wide as wide;
fn utf16_str(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

// ============================ R1: diskbench ============================
// 契约（v2 §2.2）：进度行 __PROG__{"phase","percent"}；最终 JSON 必含
//   sequentialRead/Write、randomRead/Write、iops、latency、blockSize、queueDepth、
//   threads、measured:true。拍板：QD=每线程在途上限；nobuf 默认。

const BENCH_BLOCKS: [u64; 3] = [4096, 65536, 1048576];
const BENCH_DURATIONS: [u64; 3] = [4, 8, 16];
const BENCH_QD: [usize; 3] = [1, 8, 32];
const BENCH_THREADS: [usize; 3] = [1, 4, 8];
const BUF_CAP_PER_THREAD: usize = 16 * 1024 * 1024;
const SEQ_WINDOW_TOTAL: u64 = 256 * 1024 * 1024;
const RAND_WINDOW_TOTAL: u64 = 128 * 1024 * 1024;

/// 数值参数解析（P1-6E①）：「没给」与「给了但不是数字」都回落默认，但后者**必须留痕**。
/// 旧写法 `.parse().unwrap_or(默认)` 让两种情况完全同形，报告上看不出任何异常。
fn parse_bench_arg(raw: Option<&str>, default: u64, name: &str, warn: &mut Vec<String>) -> u64 {
    let Some(v) = raw else { return default };
    match v.parse::<u64>() {
        Ok(n) => n,
        Err(_) => {
            warn.push(format!("{name}={v} 不是数字，已按默认 {default} 执行"));
            default
        }
    }
}

/// 白名单外的取值回落默认，但**必须留一条告警**（P1-6E①）。
/// 抽成函数只为了让它可单测：`--qd 3` 这种「不在档位里」的写法与「畸形字符串」一样，
/// 都不许悄悄变成 qd=1 的实测数字。
fn clamp_to_whitelist(
    got: usize,
    allowed: &[usize],
    default: usize,
    name: &str,
    warn: &mut Vec<String>,
) -> usize {
    if allowed.contains(&got) {
        return got;
    }
    warn.push(format!("{name}={got} 不在档位 {:?} 内，已按 {default} 执行", allowed));
    default
}

/// 告警进**回执 JSON**（P1-6E 的验收口径：「不能只写 stderr」）。
/// 这个 crate 的两个入口共用 `diskbench_core`：CLI 把返回值原样写成 stdout 末行，
/// Tauri 侧走 `diskbench_json` 直接拿返回值 —— 所以往 stdout 打告警行，lib 调用方
/// 一个字也收不到，等于没留痕。空清单必须整段缺席，不能塞 `"warn":[]` 骗解析端。
fn bench_warn_field(warn: &[String]) -> String {
    if warn.is_empty() {
        return String::new();
    }
    let items: Vec<String> = warn.iter().map(|w| format!("\"{}\"", json_escape(w))).collect();
    format!(",\"warn\":[{}]", items.join(","))
}

/// 进度行：`{"phase","percent"}`（**不含** `__PROG__` 前缀）。
/// CLI 包装补前缀直写 stdout，Tauri 侧把同一 JSON 直接派发给前端事件。
fn bench_progress(on_progress: &mut dyn FnMut(&str), phase: &str, percent: u64) {
    on_progress(&format!("{{\"phase\":\"{}\",\"percent\":{}}}", phase, percent.min(100)));
}

/// 4K 偏移表（扇区对齐）+ xorshift64 洗牌；时长制循环环形复用
fn build_offset_map(file_size: u64, io_size: u64) -> Vec<u64> {
    let n = (file_size / io_size) as usize;
    let mut map: Vec<u64> = (0..n as u64).map(|i| i * io_size).collect();
    let mut s: u64 = 0x9E3779B97F4A7C15 ^ (n as u64).wrapping_mul(0xA0761D6478BD642F);
    if s == 0 { s = 0xDEADBEEF; }
    for i in (1..n).rev() {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        let j = (s % (i as u64 + 1)) as usize;
        map.swap(i, j);
    }
    map
}

/// 单线程一个阶段。kind: 0=seq write,1=seq read,2=rand read,3=rand write
/// 返回 (字节数, 完成请求数, 端到端累计时延 ns)
unsafe fn bench_phase(
    handle: *mut core::ffi::c_void,
    kind: u8,
    io_size: usize,
    deadline_ms: u64,
    qd: usize,
    seq_size: u64,
    offsets: &[u64],
) -> (u64, u64, u128) {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, WAIT_OBJECT_0};
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};

    let mut ovl: Vec<OVERLAPPED> = Vec::with_capacity(qd);
    let mut events: Vec<*mut core::ffi::c_void> = Vec::with_capacity(qd);
    let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(qd);
    let mut in_flight: Vec<(u64, u128)> = Vec::with_capacity(qd);
    let mut ring: usize = 0;
    let mut next_seq: u64 = 0;
    let (mut bytes_done, mut ops_done, mut lat_total) = (0u64, 0u64, 0u128);
    for _ in 0..qd {
        let mut o: OVERLAPPED = std::mem::zeroed();
        let ev = CreateEventW(std::ptr::null(), 0, 0, std::ptr::null());
        o.hEvent = ev;
        events.push(ev);
        ovl.push(o);
        bufs.push(vec![0u8; io_size]);
        in_flight.push((u64::MAX, 0));
    }
    let mut submit = |i: usize, ovl: &mut Vec<OVERLAPPED>, bufs: &mut Vec<Vec<u8>>, in_flight: &mut Vec<(u64, u128)>| {
        let off = if kind <= 1 { let o = next_seq % seq_size; next_seq += io_size as u64; o }
                  else { let o = offsets[ring % offsets.len()]; ring += 1; o };
        // OVERLAPPED.Anonymous 是 union：Offset/OffsetHigh 在 OVERLAPPED_0_0 变体里（windows-sys 0.59）
        ovl[i].Anonymous.Anonymous.Offset = off as u32;
        ovl[i].Anonymous.Anonymous.OffsetHigh = (off >> 32) as u32;
        in_flight[i] = (off, mono_ns());
        let ok = if kind == 0 || kind == 3 {
            WriteFile(handle, bufs[i].as_ptr(), io_size as u32, std::ptr::null_mut(), &mut ovl[i])
        } else {
            ReadFile(handle, bufs[i].as_mut_ptr(), io_size as u32, std::ptr::null_mut(), &mut ovl[i])
        };
        if ok == 0 && GetLastError() != 997 {
            in_flight[i].0 = u64::MAX; // 提交即失败：标记跳过
            SetEvent(events[i]);
        }
    };
    for i in 0..qd { submit(i, &mut ovl, &mut bufs, &mut in_flight); }
    loop {
        if mono_ms() >= deadline_ms { break; }
        let n = events.len() as u32;
        let wait = WaitForMultipleObjects(n, events.as_ptr(), 0, 200);
        if wait < WAIT_OBJECT_0 || wait >= WAIT_OBJECT_0 + n { continue; }
        let i = (wait - WAIT_OBJECT_0) as usize;
        let mut transferred: u32 = 0;
        let _ = GetOverlappedResult(handle, &ovl[i], &mut transferred, 0);
        if in_flight[i].0 != u64::MAX {
            lat_total += mono_ns().saturating_sub(in_flight[i].1);
            bytes_done += transferred as u64;
            ops_done += 1;
        }
        if mono_ms() < deadline_ms {
            submit(i, &mut ovl, &mut bufs, &mut in_flight);
        } else {
            in_flight[i].0 = u64::MAX;
        }
    }
    // 收尾：等全部在途落定（截止后仍在途的请求很小，1s 足够）
    let hard = mono_ms() + 1000;
    let mut remaining: Vec<usize> = (0..qd).collect();
    while !remaining.is_empty() && mono_ms() < hard {
        let hs: Vec<*mut core::ffi::c_void> = remaining.iter().map(|&i| events[i]).collect();
        let n = hs.len() as u32;
        let wait = WaitForMultipleObjects(n, hs.as_ptr(), 1, 300);
        if wait < WAIT_OBJECT_0 || wait >= WAIT_OBJECT_0 + n { break; }
        let i = remaining.remove((wait - WAIT_OBJECT_0) as usize);
        let mut transferred: u32 = 0;
        let _ = GetOverlappedResult(handle, &ovl[i], &mut transferred, 0);
        if in_flight[i].0 != u64::MAX {
            lat_total += mono_ns().saturating_sub(in_flight[i].1);
            bytes_done += transferred as u64;
            ops_done += 1;
        }
    }
    for ev in events { let _ = CloseHandle(ev); }
    (bytes_done, ops_done, lat_total)
}

unsafe fn open_bench_file(path: &str, size: u64, nobuf: bool) -> *mut core::ffi::c_void {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, SetEndOfFile, SetFilePointer, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_FLAG_OVERLAPPED, OPEN_ALWAYS,
    };
    let p = wide(path);
    let flags = FILE_FLAG_OVERLAPPED | if nobuf { 0x2000_0000u32 /*FILE_FLAG_NO_BUFFERING*/ } else { 0 };
    let h = CreateFileW(
        p.as_ptr(),
        0x8000_0000u32 | 0x4000_0000u32, // GENERIC_READ | GENERIC_WRITE
        (FILE_SHARE_READ | FILE_SHARE_WRITE) as u32,
        std::ptr::null(),
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | flags,
        0 as *mut _,
    );
    if h.is_null() || h as isize == -1 { return std::ptr::null_mut(); }
    let mut hi = (size >> 32) as i32;
    SetFilePointer(h, size as i32, &mut hi, 0); // FILE_BEGIN，lpDistanceToMoveHigh: *mut i32
    if SetEndOfFile(h) == 0 {
        windows_sys::Win32::Foundation::CloseHandle(h);
        return std::ptr::null_mut();
    }
    h
}

/// 磁盘测速核心：Ok = 最终结果 JSON 文本；Err = 失败原因消息。
/// CLI 与 lib 共用**同一实现**（`run_diskbench` 只做 stdout 写回包装，不得另写一份）。
fn diskbench_core(args: &[String], on_progress: &mut dyn FnMut(&str)) -> Result<String, String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Storage::FileSystem::{DeleteFileW, GetDiskFreeSpaceW};
    let dir = match arg_value(args, "path") {
        Some(p) => p.trim_end_matches('\\').to_string(),
        None => return Err("缺少 --path".to_string()),
    };
    // P1-6E①：参数「畸形」与「没给」是两件事。旧写法先 `parse().unwrap_or(默认)` 再查白名单，
    // 于是 `--qd abc` 与「用户没写 --qd」完全同形 —— 明明要的是高队列深度，实测回来的
    // 却是 qd=1 的数字且没有任何痕迹，报告上看不出错。现在四个数值参数统一走 parse_arg：
    // 回落默认照旧（不改变可跑性），但**必须留下一条告警**，由 `@@PERFWARN@@` 透到输出里。
    let mut arg_warn: Vec<String> = Vec::new();
    let block = parse_bench_arg(arg_value(args, "block-bytes"), 1048576, "block-bytes", &mut arg_warn);
    let duration = parse_bench_arg(arg_value(args, "duration"), 8, "duration", &mut arg_warn);
    let qd_req = parse_bench_arg(arg_value(args, "qd"), 1, "qd", &mut arg_warn) as usize;
    let th_req = parse_bench_arg(arg_value(args, "threads"), 1, "threads", &mut arg_warn) as usize;
    let mode = arg_value(args, "mode").unwrap_or("nobuf").to_string();
    if !BENCH_BLOCKS.contains(&block) || !BENCH_DURATIONS.contains(&duration) {
        return Err("非法参数（block/duration 不在白名单）".to_string());
    }
    let qd_req = clamp_to_whitelist(qd_req, &BENCH_QD, 1, "qd", &mut arg_warn);
    let threads = clamp_to_whitelist(th_req, &BENCH_THREADS, 1, "threads", &mut arg_warn);
    // 非固定盘 / 探测失败回落 buf（nobuf 在内存盘、网络盘不可靠）
    let mut nobuf = mode != "buf";
    unsafe {
        // 审查 v2-L18：原来写 `&dir[..3.min(dir.len())]` 按**字节**切片取盘符根，
        // 首 3 字节落在多字节字符中间会直接 panic（CLI 直调 `--path` 可达）。
        // 现在只在确认是 `X:` 形态时取前两个 ASCII 字节，其余一律不判、保守回落 buf。
        let root: String = match drive_root_prefix(&dir) {
            Some(p) => format!("{p}\\"),
            None => dir.clone(),
        };
        let (mut spc, mut bps, mut fc, mut tc) = (0u32, 0u32, 0u32, 0u32);
        if GetDiskFreeSpaceW(wide(&root).as_ptr(), &mut spc, &mut bps, &mut fc, &mut tc) == 0 { nobuf = false; }
    }
    // QD=每线程在途上限；受每线程 16MB 缓冲上限折算（guide 说明）
    let qd_eff = qd_req.max(1).min((BUF_CAP_PER_THREAD / block as usize).max(1));
    let bench_dir = resolve_bench_dir(&dir, arg_value(args, "bench-dir"))?;
    bench_progress(on_progress, "seqwrite", 0);

    unsafe {
        let _ = std::fs::create_dir_all(&bench_dir);
        let seq_per = (SEQ_WINDOW_TOTAL / threads as u64 / block).max(8) * block;
        let rand_per = ((RAND_WINDOW_TOTAL / threads as u64) / 4096).max(8) * 4096;
        // 文件名带 PID + 单调时钟戳（审查 v2-M6）：超时后原生工作线程**仍在跑完整轮**
        // （上层只是不再等它），同名文件会让下一轮和这一轮抢同一块盘、互相把对方的
        // 字节数算进自己的结果。不同名至少保证两轮的测量对象互不相干。
        let stamp = format!("{}_{}", std::process::id(), mono_ms());
        let mut handles: Vec<*mut core::ffi::c_void> = Vec::new();
        let mut files: Vec<String> = Vec::new();
        for t in 0..threads {
            let name = format!("tb_{t}_{stamp}.bin");
            let full = format!("{}\\{}", bench_dir, name);
            let h = open_bench_file(&full, seq_per.max(rand_per), nobuf);
            if h.is_null() { break; }
            handles.push(h);
            files.push(full);
        }
        if handles.is_empty() {
            for f in &files { DeleteFileW(wide(f).as_ptr()); }
            return Err("测试文件创建失败".to_string());
        }
        // 审查 v2-M6：句柄数不足时**不能**继续 —— 原实现 `break` 后照样往下测，
        // 最终 JSON 里却写请求的 `threads`（请求 8 线程实开 1 线程），
        // 于是测速历史里出现口径不自洽的曲线，且 `measured:true` 让上层护栏永不触发。
        // 开测前先判一次：没必要为注定作废的结果再跑满一整轮（duration 最长 16s×4 段）。
        if let Err(msg) = bench_setup_verdict(handles.len(), threads) {
            let opened = handles.len();
            let _ = opened;
            for h in handles { let _ = CloseHandle(h); }
            for f in &files { DeleteFileW(wide(f).as_ptr()); }
            return Err(msg);
        }
        let t0 = mono_ms();
        let phase_ms = duration * 1000;
        let half_ms = duration * 500;
        // HANDLE 是 *mut c_void 不满足 Send；edition2021 精确捕获会连字段位置一起抓，
        // 包装体也绕不开 → 跨线程一律先转 usize（Send），闭包内再转回 HANDLE（同进程内安全）
        let run_stage = |kind: u8, io: usize, ms: u64, seq: u64, offs: &[u64]| -> (u64, u64, u128) {
            let start = mono_ms();
            let hs: Vec<usize> = handles.iter().map(|h| *h as usize).collect();
            std::thread::scope(|s| {
                let mut js = Vec::new();
                for hz in hs {
                    js.push(s.spawn(move || bench_phase(hz as *mut core::ffi::c_void, kind, io, start + ms, qd_eff, seq, offs)));
                }
                let mut acc = (0u64, 0u64, 0u128);
                for j in js {
                    let (b, o, l) = j.join().unwrap_or((0, 0, 0));
                    acc.0 += b; acc.1 += o; acc.2 += l;
                }
                acc
            })
        };
        let seq_w = run_stage(0, block as usize, phase_ms, seq_per, &[]);
        bench_progress(on_progress, "seqwrite", 40);
        let seq_r = run_stage(1, block as usize, phase_ms, seq_per, &[]);
        bench_progress(on_progress, "seqread", 80);
        let offsets = build_offset_map(rand_per, 4096);
        let rd_r = run_stage(2, 4096, half_ms, rand_per, &offsets);
        bench_progress(on_progress, "randread", 90);
        let wr_r = run_stage(3, 4096, half_ms, rand_per, &offsets);
        bench_progress(on_progress, "randwrite", 100);
        let elapsed = mono_ms().saturating_sub(t0);

        // 口径（v2 §3.1）：MB/s 按真实阶段耗时；iops=4K 随机读 IOPS（保历史可比）；
        // latency=随机读单请求端到端平均（含排队），毫秒
        let mbs = |b: u64, ms: u64| b as f64 / (1024.0 * 1024.0) / (ms as f64 / 1000.0);
        let seq_write = mbs(seq_w.0, phase_ms);
        let seq_read = mbs(seq_r.0, phase_ms);
        let rand_read = mbs(rd_r.0, half_ms);
        let rand_write = mbs(wr_r.0, half_ms);
        let iops = rd_r.1 as f64 / (half_ms as f64 / 1000.0);
        let latency = if rd_r.1 > 0 { (rd_r.2 as f64 / rd_r.1 as f64) / 1e6 } else { 0.0 };
        // 审查 v2-M6：`measured:true` 以前是**无条件**写死的。盘被配额/只读/杀软拦下时
        // 每个阶段都是 0 次完成，输出却是 `0 MB/s 且 measured:true`，被当成一次真实测量
        // 写进测速历史（上层唯一的护栏就是 measured）。这里先判"到底测到没有"。
        let opened = handles.len();
        if let Err(msg) = bench_verdict(opened, threads, [seq_w.1, seq_r.1, rd_r.1, wr_r.1]) {
            for h in handles { let _ = CloseHandle(h); }
            for f in &files { DeleteFileW(wide(f).as_ptr()); }
            return Err(msg);
        }
        let result = format!(
            "{{\"measured\":true,\"sequentialRead\":{:.1},\"sequentialWrite\":{:.1},\"randomRead\":{:.1},\"randomWrite\":{:.1},\"iops\":{:.0},\"latency\":{:.3},\"blockSize\":{},\"queueDepth\":{},\"threads\":{},\"duration\":{},\"ioMode\":\"{}\",\"qdEffective\":{},\"elapsedMs\":{}}}{}",
            seq_read, seq_write, rand_read, rand_write, iops, latency, block, qd_req, opened, duration,
            if nobuf { "nobuf" } else { "buf" }, qd_eff, elapsed, bench_warn_field(&arg_warn)
        );
        // 失败分支（上面的 `Err(msg)`）不带 warn：那一轮的结果整份作废，调用方只看错误消息，
        // 再拼一条参数回落反而会把真正的失败原因挤掉。留痕只针对「这一轮确实出了数」。
        for h in handles { let _ = CloseHandle(h); }
        for f in &files { DeleteFileW(wide(f).as_ptr()); }
        Ok(result)
    }
}

/// 取 `X:` 形态的盘符前缀（两个 ASCII 字节 + 冒号），不是这个形态返回 `None`。
/// 审查 v2-L18：调用方要拿它拼盘符根去 `GetDiskFreeSpaceW`，原来的 `&dir[..3]`
/// 按字节切片会在多字节首字符上 panic。
fn drive_root_prefix(dir: &str) -> Option<&str> {
    let b = dir.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        Some(&dir[..2])
    } else {
        None
    }
}

/// 测速结果诚实性判定（纯函数，便于断言；审查 v2-M6）。
/// 要区分的是「测到了 0」与「根本没测成」：
///   · 建出来的句柄数少于请求数 ⇒ 线程数失真，`threads` 字段与历史曲线都不可比；
///   · 任一阶段 0 次完成 ⇒ 那一列是凭空写出来的 0，不是测量值（写失败被静默跳过的形态）。
/// 判 Err 之后上层（`commands/diskbench.rs`）唯一的护栏 `measured != true` 才会生效。
fn bench_verdict(opened: usize, requested: usize, ops_per_stage: [u64; 4]) -> Result<(), String> {
    bench_setup_verdict(opened, requested)?;
    if ops_per_stage.iter().all(|o| *o == 0) {
        return Err("四个阶段没有任何一次 IO 完成，测速未成功".to_string());
    }
    if let Some(i) = ops_per_stage.iter().position(|o| *o == 0) {
        const NAMES: [&str; 4] = ["顺序写", "顺序读", "随机读", "随机写"];
        return Err(format!("{}阶段没有完成任何 IO，本轮测速结果不完整", NAMES[i]));
    }
    Ok(())
}

/// 开测前的那一半判定（句柄建立阶段）：不值得为注定作废的结果再跑满一整轮。
fn bench_setup_verdict(opened: usize, requested: usize) -> Result<(), String> {
    if opened == 0 {
        return Err("测试文件创建失败".to_string());
    }
    if opened != requested {
        return Err(format!("测试文件只建成 {opened}/{requested} 个，本轮测速作废"));
    }
    Ok(())
}

/// 测速目录名（真机取证 2026-10-25 CDP）。
///
/// 原生侧原先自己拼 `{}\Trim-DiskBench`，而主进程按 `Trim-DiskBench-<世代号>` 清理 ——
/// 两个名字**从来不是同一个**：清理动作落在一个原生根本不创建的目录上，残留没清掉、
/// 「按世代隔离」也没兑现，成功分支跑完就在用户目录下留一个空目录。
/// 现在目录名只有调用方这一个来源，原生只做「必须确实在 `--path` 之下」的形状校验
/// （原生只在这里建文件、删自己建的文件，不删目录，所以这不是删除面守卫，
///  而是防止调用方把测速写到盘上任意位置）。
fn resolve_bench_dir(dir: &str, raw: Option<&str>) -> Result<String, String> {
    let base = dir.trim_end_matches('\\');
    let got = match raw {
        Some(s) => s.to_string(),
        None => format!("{base}\\Trim-DiskBench"),
    };
    let (b, g) = (base.to_ascii_lowercase(), got.to_ascii_lowercase());
    if !g.starts_with(&b) || g.len() <= b.len() + 1 {
        return Err("非法参数（--bench-dir 必须位于 --path 之下）".to_string());
    }
    Ok(got)
}

/// 磁盘测速 **数据入口**（lib 直调）：args 与 CLI `diskbench` 参数一致；
/// 进度行 JSON（不含 `__PROG__` 前缀）逐个交给 `on_progress`；
/// 返回**最终结果 JSON 文本**（与 CLI 最后那行 JSON 完全一致）。
/// 参数非法 / 无 `--path` / 测试文件创建失败等错误分支返回 `{"error":"…"}`（可解析 JSON）。
pub fn diskbench_json(args: &[String], on_progress: &mut dyn FnMut(&str)) -> String {
    match diskbench_core(args, on_progress) {
        Ok(j) => j,
        Err(msg) => format!("{{\"error\":\"{}\"}}", json_escape(&msg)),
    }
}

/// CLI 入口（`finder diskbench …`）：进度行补 `__PROG__` 前缀直写 stdout，末尾写结果行；
/// 错误消息按原样直写 stdout 并以退出码 2 返回——行为与 lib 化前逐字一致。
pub fn run_diskbench(args: &[String]) -> i32 {
    match diskbench_core(args, &mut |p| { let _ = out_line(&format!("__PROG__{}", p)); }) {
        Ok(j) => { let _ = out_line(&j); 0 }
        Err(msg) => { let _ = out_line(&msg); 2 }
    }
}

// ============================ R2b: ov-metrics ============================
// 契约（v2 §2.4）：success/cpu(数字；首拍 null，主进程差分 cpuRaw)/memory{total,free,used,percent}/
//   disks[{name:"C:",label,total,free,used,percent}]/uptime/processes/system{caption,version,build,...}

/// CPU 原始计数（busy/idle，全部逻辑处理器求和）。返回 `None` = 这次没采到。
///
/// 审查 v2-M6：原来是固定缓冲 `[0u8; 64*48]`，而 `SystemProcessorPerformanceInformation`
/// 是**按逻辑处理器数**返回 N 份 48 字节结构体 ⇒ >64 核的机器必得
/// `STATUS_INFO_LENGTH_MISMATCH`，于是 `cpuRaw` 恒 null、概览页 CPU 永久 `--`；
/// 更要紧的是当时 `success` 无条件为 true，让本来能正常给出 CPU 的 PS 引擎**永不回落**。
/// 现在按 ReturnLength 重试一次，并把「采没采到」如实回给调用方。
unsafe fn cpu_raw_times() -> Option<(u64, u64)> {
    let mut buf: Vec<u8> = vec![0u8; CPU_ITEM_LEN * 64];
    let mut ret: u32 = 0;
    let mut st = NtQuerySystemInformation(
        SYS_PROCESSOR_PERFORMANCE_INFORMATION,
        buf.as_mut_ptr(),
        buf.len() as u32,
        &mut ret,
    );
    if st == STATUS_INFO_LENGTH_MISMATCH {
        let want = cpu_buf_retry_len(ret, buf.len())?;
        buf = vec![0u8; want];
        ret = 0;
        st = NtQuerySystemInformation(
            SYS_PROCESSOR_PERFORMANCE_INFORMATION,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut ret,
        );
    }
    if st != 0 {
        return None;
    }
    let n = (ret as usize).min(buf.len()) / CPU_ITEM_LEN;
    if n == 0 {
        return None;
    }
    let (mut busy, mut idle) = (0u64, 0u64);
    for i in 0..n {
        let rd = |o: usize| -> u64 {
            let mut v: u64 = 0;
            for k in 0..8 {
                v |= (buf[i * CPU_ITEM_LEN + o + k] as u64) << (8 * k);
            }
            v
        };
        let idle_t = rd(0);
        idle += idle_t;
        busy += rd(8).saturating_sub(idle_t) + rd(16);
    }
    Some((busy, idle))
}

/// 缓冲不足时按 `ReturnLength` 重算尺寸（纯函数，便于断言；审查 v2-M6）。
/// 返回 `None` = 不值得一试（没给出长度，或超过 4096 逻辑核这种荒谬值）。
/// 按整项对齐，避免尾端半条记录被当成一条读进累加（那会把随机字节算成时间）。
fn cpu_buf_retry_len(ret: u32, cur: usize) -> Option<usize> {
    let need = ret as usize;
    if need <= cur || need > CPU_ITEM_LEN * 4096 {
        return None;
    }
    Some(need.div_ceil(CPU_ITEM_LEN) * CPU_ITEM_LEN)
}

unsafe fn uptime_text() -> String {
    // GetTickCount64：含睡眠的开机时长；与 PS LastBootUpTime 墙钟口径的细微差异可接受
    let secs = windows_sys::Win32::System::SystemInformation::GetTickCount64() / 1000;
    let (days, hours, mins) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    if days > 0 { format!("{} 天 {} 小时 {} 分钟", days, hours, mins) }
    else if hours > 0 { format!("{} 小时 {} 分钟", hours, mins) }
    else { format!("{} 分钟", mins) }
}

/// RtlGetVersion 的返回码：STATUS_SUCCESS = 0。
/// 旧写法把返回码直接丢弃（N1b-L01）—— 失败时结构体还是全零，于是把
/// 「一个都不存在的版本号 0.0.0」当读数报给用户，界面上与真实读数同形。
const STATUS_SUCCESS: i32 = 0;

/// 版本三元组的三态换算（纯函数，便于断言；N1b-L01）。
/// `None` = 调用失败（返回码非 0）⇒ 出口必须给空串「没读到」，不许给 `0.0.0`。
fn os_version_fields(status: i32, major: u32, minor: u32, build: u32) -> Option<(String, String)> {
    if status != STATUS_SUCCESS {
        return None;
    }
    Some((format!("{major}.{minor}.{build}"), build.to_string()))
}

/// REG_SZ 取值的三态判定（纯函数，便于断言；N1b-L01）。
/// 三条出口彼此可分：`Ok(Some(s))` = 读到字符串值；`Ok(None)` = 值不存在/长度为 0；
/// `Err(())` = **类型不是 REG_SZ** 或不是良构 UTF-16（"形状不符"不是"读不到"，
/// 更不是"确实没有"——旧写法取了 `typ` 却不校验，REG_MULTI_SZ/REG_DWORD 被
/// lossy 解码成乱码照样返回 Some）。
fn reg_sz_value(typ: u32, bytes: &[u8]) -> Result<Option<String>, ()> {
    // REG_SZ = 1；REG_EXPAND_SZ 不在此列（ProductName 是 REG_SZ，
    // 顺手放开等于给这条通道多开一个没验过的形状）
    if typ != 1 {
        return Err(());
    }
    // 奇数字节 = 半条 UTF-16 码元（不是「值为空」，是形状不合）
    if bytes.len() % 2 != 0 {
        return Err(());
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // 去掉尾部 NUL（REG_SZ 常带一个终止符，也可能带两个）
    let end = u16s
        .iter()
        .rposition(|&c| c != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    if end == 0 {
        // 值存在但整串是终止符 = 「确实没有内容」，与下面的「解不出」是两回事
        return Ok(None);
    }
    match crate::util::decode_wide_exact(&u16s[..end]) {
        Some(s) => Ok(Some(s)),
        None => Err(()),
    }
}

unsafe fn os_version_strings() -> (String, bool, Option<String>, Option<String>) {
    // RtlGetVersion（避开 manifest 兼容清单）；caption 取注册表 ProductName（与 PS 的
    // 本地化 Caption 措辞可能有别，已知差异，见交付报告）
    // N1b-L01：缓冲区从 `[0u8; 276]` + 魔数偏移换成 `OSVERSIONINFOW`（尺寸/偏移在
    // util::ffi 里由 `const _` 编译期钉住，与同文件 RM_PROCESS_INFO 同一标准）；
    // 返回码必须查，失败 ⇒ version/build 走「没读到」（空串），不编造 0.0.0。
    let mut vi = crate::util::ffi::OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<crate::util::ffi::OSVERSIONINFOW>() as u32,
        dwMajorVersion: 0,
        dwMinorVersion: 0,
        dwBuildNumber: 0,
        dwPlatformId: 0,
        szCSDVersion: [0u16; 128],
    };
    let status = RtlGetVersion(&mut vi as *mut _ as *mut u8);
    // caption 的「读不到」不再伪装成读数：第二位 = 是否真读到 ProductName。
    // 「Windows」是刻意保留的通用兜底标签（界面上不空格子），但它**不进** okSystem 位。
    let product = reg_get_string(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
    let caption_read = matches!(product, Ok(Some(_)));
    let caption = product.unwrap_or(None).unwrap_or_else(|| "Windows".to_string());
    let fields = os_version_fields(status, vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    match fields {
        Some((version, build)) => (caption, caption_read, Some(version), Some(build)),
        // 读不到：None ⇒ 出口给空串（渲染层按「有值才拼这段」处理）
        None => (caption, caption_read, None, None),
    }
}

/// 取一个 REG_SZ 值。三条出口彼此可分（N1b-L01 三态口径）：
/// `Ok(Some(s))` = 读到字符串；`Ok(None)` = 键开到了但没有该值/值为空；
/// `Err(())` = 打不开键、或**形状不合**（类型不是 REG_SZ、半条码元、孤立代理项）。
/// 「形状不符」不是「读不到」更不是「确实没有」，旧写法三者折成一条 `Option` 且把
/// 非字符串类型 lossy 解码成乱码照样当 Some 返回。
/// 为什么这里不留痕：本函数被 ov-metrics 每 ~2.5s 调一次，写 stderr 会刷屏
/// （且 GUI 子系统里那几个字本来就蒸发）；形状不合统一并进 `okSystem` 位上抛。
unsafe fn reg_get_string(sub: &str, name: &str) -> Result<Option<String>, ()> {
    let sub_w = wide(sub);
    let name_w = wide(name);
    let mut hk: isize = 0;
    if RegOpenKeyExW(0x8000_0002u32 as isize /*HKLM*/, sub_w.as_ptr(), 0, 0x20019 /*KEY_READ*/, &mut hk) != 0 {
        return Err(());
    }
    let mut out = Err(());
    let (mut typ, mut len) = (0u32, 0u32);
    if RegQueryValueExW(hk, name_w.as_ptr(), std::ptr::null_mut(), &mut typ, std::ptr::null_mut(), &mut len) == 0 {
        if len == 0 || len >= 4096 {
            // len==0 = 值不存在（不是「解不出」）；len 荒谬（≥4096）按形状不合
            out = if len == 0 { Ok(None) } else { Err(()) };
        } else {
            let mut buf = vec![0u8; len as usize];
            let mut len2 = len;
            if RegQueryValueExW(hk, name_w.as_ptr(), std::ptr::null_mut(), &mut typ, buf.as_mut_ptr(), &mut len2) == 0 {
                out = reg_sz_value(typ, &buf[..(len2 as usize).min(buf.len())]);
            }
        }
    }
    RegCloseKey(hk);
    out
}

/// `success` 字段的口径（纯函数，便于断言；审查 v2-M6）。
/// 上层（`commands/overview.rs`）**唯一**的回落判据就是 `success != true`，而回落是一次性
/// 换成 PS 引擎的整套字段 ⇒ 取「CPU 原始计数与物理内存全部采到」，不是「至少一个子系统」：
/// 只要有一块缺失，PS 那份完整数据就更可信。否则 CPU 单独坏掉时护栏永不触发。
fn metrics_success(cpu_ok: bool, mem_ok: bool) -> bool {
    cpu_ok && mem_ok
}

/// ov-metrics **数据入口**（lib 直调）：返回单行 JSON，与 CLI 行协议同构。
///
/// 为什么要这个入口：该通道被渲染层按 ~2.5s 节奏轮询，CLI 形态每拍都要付一次
/// 进程创建成本；Tauri 侧改为函数直调后，CPU/内存开销与延迟都显著下降
/// （迁移方案 B 批「finder 内化为 lib 调用」）。
///
/// 注意：cpu 首拍恒为 null（本引擎无状态，差分由调用方缓存 cpuRaw 完成）——
/// 该语义是契约的一部分（渲染层首拍显示 `--`），lib 化不得"优化"掉。
///
/// `success` 口径（审查 v2-M6）：以前是字面量 `true`，任何子系统失败都照样报成功，
/// 于是上层唯一的回落护栏（`commands/overview.rs` 判 `success != true`）永不触发。
/// 现在取「CPU 原始计数与物理内存**全部**采到」才算成功 —— 不是「至少一个」：
/// 上层回落是一次性换整套字段，只要有一块缺失，PS 引擎那份完整数据就更可信。
/// 各子系统另有 `okCpu`/`okMemory`/`okDisks`/`okProcesses` 位，供上层将来按位决定回落粒度。
pub fn ov_metrics_json() -> String {
    unsafe {
        // CPU：finder 无状态 → 输出原始计数，主进程缓存差分；首拍 cpu=null（渲染层显示 --）
        let cpu_times = cpu_raw_times();
        let cpu_raw = cpu_times
            .map(|(b, i)| format!("{{\"busy\":{},\"idle\":{}}}", b, i))
            .unwrap_or_else(|| "null".to_string());
        let cpu_ok = cpu_times.is_some();
        // 内存（口径对齐 PS：TotalVisibleMemorySize/FreePhysicalMemory ≈ ullTotalPhys/ullAvailPhys）
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
        ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        // 审查 v2-M6：返回值原来没判 —— 调用失败时 `ms` 全零会被当成"内存 0 字节"如实报出去
        let mem_ok = GlobalMemoryStatusEx(&mut ms) != 0;
        let (total, free) = (ms.ullTotalPhys, ms.ullAvailPhys);
        let used = total.saturating_sub(free);
        let mem_percent = if total > 0 { used as f64 * 100.0 / total as f64 } else { 0.0 };
        // 磁盘（固定盘；name 必须 C: DeviceID 形式——渲染层按 ^c: 找主盘）
        // DRIVE_FIXED=3（windows-sys 0.59 收在 WindowsProgramming 小模块，为控制 feature 面就地声明）
        const DRIVE_FIXED: u32 = 3;
        use windows_sys::Win32::Storage::FileSystem::{
            GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
        };
        let mut disks: Vec<String> = Vec::new();
        let mask = GetLogicalDrives();
        // mask == 0 是调用失败（不是"真没有盘"），与"枚举到但没有固定盘"要分开记
        let disks_probed = mask != 0;
        for i in 0..26u32 {
            if mask & (1 << i) == 0 { continue; }
            let letter = (b'A' + i as u8) as char;
            let root = format!("{}:\\", letter);
            let rw = wide(&root);
            if GetDriveTypeW(rw.as_ptr()) != DRIVE_FIXED { continue; }
            let (mut t, mut f) = (0u64, 0u64);
            if GetDiskFreeSpaceExW(rw.as_ptr(), std::ptr::null_mut(), &mut t, &mut f) == 0 { continue; }
            let mut vol = [0u16; 261];
            GetVolumeInformationW(rw.as_ptr(), vol.as_mut_ptr(), 261, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0);
            let label = utf16_str(&vol);
            let used = t.saturating_sub(f);
            let percent = if t > 0 { used as f64 * 100.0 / t as f64 } else { 0.0 };
            disks.push(format!(
                "{{\"name\":\"{}:\",\"label\":\"{}\",\"total\":{},\"free\":{},\"used\":{},\"percent\":{:.1}}}",
                letter, json_escape(&label), t, f, used, percent
            ));
        }
        // 进程数（Toolhelp32 快照）
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        let mut processes: u32 = 0;
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        // 失败返回的是 INVALID_HANDLE_VALUE(-1) 而不是 null，只判 is_null 会把失败当成功
        let snap_ok = !snap.is_null() && (snap as isize != -1);
        if snap_ok {
            let mut pe: PROCESSENTRY32W = std::mem::zeroed();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut pe) != 0 {
                loop {
                    processes += 1;
                    if Process32NextW(snap, &mut pe) == 0 { break; }
                }
            }
            windows_sys::Win32::Foundation::CloseHandle(snap);
        }
        let (caption, caption_read, version, build) = os_version_strings();
        // N1b-L01：系统段单独给一位（与 okCpu/okMemory/okDisks/okProcesses 同族）。
        // 读不到时 version/build 一律是空串而不是「0.0.0」——空串 + okSystem:false 才是
        // 「没读到」的形状；将来上层要按位决定回落粒度就有可对账的入口（本轮宿主未消费）。
        let ok_system = caption_read && version.is_some() && build.is_some();
        let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
        let user = std::env::var("USERNAME").unwrap_or_default();
        let success = metrics_success(cpu_ok, mem_ok);
        let json = format!(
            "{{\"success\":{},\"okCpu\":{},\"okMemory\":{},\"okDisks\":{},\"okProcesses\":{},\"okSystem\":{},\"cpu\":null,\"cpuRaw\":{},\"memory\":{{\"total\":{},\"free\":{},\"used\":{},\"percent\":{:.1}}},\"disks\":[{}],\"uptime\":\"{}\",\"processes\":{},\"system\":{{\"caption\":\"{}\",\"version\":\"{}\",\"build\":\"{}\",\"computerName\":\"{}\",\"userName\":\"{}\"}}}}",
            success, cpu_ok, mem_ok, disks_probed && !disks.is_empty(), snap_ok, ok_system,
            cpu_raw, total, free, used, mem_percent, disks.join(","),
            json_escape(&uptime_text()), processes,
            json_escape(&caption),
            json_escape(version.as_deref().unwrap_or("")),
            json_escape(build.as_deref().unwrap_or("")),
            json_escape(&computer), json_escape(&user)
        );
        json
    }
}

/// CLI 入口（`finder ov-metrics`）：打印单行 JSON 后退出。
/// 行为与 lib 化前逐字一致（基线对拍见迁移方案附录 D）。
pub fn run_ov_metrics() -> i32 {
    let _ = out_line(&ov_metrics_json());
    0
}

// ============================ R2a: net-sample（daemon） ============================
// 契约（v2 §2.3）：{"t":ms,"adapters":[{"name":连接名,"desc":描述,"up":B/s,"down":B/s,"ifIndex":n}]}
// up=发送、down=接收（对齐 PS up=tx/down=rx）；首拍无基线不输出该卡；
// 过滤：OperStatus=Up + InterfaceType∈{6,71}（以太网/无线，等价 PhysicalAdapter 主路径），
//       排除 loopback(24)/tunnel(131)/propVirtual(53) 等。

/// 单帧网络采样器（lib 直调）：持有上一帧计数，逐帧返回与 CLI 行协议同构的 JSON。
///
/// 为什么需要它：`net-sample --daemon` 形态依赖一个常驻子进程；Tauri 侧改为
/// in-process 采样后，省掉常驻 pwsh/子进程，且生命周期由窗口侧统一管理
/// （空闲回收、退出清理）。**首拍无基线不输出该卡**的语义原样保留。
#[derive(Default)]
pub struct NetSampler {
    /// ifIndex → (上一帧 rx, 上一帧 tx, 采样时刻的**单调**毫秒)。
    /// 每帧结束按「本帧接口表里存在的 ifIndex」剪枝（审查 v2-L18），否则常驻形态下会无界增长。
    prev: std::collections::HashMap<u32, (u64, u64, u64)>,
    /// 最近一次「读接口表失败」的返回码（N1b-M06）。
    /// `sample_frame()` 的签名不许动（宿主 `commands/realtime.rs` 按 `Option` 分支），
    /// 所以这条三态只能**带外**可读：成功采样清 None，失败置码。
    /// 为什么必须留：旧形态把「GetIfTable2 挂了」与「这台机器没插网卡/首拍无基线」
    /// 一起折成 `None`，上层只能画「没有网络」，用户与排障者都无从分辨。
    last_error: Option<i32>,
}

impl NetSampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// 采一帧：返回 `Some(json行)`；首拍或当前无符合条件的物理网卡时返回 `None`
    /// （调用方据此保持"空列表而非报错"的上层语义）。
    /// **读表失败也返回 `None`**，但可用 [`NetSampler::last_error`] 取出 NTSTATUS 分辨
    /// 到底是哪一种（宿主把它写进日志即可，不需要改这条通道的形状）。
    pub fn sample_frame(&mut self) -> Option<String> {
        match read_if_table_frame(&mut self.prev) {
            Ok(line) => {
                self.last_error = None;
                line
            }
            Err(code) => {
                self.last_error = Some(code);
                None
            }
        }
    }

    /// 最近一次读接口表的失败码；`None` = 上一次读表是成功的（N1b-M06）。
    pub fn last_error(&self) -> Option<i32> {
        self.last_error
    }
}

/// `GetIfTable2` 返回 0 却给了空指针：调用约定上不该发生，但必须与「确无网卡」分开记。
/// 本 crate 不引新状态码，用固定的负值表示这一形态。
const NET_READ_NULL_TABLE: i32 = -1;

/// 读一次接口的失败判据（纯函数，便于断言；N1b-M06）。
/// `Some(code)` = 读不到（携带原始返回码）；`None` = 读到了表。
fn if_table_read_failure(rc: i32, table_null: bool) -> Option<i32> {
    if rc != STATUS_SUCCESS {
        return Some(rc);
    }
    if table_null {
        return Some(NET_READ_NULL_TABLE);
    }
    None
}

/// 读一次 GetIfTable2 并按上一帧差分出一行 JSON（CLI 与 lib 共用同一实现）。
/// 返回 `Err(码)` = 读表失败；`Ok(None)` = 读到了但本帧不产出（首拍无基线 / 无符合条件的物理网卡）；
/// `Ok(Some(line))` = 有帧。三态不许再折成一条 `Option`（N1b-M06）。
fn read_if_table_frame(
    prev: &mut std::collections::HashMap<u32, (u64, u64, u64)>,
) -> Result<Option<String>, i32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
    unsafe {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        let rc = GetIfTable2(&mut table);
        // GetIfTable2 报的是 WIN32_ERROR（u32），本模块的错误码通道是 i32
        // （`last_error()` 的契约，宿主按 `code as u32` 回打原始十六进制）。
        // WIN32_ERROR 的实际取值远小于 0x8000_0000，转换无损；
        // 通道里的负值只留给本 crate 自己的哨兵（NET_READ_NULL_TABLE = -1）。
        let rc = rc as i32;
        if let Some(code) = if_table_read_failure(rc, table.is_null()) {
            // 失败路径不 free：table 仍是 null（或调用方给的野值未产生），无泄漏
            return Err(code);
        }
        let now = now_ms();
        // 帧间差分走单调时钟（审查 v2-L18）：`t` 字段本身是对外契约里的 epoch 毫秒
        // （渲染层 new Date(t) 画时间轴），但拿墙钟做 dt 时，NTP 前跳会让 dt 虚大、
        // 速率凭空腰斩，后跳会让 dt 归零而被 max(1) 放大成一帧假尖峰。
        let mono = mono_ms();
        let mut adapters: Vec<String> = Vec::new();
        let mut present: Vec<u32> = Vec::new();
        // Table 在绑定里是 [MIB_IF_ROW2; 1] 定长数组，真实条目数是 NumEntries → 按指针步进
        let base = (*table).Table.as_ptr();
        for i in 0..(*table).NumEntries as usize {
            let row = &*base.add(i);
            // 本帧"接口表里存在"的 ifIndex 全部记下来（供结尾剪枝），与是否被过滤无关
            present.push(row.InterfaceIndex);
            if row.OperStatus != 1 { continue; } // IfOperStatusUp
            let if_type = row.Type; // IF_TYPE（6=以太网，71=802.11 无线）
            if !(if_type == 6 || if_type == 71) { continue; }
            // InterfaceAndOperStatusFlags（bit0=Hardware,1=Filter,2=Endpoint）：
            // 只保留硬件接口——对齐 Get-NetAdapter -Physical，排除 WFP 过滤器伪卡
            let flags = row.InterfaceAndOperStatusFlags._bitfield;
            // 实测（本机）：真卡 flags=0b101（Hardware+Endpoint）、WFP 伪卡=0b10（Filter）→
            // 只保留 HardwareInterface=1 且 FilterInterface=0
            if flags & 0x01 == 0 || flags & 0x02 != 0 { continue; }
            let (in_o, out_o) = (row.InOctets, row.OutOctets);
            if let Some(&(pi, po, pt)) = prev.get(&row.InterfaceIndex) {
                let dt = (mono.saturating_sub(pt)).max(1) as f64;
                let down = in_o.saturating_sub(pi) as f64 * 1000.0 / dt;
                let up = out_o.saturating_sub(po) as f64 * 1000.0 / dt;
                adapters.push(format!(
                    "{{\"name\":\"{}\",\"desc\":\"{}\",\"up\":{:.0},\"down\":{:.0},\"ifIndex\":{}}}",
                    json_escape(&utf16_str(&row.Alias)), json_escape(&utf16_str(&row.Description)),
                    up.max(0.0), down.max(0.0), row.InterfaceIndex
                ));
            }
            prev.insert(row.InterfaceIndex, (in_o, out_o, mono));
        }
        FreeMibTable(table as *mut core::ffi::c_void);
        // 审查 v2-L18：基线表原来**只插不清**。CLI 形态一退进程就没了，无所谓；
        // lib 直调形态下采样器常驻进程内（空闲回收前一直活着），拔掉/重启后换 ifIndex 的
        // 旧条目会永久留着 —— 既涨内存，也让"同一 ifIndex 被系统复用"时拿跨越很久的旧计数
        // 做差分，画出一个假尖峰。按本帧实际存在的接口集合剪枝。
        prev.retain(|k, _| present.contains(k));
        if adapters.is_empty() {
            // 读到表了但本帧不产出：首拍无基线，或确无符合条件的物理网卡。
            // 这一支与上面「读表失败」必须是两条出口（N1b-M06），调用方靠 last_error 分。
            return Ok(None);
        }
        Ok(Some(format!(
            "{{\"t\":{},\"adapters\":[{}]}}",
            now,
            adapters.join(",")
        )))
    }
}

pub fn run_net_sample(args: &[String]) -> i32 {
    let interval = arg_value(args, "interval").map(|v| v.parse::<u64>().unwrap_or(1000)).unwrap_or(1000).clamp(200, 10_000);
    let mut sampler = NetSampler::new();
    // 只在「失败码变化」的那一拍出声：本函数是 1s 一轮的常驻循环，
    // 每拍都写 stderr 会把真留痕淹掉（lib 直调侧由宿主读 last_error，不经过这里）。
    let mut reported: Option<i32> = None;
    loop {
        match sampler.sample_frame() {
            Some(line) => {
                if out_line(&line).is_err() { return 0; } // 管道断裂 = 父进程已退出
            }
            None => {
                let err = sampler.last_error();
                if err.is_some() && err != reported {
                    if let Some(code) = err {
                        eprintln!(
                            "[finder-warn] net-sample 读接口表失败（GetIfTable2 返回 0x{:08X}）——\
                             这与「本机没有可用网卡」是两种结论",
                            code as u32
                        );
                    }
                    reported = err;
                } else if err.is_none() {
                    reported = None;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(interval));
    }
}

// ============================ R3: mem-clean ============================
// 契约（v2 §2.5）：--items 恰好 5 个合法 id（含 standbyPriority0）；
// 输出 {"before","after","freed","results":[{"id","name","ok","status","elapsedMs"}]}；
// 顺序 workingSet(80,1)→modified(80,2)→standby(80,3)→standbyPriority0(80,4)→combine(130)；
// combine 修正（真机 v0.1.6 反馈）：旧实现误用 info class 87（= SystemSpecialPoolInformation，
// 内核以 C0000022 拒绝）+ 8 字节全零缓冲。Mem Reduct 同功能用的是
// SystemCombinePhysicalMemoryInformation = 130 + 零初始化的 MEMORY_COMBINE_INFORMATION_EX
// （x64 上 24 字节：HANDLE + SIZE_T + ULONG）。参考 phnt/ntexapi.h 与 memreduct src/main.c。
const SYS_COMBINE_PHYSICAL_MEMORY_INFORMATION: u32 = 130;

#[repr(C)]
struct MemoryCombineInformationEx {
    handle: *mut core::ffi::c_void,
    pages_combined: usize,
    flags: u32,
}
// 双特权；82/84 黑名单继承（不提供，不是失败）。

const MEM_ITEMS: [(&str, u32, u32, u8, &str); 5] = [
    ("workingSet", 80, 1, 0, "工作集"),
    ("modified", 80, 2, 0, "修改列表"),
    ("standby", 80, 3, 0, "备用列表"),
    ("standbyPriority0", 80, 4, 0, "低优先级备用列表"),
    ("combine", SYS_COMBINE_PHYSICAL_MEMORY_INFORMATION, 0, 1, "合并物理内存页"),
];

/// 把特权加进当前进程令牌。**返回 true 的含义是「真的加上了」**，不是
/// 「AdjustTokenPrivileges 没报错」——N1b-M06：`AdjustTokenPrivileges` 在请求的特权
/// 不在令牌里时**照样返回非 0**，只把 LastError 置成 `ERROR_NOT_ALL_ASSIGNED`，
/// 旧写法 `!= 0` 直接当成功，于是调用方把「没提权」当成「已提权」，
/// 而 `let _ =` 又把这个布尔整个丢掉。
unsafe fn enable_privilege(name: &str) -> bool {
    use windows_sys::Win32::Foundation::{GetLastError, SetLastError, CloseHandle, ERROR_NOT_ALL_ASSIGNED};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: *mut core::ffi::c_void = std::ptr::null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 { return false; }
    let nw = wide(name);
    let mut luid = windows_sys::Win32::Foundation::LUID { LowPart: 0, HighPart: 0 };
    let mut res = false;
    if LookupPrivilegeValueW(std::ptr::null(), nw.as_ptr(), &mut luid) != 0 {
        let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = 2; // SE_PRIVILEGE_ENABLED
        // ATP 自己不清 LastError，不先归零就会把更早的残留码读成本次的失败原因
        SetLastError(0);
        if AdjustTokenPrivileges(token, 0, &mut tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
            res = GetLastError() != ERROR_NOT_ALL_ASSIGNED;
        }
    }
    CloseHandle(token);
    res
}

unsafe fn avail_phys_bytes() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
    ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    // 返回 0 = 失败，此时结构体仍是全零。旧写法把失败当「可用 0 字节」返回，于是
    // before=0 ⇒ freed = after ≈ 整机空闲内存，能凭空报出「释放 12 GB」（v5 M-2）。
    if GlobalMemoryStatusEx(&mut ms) == 0 {
        None
    } else {
        Some(ms.ullAvailPhys)
    }
}

/// 释放量的三态判定（纯函数，便于断言；N1b-M06）。
///
/// `measured = false` 必须与「确实没释放」区分开，两种形态都算：
/// ① 前后两次 `GlobalMemoryStatusEx` 至少一次读不到（v5 M-2 已修的那半）；
/// ② 本次选中的区域**一个都没执行成功**（全失败 / 空集）。此时 `freed` 报的是
///    「这几秒整机可用内存的净变化」，与他人进程的活动不可分，却标着
///    `freedMeasured:true` —— 等于把「本模块什么都没做成」伪装成「测到了释放量」。
/// 数值口径不变：`freed` 仍是 saturating 差（后小于前给 0，不出负数）。
fn mem_freed_verdict(before: Option<u64>, after: Option<u64>, statuses: &[i32]) -> (u64, bool) {
    let any_region_ok = statuses.iter().any(|&s| s == STATUS_SUCCESS);
    match (before, after) {
        (Some(b), Some(a)) if any_region_ok => (a.saturating_sub(b), true),
        _ => (0, false),
    }
}

/// 内存清理核心：Ok = 最终结果 JSON；Err = 失败原因消息（CLI 侧原样直写 stdout）。
/// 白名单校验与原行为逐字一致（`--items` 缺失在 CLI 包装里处理，不进核心）。
fn mem_clean_core(want: &[String]) -> Result<String, String> {
    if want.is_empty() {
        return Err("未选择要清理的内存区域".to_string());
    }
    for id in want {
        if !MEM_ITEMS.iter().any(|m| m.0 == id.as_str()) {
            return Err(format!("非法区域 id: {}", id)); // fail-closed：白名单外拒绝
        }
    }
    unsafe {
        // 双特权，缺一不可（`vendor/upstream-js/src/scripts-powershell/memory-scripts.js:72-99` 同口径）
        // N1b-M06：旧写法 `let _ =` 把返回值整个丢掉。现在 true 的含义是「令牌里真的
        // 加上了」（AdjustTokenPrivileges 的 `ERROR_NOT_ALL_ASSIGNED` 已查），并把两位
        // 如实带进回执的 `privileges` 段：没提权时 5 个区域全会被系统拒绝，界面上要能
        // 说出「是缺特权」而不是「清了但没释放」。
        let priv_profile = enable_privilege("SeProfileSingleProcessPrivilege");
        let priv_quota = enable_privilege("SeIncreaseQuotaPrivilege");
        let before = avail_phys_bytes();
        let mut results: Vec<String> = Vec::new();
        // 本次**实际执行**的区域 NTSTATUS（判「有没有真做成一件事」用，见 mem_freed_verdict）
        let mut statuses: Vec<i32> = Vec::new();
        for (id, cls, val, kind, label) in MEM_ITEMS.iter() {
            if !want.iter().any(|w| w == id) { continue; }
            // E4：每区域耗时（方案 §3.5 E4）。计时**包住 NtSetSystemInformation 调用**，
            // 失败路径同样计时 —— 只测成功路径等于把「慢的失败」藏起来，而那恰恰是用户
            // 最想知道「为什么这一步卡了」的场合。
            //
            // ⚠️ 只加字段，不参与任何判定：ok/status/freed 三者都不看它。E4 的前提是
            // 「只加日志字段」，一旦让耗时进判定就成了行为变更。
            let t0 = std::time::Instant::now();
            let status: i32 = if *kind == 0 {
                let buf: u64 = *val as u64;
                NtSetSystemInformation(*cls, &buf as *const u64 as *mut u8, 8)
            } else {
                // combine：零初始化 MEMORY_COMBINE_INFORMATION_EX（Handle=NULL → 全部进程）
                let mut buf: MemoryCombineInformationEx = std::mem::zeroed();
                NtSetSystemInformation(
                    *cls,
                    &mut buf as *mut MemoryCombineInformationEx as *mut u8,
                    std::mem::size_of::<MemoryCombineInformationEx>() as u32,
                )
            };
            let elapsed_ms = t0.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            statuses.push(status);
            results.push(format!("{{\"id\":\"{}\",\"name\":\"{}\",\"ok\":{},\"status\":{},\"elapsedMs\":{elapsed_ms}}}", id, label, status == 0, status));
        }
        let after = avail_phys_bytes();
        // v5 M-2：任一端读失败 ⇒ 差值不可信，如实回 0 并置 freedMeasured=false，让渲染层
        // 说「未测到释放量」而不是「释放 0 B」（后者看着像"确实没释放"，是两种不同的结论）。
        // N1b-M06：判定收进 `mem_freed_verdict`，多并一条「本轮一个区域都没做成」的形态。
        // 口径提醒：freed 本来就是「这几秒内全系统可用内存的净变化」，不是本模块独占成果 ——
        // 期间其它进程分配/释放、系统自行回收都算得进来，UI 文案不得写成"本模块释放了 X"。
        let (freed, measured) = mem_freed_verdict(before, after, &statuses);
        Ok(format!(
            "{{\"before\":{},\"after\":{},\"freed\":{},\"freedMeasured\":{},\"privileges\":{{\"seProfileSingleProcess\":{},\"seIncreaseQuota\":{}}},\"results\":[{}]}}",
            before.unwrap_or(0), after.unwrap_or(0), freed, measured, priv_profile, priv_quota, results.join(",")
        ))
    }
}

/// 内存清理 **数据入口**（lib 直调）：items 形如 ["workingSet","standby",...]；
/// 返回最终 JSON 文本（与 CLI `mem-clean --items a,b,c` 输出的那行 JSON 完全一致）；
/// 失败时也返回可解析 JSON（`{"error":"…"}`），调用方无需区分成功/失败即可解析。
pub fn mem_clean_json(items: &[String]) -> String {
    match mem_clean_core(items) {
        Ok(j) => j,
        Err(msg) => format!("{{\"error\":\"{}\"}}", json_escape(&msg)),
    }
}

/// CLI 入口（`finder mem-clean --items a,b,c`）：参数解析 + stdout 写回包装，
/// 与 `mem_clean_json` 共用同一核心实现（不允许两份）。
pub fn run_mem_clean(args: &[String]) -> i32 {
    let items_str = match arg_value(args, "items") {
        Some(v) => v.to_string(),
        None => { let _ = out_line("缺少 --items"); return 2; }
    };
    let want: Vec<String> = items_str.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    match mem_clean_core(&want) {
        Ok(j) => { let _ = out_line(&j); 0 }
        Err(msg) => { let _ = out_line(&msg); 2 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 审查 v2-M6：`success` 以前是字面量 `true`，任何子系统失败都照样报成功，
    /// 上层唯一的回落护栏（判 `success != true`）因此永不触发 —— 高核数机器上
    /// CPU 永久 `--` 就是这么来的。这里钉住「关键子系统缺一即不成功」。
    #[test]
    fn metrics_success_requires_the_key_subsystems() {
        assert!(metrics_success(true, true));
        assert!(!metrics_success(false, true), "CPU 采不到就不能报成功");
        assert!(!metrics_success(true, false), "内存采不到就不能报成功");
        assert!(!metrics_success(false, false));
    }

    /// 审查 v2-M6：>64 逻辑核的机器必得 STATUS_INFO_LENGTH_MISMATCH，
    /// 原实现固定 64 项缓冲 ⇒ 恒 None。这里验按 ReturnLength 重取尺寸的那一步。
    #[test]
    fn cpu_buffer_retry_grows_by_return_length_and_rejects_absurd_values() {
        // 128 核：需要 128*48 = 6144 字节，起始缓冲 3072 ⇒ 重试
        assert_eq!(cpu_buf_retry_len((128 * CPU_ITEM_LEN) as u32, CPU_ITEM_LEN * 64), Some(128 * CPU_ITEM_LEN));
        // 长度没变化（不是"不够大"造成的失败）⇒ 不重试，避免死循环
        assert_eq!(cpu_buf_retry_len((64 * CPU_ITEM_LEN) as u32, CPU_ITEM_LEN * 64), None);
        assert_eq!(cpu_buf_retry_len(0, CPU_ITEM_LEN * 64), None);
        // 荒谬值（>4096 核）直接放弃，不照单分配巨型缓冲
        assert_eq!(cpu_buf_retry_len(u32::MAX, CPU_ITEM_LEN), None);
        // 非整项长度要向上对齐到整项，否则尾端半条记录会被当成一条读进累加
        let got = cpu_buf_retry_len((64 * CPU_ITEM_LEN + 1) as u32, CPU_ITEM_LEN * 64).unwrap();
        assert_eq!(got % CPU_ITEM_LEN, 0);
        assert_eq!(got, 65 * CPU_ITEM_LEN);
    }

    /// 审查 v2-M6：「0 MB/s」与「没测成」必须能区分 —— 后者过去也写 `measured:true`，
    /// 于是被当成一次真实测量落进测速历史，曲线再也不可比。
    #[test]
    fn bench_verdict_refuses_disguised_failures() {
        // 请求 8 线程只开起来 1 个：线程数失真，整轮作废
        assert!(bench_verdict(1, 8, [10, 10, 10, 10]).is_err());
        // 一个文件都建不出来
        assert!(bench_verdict(0, 1, [0, 0, 0, 0]).is_err());
        // 四阶段全 0（盘被配额/只读/杀软拦住的形态）
        assert!(bench_verdict(4, 4, [0, 0, 0, 0]).is_err());
        // 只有某一阶段 0（写失败被静默跳过、读却在跑）同样不完整
        let e = bench_verdict(2, 2, [900, 800, 0, 500]).unwrap_err();
        assert!(e.contains("随机读"), "错误里要指得出是哪一段没测到：{e}");
        // 正常一轮才放行
        assert!(bench_verdict(2, 2, [900, 800, 700, 500]).is_ok());
    }

    /// 审查 v2-L18：取盘符根曾经是 `&dir[..3.min(dir.len())]` —— 按字节切片，
    /// 首 3 字节落在多字节字符中间直接 panic（CLI 直调 `--path` 可达）。
    #[test]
    fn drive_root_prefix_never_slices_through_a_char() {
        assert_eq!(drive_root_prefix(r"C:\Users"), Some("C:"));
        assert_eq!(drive_root_prefix("D:"), Some("D:"));
        // 非 ASCII 开头的路径：旧写法会 panic，新写法只能给 None
        assert_eq!(drive_root_prefix("临时目录"), None);
        assert_eq!(drive_root_prefix(r"\\nas\share\x"), None);
        assert_eq!(drive_root_prefix(""), None);
        assert_eq!(drive_root_prefix("C"), None);
    }

    /// 单调时钟：必须严格不回退，且与墙钟量级一致（口径换了不能把 4 秒阶段算成 4 毫秒）。
    #[test]
    fn mono_clock_is_monotonic_and_in_ms() {
        let a = mono_ns();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let b = mono_ns();
        assert!(b > a, "单调时钟出现回退：{a} -> {b}");
        let dms = (b - a) / 1_000_000;
        assert!((15..3_000).contains(&dms), "单调时钟量级不对（差了 {dms} ms）");
        assert!(mono_ms() > 0);
    }

    /// v7.2 W4（N1b-L01）破坏自证：`RtlGetVersion` 的返回码必须进判定。
    /// 旧写法丢弃返回码 ⇒ 失败时把全零结构体读成「0.0.0」，一个都不存在的版本号
    /// 与真实读数在界面上同形。正向点名：失败给 None，成功给逐字三元组。
    #[test]
    fn os_version_fields_把调用失败与读数分开() {
        // 尺寸不被接受（STATUS_INFO_LENGTH_MISMATCH）与任意非 0 码一律 None
        assert_eq!(
            os_version_fields(STATUS_INFO_LENGTH_MISMATCH, 0, 0, 0),
            None,
            "调用失败不得折成 0.0.0"
        );
        assert_eq!(os_version_fields(1, 10, 0, 22631), None, "非 0 就是失败，哪怕字段看着像读数");
        assert_eq!(
            os_version_fields(0, 10, 0, 22631),
            Some(("10.0.22631".to_string(), "22631".to_string())),
            "成功时 version 是 major.minor.build、build 是单独的十进制串"
        );
        // 真读到 0.0.0 也要照常输出（判据是返回码，不是「值看着不像版本」）
        assert_eq!(
            os_version_fields(0, 0, 0, 0),
            Some(("0.0.0".to_string(), "0".to_string()))
        );
    }

    /// v7.2 W4（N1b-L01）：注册表取值的三态与类型校验。
    /// 旧写法取了 `typ` 却不校验，REG_DWORD/REG_MULTI_SZ 被 lossy 解码成乱码照样当 Some，
    /// 孤立代理项也被换成 U+FFFD 当正常名字返回。
    #[test]
    fn reg_sz_value_只认_reg_sz_且拒绝有损解码() {
        let utf16 = |s: &str| -> Vec<u8> {
            let mut v: Vec<u8> = s
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect();
            v.extend([0u8, 0u8]); // 终止符
            v
        };
        // REG_SZ = 1：正常读到，尾部 NUL 被裁掉
        assert_eq!(
            reg_sz_value(1, &utf16("Windows 11 专业版")),
            Ok(Some("Windows 11 专业版".to_string()))
        );
        // REG_EXPAND_SZ(2) / REG_MULTI_SZ(7) / REG_DWORD(4) 都不是本通道认的形状
        for bad_typ in [2u32, 4, 7, 11] {
            assert_eq!(
                reg_sz_value(bad_typ, &utf16("x")),
                Err(()),
                "类型 {bad_typ} 不是 REG_SZ，必须判形状不合"
            );
        }
        // 半条码元 = 形状不合（不是「值为空」）
        assert_eq!(reg_sz_value(1, &[0x41]), Err(()));
        // 孤立代理项 = 非良构 UTF-16 ⇒ 形状不合，不许 lossy 成含 U+FFFD 的假名字
        let lone = [0x3Du8, 0xD8u8, 0x00, 0x00];
        assert_eq!(reg_sz_value(1, &lone), Err(()), "孤立代理项必须判形状不合");
        // 只有 NUL = 空值 ⇒「确实没有」，与上面两种不同
        assert_eq!(reg_sz_value(1, &[0u8, 0u8]), Ok(None));
        assert_eq!(reg_sz_value(1, &[]), Ok(None), "零长度 = 值不存在");
    }

    /// v7.2 W4（N1b-M06）：`GetIfTable2` 的失败必须与「本帧没有可输出的网卡」分得开。
    /// 旧写法两条都 `return None` ⇒ 渲染层只能画「没有网络」，API 挂了没人知道。
    #[test]
    fn if_table_read_failure_把读不到与确无网卡分开() {
        // 返回码非 0 ⇒ 带上原始码（宿主/CLI 能说出是哪个 NTSTATUS）
        assert_eq!(if_table_read_failure(STATUS_INFO_LENGTH_MISMATCH, false), Some(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(if_table_read_failure(5, true), Some(5));
        // 返回码 0 却给空指针：调用约定违例，也只能算「读不到」
        assert_eq!(if_table_read_failure(0, true), Some(NET_READ_NULL_TABLE));
        // 真读到表 ⇒ 不是失败（后面 adapters 为空是「确无符合条件网卡」，另一条出口）
        assert_eq!(if_table_read_failure(0, false), None);
    }

    /// v7.2 W4（N1b-M06）：mem-clean 的释放量三态。
    /// 旧写法只查「前后两次读数是否在」，于是 5 个区域全被系统拒绝时照样
    /// `freedMeasured:true` 报出一个由别人进程造成的差值。
    #[test]
    fn mem_freed_verdict_全失败时不谎称测到释放() {
        // ① 正常：一端成功 + 两次读数都在 ⇒ 差值可信
        assert_eq!(mem_freed_verdict(Some(100), Some(180), &[0]), (80, true));
        assert_eq!(
            mem_freed_verdict(Some(100), Some(180), &[-1073741772, 0]),
            (80, true),
            "部分区域失败但有一端成功 ⇒ 仍按测到处理（差值口径不变）"
        );
        // ② 本模块一个区域都没做成 ⇒ 不成立，freed 归零并明说没测到
        assert_eq!(mem_freed_verdict(Some(100), Some(180), &[-1073741772, -1073741772]), (0, false));
        assert_eq!(mem_freed_verdict(Some(100), Some(180), &[]), (0, false), "空集 = 没执行任何区域");
        // ③ 任一端读不到（v5 M-2 那半，不许被本次改动弄丢）
        assert_eq!(mem_freed_verdict(None, Some(180), &[0]), (0, false));
        assert_eq!(mem_freed_verdict(Some(100), None, &[0]), (0, false));
        // ④ 成功但可用内存没涨（或被别人吃掉）⇒ 测到了，值是 0
        assert_eq!(mem_freed_verdict(Some(180), Some(100), &[0]), (0, true));
    }

    /// v7.2 W4（N1b-L01）真机探针（**只写不跑**）：真实 `RtlGetVersion` + 真实注册表。
    /// 钉的是「这台机器上返回码确实是 0，且三元组不是被兜出来的空串」——
    /// 单元用例只能证纯函数的分档，证不到 API 实际接受我们填的 276 字节尺寸。
    #[cfg(windows)]
    #[test]
    #[ignore = "真机探针：调 RtlGetVersion 与读 HKLM ProductName（只读，无副作用）"]
    fn 真机系统版本段读得到且形状合() {
        let (caption, caption_read, version, build) = unsafe { os_version_strings() };
        assert!(caption_read, "ProductName 必须真读到（不是兜底的通用标签）：{caption}");
        assert!(caption.contains("Windows"), "caption 里必须带产品名：{caption}");
        let v = version.expect("RtlGetVersion 必须返回 0，否则这里才是 None");
        let b = build.expect("build 与 version 同进退");
        let major: u32 = v
            .split('.')
            .next()
            .and_then(|s| s.parse().ok())
            .expect("version 首段必须是数字");
        assert!(major >= 6, "Windows NT 系主版本不可能小于 6：{v}");
        assert_eq!(v.rsplit('.').next().unwrap(), b.as_str(), "build 必须与 version 末段一致");
        assert!(
            !b.is_empty() && b.chars().all(|c| c.is_ascii_digit()),
            "build 必须是十进制数字串：{b}"
        );
    }
}

#[cfg(test)]
mod p1_6e_arg_tests {
    use super::{bench_warn_field, clamp_to_whitelist, parse_bench_arg, resolve_bench_dir};

    /// 「没给参数」与「给了但不是数字」都回落默认，但只有后者留痕。
    /// 判红自证：把 `parse_bench_arg` 的 `Err(_) =>` 支并回 `unwrap_or(default)` ⇒ 第二条红。
    #[test]
    fn 缺参与畸形参回落同一默认但只有一条留痕() {
        let mut w: Vec<String> = Vec::new();
        assert_eq!(parse_bench_arg(None, 8, "duration", &mut w), 8);
        assert!(w.is_empty(), "没给参数不是异常，不得造告警：{w:?}");
        assert_eq!(parse_bench_arg(Some("abc"), 8, "duration", &mut w), 8);
        assert_eq!(w.len(), 1, "畸形值必须留一条：{w:?}");
        assert!(w[0].contains("duration=abc") && w[0].contains("已按默认 8"), "告警点名原值与默认值：{w:?}");
        assert_eq!(parse_bench_arg(Some("12"), 8, "duration", &mut w), 12);
        assert_eq!(w.len(), 1, "合法值不再追加告警：{w:?}");
    }

    /// P1-6E①：白名单外的取值可以回落默认，但**必须留下告警** —— 旧写法是
    /// `if allowed.contains { v } else { 1 }`，「用户要的是 3」这条信息整条消失，
    /// 报告上只剩一个看不出问题的 qd=1。
    /// 判红自证：把 `clamp_to_whitelist` 里的 `warn.push(..)` 删掉 ⇒ 后两条断言红。
    #[test]
    fn 档位外的值回落默认但必须留痕() {
        let mut w: Vec<String> = Vec::new();
        assert_eq!(clamp_to_whitelist(8, &[1usize, 8, 32], 1, "qd", &mut w), 8);
        assert!(w.is_empty(), "命中档位不得造告警：{w:?}");

        assert_eq!(clamp_to_whitelist(3, &[1usize, 8, 32], 1, "qd", &mut w), 1);
        assert_eq!(w.len(), 1, "回落默认必须留一条告警，实得 {w:?}");
        assert!(w[0].contains("qd=3") && w[0].contains("已按 1 执行"), "告警要点名原值与回落值：{w:?}");

        assert_eq!(clamp_to_whitelist(9, &[1usize, 4, 8], 1, "threads", &mut w), 1);
        assert_eq!(w.len(), 2, "两次回落要留两条：{w:?}");
    }

    /// 留痕的落点是**回执 JSON**，不是 stdout/stderr：`diskbench_json`（Tauri 直调）
    /// 根本不读标准输出，写在 stdout 等于没写。
    /// 判红自证：把 `bench_warn_field` 直接改成返回空串 ⇒ 前两条断言红。
    #[test]
    fn 告警渲染进回执且空清单整段缺席() {
        assert_eq!(bench_warn_field(&[]), "", "空清单要整段缺席，不得塞 \"warn\":[]");
        let one = bench_warn_field(&["qd=3 不在档位内，已按 1 执行".to_string()]);
        assert!(one.starts_with(",\"warn\":["), "必须拼在既有对象末尾：{one}");
        assert!(one.contains("qd=3"), "告警原文要能在回执里找到：{one}");
        assert_eq!(
            bench_warn_field(&["a".to_string(), "b\"带引号\"".to_string()]),
            ",\"warn\":[\"a\",\"b\\\"带引号\\\"\"]",
            "两条都要进数组，且内嵌引号必须转义（否则回执整段解析失败）"
        );
    }

    /// 目录名的唯一来源（真机取证发现的两侧不同名）：调用方给名，原生只验形状。
    /// 判红自证：删掉前缀校验 ⇒ 第三条红；把分隔符拼错 ⇒ 第二条红。
    #[test]
    fn 测速目录名由调用方单源给定() {
        assert_eq!(
            resolve_bench_dir("C:\\Users\\me\\Downloads", Some("C:\\Users\\me\\Downloads\\Trim-DiskBench-7")).ok(),
            Some("C:\\Users\\me\\Downloads\\Trim-DiskBench-7".to_string()),
            "调用方给的名字必须原样采用（两侧同名是这条修复的全部意义）"
        );
        assert_eq!(
            resolve_bench_dir("C:\\Users\\me\\Downloads\\", None).ok(),
            Some("C:\\Users\\me\\Downloads\\Trim-DiskBench".to_string()),
            "CLI 不给名时留在原位置，且末尾反斜杠不得拼出双分隔符"
        );
        assert!(resolve_bench_dir("C:\\base", Some("D:\\other\\Trim-DiskBench-1")).is_err(), "目录不在 --path 之下要拒");
        assert!(resolve_bench_dir("C:\\base", Some("C:\\base")).is_err(), "目录等于根本身要拒（清理动作会指向用户的整个目录）");
        assert!(resolve_bench_dir("C:\\base", Some("c:\\BASE\\Trim-DiskBench-1")).is_ok(), "Windows 路径大小写不敏感");
    }
}
