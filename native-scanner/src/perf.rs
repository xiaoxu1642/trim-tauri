//! perf.rs — v3.7.1 Rust 化批次（方案：update history/9.23/Trim-Rust化方案-R1R2R3-v2-2026-09-23.md）
//!
//! 四个子命令（契约以现有渲染层读取字段为准，v2 铁律）：
//!   diskbench   磁盘测速（nobuf 默认，QD=每线程在途上限，OVERLAPPED event 等待）
//!   ov-metrics  系统概览高频指标（字段与 overview-scripts.js:60-74 一一对应）
//!   net-sample  实时网速采样（--daemon 常驻，每秒一行 JSON，差分在 Rust）
//!   mem-clean   内存清理（NtSetSystemInformation 逐字平移，双特权，82/84 黑名单继承）
//!
//! 通用：argv 传参；stdout 逐行；进度行 + 最终单行 JSON；单项失败不中断；fail-closed 不假成功。

use crate::json_escape;
use std::io::Write as _;

// 手写 ntdll / kernel32 补充声明（windows-sys 覆盖不到或类型 Hunt 成本高的少量函数）
#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(class: u32, info: *mut u8, len: u32, return_len: *mut u32) -> i32;
    fn NtSetSystemInformation(class: u32, info: *mut u8, len: u32) -> i32;
}

const SYS_PROCESSOR_PERFORMANCE_INFORMATION: u32 = 8;

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

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
fn now_ns() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}
fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain([0]).collect() }
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
        in_flight[i] = (off, now_ns());
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
        if now_ms() >= deadline_ms { break; }
        let n = events.len() as u32;
        let wait = WaitForMultipleObjects(n, events.as_ptr(), 0, 200);
        if wait < WAIT_OBJECT_0 || wait >= WAIT_OBJECT_0 + n { continue; }
        let i = (wait - WAIT_OBJECT_0) as usize;
        let mut transferred: u32 = 0;
        let _ = GetOverlappedResult(handle, &ovl[i], &mut transferred, 0);
        if in_flight[i].0 != u64::MAX {
            lat_total += now_ns().saturating_sub(in_flight[i].1);
            bytes_done += transferred as u64;
            ops_done += 1;
        }
        if now_ms() < deadline_ms {
            submit(i, &mut ovl, &mut bufs, &mut in_flight);
        } else {
            in_flight[i].0 = u64::MAX;
        }
    }
    // 收尾：等全部在途落定（截止后仍在途的请求很小，1s 足够）
    let hard = now_ms() + 1000;
    let mut remaining: Vec<usize> = (0..qd).collect();
    while !remaining.is_empty() && now_ms() < hard {
        let hs: Vec<*mut core::ffi::c_void> = remaining.iter().map(|&i| events[i]).collect();
        let n = hs.len() as u32;
        let wait = WaitForMultipleObjects(n, hs.as_ptr(), 1, 300);
        if wait < WAIT_OBJECT_0 || wait >= WAIT_OBJECT_0 + n { break; }
        let i = remaining.remove((wait - WAIT_OBJECT_0) as usize);
        let mut transferred: u32 = 0;
        let _ = GetOverlappedResult(handle, &ovl[i], &mut transferred, 0);
        if in_flight[i].0 != u64::MAX {
            lat_total += now_ns().saturating_sub(in_flight[i].1);
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
    let block = arg_value(args, "block-bytes").map(|v| v.parse::<u64>().unwrap_or(1048576)).unwrap_or(1048576);
    let duration = arg_value(args, "duration").map(|v| v.parse::<u64>().unwrap_or(8)).unwrap_or(8);
    let qd_req = arg_value(args, "qd").map(|v| v.parse::<usize>().unwrap_or(1)).unwrap_or(1);
    let th_req = arg_value(args, "threads").map(|v| v.parse::<usize>().unwrap_or(1)).unwrap_or(1);
    let mode = arg_value(args, "mode").unwrap_or("nobuf").to_string();
    if !BENCH_BLOCKS.contains(&block) || !BENCH_DURATIONS.contains(&duration) {
        return Err("非法参数（block/duration 不在白名单）".to_string());
    }
    let qd_req = if BENCH_QD.contains(&qd_req) { qd_req } else { 1 };
    let threads = if BENCH_THREADS.contains(&th_req) { th_req } else { 1 };
    // 非固定盘 / 探测失败回落 buf（nobuf 在内存盘、网络盘不可靠）
    let mut nobuf = mode != "buf";
    unsafe {
        let root = format!("{}\\", &dir[..3.min(dir.len())]);
        let (mut spc, mut bps, mut fc, mut tc) = (0u32, 0u32, 0u32, 0u32);
        if GetDiskFreeSpaceW(wide(&root).as_ptr(), &mut spc, &mut bps, &mut fc, &mut tc) == 0 { nobuf = false; }
    }
    // QD=每线程在途上限；受每线程 16MB 缓冲上限折算（guide 说明）
    let qd_eff = qd_req.max(1).min((BUF_CAP_PER_THREAD / block as usize).max(1));
    bench_progress(on_progress, "seqwrite", 0);

    unsafe {
        let bench_dir = format!("{}\\Trim-DiskBench", dir);
        let _ = std::fs::create_dir_all(&bench_dir);
        let seq_per = (SEQ_WINDOW_TOTAL / threads as u64 / block).max(8) * block;
        let rand_per = ((RAND_WINDOW_TOTAL / threads as u64) / 4096).max(8) * 4096;
        let mut handles: Vec<*mut core::ffi::c_void> = Vec::new();
        let mut files: Vec<String> = Vec::new();
        for t in 0..threads {
            let name = format!("tb_t{}.bin", t);
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
        let t0 = now_ms();
        let phase_ms = duration * 1000;
        let half_ms = duration * 500;
        // HANDLE 是 *mut c_void 不满足 Send；edition2021 精确捕获会连字段位置一起抓，
        // 包装体也绕不开 → 跨线程一律先转 usize（Send），闭包内再转回 HANDLE（同进程内安全）
        let run_stage = |kind: u8, io: usize, ms: u64, seq: u64, offs: &[u64]| -> (u64, u64, u128) {
            let start = now_ms();
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
        let elapsed = now_ms() - t0;

        // 口径（v2 §3.1）：MB/s 按真实阶段耗时；iops=4K 随机读 IOPS（保历史可比）；
        // latency=随机读单请求端到端平均（含排队），毫秒
        let mbs = |b: u64, ms: u64| b as f64 / (1024.0 * 1024.0) / (ms as f64 / 1000.0);
        let seq_write = mbs(seq_w.0, phase_ms);
        let seq_read = mbs(seq_r.0, phase_ms);
        let rand_read = mbs(rd_r.0, half_ms);
        let rand_write = mbs(wr_r.0, half_ms);
        let iops = rd_r.1 as f64 / (half_ms as f64 / 1000.0);
        let latency = if rd_r.1 > 0 { (rd_r.2 as f64 / rd_r.1 as f64) / 1e6 } else { 0.0 };
        let result = format!(
            "{{\"measured\":true,\"sequentialRead\":{:.1},\"sequentialWrite\":{:.1},\"randomRead\":{:.1},\"randomWrite\":{:.1},\"iops\":{:.0},\"latency\":{:.3},\"blockSize\":{},\"queueDepth\":{},\"threads\":{},\"duration\":{},\"ioMode\":\"{}\",\"qdEffective\":{},\"elapsedMs\":{}}}",
            seq_read, seq_write, rand_read, rand_write, iops, latency, block, qd_req, threads, duration,
            if nobuf { "nobuf" } else { "buf" }, qd_eff, elapsed
        );
        for h in handles { let _ = CloseHandle(h); }
        for f in &files { DeleteFileW(wide(f).as_ptr()); }
        Ok(result)
    }
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

unsafe fn cpu_raw_times() -> Option<(u64, u64)> {
    let mut buf = [0u8; 64 * 48];
    let mut ret: u32 = 0;
    if NtQuerySystemInformation(SYS_PROCESSOR_PERFORMANCE_INFORMATION, buf.as_mut_ptr(), buf.len() as u32, &mut ret) != 0 {
        return None;
    }
    let n = (ret as usize / 48).min(64);
    let (mut busy, mut idle) = (0u64, 0u64);
    for i in 0..n {
        let rd = |o: usize| -> u64 {
            let mut v: u64 = 0;
            for k in 0..8 { v |= (buf[i * 48 + o + k] as u64) << (8 * k); }
            v
        };
        let idle_t = rd(0);
        idle += idle_t;
        busy += rd(8).saturating_sub(idle_t) + rd(16);
    }
    Some((busy, idle))
}

unsafe fn uptime_text() -> String {
    // GetTickCount64：含睡眠的开机时长；与 PS LastBootUpTime 墙钟口径的细微差异可接受
    let secs = windows_sys::Win32::System::SystemInformation::GetTickCount64() / 1000;
    let (days, hours, mins) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    if days > 0 { format!("{} 天 {} 小时 {} 分钟", days, hours, mins) }
    else if hours > 0 { format!("{} 小时 {} 分钟", hours, mins) }
    else { format!("{} 分钟", mins) }
}

unsafe fn os_version_strings() -> (String, String, String) {
    // RtlGetVersion（避开 manifest 兼容清单）；caption 取注册表 ProductName（与 PS 的
    // 本地化 Caption 措辞可能有别，已知差异，见交付报告）
    #[link(name = "ntdll")]
    extern "system" { fn RtlGetVersion(info: *mut u8) -> i32; }
    let mut vi = [0u8; 276]; // OSVERSIONINFOW
    vi[0..4].copy_from_slice(&276u32.to_le_bytes());
    RtlGetVersion(vi.as_mut_ptr());
    let rd = |o: usize| u32::from_le_bytes([vi[o], vi[o + 1], vi[o + 2], vi[o + 3]]);
    // OSVERSIONINFOW 布局：0=size, 4=major, 8=minor, 12=buildNumber, 16=platformId
    let (major, minor, build) = (rd(4), rd(8), rd(12));
    let caption = reg_get_string(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    (caption, format!("{}.{}.{}", major, minor, build), build.to_string())
}

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(key: isize, sub: *const u16, opt: u32, sam: u32, out: *mut isize) -> i32;
    fn RegQueryValueExW(key: isize, name: *const u16, res: *mut u32, typ: *mut u32, data: *mut u8, len: *mut u32) -> i32;
    fn RegCloseKey(key: isize) -> i32;
}

unsafe fn reg_get_string(sub: &str, name: &str) -> Option<String> {
    let sub_w = wide(sub);
    let name_w = wide(name);
    let mut hk: isize = 0;
    if RegOpenKeyExW(0x8000_0002u32 as isize /*HKLM*/, sub_w.as_ptr(), 0, 0x20019 /*KEY_READ*/, &mut hk) != 0 { return None; }
    let mut out = None;
    let (mut typ, mut len) = (0u32, 0u32);
    if RegQueryValueExW(hk, name_w.as_ptr(), std::ptr::null_mut(), &mut typ, std::ptr::null_mut(), &mut len) == 0 && len > 0 && len < 4096 {
        let mut buf = vec![0u8; len as usize];
        let mut len2 = len;
        if RegQueryValueExW(hk, name_w.as_ptr(), std::ptr::null_mut(), &mut typ, buf.as_mut_ptr(), &mut len2) == 0 {
            let u16s: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            out = Some(String::from_utf16_lossy(&u16s).trim_end_matches('\0').to_string());
        }
    }
    RegCloseKey(hk);
    out
}

/// ov-metrics **数据入口**（lib 直调）：返回单行 JSON，与 CLI 行协议同构。
///
/// 为什么要这个入口：该通道被渲染层按 ~2.5s 节奏轮询，CLI 形态每拍都要付一次
/// 进程创建成本；Tauri 侧改为函数直调后，CPU/内存开销与延迟都显著下降
/// （迁移方案 B 批「finder 内化为 lib 调用」）。
///
/// 注意：cpu 首拍恒为 null（本引擎无状态，差分由调用方缓存 cpuRaw 完成）——
/// 该语义是契约的一部分（渲染层首拍显示 `--`），lib 化不得"优化"掉。
pub fn ov_metrics_json() -> String {
    unsafe {
        // CPU：finder 无状态 → 输出原始计数，主进程缓存差分；首拍 cpu=null（渲染层显示 --）
        let cpu_raw = cpu_raw_times()
            .map(|(b, i)| format!("{{\"busy\":{},\"idle\":{}}}", b, i))
            .unwrap_or_else(|| "null".to_string());
        // 内存（口径对齐 PS：TotalVisibleMemorySize/FreePhysicalMemory ≈ ullTotalPhys/ullAvailPhys）
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
        ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut ms);
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
        if !snap.is_null() {
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
        let (caption, version, build) = os_version_strings();
        let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
        let user = std::env::var("USERNAME").unwrap_or_default();
        let json = format!(
            "{{\"success\":true,\"cpu\":null,\"cpuRaw\":{},\"memory\":{{\"total\":{},\"free\":{},\"used\":{},\"percent\":{:.1}}},\"disks\":[{}],\"uptime\":\"{}\",\"processes\":{},\"system\":{{\"caption\":\"{}\",\"version\":\"{}\",\"build\":\"{}\",\"computerName\":\"{}\",\"userName\":\"{}\"}}}}",
            cpu_raw, total, free, used, mem_percent, disks.join(","),
            json_escape(&uptime_text()), processes,
            json_escape(&caption), json_escape(&version), json_escape(&build),
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
    prev: std::collections::HashMap<u32, (u64, u64, u64)>,
}

impl NetSampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// 采一帧：返回 `Some(json行)`；首拍或当前无符合条件的物理网卡时返回 `None`
    /// （调用方据此保持"空列表而非报错"的上层语义）。
    pub fn sample_frame(&mut self) -> Option<String> {
        read_if_table_frame(&mut self.prev)
    }
}

/// 读一次 GetIfTable2 并按上一帧差分出一行 JSON（CLI 与 lib 共用同一实现）
fn read_if_table_frame(
    prev: &mut std::collections::HashMap<u32, (u64, u64, u64)>,
) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
    unsafe {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        if GetIfTable2(&mut table) != 0 || table.is_null() {
            return None;
        }
        let now = now_ms();
        let mut adapters: Vec<String> = Vec::new();
        // Table 在绑定里是 [MIB_IF_ROW2; 1] 定长数组，真实条目数是 NumEntries → 按指针步进
        let base = (*table).Table.as_ptr();
        for i in 0..(*table).NumEntries as usize {
            let row = &*base.add(i);
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
                let dt = (now.saturating_sub(pt)).max(1) as f64;
                let down = in_o.saturating_sub(pi) as f64 * 1000.0 / dt;
                let up = out_o.saturating_sub(po) as f64 * 1000.0 / dt;
                adapters.push(format!(
                    "{{\"name\":\"{}\",\"desc\":\"{}\",\"up\":{:.0},\"down\":{:.0},\"ifIndex\":{}}}",
                    json_escape(&utf16_str(&row.Alias)), json_escape(&utf16_str(&row.Description)),
                    up.max(0.0), down.max(0.0), row.InterfaceIndex
                ));
            }
            prev.insert(row.InterfaceIndex, (in_o, out_o, now));
        }
        FreeMibTable(table as *mut core::ffi::c_void);
        if adapters.is_empty() {
            return None;
        }
        Some(format!("{{\"t\":{},\"adapters\":[{}]}}", now, adapters.join(",")))
    }
}

pub fn run_net_sample(args: &[String]) -> i32 {
    let interval = arg_value(args, "interval").map(|v| v.parse::<u64>().unwrap_or(1000)).unwrap_or(1000).clamp(200, 10_000);
    let mut sampler = NetSampler::new();
    loop {
        if let Some(line) = sampler.sample_frame() {
            if out_line(&line).is_err() { return 0; } // 管道断裂 = 父进程已退出
        }
        std::thread::sleep(std::time::Duration::from_millis(interval));
    }
}

// ============================ R3: mem-clean ============================
// 契约（v2 §2.5）：--items 恰好 5 个合法 id（含 standbyPriority0）；
// 输出 {"before","after","freed","results":[{"id","name","ok","status"}]}；
// 顺序 workingSet(80,1)→modified(80,2)→standby(80,3)→standbyPriority0(80,4)→combine(87)；
// 双特权；82/84 黑名单继承（不提供，不是失败）。

const MEM_ITEMS: [(&str, u32, u32, u8, &str); 5] = [
    ("workingSet", 80, 1, 0, "工作集"),
    ("modified", 80, 2, 0, "修改列表"),
    ("standby", 80, 3, 0, "备用列表"),
    ("standbyPriority0", 80, 4, 0, "低优先级备用列表"),
    ("combine", 87, 0, 1, "合并物理内存页"), // kind=1：8 字节全零缓冲（HandleCount=0）
];

unsafe fn enable_privilege(name: &str) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
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
        res = AdjustTokenPrivileges(token, 0, &mut tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0;
    }
    CloseHandle(token);
    res
}

unsafe fn avail_phys_bytes() -> u64 {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
    ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    GlobalMemoryStatusEx(&mut ms);
    ms.ullAvailPhys
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
        // 双特权，缺一不可（memory-scripts.js:72-99 同口径）
        let _ = enable_privilege("SeProfileSingleProcessPrivilege");
        let _ = enable_privilege("SeIncreaseQuotaPrivilege");
        let before = avail_phys_bytes();
        let mut results: Vec<String> = Vec::new();
        for (id, cls, val, kind, label) in MEM_ITEMS.iter() {
            if !want.iter().any(|w| w == id) { continue; }
            let status: i32 = if *kind == 0 {
                let buf: u64 = *val as u64;
                NtSetSystemInformation(*cls, &buf as *const u64 as *mut u8, 8)
            } else {
                let buf: u64 = 0; // combine：HandleCount=0 → 合并全部
                NtSetSystemInformation(*cls, &buf as *const u64 as *mut u8, 8)
            };
            results.push(format!("{{\"id\":\"{}\",\"name\":\"{}\",\"ok\":{},\"status\":{}}}", id, label, status == 0, status));
        }
        let after = avail_phys_bytes();
        let freed = after.saturating_sub(before);
        Ok(format!(
            "{{\"before\":{},\"after\":{},\"freed\":{},\"results\":[{}]}}",
            before, after, freed, results.join(",")
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
