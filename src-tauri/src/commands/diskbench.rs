//! diskbench 域（B 批）：diskbench:run（+ `diskbench:progress` 事件）
//!
//! 注册清单（与 lib.rs 的 `generate_handler!` 逐条对齐，同 U-R1d 的 `R1d-L03` 口径）：
//!   commands::diskbench::diskbench_run,
//!
//! 实现体来源：main.js 5381-5551（含 isDiskBenchAllowedPath / getPathFreeBytes /
//! runFinderDiskbench / diskbench:run）。
//!
//! 安全与语义要点（逐条复刻）：
//! - 路径必须存在、必须是**普通目录**（非符号链接）；
//! - 必须在**用户可写安全白名单**内：用户主目录 + TEMP + LOCALAPPDATA + APPDATA（SP-1）；
//! - 剩余空间预检 ≥ 约 1 GB（statfs 失败则跳过，不阻塞）；
//! - 参数白名单化（blockSize/queueDepth/threads/duration/ioMode，非法值回落默认）；
//! - `<路径>\Trim-DiskBench-<世代号>` 残留目录：异常/超时/未完成时递归清理——那是应用自产基准
//!   临时数据（同临时脚本直接 unlink 的既有口径），不进回收站、不落删除清单。
//!   目录名带世代号（v7.2 `R1d-M09`）：超时后工作线程不中断，固定名会让清理与野线程共用一个目录。
//!
//! 引擎：**原生优先**——直调 `trim_finder::perf::diskbench_json`（签名已冻结）。
//! 进度行 JSON 由回调转 `diskbench:progress` 事件（载荷即该行解析后的对象）。
//!
//! ⚠️ 与 Electron 的差异（如实记录）：
//! - **PS 回落路径不实现**。Electron 在「finder exe 不存在 / 原生失败」时回落 PowerShell 脚本
//!   （并诚实化强制 QD1/T1）。Tauri 侧原生引擎已编译进二进制，不存在「exe 缺失」这个回落前提；
//!   原生失败直接返回失败（不伪造 engine:'powershell' 结果）。
//! - 超时采用「工作线程 + recv_timeout」模拟 Electron 的进程 kill + 残留清理；进程内原生调用
//!   无法真正中止，超时后该线程会继续跑完（其残留目录已被清理，可能被重建），属已知限制。

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{Emitter, WebviewWindow};

use crate::commands::state::{DISKBENCH_GEN, DISKBENCH_RUNNING};
use crate::engine::{guard, log};

/// 剩余空间下限（测速峰值写约 384 MB + 缓冲余量，照抄 main.js 5384）
const DISKBENCH_MIN_FREE_BYTES: u64 = 1024 * 1024 * 1024;

/// 残留目录占位的最多换号次数（R1d-L05）：同名碰撞是异常场景，换几次号够用即可，
/// 不做无界重试。
const DISKBENCH_DIR_CLAIM_TRIES: usize = 8;

/// 单飞位的 RAII 释放（v7.2 `R1d-M09`）：`?`/早退/panic 三条出口都必须把位放回去，
/// 手写在每个 return 前迟早漏一条 ⇒ 之后永远判「测速进行中」。
struct RunGuard;

impl Drop for RunGuard {
    fn drop(&mut self) {
        DISKBENCH_RUNNING.store(false, Ordering::SeqCst);
    }
}

/// 白名单路径判定（照抄 main.js isDiskBenchAllowedPath）：
/// roots = 用户主目录 + TEMP + LOCALAPPDATA + APPDATA；target == root 或位于 root 之下。
fn is_diskbench_allowed_path(resolved: &Path) -> bool {
    let target = resolved.to_string_lossy().to_lowercase();
    allowed_roots().iter().any(|root| {
        let r = root.to_string_lossy().to_lowercase();
        let r = r.trim_end_matches('\\');
        target == r || target.starts_with(&format!("{r}\\"))
    })
}

fn allowed_roots() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for key in ["USERPROFILE", "LOCALAPPDATA", "APPDATA"] {
        if let Ok(v) = std::env::var(key) {
            if !v.trim().is_empty() {
                out.push(canonical(Path::new(&v)).unwrap_or_else(|| PathBuf::from(v)));
            }
        }
    }
    let tmp = std::env::temp_dir();
    out.push(canonical(&tmp).unwrap_or(tmp));
    out
}

/// 规范化 + 去 verbatim 前缀（`\\?\C:\…` → `C:\…`）；失败返回 None。
/// 用于把白名单根与目标路径归一（顺带消解 `..`，等价 path.resolve 的语义）。
fn canonical(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok().map(strip_verbatim)
}

fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        if let Some(unc) = rest.strip_prefix("UNC\\") {
            return PathBuf::from(format!(r"\\{unc}"));
        }
        return PathBuf::from(rest);
    }
    p
}

/// 目标盘可用字节（GetDiskFreeSpaceExW；不可用时 None，不阻塞测速）
fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut free = 0u64;
    let ok = unsafe { GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), Some(&mut free), None, None) };
    if ok.is_ok() {
        Some(free)
    } else {
        None
    }
}

/// 逐个世代号尝试占位（R1d-L05），返回本场**亲手建成**的那个目录。
///
/// 判据为什么是「`create_dir` 成功」而不是「目录存在」：清理侧只凭名字就 `remove_dir_all`，
/// 同名目录若是上轮遗留或用户自建，先删后跑等于删别人的目录。占不到就换下一个世代号，
/// 用尽仍占不到则拒绝运行。`claim` 只承载「占位这一次动作」（生产传 `std::fs::create_dir`），
/// 测试不必碰盘。
fn claim_residue_dir<F>(base: &Path, mut claim: F) -> Result<PathBuf, String>
where
    F: FnMut(&Path) -> std::io::Result<()>,
{
    let mut last_err = String::from("同名目录已存在");
    for _ in 0..DISKBENCH_DIR_CLAIM_TRIES {
        let generation = DISKBENCH_GEN.fetch_add(1, Ordering::Relaxed) + 1;
        let candidate = base.join(format!("Trim-DiskBench-{generation}"));
        match claim(&candidate) {
            Ok(()) => return Ok(candidate),
            // 同名目录已存在：不是本场建的，换号重试
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = e.to_string(),
            // 其它失败（路径不可写等）换号也没用
            Err(e) => return Err(e.to_string()),
        }
    }
    Err(last_err)
}

/// 残留测试目录递归清理（应用自产临时数据；失败只记日志，不影响结果）
///
/// R1d-L05：调用方在调原生**之前**已 `create_dir` 占位成功，所以这里的 `dir` 只可能是
/// 本场亲手建的那个（同名目录的碰撞在占位处已换号，不会删到别人的目录）。
///
/// 审查 v3-L1：删前先过 `dir_delete_blocked`。
/// **注意**（B2-7 起）：维护任务的搜索索引 / 更新缓存两支已改走
/// `protect::validate_mutation_target`（四道组合闸），与这里**不再同口径** ——
/// 别拿本处当「维护链怎么判」的依据，也别把这里的宽松判据解释成维护链的判据。
/// `residue_dir` 位于**用户在 UI 里自选的测速路径**下，若该目录被换成指向别处的 junction，
/// 直接 `remove_dir_all` 会把链接目标一起处理掉；且这是本仓唯一一处「用户可设路径下的
/// 递归删除」，此前恰好漏了这道闸。属性读不到同样按拒绝处理（fail-closed）。
///
/// `abnormal` 只改日志级别与措辞：成功分支现在**也**走这里（原生只删自己建的文件、
/// 不删目录 ⇒ 由建目录的这一侧收干净），把正常收尾写成「异常结束」是假告警。
fn cleanup_residue(dir: &Path, abnormal: bool) {
    if !dir.exists() {
        return;
    }
    if let Some(reason) = crate::engine::native::dir_delete_blocked(dir) {
        log::write_log(
            "warn",
            &format!("测速残留目录未通过删除前校验，已跳过清理: {} — {}", dir.display(), reason),
        );
        return;
    }
    let mut last_err = None;
    for _ in 0..3 {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => {
                if abnormal {
                    log::write_log(
                        "warn",
                        &format!("磁盘测速异常结束，已清理残留测试目录: {}", dir.display()),
                    );
                } else {
                    log::write_log(
                        "info",
                        &format!("磁盘测速结束，已清理测试目录: {}", dir.display()),
                    );
                }
                return;
            }
            Err(e) => last_err = Some(e),
        }
    }
    if let Some(e) = last_err {
        log::write_log(
            "error",
            &format!("磁盘测速残留清理失败: {} -> {e}", dir.display()),
        );
    }
}

/// `Number(v)` 口径的宽松数值解析（数字/数字字符串）
fn js_number(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

/// 参数白名单化：允许值集合内取原值，否则回落默认。
///
/// P1-6E①：回落这件事**必须留痕**。三种形态要分清 ——
///   · 「这个键根本没给」= 前端没传，属正常默认路径，不产告警；
///   · 「给了但不在档位里」/「给了但不是数」/「给了个带小数」= 用户以为按自己选的在跑，
///     实际跑的是默认值，回执里的 `queueDepth/threads` 又会写成**回落后的值**，
///     于是「4 线程」的历史记录其实是 1 线程 —— 不告警就无人能发现。
fn pick(v: Option<&Value>, allowed: &[i64], default: i64, label: &str, warn: &mut Vec<String>) -> i64 {
    let Some(raw) = v else { return default };
    let Some(n) = js_number(Some(raw)) else {
        warn.push(format!("{label}不是可选值，已按默认 {default} 执行"));
        return default;
    };
    let i = n.trunc() as i64;
    if n != i as f64 {
        warn.push(format!("{label}的 {n} 不是整数，已取整为 {i}"));
    }
    if allowed.contains(&i) {
        i
    } else {
        warn.push(format!("{label}的 {i} 不是可选值，已按默认 {default} 执行"));
        default
    }
}

/// 原生回执 → 前端契约（纯函数，便于断言）。
///
/// 做三件事：① 把 `pick` 的回落告警与原生侧 `data.warn` 合成一个 `warn` 数组（只在非空时出现）；
/// ② 原生失败分支返回的是 `{"error":"…"}`，旧写法只判 `measured` 就吐
/// `{"success":false}`，把真实原因整条丢掉 —— 前端 `throw new Error(response.message)`
/// 于是显示「磁盘测速失败：undefined」，用户看不到"为什么没测成"（P1-6 族的同一个形状：
/// 失败信息被折成无信息）。现在 `error` 原样抬到 `message`。
/// ③ `measured` 仍是唯一的成功判据，不从 `data` 里猜。
fn bench_response(data: Value, mut warn: Vec<String>) -> Value {
    if let Some(arr) = data.get("warn").and_then(|w| w.as_array()) {
        for w in arr.iter().filter_map(|x| x.as_str()) {
            warn.push(w.to_string());
        }
    }
    let measured = data.get("measured").and_then(|v| v.as_bool()) == Some(true);
    let mut out = json!({ "success": measured, "data": data, "engine": "rust" });
    if !measured {
        out["message"] = json!(data.get("error").and_then(|e| e.as_str()).unwrap_or("磁盘测速未成功（原生引擎无更多说明）"));
    }
    if !warn.is_empty() {
        out["warn"] = json!(warn);
    }
    out
}

/// 等待结果的两类失败必须说成两句话（R1d-L04）：`Timeout` 是「还在盘上跑」，
/// `Disconnected` 是 sender 随工作线程结束被丢弃（多半 panic）——旧写法用 `Err(_)`
/// 把后者也说成超时，排查方向直接错。返回 (给用户的话, 日志级别)。
fn wait_failure(kind: mpsc::RecvTimeoutError) -> (&'static str, &'static str) {
    match kind {
        mpsc::RecvTimeoutError::Timeout => ("磁盘测速超时（原生引擎）", "warn"),
        mpsc::RecvTimeoutError::Disconnected => {
            ("磁盘测速线程异常结束，未返回结果（详见日志）", "error")
        }
    }
}

/// 工作线程的 panic 载荷 → 可写日志的一句话（载荷可能不是字符串，别 downcast 失败就丢）
fn panic_payload(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "无法读取的 panic 载荷".to_string()
    }
}

/// diskbench:run — 磁盘测速（原生引擎优先）
///
/// R1d-M09 的世代号只解决「别去动别人正在写的目录」，**不解决盘上留残**。
/// 真机复核（2026-10-25 CDP，跑成功一次后列目录）：留残成立——原生引擎写的是固定名
/// `Trim-DiskBench`，只删自己建的文件、不删目录；而这里按 `Trim-DiskBench-<世代号>`
/// 清理，两个名字不同名，所以异常路径的清理也一直落在空处。
/// 现在目录名单源（本侧算、`--bench-dir` 交给原生），并且**成功分支也收尾**，
/// 留残由 `#[ignore]` 探针 `u_r1d_diskbench_leaves_no_residue_on_success` 钉住。
#[tauri::command]
pub async fn diskbench_run<R: tauri::Runtime>(window: WebviewWindow<R>, options: Option<Value>) -> Result<Value, String> {
    // 审查 v2-L17：测速要独占读盘、属"会动系统资源"的写侧通道，且唯一调用方是主窗的
    // `diskbench.js`（`app.js` 页面表）⇒ 收 MAIN，不用放行全部四个窗口 label 的 readonly 档。
    guard::guard(&window, guard::MAIN)?;
    let opts = options.unwrap_or_else(|| json!({}));

    let requested = opts
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if requested.is_empty() || !Path::new(&requested).exists() {
        return Ok(json!({ "success": false, "message": "测速路径不存在" }));
    }
    // 必须是普通目录且非交换点；通过后再规范化（消解 .. ，用于白名单包含判定）。
    // 审查 v2-L12：用 `is_reparse`（属性位 0x400）而非 `is_symlink()` —— junction / OneDrive
    // 云占位符那类 is_symlink 判 false 的目标，一旦当成普通目录去测速会把负载压到别的存储上。
    let resolved = match std::fs::symlink_metadata(&requested) {
        Ok(meta) if meta.is_dir() && !crate::engine::protect::is_reparse(&meta) => {
            canonical(Path::new(&requested))
                .ok_or_else(|| "测速路径无法规范化，已拒绝".to_string())?
        }
        Ok(_) => return Ok(json!({ "success": false, "message": "测速路径必须是普通目录" })),
        Err(_) => return Ok(json!({ "success": false, "message": "测速路径不可访问" })),
    };

    // SP-1：白名单（用户主目录 + TEMP + AppData）
    if !is_diskbench_allowed_path(&resolved) {
        log::write_log(
            "warn",
            &format!("磁盘测速路径不在白名单内，已拒绝: {}", resolved.display()),
        );
        return Ok(json!({
            "success": false,
            "message": "测速路径受限，请选择用户目录（如下载、文档、桌面）或临时目录下的路径",
        }));
    }

    // R1d-L01：路径存在、普通目录、白名单与空间预检都定住以后才占单飞位；
    // 失败路径不得留下「测速进行中」。真实测速仍是独占读盘长任务，必须互斥。
    if DISKBENCH_RUNNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        log::write_log("warn", "磁盘测速已有一场在跑，本次请求已拒绝（单飞）");
        return Ok(json!({
            "success": false,
            "busy": true,
            "message": "已有一次磁盘测速在进行，请等待其结束后再试",
        }));
    }
    // Drop 里放位：panic 路径不用各写一遍 store(false)。R1d-M10：guard 所有权要交给
    // 工作线程——超时出口不能放位，否则野线程还在独占读盘，第二场立刻被放行。
    let run_guard = RunGuard;

    // SP-1：剩余空间预检（实测不可用则跳过）
    if let Some(free) = free_bytes(&resolved) {
        if free < DISKBENCH_MIN_FREE_BYTES {
            log::write_log(
                "warn",
                &format!(
                    "磁盘测速目标盘剩余空间不足: {} free={free}",
                    resolved.display()
                ),
            );
            return Ok(json!({
                "success": false,
                "message": "目标磁盘剩余空间不足，请选择空间更大的盘符（需至少约 1 GB）",
            }));
        }
    }

    // 参数白名单化（非法值回落默认，但**每一条回落都记进 warn 并随回执带回**，P1-6E①）
    let mut param_warn: Vec<String> = Vec::new();
    let block = pick(opts.get("blockSize"), &[4096, 65536, 1048576], 1048576, "块大小", &mut param_warn);
    let qd = pick(opts.get("queueDepth"), &[1, 8, 32], 1, "队列深度", &mut param_warn);
    let threads = pick(opts.get("threads"), &[1, 4, 8], 1, "线程数", &mut param_warn);
    let dur = pick(opts.get("duration"), &[4, 8, 16], 8, "时长", &mut param_warn);
    if !param_warn.is_empty() {
        log::write_log("warn", &format!("磁盘测速参数回落: {}", param_warn.join("；")));
    }
    let io_mode = if opts.get("ioMode").and_then(|v| v.as_str()) == Some("buf") {
        "buf"
    } else {
        "nobuf"
    };
    let bench_timeout = Duration::from_millis((dur as u64) * 1000 * 4 + 60_000);

    // ② 世代号——超时只是 `recv_timeout` 返回，**工作线程不会被中断**（同文件头已如实
    //    记录这个限制）。旧写法残留目录固定名 `Trim-DiskBench` ⇒ 超时后清理的是野线程
    //    正在写的那个目录，而野线程随后又把它建回来：清理动作与写入者共用一个名字，
    //    谁先谁后看运气。目录名带本次运行的世代号后，清理只针对自己那一份，
    //    野线程留在盘上的那一份由**它自己**的收尾处理（清理失败会记日志，不静默）。
    //
    //    真机取证（2026-10-25 CDP）：加世代号那一批只改了**主进程这一侧**，原生引擎仍把
    //    文件写进固定名 `Trim-DiskBench`（`native-scanner/src/perf.rs`），于是清理动作
    //    落在一个根本不存在的目录上——残留一个没清、隔离也没生效，成功分支每次跑完都在
    //    用户目录留一个空目录。现在目录名由这里唯一决定，并以 `--bench-dir` 交给原生。
    //    R1d-L05：世代号只解决「别撞上野线程正在写的目录」，「这个目录是不是本场建的」
    //    另需一条证据。旧清理判据只有「名字像本场产物」⇒ 上轮进程遗留或用户自建的同名
    //    目录会被整棵 `remove_dir_all`。现在先自己 `create_dir` 占位：占不到（已存在）
    //    就换下一个世代号，仍占不到才拒绝运行——清理因此只可能删本场亲手建的那个空目录。
    let residue_dir = match claim_residue_dir(&resolved, |p: &Path| std::fs::create_dir(p)) {
        Ok(dir) => dir,
        Err(why) => {
            log::write_log(
                "warn",
                &format!("磁盘测速临时目录占位失败: {} -> {why}", resolved.display()),
            );
            return Ok(json!({
                "success": false,
                "message": "测速临时目录不可用（同名目录已存在或路径不可写），请换一个测速目录再试",
            }));
        }
    };

    let args: Vec<String> = vec![
        "diskbench".to_string(),
        "--path".to_string(),
        resolved.to_string_lossy().to_string(),
        "--block-bytes".to_string(),
        block.to_string(),
        "--duration".to_string(),
        dur.to_string(),
        "--qd".to_string(),
        qd.to_string(),
        "--threads".to_string(),
        threads.to_string(),
        "--mode".to_string(),
        io_mode.to_string(),
        "--bench-dir".to_string(),
        residue_dir.to_string_lossy().to_string(),
    ];

    // 原生引擎在工作线程内执行：进度行 JSON → diskbench:progress 事件；
    // 主侧等待模拟 Electron 的进程超时中止。
    let handle = window.clone();
    let (tx, rx) = mpsc::channel::<String>();
    let worker_guard = run_guard;
    let worker = std::thread::spawn(move || {
        let _worker_guard = worker_guard;
        let mut emit = |line: &str| {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                let _ = handle.emit("diskbench:progress", v);
            }
        };
        let out = trim_finder::perf::diskbench_json(&args, &mut emit);
        let _ = tx.send(out);
    });

    // R1d-L04：`recv_timeout` 要一直等完整场测速时长加收尾余量，是同步阻塞 ⇒
    // 整段丢进阻塞池，不再占住一个 async worker 整场测速。
    let recv = tauri::async_runtime::spawn_blocking(move || rx.recv_timeout(bench_timeout)).await;
    let out = match recv {
        Ok(Ok(o)) => o,
        Ok(Err(kind)) => {
            let (message, level) = wait_failure(kind);
            // Disconnected ⇒ sender 已随线程结束被丢弃，join 立刻返回，只借它取 panic 载荷；
            // Timeout 时工作线程仍在盘上跑（进程内原生调用拦不住），不能 join。
            let detail = match kind {
                mpsc::RecvTimeoutError::Disconnected => match worker.join() {
                    Ok(()) => "工作线程未返回结果即结束".to_string(),
                    Err(p) => format!("工作线程 panic: {}", panic_payload(&*p)),
                },
                mpsc::RecvTimeoutError::Timeout => String::new(),
            };
            cleanup_residue(&residue_dir, true);
            if detail.is_empty() {
                log::write_log(level, message);
            } else {
                log::write_log(level, &format!("{message}（{detail}）"));
            }
            return Ok(json!({ "success": false, "message": message }));
        }
        Err(e) => {
            cleanup_residue(&residue_dir, true);
            log::write_log("error", &format!("磁盘测速等待任务异常: {e}"));
            return Ok(json!({ "success": false, "message": format!("磁盘测速等待任务异常: {e}") }));
        }
    };

    let data: Value = match serde_json::from_str(out.trim()) {
        Ok(v) => v,
        Err(e) => {
            cleanup_residue(&residue_dir, true);
            log::write_log("warn", &format!("磁盘测速结果解析失败: {e}"));
            return Ok(json!({ "success": false, "message": format!("磁盘测速结果解析失败: {e}") }));
        }
    };

    let measured = data.get("measured").and_then(|v| v.as_bool()) == Some(true);
    // 目录是这里建的，收尾也归这里删：**成功分支同样要清**（原生只删自己建的文件，
    // 旧写法把「原生会自删目录」当假设，实测每次成功都在用户目录下留一个空目录）。
    cleanup_residue(&residue_dir, !measured);
    Ok(bench_response(data, param_warn))
}

#[cfg(test)]
mod p1_6e_diskbench_param_tests {
    use super::{bench_response, claim_residue_dir, pick, DISKBENCH_DIR_CLAIM_TRIES};
    use serde_json::json;
    use std::path::{Path, PathBuf};

    const QD: &[i64] = &[1, 8, 32];

    /// 「没给键」与「给了但不在档位」都回落默认，但只有后者留痕（P1-6E①）。
    /// 判红自证：把 `pick` 的 `None => return default` 之外那条 `warn.push` 删掉 ⇒ 第二段红。
    #[test]
    fn 缺键不告警_档位外与带小数都要点名() {
        let mut w: Vec<String> = Vec::new();
        assert_eq!(pick(None, QD, 1, "队列深度", &mut w), 1);
        assert!(w.is_empty(), "前端没传这个键不是异常：{w:?}");

        assert_eq!(pick(Some(&json!(3)), QD, 1, "队列深度", &mut w), 1);
        assert_eq!(w.len(), 1, "档位外的值必须留痕：{w:?}");
        assert!(w[0].contains("队列深度") && w[0].contains("3") && w[0].contains("默认 1"), "告警要点名参数、原值与回落值：{w:?}");

        assert_eq!(pick(Some(&json!("8")), QD, 1, "队列深度", &mut w), 8);
        assert_eq!(w.len(), 1, "数字字符串命中档位，不追加告警：{w:?}");

        assert_eq!(pick(Some(&json!(8.5)), QD, 1, "队列深度", &mut w), 8);
        assert_eq!(w.len(), 2, "带小数取整也要留痕，否则「8.5」静默变成 8：{w:?}");
        assert!(w[1].contains("不是整数"), "告警要说清是取整不是回落：{w:?}");

        assert_eq!(pick(Some(&json!("abc")), QD, 1, "队列深度", &mut w), 1);
        assert_eq!(w.len(), 3, "给了但不是数字同样要留痕：{w:?}");
    }

    /// 测速没跑成时，原生侧的失败原因必须抬到 `message`。
    /// 旧写法只吐 `{"success":false}`，前端 `new Error(response.message)` 得到
    /// 「磁盘测速失败：undefined」——真正的失败原因整条消失。
    /// 判红自证：把 `bench_response` 里 `!measured` 那段删掉 ⇒ 第一条红。
    #[test]
    fn 原生error不得折成无消息() {
        let r = bench_response(json!({ "error": "测试文件只建成 1/8 个，本轮测速作废" }), Vec::new());
        assert_eq!(r["success"], json!(false));
        assert_eq!(r["message"], json!("测试文件只建成 1/8 个，本轮测速作废"));

        // measured 缺失/为 false 但也没有 error：仍要给一句可显示的说明，不能再留 undefined
        let r2 = bench_response(json!({ "sequentialRead": 0.0 }), Vec::new());
        assert_eq!(r2["success"], json!(false));
        assert!(r2["message"].as_str().unwrap_or_default().contains("磁盘测速"), "无 error 也要有兜底文案：{r2}");

        // 成功分支不造 message 字段，前端按 success 走展示路径
        let r3 = bench_response(json!({ "measured": true, "iops": 1234 }), Vec::new());
        assert_eq!(r3["success"], json!(true));
        assert!(r3.get("message").is_none(), "成功回执不塞 message：{r3}");
    }

    /// 告警只有一个出口：`pick` 的回落与原生 `data.warn` 合并进同一个 `warn` 数组，
    /// 空清单整段缺席（前端不必分辨两种形态）。
    /// 判红自证：把 `bench_response` 里合并 `data.warn` 的循环删掉 ⇒ 第二条红。
    #[test]
    fn 两路告警合成一个warn数组且空时缺席() {
        let clean = bench_response(json!({ "measured": true }), Vec::new());
        assert!(clean.get("warn").is_none(), "无告警不塞空数组：{clean}");

        let r = bench_response(
            json!({ "measured": true, "warn": ["qd=3 不在档位内，已按 1 执行"] }),
            vec!["线程数的 9 不是可选值，已按默认 1 执行".to_string()],
        );
        let arr = r["warn"].as_array().expect("warn 必须是数组");
        assert_eq!(arr.len(), 2, "前端侧与原生侧各一条：{arr:?}");
        assert!(arr.iter().any(|x| x.as_str().unwrap_or_default().contains("线程数")));
        assert!(arr.iter().any(|x| x.as_str().unwrap_or_default().contains("qd=3")));
        // data 原样带回，历史记录字段一个都不能少
        assert_eq!(r["data"]["measured"], json!(true));
    }

    /// R1d-M10：单飞位所有权移进工作线程，超时出口不再提前放位。
    /// 判红自证：把 worker_guard 捕获移出闭包（恢复 `let _run_guard`）⇒ 断言红。
    #[test]
    fn 测速单飞位所有权交给工作线程() {
        let src = include_str!("diskbench.rs");
        assert!(src.contains(concat!("let run_guard", " = RunGuard;")), "命令体持有 guard 以覆盖早退路径");
        assert!(src.contains(concat!("let worker_guard", " = run_guard;")), "spawn 前把 guard 移进闭包");
        assert!(src.contains(concat!("let _worker_guard", " = worker_guard;")), "工作线程收尾才放位");
    }

    /// R1d-L04：线程异常结束（sender 丢弃）不许再说成「超时」。
    /// 判红自证：把 `wait_failure` 的 `Disconnected` 臂并回 Timeout ⇒ 前三条断言红。
    #[test]
    fn 超时与线程异常结束不是同一句话() {
        use std::sync::mpsc::RecvTimeoutError;
        let (t_msg, t_level) = super::wait_failure(RecvTimeoutError::Timeout);
        let (d_msg, d_level) = super::wait_failure(RecvTimeoutError::Disconnected);
        assert_ne!(t_msg, d_msg, "两种失败必须给两句话");
        assert!(!d_msg.contains("超时"), "线程结束不是超时: {d_msg}");
        assert!(t_msg.contains("超时"), "超时那条要说得出来是超时: {t_msg}");
        assert_eq!((t_level, d_level), ("warn", "error"), "线程异常要按 error 记账");
    }

    /// R1d-L01：路径校验失败必须发生在单飞占位之前；无效路径连调两次也不能
    /// 表现成「上一场还在进行」。
    /// 判红自证：把 CAS 块移回入口，源序断言立即红。
    #[test]
    fn r1d_diskbench_singleflight_after_validation() {
        let src = include_str!("diskbench.rs");
        let cas = src.find("compare_exchange(false, true").expect("单飞 CAS 必须仍在源里");
        let probe = |needle: &str, label: &str| -> usize {
            let mut pos = 0usize;
            while let Some(idx) = src[pos..].find(needle) {
                let absolute = pos + idx;
                if absolute < src.find("#[cfg(test)]").unwrap_or(src.len()) {
                    return absolute;
                }
                pos = absolute + 1;
            }
            panic!("{label}必须仍在源里");
        };
        let requested = probe("if requested.is_empty()", "路径存在校验");
        let resolved = probe("symlink_metadata(&requested)", "普通目录校验");
        let whitelist = probe("if !is_diskbench_allowed_path(&resolved)", "白名单校验");
        assert!(requested < cas, "路径存在校验必须先于单飞 CAS");
        assert!(resolved < cas, "普通目录校验必须先于单飞 CAS");
        assert!(whitelist < cas, "白名单校验必须先于单飞 CAS");
    }

    /// R1d-L02：canonicalize 失败只能拒，不能把带 `..` 的原串交给白名单判定。
    /// 判红自证：恢复 canonical 失败回落，第一条断言红。
    #[test]
    fn r1d_diskbench_rejects_uncanonical_path() {
        let src = include_str!("diskbench.rs");
        let implementation_end = src.find("#[cfg(test)]").unwrap_or(src.len());
        let implementation = &src[..implementation_end];
        assert!(
            implementation.contains(r#".ok_or_else(|| "测速路径无法规范化，已拒绝".to_string())?"#),
            "canonicalize 失败必须直接拒"
        );
        assert!(
            !implementation.contains("canonical(Path::new(&requested)).unwrap_or_else"),
            "不得回落未归一串"
        );

        let user = std::env::var("USERNAME").unwrap_or_default();
        let probe = format!(r"C:\Users\{user}\..\..\Windows");
        assert!(probe.contains(r"\..\..\"), "验收探针必须保留未折叠形态: {probe}");
    }

    /// R1d-L05：清理只许删「本场 `create_dir` 占位成功」的那个目录，
    /// 不许按「名字像本场产物」删——同名目录可能是上轮遗留或用户自建。
    /// 判红自证：把换号重试去掉（或改成「已存在就采用」）⇒ 前三条断言红。
    #[test]
    fn 残留目录只认本场占位成功的那个() {
        let base = Path::new(r"C:\bench");
        let mut tried: Vec<PathBuf> = Vec::new();
        let refused = claim_residue_dir(base, |p: &Path| -> std::io::Result<()> {
            tried.push(p.to_path_buf());
            Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
        });
        assert!(refused.is_err(), "一直占不到必须拒绝运行，不许采用同名目录: {refused:?}");
        assert_eq!(tried.len(), DISKBENCH_DIR_CLAIM_TRIES, "换号次数用尽才放弃");
        let uniq: std::collections::HashSet<&PathBuf> = tried.iter().collect();
        assert_eq!(uniq.len(), tried.len(), "每次重试必须换新世代号：{tried:?}");
        assert!(
            tried.iter().all(|p| p.parent() == Some(base)),
            "候选必须落在用户所选目录下：{tried:?}"
        );

        // 占位失败几次后成功：返回的必须是本次占到的路径，且仍在用户所选目录下
        let mut n = 0usize;
        let claimed = claim_residue_dir(base, |_: &Path| {
            n += 1;
            if n < 3 {
                Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
            } else {
                Ok(())
            }
        })
        .expect("第三次占位应成功");
        assert_eq!(claimed.parent(), Some(base), "返回路径必须仍在用户所选目录下");
        assert!(
            claimed
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("Trim-DiskBench-"))
                .unwrap_or(false),
            "目录名必须带世代号: {}",
            claimed.display()
        );
    }
}
