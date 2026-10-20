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

/// 残留测试目录递归清理（应用自产临时数据；失败只记日志，不影响结果）
///
/// 审查 v3-L1：删前先过 `dir_delete_blocked` —— 与维护任务（搜索索引 / 更新缓存）同一口径。
/// `residue_dir` 位于**用户在 UI 里自选的测速路径**下，若该目录被换成指向别处的 junction，
/// 直接 `remove_dir_all` 会把链接目标一起处理掉；且这是本仓唯一一处「用户可设路径下的
/// 递归删除」，此前恰好漏了这道闸。属性读不到同样按拒绝处理（fail-closed）。
fn cleanup_residue(dir: &Path) {
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
                log::write_log(
                    "warn",
                    &format!("磁盘测速异常结束，已清理残留测试目录: {}", dir.display()),
                );
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

/// 参数白名单化：允许值集合内取原值，否则回落默认
fn pick(v: Option<&Value>, allowed: &[i64], default: i64) -> i64 {
    match js_number(v) {
        Some(n) => {
            let i = n.trunc() as i64;
            if allowed.contains(&i) {
                i
            } else {
                default
            }
        }
        None => default,
    }
}

/// diskbench:run — 磁盘测速（原生引擎优先）
///
/// R1d-M09 的世代号只解决「别去动别人正在写的目录」，**不解决盘上留残**：
/// 成功分支（`measured == true`）刻意不清理，依赖原生引擎自删自己的测试目录。
/// 真机复核项（本轮档位未验）：测成功后 `Trim-DiskBench-<n>` 是否真的消失——
/// 若原生侧没删，应用侧就只会攒下一个空目录（世代号让每次运行换一个名字，
/// 攒的是「一串空残留」而不是「一个空残留」）。复核方法：跑一次成功后列目录，
/// 或让原生侧补一条自删断言（属 N1b 射程，不在本单元定罪）。
#[tauri::command]
pub async fn diskbench_run<R: tauri::Runtime>(window: WebviewWindow<R>, options: Option<Value>) -> Result<Value, String> {
    // 审查 v2-L17：测速要独占读盘、属"会动系统资源"的写侧通道，且唯一调用方是主窗的
    // `diskbench.js`（`app.js` 页面表）⇒ 收 MAIN，不用放行五窗的 readonly 档。
    guard::guard(&window, guard::MAIN)?;
    // v7.2 `R1d-M09`：单飞闸**在入口就占位**。
    // 原生测速是独占读盘的长任务，旧写法没有互斥：连点两次（或两条命令并发）会同时压在
    // 同一块盘上，两份结果都「成功」却都不可信，进度事件还互相插。
    // 占位放在所有校验之前是刻意的：本命令的早退出口有五条（路径不存在/非普通目录/
    // 不在白名单/剩余空间不足/超时），放后面就等于「早退路径根本不占位」⇒ 既守不住
    // 「一场测速正在进行时新请求立刻被拒」，也让释放责任无法用 RAII 统一承担。
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
    // Drop 里放位：五条早退出口与 panic 路径都不用各写一遍 store(false)
    let _run_guard = RunGuard;
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
            canonical(Path::new(&requested)).unwrap_or_else(|| PathBuf::from(&requested))
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

    // 参数白名单化（非法值一律回落默认）
    let block = pick(opts.get("blockSize"), &[4096, 65536, 1048576], 1048576);
    let qd = pick(opts.get("queueDepth"), &[1, 8, 32], 1);
    let threads = pick(opts.get("threads"), &[1, 4, 8], 1);
    let dur = pick(opts.get("duration"), &[4, 8, 16], 8);
    let io_mode = if opts.get("ioMode").and_then(|v| v.as_str()) == Some("buf") {
        "buf"
    } else {
        "nobuf"
    };
    let bench_timeout = Duration::from_millis((dur as u64) * 1000 * 4 + 60_000);

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
    ];
    // ② 世代号——超时只是 `recv_timeout` 返回，**工作线程不会被中断**（同文件头已如实
    //    记录这个限制）。旧写法残留目录固定名 `Trim-DiskBench` ⇒ 超时后清理的是野线程
    //    正在写的那个目录，而野线程随后又把它建回来：清理动作与写入者共用一个名字，
    //    谁先谁后看运气。目录名带本次运行的世代号后，清理只针对自己那一份，
    //    野线程留在盘上的那一份由**它自己**的收尾处理（清理失败会记日志，不静默）。
    let generation = DISKBENCH_GEN.fetch_add(1, Ordering::Relaxed) + 1;
    let residue_dir = resolved.join(format!("Trim-DiskBench-{generation}"));

    // 原生引擎在工作线程内执行：进度行 JSON → diskbench:progress 事件；
    // 主线程用 recv_timeout 模拟 Electron 的进程超时中止。
    let handle = window.clone();
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut emit = |line: &str| {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                let _ = handle.emit("diskbench:progress", v);
            }
        };
        let out = trim_finder::perf::diskbench_json(&args, &mut emit);
        let _ = tx.send(out);
    });

    let out = match rx.recv_timeout(bench_timeout) {
        Ok(o) => o,
        Err(_) => {
            cleanup_residue(&residue_dir);
            log::write_log("warn", "磁盘测速超时（原生引擎）");
            return Ok(json!({ "success": false, "message": "磁盘测速超时（原生引擎）" }));
        }
    };

    let data: Value = match serde_json::from_str(out.trim()) {
        Ok(v) => v,
        Err(e) => {
            cleanup_residue(&residue_dir);
            log::write_log("warn", &format!("磁盘测速结果解析失败: {e}"));
            return Ok(json!({ "success": false, "message": format!("磁盘测速结果解析失败: {e}") }));
        }
    };

    let measured = data.get("measured").and_then(|v| v.as_bool()) == Some(true);
    if !measured {
        // 测量未完成也做残留清理（同异常路径口径）
        cleanup_residue(&residue_dir);
    }
    Ok(json!({ "success": measured, "data": data, "engine": "rust" }))
}