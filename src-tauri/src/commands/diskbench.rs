//! diskbench 域（B 批）：diskbench:run（+ `diskbench:progress` 事件）
//!
//! 需在 lib.rs 的 invoke_handler 中注册（本任务不改 lib.rs，请统一登记）：
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
//! - `<路径>\Trim-DiskBench` 残留目录：异常/超时/未完成时递归清理——那是应用自产基准
//!   临时数据（同临时脚本直接 unlink 的既有口径），不进回收站、不落删除清单。
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
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{Emitter, WebviewWindow};

use crate::engine::{guard, log};

/// 剩余空间下限（测速峰值写约 384 MB + 缓冲余量，照抄 main.js 5384）
const DISKBENCH_MIN_FREE_BYTES: u64 = 1024 * 1024 * 1024;

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
fn cleanup_residue(dir: &Path) {
    if !dir.exists() {
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
#[tauri::command]
pub async fn diskbench_run<R: tauri::Runtime>(window: WebviewWindow<R>, options: Option<Value>) -> Result<Value, String> {
    // 审查 v2-L17：测速要独占读盘、属"会动系统资源"的写侧通道，且唯一调用方是主窗的
    // `diskbench.js`（`app.js` 页面表）⇒ 收 MAIN，不用放行五窗的 readonly 档。
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
    let residue_dir = resolved.join("Trim-DiskBench");

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