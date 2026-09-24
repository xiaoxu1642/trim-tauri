//! PowerShell 7 执行层（对照 main.js 505-785 段 + src/main/pwsh-runtime.js）
//!
//! 候选链（顺序即优先级，与 JS 侧逐条对齐）：
//! ① env PWSH7_PATH ② %ProgramFiles%\PowerShell\7\pwsh.exe ③ where.exe pwsh.exe
//! ④ %LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe（仅非 0 字节的真实安装；0 字节是
//!    Store 应用执行别名存根，执行会拉起商店）⑤ 内置运行时
//!   %LOCALAPPDATA%\Trim\pwsh\<version>\pwsh.exe（仅 .ready 标记存在时）
//!
//! **刻意不做 Windows PowerShell 5.1 兜底**：PS 引擎脚本使用 PS7 专属语法与
//! UTF-8 默认编码，5.1 静默降级会产生假结果，比明确失败更危险（设计文档方案 A 同口径）。
//!
//! 临时脚本写 `<数据目录>\tmp\`（当前用户 ACL 保护）而非 %TEMP%（全局可写，
//! 提权执行时构成 TOCTOU 本地提权窗口，审查 A1）；`.ps1` 带 UTF-8 BOM
//! （PS 5.1/7 均兼容，避免无 BOM 中文注释乱码解析失败）。
//! 保护手段**只有那一条 ACL**：NTFS 没有 POSIX mode 位，`set_permissions(0o600)`
//! 在 Windows 上只能改只读位、对同用户其他进程零约束，故不做也不声称。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::engine::{log, paths};

pub struct PsOutput {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
    pub timed_out: bool,
}

// ==================== 子进程树兜底（审查 M6） ====================
//
// `child.kill()` 只杀 pwsh 本身。脚本里 `& dism.exe ... | Out-String`（cleanup_execute.ps1:573）、
// `sfc`（maint_sfc.ps1:38）、`Start-Process -Wait` 起的安装器都是 pwsh 的**子孙**，
// 它们继续握着 stdout 写端 → 读管道的线程不会返回 → `join()` 一直阻塞。
// 实测：超时配 5s，真实耗时 24.4s，且成功路径（code=0）一样能被挂住 —— 「超时」形同虚设，
// 用户看到「超时失败、可重试」后重试，第二个 DISM 就与不可回滚的 /ResetBase 并发跑。
//
// 解法是 Windows 的 Job Object：pwsh 一 spawn 就放进 job（子孙自动继承成员资格），
// 超时那一刻 `TerminateJobObject` 一次干掉整棵树，管道写端全部关闭，读线程随即返回。
//
// **刻意不用 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`**：多个脚本会用不带 -Wait 的
// `Start-Process` 故意留下长命进程 —— cleanup_execute.ps1:276-277 重启刚被清理的应用、
// cm_restart_explorer.ps1:25 拉起 explorer.exe、maint_store.ps1:38 跑 wsreset.exe。
// 那些进程同样是 job 成员，若「关句柄即杀全树」，正常跑完时反而会把用户的 explorer /
// 应用一起杀掉。所以只在**超时**这一条路径上显式 Terminate，成功路径只 CloseHandle。
/// 一次性 Job Object 句柄；Drop 只关句柄（**不**杀成员，理由见上）。
pub struct ProcessJob(windows::Win32::Foundation::HANDLE);

impl ProcessJob {
    /// 建 job 并把**已 spawn 的子进程**放进去。任一步失败都返回 `Err`，调用方降级为
    /// 「只杀 pwsh」的旧行为 —— 建不了 job 不该让整条 PS 执行链失败。
    fn create_for(child_pid: u32) -> Result<Self, String> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };
        unsafe {
            let job = CreateJobObjectW(None, PCWSTR::null())
                .map_err(|e| format!("建 Job 失败: {e}"))?;
            // AssignProcessToJobObject 要求进程句柄带 PROCESS_SET_QUOTA | PROCESS_TERMINATE，
            // std::process::Child 自带的那个权限位不足，故按 PID 另开一个。
            // PID 复用窗口极小：就在 spawn 之后的这几微秒内，且子进程尚未退出。
            let proc = match OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                child_pid,
            ) {
                Ok(h) => h,
                Err(e) => {
                    let _ = CloseHandle(job);
                    return Err(format!("打开子进程句柄失败: {e}"));
                }
            };
            let assigned = AssignProcessToJobObject(job, proc);
            let _ = CloseHandle(proc);
            if let Err(e) = assigned {
                let _ = CloseHandle(job);
                return Err(format!("子进程入 Job 失败: {e}"));
            }
            Ok(Self(job))
        }
    }

    /// 终止 job 内**全部**进程（含子孙）。超时专用。
    fn terminate(&self) {
        use windows::Win32::System::JobObjects::TerminateJobObject;
        unsafe {
            let _ = TerminateJobObject(self.0, 1);
        }
    }
}

impl Drop for ProcessJob {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// 读管道宽限期：pwsh 本体已不在跑，但子孙可能还占着 stdout/stderr 写端。
/// 等 `READ_GRACE` 让正常输出冲刷完；等不到就终止子进程树再收一次。
/// 返回空串只发生在「终止之后仍读不到」这一种情况下（此时线程已失控，宁可截断）。
fn take_reader(rx: std::sync::mpsc::Receiver<String>, job: &Option<ProcessJob>) -> String {
    const READ_GRACE: Duration = Duration::from_secs(5);
    match rx.recv_timeout(READ_GRACE) {
        Ok(s) => s,
        Err(_) => {
            if let Some(j) = job {
                j.terminate();
            }
            log::write_log("warn", "子进程树占住输出管道超过宽限期，已终止后再收一次");
            rx.recv_timeout(READ_GRACE).unwrap_or_default()
        }
    }
}

static CACHED_PWSH: Mutex<Option<PathBuf>> = Mutex::new(None);
/// 探测失败负缓存时间戳（ms）：损坏/卡死的候选会拖满超时，60s 内复用失败结论
static PROBE_FAILED_AT: AtomicI64 = AtomicI64::new(0);
static PROBE_ERROR: Mutex<Option<String>> = Mutex::new(None);
const PROBE_FAIL_TTL_MS: i64 = 60_000;

/// 内置运行时版本（与 vendor/pwsh 包一致）
pub const PWSH_VERSION: &str = "7.6.6";

fn local_appdata() -> PathBuf {
    let v = std::env::var("LOCALAPPDATA").unwrap_or_default();
    if v.is_empty() {
        PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default())
            .join("AppData")
            .join("Local")
    } else {
        PathBuf::from(v)
    }
}

fn runtime_root_dir() -> PathBuf {
    local_appdata().join("Trim").join("pwsh")
}

fn pwsh_exe_path_for(version: &str) -> PathBuf {
    runtime_root_dir().join(version).join("pwsh.exe")
}

fn ready_marker_path(version: &str) -> PathBuf {
    runtime_root_dir().join(version).join(".ready")
}

/// 指定版本是否就绪（exe 存在非 0 字节 + .ready 标记存在）
pub fn is_version_ready(version: &str) -> bool {
    let exe = pwsh_exe_path_for(version);
    let marker = ready_marker_path(version);
    exe.is_file()
        && std::fs::metadata(&exe).map(|m| m.len() > 0).unwrap_or(false)
        && marker.is_file()
}

/// 最新已就绪的内置运行时 exe（按 .ready mtime 倒序取第一个）
pub fn latest_ready_exe_path() -> Option<PathBuf> {
    let root = runtime_root_dir();
    let mut ready: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();
    for entry in std::fs::read_dir(&root).ok()?.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_version_ready(&name) {
            continue;
        }
        let mtime = std::fs::metadata(ready_marker_path(&name))
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        ready.push((pwsh_exe_path_for(&name), mtime));
    }
    ready.sort_by(|a, b| b.1.cmp(&a.1));
    ready.into_iter().next().map(|(p, _)| p)
}

/// 候选链解析。失败返回 (code, 消息)：code ∈ {PWSH7_NOT_FOUND, PWSH7_PREPARING}
pub fn resolve_pwsh() -> Result<PathBuf, (String, String)> {
    if let Some(p) = CACHED_PWSH.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return Ok(p);
    }
    let now = crate::engine::now_ms();
    let failed_at = PROBE_FAILED_AT.load(Ordering::Relaxed);
    if failed_at > 0 && now - failed_at < PROBE_FAIL_TTL_MS {
        let msg = PROBE_ERROR
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(|| "未找到 PowerShell 7（pwsh.exe）".into());
        return Err(("PWSH7_NOT_FOUND".into(), msg));
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("PWSH7_PATH") {
        if !p.trim().is_empty() {
            candidates.push(PathBuf::from(p));
        }
    }
    if let Ok(pf) = std::env::var("ProgramFiles") {
        candidates.push(PathBuf::from(pf).join("PowerShell").join("7").join("pwsh.exe"));
    }
    // where.exe pwsh.exe（尊重用户自装版本）
    if let Ok(out) = Command::new("where.exe").arg("pwsh.exe").output() {
        if out.status.success() {
            for line in String::from_utf8_lossy(&out.stdout).split(['\r', '\n']) {
                let line = line.trim();
                if !line.is_empty() {
                    candidates.push(PathBuf::from(line));
                }
            }
        }
    }
    // WindowsApps 存根：排后，且仅非 0 字节时才算真实安装
    let stub = local_appdata()
        .join("Microsoft")
        .join("WindowsApps")
        .join("pwsh.exe");
    if std::fs::metadata(&stub).map(|m| m.len() > 0).unwrap_or(false) {
        candidates.push(stub);
    }
    // 内置运行时：最末位（尊重用户自装版本，避免版本分裂）
    if let Some(builtin) = latest_ready_exe_path() {
        candidates.push(builtin);
    }

    for candidate in candidates {
        if candidate.is_file() && is_pwsh7_executable(&candidate) {
            *CACHED_PWSH.lock().unwrap_or_else(|e| e.into_inner()) = Some(candidate.clone());
            *PROBE_ERROR.lock().unwrap_or_else(|e| e.into_inner()) = None;
            PROBE_FAILED_AT.store(0, Ordering::Relaxed);
            return Ok(candidate);
        }
    }

    // 审查 M9：不得承诺「内置运行时」——随包解压链在 Phase 4 才决定，当前仓库里没有
    // 任何内置 zip 资产，`latest_ready_exe_path()` 恒为空。指向「设置页立即准备」同样
    // 是错的（pwsh:prepare 只是重跑本候选链）。文案只说用户能做到的事。
    let msg = "未找到 PowerShell 7（pwsh.exe）。请先安装 PowerShell 7（winget install Microsoft.PowerShell）后重试。".to_string();
    PROBE_FAILED_AT.store(crate::engine::now_ms(), Ordering::Relaxed);
    *PROBE_ERROR.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg.clone());
    Err(("PWSH7_NOT_FOUND".into(), msg))
}

/// 探测候选是否可用的 PS7（跑一句版本号，5s 超时）
fn is_pwsh7_executable(exe: &Path) -> bool {
    let mut child = match Command::new(exe)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$PSVersionTable.PSVersion.Major",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    out.trim().starts_with('7')
}

/// 写临时 PowerShell 脚本：返回脚本绝对路径（调用方负责执行后删除）
pub fn write_temp_script(content: &str, suffix: &str) -> Result<PathBuf, String> {
    let dir = paths::temp_script_dir()?;
    let file = dir.join(format!(
        "script_{}_{}{}",
        crate::engine::now_ms(),
        random_token(),
        suffix
    ));
    // .ps1 写入带 BOM 的 UTF-8：PS 5.1 默认按系统 ANSI 读取无 BOM 脚本，
    // 中文注释会乱码导致解析失败；PS7 亦兼容 BOM。
    let bytes: Vec<u8> = if suffix.eq_ignore_ascii_case(".ps1") {
        let mut v = vec![0xEF, 0xBB, 0xBF];
        v.extend_from_slice(content.as_bytes());
        v
    } else {
        content.as_bytes().to_vec()
    };
    std::fs::write(&file, bytes).map_err(|e| format!("写入临时脚本失败: {e}"))?;
    Ok(file)
}

fn random_token() -> String {
    use std::sync::atomic::AtomicU32;
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{nanos:x}{n:x}")
}

/// 执行临时脚本文件（`-File` 方式，避免命令行长度上限）。
/// 超时 kill 并返回 `timed_out=true`（调用方按 code=-1 处理，与 JS 侧一致）。
pub fn run_file(script_path: &Path, timeout: Duration, diag_op: Option<&str>) -> Result<PsOutput, String> {
    run_file_impl(script_path, timeout, diag_op, None)
}

/// 流式执行：脚本每输出一行就立刻交给 `on_line`，同时**仍然**累积完整 stdout，
/// 所以 `@@RESULT@@` / `@@DIAG@@` 等收尾后处理与 `run_file` 完全一致。
///
/// 为什么单独开函数、而不是给 `run_file` 加一个 `Option<回调>`：那样这条路径是实时的
/// 这件事会藏进一个 `None` 里。两个必须让读代码的人一眼看到的约束：
/// 1. **回调在 stdout 读取线程上执行** —— 回调里阻塞（等锁、等通道）会直接把管道堵住，
///    脚本随后的输出全卡住，最后撞超时。只准做投递（`emit`）这类有界动作。
/// 2. 超时 kill 后仍可能有已缓冲的行回调出来，调用方需自己判幂等。
pub fn run_file_streaming<F>(
    script_path: &Path,
    timeout: Duration,
    diag_op: Option<&str>,
    on_line: F,
) -> Result<PsOutput, String>
where
    F: FnMut(&str) + Send + 'static,
{
    run_file_impl(script_path, timeout, diag_op, Some(Box::new(on_line)))
}

fn run_file_impl(
    script_path: &Path,
    timeout: Duration,
    diag_op: Option<&str>,
    on_line: Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<PsOutput, String> {
    let exe = resolve_pwsh().map_err(|(_, msg)| msg)?;
    let trim_tmp = paths::temp_script_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut child = Command::new(&exe)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(script_path)
        .env("TRIM_TMP", trim_tmp)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("PowerShell 7 启动失败: {e}"))?;

    // 审查 M6：立刻把 pwsh 塞进 Job Object（趁它还没来得及 spawn 子孙）。
    // 建不了 job 时只降级、不失败：大不了退回「超时只杀 pwsh 本体」的旧行为，并在日志里留痕。
    let job = match ProcessJob::create_for(child.id()) {
        Ok(j) => Some(j),
        Err(e) => {
            log::write_log("warn", &format!("子进程树兜底不可用，超时将只能杀 pwsh 本体: {e}"));
            None
        }
    };

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    // 读线程用 channel 交结果，不用 `join()`：`join` 不可中断，只要还有子孙握着管道写端
    // 就会无限期挂住 —— 实测 pwsh 已 `code=0` 退出，函数仍挂 19.7s（被一个 20s 的 ping 拖住）。
    // 只有 channel 能做到「等一段，等不到就去终止子进程树」。
    let (tx_out, rx_out) = std::sync::mpsc::channel();
    let (tx_err, rx_err) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx_out.send(read_all(stdout_pipe, on_line));
    });
    std::thread::spawn(move || {
        let _ = tx_err.send(read_all(stderr_pipe, None));
    });

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let mut code = -1i32;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                code = status.code().unwrap_or(-1);
                break;
            }
            Ok(None) => {
                if Instant::now() > deadline {
                    // 顺序要紧：先终止整棵子进程树（管道写端随之全部关闭），再 kill/wait pwsh
                    // 本体。只 kill 本体的话，读线程还在等 dism/sfc/安装器退出，
                    // 循环之后的 join() 会把「超时」拖成「等子孙自己跑完」（实测 5s→24.4s）。
                    if let Some(j) = &job {
                        j.terminate();
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(format!("等待 PowerShell 7 失败: {e}")),
        }
    }

    // 本体已退出（或被终止），剩下的只是某个子孙还占着管道写端：给一段宽限期冲刷正常输出，
    // 等不到就终止整棵树。宁可截断也不无限期挂住调用方 —— 清理/维护主循环等不起，
    // 而且「超时了」的语义要求函数真的在超时点返回。
    let mut stdout = take_reader(rx_out, &job);
    let mut stderr = take_reader(rx_err, &job);
    if timed_out {
        stderr.push_str("\nPowerShell 7 执行超时");
        code = -1;
    }
    // @@DIAG@@ 诊断行转日志并从 stdout 剔除（与 extractDiagLines 同口径）
    let stdout_clean = match diag_op {
        Some(op) => crate::diag::extract_diag_lines(&stdout, op),
        None => std::mem::take(&mut stdout),
    };
    if code != 0 && !stderr.trim().is_empty() {
        log::write_log("warn", &format!("PowerShell 7 退出码 {code}: {}", stderr.trim()));
    }
    Ok(PsOutput {
        stdout: stdout_clean,
        stderr,
        code,
        timed_out,
    })
}

/// 读尽管道；带 `on_line` 时边读边回调完整行。
///
/// 逐行切分**不改变**最终返回的字符串：所有字节（含 `\r`、`\n` 与末尾残段）都照原样
/// 进 `acc`，最后仍按整体 `from_utf8_lossy`。回调收到的行是去掉尾部 `\r` 的内容；
/// 末尾没有换行的残段在流结束时也补发一次，保证「回调看到的行集合 == stdout 按行切」。
fn read_all(pipe: Option<impl Read>, mut on_line: Option<Box<dyn FnMut(&str) + Send>>) -> String {
    let mut acc: Vec<u8> = Vec::new();
    let mut line_buf: Vec<u8> = Vec::new();
    if let Some(mut p) = pipe {
        let mut chunk = [0u8; 4096];
        loop {
            match p.read(&mut chunk) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    acc.extend_from_slice(&chunk[..n]);
                    if let Some(cb) = on_line.as_mut() {
                        for b in &chunk[..n] {
                            if *b == b'\n' {
                                let line = String::from_utf8_lossy(&line_buf).replace('\r', "");
                                cb(&line);
                                line_buf.clear();
                            } else {
                                line_buf.push(*b);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        if let Some(cb) = on_line.as_mut() {
            if !line_buf.is_empty() {
                let line = String::from_utf8_lossy(&line_buf).replace('\r', "");
                cb(&line);
                line_buf.clear();
            }
        }
    }
    String::from_utf8_lossy(&acc).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// 跑一次带回调的读取，返回（最终 stdout 字符串, 回调收到的行序列）。
    /// 回调要求 `Send + 'static`，所以收集容器只能放 Arc<Mutex<..>> 里由闭包持有，
    /// 读完后 Arc 引用数已归 1，可安全 into_inner。
    fn collect(input: &str) -> (String, Vec<String>) {
        let shared = Arc::new(Mutex::new(Vec::<String>::new()));
        let s = {
            let shared = Arc::clone(&shared);
            Box::new(move |l: &str| shared.lock().unwrap().push(l.to_string()))
                as Box<dyn FnMut(&str) + Send>
        };
        let out = read_all(Some(std::io::Cursor::new(input.as_bytes())), Some(s));
        let lines = Arc::try_unwrap(shared)
            .expect("回调闭包应已随 read_all 结束而释放")
            .into_inner()
            .unwrap();
        (out, lines)
    }

    #[test]
    fn 加回调不得改变最终stdout字节() {
        let input = "a\r\nb\n@@PROGRESS:50@@\n\rc";
        let plain = read_all(Some(std::io::Cursor::new(input.as_bytes())), None);
        let (with_cb, _) = collect(input);
        assert_eq!(plain, with_cb, "流式路径必须与原来的一次性收集逐字节一致");
        assert_eq!(with_cb, input);
    }

    #[test]
    fn 回调行集合等于按行切分() {
        let (_, lines) = collect("one\r\ntwo\nthree\n");
        // \r 被剥掉；每个 \n 触发一行；结尾本就有换行故不产生空尾行
        assert_eq!(lines, vec!["one", "two", "three"]);
    }

    #[test]
    fn 末尾无换行的残段也必须补发() {
        // 脚本被超时 kill 时最后一行常常没有换行。不补发就会丢一条 @@PROGRESS@@，
        // 进度条永久停在半路 —— 正是本次改造要消灭的现象。
        let (_, lines) = collect("a\nTAIL");
        assert_eq!(lines, vec!["a", "TAIL"]);
    }

    #[test]
    fn 空输入得到空串与零行() {
        let (s, lines) = collect("");
        assert_eq!(s, "");
        assert!(lines.is_empty());
    }

    #[test]
    fn 中文行不被拆坏() {
        // \n 字节不可能出现在 UTF-8 多字节序列内部，故逐行 lossy 与整体 lossy 等价。
        let input = "清理完成\n开始扫描\n旧缓存备份\n";
        let (s, lines) = collect(input);
        assert_eq!(s, input);
        assert_eq!(lines, vec!["清理完成", "开始扫描", "旧缓存备份"]);
    }

    #[test]
    fn 协议行读取层不得吞行() {
        let (_, lines) = collect("@@PROGRESS:0@@\n@@PROGRESS:37@@\n@@PROGRESS:37@@\n@@DONE@@\n");
        let pcts: Vec<u32> = lines
            .iter()
            .filter_map(|l| {
                l.trim()
                    .strip_prefix("@@PROGRESS:")
                    .and_then(|x| x.strip_suffix("@@"))
                    .and_then(|x| x.parse().ok())
            })
            .collect();
        // 同值重复行照原样交出去，去重是调用方的策略，读取层不做判断
        assert_eq!(pcts, vec![0, 37, 37]);
    }

    #[test]
    fn 大输出跨多个读取块仍完整() {
        // 单块 4096 字节，构造 3 倍长度的行序列逼出多次 read 拼接
        let input = "x".repeat(5000) + "\n" + &"y".repeat(8000) + "\n";
        let (s, lines) = collect(&input);
        assert_eq!(s, input);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), 5000);
        assert_eq!(lines[1].len(), 8000);
    }

    /// 真机串流验证：上面几条只测了读取器，这条测的是**整条 pwsh 执行路径**。
    /// 只回显文本，不碰注册表/文件/进程，故无副作用；需要本机装了 PowerShell 7，
    /// 与其余 7 条慢测同属发布前门禁。
    #[test]
    #[ignore = "真实启动 PowerShell 7，发布前门禁跑"]
    fn 真实pwsh流式按序收到每一行协议() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // 故意在协议行之间夹中文与普通行，验证不串字、不吞行、顺序不乱
        let script = "Write-Output '@@PROGRESS:0@@'\n\
                      Write-Output '正在扫描组件存储'\n\
                      Write-Output '@@PROGRESS:50@@'\n\
                      Write-Output '@@PROGRESS:50@@'\n\
                      Write-Output '@@DONE@@'";
        let path = write_temp_script(script, ".ps1").unwrap();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let count = Arc::new(AtomicUsize::new(0));
        let (s, c) = (Arc::clone(&seen), Arc::clone(&count));
        let out = run_file_streaming(
            &path,
            Duration::from_secs(60),
            None,
            move |line| {
                c.fetch_add(1, Ordering::SeqCst);
                s.lock().unwrap().push(line.to_string());
            },
        );
        let _ = std::fs::remove_file(&path);
        let out = out.expect("pwsh 流式执行失败");
        let lines = seen.lock().unwrap().clone();

        assert_eq!(out.code, 0, "stderr: {}", out.stderr);
        assert_eq!(
            lines,
            vec!["@@PROGRESS:0@@", "正在扫描组件存储", "@@PROGRESS:50@@", "@@PROGRESS:50@@", "@@DONE@@"],
            "回调必须按序收到每一行，包括同值重复行（去重是调用方的策略）"
        );
        assert_eq!(count.load(Ordering::SeqCst), lines.len());
        // 流式与一次性收集必须给出同一个 stdout，收尾解析才不会看到不同视图
        assert!(out.stdout.contains("@@DONE@@"), "累积 stdout 应含全部输出: {}", out.stdout);
        for probe in ["@@PROGRESS:50@@", "正在扫描组件存储"] {
            assert!(out.stdout.contains(probe), "stdout 丢了 {probe}");
        }
    }

    /// 审查 M6 回归断言：**子孙进程握着 stdout 写端时，函数必须自己收回来**。
    ///
    /// 脚本用 `Start-Process -NoNewWindow`（不带 -Wait）拉起一个 20 秒的 ping：它继承 pwsh 的
    /// 标准输出，pwsh 自己立刻 `exit 0`，但读线程要等这个子孙关掉写端才能返回。
    /// 旧实现是 `join()`（不可中断）→ 实测 pwsh 早已 code=0 退出，函数仍挂 19.7s。
    /// 现在走 channel + 宽限期 + `TerminateJobObject`，应在 5s 宽限期后把树杀掉并返回。
    /// 断言只看墙上时间与退出码（ping 到 localhost，无副作用）。
    #[test]
    #[ignore = "真实启动 PowerShell 7 与子孙进程，发布前门禁跑"]
    fn 子孙进程占住管道时函数必须自己收回来() {
        let script = "$g = Start-Process -FilePath 'ping' -ArgumentList '-n','20','127.0.0.1' -NoNewWindow -PassThru\n\
                      Write-Output '@@DONE@@'";
        let path = write_temp_script(script, ".ps1").unwrap();
        let started = Instant::now();
        let out = run_file(&path, Duration::from_secs(60), None);
        let elapsed = started.elapsed();
        let _ = std::fs::remove_file(&path);

        let out = out.expect("pwsh 执行链本身不应报错");
        assert_eq!(out.code, 0, "本体是正常退出的，不该被记成失败: {}", out.stderr);
        assert!(!out.timed_out, "本体没超时，不应判 timed_out");
        assert!(
            elapsed < Duration::from_secs(12),
            "应在宽限期后终止子进程树并返回（旧实现会等 ping 自己跑完 ≈20s），实耗 {elapsed:?}"
        );
        assert!(out.stdout.contains("@@DONE@@"), "正常输出不得被截断: {}", out.stdout);
    }

    /// 审查 M6 的另一半：**本体还在等子孙**（`& dism ... | Out-String` 那种）时，
    /// 超时点必须真的把整棵树收回来并按时返回 —— 否则用户看到「超时失败，可重试」，
    /// 实际第二个 DISM 正与不可回滚的 /ResetBase 并发跑。
    #[test]
    #[ignore = "真实启动 PowerShell 7 与子孙进程，发布前门禁跑"]
    fn 超时必须按时收回整棵子进程树() {
        let script = "& ping -n 20 127.0.0.1 | Out-String\nWrite-Output '@@DONE@@'";
        let path = write_temp_script(script, ".ps1").unwrap();
        let started = Instant::now();
        let out = run_file(&path, Duration::from_secs(4), None);
        let elapsed = started.elapsed();
        let _ = std::fs::remove_file(&path);

        let out = out.expect("pwsh 执行链本身不应报错");
        assert!(out.timed_out, "4s 超时应判定时，实际 code={}", out.code);
        assert!(
            elapsed < Duration::from_secs(9),
            "超时点之后应立刻收树返回（旧实现会被 ping 拖到 ≈20s），实耗 {elapsed:?}"
        );
        assert_eq!(out.code, -1, "超时统一按 -1 回执");
    }
}

/// 清理超过 1 小时的临时脚本（含历史版本遗留在全局可写 %TEMP%\Trim 下的残留）。
/// lstat 不跟随符号链接：非常规文件（链接/设备）直接跳过（审查 1-6）。
pub fn cleanup_temp_scripts() {
    let mut dirs = Vec::new();
    if let Ok(d) = paths::temp_script_dir() {
        dirs.push(d);
    }
    dirs.push(std::env::temp_dir().join("Trim"));
    let cutoff = Duration::from_secs(3600);
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let age = meta
                .modified()
                .ok()
                .and_then(|m| std::time::SystemTime::now().duration_since(m).ok())
                .unwrap_or_default();
            if age > cutoff {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}