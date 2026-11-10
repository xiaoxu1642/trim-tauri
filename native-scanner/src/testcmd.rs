//! 测试用子进程执行器：带超时 + 杀整树（A14 / X1-L01 一族）。
//!
//! 为什么要有：测试里的 `Command::new(...).output()` **没有超时**——被测命令占住
//! stdout 管道或干脆挂住时，`cargo test` 会永远等下去，一次挂住就废掉整轮验收。
//!
//! 与 `src-tauri` 侧 `engine::testcmd` 是**同一纪律的两份实现**：本 crate 是独立的
//! （`trim-finder` 不依赖 `trim-tauri`，反向依赖会成环），所以只能各写一份；
//! 两边的行为约定保持一致（超时返回 `Err`，不伪装成「命令失败」；Job 杀整树）。
//!
//! 落点说明：不加 `#[cfg(test)]` —— 集成测试编译时 `cfg(test)` 对被依赖 crate 不生效，
//! 收在 cfg(test) 里的话集成测试用不了。生产构建不会调用它。

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// 子进程执行超时。
#[derive(Debug)]
pub struct Timeout {
    /// 超时的时限（与调用方传入的一致，便于回执自证）。
    pub limit: Duration,
    /// 命令行（仅用于报错文案）。
    pub cmd: String,
}

impl std::fmt::Display for Timeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "命令超时（>{:?}）：{}", self.limit, self.cmd)
    }
}

/// Job Object 句柄；Drop 只关句柄（**不**杀成员）。
struct ProcessJob(windows_sys::Win32::Foundation::HANDLE);

impl ProcessJob {
    /// 建 job 并把**已 spawn 的子进程**放进去。
    ///
    /// 建不了 job 时返回 `Err` —— 调用方降级为「超时只杀直接子进程」，不因此判红：
    /// 收树兜底不可用是环境问题，不是被测行为。
    #[cfg(windows)]
    fn create_for(child_pid: u32) -> Result<Self, String> {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };
        unsafe {
            let job: HANDLE = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err("建 Job 失败".to_string());
            }
            let proc = OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                child_pid,
            );
            if proc.is_null() {
                let _ = CloseHandle(job);
                return Err("打开子进程句柄失败".to_string());
            }
            let assigned = AssignProcessToJobObject(job, proc);
            let _ = CloseHandle(proc);
            if assigned == 0 {
                let _ = CloseHandle(job);
                return Err("子进程入 Job 失败".to_string());
            }
            Ok(Self(job))
        }
    }

    /// 终止 job 内**全部**进程（含子孙）。超时专用。
    fn terminate(&self) {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::JobObjects::TerminateJobObject;
            let _ = TerminateJobObject(self.0, 1);
        }
    }
}

impl Drop for ProcessJob {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::Foundation::CloseHandle;
            let _ = CloseHandle(self.0);
        }
    }
}

/// 执行一个子进程并等待其结束；超时则杀整棵树并返回 `Err(Timeout)`。
pub fn run_test_cmd(cmd: &mut Command, timeout: Duration) -> Result<Output, Timeout> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("测试子进程启动失败: {e}"));

    // 立刻入 Job：趁它还没来得及 spawn 子孙。建不了 job 时降级（不因此判红）。
    #[cfg(windows)]
    let job = ProcessJob::create_for(child.id()).ok();
    #[cfg(not(windows))]
    let job: Option<ProcessJob> = None;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let (tx_out, rx_out) = std::sync::mpsc::channel();
    let (tx_err, rx_err) = std::sync::mpsc::channel();

    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = stdout_pipe {
            use std::io::Read;
            let _ = p.read_to_end(&mut buf);
        }
        let _ = tx_out.send(buf);
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = stderr_pipe {
            use std::io::Read;
            let _ = p.read_to_end(&mut buf);
        }
        let _ = tx_err.send(buf);
    });

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break None,
        }
    };

    let status = match status {
        Some(s) => s,
        None => {
            if let Some(j) = &job {
                j.terminate();
            } else {
                let _ = child.kill();
            }
            let _ = child.wait();
            let _ = out_handle.join();
            let _ = err_handle.join();
            return Err(Timeout {
                limit: timeout,
                cmd: format!("{cmd:?}"),
            });
        }
    };

    let stdout_bytes = rx_out.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let stderr_bytes = rx_err.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let _ = out_handle.join();
    let _ = err_handle.join();

    Ok(Output {
        status,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// X1-L01：超时必须真的返回 Timeout（而不是伪装成「命令失败」）。
    #[test]
    fn 超时返回超时而不是命令失败() {
        let started = Instant::now();
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", "ping -n 6 127.0.0.1 >nul"]);
        let r = run_test_cmd(&mut cmd, Duration::from_secs(1));
        let elapsed = started.elapsed();
        assert!(r.is_err(), "sleep 类命令必须超时而不是正常返回");
        assert!(
            elapsed < Duration::from_secs(4),
            "超时必须准时返回，实际耗时 {elapsed:?}"
        );
    }

    /// X1-L01：正常命令必须正常返回，且能拿到 stdout。
    #[test]
    fn 正常命令返回输出() {
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", "echo trim-probe"]);
        let out = run_test_cmd(&mut cmd, Duration::from_secs(10)).expect("正常命令不应超时");
        assert!(out.status.success(), "echo 应成功退出");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("trim-probe"), "stdout 未拿到预期内容: {text:?}");
    }
}
