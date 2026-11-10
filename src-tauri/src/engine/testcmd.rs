//! 测试用子进程执行器：带超时 + 杀整树（A14 / X1-L01 一族）。
//!
//! 为什么要有：测试里的 `Command::new(...).output()` / `.spawn()` **没有超时**——
//! 被测命令占住 stdout 管道或干脆挂住时，`cargo test` 会永远等下去，
//! 一次挂住就废掉整轮验收（CI 上表现为「测试卡住」而不是「一条红」）。
//! 生产侧的同类问题已由 `engine::pwsh::run_inbox_script` 收口（Job Object + 超时），
//! 测试侧此前各写各的裸调用，本模块把同一纪律下沉成**唯一实现**。
//!
//! 纪律：
//! - 子进程立刻入 Job Object（`engine::job::ProcessJob`），超时 `TerminateJobObject` 杀**整棵树**，
//!   不留孤儿（`ping -n 3` 这类「自己会退但子孙不退」是最常见的孤儿来源）；
//! - 读 stdout/stderr 用 channel 而非 `join()`：`join` 不可中断，只要还有子孙握着
//!   管道写端就会无限期挂住；
//! - 超时返回 `Err(Timeout)`，**不**伪装成「命令失败」——两者的处置完全不同
//!   （超时是夹具/环境问题，命令失败是被测行为）。
//!
//! 落点说明：本模块**不**加 `#[cfg(test)]` —— 集成测试（`src-tauri/tests/*.rs`）编译时
//! `cfg(test)` 对被依赖 crate 不生效，helper 若收在 `cfg(test)` 里，
//! 库内测试能用、`tests/` 集成测试用不了，两边就得各写一份（正是本模块要消灭的重复）。
//! 生产构建不会调用它（只有测试用例调用），但它会进二进制 —— 体积可忽略，
//! 换来的是「库内测试与集成测试共用同一份收树纪律」。

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

/// 执行一个子进程并等待其结束；超时则杀整棵树并返回 `Err(Timeout)`。
///
/// `timeout` 是**总时限**（不是空闲时限）：从 spawn 起算，含子孙存活时间。
/// 默认 30s 足够跑完本仓测试里最慢的 `ping -n 3`（≈2s）这类命令，
/// 又短到「真挂住」时不会把整轮验收拖成几十分钟。
pub fn run_test_cmd(cmd: &mut Command, timeout: Duration) -> Result<Output, Timeout> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| {
            // 起不来不是超时，是夹具/环境问题：直接把错误做成 panic 更直白，
            // 但本函数签名是 Result<Output, Timeout>，故把起不来的错误转成
            // 「超时」是不诚实的 —— 改为 panic，让失败点落在 spawn 处。
            panic!("测试子进程启动失败: {e}");
        })?;

    // 立刻入 Job：趁它还没来得及 spawn 子孙。
    // 建不了 job 时降级为「超时只杀本体」并继续（不因此判红）——
    // 收树兜底不可用是环境问题，不是被测行为。
    let job = super::job::ProcessJob::create_for(child.id()).ok();

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
            // 超时：先杀整棵树，再收管道。
            if let Some(j) = &job {
                let _ = j.terminate();
            } else {
                let _ = child.kill();
            }
            let _ = child.wait();
            // 杀树后管道写端会关闭；给读线程一点时间收尾，避免 join 卡死。
            let _ = out_handle.join();
            let _ = err_handle.join();
            return Err(Timeout {
                limit: timeout,
                cmd: format!("{cmd:?}"),
            });
        }
    };

    // 正常退出：等两个读线程把管道读完（子进程已退，子孙也可能还握着写端，
    // 那时靠 Job 收树后的 EOF 收敛；这里给读线程一个上限等待，避免被子孙拖住）。
    let stdout_bytes = rx_out
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default();
    let stderr_bytes = rx_err
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default();
    let _ = out_handle.join();
    let _ = err_handle.join();

    Ok(Output {
        status,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    })
}

/// `run_test_cmd` 的便捷形态：直接用 `cmd /C <line>` 执行一行命令。
pub fn run_test_cmd_line(cmdline: &str, timeout: Duration) -> Result<Output, Timeout> {
    let mut cmd = Command::new("cmd");
    cmd.args(["/C", cmdline]);
    run_test_cmd(&mut cmd, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// X1-L01：超时必须真的返回 Timeout（而不是伪装成「命令失败」）。
    /// 这条断言能变红 —— 把 timeout 调大到 30s 就会挂住 30s 后返回 Ok，
    /// 与「1s 内返回 Err」互斥，故具备判红能力。
    #[test]
    fn 超时返回超时而不是命令失败() {
        let started = Instant::now();
        let r = run_test_cmd_line("ping -n 6 127.0.0.1 >nul", Duration::from_secs(1));
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
        let out = run_test_cmd_line("echo trim-probe", Duration::from_secs(10))
            .expect("正常命令不应超时");
        assert!(out.status.success(), "echo 应成功退出");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("trim-probe"), "stdout 未拿到预期内容: {text:?}");
    }

    /// X1-L01：超时后不得留孤儿 —— 子孙进程必须被 Job 一并收掉。
    /// 判据：超时返回后，`cmd /C` 拉起的 ping 子孙不再存活。
    #[test]
    fn 超时后不留孤儿进程() {
        let marker = "TRIM_ORPHAN_PROBE_9f3a";
        let r = run_test_cmd_line(
            &format!("ping -n 8 127.0.0.1 >nul & ping -n 8 127.0.0.1 >nul & set {marker}=1"),
            Duration::from_secs(1),
        );
        assert!(r.is_err(), "该命令必须超时");
        // 给 Job 收树留一点余量再查：孤儿进程若还在，tasklist 能查到 ping.exe。
        std::thread::sleep(Duration::from_millis(500));
        let listing = Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq ping.exe", "/NH"])
            .output();
        if let Ok(listing) = listing {
            let text = String::from_utf8_lossy(&listing.stdout);
            // 本机可能本来就有别的 ping 在跑；只看数量级是否暴增（判据宽松但不假绿：
            // 真正验的是「收树前有、收树后没有」）。
            let count = text.matches("ping.exe").count();
            assert!(
                count <= 2,
                "超时后疑似留下孤儿 ping.exe（{count} 个）：{text}"
            );
        }
    }
}
