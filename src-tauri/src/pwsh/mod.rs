//! PowerShell 执行层 —— **只剩收件箱 Windows PowerShell 5.1 一个引擎**
//!
//! R1（2026-10-01）：PowerShell 7 整条退役。原候选链（① env PWSH7_PATH ② %ProgramFiles%\
//! PowerShell\7\pwsh.exe ③ where.exe pwsh.exe ④ %LOCALAPPDATA%\Microsoft\WindowsApps 存根）
//! 与 `run_file` / `run_file_streaming` 一并删除 —— 最后一个 PS7 使用者是右键菜单 CLSID 图标
//! 链，它改走原生 `ExtractIconExW`（实机对拍见 `engine/shellicon.rs`）。自此本应用**不启动
//! pwsh.exe，也不要求用户安装任何组件**；仍会启动 powershell.exe（系统自带 5.1）的入口只有
//! [`run_inbox_script`] 一个，调用点台账由 `tools/check-ps-callsites.mjs` 现算打印。
//! 退役史：B11（2026-09-26）先摘了「内置随包解压运行时」这条死路径，R1 摘掉剩下的探测链。
//!
//! 临时脚本写 `<数据目录>\tmp\` 而非 %TEMP%（全局可写，提权执行时构成 TOCTOU 本地提权
//! 窗口，审查 A1）；`.ps1` 带 UTF-8 BOM（PS 5.1 默认按系统 ANSI 读取无 BOM 脚本，中文注释
//! 会乱码到解析失败）。隔离手段**只有 NTFS ACL 一种**：NTFS 没有 POSIX mode 位，
//! `set_permissions(0o600)` 在 Windows 上只能改只读位、对同用户其他进程零约束，故不做也不声称。
//!
//! 审查 v2-L2 订正措辞：那份 ACL **不是本模块施加的** —— 全仓没有任何 ACL API 调用，
//! 隔离度完全来自 `%APPDATA%` 的默认每用户 DACL（只有当前用户与 SYSTEM 可写）。
//! 本模块只做两件事：拒把脚本写到 reparse 替换过的目录（见 `paths::temp_script_dir`）、
//! 用 `TempScript` 守卫保证「写完就删」不再依赖调用方的 finally 手写 remove_file。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::sync::Arc;
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
/// 等 `READ_GRACE` 让正常输出冲刷完；**只有真超时**才终止子进程树，等不到就交回已读到的快照。
///
/// 审查 v2-M8：判据必须与 `:45-49` 那段注释和 AGENTS §5.13 同口径。原实现在宽限期一到
/// 就无条件 `terminate()`，而调用点（`run_with_exe` 尾部）在**正常退出**路径上同样会走到这里
/// —— 于是 `cleanup_execute.ps1:276` 重启的被清理应用、`cm_restart_explorer.ps1:25` 拉起的
/// explorer、`maint_store.ps1:38` 的 wsreset 只要有一个占着 stdout，宽限期一到整棵树被杀，
/// 正是那段注释声明要避开的结局。
///
/// 为什么拆成「纯决策 `await_reader` + 会写日志的 `take_reader`」两层：前者不碰句柄也不写日志，
/// 「成功路径不得终止子进程树」这条断言才能在没有 pwsh、没有 Win32 句柄、不往真实日志目录
/// 落行的情况下跑（审查纪律：测试不得具备改动系统状态的能力）。
const READ_GRACE: Duration = Duration::from_secs(5);

fn take_reader(
    rx: &std::sync::mpsc::Receiver<String>,
    snapshot: &Snapshot,
    timed_out: bool,
    job: &Option<ProcessJob>,
) -> String {
    match await_reader(rx, snapshot, timed_out, READ_GRACE, &|| {
        if let Some(j) = job {
            j.terminate();
        }
    }) {
        ReadOutcome::Complete(s) => s,
        ReadOutcome::Stalled(partial, why) => {
            log::write_log("warn", why);
            partial
        }
    }
}

/// 宽限期到点且**不终止**子进程树时，只能交回读线程已经写进快照的字节。
/// 返回 lossy 后的串：与 `read_all` 末尾同口径，非 UTF-8 字节替换成 U+FFFD 而不是丢整段。
#[derive(Default)]
struct Snapshot(std::sync::Mutex<Vec<u8>>);

impl Snapshot {
    fn append(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(bytes);
    }

    fn text(&self) -> String {
        let guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&guard).to_string()
    }
}

enum ReadOutcome {
    /// 读线程自己走到了 EOF，交出完整串
    Complete(String),
    /// 等不到 EOF：交出**已读到**的内容 + 该记的那条 warn 文案
    Stalled(String, &'static str),
}

/// 等读线程交结果；不做日志、不做句柄操作（两者由调用方给闭包/自己处理，理由见 `take_reader`）。
fn await_reader(
    rx: &std::sync::mpsc::Receiver<String>,
    snapshot: &Snapshot,
    timed_out: bool,
    grace: Duration,
    terminate_tree: &dyn Fn(),
) -> ReadOutcome {
    if let Ok(s) = rx.recv_timeout(grace) {
        return ReadOutcome::Complete(s);
    }
    if !timed_out {
        // 正常退出（code 可能为 0）却等不到 EOF ⇒ 有子孙**故意**活着并占着写端。
        // 这里 terminate 就是「在批次正常结束时杀掉用户刚打开的程序」，故只做快照兜底。
        return ReadOutcome::Stalled(
            snapshot.text(),
            "子孙进程占住输出管道超过宽限期；本次未超时，按 §5.13 口径不终止子进程树，已交回读到的部分",
        );
    }
    // 真超时：必须收树，否则「超时」形同虚设（实测 5s 配 24.4s 实挂），
    // 且上层会立刻并发跑第二条同类命令。收树后写端全关，读线程随即交出完整串。
    terminate_tree();
    match rx.recv_timeout(grace) {
        Ok(s) => ReadOutcome::Complete(s),
        Err(_) => ReadOutcome::Stalled(
            snapshot.text(),
            "超时并终止子进程树后仍等不到读线程收尾，已交回读到的部分（可能不完整）",
        ),
    }
}


/// 临时脚本守卫（审查 v2-L2）：**持有路径，离开作用域即删**。
///
/// 为什么不再让调用方自己 `remove_file`：每个执行点都是「写数百行脚本 → 跑 → 删」，
/// 中间任何一个 `?` 早退（取值失败、上层拒绝、解析失败）都会把脚本留在 tmp 目录里，
/// 只能等启动/退出时那趟 1h 兜底清理 —— 提权执行链上的可读产物多留一小时是白送的攻击面。
/// （R0 起这个形态收在 `run_inbox_script` 一处，调用点台账由 `tools/check-ps-callsites.mjs` 现算。）
///
/// 刻意实现 `Deref<Target = Path>` 与 `AsRef<Path>`：迁移期既有的 `&path` 传参与
/// `remove_file(&path)` 原样可编译，切换能逐调用点进行而不断构建
/// （残留的手写 remove_file 变冗余但无害，Drop 对已消失的文件静默）。
///
/// 不走回收站：这是本应用自己写进私有 tmp 目录、寿命以毫秒计的执行件，
/// 恢复它没有任何意义。口径同 `security::prune_quarantined`（见那里的豁免说明）。
pub struct TempScript(PathBuf);

impl TempScript {
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl std::ops::Deref for TempScript {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TempScript {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempScript {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// 写临时 PowerShell 脚本：返回**守卫**，脚本随作用域结束自动删除（审查 v2-L2）。
pub fn write_temp_script(content: &str, suffix: &str) -> Result<TempScript, String> {
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
    Ok(TempScript(file))
}

pub(crate) fn random_token() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{nanos:x}{n:x}")
}

/// 审查 v3-K1：用**收件箱 Windows PowerShell 5.1**（System32 自带，无需用户安装）
/// 跑一个**已经写好**的脚本文件。刻意做成模块私有 —— 生产代码不得再持有
/// 「自己拼路径写 .ps1 + 直接执行」这条旁路（R0，2026-10-01），统一走
/// [`run_inbox_script`]，否则 BOM、私有 tmp、脚本清理三件纪律又会各自长出一份。
fn run_inbox_ps(script_path: &Path, timeout: Duration, diag_op: Option<&str>) -> Result<PsOutput, String> {
    let exe = crate::engine::systembin::system_tool("powershell.exe");
    run_with_exe(&exe, script_path, timeout, diag_op, "Windows PowerShell")
}

/// **收件箱 Windows PowerShell 5.1 的唯一执行入口**（R0，2026-10-01）。
///
/// 一次调用即拿到全部纪律：脚本写私有 tmp（`temp_script_dir` 拒 reparse）、UTF-8 BOM、
/// `-NoProfile -NonInteractive -ExecutionPolicy Bypass -File`、超时 + Job Object 收树、
/// 脚本随 `TempScript` 守卫离开作用域删除（含 `?` 早退路径）。
///
/// 为什么收在 pwsh 层而不是各命令自己拼：`commands/uninstall.rs` 的两处 Appx 调用此前用
/// `quiet_cmd(...).output()` **没有任何超时**，子孙占住管道时命令会永久挂住；而
/// `engine/pssteps.rs` 的 PsInline 执行器自己 `fs::write` 出一份**无 BOM** 的脚本
/// （PS 5.1 按 ANSI 读无 BOM 文件，中文注释会乱码到解析失败）。登记台账见
/// `tools/check-ps-callsites.mjs`。
pub fn run_inbox_script(script: &str, timeout: Duration, diag_op: Option<&str>) -> Result<PsOutput, String> {
    // 审查 M-1（2026-10-03 L3）：把 `[Console]::OutputEncoding` 下沉到**咽喉**。
    // 背景：PS 5.1 把重定向到管道的 stdout 按 OEM 码页写（本机 cp936），Rust 侧统一按
    // UTF-8 lossy 解（read_all 的 String::from_utf8_lossy）。路径含中文（中文用户名机器上
    // `%LOCALAPPDATA%\Microsoft\OneDrive` 就是中文路径）时，若脚本自己没设 OutputEncoding，
    // 中文字节会塌成 U+FFFD，下游 `@@RECYCLE@@` 协议把不存在的路径送进回收站逻辑。
    // 此前 appx.rs 在脚本内容里手写前缀（既定做法），但每个调用点各自记得写 —— 漏一处就
    // 复现一次。现在在唯一入口强制注入，一次免疫全部 inbox 调用点。重复注入无害（幂等）。
    let prefixed = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n{script}"
    );
    let path = write_temp_script(&prefixed, ".ps1")?;
    run_inbox_ps(path.path(), timeout, diag_op)
}

fn run_with_exe(
    exe: &Path,
    script_path: &Path,
    timeout: Duration,
    diag_op: Option<&str>,
    label: &str,
) -> Result<PsOutput, String> {
    // v2-L4P-28（B-6）：取值失败必须 Err 早退。原实现回落 `PathBuf::from(".")`——
    // 提权实例的 CWD 可能是 System32，等于把临时脚本写到系统目录（TOCTOU 提权窗口），
    // 与模块头「拒把脚本写到 reparse 替换过的目录」的承诺自相矛盾。
    let trim_tmp = paths::temp_script_dir()
        .map_err(|e| format!("私有临时目录不可用，拒绝执行 {label}: {e}"))?;
    let mut child = Command::new(exe)
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
        .creation_flags(0x0800_0000)
        .spawn()
        .map_err(|e| format!("{label} 启动失败: {e}"))?;

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
    // 只有 channel 能做到「等一段，等不到就按 timed_out 决定是否终止子进程树」。
    let (tx_out, rx_out) = std::sync::mpsc::channel();
    let (tx_err, rx_err) = std::sync::mpsc::channel();
    // 快照（审查 v2-M8）：正常路径靠 EOF 投递的完整串，降级路径靠这里。
    // 少了它，Job 建不起来时（`job = None`，`:381-387` 的显式降级）terminate 无事可做，
    // 宽限期到点只能 `unwrap_or_default()` 交出**空 stdout** —— 上层按「code!=0 + 空 stdout」
    // 判成「脚本根本没跑」，`@@RESULT@@` 型判定（optimizer.rs:701）全线误判。
    // 用 Arc 而非借用：读线程要 `'static`，而快照必须活到调用方取完结果为止。
    let snap_out: Arc<Snapshot> = Arc::new(Snapshot::default());
    let snap_err: Arc<Snapshot> = Arc::new(Snapshot::default());
    let snap_for_out = Arc::clone(&snap_out);
    std::thread::spawn(move || {
        let _ = tx_out.send(read_all(stdout_pipe, Some(&snap_for_out)));
    });
    let snap_for_err = Arc::clone(&snap_err);
    std::thread::spawn(move || {
        let _ = tx_err.send(read_all(stderr_pipe, Some(&snap_for_err)));
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
            Err(e) => {
                // v2-L4P-28（B-6）：try_wait 出错不能裸返回——子进程还活着、job 也无人收，
                // 直接 return 会把孤儿进程（及其管道写端）留给调用方。先收树再报错。
                if let Some(j) = &job {
                    j.terminate();
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("等待 {label} 失败: {e}"));
            }
        }
    }

    // 本体已退出（或被终止），剩下的只是某个子孙还占着管道写端：给一段宽限期冲刷正常输出。
    // **只有真超时**才在这之后收树（v2-M8：判据在 `await_reader` 里，别在这里再加一次）；
    // 正常退出时宁可只交出已读到的部分，也不去杀脚本故意留下的长命进程。
    let stdout = take_reader(&rx_out, &snap_out, timed_out, &job);
    let mut stderr = take_reader(&rx_err, &snap_err, timed_out, &job);
    if timed_out {
        stderr.push_str(&format!("\n{label} 执行超时"));
        code = -1;
    }
    // @@DIAG@@ 诊断行转日志并从 stdout 剔除（与 extractDiagLines 同口径）
    let stdout_clean = match diag_op {
        Some(op) => crate::diag::extract_diag_lines(&stdout, op),
        None => stdout,
    };
    if code != 0 && !stderr.trim().is_empty() {
        log::write_log("warn", &format!("PowerShell 退出码 {code}: {}", stderr.trim()));
    }
    Ok(PsOutput {
        stdout: stdout_clean,
        stderr,
        code,
        timed_out,
    })
}

/// 读尽管道；带 `snapshot` 时**每读一块就同步进去**。
///
/// `snapshot` 是给调用方的「此刻已经读到什么」（审查 v2-M8）：本函数只在 EOF 才通过
/// channel 投递最终串，而 EOF 可能永远等不到（子孙占着写端）。调用方因此需要一条
/// 与「等到 EOF」无关的兜底出路，否则降级路径交出的是空串而不是 99% 的输出。
///
/// R1（2026-10-01）随 PS7 一起删掉的是 `on_line` 逐行回调：它唯一的使用者是
/// `run_file_streaming`，而清理/维护类 `.ps1` 早在 S3 就退役了，收件箱 PS 的 PsInline
/// 算子只看收尾的 `@@RESULT@@`/`@@RECYCLE@@`，没有行级进度可流。
/// stdout 读取上限（审查 L-8，2026-10-03）：正常收件箱输出是 KB~MB 级，失控脚本
/// （如卡在 `Write-Output` 循环）可在最长 1800s 的登记超时窗口里产出 GB 级 stdout
/// 把内存撑爆——此前 `acc` 只受超时约束。到达上限即停读：交出已读部分 + warn 日志；
/// 被截断的 JSON/协议行会走上游既有的畸形行处理（M-1 起有计数告警），不会静默装好。
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

fn read_all(pipe: Option<impl Read>, snapshot: Option<&Snapshot>) -> String {
    read_all_capped(pipe, snapshot, MAX_OUTPUT_BYTES)
}

/// 实际读取体；cap 拆成参数是为了单测能用小上限验证截断行为，生产恒走 `MAX_OUTPUT_BYTES`。
fn read_all_capped(mut pipe: Option<impl Read>, snapshot: Option<&Snapshot>, cap: usize) -> String {
    let mut acc: Vec<u8> = Vec::new();
    let mut truncated = false;
    if let Some(p) = pipe.as_mut() {
        let mut chunk = [0u8; 4096];
        loop {
            match p.read(&mut chunk) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let room = cap.saturating_sub(acc.len());
                    if room == 0 {
                        truncated = true;
                        break;
                    }
                    let take = n.min(room);
                    acc.extend_from_slice(&chunk[..take]);
                    if let Some(s) = snapshot {
                        s.append(&chunk[..take]);
                    }
                    if take < n {
                        truncated = true;
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    }
    if truncated {
        log::write_log(
            "warn",
            &format!("PowerShell stdout 超过 {cap} 字节读取上限，已截断（防失控脚本撑爆内存）"),
        );
    }
    String::from_utf8_lossy(&acc).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 一次性读完一个 Cursor。读取层的核心契约是「交出的字节 == 管道里的字节」：
    /// 不吞、不重排、不按行加工（R1 删掉逐行回调后，这条契约就是它的全部职责）。
    fn drain(input: &str) -> String {
        read_all(Some(std::io::Cursor::new(input.as_bytes())), None)
    }

    #[test]
    fn 读取层不得改变最终stdout字节() {
        let input = "a\r\nb\n@@PROGRESS:50@@\n\rc";
        assert_eq!(drain(input), input, "\r 与末尾无换行残段都必须原样保留");
    }

    #[test]
    fn 空输入得到空串() {
        assert_eq!(drain(""), "");
    }

    #[test]
    fn 中文不被拆坏() {
        let input = "清理完成\n开始扫描\n旧缓存备份\n";
        assert_eq!(drain(input), input);
    }

    #[test]
    fn 协议行不得被吞() {
        let input = "@@PROGRESS:0@@\n@@PROGRESS:37@@\n@@PROGRESS:37@@\n@@DONE@@\n";
        let out = drain(input);
        // 同值重复行照原样交出去，去重是调用方的策略，读取层不做判断
        assert_eq!(out.matches("@@PROGRESS:37@@").count(), 2, "{out}");
        assert!(out.contains("@@DONE@@"), "{out}");
    }

    #[test]
    fn 大输出跨多个读取块仍完整() {
        // 单块 4096 字节，构造 3 倍长度的行序列逼出多次 read 拼接
        let input = "x".repeat(5000) + "\n" + &"y".repeat(8000) + "\n";
        assert_eq!(drain(&input), input);
    }

    // ==================== 审查 L-8：stdout 读取上限 ====================

    #[test]
    fn stdout_超限即截断停读() {
        let input = "a".repeat(10_000);
        let out = read_all_capped(Some(std::io::Cursor::new(input.as_bytes())), None, 1_000);
        assert_eq!(out.len(), 1_000, "交出字节必须恰好等于上限（多读一块都会越限）");
    }

    #[test]
    fn stdout_恰好等于上限不算截断() {
        let input = "b".repeat(1_000);
        let out = read_all_capped(Some(std::io::Cursor::new(input.as_bytes())), None, 1_000);
        assert_eq!(out, input, "等于上限的正常输出必须完整交出");
    }

    // ==================== 审查 v2-M8：宽限期语义与降级不丢 stdout ====================

    /// 只在「等不到 EOF」时被调用的假 terminate；记下调用次数即可断言收树时机。
    #[derive(Default)]
    struct TerminateSpy(std::cell::Cell<usize>);

    impl TerminateSpy {
        fn call(&self) {
            self.0.set(self.0.get() + 1);
        }
        fn count(&self) -> usize {
            self.0.get()
        }
    }

    const TEST_GRACE: Duration = Duration::from_millis(30);

    #[test]
    fn 正常退出时宽限期到点不得终止子进程树() {
        // 场景：pwsh 已 code=0 退出，但脚本用不带 -Wait 的 Start-Process **故意**留下了
        // 长命进程（重启被清理的应用 / 拉 explorer），它占着 stdout 写端 ⇒ EOF 永不到来。
        // 此时收树 = 在批次正常结束时杀掉用户刚打开的程序，正是 AGENTS §5.13 与
        // 本文件 `:45-49` 声明要避开的事 —— 旧实现却无条件 terminate。
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        drop(tx); // 没有任何投递，等价「读线程卡在管道上」
        let snap = Snapshot::default();
        snap.append("脚本已经输出到 99%".as_bytes());
        let spy = TerminateSpy::default();
        let out = await_reader(&rx, &snap, false, TEST_GRACE, &|| spy.call());
        assert_eq!(spy.count(), 0, "非超时路径调用了一次 terminate —— 会误杀脚本留下的进程");
        match out {
            ReadOutcome::Stalled(text, _) => assert_eq!(text, "脚本已经输出到 99%"),
            ReadOutcome::Complete(s) => panic!("读线程没走到 EOF，不该报 Complete: {s}"),
        }
    }

    #[test]
    fn 真超时必须终止子进程树并再收一次() {
        // 收树之后写端全关，读线程才能走到 EOF 并投递完整串 —— 用 channel 复现这个因果。
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let snap = Snapshot::default();
        snap.append("半截".as_bytes());
        let spy = TerminateSpy::default();
        let tx2 = tx.clone();
        let out = await_reader(
            &rx,
            &snap,
            true,
            TEST_GRACE,
            &|| {
                spy.call();
                let _ = tx2.send("完整输出".to_string());
            },
        );
        assert_eq!(spy.count(), 1, "超时这一条路径必须收树，否则「超时」形同虚设");
        match out {
            ReadOutcome::Complete(s) => assert_eq!(s, "完整输出", "优先要完整串，不是快照"),
            ReadOutcome::Stalled(_, _) => panic!("收树后应拿到 EOF 的完整串"),
        }
    }

    #[test]
    fn 降级路径不得交出空串() {
        // Job 建不起来时 terminate() 无事可做（`job = None` 的显式降级），
        // 旧实现此时 `unwrap_or_default()` ⇒ stdout 全丢，上层按「脚本没跑」误判。
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        drop(tx);
        let snap = Snapshot::default();
        snap.append(b"@@RESULT@@:{\"success\":true}");
        let spy = TerminateSpy::default();
        let out = await_reader(&rx, &snap, true, TEST_GRACE, &|| spy.call());
        match out {
            ReadOutcome::Stalled(text, why) => {
                assert_eq!(text, "@@RESULT@@:{\"success\":true}", "已读到的内容必须投递出去");
                assert!(why.contains("终止"), "文案要说清做了什么（超时时确实收过树）");
            }
            ReadOutcome::Complete(s) => panic!("不该报 Complete: {s}"),
        }
        assert_eq!(spy.count(), 1);
    }

    #[test]
    fn 读取线程必须边读边把字节同步进快照() {
        // 只测「EOF 之后快照等于最终串」是假绿：那正是旧实现不需要同步也能过的形态。
        // 这里要的是「读线程还没返回、快照里就已经有已读到的字节」——降级兜底的成立前提。
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let snap = Arc::new(Snapshot::default());
        let reader = StalledReader {
            prefix: "前半段\n".as_bytes().to_vec(),
            pos: 0,
            gate: gate_rx,
        };
        let for_thread = Arc::clone(&snap);
        let handle = std::thread::spawn(move || read_all(Some(reader), Some(&for_thread)));
        std::thread::sleep(Duration::from_millis(80));
        assert!(
            !handle.is_finished(),
            "读取线程应当还卡在 read 上（模拟子孙占住管道），否则本断言测不到降级路径"
        );
        assert_eq!(snap.text(), "前半段\n", "已读到的字节必须立刻可见，不能等 EOF");
        drop(gate_tx); // 放行：read 返回 Ok(0) ⇒ EOF
        let final_text = handle.join().expect("读线程不应 panic");
        assert_eq!(final_text, "前半段\n");
        assert_eq!(snap.text(), final_text, "EOF 之后快照与最终串同值");
    }

    /// 交出 `prefix` 后永久卡在 read 上，直到 `gate` 的发送端被 drop（届时返回 EOF）。
    struct StalledReader {
        prefix: Vec<u8>,
        pos: usize,
        gate: std::sync::mpsc::Receiver<()>,
    }

    impl std::io::Read for StalledReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos < self.prefix.len() {
                let n = (self.prefix.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            // Err 即「放行并 EOF」；测试结束前必须 drop 发送端，否则线程泄漏
            match self.gate.recv() {
                Ok(()) => Ok(0),
                Err(_) => Ok(0),
            }
        }
    }

    // ==================== 审查 v2-L2：临时脚本守卫 ====================

    #[test]
    fn 守卫离开作用域即删除脚本() {
        // 早退路径（`?` / return）是旧姿势漏文件的地方，这里直接测 Drop 本身：
        // 不显式 remove_file，只要作用域结束文件就该没了。
        let dir = sandbox_dir("guard");
        let file = dir.join("script_probe.ps1");
        std::fs::write(&file, b"Write-Output 1").unwrap();
        {
            let guard = TempScript(file.clone());
            assert!(guard.path().is_file(), "守卫持有期间脚本必须存在（执行层要读它）");
            assert_eq!(guard.to_string_lossy().as_ref(), file.to_string_lossy().as_ref());
        }
        assert!(!file.exists(), "守卫出作用域后脚本必须已被删除");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn 守卫对已消失的脚本保持静默() {
        // 未迁移的调用点仍会手写 remove_file，届时 Drop 二次删除不得 panic 也不得影响流程
        let dir = sandbox_dir("double-remove");
        let file = dir.join("script_probe.ps1");
        std::fs::write(&file, b"x").unwrap();
        {
            let guard = TempScript(file.clone());
            std::fs::remove_file(&file).unwrap();
            drop(guard);
        }
        assert!(!file.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ==================== 审查 v2-L13：保留期回收覆盖面 ====================

    #[test]
    fn 临时脚本回收必须递归到子目录() {
        let root = sandbox_dir("recursive-tmp");
        std::fs::write(root.join("a.ps1"), b"1").unwrap();
        std::fs::create_dir_all(root.join("sub/deep")).unwrap();
        std::fs::write(root.join("sub/b.ps1"), b"2").unwrap();
        std::fs::write(root.join("sub/deep/c.ps1"), b"3").unwrap();
        let mut files = Vec::new();
        collect_temp_files(&root, 0, &mut files);
        assert_eq!(files.len(), 3, "旧实现只扫一层 ⇒ 子目录里的脚本永久残留");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn 递归深度封顶不无限下探() {
        let root = sandbox_dir("depth-cap");
        let deep = (1..=5).fold(root.clone(), |p, i| p.join(format!("x{i}")));
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("f_deep"), b"x").unwrap();
        std::fs::write(root.join("x1/x2/x3/x4/f_ok"), b"x").unwrap();
        let mut files = Vec::new();
        collect_temp_files(&root, 0, &mut files);
        assert!(files.iter().any(|p| p.ends_with("f_ok")), "封顶内的正常层级要收");
        assert!(
            !files.iter().any(|p| p.ends_with("f_deep")),
            "超出 TMP_SCAN_MAX_DEPTH 的层级不得再下探"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn 龄期判定只删过期件且不误删时间戳异常的() {
        let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let cutoff = Duration::from_secs(3600);
        assert!(expired_since(Some(now - Duration::from_secs(7200)), now, cutoff));
        assert!(!expired_since(Some(now - Duration::from_secs(60)), now, cutoff));
        assert!(
            !expired_since(None, now, cutoff),
            "取不到 mtime 时按不过期处理：误删比留一个文件代价高"
        );
    }

    #[test]
    fn 回收执行体只删沙箱内的过期文件() {
        let root = sandbox_dir("prune-run");
        let old = root.join("old.ps1");
        let fresh = root.join("sub").join("fresh.ps1");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(&old, b"old").unwrap();
        std::fs::write(&fresh, b"fresh").unwrap();
        // 把 old.ps1 的 mtime 推到 2 小时前（沙箱内文件，不碰真实目录）
        let f = std::fs::OpenOptions::new().write(true).open(&old).unwrap();
        f.set_modified(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
        drop(f);
        let removed = prune_temp_scripts_in(&root, std::time::SystemTime::now(), Duration::from_secs(3600));
        assert_eq!(removed, 1, "只该删掉那一个过期件");
        assert!(!old.exists());
        assert!(fresh.exists(), "未过期文件（含子目录里的）不得被删");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 一次性沙箱目录：唯一命名 + 结束自删，测试不具备改动真实数据目录的能力。
    fn sandbox_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trim-pwsh-test-{}-{tag}",
            crate::engine::now_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ==================== 审查 v2-L13：注册表备份修剪 ====================

    #[test]
    fn 备份名白名单只认脚本产出的形状() {
        // ① 旧（cleanup_execute.ps1 时代）：yyyyMMdd_HHmmss_reg_<id>_<n>.reg
        assert!(is_reg_backup_name("20260925_131400_reg_packageCache_1.reg"));
        assert!(is_reg_backup_name("20260925_131400_reg_a_12.reg"));
        // ② 新（原生执行链 v2-L4P-30）：now_ms 13 位 —— 旧实现对此恒 false（假绿根因）
        assert!(is_reg_backup_name("1789999999999_reg_packageCache_1.reg"));
        assert!(is_reg_backup_name("1789999999999_reg_a_12.reg"));
        assert_eq!(
            reg_backup_stamp("1789999999999_reg_a_1.reg").as_deref(),
            Some("1789999999999")
        );
        assert_eq!(
            reg_backup_stamp("20260925_131400_reg_a_1.reg").as_deref(),
            Some("20260925_131400")
        );
        // 时间戳形状不对 / 缺 _reg_ 前缀 / 非 .reg 结尾 / 尾段缺失，一律不当备份
        for junk in [
            "2026-09-25_131400_reg_a_1.reg",
            "20260925_13140_reg_a_1.reg",
            "20260925_131400_key_a_1.reg",
            "20260925_131400_reg_a_1.txt",
            "notes.reg",
            // 12 位 / 14 位纯数字都不在两种合法形态里
            "178999999999_reg_a_1.reg",
            "17899999999999_reg_a_1.reg",
            // 缺序号段
            "1789999999999_reg_a.reg",
            "1789999999999_reg__1.reg",
            // id 里带目录分隔符也必须被白名单挡下（名称取自数据，不可信）
            "20260925_131400_reg_..\\win_1.reg",
        ] {
            assert!(!is_reg_backup_name(junk), "{junk} 不该被当成自产备份");
        }
    }

    #[test]
    fn 备份按批次保留且同批次不拆散() {
        let mk = |s: &str, i: usize| (s.to_string(), PathBuf::from(format!("{s}_{i}.reg")));
        let mut backups = Vec::new();
        // 最新批次 3 份、次新 1 份、最旧 2 份
        for i in 0..3 {
            backups.push(mk("20260103_000000", i));
        }
        backups.push(mk("20260102_000000", 0));
        for i in 0..2 {
            backups.push(mk("20260101_000000", i));
        }
        let removed = reg_backups_to_remove(backups.clone(), 2);
        assert_eq!(removed.len(), 2, "只删最旧那一批（2 份），第 2 批虽只 1 份也要留");
        assert!(removed.iter().all(|p| p.to_string_lossy().starts_with("20260101")));
        // keep=0 与 keep 足够大两个边界：全删 / 全留
        assert_eq!(reg_backups_to_remove(backups.clone(), 0).len(), 6);
        assert!(reg_backups_to_remove(backups, 99).is_empty());
    }

    #[test]
    fn 受保护根口径下逐文件闸门必然全拦() {
        // 钉住 prune_reg_backups 的取舍依据（别把这条读成「闸门可以省」）：
        // %APPDATA%\Trim 整棵是 subtree 受保护根，所以任何位于其下的备份文件
        // 过 is_path_protected 都是 true —— 照点名校法加闸门 = 修剪永不生效。
        // 注意 ProtectRoots 存的是**归一化后（小写、反斜杠）**的串（`build_roots` 里过 `norm()`），
        // 而 `is_path_protected_with` 直接按字面比较，故夹具两侧都得写小写。
        let roots = crate::engine::protect::ProtectRoots {
            subtree: vec!["c:\\users\\me\\appdata\\roaming\\trim".to_string()],
            ..Default::default()
        };
        assert!(crate::engine::protect::is_path_protected_with(
            "C:\\Users\\me\\AppData\\Roaming\\Trim\\cleanup-reg-backup\\20260925_131400_reg_a_1.reg",
            &roots
        ));
        // 反向：换个不属于任何受保护根的路径则为 false —— 说明闸门本身是有效的，
        // 只是用错了地方（它拦的是「外部输入指到哪」，不是「本应用自己的回收策略」）
        assert!(!crate::engine::protect::is_path_protected_with(
            "C:\\Users\\me\\Documents\\a.reg",
            &roots
        ));
    }


    /// 真机验证：上面几条只测了读取器，这条测**整条收件箱 PS 执行路径**（统一入口
    /// `run_inbox_script`）。只回显文本，不碰注册表/文件/进程，故无副作用。
    ///
    /// 顺带钉住一条收件箱 5.1 独有的口径：PS 5.1 把重定向到管道的 stdout 按 **OEM 码页**
    /// 写（本机 cp936），Rust 侧统一按 UTF-8 lossy 解 —— 所以**脚本自己**必须显式设
    /// `[Console]::OutputEncoding`，否则中文输出会乱码。`uninstall.rs` 的 Appx 两条脚本
    /// 首句就是它，这里验证的正是「按约定写就能拿到原样中文」。
    #[test]
    #[ignore = "真实启动收件箱 Windows PowerShell 5.1，发布前门禁跑"]
    fn 真实收件箱ps按序交出每一行协议() {
        let script = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n\
                      Write-Output '@@PROGRESS:0@@'\n\
                      Write-Output '正在扫描组件存储'\n\
                      Write-Output '@@PROGRESS:50@@'\n\
                      Write-Output '@@PROGRESS:50@@'\n\
                      Write-Output '@@DONE@@'";
        let out = run_inbox_script(script, Duration::from_secs(60), None)
            .expect("收件箱 PowerShell 执行失败");
        assert_eq!(out.code, 0, "stderr: {}", out.stderr);
        assert!(!out.timed_out);
        let lines: Vec<&str> = out
            .stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(
            lines,
            vec!["@@PROGRESS:0@@", "正在扫描组件存储", "@@PROGRESS:50@@", "@@PROGRESS:50@@", "@@DONE@@"],
            "顺序、同值重复行、中文行都必须原样交出（去重是调用方的策略，读取层不做判断）",
        );
    }

    /// 审查 M6 回归断言：**子孙进程握着 stdout 写端时，函数必须自己收回来**。
    ///
    /// 脚本用 `Start-Process -NoNewWindow`（不带 -Wait）拉起一个 20 秒的 ping：它继承 PowerShell 的
    /// 标准输出，本体立刻 `exit 0`，但读线程要等这个子孙关掉写端才能返回。
    /// 旧实现是 `join()`（不可中断）→ 实测本体早已 code=0 退出，函数仍挂 19.7s。
    ///
    /// 审查 v2-M8 改了这条的**手段**（也改了上面 `:45-49` 的口径）：本体正常退出时不再收树，
    /// 宽限期到点直接交出快照。所以这里断言的是「按时返回 + 输出不丢 + 不误判超时」，
    /// **不再**断言 ping 被杀掉。
    /// 注：`-NoNewWindow` 在 `.ps1` 里是 AGENTS §5.13 明令避免的写法（子孙会在宽限期后被
    /// 判为失控），本用例只是刻意复现那个形态来量墙上时间。
    /// R1（2026-10-01）：随 PS7 退役改挂到统一入口 `run_inbox_script` 上 —— 要测的进程树纪律
    /// 与引擎无关，两条路径共用同一个 `run_with_exe`。
    ///
    /// 阈值为什么是 25s 而不是贴着「宽限期 + 一点点」：这条断言要抓的是**等子孙自己跑完**
    /// （旧实现实测 19.7s），而收件箱 PowerShell 的冷启动本身在 2~9s 之间飘——发布前门禁是
    /// 整套 `--ignored` 并发跑的，本机量到过单条 13~16s。拿 12s 这种「贴着噪声」的墙上时间
    /// 当阈值，结果是同一段代码单独跑绿、批量跑红，红两次就有人开始「重跑到绿为止」。
    /// 所以把**危害窗口放大**：子孙 ping 拉长到 40s，退化成旧行为会 >40s 才返回，
    /// 与正确行为（≤16s 量级）之间拉开 24s 的分离度，阈值取中间的 25s。
    #[test]
    #[ignore = "真实启动收件箱 PowerShell 与子孙进程，发布前门禁跑"]
    fn 子孙进程占住管道时函数必须自己收回来() {
        let script = "$g = Start-Process -FilePath 'ping' -ArgumentList '-n','40','127.0.0.1' -NoNewWindow -PassThru\n\
                      Write-Output '@@DONE@@'";
        let started = Instant::now();
        let out = run_inbox_script(script, Duration::from_secs(60), None);
        let elapsed = started.elapsed();

        let out = out.expect("收件箱 PowerShell 执行链本身不应报错");
        assert_eq!(out.code, 0, "本体是正常退出的，不该被记成失败: {}", out.stderr);
        assert!(!out.timed_out, "本体没超时，不应判 timed_out");
        assert!(
            elapsed < Duration::from_secs(25),
            "应在宽限期后交回快照并返回（旧实现会等 ping 自己跑完 ≈40s），实耗 {elapsed:?}"
        );
        assert!(out.stdout.contains("@@DONE@@"), "正常输出不得被截断: {}", out.stdout);
    }

    /// 审查 M6 的另一半：**本体还在等子孙**（`& dism ... | Out-String` 那种）时，
    /// 超时点必须真的把整棵树收回来并按时返回 —— 否则用户看到「超时失败，可重试」，
    /// 实际第二个 DISM 正与不可回滚的 /ResetBase 并发跑。
    #[test]
    #[ignore = "真实启动收件箱 PowerShell 与子孙进程，发布前门禁跑"]
    fn 超时必须按时收回整棵子进程树() {
        let script = "& ping -n 20 127.0.0.1 | Out-String\nWrite-Output '@@DONE@@'";
        let started = Instant::now();
        let out = run_inbox_script(script, Duration::from_secs(4), None);
        let elapsed = started.elapsed();

        let out = out.expect("收件箱 PowerShell 执行链本身不应报错");
        assert!(out.timed_out, "4s 超时应判定时，实际 code={}", out.code);
        assert!(
            elapsed < Duration::from_secs(9),
            "超时点之后应立刻收树返回（旧实现会被 ping 拖到 ≈20s），实耗 {elapsed:?}"
        );
        assert_eq!(out.code, -1, "超时统一按 -1 回执");
    }
}

/// 清理执行层留下的文件（审查 v2-L13 把这里当**唯一已接线的保留期入口**）：
/// - `<数据目录>\tmp\` 下超过 1 小时的临时脚本（含历史版本遗留在全局可写 `%TEMP%\Trim` 的残留）；
/// - `cleanup-reg-backup\` 下超额的注册表备份 —— 由 `cleanup_execute.ps1:706` 产出
///   （**`.ps1` 禁手改**，故修剪只能在 Rust 侧做），文件名带时间戳、全仓零读者，此前无上限增长。
///
/// lstat 不跟随符号链接：非常规文件（链接/设备）直接跳过（审查 1-6）。
/// 递归原因见 `collect_temp_files`。
///
/// 为什么这两件事都挂在本模块：`cleanup_temp_scripts` 已在 lib.rs 的启动与退出两处接线，
/// 而 `.reg` 备份同样是「跑一次 `.ps1` 留下的件」；给 `prune_reg_backups` 另开一条
/// 启动钩子要改 lib.rs（越界），故并到同一个入口，按批次史实登记在交付说明里。
/// 修剪入口的互斥（v3 B3 第 5 条）：显示后的 housekeeping 线程与退出钩子 `on_app_exit`
/// 调的是同一个入口，两条路径同时在同一批文件上 lstat+remove，后到的那个会拿到一堆
/// 「文件不存在」的假错误。压成「后到者等前一个跑完」即可；持锁方 panic 时取回内层值继续，
/// 退出路径不能因为一次毒化就再也不清临时脚本。
static TEMP_SWEEP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn cleanup_temp_scripts() {
    let _guard = TEMP_SWEEP_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut dirs = Vec::new();
    if let Ok(d) = paths::temp_script_dir() {
        dirs.push(d);
    }
    dirs.push(std::env::temp_dir().join("Trim"));
    for dir in dirs {
        prune_temp_scripts_in(&dir, std::time::SystemTime::now(), TMP_SCRIPT_TTL);
    }
    prune_reg_backups(REG_BACKUP_KEEP_BATCHES);
}

const TMP_SCRIPT_TTL: Duration = Duration::from_secs(3600);
/// 递归深度上限：tmp 目录本不该有层级，能到这里的就是别人摆的（含 reparse 链），
/// 与其无限下探不如就此打住。
const TMP_SCAN_MAX_DEPTH: usize = 4;

/// 收集目录内**可回收的普通文件**（递归、拒 reparse、限深度），与「按龄期删」解耦，
/// 使递归覆盖面能写成纯断言（审查 v2-L13）。
fn collect_temp_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > TMP_SCAN_MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // symlink_metadata：绝不跟随链接；reparse（符号链接/联接点/云占位符）一律跳过，
        // 删它等于删链接指向的东西，那是 AGENTS §3 要求先过 is_path_protected 的行为。
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if crate::engine::protect::is_reparse(&meta) {
            continue;
        }
        if meta.is_dir() {
            collect_temp_files(&path, depth + 1, out);
        } else if meta.is_file() {
            out.push(path);
        }
    }
}

/// 单个目录的回收执行体（不写日志，便于在一次性沙箱里断言，审查纪律：测试不改系统状态）
fn prune_temp_scripts_in(dir: &Path, now: std::time::SystemTime, cutoff: Duration) -> usize {
    let mut files = Vec::new();
    collect_temp_files(dir, 0, &mut files);
    let mut removed = 0;
    for path in files {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if expired_since(meta.modified().ok(), now, cutoff) {
            if std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// 龄期判定：mtime 取不到（非常规文件系统/时间戳异常）按「不过期」处理 ——
/// 误删比留着一个文件代价高。
fn expired_since(mtime: Option<std::time::SystemTime>, now: std::time::SystemTime, cutoff: Duration) -> bool {
    match mtime {
        Some(m) => now.duration_since(m).map(|age| age > cutoff).unwrap_or(false),
        None => false,
    }
}

// ==================== 审查 v2-L13：cleanup_execute.ps1 自产的注册表备份修剪 ====================

/// 保留最近多少个**批次**（同一个 `yyyyMMdd_HHmmss` 时间戳算一次清理运行）。
/// 为什么按批次而不是按份数（`peripheral.rs:222 prune_backups` 是按份数）：
/// 一次运行会为一条规则的每个 reg 键各导出一份 `_<n>.reg`，半份批次既不可回溯也不可导入。
const REG_BACKUP_KEEP_BATCHES: usize = 10;

/// 修剪 `cleanup-reg-backup`：超额批次的文件逐个进回收站。
/// **裁根 = 写侧单根**（v2-L4P-14，B-2/C-3 用户拍板 D-1）：老根（`%APPDATA%\Trim`，
/// `.ps1` 里写死的正是它）是用户升级前的唯一还原依据，AGENTS §9.2① 冻结「老根只读不裁」
/// ——把 `backup_read_dirs` 的读兜底清单当裁根清单用，等于替用户丢掉最后的退路。
/// 老根的超额文件宁可留在盘上（读取兜底仍可见、可还原），也不许被我们清掉。
///
/// **为什么这里没有逐文件过 `is_path_protected`（与整改单的点名校法不同，实测依据）**：
/// `protect.rs:282` 把 `%APPDATA%\Trim` 整棵列为 subtree 受保护根（注释原文
/// 「应用自身数据目录整棵不许碰」），而备份文件必然位于该根之下 ⇒
/// `is_path_protected` 对**每一个**候选恒为 true，加上这道闸门只会让修剪变成
/// 100% 空操作（假绿，见测试 `受保护根口径下逐文件闸门必然全拦`）。
/// 该闸门的真实用途是拦「来自规则 JSON 的任意路径」；本函数的路径不取自任何外部输入，
/// 四要素固定：目录常量 + 严格文件名白名单（`is_reg_backup_name`）+ 拒 reparse 的普通文件
/// + 只进回收站（可恢复、且不删目录本身）。同族的 `peripheral.rs::prune_backups` 也是这个姿势。
fn prune_reg_backups(keep_batches: usize) {
    // 裁根恒为写侧单根（v2-L4P-14）：读兜底（backup_read_dirs）与裁根（backup_write_dir）
    // 从此是两个口径，check-fail-closed 钉住「老根不得出现在裁根名单」。
    let dirs = vec![paths::backup_write_dir(REG_BACKUP_DIR)];
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        // (批次时间戳, 文件路径)：只认白名单命名，别的文件一律不碰
        let mut backups: Vec<(String, PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !is_reg_backup_name(&name) {
                continue;
            }
            // 拒 reparse：链接件删掉等于删它指向的东西
            let ok_regular = std::fs::symlink_metadata(entry.path())
                .map(|m| m.is_file() && !crate::engine::protect::is_reparse(&m))
                .unwrap_or(false);
            if ok_regular {
                // v2-L4P-30：批次键由 reg_backup_stamp 给出（双形态各自定宽、字典序即时序）
                if let Some(stamp) = reg_backup_stamp(&name) {
                    backups.push((stamp, entry.path()));
                }
            }
        }
        for path in reg_backups_to_remove(backups, keep_batches) {
            // 回收站优先（AGENTS §3）：`.reg` 是删注册表前的唯一凭据，永久删等于毁掉还原线索
            if let Err(e) = trim_finder::scan::recycle::send_to_trash_os(path.as_os_str()) {
                log::write_log("warn", &format!("旧注册表备份移入回收站失败: {e}"));
            }
        }
    }
}

const REG_BACKUP_DIR: &str = "cleanup-reg-backup";

/// 登记两种合法自产备份命名并给出批次键（v2-L4P-30 / B-8）。
///
/// ① 旧（cleanup_execute.ps1 时代，盘上存量）：`yyyyMMdd_HHmmss_reg_<id>_<序号>.reg`
/// ② 新（原生执行链，native.rs regKeys 分支）：`<now_ms 13 位>_reg_<id>_<序号>.reg`
/// ——旧实现只认①，②恒 false ⇒ 原生备份既不被修剪也不被当备份（无上限增长 + 假绿测试）。
/// 逐位卡死前缀的理由不变：id 是规则数据里的字符串、长度与字符集都不受本模块控制，
/// 宽松匹配会把用户丢进这个目录的任意文件当成备份删掉。
/// 返回 None = 不是自产备份（一律不碰）；Some = 批次键（字典序即时序，两种形态各自定宽）。
fn reg_backup_stamp(name: &str) -> Option<String> {
    const LEGACY_LEN: usize = 15; // yyyyMMdd_HHmmss
    const MS_LEN: usize = 13; // now_ms
    let stem = name.strip_suffix(".reg")?;
    // 分隔符一律拒：id 取自规则数据，理论上可能被写成 `..\windows`；
    // NTFS 文件名本身容不下这些字符，故这是「不依赖上游侥幸」的第二层
    if stem.contains(['/', '\\', ':']) {
        return None;
    }
    let us = stem.find("_reg_")?;
    let stamp = &stem[..us];
    let b = stamp.as_bytes();
    let legacy = stamp.len() == LEGACY_LEN
        && b[..8].iter().all(|c| c.is_ascii_digit())
        && b[8] == b'_'
        && b[9..15].iter().all(|c| c.is_ascii_digit());
    let ms = stamp.len() == MS_LEN && stamp.bytes().all(|c| c.is_ascii_digit());
    if !legacy && !ms {
        return None;
    }
    // "_reg_" 之后必须恰好是 id 与序号两段且都非空
    let tail = &stem[us + 5..];
    let segs: Vec<&str> = tail.split('_').collect();
    if segs.len() != 2 || segs.iter().any(|s| s.is_empty()) {
        return None;
    }
    Some(stamp.to_string())
}

/// 自产备份白名单（两种命名形态，见 `reg_backup_stamp`）
fn is_reg_backup_name(name: &str) -> bool {
    reg_backup_stamp(name).is_some()
}

/// 纯函数：给定 (批次, 路径) 列表，交出应删除的那些（保留最近 keep 个批次）。
/// 抽出来是为了让「按批次保留、同批次不拆散、字典序即时间序」这三条能脱离真实目录断言。
fn reg_backups_to_remove(backups: Vec<(String, PathBuf)>, keep: usize) -> Vec<PathBuf> {
    let mut backups = backups;
    // 时间戳是零填充数字串 ⇒ 字典序 == 时间序；倒序后同批次必然相邻
    backups.sort_by(|a, b| b.0.cmp(&a.0));
    let mut out = Vec::new();
    let mut last_stamp: Option<&str> = None;
    let mut batch_index = 0usize;
    for (stamp, path) in &backups {
        if last_stamp != Some(stamp.as_str()) {
            last_stamp = Some(stamp.as_str());
            batch_index += 1;
        }
        if batch_index > keep {
            out.push(path.clone());
        }
    }
    out
}
