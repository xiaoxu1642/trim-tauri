//! elevate 域：UAC 自提权与新旧实例交接握手
//!
//! 对照源仓库 `Trim/main.js` 5645-5716（两个通道）与 33-62（单实例锁 + 旗标）。
//! 应用以普通权限启动（asInvoker），需要管理员权限时经 UAC 重新拉起自身。
//!
//! # 与迁移清单的一处**必要偏离**（清单原文不可实现，非笔误）
//!
//! `剩余任务清单` 写的是「单实例插件回调做 20s 超时握手，只认带旗标的 second-instance」。
//! 实测 `tauri-plugin-single-instance` 2.4.5 的 Windows 实现
//! （`src/platform_impl/windows.rs`）里，第二实例在 `Setup` 阶段发现具名 mutex 已存在时：
//! 发一条 `WM_COPYDATA` 给第一实例 → 然后**无条件** `app.cleanup_before_exit();
//! std::process::exit(0)`。也就是说：提权拉起的**新**实例会把自己在建窗之前杀掉，
//! first-instance 侧的回调根本等不到一个活着的接管者。
//!
//! 因此：**带提权旗标的实例跳过单实例插件**（见 lib.rs 的条件注册），交接改走数据目录下的
//! 握手文件状态机。语义与上游 B5 等价且双向成立：
//!   - 旧实例不确认新实例活着就不退出 → 用户拒了 UAC / 新实例崩溃时不会把应用弄丢；
//!   - 新实例不确认旧实例让位就不建窗 → 避免两个主窗口同时可见的交接缝隙。
//!
//! # 安全口径
//!
//! 提权入口是最高价值 IPC 目标，`elevate:request` 只认主窗口 label。
//! 直用 `ShellExecuteW(verb="runas")`，不再经 PowerShell `Start-Process` 中转
//! （少一个外部进程与一条字符串拼接路径；用户拒绝 UAC 由返回值直接判定，无需 exit code）。

use std::path::PathBuf;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, Runtime, WebviewWindow};

use crate::engine::{guard, log, paths};
use crate::security;

/// 提权重启旗标（对照 main.js `ELEVATED_RELAUNCH_FLAG`）
pub const RELAUNCH_FLAG: &str = "--elevated-relaunch";

/// 握手文件名（落在应用私有数据目录）
const HANDSHAKE_FILE: &str = "elevate-handshake.json";

/// 握手阶段
const PHASE_REQUESTED: &str = "requested";
const PHASE_READY: &str = "ready";
const PHASE_RELEASED: &str = "released";

/// 旧实例等新实例报到的超时（对照 main.js `ELEVATE_HANDSHAKE_TIMEOUT`）
const HANDSHAKE_TIMEOUT_MS: u64 = 20_000;
/// 新实例等旧实例让位的超时（对照 main.js 的 15s 拿锁重试窗口）
const TAKEOVER_TIMEOUT_MS: u64 = 15_000;
/// 轮询间隔（对照 main.js 的 500ms / 250ms）
const OLD_POLL_MS: u64 = 500;
const NEW_POLL_MS: u64 = 250;

fn handshake_path() -> PathBuf {
    paths::app_data_dir().join(HANDSHAKE_FILE)
}

/// 一次性交接标记（nonce）。
///
/// 用途是**防重放**而非防攻击：旧实例在等 `ready`，若磁盘上残留着上一轮提权没清掉的
/// `ready`，就会被误判为「新实例已报到」而退位 —— 结果是两个实例都不在了。nonce 让旧
/// 实例只认本次请求产生的那一条记录。因此它不需要密码学强度；真正要防的本机恶意写者
/// 已经能改我们 ACL 保护的数据目录，猜不猜得到 nonce 无所谓。
///
/// 熵源取 `RandomState` 的哈希种子（std 按进程用 OS 熵随机初始化），再混入纳秒与 pid ——
/// 只为一个 16 位十六进制标记不值得新增 rand/getrandom 依赖。
fn new_nonce() -> String {
    use std::hash::{BuildHasher, Hasher};
    let state = std::collections::hash_map::RandomState::new();
    let ticks = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut a = state.build_hasher();
    a.write_u64(ticks);
    let mut b = state.build_hasher();
    b.write_u64(std::process::id() as u64);
    b.write_u64(a.finish());
    format!("{:016x}", b.finish())
}

fn write_phase(nonce: &str, phase: &str) -> bool {
    let payload = json!({
        "nonce": nonce,
        "phase": phase,
        "pid": std::process::id(),
        "at": crate::engine::now_ms(),
    });
    match security::atomic_write_json(&handshake_path(), &payload) {
        Ok(()) => true,
        Err(e) => {
            log::write_log("error", &format!("写提权握手文件失败: {e}"));
            false
        }
    }
}

/// 读握手文件，返回 `(nonce, phase, 写入方 pid)`；
/// 损坏/缺失一律 None（交接是可损失路径，不隔离、不报错）
fn read_handshake() -> Option<(String, String, u32)> {
    let text = std::fs::read_to_string(handshake_path()).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    Some((
        v.get("nonce")?.as_str()?.to_string(),
        v.get("phase")?.as_str()?.to_string(),
        // pid 缺失按 0 处理，交给 takeover_writer_gone 判（0 不是合法 pid）
        v.get("pid").and_then(|p| p.as_u64()).unwrap_or(0) as u32,
    ))
}

/// 握手记录里那个 pid 是否已给不出「还活着」的证据（审查 L2）。
///
/// 判据刻意设计成「只在拿到反证时才否决」（fail-open）：`OpenProcess` 只有返回
/// `ERROR_INVALID_PARAMETER`（该 pid 不存在）才算确证死亡；其它失败（跨完整性级别、
/// 句柄权限不足）一律当活着。因为误判"已死"的代价是**旧实例拒不让位**，会把这条
/// 无法真机回归的提权交接路径弄坏，比放过一条伪造记录严重得多。
///
/// 买到什么：① 新实例写完 `ready` 就崩溃/秒退时，旧实例不再据此 `app.exit(0)`，
/// 用户不会失去应用；② 只把 `phase` 改成 `ready` 的改文件者，pid 仍是旧实例自己的，
/// 当场被识破。
/// 买不到什么：伪造方填一个当时确实活着的 pid 即可绕过 —— 但那要求它已能写我们 ACL
/// 保护的数据目录，`new_nonce` 的注释（:59-62）已把这种本机写者划在威胁模型之外。
#[cfg(windows)]
fn takeover_writer_gone(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_INVALID_PARAMETER};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    if pid == 0 || pid == std::process::id() {
        // 无 pid 字段，或写记录的就是本进程 —— 都不构成「另一个实例活着」的证据
        return true;
    }
    match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => {
            // 审查 v2-L14：`OpenProcess` 成功**不等于这个进程还在跑**。正在退出的进程、
            // 以及 `ShellExecuteW` 的宿主（explorer）短时握着句柄时都还打得开 —— 新实例写完
            // `ready` 后秒退，旧实例据此让位就会把用户的应用弄没。必须问退出码：
            // 只有 STILL_ACTIVE(259) 才算「这个实例真的活着」；问不出来也按活着处理（不让位）。
            let mut code: u32 = 0;
            let alive = match unsafe { GetExitCodeProcess(h, &mut code) } {
                Ok(()) => code == 259,
                Err(_) => true,
            };
            unsafe {
                let _ = CloseHandle(h);
            }
            !alive
        }
        // 只有「参数无效」是这个 pid 不存在的确定反证；其余失败按活着处理
        Err(_) => {
            let last = unsafe { GetLastError() };
            last == ERROR_INVALID_PARAMETER
        }
    }
}

#[cfg(not(windows))]
fn takeover_writer_gone(_pid: u32) -> bool {
    false
}

/// 握手是否属于本次请求：nonce 必须逐字相等。
/// 为什么这么严：等待期间用户可能又点了一次提权，或上一轮的 released 还没清 ——
/// 认了旧文件就会让旧实例误判「已接管」而退出，结果是两个实例都没了。
fn handshake_matches(file_nonce: &str, phase: &str, want: &str, want_phase: &str) -> bool {
    file_nonce == want && phase == want_phase
}

fn clear_handshake() {
    let p = handshake_path();
    if p.exists() {
        let _ = std::fs::remove_file(&p);
    }
}

/// 审查 M5：是否真的有一次提权交接在进行 —— lib.rs 用它决定是否跳过单实例插件。
///
/// 旧判据是「命令行带 `--elevated-relaunch` 旗标」（`is_relaunch_from_elevation`，已删：
/// 删掉后无人调用，留着就是审查 L19 那类零调用 pub fn），于是本机任何进程手敲这个旗标就能
/// ① 让该会话不注册单实例（双开，且第二实例没有「唤回主窗」语义）、
/// ② 在建窗前白等满交接超时。旗标是纯命令行参数，不构成任何凭据。
/// 现在要求三件事同时成立：带 nonce + 自己是管理员令牌 + 握手文件里的 nonce 与命令行一致
/// 且 phase 仍是 `requested`（旧实例刚发出请求、还没见到新实例报到）。
/// 少任何一条都按普通启动处理：单实例保护照常注册。
pub fn elevation_takeover_pending() -> bool {
    takeover_pending(
        relaunch_nonce().as_deref(),
        crate::engine::sysinfo::is_admin(),
        read_handshake().as_ref().map(|(n, p, _)| (n.as_str(), p.as_str())),
    )
}

/// `elevation_takeover_pending` 的纯判据部分，单独拿出来是为了可测：
/// 三条件全由环境（进程参数 / 令牌 / 数据目录里的文件）决定，测试里造不出来。
fn takeover_pending(
    nonce: Option<&str>,
    admin: bool,
    handshake: Option<(&str, &str)>,
) -> bool {
    let Some(nonce) = nonce else { return false };
    admin && matches!(handshake, Some((n, p)) if n == nonce && p == PHASE_REQUESTED)
}

/// 取旗标里携带的 nonce（`--elevated-relaunch=<nonce>`）
fn relaunch_nonce() -> Option<String> {
    std::env::args().find_map(|a| a.strip_prefix(&format!("{RELAUNCH_FLAG}=")).map(String::from))
}

// ==================== 新实例侧 ====================

/// 提权后的新实例在**建窗之前**调用：报到 + 等旧实例让位。
///
/// 返回值 = 旧实例是否**确认让位**（握手走到了 released）。调用方据此决定要不要
/// 注册单实例插件：确认让位则 mutex 已空闲、正常注册即可恢复单实例保护；
/// 超时未确认则 mutex 可能仍被旧实例持有，此时注册会让插件把自己直接 `exit(0)` 杀掉，
/// 所以宁可不注册（代价是这个会话失去单实例约束，也强于应用起不来）。
pub fn take_over_as_elevated_instance() -> bool {
    let Some(nonce) = relaunch_nonce() else {
        // 手敲旗标启动（无 nonce）：没有旧实例在等，直接放行
        log::write_log("info", "提权旗标未携带 nonce，跳过交接握手直接启动");
        return true;
    };
    if write_phase(&nonce, PHASE_READY) {
        log::write_log("info", "提权重启的新实例已向旧实例报到");
    }
    let started = std::time::Instant::now();
    loop {
        // 这里**不**做 pid 存活判定：`released` 由旧实例写完后立刻 `app.exit(0)`，
        // 写记录的那个进程按设计就是要消失。存活判定只用在旧实例等 `ready` 的一侧。
        if let Some((n, phase, _pid)) = read_handshake() {
            if handshake_matches(&n, &phase, &nonce, PHASE_RELEASED) {
                clear_handshake();
                log::write_log("info", "旧实例已让位，提权实例继续启动");
                return true;
            }
        }
        if started.elapsed().as_millis() as u64 > TAKEOVER_TIMEOUT_MS {
            // 旧实例没让位也要继续跑：宁可短暂双开，也不能让提权后的实例卡死不起
            log::write_log(
                "warn",
                "等待旧实例让位超时，新实例照常启动（可能出现两个窗口，且本会话不启用单实例锁）",
            );
            clear_handshake();
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(NEW_POLL_MS));
    }
}

// ==================== 旧实例侧 ====================

/// 旧实例发出提权请求后挂起的 20s 握手监视：
/// 只认带本次 nonce 的 ready；确认到才退出让位，超时则保持自身存活并通知渲染层。
fn arm_handshake<R: Runtime>(app: AppHandle<R>, nonce: String) {
    std::thread::spawn(move || {
        log::write_log("info", "等待提权后的新实例就绪");
        let started = std::time::Instant::now();
        // 审查 v2-L14：判死为真时不改文件、也不 break，会继续 500ms 轮询到 20s 超时 ——
        // 同一条 warn 最多刷约 40 行，把日志真正想留下的线索埋掉。只报第一次。
        let mut gone_warned = false;
        loop {
            if let Some((n, phase, pid)) = read_handshake() {
                if handshake_matches(&n, &phase, &nonce, PHASE_READY) {
                    if takeover_writer_gone(pid) {
                        if !gone_warned {
                            gone_warned = true;
                            log::write_log(
                                "warn",
                                &format!("收到 ready 但写记录的进程 (pid {pid}) 已不在，不让位、继续等待"),
                            );
                        }
                    } else {
                        log::write_log("info", "检测到提权后的新实例已启动，退出当前实例");
                        // 先落 released 再退出：新实例在等这个标记才肯建窗
                        write_phase(&nonce, PHASE_RELEASED);
                        crate::on_app_exit();
                        app.exit(0);
                        return;
                    }
                }
            }
            if started.elapsed().as_millis() as u64 > HANDSHAKE_TIMEOUT_MS {
                log::write_log("warn", "未检测到提权后的新实例启动，保持当前实例运行");
                clear_handshake();
                let main = app.get_webview_window("main");
                if let Some(w) = main {
                    let _ = w.emit(
                        "elevate:notice",
                        json!({ "message": "未检测到新实例启动，已保持当前运行状态" }),
                    );
                }
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(OLD_POLL_MS));
        }
    });
}

// ==================== IPC 命令 ====================

/// elevate:status — 当前进程是否以管理员身份运行。
/// 用 Rust 令牌 elevation（`IsUserAnAdmin`），等价上游的 `net session` 探测但无外部进程。
#[tauri::command]
pub fn elevate_status<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    Ok(json!({ "isAdmin": crate::engine::sysinfo::is_admin() }))
}

/// elevate:request — 以 runas 直拉自身带提权旗标，随后挂 20s 交接握手
#[tauri::command]
pub fn elevate_request<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    // 审查 1-3 同款：UAC 提权是最高价值 IPC 目标，只认主窗口
    guard::guard(&window, guard::MAIN)?;
    let app = window.app_handle().clone();
    // 不做「已是管理员就直接返回」的短路：上游没有这个分支，且渲染层拿到 success 后
    // 承诺「应用即将以管理员身份重启」——早退会让这句话落空、用户以为卡住。
    // 已提权进程再 runas 一次是即刻完成的，握手照常走完，行为与上游一致。
    log::write_log("info", "请求管理员权限提升 (UAC)");

    let nonce = new_nonce();
    if !write_phase(&nonce, PHASE_REQUESTED) {
        return Ok(json!({ "success": false, "message": "无法写入提权握手状态，已拒绝提权" }));
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            clear_handshake();
            return Ok(json!({ "success": false, "message": e.to_string() }));
        }
    };
    // 参数独立传 PCWSTR，不做 shell 字符串拼接 → 无命令注入面
    let params = format!("{RELAUNCH_FLAG}={nonce}");
    match runas_launch(&exe, &params) {
        Ok(()) => {
            log::write_log("info", "UAC 提权成功，等待新实例就绪后退出当前实例");
            arm_handshake(app, nonce);
            Ok(json!({ "success": true, "relaunching": true }))
        }
        Err(e) => {
            clear_handshake();
            log::write_log("warn", &format!("UAC 提权被用户取消或失败: {e}"));
            Ok(json!({ "success": false, "message": "提权请求被取消或失败" }))
        }
    }
}

/// `ShellExecuteW(verb="runas")`：弹 UAC 并以管理员身份拉起自身。
/// 返回值 <=32 是 SE_ERR_* 错误码，其中 1223 = 用户在 UAC 里点了「否」。
#[cfg(windows)]
fn runas_launch(exe: &std::path::Path, params: &str) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let exe_w = wide(&exe.to_string_lossy());
    let params_w = wide(params);
    let verb_w = wide("runas");
    let workdir_w = wide(&exe.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default());
    let code = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb_w.as_ptr()),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR(params_w.as_ptr()),
            PCWSTR(workdir_w.as_ptr()),
            SW_SHOWNORMAL,
        )
    };
    if code.0 as usize > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecuteW 返回 {}", code.0 as isize))
    }
}

#[cfg(not(windows))]
fn runas_launch(_exe: &std::path::Path, _params: &str) -> Result<(), String> {
    Err("本平台不支持 UAC 提权".into())
}

// ==================== 纯函数单测 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 握手只认逐字相等的_nonce() {
        assert!(handshake_matches("a1b2", "ready", "a1b2", "ready"));
        // nonce 不符：上一轮残留或用户又点了一次提权，都不能认
        assert!(!handshake_matches("other", "ready", "a1b2", "ready"));
        // 阶段不符：requested 阶段是新实例还没报到，不能提前退出
        assert!(!handshake_matches("a1b2", "requested", "a1b2", "ready"));
        assert!(!handshake_matches("a1b2", "released", "a1b2", "ready"));
    }

    /// 审查 L2：ready 记录里的 pid 判据。
    /// 「自己的 pid」与「0（无字段）」都必须判给不出存活证据 —— 前者正是「只把 phase
    /// 改成 ready」的改文件者留下的形态（记录仍是旧实例自己写的）。
    #[test]
    fn 写记录者是自己或无pid时不算接管者() {
        assert!(takeover_writer_gone(0));
        assert!(takeover_writer_gone(std::process::id()));
    }

    /// fail-closed 的那一半：确证不存在的 pid 判死。
    /// Windows 的 pid 必为 4 的倍数且上限不到 0xFFFFFFFF，故 u32::MAX 必然不存在；
    /// 而判据只在 `ERROR_INVALID_PARAMETER` 时否决，其余失败按活着处理（fail-open），
    /// 所以这条同时证明了「权限类失败不会被误当成进程已死」。
    #[cfg(windows)]
    #[test]
    fn 不存在的pid判死而权限不足不否决() {
        assert!(takeover_writer_gone(u32::MAX));
    }

    #[test]
    fn nonce_每次不同且为固定长度十六进制() {        let a = new_nonce();
        let b = new_nonce();
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "同一次进程内两次 nonce 相同则可预测");
    }

    #[test]
    fn 旗标解析覆盖裸旗标与带值两种形式() {
        // relaunch_nonce 走 std::env::args，
        // 这里只能断言前缀常量的契约不被写错
        assert!(RELAUNCH_FLAG.starts_with("--"));
        assert!(format!("{RELAUNCH_FLAG}=abc").starts_with(&format!("{RELAUNCH_FLAG}=")));
        assert!(!RELAUNCH_FLAG.contains(' '));
    }

    /// 审查 M5 回归断言：跳过单实例插件的判据必须是「nonce + 管理员令牌 + 握手文件对得上」
    /// 三者齐全，**光有旗标不算**。旧实现只看旗标，本机任何进程手敲即可双开并白等超时。
    #[test]
    fn 交接判据要求三条件同时成立() {
        // 正例：完整交接在途
        assert!(takeover_pending(Some("n1"), true, Some(("n1", PHASE_REQUESTED))));
        // 光有 nonce（命令行带旗标但没有旧实例写的握手文件）→ 不跳过单实例
        assert!(!takeover_pending(Some("n1"), true, None));
        // 握手文件是别人的 nonce → 不认（防手敲旗标蹭一次双开）
        assert!(!takeover_pending(Some("n1"), true, Some(("n2", PHASE_REQUESTED))));
        // 已经走到 ready/released 的旧文件不得再被当成本次请求
        assert!(!takeover_pending(Some("n1"), true, Some(("n1", PHASE_READY))));
        assert!(!takeover_pending(Some("n1"), true, Some(("n1", PHASE_RELEASED))));
        // 非管理员令牌（旗标是别人塞的）→ 不跳过
        assert!(!takeover_pending(Some("n1"), false, Some(("n1", PHASE_REQUESTED))));
        // 裸旗标（无 nonce）→ 不跳过
        assert!(!takeover_pending(None, true, Some(("n1", PHASE_REQUESTED))));
    }

    #[test]
    fn 超时窗口与上游一致() {
        assert_eq!(HANDSHAKE_TIMEOUT_MS, 20_000);
        assert_eq!(TAKEOVER_TIMEOUT_MS, 15_000);
    }
}
