//! updater 域：自动更新（多线路容灾 + 镜像偏好 + 断代后的 minisign 信任模型）
//!
//! 对照源仓库 `Trim/src/main/updater.js`（388 行）。通道契约、状态机 phase、
//! `updater:state-changed` 负载字段名一律保持与渲染层 `src/scripts/updater-ui.js` 一致。
//!
//! # 断代说明（方案 S7 / Q2，2026-09-24 用户拍板走 tauri-plugin-updater + minisign）
//!
//! 上游是 electron-updater 拉 `latest.yml` + 旁路 `latest.yml.sig`（ed25519 验签 yml 原文，
//! 再从已验签原文抽 version/sha512 作可信锚点）。本实现是 tauri-plugin-updater 拉
//! `latest.json`，其 `signature` 字段是 **minisign** 对安装包的签名，内置公钥在
//! `tauri.conf.json` → `plugins.updater.pubkey`。
//!
//! **信任模型同构**：完整性锚点绝不以「下载通道自己说的话」为准，必须由应用内置公钥背书
//! —— 通道被接管时可同时伪造清单与其所指产物，故清单里的值只能当待验对象。
//! 差别只在：验签对象从「yml 原文」变成「安装包字节」，且由插件在 `download()` 返回前
//! 强制执行（`tauri-plugin-updater` 的 `updater.rs:746 verify_signature`，非本文件），不给调用方漏掉这一步的机会。
//!
//! # 验签时点从 check 移到 download（断代带来的真实差异，勿当等价照抄）
//!
//! 上游在**检查阶段**就 ed25519 验签 latest.yml 原文，拿到可信锚点才认「有新版」；
//! 插件的 `check()` 只是走 TLS 拉 JSON，**不验清单**，验签发生在 `download()` 里。
//! 于是「签名问题」在检查阶段基本不会浮现，而是在点下载时才失败 —— 本文件的
//! `is_signature_failure` 因此**两个阶段都要过一遍**，否则用户会把「已阻止」当成网络抖动反复重试。
//!
//! 更关键的是必须打开 `tauri.conf.json` → `plugins.updater.requireSignedVersion = true`：
//! 清单本身不可信，若不要求「签名里的版本 == 清单宣布的版本」，能伪造响应者即可把一个
//! 虚高的 `version` 与某个旧版的**合法**签名配对，把用户降到一个真实但过期的构建上。
//! 开了它，保证强度才与上游「清单原文被内置公钥背书」等价。
//!
//! # 闭环状态（2026-09-25 v0.1.2）
//!
//! 1. minisign 密钥对已生成，公钥已回填 	auri.conf.json > plugins.updater.pubkey；
//!    私钥在本机 ~/.tauri-signer/trim-updater.key（密码见发版记录），CI 发版时须以
//!    TAURI_SIGNING_PRIVATE_KEY + TAURI_SIGNING_PRIVATE_KEY_PASSWORD 两个 secret 注入。
//! 2. FEEDS 三条已改指 xiaoxu1642/trim-tauri/releases/latest/download/（本仓库），
//!    与 Electron 版 xiaoxu1642/Trim 完全分仓，不会混装。
//! 3. v0.1.2 是首发手动安装包（无 latest.json，updater 从下一版 v0.1.3 起生效）；
//!    老 Electron 用户迁移引导仍待 Phase 4 实现。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, Runtime, WebviewWindow};
use tauri_plugin_updater::{Update, UpdaterExt};
use url::Url;

use crate::engine::{guard, log, paths};
use crate::security;

/// 镜像偏好文件（与上游 `MIRROR_FILE` 同名，同一数据目录两侧可共用）
const MIRROR_FILE: &str = "update-mirror.json";
/// 单线路检查超时（对照上游 CHECK_TIMEOUT_MS）
const CHECK_TIMEOUT_MS: u64 = 20_000;
/// 清单文件名（上游拼 latest.yml，插件约定 latest.json）
const MANIFEST: &str = "latest.json";

/// 线路基址（对照上游 MIRRORS / GITHUB_DOWNLOAD_BASE，**尾斜杠 = 目录前缀**）。
/// 实际端点 = 基址 + `latest.json`。
const FEEDS: &[(&str, &str, &str)] = &[
    (
        "github",
        "GitHub 直连",
        "https://github.com/xiaoxu1642/trim-tauri/releases/latest/download/",
    ),
    (
        "gh-proxy",
        "gh-proxy 镜像",
        "https://gh-proxy.com/https://github.com/xiaoxu1642/trim-tauri/releases/latest/download/",
    ),
    (
        "ghfast",
        "ghfast 镜像",
        "https://ghfast.top/https://github.com/xiaoxu1642/trim-tauri/releases/latest/download/",
    ),
];

/// auto = GitHub 优先、失败自动回退镜像；指定镜像 = 该镜像优先、其余兜底（含 GitHub）。
/// 'github' 既是偏好项也是 FEEDS 里的一条真实线路。
const MIRROR_IDS: &[&str] = &["auto", "github", "gh-proxy", "ghfast"];

// ==================== 进程内状态（上游 autoUpdater 同样是进程单例） ====================

static CHECKING: AtomicBool = AtomicBool::new(false);
/// 检查通过、等用户点下载的更新，连它**来自哪条线路**一起锁定（下载前要复验同一线路）
static PENDING: Mutex<Option<Pending>> = Mutex::new(None);
/// 已下载并验签通过、等用户点重启安装的包
static DOWNLOADED: Mutex<Option<Downloaded>> = Mutex::new(None);
/// 正在跑的下载任务（取消走 abort，对齐上游 CancellationToken）
static DOWNLOAD_TASK: Mutex<Option<tauri::async_runtime::JoinHandle<()>>> = Mutex::new(None);

/// 检查阶段锁定的可信锚点。`signature` 是 minisign 签名字符串 —— 复验时比对它，
/// 等价于上游比对 sha512：清单里的签名变了就意味着指向的产物变了。
#[derive(Clone)]
struct Pending {
    update: Update,
    mirror: String,
}

struct Downloaded {
    update: Update,
    bytes: Vec<u8>,
}

/// 锁中毒（持有者 panic）不该让更新链路整个失效，取回内层值继续用
fn lock<T>(slot: &Mutex<T>) -> MutexGuard<'_, T> {
    slot.lock().unwrap_or_else(|e| e.into_inner())
}

/// CHECKING 的 RAII 复位：safe_check 有多个提前 return 分支，手工 store 必漏一条
struct CheckingGuard;

impl Drop for CheckingGuard {
    fn drop(&mut self) {
        CHECKING.store(false, Ordering::SeqCst);
    }
}

// ==================== 线路与偏好 ====================

fn mirror_pref() -> String {
    std::fs::read_to_string(paths::join_data(MIRROR_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.get("mirror").and_then(|m| m.as_str()).map(String::from))
        .filter(|id| MIRROR_IDS.contains(&id.as_str()))
        .unwrap_or_else(|| "auto".into())
}

fn save_mirror_pref(id: &str) -> Result<(), String> {
    if !MIRROR_IDS.contains(&id) {
        return Err("unknown-mirror".into());
    }
    security::atomic_write_json(&paths::join_data(MIRROR_FILE), &json!({ "mirror": id }))
}

/// 基址必须是带尾斜杠的目录前缀 —— 少了斜杠会拼出一个 404 端点，
/// 而 404 会被当成「这条线路不通」去退下一条，镜像配错就永远查不出来。
fn endpoint_of(base: &str) -> Option<Url> {
    if !base.ends_with('/') {
        return None;
    }
    Url::parse(&format!("{base}{MANIFEST}")).ok()
}

/// 按偏好排出线路尝试顺序（对照上游 `orderedFeeds()`）：指定镜像时该镜像优先、其余兜底。
/// 未知偏好不返回空表，退回默认顺序 —— 配错偏好不该让「检查更新」整个失效。
fn ordered_feeds(pref: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    let mut all = FEEDS.to_vec();
    if let Some(pos) = all.iter().position(|(id, _, _)| *id == pref) {
        all.rotate_left(pos);
    }
    all
}

fn push<R: Runtime>(app: &AppHandle<R>, state: Value) {
    let _ = app.emit("updater:state-changed", state);
}

/// 开发环境短路（对照上游 `!app.isPackaged`）：dev 构建没有可装的 updater 产物
fn is_dev_build() -> bool {
    cfg!(debug_assertions)
}

// ==================== 核心：按线路逐一检查 ====================

/// 对**单条**线路检查一次。插件的 `check()` 内部已完成清单获取 + minisign 验签，
/// 返回 Err 即该线路不可信或不可达，调用方换下一条（对齐上游逐线路独立验签）。
/// `Ok(None)` = 线路可用且清单已验签，只是版本不高于当前。
async fn check_once<R: Runtime>(app: &AppHandle<R>, base: &str) -> Result<Option<Update>, String> {
    let endpoint = endpoint_of(base).ok_or("线路基址非法（需带尾斜杠的 https 目录前缀）")?;
    let updater = app
        .updater_builder()
        .endpoints(vec![endpoint])
        .map_err(|e| e.to_string())?
        .timeout(std::time::Duration::from_millis(CHECK_TIMEOUT_MS))
        .build()
        .map_err(|e| e.to_string())?;
    updater.check().await.map_err(|e| e.to_string())
}

/// 多线路容灾检查（对照上游 `safeCheck`）。`silent=true` 时失败不打扰用户。
async fn safe_check<R: Runtime>(app: AppHandle<R>, silent: bool) -> Value {
    if is_dev_build() {
        return json!({ "skipped": true, "reason": "dev" });
    }
    if CHECKING.swap(true, Ordering::SeqCst) {
        return json!({ "skipped": true, "reason": "already-checking" });
    }
    let _guard = CheckingGuard;

    push(&app, json!({ "phase": "checking" }));
    let pref = mirror_pref();
    let mut last_error = String::new();
    // 审查 L8：签名判定要**跨线路累积**。只看循环结束后残留的那条错误，会出现
    // 「GitHub 线路验签失败 + 镜像线路网络超时」= 最后一条是网络错 ⇒ 被报成可重试的
    // 网络抖动，与 :255-260 自述的保守方向相反（用户会对着一个永远无解的签名问题反复点）。
    let mut sig_failed_any = false;

    for (id, label, base) in ordered_feeds(&pref) {
        match check_once(&app, base).await {
            Ok(Some(update)) => {
                log::write_log(
                    "info",
                    &format!(
                        "[updater] 发现新版本 {}（当前 {}，经 {label}）",
                        update.version, update.current_version
                    ),
                );
                *lock(&PENDING) = Some(Pending { update: update.clone(), mirror: id.into() });
                push(
                    &app,
                    json!({
                        "phase": "available",
                        "version": update.version,
                        "currentVersion": update.current_version,
                        "releaseNotes": update.body.clone().unwrap_or_default(),
                        "releaseDate": update.date.map(|d| d.to_string()).unwrap_or_default(),
                        "via": id,
                    }),
                );
                return json!({ "ok": true, "via": id });
            }
            Ok(None) => {
                // 可达且清单已验签，只是版本不高于当前 —— 没必要再问镜像
                *lock(&PENDING) = None;
                push(
                    &app,
                    json!({
                        "phase": "latest",
                        "currentVersion": app.package_info().version.to_string(),
                        "via": id,
                    }),
                );
                return json!({ "ok": true, "via": id });
            }
            Err(e) => {
                sig_failed_any = sig_failed_any || is_signature_failure(&e);
                last_error = e;
                log::write_log("warn", &format!("[updater] 线路 {label} 检查失败: {last_error}"));
            }
        }
    }

    let sig_failed = sig_failed_any;
    log::write_log("error", &format!("[updater] 检查失败（全部线路）: {last_error}"));
    if !silent {
        let message = if sig_failed {
            "更新信息签名校验失败或未签名，已阻止。请前往官方 Releases 页面手动下载安装包。"
                .to_string()
        } else {
            last_error.clone()
        };
        push(&app, json!({ "phase": "error", "sigFailed": sig_failed, "message": message }));
    }
    json!({ "ok": false, "error": last_error, "sigFailed": sig_failed })
}

/// 从插件错误串里辨认签名/清单校验类失败。
///
/// 为什么只能做字符串匹配：插件把验签失败与网络失败混在同一层 `Error` 变体里
/// （`Update`/`Network`/`Io`），拿不到结构化判据。取**保守方向**——宁可把问题说成
/// 「已阻止」并给出手动出口，也不能把签名问题说成网络问题让用户反复重试一个永远无解的操作。
fn is_signature_failure(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    ["signature", "pubkey", "public key", "minisign", "signed version", "invalid key"]
        .iter()
        .any(|k| e.contains(k))
}

// ==================== IPC 命令 ====================

/// updater:check —— 手动检查（渲染层「检查更新」按钮）
#[tauri::command]
pub async fn updater_check<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    Ok(safe_check(window.app_handle().clone(), false).await)
}

/// updater:download —— 下载已锁定的更新。**下载前先复验**，关掉 TOCTOU 窗口。
#[tauri::command]
pub async fn updater_download<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let app = window.app_handle().clone();

    if lock(&DOWNLOAD_TASK).is_some() {
        return Ok(json!({ "ok": false, "error": "already-downloading" }));
    }
    // fail-closed：没有已验签的锚点绝不下载。用户可能隔几分钟才点下载，期间发布侧内容
    // 可能已变化 —— 所以不能直接用检查阶段的结果，要重取一次并逐字比对。
    let Some(pending) = lock(&PENDING).clone() else {
        log::write_log("warn", "[updater] 未取得已验签锚点，已拒绝下载（fail-closed）");
        push(
            &app,
            json!({ "phase": "error", "sigFailed": true,
                    "message": "未取得发布签名，已阻止下载。请重新检查更新。" }),
        );
        return Ok(json!({ "ok": false, "error": "unsigned-or-unverified" }));
    };

    let base = FEEDS
        .iter()
        .find(|(id, _, _)| *id == pending.mirror)
        .map(|(_, _, b)| *b)
        .unwrap_or(FEEDS[0].2);
    let reverified = match check_once(&app, base).await {
        Ok(Some(re)) => {
            re.version == pending.update.version && re.signature == pending.update.signature
        }
        Ok(None) => false,
        Err(e) => {
            log::write_log("warn", &format!("[updater] 下载前复验失败: {e}，已拒绝下载"));
            push(
                &app,
                json!({ "phase": "error", "sigFailed": true,
                        "message": "发布签名在本次会话内发生变化或复验失败，已阻止下载。请重新检查更新。" }),
            );
            return Ok(json!({ "ok": false, "error": "anchor-changed" }));
        }
    };
    if !reverified {
        log::write_log("warn", "[updater] 下载前复验与锚点不一致，已拒绝下载");
        push(
            &app,
            json!({ "phase": "error", "sigFailed": true,
                    "message": "发布签名在本次会话内发生变化，已阻止下载。请重新检查更新。" }),
        );
        return Ok(json!({ "ok": false, "error": "anchor-changed" }));
    }

    let update = pending.update.clone();
    let version = update.version.clone();
    let task = tauri::async_runtime::spawn(async move {
        // 插件回的是**增量**字节数，累计值、百分比与速度由我们自己算
        let mut transferred: u64 = 0;
        let started = std::time::Instant::now();
        let app2 = app.clone();
        let outcome = update
            .download(
                |chunk, total| {
                    transferred += chunk as u64;
                    let percent = total
                        .filter(|t| *t > 0)
                        .map(|t| ((transferred as f64 / t as f64) * 100.0).round() as u32)
                        .unwrap_or(0);
                    let secs = started.elapsed().as_secs_f64().max(0.001);
                    let _ = app2.emit(
                        "updater:state-changed",
                        json!({
                            "phase": "downloading",
                            "percent": percent,
                            "speed": (transferred as f64 / secs) as u64,
                            "transferred": transferred,
                            "total": total.unwrap_or(0),
                        }),
                    );
                },
                || {},
            )
            .await;
        match outcome {
            Ok(bytes) => {
                // 走到这里说明插件**已经**用内置公钥验过 minisign 签名
                // （verify_signature 在 download 返回前），故 ready 意味着包体可信，
                // 不只是「下载完成」
                log::write_log("info", &format!("[updater] {version} 已下载并验签，等待用户确认安装"));
                *lock(&DOWNLOADED) = Some(Downloaded { update, bytes });
                *lock(&PENDING) = None;
                push(&app, json!({ "phase": "ready", "version": version }));
            }
            Err(e) => {
                // 用户主动取消由 updater:cancel-download 直接 abort 任务并推 idle，
                // 不会走到这里；所以此分支只剩真实失败。
                // 验签就在 download 返回前发生（见文件头），故**下载阶段才是签名问题
                // 真正会浮现的地方** —— 这里不过一遍分类，用户看到的会是
                // 「更新失败，点击按钮重试」，而重试永远不会有结果。
                let msg = e.to_string();
                let sig_failed = is_signature_failure(&msg);
                log::write_log(
                    "error",
                    &format!("[updater] 下载{}: {msg}", if sig_failed { "被阻止" } else { "失败" }),
                );
                push(
                    &app,
                    json!({ "phase": "error", "sigFailed": sig_failed, "message": msg }),
                );
            }
        }
        *lock(&DOWNLOAD_TASK) = None;
    });
    *lock(&DOWNLOAD_TASK) = Some(task);
    Ok(json!({ "ok": true }))
}

/// updater:cancel-download —— 中止下载并归位 idle
#[tauri::command]
pub fn updater_cancel_download<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if let Some(task) = lock(&DOWNLOAD_TASK).take() {
        task.abort();
    }
    *lock(&DOWNLOADED) = None;
    push(window.app_handle(), json!({ "phase": "idle" }));
    Ok(json!({ "ok": true }))
}

/// updater:install —— 用户确认后落盘并执行替换，装完自动重启
#[tauri::command]
pub fn updater_install<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let Some(d) = lock(&DOWNLOADED).take() else {
        return Ok(json!({ "ok": false, "error": "nothing-downloaded" }));
    };
    log::write_log("info", "[updater] 用户确认安装，退出并执行替换");
    // 安装参数取自 conf 的 plugins.updater.windows.installMode = "quiet"（NSIS `/S /R`），
    // 等价上游 quitAndInstall(isSilent=true, isForceRunAfter=true)
    match d.update.install(&d.bytes) {
        Ok(()) => Ok(json!({ "ok": true })),
        Err(e) => {
            log::write_log("error", &format!("[updater] 安装失败: {e}"));
            Ok(json!({ "ok": false, "error": e.to_string() }))
        }
    }
}

/// updater:set-mirror —— 切换更新线路偏好
#[tauri::command]
pub fn updater_set_mirror<R: Runtime>(
    window: WebviewWindow<R>,
    mirror: Option<String>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let id = mirror.filter(|m| !m.trim().is_empty()).unwrap_or_else(|| "auto".into());
    match save_mirror_pref(&id) {
        Ok(()) => {
            log::write_log("info", &format!("[updater] 更新镜像偏好已保存: {id}"));
            Ok(json!({ "ok": true, "mirror": id }))
        }
        Err(e) => Ok(json!({ "ok": false, "reason": e, "mirror": mirror_pref() })),
    }
}

/// updater:get-mirror —— 当前偏好 + 下拉选项（选项由线路表推导，避免两处清单漂移）
#[tauri::command]
pub fn updater_get_mirror<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let mut options = vec![json!({ "id": "auto", "label": "自动（推荐）" })];
    options.extend(FEEDS.iter().map(|(id, label, _)| json!({ "id": id, "label": label })));
    Ok(json!({ "mirror": mirror_pref(), "options": options }))
}

/// 启动 8s 后静默检查一次（对照上游 initUpdater 的 setTimeout）。
/// 为什么延后：避开窗口动画与概览预热的资源抢占期。
pub fn schedule_silent_check<R: Runtime>(app: &AppHandle<R>) {
    if is_dev_build() {
        log::write_log("info", "[updater] 开发环境，跳过自动更新");
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(8));
        tauri::async_runtime::spawn(async move {
            let _ = safe_check(app, true).await;
        });
    });
}

// ==================== 纯函数单测 ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(pref: &str) -> Vec<&'static str> {
        ordered_feeds(pref).iter().map(|f| f.0).collect()
    }

    #[test]
    fn auto_偏好下_github_优先() {
        assert_eq!(ids("auto"), vec!["github", "gh-proxy", "ghfast"]);
    }

    #[test]
    fn 指定镜像优先但_github_仍在兜底序列() {
        let v = ids("ghfast");
        assert_eq!(v[0], "ghfast");
        assert_eq!(v.len(), 3, "不能丢线路");
        assert!(v.contains(&"github"), "镜像被污染/下线时必须有直连可退");
        // 'github' 作为显式偏好，结果等价于 auto
        assert_eq!(ids("github"), ids("auto"));
    }

    #[test]
    fn 未知偏好退回默认顺序而非空表() {
        assert_eq!(ids("evil-mirror"), vec!["github", "gh-proxy", "ghfast"]);
    }

    #[test]
    fn 端点由基址拼出_latest_json() {
        let u = endpoint_of("https://github.com/o/r/releases/latest/download/").unwrap();
        assert_eq!(u.as_str(), "https://github.com/o/r/releases/latest/download/latest.json");
        // 漏尾斜杠必须直接判非法，而不是拼出一个 404 端点被误当「线路不通」
        assert!(endpoint_of("https://github.com/o/r/releases/latest/download").is_none());
        assert!(endpoint_of("不是个 url").is_none());
    }

    #[test]
    fn 线路表与偏好白名单一致() {
        for (id, _, base) in FEEDS {
            assert!(MIRROR_IDS.contains(id), "{id} 未登记进偏好白名单");
            assert!(base.ends_with('/'), "{id} 基址必须带尾斜杠");
            assert!(base.starts_with("https://"), "{id} 必须走 https");
        }
        // 白名单 = auto + 全部真实线路（'github' 本身就是线路，不额外占位）
        assert_eq!(MIRROR_IDS.len(), FEEDS.len() + 1);
    }

    #[test]
    fn 签名类错误必须与网络错误区分开() {
        assert!(is_signature_failure("Invalid signature"));
        assert!(is_signature_failure("failed to verify minisign signature"));
        assert!(is_signature_failure("require signed version but none found"));
        assert!(is_signature_failure("public key mismatch"));
        assert!(is_signature_failure("Invalid pubkey"));
        // 纯网络失败不能被说成「已阻止」，否则用户以为遭了攻击
        assert!(!is_signature_failure("request error sending https://x: timed out"));
        assert!(!is_signature_failure("HTTP status code: 404 Not Found"));
    }

    #[test]
    fn 检查标记在提前_return_后必须复位() {
        // safe_check 有 4 个出口（dev/已在检查/命中/全败），CheckingGuard 负责后两条
        // 之外的所有路径；这里断言 Drop 确实会复位
        CHECKING.store(true, Ordering::SeqCst);
        {
            let _g = CheckingGuard;
            assert!(CHECKING.load(Ordering::SeqCst));
        }
        assert!(!CHECKING.load(Ordering::SeqCst), "离开作用域后必须已复位");
    }
}
