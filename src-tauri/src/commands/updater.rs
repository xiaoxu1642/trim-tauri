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
//! 1. minisign 密钥对已生成，公钥已回填 `tauri.conf.json` → `plugins.updater.pubkey`。
//!    v2-L4P-25（A-7）：私钥路径与发版/签名流程只以 AGENTS §7.4 为唯一真源，本文件
//!    不再维护第二份（文档互相抄路径是「红线指向虚无」的温床，L4 D-3 同族教训）。
//! 2. FEEDS 两条：`atomgit`（https://api.atomgit.com/api/v5/repos/xiaoxiaoxu1642/trim-tauri/raw/）
//!    与 `github`（https://github.com/xiaoxu1642/trim-tauri/releases/latest/download/），
//!    **顺序固定 AtomGit 国内源优先、失败自动回退 GitHub**（2026-10-06 起不再提供线路
//!    选择 UI 与 per-machine 偏好：默认就该是国内源，用户不需要理解「线路」概念；
//!    已退役的 `updater:set-mirror` / `updater:get-mirror` 见 git 历史）。
//!    2026-10-03 用户拍板由三源（GitHub + 两个加速代理）改二源；
//!    2026-10-05 再由 Gitee 换成 AtomGit（Gitee 附件只能网页手动传，AtomGit 有发布 API）。
//!    **两仓发版必须同步**：AtomGit 侧 release 资产与 GitHub 侧同名同版本，
//!    否则国内源会长期停在旧版（表现为「检查更新说已是最新」而 GitHub 有新版）。
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

/// 安装前留下的「本次要装到哪个版本」标记：替换完成后本进程已退出，
/// 由新版本实例首启读一次并给出完成提示（读后即删）。
const DONE_FILE: &str = "update-applied.json";
/// 单线路检查超时（对照上游 CHECK_TIMEOUT_MS）
const CHECK_TIMEOUT_MS: u64 = 20_000;
// 原先这里有个全局 `MANIFEST = "latest.json"`（上游拼 latest.yml，插件约定 latest.json）。
// 2026-10-03 二源改造后**删掉**：清单名已由 FEEDS 逐线路自带（AtomGit 走 api raw 托管、
// 文件名 latest-atomgit.json），留一个全局常量会让人以为「所有线路共用一个清单名」，
// 于是给 Gitee 线路也拼 latest.json —— 而 GitHub 的 latest.json 里 url 指向 GitHub，
// 拼出来的端点会给出「从 Gitee 查更新、点下载却回 GitHub」的假象。死字段不留。

/// 线路表：(id, 显示名, 基址, 清单文件名)
///
/// 2026-10-03 用户拍板：**三源改二源**。原三源是 `github` + `gh-proxy` + `ghfast`
/// （两个都是 GitHub 加速代理），换成 `gitee`（国内源，直连）+ `github`。
/// 删掉加速代理的另一个理由：它们的可用性不由本项目控制，且**清单与产物都经它们转发**——
/// 信任模型里这条链已经够长（TLS → 清单 → minisign 验签），不该再叠一层第三方代理。
/// 2026-10-05 用户拍板：**Gitee 换成 AtomGit** —— Gitee 的 release 附件只能网页手动两步
/// 上传（每发一版都要人工拖文件），AtomGit 建 release / 传附件 / 下载全是 API，可自动化。
///
/// # 为什么 AtomGit 走 api raw 端点（实测踩出来的，别改回去）
///
/// 清单仍走「仓库文件随 commit 走」的托管形态（端点与 tag 无关，天然稳定），
/// 但取文件的端点换成了 API：`api.atomgit.com/api/v5/repos/{owner}/{repo}/raw/{path}`
/// —— 匿名 200、application/octet-stream、无重定向、与库内文件逐字节一致（2026-10-05 实测）。
/// 两条死路别再试：① `raw.gitcode.com/.../raw/main/*.json` 恒 403「暂不支持预览」
///（该域名只服务预览，json/toml 拿不到）；② 抄 GitHub 的 `releases/latest/download/`
/// 同形别名同样不存在 —— Gitee 当年就栽在这个别名上（302 到 `repository/archive/…`
/// 恒 404，「线路配了、永远查不到新版、日志只记线路不通」）。
/// 另外 `gitcode.com/.../releases/download/...` 网页直链匿名 curl 是 418（反爬），
/// 所以清单里的下载 url 必须用 attach_files 的 API 下载端点（见发版脚本）。
/// 清单文件名也因此与 GitHub 侧区分开：AtomGit 侧叫 `latest-atomgit.json`、
/// GitHub 侧仍叫 `latest.json`（两条线路的 `url` 字段各指自己的下载源）。
const FEEDS: &[(&str, &str, &str, &str)] = &[
    (
        "atomgit",
        "AtomGit 国内源",
        "https://api.atomgit.com/api/v5/repos/xiaoxiaoxu1642/trim-tauri/raw/",
        "latest-atomgit.json",
    ),
    (
        "github",
        "GitHub 直连",
        "https://github.com/xiaoxu1642/trim-tauri/releases/latest/download/",
        "latest.json",
    ),
];

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
    /// 已核对通过的包体 SHA-256（小写 hex）。安装前写的完成标记要带上它，
    /// 用户在「更新已完成」弹窗里能看见并自行与发布页核对。
    sha256: String,
    /// 这次包体实际来自哪条线路（回退换线时与检查阶段的线路可能不同）
    via: String,
    /// 落在用户「下载」目录里的那份安装包路径（插件自己只用内存字节安装，
    /// 这份是给用户看得见/事后自查的；写失败为空，不影响更新本身）
    saved_to: String,
}

/// 把下载好的安装包按发布时的文件名放进用户「下载」目录。
///
/// 为什么放这里而不是只留在内存：用户 2026-10-05 指定的流程要求「下载到下载文件夹」，
/// 而且一份看得见的安装包是自动更新唯一的事后凭证 —— 装完想核对哈希、或想再装一次，
/// 都不用重新下载。文件名沿用发布名，与下载 URL 末段一致，避免同名不同物。
/// 返回 `None` = 没写成（没有下载目录 / 磁盘或权限问题），调用方只记日志不阻断。
fn save_to_downloads(bytes: &[u8], file_name: &str) -> Option<String> {
    let dir = std::env::var_os("USERPROFILE")
        .map(std::path::PathBuf::from)
        .map(|h| h.join("Downloads"))
        .filter(|d| d.is_dir())?;
    // 只接受一个纯文件名：URL 末段理论上可被清单写坏，路径分隔符一律拒绝
    if file_name.is_empty()
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name.contains("..")
    {
        return None;
    }
    let path = dir.join(file_name);
    match std::fs::write(&path, bytes) {
        Ok(_) => Some(path.to_string_lossy().to_string()),
        Err(e) => {
            log::write_log("warn", &format!("[updater] 安装包写入下载目录失败（不影响更新）: {e}"));
            None
        }
    }
}

/// 清单里声明的包体 SHA-256（可选字段）。
///
/// 取的是插件已经拉回来并**随对象带出**的 `Update::raw_json`，不再自己发一次 HTTP ——
/// 第二条获取路径就是第二条会漂移的链（AGENTS §5.16）。
/// 优先 `platforms.<target>.sha256`，退回顶层 `sha256`；两处都没有就返回 None（不猜）。
fn manifest_sha256(raw: &Value, target: &str) -> Option<String> {
    let obj = raw.as_object()?;
    let cand = obj
        .get("platforms")
        .and_then(|p| p.get(target))
        .and_then(|p| p.get("sha256"))
        .or_else(|| obj.get("sha256"));
    let s = cand?.as_str()?.trim().to_ascii_lowercase();
    // 只认 64 位十六进制：长度/字符集不合格的值等于清单写坏了，不当声明用
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(s)
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

// ==================== 线路顺序 ====================

/// 基址必须是带尾斜杠的目录前缀 —— 少了斜杠会拼出一个 404 端点，
/// 而 404 会被当成「这条线路不通」去退下一条，镜像配错就永远查不出来。
///
/// `manifest` 由**线路自带**（见 FEEDS 注释：AtomGit 走 api raw 托管、文件名与 GitHub 侧不同），
/// 不能用全局常量 `MANIFEST` —— 那是 GitHub 侧的约定。
fn endpoint_of(base: &str, manifest: &str) -> Option<Url> {
    if !base.ends_with('/') {
        return None;
    }
    Url::parse(&format!("{base}{manifest}")).ok()
}

/// 线路尝试顺序 = FEEDS 表顺序（**AtomGit 国内源优先、GitHub 兜底**）。
///
/// 2026-10-06 线路选择 UI 与 per-machine 偏好整链退役后顺序固化：默认就该是国内源，
/// 不该再出现「某台机器被固定到 GitHub 直连、国内用户每次检查都先吃超时」的状态。
///
/// **兜底序列里必须始终留着另一条真实线路**：国内线路被墙/仓库转私有、或 GitHub
/// 在某网络下不可达时，另一条就是唯一出路。丢线路 = 更新功能整体失效。
fn ordered_feeds() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    FEEDS.to_vec()
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
async fn check_once<R: Runtime>(
    app: &AppHandle<R>,
    base: &str,
    manifest: &str,
) -> Result<Option<Update>, String> {
    let endpoint = endpoint_of(base, manifest)
        .ok_or("线路基址非法（需带尾斜杠的 https 目录前缀）")?;
    let updater = app
        .updater_builder()
        .endpoints(vec![endpoint])
        .map_err(|e| e.to_string())?
        .timeout(std::time::Duration::from_millis(CHECK_TIMEOUT_MS))
        // v2-L4P-21（A-3）：插件的 Windows install_inner 末尾是 `std::process::exit(0)`
        // —— 绕过 Tauri 的 RunEvent::Exit，`on_app_exit` 的 log flush / 私有 tmp 清扫 /
        // realtime 停机全部跳过。on_before_exit 是插件留给这条退出路径的唯一钩子，
        // 每个 builder 都必须挂上（Update 对象由该 builder 产出，钩子随对象走）。
        .on_before_exit(|| crate::on_app_exit())
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
    let mut last_error = String::new();
    // 审查 L8：签名判定要**跨线路累积**。只看循环结束后残留的那条错误，会出现
    // 「GitHub 线路验签失败 + 镜像线路网络超时」= 最后一条是网络错 ⇒ 被报成可重试的
    // 网络抖动，与 :255-260 自述的保守方向相反（用户会对着一个永远无解的签名问题反复点）。
    let mut sig_failed_any = false;

    for (id, label, base, manifest) in ordered_feeds() {
        match check_once(&app, base, manifest).await {
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
/// （`Update`/`Network`/`Io`），而错误在 IPC 边界上已序列化成字符串（插件 `impl
/// Serialize` 就是 `to_string()`），拿不到结构化判据。取**保守方向**——宁可把问题说成
/// 「已阻止」并给出手动出口，也不能把签名问题说成网络问题让用户反复重试一个永远无解的操作。
///
/// v2-L4P-20（A-2）：关键字逐条对过插件 2.12.0 的 `#[error]` Display 原文——
/// `SignedVersionMismatch` 的文案是 "was signed for version … tampered"（旧清单的
/// "signed version" 匹配不上），`SignatureUtf8` 是 "could not be decoded"；这三条
/// 都是 requireSignedVersion 链路会真实浮现的失败，漏掉 = 被报成可重试的网络抖动。
fn is_signature_failure(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    [
        "signature",
        "pubkey",
        "public key",
        "minisign",
        "signed version",
        "signed for version",
        "invalid key",
        "tampered",
        "could not be decoded",
    ]
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

    // 复验必须用**当初那条线路的基址 + 清单名**：清单名线路自带（AtomGit 是
    // latest-atomgit.json），漏传 manifest 会拿 GitHub 的清单名去拼 AtomGit 的 raw 基址
    // —— 拼出一个 404 端点，把「已锁定的锚点」判成「变了」，于是下载被无理由拒绝。
    let (base, manifest) = FEEDS
        .iter()
        .find(|(id, _, _, _)| *id == pending.mirror)
        .map(|(_, _, b, m)| (*b, *m))
        .unwrap_or((FEEDS[0].2, FEEDS[0].3));
    let reverified = match check_once(&app, base, manifest).await {
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
    let pinned_mirror = pending.mirror.clone();
    let task = tauri::async_runtime::spawn(async move {
        // 插件回的是**增量**字节数，累计值、百分比与速度由我们自己算。
        // 每次尝试的开头各自赋值（见下面循环里那两行），所以这里只声明不初始化。
        let mut transferred: u64;
        let mut started: std::time::Instant;
        let app2 = app.clone();
        // 下载候选：锁定那条线路优先，其余线路**只有在给出同一个版本、同一份签名**时才入列。
        // 「换线路」允许的只是换通道，不允许换包 —— 两线给不同签名意味着有人在中间换包，
        // 那必须拒绝而不是"那就试另一条"（用户 2026-10-05 裁定的「先试快的、失败自动换另一个」
        // 就是这个前提下的自动换线）。
        let mut candidates: Vec<(String, Update)> = vec![(pinned_mirror.clone(), update.clone())];
        for (id, _, base, manifest) in FEEDS.iter().filter(|(id, _, _, _)| *id != pinned_mirror) {
            match check_once(&app2, base, manifest).await {
                Ok(Some(u)) if u.version == update.version && u.signature == update.signature => {
                    candidates.push(((*id).to_string(), u));
                }
                Ok(Some(_)) => {
                    log::write_log(
                        "warn",
                        &format!("[updater] 线路 {id} 的清单与已锁定锚点不一致，不作为下载候选（不换包原则）"),
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    log::write_log(
                        "warn",
                        &format!("[updater] 备用线路 {id} 取清单失败，跳过: {e}"),
                    );
                }
            }
        }
        let mut outcome: Option<(String, Vec<u8>)> = None;
        let mut last_err = String::new();
        let mut last_sig_failed = false;
        for (via, cand) in &candidates {
            transferred = 0;
            // 换线后重新计时：否则第二条线路的速度被第一条的等待时间摊薄，界面显示会误导
            started = std::time::Instant::now();
            let r = cand
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
            match r {
                Ok(bytes) => {
                    outcome = Some((via.clone(), bytes));
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    last_sig_failed = is_signature_failure(&msg);
                    last_err = msg;
                    // 签名/清单类失败**不自动换线**：那正是最需要停下来的判据，
                    // 换线重试等于给同一次篡改再试一次的机会。
                    if last_sig_failed {
                        log::write_log("error", &format!("[updater] {via} 下载被签名判据阻止，不再尝试其它线路"));
                        break;
                    }
                    log::write_log(
                        "warn",
                        &format!("[updater] {via} 下载失败，尝试自动换到下一条线路: {last_err}"),
                    );
                }
            }
        }
        match outcome {
            Some((via, bytes)) => {
                // 走到这里说明插件**已经**用内置公钥验过 minisign 签名
                // （verify_signature 在 download 返回前），故 ready 意味着包体可信，
                // 不只是「下载完成」。
                //
                // sha256 是**交叉核对**，不是第二道信任锚：锚仍然是内置公钥背书的 minisign 签名。
                // 清单若声明了 sha256，就得和实际字节一致——不一致说明清单与产物对不上
                // （截断、错配、发布侧只更新了一处），一律不进安装。
                let actual = crate::engine::hash::sha256_bytes(&bytes);
                let declared = manifest_sha256(&update.raw_json, &update.target);
                if let Some(d) = &declared {
                    if *d != actual {
                        log::write_log(
                            "error",
                            &format!("[updater] 包体哈希与清单声明不一致（声明 {d}，实际 {actual}），已阻止安装"),
                        );
                        push(
                            &app,
                            json!({
                                "phase": "error", "sigFailed": true,
                                "message": "安装包哈希与发布清单声明不一致，已阻止安装。请重新检查更新或前往官方 Releases 页面手动下载。"
                            }),
                        );
                        *lock(&DOWNLOAD_TASK) = None;
                        return;
                    }
                }
                log::write_log(
                    "info",
                    &format!(
                        "[updater] {} 已下载并验签（经 {via}，sha256={actual}{}），等待用户确认安装",
                        version,
                        if declared.is_some() { "，哈希已核对" } else { "，清单未声明哈希" }
                    ),
                );
                // 下载 URL 的末段就是发布名（Trim_x.y.z_x64-setup.exe）
                let file_name = update
                    .download_url
                    .path_segments()
                    .and_then(|mut s| s.next_back())
                    .unwrap_or("")
                    .to_string();
                let saved = save_to_downloads(&bytes, &file_name).unwrap_or_default();
                *lock(&DOWNLOADED) = Some(Downloaded {
                    sha256: actual.clone(),
                    via: via.clone(),
                    saved_to: saved.clone(),
                    update,
                    bytes,
                });
                *lock(&PENDING) = None;
                push(&app, json!({
                    "phase": "ready", "version": version, "sha256": actual, "via": via,
                    "savedTo": saved,
                }));
            }
            None => {
                // 用户主动取消由 updater:cancel-download 直接 abort 任务并推 idle，
                // 不会走到这里；所以此分支只剩真实失败。
                // 验签就在 download 返回前发生（见文件头），故**下载阶段才是签名问题
                // 真正会浮现的地方** —— 这里不过一遍分类，用户看到的会是
                // 「更新失败，点击按钮重试」，而重试永远不会有结果。
                log::write_log(
                    "error",
                    &format!("[updater] 下载{}（{}）: {last_err}", if last_sig_failed { "被阻止" } else { "失败，含全部线路" }, candidates.len()),
                );
                push(
                    &app,
                    json!({ "phase": "error", "sigFailed": last_sig_failed, "message": last_err }),
                );
            }
        }
        // 技术债 T2（v2 审查，2026-10-01 登记维持）：本行与 spawn 后的 `= Some(task)` 存在
        // 理论乱序 —— 若下载在本行执行前就瞬时完成（微秒级，实测不可达），此处置 None 会被
        // Some(已完成句柄) 覆盖 → `is_some()` 守卫误判「下载中」。干净修法需 JoinHandle 终态
        // 判活（tauri 2.11 的 JoinHandle 无 is_finished，已查证）或显式 DownloadState 枚举，
        // 随统一出口重构一并带走；现实兜底是 updater:cancel-download 的 take() 会清掉死句柄，可自愈。
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
    // 安装前留「本次要装到哪个版本」的标记：install 走的是 NSIS 静默替换，替换完成后
    // 本进程已经不存在（`process::exit(0)`），新实例起来后才能读到它，从而给出
    // 「更新已完成」的确认界面（用户 2026-10-05 要求的「完成更新 / 打开应用」两按钮出口）。
    // 写失败不阻断安装——标记只影响完成后的一句提示，不影响更新本身。
    let marker = json!({
        "fromVersion": d.update.current_version,
        "toVersion": d.update.version,
        "sha256": d.sha256,
        "via": d.via,
        "installerPath": d.saved_to,
        "at": crate::engine::now_ms(),
    });
    if let Err(e) = security::atomic_write_json(&paths::join_data(DONE_FILE), &marker) {
        log::write_log("warn", &format!("[updater] 更新完成标记写入失败（不影响安装）: {e}"));
    }
    // v2-L4P-21（A-3）：install 的 Windows 路径以 `std::process::exit(0)` 收尾，
    // 其间不会再回到 RunEvent::Exit——on_before_exit 钩子已在 builder 上挂
    // on_app_exit，这里再补一次日志刷盘，保证「安装中」之前的最后一条日志落盘
    //（AGENTS §3：危险操作前 log::flush_sync()）。
    log::flush_sync();
    // 安装参数取自 conf 的 plugins.updater.windows.installMode = "quiet"（NSIS `/S /R`），
    // 等价上游 quitAndInstall(isSilent=true, isForceRunAfter=true)
    match d.update.install(&d.bytes) {
        Ok(()) => Ok(json!({ "ok": true })),
        Err(e) => {
            log::write_log("error", &format!("[updater] 安装失败: {e}"));
            // 安装既然没起来，标记就是废信息：立刻清掉，免得下次启动谎报「更新已完成」。
            if let Err(e) = std::fs::remove_file(paths::join_data(DONE_FILE)) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    log::write_log("warn", &format!("[updater] 清理更新完成标记失败: {e}"));
                }
            }
            Ok(json!({ "ok": false, "error": e.to_string() }))
        }
    }
}

/// updater:completion —— 取走并清除「更新已完成」标记（新版本实例首启读一次）
///
/// 读后即删：这台机器已经告诉过用户「装好了」，第二次启动再弹一次就成了骚扰。
/// 只认 `toVersion == 当前版本` 的标记：装的是 0.7.0 而当前跑的是 0.6.3，说明那次替换
/// 没落地（或用户又装了旧包），此时谎报成功比不报更糟。
///
/// 顺带做用户 2026-10-05 要的最后一步：清掉下载目录里那份安装包。清理结果**照实回报**
/// （`cleaned` / `cleanFailed`），程序文件本身由 NSIS 覆盖安装替换，Trim 不另外删
/// 「旧版代码文件」—— 那是安装器的职责，我们看不到也没有那份清单。
#[tauri::command]
pub fn updater_completion<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let path = paths::join_data(DONE_FILE);
    let Some(v) = crate::security::read_json_or_default(&path).as_object().cloned() else {
        return Ok(json!({ "ok": true, "data": Value::Null }));
    };
    let _ = std::fs::remove_file(&path);
    let current = window.app_handle().package_info().version.to_string();
    if v.get("toVersion").and_then(|x| x.as_str()) != Some(current.as_str()) {
        log::write_log(
            "warn",
            &format!(
                "[updater] 更新完成标记指向 {}，当前版本 {current}，不作为「已更新」上报",
                v.get("toVersion").and_then(|x| x.as_str()).unwrap_or("(空)")
            ),
        );
        return Ok(json!({ "ok": true, "data": Value::Null }));
    }
    let mut data = serde_json::Map::from_iter(v);
    let installer = data
        .get("installerPath")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let (cleaned, clean_failed) = match clean_installer(&installer) {
        Cleaned::Yes => (true, false),
        Cleaned::Nothing => (false, false),
        Cleaned::Failed => (false, true),
    };
    data.insert("cleaned".into(), json!(cleaned));
    data.insert("cleanFailed".into(), json!(clean_failed));
    Ok(json!({ "ok": true, "data": Value::Object(data) }))
}

enum Cleaned {
    /// 真的删掉了一份
    Yes,
    /// 没有可删的（路径为空，或文件已经不在了）
    Nothing,
    /// 想删但没删动（权限/占用）
    Failed,
}

/// 只删「我们自己放进下载目录的那一个文件」：文件名必须还是发布名形状
/// （`Trim_<版本>_x64-setup.exe`），且必须真的在某个 Downloads 目录下。
/// 标记里的路径来自磁盘上的一份 JSON，虽然只有本应用写得进去，但删除出口一律不信任输入。
fn clean_installer(path: &str) -> Cleaned {
    if path.is_empty() {
        return Cleaned::Nothing;
    }
    let p = std::path::Path::new(path);
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let shape_ok = name.starts_with("Trim_") && name.ends_with("_x64-setup.exe") && !name.contains("..");
    let in_downloads = std::env::var_os("USERPROFILE")
        .map(std::path::PathBuf::from)
        .map(|h| p.parent() == Some(h.join("Downloads").as_path()))
        .unwrap_or(false);
    if !shape_ok || !in_downloads {
        log::write_log("warn", &format!("[updater] 清理跳过：安装包路径不在下载目录或文件名不合形状: {path}"));
        return Cleaned::Nothing;
    }
    match std::fs::remove_file(p) {
        Ok(()) => Cleaned::Yes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Cleaned::Nothing,
        Err(e) => {
            log::write_log("warn", &format!("[updater] 清理安装包失败: {e}"));
            Cleaned::Failed
        }
    }
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
        // 3 秒：够首帧画完（更新弹窗不该跟开屏动画抢），又不至于让用户以为「打开就没反应」。
        // 用户 2026-10-05 指定的时点；发现新版本由渲染层无条件弹 available 弹窗（不是静默）。
        std::thread::sleep(std::time::Duration::from_secs(3));
        tauri::async_runtime::spawn(async move {
            let _ = safe_check(app, true).await;
        });
    });
}

// ==================== 纯函数单测 ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_ids() -> Vec<&'static str> {
        ordered_feeds().iter().map(|f| f.0).collect()
    }

    /// 清理出口的输入不可信：标记里的路径来自磁盘上的一份 JSON，
    /// 只有「下载目录 + 发布名形状」同时成立才允许删，其余一律不碰文件。
    #[test]
    fn clean_installer_refuses_anything_but_our_own_download_file() {
        // 空路径 = 没写过下载目录
        assert!(matches!(clean_installer(""), Cleaned::Nothing));
        // 名字对但不在下载目录（这里刻意用一个必然不存在的路径：判据必须在**触盘之前**就拒掉，
        // 所以返回 Nothing 而不是 Failed）
        assert!(matches!(clean_installer(r"C:\Windows\Trim_9.9.9_x64-setup.exe"), Cleaned::Nothing));
        assert!(matches!(clean_installer(r"C:\Users\someone\Documents\Trim_9.9.9_x64-setup.exe"), Cleaned::Nothing));
        // 形状不合（缺前后缀、带穿越）
        let dl = std::env::var_os("USERPROFILE")
            .map(|h| std::path::PathBuf::from(h).join("Downloads").join("whatever.txt").to_string_lossy().to_string())
            .unwrap_or_default();
        assert!(matches!(clean_installer(&dl), Cleaned::Nothing));
        assert!(matches!(clean_installer(r"C:\Users\x\Downloads\Trim_..\..\evil-setup.exe"), Cleaned::Nothing));
        // 真的不存在的那个下载目录文件 → Nothing（不是 Failed：没删动不是因为权限）
        let missing = std::env::var_os("USERPROFILE")
            .map(|h| {
                std::path::PathBuf::from(h)
                    .join("Downloads")
                    .join("Trim_0.0.0-should-not-exist_x64-setup.exe")
                    .to_string_lossy()
                    .to_string()
            })
            .unwrap_or_default();
        assert!(matches!(clean_installer(&missing), Cleaned::Nothing));
    }

    /// 下载文件名来自清单里的 URL 末段，不可信：路径分隔符与穿越一律拒绝。
    #[test]
    fn save_to_downloads_rejects_names_with_path_parts() {
        assert!(save_to_downloads(b"x", "").is_none());
        assert!(save_to_downloads(b"x", "..\\setup.exe").is_none());
        assert!(save_to_downloads(b"x", "a/b.exe").is_none());
        assert!(save_to_downloads(b"x", r"a\b.exe").is_none());
    }

    /// 清单里的 sha256 只是**交叉核对值**（信任锚始终是内置公钥背书的 minisign 签名），
    /// 所以取不到/不合格式的声明一律当"清单没写"，绝不拿一个畸形串去拦正常更新。
    #[test]
    fn manifest_sha256_reads_declared_value_or_none() {
        let good = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let raw = json!({
            "version": "9.9.9",
            "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "platforms": { "windows-x86_64": { "sha256": good } }
        });
        // 平台位优先于顶层：换平台时顶层那个值不属于这个包
        assert_eq!(manifest_sha256(&raw, "windows-x86_64").as_deref(), Some(good));
        // 大写声明归一化成小写比较口径
        let upper = json!({ "platforms": { "windows-x86_64": { "sha256": good.to_uppercase() } } });
        assert_eq!(manifest_sha256(&upper, "windows-x86_64").as_deref(), Some(good));
        // 没有平台项时退回顶层
        assert_eq!(manifest_sha256(&raw, "linux-x64").as_deref(), Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        // 格式不合格（短串、非 hex、空、类型错）都当没声明 —— 正向对照：不合格清单不得拦下载
        for bad in [
            json!({ "sha256": "abc" }),
            json!({ "sha256": "zz".repeat(32).as_str() }),
            json!({ "sha256": "" }),
            json!({ "sha256": 123 }),
            json!({}),
            json!([]),
        ] {
            assert_eq!(manifest_sha256(&bad, "windows-x86_64"), None, "畸形声明被当成了有效值: {bad}");
        }
    }

    #[test]
    fn 国内源恒优先且_github_始终在兜底位() {
        // 2026-10-06 线路选择 UI 退役后顺序固化：每次检查都 AtomGit 先、GitHub 兜底，
        // 任何机器上都不再可能被固定到 GitHub 直连。
        assert_eq!(feed_ids(), vec!["atomgit", "github"]);
    }

    #[test]
    fn 端点由基址加线路自带清单名拼出() {
        let u = endpoint_of("https://github.com/o/r/releases/latest/download/", "latest.json").unwrap();
        assert_eq!(u.as_str(), "https://github.com/o/r/releases/latest/download/latest.json");
        // AtomGit 走 api raw 托管，清单名线路自带
        let a = endpoint_of("https://api.atomgit.com/api/v5/repos/o/r/raw/", "latest-atomgit.json").unwrap();
        assert_eq!(a.as_str(), "https://api.atomgit.com/api/v5/repos/o/r/raw/latest-atomgit.json");
        // 漏尾斜杠必须直接判非法，而不是拼出一个 404 端点被误当「线路不通」
        assert!(endpoint_of("https://github.com/o/r/releases/latest/download", "latest.json").is_none());
        assert!(endpoint_of("不是个 url", "latest.json").is_none());
    }

    /// **AtomGit 线路必须走 api raw 端点**（2026-10-05 三条实测死路的判据形态）。
    ///
    /// ① 抄 GitHub 的 `releases/latest/download/` 同形别名不存在 —— Gitee 当年即栽在这里
    ///（302 到 `repository/archive/…` 恒 404，表现为「线路配了、永远查不到新版、
    /// 日志只记线路不通」）；② `raw.gitcode.com/.../raw/main/*.json` 恒 403「暂不支持预览」
    ///（该域名只服务预览，json/toml 拿不到）；③ 唯一可用的是 API raw：
    /// `api.atomgit.com/api/v5/repos/{owner}/{repo}/raw/{path}` —— 匿名 200、
    /// application/octet-stream、字节与库内文件一致。形态错了不会红，只会静默退回 GitHub，
    /// 所以把判据直接钉死。
    #[test]
    fn atomgit线路必须走api_raw端点() {
        let a = FEEDS.iter().find(|(id, ..)| *id == "atomgit").expect("必须有 atomgit 线路");
        assert!(
            a.2.contains("api.atomgit.com") && a.2.contains("/raw/"),
            "AtomGit 基址必须走 API raw 端点（实测 raw.gitcode.com 对 json 恒 403）：{}",
            a.2
        );
        assert!(
            !a.2.contains("raw.gitcode.com") && !a.2.contains("gitcode.com/"),
            "AtomGit 的网页 raw 端点拿不到 json，别写回这些同形但无效的地址：{}",
            a.2
        );
        assert!(
            !a.2.contains("releases/latest"),
            "releases/latest/download/ 别名在 AtomGit 上不存在（Gitee 当年即栽在这里）：{}",
            a.2
        );
        // 清单名必须与 GitHub 侧区分：url 字段指向各自的下载源，同名会串
        assert_eq!(a.3, "latest-atomgit.json", "AtomGit 侧清单名必须带 -atomgit 后缀");
        let gh = FEEDS.iter().find(|(id, ..)| *id == "github").expect("必须有 github 线路");
        assert_eq!(gh.3, "latest.json", "GitHub 侧清单名保持 latest.json");
    }

    #[test]
    fn 线路表恰好两条且形态合法() {
        for (id, _, base, manifest) in FEEDS {
            assert!(base.ends_with('/'), "{id} 基址必须带尾斜杠");
            assert!(base.starts_with("https://"), "{id} 必须走 https");
            // 清单名要能安全拼进 URL：不能带斜杠/查询串（否则拼出不可预期的端点）
            assert!(
                !manifest.contains('/') && !manifest.contains('?'),
                "{id} 清单名含路径分隔符或查询串，会拼出不可预期端点：{manifest}"
            );
            assert!(manifest.ends_with(".json"), "{id} 清单应为 json：{manifest}");
        }
        // 线路表**恰好两条**：三源时代留下的加速代理不得复活（2026-10-03 用户拍板）
        assert_eq!(FEEDS.len(), 2, "更新线路应只有 AtomGit + GitHub 两条: {FEEDS:?}");
        // 已退役的线路 id 不得回到线路表：加速代理（2026-10-03）、Gitee（2026-10-05）
        for gone in ["gh-proxy", "ghfast", "gitee"] {
            assert!(
                !FEEDS.iter().any(|(id, ..)| *id == gone),
                "{gone} 已下线，不得回到线路表"
            );
        }
        // 清单名不得两条相同（相同则 url 字段必有一个指错仓库）
        assert_ne!(FEEDS[0].3, FEEDS[1].3, "两条线路的清单名不能相同（url 字段会指错源）");
    }

    #[test]
    fn 签名类错误必须与网络错误区分开() {
        assert!(is_signature_failure("Invalid signature"));
        assert!(is_signature_failure("failed to verify minisign signature"));
        assert!(is_signature_failure("require signed version but none found"));
        assert!(is_signature_failure("public key mismatch"));
        assert!(is_signature_failure("Invalid pubkey"));
        // v2-L4P-20：三条真实 Display 原文（tauri-plugin-updater 2.12.0 #[error] 逐字抄）
        assert!(is_signature_failure(
            "The update was signed for version 0.4.4 but the update endpoint announced version 0.4.5. The endpoint response may have been tampered with to force installing a different release."
        ));
        assert!(is_signature_failure(
            "The update signature does not specify the version it was signed for, which `requireSignedVersion` requires. Re-sign and re-publish this release, or disable `requireSignedVersion`."
        ));
        assert!(is_signature_failure(
            "The signature xyz= could not be decoded, please check if it is a valid base64 string. The signature must be the contents of the `.sig` file generated by the Tauri bundler, as a string."
        ));
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
