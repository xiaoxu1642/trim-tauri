//! runtimes 域（B 批）：runtimes:collect / runtimes:install（+ `runtimes:install-progress` 事件）
//!
//! 需在 lib.rs 的 invoke_handler 中注册（本任务不改 lib.rs，请统一登记）：
//!   commands::runtimes::runtimes_collect,
//!   commands::runtimes::runtimes_install,
//!
//! 实现体来源：main.js 7500-7704（runRuntimesCollect / downloadRedist / runtimes:install），
//! 安装包元数据取自 src/scripts-powershell/runtimes-scripts.js 的 INSTALLERS 白名单。
//!
//! 安全三闸门（方案 §5，逐条复刻 main.js）：
//!   ① 来源白名单：URL 初始主机 + **重定向终点主机**都必须在 REDIST_HOST_WHITELIST 内；
//!   ② SHA-256 + 尺寸双校验：下载后 + 缓存命中复核 + **提权执行前复核**（RT-1），任一不符即删除中止；
//!   ③ 快照校验 + 管理员判定：动作必须属于**本窗口**最近一次 runtimes:collect 的待修复项，
//!      且当前进程必须是管理员（否则 needAdmin）。
//!
//! HTTP 传输：走 `engine::winhttp`（与 cleanup 规则更新共用的 WinHTTP 原生实现，
//! 零新增第三方 HTTP 依赖，TLS/代理走系统栈），含**重定向终点 host 白名单**（闸门 1b，
//! 经 `allow_host` 判定器传入）与 content-length/累计字节双尺寸早退。
//! 全部下载相关判定（白名单/尺寸上限/双校验/原子改名/装前复核）均已实现，无遗留 TODO。

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::{Emitter, WebviewWindow};

use crate::engine::{guard, log, paths, sysinfo, winhttp};
use crate::pwsh;

// ==================== 外置 PS 脚本（编译期嵌入，禁止手写） ====================
const RUNTIMES_STATUS_PS: &str = include_str!("../../ps/runtimes_status.ps1");
const REPAIR_VC_X64_PS: &str = include_str!("../../ps/runtimes_repair_vc_x64.ps1");
const REPAIR_VC_X86_PS: &str = include_str!("../../ps/runtimes_repair_vc_x86.ps1");
const REPAIR_NETFX48_PS: &str = include_str!("../../ps/runtimes_repair_netfx48.ps1");
const REPAIR_NETFX35_PS: &str = include_str!("../../ps/runtimes_repair_netfx35.ps1");

/// 修复脚本里的**安装包路径哨兵**（生成期由 `tools/ps-map/runtimes.mjs` + ps-mapping 的
/// `sentinelPath` 写入该唯一 token；运行前替换为真实缓存包路径，见 `replace_installer_path`）。
///
/// 审查 M22：这里**刻意不再是一个路径**。旧值是「上游 `runtimes-scripts.js` 自身在本机的
/// 绝对路径」（上游 `repair()` 用 `fs.existsSync` 校验入参，生成期只能借真实路径过闸），
/// 于是开发者机器布局被写进 66 个 `.ps1` 并随 `include_str!` 编进发布的二进制；
/// 而且门禁坐标一改（vendor 进仓库）文本层对拍就整批红。token 与本机无关、全局唯一，
/// 「缺哨兵即 Err」的 fail-closed 判定保持不变。
const RUNTIMES_PATH_SENTINEL: &str = "@@TRIM_INSTALLER_PATH@@";

// ==================== 下载白名单 / 上限 / 缓存目录（逐项照抄 main.js 7506-7511） ====================
const REDIST_HOST_WHITELIST: &[&str] = &[
    "aka.ms",
    "go.microsoft.com",
    "download.microsoft.com",
    "download.visualstudio.microsoft.com",
    "www.microsoft.com",
];
/// 单包上限兜底（防白名单主机被挂大文件）
const REDIST_MAX_BYTES: u64 = 300 * 1024 * 1024;

fn redist_cache_dir() -> PathBuf {
    paths::app_data_dir().join("redist")
}

/// 安装包元数据（url/sha256/bytes 与 runtimes-scripts.js INSTALLERS 同源，改包必须同步）。
/// 注：包名（name）已烘焙进外置 PS 修复脚本（如「正在安装 VC++ 2015-2022 x64…」），
/// 故此处不再重复持有。
struct Installer {
    url: &'static str,
    sha256: &'static str,
    bytes: u64,
}

const INSTALLERS: &[(&str, Installer)] = &[
    (
        "vc-x64",
        Installer {
            url: "https://aka.ms/vs/17/release/vc_redist.x64.exe",
            sha256: "cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b",
            bytes: 25635768,
        },
    ),
    (
        "vc-x86",
        Installer {
            url: "https://aka.ms/vs/17/release/vc_redist.x86.exe",
            sha256: "0c09f2611660441084ce0df425c51c11e147e6447963c3690f97e0b25c55ed64",
            bytes: 13953392,
        },
    ),
    (
        "netfx48",
        Installer {
            url: "https://go.microsoft.com/fwlink/?linkid=2088631",
            sha256: "0a3a390c47e639d0f7fc65b21195fee6b7f65b066f80f70c60fab191d14b7e40",
            bytes: 121346568,
        },
    ),
];

/// netfx35 走 DISM 启用，不消费安装包
const NETFX35: &str = "netfx35";

fn installer(action_id: &str) -> Option<&'static Installer> {
    INSTALLERS
        .iter()
        .find(|(id, _)| *id == action_id)
        .map(|(_, meta)| meta)
}

fn is_allowed_action(action_id: &str) -> bool {
    action_id == NETFX35 || installer(action_id).is_some()
}

// ==================== 快照（按窗口 label 分槽，对齐 Electron runtimesSnapshots 的 sender.id 分槽） ====================
static SNAPSHOTS: Mutex<Option<HashMap<String, Value>>> = Mutex::new(None);

fn snapshot_store(label: &str, items: Value) {
    let mut g = SNAPSHOTS.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashMap::new).insert(label.to_string(), items);
}

fn snapshot_get(label: &str) -> Option<Value> {
    SNAPSHOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(label).cloned())
}

/// 动作是否属于本窗口最近一次采集到的待修复项（修复动作的 repair.id）
fn snapshot_has_repair(label: &str, action_id: &str) -> bool {
    match snapshot_get(label) {
        Some(Value::Array(items)) => items.iter().any(|it| {
            it.get("repair")
                .and_then(|r| r.get("id"))
                .and_then(|v| v.as_str())
                == Some(action_id)
        }),
        _ => false,
    }
}

// ==================== 通用工具 ====================
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 流式 SHA-256（4MB 缓冲，与 JS sha256File 同口径）
fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(to_hex(&hasher.finalize()))
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// 闸门 1：主机白名单（URL 解析比较，禁字符串 includes）；
/// host 解析复用 `engine::winhttp::url_host`（等价 JS `new URL(url).hostname`）
fn is_whitelisted_host(host: &str) -> bool {
    REDIST_HOST_WHITELIST.contains(&host.to_ascii_lowercase().as_str())
}

/// 缓存文件名：`<sha256 前 12 位>-<文件名>`。文件名取 URL 路径最后一个非空段，
/// 不合规（RT-3：URL 以 / 结尾等异常形态）则回退 `<actionId>.bin`，保证恒非空可辨识。
fn cache_file_name(inst: &Installer, action_id: &str) -> String {
    let last_seg = inst
        .url
        .split('?')
        .next()
        .unwrap_or("")
        .split('/')
        .filter(|s| !s.is_empty())
        .next_back()
        .unwrap_or("")
        .trim();
    let file_part = if is_valid_file_part(last_seg) {
        last_seg.to_string()
    } else {
        format!("{action_id}.bin")
    };
    let sha12 = &inst.sha256[..12.min(inst.sha256.len())];
    format!("{sha12}-{file_part}")
}

/// `/[a-zA-Z0-9._-]{1,64}\.[a-zA-Z0-9._-]{1,10}$/` 的手写等价实现
fn is_valid_file_part(s: &str) -> bool {
    let Some((stem, ext)) = s.rsplit_once('.') else {
        return false;
    };
    let ok_chars = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    ok_chars(stem) && stem.len() <= 64 && ok_chars(ext) && ext.len() <= 10
}

fn emit_progress<R: tauri::Runtime>(window: &WebviewWindow<R>, payload: Value) {
    let _ = window.emit("runtimes:install-progress", payload);
}

// ==================== 下载（复用 engine::winhttp 传输层） ====================
//
// HTTP 传输下沉到 `engine::winhttp`（与 cleanup 规则库在线更新共用同一实现）：
// 零新增第三方 HTTP 依赖、TLS 与代理走系统栈、跟随重定向并取回终点 URL。
// 本域保留的是**闸门语义**（判定点全部在建文件之前）：
//   ① 闸门 1a：初始主机白名单（见 download_redist）；
//   ② 闸门 1b：**重定向终点** host 白名单——经 `allow_host = Some(&is_whitelisted_host)`
//      传入 winhttp，由其收到响应头后即判定，不通过即中止、不留半成品；
//   ③ 尺寸上限 REDIST_MAX_BYTES 由 `max_bytes` 传入（声明值 + 流式累计双早退）。

/// 下载安装包到 `dest`（HTTP 传输见 `engine::winhttp::download_to_file`）。
///
/// 语义（缺一即削掉安全闸门）：
///   1) 跟随重定向，并对**重定向终点** host 调 `is_whitelisted_host`，不在白名单即中止（闸门 1b）；
///   2) 尺寸上限 REDIST_MAX_BYTES：content-length 声明值或流式累计超限均中止；
///   3) 按 `on_progress(已收字节, 预估总字节)` 驱动下载进度（预估优先取 content-length，取不到为 0）；
///   4) 任何失败都删除 `dest` 半成品。
fn download_to(url: &str, dest: &Path, mut on_progress: impl FnMut(u64, u64)) -> Result<(), String> {
    let r = winhttp::download_to_file(
        url,
        dest,
        &[],
        // 发送/接收阶段超时 30s（与迁移前 15/15/30/30 一致；解析/连接阶段由 winhttp 固定为 15s）
        Duration::from_secs(30),
        Some(REDIST_MAX_BYTES),
        // 白名单判定器：winhttp 在**建文件之前**对重定向终点 host 调用（闸门 1b）
        Some(&|h: &str| is_whitelisted_host(h)),
        &mut on_progress,
    );
    if r.is_err() {
        // 统一的失败出口：半成品一律删除（网络中断/状态码非 2xx/白名单不通过/写盘失败都走这里）
        let _ = std::fs::remove_file(dest);
    }
    r
}

/// 下载运行库安装包（返回缓存中的真实路径）
/// 流程照抄 main.js downloadRedist：来源白名单 → 缓存命中复核 → 流式下载 → 尺寸上限
/// → SHA-256/尺寸双校验 → 原子改名入缓存。
fn download_redist<R: tauri::Runtime>(window: &WebviewWindow<R>, action_id: &str) -> Result<PathBuf, String> {
    let inst = installer(action_id).ok_or_else(|| "未知的安装包".to_string())?;
    // 闸门 1a：初始主机白名单
    let initial_host = winhttp::url_host(inst.url).ok_or_else(|| "下载地址无效".to_string())?;
    if !is_whitelisted_host(&initial_host) {
        return Err("下载地址主机不在白名单内".into());
    }

    let cache_dir = redist_cache_dir();
    std::fs::create_dir_all(&cache_dir).map_err(|e| format!("创建缓存目录失败: {e}"))?;
    let cache_path = cache_dir.join(cache_file_name(inst, action_id));

    // 缓存命中：复验 hash + 尺寸后直接复用（不信任缓存内容）
    if cache_path.is_file() {
        let hash_ok = sha256_file(&cache_path)
            .map(|h| h == inst.sha256 && file_len(&cache_path) == inst.bytes)
            .unwrap_or(false);
        if hash_ok {
            emit_progress(
                window,
                json!({ "phase": "download", "percent": 100, "cached": true }),
            );
            return Ok(cache_path);
        }
        // 缓存内容与期望不符：删除脏包重新下载
        let _ = std::fs::remove_file(&cache_path);
    }

    emit_progress(window, json!({ "phase": "download", "percent": 0 }));
    let tmp_path = PathBuf::from(format!("{}.downloading", cache_path.to_string_lossy()));

    // 流式进度 → 事件（percent 封顶 99，单调不倒退；对齐 main.js 7589-7605）
    let last_pct = std::cell::Cell::new(0i64);
    let dl = download_to(inst.url, &tmp_path, |got, total| {
        let est = if total > 0 { total } else { inst.bytes };
        if est == 0 {
            return;
        }
        let pct = (((got as f64 / est as f64) * 100.0).round() as i64).min(99);
        if pct > last_pct.get() {
            last_pct.set(pct);
            emit_progress(window, json!({ "phase": "download", "percent": pct }));
        }
    });
    if let Err(e) = dl {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // 尺寸上限兜底（声明长度判定在 download_to 内；此处对落盘文件再兜一层）
    if file_len(&tmp_path) > REDIST_MAX_BYTES {
        let _ = std::fs::remove_file(&tmp_path);
        return Err("安装包超过尺寸上限，已中止".into());
    }

    // 闸门 2：SHA-256 + 尺寸双校验，任一不符 → 删除并中止，绝不执行
    let hash = match sha256_file(&tmp_path) {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("安装包读取失败: {e}"));
        }
    };
    if hash != inst.sha256 || file_len(&tmp_path) != inst.bytes {
        let _ = std::fs::remove_file(&tmp_path);
        log::write_log(
            "error",
            &format!("运行库安装包校验未通过: {action_id}（hash/尺寸不符，已删除）"),
        );
        return Err("安装包校验未通过（SHA-256 或尺寸不符），已删除并中止".into());
    }
    std::fs::rename(&tmp_path, &cache_path).map_err(|e| format!("写入缓存失败: {e}"))?;
    emit_progress(window, json!({ "phase": "download", "percent": 100 }));
    Ok(cache_path)
}

// ==================== 修复脚本生成（哨兵替换） ====================
/// `.ps1` 顶部来源说明块的结束标记（与 `cleanup.rs` 的 `PROVENANCE_END` 同一个约定）
const PROVENANCE_END: &str = "# PROVENANCE>>>";

/// 审查 L3：哨兵 token **同时出现在 PROVENANCE 注释行**（`ps/runtimes_repair_*.ps1:2` 的
/// `repair("netfx48", "@@TRIM_INSTALLER_PATH@@")`），对它做全量 `replace` 会把真实安装包
/// 路径注入进 `#` 注释，来源记录当场失真。故一律「只替换正文，来源块原样保留」，
/// 哨兵有无也只看正文 —— 否则光靠注释行那个 token 就能骗过"模板带哨兵"的判定。
fn split_provenance(template: &str) -> (&str, &str) {
    match template.find(PROVENANCE_END) {
        Some(i) => {
            let cut = i + PROVENANCE_END.len();
            template.split_at(cut)
        }
        None => ("", template),
    }
}

/// 把脚本里的安装包路径哨兵替换为真实缓存包路径（单引号转义，PS 单引号字符串）
fn replace_installer_path(template: &str, installer_path: &Path, action_id: &str) -> Result<String, String> {
    if !installer_path.is_file() {
        return Err(format!("安装包不存在: {action_id}"));
    }
    let (head, body) = split_provenance(template);
    if !body.contains(RUNTIMES_PATH_SENTINEL) {
        return Err("修复脚本缺少安装包路径哨兵".into());
    }
    let escaped = installer_path.to_string_lossy().replace('\'', "''");
    let out = body.replace(RUNTIMES_PATH_SENTINEL, &escaped);
    if out.contains(RUNTIMES_PATH_SENTINEL) {
        return Err("安装包路径替换失败（哨兵残留）".into());
    }
    Ok(format!("{head}{out}"))
}

fn build_repair_script(action_id: &str, installer_path: Option<&Path>) -> Result<String, String> {
    match action_id {
        "netfx35" => Ok(REPAIR_NETFX35_PS.to_string()),
        "vc-x64" => replace_installer_path(
            REPAIR_VC_X64_PS,
            installer_path.ok_or_else(|| format!("安装包不存在: {action_id}"))?,
            action_id,
        ),
        "vc-x86" => replace_installer_path(
            REPAIR_VC_X86_PS,
            installer_path.ok_or_else(|| format!("安装包不存在: {action_id}"))?,
            action_id,
        ),
        "netfx48" => replace_installer_path(
            REPAIR_NETFX48_PS,
            installer_path.ok_or_else(|| format!("安装包不存在: {action_id}"))?,
            action_id,
        ),
        _ => Err(format!("未知的修复动作: {action_id}")),
    }
}

// ==================== 采集 / 安装 ====================
/// 跑一次运行库检测（超时 25s，diagOp 'runtimes.collect'），并落到本窗口快照槽。
/// 返回脚本输出的完整 data 对象（{items, summary}）。
fn run_runtimes_collect(label: &str) -> Result<Value, String> {
    // B7 S2：默认原生，TRIM_LEGACY_RUNTIMES=1 回退 PS
    let legacy = std::env::var("TRIM_LEGACY_RUNTIMES").map(|v| v == "1").unwrap_or(false);
    if !legacy {
        match crate::engine::native::runtimes_status() {
            Ok(data) => {
                if let Some(items) = data.get("items").filter(|v| v.is_array()).cloned() {
                    snapshot_store(label, items);
                }
                log::write_log("info", "运行库检测原生完成");
                return Ok(data);
            }
            Err(e) => return Err(format!("原生检测失败（设 TRIM_LEGACY_RUNTIMES=1 可回退 PS）: {e}")),
        }
    }
    let path = pwsh::write_temp_script(RUNTIMES_STATUS_PS, ".ps1")?;
    let out = pwsh::run_file(&path, Duration::from_secs(25), Some("runtimes.collect"));
    let _ = std::fs::remove_file(&path);
    let out = out?;
    if out.stdout.trim().is_empty() {
        return Err(if out.stderr.trim().is_empty() {
            "运行库检测无输出".into()
        } else {
            out.stderr.trim().to_string()
        });
    }
    // 取最后一行以 { 开头的输出（脚本可能带前置可读行）
    let line = out
        .stdout
        .trim()
        .split('\n')
        .filter(|l| l.trim().starts_with('{'))
        .last()
        .ok_or_else(|| "运行库检测结果格式异常".to_string())?
        .trim()
        .to_string();
    let data: Value = serde_json::from_str(&line).map_err(|e| format!("运行库检测解析失败: {e}"))?;
    let items = data
        .get("items")
        .filter(|v| v.is_array())
        .cloned()
        .ok_or_else(|| "运行库检测结果格式异常".to_string())?;
    if out.code != 0 {
        log::write_log("warn", &format!("运行库检测退出码 {}", out.code));
    }
    snapshot_store(label, items);
    Ok(data)
}

/// runtimes:collect — 只读采集
#[tauri::command]
pub async fn runtimes_collect<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let label = window.label().to_string();
    let result = tauri::async_runtime::spawn_blocking(move || run_runtimes_collect(&label)).await;
    Ok(match result {
        Ok(Ok(data)) => json!({ "success": true, "data": data }),
        Ok(Err(message)) => json!({ "success": false, "message": message }),
        Err(e) => json!({ "success": false, "message": format!("采集任务异常: {e}") }),
    })
}

/// 安装主体（阻塞线程内执行）
fn do_install<R: tauri::Runtime>(window: &WebviewWindow<R>, action_id: &str, label: &str) -> Value {
    emit_progress(window, json!({ "phase": "download", "percent": 0 }));

    // 下载 + 装前复核（netfx35 跳过：DISM 不消费安装包）
    let mut local_path: Option<PathBuf> = None;
    if action_id != NETFX35 {
        let meta = match installer(action_id) {
            Some(m) => m,
            None => return json!({ "success": false, "message": "未知的修复动作" }),
        };
        match download_redist(window, action_id) {
            Ok(p) => {
                // RT-1：提权执行前最后一次 SHA-256 / 尺寸复核，收敛「下载校验 → 提权执行」窗口
                match sha256_file(&p) {
                    Ok(h) if h == meta.sha256 && file_len(&p) == meta.bytes => local_path = Some(p),
                    Ok(_) => {
                        let _ = std::fs::remove_file(&p);
                        log::write_log(
                            "error",
                            &format!("运行库安装包执行前复核未通过: {action_id}（SHA-256 不符，已删除并中止）"),
                        );
                        return json!({ "success": false, "message": "安装包执行前校验未通过（SHA-256 不符），已中止" });
                    }
                    Err(e) => return json!({ "success": false, "message": format!("安装包读取失败: {e}") }),
                }
            }
            Err(e) => {
                log::write_log("error", &format!("运行库安装包下载失败: {action_id} -> {e}"));
                return json!({ "success": false, "message": e });
            }
        }
    }

    log::flush_sync(); // 危险操作前刷盘：静默安装会写入系统运行库

    let start = crate::engine::now_ms();
    emit_progress(window, json!({ "phase": "install", "percent": 100 }));

    // B7 S2：默认原生，TRIM_LEGACY_RUNTIMES=1 回退 PS
    let legacy = std::env::var("TRIM_LEGACY_RUNTIMES").map(|v| v == "1").unwrap_or(false);
    let ps_repair = || -> (bool, String) {
        let script = match build_repair_script(action_id, local_path.as_deref()) {
            Ok(s) => s,
            Err(e) => return (false, e),
        };
        let script_path = match pwsh::write_temp_script(&script, ".ps1") {
            Ok(p) => p,
            Err(e) => return (false, e),
        };
        let diag_op = format!("runtimes.install.{action_id}");
        let out = pwsh::run_file(&script_path, Duration::from_secs(600), Some(&diag_op));
        let _ = std::fs::remove_file(&script_path);
        let out = match out {
            Ok(o) => o,
            Err(e) => return (false, e),
        };
        let lines: Vec<String> = out
            .stdout
            .trim()
            .split('\n')
            .map(|l| l.trim_end_matches('\r').to_string())
            .collect();
        let result_line = lines.iter().filter(|l| l.starts_with("@@RESULT@@")).last();
        let ps_ok = result_line.map(|l| l.as_str()) == Some("@@RESULT@@ok");
        let ps_reason = if ps_ok {
            String::new()
        } else {
            lines
                .iter()
                .filter(|l| {
                    !l.is_empty() && !l.starts_with("@@RESULT@@") && !l.starts_with("@@DIAG@@")
                })
                .last()
                .cloned()
                .unwrap_or_else(|| {
                    if out.stderr.trim().is_empty() {
                        "修复未成功，请查看日志".into()
                    } else {
                        out.stderr.trim().to_string()
                    }
                })
        };
        (ps_ok, ps_reason)
    };
    let (ok, reason) = if legacy {
        ps_repair()
    } else {
        match crate::engine::native::runtimes_repair(action_id, local_path.as_deref().and_then(|p| p.to_str())) {
            Ok((success, msg)) => {
                if success {
                    (true, String::new())
                } else {
                    (false, format!("原生修复未成功（设 TRIM_LEGACY_RUNTIMES=1 可回退 PS）: {msg}"))
                }
            }
            Err(e) => (false, format!("原生修复异常（设 TRIM_LEGACY_RUNTIMES=1 可回退 PS）: {e}")),
        }
    };

    // 修复后自动重跑检测（回传最新 items/summary；N2：重跑也写回本窗口快照）
    let collect = run_runtimes_collect(label);
    let (items, summary) = match &collect {
        Ok(d) => (
            d.get("items").cloned().unwrap_or(Value::Null),
            d.get("summary").cloned().unwrap_or(Value::Null),
        ),
        Err(_) => (Value::Null, Value::Null),
    };
    let elapsed = crate::engine::now_ms() - start;
    if ok {
        log::write_log("info", &format!("运行库修复完成: {action_id}（{elapsed}ms）"));
    } else {
        log::write_log(
            "warn",
            &format!("运行库修复未成功: {action_id} -> {}", reason.chars().take(120).collect::<String>()),
        );
    }
    json!({
        "success": ok,
        "items": items,
        "summary": summary,
        "message": reason,
    })
}

/// runtimes:install — 白名单化一键安装（快照校验 + 管理员判定 + 三闸门）
#[tauri::command]
pub async fn runtimes_install<R: tauri::Runtime>(window: WebviewWindow<R>, action_id: String) -> Result<Value, String> {
    if action_id.is_empty() || action_id.len() > 40 {
        return Ok(json!({ "success": false, "message": "参数不合法" }));
    }
    if !is_allowed_action(&action_id) {
        return Ok(json!({ "success": false, "message": "未知的修复动作" }));
    }
    let label = guard::guard(&window, guard::MAIN)?;

    // 快照校验：动作必须属于本窗口最近一次检测出的待修复项（分槽，对齐 RT-4）
    if !snapshot_has_repair(&label, &action_id) {
        return Ok(json!({
            "success": false,
            "message": "该修复动作不在当前检测快照内，请先重新扫描",
        }));
    }
    // 全部安装动作需要管理员；不走静默提权，交由渲染层 elevate:request 握手
    if !sysinfo::is_admin() {
        return Ok(json!({
            "success": false,
            "needAdmin": true,
            "message": "该修复动作需要管理员权限",
        }));
    }

    let w = window.clone();
    let action = action_id.clone();
    let result =
        tauri::async_runtime::spawn_blocking(move || do_install(&w, &action, &label)).await;
    Ok(match result {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": format!("安装任务异常: {e}") }),
    })
}

// ==================== 下载闸门的真实链路验证（--ignored，发布前手动跑） ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 两道闸门都必须在**真实网络**下成立，静态自证不足：
    /// ① 非白名单主机在**落盘之前**就被拒（闸门 1a，且失败不留半成品）；
    /// ② 真实下载走完整链路——跟随重定向（aka.ms 会跳到 download.visualstudio.microsoft.com）
    ///    → **终点 host** 白名单（闸门 1b）→ content-length/流式读取 → 尺寸 + SHA-256（闸门 2）。
    ///
    /// 该用例会发一次真实请求并把约 25MB 落到系统临时目录，故默认 `#[ignore]`；
    /// 发布前门禁执行：`cargo test -- --ignored redist_gates`
    /// （对齐方案 2.3「集成测试默认 ignore，发布前作为门禁」）。
    #[test]
    #[ignore = "需要网络与约 25MB 落盘；发布前手动执行"]
    fn redist_gates_reject_and_accept() {
        // ① 闸门 1a：非白名单主机 → 拒绝且不落盘
        let bad = std::env::temp_dir().join("trim-redist-nonwhitelist.bin");
        let _ = std::fs::remove_file(&bad);
        let err = download_to("https://example.com/vc_redist.x64.exe", &bad, |_, _| {});
        assert!(err.is_err(), "非白名单主机必须被拒绝");
        assert!(!bad.exists(), "拒绝时不得留下半成品文件");

        // ② 闸门 1b + 2：真实下载 vc-x64（走重定向），校验终点白名单、尺寸与 SHA-256
        let inst = installer("vc-x64").expect("vc-x64 元数据缺失");
        let dest = std::env::temp_dir().join("trim-redist-vc-x64.exe");
        let _ = std::fs::remove_file(&dest);
        let mut last_got = 0u64;
        download_to(inst.url, &dest, |got, _| last_got = got)
            .expect("真实下载失败（网络不可用时忽略本用例）");
        assert_eq!(file_len(&dest), inst.bytes, "落盘尺寸与安装包元数据不符");
        assert_eq!(
            sha256_file(&dest).unwrap(),
            inst.sha256,
            "SHA-256 不符：闸门 2 会拒绝该包"
        );
        assert_eq!(last_got, inst.bytes, "流式累计字节与最终文件长度不一致");
        let _ = std::fs::remove_file(&dest);
    }

    /// 审查 L3：哨兵替换只吃正文，PROVENANCE 注释行必须原样保留 token；
    /// 且「缺哨兵」的判定只看正文 —— 注释行那个 token 不算数。
    #[test]
    fn 哨兵替换只作用于正文() {
        let tmpl = "# <<<PROVENANCE\n\
# 来源：x.js → repair(\"netfx48\", \"@@TRIM_INSTALLER_PATH@@\")\n\
# PROVENANCE>>>\n\
$p = '@@TRIM_INSTALLER_PATH@@'\n";
        // 拿一个必然存在的文件当"安装包"
        let me = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let out = replace_installer_path(tmpl, &me, "netfx48").expect("替换失败");
        let head = out.split_once("# PROVENANCE>>>").unwrap().0;
        assert!(
            head.contains(RUNTIMES_PATH_SENTINEL),
            "来源注释行里的 token 被替换掉了 ⇒ 来源记录失真"
        );
        let body = out.split_once("# PROVENANCE>>>").unwrap().1;
        assert!(!body.contains(RUNTIMES_PATH_SENTINEL), "正文里哨兵未替换");
        assert!(body.contains("Cargo.toml"), "正文未写入真实路径");

        // 只有注释行带 token、正文没有 ⇒ 必须判"缺哨兵"而不是放行
        let only_in_head = "# <<<PROVENANCE\n# 说明\n\
# PROVENANCE>>>\nWrite-Output 'no sentinel here'\n";
        assert!(
            replace_installer_path(only_in_head, &me, "netfx48").is_err(),
            "注释行里的 token 不得充当哨兵"
        );
    }
}