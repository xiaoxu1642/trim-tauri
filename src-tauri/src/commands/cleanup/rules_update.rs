//! 规则在线更新：HTTP/Git 双通道、远端校验与更新落地（传输层已接 engine::winhttp）。
//!
//! 传输层只认 `https://`（拒非 https 源并逐条落日志），发布源清单的唯一拼装口是
//! `release_source_urls_for`——与残留规则库共用同一份，避免两本账漂移。
//! 远端包必须过与装载侧同一个 `validate_cleanup_package` 才落盘。

use crate::security;
use crate::engine::{guard, log, paths, rules_signature, winhttp};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;
use tauri::Emitter;
use tauri::WebviewWindow;
use super::rules::*;
use super::state::*;
// ==================== 规则在线更新（HTTP 传输层已接入 engine::winhttp） ====================

/// 从覆盖配置的 `urls` 里挑出 https 源，返回 `(接受, 被拒)`（审查 v2-L4）
///
/// 自定义源此前 `http://` 与 `https://` 一并接受。内容虽有 ed25519 验签兜底（篡改过不了签），
/// 但明文 HTTP 还会把自定义请求头（可能含 Authorization / 私有镜像 token）暴露在链路上，
/// 且中间人可以整段替换响应做成「全部源失败」的拒绝服务。纵深原则：传输层只认 https。
/// 被拒的源由调用方逐条写日志——不让用户以为「配了但没生效」却无从发现。
/// 拆成纯函数是为了可测：判定面（哪些留下、哪些被拒）不依赖数据目录与磁盘。
pub(crate) fn pick_https_urls(cfg: &Value) -> (Vec<String>, Vec<String>) {
    let mut accepted: Vec<String> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();
    let Some(arr) = cfg.get("urls").and_then(|v| v.as_array()) else {
        return (accepted, rejected);
    };
    for u in arr.iter().filter_map(|v| v.as_str()) {
        if u.to_ascii_lowercase().starts_with("https://") {
            if accepted.len() < 10 {
                accepted.push(u.to_string());
            }
        } else {
            rejected.push(u.to_string());
        }
    }
    (accepted, rejected)
}

/// 更新源覆盖配置（对照 loadRulesUpdateOverride）：读指定文件，只认 https 源，
/// 附带可选的 `headers`（私有源鉴权由用户自配）。清理库与残留库共用这套 schema，
/// 差别只在**读哪个文件**（决策清单 D6 定为各一份，避免动清理域的读侧语义）。
pub(crate) fn load_update_override(file: &Path) -> Option<(Vec<String>, Vec<(String, String)>)> {
    let text = std::fs::read_to_string(file).ok()?;
    let cfg: Value = serde_json::from_str(&text).ok()?;
    if !cfg.is_object() {
        return None;
    }
    let (urls, rejected) = pick_https_urls(&cfg);
    for u in rejected {
        log::write_log(
            "warn",
            &format!("规则库自定义源不是 https，已拒绝使用: {u}"),
        );
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(obj) = cfg.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if k.chars().count() <= 128 {
                if let Some(s) = v.as_str() {
                    if s.chars().count() <= 1024 {
                        headers.push((k.clone(), s.to_string()));
                    }
                }
            }
        }
    }
    Some((urls, headers))
}

/// 清理库的用户覆盖源（各库一份文件，决策清单 D6：不动清理域读侧语义、也不给残留库
/// 复用同一个文件——两个同名文件不同 schema 比两个文件名更糟）
pub(crate) fn load_rules_update_override() -> Option<(Vec<String>, Vec<(String, String)>)> {
    load_update_override(&paths::data_file_for_read("cleanup/update-source.json"))
}

/// 源清单装配：用户覆盖源在前（共用同一份 headers），内置发布源在后，总数截到 16。
/// 清理与残留两库共用本函数，差别只在传入的内置 URL 列表——清单本身不复制第二份。
pub(crate) fn assemble_sources(
    override_cfg: Option<(Vec<String>, Vec<(String, String)>)>,
    base_urls: &[String],
) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    if let Some((urls, headers)) = override_cfg.as_ref() {
        for u in urls {
            out.push((u.clone(), headers.clone()));
        }
    }
    let headers = override_cfg.map(|(_, h)| h).unwrap_or_default();
    for url in base_urls {
        out.push((url.clone(), headers.clone()));
    }
    out.truncate(16);
    out
}

/// 更新源清单（update / check-version 共用；对照 buildRulesSources）
pub(super) fn build_rules_sources() -> Vec<(String, Vec<(String, String)>)> {
    assemble_sources(
        load_rules_update_override(),
        &RULES_UPDATE_URLS.map(String::from),
    )
}

/// HTTP 传输层（复用 `engine::winhttp`，与 runtimes 安装包下载共用同一实现）。
///
/// 规则库更新源可由用户在数据目录 `update-source.json` 覆盖（**用户自选源**），
/// 故此处 `allow_host = None`——**不套宿主白名单**；这条链路的安全性由 `validate_remote_rules`
/// 的 **ed25519 验签 + JSON 结构校验 + 条目形状 + 版本防降级**兜底
/// （传输可去任意源，但内容必须凭内置公钥签名通过才算数）。
/// 尺寸上限 RULES_MAX_SIZE 经 `max_bytes` 传入：content-length 声明值或流式累计超限均中止
/// （先拦超大响应再解析，防 OOM）；全程在内存完成，任何失败都不落盘。
pub(super) fn http_get(
    url: &str,
    headers: &[(String, String)],
    timeout: Duration,
    on_progress: Option<&dyn Fn(f64)>,
) -> Result<String, String> {
    http_get_limited(url, headers, timeout, RULES_MAX_SIZE, on_progress)
}

/// 同上，但**尺寸上限由调用方给**：清理库（2 MiB）与残留规则库（几百 KB）量级不同，
/// 共用一个上限会让残留库要么被清理库的宽松值放过、要么被它的严格值误拒。
/// 传输层实现仍然只有这一处（`engine::winhttp`），不重写第二份。
pub(crate) fn http_get_limited(
    url: &str,
    headers: &[(String, String)],
    timeout: Duration,
    max_bytes: usize,
    on_progress: Option<&dyn Fn(f64)>,
) -> Result<String, String> {
    // 进度：按「已收字节 / 声明总长」折算为 0..99（100 由更新/落盘成功时另行表达）；
    // 总长未知则不打点（不误报进度），且单调不倒退。
    let mut last = -1.0f64;
    let mut cb = |got: u64, total: u64| {
        let Some(report) = on_progress else {
            return;
        };
        if total == 0 {
            return;
        }
        let pct = ((got as f64 / total as f64) * 100.0).min(99.0);
        if pct > last {
            last = pct;
            report(pct);
        }
    };
    winhttp::get_text(url, headers, timeout, max_bytes as u64, None, &mut cb)
}

/// 内容校验器（对照 makeRulesValidator：尺寸 → 验签 → JSON 结构 → 条目形状 → 版本防降级）
pub(super) fn validate_remote_rules(text: &str, current_version: f64) -> Result<(f64, String), String> {
    let len = text.chars().count();
    if len < RULES_MIN_SIZE {
        return Err("内容过小，疑似异常响应".to_string());
    }
    if len > RULES_MAX_SIZE {
        return Err("内容过大，疑似异常响应".to_string());
    }
    rules_signature::verify_rules_text(text)?;
    let parsed: Value = serde_json::from_str(text).map_err(|_| "JSON 解析失败".to_string())?;
    // 更新链必须调用**装载侧同一个**语义校验器：另写一套字段规则就会「更新放行、装载拒绝」，
    // 两边都觉得自己对（残留域 E4b 同一断言，本域此前只查 id/name 是否存在）
    validate_cleanup_package(&parsed)?;
    let version = js_num_or_zero(parsed.get("rulesVersion"));
    if version < current_version {
        return Err(format!(
            "下载版本({})低于当前版本({})，已拒绝（防降级）",
            js_num_str(version),
            js_num_str(current_version)
        ));
    }
    Ok((version, text.to_string()))
}

pub(super) struct FetchResult {
    ok: bool,
    text: String,
    version: f64,
    source: String,
    error: String,
}

/// git 回退（开发机）：经本机凭据深拉远程 main 取规则文件；不可用返回 None
pub(super) fn git_fetch_rules_file() -> Option<String> {
    // Electron 用 __dirname（dev = 仓库根）；Tauri 用 current_exe() 目录——
    // 常规开发/打包布局下无 .git，与 Electron「打包后自然跳过」同语义
    let repo_dir = paths::exe_dir();
    if !repo_dir.join(".git").exists() {
        return None;
    }
    let cwd = repo_dir.to_string_lossy().to_string();
    if run_git(&cwd, &["fetch", "--depth=1", "origin", "main"], 60).is_none() {
        return None;
    }
    // 仓库内实际路径是 `src-tauri/data/cleanup-rules.json`（Electron 时代才是 src/data）；
    // 写错路径时 git show 直接失败，回退链静默不生效（方案 D6）。
    run_git(
        &cwd,
        &["show", "FETCH_HEAD:src-tauri/data/cleanup-rules.json"],
        15,
    )
}

/// 带超时的 git 调用（对照 exec 的 timeout；超时 kill 并返回 None）
pub(super) fn run_git(cwd: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    use std::process::Stdio;
    // v0.1.6 真机修复：git 也在后台静默跑（规则库更新不该闪控制台窗）
    let mut child = crate::engine::systembin::quiet_cmd("git")
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
    let out = child.wait_with_output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// 拉取远端规则文本（含 git 回退）；on_progress 可选（0..99）
pub(super) fn fetch_remote_rules_text(
    current_version: f64,
    on_progress: Option<&dyn Fn(f64)>,
) -> FetchResult {
    let mut seen: HashSet<String> = HashSet::new();
    let mut last_error = String::new();
    for (url, headers) in build_rules_sources() {
        if url.is_empty() || !seen.insert(url.clone()) {
            continue;
        }
        match http_get(
            &url,
            &headers,
            Duration::from_millis(RULES_DOWNLOAD_TIMEOUT_MS),
            on_progress,
        ) {
            Err(e) => last_error = e,
            Ok(text) => {
                match validate_remote_rules(&text, current_version) {
                    Ok((version, text)) => {
                        return FetchResult {
                            ok: true,
                            text,
                            version,
                            source: url,
                            error: String::new(),
                        }
                    }
                    Err(e) => last_error = e,
                }
            }
        }
    }
    // git 回退：HTTP 全部失败时，开发机经本机凭据拉取远程
    if let Some(git_text) = git_fetch_rules_file() {
        match validate_remote_rules(&git_text, current_version) {
            Ok((version, text)) => {
                return FetchResult {
                    ok: true,
                    text,
                    version,
                    source: "git:origin/main".to_string(),
                    error: String::new(),
                }
            }
            Err(e) => {
                return FetchResult {
                    ok: false,
                    text: String::new(),
                    version: 0.0,
                    source: "git".to_string(),
                    error: format!("{e}（本机 git 已取到远程规则）"),
                }
            }
        }
    }
    FetchResult {
        ok: false,
        text: String::new(),
        version: 0.0,
        source: String::new(),
        error: last_error,
    }
}

/// cleanup:update-rules — 拉取 → 校验 → 原子落盘 → 抬升防回滚水位线
#[tauri::command]
pub async fn cleanup_update_rules<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let rules = rules_value().unwrap_or_else(|_| json!({}));
    let current_version = js_num_or_zero(rules.get("rulesVersion")).max(rules_watermark());
    let _ = window.emit("cleanup:rules-download-progress", json!({ "percent": 0 }));
    let win = window.clone();
    let task = tauri::async_runtime::spawn_blocking(move || {
        let progress = |pct: f64| {
            let _ = win.emit("cleanup:rules-download-progress", json!({ "percent": pct }));
        };
        fetch_remote_rules_text(current_version, Some(&progress))
    });
    let result = match task.await {
        Ok(r) => r,
        Err(e) => return json!({ "success": false, "message": e.to_string() }),
    };
    if !result.ok {
        let revertible = result.error.contains("版本") || result.error.contains("防降级");
        let hint = if paths::exe_dir().join(".git").exists() {
            if revertible {
                "（远程规则版本未更新或低于本地，请先在源仓库发布新规则）"
            } else {
                "（已尝试本机 git 回退仍失败，请检查网络或远程分支）"
            }
        } else {
            "（HTTP 发布源不可达；私有仓库请先公开仓库，或在数据目录 update-source.json 配置可访问源）"
        };
        log::write_log("warn", &format!("清理规则库更新失败: {}", result.error));
        return json!({
            "success": false,
            "message": format!("所有发布源均不可用或校验未通过：{}{hint}", result.error)
        });
    }
    let dir = data_rules_write_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return json!({ "success": false, "message": format!("写入规则失败: {e}") });
    }
    // 审查 M10：改走 `security::atomic_write_file`。原来的 `fs::write` + `fs::rename`
    // 缺 `sync_all` —— 断电/蓝屏时 rename 可能先落、内容后落，规则文件会变成 0 字节或半截；
    // 用字节级入口（不是 atomic_write_json）是刻意的：重新序列化 JSON 会改动键序/空白，
    // 而 `_sig` 是对**原文本**签的，一旦重排就把合法规则变成验签失败。
    let target = data_rules_write_file();
    if let Err(e) = security::atomic_write_file(&target, result.text.as_bytes()) {
        return json!({ "success": false, "message": format!("写入规则失败: {e}") });
    }
    // 落盘成功即抬升水位线（只升不降）；写失败不阻断本次更新，读取侧仍有验签兜底
    set_rules_watermark(result.version);
    log::write_log(
        "info",
        &format!("清理规则库已更新: rulesVersion={}", js_num_str(result.version)),
    );
    let winapp2_version = serde_json::from_str::<Value>(&result.text)
        .ok()
        .and_then(|v| v.get("winapp2Version").cloned())
        .unwrap_or(Value::Null);
    json!({
        "success": true,
        "rulesVersion": result.version,
        "winapp2Version": winapp2_version,
        "source": result.source
    })
}

/// cleanup:check-rules-version — 轻量只读版本检测（拉远端验签后只读版本号，不写盘）
#[tauri::command]
pub async fn cleanup_check_rules_version<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let rules = rules_value().unwrap_or_else(|_| json!({}));
    let current_version = js_num_or_zero(rules.get("rulesVersion")).max(rules_watermark());
    let current_winapp2 = match rules.get("winapp2Version") {
        Some(v) if !v.is_null() => v.clone(),
        _ => Value::Null,
    };
    let task = tauri::async_runtime::spawn_blocking(move || fetch_remote_rules_text(current_version, None));
    let result = match task.await {
        Ok(r) => r,
        Err(e) => return json!({ "success": false, "message": e.to_string() }),
    };
    if !result.ok {
        let msg = if result.error.is_empty() {
            "检测失败".to_string()
        } else {
            result.error
        };
        return json!({
            "success": false,
            "currentVersion": current_version,
            "currentWinapp2Version": current_winapp2,
            "message": msg
        });
    }
    let remote_winapp2 = serde_json::from_str::<Value>(&result.text)
        .ok()
        .and_then(|v| v.get("winapp2Version").cloned())
        .unwrap_or(Value::Null);
    json!({
        "success": true,
        "currentVersion": current_version,
        "currentWinapp2Version": current_winapp2,
        "remoteVersion": result.version,
        "remoteWinapp2Version": remote_winapp2,
        "hasUpdate": result.version > current_version,
        "source": result.source
    })
}

