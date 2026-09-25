//! realtime 域（批次 A）：实时网速监控 7 条通道
//!
//! 关键设计（对照 main.js 5796-6087，逐条复刻）：
//! - **常驻流式采样器**：旧实现每 1.5s 拉起一个 pwsh（冷启动 ~1.2s + 采样窗 900ms）
//!   导致进程重叠、图表断续。改为单个常驻 pwsh 每秒输出一行 JSON，命令直接返回缓存
//!   （毫秒级），渲染层曲线平滑连续。
//! - **空闲自动回收**：连续 30s 无采样请求即结束常驻进程（离开测速页不占资源）。
//! - `realtime:sample` 首个基线窗口内暂无差值数据 → 返回**空列表而非失败**，
//!   让渲染层继续等待而不是弹错。
//! - 报告落盘前做 schema 校验（SP-2）：拒绝非网速报告结构污染缓存；样本数上限 1e6 防爆盘。
//! - 报告目录 `cache/realtime-reports`，超过 7 天自动清理。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tauri::WebviewWindow;

use crate::engine::{guard, log, native, paths};
use crate::pwsh;
use crate::security;

/// PS 脚本编译期嵌入（生成自源仓库，见 tools/sync-ps-from-js.mjs）
const ADAPTERS_PS: &str = include_str!("../../ps/realtime_adapters.ps1");
const LOSS_PS: &str = include_str!("../../ps/realtime_loss.ps1");
// realtime_stream.ps1 已退役（B0 S3）：Tauri 侧全程使用进程内 NetSampler，
// 不再起常驻 pwsh；.ps1 文件与 ps-mapping 条目均已删除。

/// 空闲回收阈值：连续 30s 无采样请求即停采样线程
const IDLE_STOP_MS: i64 = 30_000;
const IDLE_TICK_MS: u64 = 10_000;
/// 采样间隔（对齐 Electron 原生 `net-sample --daemon --interval 1000`）
const SAMPLE_INTERVAL_MS: u64 = 1000;
/// 报告保留 7 天
const REPORT_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// 报告样本数上限（超长记录防爆盘）
const REPORT_MAX_SAMPLES: usize = 1_000_000;

struct Sampler {
    stop: Option<Arc<AtomicBool>>,
    last_request_at: i64,
    reaper_started: bool,
}

static SAMPLER: Mutex<Option<Sampler>> = Mutex::new(None);
/// 采样器最近一帧（{ t, adapters:[{name,up,down,ifIndex}] }）
static LATEST: Mutex<Option<Value>> = Mutex::new(None);

fn with_sampler<T>(f: impl FnOnce(&mut Sampler) -> T) -> T {
    let mut guard = SAMPLER.lock().unwrap_or_else(|e| e.into_inner());
    let s = guard.get_or_insert(Sampler {
        stop: None,
        last_request_at: 0,
        reaper_started: false,
    });
    f(s)
}

/// 启动（或复用）进程内采样线程
fn ensure_sampler() {
    let now = crate::engine::now_ms();
    with_sampler(|s| {
        s.last_request_at = now;
        if s.stop.is_some() {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        std::thread::spawn(move || {
            // 线程内持有 NetSampler（首拍无基线 → 返回 None，上层据此返回空列表）
            let mut sampler = trim_finder::perf::NetSampler::new();
            while !flag.load(Ordering::Relaxed) {
                match sampler.sample_frame() {
                    Some(line) => {
                        if let Ok(v) = serde_json::from_str::<Value>(&line) {
                            *LATEST.lock().unwrap_or_else(|e| e.into_inner()) = Some(v);
                        }
                    }
                    None => {} // 首拍 / 当前无符合条件的物理网卡
                }
                // 切成小步睡眠，保证 stop 请求能被及时响应（≤100ms 退出）
                for _ in 0..(SAMPLE_INTERVAL_MS / 100) {
                    if flag.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
        s.stop = Some(stop);
        log::write_log("info", "实时网速采样器启动（进程内 NetSampler，原生 GetIfTable2）");
    });
    start_reaper_once();
}

/// 空闲回收线程（进程内只启动一次）
fn start_reaper_once() {
    let first = with_sampler(|s| {
        if s.reaper_started {
            return false;
        }
        s.reaper_started = true;
        true
    });
    if !first {
        return;
    }
    std::thread::spawn(|| loop {
        std::thread::sleep(Duration::from_millis(IDLE_TICK_MS));
        let idle = with_sampler(|s| {
            s.stop.is_some() && crate::engine::now_ms() - s.last_request_at > IDLE_STOP_MS
        });
        if idle {
            stop_sampler("空闲回收");
        }
    });
}

fn stop_sampler(cause: &str) {
    let stopped = with_sampler(|s| match s.stop.take() {
        Some(flag) => {
            flag.store(true, Ordering::Relaxed);
            true
        }
        None => false,
    });
    *LATEST.lock().unwrap_or_else(|e| e.into_inner()) = None;
    if stopped {
        log::write_log("info", &format!("实时网速采样器已停止（{cause}）"));
    }
}

/// 供应用退出时清理（lib.rs 的 `on_app_exit` 是唯一退出钩子，覆盖窗口关闭/关机/异常三条路径）
///
/// 审查 v2-L13：顺带在这里回收过期报告 —— 报告 TTL 此前只有 save/list 两个触发点，
/// 用户不再打开网速页就永不触发；挂在退出路径上保证「每次运行至少回收一次」，
/// 且不需要动 lib.rs。启动钩子（覆盖崩溃/被杀进程那一半）见交付说明的越界需求。
pub fn shutdown_sampler() {
    stop_sampler("应用退出");
    prune_reports();
}

fn ps_json(script: &'static str, timeout_secs: u64, op: &str) -> Result<Value, String> {
    // 审查 v2-L2：脚本由 `TempScript` 守卫持有，出作用域即删。
    // 旧姿势是「run_file 后手写 remove_file」，而本函数在 remove_file 之后还有三处早退
    // （`out?` / TIMEOUT / code!=0），任一命中都靠启动期 1h 兜底才收得回来。
    let path = pwsh::write_temp_script(script, ".ps1")?;
    let out = pwsh::run_file(path.path(), Duration::from_secs(timeout_secs), Some(op))?;
    if out.timed_out {
        return Err("TIMEOUT".into());
    }
    if out.code != 0 {
        return Err(out.stderr.trim().to_string());
    }
    serde_json::from_str(out.stdout.trim()).map_err(|e| format!("解析结果失败: {e}"))
}

/// realtime:adapters — 枚举物理网卡
///
/// B1 S2：默认只走 Rust 原生；设 `TRIM_LEGACY_REALTIME=1` 可回退 PS（隐藏诊断开关）。
#[tauri::command]
pub async fn realtime_adapters<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let legacy = std::env::var("TRIM_LEGACY_REALTIME").map(|v| v == "1").unwrap_or(false);
    if legacy {
        let r = tauri::async_runtime::spawn_blocking(|| ps_json(ADAPTERS_PS, 10, "realtime:adapters")).await;
        return Ok(match r {
            Ok(Ok(v)) => v,
            Ok(Err(e)) if e == "TIMEOUT" => serde_json::json!({ "success": false, "message": "网卡枚举超时，请重试" }),
            Ok(Err(e)) => serde_json::json!({ "success": false, "message": if e.is_empty() { "网卡枚举失败" } else { &e } }),
            Err(e) => serde_json::json!({ "success": false, "message": format!("枚举任务异常: {e}") }),
        });
    }
    match tauri::async_runtime::spawn_blocking(native::realtime_adapters).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Ok(serde_json::json!({ "success": false, "message": format!("原生枚举失败（设 TRIM_LEGACY_REALTIME=1 可回退 PS）: {e}") })),
        Err(e) => Ok(serde_json::json!({ "success": false, "message": format!("枚举任务异常: {e}") })),
    }
}

/// realtime:sample — 返回常驻采样器缓存（首个基线窗口返回空列表，不报错）
#[tauri::command]
pub fn realtime_sample<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    ensure_sampler();
    if let Some(frame) = LATEST.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return Ok(serde_json::json!({
            "success": true,
            "adapters": frame.get("adapters").cloned().unwrap_or(Value::Array(vec![])),
            "t": frame.get("t").cloned().unwrap_or(Value::Null),
        }));
    }
    let alive = with_sampler(|s| s.stop.is_some());
    if alive {
        Ok(serde_json::json!({ "success": true, "adapters": [] }))
    } else {
        Ok(serde_json::json!({ "success": false, "message": "流量采样进程未就绪" }))
    }
}

/// realtime:loss — 丢包检测（ping 默认网关）
///
/// B1 S2：默认只走 Rust 原生；设 `TRIM_LEGACY_REALTIME=1` 可回退 PS（隐藏诊断开关）。
#[tauri::command]
pub async fn realtime_loss<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let legacy = std::env::var("TRIM_LEGACY_REALTIME").map(|v| v == "1").unwrap_or(false);
    if legacy {
        let r = tauri::async_runtime::spawn_blocking(|| ps_json(LOSS_PS, 10, "realtime:loss")).await;
        return Ok(match r {
            Ok(Ok(v)) => v,
            Ok(Err(e)) if e == "TIMEOUT" => serde_json::json!({ "success": false, "message": "丢包检测超时" }),
            Ok(Err(_)) => serde_json::json!({ "success": false, "message": "丢包检测失败" }),
            Err(e) => serde_json::json!({ "success": false, "message": format!("检测任务异常: {e}") }),
        });
    }
    match tauri::async_runtime::spawn_blocking(native::realtime_loss).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Ok(serde_json::json!({ "success": false, "message": format!("原生检测失败（设 TRIM_LEGACY_REALTIME=1 可回退 PS）: {e}") })),
        Err(e) => Ok(serde_json::json!({ "success": false, "message": format!("检测任务异常: {e}") })),
    }
}

// ==================== 记录报告 ====================

fn ensure_report_dir() -> Result<std::path::PathBuf, String> {
    let dir = paths::realtime_report_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

/// 清理超过 7 天的旧报告（保存/列出时都会调用）。
///
/// 审查 v2-L13：只有这两处触发 ⇒ 用户此后不再打开网速页，`cache/realtime-reports`
/// 里的过期报告就永远回收不掉（TTL 承诺写在文件头与 readme 里）。判据抽成
/// `report_expired` 纯函数，并挂到进程生命周期两端：
/// - 退出：`shutdown_sampler`（lib.rs 的 `on_app_exit` 已接线，本文件内可改）
/// - 启动：`prune_reports` 已 `pub`，接一行调用属 lib.rs（越界，见交付说明）
pub fn prune_reports() {
    let Ok(dir) = ensure_report_dir() else { return };
    prune_reports_in(&dir, crate::engine::now_ms(), REPORT_TTL_MS);
}

/// 执行体（不读全局目录、不写日志）：便于在一次性沙箱里断言真实删除行为。
fn prune_reports_in(dir: &std::path::Path, now_ms: i64, ttl_ms: i64) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let mtime = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64);
        if report_expired(mtime, now_ms, ttl_ms)
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// 报告龄期判定（纯函数，便于断言）。
/// `mtime` 取不到时按「不过期」处理：误删用户的报告比留一个文件代价高。
fn report_expired(mtime_ms: Option<i64>, now_ms: i64, ttl_ms: i64) -> bool {
    match mtime_ms {
        Some(m) => now_ms - m > ttl_ms,
        None => false,
    }
}

/// SP-2：报告 schema 校验，拒绝非网速报告结构
fn validate_report(data: &Value) -> Result<(), String> {
    let obj = data
        .as_object()
        .ok_or_else(|| "报告必须是对象".to_string())?;
    for k in [
        "durationSec",
        "maxDown",
        "maxUp",
        "minDown",
        "minUp",
        "avgDown",
        "avgUp",
    ] {
        let v = obj.get(k).and_then(|v| v.as_f64());
        match v {
            Some(n) if n.is_finite() && n >= 0.0 => {}
            _ => return Err(format!("字段 {k} 非法")),
        }
    }
    match obj.get("createdAt").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => {}
        _ => return Err("createdAt 非法".into()),
    }
    let samples = obj
        .get("samples")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "samples 非法".to_string())?;
    if samples.len() > REPORT_MAX_SAMPLES {
        return Err("样本过多（超出上限）".into());
    }
    for s in samples.iter().take(REPORT_MAX_SAMPLES) {
        let so = s.as_object().ok_or_else(|| "样本字段非法".to_string())?;
        for k in ["t", "down", "up"] {
            match so.get(k).and_then(|v| v.as_f64()) {
                Some(n) if n.is_finite() => {}
                _ => return Err("样本字段非法".into()),
            }
        }
    }
    Ok(())
}

/// realtime:report-save
#[tauri::command]
pub fn realtime_report_save<R: tauri::Runtime>(window: WebviewWindow<R>, data: Value) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Err(why) = validate_report(&data) {
        log::write_log(
            "warn",
            &format!("拒绝保存网速报告（schema 校验失败）: {why}"),
        );
        return Ok(serde_json::json!({
            "success": false,
            "message": format!("报告数据非法，未保存（{why}）"),
        }));
    }
    let dir = ensure_report_dir()?;
    prune_reports();
    let name = format!("realtime-{}.json", crate::engine::now_ms());
    match security::atomic_write_json(&dir.join(&name), &data) {
        Ok(()) => Ok(serde_json::json!({ "success": true, "name": name })),
        Err(e) => {
            log::write_log("error", &format!("保存网速报告失败: {e}"));
            Ok(serde_json::json!({ "success": false, "message": e }))
        }
    }
}

/// realtime:report-list（按 createdAt 倒序）
#[tauri::command]
pub fn realtime_report_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    prune_reports();
    let dir = paths::realtime_report_dir();
    let mut out: Vec<Value> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let Ok(d) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            out.push(serde_json::json!({
                "name": name,
                "createdAt": d.get("createdAt").cloned().unwrap_or(Value::Null),
                "durationSec": d.get("durationSec").cloned().unwrap_or(Value::Null),
                "maxDown": d.get("maxDown").cloned().unwrap_or(Value::Null),
                "maxUp": d.get("maxUp").cloned().unwrap_or(Value::Null),
                "minDown": d.get("minDown").cloned().unwrap_or(Value::Null),
                "minUp": d.get("minUp").cloned().unwrap_or(Value::Null),
                "avgDown": d.get("avgDown").cloned().unwrap_or(Value::Null),
                "avgUp": d.get("avgUp").cloned().unwrap_or(Value::Null),
                "samples": d.get("samples").cloned().unwrap_or(Value::Array(vec![])),
                "adapter": d.get("adapter").cloned().unwrap_or_else(|| serde_json::json!("")),
            }));
        }
    }
    out.sort_by(|a, b| {
        let sa = a.get("createdAt").and_then(|v| v.as_str()).unwrap_or("");
        let sb = b.get("createdAt").and_then(|v| v.as_str()).unwrap_or("");
        sb.cmp(sa)
    });
    Ok(serde_json::json!({ "success": true, "reports": out }))
}

/// realtime:report-delete（basename 化，防路径穿越）
#[tauri::command]
pub fn realtime_report_delete<R: tauri::Runtime>(window: WebviewWindow<R>, name: String) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let base = std::path::Path::new(&name)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let fp = paths::realtime_report_dir().join(base);
    if fp.is_file() {
        let _ = std::fs::remove_file(&fp);
    }
    Ok(serde_json::json!({ "success": true }))
}

/// realtime:report-clear
#[tauri::command]
pub fn realtime_report_clear<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let dir = ensure_report_dir()?;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    Ok(serde_json::json!({ "success": true }))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 一次性沙箱：唯一命名 + 结束自删（不得碰真实数据目录）
    fn sandbox(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trim-realtime-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn put(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"{}").unwrap();
        p
    }

    #[test]
    fn 报告龄期判定取不到时间戳时不过期() {
        let ttl = 7 * 24 * 60 * 60 * 1000;
        assert!(report_expired(Some(0), ttl * 3, ttl));
        assert!(!report_expired(Some(ttl * 3 - 1000), ttl * 3, ttl));
        assert!(
            !report_expired(None, ttl * 3, ttl),
            "mtime 取不到按不过期处理：误删报告比留一个文件代价高"
        );
    }

    /// 审查 v2-L13：TTL 回收必须真的动文件（旧实现只在 save/list 两个入口被动触发）
    #[test]
    fn 过期报告被回收而新鲜件与非报告件不动() {
        let dir = sandbox("reports");
        let old = put(&dir, "realtime-old.json");
        let fresh = put(&dir, "realtime-fresh.json");
        let other = put(&dir, "keep.txt");
        // 把 old 的时间戳推到 2020-01-01（沙箱内文件）
        let f = std::fs::OpenOptions::new().write(true).open(&old).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_577_836_800))
            .unwrap();
        drop(f);
        let removed = prune_reports_in(&dir, crate::engine::now_ms(), REPORT_TTL_MS);
        assert_eq!(removed, 1);
        assert!(!old.exists(), "超过 7 天的报告必须被回收");
        assert!(fresh.exists() && other.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
