//! realtime 域（批次 A）：实时网速监控 7 条通道
//!
//! 关键设计（对照 main.js 5796-6087，逐条复刻）：
//! - **进程内常驻采样线程**：Electron 时代每 1.5s 拉起一个 pwsh（冷启动 ~1.2s + 采样窗
//!   900ms）导致进程重叠、图表断续，曾以「单个常驻 pwsh」过渡；Tauri 侧为**进程内采样
//!   线程**（无任何 pwsh 子进程），命令直接返回缓存（毫秒级），渲染层曲线平滑连续。
//!   旧注释「常驻 pwsh」为过渡期遗物（2026-09-25 审计修正）。
//! - **空闲自动回收**：连续 30s 无采样请求即停采样线程（离开测速页不占资源）。
//! - `realtime:sample` 首个基线窗口内暂无差值数据 → 返回**空列表而非失败**，
//!   让渲染层继续等待而不是弹错。
//! - 报告落盘前做 schema 校验（SP-2）：拒绝非网速报告结构污染缓存；样本数上限 1e6 防爆盘。
//! - 报告目录 `cache/realtime-reports`，超过 7 天自动清理。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tauri::WebviewWindow;

use crate::engine::{guard, log, native, paths};
use crate::security;

/// 空闲回收阈值：连续 30s 无采样请求即停采样线程
const IDLE_STOP_MS: i64 = 30_000;
const IDLE_TICK_MS: u64 = 10_000;
/// 采样间隔（对齐 Electron 原生 `net-sample --daemon --interval 1000`）
const SAMPLE_INTERVAL_MS: u64 = 1000;
/// 报告保留 7 天
const REPORT_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// 报告样本数上限（超长记录防爆盘）
const REPORT_MAX_SAMPLES: usize = 1_000_000;
/// 单份报告可读上限（v7.2 `R1d-M06`）。
/// 为什么是 8 MB：样本行是 `{t,down,up}` 三个数字，pretty JSON 下一条约 60 字节，
/// 8 MB ≈ 13 万条 ≈ 36 小时连续采样——覆盖「挂机一整夜」的真实用法；
/// 而 `REPORT_MAX_SAMPLES`（1e6）只是防爆盘的远端上限，不能作为「读得动」的依据。
const REPORT_READ_MAX_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) struct Sampler {
    stop: Option<Arc<AtomicBool>>,
    last_request_at: i64,
    reaper_started: bool,
}

use crate::commands::state::{LATEST, SAMPLER};

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
        stop_sampler_if_idle(crate::engine::now_ms());
    });
}

/// 空闲停机判据（纯函数，单测钉住边界）：只有「采样器存在」且「确实超过空闲阈值」才停。
fn idle_stop_needed(stop_present: bool, last_request_at: i64, now: i64) -> bool {
    stop_present && now - last_request_at > IDLE_STOP_MS
}

fn stop_sampler_if_idle(now: i64) -> bool {
    // R1d-M14：判空闲与停机必须在**同一把锁**里复查；旧实现先判后停，两步之间的
    // 采样请求会被刚发起的回收打断。
    let stopped = with_sampler(|s| {
        if !idle_stop_needed(s.stop.is_some(), s.last_request_at, now) {
            return false;
        }
        match s.stop.take() {
            Some(flag) => {
                flag.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    });
    if stopped {
        *LATEST.lock().unwrap_or_else(|e| e.into_inner()) = None;
        log::write_log("info", "实时网速采样器已停止（空闲回收）");
    }
    stopped
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

/// realtime:adapters — 枚举物理网卡
///
/// S3：纯 Rust 原生，无 PS 回退。
#[tauri::command]
pub async fn realtime_adapters<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    match tauri::async_runtime::spawn_blocking(native::realtime_adapters).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Ok(serde_json::json!({ "success": false, "message": format!("原生枚举失败: {e}") })),
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
        // R1d-M14：采样器被显式停机（退出/其它入口）后，本拍重启并按首拍空列表返回，
        // 不再产出 success:false —— 前端会据此弹「采集失败」，而事实只是首拍没数据。
        ensure_sampler();
        Ok(serde_json::json!({ "success": true, "adapters": [] }))
    }
}

/// realtime:loss — 丢包检测（ping 默认网关）
///
/// S3：纯 Rust 原生，无 PS 回退。
#[tauri::command]
pub async fn realtime_loss<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    match tauri::async_runtime::spawn_blocking(native::realtime_loss).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Ok(serde_json::json!({ "success": false, "message": format!("原生检测失败: {e}") })),
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
/// - 启动：审查 v3-L3 已在 lib.rs 的 `setup` 接线（此前注释写「越界未接」，
///   导致只有打开网速页的用户才享受得到 TTL 回收）
/// 回收过期报告，返回**真的删掉了多少份**（v7.2 `R1d-L07`：调用方要把这个数回执给用户，
/// 不能再让它消失在 `()` 里——用户点「查看列表」时被动删掉的是他自己存的历史）。
pub fn prune_reports() -> usize {
    let Ok(dir) = ensure_report_dir() else { return 0 };
    // P0-2A：报告根被换成 junction 时，TTL 裁剪会在链接另一头删掉同形态的 `.json`。
    // 这一道放在入口而不是执行体：`prune_reports_in` 要保持「只吃入参目录」的沙箱可测性。
    //
    // B2-4 未把这里并进 `report_root_gate`，理由不是「懒得改」：`check-delete-root-guard`
    // 的判据是「根入口函数体内**看得见** `inspect_root(`」（注释里写不算，见该门禁 C3 自检）。
    // 套一层 `report_root_verdict` 会让它对 `prune_reports_in` 失明 —— 那等于把唯一能盯住
    // 这条的机检关掉，换来的只是少一行重复。判据本体仍然是同一个 `protect::inspect_root`。
    let verdict = crate::engine::protect::inspect_root(&dir, crate::engine::paths::data_root_base(&dir).as_deref());
    if !verdict.is_trusted() {
        crate::engine::protect::note_root_skipped("网速报告 TTL 裁剪", &dir, &verdict);
        return 0;
    }
    prune_reports_in(&dir, crate::engine::now_ms(), REPORT_TTL_MS)
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

/// 报告体积闸（R1d-M13）：与读取侧同常量、同 pretty 序列化口径。
/// 旧实现写侧只限样本数（1e6 ≈ 83 MiB），读侧限 8 MiB ⇒ 能保存但永远打不开。
fn report_bytes_check(data: &Value) -> Result<usize, String> {
    let bytes = serde_json::to_string_pretty(data)
        .map_err(|e| format!("报告序列化失败: {e}"))?
        .len();
    if bytes > REPORT_READ_MAX_BYTES as usize {
        return Err(format!(
            "报告体积 {} B 超过单份可读上限 {} B，未保存",
            bytes, REPORT_READ_MAX_BYTES
        ));
    }
    Ok(bytes)
}

/// 报告名后缀的进程内序号（v7.2 `R1d-L12`）。
/// 只用毫秒时间戳时，同一毫秒内两次 save 会生成**同一个名字**：后一份静默覆盖前一份，
/// 而两条回执都回同一个 `name` ⇒ 用户在列表里看到两份、盘上只有一份。
/// 加进程内单调序号即可彻底避开（毫秒本身已保证跨进程不撞名）。
static REPORT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn report_name() -> String {
    let seq = REPORT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("realtime-{}-{:04}.json", crate::engine::now_ms(), seq % 10000)
}

/// realtime:report-save
#[tauri::command]
pub async fn realtime_report_save<R: tauri::Runtime>(window: WebviewWindow<R>, data: Value) -> Result<Value, String> {
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
    let name = report_name();
    // 审查 v2-F13：目录清理 + `to_string_pretty` 序列化 + `sync_all` 全是磁盘 I/O，
    // 同步命令会把这段停顿留在主线程上。与同文件另两条写法对齐，丢进阻塞池。
    // 性能优化 P1：建目录的 `create_dir_all` 同样是磁盘 I/O，一并收进同一个阻塞任务。
    let payload = data;
    let report_name = name.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        report_bytes_check(&payload)?;
        let dir = ensure_report_dir()?;
        let path = dir.join(&report_name);
        let pruned = prune_reports_in(&dir, crate::engine::now_ms(), REPORT_TTL_MS);
        security::atomic_write_json(&path, &payload)?;
        Ok::<usize, String>(pruned)
    })
    .await;
    match res {
        // v7.2 `R1d-L07`：顺带回收的过期报告条数进回执 + 日志留痕。
        // 旧实现只 `prune_reports_in(…)` 取 `()`：用户点「查看列表」时被删掉的是
        // 他 7 天前存的报告，既不告知条数也不告知路径，属静默破坏性副作用。
        Ok(Ok(pruned)) => {
            if pruned > 0 {
                log::write_log(
                    "info",
                    &format!(
                        "网速报告目录已回收 {pruned} 份过期报告（保留 {} 天）",
                        REPORT_TTL_MS / 86_400_000
                    ),
                );
            }
            Ok(serde_json::json!({ "success": true, "name": name, "prunedReports": pruned }))
        }
        Ok(Err(e)) => {
            log::write_log("error", &format!("保存网速报告失败: {e}"));
            Ok(serde_json::json!({ "success": false, "message": e }))
        }
        Err(e) => {
            log::write_log("error", &format!("保存网速报告任务异常: {e}"));
            Ok(serde_json::json!({ "success": false, "message": format!("保存任务异常: {e}") }))
        }
    }
}

/// realtime:report-list（按 createdAt 倒序）
///
/// v2-L4P-35（F-4）：与 report_save 对齐——async + spawn_blocking（读目录 + 每份
/// 报告整文件 read_to_string + JSON 解析全是磁盘 I/O）；列表只回 `sampleCount`
/// 不回 samples 全量（7200 点 × N 份报告整包过 IPC 毫无必要），明细走
/// `realtime:report-get` 按需取。
#[tauri::command]
pub async fn realtime_report_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let dir = paths::realtime_report_dir();
    let out = tauri::async_runtime::spawn_blocking(move || -> (Vec<Value>, usize) {
        // 性能优化 P1：prune_reports 内含 create_dir_all + read_dir + remove_file，
        // 留在 async 体内会占住 runtime worker，移进同一个阻塞任务的最前面。
        // R1d-L07：回收条数不再丢进 `()`，随回执透出并留一条日志。
        let pruned = prune_reports();
        let mut out: Vec<Value> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".json") {
                    continue;
                }
                // R1d-M13：超过单份可读上限的件不再整读+解析，只回轻量标记。
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if meta.len() > REPORT_READ_MAX_BYTES {
                    out.push(serde_json::json!({
                        "name": name,
                        "tooLarge": true,
                        "bytes": meta.len(),
                        "sampleCount": 0,
                    }));
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(entry.path()) else {
                    continue;
                };
                let Ok(d) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                let sample_count = d
                    .get("samples")
                    .and_then(|s| s.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
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
                    "sampleCount": sample_count,
                    "adapter": d.get("adapter").cloned().unwrap_or_else(|| serde_json::json!("")),
                }));
            }
        }
        out.sort_by(|a, b| {
            let sa = a.get("createdAt").and_then(|v| v.as_str()).unwrap_or("");
            let sb = b.get("createdAt").and_then(|v| v.as_str()).unwrap_or("");
            sb.cmp(sa)
        });
        (out, pruned)
    })
    .await
    .map_err(|e| format!("报告列表任务异常: {e}"))?;
    let (out, pruned) = out;
    if pruned > 0 {
        log::write_log(
            "info",
            &format!(
                "网速报告目录已回收 {pruned} 份过期报告（保留 {} 天）",
                REPORT_TTL_MS / 86_400_000
            ),
        );
    }
    Ok(serde_json::json!({
        "success": true,
        "reports": out,
        // R1d-L07：本次「查看列表」顺带删掉了多少份过期报告（目录路径见日志与
        // `paths::realtime_report_dir()`），不让用户在不知情时丢历史
        "prunedReports": pruned
    }))
}

/// realtime:report-get —— 按名取单份报告全文（v2-L4P-35：列表瘦身后的明细入口）
#[tauri::command]
pub async fn realtime_report_get<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    name: String,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    // 复用 report_path 的唯一解析出口（basename 化 + .json 后缀 + 限定目录）
    let Some(path) = report_path(&name) else {
        return Ok(serde_json::json!({ "success": false, "message": "报告名非法" }));
    };
    // v7.2 `R1d-M06`：整文件读之前先过尺寸闸。
    // `validate_report` 只封样本数上限（1e6），一份合规报告可达数十 MB；旧写法
    // `read_to_string` 无上限，整包再整包过 IPC ⇒ 「明细入口」本身成了内存与 IPC 的
    // 放大面。判据用 metadata（不读内容），超限如实拒绝而不是截半份糊过去。
    let size = tauri::async_runtime::spawn_blocking({
        let p = path.clone();
        move || std::fs::metadata(&p).map(|m| m.len()).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("报告尺寸查询任务异常: {e}"))?
    .map_err(|e| format!("报告读取失败: {e}"))?;
    if size > REPORT_READ_MAX_BYTES {
        log::write_log(
            "warn",
            &format!("网速报告过大已拒绝读取: {name}（{size} 字节 > {REPORT_READ_MAX_BYTES}）"),
        );
        return Ok(serde_json::json!({
            "success": false,
            "tooLarge": true,
            "bytes": size,
            "message": format!("该报告体积 {} MB，超过单份可读上限，已拒绝打开", size / (1024 * 1024)),
        }));
    }
    let text = tauri::async_runtime::spawn_blocking(move || std::fs::read_to_string(path))
        .await
        .map_err(|e| format!("报告读取任务异常: {e}"))?
        .map_err(|e| format!("报告读取失败: {e}"))?;
    match serde_json::from_str::<Value>(&text) {
        Ok(d) => Ok(serde_json::json!({ "success": true, "report": d })),
        Err(e) => Ok(serde_json::json!({ "success": false, "message": format!("报告解析失败: {e}") })),
    }
}

/// 报告文件的唯一解析出口：basename 化 + `.json` 后缀 + 限定报告目录。
///
/// 审查 v2-F9：删除口原先只 `file_name()` 而不要求 `.json`，比列举口宽 ——
/// 同一目录下若有非报告文件，删得掉却列不出。三个出口（`delete`/`clear`/`list`）
/// 共用同一个后缀判定后，口径不会再分叉。
fn report_path(name: &str) -> Option<std::path::PathBuf> {
    let base = std::path::Path::new(name).file_name()?.to_str()?;
    if !base.ends_with(".json") || base.trim().is_empty() {
        return None;
    }
    Some(paths::realtime_report_dir().join(base))
}

/// B2-4：报告目录被拒时的**回执口径唯一出口**（`report-delete` 与 `report-clear` 共用）。
///
/// 病根：删除侧只判 `fp.is_file()` 就 `remove_file`，而 `is_file()` 会**跟随链接** ——
/// 报告目录被换成 junction 时「是文件」照样成立，删掉的是链接另一头那份，既不进回收站
/// 也不过受保护判定；清空侧早就补了根判定（P0-2A），删除侧一直没补。
/// 两个入口动的是**同一个根**，判据各写一份的必然结果就是「一个入口拒收、另一个入口穿透」。
///
/// 分工：`inspect_root` 本身留在各入口函数体内**可见**（`check-delete-root-guard` 的判据
/// 就是「根入口体内看得见判据」，套一层间接会让它对这两个根入口失明），本函数只统一
/// 「判出不可信之后怎么回话」。两种结局：
/// - `SkipMissing`（根不存在）⇒ **幂等成功**，且**不带** `skippedReparse` ——
///   报告目录都没了，报告必然也不在，这与「删一份本来就没有的报告」同义；
///   这时候报「被安全判定拒掉」反而是假话。
/// - `Rejected`（自身/祖先 reparse、不是目录、元数据读不出）⇒ `success:false` +
///   `skippedReparse:true`。**禁回 `success:true + removed:0`**：那与「本来就没有」同形，
///   正是 P1-6「失败被伪装成空结果」那一族。
fn report_root_receipt(
    caller: &str,
    dir: &std::path::Path,
    verdict: &crate::engine::protect::RootVerdict,
) -> Value {
    if matches!(verdict, crate::engine::protect::RootVerdict::SkipMissing) {
        return serde_json::json!({
            "success": true, "removed": 0, "failed": 0,
            "message": "报告目录不存在，报告已不在",
        });
    }
    crate::engine::protect::note_root_skipped(caller, dir, verdict);
    serde_json::json!({
        "success": false, "removed": 0, "failed": 0, "skippedReparse": true,
        "message": format!("报告目录未通过安全判定，本次未删除：{}", verdict.reason()),
    })
}

/// realtime:report-delete（basename 化 + `.json` 后缀，防路径穿越）
///
/// v7.2 `R1d-L11`：`is_file` + `remove_file` 是磁盘 I/O，同步命令体里做就占住主线程
/// ⇒ 改 async + `spawn_blocking`（同文件 v2-F13 口径），并在删除前补 `flush_sync`，
/// 让「删了哪一份」这条日志先落盘再动文件。
///
/// B2-4：动文件之前先过 `report_root_gate`（与 `report-clear` 同一道根判定、同一句回执）。
#[tauri::command]
pub async fn realtime_report_delete<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    name: String,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    // 审查 v2-F9：原先恒返回 `success:true` —— `remove_file` 的错误被 `let _ =` 丢掉，
    // 文件被占用时前端照样弹「已删除」，刷新后记录又回来了（状态说谎）。
    // 同时补上 `.json` 后缀判定，与 `report_list`/`prune_reports_in`/`report_clear` 三处同口径。
    let Some(fp) = report_path(&name) else {
        log::write_log("warn", &format!("拒绝删除网速报告（名称非法）: {name}"));
        return Ok(serde_json::json!({ "success": false, "removed": 0, "message": "报告名称非法，未删除" }));
    };
    // 名称闸在前（不碰盘、且能给出更准的错因），根判据在后（这时才真正要知道目录可信不可信）。
    // `fp` 与判定的根来自同一个 `paths::realtime_report_dir()`，不存在「判 A 删 B」。
    let report_dir = paths::realtime_report_dir();
    let verdict = crate::engine::protect::inspect_root(
        &report_dir,
        crate::engine::paths::data_root_base(&report_dir).as_deref(),
    );
    if !verdict.is_trusted() {
        // B2-4：不可信根回 `success:false + skippedReparse:true`，**不回** `success:true
        // + removed:0`（那与「本来就没有」同形）。回执措辞与清空侧共用 `report_root_receipt`。
        return Ok(report_root_receipt("删除网速报告", &report_dir, &verdict));
    }
    let target_name = name.clone();
    let job = tauri::async_runtime::spawn_blocking(move || {
        if !fp.is_file() {
            return Ok::<i64, String>(-1); // -1 = 已不存在（幂等成功）
        }
        crate::engine::log::flush_sync();
        match std::fs::remove_file(&fp) {
            Ok(()) => Ok(1),
            Err(e) => Err(e.to_string()),
        }
    })
    .await
    .map_err(|e| format!("删除任务异常: {e}"))?;
    match job {
        Ok(-1) => Ok(serde_json::json!({ "success": true, "removed": 0 })),
        Ok(_) => Ok(serde_json::json!({ "success": true, "removed": 1 })),
        Err(e) => {
            log::write_log("warn", &format!("删除网速报告失败: {target_name} -> {e}"));
            Ok(serde_json::json!({
                "success": false, "removed": 0,
                "message": format!("删除失败：{e}"),
            }))
        }
    }
}

/// realtime:report-clear
///
/// v7.2 `R1d-L11`：`read_dir` + 逐个 `remove_file` 是整段磁盘 I/O，同步命令体里跑
/// 会占住主线程（与 report_delete 同一处口径）⇒ 执行体进阻塞池，删除前补 `flush_sync`。
#[tauri::command]
pub async fn realtime_report_clear<R: tauri::Runtime>(
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let dir = ensure_report_dir()?;
    // P0-2A：清空是「全部删完」的强断言，根不可信时一条都不许删，而且**不能回 success:true
    // + removed:0** —— 那与「本来就没有报告」同形（方案 P1-6 的「失败被伪装成空结果」族）。
    // B2-4：回执措辞收进 `report_root_receipt`，删除侧改用它同一份 —— 两处不再是各写一句。
    let verdict = crate::engine::protect::inspect_root(
        &dir,
        crate::engine::paths::data_root_base(&dir).as_deref(),
    );
    if !verdict.is_trusted() {
        return Ok(report_root_receipt("清空网速报告", &dir, &verdict));
    }
    let counted = tauri::async_runtime::spawn_blocking(move || {
        let mut removed = 0usize;
        let mut gone = 0usize;
        let mut denied = 0usize;
        let mut failed = 0usize;
        // 审查 v2-F9：同上 —— 清空是「全部删完」的强断言，有一条失败就不能报成功。
        if let Ok(entries) = std::fs::read_dir(&dir) {
            crate::engine::log::flush_sync();
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".json") {
                    continue;
                }
                match std::fs::remove_file(entry.path()) {
                    Ok(()) => removed += 1,
                    Err(e) => {
                        // R4（2026-10-15）：失败按因分档（共享判据 classify_delete_error）。
                        // 不分档的话权限不足会被笼统说成「（可能被占用）」——提权对后者没用、
                        // 对前者有用，用户拿到的下一步动作是错的。
                        match crate::engine::native::classify_delete_error(&e) {
                            crate::engine::native::DeleteFailureKind::Denied => denied += 1,
                            crate::engine::native::DeleteFailureKind::Gone => gone += 1,
                            _ => failed += 1,
                        }
                        log::write_log("warn", &format!("清空网速报告失败: {name} -> {e}"));
                    }
                }
            }
        }
        (removed, gone, denied, failed)
    })
    .await
    .map_err(|e| format!("清空任务异常: {e}"))?;
    let (removed, gone, denied, failed) = counted;
    if failed > 0 || denied > 0 {
        let mut parts = vec![format!("已删除 {removed} 条")];
        if gone > 0 {
            parts.push(format!("{gone} 条在删除时已不存在"));
        }
        if failed > 0 {
            parts.push(format!("{failed} 条被占用未删"));
        }
        if denied > 0 {
            parts.push(format!("{denied} 条因权限不足未删（需管理员）"));
        }
        return Ok(serde_json::json!({
            "success": false, "removed": removed, "failed": failed + denied,
            "message": parts.join("，"),
        }));
    }
    Ok(serde_json::json!({ "success": true, "removed": removed, "failed": 0 }))
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

    /// B2-4：报告目录根不可信时，两个删除入口必须回「失败 + `skippedReparse`」，
    /// 且**不允许**回 `success:true + removed:0`（那与「本来就没有」同形，P1-6 族）。
    ///
    /// 夹具走目录符号链接（`symlink_dir`）。造不出来就显式 SKIP 并打印 —— 不假绿：
    /// 本机开不开开发者模式是环境属性，硬判红等于让这条判据随机器红绿。
    /// 判红自证：把 `report_root_receipt` 的 `Rejected` 分支改成回
    /// `{"success": true, "removed": 0}` ⇒ 本用例第一条断言当场红。
    #[test]
    fn 报告根是链接时删除必须拒且连接另一头零改动() {
        // 走自删守卫而不是本地 `sandbox()` + 手写收尾：本文件的删除原语调用点已按文件
        // 计数进了棘轮（现算见 `node tools/check-delete-callsites.mjs`），多一处就要 review。
        let sb = crate::testutil::Sandbox::new(&format!("realtime-junction-{}", std::process::id()));
        let root = sb.path();
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        put(&real, "realtime-a.json");
        let link = root.join("link");
        if std::os::windows::fs::symlink_dir(&real, &link).is_err() {
            println!("SKIP：本机 symlink_dir 失败（需开发者模式/提权），报告根 reparse 一面未校验");
            return;
        }
        // 走与命令体同一条路：先判根，再按判据取回执
        let verdict = crate::engine::protect::inspect_root(
            &link,
            crate::engine::paths::data_root_base(&link).as_deref(),
        );
        assert!(!verdict.is_trusted(), "目录符号链接必须判不可信: {verdict:?}");
        let receipt = report_root_receipt("测试删除网速报告", &link, &verdict);
        assert_eq!(
            receipt["success"],
            serde_json::json!(false),
            "不可信根禁回 success:true（那与「本来就没有」同形）: {receipt}"
        );
        assert_eq!(
            receipt["skippedReparse"],
            serde_json::json!(true),
            "必须点名「是被安全判定拒掉」，否则回执与真实原因脱钩: {receipt}"
        );
        assert_eq!(receipt["removed"], serde_json::json!(0));
        // 判定档只判定、不删：链接另一头一个文件都不许动
        assert!(real.join("realtime-a.json").exists(), "根判定期间不得动链接另一头的文件");
        // 正向对照：可信根必须放行 —— 否则「恒判不可信」也能让上面三条全绿（假绿形态）
        let ok = crate::engine::protect::inspect_root(
            &real,
            crate::engine::paths::data_root_base(&real).as_deref(),
        );
        assert!(ok.is_trusted(), "普通目录必须判可信: {ok:?}");
        // 根不存在 ⇒ 幂等成功，但**不许**冒充 skippedReparse（那不是被安全判定拒掉）
        let nope = root.join("nope");
        let gone_v = crate::engine::protect::inspect_root(
            &nope,
            crate::engine::paths::data_root_base(&nope).as_deref(),
        );
        assert!(!gone_v.is_trusted(), "根不存在也不是「可信」");
        let gone = report_root_receipt("测试删除网速报告", &nope, &gone_v);
        assert_eq!(gone["success"], serde_json::json!(true), "根不存在是幂等成功: {gone}");
        assert_eq!(gone["removed"], serde_json::json!(0));
        assert!(
            gone.get("skippedReparse").is_none(),
            "根不存在不许冒充被安全判定拒掉: {gone}"
        );
    }

    /// B2-4：两个删除入口必须共用**同一道**根判定与同一句回执措辞 ——
    /// 「一个入口拒收、另一个入口穿透」正是这条病的形态，各写一份就会复发。
    /// 判红自证：把删除侧的 `inspect_root` 判定块删掉 ⇒ `inspect_root(` 从 3 掉到 2，当场红。
    ///
    /// 期望每个根入口体内各自看得见 `inspect_root(`（`prune_reports` / `report-delete` /
    /// `report-clear`），而不是抽成一个公共函数：
    /// `check-delete-root-guard` 的判据是「根入口**函数体内**看得见 `inspect_root(`」，
    /// 套一层间接会让它对这些根入口全部失明 —— 不许为了少写两行去关掉那道机检。
    /// 判据本体仍是同一个 `protect::inspect_root`，措辞由 `report_root_receipt` 单点给。
    #[test]
    fn 报告删除与清空共用同一道根判定() {
        let src = include_str!("realtime.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or("");
        assert_eq!(
            prod.matches("fn report_root_receipt(").count(),
            1,
            "拒收回执的口径只许有这一个实现"
        );
        assert_eq!(
            prod.matches("report_root_receipt(\"删除网速报告\"").count()
                + prod.matches("report_root_receipt(\"清空网速报告\"").count(),
            2,
            "report-delete 与 report-clear 被判不可信时必须回同一份回执"
        );
        assert_eq!(
            prod.matches("protect::inspect_root(").count(),
            3,
            "三处根入口（TTL 裁剪 / 删除 / 清空）各自体内都要看得见判据，不许被间接层藏起来"
        );
    }

    /// R1d-M14：空闲停机只在超过阈值时成立（边界两侧各测一次）。
    #[test]
    fn 空闲停机只在超过阈值时成立() {
        assert!(!idle_stop_needed(false, 0, 1_000_000));
        assert!(!idle_stop_needed(true, 1_000_000, 1_000_000 + IDLE_STOP_MS));
        assert!(idle_stop_needed(true, 1_000_000, 1_000_001 + IDLE_STOP_MS));
    }

    /// R1d-M13：写侧体积闸与读上限同源（1e6 样本不再能保存成打不开的文件）。
    #[test]
    fn 报告体积闸与读上限同源() {
        let small = serde_json::json!({"samples": [{"t": 1, "down": 1.0, "up": 1.0}]});
        assert!(report_bytes_check(&small).is_ok());
        let one = serde_json::json!({"t": 1, "down": 1.0, "up": 1.0});
        let big = serde_json::json!({"samples": vec![one; 200_000]});
        let err = report_bytes_check(&big).unwrap_err();
        assert!(err.contains("可读上限"), "{err}");
    }
}
