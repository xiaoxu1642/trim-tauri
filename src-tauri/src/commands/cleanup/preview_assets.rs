//! 清理域图片预览的 asset 放行（preview 子窗退役后的承接件）
//!
//! 背景：图片预览从「独立子窗 + base64 dataURL」改为「主窗内 LiteBox 灯箱 + asset
//! 协议磁盘直连」。asset 协议的静态 scope（tauri.conf.json）只放行 backgrounds/fonts，
//! 而图片缓存目录是用户配置的动态路径，静态写死等于把任意用户目录常开给前端。
//!
//! 所以口径是**运行时按需放行**：用户点开某组预览时，只把这一组图片路径逐个
//! `allow_file` 进 asset scope —— 暴露面从「整个扫描目录常开」收紧到「你点开看的
//! 那几张图」。
//!
//! 两条与实现相符的约束（R4-M04：本文件旧文案把这两句写成了做不到的承诺）：
//! 1. **scope 只增不减**。当前依赖的 asset scope 只有 `allow_file` / `forbid_file` 两个
//!    动作（按 Cargo.lock 锁定的 tauri 版本实测，升级依赖时要复核这条），**没有**
//!    dismiss/revoke，而 forbid 永久优先 —— 本次会话内点过的每一组图恒可读，直到进程退出。
//!    「按需放行」不等于「临时授权」，别把它当成关掉就失效的开关。
//! 2. **累计面靠 [`MAX_SESSION_ALLOWS`] 兜**：单次上限只挡一次调用塞进来的清单，
//!    逐组点开照样能把 scope 无限撑大。
//!
//! 尚未落地的一条（属跨面改动，已登记进 P1 汇报）：把放行集**绑定到来源快照** ——
//! 即只放行「本窗口最近一次扫描结果里出现过的文件路径」，其余拒放（同域
//! `cleanup_item_detail` 已经是这个口径）。做不到的原因：本命令唯一消费方是主窗磁盘
//! 清理页的预览（`cleanup.js` 的 openPreview 吃 `fileCleanData`），那份清单在
//! `engine::snapshot` 的 **fileclean 域槽**里，而本域只握有 cleanup 域的槽、且
//! `engine::snapshot` 没有「按 label 列出各域槽」的读口。要落地必须二选一：给
//! `engine::snapshot` 加那个读口（引擎射程），或把预览字节改走一条非 asset 的读图通道
//! （原 `fileclean:read-image` 已随预览链退役，重开属 fileclean 域）。
//! 拿 cleanup 域的槽去核 fileclean 域的路径 = 把磁盘清理页的预览锁死，
//! 属 AGENTS §3「档位/闸写错方向会锁死功能」的同型错误，不硬改。

use crate::engine::{guard, log};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use tauri::{AppHandle, Manager, Runtime, WebviewWindow};

/// 单次放行条数上限：与同域**条目明细上限**同一数字（`cleanup_item_detail` 里明细只列
/// 600 条，预览就应该能吃下 600 张）。旧值 500 比明细还小 ⇒ 501–600 张的组预览必然打不开
/// （消费方拿 `success:false` 就不开灯箱），R4-L03。超限**截断并如实回执**，不再整包拒绝。
/// 两侧数字由 contract_tests 的「预览上限与明细上限同一数字」现算对拍（§5.16：不许各记一本账）。
const MAX_PATHS: usize = 600;

/// 单条路径的字符数上限（Windows MAX_PATH）。判据按**字符数**：旧形态用 `p.len()`
/// 即字节数，一条全中文路径实际只允许约 86 字，与同域其它长度闸（一律 `chars().count()`）
/// 分叉（R4-L03）。
const MAX_PATH_CHARS: usize = 260;

/// 本次会话累计放行上限（R4-M04）：asset scope 只增不减，单次上限管不住「逐组点开」的
/// 累计增长。取 5000 = 单次上限的 ~8 次满额调用，真实使用中点不到；打满时如实回执失败，
/// 不再静默继续扩面。
const MAX_SESSION_ALLOWS: usize = 5_000;

/// 本进程已放行的条数（asset scope 无撤销动作，只能自己记账封顶）
static SESSION_ALLOWED: AtomicUsize = AtomicUsize::new(0);

/// 路径清单的准入过滤（R4-L03：抽成纯函数，好让「按字符数判长度」这件事能被断言）。
/// 返回 `(可放行清单, 被拒原因计数)`；原因只回**条数**，不把用户路径拼进回执或日志。
pub(super) fn filter_preview_paths(list: &[Value]) -> (Vec<String>, [usize; 3]) {
    // [空路径, 超长（按字符数）, 含 NUL / 非字符串]
    let mut reasons = [0usize; 3];
    let mut kept: Vec<String> = Vec::with_capacity(list.len());
    for v in list {
        let Some(p) = v.as_str() else {
            reasons[2] += 1;
            continue;
        };
        if p.is_empty() {
            reasons[0] += 1;
        } else if p.chars().count() > MAX_PATH_CHARS {
            reasons[1] += 1;
        } else if p.contains('\0') {
            reasons[2] += 1;
        } else {
            kept.push(p.to_string());
        }
    }
    (kept, reasons)
}

/// cleanup:allow-preview-assets — 把本次预览的图片路径逐个放行进 asset 协议 scope
///
/// 主窗专属（`MAIN`）：预览入口只在主窗，子窗没有理由申请文件读取授权。
#[tauri::command]
pub async fn cleanup_allow_preview_assets<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    paths: Option<Value>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let Some(arr) = paths.as_ref().and_then(|v| v.as_array()) else {
        return json!({ "success": false, "message": "缺少路径清单" });
    };
    // R4-L03：超出单次上限**截断**而不是整包拒绝 —— 渲染层拿 success:false 就不开灯箱，
    // 旧形态等于让「图片多于上限的组」永远无法预览；截断后回执带 truncated，日志点名实到条数。
    let truncated = arr.len() > MAX_PATHS;
    if truncated {
        log::write_log(
            "warn",
            &format!(
                "预览放行清单超过单次上限 {MAX_PATHS}（实到 {} 条），已截断放行前 {MAX_PATHS} 条",
                arr.len()
            ),
        );
    }
    let used = SESSION_ALLOWED.load(Ordering::Relaxed);
    if used >= MAX_SESSION_ALLOWS {
        // 诚实回执：额度打满不是「放行成功但跳过几条」，而是这次一张都放不进去
        return json!({
            "success": false,
            "message": format!("本次会话的预览放行额度已用尽（累计上限 {MAX_SESSION_ALLOWS} 条），重启应用后可继续预览"),
            "sessionAllowed": used,
        });
    }
    let (kept, reasons) = filter_preview_paths(&arr[..arr.len().min(MAX_PATHS)]);
    let invalid = reasons[0] + reasons[1] + reasons[2];
    let scope = app.asset_protocol_scope();
    let mut allowed = 0usize;
    let mut allow_failed = 0usize;
    for p in &kept {
        match scope.allow_file(std::path::Path::new(p)) {
            Ok(()) => allowed += 1,
            Err(_) => allow_failed += 1,
        }
    }
    // 累计账只加**真的放出去**的条数（scope 也只因为这些条目变大）
    SESSION_ALLOWED.fetch_add(allowed, Ordering::Relaxed);
    let skipped = invalid + allow_failed;
    let mut receipt = json!({
        // 一条都没放成就不是成功：渲染层据此弹提示，而不是开一个全黑的灯箱
        "success": allowed > 0,
        "requested": arr.len() as i64,
        "allowed": allowed,
        "skipped": skipped,
        "invalid": invalid,
        "allowFailed": allow_failed,
        "truncated": truncated,
        "sessionAllowed": SESSION_ALLOWED.load(Ordering::Relaxed),
    });
    if allowed == 0 {
        // 渲染层把 message 直接当 toast 文案，这里必须说清「为什么一张都没放成」
        receipt["message"] = json!(format!(
            "本次 {request_n} 条路径都没能放行进预览（无效 {invalid} 条 / 放行被拒 {allow_failed} 条）",
            request_n = kept.len() + invalid
        ));
    }
    receipt
}
