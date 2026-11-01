//! app 域（批次 A）：app:get-info / app:get-theme / app:read-usage / app:open-external
//! / app:open-doc（子窗窄出口）
//! 外加窗口生命周期握手 app:first-paint（原 onSafe send 通道，直连命令注册）

use tauri::{AppHandle, WebviewWindow};

use crate::engine::{appearance, guard, paths, sysinfo};

/// 使用说明数据源：根目录 readme.md（用户文档与应用内弹窗同源）
const README_MD: &str = include_str!("../../../readme.md");

/// app:get-info — 字段形状对齐 Electron 版；未迁移字段显式给 null（渲染层已有 N/A 兜底）
#[tauri::command]
pub fn app_get_info<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard_readonly(&window)?;
    let build = sysinfo::windows_build();
    let username = std::env::var("USERNAME").unwrap_or_default();
    let homedir = std::env::var("USERPROFILE").unwrap_or_default();
    Ok(serde_json::json!({
        "name": "Trim",
        "version": env!("CARGO_PKG_VERSION"),
        // Electron/Node/Chrome 在 Tauri 下不存在，显式 null（渲染层显示 N/A）
        "electron": null,
        "node": null,
        "chrome": null,
        "runtime": "tauri",
        "platform": "win32",
        // 口径对齐 Node process.arch（'x64'/'arm64'），非 Rust 的 target 三元组（'x86_64'）。
        // 渲染层设置页直接展示该值，两者不一致会显示成 x86_64 而暴露迁移痕迹。
        "arch": node_arch(),
        "osVersion": sysinfo::os_version(),
        "osBuild": build,
        "fluentSupport": sysinfo::fluent_support_level(),
        "micaEnabled": sysinfo::fluent_support_level() != "none",
        "materialEnabled": appearance::material_enabled(),
        "isAdmin": sysinfo::is_admin(),
        "username": username,
        "homedir": homedir,
        // 刻意不再有 "powerShell" 字段：R1 起本应用不依赖 PowerShell 7，剩余步骤走
        // 系统自带的收件箱 Windows PowerShell 5.1；这个字段此前硬编码
        // "PowerShell 7" 且**零消费者**，是"应用要装 PS7"这个误解的唯一来源。
        // 每步真实执行引擎改由 optimizer:list 的 execMode 按编译器实算下发。
        // v2.6.0（P2-9）：数据目录形态（设置页「系统信息」展示）
        "portable": paths::is_portable(),
        "dataDir": paths::app_data_dir().to_string_lossy(),
    }))
}

/// app:read-usage — 返回使用说明 Markdown 全文
#[tauri::command]
pub fn app_read_usage<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<serde_json::Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if README_MD.trim().is_empty() {
        return Ok(serde_json::json!({ "success": false, "message": "使用说明文件不存在" }));
    }
    Ok(serde_json::json!({ "success": true, "content": README_MD }))
}

/// app:open-external — 受控外部链接出口：**只放行 https**，
/// 防 file: / javascript: / data: 等注入（渲染层导航已被 CSP 与窗口策略禁止）
#[tauri::command]
pub fn app_open_external<R: tauri::Runtime>(window: WebviewWindow<R>, url: String) -> serde_json::Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return serde_json::json!({ "ok": false, "reason": "forbidden", "message": msg });
    }
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return serde_json::json!({ "ok": false, "reason": "empty" });
    }
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("https://") {
        let scheme = trimmed.split(':').next().unwrap_or("");
        return serde_json::json!({ "ok": false, "reason": "scheme", "protocol": format!("{scheme}:") });
    }
    match open_https(trimmed) {
        Ok(()) => serde_json::json!({ "ok": true }),
        Err(e) => serde_json::json!({ "ok": false, "reason": "open-failed", "message": e }),
    }
}

/// 模型子窗「API 文档」入口的**窄出口**：地址只从这张表里取，渲染层传不了任意 URL。
///
/// 为什么不复用 `app:open-external`：那条按 `MAIN` 判档，`models` 是子窗、调它必被拒；
/// 而把它的档位下放到 readonly 换来的是「任何一扇窗都能让系统浏览器打开任意 https」，
/// 比这条命令本身需要的面宽得多（2026-10-22 目检批用户裁定走窄命令）。
/// 表里的 key 同时是渲染层 `DOC_LINKS` 的键集，两侧分叉由
/// `tools/check-native-hygiene.mjs` 的 N14 对账（§5.16 同一份判据不许各写一份）。
const DOC_LINKS: &[(&str, &str)] = &[
    ("baidu_pro", "https://cloud.baidu.com/doc/qianfan/s/Kmiy99ziv"),
    ("zhihu", "https://developer.zhihu.com/docs?key=zhida"),
    ("metaso", "https://metaso.cn/search-api/playground"),
];

/// app:open-doc — 只接受白名单 key，打开对应的厂商 API 文档
#[tauri::command]
pub fn app_open_doc<R: tauri::Runtime>(window: WebviewWindow<R>, key: String) -> serde_json::Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return serde_json::json!({ "ok": false, "reason": "forbidden", "message": msg });
    }
    let Some((_, url)) = DOC_LINKS.iter().find(|(k, _)| *k == key.as_str()) else {
        return serde_json::json!({ "ok": false, "reason": "unknown-key" });
    };
    match open_https(url) {
        Ok(()) => serde_json::json!({ "ok": true }),
        Err(e) => serde_json::json!({ "ok": false, "reason": "open-failed", "message": e }),
    }
}

/// 用系统默认浏览器打开 https（不经 shell 拼接命令，避免命令注入）
fn open_https(url: &str) -> Result<(), String> {
    let wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let op = unsafe {
        windows::Win32::UI::Shell::ShellExecuteW(
            None,
            windows::core::w!("open"),
            windows::core::PCWSTR(wide.as_ptr()),
            None,
            None,
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW 返回值 <= 32 表示失败
    if op.0 as usize > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecute 返回 {}", op.0 as usize))
    }
}

/// Node `process.arch` 口径（渲染层设置页直接展示该字段）
const fn node_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86") {
        "ia32"
    } else {
        std::env::consts::ARCH
    }
}

/// 启动看门狗超时阈值。取 12s：本地资源、无网络依赖，正常首帧在 2s 内；
/// 留足慢盘与杀软扫描的余量——宁可漏报，也不要在正常启动后凭空写一条 WARN。
const BOOT_WATCHDOG_MS: u64 = 12_000;

/// 看门狗到点的判据：只有「渲染层没画出首帧」才需要记一条日志。
///
/// 单独抽成纯函数，是因为线程 + 定时器的组合在没有窗口的测试里跑不了，
/// 而"什么情况下该报警"恰恰是这条机制唯一有判断含量的部分。
/// 参数是 `painted` 而不是 `shown`（R8-M05）：3s/8s 兜底显示的窗口同样 `shown == true`，
/// 用它当判据会让看门狗结构上永远不报警，而白屏正是被测对象。
fn boot_watchdog_note(painted: bool) -> Option<&'static str> {
    if painted {
        return None;
    }
    Some("启动看门狗：主窗首帧握手超时未到，界面可能白屏或渲染脚本未执行；可导出日志反馈（日志已含渲染层异常行）")
}

/// 挂启动看门狗：到点检查主窗是否收到了**真实首帧握手**。
///
/// 为什么需要：白屏、材质不渲染、脚本抛错这类问题此前**只在 DevTools 里可见**，
/// 用户侧一句"打开是空的"没有任何可诊断信息（v2-U4 长期挂着的未验证项就是这个）。
/// 信号是 `ShowState.painted`（R8-M05）：它在 `on_render_first_paint` 里由 `app:first-paint`
/// 置位；旧实现读 `shown`，而 3s/8s 兜底也会把它置真（12s 晚于 8s），看门狗因此失明。
///
/// 刻意**不自动 reload**（竞品那种做法在这里不安全）：本应用的窗口显示与提权重启握手
/// 耦合（§5.7 文件握手状态机），重载可能把用户正在确认的危险操作打断。只记录，不干预。
pub fn start_boot_watchdog<R: tauri::Runtime>(app: tauri::AppHandle<R>) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(BOOT_WATCHDOG_MS));
        use tauri::Manager;
        let Some(state) = app.try_state::<crate::ShowState>() else {
            return; // 状态都没建起来 = 启动更早就断了，不在这里重复报
        };
        let painted = state.painted.load(std::sync::atomic::Ordering::SeqCst);
        if let Some(note) = boot_watchdog_note(painted) {
            crate::engine::log::write_log("warn", &format!("{note}（阈值 {BOOT_WATCHDOG_MS}ms）"));
        }
    });
}

/// app:first-paint — 渲染层 DOMContentLoaded + 双 rAF 黑闪握手（只认首个通知）
///
/// 只认 `main` 的帧：`tauri-api.js` 在**每个**窗口里都会发这条，而闩锁是全局一次性的。
/// 若不按 label 判定，一个先渲染完的子窗（preview/models/…）会把主窗口提前 show 出来，
/// 主窗自己那帧还没画完 —— 正是这套握手要消灭的黑闪。子窗的首帧由各自的
/// `on_page_load(Finished)` 路径处理，不经过这里。
#[tauri::command]
pub fn app_first_paint<R: tauri::Runtime>(app: AppHandle<R>, window: WebviewWindow<R>) {
    // 审查 v2-F15：全仓唯一不走统一 `guard*` 的命令注册——条数现算以
    // `node tools/check-channel-map.mjs --strict` 为准（勿在此写死数字）。
    // 这里刻意按 label 判定而非 `guard(window, MAIN)`，是因为非 main 是**正常路径**
    // （四个子窗都会发这条通知，见上面注释），用 guard 会把每一次子窗首帧都记成
    // error 级「来源校验失败」，把真正的注入尝试淹掉。
    // 但**留痕不能省**：`engine/guard.rs` 的 `guard()` 注释写明「静默拒绝会掩盖注入尝试」，
    // 所以非 main 时至少留一条 debug，未知 label 才升级为 warn。
    let label = window.label().to_string();
    if label != "main" {
        let known = crate::engine::guard::APP_WINDOWS.contains(&label.as_str());
        crate::engine::log::write_log(
            if known { "debug" } else { "warn" },
            &format!("app:first-paint 已忽略非主窗来源：'{label}'（子窗首帧走 on_page_load 路径）"),
        );
        return;
    }
    // R8-M05：这里必须走 `on_render_first_paint` 而不是直接 `show_main_window_when_ready`。
    // 前者先置 `ShowState.painted` 再显示、再投递待编辑意图；绕过它 = 首帧信号永不置位，
    // 看门狗会对着正常启动报白屏、提权意图永远留在槽里。
    crate::on_render_first_paint(&app);
}
#[cfg(test)]
mod boot_watchdog_tests {
    use super::boot_watchdog_note;

    const SELF: &str = include_str!("app.rs");

    /// 只取生产段：所有 `#[cfg(test)]` 模块以下不参与匹配，避免断言里的字面量被自己数进去。
    fn prod() -> &'static str {
        let cut = SELF
            .find("#[cfg(test)]")
            .expect("找不到 #[cfg(test)]——断言的截断锚点变了");
        &SELF[..cut]
    }

    /// 函数体：从签名行起到第一个顶格 `}` 之前（注释里的同名散文不算函数体）。
    fn fn_body(name: &str) -> &'static str {
        let src = prod();
        let at = src.find(name).unwrap_or_else(|| panic!("找不到 {name}——结构变了，断言要同步"));
        let tail = &src[at..];
        let end = tail.find("\n}\n").unwrap_or(tail.len());
        &tail[..end]
    }

    /// 看门狗只在没收到首帧时说话：正常启动不得凭空留一条 WARN；
    /// 兜底显示（`shown == true` 但 `painted == false`）必须仍然报警（R8-M05）。
    #[test]
    fn watchdog_stays_silent_only_once_first_paint_arrived() {
        assert!(boot_watchdog_note(true).is_none(), "已收到首帧还报警就是噪音");
        let note = boot_watchdog_note(false).expect("未收到首帧必须给出可诊断的一条");
        assert!(note.contains("白屏") && note.contains("导出日志"), "文案要指向下一步动作: {note}");
    }

    /// R8-M05 破坏自证：看门狗改回读 `shown` 时必红。
    /// 3s/8s 兜底显示也会把 `shown` 置真（12s 看门狗晚于 8s 兜底），读它 = 白屏永远不报警。
    #[test]
    fn watchdog_reads_painted_not_shown() {
        let body = fn_body("pub fn start_boot_watchdog");
        assert!(
            body.contains("state.painted.load("),
            "看门狗必须读「渲染层首帧」信号 painted"
        );
        assert!(
            !body.contains("state.shown"),
            "读 shown 等于把兜底显示当成渲染就绪，白屏告警结构上失效"
        );
    }

    /// R8-M05：首帧命令必须经置位入口，直接调共用显示函数 = `painted` 永不置位。
    #[test]
    fn first_paint_goes_through_painted_entry() {
        let body = fn_body("pub fn app_first_paint");
        assert!(
            body.contains("crate::on_render_first_paint(&app)"),
            "首帧命令必须经 on_render_first_paint（置位 + 显示 + 投递意图）"
        );
        assert!(
            !body.contains("crate::show_main_window_when_ready("),
            "绕过置位入口直接显示：看门狗会对正常启动报白屏、意图永远送不出去"
        );
    }
}
