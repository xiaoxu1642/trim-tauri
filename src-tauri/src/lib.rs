//! Trim · Tauri 实现（Phase 1：IPC 域分批迁移）
//!
//! 模块分层（迁移方案 7.2）：
//! - `engine/`   跨域共用：路径解析、日志、来源校验、扫描缓存、外观、系统判定
//! - `security/` 配置原子写、损坏隔离、密钥脱敏/解密
//! - `pwsh/`     PowerShell 7 候选链与执行层
//! - `diag/`     失败诊断四元组
//! - `commands/` 一域一文件的 IPC 命令面
//!
//! 本文件只负责应用装配：窗口生命周期（黑闪握手 / 材质 / 圆角）、启动期一次性任务、
//! 命令注册。业务逻辑一律下沉到上述模块。

pub mod commands;
pub mod diag;
pub mod engine;
pub mod pwsh;
pub mod safestorage;
pub mod security;

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, Runtime, WebviewWindow};
use windows::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND,
};
use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_SHOWNOACTIVATE};

use crate::engine::{appearance, log, paths, sysinfo};

const APP_NAME: &str = "Trim";

/// 主窗口 label（R8-L03）：建窗、单实例唤回、首帧显示、事件判定共用这一个常量。
/// 四处字面量各自漂移时没有任何机械核对，症状是窗口建得出来但 IPC/唤回找错对象。
pub const MAIN_LABEL: &str = "main";

/// appearance.json 里窗口状态的键（R8-M01 读写唯一真源）。
/// 改名 = 所有用户的窗口位置恢复静默失效，所以读写两侧都只许引用这个常量。
const WINDOW_STATE_KEY: &str = "windowState";

/// 主窗口最小内容区（2026-10-11 用户实测锁定：外框 1403×870 / 客户区 1387×861，
/// 即"锁死当前尺寸为下限，不设最大"）。建窗与窗口状态 sanitize 用客户区读数 1387×861；
/// 拖拽下限另按外框口径，见 MIN_TRACK_WIDTH 与建窗后 set_min_size 的注释。
const MIN_WIDTH: f64 = 1387.0;
const MIN_HEIGHT: f64 = 861.0;

/// 拖拽钳制用的「外框口径」最小值 = 表格外框读数 1403×870。
///
/// 为什么必须与 MIN_WIDTH/MIN_HEIGHT 分开（tao 0.35.3 对无边框带阴影窗两条路径口径不一致）：
/// - 建窗与 set_inner_size：会补隐藏边框 insets（本机实测 (16,9)），传入值按客户区口径解释；
/// - WM_GETMINMAXINFO：只对 decorated 窗做非客户区换算，无边框带阴影窗把传入值直接当
///   「外框」下限（实测 minTrack == 传入值），而拖拽钳制的正是外框。
/// 若拖拽下限沿用客户区数值，外框会被拖到 1387×861、客户区缩到 1371×852 —— 比锁定值软 (16,9)。
const MIN_TRACK_WIDTH: f64 = 1403.0;
const MIN_TRACK_HEIGHT: f64 = 870.0;

// ==================== 材质 / 圆角（D4 / D3） ====================

use window_vibrancy::{apply_acrylic, apply_mica, apply_tabbed, clear_acrylic, clear_mica};

/// 应用窗口材质，返回实际生效值。失败不阻塞（材质是「可损失的视觉增强」，
/// 页面本身始终提供不透明 CSS 兜底）。
pub fn apply_material<R: Runtime>(window: &WebviewWindow<R>, material: &str) -> String {
    apply_material_outcome(window, material).0
}

/// 同上，但额外回报**原生层操作是否成功**：`appearance:set-material` 的 `nativeApplied`
/// 回执要用它（上游靠 `setBackgroundMaterial` 是否抛错判断，我们据 window-vibrancy 的
/// Result 判断，语义等价）。
///
/// 与上游的一处**刻意差异**：'none' 上游是早退、根本不碰原生层，因而恒报未应用；
/// 我们仍清一次 DWM backdrop —— Electron 只在建窗参数里设材质，而我们可能在进程存活
/// 期内从 mica 切到 none，不清复位会残留半透明背板。故 'none' 的成败按「清除是否成功」
/// 计，比上游的恒 false 更贴合实际（该字段渲染层无消费方，仅回执）。
pub fn apply_material_outcome<R: Runtime>(
    window: &WebviewWindow<R>,
    material: &str,
) -> (String, bool) {
    let normalized = appearance::normalize_material(Some(material));
    let result: Result<(), _> = match normalized.as_str() {
        "mica" => apply_mica(window, None),
        "mica-alt" => apply_tabbed(window, None),
        // 浅色主题低 alpha：细透明度分级仍由渲染层 data-material 完成
        "acrylic" | "thin-acrylic" => apply_acrylic(window, Some((245, 246, 248, 90))),
        // none：清除 DWM 背景（内部把 SystemBackdropType 复位 NONE），
        // 渲染层 data-material="none" 的不透明底色兜底不变
        _ => clear_mica(window).and(clear_acrylic(window)),
    };
    if let Err(e) = &result {
        eprintln!("[trim] 材质 {normalized} 应用失败（忽略，CSS 不透明兜底）: {e}");
    }
    (normalized, result.is_ok())
}

/// forceRoundCorners 等价：DWMWA_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND。
/// 必须在 show 之前调用（与 Electron 版同一时机，避免 show 后二次改窗的重绘跳变）。
fn force_round_corners<R: Runtime>(window: &WebviewWindow<R>) {
    if let Ok(hwnd) = window.hwnd() {
        unsafe {
            let preference: i32 = DWMWCP_ROUND.0;
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_WINDOW_CORNER_PREFERENCE,
                &preference as *const _ as *const _,
                std::mem::size_of_val(&preference) as u32,
            );
        }
    }
}

// ==================== 窗口状态恢复（sanitize 逻辑对照 main.js 866 段） ====================

pub(crate) struct ShowState {
    /// 显示成功闩锁（R8-M02）：CAS 占位防并发重复显示；显示动作失败会复位，
    /// 让 3s/8s 兜底与后续首帧还能重试。看门狗读它 = 「主窗已成功显示」。
    pub(crate) shown: AtomicBool,
    maximized: bool,
}

#[derive(serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WindowState {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    maximized: Option<bool>,
}

/// 多显示器可见性 sanitize：状态与显示器必须有足够交叠，否则视为不可用（回退默认位置）
fn sanitize_window_state<R: Runtime>(
    app: &AppHandle<R>,
    state: &WindowState,
) -> Option<(f64, f64, f64, f64)> {
    if !state.width.is_finite()
        || !state.height.is_finite()
        || !state.x.is_finite()
        || !state.y.is_finite()
        || state.width < MIN_WIDTH
        || state.height < MIN_HEIGHT
    {
        return None;
    }
    let monitors = app.available_monitors().ok()?;
    let visible = monitors.iter().any(|m| {
        let scale = m.scale_factor() as f64;
        // 状态是逻辑坐标（Electron useContentSize 即客户区 DIP），显示器为物理像素
        let ax = m.position().x as f64 / scale;
        let ay = m.position().y as f64 / scale;
        let aw = m.size().width as f64 / scale;
        let ah = m.size().height as f64 / scale;
        state.x + state.width > ax + 20.0
            && state.y + state.height > ay + 20.0
            && state.x < ax + aw - 20.0
            && state.y < ay + ah - 20.0
    });
    if visible {
        Some((state.x, state.y, state.width, state.height))
    } else {
        None
    }
}

/// 保存窗口位置 / 尺寸 / 最大化状态（R8-M01）。
///
/// 为什么原来恢复分支不可达：Tauri 轨从没有任何写点——Electron 基线的读写在
/// `vendor/upstream-js/main.js`，那份是只读上游快照、不参与运行时。没有写侧时
/// `sanitize_window_state` 的恢复整条链路是死的。
///
/// 必须在窗口还活着时读几何：`CloseRequested` 回调里窗口仍在；`RunEvent::Exit`
/// 只做 best-effort（那时窗口可能已销毁，读不到就跳过，不写半份状态）。
/// 写侧走 `appearance::update_appearance`（读-改-写原语，进程内锁），不许自拼
/// load→改→atomic_write_json。
///
/// 已知差别：最大化时记的是最大化几何（Tauri 没有 Electron `getNormalBounds` 的等价物），
/// 下次启动会先按这份几何摆好再最大化；用户点还原时由系统决定还原位。
fn save_window_state<R: Runtime>(window: &WebviewWindow<R>) {
    let (Ok(pos), Ok(size), Ok(scale)) =
        (window.outer_position(), window.inner_size(), window.scale_factor())
    else {
        return;
    };
    if !scale.is_finite() || scale <= 0.0 {
        return;
    }
    // 读侧按逻辑坐标（DIP）sanitize 与 set_position/set_size，这里同口径折回。
    let state = serde_json::json!({
        "x": pos.x as f64 / scale,
        "y": pos.y as f64 / scale,
        "width": size.width as f64 / scale,
        "height": size.height as f64 / scale,
        "maximized": window.is_maximized().unwrap_or(false),
    });
    let res = appearance::update_appearance(|ap| {
        let Some(obj) = ap.as_object_mut() else {
            return Err("外观配置不是对象，拒绝写入窗口状态".to_string());
        };
        obj.insert(WINDOW_STATE_KEY.to_string(), state.clone());
        Ok(())
    });
    if let Err(e) = res {
        log::write_log("warn", &format!("窗口状态保存失败（不影响退出）: {e}"));
    }
}

// ==================== 子窗口显示 / 聚焦（开发期后台回归开关） ====================

/// 开发期「不激活前台」开关（与 `show_main_window_when_ready` 用同一环境变量）。
///
/// 存在意义：弹窗类通道（processManager / models）若在 CDP 后台回归时按生产语义
/// `show()+set_focus()`，会把窗口弹到用户前台——这与「调试期不打扰用户」的硬性约束冲突。
/// 故开发期改用 `SW_SHOWNOACTIVATE`（显示但不抢焦点），生产环境行为完全不变。
pub fn dev_noactivate() -> bool {
    std::env::var("TRIM_DEV_NOACTIVATE").as_deref() == Ok("1")
}

/// wry 0.55.1 WebView2 的默认浏览器参数（R8-L02）。
///
/// 上游 `webview2/mod.rs` 是 `additional_browser_args(...).unwrap_or_else(|| 默认串)`——
/// **传参即整串替换**。只传自己的调试参数会把三个关闭项丢掉（msWebOOUI / msPdfOOUI /
/// msSmartScreenProtection），所以这里显式拼回默认值。升级 wry 时必须重核这条字面量：
/// 它没有编译期校验，漂移了只会表现为行为差异。
const WRY_DEFAULT_BROWSER_ARGS: &str =
    "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection";

/// 把 `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` 环境变量透传给 builder（审查 K4 复盘）。
///
/// 实测陷阱：主窗在 `lib.rs` 里透传了这份参数（Phase 0 为了让 CDP 端口生效），而四个子窗
/// **没有**透传 —— 同一个 WebView2 user-data-folder 下浏览器参数不一致时，第二个 core 创建
/// 不出来，`build()` 却照样返回成功、`get_webview_window` 也查得到，只是 `hwnd=0x0`。
/// 结果就是「带着调试端口启动时，所有子窗静默失效」，做真机验收的人会据此误判产品坏了。
/// 所以每个建窗点都必须过这一手。
///
/// 审查 v2-L4：签名对 manager 泛型化（`M: Manager<R>`），因为主窗的 builder 是在 `setup` 里
/// 由 `&mut App` 建的、子窗的由 `&AppHandle` 建的——原先只吃 `AppHandle<R>`，主窗想复用这个
/// helper 就得先把 builder 拆开，于是它当年被内联复制了一份，这正是"约束靠人记"的下场。
pub fn with_browser_args<R: tauri::Runtime, M: tauri::Manager<R>>(
    mut builder: tauri::WebviewWindowBuilder<'_, R, M>,
) -> tauri::WebviewWindowBuilder<'_, R, M> {
    if let Ok(extra) = std::env::var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS") {
        let extra = extra.trim();
        if !extra.is_empty() {
            // R8-L02：additional_browser_args 是替换不是追加，必须把 wry 默认串拼回来
            builder = builder.additional_browser_args(&format!("{WRY_DEFAULT_BROWSER_ARGS} {extra}"));
        }
    }
    builder
}

/// 显示并聚焦窗口（生产语义）；开发期只显示不抢焦点。
pub fn activate_window<R: Runtime>(window: &WebviewWindow<R>) {
    if dev_noactivate() {
        if let Ok(hwnd) = window.hwnd() {
            unsafe {
                let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            }
            return;
        }
        // R8-L01：拿不到 hwnd 时也要把窗口显示出来。旧实现会落回生产分支的
        // show()+set_focus()，等于在 dev 档抢前台；而单纯退回隐藏又会让窗口永不显示。
        // dev 档的统一语义：只显示、不聚焦。
        let _ = window.show();
        return;
    }
    let _ = window.show();
    let _ = window.set_focus();
}

/// 聚焦已存在的窗口（生产语义）；开发期不抢焦点。
pub fn focus_window<R: Runtime>(window: &WebviewWindow<R>) {
    if dev_noactivate() {
        return;
    }
    let _ = window.set_focus();
}

// ==================== 黑闪握手 ====================

/// 首帧握手显示窗口。3s / 8s 两级兜底与 Electron 版一致
/// （渲染异常或脚本失败时仍照常显示，不让窗口永久隐藏）。
///
/// R8-M02：闩锁语义 = **显示成功**，不是「抢到名额」。抢名额用 CAS 防并发重复显示，
/// 显示动作返回 Err 时立即复位并写 warn——3s/8s 兜底与后续首帧因此还能重试；
/// 旧实现的 `swap(true)` 先占位、`let _ =` 吞掉全部失败，窗口没显示也照样写
/// 「主窗口显示」并让看门狗以为界面已画出来。
pub fn show_main_window_when_ready<R: Runtime>(app: &AppHandle<R>, cause: &str) {
    let state = app.state::<ShowState>();
    if !claim_show_slot(&state.shown) {
        return;
    }
    let result = match app.get_webview_window(MAIN_LABEL) {
        Some(window) => show_main_window(&window, state.maximized),
        None => Err("主窗口不存在（get_webview_window 返回 None）".to_string()),
    };
    match result {
        Ok(()) => {
            log::write_log("info", &format!("主窗口显示（触发: {cause}）"));
            // R16：提权后消费到的待编辑意图只在首帧显示之后交给渲染层；页面脚本此时才已挂载。
            if let Some(state) = app.try_state::<commands::state::PendingEditState>() {
                if let Some(intent) = state.take() {
                    if let Some(window) = app.get_webview_window(MAIN_LABEL) {
                        let _ = window.emit("syspanel:edit-intent", intent);
                    }
                }
            }
            // v3 B3：显示动作落地之后才排队 housekeeping。真实首帧握手与 3s / 8s 两级兜底都经过
            // 这个函数，所以渲染脚本白屏时清理照样会跑；下面的闩锁保证三条路径最多排队一次。
            schedule_startup_housekeeping_once(app);
        }
        Err(e) => {
            // 复位 = 允许后续兜底重试；日志必须带拒因，否则「没显示」又成了无证据状态。
            state.shown.store(false, Ordering::SeqCst);
            log::write_log("warn", &format!("主窗口显示失败（触发: {cause}）：{e}"));
        }
    }
}

/// 抢「本次显示尝试」的唯一名额（CAS）；失败方直接返回，避免三条触发路径重复显示。
fn claim_show_slot(flag: &AtomicBool) -> bool {
    flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

/// 把「显示」这件事收成可返回成败的一处（R8-L01/M02 的共同落点）：
/// dev 档只显示不聚焦；生产档 show 成功即算显示成功（聚焦失败不影响闩锁）。
fn show_main_window<R: Runtime>(window: &WebviewWindow<R>, maximized: bool) -> Result<(), String> {
    if maximized {
        // 最大化前移到 show 之前，避免 show 后可见的尺寸跳变/边框重绘；
        // 最大化失败不阻断显示，成败由 show 决定。
        let _ = window.maximize();
    }
    force_round_corners(window);
    // 开发期 CDP 后台调试开关：TRIM_DEV_NOACTIVATE=1 时窗口显示但不激活前台，
    // 避免真机调试抢占用户桌面（仅调试构建使用，发布链路不带此变量）。
    if dev_noactivate() {
        // SW_SHOWNOACTIVATE(4)：显示窗口但不抢输入焦点/不置顶前台
        let hwnd = window.hwnd().map_err(|e| format!("拿不到窗口句柄: {e}"))?;
        unsafe {
            let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        }
        return Ok(());
    }
    window.show().map_err(|e| format!("show 失败: {e}"))?;
    let _ = window.set_focus();
    Ok(())
}

// ==================== 显示后一次性 housekeeping（v3 B2 / B3） ====================

/// 启动回收任务的排队闩锁。只回答「本次进程有没有排过队」，不承载别的业务状态。
#[derive(Default)]
pub(crate) struct StartupHousekeeping {
    scheduled: AtomicBool,
}

impl StartupHousekeeping {
    /// 抢到唯一名额返回 true，重复调用返回 false。
    /// 刻意做成不依赖运行时的纯方法：「首帧 + 3s 兜底 + 8s 兜底最多排队一次」这条
    /// 判据要能在无窗口环境里断言（线程与定时器组合在建窗测试里跑不起来）。
    fn try_schedule(&self) -> bool {
        !self.scheduled.swap(true, Ordering::SeqCst)
    }
}

/// 由 `show_main_window_when_ready` 在实际显示之后调用：把回收类磁盘 IO 挪出主线程建窗路径。
/// 拿不到状态 = 启动更早就断了，这里不替它兜底（与首帧看门狗同一判断）。
fn schedule_startup_housekeeping_once<R: Runtime>(app: &AppHandle<R>) {
    let Some(state) = app.try_state::<StartupHousekeeping>() else {
        return;
    };
    if !state.try_schedule() {
        return;
    }
    std::thread::spawn(run_startup_housekeeping);
}

/// 执行体：只调用无 UI 依赖的回收函数 —— 不碰窗口材质、不改保护清单、不重读并覆盖用户
/// 设置（v3 B3 第 4 条）。这四项都是「不做就永远回收不掉」的被动清理，延后到显示之后
/// 不改变任何用户可见的初始状态。
fn run_startup_housekeeping() {
    log::write_log(
        "debug",
        "启动 housekeeping（显示后一次性）：日志 / 隔离件 / 网速报告 / 临时脚本",
    );
    log::prune_old_logs();
    // 审查 M15/G4：隔离件（*.corrupt-*）此前没有任何回收路径
    crate::security::prune_quarantined(&paths::app_data_dir());
    crate::security::prune_stale_atomic_temps(&paths::app_data_dir());
    // 审查 v3-L3：网速报告的 7 天 TTL 此前只在 save/list 两个入口被动触发，用户不再打开
    // 网速页就永远回收不掉；与退出端（`on_app_exit` → `realtime::shutdown_sampler`）合成
    // 完整生命周期。
    commands::realtime::prune_reports();
    // 与退出钩子共用 pwsh 层互斥：避免启动线程和 on_app_exit 同时修剪同一批临时脚本。
    pwsh::cleanup_temp_scripts();
}

// ==================== 入口 ====================

/// 命令注册面（唯一真源）：生产入口与 tauri::test 集成测试共用同一份清单，
/// 避免测试里复制一份导致「新命令没被测试覆盖」的静默漂移。
pub fn build_app<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    builder.invoke_handler(tauri::generate_handler![
        // ---- A 批：app ----
        commands::app::app_get_info,
        commands::app::app_read_usage,
        commands::app::app_open_external,
        commands::app::app_first_paint,
        // ---- A 批：log / diag / modal / window / shutdown / intro ----
        commands::log::log_write,
        commands::log::log_read,
        commands::log::log_export,
        commands::misc::diag_dwm_conflict,
        commands::misc::modal_open,
        commands::misc::modal_close,
        commands::misc::intro_load,
        commands::misc::debug_data_dirs,
        // ---- A 批：device / system / overview ----
        commands::device::device_scan,
        commands::system::system_disk_type,
        commands::system::system_disk_list,
        commands::syspanel::syspanel_power_plan_get,
        commands::syspanel::syspanel_power_plan_apply,
        commands::syspanel::syspanel_power_settings_dump,
        commands::syspanel::syspanel_power_plan_duplicate,
        commands::syspanel::syspanel_power_plan_rename,
        commands::syspanel::syspanel_power_plan_delete,
        commands::syspanel::syspanel_power_plan_import,
        commands::syspanel::syspanel_power_plan_export,
        commands::syspanel::syspanel_power_settings_unlock,
        commands::syspanel::syspanel_power_settings_apply,
        commands::syspanel::syspanel_power_settings_revert,
        commands::syspanel::syspanel_power_settings_compare,
        commands::syspanel::syspanel_power_settings_open_regedit,
        commands::syspanel::syspanel_power_ultimate_enable,
        commands::syspanel::syspanel_power_hide_high_performance,
        commands::syspanel::syspanel_power_restore_high_performance,
        commands::syspanel::syspanel_pagefile_state,
        commands::syspanel::syspanel_pagefile_apply,
        commands::overview::overview_metrics,
        commands::overview::overview_hardware,
        // ---- A 批：paths ----
        commands::paths::paths_load,
        commands::paths::paths_save,
        commands::paths::paths_browse,
        commands::paths::paths_app_icon,
        commands::paths::paths_file_icon,
        // ---- A 批：realtime ----
        commands::realtime::realtime_adapters,
        commands::realtime::realtime_sample,
        commands::realtime::realtime_loss,
        commands::realtime::realtime_report_save,
        commands::realtime::realtime_report_list,
        commands::realtime::realtime_report_get,
        commands::realtime::realtime_report_delete,
        commands::realtime::realtime_report_clear,
        // ---- B 批：finder（只读扫描 + 删除，走原生引擎 sink 直调）----
        commands::finder::finder_scan,
        commands::finder::finder_delete,
        commands::finder::finder_delete_manifest,
        commands::finder::finder_open_backup_dir,
        commands::finder::finder_ignore_folder,
        commands::finder::finder_ignore_list,
        commands::finder::finder_ignore_remove,
        // ---- 卸载域 MVP（竞品借鉴落地方案 P0，2026-09-28；全档 MAIN）----
        commands::uninstall::uninstall_list,
        commands::uninstall::uninstall_run,
        commands::uninstall::uninstall_modify,
        commands::uninstall::uninstall_pending_add,
        commands::uninstall::uninstall_pending_list,
        commands::uninstall::uninstall_pending_revoke,
        commands::uninstall::uninstall_residue_scan,
        commands::uninstall::uninstall_residue_execute,
        // 机-wide 扫描（失效残留 / 卸载遗留 / 七个深扫器报告）已整条退役：只剩
        // `uninstall_residue_scan` 按应用维度产出四类残留（服务/驱动/注册表/文件）
        commands::uninstall::uninstall_dir_size,
        commands::uninstall::uninstall_reg_backup_list,
        commands::uninstall::uninstall_reg_backup_restore,
        commands::uninstall::uninstall_batch_list,
        commands::uninstall::uninstall_batch_restore,
        commands::uninstall::uninstall_report_list,
        commands::uninstall::uninstall_report_get,
        commands::uninstall::uninstall_appx_logo,
        // ---- B 批：memory（6）+ processManager 窗口（2+send）----
        // preview 窗口（2+send）已整链退役：图片预览改主窗内嵌 LiteBox（见 cleanup/preview_assets.rs），
        // 跨窗传 preview:data 的监听竞态根因随之消失。
        commands::memory::memory_info,
        commands::memory::memory_clean,
        commands::memory::memory_processes,
        commands::memory::memory_kill,
        commands::memory::memory_stubborn_kill,
        commands::memory::memory_stubborn_block,
        commands::processmanager::process_manager_open_window,
        commands::processmanager::process_manager_close_window,
        commands::processmanager::process_manager_report,
        commands::cleanup::cleanup_allow_preview_assets,
        // v0.5.0 残留扫描副窗（label `residue`，与 guard::APP_WINDOWS / capabilities 同步）
        commands::residue::residue_open_window,
        commands::residue::residue_close_window,
        // ---- B 批：runtimes / netcheck / diskbench ----
        // R1（2026-10-01）：`pwsh_status` 随整条 PowerShell 7 链退役 —— 右键图标改原生取图后
        // 本应用不再需要用户自装 PS7，「探测候选链并回报状态」这件事失去了对象。
        // （更早的 B11 已摘除 `pwsh_prepare`：零调用方 + 无内置解压链可准备。）
        commands::runtimes::runtimes_collect,
        commands::runtimes::runtimes_install,
        commands::netcheck::netcheck_collect,
        commands::netcheck::netcheck_repair,
        commands::diskbench::diskbench_run,
        // ---- C 批：cleanup（规则库验签 / 扫描 / 执行 / 占用检测 / 明细，9 条）----
        commands::cleanup::cleanup_rules,
        commands::cleanup::cleanup_reg_backup_list,
        commands::cleanup::cleanup_reg_backup_restore,
        commands::cleanup::cleanup_file_backup_list,
        commands::cleanup::cleanup_file_backup_restore,
        commands::cleanup::cleanup_scan,
        commands::cleanup::cleanup_execute,
        commands::cleanup::cleanup_check_locked,
        commands::cleanup::cleanup_kill_locked_processes,
        commands::cleanup::cleanup_query_locked,
        commands::cleanup::cleanup_item_detail,
        commands::cleanup::cleanup_age_policy,
        commands::cleanup::cleanup_set_age_policy,
        // G-4（2026-10-07）：回收站清空改 Shell API（选项 B）——查询条目数与体积 + 清空
        commands::cleanup::cleanup_recycle_stats,
        commands::cleanup::cleanup_empty_recycle_bin,
        // G-4 修订（2026-10-07）：回收站行「明细」= 打开系统回收站（Shell 虚拟命名空间）
        commands::cleanup::cleanup_open_recycle_bin,
        // ---- C 批：settings / models / aidesc / quickcmds / bench-history / fonts / paths:scan ----
        // 审查 v2-F4 彻底方案：`settings_save` 已整链摘除（零调用方的死写入通道，
        // 摘除记录见 settings.rs 头部注释）。AI 模型配置写入由 `models_save` 承载。
        commands::settings::settings_load,
        // v4 P2-13：UI 偏好键的后端真源（渲染层 localStorage 只是镜像；见 settings.rs）
        commands::settings::settings_get_prefs,
        commands::settings::settings_set_pref,
        commands::models::models_save,
        commands::models::models_set_scope,
        commands::models::models_test,
        commands::models::models_open_window,
        commands::models::models_close_window,
        commands::aidesc::aidesc_get,
        commands::quickcmds::quickcmds_run,
        commands::benchhistory::bench_history_add,
        commands::benchhistory::bench_history_list,
        commands::benchhistory::bench_history_delete,
        commands::benchhistory::bench_history_clear,
        commands::fonts::fonts_list,
        commands::fonts::fonts_import,
        commands::fonts::fonts_remove_imported,
        commands::fonts::fonts_save_config,
        commands::paths::paths_scan,
        // ---- D 批（删除与高危：文件清理 / 维护 / 右键 / 启动项 / 优化 / 外设，37 条）----
        commands::fileclean::fileclean_scan,
        commands::fileclean::fileclean_delete_file,
        commands::fileclean::fileclean_execute,
        commands::maintenance::maintenance_tasks,
        commands::maintenance::maintenance_run,
        commands::contextmenu::contextmenu_scan,
        commands::contextmenu::contextmenu_toggle,
        commands::contextmenu::contextmenu_icons,
        commands::contextmenu::contextmenu_open_in_regedit,
        commands::contextmenu::contextmenu_restart_explorer,
        commands::startup::startup_scan,
        commands::startup::startup_toggle,
        commands::startup::startup_delete,
        commands::startup::startup_openlocation,
        commands::startup::startup_open_source,
        commands::startup::startup_add,
        commands::optimizer::optimizer_run,
        commands::optimizer::optimizer_list,
        commands::optimizer::optimizer_check_optimized,
        commands::optimizer::optimizer_batch_preflight,
        commands::optimizer::optimizer_state_overview,
        commands::optimizer::optimizer_stale_dismiss,
        commands::optimizer::optimizer_list_groups,
        commands::optimizer::optimizer_touch_recent,
        commands::optimizer::optimizer_svc_mem_current,
        commands::optimizer::optimizer_backup_reg,
        commands::optimizer::optimizer_restore_reg,
        commands::optimizer::optimizer_check_restore,
        commands::optimizer::optimizer_create_restore,
        commands::optimizer::optimizer_list_restore,
        commands::optimizer::optimizer_restore_frequency,
        commands::optimizer::optimizer_genadvice,
        commands::optimizer::optimizer_bcd_enum,
        commands::optimizer::optimizer_external_scan,
        commands::optimizer::optimizer_nara_panel,
        commands::optimizer::optimizer_privacy_panel,
        commands::peripheral::peripheral_query,
        commands::peripheral::peripheral_apply,
        commands::peripheral::peripheral_restore_backup,
        // ---- E 批：appearance（材质读写与广播 / 环境自适应 / 背景图管理，8 条）----
        commands::appearance::appearance_get_material,
        commands::appearance::appearance_set_material,
        commands::appearance::appearance_set_material_enabled,
        commands::appearance::appearance_get_env,
        commands::appearance::appearance_bg_import,
        commands::appearance::appearance_bg_delete,
        commands::appearance::appearance_bg_list,
        commands::appearance::appearance_bg_open_dir,
        // ---- E 批：elevate（UAC 自提权 + 新旧实例交接）----
        commands::elevate::elevate_request,
        // ---- E 批：updater（多线路容灾 + minisign 断代，6 条）----
        commands::updater::updater_check,
        commands::updater::updater_completion,
        commands::updater::updater_download,
        commands::updater::updater_cancel_download,
        commands::updater::updater_install,
    ])
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // ---------- 提权接管握手：必须早于任何建窗 ----------
    // 带旗标的实例一律**不注册**单实例插件：实测 tauri-plugin-single-instance 2.4.5 的
    // Windows 实现里，第二实例发现 mutex 已存在时发完 WM_COPYDATA 就无条件
    // `cleanup_before_exit(); process::exit(0)` —— 注册了就会把提权后的新实例自己在
    // 建窗前杀掉。改为先走文件握手（见 commands::elevate）。
    // 旧实例确认让位后 mutex 已空闲，此时仍可正常注册以恢复单实例保护。
    let elevated_relaunch = commands::elevate::elevation_takeover_pending();
    let mut takeover_released = false;
    let pending_edit_intent = if elevated_relaunch {
        // R8-M04：握手返回值 = 旧实例是否**确认让位**（mutex 已空闲）。只有这一档才敢
        // 补注册单实例插件；超时档仍不注册（插件会把新实例在建窗前 exit(0)，v5-K03 的双亡）。
        takeover_released = commands::elevate::take_over_as_elevated_instance();
        commands::elevate::take_pending_edit_intent()
    } else {
        None
    };

    let builder = build_app(tauri::Builder::default())
        .plugin(tauri_plugin_dialog::init())
        // updater 插件必须注册：`UpdaterExt::updater_builder()` 直接取插件的
        // `state::<UpdaterState>()`，未注册会 panic 而不是报错。
        // 线路端点由 commands::updater 按用户偏好逐个传入（覆盖 conf 的 endpoints），
        // 而**公钥只从 conf 读**——它必须是编译期固化的信任锚点，不能由运行时决定。
        .plugin(tauri_plugin_updater::Builder::new().build());

    #[cfg(desktop)]
    let builder = if !elevated_relaunch || takeover_released {
        // 普通启动恒注册；提权重启只在「旧实例已确认让位、mutex 已空闲」时补注册
        // （R8-M04）。take_over_as_elevated_instance 返回 true 前已经等旧实例进程退出，
        // 所以这里不会重演 v5-K03 的「新旧双亡」。
        builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // 对照 main.js 57-62：再次启动应用 = 把已有主窗口唤回前台，而不是开第二个
            if let Some(w) = app.get_webview_window(MAIN_LABEL) {
                if w.is_minimized().unwrap_or(false) {
                    let _ = w.unminimize();
                }
                focus_window(&w);
            }
        }))
    } else {
        // 超时档（takeover_released == false）：旧实例可能仍持有 mutex，注册会让插件
        // 在建窗前 exit(0)。宁可本会话没有单实例约束，也不让提权后的应用消失。
        log::write_log(
            "warn",
            "提权实例未确认旧实例让位：本会话不注册单实例插件（避免插件在建窗前 exit(0)）",
        );
        builder
    };

    builder
        .setup(move |app| {
            app.manage(commands::state::PendingEditState::new(pending_edit_intent));
            // 窗口在代码中创建（而非 tauri.conf.json 声明），唯一原因：需要
            // additional_browser_args 显式透传 WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
            // ——实测 Tauri/wry 2.11 自带默认浏览器参数时，WebView2 加载器会忽略该环境变量，
            // 导致 CDP 远程调试端口起不来（Phase 0 结论，B2 已记录）。
            use tauri::{WebviewUrl, WebviewWindowBuilder};
            let builder = WebviewWindowBuilder::new(app, MAIN_LABEL, WebviewUrl::App("index.html".into()))
                .title(APP_NAME)
                .inner_size(MIN_WIDTH, MIN_HEIGHT)
                .min_inner_size(MIN_WIDTH, MIN_HEIGHT)
                .resizable(true)
                .maximizable(true)
                .decorations(false)
                .transparent(true)
                .visible(false)
                .shadow(true);
            // 审查 v2-L4：主窗也过一次 `with_browser_args`。四个子窗早就统一走它，只有主窗内联
            // 同款 env 读取——「建窗必须透传浏览器参数」这条 K4 换来的约束靠人记住必然漏，
            // 收成一个函数后新增建窗点就只有一条路可走。
            let window = with_browser_args(builder)
                .build()
                .expect("main 窗口创建失败");

            // 建窗后把最小尺寸改按「外框口径」再设一次：builder 的 min_inner_size 只覆盖
            // 建窗/尺寸变更的换算，拖拽钳制走 WM_GETMINMAXINFO（原因见 MIN_TRACK_* 注释）。
            // 不设 max —— 无任何上限约束，ptMaxTrackSize 实测为 0（不限制最大值）。
            let _ = window.set_min_size(Some(LogicalSize::new(MIN_TRACK_WIDTH, MIN_TRACK_HEIGHT)));

            // R8-M01 写侧：窗口关闭请求时还在，几何读得到（RunEvent::Exit 时可能已销毁）。
            // `WebviewWindow` 要 clone 进闭包（回调是 'static）。
            let state_window = window.clone();
            window.on_window_event(move |event| {
                if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                    save_window_state(&state_window);
                }
            });

            // ---------- 启动期同步任务（v3 B1：首帧前必须落地的迁移与安全边界） ----------
            // 只留「后续读写依赖它」的四项：老根迁移、名单文件迁移、配置语义迁移、
            // 受保护路径清单。回收类 housekeeping 已挪进显示后一次性批次（v3 B2/B3）——
            // 它们不改变窗口布局、保护清单或初始材质，没理由在主窗建窗前抢占磁盘 IO；
            // 反过来把迁移也延后，就会出现「扫描读老根、清理写新根」的两份真相。
            if let Some(note) = paths::migrate_legacy_once() {
                log::write_log("info", &note);
            }
            // N2（2026-09-29）：名单文件（清理排除 / 空目录忽略）另走一条搬迁，不受
            // appearance.json 闸门限制 —— 它们是扫描器每轮都要读的活性文件，滞留老根
            // 会造成「读老根、写新根」两份真相：用户删掉一条排除项，下轮扫描又生效。
            if let Some(note) = paths::migrate_list_files_once() {
                log::write_log("info", &note);
            }
            appearance::migrate_bg_opacity_fog();
            // C 批安全地基：受保护路径清单补全（Electron 用 app.getPath 取 known folder，
            // 可能被 OneDrive/组策略重定向，纯环境变量推导覆盖不到）
            engine::protect::configure_from_app(app.handle());
            commands::misc::detect_dwm_inject_tools_async(app.handle().clone());
            log::write_log(
                "info",
                &format!(
                    "应用启动（管理员: {}，数据目录: {}，便携: {}）",
                    if sysinfo::is_admin() { "是" } else { "否" },
                    paths::app_data_dir().to_string_lossy(),
                    if paths::is_portable() { "是" } else { "否" }
                ),
            );
            // 审查 v2-C-002：README 承诺「适用 Windows 11 22H2 及以上」，此前代码里没有
            // 任何断言、日志也不记录实测版本 —— 这条承诺静态无法证伪。现在把实测 build
            // 与判定结果落进日志；低于下限只 warn 不阻断（在 21H2 上材质会降级、其余功能
            // 多数仍可用，替用户做「拒绝启动」的决定越权了）。
            let build = sysinfo::windows_build();
            if sysinfo::supported() {
                log::write_log("info", &format!("系统版本 10.0.{build}（达到最低支持 build {}）", sysinfo::MIN_SUPPORTED_BUILD));
            } else {
                log::write_log(
                    "warn",
                    &format!(
                        "系统版本 10.0.{build} 低于承诺的最低支持 build {}（Windows 11 22H2）：窗口材质将不可用，部分功能未在该版本验证",
                        sysinfo::MIN_SUPPORTED_BUILD
                    ),
                );
            }

            // ---------- 窗口状态恢复 ----------
            let ap = appearance::load_appearance();
            let mut maximized = false;
            if let Some(ws) = ap
                .get(WINDOW_STATE_KEY)
                .and_then(|v| serde_json::from_value::<WindowState>(v.clone()).ok())
            {
                if let Some((x, y, w, h)) = sanitize_window_state(app.handle(), &ws) {
                    let _ = window.set_position(LogicalPosition::new(x, y));
                    let _ = window.set_size(LogicalSize::new(w, h));
                    maximized = ws.maximized.unwrap_or(false);
                } else if ws.maximized.unwrap_or(false) {
                    maximized = true;
                }
            }

            // ---------- 材质与圆角（show 之前就绪） ----------
            force_round_corners(&window);
            apply_material(&window, &appearance::effective_material());

            app.manage(ShowState {
                shown: AtomicBool::new(false),
                maximized,
            });
            // v3 B3：housekeeping 的排队闩锁与 ShowState.shown 分开两份状态。
            // shown 在 R8-M02 后的语义 = 「主窗已成功显示」（失败会复位）；它不再承载
            // 「抢到名额」这层意义，排队次数由 StartupHousekeeping 自己的闩锁回答。
            app.manage(StartupHousekeeping::default());

            // 首帧看门狗：必须排在 manage(ShowState) 之后 —— 它读的就是这个状态。
            commands::app::start_boot_watchdog(app.handle().clone());

            // ---------- 环境自适应（电池降级 / 系统透明开关）----------
            // 必须在建窗与首次 apply_material 之后：降级逻辑要能拿到 main 窗判最大化，
            // 且不能早于初始材质落地，否则会被随后的 apply_material 覆盖。
            commands::appearance::init_env(app.handle());

            // 启动 8s 后静默检查一次更新（避开窗口动画与概览预热的资源抢占期）
            commands::updater::schedule_silent_check(app.handle());

            // 黑闪兜底：3s / 8s 两级（run_on_main_thread 保证窗口操作在主线程）
            for (delay_ms, cause) in [
                (3000u64, "ready-to-show 3s 兜底"),
                (8000u64, "创建后 8s 兜底"),
            ] {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    let main_thread_handle = handle.clone();
                    let _ = handle.run_on_main_thread(move || {
                        show_main_window_when_ready(&main_thread_handle, cause);
                    });
                });
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Tauri 运行时构建失败")
        .run(|app, event| {
            // 唯一退出钩子：覆盖窗口关闭、shutdown:complete、异常退出三条路径
            if let tauri::RunEvent::Exit = event {
                // R8-M01 兜底：正常关闭已由 CloseRequested 写过；这里补 shutdown:complete /
                // 异常退出路径。窗口可能已销毁，读不到几何就静默跳过（不写半份状态）。
                if let Some(w) = app.get_webview_window(MAIN_LABEL) {
                    save_window_state(&w);
                }
                on_app_exit();
            }
        });
}

/// 进程退出前的统一收尾（对齐 Electron 的 before-quit 编排中 Phase 1 已实现的部分）：
/// 刷盘日志 → 停掉进程内实时采样线程 → 收掉静默检查线程 → 清理临时 pwsh 脚本。
/// 不这样做会留下半截日志与残留脚本文件（渲染层异常退出路径同样会走到这里）。
pub fn on_app_exit() {
    log::flush_sync();
    commands::realtime::shutdown_sampler();
    // 审查 M-05：静默检查线程的 3s sleep 阶段此前无从 join；这里 join 一次。
    // 有上界（最多 3s），不会把退出卡成无限等待。
    commands::updater::join_silent_check_thread();
    pwsh::cleanup_temp_scripts();
}

#[cfg(test)]
mod tests {
    const SELF: &str = include_str!("lib.rs");

    /// 只取生产段：所有 `#[cfg(test)]` 模块以下不参与计数，避免断言里的字符串字面量
    /// 把测试自己算进接线数（旧版用「两处 token 互相抵消」，扫描面其实是瞎的）。
    fn prod() -> &'static str {
        let cut = SELF.find("#[cfg(test)]").expect("找不到 #[cfg(test)]——断言的截断锚点变了");
        &SELF[..cut]
    }

    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    rs_files(&p, out);
                } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                    out.push(p);
                }
            }
        }
    }

    /// 审查 v2-L4 的常驻断言：**每个建窗点都必须过一次 `with_browser_args`**。
    /// R8-M03：旧实现全局数两个 token 再比相等——一处漏透传 + 一处重复包裹 = 5/5 恒绿，
    /// 且 `read_to_string` 失败静默跳过。现改为**逐文件点名**：凡文件内出现建窗 token，
    /// 就必须同文件出现透传 token，并把命中的文件清单打进 `reached`。
    /// token 用 concat! 拼，避免测试源码里的字面量被自己数进去。
    #[test]
    fn every_window_builder_goes_through_browser_args() {
        let builder_token = concat!("WebviewWindowBuilder", "::new(");
        let wrap_token = concat!("with_browser_args", "(");
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rs_files(&root, &mut files);
        let mut builders = 0usize;
        let mut reached: Vec<String> = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        for f in &files {
            let t = std::fs::read_to_string(f).unwrap_or_else(|e| {
                panic!("读不了源文件 {}：{e}（仓内源码不该读不到，静默跳过会让本断言瞎）", f.display())
            });
            let n = t.matches(builder_token).count();
            if n == 0 {
                continue;
            }
            builders += n;
            if !t.contains(wrap_token) {
                failures.push(format!("{}：{n} 个建窗点但 0 处 with_browser_args", f.display()));
            }
            reached.push(f.strip_prefix(&root).unwrap_or(f).display().to_string());
        }
        assert!(builders > 0, "一个建窗点都没扫到——扫描根目录是否变了");
        assert!(
            failures.is_empty(),
            "以下文件有建窗点但没透传浏览器参数（K4 的静默 hwnd=0x0）：{failures:#?}；本次命中的建窗文件：{reached:?}"
        );
        println!("reached 建窗文件（{}）：{reached:?}", reached.len());
    }

    /// R8-L01：`TRIM_DEV_NOACTIVATE` 的判定只许有一处定义；dev 档两条路径都不能落回
    /// 生产分支的 set_focus（旧实现 hwnd 失败时直接抢前台）。
    #[test]
    fn l01_dev_noactivate_has_single_source() {
        let src = prod();
        let needle = concat!("std::env::var(", "\"TRIM_DEV_NOACTIVATE\")");
        assert_eq!(
            src.matches(needle).count(),
            1,
            "环境变量判定只许留在 dev_noactivate 定义处（内联复制品会让两条兜底方向再次分叉）"
        );
        assert!(src.contains("if dev_noactivate() {"), "显示路径必须调用 dev_noactivate()");
        let at = src.find("fn activate_window").expect("activate_window 不见了");
        let tail = &src[at..];
        let end = tail.find("\n}\n").map(|e| at + e).unwrap_or(src.len());
        let body = &src[at..end];
        let dev = &body[body.find("if dev_noactivate()").expect("dev 分支不见了")..];
        assert_eq!(
            dev.matches("return;").count(),
            2,
            "dev 档有 hwnd / 无 hwnd 两条路径都必须返回（不得落回生产分支抢前台）"
        );
    }

    /// R8-L02：`additional_browser_args` 传参即替换，必须把 wry 默认串拼回来。
    #[test]
    fn l02_browser_args_append_wry_defaults() {
        assert_eq!(
            super::WRY_DEFAULT_BROWSER_ARGS,
            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection",
            "默认串必须与 wry 0.55.1 的 WebView2 默认值一致（升级 wry 时重核）"
        );
        let src = prod();
        assert!(
            src.contains("format!(\"{WRY_DEFAULT_BROWSER_ARGS} {extra}\")"),
            "必须拼接 wry 默认串；裸传 extra 会把 msWebOOUI/msPdfOOUI/msSmartScreenProtection 丢掉"
        );
        assert!(!src.contains("additional_browser_args(extra)"), "裸传 extra 的旧形态不得回来");
    }

    /// R8-L03：主窗 label 单一真源，且与 guard::MAIN 同源。
    #[test]
    fn l03_main_label_has_single_source() {
        assert_eq!(super::MAIN_LABEL, "main");
        let src = prod();
        assert_eq!(
            src.matches("\"main\"").count(),
            1,
            "主窗 label 只许在 MAIN_LABEL 定义处出现字面量（建窗/查窗/唤回点必须引用常量）"
        );
        assert_eq!(
            crate::engine::guard::MAIN,
            [super::MAIN_LABEL].as_slice(),
            "guard::MAIN 必须与 MAIN_LABEL 同源"
        );
        assert!(
            crate::engine::guard::APP_WINDOWS.contains(&super::MAIN_LABEL),
            "APP_WINDOWS 必须包含主窗 label"
        );
    }

    /// R8-M01：窗口状态读写必须引用同一常量，且关闭请求上有主写点。
    #[test]
    fn m01_window_state_read_write_single_source() {
        assert_eq!(
            super::WINDOW_STATE_KEY, "windowState",
            "改名会让所有用户的窗口位置恢复静默失效（存量数据键）"
        );
        let src = prod();
        assert_eq!(
            src.matches("\"windowState\"").count(),
            1,
            "键名只许在常量定义处出现一次；读写两侧必须引用常量"
        );
        assert!(src.contains(".get(WINDOW_STATE_KEY)"), "读侧必须引用同一常量");
        assert!(
            src.contains("insert(WINDOW_STATE_KEY.to_string()"),
            "写侧必须引用同一常量"
        );
        assert!(src.contains("CloseRequested"), "CloseRequested 是主写点（窗口还活着，几何可读）");
        assert!(src.contains("save_window_state(&state_window)"), "写侧没挂到窗口事件上");
        assert!(src.contains("save_window_state(&w)"), "RunEvent::Exit 的 best-effort 兜底不见了");
    }

    /// R8-M02：闩锁语义 = 显示成功；失败必须复位并留 warn，不许先占位后吞错。
    #[test]
    fn m02_show_latch_releases_on_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let flag = AtomicBool::new(false);
        assert!(super::claim_show_slot(&flag), "第一条触发路径必须抢到名额");
        assert!(!super::claim_show_slot(&flag), "并发的第二条触发路径不得重复显示");
        flag.store(false, Ordering::SeqCst);
        assert!(
            super::claim_show_slot(&flag),
            "显示失败复位后必须允许 3s/8s 兜底重试（不得永久放弃）"
        );
        let src = prod();
        assert!(src.contains("主窗口显示失败（触发:"), "失败必须留 warn 日志（带拒因）");
        assert!(src.contains("state.shown.store(false"), "失败必须复位闩锁");
        assert!(!src.contains("shown.swap(true"), "旧语义「先占位后做」不得回来");
        assert!(src.contains("show().map_err"), "show 的失败必须进 Result，不许 let _ = 吞掉");
    }

    /// C06 渲染层回执契约（源码形态）：三条「后端给了、前端裁掉/写错」的修法必须留在线上代码里。
    /// 这些字段的最终观感由真机目检确认，但「代码里是否还有这条承诺」可以机械判红。
    #[test]
    fn c06_renderer_receipt_contracts() {
        let cleanup = include_str!("../../src/scripts/cleanup.js");
        assert!(
            cleanup.contains("if (it.ifDeleted) o.ifDeleted = it.ifDeleted;"),
            "F4a1-M01：高危删除后果字段被 pickRuleItem 裁掉了"
        );
        assert!(
            cleanup.contains("o.evidenceItems = it.evidenceItems.map"),
            "F4a1-M01：依据逐条字段被 pickRuleItem 裁掉了"
        );
        let optimizer = include_str!("../../src/scripts/optimizer.js");
        assert!(
            optimizer.contains("'设置已生效 — ' + t.label"),
            "F4b-M01：Toast 副标题必须读 entry.label"
        );
        assert!(
            !optimizer.contains("'设置已生效 — ' + t.title"),
            "F4b-M01：entry 没有 title 字段，读它必然渲染 undefined"
        );
        let ctx = include_str!("../../src/scripts/contextmenu.js");
        assert!(ctx.contains("当前为演示数据，未读写系统"), "F4a2-M05：预览链必须明示演示数据");
        assert!(
            ctx.contains("演示数据：勾选只改本地状态，未写入系统"),
            "F4a2-M05：演示模式的勾选必须提示不写系统"
        );
        assert!(
            ctx.contains("演示数据（未读写系统） · "),
            "F4a2-M05：看板汇总必须带演示标识"
        );
    }

    /// U-A1（v7.2 P1）：前端三态与共享失败态的源码契约。
    #[test]
    fn u_a1_renderer_receipt_contracts() {
        let font = include_str!("../../src/scripts/fontmanager.js");
        assert!(font.contains("resp.success === false"), "A1-L04：字体配置 success:false 未被认领");
        assert!(font.contains("读取字体配置失败"), "A1-L04：失败提示文案不见了");
        let net = include_str!("../../src/scripts/netspeed.js");
        assert!(net.contains("return { up: null, down: null }"), "A1-L05：采样失败必须回 null");
        assert!(net.contains("sampleErrorShown"), "A1-L05：失败状态必须可见且不刷屏");
        let mem = include_str!("../../src/scripts/memoryclean.js");
        assert!(mem.contains("回执字段不完整"), "A1-L06：缺字段不得报成功");
        assert!(mem.contains("resp.success === false"), "A1-L06：命令层判负必须被认领");
        let modal = include_str!("../../src/scripts/modal.js");
        assert!(modal.contains("function errorState"), "A1-L07：共享失败态件不见了");
        assert!(modal.contains("window.errorState = errorState"), "A1-L07：失败态件未导出");
        let ctx = include_str!("../../src/scripts/contextmenu.js");
        assert!(ctx.contains("window.errorState({ title: '扫描失败'"), "A1-L07：失败态件没有消费方");
    }

    /// A1-M12（v7.2 P1）：六个读侧 loader 的 degraded 位必须出现在回执里。
    #[test]
    fn u_a1_degraded_receipts_contract() {
        assert!(include_str!("commands/paths.rs").contains("\"degraded\": degraded"));
        assert!(include_str!("commands/settings.rs").contains("\"degraded\": degraded"));
        assert!(include_str!("commands/appearance.rs").contains("\"degraded\": degraded"));
        assert!(include_str!("commands/optimizer/overview.rs").contains("\"degraded\": degraded"));
        assert!(include_str!("engine/native/syspanel.rs").contains("\"degraded\": degraded"));
        assert!(include_str!("commands/fileclean.rs").contains("o.insert(\"degraded\".into(), json!(degraded))"));
    }

    /// U-A2（v7.2 P1）：Promise 出口与软锁的源码契约（A2-L02 报告后已修，附反向确认）。
    #[test]
    fn u_a2_promise_exit_contracts() {
        assert!(
            include_str!("../../src/scripts/residue-window.js")
                .contains("if (hint) hint.textContent = '正在清理残留…';"),
            "A2-M01：置锁后的 DOM 写必须进 try 且守卫"
        );
        assert!(
            include_str!("../../src/scripts/uninstall.js").contains("running = true;\n    try {"),
            "A2-M02：await 必须移进 try"
        );
        assert!(
            include_str!("../../src/scripts/finder.js").contains("s.scanning = false; // A2-M03"),
            "A2-M03：早退分支必须复位 mutex"
        );
        assert!(
            include_str!("../../src/scripts/memoryclean.js")
                .contains(".finally(() => { memBusy = false; }).catch"),
            "A2-M04：finally 后必须有 catch"
        );
        assert!(
            include_str!("../../src/scripts/optimizer.js").contains("A2-M05"),
            "A2-M05：横幅收起必须受写成功门控"
        );
        assert!(
            include_str!("../../src/scripts/app.js").contains("await window.api?.app?.openExternal?.(url)"),
            "A2-L01：openExternal 必须 await"
        );
        assert!(
            include_str!("../../src/scripts/tauri-api.js").contains("pluginInvoke('minimize').catch"),
            "A2-L03：minimize 必须接 catch"
        );
        assert!(
            include_str!("../../src/scripts/pathbinding.js").contains("背景图列表加载失败"),
            "A2-L02：listBg 链必须有 catch（报告后已修，防回退）"
        );
    }

    /// U-A3（P1-W1）：键盘/读屏可达性的落点契约。渲染层行为本身需真机，
    /// 这里钉住「改回去就红」的源码形状。
    #[test]
    fn u_a3_accessibility_contracts() {
        let litebox = include_str!("../../src/vendor/litebox.js");
        assert!(
            litebox.contains("if (e.ctrlKey || e.altKey || e.metaKey || !consumed) return;"),
            "A3-M01：灯箱 keydown 只许拦截自己消费的键，Tab/修饰键必须交还浏览器"
        );
        assert!(
            !litebox.contains(".title =") && !litebox.contains("|| e.title"),
            "A3-M02：灯箱不许再把 title 当描述/提示（红线：data-tip）"
        );
        assert!(
            litebox.contains("this.getElem('.lightbox-image').alt = caption"),
            "A3-M02：图片描述必须落到 alt"
        );

        assert!(
            include_str!("../../src/scripts/models-window.js").contains("A3-M03")
                && include_str!("../../src/scripts/models-window.js")
                    .contains("if (document.querySelector('.usage-backdrop')) return;"),
            "A3-M03：模型子窗 Esc 必须先判叠层"
        );
        assert!(
            include_str!("../../src/scripts/diskbench.js").contains("A3-M04"),
            "A3-M04：盘测历史弹窗 Esc 必须先判叠层"
        );

        let optimizer = include_str!("../../src/scripts/optimizer.js");
        assert!(
            !optimizer.contains("row.setAttribute('aria-checked'"),
            "A3-M05：aria-checked 不许写在无 role 的行 div 上"
        );
        assert_eq!(
            optimizer.matches("box.setAttribute('aria-checked'").count(),
            4,
            "A3-M05：四个写点（pick 两处 + nara/privacy 行勾选）都必须落在 .checkbox 上"
        );

        let html = include_str!("../../src/index.html");
        for host in [
            "id=\"maintSelCount\"",
            "id=\"maintBatchProgressText\"",
            "id=\"emptyPaneCountFiles\"",
            "id=\"emptyPaneCountDirs\"",
            "id=\"rtSummary\"",
            "id=\"diskBenchStatus\"",
            "id=\"startupTotal\"",
            "id=\"startupEnabled\"",
            "id=\"startupDisabled\"",
            "id=\"startupListCount\"",
        ] {
            assert!(
                html.contains(&format!("{host} role=\"status\" aria-live=\"polite\"")),
                "A3-M06/L01：{host} 是异步文本宿主，必须有 role=status + aria-live"
            );
        }
        assert!(
            include_str!("../../src/residue-window.html")
                .contains("id=\"rsFootHint\" role=\"status\" aria-live=\"polite\""),
            "A3-M06：残留子窗底部提示必须有 aria-live"
        );

        assert!(
            include_str!("../../src/styles/litebox.css").contains("prefers-reduced-motion:reduce")
                && include_str!("../../src/styles/litebox.css").contains("button:focus-visible"),
            "A3-L05：灯箱样式必须自带减动效归零与焦点环（不能只靠挂载点恰好是 body 子代）"
        );
        assert!(
            include_str!("../../src/styles/main.css").contains(".nara-checkrow:has(.checkbox:focus-visible)"),
            "A3-L02：焦点实际落在内层 .checkbox，焦点规则必须指向它"
        );
        assert!(
            include_str!("../../src/styles/main-pages.css")
                .contains(".qc-search-wrap:focus-within {\n  border-color: var(--accent);\n  box-shadow: 0 0 0 2px var(--accent-light);"),
            "A3-L03：搜索框 outline:none 后必须有可见的 2px 替代环"
        );
        assert!(
            include_str!("../../src/styles/main.css").contains(".skin-row select:focus-visible {\n  border-color: var(--accent);\n  outline: 2px solid var(--accent);"),
            "A3-L04：下拉框焦点环必须是实色 outline，不能只有 1px 浅色阴影"
        );

        let ds = include_str!("../../src/scripts/ds.js");
        assert!(
            ds.contains("ds.reducedMotionQuery = reducedMotionQuery;"),
            "A3-L06：MediaQueryList 的缓存/求值必须由 ds 唯一持有"
        );
        for (name, src) in [
            ("app.js", include_str!("../../src/scripts/app.js")),
            ("liquid-glass.js", include_str!("../../src/scripts/liquid-glass.js")),
            ("mouse-trail.js", include_str!("../../src/scripts/mouse-trail.js")),
            ("pathbinding.js", include_str!("../../src/scripts/pathbinding.js")),
            ("spotlight.js", include_str!("../../src/scripts/spotlight.js")),
            ("tilt.js", include_str!("../../src/scripts/tilt.js")),
        ] {
            assert!(
                !src.contains("matchMedia('(prefers-reduced-motion: reduce)')"),
                "A3-L06：{name} 不许再自建 reduced-motion 求值"
            );
        }

        assert!(
            include_str!("../../src/scripts/cleanup.js")
                .contains("btn.setAttribute('aria-label', '删除当前图片（进回收站）');"),
            "A3-U03：灯箱运行时注入的图标按钮必须有可访问名"
        );
    }

    /// U-A5（P1-W1）：进程/句柄卫生的源码形状契约。真机句柄计数不可在快速组做，
    /// 这里钉住「改回旧形状就红」的判据。
    #[test]
    fn u_a5_process_handle_contracts() {
        let systembin = include_str!("engine/systembin.rs");
        assert!(
            systembin.contains("engine::job::ProcessJob::create_for") && systembin.contains("终止未确认"),
            "A5-M01/M02：超时底座必须共用 ProcessJob 收树，且终止证据要进回执"
        );
        assert!(
            include_str!("engine/job.rs").contains("pub(crate) fn terminate"),
            "A5-M02：ProcessJob 必须是 pwsh/systembin 共用实现"
        );

        let list_run = include_str!("commands/uninstall/list_run.rs");
        assert!(
            list_run.contains("UninstallerWait::ExitCodeUnknown")
                && list_run.contains("let read = GetExitCodeProcess")
                && list_run.contains("h.0.is_null()"),
            "A5-M04：等待/读码失败必须独立结局，NULL 句柄也要拦"
        );
        assert!(
            list_run.contains("unwrap_or(pe.szExeFile.len())"),
            "A5-M06：定长 UTF-16 无 NUL 时必须取整段，不能折成空串"
        );

        assert!(
            include_str!("commands/uninstall/dead.rs").contains("expanded.to_ascii_lowercase()")
                && list_run.contains("let low = s.to_ascii_lowercase();"),
            "A5-M07：字节偏移必须与小写化副本同源（禁 full to_lowercase 后再切原串）"
        );

        assert!(
            include_str!("engine/native/startup.rs").contains("let backup_ok = export_out")
                && include_str!("engine/native/startup.rs").contains("m.len() > 0"),
            "A5-M03：reg export 备份必须同时判退出码与文件非空"
        );
        assert!(
            include_str!("engine/native/process.rs").contains("unwrap_or(entry.szExeFile.len())"),
            "A5-M06：顽固软件进程名同样按整段解码"
        );
        assert!(
            include_str!("../../native-scanner/src/cleanup_scan.rs").contains("unwrap_or(pi.strAppName.len())"),
            "A5-M06：Restart Manager 应用名同样按整段解码"
        );

        assert!(
            include_str!("engine/shellicon.rs").contains("destroy_icon_logged")
                && include_str!("engine/native/syspanel.rs").contains("字节数为奇数"),
            "A5-L02/L05：句柄关闭与截断字节必须留痕"
        );
        assert!(
            include_str!("engine/native/contextmenu.rs").contains("已拉起 PID"),
            "A5-L04：fire-and-forget 的 explorer 重启必须留 PID/失败日志"
        );
        assert!(
            include_str!("engine/native/process.rs").contains("WPS 更新注册表（UpdateMode 写入失败）"),
            "A5-L01：注册表写值失败必须进失败台账"
        );
    }

    /// U-A6（P1-W1）：判定的字节必须与执行的字节同源。
    #[test]
    fn u_a6_byte_identity_contracts() {
        let security = include_str!("security/mod.rs");
        assert!(
            security.contains(".create_new(true)") && security.contains("if opened"),
            "A6-L03：原子写临时件必须 create_new，且 open 失败时不得删别人的同名文件"
        );
        assert!(
            include_str!("engine/delete_manifest.rs").contains("fn batch_time_key"),
            "A6-M05：删除清单裁剪/读取必须按解析出的批次时刻排序（C07 前修防回退）"
        );
        assert!(
            security.contains("fn prune_quarantined_depth"),
            "A6-M06：隔离件回收必须递归到子目录产出点（C11 前修防回退）"
        );

        assert!(
            include_str!("diag/mod.rs").contains("pub fn strip_diag_lines")
                && include_str!("pwsh/mod.rs").contains("strip_diag_lines(&stdout, diag_op)"),
            "A6-M07：DIAG 清洗必须无条件执行，不能以调用点登记为条件"
        );

        let net = include_str!("engine/native/runtimes_net.rs");
        assert!(
            !net.contains("winhttp_proxy_configured") && net.contains("fn winhttp_proxy_native"),
            "A6-M08：WinHTTP 代理必须走 API，不得回到本地化 stdout 判据"
        );
        assert!(
            include_str!("engine/native/maintenance.rs").contains("<Enabled>false</Enabled>"),
            "A6-L04：任务禁用态必须读 XML，不得匹配本地化列文本"
        );
        assert!(
            include_str!("commands/fileclean.rs").contains("\"manifestPath\": manifest_path"),
            "A6-L05：manifestPath 必须回执实际写入的对象，不是裸文件名"
        );
    }

    /// C12/C13（P1-W2）：并发写者图与读侧三态/形状的源码契约。
    #[test]
    fn c12_c13_concurrency_and_shape_contracts() {
        let fileclean = include_str!("commands/fileclean.rs");
        assert!(
            fileclean.contains("\"size\": size,") && !fileclean.contains("\"freed\": size,"),
            "R1d-M03：删除清单写侧必须用读侧认的 size 键"
        );
        assert!(
            fileclean.contains("m.get_mut(&slot_key(owner, ty))"),
            "R1d-M04：文件槽必须一次加锁内就改，不能 get→clone→insert"
        );
        assert!(
            include_str!("commands/finder.rs").contains("static EMPTY_IGNORE_LOCK"),
            "R1d-M04：空目录忽略名单的 RMW 必须有域内锁"
        );
        let aidesc = include_str!("commands/aidesc.rs");
        assert!(
            aidesc.contains("static BAIDU_USAGE_LOCK") && aidesc.contains("static AI_CACHE_LOCK")
                && aidesc.contains("fn save_ai_cache_entry"),
            "R1d-M04：百度日计数与简介缓存必须各自串行化"
        );
        let security = include_str!("security/mod.rs");
        assert!(
            security.contains("配置结构不符") && security.contains("隔离改名失败"),
            "R7-M04：结构不符/隔离失败必须留痕"
        );
        assert!(
            include_str!("../../src/scripts/cleanup.js").contains("failedSources")
                && include_str!("../../src/scripts/pathbinding.js").contains("背景图列表读取失败")
                && include_str!("../../src/scripts/syspanel.js").contains("rows: null"),
            "A1-L01/L02/L03：读取失败不得与「没有数据」同形"
        );
    }

    /// U-R5a（P1-W2）：native 执行层的四个收口坐标。
    #[test]
    fn u_r5a_native_contracts() {
        let startup = include_str!("engine/native/startup.rs");
        assert!(
            startup.contains("format!(\"{task_path}{task_name}\")"),
            "R5a-M02：/TN 拼接必须与启用臂同源（task_path 已带尾分隔符）"
        );
        assert!(
            startup.contains("match read_disabled_records()"),
            "R5a-L06：扫描侧必须复用三态读器，不能内联 read_to_string+from_str"
        );
        let cm = include_str!("engine/native/contextmenu.rs");
        assert!(
            cm.contains("item.native_reg_path, enabled_text"),
            "R5a-M09：CLSID 去重键必须带坐标"
        );
        assert!(
            cm.contains("still_explorer"),
            "R5a-L07：终止前必须按句柄重查镜像"
        );
    }

    /// U-R5b（P1-W2）：native 杂项七条。
    #[test]
    fn u_r5b_native_contracts() {
        assert!(
            include_str!("engine/native/paths_scan.rs").contains("fn strip_icon_suffix"),
            "R5b-M02：图标索引后缀必须按末尾逗号剥，不能按首个空格"
        );
        assert!(
            include_str!("engine/native/runtimes_net.rs").contains("delete_manifest::iso_now()"),
            "R5b-M05：collectedAt 必须是 ISO 形态"
        );
        assert!(
            include_str!("commands/peripheral.rs").contains("rest.get(15..)"),
            "R5b-M07：批次名切片必须走 get，避免非字符边界 panic"
        );
        assert!(
            include_str!("engine/native/maintenance.rs").matches("SC_CMD_TIMEOUT").count() >= 2,
            "R5b-M09：sc stop/start 必须用 30s 档而非维护总超时"
        );
        assert!(
            include_str!("engine/native/memory.rs").contains("PROCESS_QUERY_INFORMATION | PROCESS_VM_READ"),
            "R5b-M10：32 位进程内存计数需要更高权限的句柄"
        );
        assert!(
            include_str!("engine/native/syspanel.rs").contains("枚举达到上限"),
            "R5b-M14：电源枚举触顶/失败必须留痕"
        );
        assert!(
            include_str!("engine/sysrestore.rs").contains("《依赖清单》"),
            "R5b-L11：依赖登记指代必须改成现行文档名"
        );
    }

    /// U-R7（P1-W2）：pwsh/security/diag 的十项收口。
    #[test]
    fn u_r7_protocol_and_secret_contracts() {
        let pwsh = include_str!("pwsh/mod.rs");
        assert!(
            pwsh.contains("PowerShell 管道读取错误") && pwsh.contains("fn write_temp_script"),
            "R7-L01/L03：读错误留痕 + 临时脚本写入口收为私有"
        );
        assert!(
            !pwsh.contains("`:45-49`") && !pwsh.contains("`:381-387`"),
            "R7-M06：内部行号引用必须改成稳定锚点"
        );
        let security = include_str!("security/mod.rs");
        assert!(
            security.contains("prune_stale_atomic_temps")
                && security.contains("密钥解密失败")
                && security.contains("非 .json 文件被隔离")
                && security.contains("密钥字段"),
            "R7-L05/L06/L07/L09：临时件回收与密钥形状/失败留痕"
        );
        assert!(
            include_str!("diag/mod.rs").contains("had_crlf"),
            "R7-L10：DIAG 清洗必须保持原文行尾形态"
        );
        assert!(
            include_str!("safestorage.rs")
                .contains("decrypt_dpapi_v1(value: &str, aes_key: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>"),
            "R7-L08：解密出的明文必须由 Zeroizing 持有"
        );
    }

    /// R8-M04：握手返回值必须被消费，builder 分支必须据此补注册单实例。
    #[test]
    fn m04_elevated_takeover_result_is_consumed() {
        let src = prod();
        assert!(
            !src.contains("let _ = commands::elevate::take_over_as_elevated_instance();"),
            "握手返回值被丢弃 = 提权实例永不补注册单实例（R8-M04）"
        );
        assert!(
            src.contains("takeover_released = commands::elevate::take_over_as_elevated_instance()"),
            "返回值必须落到 takeover_released"
        );
        assert!(
            src.contains("if !elevated_relaunch || takeover_released"),
            "builder 分支必须消费 takeover_released（确认让位后才补注册）"
        );
    }
}

#[cfg(test)]
mod startup_housekeeping_tests {
    /// lib.rs 自身：用来把「首帧前同步 / 显示后回收」这条边界钉成常驻断言。
    /// 之所以要数源码而不是跑运行时：这三条触发路径（真实首帧、3s 兜底、8s 兜底）
    /// 都靠线程 + 定时器，无窗口环境里跑不出「排队了几次」，而 v2 方案恰恰是把它们
    /// 混进首帧前才暴露出问题的。
    const SELF: &str = include_str!("lib.rs");

    /// 只取生产段：所有 `#[cfg(test)]` 模块以下不参与计数，避免断言里写的字符串字面量
    /// 本身含有被数的模式（整份文件一起扫会把自己算进接线数，红得莫名其妙）。
    fn prod() -> &'static str {
        let cut = SELF
            .find("#[cfg(test)]")
            .expect("找不到 #[cfg(test)]——断言的截断锚点变了");
        &SELF[..cut]
    }

    /// setup 闭包体（`.setup(|app| {` 到第一个 `Ok(())` 之前）。
    fn setup_body() -> &'static str {
        let src = prod();
        let start = src
            .find(".setup(move |app| {")
            .or_else(|| src.find(".setup(|app| {"))
            .expect("没找到 setup 闭包——lib.rs 结构变了");
        let end = src[start..].find("Ok(())").expect("没找到 setup 闭包结尾");
        &src[start..start + end]
    }

    /// 三条显示路径最多排队一次：闩锁本身是纯逻辑，直接点名断言。
    #[test]
    fn housekeeping_latch_queues_at_most_once() {
        let latch = super::StartupHousekeeping::default();
        assert!(latch.try_schedule(), "首帧握手那条路径必须抢到唯一名额");
        assert!(!latch.try_schedule(), "3s 兜底不得再排一次");
        assert!(!latch.try_schedule(), "8s 兜底不得再排一次");
    }

    /// v3 B1/B2 的分界：回收类任务不许回到首帧前的同步路径，迁移与安全边界不许被挪走。
    #[test]
    fn only_migrations_and_safety_stay_before_show() {
        let body = setup_body();
        for name in [
            "prune_old_logs",
            "prune_quarantined",
            "prune_reports",
            "cleanup_temp_scripts",
        ] {
            assert!(!body.contains(name), "回收任务 {name} 回到了首帧前（v3 B2 的边界被改回去）");
        }
        for name in [
            "migrate_legacy_once",
            "migrate_list_files_once",
            "migrate_bg_opacity_fog",
            "configure_from_app",
            "force_round_corners",
            "apply_material",
            "init_env",
        ] {
            assert!(body.contains(name), "首帧前必须完成的 {name} 不见了（v3 B1）");
        }
    }

    /// 接线数量：调度点一处、临时脚本修剪两处（显示后 + 退出）、其余回收各一处。
    /// 多出来的那份就是「第二真源」，与本仓 §5.16/§7.1 反复踩过的分叉同类。
    #[test]
    fn housekeeping_wiring_is_single_source() {
        let src = prod();
        assert_eq!(
            src.matches("schedule_startup_housekeeping_once(app);").count(),
            1,
            "显示路径上的调度点必须恰好一处（定义行带泛型参数，不以此模式计入）"
        );
        assert_eq!(
            src.matches("pwsh::cleanup_temp_scripts();").count(),
            2,
            "临时脚本修剪只允许「显示后 housekeeping」与「on_app_exit」两处接线"
        );
        for name in [
            "log::prune_old_logs();",
            "crate::security::prune_quarantined(",
            "commands::realtime::prune_reports();",
        ] {
            assert_eq!(src.matches(name).count(), 1, "{name} 出现不止一处——回收口径出现第二真源");
        }
    }
}
