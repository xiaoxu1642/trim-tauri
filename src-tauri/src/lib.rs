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

use tauri::{AppHandle, LogicalPosition, LogicalSize, Manager, Runtime, WebviewWindow};
use windows::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND,
};
use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_SHOWNOACTIVATE};

use crate::engine::{appearance, log, paths, sysinfo};

const APP_NAME: &str = "Trim";
/// 主窗口最小内容区（AGENTS.md 红线：1294×870）
const MIN_WIDTH: f64 = 1294.0;
const MIN_HEIGHT: f64 = 870.0;

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
    /// `pub(crate)` 是为了让首帧看门狗（commands::app）能读到它——
    /// 看门狗不另建一份状态，避免「两个真相判断界面是否画出来了」。
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

// ==================== 子窗口显示 / 聚焦（开发期后台回归开关） ====================

/// 开发期「不激活前台」开关（与 `show_main_window_when_ready` 用同一环境变量）。
///
/// 存在意义：弹窗类通道（preview / processManager / models）若在 CDP 后台回归时按生产语义
/// `show()+set_focus()`，会把窗口弹到用户前台——这与「调试期不打扰用户」的硬性约束冲突。
/// 故开发期改用 `SW_SHOWNOACTIVATE`（显示但不抢焦点），生产环境行为完全不变。
pub fn dev_noactivate() -> bool {
    std::env::var("TRIM_DEV_NOACTIVATE").as_deref() == Ok("1")
}

/// 把 `WEBVIEW2_ADDITIONAL_BROWSER_ARGS` 环境变量透传给 builder（审查 K4 复盘）。
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
            builder = builder.additional_browser_args(extra);
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
pub fn show_main_window_when_ready<R: Runtime>(app: &AppHandle<R>, cause: &str) {
    let state = app.state::<ShowState>();
    if state.shown.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Some(window) = app.get_webview_window("main") {
        if state.maximized {
            // 最大化前移到 show 之前，避免 show 后可见的尺寸跳变/边框重绘
            let _ = window.maximize();
        }
        force_round_corners(&window);
        // 开发期 CDP 后台调试开关：TRIM_DEV_NOACTIVATE=1 时窗口显示但不激活前台，
        // 避免真机调试抢占用户桌面（仅调试构建使用，发布链路不带此变量）。
        if std::env::var("TRIM_DEV_NOACTIVATE").as_deref() == Ok("1") {
            // SW_SHOWNOACTIVATE(4)：显示窗口但不抢输入焦点/不置顶前台
            if let Ok(hwnd) = window.hwnd() {
                let _ = unsafe { ShowWindow(hwnd, SW_SHOWNOACTIVATE) };
            }
        } else {
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
    log::write_log("info", &format!("主窗口显示（触发: {cause}）"));
    // v3 B3：显示动作落地之后才排队 housekeeping。真实首帧握手与 3s / 8s 两级兜底都经过
    // 这个函数，所以渲染脚本白屏时清理照样会跑；下面的闩锁保证三条路径最多排队一次。
    schedule_startup_housekeeping_once(app);
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
        commands::syspanel::syspanel_pagefile_state,
        commands::syspanel::syspanel_pagefile_apply,
        commands::overview::overview_metrics,
        commands::overview::overview_hardware,
        commands::overview::overview_checkup,
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
        // ---- B 批：memory（6）+ processManager 窗口（2+send）+ preview 窗口（2+send）----
        commands::memory::memory_info,
        commands::memory::memory_clean,
        commands::memory::memory_processes,
        commands::memory::memory_kill,
        commands::memory::memory_stubborn_kill,
        commands::memory::memory_stubborn_block,
        commands::processmanager::process_manager_open_window,
        commands::processmanager::process_manager_close_window,
        commands::processmanager::process_manager_report,
        commands::preview::preview_open_window,
        commands::preview::preview_close_window,
        commands::preview::preview_image_deleted,
        // v0.5.0 残留扫描副窗（label `residue`，与 guard::APP_WINDOWS / capabilities 同步）
        commands::residue::residue_open_window,
        commands::residue::residue_close_window,
        // v0.7.0 第四期：右键菜单动作面板（新副窗，四处同步之一）
        commands::actions::actions_open_window,
        commands::actions::actions_close_window,
        commands::actions::actions_list,
        commands::actions::actions_apply,
        commands::actions::actions_remove,
        commands::actions::actions_run_script,
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
        commands::cleanup::cleanup_retry_failed_delete,
        commands::cleanup::cleanup_check_locked,
        commands::cleanup::cleanup_kill_locked_processes,
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
        commands::fileclean::fileclean_read_image,
        commands::fileclean::fileclean_delete_file,
        commands::fileclean::fileclean_execute,
        commands::maintenance::maintenance_tasks,
        commands::maintenance::maintenance_run,
        commands::contextmenu::contextmenu_scan,
        commands::contextmenu::contextmenu_backup,
        commands::contextmenu::contextmenu_remove,
        commands::contextmenu::contextmenu_toggle,
        commands::contextmenu::contextmenu_restore,
        commands::contextmenu::contextmenu_icons,
        commands::contextmenu::contextmenu_open_in_regedit,
        commands::contextmenu::contextmenu_restart_explorer,
        commands::contextmenu::contextmenu_win11_classic,
        commands::contextmenu::contextmenu_blocked_list,
        commands::startup::startup_scan,
        commands::startup::startup_toggle,
        commands::startup::startup_delete,
        commands::startup::startup_openlocation,
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
    let takeover_released = if elevated_relaunch {
        commands::elevate::take_over_as_elevated_instance()
    } else {
        true
    };

    let builder = build_app(tauri::Builder::default())
        .plugin(tauri_plugin_dialog::init())
        // updater 插件必须注册：`UpdaterExt::updater_builder()` 直接取插件的
        // `state::<UpdaterState>()`，未注册会 panic 而不是报错。
        // 线路端点由 commands::updater 按用户偏好逐个传入（覆盖 conf 的 endpoints），
        // 而**公钥只从 conf 读**——它必须是编译期固化的信任锚点，不能由运行时决定。
        .plugin(tauri_plugin_updater::Builder::new().build());

    #[cfg(desktop)]
    let builder = if elevated_relaunch && !takeover_released {
        builder
    } else {
        builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // 对照 main.js 57-62：再次启动应用 = 把已有主窗口唤回前台，而不是开第二个
            if let Some(w) = app.get_webview_window("main") {
                if w.is_minimized().unwrap_or(false) {
                    let _ = w.unminimize();
                }
                focus_window(&w);
            }
        }))
    };

    builder
        .setup(|app| {
            // 窗口在代码中创建（而非 tauri.conf.json 声明），唯一原因：需要
            // additional_browser_args 显式透传 WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
            // ——实测 Tauri/wry 2.11 自带默认浏览器参数时，WebView2 加载器会忽略该环境变量，
            // 导致 CDP 远程调试端口起不来（Phase 0 结论，B2 已记录）。
            use tauri::{WebviewUrl, WebviewWindowBuilder};
            let builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
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
                .get("windowState")
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
            // shown 表示「显示调用抢到了名额」，不代表窗口真的画出来了；把它当业务状态
            // 复用，白屏路径与兜底路径的清理会绑成同一个真相，很难判「到底排队了几次」。
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
        .run(|_app, event| {
            // 唯一退出钩子：覆盖窗口关闭、shutdown:complete、异常退出三条路径
            if let tauri::RunEvent::Exit = event {
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
    /// 这条约束是 K4 用一次误判换来的——不透传浏览器参数时同一 WebView2 user-data-folder 下
    /// 第二个 core 建不出来，而 `build()` 照样返回 Ok、`get_webview_window` 照样查得到，
    /// 只有 `hwnd=0x0`；靠人在每个新窗口记得它是必漏的，所以这里直接数源码。
    /// 只读文本、不建窗口、不依赖运行时；定义行写成 `with_browser_args<R>(` 故不计入调用数。
    #[test]
    fn every_window_builder_goes_through_browser_args() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rs_files(&root, &mut files);
        let (mut builders, mut guarded) = (0usize, 0usize);
        for f in &files {
            let Ok(t) = std::fs::read_to_string(f) else { continue };
            builders += t.matches("WebviewWindowBuilder::new(").count();
            guarded += t.matches("with_browser_args(").count();
        }
        assert!(builders > 0, "一个建窗点都没扫到——扫描根目录是否变了");
        assert_eq!(
            builders, guarded,
            "建窗点数 {builders} ≠ with_browser_args 调用数 {guarded}：有窗口没透传浏览器参数（K4 的静默 hwnd=0x0）"
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

    /// 只取生产段（本测试模块以下不参与计数）：断言里写的字符串字面量本身含有被数的
    /// 模式，整份文件一起扫会把自己算进接线数，红得莫名其妙。
    fn prod() -> &'static str {
        let cut = SELF
            .find("mod startup_housekeeping_tests")
            .expect("找不到本测试模块——断言的截断锚点变了");
        &SELF[..cut]
    }

    /// setup 闭包体（`.setup(|app| {` 到第一个 `Ok(())` 之前）。
    fn setup_body() -> &'static str {
        let src = prod();
        let start = src.find(".setup(|app| {").expect("没找到 setup 闭包——lib.rs 结构变了");
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