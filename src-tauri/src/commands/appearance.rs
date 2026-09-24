//! appearance 域：窗口材质读写与广播、环境自适应、导入背景图管理
//!
//! 对照源仓库 `Trim/main.js`：4100-4314（8 个通道）、808-818（材质原生映射）、
//! 4136-4213（环境自适应）、7772-7785（启动期电源/透明初始化与订阅）。
//!
//! 与上游的两处**刻意差异**（均属安全口径，勿当笔误回退）：
//! 1. `appearance:bg-delete` 上游是 `fs.unlinkSync` **永久删除**。本实现走回收站
//!    （AGENTS.md §5「删除统一 trashOrUnlink 回收站优先」+ 交接 §3.3.1「不做永久兜底」）。
//!    背景图是用户自己导入的副本，误删应可还原。
//! 2. 上游 `applyNativeMaterialAll('none')` 对 'none' 早退、完全不碰原生层（Electron 只在
//!    建窗参数里设材质）。我们额外清一次 DWM backdrop —— 进程存活期内可能从 mica 切到
//!    none，不清复位会残留半透明背板。`nativeApplied` 回执仍按上游语义对 'none' 给 false。
//!
//! ⚠️ 已知联动缺口：`bg-list` / `bg-import` 回传的绝对路径，渲染层 `pathbinding.js`
//! 会拼成 `file:///` 作为 `<img src>` 与背景图。Tauri 页源是 `http://tauri.localhost`，
//! Chromium 拦 `file:` 子资源 —— 与已登记的 P1 项（fonts copyUrl / fileclean:read-image）
//! 同因，需启用 asset 协议（`tauri.conf.json` assetProtocol scope + index.html CSP 的
//! `img-src asset: http://asset.localhost`）后才会真正显示。本模块**保持上游返回契约不变**，
//! 不改成 dataURL（那是渲染层共享代码，改一处要动两侧）。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, Runtime, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::engine::{guard, log, paths, protect};

/// 材质合法值全集（对照上游 `MATERIAL_NATIVE_MAP` 的键；与
/// `engine::appearance::MATERIALS` 同源，两处必须一起改）
const MATERIALS: &[&str] = &["mica", "mica-alt", "acrylic", "thin-acrylic", "none"];

/// 背景图扩展名白名单（对照上游 dialog filters 与 bg-list 的正则）
const BG_EXTS: &[&str] = &["png", "jpg", "jpeg", "webp", "bmp", "gif"];

// ==================== 环境态（对照 main.js 4139-4150） ====================

/// 电池供电中（会话级降级判据，不改用户存储的偏好）
static ENV_ON_BATTERY: AtomicBool = AtomicBool::new(false);
/// 系统「透明效果」开关为开（读不到按开处理，不误降级）
static ENV_TRANSPARENCY_ON: AtomicBool = AtomicBool::new(true);
/// 电池降级是否**已由本机制施加**。接电时只还原自己降的那一次，避免覆盖用户切换
static BATTERY_SWAPPED: AtomicBool = AtomicBool::new(false);

fn env_payload() -> Value {
    json!({
        "onBattery": ENV_ON_BATTERY.load(Ordering::Relaxed),
        "transparencyOff": !ENV_TRANSPARENCY_ON.load(Ordering::Relaxed),
    })
}

// ==================== 材质应用与广播 ====================

/// 把材质应用到全部存活窗口；单窗失败不影响其余窗口与持久化
/// （Win11 27H2 运行中重设可能不生效，重启后由构造参数保证最终一致）。
/// 返回 nativeApplied：至少一个窗口原生层应用成功。
fn apply_material_all<R: Runtime>(app: &AppHandle<R>, material: &str) -> bool {
    let mut native_applied = false;
    for (label, window) in app.webview_windows() {
        let (effective, ok) = crate::apply_material_outcome(&window, material);
        if ok {
            native_applied = true;
        } else {
            log::write_log(
                "warn",
                &format!("原生窗口材质不可用（{label} / {effective}），使用 CSS 回退"),
            );
        }
    }
    native_applied
}

/// 广播「生效材质」字符串（总开关关闭时为 'none'），主窗 pathbinding 与
/// 子窗 window-material 统一跟随。渲染层以 `target:{kind:'Any'}` 订阅，故全局 emit。
fn broadcast_material<R: Runtime>(app: &AppHandle<R>, effective: &str) {
    let _ = app.emit("appearance:material-changed", effective.to_string());
}

fn broadcast_env<R: Runtime>(app: &AppHandle<R>) {
    let _ = app.emit("appearance:env-state", env_payload());
}

/// 生效材质：总开关关闭一律 'none'（此时所选材质只做记忆）
fn effective_of(material: &str, enabled: bool) -> String {
    if enabled {
        material.to_string()
    } else {
        "none".into()
    }
}

/// 电池供电时亚克力系是否应临时降级为 mica
fn should_swap_to_mica(material: &str, material_enabled: bool, on_battery: bool) -> bool {
    let swappable = material == "acrylic" || material == "thin-acrylic";
    on_battery && material_enabled && swappable
}

/// 电池供电：亚克力系临时降级为 mica，接电恢复用户设置。
/// 窗口最大化时跳过 —— Win11 27H2 运行中重设原生材质可能黑屏，等下次事件再试。
fn apply_battery_material_swap<R: Runtime>(app: &AppHandle<R>, on_battery: bool) {
    let ap = crate::engine::appearance::load_appearance();
    let material_enabled = ap.get("materialEnabled").and_then(|v| v.as_bool()) != Some(false);
    let material = ap
        .get("material")
        .and_then(|v| v.as_str())
        .unwrap_or("mica")
        .to_string();

    let main_maximized = app
        .get_webview_window("main")
        .and_then(|w| w.is_maximized().ok())
        .unwrap_or(false);

    if on_battery && should_swap_to_mica(&material, material_enabled, true) {
        if main_maximized {
            log::write_log("info", "电池供电：窗口处于最大化，材质降级跳过（防 27H2 材质重设风险）");
            return;
        }
        apply_material_all(app, "mica");
        broadcast_material(app, "mica");
        BATTERY_SWAPPED.store(true, Ordering::Relaxed);
        log::write_log("info", "电池供电：窗口材质临时降级为 mica（接电自动恢复）");
    } else if !on_battery && BATTERY_SWAPPED.load(Ordering::Relaxed) {
        if main_maximized {
            return; // 还原路径同上跳过：保持 swapped 标志，等下一次非最大化事件
        }
        BATTERY_SWAPPED.store(false, Ordering::Relaxed);
        let effective = effective_of(&material, material_enabled);
        apply_material_all(app, &effective);
        broadcast_material(app, &effective);
        log::write_log("info", "已接通电源：窗口材质恢复用户设置");
    }
}

// ==================== IPC 命令 ====================

/// appearance:get-material
///
/// 注意默认值：上游此处回退 **'mica-alt'**（设置页卡片默认选中项），
/// 而窗口建窗侧 `getSavedMaterial()` 回退 'mica'。两者本就不同，勿"统一"掉。
#[tauri::command]
pub fn appearance_get_material<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let ap = crate::engine::appearance::load_appearance();
    Ok(json!({
        "material": ap.get("material").and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("mica-alt"),
        "materialEnabled": ap.get("materialEnabled").and_then(|v| v.as_bool()) != Some(false),
    }))
}

/// appearance:set-material — 切换材质：校验 → 落盘 → 应用到全窗 → 广播生效值
#[tauri::command]
pub fn appearance_set_material<R: Runtime>(
    window: WebviewWindow<R>,
    material: Option<String>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let Some(material) = material.filter(|m| MATERIALS.contains(&m.as_str())) else {
        return Ok(json!({ "success": false, "message": "未知的材质" }));
    };
    let app = window.app_handle().clone();
    let mut ap = crate::engine::appearance::load_appearance();
    let enabled = ap.get("materialEnabled").and_then(|v| v.as_bool()) != Some(false);
    if let Some(obj) = ap.as_object_mut() {
        obj.insert("material".into(), json!(material));
    }
    crate::engine::appearance::save_appearance(&ap);

    let effective = effective_of(&material, enabled);
    let native_applied = apply_material_all(&app, &effective);
    broadcast_material(&app, &effective);
    log::write_log(
        "info",
        &format!("窗口材质切换: {material}（总开关{}，生效 {effective}）", if enabled { "开" } else { "关" }),
    );
    Ok(json!({ "success": true, "nativeApplied": native_applied }))
}

/// appearance:set-material-enabled — 材质总开关。
/// 关闭 = 生效材质置 none（各窗口即时不透明），所选材质保留记忆。
#[tauri::command]
pub fn appearance_set_material_enabled<R: Runtime>(
    window: WebviewWindow<R>,
    enabled: Option<bool>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let on = enabled.unwrap_or(false);
    let app = window.app_handle().clone();
    let mut ap = crate::engine::appearance::load_appearance();
    let material = ap
        .get("material")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("mica")
        .to_string();
    if let Some(obj) = ap.as_object_mut() {
        obj.insert("materialEnabled".into(), json!(on));
    }
    crate::engine::appearance::save_appearance(&ap);

    // 此处回退 'mica'（对齐上游 4243 行），与 get-material 的 'mica-alt' 默认值不同是刻意：
    // 开关侧要的是「恢复到一个能看的材质」，展示侧要的是「设置页默认高亮项」。
    let effective = effective_of(&material, on);
    let native_applied = apply_material_all(&app, &effective);
    broadcast_material(&app, &effective);
    log::write_log(
        "info",
        &format!("窗口材质总开关: {}（生效材质 {effective}）", if on { "开启" } else { "关闭" }),
    );
    Ok(json!({
        "success": true,
        "material": effective,
        "materialEnabled": on,
        "nativeApplied": native_applied,
    }))
}

/// appearance:get-env — 环境降级态只读快照（渲染层液态玻璃引擎消费）
#[tauri::command]
pub fn appearance_get_env<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    Ok(env_payload())
}

// ==================== 背景图文件管理 ====================

/// 导入的背景图统一复制到 `<数据目录>/backgrounds` 持久保存；删除按文件名移除。
fn bg_dir() -> PathBuf {
    paths::app_data_dir().join("backgrounds")
}

/// 词法绝对化 + 小写化（Windows 路径大小写不敏感），不触盘、可折叠 `..`
fn path_key(p: &Path) -> String {
    std::path::absolute(p)
        .unwrap_or_else(|_| p.to_path_buf())
        .to_string_lossy()
        .to_lowercase()
}

fn bg_ext_ok(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| BG_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// appearance:bg-import — 原生对话框选图 → 复制到 backgrounds
#[tauri::command]
pub fn appearance_bg_import<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let picked = window
        .dialog()
        .file()
        .set_title("选择背景图片")
        .add_filter("图片文件", BG_EXTS)
        .blocking_pick_file();
    let Some(picked) = picked else {
        return Ok(json!({ "success": false, "canceled": true }));
    };
    let src = match picked.into_path() {
        Ok(p) => p,
        Err(e) => return Ok(json!({ "success": false, "message": format!("无效路径: {e}") })),
    };
    let file_name = src
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    if !bg_ext_ok(&file_name) {
        return Ok(json!({ "success": false, "message": "所选文件不是受支持的图片格式" }));
    }
    let dir = bg_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log::write_log("error", &format!("创建背景图目录失败: {e}"));
        return Ok(json!({ "success": false, "message": e.to_string() }));
    }
    let ext = src
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e.to_ascii_lowercase()))
        .unwrap_or_else(|| ".png".into());
    let dest = dir.join(format!("bg_{}{ext}", crate::engine::now_ms()));
    // 审查 L9：先量体积再拷。扩展名白名单挡不住一个 4 GB 的 .png —— 这条命令是同步的
    // （对话框本身要阻塞主线程），无上限的 fs::copy 会把 UI 钉死并写满数据盘。
    const MAX_BG_BYTES: u64 = 50 * 1024 * 1024;
    match std::fs::metadata(&src) {
        Ok(m) if m.len() > MAX_BG_BYTES => {
            return Ok(json!({
                "success": false,
                "message": format!("图片过大（{} MB），背景图上限 50 MB", m.len() / 1024 / 1024),
            }));
        }
        Ok(_) => {}
        Err(e) => return Ok(json!({ "success": false, "message": e.to_string() })),
    }
    match std::fs::copy(&src, &dest) {
        Ok(_) => {
            let name = dest
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            log::write_log("info", &format!("导入背景图片: {name}"));
            Ok(json!({
                "success": true,
                "data": { "path": dest.to_string_lossy(), "name": name },
            }))
        }
        Err(e) => {
            log::write_log("error", &format!("导入背景图片失败: {e}"));
            Ok(json!({ "success": false, "message": e.to_string() }))
        }
    }
}

/// appearance:bg-delete — 仅允许删 backgrounds 目录的**直接子项**（上游同款约束），
/// 且拒绝符号链接目标；删除走回收站（见文件头差异 1）。
#[tauri::command]
pub fn appearance_bg_delete<R: Runtime>(
    window: WebviewWindow<R>,
    file: Option<String>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let dir = bg_dir();
    let raw = file.unwrap_or_default();
    if raw.trim().is_empty() {
        return Ok(json!({ "success": false, "message": "路径无效" }));
    }
    let target = PathBuf::from(&raw);
    // 必须是 backgrounds 的直接子项：既挡 `..\..\windows\...` 穿越，也挡子目录逃逸
    if target.parent().map(path_key).as_deref() != Some(path_key(&dir).as_str()) {
        log::write_log("warn", &format!("拒绝删除背景图目录外的路径: {raw}"));
        return Ok(json!({ "success": false, "message": "路径无效" }));
    }
    if !bg_ext_ok(&raw) {
        return Ok(json!({ "success": false, "message": "路径无效" }));
    }
    // 名字受控但父目录可能被换成交换点，删除前再确认目标自身不是链接。
    // 审查 v2-L12：判据用 `protect::is_reparse`（属性位 0x400）而不是 `is_symlink()` ——
    // 后者在 Windows 上只认 SYMLINK/MOUNT_POINT 两种 tag，OneDrive 云占位符那类
    // `is_symlink=false && is_dir=true` 的 reparse 会被放过去，等于删到另一块存储上。
    match std::fs::symlink_metadata(&target) {
        Ok(meta) if protect::is_reparse(&meta) => {
            return Ok(json!({ "success": false, "message": "拒绝删除符号链接目标" }));
        }
        Err(_) => return Ok(json!({ "success": true })), // 不存在 = 幂等成功（对齐上游 existsSync 短路）
        Ok(_) => {}
    }
    let p = target.to_string_lossy().to_string();
    if protect::is_path_protected(&p) {
        return Ok(json!({ "success": false, "message": "该路径受保护，已拒绝删除" }));
    }
    // 审查 M11：删除前把缓冲日志刷盘（AGENTS §3）。此处是「用户文件进回收站」的出口，
    // 若紧随其后的操作让进程异常退出，未落盘的日志会让这次删除无从追溯。
    log::flush_sync();
    match trim_finder::scan::recycle::send_to_trash(&p) {
        Ok(()) => Ok(json!({ "success": true })),
        Err(e) => {
            log::write_log("error", &format!("背景图片移入回收站失败: {e}"));
            Ok(json!({ "success": false, "message": e.to_string() }))
        }
    }
}

/// appearance:bg-list — 列出 backgrounds 下的图片，按文件名倒序
#[tauri::command]
pub fn appearance_bg_list<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let dir = bg_dir();
    if !dir.is_dir() {
        return Ok(json!({ "success": true, "data": [] }));
    }
    let mut files: Vec<Value> = Vec::new();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !bg_ext_ok(&name) || !entry.path().is_file() {
                    continue;
                }
                files.push(json!({ "path": entry.path().to_string_lossy(), "name": name }));
            }
        }
        Err(e) => return Ok(json!({ "success": false, "data": [], "message": e.to_string() })),
    }
    // 上游是 `b.name.localeCompare(a.name)`；文件名为定长 `bg_<ms>.<ext>`，
    // 定长同宽下序数倒序与词典倒序结果一致。
    files.sort_by(|a, b| {
        let an = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let bn = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
        bn.cmp(an)
    });
    Ok(json!({ "success": true, "data": files }))
}

/// appearance:bg-open-dir — mkdir -p 后用系统 Shell 打开目录
#[tauri::command]
pub fn appearance_bg_open_dir<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let dir = bg_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Ok(json!({ "success": false, "message": e.to_string() }));
    }
    open_folder(&dir);
    Ok(json!({ "success": true }))
}

/// 用 Explorer 打开目录（不经 shell 拼接命令，避免命令注入）
fn open_folder(dir: &Path) {
    let arg = format!("/select,{}", dir.to_string_lossy().replace('/', "\\"));
    let _ = std::process::Command::new("explorer.exe").arg(&arg).spawn();
}

// ==================== 启动期环境自适应接线 ====================

/// 启动期初始化环境态，并挂电源事件监听（对照 main.js 7772-7785）。
/// 由 lib.rs setup 调用。
pub fn init_env<R: Runtime>(app: &AppHandle<R>) {
    ENV_ON_BATTERY.store(power::query_on_battery(), Ordering::Relaxed);
    ENV_TRANSPARENCY_ON.store(query_sys_transparency(), Ordering::Relaxed);
    broadcast_env(app);
    apply_battery_material_swap(app, ENV_ON_BATTERY.load(Ordering::Relaxed));
    log::write_log(
        "info",
        &format!(
            "环境自适应就绪: 电池={} 系统透明效果={}",
            if ENV_ON_BATTERY.load(Ordering::Relaxed) { "是" } else { "否" },
            if ENV_TRANSPARENCY_ON.load(Ordering::Relaxed) { "开" } else { "关" },
        ),
    );
    let app_watch = app.clone();
    power::spawn_watcher(move || on_power_event(&app_watch));
}

/// 电源事件回调（由本文件 `power` 子模块的消息线程调用）：重读两个环境量，
/// 只在**变化**时广播并做材质降级/还原 —— 上游是 OS 推送，这里等价复刻。
fn on_power_event<R: Runtime>(app: &AppHandle<R>) {
    let battery = power::query_on_battery();
    let battery_changed = ENV_ON_BATTERY.swap(battery, Ordering::Relaxed) != battery;
    let transparency = query_sys_transparency();
    let transparency_changed =
        ENV_TRANSPARENCY_ON.swap(transparency, Ordering::Relaxed) != transparency;
    if !battery_changed && !transparency_changed {
        return;
    }
    broadcast_env(app);
    if battery_changed {
        apply_battery_material_swap(app, battery);
    }
}

/// 读系统「透明效果」开关（HKCU `…\Personalize` / `EnableTransparency`）。
/// 读不到按**开启**处理，避免在无该键的旧系统上误降级（对齐上游注释）。
/// 走 `reg.exe` 而非注册表 API：与 `commands::misc::detect_dwm_inject_tools`
/// 同源姿势，且不为一个低频只读查询新增 windows crate feature。
fn query_sys_transparency() -> bool {
    let out = std::process::Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "/v",
            "EnableTransparency",
        ])
        .output();
    let Ok(out) = out else { return true };
    let text = String::from_utf8_lossy(&out.stdout);
    // 形如：    EnableTransparency    REG_DWORD    0x1
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if it.next() != Some("EnableTransparency") {
            continue;
        }
        if let Some(hex) = it.find(|t| t.starts_with("0x") || t.starts_with("0X")) {
            return u32::from_str_radix(&hex[2..], 16).map(|v| v != 0).unwrap_or(true);
        }
    }
    true
}

/// 电源事件源（方案 §121「Rust 侧电源事件复刻」）
///
/// Electron 用 `powerMonitor.on('on-battery' | 'on-ac' | 'resume')`。Win32 侧的等价物是
/// `WM_POWERBROADCAST`：系统以 HWND_BROADCAST 投递给**所有顶层窗口**，因此必须真的建一个
/// 顶层窗口才收得到 —— 消息专用窗口（HWND_MESSAGE）收不到广播，这是常见误区。
/// 这里建一个 0×0、不可见、不进任务栏的 WS_POPUP 窗口跑独立消息循环，
/// 收到电源相关消息后置标志，循环据此回调上层判据。
///
/// 无电池台式机（本机即是）：`GetSystemPowerStatus` 报 ACLineStatus=1/255，
/// `query_on_battery()` 恒 false，监听线程全程空转不触发降级 —— 属预期，非未生效。
#[cfg(windows)]
mod power {
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        PostQuitMessage, RegisterClassExW, TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT,
        MSG, WM_POWERBROADCAST, WNDCLASSEXW, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_POPUP,
    };

    const PBT_APMPOWERSTATUSCHANGE: usize = 0x0004;
    const PBT_APMRESUMEAUTOMATIC: usize = 0x0012;
    const PBT_APMRESUMESUSPEND: usize = 0x0007;

    /// 电源状态变化待处理标志（wndproc 置位，消息循环消费）
    static PENDING: AtomicBool = AtomicBool::new(false);

    /// 是否处于电池供电。
    /// ACLineStatus：0=离线(电池)、1=在线(市电)、255=未知；无电池台式机恒非 0。
    /// 只在「明确离线」时降级，查询失败按市电处理 —— 与系统透明开关同口径，宁不误降。
    pub fn query_on_battery() -> bool {
        unsafe {
            let mut st = SYSTEM_POWER_STATUS::default();
            GetSystemPowerStatus(&mut st).is_ok() && st.ACLineStatus == 0
        }
    }

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_POWERBROADCAST
            && matches!(
                wparam.0,
                PBT_APMPOWERSTATUSCHANGE | PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND
            )
        {
            PENDING.store(true, Ordering::Relaxed);
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }

    /// 启动监听线程并把「变化时做什么」以闭包传进来 —— 闭包在此层完成类型擦除，
    /// 上层只需捕获自己的 `AppHandle<R>`，本模块因此与 Tauri 泛型无耦合。
    ///
    /// 分离线程、不 join：消息循环设计上是常驻的，join 会永久阻塞调用方。
    /// 注册/建窗失败在线程内自行记日志并放弃降级 —— 材质退回用户设置值，
    /// 不影响任何功能（可损失的视觉增强，不是正确性依赖）。
    pub fn spawn_watcher<F: Fn() + Send + 'static>(on_change: F) {
        std::thread::spawn(move || {
            if !watcher_main(on_change) {
                crate::engine::log::write_log(
                    "warn",
                    "电源事件监听未就绪（窗口注册/创建失败）：电池供电材质降级不可用",
                );
            }
        });
    }

    fn watcher_main<F: Fn()>(on_change: F) -> bool {
        let class_name: Vec<u16> = "TrimPowerWatcher\0".encode_utf16().collect();
        unsafe {
            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(wndproc),
                hInstance: HINSTANCE::default(),
                lpszClassName: PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };
            // 类已注册（重复启动）时返回 0 —— 复用既有类继续跑，不当失败
            let _ = RegisterClassExW(&wc);
            let name = PCWSTR(class_name.as_ptr());
            let Ok(hwnd) = CreateWindowExW(
                WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                name,
                name,
                WS_POPUP,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                0,
                0,
                None,
                None,
                None,
                None,
            ) else {
                return false;
            };
            if hwnd.is_invalid() {
                return false;
            }
            // GetMessageW 阻塞期零 CPU；hwnd 传 None = 收取本线程所有窗口的消息
            // （WM_POWERBROADCAST 是广播投递进来的，绑定单窗过滤会漏）
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
                if PENDING.swap(false, Ordering::Relaxed) {
                    on_change();
                }
            }
            let _ = DestroyWindow(hwnd);
            PostQuitMessage(0);
            true
        }
    }
}

/// 非 Windows 平台无电源广播机制：环境量固定为「市电 + 透明开」，不降级。
#[cfg(not(windows))]
mod power {
    pub fn query_on_battery() -> bool {
        false
    }
    pub fn spawn_watcher<F: Fn() + Send + 'static>(_on_change: F) {}
}



// ==================== 纯函数单测 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_of_置零_when_disabled() {
        assert_eq!(effective_of("acrylic", true), "acrylic");
        assert_eq!(effective_of("acrylic", false), "none");
        assert_eq!(effective_of("none", true), "none");
    }

    #[test]
    fn 电池降级仅作用于亚克力系且需总开关开() {
        assert!(should_swap_to_mica("acrylic", true, true));
        assert!(should_swap_to_mica("thin-acrylic", true, true));
        // 总开关关闭：本就 no-op，不该再降级
        assert!(!should_swap_to_mica("acrylic", false, true));
        // mica 系不降（上游只有亚克力系耗电差异）
        assert!(!should_swap_to_mica("mica", true, true));
        assert!(!should_swap_to_mica("mica-alt", true, true));
        // 非电池态不降
        assert!(!should_swap_to_mica("acrylic", true, false));
    }

    #[test]
    fn 材质白名单拒绝未知值() {
        assert!(MATERIALS.contains(&"thin-acrylic"));
        assert!(!MATERIALS.contains(&"Mica"));
        assert!(!MATERIALS.contains(&"blur-behind"));
        assert!(!MATERIALS.contains(&""));
    }

    #[test]
    fn 背景图扩展名判定只认白名单() {
        assert!(bg_ext_ok("bg_1700.png"));
        assert!(bg_ext_ok("a.JPEG"));
        assert!(bg_ext_ok("a.webp"));
        assert!(!bg_ext_ok("a.exe"));
        assert!(!bg_ext_ok("noext"));
        assert!(!bg_ext_ok("a.png.txt"));
    }

    #[test]
    fn 背景图删除必须落在目录直接子项内() {
        let dir = PathBuf::from(r"C:\Users\x\AppData\Roaming\com.xiaoxu.trim\backgrounds");
        let inside = dir.join("bg_1.png");
        assert_eq!(inside.parent().map(path_key), Some(path_key(&dir)));
        // 穿越：backgrounds\..\appearance.json 的父目录是数据目录，不等
        let escape = dir.join(r"..\appearance.json");
        assert_ne!(PathBuf::from(escape).parent().map(path_key), Some(path_key(&dir)));
        // 子目录逃逸
        let sub = dir.join("nested").join("x.png");
        assert_ne!(sub.parent().map(path_key), Some(path_key(&dir)));
        // 大小写与正斜杠差异应视为同一目录
        let upper = dir.to_string_lossy().to_uppercase();
        let alt = PathBuf::from(upper.as_str()).join("bg_1.png");
        assert_eq!(alt.parent().map(path_key), Some(path_key(&dir)));
    }

    #[test]
    fn 环境态载荷字段与上游一致() {
        let v = env_payload();
        assert!(v.get("onBattery").is_some());
        assert!(v.get("transparencyOff").is_some());
        assert_eq!(v["transparencyOff"], json!(false));
    }
}
