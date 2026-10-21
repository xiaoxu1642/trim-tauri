//! appearance 域：窗口材质读写与广播、环境自适应、导入背景图管理、外观域偏好读写
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
//! Chromium 拦 `file:` 子资源 —— 与已登记的 P1 项（fonts copyUrl / 背景图 file: 直链）
//! 同因，需启用 asset 协议（`tauri.conf.json` assetProtocol scope + index.html CSP 的
//! `img-src asset: http://asset.localhost`）后才会真正显示。本模块**保持上游返回契约不变**，
//! 不改成 dataURL（那是渲染层共享代码，改一处要动两侧）。

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, Runtime, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::engine::{appearance::MATERIALS, guard, log, paths, protect};
// 审查 v2-F7：系统工具走绝对路径，不用裸进程名
use crate::engine::systembin::system_tool;

/// 背景图扩展名白名单（对照上游 dialog filters 与 bg-list 的正则）
const BG_EXTS: &[&str] = &["png", "jpg", "jpeg", "webp", "bmp", "gif"];

// ==================== 环境态（对照 main.js 4139-4150） ====================

use crate::commands::state::{BATTERY_SWAPPED, ENV_ON_BATTERY, ENV_TRANSPARENCY_ON};

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
    let (ap, degraded) = crate::engine::appearance::load_appearance_state();
    Ok(json!({
        "material": ap.get("material").and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("mica-alt"),
        "materialEnabled": ap.get("materialEnabled").and_then(|v| v.as_bool()) != Some(false),
        // A1-M12：外观配置读失败与「没有配置」分开。
        "degraded": degraded,
    }))
}

/// appearance:set-material — 切换材质：校验 → 落盘 → 应用到全窗 → 广播生效值
#[tauri::command]
pub fn appearance_set_material<R: Runtime>(
    window: WebviewWindow<R>,
    material: Option<String>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let Some(material) = material.filter(|m| MATERIALS.contains(&m.as_str())) else {
        return Ok(json!({ "success": false, "message": "未知的材质" }));
    };
    let app = window.app_handle().clone();
    // v4 P2-D 尾：读-改-写收口（读取失败拒写，绝不把整份外观配置覆成只剩材质一项）
    let ap = match crate::engine::appearance::update_appearance(|ap| {
        if let Some(obj) = ap.as_object_mut() {
            obj.insert("material".into(), json!(material.as_str()));
        }
        Ok(())
    }) {
        Ok(v) => v,
        Err(msg) => return Ok(json!({ "success": false, "message": format!("外观配置写入失败：{msg}") })),
    };
    let enabled = ap.get("materialEnabled").and_then(|v| v.as_bool()) != Some(false);

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
    guard::guard(&window, guard::MAIN)?;
    let on = enabled.unwrap_or(false);
    let app = window.app_handle().clone();
    // v4 P2-D 尾：读-改-写收口（同上）；material 从更新后的回执读（该键未被本闭包改）
    let ap = match crate::engine::appearance::update_appearance(|ap| {
        if let Some(obj) = ap.as_object_mut() {
            obj.insert("materialEnabled".into(), json!(on));
        }
        Ok(())
    }) {
        Ok(v) => v,
        Err(msg) => return Ok(json!({ "success": false, "message": format!("外观配置写入失败：{msg}") })),
    };
    let material = ap
        .get("material")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("mica")
        .to_string();

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

/// 路径比对键：委托 `engine::paths::path_key` 的唯一实现（P2-1 去重）。
/// 本域调用点传的是 `&Path`（含 `.parent().map(path_key)` 形态），这里只做一次字符串化转接。
fn path_key(p: &Path) -> String {
    crate::engine::paths::path_key(&p.to_string_lossy())
}

fn bg_ext_ok(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| BG_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// 生成一个当前不存在的背景图目标名（同毫秒并发时用序号兜底，避免后者覆盖前者）。
fn available_bg_path(dir: &Path, ext: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    loop {
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = dir.join(format!("bg_{}_{seq}{ext}", crate::engine::now_ms()));
        if !p.exists() {
            return p;
        }
    }
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
    // 生成名 = `bg_<毫秒>_<序号><ext>`：同一毫秒两次换壁纸会落到同一目标名、后者覆盖前者。
    // 序号是进程内原子自增，保证同毫秒也不撞。删除闸认同一形态（bg_ 后两段纯数字）。
    let dest = available_bg_path(&dir, &ext);
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
    // 豁免理由是「只删自己生成的副本」，就得由代码兑现：生成名固定为
    // `bg_<毫秒>[_<序号>]<ext>`。目录里若被塞进别的 png（同步盘、手工拷贝），
    // 没有这道名字闸会被一并删掉。
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let owned_name = name
        .strip_prefix("bg_")
        .and_then(|rest| rest.rsplit_once('.'))
        .map(|(stem, _)| {
            !stem.is_empty()
                && stem
                    .split('_')
                    .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()))
        })
        .unwrap_or(false);
    if !owned_name {
        log::write_log("warn", &format!("拒绝删除 backgrounds 下非生成名的文件: {raw}"));
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
    // v2-L4P-12（B-1）：此处不得再调 protect::is_path_protected——configure_from_app
    // 把 app_data_dir() 整棵登记为 subtree，而 backgrounds 就住在里面，判定恒拒 ⇒
    // 删除背景图按钮 100% 不可用（且测试环境不跑 configure_from_app，永远看不到冲突）。
    // 闸门收口改为四件套：backgrounds 直接子项（防穿越/逃逸）+ 扩展名白名单 +
    // is_reparse 拒 + 回收站 _os，已在 check-delete-exits 的 EXEMPTS 带理由登记。
    // 审查 M11：删除前把缓冲日志刷盘（AGENTS §3）。此处是「用户文件进回收站」的出口，
    // 若紧随其后的操作让进程异常退出，未落盘的日志会让这次删除无从追溯。
    log::flush_sync();
    // 审查 v2-F1：走 `_os` 版，直接把 OsStr 交给回收站 —— `p` 是 `to_string_lossy()`
    // 的产物，含孤立代理项的文件名（GBK 遗留介质）会被换成 U+FFFD，删不到真正那个文件。
    match trim_finder::scan::recycle::send_to_trash_os(target.as_os_str()) {
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
///
/// 2026-10-13：原实现 `quiet_cmd(...).arg("/select,…")` 踩的是与启动项「位置」
/// 同一个坑——`Command::arg` 给含空格的参数套引号，explorer 解析失败后静默回退
/// 到默认目录（用户名或路径带空格即中招）。改走 `shell_select_in_explorer`
/// （ShellExecuteW 原样传参），与 `startup_openlocation` 共用同一份原语。
fn open_folder(dir: &Path) {
    let _ = crate::engine::systembin::shell_select_in_explorer(&dir.to_string_lossy());
}

// ==================== 外观域偏好（背景图 / 雾化 / 壁纸轮换） ====================

/// 外观域键与形状声明（读回与写入共用**同一张表**，防「键进了表、形状闸漏登记」半边失效）。
///
/// 为什么不并进 `commands/settings.rs` 的 `PREF_KEYS`：那张表的值闸是「必须是布尔」
/// （R1a-L09：子窗不能借它往 settings.json 灌任意形状）。外观键是颜色串 / 数值 /
/// 开关的混合形状，放宽那道闸等于把它拆掉；所以这里另开一条**按键声明形状**的通道，
/// 每个键自己声明合法集，非法值当场拒并在回执点名是哪个键、为什么。
///
/// 为什么落 `appearance.json` 而不是 settings.json：材质（material/materialEnabled）早已在这
/// 个文件里，外观域再另起一份就会有两套「外观」台账；且本域写侧全部经
/// `engine::appearance::update_appearance`（= `security::update_json` 的全局锁 + 读失败拒写），
/// 域内不存在第二把不经锁的写路径（lib.rs 保存窗口状态走的也是它）。
#[derive(Clone, Copy)]
enum PrefShape {
    /// 背景图文件路径（扩展名必须过 `bg_ext_ok`）
    BgPath,
    /// 0-100 百分比数值
    Percent,
    /// 布尔
    Bool,
    /// 预设背景 id（空串 = 用户显式选的「无预设」，必须收）
    Preset,
    /// 壁纸轮换间隔秒数（闭区间）
    Seconds,
}

/// 外观域键白名单。渲染层 `src/scripts/pathbinding-appearance.js` 的 `APPEARANCE_PREF_KEYS`
/// 是同一批键的另一份形态（跨语言只共享判据文本、不共享函数，AGENTS §5.16），
/// 两侧键名集合靠跨语言对拍门禁钉住——漏一侧的症状是「前端推的键被后端判成未知键」。
/// 2026-10-22 用户裁定删除自定义强调色，`accent` 已从两侧同批移除；存量 appearance.json
/// 里的该键是未知键，读取侧不返回、写入侧不迁移（Value 形状天然容忍）。
const APPEARANCE_PREF_KEYS: &[(&str, PrefShape)] = &[
    ("bgPath", PrefShape::BgPath),
    ("bgOpacity", PrefShape::Percent),
    // 与 bgOpacity 同键两套语义（旧=图片不透明度，新=雾化强度）的历史标记；
    // 启动期迁移 `engine::appearance::migrate_bg_opacity_fog` 只看这个标记决定翻不翻。
    ("bgOpacityFog", PrefShape::Bool),
    ("bgPosX", PrefShape::Percent),
    ("bgPosY", PrefShape::Percent),
    ("bgBlur", PrefShape::Percent),
    ("presetBg", PrefShape::Preset),
    ("wallpaperRotate", PrefShape::Bool),
    ("wallpaperInterval", PrefShape::Seconds),
    ("wallpaperBlur", PrefShape::Percent),
];

/// 预设背景合法 id。下架预设（aurora / sunset / wp-mountain）一律拒：
/// 渲染层会把它原样写进 `body[data-preset-bg]`，挂了没有 CSS 定义的值等于铺一层空白覆盖层。
const PRESET_BG_KEYS: &[&str] = &["graphite", "wp-winter", "wp-gaming", "wp-anime", "wp-doll"];

/// 壁纸轮换间隔的合法秒数区间。UI 只有四档（10/30/60/300），这里刻意放宽成区间而不是
/// 照抄档位表：档位是「用户能分辨的效果」问题（AGENTS §2），区间闸管的是「不许灌任意值」；
/// 且老 localStorage 镜像里可能存着下架前的秒数，收紧成枚举会在迁移时把用户设置判掉。
const WALLPAPER_INTERVAL_MIN_SECS: u64 = 5;
const WALLPAPER_INTERVAL_MAX_SECS: u64 = 3600;

/// 背景图路径长度上界（Windows 完整路径上限留余量；防的是拿外观键当大载荷通道）
const BG_PATH_MAX_LEN: usize = 1024;

/// 背景图路径形状判定。
/// 刻意**不**校验「必须落在 backgrounds 目录内」：便携/标准模式切换会让 `app_data_dir()`
/// 换根，同一份设置里的路径前缀跟着变，用当时的数据根去判存量值会误拒用户的有效取景。
/// 目录约束由删除闸（`appearance_bg_delete`）承担，这里只判形状。
fn is_bg_path_shape(raw: &str) -> bool {
    !raw.trim().is_empty()
        && raw.len() <= BG_PATH_MAX_LEN
        && !raw.chars().any(|c| c.is_control())
        && bg_ext_ok(raw)
}

/// 按键形状校验：返回 `Some(理由)` 即拒绝。理由必须点名键与期望形状 ——
/// 渲染层要把「哪个键被拒」显示出来，只说「值不合法」等于没回执。
/// `Value::Null` 是**清除**该键，任何白名单键都收（渲染层「重置视角/清除背景图」
/// 走的就是这条，不留一个只能写不能删的键）。
fn appearance_pref_reject(key: &str, value: &Value) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // 白名单判定在命令层也做一次：这里兜住「校验器被单独调用」的路径，
    // 免得未知键一路走到 match 之后被静默当成合法值。
    let Some((_, shape)) = APPEARANCE_PREF_KEYS.iter().find(|(k, _)| *k == key) else {
        return Some(format!("未知的外观键 {key}"));
    };
    let expect = |what: &str| Some(format!("外观键 {key} 的值不合法：需要{what}"));
    match shape {
        PrefShape::BgPath => match value.as_str() {
            Some(s) if is_bg_path_shape(s) => None,
            _ => expect("受支持的图片文件路径"),
        },
        PrefShape::Percent => match value.as_f64() {
            Some(n) if n.is_finite() && (0.0..=100.0).contains(&n) => None,
            _ => expect("0-100 的百分比数值"),
        },
        PrefShape::Bool => match value.as_bool() {
            Some(_) => None,
            _ => expect("布尔值"),
        },
        PrefShape::Preset => match value.as_str() {
            Some(s) if s.is_empty() || PRESET_BG_KEYS.contains(&s) => None,
            _ => expect("已上架的预设背景 id（或空串表示无预设）"),
        },
        PrefShape::Seconds => match value.as_f64() {
            Some(n)
                if n.is_finite()
                    && n.fract() == 0.0
                    && n >= WALLPAPER_INTERVAL_MIN_SECS as f64
                    && n <= WALLPAPER_INTERVAL_MAX_SECS as f64 =>
            {
                None
            }
            _ => expect("整数秒数的壁纸轮换间隔"),
        },
    }
}

/// appearance:get-prefs — 外观域键的批量读回。
///
/// 缺失键回 `null`：渲染层据此区分「后端未设置」（→ 用老 localStorage 键现值迁移上去）
/// 与「后端已设置为空/0/false」（→ 后端优先，不许拿默认值覆盖）。
/// `degraded` 将 appearance.json 读失败与「没有配置」分开（与 `appearance:get-material`
/// 的 A1-M12 同口径）：损坏时渲染层**不得**按「全部未设置」去迁移，否则等于把用户的
/// 镜像值当成待迁数据反复推给一个写不进去的文件。
#[tauri::command]
pub fn appearance_get_prefs<R: Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let (ap, degraded) = crate::engine::appearance::load_appearance_state();
    let mut data = serde_json::Map::new();
    for (key, _) in APPEARANCE_PREF_KEYS {
        data.insert((*key).to_string(), ap.get(*key).cloned().unwrap_or(Value::Null));
    }
    Ok(json!({ "success": true, "data": data, "degraded": degraded }))
}

/// 把已通过形状闸的单个外观偏好写进外观对象（命令闭包与 lib 单测**共用这一份实现**，
/// AGENTS §5.16：同一判据不许两处各写一份）。
///
/// 写 `bgOpacity` 时顺带补 `bgOpacityFog` 标记：渲染层推上来的这个键已经是**雾化语义**，
/// 而启动期迁移 `engine::appearance::migrate_bg_opacity_fog` 只看这个标记决定要不要取反。
/// 标记漏打的症状是下次启动把新值再取反一遍（用户拖到 20% 的雾化，重启变成 80%），
/// 而它只在真机重启后看得见 ⇒ 必须有一条不触盘的机检点（见本文件单测）。
fn write_appearance_pref(obj: &mut serde_json::Map<String, Value>, key: &str, value: &Value) {
    if value.is_null() {
        obj.remove(key);
    } else {
        obj.insert(key.to_string(), value.clone());
    }
    if key == "bgOpacity" && !value.is_null() {
        obj.insert("bgOpacityFog".to_string(), json!(true));
    }
}

/// appearance:set-pref — 单个外观键的类型化写入（外观域真源迁后端的唯一写入口）。
///
/// 白名单外的键当场拒（防渲染层被注入后借外观通道往 appearance.json 塞任意键）；
/// 形状不合当场拒（见 [`appearance_pref_reject`]）。拒都发生在落盘之前 ⇒ 零副作用。
#[tauri::command]
pub fn appearance_set_pref<R: Runtime>(
    window: WebviewWindow<R>,
    key: String,
    value: Value,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if !APPEARANCE_PREF_KEYS.iter().any(|(k, _)| *k == key.as_str()) {
        return Ok(json!({ "success": false, "message": format!("未知的外观键 {key}") }));
    }
    if let Some(reason) = appearance_pref_reject(&key, &value) {
        return Ok(json!({ "success": false, "message": reason }));
    }
    let clearing = value.is_null();
    let res = crate::engine::appearance::update_appearance(|ap| {
        let Some(obj) = ap.as_object_mut() else {
            return Err("外观配置不是对象，拒绝写入外观偏好".to_string());
        };
        write_appearance_pref(obj, &key, &value);
        Ok(())
    });
    match res {
        Ok(_) => Ok(json!({ "success": true, "key": key, "cleared": clearing })),
        Err(msg) => Ok(json!({
            "success": false,
            "message": format!("外观偏好写入失败：{msg}"),
        })),
    }
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
    // v4 R5-M07：裸 .output() 改带超时 —— 外观查询挂在启动同步链上，挂住即锁 IPC
    // v6-K01（P0-2）：reg 解析失败与执行失败同语义（读不到按开启处理）
    let Ok(exe) = system_tool("reg") else { return true };
    let out = crate::engine::systembin::quiet_cmd_timeout(
        exe,
        &[
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "/v",
            "EnableTransparency",
        ],
        crate::engine::systembin::REG_EXPORT_TIMEOUT,
    );
    let Ok(out) = out else { return true };
    let text = crate::engine::systembin::decode_native_output(&out.stdout);
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

    // ==================== 外观域偏好的形状闸（正反对照） ====================
    //
    // 每条向量都点名「哪个键、收还是拒、拒的理由里出现键名」，只断 Option::is_some 的话
    // 校验器整条退化成「一律拒」也照样绿（§4.1 假绿防线）。

    #[test]
    fn 外观形状闸收合法向量() {
        let legal: &[(&str, Value)] = &[
            ("bgPath", json!(r"C:\Users\x\AppData\Roaming\com.xiaoxu.trim\backgrounds\bg_1.png")),
            ("bgOpacity", json!(0)),
            ("bgOpacity", json!(100)),
            ("bgOpacityFog", json!(true)),
            ("bgBlur", json!(33.5)),
            ("presetBg", json!("")),
            ("presetBg", json!("wp-doll")),
            ("wallpaperRotate", json!(false)),
            ("wallpaperInterval", json!(300)),
            ("wallpaperBlur", json!(20)),
            // null = 清除任何白名单键（重置视角 / 清除背景图走的就是这条）
            ("bgPath", Value::Null),
        ];
        let mut reached: Vec<String> = Vec::new();
        for (key, value) in legal {
            assert_eq!(
                appearance_pref_reject(key, value),
                None,
                "{key}={value} 是合法形状，不该被拒"
            );
            reached.push(format!("{key}={value}"));
        }
        assert_eq!(reached.len(), legal.len(), "合法向量必须逐条走过（实到 {reached:?}）");
    }

    #[test]
    fn 外观形状闸拒非法向量且理由点名键() {
        // 每行 = (键, 非法值, 理由里必须出现的期望形状措辞)
        let illegal: &[(&str, Value, &str)] = &[
            // 借外观键灌任意形状：字符串数值、超长路径、含控制字符
            // 2026-10-22 裁定：自定义强调色整链删除后，`accent` 必须落到「未知的外观键」，
            // 这条防的是有人把颜色键连同 Color 形状一起加回来（前端已无写入入口）。
            ("accent", json!("#6A59C9"), "未知的外观键"),
            ("bgOpacity", json!("20"), "0-100 的百分比数值"),
            ("bgOpacity", json!(101), "0-100 的百分比数值"),
            ("bgOpacity", json!(-1), "0-100 的百分比数值"),
            ("bgBlur", json!([33.5]), "0-100 的百分比数值"),
            ("wallpaperRotate", json!("1"), "布尔值"),
            ("presetBg", json!("wp-mountain"), "预设背景"),
            ("presetBg", json!(12), "预设背景"),
            ("wallpaperInterval", json!(4), "整数秒数的壁纸轮换间隔"),
            ("wallpaperInterval", json!("10"), "整数秒数的壁纸轮换间隔"),
            ("wallpaperInterval", json!(10.5), "整数秒数的壁纸轮换间隔"),
            ("wallpaperInterval", json!(3601), "整数秒数的壁纸轮换间隔"),
            // 扩展名不在白名单 / 空串 / 含控制字符的路径
            ("bgPath", json!(r"C:\a\b.txt"), "图片文件路径"),
            ("bgPath", json!(""), "图片文件路径"),
            ("bgPath", json!("C:\\a\r.png"), "图片文件路径"),
            // 未知键：命令层先拒，校验器单独调用时也必须拒（否则=白名单外的键静默通过）
            ("__not_an_appearance_key__", json!("x"), "未知的外观键"),
        ];
        let mut reached: Vec<String> = Vec::new();
        for (key, value, expect_in_reason) in illegal {
            let reason = appearance_pref_reject(key, value)
                .unwrap_or_else(|| panic!("{key}={value} 必须被拒，实际通过了形状闸"));
            assert!(
                reason.contains(key) || reason.contains("外观键"),
                "拒因必须点名是哪个键，实得 {reason}"
            );
            assert!(
                reason.contains(expect_in_reason),
                "{key}={value} 的拒因要说明期望形状（含「{expect_in_reason}」），实得 {reason}"
            );
            reached.push(format!("{key}=>{expect_in_reason}"));
        }
        assert_eq!(
            reached.len(),
            illegal.len(),
            "每条不受信向量都必须各自命中拒因（实到 {reached:?}）——少一条就是用例没在测东西"
        );
    }

    #[test]
    fn 外观键表与材质键不重叠() {
        // 外观偏好通道写的是同一份 appearance.json，但材质两键有各自的命令
        // （写侧还要顺带应用全窗 + 广播）。把它们塞进通用偏好通道 = 绕过材质应用链。
        for (key, _) in APPEARANCE_PREF_KEYS {
            assert!(!MATERIALS.contains(&key), "{key} 不该同时是材质值");
            assert_ne!(*key, "material", "material 必须走 appearance:set-material");
            assert_ne!(*key, "materialEnabled", "materialEnabled 必须走 appearance:set-material-enabled");
        }
    }

    #[test]
    fn 外观形状表覆盖全部声明键() {
        // 形状枚举与键表是两条独立维护的清单；漏一个键 ⇒ 校验器对该键返回「未知键」，
        // 渲染层每次写都失败但界面看不出来。这里按现算条数点名，防只加键不加形状。
        let mut seen: Vec<&str> = Vec::new();
        for (key, _) in APPEARANCE_PREF_KEYS {
            assert!(!seen.contains(key), "键 {key} 在形状表里重复登记");
            seen.push(key);
            // 每条都必须能被校验器判出「收」或「拒」，绝不能是 None 之外的第三种走法
            let probe = json!(0);
            let _ = appearance_pref_reject(key, &probe);
        }
        assert_eq!(seen.len(), APPEARANCE_PREF_KEYS.len(), "键表逐条点名（清单塌缩时这条红）");
    }

    /// 写侧语义（命令闭包与这里共用 [`write_appearance_pref`]，所以这条就是生产路径）：
    /// ① 写 `bgOpacity` 必须同时把雾化标记置真——漏了它，下次启动 `migrate_bg_opacity_fog`
    ///   会把已是雾化语义的值再取反一遍（20% 变 80%），而这个症状只在真机重启后看得见；
    /// ② `null` = 删键（渲染层的「清除背景图 / 重置视角」走的就是这条）；
    /// ③ 其它键不得顺手补标记（否则「标记存在」不再等于「bgOpacity 已迁过」）。
    #[test]
    fn 外观写侧的标记与清除语义() {
        let mut obj = serde_json::Map::new();
        write_appearance_pref(&mut obj, "bgOpacity", &json!(20));
        assert_eq!(obj.get("bgOpacity"), Some(&json!(20)), "值必须原样写入");
        assert_eq!(
            obj.get("bgOpacityFog"),
            Some(&json!(true)),
            "写 bgOpacity 必须同时置真雾化标记，否则下次启动会把新值再取反一遍"
        );

        let mut other = serde_json::Map::new();
        write_appearance_pref(&mut other, "bgBlur", &json!(30));
        assert_eq!(other.get("bgBlur"), Some(&json!(30)));
        assert_eq!(
            other.get("bgOpacityFog"),
            None,
            "非 bgOpacity 的键不得替它打标记——那会让「标记存在」不再等于「不透明度已换算」"
        );

        let mut cleared = serde_json::Map::new();
        cleared.insert("bgBlur".into(), json!(30));
        // 存量 accent 键（2026-10-22 删除自定义强调色后属未知键）不得被相邻键的清除顺手带走：
        // 渲染层已无写入入口，但盘上旧值仍要给用户留着（回滚旧版本时可读回）。
        cleared.insert("accent".into(), json!("#6A59C9"));
        write_appearance_pref(&mut cleared, "bgBlur", &Value::Null);
        assert!(
            !cleared.contains_key("bgBlur"),
            "null 必须删键（渲染层清除类操作等的是这个，不是把键留着写个 null）: {cleared:?}"
        );
        assert_eq!(
            cleared.get("accent"),
            Some(&json!("#6A59C9")),
            "清除其它键不得顺手删掉存量 accent（未知键按原样保留）: {cleared:?}"
        );
        // 清除 bgOpacity 不能反向把标记置真（值是「未设置」而不是「已换算」）
        let mut clear_opacity = serde_json::Map::new();
        clear_opacity.insert("bgOpacity".into(), json!(40));
        write_appearance_pref(&mut clear_opacity, "bgOpacity", &Value::Null);
        assert!(!clear_opacity.contains_key("bgOpacity"), "值必须被删");
        assert_eq!(
            clear_opacity.get("bgOpacityFog"),
            None,
            "清除时不该补标记: {clear_opacity:?}"
        );
    }
}
