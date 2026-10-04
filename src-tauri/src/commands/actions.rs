//! actions 域（v0.7.0 第四期）：右键菜单「自定义项」的图形化落点。
//!
//! 为什么不把 Nilesoft Shell 打进来（取证与红线对照见本机资料区方案 §10）：那是**注入型**
//! 扩展 —— COM 注册把 dll 拉进 explorer.exe，再 Detours 钩 `CoCreateInstance`、IAT 改写宿主
//! 每一个模块的 `TrackPopupMenu`、Win11 上换任务栏 WNDPROC，注册要 HKLM+提权；二进制无签名、
//! 上游不产 Release、附带的 Detours/plutosvg/FreeType/字体许可证都没随件。
//! 这些正面撞 AGENTS §9.1（不透传第三方工具）、§9.2（产物要有可验的字节链）、§2（不为便利
//! 默认放宽安全基线）。所以这里只**借能力语义**：GUI 点几下 ⇒ 写 HKCU 经典菜单键，
//! Explorer 原生渲染，零注入、免提权、只影响当前登录账号。
//!
//! 三条硬边界：
//! 1. **只写 `HKCU\Software\Classes`**（用户裁定 2026-10-05：只给当前账号加）。HKLM 支路
//!    刻意不开 —— 要提权，且卸载那条链已有自己的 HKLM 闸门，不在这里开第二道。
//! 2. 键形状固定：`HKCU\Software\Classes\<class>\shell\<id>` 的 `(Default)`=标题、`Icon`、
//!    `\command\(Default)`=命令行。`class`/`id` 都过字符集闸；**命令串只从随包数据文件取**，
//!    渲染层只能回传 id —— 与 §9.1「不透传外部命令行」是同一条姿势。
//! 3. 写与删都过 A1 判据 `reg_target_block_reason`：数据文件被改坏时，不会把写引到别处。

use crate::engine::{guard, log, native, protect, sysinfo};
use serde_json::{Value, json};
use std::path::Path;
use tauri::webview::PageLoadEvent;
use tauri::window::Color;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ};

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16().chain(std::iter::once(0)).flat_map(|c| c.to_le_bytes()).collect()
}

/// 子窗口 label（与 `engine::guard::APP_WINDOWS`、`capabilities/subwindows.json` 逐字一致）
pub const LABEL: &str = "actions";
const PAGE: &str = "actions-window.html";
const TITLE: &str = "右键菜单动作";

/// 写入根：只这一棵（裁定 6）
const CLASSES_ROOT: &str = r"Software\Classes";

/// 允许挂菜单项的类，都是 HKCU 下的 per-user 类
const ALLOWED_CLASSES: &[&str] = &["*", "Directory", "Directory\\Background", "Drive"];

/// 随包内置动作清单（真源，渲染层不许写）。
/// 形状：`{ "version": n, "items": [{id,title,class,command,args,glyph,note}] }`
const ITEMS_JSON: &str = include_str!("../../data/contextmenu-items.json");

/// id 直接成为注册表键名 ⇒ 只允许 `[A-Za-z0-9._-]`，外加文件类合法键名 `*`
fn valid_id(s: &str) -> bool {
    // `*` 只允许**整体等于**它（文件类的合法键名）；`a*b` 这种混排不是任何已知类的键名，
    // 放行只会让「我们写到哪」变成字符集能拼出来的任何东西
    if s == "*" {
        return true;
    }
    if s.chars().all(|c| c == '.') {
        return false; // "." 与 ".." 一律不吃：它们会是键名里的歧义段
    }
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn valid_class(s: &str) -> bool {
    ALLOWED_CLASSES.contains(&s)
}

fn full_key(class: &str, id: &str) -> String {
    format!(r"{CLASSES_ROOT}\{class}\shell\{id}")
}

/// A1 判据 + 本域窄口子的**复合出口**（装载侧列「可移除」与执行侧删键都走这里，
/// AGENTS §5.16/N6 禁的就是两处各一套判据）。
/// 返回 `None` = 允许动这个键；`Some(理由)` = 拒，理由直接进明细与日志。
///
/// A1 本体（`reg_target_block_reason`）刻意**不改**：整棵 `HKCU\Software\Classes` 属禁删面
/// 是对的（残留链可能删到别人软件的菜单）。让路的只有 `TRIM.` 前缀那一层形状，
/// 判据在 `protect::trim_shell_key_narrow_deny`，与卸载那条链上服务键窄口子同一个姿势。
fn a1_gate(key: &str) -> Option<String> {
    let full = format!(r"HKCU\{key}");
    match protect::reg_target_block_reason(&full) {
        None => None,
        Some(reason) => match protect::trim_shell_key_narrow_deny(&full) {
            None => {
                // 放行必须留痕：全仓要能在日志里数出「A1 让路」发生了几次、为了哪个键
                log::write_log("warn", &format!("A1 菜单键窄口子放行（TRIM. 前缀形状合格）: {full}"));
                None
            }
            Some(_) => Some(reason),
        },
    }
}

/// 读数据文件并按形状校验。**逐条**丢不合格项（一处写坏不该让其余全消失），
/// 丢了几条要回显，不许静默。
fn load_items() -> (Vec<Value>, usize) {
    let parsed: Value = serde_json::from_str(ITEMS_JSON).unwrap_or_else(|e| {
        log::write_log("error", &format!("contextmenu-items.json 解析失败: {e}"));
        json!({})
    });
    let raw = parsed.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
    let total = raw.len();
    let mut ok = Vec::new();
    for it in raw.into_iter() {
        let id = it.get("id").and_then(Value::as_str).unwrap_or("");
        let class = it.get("class").and_then(Value::as_str).unwrap_or("");
        let command = it.get("command").and_then(Value::as_str).unwrap_or("");
        let title = it.get("title").and_then(Value::as_str).unwrap_or("").trim();
        // 命令必须是一个**存在的绝对路径可执行文件**：数据文件被误改成
        // `powershell -c ...` 这类串时，写进注册表等于给资源管理器挂一条任意命令。
        let command_ok = Path::new(command).is_absolute() && Path::new(command).exists();
        if valid_id(id) && valid_class(class) && command_ok && !title.is_empty() {
            ok.push(it.clone());
        }
    }
    let dropped = total - ok.len();
    (ok, dropped)
}

/// 写入（或覆盖）一个自定义菜单项。`(Default)` 在经典菜单里就是显示名。
/// 全部走 `engine::native` 的既有注册表写出口，不在本域另起一套 Win32 胶水
/// （删除/写入出口集中在一处，`check-delete-exits` 才数得清）。
unsafe fn write_item(class: &str, id: &str, title: &str, command: &str, args: &str, glyph: &str) -> Result<(), String> {
    let key = full_key(class, id);
    native::reg_key_ensure_checked(HKEY_CURRENT_USER, &key).map_err(|e| format!("创建 {key} 失败: {e}"))?;
    native::reg_restore_write_checked(HKEY_CURRENT_USER, &key, "", REG_SZ, &utf16z(title))
        .map_err(|e| format!("写入 {key} 默认值失败: {e}"))?;
    if !glyph.is_empty() {
        // Icon 值形如 `"C:\path\app.exe",0`：取该 exe 的第一个图标
        native::reg_restore_write_checked(HKEY_CURRENT_USER, &key, "Icon", REG_SZ, &utf16z(&format!("\"{command}\",0")))
            .map_err(|e| format!("写入 Icon 失败: {e}"))?;
    }
    let cmd_key = format!(r"{key}\command");
    native::reg_key_ensure_checked(HKEY_CURRENT_USER, &cmd_key).map_err(|e| format!("创建 {cmd_key} 失败: {e}"))?;
    // 命令行重新构造：加引号的 exe + 数据文件里的参数串（含 %1 / %V 这类经典占位符）
    let line = if args.trim().is_empty() { format!("\"{command}\"") } else { format!("\"{command}\" {}", args.trim()) };
    native::reg_restore_write_checked(HKEY_CURRENT_USER, &cmd_key, "", REG_SZ, &utf16z(&line))
        .map_err(|e| format!("写入命令行失败: {e}"))
}

unsafe fn delete_item(class: &str, id: &str) -> Result<(), String> {
    let key = full_key(class, id);
    if native::reg_key_remove(HKEY_CURRENT_USER, &key, true) {
        Ok(())
    } else {
        Err(format!("删除 {key} 失败"))
    }
}

/// 现读某一类 shell 下的自定义项 id（只认形状合格的，别的软件的键不显示也不删）
fn read_shell_ids(class: &str) -> Vec<String> {
    native::reg_enum_subkeys_pub(HKEY_CURRENT_USER, &format!(r"{CLASSES_ROOT}\{class}\shell"))
        .into_iter()
        .filter(|s| valid_id(s))
        .collect()
}

/// actions:list —— 内置动作 + 它们在 HKCU 里的当前落点（只读档，副窗消费）
#[tauri::command]
pub async fn actions_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let (items, dropped) = tauri::async_runtime::spawn_blocking(load_items)
        .await
        .map_err(|e| format!("读取动作清单失败: {e}"))?;
    let mut out = Vec::new();
    for it in &items {
        let class = it.get("class").and_then(Value::as_str).unwrap_or("");
        let id = it.get("id").and_then(Value::as_str).unwrap_or("");
        let present = read_shell_ids(class).iter().any(|x| x == id);
        out.push(json!({
            "id": id, "class": class,
            "title": it.get("title").and_then(Value::as_str).unwrap_or(""),
            "command": it.get("command").and_then(Value::as_str).unwrap_or(""),
            "args": it.get("args").and_then(Value::as_str).unwrap_or(""),
            "glyph": it.get("glyph").and_then(Value::as_str).unwrap_or(""),
            "note": it.get("note").and_then(Value::as_str).unwrap_or(""),
            "installed": present,
            // 装载侧同一个判据（§5.16）：界面据此决定「移除」按钮亮不亮，
            // 不另写一份「看起来等价」的判断，免得 UI 说能删而执行侧被 A1 拒
            "removable": a1_gate(&full_key(class, id)).is_none(),
        }));
    }
    Ok(json!({
        "success": true,
        "data": {
            "items": out,
            // 校验丢掉的条数必须可见：静默少几条 = 用户以为「没做出来」
            "droppedInvalid": dropped,
            "scope": "HKCU",
            "admin": sysinfo::is_admin(),
        },
    }))
}

/// actions:apply —— 把勾选的内置动作投影成 HKCU 经典菜单键。
///
/// 档位是窄窗口集 `guard::ACTIONS_WINDOWS`（只有本副窗）：写侧命令不给其它子窗，
/// 也不留 MAIN（留 MAIN 会让本副窗每次 IPC 判越权，§3 M1~M3）。
#[tauri::command]
pub async fn actions_apply<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    ids: Vec<String>,
) -> Result<Value, String> {
    guard::guard(&window, guard::ACTIONS_WINDOWS)?;
    if ids.is_empty() || ids.len() > 40 {
        return Err("ids 为空或超过 40 项上限".to_string());
    }
    let (items, _) = load_items();
    // 渲染层只能表达「选了哪些 id」；标题/命令/参数一律取随包数据（§9.1 同一条姿势）
    let picked: Vec<Value> = items
        .iter()
        .filter(|it| it.get("id").and_then(Value::as_str).is_some_and(|id| ids.iter().any(|x| x == id)))
        .cloned()
        .collect();
    if picked.is_empty() {
        return Err("没有一项在内置动作清单里".to_string());
    }
    let details = tauri::async_runtime::spawn_blocking(move || unsafe {
        let mut out = Vec::new();
        for it in &picked {
            let id = it.get("id").and_then(Value::as_str).unwrap_or("");
            let class = it.get("class").and_then(Value::as_str).unwrap_or("");
            let key = full_key(class, id);
            if let Some(reason) = a1_gate(&key) {
                out.push(json!({ "id": id, "status": "skip", "message": reason }));
                continue;
            }
            let r = write_item(
                class,
                id,
                it.get("title").and_then(Value::as_str).unwrap_or(""),
                it.get("command").and_then(Value::as_str).unwrap_or(""),
                it.get("args").and_then(Value::as_str).unwrap_or(""),
                it.get("glyph").and_then(Value::as_str).unwrap_or(""),
            );
            match r {
                Ok(()) => out.push(json!({ "id": id, "status": "ok", "message": key })),
                Err(e) => out.push(json!({ "id": id, "status": "fail", "message": e })),
            }
        }
        out
    })
    .await
    .map_err(|e| format!("写入任务异常: {e}"))?;
    let ok = details.iter().filter(|d| d["status"] == json!("ok")).count();
    log::write_log("info", &format!("actions_apply HKCU 自定义菜单项：成功 {ok} / 提交 {}", details.len()));
    // restartExplorerHelp：HKCU 经典菜单项通常即时生效，但已开着的资源管理器窗口
    // 不一定重读 —— 文案给「没出现就重启资源管理器」，不假装一定立刻可见（§9.3）
    Ok(json!({ "success": true, "data": { "details": details, "okCount": ok, "restartExplorerHelp": true } }))
}

/// actions:remove —— 撤掉内置动作写过的 HKCU 键（清单之外一项都不删）
#[tauri::command]
pub async fn actions_remove<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    ids: Vec<String>,
) -> Result<Value, String> {
    guard::guard(&window, guard::ACTIONS_WINDOWS)?;
    if ids.is_empty() || ids.len() > 40 {
        return Err("ids 为空或超过 40 项上限".to_string());
    }
    let (items, _) = load_items();
    let picked: Vec<Value> = items
        .iter()
        .filter(|it| it.get("id").and_then(Value::as_str).is_some_and(|id| ids.iter().any(|x| x == id)))
        .cloned()
        .collect();
    if picked.is_empty() {
        return Err("没有一项在内置动作清单里，拒绝删除清单之外的注册表键".to_string());
    }
    let details = tauri::async_runtime::spawn_blocking(move || unsafe {
        let mut out = Vec::new();
        for it in &picked {
            let id = it.get("id").and_then(Value::as_str).unwrap_or("");
            let class = it.get("class").and_then(Value::as_str).unwrap_or("");
            let key = full_key(class, id);
            if let Some(reason) = a1_gate(&key) {
                out.push(json!({ "id": id, "status": "skip", "message": reason }));
                continue;
            }
            match delete_item(class, id) {
                Ok(()) => out.push(json!({ "id": id, "status": "ok", "message": key })),
                Err(e) => out.push(json!({ "id": id, "status": "fail", "message": e })),
            }
        }
        out
    })
    .await
    .map_err(|e| format!("删除任务异常: {e}"))?;
    let ok = details.iter().filter(|d| d["status"] == json!("ok")).count();
    log::write_log("info", &format!("actions_remove HKCU 自定义菜单项：删除 {ok} / 提交 {}", details.len()));
    Ok(json!({ "success": true, "data": { "details": details, "okCount": ok } }))
}

/// 用户脚本的形状闸（**纯函数**，单测直接吃向量）。
/// 只做三件事：非空、长度上限、拒 ` `。刻意**不**做关键字黑名单 ——
/// 那不是安全边界（`Rm-Out` 拼一下就越得过），给了只会让人误以为这里拦住了什么。
/// 真正的边界是：跑在非提权令牌里 + 逐项确认 + 全量留痕（见 actions_run_script 的注释）。
fn user_script_deny(script: &str) -> Option<String> {
    const MAX_CHARS: usize = 8000;
    let s = script.trim();
    if s.is_empty() {
        return Some("脚本为空".to_string());
    }
    if s.chars().count() > MAX_CHARS {
        return Some(format!("脚本 {} 字超上限 {MAX_CHARS}，请拆小", s.chars().count()));
    }
    if s.contains(' ') {
        return Some("脚本含 NUL".to_string());
    }
    None
}

/// actions:run-script —— 用户在副窗里自己写的 PowerShell 直调（裁定 7）。
///
/// 七条护栏里落在后端的四条，逐条写明「为什么是这条」：
/// ① **唯一入口** `pwsh::run_inbox_script`（私有 tmp + BOM + `-File` + Job Object 超时收树，§3）；
///    不自己 `fs::write` 一份 .ps1 再跑，也不 `pub` 出低层 `run_inbox_ps`。
/// ② 超时是**固定 120 秒、用户不可配** —— 能配超时等于能把「超时收树」这道护栏关掉；
///    超时会把 pwsh 连同子孙进程一起终止（§5.13），UI 必须写这句，别让人以为脚本会跑完。
/// ③ **不代提权**：脚本就在当前（通常非提权）令牌里跑。写不动 HKLM/受保护区是操作系统在挡，
///    不是我们自己实现的一套拦截 —— 后者一定会漏。`elevate:request` 不下放给本副窗。
/// ④ 全量留痕：脚本正文进日志（过 `log::write_log` 的长度上限与 sanitize）。
///
/// 必须说清的边界（AGENTS §9.3 话术纪律，也写进回执给前端显示）：
/// **用户自己写的脚本不经过 Trim 的删除红线** —— A1 禁删面、回收站优先、驱动独立禁删面
/// 都在 Rust 命令体里，脚本一句 `Remove-Item` 就绕过去了。本面板的承诺只有
/// 「不代提权 + 逐项确认 + 全程留痕」三件，不把它当安全边界卖。
#[tauri::command]
pub async fn actions_run_script<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    script: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::ACTIONS_WINDOWS)?;
    if let Some(reason) = user_script_deny(&script) {
        return Err(reason);
    }
    let body = script.trim().to_string();
    log::write_log("info", &format!("actions:run-script 提交执行，{} 字（非提权令牌，超时 120 秒整树终止）", body.chars().count()));
    let out = tauri::async_runtime::spawn_blocking(move || {
        crate::pwsh::run_inbox_script(&body, std::time::Duration::from_secs(120), Some("actions:run-script"))
    })
    .await
    .map_err(|e| format!("脚本任务异常: {e}"))??;
    Ok(json!({
        "success": true,
        "data": {
            "exitCode": out.code,
            "timedOut": out.timed_out,
            "stdout": out.stdout,
            "stderr": out.stderr,
            "elevated": sysinfo::is_admin(),
            // 这句必须显示给用户，而不是只写在代码注释里
            "boundary": "你自己写的脚本不经过 Trim 的删除红线（A1 禁删面/回收站优先都不在它路上）；Trim 只做确认、留痕与不代提权。",
        },
    }))
}

/// actions:open-window —— 打开「右键菜单动作」副窗（单例，已开则聚焦）
///
/// 档位 MAIN：只有主窗入口按钮会调它，副窗自己不调（与 residue 窗同一口径；
/// `check-channel-map` 的 D5 判据是「放宽到只读档 ⇒ 必须真有子窗调用点」）。
#[tauri::command]
pub async fn actions_open_window<R: tauri::Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if let Some(existing) = app.get_webview_window(LABEL) {
        crate::focus_window(&existing);
        return Ok(json!({ "success": true, "alreadyOpen": true }));
    }
    let builder = WebviewWindowBuilder::new(&app, LABEL, WebviewUrl::App(PAGE.into()))
        .title(TITLE)
        .inner_size(900.0, 660.0)
        .min_inner_size(680.0, 460.0)
        .background_color(Color(243, 243, 243, 255))
        .center()
        .visible(false)
        .on_page_load(|win, payload| {
            if payload.event() == PageLoadEvent::Finished {
                crate::activate_window(&win);
            }
        });
    // §5.15：建窗点必须过 with_browser_args，否则同一 user-data-folder 下第二个 core
    // 建不出来，而 build() 照样返回 Ok、get_webview_window 照样查得到，只是 hwnd=0x0
    let builder = crate::with_browser_args(builder);
    match builder.parent(&window) {
        Ok(b) => match b.build() {
            Ok(_) => Ok(json!({ "success": true })),
            Err(e) => {
                log::write_log("error", &format!("创建「右键菜单动作」窗口失败: {e}"));
                Ok(json!({ "success": false, "message": format!("创建「右键菜单动作」窗口失败: {e}") }))
            }
        },
        Err(e) => Ok(json!({ "success": false, "message": format!("窗口挂靠主窗失败: {e}") })),
    }
}

/// actions:close-window —— 关掉发起调用的窗口本身
#[tauri::command]
pub fn actions_close_window<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Err(e) = window.close() {
        log::write_log("warn", &format!("关闭「右键菜单动作」窗口失败: {e}"));
    }
    Ok(json!({ "success": true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_and_class_gates_are_the_shape_this_code_writes_into_the_registry() {
        // 合格
        assert!(valid_id("trim.copyPath") && valid_id("*") && valid_id("a_b-c.1"));
        assert!(valid_class("*") && valid_class("Directory") && valid_class("Directory\\Background") && valid_class("Drive"));
        // 形状不合格：这些都会变成键名，注入面就在这一层关掉
        for bad in ["", "..", "..\\..\\x", "a b", "a\\b", "a*b", "(Get-Content x)", &"x".repeat(65)] {
            assert!(!valid_id(bad), "id 判据误接受: {bad:?}");
        }
        for bad in ["HKLM\\x", "", "*", "directory", "Software\\Classes"] {
            assert_eq!(bad == "*", valid_class(bad), "class 判据不一致: {bad:?}");
        }
    }

    /// 随包数据必须**真的**过自己的闸：闸写对但数据写坏，症状是列表空白，
    /// 而本单测不碰注册表就能抓到。
    #[test]
    fn shipped_items_pass_their_own_gates_and_point_at_existing_executables() {
        let (ok, dropped) = load_items();
        assert!(!ok.is_empty(), "内置动作清单一条都没过闸（dropped={dropped}）—— 数据文件或闸写坏了");
        assert_eq!(dropped, 0, "随包数据里有 {dropped} 条不合格项，不该带着坏数据发布");
        for it in &ok {
            assert!(valid_id(it["id"].as_str().unwrap_or("")));
            assert!(valid_class(it["class"].as_str().unwrap_or("")));
            assert!(Path::new(it["command"].as_str().unwrap_or("")).is_absolute());
        }
    }

    #[test]
    fn user_script_gate_is_shape_only_and_names_every_reject() {
        assert!(user_script_deny("   ").is_some());
        assert!(user_script_deny(&"x".repeat(8001)).is_some());
        assert!(user_script_deny("Get-Process
").is_none());
        assert!(user_script_deny("a b").is_some());
        // 正向对照：合法脚本必须真的通过（否则上面几条是"恒拒"也在绿）
        assert!(user_script_deny("Write-Output 'ok'").is_none());
    }

    #[test]
    fn shipped_ids_are_all_narrow_gate_shapes() {
        // 随包 id 必须正好落进 A1 窄口子认的形状；哪一天有人把 id 改成不带 trim. 前缀，
        // 这条会红，症状是「移除按钮点了被 A1 拒」—— 提前在单测里抓到。
        let (items, _) = load_items();
        assert!(!items.is_empty(), "清单为空：本断言会空跑");
        for it in &items {
            let key = full_key(it["class"].as_str().unwrap(), it["id"].as_str().unwrap());
            assert!(a1_gate(&key).is_none(), "随包项 {key} 走不了窄口子，移除会永久失败");
        }
    }

    #[test]
    fn narrow_gate_does_not_let_other_peoples_menu_keys_through() {
        // 别人的菜单项（不带 TRIM. 前缀）必须仍被拒；这条就是「豁免只给 TRIM.」的凭证
        assert!(a1_gate(r"Software\Classes\*\shell\VSCode")  .is_some(), "非 TRIM 前缀被放行了");
        assert!(a1_gate(r"Software\Classes\Directory\shell").is_some());
        // HKLM 同形状也不给走（口子只认 HKCU）
        assert!(a1_gate(r"Software\Classes\*\shell\TRIM.x").is_some()
            || protect::reg_target_block_reason(r"HKLM\Software\Classes\*\shell\TRIM.x").is_some());
        // 而 A1 确实拦着整棵 Classes —— 这条变绿说明禁删面缩了，要回来复核本域
        assert!(protect::reg_target_block_reason(r"HKCU\Software\Classes\*\shellnything").is_some());
    }
}

