//! models 域（C 批）：models:save / models:set-scope / models:test /
//! models:open-window / models:close-window
//!
//! 对照 main.js 4842-4961（save / set-scope / test）、6717-6761（大模型管理独立窗口）。
//!
//! # 要点
//!
//! - 配置真源仍是 `settings.json`（密钥掩码 + 掩码穿透：回传掩码 = 未修改 → 保留已存真值）；
//! - **保存即校验**：向该模型发一条确认消息，只有返回内容才置 `verified`；
//!   密钥为空时不校验、强制 `verified=false`/`enabled=false`（与 Electron 同语义）；
//! - 作用域权威校验在 Rust 侧：`key` 必须属于 `AI_MODEL_KEYS`，
//!   `set-scope` 只接受「已验证且已启用」的模型，且**只写全局槽位**（`aiScopes.global`）；
//! - `models:open-window` 窗口参数照抄 main.js：720×680 / 最小 600×520 / 父窗 main /
//!   `modal: false` / 标题「大模型管理」/ 背景 `#f3f3f3` / 先隐藏等首帧再 show；
//!   窗口 label 固定 `"models"`（guard::APP_WINDOWS 已含该 label）。
//!
//! 需要加入 lib.rs `generate_handler!` 的完整行：
//!   commands::models::models_save,
//!   commands::models::models_set_scope,
//!   commands::models::models_test,
//!   commands::models::models_open_window,
//!   commands::models::models_close_window,

use serde_json::{json, Value};
use tauri::webview::PageLoadEvent;
use tauri::window::Color;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::engine::{guard, log};
use crate::security::SECRET_MASK;

use super::aidesc::call_model_text;
use super::settings::{
    self, clamp_timeout, is_http_url, is_private_api_url, js_string, js_truthy,
    model_display_name, models_config, normalize_chat_completions_url,
    truthy_string, AI_MODEL_KEYS, AI_SCOPES, GLOBAL_ENGINE_KEY,
};

/// 子窗口 label（与 Electron 窗口角色同名）
pub const LABEL: &str = "models";
/// 页面与标题
const PAGE: &str = "models-window.html";
const TITLE: &str = "大模型管理";

/// 取字符串字段（JS `String(cfg.x).trim()`），`undefined/null` → None
fn cfg_str(cfg: &Value, key: &str) -> Option<String> {
    match cfg.get(key) {
        None | Some(Value::Null) => None,
        Some(v) => Some(js_string(v).trim().to_string()),
    }
}

/// P1-5：读-改-写的「改」只允许动**本次那一个键**。
///
/// 旧形态是 `build_next(current, models, scope, key)` —— 把命令开头 `models_config()`
/// 读到的整张 models 表盖回盘上。而 `models_save` 在取快照与写入之间要等一次连通性校验
/// （`call_model_text` 的 spawn_blocking，超时上限由该模型自己的 `timeout` 决定），
/// 期间另一个模型键的保存早已落盘，被这份旧快照整表顶掉：
/// 用户看到「两个都保存成功了」，盘上却只剩后写的那一个。`models_set_scope` 同病，
/// 吞的是别的槽位。
///
/// `current` 由 `settings::update_settings` 在锁内给出（= 盘上最新值），本函数只在它上面
/// 改 `models[key]` 与（scope 命中槽位时）`aiScopes[scope]`，其余键原样保留。
/// 同一 key / 同一 slot 的并发允许后写者胜 —— 方案 P1-5 的验收边界就是这一条。
///
/// 返回新值而不是收 `&mut`：与本仓其余读-改-写闭包同姿势（盘上现值先拷进局部变量、
/// 改完再 `*next =`，见 `fonts.rs` 三处与 `settings.rs` 的 `update_settings` 调用），
/// 不新造第三种写法。
/// `entry` 为 `None` 时只动槽位（`models_set_scope` 只要写 `aiScopes[slot]`，
/// 不许顺手往 models 里塞一个字符串）。
/// `slot` 为 `None` 时不动槽位 —— 是否算「一个真槽位」由调用方判：`models_save` 只在
/// scope 命中 `AI_SCOPES` 时给 `Some`，`models_set_scope` 的 slot 已经过 `GLOBAL_ENGINE_KEY`
/// 兜底，恒给 `Some`（判据留在调用方，本函数不猜语义）。
///
/// `full_models` 是 R1b-M09 的首次引导：盘上**没有** `models` 段时，读侧那套「平铺字段
/// 一次性迁移」只看「models 段整体缺失」，只补写本键会让 `stored` 变 Some、迁移分支
/// 永久失效，其余键静默回退出厂值。所以首次写入要用读侧已迁移好的**整张** models 建段，
/// 再覆盖本键；盘上已有 models 段时该参数不参与（按键补写语义不变，并发判据仍守 P1-5）。
fn apply_model_edit(
    current: &Value,
    key: &str,
    entry: Option<&Value>,
    slot: Option<&str>,
    full_models: Option<&Value>,
) -> Value {
    let mut next = current.clone();
    let Some(map) = next.as_object_mut() else { return next };
    if let Some(e) = entry {
        let models = match map.entry("models") {
            serde_json::map::Entry::Vacant(v) => {
                v.insert(full_models.cloned().unwrap_or_else(|| json!({})))
            }
            serde_json::map::Entry::Occupied(occ) => occ.into_mut(),
        };
        if let Some(m) = models.as_object_mut() {
            m.insert(key.to_string(), e.clone());
        }
    }
    if let Some(s) = slot {
        let scopes = map.entry("aiScopes").or_insert_with(|| json!({}));
        if let Some(sm) = scopes.as_object_mut() {
            sm.insert(s.to_string(), json!(key));
        }
    }
    next
}

/// `models_save` 的 scope ⇒ 槽位：只有命中模块槽位表才算一个槽，缺省/非法值不写
/// （与退役前的 `build_next` 同口径）。
fn save_slot(scope: &str) -> Option<&str> {
    if AI_SCOPES.contains(&scope) { Some(scope) } else { None }
}

/// models:save — 保存单个模型项（含连通性校验，落盘携带密钥的配置）
#[tauri::command]
pub async fn models_save<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    key: Option<String>,
    config: Option<Value>,
    scope: Option<String>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let key = key.unwrap_or_default();
    if !AI_MODEL_KEYS.contains(&key.as_str()) {
        return Ok(json!({ "success": false, "message": "未知的模型项" }));
    }
    let cfg = config.unwrap_or_else(|| json!({}));
    let base = settings::base_model(&key);
    let raw_url = {
        let submitted = truthy_string(cfg.get("apiUrl")).unwrap_or_default().trim().to_string();
        if submitted.is_empty() {
            base.get("apiUrl").and_then(|v| v.as_str()).unwrap_or("").to_string()
        } else {
            submitted
        }
    };
    if !is_http_url(&raw_url) {
        return Ok(json!({
            "success": false,
            "message": "API 接口地址格式无效，请以 http(s):// 开头"
        }));
    }
    let timeout = clamp_timeout(cfg.get("timeout"), 30);
    let mut models = models_config();
    // 百度千帆走专用 web_summary 接口（不归一化）；其余统一归一为 OpenAI 兼容 chat/completions
    let api_url = if key == "baidu_pro" {
        raw_url
    } else {
        normalize_chat_completions_url(&raw_url)
    };
    if is_private_api_url(&api_url) {
        return Ok(json!({ "success": false, "message": "API 接口地址不允许指向本机或内网网段" }));
    }
    // 审查 v2-U2（v3 拍板收紧）：域名一律放行，明文 http 下中间人可替换响应且自定义头
    // （含 Authorization）明文过链路 ⇒ 自定义源只认 https。与 cleanup 规则源同一口径。
    if let Some(reason) = settings::is_insecure_api_scheme(&api_url) {
        return Ok(json!({ "success": false, "message": reason }));
    }

    let cur = models.get(&key).cloned().unwrap_or_else(|| json!({}));
    // 掩码穿透（审查 1-5）：渲染层回传掩码 = 用户未修改密钥，保留已存真值；空串仍表示清除
    let api_key = match cfg_str(&cfg, "apiKey") {
        Some(v) if v != SECRET_MASK => v,
        _ => truthy_string(cur.get("apiKey")).unwrap_or_default(),
    };
    let patch = json!({
        "apiUrl": api_url,
        "apiKey": api_key,
        "model": match cfg.get("model") {
            Some(_) => cfg_str(&cfg, "model").unwrap_or_default(),
            None => truthy_string(cur.get("model")).unwrap_or_default(),
        },
        "prompt": match cfg.get("prompt") {
            Some(_) => cfg_str(&cfg, "prompt").unwrap_or_default(),
            None => truthy_string(cur.get("prompt")).unwrap_or_default(),
        },
        "customName": match cfg.get("customName") {
            Some(_) => cfg_str(&cfg, "customName").unwrap_or_default(),
            None => truthy_string(cur.get("customName")).unwrap_or_default(),
        },
        "timeout": timeout,
        "enabled": match cfg.get("enabled") {
            Some(_) => js_truthy(cfg.get("enabled")),
            None => js_truthy(cur.get("enabled")),
        },
    });
    let merged = settings::merge_model(cur.clone(), Some(&patch));
    if let Some(map) = models.as_object_mut() {
        map.insert(key.clone(), merged);
    }
    let entry = models.get(&key).cloned().unwrap_or_else(|| json!({}));
    let scope_text = if scope.as_deref().map(|s| AI_SCOPES.contains(&s)).unwrap_or(false) {
        format!(
            "，来源模块：{}",
            settings::scope_meta(scope.as_deref().unwrap_or("")).0
        )
    } else {
        String::new()
    };

    if key == "custom" && !js_truthy(entry.get("model")) {
        return Ok(json!({ "success": false, "message": "自定义模型需要填写模型名称" }));
    }

    // 密钥留空时（默认空态）：不允许启用该模型，跳过连通性校验（无凭据必然失败）
    if truthy_string(entry.get("apiKey")).unwrap_or_default().trim().is_empty() {
        if let Some(map) = models.as_object_mut() {
            if let Some(item) = map.get_mut(&key).and_then(|v| v.as_object_mut()) {
                item.insert("verified".into(), json!(false));
                item.insert("enabled".into(), json!(false));
                item.remove("verifiedAt");
            }
        }
        // v4 组 1：读-改-写收口 —— update_settings 内部的「最新盘上值」替代旧 current 克隆
        let touched = models.get(&key).cloned().unwrap_or_else(|| json!({}));
        let full_models = models.clone();
        let saved = settings::update_settings(|next| {
            *next = apply_model_edit(next, &key, Some(&touched), save_slot(scope.as_deref().unwrap_or("")), Some(&full_models));
            Ok(())
        })
        .is_ok();
        log::write_log(
            "info",
            &format!(
                "保存模型配置[无密钥]: {}，已保存但未启用（密钥为空）{scope_text}",
                model_display_name(&key, Some(&entry))
            ),
        );
        return Ok(json!({
            "success": saved,
            "message": if saved { "" } else { "写入配置文件失败" },
            "data": { "verified": false, "reply": "", "emptyKey": true }
        }));
    }

    // 保存即校验：向该模型发送一条确认消息，只有返回内容才确认新增成功
    let verify_cfg = models.get(&key).cloned().unwrap_or_else(|| json!({}));
    let verify_key = key.clone();
    let verify_resp = tauri::async_runtime::spawn_blocking(move || {
        call_model_text(&verify_key, &verify_cfg, settings::AI_VERIFY_PROMPT)
    })
    .await
    .map_err(|e| format!("连通性校验任务异常: {e}"))?;
    let reply = verify_resp
        .as_deref()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let ok = !reply.is_empty();

    if let Some(map) = models.as_object_mut() {
        if let Some(item) = map.get_mut(&key).and_then(|v| v.as_object_mut()) {
            let enabled_now = js_truthy(item.get("enabled"));
            item.insert("verified".into(), json!(ok));
            item.insert("enabled".into(), json!(if ok { enabled_now } else { false }));
            if ok {
                item.insert("verifiedAt".into(), json!(settings::iso_utc_now()));
            } else {
                item.remove("verifiedAt");
            }
        }
    }
    // v4 组 1：读-改-写收口（同上）
    let touched = models.get(&key).cloned().unwrap_or_else(|| json!({}));
        let full_models = models.clone();
    let saved = settings::update_settings(|next| {
        *next = apply_model_edit(next, &key, Some(&touched), save_slot(scope.as_deref().unwrap_or("")), Some(&full_models));
        Ok(())
    })
    .is_ok();
    let entry = models.get(&key).cloned().unwrap_or_else(|| json!({}));
    log::write_log(
        "info",
        &format!(
            "保存模型配置: {}，连通性校验{}{scope_text}",
            model_display_name(&key, Some(&entry)),
            if ok { "成功" } else { "失败" }
        ),
    );
    Ok(json!({
        "success": saved,
        "message": if saved { "" } else { "写入配置文件失败" },
        "data": {
            "verified": ok,
            "reply": if ok { reply.chars().take(200).collect::<String>() } else { String::new() },
        }
    }))
}

/// models:set-scope — 设置 AI 简介全局模型（统筹全局：只写 global 槽位）
///
/// 适配层载荷为 `{ scope, key }`（modelpicker 传所选模块），但 Electron 侧 handler 只读
/// `key` 且**只写 `aiScopes.global`**——此处保持同一语义，`scope` 仅用于接收载荷。
#[tauri::command]
pub fn models_set_scope<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    key: Option<String>,
    scope: Option<String>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let key = key.unwrap_or_default();
    if !AI_MODEL_KEYS.contains(&key.as_str()) {
        return Ok(json!({ "success": false, "message": "未知的模型项" }));
    }
    let models = models_config();
    let selected = models.get(&key).cloned().unwrap_or_else(|| json!({}));
    if !js_truthy(selected.get("enabled")) || !js_truthy(selected.get("verified")) {
        return Ok(json!({ "success": false, "message": "只能选择已验证且已启用的模型" }));
    }
    // R1b-M06：scope 是模块槽位（AI_SCOPES 六项）时写该槽；global/缺省才写全局槽。
    let slot = scope
        .as_deref()
        .filter(|s| AI_SCOPES.contains(s))
        .unwrap_or(GLOBAL_ENGINE_KEY);
    // P1-5：旧写法先 `scope_engines()` 取整张快照、再在闭包里 `insert("aiScopes", 整块)`
    // —— 别的槽位被这份快照整表顶掉。现在只在锁内的盘上最新值上改**本次那一个槽**，
    // 写入口径与 models_save 同一条（apply_model_edit 的 entry=None 分支）。
    let slot_owned = slot.to_string();
    let ok = settings::update_settings(|next| {
        *next = apply_model_edit(next, &key, None, Some(slot_owned.as_str()), None);
        Ok(())
    })
    .is_ok();
    log::write_log(
        "info",
        &format!(
            "切换 AI 简介全局模型: {}",
            model_display_name(&key, Some(&selected))
        ),
    );
    Ok(json!({
        "success": ok,
        "message": if ok { "" } else { "写入配置文件失败" }
    }))
}

/// models:test — 单独测试某个模型的连通性（不落盘；草稿配置优先）
#[tauri::command]
pub async fn models_test<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    key: Option<String>,
    config: Option<Value>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let key = key.unwrap_or_default();
    if !AI_MODEL_KEYS.contains(&key.as_str()) {
        return Ok(json!({ "success": false, "message": "未知的模型项" }));
    }
    let cfg = config.unwrap_or_else(|| json!({}));
    let models = models_config();
    let base = models.get(&key).cloned().unwrap_or_else(|| json!({}));

    let raw_url = truthy_string(cfg.get("apiUrl"))
        .or_else(|| truthy_string(base.get("apiUrl")))
        .unwrap_or_default()
        .trim()
        .to_string();
    let api_url = if key == "baidu_pro" {
        raw_url
    } else {
        normalize_chat_completions_url(&raw_url)
    };
    let api_key = match cfg_str(&cfg, "apiKey") {
        Some(v) if v != SECRET_MASK => v,
        _ => truthy_string(base.get("apiKey")).unwrap_or_default(),
    };
    let model = match cfg.get("model") {
        Some(_) => cfg_str(&cfg, "model").unwrap_or_default(),
        None => truthy_string(base.get("model")).unwrap_or_default(),
    };
    let timeout = match cfg.get("timeout") {
        Some(_) => clamp_timeout(cfg.get("timeout"), 30),
        None => clamp_timeout(base.get("timeout"), 30),
    };
    if !is_http_url(&api_url) {
        return Ok(json!({
            "success": false,
            "message": "API 接口地址格式无效，请以 http(s):// 开头"
        }));
    }
    if is_private_api_url(&api_url) {
        return Ok(json!({ "success": false, "message": "API 接口地址不允许指向本机或内网网段" }));
    }
    // 审查 v2-U2（v3 拍板收紧）：与 save 同一口径，测试连接同样只认 https。
    if let Some(reason) = settings::is_insecure_api_scheme(&api_url) {
        return Ok(json!({ "success": false, "message": reason }));
    }

    let test_cfg = json!({
        "apiUrl": api_url,
        "apiKey": api_key,
        "model": model,
        "timeout": timeout,
    });
    let test_key = key.clone();
    let start = crate::engine::now_ms();
    let reply = tauri::async_runtime::spawn_blocking(move || {
        call_model_text(&test_key, &test_cfg, settings::AI_VERIFY_PROMPT)
    })
    .await
    .map_err(|e| format!("连通性测试任务异常: {e}"))?;
    let latency_ms = crate::engine::now_ms() - start;
    let reply = reply
        .as_deref()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if !reply.is_empty() {
        return Ok(json!({
            "success": true,
            "message": "连接成功",
            "latencyMs": latency_ms,
            "data": { "reply": reply.chars().take(200).collect::<String>() }
        }));
    }
    Ok(json!({
        "success": false,
        "message": "连接失败：未获得有效响应（请检查地址、密钥与模型名称）",
        "latencyMs": latency_ms
    }))
}

/// models:open-window — 打开「大模型管理」独立窗口（单例）
#[tauri::command]
pub async fn models_open_window<R: tauri::Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Some(existing) = app.get_webview_window(LABEL) {
        crate::focus_window(&existing);
        return Ok(json!({ "success": true, "alreadyOpen": true }));
    }
    let builder = WebviewWindowBuilder::new(&app, LABEL, WebviewUrl::App(PAGE.into()))
        .title(TITLE)
        .inner_size(720.0, 680.0)
        .min_inner_size(600.0, 520.0)
        // 与主窗同源的浅色底（Electron backgroundColor: '#f3f3f3'）
        .background_color(Color(243, 243, 243, 255))
        .center()
        // 先隐藏，等首帧渲染完成再显示（ready-to-show 等价物）
        .visible(false)
        .on_page_load(|window, payload| {
            if payload.event() == PageLoadEvent::Finished {
                // 开发期不抢前台（见 lib.rs::activate_window）
                crate::activate_window(&window);
            }
        });
    // 审查 K4 复盘：子窗也必须透传浏览器参数，否则带调试端口启动时静默建不出窗
    let builder = crate::with_browser_args(builder);
    match builder.parent(&window) {
        Ok(builder) => match builder.build() {
            Ok(w) => Ok(super::window_built_receipt(&w, TITLE)),
            Err(e) => {
                log::write_log("error", &format!("创建「大模型管理」窗口失败: {e}"));
                Ok(json!({
                    "success": false,
                    "message": format!("创建「大模型管理」窗口失败: {e}")
                }))
            }
        },
        Err(e) => {
            log::write_log("error", &format!("「大模型管理」窗口挂靠主窗口失败: {e}"));
            Ok(json!({
                "success": false,
                "message": format!("「大模型管理」窗口挂靠主窗口失败: {e}")
            }))
        }
    }
}

/// models:close-window — 关闭发起调用的窗口本身（窗口内「完成」按钮）
#[tauri::command]
pub fn models_close_window<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    if let Err(e) = window.close() {
        log::write_log("warn", &format!("关闭「大模型管理」窗口失败: {e}"));
    }
    Ok(json!({ "success": true }))
}
#[cfg(test)]
mod p1_5_concurrency_tests {
    use super::*;

    /// 并发保存两个模型键：A 的快照是「校验开始前」读的那张，B 在校验期间落盘。
    /// 旧 `build_next` 在这里会把整张 A 快照盖回去，B 那一键就此消失。
    /// 判红自证：把 `apply_model_edit` 的 `entry` 分支改回
    /// `map.insert("models", models_snapshot.clone())`（整表替换）⇒ 本用例红。
    #[test]
    fn 两个模型键并发保存互不吞() {
        let 盘上最新 = json!({
            "models": { "metaso": { "model": "m", "verified": true }, "xiaoce": { "model": "n" } },
            "aiScopes": { "global": "metaso" },
        });
        // A 在校验前读到的旧快照（没有 B 那一键）
        let a_旧快照 = json!({ "metaso": { "model": "m", "verified": true } });
        let mut 模拟盘 = 盘上最新.clone();
        // B 先落盘（用同一把写入口径，只是另一个键）
        模拟盘 = apply_model_edit(&模拟盘, "xiaoce", Some(&json!({ "model": "n", "verified": true })), None, None);
        // A 的校验这时才回来，拿着旧快照写
        模拟盘 = apply_model_edit(&模拟盘, "metaso", Some(a_旧快照.get("metaso").unwrap()), None, None);

        let models = 模拟盘["models"].as_object().unwrap();
        assert!(models.contains_key("xiaoce"), "B 那一键被 A 的旧快照吞掉了");
        assert!(models.contains_key("metaso"), "A 自己的键必须写入");
        assert_eq!(models.len(), 2, "不得凭空多键或少键: {models:?}");
        // 无关字段必须整块保住
        assert_eq!(模拟盘["aiScopes"]["global"], json!("metaso"), "aiScopes 不得被顺手改掉");
    }

    /// 并发设两个槽位：A 设 optimizer、B 设 aidesc，两个槽都必须在。
    /// 判红自证：把槽位分支改回「取整张 aiScopes 快照再整块 insert」⇒ 本用例红。
    #[test]
    fn 两个槽位并发设置互不吞() {
        let mut 盘 = json!({ "models": {}, "aiScopes": { "global": "metaso" } });
        盘 = apply_model_edit(&盘, "siliconflow", None, Some("aidesc"), None);
        盘 = apply_model_edit(&盘, "metaso", None, Some("optimizer"), None);
        let scopes = 盘["aiScopes"].as_object().unwrap();
        assert_eq!(scopes.get("aidesc"), Some(&json!("siliconflow")));
        assert_eq!(scopes.get("optimizer"), Some(&json!("metaso")));
        assert_eq!(scopes.get("global"), Some(&json!("metaso")), "没被点名的槽必须原样保留");
    }

    /// 边界三条：scope 不是真槽位时不动 aiScopes；entry=None 时不往 models 塞字符串；
    /// models/aiScopes 尚不存在时按需建出（首次保存路径）。
    /// 判红自证：删掉 `save_slot` 的 AI_SCOPES 过滤 ⇒ 第一条红；
    /// 把 `if let Some(e)` 的守卫去掉 ⇒ 第二条红。
    #[test]
    fn 未点名的键与非法槽位一律不动() {
        let base = json!({ "models": { "metaso": { "model": "m" } }, "aiScopes": { "global": "metaso" } });
        let out = apply_model_edit(&base, "metaso", Some(&json!({ "model": "m2" })), save_slot("随便一个不是槽位的串"), None);
        assert_eq!(out["aiScopes"], base["aiScopes"], "非法 scope 不得写 aiScopes");
        assert_eq!(out["models"]["metaso"]["model"], json!("m2"));

        let out = apply_model_edit(&base, "metaso", None, Some("global"), None);
        assert_eq!(out["models"]["metaso"]["model"], json!("m"), "entry=None 不得改 models");
        assert!(out["models"]["metaso"].is_object(), "models 里不许出现字符串条目");

        let 空 = json!({});
        let out = apply_model_edit(&空, "metaso", Some(&json!({ "model": "m" })), Some("global"), None);
        assert_eq!(out["models"]["metaso"]["model"], json!("m"), "首次保存必须建出 models 段");
        assert_eq!(out["aiScopes"]["global"], json!("metaso"), "首次保存必须建出 aiScopes 段");
    }

    /// R1b-M09 回归钉：盘上没有 models 段（平铺字段时代）时，首次保存必须用
    /// 读侧迁移好的**整张** models 建段 —— 只补写本键会让迁移分支永久失效，
    /// 其余键的平铺旧值不再被采信、静默回退出厂值。
    #[test]
    fn 首次保存必须用整张迁移表建段() {
        let 平铺迁移整表 = json!({
            "baidu": { "model": "b-old", "verified": true },
            "zhihu": { "model": "z-old", "verified": true },
            "metaso": { "model": "m-old", "verified": true },
            "custom": { "model": "c-old", "verified": true }
        });
        let 盘上无models段 = json!({});
        let out = apply_model_edit(
            &盘上无models段, "metaso",
            Some(&json!({ "model": "m-new", "verified": false })),
            None, Some(&平铺迁移整表),
        );
        assert_eq!(out["models"]["metaso"]["model"], json!("m-new"), "本次键按新值写");
        assert_eq!(out["models"]["baidu"]["model"], json!("b-old"), "其余键的平铺旧值必须随首次写入落盘");
        assert_eq!(out["models"]["custom"]["model"], json!("c-old"), "其余键不得回退出厂默认");
        // 盘上已有 models 段时整表参数不参与：按键补写语义不变（P1-5 并发判据）
        let 已有段 = json!({ "models": { "baidu": { "model": "b-live" } } });
        let out = apply_model_edit(
            &已有段, "metaso", Some(&json!({ "model": "m-new2" })), None,
            Some(&json!({ "baidu": { "model": "旧快照" } })),
        );
        assert_eq!(out["models"]["baidu"]["model"], json!("b-live"), "已有段时不得被旧快照整表顶掉");
        assert_eq!(out["models"]["metaso"]["model"], json!("m-new2"));
    }
}
