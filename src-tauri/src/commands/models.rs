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
    model_display_name, models_config, normalize_chat_completions_url, scope_engines,
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

/// `{...current, models, aiScopes: loadScopeEngines()}` + 可选写入来源模块
fn build_next(current: &Value, models: &Value, scope: &str, key: &str) -> Value {
    let mut next = current.clone();
    if let Some(map) = next.as_object_mut() {
        map.insert("models".into(), models.clone());
        let mut scopes = scope_engines();
        if AI_SCOPES.contains(&scope) {
            if let Some(sm) = scopes.as_object_mut() {
                sm.insert(scope.to_string(), json!(key));
            }
        }
        map.insert("aiScopes".into(), scopes);
    }
    next
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
    let current = settings::load_settings();
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
        let next = build_next(&current, &models, scope.as_deref().unwrap_or(""), &key);
        let saved = settings::save_settings(&next);
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
    let next = build_next(&current, &models, scope.as_deref().unwrap_or(""), &key);
    let saved = settings::save_settings(&next);
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
    let _ = scope; // 与 Electron 同语义：忽略模块参数，统一写全局槽位
    let key = key.unwrap_or_default();
    if !AI_MODEL_KEYS.contains(&key.as_str()) {
        return Ok(json!({ "success": false, "message": "未知的模型项" }));
    }
    let models = models_config();
    let selected = models.get(&key).cloned().unwrap_or_else(|| json!({}));
    if !js_truthy(selected.get("enabled")) || !js_truthy(selected.get("verified")) {
        return Ok(json!({ "success": false, "message": "只能选择已验证且已启用的模型" }));
    }
    let current = settings::load_settings();
    let mut scopes = scope_engines();
    if let Some(map) = scopes.as_object_mut() {
        map.insert(GLOBAL_ENGINE_KEY.into(), json!(key));
    }
    let mut next = current.clone();
    if let Some(map) = next.as_object_mut() {
        map.insert("aiScopes".into(), scopes);
    }
    let ok = settings::save_settings(&next);
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
    match builder.parent(&window) {
        Ok(builder) => match builder.build() {
            Ok(_) => Ok(json!({ "success": true })),
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