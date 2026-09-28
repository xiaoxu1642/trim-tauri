//! MockRuntime 无窗口验证底座（共享 fixture）。
//!
//! 为什么单独成模块：此前 `main_window` / `invoke` 等六个 helper 私有于
//! `ipc_smoke.rs`，agent 验证新模块只能改回归网文件本身或整段复制 helper——
//! 复制会随时间漂移（一处修 invoke_key/URL 语义、另一处还在用旧口径）。
//! 这里做单一真源，`ipc_smoke.rs` 与后续模块验证文件统一 `mod common;` 引用。
//!
//! 用法（tests/<name>.rs 顶部）：
//! ```text
//! mod common;
//! use common::{main_window, invoke, ipc};
//! ```
//!
//! 约束（与 ipc_smoke.rs 文件头一致，改动前先读那里）：
//! - 每条用例独立建 app+窗口：快照类命令按窗口 label 分槽，共享 app 会状态串台。
//! - `url` 固定 `http://tauri.localhost`：mock runtime 据此判 Origin::Local，ACL 不拦自定义命令。
//! - `invoke_key` 用 `tauri::test::INVOKE_KEY`：与 `mock_builder` 注入的钥匙一致。
//! - 参数名按 tauri 宏默认 `rename_all = "camelCase"`。
//! - 命令清单来自 `trim_tauri_lib::build_app`——与生产共用同一份 `generate_handler!`，
//!   新命令漏注册在这里会直接 panic（「命令未注册」），不会静默漂移。
//!
//! `allow(dead_code)`：共享 fixture 在每个测试 crate 独立编译，各文件只取所需，
//! 未引用的 helper 会触发 dead-code 警告并撞 AGENTS §4「0 警告」验收线——
//! 这是 Rust common-module 模式的固定代价，整表压制而非逐个标注（新增 helper 免漏标）。
#![allow(dead_code)]

use serde_json::Value;
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{
    get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY,
};
use tauri::webview::InvokeRequest;
use tauri::{WebviewUrl, WebviewWindow, WebviewWindowBuilder};

/// 建一个独立的测试 App + 主窗口（label = `main`）。
pub fn main_window() -> WebviewWindow<MockRuntime> {
    window_with_label("main")
}

/// 建一个指定 label 的测试窗口（label 集与生产一致，见 `engine::guard::APP_WINDOWS`）。
///
/// label 合法性不做测试侧硬编码校验：guard 档位本身就按 APP_WINDOWS 判，
/// 传未知 label 的窗口调任何带档位的命令会被来源校验拒杀——这正是档位回归的测点。
pub fn window_with_label(label: &str) -> WebviewWindow<MockRuntime> {
    let app = trim_tauri_lib::build_app(mock_builder())
        .build(mock_context(noop_assets()))
        .expect("测试 App 构建失败");
    WebviewWindowBuilder::new(&app, label, WebviewUrl::default())
        .build()
        .unwrap_or_else(|e| panic!("测试窗口 {label} 创建失败: {e}"))
}

/// 四个子窗 label（剔除主窗），从 `engine::guard::APP_WINDOWS` 派生——
/// 单一真源在 guard.rs，新增子窗时这里自动跟随，不会和守卫清单漂移。
/// ipc_smoke 的「子窗口来源校验档位」组与新的子窗档位测试都用它。
pub fn sub_windows() -> Vec<&'static str> {
    trim_tauri_lib::engine::guard::APP_WINDOWS
        .iter()
        .copied()
        .filter(|l| *l != "main")
        .collect()
}

/// 经真实 IPC 调用链发一条命令（不取回执——只断「不被拒杀」的档位场景用）。
pub fn ipc(window: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) {
    let req = ipc_request(cmd, args);
    let _ = get_ipc_response(window, req);
}

/// 经真实 IPC 调用链发一条命令并取回返回体（JSON）。
///
/// panic 语义：命令未注册 / invoke_key 不符 / 返回体不是合法 JSON 都会 panic——
/// 正向用例（期望命令存在且回 JSON）用它。
pub fn invoke(window: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Value {
    match get_ipc_response(window, ipc_request(cmd, args)) {
        Ok(body) => body.deserialize::<Value>().expect("命令返回体不是合法 JSON"),
        Err(e) => panic!("{cmd} 被 IPC 层拒绝（命令未注册或 invoke_key 不符）: {e}"),
    }
}

/// 同 `invoke`，但把回执压成文本返回。
/// 命令签名是 `Result<_, String>` 时（来源校验失败即此类）回执不是 JSON 对象，
/// `invoke` 会直接 panic —— 档位断言只看「有没有被拒杀」，用这个。
pub fn invoke_text(window: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> String {
    match get_ipc_response(window, ipc_request(cmd, args)) {
        Ok(body) => match body.deserialize::<Value>() {
            Ok(v) => v.to_string(),
            Err(e) => format!("<非 JSON 回执 {e}>"),
        },
        Err(e) => e.to_string(),
    }
}

/// 断言「命令确实越过了档位、跑进后面的逻辑」，而不只是「没被来源校验拒杀」。
/// 审查 v2-M16② 教训：只断「不含 IPC 来源校验失败」时，命令整条消失也是绿的，
/// 档位回归网会被无声架空。必须由调用方点名正向特征（期望回执含其一）。
pub fn assert_guard_passed(text: &str, ctx: &str, reached: &[&str]) {
    assert!(
        !text.contains("IPC 来源校验失败"),
        "{ctx}: 被来源校验拒杀，回执 {text}"
    );
    assert!(
        reached.iter().any(|k| text.contains(k)),
        "{ctx}: 拿不到任何「已越过档位」的正向回执（期望含其一：{reached:?}），回执 {text}"
    );
}

/// 取返回体 message 字段（负例文案断言用）
pub fn message_of(res: &Value) -> String {
    res.get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// 构造一条最小可用的 InvokeRequest。
///
/// 字段语义见模块头「约束」。`json!({})` 空参的直写惯法留给调用方
/// （`use serde_json::json`），这里不封装 args 层以保持薄。
fn ipc_request(cmd: &str, args: Value) -> InvokeRequest {
    InvokeRequest {
        cmd: cmd.to_string(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url: "http://tauri.localhost".parse().expect("测试 URL 解析失败"),
        body: InvokeBody::Json(args),
        headers: Default::default(),
        invoke_key: INVOKE_KEY.to_string(),
    }
}
