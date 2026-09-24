//! IPC 集成冒烟：Tauri 官方**无窗口测试路径**（`tauri::test` 的 MockRuntime）。
//!
//! 背景：原 `tools/cdp-smoke.mjs` 走 CDP 远程调试端口，必须建真实 WebView2 窗口。
//! 按要求**全局停用 CDP** 后改为本文件——不建真实窗口、不抢前台、不开远程调试端口，
//! 直接经**真实 IPC 调用链**回归：
//! `get_ipc_response` → `Webview::on_message` → `#[tauri::command]` 命令体 → 返回体。
//!
//! 覆盖面对应原 CDP 脚本用例：
//! - **快速组（默认跑）**：形状校验 + 负例拦截（白名单/快照闸门/掩码语义）。
//! - **重/外呼组（`#[ignore]`）**：真实 PowerShell、真实扫盘、真实网络探测，
//!   由 `cargo test --test ipc_smoke -- --ignored` 作为发布前门禁执行。
//!
//! 命令清单来自 `trim_tauri_lib::build_app`——与生产入口共用同一份 `generate_handler!`，
//! 测试里不再复制清单，新增命令漏测不会静默漂移。
//!
//! 已知不覆盖（如实登记）：子窗口（preview / processManager / models）的
//! 「建窗 → 加载 → 自关」链路依赖真实 WebView 行为，mock runtime 覆盖不到，
//! 留 Phase 2 手动验收；**不**为此引入 WebDriver/tauri-driver 依赖。
//! （审查 M1~M3 后补：子窗 label 的**来源校验档位**已可 mock 覆盖，见文件末尾
//!  「子窗口来源校验档位」一组；仍不覆盖的是真实建窗与页面加载。）

use serde_json::{json, Value};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{
    get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY,
};
use tauri::webview::InvokeRequest;
use tauri::{WebviewUrl, WebviewWindow, WebviewWindowBuilder};

/// 建一个独立的测试 App + 主窗口（label = `main`）。
///
/// 每条用例各自建 app/窗口：快照类命令（finder/memory）按**窗口 label 分槽**，
/// 独立 app 可避免用例间状态串台；label 用 `main` 与生产一致（`guard` 只放行已知窗口）。
fn main_window() -> WebviewWindow<MockRuntime> {
    let app = trim_tauri_lib::build_app(mock_builder())
        .build(mock_context(noop_assets()))
        .expect("测试 App 构建失败");
    WebviewWindowBuilder::new(&app, "main", WebviewUrl::default())
        .build()
        .expect("测试主窗口创建失败")
}

/// 经真实 IPC 调用链发一条命令并取回返回体。
///
/// - `url` 固定 `http://tauri.localhost`：Windows 下 mock runtime 的本地来源
///   （`is_local_url` 据此判 Origin::Local，ACL 不拦自定义命令）；
/// - `invoke_key` 用 `tauri::test::INVOKE_KEY`：与 `mock_builder` 注入的钥匙一致；
/// - 参数名按既有约定用 camelCase（tauri 宏默认 `rename_all = "camelCase"`）。
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

fn invoke(window: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Value {
    match get_ipc_response(window, ipc_request(cmd, args)) {
        Ok(body) => body.deserialize::<Value>().expect("命令返回体不是合法 JSON"),
        Err(e) => panic!("{cmd} 被 IPC 层拒绝（命令未注册或 invoke_key 不符）: {e}"),
    }
}

/// 同 `invoke`，但把回执压成文本返回。
/// 命令签名是 `Result<_, String>` 时（来源校验失败即此类）回执不是 JSON 对象，
/// `invoke` 会直接 panic —— 审查 M1~M3 的档位断言只看「有没有被拒杀」，用这个。
fn invoke_text(window: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> String {
    match get_ipc_response(window, ipc_request(cmd, args)) {
        Ok(body) => match body.deserialize::<Value>() {
            Ok(v) => v.to_string(),
            Err(e) => format!("<非 JSON 回执 {e}>"),
        },
        Err(e) => e.to_string(),
    }
}

/// 取返回体 message 字段（负例文案断言用）
fn message_of(res: &Value) -> String {
    res.get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

// ==================== 快速组（默认跑） ====================

/// cleanup:rules 必须走完整规则库加载链（数据目录验签 > 内置兜底）。
/// 防的是：规则库读取失败会让清理页规则表整体塌成空（表现为「没有可清理项」）。
#[test]
fn cleanup_rules_success() {
    let w = main_window();
    let res = invoke(&w, "cleanup_rules", json!({}));
    assert_ne!(res["success"], json!(false), "规则库验签加载链不应失败: {res}");
}

/// settings:load 密钥掩码语义：返回体里**不得**出现 `dpapi:v1:` 密文。
/// 防的是：密钥经 IPC 明文回渲染层（掩码绕过 = 凭据外泄）。
#[test]
fn settings_load_masks_dpapi_secrets() {
    let w = main_window();
    let res = invoke(&w, "settings_load", json!({}));
    assert_eq!(res["success"], json!(true), "settings:load 应成功: {res}");
    assert!(
        !res.to_string().contains("dpapi:v1:"),
        "settings:load 返回体外泄了 dpapi:v1: 密文（掩码语义被破坏）"
    );
}

/// fonts:list 形状：`success` 为布尔、`data.list` 为数组。
/// 防的是：形状漂移让渲染层字体下拉渲染崩掉（前端按 data.list 直接 map）。
#[test]
fn fonts_list_shape() {
    let w = main_window();
    let res = invoke(&w, "fonts_list", json!({}));
    assert!(res["success"].is_boolean(), "success 必须是布尔: {res}");
    assert!(res["data"]["list"].is_array(), "data.list 必须是数组: {res}");
}

/// bench_history_list 形状：`success` 恒 true、`data` 恒为数组（无记录时空数组）。
/// 防的是：空历史被返回成 null 让「跑分记录」页报错。
#[test]
fn bench_history_list_shape() {
    let w = main_window();
    let res = invoke(&w, "bench_history_list", json!({}));
    assert_eq!(res["success"], json!(true), "bench_history:list 应成功: {res}");
    assert!(res["data"].is_array(), "data 必须是数组: {res}");
}

/// quickcmds:run 白名单闸门：未知 id 一律拒绝。
/// 防的是：渲染层被注入后借快捷指令通道执行任意命令（QC-1 禁止任意命令执行）。
#[test]
fn quickcmds_run_rejects_unknown_id() {
    let w = main_window();
    let res = invoke(&w, "quickcmds_run", json!({ "id": "__trim_smoke_unknown__" }));
    assert_eq!(res["success"], json!(false), "未知指令必须被拒: {res}");
    assert!(message_of(&res).contains("未知指令"), "文案应含「未知指令」: {res}");
}

/// diskbench:run 路径白名单（SP-1）：系统目录不在「用户目录/TEMP/AppData」内。
/// 防的是：任意路径落盘测速（往系统盘刷数据、污染只读目录）。
#[test]
fn diskbench_run_rejects_outside_whitelist() {
    let w = main_window();
    let res = invoke(&w, "diskbench_run", json!({ "options": { "path": "C:\\Windows" } }));
    assert_eq!(res["success"], json!(false), "白名单外路径必须被拒: {res}");
}

/// finder:delete 快照闸门：未扫描过的路径先判「已过期」。
/// 判定顺序与 Electron 一致——**快照校验先于受保护路径判定**；
/// 防的是：绕过扫描快照提交任意路径，越权删除未授权目标。
#[test]
fn finder_delete_rejects_unscanned_path() {
    let w = main_window();
    let res = invoke(
        &w,
        "finder_delete",
        json!({ "items": [{ "path": "C:\\__trim_smoke_unscanned__\\never.txt" }] }),
    );
    assert_eq!(res["success"], json!(false), "未扫描路径必须被拒: {res}");
    assert!(message_of(&res).contains("已过期"), "文案应含「已过期」: {res}");
}

/// finder:scan 类型白名单：未知扫描类型在触盘前即拒绝。
/// 防的是：未知类型被透传到原生引擎导致行为未定义/报错文案漂移。
#[test]
fn finder_scan_rejects_unknown_type() {
    let w = main_window();
    let res = invoke(&w, "finder_scan", json!({ "scanType": "__trim_smoke_unknown__" }));
    assert_eq!(res["success"], json!(false), "未知扫描类型必须被拒: {res}");
    assert!(
        message_of(&res).contains("未知扫描类型"),
        "文案应含「未知扫描类型」: {res}"
    );
}

/// finder:delete-manifest 形状：`success` 恒 true、`data.items` 恒为数组（允许为空）。
/// 防的是：清单读取失败让「删除记录」页整体报错（应为空列表降级）。
#[test]
fn finder_delete_manifest_shape() {
    let w = main_window();
    let res = invoke(&w, "finder_delete_manifest", json!({}));
    assert_eq!(res["success"], json!(true), "delete-manifest 应成功: {res}");
    assert!(res["data"]["items"].is_array(), "data.items 必须是数组: {res}");
}

// ==================== 重 / 外呼组（默认 ignore，发布前门禁跑） ====================

/// pwsh:status 形状：`success` true 且 `data.status` 是字符串。
/// 成本：候选链探测会同步 spawn PowerShell 探测候选版本（秒级）。
#[test]
#[ignore = "需本机 PowerShell 7 候选链探测（同步 spawn，秒级），发布前门禁跑"]
fn pwsh_status_shape() {
    let w = main_window();
    let res = invoke(&w, "pwsh_status", json!({}));
    assert_eq!(res["success"], json!(true), "pwsh:status 应成功: {res}");
    assert!(res["data"]["status"].is_string(), "data.status 必须是字符串: {res}");
}

/// memory:info 形状 + 物理内存总量 > 0。
/// 成本：真实跑一段 PowerShell 脚本（进程外呼 + 秒级）。
#[test]
#[ignore = "走真实 PowerShell 脚本读取内存信息（外呼 + 秒级），发布前门禁跑"]
fn memory_info_reports_total() {
    let w = main_window();
    let res = invoke(&w, "memory_info", json!({}));
    assert_eq!(res["success"], json!(true), "memory:info 应成功: {res}");
    let total = res["data"]["total"].as_f64().unwrap_or(0.0);
    assert!(total > 0.0, "data.total 必须 > 0: {res}");
}

/// memory:processes 形状：真实列进程，`processes` 必须是非空数组。
/// 成本：真实 PowerShell 枚举进程（外呼 + 秒级）。
#[test]
#[ignore = "走真实 PowerShell 枚举进程（外呼 + 秒级），发布前门禁跑"]
fn memory_processes_non_empty() {
    let w = main_window();
    let res = invoke(&w, "memory_processes", json!({}));
    assert_eq!(res["success"], json!(true), "memory:processes 应成功: {res}");
    let processes = res["processes"].as_array().cloned().unwrap_or_default();
    assert!(!processes.is_empty(), "processes 必须非空: {res}");
}

/// memory:kill 快照白名单：PID 不在「本窗口最近一次扫描」内一律拒绝。
/// 防的是：渲染层被注入后结束任意进程；该负例不真杀进程，但与扫描语义同组跑。
#[test]
#[ignore = "依赖 memory:processes 的扫描语义（快照白名单），与重/外呼组同跑"]
fn memory_kill_requires_recent_scan() {
    let w = main_window();
    let res = invoke(&w, "memory_kill", json!({ "pid": 2_147_483_000 }));
    assert_eq!(res["success"], json!(false), "未扫描 PID 必须被拒: {res}");
    assert!(
        message_of(&res).contains("最近一次扫描"),
        "文案应含「最近一次扫描」: {res}"
    );
}

/// finder:scan（bigfiles）正向链路：对 `CARGO_MANIFEST_DIR/src` 这个小目录扫 5 条。
/// 成本：真实递归扫盘（IO），且正向结果依赖本机磁盘状态。
#[test]
#[ignore = "真实递归扫盘（IO 成本），发布前门禁跑"]
fn finder_scan_bigfiles_small_dir() {
    let w = main_window();
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "\\src");
    let res = invoke(
        &w,
        "finder_scan",
        json!({ "scanType": "bigfiles", "paths": [src], "count": 5 }),
    );
    assert_eq!(res["success"], json!(true), "小目录 bigfiles 扫描应成功: {res}");
    assert!(res["data"].is_array(), "data 必须是数组: {res}");
    // 审查 M8：回执必须自带「这份结果完不完整」的元数据。旧形状只有 success+data，
    // 于是「整个目录没权限读」与「真的没有大文件」在渲染层长得一模一样。
    assert!(
        res["errors"].is_number(),
        "errors 必须是数字（原生侧告警计数），回执 {res}"
    );
    assert!(
        res["truncated"].is_boolean(),
        "truncated 必须是布尔（是否撞到条目上限），回执 {res}"
    );
    assert_eq!(res["truncated"], json!(false), "小目录不该触发截断: {res}");
}

/// runtimes:collect 形状（`success` 为布尔）。
/// 成本：探测本机运行时，可能触发外部命令/外呼，耗时与结果均依赖本机环境。
#[test]
#[ignore = "探测本机运行时（可能触发外部命令/外呼），发布前门禁跑"]
fn runtimes_collect_shape() {
    let w = main_window();
    let res = invoke(&w, "runtimes_collect", json!({}));
    assert!(res["success"].is_boolean(), "success 必须是布尔: {res}");
}

/// netcheck:collect 形状（`success` 为布尔）。
/// 成本：真实网络探测，依赖外网可达性（离线环境会失败，故不与快速组同跑）。
#[test]
#[ignore = "真实网络探测（外网依赖），发布前门禁跑"]
fn netcheck_collect_shape() {
    let w = main_window();
    let res = invoke(&w, "netcheck_collect", json!({}));
    assert!(res["success"].is_boolean(), "success 必须是布尔: {res}");
}

// ==================== 子窗口来源校验档位（审查 M1~M3 回归网） ====================
//
// 为什么单列一组：本文件此前**每条用例都建 label="main" 的窗口**，于是「子窗专属命令被
// `guard::MAIN` 拒杀」这类缺陷在几十条绿灯里完全隐形——外设窗的 apply/restore、
// 预览窗的 delete-file 全部 100% 不可用却测不出来（文件头的「已知不覆盖：子窗口」即此）。
// 这些用例只打快速组，不建真实窗口、不跑 PowerShell。

/// 建一个指定 label 的测试窗口（与生产同 label 集，见 `engine::guard::APP_WINDOWS`）。
fn window_with_label(label: &str) -> WebviewWindow<MockRuntime> {
    let app = trim_tauri_lib::build_app(mock_builder())
        .build(mock_context(noop_assets()))
        .expect("测试 App 构建失败");
    WebviewWindowBuilder::new(&app, label, WebviewUrl::default())
        .build()
        .unwrap_or_else(|e| panic!("测试窗口 {label} 创建失败: {e}"))
}

/// 断言回执里**不是**来源校验失败（档位放对的判据）。
fn assert_guard_passed(text: &str, ctx: &str) {
    assert!(!text.contains("IPC 来源校验失败"), "{ctx}: 被来源校验拒杀，回执 {text}");
}

/// 外设子窗必须能调 `peripheral_apply`（非管理员时回 needAdmin，而不是被拒杀）。
/// 传空 options → 三组都归一为 -1 → 命令在写注册表之前就返回「没有需要应用的设置」，
/// 因此本用例在任何权限等级下都不会改动系统。
#[test]
fn peripheral_subwindow_can_call_apply() {
    let w = window_with_label("peripheral");
    let text = invoke_text(&w, "peripheral_apply", json!({ "options": {} }));
    assert_guard_passed(&text, "peripheral_apply 应允许外设窗调用");
}

/// 提权仍是主窗专属红线（AGENTS.md §3）：子窗不得触发放开。
#[test]
fn subwindow_cannot_request_elevation() {
    for label in ["peripheral", "preview", "processManager", "models"] {
        let w = window_with_label(label);
        let text = invoke_text(&w, "elevate_request", json!({}));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调 elevate_request 必须被拒（红线：提权只认主窗），回执 {text}"
        );
    }
}

/// 预览窗调 `fileclean_delete_file` 不得被档位拒杀（M2）：
/// 没有扫描槽时在 `in_scope` 处返回「不在扫描范围内」，这一层才是真闸门。
#[test]
fn preview_subwindow_reaches_fileclean_delete() {
    let w = window_with_label("preview");
    let text = invoke_text(&w, "fileclean_delete_file", json!({ "filePath": "C:\\nope\\a.jpg" }));
    assert_guard_passed(&text, "fileclean_delete_file 应允许预览窗调用（由 in_scope 收口）");
    assert!(
        text.contains("不在扫描范围"),
        "预览窗删除必须由 in_scope 拦下，而不是放行任意路径，回执 {text}"
    );
}