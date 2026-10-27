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
//! 已知不覆盖（如实登记）：**盲区成员不在此手抄**——窗口真源是
//! `engine::guard::APP_WINDOWS`（子窗 label 由 `common::sub_windows()` 从它派生）。
//! 该常量里的**每一个 label**（含主窗）的「建窗 → 加载 → 自关」链路都依赖真实 WebView 行为，
//! mock runtime 覆盖不到，留手动验收；**不**为此引入 WebDriver/tauri-driver 依赖。
//! （审查 X1-L04 订正：此前这段按记忆点名子窗，既点了已退役的那一个、又漏了现役的那一个
//! ——自然语言清单不在注释防腐蚀门禁的三种可机检形状里，抓不到这种漂移，
//! 所以改成只指真源、不列成员。）
//! （审查 M1~M3 后补：子窗 label 的**来源校验档位**已可 mock 覆盖，见文件末尾
//!  「子窗口来源校验档位」一组；仍不覆盖的是真实建窗与页面加载。）

mod common;

use common::{
    assert_guard_passed, invoke, invoke_text, main_window, message_of, probe_guard,
    sub_windows, window_with_label,
};
use serde_json::json;

// ==================== 快速组（默认跑） ====================

/// cleanup:rules 必须走完整规则库加载链（数据目录验签 > 内置兜底）。
/// 防的是：规则库读取失败会让清理页规则表整体塌成空（表现为「没有可清理项」）。
#[test]
fn cleanup_rules_success() {
    let w = main_window();
    let res = invoke(&w, "cleanup_rules", json!({}));
    assert_ne!(res["success"], json!(false), "规则库验签加载链不应失败: {res}");
}

/// settings:load 密钥掩码语义：**在场密钥必须被掩码**，且返回体里**不得**出现 `dpapi:v1:` 密文。
/// X1-M02：旧版在清空后的测试根上断「不含 dpapi:v1:」—— 没有密钥在场 ⇒ 反向断言必然成立，
/// 把 `SECRET_MASK` 换成明文回显这条也不会红。现在自播种一个密钥夹具做双向断言；
/// 播种触盘 ⇒ 按快组纪律挪真机组（`#[ignore]`，发布前门禁跑）。
#[test]
#[ignore = "自播种写盘（往隔离测试根播密钥夹具），按快组纪律挪真机组"]
fn settings_load_masks_dpapi_secrets() {
    // 真机组纪律：先定根（隔离测试根），播种才不落在真实数据目录上
    let _data = probe_guard();
    let w = main_window();
    let f = trim_tauri_lib::engine::paths::join_data("settings.json");
    std::fs::write(&f, "{\"baiduApiKey\": \"dpapi:v1:AAAAprobe\"}")
        .expect("往隔离测试根播种 settings.json 失败");
    let res = invoke(&w, "settings_load", json!({}));
    assert_eq!(res["success"], json!(true), "settings:load 应成功: {res}");
    assert!(
        res.to_string().contains(trim_tauri_lib::security::SECRET_MASK),
        "在场密钥未被掩码（掩码语义正向失效）: {res}"
    );
    assert!(
        !res.to_string().contains("dpapi:v1:"),
        "settings:load 返回体外泄了 dpapi:v1: 密文（掩码语义被破坏）"
    );
}

/// fonts:list 形状：`success` 为布尔、`data.list` 为数组。
/// 钉的是**后端契约本身**，不做「前端会兜底」的假设：渲染层 `fontmanager.js` 现算确有
/// `resp.data.list || []` 兜底，但兜底把形状漂移吞成「列表为空」——用户看到的是没有字体，
/// 不是页面崩。本用例要的是漂移当场判红，而不是依赖某一侧恰好写了兜底。
#[test]
fn fonts_list_shape() {
    let w = main_window();
    let res = invoke(&w, "fonts_list", json!({}));
    assert!(res["success"].is_boolean(), "success 必须是布尔: {res}");
    assert!(res["data"]["list"].is_array(), "data.list 必须是数组: {res}");
}

/// bench_history_list 形状：`success` 恒 true、`data` 恒为数组（无记录时空数组）。
/// 钉的是**后端契约本身**，不做「前端会兜底」的假设：渲染层 `diskbench.js` 现算确有
/// `resp.data || []` 兜底，但兜底把「空历史」与「形状塌成 null」压成同一表现——跑分页只是
/// 不显示记录，看不出契约被破坏。形状漂移必须在本层当场判红；
/// 与磁盘真值的条数对拍在 `module_smoke.rs` 的 `bench_history_list_matches_file_truth`（此处不重复钉）。
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
///
/// X1-M03（v7.2 C08）补拒因点名：此前只断 `success:false`，白名单闸被摘掉时
/// `C:\Windows` 会真去落盘测速、失败也回 `success:false` ⇒ 用例照绿——
/// 正是它自己注释声明要防的事。needle 取自 diskbench.rs 白名单分支的文案。
#[test]
fn diskbench_run_rejects_outside_whitelist() {
    let w = main_window();
    let res = invoke(&w, "diskbench_run", json!({ "options": { "path": "C:\\Windows" } }));
    assert_eq!(res["success"], json!(false), "白名单外路径必须被拒: {res}");
    assert!(
        message_of(&res).contains("测速路径受限"),
        "拒因必须点名白名单闸（否则「闸没了但测速自己失败」会冒充绿灯）: {res}"
    );
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
//
// `pwsh_status_shape` 随 v2-R1 一起删掉：PS7 通道整条摘除后 `pwsh_status` 命令不复存在，
// 用例在 `--ignored` 里报 "Command pwsh_status not found"。默认 `cargo test` 跑不到它，
// 所以这条只能靠发布前实跑 `#[ignore]` 抓到（AGENTS §4「照原样跑」的意义就在这）。

/// memory:info 形状 + 物理内存总量 > 0。
/// 成本：**已经是纯原生只读采集**（`native::memory_info`，`engine:"rust"`，无 PowerShell），
/// 留在这里是历史归类——原先这条走 PS 脚本。不挪进快速组是为了不动这一组的分组结构；
/// 真要挪，先确认 `spawn_blocking` 在 MockRuntime 下不引入调度依赖。
#[test]
#[ignore = "读真实性能计数器（进程外 API，毫秒级），发布前门禁跑"]
fn memory_info_reports_total() {
    let _data = probe_guard();
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
    let _data = probe_guard();
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
    let _data = probe_guard();
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
    let _data = probe_guard();
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
    let _data = probe_guard();
    let w = main_window();
    let res = invoke(&w, "runtimes_collect", json!({}));
    assert!(res["success"].is_boolean(), "success 必须是布尔: {res}");
    // v5 P2：只断「success 是布尔」⇒ 检测整条失败（success:false、压根没有 items）也绿。
    // 按 §4.1 纪律③「形状断言对渲染层消费口径写」补齐：前端 runtimes.js 对 data.items
    // 直接 `.map`、读 summary.{total,ok,warn,fail}，并按 id 去 ITEM_META 取标签。
    assert!(res["success"].as_bool().unwrap_or(false), "本机运行库检测整条失败: {res}");
    let items = res["data"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("data.items 必须是数组（前端直接 .map）: {res}"));
    assert_eq!(
        items.len(), 6,
        "检测项数变了（前端 ITEM_META 与雷达节点按 id 取标签，增减要同步）: {items:?}"
    );
    for it in items {
        let id = it["id"].as_str().unwrap_or("");
        assert!(!id.is_empty(), "条目缺 id: {it}");
        assert!(
            matches!(it["status"].as_str(), Some("ok") | Some("warn") | Some("fail") | Some("info")),
            "{id} 的 status 不在前端 STATUS_LABEL 枚举内: {it}"
        );
        assert!(it["evidence"].is_array(), "{id} 缺 evidence 数组（前端逐条渲染）: {it}");
    }
    let s = &res["data"]["summary"];
    assert_eq!(s["total"].as_u64(), Some(items.len() as u64), "summary.total 与 items 数不符: {s}");
}

/// netcheck:collect 形状（`success` 为布尔）。
/// 成本：真实网络探测，依赖外网可达性（离线环境会失败，故不与快速组同跑）。
#[test]
#[ignore = "真实网络探测（外网依赖），发布前门禁跑"]
fn netcheck_collect_shape() {
    let _data = probe_guard();
    let w = main_window();
    let res = invoke(&w, "netcheck_collect", json!({}));
    assert!(res["success"].is_boolean(), "success 必须是布尔: {res}");
    // X1-L02（v7.2 C08）：原实现只断「success 是布尔」⇒ 检测整条失败
    // （success:false、压根没有 items）也绿；同文件兄弟 runtimes_collect_shape
    // （:208-234）已按 v5 P2 补齐渲染层口径，这里是唯一没跟上的——一文件内双标。
    // 按 §4.1 纪律③「形状断言对渲染层消费口径写」对齐：netcheck.js:180 对
    // `resp.data.items` 直接取用（非数组 ⇒ 整页 setAll('pending') + 报错），
    // :189-192 按 id 索引并给 status 缺省 'unknown'，:199-201 只认 fail/warn。
    assert!(res["success"].as_bool().unwrap_or(false), "本机网络检测整条失败: {res}");
    let items = res["data"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("data.items 必须是数组（前端 :180 直接取用）: {res}"));
    for it in items {
        let id = it["id"].as_str().unwrap_or("");
        assert!(!id.is_empty(), "条目缺 id（前端按 id 建索引）: {it}");
        assert!(
            matches!(
                it["status"].as_str(),
                Some("ok") | Some("warn") | Some("fail") | Some("info") | Some("unknown")
            ),
            "{id} 的 status 不在前端消费枚举内（:192 兜底 unknown）: {it}"
        );
    }
}

// ==================== 子窗口来源校验档位（审查 M1~M3 回归网） ====================
//
// 为什么单列一组：本文件此前**每条用例都建 label="main" 的窗口**，于是「子窗专属命令被
// `guard::MAIN` 拒杀」这类缺陷在几十条绿灯里完全隐形——外设窗的 apply/restore、
// 预览窗的 delete-file 全部 100% 不可用却测不出来（文件头的「已知不覆盖：子窗口」即此）。
// 这些用例只打快速组，不建真实窗口、不跑 PowerShell。
// helper（window_with_label / invoke_text / assert_guard_passed）见 tests/common/mod.rs。

/// 外设优化改应用内弹窗（2026-10-07）后的档位：**主窗**可调 `peripheral_apply`，
/// 旧子窗 label `peripheral` 调则被来源校验拒杀（防残留/被注入的窗口写 HKLM）。
/// 传空 options → 两组都归一为 -1 → 命令在写注册表之前就返回「没有需要应用的设置」，
/// 因此本用例在任何权限等级下都不会改动系统。
#[test]
fn peripheral_apply_is_main_only() {
    let w = main_window();
    let text = invoke_text(&w, "peripheral_apply", json!({ "options": {} }));
    assert_guard_passed(
        &text,
        "peripheral_apply 应允许主窗调用",
        &["needAdmin", "没有需要应用"],
    );

    let sub = window_with_label("peripheral");
    let text = invoke_text(&sub, "peripheral_apply", json!({ "options": {} }));
    assert!(
        text.contains("IPC 来源校验失败"),
        "外设优化已退役子窗档，peripheral label 调 peripheral_apply 必须被拒，回执 {text}"
    );
}

/// 提权仍是主窗专属红线（AGENTS.md §3）：子窗不得触发放开。
#[test]
fn subwindow_cannot_request_elevation() {
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "elevate_request", json!({}));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调 elevate_request 必须被拒（红线：提权只认主窗），回执 {text}"
        );
    }
}

/// 审查 v2-H2：顽固软件治理的两条命令此前挂 `guard_readonly`（放行全部五个应用窗口），
/// 而 `tauri-api.js` 在所有窗口加载 —— 子窗一旦被注入就能直接结束系统进程 / 改服务启动类型，
/// 且后端不校验任何前端确认值（stubborn_kill 前端原本连确认都没有）。档位必须是主窗专属。
#[test]
fn subwindow_cannot_call_stubborn_commands() {
    for label in sub_windows() {
        for cmd in ["memory_stubborn_kill", "memory_stubborn_block"] {
            let w = window_with_label(label);
            let text = invoke_text(&w, cmd, json!({}));
            assert!(
                text.contains("IPC 来源校验失败"),
                "{label} 窗调 {cmd} 必须被拒（v2-H2：主窗专属高危通道），回执 {text}"
            );
        }
    }
}

/// 主窗调用不得被档位拒杀（防「升档升过头」把功能锁死）：
/// 非管理员时应在档位之后落到 needAdmin，而不是来源校验失败。
///
/// X1-K01（v7.2 C08）：原实现在提权态下 `eprintln! + return`——**0 断言计 passed**，
/// 主 agent 报的 686 passed 里这条从来没断过任何东西（本机恒提权态 ⇒ 恒空跑）。
/// 修法 = 「任何权限态都有断言对象」：
/// - 非管理员腿（原样）：正向调用 + needAdmin/结果回执断言；
/// - 提权态：正向调用会**真实**结束进程/改服务启动类型/删计划任务，不执行；
///   改跑同族反向腿——档位层判定（`guard` 先于命令体）在任何权限态下都安全，
///   且可判红（档位放错即红）。这样两种环境各有一条能红的断言，
///   「静默跳过计 passed」不再可能。
#[test]
fn main_window_reaches_stubborn_commands() {
    let admin = trim_tauri_lib::engine::sysinfo::is_admin();
    if admin {
        eprintln!(
            "⚠ main_window_reaches_stubborn_commands：提权态，正向腿不执行（真实系统变更），改跑反向腿"
        );
    }
    for cmd in ["memory_stubborn_kill", "memory_stubborn_block"] {
        if !admin {
            let w = main_window();
            let text = invoke_text(&w, cmd, json!({}));
            assert!(
                !text.contains("IPC 来源校验失败"),
                "主窗调 {cmd} 不得被档位拒杀，回执 {text}"
            );
            assert!(
                text.contains("needAdmin") || text.contains("killed") || text.contains("failedCount"),
                "主窗调 {cmd} 应越过档位进入命令体（needAdmin 或结果回执），回执 {text}"
            );
        }
        // 两态都跑的反向腿：子窗必须在档位处被拒（v2-H2：主窗专属高危通道）。
        // 破坏自证：把任一命令的 guard(MAIN) 放回 guard_readonly ⇒ 本腿红。
        for label in sub_windows() {
            let sub = window_with_label(label);
            let text = invoke_text(&sub, cmd, json!({}));
            assert!(
                text.contains("IPC 来源校验失败"),
                "{label} 窗调 {cmd} 必须被拒（v2-H2：主窗专属高危通道），回执 {text}"
            );
        }
    }
}

/// 图片预览退役（改主窗内嵌 LiteBox）后 fileclean_delete_file 收紧为主窗档：
/// 任何子窗调用都必须在来源校验处被拒（原来「preview 子窗可达、由 in_scope 收口」
/// 的窄口径随预览窗一起退役）。
#[test]
fn subwindow_cannot_delete_fileclean_image() {
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "fileclean_delete_file", json!({ "filePath": "C:\\nope\\a.jpg" }));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调 fileclean_delete_file 必须被拒（主窗档），回执 {text}"
        );
    }
}

/// G-4 修订（2026-10-07）：回收站行「明细」= 打开系统回收站（主窗档）。
/// 子窗调用必须在来源校验处被拒——否则被注入的子窗能直接弹系统回收站窗口。
/// 主窗正向不在快速组覆盖：它**真的会打开系统窗口**，留真机目检（同 peripheral_apply
/// 用空参数早退的招数在无参数命令上不存在）。
#[test]
fn subwindow_cannot_open_recycle_bin() {
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "cleanup_open_recycle_bin", json!({}));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调 cleanup_open_recycle_bin 必须被拒（主窗档），回执 {text}"
        );
    }
}