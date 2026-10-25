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
//! use common::{main_window, invoke, ipc_fire_no_assert};
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
//! C08（v7.2 X1-M02）口径订正：「共用 generate_handler!」只保证**漏注册会 panic**，
//! 不保证**被调用**——两个是不变量强度不同的事实，此前这条注释把前者写成了后者。
//! 「哪些命令在 tests/ 里有调用方」以现算为准（工具：`tools/check-tests-helper-parity.mjs`
//! 的调用面清单段，数字不写进注释，防止下次漂移又骗人）。
//!
//! C08（v7.2 R6b-M01🔴）数据根隔离：每个测试进程首次建窗前注入
//! `TRIM_TEST_DATA_ROOT`（按测试二进制名分根），`paths::app_data_dir()` 据此
//! 把全部数据目录写侧重定向到 `target/test-data-root/<bin>`——测试夹具不再
//! 写穿真实 `%APPDATA%\com.xiaoxu.trim`。普通 release 进程没有这个变量，
//! 生产行为不变（机制全貌见 `paths::lib_test_data_root` 的文档）。
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
///
/// C08（v7.2 R6b-M01🔴）：建窗前先确保测试数据根已注入（进程内只做一次）。
/// 顺序即语义——必须在任何可能触达 `paths::app_data_dir()` 的调用之前，
/// 否则 DATA_DIR 的 OnceLock 会把真实根先定死，后面再设变量就无效了。
pub fn window_with_label(label: &str) -> WebviewWindow<MockRuntime> {
    ensure_test_data_root();
    let app = trim_tauri_lib::build_app(mock_builder())
        .build(mock_context(noop_assets()))
        .expect("测试 App 构建失败");
    WebviewWindowBuilder::new(&app, label, WebviewUrl::default())
        .build()
        .unwrap_or_else(|e| panic!("测试窗口 {label} 创建失败: {e}"))
}

/// C08（v7.2 R6b-M01🔴）：把本测试进程的数据根重定向到 `target/test-data-root/<bin>`。
///
/// 两个设计点：
/// - **按测试二进制分根**（`current_exe` 的 stem，剥掉 cargo 追加的 `-<hash>`）：
///   `ipc_smoke` / `module_smoke` / `safestorage_compat` 是各自独立的进程，
///   共用一个根会在并行跑时互踩（都写 `optimization-state.json`）。
/// - **进程内首次调用即清根**：上一次 cargo test 的残留会让「初始状态」类断言
///   假红/假绿（判红实验跑过之后里面会留残留，optimization_state 夹具踩过两次）。
///
/// 环境变量名与 `paths::app_data_dir()` 的读取侧互为契约：改一侧必须同步另一侧
/// （`tools/check-fail-closed.mjs` 有 D 段钉注入，本变量名由其对拍兜底）。
///
/// **可见性必须是 `pub`**：只有 `main_window`/`window_with_label` 会调它，而
/// 直接调引擎函数的真机 `#[ignore]` 探针（启动项台账、pref 写入那一族）不建窗——
/// 那样数据根隔离就变成「同一进程里恰好有用例先建过窗」的竞态结果，
/// 单条 `--ignored` 跑时 `disabled.json` 会落到用户真实数据目录。探针要自己点名隔离。
///
/// 返回隔离根（P1-4：`probe_guard` 要拿它自证）。返回值的既有调用方全部忽略它，
/// 这个 widening 不破坏任何调用点。
pub fn ensure_test_data_root() -> &'static std::path::PathBuf {
    static ONCE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let stem = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_string()))
            // cargo 的测试二进制名 = `<name>-<hash>`（如 `ipc_smoke-4a3f2b1c`），
            // 剥掉后缀让根目录名跨构建稳定，否则每次构建都换新根、旧的无限堆积。
            // 本仓三个测试文件名均不含连字符，取首段无歧义。
            .map(|s| s.split('-').next().unwrap_or("shared").to_string())
            .unwrap_or_else(|| "shared".to_string());
        let root = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            // 逐段 join，不写 "target/test-data-root"：正斜杠会原样留在路径字符串里，
            // cmd 内建命令（`mklink /J`）把 `/test-data-root` 当开关解析 ⇒ junction 夹具
            // 静默退化成 SKIP。与 `engine::paths::lib_test_data_root` 同一条口径。
            .join("target")
            .join("test-data-root")
            .join(stem);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("测试数据根可创建");
        // edition 2021：set_var 尚非 unsafe。进程内并行用例写入同一个值，
        // 与 DATA_DIR 的 OnceLock 首次 init 竞态无害（值相同，谁先设都一样）。
        std::env::set_var("TRIM_TEST_DATA_ROOT", &root);
        root
    })
}

/// P1-4（X1-K01）：**真机 `#[ignore]` 探针的统一首语句**。
///
/// 与 `ensure_test_data_root()` 的差别不是「多做了一件事」，而是**做这件事的姿势能被门禁看见**：
/// 探针原先要么首句就是 `main_window()`（定根藏在 helper 里），要么首句直接调
/// `trim_tauri_lib::…`。后者在并行跑时把进程级 `DATA_DIR` 的 `OnceLock` 定死到**真实**
/// `%APPDATA%`，同批其它探针随后就写进用户数据目录——单条 `--ignored` 跑时还一切正常，
/// 全量跑才出问题，正是最难复现的那类。
///
/// 返回值刻意**要求持有**（`#[must_use]`）：`probe_guard();` 这种丢弃写法会出警告，
/// 于是「首语句确实是定根」这件事既有语义（拿到根路径可自证）也有形式（不能空转过去）。
/// 幂等性由 `ensure_test_data_root` 的 `OnceLock` 保证，同一条测试里重复调用无害。
#[must_use = "探针必须自己声明隔离根（helper 里替它定根，门禁看不见这条探针有没有定过）"]
pub fn probe_guard() -> TestDataGuard {
    let g = ensure_test_data_root();
    TestDataGuard { root: g.clone() }
}

/// [`probe_guard`] 的持有物：测试数据根的**实际落点**。
///
/// 探针可以直接拿它自证「我写的文件确实落在 target 下而不是 %APPDATA% 下」——
/// 这是 C08 那次事故（夹具把 `optimization-state.json` 的 `prefs.recent` 覆盖成假条目）
/// 唯一可靠的现场检查。
pub struct TestDataGuard {
    pub root: std::path::PathBuf,
}

impl TestDataGuard {
    /// 断言这个根在 `target` 下而不是用户目录（探针写盘前的一眼自检）。
    pub fn assert_isolated(&self) {
        let s = self.root.to_string_lossy().replace('\\', "/");
        assert!(s.contains("test-data-root"), "测试数据根不在 target/test-data-root 下: {s}");
        assert!(!s.to_uppercase().contains(r"APPDATA"), "测试数据根指向用户目录: {s}");
    }
}

/// C08（v7.2 X1-M05）：清空全部快照槽（测试底座隔离出口）。
///
/// 槽是进程级 static，并行用例共用同一 label 槽——helper 只给出口，
/// **并发语义由调用方声明**：快照类断言（依赖「某窗最近一次扫描」的用例）
/// 不得对同一 label 并发跑；确实要并行的域先确认各自的 `domain_key` 不同。
pub fn reset_snapshots() {
    trim_tauri_lib::engine::snapshot::clear_all();
}

/// C08（v7.2 X1-M04）：**缺样本的统一出口**——打印跳过标记、记入进程台账，
/// 返回 `true`（调用方据此 `return`：本条不判红，也不冒充通过）。
///
/// 修的是同一份文件里两个相反方向的病态：
/// - 真机组（`--ignored`）：本机没有样本时 `assert!(!x.is_empty())` 直接判红，
///   把「这台机器没有装机清单」记成代码缺陷——发布前门禁被环境噪声堵住；
/// - 快速组：缺文件时 `Err(_) => {}` 静默只剩形状断言，用例自述的回归目的
///   （如条数对拍）根本没跑，却与跑全了的一样计 ok（§4.1 定义的碰巧绿）。
///
/// 台账（进程级 Vec）让「本轮哪些判据无对象」可点名；`eprintln!` 带
/// `⚠ [skip-sample]` 前缀，发布前门禁按仓库约定 `--nocapture` 跑即可见。
pub fn skip_and_record(what: &str) -> bool {
    static SKIPPED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    eprintln!("⚠ [skip-sample] {what}");
    if let Ok(mut v) = SKIPPED.lock() {
        v.push(what.to_string());
    }
    true
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

/// 经真实 IPC 调用链发一条命令（**不取回执**——只用于「别被拒杀」的档位场景）。
///
/// X1-L01（v7.2 C08）：本 helper **不构成断言**——回执被整体丢弃，
/// 「命令跑没跑、成没成」一概不知。原名叫 `ipc`，与同文件的 `invoke` /
/// `invoke_text` 摆在一起时，读起来像第三条取证通道，`AGENTS.md` §4.2 的
/// 单一真源清单也曾据此把它当断言件引用。改名 `ipc_fire_no_assert` 让
/// 「不开火验证」写在名字上：调用它之后必须另配 `invoke_text` +
/// `assert_guard_passed`（或明确的负例断言），否则该场景等于没测。
///
/// 现算全仓 0 引用（保留是为档位场景的「只求不拒杀」形态留件，不是死代码——
/// 一旦出现调用方而没配断言，这条注释就是它的对照判据）。
pub fn ipc_fire_no_assert(window: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) {
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

/// 来源校验拒杀回执的文案标记——**唯一真源**（生产侧文案见 `engine::guard::guard`）。
///
/// 为什么收成常量：拒侧此前在每条用例里手写同一串，与「helper 单一真源」口径不一致；
/// `guard()` 改文案时散点会齐刷刷判红，而「改文案」本该只红在一处。
pub const GUARD_REJECT_MARK: &str = "IPC 来源校验失败";

/// 断言「命令确实越过了档位、跑进后面的逻辑」，而不只是「没被来源校验拒杀」。
/// 审查 v2-M16② 教训：只断「不含 IPC 来源校验失败」时，命令整条消失也是绿的，
/// 档位回归网会被无声架空。必须由调用方点名正向特征（期望回执含其一）。
pub fn assert_guard_passed(text: &str, ctx: &str, reached: &[&str]) {
    assert!(
        !text.contains(GUARD_REJECT_MARK),
        "{ctx}: 被来源校验拒杀，回执 {text}"
    );
    assert!(
        reached.iter().any(|k| text.contains(k)),
        "{ctx}: 拿不到任何「已越过档位」的正向回执（期望含其一：{reached:?}），回执 {text}"
    );
}

/// `assert_guard_passed` 的成对侧：断言这次调用**就是被来源校验拒杀**的。
///
/// 拒侧此前没有 helper，各用例手写 `text.contains("…")` 加一条临时消息；换个窗口 label
/// 或换条命令时，判红消息有没有点名「谁被拒」全靠写用例的人当场想到。这里把
/// 「命中拒杀串」与「点名是哪次调用」钉成一个动作，判定强度与原来逐字等价——
/// 仍是「回执含拒杀标记」，不新增也不减少条件。
pub fn assert_guard_rejected(text: &str, ctx: &str) {
    assert!(
        text.contains(GUARD_REJECT_MARK),
        "{ctx}: 期望被来源校验拒杀（回执应含「{GUARD_REJECT_MARK}」），实得 {text}"
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
