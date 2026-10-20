//! 模块轻量验证模板（MockRuntime 底座消费示例）。
//!
//! 定位：`ipc_smoke.rs` 是既有回归网（改动需评审）；本文件是**给 agent/新模块用的
//! 轻量验证落点**——验证某个模块的命令链路时，复制一个用例改命令名与断言即可，
//! 不必动回归网文件。底座 helper 单一真源在 `tests/common/mod.rs`。
//!
//! 用例编写的三条纪律（沿用 ipc_smoke 与 AGENTS §3 的教训）：
//! 1. 档位断言必须点名正向特征（`assert_guard_passed` 的 `reached`），
//!    只断「不含来源校验失败」会被「命令整条消失」假绿穿透（v2-M16②）。
//! 2. 快速组只用**零副作用**命令（纯读、负例拦截）；会触盘/外呼/改系统的一律
//!    `#[ignore]` 进发布前门禁组。
//! 3. 形状断言对着渲染层消费口径写（前端直接 `.map` 的字段必须断类型），
//!    防的是后端形状漂移让页面静默崩。

mod common;

use common::{invoke, invoke_text, main_window, skip_and_record, sub_windows, window_with_label};
use serde_json::json;
use trim_tauri_lib::engine::guard::APP_WINDOWS;

// ==================== 底座自身的元断言 ====================

/// `sub_windows()` 必须由 `guard::APP_WINDOWS` 派生且剔除主窗——
/// 防的是：派生逻辑被改成硬编码清单后，新增子窗时档位回归网漏测新 label。
#[test]
fn sub_windows_derives_from_guard_list() {
    let subs = sub_windows();
    assert_eq!(
        subs.len(),
        APP_WINDOWS.len() - 1,
        "子窗数应为 APP_WINDOWS 减主窗: {subs:?} vs {APP_WINDOWS:?}"
    );
    assert!(!subs.contains(&"main"), "sub_windows 不得含主窗: {subs:?}");
    for l in &subs {
        assert!(APP_WINDOWS.contains(l), "{l} 不在 APP_WINDOWS: {subs:?}");
    }
}

/// X1-K02（v4-K10，2026-10-09）：清单塌缩的元断言。
///
/// 上面那条老元断言在清单塌成 `["main"]` 时全部仍成立（`0 == 1-1`、空集不含 main、
/// 循环 0 次），于是依赖 `sub_windows()` 的档位用例 100% 空转而测试全绿。这里加两条硬钉：
/// ① 双方长度下界（按现算值取粗下界：APP_WINDOWS 4 含主窗 / 子窗 3；2026-10-13 preview
///    子窗随图片预览改主窗内嵌 LiteBox 退役，5/4 → 4/3；新增子窗自动满足，塌缩即红）；
///    ② `sub_windows()` 与 `capabilities/subwindows.json` 的 windows 数组
///    逐条相等 —— 这是 AGENTS §2「新增子窗 label 四处同步」里前两处的机检（漏同步的症状：
///    窗口建得出来、每次 IPC 都判越权）。
#[test]
fn sub_windows_matches_capabilities_manifest() {
    let subs = sub_windows();
    assert!(APP_WINDOWS.len() >= 4, "APP_WINDOWS 塌缩（现算 4 含主窗）: {APP_WINDOWS:?}");
    assert!(subs.len() >= 3, "sub_windows() 塌缩（现算 3）: {subs:?}");

    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities/subwindows.json");
    let text = std::fs::read_to_string(&p).expect("读得到 capabilities/subwindows.json");
    let v: serde_json::Value = serde_json::from_str(&text).expect("subwindows.json 是合法 JSON");
    let mut declared: Vec<String> = v["windows"]
        .as_array()
        .expect("subwindows.json 缺 windows 数组（四处同步之一）")
        .iter()
        .map(|x| x.as_str().expect("windows 元素必须是字符串").to_string())
        .collect();
    let mut actual: Vec<String> = subs.iter().map(|s| s.to_string()).collect();
    declared.sort();
    actual.sort();
    assert_eq!(
        actual, declared,
        "sub_windows() ⇄ capabilities/subwindows.json 的 windows 必须逐条相等（顺序不计）"
    );
}

/// 未知 label 的窗口不得调过 guard_readonly 档（防「白名单靠猜」）：
/// 子窗清单外注入的窗口（模拟被注入页）调只读档命令必须被拒杀。
#[test]
fn unknown_label_window_is_rejected() {
    let w = window_with_label("__trim_injected__");
    let text = invoke_text(&w, "settings_load", json!({}));
    assert!(
        text.contains("IPC 来源校验失败"),
        "未知 label 调 settings_load 必须被拒，回执 {text}"
    );
}

// ==================== 各模块零副作用读命令形状 ====================

/// app:get-info 形状：version 非空字符串、runtime 恒 "tauri"、
/// electron/node/chrome 显式 null（渲染层按 null 显示 N/A，缺字段会渲染成 undefined）。
#[test]
fn app_get_info_shape() {
    let w = main_window();
    let res = invoke(&w, "app_get_info", json!({}));
    assert!(res["version"].is_string(), "version 必须是字符串: {res}");
    assert_eq!(res["runtime"], json!("tauri"), "runtime 应为 tauri: {res}");
    for k in ["electron", "node", "chrome"] {
        assert!(res[k].is_null(), "{k} 应显式为 null: {res}");
    }
}

/// intro:load 形状：`data` 必须是对象（简介库整体透传，前端按键索引；
/// 塌成 null 会让悬浮简介全部静默消失——与 cleanup_rules 塌空同型的坑）。
#[test]
fn intro_load_shape() {
    let w = main_window();
    let res = invoke(&w, "intro_load", json!({}));
    assert_eq!(res["success"], json!(true), "intro:load 应成功: {res}");
    assert!(res["data"].is_object(), "data 必须是对象: {res}");
}

/// paths:load 形状：`data` 必须是对象。
/// 防的是：配置文件损坏时返回 null，路径绑定页的 Object.entries 直接抛。
#[test]
fn paths_load_shape() {
    let w = main_window();
    let res = invoke(&w, "paths_load", json!({}));
    assert_eq!(res["success"], json!(true), "paths:load 应成功: {res}");
    assert!(res["data"].is_object(), "data 必须是对象: {res}");
}

/// paths:save 负例：key 白名单外的写入必须在落盘前被拒。
/// 防的是：渲染层被注入后借路径通道往配置里塞任意键（配置面越权）。
///
/// X1-M03（v7.2 C08）两点补强：
/// ① 拒因点名——此前只断 `success:false`，白名单闸被摘掉时 `__trim_smoke_key__`
///    会经 `atomic_write_json` 落进用户配置（落盘成功 ⇒ success:true 会红，但
///    「闸没了、写入又因别的原因失败」同样只回 success:false ⇒ 冒充绿灯）。
///    needle 取自 paths.rs 白名单分支的「路径配置无效」。
/// ② 落点说明——本命令读写的 `paths.json` 在 `paths::paths_config_file()` 下，
///    C08 数据根隔离后已重定向到 `target/test-data-root/<bin>`，不再写穿用户配置。
#[test]
fn paths_save_rejects_unknown_key() {
    let w = main_window();
    let res = invoke(
        &w,
        "paths_save",
        json!({ "key": "__trim_smoke_key__", "value": "C:\\x" }),
    );
    assert_eq!(res["success"], json!(false), "白名单外 key 必须被拒: {res}");
    assert!(
        common::message_of(&res).contains("路径配置无效"),
        "拒因必须点名白名单闸（同族对照 settings_set_pref 点名「未知的偏好键」）: {res}"
    );
}

/// 子窗档位通用式：guard_readonly 档命令从**每个**子窗 label 都应能越过档位
/// （以 settings_load 为载体；真数据断言在各模块自己的用例里）。
/// 防的是：M1~M3 那类「子窗专属通道被按 MAIN 校验锁死」的镜像缺陷——
/// 只读档降成主窗专属会让子窗功能 100% 不可用。
#[test]
fn readonly_channel_passes_guard_from_every_subwindow() {
    let mut reached: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "settings_load", json!({}));
        assert!(
            !text.contains("IPC 来源校验失败"),
            "{label} 窗调 guard_readonly 档命令不得被拒杀，回执 {text}"
        );
        // 正向特征：settings:load 返回体是 JSON 且含 success 字段
        assert!(
            text.contains("success"),
            "{label} 窗应越过档位进入命令体（回执含 success），回执 {text}"
        );
        reached.push(label);
    }
    assert_eq!(reached, sub_windows(), "每个子窗 label 都必须被点名走过（清单塌缩时这条红）");
}

// ==================== P2-13：UI 偏好键后端真源（get-prefs / set-pref） ====================

/// 形状断言：get-prefs 必须把**四个白名单键**全部带回（值为 null 也算在场）——
/// 缺键会让渲染层把「未设置」读成 undefined 再塌成默认值，三态语义就没了。
/// （只读命令，读的是真实 settings.json，与 settings_load 同列的零副作用读。）
#[test]
fn settings_get_prefs_shape_lists_all_whitelist_keys() {
    let w = main_window();
    let res = invoke(&w, "settings_get_prefs", json!({}));
    assert_eq!(res["success"], json!(true), "get-prefs 应成功: {res}");
    let data = res["data"].as_object().expect("data 必须是对象");
    let mut keys: Vec<&str> = data.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
        keys,
        ["liquidMotion", "mouseTrail", "residueBackupPack", "startupDefend"],
        "白名单四键必须逐个在场（值为 null 也算在场）: {res}"
    );
}

/// 档位正向断言（§4.2 纪律①）：四个子窗 label 都能调 get-prefs（残留副窗要读备份开关、
/// 模型/进程副窗的玻璃引擎要读档位），`reached` 逐窗点名——只断「不含校验失败」
/// 会被子窗清单塌缩骗过。
#[test]
fn settings_get_prefs_reaches_every_subwindow() {
    let mut reached: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "settings_get_prefs", json!({}));
        assert!(
            !text.contains("IPC 来源校验失败"),
            "{label} 窗调 get-prefs 不得被拒杀，回执 {text}"
        );
        assert!(text.contains("success"), "{label} 窗应越过档位进入命令体，回执 {text}");
        reached.push(label);
    }
    assert_eq!(reached, sub_windows(), "每个子窗 label 都必须被点名走过（清单塌缩时这条红）");
}

/// 负例：白名单外的键必须在**落盘前**被拒（防渲染层被注入后借偏好通道往 settings.json
/// 塞任意键）。拒在写之前 ⇒ 零副作用，可进快速组。
#[test]
fn settings_set_pref_rejects_unknown_key() {
    let w = main_window();
    let res = invoke(&w, "settings_set_pref", json!({ "key": "__trim_smoke_key__", "value": 1 }));
    assert_eq!(res["success"], json!(false), "白名单外 key 必须被拒: {res}");
    let msg = res["message"].as_str().unwrap_or("");
    assert!(msg.contains("未知的偏好键"), "拒绝理由要点名白名单: {res}");
}

// ==================== 卸载残留链三道闸（M1 安全收口 2026-09-28） ====================
//
// 覆盖对象是**命令边界**而不是判定函数本身（判定函数的正反例在 lib 单测里由
// `tools/fixtures/residue-contract.json` 驱动）。这些用例各自钉住一条顺序/形状，
// 都是零副作用（纯读或在任何删除动作之前整批拒绝）：
// - 残留扫描与残留执行是窄窗口集（`guard::RESIDUE_WINDOWS`）档，其余窗口与主窗必须被拒杀；
// - 执行侧的快照闸必须**先于**删除：受保护注册表容器在无快照时也要被整批拒绝，
//   这条防的是「把快照闸挪到删除之后」那类改动；
// - 扫描返回形状是渲染层直接 `.map` 的 `data.findings`，塌成 null 会让残留面板整片崩。

const GHOST_APP_ID: &str = r"HKLM|SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TrimNoSuch-9f3a";

// ==================== 残留链窄窗口集的统一断言 ====================
//
// 面板整块搬进 `residue` 副窗后，残留链命令的档位从 `guard::MAIN` 换成
// `guard::RESIDUE_WINDOWS`（= 只有 "residue"）。断言形状随之翻转，但**判据要点名「做到了什么」**
// （AGENTS §4.1 纪律①）：
// - 允许集里的窗口必须越过档位，并且必须读得到命令体自己的早退特征 `needle`
//   —— 只断「不含拒杀」会被「命令整条消失」假绿穿透（v2-M16② 的前车）；
// - 允许集外的窗口（含主窗）**全部**必须被拒杀。
// - `reached` 集合显式断言「越过的窗口恰好等于允许集」，不是「至少一个」。
//
// 允许集是**参数**而不是写死的 `residue`：2026-10-13 裁定把 `uninstall_pending_add`
// 的入口放宽到 `guard::PENDING_DELETE_WINDOWS`（= 主窗失败引导 + 残留副窗两个消费方），
// 当时这条断言还按「residue 独占」写，于是提交里就留了一条恒红用例。2026-10-18（v6-K13）
// list/revoke 同集放宽（待删清单对主窗可见可撤回）。档位以「谁真的需要调它」
// 为准（AGENTS §3），测试必须跟着允许集走，而不是反过来。
const RESIDUE_LABEL: &str = "residue";

fn assert_window_tier(cmd: &str, args: serde_json::Value, needle: &str, allowed: &[&str]) {
    let mut reached: Vec<&str> = Vec::new();
    for label in trim_tauri_lib::engine::guard::APP_WINDOWS {
        let w = if *label == "main" { main_window() } else { window_with_label(label) };
        let text = invoke_text(&w, cmd, args.clone());
        if allowed.contains(label) {
            assert!(
                !text.contains("IPC 来源校验失败"),
                "{label} 窗调 {cmd} 不该被档位拒杀，回执 {text}"
            );
            assert!(
                text.contains(needle),
                "{label} 窗应越过档位进入命令体（期望特征 {needle}），回执 {text}"
            );
            reached.push(label);
        } else {
            assert!(
                text.contains("IPC 来源校验失败"),
                "{label} 窗调 {cmd} 必须被来源校验拒杀，回执 {text}"
            );
        }
    }
    assert_eq!(
        reached,
        allowed.to_vec(),
        "越过档位的窗口必须恰好等于允许集 {allowed:?}（实到 {reached:?}）"
    );
}

/// 残留链命令的「只有 residue 能调」写法（`RESIDUE_WINDOWS` 档）。
fn assert_residue_window_only(cmd: &str, args: serde_json::Value, needle: &str) {
    assert_window_tier(cmd, args, needle, &[RESIDUE_LABEL]);
}

#[test]
fn residue_scan_is_residue_window_only() {
    // 正向特征取「缺 | 分隔」的早退文案：它在档位之后、任何注册表读取之前
    assert_residue_window_only(
        "uninstall_residue_scan",
        json!({ "appId": "no-separator" }),
        "app_id 格式错误",
    );
}

/// 合法形状但不存在的卸载键 → 空集（不是报错），且 `findings` 必须是数组。
/// 这条同时是 A1 的反向保险：硬否决把候选丢掉之后，命令仍必须回一个合法空集，
/// 不许变成 `null` 或整条失败。调用方 = residue 副窗（v0.7.0）。
#[test]
fn residue_scan_unknown_key_returns_empty_findings_array() {
    let w = window_with_label(RESIDUE_LABEL);
    let res = invoke(&w, "uninstall_residue_scan", json!({ "appId": GHOST_APP_ID }));
    assert_eq!(res["success"], json!(true), "不存在的卸载键应回空集而非报错: {res}");
    let findings = res["data"]["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("data.findings 必须是数组: {res}"));
    assert!(findings.is_empty(), "不存在的键不该产出候选: {findings:?}");
}

/// 执行侧两道闸的顺序：目标先过快照闸。空快照时哪怕给的是受保护注册表容器，
/// 也必须在任何删除动作之前被整批拒绝。
///
/// 刻意只选**任何扫描都产不出**的注册表容器，不选目录：快照槽是进程级 static
/// （按 label 分槽、跨用例共享），万一将来有用例先往 residue 槽写过快照，这些目标也不
/// 可能在里面；即便快照闸被改坏，A1 硬否决是第二道 —— 本用例永远不会真的删掉东西。
#[test]
fn residue_execute_requires_snapshot_before_any_delete() {
    const HOSTILE: &str = "HKLM\\SOFTWARE";
    const HOSTILE2: &str = "HKLM\\SYSTEM";
    let args = json!({
        "appId": GHOST_APP_ID,
        "targets": [
            { "kind": "reg_key", "target": HOSTILE },
            { "kind": "reg_key", "target": HOSTILE2 }
        ]
    });
    // 档位：residue 越过并读到快照闸文案，其余窗口与主窗被拒杀
    assert_residue_window_only("uninstall_residue_execute", args.clone(), "不在本次扫描快照");
    // 形状：整批拒绝必须指向快照闸本身，而不是任何删除原语被跑过
    let w = window_with_label(RESIDUE_LABEL);
    let res = invoke(&w, "uninstall_residue_execute", args);
    assert_eq!(res["success"], json!(false), "无快照时不得执行任何删除: {res}");
    assert!(
        common::message_of(&res).contains("不在本次扫描快照"),
        "整批拒绝的文案应指向快照闸，回执 {res}"
    );
}

// ==================== 卸载执行链（M2 静默知识：档位与现读） ====================

/// `uninstall:run` 是 MAIN 档，且命令串一律后端现读注册表。
/// 主窗用「卸载键不存在」的早退作正向特征：它发生在任何卸载器被启动之前，
/// 所以本用例零副作用（不会有进程被拉起来），同时证明档位已越过。
#[test]
fn uninstall_run_is_main_only_and_passes_guard_from_main() {
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "uninstall_run", json!({ "appId": GHOST_APP_ID }));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调卸载命令必须被来源校验拒杀，回执 {text}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");
    let w = main_window();
    let res = invoke(&w, "uninstall_run", json!({ "appId": GHOST_APP_ID }));
    assert_eq!(res["success"], json!(false), "不存在的卸载键不得假装成功: {res}");
    assert!(
        common::message_of(&res).contains("卸载注册表键不存在"),
        "主窗应越过档位进入「现读注册表」这一步，回执 {res}"
    );
}

/// `uninstall:modify`（P1-D6）与 `uninstall:run` 同为 MAIN 档。
/// 主窗正向特征同口径：用「卸载键不存在」的早退证明档位已越过 —— 它发生在任何
/// ModifyPath 进程被启动之前，所以零副作用（不会有修改/修复程序被拉起来）。
#[test]
fn uninstall_modify_is_main_only_and_passes_guard_from_main() {
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "uninstall_modify", json!({ "appId": GHOST_APP_ID }));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调修改/修复命令必须被来源校验拒杀，回执 {text}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");
    let w = main_window();
    let res = invoke(&w, "uninstall_modify", json!({ "appId": GHOST_APP_ID }));
    assert_eq!(res["success"], json!(false), "不存在的卸载键不得假装成功: {res}");
    assert!(
        common::message_of(&res).contains("卸载注册表键不存在"),
        "主窗应越过档位进入「现读注册表」这一步，回执 {res}"
    );
}

/// 重启后删三条命令的档位（2026-10-13 裁定 split；2026-10-18 v6-K13 起三條同集）：
/// - `add` / `list` / `revoke` 都走 `PENDING_DELETE_WINDOWS`（= 主窗清理域失败引导
///   + 残留副窗两个消费方），主窗必须**越过**档位；models/processManager 拒杀。
///   add 用「空目标早退」做正向特征（零副作用，不写 PFRO）；list 用数据形状里的键名
///   `entries`（档位拒杀只回 {success:false,message}）；revoke 会写 PFRO ⇒ 正例只用
///   「不存在的 batchId」——命令体在写任何东西之前因 scoped 为空早退（零副作用），
///   正向特征取回执里的 `revoked`；提权态下的真机正例留给发布前 #[ignore] 组（§4.2 ②）。
/// - residue 的 scan/execute 仍只给 `residue`（见上面的 assert_residue_window_only）。
#[test]
fn pending_delete_channels_window_tier() {
    // add：主窗 + residue 两个都越过；models/processManager 拒杀
    assert_window_tier(
        "uninstall_pending_add",
        json!({ "targets": [] }),
        "没有要登记的目标",
        &["main", RESIDUE_LABEL],
    );
    // list：主窗 + residue 都越过（K13：待删清单对主窗可见）
    assert_window_tier("uninstall_pending_list", json!({}), "entries", &["main", RESIDUE_LABEL]);
    // revoke：主窗 + residue 都越过；不存在的 batchId ⇒ scoped 空 ⇒ 早退零写
    assert_window_tier(
        "uninstall_pending_revoke",
        json!({ "batchId": "no-such-batch" }),
        "revoked",
        &["main", RESIDUE_LABEL],
    );
}

/// v2-B1/B2（2026-10-01 复核批次）：pending-add 的纵深防御正例。
/// 两条路径都在**写入任何东西之前**短路：受保护/不可归一化目标在循环内第一道闸被
/// skip（`added=0` → 不写 PFRO、不写待删文档），超限在 spawn_blocking 之前整批拒绝；
/// 除只读 PFRO/文档读取外零副作用，可进快速组。v0.7.0 起调用方是 residue 副窗。
/// 向量口径（对照 protect::build_default_roots）：空串=归一化失败、裸盘符与盘符根=
/// drive_root、`System32\config` 子树与 `C:\Windows` exact=受保护清单本体。
#[test]
fn pending_add_rejects_protected_paths_and_over_limit() {
    let w = window_with_label(RESIDUE_LABEL);
    let res = invoke(
        &w,
        "uninstall_pending_add",
        json!({ "targets": ["", "C:", "C:\\", "C:\\Windows", "C:\\Windows\\System32\\config\\SAM"] }),
    );
    assert_eq!(
        res["success"], json!(true),
        "受保护路径应逐项 skip 而非整批失败: {res}"
    );
    assert_eq!(res["data"]["added"], json!(0), "受保护路径一项都不许登记: {res}");
    let rows = res["data"]["details"].as_array().expect("details 应为数组");
    assert_eq!(rows.len(), 5, "五个目标都应有逐项回执: {res}");
    for r in rows {
        assert_eq!(r["status"], json!("skip"), "受保护目标必须 skip: {r}");
        assert!(
            r["message"].as_str().unwrap_or("").contains("受保护路径"),
            "skip 原因必须写明受保护路径: {r}"
        );
    }
    // 单批上限：33 项 > PENDING_ADD_MAX_ITEMS(32)，整批失败且信息写明口径
    let over: Vec<String> = (0..33)
        .map(|i| format!("C:\\nonexistent-trim-pending-{i}.bin"))
        .collect();
    let res = invoke(&w, "uninstall_pending_add", json!({ "targets": over }));
    assert_eq!(res["success"], json!(false), "超上限必须整批失败: {res}");
    assert!(
        common::message_of(&res).contains("32"),
        "失败信息应写明上限口径 32: {res}"
    );
}

/// v6-K11：外设备份还原必须带**显式高危确认字段** `confirmedHighRisk=true`。
///
/// 拒杀顺序：窗口档位 → 确认字段 → 提权检查。确认闸在 is_admin 之前，所以负例腿
/// 在任何提权态下都零副作用（不读备份目录、不碰注册表）。缺字段/false 都必须拒——
/// 「裸调用」正是渲染层漏传或 IPC 注入的形态。
/// 破坏自证：把命令签名里的 `confirmed_high_risk` 闸删掉 ⇒ 负例腿红（裸调用落到
/// needAdmin 或真实导入，`message.contains("confirmedHighRisk")` 不再成立）。
///
/// X1-M01（v7.2 C08）补**正向腿**——此前只有负例，闸「把 true 也一并拒」的过度
/// 收紧形态整网无覆盖（负例两条对这种形态全绿）。正向腿零副作用的两态保证：
/// - 非提权态：闸之后紧跟 is_admin 检查，停在 needAdmin，不读备份、不碰注册表；
/// - 提权态：native 读「新根（C08 测试空根）+ 老根兜底」，仅当两个候选里都找不到
///   备份文件时才放行（no-backup 只读分支）；老根有真实备份则跳过正向调用——
///   那种机器上导入的是用户自己的备份、仍属真实系统变更，正向腿改由负例腿守闸。
#[test]
fn peripheral_restore_requires_explicit_high_risk_field() {
    let w = main_window();
    let bare = invoke(&w, "peripheral_restore_backup", json!({}));
    assert_eq!(bare["success"], json!(false), "缺 confirmedHighRisk 必须拒: {bare}");
    assert!(
        common::message_of(&bare).contains("confirmedHighRisk"),
        "拒因应点名字段: {bare}"
    );
    // 显式 false 同样拒（只有 === true 放行，见渲染层封装）
    let falsy = invoke(&w, "peripheral_restore_backup", json!({ "confirmedHighRisk": false }));
    assert_eq!(falsy["success"], json!(false), "false 必须拒: {falsy}");
    assert!(
        common::message_of(&falsy).contains("confirmedHighRisk"),
        "false 的拒因同样应点名字段: {falsy}"
    );

    // 正向腿：显式 true 必须越过确认闸（不再出现确认闸拒因）。
    // 破坏自证：把闸写成恒拒（如 `!= Some(false)`）⇒ 负例腿全绿而本腿红。
    let backups_present = trim_tauri_lib::engine::paths::backup_read_dirs("peripheral-backup")
        .iter()
        .any(|d| {
            std::fs::read_dir(d)
                .map(|rd| rd.flatten().any(|e| e.path().is_file()))
                .unwrap_or(false)
        });
    if !trim_tauri_lib::engine::sysinfo::is_admin() || !backups_present {
        let passed = invoke(&w, "peripheral_restore_backup", json!({ "confirmedHighRisk": true }));
        assert_eq!(
            passed["success"],
            json!(false),
            "两种安全态都不该真去还原（非提权→needAdmin；无备份→no-backup）: {passed}"
        );
        assert!(
            !common::message_of(&passed).contains("confirmedHighRisk"),
            "显式确认后不应再被确认闸拒（过度收紧形态，负例腿抓不到）: {passed}"
        );
    } else {
        eprintln!(
            "⚠ peripheral_restore 正向腿跳过：提权态且老根存在真实备份，\
             正向调用会真实导入（负例腿仍全量断言）"
        );
    }
}

/// X1-M01（v7.2 C08）：`optimizer_run` 的高危确认闸此前零回归网。
///
/// 判据结构（`preflight_reason`，apply.rs）：**is_admin 先于确认闸** ⇒ 两态各有一条
/// 能红的断言腿，不存在「某权限态静默跳过计 passed」（照 X1-K01 的两态腿模式）：
/// - 提权态：is_admin 已过，缺确认必须落在 `needConfirm: true` —— 这条腿直接守着
///   确认闸本身，闸被摘掉/改松 ⇒ 红；
/// - 非提权态：必须落在 `needAdmin: true` —— 守着「is_admin 先行」的判据顺序，
///   顺序若被改成确认闸先行，本态会看到 needConfirm ⇒ 红。
/// 零副作用：两种拒绝都在执行链之前早退，不组装步骤、不落盘。
/// 高危 id **动态取**（目录里第一个 `risk=="high"`）：写死 id 会在目录退役时假红，
/// 而目录本身是 `include_str!` 进二进制的，退役即编译期事实。
#[test]
fn optimizer_run_high_risk_confirm_gate_has_two_state_legs() {
    let w = main_window();
    let list = invoke(&w, "optimizer_list", json!({}));
    let rows = list["data"]
        .as_array()
        .expect("optimizer_list 回执 data 应为数组（渲染层直接 .map）");
    let high_id = rows
        .iter()
        .find(|r| r.get("risk").and_then(|v| v.as_str()) == Some("high"))
        .and_then(|r| r.get("id").and_then(|v| v.as_str()))
        .expect("目录里应存在 risk==high 的优化项（高危确认闸的服役对象）");
    let res = invoke(
        &w,
        "optimizer_run",
        json!({ "optionId": high_id, "params": { "confirmedHighRisk": false } }),
    );
    assert_eq!(res["success"], json!(false), "高危项缺确认必须拒: {res}");
    if trim_tauri_lib::engine::sysinfo::is_admin() {
        assert_eq!(
            res["needConfirm"],
            json!(true),
            "提权态下高危缺确认应命 needConfirm（确认闸本身）: {res}"
        );
    } else {
        assert_eq!(
            res["needAdmin"],
            json!(true),
            "非提权态下 is_admin 先行，应命 needAdmin（判据顺序）: {res}"
        );
    }
}

/// X1-M01（v7.2 C08）：syspanel 三条写侧出口的 `confirmedHighRisk` 闸此前零回归网。
///
/// 与 optimizer_run 不同，这三条的确认闸是**命令体第一道**（guard 之后、任何系统
/// 调用之前）⇒ 非提权态也可达，本机恒提权态也一样可达（闸不看权限）。
/// 破坏自证：摘掉任一闸 ⇒ 对应调用落到命令体——`pagefile_apply` 还有
/// `validate_pagefile` 第二道（managed=false + entries=[] 必拒），另两条传不存在
/// 的 GUID/powercfg 必错——但两种落点的文案都不含「二次确认」⇒ 本用例红。
/// 零副作用：`confirmedHighRisk` 恒为 false，永远到不了真实删除/写入。
#[test]
fn syspanel_high_risk_confirm_gates_reject_unconfirmed() {
    let w = main_window();
    let cases: &[(&str, serde_json::Value)] = &[
        // 不存在任何真实电源方案的伪造 GUID：闸若失守，命令体按「方案不存在」拒，
        // 而不是真去删 Balanced（双防线之一）。
        (
            "syspanel_power_plan_delete",
            json!({ "guid": "00000000-0000-0000-0000-trimnosuchplan", "confirmedHighRisk": false }),
        ),
        ("syspanel_power_hide_high_performance", json!({ "confirmedHighRisk": false })),
        // managed=false + entries=[] 是「全关虚拟内存」形态：validate_pagefile 必拒
        // （双防线之二）；确认闸失守时落点也不是删除。
        (
            "syspanel_pagefile_apply",
            json!({ "managed": false, "entries": [], "confirmedHighRisk": false }),
        ),
    ];
    for (cmd, args) in cases {
        // 三条命令签名都是 Result<Value, String>：闸拒走 Err，回执不是 JSON，
        // 必须用 invoke_text 取文本（invoke 会 panic）。
        let text = invoke_text(&w, cmd, args.clone());
        assert!(
            text.contains("二次确认"),
            "{cmd} 缺 confirmedHighRisk 必须点名「二次确认」后拒: {text}"
        );
    }
}

/// M5 D1：卸载域注册表备份的列表/还原两条通道都是 MAIN 档。
///
/// 还原会经 `reg import` 写注册表，所以档位是它的第一道闸，子窗一律拒杀。
/// 主窗正向特征刻意选两条**零副作用**路径：list 只读目录，restore 用越界文件名在
/// 参数校验处就早退（进不到封条判定、更进不到 reg.exe）。list 的形状也钉住：
/// 渲染层对 `data.backups` 直接 `.map`，塌成 null 会让备份弹窗整片崩。
#[test]
fn reg_backup_channels_are_main_only() {
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let list = invoke_text(&w, "uninstall_reg_backup_list", json!({}));
        assert!(
            list.contains("IPC 来源校验失败"),
            "{label} 窗调卸载域备份列表必须被来源校验拒杀，回执 {list}"
        );
        let restore = invoke_text(
            &w,
            "uninstall_reg_backup_restore",
            json!({ "file": "..\\..\\evil.reg" }),
        );
        assert!(
            restore.contains("IPC 来源校验失败"),
            "{label} 窗调卸载域备份还原必须被拒杀，回执 {restore}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");

    let w = main_window();
    let list = invoke(&w, "uninstall_reg_backup_list", json!({}));
    assert_eq!(list["success"], json!(true), "主窗列表应越过档位进入实现: {list}");
    assert!(
        list["data"]["backups"].is_array(),
        "backups 必须是数组（渲染层直接 .map，null 会让弹窗整片崩）: {list}"
    );

    let restore = invoke(
        &w,
        "uninstall_reg_backup_restore",
        json!({ "file": "..\\..\\evil.reg" }),
    );
    assert_eq!(restore["success"], json!(false), "越界文件名必须早退: {restore}");
    assert!(
        common::message_of(&restore).contains("备份文件名非法"),
        "主窗应越过档位进入参数校验，回执 {restore}"
    );
}

/// B6 体积兜底：MAIN 档 + 入参形状闸。
///
/// `path` 的真源是注册表 `InstallLocation`，也就是**软件自己能写**的字段，所以路径形状
/// 必须在读盘前定死：非绝对 / 不存在 / 空串一律早退。正向特征点名取仓库自带的
/// `src-tauri/data`（小、只读、每次构建都在），只断「命令整条消失」打不穿的 success 与
/// 渲染层直接消费的 `sizeKb`/`partial` 两个字段类型。
#[test]
fn dir_size_channel_is_main_only_and_refuses_non_absolute() {
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "uninstall_dir_size", json!({ "path": "C:\\Windows\\Temp" }));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调体积兜底必须被拒杀，回执 {text}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");

    let w = main_window();
    // `"."` 而不是随便一个相对串：它**一定**存在，所以去掉绝对路径闸后这条必然变绿，
    // 判红才有意义（`"../../Windows"` 在本机恰好解析不到，曾经假判绿过一次）。
    for bad in ["", "   ", ".", "./data", "C:\\Trim-不存在的目录-xyz"] {
        let res = invoke(&w, "uninstall_dir_size", json!({ "path": bad }));
        assert_eq!(res["success"], json!(false), "{bad} 必须被形状闸早退: {res}");
        assert!(
            common::message_of(&res).contains("路径不可用"),
            "主窗应越过档位进入参数校验，回执 {res}"
        );
    }

    let data_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data");
    let res = invoke(
        &w,
        "uninstall_dir_size",
        json!({ "path": data_dir.to_string_lossy() }),
    );
    assert_eq!(res["success"], json!(true), "{data_dir:?} 应可估算: {res}");
    assert!(
        res["data"]["sizeKb"].is_number(),
        "sizeKb 必须是数字（渲染层直接 '≈' + fmtSizeKb）: {res}"
    );
    assert!(
        res["data"]["partial"].is_boolean(),
        "partial 必须是布尔（截断时前端要在提示里带上'实际可能更大'）: {res}"
    );
}

/// v2-M14 接线：还原通道认得**退役项**的 id。
///
/// 退役项已从优化目录移除，原先 `find_option` 判不到就被拒「未知的优化选项」，于是它们
/// 留在备份文件里的原值**连手动还原的出口都没有**。这里钉两件事：未知 id 仍然拒、退役 id
/// 不再被当成未知。
///
/// 刻意只挑一个**本机没有备份记录**的退役 id：有备份的话命令会真去写注册表，快速组不许碰。
#[test]
fn restore_reg_recognises_retired_ids_but_still_refuses_unknown() {
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "optimizer_restore_reg", json!({ "optionId": "any" }));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调优化项还原必须被拒杀，回执 {text}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");

    let w = main_window();
    let unknown = invoke(&w, "optimizer_restore_reg", json!({ "optionId": "trim-不存在的选项" }));
    assert_eq!(unknown["success"], json!(false), "未知 id 必须拒: {unknown}");
    assert!(
        common::message_of(&unknown).contains("未知的优化选项"),
        "主窗应越过档位进入参数校验，回执 {unknown}"
    );

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data");
    let retired: Vec<String> = {
        let text = std::fs::read_to_string(dir.join("retired-optimizations.json")).expect("退役清单可读");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("退役清单是合法 JSON");
        parsed["items"]
            .as_array()
            .map(|a| a.iter().filter_map(|i| i["id"].as_str().map(String::from)).collect())
            .unwrap_or_default()
    };
    assert!(retired.len() >= 10, "退役清单解析不出条目: {retired:?}");
    let backups: serde_json::Value = std::fs::read_to_string(
        trim_tauri_lib::engine::paths::app_data_dir().join("optimizer-backups.json"),
    )
    .ok()
    .and_then(|t| serde_json::from_str(&t).ok())
    .unwrap_or(json!({}));
    let id = retired
        .iter()
        .find(|id| backups.get(id.to_string()).is_none())
        .expect("挑得出一个本机无备份的退役 id");
    let res = invoke(&w, "optimizer_restore_reg", json!({ "optionId": id }));
    assert_eq!(res["success"], json!(false), "无备份记录不该报成功: {res}");
    assert!(
        !common::message_of(&res).contains("未知的优化选项"),
        "退役 id {id} 必须被还原通道认得（这条就是 v2-M14 的接线点），回执 {res}"
    );
}

// ==================== 重/外呼组（默认 ignore，发布前跑） ====================

/// A1 收紧的**放行回测**（真机、只读）：装机清单里每个桌面程序的卸载键必然存在，
/// 所以残留扫描必须照样产出「卸载注册表项仍存在」这条最高置信候选 —— 这是
/// 「结构收口把主功能误杀」最直接的探测器（`HKLM\SOFTWARE\…\Uninstall\<产品键>`
/// 属于容器下的产品叶键，按设计必须放行）。
///
/// 同时断言扫描产出的每个 `reg_key` 目标都不落在保护面内（扫描侧硬闸无漏放），
/// 以及候选形状是渲染层直接消费的字段集。
///
/// 成本：按程序逐个扫（含开始菜单/跳转列表目录读），耗时随装机清单变化，
/// 故不进快速组。跑法：`cargo test --test module_smoke -- --ignored`
///
/// X1-M04（v7.2 C08）缺样本口径：两处「本机无对象」原先是硬 assert 判红——把
/// 「这台机器没有桌面程序 / 没有注册表寻址程序」记成代码缺陷，发布前门禁被
/// 环境噪声堵住。改成 `skip_and_record` 明示跳过：本机无样本 ≠ 判据失效，
/// 但也不许静默计通过。
#[test]
#[ignore = "逐个程序残留扫描会读多目录且依赖装机清单，发布前门禁跑"]
fn residue_scan_on_real_apps_keeps_uninstall_key_candidate() {
    use serde_json::Value;
    use trim_tauri_lib::engine::protect;
    let w = main_window();
    let list = invoke(&w, "uninstall_list", json!({ "scope": "user" }));
    assert_eq!(list["success"], json!(true), "uninstall_list 应成功: {list}");
    let apps = list["data"]["apps"].as_array().cloned().unwrap_or_default();
    // 条目里的寻址键是 `id`（`HKLM|<卸载子路径>` / `APPX|<包全名>`），不是 appId
    let sample: Vec<&Value> = apps.iter().take(8).collect();
    if sample.is_empty() {
        skip_and_record("residue_scan：本机没有桌面程序可采样（A1 放行回测无对象）");
        return;
    }

    // 列表档位是 MAIN（主窗取）、残留扫描在窄窗口集内（residue 副窗取）——两窗分工不可互换
    let wr = window_with_label(RESIDUE_LABEL);
    let mut checked = 0;
    for a in sample {
        let Some(app_id) = a["id"].as_str() else { continue };
        // 只测注册表寻址的桌面程序（APPX| 前缀走另一条口径）
        if !app_id.contains('|') || app_id.starts_with("APPX|") {
            continue;
        }
        let res = invoke(&wr, "uninstall_residue_scan", json!({ "appId": app_id }));
        assert_eq!(res["success"], json!(true), "{app_id} 扫描应成功: {res}");
        let findings = res["data"]["findings"].as_array().unwrap_or_else(|| {
            panic!("{app_id} 的 data.findings 必须是数组: {res}");
        });
        checked += 1;
        let mut has_uninstall_key = false;
        for f in findings {
            for k in ["kind", "target", "reason", "confidence", "risk"] {
                assert!(f[k].is_string(), "{app_id} 候选缺字符串字段 {k}: {f}");
            }
            assert!(f["defaultChecked"].is_boolean(), "{app_id} 候选缺 defaultChecked: {f}");
            // C4：contribs 可缺（有的链只有一句结论），但一旦出现必须是「对象 + 非空 code/text」
            // 数组——渲染层直接 .map，混进字符串或 null 会让整张残留表崩。
            if let Some(cs) = f["contribs"].as_array() {
                assert!(
                    !cs.is_empty()
                        && cs.iter().all(|c| {
                            !c["code"].as_str().unwrap_or("").is_empty()
                                && !c["text"].as_str().unwrap_or("").is_empty()
                        }),
                    "{app_id} 贡献项形状不合规: {f}"
                );
            }
            if f["kind"].as_str() == Some("reg_key") {
                let t = f["target"].as_str().unwrap_or("");
                // 服务/驱动桶（v0.7.0 四类残留）的 target 天生落在 HKLM\SYSTEM 整棵禁删树内，
                // 执行链走的是服务键窄口子（八道现读判据），**不适用** protect 通用闸——
                // 对它断 protect 放行等于要求产品把服务键候选全部撤掉，与 0.7.1 设计
                // （扫出来、点执行由窄口子现读判定，本机 ACE-CORE 驱动实例坐实）直接冲突。
                // 这里断「形状命中窄口子」：形状合法 ⇒ 执行侧必然进八道判定，保护语义不缺位。
                if matches!(f["bucket"].as_str(), Some("service") | Some("driver")) {
                    assert!(
                        trim_tauri_lib::commands::uninstall::looks_like_service_key(t),
                        "服务/驱动桶候选 {t} 不是一层服务键形状，执行链不会走窄口子（{app_id}）"
                    );
                } else {
                    assert!(
                        protect::reg_target_block_reason(t).is_none(),
                        "扫描侧硬闸漏放受保护目标 {t}（{app_id}）"
                    );
                }
                if f["reason"].as_str().unwrap_or("").contains("卸载注册表项仍存在") {
                    has_uninstall_key = true;
                }
            }
        }
        assert!(
            has_uninstall_key,
            "{app_id} 在清单里就说明它的卸载键存在，扫描必须产出该候选（A1 误杀信号）"
        );
    }
    if checked == 0 {
        skip_and_record("residue_scan：样本里没有可用的注册表寻址程序（APPX 专属机器）");
        return;
    }
}

// 需要真实环境的验证（pwsh / 扫盘 / 网络 / 改系统），复制下面这个骨架进来：
//
// #[test]
// #[ignore = "<说明成本>，发布前门禁跑"]
// fn <module>_<command>_shape() {
//     let w = main_window();
//     let res = invoke(&w, "<command>", json!({}));
//     assert_eq!(res["success"], json!(true), "...: {res}");
// }
//
// 跑法：cargo test --test module_smoke -- --ignored

/// M6 图标第四源（真机 `#[ignore]`）：`shortcutPath` 是后端算好的，前端只按优先级尝试，
/// 所以这里钉三条 —— 字段形状（要么没有、要么是个真实存在的 .lnk）、至少有一行命中
/// （一台装过软件、桌面有快捷方式的机器全空 = 匹配或根目录断了）、以及它不越界
/// （只落在四个快捷方式根里，不指向任意路径）。
///
/// X1-M04（v7.2 C08）缺样本口径：两处「本机无对象」原先是硬 assert 判红
/// （无已安装程序 / 无一行匹配快捷方式）——干净克隆或精简机上跑发布前门禁会被
/// 环境噪声堵住。改成 `skip_and_record` 明示跳过。
#[test]
#[ignore = "读桌面与开始菜单，发布前门禁跑"]
fn uninstall_list_rows_carry_resolvable_shortcuts() {
    let w = main_window();
    let res = invoke(&w, "uninstall_list", json!({ "scope": "user" }));
    assert_eq!(res["success"], json!(true), "列表应成功: {res}");
    let apps = res["data"]["apps"].as_array().cloned().unwrap_or_default();
    if apps.is_empty() {
        skip_and_record("shortcuts：本机没有已安装程序可采样（第四源回归无对象）");
        return;
    }
    let mut hit = 0usize;
    for a in &apps {
        let p = match a.get("shortcutPath").and_then(|v| v.as_str()) {
            Some(p) if !p.is_empty() => p,
            _ => continue,
        };
        hit += 1;
        assert!(p.len() > 4 && p.to_lowercase().ends_with(".lnk"), "第四源必须是 .lnk: {p}");
        assert!(std::path::Path::new(p).exists(), "给出的快捷方式路径必须真实存在: {p}");
        let low = p.to_lowercase();
        assert!(
            low.contains("desktop") || low.contains("start menu"),
            "shortcutPath 只应落在桌面/开始菜单根里: {p}"
        );
    }
    println!("带 shortcutPath 的行数: {hit} / {}", apps.len());
    if hit == 0 {
        skip_and_record("shortcuts：全机没有任何一行匹配到快捷方式（索引或匹配链待查，本机无对象）");
        return;
    }
}

/// 探针清场守卫：断言失败（panic 走 unwind）也必须把注册表键与临时文件收掉，
/// 否则一次失败的发布前门禁会在用户机器上留下假备份与假档案。
struct RestoreProbeGuard {
    sub: &'static str,
    file: std::path::PathBuf,
    seal: std::path::PathBuf,
}

impl Drop for RestoreProbeGuard {
    fn drop(&mut self) {
        use trim_tauri_lib::engine::native;
        use windows::Win32::System::Registry::HKEY_CURRENT_USER;
        let _ = native::reg_key_remove(HKEY_CURRENT_USER, self.sub, true);
        let _ = std::fs::remove_file(&self.file);
        let _ = std::fs::remove_file(&self.seal);
    }
}

/// M5 D1 的真机闭环：`reg import` 到底有没有把值写回注册表。
///
/// 这条一直是缺口——之前只证到「命令边界与四道闸的判定」，从没让 reg.exe 真跑过一次。
/// 用一次性探针键 `HKCU\Software\TrimRestoreProbe`（不碰任何真实软件键）。
/// 顺带在同一条真链上钉封条闸门：写一条错摘要后再还原必须被硬拒——
/// 否则「封条」只是注释里的承诺。
///
/// C08（v7.2 R6b-M01🔴）次序纪律：`paths::app_data_dir()` 的 OnceLock **首次调用即定死**，
/// 而测试根靠 `main_window()` 注入环境变量——本用例原先先取数据根再建窗，并行竞态下
/// 可能把真实根定死，假 .reg 就此写进用户备份目录。现在建窗先行（顺序即语义），
/// 且真机组跑 `--ignored` 时同样落在 `target/test-data-root/<bin>` 下。
#[test]
#[ignore = "真跑 reg import 写注册表（一次性 HKCU 探针键），发布前门禁跑"]
fn reg_backup_restore_writes_registry_end_to_end() {
    use trim_tauri_lib::engine::{native, paths};
    use windows::Win32::System::Registry::HKEY_CURRENT_USER;
    let sub = r"Software\TrimRestoreProbe";
    let probe_val = || native::read_reg_value_text(HKEY_CURRENT_USER, sub, "probe").map(|(_, s)| s);
    // 建窗先行：注入 TRIM_TEST_DATA_ROOT，之后每次 app_data_dir() 都落测试根
    let w = main_window();
    let dir = paths::app_data_dir().join("uninstall-reg-backup");
    std::fs::create_dir_all(&dir).expect("备份目录应可建");
    let name = "1790000000001_TrimRestoreProbe.reg";
    let file = dir.join(name);
    let seal = dir.join(format!("{name}.meta.json"));
    let _guard = RestoreProbeGuard { sub, file: file.clone(), seal: seal.clone() };
    assert_eq!(probe_val(), None, "前置条件：探针键必须不存在（守卫没清干净？）");

    std::fs::write(
        &file,
        "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\TrimRestoreProbe]\r\n\"probe\"=\"restored\"\r\n",
    )
    .expect("备份应可写");

    let res = invoke(&w, "uninstall_reg_backup_restore", json!({ "file": name }));
    assert_eq!(res["success"], json!(true), "无封条（missing）的合法备份应可还原: {res}");
    assert_eq!(
        probe_val().as_deref(),
        Some("restored"),
        "reg import 必须真的把值写进注册表，不能只回一个 success"
    );

    // 封条闸门：同一份文件，补一条错摘要后再还原必须被拒
    std::fs::write(
        &seal,
        br#"{"sha256":"0000000000000000000000000000000000000000000000000000000000000000","target":"HKCU\Software\TrimRestoreProbe"}"#,
    )
    .expect("封条应可写");
    let again = invoke(&w, "uninstall_reg_backup_restore", json!({ "file": name }));
    assert_eq!(again["success"], json!(false), "封条不符必须硬拒，实测 {again}");
    assert!(
        common::message_of(&again).contains("封条"),
        "回执必须说明是封条拦下的，实测 {again}"
    );
    assert_eq!(probe_val().as_deref(), Some("restored"), "被拒的还原不得改动已有键值");
}

/// log:write 的边界行为（N3）：五个应用窗都可调（子窗没有 logger.js，直连本通道），
/// 未知 label 必须拒杀；越过后还要证明**清洗真的发生了**——非法 level 降级为 INFO、
/// 带换行的消息不能撑出第二行日志、消息前会带上窗口 label。
///
/// 正向特征刻意取"降级为 INFO"而不是"没报来源校验失败"：后者在命令整条消失时也会成立
/// （v2-M16② 的老坑）。
///
/// C08/X1-M03 落点口径：`log_write` 在测试进程**不落盘**——`log_sink_enabled()` 靠
/// 「exe 落在 target/<profile>/deps」判测试进程（`集成测试进程不写生产日志` 用例钉的
/// 就是它），`write_log` 直接返回行文本。因此本用例既不写生产日志目录、也不写测试
/// 数据根；断言的全部是返回值。C08 的 `TRIM_TEST_DATA_ROOT` 是第二层保险：
/// 万一 sink 判据失效，落点也会是测试根而非用户日志。
#[test]
fn log_write_is_readonly_tier_and_sanitizes_renderer_input() {
    let evil = "第一行\n[2099-01-01 00:00:00] [ERROR] 伪造行";
    let labels = ["main"].into_iter().chain(sub_windows().into_iter());
    for label in labels {
        let w = window_with_label(label);
        let res = invoke(&w, "log_write", json!({ "level": "CRITICAL] [x", "message": evil }));
        let line = res.as_str().unwrap_or_else(|| panic!("{label} 窗应返回日志行字符串，实测 {res}"));
        assert!(
            line.contains("[INFO]"),
            "{label} 窗应越过档位并被 level 白名单降级为 INFO，实测 {line}"
        );
        assert!(
            line.contains(&format!("[{label}]")),
            "日志行要带窗口 label 才知道是谁报的: {line}"
        );
        // 行边界：write_log 只在末尾加一个换行，消息里的换行必须已被吃掉
        assert_eq!(
            line.matches('\n').count(),
            1,
            "一条消息只能占一行（末尾那一个换行是 write_log 加的），实测 {line:?}"
        );
        assert!(
            !line.contains("\n[2099"),
            "换行没被清洗就会留下伪造的行首: {line:?}"
        );
        assert!(line.contains("2099"), "内容本身不该被吞掉，只吞行边界: {line}");
    }
    let w = window_with_label("not-a-trim-window");
    let text = invoke_text(&w, "log_write", json!({ "level": "error", "message": "x" }));
    assert!(
        text.contains("IPC 来源校验失败"),
        "未知 label 必须被来源校验拒杀，回执 {text}"
    );
}

// ==================== HiBit §H1 卸载还原包（batch-list / batch-restore）====================

/// 两个新通道的档位：子窗一律被来源校验拒杀，主窗进入实现。
/// 正向断言点名 `reached`（AGENTS §4.1 纪律①）——只断「不含校验失败」会被
/// 「命令整条没注册/直接消失」假绿穿透（v2-M16② 的前科就在这条上）。
#[test]
fn batch_pack_channels_are_main_only() {
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let list = invoke_text(&w, "uninstall_batch_list", json!({}));
        assert!(
            list.contains("IPC 来源校验失败"),
            "{label} 窗调还原包列表必须被拒杀，回执 {list}"
        );
        let restore = invoke_text(&w, "uninstall_batch_restore", json!({ "batchId": "x" }));
        assert!(
            restore.contains("IPC 来源校验失败"),
            "{label} 窗调整批还原必须被拒杀（它往磁盘写文件），回执 {restore}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");

    let w = main_window();
    let list = invoke(&w, "uninstall_batch_list", json!({}));
    assert_eq!(list["success"], json!(true), "主窗应越过档位进入实现: {list}");
    // 形状按渲染层的消费口径断：弹窗对 packs 直接 .map，totalBytes 进 formatSize
    assert!(list["data"]["packs"].is_array(), "packs 必须是数组: {list}");
    assert!(
        list["data"]["totalBytes"].is_number(),
        "totalBytes 必须是数字（缺失会让界面显示 NaN 而不是 0）: {list}"
    );
}

/// 还原是「按 manifest 里的路径往磁盘写」，`batchId` 来自渲染层，先当不可信文件名：
/// 任何分隔符/`..` 都必须被格式闸门拒掉，且不能因此碰到盘。
#[test]
fn batch_restore_refuses_hostile_batch_id() {
    let w = main_window();
    for bad in ["", r"..\..\x", "a/b", r"a\b"] {
        let r = invoke(&w, "uninstall_batch_restore", json!({ "batchId": bad }));
        assert_eq!(r["success"], json!(false), "恶意 batchId {bad:?} 必须失败: {r}");
        assert!(
            r["message"].as_str().unwrap_or("").contains("格式不合法"),
            "理由必须是格式拒杀，实得 {r}"
        );
    }
    // 形状合法但不存在：报「找不到」，不崩也不静默成功
    let miss = invoke(&w, "uninstall_batch_restore", json!({ "batchId": "2020-01-01T00-00-00-000Z" }));
    assert_eq!(miss["success"], json!(false));
    assert!(
        miss["message"].as_str().unwrap_or("").contains("找不到"),
        "理由应为找不到，实得 {miss}"
    );
}

/// 新增的 `backup` 参数是 Option——旧调用形状（只送 appId+targets）必须仍然进实现，
/// 否则前端一处没改就是整条残留清理不可用。这里用空 targets 触发**零副作用**的入参闸门。
/// v0.7.0 起调用方是 residue 副窗（主窗已没有这条链的入口）。
#[test]
fn residue_execute_still_accepts_call_without_backup_arg() {
    let w = window_with_label(RESIDUE_LABEL);
    let r = invoke(&w, "uninstall_residue_execute", json!({ "appId": "MACHINE|all", "targets": [] }));
    assert!(
        r["message"].as_str().unwrap_or("").contains("targets 为空"),
        "缺 backup 参数的旧调用应进实现并停在入参闸门，实得 {r}"
    );
}

/// N9：清理域的 `.reg` 还原链必须与卸载域同一套闸。
/// 此前它只有"文件名白名单 + 直接 reg import"，而同一威胁模型（用户可写目录里的一份 .reg
/// 被拿去写注册表）在卸载域收了四道；N1 之后列表还会跨根列出 Electron 轨写的老文件，
/// 弱链的输入面同步扩大。
///
/// 覆盖分两层，全部停在**写注册表之前**，零副作用：
/// ① 命令边界（真实 IPC）：子窗一律被档位拒杀；主窗的文件名白名单与「文件不存在」两个早退。
/// ② 内容闸（命令链直接调用的**同一函数** `reg_backup_restore_guards`）：缺版本头、
///    内容指向受保护容器。
///
/// X1-K01（v4-K09，2026-10-09）隔离改造：②原先靠往**用户真实备份根**
/// `%APPDATA%\<id>\cleanup-reg-backup` 写假 .reg 让命令的 resolve 命中——测试假件与用户
/// 真备份混居（进程被杀时 Drop 不跑会永久残留；发版前 #[ignore] 实跑还会读到假基线）。
/// 现在文件落 `temp_script_dir()`（应用私有 tmp，AGENTS §3 指定的临时产物位置）；
/// 让 `cleanup_reg_backup_restore` 读到文件的唯一位置就是两个用户备份根，那正是本条要根除
/// 的写入面。「命令链确实调了这道闸」由 backup.rs 的单点调用维持，调用点登记见 P3-5。
///
/// C08（v7.2 R6b-M01🔴）落点口径：`temp_script_dir()` = `app_data_dir()/tmp`，集成测试
/// 进程里已重定向到 `target/test-data-root/<bin>`——即便 Drop 没跑，残留也只在测试根。
/// 次序纪律：本用例的子窗档位段先建窗、`temp_script_dir()` 在后 ⇒ 环境变量先于首次
/// `app_data_dir()`（新增「直接取数据根」的步骤时刻核对这条，见 reg_backup 真机用例）。
#[test]
fn cleanup_reg_backup_restore_shares_the_uninstall_domain_gates() {
    use trim_tauri_lib::engine::paths;
    use trim_tauri_lib::engine::reg_backup::reg_backup_restore_guards;

    // ① 档位：子窗一律拒杀（rejected 全等防清单塌缩时整段空转）
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let r = invoke_text(&w, "cleanup_reg_backup_restore", json!({ "file": "1_x.reg" }));
        assert!(
            r.contains("IPC 来源校验失败"),
            "{label} 窗调清理域备份还原必须被拒杀，回执 {r}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");

    // ② 命令边界两个早退面（零触盘、不依赖备份根内容）
    let w = main_window();
    let bad = invoke(&w, "cleanup_reg_backup_restore", json!({ "file": "..\\x.reg" }));
    assert_eq!(bad["success"], json!(false), "越界文件名必须早退: {bad}");
    assert!(
        common::message_of(&bad).contains("备份文件名非法"),
        "主窗应越过档位停在文件名白名单，实得 {bad}"
    );
    let missing = invoke(
        &w,
        "cleanup_reg_backup_restore",
        json!({ "file": "1700000000000_reg_zzgate_9.reg" }),
    );
    assert_eq!(missing["success"], json!(false), "备份根里没有的文件必须拒: {missing}");
    assert!(
        common::message_of(&missing).contains("备份文件不存在"),
        "回执应指明是 resolve 出口拦下的，实得 {missing}"
    );

    // ③ 内容闸：文件落应用私有 tmp（不进用户备份根）
    let dir = paths::temp_script_dir().expect("私有 tmp 应可用");
    let stamp = 1_700_000_000_000i64;
    let no_header_name = format!("{stamp}_reg_zzgate_1.reg");
    let deny_name = format!("{}_reg_zzgate_2.reg", stamp + 1);
    let no_header = dir.join(&no_header_name);
    let deny_target = dir.join(&deny_name);
    // 用例中途 panic 也必须清掉探针文件（私有 tmp 里也不留垃圾）
    struct Cleanup(Vec<std::path::PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for p in &self.0 {
                let _ = std::fs::remove_file(p);
                let _ = std::fs::remove_file({
                    let mut s = p.as_os_str().to_os_string();
                    s.push(".meta.json");
                    std::path::PathBuf::from(s)
                });
            }
        }
    }
    let _guard = Cleanup(vec![no_header.clone(), deny_target.clone()]);

    std::fs::write(&no_header, "[HKEY_CURRENT_USER\\Software\\zzgate]\r\n\"a\"=dword:1\r\n").unwrap();
    std::fs::write(
        &deny_target,
        "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE]\r\n\"a\"=dword:1\r\n",
    )
    .unwrap();

    let e1 = reg_backup_restore_guards(&no_header, &no_header_name, "cleanup", true).unwrap_err();
    assert!(e1.contains("合法的 .reg"), "缺版本头必须被形状闸拒，实得 {e1}");
    let e2 = reg_backup_restore_guards(&deny_target, &deny_name, "cleanup", true).unwrap_err();
    assert!(e2.contains("受保护"), "指向 HKLM\\SOFTWARE 必须被禁删面拒，实得 {e2}");

    // 判红自测口径：任一道闸被摘掉，对应的 unwrap_err 当场 panic 变红；①的 rejected 全等
    // 在清单塌缩时变红。命令链侧接线（backup.rs 调 guards）由 P3-5 的调用点登记门禁接续。
}

/// 集成测试进程同样不许写生产日志（2026-10-02 修：测试夹具灌进了用户看得见的日志页）。
///
/// 为什么这条必须放在**集成测试**里：单元测试靠 `cfg!(test)` 就够，而集成测试链的是
/// **非 test 构建**的 lib，`cfg!(test)` 是 false —— 那条路径只能靠「产物落在 deps 目录」
/// 这一判据兜住。本用例就是那条判据的活体证据：判据失效时它会红，而不是让污染静默回来。
#[test]
fn 集成测试进程不写生产日志() {
    assert!(
        !trim_tauri_lib::engine::log::log_sink_enabled(),
        "集成测试进程打开了生产日志落盘 —— 测试夹具会再次灌进用户的「操作日志」"
    );
}

// ==================== M1 optimizer:batch-preflight ====================

/// M1 档位：预检是**纯只读**判定，档位挂 `guard_readonly`（放行五个窗口 label）。
///
/// 与 `optimizer_restore_reg` 那条对照着看：还原写注册表，四个子窗调它必须被拒杀；
/// 预检只读数据层与 `is_admin()`，子窗调它应当放行 —— 一放一拒之间就是档位的意义。
#[test]
fn batch_preflight_is_readonly_for_all_app_windows() {
    // R1-1.7：子窗清单必须由 `sub_windows()` 派生，不许硬编码 label 字面量
    let mut reached: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(&label);
        let text = invoke_text(&w, "optimizer_batch_preflight", json!({ "ids": ["svc_w32time_manual"] }));
        assert!(
            !text.contains("IPC 来源校验失败"),
            "{label} 窗调只读预检竟被拒杀（档位应与 optimizer_check_optimized 同档）: {text}"
        );
        assert!(
            text.contains("\"runnable\"") || text.contains("\"rejected\""),
            "{label} 窗应越过档位拿到预检结果形状，回执 {text}"
        );
        reached.push(label);
    }
    assert_eq!(reached, sub_windows(), "每个子窗 label 都必须被点名走过（清单塌缩时这条红）");
}

/// R1-1.4 / R1-1.5：空 ids 与未知 id 的**fail-closed** 形状。
///
/// 两条都是「不许乐观放行」：空入参若回「全部可执行」，前端会走进「零项全部通过」的
/// 确认弹窗；未知 id 若被算进 `runnable`，用户会对一个不存在的项发 run。
#[test]
fn batch_preflight_empty_and_unknown_ids_are_fail_closed() {
    let w = main_window();

    let empty = invoke(&w, "optimizer_batch_preflight", json!({ "ids": [] }));
    common::assert_guard_passed(
        &serde_json::to_string(&empty).unwrap_or_default(),
        "空 ids 预检",
        &["runnable", "rejected"],
    );
    assert_eq!(empty["runnable"].as_array().map(|a| a.len()), Some(0), "空 ids 不得回任何可执行项: {empty}");
    assert_eq!(empty["rejected"].as_array().map(|a| a.len()), Some(0), "空 ids 也没有拒绝项: {empty}");

    let unknown = invoke(&w, "optimizer_batch_preflight", json!({ "ids": ["__不存在的id__"] }));
    assert_eq!(unknown["success"], json!(true), "预检本身是只读判定，应报成功: {unknown}");
    assert_eq!(unknown["runnable"].as_array().map(|a| a.len()), Some(0), "未知 id 不得进 runnable: {unknown}");
    let rejected = unknown["rejected"].as_array().cloned().unwrap_or_default();
    assert_eq!(rejected.len(), 1, "未知 id 必须进 rejected: {unknown}");
    assert_eq!(rejected[0]["id"], json!("__不存在的id__"), "rejected 须点名是哪一项: {unknown}");
    assert!(
        common::message_of(&rejected[0]).is_empty() && rejected[0]["reason"].as_str().unwrap_or("").contains("未知选项"),
        "拒绝理由必须在 reason 字段（不是 message）: {unknown}"
    );
}

/// R1-1.3 命令层形状：`runnable` / `rejected` 的字段类型对着渲染层消费口径断。
///
/// 前端 `filterByPreflight` 直接 `.map` `rejected[].id/reason` 并 `new Set(res.runnable)`，
/// 字段缺失或类型不对会让批量预检静默把整批判成「全被拦」。快速组只传零副作用 id。
#[test]
fn batch_preflight_response_shape_matches_renderer_contract() {
    let w = main_window();
    let res = invoke(&w, "optimizer_batch_preflight", json!({ "ids": ["svc_w32time_manual", "__不存在的id__"] }));
    assert_eq!(res["success"], json!(true), "回执 {res}");
    assert!(res["runnable"].is_array(), "runnable 必须是数组（前端 new Set(...)）: {res}");
    assert!(res["rejected"].is_array(), "rejected 必须是数组（前端 .map）: {res}");
    for r in res["rejected"].as_array().cloned().unwrap_or_default() {
        assert!(r["id"].is_string(), "rejected[].id 必须是字符串: {r}");
        assert!(r["reason"].is_string(), "rejected[].reason 必须是字符串: {r}");
    }
    // 两个 id 恰好一个未知 ⇒ 合计必须等于入参数，不许有第三个去向（既不 runnable 也不 rejected）
    let total = res["runnable"].as_array().map(|a| a.len()).unwrap_or(0)
        + res["rejected"].as_array().map(|a| a.len()).unwrap_or(0);
    assert_eq!(total, 2, "runnable+rejected 必须恰好覆盖全部入参（无处可丢）: {res}");
}

// ==================== R1-3 E4 区域耗时 ====================

/// E4 的形状契约：三个域的 `results[]` 每项都带 `elapsedMs`，且它是**非负整数**。
///
/// 为什么这条断「非负」：`elapsedMs` 来自 `Instant::elapsed().as_millis()`，恒 ≥ 0。
/// 一旦出现负数或小数，说明计时口径被改坏（或经过了 lossy 转换）——
/// 而耗时会进日志给人看，负数会被读成「系统时钟回拨」这类无法解释的现象。
///
/// 快速组只跑 `memory_clean` 的**形状面**（用不存在的区域 id 触发参数校验早退）。
/// contextmenu / startup 两域要真删文件才有 results，一律 `#[ignore]`。
///
/// 零副作用的两态口径（X1-M03 补）：提权态下 is_admin 已过、会进原生引擎，但
/// 白名单 fail-closed 在任何 `NtSetSystemInformation` 之前（perf.rs:818-822），
/// 非法 id 整批拒、一个区域都不会被碰；非提权态在 is_admin 处早退。
#[test]
fn memory_clean_results_shape_carries_elapsed() {
    // 反向前提：确认耗时字段的产出侧确实存在（否则下面这条形状断言会恒空）
    let perf = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("src-tauri 的父目录是仓根")
            .join("native-scanner")
            .join("src")
            .join("perf.rs"),
    )
    .expect("读得到 native-scanner/src/perf.rs");
    assert!(
        perf.contains("\"elapsedMs\"") && perf.contains(".elapsed()"),
        "内存清理的耗时字段在产出侧消失了 —— E4 的实现被回退了？"
    );
    let w = main_window();
    let res = invoke(&w, "memory_clean", json!({ "items": ["__不存在的区域__"] }));
    assert_eq!(res["success"], json!(false), "非法区域 id 必须拒: {res}");
    // X1-M03：拒因要点名——提权态=原生白名单（「非法区域 id」），非提权态=needAdmin。
    // 只断 success:false 分不清「闸拦住了」与「闸没了但别的原因失败」。
    assert!(
        common::message_of(&res).contains("非法区域 id")
            || common::message_of(&res).contains("需要管理员权限"),
        "拒因必须可点名（提权态=原生白名单 fail-closed；非提权态=needAdmin）: {res}"
    );
}

/// `elapsedMs` 的**类型**契约对着渲染层消费口径断。
///
/// 前端按 `Array.isArray(results)` + 每项取字段渲染，其中 memoryclean.js
/// 用 `filter(x => x.ok)`、startup 用 `r.status === 'error'`。
/// `elapsedMs` 缺失不会让它们崩（都在已有 `|| []` 兜底之内），但**渲染层绝不许
/// 假设它存在** —— 这条断言从数据侧反证：字段是每项必有，不是「有时才有」。
///
/// 2026-10-09（D3）：contextmenu 域随右键删除链整链退役（载体 remove + 嵌套 push_result
/// 已删），本断言的登记面同步收缩到 startup / perf 两个域。
#[test]
fn elapsed_ms_是每项必有的非负整数() {
    // 静态口径：产出域的源码里，写入 results 的那一处必须带 elapsedMs。
    // needle 要**精确到该域的那一处**，不能只查字段名 —— perf.rs 的 diskbench
    // 早就有一个 `elapsedMs`（`perf.rs:369`），只查字段名的话这条断言在
    // mem-clean 那处被删掉之后依然会绿（假绿）。
    let files = [
        // mem-clean 的 results.push（`status:{},\"elapsedMs\":{elapsed_ms}` 形态）
        ("native-scanner/src/perf.rs", r#""status\":{},\"elapsedMs\":{elapsed_ms}"#),
        ("src-tauri/src/commands/startup.rs", r#""elapsedMs".into(),"#),
    ];
    for (rel, needle) in files {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("src-tauri 的父目录是仓根")
            .join(rel);
        let src = std::fs::read_to_string(&p).expect(&format!("读得到 {rel}"));
        assert!(src.contains(needle), "{rel} 里找不到耗时写入点（needle={needle}）");
        // 计时必须真在算，不许恒为 0
        assert!(
            src.contains(".elapsed()"),
            "{rel} 有字段名但没有 elapsed() 计算 ⇒ 耗时恒为 0 的假绿"
        );
    }
}

// ==================== syspanel 回执形状（2026-10-03 读取失败根因） ====================

/// syspanel 全域命令的回执必须是 `{ success, data }`，**不是裸对象**。
///
/// 根因（真实缺陷）：`syspanel_power_plan_get` / `pagefile_state` 早期直接
/// `Ok(power_plan_state())` 返回裸 state，裸对象没有 `success` 字段 ⇒ 渲染层
/// `syspanel.js` 的 `resp.success` 恒为 undefined ⇒ 两块面板永远显示
/// 「读取电源方案失败 / 读取虚拟内存失败」，而后端其实读到了数据。
///
/// 为什么用静态口径而不是 `invoke`：命令只在**主窗**放行（`guard(MAIN)`），
/// 且读值/写值会触真实 Power API；导出还会拉起 `powercfg.exe` —— 不属快速组零副作用命令。
/// 断言改为「命令体必须走统一 success/data 包装」，锁的正是那次漂移本身。
#[test]
fn syspanel_回执必须是_success_data_包装() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/commands/syspanel.rs");
    let src = std::fs::read_to_string(&p).expect("读得到 src-tauri/src/commands/syspanel.rs");
    assert!(
        src.contains(r#"Ok(json!({ "success": true, "data": data }))"#),
        "syspanel_ok 必须保持 success/data 包装"
    );
    let commands = [
        "syspanel_power_plan_get",
        "syspanel_power_plan_apply",
        "syspanel_power_settings_dump",
        "syspanel_power_plan_duplicate",
        "syspanel_power_plan_rename",
        "syspanel_power_plan_delete",
        "syspanel_power_plan_import",
        "syspanel_power_plan_export",
        "syspanel_power_settings_unlock",
        "syspanel_power_settings_apply",
        "syspanel_power_settings_revert",
        "syspanel_power_settings_compare",
        "syspanel_power_settings_open_regedit",
        "syspanel_pagefile_state",
        "syspanel_pagefile_apply",
    ];
    for name in commands {
        let needle = format!("fn {name}<R: Runtime>");
        let start = src
            .find(&needle)
            .or_else(|| src.find(&format!("fn {name}<R: tauri::Runtime>")))
            .unwrap_or_else(|| panic!("找不到命令 {name}"));
        let body = &src[start..];
        let end = body.find("\n}\n").unwrap_or(body.len());
        let body = &body[..end];
        assert!(
            body.contains("syspanel_ok")
                || body.contains("syspanel_result_from_data")
                || body.contains(r#"json!({ "success": true, "data":"#)
                || body.contains(r#"json!({ "success": true, "data": state })"#),
            "{name} 回执未走统一 success/data 包装：{body}"
        );
    }
    // 反向：Ok( 直接返回裸值的形态必须已经不存在。
    // 判据**精确到带右括号的形态**（`Ok(power_plan_state())`）：写成 `Ok(power_plan_state`
    // 会连 `Ok(json!({ "success": true, "data": power_plan_state() }))` 一起命中 ⇒ 恒红。
    // substring 判据必须与被禁写法逐字对齐，本仓已因此踩过多次。
    assert!(
        !src.contains("Ok(power_plan_state())") && !src.contains("Ok(pagefile_state())"),
        "仍有命令裸返回 state ⇒ 渲染层恒判读取失败"
    );
}

/// v5 P0：`cases` 里登记的 syspanel 命令全部是主窗档；子窗调用必须在 guard 处被拒杀，
/// 不得进入真实 Power API 或文件对话框。
///
/// v6 X1-M01：入参**一律畸形/不存在**——本用例此前带着真实写侧合法入参
/// （`381b4222-…` = 标准 Balanced 方案的真实 GUID + `confirmedHighRisk:true`）。
/// 档位是第一道闸没错，但若将来有人把档位回退（历史上发生过 readonly 静默放宽），
/// 这些调用就会**真的删掉 Balanced / 真的写电源设置**。改成畸形入参后，即使档位
/// 被回退，命令体自身也会因「方案不存在」拒绝——快速组靠两道防线而不是一道。
/// （`ultimate_enable` / `restore_high_performance` 无入参可畸形，保持 `{}`；
/// 它们的命令体行为由 native 层真机探针与发版手册覆盖。）
#[test]
fn syspanel_power_编辑命令_is_main_only() {
    // 伪造 GUID：命令体按「方案不存在」拒绝（powercfg 对不存在 GUID 必报错），
    // 不指向任何真实电源方案。
    const NO_SUCH_GUID: &str = "00000000-0000-0000-0000-trimnosuchplan";
    let cases: &[(&str, serde_json::Value)] = &[
        ("syspanel_power_settings_dump", json!({ "schemeGuid": NO_SUCH_GUID })),
        ("syspanel_power_plan_duplicate", json!({ "sourceGuid": NO_SUCH_GUID, "name": "x" })),
        ("syspanel_power_plan_rename", json!({ "guid": NO_SUCH_GUID, "name": "x" })),
        ("syspanel_power_plan_delete", json!({ "guid": NO_SUCH_GUID, "confirmedHighRisk": true })),
        ("syspanel_power_plan_import", json!({})),
        ("syspanel_power_plan_export", json!({ "guid": NO_SUCH_GUID })),
        ("syspanel_power_settings_unlock", json!({ "schemeGuid": NO_SUCH_GUID })),
        ("syspanel_power_settings_apply", json!({ "schemeGuid": NO_SUCH_GUID, "changes": [], "applyActive": false })),
        ("syspanel_power_settings_revert", json!({ "schemeGuid": NO_SUCH_GUID, "sessionId": "x" })),
        ("syspanel_power_settings_compare", json!({ "subgroupGuid": NO_SUCH_GUID, "settingGuid": NO_SUCH_GUID })),
        ("syspanel_power_settings_open_regedit", json!({ "subgroupGuid": NO_SUCH_GUID, "settingGuid": NO_SUCH_GUID })),
        // G-04 专用能力（2026-10-16）：三命令同为写侧、系统级、只在主窗电源卡触发。
        // 子窗调用必须在 guard 处拒杀，不得进入真实 Power API / 文件系统。
        // （前两条无入参可畸形——见上方 X1-M01 注。）
        ("syspanel_power_ultimate_enable", json!({})),
        ("syspanel_power_hide_high_performance", json!({ "confirmedHighRisk": true })),
        ("syspanel_power_restore_high_performance", json!({})),
    ];
    let mut rejected = Vec::<String>::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        for (cmd, args) in cases {
            let text = invoke_text(&w, cmd, args.clone());
            assert!(
                text.contains("IPC 来源校验失败"),
                "{label} 窗调 {cmd} 必须被来源校验拒杀，回执 {text}"
            );
            rejected.push(format!("{label}:{cmd}"));
        }
    }
    assert_eq!(
        rejected.len(),
        sub_windows().len() * cases.len(),
        "每个子窗 label 都必须逐命令被拒杀（清单塌缩时这条红）"
    );
}

/// 2026-10-03 根治：「未完成还原」横幅的 per-id 忽略是写操作（记账 prefs 段），
/// 优化页只在主窗 ⇒ 档位必须 MAIN，子窗被拒。正向特征（主窗能通过来源校验）
/// 由 pending 侧同名模板核对过的同族形态覆盖；这里按模板纪律只点子窗拒绝侧。
#[test]
fn optimizer_stale_dismiss_is_main_only() {    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "optimizer_stale_dismiss", json!({ "ids": ["x"] }));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调 optimizer_stale_dismiss 必须被来源校验拒杀，回执 {text}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");
}

/// 账外核对（2026-10-15 拍板）：只读但只被主窗优化页消费 ⇒ 按 D5 判据取 MAIN，子窗被拒杀。
/// 只点子窗拒绝侧；命中判定由 `external_scan.rs` 的单测与真机探针覆盖。
#[test]
fn optimizer_external_scan_is_main_only() {
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "optimizer_external_scan", json!({}));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调 optimizer_external_scan 必须被来源校验拒杀，回执 {text}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");
}

/// 2026-10-04 磁盘清理审计 §5.6：item-detail 的 path 形参必须与扫描快照同源。
/// MockRuntime 没有真实扫描（快照为空）⇒ 任意非空 path 必须被拒——这正好是
/// 「任意目录读暴露面」的拒收面；空 path 走规则自身枚举，不得触发该拒绝。
#[test]
fn cleanup_item_detail_path_不在快照时被拒() {
    let w = main_window();
    // ① 任意非空 path（快照为空 = 必然不同源）必须被拒
    let text = invoke_text(
        &w,
        "cleanup_item_detail",
        json!({ "id": "__no_such_id__", "path": r"C:\Windows\Web" }),
    );
    assert!(
        text.contains("已拒绝枚举") || text.contains("不是本次扫描结果"),
        "任意目录读必须被拒（§5.6）: {text}"
    );
    // ② 空 path：不得触发 §5.6 拒绝（走规则自身的枚举面，回执可能是成功或
    //    规则不存在，但必须是别的理由）
    let text2 = invoke_text(
        &w,
        "cleanup_item_detail",
        json!({ "id": "__no_such_id__", "path": "" }),
    );
    assert!(
        !text2.contains("不是本次扫描结果") && !text2.contains("已拒绝枚举"),
        "空 path 不得被 §5.6 拒绝误伤: {text2}"
    );
}

/// 2026-10-06 任务三：`optimizer_restore_frequency`（还原点弹窗「恢复默认创建频率」）
/// 的档位正例 —— 主窗调用必须越过档位，且回执是三态之一（needAdmin / missing / success）
/// 且带 message，绝不许静默。
///
/// `#[ignore]` 的原因：本机若为管理员且已存在 `tf_restore_point` 备份（开发机就是），
/// 命令会**真的执行一次回收**（把 `SystemRestorePointCreationFrequency` 恢复为备份原值 /
/// 无原值则删值）—— 幂等且只动这一个键，但按纪律②「改系统的进发布前门禁组」。
#[test]
#[ignore = "管理员环境会真写注册表（恢复频率键，幂等；顺带清本机 0x0 残留），发布前门禁跑"]
fn optimizer_restore_frequency_主窗越档且回执确定() {
    let w = main_window();
    let res = invoke(&w, "optimizer_restore_frequency", json!({}));
    let text = res.to_string();
    common::assert_guard_passed(
        &text,
        "主窗调 optimizer_restore_frequency",
        &["needAdmin", "missing", "success"],
    );
    let msg = common::message_of(&res);
    assert!(!msg.is_empty(), "无论成败都必须有 message（回收了什么 / 为什么不能回收）: {res}");
    if res["success"] == json!(true) {
        // 成功回执必须写明「写了什么」：写回原值 or 删除覆写值（recycle_freq_override 两个成功分支）
        assert!(
            msg.contains("已写回") || msg.contains("已删除"),
            "成功回执必须写明回收动作（写回原值 / 删除覆写值）: {res}"
        );
    } else {
        let need_admin = res["needAdmin"] == json!(true);
        let missing = res["missing"] == json!(true);
        assert!(
            need_admin || missing,
            "失败必须显式回 needAdmin 或 missing（未知失败 = 静默黑洞）: {res}"
        );
    }
}

/// 同一命令的子窗侧：一律被来源校验拒杀（MAIN 档，guard 先于一切 ⇒ 零副作用，留快速组）。
#[test]
fn optimizer_restore_frequency_子窗一律拒杀() {
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "optimizer_restore_frequency", json!({}));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调 optimizer_restore_frequency 必须被来源校验拒杀，回执 {text}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");
}

/// 2026-10-06 任务四：空目录忽略名单三命令 —— 档位与负例。
/// （清理计划导出已随 2026-10-06 用户裁定全链路退役，本用例中的相应段落同撤。）
///
/// 全部 MAIN 档：① 子窗一律拒杀（零副作用）；② 主窗负例都在**写盘之前**
/// 被拒（不存在的目录 / 不在名单的条目）—— 快速组零副作用；
/// 真写名单的路径留给真机验收（§4.1：MockRuntime 覆盖不到真实 IO 后果）。
#[test]
fn finder_ignore名单_档位与负例() {
    // ① 子窗一律拒杀
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        for (cmd, args) in [
            ("finder_ignore_folder", json!({ "path": "C:\\__trim_test_missing__" })),
            ("finder_ignore_list", json!({})),
            ("finder_ignore_remove", json!({ "path": "C:\\__trim_test_missing__" })),
        ] {
            let text = invoke_text(&w, cmd, args);
            assert!(
                text.contains("IPC 来源校验失败"),
                "{label} 窗调 {cmd} 必须被来源校验拒杀，回执 {text}"
            );
        }
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");
    let w = main_window();
    // ② 不存在的目录：在读取 / 写盘之前拒绝
    // X1-M03（v7.2 C08）补拒因点名：只断 success:false 分不清「存在性闸拦住了」与
    // 「闸没了、写名单自己失败」。needle 取自 finder.rs:1007-1008 的存在性分支。
    // 落点说明：真写路径写 `empty-ignore.txt`（`app_data_dir()` 下），C08 数据根
    // 隔离后已重定向到测试根；本负例在写盘前被拒，两种形态都不碰名单。
    let res = invoke(&w, "finder_ignore_folder", json!({ "path": "C:\\__trim_test_missing__" }));
    assert_eq!(res["success"], json!(false), "不存在的目录必须拒: {res}");
    assert!(
        common::message_of(&res).contains("只能忽略本机存在的文件夹"),
        "拒因必须点名存在性闸: {res}"
    );
    // ③ 不在名单的条目 → missing 且零副作用（不写盘）
    let res = invoke(&w, "finder_ignore_remove", json!({ "path": "C:\\__trim_test_missing__" }));
    assert_eq!(res["success"], json!(false), "不在名单的条目必须拒: {res}");
    assert_eq!(res["missing"], json!(true), "拒绝形态应为 missing: {res}");
    // ④ 读侧（只读，零副作用）：主窗越过档位
    let res = invoke(&w, "finder_ignore_list", json!({}));
    common::assert_guard_passed(&res.to_string(), "主窗调 finder_ignore_list", &["success"]);
}

// ==================== v4-K04：quickcmds_run 升 MAIN 档 ====================

/// quickcmds_run 挂 `guard::MAIN`（白名单含等效提权出口 `sys-cmd-admin`：
/// `Start-Process cmd -Verb RunAs`，子窗失陷即可弹 UAC 交出管理员 CMD）。
/// 子窗一律拒杀（rejected 全等防清单塌缩）；主窗越过档位后停在白名单查询
/// （未知 id 早退，零副作用）。
#[test]
fn quickcmds_run_is_main_only() {
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "quickcmds_run", json!({ "id": "__trim_smoke_unknown__" }));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调快捷指令必须被来源校验拒杀（v4-K04 升 MAIN），回执 {text}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");
    let w = main_window();
    let res = invoke(&w, "quickcmds_run", json!({ "id": "__trim_smoke_unknown__" }));
    assert_eq!(res["success"], json!(false), "主窗越过档位后未知 id 必须被白名单拒: {res}");
    assert!(
        common::message_of(&res).contains("未知指令"),
        "主窗应越过档位进入白名单查询（正向特征），回执 {res}"
    );
}

// ==================== v4 修复：启动项禁用/启用整条原生链（数组台账读器回归） ====================

/// 真机 `#[ignore]` 探针：注册表启动项的**禁用/启用**端到端（含批准位回读）。
///
/// 背景（真机症状「能删除不能禁用」的根因）：R5-M03 台账三态化借用了只认对象的
/// `read_json_state`，而禁用台账 `disabled.json` 是**裸数组** —— 合法数组被判损坏，
/// 每次启用/禁用都在「读台账」处整批中止；删除链不读台账所以照常可用。
/// 本用例自建 HKCU Run 探针值 → 走 `startup_toggle` 真实注册表路径 → 断言
/// StartupApproved 批准位 bit0 翻转 → 还原 → 清理（Drop 守卫，断言失败也会清）。
/// 数组读器一旦退回对象版，第一条断言即红（回执 message 变为「台账读取失败」）。
#[test]
#[ignore = "真写 HKCU Run 探针值 + StartupApproved blob（自建自清），发布前门禁跑"]
fn startup_toggle_registry_probe_disable_and_enable() {
    use trim_tauri_lib::engine::native::{hive_hkcu, read_reg_binary_opt, startup_toggle};

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const SA_KEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    const NAME: &str = "TrimProbeToggleX";

    struct ProbeCleanup;
    impl Drop for ProbeCleanup {
        fn drop(&mut self) {
            for key in [SA_KEY, RUN_KEY] {
                let _ = std::process::Command::new("reg")
                    .args(["delete", &format!(r"HKCU\{key}"), "/v", NAME, "/f"])
                    .output();
            }
        }
    }
    let _cleanup = ProbeCleanup;

    let st = std::process::Command::new("reg")
        .args([
            "add",
            &format!(r"HKCU\{RUN_KEY}"),
            "/v",
            NAME,
            "/t",
            "REG_SZ",
            "/d",
            r"C:\Windows\System32\notepad.exe",
            "/f",
        ])
        .status()
        .expect("reg.exe 可执行");
    assert!(st.success(), "建探针 Run 值失败（下面两条断言无意义）");

    let item = json!({
        "id": format!("reg|HKEY_CURRENT_USER\\{RUN_KEY}|{NAME}"),
        "name": NAME,
        "source": "registry",
        "hive": "HKCU",
        "regPath": format!("HKEY_CURRENT_USER\\{RUN_KEY}"),
        "valueName": NAME,
        "valueType": "String",
        "valueData": r"C:\Windows\System32\notepad.exe",
        "filePath": "",
        "taskPath": "",
        "taskName": "",
    });

    let res = startup_toggle(&[item.clone()], false).expect("禁用不应整批失败（数组台账读器回归的判红点）");
    assert_eq!(res["failed"], json!(0), "禁用应全部成功: {res}");
    let blob = read_reg_binary_opt(hive_hkcu(), SA_KEY, NAME).expect("批准位应已写出");
    assert!(blob.starts_with("03"), "bit0 置位 ⇒ 首字节 03，实际 {blob}");

    let res2 = startup_toggle(&[item], true).expect("启用不应整批失败");
    assert_eq!(res2["failed"], json!(0), "启用应全部成功: {res2}");
    let blob2 = read_reg_binary_opt(hive_hkcu(), SA_KEY, NAME).expect("批准位应仍在");
    assert!(blob2.starts_with("02"), "bit0 清零 ⇒ 首字节 02，实际 {blob2}");
}

/// RunOnce 探针的注册表路径（真机用例与清理守卫共用一份字面量）。
const RUNONCE_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";

/// RunOnce 探针项（与扫描产出的字段形状一致）。
fn runonce_probe_item() -> serde_json::Value {
    json!({
        "id": format!("reg|HKEY_CURRENT_USER\\{RUNONCE_KEY}|TrimProbeRunOnceX"),
        "name": "TrimProbeRunOnceX",
        "source": "registry",
        "hive": "HKCU",
        "regPath": format!("HKEY_CURRENT_USER\\{RUNONCE_KEY}"),
        "valueName": "TrimProbeRunOnceX",
        "valueType": "String",
        "valueData": r"C:\Windows\System32\notepad.exe",
        "filePath": "",
        "taskPath": "",
        "taskName": "",
    })
}

/// 真机 `#[ignore]` 探针：RunOnce 项的禁用必须走「备份 + 删值」。
///
/// 背景：StartupApproved 没有 RunOnce 子键（系统约定只覆盖 Run/Run32/启动文件夹），
/// 旧实现对 RunOnce 也写批准位 —— 死数据：界面显示「已禁用」而下次登录该程序照样
/// 执行一次。修复后禁用 = 删值 + 记台账（扫描合并仍以「已禁用（Trim）」呈现），
/// 启用 = 从台账恢复原值。本用例自建自清；判红点：禁用后值还在 ⇒ 红。
#[test]
#[ignore = "真写 HKCU RunOnce 探针值（自建自清），发布前门禁跑"]
fn startup_toggle_runonce_probe_uses_backup_delete() {
    use trim_tauri_lib::engine::native::startup_toggle;

    const NAME: &str = "TrimProbeRunOnceX";
    let full_key = || format!(r"HKCU\{RUNONCE_KEY}");
    let reg_query = || {
        std::process::Command::new("reg")
            .args(["query", &full_key(), "/v", NAME])
            .output()
            .expect("reg.exe 可执行")
            .status
            .success()
    };

    struct ProbeCleanup;
    // Drop 守卫：尽力复原（启用回写走台账/清账），再删掉探针值，断言失败也不留痕。
    impl Drop for ProbeCleanup {
        fn drop(&mut self) {
            let _ = trim_tauri_lib::engine::native::startup_toggle(&[runonce_probe_item()], true);
            let _ = std::process::Command::new("reg")
                .args(["delete", &format!(r"HKCU\{RUNONCE_KEY}"), "/v", NAME, "/f"])
                .output();
        }
    }
    let _cleanup = ProbeCleanup;

    let _ = std::process::Command::new("reg")
        .args(["delete", &full_key(), "/v", NAME, "/f"])
        .output();
    let st = std::process::Command::new("reg")
        .args([
            "add", &full_key(), "/v", NAME, "/t", "REG_SZ", "/d",
            r"C:\Windows\System32\notepad.exe", "/f",
        ])
        .status()
        .expect("reg.exe 可执行");
    assert!(st.success(), "建探针 RunOnce 值失败");

    let res = startup_toggle(&[runonce_probe_item()], false).expect("禁用不应整批失败");
    assert_eq!(res["failed"], json!(0), "禁用应成功: {res}");
    let msg = res["results"][0]["message"].as_str().unwrap_or("");
    assert!(msg.contains("RunOnce"), "回执应点名 RunOnce 走向备份删除: {res}");
    assert!(!reg_query(), "禁用后 RunOnce 值必须已删除（写批准位是死数据，系统不认）");

    let res2 = startup_toggle(&[runonce_probe_item()], true).expect("启用不应整批失败");
    assert_eq!(res2["failed"], json!(0), "启用应成功（从台账恢复原值）: {res2}");
    assert!(reg_query(), "启用后原值必须已恢复");
}

/// v4 修复回归（快速组）：测速历史回执与**磁盘真值**自比对 ——/// 同一回归的另一受害者：`bench-history.json` 也是裸数组，被对象读器判损坏后
/// 列表恒空（文件里明明有记录）。本用例不依赖装机数据：文件不存在时只验形状，
/// 存在时必须条数一致（采集与判定拆开：真值取自文件本身，不是硬编码期望）。
///
/// X1-M04（v7.2 C08）两方向口径声明（此前同文件内两个相反方向都不合规）：
/// - **缺样本**（本机无该文件）：条数对拍无对象 ⇒ `skip_and_record` 明示跳过，
///   不再 `Err(_) => {}` 静默绿——那条支路让「数组读器回归」这个立项目的碰巧绿；
/// - **合法损坏态**：按 §5.26，`bench-history.json` 是「只读缓存、损坏静默降级」的
///   合法状态，命令回空数组是设计行为 ⇒ 不判红，同样走 skip 并说明。
/// 另外修了一个次序隐患：`join_data` 会首次定死 `app_data_dir()` 的 OnceLock，
/// 必须先建窗注入测试根再取路径（与 reg_backup 真机用例同一条纪律）。
#[test]
fn bench_history_list_matches_file_truth() {
    let w = main_window();
    let f = trim_tauri_lib::engine::paths::join_data("bench-history.json");
    let raw = std::fs::read_to_string(&f);
    let res = invoke(&w, "bench_history_list", json!({}));
    assert_eq!(res["success"], json!(true), "列表应成功: {res}");
    assert!(res["data"].is_array(), "data 必须是数组: {res}");
    let n_cmd = res["data"].as_array().map(|a| a.len()).unwrap_or(usize::MAX);
    match raw {
        Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) => {
                let n_file = v.as_array().map(|a| a.len()).unwrap_or(0);
                assert_eq!(
                    n_cmd, n_file,
                    "回执条数必须与磁盘真值一致（数组读器回归时命令恒 0）: file={n_file} cmd={n_cmd}"
                );
            }
            // 合法损坏态（§5.26）：降级是设计行为，不当代码缺陷判红
            Err(e) => {
                skip_and_record(&format!(
                    "bench_history：本机历史文件存在但非合法 JSON（{e}）——按 §5.26 属合法降级态，条数对拍不判红"
                ));
            }
        },
        // 缺样本：形状断言已跑（上面两条），对拍段无对象——明示跳过而非静默绿
        Err(_) => {
            skip_and_record("bench_history：本机无 bench-history.json，条数对拍无对象（形状断言已跑）");
        }
    }
}

/// 性能优化 P0-3 前置实测（v2 §九#7 被推翻后重设计为「先量再决定要不要上限」）。
///
/// 原方案要给 `startup_scan()` 加 `.take(500)`，被 v2 判为回归；这里出的是**真实条数**：
/// ① 本机枚举到多少条（决定「上限」在现实机器上是否会触发）；
/// ② 是否已超过写侧的 500 条整批上限（`commands/startup.rs` 的 `items.len() > 500` 判拒）——
///    超了才说明「全选一键禁用」本就有问题，没超就说明加上限只是凭空引入风险。
/// 只读数、不改判据；结论用于决定这条要不要动手。
///
/// X1-M04（v7.2 C08）：本条是自述「**非回归判据**」的取数探针，却挂着硬断言
/// （枚举失败 `.expect` 炸、启动项为空 `assert!` 红）——与回归用例混居在发布前
/// 门禁批次里，本机无样本就把门禁堵住。按探针定位改成**只打印**：枚举失败与
/// 空样本都走 `skip_and_record` 明示无对象，拿数走 `println!`。
#[test]
#[ignore = "真机实测：读注册表与计划任务，非回归判据，取数时手动 --ignored 跑"]
fn startup_scan_真实条数与写侧上限关系实测() {
    let Ok(items) = trim_tauri_lib::engine::native::startup_scan() else {
        skip_and_record("startup_scan：本机启动项枚举失败（取数探针无对象，先查环境再谈判据）");
        return;
    };
    let mut by_source: std::collections::BTreeMap<String, usize> = Default::default();
    for it in &items {
        *by_source
            .entry(it.get("source").and_then(|v| v.as_str()).unwrap_or("?").to_string())
            .or_insert(0) += 1;
    }
    if items.is_empty() {
        skip_and_record("startup_scan：本机启动项为空（取数探针无对象；真为空该去查判据退化，但那不是本条的断言）");
        return;
    }
    let over_write_cap = items.len() > 500;
    println!(
        "startup_scan 实测：总 {} 条，分来源 {:#?}；写侧整批上限 500 —— {}（enabled/disabled 计数 {} / {}）",
        items.len(),
        by_source,
        if over_write_cap { "已超：全选一键操作本就会被 validate_snapshot_items 整批拒" } else { "未超：take(500) 在现实机器上永不触发，纯增风险" },
        items.iter().filter(|i| i.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true)).count(),
        items.iter().filter(|i| i.get("enabled").and_then(|v| v.as_bool()) == Some(false)).count(),
    );
}

/// P0-A2（2026-10-16 总方案 v2 §3）：匹配器归一后，扫描侧 `wildcard_match` 是
/// 两侧唯一真源（执行侧 glob_match 委托它，委托接线由 cleanup.rs 内单测钉）。
/// 本仓 `cargo test` 跑不到 native-scanner 自己的测试（那边唯一自动入口是
/// check-scan-rule-diff 门禁），故在这里补钉它的语义：大小写不敏感、支持 `?`
/// 与多星回溯——`*Cache*` 必须命中 "Code Cache" 这类中间还有内容的形态
/// （修前执行侧只认第一个 `*`，恒不匹配）。
#[test]
fn wildcard_match_多星与大小写不敏感() {
    use trim_finder::cleanup_scan::wildcard_match;
    // 样本与 cleanup.rs 内委托用例同源：真实规则段形态 + 大小写形态 + ? + 负样本
    assert!(wildcard_match("CacheStorage", "*Cache*"), "*Cache* 应命中 CacheStorage");
    assert!(wildcard_match("Code Cache", "*Cache*"), "*Cache* 应命中 Code Cache（中间有内容）");
    assert!(wildcard_match("Cache", "*cache*"), "*cache* 应命中 Cache（大小写不敏感）");
    assert!(wildcard_match("GPUCache", "*cache*"), "*cache* 应命中 GPUCache");
    assert!(wildcard_match("app.log", "*.LOG"), "*.LOG 应命中 app.log（大小写不敏感）");
    assert!(wildcard_match("x.patch.err", "*PATCH.ERR"), "*PATCH.ERR 应命中 x.patch.err");
    assert!(wildcard_match("abc", "a?c"), "a?c 应命中 abc（? 恰一字符）");
    assert!(!wildcard_match("Logs", "*Cache*"), "无 cache 子串不得命中");
    assert!(!wildcard_match("ac", "a?c"), "? 不匹配空");
    assert!(!wildcard_match("a.log", "*.txt"), "后缀不合不得命中");
}

// ==================== C1-1：占用查询（P1-D，主窗内嵌卡片） ====================

/// C1-1 主窗档反向钉：`cleanup_query_locked` 比 check-locked 的 readonly 更紧——
/// 未知 label（模拟被注入页）与全部子窗调它都必须被来源校验拒杀。
/// 档位按「谁真的需要调它」判：占用查询入口只在主窗磁盘清理页（内嵌卡片），
/// 下放给子窗就是白给放宽（AGENTS §3）。
#[test]
fn cleanup_query_locked_is_main_only() {
    let w = window_with_label("__trim_injected__");
    let text = invoke_text(&w, "cleanup_query_locked", json!({ "path": r"C:\Windows" }));
    assert!(
        text.contains("IPC 来源校验失败"),
        "未知 label 调占用查询必须被拒（主窗档），回执 {text}"
    );
    let mut rejected: Vec<&str> = Vec::new();
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "cleanup_query_locked", json!({ "path": r"C:\Windows" }));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调占用查询必须被来源校验拒杀（主窗档），回执 {text}"
        );
        rejected.push(label);
    }
    assert_eq!(rejected, sub_windows(), "每个子窗 label 都必须被点名拒杀（清单塌缩时这条红）");
}

/// C1-1 占用查询：主窗 + 不存在的路径必须「明说路径不存在」，不许装「无占用」——
/// 假空结果会让用户以为文件没被占（与「解占用」的功能定位直接冲突）。
/// 早退发生在任何 RM 注册之前 ⇒ 零副作用，可做 MockRuntime 快测。
#[test]
fn cleanup_query_locked_reports_missing_path_honestly() {
    let mut missing = std::env::temp_dir().join(format!(
        "__trim_smoke_no_such_query_{}__",
        std::process::id()
    ));
    // 「不存在」是断言前提：极端残留（同名历史产物）时加后缀再探测
    while missing.exists() {
        missing.push("_");
    }
    let w = main_window();
    let res = invoke(&w, "cleanup_query_locked", json!({ "path": missing.to_string_lossy() }));
    assert_eq!(res["success"], json!(false), "不存在的路径不得装「无占用」: {res}");
    assert!(
        common::message_of(&res).contains("路径不存在"),
        "必须以「路径不存在」明说，回执 {res}"
    );
}

/// 真机 `#[ignore]` 探针：占用查询端到端（RM 管线真跑）。
///
/// 形态修正（2026-10-16 本机实测，诊断数据在 `target/probe-c1-1-rm/`）：交接文档原
/// 设计「用记事本占住文件」在 Win11 26H2 的 Store 版记事本上**不成立**——实测记事本
/// 打开文件后不持句柄（独占探测 8 次全成功、可重命名、RM 零报告），构造不出「被占用」。
/// 改用确定性形态：独立 powershell 子进程以 `FileShare.None` 独占打开探针文件并保持
/// ——这正是产品面「文件被某进程占用」的等价物（`file_deletable` 探测失败 → 进 RM 查询）。
/// 为什么必须用外部进程而不能用测试进程自己的句柄：解析器会剔除**调用方自身 PID**
/// （RM 总会把调用方列入占用者名单，v3.7.3 修复①）——测试进程自己占文件会被这条
/// 剔除逻辑吃掉，验不出真东西。断言以 holder 的 **PID** 为准（不依赖 app 名字符串形态）。
/// 清场：Drop 守卫 kill holder + 删临时目录（powershell 是本次 spawn 的子进程，
/// 不存在「误杀用户进程」面）。
#[test]
#[ignore = "真机探针：起 powershell 持文件句柄（自建自清），发布前门禁跑"]
#[cfg(windows)]
fn cleanup_query_locked_probe_names_locking_process() {
    let dir = std::env::temp_dir().join(format!("__trim_lock_probe_{}__", std::process::id()));
    std::fs::create_dir_all(&dir).expect("建探针目录失败");
    let file = dir.join("probe.txt");
    std::fs::write(&file, b"trim lock probe").expect("写探针文件失败");

    struct ProbeCleanup {
        child: Option<std::process::Child>,
        dir: std::path::PathBuf,
    }
    impl Drop for ProbeCleanup {
        fn drop(&mut self) {
            if let Some(mut c) = self.child.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    // holder：Windows PowerShell（系统必带，-WindowStyle Hidden 不弹窗）独占持有 120 秒。
    // 路径单引号转义成 ''（PS 单引号字符串规则）——temp 路径理论上可不含单引号，但别赌。
    let ps_path = file.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$fs=[IO.File]::Open('{ps_path}',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None); Start-Sleep -Seconds 120"
    );
    let child = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .spawn()
        .expect("启动 holder powershell 失败");
    let holder_pid = child.id() as i64;
    let _cleanup = ProbeCleanup { child: Some(child), dir: dir.clone() };

    // 独占探测（与 file_deletable 同口径）：失败 = 文件已被持有
    fn file_held(p: &std::path::Path) -> bool {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).share_mode(0).open(p).is_err()
    }

    // 前提轮询：holder 起效（powershell 冷启动 + 脚本执行可达数秒）
    let mut held = false;
    for _ in 0..15 {
        if file_held(&file) {
            held = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(held, "holder 未成功持有文件（环境问题：powershell 未能持句柄），先排查环境再判产品");

    let named = |res: &serde_json::Value| {
        res["procs"]
            .as_array()
            .map(|a| a.iter().any(|p| p.get("pid").and_then(|v| v.as_i64()) == Some(holder_pid)))
            .unwrap_or(false)
    };

    let w = main_window();
    // ① 文件形态：查询必须点名 holder（最多 20 次 × 500ms，容忍 RM 会话建立延迟）
    let mut hit_file = false;
    for _ in 0..20 {
        let res = invoke(&w, "cleanup_query_locked", json!({ "path": file.to_string_lossy() }));
        assert_eq!(res["success"], json!(true), "真机占用查询应成功: {res}");
        if named(&res) {
            hit_file = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(hit_file, "独占持有探针文件的 holder（pid={holder_pid}）必须被点名");

    // ② 目录形态：整树分支（collect_query_tree）对同一占用也必须点名
    let res_dir = invoke(&w, "cleanup_query_locked", json!({ "path": dir.to_string_lossy() }));
    assert_eq!(res_dir["success"], json!(true), "目录查询应成功: {res_dir}");
    assert!(
        named(&res_dir),
        "目录整树查询必须点名 holder pid={holder_pid}（collect_query_tree 分支）: {res_dir}"
    );
}



// ==================== U-R1d（v7.2 P1-W2）：度量链出口收口 ====================

/// `finder_delete_manifest` / `realtime_report_delete` 由同步 `pub fn` 改成
/// `async` + `spawn_blocking`（R1d-L11）。改档位的判据不是「有没有返回值」，而是
/// **命令是否还在 generate_handler! 里、还能被 invoke 打穿**——签名换了但注册漏改、
/// 或 async 化后 `window` 生命周期写坏，症状都是「命令不存在/回执为空」。
/// 负例（非法报告名）在触盘之前就被拒，因此属零副作用快速组。
#[test]
fn u_r1d_同步命令转阻塞池后出口仍可达() {
    let w = main_window();
    // ① 清单读取：回执形状（items 必须是数组、dir 是字符串）——渲染层直接 .map
    let res = invoke(&w, "finder_delete_manifest", json!({}));
    common::assert_guard_passed(&res.to_string(), "主窗调 finder_delete_manifest", &["success"]);
    assert!(
        res["data"]["items"].is_array(),
        "async 化后 items 仍必须是数组（渲染层直接 .map）: {res}"
    );
    assert!(
        res["data"]["dir"].is_string(),
        "清单目录字段必须是字符串: {res}"
    );
    // ② 报告名非法：必须在动盘之前拒绝，且拒因点名
    let res = invoke(
        &w,
        "realtime_report_delete",
        json!({ "name": "not-a-report.txt" }),
    );
    assert_eq!(res["success"], json!(false), "非 .json 报告名必须拒: {res}");
    assert!(
        common::message_of(&res).contains("报告名称非法"),
        "拒因必须点名名称闸（否则分不清是闸拦的还是 remove_file 自己失败）: {res}"
    );
    assert_eq!(res["removed"], json!(0), "拒绝路径不得声称删过东西: {res}");
}

/// `netcheck_repair` 的 R1d-M07 出口：快照作废之后，修复必须被快照闸整条拒掉。
///
/// 为什么这条能当机检用：`netcheck_collect` 需要管理员（`guard::MAIN` + 只读档在
/// MockRuntime 里能过，但 `is_admin()` 取决于跑测试的进程），非管理员态下 collect
/// 会走 needAdmin 分支、**根本不写快照** ⇒ 恰好是「槽为空」这个待验形态。
/// 提权态跑则先 collect 再 repair，两种形态都要求 repair 的回执非绿（判「不在快照内」
/// 或 needAdmin），不许出现 success:true。
#[test]
fn u_r1d_netcheck_快照作废后修复不绿() {
    let w = main_window();
    // 先做一次采集：成功则本窗槽有账，失败/需提权则槽为空——两种都继续往下判
    let _ = invoke(&w, "netcheck_collect", json!({}));
    // 再判一个**不在本窗快照里**的动作 id：必须拒，且拒因点名快照闸
    let res = invoke(&w, "netcheck_repair", json!({ "actionId": "__trim_probe_absent__" }));
    assert_eq!(res["success"], json!(false), "白名单外的动作 id 必须拒: {res}");
    assert!(
        common::message_of(&res).contains("不在当前检测快照内"),
        "拒因必须点名快照闸（M07 的作废语义就是靠这条闸生效）: {res}"
    );
}

/// `diskbench_run` 的 R1d-M09 单飞闸：白名单外路径的拒绝必须在**占位之前**。
/// 否则一条越界请求把 `DISKBENCH_RUNNING` 置 true 后又从早退分支返回，
/// 后续所有测速都被误判「进行中」（RAII guard 恰好防住这个形态，故点名顺序）。
#[test]
fn u_r1d_diskbench_越界路径拒绝后单飞位不放脏() {
    let w = main_window();
    let bad = json!({ "options": { "path": "C:\\__trim_probe_outside_whitelist__" } });
    let first = invoke(&w, "diskbench_run", bad.clone());
    assert_eq!(first["success"], json!(false), "白名单外路径必须拒: {first}");
    assert_ne!(
        first["busy"],
        json!(true),
        "越界拒因必须是路径白名单，不能是「单飞位被占」: {first}"
    );
    // 同一条再来一次：若上一条把位占住没放，这条会回 busy:true
    let second = invoke(&w, "diskbench_run", bad);
    assert_ne!(
        second["busy"],
        json!(true),
        "早退路径必须释放单飞位（RAII Drop），否则第二次请求被误判进行中: {second}"
    );
}
