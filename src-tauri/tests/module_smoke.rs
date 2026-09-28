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

use common::{invoke, invoke_text, main_window, sub_windows, window_with_label};
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

/// cleanup:exclude-list 形状（C-1 排除名单）：`data.entries` 必须是数组。
/// 防的是：名单文件缺失时弹窗渲染崩（应为空列表降级）。
#[test]
fn cleanup_exclude_list_shape() {
    let w = main_window();
    let res = invoke(&w, "cleanup_exclude_list", json!({}));
    assert_eq!(res["success"], json!(true), "exclude-list 应成功: {res}");
    assert!(
        res["data"]["entries"].is_array(),
        "data.entries 必须是数组: {res}"
    );
}

/// cleanup:custom-list 形状：`data.entries` 必须是数组（返回体为 {file, entries}）。
/// 防的是：自定义目录文件缺失时弹窗渲染崩（应为空列表降级）。
#[test]
fn cleanup_custom_list_shape() {
    let w = main_window();
    let res = invoke(&w, "cleanup_custom_list", json!({}));
    assert_eq!(res["success"], json!(true), "custom-list 应成功: {res}");
    assert!(
        res["data"]["entries"].is_array(),
        "data.entries 必须是数组: {res}"
    );
}

/// paths:save 负例：key 白名单外的写入必须在落盘前被拒。
/// 防的是：渲染层被注入后借路径通道往配置里塞任意键（配置面越权）。
#[test]
fn paths_save_rejects_unknown_key() {
    let w = main_window();
    let res = invoke(
        &w,
        "paths_save",
        json!({ "key": "__trim_smoke_key__", "value": "C:\\x" }),
    );
    assert_eq!(res["success"], json!(false), "白名单外 key 必须被拒: {res}");
}

/// 子窗档位通用式：guard_readonly 档命令从**每个**子窗 label 都应能越过档位
/// （以 settings_load 为载体；真数据断言在各模块自己的用例里）。
/// 防的是：M1~M3 那类「子窗专属通道被按 MAIN 校验锁死」的镜像缺陷——
/// 只读档降成主窗专属会让子窗功能 100% 不可用。
#[test]
fn readonly_channel_passes_guard_from_every_subwindow() {
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
    }
}

// ==================== 卸载残留链三道闸（M1 安全收口 2026-09-28） ====================
//
// 覆盖对象是**命令边界**而不是判定函数本身（判定函数的正反例在 lib 单测里由
// `tools/fixtures/residue-contract.json` 驱动）。这三条用例各自钉住一条顺序/形状，
// 都是零副作用（纯读或在任何删除动作之前整批拒绝）：
// - 残留扫描与残留执行是 `guard::MAIN` 档（唯一调用方是主窗卸载页），子窗必须被拒杀；
// - 执行侧的快照闸必须**先于**删除：受保护注册表容器在无快照时也要被整批拒绝，
//   这条防的是「把快照闸挪到删除之后」那类改动；
// - 扫描返回形状是渲染层直接 `.map` 的 `data.findings`，塌成 null 会让残留面板整片崩。

const GHOST_APP_ID: &str = r"HKLM|SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TrimNoSuch-9f3a";

#[test]
fn residue_scan_is_main_only_and_passes_guard_from_main() {
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "uninstall_residue_scan", json!({ "appId": GHOST_APP_ID }));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调残留扫描必须被来源校验拒杀，回执 {text}"
        );
    }
    let w = main_window();
    // 正向特征用「缺 | 分隔」的早退文案：它在档位之后、任何注册表读取之前，
    // 拿得到它就证明档位已越过（只断「不含拒杀」会被命令消失假绿穿透，v2-M16②）
    let res = invoke(&w, "uninstall_residue_scan", json!({ "appId": "no-separator" }));
    assert_eq!(res["success"], json!(false), "非法 app_id 必须失败: {res}");
    assert!(
        common::message_of(&res).contains("app_id 格式错误"),
        "主窗应越过档位进入命令体（期望读到格式错误早退），回执 {res}"
    );
}

/// 合法形状但不存在的卸载键 → 空集（不是报错），且 `findings` 必须是数组。
/// 这条同时是 A1 的反向保险：硬否决把候选丢掉之后，命令仍必须回一个合法空集，
/// 不许变成 `null` 或整条失败。
#[test]
fn residue_scan_unknown_key_returns_empty_findings_array() {
    let w = main_window();
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
/// （按 label 分槽、跨用例共享），万一将来有用例先往 main 槽写过快照，这些目标也不
/// 可能在里面；即便快照闸被改坏，A1 硬否决是第二道 —— 本用例永远不会真的删掉东西。
#[test]
fn residue_execute_requires_snapshot_before_any_delete() {
    const HOSTILE: &str = "HKLM\\SOFTWARE";
    const HOSTILE2: &str = "HKLM\\SYSTEM";
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(
            &w,
            "uninstall_residue_execute",
            json!({ "appId": GHOST_APP_ID, "targets": [{ "kind": "reg_key", "target": HOSTILE }] }),
        );
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调残留执行必须被来源校验拒杀，回执 {text}"
        );
    }
    let w = main_window();
    let res = invoke(
        &w,
        "uninstall_residue_execute",
        json!({
            "appId": GHOST_APP_ID,
            "targets": [
                { "kind": "reg_key", "target": HOSTILE },
                { "kind": "reg_key", "target": HOSTILE2 }
            ]
        }),
    );
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
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "uninstall_run", json!({ "appId": GHOST_APP_ID }));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调卸载命令必须被来源校验拒杀，回执 {text}"
        );
    }
    let w = main_window();
    let res = invoke(&w, "uninstall_run", json!({ "appId": GHOST_APP_ID }));
    assert_eq!(res["success"], json!(false), "不存在的卸载键不得假装成功: {res}");
    assert!(
        common::message_of(&res).contains("卸载注册表键不存在"),
        "主窗应越过档位进入「现读注册表」这一步，回执 {res}"
    );
}

/// A3 两条残留库更新命令都是 MAIN 档（唯一调用方是主窗卸载页）。
///
/// 快速组这里**只断子窗被拒杀**，不测主窗正向特征：这两条命令过了档位就要出网
/// （更新还会写数据目录），属 §4.1 纪律② 的「外呼/触盘」，正例落在
/// `cargo test --lib -- --ignored` 的 `residue_update_chain_verify`（只读不落盘）。
/// 子窗这条断言本身也能证明命令已注册：未注册时回执是「命令不存在」而不是来源校验失败。
#[test]
fn residue_rule_update_channels_are_main_only() {
    for cmd in ["uninstall_check_residue_version", "uninstall_update_residue_rules"] {
        for label in sub_windows() {
            let w = window_with_label(label);
            let text = invoke_text(&w, cmd, json!({}));
            assert!(
                text.contains("IPC 来源校验失败"),
                "{label} 窗调 {cmd} 必须被来源校验拒杀，回执 {text}"
            );
        }
    }
}

/// C2 两条应用数据遗留命令都是 MAIN 档（唯一调用方是主窗卸载页）。
///
/// 快速组里主窗正向特征只走 `orphan_ignore` 的参数校验早退路（格式错即返回，
/// 不 load/save 所有权档案，零副作用）；`orphan_scan` 会读档案并可能写回（升级/过期），
/// 且要逐目录读盘，正例只在下面的 `#[ignore]` 组里跑。
#[test]
fn orphan_channels_are_main_only() {
    for label in sub_windows() {
        let w = window_with_label(label);
        let scan = invoke_text(&w, "uninstall_orphan_scan", json!({}));
        assert!(
            scan.contains("IPC 来源校验失败"),
            "{label} 窗调应用数据遗留扫描必须被来源校验拒杀，回执 {scan}"
        );
        let ign = invoke_text(
            &w,
            "uninstall_orphan_ignore",
            json!({ "appId": "no-separator", "displayName": "x" }),
        );
        assert!(
            ign.contains("IPC 来源校验失败"),
            "{label} 窗调遗留忽略必须被拒杀，回执 {ign}"
        );
    }
    let w = main_window();
    let res = invoke(
        &w,
        "uninstall_orphan_ignore",
        json!({ "appId": "no-separator", "displayName": "Acme" }),
    );
    assert_eq!(res["success"], json!(false), "非法 appId 必须早退: {res}");
    assert!(
        common::message_of(&res).contains("app_id 格式错误"),
        "主窗应越过档位进入参数校验，回执 {res}"
    );
}

/// M5 D1：卸载域注册表备份的列表/还原两条通道都是 MAIN 档。
///
/// 还原会经 `reg import` 写注册表，所以档位是它的第一道闸，子窗一律拒杀。
/// 主窗正向特征刻意选两条**零副作用**路径：list 只读目录，restore 用越界文件名在
/// 参数校验处就早退（进不到封条判定、更进不到 reg.exe）。list 的形状也钉住：
/// 渲染层对 `data.backups` 直接 `.map`，塌成 null 会让备份弹窗整片崩。
#[test]
fn reg_backup_channels_are_main_only() {
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
    }

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

/// M6 失效残留扫描是 MAIN 档：它产出的注册表候选会进同一条删除链，
/// 子窗一律拒杀。正向特征放在下面的 `#[ignore]` 真机用例里（那条会断言 success 与
/// 四类候选的硬约束）；这里只断"拒杀"，因为命令本体要读注册表三根并枚举设备，
/// 不属于快速组的零副作用范围。
#[test]
fn dead_scan_channel_is_main_only() {
    for label in sub_windows() {
        let w = window_with_label(label);
        let text = invoke_text(&w, "uninstall_dead_scan", json!({}));
        assert!(
            text.contains("IPC 来源校验失败"),
            "{label} 窗调失效残留扫描必须被拒杀，回执 {text}"
        );
    }
}

/// 真机应用数据遗留扫描（`#[ignore]`）：先按**档案实际状态**决定断言哪条，两条路都要能钉红。
/// - 档案空 / 没有任何 historical → 必须**拒绝扫描并给出可读原因**，不许回空集
///   （空集会被读成「这台机器没有遗留数据」，那是把"不知道"伪装成"知道"）；
/// - 有 historical 且产出候选 → 断言候选形状与「一律不自动勾选、置信度封顶 medium、
///   不是受保护路径、带 ownerAppId」这四条硬约束。
#[test]
#[ignore = "逐目录读盘且依赖本机卸载记录，发布前门禁跑"]
fn orphan_scan_refuses_or_returns_unchecked_candidates() {
    use serde_json::Value;
    let w = main_window();
    let res = invoke(&w, "uninstall_orphan_scan", json!({}));
    // 自己读一遍档案判断"该不该有产出"，而不是靠回执猜
    let own = trim_tauri_lib::engine::paths::app_data_dir().join("uninstall-ownership.json");
    let has_historical = std::fs::read_to_string(&own)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|d| {
            d["owners"].as_array().map(|a| {
                a.iter()
                    .any(|o| o["state"].as_str() == Some("historical"))
            })
        })
        .unwrap_or(false);
    if !has_historical {
        assert_eq!(
            res["success"],
            json!(false),
            "没有已确认卸载完成的记录时不得回空集伪装「没有遗留数据」，实测 {res}"
        );
        let msg = common::message_of(&res);
        assert!(
            msg.contains("还没有卸载记录") || msg.contains("还没有已确认卸载完成") || msg.contains("获取失败"),
            "拒绝扫描必须给出可读原因，实测: {msg}"
        );
        println!("[orphan] 档案无 historical，按预期拒绝扫描：{msg}");
        return;
    }
    assert_eq!(res["success"], json!(true), "有 historical 时扫描应成功: {res}");
    let findings = res["data"]["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("data.findings 必须是数组: {res}"));
    for f in findings {
        assert_eq!(f["kind"], json!("folder"), "该组候选只给目录: {f}");
        assert_eq!(f["origin"], json!("orphan"), "候选要标明来源: {f}");
        assert_eq!(
            f["defaultChecked"],
            json!(false),
            "该组候选一律不得默认勾选: {f}"
        );
        assert!(
            f["confidence"] == json!("low") || f["confidence"] == json!("medium"),
            "该组候选置信度封顶 medium: {f}"
        );
        let t = f["target"].as_str().unwrap_or("");
        assert!(
            !trim_tauri_lib::engine::protect::is_path_protected(t),
            "该组候选不得是受保护路径: {t}"
        );
        assert!(
            !f["ownerAppId"].as_str().unwrap_or("").is_empty(),
            "忽略操作要靠 ownerAppId 寻址: {f}"
        );
    }
    println!("[orphan] 本机产出 {} 条候选（均未自动勾选）", findings.len());
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
    assert!(!sample.is_empty(), "本机没有桌面程序可采样，本用例失去意义");

    let mut checked = 0;
    for a in sample {
        let Some(app_id) = a["id"].as_str() else { continue };
        // 只测注册表寻址的桌面程序（APPX| 前缀走另一条口径）
        if !app_id.contains('|') || app_id.starts_with("APPX|") {
            continue;
        }
        let res = invoke(&w, "uninstall_residue_scan", json!({ "appId": app_id }));
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
            if f["kind"].as_str() == Some("reg_key") {
                let t = f["target"].as_str().unwrap_or("");
                assert!(
                    protect::reg_target_block_reason(t).is_none(),
                    "扫描侧硬闸漏放受保护目标 {t}（{app_id}）"
                );
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
    assert!(checked > 0, "样本里没有可用的注册表寻址程序");
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

/// M6 失效残留扫描（真机 `#[ignore]`）：四类候选都要能产出，且硬约束一条不许破。
///
/// 这条用例的存在理由是「结构收口把功能误杀」和「判定放宽到敢删东西」两个方向都会
/// 静默出问题：前者表现为注册表类候选为空（禁删面把 Uninstall 例外吃掉了），后者表现为
/// 出现 `confidence:"high"` 或 `deleteCapable` 与 kind 不匹配的条目。
/// 计数用 println 打出来，发布前门禁那一步人工过一眼量级是否合理。
///
/// 如实标注一处空转：本机没有失效卸载项/App Paths（实测 uninstall=0、appPaths=0、
/// service=2、device=61），所以「不自动勾选」「置信度不 high」这两条在本机只对服务与
/// 设备行生效；注册表类的同两条断言由 lib 单测非空转地钉住（破坏 defaultChecked 即判红）。
#[test]
#[ignore = "读注册表三根 + SetupAPI 枚举设备（秒级），发布前门禁跑"]
fn dead_scan_reports_four_classes_under_hard_constraints() {
    use trim_tauri_lib::engine::protect;
    let w = main_window();
    let res = invoke(&w, "uninstall_dead_scan", json!({}));
    assert_eq!(res["success"], json!(true), "扫描应成功: {res}");
    let findings = res["data"]["findings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut by_class: std::collections::HashMap<String, usize> = Default::default();
    for f in &findings {
        *by_class
            .entry(f["deadClass"].as_str().unwrap_or("?").to_string())
            .or_default() += 1;
        assert_eq!(f["origin"], json!("dead"), "候选必须标 origin=dead: {f}");
        assert_eq!(
            f["defaultChecked"],
            json!(false),
            "失效残留一律不自动勾选（落点缺失也可能是移动盘没插）: {f}"
        );
        let conf = f["confidence"].as_str().unwrap_or("");
        assert!(
            conf == "low" || conf == "medium",
            "本链置信度封顶 medium，high 会把'没插盘'说成'一定是残留': {f}"
        );
        let kind = f["kind"].as_str().unwrap_or("");
        if kind == "reg_key" {
            let t = f["target"].as_str().unwrap_or("");
            assert!(
                protect::reg_target_block_reason(t).is_none(),
                "可删候选被禁删面挡住 = 收口把功能误杀，目标 {t}"
            );
            assert_eq!(f["deleteCapable"], json!(true), "注册表类应给删除出口: {f}");
        } else {
            assert_eq!(
                f["deleteCapable"],
                json!(false),
                "服务/设备/说明行只展示，不开删除通道: {f}"
            );
        }
    }
    let counts: Vec<(&str, usize)> = vec![
        ("uninstall", *by_class.get("uninstall").unwrap_or(&0)),
        ("appPaths", *by_class.get("appPaths").unwrap_or(&0)),
        ("service", *by_class.get("service").unwrap_or(&0)),
        ("device", *by_class.get("device").unwrap_or(&0)),
    ];
    println!("失效残留四类计数: {counts:?} 总计 {}", findings.len());
    println!("说明行: {:?}", res["data"]["notes"]);
    assert!(
        counts.iter().any(|(_, n)| *n > 0),
        "本机四类候选全空，说明判定或采集链断了（真机上一台用过的 Windows 不可能四类皆空）"
    );
}

/// M6 图标第四源（真机 `#[ignore]`）：`shortcutPath` 是后端算好的，前端只按优先级尝试，
/// 所以这里钉三条 —— 字段形状（要么没有、要么是个真实存在的 .lnk）、至少有一行命中
/// （一台装过软件、桌面有快捷方式的机器全空 = 匹配或根目录断了）、以及它不越界
/// （只落在四个快捷方式根里，不指向任意路径）。
#[test]
#[ignore = "读桌面与开始菜单，发布前门禁跑"]
fn uninstall_list_rows_carry_resolvable_shortcuts() {
    let w = main_window();
    let res = invoke(&w, "uninstall_list", json!({ "scope": "user" }));
    assert_eq!(res["success"], json!(true), "列表应成功: {res}");
    let apps = res["data"]["apps"].as_array().cloned().unwrap_or_default();
    assert!(!apps.is_empty(), "本机应有已安装程序，否则这条用例证明不了什么");
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
    assert!(hit > 0, "全机没有任何一行匹配到快捷方式 = 索引或匹配链断了");
}
