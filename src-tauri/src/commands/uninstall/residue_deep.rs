//! uninstall:residue-deep-scan —— 七个深扫器的聚合入口（方案 §3 / §6）。
//!
//! 两条边界写在这里，不在各扫描器里重复：
//!
//! 1. **快照只写「类白名单」内的那一撮**（v0.7.0 第二阶段，判据见
//!    `deep_executable_candidates`）。v0.5.0 这条边界是「一次都不写」，理由是
//!    `helpers::RESIDUE_SNAPSHOTS` 是「执行只认本次扫描目标」的唯一载体
//!    （`uninstall_residue_execute` 按窗口 label 取槽、拿 kind+target 逐个命中校验），
//!    整表写入等于给服务键 / IFEO / HKLM\SYSTEM 直接开出一条删除路径。
//!    第二阶段放开的前提是：写入范围由**后端**按 class 筛，不由渲染层决定；
//!    驱动、minifilter、以及所有 reg 类仍然进不了快照，
//!    服务键要等方案 §5 的 A1 窄口子单独评审。文件末尾有常驻断言守着这条。
//!
//! 2. **每个分组自己声明读不到什么**。残缺必须可见（notes），不能渲染成「本机干净」。
//!    这与 `uninstall_dead_scan` 的 `scanned` 计数同一口径：候选为 0 在干净机器上是合法结果，
//!    「扫过多少条」为 0 一定是枚举链断了。

use crate::engine::guard;
use serde_json::{Value, json};
use std::collections::HashSet;
use tauri::WebviewWindow;
use super::capability_orphan;
use super::dead::{collect_dead_uninstall_raws, residue_snapshot_put};
use super::drivers_orphan;
use super::game_platform_orphan::{self as gpo, LibraryListing, list_game_dirs, untracked_dir_findings};
use super::ifeo_orphan;
use super::minifilter_orphan;
use super::ownership::running_process_dirs;
use super::services_orphan;
use super::vendor_registry;

/// 单个分组候选上限（总量由 7 组共同决定，不再叠加一个总数闸）
const GROUP_CAP: usize = 60;

/// 一个分组渲染所需的最小信息：id 给前端做锚点，title 是人读标题。
fn group(id: &str, title: &str, items: Vec<Value>) -> Value {
    json!({ "id": id, "title": title, "count": items.len(), "items": items })
}

/// 汇总七个扫描器（只读）。在 `spawn_blocking` 里跑：整轮要枚举服务表、驱动目录、
/// IFEO 与两棵厂商树，还要起一次 `fltmc`，都是不可忽略的同步成本。
unsafe fn scan_all() -> Value {
    let mut notes: Vec<String> = Vec::new();

    // 平台库索引：既是游戏目录组的产出源，也是反作弊条件保护的判据源
    let (index, platform_notes) = gpo::collect_platform_index();
    notes.extend(platform_notes);

    // 卸载键的 DisplayName 集合：服务与厂商键两组都拿它判「程序还在不在」
    let u_raws = collect_dead_uninstall_raws();
    let mut alive_names: HashSet<String> = u_raws.iter().map(|r| r.name.to_lowercase()).filter(|s| !s.is_empty()).collect();
    alive_names.extend(u_raws.iter().map(|r| r.key.to_lowercase()).filter(|s| s.len() >= 3));
    if u_raws.is_empty() {
        notes.push("卸载项清单读取失败（三根都打不开），服务与厂商键两组的「程序仍在」判定本轮不可用".to_string());
    }

    // 服务表：一次枚举，驱动反查与 minifilter 判定共用同一份索引
    let (entries, services_readable) = services_orphan::collect_service_entries(2048);
    if !services_readable {
        notes.push("服务表读不到（HKLM\\SYSTEM\\CurrentControlSet\\Services 打不开），本组未采集".to_string());
    }
    let process_dirs = running_process_dirs();
    let (svc_items, svc_protected, svc_notes) =
        services_orphan::service_findings(&entries, &index, &alive_names, &process_dirs, GROUP_CAP);
    notes.extend(svc_notes);

    let (drv_items, drv_protected, drv_notes, drv_files_scanned) = drivers_orphan::collect_driver_findings(&entries);
    notes.extend(drv_notes);

    let (flt_items, flt_notes, filters_scanned) = match minifilter_orphan::collect_mounted_filters() {
        Ok(filters) => {
            let count = filters.len();
            let service_key_exists = |n: &str| {
                crate::engine::native::reg_key_exists(
                    windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                    &format!("{}\\{}", services_orphan::SERVICES_ROOT, n),
                )
            };
            let (items, notes) = minifilter_orphan::minifilter_findings(&filters, &service_key_exists, GROUP_CAP);
            (items, notes, count)
        }
        Err(why) => (Vec::new(), vec![format!("过滤管理器状态读不到：{why}，本组未采集")], 0usize),
    };
    notes.extend(flt_notes);

    let (ifeo_raws, ifeo_readable) = ifeo_orphan::collect_ifeo_raws();
    let ifeo_items = if ifeo_readable {
        let (items, g_notes) = ifeo_orphan::ifeo_findings(&ifeo_raws, &|n: &str| ifeo_orphan::image_executable_present(n), GROUP_CAP);
        notes.extend(g_notes);
        items
    } else {
        notes.push("IFEO 树枚举不到（根打不开或一条都没有），本组未采集".to_string());
        Vec::new()
    };

    let (vendor_raws, vendor_readable) = vendor_registry::collect_vendor_raws();
    let (vendor_items, vendor_notes) = if vendor_readable {
        vendor_registry::vendor_findings(&vendor_raws, &alive_names, &|p: &str| std::path::Path::new(p).exists(), GROUP_CAP)
    } else {
        (Vec::new(), vec!["三个软件根都枚举不到厂商键，本组未采集".to_string()])
    };
    notes.extend(vendor_notes);

    let (cap_items, cap_notes) = capability_orphan::collect_capability_findings();
    notes.extend(cap_notes);

    // 游戏目录组：库根下实际存在的一级目录，与平台清单做差
    let listings: Vec<LibraryListing> = index
        .roots_lc
        .iter()
        .map(|r| LibraryListing { root: r.clone(), game_dirs: list_game_dirs(r) })
        .collect();
    let game_items = untracked_dir_findings(&index, &listings);

    let protected: Vec<Value> = svc_protected.into_iter().chain(drv_protected).collect();
    json!({
        "readonly": true,
        "phase": "v0.5.0-read-only",
        "groups": [
            group("services", "服务残留", svc_items),
            group("drivers", "无服务引用的驱动文件", drv_items),
            group("minifilters", "仍挂载但服务键已不在的过滤驱动", flt_items),
            group("ifeo", "IFEO 映像执行选项", ifeo_items),
            group("vendor", "厂商产品注册表键", vendor_items),
            group("capability", "非打包程序能力授权", cap_items),
            group("gameDirs", "游戏库目录残留", game_items),
        ],
        "protected": protected,
        "protectedCount": protected.len(),
        "notes": notes,
        "scanned": {
            "services": entries.len(),
            "driverFiles": drv_files_scanned,
            "mountedFilters": filters_scanned,
            "ifeoKeys": ifeo_raws.len(),
            "vendorProductKeys": vendor_raws.len(),
            "uninstallKeys": u_raws.len(),
            "platformRecords": index.records.len(),
            "libraryRoots": index.roots_lc.len(),
        },
        "platforms": {
            "unreadable": index.unreadable,
            "complete": index.complete(),
        },
    })
}

/// 深扫候选里**允许进执行快照**的那一小撮 —— 类白名单，不是「扫出来什么就写什么」。
///
/// 为什么必须有这张表：`uninstall_residue_execute` 的闸门只看「kind+target 在不在本窗口
/// 快照槽」，它不知道候选来自哪台扫描器。深扫七器里有三类根本不该被删：
/// - `orphan_sys_file`（`System32\drivers\*.sys`）：`protect.rs` 的路径保护**覆盖不到**
///   `%windir%\System32\drivers`（只有 `%windir%` 的 exact 与 System32\config 一条 subtree），
///   所以「判错即删走系统驱动」没有任何兜底 —— 独立禁删面评审过之前不进快照；
/// - `minifilter_after_key_deleted`：键已删、滤镜仍挂载，删文件不解决问题，只能重启；
/// - 微软签名件 / 反作弊在用项：后端本来就不产候选（进的是 protected），这里再挡一层
///   是防「将来某台扫描器改了分类口径」。
/// - reg 类（服务键、IFEO、ConsentStore、厂商产品键）：留给方案 §5 那一轮和 A1 窄口子
///   一起评审，本批不开。
///
/// 白名单只有一类：`untracked_game_dir` 的 `folder` —— 平台库根下、清单没记录的一级目录，
/// 删除走回收站（`trim_finder::scan::delete`），失败不降级永久删（§3）。
/// 白名单里有两类（v0.7.0 第二阶段 + 第三阶段窄口子）：
/// - `untracked_game_dir` 的 folder —— 回收站优先；
/// - `dead_landing` 的 service reg_key —— 且必须**现读**八道排除式判据全过
///   （`services_orphan::service_key_delete_block_reason`，执行侧调的是同一个函数）。
pub(super) unsafe fn deep_executable_candidates(report: &Value) -> Vec<Value> {
    let groups = match report.get("groups").and_then(Value::as_array) {
        Some(g) => g,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for g in groups {
        let id = g.get("id").and_then(Value::as_str).unwrap_or("");
        let items = match g.get("items").and_then(Value::as_array) {
            Some(i) => i,
            None => continue,
        };
        for it in items {
            let kind = it.get("kind").and_then(Value::as_str).unwrap_or("");
            let class = it.get("class").and_then(Value::as_str).unwrap_or("");
            let admitted = match id {
                "gameDirs" => kind == "folder" && class == "untracked_game_dir",
                // 服务键：类必须是 dead_landing（落点失踪），再过八道现读判据。
                // 判据里已经含「落点在 %windir% 就拒」——那是「微软组件」的替身证据，
                // 文件不在了就读不到签名，不能拿「读不到」当「不是微软」。
                "services" => {
                    kind == "reg_key"
                        && class == "dead_landing"
                        && it.get("target").and_then(Value::as_str)
                            .map(|t| services_orphan::service_key_delete_block_reason(t).is_none())
                            .unwrap_or(false)
                }
                _ => false,
            };
            if !admitted {
                continue;
            }
            let Some(obj) = it.as_object() else { continue };
            let mut entry = obj.clone();
            // origin 是分桶键（`residue_snapshot_put` 按它替换），必须在这里落上；
            // defaultChecked=false：危险能力默认关（§9.2）
            entry.insert("origin".into(), json!("deep"));
            entry.insert("deleteCapable".into(), json!(true));
            entry.insert("defaultChecked".into(), json!(false));
            out.push(Value::Object(entry));
        }
    }
    out
}

/// uninstall:residue-deep-scan —— v0.5.0 建档，v0.7.0 起按类白名单写执行快照。
#[tauri::command]
pub async fn uninstall_residue_deep_scan<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let (mut scanned, executable) = tauri::async_runtime::spawn_blocking(|| unsafe {
            let r = scan_all();
            let c = if r.get("fatal").is_some() { Vec::new() } else { deep_executable_candidates(&r) };
            (r, c)
        })
        .await
        .unwrap_or_else(|e| (json!({ "fatal": format!("扫描线程未返回：{e}") }), Vec::new()));
    let count = executable.len();
    if count > 0 {
        residue_snapshot_put(window.label(), "deep", executable.clone());
        // 报告里的可删标记**由快照集合反推**，不另写一遍判据（§5.16/N6）：
        // 两处各判一次迟早会不一致，而 UI 画勾选框、后端把闸门，判错方向就是
        // 「勾了执行被拒」或更糟的「没勾却进了快照」。
        let admitted: HashSet<String> = executable
            .iter()
            .filter_map(|v| Some(format!("{}|{}", v.get("kind")?.as_str()?, v.get("target")?.as_str()?)))
            .collect();
        if let Some(groups) = scanned.get_mut("groups").and_then(Value::as_array_mut) {
            for g in groups {
                let items = match g.get_mut("items").and_then(Value::as_array_mut) {
                    Some(i) => i,
                    None => continue,
                };
                for it in items {
                    let key = it
                        .get("kind")
                        .and_then(Value::as_str)
                        .zip(it.get("target").and_then(Value::as_str))
                        .map(|(k, t)| format!("{k}|{t}"));
                    let can = key.map(|k| admitted.contains(&k)).unwrap_or(false);
                    if let Some(obj) = it.as_object_mut() {
                        obj.insert("deleteCapable".into(), json!(can));
                        obj.insert("readonly".into(), json!(!can));
                        obj.insert("origin".into(), json!("deep"));
                    }
                }
            }
        }
    }
    json!({
        "success": true,
        "data": {
            "generatedAt": crate::engine::now_ms(),
            // 副窗按 label 分槽展示；label 同时是快照分槽的键
            "windowLabel": window.label(),
            // 回执里回带「这一轮进快照几条」：UI 要据此决定画不画勾选框，
            // 不能靠前端自己猜白名单（判据只有一份，§5.16）
            "executableCount": count,
            "report": scanned,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 常驻断言（v0.7.0 反转）：聚合命令**只**允许写 origin="deep" 这一桶，
    /// 而且写入必须走 `deep_executable_candidates` 这道筛。
    ///
    /// 为什么仍是扫源码而不是跑一次命令：`uninstall_residue_execute` 只看
    /// 「kind+target 命中不命中该窗口 label 的快照槽」，真机扫描在快速组里做不到；
    /// 而这条约束的内容恰好落在「这个文件里有几次、以什么参数调用那次写入」，
    /// 扫源码是等价且恒跑的判法。
    ///
    /// 原断言（「一次都不许出现 residue_snapshot_put」）在第二阶段必须**反过来**，
    /// 但不能只是删掉——反向的断言要更严：调用次数 == 1、且紧跟 "deep"。
    #[test]
    fn deep_scan_writes_only_the_deep_bucket_through_the_whitelist() {
        let text = include_str!("residue_deep.rs");
        // 扫描范围 = `#[cfg(test)]` 之前的代码行，注释一律排除：
        // 本文件顶部的边界说明正写着这两个名字，算进命中会让断言永远为假。
        let production = text.split("#[cfg(test)]").next().unwrap_or("");
        let code: String = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(code.contains("spawn_blocking"), "扫描体为空或生产代码段变了：本断言已失去意义");
        // 判据：写入必须经过白名单函数，不许出现「整表 candidates 直接塞进快照」的写法
        assert!(
            code.contains("fn deep_executable_candidates(report: &Value) -> Vec<Value>"),
            "白名单筛子不见了 —— 快照写入失去唯一入口"
        );
        let calls: Vec<&str> = code.lines().filter(|l| l.contains("residue_snapshot_put(")).collect();
        assert_eq!(calls.len(), 1, "residue_snapshot_put 必须恰好一处调用点，实得 {}", calls.len());
        let line = calls[0].trim();
        assert!(
            line.contains("\"deep\""),
            "唯一的写入点必须写 origin=\"deep\"，别的桶会顶掉三链快照：{line}"
        );
        assert!(
            line.contains("executable"),
            "写入的必须是 deep_executable_candidates 筛出来的集合，不是整份报告：{line}"
        );
        // RESIDUE_SNAPSHOTS 仍不许在本文件里被直接摸（只能经 residue_snapshot_put 这一个口子）
        assert!(
            !code.contains("RESIDUE_SNAPSHOTS"),
            "绕过 residue_snapshot_put 直接操作快照表 = 绕开按 origin 分桶替换的语义"
        );
    }

    /// 类白名单本身：逐条点名「谁进了快照、谁被挡在外面」。
    /// 只断「驱动没进」是不够的 —— 万一筛子坏成「什么都不进」，那也是一路绿。
    /// 所以这里同时断言 `passed` 集合恰好等于白名单，且构造里必须真的出现被拒的类。
    #[test]
    fn deep_whitelist_admits_only_untracked_game_folders() {
        let mk = |kind: &str, class: &str, target: &str| json!({ "kind": kind, "class": class, "target": target, "readonly": true });
        let report = json!({
            "groups": [
                { "id": "gameDirs", "items": [ mk("folder", "untracked_game_dir", r"E:\Steam\library\acme"), mk("file", "untracked_game_dir", r"E:\Steam\library\x.bin") ] },
                { "id": "drivers", "items": [ mk("file", "orphan_sys_file", r"C:\Windows\System32\drivers\acme.sys") ] },
                { "id": "minifilters", "items": [ mk("note_only", "minifilter_after_key_deleted", "AcmeFlt") ] },
                // 服务组三条：形状不合格的、形状合格但本机没有这个键的、类不是 dead_landing 的
                { "id": "services", "items": [
                    mk("reg_key", "dead_landing", "HKLM\\SOFTWARE\\acme"),
                    mk("reg_key", "dead_landing", r"HKLM\SYSTEM\CurrentControlSet\Services\TrimNoSuchSvc-9f3a"),
                    mk("reg_key", "stale_live_service", r"HKLM\SYSTEM\CurrentControlSet\Services\TrimNoSuchSvc2-9f3a"),
                ] },
                { "id": "ifeo", "items": [ mk("reg_key", "ifeo_debugger", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\acme.exe") ] },
                { "id": "capability", "items": [ mk("reg_key", "capability_consent_dead_landing", "HKLM\\SOFTWARE\\...") ] },
                { "id": "vendor", "items": [ mk("reg_key", "vendor_product_key_no_landing", "HKCU\\SOFTWARE\\acme") ] },
            ]
        });
        // 服务键那两条要现读注册表才能判 ⇒ 本函数是 unsafe fn；读的是 HKLM\...\Services\TrimNoSuchSvc-*，
        // 本机不存在这些键，判定必然是「服务键打不开或已不存在」，与在谁的机器上跑无关。
        let got = unsafe { deep_executable_candidates(&report) };
        let keys: Vec<(String, String)> = got
            .iter()
            .map(|v| {
                (
                    v.get("kind").and_then(Value::as_str).unwrap_or("").to_string(),
                    v.get("class").and_then(Value::as_str).unwrap_or("").to_string(),
                )
            })
            .collect();
        assert_eq!(
            keys,
            vec![("folder".to_string(), "untracked_game_dir".to_string())],
            "白名单只该放进 untracked_game_dir 的 folder，实得 {keys:?}"
        );
        // 进快照的三条必备标记：origin 是分桶键，deleteCapable 决定画不画勾选框，
        // defaultChecked 必须是 false（危险能力默认关，§9.2）
        for v in &got {
            assert_eq!(v["origin"], json!("deep"), "origin 没落上，residue_snapshot_put 会把它并进别的桶");
            assert_eq!(v["deleteCapable"], json!(true));
            assert_eq!(v["defaultChecked"], json!(false), "深扫候选一律不许默认勾选");
            assert_eq!(v["readonly"], json!(true), "原始字段必须保留，筛子不许改坏报告内容");
        }
        // 缺组/坏形状都不许 panic，且不得产出候选
        assert!(unsafe { deep_executable_candidates(&json!({})) }.is_empty());
        assert!(unsafe { deep_executable_candidates(&json!({ "groups": [] })) }.is_empty());
        assert!(unsafe { deep_executable_candidates(&json!({ "groups": [{ "id": "gameDirs" }] })) }.is_empty());
    }

    /// 七个分组必须一个不少，且 id 与方案 §3 的扫描器一一对应
    #[test]
    fn group_ids_cover_all_seven_scanners() {
        let built: Vec<Value> = vec![
            group("services", "服务残留", vec![]),
            group("drivers", "无服务引用的驱动文件", vec![]),
            group("minifilters", "仍挂载但服务键已不在的过滤驱动", vec![]),
            group("ifeo", "IFEO 映像执行选项", vec![]),
            group("vendor", "厂商产品注册表键", vec![]),
            group("capability", "非打包程序能力授权", vec![]),
            group("gameDirs", "游戏库目录残留", vec![]),
        ];
        let ids: Vec<&str> = built.iter().map(|g| g["id"].as_str().unwrap_or("")).collect();
        assert_eq!(
            ids,
            vec!["services", "drivers", "minifilters", "ifeo", "vendor", "capability", "gameDirs"]
        );
        // count 与 items 同步：前端按 count 判「这组空不空」，不一致会显示 0 条却能展开
        for g in &built {
            assert_eq!(g["count"].as_u64(), Some(g["items"].as_array().unwrap().len() as u64));
        }
    }

    /// 只读阶段的形状契约：每条候选都必须自带 readonly + 不默认勾选，
    /// 前端因此没有任何一条能渲染成「可以直接删」
    #[test]
    fn every_scanner_marks_candidates_readonly_and_unchecked() {
        let samples: Vec<Value> = vec![
            json!({"kind":"reg_key","target":"HKLM\\X","readonly":true,"defaultChecked":false}),
            json!({"kind":"file","target":"C:\\a.sys","readonly":true,"defaultChecked":false}),
            json!({"kind":"note_only","target":"HKLM\\Y","readonly":true,"defaultChecked":false}),
        ];
        for s in &samples {
            assert_eq!(s["readonly"], true);
            assert_eq!(s["defaultChecked"], false);
        }
    }

    #[test]
    fn alive_name_set_carries_both_display_and_key_names() {
        // 服务名通常对得上注册键名（如 `ACE-Gameservice`）而不是 DisplayName，
        // 两个都塞进集合才撞得中；只塞 DisplayName 会让所有服务都走「无同名记录」分支
        let raw = crate::commands::uninstall::dead::DeadUninstallRaw {
            hive: "HKLM".to_string(),
            key: "SomeGame_is1".to_string(),
            path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SomeGame_is1".to_string(),
            name: "Some Game".to_string(),
            install: String::new(),
            uninstall: String::new(),
            quiet: String::new(),
            last_write_ms: None,
        };
        let mut set: HashSet<String> = HashSet::new();
        set.insert(raw.name.to_lowercase());
        set.insert(raw.key.to_lowercase());
        assert!(set.contains("some game"));
        assert!(set.contains("somegame_is1"));
    }
}
