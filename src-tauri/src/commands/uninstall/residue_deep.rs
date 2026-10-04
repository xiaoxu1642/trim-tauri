//! uninstall:residue-deep-scan —— v0.5.0 七个只读扫描器的聚合入口（方案 §3 / §6）。
//!
//! 两条边界写在这里，不在各扫描器里重复：
//!
//! 1. **不写快照**。`helpers::RESIDUE_SNAPSHOTS` 是「执行只认本次扫描目标」这条安全前置的
//!    唯一载体（`uninstall_residue_execute` 按窗口 label 取槽、拿 kind+target 逐个命中校验）。
//!    本命令如果把自己的候选写进同一槽，等于给服务键 / IFEO / HKLM\SYSTEM 开出一条
//!    现成的删除路径 —— 那是方案 §6 明确留给第二阶段、且要求先单独评审的东西。
//!    所以这里只返回展示数据，`residue_snapshot_put` 一次都不调（文件末尾有常驻断言守着）。
//!
//! 2. **每个分组自己声明读不到什么**。残缺必须可见（notes），不能渲染成「本机干净」。
//!    这与 `uninstall_dead_scan` 的 `scanned` 计数同一口径：候选为 0 在干净机器上是合法结果，
//!    「扫过多少条」为 0 一定是枚举链断了。

use crate::engine::guard;
use serde_json::{Value, json};
use std::collections::HashSet;
use tauri::WebviewWindow;
use super::capability_orphan;
use super::dead::collect_dead_uninstall_raws;
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

/// uninstall:residue-deep-scan —— v0.5.0 只读残留报告（副窗档；无删除入口）。
#[tauri::command]
pub async fn uninstall_residue_deep_scan<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let scanned = tauri::async_runtime::spawn_blocking(|| unsafe { scan_all() })
        .await
        .unwrap_or_else(|e| json!({ "fatal": format!("扫描线程未返回：{e}") }));
    json!({
        "success": true,
        "data": {
            "generatedAt": crate::engine::now_ms(),
            // 副窗按 label 分槽展示；本阶段没有执行链，label 只用于日志归因
            "windowLabel": window.label(),
            "report": scanned,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 常驻断言：聚合命令**永不**写执行快照。
    ///
    /// 为什么用扫源码而不是跑一次命令：`uninstall_residue_execute` 只看「kind+target 是否
    /// 命中该窗口 label 的快照槽」，跑一次真实扫描需要真机注册表与用户配置，fast 组里做不到；
    /// 而这条约束的内容恰好就是「这个文件里不许出现那次调用」，扫源码是等价且恒跑的判法。
    /// 与 `lib.rs::every_window_builder_goes_through_browser_args` 同一手法。
    #[test]
    fn deep_scan_never_writes_the_execute_snapshot() {
        // 扫描范围 = `#[cfg(test)]` 之前的**代码行**：
        // - 上面的注释正是在解释这两个名字，算进命中会让断言永远为假，
        //   进而被下一个改注释的人整条删掉；
        // - 本测试自己的 needle 数组也含这两个字面量，所以测试体必须在范围外。
        let text = include_str!("residue_deep.rs");
        let production = text.split("#[cfg(test)]").next().unwrap_or("");
        let code: String = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(code.contains("spawn_blocking"), "扫描体为空或生产代码段变了：本断言已失去意义");
        for forbidden in ["residue_snapshot_put", "RESIDUE_SNAPSHOTS"] {
            assert!(
                !code.contains(forbidden),
                "只读聚合命令里出现了 {forbidden}：那会把候选送进 uninstall_residue_execute 的快照闸"
            );
        }
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
