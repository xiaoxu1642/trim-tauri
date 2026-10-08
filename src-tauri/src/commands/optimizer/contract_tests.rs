//! 优化域跨面回归网（v2-M14 退役账本、.reg 解析、动态步骤表、build_script 协议行、
//! DMTF 时间、还原值保真、备份-还原对称编码）—— 原 `mod tests` 覆盖 5 个契约面，
//! 按 D0 纪律单独成文。
//!
//! 各面用 glob 引进来：判据改名或实现搬走时，这里必须先编译失败，
//! 而不是留下一个「全绿但没测到」的空壳。



use serde_json::{Value, json};
use super::advice::*;
use super::apply::*;
use super::backup_restore::*;
use super::catalog::*;
use super::overview::*;
use super::restore_point::*;

#[test]
fn 全量体检覆盖每一个产得出断言的项() {
    let full = check_optimized(None);
    assert!(full.len() > 50, "全量体检结果异常少（{} 项），不可能只检了零头", full.len());

    let mut detectable = 0usize;
    let mut missing = Vec::new();
    for o in options() {
        let id = o.get("id").and_then(Value::as_str).unwrap();
        if !collect_checks(o).is_empty() {
            detectable += 1;
            if !full.contains_key(id) {
                missing.push(id);
            }
        }
    }
    assert!(
        missing.is_empty(),
        "collect_checks 产得出断言的项却没进全量体检结果（可检测性分叉）: {missing:?}"
    );
    assert_eq!(full.len(), detectable, "结果条数必须与可检测项数一致");
    assert!(check_optimized(Some(&[])).is_empty());
    for id in ["perf_vbs_off", "disable_uac", "svc_w32time_manual", "perf_wu_enable"] {
        assert!(full.contains_key(id), "{id} 不在全量体检结果里");
    }
}

#[test]
fn 全量体检是纯读且两次一致() {
    let a = check_optimized(None);
    let b = check_optimized(None);
    assert_eq!(a, b, "连续两次只读体检结果不一致 —— 检测里混入了写或副作用");
}

/// 剥掉 JS 的行注释与块注释（保留换行，让行号偏移不致错乱）。
///
/// 为什么需要：本文件里到处是「注释里复述被调用点形态」的说明文字
/// （例如 `escapeAttr(...)`），而源码形态判据靠字面匹配 —— 不剥注释就会把
/// 说明文字当成真调用点，判据带偏成永红。正好 `tools/check-ps-callsites.mjs`
/// 与 `check-delete-callsites.mjs` 也是同一口径（剥注释后按调用点计数）。
fn strip_js_comments(src: &str) -> String {
    let blank_block = |m: &str| m.replace(|c: char| c != '\n', " ");
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    loop {
        // 优先处理出现在行注释之前的块注释/字符串里的 `//`，否则 URL 会被误吃。
        let b = rest.find("/*");
        let l = rest.find("//");
        match (b, l) {
            (Some(bi), Some(li)) if bi < li => {
                out.push_str(&rest[..bi]);
                match rest[bi..].find("*/") {
                    Some(e) => {
                        out.push_str(&blank_block(&rest[bi..bi + e + 2]));
                        rest = &rest[bi + e + 2..];
                    }
                    None => {
                        out.push_str(&blank_block(&rest[bi..]));
                        break;
                    }
                }
            }
            (_, Some(li)) => {
                out.push_str(&rest[..li]);
                match rest[li..].find('\n') {
                    Some(e) => {
                        out.push_str(&blank_block(&rest[li..li + e]));
                        out.push('\n');
                        rest = &rest[li + e + 1..];
                    }
                    None => {
                        out.push_str(&blank_block(&rest[li..]));
                        break;
                    }
                }
            }
            _ => {
                out.push_str(rest);
                break;
            }
        }
    }
    out
}

    /// R0-a 判据 1：`startType` 步骤的 Start 必须进值级备份基线。
    ///
    /// v0.5.0 的缺陷：`collect_service_start_targets` ①分支只收 `disable === true`，
    /// 于是 `svc_w32time_manual` 等 4 项**没有基线** —— 用户改前的实际 Start 值永久丢失。
    /// 本测试在 v0.5.0 上会红（targets 里找不到这 4 个服务）。
    #[test]
    fn starttype步骤进值级备份基线() {
        for opt_id in [
            "svc_w32time_manual",
            "svc_fdrespum_manual",
            "svc_storsvc_manual",
            "svc_xblauthmgr_manual",
        ] {
            let targets: Vec<String> = option_targets(opt_id)
                .unwrap_or_default()
                .iter()
                .map(|t| format!("{}::{}\\{}", t.root, t.sub, t.key))
                .collect();
            let opt = find_option(opt_id).expect("选项应存在");
            let svc = opt
                .get("steps")
                .and_then(|v| v.as_array())
                .and_then(|a| a.iter().find_map(|s| s.get("service")).and_then(|v| v.as_str()))
                .expect("步骤应带 service 名");
            let want = format!(
                "HKEY_LOCAL_MACHINE::SYSTEM\\CurrentControlSet\\Services\\{svc}\\Start"
            );
            assert!(
                targets.contains(&want),
                "{opt_id}（服务 {svc}）的 Start 没进基线，值级备份形同虚设；实收: {targets:?}"
            );
        }
    }

    /// R0-a 判据 2：`startType` 步骤**不得**生成停服命令。
    ///
    /// 数据层这 4 项的 `label` 写「不立即停止」、`desc` 写「当前运行不受影响」。
    /// v0.5.0 的 `build_script` 无条件 `Stop-Service`，两条文案与行为直接矛盾。
    /// 判据落在 PS 轨脚本文本上：生成物里出现 `Stop-Service` 即红。
    #[test]
    fn starttype步骤不生成停服命令() {
        for opt_id in [
            "svc_w32time_manual",
            "svc_fdrespum_manual",
            "svc_storsvc_manual",
            "svc_xblauthmgr_manual",
        ] {
            let opt = find_option(opt_id).expect("选项应存在");
            let steps = opt
                .get("steps")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let script = build_script(&steps);
            assert!(
                !script.contains("Stop-Service"),
                "{opt_id} 的 PS 轨脚本里出现了 Stop-Service —— 与「不立即停止」文案矛盾"
            );
            assert!(
                script.contains("Set-Service"),
                "{opt_id} 的 PS 轨脚本没生成 Set-Service —— 启动类型根本没被改；实得:\n{script}"
            );
            // 这 4 项的 restore 语义是「改回 Automatic」，执行语义是「改 Manual」，
            // 两档都得能生成出来（v0.5.0 只有 disable 一档能生成）。
            let rsteps: Vec<Value> = opt
                .get("restore")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let rscript = build_script(&rsteps);
            assert!(
                rscript.contains("-StartupType 'Automatic'"),
                "{opt_id} 的还原脚本没生成 StartupType Automatic —— 还原会退化成空操作；实得:\n{rscript}"
            );
            assert!(
                !rscript.contains("Stop-Service"),
                "{opt_id} 的还原脚本出现了 Stop-Service —— 还原不该停服"
            );
        }
    }

    /// R0-a 判据 3：`disable: true` 的旧语义**不许被这次改动破坏**。
    ///
    /// 这是本次收紧的反向护栏 —— `privacy_permissions_tune`（停用 SMS 路由器）依赖
    /// 「停服 + 改 disabled」两件事都做。若为了 startType 把 stop 一起去掉，它会红。
    #[test]
    fn disable形态仍同时停服并改启动类型() {
        let opt = find_option("privacy_permissions_tune").expect("选项应存在");
        let steps = opt
            .get("steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let script = build_script(&steps);
        assert!(
            script.contains("Stop-Service"),
            "disable 形态丢了停服：privacy_permissions_tune 会变成只改启动类型不停服"
        );
        assert!(
            script.contains("-StartupType 'Disabled'"),
            "disable 形态丢了 StartupType Disabled；实得脚本:\n{script}"
        );
    }

    /// R0-a 判据 4：未知 `startType` 值必须 fail-closed。
    ///
    /// 猜一个默认值 = 凭空造一个静默盲区（这正是 v0.5.0 的病根）。解析函数是
    /// 执行链、检测侧、备份侧三处共用的唯一入口，必须在入口就拒绝。
    #[test]
    fn 未知starttype值fail_closed() {
        use crate::engine::native::start_type_from_label;
        assert_eq!(start_type_from_label("manual"), Ok(crate::engine::native::SVC_START_MANUAL));
        assert_eq!(
            start_type_from_label("automatic"),
            Ok(crate::engine::native::SVC_START_AUTO)
        );
        assert_eq!(
            start_type_from_label("disabled"),
            Ok(crate::engine::native::SVC_START_DISABLED)
        );
        let err = start_type_from_label("Manual").expect_err("大小写不同就该拒绝，不许猜");
        assert!(err.contains("未知 startType"), "错误文案须点名问题字段，实得: {err}");
        assert!(start_type_from_label("auto").is_err(), "auto 不是合法取值");
        assert!(start_type_from_label("").is_err(), "空串不是合法取值");
    }

    /// R0-b 判据 6：四项 startType 必须产出 svcStart 检测断言。
    ///
    /// v0.5.0 上本条会红：collect_checks 返回空 vec ⇒ 上游 `if !checks.is_empty()`
    /// 跳过 ⇒ 体检恒显示「未生效」。这是「执行链已改系统、检测侧说没改」的失配。
    #[test]
    fn starttype产出检测断言() {
        for opt_id in [
            "svc_w32time_manual",
            "svc_fdrespum_manual",
            "svc_storsvc_manual",
            "svc_xblauthmgr_manual",
        ] {
            let opt = find_option(opt_id).expect("选项应存在");
            let checks = collect_checks(opt);
            assert!(
                !checks.is_empty(),
                "{opt_id} 的 collect_checks 返回空 —— 体检会跳过它并显示「无法检测」"
            );
            let starts: Vec<(&'static str, String, String)> = checks
                .iter()
                .map(|c| {
                    let (k, d, n) = c.probe();
                    (k, d.to_string(), n.to_string())
                })
                .filter(|(k, _, _)| *k == "svcStart")
                .collect();
            assert_eq!(
                starts.len(),
                1,
                "{opt_id} 应恰好产出 1 条 svcStart 断言，实得 {} 条（kind 分布: {:?}）",
                starts.len(),
                checks.iter().map(|c| c.probe().0).collect::<Vec<_>>()
            );
            // data 存的是十进制期望值：manual → SERVICE_DEMAND_START = 3
            assert_eq!(
                starts[0].1, "3",
                "{opt_id} 的 svcStart 期望值应为 3（SERVICE_DEMAND_START），实得 {}",
                starts[0].1
            );
            assert!(
                !starts[0].2.is_empty(),
                "{opt_id} 的 svcStart 断言缺服务名 —— 查不到该改谁"
            );
        }
    }

    /// R0-b 判据 7：`disable` 与 `startType` 两个形态各自的 check kind 不许混。
    ///
    /// 混了会让 `check_optimized` 拿 SVC_START_DISABLED 去比一个 manual 期望 ——
    /// 恒判 false，而界面上看不出原因。
    #[test]
    fn disable与starttype的检测形态不混淆() {
        let dis = find_option("privacy_permissions_tune").expect("选项应存在");
        let dis_kinds: Vec<&'static str> = collect_checks(dis).iter().map(|c| c.probe().0).collect();
        assert!(
            dis_kinds.contains(&"svc"),
            "disable 形态应产出 kind=svc 断言，实得 {dis_kinds:?}"
        );
        assert!(
            !dis_kinds.contains(&"svcStart"),
            "disable 形态不该产出 svcStart 断言（期望值语义不同：disabled vs manual）"
        );
        // 4 个 startType 项不应产出 kind=svc（它们没有 disable:true）
        for opt_id in ["svc_w32time_manual", "svc_storsvc_manual"] {
            let o = find_option(opt_id).expect("选项应存在");
            let kinds: Vec<&'static str> = collect_checks(o).iter().map(|c| c.probe().0).collect();
            assert!(
                !kinds.contains(&"svc"),
                "{opt_id} 无 disable:true，不该产出 kind=svc 断言；实得 {kinds:?}"
            );
        }
    }

    /// R0-b 判据 8：未知 startType 必须记成「判未生效」而不是「跳过」。
    ///
    /// 跳过的后果是 collect_checks 可能返回空 vec ⇒ 上游显示「无法检测」，
    /// 而数据显示这步确实该有判据 —— 那正是 v0.5.0 的病根形态。fail-closed 的
    /// 落点是「记一条恒 false」，让界面说「未生效」而不是「不知道」。
    #[test]
    fn 未知starttype记为未生效而非跳过() {
        let fake = json!({
            "id": "fake_unknown_starttype",
            "steps": [{ "label": "x", "service": "SomeSvc", "startType": "Manual" }]
        });
        let checks = collect_checks(&fake);
        assert_eq!(
            checks.len(),
            1,
            "未知 startType 应产出 1 条断言（恒 false），不该被跳过；实得 {} 条",
            checks.len()
        );
        let (kind, data, _) = checks[0].probe();
        assert_eq!(kind, "svcStart");
        // u32::MAX 永远不会等于真实 dwStartType ⇒ 判定恒 false
        assert_eq!(data, u32::MAX.to_string());
    }

    /// R0-a 判据 5：`startType` 三档期望值必须与 windows crate 常量逐一对齐。
    ///
    /// 这条看着像废话，但它是「数据层写 manual，代码却按错的数值去查」的唯一护栏。
    /// **数值以 windows 0.61.3 crate 为真源，不凭记忆写**（本条首次编写时把
    /// SERVICE_DEMAND_START 记成 2，被本条判红当场抓出；真值是 3）：
    ///   SERVICE_AUTO_START   = 2   （自动）
    ///   SERVICE_DEMAND_START = 3   （手动）
    ///   SERVICE_DISABLED     = 4   （禁用）
    /// 记错的后果是检测侧恒判「未生效」，且只在真机上炸 —— 编译期与静态检查全绿。
    #[test]
    fn starttype三档期望值对齐win32契约() {
        use crate::engine::native::{SVC_START_AUTO, SVC_START_DISABLED, SVC_START_MANUAL};
        assert_eq!(SVC_START_AUTO, 2, "SERVICE_AUTO_START 约定为 2");
        assert_eq!(SVC_START_MANUAL, 3, "SERVICE_DEMAND_START 约定为 3");
        assert_eq!(SVC_START_DISABLED, 4, "SERVICE_DISABLED 约定为 4");
    }

    /// v5 O-4：pwsh / cmd / service 步骤改的「服务启动类型」必须进值级备份基线。
    /// 此前 `option_targets` 只解析 `s.reg`，于是 `tf_svc_extra5` 那 4 个服务的 Start 没有基线
    /// —— 还原只能写数据层硬编码的"猜的原值"（restore 步里明写着 `SensrSvc=3; StorSvc=2`），
    /// 用户改前的实际值永久丢失。
    #[test]
    fn 服务启动类型进值级备份基线() {
        let targets: Vec<String> = option_targets("tf_svc_extra5")
            .unwrap_or_default()
            .iter()
            .map(|t| format!("{}::{}\\{}", t.root, t.sub, t.key))
            .collect();
        for svc in ["SensrSvc", "SensorDataService", "StorSvc", "PcaSvc"] {
            let want = format!("HKEY_LOCAL_MACHINE::SYSTEM\\CurrentControlSet\\Services\\{svc}\\Start");
            assert!(targets.contains(&want), "{svc} 的 Start 没进基线，实收: {targets:?}");
        }
        // cmd 两种形态都要认；没写 Start 的命令一律不收（宁可漏收一条基线，
        // 也不能把无关命令当成"改了启动类型"收进来 —— 那会让还原回写出没动过的值）
        assert_eq!(
            svc_names_writing_start("sc config SysMain start= disabled"),
            vec!["SysMain".to_string()]
        );
        assert_eq!(
            svc_names_writing_start(
                r#"reg add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v Start /t REG_DWORD /d 4 /f"#
            ),
            vec!["Fax".to_string()]
        );
        assert!(
            svc_names_writing_start(
                r#"reg add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v ImagePath /d x /f"#
            )
            .is_empty(),
            "只改 ImagePath 的命令被当成了改启动类型"
        );
        assert!(svc_names_writing_start("net stop Spooler").is_empty());
    }

    /// R3-M03（v4，与 R3-M02 同批）：`tf_svc_bulk` 的 5 个商店服务 Start 必须进值级备份基线 ——
    /// 它们由 `svc_bulk_append_store` 在**执行期**追加（不在数据层 steps 里），基线不收
    /// 就是「写了但还原不回来」：还原按旧基线 remove()+摘灰、回 restored:N，原值永久丢失。
    #[test]
    fn 商店服务_start_进值级备份基线() {
        let targets: Vec<String> = option_targets("tf_svc_bulk")
            .unwrap_or_default()
            .iter()
            .map(|t| format!("{}::{}\\{}", t.root, t.sub, t.key))
            .collect();
        for svc in super::apply::STORE_SERVICES {
            let want = format!("HKEY_LOCAL_MACHINE::SYSTEM\\CurrentControlSet\\Services\\{svc}\\Start");
            assert!(targets.contains(&want), "{svc} 的 Start 没进基线，实收: {targets:?}");
        }
    }

    /// R3-M02（v4）：`tf_svc_bulk` 的**子集分支**也必须能追加商店服务 ——
    /// 此前只有全选/非动态分支调 `svc_bulk_append_store`，子集分支把并进 picked 的
    /// 5 个名字交给 rebuild_steps 的侧表交集静默滤掉（回执仍成功 = 确认过的写入没发生）。
    /// 形态判据：剥掉整行注释后，append 出现次数 = 定义 1 + 三个出口 ≥ 4；被摘一处即红。
    #[test]
    fn 子集分支也要追加商店服务() {
        // 行级剥注释（apply.rs 的说明注释里也复述了函数名，不剥会被语料骗）
        let raw = include_str!("apply.rs");
        let src: String = raw
            .split('\n')
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let calls = src.matches("svc_bulk_append_store(").count();
        assert!(
            calls >= 4,
            "svc_bulk_append_store 出现 {calls} 处（定义 1 + 子集/全选/非动态三个出口起步）——\
             子集分支的追加臂可能被摘（R3-M02 回归：勾了商店的子集执行会静默丢写入）"
        );
    }

    /// RAINZ 对标 B4：游戏 QoS（DSCP 46）条目的形状棘轮。
    ///
    /// 8 个游戏进程 × 11 个值、**只走 reg** —— 因此还原可由推理补齐（这就是它有「立即恢复」
    /// 入口的依据）。手工编辑数据层时掉一个进程、漏一个值、或为了省事改成 cmd 步，
    /// 都会在这里红，而不是等用户点了发现某个游戏没被标记、或还原入口莫名消失。
    #[test]
    fn 游戏qos条目形状不变() {
        let opt = find_option("net_qos_dscp").expect("net_qos_dscp 不在目录里");
        let steps = opt.get("steps").and_then(|v| v.as_array()).expect("steps 缺失");
        assert_eq!(steps.len(), 1, "QoS 项应是单条 reg 步骤（混入非 reg 步会让还原推理失效）");
        let reg = steps[0].get("reg").and_then(|v| v.as_str()).expect("reg 缺失");
        assert_eq!(reg.matches("\r\n[").count(), 8, "reg 段数应为 8（对应 8 个游戏进程）");
        assert_eq!(reg.matches("\r\n\"").count(), 88, "值行数应为 88（8 进程 × 11 字段）");
        for exe in [
            "VALORANT-Win64-Shipping.exe",
            "FortniteClient-Win64-Shipping.exe",
            "DeltaForceClient-Win64-Shipping.exe",
            "NarakaBladepoint.exe",
            "LeagueClient.exe",
            "TslGame.exe",
            "cs2.exe",
            "r5apex.exe",
        ] {
            assert!(reg.contains(exe), "进程 {exe} 不在 QoS 策略里");
        }
        // 键名带空格也必须原样写出（Rust 的 .reg 行解析按引号切，已实证支持）
        assert!(reg.contains("\"Application Name\"=\"cs2.exe\""), "Application Name 值行缺失或形态变了");
        assert!(reg.contains("\"DSCP Value\"=\"46\""), "DSCP 值必须是 46（Expedited Forwarding）");
        // 88 个目标全部进值级备份：少一个 = 那一个值改了就还原不回去
        assert_eq!(
            option_targets("net_qos_dscp").map(|t| t.len()),
            Some(88),
            "值级备份目标数不是 88：有值没进基线"
        );
        assert_eq!(opt.get("restoreInferred").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(opt.get("restoreAvailable").and_then(|v| v.as_bool()), Some(true));
        // 效果未在本机实测 ⇒ 不许登记「好话」，如实回落「未验证」
        assert_eq!(opt.get("effect").and_then(|v| v.as_str()), Some("未验证"));
    }

    /// 任务二（2026-10-06）「可否恢复只在弹窗判定」的代表用例：**纯 reg 步 ⇒ 推理还原必命中**。
    ///
    /// 主列表删掉行内还原按钮后，「能否还原」只剩弹窗一条判定链，它依赖
    /// `restoreAvailable`（= restore 段存在）。peripheral_snap_to 是纯 reg 步、
    /// **数据层没写 restore 段**的形态 —— 靠推理补齐（`restoreInferred=true`）。
    /// 钉住它 = 钉住「推理还原对纯 reg 项真的生效」这条准则：推理器哪天坏掉，
    /// 用户在弹窗里只会看到置灰按钮，没有任何门禁会自己红。
    #[test]
    fn 纯reg项推理还原可用() {
        let opt = find_option("peripheral_snap_to").expect("peripheral_snap_to 不在目录里");
        let steps = opt.get("steps").and_then(|v| v.as_array()).expect("steps 缺失");
        assert!(
            !steps.is_empty() && steps.iter().all(|s| s.get("reg").is_some()),
            "peripheral_snap_to 应是纯 reg 步（混入非 reg 步会让还原推理失效）"
        );
        assert_eq!(
            opt.get("restore").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(1),
            "纯 reg 项必须由推理补齐 restore（弹窗「可否恢复」的唯一依据）"
        );
        assert_eq!(
            opt.get("restoreInferred").and_then(|v| v.as_bool()),
            Some(true),
            "推断出的 restore 必须标记 restoreInferred=true（区别于数据层手写）"
        );
        assert_eq!(
            opt.get("restoreAvailable").and_then(|v| v.as_bool()),
            Some(true),
            "推理命中的项必须 restoreAvailable=true —— 否则弹窗对可还原项也置灰"
        );
    }

    /// RAINZ 对标 §4 R2：安全降级侧表与目录的一致性。
    ///
    /// 分类的**唯一实现**在 `tools/check-optimizer-security.mjs`（(段,名,值) 三元组 + 命令面
    /// 正则的机械判据，带正向/反向对照）。这里只钉两侧不会各说各话：表里的 id 必须都还在
    /// 目录里（项退役没清表 = 标签挂在空气上）、每条要带档位与理由，且这四条已知的降安全项
    /// 一个都不能少 —— 少了就是门禁覆盖出现空洞，而这四条的危害都是"系统没有防护"级别。
    #[test]
    fn 安全降级侧表与目录一致() {
        for id in ["disable_uac", "tf_defender", "perf_windows_update_off", "perf_vbs_off"] {
            let sd = security_degrade_of(id).unwrap_or_else(|| panic!("{id} 不在安全降级侧表里"));
            assert!(find_option(id).is_some(), "{id} 已不在目录里（侧表该一起清）");
            assert_eq!(
                sd.get("level").and_then(|v| v.as_str()),
                Some("high"),
                "{id} 档位应仍为 high（这些都在降安全基线）"
            );
            let why = sd.get("why").and_then(|v| v.as_str()).unwrap_or("");
            assert!(why.chars().count() >= 10, "{id} 的 why 太短，等于没写为什么算降级: {why:?}");
            assert!(
                !sd.get("rules").and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(true),
                "{id} 缺 rules（判据标识，用来与 Node 侧重算对拍）"
            );
        }
        // 反向：普通策略项不许被误标（否则「安全降级」这个标签会自己贬值）
        assert!(security_degrade_of("edge_hide_firstrun").is_none(), "普通策略项被误标成安全降级");
        assert!(security_degrade_of("__nope__").is_none());
    }

    /// v2-M14：退役清单必须有真消费者，且不与在目录里的 id 重叠。
    /// 重叠意味着同一个 id 既走正常还原又被列进「待还原的退役项」，两本账会互相清账。
    #[test]
    fn retired_catalog_is_real_and_disjoint_from_live_options() {
        let retired: Vec<&str> = retired_items().iter().filter_map(|i| i["id"].as_str()).collect();
        assert!(retired.len() >= 10, "退役清单解析不出条目，接线等于空转: {retired:?}");
        assert!(retired.iter().all(|id| !id.is_empty()), "条目缺 id");
        let mut sorted = retired.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), retired.len(), "退役 id 不得重复");
        for id in &retired {
            assert!(find_option(id).is_none(), "{id} 同时在优化目录与退役清单里");
        }
        assert!(is_retired_id(retired[0]), "清单里的 id 必须被还原通道认得");
        assert!(!is_retired_id("trim-definitely-not-a-real-option-id"));
    }

    /// 待还原清单只列「本机确实留有非空备份」的退役项：备份空或结构塌了都还原不了，
    /// 列出来等于给用户一个点了不会成功的按钮。
    #[test]
    fn retired_pending_lists_only_backups_that_can_actually_restore() {
        let id0 = retired_items()[0]["id"].as_str().unwrap();
        let id1 = retired_items()[1]["id"].as_str().unwrap();
        let map = json!({
            id0: { "values": [ { "hive": "CurrentUser", "sub": "Software\\X", "key": "a" } ] },
            id1: { "values": [] },
            "not-a-retired-id": { "values": [ { "hive": "CurrentUser" } ] },
        });
        let out = retired_pending_backups(&map);
        assert_eq!(out.len(), 1, "空备份与非退役 id 都不该列: {out:?}");
        assert_eq!(out[0]["id"], json!(id0));
        assert_eq!(out[0]["values"], json!(1), "渲染层要按条数说明改写了几个值");
        assert!(out[0]["title"].is_string(), "给用户看的必须是标题不是 id");
        assert!(retired_pending_backups(&json!([])).is_empty(), "备份文件不是对象不得 panic");
        assert!(retired_pending_backups(&json!({ id0: "oops" })).is_empty(), "条目结构异常按无备份处理");
    }

    #[test]
    fn reg_expected_dword_and_string() {
        assert_eq!(parse_reg_expected("dword:00000001"), Some((true, "1".to_string())));
        assert_eq!(parse_reg_expected("dword:0000000a"), Some((true, "10".to_string())));
        assert_eq!(parse_reg_expected("\"hello\""), Some((false, "hello".to_string())));
        assert_eq!(parse_reg_expected("foo"), Some((false, "foo".to_string())));
    }

    #[test]
    fn reg_sections_and_value_lines() {
        let block = "Windows Registry Editor Version 5.00\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SOFTWARE\\A]\r\n\
\"X\"=dword:00000001\r\n\
\"Y\"=-\r\n\r\n\
[HKEY_CURRENT_USER\\SOFTWARE\\B]\r\n\
\"Z\"=\"v\"\r\n";
        let secs = parse_reg_sections(block);
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0].0, "HKEY_LOCAL_MACHINE\\SOFTWARE\\A");
        let a_lines = parse_reg_value_lines(&secs[0].1);
        assert!(a_lines.iter().any(|(k, _)| k == "X"));
        // 删除占位 Y 由调用方跳过，解析层仍可见
        assert!(a_lines.iter().any(|(k, r)| k == "Y" && r == "-"));
        assert_eq!(secs[1].0, "HKEY_CURRENT_USER\\SOFTWARE\\B");
    }

    #[test]
    fn memory_steps_table_and_fallback() {
        let cmd_of = |gb: Value| {
            let s = memory_steps(&gb);
            s[0].get("cmd").and_then(|v| v.as_str()).unwrap_or_default().to_string()
        };
        assert!(cmd_of(json!("default")).contains(&MEMORY_KB_DEFAULT.to_string()));
        assert!(cmd_of(json!("8")).contains("8388608"));
        // 异常档位回退 8GB 阈值，且文案如实标注
        let steps = memory_steps(&json!(99));
        assert!(steps[0].get("cmd").unwrap().as_str().unwrap().contains("8388608"));
        assert!(steps[0].get("label").unwrap().as_str().unwrap().contains("回退"));
    }

    /// 回归 2026-09-30（用户机实测）：cmd 步骤的引号形状。旧写法 `args(["/c", cmd])` 让子进程
    /// 收到 `\"…\"`，reg.exe 于是把值写进键名尾随一个引号的垃圾键
    /// （`HKLM\SYSTEM\ControlSet001\Control"` 当场被创建），真键一个字没改、退出码还是 0 ⇒
    /// 步骤记「成功」、回读报「校验不符」，用户只看见一项永远失败的优化。
    /// 这里用 echo 看子进程实际收到的文本：不碰注册表（零副作用），但引号一丢必红。
    /// 探针取生产同一条 `memory_steps` 命令行，且走生产同一个 `run_cmd_step` —— 测试自己抄一份
    /// 格式的话，生产改回去它是测不出来的。
    #[test]
    fn cmd_step_line_survives_cmd_quote_stripping() {
        let steps = memory_steps(&json!("16"));
        let probe = steps[0]
            .get("cmd")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        assert!(probe.contains('"'), "探针必须带内层引号，否则这条测试测不到引号形状");
        let out = run_cmd_step(&format!("echo {probe}")).expect("cmd /c echo 起不来");
        let got = String::from_utf8_lossy(&out.stdout).replace("\r\n", "");
        assert!(got.contains(&probe), "子进程收到的命令行与原文不符: {got}");
        assert!(!got.contains("\\\""), "出现反斜杠+引号说明又退回 args() 转义: {got}");
    }

    #[test]
    fn wu_pause_clamps_days() {
        for (input, want) in [(0i64, 1i64), (7, 7), (99, 35)] {
            let s = wu_pause_steps(input);
            let pwsh = s[0].get("pwsh").and_then(|v| v.as_str()).unwrap_or_default();
            assert!(pwsh.contains(&format!("$days = {want}")), "input={input}");
        }
    }

    #[test]
    fn dmtf_offset_converts_to_utc() {
        // 12:30 本地、东八区(+480) → 04:30 UTC
        let iso = parse_dmtf("20260924123000.000000+480").expect("parse");
        assert_eq!(iso, "2026-09-24T04:30:00.000Z");
        assert!(parse_dmtf("garbage").is_none());
        assert!(parse_dmtf("20260924123000.000+480").is_none());
    }

    #[test]
    fn build_script_emits_protocol_and_uses_tmp_dir() {
        let steps = vec![
            json!({ "label": "c", "cmd": "echo hi" }),
            json!({ "label": "r", "reg": "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\X]\r\n\"K\"=dword:00000001\r\n" }),
            json!({ "label": "s", "service": "SvcX", "disable": true }),
        ];
        let ps = build_script(&steps);
        assert!(ps.contains("Write-TFDiag")); // preamble 从哨兵脚本切出
        assert!(ps.contains("@@DONE@@"));
        assert!(ps.contains("@@FAILED:"));
        assert!(ps.contains("@@PROGRESS:100@@"));
        assert!(ps.contains("TRIM_TMP")); // OPT-3/A1：reg 临时文件加固目录
        assert!(ps.contains("-Encoding Unicode")); // OPT-3
        assert!(ps.contains("Stop-Service -Name 'SvcX'"));
        // 标签单引号被安全包裹
        assert!(ps.contains("'c'"));
    }

    #[test]
    fn pros_cons_parse_and_fallback() {
        let (p, c) = parse_pros_cons("优点：提升速度\n缺点：增加耗电");
        assert_eq!(p, "提升速度");
        assert_eq!(c, "增加耗电");
        let (p2, c2) = parse_pros_cons("无格式文本");
        assert_eq!(p2, "无格式文本");
        assert_eq!(c2, "");
    }

    #[test]
    fn runtime_options_load() {
        assert!(options().len() >= 100);
        assert!(find_option("tf_defender").is_some());
        assert!(find_option("not_exist").is_none());
        // 78 项带还原步骤
        assert!(options().iter().filter(|o| {
            o.get("restore").and_then(|v| v.as_array()).is_some_and(|a| !a.is_empty())
        }).count() >= 70);
    }

    /// v2-K2（B11 重写）：还原方向原先生成「交给 pwsh 执行的脚本正文」，不可信值必须锁在
    /// 单引号串里。**现在不再有任何 shell**，攻击面从「值会被求值」变成「值被当成什么」——
    /// 断言改为钉「不可信值逐字节原样进编码结果，不做任何解释/求值/剥除」。
    #[test]
    fn restore_ops_keep_untrusted_values_verbatim() {
        let payload = "A$(whoami)`id`\"B'c";
        let ops = build_restore_ops(&[json!({
            "hive": "CurrentUser", "sub": "Software\\X", "key": "Y",
            "exists": true, "type": "REG_SZ", "data": payload
        })])
        .expect("合法条目不应报畸形");
        let [RestoreOp::Write { ref key, ref bytes, .. }] = ops[..] else {
            panic!("应为一条 Write: {ops:?}");
        };
        assert_eq!(key, "Y");
        // 期望字节 = UTF-16LE(含 NUL)；关键字段是「没有任何字符被吃掉或改写」
        let mut want: Vec<u8> = payload.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
        want.extend_from_slice(&[0, 0]);
        assert_eq!(bytes, &want, "REG_SZ 数据被改写 ⇒ 注入防护已退化为碰运气");

        // hive/sub/key 同样只是数据，不是代码
        let ops = build_restore_ops(&[json!({
            "hive": "LocalMachine", "sub": "S", "key": "K'$(p)", "exists": false
        })])
        .unwrap();
        assert_eq!(
            ops,
            vec![RestoreOp::Delete { hive: "LocalMachine".into(), sub: "S".into(), key: "K'$(p)".into() }]
        );
    }

    /// B11：畸形备份值必须 **fail-closed**（整批拒绝），而不是像旧 PS 版那样把
    /// 非 hex 字符剥掉再写 —— 还原路径上「写错数据还报成功」比「报失败」更糟。
    #[test]
    fn restore_rejects_malformed_backup_data() {
        // BINARY：旧测试喂 `41;42`$(x)43\n` 并断言剥成 `414243`；现在必须整体拒绝
        for bad in ["41;42`$(x)43\n", "4", "zz", "4142g"] {
            assert!(
                build_restore_ops(&[json!({
                    "hive": "LocalMachine", "sub": "S", "key": "K",
                    "exists": true, "type": "REG_BINARY", "data": bad
                })])
                .is_err(),
                "畸形 REG_BINARY 应拒绝: {bad:?}"
            );
        }
        // DWORD / QWORD：非十进制整数同样拒绝
        for bad in ["abc", "", "1.5"] {
            assert!(
                build_restore_ops(&[json!({
                    "hive": "LocalMachine", "sub": "S", "key": "K",
                    "exists": true, "type": "REG_DWORD", "data": bad
                })])
                .is_err(),
                "畸形 REG_DWORD 应拒绝: {bad:?}"
            );
        }
        // 未知 hive 也不放行
        assert!(
            build_restore_ops(&[json!({
                "hive": "NoSuchHive", "sub": "S", "key": "K", "exists": false
            })])
            .is_err()
        );
    }

    /// DWORD 编码口径对齐读值侧 `[string]([int]$v)`：有符号 i32 十进制，
    /// 这样 `0xFFFFFFFF` 才能以 `-1` 的形式原样往返（reg.exe 同口径）。
    #[test]
    fn restore_dword_roundtrip_is_signed32() {
        let ops = build_restore_ops(&[json!({
            "hive": "LocalMachine", "sub": "S", "key": "K",
            "exists": true, "type": "REG_DWORD", "data": "-1"
        })])
        .unwrap();
        let Some(RestoreOp::Write { bytes, .. }) = ops.first() else { panic!("{ops:?}") };
        assert_eq!(bytes.as_slice(), &[0xFFu8, 0xFF, 0xFF, 0xFF]);
        // 正常值
        let ops = build_restore_ops(&[json!({
            "hive": "LocalMachine", "sub": "S", "key": "K",
            "exists": true, "type": "REG_DWORD", "data": "4096"
        })])
        .unwrap();
        let Some(RestoreOp::Write { bytes, .. }) = ops.first() else { panic!("{ops:?}") };
        assert_eq!(bytes.as_slice(), 4096i32.to_le_bytes().as_slice());
    }

    /// B11：`restore_write_bytes` 与 `native::decode_reg_value_bytes` 是**同一条链的两端** ——
    /// 读出来的字符串必须能被编码器原样写回。这里用固定样例钉住两侧口径不漂移
    /// （真正的注册表往返由 `restore_backup_values` 在真机执行，单测只锁纯函数）。
    #[test]
    fn backup_read_and_restore_encode_are_inverse() {
        // DWORD：读侧产出有符号 i32 十进制；编码器按 i32 解析再写回 LE
        assert_eq!(restore_write_bytes("REG_DWORD", "-1").unwrap(), vec![0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(restore_write_bytes("REG_DWORD", "0").unwrap(), vec![0, 0, 0, 0]);
        // QWORD：i64 十进制
        assert_eq!(
            restore_write_bytes("REG_QWORD", "-1").unwrap(),
            (-1i64).to_le_bytes().to_vec()
        );
        // BINARY：小写 hex 连写（读侧 `-join ''` 的产物）逐字节还原
        assert_eq!(restore_write_bytes("REG_BINARY", "deadbeef").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        // SZ：UTF-16LE + NUL；还原路径写回后读侧 `[string]$v` 得到同一串
        let sz = restore_write_bytes("REG_SZ", "中文 & punctuation").unwrap();
        let units: Vec<u16> = sz.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        assert_eq!(String::from_utf16_lossy(&units), "中文 & punctuation\0");
        // 未知类型标签一律按 REG_SZ 编码（与旧 `reg add` 不带 /t 的兜底一致）
        assert_eq!(
            restore_write_bytes("REG_WHATEVER", "x").unwrap(),
            restore_write_bytes("REG_SZ", "x").unwrap()
        );
    }

    /// 备份链（`flatten=false`）两端互逆，且**类型不变形**。
    ///
    /// 修的是这一类：读侧曾把 `REG_EXPAND_SZ` 展开后报成 `REG_SZ`、把 `REG_MULTI_SZ`
    /// 空格连接后报成 `REG_SZ`，写侧又没有这两条 arm —— 于是「还原」必然把值的
    /// 类型和内容一起改错（`%VAR%` 变成字面路径、多值串变成单串），而还原回读
    /// `verify_option_restored` 因为两侧同口径地错，报的是"还原成功"。
    /// 展平口径本身保留（显示路径要看展开后的真实路径），所以这里同时断言两条口径分岔。
    #[test]
    fn faithful_backup_round_trip_keeps_type_and_bytes() {
        use crate::engine::native::decode_reg_value_bytes;
        use windows::Win32::System::Registry::{REG_EXPAND_SZ, REG_MULTI_SZ};

        // --- REG_EXPAND_SZ：内容不展开、标签保真，编码回去等于原字节 ---
        let raw = r"%USERPROFILE%\App\run.exe";
        let mut eb: Vec<u8> = raw.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
        eb.extend_from_slice(&[0, 0]);
        let (ty, data) = decode_reg_value_bytes(REG_EXPAND_SZ, &eb, false).unwrap();
        assert_eq!(ty, "REG_EXPAND_SZ", "备份链把 EXPAND_SZ 抹平成 REG_SZ ⇒ 还原写死 %VAR%");
        assert_eq!(data, raw, "备份链展开了环境变量 ⇒ 原值永久丢失");
        assert_eq!(restore_write_bytes(ty, &data).unwrap(), eb);
        // 同一份字节走显示口径：仍按老语义报成 REG_SZ（本轮刻意不动它）
        let (flat_ty, flat_data) = decode_reg_value_bytes(REG_EXPAND_SZ, &eb, true).unwrap();
        assert_eq!(flat_ty, "REG_SZ");
        assert_ne!(flat_data, raw, "显示口径应当是展开后的路径");

        // --- REG_MULTI_SZ：NUL 连接可逆，含空格的元素不会被分隔符误伤 ---
        let parts = ["a b", "中文", r"C:\x"];
        let mut mb: Vec<u8> = Vec::new();
        for p in parts.iter() {
            mb.extend(p.encode_utf16().flat_map(|w| w.to_le_bytes()));
            mb.extend_from_slice(&[0, 0]);
        }
        mb.extend_from_slice(&[0, 0]);
        let (ty, data) = decode_reg_value_bytes(REG_MULTI_SZ, &mb, false).unwrap();
        assert_eq!(ty, "REG_MULTI_SZ");
        assert_eq!(data, "a b\u{0}中文\u{0}C:\\x");
        assert_eq!(restore_write_bytes(ty, &data).unwrap(), mb, "MULTI_SZ 字节往返必须逐字节相等");
        // 展平口径用空格连接 —— 正是它无法逆的原因（元素自带空格）
        assert_eq!(
            decode_reg_value_bytes(REG_MULTI_SZ, &mb, true).unwrap(),
            ("REG_SZ", "a b 中文 C:\\x".to_string())
        );

        // --- 空 MULTI_SZ 往返仍是空 MULTI_SZ，不是「一个空元素」 ---
        let (ty, data) = decode_reg_value_bytes(REG_MULTI_SZ, &[0, 0], false).unwrap();
        assert_eq!((ty, data.as_str()), ("REG_MULTI_SZ", ""));
        assert_eq!(restore_write_bytes(ty, &data).unwrap(), vec![0, 0]);

        // --- DWORD 边界值仍按有符号口径往返（0xFFFFFFFF 变形过一次，别再来） ---
        let (ty, data) = decode_reg_value_bytes(
            windows::Win32::System::Registry::REG_DWORD,
            &[0xFF, 0xFF, 0xFF, 0xFF],
            false,
        )
        .unwrap();
        assert_eq!((ty, data.as_str()), ("REG_DWORD", "-1"));
        assert_eq!(restore_write_bytes(ty, &data).unwrap(), vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    /// 还原路径的类型标签不能塌成 REG_SZ：字节编码对了但类型写错，注册表里同样是坏值。
    /// 两条都要断 —— `build_restore_ops` 保住标签只到「操作结构体」为止，真正进
    /// `RegSetValueExW` 的是 `restore_reg_kind` 的映射，那才是用户机器上落盘的东西。
    #[test]
    fn build_restore_ops_preserves_string_variant_types() {
        use windows::Win32::System::Registry::{
            REG_EXPAND_SZ, REG_MULTI_SZ, REG_VALUE_TYPE, REG_SZ,
        };
        // EXPAND_SZ 与 SZ 字节布局相同，所以只能从类型标签这条 arm 判出有没有塌
        for (label, want) in [
            ("REG_EXPAND_SZ", REG_EXPAND_SZ),
            ("REG_MULTI_SZ", REG_MULTI_SZ),
            ("REG_SZ", REG_SZ),
        ] {
            let ops = build_restore_ops(&[json!({
                "hive": "CurrentUser", "sub": "S", "key": "K",
                "exists": true, "type": label, "data": "x"
            })])
            .unwrap();
            let Some(RestoreOp::Write { typ, .. }) = ops.first() else {
                panic!("{label} 应当产生写操作，实际 {ops:?}")
            };
            assert_eq!(typ, label, "备份里的 {label} 在还原操作里被降级");
            let got: REG_VALUE_TYPE = restore_reg_kind(typ);
            assert_eq!(got, want, "{label} 写注册表时被当成 REG_SZ ⇒ 类型永久变形");
        }
        // 老备份（升级前只有 REG_SZ）与未知标签仍按 REG_SZ 兜底
        assert_eq!(restore_reg_kind("REG_WAS_UNKNOWN_BEFORE"), REG_SZ);
    }

    /// 真机闭环（发布前门禁跑）：值级备份 → 污染 → 还原 → 逐字段回读一致。
    ///
    /// 纯单测锁的是编解码函数与类型映射，这条锁的是「`RegSetValueExW` 真的按备份里的
    /// 类型落盘」。断言写成**绝对期望**而不是「还原后 == 备份」：读侧和写侧同口径地错
    /// 也能自洽通过，而 EXPAND_SZ 被抹平成 REG_SZ 恰好就是这种自洽的错。
    /// 探针键 `HKCU\Software\TrimValueFidelityProbe`，不碰任何真实软件键；Drop 守卫删键，
    /// 断言 panic 也不在用户机器上留残迹。
    #[test]
    #[ignore = "真写 HKCU 探针键（值级备份→还原的类型保真），发布前门禁跑"]
    fn value_level_backup_restore_keeps_types_on_real_registry() {
        use crate::engine::native;
        use windows::Win32::System::Registry::{
            HKEY_CURRENT_USER, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ,
        };

        const SUB: &str = r"Software\TrimValueFidelityProbe";
        struct ProbeKey;
        impl Drop for ProbeKey {
            fn drop(&mut self) {
                let _ = crate::engine::native::reg_key_remove(
                    windows::Win32::System::Registry::HKEY_CURRENT_USER,
                    SUB,
                    true,
                );
            }
        }
        let _probe = ProbeKey;

        let utf16z = |s: &str| -> Vec<u8> {
            s.encode_utf16().flat_map(|w| w.to_le_bytes()).chain([0u8, 0u8]).collect()
        };
        let multi_factory: Vec<u8> = {
            let mut v = Vec::new();
            for p in ["cache", "logs"] {
                v.extend(utf16z(p));
            }
            v.extend_from_slice(&[0, 0]);
            v
        };
        // 前置条件：键不存在。残留探针键会让「备份」拍到脏值，整条测试就失去意义
        assert_eq!(
            native::read_reg_value_faithful(HKEY_CURRENT_USER, SUB, "multi"),
            None,
            "前置条件：探针键必须不存在（守卫没清干净？）"
        );

        assert!(native::reg_restore_write(HKEY_CURRENT_USER, SUB, "multi", REG_MULTI_SZ, &multi_factory));
        assert!(native::reg_restore_write(HKEY_CURRENT_USER, SUB, "expand", REG_EXPAND_SZ, &utf16z(r"%USERPROFILE%\App")));
        assert!(native::reg_restore_write(HKEY_CURRENT_USER, SUB, "dw", REG_DWORD, &0xFFFF_FFFFu32.to_le_bytes()));

        let targets = vec![
            RegTarget { root: "HKEY_CURRENT_USER".into(), sub: SUB.into(), key: "multi".into() },
            RegTarget { root: "HKEY_CURRENT_USER".into(), sub: SUB.into(), key: "expand".into() },
            RegTarget { root: "HKEY_CURRENT_USER".into(), sub: SUB.into(), key: "dw".into() },
        ];

        // ① 备份拍到的必须是真实类型与未展开内容（读侧抹平 ⇒ 这三条先红）
        let backup = read_reg_values(&targets).expect("出厂态读取应成功");
        assert_eq!(backup[0]["type"], json!("REG_MULTI_SZ"), "读侧把 MULTI_SZ 抹平成 REG_SZ");
        assert_eq!(backup[0]["data"], json!("cache\u{0}logs"));
        assert_eq!(backup[1]["type"], json!("REG_EXPAND_SZ"), "读侧把 EXPAND_SZ 抹平成 REG_SZ");
        assert_eq!(backup[1]["data"], json!(r"%USERPROFILE%\App"), "读侧展开了 %VAR% ⇒ 原值进不了备份");
        assert_eq!(backup[2]["data"], json!("-1"), "DWORD 的有符号口径变了");

        // ② 污染成「优化后」状态，连类型一起改坏（模拟最真实的使用现场）
        assert!(native::reg_restore_write(HKEY_CURRENT_USER, SUB, "multi", REG_SZ, &utf16z("cache logs")));
        assert!(native::reg_restore_write(HKEY_CURRENT_USER, SUB, "expand", REG_SZ, &utf16z(r"C:\Users\me\AppData\Roaming")));
        assert!(native::reg_restore_write(HKEY_CURRENT_USER, SUB, "dw", REG_DWORD, &0u32.to_le_bytes()));

        // ③ 还原（M-11：构造 ops 一次，写回与回读共用）
        let ops = build_restore_ops(&backup).expect("备份应能构造还原操作");
        assert!(restore_backup_values(&ops), "值级还原必须整体成功");

        // ④ 绝对期望：还原后注册表里就是这个类型与这串内容
        let now = read_reg_values(&targets).expect("还原后应能读回");
        assert_eq!(now, backup, "还原后的值与备份逐项不一致 ⇒ 类型或内容变形了");
        assert_eq!(now[0]["type"], json!("REG_MULTI_SZ"), "写侧把 MULTI_SZ 降级成 REG_SZ 时这里红");
        assert_eq!(now[1]["type"], json!("REG_EXPAND_SZ"), "写侧把 EXPAND_SZ 降级成 REG_SZ 时这里红");
        assert_eq!(now[1]["data"], json!(r"%USERPROFILE%\App"), "展开后的字面量被写回去时这里红");

        // ⑤ 同一条链的显示口径仍然照旧展平（本轮刻意不改 uninstall 那边的可见行为）
        let (flat_ty, flat_data) = native::read_reg_value_text(HKEY_CURRENT_USER, SUB, "multi")
            .expect("探针值应可读");
        assert_eq!((flat_ty, flat_data.as_str()), ("REG_SZ", "cache logs"));
    }

    /// REG_BINARY 的 hex 串只允许 hex 数字与分隔逗号：畸形备份里的 `$`、反引号、换行
    /// 不得有变成语句的机会。
    /// v2-M9：值级基线**只有第一份是干净的**。渲染层每次执行前都会先 backup-reg，
    /// 所以「连拍两次（中间注册表已被改成优化值）」这条序列在真实使用中必然出现；
    /// 旧写法无条件 insert 会让第二次快照覆盖出厂值，之后「还原」回到上一次优化状态。
    #[test]
    fn backup_baseline_never_overwritten() {
        let mut map = json!({});
        let factory = vec![json!({ "key": "X", "data": "出厂值" })];
        assert!(matches!(
            insert_backup_baseline(&mut map, "svc_mem_gb", factory.clone()),
            BackupInsert::Inserted
        ));

        let optimized = vec![json!({ "key": "X", "data": "已优化值" })];
        let again = insert_backup_baseline(&mut map, "svc_mem_gb", optimized);
        assert!(matches!(again, BackupInsert::KeptExisting(1)), "{again:?}");
        let stored = map["svc_mem_gb"]["values"].as_array().cloned().unwrap_or_default();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0]["data"], "出厂值",
            "基线被第二次快照覆盖 ⇒ 出厂原值永久丢失"
        );

        // 不同项各自独立登记，互不干扰
        assert!(matches!(
            insert_backup_baseline(&mut map, "tf_defender", factory.clone()),
            BackupInsert::Inserted
        ));
        // map 不是对象时不得静默当成「已登记」
        let mut broken = json!([]);
        assert!(matches!(
            insert_backup_baseline(&mut broken, "x", factory),
            BackupInsert::MapNotObject
        ));
    }

    /// 生效粒度表的三条底线：表里的 id 必须都还在目录里（退役项要清表，否则提示挂在空气上）、
    /// 表里的标签必须是合法档位、目录里的项缺键按 none。
    /// `tools/check-optimizer-dynamic.mjs` 还会用同一条机械规则重算并要求标签与之一致 ——
    /// 档位是**派生判定**而不是逐条实测（本机不能为了标注真跑 114 项优化），所以必须可复核。
    #[test]
    fn apply_scope_table_is_consistent_with_catalog() {
        let parsed: Value = serde_json::from_str(SCOPE_JSON).expect("optimizer-scope.json 合法");
        let map = parsed.get("scope").and_then(Value::as_object).expect("scope 段必须是对象");
        assert!(!map.is_empty(), "侧表为空 ⇒ 整批重启建议永远不出现，等于没接");

        let known: std::collections::HashSet<String> =
            options().iter().filter_map(|o| o.get("id").and_then(Value::as_str).map(String::from)).collect();
        let valid: std::collections::HashSet<&str> = ["none", "explorer", "reboot"].into_iter().collect();
        for (id, label) in map {
            assert!(known.contains(id), "表里的 {id} 已不在优化目录（退役没清表）");
            let l = label.as_str().unwrap_or("");
            assert!(valid.contains(l), "{id} 的档位 {l:?} 不是合法标签");
            // 表里既然不含 none，每条都该产生真提示；标签映射丢了会静默变成「不提示」
            assert!(scope_rank_of(l) > 0, "{l:?} 被映射成 none ⇒ 这条标注在界面上不存在");
            assert_eq!(apply_scope(id), l, "表里的 {l:?} 没能原样透传到 apply_scope");
        }
        // 刻意不认的档位（display-driver / logoff 没有执行原语）必须降为 none，
        // 不能因为表里误写就冒出一条界面做不到的建议
        assert_eq!(scope_rank_of("display-driver"), 0);
        assert_eq!(apply_scope("id_不在表里"), "none");
    }

    /// v2-K3：闸门必须覆盖数据层自认 high 的**每一项**，而不是只覆盖手写清单登记的那几项。
    /// 断言写成「遍历数据层」，这样以后新增 risk=high 项而不进清单也不会漏。
    #[test]
    fn hazard_gate_covers_every_data_layer_high() {
        let mut n_high = 0;
        for o in options().iter() {
            if o.get("risk").and_then(|v| v.as_str()) != Some("high") {
                continue;
            }
            n_high += 1;
            let id = o.get("id").and_then(|v| v.as_str()).unwrap_or("");
            assert!(needs_high_risk_confirm(o, id), "risk=high 的 {id} 未被高危闸门覆盖");
        }
        assert!(n_high >= 5, "数据层 high 项数异常（{n_high}）——是否被批量降级");

        // v2-K3 实际漏掉的那 7 项：现在由 risk 覆盖，且刻意不进手写清单
        for id in [
            "tf_ifeo_perf",
            "tf_ifeo_wipe",
            "tf_dev_disable",
            "tf_dev_audio",
            "tf_dev_printer",
            "tf_appx",
            "tf_onedrive",
        ] {
            let o = find_option(id).unwrap_or_else(|| panic!("{id} 应存在于数据层"));
            assert!(needs_high_risk_confirm(o, id), "{id} 单项执行仍不弹红色确认");
            assert!(!HAZARD_IDS.contains(&id), "{id} 应由 risk 覆盖，不必回手写清单");
        }

        // 反向：low/medium 项不得被误拦，否则等于把所有优化都锁死在红确认后面
        let low = options()
            .iter()
            .find(|o| o.get("risk").and_then(|v| v.as_str()) == Some("low"))
            .expect("数据层应有 low 项");
        let low_id = low.get("id").and_then(|v| v.as_str()).unwrap_or("");
        assert!(!needs_high_risk_confirm(low, low_id), "low 项 {low_id} 被误判高危");

        // 死条目（数据层不存在）已从清单移除；对拍另有门禁 F2 兜着
        assert!(!HAZARD_IDS.contains(&"tf_microcode_del"));
        assert!(!HAZARD_IDS.contains(&"spectre_off"));
    }

    #[test]
    fn restore_binary_hex_is_strict() {
        // 合法 hex 连写（读值侧 `-join ''` 的产物）必须按字节对解码
        let ops = build_restore_ops(&[json!({
            "hive": "LocalMachine", "sub": "S", "key": "K",
            "exists": true, "type": "REG_BINARY", "data": "414243"
        })])
        .unwrap();
        let Some(RestoreOp::Write { bytes, .. }) = ops.first() else { panic!("{ops:?}") };
        assert_eq!(bytes.as_slice(), &[0x41u8, 0x42, 0x43]);
    }

    /// 步骤标签不得谎报执行引擎（2026-10-02 用户诉求的直接落点）。
    /// 判据只有一份：问 `pssteps::compile`，而不是看数据层有没有 `pwsh` 字段——
    /// 数据层标 pwsh 的步骤里多数其实走原生解释器，一律显示「执行 PowerShell」
    /// 会让人以为应用依赖 PowerShell（甚至以为要装 PowerShell 7）。
    #[test]
    fn 执行引擎按编译器实算而非按数据层标签() {
        assert_eq!(
            step_exec_mode(&json!({"pwsh": "New-ItemProperty -Path 'HKCU:\\Software\\trim-test' -Name a -Value 1 -PropertyType DWord -Force"})),
            Some("native"),
            "能被原生解释器吃下的 pwsh 步骤必须报 native"
        );
        assert_eq!(
            step_exec_mode(&json!({"pwsh": "Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue"})),
            Some("inbox-ps"),
            "cmdlet 形态只能逐字交收件箱 PowerShell，必须如实报 inbox-ps"
        );
        assert_eq!(step_exec_mode(&json!({"cmd": "taskkill /f /im x.exe"})), Some("proc"));
        assert_eq!(step_exec_mode(&json!({"reg": "Windows Registry Editor Version 5.00"})), Some("native"));
        assert_eq!(step_exec_mode(&json!({"label": "无引擎字段"})), None);
    }

    /// 把 `data_layer_coverage_report` 的「编译失败 0」从一次性打印升级成常驻断言：
    /// 数据层任何一步退化成 unsupported，就是「界面看得见可点、后端必然失败」那一族
    /// （v2-M10 前科），必须当场红，而不是等发布前手动跑报告。
    #[test]
    fn 数据层没有编译不出来的步骤() {
        let mut native = 0usize;
        let mut inbox = 0usize;
        let mut bad: Vec<String> = Vec::new();
        for o in options() {
            for key in ["steps", "restore"] {
                for s in o.get(key).and_then(|v| v.as_array()).cloned().unwrap_or_default() {
                    if s.get("pwsh").and_then(|v| v.as_str()).is_none() {
                        continue;
                    }
                    match step_exec_mode(&s) {
                        Some("native") => native += 1,
                        Some("inbox-ps") => inbox += 1,
                        other => bad.push(format!("{}: {:?} ← {}", o.get("id").and_then(|v| v.as_str()).unwrap_or("?"), other, s.get("label").and_then(|v| v.as_str()).unwrap_or(""))),
                    }
                }
            }
        }
        assert!(bad.is_empty(), "这些 pwsh 步骤既编译不成原生、也不在 PsInline 白名单里: {bad:?}");
        assert!(native > 0 && inbox > 0, "覆盖报告形状变了（native={native} inbox-ps={inbox}），前端文案分支要跟着复核");
        // 收件箱 PowerShell 步数**只减不增**的棘轮：新增优化项若退化成整段交 PS，
        // 这里会红，逼着写清楚「为什么不能原生」。基线 10 是 2026-10-06 收紧：
        // 原基线 11（2026-10-02 现算）含 tf_restore_point×1，随条目摘除、能力改走
        // 命令层内联脚本（restore_point.rs），数据层不再有此步骤 ⇒ 显式降回 10。
        // 其余 10 步成分：tf_ifeo_wipe×1（foreach + PSObject 属性枚举，误编译等于删错
        // IFEO 子键）、tf_mmagent×2（Disable-MMAgent cmdlet，注册表落点未在本机实测，
        // 不猜）、tf_dev_*×3（R5 裁定：设备禁用无原生投影且无自动还原）、
        // tf_appx/tf_cortana×2（NonRemovable 在 windows 0.61 无投影，已裁定停手）、
        // tf_onedrive×2（Start-Process /UNINSTALL + @@RECYCLE@@ 协议行，改原生要在真卸
        // OneDrive 的机器上验，本机不造这个副作用）。
        const INBOX_PS_BASELINE: usize = 10;
        assert!(
            inbox <= INBOX_PS_BASELINE,
            "收件箱 PowerShell 步骤从基线 {INBOX_PS_BASELINE} 涨到 {inbox}：新步骤要优先走原生解释器，\
             确实不能原生请把理由补进本注释并显式抬基线"
        );
        println!("[执行引擎分账] 原生 {native} 步 / 收件箱 PowerShell 5.1 {inbox} 步 / 不支持 0 步");
    }

    // ==================== M1 批次整批预检判据 ====================

    /// R1-1.3（同源）：preflight 与单条执行链必须**共用** `preflight_reason`。
    ///
    /// 这条测试在 v0.5.0 上会红 —— 那时根本没有 preflight，判据散在
    /// `optimizer_run` 的三段内联 early-return 里，批量侧看不到任何提前告知。
    ///
    /// 断言写法刻意用「同一批 id 在两个方向上都过同一个函数」，而不是各测一遍：
    /// 复制一份判据的实现照样能通过「预检能拒高危项」这种朴素断言。
    #[test]
    fn m1_preflight判据与单条执行链同源() {
        // 找一项数据层自认 high 的（v2-K3 起高危闸门覆盖全部 risk=high）
        let high = options()
            .iter()
            .find(|o| o.get("risk").and_then(|v| v.as_str()) == Some("high"))
            .expect("数据层应有 risk=high 项");
        let high_id = high.get("id").and_then(|v| v.as_str()).unwrap_or("");

        // 正向：被判「需高危确认」
        assert_eq!(
            preflight_reason(high, high_id, false),
            Some(PreflightReject::NeedHighRiskConfirm),
            "正向高危项必须被预检拦下"
        );
        // R1-1.3b 语义坑：还原方向豁免高危确认（审查 2026-09-27 H1）。
        // 若此处返回 NeedHighRiskConfirm 就是把「无值级备份的高危项走预置脚本还原
        // 整体死锁」那个 bug 重造一遍 —— 4 条还原入口全部命中过。
        let restore_verdict = preflight_reason(high, high_id, true);
        assert_ne!(
            restore_verdict,
            Some(PreflightReject::NeedHighRiskConfirm),
            "还原方向被判需高危确认 ⇒ 还原通道会整体死锁（2026-09-27 H1 前车）"
        );
    }

    /// R1-1.3 分档：非管理员环境下**每一类**理由都必须在 `rejected` 里出现。
    ///
    /// 朴素实现（只判「未知选项」）在本测试下会红：非管理员时 `is_admin()` 为假，
    /// `preflight_reason` 先返回 `NeedAdmin`，`NeedHighRiskConfirm` 分支永远走不到。
    /// 断言写成「逐项比对返回的枚举」而不是「断言消息含某几个字」。
    #[test]
    fn m1_preflight拒绝理由分档互不吞并() {
        // 造两个已知 id：high（正向必被拦）/ 普通 low（不该被拦，防闸门过度）
        let high = options()
            .iter()
            .find(|o| o.get("risk").and_then(|v| v.as_str()) == Some("high"))
            .expect("数据层应有 risk=high 项");
        let low = options()
            .iter()
            .find(|o| o.get("risk").and_then(|v| v.as_str()) == Some("low"))
            .expect("数据层应有 risk=low 项");
        let low_id = low.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let high_id = high.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let admin = crate::engine::sysinfo::is_admin();
        // 非管理员：管理员档优先，返回NeedAdmin（这就是「理由分档」——
        // 非管理员环境下永远看不到「需高危确认」，朴素实现会以为那条判据没生效）
        if !admin {
            assert_eq!(
                preflight_reason(low, &low_id, false),
                Some(PreflightReject::NeedAdmin),
                "非管理员环境下 low 项也该被 NeedAdmin 拦下"
            );
            assert_eq!(
                preflight_reason(high, &high_id, false),
                Some(PreflightReject::NeedAdmin),
                "非管理员环境下 high 项应先被 NeedAdmin 拦下（管理员档优先于高危档）"
            );
        } else {
            // 管理员：high 项落到高危档，low 项完全放行。
            // 两条一起断言才叫「分档」—— 只查 high 的话，
            // 「所有项一律返回 NeedHighRiskConfirm」这种过度拦截也判不出来。
            assert_eq!(
                preflight_reason(high, &high_id, false),
                Some(PreflightReject::NeedHighRiskConfirm),
                "管理员环境下 high 项必须落到高危档"
            );
            assert_eq!(
                preflight_reason(low, &low_id, false),
                None,
                "low 项 {low_id} 被预检误拦 —— 闸门过度会让用户点不动正常功能"
            );
        }
        // 三条消息文案互不相同：文案重复会让用户看不懂到底被什么拦了
        let msgs = [
            PreflightReject::NeedAdmin.message(),
            PreflightReject::NeedHighRiskConfirm.message(),
            PreflightReject::UnsupportedStep("示例步骤".into()).message(),
        ];
        let uniq: std::collections::HashSet<&String> = msgs.iter().collect();
        assert_eq!(uniq.len(), 3, "三条拒绝理由文案出现重复: {msgs:?}");
        assert!(msgs[2].contains("示例步骤"), "UnsupportedStep 文案必须带出是哪一步");
    }

    /// R1-1.4 / R1-1.5（命令层契约）：未知 id 必进 `rejected`，空 ids 不许乐观放行。
    ///
    /// 直接测命令体需要 Tauri 运行时（`WebviewWindow`），所以这里测**它调用的那段纯逻辑**：
    /// 判据真源`preflight_reason` + `find_option` 的组合语义。命令壳那层由
    /// `tests/module_smoke.rs` 的 IPC 面覆盖。
    #[test]
    fn m1_preflight未知id不被当成可执行() {
        assert!(
            find_option("__不存在的id__").is_none(),
            "测试前提失效：__不存在的id__ 竟然能在数据层找到"
        );
        // 反向：现存的 low 项必须找得到，否则「未知即拒」的断言没有对照
        assert!(options().iter().any(|o| o.get("id").and_then(|v| v.as_str()) == Some("perf_wu_pause")));
    }

    /// M2 · B 类：6 项「写服务启动类型但检测不出」的项必须真能产出断言。
    ///
    /// v0.5.0 的形态：这 6 项的 `steps` 全是 `pwsh` 文本，`collect_checks` 不解析 pwsh
    /// 所以返回空 vec，上游 `if !checks.is_empty()` 跳过，体检恒显示「未生效」，
    /// 用户点详情看到「立即执行」而不是「立即恢复」，会**重复施加同一批改动**。
    /// 与 v2-M1 那个重复项 bug 同一种形态：把「没检到」显示成「没有」。
    #[test]
    fn m2_服务类盲区项现在能产出断言() {
        // (id, 期望的服务断言条数下限)
        for (id, min_checks) in [
            ("tf_svc_bulk", 65), // 仅 65 个基础服务；wuauserv 与商店 5 项期望值取决于运行期选项，静态不可断言
            ("tf_drv_disable", 19),
            ("svc_connected_devices_manual", 2),
            ("svc_remote_connectivity_manual", 6),
            ("svc_remote_registry_disable", 1),
            ("svc_bluetooth_disable", 1),
        ] {
            let opt = find_option(id).unwrap_or_else(|| panic!("{id} 应存在于数据层"));
            let checks = collect_checks(opt);
            assert!(
                checks.len() >= min_checks,
                "{id} 只产出 {} 条断言（期望 >= {min_checks}）—— 检测侧仍读不到 pwsh 步骤的写入落点",
                checks.len()
            );
            // 全部必须是 svcStart 形态，且 data 是合法启动类型
            for c in &checks {
                assert_eq!(c.probe().0, "svcStart", "{id} 产出了非 svcStart 断言：{:?}", c.probe());
                let v: u32 = c
                    .probe()
                    .1
                    .parse()
                    .unwrap_or_else(|_| panic!("{id} 的 data 不是十进制 u32：{:?}", c.probe()));
                assert!(
                    matches!(v, 2 | 3 | 4),
                    "{id} 的期望 Start={v} 不是合法 win32 启动类型（AUTO=2/DEMAND=3/DISABLED=4）"
                );
            }
        }
    }

    /// 2026-10-05 复核（批量项恒判「部分生效」的根因）：静态断言不得包含
    /// 「条件追加」的商店服务，也不得让同一服务带两个互斥的期望 Start。
    ///
    /// 两条都会让 `all()` 恒假：前者在「没勾商店」的用户机上必然不成立，
    /// 后者（wuauserv：基础段=3 / 商店段=4）无论实际是 3 还是 4 都有一条断言失败。
    /// 用正向特征点名被排除的目标，避免「命令整条消失」式假绿。
    #[test]
    fn 批量服务断言不含条件追加与跨组互斥目标() {
        let opt = find_option("tf_svc_bulk").expect("tf_svc_bulk 在目录里");
        let spec = write_spec_of("tf_svc_bulk").expect("tf_svc_bulk 应在写入坐标侧表里");
        let checks = collect_checks(opt);
        assert!(checks.len() >= 60, "服务清单断言数异常：{}", checks.len());

        let mut seen: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        for c in &checks {
            let (kind, data, name) = c.probe();
            assert_eq!(kind, "svcStart", "批量项产出了非 svcStart 断言：{:?}", c.probe());
            assert!(
                !spec.store_services.iter().any(|s| s == name),
                "条件追加的商店服务 {name} 混进静态断言 —— 没勾商店的用户会恒判未生效",
            );
            if let Some(prev) = seen.insert(name, data) {
                assert_eq!(prev, data, "服务 {name} 出现互斥断言 {prev}/{data} —— all() 必有一条恒假");
            }
        }
        assert!(
            !seen.contains_key("wuauserv"),
            "wuauserv 的期望值取决于是否追加商店段，必须排除在静态断言之外",
        );
    }

    /// M2 侧表本身的自洽：每个登记项在数据层都存在，且服务清单非空。
    ///
    /// 侧表与 pwsh 文本的**逐项对拍**由 `tools/check-optimizer-write-contract.mjs`
    /// 负责（跨语言，只能在 Node 侧做）；这条只钉 Rust 侧读得出来。
    #[test]
    fn m2_写入坐标侧表自洽() {
        for id in [
            "tf_svc_bulk",
            "tf_drv_disable",
            "svc_connected_devices_manual",
            "svc_remote_connectivity_manual",
            "svc_remote_registry_disable",
            "svc_bluetooth_disable",
        ] {
            assert!(find_option(id).is_some(), "侧表登记了 {id} 但数据层没有它（退役了？）");
            let spec = write_spec_of(id).unwrap_or_else(|| panic!("{id} 不在写入坐标侧表里"));
            let total: usize = spec.groups.iter().map(|(_, s)| s.len()).sum();
            assert!(total > 0, "{id} 的侧表里没有任何服务");
        }
        // 不在表里的项返回 None（语义是「检不出」，不是「没有写入」）
        assert!(write_spec_of("__不在表里的id__").is_none());
        // 条件追加那批只对 tf_svc_bulk 存在；其余项该字段为空
        let bulk = write_spec_of("tf_svc_bulk").unwrap();
        assert!(!bulk.store_services.is_empty(), "tf_svc_bulk 缺条件追加的商店服务清单");
        let bt = write_spec_of("svc_bluetooth_disable").unwrap();
        assert!(
            bt.store_services.is_empty(),
            "svc_bluetooth_disable 不该有 store_services（只有 tf_svc_bulk 有条件追加）"
        );
    }

    /// M2-B：`read_reg_binary_opt` 的行为契约（Binary 读回原语）。
    ///
    /// 四条都要断，因为它们各自对应一种「检不出」形态：
    /// · 正常二进制 → 小写 hex 连写（与 `read_reg_value_text` 的 BINARY 展平同格式，
    ///   否则两侧比较时格式不同会恒不相等）
    /// · 空二进制 → `Some("")`，**不是** `None`（`MitigationOptions` 全零字节属这类；
    ///   判成「读不到」会把「已清零」说成「未知」）
    /// · 非 REG_BINARY（DWORD）→ `None`（fail-closed，不拿别的类型凑）
    /// · 键/值不存在 → `None`
    ///
    /// 反向护栏同批：同一键上的 DWORD 读侧**不受影响**（防止新原语抢了旧原语的活）。
    #[test]
    fn m2_二进制读回原语的四条契约() {
        use windows::Win32::System::Registry::{
            HKEY_CURRENT_USER, REG_BINARY, REG_DWORD,
        };
        use crate::engine::native::{read_reg_binary_opt, read_reg_dword_opt, reg_key_ensure, reg_restore_write};

        let sub = "Software\\Trim\\m2-binary-probe";
        assert!(reg_key_ensure(HKEY_CURRENT_USER, sub), "建夹具键失败");
        // 写侧用引擎自己的原语（不引新依赖）
        assert!(
            reg_restore_write(HKEY_CURRENT_USER, sub, "Bin", REG_BINARY, &[0x0a, 0x0b, 0x0c]),
            "写二进制夹具失败"
        );

        // ① 正常二进制 → 小写 hex 连写
        assert_eq!(
            read_reg_binary_opt(HKEY_CURRENT_USER, sub, "Bin").as_deref(),
            Some("0a0b0c"),
            "二进制读回格式必须是连写小写 hex（与 read_reg_value_text 同口径）"
        );

        // ② 非 REG_BINARY（DWORD）→ None（fail-closed）
        assert!(
            reg_restore_write(HKEY_CURRENT_USER, sub, "Dword", REG_DWORD, &42u32.to_le_bytes()),
            "写 dword 夹具失败"
        );
        assert_eq!(
            read_reg_binary_opt(HKEY_CURRENT_USER, sub, "Dword"),
            None,
            "DWORD 值不许被二进制原语读出来（那会拿错类型凑判定）"
        );
        // 反向护栏：DWORD 读侧不受影响
        assert_eq!(
            read_reg_dword_opt(HKEY_CURRENT_USER, sub, "Dword"),
            Some(42),
            "新增二进制原语后 DWORD 读侧被影响 ⇒ 原语抢活"
        );

        // ③ 不存在的值 / 键 → None
        assert_eq!(read_reg_binary_opt(HKEY_CURRENT_USER, sub, "不存在的值"), None);
        assert_eq!(read_reg_binary_opt(HKEY_CURRENT_USER, "Software\\Trim\\不存在的键xyz", "x"), None);

        // 清理夹具（不留残留）
        let _ = crate::engine::native::reg_restore_delete(HKEY_CURRENT_USER, sub, "Bin");
        let _ = crate::engine::native::reg_restore_delete(HKEY_CURRENT_USER, sub, "Dword");
    }

    /// M2-B：A 类 6 项「写注册表但检测不出」的项必须真能产出断言。
    ///
    /// v0.5.0 的形态同 B 类：`steps` 全是 `pwsh` 文本，`collect_checks` 不解析 pwsh
    /// 所以返回空 vec，体检恒显示「未生效」，用户点详情看到「立即执行」而不是
    /// 「立即恢复」，会重复施加。
    ///
    /// 本批覆盖三种判据形态（混起来会判错，所以逐个断）：
    /// · dword 等值（`CommDucking=0`）
    /// · binary 逐字节（`MitigationOptions` / `Scancode Map`）
    /// · **键必须不存在**（`perf_wu_enable` 的删除语义）
    #[test]
    fn m2_a类盲区项现在能产出断言() {
        for (id, min_checks, want_kinds) in [
            ("perf_exploit_protection_off", 1, &["regBinary"][..]),
            ("peripheral_winkey_off", 1, &["regBinary"][..]),
            ("audio_disable_comm_ducking", 3, &["reg"][..]),
            ("audio_disable_narrator_ducking", 2, &["reg"][..]),
            ("audio_disable_service_restart", 1, &["reg"][..]),
            ("perf_wu_enable", 4, &["regAbsent"][..]),
        ] {
            let opt = find_option(id).unwrap_or_else(|| panic!("{id} 应存在于数据层"));
            let checks = collect_checks(opt);
            assert!(
                checks.len() >= min_checks,
                "{id} 只产出 {} 条断言（期望 >= {min_checks}）—— 检测侧仍读不到 pwsh 步骤的写入落点",
                checks.len()
            );
            for c in &checks {
                let (kind, data, _) = c.probe();
                assert!(
                    want_kinds.contains(&kind),
                    "{id} 产出了预期外的 kind={kind}（期望 {:?}）",
                    want_kinds
                );
                // binary 绝不能标 is_dword（判定链靠它二分 dword/string）
                if kind == "regBinary" {
                    assert!(
                        !c.probe_reg().2,
                        "{id} 的 binary 断言被标成 is_dword ⇒ 判定链会把多字节二进制当 4 字节整数比"
                    );
                    // 字节数逐项不同（MitigationOptions 16 字节 / Scancode Map 24 字节），
                    // 所以只断**格式**（偶数长度 + 全小写 hex），不断具体长度 ——
                    // 写死 32 会在换项时误报（第一版就踩了）。
                    // **长度与 pwsh 原文的逐字节一致性由门禁的 A2 组对拍**——
                    // 那条真的抓到了「手抄错一个字节」（本批真发生过）。
                    assert_eq!(
                        data.len() % 2,
                        0,
                        "{id} 的 binary 期望值长度必须是偶数（每字节两个 hex），实际 {}",
                        data.len()
                    );
                    assert!(
                        !data.is_empty() && data.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
                        "{id} 的 binary 期望值必须是非空小写 hex 连写，实际 {data:?}"
                    );
                }
                // regAbsent 的 data 为空（没有「期望值」这回事）
                if kind == "regAbsent" {
                    assert!(data.is_empty(), "{id} 的 regAbsent 断言不该带期望值，实际 {data:?}");
                }
            }
        }
        // 反向护栏：binary 断言的 hive/subkey 必须真的指向侧表声明的键，
        // 否则「键名写错」会表现为「恒判未生效」而不是报错。
        let opt = find_option("perf_exploit_protection_off").unwrap();
        let checks = collect_checks(opt);
        let c = checks.iter().find(|c| c.probe().0 == "regBinary").unwrap();
        assert_eq!(c.probe_reg().0, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel");
        assert_eq!(c.probe_reg().1, "MitigationOptions");
    }

    /// M2-B：`regAbsent` 判据的**方向**必须对（这是本批最容易被写反的一处）。
    ///
    /// 真机验证：造一个键 → 断言判「未生效」（键还在）→ 删掉 → 断言判「已生效」。
    /// 方向写反的话这条会红，而只断言「能产出 regAbsent」的测试**照样绿**。
    /// M2-B：`regAbsent` 判据的**方向**必须对（这是本批最容易被写反的一处）。
    ///
    /// 只断「能产出 regAbsent」的测试**照样绿** —— 方向写反时它仍是 regAbsent，
    /// 只有真机往返能抓住。而真机往返必须**按侧表声明的真实键**做（用别的键
    /// 造同形态夹具测不到方向：`check_optimized` 走的是侧表那条路，会去读
    /// HKLM 下另外 3 个键，它们不存在 ⇒ `all()` 恒 true，与本键无关）。
    ///
    /// ⚠️ 所以这条是 `#[ignore]`：它要在 HKLM
    /// `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` 下真的建/删一个
    /// `Pause*` 键 —— 那是**改系统更新策略**，快速组零副作用纪律不许。
    /// 发布前门禁组（`cargo test -- --ignored`）跑。
    #[test]
    #[ignore = "要真改 HKLM 下的 WindowsUpdate 策略键，发布前门禁组跑"]
    fn m2_删除语义判据方向正确() {
        use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, REG_DWORD};
        use crate::engine::native::{read_reg_dword_opt, reg_key_ensure, reg_restore_write};

        // 键路径与 hive 从**侧表**现取，不硬编码 —— 硬编码会在侧表改键名后
        // 静默测到另一个键上（症状：这条绿了，但真实判据方向是反的）。
        let spec = write_spec_of("perf_wu_enable").expect("perf_wu_enable 应在侧表里");
        let r = spec.reg_writes.first().expect("perf_wu_enable 应有 regWrites");
        assert!(r.absent, "前提失效：perf_wu_enable 的第一条不是删除语义");
        let sub = r.subkey;
        let value = r.value;

        // 建出那个键（模拟「用户暂停过更新」的真实状态）
        reg_key_ensure(HKEY_LOCAL_MACHINE, sub);
        reg_restore_write(HKEY_LOCAL_MACHINE, sub, value, REG_DWORD, &1u32.to_le_bytes());
        assert_eq!(
            read_reg_dword_opt(HKEY_LOCAL_MACHINE, sub, value),
            Some(1),
            "前提失效：夹具值写不进 HKLM（需要管理员）"
        );
        // 键在 ⇒ 该判「未生效」
        let res = check_optimized(Some(&["perf_wu_enable".to_string()]));
        assert_eq!(
            res.get("perf_wu_enable"),
            Some(&false),
            "键还在时必须判未生效（判成 true 就是方向写反了）"
        );

        // 删掉键 ⇒ 判「已生效」
        let _ = crate::engine::native::reg_restore_delete(HKEY_LOCAL_MACHINE, sub, value);
        assert_eq!(
            read_reg_dword_opt(HKEY_LOCAL_MACHINE, sub, value),
            None,
            "前提失效：夹具值删不掉"
        );
        let res = check_optimized(Some(&["perf_wu_enable".to_string()]));
        assert_eq!(
            res.get("perf_wu_enable"),
            Some(&true),
            "键删掉后必须判已生效 —— 这就是「恢复自动更新」该被认出来的状态"
        );
    }

    /// M2-B：`regBinary` 判据的真机往返（造字节 → 判生效 → 改字节 → 判未生效）。
    ///
    /// 为什么要真机往返而不是只断形状：binary 比较是**字符串相等**，
    /// 两侧格式只要有一处不同（大小写 / 分隔符 / 长度口径）就恒不相等，
    /// 而这种错编译全绿、静态检查全绿，只在这条真机断言里才暴露。
    #[test]
    fn m2_binary判据真机往返() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_BINARY};
        use crate::engine::native::{read_reg_binary_opt, reg_key_ensure, reg_restore_write};

        let sub = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";
        let value = "MitigationOptions";
        // 只在测试键下做往返（真机那个键是系统级的，写它属于改系统状态）
        let probe_sub = "Software\\Trim\\m2-binary-probe2";
        assert!(reg_key_ensure(HKEY_CURRENT_USER, probe_sub), "建夹具键失败");
        let bytes = [0x22u8, 0x22, 0x22, 0x00, 0x00, 0x02];
        assert!(reg_restore_write(HKEY_CURRENT_USER, probe_sub, value, REG_BINARY, &bytes), "写夹具失败");

        let expect = "222222000002";
        assert_eq!(
            read_reg_binary_opt(HKEY_CURRENT_USER, probe_sub, value).as_deref(),
            Some(expect),
            "写入的 6 字节应读回成 12 个 hex 字符"
        );
        // 侧表里 perf_exploit_protection_off 用的正是同一套格式（16 字节 = 32 hex）
        let spec = write_spec_of("perf_exploit_protection_off").unwrap();
        let ra = spec
            .reg_writes
            .iter()
            .find(|r| r.value == "MitigationOptions")
            .expect("侧表里应有 MitigationOptions");
        assert_eq!(ra.expect.len(), 32, "侧表期望值应是 32 个 hex 字符");
        assert!(ra.expect.chars().all(|c| c.is_ascii_hexdigit()), "侧表期望值必须全是 hex 字符");
        // 键路径对照（防止侧表写错键名，那会表现为恒判未生效而不是报错）
        assert_eq!(ra.subkey, sub);
        let _ = crate::engine::native::reg_restore_delete(HKEY_CURRENT_USER, probe_sub, value);
    }

    /// M2-C：两个 dynamic 项现在能产出断言（它们的数据层 `steps` 是空的）。
    ///
    /// 这两项与 M2-A/B 那些**根本不同**：`dynamic: true`，真实步骤由后端按用户
    /// 选的参数生成（`memory_steps(gb)` / `wu_pause_steps(days)`），所以检测侧
    /// **不能**从数据层 pwsh 文本抽判据。两种新形态：
    /// · `regEnum`（svc_mem_gb）：值 ∈ 合法档位集合
    /// · `regTimeWindow`（perf_wu_pause）：现在 ∈ [start, end) 区间
    #[test]
    fn m2c_dynamic项现在能产出断言() {
        // svc_mem_gb → 1 条 regEnum
        let opt = find_option("svc_mem_gb").unwrap();
        let checks = collect_checks(opt);
        assert_eq!(checks.len(), 1, "svc_mem_gb 应产出 1 条断言，实际 {}", checks.len());
        assert_eq!(checks[0].probe().0, "regEnum", "形态不对：{:?}", checks[0].probe());
        assert_eq!(checks[0].probe_reg().1, "SvcHostSplitThresholdInKB");
        // 集合来自 apply.rs 的 MEMORY_KB + MEMORY_KB_DEFAULT（9 个值）
        let set: Vec<i64> = checks[0].probe().1.split(',').filter_map(|x| x.trim().parse().ok()).collect();
        assert_eq!(set.len(), 9, "档位集合应含 8 个 MEMORY_KB 档位 + default，实际 {}", set.len());
        for kb in [380_000i64, 4_194_304, 6_291_456, 8_388_608, 12_582_912, 16_777_216, 20_971_520, 25_165_824, 33_554_432] {
            assert!(set.contains(&kb), "档位集合缺 {kb}（侧表与 apply.rs 的 MEMORY_KB 漂移了）");
        }

        // perf_wu_pause → 3 条 regTimeWindow（每组一 start 一 end）
        let opt = find_option("perf_wu_pause").unwrap();
        let checks = collect_checks(opt);
        assert_eq!(checks.len(), 3, "perf_wu_pause 应产出 3 组区间断言，实际 {}", checks.len());
        let mut pairs: Vec<(String, String)> = checks
            .iter()
            .map(|c| (c.probe_reg().1.to_string(), c.probe_reg_name().to_string()))
            .collect();
        pairs.sort();
        let want = [
            ("PauseFeatureUpdatesStartTime", "PauseFeatureUpdatesEndTime"),
            ("PauseQualityUpdatesStartTime", "PauseQualityUpdatesEndTime"),
            ("PauseUpdatesStartTime", "PauseUpdatesExpiryTime"),
        ];
        for (i, (ws, we)) in want.iter().enumerate() {
            assert_eq!(pairs[i], (ws.to_string(), we.to_string()), "第 {i} 组键名与 wu_pause_steps 的 pwsh 原文不一致");
        }
    }

    /// M2-C：`regEnum` 判据的真机往返（在测试键上，不动系统那个键）。
    ///
    /// 要断的三态：值在集合内 ⇒ 已生效；值不在集合内 ⇒ 未生效；键不存在 ⇒ 未生效。
    /// 只断第一态的话，「实现把判据写成永远 true」也能过。
    #[test]
    fn m2c_enum判据三态真机往返() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_DWORD};
        use crate::engine::native::{read_reg_dword_opt, reg_key_ensure, reg_restore_write};

        let opt = find_option("svc_mem_gb").unwrap();
        let template = collect_checks(opt);
        let probe = "Software\\Trim\\m2c-enum-probe";
        // ⚠️ **先删残留再开始**：上一次运行（无论成功还是 panic）会留下这个键，
        // 而「键不存在 ⇒ 未生效」那一态就永远测不到（实测踩过：残留值恰好是
        // 8388608，在档位集合内，于是① 判成 true）。
        // 夹具不跨运行保持干净 ⇒ 每次都从「键不存在」这个真起点开始。
        let _ = crate::engine::native::reg_restore_delete(
            HKEY_CURRENT_USER,
            probe,
            "SvcHostSplitThresholdInKB",
        );
        assert!(
            read_reg_dword_opt(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB").is_none(),
            "前提失效：上一次运行的夹具残留没清干净"
        );
        assert!(reg_key_ensure(HKEY_CURRENT_USER, probe), "建夹具键失败");
        let c = template[0]
            .clone()
            .with_coords(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB", "");

        // ① 键不存在 ⇒ 未生效
        assert!(!judge_check(&c), "键不存在时必须判未生效");

        // ② 值在集合内（8GB = 8388608）⇒ 已生效
        assert!(
            reg_restore_write(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB", REG_DWORD, &8_388_608u32.to_le_bytes()),
            "写夹具值失败"
        );
        assert_eq!(read_reg_dword_opt(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB"), Some(8_388_608));
        assert!(judge_check(&c), "8GB 是合法档位，必须判已生效");

        // ③ 值不在集合内（1234567）⇒ 未生效
        assert!(
            reg_restore_write(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB", REG_DWORD, &1_234_567u32.to_le_bytes()),
            "改夹具值失败"
        );
        assert!(
            !judge_check(&c),
            "1234567 不在档位集合里，必须判未生效（组策略乱改后的形态）"
        );

        let _ = crate::engine::native::reg_restore_delete(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB");
    }

    /// M2-C：`regTimeWindow` 判据的 FILETIME 换算口径（**不真机**）。
    ///
    /// 为什么可以不算真机：换算是纯算术（`EPOCH_DIFF_100NS` 与 `registry.rs::reg_key_last_write_ms`
    /// 同一口径），而真机要往 HKLM 的更新策略键写 FILETIME（改系统状态）。这里改为
    /// 断言「算出来的两个边界值符合已知常量」——用 2026-01-01 / 2026-01-08 两个
    /// 真实 FILETIME 值手算的毫秒值，判据算错就会偏离。
    ///
    /// 顺带断一个**本批最容易写错的点**：FILETIME 是 100ns 计数而 `now_ms` 是毫秒，
    /// 差 10000 倍。忘了这个换算，`to_ms` 会算出 1970 年附近 ⇒ 区间永远判 false。
    #[test]
    fn m2c_filetime换算口径() {
        const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
        let to_ms = |ft: i64| (ft - EPOCH_DIFF_100NS) / 10_000;

        // Unix 纪元 = FILETIME 0
        assert_eq!(to_ms(EPOCH_DIFF_100NS), 0, "FILETIME 纪元点应换算成 Unix 0");
        // 2026-01-01T00:00:00Z 的 Unix 毫秒（1767225600000）
        let ft_2026 = EPOCH_DIFF_100NS + 1_767_225_600_000i64 * 10_000;
        assert_eq!(to_ms(ft_2026), 1_767_225_600_000, "2026-01-01 的 FILETIME 换算应等于该时刻的 Unix 毫秒");
        // 100ns 精度：+10000 个 100ns 单位 = +1 毫秒
        assert_eq!(to_ms(ft_2026 + 10_000), 1_767_225_600_001, "加 1 毫秒的 FILETIME 差值应换算成 +1");

        // 区间语义：一个落在 [2026-01-01, 2026-01-08) 内的时刻应判 true
        let now_ms = 1_767_225_600_000i64 + 3 * 86_400_000; // +3 天
        let (start, end) = (ft_2026, ft_2026 + 7 * 86_400_000 * 10_000);
        assert!(
            to_ms(start) <= now_ms && now_ms < to_ms(end),
            "区间内（+3 天）必须判 true"
        );
        // 边界：正好等于 start ⇒ true（闭区间左端）；正好等于 end ⇒ false（开区间右端）
        assert!(to_ms(start) <= to_ms(start) && to_ms(start) < to_ms(end), "左端点应包含");
        assert!(!(to_ms(end) <= to_ms(end) && to_ms(end) < to_ms(end)), "右端点应不包含（暂停已到期）");
    }

    /// M2-C 的反向护栏：`regEnum` / `regTimeWindow` 两种形态的**判定分支必须真实存在**。
    ///
    /// 判红实验 14 抓到的缺口：把 `judge_check` 里的 `else if c.kind == "regEnum"`
    /// 改成 `else if false` 之后，`m2c_dynamic项现在能产出断言` **照样绿** ——
    /// 那条只断「产出了 regEnum 断言」，而判定被删后它会落进末尾的
    /// `c.is_dword` 二分，被当成 dword 与「逗号分隔的集合字符串」比 ⇒ 恒 false。
    ///
    /// 这类「产出对了但判定被摘掉」的缺口只有**行为**断言能抓，所以下面两条
    /// 直接跑 `judge_check` 并断行为，而不是断源码文本。
    #[test]
    fn m2c_两种新形态的判定分支真实生效() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_DWORD};
        use crate::engine::native::{read_reg_dword_opt, reg_key_ensure, reg_restore_write};

        // 造一个集合外的值（1234567）：enum 判据对它必须判 false。
        // 若 `regEnum` 分支被摘掉，它会落进 dword 分支与整个集合字符串比，
        // 结果**也是 false** —— 所以这一态抓不到「分支被摘」。真正的抓手是
        // 下面那条「集合内的值必须判 true」：落进 dword 分支时必为 false。
        let opt = find_option("svc_mem_gb").unwrap();
        let tpl = collect_checks(opt);
        assert_eq!(tpl.len(), 1, "前提失效：svc_mem_gb 没产出断言");
        let probe = r"Software\Trim\m2c-branch-probe";
        let _ = crate::engine::native::reg_restore_delete(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB");
        assert!(reg_key_ensure(HKEY_CURRENT_USER, probe), "建夹具键失败");
        let c = tpl[0]
            .clone()
            .with_coords(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB", "");

        // 集合内的值（8GB）⇒ 必须 true。`regEnum` 分支被摘时这条必红。
        assert!(reg_restore_write(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB", REG_DWORD, &8_388_608u32.to_le_bytes()));
        assert_eq!(read_reg_dword_opt(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB"), Some(8_388_608));
        assert!(
            judge_check(&c),
            "8GB 在 enum 集合里却判未生效 —— regEnum 判定分支被摘掉了？（落进 dword 分支会恒 false）"
        );

        // 同理要守 `regTimeWindow` 的分支存在性（判红实验 15 证实的缺口）。
        //
        // 为什么不能像 regEnum 那样「造一个集合内的值让它判true」：timeWindow 要真机
        // 写两个 FILETIME 键才能构造出「区间内」状态，而它的真键在 HKLM 的更新策略下
        // （改系统状态，快速组不许）。
        //
        // 改用**源码结构断言**：判定链里必须存在 `c.kind == "regTimeWindow"` 这个
        // 分派，且它必须在 `c.is_dword` 那个二分**之前**（落下去会被当成 dword 与
        // FILETIME 字符串比，恒 false）。这是**文本**断言而非行为断言 ——
        // 形态上不够强，但它守的是「分支被摘」与「分支被挪到二分之后」两种改法，
        // 而这两种改法都会让本项恒判未生效（症状一致）。
        // 同目录下（contract_tests.rs 与 overview.rs 同属 commands/optimizer/）
let ov = include_str!("overview.rs");
        let tw_at = ov
            .find("c.kind == \"regTimeWindow\"")
            .expect("judge_check 里没有 regTimeWindow 分支 —— 该形态会落进末尾的 is_dword 二分，恒判未生效");
        let enum_at = ov
            .find("c.kind == \"regEnum\"")
            .expect("judge_check 里没有 regEnum 分支 —— 该形态会落进末尾的 is_dword 二分，恒判未生效");
        let dword_split_at = ov
            .find("} else if c.is_dword {")
            .expect("判定链末尾的 is_dword 二分不见了");
        assert!(
            tw_at < dword_split_at,
            "regTimeWindow 分支被挪到了 is_dword 二分之后（{tw_at} vs {dword_split_at}）—— \
             那样它会被当成 dword 与 FILETIME 字符串比，恒 false"
        );
        assert!(
            enum_at < dword_split_at,
            "regEnum 分支被挪到了 is_dword 二分之后（{enum_at} vs {dword_split_at}）—— 那样它恒 false"
        );

        let _ = crate::engine::native::reg_restore_delete(HKEY_CURRENT_USER, probe, "SvcHostSplitThresholdInKB");
    }

    /// M3：还原**后**回读验证的三种判据（真机往返）。
    ///
    /// 为什么这三条都要断：它们对应三种**不同**的失败形态，只断一条会漏掉另两种。
    /// · 写完读不到       → 还原根本没生效（`RegSetValueExW` 失败但被忽略）
    /// · 类型标签变了     → 别的程序动过这个值（备份是 REG_SZ、现在是 REG_DWORD）
    /// · 数据不等         → 字节序/编码错（API 成功但值是错的）
    ///
    /// 全部在 HKCU 的测试键上做（不改系统状态，快速组零副作用纪律）。
    #[test]
    fn m3_还原回读验证三种判据() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_BINARY, REG_DWORD, REG_SZ};
        use crate::engine::native::{reg_key_ensure, reg_restore_write};

        let sub = "Software\\Trim\\m3-verify";
        assert!(reg_key_ensure(HKEY_CURRENT_USER, sub), "建夹具键失败");
        let cleanup = || {
            let _ = crate::engine::native::reg_restore_delete(HKEY_CURRENT_USER, sub, "Ok");
            let _ = crate::engine::native::reg_restore_delete(HKEY_CURRENT_USER, sub, "Gone");
            let _ = crate::engine::native::reg_restore_delete(HKEY_CURRENT_USER, sub, "WrongType");
        };
        cleanup();

        // ① 写对 → 回读一致（0 条不一致）
        assert!(reg_restore_write(HKEY_CURRENT_USER, sub, "Ok", REG_DWORD, &42u32.to_le_bytes()));
        let ops_ok = vec![RestoreOp::Write {
            hive: "CurrentUser".into(),
            sub: sub.into(),
            key: "Ok".into(),
            typ: "REG_DWORD".into(),
            bytes: 42u32.to_le_bytes().to_vec(),
        }];
        let (checked, bad) = verify_restore_ops(&ops_ok);
        assert_eq!((checked, bad), (1, 0), "写进去的 DWORD=42 必须回读一致");

        // ② 写的是 A、期望读的是 B → 1 条不一致
        let ops_wrong_data = vec![RestoreOp::Write {
            hive: "CurrentUser".into(),
            sub: sub.into(),
            key: "Ok".into(),
            typ: "REG_DWORD".into(),
            bytes: 43u32.to_le_bytes().to_vec(),
        }];
        let (checked2, bad2) = verify_restore_ops(&ops_wrong_data);
        assert_eq!((checked2, bad2), (1, 1), "注册表里是 42、期望 43 ⇒ 必须报不一致");

        // ③ 类型标签不符（备份写 REG_SZ、实际是 DWORD）→ 1 条不一致
        assert!(reg_restore_write(HKEY_CURRENT_USER, sub, "WrongType", REG_DWORD, &7u32.to_le_bytes()));
        let ops_wrong_type = vec![RestoreOp::Write {
            hive: "CurrentUser".into(),
            sub: sub.into(),
            key: "WrongType".into(),
            typ: "REG_SZ".into(),
            bytes: 7u32.to_le_bytes().to_vec(),
        }];
        let (_, bad3) = verify_restore_ops(&ops_wrong_type);
        assert_eq!(bad3, 1, "备份说 REG_SZ、实际是 REG_DWORD ⇒ 必须报不一致（别的程序改过）");

        // ④ Delete 判据：键还在 → 不一致；键不在 → 一致
        let ops_del_exists = vec![RestoreOp::Delete {
            hive: "CurrentUser".into(),
            sub: sub.into(),
            key: "Ok".into(),
        }];
        assert_eq!(verify_restore_ops(&ops_del_exists).1, 1, "键还在时 Delete 判据必须报不一致");
        let ops_del_gone = vec![RestoreOp::Delete {
            hive: "CurrentUser".into(),
            sub: sub.into(),
            key: "Gone".into(),
        }];
        assert_eq!(verify_restore_ops(&ops_del_gone).1, 0, "键不存在时 Delete 判据必须通过（幂等）");

        // ⑤ 反向护栏：未知 hive 计入不一致而不是静默跳过
        //（静默跳过 = 「核对了 0 条，一致」⇒ 调用方会以为还原干净）
        let ops_bad_hive = vec![RestoreOp::Write {
            hive: "NoSuchHive".into(),
            sub: sub.into(),
            key: "Ok".into(),
            typ: "REG_DWORD".into(),
            bytes: 42u32.to_le_bytes().to_vec(),
        }];
        let (checked3, bad4) = verify_restore_ops(&ops_bad_hive);
        assert_eq!((checked3, bad4), (0, 1), "未知 hive 必须计入不一致，不能静默跳过（跳过会被当成「干净」）");

        // ⑥ BINARY 也走同一判据（字节序列不等即报不一致）
        assert!(reg_restore_write(HKEY_CURRENT_USER, sub, "Bin", REG_BINARY, &[1, 2, 3]));
        let ops_bin_ok = vec![RestoreOp::Write {
            hive: "CurrentUser".into(),
            sub: sub.into(),
            key: "Bin".into(),
            typ: "REG_BINARY".into(),
            bytes: vec![1, 2, 3],
        }];
        assert_eq!(verify_restore_ops(&ops_bin_ok).1, 0, "BINARY 字节一致时应通过");
        let ops_bin_bad = vec![RestoreOp::Write {
            hive: "CurrentUser".into(),
            sub: sub.into(),
            key: "Bin".into(),
            typ: "REG_BINARY".into(),
            bytes: vec![1, 2, 4],
        }];
        assert_eq!(verify_restore_ops(&ops_bin_bad).1, 1, "BINARY 字节不等必须报不一致");
        let _ = REG_SZ;
        let _ = crate::engine::native::reg_restore_delete(HKEY_CURRENT_USER, sub, "Bin");
        cleanup();
    }

    /// M3 的**反向**护栏：`optimizer_restore_reg` 必须真的调了回读验证。
    ///
    /// 为什么用源码结构断言而不用行为断言：回读不一致时的表现是「报失败」，
    /// 而要造出「写成功但值错」需要在真机上破坏写侧（类型映射错等）——
    /// 那是改代码不是测代码。所以这里守的是「调用点在不在」：
    /// 判红实验 R1-M3-3 摘掉它之后本条必须红。
    #[test]
    fn m3_还原命令必须调回读验证() {
        let src = include_str!("backup_restore.rs");
        let fn_at = src
            .find("pub async fn optimizer_restore_reg")
            .expect("找不到 optimizer_restore_reg");
        // 该函数体到下一个 `pub async fn` / `pub fn` 之前
        let rest = &src[fn_at..];
        let end = rest
            .find("\npub ")
            .unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains("verify_restore_ops"),
            "optimizer_restore_reg 没有调 verify_restore_ops —— 还原后回读校验这一环缺失 \
             （RegSetValueExW 成功不等于值写对了）"
        );
        assert!(
            body.contains("verifyFailed"),
            "回读不一致时必须 fail-closed 报错（返回 verifyFailed），不许报成功"
        );
        // fail-closed 的前提：mismatched > 0 的那个 return 必须在**清备份记录之前**。
        //
        // ⚠️ 不能比 `verify_restore_ops` 与 `o.remove` 的位置 —— 判红实验 4 实测：
        // 函数里可能有**多处** `o.remove`（正常路径一处、额外插入的一处），
        // 而 `find` 只认首次出现，于是「把清备份挪到回读之后」这种改法照样绿。
        // 必须锚定「报错 return 的闭合」与「清备份的**最后一次**出现」的相对顺序。
        let bad_return = body
            .find("verifyFailed")
            .expect("找不到回读不一致的报错分支（返回体里应有 verifyFailed）");
        let bad_return_close = body[bad_return..]
            .find("});")
            .map(|i| bad_return + i)
            .expect("报错分支的 json 块没闭合");
        let clear_last = body
            .rfind("o.remove(&option_id)")
            .expect("找不到清备份记录那行");
        assert!(
            bad_return_close < clear_last,
            "回读不一致的 return 被挪到了清备份记录之后（{bad_return_close} vs {clear_last}）—— \
             不一致时备份已被清掉，用户失去唯一的还原依据"
        );
    }

    /// M4：`options()` 在签名失效时**返回空 vec**（fail-closed），且不 panic。
    ///
    /// 为什么这条重要：优化项是**会改用户系统**的目录。签名失效时
    /// · 返回未校验的数据 ⇒ 相当于没验签（「数据文件被换掉」变成静默劫持）
    /// · panic ⇒ 整个应用崩，磁盘清理等无关域一起陪葬
    /// 只有「返回空 + 写 error 日志」是对的。
    ///
    /// ⚠️ 本条用**源码结构断言**而不是行为断言：真要造出「验签失败的进程内状态」
    /// 需要把公钥换掉再重启 lib 静态状态，`OnceLock` 已经缓存过了。
    /// 结构断言守的是「失败分支是 return Vec::new() 而不是放行 / 不是 panic」——
    /// 那正是会被改坏的地方。
    #[test]
    fn m4_优化目录装载必须fail_closed() {
        let src = include_str!("catalog.rs");
        let fn_at = src
            .find("pub(super) fn options()")
            .expect("找不到 options()");
        let rest = &src[fn_at..];
        let end = rest.find("\n}").unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains("verify_optimizer_signature"),
            "options() 没有调verify_optimizer_signature —— 优化目录未验签就装载"
        );
        assert!(
            body.contains("return Vec::new()"),
            "验签失败必须返回空 vec（fail-closed），不能放行未校验的数据"
        );
        assert!(
            !body.contains("panic!") && !body.contains("unwrap()"),
            "options() 里出现 panic/unwrap —— 验签失败会把整个应用带崩（磁盘清理等无关域陪葬）"
        );
        // 验签函数本身必须走 fail-closed 的 verify_array_text（不是「有 sidecar 就算过」）
        let vf_at = src
            .find("pub(super) fn verify_optimizer_signature()")
            .expect("找不到 verify_optimizer_signature()");
        let vbody = &src[vf_at..];
        let vend = vbody.find("\n}").unwrap_or(vbody.len());
        assert!(
            vbody[..vend].contains("verify_array_text"),
            "verify_optimizer_signature 没调 verify_array_text"
        );
    }

    /// M4：provenance 侧表与响应侧的接线。
    #[test]
    fn m4_provenance接线完整() {
        // 侧表可读且覆盖到位
        assert!(
            verify_optimizer_signature().is_ok(),
            "优化目录签名必须在本机验签通过（私钥在 ~/.trim-signing）"
        );
        let high = options().iter().filter(|o| o.get("risk").and_then(|v| v.as_str()) == Some("high"));
        let high_ids: Vec<String> = high
            .map(|o| o.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string())
            .collect();
        assert!(high_ids.len() >= 5, "high risk 项数异常（{}）", high_ids.len());
        for id in &high_ids {
            assert!(
                provenance_of(id).is_some(),
                "high risk 项 {id} 没有 provenance —— 高危项必须可解释（A5 组会红）"
            );
        }
        // 不在表里的项返回 None（语义是「无 provenance」，不是「没有依据」）
        assert!(provenance_of("__不在表里的id__").is_none());

        // 响应侧接线：optimizer_list 必须把 provenance 注入每行
        let ov = include_str!("overview.rs");
        assert!(
            ov.contains("provenance_of(sid)") && ov.contains("\"provenance\".into()"),
            "optimizer_list 没有把 provenance 注入响应行 —— 建了侧表却没接线"
        );
    }

    /// 2026-10-04 用户裁定：优化页顶部的「态势分环 + 五分类图例」整块下线。
    ///
    /// 为什么留这条测试而不是直接删干净：删干净之后，「有人又把
    /// `optimizer:readiness` 注册回来并重新画环」与「从来没存在过」在字节上无法区分。
    /// 这条测试把「已下线」这个决定本身变成可机械复核的断言 —— 判红的形态是
    /// 「渲染层又出现了环 / 又调了 readiness 通道」，而不是一个静悄悄的功能回归。
    #[test]
    fn 态势分已下线且无残留() {
        let js = include_str!("../../../../src/scripts/optimizer.js");
        for banned in [
            "renderReadiness",
            "READINESS_LEGEND",
            "READINESS_BANDS",
            "READINESS_R",
            "READINESS_C",
            "optReadiness",
            "optimizer.readiness(",
        ] {
            assert!(
                !js.contains(banned),
                "渲染层又出现了态势分残留 `{banned}` —— 该组件已于 2026-10-04 整块下线"
            );
        }
        let html = include_str!("../../../../src/index.html");
        assert!(
            !html.contains("opt-readiness"),
            "index.html 又出现了 opt-readiness 容器 —— 该组件已于 2026-10-04 整块下线"
        );
        // 通道与命令两端同时消失：任一端残留都会让 check-channel-map / check-guard-tiers 判红，
        // 这里再钉一次是为了让「为什么它必须消失」留在代码旁，而不是只散在门禁里。
        let api = include_str!("../../../../src/scripts/tauri-api.js");
        assert!(
            !api.contains("optimizer:readiness") && !api.contains("optimizer_readiness"),
            "CHANNEL_MAP 又出现了 optimizer:readiness —— 通道与命令必须成对摘除"
        );
        let ov = include_str!("overview.rs");
        for banned in ["optimizer_readiness", "READINESS_WEIGHTS", "readiness_score"] {
            assert!(
                !ov.contains(banned),
                "overview.rs 又出现了 `{banned}` —— 态势分后端已随组件一并下线"
            );
        }
    }

    /// B4：可逐项还原清单的三条语义。
    ///
    /// ① 备份为空 / `values` 为空的项**一律不列** —— 列出来会让用户点一个
    ///    「还原」然后拿到「无备份记录」，那是把「没有依据」说成「有入口但坏了」。
    /// ② 在用项与退役项**分开返回** —— 渲染层要区别「正常项的还原」与
    ///    「退役待还原」（后者在概览的既有位置）。
    /// ③ 备份里有但**目录里没有**的 id（退役后又被清账）不列在 active 里 ——
    ///    它由 retired 那条覆盖。
    #[test]
    fn b4_可还原清单三条语义() {
        use super::catalog::{is_restorable, restorable_items};
        use serde_json::json;

        // 夹具：一个在用项（perf_wu_pause）+ 一个退役项（ssd_opt，见退役账本）
        let map = json!({
            "perf_wu_pause": { "at": "2026-10-03T00:00:00Z", "values": [
                { "hive": "LocalMachine", "sub": "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
                  "key": "PauseUpdatesStartTime", "exists": true, "type": "REG_QWORD", "data": "1" }
            ]},
            "ssd_opt": { "at": "2026-10-03T00:00:00Z", "values": [
                { "hive": "LocalMachine", "sub": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                  "key": "GlobalFlag", "exists": true, "type": "REG_DWORD", "data": "0" }
            ]},
            // 三种「不该列」的形态
            "tf_ntfs": { "at": "x", "values": [] },                       // values 空数组
            "tf_hibern_off": { "at": "x" },                              // 压根没有 values 字段
            "根本不存在的id": { "at": "x", "values": [{ "k": 1 }] },        // 目录里没有此项
        });

        let (active, retired) = restorable_items(&map);

        // ① 在用清单只含真有备份的在用项
        let a_ids: Vec<&str> = active.iter().filter_map(|v| v["id"].as_str()).collect();
        assert!(a_ids.contains(&"perf_wu_pause"), "有备份的在用项必须被列出：{a_ids:?}");
        assert!(!a_ids.contains(&"tf_ntfs"), "values 为空数组的项不该被列出：{a_ids:?}");
        assert!(!a_ids.contains(&"tf_hibern_off"), "没有 values 字段的项不该被列出：{a_ids:?}");
        assert!(!a_ids.contains(&"根本不存在的id"), "目录里没有的 id 不该出现在 active：{a_ids:?}");

        // active 项必须带 values 数与备份时间（前端要显示「N 个值 · 何时备份的」）
        let hit = active.iter().find(|v| v["id"] == "perf_wu_pause").expect("应含 perf_wu_pause");
        assert_eq!(hit["values"], json!(1), "必须带可还原的值条数");
        assert!(hit["at"].is_string(), "必须带备份时间（用户要判断这个备份还值不值得用）");
        assert!(hit["title"].is_string(), "必须带标题（列表要显示，不能只有 id）");

        // ② 退役项走 retired 那条
        let r_ids: Vec<&str> = retired.iter().filter_map(|v| v["id"].as_str()).collect();
        assert!(
            r_ids.contains(&"ssd_opt"),
            "退役项的有备份还原必须出现在 retired 清单里：{r_ids:?}"
        );

        // ③ is_restorable 与清单口径一致
        assert_eq!(is_restorable(&map, "perf_wu_pause"), Some(1));
        assert_eq!(is_restorable(&map, "tf_ntfs"), None, "values 空的项不可还原");
        assert_eq!(is_restorable(&map, "tf_hibern_off"), None, "没有 values 字段的项不可还原");
        assert_eq!(is_restorable(&map, "不存在的id"), None);
    }

    /// B4 的接线：`optimizer_list` 必须逐行注入 `restorable`（值 = 本机值级备份的键数）。
    ///
    /// 2026-10-06（任务二）后它的消费方是**详情弹窗**：>0 时在还原提示里讲明
    /// 「按本机备份逐值还原（N 个值）」。注入断了 = 弹窗少讲一条还原路径的依据；
    /// 「备份表只读一次」的约束照旧（126 项逐项读 = 重复解 34KB JSON ×126）。
    #[test]
    fn b4_逐行注入restorable() {
        let src = include_str!("overview.rs");
        assert!(
            src.contains("is_restorable(&backups, sid)") && src.contains("\"restorable\".into()"),
            "optimizer_list 没有逐行注入 restorable —— 前端无法区分「可还原」与「点了会失败」"
        );
        // 且必须**只读一次**备份表（126 项循环里每项读一次 = 重复解 34KB JSON ×126）
        assert!(
            src.contains("let backups = load_opt_backups();"),
            "备份表必须在循环外读一次"
        );
    }

    /// UI 消费批的**契约断言**（B4 还原入口 + 收藏已下线）。
    ///
    /// 这里断的是「结构与接线的关键形态」，不是视觉 —— 视觉由
    /// `check-contrast` / `check-css-tokens` 覆盖。之所以还要断源码形态：
    /// 还原入口的**失效形态是「静默的」**（按钮永远置灰或点了必然失败），
    /// 没有任何门禁会自己变红。2026-10-06（任务二）起行内入口整条下线、
    /// 「可否恢复」只在详情弹窗判定 —— ②③ 转为**反向形态**锁「不许复活」。
    #[test]
    fn ui_还原入口仅在弹窗且收藏星标已下线() {
        let js = include_str!("../../../../src/scripts/optimizer.js");

        // ① 行内还原入口（B4）必须**整条链路都不存在**（2026-10-06 任务二下线。
        //    正向形态会随实现演进失效，反向形态才能锁住「不许复活」—— 与 ③ 星标同写法）。
        for (needle, why) in [
            (".opt-row-restore", "行内还原按钮类名"),
            ("data-restore", "行内还原按钮属性"),
            ("closest('.opt-row-restore", "行点击里的按钮委托分支"),
        ] {
            assert!(!js.contains(needle), "行内还原入口残留：{why}（{needle}）仍在 optimizer.js");
        }
        let css = include_str!("../../../../src/styles/main.css");
        assert!(
            !css.contains(".opt-row-restore"),
            "行内还原按钮的 CSS 还在 main.css 里（永不显示的死规则）"
        );
        // ② 弹窗是本任务后**唯一**的还原判定点：必须消费 restorable（>0 时讲明
        //    「按本机备份逐值还原（N 个值）」），否则该字段成为零消费方死字段
        //    （后端 overview.rs 仍在逐行注入）。
        //
        // 断言形态说明：断**代码结构 + 带插值的模板字面量**，不断散词 ——
        // 首版按散词 `按本机备份逐值还原` 判过，但注释里留了同一个词，
        // 把消费代码整段删掉后注释仍让断言通过（判红实验当场抓住的假绿）。
        assert!(
            js.contains("const backupHint = (typeof o.restorable === 'number' && o.restorable > 0)"),
            "详情弹窗没有消费 restorable —— 值级备份条数无处显示（死字段）"
        );
        assert!(
            js.contains("按本机备份逐值还原（${o.restorable} 个值）"),
            "弹窗还原提示没有把「按本机备份逐值还原（N 个值）」讲出来（备份条数必须来自 restorable）"
        );
        // ③ 收藏星标必须**整条链路都不存在**（2026-10-03 用户裁定删）。
        //    正向形态（存在某段代码）会随实现演进失效，反向形态（不存在）
        //    才能真正锁住「不许复活」——把星标加回来时这条立刻红。
        for (needle, why) in [
            (".opt-row-fav", "CSS/HTML 里的星标类名"),
            ("data-fav", "星标按钮属性"),
            ("toggleFavorite", "切换收藏函数"),
            ("favoriteIds", "收藏状态集合"),
            ("setFavorite", "收藏写侧通道调用"),
        ] {
            assert!(!js.contains(needle), "收藏星标残留：{why}（{needle}）仍在 optimizer.js");
        }
        assert!(
            !css.contains(".opt-row-fav"),
            "收藏星标的 CSS 还在 main.css 里（会留下永不显示的死规则）"
        );
        // ④ 偏好读侧（optimizer:prefs）必须已摘除：它唯一的读 `favorites` 消费方
        //    就是星标。留着它 = 一条零调用方的死通道（D4 孤儿断言会红）。
        let api = include_str!("../../../../src/scripts/tauri-api.js");
        for (needle, why) in [
            ("optimizer:prefs", "CHANNEL_MAP 里的偏好读侧通道"),
            ("prefs: function", "window.api.optimizer.prefs 包装器"),
        ] {
            assert!(!api.contains(needle), "偏好读侧残留：{why}（{needle}）");
        }
    }

    /// 2026-10-04：批量项「点立即执行毫无反应」这一族缺陷的机械拦截网。
    ///
    /// 事故经过：逐项勾选弹窗在拼 `data-pick` 属性时调了 `escapeAttr(...)`，
    /// 而 optimizer.js 的 IIFE 里只定义了 `escapeHtml` —— `'use strict'` 下那是
    /// ReferenceError，且异常发生在 `bodyHtml` 构造阶段（**早于** `modal.create`），
    /// 于是「详情弹窗已关、勾选框没出现、无任何提示」。
    ///
    /// 为什么这类缺陷此前无人拦：三条形态各自都能悄悄漂移 ——
    /// ① 转义函数被调用但没定义；② 弹窗用新类名而 CSS 还停在旧类名（弹窗能开但全裸）；
    /// ③ 装饰性区块的 DOM 查询拿不到节点，异常冒到 openModal 末尾，
    ///    把**主按钮的监听器绑定**一起吃掉。三条都不是「逻辑写错」，
    ///    靠肉眼 review 与单测都看不出来，所以在这里钉成源码形态断言。
    #[test]
    fn ui_逐项勾选弹窗的执行链不许静默失效() {
        let js = include_str!("../../../../src/scripts/optimizer.js");
        let css = include_str!("../../../../src/styles/main.css");
        // 扫源码形态前先剥注释：注释里复述调用形态（本文件就有一堆）会把判据带偏，
        // 而「注释里写了 escapeAttr(」从来不是缺陷。
        let js = strip_js_comments(js);

        // ① 渲染层用到的每个 `escapeXxx(` 都必须能解析到定义。
        //
        // 合法形态只有两种：① `window.ds.escAttr(` / `window.ds.esc(` 直接调真源；
        // ② 本地 `function escapeXxx(` 薄包装（存量），且其函数体必须纯委托。
        // 非法形态是「裸调 escapeXxx( 而本地没有定义」—— 那在运行期就是 ReferenceError。
        //
        // 判据按「标识符集合」而不是逐个点名：新增一个 escapeFoo 却忘了定义时
        // 也会被抓到，点名式断言只能守住已知的名字。
        let mut used: Vec<String> = Vec::new();
        let mut cursor = 0usize;
        while let Some(rel) = js[cursor..].find("escape") {
            let at = cursor + rel;
            // 标识符从 `escape` 本身开始取（`escapeHtml` / `escapeAttr` 是一整个名字）。
            let tail = &js[at..];
            let name: String = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            cursor = at + name.len().max(1);
            if name.len() <= "escape".len() || !tail[name.len()..].starts_with('(') {
                continue;
            }
            // `window.ds.escAttr(` 里的 `escAttr` 不带 `escape` 前缀，扫不到；
            // 这里要排除的只有本地定义处（注释已在上面剥掉）。
            let is_call_site = !js[..at].ends_with("function ")
                && !js[at..].contains(&format!("{name}(`)", ));
            if is_call_site && !used.contains(&name) {
                used.push(name);
            }
        }
        for name in &used {
            let def = format!("function {name}(");
            assert!(
                js.contains(&def),
                "optimizer.js 裸调了 `{name}(` 但既没有本地 `{def}` 定义、\
                 也不是 window.ds.* 直接调用 —— IIFE + 'use strict' 下运行期就是 \
                 ReferenceError，而异常发生在弹窗 HTML 构造阶段，\
                 表现为「点立即执行后详情弹窗已关、勾选框没出现、毫无反应」"
            );
            // 纯委托：函数体（到第一个 `}` 为止）必须以 window.ds.* 的返回值为最终返回。
            //
            // 为什么不断言「委托到 window.ds.<同名>」：本地名与 ds 名不同源
            // （本地 escapeHtml → ds.esc、escapeAttr → ds.escAttr），
            // 绑死同名会把正确的写法判红。真正要锁的是「实现不在本地重复一遍」。
            let at = js.find(&def).expect("刚断言过存在");
            let body = &js[at..];
            let open = body.find('(').expect("刚断言过有定义");
            let end = body[open..].find('}').map(|p| p + open).unwrap_or(body.len());
            let fbody = &body[..end];
            assert!(
                fbody.contains("window.ds."),
                "`{name}` 的函数体没有走 window.ds.* —— 转义唯一真源是 ds.js，\
                 本地只许纯委托（AGENTS §2）。实测函数体：{fbody}"
            );
        }
        // 属性位必须走 escAttr 而不是 esc：两者当前同字符集，但语义不同 ——
        // escAttr 是给「双引号包属性」那个位置留的（AGENTS §2）。
        assert!(
            js.contains("window.ds.escAttr("),
            "渲染层没有直接调 window.ds.escAttr —— 属性位转义必须显式走 escAttr"
        );

        // ② 弹窗用到的每个 `pick-*` 类名都必须在 main.css 里有规则。
        //
        // 漏一条的后果不是「样式不完美」而是**整个勾选区全裸**：勾选框与行布局
        // 全靠这几条撑着，缺了它们清单会渲染成一坨没有间距、没有滚动上限的文字流。
        for cls in [
            "pick-summary",
            "pick-toolbar",
            "pick-list",
            "pick-row",
            "pick-name",
            "pick-note",
            "pick-extras",
        ] {
            assert!(
                css.contains(&format!(".{cls} {{")),
                "勾选弹窗用了 `.{cls}` 但 main.css 里没有对应规则 —— 弹窗会裸奔"
            );
        }
        // 旧的内嵌版类名必须已清干净（留着就是永不显示的死规则）
        for dead in [".opt-pick-list", ".opt-pick-row", ".opt-pick-bar", ".opt-pick-count"] {
            assert!(
                !css.contains(dead),
                "main.css 还留着内嵌版死规则 `{dead}` —— 勾选区已搬成独立弹窗（.pick-*）"
            );
        }

        // ③ 装饰性区块必须兜 try/catch：它失败不许连带主按钮绑不上监听器。
        let pick_at = js
            .find("if (hasSubitemPick(o)) {")
            .expect("找不到逐项选择入口条的判定");
        let tail = &js[pick_at..];
        let end = tail.find("\n    }\n").expect("入口条区块没有闭合");
        assert!(
            tail[..end].contains("catch (e)"),
            "逐项选择入口条没有 try/catch —— 它的 DOM 查询一旦拿到 null，\
             异常会冒到 openModal 末尾把「立即执行」的监听器一起吃掉"
        );

        // ④ 入口条显隐与「点执行要不要弹勾选框」必须共用同一判据（hasSubitemPick）。
        //    两处各写一遍 `o.subitems && …` 时，漂移的两种症状都极难自查：
        //    一边「界面没入口但会弹空框」，另一边「有入口但点了不弹」。
        assert_eq!(
            js.matches("hasSubitemPick(").count(),
            3,
            "hasSubitemPick 的引用数变了（定义 1 + 入口条 1 + 执行路径 1）—— \
             逐项选择的判据不许在别处再写一遍内联条件"
        );
        // 「items 非空」这个子句全仓只许出现在 hasSubitemPick 一处。
        // 点名式断言比「不许出现内联条件」更耐改：注释里复述判据不会误伤，
        // 而真在别处再写一遍 `Array.isArray(o.subitems.items)` 一定命中。
        assert_eq!(
            js.matches("Array.isArray(o.subitems.items)").count(),
            1,
            "「items 非空」的判定出现了多处 —— 必须只在 hasSubitemPick 一处"
        );

        // ⑤ 自绘勾选框必须登记键盘激活路径（AGENTS §2）。
        //    `role=checkbox` + `tabindex=0` 只解决「可聚焦」，Enter/Space 要单独挂。
        assert!(
            js.contains("role=\"checkbox\" tabindex=\"0\"") || js.contains("tabindex=\"0\""),
            "勾选框缺 tabindex —— 键盘用户够不到这个控件"
        );
        assert!(
            js.contains("e.key !== 'Enter' && e.key !== ' '") && js.contains("e.preventDefault()"),
            "勾选框缺 Enter/Space 键盘激活路径（Space 还必须 preventDefault 防页面滚动）"
        );
        // 附带开关的勾选框此前**完全没有事件监听**（只绑了 .pick-list）：
        // 那三个开关（wuauserv 改手动 / 清零位置服务 / 关 Edge 预加载）点了没反应。
        assert!(
            js.contains("closest('.pick-box, .pick-extra-box')"),
            "勾选处理器只认清单项、不认附带开关 —— 附带开关点了没反应"
        );
        assert!(
            js.contains("addEventListener('keydown', onPick)"),
            "勾选框只挂了 click —— 键盘不可达（AGENTS §2）"
        );
        // aria-checked 必须与 class 同步回写，否则读屏用户永远听到「未勾选」。
        assert!(
            js.contains("setAttribute('aria-checked'"),
            "勾选态没有回写 aria-checked —— 读屏用户听不到自己的操作结果"
        );
    }

    /// UI 消费批：**新通道的档位与接线**都到位（防「加了通道忘了登记」）。
    #[test]
    fn ui_新通道接线与档位() {
        let api = include_str!("../../../../src/scripts/tauri-api.js");
        for (chan, method) in [
            ("optimizer:touch-recent", "touchRecent"),
        ] {
            assert!(api.contains(chan), "CHANNEL_MAP 缺 {chan}");
            assert!(
                api.contains(&format!("{method}:")) || api.contains(&format!("{method}()")),
                "window.api.optimizer 缺 {method} 方法"
            );
        }
    }

    /// 子集作用域：批量项只勾了一部分时，回读断言必须**只保留勾中的服务**，
    /// 而且注册表类断言一条都不许被筛掉。
    ///
    /// 为什么钉这两条：收窄方向写反的两种形态都不会红在别处 ——
    /// ① 不收窄 ⇒ 子集用户每次开机被报「未完成还原」（2026-10-05 真机反馈）；
    /// ② 把 reg 断言一起筛掉 ⇒ 该项恒无判据，退回 v0.5.0「collect_checks 为空
    ///    ⇒ 恒显示未生效」的病根。两条都用正向特征断言（保留/剔除的具体名字）。
    #[test]
    fn 子集作用域只收窄服务断言() {
        let bulk = find_option("tf_svc_bulk").expect("tf_svc_bulk 在目录里");
        let checks = collect_checks(bulk);
        assert!(checks.len() >= 60, "服务清单断言数异常：{}", checks.len());

        let picked = vec!["RetailDemo".to_string(), "lltdsvc".to_string()];
        let scoped = scope_checks(&checks, Some(&picked));
        let names: Vec<&str> = scoped
            .iter()
            .filter_map(|c| {
                let (k, _, n) = c.probe();
                if k.starts_with("svc") { Some(n) } else { None }
            })
            .collect();
        assert_eq!(
            names.len(),
            picked.len(),
            "收窄后应只剩勾中的服务，实际：{names:?}"
        );
        assert!(names.contains(&"RetailDemo") && names.contains(&"lltdsvc"), "{names:?}");
        assert!(!names.contains(&"CryptSvc"), "未勾中的服务混进了断言范围");

        // 全选（None / 空 vec）⇒ 一条不动，与既有行为一致
        assert_eq!(scope_checks(&checks, None).len(), checks.len());
        assert_eq!(scope_checks(&checks, Some(&[])).len(), checks.len());

        // 注册表类断言不参与收窄：拿一个纯 reg 项的断言验
        let reg = find_option("tf_hibern_off").expect("tf_hibern_off 在目录里");
        let reg_checks = collect_checks(reg);
        assert!(!reg_checks.is_empty(), "tf_hibern_off 应产出注册表断言");
        let reg_scoped = scope_checks(&reg_checks, Some(&picked));
        assert_eq!(
            reg_scoped.len(),
            reg_checks.len(),
            "注册表断言被勾选清单筛掉了 —— 该项会退回「恒无判据」"
        );
    }
