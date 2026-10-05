//! 跨契约面的残留/追踪回归网（v3 D0：无法归属单一契约面，按纪律单独成文）。
//!
//! 这些用例同时盯 list_run 的第三方模块口径、residue 的前缀反查、ownership 状态机、
//! C3 阈值表与 M2 静默知识（B1 构造闸 / B2 分档 / B4 第二证据），
//! 所以它不属于任何单个域文件；glob 引进各域符号是为了让「实现搬走」立刻反映成
//! 编译错误，而不是悄悄少测一条。



use crate::engine::{protect, rules_signature};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;
use super::appx::*;
use super::backup_report::*;
use super::dead::*;
use super::helpers::*;
use super::list_run::*;
use super::ownership::*;
use super::residue::*;
use super::residue_update::*;
    /// P2-D4 的「第三方模块」口径：排除 Windows 目录与本应用自身目录，且前缀命中
    /// 不得跨路径段（C:\Windows.old 不能被 C:\Windows 前缀吃掉）。
    #[test]
    fn third_party_module_scope_excludes_system_and_self() {
        assert!(!is_third_party_module(r"C:\Windows\System32\kernel32.dll"));
        // 边界：Windows.old 不属于 C:\Windows 前缀段，必须算第三方
        assert!(is_third_party_module(r"C:\Windows.old\System32\app.dll"));
        assert!(is_third_party_module(
            r"C:\Program Files\AVAST Software\AV\avcuf64.dll"
        ));
        // 自身目录里的模块不算第三方（拿真机 current_exe 现算，不写死路径）
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let sample = dir.join("self_module.dll");
                assert!(!is_third_party_module(&sample.to_string_lossy()));
            }
        }
        // 非法/无目录形态一律不判第三方（模块枚举不会产这种值，防御性回 false）
        assert!(!is_third_party_module("kernel32.dll"));
    }

    /// U-2 反查的前缀语义：值名以已知 exe 开头（MuiCache `<exe>.xxx` / BAM 完整路径），
    /// 或落在安装目录前缀下；前缀命中不得跨「路径段」误放行。
    #[test]
    fn trace_prefix_hit_matches_exe_and_dir() {
        let exes = vec!["c:\\apps\\foo\\foo.exe".to_string()];
        assert!(trace_prefix_hit("c:\\apps\\foo\\foo.exe.FriendlyAppName", &exes, ""));
        assert!(trace_prefix_hit("c:\\apps\\foo\\foo.exe", &exes, ""));
        assert!(!trace_prefix_hit("c:\\apps\\foobar\\foo.exe", &exes, ""));
        assert!(trace_prefix_hit("c:\\apps\\foo\\helper.exe", &exes, "c:\\apps\\foo"));
        assert!(!trace_prefix_hit("c:\\apps\\foobar\\x.exe", &exes, "c:\\apps\\foo"));
        // 无目录线索时不能放行任意路径
        assert!(!trace_prefix_hit("d:\\elsewhere\\foo.exe", &exes, ""));
    }

    /// reg_value 目标格式往返：`HKCU\<键>::<值名>` 按 rsplit_once("::") 拆，
    /// 值名（完整路径）含 `:` 但不含 `::`，rsplit 保证只切最后一刀。
    #[test]
    fn reg_value_target_roundtrip() {
        let target = r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache::C:\Apps\Foo\Foo.exe.FriendlyAppName";
        let (key, val) = target.rsplit_once("::").unwrap();
        assert!(key.starts_with("HKCU\\") && key.contains("MuiCache"));
        assert_eq!(val, r"C:\Apps\Foo\Foo.exe.FriendlyAppName");
        // 无分隔 → None（执行侧按 skip 处理，不 panic）
        assert!(r"HKCU\Software\Foo".rsplit_once("::").is_none());
    }

    /// collect_program_objects：UninstallString / DisplayIcon 双来源提取 exe；
    /// DisplayIcon 的 `,图标索引` 后缀被剥掉；不存在的安装目录不进 dir。
    #[test]
    fn collect_program_objects_from_cmds() {
        let (exes, dir) = collect_program_objects(
            "",
            r#""C:\Apps\Foo\unins000.exe" /SILENT"#,
            r"C:\Apps\Foo\Foo.exe,0",
        );
        assert!(exes.iter().any(|e| e == r"C:\Apps\Foo\unins000.exe"));
        assert!(exes.iter().any(|e| e == r"C:\Apps\Foo\Foo.exe"));
        assert!(dir.is_none());
    }

    /// msiexec 形态不入 exe 集（msiexec.exe 是系统组件，反查它只会误伤）
    #[test]
    fn collect_program_objects_skips_msiexec() {
        let (exes, _) = collect_program_objects("", r"C:\Windows\System32\msiexec.exe /X{GUID}", "");
        assert!(exes.is_empty(), "msiexec 不该作为程序对象：{exes:?}");
    }

    /// U-1 + A2：内置残留规则库验签 + 整包语义校验自检（数据文件被改而 Node 门禁没跑时，
    /// `cargo test` 这一侧仍会抓住）。校验器就是运行期真身，不是测试专用的第二套口径。
    #[test]
    fn builtin_residue_rules_verify_and_contract() {
        let text = include_str!("../../../data/uninstall-residue-rules.json");
        rules_signature::verify_rules_text(text).expect("内置残留规则库验签失败");
        let v: Value = serde_json::from_str(text).expect("内置残留规则库 JSON 解析失败");
        validate_residue_package(&v).expect("内置残留规则库语义校验未通过");
        let rules = v.get("rules").and_then(|r| r.as_array()).expect("rules 非数组");
        assert!(!rules.is_empty(), "rules 为空");
    }

    /// 夹具由 `node tools/gen-residue-fixture.mjs` 生成，与 `check-residue-rule-contract.mjs`
    /// 的独立实现共用（方案 §4.3 第三步 / §6.1：不跨语言调用，只靠同一组正反例钉口径）。
    /// 任何一侧放宽判定，另一侧就会在这里判红。
    #[test]
    fn residue_validator_matches_shared_fixture() {
        let raw = include_str!("../../../../tools/fixtures/residue-contract.json");
        let f: Value = serde_json::from_str(raw).expect("残留契约夹具解析失败");
        let cases = f["packages"].as_array().expect("夹具缺 packages");
        let mut diff: Vec<String> = Vec::new();
        let mut rejected = 0;
        for c in cases {
            let label = c["label"].as_str().unwrap_or("?");
            let expect_ok = c["ok"].as_bool().unwrap_or(false);
            let got_ok = validate_residue_package(&c["pkg"]).is_ok();
            if !got_ok {
                rejected += 1;
            }
            if got_ok != expect_ok {
                diff.push(format!(
                    "{label}: 夹具要求{}，Rust 判为{}",
                    if expect_ok { "放行" } else { "整包拒绝" },
                    if got_ok { "放行" } else { "拒绝" }
                ));
            }
        }
        assert!(
            cases.len() >= 30 && rejected >= 25,
            "夹具用例数 {}（其中判红 {rejected}）过少，无法覆盖各保护类别",
            cases.len()
        );
        assert!(diff.is_empty(), "语义校验与夹具不一致：\n{}", diff.join("\n"));
    }

    // ==================== C2 所有权状态机 / C3 阈值表 ====================

    fn ids_of(list: &[&str]) -> HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }
    const A_ID: &str = r"HKLM|SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Acme";

    /// 状态机全路径：pending 不被"点击卸载"直接升级成事实；程序消失且安装目录 ENOENT 才
    /// historical；目录还在就不升级；超稳定期回收；重装的 historical 撤销。
    #[test]
    fn ownership_state_machine_only_promotes_on_closed_evidence() {
        let norm = |s: &str| s.to_lowercase();
        let mut doc = ownership::empty_doc();
        assert!(ownership::record_pending(
            &mut doc, A_ID, "Acme", "Acme Corp", r"C:\Program Files\Acme", &[], 1000, norm
        ));
        assert_eq!(doc["owners"].as_array().unwrap().len(), 1);
        assert_eq!(doc["owners"][0]["state"], json!("pending"));
        // 再卸一次同一程序：刷新而不是叠记录
        assert!(ownership::record_pending(
            &mut doc, A_ID, "Acme", "Acme Corp", r"C:\Program Files\Acme", &[], 2000, norm
        ));
        assert_eq!(doc["owners"].as_array().unwrap().len(), 1, "同一 appId 必须刷新");
        assert_eq!(doc["owners"][0]["recordedAt"], json!(2000));

        // ① 程序仍在清单 → 继续 pending
        let exists_all = |_: &Path| true;
        let (p, r) = ownership::rescan(&mut doc, &ids_of(&[A_ID]), 3000, &exists_all);
        assert_eq!((p, r), (0, 0));
        assert_eq!(doc["owners"][0]["state"], json!("pending"));

        // ② 程序消失但安装目录还在 → 不升级（可能是半途退出/别人复用同目录）
        let (p, r) = ownership::rescan(&mut doc, &ids_of(&[]), 3000, &exists_all);
        assert_eq!((p, r), (0, 0), "安装目录仍在时不得升级");
        assert_eq!(doc["owners"][0]["state"], json!("pending"));

        // ③ 程序消失且目录 ENOENT → historical
        let gone = |_: &Path| false;
        let (p, r) = ownership::rescan(&mut doc, &ids_of(&[]), 3000, &gone);
        assert_eq!((p, r), (1, 0));
        assert_eq!(doc["owners"][0]["state"], json!("historical"));
        assert_eq!(doc["owners"][0]["confirmedAt"], json!(3000));

        // ④ 重装：historical 记录撤销（否则会被当成应用数据遗留来源）
        let (p, r) = ownership::rescan(&mut doc, &ids_of(&[A_ID]), 4000, &gone);
        assert_eq!((p, r), (0, 1));
        assert!(doc["owners"].as_array().unwrap().is_empty());

        // ⑤ pending 超稳定期 → 回收（卸载没继续的事实不该永久挂着）
        let mut doc2 = ownership::empty_doc();
        ownership::record_pending(&mut doc2, A_ID, "Acme", "", "", &[], 1000, norm);
        let later = 1000 + ownership::PENDING_TTL_MS + 1;
        let (_, removed) = ownership::rescan(&mut doc2, &ids_of(&[]), later, &exists_all);
        assert_eq!(removed, 1, "超稳定期的 pending 必须回收");
        assert!(doc2["owners"].as_array().unwrap().is_empty());
    }

    /// 忽略清单：既挡住后续再被记录，也让历史里的同一条消失（否则用户忽略了还反复出现）。
    #[test]
    fn ownership_ignore_stops_re_adopting_the_owner() {
        let norm = |s: &str| s.to_lowercase();
        let mut doc = ownership::empty_doc();
        ownership::record_pending(&mut doc, A_ID, "Acme", "", r"C:\Program Files\Acme", &[], 1000, norm);
        ownership::ignore(&mut doc, A_ID, "Acme", 2000, norm);
        assert!(doc["owners"].as_array().unwrap().is_empty(), "忽略后 owners 必须清空该条");
        assert!(ownership::is_ignored(&doc, A_ID, "acme"));
        assert!(
            !ownership::record_pending(&mut doc, A_ID, "Acme", "", "", &[], 3000, norm),
            "被忽略的 owner 不得重新记录"
        );
        // 同显示名、不同 hive 的条目也按名字挡住（同一款程序可能两处都有键）
        assert!(ownership::is_ignored(&doc, "HKCU|SOFTWARE\\x", "acme"));
    }

    /// 上限裁剪只动最旧的 historical，pending 有生命周期意义不被裁；
    /// 全是 pending 且超限时才动 pending（宁可丢历史也不无界增长）。
    /// HiBit §9.1 足迹差分的判据：时序（差集）+ 归属（token）+ 基线可信，三者缺一不可。
    #[test]
    fn footprint_diff_needs_timing_ownership_and_a_trustworthy_baseline() {
        let baseline = vec![
            r"HKCU\Software\Netease".to_string(),
            r"HKCU\Software\7-Zip".to_string(),
        ];
        let current = vec![
            r"HKCU\Software\Netease".to_string(),
            r"HKCU\Software\NETEASEGODLIKE".to_string(),
            r"HKCU\Software\Clash Verge Rev".to_string(),
        ];
        let fresh = footprint::new_keys_since(&baseline, &current);
        assert_eq!(fresh.len(), 2, "基线里没有的两条才算新增: {fresh:?}");
        let owner = json!({
            "displayName": "网易大神",
            "publisher": "Netease",
            "installLocation": r"C:\Games\GodLike",
            "ownedPaths": [r"C:\Games\GodLike\unins000.exe"]
        });
        let toks = footprint::tokens_of(&owner);
        assert!(
            footprint::key_belongs_to(r"HKCU\Software\NeteaseGodLike", &toks),
            "厂商段 + 产品段都在 token 里，这条必须有归属证据: {toks:?}"
        );
        assert!(
            !footprint::key_belongs_to(r"HKCU\Software\Clash Verge Rev", &toks),
            "别家程序的键不能算到这个 owner 头上"
        );
        // 基线缺失或被截断 = 不可信，差分侧必须整条跳过（不能拿半份基线去判"新键"）
        assert!(footprint::baseline_of(&json!({ "state": "historical" })).is_none());
        assert!(footprint::baseline_of(&json!({ "footprint": { "keys": [], "capped": true } })).is_none());
        assert_eq!(
            footprint::baseline_of(&json!({ "footprint": { "keys": ["a"], "capped": false } })),
            Some(vec!["a".to_string()])
        );
        // 结构性容器与 GUID 形态键都不是厂商落点
        for deny in [
            "Microsoft",
            "Classes",
            "WOW6432Node",
            "Policies",
            "RegisteredApplications",
            "appdatalow",
            "14d8c5cd-3d3a-5fb8-8746-849118a754ce",
            "x",
            "",
        ] {
            assert!(!footprint::is_vendor_key(deny), "{deny} 不该被当成厂商键");
        }
        assert!(footprint::is_vendor_key("NeteaseGodLike"));
        assert!(footprint::is_vendor_key("7-Zip"));
    }

    /// 基线写入的两个边界：owner 不在档里不写；超上限必须标 capped（差分侧据此拒产候选）。
    #[test]
    fn footprint_baseline_records_only_known_owner_and_flags_capped() {
        let mut doc = ownership::empty_doc();
        assert!(
            !ownership::set_footprint(&mut doc, "HKCU|X", &[r"HKCU\Software\X".to_string()], 1),
            "档里没有这个 owner 就不该凭空写基线"
        );
        let norm = |s: &str| s.to_lowercase();
        assert!(ownership::record_pending(
            &mut doc, "HKCU|X", "Acme", "", r"C:\Acme", &[], 1000, norm
        ));
        let many: Vec<String> = (0..=footprint::MAX_KEYS_PER_OWNER)
            .map(|i| format!(r"HKCU\Software\K{i}"))
            .collect();
        assert!(ownership::set_footprint(&mut doc, "HKCU|X", &many, 1500));
        let o = &doc["owners"][0];
        assert_eq!(o["footprint"]["capped"], json!(true), "超上限必须如实标截断");
        assert_eq!(
            o["footprint"]["keys"].as_array().unwrap().len(),
            footprint::MAX_KEYS_PER_OWNER
        );
        assert!(
            footprint::baseline_of(o).is_none(),
            "截断的基线不可信，差分必须跳过这一条"
        );
        assert!(ownership::set_footprint(&mut doc, "HKCU|X", &[r"HKCU\Software\Keep".to_string()], 2000));
        assert_eq!(
            footprint::baseline_of(&doc["owners"][0]),
            Some(vec![r"HKCU\Software\Keep".to_string()]),
            "刷新后要能读回，且 capped 标记跟着清掉"
        );
        // 空清单一律拒写：那会把"一个根都没枚举到"伪装成"这台机器没有厂商键"
        assert!(
            !ownership::set_footprint(&mut doc, "HKCU|X", &[], 2500),
            "空基线不能写进去，否则下一轮差分把全部现存键算成新键"
        );
        assert!(
            footprint::baseline_of(&doc["owners"][0]).unwrap().len() == 1,
            "被拒的写入不许留下半份基线"
        );
    }

    /// 真机足迹采集（`#[ignore]`）：三个 Software 根能枚举出厂商键集合，且**同一台机器上
    /// 连读两次的差集为空** —— 差分不稳定就说明采集在漂（排除表没生效或枚举被 cap 截断），
    /// 那这条链产出的"新键"全是假候选。
    #[test]
    #[ignore = "读注册表三个 Software 根，发布前门禁跑"]
    fn vendor_footprint_captures_real_keys_and_is_stable() {
        let a = unsafe { collect_vendor_keys() };
        assert!(
            a.len() >= 20,
            "本机实测三根有上百个顶层键，只取到 {} 条说明枚举或排除表坏了",
            a.len()
        );
        assert!(
            a.iter()
                .all(|k| k.starts_with(r"HKCU\Software\") || k.starts_with(r"HKLM\SOFTWARE\")),
            "目标串必须与执行侧同口径: {a:?}"
        );
        assert!(
            !a.iter().any(|k| k.to_lowercase().contains("\\microsoft")
                || k.to_lowercase().contains("\\classes")),
            "结构性容器漏排除: {a:?}"
        );
        let b = unsafe { collect_vendor_keys() };
        assert_eq!(
            footprint::new_keys_since(&a, &b),
            Vec::<String>::new(),
            "同一台机器连读两次不该差出新键"
        );
    }

    #[test]
    fn ownership_cap_prefers_dropping_oldest_historical() {
        let norm = |s: &str| s.to_lowercase();
        let pid = |i: usize| format!(r"HKLM|SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\P{i}");
        let mut doc = ownership::empty_doc();
        for i in 0..ownership::MAX_RECORDS {
            ownership::record_pending(
                &mut doc, &pid(i), "P", "", &format!(r"C:\Program Files\P{i}"), &[], 1000, norm,
            );
        }
        // ① 安装目录都还在 → 一条都不升级，也不裁（400 条刚好在上限内）
        let (p, r) = ownership::rescan(&mut doc, &ids_of(&[]), 1500, &|_: &Path| true);
        assert_eq!((p, r), (0, 0), "目录还在时不该有升级");
        assert_eq!(doc["owners"].as_array().unwrap().len(), ownership::MAX_RECORDS);

        // ② 越过上限：全部目录消失 → 升级为 historical，同时裁回上限
        ownership::record_pending(&mut doc, &pid(999), "P999", "", r"C:\Program Files\P999", &[], 1500, norm);
        let (p, _) = ownership::rescan(&mut doc, &ids_of(&[]), 1600, &|_: &Path| false);
        assert!(p >= 1, "目录消失后必须升级，实测 {p}");
        assert_eq!(
            doc["owners"].as_array().unwrap().len(),
            ownership::MAX_RECORDS,
            "超限必须裁回上限"
        );

        // ③ 混合形态：新进来的 pending 不许被裁，该裁的是最旧的 historical
        ownership::record_pending(&mut doc, &pid(1000), "Fresh", "", r"C:\Program Files\P1000", &[], 9000, norm);
        let (_, _) = ownership::rescan(&mut doc, &ids_of(&[]), 9500, &|p: &Path| {
            // 只有新记录的目录还在 → 它保持 pending，其余已在清单外且目录消失
            p.to_string_lossy().ends_with("P1000")
        });
        let owners = doc["owners"].as_array().unwrap();
        assert_eq!(owners.len(), ownership::MAX_RECORDS, "仍然超限即裁失败");
        assert!(
            owners.iter().any(|o| o["displayName"] == json!("Fresh") && o["state"] == json!("pending")),
            "新写入的 pending 被裁掉了"
        );
    }

    /// B6：体积兜底必须有界且诚实标注截断；不存在的目录与相对路径不接受。
    /// H5：顺带把命名数据流（ADS）算出来——这条是真跑 `FindFirstStreamW`，
    /// 不是打桩：ADS 的全部意义就是"本体之外还占着多少"，不落到真实文件系统上就验不到。
    #[test]
    fn bounded_dir_size_counts_files_and_flags_partial() {
        let dir = std::env::temp_dir().join(format!("trim-dirsize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub\\deep")).expect("临时目录");
        std::fs::write(dir.join("a.bin"), vec![b'1'; 1024]).expect("写文件");
        std::fs::write(dir.join("sub\\deep\\b.bin"), vec![b'2'; 2048]).expect("写文件");
        // 给 a.bin 挂一条 ADS（下载来源标记就是这个形状）。`文件:流名` 直接 open 即建流。
        let ads_body = b"ZoneId=0\r\nHostUrl=https://example.com/x";
        std::fs::write(dir.join("a.bin:Zone.Identifier"), ads_body.to_vec())
            .expect("写 ADS（非 NTFS 或策略禁用时本用例不适用）");
        let ds = bounded_dir_size(&dir);
        assert_eq!(ds.bytes, 3072, "两文件共 3072 字节: {}", ds.bytes);
        assert_eq!(ds.files, 2, "递归两层应数到两个文件");
        assert!(!ds.partial, "小规模不该报截断");
        assert_eq!(ds.ads_streams, 1, "应当只数到那一条命名流（默认流不计）: {ds:?}");
        assert_eq!(ds.ads_bytes as usize, ads_body.len(), "ADS 字节数必须与写入量一致: {ds:?}");
        // 文件数触顶：只数到上限个、必须标截断（哪个文件先被读到随枚举序变，所以只断上界）
        let ds1 = bounded_dir_size_in(&dir, 1, 8);
        assert_eq!(ds1.files, 1, "文件闸应把计数卡在上限");
        assert!(ds1.bytes < 3072, "截断后不该是完整金额: {}", ds1.bytes);
        assert!(ds1.partial, "有界截断却回 partial=false，UI 就会把半截值当完整值");
        // 层级触顶：sub/deep 在 depth=2，depth_cap=2 时进不去
        let ds2 = bounded_dir_size_in(&dir, 100, 2);
        assert!(ds2.partial, "深度闸命中必须上报截断");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// H6：`Staged` 子树**一个不漏**地进列表，且每一行都不可卸载。
    ///
    /// 期望值不写死、从注册表现算（`reg_enum_subkeys_pub` 与实现走的是同一份枚举）——
    /// 这样"漏读某一层"会当场红，而在没有商店包的机器上也不会靠 `count>0` 假装验过。
    #[test]
    fn appx_store_extras_covers_every_staged_package_and_is_never_removable() {
        use crate::engine::native;
        use std::collections::HashSet;
        use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
        const STORE: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore";

        let mut expected_staged = 0usize;
        let mut sample_family = String::new();
        for fam in native::reg_enum_subkeys_pub(HKEY_LOCAL_MACHINE, &format!(r"{STORE}\Staged")) {
            let kids = native::reg_enum_subkeys_pub(HKEY_LOCAL_MACHINE, &format!(r"{STORE}\Staged\{fam}"));
            if sample_family.is_empty() {
                sample_family = fam.clone();
            }
            expected_staged += kids.len();
        }

        let rows = enum_appx_store_extras(&HashSet::new());
        let staged = rows.iter().filter(|r| r["appxState"] == json!("staged")).count();
        assert_eq!(staged, expected_staged, "Staged 子树漏读（实现数 {staged} / 注册表数 {expected_staged}）");

        // 形状按渲染层消费口径断：`removable===false` 才是前端禁用按钮的判据，
        // 缺这个字段会被当成可卸载，等于把"当前用户删不掉"的包推去执行
        for r in &rows {
            assert_eq!(r["removable"], json!(false), "这一类必须显式不可卸载: {r}");
            let id = r["id"].as_str().unwrap_or("");
            let Some(full) = id.strip_prefix("APPX|") else {
                panic!("id 必须带 APPX| 前缀: {id}");
            };
            assert!(valid_appx_fullname(full), "包全名没过字符集闸: {full}");
            assert!(!r["reason"].as_str().unwrap_or("").is_empty(), "必须交代为什么不可卸载");
            // 发布商这一路是**哈希**不是 CN= 串：裸哈希上屏在厂商列看着像乱码，
            // 而且真机第一版因此把 `Microsoft.Services.Store.Engagement` 归进了「第三方」。
            let publ = r["publisher"].as_str().unwrap_or("—");
            assert!(!publ.contains("wekyb"), "发布商列出现裸哈希: {r}");
            if r["displayName"].as_str().unwrap_or("").to_lowercase().starts_with("microsoft") {
                assert_eq!(r["group"], json!("system"), "微软包被归成第三方: {r}");
            }
        }

        // 去重：已经在当前用户列表里的全名不得再出第二次（同一行出两次会被勾两次）
        if !sample_family.is_empty() {
            let kids = native::reg_enum_subkeys_pub(
                HKEY_LOCAL_MACHINE,
                &format!(r"{STORE}\Staged\{sample_family}"),
            );
            if let Some(first) = kids.first() {
                let mut seen = HashSet::new();
                seen.insert(first.clone());
                let again = enum_appx_store_extras(&seen);
                assert!(
                    again.iter().all(|r| r["id"] != json!(format!("APPX|{first}"))),
                    "seen 里的 {first} 又出了一次"
                );
            }
        }
    }

    #[test]
    fn prefetch_and_icon_parsers_refuse_guessing() {
        assert_eq!(prefetch_entry_exe("OBS64.EXE-2F3A1B4C.pf").as_deref(), Some("OBS64.EXE"));
        assert_eq!(prefetch_entry_exe("obs64.exe-2f3a1b4c.PF"), None, "扩展名大小写形态不认（Prefetch 全大写）");
        assert_eq!(prefetch_entry_exe("OBS64.EXE-2F3A1B4.pf"), None, "哈希位数不对不认");
        assert_eq!(prefetch_entry_exe("OBS64.EXE.pf"), None, "没有哈希段不认");
        assert_eq!(prefetch_entry_exe("readme.txt"), None);
        assert_eq!(exe_name_from_display_icon(r"C:\Apps\Foo\foo.exe,0").as_deref(), Some("FOO.EXE"));
        assert_eq!(exe_name_from_display_icon(r"C:\Apps\Foo\icon.dll,1"), None, "dll 不是主程序");
        assert_eq!(exe_name_from_display_icon(""), None);
    }

    /// C3：阈值表的排序本身就是判据（目录比快捷方式严），三条不许被"顺手统一"成一个数。
    #[test]
    fn name_threshold_table_keeps_risk_ordering() {
        assert!(
            NAME_MIN_SIMILAR > NAME_MIN_SHORTCUT,
            "整棵目录删除的门槛必须高于只删一个 .lnk 的门槛"
        );
        assert!(NAME_MIN_SHORTCUT >= NAME_MIN_RULE_WORD);
        assert_eq!(NAME_MIN_SIMILAR, 5);
        assert_eq!(NAME_MIN_SHORTCUT, 4);
        assert_eq!(NAME_MIN_RULE_WORD, 2, "2 是规则库短词门槛，与「至少两组条件」的 U-1 口径同源");
        // 精确同名那一档必须**低于**互含那一档：它是 HashMap 查表，不是猜测，
        // 沿用 5 会让所有 2-4 字中文产品名从所有权链上消失（2026-09-28 网易大神实测）。
        assert_eq!(NAME_MIN_EXACT, 2);
        assert!(
            NAME_MIN_EXACT < NAME_MIN_SIMILAR,
            "精确同名的容错应比互含猜测宽，不许被\"顺手统一\"回 5"
        );
        // 上限收口后各归一类：名称类 20、侧痕反查 20、exe 收集 16（三处不许再写死字面量）
        assert_eq!(NAME_HIT_CAP, 20);
        assert_eq!(SIDE_TRACE_CAP, 20);
        assert_eq!(PROGRAM_EXE_CAP, 16);
    }

    /// 同名多候选降级：判定依据是「父目录不同」，不是「条数多」——
    /// 同一目录下的多个子项不构成歧义。
    #[test]
    fn ambiguity_is_about_parents_not_counts() {
        assert!(!name_is_ambiguous(&[]));
        assert!(!name_is_ambiguous(&[r"C:\Program Files\Acme\a".to_string()]));
        assert!(
            !name_is_ambiguous(&[
                r"C:\Program Files\Acme\a".to_string(),
                r"C:\Program Files\Acme\b".to_string()
            ]),
            "同一父目录下的多条不构成归属歧义"
        );
        assert!(name_is_ambiguous(&[
            r"C:\Users\x\AppData\Roaming\Acme".to_string(),
            r"C:\Users\x\AppData\Local\Acme".to_string()
        ]));
    }

    /// A4 + A6：规则库目标里的 `%TOKEN%` 没解析出来时，必须报成「变量未解析」，
    /// 不能落到「目标不存在」那条分支上——后者是在告诉用户"这程序没留东西"，
    /// 而真相是"这台机器取不到这个变量"。同时钉住候选带 ruleId（面板要能回答谁产的）。
    #[test]
    fn residue_rule_unexpanded_token_is_reported_not_hidden() {
        let rules = json!({ "rules": [{
            "id": "residue-unexpanded-probe",
            "displayName": ["探针程序"],
            "publisher": ["ProbeSoft"],
            "uninstallKey": [],
            "residue": [
                { "kind": "folder", "target": r"%TRIM_NO_SUCH_VAR%\Data", "note": "未解析变量目标" },
                { "kind": "folder", "target": r"%APPDATA%\ProbeMissing-9f3a", "note": "解析成功但不存在" },
            ],
        }]});
        let (out, vetoed) = residue_rules_hits(&rules, "探针程序", "ProbeSoft", r"Software\X\Uninstall\Probe", false);
        assert!(out.is_empty(), "两条都不该出候选: {out:?}");
        let joined = vetoed.join("\n");
        assert!(
            joined.contains("未解析变量 %TRIM_NO_SUCH_VAR%"),
            "未展开目标必须显式报出变量名，实测 {vetoed:?}"
        );
        // 反面对照：变量解析成功、只是路径不存在 —— 不能被说成变量问题
        assert!(
            !joined.contains("ProbeMissing") && !joined.contains("%APPDATA%"),
            "已解析的目标不该进未解析清单: {vetoed:?}"
        );
        // 命中且存在 → 候选必须带 ruleId（A6）
        let dir = std::env::temp_dir();
        let rules2 = json!({ "rules": [{
            "id": "residue-ruleid-probe",
            "displayName": ["探针程序"],
            "publisher": ["ProbeSoft"],
            "uninstallKey": [],
            "residue": [{ "kind": "folder", "target": dir.to_string_lossy().to_string(), "note": "存在的目录" }],
        }]});
        let (out2, _) = residue_rules_hits(&rules2, "探针程序", "ProbeSoft", r"Software\X\Uninstall\Probe", false);
        assert_eq!(out2.len(), 1, "存在的目标应出候选: {out2:?}");
        assert_eq!(out2[0]["ruleId"], json!("residue-ruleid-probe"), "候选必须带 ruleId: {out2:?}");
    }

    /// 2026-10-04 扩库回归网：每条规则的**匹配条件**必须能在真实卸载项上命中。
    ///
    /// 这条测试守的是与 B2 落点棘轮互补的那一半。落点存在性没法在单测里断言
    /// （依赖具体机器），但「匹配组能不能认出这个程序」是可以完全确定地判的：
    /// 夹具里的 `(displayName, publisher, uninstallKey 末段)` 三元组全部取自
    /// 2026-10-04 本机 `HKLM/HKCU\...\CurrentVersion\Uninstall` 的实读值。
    ///
    /// 为什么要这条：微信 4.x 那次腐坏里，`displayName/publisher/uninstallKey`
    /// 三个条件组**照样命中**（名字还是「微信」、发行商还是腾讯），坏的只有落点。
    /// 也就是说条件组这一侧当时是「绿的」—— 若只靠条件组自检，扩库时把 pattern
    /// 写错（大小写、发行商全称 vs 简称、`uninstallKey` 填了 GUID 前的乱码）
    /// 不会有任何东西变红。落点那侧由 B2 棘轮兜底，条件组这侧就归本测试。
    #[test]
    fn 每条残留规则的匹配组都能认出它的目标程序() {
        // (规则 id, 实读 DisplayName, 实读 Publisher, 实读卸载键末段)
        let cases: &[(&str, &str, &str, &str)] = &[
            ("residue-360safe", "360安全卫士", "奇虎", "360safe"),
            ("residue-eset", "ESET Security", "ESET", "ESET"),
            ("residue-roboform", "RoboForm", "Siber Systems", "RoboForm"),
            ("residue-ccleaner", "CCleaner", "Piriform", "CCleaner"),
            // 微信 4.x：卸载键从 WeChat 改名成 Weixin，实读发行商是「腾讯科技(深圳)有限公司」
            ("residue-wechat", "微信", "腾讯科技(深圳)有限公司", "Weixin"),
            ("residue-qq", "QQ", "腾讯科技(深圳)有限公司", "QQ"),
            ("residue-mailmaster", "网易邮箱大师", "NetEase(Hangzhou) Network Co. Ltd.", "MailMaster"),
            ("residue-hibit", "HiBit Uninstaller 4.0.10.100", "HiBitSoftware", "Uninstaller"),
            ("residue-everything", "Everything 1.4.1.1032 (x64)", "voidtools", "Everything"),
            ("residue-clash-verge", "Clash Verge", "Clash Verge Rev", "Clash Verge"),
            ("residue-douyin", "抖音", "Beijing Microlive Vision Technology Co., Ltd.", "douyin"),
            ("residue-potplayer", "PotPlayer-64 bit", "Kakao Corp.", "PotPlayer64"),
        ];
        let rules = load_residue_rules().expect("内置残留规则库应可装载（验签 + 语义校验）");

        for (id, name, publisher, key_leaf) in cases {
            let rule = rules["rules"]
                .as_array()
                .expect("rules 是数组")
                .iter()
                .find(|r| r["id"] == *id)
                .unwrap_or_else(|| panic!("规则库里没有 {id}"));
            // 判定逻辑直接照抄运行期口径（≥2 组命中，见 residue_update.rs），
            // 不去调 residue_rules_hits —— 那个函数还会按路径存在性过滤落点，
            // 而落点存在性是机器相关的，不该由这条测试负责。
            let norm = |s: &str| -> String {
                s.trim().to_lowercase().replace([' ', '-', '_', '.'], "")
            };
            let contains = |hay: &str, needle: &str| -> bool {
                // 与 residue_update.rs 的 contains2 同口径：pattern 长���须 ≥ 2 字符
                let n = norm(needle);
                n.chars().count() >= NAME_MIN_RULE_WORD && norm(hay).contains(&n)
            };
            // 每个条件组各配各的实读值：拿 DisplayName 去撞 publisher 那组是错的
            // （第一版就踩了这个，写出来免得后人再踩一次）。
            let haystack = |field: &str| -> &str {
                match field {
                    "displayName" => name,
                    "publisher" => publisher,
                    _ => key_leaf,
                }
            };
            let group_hit = |field: &str| -> bool {
                rule[field]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .any(|p| contains(haystack(field), p))
                    })
                    .unwrap_or(false)
            };
            let hits = ["displayName", "publisher", "uninstallKey"]
                .iter()
                .filter(|f| group_hit(f))
                .count();
            assert!(
                hits >= 2,
                "{id} 的匹配条件认不出它的目标程序（只命中 {hits}/3 组）。\
                 实读三元组：DisplayName={name:?} Publisher={publisher:?} 卸载键末段={key_leaf:?}。\
                 少命中一组的后果：该规则在这台机器上永远不出候选，且不会有任何日志"
            );
        }
    }

    /// 运行进程目录判定：候选与进程目录互为祖先/子孙都算在用；大小写与尾随分隔符不许绕过。
    #[test]
    fn running_process_ancestry_blocks_candidates() {
        let mut procs = HashSet::new();
        procs.insert(r"c:\program files\acme\bin".to_lowercase());
        assert!(under_running_process(Path::new(r"C:\Program Files\Acme"), &procs));
        assert!(under_running_process(Path::new(r"C:\Program Files\Acme\bin"), &procs));
        // 候选在运行进程目录**里面**：只查祖先就会漏掉这一半
        assert!(
            under_running_process(Path::new(r"C:\Program Files\Acme\bin\plugins"), &procs),
            "候选位于正在运行的进程目录之内，必须视为在用"
        );
        assert!(!under_running_process(Path::new(r"D:\Data\Other"), &procs));
        // 同盘但毫不相干的目录 —— M4 真机缺陷的回归钉：旧实现走 `dir.ancestors()`，
        // 走到 `C:\` 时任何进程路径都 starts_with 它，于是**全盘恒为在用**，
        // 应用数据遗留链在任何机器上都产不出一个候选（2026-09-29 探针实测暴露）。
        assert!(
            !under_running_process(Path::new(r"C:\Users\x\AppData\Local\SomeLeftover"), &procs),
            "同盘无关目录不得被判成在用"
        );
        // 同级兄弟前缀不许互相污染（裸字符串前缀比就会）
        let mut sib = HashSet::new();
        sib.insert(r"c:\program files\acmebackup".to_string());
        assert!(
            !under_running_process(Path::new(r"C:\Program Files\Acme"), &sib),
            r"按裸前缀比会把兄弟目录 acmebackup 误判进 Acme 的树里"
        );
        // 快照为空（取不到）时不该放行任何候选 —— 由调用方按 None 拒绝扫描
        assert!(!under_running_process(Path::new(r"C:\Program Files\Acme"), &HashSet::new()));
    }

    /// 可弃子目录清单必须与 norm_name 的输出同形（小写、无首尾空白）——
    /// 否则条目永远匹配不上，成了一条静默失效的白名单。
    #[test]
    fn disposable_subdir_names_are_normalized() {
        for name in ORPHAN_DISPOSABLE_SUBDIRS {
            assert_eq!(&norm_name(name), name, "清单里的 {name} 不是归一化形态，永远不会命中");
        }
        assert!(ORPHAN_SCAN_ROOTS.contains(&"LOCALAPPDATA"), "应用数据遗留扫描必须覆盖用户级数据根");
    }

    /// A1 扫描侧硬闸：受保护的注册表目标**不得进候选列表**。
    /// 快照闸只证明「来自上次扫描」，证明不了「不该删」—— 危险候选本来就是扫描器按
    /// 规则产出的，所以收口点必须在产候选这一层（方案 §4.1）。
    #[test]
    fn protected_reg_target_never_becomes_candidate() {
        let pkg = json!({
            "rulesVersion": 20260928,
            "prov": [{ "sourceClass": "test", "reviewedAt": "2026-09-28" }],
            "rules": [{
                "id": "fixture-evil",
                "displayName": ["EvilApp"],
                "publisher": ["EvilCorp"],
                "uninstallKey": ["EvilApp"],
                "residue": [
                    { "kind": "reg_key", "target": "HKLM\\SOFTWARE", "note": "整棵软件配置" },
                    { "kind": "reg_key", "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "note": "自启动" },
                    { "kind": "reg_key", "target": "HKLM\\SYSTEM", "note": "系统配置" }
                ]
            }]
        });
        let (hits, vetoed) = residue_rules_hits(&pkg, "EvilApp 1.0", "EvilCorp", "EvilApp", false);
        assert!(hits.is_empty(), "受保护注册表目标进入了候选列表: {hits:?}");
        assert_eq!(
            vetoed.len(),
            3,
            "三条危险目标都应各自给出否决原因（祖先/命名空间树/整棵禁删各一类）: {vetoed:?}"
        );
    }

    /// HiBit §H3 的全部安全支点：**学习库复用签名库那一个校验器**，不另开一套。
    /// 这条测试就是钉住它——哪天学习库加了自有字段（字段白名单不放）、或改了 kind，
    /// 这里当场红，而不是等装载时在用户机器上把整库隔离掉才发现。
    #[test]
    fn learned_doc_is_valid_under_the_signed_library_validator() {
        let mut doc = learned::empty_doc();
        let entries = vec![
            ("folder", r"C:\Users\me\AppData\Roaming\ProbeSoft\cache".to_string()),
            ("reg_key", r"HKCU\Software\ProbeSoft\Settings".to_string()),
        ];
        let n = learned::learn(
            &mut doc,
            "ProbeSoft 测试程序",
            "ProbeCorp",
            r"Software\X\Uninstall\ProbeSoft",
            &entries,
            1,
        );
        assert_eq!(n, 2, "两条落点都该学到: {doc}");
        validate_residue_package(&doc).expect("学习库文档必须过签名库同一个校验器");
        let rules = doc["rules"].as_array().cloned().unwrap_or_default();
        assert_eq!(rules.len(), 1);
        // 双条件组是 U-1 口径：displayName + uninstallKey 必须都在，缺一组校验器整包拒
        assert!(!rules[0]["displayName"].as_array().unwrap().is_empty());
        assert!(!rules[0]["uninstallKey"].as_array().unwrap().is_empty());
        let id = rules[0]["id"].as_str().unwrap_or("");
        assert!(
            id.starts_with("learned-") && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "学习库 id 不合签名库字符集白名单（中文名不能直接当 id）: {id}"
        );
        // 纯函数侧：坏 JSON 与语义不合都必须是 Err（装载侧据此隔离停用，不尽力解析）
        assert!(learned::from_text("not json").is_err());
        assert!(learned::from_text(r#"{"rulesVersion":1,"prov":[],"rules":[]}"#).is_err());
        assert!(learned::from_text(&doc.to_string()).is_ok(), "learn() 的产物必须能被 load 侧原样接受");
    }

    /// 学习库特有的三道收紧。缺任何一道，本机自采数据都会把「共享容器」或「厂商顶层键」
    /// 学成下次可直接勾选的残留——签名库有人审，学习库没有。
    #[test]
    fn learned_floor_rejects_shared_and_shallow_targets() {
        // token 必须是显示名的**真实小写形态**（`ProbeSoft` → `probesoft`）。第一版手写成
        // `probsoft`（少一个 e），实现被假断言判成错，我围着它调试了两轮 —— 归属类断言的
        // 期望值应由被测的同一条派生链给出，不要手抄字面量。
        let tokens = vec!["probesoft 测试程序".to_string(), "probcorp".to_string()];
        // 归属：路径里没有任何一段属于这程序 ⇒ 不学（Recent 是全家共享容器）
        assert!(learned::target_reject_reason(
            "folder",
            r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Recent",
            &tokens
        )
        .is_some());
        assert!(
            learned::target_reject_reason("folder", r"C:\Users\me\SomeRandomDir", &tokens).is_some(),
            "候选自己的末段不能当归属证据（第一版把 ownedPaths 喂进 token 集就在这里假过）"
        );
        assert!(
            learned::target_reject_reason("folder", r"C:\Users\me\AppData\Roaming\ProbeSoft\cache", &tokens)
                .is_none(),
            "有归属段就该放行，实得拒绝原因: {:?}",
            learned::target_reject_reason("folder", r"C:\Users\me\AppData\Roaming\ProbeSoft\cache", &tokens)
        );
        // 注册表深度：厂商顶层键（hive 之下 2 段）不学，三段才学
        assert!(learned::target_reject_reason("reg_key", r"HKCU\Software\ProbeSoft", &tokens).is_some());
        assert!(learned::target_reject_reason("reg_key", r"HKCU\Software\ProbeSoft\Settings", &tokens).is_none());
        // 禁删面：A1 那条清单**刻意没有深度规则**（有就会误拒 `HKLM\SOFTWARE\ESET` 这类
        // 合法二级产品键），所以 `HKLM\SOFTWARE\ProbeSoft\X` 该放行——它归属成立、深度够。
        // 真正必须拒的是整棵容器与命名空间树这两类。
        assert!(
            learned::target_reject_reason("reg_key", r"HKLM\SOFTWARE", &tokens).is_some(),
            "整棵 SOFTWARE 必须被禁删面拒"
        );
        assert!(learned::target_reject_reason(
            "reg_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            &tokens
        )
        .is_some());
        assert!(learned::target_reject_reason("reg_key", r"HKLM\SOFTWARE\ProbeSoft\X", &tokens).is_none());
        assert!(learned::target_reject_reason("shortcut", r"C:\x\ProbeSoft.lnk", &tokens).is_some());
    }

    /// 证据等级分岔必须**由参数产生**，不能靠产出后再改字段：签名库那条
    /// `defaultChecked: true` 正是靠这条链把候选默认勾上的，学习库若走同一条路，
    /// 「本机猜的」就会被界面当成「官方规则」推荐。
    #[test]
    fn learned_hits_are_never_auto_checked_while_signed_hits_are() {
        // 命中链要求目标**真实存在**（不存在的落点不该出现在面板里，这是生产语义），
        // 所以这里在临时目录下建一个真目录并挂 Drop 清掉；固定假路径会让两条链都空手而归，
        // 断言就退化成「什么都没发生也算过」。
        let dir = std::env::temp_dir().join(format!("trim-learn-{}", std::process::id()));
        let sub = dir.join("ProbeSoftCache");
        std::fs::create_dir_all(&sub).expect("建临时命中目标");
        struct Clean(std::path::PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _clean = Clean(dir.clone());
        let target = sub.to_string_lossy().to_string();

        let doc = json!({
            "rulesVersion": 1.0,
            "prov": [{ "sourceClass": learned::LEARNED_SOURCE_CLASS, "reviewedAt": "本机自采 x" }],
            "rules": [{
                "id": "learned-abc123",
                "displayName": ["ProbeSoft"],
                "publisher": ["ProbeCorp"],
                "uninstallKey": ["ProbeSoft"],
                "residue": [{ "kind": "folder", "target": target, "note": "本机自采" }]
            }]
        });
        let (learned_hits, _) = residue_rules_hits(
            &doc,
            "ProbeSoft",
            "ProbeCorp",
            r"Software\X\Uninstall\ProbeSoft",
            true,
        );
        assert_eq!(learned_hits.len(), 1, "学习库命中链断了: {learned_hits:?}");
        assert_eq!(learned_hits[0]["defaultChecked"], json!(false), "学习库候选不得默认勾选");
        assert_eq!(learned_hits[0]["confidence"], json!("medium"), "学习库证据上限是 medium");
        assert!(
            learned_hits[0]["reason"].as_str().unwrap_or("").contains("本机学习库"),
            "候选必须交代自己是本机学习库而不是官方规则: {}",
            learned_hits[0]["reason"]
        );
        // 同一份文档按签名库口径跑必须还是 high + 默认勾选——参数没分岔就是假绿
        let (signed_hits, _) = residue_rules_hits(
            &doc,
            "ProbeSoft",
            "ProbeCorp",
            r"Software\X\Uninstall\ProbeSoft",
            false,
        );
        assert_eq!(signed_hits.len(), 1);
        assert_eq!(signed_hits[0]["defaultChecked"], json!(true));
        assert_eq!(signed_hits[0]["confidence"], json!("high"));
    }

    /// 学不到东西的情形必须**整条不写**，而不是写一份下一轮会被校验器拒掉的文档。
    #[test]
    fn learn_skips_when_identity_or_targets_are_unusable() {
        let base = |name: &str, publisher: &str, entries: Vec<(&str, String)>| {
            let mut doc = learned::empty_doc();
            learned::learn(&mut doc, name, publisher, r"Software\X\Uninstall\ProbeSoft", &entries, 1)
        };
        assert_eq!(base("ProbeSoft", "ProbeCorp", vec![]), 0, "没有落点不写");
        assert_eq!(base("", "ProbeCorp", vec![("folder", r"C:\x\ProbeSoft".to_string())]), 0, "没有程序名不写");
        // 显示名 + 卸载键末段已经是两组，publisher 空不该把它判死
        assert!(
            base("ProbeSoft", "", vec![("folder", r"C:\x\ProbeSoft".to_string())]) > 0,
            "双条件组应成立"
        );
        // 全部落点过不了归属 ⇒ 一条都不学，且不留空规则（空 residue 会被校验器整包拒）
        let mut doc = learned::empty_doc();
        let n = learned::learn(
            &mut doc,
            "ProbeSoft",
            "ProbeCorp",
            r"Software\X\Uninstall\ProbeSoft",
            &[("folder", r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Recent".to_string())],
            1,
        );
        assert_eq!(n, 0, "无归属落点不该学: {doc}");
        assert!(doc["rules"].as_array().map(|a| a.is_empty()).unwrap_or(false), "不该留下空规则");
    }

    /// D3 + C1：残留执行的单一判定入口（不依赖真机）。判定收进 classify_residue_op 之后，
    /// 一个函数就能把六道只读闸全测到 —— 取代原先只覆盖目录重解析那一段的测试。
    /// D1/D2：备份文件名白名单与封条命名。还原是**写注册表**的通道，
    /// 文件名是唯一决定"读哪个文件去 import"的输入，必须挡住穿越与非 .reg。
    #[test]
    fn reg_backup_name_and_seal_paths_are_narrowed() {
        assert!(valid_uninstall_backup_name("1790561031234_ESET.reg"));
        assert!(valid_uninstall_backup_name("1790561031234_acme_RASAPI32.reg"));
        for bad in [
            "",
            "x.txt",
            "../1_x.reg",
            r"..\..\windows.reg",
            "a/b.reg",
            "a reg.reg",
            "1_x.reg.meta.json", // 封条自身不得被当成备份列出/还原
            &format!("{}.reg", "s".repeat(200)),
        ] {
            assert!(!valid_uninstall_backup_name(bad), "非法文件名被放行: {bad}");
        }
        // 封条同目录、后缀固定：人工核对时一眼能找到，列表按 .reg 收尾天然排除它
        let p = std::path::PathBuf::from(r"C:\x\1_a.reg");
        assert_eq!(
            crate::engine::reg_backup::reg_seal_path_for(&p),
            std::path::PathBuf::from(r"C:\x\1_a.reg.meta.json"),
        );
    }

    #[test]
    fn classify_residue_op_gates_run_before_any_mutation() {
        let skip_msg = |kind: &str, target: &str| -> Option<String> {
            match classify_residue_op(kind, target) {
                OpVerdict::Skip(m) => Some(m),
                OpVerdict::Ready(_) => panic!("{kind} 不该通过判定: {target}"),
                OpVerdict::Abort(m) => panic!("{kind} 不该整批拒绝: {m}"),
            }
        };
        let ghost = std::env::temp_dir().join("trim-no-such-dir-9f3a\\DataStore");
        let ghost_s = ghost.to_string_lossy().to_string();

        // ① 不存在的目录/文件：Skip 且给原因（原先被静默滤掉，批次报告里连一行都没有）
        assert!(skip_msg("folder", &ghost_s).unwrap_or_default().contains("不存在"));
        assert!(skip_msg("file", &ghost_s).unwrap_or_default().contains("不存在"));
        // ② 受保护路径：整批拒绝，不降级成单项跳过。用 %WINDIR% 而不是应用数据目录——
        // 后者只在 `configure_from_app()` 跑过之后才进 subtree 清单，单测环境里没有那一步
        let win = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
        match classify_residue_op("folder", &win) {
            OpVerdict::Abort(m) => assert!(m.contains("受保护"), "实测: {m}"),
            _ => panic!("系统根目录必须触发整批拒绝"),
        }
        // ③ A1 硬否决：受保护注册表容器 Skip 且带原因
        let m = skip_msg("reg_key", "HKLM\\SOFTWARE").unwrap_or_default();
        assert!(m.contains("已拒绝删除"), "实测: {m}");
        // ④ 合法形状但不存在的注册表键
        assert!(skip_msg(
            "reg_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TrimNoSuch-9f3a"
        )
        .unwrap_or_default()
        .contains("已不存在"));
        // ⑤ reg_value 形状闸：缺 :: 与值名为空都要出局
        assert!(skip_msg("reg_value", r"HKCU\Software\Acme").unwrap_or_default().contains("::"));
        assert!(skip_msg("reg_value", r"HKCU\Software\Acme::").unwrap_or_default().contains("为空"));
        // ⑥ 未知 kind 不静默放行
        assert!(skip_msg("whatever", r"C:\x").unwrap_or_default().contains("未知残留类型"));
        // ⑦ 真实系统目录（整条链非 reparse、不属保护面）应进入变更清单
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let sys32 = format!("{}\\Windows\\System32", drive.trim_end_matches('\\'));
        assert!(
            matches!(classify_residue_op("folder", &sys32), OpVerdict::Ready(_)),
            "真实系统目录被误拦: {sys32}"
        );
    }

    // ==================== M2 静默知识（B1 构造闸 / B2 分档 / B4 第二证据） ====================

    fn exists_all(_: &Path) -> bool {
        true
    }
    fn exists_none(_: &Path) -> bool {
        false
    }

    /// B1 构造闸：每一类「无法静态证明安全」的形态都要拒。逐类一条，缺一条就是漏一种绕过面
    /// —— 静默串来自注册表，是软件自己能写的字段，不能当成可信输入。
    #[test]
    fn quiet_string_gate_rejects_each_unsafe_shape() {
        let cases = [
            (r"C:\Windows\System32\cmd.exe".to_string(), "/c del C:\\x".to_string(), "宿主"),
            (
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
                "-Command Remove-Item".to_string(),
                "宿主",
            ),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S | more".to_string(), "管道"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S & calc".to_string(), "复合命令"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S && taskkill".to_string(), "复合命令"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S > C:\\x\\log.txt".to_string(), "重定向"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S < NUL".to_string(), "重定向"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S ; reboot".to_string(), "分号"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S $env:FOO".to_string(), "变量"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S `whoami`".to_string(), "反引号"),
            (
                r"C:\Program Files\Foo\u.exe".to_string(),
                "/D=\"%ProgramFiles%\\Foo\"".to_string(),
                "变量替换",
            ),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S \"unclosed".to_string(), "引号"),
            ("unins000.exe".to_string(), "/S".to_string(), "绝对路径"),
            (r"\\server\share\u.exe".to_string(), "/S".to_string(), "绝对路径"),
            (r"C:\Program Files\Foo\setup.msi".to_string(), "/quiet".to_string(), ".exe"),
        ];
        for (exe, args, label) in cases {
            let reason = quiet_string_reject_reason(&exe, &args, &exists_all);
            assert!(
                reason.is_some(),
                "[{label}] 该形态必须被拒：exe={exe:?} args={args:?}"
            );
        }
        // 存在性也是闸的一部分：路径写法都对但文件不存在同样不放行
        assert!(
            quiet_string_reject_reason(r"C:\Program Files\Foo\u.exe", "/S", &exists_none).is_some(),
            "文件不存在的厂商串必须被拒"
        );
    }

    /// 正例：字面的「绝对路径 exe + 参数」必须放行，含 NSIS 常见的 `/D="路径"` 形态。
    #[test]
    fn quiet_string_gate_admits_literal_absolute_command() {
        for (exe, args) in [
            (r"C:\Program Files\Foo\unins000.exe", "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART"),
            (r"C:\Program Files (x86)\Foo\uninstall.exe", "/S /D=C:\\Program Files\\Foo"),
            (r"D:\Foo\u.exe", "/S /D=\"C:\\Program Files\\Foo Data\""),
        ] {
            assert_eq!(
                quiet_string_reject_reason(exe, args, &exists_all),
                None,
                "合法厂商串被误拒: {exe} {args}"
            );
        }
    }

    /// B1 优先级：厂商静默串存在且过闸 → 用它，不再本地拼参数（BCU silentIfAvailable 的口径）。
    #[test]
    fn vendor_quiet_string_wins_over_whitelist() {
        let original = (
            r"C:\Program Files\Foo\uninstall.exe".to_string(),
            "/S".to_string(),
        );
        let quiet = r#""C:\Program Files\Foo\unins000.exe" /VERYSILENT /NORESTART"#;
        let c = pick_silent_candidate("nsis", None, &original, Some(quiet), &exists_all).expect("应有静默候选");
        assert_eq!(c.source, "vendor", "厂商串过闸后必须优先于白名单派生");
        assert_eq!(c.exe, r"C:\Program Files\Foo\unins000.exe");
        assert_eq!(c.args, "/VERYSILENT /NORESTART");
        assert!(c.vendor_reject.is_none());
    }

    /// B1 回退：厂商串被拒 → 退回白名单派生并**留下拒绝原因**；两类都不可用 → None（原厂 UI）。
    #[test]
    fn rejected_vendor_falls_back_to_whitelist_then_to_original_ui() {
        let original = (r"C:\Program Files\Foo\unins000.exe".to_string(), String::new());
        let bad = r"C:\Windows\System32\cmd.exe /c C:\Program Files\Foo\unins000.exe /S";
        let c = pick_silent_candidate("inno", None, &original, Some(bad), &exists_all).expect("白名单派生要接住");
        assert_eq!(c.source, "whitelist");
        assert_eq!(c.args, "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART");
        let reason = c.vendor_reject.expect("必须记录厂商串被拒的原因");
        assert!(reason.contains("宿主"), "原因要点明是哪一类风险，实测: {reason}");

        // 非白名单类型 + 无可用厂商串 → 不猜静默，交回原厂界面
        assert!(
            pick_silent_candidate("unknown", None, &original, None, &exists_all).is_none(),
            "unknown 类型不得凭空造静默命令"
        );
        // MSI 仍按产品码派生（原行为不受 B1 影响）
        let msi = pick_silent_candidate(
            "msi",
            Some("{1D180B6A-C6AE-4D6E-A2A8-000000001001}"),
            &original,
            None,
            &exists_all,
        )
        .expect("msi 应产出静默候选");
        assert_eq!(msi.exe, "msiexec.exe");
        assert!(msi.args.starts_with("/X{1D180B6A") && msi.args.contains("/qn /norestart"));
    }

    /// §2.4（2026-10-06 拍板·选项②）：vendor 串过闸后，Inno 且含独立 /SILENT token
    /// 才升级为全静默；/VERYSILENT 天然不重复触发；非 Inno 保持 vendor 原文。
    /// 升级只动参数，exe 与 source 语义不变。
    #[test]
    fn inno_vendor_silent_is_upgraded_to_verysilent() {
        let original = (r"C:\Program Files\Foo\unins000.exe".to_string(), String::new());
        // inno + /SILENT（大小写不敏感）→ 升级，且保留其余参数原序
        let quiet = r#""C:\Program Files\Foo\unins000.exe" /LANG=zh /SILENT /NOICONS"#;
        let c = pick_silent_candidate("inno", None, &original, Some(quiet), &exists_all).expect("过闸候选");
        assert_eq!(c.source, "vendor");
        assert_eq!(c.args, "/LANG=zh /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /NOICONS");
        // 小写 /silent 同样命中（Inno 命令行大小写不敏感）
        let lower = r#""C:\Program Files\Foo\unins000.exe" /silent"#;
        assert_eq!(
            pick_silent_candidate("inno", None, &original, Some(lower), &exists_all)
                .expect("过闸候选")
                .args,
            "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
        );
        // inno + /VERYSILENT：无独立 /SILENT token，不重复升级（保持原文）
        let very = r#""C:\Program Files\Foo\unins000.exe" /VERYSILENT /NORESTART"#;
        assert_eq!(
            pick_silent_candidate("inno", None, &original, Some(very), &exists_all)
                .expect("过闸候选")
                .args,
            "/VERYSILENT /NORESTART"
        );
        // 非 inno（nsis）带 /SILENT：保持 vendor 原文，不套 Inno 语义
        let nsis_quiet = r#""C:\Program Files\Foo\u.exe" /SILENT"#;
        assert_eq!(
            pick_silent_candidate("nsis", None, &original, Some(nsis_quiet), &exists_all)
                .expect("过闸候选")
                .args,
            "/SILENT"
        );
        // 升级条件不满足 ≠ 失败路径：失败回退仍由 rejected_vendor_falls_back_to_whitelist 接住
    }

    /// B2 分档：语义与「是否回退原厂界面」成对钉住。
    /// 用户取消(1602) 与并发安装(1618) **不回退**（2026-09-28 裁定：取消是用户决定，
    /// 自动重弹界面等于无视取消；1618 的有界重试要真机证据才定）。
    #[test]
    fn exit_codes_classified_with_fallback_decision() {
        let cases = [
            (0u32, "卸载成功", false),
            (3010, "卸载成功，需重启完成", false),
            (1605, "产品未安装（该卸载键已无对应产品）", false),
            (1602, "用户取消", false),
            (1618, "另一个安装或卸载正在进行，请稍后再试", false),
            (1603, "安装器内部错误", true),
            // 未确认语义的码（含 NSIS 的 1/2）保持原行为：回退原厂界面
            (1, "其它退出码", true),
            (2, "其它退出码", true),
            (1619, "其它退出码", true),
        ];
        for (code, meaning, fall_back) in cases {
            let got = classify_exit(code);
            assert_eq!(got.0, meaning, "退出码 {code} 的语义文案漂移");
            assert_eq!(got.1, fall_back, "退出码 {code} 的回退决策应为 {fall_back}");
        }
    }

    /// B4 第二证据：只认独有文件名。`uninstall.exe` 太通用，认了就等于把 `/S` 发给
    /// 未知卸载器 —— 识别可以弱，执行不能猜。
    #[test]
    fn second_evidence_only_recognizes_own_names() {
        let by_name = |want: &'static str| move |p: &Path| {
            p.file_name().and_then(|n| n.to_str()) == Some(want)
        };
        assert_eq!(
            second_evidence_kind(r"C:\Program Files\Foo", &by_name("unins000.exe")),
            Some("inno")
        );
        assert_eq!(
            second_evidence_kind(r"C:\Program Files\Foo", &by_name("nsisunins.exe")),
            Some("nsis")
        );
        assert_eq!(
            second_evidence_kind(r"C:\Program Files\Foo", &by_name("uninstall.exe")),
            None,
            "通用名不得被当成 NSIS"
        );
        // 输入不可信：空串、无盘符、超长一律不探
        let exists_all2 = |_: &Path| true;
        assert!(second_evidence_kind("", &exists_all2).is_none());
        assert!(second_evidence_kind("Foo\\Bar", &exists_all2).is_none());
        assert!(second_evidence_kind(&format!("C:\\{}", "a".repeat(300)), &exists_all2).is_none());
        // 尾随分隔符不能把探测变成目录本身
        assert_eq!(
            second_evidence_kind(r"C:\Program Files\Foo\", &by_name("unins000.exe")),
            Some("inno")
        );
    }
    /// M6：注册表里记着的落点写法五花八门，解析必须"认不出就无证据"，
    /// 而不是"猜一个路径出来判它不存在"。下面每条都是真机见过的形态。
    #[test]
    fn dead_landing_parses_registry_forms() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let cases: &[(&str, Option<&str>)] = &[
            (r#""C:\Program Files\Foo\unins000.exe" /SILENT"#, Some(r"C:\Program Files\Foo\unins000.exe")),
            (r"C:\Program Files\AntiCheatExpert\ACE-CORE102706.sys", Some(r"C:\Program Files\AntiCheatExpert\ACE-CORE102706.sys")),
            (r"C:\Windows\System32\svchost.exe -k netsvcs", Some(r"C:\Windows\System32\svchost.exe")),
            (r"\??\C:\Windows\System32\drivers\ACEX.sys", Some(r"C:\Windows\System32\drivers\ACEX.sys")),
            (r"\\server\share\unins000.exe /S", Some(r"\\server\share\unins000.exe")),
            // 认不出的一律 None —— 把"判不出来"当成"不存在"就是假阳性的来源
            ("notepad.exe", None),
            (r"C:\Program Files\Foo\launcher", None),
            (r"cmd /c del C:\x", None),
            (r"%NO_SUCH_TRIM_VAR%\a.exe", None),
            ("", None),
        ];
        for (raw, want) in cases {
            assert_eq!(dead_landing(raw).as_deref(), *want, "落点解析不符: {raw:?}");
        }
        // %SystemRoot% 展开依赖本机环境，只断前缀不断全串
        let exp = dead_landing(r"%SystemRoot%\system32\foo.exe").unwrap_or_default();
        assert!(
            exp.to_lowercase().starts_with(&windir.to_lowercase()),
            "变量没展开: {exp}"
        );
        // 未闭合引号不许把整串（含参数）当路径
        assert_eq!(dead_landing(r#""C:\Program Files\Foo\unins000.exe /S"#), None);
    }

    /// M6 卸载项判据：全部落点缺失才算失效；MSI 产品码键要求两条落点。
    /// C4 的贡献项断言也挂在这里——这两个函数的判据是同一条证据链。
    #[test]
    fn dead_uninstall_needs_every_landing_missing() {
        let present: std::collections::HashSet<String> = [
            r"C:\Program Files\Alive",
            r"C:\Program Files\Alive\unins000.exe",
            r"C:\Program Files\Half\unins000.exe",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let exists = |p: &str| present.iter().any(|x| x.eq_ignore_ascii_case(p));
        let mk = |name: &str, key: &str, install: &str, un: &str| DeadUninstallRaw {
            hive: "HKLM".to_string(),
            key: key.to_string(),
            path: format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{key}"),
            name: name.to_string(),
            install: install.to_string(),
            uninstall: un.to_string(),
            quiet: String::new(),
            last_write_ms: Some(1_700_000_000_000),
        };
        let guid = "{1D4E2B7A-2F3C-4D5E-8A9B-0C1D2E3F4A5B}";
        let rows = vec![
            mk("Alive", "Alive", r"C:\Program Files\Alive", r"C:\Program Files\Alive\unins000.exe"),
            mk("Half", "Half", r"C:\Program Files\Half", r"C:\Program Files\Half\unins000.exe"),
            mk("Gone", "Gone", r"C:\Program Files\Gone", r"C:\Program Files\Gone\unins000.exe"),
            mk("NoLanding", "NoLanding", "", ""),
            mk("RelativeOnly", "RelativeOnly", "", "unins000.exe"),
            mk("", "Nameless", r"C:\Program Files\Nameless", r"C:\Program Files\Nameless\u.exe"),
            mk("MsiOne", guid, r"C:\Program Files\MsiOne", ""),
        ];
        let out = dead_uninstall_findings(&rows, &exists, 1_700_000_900_000);
        let targets: Vec<&str> = out.iter().map(|f| f["target"].as_str().unwrap_or("")).collect();
        assert_eq!(
            targets,
            vec![r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Gone"],
            "候选集合不符（半存活/无落点/相对名/无名/MSI 单证据都不该出）: {out:?}"
        );
        assert_eq!(out[0]["confidence"], json!("medium"), "两条落点全部缺失才给 medium");
        assert_eq!(out[0]["defaultChecked"], json!(false));
        assert_eq!(out[0]["deleteCapable"], json!(true));
        // MSI 键两条落点全部缺失才放行，且置信度按证据条数走
        let msi_two = mk("MsiTwo", guid, r"C:\Program Files\MsiTwo", r"C:\Program Files\MsiTwo\setup.exe /x");
        let out2 = dead_uninstall_findings(&[msi_two], &exists, 1_700_000_900_000);
        assert_eq!(out2.len(), 1, "MSI 键两条落点全缺应产出: {out2:?}");
        assert_eq!(out2[0]["confidence"], json!("medium"), "两条落点全缺给 medium: {out2:?}");
        // 普通键单条落点缺失即产出，但置信度只到 low
        let one = mk("OneLanding", "OneLanding", "", r"C:\Program Files\OneLanding\unins000.exe");
        let out3 = dead_uninstall_findings(&[one], &exists, 1_700_000_900_000);
        assert_eq!(out3.len(), 1, "普通键单条落点缺失就该产出: {out3:?}");
        assert_eq!(out3[0]["confidence"], json!("low"), "一条落点不给 medium: {out3:?}");
        // C4：贡献项按 code 断言（不按中文文案断言，改文案不该碎掉测试），每条都得有 text。
        let c = &out[0]["contribs"];
        let codes: Vec<&str> = c.as_array().unwrap().iter().map(|x| x["code"].as_str().unwrap_or("")).collect();
        assert_eq!(codes.iter().filter(|k| *k == &"landingMissing").count(), 2, "两条落点各一条: {c}");
        assert!(codes.contains(&"entry") && codes.contains(&"dormant"), "键位置与沉睡证据都要在: {c}");
        assert!(
            c.as_array().unwrap().iter().all(|x| !x["text"].as_str().unwrap_or("").is_empty()),
            "有 code 没 text 等于给用户一个看不懂的代号: {c}"
        );
        assert!(
            !codes.contains(&"msiRule"),
            "普通键不该出现 MSI 口径: {c}"
        );
        assert!(out2[0]["contribs"]
            .as_array().unwrap()
            .iter().any(|x| x["code"] == json!("msiRule")),
            "MSI 键要说明为什么要求两条落点: {}", out2[0]);
        let one_codes: Vec<&str> = out3[0]["contribs"].as_array().unwrap()
            .iter().map(|x| x["code"].as_str().unwrap_or("")).collect();
        assert_eq!(one_codes.iter().filter(|k| *k == &"landingMissing").count(), 1, "一条落点只该有一条证据: {one_codes:?}");
    }

    #[test]
    fn dead_app_paths_rows_target_only_their_own_key() {
        let raws = vec![
            DeadAppPathRaw {
                hive: "HKLM".to_string(),
                key: "foo.exe".to_string(),
                path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\foo.exe".to_string(),
                value: r"C:\Program Files\Foo\foo.exe".to_string(),
                last_write_ms: None,
            },
            DeadAppPathRaw {
                hive: "HKLM".to_string(),
                key: "bar.exe".to_string(),
                path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\bar.exe".to_string(),
                value: "bar.exe".to_string(),
                last_write_ms: None,
            },
            DeadAppPathRaw {
                hive: "HKLM".to_string(),
                key: "live.exe".to_string(),
                path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\live.exe".to_string(),
                value: r"C:\Windows\explorer.exe".to_string(),
                last_write_ms: None,
            },
        ];
        let out = dead_app_paths_findings(&raws, &|p| p.eq_ignore_ascii_case(r"C:\Windows\explorer.exe"), 1_700_000_900_000);
        assert_eq!(out.len(), 1, "只有落点确实缺失的那条该出候选: {out:?}");
        let target = out[0]["target"].as_str().unwrap_or("");
        assert_eq!(target, r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\foo.exe");
        assert_eq!(out[0]["deleteCapable"], json!(true));
        assert!(
            protect::reg_target_block_reason(target).is_none(),
            "M1 给 App Paths 留的例外放行没生效，本类候选会被执行侧全量拒杀: {target}"
        );
        // C4：读不到写入时间时明确给 dormantUnknown，不许出现"沉默即很久"那种暗示
        let codes: Vec<&str> = out[0]["contribs"].as_array().unwrap()
            .iter().map(|x| x["code"].as_str().unwrap_or("")).collect();
        assert!(codes.contains(&"entry") && codes.contains(&"targetMissing"), "键与缺失目标都要点名: {codes:?}");
        assert!(codes.contains(&"dormantUnknown"), "无写入时间不该编沉睡证据: {codes:?}");
        assert!(!codes.contains(&"dormant"), "{codes:?}");
    }

    /// 快照分桶：面板现在同时展示多组候选，整槽覆盖会让先扫那组在执行时被快照闸判过期。
    #[test]
    fn residue_snapshot_buckets_replace_only_their_own_origin() {
        let label = "test-snapshot-merge";
        residue_snapshot_put(label, "app", vec![json!({ "kind": "folder", "target": "C:\\a", "origin": "app" })]);
        residue_snapshot_put(label, "dead", vec![json!({ "kind": "reg_key", "target": "HKCU\\Software\\X", "origin": "dead" })]);
        let both: Vec<String> = residue_snapshots()
            .lock()
            .map(|g| g.get(label).cloned().unwrap_or_default().1)
            .unwrap_or_default()
            .iter()
            .map(|f| f["target"].as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(both.len(), 2, "两组扫描的候选必须共存: {both:?}");
        residue_snapshot_put(label, "dead", vec![json!({ "kind": "reg_key", "target": "HKCU\\Software\\Y", "origin": "dead" })]);
        let after: Vec<String> = residue_snapshots()
            .lock()
            .map(|g| g.get(label).cloned().unwrap_or_default().1)
            .unwrap_or_default()
            .iter()
            .map(|f| f["target"].as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(after.len(), 2, "重扫只换自己那一桶: {after:?}");
        assert!(after.iter().any(|t| t == "C:\\a"), "app 桶被误替换: {after:?}");
        assert!(after.iter().any(|t| t.ends_with("Software\\Y")), "dead 桶没换: {after:?}");
        assert!(!after.iter().any(|t| t.ends_with("Software\\X")), "dead 桶旧值残留: {after:?}");
        let _ = residue_snapshots().lock().map(|mut g| g.remove(label));
    }

    /// 沉睡时长：读不到就留未知。把 0 显示成"很久没动过"是把没把握说成有把握。
    #[test]
    fn dormant_stays_unknown_instead_of_looking_ancient() {
        assert_eq!(dormant_delta(None, 1_700_000_900_000), Value::Null);
        assert_eq!(dormant_delta(Some(0), 1_700_000_900_000), Value::Null);
        assert_eq!(dormant_delta(Some(1_700_000_900_001), 1_700_000_900_000), Value::Null, "时钟回拨不给负数");
        assert_eq!(dormant_delta(Some(1_700_000_000_000), 1_700_000_900_000), json!(900_000));
    }
