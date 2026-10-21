//! 跨契约面的残留/追踪回归网（v3 D0：无法归属单一契约面，按纪律单独成文）。
//!
//! 这些用例同时盯 list_run 的第三方模块口径、residue 的前缀反查、本机学习库判定、
//! C3 阈值表与 M2 静默知识（B1 构造闸 / B2 分档 / B4 第二证据），
//! 所以它不属于任何单个域文件；glob 引进各域符号是为了让「实现搬走」立刻反映成
//! 编译错误，而不是悄悄少测一条。



use crate::engine::rules_signature;
use serde_json::{Value, json};
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

    // ==================== C3 阈值表 ====================

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

    /// R2-M01 + R2-L09（v4）：规则库的 `shortcut` 与 `reg_value` 产出臂（含执行侧同款 A1）——
    /// 此前两个 kind 都落在 `_ => continue` 被静默丢弃（209 条 residue 条目里 35 条 shortcut
    /// ＝ 16.7% 的库配了永远 0 命中；reg_value 则因无产出臂而「碰巧安全」，补臂必须同批补闸）。
    #[test]
    fn rules_emit_shortcut_and_reg_value_with_execution_side_gates() {
        // 命中链要求落点真实存在（生产语义），所以造一个真 .lnk 并挂 Drop 清掉。
        let dir = std::env::temp_dir().join(format!("trim-rules-{}", std::process::id()));
        let lnk = dir.join("ProbeSoft.lnk");
        std::fs::create_dir_all(&dir).expect("建临时命中目标");
        std::fs::write(&lnk, b"x").expect("写探针 .lnk");
        struct Clean(std::path::PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _clean = Clean(dir.clone());

        let doc = |id: &str, residue: Value| json!({
            "rulesVersion": 1.0,
            "prov": [],
            "rules": [{
                "id": id,
                "displayName": ["ProbeSoft"], "publisher": ["ProbeCorp"], "uninstallKey": ["ProbeSoft"],
                "residue": [residue]
            }]
        });
        let run = |doc: &Value| {
            residue_rules_hits(doc, "ProbeSoft", "ProbeCorp", r"Software\X\Uninstall\ProbeSoft", false)
        };

        // ① shortcut 正例：存在 ⇒ 产出（修前恒 0 命中）
        let (hits, _) = run(&doc("p-shortcut", json!({ "kind": "shortcut", "target": lnk.to_string_lossy(), "note": "开始菜单快捷方式" })));
        assert_eq!(hits.len(), 1, "shortcut 产出臂断了: {hits:?}");
        assert_eq!(hits[0]["kind"], json!("shortcut"));

        // ② shortcut 不存在 ⇒ 不产
        let (hits, _) = run(&doc("p-shortcut2", json!({ "kind": "shortcut", "target": dir.join("no-such.lnk").to_string_lossy(), "note": "缺" })));
        assert!(hits.is_empty(), "不存在的 shortcut 不该出现: {hits:?}");

        // ③ reg_value 被 A1 硬否决（Microsoft 树内、非 Run 六根）⇒ 不产 + 留 vetoed 证据
        let (hits, vetoed) = run(&doc("p-rv-denied", json!({ "kind": "reg_value", "target": r"HKLM\SYSTEM\CurrentControlSet\Services\TrimProbe::Start", "note": "系统树内" })));
        assert!(hits.is_empty(), "系统树内的 reg_value 不得进候选: {hits:?}");
        assert!(vetoed.iter().any(|v| v.contains("硬否决")), "否决必须留证据: {vetoed:?}");

        // ④ reg_value 第三方键但值不存在 ⇒ 不产（存在性闸）；同时不得被误 vetoed
        let (hits, vetoed) = run(&doc("p-rv-missing", json!({ "kind": "reg_value", "target": r"HKCU\Software\TrimNoSuchProbe9f3a\X::probe", "note": "探针" })));
        assert!(hits.is_empty(), "不存在的值不该产候选: {hits:?}");
        assert!(vetoed.is_empty(), "第三方键不该被 protect 面误否: {vetoed:?}");
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
        // ⑦ 系统目录（整条链非 reparse、不属 protect 面）在**执行侧**也必须拒 ——
        // v4-K02 修复前这里是 `Ready`，意味着 System32 真能被送进回收站（还被本用例
        // 钉成了「期望行为」）。现在与扫描侧共用 in_system_namespace 判据：Skip
        // （系统目标是扫描面漏网、不是恶意请求，不整批 Abort）。
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let sys32 = format!("{}\\Windows\\System32", drive.trim_end_matches('\\'));
        assert!(
            matches!(classify_residue_op("folder", &sys32), OpVerdict::Skip(_)),
            "系统目录必须被拒（v4-K02）: {sys32}"
        );
        // v5-K02 批次 1（R2a-K01）：同一目录的非规范写法在执行侧同样必须 Skip。
        // bypass-probe 修前实测这三种形态 is_system_namespace=false（判据入口不归一），
        // 曾以 Ready 进删除链；入口过 normalize_for_compare 后三形态与规范形态同结论。
        // 判红自证：把 is_system_namespace 的归一删掉 ⇒ 本组三条全红。
        let d = drive.trim_end_matches('\\');
        for form in [
            format!(r"\\?\{sys32}"),
            format!("{d}\\Program Files\\..\\Windows\\System32"),
            r"\Windows\System32".to_string(),
        ] {
            assert!(
                matches!(classify_residue_op("folder", &form), OpVerdict::Skip(_)),
                "非规范系统目录形态必须被拒: {form}"
            );
        }
        // ⑧ 反例：合法安装位置（%ProgramFiles% 子孙）不许被系统命名空间判据误伤。
        // 用 Windows 自带的 Common Files（几乎必然存在）；不存在时显式跳过并说明。
        let pf = format!("{}\\Program Files\\Common Files", drive.trim_end_matches('\\'));
        if Path::new(&pf).is_dir() {
            assert!(
                matches!(classify_residue_op("folder", &pf), OpVerdict::Ready(_)),
                "合法安装位置被误拦: {pf}"
            );
        } else {
            println!("跳过 Program Files 反例：{pf} 不在本机（不影响系统目录判据的判定）");
        }
    }

    /// v4-K02 共用化：系统组件 exe 判据在反查侧与 exeParent 分支同源
    /// （`<System32>\msiexec.exe` 的父目录不得成为候选依据）。
    /// 系统命名空间判据本体（`protect::is_system_namespace`）的单测在 protect.rs
    /// 归属地（K02 与 K01 两个消费方共用同一实现）。
    #[test]
    fn system_component_exe_is_shared_judgement() {
        assert!(is_system_component_exe(r"C:\Windows\System32\msiexec.exe"));
        assert!(is_system_component_exe(r"c:\windows\system32\MSIEXEC.EXE"));
        assert!(!is_system_component_exe(r"C:\Apps\Foo\unins000.exe"));
        assert!(!is_system_component_exe("msiexec.exe"), "裸名不进判据（由空父目录闸挡）");
    }

    /// J12（2026-10-16）：残留 folder 候选的**断链 junction** 改判可删（删链接本体，
    /// 实际删除仍走 trim_finder 回收站原语）；活链仍拒；上级是链接的目标仍拒。
    /// 建链需管理员/开发者模式；失败显式跳过并说明（§2 纪律）。
    #[cfg(windows)]
    #[test]
    fn 断链_junction_的_folder_候选放行_活链仍拒() {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("trim-res-j12-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        let link = dir.join("link");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("keep.txt"), b"x").unwrap();
        let st = Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&link)
            .arg(&target)
            .output();
        if !matches!(st, Ok(o) if o.status.success()) {
            eprintln!("[J12] 建 junction 失败（需管理员/开发者模式），本用例跳过（未校验）");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let link_s = link.to_string_lossy().to_string();

        // ① 活链仍拒（目标在 → 不属于「断链」对象）
        assert!(
            matches!(classify_residue_op("folder", &link_s), OpVerdict::Skip(_)),
            "活链必须仍拒: {link_s}"
        );

        // ② 断链放行（分类层 Ready；删除时 trim_finder::scan::delete 走回收站原语）
        std::fs::remove_dir_all(&target).unwrap();
        assert!(
            matches!(classify_residue_op("folder", &link_s), OpVerdict::Ready(_)),
            "断链 junction 必须放行（J12）: {link_s}"
        );

        // ③ 上级是链接的目标仍拒：link 复活为活链，候选取 link\inner（自身不是链接，
        //    但上级 link 是）——借目录树删别处的形态必须原样拦住
        std::fs::create_dir_all(&target).unwrap();
        let inner = link.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let inner_s = inner.to_string_lossy().to_string();
        assert!(
            matches!(classify_residue_op("folder", &inner_s), OpVerdict::Skip(_)),
            "上级是链接的目标必须仍拒: {inner_s}"
        );

        // 收尾：先拆 junction 再清目录（remove_dir_all 对 junction 子项的行为不作依赖）
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&dir);
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

    /// 快照分桶：面板现在同时展示多组候选，整槽覆盖会让先扫那组在执行时被快照闸判过期。
    /// v4 P2-F（R2-M02）：输入**刻意不写 origin** —— 打标由 `residue_snapshot_put` 入口
    /// 统一完成（生产侧曾 0 处赋值，分桶过滤恒不命中、重扫只累加且触顶保旧砍新）。
    #[test]
    fn residue_snapshot_buckets_replace_only_their_own_origin() {
        let label = "test-snapshot-merge";
        residue_snapshot_put(label, "app", vec![json!({ "kind": "folder", "target": "C:\\a" })]);
        residue_snapshot_put(label, "dead", vec![json!({ "kind": "reg_key", "target": "HKCU\\Software\\X" })]);
        let both: Vec<String> = residue_snapshots()
            .lock()
            .map(|g| g.get(label).cloned().unwrap_or_default().1)
            .unwrap_or_default()
            .iter()
            .map(|f| f["target"].as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(both.len(), 2, "两组扫描的候选必须共存: {both:?}");
        residue_snapshot_put(label, "dead", vec![json!({ "kind": "reg_key", "target": "HKCU\\Software\\Y" })]);
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

    /// v0.7.0 四类口径：服务键归属判据（纯函数）。落点在该应用安装目录之下、或服务名与
    /// 程序名 token 互含，才算属于这个应用；兄弟目录前缀与无关服务名都要挡住。
    #[test]
    fn service_belongs_to_app_matches_landing_or_name_token() {
        let tokens = vec!["acme".to_string(), "editor".to_string()];
        let app_dir = r"c:\program files\acme";
        // ① 落点在安装目录之下（大小写不敏感、按 `\` 段前缀比较）
        assert!(service_belongs_to_app("AcmeSvc", Some(r"C:\Program Files\Acme\bin\a.exe"), &tokens, app_dir));
        // ② 服务名与 token 互含（token 可能比服务名长，也可能短）
        assert!(service_belongs_to_app("AcmeUpdateService", None, &tokens, ""));
        assert!(service_belongs_to_app("editor", None, &tokens, ""));
        // 兄弟目录前缀不许被当成「之下」：Acme2 不属于 Acme（否则同级目录互相污染）
        assert!(!service_belongs_to_app("Other", Some(r"C:\Program Files\Acme2\a.exe"), &tokens, app_dir));
        // 落点与名字都对不上 ⇒ 不归属
        assert!(!service_belongs_to_app("WindowsUpdate", Some(r"C:\Windows\System32\svc.exe"), &tokens, app_dir));
        // token 不足 2 字符不参与名字互含（短名字误报率爆炸）
        assert!(!service_belongs_to_app("x", None, &["x".to_string()], ""));
        // 落点缺失、安装目录也为空时不靠空字符串误判
        assert!(!service_belongs_to_app("Other", None, &tokens, ""));
    }

    // ==================== U-R2a（v7.2 P1-W2）· uninstall 残留链 14 条单元契约 ====================
    //
    // 一条用例钉一个条目，断言一律点名「做到了什么」（AGENTS §4.1）：期望集合逐字给出，
    // 并按「正向 + 反向对照」成对写（只断"没报错"的不算验收）。
    // 源码形态断言只用于两类对象：① 顺序（谁先谁后是语义本身）② 唯一出口（同一判据
    // 出现第二份即红，§5.16/N6）。锚点一律是 file + 判别性子串，禁行号（§5.19）。
    // 依赖真实注册表的两条另写 `#[ignore]` 真机探针（本档位不跑，见各自文档注释）。

    /// R2a-L01：hive 前缀的定长字节切片必须先过字符边界。
    /// 判红自证：把 `parse_reg_target` 的判断退回 `t[..prefix.len()]` ⇒ ①②两条当场 panic。
    #[test]
    fn r2a_l01_非ascii键名不再踩切片边界() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        // ① 主形态：`HKEY_CURRENT_USER\` 前缀长 18，而本串第 18 字节落在「信」内部
        //    （`HKCU\Software\` = 14 字节，后面「微信」各 3 字节）——旧写法在这里直接 panic，
        //    panic 沿 learned::load 把整轮残留扫描带崩，连隔离损坏文件的路径都到不了。
        let (hk, rest) = parse_reg_target(r"HKCU\Software\微信").expect("HKCU 前缀必须解析成功");
        assert_eq!(hk.0, HKEY_CURRENT_USER.0, "hive 必须是 HKCU");
        assert_eq!(rest, r"Software\微信", "非 ASCII 叶名必须原样留在子键路径里");
        // ② 根本不是 hive 的 CJK 串（第 18 字节同样落在「飞」内）：必须 None，不许 panic
        assert!(parse_reg_target(r"软件\微软\讯飞\钉钉").is_none(), "非 HKCU/HKLM 一律拒");
        // ③ 长前缀的大小写混写照常命中，且多余的 `\` 被剥掉（既有语义不变）
        let (hk, rest) = parse_reg_target(r"hkey_local_machine\Software\Acme").expect("长前缀必须命中");
        assert_eq!(hk.0, HKEY_LOCAL_MACHINE.0);
        assert_eq!(rest, r"Software\Acme");
        // ④ 只有前缀、没有子键路径 → None（字节判据 `t.len() > prefix.len()` 的既有语义）
        assert!(parse_reg_target("HKCU\\").is_none(), "裸前缀不算目标");
        // ⑤ 中文叶名紧跟短前缀：前三条前缀的 `get` 都拿不到边界（18/19 都落在「网易」内），
        //    必须逐条 continue 之后由 `HKLM\`（第 5 字节是边界）命中 —— 旧写法在这条上同样 panic
        let (_, rest) = parse_reg_target(r"HKLM\SOFTWARE\网易大神").expect("HKLM 短前缀必须命中");
        assert_eq!(rest, r"SOFTWARE\网易大神");
    }

    /// R2a-L11（§5.16/N6）：本单元「按注册表回报长度分配」只许共用同一份上限。
    /// 判红自证：给任一文件再加一处 `let mut buf = vec![0u8; size as usize];` 而不配
    /// `> MAX_REG_STR_BYTES` ⇒ 两个计数当场不等。
    #[test]
    fn r2a_l11_按回报长度分配共用同一份上限() {
        const ALLOC: &str = "let mut buf = vec![0u8; size as usize];";
        const CEILING: &str = "> MAX_REG_STR_BYTES";
        // 闭包写不出「返回借用入参」的生命周期关系（返回类型会退化成入参的更短那个），
        // 所以这条纯函数用 fn 写：省略号写法把输出生命周期绑到入参上。
        fn prod(src: &str) -> &str {
            src.split("#[cfg(test)]").next().unwrap_or(src)
        }
        let helpers = prod(include_str!("helpers.rs"));
        let pending = prod(include_str!("pending_delete.rs"));
        let allocs = helpers.matches(ALLOC).count() + pending.matches(ALLOC).count();
        let ceilings = helpers.matches(CEILING).count() + pending.matches(CEILING).count();
        // 正向特征：现算的分配点集合必须是「三处」（helpers 两处 + PFRO 一处），
        // 少一处说明锚点被改写、用例本身已失效，不许悄悄退化成恒等式。
        assert_eq!(allocs, 3, "分配点锚点失配（helpers reg_sz/reg_multi_sz + pending_delete read_pfro）: {allocs}");
        assert_eq!(allocs, ceilings, "每处按回报长度分配都必须有一道 MAX_REG_STR_BYTES 上限: 分配 {allocs} / 上限 {ceilings}");
    }

    /// R2a-L02：快照装不下时，**返回给渲染层的那一份必须恰是快照接受的同一份**。
    /// 正向特征：接受的条数、条目身份、以及「用执行侧同一个判据能查到」三件事逐条点名；
    /// 反向对照：被丢弃的那条用同一判据查不到（旧写法在这里是"面板有、快照没有"）。
    #[test]
    fn r2a_l02_面板清单恰是快照接受的那一份() {
        let label = "test-r2a-snapshot-overflow";
        let mk = |n: usize, tag: &str| -> Vec<Value> {
            (0..n).map(|i| json!({ "kind": "reg_key", "target": format!(r"HKCU\Software\{tag}{i}") })).collect()
        };
        // 先把另一桶灌到容量边界：dead 桶占 SNAPSHOT_CAP-1 ⇒ app 桶只剩 1 个位置
        let dead = residue_snapshot_put(label, "dead", mk(SNAPSHOT_CAP - 1, "dead"));
        assert_eq!(dead.len(), SNAPSHOT_CAP - 1, "前置夹具必须真的占满除 1 格外的容量");
        let accepted = residue_snapshot_put(label, "app", mk(50, "app"));
        assert_eq!(accepted.len(), 1, "只剩 1 个位置时快照必须只接受 1 条（旧写法返回全量 50 条给面板）");
        assert_eq!(accepted[0]["target"].as_str(), Some(r"HKCU\Software\app0"));
        let stored: Vec<Value> = residue_snapshots()
            .lock()
            .map(|g| g.get(label).cloned().unwrap_or_default().1)
            .unwrap_or_default();
        assert_eq!(stored.len(), SNAPSHOT_CAP, "槽内总量必须正好是容量上限，不得超");
        // 用**执行侧同一个判据**核（snapshot_has）——测试不另写一份比较（§5.16/N6）
        let k = accepted[0]["kind"].as_str().unwrap();
        let t = accepted[0]["target"].as_str().unwrap();
        assert!(snapshot_has(&stored, k, t), "面板拿到的这条必须能过快照闸");
        assert!(!snapshot_has(&stored, "reg_key", r"HKCU\Software\app1"), "被丢弃的条目不得留在快照里");
        assert!(!stored.iter().any(|f| f["origin"].as_str() == Some("app") && *f != accepted[0]), "app 桶只能有返回的那一条");
        let _ = residue_snapshots().lock().map(|mut g| g.remove(label));
    }

    /// R2a-L02：三个上限现算对账（数字只许有一份出处，关系靠常量算、不手抄）。
    #[test]
    fn r2a_l02_三个上限互相对得上() {
        // 代码侧各产源臂上限：目录/快捷方式两趟 NAME_HIT_CAP + 五路侧痕 SIDE_TRACE_CAP + 服务桶
        let code_arms = 2 * NAME_HIT_CAP + 5 * SIDE_TRACE_CAP + SERVICE_RESIDUE_CAP;
        assert!(
            code_arms <= SNAPSHOT_CAP,
            "各产源臂上限和 {code_arms} 必须 ≤ 快照容量 {SNAPSHOT_CAP}，否则扫描出的候选整批落不进快照"
        );
        assert!(
            RESIDUE_EXECUTE_MAX <= SNAPSHOT_CAP,
            "单批执行上限 {RESIDUE_EXECUTE_MAX} 必须 ≤ 快照容量 {SNAPSHOT_CAP}，否则合法批次永远无法一次执行"
        );
        // 报告根：保留份数与列表可见份数同源（一个数字两个消费点）
        assert_eq!(REPORT_KEEP, 50, "报告保留份数若改动必须同步列表侧（本断言点名现算值）");
    }

    /// R2a-L04：4MB 护栏必须挡在**读之前**（拿真实磁盘样本证伪，不是源码形状）。
    /// 正向特征：小文件命中、超阈值文件不命中且不计入候选；判红自证：把元数据判据删掉，
    /// 巨型那条会因字节包含命中而回到结果里 ⇒ 当场红。
    #[test]
    fn r2a_l04_巨型目标文件在读之前就被挡下() {
        let root = crate::engine::paths::temp_script_dir().expect("应用私有 tmp 目录")
            .join(format!("trim-r2a-l04-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let needle = r"c:\apps\acme\acme.exe";
        let bytes: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
        // ① 正常尺寸且含线索 —— 必须命中
        let small = root.join("11111111111111111111111111111111_0011a000.destinations-ms");
        std::fs::write(&small, [&bytes[..], b"pad".as_slice()].concat()).unwrap();
        // ② 同样含线索但超过 4MB —— 必须在读之前被挡下
        let huge = root.join("22222222222222222222222222222222_0011a000.destinations-ms");
        {
            let mut f = std::fs::File::create(&huge).unwrap();
            std::io::Write::write_all(&mut f, &bytes).unwrap();
            f.set_len(4 * 1024 * 1024 + 1).unwrap();
        }
        // ③ 空文件（旧写法靠 bytes.is_empty() 挡）—— 同样不命中
        std::fs::write(root.join("33333333333333333333333333333333_0011a000.destinations-ms"), b"").unwrap();
        // ④ 同名目录（元数据 is_file 判据）—— 不命中也不报错
        std::fs::create_dir_all(root.join("44444444444444444444444444444444_0011a000.destinations-ms")).unwrap();
        // ⑤ 非 .destinations-ms 的巨型文件不得被打开（扩展名闸在先）
        std::fs::write(root.join("ignored.txt"), &bytes).unwrap();

        let hits = jumplist_hits(&[needle.to_string()], "", 20, &root);
        assert_eq!(hits.len(), 1, "只应命中那一份正常尺寸的目标文件: {hits:?}");
        assert!(hits[0].replace('\\', "/").ends_with("0011a000.destinations-ms"));
        assert!(hits[0].contains("11111111111111111111111111111111"), "命中的必须是小的那份: {hits:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// R2a-L05：重复提交的同一目标合并成一次变更。
    /// 正向特征：点名保留下来的 `(kind,target)` 集合与被合并掉的条数（旧写法两条都留下，
    /// 第二条落到删除分支时目标已不在 ⇒ 回执记 fail、failCount 虚高）。
    #[test]
    fn r2a_l05_重复目标合并成一次变更() {
        let submitted = vec![
            ("reg_key".to_string(), r"HKCU\Software\Acme".to_string()),
            ("folder".to_string(), r"C:\Apps\Acme".to_string()),
            // 大小写不同的同一路径：与 snapshot_has 同口径，必须算重复
            ("reg_key".to_string(), r"hkcu\software\acme".to_string()),
            // kind 不同 ⇒ 不是重复（快照按 (kind,target) 判，去重必须同判据）
            ("file".to_string(), r"C:\Apps\Acme".to_string()),
            ("reg_key".to_string(), r"HKCU\Software\Acme".to_string()),
        ];
        let (kept, dropped) = dedupe_targets(submitted);
        assert_eq!(dropped, 2, "应合并掉 2 条: {kept:?}");
        let got: Vec<(&str, &str)> = kept.iter().map(|(k, t)| (k.as_str(), t.as_str())).collect();
        assert_eq!(
            got,
            vec![
                ("reg_key", r"HKCU\Software\Acme"),
                ("folder", r"C:\Apps\Acme"),
                ("file", r"C:\Apps\Acme"),
            ],
            "保留集合必须逐条点名，且顺序按首次出现"
        );
        // 空输入不得凭空造条目
        let (empty_kept, empty_dropped) = dedupe_targets(Vec::new());
        assert!(empty_kept.is_empty() && empty_dropped == 0, "空输入必须原样回空");
    }

    /// R2a-L10：补桶只补**没带 bucket** 的候选，服务/驱动桶必须原样保留。
    /// 判红自证：删掉 `if f.get("bucket").is_some() { continue; }` ⇒ 第一个断言当场红；
    /// 把调用点挪回服务块之前 ⇒ 第二个断言（顺序）红。
    #[test]
    fn r2a_l10_补桶不得覆盖自带的服务桶() {
        let mut findings = vec![
            json!({ "kind": "reg_key", "target": "HKLM\\A", "bucket": "service" }),
            json!({ "kind": "reg_key", "target": "HKLM\\B", "bucket": "driver" }),
            json!({ "kind": "reg_key", "target": "HKCU\\C" }),
            json!({ "kind": "reg_value", "target": r"HKCU\C::v" }),
            json!({ "kind": "folder", "target": r"C:\Apps\A" }),
            json!({ "kind": "shortcut", "target": r"C:\Start\A.lnk" }),
        ];
        fill_missing_buckets(&mut findings);
        let buckets: Vec<&str> = findings.iter().map(|f| f["bucket"].as_str().unwrap_or("")).collect();
        assert_eq!(
            buckets,
            vec!["service", "driver", "registry", "registry", "file", "file"],
            "自带桶必须原样保留，其余按 kind 归 registry/file"
        );
        // 顺序契约：扫描体里补桶必须排在服务/驱动候选入列**之后**（否则护栏恒不命中）
        let prod = include_str!("residue.rs").split("#[cfg(test)]").next().unwrap_or("");
        let i_push = prod.find("\"bucket\": bucket,").expect("找不到服务/驱动候选的 push");
        let i_fill = prod.find("fill_missing_buckets(&mut findings)").expect("找不到补桶调用点");
        assert!(i_push < i_fill, "服务/驱动候选必须先入列，补桶的「已存在即跳过」才是真护栏");
    }

    /// R2a-L06：两处 export 必须走同一个文件名出口（撞名让路）。
    /// 判红自证：任何一处退回自己 `join(format!("{}_{}.reg", ...))` ⇒ 计数红。
    #[test]
    fn r2a_l06_两处export共用唯一文件名出口() {
        let prod = include_str!("residue.rs").split("#[cfg(test)]").next().unwrap_or("");
        assert_eq!(
            prod.matches("new_reg_backup_file(&backup_dir, crate::engine::now_ms(),").count(),
            2,
            "reg_key 与 reg_value 两处都必须经 new_reg_backup_file 生成落盘名"
        );
        assert_eq!(
            prod.matches("format!(\"{}_{}.reg\"").count(),
            0,
            "执行侧不得再留第二处自拼备份名（撞名会连封条一起覆盖）"
        );
    }

    /// R2a-L07：执行入口的形状闸必须与扫描入口**同一对函数**（§5.16/N6 只许一份判据）。
    /// 判红自证：把执行侧那两条闸删掉 ⇒ 计数从 2 掉到 1 当场红。
    #[test]
    fn r2a_l07_执行侧形状闸与扫描侧同一对() {
        let prod = include_str!("residue.rs").split("#[cfg(test)]").next().unwrap_or("");
        assert_eq!(
            prod.matches("valid_uninstall_key_path(key_path)").count(),
            2,
            "卸载键形状闸必须在扫描与执行两处各出现一次（不许出现第三份自写校验）"
        );
        assert_eq!(
            prod.matches("valid_appx_fullname(key_path)").count(),
            2,
            "Appx 包全名闸必须在扫描与执行两处各出现一次"
        );
        // 形状集合本身由 helpers/appx 各自的用例钉（这里只钉「两个阶段走同一对闸」）
        assert!(valid_uninstall_key_path(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme"));
        assert!(!valid_uninstall_key_path("all"), "MACHINE|all 的键段必须过不了形状闸");
    }

    /// R2a-L12：注册表两类 ok 行必须点名「对应哪一份备份」，旧的一句泛称不再存在。
    #[test]
    fn r2a_l12_注册表ok行点名备份文件() {
        let prod = include_str!("residue.rs").split("#[cfg(test)]").next().unwrap_or("");
        assert_eq!(prod.matches("删除前已导出").count(), 2, "reg_key 与 reg_value 两条 ok 文案都要点名备份");
        assert_eq!(prod.matches("\"backupFile\"").count(), 2, "两条 ok 明细都要带上备份文件名");
        assert_eq!(prod.matches("已删除（备份已留存）").count(), 0, "「备份已留存」这种无法核对的泛称必须已撤掉");
        // 展示名只给文件名，不给数据根绝对路径
        assert_eq!(reg_backup_file_name(std::path::Path::new(r"C:\data\uninstall-reg-backup\1_A.reg")), "1_A.reg");
        assert_eq!(reg_backup_file_name(std::path::Path::new("not-a-path")), "");
    }

    /// R2a-L03：报告根只有一个入口、写完就裁（同域 `.reg` 备份的既有口径）。
    #[test]
    fn r2a_l03_报告根唯一入口且写完即裁() {
        let prod = include_str!("residue.rs").split("#[cfg(test)]").next().unwrap_or("");
        assert_eq!(prod.matches("join(\"uninstall-reports\")").count(), 0, "执行侧不得再直拼报告根（与列表侧分叉）");
        assert_eq!(prod.matches("uninstall_reports_dir()").count(), 1, "报告根必须经唯一入口取");
        assert_eq!(
            prod.matches("prune_backups_ext(&reports_dir, REPORT_KEEP, &[\"json\"])").count(),
            1,
            "报告落盘后必须按 REPORT_KEEP 裁一次（这个根此前只写不裁）"
        );
    }

    /// R2a-M02：归属身份现读必须排在**第一个注册表变更之前**。
    /// 判红自证：把 `residue_identity` 的调用挪回 await 之后 ⇒ 顺序断言当场红；
    /// 挪动 `reg_key_remove` 也红（两侧都是锚点）。
    #[test]
    fn r2a_m02_身份现读先于第一个变更() {
        let prod = include_str!("residue.rs").split("#[cfg(test)]").next().unwrap_or("");
        let i_id = prod.find("let identity = residue_identity(&").expect("找不到归属身份现读点");
        let i_del = prod.find("reg_key_remove(hive, rest, true)").expect("找不到卸载键删除调用点");
        assert!(
            i_id < i_del,
            "身份必须在删键之前现读：删完再读 DisplayName 恒空，最常见那一批永远学不到（M02）"
        );
        // 身份随批次结果一起带回命令边界，学习链不再自己回读注册表
        assert_eq!(
            prod.matches("learn_from_deletions(&app_id, &details, identity)").count(),
            1,
            "回写侧必须用带回的身份（旧写法在批次结束后再读一次注册表）"
        );
        assert_eq!(
            prod.matches("fn learn_from_deletions(app_id: &str, details: &[Value]) -> usize").count(),
            0,
            "旧签名（函数体内自己回读注册表）不得复活"
        );
    }

    /// R2a-M02：可学落点的映射表（纯函数，不碰学习库文件）。
    /// 正向特征：点名"进得来的是哪三条"，反向对照点名"被挡掉的是哪几条"。
    #[test]
    fn r2a_m02_可学落点映射与kind口径对齐() {
        let details = vec![
            json!({ "kind": "dir", "target": r"C:\Apps\A", "status": "ok" }),
            json!({ "kind": "folder", "target": r"C:\Apps\B", "status": "ok" }),
            json!({ "kind": "file", "target": r"C:\Apps\A\a.txt", "status": "ok" }),
            json!({ "kind": "reg_key", "target": r"HKCU\Software\A", "status": "ok" }),
            // 失败行不得学（否则下轮把"删不掉的路径"当已知残留反复推荐）
            json!({ "kind": "file", "target": r"C:\Apps\locked.txt", "status": "fail" }),
            json!({ "kind": "file", "target": r"C:\Apps\denied.txt", "status": "skip" }),
            // shortcut / reg_value 是签名库独有 kind，学习库允许集维持不变
            json!({ "kind": "shortcut", "target": r"C:\Start\A.lnk", "status": "ok" }),
            json!({ "kind": "reg_value", "target": r"HKCU\C::v", "status": "ok" }),
            // 缺 target 的行不得凭空造条目
            json!({ "kind": "file", "status": "ok" }),
        ];
        let got = learnable_entries(&details);
        let mapped: Vec<(&str, &str)> = got.iter().map(|(k, t)| (*k, t.as_str())).collect();
        assert_eq!(
            mapped,
            vec![
                ("folder", r"C:\Apps\A"),
                ("folder", r"C:\Apps\B"),
                ("file", r"C:\Apps\A\a.txt"),
                ("reg_key", r"HKCU\Software\A"),
            ],
            "只收 ok 的三类落点，且 dir 必须归一成 folder（学习库 schema 口径）"
        );
        assert!(learnable_entries(&[]).is_empty(), "空明细不得造条目");
    }

    /// R2a-M02 真机探针（`#[ignore]`，发布前实跑）：`residue_identity` 走的
    /// `engine::native::read_reg_value_text` 是真实注册表读，MockRuntime 覆盖不到。
    /// 要验三件事：① 真实卸载键能读到非空 DisplayName；② 返回的 key_path 恰是 app_id
    /// 竖线后那一段（学习库的 uninstallKey 匹配组就是它）；③ 键不存在时是 None 而不是崩。
    /// 跑法：`cargo test --release -- --ignored r2a`（需管理员无关，只读 HKLM/HKCU）。
    #[test]
    #[ignore = "真机现读卸载键身份（需本机注册表样本）"]
    fn live_r2a_m02_现读真实卸载键身份() {
        use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
        const ROOT: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let mut checked = 0usize;
        let mut sample: Option<(String, String)> = None;
        for name in unsafe { reg_enum_subkeys(HKEY_LOCAL_MACHINE, ROOT, 256) } {
            let app_id = format!("HKLM|{ROOT}\\{name}");
            if let Some((display_name, publisher, key_path)) = residue_identity(&app_id) {
                checked += 1;
                assert!(!display_name.trim().is_empty(), "读到身份却给了空显示名: {app_id}");
                assert_eq!(key_path, format!(r"{ROOT}\{name}"), "key_path 必须是 app_id 竖线后那一段");
                if publisher.trim().is_empty() && sample.is_none() {
                    sample = Some((display_name.clone(), name.clone()));
                }
            }
        }
        if checked == 0 {
            eprintln!("⚠ [skip-sample] 本机 {ROOT} 下没有可读 DisplayName 的卸载键，本探针未取证");
            return;
        }
        // 反向对照：一个必然不存在的键只能得到 None（不是崩、也不是空串身份）
        assert!(residue_identity(&format!("HKLM|{ROOT}\\TrimNoSuchApp-9f3a")).is_none());
        // APPX / 合成 id 没有卸载键身份
        assert!(residue_identity("MACHINE|all").is_none());
        assert!(residue_identity("APPX|Microsoft.Windows.Notepad_8wekyb3d8bbwe__8wekyb3d8bbwe").is_none());
        eprintln!("✓ [live-r2a] 现读到 {checked} 份真实身份，样例: {sample:?}");
    }

    /// R2a-L01 真机探针（`#[ignore]`）：审查档位的只读枚举只能证明「本机当下没有
    /// 非 ASCII 一级子键」，换一台机器未必。本探针把「现算全量 + 逐条解析不 panic」
    /// 固定成发版前实跑项（报告 §3 U01 的收口）。
    /// 跑法：`cargo test --release -- --ignored live_r2a_l01`。
    #[test]
    #[ignore = "真机枚举注册表一级子键并逐条过 hive 前缀解析"]
    fn live_r2a_l01_真实键名全量过hive解析() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        let mut total = 0usize;
        let mut non_ascii = 0usize;
        for (hive, hive_name, root) in [
            (HKEY_CURRENT_USER, "HKCU", r"Software"),
            (HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE"),
            (HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\WOW6432Node"),
        ] {
            for name in unsafe { reg_enum_subkeys(hive, root, 4096) } {
                total += 1;
                if !name.is_ascii() {
                    non_ascii += 1;
                }
                // 旧写法在这里对非 ASCII 叶名直接 panic（本探针的意义就是让它跑到底）
                let parsed = parse_reg_target(&format!("{hive_name}\\{root}\\{name}"));
                assert!(parsed.is_some(), "真实键名解析失败: {hive_name}\\{root}\\{name}");
                assert_eq!(parsed.unwrap().1, format!(r"{root}\{name}"), "子键路径必须原样保留: {name}");
            }
        }
        assert!(total > 0, "三根一级子键枚举为空 ⇒ 探针未取证（注册表读失败要查根因）");
        eprintln!("✓ [live-r2a] 现算一级子键 {total} 条，其中非 ASCII {non_ascii} 条，全部无 panic");
    }

