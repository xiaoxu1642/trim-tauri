//! 清理规则的验收三件套（D6 第 1 条）：源清单拼装、https-only、语义校验判定器、
//! 装载与更新两处同校——跨 rules 与 rules_update 两个契约面，故单独成文。
//!
//! 各面 glob 引进来是为了让「实现搬走 / 判据改名」立刻变成编译错误，
//! 而不是让用例静默少测一条。


use serde_json::{Value, json};
use std::time::Duration;
use super::rules::*;
use super::rules_update::*;
use super::state::*;
    use super::*;

    /// 发布源清单的唯一拼装口是 `release_source_urls_for`（残留库共用）。
    /// 清理库这份 const 若与它漂移（改了一个镜像、漏了另一个），在线更新会**只坏一个域**，
    /// 而那种半坏形态最容易长期无人发现 —— 故按整条 URL 逐字钉住。
    #[test]
    fn 三条源与仓库内路径的拼装必须同源() {
        let built = release_source_urls_for("src-tauri/data/cleanup-rules.json");
        assert_eq!(built.len(), RULES_UPDATE_URLS.len(), "源条数漂移");
        for (i, url) in RULES_UPDATE_URLS.iter().enumerate() {
            assert_eq!(built[i], *url, "第 {i} 条源与拼装口不一致");
        }
        // 残留库用同一函数换路径，禁止再抄第二份清单
        let residue = release_source_urls_for("src-tauri/data/uninstall-residue-rules.json");
        for u in &residue {
            assert!(u.ends_with("uninstall-residue-rules.json"), "残留源路径错: {u}");
            assert!(u.starts_with("https://"), "源必须 https: {u}");
        }
    }

    /// 审查 v2-L4：自定义规则源只认 https —— 明文 http 与非法协议一律进「被拒」，
    /// 且大小写不敏感（`HTTPS://` 也要认）。
    #[test]
    fn custom_rules_source_is_https_only() {
        let cfg = json!({
            "urls": [
                "https://example.com/rules.json",
                "HTTPS://mirror.example.org/r.json",
                "http://plain.example.net/r.json",
                "ftp://nope/r.json",
                "rules.json"
            ]
        });
        let (accepted, rejected) = pick_https_urls(&cfg);
        assert_eq!(
            accepted,
            vec![
                "https://example.com/rules.json".to_string(),
                "HTTPS://mirror.example.org/r.json".to_string()
            ],
            "https 源必须全部保留（大小写不敏感）: {accepted:?}"
        );
        assert_eq!(
            rejected,
            vec![
                "http://plain.example.net/r.json".to_string(),
                "ftp://nope/r.json".to_string(),
                "rules.json".to_string()
            ],
            "非 https 源必须全部被拒: {rejected:?}"
        );
    }

    /// 缺 `urls`（或不是数组）→ 两个列表都空，不许回退到内置源之外的隐式行为。
    #[test]
    fn custom_rules_source_missing_urls_is_empty() {
        let (accepted, rejected) = pick_https_urls(&json!({ "headers": {} }));
        assert!(accepted.is_empty() && rejected.is_empty());
    }

    /// 首个差异的定位信息（行号 + 两侧原文片段）

    /// PS 模板替换对拍：同一合成输入，JS 生成 vs Rust 生成**逐字节**比较。
    ///


    /// 版本号文案（`Number(x)||0` 与 JS String(n) 同口径）
    #[test]
    fn version_text() {
        assert_eq!(js_num_str(js_num_or_zero(Some(&json!("42")))), "42");
        assert_eq!(js_num_str(js_num_or_zero(Some(&json!(0)))), "0");
    }

    /// 规则更新链路真实网络验证（默认 `#[ignore]`，发布前手动跑）：
    /// 真拉内置发布源 → `http_get`（`allow_host = None`，用户自选源链路）→
    /// `validate_remote_rules`（尺寸 → **ed25519 验签** → JSON 结构 → 条目形状 → 版本防降级）
    /// → `rulesVersion` 可解析、原文可 JSON 解析。
    ///
    /// 该链路的信任边界是「验签 + 防降级」而非宿主白名单，本用例正是验证这一点。
    /// 源不可达（无网络/私有仓库未公开）时打印原因并跳过——改用 git 回退路径的结论代替。
    /// 执行：`cargo test -- --ignored rules_update`
    #[test]
    #[ignore = "需要网络；发布前手动执行"]
    fn rules_update_chain_verify() {
        let mut last_err = String::new();
        let mut fetched: Option<(&str, String)> = None;
        for url in RULES_UPDATE_URLS {
            match http_get(url, &[], Duration::from_millis(RULES_DOWNLOAD_TIMEOUT_MS), None) {
                Ok(t) => {
                    fetched = Some((url, t));
                    break;
                }
                Err(e) => last_err = format!("{url} -> {e}"),
            }
        }
        let Some((source, text)) = fetched else {
            // 审查 M13：这里原本 `return` —— 断网时这条发布前门禁**绿灯通过**，
            // 而它是唯一真跑过网络 + 真验签的链路用例，"跑过了" 与 "没网" 无法区分。
            // 发布前门禁的语义是「必须真验成」，所以拿不到源就失败，让人去处理网络/源。
            panic!(
                "所有发布源均不可达，规则库更新链未被真正验证（最后错误：{last_err}）。\
                 本用例是发布前门禁：请联网后重跑 `cargo test rules_update_chain_verify -- --ignored --nocapture`，\
                 不许把跳过状态计入通过。"
            );
        };
        // current_version 传 0：只验签名/结构/形状，不做降级比较（本地版本无关）
        let (version, ok_text) =
            validate_remote_rules(&text, 0.0).expect("远端规则未通过 ed25519 验签/结构校验");
        assert_eq!(ok_text, text, "校验通过时返回文本应与原文一致");
        let parsed: Value = serde_json::from_str(&ok_text).expect("验签通过的文本必须可 JSON 解析");
        assert!(
            parsed.get("rulesVersion").is_some(),
            "规则缺少 rulesVersion 字段"
        );
        assert!(version > 0.0, "rulesVersion 无法解析为正数（得到 {}）", version);
        eprintln!(
            "[rules-update] ✓ 源 {} 验签通过，rulesVersion={}",
            source,
            js_num_str(version)
        );
    }

    // ==================== V2 P1-B0 清理库语义校验（2026-09-30） ====================

    fn ok_item() -> Value {
        json!({
            "id": "t-ok",
            "ver": 20260928,
            "name": "测试项",
            "risk": "low",
            "evidence": "只作用于测试目录",
            "recommended": true,
            "domain": "system",
            "group": "g1",
            "nature": "log",
            "regenerable": true,
            "prov": {
                "source": "builtin",
                "sourceClass": "independent",
                "ref": "tests/cleanup",
                "reviewedAt": "2026-09-30"
            },
            "fileKeys": [{ "path": "%LOCALAPPDATA%\\TrimTest", "pattern": "*", "recurse": true }]
        })
    }

    fn ok_pkg(item: Value) -> Value {
        json!({
            "version": 2,
            "rulesVersion": 20260928,
            "groups": [{ "key": "g1", "title": "测试组", "items": [item] }]
        })
    }

    /// 坏包必须整包拒绝，且原因要指到具体字段（"没报错"不等于"已验证"）
    fn expect_reject(item: Value, needle: &str) {
        match validate_cleanup_package(&ok_pkg(item)) {
            Ok(()) => panic!("应拒绝且含「{needle}」，但被放行了"),
            Err(err) => assert!(err.contains(needle), "拒绝原因未指到「{needle}」，实际：{err}"),
        }
    }

    #[test]
    fn 内置清理规则必须通过语义校验() {
        let v: Value = serde_json::from_str(BUILTIN_RULES_JSON).expect("内置规则 JSON 坏了");
        if let Err(reason) = validate_cleanup_package(&v) {
            panic!("内置清理规则未通过装载侧语义校验（发布物自身坏了）: {reason}");
        }
    }

    /// v5 C-1：删树 / 通配清值型 `regKeys` 必须过注册表禁删面。装载侧不拦，一条**验签通过**的
    /// 规则就能把 `HKCU\Software\Microsoft\…` 整棵端掉，而执行侧那道闸要等到删除时才响。
    /// 六条断言各钉一个方向 —— 只留拒的那几条，"把所有 regKeys 一刀切拒掉"也能全绿。
    #[test]
    fn 清理语义校验_删树与通配清值过注册表禁删面() {
        let mut t = ok_item();
        // ① Microsoft 树内删树 → 拒
        t["regKeys"] = json!([{ "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" }]);
        expect_reject(t.clone(), "禁删面");

        // ② 同一目标改成通配清值（不在放行清单里）→ 同样拒：一次清空该键全部值与删树同族
        t["regKeys"] = json!([
            { "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "*" }
        ]);
        expect_reject(t.clone(), "通配清值");

        // ③ 具名单值删除 → 放行（`reg_target_block_reason` 自述只管递归删除，别越界裁功能）
        t["regKeys"] = json!([
            { "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "OneDrive" }
        ]);
        validate_cleanup_package(&ok_pkg(t.clone()))
            .expect("具名 value 被误拒 = 禁删面越出「递归删除」管辖语义");

        // ④ 放行清单内的 MRU 键 → 放行（内置库两条 MRU 规则就是这个写法，清单必须自洽）
        t["regKeys"] = json!([
            { "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "value": "*" }
        ]);
        validate_cleanup_package(&ok_pkg(t.clone()))
            .expect("CLEANUP_REG_WIPE_ALLOW 内的键被拒 = 内置库自身过不了自己的闸");

        // ⑤ 树外产品键删树 → 放行（protect.rs 注释里点名的合法形态）
        t["regKeys"] = json!([{ "path": "HKLM\\SOFTWARE\\ESET" }]);
        validate_cleanup_package(&ok_pkg(t.clone())).expect("树外产品键被误拒 = 判据过宽");

        // ⑥ 大小写不规范的写法同样拦得住：`normalize_reg_target` 归一成大写再比对，
        //    `hkcu\…` 不得成为绕过禁删面的写法
        t["regKeys"] = json!([{ "path": "hkcu\\Software\\microsoft\\windows\\currentversion\\Run" }]);
        expect_reject(t, "禁删面");
    }

    #[test]
    fn 清理语义校验_合法最小包通过() {
        validate_cleanup_package(&ok_pkg(ok_item())).expect("合法包被拒");
    }

    #[test]
    fn 清理语义校验_判定器不会恒放行() {
        // 反向钉桩：包彻底坏掉时若还放行，说明校验器坏成"永远绿"（本仓有假绿前科 v1 M13）
        let junk = json!({ "rulesVersion": 1, "groups": [] });
        assert!(validate_cleanup_package(&junk).is_err(), "空 groups 的包被放行 = 校验器失效");
        let junk2 = json!({ "groups": [{ "key": "k", "items": [{}] }] });
        assert!(validate_cleanup_package(&junk2).is_err(), "缺 rulesVersion / 空条目被放行 = 校验器失效");
    }

    #[test]
    fn 清理语义校验_逐条拒掉坏包形态() {
        // 必填与枚举
        let mut it = ok_item();
        it.as_object_mut().unwrap().remove("name");
        expect_reject(it, "缺必填字段 name");
        let mut it = ok_item();
        it["risk"] = json!("deluxe");
        expect_reject(it, "risk「deluxe」");
        let mut it = ok_item();
        it["prov"]["sourceClass"] = json!("imported");
        expect_reject(it, "prov.sourceClass「imported」");

        // 未知字段与已裁决移除的字段
        let mut it = ok_item();
        it.as_object_mut().unwrap().insert("sizeHint".to_string(), json!(1));
        expect_reject(it, "未知字段 sizeHint");
        let mut it = ok_item();
        it.as_object_mut().unwrap().insert("deleteMode".to_string(), json!("recycle"));
        expect_reject(it, "已裁决移除的字段 deleteMode");
        let mut it = ok_item();
        it.as_object_mut().unwrap().insert("excludeKeys".to_string(), json!([]));
        expect_reject(it, "已裁决移除的字段 excludeKeys");

        // 形态：/ 分隔符、? 通配、多星 pattern、缺显式 recurse、子对象未知字段
        let mut it = ok_item();
        it["fileKeys"][0]["path"] = json!("%LOCALAPPDATA%/TrimTest");
        expect_reject(it, "含 / 分隔符");
        let mut it = ok_item();
        it["fileKeys"][0]["path"] = json!("%LOCALAPPDATA%\\Trim?Test");
        expect_reject(it, "含 ? 通配");
        let mut it = ok_item();
        it["fileKeys"][0]["pattern"] = json!("**");
        expect_reject(it, "单星能力");
        let mut it = ok_item();
        it["fileKeys"][0].as_object_mut().unwrap().remove("recurse");
        expect_reject(it, "缺必填字段 recurse");
        let mut it = ok_item();
        it["fileKeys"][0].as_object_mut().unwrap().insert("depth".to_string(), json!(2));
        expect_reject(it, "fileKeys 未知字段 depth");

        // 布尔字段不许写成字符串
        let mut it = ok_item();
        it["recommended"] = json!("true");
        expect_reject(it, "recommended 必须是布尔");

        // 条目级版本戳：缺失与不等都必须红（V2 P2-A1）
        let mut it = ok_item();
        it.as_object_mut().unwrap().remove("ver");
        expect_reject(it, "缺条目级版本戳 ver");
        let mut it = ok_item();
        it["ver"] = json!(20260101);
        expect_reject(it, "与顶层 rulesVersion");
        let mut it = ok_item();
        it["ver"] = json!("20260928");
        expect_reject(it, "缺条目级版本戳 ver");

        // 时效护栏：互斥 + 正整数
        let mut it = ok_item();
        it["minAgeHours"] = json!(24);
        it["minAgeDays"] = json!(1);
        expect_reject(it, "互斥");
        let mut it = ok_item();
        it["minAgeDays"] = json!(0);
        expect_reject(it, "必须是正整数");

        // 进程约束字段写了就必须非空
        let mut it = ok_item();
        it["restartProcesses"] = json!([]);
        expect_reject(it, "restartProcesses 存在但不是非空数组");

        // token 未登记（清理侧允许集与残留侧刻意不同，见 tools/rule-schema.json）
        let mut it = ok_item();
        it["fileKeys"][0]["path"] = json!("%ZZ_NOT_A_REAL_TOKEN%\\x");
        expect_reject(it, "未登记");

        // excludePaths 的 :: 具名值排除只能配具名值 regKeys（F-2）
        let mut it = ok_item();
        it["regKeys"] = json!([{ "path": "HKCU\\Software\\TrimTest" }]);
        it["excludePaths"] = json!(["HKCU\\Software\\TrimTest::ValueName"]);
        expect_reject(it, "excludePaths 含具名值排除");

        // id 字符集 / 重复 / 目标精确重复
        let mut it = ok_item();
        it["id"] = json!("bad id!");
        expect_reject(it, "id 含非");
        let pair = json!({
            "version": 2,
            "rulesVersion": 20260928,
            "groups": [{ "key": "g1", "title": "T", "items": [ok_item(), ok_item()] }]
        });
        let err = validate_cleanup_package(&pair).unwrap_err();
        assert!(err.contains("规则 id 重复"), "重复 id 未被拒: {err}");
        let mut other = ok_item();
        other["id"] = json!("t-other");
        let overlap = json!({
            "version": 2,
            "rulesVersion": 20260928,
            "groups": [{ "key": "g1", "title": "T", "items": [ok_item(), other] }]
        });
        let err = validate_cleanup_package(&overlap).unwrap_err();
        assert!(err.contains("精确重复"), "目标精确重复未被拒: {err}");

        // 组结构：title 必填
        let bad_group = json!({
            "version": 2,
            "rulesVersion": 20260928,
            "groups": [{ "key": "g1", "items": [ok_item()] }]
        });
        let err = validate_cleanup_package(&bad_group).unwrap_err();
        assert!(err.contains("groups.缺必填字段 title"), "组缺 title 未被拒: {err}");

        // 顶层未知字段（残留库早有此道，清理库此前没有）
        let mut pkg = ok_pkg(ok_item());
        pkg.as_object_mut().unwrap().insert("extraTop".to_string(), json!(1));
        let err = validate_cleanup_package(&pkg).unwrap_err();
        assert!(err.contains("顶层未知字段 extraTop"), "顶层未知字段未被拒: {err}");
    }

    #[test]
    fn 清理语义校验与夹具一致() {
        // 夹具由 Node 侧维护（tools/fixtures/cleanup-contract.json），两个消费者各自独立实现判定：
        // 任何一侧放宽，另一侧就在这里判红（口径同 uninstall.rs::residue_validator_matches_shared_fixture）
        let raw = include_str!("../../../../tools/fixtures/cleanup-contract.json");
        let f: Value = serde_json::from_str(raw).expect("清理契约夹具解析失败");
        let cases = f["packages"].as_array().expect("夹具缺 packages");
        let mut diff: Vec<String> = Vec::new();
        let mut rejected = 0usize;
        for c in cases {
            let label = c["label"].as_str().unwrap_or("?");
            let expect_ok = c["ok"].as_bool().unwrap_or(false);
            let got_ok = validate_cleanup_package(&c["pkg"]).is_ok();
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
            cases.len() >= 12 && rejected >= 10,
            "夹具用例数 {}（其中判红 {rejected}）过少，无法覆盖各保护类别",
            cases.len()
        );
        assert!(diff.is_empty(), "语义校验与夹具不一致：\n{}", diff.join("\n"));
    }

    #[test]
    fn 清理装载与更新两处都接同一个语义校验器() {
        // 接线断言（口径同 tools/check-residue-rule-contract.mjs 的 E2/E4b）：数据目录与
        // 更新链各写一套字段规则，就是"更新放行、装载拒绝"那种分叉的起点。
        // v3 D3 起本域拆成 commands/cleanup/ 目录，断言读整个目录而不是单个文件——
        // 装载侧在 rules.rs、更新侧在 rules_update.rs，两侧都必须在这份文本里看得见，
        // 少一侧就等于断言静默脱网。
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/commands/cleanup");
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .expect("读自身源码做接线断言")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("rs"))
            .collect();
        files.sort();
        // 排除测试文件自己：本用例的断言字面量里就写着 `validate_cleanup_package(&parsed)`，
        // 把自己算进对照文本等于让死断言自我证明（同 check-assets-used 排除 vendor/docs 的理由）。
        files.retain(|p| {
            p.file_name().and_then(|s| s.to_str()).map(|n| !n.contains("_tests")).unwrap_or(false)
        });
        let src = files
            .iter()
            .map(|p| std::fs::read_to_string(p).expect("读自身源码做接线断言"))
            .collect::<Vec<_>>()
            .join("\n");
        let fn_body = |head: &str| -> String {
            let i = src.find(head).unwrap_or_else(|| panic!("找不到 {head}"));
            let rest = &src[i..];
            rest[..rest.find("\n}\n").unwrap_or(rest.len())].to_string()
        };
        let load = fn_body("fn read_verified_data_rules");
        assert!(
            load.contains("validate_cleanup_package(&parsed)") && load.contains("quarantine_file(&file"),
            "数据目录装载缺语义校验或缺隔离动作：只回退内置不隔离 = 每次扫描重复判同一份坏文件"
        );
        let builtin = fn_body("fn read_builtin_rules");
        assert!(
            builtin.contains("validate_cleanup_package(&v)"),
            "内置副本没过同一道语义校验 = 给内置开了豁免通道"
        );
        let remote = fn_body("fn validate_remote_rules");
        assert!(
            remote.contains("validate_cleanup_package(&parsed)") && remote.contains("verify_rules_text"),
            "更新链必须复用装载侧校验器（不许另写一套字段规则）"
        );
        assert!(
            !remote.contains("\"条目缺少 id/name 字段\""),
            "更新链退回了旧的弱形状检查（只查 id/name 是否存在）"
        );
    }
