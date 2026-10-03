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

    /// 剥掉 Rust 行注释与块注释（保留换行）。
    ///
    /// 为什么本文件需要它：下面几条判据是**读源码形态**的，而源码里大量注释会
    /// 复述被禁的写法本身（我自己在写 §3.6 那条的注释时就踩了一次：
    /// 注释里的 `to_recycle.unwrap_or(false)` 被自己的断言抓到，假红）。
    /// 「注释里写了被禁写法」从来不是缺陷，只有真实代码里写了才是。
    fn strip_rust_comments(src: &str) -> String {
        let blank = |m: &str| m.replace(|c: char| c != '\n', " ");
        let mut out = String::with_capacity(src.len());
        let mut rest = src;
        loop {
            let b = rest.find("/*");
            let l = rest.find("//");
            match (b, l) {
                (Some(bi), Some(li)) if bi < li => {
                    out.push_str(&rest[..bi]);
                    match rest[bi..].find("*/") {
                        Some(e) => {
                            out.push_str(&blank(&rest[bi..bi + e + 2]));
                            rest = &rest[bi + e + 2..];
                        }
                        None => {
                            out.push_str(&blank(&rest[bi..]));
                            break;
                        }
                    }
                }
                (_, Some(li)) => {
                    out.push_str(&rest[..li]);
                    match rest[li..].find('\n') {
                        Some(e) => {
                            out.push_str(&blank(&rest[li..li + e]));
                            out.push('\n');
                            rest = &rest[li + e + 1..];
                        }
                        None => {
                            out.push_str(&blank(&rest[li..]));
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

    /// 2026-10-04 磁盘清理审计 §3.6：v3.3.0「常规清理固定永久删」必须钉在删除发生处。
    ///
    /// 原实现 `let to_recycle = to_recycle.unwrap_or(false);` —— 裁定只在渲染层
    /// （`cleanup.js` 的 `const toRecycle = false;`）强制，命令侧任何传 `true` 的
    /// 调用方都能翻转。翻转的后果不是「换个删法」，而是给不可逆的
    /// `cleanup:retry-failed-delete` 喂数据（`TRASH_FAILURES` 的唯一来源）。
    ///
    /// 判据是**赋值形态**而不是运行结果：`unwrap_or(false)` 与 `= false` 在
    /// 「调用方传 false」时行为完全一样，只有读源码分得开 —— 所以这条必须断源码。
    #[test]
    fn 常规清理的永久删裁定钉在命令侧() {
        let code = strip_rust_comments(include_str!("scan_execute.rs"));
        // ① 命令体内不得再出现「把渲染层参数解包成运行开关」的形态
        assert!(
            !code.contains("to_recycle.unwrap_or("),
            "cleanup_execute 又把渲染层的 to_recycle 解包成运行开关 —— \
             v3.3.0 裁定只在本仓 JS 层强制时是「任何调用方都能翻转永久删」；\
             正确形态是命令体内 `let to_recycle = false;`"
        );
        // ② 必须存在那句钉死（否则 ① 可能被改成别的形状而失去等价语义）
        assert!(
            code.contains("let to_recycle = false;"),
            "命令体内找不到 `let to_recycle = false;` —— 永久删裁定没有被钉在删除发生处"
        );
        // ③ 回收站分支必须挂 debug_assert，让「恒不可达」写进可验位置：
        //    有人把 to_recycle 改回变量时 debug 构建立刻响，而不是等真跑到线上。
        assert!(
            code.contains("debug_assert!(!to_recycle"),
            "回收站分支没有 debug_assert 标注恒不可达 —— 该分支看起来像活代码，\
         下次「顺手恢复回收站优先」的人不会知道自己踩的是 v3.3.0 裁定"
        );
        // ④ 渲染层那一侧也钉住：固定值不能被改成跟着用户勾选走
        let js = include_str!("../../../../src/scripts/cleanup.js");
        assert!(
            js.contains("const toRecycle = false;"),
            "cleanup.js 的 toRecycle 不再是固定 false —— 常规清理固定永久删是 v3.3.0 用户裁定"
        );
    }

    /// 2026-10-04 审计 §4.1：受保护路径的拒绝必须走独立计数，且独立留痕。
    ///
    /// **为什么这条是源码形态断言而不是行为断言** —— 这是本轮唯一一处「判红实验
    /// 暴露了测试没测到东西」的地方，值得写清楚：
    ///
    /// `engine/native/cleanup.rs` 里已有 `受保护路径的拒绝不混进被占用`（纯函数
    /// `classify_outcome` 的 7 条行为断言）。但**把受保护拒绝并回 `failed` 那个
    /// 真实缺陷态下，那 7 条全绿** —— 因为它们直接构造 `OutcomeCounters`，
    /// 根本走不到引擎循环里「哪个分支 +1」那一步。也就是说它们钉住的是
    /// **措辞与记账政策**，钉不住**接线**。
    ///
    /// 接线无法用行为测试覆盖的原因是环境性的：`is_path_protected` 读全局
    /// `protect::ROOTS`，用 `configure()` 注入就得写全局状态，会污染同进程并发跑的
    /// 保护断言（protect.rs M13 记的正是这个坑，本仓测试默认多线程）。
    /// 所以这里退一步断源码形态 —— 与 §3.6 的 `to_recycle` 同款取舍。
    #[test]
    fn 受保护拒绝的接线不许并回被占用() {
        let code = strip_rust_comments(include_str!("../../engine/native/cleanup.rs"));

        // ① protect 分支必须 +1 到 protected_blocked
        let at = code.find("is_path_protected(path)").expect("找不到 protect 判定");
        let branch = &code[at..];
        let end = branch.find("} else").unwrap_or(branch.len());
        let br = &branch[..end];
        assert!(
            br.contains("protected_blocked += 1"),
            "protect 分支没有给 protected_blocked 计数: {br}"
        );
        assert!(
            !br.contains("failed += 1"),
            "protect 分支又给 failed 计数了 —— 那就是「被占用」，\
             渲染层会弹「关闭相关程序后重试」的误导提示（cleanup.js:1274）: {br}"
        );

        // ② 必须留痕。这是全仓唯一永久删除链的安全闸门在动作，不是用户的操作问题。
        assert!(
            code.contains("个目标位于受保护路径，已拒绝删除"),
            "受保护拒绝没有留痕 —— 对照同文件注册表侧与回收站支都记日志，\
             唯独永久删这条不记会让这次拦截完全无迹可查"
        );

        // ③ details 里必须有独立字段，且 residual 不得混入它
        assert!(
            code.contains("\"protectedBlocked\": protected_blocked"),
            "details 缺 protectedBlocked 字段 —— 真实条数无处可查"
        );

        // ④ 分类必须走纯函数（否则行为断言与接线之间又会被一段内联逻辑隔开）
        assert!(
            code.contains("fn classify_outcome("),
            "classify_outcome 不见了 —— status/message 的判定又内联回循环里"
        );
        assert!(
            code.contains("classify_outcome(\n            &outcome,"),
            "classify_outcome 的调用点不见了 —— 判定与接线脱钩"
        );
    }

    /// 2026-10-04 磁盘清理审计 §4.6：契约表查询不许有「取不到就挑个默认值」的形态。
    ///
    /// 契约表 `engine/rule_schema.rs` 头上声明的是 fail-closed：「所有校验器拿到
    /// `None` 都必须整包拒绝」。而 `validate_cleanup_package` 此前 19 处查询里有
    /// 17 处 `unwrap_or(empty.clone())`、6 处 `unwrap_or(0)` —— 声明与实现相反。
    ///
    /// 多数默认值**碰巧**也是 fail-closed（空 `itemFields` 会让未知字段检查拒掉
    /// 每一条），所以表整体坏掉时看起来仍然安全 —— 这正是它能活这么久的原因。
    /// 但两条不是，而它们恰好是最要命的护栏：
    ///   · `positiveIntFields` 变空 ⇒ `minAgeHours/minAgeDays` 不再要求正整数，
    ///     扫描侧把 `minAgeHours: -5` 当「未声明」⇒ **minAge 护栏静默消失**，
    ///     刚创建的文件变可删；
    ///   · `exclusiveNumericFields` 变空 ⇒ 双声明时扫描侧按「未声明」处理
    ///     （完全没有护栏）、执行侧按 `max()` 取 —— 正是代码注释警告的分叉。
    ///
    /// 判据是**结构形态**而不是运行结果：默认值选得对不对，行为上可能与整包拒绝
    /// 无法区分（这正是问题），只有读源码分得开。
    #[test]
    fn 契约表查询一律走_req_不许挑默认值() {
        let code = strip_rust_comments(include_str!("rules.rs"));
        // ① 契约表查询不许直接 unwrap_or
        for line in code.lines() {
            let l = line.trim();
            if !l.contains("rule_schema::") {
                continue;
            }
            assert!(
                !l.contains("unwrap_or("),
                "契约表查询又出现了 unwrap_or（取不到就挑默认值，违反 fail-closed 声明）: {l}"
            );
        }
        // ② 必须走那两个 helper（缺席/无调用方 = 有人绕开它们自己查表）
        assert!(code.contains("fn req_list("), "缺少 req_list —— 契约表字符串数组查询的统一入口不见了");
        assert!(code.contains("fn req_number("), "缺少 req_number —— 契约表数值查询的统一入口不见了");
        for (helper, exact, what) in [
            ("req_list", 21usize, "字符串数组类查询（字段白名单 / 必填集 / 枚举）"),
            ("req_number", 10usize, "数值类查询（上限与权重）"),
        ] {
            let calls = code.matches(&format!("{helper}(\"cleanup\", ")).count();
            assert_eq!(
                calls, exact,
                "{helper} 的调用方是 {calls} 个，与本清单登记的 {exact} 个不符（{what}）。\
                 两种可能都要人工确认：① 新增了契约表查询 —— 请同步 tools/rule-schema.json \
                 与 engine/rule_schema.rs 的 `清理域被查询的每个契约键都存在`，并把这里的数字 \
                 改成新值；② 有查询被改回直接 rule_schema:: 读表 —— 那就是 fail-open 回潮，\
                 必须走 {helper}。"
            );
        }
        // ③ 两个 helper 自身必须是「取不到即 Err」，不能再有默认值分支
        for helper in ["fn req_list(", "fn req_number("] {
            let at = code.find(helper).expect("刚断言过存在");
            let body = &code[at..];
            // 花括号配平取函数体（在已剥注释的文本上做，字符串里的大括号不会截断）
            let start = body.find('{').expect("函数体缺 {");
            let mut depth = 0usize;
            let mut end = body.len();
            for (i, c) in body[start..].char_indices() {
                if c == '{' {
                    depth += 1;
                } else if c == '}' {
                    depth -= 1;
                    if depth == 0 {
                        end = start + i;
                        break;
                    }
                }
            }
            let fbody = &body[..end];
            assert!(
                !fbody.contains("unwrap_or"),
                "{helper} 内部又出现默认值分支（fail-closed 声明被架空）: {fbody}"
            );
            assert!(
                fbody.contains("ok_or_else"),
                "{helper} 内部没有 ok_or_else —— 取不到时不是整包拒绝: {fbody}"
            );
        }
        // ④ 关键：那两个护栏键在契约表里必须**非空**（空数组比缺键更隐蔽，
        //    `rule_schema::list` 返回 Some(空 vec)，`is_some()` 照样过）
        for (key, why) in [
            ("positiveIntFields", "minAge 护栏（minAgeHours/minAgeDays 必须是正整数）"),
            ("exclusiveNumericFields", "双声明互斥（扫描/执行两侧不得对同一份规则给出不同护栏）"),
            ("nonEmptyArrayFields", "非空数组约束"),
        ] {
            let v = crate::engine::rule_schema::list("cleanup", key).unwrap_or_default();
            assert!(!v.is_empty(), "cleanup.{key} 为空数组 —— {why} 形同虚设");
        }
    }

    /// 2026-10-04 磁盘清理审计 §3.2：扫描成功路径必须留痕。
    /// 引擎把「变量未解析 / pathPs 被拒 / 深度上限 / 跳过 junction」全部写到 stderr，
    /// 而命令侧此前**只在退出码非 0 时读它** —— 成功路径直接丢弃。偏偏「扫描成功
    /// 但某个条目空」只发生在成功路径，于是引擎自述「供对账用的通道」在对账最需要的
    /// 时刻是关的。这条断「成功路径也读 stderr」这个形态。
    #[test]
    fn 扫描成功路径也记留痕() {
        let code = strip_rust_comments(include_str!("scan_execute.rs"));
        assert!(
            code.contains("清理扫描留痕"),
            "扫描成功路径没有写留痕日志 —— 「有条目但一个文件都没扫到」这类问题将无迹可查"
        );
        // 且必须记 warn 而不是 error：这些不是失败，是「已按规则降级并留痕」。
        // 记成 error 会把正常降级刷成故障，真出故障时反而被淹。
        assert!(
            code.contains("\"warn\", &format!(\"清理扫描留痕"),
            "扫描留痕应记 warn（降级留痕 ≠ 失败）"
        );
        // 空 stderr 是绝大多数扫描的常态，不要为它写一行日志
        assert!(
            code.contains("if !stderr.trim().is_empty()"),
            "扫描留痕没有空串守卫 —— 正常扫描也会每次写一条空日志"
        );
        // 原先那个恒假的 `if code != 0`（块内已 return）必须已被删掉：
        // 它让 `code` 在块外留一个看似有意义的绑定，掩盖「成功路径无人读 stderr」这件事。
        assert!(
            !code.contains("扫描失败: {}"),
            "scan_execute 里又出现了块外那个恒假的 `if code != 0`（块内已 return）"
        );
    }

    /// 2026-10-04 磁盘清理审计 §3.1：规则侧不许出现设备/verbatim 路径前缀。
    ///
    /// 为什么必须在**装载端**拦（而不是只靠 `engine::protect`）：设备路径目标在
    /// 扫描侧会被当成合法路径枚举与计数，在执行侧又过不了保护判定 ——
    /// 净效果是「有条目、体积也报出来了，清理完什么都没释放」，用户无从判断。
    /// 同一条链的另一头是 `paths_save`：存进来的值会被原样采纳成条目 path，
    /// 那条入口的闸门在 `commands/paths.rs::path_value_problem`（同批新增）。
    ///
    /// ⚠️ 写这条用例时踩到的一件事，值得留在断言里：**`\\?\` 与 `\??\` 早就被
    /// 原有那条「含 `?` 通配」检查拒掉了**（两个前缀自身含 `?`）。也就是说
    /// §3.1 里真正漏网的只有 `\\.\`（不含 `?`）。但「被拒」不等于「对」——
    /// 原理由把一个安全语义问题报成 glob 能力问题，排查会被引到 `expand_glob_dirs`
    /// 上去、找不到真正的防线。所以下面逐条断**理由**，不只是断「被拒」。
    #[test]
    fn 清理语义校验_设备路径前缀不许进规则库() {
        // ① 设备路径：三个形态各钉一条，且理由必须指向「设备路径」
        for bad in [r"\\.\C:\Windows\Temp", r"\??\C:\Windows\Temp", r"\\.\PIPE\foo"] {
            let mut t = ok_item();
            t["fileKeys"] = json!([{ "path": bad, "pattern": "*", "recurse": true }]);
            expect_reject(t, "设备路径");
        }
        // ② `\\?\` 长路径前缀：合法但执行侧不支持，理由不许再被报成「含 ? 通配」
        let mut t = ok_item();
        t["fileKeys"] = json!([{ "path": r"\\?\C:\Users\tester\AppData\Local\TrimTest", "pattern": "*", "recurse": true }]);
        expect_reject(t.clone(), "长路径前缀");
        assert!(
            validate_cleanup_package(&ok_pkg(t.clone())).is_err(),
            "长路径前缀必须被拒（执行侧不还原长路径，会扫描命中但执行漏删）"
        );
        // ③ 真正的单问号通配仍按原理由拒 —— 防止上面两条把 `?` 分支整体废掉
        let mut t = ok_item();
        t["fileKeys"] = json!([{ "path": r"C:\Users\tester\AppData\Local\Tri?Test", "pattern": "*", "recurse": true }]);
        expect_reject(t, "含 ? 通配");
        // ④ 正向对照：普通形态必须仍放行（收紧过头会把正常规则打死）
        for good in [r"%LOCALAPPDATA%\TrimTest", r"C:\Users\tester\AppData\Local\TrimTest"] {
            let mut t = ok_item();
            t["fileKeys"] = json!([{ "path": good, "pattern": "*", "recurse": true }]);
            if let Err(reason) = validate_cleanup_package(&ok_pkg(t)) {
                panic!("合法形态 `{good}` 被误拒: {reason}");
            }
        }
        // ⑤ 直接断判定器本身
        for bad in [r"\\.\C:\x", r"\??\C:\x", r"\\.\PIPE\foo", r"\\.\PhysicalDrive0", r"\\?\C:\x"] {
            assert!(
                file_path_form_problem(bad, 260).is_some(),
                "file_path_form_problem 放过前缀形态 `{bad}`"
            );
        }
        // ⑥ detect[].path 已纳入形态闸（审计 §4.11）。
        //    detect 此前**完全不过任何校验**（它在 itemFields 白名单里，不是未知
        //    字段），于是设备路径能从这里进库：扫描侧判「存在」、执行侧永远删不掉，
        //    净效果是「条目恒显示存在、清理时一条不删」。§3.1 只给 fileKeys 装了闸。
        for bad in [r"\\.\C:\Windows\Temp", r"\??\C:\Windows\Temp"] {
            let mut t = ok_item();
            t["detect"] = json!([{ "path": bad }]);
            expect_reject(t, "设备路径");
        }
        // detect 的 type=reg 形态是**注册表**路径，不能套文件闸（那份闸按盘符判形态）
        let mut t2 = ok_item();
        t2["detect"] = json!([{ "type": "reg", "path": r"HKCU\Software\SomeVendor" }]);
        if let Err(reason) = validate_cleanup_package(&ok_pkg(t2)) {
            panic!("detect type=reg 的正常注册表路径被误拒: {reason}");
        }
        // …但注册表形态也必须有自己的最小口径（hive 前缀）
        let mut t3 = ok_item();
        t3["detect"] = json!([{ "type": "reg", "path": r"C:\Windows\Temp" }]);
        expect_reject(t3, "必须以 HKLM");

        // ⑦ excludePaths[] 同样纳入（它是**字符串**数组，与 detect 不同形）
        for (bad, needle) in [
            (r"\\.\C:\Windows\Temp", "设备路径"),
            (r"\??\C:\Windows\Temp", "设备路径"),
            (r"\\?\C:\Users\x", "长路径前缀"),
        ] {
            let mut t = ok_item();
            t["excludePaths"] = json!([bad]);
            expect_reject(t, needle);
        }
        // 正向对照：`::` 具名值形态是**注册表面**，不得被文件闸误伤
        let mut t = ok_item();
        t["excludePaths"] = json!([r"HKLM\SOFTWARE\SomeVendor::KeepMe"]);
        if let Err(reason) = validate_cleanup_package(&ok_pkg(t.clone())) {
            // 该形态要求 regKeys 不含删树/通配；ok_item 没有 regKeys，应当放行
            panic!("excludePaths 的 :: 具名值形态被文件闸误伤: {reason}");
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

// ==================== §4.7 防回滚水位线：进程内高水位（2026-10-04） ====================

/// 高水位 CAS 只升不降、非法值忽略。
///
/// 静态量是进程级的：本测试开头先归零（全仓只有本用例触这个量，无并发竞争面）。
#[test]
fn 进程内高水位只升不降且忽略非法值() {
    WATERMARK_HIGH.store(0, std::sync::atomic::Ordering::Relaxed);
    watermark_high_raise(100.0);
    assert_eq!(watermark_high_get(), 100.0, "抬升必须生效");
    watermark_high_raise(50.0);
    assert_eq!(watermark_high_get(), 100.0, "更低版本不得降地板");
    watermark_high_raise(f64::NAN);
    watermark_high_raise(0.0);
    watermark_high_raise(-5.0);
    assert_eq!(watermark_high_get(), 100.0, "非法值必须忽略");
    watermark_high_raise(f64::INFINITY);
    assert_eq!(watermark_high_get(), 100.0, "无限值也是非法值（版本是有限日期戳）");
    watermark_high_raise(200.0);
    assert_eq!(watermark_high_get(), 200.0, "更高版本必须抬上去");
    WATERMARK_HIGH.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// §4.7 接线钉（审计 §9.4 教训）：高水位必须真的折进读取侧地板与写入侧落盘前。
/// 纯函数测试走不到这两处接线 —— 把 raise 调用摘掉，上面那条用例照样全绿。
#[test]
fn 水位线高水位_两侧接线在位() {
    let src = include_str!("rules.rs");
    // 读取侧：磁盘值先抬进高水位、再与高水位取 max 返回
    assert!(
        src.contains("watermark_high_raise(disk);"),
        "rules_watermark 必须把磁盘值抬进进程内高水位（否则文件被删后地板回落，§4.7 复发）"
    );
    assert!(
        src.contains("watermark_high_get();") || src.contains("watermark_high_get()"),
        "rules_watermark 必须折入进程内高水位"
    );
    // 写入侧：落盘前先抬高水位（写盘失败时本进程仍记得该版本）
    assert!(
        src.contains("watermark_high_raise(version);"),
        "set_rules_watermark 必须在写盘前抬进程内高水位"
    );
    // 地板消费点：floor 仍取 max(builtin, rules_watermark())——rules_watermark 现含进程内记忆
    assert!(
        src.contains("let floor = builtin_version.max(rules_watermark());"),
        "防回滚地板的消费点漂移了"
    );
}
