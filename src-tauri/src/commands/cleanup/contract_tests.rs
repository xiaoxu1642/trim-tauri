//! 清理规则的验收三件套（D6 第 1 条）：语义校验判定器、装载面接线——
//! 在线更新链已退役（2026-10-06 用户裁定：规则只随包体更新），本文件只保留装载侧契约。
//!
//! 各面 glob 引进来是为了让「实现搬走 / 判据改名」立刻变成编译错误，
//! 而不是让用例静默少测一条。


use serde_json::{Value, json};
use super::rules::*;
use super::state::*;

// R4-L06：这里原本挂着两段孤儿 `///`（「首个差异的定位信息」「PS 模板替换对拍」）——
// 它们描述的机制都已退役，而 Rust 会把紧邻的 doc 注释归给**下一个 item**，
// 于是这两段读起来像 `js_num_str` 的文档。退役说明不该靠「挂在谁头上」活着，直接删。

/// 版本号文案（`Number(x)||0` 与 JS String(n) 同口径）——随更新链退役后仅测试消费，收进本文件
fn js_num_str(n: f64) -> String {
    if !n.is_finite() {
        return "NaN".to_string();
    }
    if n.fract() == 0.0 && n.abs() < 9e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

    /// 版本号文案（`Number(x)||0` 与 JS String(n) 同口径）
    #[test]
    fn version_text() {
        assert_eq!(js_num_str(js_num_or_zero(Some(&json!("42")))), "42");
        assert_eq!(js_num_str(js_num_or_zero(Some(&json!(0)))), "0");
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

    /// pathPs 必须进重复目标登记册（与 fileKeys/regKeys 同姿势）。
    /// 真机依据（2026-10-22 gfx 组）：`nvidiaCache`（pathPs 整树）报的 387,378,791 B 与
    /// `nvidiaShaderCache` 清单里落在同一目录树下的 162 个文件逐字节相等，而登记册
    /// 从不收 pathPs ⇒ 装载侧与门禁都看不见 ⇒ 界面逐条相加虚高 1.61×。
    /// 判红自证：删掉 rules.rs 里 `ps|` 那段登记 ⇒ 第一条断言红；
    /// 把它写成大小写敏感比较 ⇒ 第二条（不同大小写的同根）红。
    #[test]
    fn 目录型同根重复必须整包拒绝() {
        let pkg = |a: Value, b: Value| {
            json!({
                "version": 2,
                "rulesVersion": 20260928,
                "groups": [{ "key": "g1", "title": "测试组", "items": [a, b] }]
            })
        };
        let mut p1 = ok_item();
        p1["id"] = json!("ps-a");
        p1["pathPs"] = json!(r"$env:LOCALAPPDATA + '\TrimTestCache'");
        p1["fileKeys"] = json!([{ "path": "%LOCALAPPDATA%\\TrimTestA", "pattern": "*", "recurse": true }]);
        let mut p2 = ok_item();
        p2["id"] = json!("ps-b");
        // 大小写不同的同一根：Windows 路径大小写不敏感，登记必须折成同一个键
        p2["pathPs"] = json!(r"$env:LOCALAPPDATA + '\trimtestcache'");
        p2["fileKeys"] = json!([{ "path": "%LOCALAPPDATA%\\TrimTestB", "pattern": "*", "recurse": true }]);
        let err = validate_cleanup_package(&pkg(p1.clone(), p2.clone()))
            .expect_err("同根的两条 pathPs 必须整包拒绝");
        assert!(
            err.contains("pathPs 与 ps-a 精确重复"),
            "拒绝原因必须指到前一条 id（且点名是 pathPs 面），实际：{err}"
        );
        // 正向对照：不同根的两条照常放行 —— 闸收紧过头会把正常规则打死
        p2["pathPs"] = json!(r"$env:LOCALAPPDATA + '\TrimTestOther'");
        if let Err(reason) = validate_cleanup_package(&pkg(p1, p2)) {
            panic!("不同根的 pathPs 不得被拒: {reason}");
        }
        // 退化位对照：`pathPs:"''"` 求值为空、整条在扫描侧 detect 就 continue（现算全库 1 条：
        // wechatCache），它不是「根」，两条这样的规则各靠 candidatesPs 自动发现，彼此不重复。
        // 若把它们当精确重复整包拒，就是拿一个不存在的冲突打死合法发布物。
        let mut d1 = ok_item();
        d1["id"] = json!("ps-dead-a");
        d1["pathPs"] = json!("''");
        d1["fileKeys"] = json!([{ "path": "%LOCALAPPDATA%\\TrimTestDeadA", "pattern": "*", "recurse": true }]);
        let mut d2 = ok_item();
        d2["id"] = json!("ps-dead-b");
        d2["pathPs"] = json!("''");
        d2["fileKeys"] = json!([{ "path": "%LOCALAPPDATA%\\TrimTestDeadB", "pattern": "*", "recurse": true }]);
        if let Err(reason) = validate_cleanup_package(&pkg(d1, d2)) {
            panic!("两条退化位 '' 不得被判 pathPs 精确重复: {reason}");
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
    /// 调用方都能翻转。翻转的后果不是「换个删法」——回收站支会重新变成活路径
    /// （2026-10-12 起该支与回收站重试链已整链退役，钉桩继续守等价裁定）。
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

    // ==================== P0 约束条款回归断言（G-1 同批，2026-10-07） ====================
    //
    // R-3 / R-4 / S-2 是方案 §2.3–§2.4 的**约束条款**：价值不在"现在对"，而在防止后续
    // 重构把口径放宽 —— 所以判据断的是**源码形态**。行为测试在放宽的当天往往照样全绿
    // （例：还原成功后顺手删掉备份，用户那天确实还原到了；只有读源码分得开）。

    /// R-3：具名单值删除前必须导出**整父键**，且备份失败时整条不删。
    ///
    /// 导出目标若掺进具名值（`键::值` 那种形态），零长度值与同键其它值就丢了还原依据；
    /// 备份失败若继续删除，等于「无备份地删」——R-3 两条都要钉住。
    #[test]
    fn 注册表删除前置备份_导出整父键且失败不删() {
        let code = strip_rust_comments(include_str!("../../engine/native/cleanup.rs"));
        let at = code.find("let stamp = crate::engine::now_ms();").expect("找不到清理域注册表备份段");
        let seg = &code[at..];
        let seg = &seg[..seg.find("let mut removed = 0i64;").unwrap_or(seg.len())];
        // ① 导出目标由键路径 rest 拼成（整父键）；备份循环里具名值被显式忽略（`rest, _`）
        assert!(
            seg.contains("format!(\"{hive_short}\\\\{rest}\")"),
            "注册表备份的导出目标必须由键路径拼成（整父键）: {seg}"
        );
        assert!(
            seg.contains("for (i, (hive, rest, _)) in parsed.iter().enumerate()"),
            "备份循环必须显式忽略具名值（`rest, _`）—— 掺进值名就不是整父键了"
        );
        // ② 备份失败分支必须排在删除循环之前（先备份后删，失败即整条不删）
        let fail_at = seg.find("if backup_failed").expect("找不到备份失败分支");
        let remove_at = code[at..]
            .find("for (hive, rest, value) in &parsed")
            .expect("找不到删除循环");
        assert!(fail_at < remove_at, "备份失败分支必须排在删除循环之前（先备份后删）");
    }

    /// R-4：还原成功不得自删还原依据（`.reg` / 清单 / 副本只按统一保留上限裁撤）。
    ///
    /// 判据分两半：还原链**一个删除调用都不许有**；删除链的保留上限裁撤必须还在位。
    #[test]
    fn 还原链不得删除自己的还原依据() {
        let restore = strip_rust_comments(include_str!("backup.rs"));
        for needle in ["remove_file", "remove_dir_all", "remove_dir("] {
            assert!(
                !restore.contains(needle),
                "backup.rs 出现 {needle}：还原链不得删除 .reg 备份 / 清单 / 副本\
                 （保留裁剪只走 paths::prune_backups 与 native::prune_file_backups）"
            );
        }
        // 另一半：不是"不裁"，而是"只按统一上限裁"——裁撤接线必须还在
        let engine = strip_rust_comments(include_str!("../../engine/native/cleanup.rs"));
        assert!(engine.contains("paths::prune_backups("), "注册表备份的保留上限裁撤不见了");
        assert!(engine.contains("prune_file_backups("), "永久删副本的保留上限裁撤不见了");
        let paths = strip_rust_comments(include_str!("../../engine/paths.rs"));
        assert!(paths.contains("BACKUP_KEEP"), "统一保留上限常量 BACKUP_KEEP 不见了");
    }

    /// S-2：结束进程只允许使用「占用检测确认过的一次性白名单」；系统关键进程不可结束。
    #[test]
    fn 结束进程只认一次性白名单快照() {
        let code = strip_rust_comments(include_str!("scan_execute.rs"));
        assert!(
            code.contains(
                "pub fn cleanup_kill_locked_processes<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {"
            ),
            "结束进程入口的签名必须只有 window —— 接受调用方传入的 PID 清单 = 绕过占用检测"
        );
        let at = code.find("pub fn cleanup_kill_locked_processes").expect("找不到结束进程入口");
        let body = &code[at..];
        let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
        assert!(
            body.contains(".remove(&label)"),
            "白名单必须一次性取走（remove）：反复读同一份陈旧 PID 快照会杀到被复用的 PID"
        );
        assert!(body.contains("pid == self_pid"), "缺自身 PID 剔除：存在结束自己的路径");
        assert!(
            code.contains(r#".filter(|p| p.get("critical").and_then(|v| v.as_bool()) == Some(false))"#),
            "白名单构建必须剔除 critical 进程（系统关键进程只展示、无结束入口）"
        );
    }

    /// S-2 的另一半：占用检测必须**先于**执行删除（渲染层流程）。
    #[test]
    fn 占用检测先于执行删除() {
        let js = include_str!("../../../../src/scripts/cleanup.js");
        let lock = js.find("await offerCloseLocked(lockIds)").expect("找不到清理前占用检测调用点");
        let exec = js.find("api.cleanup.execute(").expect("找不到清理执行调用点");
        assert!(lock < exec, "占用检测必须在清理执行之前（S-2：锁定检查先于删除）");
    }

    // ==================== G-2 全局年龄策略（2026-10-07） ====================
    //
    // 行为面（只收紧 / 关闭不变 / 三档）已由 native-scanner 的
    // `global_min_age_only_tightens` 与 `global_min_age_file_text_shapes` 钉住；
    // 这里钉的是**接线**与**双真源**——两条都是行为测试看不见的那一类。

    /// G-2：扫描侧与执行侧必须调**同一个**读取函数与**同一个** tighten，
    /// 且文件名只有一个字面量（写侧引用读侧常量）。
    #[test]
    fn 全局年龄策略两侧共用同一读取与并法() {
        let engine = strip_rust_comments(include_str!("../../engine/native/cleanup.rs"));
        assert!(
            engine.contains("trim_finder::cleanup_scan::load_global_min_age_days()"),
            "执行侧没有走共享的全局阈值读取函数 —— 自己解析就是第二份口径（AGENTS §5.16 N6）"
        );
        assert!(
            engine.contains(".tighten("),
            "执行侧没有把全局阈值并进年龄护栏（G-2 的核心：max(规则阈值, 全局阈值)）"
        );
        let scan = strip_rust_comments(include_str!("../../../../native-scanner/src/cleanup_scan.rs"));
        assert!(
            scan.contains(".tighten(global_min_age_days)"),
            "扫描侧没有把全局阈值并进年龄护栏 —— 那会出现「扫描按规则阈值、执行按全局阈值」的分叉"
        );
        // 文件名唯一真源：整个 Rust 源码里 `cleanup-min-age-days.txt` 只许出现在常量定义那一处
        let mut literals = 0usize;
        for src in [&scan, &engine] {
            literals += src.matches("cleanup-min-age-days.txt").count();
        }
        let policy = strip_rust_comments(include_str!("policy.rs"));
        literals += policy.matches("cleanup-min-age-days.txt").count();
        assert_eq!(
            literals, 1,
            "`cleanup-min-age-days.txt` 字面量出现 {literals} 次（应只在 native-scanner 的常量定义处）—— \
             两端各写一遍就是「设置页写 A 文件、扫描读 B 文件」的静默失效"
        );
        assert!(
            policy.contains("trim_finder::cleanup_scan::GLOBAL_MIN_AGE_FILE"),
            "写侧没有引用读侧的文件名常量"
        );
    }

    /// G-2：写入侧只放行 UI 档位，且「关闭」写空文件（不是写 0）。
    #[test]
    fn 全局年龄策略写入侧卡档且关闭写空文件() {
        let policy = strip_rust_comments(include_str!("policy.rs"));
        assert!(
            policy.contains("if !AGE_POLICY_TIERS.contains(&days)"),
            "写入侧缺少档位闸 —— 前端被绕过就能传任意天数（方案 §2.1 G-2 明令不许绕过）"
        );
        assert!(
            policy.contains("AGE_POLICY_TIERS: [u64; 3] = [0, 14, 30]"),
            "档位表必须是 UI 提供的三档（0 = 关闭 / 14 / 30）"
        );
        assert!(
            policy.contains(r#"if days == 0 { String::new() } else { format!("{days}\r\n") }"#),
            "「关闭」必须写**空文件**（写 0 会让人工核查时读出「0 天」这种不存在的档位）"
        );
        // 前端那条选择器的档位必须与后端一致（措辞/取值漂了会出现「选了 14 实际 30」）
        let js = include_str!("../../../../src/scripts/cleanup.js");
        assert!(
            js.contains("const AGE_POLICY_TIERS = [0, 14, 30];"),
            "前端档位表与后端不一致（两处必须同值）"
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
             渲染层会弹「关闭相关程序后重试」的误导提示（`cleanup.js` 的 `offerCleanupRetryPanel`）: {br}"
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

    /// R4（2026-10-15）：失败分档的**接线**钉桩（R3「清位+重试」经实测证伪后退役，
    /// 见 cleanup.rs 注释与方案附录 C——这里同时把「retry 不许悄悄回潮」钉住）。
    ///
    /// 与上一条同理由：分档正确性由纯函数用例钉住，而「循环里的 Err 分支把错误往哪个
    /// 计数器放」这层接线，行为测试够不到（protect 全局态污染 + 真实共享冲突难以稳定复现）。
    #[test]
    fn 删除失败分档的接线在位() {
        let code = strip_rust_comments(include_str!("../../engine/native/cleanup.rs"));
        // ① Err 分支必须经共享判据分档（并回 failed 独吞 = 权限问题又被说成「被占用」）
        assert!(
            code.contains("classify_delete_error(&e)"),
            "删除失败的 Err 分支没走共享分档判据（denied/gone 会被并回 failed）"
        );
        // ② 删除恰好一次：R3 应用层「清位+重试」经实测证伪已退役（std 自带清位）。
        //    回潮 = 死代码复活，且「一个文件删两次」的形态会回来——这里判红。
        assert_eq!(
            code.matches("std::fs::remove_file(path)").count(),
            1,
            "删除循环里应恰好一次 remove_file(path)（R3 清位重试已证伪退役，见注释）"
        );
        // ③ 两个新档必须以独立字段外发（渲染层按字段分档提示）
        for field in ["\"denied\": denied", "\"gone\": gone"] {
            assert!(code.contains(field), "details 缺独立字段 {field}");
        }
    }

    /// K12（v6）：逐文件失败明细的接线钉桩——「登记到重启后删除」的登记面只认
    /// `failedFiles`（{path, reason}），拿不到明细不得登记（前端 collectFailedPaths
    /// 的兜底就是「不计入」）。判据同 ④：分档正确性由纯函数钉，这里钉「明细真的
    /// 在收集、真的随 details 外发」这层接线。
    /// 判红自证：把 failed_files 的收集或外发删掉 ⇒ ①② 红。
    #[test]
    fn 逐文件失败明细接线在位() {
        let code = strip_rust_comments(include_str!("../../engine/native/cleanup.rs"));
        // ① Err 分支的两个可延期档必须进明细（occupied/denied）；gone 不进（无可删）
        assert!(
            code.contains("failed_files.push(json!({ \"path\": path, \"reason\": \"denied\" })"),
            "denied 档没进 failed_files 明细"
        );
        assert!(
            code.contains("failed_files.push(json!({ \"path\": path, \"reason\": \"occupied\" })"),
            "occupied 档没进 failed_files 明细"
        );
        // ② 明细与总数必须随 details 外发（渲染层消费的就是这两个字段）
        for field in ["\"failedFiles\": failed_files", "\"failedFilesTotal\": failed + denied"] {
            assert!(code.contains(field), "details 缺字段 {field}");
        }
        // ③ 安全闸门的三档（protected/reparse/identity）不许进明细——它们的出路不是
        //    永久删出口（前端也不该把它们送去登记）
        let seg = &code[code.find("failed_files.push").unwrap_or(0)..];
        let seg = &seg[..seg.find("details.push").unwrap_or(seg.len())];
        for gate in ["protected_blocked +=", "reparse_blocked +=", "identity_blocked +="] {
            assert!(
                !seg.contains(&format!("{gate} 1;\n                                failed_files.push")),
                "安全闸门档 {gate} 疑似进了 failed_files 明细"
            );
        }
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
        // ① 契约表查询不许直接 unwrap_or（**含 unwrap_or_default**——R4-M02：原针带
        // 尾括号 `unwrap_or(` 抓不到 `unwrap_or_default(`，差一个后缀让整条断言恒不命中）
        for line in code.lines() {
            let l = line.trim();
            if !l.contains("rule_schema::") {
                continue;
            }
            assert!(
                !l.contains("unwrap_or"),
                "契约表查询又出现了 unwrap_or（取不到就挑默认值，违反 fail-closed 声明）: {l}"
            );
        }
        // ② 必须走那两个 helper（缺席/无调用方 = 有人绕开它们自己查表）
        assert!(code.contains("fn req_list("), "缺少 req_list —— 契约表字符串数组查询的统一入口不见了");
        assert!(code.contains("fn req_number("), "缺少 req_number —— 契约表数值查询的统一入口不见了");
        for (helper, exact, what) in [
            ("req_list", 22usize, "字符串数组类查询（字段白名单 / 必填集 / 枚举）"),
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

        // A15 ifDeleted（P2-1，2026-10-16）：high 必填；写了就必须是非空字符串
        let mut it = ok_item();
        it["risk"] = json!("high");
        expect_reject(it, "ifDeleted");
        let mut it = ok_item();
        it["risk"] = json!("high");
        it["ifDeleted"] = json!("删除后测试目标不可恢复（自检）");
        validate_cleanup_package(&ok_pkg(it)).expect("high 带 ifDeleted 必须放行");
        let mut it = ok_item();
        it["ifDeleted"] = json!("   ");
        expect_reject(it, "ifDeleted");
        let mut it = ok_item();
        it["ifDeleted"] = json!(42);
        expect_reject(it, "ifDeleted");

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

        // 年龄轴（G-1）：缺省合法、单轴合法、脱离 minAge* 与非法枚举/双轴一律拒
        for axis in ["mtime", "ctime"] {
            let mut it = ok_item();
            it["minAgeDays"] = json!(7);
            it["ageAxis"] = json!(axis);
            validate_cleanup_package(&ok_pkg(it))
                .unwrap_or_else(|e| panic!("合法单轴 ageAxis={axis} 被拒: {e}"));
        }
        let mut it = ok_item();
        it["ageAxis"] = json!("mtime");
        expect_reject(it, "只能在声明 minAgeHours/minAgeDays 时出现");
        let mut it = ok_item();
        it["minAgeDays"] = json!(7);
        it["ageAxis"] = json!("birthtime");
        expect_reject(it, "只允许单轴");
        let mut it = ok_item();
        it["minAgeDays"] = json!(7);
        it["ageAxis"] = json!(["mtime", "ctime"]);
        expect_reject(it, "只允许单轴");

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
    fn 清理装载面接线_数据目录与内置同一校验器() {
        // 接线断言（口径同 tools/check-residue-rule-contract.mjs 的 E2）：数据目录与
        // 内置副本必须各过同一道语义校验，漏一侧就等于给那一侧开豁免通道。
        // v3 D3 起本域拆成 commands/cleanup/ 目录，断言读整个目录而不是单个文件。
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
    // 地板消费点：floor 仍取 max(builtin, rules_watermark())——rules_watermark 现含进程内记忆；
    // 写侧（set_rules_watermark）已随在线更新链退役，读侧保留。
    assert!(
        src.contains("let floor = builtin_version.max(rules_watermark());"),
        "防回滚地板的消费点漂移了"
    );
}

// ==================== §5.4 规则查找单点真源（2026-10-04） ====================

/// 命令侧 find_cleanup_rule_by_id 必须与引擎侧 find_rule_by_id 同源且同结果。
/// 旧双实现里命令侧的互斥 else（有 subGroups 就不看 g.items）会与引擎侧
/// （subGroups 优先、自有条目也扫）在「双形态组」上分叉：引擎按它动刀、
/// 命令侧报「未找到清理规则」。
#[test]
fn 规则查找单点真源_双形态组两侧同结果() {
    let rules = json!({
        "groups": [{
            "key": "g",
            "subGroups": [{"items": [
                {"id": "in_sub", "name": "子组条目"}
            ]}],
            "items": [
                {"id": "in_own", "name": "组内自有条目"}
            ]
        }]
    });
    // 双形态组：g.items 里的条目引擎侧历来找得到，命令侧必须同样找得到
    let own = find_cleanup_rule_by_id(&rules, "in_own");
    assert!(own.is_some(), "双形态组里 g.items 的条目命令侧不得报「未找到清理规则」");
    let via_engine = crate::engine::native::find_rule_by_id(&rules, "in_own");
    assert_eq!(own, via_engine, "两侧必须返回同一份条目");
    assert!(find_cleanup_rule_by_id(&rules, "in_sub").is_some(), "subGroups 条目照常命中");
    // 单点真源的另一半：不许存在第二份遍历（计数棘轮）
    let rules_src = include_str!("rules.rs");
    let engine_src = include_str!("../../engine/native/cleanup.rs");
    assert_eq!(
        rules_src.matches("fn find_cleanup_rule_by_id").count(),
        1,
        "命令侧委托入口必须恰好一个"
    );
    assert_eq!(
        engine_src.matches("fn find_rule_by_id").count(),
        1,
        "引擎侧遍历实现必须恰好一个"
    );
    assert!(
        rules_src.contains("crate::engine::native::find_rule_by_id(rules, id)"),
        "命令侧必须是薄委托，不是自写遍历"
    );
}

/// v6-K10：清理回执外层 success 判据——「什么都没删」不是成功。
/// 旧判据 `failed == 0` 在全 skip（太新/排除/未解析/受保护）或空跑时照样回
/// success:true，渲染层弹「清理完成！释放 0 B」。
/// 判红自证：把 `cleanup_receipt_success` 改回 `failed == 0` ⇒ ①② 红。
#[test]
fn 全跳过回执必须_success_false() {
    use crate::commands::cleanup::scan_execute::cleanup_receipt_success;
    // ① 全 skip（0 失败 0 成功 0 部分成功）⇒ 不得报成功
    assert!(
        !cleanup_receipt_success(0, 0, 0),
        "全 skip / 空跑不得报 success:true（K10）"
    );
    // ② 真「全被受保护拒绝」的形态：details 全是 skip/protected ⇒ 同上
    assert!(!cleanup_receipt_success(0, 0, 0), "受保护全拒不得报成功");
    // ③ 正常成功 / 部分成功 / 硬失败三态不回退
    assert!(cleanup_receipt_success(0, 3, 0), "正常成功必须仍是 true");
    assert!(cleanup_receipt_success(0, 1, 2), "部分成功必须仍是 true");
    assert!(!cleanup_receipt_success(2, 1, 0), "有硬失败必须 false（v5 C-3 既有口径）");
}

/// R2a-M03：清理域「删除失败文件路径」集合的取法（登记闸白名单的来源）。
///
/// 这份集合进 `engine::delete_failed` 台账，`uninstall_pending_add` 凭它核对
/// 「只收删除失败项」——白名单窄于渲染层要送的那批时，合法登记会被误拒。
/// 口径：引擎侧逐文件失败明细 `failedFiles[].path` + 「整项失败且路径在行上」的
/// `error` / `fail` 行。渲染层 `collectFailedPaths` 只取前者 + `error` 行，
/// 本函数取超集（多收 `fail` 行）：闸要拦的是「从没有失败过的文件」，
/// 不是「渲染层没提到的失败文件」。
///
/// 判红自证：把 `cleanup_failed_paths` 里的 `failedFiles` 分支删掉 ⇒ 首条断言红。
#[test]
fn 清理失败路径集合_取逐文件明细与整项失败行() {
    use crate::commands::cleanup::scan_execute::cleanup_failed_paths;
    let details = json!([
        { "id": "a", "status": "ok", "failedFiles": [] },
        { "id": "b", "status": "partial",
          "failedFiles": [ { "path": "C:\\占用.bin", "reason": "occupied" },
                          { "path": "C:\\占用.bin", "reason": "occupied" } ] },
        { "id": "c", "status": "error", "path": "C:\\整项失败.bin" },
        { "id": "d", "status": "fail", "path": "C:\\整项失败2.bin" },
        { "id": "e", "status": "skip" }
    ]);
    let paths = cleanup_failed_paths(details.as_array().expect("details 是数组"));
    assert!(
        paths.iter().any(|p| p == "C:\\占用.bin"),
        "逐文件失败明细必须进集合: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p == "C:\\整项失败.bin"),
        "error 行自带的路径必须进集合: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p == "C:\\整项失败2.bin"),
        "fail 行自带的路径必须进集合: {paths:?}"
    );
    assert_eq!(paths.len(), 3, "重复路径必须去重、成功行不得进集合: {paths:?}");
}

/// R2a-M03 接线钉：三个执行命令都必须把失败路径记进失败回执台账。
///
/// 纯函数测试只证明 `cleanup_failed_paths` 取法对，证明不了「回执真的被记进台账」
/// —— 把 record 调用删掉，上面那条照样全绿，而登记闸会拒掉全部合法登记
/// （症状：清理/残留明明失败了，登记面却说「不是删除失败回执里的文件」）。
#[test]
fn 清理失败回执_三个执行命令都落台账() {
    let scan_src = include_str!("scan_execute.rs");
    assert!(
        scan_src.contains("delete_failed::record"),
        "cleanup:execute 必须把删除失败路径记进失败回执台账（登记闸只认台账里的路径）"
    );
    let fc_src = include_str!("../fileclean.rs");
    assert!(
        fc_src.contains("delete_failed::record"),
        "fileclean:execute 必须把回收站失败的文件记进失败回执台账"
    );
    let residue_src = include_str!("../uninstall/residue.rs");
    assert!(
        residue_src.contains("delete_failed::record"),
        "uninstall:residue-execute 必须把删除失败的文件记进失败回执台账"
    );
}

// ==================== P1-W2 / U-R4（v7.2 分报告 R4，2026-10-20 批次） ====================
//
// 这一批断言的共同取舍：判据对象是**接线与实参形态**，行为测试够不到 —— 够不到的意思就是
// 「改一处实参 / 摘一处调用，用例照样全绿」（§4.1：只会打印 ✓ 的断言不算验收）。
// 每条都点名正向特征（命中的条目集合、位置实参清单、调用点计数、分档计数），
// 并在注释里写清破坏方式，由主 agent 做破坏自证。

/// 按声明头取函数体（到第一个顶格 `}` 为止）。
///
/// 为什么自己截：下面要判「早退与置空的先后」「函数体内有没有裸 insert」，
/// 拿整份文件比会把别的命令算进来。锚点用函数名不用行号（§5.19）。
fn command_fn_body(code: &str, head: &str) -> String {
    let i = code
        .find(head)
        .unwrap_or_else(|| panic!("找不到 {head} —— 接线断言的锚点漂移了"));
    let rest = &code[i..];
    rest[..rest.find("\n}\n").unwrap_or(rest.len())].to_string()
}

/// 从**以 `(` 开头**的文本取出顶层位置实参清单（嵌套括号里的逗号不当分隔符；空位与尾逗号跳过）。
fn top_level_args(src: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth = 0usize;
    for c in src.chars() {
        match c {
            '(' => {
                depth += 1;
                if depth > 1 {
                    cur.push(c);
                }
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let t = cur.trim();
                    if !t.is_empty() {
                        out.push(t.to_string());
                    }
                    return out;
                }
                cur.push(c);
            }
            ',' if depth == 1 => {
                let t = cur.trim();
                if !t.is_empty() {
                    out.push(t.to_string());
                }
                cur.clear();
            }
            _ => {
                if depth >= 1 {
                    cur.push(c);
                }
            }
        }
    }
    out
}

/// 取 `needle`（必须以 `(` 结尾）那一处调用/签名的位置实参清单。
///
/// 切片从括号本身开始（needle 全 ASCII ⇒ 字节下标落在字符边界上），
/// 否则 `top_level_args` 等不到开括号、一个实参都切不出来。
fn args_at(code: &str, needle: &str) -> Vec<String> {
    let at = code
        .find(needle)
        .unwrap_or_else(|| panic!("找不到 {needle} —— 调用点或签名漂移了"));
    top_level_args(&code[at + needle.len() - 1..])
}

/// 取源码里 `head` 之后第一串连续数字（用来把两侧写死的上限数字拉出来对拍）。
fn number_after(src: &str, head: &str) -> Option<usize> {
    let at = src.find(head)?;
    let rest = &src[at + head.len()..];
    let digits: String = rest
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// R4-M02：永久删钉桩必须**就是**传给删除原语的那个实参。
///
/// 缺陷形态（本条要抓的）：命令体里既有 `let to_recycle = false;` 又有
/// `debug_assert!(!to_recycle`，而调用点第三位写的是字面 `false` —— 那三条断言与实参
/// 没有任何一条对得上，把实参改成 `true` 后引擎走「只枚举不删除、freed 照计」分支：
/// 一个文件没删、也没进回收站，回执仍 success:true、释放量照报，`cargo test` 全绿。
///
/// 破坏自证：① 把 scan_execute.rs 调用点第三位改回 `false` ⇒ ② 的等值断言红；
/// ② 把 `let to_recycle = false;` 改名 ⇒ ①②都红；③ 把引擎形参顺序调过来 ⇒ ③ 红。
#[test]
fn 永久删钉桩必须是被传进删除原语的实参() {
    let code = strip_rust_comments(include_str!("scan_execute.rs"));
    let engine = strip_rust_comments(include_str!("../../engine/native/cleanup.rs"));
    // ① 钉桩本体在场（v3.3.0 裁定的代码位）
    assert!(code.contains("let to_recycle = false;"), "命令体里找不到永久删钉桩变量");
    assert!(code.contains("debug_assert!(!to_recycle"), "钉桩没有被 debug_assert 标成恒不可达");
    // ② 调用点的位置实参清单（不是「文件里有没有某句话」）
    let args = args_at(&code, "crate::engine::native::cleanup_execute(");
    assert_eq!(args.len(), 5, "调用点实参数与引擎签名不符: {args:?}");
    assert_eq!(
        args[2], "to_recycle",
        "第三位必须传钉桩变量本身，不能传字面量 —— 否则改这一处实参，整套契约测试照样全绿（R4-M02）: {args:?}"
    );
    assert_eq!(
        args[3], "auto_rebuild",
        "第四位必须点名 auto_rebuild —— to_recycle 与它是相邻两个 bool 位置实参，\
         形参顺序一旦被调即静默互换: {args:?}"
    );
    // ③ 与引擎形参名逐位对拍：命令侧传的名字必须正是引擎那一位的形参名
    let params: Vec<String> = args_at(&engine, "pub fn cleanup_execute(")
        .iter()
        .map(|p| p.split(':').next().unwrap_or("").trim().to_string())
        .collect();
    assert_eq!(params.len(), 5, "引擎形参清单漂移: {params:?}");
    assert_eq!(args[2], params[2], "命令侧第三位与引擎 to_recycle 形参不同名: {args:?} vs {params:?}");
    assert_eq!(args[3], params[3], "命令侧第四位与引擎 auto_rebuild 形参不同名: {args:?} vs {params:?}");
    // ④ 全仓生产调用点必须恰好这一处（第二条永久删出口 = 分桶复活）
    assert_eq!(
        code.matches("native::cleanup_execute(").count(),
        1,
        "cleanup_execute 里出现多条删除原语调用点 —— 「固定永久删」的出口必须唯一"
    );
}

/// R4-L05：被忽略的入参必须留在回执上（注释原本就承诺「如实回执并写日志」，代码只做了日志那一半）。
///
/// 破坏自证：把 `with_ignored_flags` 的两个调用点摘掉 ⇒ ② 计数红；
/// 把函数改成无条件加字段 ⇒ ① 的第二段红。
#[test]
fn 被忽略的_to_recycle_必须留在回执上() {
    use crate::commands::cleanup::scan_execute::with_ignored_flags;
    // ① 行为面（纯函数、零副作用）：忽略才加字段，没忽略不许凭空造字段
    let hit = with_ignored_flags(json!({ "success": true }), true);
    assert_eq!(hit["toRecycleIgnored"], json!(true), "被忽略的入参没上回执: {hit}");
    let miss = with_ignored_flags(json!({ "success": true, "message": "m" }), false);
    assert_eq!(miss, json!({ "success": true, "message": "m" }), "未发生忽略时不得添加字段: {miss}");
    // ② 接线面：cleanup_execute 的两个出口（Ok / Err）都必须过它，只写日志 = 本条缺陷态
    let code = strip_rust_comments(include_str!("scan_execute.rs"));
    assert!(
        code.contains("let to_recycle_ignored = to_recycle == Some(true);"),
        "「入参有没有被忽略」没被记成布尔，回执留痕无从判断"
    );
    assert_eq!(
        code.matches("with_ignored_flags(").count(),
        code.matches("fn with_ignored_flags(").count() + 2,
        "回执装饰的调用点必须是定义 1 处 + 出口 2 处: {}",
        code.matches("with_ignored_flags(").count()
    );
}

/// R4-M03：占用检测/查询必须**先置空**一次性白名单再判早退；写槽只有 state 里那两个入口。
///
/// 缺陷形态：`cleanup_query_locked` 五条早退（缺参 / 盘符相对 / 路径不存在 / 空目录或全
/// reparse / RM 调用失败）都不写槽 ⇒ 上一次成功检测的名单在这次失败后仍可被「结束进程」
/// 取走，杀的是没被查过的 PID 集，与该命令函数头第③条承诺相反。
///
/// 破坏自证：① 删掉 query-locked 的 `reset_lock_whitelist(&label);` ⇒ 行为面 ① 仍绿但
/// 接线面「reset 之前只许 1 条早退」立刻红；② 把名单写回改成裸 `.insert(...)` ⇒ 棘轮红；
/// ③ 在 guard 之后、reset 之前加一条早退 ⇒ 红（正是缺陷态）。
#[test]
fn 占用检测失败不得留下上一次的名单() {
    // ① 行为面（进程内、零副作用）：store 写得进、reset 清空得掉
    let probe = "__contract_lock_whitelist_probe__";
    store_lock_whitelist(probe, vec![json!({ "pid": 4242, "app": "probe" })]);
    let after_store = lock_whitelist()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(probe)
        .cloned()
        .unwrap_or_default();
    assert_eq!(after_store.len(), 1, "store 必须真的写进本槽（否则下面的 reset 没有对照对象）: {after_store:?}");
    reset_lock_whitelist(probe);
    let after_reset = lock_whitelist()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(probe)
        .cloned()
        .unwrap_or_default();
    assert!(after_reset.is_empty(), "reset 之后槽必须为空名单: {after_reset:?}");
    // 收尾：探针键不许留在进程内表里（同 label 的其他用例会被它顶账）
    lock_whitelist().lock().unwrap_or_else(|e| e.into_inner()).remove(probe);

    // ② 接线面：两条命令都必须「置空在任何业务早退之前」，成功路径才写名单
    let code = strip_rust_comments(include_str!("scan_execute.rs"));
    for head in ["pub async fn cleanup_check_locked", "pub async fn cleanup_query_locked"] {
        let body = command_fn_body(&code, head);
        let reset_at = body
            .find("reset_lock_whitelist(")
            .unwrap_or_else(|| panic!("{head} 没有先置空一次性白名单（R4-M03）"));
        let returns_before = body[..reset_at].matches("return json!(").count();
        assert_eq!(
            returns_before, 1,
            "{head} 在置空白名单之前有 {returns_before} 条早退（只允许 guard 那一条）—— \
             其余早退都会把上一次的名单留给「结束进程」"
        );
        assert!(body.contains("store_lock_whitelist("), "{head} 的名单写入没走统一入口");
        assert!(!body.contains("lock_whitelist()"), "{head} 又自己碰白名单槽（写侧必须只走 state 的两个函数）");
    }
    // ③ 棘轮：全命令面对槽的取用只允许「结束进程」那一次 remove
    assert_eq!(
        code.matches("lock_whitelist()").count(),
        1,
        "命令层直接碰 lock_whitelist() 的地方应为 1（kill 的一次性 remove），实到 {}",
        code.matches("lock_whitelist()").count()
    );
    let kill_body = command_fn_body(&code, "pub fn cleanup_kill_locked_processes");
    assert!(kill_body.contains(".remove(&label)"), "结束进程必须一次性取走名单（remove 而非 get）");
    assert_eq!(code.matches("reset_lock_whitelist(").count(), 2, "置空入口必须恰好 check / query 各一处");
    assert_eq!(code.matches("store_lock_whitelist(").count(), 2, "写名单入口必须恰好 check / query 各一处");
}

/// R4-L01 / R4-L02：验签通过后的三条早退必须与语义失败**同处置**（留痕 + 隔离），
/// 且防回滚地板读的是严格数字。
///
/// 破坏自证：① 把任一 `quarantine_file(&file, …)` 或 `log::write_log("error", …)` 删掉 ⇒ 计数红；
/// ② 把地板那两行的 `.and_then(Value::as_f64)` 换回 `.map(js_number)` ⇒ 严格数字断言红。
#[test]
fn 验签通过后的早退必须留痕并隔离() {
    let rules = strip_rust_comments(include_str!("rules.rs"));
    let body = command_fn_body(&rules, "pub(super) fn read_verified_data_rules");
    assert_eq!(
        body.matches("quarantine_file(&file").count(),
        4,
        "数据目录装载的隔离动作应为 4 处（解析失败 / groups 形状不合 / rulesVersion 非严格数字 / 语义不合规），实到 {}",
        body.matches("quarantine_file(&file").count()
    );
    assert_eq!(
        body.matches("\"error\"").count(),
        4,
        "每条整包拒绝都必须留一条 error 痕迹（静默回退内置 = 用户只会看到「规则永远是旧的」）"
    );
    // 防回滚地板读严格数字（与 validate_cleanup_package 同一口径）
    assert!(body.contains(".and_then(Value::as_f64)"), "地板读 rulesVersion 没走严格数字: {body}");
    assert!(
        !body.contains("map(js_number)"),
        "地板又用宽松 js_number —— 字符串/布尔会被吞成数字、数组/对象变 NaN，\
         而 `NaN < floor` 恒假 ⇒ 地板被整个跳过（fail-closed 只剩靠顺序）"
    );
    assert!(
        rules.contains(r#"top.get("rulesVersion").and_then(Value::as_f64)"#),
        "语义校验侧的严格数字口径漂了（两侧必须同一个判据，§5.16）"
    );
}

/// R4-L03：预览放行的长度闸必须按**字符数**，超限必须截断而不是整包拒绝。
///
/// 破坏自证：① 把 `p.chars().count()` 改回 `p.len()` ⇒ ① 段红（中文路径被误拒）；
/// ② 把「截断」改回 `if arr.len() > MAX_PATHS { return success:false }` ⇒ 上限对拍那条红。
#[test]
fn 预览放行的长度闸按字符数且超限截断() {
    use crate::commands::cleanup::preview_assets::filter_preview_paths;
    // ① 样本必须同时满足「字符数在闸内、字节数越闸」，否则这条断言没有对照对象
    let cjk = format!("C:\\Users\\测试\\{}", "图".repeat(90));
    assert!(
        cjk.chars().count() < 260 && cjk.len() > 260,
        "样本字符数 {} / 字节数 {} 没有跨越判据分叉点",
        cjk.chars().count(),
        cjk.len()
    );
    let (kept, reasons) = filter_preview_paths(&[json!(cjk.clone())]);
    assert_eq!(kept, vec![cjk], "中文路径必须放行（旧判据按字节 ⇒ 实际只允许约 86 字）: {kept:?} {reasons:?}");
    assert_eq!(reasons, [0, 0, 0], "合法条目不得计任何拒因: {reasons:?}");
    // ② 真超长（按字符数越闸）必须拒，且计入「超长」那一档
    let too_long = format!("C:\\{}", "x".repeat(300));
    assert!(too_long.chars().count() > 260 && too_long.len() == too_long.chars().count());
    let (kept, reasons) = filter_preview_paths(&[json!(too_long)]);
    assert!(kept.is_empty(), "超过 260 字符的路径不得放行: {kept:?}");
    assert_eq!(reasons, [0, 1, 0], "超长必须只计「超长」这一档: {reasons:?}");
    // ③ 非字符串 / 空串 / 含 NUL 分档计数，不许静默丢
    let (kept, reasons) = filter_preview_paths(&[json!(123), json!(""), json!("a\0b")]);
    assert!(kept.is_empty(), "三类非法形态都不得放行: {kept:?}");
    assert_eq!(reasons, [1, 0, 2], "拒因分档（空 / 超长 / 非串或含 NUL）: {reasons:?}");
    // ④ 接线：命令侧必须截断 + 如实回执，不再有整包拒绝的文案
    let src = strip_rust_comments(include_str!("preview_assets.rs"));
    assert!(src.contains("let truncated = arr.len() > MAX_PATHS;"), "超上限的清单必须走截断形态（截断位还要进回执）");
    assert!(!src.contains("路径清单超过上限"), "预览对超长清单仍是整包拒绝 —— 消费方拿 success:false 就不开灯箱，大组永远打不开");
    assert!(src.contains("p.chars().count() > MAX_PATH_CHARS") || src.contains("chars().count() > MAX_PATH_CHARS"), "长度闸没走 MAX_PATH_CHARS");
}

/// R4-L03 / 同域上限对拍：预览放行上限 ⇄ 条目明细上限必须是同一个数字。
///
/// 两侧没有共享常量可指（一在 preview_assets 的常量位、一在 cleanup_item_detail 的分支里），
/// 旧形态是 500 对 600 ⇒ 明细能列出 600 条、预览只放 500 张，501–600 张的组必然打不开。
/// 破坏自证：把 `MAX_PATHS` 或明细的 `let cap` 任一改动 ⇒ 等值断言红。
#[test]
fn 预览上限与明细上限同一数字() {
    let preview = strip_rust_comments(include_str!("preview_assets.rs"));
    let detail_file = strip_rust_comments(include_str!("scan_execute.rs"));
    let detail = command_fn_body(&detail_file, "pub async fn cleanup_item_detail");
    let cap_preview = number_after(&preview, "const MAX_PATHS: usize =").expect("preview_assets 里找不到 MAX_PATHS 常量");
    let cap_detail = number_after(&detail, "let cap =").expect("cleanup_item_detail 里找不到明细上限");
    assert!(cap_preview > 0 && cap_detail > 0, "两个上限都必须为正数: {cap_preview} / {cap_detail}");
    assert_eq!(
        cap_preview, cap_detail,
        "预览放行上限({cap_preview}) ⇄ 明细枚举上限({cap_detail}) 分叉：明细列得出、预览放不下（§5.16 同判定不许两本账）"
    );
}

/// R4-M04（本域可落的部分）：asset scope 只增不减 ⇒ 单次上限之外还必须有累计闸。
///
/// 来源快照绑定那一半属跨面改动（放行集要核 fileclean 域的槽），已登记进 P1 汇报。
/// 破坏自证：删掉 `SESSION_ALLOWED.fetch_add(...)` 或把常量调到 0 ⇒ 本条红。
#[test]
fn 预览放行有累计闸且注释与实现相符() {
    let src = strip_rust_comments(include_str!("preview_assets.rs"));
    assert!(
        src.contains("const MAX_SESSION_ALLOWS: usize ="),
        "会话累计放行上限不见了（asset scope 没有撤销动作，单次上限挡不住逐组点开的累计增长）"
    );
    assert_eq!(src.matches("static SESSION_ALLOWED").count(), 1, "累计账只许一份进程内表示");
    assert!(src.contains("SESSION_ALLOWED.fetch_add(allowed"), "累计账必须只加真的放出去的条数，不是加进来的条数");
    // 模块注释必须写死「scope 只增不减」——旧文案写成「本次没点开的前端拿不到授权」，
    // 那是做不到的承诺（同一会话更早点开过的组图恒可读）。
    let raw = include_str!("preview_assets.rs");
    assert!(raw.contains("只增不减"), "模块头没登记 asset scope 不可撤销这条约束");
    assert!(!raw.contains("本次没点开的前端拿不到授权"), "模块头又出现与实现不符的承诺");
}

/// R4-M05：custom 开关的遍历口径必须与引擎一致 —— 双形态组里 `g.items` 的条目要落得到开关。
///
/// 破坏自证：① 把 `collect_group_items` 改回「有 subGroups 就 return」的互斥形态 ⇒ ①②红；
/// ② 把 `set_enabled_by_id` 的回写删掉 ⇒ ② 红；③ 让它跨组继续找（改完第一处不返回）
/// ⇒ ③ 的第二条红。
#[test]
fn custom开关与引擎同遍历口径_双形态组不落空() {
    let rules = json!({
        "rulesVersion": 20260928,
        "groups": [{
            "key": "g",
            "title": "双形态组",
            "subGroups": [{ "key": "sg", "items": [{ "id": "in_sub", "enabled": true }] }],
            "items": [{ "id": "in_own", "enabled": true }]
        }]
    });
    // ① 超集口径 + 顺序点名（引擎侧 find_rule_by_id 也是 subGroups 在前）
    let ids: Vec<String> = collect_group_items(&rules["groups"][0])
        .iter()
        .map(|v| v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string())
        .collect();
    assert_eq!(ids, vec!["in_sub".to_string(), "in_own".to_string()], "组内条目集合与顺序: {ids:?}");
    // ② 开关真的落到 g.items 那一条上（旧形态把它当「未知 id」忽略）
    let mut merged = rules.clone();
    let custom = json!({ "groups": [{ "key": "c", "items": [{ "id": "in_own", "enabled": false }] }] });
    assert!(apply_custom_toggles(&mut merged, &custom, "probe.json"), "白名单内的开关不得整文件拒载");
    assert_eq!(
        find_cleanup_rule_by_id(&merged, "in_own").and_then(|v| v.get("enabled").cloned()),
        Some(json!(false)),
        "双形态组 g.items 条目的开关必须被写入 ——「引擎按哪条动刀」与「开关落点」得是同一个对象"
    );
    assert_eq!(
        find_cleanup_rule_by_id(&merged, "in_sub").and_then(|v| v.get("enabled").cloned()),
        Some(json!(true)),
        "没被点名的条目不得被顺手改"
    );
    // ③ 首个命中即返回（与引擎同序）：同名条目只改 subGroups 那一份
    let mut dup = json!({
        "groups": [{
            "key": "g",
            "subGroups": [{ "items": [{ "id": "same", "enabled": true, "where": "sub" }] }],
            "items": [{ "id": "same", "enabled": true, "where": "own" }]
        }]
    });
    let custom2 = json!({ "groups": [{ "items": [{ "id": "same", "enabled": false }] }] });
    assert!(apply_custom_toggles(&mut dup, &custom2, "dup.json"));
    let hit = find_cleanup_rule_by_id(&dup, "same").expect("同 id 必须仍能查到");
    assert_eq!(hit["where"], json!("sub"), "两侧必须命中同一个对象（引擎 find_rule_by_id 首个命中即返回）: {hit}");
    // ④ 真库对拍：命令侧的组内条目集合必须全部是引擎查得到的（内置副本 = 发布物自身）
    let lib: Value = serde_json::from_str(BUILTIN_RULES_JSON).expect("内置清理规则解析失败");
    let mut listed = 0usize;
    let mut missing: Vec<String> = Vec::new();
    for g in lib["groups"].as_array().expect("内置库 groups 必须是数组") {
        for it in collect_group_items(g) {
            let id = it.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            listed += 1;
            if crate::engine::native::find_rule_by_id(&lib, &id).is_none() {
                missing.push(id);
            }
        }
    }
    assert!(listed >= 150, "真库条目数现算 {listed} 条，低于地板 150（内置库只增不减）= 有一侧的遍历在漏条目");
    assert!(missing.is_empty(), "命令侧列出但引擎查不到的条目（口径分叉）: {missing:?}");
    // ⑤ 白名单闸不回退：custom 带禁止字段仍整文件拒载
    let mut bad = merged.clone();
    let custom_bad = json!({ "groups": [{ "items": [{ "id": "in_own", "enabled": false, "path": "C:\\x" }] }] });
    assert!(!apply_custom_toggles(&mut bad, &custom_bad, "bad.json"), "custom 携带禁止字段必须整文件拒载（审查 B-3）");
}

/// R4-L04：引擎整体失败的对外文案不得再提退役前的「分桶」。
///
/// 破坏自证：把 message 改回 `原生执行失败(永久删桶)` ⇒ 第一条红；把留痕日志删掉 ⇒ 第三条红。
#[test]
fn 引擎失败的对外文案不得再提退役的分桶() {
    let code = strip_rust_comments(include_str!("scan_execute.rs"));
    assert!(!code.contains("永久删桶"), "回执文案里又出现退役前的「桶」字（渲染层把它当 toast 文案，暗示还有另一个桶）");
    assert!(code.contains("原生执行失败: {e}"), "对外文案必须就是「原生执行失败」");
    assert!(code.contains("原生执行失败(永久删形态)"), "引擎整体失败的留痕日志不见了（删除形态只在日志里点名）");
}

/// R4-L06：`///` 不许孤儿挂靠 —— doc 注释会被 Rust 归给**下一个 item**。
///
/// 破坏自证：在任一 `#[cfg(test)] mod tests` 上方补一行 `/// 说明` ⇒ 本条红。
#[test]
fn doc注释不得挂在测试模块头上() {
    let files: [(&str, &str); 9] = [
        ("mod.rs", include_str!("mod.rs")),
        ("rules.rs", include_str!("rules.rs")),
        ("state.rs", include_str!("state.rs")),
        ("scan_execute.rs", include_str!("scan_execute.rs")),
        ("preview_assets.rs", include_str!("preview_assets.rs")),
        ("policy.rs", include_str!("policy.rs")),
        ("recycle_bin.rs", include_str!("recycle_bin.rs")),
        ("backup.rs", include_str!("backup.rs")),
        ("contract_tests.rs", include_str!("contract_tests.rs")),
    ];
    for (name, src) in files {
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if !t.starts_with("///") {
                continue;
            }
            // doc 块之后允许空行与属性行，落在第一行「真 item」上
            let mut j = i + 1;
            while j < lines.len() {
                let n = lines[j].trim();
                if n.is_empty() || n.starts_with("#[") || n.starts_with("//!") {
                    j += 1;
                    continue;
                }
                break;
            }
            let target = lines.get(j).map(|s| s.trim()).unwrap_or("");
            let targets_test_mod = (target.starts_with("mod ") && target.contains("tests"))
                || (j > i && lines[j - 1].trim() == "#[cfg(test)]" && target.starts_with("mod "));
            assert!(
                !targets_test_mod,
                "{name}:{} 的 doc 注释挂在测试模块头上（孤儿 ///，读起来像模块文档）: {target}",
                i + 1
            );
        }
    }
    // 三条历史孤儿必须已经消失（判据对象是注释原文，所以读未剥注释的文本）
    let raw_rules = include_str!("rules.rs");
    assert!(!raw_rules.contains("/// 执行/明细的 PS 超时"), "rules.rs 的 PS 超时孤儿 /// 回来了（该链已随 S3 退役）");
    let raw_state = include_str!("state.rs");
    assert!(!raw_state.contains("/// 数字按 JS String(n)"), "state.rs 的 js_num_str 孤儿 /// 回来了");
    // 本文件自己那两条：判据字符串**分两段拼接**，否则「门禁自己的文案也算语料」会让
    // 断言永远命中自己（AGENTS §4.1 假阳性②）。
    let gone_a = "/// 首个差".to_string() + "异定位信息（行号 + 两侧原文片段）";
    let gone_b = "/// PS 模板替换对拍".to_string() + "：同一合成输入，JS 生成 vs Rust 生成**逐字节**比较。";
    let raw_self = include_str!("contract_tests.rs");
    assert!(!raw_self.contains(gone_a.as_str()), "contract_tests 的「首个差异定位」孤儿 /// 回来了");
    assert!(!raw_self.contains(gone_b.as_str()), "contract_tests 的「PS 模板替换对拍」孤儿 /// 回来了");
}

/// R4-L06 同族：注释里不许裸写本域已不存在的已退役脚本名（分报告门禁候选③点名的形态）。
///
/// 破坏自证：在 scan_execute.rs 的注释里再裸写一次那个名字 ⇒ 本条红。
#[test]
fn 注释不得裸写本域已不存在的脚本名() {
    // 判据对象是**注释文本**，所以读原文而不是剥注释后的结果；
    // 名字本身同样分两段拼（本文件的说明文字也算语料）。
    let retired = "DETAIL_".to_string() + "SCRIPT";
    let src = include_str!("scan_execute.rs");
    assert!(!src.contains(retired.as_str()), "注释里又点名已随 S3 退役的 PS 明细脚本名");
}

/// R4-L08：零消费点的「目录别名」不许留在规则域（把存在当接入）。
#[test]
fn 规则域不得留零消费点的目录别名() {
    let rules = strip_rust_comments(include_str!("rules.rs"));
    let md = strip_rust_comments(include_str!("mod.rs"));
    assert!(!rules.contains("fn data_rules_dir"), "rules.rs 又出现第二份「规则库根目录」命名");
    assert!(!md.contains("data_rules_dir"), "mod.rs 台账还在 re-export 它（pub 且被 re-export ≠ 已接入）");
    // 保留的那份必须是真消费点：data_rules_file 被装载链用着
    assert!(rules.contains("fn data_rules_file"), "规则库文件读取入口不见了");
    let load = command_fn_body(&rules, "pub(super) fn read_verified_data_rules");
    assert!(load.contains("data_rules_file()"), "装载链没吃到 data_rules_file() 这个入口");
}

/// R4-L09：模块头声称的删除闸必须真在本域存在（不许再写一条零调用的闸名）。
#[test]
fn 模块头声称的删除闸必须真在清理域里() {
    let state = include_str!("state.rs");
    let head = &state[..state.find("use crate::engine::paths;").unwrap_or(state.len())];
    assert!(head.contains("validate_snapshot_items"), "模块头必须点名本域真实的第一道闸");
    // 只禁「把 in_scope 当本域闸来声称」的两种写法（新注释里点名它是为了说明它**不是**闸，
    // 那属于 §4.1 说的自指语料，不算违例）
    for claim in ["+ `in_scope`", "in_scope 决定能不能删"] {
        assert!(
            !head.contains(claim),
            "模块头又声称有一道 in_scope 闸 —— 它只是 commands/fileclean.rs 的私有判据，本域零调用（与审查 v5 C-1 同形）: {claim}"
        );
    }
    // 第二道闸必须点名到引擎侧的真名字（三面各一个），不写「等等机制」这种含混话
    for gate in ["is_path_protected", "final_path_protected", "is_reparse"] {
        assert!(head.contains(gate), "模块头缺第二道闸的点名 {gate}");
    }
    // 反向对照：这些名字在本域确实可达（写进注释的判据必须是真的）
    let engine = strip_rust_comments(include_str!("../../engine/native/cleanup.rs"));
    for gate in ["is_path_protected", "final_path_protected", "is_reparse"] {
        assert!(engine.contains(gate), "引擎侧找不到 {gate} —— 模块头点了个不存在的闸");
    }
}

/// R4-U03（2026-10-20 用户裁定）：`cleanup:rules` 收回主窗独占，读值走 Arc 入口。
///
/// 仓外侧同步核对（本断言管不到的两处）：`tools/check-guard-tiers.mjs` 的 MUST_MAIN 增、
/// MUST_READONLY 删；`tools/check-channel-map.mjs` 的 D5 只读档豁免删。
/// 破坏自证：把 guard 改回 `guard_readonly` ⇒ 前两条红，且 check-guard-tiers 的 B/D 组红。
#[test]
fn rules_出口主窗独占且走_arc_读值() {
    let rules = strip_rust_comments(include_str!("rules.rs"));
    let body = command_fn_body(&rules, "pub fn cleanup_rules");
    assert!(body.contains("guard::guard(&window, guard::MAIN)"), "cleanup:rules 不再是主窗独占: {body}");
    assert!(!body.contains("guard_readonly"), "cleanup:rules 又走只读档（= 三个子窗可调整库删除路径）");
    assert!(body.contains("rules_value_arc()"), "读值没走 Arc 入口: {body}");
    assert!(!body.contains("rules_value()"), "又用兼容入口（命中缓存也整树深克隆）");
}

/// R4-L07：gameRedist 回填的条数必须过与扫描侧同一条上限，超限如实置截断位。
///
/// 破坏自证：① 把 `cap_backfill_files` 的 `take(cap)` 去掉 ⇒ ①②红；
/// ② 把调用点第二实参改成字面量 500 ⇒ 接线断言红（数字必须来自 PLAN_CAP_PER_ITEM）。
#[test]
fn game_redist_回填也受同一条数上限约束() {
    use crate::commands::cleanup::scan_execute::cap_backfill_files;
    let files: Vec<(String, u64)> = (0..5).map(|i| (format!("C:\\x\\f{i}"), i as u64)).collect();
    let (arr, trunc) = cap_backfill_files(&files, 3);
    assert_eq!(arr.len(), 3, "超限必须截断到上限，实到 {}", arr.len());
    assert!(trunc, "被上限裁掉必须如实报 truncated");
    let (arr, trunc) = cap_backfill_files(&files, 5);
    assert_eq!(arr.len(), 5, "刚好等于上限不得少写条目");
    assert!(!trunc, "未越上限时 truncated 必须是 false");
    assert_eq!(arr[0], json!({ "path": "C:\\x\\f0", "size": 0 }), "回填条目形状（无 birthtimeNs = 引擎侧恒无身份证基线）: {}", arr[0]);
    // 接线：上限取扫描侧同一常量，且超限要在命令侧置 filesTruncated
    let code = strip_rust_comments(include_str!("scan_execute.rs"));
    assert!(code.contains("cap_backfill_files(files, PLAN_CAP_PER_ITEM)"), "回填的条数闸没走 PLAN_CAP_PER_ITEM（同判定两本账，§5.16）");
    assert_eq!(
        code.matches("cap_backfill_files(").count(),
        code.matches("fn cap_backfill_files(").count() + 1,
        "回填闸的调用点必须恰好一处"
    );
    assert!(code.contains("if files_truncated {"), "超限没在条目上置 filesTruncated（确认弹窗看不出清单被裁）");
    assert!(code.contains("无 birthtimeNs 身份证基线"), "「这 3 条无身份证基线」这条事实没在留痕里点名（R4-L07）");
}

// ==================== 真机探针（只写不跑；本批禁跑 cargo） ====================

/// R4-L01 / R4-L02 的真机探针。
///
/// 验的是什么：数据目录那份 `rules.json` **真实存在且真实验签通过**时，装载链的每一条
/// 早退都必须留下隔离件 —— 也就是「判坏了要看得见」，不再静默吃内置副本。
/// 为什么不伪造样本：验签要私钥（仓库外的本机密钥材料），伪造出来的坏包只会走到
/// 「验签失败」那条早退，正好绕开本批改判的三条分支。
///
/// 零新增副作用：本用例只读盘 + 调既有装载函数。若真实文件恰好是坏的，装载函数
/// **本来就会**把它隔离（这正是被测行为），探针不额外改任何东西。
///
/// 跑法：`cargo test --lib -- --ignored`（真机档；发版前必跑，见验收纪律）。
#[test]
#[ignore]
fn 真机_数据目录坏规则必须留下隔离件() {
    use crate::engine::rules_signature;
    let file = data_rules_file();
    let Some(text) = std::fs::read_to_string(&file).ok() else {
        // 数据目录规则不在场（首启动常态）：没有对照对象，如实跳过
        return;
    };
    // 验签失败那条早退刻意不隔离（回退内置、现场留给用户自己看），不在本批判面内
    if rules_signature::verify_rules_text(&text).is_err() {
        return;
    }
    // 只有「验签通过后被判定为坏」的三种形态才要求隔离件在场
    let parsed: Option<Value> = serde_json::from_str(&text).ok();
    let bad_shape = match parsed.as_ref() {
        None => true,
        Some(v) => {
            let groups_ok = v.get("groups").map(|g| g.is_array()).unwrap_or(false);
            let ver_ok = v.get("rulesVersion").and_then(Value::as_f64).is_some();
            !groups_ok || !ver_ok
        }
    };
    if !bad_shape {
        // 合法包：装载链必须真的吃到它（否则「静默回退内置」又把这条判据骗过去了）
        let got = read_verified_data_rules().expect("验签通过且形状合法的规则必须被装载（None = 静默回退内置）");
        let want = parsed.as_ref().expect("上面已解析过").get("rulesVersion").and_then(Value::as_f64);
        assert_eq!(
            got.get("rulesVersion").and_then(Value::as_f64),
            want,
            "装载结果不是数据目录那份（rulesVersion 不符）= 被静默换成了内置副本"
        );
        return;
    }
    let dir = file.parent().expect("规则文件必须有父目录");
    let name = file.file_name().expect("规则文件必须有文件名").to_string_lossy().to_string();
    let needle = format!("{name}.corrupt-");
    let has_quarantine = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().starts_with(&needle))
        })
        .unwrap_or(false);
    assert!(
        has_quarantine,
        "验签通过的坏规则被判坏却没有任何隔离件（{needle}…）—— 静默回退内置，R4-L01/L02 的缺陷态"
    );
}

/// R4-L07 的真机探针：真实 gameRedist 目录的回填清单必须受同一条上限约束，
/// 并且**不许**凭空造出 birthtimeNs（缺基线是事实，引擎按 identityUnbaselined 记账）。
///
/// 触真实磁盘（三家平台目录）⇒ 归真机档，禁进快速组。
/// 跑法：`cargo test --lib -- --ignored`。
#[test]
#[ignore]
fn 真机_game_redist_回填清单受同一上限且无伪造身份证() {
    use crate::commands::cleanup::scan_execute::cap_backfill_files;
    let r = crate::commands::gameclean::collect_redist_by_platform();
    let mut checked = 0usize;
    for (label, files) in [
        ("steam", &r.steam.files),
        ("epic", &r.epic.files),
        ("wegame", &r.wegame.files),
    ] {
        let (arr, trunc) = cap_backfill_files(files, PLAN_CAP_PER_ITEM);
        assert!(arr.len() <= PLAN_CAP_PER_ITEM, "{label} 回填条数越上限: {}", arr.len());
        assert_eq!(trunc, files.len() > PLAN_CAP_PER_ITEM, "{label} 截断位与实到条数不符（files={} / arr={})", files.len(), arr.len());
        for v in &arr {
            assert!(
                v.get("birthtimeNs").is_none(),
                "{label} 回填条目不得凭空造 birthtimeNs 基线: {v}"
            );
            assert!(
                v.get("path").and_then(|x| x.as_str()).map(|p| !p.is_empty()).unwrap_or(false),
                "{label} 回填条目必须带非空 path: {v}"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "真机上三家平台至少要回填一个文件，否则本探针没有对照对象（请换有装运行库的机器跑）");
}
