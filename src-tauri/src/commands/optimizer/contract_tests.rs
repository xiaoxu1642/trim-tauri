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

        // ③ 还原
        assert!(restore_backup_values(&backup), "值级还原必须整体成功");

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
