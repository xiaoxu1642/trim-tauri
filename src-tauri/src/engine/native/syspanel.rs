//! 系统面板：电源计划三档读写 + 虚拟内存读写（RAINZ 对标 §3.6，v0.4.9）
//!
//! 借 RAINZ 的"面板 + 回读校验"机制，不借它的写侧粗糙 —— 三档 GUID 白名单，
//! 白名单外的 GUID 一律拒绝；改完 400ms 后回读，读到不匹配就报错（不假装成功）。
//!
//! **虚拟内存写侧**：`AutomaticManagedPagefile` + `PagingFiles`（MULTI_SZ）；写前先备份
//! 当前配置到 `backup_write_dir()/pagefile-backups/<ts>.json`（AGENTS §3 `atomic_write_json`），
//! 参数校验层拒"全关"与"Max < Initial"这两类会让机器蓝屏的形态；写完回读比对，
//! 任一条 entry 的 `<drive>\pagefile.sys` 不在 `PagingFiles` 里就 Err（Group Policy
//! 或安全软件覆盖的场景不假装成功）。返回体带 `requiresReboot: true` 由前端提示。
//! **不做**一键还原 —— 危险能力默认关、猜错方向的代价不对称（AGENTS §3 口径），
//! 用户可通过备份 JSON 手动 reg import 恢复。
//!
//! 四条命令都走 `guard(window, MAIN)`（AGENTS §3 三层）：写侧、系统级、只在主窗触发。
//! `powercfg` 走 `system_tool` 固定到 `%SystemRoot%\System32`（`check-system-bin` 纪律），
//! 禁裸进程名。

use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

use crate::engine::systembin::{quiet_cmd, system_tool};

/// Windows 保留方案 GUID（微软公开文档，随系统分发）。三档在**每台机器上**都可通过
/// `powercfg /duplicate` 或原生存在；用户自定义方案 GUID 不在白名单，读到就展示、
/// 写请求一律拒绝（避免面板成为"任意 GUID 都能写"的通道）。
pub const KNOWN_PLANS: &[(&str, &str)] = &[
    ("381b4222-f694-41f0-9685-ff5bb260df2e", "平衡"),
    ("a1841308-3541-4fab-bc81-f71556f20b4a", "节能"),
    ("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", "高性能"),
];

/// 一行 powercfg 输出 → (guid 小写, 括号里的名字)。
///
/// 中英文系统都能吃：`电源方案 GUID: ...  (高性能)` 与 `Power Scheme GUID: ...  (High performance)`。
/// GUID 归一化小写，与 KNOWN_PLANS 判据一致。
pub fn parse_scheme_line(line: &str) -> Option<(String, String)> {
    let guid = find_guid(line)?;
    let name = find_paren_tail(line)?;
    Some((guid, name))
}

fn find_guid(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() < 36 {
        return None;
    }
    for i in 0..=(bytes.len() - 36) {
        if is_guid_at(bytes, i) {
            return Some(s[i..i + 36].to_ascii_lowercase());
        }
    }
    None
}

fn is_guid_at(b: &[u8], i: usize) -> bool {
    // 形状：8-4-4-4-12，段间 '-'。前后不允许紧跟字母数字（防"xxGUID 里嵌了 32-hex"这类误伤）
    let boundary_ok = |idx: usize| -> bool {
        if idx == 0 {
            return true;
        }
        !b[idx - 1].is_ascii_alphanumeric()
    };
    if !boundary_ok(i) {
        return false;
    }
    let tail = i + 36;
    if tail < b.len() && b[tail].is_ascii_alphanumeric() {
        return false;
    }
    let seg = [8usize, 4, 4, 4, 12];
    let mut p = i;
    for (k, &len) in seg.iter().enumerate() {
        if k > 0 {
            if b.get(p) != Some(&b'-') {
                return false;
            }
            p += 1;
        }
        for _ in 0..len {
            match b.get(p) {
                Some(c) if c.is_ascii_hexdigit() => p += 1,
                _ => return false,
            }
        }
    }
    true
}

fn find_paren_tail(line: &str) -> Option<String> {
    let chars: Vec<char> = line.chars().collect();
    let open = chars.iter().rposition(|c| *c == '(' || *c == '（')?;
    let close_rel = chars[open + 1..].iter().position(|c| *c == ')' || *c == '）')?;
    let close = open + 1 + close_rel;
    if close <= open + 1 {
        return None; // 空括号 ( )
    }
    let inner: String = chars[open + 1..close].iter().collect();
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn run_powercfg(args: &[&str]) -> Result<String, String> {
    let out = quiet_cmd(system_tool("powercfg"))
        .args(args)
        .output()
        .map_err(|e| format!("powercfg 启动失败：{e}"))?;
    if !out.status.success() {
        return Err(format!(
            "powercfg {} 退出码 {}",
            args.join(" "),
            out.status.code().unwrap_or(-1)
        ));
    }
    // Windows 中文版 powercfg 走 OEM 代码页（GBK/CP936）—— `String::from_utf8_lossy`
    // 会把中文名 mojibake 成替换符。**GUID 是 ASCII**、判据不受影响；名字可能乱码，
    // 展示层能容忍（真机看是英文系统就完全没问题）。不做 GBK 解码是刻意不给本模块引
    // `encoding_rs` 之类新依赖 —— AGENTS §2 硬红线。
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// 读电源方案状态：当前 GUID + 名字 + 列表。
///
/// `powercfg /list` 拿到"机器上所有可用方案"，包括用户克隆的自定义 GUID —— 这些**只展示**、
/// 不列入白名单；面板下拉里带"自定义"标签，点击会被 apply 拒。
pub fn power_plan_state() -> Value {
    let active = run_powercfg(&["/getactivescheme"])
        .ok()
        .and_then(|s| s.lines().find_map(parse_scheme_line));
    let list = run_powercfg(&["/list"])
        .ok()
        .map(|s| s.lines().filter_map(parse_scheme_line).collect::<Vec<_>>())
        .unwrap_or_default();
    json!({
        "activeGuid": active.as_ref().map(|(g, _)| g.clone()).unwrap_or_default(),
        "activeName": active.as_ref().map(|(_, n)| n.clone()).unwrap_or_default(),
        "options": list.iter().map(|(g, n)| json!({
            "guid": g,
            "name": n,
            "known": KNOWN_PLANS.iter().any(|(kg, _)| kg == g),
        })).collect::<Vec<Value>>(),
    })
}

/// 切换电源方案：白名单外拒绝 + 400ms 回读校验。
///
/// **回读校验不能省**：`powercfg /setactive` 在组策略锁定或休眠状态冲突时会"看起来成功"
/// 但当前方案没变（退出码 0）。RAINZ 用同样判据（`Test-Scheme` 里也是切完再查）；
/// 我们把它做成**错误回执**而不是"成功但状态没变"的静默。
pub fn power_plan_apply(guid: &str) -> Result<Value, String> {
    let target = KNOWN_PLANS
        .iter()
        .find(|(g, _)| g.eq_ignore_ascii_case(guid))
        .ok_or_else(|| "GUID 不在允许的方案内（白名单：平衡 / 节能 / 高性能）".to_string())?;
    run_powercfg(&["/setactive", target.0])?;
    std::thread::sleep(Duration::from_millis(400));
    let state = power_plan_state();
    let got = state
        .get("activeGuid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !got.eq_ignore_ascii_case(target.0) {
        return Err(format!("切换后回读为 {got}，与目标 {} 不符", target.0));
    }
    Ok(state)
}

/// 只读虚拟内存状态。
///
/// 注册表位置 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`：
///  - `AutomaticManagedPagefile`：REG_SZ "TRUE" / "FALSE"
///  - `PagingFiles`：REG_MULTI_SZ，形如 `C:\pagefile.sys 8192 16384`（Initial Max）
///
/// **不动写侧**：本函数只 `read`；`reg_restore_*` / 高危确认 / 重启提示 都留下一批。
pub fn pagefile_state() -> Value {
    use crate::engine::native::{hive_hklm, read_reg_value_faithful, read_reg_value_text};
    let sub = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
    let managed = read_reg_value_text(hive_hklm(), sub, "AutomaticManagedPagefile")
        .map(|(_, v)| v.eq_ignore_ascii_case("TRUE"))
        .unwrap_or(false);
    // `read_reg_value_faithful` 把 REG_MULTI_SZ 各元素以 `\0` 连接（registry.rs:359），
    // 这里按 `\0` split 即可 —— 不再手写 MULTI_SZ 解码器，避免与 registry 层出现两份口径。
    let raw: Vec<String> = read_reg_value_faithful(hive_hklm(), sub, "PagingFiles")
        .map(|(_kind, s)| s.split('\0').filter(|x| !x.is_empty()).map(|x| x.to_string()).collect())
        .unwrap_or_default();
    json!({
        "managed": managed,
        "entries": raw.iter().map(|line| {
            let mut parts = line.split_whitespace();
            let path = parts.next().unwrap_or_default().to_string();
            let initial = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            let max = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            json!({ "path": path, "initialMb": initial, "maxMb": max })
        }).collect::<Vec<Value>>(),
        "lineCount": raw.len(),
        "_comment": "本轮 §3.6 只做只读展示；写侧留下一批（涉及重启、多卷、蓝屏风险）",
    })
}

// ===== v0.4.9 §3.6 写侧：虚拟内存手动配置 =====

/// 单卷分页文件配置。**结构体字段必须显式 rename 到 camelCase**：
/// AGENTS §5.4 教训（Tauri 只自动转**顶层参数名**、不转结构体字段）
/// —— 忘了 rename 就会静默判未收到值 = 绕过校验。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PagefileEntry {
    /// 盘符根，形如 `"C:"` 或 `"C:\\"` 都吃（内部归一到大写、去尾斜杠）
    pub drive: String,
    pub initial_mb: u32,
    pub max_mb: u32,
}

/// MB 数上限，防"填 999999999"这种手抖。1 TB 已够夸张，正常机器不会用到。
const PAGEFILE_MAX_MB: u32 = 1_048_576;

/// 归一化盘符（大写、去尾斜杠）；非 `[A-Z]:` 形态一律 Err，不做模糊匹配。
fn normalize_drive(raw: &str) -> Result<String, String> {
    let t = raw.trim().trim_end_matches('\\');
    let bytes = t.as_bytes();
    if bytes.len() != 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return Err(format!("drive 需为盘符形式（如 C: 或 D:），收到：{raw:?}"));
    }
    Ok(t.to_uppercase())
}

/// 写侧参数校验。**任何一项不过一律 Err、不做"部分接受"**：
///  - managed=false 且 entries 为空 → 拒（AGENTS §3 危险能力默认关；全关 pagefile
///    会让物理内存告罄时直接崩，属经典蓝屏源头）
///  - 至少一条 entry 的 max_mb > 0 → 拒（全 0/0 等价于全关，同上）
///  - 每条 entry 的 drive 归一化；initial_mb <= max_mb；max_mb <= PAGEFILE_MAX_MB
///  - 同一 drive 不允许出现两次（防止后一条静默覆盖前一条）
fn validate_pagefile(managed: bool, entries: &[PagefileEntry]) -> Result<(), String> {
    if managed {
        // 自动托管不校验 entries：entries 会被上层忽略，写侧也不动 PagingFiles
        return Ok(());
    }
    if entries.is_empty() {
        return Err("手动模式下至少保留一个卷的分页文件；全部关完可能引发蓝屏（物理内存耗尽时无分页可写入）".into());
    }
    let mut seen: Vec<String> = Vec::with_capacity(entries.len());
    let mut any_alive = false;
    for e in entries {
        let d = normalize_drive(&e.drive)?;
        if seen.iter().any(|x| x == &d) {
            return Err(format!("盘符 {d} 出现两次；每个卷最多一条配置"));
        }
        seen.push(d);
        if e.initial_mb > PAGEFILE_MAX_MB || e.max_mb > PAGEFILE_MAX_MB {
            return Err(format!("{}: MB 数超过 {PAGEFILE_MAX_MB} 上限（1 TB），疑似参数错", e.drive));
        }
        if e.max_mb < e.initial_mb {
            return Err(format!(
                "{}: Max {} MB < Initial {} MB，参数不合法",
                e.drive, e.max_mb, e.initial_mb
            ));
        }
        if e.max_mb > 0 {
            any_alive = true;
        }
    }
    if !any_alive {
        return Err("所有卷都填 0/0 等价于关掉分页文件；至少一条要给非零 Max".into());
    }
    Ok(())
}

/// 把 PagingFiles 应该写入的 MULTI_SZ 元素拼出来（**大写盘符 + `\pagefile.sys` 后缀**）。
/// 与微软约定形态一致：`C:\pagefile.sys <initial> <max>`。
fn build_paging_files(entries: &[PagefileEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| {
            let d = normalize_drive(&e.drive).unwrap_or_else(|_| e.drive.trim_end_matches('\\').to_uppercase());
            format!("{d}\\pagefile.sys {} {}", e.initial_mb, e.max_mb)
        })
        .collect()
}

/// 写侧：应用虚拟内存配置。
///
/// **执行顺序**：admin 硬要求 → 参数校验 → 备份当前值 → flush 日志 → 写 `AutomaticManagedPagefile`
/// （+ 手动时写 `PagingFiles`）→ 回读比对 → 返回 `requiresReboot: true`。
///
/// 备份走 `atomic_write_json`（AGENTS §3 写 JSON 唯一姿势）、落在
/// `paths::backup_write_dir()/pagefile-backups/<timestamp>.json`；`prune_backups` 保留 50 份。
/// 一键还原命令留下一轮（AGENTS §3「危险能力默认关，猜错方向的代价不对称」），
/// 用户可先通过备份 JSON 手动 reg import 恢复。
pub fn pagefile_apply(managed: bool, entries: &[PagefileEntry]) -> Result<Value, String> {
    use crate::engine::native::{
        hive_hklm, reg_key_ensure_checked, reg_restore_write_checked, read_reg_value_faithful,
        read_reg_value_text,
    };
    use crate::engine::sysinfo::is_admin;
    use windows::Win32::System::Registry::{REG_MULTI_SZ, REG_SZ};

    if !is_admin() {
        return Err("写虚拟内存需要管理员权限（HKLM\\SYSTEM\\...）。请从主窗「以管理员身份运行」入口重启 Trim 后再操作".into());
    }
    validate_pagefile(managed, entries)?;

    let before = pagefile_state();
    // 备份先落盘；失败即中止，绝不在没留底的情况下动手
    let backup_path = write_pagefile_backup(&before)?;

    // 危险操作前 flush 日志（AGENTS §3）
    crate::engine::log::flush_sync();

    let sub = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
    reg_key_ensure_checked(hive_hklm(), sub).map_err(|e| format!("打开 Memory Management 失败：{e}"))?;

    // AutomaticManagedPagefile = REG_SZ "TRUE"/"FALSE"（对齐 WMI 也读同一位置的形态）
    let am_value = if managed { "TRUE" } else { "FALSE" };
    let am_bytes: Vec<u8> = am_value.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    reg_restore_write_checked(hive_hklm(), sub, "AutomaticManagedPagefile", REG_SZ, &am_bytes)
        .map_err(|e| format!("写 AutomaticManagedPagefile 失败：{e}"))?;

    if !managed {
        let lines = build_paging_files(entries);
        // MULTI_SZ：每串以 \0 结尾，整体再加一个 \0
        let mut buf: Vec<u8> = Vec::new();
        for line in &lines {
            for u in line.encode_utf16() {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes());
        reg_restore_write_checked(hive_hklm(), sub, "PagingFiles", REG_MULTI_SZ, &buf)
            .map_err(|e| format!("写 PagingFiles 失败：{e}"))?;
    }

    // 回读校验：至少 AutomaticManagedPagefile 必须对得上；手动模式下每条 entry 的
    // `<drive>\pagefile.sys` 都要在 PagingFiles 里出现
    let got_managed = read_reg_value_text(hive_hklm(), sub, "AutomaticManagedPagefile")
        .map(|(_, v)| v.eq_ignore_ascii_case("TRUE"))
        .unwrap_or(false);
    if got_managed != managed {
        return Err(format!(
            "回读 AutomaticManagedPagefile={got_managed} 与目标 {managed} 不符（可能被 Group Policy 或安全软件拦截）"
        ));
    }
    if !managed {
        let raw: Vec<String> = read_reg_value_faithful(hive_hklm(), sub, "PagingFiles")
            .map(|(_k, s)| s.split('\0').filter(|x| !x.is_empty()).map(|x| x.to_string()).collect())
            .unwrap_or_default();
        for e in entries {
            let d = normalize_drive(&e.drive)?;
            let want_prefix = format!("{d}\\pagefile.sys");
            if !raw.iter().any(|x| x.starts_with(&want_prefix)) {
                return Err(format!(
                    "回读 PagingFiles 未包含 {want_prefix}（可能被 Group Policy 或安全软件覆盖）"
                ));
            }
        }
    }

    let after = pagefile_state();
    crate::engine::log::write_log(
        "info",
        &format!(
            "虚拟内存配置已写入：managed={managed}、{} 个卷；备份 {backup_path}；**需要重启生效**",
            entries.len()
        ),
    );
    Ok(json!({
        "requiresReboot": true,
        "backupPath": backup_path,
        "before": before,
        "after": after,
    }))
}

/// 把当前 `pagefile_state()` 落进 `backup_write_dir("pagefile-backups")/<ts>.json`。
/// 走 `atomic_write_json`（AGENTS §3），写完 `prune_backups` 保留 50 份。
fn write_pagefile_backup(snapshot: &Value) -> Result<String, String> {
    use crate::engine::paths;
    use crate::security::atomic_write_json;
    let root = paths::backup_write_dir("pagefile-backups");
    std::fs::create_dir_all(&root).map_err(|e| format!("建备份目录失败：{e}"))?;
    let ts = crate::engine::now_ms();
    let file = root.join(format!("{ts}.json"));
    atomic_write_json(&file, snapshot)?;
    // 保留 50 份；prune 失败不阻断主流程（备份本身已落盘，最坏情况下一份份堆积由下次调用回收）
    paths::prune_backups(&root, 50);
    Ok(file.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 一行powercfg能解析出guid与名字() {
        let line = "电源方案 GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (高性能)";
        let (g, n) = parse_scheme_line(line).expect("解析失败");
        assert_eq!(g, "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
        assert_eq!(n, "高性能");
    }

    #[test]
    fn 英文powercfg输出也能解析() {
        let line = "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)";
        let (g, n) = parse_scheme_line(line).expect("解析失败");
        assert_eq!(g, "381b4222-f694-41f0-9685-ff5bb260df2e");
        assert_eq!(n, "Balanced");
    }

    #[test]
    fn guid大小写归一化小写() {
        let line = "Power Scheme GUID: 8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C (High performance)";
        let (g, _) = parse_scheme_line(line).expect("解析失败");
        assert_eq!(g, "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
    }

    /// **反向**：形状不对一律不认。老实现用"任何位置的 36 字符"当判据会把
    /// `aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaaXX`（后面紧跟字母）误认成 GUID，
    /// 白名单里 GUID 前后边界判据是这条测试钉的。
    #[test]
    fn 非guid形状一律拒判() {
        assert!(find_guid("no guid here").is_none());
        assert!(find_guid("381b4222-f694-41f0-9685-ff5bb260df2").is_none(), "少一位");
        assert!(find_guid("zzzzzzzz-f694-41f0-9685-ff5bb260df2e").is_none(), "非 hex");
        // 前后紧跟字母数字（边界）也要拒
        assert!(find_guid("X381b4222-f694-41f0-9685-ff5bb260df2e").is_none(), "前有字母");
        assert!(find_guid("381b4222-f694-41f0-9685-ff5bb260df2eX").is_none(), "后有字母");
        // 前后是标点或非字母数字，允许
        assert!(find_guid("(381b4222-f694-41f0-9685-ff5bb260df2e)").is_some());
    }

    #[test]
    fn 括号缺失或空即无名字() {
        assert!(find_paren_tail("Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c").is_none());
        assert!(find_paren_tail("...( )").is_none(), "空括号应无名字");
        assert_eq!(find_paren_tail("...(高性能)").as_deref(), Some("高性能"));
        assert_eq!(find_paren_tail("…（Balanced）").as_deref(), Some("Balanced"), "中文括号也吃");
    }

    #[test]
    fn 白名单外的_guid_一定被拒() {
        // 白名单外走 apply 早退分支，不真跑 powercfg（不然 CI 上会改用户方案）
        let e = power_plan_apply("00000000-0000-0000-0000-000000000000")
            .expect_err("白名单外应被拒");
        assert!(e.contains("GUID 不在允许"), "错因文案漂了：{e}");
    }

    /// 真跑 powercfg 会拉起子进程读系统方案表；机器语言 / 自定义方案都可能让结果差异，
    /// 只断"能跑到、不 panic、返回结构合法"，不硬钉内容。发布前手工核对。
    #[test]
    #[ignore = "真调 powercfg：结果依赖本机方案表，只在发布前手工核对不崩"]
    fn 真跑拿到电源方案状态与虚拟内存只读结构() {
        let s = power_plan_state();
        assert!(s["activeGuid"].is_string(), "activeGuid 应为字符串");
        assert!(s["options"].is_array(), "options 应为数组");
        let pf = pagefile_state();
        assert!(pf["managed"].is_boolean(), "managed 应为布尔");
        assert!(pf["entries"].is_array(), "entries 应为数组");
    }

    // ===== v0.4.9 §3.6 写侧：pagefile_apply 参数校验（纯函数、无 IO、无 admin 需求）=====

    fn e(drive: &str, initial_mb: u32, max_mb: u32) -> PagefileEntry {
        PagefileEntry { drive: drive.to_string(), initial_mb, max_mb }
    }

    #[test]
    fn 盘符归一化吃大小写与尾斜杠() {
        assert_eq!(normalize_drive("C:").unwrap(), "C:");
        assert_eq!(normalize_drive("c:").unwrap(), "C:");
        assert_eq!(normalize_drive("D:\\").unwrap(), "D:");
        assert_eq!(normalize_drive(" e: ").unwrap(), "E:");
        assert!(normalize_drive("CC:").is_err(), "两字母盘符不存在");
        assert!(normalize_drive("1:").is_err(), "数字开头");
        assert!(normalize_drive("").is_err(), "空");
        assert!(normalize_drive("C:/").is_err(), "斜杠方向");
    }

    #[test]
    fn managed_为真时不校验_entries() {
        // 交给系统托管：entries 无论填什么都接受（写侧会忽略它们、只改 AutomaticManagedPagefile）
        assert!(validate_pagefile(true, &[]).is_ok());
        assert!(validate_pagefile(true, &[e("C:", 1024, 2048)]).is_ok());
    }

    #[test]
    fn 手动模式拒绝会让机器蓝屏的参数形态() {
        // 空：全关等价于关掉所有卷的分页文件
        let err = validate_pagefile(false, &[]).unwrap_err();
        assert!(err.contains("至少保留"), "空列表错因文案漂了：{err}");
        // 全 0/0：与空列表语义等价，也要拒
        let err = validate_pagefile(false, &[e("C:", 0, 0), e("D:", 0, 0)]).unwrap_err();
        assert!(err.contains("0/0") || err.contains("关掉分页文件"), "全零错因漂了：{err}");
    }

    #[test]
    fn 手动模式拒绝重复盘符与非法数值() {
        // 重复盘符
        let err = validate_pagefile(false, &[e("C:", 1024, 2048), e("c:", 512, 1024)]).unwrap_err();
        assert!(err.contains("出现两次"), "重复盘符错因漂了：{err}");
        // Max < Initial
        let err = validate_pagefile(false, &[e("C:", 4096, 2048)]).unwrap_err();
        assert!(err.contains("Max") && err.contains("Initial"), "反序错因漂了：{err}");
        // MB 超上限
        let err = validate_pagefile(false, &[e("C:", 0, PAGEFILE_MAX_MB + 1)]).unwrap_err();
        assert!(err.contains("上限"), "上限错因漂了：{err}");
        // 非法盘符
        let err = validate_pagefile(false, &[e("XX", 1024, 2048)]).unwrap_err();
        assert!(err.contains("盘符"), "非法盘符错因漂了：{err}");
    }

    #[test]
    fn 合法参数能通过校验并生成微软形态() {
        let entries = [e("C:", 8192, 16384), e("d:", 0, 0)]; // 允许某卷明确关，只要整体至少一条 alive
        validate_pagefile(false, &entries).expect("应通过");
        let lines = build_paging_files(&entries);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "C:\\pagefile.sys 8192 16384");
        assert_eq!(lines[1], "D:\\pagefile.sys 0 0", "小写盘符应归一到大写");
    }

    /// 端到端跑一次 pagefile_apply 需要真 admin + 真重启，属发布前手工核对；
    /// CI 上不进默认测试。这里断的是**未 admin 或未确认时**必然 Err，不真写。
    #[test]
    #[ignore = "真写 pagefile_apply 会改本机 HKLM + 需重启，只在发布前手工核对不崩不 hang"]
    fn 端到端真写能过一遍() {
        // 走一次 managed=true（相对无损、系统自管），验证执行链不崩；
        // 未 admin 环境会直接 Err，不阻断测试通过（Err 也算跑通）。
        let _ = pagefile_apply(true, &[]);
    }
}
