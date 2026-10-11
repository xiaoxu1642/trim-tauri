//! BCD 枚举与条件命中判定（2026-10-11 C3）
//!
//! 三侧职责（只读）：
//!   1. 枚举：`bcdedit /enum {current}` + `{globalsettings}` 原始 stdout →
//!      `BcdMap { current: HashMap<name, value>, globals: HashMap<name, value> }`
//!   2. 判定：5 行面板各三态 → `BcdRowState { kind: "unhit"|"optimized"|"executable", ... }`
//!   3. 通道：`optimizer:bcd-enum`（guard::MAIN，只读）下发整面板状态
//!
//! **为什么后端做解析不交给前端**：
//!   - 三态判据（未命中 / 已优化 / 可执行）是稳定契约，改判据只动后端；
//!   - 元素名是 bcdedit 英文标识符（`hypervisorlaunchtype` 等），前端直接碰等于暴露系统内部词汇；
//!   - `bcdedit` 是系统工具，前端无权直接 spawn；
//!   - 保护态判定（Hyper-V/WSL 在用时整行跳过）要同时查 3 个元素值，放在一起判更稳。
//!
//! bcdedit /enum 输出格式（真实探测，本台机器）：
//! ```text
//! Windows Boot Loader
//! -------------------
//! identifier              {current}
//! configaccesspolicy      Default
//! hypervisorlaunchtype    Off
//! useplatformtick         Yes
//! ```
//! 元素名左对齐 22 字符，值跟在后面。继承行无元素名（缩进的 `{dbgsettings}` 这种），跳过。

use crate::engine::{guard, systembin};
use serde_json::{Value, json};
use std::collections::HashMap;
use tauri::{Runtime, WebviewWindow};

// bcdedit /enum 超时常量（systembin 真源：engine::systembin::BCDEDIT_ENUM_TIMEOUT = 15s）
pub use crate::engine::systembin::BCDEDIT_ENUM_TIMEOUT;

/// BCD 元素 map：元素名（小写规范化）→ 当前值
pub type BcdMap = HashMap<String, String>;

/// 一行面板的三态
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BcdRowKind {
    /// 所有登记元素都未在 BCD 里出现（常态）→ 复选框 disabled
    Unhit,
    /// 所有登记元素都已在目标值 → 已优化
    Optimized,
    /// 至少一个登记元素存在且值≠目标 → 可执行
    Executable,
}

impl BcdRowKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            BcdRowKind::Unhit => "unhit",
            BcdRowKind::Optimized => "optimized",
            BcdRowKind::Executable => "executable",
        }
    }
}

/// 面板单行状态
#[derive(Clone, Debug)]
pub struct BcdRowState {
    pub row_id: &'static str,
    pub kind: BcdRowKind,
    /// 保护态：检测到 Hyper-V/WSL/模拟器在用（当前值为 Auto/On/Enable/Yes）→ 整行跳过
    pub protection_hit: bool,
    /// 命中的元素详情（前端展示用）
    pub elements: Vec<BcdElementDetail>,
}

#[derive(Clone, Debug)]
pub struct BcdElementDetail {
    pub name: String,
    pub current: Option<String>,
    pub target: String,
    pub exists: bool,
    pub needs_change: bool,
}

// ==================== 1. bcdedit /enum 解析 ====================

/// 解析 bcdedit /enum 的原始 stdout → 元素 map
///
/// 解析规则（fail-closed）：
///   - 逐行扫，匹配 `^\s*([a-zA-Z][a-zA-Z0-9_:]*)\s{2,}(.+)$`（元素名 + 2+ 空格 + 值）
///   - 元素名转小写做键（bcdedit 不区分大小写，统一归一）
///   - 继承行（只有 GUID 值、无元素名）跳过
///   - 区块标题行（`Windows Boot Loader` / `Global Settings` / 破折号线）跳过
pub fn parse_bcd_enum(stdout: &str) -> BcdMap {
    let mut map = BcdMap::new();
    for line in stdout.lines() {
        let trimmed = line.trim_end();
        // 区块标题 / 破折号线 / 空行 → 跳过
        if trimmed.is_empty()
            || trimmed.chars().all(|c| c == '-' || c == ' ')
            || is_section_header(trimmed)
        {
            continue;
        }
        // 匹配：元素名 + 2+ 空格 + 值
        if let Some((name, value)) = split_name_value(trimmed) {
            map.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
    }
    map
}

fn is_section_header(line: &str) -> bool {
    matches!(
        line,
        "Windows Boot Manager"
            | "Windows Boot Loader"
            | "Windows Memory Tester"
            | "Resume from Hibernate"
            | "Windows Operating System"
            | "Global Settings"
            | "Custom Actions"
            | "Device options"
    )
}

/// 一行文本拆成 (元素名, 值) —— 按「2+ 空格分隔」匹配
///
/// 不用 split_whitespace：值里可能含空格（如 `partition=C:` 不含，但 `bootmenupolicy Standard` 值就是 Standard）。
/// 元素名本身不含空格（bcdedit 规范），所以「找到第一个 2+ 连续空格 → 左边是名、右边是值」。
fn split_name_value(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    // 元素名起点必须是字母（或自定义标识符前缀 custom:）
    let name_start = i;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b' ' || c == b'\t' {
            break;
        }
        // 合法元素名字符：字母数字下划线冒号（custom:16000067 这种）
        if !(c.is_ascii_alphanumeric() || c == b'_' || c == b':') {
            return None; // 不是合法元素名行（继承 GUID 值这类）
        }
        i += 1;
    }
    if i == name_start {
        return None; // 没有元素名
    }
    let name = &line[name_start..i];
    // 必须至少 2 个连续空格才是分隔（单空格可能是元素名的一部分？不会，元素名不含空格）
    let mut space_count = 0;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        space_count += 1;
        i += 1;
    }
    if space_count < 2 {
        return None; // 分隔不够 → 不是元素行
    }
    let value = &line[i..];
    if value.is_empty() {
        return None;
    }
    Some((name, value))
}

/// 跑 `bcdedit /enum {current}` + `/enum {globalsettings}`，返回两张 map
///
/// 任一枚举失败（退出码非 0）→ 对应 map 为空、整体不报错（前端拿到的是缺失态）。
/// 超时 → 函数直接返回 Err（fail-closed），调用方决定是报网络错误还是降级。
pub fn enum_bcd_maps() -> Result<(BcdMap, BcdMap), String> {
    let current = run_bcd_enum("{current}")?;
    let globals = run_bcd_enum("{globalsettings}")?;
    Ok((parse_bcd_enum(&current), parse_bcd_enum(&globals)))
}

fn run_bcd_enum(identifier: &str) -> Result<String, String> {
    let args = vec!["/enum".to_string(), identifier.to_string()];
    let out = systembin::quiet_cmd_timeout(
        systembin::system_tool("bcdedit.exe"),
        &args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        BCDEDIT_ENUM_TIMEOUT,
    )
    .map_err(|e| format!("bcdedit spawn 失败: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "bcdedit /enum {identifier} 退出码 {}",
            out.status.code().unwrap_or(-1)
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("bcdedit stdout 非 UTF-8: {e}"))
}

// ==================== 2. 条件命中判定 ====================

/// 目标值归一化（用于大小写不敏感比较）
fn norm_val(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// 一行面板的登记元素 → 目标值表
///
/// 所有字符串小写（与 parse_bcd_enum 的键归一一致）。
/// 用函数返回避免 STATICS 生命周期问题。
fn row_targets(row_id: &str) -> Vec<(&'static str, &'static str)> {
    match row_id {
        "nara_bcd_timer" => vec![
            ("disabledynamictick", "yes"),
            ("useplatformtick", "yes"),
            ("useplatformclock", "__DELETE__"), // __DELETE__ 哨兵：元素应被删除（不存在）
        ],
        "nara_bcd_vsm" => vec![
            ("hypervisorlaunchtype", "off"),
            ("vsmlaunchtype", "off"),
            ("isolatedcontext", "no"),
        ],
        "nara_bcd_boot" => vec![
            ("timeout", "0"),
            ("bootmenupolicy", "standard"),
            ("bootux", "disabled"),
            ("quietboot", "yes"),
        ],
        "nara_bcd_lowmem" => vec![
            ("firstmegabytepolicy", "useall"),
            ("avoidlowmemory", "0x8000000"),
            ("nolowmem", "yes"),
            ("allowedinmemorysettings", "0x0"),
        ],
        "nara_bcd_irq" => vec![
            ("configaccesspolicy", "default"),
            ("msi", "default"),
            ("usephysicaldestination", "no"),
            ("usefirmwarepcisettings", "no"),
        ],
        _ => Vec::new(),
    }
}

/// VSM 行保护态：检测到 Hyper-V/WSL/模拟器在用时跳过
///
/// 判据（任一满足即保护态）：
///   - hypervisorlaunchtype ∈ {Auto, On, Enable}
///   - vsmlaunchtype ∈ {Auto, On, Enable}
///   - isolatedcontext == Yes
fn vsm_protection_hit(current: &BcdMap) -> bool {
    let protected_values = ["auto", "on", "enable"];
    if let Some(v) = current.get("hypervisorlaunchtype") {
        if protected_values.contains(&norm_val(v).as_str()) {
            return true;
        }
    }
    if let Some(v) = current.get("vsmlaunchtype") {
        if protected_values.contains(&norm_val(v).as_str()) {
            return true;
        }
    }
    if let Some(v) = current.get("isolatedcontext") {
        if norm_val(v) == "yes" {
            return true;
        }
    }
    false
}

/// 对一行面板做三态判定
pub fn evaluate_row(row_id: &str, current: &BcdMap, _globals: &BcdMap) -> BcdRowState {
    let targets = row_targets(row_id);
    let static_id = ALL_ROW_IDS.iter().find(|&&id| id == row_id).copied().expect("evaluate_row: row_id must be in ALL_ROW_IDS");
    let mut elements = Vec::with_capacity(targets.len());
    let mut any_exists = false;
    let mut any_needs = false;

    for (name, target) in &targets {
        // BCD 面板登记元素全在 {current}，globals 暂不消费
        let map = current;
        let exists = map.contains_key(*name);
        any_exists = any_exists || exists;

        let current_val = map.get(*name).cloned();
        let needs_change = if *target == "__DELETE__" {
            // 目标是删除 → 当前存在就是需要改
            exists
        } else {
            // 目标是值匹配 → 当前存在且值不等于目标就是需要改
            exists && current_val.as_ref().map_or(false, |v| norm_val(v) != norm_val(target))
        };
        any_needs = any_needs || needs_change;

        elements.push(BcdElementDetail {
            name: name.to_string(),
            current: current_val,
            target: target.to_string(),
            exists,
            needs_change,
        });
    }

    // VSM 行保护态
    if row_id == "nara_bcd_vsm" && vsm_protection_hit(current) {
        return BcdRowState {
            row_id: static_id,
            kind: BcdRowKind::Unhit,
            protection_hit: true,
            elements,
        };
    }

    let kind = if !any_exists {
        BcdRowKind::Unhit
    } else if any_needs {
        BcdRowKind::Executable
    } else {
        BcdRowKind::Optimized
    };

    BcdRowState {
        row_id: static_id,
        kind,
        protection_hit: false,
        elements,
    }
}

/// 全部 5 行面板的 row_id 顺序
pub const ALL_ROW_IDS: &[&str] = &[
    "nara_bcd_timer",
    "nara_bcd_vsm",
    "nara_bcd_boot",
    "nara_bcd_lowmem",
    "nara_bcd_irq",
];

/// 检测到的**危险/无文档元素**名单（前端告警条）。
///
/// 白名单外还有大量系统常态元素（identifier/device/path/description/locale/osdevice/
/// systemroot/resumeobject/inherit/nx/flightsigning 等），全报等于噪音；口径与
/// check-optimizer-security 的 BCD 禁写名单一致，唯独不含 `nx`（OptIn 是系统默认态，
/// 禁写但不必告警）。
fn dangerous_elements(current: &BcdMap) -> Vec<String> {
    current
        .keys()
        .filter(|k| {
            let n = k.to_ascii_lowercase();
            n == "vm"
                || n == "increaseuserva"
                || n == "tpmbootentropy"
                || n.starts_with("linearaddress")
                || n.starts_with("custom:")
        })
        .cloned()
        .collect()
}

// ==================== 3. Tauri 命令 ====================

/// optimizer:bcd-enum —— BCD 面板全状态枚举
///
/// 返回形状：
/// ```json
/// {
///   "success": true,
///   "data": {
///     "rowStates": [
///       { "rowId": "nara_bcd_timer", "kind": "unhit", "protectionHit": false, "elements": [...] },
///       ...
///     ],
///     "unknownBcdValues": ["linearaddress57", "custom:16000067"]
///   }
/// }
/// ```
///
/// unknownBcdValues = 检测到但不在白名单元素集合里的元素名（前端可做告警条）
#[tauri::command]
pub async fn optimizer_bcd_enum<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }

    let (current, globals) = match enum_bcd_maps() {
        Ok(maps) => maps,
        Err(msg) => return json!({ "success": false, "message": msg }),
    };

    let rows: Vec<Value> = ALL_ROW_IDS
        .iter()
        .map(|&id| {
            let state = evaluate_row(id, &current, &globals);
            json!({
                "rowId": state.row_id,
                "kind": state.kind.as_str(),
                "protectionHit": state.protection_hit,
                "elements": state.elements.iter().map(|e| json!({
                    "name": e.name,
                    "current": e.current,
                    "target": e.target,
                    "exists": e.exists,
                    "needsChange": e.needs_change,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    let mut unknown = dangerous_elements(&current);
    unknown.sort();

    json!({
        "success": true,
        "data": {
            "rowStates": rows,
            "unknownBcdValues": unknown,
        }
    })
}

// ==================== 辅助导出 ====================
// __cmd__optimizer_bcd_enum 和 __tauri_command_name_optimizer_bcd_enum 由 #[tauri::command] 宏自动生成，
// 在 optimizer/mod.rs 里通过 `pub use bcd::{.., __cmd__.., __tauri_command_name_..}` 统一导出。

// ==================== 单测（parse_bcd_enum + evaluate_row）====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实探测样本（本台 Windows 11 输出，节选）
    const SAMPLE_CURRENT: &str = r#"
Windows Boot Loader
-------------------
identifier              {current}
device                  partition=C:
path                    \Windows\system32\winload.efi
configaccesspolicy      Default
linearaddress57         optout
vm                      No
bootmenupolicy          Standard
hypervisorlaunchtype    Off
vsmlaunchtype           Off
usephysicaldestination  No
usefirmwarepcisettings  No
useplatformtick         Yes
disabledynamictick      Yes
nx                      OptIn
custom:16000067         Yes
inherit                 {bootloadersettings}
                        {dbgsettings}
"#;

    #[test]
    fn parse_handles_real_output() {
        let map = parse_bcd_enum(SAMPLE_CURRENT);
        assert_eq!(map.get("configaccesspolicy").unwrap(), "Default");
        assert_eq!(map.get("linearaddress57").unwrap(), "optout");
        assert_eq!(map.get("hypervisorlaunchtype").unwrap(), "Off");
        assert_eq!(map.get("disabledynamictick").unwrap(), "Yes");
        assert_eq!(map.get("custom:16000067").unwrap(), "Yes");
        // 继承缩进值行跳过（不应被当成元素）
        assert!(map.get("{dbgsettings}").is_none());
        assert!(map.contains_key("inherit")); // inherit 本身是元素
    }

    #[test]
    fn parse_handles_globalsettings() {
        let globals = r#"
Global Settings
---------------
identifier              {globalsettings}
custom:16000067         Yes
"#;
        let map = parse_bcd_enum(globals);
        assert_eq!(map.get("custom:16000067").unwrap(), "Yes");
    }

    #[test]
    fn evaluate_timer_row() {
        let map = parse_bcd_enum(SAMPLE_CURRENT);
        let state = evaluate_row("nara_bcd_timer", &map, &BcdMap::new());
        // 本台 disabledynamictick=Yes ✓, useplatformtick=Yes ✓, useplatformclock 不存在 ✓
        assert_eq!(state.kind, BcdRowKind::Optimized);
        assert!(!state.protection_hit);
    }

    #[test]
    fn evaluate_vsm_row_off() {
        let map = parse_bcd_enum(SAMPLE_CURRENT);
        // hypervisorlaunchtype=Off ✓, vsmlaunchtype=Off ✓
        // isolatedcontext 不存在 = 系统默认 No ✓ → 全部已优化
        let state = evaluate_row("nara_bcd_vsm", &map, &BcdMap::new());
        assert_eq!(state.kind, BcdRowKind::Optimized);
        assert!(!state.protection_hit);
    }

    #[test]
    fn evaluate_vsm_protection_hit() {
        let mut map = BcdMap::new();
        map.insert("hypervisorlaunchtype".into(), "Auto".into());
        map.insert("isolatedcontext".into(), "Yes".into());
        let state = evaluate_row("nara_bcd_vsm", &map, &BcdMap::new());
        assert!(state.protection_hit);
        assert_eq!(state.kind, BcdRowKind::Unhit); // 保护态直接 unhit
    }

    #[test]
    fn evaluate_boot_row_unhit() {
        let map = BcdMap::new(); // 空 BCD（所有元素都未出现）
        let state = evaluate_row("nara_bcd_boot", &map, &BcdMap::new());
        assert_eq!(state.kind, BcdRowKind::Unhit);
    }

    #[test]
    fn evaluate_boot_row_executable() {
        let mut map = BcdMap::new();
        map.insert("timeout".into(), "30".into());
        let state = evaluate_row("nara_bcd_boot", &map, &BcdMap::new());
        assert_eq!(state.kind, BcdRowKind::Executable); // timeout=30 ≠ 0
        assert!(state.elements.iter().find(|e| e.name == "timeout").unwrap().needs_change);
    }

    #[test]
    fn evaluate_lowmem_row_unhit() {
        // 常态：本台没有 firstmegabytepolicy 等危险元素 → unhit
        let map = parse_bcd_enum(SAMPLE_CURRENT);
        let state = evaluate_row("nara_bcd_lowmem", &map, &BcdMap::new());
        assert_eq!(state.kind, BcdRowKind::Unhit);
    }

    #[test]
    fn evaluate_irq_row_optimized() {
        let map = parse_bcd_enum(SAMPLE_CURRENT);
        let state = evaluate_row("nara_bcd_irq", &map, &BcdMap::new());
        // configaccesspolicy=Default ✓
        // msi 不存在 = 默认 Default ✓
        // usephysicaldestination=No ✓
        // usefirmwarepcisettings=No ✓ → 全部已优化
        assert_eq!(state.kind, BcdRowKind::Optimized);
    }

    #[test]
    fn 危险元素只报无文档名单() {
        let map = parse_bcd_enum(SAMPLE_CURRENT);
        // 样本含 linearaddress57 / vm / custom:16000067（危险），
        // 以及 nx=OptIn / configaccesspolicy / inherit 等常态元素（不得报）
        let danger = dangerous_elements(&map);
        for must in ["custom:16000067", "linearaddress57", "vm"] {
            assert!(danger.contains(&must.to_string()), "应报 {must}: {danger:?}");
        }
        for quiet in ["nx", "configaccesspolicy", "inherit", "flightsigning"] {
            assert!(!danger.contains(&quiet.to_string()), "常态元素 {quiet} 不该告警");
        }
    }
}
