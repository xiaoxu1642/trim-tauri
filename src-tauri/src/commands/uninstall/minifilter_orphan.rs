//! 已挂载 minifilter 与服务键失配扫描（v0.5.0 只读，方案 §3 `minifilter_orphan`）。
//!
//! 三类里的第三类（`minifilter_after_key_deleted`）：服务键已经被删掉，驱动却还挂在
//! 过滤管理器上。这种状态**不是**「还能再删一次」，而是「卸载没走完，必须重启才散干净」，
//! 所以本组的产出语义是提示而不是候选目标 —— 拿它去删键会失败（键早没了），
//! 拿它去删文件会被占用挡住。方案 §3 给它的话术就是「需重启卸载」。
//!
//! `fltmc` 是权威来源（内核过滤管理器实时状态），注册表里没有等价物；
//! 非管理员或组件异常时 `fltmc` 会失败，那时整组不产候选并写 note，
//! 不能把「一个都没读到」说成「这台机器没有孤儿滤镜」。

use serde_json::{Value, json};
use super::residue_update::contribs;
use super::services_orphan::SERVICES_ROOT;
use crate::engine::systembin::{quiet_cmd_timeout, system_tool, FLTMC_TIMEOUT};

/// 挂载中的 minifilter（只取判定要用的字段）
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MountedFilter {
    pub(super) name: String,
    pub(super) altitude: String,
    pub(super) instances: u32,
}

/// 解析 `fltmc filters` 的表格输出。
///
/// 形如：
/// ```text
/// Filter Name                     Num Instances    Altitude    Frame
/// -----------------------------------------------------------------------------
/// WdFilter                              1             3280      0
/// bindflt                               1            40980      0
/// ```
/// 表头、分隔线、`No filters are registered...` 这类句子行都不能当成滤镜名 ——
/// 把「No」当名字会凭空造出一条「服务键不存在」的候选。
/// 判据：**第 2~4 段必须是数字**（实例数 / 高度 / 帧号），名字允许带空格时按此规则自然收敛。
pub(super) fn parse_fltmc_filters(text: &str) -> Vec<MountedFilter> {
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        // 名字可以含空格，所以从右往左取三个数字列，剩下的一律算名字
        let (frame, altitude, instances, name) = (cols[cols.len() - 1], cols[cols.len() - 2], cols[cols.len() - 3], &cols[..cols.len() - 3]);
        let ok = |s: &str| s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty();
        if !(ok(frame) && ok(altitude) && ok(instances)) {
            continue;
        }
        let name = name.join(" ").trim().to_string();
        if name.is_empty() || name.eq_ignore_ascii_case("Filter") {
            continue;
        }
        out.push(MountedFilter { name, altitude: altitude.to_string(), instances: instances.parse().unwrap_or(0) });
    }
    out
}

/// 纯判定：挂载中的滤镜名 → 服务键是否还在。
///
/// `service_key_exists` 注入（真实实现读注册表，单测注入表），返回 (候选, notes)。
pub(super) fn minifilter_findings(
    filters: &[MountedFilter],
    service_key_exists: &dyn Fn(&str) -> bool,
    cap: usize,
) -> (Vec<Value>, Vec<String>) {
    let mut candidates = Vec::new();
    let mut notes = Vec::new();
    for f in filters {
        if service_key_exists(&f.name) {
            continue;
        }
        if candidates.len() >= cap {
            notes.push(format!("minifilter 候选已达上限 {cap} 条，其余省略"));
            break;
        }
        candidates.push(json!({
            "kind": "note_only", "target": format!("HKLM\\{SERVICES_ROOT}\\{}", f.name),
            "class": "minifilter_after_key_deleted",
            "reason": format!("服务键已不存在，但过滤管理器仍挂着 {0}（高度 {1}，实例 {2} 个）—— 需要重启后才会散干净，本条不作为删除目标", f.name, f.altitude, f.instances),
            "confidence": "high", "risk": "low",
            "readonly": true, "defaultChecked": false,
            "details": json!({ "filterName": f.name, "altitude": f.altitude, "instances": f.instances }),
            "contribs": contribs(&[
                ("filterAttached", format!("fltmc 实时列出 {0}（高度 {1}）", f.name, f.altitude)),
                ("serviceKeyGone", format!("{SERVICES_ROOT}\\{} 打不开", f.name)),
            ]),
        }));
    }
    (candidates, notes)
}

/// 真实读取 `fltmc filters`。返回 (滤镜清单, 失败原因)：
/// `Err` 时调用方必须整组不产候选并把这个原因写进 notes。
pub(super) fn collect_mounted_filters() -> Result<Vec<MountedFilter>, String> {
    let out = quiet_cmd_timeout(system_tool("fltmc.exe"), &["filters"], FLTMC_TIMEOUT)
        .map_err(|e| format!("fltmc 启动失败：{e}"))?;
    if !out.status.success() {
        return Err("fltmc 退出码非 0（通常需要管理员权限，或过滤管理器不可达）".to_string());
    }
    let text = String::from_utf16_lossy(&decode_utf16_le(&out.stdout));
    let filters = parse_fltmc_filters(&text);
    if filters.is_empty() {
        // 成功退出但一行都没解析出来：要么真没挂任何滤镜（极不可能），要么输出格式不是
        // 预期的表格。两种都不该静默当成「干净」，交给调用方写 note。
        return Err("fltmc 输出里没有解析出任何滤镜行（格式与预期不符）".to_string());
    }
    Ok(filters)
}

/// 控制台输出按 UTF-16LE 解（fltmc 在英文/中文系统上都这么出，含表头破折号线）。
fn decode_utf16_le(bytes: &[u8]) -> Vec<u16> {
    let mut b = bytes;
    if b.len() >= 2 && b[0] == 0xFF && b[1] == 0xFE {
        b = &b[2..];
    }
    b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Filter Name                     Num Instances    Altitude    Frame\n\
-----------------------------------------------------------------------------\n\
WdFilter                              1             3280      0\n\
bindflt                               1            40980      0\n\
FileInfo                              1             4050      0\n\
AliProtectHipsFilter                  1            38520      0\n";

    #[test]
    fn parses_table_and_skips_header_and_rule() {
        let f = parse_fltmc_filters(SAMPLE);
        assert_eq!(f.len(), 4);
        assert_eq!(f[0].name, "WdFilter");
        assert_eq!(f[0].altitude, "3280");
        assert_eq!(f[3].name, "AliProtectHipsFilter");
    }

    #[test]
    fn prose_and_partial_lines_are_not_filters() {
        // 「No filters are registered...」整句有 4 个词，但后三列不是数字 ⇒ 必须被跳过
        let junk = "No filters are registered with the filter manager.\nFilter Name Num Instances Altitude Frame\n---\nrandom words here\n";
        assert!(parse_fltmc_filters(junk).is_empty());
    }

    #[test]
    fn filter_name_with_space_keeps_whole_name() {
        let got = parse_fltmc_filters("Some Legacy Filter                        1             3280      0\n");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "Some Legacy Filter");
    }

    #[test]
    fn only_filters_without_service_key_are_reported() {
        let filters = parse_fltmc_filters(SAMPLE);
        let (cand, notes) = minifilter_findings(&filters, &|n: &str| n != "AliProtectHipsFilter", 60);
        assert_eq!(cand.len(), 1);
        assert_eq!(cand[0]["class"], "minifilter_after_key_deleted");
        assert!(notes.is_empty());
    }

    #[test]
    /// 本组语义是提示不是删除目标：既给 readonly，也给 `kind: note_only`，
    /// 保证第二阶段就算接上执行链，这类也不会被当成可删键（键早就不在了）
    fn candidate_is_explicitly_not_a_delete_target() {
        let filters = [MountedFilter { name: "Gone".to_string(), altitude: "3280".to_string(), instances: 1 }];
        let (cand, _) = minifilter_findings(&filters, &|_: &str| false, 60);
        assert_eq!(cand[0]["kind"], "note_only");
        assert_eq!(cand[0]["readonly"], true);
        assert_eq!(cand[0]["defaultChecked"], false);
        let reason = cand[0]["reason"].as_str().unwrap_or("");
        assert!(reason.contains("需") && reason.contains("重启"));
        assert_eq!(cand[0]["target"], r"HKLM\SYSTEM\CurrentControlSet\Services\Gone");
    }

    #[test]
    fn cap_leaves_a_note() {
        let many: Vec<MountedFilter> = (0..5).map(|i| MountedFilter { name: format!("F{i}"), altitude: "1".into(), instances: 0 }).collect();
        let (cand, notes) = minifilter_findings(&many, &|_: &str| false, 2);
        assert_eq!(cand.len(), 2);
        assert!(notes.iter().any(|n| n.contains("已达上限")));
    }

    #[test]
    fn utf16le_bom_is_stripped_before_decoding() {
        let mut bytes = vec![0xFF, 0xFE];
        for u in "Ab1".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(String::from_utf16_lossy(&decode_utf16_le(&bytes)), "Ab1");
    }
}
