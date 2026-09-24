//! 失败诊断四元组（对照 src/main/diag.js，P1-11）
//!
//! 参考 MangoDisk 审计模型：failure_stage / mutation_state / diagnostic_digest / native_error_code。
//! PS 侧：脚本内 `Write-TFDiag` 输出 `@@DIAG@@{json}` 行；Rust 侧提取该行写入操作日志，
//! 返回清洗后的 stdout（与 JS 侧 extractDiagLines 同口径）。
//! `format_diag` 先剥离 C0 控制字符与 DEL（`\s` 只覆盖空白类，其余 C0 可伪造日志行），
//! 再压空白并截断 300 字符，防日志注入（火眼眼审查 2026-09-14 LOW）。

pub const DIAG_PREFIX: &str = "@@DIAG@@";

/// 从 stdout 提取 @@DIAG@@ 行写入日志，返回清洗后的 stdout。
/// `op` 为操作名（写入日志的 op= 字段）。
pub fn extract_diag_lines(stdout: &str, op: &str) -> String {
    if !stdout.contains(DIAG_PREFIX) {
        return stdout.to_string();
    }
    let mut kept: Vec<&str> = Vec::new();
    for line in stdout.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        match parse_diag_line(line) {
            Some(d) => {
                crate::engine::log::write_log("error", &format_diag(op, &d));
            }
            None => kept.push(line),
        }
    }
    kept.join("\n")
}

fn parse_diag_line(line: &str) -> Option<serde_json::Value> {
    let rest = line.strip_prefix(DIAG_PREFIX)?;
    let v: serde_json::Value = serde_json::from_str(rest).ok()?;
    match v.get("failure_stage").and_then(|s| s.as_str()) {
        Some(s) if !s.is_empty() => Some(v),
        _ => None,
    }
}
/// 统一日志格式：[DIAG] op=<操作> stage=.. mutation=.. digest=.. native=.. detail=..
pub fn format_diag(op: &str, d: &serde_json::Value) -> String {
    let get = |k: &str| -> String {
        d.get(k)
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default()
    };
    let detail: String = get("detail")
        .chars()
        .map(|c| {
            let code = c as u32;
            if code <= 0x1F || code == 0x7F {
                ' '
            } else {
                c
            }
        })
        .collect();
    let detail = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    let detail = detail.chars().take(300).collect::<String>();
    format!(
        "[DIAG] op={op} stage={} mutation={} digest={} native={} detail={detail}",
        get("failure_stage"),
        get("mutation_state"),
        get("diagnostic_digest"),
        get("native_error_code")
    )
}