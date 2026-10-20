//! 失败诊断四元组（对照 src/main/diag.js，P1-11）
//!
//! 参考 MangoDisk 审计模型：failure_stage / mutation_state / diagnostic_digest / native_error_code。
//! PS 侧：脚本内 `Write-TFDiag` 输出 `@@DIAG@@{json}` 行；Rust 侧提取该行写入操作日志，
//! 返回清洗后的 stdout（与 JS 侧 extractDiagLines 同口径）。
//!
//! R7-M01/M02（v7.2 C06）：净化必须覆盖**全部**字段，不只 detail——载荷来自 PS stdout，
//! 任何一个字段带换行都能伪造出整行日志；畸形 `@@DIAG@@` 行必须计数/告警，并且**不再
//! 原样留在「已清洗」stdout 里**交回上层。

pub const DIAG_PREFIX: &str = "@@DIAG@@";

/// 诊断行协议处理结果（拆成纯函数，单测不触日志、不碰盘）。
struct DiagSplit {
    /// 去掉诊断行后的 stdout
    clean: String,
    /// 解析成功的诊断体（调用方写日志）
    diagnostics: Vec<serde_json::Value>,
    /// 以 `@@DIAG@@` 开头但解析不出的行数
    malformed: usize,
}

fn split_diag_lines(stdout: &str) -> DiagSplit {
    if !stdout.contains(DIAG_PREFIX) {
        return DiagSplit { clean: stdout.to_string(), diagnostics: Vec::new(), malformed: 0 };
    }
    let mut kept: Vec<&str> = Vec::new();
    let mut diagnostics = Vec::new();
    let mut malformed = 0usize;
    for line in stdout.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if !line.starts_with(DIAG_PREFIX) {
            kept.push(line);
            continue;
        }
        match parse_diag_line(line) {
            Some(d) => diagnostics.push(d),
            // R7-M02：协议行坏了也不能交给上层当数据；计数后由调用方告警。
            None => malformed += 1,
        }
    }
    DiagSplit { clean: kept.join("\n"), diagnostics, malformed }
}

/// 从 stdout 提取 @@DIAG@@ 行写入日志，返回清洗后的 stdout（诊断行一律不留在输出里）。
/// `op` 为操作名（写入日志的 op= 字段）。
pub fn extract_diag_lines(stdout: &str, op: &str) -> String {
    strip_diag_lines(stdout, Some(op))
}

/// 无条件清洗 @@DIAG@@ 行（A6-M07）：是否写诊断日志取决于调用点是否登记 `op`，
/// 但**剔除协议行不取决于**它——脚本吐了 DIAG，未登记 op 的调用点也不能把原始行
/// 交给上层协议判据。畸形行即使 op 未登记也告警。
pub fn strip_diag_lines(stdout: &str, op: Option<&str>) -> String {
    let split = split_diag_lines(stdout);
    let had_crlf = stdout.contains("\r\n");
    if let Some(op) = op {
        for d in &split.diagnostics {
            crate::engine::log::write_log("error", &format_diag(op, d));
        }
    }
    if split.malformed > 0 {
        crate::engine::log::write_log(
            "warn",
            &format!(
                "诊断行协议异常：op={} 有 {} 行 @@DIAG@@ 无法解析（已从输出中移除）",
                op.unwrap_or("(未登记 diag)"),
                split.malformed
            ),
        );
    }
    // R7-L10：有 DIAG 行时 split 用 LF join；原文是 CRLF 的调用点必须保持同一行尾形态。
    if had_crlf && !split.clean.contains("\r\n") {
        split.clean.replace('\n', "\r\n")
    } else {
        split.clean
    }
}

fn parse_diag_line(line: &str) -> Option<serde_json::Value> {
    let rest = line.strip_prefix(DIAG_PREFIX)?;
    let v: serde_json::Value = serde_json::from_str(rest).ok()?;
    match v.get("failure_stage").and_then(|s| s.as_str()) {
        Some(s) if !s.is_empty() => Some(v),
        _ => None,
    }
}

/// 单个诊断字段的净化：剥 C0/DEL → 压空白 → 截 300 字符。
/// R7-M01：旧实现只净化 detail，其余四字段原样进 `format!`，一条带 `\n` 的载荷即可
/// 伪造出独立的日志行。现在五字段共用同一出口。
fn sanitize_field(raw: &str) -> String {
    let s: String = raw
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
    s.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect()
}

/// 统一日志格式：[DIAG] op=<操作> stage=.. mutation=.. digest=.. native=.. detail=..
pub fn format_diag(op: &str, d: &serde_json::Value) -> String {
    let get = |k: &str| -> String {
        let raw = d
            .get(k)
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        sanitize_field(&raw)
    };
    format!(
        "[DIAG] op={op} stage={} mutation={} digest={} native={} detail={}",
        get("failure_stage"),
        get("mutation_state"),
        get("diagnostic_digest"),
        get("native_error_code"),
        get("detail")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R7-M01：四个非 detail 字段同样必须被压成一行。
    #[test]
    fn 四字段换行载荷不得伪造日志行() {
        let d = serde_json::json!({
            "failure_stage": "startup\n[ERROR] 用户数据已永久删除，不可恢复",
            "mutation_state": "a\u{0000}b",
            "diagnostic_digest": "d\r\ne",
            "native_error_code": "5\n[WARN] 伪造",
            "detail": "ok"
        });
        let line = format_diag("probe", &d);
        assert!(!line.contains('\n'), "净化后不得含换行: {line:?}");
        assert!(!line.contains('\u{0000}'), "净化后不得含 NUL: {line:?}");
        assert!(line.contains("startup [ERROR] 用户数据已永久删除，不可恢复"), "原文应压成同一行: {line}");
    }

    /// R7-M02：畸形诊断行不得回到 stdout，且计数正确。
    #[test]
    fn 畸形诊断行从输出移除并计数() {
        let input = "@@DIAG@@不是JSON\r\n@@DIAG@@{\"failure_stage\":\"ok\"}\n普通输出\n";
        let split = split_diag_lines(input);
        assert_eq!(split.malformed, 1, "畸形行必须计数");
        assert_eq!(split.diagnostics.len(), 1, "合法行必须解析");
        assert!(!split.clean.contains(DIAG_PREFIX), "诊断行不得残留在回传 stdout: {:?}", split.clean);
        assert!(split.clean.contains("普通输出"), "普通输出必须保留: {:?}", split.clean);
    }

    /// 无诊断行时原样交回（包括 CRLF 形态），不制造第二字节形状。
    #[test]
    fn 无诊断行时原样返回() {
        let input = "a\r\nb\r\n";
        let split = split_diag_lines(input);
        assert_eq!(split.clean, input);
        assert_eq!(split.malformed, 0);
        assert!(split.diagnostics.is_empty());
    }

    /// A6-M07：op 未登记的调用点也必须把 DIAG 行剔掉（日志可以少写，协议行不能回流）。
    #[test]
    fn 未登记op时仍剔除诊断行() {
        let input = "@@DIAG@@{\"failure_stage\":\"ok\"}\n@@DONE@@\n";
        let out = strip_diag_lines(input, None);
        assert!(!out.contains(DIAG_PREFIX), "DIAG 不得留在回传 stdout: {out:?}");
        assert!(out.contains("@@DONE@@"), "上层协议行必须保留: {out:?}");
    }
}
