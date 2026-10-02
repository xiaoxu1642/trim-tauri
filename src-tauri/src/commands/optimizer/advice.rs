//! optimizer:genadvice —— 优化项优缺点文案的 AI 生成链（含回落解析 parse_pros_cons）。
//!
//! 只读外呼：不写注册表、不改系统状态；模型密钥不明文回渲染层。
//! 文案是「建议」不是「判定」，不得参与 apply/restore 的决策路径。

use crate::engine::{guard, log};
use serde_json::{Value, json};
use tauri::{Runtime, WebviewWindow};
use super::catalog::*;
// ==================== AI 优缺点生成（optimizer:genadvice） ====================

pub(super) const ADVICE_SYSTEM: &str = "你是专业的 Windows 系统优化助手。请用简洁客观的中文，针对给定优化项分别说明优点与缺点，语言精炼、不说空话和营销话术，不要输出思考过程，只输出最终结果。";

/// optimizer:genadvice —— 按作用域首选模型生成优缺点，失败按已启用模型依次尝试
#[tauri::command]
pub async fn optimizer_genadvice<R: Runtime>(
    window: WebviewWindow<R>,
    option_id: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let option_id = option_id.unwrap_or_default();
    let Some(opt) = find_option(&option_id) else {
        return json!({ "success": false, "message": "未知的优化选项" });
    };
    let title = opt.get("title").and_then(|v| v.as_str()).unwrap_or(&option_id);
    let desc = opt.get("desc").and_then(|v| v.as_str()).unwrap_or("");

    let models = crate::commands::settings::models_config();
    let scopes = crate::commands::settings::scope_engines();
    let preferred = scopes
        .get("optimizer")
        .and_then(|v| v.as_str())
        .unwrap_or("metaso")
        .to_string();

    // [首选] + 其余已启用模型，保序去重
    let keys = crate::commands::settings::AI_MODEL_KEYS;
    let mut order: Vec<&str> = Vec::new();
    order.push(preferred.as_str());
    for k in keys {
        if *k != preferred.as_str() {
            order.push(k);
        }
    }
    order.retain(|k| {
        models
            .get(k)
            .and_then(|c| c.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    });
    if order.is_empty() {
        return json!({
            "success": false,
            "message": "当前没有已启用的模型，请在「设置 - 大模型管理」中启用并保存至少一个模型"
        });
    }

    let query = format!(
        "优化项名称：{title}\n优化项说明：{desc}\n\
请分别给出该优化项的「优点」和「缺点」，各用一到三句话，并严格按下面两行格式输出：\n\
优点：...\n缺点：..."
    );
    let message = format!("{ADVICE_SYSTEM}\n{query}");

    let mut text: Option<String> = None;
    let mut used_engine = "";
    for eng in order {
        if let Some(cfg) = models.get(eng) {
            if let Some(t) = crate::commands::aidesc::call_model_text(eng, cfg, &message) {
                if !t.trim().is_empty() {
                    text = Some(t);
                    used_engine = eng;
                    break;
                }
            }
        }
    }
    let Some(text) = text else {
        log::write_log("warn", &format!("优化项优缺点生成失败: {title}"));
        return json!({
            "success": false,
            "message": "所选模型未返回结果，请在「设置 - 大模型管理」中检查地址、密钥与模型名称（或确认网络）"
        });
    };

    let (pros, cons) = parse_pros_cons(&text);
    let cfg = models.get(used_engine);
    let source = crate::commands::settings::model_display_name(used_engine, cfg);
    log::write_log("info", &format!("优化项优缺点生成成功 ({source}): {title}"));
    json!({ "success": true, "data": { "pros": pros, "cons": cons, "raw": text, "source": source } })
}

/// 解析「优点：…/缺点：…」两行格式（对照 parseProsCons）
pub(super) fn parse_pros_cons(text: &str) -> (String, String) {
    let t = text.replace("\r\n", "\n");
    let t = t.trim();

    let content_after_label = |label: &str, search_from: usize| -> Option<usize> {
        let idx = t[search_from..].find(label)? + search_from;
        let mut it = t[idx + label.len()..].char_indices();
        let (_, c) = it.next()?;
        if c != ':' && c != '：' {
            return None;
        }
        Some(idx + label.len() + c.len_utf8())
    };

    let pros_start = content_after_label("优点", 0);
    // 缺点标签需在行首（允许前导空白），与 JS 前瞻 `\n\s*缺点` 同口径
    let cons_label = {
        let mut found = None;
        if let Some(ps) = pros_start {
            let tail = &t[ps..];
            if let Some(rel) = tail.find("\n") {
                let mut from = ps + rel;
                while from < t.len() {
                    let rest = &t[from..];
                    let trimmed = rest.trim_start_matches([' ', '\t', '\n']);
                    let skipped = rest.len() - trimmed.len();
                    if trimmed.starts_with("缺点") {
                        let label_abs = from + skipped;
                        if let Some(cs) = content_after_label("缺点", label_abs) {
                            found = Some((label_abs, cs));
                            break;
                        }
                    }
                    // 继续找下一个换行
                    match t[from + 1..].find('\n') {
                        Some(rel) => from = from + 1 + rel,
                        None => break,
                    }
                }
            }
        }
        found
    };

    let clean = |s: &str| -> String {
        s.trim()
            .trim_matches([' ', '\t', '\n', '-', '—', '*', '·'])
            .trim()
            .to_string()
    };

    match (pros_start, cons_label) {
        (Some(ps), Some((cl, cs))) => {
            let pros = clean(&t[ps..cl]);
            let cons = clean(&t[cs..]);
            if pros.is_empty() && cons.is_empty() {
                (t.to_string(), String::new())
            } else {
                (pros, cons)
            }
        }
        _ => (t.to_string(), String::new()),
    }
}

