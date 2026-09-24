//! 规则库验签（C 批 cleanup 安全地基）
//!
//! 移植 `src/main/rules-signature.js`：规则内容直接决定 PowerShell 删除目标
//! （pathPs / fileKeys / regKeys），在线更新链路的任何 HTTP 源（含第三方代理）都只视为
//! 不可信传输通道，内容必须凭内置公钥自证。
//!
//! 冻结 API（cleanup.rs 依赖，勿改签名）：
//! ```text
//! pub fn verify_rules_text(text: &str) -> Result<(), String>;   // Err(reason) 与 JS 的 reason 文案一致
//! pub fn canonical_body_text(parsed: &serde_json::Value) -> Option<String>;
//! pub const RULES_PUBKEY_PEM: &str;
//! ```
//! 实现要点（已定）：
//! - 签名对象 = 规则 JSON 根对象去掉 `_sig` 后的**紧凑序列化文本**（UTF-8 字节）。
//!   键序必须等于原文件解析插入序 → 依赖 `serde_json` 的 `preserve_order` 特性（Cargo.toml 已开）。
//! - 公钥为内置 PEM（SubjectPublicKeyInfo，Ed25519）；Rust 侧 base64 解码后取末尾 32 字节，
//!   用 `ed25519_dalek::VerifyingKey::from_bytes` + `verify_strict` 验签（依赖已加）。
//! - 失败原因文案逐条对齐 JS（'JSON 解析失败' / '规则文件根不是 JSON 对象' / '缺少签名块 _sig，…' /
//!   '不支持的签名算法: X' / '签名数据解码失败' / '签名校验异常: …' / '签名校验失败，内容可能被篡改，已拒绝'）。

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};

/// 内置公钥 PEM（发布方 scripts/sign-rules.js gen 生成；更换密钥对必须同步发新版应用）
pub const RULES_PUBKEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAQehWbhuKKCxcWOje/8AZXYN192Z3Ryi8+cQ6ENwXAtY=\n\
-----END PUBLIC KEY-----";

/// 取规则对象的规范化签名文本（无 `_sig` 的紧凑 JSON 文本）
///
/// 对照 JS `canonicalBodyText`：`JSON.stringify({...parsed, _sig: undefined})`。
/// 这里逐键重建 Map（而非 shift_remove）——保证键序 = 原解析插入序，
/// 不依赖 `serde_json::Map::remove` 在 preserve_order 下是移位还是交换语义。
pub fn canonical_body_text(parsed: &Value) -> Option<String> {
    let obj = parsed.as_object()?;
    let mut body: Map<String, Value> = Map::new();
    for (k, v) in obj {
        if k == "_sig" {
            continue;
        }
        body.insert(k.clone(), v.clone());
    }
    serde_json::to_string(&Value::Object(body)).ok()
}

/// PEM → Ed25519 公钥字节（SubjectPublicKeyInfo 的末尾 32 字节）
fn verifying_key() -> Result<VerifyingKey, String> {
    let mut b64 = String::new();
    let mut inside = false;
    for line in RULES_PUBKEY_PEM.lines() {
        let t = line.trim();
        if t == "-----BEGIN PUBLIC KEY-----" {
            inside = true;
        } else if t == "-----END PUBLIC KEY-----" {
            inside = false;
        } else if inside {
            b64.push_str(t);
        }
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("内置公钥解码失败: {e}"))?;
    if der.len() < 32 {
        return Err("内置公钥长度不足".to_string());
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&der[der.len() - 32..]);
    VerifyingKey::from_bytes(&raw).map_err(|e| format!("内置公钥非法: {e}"))
}

/// JS 真值判定（`if (sig.alg && ...)`）——用于 `alg` 字段的跳过语义
fn js_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// JS 字符串化（`${sig.alg}` 落进错误文案时的取值）
fn js_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Array(a) => a.iter().map(js_to_string).collect::<Vec<_>>().join(","),
        // JSON 对象走默认 Object.prototype.toString（JS 模板字面量同结果）
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// 验签：text 为完整规则文件文本。通过返回 Ok(())，否则 Err(reason)
pub fn verify_rules_text(text: &str) -> Result<(), String> {
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Err("JSON 解析失败".to_string()),
    };
    if !parsed.is_object() {
        return Err("规则文件根不是 JSON 对象".to_string());
    }
    let sig_obj = parsed.get("_sig").and_then(|s| s.as_object());
    let sig_b64 = sig_obj
        .and_then(|o| o.get("sig"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let Some(sig_b64) = sig_b64 else {
        return Err("缺少签名块 _sig，已拒绝（发布方需先经 scripts/sign-rules.js 签名）".to_string());
    };
    if let Some(alg) = sig_obj.and_then(|o| o.get("alg")) {
        if js_truthy(alg) && alg.as_str() != Some("ed25519") {
            return Err(format!("不支持的签名算法: {}", js_to_string(alg)));
        }
    }
    let body = match canonical_body_text(&parsed) {
        Some(b) => b,
        None => return Err("签名数据解码失败".to_string()),
    };
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(sig_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Err("签名数据解码失败".to_string()),
    };
    let key = match verifying_key() {
        Ok(k) => k,
        Err(e) => return Err(format!("签名校验异常: {e}")),
    };
    // 长度不是 64 的签名在 Node/OpenSSL 下要么抛错要么恒 false；此处统一按「校验失败」处理
    // （文案取 JS 的失败分支，不冒充 Node 的异常文案）。
    let arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Err("签名校验失败，内容可能被篡改，已拒绝".to_string()),
    };
    let signature = Signature::from_bytes(&arr);
    match key.verify_strict(body.as_bytes(), &signature) {
        Ok(()) => Ok(()),
        Err(_) => Err("签名校验失败，内容可能被篡改，已拒绝".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    /// 内置公钥可解析
    #[test]
    fn pubkey_parses() {
        assert!(verifying_key().is_ok());
    }

    /// 篡改正文 → 必须拒绝（文案与 JS 一致）
    #[test]
    fn tampered_body_rejected() {
        let text = tamper_body();
        let err = verify_rules_text(&text).unwrap_err();
        assert_eq!(err, "签名校验失败，内容可能被篡改，已拒绝");
    }

    use ed25519_dalek::SigningKey;

    /// 用另一密钥对签名 → 必须拒绝（内置公钥固定）。种子写死，避免引入随机数依赖
    #[test]
    fn wrong_key_rejected() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut body: Map<String, Value> = Map::new();
        body.insert("rulesVersion".into(), Value::from(1));
        body.insert("groups".into(), Value::from(Vec::<Value>::new()));
        let canonical = serde_json::to_string(&Value::Object(body.clone())).unwrap();
        let sig = sk.sign(canonical.as_bytes());
        let mut root = body;
        let mut sig_block: Map<String, Value> = Map::new();
        sig_block.insert("alg".into(), Value::from("ed25519"));
        sig_block.insert(
            "sig".into(),
            Value::from(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())),
        );
        root.insert("_sig".into(), Value::Object(sig_block));
        let text = serde_json::to_string(&Value::Object(root)).unwrap();
        assert_eq!(
            verify_rules_text(&text).unwrap_err(),
            "签名校验失败，内容可能被篡改，已拒绝"
        );
    }

    /// 缺失 / 非对象 / 算法不支持 / JSON 坏 → 文案逐条对齐
    #[test]
    fn reason_messages_match_js() {
        assert_eq!(verify_rules_text("{").unwrap_err(), "JSON 解析失败");
        assert_eq!(
            verify_rules_text("[1,2]").unwrap_err(),
            "规则文件根不是 JSON 对象"
        );
        assert_eq!(
            verify_rules_text(r#"{"groups":[]}"#).unwrap_err(),
            "缺少签名块 _sig，已拒绝（发布方需先经 scripts/sign-rules.js 签名）"
        );
        assert_eq!(
            verify_rules_text(r#"{"_sig":{"alg":"rsa","sig":"AAAA"}}"#).unwrap_err(),
            "不支持的签名算法: rsa"
        );
        // alg 为空串是 JS falsy → 跳过算法判定，落到解码/校验分支
        assert_eq!(
            verify_rules_text(r#"{"_sig":{"alg":"","sig":"@@@@"}}"#).unwrap_err(),
            "签名数据解码失败"
        );
    }

    /// 规范化文本 = 去掉 _sig 的紧凑 JSON，且键序不变
    #[test]
    fn canonical_body_keeps_key_order() {
        let parsed: Value =
            serde_json::from_str(r#"{"a":1,"_sig":{"sig":"x"},"b":2,"z":[3]}"#).unwrap();
        assert_eq!(canonical_body_text(&parsed).unwrap(), r#"{"a":1,"b":2,"z":[3]}"#);
    }

    /// 真实规则文件双端对拍（D6 规则 1）：本测试给出 Rust 侧结论，
    /// 与 `node -e "require('C:/KaiFa/Trim/src/main/rules-signature').verifyRulesSignature(fs.readFileSync(...))"`
    /// 的 JS 结论必须一致。文件不存在时跳过（不误报失败）。
    #[test]
    fn real_rules_file_verdict() {
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(p) = std::env::var("TRIM_RULES_FILE") {
            candidates.push(std::path::PathBuf::from(p));
        }
        candidates.push(std::path::PathBuf::from(r"..\src\data\cleanup-rules.json"));
        candidates.push(std::path::PathBuf::from(r"C:\KaiFa\Trim\src\data\cleanup-rules.json"));
        let Some(path) = candidates.into_iter().find(|p| p.is_file()) else {
            eprintln!("[rules_signature] 未找到真实规则文件，跳过双端对拍");
            return;
        };
        let text = std::fs::read_to_string(&path).unwrap();
        let verdict = verify_rules_text(&text);
        eprintln!(
            "[rules_signature] Rust 侧验签 {} → {:?}",
            path.display(),
            verdict
        );
        assert!(verdict.is_ok(), "真实规则文件验签未通过: {verdict:?}");
    }

    fn tamper_body() -> String {
        // 一份自造的最小签名：用签名私钥不可得，故直接构造「签名与正文不匹配」的样本
        let mut root: Map<String, Value> = Map::new();
        root.insert("rulesVersion".into(), Value::from(1));
        root.insert("groups".into(), Value::from(Vec::<Value>::new()));
        let mut sig_block: Map<String, Value> = Map::new();
        sig_block.insert("alg".into(), Value::from("ed25519"));
        sig_block.insert("sig".into(), Value::from("A".repeat(86) + "=="));
        root.insert("_sig".into(), Value::Object(sig_block));
        serde_json::to_string(&Value::Object(root)).unwrap()
    }
}