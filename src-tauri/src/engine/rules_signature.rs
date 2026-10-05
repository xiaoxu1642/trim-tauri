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

/// 内置公钥 PEM · 旧钥（2026-10 上旬前签发的数据包全由它签名）。
///
/// 2026-10-04 系统重装致该钥私钥丢失且无备份，0.6.6 起轮换出新钥（见 [`RULES_PUBKEY_V2_PEM`]）。
/// 保留旧钥是**刻意的兼容设计**：清理 / 残留规则库内容未变、继续带旧签名分发，
/// 老版本（≤0.6.5）用户照常可在线更新 —— 验签改为**任一内置公钥通过即放行**。
/// 退役计划：线上与内置全部换成新签名后摘掉本常量（写入发版清单，勿单方面提前删）。
pub const RULES_PUBKEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAQehWbhuKKCxcWOje/8AZXYN192Z3Ryi8+cQ6ENwXAtY=\n\
-----END PUBLIC KEY-----";

/// 内置公钥 PEM · 轮换新钥（2026-10-06 生成；此后新签发的数据包用它签名）。
///
/// 私钥在发布机的本机密钥目录（`tools/sign-cleanup-rules.mjs` 读取），绝不入库。
pub const RULES_PUBKEY_V2_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAcfi1pq5dJY2x3/d+sDdLmj1N6eGIqOmttQh5rTbKCro=\n\
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

/// 单份 PEM → Ed25519 公钥字节（SubjectPublicKeyInfo 的末尾 32 字节）。
/// `tag` 只进错误文案——两把公钥哪把坏掉要能从日志里一眼分辨。
fn parse_pubkey(pem: &str, tag: &str) -> Result<VerifyingKey, String> {
    let mut b64 = String::new();
    let mut inside = false;
    for line in pem.lines() {
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
        .map_err(|e| format!("内置公钥({tag})解码失败: {e}"))?;
    if der.len() < 32 {
        return Err(format!("内置公钥({tag})长度不足"));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&der[der.len() - 32..]);
    VerifyingKey::from_bytes(&raw).map_err(|e| format!("内置公钥({tag})非法: {e}"))
}

/// 全部内置公钥（0.6.6 起两把：旧钥 + 轮换新钥；验签**任一通过即放行**）。
fn verifying_keys() -> Result<[VerifyingKey; 2], String> {
    Ok([
        parse_pubkey(RULES_PUBKEY_PEM, "legacy")?,
        parse_pubkey(RULES_PUBKEY_V2_PEM, "v2")?,
    ])
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
    let keys = match verifying_keys() {
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
    // 任一内置公钥通过即放行（双钥轮换期，见 RULES_PUBKEY_PEM 注释）；全失败统一按原文案拒绝
    if keys
        .iter()
        .any(|k| k.verify_strict(body.as_bytes(), &signature).is_ok())
    {
        Ok(())
    } else {
        Err("签名校验失败，内容可能被篡改，已拒绝".to_string())
    }
}

/// 取**数组顶层**规则文件的规范化签名文本（M4 · `optimizer-runtime.json`）。
///
/// 与 [`canonical_body_text`] 的区别：后者要求根是对象（剥掉对象里的 `_sig`），
/// 而 `optimizer-runtime.json` 的根是**裸数组** —— 签名不在文件里，而在
/// **sidecar** `<file>.sig.json` 里（见 `tools/sign-cleanup-rules.mjs` 的 `attachSig`：
/// `arr._sig = …` 静默无效，`JSON.stringify` 不序列化数组的非索引属性，
/// 那是「打印了已签名但文件没变」的假绿）。
pub fn canonical_array_text(parsed: &Value) -> Option<String> {
    if !parsed.is_array() {
        return None;
    }
    serde_json::to_string(parsed).ok()
}

/// 校验数组顶层规则文件 + 它的 sidecar 签名（M4）。
///
/// `sidecar_text` 是 `<file>.sig.json` 的全文。**两个文件必须成对存在** ——
/// 只有正文没有 sidecar 时返回 `Err`（fail-closed），绝不「没签名就算过」。
pub fn verify_array_text(text: &str, sidecar_text: &str) -> Result<(), String> {
    let parsed: Value =
        serde_json::from_str(text).map_err(|_| "JSON 解析失败".to_string())?;
    if !parsed.is_array() {
        return Err("规则文件根不是 JSON 数组".to_string());
    }
    let side: Value = serde_json::from_str(sidecar_text)
        .map_err(|_| "签名 sidecar 不是合法 JSON".to_string())?;
    if let Some(alg) = side.get("alg") {
        if js_truthy(alg) && alg.as_str() != Some("ed25519") {
            return Err(format!("不支持的签名算法: {}", js_to_string(alg)));
        }
    }
    let sig_b64 = side
        .get("sig")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "签名 sidecar 缺少 sig 字段，已拒绝".to_string())?;
    let body =
        canonical_array_text(&parsed).ok_or_else(|| "签名数据规范化失败".to_string())?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.as_bytes())
        .map_err(|_| "签名数据解码失败".to_string())?;
    let keys = verifying_keys().map_err(|e| format!("签名校验异常: {e}"))?;
    let arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        "签名校验失败，内容可能被篡改，已拒绝".to_string()
    })?;
    let signature = Signature::from_bytes(&arr);
    if keys
        .iter()
        .any(|k| k.verify_strict(body.as_bytes(), &signature).is_ok())
    {
        Ok(())
    } else {
        Err("签名校验失败，内容可能被篡改，已拒绝".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    /// 内置公钥（两把）都可解析
    #[test]
    fn pubkey_parses() {
        let keys = verifying_keys().expect("两把内置公钥都应可解析");
        assert_eq!(keys.len(), 2, "0.6.6 起内置公钥应为「旧钥 + 轮换新钥」两把");
    }

    /// 篡改正文 → 必须拒绝（文案与 JS 一致）
    #[test]
    fn tampered_body_rejected() {
        let text = tamper_body();
        let err = verify_rules_text(&text).unwrap_err();
        assert_eq!(err, "签名校验失败，内容可能被篡改，已拒绝");
    }

    use ed25519_dalek::SigningKey;

    /// 用另一密钥对签名 → 必须拒绝（内置公钥集固定，0.6.6 起为两把）。种子写死，避免引入随机数依赖
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
    /// 与 JS 侧 `vendor/upstream-js/src/main/rules-signature.js` 的 `verifyRulesSignature(...)`
    /// 结论必须一致（JS 侧对拍命令：`node -e "const r=require('./vendor/upstream-js/src/main/rules-signature'),fs=require('fs');console.log(r.verifyRulesSignature(fs.readFileSync('src-tauri/data/cleanup-rules.json','utf8')))"`）。
    ///
    /// 审查 M13：路径改用 `CARGO_MANIFEST_DIR` 拼接（原先写 `..\src\data\...`，
    /// 规则库随 M14 移出 frontendDist 后相对基准一变就**静默跳过**、却仍计入 passed）；
    /// 该文件是仓库跟踪文件，找不到即真缺陷，故直接 panic 而不是 return。
    ///
    /// 注记（0.6.6 密钥轮换）：清理库存量内容仍是**旧钥签名**（content 未变、不重签），
    /// 故 JS 基线（只认旧钥）的对拍结论依旧成立；待清理库换新签名（旧钥退役）后，
    /// 这条对拍要改成「记录式」而不能继续断言两侧一致。
    #[test]
    fn real_rules_file_verdict() {
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(p) = std::env::var("TRIM_RULES_FILE") {
            candidates.push(std::path::PathBuf::from(p));
        }
        candidates.push(std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            r"\data\cleanup-rules.json"
        )));
        let path = candidates
            .into_iter()
            .find(|p| p.is_file())
            .unwrap_or_else(|| panic!("找不到内置规则库，双端对拍没跑（候选见上）"));
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
        // 一份自造的最小签名：测试不依赖本机私钥（要可复现），故直接构造「签名与正文不匹配」的样本
        let mut root: Map<String, Value> = Map::new();
        root.insert("rulesVersion".into(), Value::from(1));
        root.insert("groups".into(), Value::from(Vec::<Value>::new()));
        let mut sig_block: Map<String, Value> = Map::new();
        sig_block.insert("alg".into(), Value::from("ed25519"));
        sig_block.insert("sig".into(), Value::from("A".repeat(86) + "=="));
        root.insert("_sig".into(), Value::Object(sig_block));
        serde_json::to_string(&Value::Object(root)).unwrap()
    }

    /// M4：`optimizer-runtime.json` 的数组形态签名校验（四态）。
    ///
    /// 覆盖：正常通过 / 正文篡改失败 / 缺 sig 失败 / alg 不支持失败 / sidecar 非JSON 失败。
    /// 五条都断，因为它们对应五种**不同**的失效形态（只断「篡改」会漏掉
    /// 「sidecar 缺失/字段改名/算法换掉」那几种 —— 而那几种恰恰是升级路径上
    /// 最容易发生的：文件名改了、字段挪位了、有人想换算法）。
    #[test]
    fn m4_优化目录数组签名校验五态() {
        const MAIN: &str = include_str!("../../data/optimizer-runtime.json");
        const SIDECAR: &str = include_str!("../../data/optimizer-runtime.json.sig.json");

        // ① 正常：验签通过
        verify_array_text(MAIN, SIDECAR)
            .unwrap_or_else(|e| panic!("本机签名的优化目录必须验签通过（私钥在~/.trim-signing）：{e}"));

        // ② 正文被篡改 → 必须失败
        let tampered = MAIN.replace("\"risk\": \"low\"", "\"risk\": \"high\"");
        assert_ne!(tampered, MAIN, "前提失效：没能篡改出内容（数据层里没有 risk:low 形态）");
        assert!(
            verify_array_text(&tampered, SIDECAR).is_err(),
            "篡改正文后验签竟然通过 —— 签名形同虚设"
        );

        // ③ sidecar 缺 sig / alg 不支持 / 非 JSON ⇒ 三种都必须 fail-closed
        assert!(
            verify_array_text(MAIN, "{}").is_err(),
            "sidecar 为空对象时必须拒绝（没签名不许放行）"
        );
        let no_sig = SIDECAR.replace("\"sig\"", "\"notsig\"");
        assert!(
            verify_array_text(MAIN, &no_sig).is_err(),
            "sidecar 缺 sig 字段时必须拒绝"
        );
        let wrong_alg = SIDECAR.replace("ed25519", "rsa");
        assert!(
            verify_array_text(MAIN, &wrong_alg).is_err(),
            "sidecar 的 alg 改成 rsa 时必须拒绝（不支持的算法不许静默放行）"
        );
        assert!(
            verify_array_text(MAIN, "not json").is_err(),
            "sidecar 不是合法 JSON 时必须拒绝（不许 panic 也不许放行）"
        );
    }
}
