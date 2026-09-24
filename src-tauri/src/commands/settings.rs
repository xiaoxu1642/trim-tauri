//! settings 域（C 批）：settings:load / settings:save
//!
//! 对照 main.js 4774-4840（settings:load）、4977-5070（settings:save）、
//! 4669-4691（loadAiSettings/saveAiSettings）、4316-4560（AI 常量与调用参数）。
//!
//! 本模块同时是 **C 批 AI 配置链的唯一真源**：models / aidesc / fonts 三个域都从这里取
//! 配置读写、模型合并、作用域、掩码、超时钳制、SSRF 判定（避免四处复制漂移）。
//!
//! # 密钥存储链（D5 / 审查 1-5）
//!
//! - 读：`settings.json` → `security::read_json_or_quarantine`（损坏隔离）→
//!   `security::decrypt_settings_with_oscrypt`（`dpapi:v1:` → 明文；主密钥取不到时按
//!   「未配置」回落空串，不阻塞其余字段）；
//! - 写：`security::encrypt_settings_with_oscrypt`（**绝不明文落盘**；无主密钥时回落
//!   旧版「v10 + 裸 DPAPI」密文，Electron 与本项目两侧都能读）；
//! - 出口：发往渲染层前统一过 `security::mask_settings`（空值保持空串 = 未配置；
//!   未知字段一律掩码），掩码回传即「用户未修改」语义。
//!
//! # 与 Electron 的差异
//!
//! - 密钥加密：Electron 走 `safeStorage.encryptString`；Tauri 走同一 OSCrypt 主密钥
//!   （Local State 的 `os_crypt.encrypted_key`）的 AES-256-GCM，格式逐字节一致；
//!   主密钥不存在时（干净安装）落裸 DPAPI 密文——这正是旧 Electron 的既有格式，
//!   两侧均可解，绝不写明文。
//! - 时间戳：`Date.toISOString()` 由本模块的 `iso_utc_now()` 复刻（无 chrono 依赖）。
//!
//! 需要加入 lib.rs `generate_handler!` 的完整行：
//!   commands::settings::settings_load,
//!   commands::settings::settings_save,

use serde_json::{json, Value};
use tauri::WebviewWindow;

use crate::engine::{guard, log, paths};
use crate::security::{self, SECRET_MASK};

// ==================== 常量（与 main.js 逐条同值） ====================

/// 旧版平铺字段的引擎降级顺序（仅用于读取历史配置）
pub(crate) const AI_ENGINE_ORDER: &[&str] = &["baidu", "metaso", "zhihu"];
/// 大模型管理四个模型项（顺序即渲染层 modelList 的 order）
pub(crate) const AI_MODEL_KEYS: &[&str] = &["baidu_pro", "zhihu", "metaso", "custom"];
/// 各模块 AI 简介作用域
pub(crate) const AI_SCOPES: &[&str] = &["optimizer", "startup", "contextmenu", "memoryclean", "maintenance"];
/// AI 简介全局槽位（统筹全局：所有模块统一使用该模型）
pub(crate) const GLOBAL_ENGINE_KEY: &str = "global";
/// 百度千帆默认端点（web_summary，instruction 必填）
pub(crate) const DEFAULT_BAIDU_URL: &str = "https://qianfan.baidubce.com/v2/ai_search/web_summary";
/// 秘塔默认端点
pub(crate) const DEFAULT_METASO_URL: &str = "https://metaso.cn/api/v1/chat/completions";
/// 知乎直答默认端点
pub(crate) const DEFAULT_ZHIHU_URL: &str = "https://developer.zhihu.com/v1/chat/completions";
/// 秘塔密钥默认留空（用户自行填写并保存校验）
pub(crate) const AI_DEFAULT_METASO_KEY: &str = "";
/// 默认提示词（旧版平铺字段回显用）
pub(crate) const AI_DEFAULT_PROMPT: &str =
    "请简要说明以下右键菜单项的功能，控制在100字以内，仅输出最终回答，不要思考过程、解释与额外话术。";
/// 保存/测试模型时自动发送的连通性确认消息
pub(crate) const AI_VERIFY_PROMPT: &str = "api是什么，用三十个字简略回答";

/// settings.json 路径（%APPDATA%\com.xiaoxu.trim\settings.json，与 D5 数据目录一致）
pub(crate) fn settings_file() -> std::path::PathBuf {
    paths::join_data("settings.json")
}

/// AI 简介缓存目录（cache）
pub(crate) fn ai_cache_dir() -> std::path::PathBuf {
    paths::app_data_dir().join("cache")
}

// ==================== JS 语义小助手 ====================

/// JS 假值判定（`!!v`）：0/NaN/空串/null/undefined/false 为假
pub(crate) fn js_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(false),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// JS `String(v)`（仅处理本域实际出现的标量；对象按 `[object Object]` 近似）
pub(crate) fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        Value::Array(items) => items
            .iter()
            .map(|i| match i {
                Value::Null => String::new(),
                other => js_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// JS `Number(v)`
pub(crate) fn js_number(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Value::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Value::Null => 0.0,
        Value::Array(items) => match items.len() {
            0 => 0.0,
            1 => js_number(&items[0]),
            _ => f64::NAN,
        },
        Value::Object(_) => f64::NAN,
    }
}

/// JS `X || Y` 环节：真值取其字符串，假值取下一候选（C 批各域共用）
pub(crate) fn truthy_string(v: Option<&Value>) -> Option<String> {
    if js_truthy(v) {
        v.map(js_string)
    } else {
        None
    }
}

/// JS `X ? X : Y`（用于回显字段）
fn or_default(v: Option<&Value>, default: &str) -> String {
    truthy_string(v).unwrap_or_else(|| default.to_string())
}

/// `/^https?:\/\//i`
pub(crate) fn is_http_url(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// `clampTimeout`：超时约束 5~120 秒（NaN/缺失取默认值后再钳制）
pub(crate) fn clamp_timeout(v: Option<&Value>, def: i64) -> i64 {
    let n = match v {
        Some(v) => js_number(v),
        None => f64::NAN,
    };
    if !n.is_finite() || n < 5.0 {
        return def.clamp(5, 120);
    }
    if n > 120.0 {
        return 120;
    }
    n.round() as i64
}

/// `normalizeChatCompletionsUrl`：OpenAI 兼容地址归一（自定义模型仅支持 chat/completions）
pub(crate) fn normalize_chat_completions_url(raw: &str) -> String {
    let mut url = raw.trim().to_string();
    while url.ends_with('/') {
        url.pop();
    }
    if url.is_empty() {
        return String::new();
    }
    let lower = url.to_ascii_lowercase();
    if lower.ends_with("/chat/completions") {
        return url;
    }
    // `/v\d+$`
    if let Some(idx) = url.rfind("/v") {
        let tail = &url[idx + 2..];
        if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
            return format!("{url}/chat/completions");
        }
    }
    format!("{url}/v1/chat/completions")
}

/// UTC ISO-8601（毫秒精度，`new Date().toISOString()` 同形）。
/// 不引 chrono：UNIX 纪元秒直接换算（UTC 无需时区表）。
pub(crate) fn iso_utc_now() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant 的 civil_from_days（与 engine/log.rs 同算法）
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ==================== URL 解析与 SSRF 判定 ====================

/// 极简 URL 解析结果（不引 url crate；解析失败一律按私有处理 = fail-safe）
pub(crate) struct ParsedUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub secure: bool,
    /// authority 段是否用方括号包了 IP 字面量。IPv6 判定需要这个信号：`[::1]` 剥掉括号后
    /// 与畸形串（`[oops]`）在 host 上无从区分，而路径里出现 `[` 又不该触发 fail-closed。
    pub bracketed: bool,
}

/// 解析 `scheme://[userinfo@]host[:port][/path][?query]`。
/// `path` 已剥去 fragment（HTTP 请求目标不含 fragment），无路径时补 `/`。
pub(crate) fn parse_http_url(raw: &str) -> Option<ParsedUrl> {
    let s = raw.trim();
    let colon = s.find(':')?;
    let scheme = s[..colon].to_ascii_lowercase();
    let rest = &s[colon + 1..];
    let default_port: u16 = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => 0,
    };
    let secure = scheme == "https";
    if !rest.starts_with("//") {
        // 无 authority（如 `http:foo` / `mailto:x`）：host 视为空
        return Some(ParsedUrl {
            scheme,
            host: String::new(),
            port: default_port,
            path: "/".into(),
            secure,
            bracketed: false,
        });
    }
    let after = &rest[2..];
    let auth_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..auth_end];
    let path = if auth_end < after.len() {
        let p = &after[auth_end..];
        let p = p.split('#').next().unwrap_or(p);
        if p.starts_with('?') {
            format!("/{p}")
        } else {
            p.to_string()
        }
    } else {
        "/".to_string()
    };
    // 剥 userinfo（取最后一个 '@'，与浏览器一致）
    let host_port = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    if host_port.is_empty() {
        return Some(ParsedUrl {
            scheme,
            host: String::new(),
            port: default_port,
            path,
            secure,
            bracketed: false,
        });
    }
    let (host, port, bracketed) = if let Some(inner) = host_port.strip_prefix('[') {
        // IPv6 字面量必须带方括号
        let close = inner.find(']')?;
        let tail = &inner[close + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse::<u16>().ok()?,
            None => default_port,
        };
        (inner[..close].to_string(), port, true)
    } else {
        let colons = host_port.matches(':').count();
        if colons > 1 {
            // 未加方括号的 IPv6：浏览器视为非法 URL
            return None;
        }
        let (h, p) = match host_port.find(':') {
            Some(i) => (host_port[..i].to_string(), host_port[i + 1..].parse::<u16>().ok()?),
            None => (host_port.to_string(), default_port),
        };
        (h, p, false)
    };
    Some(ParsedUrl {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
        path,
        secure,
        bracketed,
    })
}

/// `net.isIPv4` 近似（严格四段十进制、无多余前导零）
fn is_ipv4(host: &str) -> Option<[u32; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u32; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
        out[i] = p.parse::<u32>().ok()?;
        if out[i] > 255 {
            return None;
        }
    }
    Some(out)
}

/// `is_ipv4` 的严格四段十进制口径**收不到** `127.1`、`2130706433`、`0x7f000001`、`0177.0.0.1`
/// 这类写法，而 Winsock / Node / 浏览器都会把它们解析成对应 IPv4 —— 审查 K1 的绕过点正是
/// 这些字面量落到了「未知域名」分支被判公网。故按 `inet_aton` 语义补齐（不引新依赖）。
///
/// 段规则：无 `0x` 前缀时**只接受十进制数字**（这排除了一切域名，`cafe.babe` 不会误判），
/// 前导 0 按八进制；首段可占剩余全部位宽，其余每段必须 ≤255。
fn parse_ipv4_aton(host: &str) -> Option<[u32; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut vals = Vec::with_capacity(parts.len());
    for p in &parts {
        if p.is_empty() || p.len() > 11 {
            return None;
        }
        let v = if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
            if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            u32::from_str_radix(hex, 16).ok()?
        } else {
            if !p.chars().all(|c| c.is_ascii_digit()) {
                return None; // 含字母即域名
            }
            let radix = if p.len() > 1 && p.starts_with('0') { 8 } else { 10 };
            u32::from_str_radix(p, radix).ok()?
        };
        vals.push(v);
    }
    let n = vals.len();
    // 末 n-1 段各占一字节，首段占剩余位（n=1 时即整个 32 位）
    for v in &vals[1..] {
        if *v > 255 {
            return None;
        }
    }
    let bits = 32 - 8 * (n as u32 - 1);
    let limit: u64 = if bits >= 32 { u32::MAX as u64 + 1 } else { 1u64 << bits };
    if vals[0] as u64 >= limit {
        return None;
    }
    let mut acc = vals[0];
    for v in &vals[1..] {
        acc = (acc << 8) | *v;
    }
    Some([(acc >> 24) & 255, (acc >> 16) & 255, (acc >> 8) & 255, acc & 255])
}

/// 标准 IPv6 文本（含 `::` 压缩与 `::ffff:1.2.3.4` 内嵌 IPv4 尾巴）展开成 16 字节。
fn parse_ipv6(host: &str) -> Option<[u8; 16]> {
    if host.contains('[') || host.contains(']') || host.is_empty() {
        return None;
    }
    let (head_s, tail_s) = match host.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (host, None),
    };
    let group = |s: &str| -> Option<u16> {
        if s.is_empty() || s.len() > 4 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u16::from_str_radix(s, 16).ok()
    };
    let mut head: Vec<u16> = Vec::new();
    if !head_s.is_empty() {
        for g in head_s.split(':') {
            head.push(group(g)?);
        }
    }
    let mut tail: Vec<u16> = Vec::new();
    if let Some(t) = &tail_s {
        if !t.is_empty() {
            let parts: Vec<&str> = t.split(':').collect();
            let last = *parts.last()?;
            let (v4_tail, mid) = if last.contains('.') {
                (Some(last), &parts[..parts.len() - 1])
            } else {
                (None, &parts[..])
            };
            for g in mid {
                tail.push(group(g)?);
            }
            if let Some(v4) = v4_tail {
                // 内嵌 IPv4 占两个 16 位组（`::ffff:7f00:1` 与 `::ffff:127.0.0.1` 等价）
                let o = is_ipv4(v4).or_else(|| parse_ipv4_aton(v4))?;
                tail.push(((o[0] << 8) | o[1]) as u16);
                tail.push(((o[2] << 8) | o[3]) as u16);
            }
        }
    }
    let mut out = [0u16; 8];
    match tail_s {
        None => {
            if head.len() != 8 {
                return None;
            }
            out.copy_from_slice(&head);
        }
        Some(_) => {
            if head.len() + tail.len() > 7 {
                // `::` 至少要代表一组零
                return None;
            }
            for (i, v) in head.iter().enumerate() {
                out[i] = *v;
            }
            for (i, v) in tail.iter().enumerate() {
                out[8 - tail.len() + i] = *v;
            }
        }
    }
    let mut b = [0u8; 16];
    for (i, g) in out.iter().enumerate() {
        b[i * 2] = (g >> 8) as u8;
        b[i * 2 + 1] = (g & 0xff) as u8;
    }
    Some(b)
}

/// IPv4 私有/特殊网段判定（原 `is_private_api_url` 内联逻辑提出，供两种字面量共用）
fn ipv4_private(o: [u32; 4]) -> bool {
    o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254) // 链路本地（含 169.254.169.254 元数据地址）
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64/10
}

/// IPv6 侧私有判定。除逐网段比对外，**6to4 / Teredo 一律按私有处理**：两者都把 IPv4
/// 地址编码进自身（`2002:v4::`、`2001:0::v4`），是隧道式绕过本机字面量校验的现成通道，
/// 而没有任何一家模型服务会用裸 6to4/Teredo 字面量当 API 端点。
fn ipv6_private(b: &[u8; 16]) -> bool {
    if b[..] == [0u8; 16] {
        return true; // `::` 未指定
    }
    if b[..15] == [0u8; 15] && b[15] == 1 {
        return true; // `::1` 环回
    }
    if b[0] & 0xfe == 0xfc {
        return true; // fc00::/7 唯一本地
    }
    if b[0] == 0xfe && b[1] & 0xc0 == 0x80 {
        return true; // fe80::/10 链路本地
    }
    // IPv4 映射/兼容形式：取出内嵌 IPv4 再走 v4 网段判定
    if (b[..10] == [0u8; 10] && b[10] == 0xff && b[11] == 0xff) || b[..12] == [0u8; 12] {
        return ipv4_private([b[12] as u32, b[13] as u32, b[14] as u32, b[15] as u32]);
    }
    if b[0] == 0x20 && b[1] == 0x02 {
        return true; // 6to4 2002::/16：内嵌 IPv4 可指向任意网段，直接拒
    }
    if b[..4] == [0x20, 0x01, 0x00, 0x00] {
        return true; // Teredo 2001:0000::/32
    }
    false
}

/// `isPrivateApiUrl`（火眼眼审查 2026-09-14）：拒绝环回/私有/链路本地网段。
/// 协议非法或解析失败一律判私有；**字面量形式一律归一化后再判**（审查 K1：整数型/缩写型/
/// IPv4-mapped 曾落到「未知域名」分支被放行）。域名解析到内网 IP 的 rebinding 不在本防线内。
pub(crate) fn is_private_api_url(raw: &str) -> bool {
    let Some(u) = parse_http_url(raw) else {
        return true; // 解析失败按私有处理（fail-safe）
    };
    if u.scheme != "http" && u.scheme != "https" {
        return true;
    }
    if u.host.is_empty() {
        return true;
    }
    if u.host == "localhost" || u.host.ends_with(".localhost") || u.host == "0.0.0.0" {
        return true;
    }
    if let Some(o) = is_ipv4(&u.host).or_else(|| parse_ipv4_aton(&u.host)) {
        return ipv4_private(o);
    }
    if u.host.contains(':') || u.bracketed {
        // 方括号里的东西只可能是 IPv6 字面量：解析不出来即畸形 → fail-closed，
        // 不允许它退回去当域名放行。
        return match parse_ipv6(&u.host) {
            Some(b) => ipv6_private(&b),
            None => true,
        };
    }
    false
}

// ==================== 配置读写（settings.json） ====================

/// `loadAiSettings`：读 + 损坏隔离 + 密钥解密
pub(crate) fn load_settings() -> Value {
    let v = security::read_json_or_quarantine(&settings_file());
    if !v.is_object() {
        return json!({});
    }
    security::decrypt_settings_with_oscrypt(&v)
}

/// `saveAiSettings`：密钥加密后原子落盘（失败仅记日志，返回 false 与 Electron 同回执）
pub(crate) fn save_settings(settings: &Value) -> bool {
    match security::encrypt_settings_with_oscrypt(settings) {
        Ok(encrypted) => match security::atomic_write_json(&settings_file(), &encrypted) {
            Ok(()) => true,
            Err(e) => {
                log::write_log("error", &format!("保存设置失败: {e}"));
                false
            }
        },
        Err(e) => {
            // 与 Electron「safeStorage 不可用即拒绝明文保存」同语义（返回 false → 渲染层提示写入失败）
            log::write_log("error", &format!("保存设置失败: {e}"));
            false
        }
    }
}

/// 取字符串字段（JS `str(k)`：仅当显式提供（非 undefined/null）时转字符串并 trim）
pub(crate) fn str_field(settings: &Value, key: &str) -> Option<String> {
    match settings.get(key) {
        None | Some(Value::Null) => None,
        Some(v) => Some(js_string(v).trim().to_string()),
    }
}

/// 掩码穿透（审查 1-5）：提交掩码视为未修改 → None 走「保留旧值」分支
pub(crate) fn str_kept(settings: &Value, key: &str) -> Option<String> {
    match str_field(settings, key) {
        Some(v) if v == SECRET_MASK => None,
        other => other,
    }
}

/// 旧版平铺字段：秘塔地址
pub(crate) fn metaso_url(s: &Value) -> String {
    let candidate = truthy_string(s.get("metasoApiUrl")).or_else(|| {
        if s.get("aiEngine").and_then(|v| v.as_str()) == Some("metaso") {
            truthy_string(s.get("aiApiUrl"))
        } else {
            None
        }
    });
    candidate
        .unwrap_or_else(|| DEFAULT_METASO_URL.to_string())
        .trim()
        .to_string()
}

/// 旧版平铺字段：百度地址
pub(crate) fn baidu_url(s: &Value) -> String {
    let candidate = truthy_string(s.get("baiduApiUrl")).or_else(|| {
        if s.get("aiEngine").and_then(|v| v.as_str()) == Some("baidu") {
            truthy_string(s.get("aiApiUrl"))
        } else {
            None
        }
    });
    candidate
        .unwrap_or_else(|| DEFAULT_BAIDU_URL.to_string())
        .trim()
        .to_string()
}

/// 旧版平铺字段：秘塔密钥
pub(crate) fn metaso_key(s: &Value) -> String {
    truthy_string(s.get("metasoApiKey"))
        .or_else(|| truthy_string(s.get("aiApiKey")))
        .unwrap_or_else(|| AI_DEFAULT_METASO_KEY.to_string())
        .trim()
        .to_string()
}

/// 旧版平铺字段：百度密钥
pub(crate) fn baidu_key(s: &Value) -> String {
    truthy_string(s.get("baiduApiKey"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

// ==================== 大模型配置（models 字段） ====================

/// 单个模型项的出厂值（键序与 main.js AI_MODELS 一致）
pub(crate) fn base_model(key: &str) -> Value {
    match key {
        "baidu_pro" => json!({
            "label": "百度千帆", "kind": "baidu_web_summary", "builtin": true,
            "apiUrl": DEFAULT_BAIDU_URL, "apiKey": "", "model": "thinking",
            "prompt": "", "timeout": 30, "enabled": false, "verified": false
        }),
        "zhihu" => json!({
            "label": "知乎直答", "kind": "openai", "builtin": true,
            "apiUrl": DEFAULT_ZHIHU_URL, "apiKey": "", "model": "zhida-fast-1p5",
            "prompt": "", "timeout": 30, "enabled": false, "verified": false
        }),
        "metaso" => json!({
            "label": "秘塔 AI", "kind": "openai", "builtin": true,
            "apiUrl": DEFAULT_METASO_URL, "apiKey": AI_DEFAULT_METASO_KEY, "model": "fast_thinking",
            "prompt": "", "timeout": 30, "enabled": false, "verified": false
        }),
        "custom" => json!({
            // 自定义模型：仅支持 OpenAI 兼容的 chat/completions 协议
            "label": "自定义模型", "kind": "openai", "builtin": false,
            "apiUrl": "", "apiKey": "", "model": "", "prompt": "", "timeout": 30,
            "enabled": false, "verified": false, "customName": ""
        }),
        _ => json!({}),
    }
}

/// `{...base, ...over}`（键序：基础键位保留，新键追加，与 JS 展开语义一致）
pub(crate) fn merge_model(base: Value, over: Option<&Value>) -> Value {
    let mut out = base;
    let Some(om) = over.and_then(|v| v.as_object()) else {
        return out;
    };
    if let Some(map) = out.as_object_mut() {
        for (k, v) in om {
            map.insert(k.clone(), v.clone());
        }
    }
    out
}

/// `loadModelsConfig`：四个模型项合并（含旧版平铺字段一次性迁移）
pub(crate) fn models_config() -> Value {
    let s = load_settings();
    let stored = s.get("models").and_then(|v| v.as_object()).cloned();
    let mut models = serde_json::Map::new();
    for key in AI_MODEL_KEYS {
        let over = stored.as_ref().and_then(|m| m.get(*key));
        models.insert((*key).to_string(), merge_model(base_model(key), over));
    }
    if stored.is_none() {
        // 旧版平铺字段：仅在 models 字段整体缺失时迁移
        if js_truthy(s.get("baiduApiUrl")) || js_truthy(s.get("baiduApiKey")) || js_truthy(s.get("baiduModel")) {
            let cur = models.get("baidu_pro").cloned().unwrap_or_else(|| json!({}));
            models.insert(
                "baidu_pro".into(),
                merge_model(
                    cur,
                    Some(&json!({
                        "apiUrl": or_default(s.get("baiduApiUrl"), DEFAULT_BAIDU_URL),
                        "apiKey": truthy_string(s.get("baiduApiKey")).unwrap_or_default(),
                        "model": or_default(s.get("baiduModel"), "thinking"),
                        "prompt": truthy_string(s.get("baiduPrompt")).unwrap_or_default(),
                        "timeout": clamp_timeout(s.get("baiduTimeout"), 30),
                    })),
                ),
            );
        }
        if js_truthy(s.get("metasoApiUrl")) || js_truthy(s.get("metasoApiKey")) || js_truthy(s.get("metasoModel")) {
            let cur = models.get("metaso").cloned().unwrap_or_else(|| json!({}));
            let base_key = truthy_string(cur.get("apiKey")).unwrap_or_default();
            models.insert(
                "metaso".into(),
                merge_model(
                    cur,
                    Some(&json!({
                        "apiUrl": or_default(s.get("metasoApiUrl"), DEFAULT_METASO_URL),
                        "apiKey": truthy_string(s.get("metasoApiKey")).unwrap_or(base_key),
                        "model": or_default(s.get("metasoModel"), "fast_thinking"),
                        "prompt": truthy_string(s.get("metasoPrompt")).unwrap_or_default(),
                        "timeout": clamp_timeout(s.get("metasoTimeout"), 30),
                    })),
                ),
            );
        }
        if js_truthy(s.get("zhihuApiUrl")) || js_truthy(s.get("zhihuApiKey")) || js_truthy(s.get("zhihuAccessSecret")) || js_truthy(s.get("zhihuModel")) {
            let cur = models.get("zhihu").cloned().unwrap_or_else(|| json!({}));
            models.insert(
                "zhihu".into(),
                merge_model(
                    cur,
                    Some(&json!({
                        "apiUrl": or_default(s.get("zhihuApiUrl"), DEFAULT_ZHIHU_URL),
                        "apiKey": truthy_string(s.get("zhihuApiKey"))
                            .or_else(|| truthy_string(s.get("zhihuAccessSecret")))
                            .unwrap_or_default(),
                        "model": or_default(s.get("zhihuModel"), "zhida-fast-1p5"),
                        "prompt": truthy_string(s.get("zhihuPrompt")).unwrap_or_default(),
                        "timeout": clamp_timeout(s.get("zhihuTimeout"), 30),
                    })),
                ),
            );
        }
    }
    Value::Object(models)
}

/// `loadScopeEngines`：各模块所选模型 + 全局槽位（global 优先，回落旧版 per-scope）
pub(crate) fn scope_engines() -> Value {
    let s = load_settings();
    let ai_scopes = s.get("aiScopes");
    let read = |key: &str| -> Option<String> {
        ai_scopes
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| AI_MODEL_KEYS.contains(&s.as_str()))
    };
    let mut scopes = serde_json::Map::new();
    for scope in AI_SCOPES {
        let v = read(scope).unwrap_or_else(|| "metaso".into());
        scopes.insert((*scope).to_string(), json!(v));
    }
    let global = read(GLOBAL_ENGINE_KEY)
        .or_else(|| read("optimizer"))
        .unwrap_or_else(|| "metaso".into());
    scopes.insert(GLOBAL_ENGINE_KEY.into(), json!(global));
    Value::Object(scopes)
}

/// `modelDisplayName`：自定义模型优先展示名，其次模型名
pub(crate) fn model_display_name(key: &str, cfg: Option<&Value>) -> String {
    let empty = json!({});
    let conf = cfg.unwrap_or(&empty);
    if key == "custom" {
        let name = truthy_string(conf.get("customName"))
            .or_else(|| truthy_string(conf.get("model")))
            .unwrap_or_default();
        let name = name.trim().to_string();
        if !name.is_empty() {
            return name;
        }
        return "自定义模型".into();
    }
    for k in AI_MODEL_KEYS {
        if *k == key {
            if let Some(label) = base_model(key).get("label").and_then(|v| v.as_str()) {
                return label.to_string();
            }
        }
    }
    key.to_string()
}

/// 作用域的日志名与默认提示词（AI_SCOPE_META）
pub(crate) fn scope_meta(scope: &str) -> (&'static str, &'static str) {
    match scope {
        "optimizer" => (
            "电脑优化中心",
            "请用简体中文简要介绍下面这个 Windows 系统优化项的作用、适用场景与需要注意的风险，控制在120字以内，只输出最终结论，不要思考过程与额外话术。",
        ),
        "startup" => (
            "启动项管理",
            "请用简体中文简要介绍下面这个 Windows 开机启动项所属软件的功能与厂商，并说明禁用它之后对日常使用有什么影响，控制在120字以内，只输出最终结论，不要思考过程与额外话术。",
        ),
        "memoryclean" => (
            "内存清理",
            "请用简体中文简要介绍下面这个 Windows 内存清理操作的作用、原理与需要注意的风险，控制在120字以内，只输出最终结论，不要思考过程与额外话术。",
        ),
        "maintenance" => (
            "系统维护",
            "请用简体中文简要解释下面这个 Windows 系统维护修复项：它是什么、什么情况下需要执行、执行后预期达到的效果与注意事项，控制在150字以内，只输出最终结论，不要思考过程与额外话术。",
        ),
        // contextmenu：未传 scope / 未知 scope 的兜底（与 JS 的 scopeKey 兜底同域）
        _ => (
            "右键管理",
            "请用简体中文简要介绍下面这个 Windows 右键菜单项的功能与所属公司，并说明是否建议保留，控制在120字以内，只输出最终结论，不要思考过程与额外话术。",
        ),
    }
}

/// 回显用：modelList 的 label/kind/builtin（来自出厂值）
fn model_meta(key: &str) -> (String, String, bool) {
    let b = base_model(key);
    (
        b.get("label").and_then(|v| v.as_str()).unwrap_or(key).to_string(),
        b.get("kind").and_then(|v| v.as_str()).unwrap_or("openai").to_string(),
        b.get("builtin").and_then(|v| v.as_bool()).unwrap_or(false),
    )
}

// ==================== 命令 ====================

/// settings:load — 返回 AI 简介配置 + 大模型管理配置（**密钥一律掩码**）
#[tauri::command]
pub fn settings_load<R: tauri::Runtime>(window: WebviewWindow<R>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let s = load_settings();
    let engine = s
        .get("aiEngine")
        .and_then(|v| v.as_str())
        .filter(|v| AI_ENGINE_ORDER.contains(v))
        .unwrap_or(AI_ENGINE_ORDER[0])
        .to_string();

    let mut data = serde_json::Map::new();
    data.insert("aiDescEnabled".into(), json!(js_truthy(s.get("aiDescEnabled"))));
    data.insert("aiEngine".into(), json!(engine));
    data.insert(
        "aiApiUrl".into(),
        json!(if engine == "baidu" { baidu_url(&s) } else { metaso_url(&s) }),
    );
    data.insert(
        "aiApiKey".into(),
        json!(if js_truthy(s.get("aiApiKey")) { SECRET_MASK } else { "" }),
    );
    data.insert("baiduApiUrl".into(), json!(or_default(s.get("baiduApiUrl"), "")));
    data.insert("metasoApiUrl".into(), json!(or_default(s.get("metasoApiUrl"), "")));
    // 百度千帆模型配置
    data.insert(
        "baiduApiKey".into(),
        json!(if baidu_key(&s).is_empty() { "" } else { SECRET_MASK }),
    );
    data.insert("baiduModel".into(), json!(or_default(s.get("baiduModel"), "thinking")));
    data.insert("baiduPrompt".into(), json!(or_default(s.get("baiduPrompt"), AI_DEFAULT_PROMPT)));
    data.insert("baiduTimeout".into(), json!(clamp_timeout(s.get("baiduTimeout"), 30)));
    // 秘塔模型配置
    data.insert(
        "metasoApiKey".into(),
        json!(if metaso_key(&s).is_empty() { "" } else { SECRET_MASK }),
    );
    data.insert("metasoModel".into(), json!(or_default(s.get("metasoModel"), "fast_thinking")));
    data.insert("metasoPrompt".into(), json!(or_default(s.get("metasoPrompt"), AI_DEFAULT_PROMPT)));
    data.insert("metasoTimeout".into(), json!(clamp_timeout(s.get("metasoTimeout"), 30)));
    // 知乎直答配置（兼容旧版遗留字段 zhihuAccessSecret）
    data.insert("zhihuApiUrl".into(), json!(or_default(s.get("zhihuApiUrl"), DEFAULT_ZHIHU_URL)));
    data.insert(
        "zhihuApiKey".into(),
        json!(if truthy_string(s.get("zhihuApiKey"))
            .or_else(|| truthy_string(s.get("zhihuAccessSecret")))
            .is_some()
        {
            SECRET_MASK
        } else {
            ""
        }),
    );
    data.insert("zhihuModel".into(), json!(or_default(s.get("zhihuModel"), "zhida-fast-1p5")));
    data.insert("zhihuPrompt".into(), json!(or_default(s.get("zhihuPrompt"), AI_DEFAULT_PROMPT)));
    data.insert("zhihuTimeout".into(), json!(clamp_timeout(s.get("zhihuTimeout"), 30)));

    // 大模型管理：四个模型项 + 密钥掩码 + _keyPresent（供渲染层判断是否已配置）
    let models = models_config();
    let mut masked_models = serde_json::Map::new();
    for key in AI_MODEL_KEYS {
        let item = models.get(*key).cloned().unwrap_or_else(|| json!({}));
        let present = js_truthy(item.get("apiKey"));
        let mut item = item;
        if let Some(map) = item.as_object_mut() {
            map.insert(
                "apiKey".into(),
                json!(if present { SECRET_MASK } else { "" }),
            );
            map.insert("_keyPresent".into(), json!(present));
        }
        masked_models.insert((*key).to_string(), item);
    }
    data.insert("models".into(), Value::Object(masked_models));
    data.insert("aiScopes".into(), scope_engines());

    let model_list: Vec<Value> = AI_MODEL_KEYS
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let cfg = models.get(*key);
            let (label, kind, builtin) = model_meta(key);
            json!({
                "key": key,
                "label": label,
                "displayName": model_display_name(key, cfg),
                "kind": kind,
                "builtin": builtin,
                "enabled": js_truthy(cfg.and_then(|c| c.get("enabled"))),
                "verified": js_truthy(cfg.and_then(|c| c.get("verified"))),
                "order": index,
            })
        })
        .collect();
    data.insert("modelList".into(), json!(model_list));

    // 出厂默认值（供「恢复默认」使用，不含密钥）
    let mut defaults = serde_json::Map::new();
    for key in AI_MODEL_KEYS {
        let b = base_model(key);
        defaults.insert(
            (*key).to_string(),
            json!({
                "apiUrl": b.get("apiUrl").and_then(|v| v.as_str()).unwrap_or(""),
                "apiKey": "",
                "model": b.get("model").and_then(|v| v.as_str()).unwrap_or(""),
                "prompt": b.get("prompt").and_then(|v| v.as_str()).unwrap_or(""),
                "timeout": b.get("timeout").and_then(|v| v.as_i64()).unwrap_or(30),
                "enabled": false,
                "customName": "",
            }),
        );
    }
    data.insert("modelDefaults".into(), Value::Object(defaults));

    // 出口统一脱敏兜底（幂等：已是掩码的值不变）
    let data = security::mask_settings(&Value::Object(data));
    Ok(json!({ "success": true, "data": data }))
}

/// settings:save — 保存 AI 简介设置（掩码穿透 + SSRF 校验 + 模型/作用域白名单）
#[tauri::command]
pub fn settings_save<R: tauri::Runtime>(window: WebviewWindow<R>, settings: Option<Value>) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let settings = match settings {
        Some(Value::Object(m)) => Value::Object(m),
        // JS 里数组也是 object：按「无任何字段」处理，与逐字段读取的结果一致
        Some(Value::Array(_)) => json!({}),
        _ => return Ok(json!({ "success": false, "message": "无效配置" })),
    };
    let current = load_settings();
    let engine = settings
        .get("aiEngine")
        .and_then(|v| v.as_str())
        .filter(|v| AI_ENGINE_ORDER.contains(v))
        .unwrap_or(AI_ENGINE_ORDER[0])
        .to_string();

    let str_ai_url = |v: Option<&Value>| -> String {
        truthy_string(v).unwrap_or_default().trim().to_string()
    };
    let cur_str = |key: &str| -> String { truthy_string(current.get(key)).unwrap_or_default() };
    // `settings.X !== undefined ? clampTimeout(settings.X, 30) : (current.X || 30)`
    let timeout_field = |field: &str| -> Value {
        match settings.get(field) {
            Some(_) => json!(clamp_timeout(settings.get(field), 30)),
            None => match current.get(field) {
                Some(v) if js_truthy(Some(v)) => v.clone(),
                _ => json!(30),
            },
        }
    };

    // 仅当字段显式提供时才覆盖，避免清空未提交的引擎配置
    let mut next = current.clone();
    if !next.is_object() {
        return Ok(json!({ "success": false, "message": "无效配置" }));
    }

    let ai_api_url = {
        let v = str_ai_url(settings.get("aiApiUrl"));
        if !v.is_empty() {
            v
        } else if engine == "baidu" {
            baidu_url(&current)
        } else {
            metaso_url(&current)
        }
    };
    let baidu_api_url = {
        let v = str_ai_url(settings.get("baiduApiUrl"));
        if !v.is_empty() {
            v
        } else if engine == "baidu" {
            str_ai_url(settings.get("aiApiUrl"))
        } else {
            cur_str("baiduApiUrl")
        }
    };
    let metaso_api_url = {
        let v = str_ai_url(settings.get("metasoApiUrl"));
        if !v.is_empty() {
            v
        } else if engine == "metaso" {
            str_ai_url(settings.get("aiApiUrl"))
        } else {
            cur_str("metasoApiUrl")
        }
    };
    let ai_api_key_raw = str_ai_url(settings.get("aiApiKey"));
    let ai_api_key = if !ai_api_key_raw.is_empty() && ai_api_key_raw != SECRET_MASK {
        ai_api_key_raw
    } else {
        cur_str("aiApiKey")
    };

    // 显式覆盖字段先收集到 flat，再按 JS「展开 + 逐字段赋值」的键序并入 next
    let mut flat = serde_json::Map::new();
    flat.insert("aiDescEnabled".into(), json!(js_truthy(settings.get("aiDescEnabled"))));
    flat.insert("aiEngine".into(), json!(engine));
    flat.insert("aiApiUrl".into(), json!(ai_api_url));
    flat.insert("aiApiKey".into(), json!(ai_api_key));
    flat.insert("baiduApiUrl".into(), json!(baidu_api_url));
    flat.insert("metasoApiUrl".into(), json!(metaso_api_url));
    // 百度千帆模型配置
    flat.insert(
        "baiduApiKey".into(),
        json!(str_kept(&settings, "baiduApiKey").unwrap_or_else(|| cur_str("baiduApiKey"))),
    );
    flat.insert(
        "baiduModel".into(),
        json!(str_field(&settings, "baiduModel").unwrap_or_else(|| cur_str("baiduModel"))),
    );
    flat.insert(
        "baiduPrompt".into(),
        json!(str_field(&settings, "baiduPrompt").unwrap_or_else(|| cur_str("baiduPrompt"))),
    );
    flat.insert("baiduTimeout".into(), timeout_field("baiduTimeout"));
    // 秘塔模型配置
    flat.insert(
        "metasoApiKey".into(),
        json!(str_kept(&settings, "metasoApiKey").unwrap_or_else(|| cur_str("metasoApiKey"))),
    );
    flat.insert(
        "metasoModel".into(),
        json!(str_field(&settings, "metasoModel").unwrap_or_else(|| cur_str("metasoModel"))),
    );
    flat.insert(
        "metasoPrompt".into(),
        json!(str_field(&settings, "metasoPrompt").unwrap_or_else(|| cur_str("metasoPrompt"))),
    );
    flat.insert("metasoTimeout".into(), timeout_field("metasoTimeout"));
    // 知乎直答配置
    flat.insert(
        "zhihuApiUrl".into(),
        json!(str_field(&settings, "zhihuApiUrl").unwrap_or_else(|| cur_str("zhihuApiUrl"))),
    );
    flat.insert(
        "zhihuApiKey".into(),
        json!(str_kept(&settings, "zhihuApiKey").unwrap_or_else(|| {
            truthy_string(current.get("zhihuApiKey"))
                .or_else(|| truthy_string(current.get("zhihuAccessSecret")))
                .unwrap_or_default()
        })),
    );
    flat.insert(
        "zhihuModel".into(),
        json!(str_field(&settings, "zhihuModel").unwrap_or_else(|| cur_str("zhihuModel"))),
    );
    flat.insert(
        "zhihuPrompt".into(),
        json!(str_field(&settings, "zhihuPrompt").unwrap_or_else(|| cur_str("zhihuPrompt"))),
    );
    flat.insert("zhihuTimeout".into(), timeout_field("zhihuTimeout"));

    // 平铺字段并入 next（键序与 JS「展开 + 逐字段赋值」一致：已有键保位，新键按序追加）
    if let Some(target) = next.as_object_mut() {
        for (k, v) in flat {
            target.insert(k, v);
        }
    }

    // 火眼眼审查 2026-09-14（HIGH）：与 models:save 同防 SSRF——4 个 URL 字段最终都会
    // 携带密钥出网；空值走「保留旧值/默认」分支不校验（掩码语义不变）。
    const URL_FIELD_LABELS: &[(&str, &str)] = &[
        ("aiApiUrl", "AI 接口地址"),
        ("baiduApiUrl", "百度千帆接口地址"),
        ("metasoApiUrl", "秘塔接口地址"),
        ("zhihuApiUrl", "知乎直答接口地址"),
    ];
    for (field, label) in URL_FIELD_LABELS {
        let v = next.get(*field).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if v.is_empty() {
            continue;
        }
        if !is_http_url(&v) {
            return Ok(json!({ "success": false, "message": format!("{label}格式无效，请以 http(s):// 开头") }));
        }
        if is_private_api_url(&v) {
            return Ok(json!({ "success": false, "message": format!("{label}不允许指向本机或内网网段") }));
        }
    }

    // 大模型管理：只接受已知模型字段，并且不能通过通用设置通道绕过验证状态。
    if let Some(submitted_all) = settings.get("models").and_then(|v| v.as_object()) {
        let current_models = models_config();
        let mut out = serde_json::Map::new();
        for model_key in AI_MODEL_KEYS {
            let current_model = current_models.get(*model_key).cloned().unwrap_or_else(|| json!({}));
            let submitted = submitted_all.get(*model_key).and_then(|v| v.as_object());
            let Some(submitted) = submitted else {
                out.insert((*model_key).to_string(), current_model);
                continue;
            };
            let cur_url = truthy_string(current_model.get("apiUrl")).unwrap_or_default();
            let model_url = truthy_string(submitted.get("apiUrl"))
                .or_else(|| {
                    if cur_url.trim().is_empty() {
                        None
                    } else {
                        Some(cur_url.clone())
                    }
                })
                .unwrap_or_default()
                .trim()
                .to_string();
            if !model_url.is_empty() {
                if !is_http_url(&model_url) {
                    return Ok(json!({
                        "success": false,
                        "message": format!("模型 {} 接口地址格式无效，请以 http(s):// 开头", model_display_name(model_key, Some(&current_model)))
                    }));
                }
                if is_private_api_url(&model_url) {
                    return Ok(json!({
                        "success": false,
                        "message": format!("模型 {} 接口地址不允许指向本机或内网网段", model_display_name(model_key, Some(&current_model)))
                    }));
                }
            }
            // SET-3（2026-09-15 v7）：掩码穿透——提交掩码视为未修改，保留已存真值
            let submitted_key = submitted.get("apiKey").map(js_string).map(|s| s.trim().to_string());
            let api_key = match &submitted_key {
                Some(k) if !k.is_empty() && k != SECRET_MASK => k.clone(),
                _ => truthy_string(current_model.get("apiKey")).unwrap_or_default(),
            };
            let pick = |k: &str| -> String {
                truthy_string(submitted.get(k))
                    .or_else(|| truthy_string(current_model.get(k)))
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            };
            let patch = json!({
                "apiUrl": model_url,
                "apiKey": api_key,
                "model": pick("model"),
                "prompt": pick("prompt"),
                "customName": pick("customName"),
                "timeout": clamp_timeout(
                    submitted.get("timeout"),
                    truthy_string(current_model.get("timeout"))
                        .and_then(|v| v.parse::<i64>().ok())
                        .unwrap_or(30),
                ),
                // 验证状态只信本地已存值，通用设置通道不得改
                "verified": js_truthy(current_model.get("verified")),
                "enabled": js_truthy(submitted.get("enabled")) && js_truthy(current_model.get("verified")),
            });
            let merged = merge_model(current_model, Some(&patch));
            out.insert((*model_key).to_string(), merged);
        }
        if let Some(target) = next.as_object_mut() {
            target.insert("models".into(), Value::Object(out));
        }
    }

    if let Some(submitted_scopes) = settings.get("aiScopes").and_then(|v| v.as_object()) {
        let mut scopes = scope_engines();
        if let Some(map) = scopes.as_object_mut() {
            for scope in AI_SCOPES.iter().chain(std::iter::once(&GLOBAL_ENGINE_KEY)) {
                if let Some(candidate) = submitted_scopes.get(*scope).and_then(|v| v.as_str()) {
                    if AI_MODEL_KEYS.contains(&candidate) {
                        map.insert((*scope).to_string(), json!(candidate));
                    }
                }
            }
        }
        if let Some(target) = next.as_object_mut() {
            target.insert("aiScopes".into(), scopes);
        }
    }

    // 清理已下线的「本地模型」与旧版知乎遗留字段，避免配置文件残留失效引擎
    if let Some(target) = next.as_object_mut() {
        for key in ["localApiUrl", "localApiKey", "localModel", "localPrompt", "localTimeout"] {
            target.remove(key);
        }
        target.remove("zhihuAccessSecret");
    }

    let ok = save_settings(&next);
    log::write_log(
        "info",
        &format!(
            "保存 AI 简介设置: enabled={}, engine={}",
            js_truthy(next.get("aiDescEnabled")),
            next.get("aiEngine").and_then(|v| v.as_str()).unwrap_or("")
        ),
    );
    Ok(json!({
        "success": ok,
        "message": if ok { "" } else { "写入配置文件失败" }
    }))
}

#[cfg(test)]
mod tests_private_url {
    //! 审查 K1 回归断言：字面量归一化后必须落进私有判定。这些形式过去全部判「公网」放行，
    //! 被注入的渲染层可借自定义模型端点把明文 Bearer 打到本机回环服务。
    use super::is_private_api_url;

    #[test]
    fn ipv4_alternate_forms_are_private() {
        for u in [
            "http://2130706433:8080/",    // 单一十进制整数 = 127.0.0.1
            "http://127.1/",              // 两段缩写
            "http://10.1.2/",             // 三段缩写
            "http://0x7f000001/",         // 十六进制
            "http://0177.0.0.1/",         // 八进制
            "http://127.0.0.1:8080/",
            "http://169.254.169.254/latest/meta-data/", // 链路本地（云元数据）
            "http://0.0.0.0/",
        ] {
            assert!(is_private_api_url(u), "{u} 应判私有");
        }
    }

    #[test]
    fn ipv6_mapped_and_tunnel_forms_are_private() {
        for u in [
            "http://[::1]:8080/",
            "http://[::]/",
            "http://[::ffff:127.0.0.1]:8080/",
            "http://[0:0:0:0:0:ffff:7f00:1]/",
            "http://[::7f00:1]/",                  // IPv4 兼容形式
            "http://[fc00::1]/",
            "http://[fd12:3456::1]/",
            "http://[fe80::1%1]/",                 // 链路本地（含 zone id 即畸形 → fail-closed）
            "http://[2002:7f00:1::]/",            // 6to4 内嵌 127.0.0.1
            "http://[2001:0000:1f00:1::]/",       // Teredo
            "http://[not-an-ipv6]/",              // 畸形一律拒
        ] {
            assert!(is_private_api_url(u), "{u} 应判私有");
        }
    }

    #[test]
    fn public_endpoints_still_allowed() {
        // 反向断言：硬化不得把正常公网端点一起拒掉（否则模型服务全线不可用）
        for u in [
            "https://api.openai.com/v1/chat/completions",
            "https://chatglm.cn/key",
            "http://8.8.8.8/",
            "http://cafe.babe/",        // 全十六进制字母的域名不得被当数字字面量
            "https://[2606:4700:4700::1111]/", // 合法公网 IPv6
            "http://api.example.com:8443/v1",
        ] {
            assert!(!is_private_api_url(u), "{u} 应放行");
        }
    }

    #[test]
    fn malformed_and_non_http_fail_closed() {
        for u in ["", "ftp://127.0.0.1/", "http:/x", "not a url", "http:///path"] {
            assert!(is_private_api_url(u), "{u} 应 fail-closed");
        }
    }
}
