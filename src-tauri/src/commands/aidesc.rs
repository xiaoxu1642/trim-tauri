//! aidesc 域（C 批）：aidesc:get
//!
//! 对照 main.js 5072-5124（aidesc:get）、4468-4568（callModelDescription /
//! callOpenAICompat / callBaiduWebSummary）、4712-4757（缓存键与百度日调用计数）。
//!
//! 本文件同时承载 **C 批 AI 传输层**：`models:save`（保存即校验）与 `models:test`
//! 复用这里的 `call_model_text`，避免两处各写一份 HTTP。
//!
//! # 传输实现（不新增 crate）
//!
//! Electron 用主进程 `fetch`；Rust 侧无 HTTP 客户端依赖，改用 **Windows 原生 WinHTTP**
//! （`windows` crate 已有依赖，仅新增特性 `Win32_Networking_WinHttp`），逐条对齐 fetch 语义：
//! POST JSON、`Authorization: Bearer`、2xx 视为 ok、超时中止（WinHttpSetTimeouts +
//! AbortController 同口径的「超时即视为失败」）、失败分支返回空（调用方按「未获得有效响应」处理）。
//! TLS 由 WinHTTP（系统 schannel）承担；代理走系统自动代理（`AUTOMATIC_PROXY`，
//! 与 Chromium 读系统代理一致）。响应体上限 1MB（异常端点不拖垮内存）。
//!
//! **重定向一律不自动跟随**（审查 v2-M7）：本链带 `Authorization: Bearer <明文密钥>`，
//! 交给 WinHTTP 自己跳的话，「公网端点 302 → 127.0.0.1」这一跳会先把凭据送到本机服务、
//! 事后复检只能拦住读回响应。现由 `post_json` 逐跳走，每跳先过 `resolve_redirect`
//! （非私有 + 同主机 + 不降级）才发下一跳。
//!
//! # 键序
//!
//! 请求体键序照抄 JS 对象字面量（`messages` → `stream` → `instruction` → `model`）；
//! `serde_json` 已开 `preserve_order`，与 Node 的 JSON.stringify 输出一致。
//!
//! 需要加入 lib.rs `generate_handler!` 的完整行：
//!   commands::aidesc::aidesc_get,

use std::path::PathBuf;

use serde_json::{json, Value};
use tauri::WebviewWindow;

use crate::engine::{guard, log};
use crate::security;

use super::settings::{
    self, clamp_timeout, js_string, js_truthy, model_display_name, models_config, scope_engines,
    scope_meta, GLOBAL_ENGINE_KEY,
};

/// 缓存有效期 7 天（JS：7 * 24 * 60 * 60 * 1000）
const AI_CACHE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// 百度千帆日调用上限（超过即拒绝，不降级到别的模型）
const BAIDU_DAILY_LIMIT: i64 = 100;
/// 百度千帆连通性/简介调用的固定人设指令（callModelText 侧）
const BAIDU_TEXT_INSTRUCTION: &str = "请严格按用户要求回答，不要输出思考过程。";
/// 响应体读取上限（防异常端点）
const MAX_BODY_BYTES: usize = 1024 * 1024;

// ==================== MD5（缓存键口径，与 JS crypto.createHash('md5') 同值） ====================
//
// 不引 md5 crate（不新增依赖）：这是纯确定性算法，自实现可对拍（见文件末尾 #[cfg(test)]）。
// 保留与 Electron 完全相同的散列，迁移后的缓存键不会漂移（命中/失效行为一致）。

fn md5_hex(input: &str) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut msg = input.as_bytes().to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, slot) in m.iter_mut().enumerate() {
            *slot = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let x = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g]);
            b = b.wrapping_add(x.rotate_left(S[i]));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = String::with_capacity(32);
    for v in [a0, b0, c0, d0] {
        for byte in v.to_le_bytes() {
            out.push_str(&format!("{byte:02x}"));
        }
    }
    out
}

/// `aiCacheKey`：MD5(菜单名称 | 厂商名称 | 引擎)
fn ai_cache_key(name: &str, company: &str, engine: &str) -> String {
    md5_hex(&format!("{name}|{company}|{engine}"))
}

// ==================== WinHTTP 传输 ====================

struct HttpResult {
    status: u16,
    body: String,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// WinHTTP 句柄 RAII（任一提前返回都不泄漏句柄）
struct WinHttpHandle(*mut std::ffi::c_void);

impl Drop for WinHttpHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Networking::WinHttp::WinHttpCloseHandle(self.0);
        }
    }
}

/// POST JSON（同步阻塞；调用方负责放到 spawn_blocking 里跑）
///
/// 重定向由本函数**逐跳自己走**（审查 v2-M7，理由见下面 `WINHTTP_OPTION_REDIRECT_POLICY_NEVER`）：
/// WinHTTP 默认策略是跟随，而本链带着 `Authorization: Bearer <明文密钥>` —— 交给它自动跟，
/// 「公网端点 302 → `http://127.0.0.1:<port>/`」这一跳会在凭据**已经发出去之后**才被发现。
fn post_json(
    url: &str,
    headers: &[(String, String)],
    body: &str,
    timeout_ms: u64,
) -> Result<HttpResult, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Networking::WinHttp::*;

    let target = settings::parse_http_url(url).ok_or_else(|| format!("接口地址无效: {url}"))?;
    if target.host.is_empty() {
        return Err(format!("接口地址缺少主机名: {url}"));
    }
    // K1：入口按私有地址口径拒一次。端点由用户在设置页自填，`models:save` 虽也校验，
    // 但本函数还被 `models:test`/`aidesc:get` 直接复用；少一处复检，被注入的渲染层就能
    // 借这里的 `Authorization: Bearer <明文密钥>` 打到本机回环服务并读回响应。
    if settings::is_private_api_url(url) {
        return Err("接口地址指向本机或内网，已按安全策略拒绝".into());
    }
    // 整条跳转链必须留在首发主机上：闸门按「最初那个用户填的端点」判，
    // 不按「上一跳」判 —— 后者会让 A→B→A 这种两跳把主机限制绕过去。
    let origin_host = target.host.clone();
    // 版本号取编译期常量：写死字面量就成了第 4 处需要手工同步的版本源
    let agent = wide(&format!("Trim/{}", env!("CARGO_PKG_VERSION")));
    let header_text: String = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    let header_wide: Vec<u16> = header_text.encode_utf16().collect();
    let timeout = timeout_ms.min(120_000) as i32;

    unsafe {
        let session = WinHttpOpen(
            PCWSTR(agent.as_ptr()),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        );
        if session.is_null() {
            return Err("WinHTTP 会话创建失败".into());
        }
        let _session = WinHttpHandle(session);
        // 超时与 fetch 的 AbortController 同口径：到点即失败（解析/连接各留 10s/15s 头寸）
        let _ = WinHttpSetTimeouts(session, 10_000, 15_000, timeout, timeout);
        // 审查 v2-M7（v1 K1 的第二半）：**关掉自动跟随**。
        // 旧实现在 `WinHttpReceiveResponse` 之后才 `query_final_url` + 复检，而那时跳转链
        // 已经跑完、`Authorization` 已经随跨主机跳转重发 —— 事后复检只拦得住"读回响应"，
        // 拦不住"本机服务已经收到明文密钥"。所以修法是**不让通道自己跳**，每跳先判后发。
        // 这里刻意不再叠一层事后复检（两层判据必然漂移，且第一层已经足够）。
        // 设不上就 fail-closed：宁可不发凭据，也不在「策略未知」的情况下把密钥交出去。
        let policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER.to_le_bytes();
        WinHttpSetOption(
            Some(session as *const std::ffi::c_void),
            WINHTTP_OPTION_REDIRECT_POLICY,
            Some(&policy),
        )
        .map_err(|_| "无法关闭自动重定向，已拒绝发出凭据".to_string())?;

        let mut current = target;
        // 跳数封顶：同主机 + 非私有仍可能配一个自指的 Location 形成死循环
        for hop in 0..=MAX_REDIRECT_HOPS {
            let host = wide(&current.host);
            let object = wide(&current.path);
            let connect = WinHttpConnect(session, PCWSTR(host.as_ptr()), current.port, 0);
            if connect.is_null() {
                return Err(format!("WinHTTP 连接失败: {}", current.host));
            }
            let _connect = WinHttpHandle(connect);
            let flags = if current.secure {
                WINHTTP_FLAG_SECURE
            } else {
                WINHTTP_OPEN_REQUEST_FLAGS(0)
            };
            let request = WinHttpOpenRequest(
                connect,
                windows::core::w!("POST"),
                PCWSTR(object.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                std::ptr::null(),
                flags,
            );
            if request.is_null() {
                return Err("WinHTTP 请求创建失败".into());
            }
            // 句柄随本轮作用域释放（声明顺序保证 request 先于 connect 关）；
            // 不这样做会在同一 session 下堆起一堆连接句柄。
            let _request = WinHttpHandle(request);
            let headers_slice: Option<&[u16]> = if header_wide.is_empty() {
                None
            } else {
                Some(&header_wide)
            };
            // 每一跳都原样带上了 Authorization（同主机前提下才可接受，判据在 resolve_redirect）
            let sent = WinHttpSendRequest(
                request,
                headers_slice,
                Some(body.as_ptr() as *const std::ffi::c_void),
                body.len() as u32,
                body.len() as u32,
                0,
            )
            .and_then(|_| WinHttpReceiveResponse(request, std::ptr::null_mut()));
            let stepped = sent.map_err(|e| format!("HTTP 请求失败: {e}")).and_then(|_| {
                let status = query_status(request);
                if (300..400).contains(&status) {
                    match query_location(request) {
                        Some(loc) => Ok(Hop::Redirect(loc)),
                        // 拿不到（超长 / 缺失）即不可判定 ⇒ fail-closed，不猜目的地
                        None => Err("接口返回重定向但无法读取 Location，已拒绝".to_string()),
                    }
                } else {
                    Ok(Hop::Done(HttpResult {
                        status: status as u16,
                        body: read_body(request),
                    }))
                }
            });
            match stepped? {
                Hop::Done(res) => return Ok(res),
                Hop::Redirect(location) => {
                    if hop == MAX_REDIRECT_HOPS {
                        return Err(format!("接口重定向超过 {MAX_REDIRECT_HOPS} 跳，已拒绝"));
                    }
                    current = resolve_redirect(&current, &origin_host, &location)?;
                }
            }
        }
        Err("接口重定向链未能收敛，已拒绝".into())
    }
}

/// 一跳的结果：拿到响应体，或者拿到一个**尚未校验**的 Location 原文。
enum Hop {
    Done(HttpResult),
    Redirect(String),
}

/// 本链只跟随「同主机 + 非私有」的跳转；跳数封顶见调用方。
const MAX_REDIRECT_HOPS: usize = 3;

/// 校验并补全一跳目标（审查 v2-M7 的**唯一**闸门，纯函数以便断言）。
///
/// 三条判据按顺序，任一不过即 `Err`：
/// 1. `Location` 能解析成 http(s) 绝对址（相对写法按 RFC 9110 以当前请求为基补全）；
/// 2. 补全后的地址不是私有/环回/链路本地（`is_private_api_url`，fail-closed 同口径）；
/// 3. 主机与**首发端点**逐字相同（跨主机的 302 是把凭据递给另一个服务的最短路径）；
///    并且不得从 https 降级到 http —— 带着 Bearer 的降级等于把密钥改成明文过网。
fn resolve_redirect(
    base: &settings::ParsedUrl,
    origin_host: &str,
    location: &str,
) -> Result<settings::ParsedUrl, String> {
    let loc = location.trim();
    if loc.is_empty() {
        return Err("接口重定向缺少 Location，已拒绝".into());
    }
    let joined = absolute_url(base, loc);
    if settings::is_private_api_url(&joined) {
        // 这条判据同时吃掉「非 http(s) 协议」（is_private_api_url 的 fail-safe 口径）
        return Err(format!("接口重定向终点不合规（本机/内网/协议非法），已拒绝: {joined}"));
    }
    let next = settings::parse_http_url(&joined)
        .ok_or_else(|| format!("接口重定向终点无法解析: {joined}"))?;
    if next.host.is_empty() {
        return Err(format!("接口重定向终点缺少主机名: {joined}"));
    }
    if next.host != origin_host {
        return Err(format!(
            "接口重定向跨主机（{origin_host} → {}），已拒绝",
            next.host
        ));
    }
    if base.secure && !next.secure {
        return Err("接口重定向把 https 降级为 http，携带的密钥会明文上网，已拒绝".into());
    }
    Ok(next)
}

/// `Location` → 绝对址。支持 `//host/path`（继承协议）、`/abs`、`rel`（相对当前路径的目录）
/// 与 `scheme://...`（原样，交由 `parse_http_url` 判协议合法性）。
fn absolute_url(base: &settings::ParsedUrl, loc: &str) -> String {
    if loc.starts_with("//") {
        return format!("{}:{loc}", base.scheme);
    }
    if loc.contains("://") {
        return loc.to_string();
    }
    let rest = if loc.starts_with('/') {
        loc.to_string()
    } else {
        // 相对当前「目录」：去掉基址最后一段（与浏览器同源算法一致）
        let dir = match base.path.rfind('/') {
            Some(i) => &base.path[..i + 1],
            None => "/",
        };
        format!("{dir}{loc}")
    };
    // `rest` 必然以 `/` 开头（上面两个分支都保证），拼成绝对址即可
    format!("{}{rest}", origin_of(base))
}

/// `scheme://host[:port]`（默认端口省略，避免把 `:443` 写进字面量后又被判成非默认端口）
fn origin_of(base: &settings::ParsedUrl) -> String {
    let host = if base.bracketed {
        format!("[{}]", base.host)
    } else {
        base.host.clone()
    };
    let default_port: u16 = if base.secure { 443 } else { 80 };
    if base.port == default_port {
        format!("{}://{host}", base.scheme)
    } else {
        format!("{}://{host}:{}", base.scheme, base.port)
    }
}

/// 状态码（读失败按 0 处理：调用方随后拿不到 2xx，等价于失败）
unsafe fn query_status(request: *mut std::ffi::c_void) -> u32 {
    use windows::core::PCWSTR;
    use windows::Win32::Networking::WinHttp::*;
    let mut status: u32 = 0;
    let mut len: u32 = std::mem::size_of::<u32>() as u32;
    let _ = WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        PCWSTR::null(),
        Some(&mut status as *mut u32 as *mut std::ffi::c_void),
        &mut len,
        std::ptr::null_mut(),
    );
    status
}

/// 读单个响应头。上限 4096 字节；放不下即返回 None（调用方 fail-closed，不去猜半个值）
unsafe fn query_header(request: *mut std::ffi::c_void, name: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Networking::WinHttp::*;
    const BUF_U16: usize = 2048;
    let name_w = wide(name);
    let mut buf = vec![0u16; BUF_U16];
    let mut len = (BUF_U16 * 2) as u32;
    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_CUSTOM,
        PCWSTR(name_w.as_ptr()),
        Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
        &mut len,
        std::ptr::null_mut(),
    )
    .ok()?;
    let taken = ((len as usize / 2).min(BUF_U16)).min(buf.len());
    let text = String::from_utf16_lossy(&buf[..taken]);
    let text = text.trim_end_matches('\0').trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

unsafe fn query_location(request: *mut std::ffi::c_void) -> Option<String> {
    query_header(request, "Location")
}

/// 读响应体，上限 `MAX_BODY_BYTES`（异常端点不拖垮内存）
unsafe fn read_body(request: *mut std::ffi::c_void) -> String {
    use windows::Win32::Networking::WinHttp::WinHttpReadData;
    let mut bytes: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 8192];
    loop {
        let mut read: u32 = 0;
        if WinHttpReadData(
            request,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len() as u32,
            &mut read,
        )
        .is_err()
        {
            break;
        }
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..read as usize]);
        if bytes.len() >= MAX_BODY_BYTES {
            break;
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}


/// fetch 的 `resp.ok`（2xx）
fn is_ok_status(status: u16) -> bool {
    (200..300).contains(&status)
}

// ==================== AI 调用链 ====================

/// `callOpenAICompat`：OpenAI 兼容 chat/completions（秘塔 / 知乎直答 / 自定义模型共用）
fn call_openai_compat(url: &str, key: &str, model: &str, prompt: &str, timeout_ms: u64) -> Option<String> {
    let mut headers: Vec<(String, String)> = vec![("Content-Type".into(), "application/json".into())];
    if !key.is_empty() {
        headers.push(("Authorization".into(), format!("Bearer {key}")));
    }
    let body = json!({
        "model": model,
        "stream": false,
        "messages": [{ "role": "user", "content": prompt }],
    })
    .to_string();
    let resp = post_json(url, &headers, &body, timeout_ms).ok()?;
    if !is_ok_status(resp.status) {
        return None;
    }
    let data: Value = serde_json::from_str(resp.body.trim()).ok()?;
    let content = data
        .get("choices")
        .and_then(|v| v.get(0))
        .and_then(|v| v.get("message"))
        .and_then(|v| v.get("content"))
        .map(js_string)?;
    let content = content.trim().to_string();
    if content.is_empty() {
        None
    } else {
        Some(content)
    }
}

/// `callBaiduWebSummary`：百度千帆·智能搜索生成高性能版（v2 ai_search/web_summary）
fn call_baidu_web_summary(
    url: &str,
    key: &str,
    model: Option<&str>,
    instruction: Option<&str>,
    query: &str,
    timeout_ms: u64,
) -> Option<String> {
    let target = if url.trim().is_empty() {
        settings::DEFAULT_BAIDU_URL
    } else {
        url.trim()
    };
    let mut headers: Vec<(String, String)> = vec![("Content-Type".into(), "application/json".into())];
    if !key.is_empty() {
        headers.push(("Authorization".into(), format!("Bearer {key}")));
    }
    let mut body = json!({
        "messages": [{ "role": "user", "content": query }],
        "stream": false,
    });
    if let Some(instruction) = instruction.filter(|v| !v.is_empty()) {
        body["instruction"] = json!(instruction);
    }
    if let Some(model) = model.map(|m| m.trim()).filter(|m| !m.is_empty()) {
        body["model"] = json!(model);
    }
    let resp = match post_json(target, &headers, &body.to_string(), timeout_ms) {
        Ok(r) => r,
        Err(e) => {
            log::write_log("error", &format!("百度千帆高性能版调用异常: {e}"));
            return None;
        }
    };
    if !is_ok_status(resp.status) {
        log::write_log(
            "warn",
            &format!(
                "百度千帆高性能版返回 {}: {}",
                resp.status,
                resp.body.chars().take(200).collect::<String>()
            ),
        );
        return None;
    }
    let data: Value = serde_json::from_str(resp.body.trim()).ok()?;
    // 多路径解析：优先 OpenAI 兼容 choices；再尝试 result/answer/text；最后兜底
    if let Some(content) = data
        .get("choices")
        .and_then(|v| v.get(0))
        .and_then(|v| v.get("message"))
        .and_then(|v| v.get("content"))
        .map(js_string)
    {
        let content = content.trim().to_string();
        if !content.is_empty() {
            return Some(content);
        }
    }
    for name in ["result", "answer", "content", "text", "summary", "reply", "output"] {
        if let Some(v) = data.get(name).and_then(|v| v.as_str()) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// `callModelText`：连通性确认消息（models:save / models:test 共用）
pub(crate) fn call_model_text(key: &str, cfg: &Value, message: &str) -> Option<String> {
    let url = cfg.get("apiUrl").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let api_key = cfg.get("apiKey").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let model = cfg.get("model").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let timeout_ms = clamp_timeout(cfg.get("timeout"), 30) as u64 * 1000;
    if key == "baidu_pro" {
        return call_baidu_web_summary(
            &url,
            &api_key,
            Some(&model),
            Some(BAIDU_TEXT_INSTRUCTION),
            message,
            timeout_ms,
        );
    }
    call_openai_compat(&url, &api_key, &model, message, timeout_ms)
}

/// `buildPrompt`：模板含 {menu}/{company} 占位符则替换，否则追加菜单名与厂商名
fn build_prompt(template: &str, name: &str, company: &str) -> String {
    let p = if template.is_empty() {
        settings::AI_DEFAULT_PROMPT
    } else {
        template
    };
    if p.contains("{menu}") || p.contains("{company}") {
        return p.replace("{menu}", name).replace("{company}", company);
    }
    format!("{p}\n菜单名称：{name}，所属软件：{company}")
}

/// `callModelDescription`：按模型种类分发（百度走 AI 搜索摘要，其余走 OpenAI 兼容）
fn call_model_description(
    key: &str,
    cfg: &Value,
    name: &str,
    company: &str,
    scope_prompt: &str,
) -> Option<String> {
    let cfg_prompt = cfg
        .get("prompt")
        .map(js_string)
        .unwrap_or_default()
        .trim()
        .to_string();
    let prompt = build_prompt(
        if cfg_prompt.is_empty() { scope_prompt } else { &cfg_prompt },
        name,
        company,
    );
    let url = cfg.get("apiUrl").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let api_key = cfg.get("apiKey").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let model = cfg.get("model").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let timeout_ms = clamp_timeout(cfg.get("timeout"), 30) as u64 * 1000;
    if key == "baidu_pro" {
        return call_baidu_web_summary(
            &url,
            &api_key,
            None,
            Some(&prompt),
            &format!("名称：{name}，所属：{company}"),
            timeout_ms,
        );
    }
    call_openai_compat(&url, &api_key, &model, &prompt, timeout_ms)
}

// ==================== 缓存与百度日调用计数 ====================

fn ai_cache_file() -> PathBuf {
    settings::ai_cache_dir().join("menuDescriptions.json")
}

fn baidu_usage_file() -> PathBuf {
    settings::ai_cache_dir().join("baiduDailyUsage.json")
}

/// `loadAiCache`（损坏只当空缓存，与 JS 的 try/catch 同语义）
fn load_ai_cache() -> Value {
    match std::fs::read_to_string(ai_cache_file()) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) if v.is_object() => v,
            _ => json!({}),
        },
        Err(_) => json!({}),
    }
}

/// `saveAiCache`（失败仅记日志，不阻塞返回简介）
///
/// 写之前先淘汰（审查 v2-L13）：TTL 原来只在**读取**分支判过一次，写入侧把整表原样落盘
/// ⇒ 再也不被查询的条目永久留在文件里，「缓存 7 天」只对还会被读到的键成立。
fn save_ai_cache(cache: &Value) {
    let (pruned, removed) = prune_ai_cache(cache, crate::engine::now_ms(), AI_CACHE_TTL_MS);
    if removed > 0 {
        log::write_log("info", &format!("简介缓存已淘汰 {removed} 条过期/畸形项"));
    }
    if let Err(e) = security::atomic_write_json(&ai_cache_file(), &pruned) {
        log::write_log("error", &format!("写入简介缓存失败: {e}"));
    }
}

/// 缓存淘汰（纯函数，便于断言）：交出剔掉过期与畸形条目后的表，以及剔掉了几条。
/// 畸形（非对象条目、`timestamp` 非数）一并清掉 —— 这类件本就不该存在，
/// 留着只会一直长，且读取分支永远把它们当 miss（等于纯垃圾）。
fn prune_ai_cache(cache: &Value, now_ms: i64, ttl_ms: i64) -> (Value, usize) {
    let Some(map) = cache.as_object() else {
        return (json!({}), 0);
    };
    let mut out = serde_json::Map::new();
    let mut removed = 0usize;
    for (key, entry) in map {
        let fresh = entry
            .get("timestamp")
            .map(settings::js_number)
            .filter(|n| n.is_finite())
            .map(|ts| now_ms - (ts as i64) < ttl_ms)
            .unwrap_or(false);
        if fresh {
            out.insert(key.clone(), entry.clone());
        } else {
            removed += 1;
        }
    }
    (Value::Object(out), removed)
}

/// `todayKey`：本地日期（与 engine::log 同一本地口径，杜绝 UTC 漂移）
fn today_key() -> String {
    log::local_date_str(std::time::SystemTime::now())
}

fn load_baidu_usage() -> Value {
    match std::fs::read_to_string(baidu_usage_file()) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) if v.is_object() => v,
            _ => json!({ "date": today_key(), "count": 0 }),
        },
        Err(_) => json!({ "date": today_key(), "count": 0 }),
    }
}

fn save_baidu_usage(u: &Value) {
    let _ = security::atomic_write_json(&baidu_usage_file(), u);
}

/// `getBaiduDailyCount`：当日次数（跨日自动清零）
fn get_baidu_daily_count() -> i64 {
    let u = load_baidu_usage();
    if u.get("date").and_then(|v| v.as_str()) == Some(today_key().as_str()) {
        u.get("count")
            .map(settings::js_number)
            .filter(|n| n.is_finite())
            .unwrap_or(0.0) as i64
    } else {
        0
    }
}

/// `incrementBaiduDailyCount`
fn increment_baidu_daily_count() -> i64 {
    let mut u = load_baidu_usage();
    let today = today_key();
    if u.get("date").and_then(|v| v.as_str()) != Some(today.as_str()) {
        u["date"] = json!(today);
        u["count"] = json!(0);
    }
    let next = u
        .get("count")
        .map(settings::js_number)
        .filter(|n| n.is_finite())
        .unwrap_or(0.0) as i64
        + 1;
    u["count"] = json!(next);
    save_baidu_usage(&u);
    next
}

// ==================== 命令 ====================

/// aidesc:get — 获取条目联网简介（按全局模型；缓存 7 天；百度日限额 100）
#[tauri::command]
pub async fn aidesc_get<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    name: Option<String>,
    company: Option<String>,
    force: Option<bool>,
    scope: Option<String>,
) -> Result<Value, String> {
    guard::guard_readonly(&window)?;
    let menu_name = name.unwrap_or_default().trim().to_string();
    let vendor = company.unwrap_or_default().trim().to_string();
    if menu_name.is_empty() {
        return Ok(json!({ "success": false, "message": "缺少名称" }));
    }
    // 模块隔离：未传 scope 时按右键管理处理，保证旧调用不报错
    let scope_key = scope.unwrap_or_default();
    let scope_key = if settings::AI_SCOPES.contains(&scope_key.as_str()) {
        scope_key
    } else {
        "contextmenu".to_string()
    };
    let (scope_label, scope_prompt) = scope_meta(&scope_key);
    let force = force.unwrap_or(false);

    let result = tauri::async_runtime::spawn_blocking(move || -> Value {
        let models = models_config();
        // 统筹全局：所有模块统一使用「大模型管理」中设置的生效模型
        let engine_key = scope_engines()
            .get(GLOBAL_ENGINE_KEY)
            .and_then(|v| v.as_str())
            .unwrap_or("metaso")
            .to_string();
        let cfg = models.get(&engine_key).cloned().unwrap_or_else(|| json!({}));
        let model = cfg.get("model").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let cache = load_ai_cache();
        let cache_key = ai_cache_key(
            &menu_name,
            &vendor,
            &format!("global:{engine_key}:{model}"),
        );

        if !force {
            if let Some(hit) = cache.get(&cache_key) {
                let desc = hit.get("desc").and_then(|v| v.as_str()).unwrap_or("");
                let ts = hit
                    .get("timestamp")
                    .map(settings::js_number)
                    .filter(|n| n.is_finite())
                    .unwrap_or(0.0) as i64;
                if !desc.is_empty() && (crate::engine::now_ms() - ts) < AI_CACHE_TTL_MS {
                    let source = hit
                        .get("source")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| model_display_name(&engine_key, Some(&cfg)));
                    return json!({
                        "success": true,
                        "data": { "desc": desc, "source": source, "cached": true }
                    });
                }
            }
        }

        // 该模块所选模型未启用 → 提示前往「设置 - 大模型管理」开启，不静默切换
        if !js_truthy(cfg.get("enabled")) {
            return json!({
                "success": false,
                "message": "disabled",
                "data": { "model": model_display_name(&engine_key, Some(&cfg)) }
            });
        }
        let is_baidu = engine_key == "baidu_pro";
        if !is_baidu && cfg.get("apiUrl").and_then(|v| v.as_str()).unwrap_or("").trim().is_empty() {
            return json!({
                "success": false,
                "message": "该模型尚未填写 API 接口地址，请在「设置 - 大模型管理」中补全"
            });
        }
        // 百度千帆超当日限额时直接返回提示，不降级到其他模型（避免简介来源与选择不一致）
        if is_baidu && get_baidu_daily_count() >= BAIDU_DAILY_LIMIT {
            log::write_log("warn", &format!("百度千帆今日调用已达 {BAIDU_DAILY_LIMIT} 次上限"));
            return json!({ "success": false, "message": "百度千帆今日调用已达上限，请更换模型或明日再试" });
        }
        if is_baidu {
            increment_baidu_daily_count();
        }

        let desc = call_model_description(&engine_key, &cfg, &menu_name, &vendor, scope_prompt);
        let Some(desc) = desc else {
            log::write_log(
                "warn",
                &format!(
                    "AI 简介获取失败 [{scope_label}/{}]: {menu_name}",
                    model_display_name(&engine_key, Some(&cfg))
                ),
            );
            return json!({ "success": false, "message": "该条目暂时无法获取简介，请检查模型配置或稍后重试" });
        };

        let source = model_display_name(&engine_key, Some(&cfg));
        let mut cache = cache;
        if let Some(map) = cache.as_object_mut() {
            map.insert(
                cache_key,
                json!({ "desc": desc, "source": source, "timestamp": crate::engine::now_ms() }),
            );
        }
        save_ai_cache(&cache);
        log::write_log("info", &format!("AI 简介获取成功 [{scope_label}/{source}]: {menu_name}"));
        json!({ "success": true, "data": { "desc": desc, "source": source, "cached": false } })
    })
    .await
    .map_err(|e| format!("AI 简介任务异常: {e}"))?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MD5 口径对拍（缓存键必须与 Electron crypto.createHash('md5') 同值）
    #[test]
    fn md5_matches_known_vectors() {
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex("The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    /// 缓存键形状：MD5(名称|厂商|引擎) 32 位十六进制
    #[test]
    fn cache_key_shape() {
        let k = ai_cache_key("解压到当前文件夹", "WinRAR", "global:metaso:fast_thinking");
        assert_eq!(k.len(), 32);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ==================== 审查 v2-M7：跳转链不得在凭据发出后才发现违规 ====================

    /// 用「公网 https 端点」当基址；port/path 有意非默认，顺带验证 origin_of 不丢端口。
    fn base() -> settings::ParsedUrl {
        settings::parse_http_url("https://api.example.com:8443/v1/chat")
            .expect("基址必须可解析")
    }

    #[test]
    fn 跳回本机或内网的_location_一律拒() {
        // 这正是 v2-M7 的咬人形态：公网端点 302 → 本机服务，旧实现先把 Bearer 发出去再复检
        for loc in [
            "http://127.0.0.1:9999/",
            "http://localhost:9999/v1",
            "http://[::1]/x",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://0177.0.0.1/",          // 八进制归一化后仍是回环
            "http://[2002:7f00:1::]/",     // 6to4 内嵌 127.0.0.1
        ] {
            assert!(
                resolve_redirect(&base(), "api.example.com", loc).is_err(),
                "{loc} 必须被拒"
            );
        }
    }

    #[test]
    fn 跨主机与降级同样被拒() {
        let b = base();
        // 跨主机：把 Authorization 递给另一个服务（绝对址与协议相对写法都要拦）
        assert!(resolve_redirect(&b, "api.example.com", "https://evil.example.org/steal").is_err());
        assert!(resolve_redirect(&b, "api.example.com", "//evil.example.org/steal").is_err());
        // https → http：密钥改成明文过网
        assert!(resolve_redirect(&b, "api.example.com", "http://api.example.com:8443/v1").is_err());
        // 不可判定即 fail-closed：空 Location 与非 http 协议
        for loc in ["", "   ", "ftp://api.example.com/x"] {
            assert!(resolve_redirect(&b, "api.example.com", loc).is_err(), "{loc} 不可跟随");
        }
    }

    #[test]
    fn 同主机的合规跳转必须被接受并补全() {
        // 反向断言：闸门不得把正常的同机跳转一起拒掉（否则换域名/加尾斜杠的端点全废）
        let b = base();
        let next = resolve_redirect(&b, "api.example.com", "https://api.example.com:8443/v2/chat")
            .expect("同主机同协议的绝对址必须放行");
        assert_eq!((next.host.as_str(), next.port, next.path.as_str()), ("api.example.com", 8443, "/v2/chat"));
        // 相对形式按 RFC 9110 以基址为参照补全，补全后同样过全套判据
        let abs = resolve_redirect(&b, "api.example.com", "/v1/completions").unwrap();
        assert_eq!((abs.host.as_str(), abs.port, abs.path.as_str()), ("api.example.com", 8443, "/v1/completions"));
        let rel = resolve_redirect(&b, "api.example.com", "completions").unwrap();
        assert_eq!(rel.path, "/v1/completions");
        let proto = resolve_redirect(&b, "api.example.com", "//api.example.com:8443/v1").unwrap();
        assert_eq!((proto.host.as_str(), proto.secure), ("api.example.com", true));
    }

    #[test]
    fn 默认端口不得被写成字面量后再判成非默认() {
        // origin_of 省略默认端口：`https://host:443` 这种写法不该让跳转目标换端口
        let b = settings::parse_http_url("https://api.example.com/v1/chat").unwrap();
        assert_eq!(origin_of(&b), "https://api.example.com");
        let n = resolve_redirect(&b, "api.example.com", "/v2/chat").unwrap();
        assert_eq!(n.port, 443);
        // IPv6 基址必须带方括号回写，否则 `https://::1:443` 之类的串无从解析
        let v6 = settings::parse_http_url("https://[2606:4700:4700::1111]/v1").unwrap();
        assert_eq!(origin_of(&v6), "https://[2606:4700:4700::1111]");
    }

    // ==================== 审查 v2-L13：简介缓存只判读不淘汰 ====================

    #[test]
    fn 缓存写入前淘汰过期与畸形条目() {
        let now: i64 = 1_760_000_000_000;
        let ttl = 7 * 24 * 60 * 60 * 1000;
        let cache = json!({
            "fresh": { "desc": "d", "timestamp": now - ttl / 2 },
            "expired": { "desc": "d", "timestamp": now - ttl * 2 },
            "边界外一秒": { "desc": "d", "timestamp": now - ttl - 1 },
            "没有timestamp": { "desc": "d" },
            "时间戳不是数": { "desc": "d", "timestamp": "昨天" },
            "条目不是对象": "随便一个字符串",
        });
        let (pruned, removed) = prune_ai_cache(&cache, now, ttl);
        assert_eq!(removed, 5, "除 fresh 之外全部该被淘汰");
        let obj = pruned.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("fresh"));
        // 反向：不得把未过期条目一起清掉（清了就是每次都重新联网要简介）
        let all_fresh = json!({ "a": { "timestamp": now }, "b": { "timestamp": now - ttl + 1 } });
        let (kept, removed) = prune_ai_cache(&all_fresh, now, ttl);
        assert_eq!((removed, kept.as_object().unwrap().len()), (0, 2));
        // 非对象整表：当作空表处理，不 panic
        let (v, removed) = prune_ai_cache(&json!([]), now, ttl);
        assert_eq!((v, removed), (json!({}), 0));
    }
}