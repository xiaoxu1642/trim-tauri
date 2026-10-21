//! WinHTTP 传输层 —— **现算唯一消费者是 runtimes 安装包下载**（`commands/runtimes.rs`）
//!
//! 历史口径更正（R6b-L06）：本文件此前自述「跨域共用：runtimes 下载 / cleanup 规则库
//! 在线更新」。清理规则库的在线更新链已在 2026-10-06 整链退役（`update-source.json`
//! 的 Rust 侧引用现算为 0），所以「两条链路语义不同」那套安全边界描述已经落空，
//! 连带的 `get_text`（小体量 JSON 取文本入口）也成了一个没有调用方的 `pub`——已删。
//! **下面「安全边界」一节里凡提到「cleanup 规则库/用户自选源」的都是退役前的形状，
//! 保留是为了说明 `allow_host = None` 这支为什么还在**：今天没有任何调用方传 `None`。
//!
//! 为什么用 WinHTTP 而不是引入 HTTP crate（reqwest/ureq 等）：
//!   1) 本应用是**纯 Windows 桌面应用**（Tauri + Win32 原生引擎），WinHTTP 随系统提供，
//!      零新增第三方依赖 → 不扩大供应链攻击面、不增加产物体积（本批约定不新增 HTTP 依赖）；
//!   2) TLS 与代理全部走**系统栈**：证书校验沿用系统根证书库、代理/PAC 沿用用户系统代理设置，
//!      与企业内网/带代理环境行为一致，避免「浏览器能下、应用下不动」；
//!   3) 「跟随重定向 + 取回终点 URL」是 WinHTTP 原生能力（WINHTTP_OPTION_URL），
//!      正好承载「重定向终点 host 白名单」这一安全闸门。
//!
//! 句柄生命周期：会话/连接/请求三个句柄都必须成对 WinHttpCloseHandle；任一失败早退（含 `?`）
//! 漏关即泄漏内核对象，故统一用 RAII 包装 `WinHandle`（Drop 关句柄），覆盖所有错误路径。
//!
//! # 安全边界（现存一条链路）
//!
//! - **runtimes 安装包**：来源固定为微软域名，调用方传入 `allow_host = Some(pred)`，
//!   对**重定向终点** host 判定，不通过即中止 → 有宿主白名单。
//!   判据与**建连 host 同源**（R6b-M10）：终点 host 由 [`crack_url`] 解析，与当初连出去
//!   用的是同一份实现；此前 `url_host` 自持一套字符串切分（authority 只在 `/ ? #` 截断、
//!   **不认 `\`**），同一个 `Location` 串两套结论 ⇒ 这道闸门可被
//!   `http://evil.com\@download.microsoft.com/` 形态绕过（手写侧交出白名单里的名字，
//!   系统侧按 `\` 归一 ⇒ 实际连到 `evil.com`）。
//! - 退役链路（描述保留供对照）：**cleanup 规则库**更新源可由用户在数据目录
//!   `update-source.json` 覆盖，不能用固定宿主白名单收口，故 `allow_host = None`；
//!   该链的安全性由 ed25519 验签 + 结构校验 + 版本防降级兜底。
//! - 自定义请求头（如 `Authorization`）：值是**不可信输入**，含 CR/LF 即丢弃该条，
//!   防止把额外请求头/响应拆分行注入到 WinHTTP 的头部块里。
//! - 闸门位置（如实记）：终点 host 判定发生在 `WinHttpReceiveResponse` **之后**，
//!   所以对「非空 headers + `Some(pred)`」这个组合，凭据会先于判定出网。现算无这样的
//!   可达调用点（headers 非空时重定向策略已被收紧成 NEVER，见 `open_response`），
//!   彻底修法是把闸门挪到 `WinHttpSendRequest` 之前——属命令层与传输层共同改动，未在本批做。

use std::ffi::c_void;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Networking::WinHttp::{
    WinHttpAddRequestHeaders, WinHttpCloseHandle, WinHttpConnect, WinHttpCrackUrl, WinHttpOpen,
    WinHttpOpenRequest, WinHttpQueryDataAvailable, WinHttpQueryHeaders, WinHttpQueryOption,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WinHttpSetTimeouts, URL_COMPONENTS, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ADDREQ_FLAG_ADD, WINHTTP_ADDREQ_FLAG_REPLACE, WINHTTP_FLAG_SECURE,
    WINHTTP_OPEN_REQUEST_FLAGS, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS, WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_OPTION_URL, WINHTTP_QUERY_CONTENT_LENGTH,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
};

/// 流式读取缓冲（64KB，与迁移前 runtimes 实现一致）
const READ_CHUNK: usize = 64 * 1024;

// ==================== 句柄与工具 ====================

/// WinHTTP 句柄 RAII 包装：Drop 时 WinHttpCloseHandle；NULL 不关（NULL 本身就是失败标记）
struct WinHandle(*mut c_void);

impl WinHandle {
    /// WinHTTP 各 *Open* 失败一律返回 NULL（不存在「部分可用」的句柄），故以 NULL 判失败
    fn new(handle: *mut c_void, what: &str) -> Result<Self, String> {
        if handle.is_null() {
            Err(format!("{what}失败"))
        } else {
            Ok(Self(handle))
        }
    }

    fn raw(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for WinHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // 句柄已由 WinHTTP 分配，关掉即释放；关闭失败无处可报，忽略返回值
            let _ = unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

/// 宽字符缓冲 → String（`len` 为 API 回填的元素个数，尾部 NUL 去掉）
fn wide_str(buf: &[u16], len: u32) -> String {
    let n = (len as usize).min(buf.len());
    String::from_utf16_lossy(&buf[..n])
        .trim_end_matches('\0')
        .to_string()
}

/// 拆好的 URL（**唯一**拆解实现 = [`crack_url`]）。
#[derive(Debug)]
struct CrackedUrl {
    /// scheme 是否为 https（决定 `WINHTTP_FLAG_SECURE`）
    secure: bool,
    /// 建连与闸门**共用**的 host（小写、去首尾空白；IPv6 字面量保留方括号 ——
    /// 那既是要传给 `WinHttpConnect` 的形态，也与 `new URL(u).hostname` 同形）
    host: String,
    port: u16,
    /// 请求路径（含 query/fragment）
    path: String,
}

/// 用系统的 `WinHttpCrackUrl` 拆 URL —— 闸门判据与建连目标必须出自这一次拆解（R6b-M10）。
///
/// 为什么必须由系统来拆：`WinHttpConnect` 拿到的 host 就是这里交出的 host。
/// 若闸门另用一套手写切分，两套对同一个串可以给出不同答案。
/// 反例（本轮构造，真机实测）：`http://evil.com\@download.microsoft.com/` ——
/// 系统把 `@` 当 userinfo 分隔符，交出 host=`download.microsoft.com`；
/// 旧的手写切分（`rsplit('@')`）也交出 `download.microsoft.com`，但它在别的形态上
/// 与系统分叉（authority 不认 `\`），闸门与建连当场各说各话。
/// 另有一类形态（`\` 当 authority 终止符）不同解析器会给出不同答案，本机无法确证
/// WinHTTP 内部跟随重定向时用哪一套 ⇒ 干脆在入口拒掉含 `\` 的 URL（见下方）。
/// 两侧并成一份之后，闸门结论**必然**与建连结论一致，不再依赖我们对那个字符的猜测。
fn crack_url(url: &str) -> Result<CrackedUrl, String> {
    // 空串必须先挡死：windows 的包装把 `slice.len()` 当显式长度传给 WinHttpCrackUrl，
    // 长度为 0 时 API 按「NUL 结尾字符串」处理，而空 Vec 的指针是悬垂的 ⇒ 读越界。
    // 这条不只是卫生：`url_host` 的入参来自渲染层/响应头，空串是可达形态。
    if url.trim().is_empty() {
        return Err("下载地址为空".into());
    }
    // 含反斜杠一律拒（fail-closed）。理由不是洁癖，是解析歧义：
    // WinHttpCrackUrl 把 `@` 当 userinfo 分隔符，于是 `http://evil.com\@download.microsoft.com/`
    // 在本机被交出 host=`download.microsoft.com`（userinfo=`evil.com\`）；
    // 而 WinINet/WinHTTP 系另有把 `\` 归一成 `/` 的解析路径，同一串会给出 host=`evil.com`。
    // 「闸门与建连同源」只保证我们的判断自洽，**不保证**与 WinHTTP 内部跟随重定向时
    // 自己的解析一致 ⇒ 遇到这个字符直接拒，整类歧义就不存在了（合法 URL 本就不含 `\`）。
    if url.contains('\\') {
        return Err("下载地址含非法字符".into());
    }
    let url_w = url.encode_utf16().collect::<Vec<u16>>(); // CrackUrl 走显式长度，不需要 NUL
    let cap = url_w.len().max(1);
    let mut scheme_buf = vec![0u16; cap];
    let mut host_buf = vec![0u16; cap];
    let mut path_buf = vec![0u16; cap];
    let mut extra_buf = vec![0u16; cap];
    let mut comps = URL_COMPONENTS::default();
    comps.dwStructSize = std::mem::size_of::<URL_COMPONENTS>() as u32;
    comps.lpszScheme = windows::core::PWSTR(scheme_buf.as_mut_ptr());
    comps.dwSchemeLength = cap as u32;
    comps.lpszHostName = windows::core::PWSTR(host_buf.as_mut_ptr());
    comps.dwHostNameLength = cap as u32;
    comps.lpszUrlPath = windows::core::PWSTR(path_buf.as_mut_ptr());
    comps.dwUrlPathLength = cap as u32;
    comps.lpszExtraInfo = windows::core::PWSTR(extra_buf.as_mut_ptr());
    comps.dwExtraInfoLength = cap as u32;
    // 缓冲长度取「整条 URL 长度」作上界：任一分量都必是 URL 的子串，故不可能截断
    unsafe { WinHttpCrackUrl(&url_w, 0, &mut comps) }.map_err(|_| "下载地址无效".to_string())?;

    let scheme = wide_str(&scheme_buf, comps.dwSchemeLength);
    let secure = if scheme.eq_ignore_ascii_case("https") {
        true
    } else if scheme.eq_ignore_ascii_case("http") {
        false
    } else {
        return Err(format!("不支持的下载协议: {scheme}"));
    };
    let host = wide_str(&host_buf, comps.dwHostNameLength)
        .trim()
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err("下载地址无效".into());
    }
    let path = {
        let p = format!(
            "{}{}",
            wide_str(&path_buf, comps.dwUrlPathLength),
            wide_str(&extra_buf, comps.dwExtraInfoLength)
        );
        if p.is_empty() { "/".to_string() } else { p }
    };
    let port = if comps.nPort != 0 {
        comps.nPort
    } else if secure {
        443
    } else {
        80
    };
    Ok(CrackedUrl { secure, host, port, path })
}

/// URL 主机解析：实现就是 [`crack_url`]，**没有第二套**（R6b-M10）。
///
/// 名字与签名保持不变：命令层 `commands/runtimes.rs` 的「初始主机白名单」闸门也在用它，
/// 那侧与本文件的重定向终点闸门从此共用同一份拆解，不会再各说各话。
/// （旧版本这里是一套手写切分，注释还写着「等价 JS new URL(url).hostname」——两侧都不等价：
/// JS 的 hostname 对 IPv6 **保留**方括号，而这里剥掉了。）
pub fn url_host(url: &str) -> Option<String> {
    crack_url(url).ok().map(|c| c.host)
}

/// 组装自定义请求头为 WinHTTP 需要的 `Name: Value\r\n` 块。
///
/// 安全：头名/头值均不得含 CR/LF（防请求头注入与响应拆分），头名还不得含冒号；
/// 命中即**丢弃该条**（拒绝该 header），不影响其余头与本次请求。
fn build_header_block(headers: &[(String, String)]) -> Vec<u16> {
    let bad = |s: &str| s.contains(['\r', '\n']);
    let mut block = String::new();
    for (name, value) in headers {
        if name.is_empty() || bad(name) || name.contains(':') || bad(value) {
            continue;
        }
        block.push_str(name);
        block.push_str(": ");
        block.push_str(value);
        block.push_str("\r\n");
    }
    block.encode_utf16().collect()
}

/// 取请求**重定向之后**的终点 URL（WinHTTP 在 ReceiveResponse 时已完成跳转）。
/// 两次调用：先用空缓冲探出所需字节数（该次必然 FALSE，但长度已回填），再取回宽字符 URL。
/// 这是「终点 host 白名单」闸门的输入源——白名单必须校验终点，不能只看初始 URL。
pub(crate) fn query_final_url(request: *mut c_void) -> Result<String, String> {
    let mut bytes: u32 = 0;
    let _ = unsafe { WinHttpQueryOption(request, WINHTTP_OPTION_URL, None, &mut bytes) };
    if bytes == 0 {
        return Err("无法获取重定向终点的下载地址".into());
    }
    let mut buf = vec![0u16; (bytes as usize / 2) + 1];
    let mut len = (buf.len() * 2) as u32;
    unsafe {
        WinHttpQueryOption(
            request,
            WINHTTP_OPTION_URL,
            Some(buf.as_mut_ptr() as *mut c_void),
            &mut len,
        )
    }
    .map_err(|_| "无法获取重定向终点的下载地址".to_string())?;
    Ok(wide_str(&buf, len / 2))
}

// ==================== 请求准备 ====================

/// 已发送并收到响应头的请求：三个句柄由 RAII 持有，Drop 时统一关闭
struct Response {
    _session: WinHandle,
    _connect: WinHandle,
    request: WinHandle,
    /// 响应体声明长度（content-length；取不到为 0，由调用方按需兜底）
    declared: u64,
    /// 重定向终点 URL（供调用方做终点 host 判定）
    final_url: String,
}

/// 发一次 GET、读完响应头：跟随重定向（ALWAYS，含跨主机）→ 非 2xx 直接失败 →
/// 回填终点 URL 与 content-length。响应体留给调用方按需流式读取。
fn open_response(
    url: &str,
    headers: &[(String, String)],
    timeout: Duration,
) -> Result<Response, String> {
    // ---------- 拆 URL：唯一实现 crack_url（R6b-M10，闸门与建连必须同源） ----------
    let CrackedUrl { secure, host, port, path } = crack_url(url)?;

    // ---------- 会话：AUTOMATIC_PROXY = 沿用用户系统代理设置（系统栈）；限制各阶段超时避免卡死 ----------
    let agent: Vec<u16> = "Trim/3.7 (winhttp)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let session = WinHandle::new(
        unsafe {
            WinHttpOpen(
                PCWSTR(agent.as_ptr()),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            )
        },
        "初始化 WinHTTP 会话",
    )?;
    // 阶段超时（毫秒）：解析/连接沿用 15s 头寸；发送/接收用调用方给的 timeout
    // （runtimes 传 30s → 与迁移前 15/15/30/30 逐字一致）
    let phase_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let _ = unsafe { WinHttpSetTimeouts(session.raw(), 15_000, 15_000, phase_ms, phase_ms) };
    // 跟随重定向：v2-L4P-22（A-4/RPT-06）——两个维度收口：
    // ① 自定义请求头非空 ⇒ 一律 NEVER。WinHTTP 跨主机 30x 会原样重发全部请求头
    //    （含用户自配的鉴权头），而此时 allow_host 是「用户自选源」分支（None），
    //    没有任何逐跳复判；最小改法是收紧方向——带自定义头就不跟跳，30x 落到
    //    下方非 2xx 失败返回，把跳转决定权还给调用方。
    // ② headers 为空 ⇒ 维持 ALWAYS + allow_host 闸门（有 Some(host) 时每跳复判主机）。
    let policy_bytes = if headers.is_empty() {
        WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS.to_le_bytes()
    } else {
        WINHTTP_OPTION_REDIRECT_POLICY_NEVER.to_le_bytes()
    };
    unsafe {
        WinHttpSetOption(
            Some(session.raw() as *const c_void),
            WINHTTP_OPTION_REDIRECT_POLICY,
            Some(&policy_bytes),
        )
    }
    .map_err(|_| "无法设置重定向策略".to_string())?;

    let host_w: Vec<u16> = host.encode_utf16().chain(std::iter::once(0)).collect();
    let connect = WinHandle::new(
        unsafe { WinHttpConnect(session.raw(), PCWSTR(host_w.as_ptr()), port, 0) },
        "连接下载服务器",
    )?;

    let verb: Vec<u16> = "GET".encode_utf16().chain(std::iter::once(0)).collect();
    let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let flags = if secure {
        WINHTTP_FLAG_SECURE
    } else {
        WINHTTP_OPEN_REQUEST_FLAGS(0)
    };
    let request = WinHandle::new(
        unsafe {
            WinHttpOpenRequest(
                connect.raw(),
                PCWSTR(verb.as_ptr()),
                PCWSTR(path_w.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                std::ptr::null(),
                flags,
            )
        },
        "创建下载请求",
    )?;

    // ---------- 自定义请求头：AddRequestHeaders（须在 SendRequest 之前；含 CR/LF 的条已丢弃） ----------
    let header_block = build_header_block(headers);
    if !header_block.is_empty() {
        unsafe {
            WinHttpAddRequestHeaders(
                request.raw(),
                &header_block,
                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
            )
        }
        .map_err(|e| format!("设置请求头失败: {e}"))?;
    }

    unsafe { WinHttpSendRequest(request.raw(), None, None, 0, 0, 0) }
        .map_err(|e| format!("下载请求发送失败: {e}"))?;
    unsafe { WinHttpReceiveResponse(request.raw(), std::ptr::null_mut()) }
        .map_err(|e| format!("下载无响应: {e}"))?;

    // ---------- 状态码：非 2xx 直接失败 ----------
    let mut status: u32 = 0;
    let mut status_len = std::mem::size_of::<u32>() as u32;
    unsafe {
        WinHttpQueryHeaders(
            request.raw(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut status as *mut u32 as *mut c_void),
            &mut status_len,
            std::ptr::null_mut(),
        )
    }
    .map_err(|e| format!("下载失败：HTTP 状态码读取失败 ({e})"))?;
    if !(200..300).contains(&status) {
        return Err(format!("下载失败：HTTP {status}"));
    }

    // 终点 URL（闸门输入源）
    let final_url = query_final_url(request.raw())?;

    // ---------- content-length（声明值）：取不到传 0，由调用方决定兜底 ----------
    let mut declared: u32 = 0;
    let mut declared_len = std::mem::size_of::<u32>() as u32;
    let declared_ok = unsafe {
        WinHttpQueryHeaders(
            request.raw(),
            WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut declared as *mut u32 as *mut c_void),
            &mut declared_len,
            std::ptr::null_mut(),
        )
    }
    .is_ok();
    Ok(Response {
        _session: session,
        _connect: connect,
        request,
        declared: if declared_ok { declared as u64 } else { 0 },
        final_url,
    })
}

/// 终点 host 校验：`allow_host = None` 不做校验（用户自选源链路）；
/// `Some(pred)` 时对**重定向终点** host 调 pred，false 即中止。
fn check_host(
    allow_host: Option<&dyn Fn(&str) -> bool>,
    final_url: &str,
) -> Result<(), String> {
    let Some(pred) = allow_host else {
        return Ok(());
    };
    let host = url_host(final_url).ok_or_else(|| "重定向终点地址无效".to_string())?;
    if !pred(&host) {
        return Err(format!("重定向终点主机未通过来源校验: {host}"));
    }
    Ok(())
}

// ==================== 公开入口 ====================

/// 下载到文件。
///
/// - `allow_host`：为 `None` 时不做宿主校验（规则库用户自定义源）；为 `Some(pred)` 时对
///   **重定向终点** host 调 pred，false 即中止——判定发生在**建文件之前**（不留半成品）。
/// - `max_bytes`：`None` 不做尺寸上限（不推荐）；`Some(n)` 时 content-length 声明值超限
///   立即中止，且流式累计超限同样中止。
/// - `on_progress(已收字节, 预估总字节)`：总字节优先取 content-length，取不到给 0。
/// - 失败时**不删除** `dest`，由调用方负责清理半成品（各链路失败出口统一删）。
pub fn download_to_file(
    url: &str,
    dest: &Path,
    headers: &[(String, String)],
    timeout: Duration,
    max_bytes: Option<u64>,
    allow_host: Option<&dyn Fn(&str) -> bool>,
    on_progress: &mut dyn FnMut(u64, u64),
) -> Result<(), String> {
    let resp = open_response(url, headers, timeout)?;
    check_host(allow_host, &resp.final_url)?;

    let max = max_bytes.unwrap_or(u64::MAX);
    let total = resp.declared;
    if total > max {
        return Err("下载内容超过尺寸上限，已中止".into());
    }
    // ---------- 流式读取：64KB 缓冲，边写盘边累计，累计超上限同样中止 ----------
    let mut file = std::fs::File::create(dest).map_err(|e| format!("创建下载文件失败: {e}"))?;
    let mut buf = vec![0u8; READ_CHUNK];
    let mut got: u64 = 0;
    on_progress(0, total);
    loop {
        let mut avail: u32 = 0;
        unsafe { WinHttpQueryDataAvailable(resp.request.raw(), &mut avail) }
            .map_err(|e| format!("下载中断: {e}"))?;
        if avail == 0 {
            break; // 响应体读完
        }
        let want = avail.min(buf.len() as u32);
        let mut read: u32 = 0;
        unsafe {
            WinHttpReadData(
                resp.request.raw(),
                buf.as_mut_ptr() as *mut c_void,
                want,
                &mut read,
            )
        }
        .map_err(|e| format!("下载中断: {e}"))?;
        if read == 0 {
            break;
        }
        got += read as u64;
        if got > max {
            return Err("下载内容超过尺寸上限，已中止".into());
        }
        file.write_all(&buf[..read as usize])
            .map_err(|e| format!("写入下载文件失败: {e}"))?;
        on_progress(got, total);
    }
    file.flush().map_err(|e| format!("写入下载文件失败: {e}"))?;
    Ok(())
}

// `get_text`（取小体量文本响应）已随 R6b-L06 删除：它的唯一预期消费者是清理规则库的
// 在线更新链，该链 2026-10-06 整链退役后现算调用点为 0，留着就是一个「谁都在用」的假象
// 加一份需要跟着维护的第二个入口。真要用再按 `download_to_file` 的形状重新收口，
// 不要在这里恢复一个不带闸门的取文本口。

#[cfg(test)]
mod tests {
    use super::*;

    /// R6b-M10（核心断言）：**终点 host 判据与建连 host 判据必须是同一份实现**。
    ///
    /// 断的不是「url_host 自己等于自己」，而是「闸门 `check_host` 真正拿到的那个串 ==
    /// `crack_url` 交出的串（也就是 `WinHttpConnect` 要用的那个）」。
    /// 判红自证：把 `url_host` 换回旧的手写切分（`split(['/','?','#'])` + `rsplit('@')`，
    /// authority 不认 `\`）⇒ 反例向量那两条立刻分叉；把 `check_host` 改成不做 fail-closed
    /// ⇒ 拆不出 host 的向量会红。
    #[test]
    fn 终点闸门收到的_host_与建连同源() {
        let vectors = [
            "https://Download.Microsoft.com/a?b=1",
            "http://example.com:8080/x",
            "https://[::1]:8443/p",
            "http://user:pass@Host.Example.com/path",
            // 反例（审查 §2-M10）：手写侧在这里交出 download.microsoft.com，系统侧不是
            r"http://evil.com\@download.microsoft.com/",
            "http://trailing.dot.com./x",
            "not-a-url",
            "ftp://a.com/x",
            "",
        ];
        for u in vectors {
            let seen = std::cell::Cell::new(None::<String>);
            let pred = |h: &str| {
                seen.set(Some(h.to_string()));
                true
            };
            let _ = check_host(Some(&pred), u);
            match crack_url(u) {
                Ok(c) => assert_eq!(
                    seen.take().as_deref(),
                    Some(c.host.as_str()),
                    "闸门判的 host 必须逐字等于同源拆解给出的 host: {u}"
                ),
                // 拆不出来 = 交不出判定输入，必须 fail-closed 不调用判定器
                Err(_) => assert_eq!(seen.take(), None, "拆不出 host 时不得放行判定: {u}"),
            }
        }
    }

    /// 反例的正向钉法：闸门**不得**把白名单里的名字当成这个串的答案。
    ///
    /// 真机实测：系统把 `@` 当 userinfo 分隔符，于是这个串的 authority 是
    /// `evil.com\`，host 落在 `download.microsoft.com`（正是白名单里的名字）。
    /// 另一套解析（`\` 当 authority 终止符）会给出 `evil.com` —— 同一个串两种答案，
    /// 正是「两套实现」那类漏洞的温床。修法不是猜哪套对（§3-U04 无法在本机确证
    /// WinHTTP 内部跟随重定向时用哪一套），而是**整类拒**：含 `\` 的 URL 一律拒。
    /// 于是白名单名字**永远拿不到**，闸门 fail-closed。
    #[test]
    fn 反例串不得被认成白名单主机() {
        let hostile = r"http://evil.com\@download.microsoft.com/";
        let got = url_host(hostile);
        assert_ne!(
            got.as_deref(),
            Some("download.microsoft.com"),
            "又回到两套实现的漏洞形态了：终点闸门会把这条认成白名单主机"
        );
        // 整类拒：拆不出 host ⇒ 闸门侧必然 fail-closed（不放行、不调用判定器）
        assert_eq!(got, None, "含反斜杠的 URL 必须整条拒，不得交出半个 host");
        // 且结论与建连侧同串（同上一条的口径，这里点名反例本身）
        assert_eq!(
            got,
            crack_url(hostile).ok().map(|c| c.host),
            "反例串两侧又给出不同 host"
        );
    }

    /// 拆解的其余对外口径钉住：scheme/port/path 三样也只能有一份实现（建连就靠这些）。
    #[test]
    fn 拆解给出_scheme_port_path() {
        let s = crack_url("https://a.com").expect("https 必须可拆");
        assert!(s.secure && s.port == 443 && s.path == "/" && s.host == "a.com", "{s:?}");
        let h = crack_url("http://a.com").expect("http 必须可拆");
        assert!(!h.secure && h.port == 80, "非 https 默认端口必须是 80: {h:?}");
        let q = crack_url("https://a.com:8443/x?q=1").expect("带端口与 query 必须可拆");
        assert_eq!(q.port, 8443, "显式端口优先");
        // path = urlPath + extraInfo 两段拼接，query 一并带走（WinHttpOpenRequest 要整段）
        assert_eq!(q.path, "/x?q=1", "query 必须留在请求路径里，实得 {:?}", q.path);
        // host 归一小写（白名单是精确比较，大小写不一律就永远判不过）
        assert_eq!(crack_url("https://A.COM/x").unwrap().host, "a.com");
        // 非 http(s) 一律拒，不给「连出去再说」留口子
        assert!(crack_url("ftp://a.com/x").is_err(), "ftp 必须拒");
        assert!(crack_url("file://C:/windows/win.ini").is_err(), "file 必须拒");
        assert!(crack_url("").is_err(), "空串必须拒");
    }

    /// `build_header_block` 是纯函数却一直没有夹具（审查 §2-M10 附带）：
    /// CR/LF 注入必须整条丢弃，且合法条目的字节形状要逐字节钉住。
    #[test]
    fn 请求头块封住_crlf_注入且合法条目逐字节() {
        let block = build_header_block(&[("X-Test".to_string(), "ok".to_string())]);
        assert_eq!(
            String::from_utf16(&block).unwrap(),
            "X-Test: ok\r\n",
            "合法条目的块形状变了会静默改掉发出去的请求头"
        );
        // 头值里的 CR/LF：整条丢弃，不得留下半个头或一条注入头
        let evil = build_header_block(&[
            ("X-Ok".to_string(), "1".to_string()),
            ("X-Bad".to_string(), "v\r\nX-Injected: 1".to_string()),
            ("X\rBad".to_string(), "v".to_string()),
            ("N:v".to_string(), "v".to_string()),
            ("".to_string(), "v".to_string()),
        ]);
        let text = String::from_utf16(&evil).unwrap();
        assert_eq!(text, "X-Ok: 1\r\n", "只有合法那条能留下，实得: {text:?}");
        assert!(!text.contains("Injected"), "注入头不得出现在块里: {text:?}");
        // 全非法 ⇒ 空块（调用方据此连 AddRequestHeaders 都不发）
        assert!(build_header_block(&[("A\r".to_string(), "b".to_string())]).is_empty());
        assert!(build_header_block(&[]).is_empty());
    }

    /// 真机探针（**只读联网**，微软域名，不落盘、不碰第三方主机）：
    /// 验证真实重定向链上「闸门收到的 host」与「终点 URL 的同源拆解」仍是同一个串，
    /// 并把终点交回给调用方（`query_final_url` 走的是 WINHTTP_OPTION_URL）。
    ///
    /// 为什么需要它：单测里两侧同源是靠同一份代码保证的，但**真实跳转**给出的
    /// `final_url` 形态（大小写、是否带端口、是否带尾点）只有联网才看得见；
    /// 审查 §3-U04 遗留的「`\` 是否被当成 authority 终止符」也只能在真机侧观察，
    /// 这里刻意不构造任何指向非白名单主机的请求。
    /// 只跑档位：`cargo test --lib -- --ignored`（发布前门禁；无网络时按失败处理，
    /// 由跑的人判是不是环境问题）。
    #[test]
    #[ignore = "真实联网（只读微软域名响应头），发布前门禁跑"]
    fn 真机_终点_host_与建连同源() {
        let url = "https://download.microsoft.com/";
        let resp = open_response(url, &[], Duration::from_secs(15)).expect("真实请求应拿到响应头");
        let gate_host = url_host(&resp.final_url).expect("终点 URL 必须能拆出 host");
        let connect_side = crack_url(&resp.final_url).expect("终点 URL 必须能同源拆解").host;
        assert_eq!(
            gate_host, connect_side,
            "真实终点上闸门 host 与建连 host 分叉: {gate_host} vs {connect_side}"
        );
        assert!(
            !gate_host.contains('@') && !gate_host.contains('\\'),
            "host 串里不该再有 userinfo 或反斜杠（那正是两套实现分叉的位置）: {gate_host}"
        );
        println!("终点 URL={} / host={gate_host}", resp.final_url);
    }
}


