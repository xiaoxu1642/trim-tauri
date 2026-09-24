//! WinHTTP 传输层（跨域共用：runtimes 安装包下载 / cleanup 规则库在线更新）
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
//! # 安全边界（两条链路语义不同，务必分清）
//!
//! - **runtimes 安装包**：来源固定为微软域名，调用方传入 `allow_host = Some(pred)`，
//!   对**重定向终点** host 判定，不通过即中止 → 有宿主白名单。
//! - **cleanup 规则库**：更新源可由用户在数据目录 `update-source.json` 覆盖（用户自选源），
//!   不能用固定的宿主白名单收口，故 `allow_host = None`；这条链路的安全性由
//!   **ed25519 验签 + JSON 结构校验 + 版本防降级**（见 `commands/cleanup.rs::validate_remote_rules`）
//!   兜底——即「传输可去任意源，但内容必须凭内置公钥签名通过才算数」。
//! - 自定义请求头（如 `Authorization`）：值是**不可信输入**，含 CR/LF 即丢弃该条，
//!   防止把额外请求头/响应拆分行注入到 WinHTTP 的头部块里。

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
    WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS, WINHTTP_OPTION_URL, WINHTTP_QUERY_CONTENT_LENGTH,
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

/// URL 主机解析（等价 JS `new URL(url).hostname`：去 userinfo / 端口 / IPv6 方括号，小写）
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if host_port.starts_with('[') {
        // IPv6 字面量 [::1]:80
        host_port.split(']').next()?.trim_start_matches('[')
    } else {
        host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port)
    };
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
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
    // ---------- 拆 URL（WinHttpCrackUrl）：scheme → 是否 TLS；host/port/path → Connect/OpenRequest ----------
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
    let host = wide_str(&host_buf, comps.dwHostNameLength);
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
    // 跟随重定向：ALWAYS 允许跳转（含跨主机），终点由调用方的 allow_host 闸门收口
    let policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS.to_le_bytes();
    unsafe {
        WinHttpSetOption(
            Some(session.raw() as *const c_void),
            WINHTTP_OPTION_REDIRECT_POLICY,
            Some(&policy),
        )
    }
    .map_err(|_| "无法启用重定向跟随".to_string())?;

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

/// 取文本响应（小体量，如规则库 JSON）。
///
/// `max_bytes` 为响应体上限：content-length 声明值超限或流式累计超限均中止（防超大响应拖垮内存）。
/// `on_progress(已收字节, 预估总字节)`：总字节取自 content-length，取不到给 0（调用方可据此不报进度）。
/// 返回 UTF-8 文本（非法字节按替换符处理，与 Node `resp.text()` 同口径；
/// 规则库的真实性由调用方的 ed25519 验签兜底，不依赖解码结果）。
pub fn get_text(
    url: &str,
    headers: &[(String, String)],
    timeout: Duration,
    max_bytes: u64,
    allow_host: Option<&dyn Fn(&str) -> bool>,
    on_progress: &mut dyn FnMut(u64, u64),
) -> Result<String, String> {
    let resp = open_response(url, headers, timeout)?;
    check_host(allow_host, &resp.final_url)?;
    if resp.declared > max_bytes {
        return Err("响应内容超过尺寸上限，已中止".into());
    }

    let mut out: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut got: u64 = 0;
    on_progress(0, resp.declared);
    loop {
        let mut avail: u32 = 0;
        unsafe { WinHttpQueryDataAvailable(resp.request.raw(), &mut avail) }
            .map_err(|e| format!("下载中断: {e}"))?;
        if avail == 0 {
            break;
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
        if got > max_bytes {
            return Err("响应内容超过尺寸上限，已中止".into());
        }
        out.extend_from_slice(&buf[..read as usize]);
        on_progress(got, resp.declared);
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

