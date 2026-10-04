//! Authenticode 签名主体读取（v0.5.0 只读扫描器的判据件）。
//!
//! 为什么需要它：方案 §3 的 `drivers_orphan` 判据是「没有服务引用 **且** 非微软签名 = 孤儿」。
//! 微软组件与第三方组件的边界只能从证书主体读，路径猜测（「在 System32 里就是系统的」）
//! 会把厂商驱动当成系统件、把系统件当成残留，两种错都不可接受。
//!
//! 只做**读取**，不做信任判定（不调 `WinVerifyTrust`）：本阶段是只读报告，
//! 需要回答的是「这个文件是谁签的」，不是「这个签名现在还可不可信」。
//! 读不到即返回 None，调用方必须当成**无证据**（不产候选），不能当成「没签名」。

use super::helpers::to_wide;
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_CERT, CERT_QUERY_CONTENT_FLAG_ALL,
    CERT_QUERY_CONTENT_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CertCloseStore,
    CertEnumCertificatesInStore, CertFreeCertificateContext, CertGetNameStringW, CryptQueryObject, HCERTSTORE,
};

/// 微软代码签名主体前缀（三种都见过：系统件、产品件、企业件）
const MICROSOFT_SUBJECTS: &[&str] = &["microsoft windows", "microsoft corporation", "msringsdk"];

/// 取文件内嵌签名证书的主体简单显示名。
///
/// `None` = 读不出（未签名、不是 PE、文件打不开、证书结构不认识）。
/// 对 `%SystemRoot%\System32\drivers` 整目录做批量调用是秒级的，所以调用方
/// 要先用便宜的条件（服务引用反查）筛出少数文件，再逐个问签名。
pub(super) unsafe fn signer_subject(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let wide = to_wide(path);
    let mut store = HCERTSTORE(std::ptr::null_mut());
    let mut ctx: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut content = CERT_QUERY_CONTENT_TYPE(0);
    let queried = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        wide.as_ptr() as *const std::ffi::c_void,
        CERT_QUERY_CONTENT_FLAG_ALL,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        None,
        Some(&mut content),
        None,
        Some(&mut store),
        None,
        Some(&mut ctx),
    )
    .is_ok();
    if !queried {
        if !store.0.is_null() {
            let _ = CertCloseStore(Some(store), 0);
        }
        return None;
    }
    // 两条取出证书的路径：PE 内嵌证书直接给 CERT_CONTEXT，
    // PKCS#7 内嵌形态则把证书放进 store，需要枚举第一条。
    let cert: *const CERT_CONTEXT = if content == CERT_QUERY_CONTENT_CERT && !ctx.is_null() {
        ctx as *const CERT_CONTEXT
    } else {
        CertEnumCertificatesInStore(store, None) as *const CERT_CONTEXT
    };
    let name = subject_of(cert);
    if !cert.is_null() {
        // 返回值是 BOOL（失败不影响我们：随后 CertCloseStore 会收掉整棵 store）
        let _ = CertFreeCertificateContext(Some(cert));
    }
    if !store.0.is_null() {
        let _ = CertCloseStore(Some(store), 0);
    }
    name
}

/// 主体简单显示名（第一次调用传空缓冲取长度，第二次取值）。
unsafe fn subject_of(cert: *const CERT_CONTEXT) -> Option<String> {
    if cert.is_null() {
        return None;
    }
    let need = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) as usize;
    if need <= 1 {
        return None;
    }
    let mut buf = vec![0u16; need];
    let got = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf)) as usize;
    if got == 0 || got > buf.len() {
        return None;
    }
    let s = String::from_utf16_lossy(&buf[..got]).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// 是否微软签名（读不到签名一律 false —— 调用方拿到 false 只代表「不是微软件」，
/// 拿到的是「查过且主体不是微软」，判孤儿前还要自己确认签名确实读到了）。
pub(super) unsafe fn is_microsoft_signed(path: &str) -> bool {
    signer_subject(path)
        .map(|s| {
            let l = s.to_lowercase();
            MICROSOFT_SUBJECTS.iter().any(|m| l.starts_with(m))
        })
        .unwrap_or(false)
}

/// 报告里给人看的签名主体行：读不到时如实说读不到，不留空（空会被读成「未签名」）。
pub(super) unsafe fn signer_label(path: &str) -> String {
    match signer_subject(path) {
        Some(s) => s,
        None => "读不出（未签名或证书结构不认识）".to_string(),
    }
}
