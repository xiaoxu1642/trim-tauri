//! Electron safeStorage 兼容层（迁移方案 D5 / R12）
//!
//! # Phase 0 第 6 项实测结论（2026-09-23，Electron 44.1.1 / Chromium 152）
//!
//! 原方案 D5 假设 Windows 侧仅为「dpapi:v1: + 裸 DPAPI」，实测 Electron 44 已随
//! Chromium OSCrypt 升级为「DPAPI 保护主密钥 + AES-256-GCM」结构：
//!
//! **主密钥**（每个 Electron 用户数据目录一份）：
//! ```text
//! <userData>/Local State (JSON) → os_crypt.encrypted_key
//! = base64( b"DPAPI" + CryptProtectData(32 字节 AES 主密钥) )
//! ```
//!
//! **密文**（settings.json 中的 `dpapi:v1:` 值）：
//! ```text
//! b"dpapi:v1:" + base64( b"v10" + nonce(12) + AES_256_GCM(明文) + tag(16) )
//! GCM 的 AAD 为空（Chromium 152 实测；曾假设为 b"v10"，对拍证伪）
//! ```
//!
//! 兼容旧版：剥掉 `v10` 后若直接以 DPAPI BLOB 魔数
//! （01 00 00 00 d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb）开头，
//! 说明是老 Electron 的「v10 + 裸 DPAPI」，无需主密钥直接 CryptUnprotectData。
//!
//! 迁移含义（需回写方案 D5）：数据迁移必须一并搬运/读取旧目录的
//! `Local State` 内 os_crypt 主密钥；取不到主密钥时 GCM 密文无法解密，
//! 按 D5 原失败语义处理（掩码=未配置、提示重填、绝不阻塞其余设置）。

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    CRYPT_INTEGER_BLOB,
};

/// Electron safeStorage 存储前缀
pub const DPAPI_V1_PREFIX: &str = "dpapi:v1:";
/// Chromium OSCrypt 加密版本前缀（Windows 新版 GCM 与旧版裸 DPAPI 共用）
const OSCRYPT_V10: &[u8] = b"v10";
/// Local State 中 encrypted_key 的 5 字节标签
const DPAPI_KEY_TAG: &[u8] = b"DPAPI";
/// 裸 DPAPI BLOB 固定魔数（DATA_BLOB Version=1 + 固定 GUID d08c9ddf-11d1-...）
const DPAPI_BLOB_MAGIC: [u8; 16] = [
    0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00,
    0xc0,
];
const AES_KEY_LEN: usize = 32;
const GCM_NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

#[derive(Debug)]
pub enum StorageError {
    /// 不是 dpapi:v1: 前缀（调用方应按「非密文」处理）
    BadPrefix,
    Base64(String),
    /// 内层不是 v10
    UnsupportedVersion(String),
    /// GCM 密文但未提供主密钥
    MissingKey,
    /// Local State / 主密钥格式不合法
    KeyFormat(String),
    Aes(String),
    Win(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::BadPrefix => write!(f, "缺少 {DPAPI_V1_PREFIX} 前缀"),
            StorageError::Base64(e) => write!(f, "base64 解码失败: {e}"),
            StorageError::UnsupportedVersion(v) => write!(f, "不支持的 OSCrypt 版本前缀: {v}"),
            StorageError::MissingKey => write!(f, "AES-GCM 密文缺少 OSCrypt 主密钥"),
            StorageError::KeyFormat(e) => write!(f, "Local State 主密钥格式错误: {e}"),
            StorageError::Aes(e) => write!(f, "AES-GCM 解密失败: {e}"),
            StorageError::Win(e) => write!(f, "CryptUnprotectData 失败: {e}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// CryptUnprotectData 薄封装：无 entropy（与 Chromium DPAPI 调用口径一致）。
pub fn crypt_unprotect(input: &[u8]) -> Result<Vec<u8>, StorageError> {
    unsafe {
        let input_blob = CRYPT_INTEGER_BLOB {
            cbData: input.len() as u32,
            pbData: input.as_ptr() as *mut _,
        };
        let mut output_blob = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(
            &input_blob,
            None::<*mut PWSTR>,
            None,
            None,
            None,
            0,
            &mut output_blob,
        )
        .map_err(|e| StorageError::Win(e.to_string()))?;

        let len = output_blob.cbData as usize;
        let mut plain = Vec::<u8>::with_capacity(len);
        std::ptr::copy_nonoverlapping(output_blob.pbData as *const u8, plain.as_mut_ptr(), len);
        plain.set_len(len);
        let _ = LocalFree(Some(HLOCAL(output_blob.pbData as *mut _)));
        Ok(plain)
    }
}

/// 从 Local State JSON 文本提取并 DPAPI 解密 OSCrypt AES 主密钥（32 字节）。
pub fn load_oscrypt_key_from_local_state(local_state_json: &str) -> Result<Vec<u8>, StorageError> {
    let root: serde_json::Value =
        serde_json::from_str(local_state_json).map_err(|e| StorageError::KeyFormat(e.to_string()))?;
    let wrapped_b64 = root
        .get("os_crypt")
        .and_then(|v| v.get("encrypted_key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| StorageError::KeyFormat("缺少 os_crypt.encrypted_key".into()))?;
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(wrapped_b64.trim())
        .map_err(|e| StorageError::KeyFormat(e.to_string()))?;
    let dpapi_blob = wrapped
        .strip_prefix(DPAPI_KEY_TAG)
        .ok_or_else(|| StorageError::KeyFormat("encrypted_key 缺少 DPAPI 标签".into()))?;
    let key = crypt_unprotect(dpapi_blob)?;
    if key.len() != AES_KEY_LEN {
        return Err(StorageError::KeyFormat(format!(
            "主密钥长度应为 {AES_KEY_LEN}，实际 {}",
            key.len()
        )));
    }
    Ok(key)
}

/// AES-256-GCM 打开 v10 密文体（不含 v10 前缀）。
/// Phase 0 实测（Chromium 152）：AAD 为空。
fn aes_gcm_open(key: &[u8], body: &[u8]) -> Result<Vec<u8>, StorageError> {
    if body.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
        return Err(StorageError::KeyFormat("GCM 密文体过短".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| StorageError::Aes(e.to_string()))?;
    let nonce = Nonce::from_slice(&body[..GCM_NONCE_LEN]);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &body[GCM_NONCE_LEN..],
                aad: b"",
            },
        )
        .map_err(|e| StorageError::Aes(e.to_string()))
}

/// 定位并解密本机 OSCrypt 主密钥：按 `engine::paths::local_state_candidates()`
/// 依次尝试（新数据目录搬迁副本 → 旧 Electron 目录），取第一个成功的。
/// 供 settings 域解密遗留 `dpapi:v1:` 密钥；全部失败时调用方按「未配置」处理（D5 语义）。
pub fn load_oscrypt_key() -> Result<Vec<u8>, StorageError> {
    let mut last_err = StorageError::KeyFormat("未找到 Local State".into());
    for path in crate::engine::paths::local_state_candidates() {
        match std::fs::read_to_string(&path) {
            Ok(text) => match load_oscrypt_key_from_local_state(&text) {
                Ok(key) => return Ok(key),
                Err(e) => last_err = e,
            },
            Err(e) => last_err = StorageError::KeyFormat(format!("{}: {e}", path.display())),
        }
    }
    Err(last_err)
}

/// CryptProtectData 薄封装：无 entropy、`CRYPTPROTECT_UI_FORBIDDEN`
/// （与 Chromium OSCrypt 同口径：绝不弹凭据 UI，失败即失败）。
pub fn crypt_protect(input: &[u8]) -> Result<Vec<u8>, StorageError> {
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    unsafe {
        let input_blob = CRYPT_INTEGER_BLOB {
            cbData: input.len() as u32,
            pbData: input.as_ptr() as *mut _,
        };
        let mut output_blob = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(
            &input_blob,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output_blob,
        )
        .map_err(|e| StorageError::Win(e.to_string()))?;

        let len = output_blob.cbData as usize;
        let mut protected = Vec::<u8>::with_capacity(len);
        std::ptr::copy_nonoverlapping(output_blob.pbData as *const u8, protected.as_mut_ptr(), len);
        protected.set_len(len);
        let _ = LocalFree(Some(HLOCAL(output_blob.pbData as *mut _)));
        Ok(protected)
    }
}

/// 12 字节 GCM nonce（系统首选 RNG；`BCryptGenRandom` 无需建句柄）
fn random_nonce() -> Result<[u8; GCM_NONCE_LEN], StorageError> {
    let mut nonce = [0u8; GCM_NONCE_LEN];
    let status = unsafe {
        BCryptGenRandom(None, &mut nonce, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    if status.0 != 0 {
        return Err(StorageError::Win(format!(
            "BCryptGenRandom 失败: 0x{:08X}",
            status.0 as u32
        )));
    }
    Ok(nonce)
}

/// AES-256-GCM 封装 v10 密文体（不含 v10 前缀，AAD 为空，与解密侧同口径）
fn aes_gcm_seal(key: &[u8], nonce: &[u8], plain: &[u8]) -> Result<Vec<u8>, StorageError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| StorageError::Aes(e.to_string()))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plain,
                aad: b"",
            },
        )
        .map_err(|e| StorageError::Aes(e.to_string()))
}

/// 加密明文密钥为 `dpapi:v1:` 值（**绝不明文落盘**）。
///
/// - 有 OSCrypt 主密钥（Local State 的 `os_crypt.encrypted_key`）→
///   `v10` + nonce(12) + AES-256-GCM，与 Electron 44 `safeStorage.encryptString` 同格式；
/// - 无主密钥（干净 Tauri 安装）→ `v10` + 裸 DPAPI BLOB，即**旧 Electron 的既有格式**，
///   Electron 与本项目两侧都能读（`decrypt_dpapi_v1` 自动识别）。
///
/// 空串返回空串（与 JS `encryptSecret` 一致：空值 = 未配置，不加密）。
pub fn encrypt_dpapi_v1(plain: &str, aes_key: Option<&[u8]>) -> Result<String, StorageError> {
    if plain.is_empty() {
        return Ok(String::new());
    }
    let mut body: Vec<u8> = OSCRYPT_V10.to_vec();
    match aes_key {
        Some(key) if key.len() == AES_KEY_LEN => {
            let nonce = random_nonce()?;
            body.extend_from_slice(&nonce);
            body.extend_from_slice(&aes_gcm_seal(key, &nonce, plain.as_bytes())?);
        }
        _ => body.extend_from_slice(&crypt_protect(plain.as_bytes())?),
    }
    Ok(format!(
        "{DPAPI_V1_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(body)
    ))
}

/// 解密 settings.json 中的 `dpapi:v1:` 值。
///
/// - 新格式（Chromium OSCrypt GCM）必须传 `aes_key`（来自 Local State）；
/// - 旧格式（v10 + 裸 DPAPI）不需要密钥。
pub fn decrypt_dpapi_v1(value: &str, aes_key: Option<&[u8]>) -> Result<Vec<u8>, StorageError> {
    let b64 = value
        .strip_prefix(DPAPI_V1_PREFIX)
        .ok_or(StorageError::BadPrefix)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| StorageError::Base64(e.to_string()))?;
    let body = decoded
        .strip_prefix(OSCRYPT_V10)
        .ok_or_else(|| StorageError::UnsupportedVersion("缺少 v10 前缀".into()))?;

    if body.starts_with(&DPAPI_BLOB_MAGIC) {
        // 旧 Electron：v10 后即裸 DPAPI BLOB
        return crypt_unprotect(body);
    }

    // 新 Electron（44 实测）：v10 + nonce + GCM
    let key = aes_key.ok_or(StorageError::MissingKey)?;
    if key.len() != AES_KEY_LEN {
        return Err(StorageError::KeyFormat(format!(
            "主密钥长度应为 {AES_KEY_LEN}，实际 {}",
            key.len()
        )));
    }
    aes_gcm_open(key, body)
}
