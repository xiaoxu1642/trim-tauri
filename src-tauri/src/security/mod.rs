//! 配置写入与密钥处理（对照 src/main/security.js）
//!
//! - `atomic_write_*`：临时文件 + 随机后缀 + fsync + rename（审查 L-5 的 4 字节随机后缀
//!   防同进程同毫秒并发写撞名导致 rename 覆盖）；
//! - `quarantine_file`：配置损坏先改名 `.corrupt-<ts>` 保留现场，再降级返回默认值——
//!   防止下一次保存直接覆盖损坏文件，事后可分析断电/磁盘错误根因（审查 4-1）；
//! - 密钥：`dpapi:v1:` 经 OSCrypt 主密钥解密；**绝不明文落盘**；发往渲染层前统一掩码，
//!   空值保持空串（表示未配置，不伪装成已配置），幂等（掩码重复调用结果不变）。

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::safestorage;

/// 密钥掩码（与渲染层 API_KEY_MASK 同值）
pub const SECRET_MASK: &str = "••••••••";

/// 需加密/脱敏的字段名（与 JS 侧 SECRET_FIELDS 同源）
pub const SECRET_FIELDS: &[&str] = &[
    "apiKey",
    "aiApiKey",
    "baiduApiKey",
    "metasoApiKey",
    "zhihuApiKey",
    "zhihuAccessSecret",
];

static WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

fn random_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    // 取纳秒低位 + 自增序号 + pid 混合，等价 JS 侧 randomBytes(4) 的唯一性目的
    format!("{:x}{:x}{:x}", nanos & 0xffff_ffff, seq, pid)
}

/// 原子写文件：temp（同目录）→ fsync → rename 覆盖；失败清理临时件
pub fn atomic_write_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or_else(|| "无效路径".to_string())?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let temp = dir.join(format!(".{name}.{}.tmp", random_suffix()));
    let result = (|| -> Result<(), String> {
        let mut f = File::create(&temp).map_err(|e| e.to_string())?;
        f.write_all(contents).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        fs::rename(&temp, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// 原子写 JSON（2 空格缩进，与 JS 侧 JSON.stringify(v, null, 2) 一致）
pub fn atomic_write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    atomic_write_file(path, text.as_bytes())
}

/// 读取 JSON 配置；损坏时先隔离再返回默认空对象（审查 4-1）
pub fn read_json_or_quarantine(path: &Path) -> serde_json::Value {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) if v.is_object() => v,
            Ok(_) => serde_json::json!({}),
            Err(e) => {
                quarantine_file(path, &e.to_string());
                serde_json::json!({})
            }
        },
        Err(_) => serde_json::json!({}),
    }
}

/// 配置文件损坏隔离：改名 `<file>.corrupt-<ts>` 保留现场
pub fn quarantine_file(path: &Path, reason: &str) {
    if !path.exists() {
        return;
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let bak: PathBuf = path.with_file_name(format!("{name}.corrupt-{ts}"));
    if fs::rename(path, &bak).is_ok() {
        crate::engine::log::write_log(
            "error",
            &format!("配置文件损坏已隔离: {name} -> {} ({reason})", bak.file_name().unwrap_or_default().to_string_lossy()),
        );
    }
}

/// 递归把 SECRET_FIELDS 字段做变换（对齐 transformSecrets）
pub fn transform_secrets(
    value: &serde_json::Value,
    transform: &dyn Fn(&str) -> String,
) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let new_v = if SECRET_FIELDS.contains(&k.as_str()) {
                    match v {
                        serde_json::Value::String(s) => {
                            serde_json::Value::String(transform(s))
                        }
                        other => transform_secrets(other, transform),
                    }
                } else {
                    transform_secrets(v, transform)
                };
                out.insert(k.clone(), new_v);
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items.iter().map(|i| transform_secrets(i, transform)).collect(),
        ),
        other => other.clone(),
    }
}

/// 发往渲染层前的统一脱敏出口（掩码即未修改语义；空值保持空串）
pub fn mask_settings(settings: &serde_json::Value) -> serde_json::Value {
    transform_secrets(settings, &|v| {
        if v.is_empty() {
            String::new()
        } else {
            SECRET_MASK.to_string()
        }
    })
}

/// 加密出口（对照 JS `encryptSettings`）：把 SECRET_FIELDS 内**非空字符串**字段加密为
/// `dpapi:v1:` 密文；空值保持空串（= 未配置，与 JS `encryptSecret` 同语义）。
///
/// 与 JS 的差异只在**密钥来源**：JS 由 Electron safeStorage 提供 OSCrypt 主密钥；
/// 这里读 Local State 的 `os_crypt.encrypted_key`，拿不到时回落旧版「v10 + 裸 DPAPI」
/// 密文——两条路都绝不明文落盘，且 Electron 侧均可解（见 safestorage.rs）。
/// 加密失败（CryptProtectData 不可用）时返回 Err，调用方按 Electron 的
/// 「safeStorage 不可用 → 拒绝保存」同语义回 `success:false`。
pub fn encrypt_settings_with_oscrypt(settings: &serde_json::Value) -> Result<serde_json::Value, String> {
    let key = safestorage::load_oscrypt_key().ok();
    encrypt_secrets(settings, key.as_deref())
}

fn encrypt_secrets(
    value: &serde_json::Value,
    key: Option<&[u8]>,
) -> Result<serde_json::Value, String> {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let new_v = if SECRET_FIELDS.contains(&k.as_str()) {
                    match v {
                        serde_json::Value::String(s) => serde_json::Value::String(
                            safestorage::encrypt_dpapi_v1(s, key).map_err(|e| e.to_string())?,
                        ),
                        other => encrypt_secrets(other, key)?,
                    }
                } else {
                    encrypt_secrets(v, key)?
                };
                out.insert(k.clone(), new_v);
            }
            Ok(serde_json::Value::Object(out))
        }
        serde_json::Value::Array(items) => Ok(serde_json::Value::Array(
            items
                .iter()
                .map(|i| encrypt_secrets(i, key))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        other => Ok(other.clone()),
    }
}

/// 解密一组遗留 dpapi:v1: 密钥（供 settings 域迁移使用；主密钥取不到时按未配置回落空串）
pub fn decrypt_settings_with_oscrypt(settings: &serde_json::Value) -> serde_json::Value {
    let key = safestorage::load_oscrypt_key().ok();
    transform_secrets(settings, &|v| {
        if !v.starts_with(safestorage::DPAPI_V1_PREFIX) {
            return v.to_string();
        }
        match key.as_deref() {
            Some(k) => safestorage::decrypt_dpapi_v1(v, Some(k))
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default(),
            None => String::new(),
        }
    })
}