//! Phase 0 第 6 项 / D5 / R12：safeStorage 兼容读验证（默认 ignore，发布前门禁性质）。
//!
//! 运行方式：
//!   $env:TRIM_DPAPI_SAMPLE="<dpapi-final.json>"; cargo test --test safestorage_compat -- --ignored --nocapture
//!   （审查 v2-L19：这里原先写的是 `--test dpapi_compat`，本仓没有那个 target，照抄会报
//!    "no test target named"——文件名 `safestorage_compat` 才是真源。）
//!
//! 样本 JSON：
//!   {
//!     "plain"/"plain2": 探针明文（含中文）,
//!     "electron1"/"electron2": "dpapi:v1:base64(v10+nonce+GCM)",  // 见下方「样本来源与边界」
//!     "encryptedKeyB64": Local State 的 os_crypt.encrypted_key,   // DPAPI 包裹的 AES 主密钥
//!     "dotnetRawB64": 裸 DPAPI 密文 base64                         // 跨实现对拍
//!   }
//!
//! 断言：
//! 1. 从 Local State 解出 32 字节 OSCrypt 主密钥；
//! 2. 主密钥 + AES-256-GCM 解开两条 v10 密文，明文逐字节一致（`safestorage.rs:138` 记的
//!    Phase 0 实测是 **AAD 为空**，不是本文件以前写的 "AAD=v10"）；
//! 3. 无主密钥时必须明确报 `MissingKey`，不许胡乱尝试；
//! 4. .NET ProtectedData 裸 DPAPI 可直接解，证明 DPAPI 层跨实现同口径。
//!
//! 样本来源与边界（2026-09-29 首次实跑通过，别再把它当"未验证"）：
//! - `encryptedKeyB64` 取本机 `%APPDATA%\com.xiaoxu.trim\Local State` 的
//!   `os_crypt.encrypted_key`，是 Chromium 系自己 DPAPI 包裹出来的真实密钥材料；
//!   .NET `ProtectedData::Unprotect` 解出 32 字节后用它加密两条 GCM 密文。
//! - 密文由 **.NET（PowerShell 7 的 `AesGcm`）** 产出，不是 Electron 进程的字节：本机
//!   `%APPDATA%\Trim` 只剩两个备份目录，Electron 时代没有任何 `dpapi:v1:` 存量密文可取。
//!   所以这条证明的是「DPAPI + AES-256-GCM(v10 前缀、空 AAD、nonce||ct||tag 布局) 能被
//!   独立实现正确读写」，**不等于**"已对着 Electron 44 产物验证过"。真机若拿到真实的
//!   Electron 密文，把它替进 electron1/electron2 再跑一次即可，断言不用改。
//! - 复现样本：pwsh 7 脚本读 Local State → 剥 5 字节 `DPAPI` 前缀 → ProtectedData::Unprotect
//!   → AesGcm(nonce 12B, 空 AAD) 加密 → `v10 + nonce + ct + tag` base64 加 `dpapi:v1:` 前缀。
//!   样本含真实主密钥的 DPAPI 包裹串与明文探针，只写 `%TEMP%\trim-dpapi-probe\`，用完删。

use base64::Engine;
use trim_tauri_lib::safestorage::{
    crypt_unprotect, decrypt_dpapi_v1, load_oscrypt_key_from_local_state,
};

#[test]
#[ignore = "依赖本机真实密文样本，仅 Phase 0 验证与发布前手动跑"]
fn decrypts_electron44_oscrypt_and_dotnet_dpapi() {
    let sample_path =
        std::env::var("TRIM_DPAPI_SAMPLE").expect("需设置 TRIM_DPAPI_SAMPLE 指向样本 JSON");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sample_path).unwrap()).unwrap();

    // 1) 主密钥：样本里存的是 encrypted_key 原文，套一层 Local State JSON 走正式解析路径
    let encrypted_key_b64 = json["encryptedKeyB64"].as_str().unwrap();
    let local_state = serde_json::json!({ "os_crypt": { "encrypted_key": encrypted_key_b64 } });
    let key = load_oscrypt_key_from_local_state(&local_state.to_string())
        .unwrap_or_else(|e| panic!("OSCrypt 主密钥解析失败: {e}"));
    assert_eq!(key.len(), 32, "AES 主密钥必须 32 字节");
    println!("[key] Local State → DPAPI → AES 主密钥（{} 字节）", key.len());

    // 2) Electron 44 GCM 密文 ×2
    for (field, plain_field) in [("electron1", "plain"), ("electron2", "plain2")] {
        let cipher = json[field].as_str().unwrap();
        let plain = json[plain_field].as_str().unwrap();
        let got = decrypt_dpapi_v1(cipher, Some(key.as_slice()))
            .unwrap_or_else(|e| panic!("{field} 解密失败: {e}"));
        assert_eq!(got, plain.as_bytes(), "{field} 明文不一致");
        println!("[{field}] AES-256-GCM 解密成功（{} 字节明文）", plain.len());
    }

    // 3) 无主密钥时 GCM 密文必须明确报 MissingKey，而不是胡乱尝试
    let err = decrypt_dpapi_v1(json["electron1"].as_str().unwrap(), None)
        .expect_err("GCM 密文无密钥应报错");
    assert!(
        matches!(err, trim_tauri_lib::safestorage::StorageError::MissingKey),
        "应报 MissingKey，实际: {err:?}"
    );

    // 4) .NET 裸 DPAPI 对拍
    let dotnet_blob = base64::engine::general_purpose::STANDARD
        .decode(json["dotnetRawB64"].as_str().unwrap())
        .unwrap();
    let dotnet_plain = crypt_unprotect(&dotnet_blob).unwrap_or_else(|e| panic!("dotnet 解密失败: {e}"));
    assert_eq!(dotnet_plain, json["plain"].as_str().unwrap().as_bytes());
    println!("[dotnet] 裸 DPAPI 跨实现解密成功");
}

// 审查 v2-F18：这条是**纯内存、零外部依赖**的结构性断言（体内只有一次
// `decrypt_dpapi_v1(...).expect_err(...)`），不属于 `AGENTS.md` §4 定义的
// 「真实 pwsh / 网络 / 大目录 / DPAPI 密文样本」任何一类 —— 被 `#[ignore]` 排除在
// 默认 `cargo test` 之外，等于把一份免费的回归覆盖关掉。取消 ignore。
#[test]
fn bad_prefix_is_distinct_error() {
    use trim_tauri_lib::safestorage::StorageError;
    assert!(matches!(
        decrypt_dpapi_v1("plain-text-value", None).expect_err("应报 BadPrefix"),
        StorageError::BadPrefix
    ));
}
