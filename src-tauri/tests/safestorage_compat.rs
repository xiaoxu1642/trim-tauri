//! Phase 0 第 6 项 / D5 / R12：safeStorage 兼容读验证（默认 ignore，发布前门禁性质）。
//!
//! 运行方式（样本由 %TEMP%\\trim-dpapi-probe 下的探针流程产出）：
//!   $env:TRIM_DPAPI_SAMPLE="<dpapi-final.json>"; cargo test --test safestorage_compat -- --ignored --nocapture
//!   （审查 v2-L19：这里原先写的是 `--test dpapi_compat`，本仓没有那个 target，照抄会报
//!    "no test target named"——文件名 `safestorage_compat` 才是真源。）
//!
//! 样本 JSON：
//!   {
//!     "plain"/"plain2": 探针明文（含中文）,
//!     "electron1"/"electron2": "dpapi:v1:base64(v10+nonce+GCM)",  // Electron 44 真实密文
//!     "encryptedKeyB64": Local State 的 os_crypt.encrypted_key,   // DPAPI 包裹的 AES 主密钥
//!     "dotnetRawB64": 裸 DPAPI 密文 base64                         // 跨实现对拍
//!   }
//!
//! 断言：
//! 1. 从 Local State 解出 32 字节 OSCrypt 主密钥；
//! 2. 主密钥 + AES-256-GCM(AAD=v10) 解开两条 Electron 44 真实密文，明文逐字节一致；
//! 3. .NET ProtectedData 裸 DPAPI 可直接解，证明 DPAPI 层跨实现同口径。

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
        let got = decrypt_dpapi_v1(cipher, Some(&key))
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

#[test]
#[ignore = "结构性用例：非 dpapi:v1: 值必须返回 BadPrefix"]
fn bad_prefix_is_distinct_error() {
    use trim_tauri_lib::safestorage::StorageError;
    assert!(matches!(
        decrypt_dpapi_v1("plain-text-value", None).expect_err("应报 BadPrefix"),
        StorageError::BadPrefix
    ));
}
