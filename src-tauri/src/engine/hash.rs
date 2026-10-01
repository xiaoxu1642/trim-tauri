//! 哈希工具（v2-L4P-41 / D-1：自 `commands/runtimes.rs` 下沉）。
//!
//! 为什么要下沉：`engine/reg_backup.rs` 的封条校验需要文件哈希，却反向依赖
//! commands 层的 runtimes 模块——分层方向违规（engine 层不得引用 commands 层，
//! 见 check-layering.mjs）。哈希是跨域共用基础设施，归位本模块后反向依赖清零。

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 流式 SHA-256（4MB 缓冲，与 JS sha256File 同口径）
pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(to_hex(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        let dir = std::env::temp_dir().join(format!("trim-hash-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("vec.txt");
        std::fs::write(&p, b"abc").unwrap();
        let h = sha256_file(&p).expect("哈希失败");
        let _ = std::fs::remove_file(&p);
        assert_eq!(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
