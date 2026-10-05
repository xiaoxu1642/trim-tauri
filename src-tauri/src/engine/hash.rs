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

/// 内存字节的 SHA-256（与 `sha256_file` 同一份 to_hex，不另起一套十六进制编码）。
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    to_hex(&hasher.finalize())
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

    /// 两条入口必须给同一个值：字节版与流式版各写一份编码就会在某一侧悄悄漂掉
    /// （AGENTS §5.16「判据不许有两套实现」）。
    #[test]
    fn bytes_and_file_hashes_agree() {
        let dir = std::env::temp_dir().join(format!("trim-hash2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("same.bin");
        let body: Vec<u8> = (0..1000u32).flat_map(|i| i.to_le_bytes()).collect();
        std::fs::write(&p, &body).unwrap();
        let from_file = sha256_file(&p).expect("文件哈希失败");
        let from_bytes = sha256_bytes(&body);
        let _ = std::fs::remove_file(&p);
        assert_eq!(from_file, from_bytes, "同一份内容两种算法给出不同摘要");
        // 已知向量（空串）：锁住 to_hex 的小写与补零口径
        assert_eq!(
            sha256_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
