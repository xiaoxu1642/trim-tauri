//! 重复文件三项升级（2026-10-06 任务四）的判据测试。
//!
//! 纪律（照 `cleanup_scan_rule_diff.rs` 的三条）：零副作用（临时目录 + 只读扫描，
//! 不进任何删除链）；断言点名正向特征（组归属 + role/match 值），不只断「没报错」；
//! 正反都断 —— 后缀同内容 → artifact 命中；后缀不同内容 → 不命中。
//!
//! 覆盖：
//! 1. `normalize_artifact_name` 各形态（含不该剥的 `(final)` 与多段扩展名）；
//! 2. `order_group_by_mtime`：最新在前（= kept）；同 mtime 保持入参顺序（稳定排序）；
//! 3. 端到端 `duplicates`：`a.ext` + `a (1).ext`（同内容）→ artifact 组且 kept = 较新者；
//!    同名同内容仍按 name 组输出（改造不破坏既有分组）。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use trim_finder::scan::{duplicates, normalize_artifact_name, order_group_by_mtime, Sink};

/// 最小收集 Sink：type/role/match 从行协议里取（短 ASCII 字段、无转义），
/// path 直接用 `item()` 给的原生真身（审查 v2-M5 口径，不解析文本行里的 lossy 串）。
struct Collect {
    rows: Mutex<Vec<(String, String, String, String)>>, // (name, type, role, match)
}

impl Sink for Collect {
    fn item(&self, path: &Path, line: &str) {
        let Some(body) = line.trim().strip_prefix("@@ITEM@@") else { return };
        let get = |k: &str| -> String {
            let key = format!("\"{k}\":\"");
            body.find(&key)
                .map(|i| {
                    let rest = &body[i + key.len()..];
                    rest.split('"').next().unwrap_or("").to_string()
                })
                .unwrap_or_default()
        };
        if get("type") != "duplicate" {
            return;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        self.rows
            .lock()
            .unwrap()
            .push((name, get("type"), get("role"), get("match")));
    }
    fn progress(&self, _n: u64) {}
    fn scanned(&self, _n: u64) {}
    fn warn(&self, _msg: &str) {}
}

fn temp_root(tag: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("trim-dup-artifact-{tag}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("建临时目录失败");
    // 8.3 短名环境下 temp_dir() 给 `ADMINI~1` 而扫描器枚举长名——拉齐后再供 roots。
    let mut real = fs::canonicalize(&base)
        .expect("canonicalize 失败")
        .to_string_lossy()
        .into_owned();
    if let Some(s) = real.strip_prefix(r"\\?\") {
        real = s.to_string();
    }
    PathBuf::from(real)
}

/// 写文件并显式设置 mtime（`File::set_modified`，std 自带，不引测试依赖）。
fn write_with_mtime(p: &Path, content: &[u8], unix_secs: u64) {
    fs::write(p, content).expect("写样本失败");
    let f = fs::OpenOptions::new().write(true).open(p).expect("打开样本失败");
    f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix_secs))
        .expect("设置 mtime 失败");
}

// ==================== 1. 归一化 ====================

#[test]
fn 下载副本名归一化各形态() {
    for (input, want) in [
        ("a.txt", "a.txt"),
        ("a (1).txt", "a.txt"),
        ("a(12).txt", "a.txt"),
        ("a - 副本.txt", "a.txt"),
        ("a - 副本 (2).txt", "a.txt"),
        ("a - Copy.TXT", "a.txt"), // 大小写不敏感
        ("a_copy.gz", "a.gz"),     // _copy 标记（直接贴主名）
        ("b (1).tar.gz", "b.tar.gz"), // 多段扩展名：序号插在主名后
        // 已知不支持形态（序号插在中间扩展名前）——显式记录，防将来误以为支持；
        // 影响面仅标签显示，不放宽删除面（见 normalize_artifact_name 注释）
        ("b.tar (1).gz", "b.tar (1).gz"),
        ("报告 (3).pdf", "报告.pdf"),
        // 不该剥的：非数字序数（真名字的一部分）
        ("a (final).txt", "a (final).txt"),
        // 与 b (1).tar.gz 同构（主名+序号+多段后缀）——规则统一处理：剥。
        // 纯标签影响（artifact 与 content 默认勾选行为相同），无删除面风险。
        ("v(1).2.txt", "v.2.txt"),
    ] {
        assert_eq!(normalize_artifact_name(input), want, "输入 {input}");
    }
}

// ==================== 2. mtime 排序 ====================

#[test]
fn 组内最新者在前且同mtime稳定() {
    let root = temp_root("order");
    let older = root.join("old.bin");
    let same_a = root.join("same_a.bin");
    let same_b = root.join("same_b.bin");
    let newer = root.join("new.bin");
    write_with_mtime(&older, b"x", 1_000);
    write_with_mtime(&same_a, b"xx", 2_000);
    write_with_mtime(&same_b, b"xxx", 2_000); // 与 same_a 同 mtime
    write_with_mtime(&newer, b"xxxx", 3_000);

    // 入参顺序刻意与 mtime 顺序不同：same_a 在前、same_b 在后（同 mtime 应保持这个相对序）
    let v: Vec<(PathBuf, u64)> = vec![
        (same_a.clone(), 2),
        (same_b.clone(), 3),
        (older.clone(), 1),
        (newer.clone(), 4),
    ];
    let order = order_group_by_mtime(&v);
    assert_eq!(v[order[0]].0, newer, "kept（第 0 位）必须是 mtime 最新的");
    assert_eq!(v[order[1]].0, same_a, "同 mtime 并列必须保持入参顺序（稳定排序）");
    assert_eq!(v[order[2]].0, same_b, "同 mtime 并列必须保持入参顺序（稳定排序）");
    assert_eq!(v[order[3]].0, older, "最旧排最后");
}

// ==================== 3. 端到端 ====================

#[test]
fn 下载副本组命中而不同内容不命中() {
    let root = temp_root("e2e");
    // 副本对（同内容、归一化同名；a (1).txt 更新 ⇒ 它应是 kept）
    write_with_mtime(&root.join("a.txt"), b"SAME-CONTENT", 1_000);
    write_with_mtime(&root.join("a (1).txt"), b"SAME-CONTENT", 2_000);
    // 反向：后缀同形但内容不同 —— 不进同一指纹组，不得出现 artifact
    write_with_mtime(&root.join("b.txt"), b"BBB-1", 1_000);
    write_with_mtime(&root.join("b (1).txt"), b"BBB-2", 1_000);
    // 既有行为：同名同内容 → name 组（root 与 sub 各一份，同名同大小）
    write_with_mtime(&root.join("same.txt"), b"NAME-CONTENT", 1_000);
    fs::create_dir_all(root.join("sub")).unwrap();
    write_with_mtime(&root.join("sub").join("same.txt"), b"NAME-CONTENT", 1_000);

    let sink = Collect { rows: Mutex::new(Vec::new()) };
    duplicates(&[root.to_string_lossy().to_string()], 1, &sink);
    let rows = sink.rows.lock().unwrap().clone();

    // 正向：a 副本对 → artifact，且 kept 是较新的 a (1).txt
    let artifact: Vec<_> = rows.iter().filter(|r| r.3 == "artifact").collect();
    assert!(
        artifact.iter().any(|r| r.0 == "a (1).txt" && r.2 == "kept"),
        "a (1).txt（较新）应为 artifact 组的 kept；实得 {rows:?}"
    );
    assert!(
        artifact.iter().any(|r| r.0 == "a.txt" && r.2 == "candidate"),
        "a.txt（较旧）应为 artifact 组的候选；实得 {rows:?}"
    );
    // 反向：b 对内容不同 → 不产生任何 artifact 行（各自都不成组）
    assert!(
        !artifact.iter().any(|r| r.0.starts_with("b.") || r.0.starts_with("b (")),
        "b 对内容不同，不得出现在 artifact 组；实得 {rows:?}"
    );
    // 既有行为：同名对仍是 name 组
    assert!(
        rows.iter().any(|r| r.0 == "same.txt" && r.3 == "name"),
        "同名对必须仍按 name 组输出（改造不得破坏既有分组）；实得 {rows:?}"
    );
}
