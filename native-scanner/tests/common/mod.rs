// tests/common/mod.rs — 集成测试共用的沙箱根（自删守卫）
//
// 为什么要它：`tempFiles` 清理条目的扫描根**就是用户 %TEMP%**，而测试一直在同一个地方建沙箱。
// 旧写法返回一个裸 `PathBuf`、把 `remove_dir_all` 手写在用例最后一行 ⇒ 任何一次断言失败 /
// panic / 早退都在盘上留一份。本机实测攒出 224 个 `trim-*` 目录（其中重复项 e2e 一家 196 个），
// 清理扫描从此常年在这种测试垃圾上命中深度上限并打留痕 —— 测试垃圾反过来污染被测对象的世界。
// 口径：返回带 Drop 的守卫，离开作用域就删（失败路径一样删）；`Deref<Target=Path>` 让
// `root.join(..)` / `&root` / `root.display()` 全部照旧，用例正文不必为守卫改一行。
#![allow(dead_code)] // 每个集成测试二进制各编一份，用不到的项会报 dead_code

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct TempRoot {
    dir: PathBuf,
}

impl TempRoot {
    /// 建 `%TEMP%\trim-<prefix>-<tag>-<pid>-<序号>` 并返回**规范化后**的路径守卫。
    /// 为什么必须规范化：8.3 短名环境下 `temp_dir()` 给 `ADMINI~1`，而扫描器枚举出的是长名 ——
    /// 不拉齐就 `strip_prefix` 全失败、命中集变成绝对路径，差分断言会以假阳性过掉。
    /// 手工剥 `\\?\` 前缀（不为测试引 dunce，且只服务本机临时目录）。
    pub fn new(prefix: &str, tag: &str) -> TempRoot {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let raw = std::env::temp_dir().join(format!("trim-{prefix}-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&raw);
        std::fs::create_dir_all(&raw).expect("建临时树失败");
        let mut real = std::fs::canonicalize(&raw)
            .expect("canonicalize 临时目录失败")
            .to_string_lossy()
            .into_owned();
        if let Some(s) = real.strip_prefix(r"\\?\") {
            real = s.to_string();
        }
        TempRoot { dir: PathBuf::from(real) }
    }

    pub fn path(&self) -> &Path { &self.dir }
}

impl std::ops::Deref for TempRoot {
    type Target = Path;
    fn deref(&self) -> &Path { &self.dir }
}

impl AsRef<Path> for TempRoot {
    fn as_ref(&self) -> &Path { &self.dir }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        // 删失败不改判：测试结论由断言给出，收尾再 panic 只会把一条红变成两条噪声
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
