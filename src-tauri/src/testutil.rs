//! `testutil` — 只在测试构建下存在的测试基建。
//!
//! 用**内层属性**整文件收掉（而不是在 lib.rs 里挂属性声明本模块）：
//! `check-native-hygiene` 的 N7/N10 与 lib.rs 的 9 条形状用例都以「文件中首个 cfg(test)
//! 标记」为生产面切割点，在 lib.rs 顶部出现该字面量会把生产段截到第 19 行。
#![cfg(test)]

//!
//! 目前只有一件事：测试沙箱的**自删守卫**。

/// 测试沙箱守卫：建在 `%TEMP%\trim-<tag>`，离开作用域（含 panic / 断言失败 / 早退）即删。
///
/// 为什么必须有它：清理条目 `tempFiles` 的扫描根**就是用户 %TEMP%**
/// （`cleanup-rules.json` 里 `pathPs: "$env:TEMP"`），而本仓测试一直在同一处建沙箱。
/// 旧写法把 `remove_dir_all` 手写在用例最后一行 ⇒ 任何一次红灯都在盘上留一份。
/// 本机实测：一次 `cargo test` 新增 40 份、累计攒到 224 个 `trim-*` 目录，其中
/// native-scanner 两条深度用例留下 70 层嵌套（> `MAX_WALK_DEPTH` 64），
/// 于是清理扫描常年在这种测试垃圾上撞深度上限并打留痕 —— **测试垃圾反过来污染了
/// 被测对象看到的世界**，且用户分不清「扫到的是自己的临时文件还是 agent 的垃圾」。
///
/// 用法（保持变量名与原来一致，用例正文零改动）：
/// ```ignore
/// let _sb = crate::testutil::sandbox(&format!("a2-multistar-{}", std::process::id()));
/// let base = _sb.path().to_path_buf();
/// ```
pub struct Sandbox(std::path::PathBuf);

impl Sandbox {
    /// 建沙箱并返回守卫。同名旧目录先删（同 pid 复用 / 上次被强杀的残留）。
    pub fn new(tag: &str) -> Sandbox {
        let dir = std::env::temp_dir().join(format!("trim-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("测试沙箱可创建");
        Sandbox(dir)
    }
    pub fn path(&self) -> &std::path::Path { &self.0 }
}

impl std::ops::Deref for Sandbox {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl AsRef<std::path::Path> for Sandbox {
    fn as_ref(&self) -> &std::path::Path { &self.0 }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // 删失败不改判：测试结论由断言给出，收尾再 panic 只会把一条红变成两条噪声。
        // 这里刻意用 `remove_dir_all` 而不是走产品删除链（回收站/保护判定）：
        // 删的是本用例刚建出来的沙箱，不是用户数据。
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
