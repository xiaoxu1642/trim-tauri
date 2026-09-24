fn main() {
    tauri_build::build();

    // 测试二进制需要 ComCtl32 v6 应用清单（否则 `cargo test` 的 exe 起不来）：
    // tauri-build 只给**应用 exe** 嵌入 windows-app-manifest.xml；而 tauri-runtime-wry 在
    // `common-controls-v6`（tauri 默认特性，本项目已启用）下会**加载期导入** ComCtl32 v6
    // 专有导出 TaskDialogIndirect。测试 exe 无清单 → 解析到 system32 的 comctl32 v5.82 →
    // 进程启动即 STATUS_ENTRYPOINT_NOT_FOUND（0xc0000139）。
    // 这里只对 test 目标补清单：rustc-link-arg-tests 不参与应用 exe / lib 的链接。
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("comctl32-v6.manifest");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-tests=/MANIFESTINPUT:{}", manifest.display());
    }
}