//! P2-B（2026-10-16）：无头清理扫描 CLI（**只读**）——`cleanup:scan` 的等价无头入口。
//!
//! 定位：CI / 脚本 / 集成场景下不启 UI 就能拿到「清理候选 + 计数」；
//! 复用 `trim_tauri_lib::commands::cleanup::cleanup_scan_headless`（与 `cleanup:scan`
//! 同一条核心，见 scan_execute.rs 的 `run_cleanup_scan_core` 注释）。
//!
//! **只读红线**：本程序不删除任何文件、不写任何系统状态；扫描出的是「候选 + 计数」。
//!
//! 用法：
//!   cargo run --example scan -- [--json] [--item <条目 id>]...
//!   · 缺省扫描全量（规则库全部条目 id，与 UI「全量扫描」口径一致）；
//!   · `--item` 可多次指定，只扫这些条目（如 `--item prefetchFiles`）；
//!   · `--json` 输出完整 JSON（candidates + counts）；缺省输出人读摘要；
//!   · 退出码：成功 0 / 扫描失败（success=false）2——fail-loud，不把失败伪装成空结果。
//!
//! 输出字段口径见 `cleanup_scan_headless` 的文档注释（locked 为「保护排除 + 独占探测
//! 失败」两类合并的不可删口径；malformedLines > 0 即行协议异常）。
use serde_json::Value;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("用法: cargo run --example scan -- [--json] [--item <条目 id>]...");
        println!("  --json         输出完整 JSON（candidates + counts）");
        println!("  --item <id>    只扫描指定条目（可多次；缺省 = 全量）");
        return;
    }
    let json_out = args.iter().any(|a| a == "--json");
    let mut cats: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--item" && i + 1 < args.len() {
            cats.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    let v = trim_tauri_lib::commands::cleanup::cleanup_scan_headless(cats);
    if json_out {
        match serde_json::to_string_pretty(&v) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("JSON 序列化失败: {e}");
                std::process::exit(2);
            }
        }
    } else {
        print_summary(&v);
    }
    if v.get("success").and_then(|b| b.as_bool()).unwrap_or(false) {
        std::process::exit(0);
    }
    std::process::exit(2);
}

/// 人读摘要：counts 一行 + 命中条目表（id / 名称 / 体积 / 文件数 / 存在性）
fn print_summary(v: &Value) {
    let success = v.get("success").and_then(|b| b.as_bool()).unwrap_or(false);
    if !success {
        println!(
            "扫描失败: {}",
            v.get("message").and_then(|m| m.as_str()).unwrap_or("(无消息)")
        );
        return;
    }
    let counts = v.get("counts").cloned().unwrap_or(Value::Null);
    let n = |k: &str| counts.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    println!("== 清理扫描（只读）==");
    println!(
        "候选条目 {} · 可删文件 {} · 不可删（保护/占用）{} 文件 / {} 条目 · 截断条目 {} · 跳过重解析点 {} · 畸形行 {}",
        n("entries"),
        n("filesTotal"),
        n("lockedFiles"),
        n("lockedEntries"),
        n("truncatedEntries"),
        n("skippedReparseTotal"),
        n("malformedLines")
    );
    if let Some(data) = v.get("data").and_then(|d| d.as_array()) {
        println!("-- 命中条目（size>0 或有文件清单）--");
        let mut shown = 0usize;
        for it in data {
            let size = it.get("size").and_then(|s| s.as_i64()).unwrap_or(0);
            let files = it
                .get("files")
                .and_then(|f| f.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if size <= 0 && files == 0 {
                continue;
            }
            println!(
                "  {} | {} | size={} | files={} | exists={}",
                it.get("id").and_then(|x| x.as_str()).unwrap_or("?"),
                it.get("name").and_then(|x| x.as_str()).unwrap_or("?"),
                size,
                files,
                it.get("exists").and_then(|x| x.as_bool()).unwrap_or(false)
            );
            shown += 1;
            if shown >= 200 {
                println!("  ……（其余条目见 --json）");
                break;
            }
        }
        if shown == 0 {
            println!("  （无命中条目）");
        }
    }
}
