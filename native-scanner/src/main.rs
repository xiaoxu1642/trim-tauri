// Trim 内建原生扫描器（CLI 入口）。
// 以行为单位输出：@@ITEM@@{json}、@@PROGRESS:n@@ 与 @@SCANNED:n@@，供 Electron 主进程流式解析。
// 重复文件三级检测：内容指纹（体积+Blake3）> 文档内容相似（shingle/Jaccard）> 同名文件，
// 每个文件最多归入一组；扫描与删除均在 Rust 中完成。
//
// 扫描性能升级（批次：大文件扫描升级 2026-09-11，对标 HiBit/SpaceSniffer 逆向）：
//   · ent.metadata() 收口所有「取大小」syscall（DirEntry 自带 WIN32_FIND_DATAW 缓存）
//   · walk 目录级分治并行（rayon，前 PAR_DEPTH 层展开）
//   · bigfiles 改「任务分片 + 每片局部 Top-K 堆 + reduce 归并」，内存 O(线程数 × N)
//   · 新增 @@SCANNED:n@@ 心跳行，大盘扫描时前端能实时看到已枚举文件数
//
// 磁盘清理扫描引擎（P0：pathPs 目录型条目 + dism 占位），方案见
// 本地资料区的《磁盘清理扫描 Rust 化方案》v1.1（不随仓库分发）
// v3.7.1 Rust 化批次（R1/R2/R3）：diskbench / ov-metrics / net-sample / mem-clean
// 方案见迁移方案文档的 R1R2R3 小节（契约优先）
//
// Phase 1 lib 化：模块声明与共享助手上移到 src/lib.rs（同一模块不能在 bin 与 lib 里
// 各声明一次，否则编译两份），bin 改为引用库；CLI 行为不变。
//
// B 批（输出汇聚器 Sink）：扫描类命令（duplicates/bigfiles/empty/appdata/sizes/delete）
// 迁到 lib 的 scan 模块，输出方向反转为回调。本文件只保留「参数解析 + StdoutSink 实现
// + 调用 scan::*」，StdoutSink 把回调原样写回 stdout/stderr，使 CLI 对外可观测行为
// （行内容与顺序、stderr 前缀、退出码）逐字节不变。
use std::ffi::OsString;
use std::io::Write as _;

use trim_finder::scan::Sink;
use trim_finder::{cleanup_scan, perf, scan};

/// CLI 侧输出汇聚器：把 scan 模块的回调原样写回标准流（格式与迁移前逐字一致）。
struct StdoutSink;

impl Sink for StdoutSink {
    fn item(&self, _path: &std::path::Path, line: &str) {
        // 原实现走 write_all（stdout 为 LineWriter，遇 '\n' 即 flush），沿同路径以对齐输出节奏
        let _ = std::io::stdout().write_all(line.as_bytes());
    }
    fn progress(&self, n: u64) {
        println!("@@PROGRESS:{}@@", n.min(100));
    }
    fn scanned(&self, n: u64) {
        println!("@@SCANNED:{}@@", n);
    }
    fn warn(&self, msg: &str) {
        eprintln!("[finder-warn] {}", msg);
    }
}

fn parse_u64(s: &str) -> u64 {
    s.parse().unwrap_or(0)
}

fn main() {
    // 审查v4-L4：命令名/数值参数经 lossy 转换足够，但原始 OsString 必须保留——
    // 文件路径含孤立代理对等非良构 UTF-16 时 to_string_lossy 会产生 U+FFFD，删除目标静默失配
    let raw: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<String> = raw.iter().map(|a| a.to_string_lossy().to_string()).collect();
    if args.is_empty() {
        println!("finder <duplicates|bigfiles|empty|appdata|sizes|delete|cleanup> [args...]");
        return;
    }
    let sink = StdoutSink;
    match args[0].as_str() {
        "duplicates" => {
            let mut min_size = 1024 * 1024u64; // 默认 1MB
            let mut roots: Vec<String> = Vec::new();
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--min-size" && i + 1 < args.len() {
                    min_size = parse_u64(&args[i + 1]);
                    i += 2;
                } else {
                    roots.push(args[i].clone());
                    i += 1;
                }
            }
            if roots.is_empty() {
                println!("duplicates 需要至少一个扫描目录");
                return;
            }
            scan::duplicates(&roots, min_size, &sink);
        }
        "bigfiles" => {
            let mut count = 50usize;
            let mut roots: Vec<String> = Vec::new();
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--count" && i + 1 < args.len() {
                    count = parse_u64(&args[i + 1]) as usize;
                    i += 2;
                } else {
                    roots.push(args[i].clone());
                    i += 1;
                }
            }
            if roots.is_empty() {
                println!("bigfiles 需要至少一个扫描目录");
                return;
            }
            scan::bigfiles(&roots, count.max(1), &sink);
        }
        "empty" => {
            let mut roots: Vec<String> = Vec::new();
            for r in args.iter().skip(1) {
                roots.push(r.clone());
            }
            if roots.is_empty() {
                println!("empty 需要至少一个扫描目录");
                return;
            }
            scan::empty(&roots, &sink);
        }
        "appdata" => {
            let mut min_mb = 10u64;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--min-size-mb" && i + 1 < args.len() {
                    min_mb = parse_u64(&args[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            scan::appdata(min_mb, &sink);
        }
        "sizes" => {
            let mut paths: Vec<String> = Vec::new();
            for a in args.iter().skip(1) {
                if !a.starts_with('-') {
                    paths.push(a.clone());
                }
            }
            if paths.is_empty() {
                println!("sizes 需要至少一个路径");
                return;
            }
            scan::sizes(&paths, &sink);
        }
        "cleanup" => {
            // 磁盘清理扫描引擎（P0）：argv 短参数 + stdin 规则 JSON（60KB 级，命令行放不下）。
            // 行协议/退出码与 PS SCAN_SCRIPT 同口径：致命错误 stderr + exit 2（fail-closed）。
            let code = cleanup_scan::run(&args[1..]);
            let _ = std::io::Write::flush(&mut std::io::stdout());
            std::process::exit(code);
        }
        "checklocked" => {
            // 清理前占用检测（v3.3.4）：stdin = {files:[{path,id}]}，输出被占用文件与占用进程。
            // 只读探测，不结束任何进程；结束进程由主进程按渲染层确认后执行。
            let code = cleanup_scan::run_checklocked();
            let _ = std::io::Write::flush(&mut std::io::stdout());
            std::process::exit(code);
        }
        "diskbench" => {
            // v3.7.1 R1：磁盘测速原生引擎（nobuf 默认，QD=每线程在途上限）
            let code = perf::run_diskbench(&args[1..]);
            let _ = std::io::Write::flush(&mut std::io::stdout());
            std::process::exit(code);
        }
        "ov-metrics" => {
            // v3.7.1 R2b：系统概览高频指标（字段契约 = overview-scripts.js:60-74）
            let code = perf::run_ov_metrics();
            let _ = std::io::Write::flush(&mut std::io::stdout());
            std::process::exit(code);
        }
        "net-sample" => {
            // v3.7.1 R2a：实时网速采样 daemon（每秒一行 JSON，差分在 Rust，管道断裂即退出）
            let code = perf::run_net_sample(&args[1..]);
            let _ = std::io::Write::flush(&mut std::io::stdout());
            std::process::exit(code);
        }
        "mem-clean" => {
            // v3.7.1 R3：内存清理（双特权 + 82/84 黑名单继承 + results[] 契约）
            let code = perf::run_mem_clean(&args[1..]);
            let _ = std::io::Write::flush(&mut std::io::stdout());
            std::process::exit(code);
        }
        "delete" => {
            // 审查v4-L4：路径取原始 OsString，命令名与格式校验用 lossy 字符串
            // FD-2：可选前置 `--protect <json>`（主进程 protectedRootsJson()）三端同源；
            // 缺省回落保守默认（default_from_env）——B 批改为按 JSON 文本注入 scan::delete。
            let mut i = 1;
            let mut protect_json: Option<String> = None;
            if args.get(i).map(|s| s.as_str()) == Some("--protect") {
                if i + 1 < raw.len() {
                    protect_json = Some(args[i + 1].clone());
                }
                i += 2;
            }
            let mut items: Vec<(String, OsString)> = Vec::new();
            while i + 1 < raw.len() {
                let kind = args[i].to_lowercase();
                let p = &args[i + 1];
                if (kind == "file" || kind == "dir") && !p.is_empty() && !p.starts_with('-') {
                    items.push((kind, raw[i + 1].clone()));
                }
                i += 2;
            }
            if items.is_empty() {
                println!("delete [--protect <json>] <file|dir> <path>...");
                return;
            }
            scan::delete(&items, protect_json.as_deref(), &sink);
        }
        "protectcheck" => {
            // FD-2 只读对拍探针：`protectcheck --protect <json> <vector...>`
            // 输出每向量 0/1（1=受保护），供 test-features 复测 JS/Rust 两侧口径一致。不碰磁盘。
            // B 批：同一份 `--protect` 文本交给 scan::protect_flags；输出格式（逗号分隔 0/1）未变。
            let mut i = 1;
            let mut protect_json: Option<String> = None;
            if args.get(1).map(|s| s.as_str()) == Some("--protect") && i + 1 < args.len() {
                protect_json = Some(args[2].clone());
                i = 3;
            }
            let vectors: Vec<String> = args.iter().skip(i).cloned().collect();
            let flags = scan::protect_flags(protect_json.as_deref(), &vectors);
            println!(
                "{}",
                flags.iter().map(|b| if *b { "1" } else { "0" }).collect::<Vec<_>>().join(",")
            );
        }
        _ => {
            println!("未知命令: {}", args[0]);
        }
    }
}