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

/// v7.2-C03（N1b-M05）：畸形数值不再折成 0——CLI 是调试入口，`--count abc`
/// 旧形态静默变 0（再被 max(1) 兜成 1），判据面与输入面脱钩。改 fail-closed：
/// 畸形 = stderr 留痕 + exit 2。
fn parse_u64(s: &str) -> Option<u64> {
    s.parse().ok()
}

/// 数值参数取值（N1b-M05）：畸形即致命，统一出口。
fn parse_u64_or_fatal(s: &str, flag: &str) -> u64 {
    match parse_u64(s) {
        Some(v) => v,
        None => {
            eprintln!("[finder-warn] {} 数值畸形: {:?}（fail-closed exit 2）", flag, s);
            std::process::exit(2);
        }
    }
}

/// `finder delete` 的参数解析（N1b-L05）：**单一判据**，返回 `(protect JSON, 待删条目)`。
///
/// 任何一处畸形都返回 Err 且调用方**不执行任何删除** —— 成对性一旦破坏，后面参数的位置
/// 语义就不可信（旧实现只在循环里报成对的那一对，尾部单个参数被静默吞掉，
/// 于是 `delete file a.txt dir` 只删 a.txt 并以 0 退出，与函数注释的「不许部分执行」相反）。
/// `raw` 是 `delete` 之后的原始 argv（路径保留 OsString，见审查v4-L4）。
fn parse_delete_args(
    raw: &[OsString],
) -> Result<(Option<String>, Vec<(String, OsString)>), Vec<String>> {
    let args: Vec<String> = raw.iter().map(|a| a.to_string_lossy().to_string()).collect();
    let mut problems: Vec<String> = Vec::new();
    let mut i = 0usize;
    let mut protect_json: Option<String> = None;
    // FD-2：可选前置 `--protect <json>`（主进程 protectedRootsJson()），缺省回落 default_from_env。
    // 缺值同样记为畸形：旧写法 `i += 2` 越过末尾后打印用法并以 0 退出，「参数写错」与
    // 「什么都没给」同形。
    if args.first().map(|s| s.as_str()) == Some("--protect") {
        if args.len() >= 2 {
            protect_json = Some(args[1].clone());
            i = 2;
        } else {
            problems.push("delete --protect 缺少 JSON 取值".to_string());
            return Err(problems);
        }
    }
    // v7.2-C03（N1b-M05）：畸形目标（kind 不是 file/dir、路径空/以 - 开头）原先静默丢弃
    // 且退出码 0——「没删」伪装成「删完」。任一畸形即留痕 + exit 2，**不执行任何删除**。
    let mut items: Vec<(String, OsString)> = Vec::new();
    while i + 1 < raw.len() {
        let kind = args[i].to_lowercase();
        let p = &args[i + 1];
        if (kind == "file" || kind == "dir") && !p.is_empty() && !p.starts_with('-') {
            items.push((kind, raw[i + 1].clone()));
        } else {
            problems.push(format!("delete 畸形目标（kind={kind:?}, path={p:?}），已拒绝"));
        }
        i += 2;
    }
    // N1b-L05：尾部落单的那个参数必须点名 —— 它既没配成一对，也不属于任何一条合法条目。
    if i < raw.len() {
        problems.push(format!("delete 尾部参数不成对，已拒绝：{:?}", args[i]));
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    Ok((protect_json, items))
}

fn main() {
    // N2：CLI 是独立调试入口，没有宿主注入数据根。这里把两个根都设成 Electron 时代的
    // 老根，使 CLI 的排除/忽略名单行为与迁移前**逐字一致**（crate 的搬迁原则）；
    // Tauri 侧不走这条路，它由 `paths::app_data_dir()` 注入当前根 + 老根兜底。
    // 老根的拼接只允许发生在 `util::legacy_cli_root`（门禁 C 段把它列为 ROOT_OWNER）。
    if let Some(root) = trim_finder::util::legacy_cli_root() {
        trim_finder::util::set_data_roots(root.clone(), root);
    }
    // 审查v4-L4：命令名/数值参数经 lossy 转换足够，但原始 OsString 必须保留——
    // 文件路径含孤立代理对等非良构 UTF-16 时 to_string_lossy 会产生 U+FFFD，删除目标静默失配
    let raw: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<String> = raw.iter().map(|a| a.to_string_lossy().to_string()).collect();
    if args.is_empty() {
        println!("finder <duplicates|bigfiles|empty|appdata|sizes|analyze|delete|cleanup> [args...]");
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
                    min_size = parse_u64_or_fatal(&args[i + 1], "--min-size");
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
                    count = parse_u64_or_fatal(&args[i + 1], "--count") as usize;
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
            // CLI 侧默认也钉 300MB 阈值（与 Tauri 通道六轮拍板口径一致）
            scan::bigfiles(&roots, count.max(1), 300 * 1024 * 1024, &sink);
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
                    min_mb = parse_u64_or_fatal(&args[i + 1], "--min-size-mb");
                    i += 2;
                } else {
                    i += 1;
                }
            }
            scan::appdata(min_mb, &sink);
        }
        "analyze" => {
            // C1-2（2026-10-16）：磁盘分析一层的 CLI 入口。应用内通道（finder.rs
            // scan_type="analyze" → scan::analyze）无 UI 自动化路径，release 性能
            // 实测需要无头入口；语义与应用内完全同源（同一个 scan::analyze）。
            let mut roots: Vec<String> = Vec::new();
            for r in args.iter().skip(1) {
                if !r.starts_with('-') {
                    roots.push(r.clone());
                }
            }
            if roots.is_empty() {
                println!("analyze 需要至少一个分析目录");
                return;
            }
            scan::analyze(&roots, &sink);
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
            // v3.7.1 R2b：系统概览高频指标（字段契约 = `vendor/upstream-js/src/scripts-powershell/overview-scripts.js:60-74`）
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
            // FD-2：可选前置 `--protect <json>`（主进程 protectedRootsJson()）三端同源。
            // N1b-L05：参数面收进 `parse_delete_args` 单一判据 —— 尾部不成对、`--protect`
            // 缺值同样判红（exit 2 且不执行任何删除），不再把「参数写错」走成「用法提示」。
            match parse_delete_args(&raw[1..]) {
                Ok((protect_json, items)) => {
                    if items.is_empty() {
                        println!("delete [--protect <json>] <file|dir> <path>...");
                        return;
                    }
                    scan::delete(&items, protect_json.as_deref(), &sink);
                }
                Err(problems) => {
                    for msg in problems {
                        eprintln!("[finder-warn] {msg}");
                    }
                    std::process::exit(2);
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<OsString> {
        v.iter().map(|s| OsString::from(*s)).collect()
    }

    /// N1b-L05 破坏自证：成对性破坏（尾部单出一个参数）必须整体判红，
    /// 那个参数必须被点名。删掉 `parse_delete_args` 末尾的 `if i < raw.len()` 尾部检查，
    /// 本条立刻红（旧实现正是「静默吞掉 dir、只删 a.txt、退出 0」）。
    #[test]
    fn delete_尾部不成对的参数必须判红() {
        let e = parse_delete_args(&argv(&["file", "a.txt", "dir"])).unwrap_err();
        assert!(
            e.iter().any(|m| m.contains("尾部参数不成对")),
            "成对性破坏必须点名判红：{e:?}"
        );
        assert!(
            e.iter().any(|m| m.contains("dir")),
            "留痕要点名被吞的那个参数（正是它让位置语义不可信）：{e:?}"
        );
        // 只有 kind 没有路径、或只有路径没有 kind，都属不成对
        assert!(parse_delete_args(&argv(&["file"])).is_err(), "单个 kind 也不成对");
        assert!(parse_delete_args(&argv(&["a.txt"])).is_err(), "单个路径也不成对");
    }

    /// 成对参数照常解析，`--protect` 的 JSON 不会被当成条目；空参数表 = 用法提示（不是畸形）。
    #[test]
    fn delete_成对参数照常解析且保护前缀不丢() {
        let (protect, items) = parse_delete_args(&argv(&["file", "a.txt", "dir", r"C:\x"])).unwrap();
        assert!(protect.is_none(), "没给 --protect 就是 None（由 scan 侧回落保守默认）");
        assert_eq!(items.len(), 2, "两对应得两条：{items:?}");
        assert_eq!(items[0].0, "file");
        assert_eq!(items[0].1, OsString::from("a.txt"));
        assert_eq!(items[1].0, "dir");
        assert_eq!(items[1].1, OsString::from(r"C:\x"));

        let (protect2, items2) =
            parse_delete_args(&argv(&["--protect", r#"{"exact":[]}"#, "file", "b.txt"])).unwrap();
        assert_eq!(
            protect2.as_deref(),
            Some(r#"{"exact":[]}"#),
            "--protect 的 JSON 不许被当成待删条目"
        );
        assert_eq!(items2.len(), 1, "保护前缀之后的参数才配对：{items2:?}");

        let (protect3, items3) = parse_delete_args(&argv(&[])).unwrap();
        assert!(protect3.is_none() && items3.is_empty(), "空参数表走用法提示，不是畸形");
    }

    /// N1b-L05 同族漏点：`--protect` 缺值原先静默越过末尾（随后打印用法并以 0 退出）。
    #[test]
    fn delete_protect缺值必须判红() {
        let e = parse_delete_args(&argv(&["--protect"])).unwrap_err();
        assert!(
            e.iter().any(|m| m.contains("--protect") && m.contains("缺少")),
            "--protect 缺值必须判红：{e:?}"
        );
    }

    /// 畸形 kind 仍逐条留痕（口径不变），但只要有畸形就整体 Err —— 不部分执行。
    #[test]
    fn delete_畸形kind整体判红() {
        let e = parse_delete_args(&argv(&["file", "a.txt", "folder", "b"])).unwrap_err();
        assert_eq!(e.len(), 1, "只有一处畸形：{e:?}");
        assert!(e[0].contains("畸形目标"), "留痕要点名 kind/path：{e:?}");
        // 同一份输入里合法的 (file,a.txt) 不得被返回 —— 调用方拿不到 items 就不可能部分执行
        assert!(e[0].contains("folder"), "要点名写错的那个 kind：{e:?}");
    }
}
