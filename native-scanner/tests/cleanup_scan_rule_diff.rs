//! 规则改动 → 命中集差分（V2 P1-C5，2026-09-30）
//!
//! 为什么放在扫描器自己的集成测试里：真正的执行侧扫描器是 Rust（`cleanup_scan::run_json`），
//! Node 门禁只能对拍文本与结构，测不出"改完这条规则到底多命中/少命中哪些文件"。
//! CRS 那套语料差分的价值也在这里 —— 静态契约全绿不代表行为没变。
//!
//! 三条纪律：
//! 1. **零副作用**：只在临时目录造文件、只跑扫描，绝不进删除链（AGENTS §4「快速组只用
//!    零副作用命令」）；本文件最后一条用例专门钉住"扫描是只读的"，前提不成立则全部断言作废；
//! 2. 断言的是**差分集合**（新增/丢失了哪些目标），不是总数 —— 差分才是"这次改动干了什么"；
//! 3. 本 crate 不依赖 serde_json（自带 JSON 解析器），**不为测试新增依赖**（AGENTS §2），
//!    因此这里用最小手写解析，只认 `@@PLANFILE@@` 这一种行。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::os::windows::process::CommandExt;

fn temp_root(tag: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("trim-rule-diff-{tag}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("建临时树失败");
    // temp_dir() 在 8.3 短名环境下给的是 `ADMINI~1`，而扫描器枚举出的是长名 —— 不拉齐
    // 就 strip_prefix 全失败、命中集变成绝对路径，"差分"断言会以假阳性过掉。
    // canonicalize 后手工剥 `\\?\` 前缀（不为测试引 dunce，且只服务本机临时目录）。
    let mut real = fs::canonicalize(&base)
        .expect("canonicalize 临时目录失败")
        .to_string_lossy()
        .into_owned();
    if let Some(s) = real.strip_prefix(r"\\?\") {
        real = s.to_string();
    }
    PathBuf::from(real)
}

fn plant(root: &Path, files: &[(&str, usize)]) {
    for (name, size) in files {
        let full = root.join(name);
        if let Some(dir) = full.parent() {
            let _ = fs::create_dir_all(dir);
        }
        fs::write(&full, vec![b'x'; *size]).expect("写样本文件失败");
    }
}

/// JSON 字符串字面量转义（只覆盖夹具里会出现的字符：反斜杠与双引号）
fn jstr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 从 `@@PLANFILE@@{"id":"…","path":"…","size":N}` 里取 path 值（最小解析，不引依赖）
fn planfile_path(line: &str) -> Option<String> {
    let body = line.strip_prefix("@@PLANFILE@@")?;
    let key = "\"path\":";
    let at = body.find(key)? + key.len();
    let rest = &body[at..];
    if !rest.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let chars: Vec<char> = rest[1..].chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            '"' => return Some(out),
            '\\' if i + 1 < chars.len() => {
                out.push(chars[i + 1]);
                i += 2;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    None
}

/// 跑一次扫描的原始输出（不做路径裁剪）
fn scan_raw(rules_json: &str) -> (i32, String, String) {
    let argv = vec!["[\"diffProbe\"]".to_string(), "{}".to_string()];
    trim_finder::cleanup_scan::run_json(&argv, rules_json, None)
}

/// 取 `"pathCandidates":[` 后紧跟的是否就是 `]`（最小解析，不引依赖）
fn path_candidates_empty(out: &str) -> Option<bool> {
    let key = "\"pathCandidates\":[";
    let at = out.find(key)? + key.len();
    Some(out[at..].starts_with(']'))
}

/// 跑一次扫描，返回 (退出码, 命中相对路径集合, stderr)
fn scan_hits(root: &Path, rules_json: &str) -> (i32, BTreeSet<String>, String) {
    let (code, out, err) = scan_raw(rules_json);
    let mut hits = BTreeSet::new();
    for line in out.lines() {
        if let Some(p) = planfile_path(line) {
            let rel = Path::new(&p)
                .strip_prefix(root)
                .map(|x| x.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| p.clone());
            hits.insert(rel);
        }
    }
    (code, hits, err)
}

/// 条目骨架（到 prov 为止），两种目标形态各接各的尾巴
const ITEM_HEAD: &str = r#"{"id":"diffProbe","name":"规则行为差分探针","ver":20260928,"risk":"low","evidence":"仅临时目录","recommended":true,"domain":"system","group":"probe","nature":"log","regenerable":true,"prov":{"source":"builtin","sourceClass":"independent","ref":"tests","reviewedAt":"2026-09-30"}"#;

fn wrap_item(item: &str) -> String {
    format!(
        r#"{{"version":2,"rulesVersion":20260928,"groups":[{{"key":"probe","title":"差分夹具","items":[{item}]}}]}}"#
    )
}

/// fileKeys 形态（文件型条目）：逐段拼，别把 JSON 塞进带转义的 format! —— 那样大括号极易数错
fn rules_json(target: &Path, pattern: &str, recurse: bool, extra: &str) -> String {
    let mut item = String::from(ITEM_HEAD);
    item.push_str(r#","fileKeys":[{"path":"#);
    item.push_str(&jstr(&target.to_string_lossy()));
    item.push_str(r#","pattern":"#);
    item.push_str(&jstr(pattern));
    item.push_str(r#","recurse":"#);
    item.push_str(if recurse { "true" } else { "false" });
    item.push_str("}]");
    item.push_str(extra);
    item.push('}');
    wrap_item(&item)
}

/// pathPs 形态（目录型条目）：`candidatesPs` 分支只在**没有 fileKeys** 时才可达
/// —— fileKeys 分支处理完会 `continue`，带 fileKeys 的条目根本走不到那段。
/// 注意 pathPs 与 candidatesPs 都要 PS 受限表达式（单引号字面量 / `$env:` 拼接），
/// 裸路径会被求值器判非法并 fail-closed 跳过。
fn rules_json_pathps(target: &Path, extra: &str) -> String {
    let mut item = String::from(ITEM_HEAD);
    item.push_str(r#","pathPs":"#);
    item.push_str(&jstr(&ps_lit(target)));
    item.push_str(extra);
    item.push('}');
    wrap_item(&item)
}

/// PS 单引号字面量形态（'' 转义撇号；临时目录不含撇号，与求值器语法对齐即可）
fn ps_lit(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy())
}

fn diff_sets(before: &BTreeSet<String>, after: &BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    (
        after.difference(before).cloned().collect(),
        before.difference(after).cloned().collect(),
    )
}

/// 改 pattern 一处，命中集多两个文件 —— 这就是"行为差分"最小可断言的形态
#[test]
fn 放宽_pattern_的命中差分可断言() {
    let root = temp_root("pattern");
    plant(&root, &[("a.log", 10), ("b.tmp", 20), ("keep.txt", 30), ("sub/c.log", 40)]);

    let (code1, narrow, err1) = scan_hits(&root, &rules_json(&root, "*.log", true, ""));
    assert_eq!(code1, 0, "扫描应正常退出：{err1}");
    let (code2, wide, err2) = scan_hits(&root, &rules_json(&root, "*", true, ""));
    assert_eq!(code2, 0, "扫描应正常退出：{err2}");

    assert_eq!(
        narrow,
        BTreeSet::from(["a.log".to_string(), "sub/c.log".to_string()]),
        "窄 pattern 应只命中两个 .log"
    );
    let (added, removed) = diff_sets(&narrow, &wide);
    assert_eq!(added, vec!["b.tmp".to_string(), "keep.txt".to_string()], "放宽后新增的命中");
    assert!(removed.is_empty(), "放宽 pattern 不该反而少命中：{removed:?}");

    fs::remove_dir_all(&root).ok();
}

/// recurse 翻转的差分只该出现在子目录里
#[test]
fn 关递归只该砍掉子目录命中() {
    let root = temp_root("recurse");
    plant(&root, &[("a.log", 5), ("sub/c.log", 5), ("sub/deep/d.log", 5)]);

    let (_, deep, _) = scan_hits(&root, &rules_json(&root, "*.log", true, ""));
    let (_, flat, _) = scan_hits(&root, &rules_json(&root, "*.log", false, ""));
    assert!(deep.contains("sub/deep/d.log"), "递归应命中两层：{deep:?}");
    assert!(!flat.contains("sub/deep/d.log"), "关递归却命中了两层：{flat:?}");
    assert!(!flat.contains("sub/c.log"), "关递归却命中了一层子目录：{flat:?}");
    assert!(flat.contains("a.log"), "关递归把本层也砍了，口径变了：{flat:?}");
    fs::remove_dir_all(&root).ok();
}

/// 时效护栏必须真能挡住命中（否则 minAgeDays 只是装饰）
#[test]
fn 时效护栏能把命中清零() {
    let root = temp_root("minage");
    plant(&root, &[("a.log", 5)]);
    let (_, plain, _) = scan_hits(&root, &rules_json(&root, "*.log", true, ""));
    assert!(plain.contains("a.log"), "基线就该命中：{plain:?}");
    let (_, aged, _) = scan_hits(&root, &rules_json(&root, "*.log", true, ",\"minAgeDays\":3650"));
    assert!(aged.is_empty(), "刚写的文件应被 minAgeDays=3650 挡掉，实际：{aged:?}");
    fs::remove_dir_all(&root).ok();
}

/// D19 钉桩（**双向**，2026-10-01 键名已对齐后翻向）：引擎现在读库里的真键名
/// `candidatesPs`/`globCandidatesPs`（`cleanup_scan.rs` 该分支的注释即登记处）。两个方向都断：
///   ① 写 `candidatesPs`（库里的真键名）时分支必须是活的（pathCandidates 真的收到它）——
///      否则钉桩是空的，下一个人删掉分支也照样绿；
///   ② 写旧缺陷键名 `candidates` 时必须被忽略——库里根本没有这个键，schema 也禁止它
///      （不在 itemFields），引擎这里同样不能给翻回去留活路。哪天这里红说明键名又被
///      改回去了：同步契约表 crossTrack 登记表与覆盖基线，别悄悄改枚举面。
#[test]
fn 活键双向钉桩_引擎认库里的键名_不认旧缺陷键名() {
    let root = temp_root("deadkey");
    plant(&root, &[("a.log", 5)]);
    let probe = jstr(&ps_lit(&root));

    // ① 库里的真键名：分支应当是活的
    let live = format!(",\"candidatesPs\":[{probe}]");
    let (code, out, err) = scan_raw(&rules_json_pathps(&root, &live));
    assert_eq!(code, 0, "引擎不认的键不该让整次扫描失败：{err}");
    assert_eq!(
        path_candidates_empty(&out),
        Some(false),
        "candidatesPs 分支没收到候选路径 —— D19 修复被回退了，先查引擎这段：{out}"
    );

    // ② 旧缺陷键名：库里不存在（schema 也不登记），引擎必须仍忽略
    let dead = format!(",\"candidates\":[{probe}]");
    let (code2, out2, err2) = scan_raw(&rules_json_pathps(&root, &dead));
    assert_eq!(code2, 0, "引擎不认的键不该让整次扫描失败：{err2}");
    assert_eq!(
        path_candidates_empty(&out2),
        Some(true),
        "candidates 竟被消费了 —— 旧缺陷键名被翻回来了。同步契约表 crossTrack 与覆盖基线后再改本用例：{out2}"
    );

    fs::remove_dir_all(&root).ok();
}

/// 前提检查：整个文件都建立在"扫描不动样本文件"上
#[test]
fn 扫描是只读的() {
    let root = temp_root("readonly");
    plant(&root, &[("a.log", 11), ("sub/c.log", 22)]);
    let (_, hits, _) = scan_hits(&root, &rules_json(&root, "*", true, ""));
    assert_eq!(hits.len(), 2, "用例本身失效：没扫到两个文件 {hits:?}");
    assert!(root.join("a.log").is_file(), "扫描把文件删了");
    assert!(root.join("sub/c.log").is_file(), "扫描把子目录文件删了");
    fs::remove_dir_all(&root).ok();
}

// ==================== R1-2 重解析点留痕 ====================

/// 造一个 junction（`mklink /J`）。不用 `std::os::windows::fs::symlink_dir`：
/// 那条API 建的是**符号链接**（要 SeCreateSymbolicLinkPrivilege），而本仓的跳过判据
/// 认的是 `FILE_ATTRIBUTE_REPARSE_POINT` 属性位 —— 符号链接与 junction 都带该位，
/// 但走不通符号链接会让用例在默认权限下直接造不出来。junction 零权限可建，
/// 且它才是真实踩坑场景（`AppData\Roaming\Application Data` 就是 junction）。
///
/// 返回 false 表示环境不允许建（精简版 Windows 缺 mklink）⇒ 调用方跳过断言，
/// **但不许把「造不出」当成「没跳过」**：此时用 `assert_skipped_or_unavailable`
/// 显式登记，而不是静默通过。
fn make_junction(link: &Path, target: &Path) -> bool {
    let out = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW：不弹黑窗（R1 起本仓统一）
        .output();
    matches!(out, Ok(o) if o.status.success())
}

/// 从扫描输出里取某个 item 行的 `skippedReparse` 值（0 表示没这行 / 值为 0）。
fn skipped_reparse_of(out: &str) -> Option<u64> {
    let key = "\"skippedReparse\":";
    let at = out.find(key)? + key.len();
    let rest = &out[at..];
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// R1-2.1 + R1-2.2：跳过必须留痕，且**留痕不许改变判定**。
///
/// 这两条是一对，缺一条就废：
/// - 只断「留痕 > 0」→ 实现可能顺手把跳过的也统计进 total（行为变更，没人审得出）；
/// - 只断「total 不变」→ 实现可能压根没记，静默丢目录。
///
/// 场景用真实形态：目标目录里有 1 个文件，根下挂一个指向它的 junction。
/// 期望：扫到 1 个文件、**total 仍为 1**、但 `skippedReparse == 1`。
/// 若 junction 没被跳过，文件会被计两次（那就是 bug，本断言正好抓住）。
#[test]
fn 重解析点跳过必须留痕且不改变命中判定() {
    let root = temp_root("reparse");
    plant(&root, &[("sub/real.log", 7)]);
    let link = root.join("junction_to_sub");
    if !make_junction(&link, &root.join("sub")) {
        // 环境造不出 junction：登记而不是静默通过。
        // 这是本用例唯一允许的「不执行断言」路径，且必须显式可见。
        eprintln!("[R1-2] 本环境无法创建 junction，跳过断言（造不出≠没跳过）");
        fs::remove_dir_all(&root).ok();
        return;
    }
    let (code, hits, err) = scan_hits(&root, &rules_json(&root, "*", true, ""));
    assert_eq!(code, 0, "扫描失败: {err}");
    assert_eq!(
        hits.len(),
        1,
        "junction 被跳过后只应命中 real.log 一次；命中 {hits:?} ⇒ 要么 junction 漏跳（重复计数），\
         要么真文件没扫到"
    );
    let (_, out, _) = scan_raw(&rules_json(&root, "*", true, ""));
    let skipped = skipped_reparse_of(&out);
    assert!(
        skipped.is_some(),
        "输出里没有 skippedReparse 字段 —— 跳过 junction 是静默的，用户看不出「为什么少了这些」: {out}"
    );
    assert_eq!(
        skipped.unwrap_or(0),
        1,
        "应恰好记1 个跳过的重解析点目录（造了 1 个 junction）: {out}"
    );
    // R1-2.2 反向判据：留痕**不许**改变判定字段。真文件仍在命中集里、且只一次。
    assert!(
        hits.iter().any(|h| h.ends_with("real.log")),
        "留痕不许影响命中集，真实文件必须仍在其中: {hits:?}"
    );
    fs::remove_dir_all(&root).ok();
}

/// R1-2.2 的另一半：**无 junction 时计数必须是 0**（不许无条件报非零）。
///
/// 这条是 R1-2 留痕的反向判据。实现很容易犯的错是「把计数初始化成非零」或者
/// 「无条件把 `visits` 当跳过数报出来」—— 那种实现在上面那条用例里也能过。
#[test]
fn 没有重解析点时留痕计数必须为零() {
    let root = temp_root("noreparse");
    plant(&root, &[("a.log", 5), ("sub/b.log", 6)]);
    let (_, out, _) = scan_raw(&rules_json(&root, "*", true, ""));
    assert_eq!(
        skipped_reparse_of(&out),
        Some(0),
        "样本树里没有 junction，计数必须是 0（无条件报非零 = 把别的计数冒充成跳过数）: {out}"
    );
    fs::remove_dir_all(&root).ok();
}

/// 2026-10-04 审计 §4.9：`excludePaths` 的目录/文件分类不得按扩展名推断。
///
/// 修前判据是 `extension().is_some()` ⇒ `Vendor.Tool` 这类**带点目录**被 routed
/// 进文件表，而 `path_excluded` 对文件表只做精确相等匹配 ⇒ 排除静默失效、
/// 整个子树照删。这里用行为差分钉住接线（不是只测分类纯函数）：排除条目
/// 指向真实存在的带点目录，断言其内部文件从命中集里消失。
///
/// 判红纪律（报告 §9.4）：本用例的夹具自检（无排除时带点目录内文件必须命中）
/// 先排除「夹具本身坏了」的可能，再断排除生效——避免把隔壁字段的失败误当通过。
#[test]
fn excludePaths_带点目录按目录前缀排除() {
    let root = temp_root("dotdir");
    plant(&root, &[("a.log", 10), ("Vendor.Tool/inside.log", 40)]);

    // 夹具自检：不排除时，带点目录内的文件必须在命中集里
    let (code0, base, err0) = scan_hits(&root, &rules_json(&root, "*.log", true, ""));
    assert_eq!(code0, 0, "扫描应正常退出：{err0}");
    assert!(
        base.contains("Vendor.Tool/inside.log"),
        "夹具自检失败：无排除时带点目录内文件未命中（夹具坏了，不是被测行为）: {base:?}"
    );

    // 排除条目是一个**带点目录**：修前它带扩展名 ⇒ 进文件表 ⇒ 精确匹配排不掉子树
    let extra = format!(
        r#","excludePaths":[{}]"#,
        jstr(&root.join("Vendor.Tool").to_string_lossy())
    );
    let (code1, excl, err1) = scan_hits(&root, &rules_json(&root, "*.log", true, &extra));
    assert_eq!(code1, 0, "扫描应正常退出：{err1}");
    assert!(
        !excl.contains("Vendor.Tool/inside.log"),
        "带点目录内的文件必须被排除（§4.9 修复没生效或被回退）: {excl:?}"
    );
    assert!(
        excl.contains("a.log"),
        "排除面不得殃及无辜 —— 目录外文件仍应命中: {excl:?}"
    );

    fs::remove_dir_all(&root).ok();
}

/// §4.9 反向面：指向**文件**的排除条目仍走精确匹配（分类器不得把文件误当目录
/// 做前缀排除——那会让 `keep.log` 之外所有 `xxx.log\...` 形态意外豁免，方向虽
/// 安全但口径混乱；钉住「按实况分类」的另一半）。
#[test]
fn excludePaths_指向文件仍按精确匹配排除() {
    let root = temp_root("dotfile");
    plant(&root, &[("a.log", 10), ("keep.log", 30)]);
    let extra = format!(
        r#","excludePaths":[{}]"#,
        jstr(&root.join("keep.log").to_string_lossy())
    );
    let (code, hits, err) = scan_hits(&root, &rules_json(&root, "*.log", true, &extra));
    assert_eq!(code, 0, "扫描应正常退出：{err}");
    assert!(hits.contains("a.log"), "未排除文件必须命中: {hits:?}");
    assert!(!hits.contains("keep.log"), "排除的文件必须从命中集消失: {hits:?}");
    fs::remove_dir_all(&root).ok();
}

/// 2026-10-04 审计 §4.8：未解析 %TOKEN% 必须被 REPORTED 而不是静默跳过。
///
/// 此前只有 fileKeys 主路径留痕，detect/configured 等字段的「永远 0 命中」没有任何
/// 对账依据。走 run_json 的 stderr 捕获验证留痕真的到达诊断通道（§3.2 收编的出口），
/// 且**判定不变**：该 detect 条目按原文判不存在（规则视为未安装），只是现在有话说。
#[test]
fn detect_未解析token必须留痕且不改判定() {
    let root = temp_root("tokdiag");
    plant(&root, &[("a.log", 10)]);
    let item = format!(
        r#"{},"detect":[{{"type":"file","path":{}}}]}}"#,
        ITEM_HEAD,
        jstr(&format!(r"{}\%TRIM_NO_SUCH_VAR_XYZ%\x", root.display()))
    );
    let (code, hits, err) = scan_hits(&root, &wrap_item(&item));
    assert_eq!(code, 0, "扫描应正常退出: {err}");
    assert!(
        err.contains("TRIM_NO_SUCH_VAR_XYZ") && err.contains("detect[].path"),
        "未解析 token 必须经 err_line 留痕（捕获模式 stderr）: {err}"
    );
    // 判定不变的另一半：未解析 detect 按「未安装」处理（不带未解析路径的条目照常命中）
    let (code2, hits2, err2) = scan_hits(&root, &rules_json(&root, "*.log", true, ""));
    assert_eq!(code2, 0, "扫描应正常退出: {err2}");
    assert!(hits2.contains("a.log"), "正常条目不受留痕改动影响: {hits2:?}");
    assert!(!hits.contains("a.log"), "detect 不命中时条目不得进命中集（判定语义原样）: {hits:?}");
    fs::remove_dir_all(&root).ok();
}
