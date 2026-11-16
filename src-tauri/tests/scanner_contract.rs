//! 扫描器公共契约测试（主仓可执行，架构优化 P3）。
//!
//! `native-scanner/` 是主仓 path 依赖、**非 workspace 成员**（见 `src-tauri/Cargo.toml`
//! 的注释），主仓 `cargo test` 跑不到它自带的 `tests/`——扫描器公共行为此前只有
//! `tools/check-scan-rule-diff.mjs` 的规则差分间接覆盖。本文件用 `trim_finder` 公共
//! API 直调，钉四类契约：重复分组、空文件时效闸、年龄护栏、回收站原语 fail-closed；
//! 由 `tools/check-scanner-contract.mjs` 包装成必跑门禁。
//!
//! 样本纪律：全部样本在本文件自建（仓库 `target/` 下的自删守卫沙箱，带 pid 防并行
//! 互删）；不进 %TEMP%——`tempFiles` 清理条目的扫描根就是 %TEMP%（见
//! `tools/check-test-sandbox.mjs` 头注释），且空文件扫描按「用户目录排除」滤掉
//! %USERPROFILE% 子树，%TEMP% 在其内，进去会被扫不到。回收站用例只测不存在路径的
//! fail-closed 形态：不真删任何文件、不依赖也不产生真实回收站状态。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use trim_finder::cleanup_scan::{rule_age_guard, AgeAxis, AgeGuard};
use trim_finder::scan::{delete, duplicates, empty, Sink};

// ---------- 基座：采集 sink / 守卫沙箱 / 时间拨动 ----------

/// 行协议采集 sink。`item` 同时留下 Sink 参数交出的**原生路径**与行文本：
/// 行内 `path` 字段经 unix 化（审查 v2-M5 的既有口径），断言一律以原生路径为身份。
#[derive(Default)]
struct Collect {
    rows: Mutex<Vec<(PathBuf, String)>>,
}

impl Sink for Collect {
    fn item(&self, path: &Path, line: &str) {
        self.rows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((path.to_path_buf(), line.to_string()));
    }
    fn progress(&self, _n: u64) {}
    fn scanned(&self, _n: u64) {}
    fn warn(&self, _m: &str) {}
}

impl Collect {
    /// item 行解析成 (原生路径, JSON)。行协议形态：`@@ITEM@@{...}`，缺前缀/坏 JSON 直接 panic——
    /// 契约测试里「行协议坏了」就是被测对象坏了，不是断言写错。
    fn item_rows(&self) -> Vec<(PathBuf, serde_json::Value)> {
        self.rows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(p, line)| {
                let body = line.strip_prefix("@@ITEM@@").expect("行协议缺 @@ITEM@@ 前缀");
                (p.clone(), serde_json::from_str(body).expect("行协议 JSON 解析失败"))
            })
            .collect()
    }
}

/// 自删守卫沙箱（Drop 兜底：断言失败 / panic / 早退都带走目录）。
/// 根放仓库 `target/` 下、目录名带 pid + 用例 tag——同一测试进程并行用例互不覆盖，
/// 复用 `native-scanner/src/scan.rs` 内部测试同款落点理由（target 不在用户目录子树）。
struct Sandbox(PathBuf);

impl Sandbox {
    fn new(tag: &str) -> Self {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("trim-scanner-contract-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("建沙箱失败");
        Sandbox(p)
    }

    fn write(&self, name: &str, content: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        fs::write(&p, content).expect("写样本失败");
        p
    }

    fn root_str(&self) -> String {
        self.0.to_string_lossy().to_string()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 把文件创建时间拨到指定时刻（SetFileTime 只写创建位；std 只能读创建时间）。
/// 形状同 `src-tauri/src/engine/shellicon.rs` 的测试辅助，`windows` 是主 crate 直依赖。
fn set_creation_time(p: &Path, t: SystemTime) {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, FILETIME, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, SetFileTime, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_SHARE_MODE, OPEN_EXISTING,
    };
    let wide: Vec<u16> = p.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let h = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_MODE(1 | 2),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .expect("CreateFileW 失败");
    // FILETIME = 1601-01-01 起 100ns 计数；Unix 纪元偏移 11644473600s
    let units = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("时间须在 Unix 纪元之后")
        .as_nanos() as u64
        / 100
        + 116_444_736_000_000_000;
    let ft = FILETIME {
        dwLowDateTime: (units & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (units >> 32) as u32,
    };
    unsafe {
        SetFileTime(h, Some(&ft), None, None).expect("SetFileTime 失败");
        let _ = CloseHandle(h);
    }
}

/// Unix 秒 → UTC 公历年（Howard Hinnant civil_from_days 含月序修正）。
/// 与 `native-scanner/src/scan.rs` 的 `civil_year` 同算法——那边是私有 fn，两份只用于
/// 一月跨年窗口的分支选择，两侧各自都有真断言兜底。
fn unix_year(unix_secs: i64) -> i64 {
    let days = unix_secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    yoe + era * 400 + mp / 10
}

// ---------- 契约 1：重复文件 ----------

/// 两个同内容文件必须进同一个 content 重复组（kept/candidate 各一、size 为真身字节数），
/// 不同内容的文件不属于任何组。同名分组优先，故成员用**不同名**样本——命中 content
/// 指纹路径而不是 name 路径，两种命中形态由 name 分组的实现细节自证（不在此钉）。
#[test]
fn duplicates_同内容成组_不同内容不成组() {
    let sb = Sandbox::new("dup");
    let payload = b"trim-contract-duplicate-payload-alpha";
    sb.write("alpha_dupe.txt", payload);
    sb.write("beta_dupe.txt", payload);
    let p3 = sb.write("gamma_solo.txt", b"trim-contract-unique-payload-gamma");
    // Sink 交出的是 canonical 真身（`\\?\` verbatim 形态，扫描从 canonical 根派生），
    // 身份比对两侧同一形态——普通形态比对会变成恒绿的假断言
    let p3_canon = fs::canonicalize(&p3).expect("canonicalize 失败");

    let sink = Collect::default();
    duplicates(&[sb.root_str()], 1, &sink);
    let rows = sink.item_rows();
    let dup: Vec<&(PathBuf, serde_json::Value)> =
        rows.iter().filter(|(_, j)| j["type"] == "duplicate").collect();

    assert_eq!(dup.len(), 2, "恰好 2 条 duplicate 行（同内容一对成一组）：{rows:?}");
    let (j0, j1) = (&dup[0].1, &dup[1].1);
    assert_eq!(j0["group"], j1["group"], "两个同内容文件必须在同一重复组");
    assert_eq!(j0["match"], "content");
    assert_eq!(j1["match"], "content");
    assert_eq!(j0["size"].as_u64(), Some(payload.len() as u64));
    assert_eq!(j1["size"].as_u64(), Some(payload.len() as u64));
    let roles: BTreeSet<String> = [j0, j1]
        .iter()
        .map(|j| j["role"].as_str().expect("role 字段").to_string())
        .collect();
    assert_eq!(
        roles,
        BTreeSet::from(["kept".to_string(), "candidate".to_string()]),
        "组内角色必须 kept/candidate 各一（最新者 kept）：{roles:?}"
    );
    // 成员身份按 Sink 交出的原生路径（行内 path 已 unix 化，不作身份判据）
    let names: Vec<String> = dup
        .iter()
        .map(|(p, _)| p.file_name().expect("样本必带文件名").to_string_lossy().to_string())
        .collect();
    assert!(
        names.contains(&"alpha_dupe.txt".to_string()) && names.contains(&"beta_dupe.txt".to_string()),
        "组成员必须恰为两个同内容样本：{names:?}"
    );
    assert!(!rows.iter().any(|(p, _)| p == &p3_canon), "不同内容的文件不属于任何结果行：{rows:?}");
}

// ---------- 契约 2：空文件 ----------

/// 空文件扫描只收「满 14 天 + 本年内创建」的零字节样本；非空文件不得进任何结果行。
/// 样本创建时间拨到 15 天前（> EMPTY_MIN_AGE）。一月上旬（UTC 1–15 日）锚点会落到
/// 上一年，「满 14 天」与「本年内」两条闸互斥 ⇒ 两个样本都被滤掉，空结果也是契约
/// （宁可不收）；其余日期走正向分支。
#[test]
fn empty_只收满龄本年空文件_非空不收() {
    let sb = Sandbox::new("empty");
    let stale_empty = sb.write("stale_empty.txt", b"");
    let full = sb.write("fresh_full.txt", b"trim-contract-nonempty-payload");
    // 期望侧也取 canonical 真身：empty() 从 canonical 根派生路径，Sink 交出的是
    // `\\?\` verbatim 形态（正是审查 v2-M5 说的「原生路径真身」），普通形态比对恒假
    let stale_canon = fs::canonicalize(&stale_empty).expect("canonicalize 失败");
    let full_canon = fs::canonicalize(&full).expect("canonicalize 失败");

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("系统时钟须在 Unix 纪元后")
        .as_secs() as i64;
    let anchor = now - 15 * 86_400;
    let cross_year = unix_year(anchor) != unix_year(now);
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(anchor as u64);
    set_creation_time(&stale_empty, t);
    set_creation_time(&full, t);

    let sink = Collect::default();
    empty(&[sb.root_str()], &sink);
    let rows = sink.item_rows();
    let empty_rows: Vec<&(PathBuf, serde_json::Value)> =
        rows.iter().filter(|(_, j)| j["type"] == "emptyfile").collect();

    if cross_year {
        assert!(
            rows.is_empty(),
            "跨年窗口内满龄与本年内互斥：两样本都必须被时效闸滤掉（宁可不收）：{rows:?}"
        );
        return;
    }
    assert_eq!(empty_rows.len(), 1, "只命中满龄的 0 字节样本：{rows:?}");
    assert_eq!(empty_rows[0].0, stale_canon, "命中的必须是那个空样本（Sink 原生路径真身）");
    assert!(!rows.iter().any(|(p, _)| p == &full_canon), "非空文件不得进任何结果行：{rows:?}");
}

// ---------- 契约 3：年龄护栏 ----------

/// 规则年龄护栏的 fail-closed 契约：mtime 轴太新拒/够老放行；轴枚举非法 ⇒ Invalid
/// 一律太新（不许「字段读不懂 ⇒ 无护栏 ⇒ 照删」）；元数据读不到 ⇒ 太新；
/// 时间戳在未来 ⇒ 太新；tighten 只收紧不放宽，Off 不被全局策略凭空加护栏。
#[test]
fn age_guard_太新拒够老放行_非法与读不到fail_closed() {
    let sb = Sandbox::new("age");
    let old = sb.write("old-enough.dat", b"x");
    let fresh = sb.write("fresh.dat", b"y");
    // std 侧直接拨 mtime（File::set_modified），不走 FFI——年龄护栏吃的就是 mtime
    let h = fs::OpenOptions::new().write(true).open(&old).expect("重开样本失败");
    h.set_modified(SystemTime::now() - Duration::from_secs(8 * 86_400))
        .expect("拨 mtime 失败");
    drop(h);

    let guard = rule_age_guard(None, Some(7.0), Some("mtime"));
    assert!(
        matches!(guard, AgeGuard::On { axis: AgeAxis::Mtime, .. }),
        "7 天 + mtime 必须解析成 On 护栏：{guard:?}"
    );
    assert!(guard.old_enough_path(&old), "mtime 8 天前 > 阈值 7 天 ⇒ 放行");
    assert!(!guard.old_enough_path(&fresh), "刚写完的文件 ⇒ 太新拒绝");
    assert!(
        !guard.old_enough_at(Some(SystemTime::now() + Duration::from_secs(3_600))),
        "时间戳在未来一律按太新（fail-closed）"
    );
    assert!(
        !guard.old_enough_path(&sb.0.join("no-such-file.dat")),
        "元数据读不到 ⇒ 太新（fail-closed）"
    );

    // 轴枚举非法 ⇒ Invalid：连 8 天前的老文件也拒——Invalid 已是最严一档
    let bad = rule_age_guard(None, Some(7.0), Some("bogus-axis"));
    assert_eq!(bad, AgeGuard::Invalid, "非法轴枚举必须解析成 Invalid：{bad:?}");
    assert!(!bad.old_enough_path(&old), "护栏字段非法必须 fail-closed，不许退化成无护栏");

    // tighten（G-2 全局策略）：只收紧不放宽；Off 不被凭空加护栏；Invalid 不因全局变松
    let tightened = guard.tighten(Some(30));
    assert!(!tightened.old_enough_path(&old), "全局 30 天并入后 8 天 < 30 天 ⇒ 拒绝");
    assert_eq!(guard.tighten(Some(0)), guard, "全局 0 = 关闭（非取消护栏），规则阈值继续生效");
    assert_eq!(AgeGuard::Off.tighten(Some(30)), AgeGuard::Off);
    assert_eq!(bad.tighten(Some(30)), AgeGuard::Invalid);
}

// ---------- 契约 4：回收站原语 ----------

/// 回收站原语的 fail-closed 形态：对不存在路径必须 Err（不许假成功），删除链必须如实
/// 回执 delresult status=fail + mode=trash-failed（M3/N-5 红线：回收站失败即失败，
/// 绝不静默转永久删除）。全程唯一目标是这条不存在的路径——不碰任何真实文件、
/// 不依赖也不产生真实回收站状态。
#[test]
fn recycle_对不存在路径fail_closed_不产生删除副作用() {
    let sb = Sandbox::new("trash");
    let ghost = sb.0.join("never-existed.bin");

    let r = trim_finder::scan::recycle::send_to_trash_os(ghost.as_os_str());
    assert!(r.is_err(), "对不存在路径必须报错，不许假成功：{r:?}");
    assert!(!ghost.exists(), "原语不得凭空创建路径");

    let sink = Collect::default();
    delete(&[("file".to_string(), ghost.as_os_str().to_os_string())], None, &sink);
    let rows = sink.item_rows();
    let del: Vec<&serde_json::Value> =
        rows.iter().map(|(_, j)| j).filter(|j| j["type"] == "delresult").collect();
    assert_eq!(del.len(), 1, "恰好一条 delresult 回执：{rows:?}");
    assert_eq!(del[0]["status"], "fail", "删除失败必须如实回执（不静默转永久删）");
    assert_eq!(del[0]["mode"], "trash-failed", "回执必须落在 trash-failed 档（失败不降级）");
    assert_eq!(del[0]["freed"].as_u64(), Some(0), "失败条目 freed 计 0");
    assert!(!ghost.exists());
}
