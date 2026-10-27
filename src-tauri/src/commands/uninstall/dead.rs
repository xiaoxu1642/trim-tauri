//! 残留链共用的两个小件（原 `uninstall:dead-scan` 的采集/判定已随「机-wide 扫描整条退役」删除）：
//!
//! - `residue_snapshot_put`：按 origin 分桶替换的执行快照写入，`residue.rs` 的四类扫描在用；
//! - `dead_landing` / `expand_pct`：从 `ImagePath` / `UninstallString` 这类原串里解析「它记着
//!   哪个文件」的唯一解析器 —— `services_orphan` / `vendor_registry` 与新的服务/驱动残留检测
//!   共用同一实现（§5.16/N6：判据只许一份）。落点解析不出时返回 `None`（无证据），
//!   调用方必须把 None 当**无证据**而不是"不存在"。

use serde_json::Value;
use super::helpers::*;

/// 单轮执行快照容量：一个 label 的槽里最多同时存多少条候选（跨 origin 合计）。
///
/// R2a-L02：从 `residue_snapshot_put` 函数内的私有 const 提成模块常量，为的是让
/// 「各产源上限之和 / 单批执行上限 / 快照容量」三者能被一条用例现算对账
/// （`residue_trace_tests` 的 `r2a_l02_*`）—— 数字只许有一份出处。
pub(super) const SNAPSHOT_CAP: usize = 400;

/// 快照分桶替换，**返回真正落进快照的那一份**（渲染层必须展示这份，不是扫描产出的全量）。
///
/// 为什么不能整槽覆盖：面板现在同时展示多组候选，先扫的那组会在后一次扫描后被
/// 快照闸判成「不在本次扫描快照中」，用户看到的勾选项点下去就报错。
/// M4 的应用数据遗留链其实已经有这个坑（它覆盖掉单程序残留的快照），一并收口。
///
/// R2a-L02（面板与快照必须同源）：槽位装不下时旧写法是 `merged.truncate(SNAPSHOT_CAP)`，
/// 截掉的是**尾部 = 这一次刚扫出来的候选**，而命令仍把那一批全量回给渲染层 ⇒
/// 「面板看得见、快照里没有」，用户勾完点删除整批判过期。现在按剩余容量当场取舍并
/// 返回接受的子集，容量语义从"悄悄丢"变成"调用方拿得到事实"，也就此不再有保头砍尾这第二种答案。
pub(super) fn residue_snapshot_put(label: &str, origin: &str, findings: Vec<Value>) -> Vec<Value> {
    // v4 P2-F（R2-M02）：origin 由**本函数**逐条打标 —— 生产侧此前 0 处赋值（候选对象
    // 里根本没有该字段），而下面的分桶过滤按 `origin != Some(origin)` 判：没有字段 ⇒
    // `None != Some(_)` 恒真 ⇒ 旧条目永不被清 ⇒ 重扫只累加。在入口统一打标后，
    // 调用方不写 origin 也成立（「谁调谁负责每条形」这条纪律不再外漏成一个必踩的坑）。
    let findings: Vec<Value> = findings
        .into_iter()
        .map(|mut f| {
            if let Some(o) = f.as_object_mut() {
                o.insert("origin".into(), serde_json::json!(origin));
            }
            f
        })
        .collect();
    let mut store = residue_snapshots().lock().unwrap_or_else(|e| e.into_inner());
    let mut merged: Vec<Value> = store
        .get(label)
        .map(|(_, f)| {
            f.iter()
                .filter(|x| x.get("origin").and_then(Value::as_str) != Some(origin))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let room = SNAPSHOT_CAP.saturating_sub(merged.len());
    let accepted: Vec<Value> = findings.into_iter().take(room).collect();
    merged.extend(accepted.iter().cloned());
    store.insert(label.to_string(), (crate::engine::now_ms(), merged));
    accepted
}

/// `%VAR%` 展开。**任一变量取不到就返回 None**：把没展开的串继续往下判，等于
/// 拿一个本机根本不存在的路径去判"落点已消失"，那是自己造出来的假阳性。
///
/// A6-M01（v7.2 C07）：展开本身不再自实现——全仓唯一展开器是扫描器的
/// `expand_env_path`（对未定义/空值变量**保留原文**），本函数只负责把它转成
/// 本域要的 `Option` 语义：拿 `first_unexpanded_token` 判残留，有残留即 None。
/// 这样三个域（本文件 / 快捷指令 / 扫描器）对「变量取不到」只有一个结论来源，
/// 且展开与残留检测同源（§5.16 N6）。
pub(super) fn expand_pct(s: &str) -> Option<String> {
    let out = trim_finder::cleanup_scan::expand_env_path(s);
    if trim_finder::cleanup_scan::first_unexpanded_token(&out).is_some() {
        return None;
    }
    Some(out)
}

/// 无引号串里「可执行段」的切点：**只认段尾扩展名**（返回切点字节下标）。
///
/// 病根（R2a-M07）：旧写法取「第一个出现的扩展名子串」的位置切，切出来的前缀**不是这条
/// 注册表值记录过的落点**，分两支都错：
/// - 切在中间目录段上（`C:\Program Files\acme.exe\bin\tool.dll` → `…\acme.exe`）：
///   这个前缀从来不是文件，`exists()` 恒假 ⇒ 把用户没见过的路径写进「落点已不存在」的证据文案；
/// - 切在末段内部（`…\app.dll.host.exe` → `…\app.dll`）：`app.dll` 不存在而 `app.dll.host.exe`
///   照样存在 ⇒ **真落点还在却判成残留**，删的是「证据其实还在」的键（不安全方向）。
///
/// 现在只认「扩展名后面是结尾 / 空白 / 引号」的命中 —— 那才是可执行段真正结束的位置；
/// 后面紧跟 `\`、`/`、`.` 的都说明这是目录名或文件名中段，跳过。同一扩展名可能有多次出现，
/// 取**最靠前且边界成立**的那个。切点因此恒为原串的一个「段边界前缀」，不会凭空造出新落点。
fn cut_at_segment_end(low: &str) -> Option<usize> {
    let b = low.as_bytes();
    let mut best: Option<usize> = None;
    for ext in [".exe", ".dll", ".sys"] {
        let mut from = 0usize;
        while let Some(i) = low[from..].find(ext) {
            let end = from + i + ext.len();
            let boundary = match b.get(end) {
                None => true,
                Some(c) => c.is_ascii_whitespace() || *c == b'"',
            };
            if boundary {
                best = Some(best.map_or(end, |cur| cur.min(end)));
                break;
            }
            from = end;
        }
    }
    best
}

/// 从 `UninstallString` / 服务 `ImagePath` / App Paths 默认值里取出「它记着哪个文件」。
///
/// `None` = 判不出来（相对名、无扩展名、`Device\` 形态、变量展开不了），
/// 调用方必须把 None 当**无证据**而不是"不存在"。
/// 截参数的口径：带引号取引号内；不带引号就在**段尾**的 `.exe/.dll/.sys` 之后切断
/// （注册表里没引号的路径只能靠段尾扩展名分参数），且结果必须以这三种扩展名结尾。
pub(super) fn dead_landing(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let s = s.strip_prefix(r"\??\").unwrap_or(s);
    // `\SystemRoot\system32\...` 是服务表里的常见写法（不是 %SystemRoot%）
    let rewritten;
    let s = if s
        .get(..11)
        .map(|p| p.eq_ignore_ascii_case(r"\SystemRoot"))
        .unwrap_or(false)
    {
        rewritten = format!("{}{}", std::env::var("SystemRoot").ok()?, &s[11..]);
        rewritten.as_str()
    } else {
        s
    };
    let expanded = expand_pct(s)?;
    let head = match expanded.strip_prefix('"') {
        Some(q) => q.split('"').next().unwrap_or("").to_string(),
        None => {
            // U-A5-M07：切成两半的偏移必须同源。to_lowercase 是 full mapping（İ→i̇ 会变长），
            // 拿它的字节下标去切原串会错位；这里只做 ASCII 小写，长度/边界与原串一致。
            let low = expanded.to_ascii_lowercase();
            // 切点是「段尾扩展名」的结束位置 ⇒ 落点恒为原串的段边界前缀。这条不变量由
            // `dead_landing_landing_is_always_a_prefix_of_the_recorded_value` 机检（R2a-M07
            // 的要害是「造出值里从未记录过的落点」，光靠人读不出这件事）。
            match cut_at_segment_end(&low) {
                Some(end) => expanded[..end].to_string(),
                None => expanded.clone(),
            }
        }
    };
    let head = head.trim().to_string();
    if head.is_empty() {
        return None;
    }
    let b = head.as_bytes();
    let is_abs = (b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\')
        || head.starts_with(r"\\");
    if !is_abs {
        return None;
    }
    let low = head.to_lowercase();
    if !(low.ends_with(".exe") || low.ends_with(".dll") || low.ends_with(".sys")) {
        return None;
    }
    Some(head)
}
