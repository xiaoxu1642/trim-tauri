//! 残留链共用的两个小件（原 `uninstall:dead-scan` 的采集/判定已随「机-wide 扫描整条退役」删除）：
//!
//! - `residue_snapshot_put`：按 origin 分桶替换的执行快照写入，`residue.rs` 的四类扫描在用；
//! - `dead_landing` / `expand_pct`：从 `ImagePath` / `UninstallString` 这类原串里解析「它记着
//!   哪个文件」的唯一解析器 —— `services_orphan` / `vendor_registry` 与新的服务/驱动残留检测
//!   共用同一实现（§5.16/N6：判据只许一份）。落点解析不出时返回 `None`（无证据），
//!   调用方必须把 None 当**无证据**而不是"不存在"。

use serde_json::Value;
use super::helpers::*;

/// 快照槽按 origin 分桶替换。
///
/// 为什么不能整槽覆盖：面板现在同时展示多组候选，先扫的那组会在后一次扫描后被
/// 快照闸判成「不在本次扫描快照中」，用户看到的勾选项点下去就报错。
/// M4 的应用数据遗留链其实已经有这个坑（它覆盖掉单程序残留的快照），一并收口。
pub(super) fn residue_snapshot_put(label: &str, origin: &str, findings: Vec<Value>) {
    const SNAPSHOT_CAP: usize = 400;
    // v4 P2-F（R2-M02）：origin 由**本函数**逐条打标 —— 生产侧此前 0 处赋值（候选对象
    // 里根本没有该字段），而下面的分桶过滤按 `origin != Some(origin)` 判：没有字段 ⇒
    // `None != Some(_)` 恒真 ⇒ 旧条目永不被清 ⇒ 重扫只累加（触顶 400 后 truncate 是
    // 从头部截，等于**保旧砍新**：用户刚扫出来的候选反而被丢）。在入口统一打标后，
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
    // v4 P2-F（R2-M02）：origin 由**本函数**逐条打标 —— 生产侧此前 0 处赋值（候选对象
    // 里根本没有该字段），而下面的分桶过滤按 `origin != Some(origin)` 判：没有字段 ⇒
    // `None != Some(_)` 恒真 ⇒ 旧条目永不被清 ⇒ 重扫只累加（触顶 400 后 truncate 是
    // 从头部截，等于**保旧砍新**：用户刚扫出来的候选反而被丢）。在入口统一打标后，
    // 调用方不写 origin 也成立（「谁调谁负责每条形」这条纪律不再外漏成一个必踩的坑）。
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
    merged.extend(findings);
    if merged.len() > SNAPSHOT_CAP {
        merged.truncate(SNAPSHOT_CAP);
    }
    store.insert(label.to_string(), (crate::engine::now_ms(), merged));
}

/// `%VAR%` 展开。**任一变量取不到就返回 None**：把没展开的串继续往下判，等于
/// 拿一个本机根本不存在的路径去判"落点已消失"，那是自己造出来的假阳性。
pub(super) fn expand_pct(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        match tail.find('%') {
            Some(j) => {
                let name = &tail[..j];
                if name.is_empty() {
                    out.push('%');
                } else {
                    out.push_str(&std::env::var(name).ok()?);
                }
                rest = &tail[j + 1..];
            }
            None => {
                out.push('%');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    Some(out)
}

/// 从 `UninstallString` / 服务 `ImagePath` / App Paths 默认值里取出「它记着哪个文件」。
///
/// `None` = 判不出来（相对名、无扩展名、`Device\` 形态、变量展开不了），
/// 调用方必须把 None 当**无证据**而不是"不存在"。
/// 截参数的口径：带引号取引号内；不带引号就在第一个 `.exe/.dll/.sys` 之后切断
/// （注册表里没引号的路径只能靠扩展名边界分参数），且结果必须以这三种扩展名结尾。
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
            let low = expanded.to_lowercase();
            let cut = [".exe", ".dll", ".sys"]
                .iter()
                .filter_map(|e| low.find(e).map(|i| i + e.len()))
                .min();
            match cut {
                Some(end) => expanded.chars().take(end).collect(),
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
