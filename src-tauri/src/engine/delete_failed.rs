//! 删除失败回执台账（进程内）：「登记面只认失败回执」这条安全前置的唯一载体。
//!
//! 为什么要它（R2a-M03）：重启后删除（PFRO）是**永久删**出口，五道约束的第一道是
//! 「只收删除失败项」。旧写法这道约束只由渲染层维持 —— `cleanup.js` 的
//! `collectFailedPaths` 与 `residue-window.js` 的失败文件筛选各自过滤一遍，
//! 命令体里没有任何判据 ⇒ 换一个消费方、或渲染层被改一句，任意文件都能被
//! 登记成「重启即删」，而 PFRO 登记不经过回收站、不可还原。
//!
//! 本模块把「本会话哪些文件的删除**没有成功**」记在命令体侧，
//! `uninstall_pending_add` 的闸循环据此核对：登记面从此只认失败回执。
//!
//! 槽键带「域」这一维（AGENTS §5.25）：残留域（副窗）与清理域（主窗）的失败回执
//! 互不相干 —— 纯 label 会让两个域的「本批失败文件」互相顶账。
//!
//! B2-8（R2a-M08 拍板 = 改代码收窄）：光有「域」这一维不够。`DOMAIN_CLEANUP` 一格里同时
//! 装着**常规清理（v3.3.0 固定永久删）**与**fileclean（回收站）**两条链的失败回执，
//! 按域名收窄会把 fileclean 的合法登记一起拒掉；所以收紧落在**每条回执**上：
//! `record()` 带 `recyclable: bool`，`is_failed_in_session` 只认 `true`。

use std::collections::HashMap;
use std::sync::Mutex;

/// 残留域：残留副窗那条删除链（回收站优先）。
pub const DOMAIN_RESIDUE: &str = "residue";
/// 清理域：主窗常规清理链（v3.3.0 裁定：固定永久删）+ 文件清理链（同属 cleanup.js 那条链）。
pub const DOMAIN_CLEANUP: &str = "cleanup";

/// 单槽路径上限：失败集合只增不减（见 [`record`] 的合并口径），封顶防长会话无界涨。
/// 超限丢最旧的（那些路径要么已删、要么已不在），不影响本批新回执。
const MAX_SLOT_PATHS: usize = 1024;

/// 槽条目：`(路径, 该次失败是否来自**可回收**的删除链)`。
///
/// B2-8（R2a-M08 拍板 = 改代码收窄）：本台账同时承载「常规清理（v3.3.0 固定永久删）」与
/// 「fileclean / 残留链（回收站）」两条删除链。永久删失败的文件**不能**降级成
/// 「重启后删除」——那也是永久删，而且绕过了回收站。所以每条回执必须带上「这次是怎么删的」，
/// 登记闸只认 `recyclable=true`。
type FailedEntry = (String, bool);

/// 槽：`{label}|{domain}` → 该槽累计的删除失败文件（路径 + 可回收性）。
static FAILED: Mutex<Option<HashMap<String, Vec<FailedEntry>>>> = Mutex::new(None);

fn slot_key(label: &str, domain: &str) -> String {
    crate::engine::snapshot::domain_key(label, domain)
}

/// 记录本批「删除没有成功」的文件路径（**并集**入该槽，不覆盖旧值）。
///
/// 为什么是并集而不是覆盖：删除回执是**会话级事实** ——「这个文件 Trim 删不掉」。
/// 覆盖会让早先那批的失败文件被后一批的回执顶掉，而用户往往是在**后一批跑完之后**
/// 才回到前一批的失败引导去点「登记到重启后删除」⇒ 命中不到回执、登记被拒，
/// 用户被引导去做一件必然无效的事（同 `engine::snapshot::by_id` 去掉长度闸那次的同族病）。
/// 并集只会**变宽**、不会引入「非失败文件」：集合里每条都是某次真实删除的失败回执。
///
/// B2-8：`recyclable` 由**调用点**按自己那条链的删除方式传入 —— 回收站链 `true`、
/// 固定永久删链 `false`。同一路径先后被两条链试过时两条例都留着（路径相同、可回收性不同），
/// 因为「哪条链删过、怎么删的」是两个事实；登记闸只看有没有一条 `recyclable=true`。
pub fn record(label: &str, domain: &str, targets: Vec<String>, recyclable: bool) {
    let mut g = FAILED.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    let slot = m.entry(slot_key(label, domain)).or_default();
    for t in targets {
        let t = t.trim().to_string();
        if t.is_empty() {
            continue;
        }
        if let Some(hit) = slot.iter_mut().find(|(x, _)| x.eq_ignore_ascii_case(&t)) {
            // 同一路径又失败一次：可回收性取**并** —— 有一条来自回收站链就够登记，
            // 不许「先被永久删链试过」把后来的回收站失败咽掉（那会让用户最后一次
            // 真实的「删不掉、但至少能进回收站」事实被前面的记录覆盖）。
            hit.1 = hit.1 || recyclable;
            continue;
        }
        slot.push((t, recyclable));
    }
    if slot.len() > MAX_SLOT_PATHS {
        let drop = slot.len() - MAX_SLOT_PATHS;
        slot.drain(0..drop);
    }
}

/// 该目标是否命中**指定槽**（某窗口某域）记录的失败回执。
///
/// 路径比较大小写不敏感（Windows 路径语义）：回执里的路径与登记时送来的路径
/// 同一来源本应逐字相同，但渲染层序列化/JSON 往返不保证大小写，两侧判据必须同口径。
///
/// 本查询**不看** `recyclable`：它回答的是「这个槽里有没有这条失败记录」（UI 用来
/// 解释「为什么这条能点登记」），登记闸的判据是 [`is_failed_in_session`]。
pub fn is_failed(label: &str, domain: &str, target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    let g = FAILED.lock().unwrap_or_else(|e| e.into_inner());
    let Some(m) = g.as_ref() else { return false };
    let Some(list) = m.get(&slot_key(label, domain)) else {
        return false;
    };
    list.iter().any(|(t, _)| t.eq_ignore_ascii_case(target))
}

/// 该目标是否命中**本会话任一删除域**的、**可回收链**的失败回执（登记闸用）。
///
/// 为什么按会话查而不按「当前窗口的槽」查：失败回执是**会话级事实**，窗口 label
/// 只是落槽的路由键 —— 清理链在主窗、残留链在副窗，而两个消费方都能调
/// `pending_add`（`guard::PENDING_DELETE_WINDOWS` = 主窗 + 副窗）。按窗口查会把
/// 「谁产出的回执」与「谁来登记」绑在一起，一旦两端窗口不同就误拒。
/// 放宽到会话级不构成越权：集合里每条都是本机 Trim **真实删除失败**的文件，
/// 登记它正是用户点「登记到重启后删除」时已确认要做的事；闸拦的是「从没有失败过
/// 的文件」被塞进永久删出口。
///
/// B2-8：只认 `recyclable=true`。永久删链（常规清理）的失败项**不算** —— 登记到重启后
/// 删除同样是永久删，而且连回收站都不经过，等于把「删不掉」的东西换个更狠的方式删，
/// 用户的「我以为还能还原」预期会被打穿。
pub fn is_failed_in_session(target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    let g = FAILED.lock().unwrap_or_else(|e| e.into_inner());
    let Some(m) = g.as_ref() else { return false };
    m.values()
        .any(|list| list.iter().any(|(t, recyclable)| *recyclable && t.eq_ignore_ascii_case(target)))
}

/// 清空某窗口某域的失败回执（测试底座与显式失效用）。
pub fn clear(label: &str, domain: &str) {
    let mut g = FAILED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(m) = g.as_mut() {
        m.remove(&slot_key(label, domain));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 槽键必须带域：两个域在同一窗口下互不顶账（AGENTS §5.25）。
    #[test]
    fn 同窗两域的失败回执互不相干() {
        let label = "delete-failed-domain-test";
        record(label, DOMAIN_RESIDUE, vec!["C:\\a.txt".to_string()], true);
        record(label, DOMAIN_CLEANUP, vec!["C:\\b.txt".to_string()], true);
        assert!(is_failed(label, DOMAIN_RESIDUE, "C:\\a.txt"));
        assert!(!is_failed(label, DOMAIN_RESIDUE, "C:\\b.txt"));
        assert!(is_failed(label, DOMAIN_CLEANUP, "C:\\b.txt"));
        assert!(!is_failed(label, DOMAIN_CLEANUP, "C:\\a.txt"));
        clear(label, DOMAIN_RESIDUE);
        clear(label, DOMAIN_CLEANUP);
    }

    /// 大小写不敏感 + 未命中即拒。
    #[test]
    fn 路径比较大小写不敏感且未命中即拒() {
        let label = "delete-failed-case-test";
        record(label, DOMAIN_CLEANUP, vec!["C:\\Temp\\A.TXT".to_string()], true);
        assert!(is_failed(label, DOMAIN_CLEANUP, "c:\\temp\\a.txt"));
        assert!(!is_failed(label, DOMAIN_CLEANUP, "C:\\Temp\\B.TXT"));
        assert!(!is_failed(label, DOMAIN_CLEANUP, ""));
        clear(label, DOMAIN_CLEANUP);
    }

    /// 并集口径：后一批的回执**不得**把早先那批的失败文件顶掉。
    ///
    /// 判红自证：把 `record` 改回覆盖（`insert` 替换整槽）⇒ 首条断言红。
    #[test]
    fn 后一批回执不顶掉早先那批() {
        let label = "delete-failed-merge-test";
        record(label, DOMAIN_CLEANUP, vec!["C:\\first.txt".to_string()], true);
        record(label, DOMAIN_CLEANUP, vec!["C:\\second.txt".to_string()], true);
        assert!(
            is_failed(label, DOMAIN_CLEANUP, "C:\\first.txt"),
            "早先那批的失败文件必须仍在（用户往往是后跑完一批才回来登记前一批）"
        );
        assert!(is_failed(label, DOMAIN_CLEANUP, "C:\\second.txt"));
        clear(label, DOMAIN_CLEANUP);
    }

    /// 会话级查询：命中任一槽即算命中；没登记过的路径一律拒。
    ///
    /// 判红自证：把 `is_failed_in_session` 改成只看某个固定槽 ⇒ 首条断言红。
    #[test]
    fn 会话级查询命中任一槽且未登记即拒() {
        let label = "delete-failed-session-test";
        record(label, DOMAIN_RESIDUE, vec!["C:\\residue-fail.txt".to_string()], true);
        assert!(
            is_failed_in_session("C:\\residue-fail.txt"),
            "残留域登记的失败文件必须能被登记闸命中"
        );
        assert!(
            !is_failed_in_session("C:\\never-failed.txt"),
            "从未删除失败过的文件不得进永久删出口"
        );
        clear(label, DOMAIN_RESIDUE);
        assert!(!is_failed_in_session("C:\\residue-fail.txt"), "清槽后不得再命中");
    }

    /// B2-8：**写入点的可回收性必须与该链的实际删除方式一致** —— 台账再严，写入点标错也会白搭。
    /// 这条钉的是三处调用点的实参，不是 `record` 的语义（后者由上面三条用例钉）。
    ///
    /// 判红自证：把 `cleanup/scan_execute.rs` 写入点的 `false` 改成 `true` ⇒ 第一条断言红
    /// （常规清理是 v3.3.0 固定的永久删链，标成可回收就等于让永久删失败项进「重启后删除」）。
    #[test]
    fn 写入点的可回收性与删除方式一致() {
        let body_of = |src: &'static str| -> &'static str {
            let rest = src.split("delete_failed::record(").nth(1).unwrap_or("");
            rest.split(");").next().unwrap_or("")
        };
        let scan = body_of(include_str!("../commands/cleanup/scan_execute.rs"));
        assert!(
            scan.contains("false"),
            "常规清理是永久删链 ⇒ 写入点必须传 false：{scan}"
        );
        let fc = body_of(include_str!("../commands/fileclean.rs"));
        assert!(fc.contains("true"), "fileclean 走回收站 ⇒ 写入点必须传 true：{fc}");
        let rs = body_of(include_str!("../commands/uninstall/residue.rs"));
        assert!(rs.contains("true"), "残留链回收站优先 ⇒ 写入点必须传 true：{rs}");
        assert!(
            rs.contains("== \"fail\""),
            "skip 行从未被尝试删除，不许记成删除失败（旧写法是 `!= \"ok\"`）：{rs}"
        );
    }

    /// B2-8 验收①：常规清理（**固定永久删**链）的失败项不得进「重启后删除」登记闸 ——
    /// 登记到重启后删除同样是永久删，连回收站都不经过。
    ///
    /// 判红自证：把 `cleanup/scan_execute.rs` 写入点的 `false` 改成 `true` ⇒ 第一条断言红。
    #[test]
    fn 永久删链的失败项不得进登记闸() {
        let label = "delete-failed-b28-perm";
        record(label, DOMAIN_CLEANUP, vec!["C:\\perm-fail.txt".to_string()], false);
        assert!(
            !is_failed_in_session("C:\\perm-fail.txt"),
            "永久删链失败的文件不得进「重启后删除」（那一步也是永久删）"
        );
        // 分槽查询仍要看得见这条（UI 用它解释「为什么它在失败列表里」）——
        // 窄的只是**登记闸**，不是「失败事实本身」
        assert!(
            is_failed(label, DOMAIN_CLEANUP, "C:\\perm-fail.txt"),
            "收窄必须只落在登记闸上，不许把失败事实一并抹掉"
        );
        clear(label, DOMAIN_CLEANUP);
    }

    /// B2-8 验收②：回收站链的失败项**必可**登记。
    #[test]
    fn 回收站链的失败项可以登记() {
        let label = "delete-failed-b28-recycle";
        record(label, DOMAIN_CLEANUP, vec!["C:\\recycle-fail.txt".to_string()], true);
        assert!(is_failed_in_session("C:\\recycle-fail.txt"), "回收站链失败项必须可登记");
        clear(label, DOMAIN_CLEANUP);
    }

    /// B2-8：同一路径先后被两条链试过 ⇒ 可回收性**取并**（有一条来自回收站链就该能登记）。
    ///
    /// 判红自证：把 `record` 的去重改回「命中即 `continue`」（不合并 flag）⇒ 第二条断言红。
    #[test]
    fn 同一路径两条链都失败时按可回收性取并() {
        let label = "delete-failed-b28-both";
        record(label, DOMAIN_CLEANUP, vec!["C:\\both.txt".to_string()], false);
        assert!(!is_failed_in_session("C:\\both.txt"), "只有永久删链失败时不得登记");
        record(label, DOMAIN_CLEANUP, vec!["C:\\both.txt".to_string()], true);
        assert!(
            is_failed_in_session("C:\\both.txt"),
            "后来又走了回收站链 ⇒ 必须可登记（不许被前一条记录咽掉）"
        );
        clear(label, DOMAIN_CLEANUP);
    }
}
