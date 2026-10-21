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

use std::collections::HashMap;
use std::sync::Mutex;

/// 残留域：残留副窗那条删除链（回收站优先）。
pub const DOMAIN_RESIDUE: &str = "residue";
/// 清理域：主窗常规清理链（v3.3.0 裁定：固定永久删）+ 文件清理链（同属 cleanup.js 那条链）。
pub const DOMAIN_CLEANUP: &str = "cleanup";

/// 单槽路径上限：失败集合只增不减（见 [`record`] 的合并口径），封顶防长会话无界涨。
/// 超限丢最旧的（那些路径要么已删、要么已不在），不影响本批新回执。
const MAX_SLOT_PATHS: usize = 1024;

/// 槽：`{label}|{domain}` → 该槽累计的删除失败文件路径。
static FAILED: Mutex<Option<HashMap<String, Vec<String>>>> = Mutex::new(None);

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
pub fn record(label: &str, domain: &str, targets: Vec<String>) {
    let mut g = FAILED.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    let slot = m.entry(slot_key(label, domain)).or_default();
    for t in targets {
        let t = t.trim().to_string();
        if t.is_empty() {
            continue;
        }
        if slot.iter().any(|x| x.eq_ignore_ascii_case(&t)) {
            continue;
        }
        slot.push(t);
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
pub fn is_failed(label: &str, domain: &str, target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    let g = FAILED.lock().unwrap_or_else(|e| e.into_inner());
    let Some(m) = g.as_ref() else { return false };
    let Some(list) = m.get(&slot_key(label, domain)) else {
        return false;
    };
    list.iter().any(|t| t.eq_ignore_ascii_case(target))
}

/// 该目标是否命中**本会话任一删除域**的失败回执（登记闸用）。
///
/// 为什么按会话查而不按「当前窗口的槽」查：失败回执是**会话级事实**，窗口 label
/// 只是落槽的路由键 —— 清理链在主窗、残留链在副窗，而两个消费方都能调
/// `pending_add`（`guard::PENDING_DELETE_WINDOWS` = 主窗 + 副窗）。按窗口查会把
/// 「谁产出的回执」与「谁来登记」绑在一起，一旦两端窗口不同就误拒。
/// 放宽到会话级不构成越权：集合里每条都是本机 Trim **真实删除失败**的文件，
/// 登记它正是用户点「登记到重启后删除」时已确认要做的事；闸拦的是「从没有失败过
/// 的文件」被塞进永久删出口。
pub fn is_failed_in_session(target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    let g = FAILED.lock().unwrap_or_else(|e| e.into_inner());
    let Some(m) = g.as_ref() else { return false };
    m.values().any(|list| list.iter().any(|t| t.eq_ignore_ascii_case(target)))
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
        record(label, DOMAIN_RESIDUE, vec!["C:\\a.txt".to_string()]);
        record(label, DOMAIN_CLEANUP, vec!["C:\\b.txt".to_string()]);
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
        record(label, DOMAIN_CLEANUP, vec!["C:\\Temp\\A.TXT".to_string()]);
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
        record(label, DOMAIN_CLEANUP, vec!["C:\\first.txt".to_string()]);
        record(label, DOMAIN_CLEANUP, vec!["C:\\second.txt".to_string()]);
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
        record(label, DOMAIN_RESIDUE, vec!["C:\\residue-fail.txt".to_string()]);
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
}
