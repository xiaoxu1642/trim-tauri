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
//! 装着**常规清理（v3.3.0 固定永久删）**与**fileclean（回收站）**两条链的失败回执；
//! 永久删失败的文件**不能**降级成「重启后删除」——那也是永久删，而且绕过了回收站。
//!
//! R2a-M01（2026-11-01 重审）：光有「哪条链」这一维仍不够。同一条回收站链里，finder 的
//! delresult 把**回收站调用失败**（`trash-failed`，东西还在原位）与**安全拒绝**
//! （`rejected` / `reparse-ancestor` / `unrecoverable-name`，见
//! `native-scanner/src/scan.rs` 的 `delete`）都报成 `status:"fail"`；只有前者是
//! 「删不掉、可换时机重试」，后者是「拒绝删」。把安全拒绝登记进 PFRO，等于绕开删除链
//! 对活链/祖先重解析点的 TOCTOU 拒绝，把「拒绝」升级成「重启后永久删」。
//! 所以准入维度落在**每条回执的失败原因 [`DeleteFailMode`]**：只有 `trash-failed` 可登记。

use std::collections::HashMap;
use std::sync::Mutex;

/// 残留域：残留副窗那条删除链（回收站优先）。
pub const DOMAIN_RESIDUE: &str = "residue";
/// 清理域：主窗常规清理链（v3.3.0 裁定：固定永久删）+ 文件清理链（同属 cleanup.js 那条链）。
pub const DOMAIN_CLEANUP: &str = "cleanup";

/// 单槽路径上限：失败集合只增不减（见 [`record_modes`] 的合并口径），封顶防长会话无界涨。
/// 超限丢最旧的（那些路径要么已删、要么已不在），不影响本批新回执。
const MAX_SLOT_PATHS: usize = 1024;

/// 一条删除失败的**原因**（R2a-M01）：[`record_modes`] 登记时必带，登记闸只认
/// [`DeleteFailMode::TrashFailed`]。
///
/// 前三类安全拒绝与 finder delresult 的 `mode` 字面量一一对应
/// （`native-scanner/src/scan.rs` 的 `MODE_*` 常量）；跨 crate 不能共享代码，
/// 靠 [`DeleteFailMode::from_finder_mode`] 收口。未知字面量归 `Unknown`（fail-closed）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeleteFailMode {
    /// 回收站调用本身失败（被占用/权限）：东西还在原位，换时机重试有意义 —— **唯一**可登记。
    TrashFailed,
    /// 安全拒绝：受保护路径 / 活链目标等（finder `rejected`）。
    Rejected,
    /// 安全拒绝：祖先目录在执行前被换成重解析点（finder `reparse-ancestor`）。
    ReparseAncestor,
    /// 安全拒绝：文件名无法无损解码、保护清单判定不可靠（finder `unrecoverable-name`）。
    UnrecoverableName,
    /// 常规清理链（v3.3.0 固定永久删）的失败：再登记 PFRO 等于换更狠的方式删（B2-8）。
    PermanentDeleteFailed,
    /// 未知/未识别的失败原因 —— 不给「不认识的 mode」发登记资格。
    Unknown,
}

impl DeleteFailMode {
    /// finder delresult 的 `mode` 字面量 → 本枚举。
    /// 改名不同步时安全拒绝会落进 `Unknown`（仍不可登记，方向安全）。
    pub fn from_finder_mode(mode: &str) -> Self {
        match mode {
            "trash-failed" => Self::TrashFailed,
            "rejected" => Self::Rejected,
            "reparse-ancestor" => Self::ReparseAncestor,
            "unrecoverable-name" => Self::UnrecoverableName,
            _ => Self::Unknown,
        }
    }

    /// 是否够格进「重启后删除」：只有回收站调用本身失败的条目。
    fn registrable(self) -> bool {
        matches!(self, Self::TrashFailed)
    }
}

/// 槽条目：`(路径, 该次失败的原因)`。
type FailedEntry = (String, DeleteFailMode);

/// 槽：`{label}|{domain}` → 该槽累计的删除失败文件（路径 + 失败原因）。
static FAILED: Mutex<Option<HashMap<String, Vec<FailedEntry>>>> = Mutex::new(None);

fn slot_key(label: &str, domain: &str) -> String {
    crate::engine::snapshot::domain_key(label, domain)
}

/// 记录本批「删除没有成功」的文件路径及其失败原因（**并集**入该槽，不覆盖旧值）。
///
/// 为什么是并集而不是覆盖：删除回执是**会话级事实** ——「这个文件 Trim 删不掉」。
/// 覆盖会让早先那批的失败文件被后一批的回执顶掉，而用户往往是在**后一批跑完之后**
/// 才回到前一批的失败引导去点「登记到重启后删除」⇒ 命中不到回执、登记被拒，
/// 用户被引导去做一件必然无效的事（同 `engine::snapshot::by_id` 去掉长度闸那次的同族病）。
/// 并集只会**变宽**、不会引入「非失败文件」：集合里每条都是某次真实删除的失败回执。
///
/// 同一条路径先后被两条链/两种原因记过时，只保留**最宽**的登记资格（B2-8 的取并口径）：
/// 后来那条是 `trash-failed` 就升级为可登记，否则保留原值 —— 不许「先被永久删链试过」
/// 把后来的回收站失败咽掉，也不许一次安全拒绝把已有的回收站失败覆盖掉。
pub fn record_modes(label: &str, domain: &str, entries: Vec<(String, DeleteFailMode)>) {
    let mut g = FAILED.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    let slot = m.entry(slot_key(label, domain)).or_default();
    for (t, mode) in entries {
        let t = t.trim().to_string();
        if t.is_empty() {
            continue;
        }
        if let Some(hit) = slot.iter_mut().find(|(x, _)| x.eq_ignore_ascii_case(&t)) {
            if mode.registrable() {
                hit.1 = mode;
            }
            continue;
        }
        slot.push((t, mode));
    }
    if slot.len() > MAX_SLOT_PATHS {
        let drop = slot.len() - MAX_SLOT_PATHS;
        slot.drain(0..drop);
    }
}

/// 旧形态入口（链级可回收性）：`true` = 该链走回收站（按 `TrashFailed` 记）、
/// `false` = 永久删链（按 `PermanentDeleteFailed` 记）。
///
/// 保留原因：`tests/module_smoke.rs` 仍以四参形态调用（该文件不在本批改动范围）。
/// 生产调用点**一律**走 [`record_modes`] —— `recyclable` 表达不了「安全拒绝」这一维，
/// 拿它记 finder 的 fail 行正是 R2a-M01 的漏洞形态（安全拒绝被记成可登记）。
pub fn record(label: &str, domain: &str, targets: Vec<String>, recyclable: bool) {
    let mode = if recyclable {
        DeleteFailMode::TrashFailed
    } else {
        DeleteFailMode::PermanentDeleteFailed
    };
    record_modes(label, domain, targets.into_iter().map(|t| (t, mode)).collect());
}

/// 该目标是否命中**本会话任一删除域**的、**回收站调用失败**的回执（登记闸用）。
///
/// 为什么按会话查而不按「当前窗口的槽」查：失败回执是**会话级事实**，窗口 label
/// 只是落槽的路由键 —— 清理链在主窗、残留链在副窗，而两个消费方都能调
/// `pending_add`（`guard::PENDING_DELETE_WINDOWS` = 主窗 + 副窗）。按窗口查会把
/// 「谁产出的回执」与「谁来登记」绑在一起，一旦两端窗口不同就误拒。
/// 放宽到会话级不构成越权：集合里每条都是本机 Trim **真实删除失败**的文件，
/// 登记它正是用户点「登记到重启后删除」时已确认要做的事；闸拦的是「从没有失败过
/// 的文件」被塞进永久删出口。
///
/// B2-8 / R2a-M01：只认 [`DeleteFailMode::TrashFailed`]。永久删链的失败项不算
/// （登记到重启后删除同样是永久删、且连回收站都不经过）；安全拒绝项（活链、
/// 祖先重解析点、不可解码名）更不算 —— 那是 finder 删除链「拒绝删」，不是「删不掉」。
pub fn is_failed_in_session(target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    let g = FAILED.lock().unwrap_or_else(|e| e.into_inner());
    let Some(m) = g.as_ref() else { return false };
    m.values().any(|list| {
        list.iter()
            .any(|(t, mode)| mode.registrable() && t.eq_ignore_ascii_case(target))
    })
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

    /// 该目标是否命中**指定槽**（某窗口某域）记录的失败回执。
    ///
    /// R6b-L18：生产侧零调用方（唯一登记闸是 [`is_failed_in_session`]），旧的 pub 版本
    /// 还宣称「UI 用它解释为什么这条能点登记」—— 那条注释没有任何消费方对应。槽级读法
    /// 只有测试需要（「两域互不顶账」「失败事实本身仍看得见」都是按槽断言），故收进测试，
    /// 判据与生产同一份（`slot_key` + 大小写不敏感比较）。
    fn is_failed(label: &str, domain: &str, target: &str) -> bool {
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

    /// 槽键必须带域：两个域在同一窗口下互不顶账（AGENTS §5.25）。
    #[test]
    fn 同窗两域的失败回执互不相干() {
        let label = "delete-failed-domain-test";
        record_modes(label, DOMAIN_RESIDUE, vec![("C:\\a.txt".to_string(), DeleteFailMode::TrashFailed)]);
        record_modes(label, DOMAIN_CLEANUP, vec![("C:\\b.txt".to_string(), DeleteFailMode::TrashFailed)]);
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
        record_modes(label, DOMAIN_CLEANUP, vec![("C:\\Temp\\A.TXT".to_string(), DeleteFailMode::TrashFailed)]);
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
        record_modes(label, DOMAIN_CLEANUP, vec![("C:\\first.txt".to_string(), DeleteFailMode::TrashFailed)]);
        record_modes(label, DOMAIN_CLEANUP, vec![("C:\\second.txt".to_string(), DeleteFailMode::TrashFailed)]);
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
        record_modes(label, DOMAIN_RESIDUE, vec![("C:\\residue-fail.txt".to_string(), DeleteFailMode::TrashFailed)]);
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

    /// B2-8 / R2a-M01：**写入点的失败原因必须与该链的实际删除方式一致** —— 台账再严，
    /// 写入点标错也会白搭。这条钉的是三处调用点的实参，不是 `record` 的语义
    /// （后者由下面几条用例钉）。
    ///
    /// 判红自证：把 `cleanup/scan_execute.rs` 写入点的 `PermanentDeleteFailed` 改成
    /// `TrashFailed` ⇒ 第一条断言红（常规清理是 v3.3.0 固定的永久删链，标成回收站失败
    /// 就等于让永久删失败项进「重启后删除」）。
    #[test]
    fn 写入点的失败原因与删除方式一致() {
        let body_of = |src: &'static str| -> &'static str {
            let rest = src.split("delete_failed::record_modes(").nth(1).unwrap_or("");
            rest.split(");").next().unwrap_or("")
        };
        let scan = body_of(include_str!("../commands/cleanup/scan_execute.rs"));
        assert!(
            scan.contains("DeleteFailMode::PermanentDeleteFailed"),
            "常规清理是永久删链 ⇒ 写入点必须标 PermanentDeleteFailed：{scan}"
        );
        let fc = body_of(include_str!("../commands/fileclean.rs"));
        assert!(
            fc.contains("DeleteFailMode::TrashFailed"),
            "fileclean 走回收站 ⇒ 写入点必须标 TrashFailed：{fc}"
        );
        let rs = body_of(include_str!("../commands/uninstall/residue.rs"));
        assert!(
            rs.contains("DeleteFailMode::from_finder_mode"),
            "残留链必须带 finder 的 mode 进台账（R2a-M01：安全拒绝不得被记成可登记的删除失败）：{rs}"
        );
        assert!(
            rs.contains("== \"fail\""),
            "skip 行从未被尝试删除，不许记成删除失败（旧写法是 `!= \"ok\"`）：{rs}"
        );
    }

    /// B2-8 验收①：常规清理（**固定永久删**链）的失败项不得进「重启后删除」登记闸 ——
    /// 登记到重启后删除同样是永久删，连回收站都不经过。
    ///
    /// 判红自证：把 `cleanup/scan_execute.rs` 写入点的 `PermanentDeleteFailed` 改成
    /// `TrashFailed` ⇒ `is_failed_in_session` 那条断言红。
    #[test]
    fn 永久删链的失败项不得进登记闸() {
        let label = "delete-failed-b28-perm";
        record_modes(label, DOMAIN_CLEANUP, vec![("C:\\perm-fail.txt".to_string(), DeleteFailMode::PermanentDeleteFailed)]);
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
        record_modes(label, DOMAIN_CLEANUP, vec![("C:\\recycle-fail.txt".to_string(), DeleteFailMode::TrashFailed)]);
        assert!(is_failed_in_session("C:\\recycle-fail.txt"), "回收站链失败项必须可登记");
        clear(label, DOMAIN_CLEANUP);
    }

    /// R2a-M01 验收①：finder 的三类**安全拒绝**（`rejected` / `reparse-ancestor` /
    /// `unrecoverable-name`）在删除链里是「拒绝删」，不是「删不掉」——一律不得进
    /// 「重启后删除」登记闸。旧写法只按 `status=="fail" && kind=="file"` 全收，
    /// 于是删除链对活链/祖先 junction 的 TOCTOU 拒绝被降级成「重启后永久删」。
    ///
    /// 判红自证：把 `is_failed_in_session` 里的 `mode.registrable()` 判断去掉
    /// （凡在槽里就命中）⇒ 首条断言红。
    #[test]
    fn 安全拒绝类失败不得进登记闸() {
        let label = "delete-failed-r2am01-reject";
        let cases = [
            ("C:\\rejected.txt", DeleteFailMode::from_finder_mode("rejected")),
            ("C:\\reparse-anc.txt", DeleteFailMode::from_finder_mode("reparse-ancestor")),
            ("C:\\lossy-name.txt", DeleteFailMode::from_finder_mode("unrecoverable-name")),
        ];
        for (p, m) in cases {
            record_modes(label, DOMAIN_RESIDUE, vec![(p.to_string(), m)]);
        }
        for (p, m) in cases {
            assert!(
                !is_failed_in_session(p),
                "{m:?} 是删除链的安全拒绝，不得拿到「重启后永久删」的资格"
            );
            // 失败事实本身仍要看得见：窄的只是登记闸（与 B2-8 同一口径）
            assert!(is_failed(label, DOMAIN_RESIDUE, p), "失败回执本身不得被抹掉");
        }
        clear(label, DOMAIN_RESIDUE);
    }

    /// R2a-M01 验收②：残留链把 finder 的 `mode` 字面量原样映射 —— 只有 `trash-failed`
    /// 可登记，三类安全拒绝与未知字面量一律 fail-closed。
    ///
    /// 判红自证：把 `from_finder_mode` 的 `"rejected"` 分支改成 `TrashFailed` ⇒ 首轮红。
    #[test]
    fn finder_mode_映射只让回收站失败可登记() {
        assert!(
            DeleteFailMode::from_finder_mode("trash-failed").registrable(),
            "回收站调用失败是唯一可登记的失败原因"
        );
        for m in [
            "rejected",
            "reparse-ancestor",
            "unrecoverable-name",
            "recycled", // 只出现在 status=ok 行；万一混进来也不得可登记
            "",
            "some-future-mode",
        ] {
            assert!(
                !DeleteFailMode::from_finder_mode(m).registrable(),
                "{m:?} 不得拿到「重启后删除」的资格（未知原因 fail-closed）"
            );
        }
    }

    /// R2a-M01 验收③：真实的回收站失败（`trash-failed`）仍可登记 —— 收窄不能收成「全拒」。
    #[test]
    fn 回收站调用失败可以登记() {
        let label = "delete-failed-r2am01-trash";
        record_modes(
            label,
            DOMAIN_RESIDUE,
            vec![("C:\\trash-failed.txt".to_string(), DeleteFailMode::from_finder_mode("trash-failed"))],
        );
        assert!(
            is_failed_in_session("C:\\trash-failed.txt"),
            "回收站调用失败的条目必须可登记（否则真·删不掉的东西没有出口）"
        );
        clear(label, DOMAIN_RESIDUE);
    }

    /// 旧形态入口（`recyclable: bool`）只为 `tests/module_smoke.rs` 保留：`true` 必须
    /// 映射成 `trash-failed`（可登记）、`false` 映射成永久删失败（不可登记），与 B2-8 一致。
    ///
    /// 判红自证：把 shim 里的 `TrashFailed`/`PermanentDeleteFailed` 对调 ⇒ 两条断言同时红。
    #[test]
    fn 旧形态入口按链可回收性映射两档mode() {
        let label = "delete-failed-legacy-shim";
        record(label, DOMAIN_RESIDUE, vec!["C:\\legacy-true.txt".to_string()], true);
        record(label, DOMAIN_CLEANUP, vec!["C:\\legacy-false.txt".to_string()], false);
        assert!(
            is_failed_in_session("C:\\legacy-true.txt"),
            "recyclable=true 是回收站链 ⇒ 必须映射成 trash-failed 并可登记"
        );
        assert!(
            !is_failed_in_session("C:\\legacy-false.txt"),
            "recyclable=false 是永久删链 ⇒ 不得可登记"
        );
        clear(label, DOMAIN_RESIDUE);
        clear(label, DOMAIN_CLEANUP);
    }

    /// B2-8：同一路径先后被两条链试过 ⇒ 登记资格**取并**（有一条来自回收站链就该能登记）。
    ///
    /// 判红自证：把 `record` 的合并改成「命中即 `continue`」（不升级 mode）⇒ 第二条断言红。
    #[test]
    fn 同一路径两条链都失败时按登记资格取并() {
        let label = "delete-failed-b28-both";
        record_modes(label, DOMAIN_CLEANUP, vec![("C:\\both.txt".to_string(), DeleteFailMode::PermanentDeleteFailed)]);
        assert!(!is_failed_in_session("C:\\both.txt"), "只有永久删链失败时不得登记");
        record_modes(label, DOMAIN_CLEANUP, vec![("C:\\both.txt".to_string(), DeleteFailMode::TrashFailed)]);
        assert!(
            is_failed_in_session("C:\\both.txt"),
            "后来又走了回收站链 ⇒ 必须可登记（不许被前一条记录咽掉）"
        );
        clear(label, DOMAIN_CLEANUP);
    }
}
