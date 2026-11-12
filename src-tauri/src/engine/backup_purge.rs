//! 备份清除（2026-11-12 用户点名：备份还原页要能单个 / 多项删除备份）。
//!
//! 四类备份此前都只有「写 + 读 + 还原」，没有任何删除面，用户只能等保留上限
//! （50 份 / 20 批）自己裁掉。这里补上显式清除，且把四类收在同一处判：
//!
//! | kind         | 根（写入只认新根）            | 删除单位                            |
//! |--------------|-------------------------------|-------------------------------------|
//! | `reg`        | `cleanup-reg-backup`          | 主文件 `.reg` + 同目录封条           |
//! | `file`       | `cleanup-files-backup`        | 清单 `manifest-*.json` + 其独占副本  |
//! | `uninst-reg` | `uninstall-reg-backup`        | 主文件 `.reg` + 封条 + HKLM 摘要值   |
//! | `pack`       | `uninstall-restore-pack`      | 整个批次目录                        |
//!
//! 四条红线（缺一条就不成立）：
//! 1. **回收站优先**（AGENTS §3）：一律 `send_to_trash_os`，不做永久删；
//! 2. **根判定在前**：候选根先过 `protect::inspect_root`，junction 根直接跳过并留痕；
//! 3. **不删老根**：老根是升级前的最后退路，`backup_read_dirs` 只用来「看见」，
//!    删除只作用于 `backup_write_dir`（与 `paths::prune_backups` 同口径）；
//! 4. **连带件同生同死**：封条、清单引用的副本、还原包整目录 —— 只删主件会留下
//!    「看起来还能还原、点下去报错」的半截备份。
//!
//! 删除是用户显式动作，所以「删不掉」必须逐条如实回报（回收站满/被占用/不可读），
//! 不许 `let _ =` 静默吞掉。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::engine::{log, paths, protect};

/// 备份名总长上限（生成侧与准入侧共用一份，别在两处各写一个数）。
const BACKUP_NAME_MAX: usize = 120;

/// 备份名合法字节：ASCII 字母数字与 `-` `_` `.`（三类备份的生成器都只产出这一组）。
pub fn backup_name_byte_ok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
}

/// 清理域注册表备份名：`<毫秒>_reg_<规则id>_<序号>.reg`，单段、无空格、无分隔符。
///
/// 判据真源在本模块：命令层的列表/还原与这里的清除必须同一份（§5.16），
/// 各写一套的下场是「列表能看见、清除点不动」。
pub fn valid_reg_backup_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name.to_lowercase().ends_with(".reg")
        && !name.contains("..")
        && name.bytes().all(backup_name_byte_ok)
}

/// 文件备份清单名：`manifest-<纯数字>.json`（防路径穿越）。
pub fn valid_file_manifest_name(name: &str) -> bool {
    let Some(stem) = name.strip_prefix("manifest-").and_then(|s| s.strip_suffix(".json")) else {
        return false;
    };
    !stem.is_empty() && stem.len() <= 20 && stem.bytes().all(|b| b.is_ascii_digit())
}

/// 卸载域注册表备份名：`<毫秒>_<净化后的键末段>.reg`，字符集同生成侧。
pub fn valid_uninstall_reg_name(name: &str) -> bool {
    let n = name.trim();
    n.len() > 4 && n.len() <= BACKUP_NAME_MAX && n.ends_with(".reg") && n.bytes().all(backup_name_byte_ok)
}

/// 备份种类：与前端列表的四栏一一对应。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Reg,
    File,
    UninstReg,
    Pack,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "reg" => Some(Kind::Reg),
            "file" => Some(Kind::File),
            "uninst-reg" => Some(Kind::UninstReg),
            "pack" => Some(Kind::Pack),
            _ => None,
        }
    }

    fn sub(self) -> &'static str {
        match self {
            Kind::Reg => "cleanup-reg-backup",
            Kind::File => "cleanup-files-backup",
            Kind::UninstReg => "uninstall-reg-backup",
            Kind::Pack => "uninstall-restore-pack",
        }
    }

    fn domain(self) -> &'static str {
        match self {
            Kind::Reg | Kind::File => "cleanup",
            Kind::UninstReg | Kind::Pack => "uninstall",
        }
    }
}

/// 一条删除请求。`name` 是列表里回传的实体名（不含路径）。
pub struct Target {
    pub kind: Kind,
    pub name: String,
}

/// 单条结果：`ok=false` 时必须带原因，前端逐条展示而不是只报总数。
fn fail(name: &str, reason: impl Into<String>) -> Value {
    json!({ "name": name, "ok": false, "reason": reason.into() })
}

fn ok(name: &str) -> Value {
    json!({ "name": name, "ok": true })
}

/// 单个文件进回收站。`is_reparse` 先拒：链接件进回收站等于把它指向的实体一起卷进来。
fn trash_file(p: &Path, label: &str) -> Result<(), String> {
    let md = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{label} 读取失败：{e}")),
    };
    if protect::is_reparse(&md) {
        return Err(format!("{label} 是链接件，拒绝投递回收站"));
    }
    trim_finder::scan::recycle::send_to_trash_os(p.as_os_str())
        .map_err(|e| format!("{label} 移入回收站失败：{e}"))
}

/// 注册表备份的封条（`<文件名>.meta.json`）。只删主文件会留下孤儿封条，
/// 而孤儿封条会让后续「封条对账」把别的域判成孤立 —— 必须一起走。
fn reg_seal_path(file: &Path) -> PathBuf {
    crate::engine::reg_backup::reg_seal_path_for(file)
}

/// 清理域注册表备份：主文件 + 封条。
fn purge_reg(root: &Path, name: &str) -> Value {
    if !valid_reg_backup_name(name) {
        return fail(name, "备份文件名非法");
    }
    let file = root.join(name);
    if !file.is_file() {
        return fail(name, "备份文件不存在");
    }
    if let Err(e) = trash_file(&file, "注册表备份") {
        return fail(name, e);
    }
    // 封条删失败不回滚主文件：主文件已经没了，封条只是孤儿；如实记 warn 并继续，
    // 否则用户会看到「删失败」但备份其实已经不在了（回执与磁盘不一致）。
    if let Err(e) = trash_file(&reg_seal_path(&file), "注册表备份封条") {
        log::write_log("warn", &format!("备份清除：{name} 的封条未清掉：{e}"));
    }
    ok(name)
}

/// 卸载域注册表备份：主文件 + 封条 + HKLM 管理员摘要值。
fn purge_uninst_reg(root: &Path, name: &str) -> Value {
    if !valid_uninstall_reg_name(name) {
        return fail(name, "备份文件名非法");
    }
    let file = root.join(name);
    if !file.is_file() {
        return fail(name, "备份文件不存在");
    }
    if let Err(e) = trash_file(&file, "卸载注册表备份") {
        return fail(name, e);
    }
    if let Err(e) = trash_file(&reg_seal_path(&file), "卸载注册表备份封条") {
        log::write_log("warn", &format!("备份清除：{name} 的封条未清掉：{e}"));
    }
    // 摘要值不在文件里：删完主文件后按现存集合对账，把孤立摘要值清掉。
    // 与写入侧共用同一份对账（`reconcile_admin_seals`），不另造一套判定。
    let dirs = paths::backup_read_dirs(Kind::UninstReg.sub());
    let roots = crate::engine::reg_backup::seal_read_roots(&dirs);
    crate::engine::reg_backup::reconcile_admin_seals("uninstall", &roots);
    ok(name)
}

/// 文件备份批次：清单 + 它独占的副本。
///
/// 关键点：副本按 `<规则id>/` 跨批次共享（见 `native/cleanup.rs` 头注），所以删副本前
/// 必须问「还有别的清单指着它吗」。这里用**删除后剩余的清单**重新算一次引用集合，
/// 只清无人认领的那部分 —— 直接按本清单的 rel 列表删会把幸存批次的还原依据一起毁掉。
fn purge_file(root: &Path, name: &str) -> Value {
    if !valid_file_manifest_name(name) {
        return fail(name, "备份清单名非法");
    }
    let manifest = root.join(name);
    if !manifest.is_file() {
        return fail(name, "备份清单不存在");
    }
    // 读不动就不删：读不动的清单其引用集合未知，删副本可能误伤别的批次（A1-M03 同口径）
    let Some(mine) = crate::engine::native::manifest_rels(&manifest) else {
        return fail(name, "备份清单解析失败，未执行删除");
    };
    if let Err(e) = trash_file(&manifest, "备份清单") {
        return fail(name, e);
    }
    // 剩余清单的引用集合
    let mut still_referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut unreadable = 0usize;
    if let Ok(rd) = std::fs::read_dir(root) {
        for ent in rd.flatten() {
            let fname = ent.file_name().to_string_lossy().to_string();
            if fname == name || !valid_file_manifest_name(&fname) {
                continue;
            }
            match crate::engine::native::manifest_rels(&ent.path()) {
                Some(rels) => {
                    for rel in rels {
                        still_referenced.insert(rel.to_lowercase());
                    }
                }
                None => unreadable += 1,
            }
        }
    }
    if unreadable > 0 {
        // 清单已经删了，副本留给裁剪链处理（它读不动时会整轮放弃，不会误删）
        log::write_log(
            "warn",
            &format!("备份清除：{name} 已删除清单，但仍有 {unreadable} 份清单不可读，本批副本暂不回收"),
        );
        return ok(name);
    }
    let root_canon = match std::fs::canonicalize(root) {
        Ok(p) => p,
        Err(e) => {
            log::write_log("warn", &format!("备份清除：{name} 的副本根真实路径解析失败（{e}），副本暂不回收"));
            return ok(name);
        }
    };
    let mut orphan_fail = 0usize;
    for rel in mine {
        // 与还原通道同一道准入：不含 .. / 不是绝对路径 / 不带盘符
        if rel.is_empty() || rel.contains("..") || rel.starts_with('\\') || rel.starts_with('/') || rel.contains(':') {
            continue;
        }
        if still_referenced.contains(&rel.to_lowercase()) {
            continue;
        }
        let victim = root.join(&rel);
        if !crate::engine::native::backup_victim_within_root(&root_canon, &victim) {
            continue;
        }
        if let Err(e) = trash_file(&victim, "备份副本") {
            orphan_fail += 1;
            log::write_log("warn", &format!("备份清除：{name} 的副本 {rel} 未清掉：{e}"));
        }
    }
    if orphan_fail > 0 {
        return fail(name, format!("清单已删除，但有 {orphan_fail} 个副本未能移入回收站"));
    }
    ok(name)
}

/// 卸载还原包：整批目录（payload.zip + manifest.tsv + registry/）一起走。
fn purge_pack(root: &Path, name: &str) -> Value {
    if crate::engine::restore_pack::batch_id_reject_reason(name).is_some() {
        return fail(name, "还原包批次号非法");
    }
    let dir = root.join(name);
    if !dir.is_dir() {
        return fail(name, "还原包不存在");
    }
    // 批次目录本身也要拒链接：`is_dir()` 跟随链接，junction 会把别处目录整棵投进回收站
    match std::fs::symlink_metadata(&dir) {
        Ok(md) if md.is_dir() && !protect::is_reparse(&md) => {}
        Ok(_) => return fail(name, "还原包目录是链接件或非目录，拒绝删除"),
        Err(e) => return fail(name, format!("还原包目录读取失败：{e}")),
    }
    trim_finder::scan::recycle::send_to_trash_os(dir.as_os_str())
        .map(|()| ok(name))
        .unwrap_or_else(|e| fail(name, format!("还原包移入回收站失败：{e}")))
}

/// 批量清除。逐条独立处理：某一项失败不影响其余（用户勾了一批，不该因为其中一项被占用就整批作废）。
///
/// 返回 `{ removed, failed: [{name, reason}], items: [...] }`，`items` 逐条带结果，
/// 前端据此刷新列表并把失败项留在屏幕上。
pub fn purge(targets: &[Target]) -> Value {
    let mut removed = 0usize;
    let mut failed: Vec<Value> = Vec::new();
    let mut items: Vec<Value> = Vec::new();
    for t in targets {
        // 每次重新取根：删除过程中目录可能被别的实例搬走/替换，缓存路径会变成「判 A 删 B」
        let root = paths::backup_write_dir(t.kind.sub());
        // 根判定必须落在删除链上游（check-delete-root-guard）：junction 根会让
        // read_dir 直接在链接另一头枚举，子项逐个判 reparse 看不到这一层。
        let verdict = protect::inspect_root(&root, paths::data_root_base(&root).as_deref());
        if !verdict.is_trusted() {
            protect::note_root_skipped("备份清除", &root, &verdict);
            let reason = format!("备份目录未通过根判定（{}）", verdict.reason());
            failed.push(json!({ "name": t.name, "reason": reason }));
            items.push(fail(&t.name, reason));
            continue;
        }
        let result = match t.kind {
            Kind::Reg => purge_reg(&root, &t.name),
            Kind::File => purge_file(&root, &t.name),
            Kind::UninstReg => purge_uninst_reg(&root, &t.name),
            Kind::Pack => purge_pack(&root, &t.name),
        };
        if result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            removed += 1;
            log::write_log("info", &format!("备份已清除：{} {}", t.kind.domain(), t.name));
        } else {
            failed.push(json!({
                "name": t.name,
                "reason": result.get("reason").and_then(|v| v.as_str()).unwrap_or("未知原因"),
            }));
        }
        items.push(result);
    }
    json!({
        "removed": removed,
        "failed": failed,
        "items": items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(tag: &str) -> PathBuf {
        let p = paths::lib_test_data_root().join(format!("backup-purge-{tag}"));
        cleanup(&p);
        std::fs::create_dir_all(&p).expect("建测试目录失败");
        p
    }

    /// 测试收尾（单点）：四处断言共用这一份，删除原语调用点只记一处。
    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    fn is_ok(v: &Value) -> bool {
        v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false)
    }

    /// 名字闸必须逐类生效：任一类的非法名都不得拼出跨目录路径。
    #[test]
    fn 备份名非法一律拒删() {
        let root = sandbox("names");
        assert!(!is_ok(&purge_reg(&root, "..\\evil.reg")));
        assert!(!is_ok(&purge_reg(&root, "a/b.reg")));
        assert!(!is_ok(&purge_file(&root, "manifest-../x.json")));
        assert!(!is_ok(&purge_pack(&root, "..")));
        cleanup(&root);
    }

    /// 不存在的条目按失败回报（而不是谎报成功）：前端要据此把该行留在列表里。
    #[test]
    fn 不存在的备份如实回报失败() {
        let root = sandbox("missing");
        for v in [
            purge_reg(&root, "1700000000000_reg_rule_1.reg"),
            purge_file(&root, "manifest-1700000000000.json"),
            purge_uninst_reg(&root, "1700000000000_leaf.reg"),
            purge_pack(&root, "drop-1700000000000"),
        ] {
            assert!(!is_ok(&v), "不存在的备份不得报成功：{v}");
            assert!(
                v.get("reason").and_then(|x| x.as_str()).unwrap_or("").len() > 0,
                "失败必须带原因"
            );
        }
        cleanup(&root);
    }

    /// 共享副本保护：删掉一份清单后，另一份仍引用的副本不能被清掉。
    /// 判红自证：把 `still_referenced` 判断删掉 ⇒ 第二条断言红。
    #[test]
    fn 共享副本不被另一批清单的删除带走() {
        let root = sandbox("shared");
        std::fs::create_dir_all(root.join("rule")).unwrap();
        std::fs::write(root.join("rule\\shared.bin"), b"payload").unwrap();
        std::fs::write(root.join("rule\\only-a.bin"), b"payload").unwrap();
        std::fs::write(
            root.join("manifest-1700000000001.json"),
            serde_json::to_vec(&json!({ "ts": 1700000000001i64, "entries": [
                { "file": "rule\\shared.bin", "path": "C:\\orig\\s", "size": 7, "rule": "rule" },
                { "file": "rule\\only-a.bin", "path": "C:\\orig\\a", "size": 7, "rule": "rule" }
            ] }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("manifest-1700000000002.json"),
            serde_json::to_vec(&json!({ "ts": 1700000000002i64, "entries": [
                { "file": "rule\\shared.bin", "path": "C:\\orig\\s", "size": 7, "rule": "rule" }
            ] }))
            .unwrap(),
        )
        .unwrap();
        let r = purge_file(&root, "manifest-1700000000001.json");
        assert!(is_ok(&r), "{r}");
        // 共享副本必须还在；只有本批独占的副本才允许被投递回收站
        assert!(root.join("rule\\shared.bin").is_file(), "另一份清单仍引用的副本被误删");
        cleanup(&root);
    }
}
