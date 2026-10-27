//! 备份写出原语（B2-2）：**私有 tmp 产出 → 判目标根 → 同卷 rename 落位**。
//!
//! 病根：四处备份写出都是「外部工具（`reg.exe export` / `powercfg /export`）或 `fs::write`
//! 直接写目标路径」。目标根若被换成 junction（B2-1 的清扫链、P0-2A 的裁剪链都栽过同一形态），
//! 直写会落在链接另一头 —— 而备份恰恰是「删除前唯一的还原依据」，写歪了等于把凭据丢在
//! 别人指定的目录里，且调用方完全不知道（`reg.exe` / `powercfg` 对链接都是透明跟随的）。
//!
//! 三道判据的顺序不能换：
//! 1. **产出在私有 tmp**（`temp_script_dir()`，每用户 DACL）：产出阶段根本不碰目标根，
//!    根被换掉时连一次写都不会落到链接另一头；
//! 2. **目标根判定**（`protect::inspect_root`）：判的是**根**，不是目标文件自身 ——
//!    目标此刻还不存在，它的 reparse 位恒为 0，拿它当判据等于没判；
//! 3. **同卷 rename 落位**：rename 是单步替换，要么旧文件、要么新文件，不会出现
//!    「写了一半的备份」被当成有效凭据。
//!
//! 落位失败一律**清理中转件后返回 `Err`**（调用方据此回 `success:false` / 「未删除」），
//! 绝不退回「直接写目标」那条老路。

use std::path::{Path, PathBuf};

/// 中转件的自删守卫：落位成功后 disarm，任何早退路径（含 `?`）都会把中转件删掉。
struct StageGuard(Option<PathBuf>);

impl StageGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for StageGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            // 删的是本函数刚在私有 tmp 里造出来的中转件，不是用户数据。
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// 备份写出：`produce` 只负责把内容写到它拿到的**中转路径**上，落位由本函数负责。
///
/// 返回落位后的字节数（调用方用它做回执 / 台账字段）。
///
/// `produce` 拿到的路径在私有 tmp 下、名字命中 [`crate::engine::tmpnames::BACKUP_STAGE`]
/// （崩溃残留由 B2-1 的清扫链兜底）；它**不得**自行把内容写到 `target` 上。
///
/// `target_root` 必须是 `target` 的**直接父目录** —— 判 A 写 B 是这类闸门最容易漏的形态。
pub fn land_backup<F>(target_root: &Path, target: &Path, produce: F) -> Result<u64, String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    if !target.parent().is_some_and(|p| crate::engine::protect::paths_same(p, target_root)) {
        return Err(format!(
            "备份目标 {} 不在被判定的根 {} 之下一层，已拒绝写出",
            target.display(),
            target_root.display()
        ));
    }

    let stage_dir = crate::engine::paths::temp_script_dir()?;
    let stage = stage_dir.join(crate::engine::tmpnames::BACKUP_STAGE.build(
        crate::engine::now_ms(),
        &crate::security::crypto_random_hex(8),
    ));
    // 名字是随机取的，理论上不会撞；真有同名残留就清掉（只可能由本函数上一次异常退出留下）。
    let _ = std::fs::remove_file(&stage);
    let mut guard = StageGuard(Some(stage.clone()));

    produce(&stage)?;

    // 产出物的形态：普通文件、非 reparse、非空。三者缺一都不算「备份已做成」——
    // 与原实现「退出码成功 + 文件在 + 内容非空」的三判同口径，只是换成判中转件。
    let md = std::fs::symlink_metadata(&stage)
        .map_err(|e| format!("备份中转件读取失败：{e}（备份未做成）"))?;
    if crate::engine::protect::is_reparse(&md) || !md.is_file() {
        return Err("备份中转件不是普通文件（备份未做成）".to_string());
    }
    if md.len() == 0 {
        return Err("备份中转件为空（备份未做成）".to_string());
    }

    // 判**根**，不判目标文件自身：目标此刻还不存在，它的 reparse 位恒为 0。
    let verdict = crate::engine::protect::inspect_root(
        target_root,
        crate::engine::paths::data_root_base(target_root).as_deref(),
    );
    if !verdict.is_trusted() {
        crate::engine::protect::note_root_skipped("备份写出", target_root, &verdict);
        return Err(format!(
            "备份根不可信（{}），已放弃写入并清理中转件",
            verdict.reason()
        ));
    }

    match std::fs::rename(&stage, target) {
        Ok(()) => {
            guard.disarm();
            Ok(md.len())
        }
        // 跨卷（用户把导出目标选在别的盘）时 rename 必然失败：那是**用户主动选的落点**，
        // 不是我们控制的数据根，退回逐字节复制并把中转件删掉。副本非原子，但这条路径上
        // 没有任何「依赖该文件才敢删除」的动作（只有用户自选导出才跨卷）。
        Err(e) if e.raw_os_error() == Some(17) => {
            std::fs::copy(&stage, target)
                .map_err(|e2| format!("跨卷复制备份到目标失败：{e2}（备份未做成）"))?;
            Ok(md.len())
        }
        Err(e) => Err(format!("备份落位失败：{e}（已清理中转件，备份未做成）")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 这组用例共用**同一个**私有 tmp 目录，而 `assert_no_stage_left` 扫的是整个目录。
    /// 不加锁时并行跑到一半的另一条用例会在里面留下自己的在途中转件 ⇒ 本组互相判红。
    /// 锁只保护这五条用例（都是毫秒级），不是生产语义的一部分。
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 落位成功：目标内容 = 产出内容，且私有 tmp 里不留中转件。
    #[test]
    fn 落位成功且不留中转件() {
        let _g = serial();
        let sb = crate::testutil::Sandbox::new(&format!("bw-ok-{}", std::process::id()));
        let root = sb.join("backups");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("x.reg");
        let n = land_backup(&root, &target, |stage| {
            std::fs::write(stage, b"HELLO").map_err(|e| e.to_string())
        })
        .expect("落位应成功");
        assert_eq!(n, 5);
        assert_eq!(std::fs::read(&target).unwrap(), b"HELLO");
        assert_no_stage_left();
    }

    /// **B2-2 验收**：备份根换成指向沙箱另一目录的 junction ⇒ 必回 `Err`，且那边零新增文件。
    ///
    /// 旧实现（`fs::write` / `reg.exe export` 直指目标路径）在这条样本上会把备份写进
    /// 链接另一头，而调用方回执照样是「备份已做成」。
    #[test]
    fn 备份根换成junction时必拒且连接另一头零新增() {
        let _g = serial();
        let sb = crate::testutil::Sandbox::new(&format!("bw-junction-{}", std::process::id()));
        // 链接目标（「另一头」）：里面预先不放任何东西，事后要断言仍为空
        let other = sb.join("elsewhere");
        std::fs::create_dir_all(&other).unwrap();
        let root = sb.join("backups");
        // 建 junction：参数分开传（整串塞给 `/C` 时 cmd 的引号剥离规则会把路径弄坏）。
        // 造不出 ≠ 不会发生：下面显式报「未校验」，不假绿也不假红。
        let out = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &root.to_string_lossy(),
                &other.to_string_lossy(),
            ])
            .output();
        let made = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
        if !made {
            let detail = out
                .map(|o| {
                    format!(
                        "code={:?} stdout={:?} stderr={:?}",
                        o.status.code(),
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    )
                })
                .unwrap_or_else(|e| e.to_string());
            eprintln!("SKIP 备份根换成junction时必拒且连接另一头零新增：本环境建不出 junction（{detail}），该判据未校验");
            return;
        }
        let target = root.join("x.reg");
        let err = land_backup(&root, &target, |stage| {
            std::fs::write(stage, b"HELLO").map_err(|e| e.to_string())
        })
        .expect_err("根是 junction 时必须拒绝落位");
        assert!(
            err.contains("备份根不可信"),
            "拒因要点名根判定而不是泛泛失败：{err}"
        );
        // 另一头零新增：这才是「没写进去」的硬证据（回执 Err 只说明我们说了失败）
        let leftover: Vec<String> = std::fs::read_dir(&other)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(leftover.is_empty(), "junction 另一头被写入了文件：{leftover:?}");
        assert_no_stage_left();
    }

    /// 产出失败 ⇒ 返回 Err，且目标不出现半截文件、私有 tmp 不留中转件。
    #[test]
    fn 产出失败时目标不落半截件且不留中转件() {
        let _g = serial();
        let sb = crate::testutil::Sandbox::new(&format!("bw-produce-fail-{}", std::process::id()));
        let root = sb.join("backups");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("x.reg");
        let err = land_backup(&root, &target, |stage| {
            // 写一半再报错：模拟外部工具中途失败
            std::fs::write(stage, b"HALF").map_err(|e| e.to_string())?;
            Err("导出工具失败".to_string())
        })
        .expect_err("产出失败必须整条失败");
        assert!(err.contains("导出工具失败"), "{err}");
        assert!(!target.exists(), "产出失败时目标绝不能出现半截文件");
        assert_no_stage_left();
    }

    /// 产出空文件 ⇒ 按「备份未做成」拒绝（三判口径：文件在但内容为空不算凭据）。
    #[test]
    fn 产出空件时按未做成拒绝() {
        let _g = serial();
        let sb = crate::testutil::Sandbox::new(&format!("bw-empty-{}", std::process::id()));
        let root = sb.join("backups");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("x.reg");
        let err = land_backup(&root, &target, |stage| {
            std::fs::write(stage, b"").map_err(|e| e.to_string())
        })
        .expect_err("空件必须拒绝");
        assert!(err.contains("为空"), "{err}");
        assert!(!target.exists());
        assert_no_stage_left();
    }

    /// 判 A 写 B：目标不在被判定的根下一层 ⇒ 直接拒（这类闸门最容易漏的形态）。
    #[test]
    fn 目标不在被判定的根之下时拒绝() {
        let _g = serial();
        let sb = crate::testutil::Sandbox::new(&format!("bw-mismatch-{}", std::process::id()));
        let root = sb.join("backups");
        let other = sb.join("other");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let target = other.join("x.reg");
        let err = land_backup(&root, &target, |stage| {
            std::fs::write(stage, b"X").map_err(|e| e.to_string())
        })
        .expect_err("目标不在根下必须拒绝");
        assert!(err.contains("不在被判定的根"), "{err}");
        assert!(!target.exists());
    }

    /// 私有 tmp 里不许留 `bakstage_…` 中转件：任何早退路径都由守卫删掉。
    fn assert_no_stage_left() {
        let Ok(dir) = crate::engine::paths::temp_script_dir() else {
            return;
        };
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return;
        };
        let left: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| crate::engine::tmpnames::BACKUP_STAGE.matches(n))
            .collect();
        assert!(left.is_empty(), "私有 tmp 残留中转件：{left:?}");
    }
}
