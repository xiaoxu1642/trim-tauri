//! 命令层共享状态集中登记（v3 审查 C-2，2026-10-07）
//!
//! 为什么集中：原先「命令层 file-scope 全局状态」散在 13 个 `commands/*.rs` 里，锁序约定
//! 只存在于各文件注释，审查时无法一处核对；现在**本文件就是命令层全局状态的唯一清单**，
//! 锁序纪律见下。
//!
//! 范围边界（刻意不搬的，别往这里顺手挪）：
//! - `engine/` / `pwsh/` / `security/` 落点的 static：依赖方向规定这些层不得依赖 commands
//!   （check-layering），搬过来会造反向依赖。
//! - 函数体内 `static CACHE`（如 `optimizer/catalog.rs`）：只在函数内可见，没有跨模块锁序问题。
//!   **豁免只给「函数体内」的 static**：文件级 `static`（模块作用域可见）同样要登记，
//!   否则「命令层全局状态唯一清单」这句话当场失效（登记面见下方各段）。
//! - 与所属域访问器/守卫强绑定的（域内登记，仅点名不再搬）：
//!   `cleanup::state` 的 `CLEANUP_SNAPSHOTS` / `LOCK_WHITELIST`、
//!   `cleanup::rules` 的 `RULES_CACHE` / `WATERMARK_HIGH`、
//!   `uninstall::helpers` 的 `RESIDUE_SNAPSHOTS`（设计注释：与取它的访问器同文件）、
//!   `optimizer::apply` 的 `OPT_RUN_INFLIGHT`、`optimizer::restore_point` 的 `RESTORE_INFLIGHT`
//!   （`pub(super)` 守卫，语义强绑定）。
//!
//! 锁序纪律：除 overview 的 `METRICS_LOCK → METRICS_CACHE → CPU_PREV` 一串
//! （串行化采集与 CPU 差分，**不得反向**）外，其余条目一律按**叶子锁**使用——
//! 持锁期间不取本表其他锁。新增嵌套前先核调用链、
//! 在这里登记一行再写代码。长期方向是迁 `tauri::State` 注入（v3 C-2 备注），届时本文件
//! 即迁移清单。
//!
//! 为什么不用 `pub`：仅命令层（commands 树）消费；放 `pub(crate)` 防外部层误引形成反向依赖。
//!
//! 槽位按域落在同目录子文件：`panel` / `diagnostics` / `file_tools` / `infra`，
//! 全部槽经下方 re-export 保持 `crate::commands::state::XXX` 引用路径不变。

mod diagnostics;
mod file_tools;
mod infra;
mod panel;

pub(crate) use diagnostics::{
    CPU_PREV, DISKBENCH_GEN, DISKBENCH_RUNNING, LATEST, METRICS_CACHE, METRICS_LOCK, SAMPLER,
};
pub(crate) use file_tools::{FILECLEAN_SCOPES, FINDER_SNAPSHOTS};
pub(crate) use infra::{
    BATTERY_SWAPPED, CDP_ACTIVE_NOW, CHECKING, DOWNLOADED, DOWNLOADING, DOWNLOAD_TASK,
    DWM_TOOL_HINT, ELEVATE_INFLIGHT, ENV_ON_BATTERY, ENV_TRANSPARENCY_ON, NETCHECK_SNAPSHOTS,
    PENDING, PendingEditState, SILENT_CHECK_THREAD, SYSTEM_DISK_CACHE,
};
pub(crate) use panel::{PROCESS_SNAPSHOTS, RUNNING, RUNTIMES_SNAPSHOTS};

#[cfg(test)]
mod registry_tests {
    /// B-04 ③：`settings.rs` 的**文件级** static 必须在命令层全局状态清单（`state/`）登记；
    /// `state/` 各子文件自己的模块级 static 也必须出现在 `mod.rs` 的 re-export 登记清单里。
    ///
    /// 豁免只给「函数体内」的 static（只在函数内可见，没有跨模块锁序问题）；
    /// 文件级 static 可见面更大，漏登记 = 「唯一清单」这句话当场失效。
    /// 解析口径：只认行首无缩进的 static 声明；`mod.rs` 的 re-export 行不是 static
    /// 声明，是登记位。判红自证：在 `settings.rs` 或任一 `state/` 子文件加一条文件级
    /// static 而不在 `mod.rs` 登记 ⇒ 本用例红。
    #[test]
    fn 文件级static必须在本清单登记() {
        let registry_src = include_str!("mod.rs");
        let state_files: [(&str, &str); 5] = [
            ("mod.rs", include_str!("mod.rs")),
            ("panel.rs", include_str!("panel.rs")),
            ("diagnostics.rs", include_str!("diagnostics.rs")),
            ("file_tools.rs", include_str!("file_tools.rs")),
            ("infra.rs", include_str!("infra.rs")),
        ];
        let settings_src = include_str!("../settings.rs");
        let mut unregistered: Vec<String> = Vec::new();
        for (fname, src) in state_files {
            for line in src.lines() {
                if let Some(name) = module_static_name(line) {
                    if !registry_src.contains(&name) {
                        unregistered.push(format!("{fname}::{name}"));
                    }
                }
            }
        }
        for line in settings_src.lines() {
            if let Some(name) = module_static_name(line) {
                if !registry_src.contains(&name) {
                    unregistered.push(format!("settings.rs::{name}"));
                }
            }
        }
        assert!(
            unregistered.is_empty(),
            "文件级 static 未在 state/mod.rs 登记清单: {unregistered:?}"
        );
    }

    /// 只认**模块作用域**（行首无缩进）的 static 声明
    fn module_static_name(line: &str) -> Option<String> {
        let rest = if let Some(r) = line.strip_prefix("pub(crate) static ") {
            r
        } else {
            line.strip_prefix("static ")?
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }
}
