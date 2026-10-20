//! IPC 命令注册面（迁移方案 7.2：一域一文件）
//!
//! 命令命名：Rust snake_case，`<域>_<动作>`；适配层 CHANNEL_MAP 是通道名的唯一真源（D2）。
//! 新增命令必须同时登记 CHANNEL_MAP 与一致性断言，防"Rust 有了、前端没接"的静默断裂。

// v3 C-2：命令层全局状态集中登记 + 锁序文档（唯一清单，新状态先登记再落点）
pub(crate) mod state;

/// 回执里的失败计数必须**存在**才能判成功（A1-M07，v7.2 P1）。
/// `unwrap_or(0)` 会把「生产侧少写/改名了该键」静默翻成 success:true——
/// 这正是「成功位由可选计数派生」的同族缺口。
pub(crate) fn required_count(data: &serde_json::Value, key: &str) -> Option<f64> {
    data.get(key).and_then(|v| v.as_f64())
}

#[cfg(test)]
mod tests {
    use super::required_count;

    /// A1-M07：键缺失必须返回 None（调用方据此判失败），不能退成 0。
    #[test]
    fn required_count_缺键为_none() {
        assert_eq!(required_count(&serde_json::json!({ "failed": 0 }), "failed"), Some(0.0));
        assert_eq!(required_count(&serde_json::json!({ "failed": 2 }), "failed"), Some(2.0));
        assert_eq!(required_count(&serde_json::json!({}), "failed"), None);
    }
}

pub mod app;
pub mod device;
pub mod log;
pub mod misc;
pub mod overview;
pub mod paths;
pub mod realtime;
pub mod system;
pub mod syspanel;
// ---- B 批（只读扫描 + 安全与运行时）----
pub mod finder;
pub mod uninstall;
pub mod memory;
pub mod netcheck;
pub mod diskbench;
pub mod residue;
pub mod processmanager;
pub mod runtimes;
// ---- C 批（安全与规则）----
pub mod cleanup;
pub mod models;
pub mod settings;
pub mod aidesc;
pub mod quickcmds;
pub mod benchhistory;
pub mod fonts;
// ---- D 批（删除与高危）----
pub mod fileclean;
pub mod contextmenu;
pub mod startup;
pub mod peripheral;
pub mod optimizer;
pub mod maintenance;
// P2-02：游戏安装包残留扫描
pub mod gameclean;
// ---- E 批（外观与更新：材质/环境/背景图、自动更新、UAC 提权）----
pub mod appearance;
pub mod elevate;
pub mod updater;