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

/// 子窗建窗回执（v7.2 P3 · R1b-U01）：`build()` 的 `Ok` **不代表窗口存在**。
///
/// AGENTS §5.15 的判据是「窗口在不在只看 `hwnd()`/OS 枚举，Tauri 成功回执不算证据」——
/// 参数不一致（典型是 `with_browser_args` 与父窗句柄的配合）时 `build()` 仍返回 Ok，
/// 而 `hwnd()` 拿到的是无效句柄：用户点了没窗、回执却说成功。三个子窗（大模型 / 进程 /
/// 残留）此前各自 `Ok(_) => success:true`，等于把这层差分吞掉。
/// 三个调用点共用这一处判据（§5.16 不各写一份），失败时落 error 日志并如实回
/// `success:false`——渲染层宁可显示「窗口打不开」，也不该显示一个不存在的成功。
pub(crate) fn window_built_receipt<R: tauri::Runtime>(
    window: &tauri::WebviewWindow<R>,
    what: &str,
) -> serde_json::Value {
    match window.hwnd() {
        Ok(h) if hwnd_is_valid(&h) => serde_json::json!({ "success": true }),
        other => {
            let detail = match other {
                Err(e) => format!("取窗口句柄失败: {e}"),
                _ => "窗口句柄无效（hwnd=0）".to_string(),
            };
            crate::engine::log::write_log(
                "error",
                &format!("「{what}」窗口 build 返回成功但 {detail} —— 按建窗失败回执"),
            );
            serde_json::json!({
                "success": false,
                "message": format!("「{what}」窗口创建后未获得有效窗口句柄（{detail}）"),
            })
        }
    }
}

/// 句柄有效性判据本体（与回执共用一处，§5.16）。抽出来是为了能在无窗口环境下钉双向：
/// 空句柄/INVALID 必须判无效、任意非空句柄必须判有效——否则「判据恒 true」这类退化不会红。
pub(crate) fn hwnd_is_valid(h: &windows::Win32::Foundation::HWND) -> bool {
    !h.is_invalid()
}

#[cfg(test)]
mod tests {
    use super::{hwnd_is_valid, required_count};

    /// A1-M07：键缺失必须返回 None（调用方据此判失败），不能退成 0。
    #[test]
    fn required_count_缺键为_none() {
        assert_eq!(required_count(&serde_json::json!({ "failed": 0 }), "failed"), Some(0.0));
        assert_eq!(required_count(&serde_json::json!({ "failed": 2 }), "failed"), Some(2.0));
        assert_eq!(required_count(&serde_json::json!({}), "failed"), None);
    }

    /// R1b-U01：建窗回执的句柄判据必须**双向**成立。只钉「空句柄判无效」的话，
    /// 把判据退化成恒 false 也会绿（窗口永远报失败）；只钉非空也会漏掉恒 true
    /// ——那正是这条要防的「build() 的 Ok 被当成窗口存在」。
    /// 判红自证：把 `hwnd_is_valid` 改成恒 true ⇒ 空句柄那条红；改成恒 false ⇒ 非空那条红。
    #[test]
    fn hwnd_is_valid_双向都判() {
        use windows::Win32::Foundation::HWND;
        let null = HWND(std::ptr::null_mut());
        assert!(!hwnd_is_valid(&null), "空句柄被判成有效 ⇒ 建窗失败会回 success:true（R1b-U01 复发）");
        let fake = HWND(1usize as *mut _);
        assert!(hwnd_is_valid(&fake), "非空句柄被判成无效 ⇒ 窗口永远报失败，用户点了没反应");
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