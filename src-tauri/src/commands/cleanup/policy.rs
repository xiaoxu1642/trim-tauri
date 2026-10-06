//! G-2 全局年龄策略（2026-10-07）：`cleanup:age-policy` / `cleanup:set-age-policy`。
//!
//! 语义（方案 §2.1 G-2）：**只收紧、不放宽**。全局阈值与规则阈值取更严格的那个
//! （`max(规则阈值, 全局阈值)`），且只作用于**自己声明了 `minAge*`** 的规则 ——
//! 关掉全局策略时命中集合必须与升级前逐项一致。
//!
//! 真源落点：`<数据根>\cleanup-min-age-days.txt`（一行整数；空文件 = 关闭）。与空目录
//! 忽略名单**同落点、同「行文本」格式、同读法**（`trim_finder::util::list_file_path`
//! ⇒ 便携模式感知），扫描侧与执行侧读的是同一份字节、同一个解析函数
//! （`trim_finder::cleanup_scan::load_global_min_age_days`）—— 不允许在这里再写一份
//! 「看起来等价」的解析。
//!
//! 两条命令的档位都是 MAIN：写操作只有主窗调；读操作服务的是主窗设置页（放只读档会被
//! `check-channel-map` D5 判「只读档却没有子窗消费方」，与空目录忽略名单三命令同理）。
//!
//! 档位闸的**方向**（为什么写入侧卡档、读取侧不卡）：
//! - 写入侧只放行 UI 提供的档位（`0` = 关闭 / `14` / `30`），这是防「绕过 UI 传任意值」
//!   的那道闸 —— 方案 §2.1 G-2 明令「不允许用户输入任意负值或空值绕过」；
//! - 读取侧容忍手改过的文件（只认第一行正整数，非法按关闭），因为全局策略**只能收紧**，
//!   手改一个大值不会放宽删除面；反过来在读取侧卡档会让「手改了却没生效」变成静默失效。

use crate::engine::{guard, log, paths};

/// 策略文件名：由 native-scanner 提供（与 `list_file_path` 读侧同一个常量）。
///
/// **写侧不用** `trim_finder::cleanup_scan::global_min_age_file()` 取路径：那个函数按
/// 「当前根优先、老根兜底」解析（读侧语义）—— 只有老根有文件时它会指向老根，拿它来写
/// 就会把新值写进升级前的目录。写侧固定落**当前根**（`app_data_dir()`），与空目录忽略
/// 名单写侧（`finder.rs` 的 `EMPTY_IGNORE_FILE`）同口径。
const AGE_POLICY_FILE: &str = trim_finder::cleanup_scan::GLOBAL_MIN_AGE_FILE;

/// UI 提供的有限档位（天）。`0` = 关闭（不覆盖规则阈值）。
pub(super) const AGE_POLICY_TIERS: [u64; 3] = [0, 14, 30];

fn age_policy_path() -> std::path::PathBuf {
    paths::app_data_dir().join(AGE_POLICY_FILE)
}

/// 当前生效值（天）。`0` = 关闭。读法与扫描侧共用同一个函数，避免两处解析漂移。
fn current_days() -> u64 {
    trim_finder::cleanup_scan::load_global_min_age_days().unwrap_or(0)
}

/// cleanup:age-policy —— 读当前全局年龄策略（设置页展示用）
#[tauri::command]
pub fn cleanup_age_policy<R: tauri::Runtime>(window: tauri::WebviewWindow<R>) -> serde_json::Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return serde_json::json!({ "success": false, "message": msg });
    }
    serde_json::json!({ "success": true, "data": {
        "days": current_days(),
        "tiers": AGE_POLICY_TIERS,
    } })
}

/// cleanup:set-age-policy —— 写全局年龄策略（`days` 必须是 UI 档位之一；`0` = 关闭）
#[tauri::command]
pub fn cleanup_set_age_policy<R: tauri::Runtime>(
    window: tauri::WebviewWindow<R>,
    days: u64,
) -> serde_json::Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return serde_json::json!({ "success": false, "message": msg });
    }
    if !AGE_POLICY_TIERS.contains(&days) {
        // 不做「就近取整」也不做钳制：那会让调用方以为自己的值生效了。
        return serde_json::json!({
            "success": false,
            "message": format!("年龄档位只能是 {:?}（0 = 关闭）", AGE_POLICY_TIERS),
        });
    }
    let file = age_policy_path();
    if let Some(dir) = file.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            log::write_log("error", &format!("全局年龄策略目录创建失败: {e}"));
            return serde_json::json!({ "success": false, "message": format!("创建数据目录失败: {e}") });
        }
    }
    // 关闭 = **空文件**（不是写 0）：读取侧「第一行非空且为正整数」才认，空文件即关闭。
    // 写 0 也能得到关闭的结论，但空文件在人工核查时更直白（没有「0 天」这种读法）。
    let body = if days == 0 { String::new() } else { format!("{days}\r\n") };
    if let Err(e) = crate::security::atomic_write_file(&file, body.as_bytes()) {
        log::write_log("error", &format!("全局年龄策略写入失败: {e}"));
        return serde_json::json!({ "success": false, "message": format!("写入失败: {e}") });
    }
    log::write_log(
        "info",
        &format!(
            "全局年龄策略已更新: {}",
            if days == 0 { "关闭（不覆盖规则阈值）".to_string() } else { format!("{days} 天（只收紧，不放宽）") }
        ),
    );
    serde_json::json!({ "success": true, "data": { "days": days } })
}
