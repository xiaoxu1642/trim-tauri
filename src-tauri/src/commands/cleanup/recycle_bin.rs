//! cleanup:recycle-stats / cleanup:empty-recycle-bin —— 回收站清空语义收口
//! （方案 v2 §2.2 G-4，2026-10-07 用户裁定走**选项 B**）。
//!
//! 缺口背景（方案 §1.1 差距 4）：旧实现是 `cleanup-rules.json` 里一条
//! `pathPs = 'C:\$Recycle.Bin'` 的普通清理规则 —— 它把回收站当**普通目录**扫、
//! 当普通目录交给**永久删链**，于是：
//!   · 展示的「占用大小」是枚举 `$Recycle.Bin` 子树算出来的，与系统回收站
//!     「条目数 / 体积」两套口径不一致；
//!   · 删除走 `cleanup:execute` 的永久删，**绕过系统回收站 API**，清完没有
//!     「回收站已清空」的系统语义（可还原性、按用户配额回收）；
//!   · 24 小时年龄门槛是这条规则自己加的，系统回收站没有这个概念。
//!
//! 选项 B 的三条落地边界（方案 §2.2 G-4 第 3/4 条）：
//! 1. **不再把 `$Recycle.Bin` 当普通清理目录**：规则条目的 `pathPs`/`minAgeHours`
//!    已撤，改挂 `special: "recycleBin"`；扫描引擎对该值只发一条 size=0 的占位
//!    （`native-scanner/src/cleanup_scan.rs::emit_recycle_bin`），不枚举任何路径。
//! 2. **清空走系统 Shell API**：`SHEmptyRecycleBinW`，不是永久删链。
//! 3. **主窗专属 + 默认关闭 + 先出条目数与体积 + 走高危确认**：两个命令都是
//!    `guard::MAIN`；条目 `domain == "special"` 使渲染层永不默认勾选
//!    （cleanup.js :996）；体积由 `cleanup:recycle-stats` 现查；
//!    清空前的红色高危确认在渲染层（`confirmDanger`）—— 它是**不可逆**动作，
//!    后端不做兜底确认，但也不假设调用方已经确认过。
//!
//! 与旧条目的行为差异（如实登记，供审计对账）：
//!   · 旧：删 `$Recycle.Bin` 下**超过 24 小时**的内容，永久删，条目大小=子树字节数。
//!   · 新：清空**整个回收站**（全部条目，不看年龄），Shell 语义，条目大小=系统口径。
//!   这是**命中集合扩张**（去掉年龄护栏），但方向是「普通目录删 → 系统回收站清空」：
//!   爆炸半径收窄到「本就是用户已丢弃的内容」，且强制经红色确认 + 体积先摆出来。

use crate::engine::{guard, log};
use serde_json::{Value, json};
use tauri::WebviewWindow;

/// SHEmptyRecycleBinW 的标志位（shellapi.h）。
///
/// 三个都开：确认 / 进度 / 提示音全部由 Trim 自己的 UI 承担，
/// 再让 Shell 弹一遍就是重复打扰（且 Shell 的确认弹窗无法被自动化验证）。
const SHERB_NOCONFIRMATION: u32 = 0x0000_0001;
const SHERB_NOPROGRESSUI: u32 = 0x0000_0002;
const SHERB_NOSOUND: u32 = 0x0000_0004;

#[cfg(windows)]
mod shell_ffi {
    /// `SHQUERYRBINFO`（shellapi.h）。
    ///
    /// 手写布局而不是引 `windows` crate：与本仓 `SHFileOperationW`
    /// （native-scanner/src/scan.rs:1647）同一姿势 —— 单点 API 不值得多引一个命名空间。
    ///
    /// 字段顺序即 ABI：`cbSize`(4) 后按 x64 默认对齐有 4 字节填充，两个 `__int64`
    /// 从偏移 8 / 16 起 ⇒ **sizeof = 24**。调用方必须把 `cb_size` 填成这个值，
    /// Shell 用它做版本校验；填错会直接返回失败。末尾单测钉住这个字节数。
    #[repr(C)]
    pub struct ShQueryRbInfo {
        pub cb_size: u32,
        pub i64_size: i64,
        pub i64_num_items: i64,
    }

    #[link(name = "shell32")]
    extern "system" {
        pub fn SHQueryRecycleBinW(psz_root_path: *const u16, p_info: *mut ShQueryRbInfo) -> i32;
        pub fn SHEmptyRecycleBinW(
            hwnd: *mut core::ffi::c_void,
            psz_root_path: *const u16,
            dw_flags: u32,
        ) -> i32;
    }
}

/// 查询回收站条目数与占用体积（所有盘合计）。
///
/// **fail-closed**：Shell 调用失败就返回 `Err`，调用方不许拿一个编造的数字接着走
/// —— 「查不到」与「是 0」是两件事（同残留扫描的 notes 口径）。
#[cfg(windows)]
fn query_recycle_stats() -> Result<(u64, u64), String> {
    use shell_ffi::{SHQueryRecycleBinW, ShQueryRbInfo};
    let mut info = ShQueryRbInfo {
        cb_size: std::mem::size_of::<ShQueryRbInfo>() as u32,
        i64_size: 0,
        i64_num_items: 0,
    };
    // 空根路径 = 所有驱动器合计（MSDN 明确支持）。
    let hr = unsafe { SHQueryRecycleBinW(std::ptr::null(), &mut info) };
    if hr < 0 {
        return Err(format!("查询回收站失败（HRESULT 0x{:08X}）", hr as u32));
    }
    // 负值理论上不出现；真出现按 0 处理而不是把它们当无符号数放大（u64 转型的经典坑）。
    let bytes = if info.i64_size > 0 { info.i64_size as u64 } else { 0 };
    let count = if info.i64_num_items > 0 { info.i64_num_items as u64 } else { 0 };
    Ok((count, bytes))
}

#[cfg(not(windows))]
fn query_recycle_stats() -> Result<(u64, u64), String> {
    Err("仅支持 Windows".to_string())
}

/// cleanup:recycle-stats —— 回收站条目数与体积（只读；主窗档）
///
/// 体积是渲染层展示「回收站」条目占用大小的唯一权威来源：扫描引擎那条占位行
/// 刻意写 size=0（`emit_recycle_bin` 的注释），真实数字只有这里能回答。
#[tauri::command]
pub async fn cleanup_recycle_stats<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // 回收站很大时 SHQueryRecycleBinW 会遍历目录：挪进 spawn_blocking 不占 UI 线程。
    match tauri::async_runtime::spawn_blocking(query_recycle_stats).await {
        Ok(Ok((count, bytes))) => json!({ "success": true, "count": count, "bytes": bytes }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": e.to_string() }),
    }
}

/// cleanup:empty-recycle-bin —— 清空回收站（**不可逆**；主窗档）
///
/// 回执里的 `count` / `freed` 是**清空前的**条目数与体积，供渲染层如实告诉用户
/// 「刚刚清掉了多少」。统计失败不阻断清空（统计只是回执用），但清空本身失败
/// 必须原样上报，不许把失败渲染成成功。
///
/// ⚠️ `SHEmptyRecycleBinW` **刻意直接写在本命令体内、不外包给 helper**：
/// 它是本仓唯一的回收站破坏性出口，而 `tools/check-delete-exits.mjs` 的
/// DELETE_MARKERS 含这个名字、扫的是**命令体**。外包一层会让「新增破坏性出口
/// 默认红」这条防线对本次改动失明（该门禁的既有前科见文件头 L-4 二跳盲区）。
#[tauri::command]
pub async fn cleanup_empty_recycle_bin<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    log::write_log("warn", "清空回收站（用户确认，Shell API，不可逆）");
    log::flush_sync(); // 危险操作执行前强制刷盘（审查 v4-L3 同口径）
    let task = tauri::async_runtime::spawn_blocking(|| {
        // 清空前先取一次统计：失败不阻断清空（统计只喂回执），清空失败则如实上报。
        let before = query_recycle_stats().ok();
        #[cfg(windows)]
        let hr = unsafe {
            shell_ffi::SHEmptyRecycleBinW(
                std::ptr::null_mut(),
                std::ptr::null(),
                SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND,
            )
        };
        #[cfg(not(windows))]
        let hr: i32 = -1;
        if hr < 0 {
            return json!({ "success": false, "message": format!("清空回收站失败（HRESULT 0x{:08X}）", hr as u32) });
        }
        let (count, bytes) = before.unwrap_or((0, 0));
        json!({ "success": true, "count": count, "freed": bytes })
    });
    match task.await {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": format!("清空任务异常终止: {e}") }),
    }
}

#[cfg(test)]
mod tests {
    /// 布局契约：`SHQUERYRBINFO` 在 x64 上必须是 24 字节。
    ///
    /// 这不是防御性断言，是**唯一的 ABI 钉桩**：`cb_size` 用它填给 Shell 做版本
    /// 校验，一旦 `repr(C)` 的对齐假设被改动（换字段类型、加字段），Shell 会直接
    /// 拒绝调用 —— 症状是「回收站永远显示 0」，其它地方没有任何东西会红。
    /// 判红实验：把 `i64_size` 改成 `i32` 即红。
    #[cfg(windows)]
    #[test]
    fn 回收站查询结构体布局为_24_字节() {
        use super::shell_ffi::ShQueryRbInfo;
        assert_eq!(
            std::mem::size_of::<ShQueryRbInfo>(),
            24,
            "SHQUERYRBINFO 的 ABI 变了：cb_size 会被 Shell 判为非法版本，查询将恒失败"
        );
    }
}
