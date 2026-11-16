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
        return Err(format!(
            "查询回收站失败（HRESULT 0x{:08X}）：{}",
            hr as u32,
            classify_shell_failure(hr)
        ));
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

/// Shell 失败原因分档（P2-04 / R03）：把 HRESULT 折成**用户可操作**的原因。
///
/// 口径与清理域其余失败分档一致（权限不足 → 提权重试；对象不存在 → 无需重试；
/// 占用 → 关程序后重试；其余不猜），**只按 HRESULT 判**，不掺任何路径细节 ——
/// 回收站里的文件名与盘符都不进回执（那属于用户隐私，不是排障信息）。
///
/// 未知码保留原始 HRESULT，不瞎猜成某一类（宁可少说，不可说错）。
fn classify_shell_failure(hr: i32) -> &'static str {
    match hr as u32 {
        // HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)：权限不足，提权重试有意义。
        0x8007_0005 => "权限不足：请以管理员身份运行 Trim 后重试（可退出后右键 Trim，选择「以管理员身份运行」）；若已提权仍失败，可能是组策略或安全软件限制了回收站操作",
        // HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)：系统或组策略不支持。
        0x8007_0032 => "当前系统或组策略不支持清空回收站，请检查回收站所在驱动器是否可用",
        // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND)：驱动器未就绪或已移除。
        0x8007_0002 | 0x8007_0003 => "回收站位置不可用（驱动器未就绪或已被移除），请插回驱动器后重试",
        // HRESULT_FROM_WIN32(ERROR_CANCELLED)：被系统取消。
        0x8007_04C7 => "操作被系统取消，请重试",
        // HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY)。
        0x8007_000E => "内存不足，请关闭其他程序后重试",
        // E_UNEXPECTED：Shell 侧状态异常。
        0x8000_FFFF => "回收站服务异常，请重启资源管理器后重试",
        _ => "原因未知，请重试；若持续失败请把下面的错误码一并反馈",
    }
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
/// P0-06（R01/R02）：清空**之后**再查一次统计，回执带 `afterCount` / `afterBytes` /
/// `partial` / `statsFailed`：
///   · `afterCount`/`afterBytes` = 清空后的实测值（非零 ⇒ `partial`，前端提示「部分未清空」）。
///   · 复查统计失败 ⇒ `statsFailed: true` 且 `afterCount`/`afterBytes` 为 `null`。
///     **不许拿清空前的旧统计冒充清空后结果**（那正是 R01 的形态）。
///   · `count`/`freed`（清空前）在清空前统计失败时同样为 `null`，与「本来就是空的」
///     区分开（沿用 v4 P2-E 的 null 口径）。
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
            return json!({ "success": false, "message": format!("清空回收站失败（HRESULT 0x{:08X}）：{}", hr as u32, classify_shell_failure(hr)) });
        }
        // P0-06（R01）：清空后**复查**统计 —— Shell 返回成功不等于真的清空了
        // （多盘回收站、权限拒绝都会留下残余）。复查失败不许拿清空前的旧数字冒充。
        let after = query_recycle_stats();
        let receipt = empty_receipt(before, after);
        if receipt["statsFailed"] == json!(true) {
            log::write_log(
                "warn",
                &format!(
                    "清空回收站完成，但统计不可得：{}",
                    receipt["statsError"].as_str().unwrap_or("未知原因")
                ),
            );
        } else if receipt["partial"] == json!(true) {
            log::write_log(
                "warn",
                &format!(
                    "清空回收站后仍有残余：{} 项 / {} 字节",
                    receipt["afterCount"].as_i64().unwrap_or(0),
                    receipt["afterBytes"].as_i64().unwrap_or(0)
                ),
            );
        }
        receipt
    });
    match task.await {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": format!("清空任务异常终止: {e}") }),
    }
}

/// 清空回收站的回执构造（**纯函数**，P0-06）。
///
/// 为什么要抽成纯函数：Shell 调用要真机才有，而「三种结局的诚实口径」是本条的全部
/// 判据 —— 不抽出来就只能靠真机碰运气验证。
///
/// 口径：
/// - `count` / `freed` = 清空**前**的条目数与体积；查不到就是 `null`（不是 0）。
/// - `afterCount` / `afterBytes` = 清空**后**的实测值；复查失败就是 `null`，
///   **绝不用清空前的旧值顶替**（R01 的核心）。
/// - `partial` = 复查成功且残余非零（真·部分未清空）。
/// - `statsFailed` = 任一次统计查询失败（清空前或清空后）。
/// - `statsError` = 首个失败原因（不含敏感信息，只有 HRESULT 与文案）。
fn empty_receipt(
    before: Option<(u64, u64)>,
    after: Result<(u64, u64), String>,
) -> Value {
    let (count, freed) = match before {
        Some((c, b)) => (json!(c), json!(b)),
        None => (Value::Null, Value::Null),
    };
    let stats_failed = count.is_null() || after.is_err();
    let (after_count, after_bytes, partial) = match &after {
        Ok((c, b)) => (
            json!(c),
            json!(b),
            Value::Bool(*c > 0 || *b > 0),
        ),
        Err(_) => (Value::Null, Value::Null, Value::Bool(false)),
    };
    let stats_error = match &after {
        Err(e) => e.clone(),
        Ok(_) if count.is_null() => "清空前统计不可得（SHQueryRecycleBinW 失败）".to_string(),
        Ok(_) => String::new(),
    };
    json!({
        "success": true,
        "count": count,
        "freed": freed,
        "afterCount": after_count,
        "afterBytes": after_bytes,
        "partial": partial,
        "statsFailed": stats_failed,
        "statsError": stats_error,
    })
}

/// cleanup:open-recycle-bin —— 打开系统回收站（回收站行「明细」入口；主窗档）
///
/// G-4 修订（用户 2026-10-07 二次反馈「还是没有明细按钮」）：回收站是 Shell 虚拟
/// 命名空间，条目清单由**系统回收站窗口**承载——自绘枚举需要 IShellFolder 遍历
/// （慢、权限面大、海量条目下不现实），打开系统窗口才是「看明细」的合理落地。
///
/// `shell:RecycleBinFolder` 是 explorer 注册的协议名（与 `ms-settings:` 同类），
/// 经 ShellExecuteW「open」解析——与 app.rs 打开 https、finder.rs 打开目录同一姿势，
/// 不经 shell 拼接命令，无命令注入面。
#[tauri::command]
pub fn cleanup_open_recycle_bin<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // 幂等动作（重复点击 = 再次激活同一系统窗口），不经危险确认、不写日志刷盘
    match open_recycle_bin() {
        Ok(()) => json!({ "success": true }),
        Err(e) => json!({ "success": false, "message": e }),
    }
}

/// 打开回收站（ShellExecuteW，不经 shell 拼接命令，避免命令注入）
#[cfg(windows)]
fn open_recycle_bin() -> Result<(), String> {
    use windows::Win32::UI::Shell::ShellExecuteW;
    let op = unsafe {
        ShellExecuteW(
            None,
            windows::core::w!("open"),
            windows::core::w!("shell:RecycleBinFolder"),
            None,
            None,
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW 返回值 <= 32 表示失败
    if op.0 as usize > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecute 返回 {}", op.0 as usize))
    }
}

#[cfg(not(windows))]
fn open_recycle_bin() -> Result<(), String> {
    Err("仅支持 Windows".to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

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

    /// P0-06（R01）：清空后复查为零 ⇒ 回执说「已清空」，且**不**带 partial。
    #[test]
    fn 回执_清空成功且复查为零_不标部分未清空() {
        let r = super::empty_receipt(Some((7, 4096)), Ok((0, 0)));
        assert_eq!(r["success"], json!(true));
        assert_eq!(r["count"], json!(7));
        assert_eq!(r["freed"], json!(4096));
        assert_eq!(r["afterCount"], json!(0));
        assert_eq!(r["afterBytes"], json!(0));
        assert_eq!(r["partial"], json!(false));
        assert_eq!(r["statsFailed"], json!(false));
    }

    /// P0-06（R01）：Shell 说成功但回收站仍有残余 ⇒ 必须标 `partial`，
    /// 让前端能说「部分未清空」而不是「已清空」。
    #[test]
    fn 回执_清空后仍有残余_必须标部分未清空() {
        let r = super::empty_receipt(Some((7, 4096)), Ok((2, 512)));
        assert_eq!(r["afterCount"], json!(2));
        assert_eq!(r["afterBytes"], json!(512));
        assert_eq!(
            r["partial"],
            json!(true),
            "复查非零必须标 partial（否则用户看到的就是假「已清空」）: {r}"
        );
        assert_eq!(r["statsFailed"], json!(false));
    }

    /// P0-06（R01/R02）：复查统计失败 ⇒ `statsFailed`，且 `afterCount`/`afterBytes`
    /// 必须是 null —— **不许拿清空前的旧统计冒充清空后结果**。
    #[test]
    fn 回执_复查统计失败_不得用清空前旧统计冒充() {
        let r = super::empty_receipt(Some((7, 4096)), Err("查询回收站失败（HRESULT 0x80000000）".to_string()));
        assert_eq!(r["statsFailed"], json!(true));
        assert!(
            r["afterCount"].is_null() && r["afterBytes"].is_null(),
            "复查失败时清空后数字必须是 null（旧统计顶替 = R01 的形态）: {r}"
        );
        // 清空前统计仍如实保留（那是「刚刚清掉了多少」的依据，不是清空后结果）。
        assert_eq!(r["count"], json!(7));
        assert_eq!(r["freed"], json!(4096));
        assert_eq!(r["partial"], json!(false), "统计不可得时不得断言「部分未清空」");
        assert!(!r["statsError"].as_str().unwrap_or("").is_empty(), "必须留失败原因");
    }

    /// P0-06：清空前统计也失败时 `count`/`freed` 是 null（不是 0），
    /// 「查不到」与「本来就是 0 项」必须能分开。
    #[test]
    fn 回执_清空前统计失败_回null而不是0() {
        let r = super::empty_receipt(None, Ok((0, 0)));
        assert!(r["count"].is_null() && r["freed"].is_null(), "清空前统计失败必须是 null: {r}");
        assert_eq!(r["statsFailed"], json!(true));
        assert_eq!(r["afterCount"], json!(0), "清空后统计成功时照常给实测值");
    }

    /// P2-04（R03）：权限不足必须给出**用户可操作**的下一步（提权重试），
    /// 而不是只甩一个 HRESULT 让用户自己猜。
    #[test]
    fn 回收站失败_权限不足给出提权出路() {
        let hr = 0x8007_0005u32 as i32;
        let msg = format!(
            "清空回收站失败（HRESULT 0x{:08X}）：{}",
            hr as u32,
            super::classify_shell_failure(hr)
        );
        assert!(msg.contains("权限不足"), "必须点名是权限问题: {msg}");
        assert!(msg.contains("管理员"), "必须给出提权出路: {msg}");
        assert!(msg.contains("0x80070005"), "必须保留原始 HRESULT 供排障: {msg}");
    }

    /// P2-04：未知码不许瞎猜成某一类，但必须保留原始码 + 给重试出路。
    #[test]
    fn 回收站失败_未知码保留原始码且不瞎猜() {
        let hr = 0x1234_5678u32 as i32;
        let msg = format!(
            "查询回收站失败（HRESULT 0x{:08X}）：{}",
            hr as u32,
            super::classify_shell_failure(hr)
        );
        assert!(msg.contains("0x12345678"), "未知码必须原样保留: {msg}");
        assert!(msg.contains("原因未知"), "未知码不得瞎猜成某一类: {msg}");
        assert!(msg.contains("重试"), "未知码也要给出下一步: {msg}");
    }

    /// P2-04：失败文案**不得带路径细节**（回收站里的文件名与盘符属用户隐私，
    /// 不是排障信息）。判据：文案里不许出现路径分隔符与盘符冒号。
    #[test]
    fn 回收站失败文案不得泄露路径细节() {
        for hr in [
            0x8007_0005u32,
            0x8007_0032,
            0x8007_0002,
            0x8007_04C7,
            0x8000_FFFF,
            0x1234_5678,
        ] {
            let msg = format!(
                "清空回收站失败（HRESULT 0x{:08X}）：{}",
                hr,
                super::classify_shell_failure(hr as i32)
            );
            assert!(!msg.contains('\\'), "文案不得含路径分隔符: {msg}");
            assert!(!msg.contains(':'), "文案不得含盘符/路径片段: {msg}");
        }
    }

    /// P2-04：查询与清空**两个**失败出口都必须走分类器 —— 少一处就有一处
    /// 仍是「只甩 HRESULT」。
    ///
    /// 判红自证：把清空出口的分类器调用去掉 ⇒ 本条红。
    #[test]
    fn 两处回收站失败出口都必须走分类器() {
        // 探针自己的字面量不得与被查字符串同形，否则计数把自己算进去。
        let needle = format!("classify_shell_failure({})", "hr");
        // 用例里的 `super::classify_shell_failure(hr)` 调用先剔掉，只数生产出口。
        let src = include_str!("recycle_bin.rs").replace("super::classify_shell_failure(", "");
        assert_eq!(
            src.matches(&needle).count(),
            2,
            "查询与清空两个失败出口都必须细分用户可操作原因: {src}"
        );
    }
}
