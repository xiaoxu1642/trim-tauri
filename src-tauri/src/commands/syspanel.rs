//! syspanel 域（P2 §3.6）：电源计划三档读写 + 虚拟内存只读
//!
//! 三条通道都走 `guard(window, MAIN)`（AGENTS §3 三层）：写侧、系统级、只在主窗触发；
//! 虚拟内存本轮只读但同域，一并 MAIN —— 下一批加写侧时不用再改档位。
//! 前端只在 `settings` 页底部"系统面板"卡里调用，其他窗口拿不到入口。
//!
//! 命令命名与 CHANNEL_MAP 键一一对应：`syspanel:power-plan-get` / `-apply` / `pagefile-state`。

use serde_json::Value;
use tauri::{Runtime, WebviewWindow};

use crate::engine::guard;
use crate::engine::native::{PagefileEntry, pagefile_apply, pagefile_state, power_plan_apply, power_plan_state};

#[tauri::command]
pub fn syspanel_power_plan_get<R: Runtime>(
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    Ok(power_plan_state())
}

#[tauri::command]
pub fn syspanel_power_plan_apply<R: Runtime>(
    window: WebviewWindow<R>,
    guid: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    power_plan_apply(&guid)
}

#[tauri::command]
pub fn syspanel_pagefile_state<R: Runtime>(
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    Ok(pagefile_state())
}

/// 虚拟内存写侧（v0.4.9 §3.6 落法另一半）：改 `AutomaticManagedPagefile`
/// 与 `PagingFiles`（手动模式下）。**高危**：
///  - 全关（entries=[] 或全 0/0）会导致物理内存耗尽时蓝屏，参数校验层直接拒
///  - 写后**需要重启才生效**（返回体里 `requiresReboot: true`），渲染层必须显式提示
///  - 走 `confirmedHighRisk: true` 二次确认（AGENTS §5.4 顶层参数 Tauri 自动转 camelCase；
///    `PagefileEntry` 字段是嵌套结构体，用 `#[serde(rename_all = "camelCase")]` 显式声明）
///  - admin 硬要求由 `pagefile_apply` 内部把关，与 `elevate_request` 主窗通道配套用
#[tauri::command]
pub fn syspanel_pagefile_apply<R: Runtime>(
    window: WebviewWindow<R>,
    managed: bool,
    entries: Vec<PagefileEntry>,
    confirmed_high_risk: bool,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if !confirmed_high_risk {
        return Err("虚拟内存改动风险高（关错配置可能导致蓝屏），需要二次确认后重试".into());
    }
    pagefile_apply(managed, &entries)
}
