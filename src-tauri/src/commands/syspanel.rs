//! syspanel 域（P2 §3.6）：电源计划三档读写 + 虚拟内存只读
//!
//! 本域电源相关通道都走 `guard(window, MAIN)`（AGENTS §3 三层）：写侧、系统级、只在主窗触发；
//! 虚拟内存与电源计划同域，一并 MAIN。
//! 前端只在主窗「Windows设置」页（2026-10-15 从设置页迁出）的电源计划与虚拟内存
//! 卡片里调用，其他窗口拿不到入口。
//!
//! 命令命名与 CHANNEL_MAP 键一一对应；v5 P0 后电源计划与逐设置编辑 13 条，
//! G-04 专用能力（开启卓越性能 / 隐藏高性能 / 还原高性能，2026-10-16）新增 3 条共 16 条。
//!
//! # 返回体必须是 `{ success, data }`（不是裸对象）
//!
//! 渲染层 `src/scripts/syspanel.js` 对四条通道一律按 `resp.success` / `resp.data` 取值。
//! 早期这两条读侧命令直接返回裸 state，裸对象没有 `success` 字段 ⇒ 前端恒判失败 ⇒
//! 面板上两块永远显示「读取电源方案失败 / 读取虚拟内存失败」，而后端其实读到了数据。
//! **命令层换签名不换回执形状，等于把失败伪装成数据缺失**；新增同域命令时照抄
//! `json!({"success": true, "data": …})`，别只抄签名。
//!
//! （判红点：`tests/module_smoke.rs::syspanel_回执必须是_success_data_包装`。断言取
//! 本文件的**生产段**再匹配 —— 判据字面量一旦出现在这段注释里，反向判据就会匹配到
//! 自己而恒红。本仓已因此踩过多次，substring 判据必须与被禁写法逐字错开。）

use serde_json::{Value, json};
use tauri::{AppHandle, Runtime, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::engine::guard;
use crate::engine::native::{
    PagefileEntry, PowerSettingChange, pagefile_apply, pagefile_state, power_high_performance_hide,
    power_high_performance_restore, power_plan_apply, power_plan_delete, power_plan_duplicate,
    power_plan_export, power_plan_import, power_plan_rename, power_plan_state,
    power_setting_compare, power_setting_open_regedit, power_settings_apply, power_settings_dump,
    power_settings_revert, power_settings_unlock, power_ultimate_enable,
};

fn syspanel_ok(data: Value) -> Result<Value, String> {
    Ok(json!({ "success": true, "data": data }))
}

fn syspanel_result_from_data(data: Value) -> Result<Value, String> {
    let success = data.get("ok").and_then(Value::as_bool).unwrap_or(true);
    Ok(json!({ "success": success, "data": data }))
}

fn require_admin_for_power_edit() -> Result<(), String> {
    if crate::engine::sysinfo::is_admin() {
        Ok(())
    } else {
        Err("编辑电源计划需要管理员权限，请先通过编辑入口提权重启 Trim".to_string())
    }
}

#[tauri::command]
pub fn syspanel_power_plan_get<R: Runtime>(
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    syspanel_ok(power_plan_state())
}

#[tauri::command]
pub fn syspanel_power_plan_apply<R: Runtime>(
    window: WebviewWindow<R>,
    guid: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    power_plan_apply(&guid).map(|state| json!({ "success": true, "data": state }))
}

#[tauri::command]
pub fn syspanel_power_settings_dump<R: Runtime>(
    window: WebviewWindow<R>,
    scheme_guid: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    power_settings_dump(&scheme_guid).and_then(syspanel_ok)
}

#[tauri::command]
pub fn syspanel_power_plan_duplicate<R: Runtime>(
    window: WebviewWindow<R>,
    source_guid: String,
    name: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    power_plan_duplicate(&source_guid, &name).and_then(syspanel_ok)
}

#[tauri::command]
pub fn syspanel_power_plan_rename<R: Runtime>(
    window: WebviewWindow<R>,
    guid: String,
    name: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    power_plan_rename(&guid, &name).and_then(syspanel_ok)
}

#[tauri::command]
pub fn syspanel_power_plan_delete<R: Runtime>(
    window: WebviewWindow<R>,
    guid: String,
    confirmed_high_risk: bool,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if !confirmed_high_risk {
        return Err("删除电源方案需要二次确认后重试".to_string());
    }
    power_plan_delete(&guid).and_then(syspanel_ok)
}

#[tauri::command]
pub async fn syspanel_power_plan_import<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let picked = app
        .dialog()
        .file()
        .set_title("导入电源计划")
        .add_filter("电源计划文件", &["powrplan"])
        .blocking_pick_file();
    let Some(path) = picked else {
        return syspanel_ok(json!({ "canceled": true }));
    };
    let path = path
        .into_path()
        .map_err(|e| format!("无效的导入路径：{e}"))?;
    power_plan_import(&path).and_then(syspanel_ok)
}

#[tauri::command]
pub async fn syspanel_power_plan_export<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    guid: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    let picked = app
        .dialog()
        .file()
        .set_title("导出电源计划")
        .set_file_name("电源计划.powrplan")
        .add_filter("电源计划文件", &["powrplan"])
        .blocking_save_file();
    let Some(path) = picked else {
        return syspanel_ok(json!({ "canceled": true }));
    };
    let path = path
        .into_path()
        .map_err(|e| format!("无效的导出路径：{e}"))?;
    power_plan_export(&guid, &path).and_then(syspanel_ok)
}

/// G-04「开启卓越性能」（2026-10-16 裁定）：已存在则直接激活，不存在则先克隆再激活。
/// 全部走 `guard(MAIN)`（写侧、系统级、只在主窗触发）；系统级失败按 Win32 错误如实报，
/// 权限不足（错误码 5）由引擎层给显式提权提示，不谎报「不支持」。
#[tauri::command]
pub fn syspanel_power_ultimate_enable<R: Runtime>(
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    power_ultimate_enable().and_then(syspanel_ok)
}

/// G-04「隐藏高性能」（2026-10-16 裁定，终态 = 导出 + 删除）：高危删除类操作，
/// 与通用删除同口径走 `confirmedHighRisk` 二次确认；引擎层只认内置高性能 GUID。
#[tauri::command]
pub fn syspanel_power_hide_high_performance<R: Runtime>(
    window: WebviewWindow<R>,
    confirmed_high_risk: bool,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    if !confirmed_high_risk {
        return Err("隐藏「高性能」会从系统移除该方案，需要二次确认后重试".to_string());
    }
    power_high_performance_hide().and_then(syspanel_ok)
}

/// G-04「还原高性能」：用隐藏时记录的备份导入回来（已存在同名方案时不重复导入）。
#[tauri::command]
pub fn syspanel_power_restore_high_performance<R: Runtime>(
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    power_high_performance_restore().and_then(syspanel_ok)
}

#[tauri::command]
pub fn syspanel_power_settings_unlock<R: Runtime>(
    window: WebviewWindow<R>,
    scheme_guid: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    // 非管理员只写一次性意图并把 token 交回渲染层；真正的 restart 由 elevate_request(launchToken)
    // 负责，新实例消费到同一 token 后才允许进入编辑会话。
    let _ = power_settings_dump(&scheme_guid)?;
    if !crate::engine::sysinfo::is_admin() {
        let launch_token = crate::commands::elevate::write_pending_edit_intent(&scheme_guid)?;
        return syspanel_ok(json!({
            "needsElevation": true,
            "launchToken": launch_token,
            "schemeGuid": scheme_guid,
        }));
    }
    power_settings_unlock(&scheme_guid).and_then(syspanel_result_from_data)
}

#[tauri::command]
pub fn syspanel_power_settings_apply<R: Runtime>(
    window: WebviewWindow<R>,
    scheme_guid: String,
    changes: Vec<PowerSettingChange>,
    apply_active: bool,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    require_admin_for_power_edit()?;
    power_settings_apply(&scheme_guid, &changes, apply_active).and_then(syspanel_result_from_data)
}

#[tauri::command]
pub fn syspanel_power_settings_revert<R: Runtime>(
    window: WebviewWindow<R>,
    scheme_guid: String,
    session_id: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    require_admin_for_power_edit()?;
    power_settings_revert(&scheme_guid, &session_id).and_then(syspanel_result_from_data)
}

#[tauri::command]
pub fn syspanel_power_settings_compare<R: Runtime>(
    window: WebviewWindow<R>,
    subgroup_guid: String,
    setting_guid: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    power_setting_compare(&subgroup_guid, &setting_guid).and_then(syspanel_ok)
}

#[tauri::command]
pub fn syspanel_power_settings_open_regedit<R: Runtime>(
    window: WebviewWindow<R>,
    subgroup_guid: String,
    setting_guid: String,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    power_setting_open_regedit(&subgroup_guid, &setting_guid).and_then(syspanel_ok)
}

#[tauri::command]
pub fn syspanel_pagefile_state<R: Runtime>(
    window: WebviewWindow<R>,
) -> Result<Value, String> {
    guard::guard(&window, guard::MAIN)?;
    Ok(json!({ "success": true, "data": pagefile_state() }))
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
    pagefile_apply(managed, &entries).map(|state| json!({ "success": true, "data": state }))
}
