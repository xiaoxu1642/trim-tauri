//! 外观配置读写（appearance.json；对照 main.js 4062-4098 段）
//!
//! 读取损坏时先隔离（quarantine）再降级空对象；`bgOpacity` 是历史遗留的
//! 「图片不透明度」语义，需一次性换算为「雾化强度」（0=纯图，100=全雾），
//! 用 `bgOpacityFog` 标记防重复迁移——与渲染层 pathbinding 的 localStorage
//! 迁移同款换算，两侧镜像必须一致。

use serde_json::Value;

use super::{log, paths};
use crate::security;

/// 材质合法值（非法值回退 mica，与设置页默认一致）
const MATERIALS: &[&str] = &["mica", "mica-alt", "acrylic", "thin-acrylic", "none"];

pub fn load_appearance() -> Value {
    security::read_json_or_quarantine(&paths::appearance_file())
}

pub fn save_appearance(v: &Value) {
    if let Err(e) = security::atomic_write_json(&paths::appearance_file(), v) {
        log::write_log("error", &format!("保存外观配置失败: {e}"));
    }
}

/// 读-改-写（v4 P2-D 尾 / R7-M01 同族）：读失败拒写（Corrupt ⇒ Err）。
///
/// 旧链 `load_appearance() → 改一处 → save_appearance()` 在读取损坏/失败时拿到 `{}`，
/// 一次「切个材质」就把整份外观配置（背景图/字体/雾化/材质…）覆成只剩这一项。
pub fn update_appearance<F>(f: F) -> Result<Value, String>
where
    F: FnOnce(&mut Value) -> Result<(), String>,
{
    crate::security::update_json(&paths::appearance_file(), f)
}

/// 读取持久化的合法材质（非法/缺失回退 mica）
pub fn saved_material() -> String {
    let ap = load_appearance();
    normalize_material(ap.get("material").and_then(|v| v.as_str()))
}

/// 材质总开关是否启用（窗口界面升级3：关闭 = 生效材质置 none，所选材质保留记忆）
pub fn material_enabled() -> bool {
    let ap = load_appearance();
    ap.get("materialEnabled").and_then(|v| v.as_bool()) != Some(false)
}

/// 生效材质：总开关关闭时一律 none
pub fn effective_material() -> String {
    if material_enabled() {
        saved_material()
    } else {
        "none".into()
    }
}

pub fn normalize_material(raw: Option<&str>) -> String {
    match raw {
        Some(m) if MATERIALS.contains(&m) => m.to_string(),
        _ => "mica".into(),
    }
}

/// 启动时执行一次 bgOpacity 语义迁移（幂等）
pub fn migrate_bg_opacity_fog() {
    // 先只读判定：不需要迁移时**不写盘**（update_appearance 的闭包跑完必落盘，
    // 每次启动都重写一遍文件没有意义）。需要迁移时才进原语，在最新盘上值上改。
    let ap = load_appearance();
    let needs = ap.get("bgOpacity").and_then(|v| v.as_f64()).is_some()
        && ap.get("bgOpacityFog").and_then(|v| v.as_bool()) != Some(true);
    if !needs {
        return;
    }
    let res = update_appearance(|ap| {
        let Some(obj) = ap.as_object_mut() else { return Ok(()) };
        let Some(opacity) = obj.get("bgOpacity").and_then(|v| v.as_f64()) else {
            return Ok(());
        };
        if obj.get("bgOpacityFog").and_then(|v| v.as_bool()) == Some(true) {
            return Ok(());
        }
        obj.insert(
            "bgOpacity".into(),
            serde_json::json!((100.0 - opacity).round()),
        );
        obj.insert("bgOpacityFog".into(), serde_json::json!(true));
        Ok(())
    });
    if let Err(e) = res {
        log::write_log("warn", &format!("appearance 雾化度语义迁移跳过（读取失败，未写入）: {e}"));
        return;
    }
    log::write_log(
        "info",
        "appearance.json 雾化度语义已迁移（旧图片不透明度 → 雾化强度）",
    );
}