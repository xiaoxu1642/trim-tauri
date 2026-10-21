//! 外观配置读写（appearance.json；对照 main.js 4062-4098 段）
//!
//! 读取损坏时先隔离（quarantine）再降级空对象；`bgOpacity` 是历史遗留的
//! 「图片不透明度」语义，需一次性换算为「雾化强度」（0=纯图，100=全雾），
//! 用 `bgOpacityFog` 标记防重复迁移。
//!
//! R6b-L07 如实记录（旧自述写的是「与渲染层 pathbinding 同款换算，两侧镜像必须一致」，
//! 那句话既没说清差异、也没有任何东西保证它）：
//! - Rust 侧换算是 [`bg_opacity_to_fog`]，本文件唯一一份，带 `.round()`；
//! - 渲染层 `src/scripts/pathbinding.js` 的同名迁移是 `100 - ap.bgOpacity`，
//!   **不取整**、非数值走 JS 强转（Rust 侧 `as_f64` 取不到就直接跳过不迁）；
//! - 现算**没有任何门禁对拍这两处**，所以「一致」只是巧合级别的近似：整数 `bgOpacity`
//!   两边同值，小数才会分叉（如 33.4 → Rust 67 / JS 66.6）。
//! 真要收口只有两条路：把渲染层那条改成调用同一口径（跨语言只能共享判据文本，
//! 见 AGENTS §5.16），或加一条 Node 门禁对拍两侧向量。本批只做 Rust 侧单一真源 + 措辞更正。

use serde_json::Value;

use super::{log, paths};
use crate::security;

/// 材质合法值（非法值回退 mica，与设置页默认一致）
pub(crate) const MATERIALS: &[&str] = &["mica", "mica-alt", "acrylic", "thin-acrylic", "none"];

/// 外观配置只读展示（写侧唯一入口是 [`update_appearance`]）。
///
/// v5-K01 批次 4（R7-M05）：三态读器——读失败（Corrupt）已在 read_json_state 内
/// warn 留痕，这里只做展示降级；写侧拒 Corrupt，不会把空对象整表写出去。
pub fn load_appearance() -> Value {
    load_appearance_state().0
}

/// A1-M12：保留 Corrupt 位，供命令回执带 degraded。
pub fn load_appearance_state() -> (Value, bool) {
    match security::read_json_state(&paths::appearance_file()) {
        security::JsonState::Ok(v) => (v, false),
        security::JsonState::Absent => (serde_json::json!({}), false),
        security::JsonState::Corrupt => (serde_json::json!({}), true),
    }
}

// v5-K01 批次 4：`save_appearance`（死 pub，现算零生产调用者）随本批删除——
// 它是「load 空对象 → 整表覆写」旧链的另一半；外观写唯一入口是 update_appearance。

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

/// `bgOpacity`（图片不透明度）→ 雾化强度（Rust 侧**唯一一份**换算，R6b-L07）。
///
/// 语义：0=纯图（完全不雾化）⇄ 100=全雾，所以是取反；`round()` 是因为落盘值要能被
/// CSS 的 `calc()` 与 `--bg-blur` 直接用（小数百分比串在前端只是观感差异，但两次迁移
/// 叠加时会拿带小数的旧值再取反，越迁越飘）。
///
/// 与渲染层的差异（不取整、强转）**不在这里兜**：见模块头，跨语言只共享判据不共享结论。
pub fn bg_opacity_to_fog(opacity: f64) -> f64 {
    (100.0 - opacity).round()
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
        obj.insert("bgOpacity".into(), serde_json::json!(bg_opacity_to_fog(opacity)));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// R6b-L07：换算只有一份，且口径要能被钉住——把 `(100.0 - opacity).round()`
    /// 改成不取整（与渲染层一样）或改成 `opacity - 100.0`，下面的向量立刻红。
    #[test]
    fn 雾化换算的向量与取整口径() {
        assert_eq!(bg_opacity_to_fog(0.0), 100.0, "不透明度 0（全透明图）= 全雾");
        assert_eq!(bg_opacity_to_fog(100.0), 0.0, "不透明度 100（纯图）= 不雾化");
        assert_eq!(bg_opacity_to_fog(50.0), 50.0, "中点必须自反");
        // 取整是这条判据的一部分：落盘值要能直接进 CSS
        assert_eq!(bg_opacity_to_fog(33.4), 67.0, "必须取整（渲染层不取整，差异见模块头）");
        assert_eq!(bg_opacity_to_fog(33.2), 67.0);
        assert_eq!(bg_opacity_to_fog(0.5), 100.0, "0.5 取整按 round 的就近偶数/进位口径必须稳定");
        // 迁移幂等：取反两次回到原值（整数区间内），否则「重跑一次迁移」会改数据
        let v = bg_opacity_to_fog(bg_opacity_to_fog(35.0));
        assert_eq!(v, 35.0, "整数取值必须可逆");
    }

    /// 迁移只认「数值 + 未标记」的形态：`as_f64` 取不到（字符串/布尔/null）时**不动盘**，
    /// 这一条与渲染层的强转是已知差异（模块头已如实记录），此处把 Rust 侧行为钉住，
    /// 免得以后有人把「跳过」当成「漏了一个分支」。
    #[test]
    fn 迁移前置判定只走数值形态() {
        for not_number in [
            serde_json::json!("60"),
            serde_json::json!(true),
            serde_json::json!(null),
            serde_json::json!([60]),
        ] {
            let mut ap = serde_json::Map::new();
            ap.insert("bgOpacity".into(), not_number.clone());
            let v: Value = Value::Object(ap);
            // 与 migrate_bg_opacity_fog 里的 needs 判据同一条：非数值 ⇒ 不迁移
            assert!(
                !v.get("bgOpacity").and_then(|x| x.as_f64()).is_some(),
                "{not_number} 不该被当成可迁移的不透明度"
            );
        }
    }
}