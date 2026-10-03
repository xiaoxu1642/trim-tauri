//! 批量优化项的「可自选目标」子清单（2026-10-03 用户裁定）。
//!
//! # 为什么要这一层
//!
//! 「移除 25 个内置 UWP 应用」「禁用 24 个冗余外设」「禁用 70+ 非必要服务」这三项
//! 此前只有两个出口：一键全选 / 一键全还原。用户看到的是「禁用 70 个服务」这种
//! **不可拆的黑箱**——里面有 `CryptSvc`（证书与 BitLocker 全靠它）和 `Netlogon`
//! （域账号登录），也有一眼就知道可禁的 `RetailDemo`。让人「一把梭」等于逼他
//! 在「全选」和「放弃」之间二选一。
//!
//! # 为什么不拆成 70 个独立优化项
//!
//! 那会让分类看板被单一维度撑爆（70 列），且每项都要独立的备份 / 检测 / 还原记账。
//! 真正的诉求是「同一批里挑几个」，不是「它们是彼此独立的优化决策」——所以保留
//! 批次粒度，在**批次内部**给选择权。
//!
//! # 清单真源与本表的关系（关键约束）
//!
//! 真源始终是 `optimizer-runtime.json` 里该项的 pwsh 文本。本表
//! `data/optimizer-subitems.json` 只登记「哪些目标值得单独列出来 + 中文解释 + 附带开关」，
//! 由 `tools/check-optimizer-subitem-contract.mjs` 强制 `targets` ⊆ 脚本里的 `@("...")`。
//! 手抄一份完整清单进本表就是制造第二份真源，漂了没有任何门禁会响。
//!
//! # 脚本重建而不是脚本改写
//!
//! 选中子集后**重跑一遍同样的动作、只喂选中的名字**（`rebuild_steps`），
//! 而不是去解析原脚本再改写 —— 后者要处理转义与语句边界，脆弱且不可测。
//! `pssteps::compile` 仍会对重建后的脚本做同一套编译校验。

use serde_json::{Value, json};
use std::sync::OnceLock;

/// 可自选目标清单（编译期内嵌；与 catalog.rs 其它侧表同一手法）
const SUBITEMS_JSON: &str = include_str!("../../../data/optimizer-subitems.json");

fn subitems_root() -> &'static Value {
    static CACHE: OnceLock<Value> = OnceLock::new();
    CACHE.get_or_init(|| {
        serde_json::from_str(SUBITEMS_JSON).expect("optimizer-subitems.json 合法")
    })
}

/// 某项的子清单；不在表里 = 该项不支持自选（前端不给勾选界面）
pub(super) fn subitems_of(option_id: &str) -> Option<Value> {
    let raw = subitems_root().get("items")?.get(option_id)?;
    // 把 `labels: {名字: 说明}` 摊成前端要的 `{value, label, note}` 数组。
    //
    // 为什么在 Rust 侧摊而不是让前端读 map：渲染层要按 `targets` 的**顺序**渲染
    // 勾选行（顺序 = 数据层脚本里的顺序 = 用户在详情里从上往下读的预期顺序），
    // 而 JS 对象键序在跨引擎时並不保证。让前端自己按 targets 遍历再查 map 才对，
    // 但那样等于把「map 缺键怎么办」的决定权交给渲染层 —— 缺键就渲染成空白行。
    // 摊平之后：未登记解释的目标**不出现**在勾选列表里（全选路径仍会执行到它们，
    // 由门禁断言覆盖率棘轮盯着解释文案的补齐进度）。
    let labels = raw.get("labels").and_then(Value::as_object).cloned().unwrap_or_default();
    let items: Vec<Value> = raw
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|t| {
            let t = t.as_str()?;
            let note = labels.get(t)?.as_str()?;
            Some(json!({ "value": t, "note": note }))
        })
        .collect();
    Some(json!({
        "label": raw.get("label"),
        "hint": raw.get("hint"),
        "items": items,
        "extras": raw.get("extras").cloned().unwrap_or(json!([])),
        // 未登记解释的目标数：界面上如实告知「还有 N 个没有单独说明」，
        // 而不是让用户以为清单就这么多。
        "unexplained": raw
            .get("targets")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0)
            .saturating_sub(items.len()),
    }))
}

/// 这一项是否支持自选目标
pub(super) fn supports_subitems(option_id: &str) -> bool {
    subitems_of(option_id).is_some()
}

/// 侧表里的原始一行（未经摊平）
fn raw_of(option_id: &str) -> Option<&'static Value> {
    subitems_root().get("items")?.get(option_id)
}

/// 清单里登记的全部目标（顺序 = 脚本里的顺序）
fn targets_of(option_id: &str) -> Vec<String> {
    raw_of(option_id)
        .and_then(|v| v.get("targets").and_then(Value::as_array).cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|x| x.as_str().map(String::from))
        .collect()
}

/// 附带开关（与清单不同形状的写入，例如「wuauserv 改手动」「关闭 Edge 预加载」）
fn extras_of(option_id: &str) -> Vec<String> {
    raw_of(option_id)
        .and_then(|v| v.get("extras").and_then(Value::as_array).cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|x| x.get("id").and_then(Value::as_str).map(String::from))
        .collect()
}

/// PowerShell 单引号串字面量（内部 `'` → `''`）。
///
/// **为什么不用双引号**：目标名来自侧表 JSON，虽经门禁对拍与脚本一致，但一旦上游
/// 数据层某天塞进一个带 `"` 或 `$` 的名字，双引号形态会被 PowerShell 当成变量/转义
/// 展开 —— 那是「静默写错服务」而不是「写失败」。单引号是字面量，唯一需要处理的
/// 只有 `'` 本身，而服务名与 AppX 通配名里不可能有单引号（真出现了也只会被转义，
/// 不会变成可执行片段）。
fn ps_single_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// 按用户勾选重建该项的 steps。
///
/// `picked` 为空或 `None` ⇒ **全选**（保持旧行为：跑原脚本，一步不动）。
/// 这是刻意保留的默认：老用户不该因为升级就发现「全选」按钮没了。
///
/// `picked` 非空 ⇒ 只对选中的目标执行对应动作。**未在清单里的 id 一律忽略**
/// （不是报错）：清单会随数据层增补，界面上勾不到的东西不该由参数硬塞进来。
pub(super) fn rebuild_steps(
    option_id: &str,
    picked: Option<&[String]>,
    picked_extras: Option<&[String]>,
) -> Option<Vec<Value>> {
    let all = targets_of(option_id);
    if all.is_empty() {
        return None;
    }
    // 全选路径：原脚本整段照抄，一步不动（不做「用全清单重建」——
    // 那会让脚本文本与数据层产生第二处分叉，而全选时重建没有任何收益）
    let Some(picked) = picked.filter(|p| !p.is_empty()) else {
        return None;
    };
    let selected: Vec<String> = all
        .iter()
        .filter(|t| picked.iter().any(|p| p == *t))
        .cloned()
        .collect();
    if selected.is_empty() {
        // 勾了一个都不在清单里：交回 None 会被上层当「全选」，**绝不能这样**。
        // 空步骤让上层走「选项无可执行步骤」的拒绝分支。
        return Some(Vec::new());
    }
    let list = selected
        .iter()
        .map(|s| ps_single_quoted(s))
        .collect::<Vec<_>>()
        .join(",");

    let (label, body) = match option_id {
        // 服务：Start=4 + 停服
        "tf_svc_bulk" | "tf_drv_disable" => (
            format!(
                "按选择禁用 {} / {} 项服务（启动类型=禁用）",
                selected.len(),
                all.len()
            ),
            format!(
                "$picked = @({list})\n\
foreach ($n in $picked) {{ $p = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n\"; if (Test-Path $p) {{ New-ItemProperty -Path $p -Name Start -Value 4 -PropertyType DWord -Force | Out-Null; Stop-Service -Name $n -Force -ErrorAction SilentlyContinue }} }}"
            ),
        ),
        // AppX：按通配名移除
        "tf_appx" => (
            format!("按选择移除 {} / {} 个内置应用", selected.len(), all.len()),
            format!(
                "$picked = @({list})\n\
foreach ($a in $picked) {{ Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue }}"
            ),
        ),
        _ => return None,
    };

    let mut steps = vec![json!({ "label": label, "pwsh": body })];
    // 附带开关：与清单不同形状的写入，逐个独立成步（失败可归因到具体开关）
    for ex in extras_of(option_id) {
        if !picked_extras.is_some_and(|e| e.iter().any(|p| *p == ex)) {
            continue;
        }
        if let Some(step) = extra_step(option_id, &ex) {
            steps.push(step);
        }
    }
    Some(steps)
}

/// 附带开关对应的步骤。**只在 sidecar 登记过 id 时才可能命中**（`extras_of` 已过滤），
/// 这里的 `_ => None` 是 fail-closed 兜底：数据层多写了一个 id 也不会凭空多一步写入。
fn extra_step(option_id: &str, extra_id: &str) -> Option<Value> {
    match (option_id, extra_id) {
        ("tf_svc_bulk", "wuau_manual") => Some(json!({
            "label": "wuauserv 改为手动启动（保持 Windows Update 可用）",
            "pwsh": "$p = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\wuauserv\"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 3 -PropertyType DWord -Force | Out-Null }"
        })),
        ("tf_svc_bulk", "lfsvc_status") => Some(json!({
            "label": "清零位置服务状态（让 lfsvc 彻底不工作）",
            "pwsh": "$p = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration\"; New-Item -Path $p -Force -ErrorAction SilentlyContinue | Out-Null; New-ItemProperty -Path $p -Name Status -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null"
        })),
        ("tf_svc_bulk", "edge_prelaunch") => Some(json!({
            "label": "关闭 Edge 预启动与标签预加载",
            "pwsh": "$a = \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main\"\nNew-Item -Path $a -Force -ErrorAction SilentlyContinue | Out-Null\nNew-ItemProperty -Path $a -Name AllowPrelaunch -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null\n$b = \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\TabPreloader\"\nNew-Item -Path $b -Force -ErrorAction SilentlyContinue | Out-Null\nNew-ItemProperty -Path $b -Name AllowTabPreloading -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null"
        })),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn 三项都支持自选且有目标() {
        for id in ["tf_svc_bulk", "tf_drv_disable", "tf_appx"] {
            assert!(supports_subitems(id), "{id} 应支持自选目标");
            assert!(
                targets_of(id).len() >= 19,
                "{id} 目标数过少：{}",
                targets_of(id).len()
            );
            // 下发结构：前端按 items 数组渲染勾选行
            let sub = subitems_of(id).expect("应下发子清单");
            let items = sub["items"].as_array().expect("items 必须是数组");
            assert!(!items.is_empty(), "{id} 的 items 为空");
            for it in items {
                assert!(it["value"].is_string(), "{id} 勾选项缺 value");
                assert!(it["note"].is_string(), "{id} 勾选项缺 note");
            }
            // unexplained 必须等于「总数 - 有解释数」，界面上要如实告知
            let total = sub["unexplained"].as_u64().unwrap() + items.len() as u64;
            assert_eq!(total as usize, targets_of(id).len(), "{id} unexplained 口径不对");
        }
        assert!(!supports_subitems("tf_ntfs"), "非批量项不该被判为支持自选");
    }

    /// 勾选子集 ⇒ 脚本里**只出现**选中的名字，且带正确的动作语义。
    ///
    /// 判据是「未选中项不得出现在重建脚本里」：这是「用户只勾了 3 个却禁了 70 个」
    /// 这类越权写入的唯一机械拦截点。只断言条数会漏掉「顺序串了」的形态。
    #[test]
    fn 勾选子集只写入选中的目标() {
        let picked = s(&["RetailDemo", "lltdsvc", "sedsvc"]);
        let steps = rebuild_steps("tf_svc_bulk", Some(&picked), None).expect("应重建出步骤");
        assert_eq!(steps.len(), 1, "未选附带开关时只应有清单这一步");
        let pwsh = steps[0]["pwsh"].as_str().expect("pwsh 字段");
        for want in ["RetailDemo", "lltdsvc", "sedsvc"] {
            assert!(pwsh.contains(want), "重建脚本缺少选中项 {want}: {pwsh}");
        }
        // 未选中项一个都不许出现（含子串误伤：sedsvc 出现过 ⇒ sedsvc 不该再出现第二次）
        for absent in ["CryptSvc", "Netlogon", "Themes", "WpnService"] {
            assert!(
                !pwsh.contains(absent),
                "未选中的 {absent} 出现在重建脚本里 —— 会越权写入: {pwsh}"
            );
        }
        // 动作语义：服务是 Start=4 + 停服
        assert!(pwsh.contains("-Name Start -Value 4"), "服务项必须写 Start=4: {pwsh}");
        assert!(pwsh.contains("Stop-Service"), "服务项必须停服: {pwsh}");
    }

    #[test]
    fn appx_子集用通配名移除() {
        let picked = s(&["*solit*", "*Sway*"]);
        let steps = rebuild_steps("tf_appx", Some(&picked), None).unwrap();
        let pwsh = steps[0]["pwsh"].as_str().unwrap();
        assert!(pwsh.contains("'*solit*'") && pwsh.contains("'*Sway*'"), "{pwsh}");
        assert!(!pwsh.contains("*OneNote*"), "未选中项混入: {pwsh}");
        assert!(pwsh.contains("Remove-AppxPackage"), "{pwsh}");
    }

    /// 全选路径必须**原样返回 None**（= 走数据层原脚本），不得重跑一遍「用清单重建」。
    ///
    /// 这条锁的是「不制造第二分叉」：全选时重建出来的脚本与数据层文本必然有细微差别
    /// （缩进、引号形态），而它没有任何收益。
    #[test]
    fn 全选走原脚本不重建() {
        assert!(rebuild_steps("tf_svc_bulk", None, None).is_none());
        assert!(rebuild_steps("tf_svc_bulk", Some(&[]), None).is_none());
    }

    /// 一个都没勾中 ⇒ 返回**空 steps**而不是 None。
    ///
    /// 形态很关键：返回 None 会被上层解读为「没指定子集」= 全选，于是用户点了「执行」
    /// 却把 70 个服务全禁了 —— 与用户意图完全相反。
    #[test]
    fn 空选择返回空步骤而非全选() {
        let steps = rebuild_steps("tf_svc_bulk", Some(&s(&["__不存在__"])), None).unwrap();
        assert!(steps.is_empty(), "不在清单里的 id 应产出空步骤让上层拒绝，而不是全选");
    }

    #[test]
    fn 附带开关各自独立成步() {
        let picked = s(&["RetailDemo"]);
        let extras = s(&["wuau_manual", "edge_prelaunch", "__不存在__"]);
        let steps = rebuild_steps("tf_svc_bulk", Some(&picked), Some(&extras)).unwrap();
        // 1 步清单 + 2 个真实附带开关（未登记 id 被忽略）
        assert_eq!(steps.len(), 3, "步数不对：{:?}", steps.iter().map(|x| &x["label"]).collect::<Vec<_>>());
        let joined: String = steps.iter().filter_map(|x| x["pwsh"].as_str()).collect();
        assert!(joined.contains("wuauserv"), "{joined}");
        assert!(joined.contains("AllowTabPreloading"), "{joined}");
        // wuauserv 那步是「改手动 3」不是「禁用 4」
        assert!(joined.contains("-Name Start -Value 3"), "{joined}");
    }

    /// 名称里的引号必须被转义 —— 单引号串字面量的唯一风险点。
    #[test]
    fn 目标名引号被正确转义() {
        assert_eq!(ps_single_quoted("Svc"), "'Svc'");
        assert_eq!(ps_single_quoted("a'b"), "'a''b'");
        // $ 与 " 在单引号内是字面量，不会被 PowerShell 展开
        assert_eq!(ps_single_quoted("$env:X\"y"), "'$env:X\"y'");
    }
}
