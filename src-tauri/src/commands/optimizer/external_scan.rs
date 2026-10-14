//! 「账外核对」：只读扫描社区常见、但**不在优化项目录**里的手动 tweak 键（2026-10-15 拍板）。
//!
//! 存在意义：用户可能用 `.reg` 素材或第三方工具直接改过一批「低延迟 / 缓解拆除」类键，
//! Trim 的优化台账对此一无所知（cankao/3 报告 §5.2：无痕改键是本目录最大的威胁面）——
//! 本命令把这些**账外**改动呈现出来。**只读**：不提供任何一键还原（拍板口径：只读清单）。
//!
//! 判据是**现值命中制**：不判「≠ 默认」（默认值知识不完备、必误报），只报「现值等于已知
//! 社区形态」的项；键/值不存在、类型不符一律静默跳过（机器间差异是常态，不是错误）。

use serde_json::{json, Value};
use tauri::{Runtime, WebviewWindow};

use crate::engine::guard;
use crate::engine::native::{hive_hklm, read_reg_dword_opt};

struct ExtTweak {
    id: &'static str,
    title: &'static str,
    subkey: &'static str,
    value_name: &'static str,
    /// (命中值, 形态名)；命中值按无符号 DWORD 比较（0xFFFFFFFF = 4294967295）
    hits: &'static [(i64, &'static str)],
    note: &'static str,
}

const KERNEL: &str = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";
const SESSION_MGR: &str = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";
const SESSION_POWER: &str = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power";
const MM_PROFILE: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile";

const EXTERNAL_TWEAKS: &[ExtTweak] = &[
    ExtTweak {
        id: "ext_sehop_off",
        title: "SEHOP 异常链保护被关闭",
        subkey: KERNEL,
        value_name: "KernelSEHOPEnabled",
        hits: &[(0, "SEHOP 关闭")],
        note: "社区低延迟素材的常见改法，会削弱漏洞利用缓解能力；Trim 未覆盖此机制，不提供一键还原。",
    },
    ExtTweak {
        id: "ext_seh_chain_off",
        title: "SEH 链校验被关闭",
        subkey: KERNEL,
        value_name: "DisableExceptionChainValidation",
        hits: &[(1, "SEH 链校验关闭")],
        note: "与 SEHOP 通常成套写入（缓解拆除类素材），会削弱异常链保护。",
    },
    ExtTweak {
        id: "ext_mitigation_override",
        title: "漏洞缓解设置被位图整体覆盖",
        subkey: KERNEL,
        value_name: "FeatureSettingsOverride",
        hits: &[(3, "缓解位图覆盖")],
        note: "以位图方式整体覆盖 Exploit Protection 的缓解设置（常见与其 Mask 键成套），影响面大。",
    },
    ExtTweak {
        id: "ext_cfg_off",
        title: "CFG 控制流保护被关闭",
        subkey: KERNEL,
        value_name: "EnableCfg",
        hits: &[(0, "CFG 关闭")],
        note: "关闭控制流保护（CFG），属缓解拆除类改法。",
    },
    ExtTweak {
        id: "ext_dll_order",
        title: "DLL 搜索顺序策略被改动",
        subkey: SESSION_MGR,
        value_name: "SearchOrderConfig",
        hits: &[(0, "搜索顺序调整")],
        note: "社区调优素材里的「DLL 搜索顺序」改法，实际效果存在争议。",
    },
    ExtTweak {
        id: "ext_hiberboot_off",
        title: "快速启动被关闭",
        subkey: SESSION_POWER,
        value_name: "HiberbootEnabled",
        hits: &[(0, "快速启动关闭")],
        note: "与 Trim「关闭休眠与快速启动」的写入同值——若这状态是手工改键而来，Trim 台账里不会有它的记账。",
    },
    ExtTweak {
        id: "ext_sysresp_0",
        title: "多媒体调度响应被设为 0",
        subkey: MM_PROFILE,
        value_name: "SystemResponsiveness",
        hits: &[(0, "响应设为 0")],
        note: "社区低延迟口径给 0；Trim 的同类优化按 10 写入（两者口径不同，手工导入会无痕覆盖 Trim 的取值）。",
    },
    ExtTweak {
        id: "ext_net_throttle_off",
        title: "网络限流已关闭",
        subkey: MM_PROFILE,
        value_name: "NetworkThrottlingIndex",
        hits: &[(4294967295, "限流关闭")],
        note: "与 Trim 同值（net_response / tf_net_tcp 也写此值）——若为手工改键而来，同样是无记账状态。",
    },
];

/// 纯判定：现值命中任一已知形态 → Some(形态名)。可单测。
fn judge_external(current: Option<i64>, hits: &[(i64, &'static str)]) -> Option<&'static str> {
    let cur = current?;
    hits.iter().find(|(v, _)| *v == cur).map(|(_, s)| *s)
}

#[tauri::command]
pub fn optimizer_external_scan<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let hive = hive_hklm();
    let findings: Vec<Value> = EXTERNAL_TWEAKS
        .iter()
        .filter_map(|t| {
            let current = read_reg_dword_opt(hive, t.subkey, t.value_name);
            let shape = judge_external(current, t.hits)?;
            Some(json!({
                "id": t.id,
                "title": t.title,
                "hive": "HKLM",
                "subkey": t.subkey,
                "value": t.value_name,
                "current": current,
                "shape": shape,
                "note": t.note,
            }))
        })
        .collect();
    json!({
        "success": true,
        "data": { "scanned": EXTERNAL_TWEAKS.len(), "findings": findings }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits_of(id: &str) -> &'static [(i64, &'static str)] {
        EXTERNAL_TWEAKS.iter().find(|t| t.id == id).expect("表里应有该项").hits
    }

    #[test]
    fn 命中判定按无符号值比对() {
        let hits = hits_of("ext_net_throttle_off");
        // 0xFFFFFFFF 必须按无符号 4294967295 命中（read_reg_dword_opt 已按无符号读出）
        assert_eq!(judge_external(Some(4294967295), hits), Some("限流关闭"));
        assert_eq!(judge_external(Some(10), hits), None, "其它值不算命中");
        assert_eq!(judge_external(None, hits), None, "值不存在不命中");
    }

    #[test]
    fn 未命中与缺值一律静默() {
        for t in EXTERNAL_TWEAKS {
            assert!(judge_external(None, t.hits).is_none(), "{}: 缺值必须不命中", t.id);
            let miss = t.hits.iter().map(|(v, _)| v + 1).collect::<Vec<_>>();
            for m in miss {
                assert!(judge_external(Some(m), t.hits).is_none(), "{}: 非形态值必须不命中", t.id);
            }
        }
    }

    #[test]
    fn 表内id唯一且各表项有命中形态() {
        let mut ids = std::collections::HashSet::new();
        for t in EXTERNAL_TWEAKS {
            assert!(ids.insert(t.id), "id 重复：{}", t.id);
            assert!(!t.hits.is_empty(), "{} 没有任何命中形态", t.id);
            assert!(!t.note.is_empty(), "{} 缺说明文案", t.id);
        }
    }

    /// 真机探针：只读扫描本机、打印命中项（不改任何键；本机预期命中 SEHOP/SEH 链/快速启动/网络限流 数项）。
    #[test]
    #[ignore = "真机探针：只读扫描本机账外 tweak 命中项"]
    fn 真机账外扫描探针() {
        let hive = hive_hklm();
        let mut hits: Vec<String> = Vec::new();
        for t in EXTERNAL_TWEAKS {
            let cur = read_reg_dword_opt(hive, t.subkey, t.value_name);
            if let Some(shape) = judge_external(cur, t.hits) {
                hits.push(format!(
                    "{}({}) = {:?} → {}",
                    t.title, t.value_name, cur, shape
                ));
            }
        }
        eprintln!(
            "账外扫描：{}/{} 项命中：{}",
            hits.len(),
            EXTERNAL_TWEAKS.len(),
            if hits.is_empty() { "（无）".to_string() } else { hits.join("；") }
        );
    }
}
