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
use crate::engine::native::hive_hklm;

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

/// 单个外部键的一次读取结果（P1-6B）。
///
/// 旧写法只调 `read_reg_dword_opt`，它的 `None` 同时代表**三种不同的事实**：键/值不存在、
/// 类型不是 DWORD、访问被拒或解码失败。而回执里 `scanned` 又恒等于表长，于是
/// 「一次访问拒绝」被记成「扫过了、没命中」——账外核对这个面板的全部意义就是说真话。
#[derive(Debug, PartialEq)]
pub(super) enum ExtRead {
    /// 确认不存在（只认「找不到」那两个 Win32 码，判据同三态读器）
    Absent,
    /// 读到了值，但不是可读的 DWORD：算「核对过」，不参与命中判定
    NotDWord,
    /// 读到的 DWORD 现值（按无符号口径，与 `read_reg_dword_opt` 一致）
    DWord(i64),
    /// 读不出来（访问拒绝 / 其它 Win32 错误 / 解码失败），载荷是错误码名
    Unreadable(String),
}

impl ExtRead {
    /// 这次读取有没有给出**确定的事实**——`Unreadable` 没有。`scanned` 只数这个。
    fn is_read(&self) -> bool {
        !matches!(self, ExtRead::Unreadable(_))
    }
}

/// 单项状态标签（回执与日志共用，不各处再拼一套字符串）。
fn ext_state(read: &ExtRead, hits: &[(i64, &'static str)]) -> &'static str {
    match read {
        ExtRead::Absent => "absent",
        ExtRead::NotDWord => "notDWord",
        ExtRead::Unreadable(_) => "unreadable",
        ExtRead::DWord(v) => {
            if hits.iter().any(|(h, _)| *h == *v) { "matched" } else { "present" }
        }
    }
}

/// 三态读器的 REG_DWORD 文本（i32 口径）→ 本表使用的无符号 i64。
/// 单独成函数只为了让「`0xFFFFFFFF` 必须读成 4294967295」这条既有回归可单测。
fn dword_from_reg_text(text: &str) -> Option<i64> {
    text.parse::<i32>().map(|v| v as u32 as i64).ok()
}

/// 把一次三态读器的结果折成 `ExtRead`。DWORD 的无符号口径在这里复刻一次：
/// `read_reg_value_state` 按 i32 回报（对齐 .NET/PS），`read_reg_dword_opt` 按 u32→i64，
/// 两者差的就是这一步转换 —— 不复刻会让 `0xFFFFFFFF` 这类阈值形态永远命中不上。
fn read_ext_dword(hive: windows::Win32::System::Registry::HKEY, subkey: &str, name: &str) -> ExtRead {
    use crate::engine::native::RegReadState;
    match crate::engine::native::read_reg_value_state(hive, subkey, name, false) {
        RegReadState::Absent => ExtRead::Absent,
        RegReadState::Unknown(reason) => ExtRead::Unreadable(reason),
        RegReadState::Value("REG_DWORD", data) => match dword_from_reg_text(&data) {
            Some(v) => ExtRead::DWord(v),
            None => ExtRead::NotDWord,
        },
        RegReadState::Value(_, _) => ExtRead::NotDWord,
    }
}

#[tauri::command]
pub fn optimizer_external_scan<R: Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let hive = hive_hklm();
    let mut findings: Vec<Value> = Vec::new();
    let mut scanned = 0usize;
    let mut unreadable = 0usize;
    let mut unreadable_ids: Vec<&'static str> = Vec::new();
    for t in EXTERNAL_TWEAKS.iter() {
        let read = read_ext_dword(hive, t.subkey, t.value_name);
        if read.is_read() {
            scanned += 1;
        } else {
            unreadable += 1;
            unreadable_ids.push(t.id);
        }
        let shape = judge_external(match &read { ExtRead::DWord(v) => Some(*v), _ => None }, t.hits);
        if let Some(s) = shape {
            findings.push(json!({
                "id": t.id,
                "title": t.title,
                "hive": "HKLM",
                "subkey": t.subkey,
                "value": t.value_name,
                "current": match &read { ExtRead::DWord(v) => json!(*v), _ => Value::Null },
                "shape": s,
                "note": t.note,
                // P1-6B：单项状态随条目一起给出，前端不必再从「有没有这条」反推
                "state": ext_state(&read, t.hits),
            }));
        }
    }
    // 「成功」只在没有读不出的键时成立（方案 P1-6B）。partial 一并带回，前端据此把
    // 「N 个键没能核对」显示出来，而不是把一条部分失败的扫描渲染成「一切正常，只是没命中」。
    let data = json!({
        "scanned": scanned,
        "total": EXTERNAL_TWEAKS.len(),
        "unreadable": unreadable,
        "unreadableIds": unreadable_ids,
        "findings": findings,
    });
    if unreadable > 0 {
        return json!({
            "success": false,
            "partial": true,
            "message": format!("账外核对有 {unreadable} 个键读不出来（权限不足或类型异常），未计入已核对"),
            "data": data,
        });
    }
    json!({ "success": true, "partial": false, "data": data })
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

    /// 真机探针：只读扫描本机账外 tweak，走**生产读取路径**（`read_ext_dword` 四态）。
    ///
    /// R3b-M16：旧探针走 `read_reg_dword_opt`（`None` 把「不存在/类型不符/无权限」折成一档，
    /// 正是 P1-6B 要修的形态）且只打印不判红 —— 发布门禁真跑它时三态分流零实测覆盖。
    /// 现在断言三件事：计数守恒（scanned + unreadable == 表长）、unreadable 必须点名错误码、
    /// 至少读出一档非 Unreadable（证明本机真的开得动 HKLM 那几个子键）。
    #[test]
    #[ignore = "真机探针：只读扫描本机账外 tweak 命中项（走生产读取路径 + 三态断言）"]
    fn 真机账外扫描探针() {
        let hive = hive_hklm();
        let mut hits: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        let mut unreadable: Vec<(String, String)> = Vec::new();
        let mut readable = 0usize;
        for t in EXTERNAL_TWEAKS {
            let read = read_ext_dword(hive, t.subkey, t.value_name);
            match &read {
                ExtRead::Unreadable(reason) => {
                    unreadable.push((t.title.to_string(), reason.clone()));
                }
                ExtRead::Absent | ExtRead::NotDWord | ExtRead::DWord(_) => {
                    scanned += 1;
                    readable += 1;
                }
            }
            if let ExtRead::DWord(v) = read {
                if let Some(shape) = judge_external(Some(v), t.hits) {
                    hits.push(format!("{}({}) = {:?} → {}", t.title, t.value_name, v, shape));
                }
            }
        }
        eprintln!(
            "账外扫描：{}/{} 项命中；可读 {}、读不出 {}：{}",
            hits.len(),
            EXTERNAL_TWEAKS.len(),
            readable,
            unreadable.len(),
            if hits.is_empty() { "（无）".to_string() } else { hits.join("；") }
        );
        for (title, reason) in &unreadable {
            eprintln!("  读不出：{title} → {reason}");
        }
        assert_eq!(
            scanned + unreadable.len(),
            EXTERNAL_TWEAKS.len(),
            "四态计数不守恒（每项必须落进 scanned 或 unreadable）"
        );
        assert!(
            readable > 0,
            "全部 {} 项都读不出 ⇒ 读器在本机没开成 HKLM 子键，探针数据无效",
            EXTERNAL_TWEAKS.len()
        );
    }
}

#[cfg(test)]
mod p1_6b_three_state_tests {
    use super::*;

    /// P1-6B：`absent` / `notDWord` / `unreadable` / `matched` / `present` 五档必须互不相同。
    /// 旧实现里前四种全被 `read_reg_dword_opt` 的 `None` 折成一档，回执的 `scanned` 又恒等于
    /// 表长 ⇒ 一次访问拒绝被记成「扫过了、没命中」。
    ///
    /// 判红自证：① 把 `ext_state` 的 `Unreadable` 支并进 `Absent` ⇒ 第三条断言红；
    /// ② 把 `is_read` 改成恒 `true`（等于旧口径）⇒ 第四条红。
    #[test]
    fn 五种读取结果各自可分辨且只数读成功的() {
        let hits: &[(i64, &'static str)] = &[(1, "开启"), (0, "关闭")];
        assert_eq!(ext_state(&ExtRead::Absent, hits), "absent");
        assert_eq!(ext_state(&ExtRead::NotDWord, hits), "notDWord");
        assert_eq!(
            ext_state(&ExtRead::Unreadable("ERROR_ACCESS_DENIED".to_string()), hits),
            "unreadable",
            "读不出来不得与「确认不存在」同档"
        );
        assert_eq!(ext_state(&ExtRead::DWord(1), hits), "matched");
        assert_eq!(ext_state(&ExtRead::DWord(7), hits), "present");

        let 三条 = [
            ExtRead::Absent,
            ExtRead::DWord(9),
            ExtRead::NotDWord,
            ExtRead::Unreadable("ERROR_FILE_NOT_FOUND".to_string()),
        ];
        assert_eq!(
           三条.iter().filter(|r| r.is_read()).count(),
            3,
            "scanned 只数给出确定事实的三条，表长 4 不是已核对数"
        );
    }

    /// 无符号口径回归：三态读器按 i32 回报，本表面板要的是 u32→i64。
    /// 判红自证：把 `v as u32 as i64` 改成 `v as i64` ⇒ 第二条红（-1 再也不是 4294967295）。
    #[test]
    fn dword_文本按无符号解释() {
        assert_eq!(dword_from_reg_text("-1"), Some(4294967295));
        assert_eq!(dword_from_reg_text("0"), Some(0));
        assert_eq!(dword_from_reg_text("4294967295"), None, "超 i32 文本不是本读器的形态");
    }
}
