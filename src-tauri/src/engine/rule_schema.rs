//! 规则库契约表的运行期消费者（V2 P0-A2 / P2-C8，2026-09-30）
//!
//! 真源是仓库根的 `tools/rule-schema.json`，编译期嵌入 ⇒ **发布物里不额外落一份数据文件**，
//! 也就不会出现"运行期读到的表与门禁读的表不同"这种分叉（本仓同类事故：更新侧与装载侧各写
//! 一套字段规则，见 uninstall.rs A2 段注释）。
//!
//! 这张表**只管词汇与数值**：字段白名单、必填集、枚举、上限、token 登记集。
//! 判定逻辑一律留在各自代码里（注册表禁删面 `protect.rs`、target 形态与单星 glob、
//! residue 三条件组≥2、excludePaths 的 `::` 具名值约束）。把逻辑塞进数据文件等于
//! 造通用规则引擎，82 条库的规模不需要，且 AGENTS §2 是零新增依赖。
//!
//! 两个域的同名条目**刻意不同值**（token 集清理侧 14 个大小写敏感、残留侧 10 个不敏感），
//! 这里不做任何"取交集/并集"的便捷函数 —— 那种 API 早晚会被用来合并两张清单，
//! 制造假一致（AGENTS §5.16 / N6 既有裁定）。
//!
//! 失败口径：表解析不了 = **fail closed**。所有校验器拿到 `None` 都必须整包拒绝，
//! 不许回退到"跳过语义校验只验签"，那等于把这条链整体关掉。

use std::sync::OnceLock;

use serde_json::Value;

/// 编译期嵌入的契约表原文（与 Node 门禁读的是同一个字节）
const CONTRACT_JSON: &str = include_str!("../../../tools/rule-schema.json");

static CONTRACT: OnceLock<Option<Value>> = OnceLock::new();

fn contract() -> Option<&'static Value> {
    CONTRACT.get_or_init(|| match serde_json::from_str::<Value>(CONTRACT_JSON) {
        Ok(v) => Some(v),
        Err(e) => {
            // 只在真的坏了时打一次（OnceLock 保证不刷屏）；正常构建永远走不到这里
            crate::engine::log::write_log("error", &format!("规则契约表解析失败，规则库装载将整体拒绝: {e}"));
            None
        }
    })
    .as_ref()
}

/// 域内字符串数组（字段白名单 / 枚举 / 匹配组名 / 禁止字段名等）
pub fn list(domain: &str, key: &str) -> Option<Vec<String>> {
    let arr = contract()?.get(domain).and_then(|d| d.get(key))?.as_array()?;
    let out: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
    // 元素个数与解析结果不一致 = 表里混进了非字符串，宁可当作表坏了
    if out.len() != arr.len() {
        return None;
    }
    Some(out)
}

/// 数值上限：先找 `limits.<key>`，再找域顶层 `<key>`（如 matchGroupsMinNonEmpty）
pub fn number(domain: &str, key: &str) -> Option<usize> {
    let c = contract()?;
    let d = c.get(domain)?;
    let hit = d
        .get("limits")
        .and_then(|l| l.get(key))
        .or_else(|| d.get(key))?
        .as_f64()?;
    if hit.is_finite() && hit >= 0.0 {
        Some(hit as usize)
    } else {
        None
    }
}

/// token 登记集 + 大小写口径（两域不同值，调用方必须各自取自己那份）
pub fn tokens(domain: &str) -> Option<(Vec<String>, bool)> {
    let c = contract()?;
    let t = c.get(domain)?.get("tokens")?.as_object()?;
    let allowed: Vec<String> = t
        .get("allowed")?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let ci = t.get("caseInsensitive")?.as_bool()?;
    Some((allowed, ci))
}

/// crossTrack 登记表里的一个键（V2 P2-D7：活来源键 / 死键 / 专用分流登记）
pub fn cross(key: &str) -> Option<Value> {
    Some(contract()?.get("crossTrack")?.get(key)?.clone())
}

/// 表是否可用（供测试与诊断；校验器内部一律按 None 即拒绝处理）
pub fn available() -> bool {
    contract().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 表坏了会让两域整体停用，所以可用性本身必须是被断言的（本仓有假绿前科）
    #[test]
    fn 契约表可解析且两域关键条目齐备() {
        assert!(available(), "嵌入的 tools/rule-schema.json 解析失败");
        for (dom, keys) in [
            (
                "cleanup",
                &[
                    "topFields",
                    "itemFields",
                    "itemRequired",
                    "fileKeyFields",
                    "regKeyFields",
                    "provFields",
                    "provRequired",
                    "riskLevels",
                    "sourceClasses",
                    "itemBannedKeys",
                    "tokens",
                ][..],
            ),
            (
                "residue",
                &[
                    "topFields",
                    "provFields",
                    "ruleFields",
                    "entryFields",
                    "matchGroups",
                    "ruleKinds",
                    "tokens",
                ][..],
            ),
        ] {
            for k in keys {
                if *k == "tokens" {
                    assert!(tokens(dom).is_some(), "{dom}.tokens 缺失");
                } else if *k == "itemBannedKeys" {
                    assert!(list(dom, "itemBannedKeys").is_some(), "{dom}.itemBannedKeys 缺失");
                } else {
                    assert!(!list(dom, k).unwrap_or_default().is_empty(), "{dom}.{k} 缺失或为空");
                }
            }
        }
    }

    /// 2026-10-04 磁盘清理审计 §4.6：清理域**每一个**被查询的键都必须在表里存在。
    ///
    /// 为什么这条与上面那条并存、而不是并进去：上面只钉了「关键的几个键在不在」，
    /// 而 `validate_cleanup_package` 实际查询 22 个字符串数组键 + 9 个数值。任何一个
    /// 键被从 `tools/rule-schema.json` 里删掉或改名，`rule_schema::list` 就返回
    /// `None` —— 修复前那 17 处会各自挑一个默认值（多数碰巧 fail-closed，两条不是：
    /// `positiveIntFields` 变空会让 **minAge 护栏静默消失**，`exclusiveNumericFields`
    /// 变空会让扫描/执行两侧对「双声明」的处理分叉）。
    ///
    /// 修复后这些键走 `req_list`/`req_number`，取不到即整包拒绝。这条测试确保
    /// 「清单」与「实现」不漂：实现里新增一个键查询，必须同步登记到这里。
    #[test]
    fn 清理域被查询的每个契约键都存在() {
        // 与 rules.rs::validate_cleanup_package / check_cleanup_item 的查询一一对应
        for k in [
            "topFields",
            "topRequired",
            "groupFields",
            "groupRequired",
            "subGroupFields",
            "subGroupRequired",
            "itemFields",
            "itemRequired",
            "itemBannedKeys",
            "fileKeyFields",
            "fileKeyRequired",
            "regKeyFields",
            "regKeyRequired",
            "provFields",
            "provRequired",
            "riskLevels",
            "sourceClasses",
            // ↓ 这三个此前**不在**上面那条存在性测试里，而恰好就是 fail-open 的那批
            "nonEmptyArrayFields",
            "positiveIntFields",
            "exclusiveNumericFields",
            // ↓ G-1（2026-10-07）：年龄轴枚举，rules.rs 的 ageAxis 校验经 req_list 查询
            "ageAxes",
            "evidenceItemFields",
        ] {
            assert!(
                list("cleanup", k).is_some(),
                "cleanup.{k} 缺失 —— validate_cleanup_package 会因此整包拒绝（fail-closed），\
                 说明实现与契约表漂了。改实现请同步改 tools/rule-schema.json 并更新本清单。"
            );
        }
        for k in [
            "evidenceWeightMax",
            "maxTextLen",
            "maxTargetLen",
            "maxGroups",
            "maxSubGroupsPerGroup",
            "maxItems",
            "maxFileKeysPerItem",
            "maxRegKeysPerItem",
            "maxExcludePathsPerItem",
        ] {
            assert!(
                number("cleanup", k).is_some(),
                "cleanup.{k} 缺失 —— 同上；且原实现曾对它 `unwrap_or(0)`，\
                 方向虽 fail-closed 但错误原因是假的（会报成「条数超上限」）"
            );
        }
        // 三个关键键必须**非空**：空数组 = 该类校验形同虚设（比缺键更隐蔽，
        // 因为 `list` 会返回 Some(空 vec)，`is_some()` 照样过）
        for k in ["positiveIntFields", "exclusiveNumericFields", "nonEmptyArrayFields"] {
            let v = list("cleanup", k).unwrap_or_default();
            assert!(
                !v.is_empty(),
                "cleanup.{k} 是**空数组** —— 比缺键更隐蔽：`list` 返回 Some(空)，\
                 `is_some()` 过得去，但那一条校验等于没写。minAge 护栏就靠它。"
            );
        }
    }

    #[test]
    fn 两域token集保持刻意不同() {
        // 这条断言防的是"哪天有人把两张清单合并成一份等价集"（AGENTS §5.16 / N6）
        let (cl, ci) = tokens("cleanup").expect("cleanup tokens");
        let (rl, ri) = tokens("residue").expect("residue tokens");
        assert!(!ci, "清理侧 token 历史上是大小写敏感，改口径要单独拍板");
        assert!(ri, "残留侧 token 历史上是大小写不敏感，改口径要单独拍板");
        assert_ne!(
            cl.len(),
            rl.len(),
            "两域 token 登记集数量相等了——很可能被合并成同一份清单，制造假一致"
        );
        assert!(cl.contains(&"TEMP".to_string()) && !rl.contains(&"TEMP".to_string()));
        assert!(rl.contains(&"PROGRAMW6432".to_string()) && !cl.contains(&"PROGRAMW6432".to_string()));
    }

    #[test]
    fn 上限取值走limits再走域顶层() {
        assert_eq!(number("residue", "maxRules"), Some(400));
        assert_eq!(number("residue", "matchGroupsMinNonEmpty"), Some(2));
        assert_eq!(number("cleanup", "maxItems"), Some(400));
        assert_eq!(number("cleanup", "maxTargetLen"), Some(260));
    }
}
