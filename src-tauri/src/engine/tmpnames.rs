//! 临时目录里**本工具产物的件名形态**（B2-1 唯一真源）。
//!
//! 病根：清扫链此前只按「落在根里 + 过了保留期」两个条件就 `remove_file`，而公共根
//! `%TEMP%\Trim` 是**全局可写**目录 —— 同机任何进程放进来的文件都会被本工具永久删掉。
//! 判据必须补上第三条：**名字确实是本工具产出的形状**。
//!
//! 为什么形态声明与拼装都收在这一个模块：生成侧若各自 `format!` 一份，改名就会与白名单
//! 漂移，而漂移的两个方向都是故障 —— 漂严了一侧是自己写出的残留再也不被清（占盘，且
//! 只能靠人手删），漂松了一侧是别人的文件被当垃圾永久删（不可逆）。所以形态只声明一次，
//! 生成（[`TmpNameShape::build`]）与判定（[`TmpNameShape::matches`]）都读同一份。
//!
//! 白名单按**根**分两份，因为两处的可信度不同：
//! - 公共根 `%TEMP%\Trim`：全局可写，只认历史上写在那里的一种形态（收件箱脚本），
//!   其余一概不碰 —— 宁可留下自己的残留，也不碰别人的文件；
//! - 私有根 `temp_script_dir()`：每用户 DACL，但清扫仍按形态判，取本工具**全部**
//!   产物的并集（该目录同时承载脚本、注册表中转件与电源方案导出件）。
//!
//! **已知取舍（B2-1，2026-10-27）**：公共根里若躺着更早版本用别的名字写下的残留
//! （现行形态之外的任何字面量），本轮起不再被清扫 —— 那是刻意的：公共根是全局可写目录，
//! 认不出的名字无法证明是本工具写的，删它就是替任意本机进程清文件。代价是一点磁盘残留，
//! 收益是不再永久删别人的文件，方向与 AGENTS §3 一致。

/// Unix 毫秒时间戳段的十进制宽度。
///
/// 取数：`node -e "console.log(String(Date.now()).length)"`（当前恒为这个值；
/// 到 2286 年才会进位。真进位时本常量与生成侧一起改，形态判定随之对齐）。
const MS_DIGITS: usize = 13;
/// 随机 token 段的小写十六进制宽度：`security::crypto_random_hex(8)` 一字节出两字符。
const TOKEN_HEX: usize = 16;
/// 进程号段的位数上限（`std::process::id()` 是 u32，十进制最多十位）。
const PID_MAX_DIGITS: usize = 10;

/// 名字里的一段判据（只判字符类与宽度，不做任何截断/容错）。
#[derive(Debug, Clone, Copy)]
enum Seg {
    /// 恰好 n 位十进制数字
    Digits(usize),
    /// 恰好 n 位小写十六进制字符
    Hex(usize),
    /// 一到多位十进制数字（进程号这类位数不定的量）
    AnyDigits,
}

impl Seg {
    fn accepts(self, s: &str) -> bool {
        let all = |f: fn(u8) -> bool| s.bytes().all(f);
        match self {
            Seg::Digits(n) => s.len() == n && all(|b| b.is_ascii_digit()),
            Seg::Hex(n) => s.len() == n && all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            Seg::AnyDigits => {
                !s.is_empty() && s.len() <= PID_MAX_DIGITS && all(|b| b.is_ascii_digit())
            }
        }
    }
}

/// 一种临时件的件名形态：`前缀 分隔符 段… 分隔符 后缀`。
#[derive(Debug)]
pub struct TmpNameShape {
    /// 字面前缀（不含后缀那个分隔符）
    prefix: &'static str,
    /// 段间分隔符，同时也是前缀与首段之间的分隔符
    sep: char,
    /// 各段判据，从左到右逐段精确消费
    segs: &'static [Seg],
    /// 字面后缀（含点与扩展名）
    suffix: &'static str,
}

impl TmpNameShape {
    /// 按本形态拼一个名字 —— **生成侧唯一出口**，与清扫白名单共用同一份形态声明。
    ///
    /// 本表里的形态都是「时间戳 + 尾巴」两段，故入参固定为 `(ms, tail)`；
    /// 将来若出现别的段数，这里的 `debug_assert` 会当场点出来（别默默拼错）。
    pub fn build(&self, ms: i64, tail: &str) -> String {
        debug_assert_eq!(self.segs.len(), 2, "build 只覆盖两段形态，新增其它段数须同步改本函数");
        format!("{}{}{}{}{}{}", self.prefix, self.sep, ms, self.sep, tail, self.suffix)
    }

    /// 名字是否**严格**符合本形态：前缀、后缀、段数与每段的字符类/宽度全部逐段精确消费，
    /// 多一个字符都不认（宽松匹配等于给「删别人的文件」开门）。
    pub fn matches(&self, name: &str) -> bool {
        let Some(rest) = name.strip_prefix(self.prefix) else {
            return false;
        };
        let Some(rest) = rest.strip_prefix(self.sep) else {
            return false;
        };
        let Some(mid) = rest.strip_suffix(self.suffix) else {
            return false;
        };
        let parts: Vec<&str> = mid.split(self.sep).collect();
        parts.len() == self.segs.len()
            && parts
                .iter()
                .zip(self.segs)
                .all(|(part, seg)| seg.accepts(part))
    }
}

/// 收件箱 PowerShell 脚本（`pwsh::write_temp_script_bytes` 产出）。
/// 也是**历史上唯一写进公共根**的形态 —— 旧版本把脚本落在 `%TEMP%\Trim`，故公共根白名单
/// 只留它这一种。
pub const SCRIPT_PS1: TmpNameShape = TmpNameShape {
    prefix: "script",
    sep: '_',
    segs: &[Seg::Digits(MS_DIGITS), Seg::Hex(TOKEN_HEX)],
    suffix: ".ps1",
};

/// 优化器注册表中转件（`commands::optimizer::apply` 写 `.reg` 后立即原生导入）。
pub const OPTIMIZER_REG: TmpNameShape = TmpNameShape {
    prefix: "wcopt",
    sep: '_',
    segs: &[Seg::Digits(MS_DIGITS), Seg::Hex(TOKEN_HEX)],
    suffix: ".reg",
};

/// 电源方案导出中转件（`engine::native::syspanel::power_plan_export`）。
pub const POWER_PLAN_EXPORT: TmpNameShape = TmpNameShape {
    prefix: "power-export",
    sep: '-',
    segs: &[Seg::Digits(MS_DIGITS), Seg::AnyDigits],
    suffix: ".powrplan",
};

/// 电源方案真机探针的导出件（`syspanel` 的 `#[ignore]` 真机用例，自建自清）。
pub const POWER_PLAN_PROBE: TmpNameShape = TmpNameShape {
    prefix: "trim-p0-export",
    sep: '-',
    segs: &[Seg::Digits(MS_DIGITS), Seg::AnyDigits],
    suffix: ".powrplan",
};

/// 公共根 `%TEMP%\Trim`（全局可写）的白名单：只认收件箱脚本形态。
pub const PUBLIC_ROOT_SHAPES: &[&TmpNameShape] = &[&SCRIPT_PS1];

/// 私有根 `temp_script_dir()` 的白名单：本工具全部产物形态的并集。
///
/// **逐点自清理确认**（B2-1 措施栏要求，2026-10-27 现算）：每个生产者都在正常路径上删掉
/// 自己写出的件，清扫只是**崩溃/强杀残留**的兜底 ——
/// - `SCRIPT_PS1`：`pwsh::write_temp_script_bytes` 返回 `TempScript` 守卫，Drop 即删；
/// - `OPTIMIZER_REG`：`commands::optimizer::apply` 原生导入后 `fs::remove_file` 删；
/// - `POWER_PLAN_EXPORT`：`syspanel::power_plan_export` 复制完 `remove_file` + `RemoveOnDrop`；
/// - `POWER_PLAN_PROBE`：真机探针用例末尾 `remove_file`（`#[ignore]`，自建自清）。
///
/// 私有根里还有测试用的沙箱目录（连同其中的文件），它们不在本表内 ⇒ 不会被清扫；
/// 那些样本由各用例自己 Drop 清理，清扫链不该替测试收尾。
pub const PRIVATE_ROOT_SHAPES: &[&TmpNameShape] = &[
    &SCRIPT_PS1,
    &OPTIMIZER_REG,
    &POWER_PLAN_EXPORT,
    &POWER_PLAN_PROBE,
];

/// 名字是否命中给定白名单中的任一份形态。
pub fn any_matches(shapes: &[&TmpNameShape], name: &str) -> bool {
    shapes.iter().any(|s| s.matches(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS_SAMPLE: i64 = 1789999999999;
    const TOKEN_SAMPLE: &str = "0123456789abcdef";

    /// 生成侧产出的名字必须被白名单接受 —— 这条把「拼装」与「判定」钉在同一份形态上，
    /// 任一侧改了宽度/前缀/后缀，这里当场红。
    #[test]
    fn 生成的名字必须被同名形态接受() {
        let cases = [
            (&SCRIPT_PS1, TOKEN_SAMPLE),
            (&OPTIMIZER_REG, TOKEN_SAMPLE),
            (&POWER_PLAN_EXPORT, "12345"),
            (&POWER_PLAN_PROBE, "12345"),
        ];
        for (shape, tail) in cases {
            let name = shape.build(MS_SAMPLE, tail);
            assert!(shape.matches(&name), "形态自己拼出的名字却判不过：{name}");
            assert!(
                any_matches(PRIVATE_ROOT_SHAPES, &name),
                "私有根白名单必须覆盖全部生产者形态：{name}"
            );
        }
    }

    /// 公共根白名单只认收件箱脚本：同机的注册表中转件与电源方案导出件都不许在公共根被删。
    #[test]
    fn 公共根白名单只认收件箱脚本形态() {
        let script = SCRIPT_PS1.build(MS_SAMPLE, TOKEN_SAMPLE);
        assert!(any_matches(PUBLIC_ROOT_SHAPES, &script));
        for name in [
            OPTIMIZER_REG.build(MS_SAMPLE, TOKEN_SAMPLE),
            POWER_PLAN_EXPORT.build(MS_SAMPLE, "1"),
            POWER_PLAN_PROBE.build(MS_SAMPLE, "1"),
        ] {
            assert!(!any_matches(PUBLIC_ROOT_SHAPES, &name), "公共根不该认这种形态：{name}");
        }
    }

    /// 近似形态一律不认：宽度差一、字符类不对、段数不对、大小写不对、路径分隔符混入。
    #[test]
    fn 近似形态一律不认() {
        let ok = SCRIPT_PS1.build(MS_SAMPLE, TOKEN_SAMPLE);
        assert!(SCRIPT_PS1.matches(&ok));
        let junk = [
            // 时间戳段少一位 / 多一位
            format!("script_{}_0123456789abcdef.ps1", &MS_SAMPLE.to_string()[1..]),
            format!("script_{}0_0123456789abcdef.ps1", MS_SAMPLE),
            // token 段少一位 / 多一位
            "script_1789999999999_0123456789abcde.ps1".to_string(),
            "script_1789999999999_0123456789abcdef0.ps1".to_string(),
            // token 段含非十六进制字符 / 大写十六进制
            "script_1789999999999_0123456789abcdeg.ps1".to_string(),
            "script_1789999999999_0123456789ABCDEF.ps1".to_string(),
            // 段数不对
            "script_1789999999999.ps1".to_string(),
            "script_1789999999999_0123456789abcdef_extra.ps1".to_string(),
            // 后缀不对 / 没有后缀
            "script_1789999999999_0123456789abcdef.reg".to_string(),
            "script_1789999999999_0123456789abcdef".to_string(),
            // 前缀不对
            "scripts_1789999999999_0123456789abcdef.ps1".to_string(),
            "script1789999999999_0123456789abcdef.ps1".to_string(),
            // 空名字与纯分隔符
            String::new(),
            "_".to_string(),
            // 路径分隔符混入（名字取自目录项，可能是任意串）
            "sub\\script_1789999999999_0123456789abcdef.ps1".to_string(),
        ];
        for name in junk {
            assert!(!SCRIPT_PS1.matches(&name), "不该认这种名字：{name:?}");
        }
    }

    /// 进程号段允许一位（`std::process::id()` 完全可能是 1 位数），但不允许空、不允许非数字。
    #[test]
    fn 进程号段允许一位但不允许空或非数字() {
        assert!(POWER_PLAN_EXPORT.matches(&POWER_PLAN_EXPORT.build(MS_SAMPLE, "7")));
        for tail in ["", "abc", "-1", "01234567890"] {
            let name = POWER_PLAN_EXPORT.build(MS_SAMPLE, tail);
            assert!(!POWER_PLAN_EXPORT.matches(&name), "不该认这种尾巴：{name:?}");
        }
    }

    /// **禁两处字面量**（B2-1 措施栏）：生成侧不得再自己 `format!` 出名字。
    ///
    /// 判据是源码形态断言，不是行为断言 —— 行为断言只能证明「今天两处一致」，源码断言才能
    /// 挡住「明天有人把生成侧改回手写 format!」这条路：那一改会让白名单静默失效，而所有
    /// 行为用例照样全绿（它们喂的是本模块的 build 产物，不经过那个手写的 format!）。
    #[test]
    fn 生成侧不得再自己拼名字() {
        let producers = [
            ("../pwsh/mod.rs", include_str!("../pwsh/mod.rs")),
            ("../commands/optimizer/apply.rs", include_str!("../commands/optimizer/apply.rs")),
            ("native/syspanel.rs", include_str!("native/syspanel.rs")),
        ];
        for (what, src) in producers {
            // 手写形态的字面量前缀（旧写法必然以它开头）
            for hand in ["\"script_{}", "\"wcopt_{}", "\"power-export-{}", "\"trim-p0-export-{}"] {
                assert!(
                    !src.contains(hand),
                    "{what} 仍在手拼临时件名（{hand}）⇒ 与清扫白名单成为两份字面量"
                );
            }
        }
        // 正向对照：三处生产者都必须真的走本模块的 build（否则上面的「没找到」是空转）
        assert!(
            include_str!("../pwsh/mod.rs").contains("tmpnames::SCRIPT_PS1.build"),
            "收件箱脚本生成侧没走 tmpnames::SCRIPT_PS1.build"
        );
        assert!(
            include_str!("../commands/optimizer/apply.rs").contains("tmpnames::OPTIMIZER_REG.build"),
            "优化器 reg 中转件生成侧没走 tmpnames::OPTIMIZER_REG.build"
        );
        assert!(
            include_str!("native/syspanel.rs").contains("tmpnames::POWER_PLAN_EXPORT.build"),
            "电源方案导出生成侧没走 tmpnames::POWER_PLAN_EXPORT.build"
        );
    }
}
