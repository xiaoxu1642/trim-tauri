//! pwsh 步骤的原生解释器（B11；v3-K1 扩展）
//!
//! **范围刻意收窄**：只认优化项数据层里实际出现的指令子集，且参数必须是**字面量**
//! （或由字面量赋值的简单变量）。不认识的构造有两条出路，没有第三条：
//! 1. **PsInline 通道**（v3-K1）：语句头在 `PS_INLINE_ALLOW` 白名单内 → 整段**逐字**
//!    交给收件箱 Windows PowerShell 5.1 执行（System32 自带，`system_tool` 解析）。
//!    逐字 = 零重解释 = 无「半懂硬执行」风险 —— 语义与旧 PS 回退路径完全一致。
//! 2. **Err（fail-closed 不变）**：不在白名单 → 编译失败。白名单的职责是**登记意识**：
//!    数据层新增任何构造必须在这里有意识地放行，`data_layer_coverage_report` 会在
//!    cargo test 阶段把未放行的构造红掉（审查 v3-M4 教训：只打印的覆盖报告放过过 K1）。
//!
//! ## 为什么不写成通用解释器
//! 半懂不懂的执行 = 静默没执行却报成功，是本项目最忌讳的「假绿」。原生面的失败
//! 模式只有一种：编译期 Err；执行面的失败只有一种：某步操作真实失败并如实记账。
//!
//! ## v3-K1 新增的原生构造（全部来自数据层实测清单）
//! - `foreach ($n in $var)`（字面量列表变量）／`foreach ($n in $map.Keys)`（哈希表键）
//! - 双引号插值 `"$var"`／`"$env:NAME"`；拼接 `"a" + $b + "c"`（赋值与命令实参两处）
//! - `[byte[]](0x..,…)` 赋值与内联 `-Value`；`@{ K = v; … }` 哈希表与 `$map[$k]` 取值
//! - `Join-Path <var|literal> <literal>`；`Test-Path -LiteralPath`
//! - `schtasks /change /tn <name> /disable|/enable`（位置式，映射 TaskChange）
//! - `powercfg <args>`（Spawn 算子，仅放行 PINNED 的 powercfg.exe）
//! - `Get-ChildItem <注册表键> | ForEach-Object { … }` → ForSubKey 原生子键枚举，
//!   `$_` 绑定为子键完整 PS 路径（`$_.PSPath` 即取该值）
//! - `Get-CimInstance Win32_VideoController|Win32_USBController | Where-Object { … "PCI*" }
//!   | ForEach-Object { … }` → ForDevKey：在 `Enum\PCI` 两级子键上按 `Class` 值过滤，
//!   成员与对应 WMI 类 ∩ `PNPDeviceID -like "PCI*"` 等价（两个 WMI 类即按设备安装类取成员）

use crate::engine::native;

/// 注册表根键（用枚举而非裸句柄，避免在数据结构里搬 `*mut c_void`）
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Hive {
    Lm,
    Cu,
    Cr,
    U,
    Cc,
}

/// 一条已解析的原生操作
#[derive(Debug, PartialEq)]
pub enum PsOp {
    /// New-Item -Path HKLM:\a\b -Force
    KeyCreate { hive: Hive, subkey: String },
    /// Remove-Item -Path …（recurse 对应 -Recurse，含全部子键与值）
    KeyRemove { hive: Hive, subkey: String, recurse: bool },
    /// New/Set-ItemProperty
    ValueWrite { hive: Hive, subkey: String, name: String, kind: u32, data: Vec<u8> },
    /// Remove-ItemProperty
    ValueRemove { hive: Hive, subkey: String, name: String },
    /// Stop-Service -Name X
    SvcStop { name: String },
    /// sc.exe config X start= N
    SvcSetStart { name: String, start: u32 },
    /// Disable/Enable-ScheduledTask（经 schtasks /Change，与既有启动项链同一工具）
    TaskChange { path: Option<String>, name: String, disable: bool },
    /// Test-Path 守卫：仅当键存在才执行其内层操作（语义是「服务没装就别硬写」）
    GuardedKeyExists { hive: Hive, subkey: String, ops: Vec<PsOp> },
    /// 注册表子键枚举（`Get-ChildItem <键> | ForEach-Object { … }`，v3-K1）
    ///
    /// 体在**执行期**对每个子键延迟解析（`$_` 绑定为子键完整 PS 路径）；编译期已用
    /// 探针值干跑校验过可解析性，执行期解析失败理论上不可达，仍按 Err 如实上报。
    ForSubKey { hive: Hive, subkey: String, body: String, vars: VarMap },
    /// 设备实例枚举（`Get-CimInstance Win32_VideoController|Win32_USBController …`，v3-K1）
    ///
    /// 在 `HKLM\SYSTEM\CurrentControlSet\Enum\PCI` 按实例 `Class` 值过滤；
    /// `$_` 绑定为 PNPDeviceID（`PCI\VEN_x…\实例串`）。
    ForDevKey { class: String, body: String, vars: VarMap },
    /// PINNED 系统工具直调（仅 powercfg，v3-K1）。白名单外的程序在编译期就 Err。
    Spawn { program: String, args: Vec<String> },
    /// 收件箱 Windows PowerShell 逐字执行（v3-K1，白名单见 `PS_INLINE_ALLOW`）
    PsInline { script: String },
}

/// 变量表（编译期逐语句就地更新；ForSubKey/ForDevKey 快照进算子供执行期延迟解析）
pub type VarMap = std::collections::HashMap<String, Expr>;// REG_VALUE_TYPE 裸值（windows crate 的 REG_VALUE_TYPE(u32)）
const KIND_SZ: u32 = 1;
const KIND_EXPAND_SZ: u32 = 2;
const KIND_BINARY: u32 = 3;
const KIND_DWORD: u32 = 4;
const KIND_QWORD: u32 = 11;

fn parse_ps_reg_path(p: &str) -> Option<(Hive, String)> {
    let p = p.trim();
    for (pref, h) in [
        ("HKLM:\\", Hive::Lm),
        ("HKCU:\\", Hive::Cu),
        ("HKCR:\\", Hive::Cr),
        ("HKU:\\", Hive::U),
        ("HKCC:\\", Hive::Cc),
        ("HKLM:", Hive::Lm),
        ("HKCU:", Hive::Cu),
        ("HKCR:", Hive::Cr),
        ("HKU:", Hive::U),
        ("HKCC:", Hive::Cc),
    ] {
        if let Some(sub) = p.strip_prefix(pref) {
            let sub = sub.trim_start_matches('\\');
            return Some((h, sub.replace('/', "\\")));
        }
    }
    for (full, h) in [
        ("HKEY_LOCAL_MACHINE", Hive::Lm),
        ("HKEY_CURRENT_USER", Hive::Cu),
        ("HKEY_CLASSES_ROOT", Hive::Cr),
        ("HKEY_USERS", Hive::U),
        ("HKEY_CURRENT_CONFIG", Hive::Cc),
    ] {
        if let Some(sub) = p.strip_prefix(full).and_then(|s| s.strip_prefix('\\')) {
            return Some((h, sub.replace('/', "\\")));
        }
        if p == full {
            return Some((h, String::new()));
        }
    }
    None
}

/// PS 引号字面量。**双引号串只在内容不含 `$`/反引号时接受** —— 依赖展开的串超出
/// 字面量范围，必须回退 PS（`unquote` 返回 None）。
fn unquote(s: &str) -> Option<String> {
    let t = s.trim();
    if let Some(inner) = t.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')) {
        return Some(inner.replace("''", "'"));
    }
    if let Some(inner) = t.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        if inner.contains('$') || inner.contains('`') {
            return None;
        }
        return Some(inner.to_string());
    }
    None
}

/// 把一段源码按**顶层** `;` 或换行拆条（引号内与括号/花括号内的分号不算；
/// 花括号深度是 v3-K1 加的：PsInline 资格扫描会直接对整段体拆条，块内的
/// `;` 不能被误当语句边界）
fn split_statements(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth_paren = 0i32;
    let mut depth_brace = 0i32;
    let mut in_sq = false;
    let mut in_dq = false;
    let mut start = 0usize;
    for (i, &c) in s.as_bytes().iter().enumerate() {
        match c {
            b'\'' if !in_dq => in_sq = !in_sq,
            b'"' if !in_sq => in_dq = !in_dq,
            b'(' if !in_sq && !in_dq => depth_paren += 1,
            b')' if !in_sq && !in_dq => depth_paren -= 1,
            b'{' if !in_sq && !in_dq => depth_brace += 1,
            b'}' if !in_sq && !in_dq => depth_brace -= 1,
            b';' | b'\n' if !in_sq && !in_dq && depth_paren == 0 && depth_brace == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// 极简分词：按空白切，`'…'` / `"…"` 保持为一个 token
fn tokenize(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_sq = false;
    let mut in_dq = false;
    for c in s.chars() {
        match c {
            '\'' if !in_dq => {
                in_sq = !in_sq;
                cur.push(c);
            }
            '"' if !in_sq => {
                in_dq = !in_dq;
                cur.push(c);
            }
            c if c.is_whitespace() && !in_sq && !in_dq => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if in_sq || in_dq {
        return None; // 引号不闭合
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// 解析后的命令：cmdlet 名 + 参数表 + 位置参数（全部为分词后的原文）
struct Cmd {
    name: String,
    named: Vec<(String, Option<String>)>,
    positional: Vec<String>,
}

fn parse_cmd(s: &str) -> Option<Cmd> {
    let toks = tokenize(s)?;
    let mut it = toks.into_iter();
    let name = it.next()?;
    if name.starts_with('-') || name.starts_with('$') {
        return None;
    }
    let mut named: Vec<(String, Option<String>)> = Vec::new();
    let mut positional = Vec::new();
    let mut pending: Option<String> = None;
    for t in it {
        if let Some(p) = pending.take() {
            // 开关参数后面跟的还是参数（如 `-Recurse -Force`）→ 前者无值
            if is_param(&t) {
                named.push((p, None));
                pending = Some(t[1..].to_string());
                continue;
            }
            named.push((p, Some(t)));
            continue;
        }
        if is_param(&t) {
            pending = Some(t[1..].to_string());
            continue;
        }
        positional.push(t);
    }
    if let Some(p) = pending {
        // 末尾的开关参数（如 -Force / -Recurse）没有值
        named.push((p, None));
    }
    Some(Cmd { name, named, positional })
}

/// 是否参数名（`-Force`、`-Path`）；`-1` 这类负数不算
fn is_param(t: &str) -> bool {
    t.starts_with('-')
        && t.len() > 1
        && !t.starts_with("--")
        && !t[1..].chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
        && !t.contains('>') // `2>$null` 是重定向，不是参数
}

fn param<'a>(cmd: &'a Cmd, k: &str) -> Option<&'a str> {
    cmd.named
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(k))
        .and_then(|(_, v)| v.as_deref())
}

fn has_flag(cmd: &Cmd, k: &str) -> bool {
    cmd.named.iter().any(|(n, v)| n.eq_ignore_ascii_case(k) && v.is_none())
}

/// 去掉管道尾巴与重定向；除 `| Out-Null` 外一律不支持
fn strip_pipeline(s: &str) -> Option<&str> {
    let mut t = s.trim();
    if let Some((head, tail)) = t.rsplit_once('|') {
        if tail.trim() == "Out-Null" {
            t = head.trim();
        } else {
            return None;
        }
    }
    // 重定向：`*> $null` / `2>$null` / `1>$null`（数据层两种都有）
    loop {
        let trimmed = t.trim_end();
        if let Some((head, tail)) = trimmed.rsplit_once('>') {
            let target = tail.trim();
            // fd 是 head 的最后一个空白分隔 token（head 以它结尾，如 `… disabled 2>`）
            let fd = head.split_whitespace().last().unwrap_or("");
            if (fd == "*" || fd == "1" || fd == "2") && target == "$null" {
                t = head[..head.len() - fd.len()].trim_end();
                continue;
            }
        }
        break;
    }
    Some(t)
}

/// `$var = <expr>` 的右侧表达式
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Str(String),
    Bytes(usize),
    /// `[byte[]](0x..,…)` 字面字节串（v3-K1：Scancode Map / MitigationOptions）
    BytesData(Vec<u8>),
    List(Vec<String>),
    /// `@{ K = v; … }` 哈希表（值按字符串存，取用方决定如何转；v3-K1）
    Map(Vec<(String, String)>),
}

/// 双引号串的变量插值：只认 `$name`（已赋值 Str）与 `$env:NAME`（进程环境变量，
/// Windows 环境名大小写不敏感）。任何解析不了的引用、含反引号 → None（fail-closed）。
fn interpolate(s: &str, vars: &VarMap) -> Option<String> {
    if s.contains('`') {
        return None;
    }
    let mut out = String::new();
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        let rest = &s[i + 1..];
        let (env, name_part) = match rest.strip_prefix("env:") {
            Some(e) => (true, e),
            None => (false, rest),
        };
        let name: String = name_part
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            return None;
        }
        let val = if env {
            std::env::var(&name).ok()
        } else {
            match vars.get(&name) {
                Some(Expr::Str(v)) => Some(v.clone()),
                _ => None,
            }
        }?;
        // 把消费掉的字符跳过（按字节前进）
        let consumed = 1 + if env { 4 } else { 0 } + name.len();
        for _ in 1..consumed {
            chars.next();
        }
        out.push_str(&val);
    }
    Some(out)
}

/// 单个拼接项 / 实参求值：引号串（含插值）、`$var`、`$var.PSPath|.PNPDeviceID`、数字
fn eval_term(t: &str, vars: &VarMap) -> Option<Expr> {
    let t = t.trim();
    if t.starts_with('\'') {
        return unquote(t).map(Expr::Str);
    }
    if t.starts_with('"') {
        return unquote(t)
            .map(Expr::Str)
            .or_else(|| interpolate(t.trim_matches('"'), vars).map(Expr::Str));
    }
    if let Some(rest) = t.strip_prefix('$') {
        let (name, prop) = match rest.split_once('.') {
            Some((n, p)) => (n, Some(p)),
            None => (rest, None),
        };
        // 属性访问只认 PSPath / PNPDeviceID：枚举算子已把绑定值规整成
        // 「解析器需要的形态」（子键完整路径 / PNPDeviceID），两者都直接取值
        if let Some(p) = prop {
            if p != "PSPath" && p != "PNPDeviceID" {
                return None;
            }
        }
        return match vars.get(name) {
            Some(Expr::Str(v)) => Some(Expr::Str(v.clone())),
            _ => None,
        };
    }
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        return Some(Expr::Str(t.to_string()));
    }
    None
}

/// 按顶层 ` + ` 拆拼接链（引号/括号/花括号/方括号内的 + 不算）；非拼接返回 None
fn split_plus(s: &str) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut in_sq = false;
    let mut in_dq = false;
    let mut start = 0usize;
    let mut found = false;
    for (i, &c) in s.as_bytes().iter().enumerate() {
        match c {
            b'\'' if !in_dq => in_sq = !in_sq,
            b'"' if !in_sq => in_dq = !in_dq,
            b'(' | b'{' | b'[' if !in_sq && !in_dq => depth += 1,
            b')' | b'}' | b']' if !in_sq && !in_dq => depth -= 1,
            b'+' if !in_sq && !in_dq && depth == 0 => {
                // 只认「 + 」（两侧空白）形态，避免吃进 `+0x1` 之类
                let prev_space = s[..i].ends_with(' ');
                let next_space = s[i + 1..].starts_with(' ');
                if prev_space && next_space {
                    parts.push(&s[start..i]);
                    start = i + 1;
                    found = true;
                }
            }
            _ => {}
        }
    }
    if !found {
        return None;
    }
    parts.push(&s[start..]);
    Some(parts)
}

fn parse_assign(stmt: &str, vars: &VarMap) -> Option<(String, Expr)> {
    let (lhs, rhs) = stmt.split_once('=')?;
    let name = lhs.trim().strip_prefix('$')?.to_string();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    let rhs = rhs.trim();
    // 拼接链（`"a" + $b + "c"`）—— 任何一项求值失败即整体 None
    if let Some(parts) = split_plus(rhs) {
        let mut acc = String::new();
        for p in parts {
            match eval_term(p, vars) {
                Some(Expr::Str(v)) => acc.push_str(&v),
                _ => return None,
            }
        }
        return Some((name, Expr::Str(acc)));
    }
    if let Some(s) = unquote(rhs) {
        return Some((name, Expr::Str(s)));
    }
    // 依赖插值的双引号串（`"HKLM:\…Services\$n"` / `"$env:SystemDrive\…"`）
    if rhs.starts_with('"') && rhs.ends_with('"') {
        if let Some(s) = interpolate(&rhs[1..rhs.len() - 1], vars) {
            return Some((name, Expr::Str(s)));
        }
        return None;
    }
    if !rhs.is_empty() && rhs.bytes().all(|b| b.is_ascii_digit()) {
        return Some((name, Expr::Str(rhs.to_string())));
    }
    if let Some(rest) = rhs.strip_prefix("New-Object") {
        let n = rest.trim().strip_prefix("byte[]")?.trim();
        let n = n.parse::<usize>().ok()?;
        return Some((name, Expr::Bytes(n)));
    }
    // `[byte[]](0x00,…)` 字面字节串
    if let Some(inner) = rhs.strip_prefix("[byte[]](").and_then(|s| s.strip_suffix(')')) {
        return Some((name, Expr::BytesData(parse_byte_list(inner)?)));
    }
    // `Join-Path <base> <leaf>`（base 可为变量或引号串）
    if let Some(rest) = rhs.strip_prefix("Join-Path") {
        let mut it = rest.trim().splitn(2, char::is_whitespace);
        let base = it.next()?.trim();
        let leaf = it.next()?.trim();
        let leaf = unquote(leaf).or_else(|| eval_term(leaf, vars).and_then(|e| match e {
            Expr::Str(s) => Some(s),
            _ => None,
        }))?;
        let base = eval_term(base, vars).and_then(|e| match e {
            Expr::Str(s) => Some(s),
            _ => None,
        })?;
        return Some((
            name,
            Expr::Str(format!(
                "{}\\{}",
                base.trim_end_matches('\\').replace('/', "\\"),
                leaf.replace('/', "\\")
            )),
        ));
    }
    if rhs.starts_with("@(") && rhs.ends_with(')') {
        let inner = &rhs[2..rhs.len() - 1];
        let mut list = Vec::new();
        for part in split_commas(inner) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            // 列表项允许插值串（tf_onedrive 的 `$env:SystemDrive\OneDriveTemp`）
            let v = match unquote(part) {
                Some(v) => v,
                None => {
                    let t = part.trim();
                    if t.starts_with('"') && t.ends_with('"') {
                        interpolate(&t[1..t.len() - 1], vars)?
                    } else {
                        return None;
                    }
                }
            };
            list.push(v);
        }
        if list.is_empty() {
            return None;
        }
        return Some((name, Expr::List(list)));
    }
    // `@{ K = v; … }` 哈希表（值 = 引号串或数字串）
    if let Some(inner) = rhs.strip_prefix("@{").and_then(|s| s.strip_suffix('}')) {
        let mut map = Vec::new();
        for part in split_statements(inner) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (k, v) = part.split_once('=')?;
            let k = k.trim().to_string();
            if k.is_empty() || k.contains(char::is_whitespace) {
                return None;
            }
            let v = v.trim();
            let v = unquote(v).unwrap_or_else(|| v.to_string());
            map.push((k, v));
        }
        if map.is_empty() {
            return None;
        }
        return Some((name, Expr::Map(map)));
    }
    None
}

/// `(0x22,0x00,…)` 字节列表 → Vec<u8>（十进制与 0x 十六进制都认）
fn parse_byte_list(inner: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for part in split_commas(inner) {
        let t = part.trim();
        if t.is_empty() {
            return None;
        }
        let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            u8::from_str_radix(h, 16).ok()?
        } else {
            t.parse::<u8>().ok()?
        };
        out.push(v);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// 按顶层逗号拆分（引号内的逗号不算；`@("a","b")` 列表用）
fn split_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_sq = false;
    let mut in_dq = false;
    let mut start = 0usize;
    for (i, &c) in s.as_bytes().iter().enumerate() {
        match c {
            b'\'' if !in_dq => in_sq = !in_sq,
            b'"' if !in_sq => in_dq = !in_dq,
            b',' if !in_sq && !in_dq => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn find_matching_brace(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_sq = false;
    let mut in_dq = false;
    for (i, &c) in s.as_bytes().iter().enumerate().skip(open) {
        match c {
            b'\'' if !in_dq => in_sq = !in_sq,
            b'"' if !in_sq => in_dq = !in_dq,
            b'{' if !in_sq && !in_dq => depth += 1,
            b'}' if !in_sq && !in_dq => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

// ==================== v3-K1：枚举管道 / 拼接 / PsInline 白名单 ====================

/// 拆管道：按顶层 `|`（引号/括号/花括号内的 | 不算 —— ForEach 体里的
/// `| Out-Null` 不能被拆出去）
fn split_pipes(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut in_sq = false;
    let mut in_dq = false;
    let mut start = 0usize;
    for (i, &c) in s.as_bytes().iter().enumerate() {
        match c {
            b'\'' if !in_dq => in_sq = !in_sq,
            b'"' if !in_sq => in_dq = !in_dq,
            b'(' | b'{' | b'[' if !in_sq && !in_dq => depth += 1,
            b')' | b'}' | b']' if !in_sq && !in_dq => depth -= 1,
            b'|' if !in_sq && !in_dq && depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// `ForEach-Object { … }` 段 → 体（剥花括号）
fn for_each_body(part: &str) -> Result<&str, String> {
    let t = part.trim();
    let Some(rest) = t.strip_prefix("ForEach-Object") else {
        return Err(format!("管道段只支持 ForEach-Object: {t}"));
    };
    let t = rest.trim();
    let Some(inner) = t.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return Err(format!("ForEach-Object 体不是单个花括号块: {t}"));
    };
    Ok(inner)
}

/// `Get-ChildItem [-LiteralPath] <path> [-ErrorAction SilentlyContinue]` → 根路径
fn child_item_root(head: &str, vars: &VarMap) -> Result<String, String> {
    let rest = head
        .trim()
        .strip_prefix("Get-ChildItem")
        .ok_or_else(|| format!("不是 Get-ChildItem: {head}"))?;
    let toks = tokenize(rest).ok_or("Get-ChildItem 参数 token 化失败")?;
    let mut positional: Vec<String> = Vec::new();
    let mut it = toks.into_iter();
    while let Some(t) = it.next() {
        if t.eq_ignore_ascii_case("-LiteralPath") || t.eq_ignore_ascii_case("-Path") {
            continue;
        }
        if t.eq_ignore_ascii_case("-ErrorAction") {
            let _ = it.next();
            continue;
        }
        if is_param(&t) {
            return Err(format!("Get-ChildItem 不支持的参数: {t}"));
        }
        positional.push(t);
    }
    if positional.len() != 1 {
        return Err(format!("Get-ChildItem 只支持一个路径参数: {head}"));
    }
    let p = positional.remove(0);
    match p.strip_prefix('$') {
        Some(name) => match vars.get(name) {
            Some(Expr::Str(s)) => Ok(s.clone()),
            _ => Err(format!("Get-ChildItem 变量 ${name} 不是字符串")),
        },
        None => unquote(&p).ok_or_else(|| format!("Get-ChildItem 路径非字面量: {p}")),
    }
}

/// CIM 类 → 设备安装类（`Enum\PCI` 实例的 `Class` 值）。
/// 等价性依据：Win32_VideoController 的成员即「Display」安装类设备、
/// Win32_USBController 即「USB」类设备；两个 WMI 类本来就按安装类取成员，
/// 数据层的 `Where PNPDeviceID -like "PCI*"` 再过滤到 PCI 总线 —— 与在
/// `Enum\PCI` 两级子键上按 Class 过滤得到的是同一集合，且不依赖 WMI 服务。
fn cim_class(head: &str) -> Result<&'static str, String> {
    let rest = head
        .trim()
        .strip_prefix("Get-CimInstance")
        .ok_or_else(|| format!("不是 Get-CimInstance: {head}"))?;
    match rest.trim() {
        "Win32_VideoController" => Ok("Display"),
        "Win32_USBController" => Ok("USB"),
        other => Err(format!(
            "Get-CimInstance 只支持 Win32_VideoController/Win32_USBController: {other}"
        )),
    }
}

/// 枚举管道 → 原生算子（v3-K1）。两段 = 注册表子键枚举；三段 = CIM 设备枚举。
fn parse_enum_pipe(raw: &str, vars: &VarMap) -> Result<Vec<PsOp>, String> {
    let parts = split_pipes(raw);
    let snapshot: Vec<(String, Expr)> = vars
        .iter()
        .filter(|(k, _)| k.as_str() != "_")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    match parts.len() {
        2 => {
            let root = child_item_root(parts[0], vars)?;
            let (hive, subkey) =
                parse_ps_reg_path(&root).ok_or_else(|| format!("枚举根不可识别: {root}"))?;
            let body = for_each_body(parts[1])?;
            // 探针干跑：保证执行期对每个子键的延迟解析不会失败（fail-closed 前移）
            let mut probe = vars.clone();
            probe.insert("_".into(), Expr::Str("HKLM:\\__PROBE__".into()));
            parse_block(body, &mut probe)?;
            Ok(vec![PsOp::ForSubKey {
                hive,
                subkey,
                body: body.to_string(),
                vars: snapshot.into_iter().collect(),
            }])
        }
        3 => {
            let class = cim_class(parts[0])?;
            let cond = parts[1].trim();
            let cond_body = cond
                .strip_prefix("Where-Object")
                .map(|r| r.trim())
                .ok_or_else(|| format!("管道第二段只支持 Where-Object: {cond}"))?;
            let inner = cond_body
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
                .ok_or("Where-Object 体不是花括号块")?;
            let toks = tokenize(inner).ok_or("Where-Object 体 token 化失败")?;
            if toks != ["$_.PNPDeviceID", "-like", "\"PCI*\""] {
                return Err(format!("Where-Object 条件不认识: {cond}"));
            }
            let body = for_each_body(parts[2])?;
            let mut probe = vars.clone();
            probe.insert("_".into(), Expr::Str("PCI\\__PROBE__".into()));
            parse_block(body, &mut probe)?;
            Ok(vec![PsOp::ForDevKey {
                class: class.to_string(),
                body: body.to_string(),
                vars: snapshot.into_iter().collect(),
            }])
        }
        _ => Err(format!("不支持的管道: {raw}")),
    }
}

/// `($a + $b)` 位置实参拼接（schtasks 任务名，v3-K1）。
/// 只替换「整个括号段可求值」的情形；求值不了就原样保留（后续环节照常报错）。
fn resolve_concat(line: &str, vars: &VarMap) -> String {
    let bytes = line.as_bytes();
    let mut out = String::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'(' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            let mut depth = 0i32;
            let mut close = None;
            for (j, &b2) in bytes.iter().enumerate().skip(i) {
                match b2 {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(j);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if let Some(close) = close {
                let inner = &line[i + 1..close];
                if let Some(parts) = split_plus(inner) {
                    let mut acc = String::new();
                    let mut ok = true;
                    for p in parts {
                        match eval_term(p, vars) {
                            Some(Expr::Str(v)) => acc.push_str(&v),
                            _ => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if ok {
                        out.push_str(&format!("'{}'", acc.replace('\'', "''")));
                        i = close + 1;
                        continue;
                    }
                }
            }
        }
        let ch = line[i..].chars().next().unwrap_or('(');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// v3-K1：白名单 —— 这些语句头可以**逐字**交给收件箱 Windows PowerShell 执行。
/// 逐字 = 零重解释 = 无「半懂硬执行」风险；白名单的职责是**登记意识**：数据层
/// 新增任何构造，必须在这里有意识地放行，否则 `data_layer_coverage_report` 红。
/// 注意：表内含原生面已支持的 cmdlet，让「原生解析失败但语义无害」的体也能走
/// 逐字通道（例如依赖 $env 展开的路径），不会出现静默错执行。
const PS_INLINE_ALLOW: &[&str] = &[
    // 内存代理 / WMI / 设备 / Appx / 计划任务对象 —— 原生不表达的 Windows 面
    "Disable-MMAgent",
    "Enable-MMAgent",
    "Get-CimInstance",
    "Invoke-CimMethod",
    "Get-PnpDevice",
    "Disable-PnpDevice",
    "Enable-PnpDevice",
    "Get-AppxPackage",
    "Remove-AppxPackage",
    "Get-ScheduledTask",
    "Disable-ScheduledTask",
    "Enable-ScheduledTask",
    // 注册表层命令（逐字执行时不重解释）
    "Get-ChildItem",
    "Get-ItemProperty",
    "Remove-ItemProperty",
    "Remove-Item",
    "Test-Path",
    "Join-Path",
    "New-Item",
    "New-ItemProperty",
    "Set-ItemProperty",
    // 下载校验流（tf_oosu）
    "Invoke-WebRequest",
    "Get-FileHash",
    "Get-AuthenticodeSignature",
    "Start-Process",
    // 输出
    "Write-Output",
    "Write-Error",
    "Write-Host",
    // 管道段
    "Where-Object",
    "ForEach-Object",
    "Sort-Object",
    "Select-Object",
    "Measure-Object",
    "ConvertTo-Json",
];

/// 顶层关键字定位：只认**花括号深度 0** 处的命中（引号内不算）。
/// `word_boundary=true` 时额外要求词边界（前：行首/空白/;/}；后：空白/{）——
/// 供 eligible_scan 的 if/foreach/try 等单词关键字用；false 供
/// "if (Test-Path"/"foreach (" 这类自带边界的短语用。
fn find_top_level(text: &str, kws: &[&str], word_boundary: bool) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut in_sq = false;
    let mut in_dq = false;
    for (i, &c) in bytes.iter().enumerate() {
        match c {
            b'\'' if !in_dq => in_sq = !in_sq,
            b'"' if !in_sq => in_dq = !in_dq,
            b'{' if !in_sq && !in_dq => depth += 1,
            b'}' if !in_sq && !in_dq => depth -= 1,
            _ if !in_sq && !in_dq && depth == 0 => {
                // 只在字符边界上做关键字匹配（注释里有中文多字节字符）
                if text.is_char_boundary(i) {
                    for kw in kws {
                        if text[i..].starts_with(kw) {
                            let before_ok = i == 0
                                || matches!(
                                    bytes[i - 1],
                                    b' ' | b'\n' | b'\r' | b'\t' | b';' | b'}'
                                );
                            let after = i + kw.len();
                            let after_ok = !word_boundary
                                || after >= bytes.len()
                                || matches!(
                                    bytes[after],
                                    b' ' | b'\n' | b'\r' | b'\t' | b'{'
                                );
                            if before_ok && after_ok {
                                return Some(i);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// PsInline 资格扫描：整段体的每个语句头要么在白名单、要么是控制流/表达式形态。
/// 结构走查与 parse_block 同构（先块后语句），保证嵌套块里的头也被逐个检查。
fn ps_inline_eligible(src: &str) -> bool {
    eligible_scan(src)
}

fn eligible_scan(src: &str) -> bool {
    let mut rest = src.trim();
    loop {
        if rest.is_empty() {
            return true;
        }
        // 先找块关键字（与 parse_block 同构的「先结构后语句」次序；只认顶层）
        let kws = ["if", "foreach", "switch", "try", "catch", "finally", "else"];
        if let Some(pos) = find_top_level(rest, &kws, true) {
            if !eligible_stmts(&rest[..pos]) {
                return false;
            }
            let tail = &rest[pos..];
            let Some(open) = tail.find('{') else { return false };
            let Some(close) = find_matching_brace(tail, open) else { return false };
            if !eligible_scan(&tail[open + 1..close]) {
                return false;
            }
            rest = tail[close + 1..].trim();
            continue;
        }
        return eligible_stmts(rest);
    }
}

fn eligible_stmts(src: &str) -> bool {
    split_statements(src).iter().all(|st| eligible_stmt(st))
}

fn eligible_stmt(st: &str) -> bool {
    let mut s = st.trim();
    if s.is_empty() || s.starts_with('#') {
        return true;
    }
    s = s.trim_start_matches('}');
    if s.is_empty() {
        return true;
    }
    // 赋值 LHS：$name = / $null =
    if s.starts_with('$') {
        if let Some((lhs, rhs)) = s.split_once('=') {
            let lhs_t = lhs.trim();
            let ok_lhs = lhs_t == "$null"
                || lhs_t
                    .strip_prefix('$')
                    .map(|n| !n.is_empty() && !n.contains(char::is_whitespace))
                    .unwrap_or(false);
            if ok_lhs {
                s = rhs.trim();
                if s.is_empty() {
                    return true;
                }
            }
        }
    }
    // 表达式形态：.NET 类型调用 / 数组与哈希字面量 / 变量 / 子表达式 /
    // 字符串或数字字面量（含大体积 base64 赋值的 RHS）
    if s.starts_with('[')
        || s.starts_with('@')
        || s.starts_with('(')
        || s.starts_with('$')
        || s.starts_with('"')
        || s.starts_with('\'')
        || s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
    {
        return true;
    }
    let head = s.split_whitespace().next().unwrap_or("");
    if matches!(head, "return" | "break" | "continue") {
        return true;
    }
    PS_INLINE_ALLOW
        .iter()
        .any(|a| a.eq_ignore_ascii_case(head))
}

/// 解析一个 pwsh 步骤体 → 操作列表。
///
/// 优先原生解析；失败时若整体在 PsInline 白名单内 → 单条 `PsOp::PsInline`
/// （逐字交给收件箱 Windows PowerShell，语义零改写）；否则维持 fail-closed Err
/// （`data_layer_coverage_report` 会在测试期红掉，见 v3-M4/K1）。
pub fn compile(body: &str) -> Result<Vec<PsOp>, String> {
    let mut vars = VarMap::new();
    match parse_block(body, &mut vars) {
        Ok(ops) => Ok(ops),
        Err(reason) => {
            if ps_inline_eligible(body) {
                Ok(vec![PsOp::PsInline { script: body.to_string() }])
            } else {
                Err(reason)
            }
        }
    }
}

/// 解析一段语句序列（可含 if/foreach 块）；`vars` 会被语句内的赋值**就地更新**
fn parse_block(
    src: &str,
    vars: &mut std::collections::HashMap<String, Expr>,
) -> Result<Vec<PsOp>, String> {
    let mut ops = Vec::new();
    let mut rest = src;
    loop {
        let trimmed = rest.trim();
        if trimmed.is_empty() {
            return Ok(ops);
        }
        // v3-K1 修正：关键字只在**花括号深度 0** 处认领 —— 否则 ForEach-Object
        // 管道体里的 foreach/if 会被误当顶层块，把管道语句拦腰截断。
        let next_block = find_top_level(
            trimmed,
            &["if (Test-Path", "foreach ("],
            false,
        );
        let Some(pos) = next_block else {
            for st in split_statements(trimmed) {
                ops.extend(parse_statement(st, vars)?);
            }
            return Ok(ops);
        };

        let head = &trimmed[..pos];
        for st in split_statements(head) {
            ops.extend(parse_statement(st, vars)?);
        }
        let tail = &trimmed[pos..];

        if tail.trim_start().starts_with("foreach (") {
            let Some(after) = parse_foreach(tail, vars, &mut ops)? else {
                return Err("foreach 解析意外失败".into());
            };
            rest = after;
            continue;
        }
        if let Some(((hive, subkey), inner, after)) = parse_if_test_path(tail, vars)? {
            ops.push(PsOp::GuardedKeyExists { hive, subkey, ops: inner });
            rest = after;
            continue;
        }
        return Err("无法识别的块结构".into());
    }
}

/// `if (Test-Path $p) { … }` → (守卫键, 内层 ops, 其后剩余文本)
fn parse_if_test_path<'a>(
    src: &'a str,
    vars: &mut std::collections::HashMap<String, Expr>,
) -> Result<Option<((Hive, String), Vec<PsOp>, &'a str)>, String> {
    let Some(rest) = src.trim_start().strip_prefix("if (Test-Path") else {
        return Ok(None);
    };
    // `-LiteralPath` 是长名形态（perf_wu_enable / tf_onedrive 在用），与短名等价
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("-LiteralPath").map(|r| r.trim_start()).unwrap_or(rest);
    // Test-Path 的参数在第一个 `(` 之后，直接取到 `)`（Test-Path 只有一个参数）
    let Some(close_paren) = rest.find(')') else {
        return Err("if (Test-Path 缺右括号".into());
    };
    let cond = rest[..close_paren].trim();
    let path = match cond.strip_prefix('$') {
        Some(name) => match vars.get(name) {
            Some(Expr::Str(s)) => s.clone(),
            _ => return Err(format!("Test-Path 的变量 ${name} 不是字符串字面量")),
        },
        None => unquote(cond).ok_or_else(|| "Test-Path 参数不是字面量".to_string())?,
    };
    let after_paren = &rest[close_paren + 1..];
    let Some(open) = after_paren.find('{') else {
        return Err("if (Test-Path 缺 {{".into());
    };
    if !after_paren[..open].trim().is_empty() {
        return Err("if (Test-Path 与 {{ 之间有多余 token".into());
    }
    let Some(close) = find_matching_brace(after_paren, open) else {
        return Err("if (Test-Path 缺配对 }}".into());
    };
    let inner = &after_paren[open + 1..close];
    let (hive, subkey) =
        parse_ps_reg_path(&path).ok_or_else(|| format!("Test-Path 路径不可识别: {path}"))?;
    let ops = parse_block(inner, vars)?;
    Ok(Some(((hive, subkey), ops, &after_paren[close + 1..])))
}

/// `foreach ($n in @("a","b")) { … }`；成功返回其后的剩余文本
fn parse_foreach<'a>(
    src: &'a str,
    vars: &mut std::collections::HashMap<String, Expr>,
    out: &mut Vec<PsOp>,
) -> Result<Option<&'a str>, String> {
    let Some(rest) = src.trim_start().strip_prefix("foreach (") else {
        return Ok(None);
    };
    // 头部闭合括号 = 第一个 `{` 之前最后一个 `)` —— 列表 `@("a","b")` 自带括号，
    // 从前往后 find 会停在列表中间
    let Some(brace) = rest.find('{') else {
        return Err("foreach 缺 {{".into());
    };
    let head_part = &rest[..brace];
    let Some(close_paren) = head_part.rfind(')') else {
        return Err("foreach ( 缺配对右括号".into());
    };
    let head = rest[..close_paren].trim();
    let Some((var, list_src)) = head.split_once(" in ") else {
        return Err("foreach 头缺 in".into());
    };
    let Some(var) = var.trim().strip_prefix('$') else {
        return Err("foreach 变量必须以 $ 开头".into());
    };
    let var = var.to_string();
    let list_src = list_src.trim();
    // 列表来源（v3-K1 扩展）：
    //   ① `@("…",…)` 字面量（历史形态）
    //   ② `$var` —— 前面语句赋值的字符串列表
    //   ③ `$map.Keys` —— 前面语句赋值的哈希表的键集
    let items: Option<Vec<String>> = if let Some(rest) = list_src.strip_prefix('$') {
        let (name, prop) = match rest.split_once('.') {
            Some((n, p)) => (n, Some(p)),
            None => (rest, None),
        };
        match (vars.get(name), prop) {
            (Some(Expr::List(l)), None) => Some(l.clone()),
            (Some(Expr::Map(m)), Some(p)) if p.eq_ignore_ascii_case("Keys") => {
                Some(m.iter().map(|(k, _)| k.clone()).collect())
            }
            _ => None,
        }
    } else {
        parse_assign(&format!("$x = {list_src}"), vars).and_then(|(_, e)| match e {
            Expr::List(l) => Some(l),
            _ => None,
        })
    };
    let Some(items) = items else {
        return Err(
            "foreach 只支持 @(\"…\") 字面量、已赋值列表变量或 $map.Keys".into(),
        );
    };
    let after_paren = &rest[close_paren + 1..];
    let Some(open) = after_paren.find('{') else {
        return Err("foreach 缺 {{".into());
    };
    if !after_paren[..open].trim().is_empty() {
        return Err("foreach 与 {{ 之间有多余 token".into());
    }
    let Some(close) = find_matching_brace(after_paren, open) else {
        return Err("foreach 缺配对 }}".into());
    };
    let inner = &after_paren[open + 1..close];
    for item in items {
        let mut scoped = vars.clone();
        scoped.insert(var.clone(), Expr::Str(item));
        out.extend(parse_block(inner, &mut scoped)?);
    }
    Ok(Some(&after_paren[close + 1..]))
}

/// 把语句里的 `$var` 替换为字面量。`-参数 $var` 与**位置参数**（如
/// `sc.exe config $n start= …`）都允许；变量出现在 cmdlet 名位置仍属未知形态。
fn resolve_vars(line: &str, vars: &VarMap) -> Result<String, String> {
    if !line.contains('$') {
        return Ok(line.to_string());
    }
    let toks = tokenize(line).ok_or("tokenize 失败")?;
    let mut out: Vec<String> = Vec::new();
    let mut it = toks.into_iter().peekable();
    while let Some(t) = it.next() {
        if is_param(&t) {
            out.push(t);
            if let Some(v) = it.peek() {
                if let Some(rest) = v.strip_prefix('$') {
                    out.push(render_var(rest, vars)?);
                    it.next();
                    continue;
                }
            }
            continue;
        }
        if let Some(rest) = t.strip_prefix('$') {
            // 位置参数上的变量（sc.exe config $n …）／哈希取值／属性访问
            out.push(render_var(rest, vars)?);
            continue;
        }
        out.push(t);
    }
    Ok(out.join(" "))
}

/// `$name` / `$name.PSPath|.PNPDeviceID` / `$name[$key]` → 引号字面量或字节哨兵。
/// 属性访问只认 PSPath / PNPDeviceID：枚举算子已把绑定值规整成解析器需要的形态
/// （子键完整 PS 路径 / PNPDeviceID），两者都直接取绑定值本身；其它属性 = 未知形态。
fn render_var(rest: &str, vars: &VarMap) -> Result<String, String> {
    // `$map[$k]`：哈希表取值（tf_svc_extra5 还原链，v3-K1）
    if let Some((name, keyexpr)) = rest.split_once('[') {
        let key = keyexpr
            .strip_suffix(']')
            .and_then(|k| k.strip_prefix('$'))
            .ok_or_else(|| format!("哈希表下标必须是 $变量: {rest}"))?;
        return match (vars.get(name), vars.get(key)) {
            (Some(Expr::Map(m)), Some(Expr::Str(k))) => {
                let v = m
                    .iter()
                    .find(|(mk, _)| mk == k)
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| format!("哈希表无键 {k}"))?;
                Ok(format!("'{}'", v.replace('\'', "''")))
            }
            _ => Err(format!("哈希表取值形态不认识: {rest}")),
        };
    }
    if let Some((name, prop)) = rest.split_once('.') {
        if prop != "PSPath" && prop != "PNPDeviceID" {
            return Err(format!("不支持的属性访问: {rest}"));
        }
        return match vars.get(name) {
            Some(Expr::Str(s)) => Ok(format!("'{}'", s.replace('\'', "''"))),
            _ => Err(format!("变量 ${name} 不是已赋值的字符串")),
        };
    }
    match vars.get(rest) {
        Some(Expr::Str(s)) => Ok(format!("'{}'", s.replace('\'', "''"))),
        Some(Expr::Bytes(n)) => Ok(format!("__BYTES_{n}__")),
        Some(Expr::BytesData(d)) => {
            // 字节串以 hex 哨兵过墙，encode_value 解回（v3-K1）
            let hex: String = d.iter().map(|b| format!("{b:02X}")).collect();
            Ok(format!("__BYTESHEX_{hex}__"))
        }
        _ => Err(format!("变量 ${rest} 不是已赋值的字符串")),
    }
}

/// 单条语句 → 0..n 个操作；赋值语句会**就地更新** vars（后续语句要用）
fn parse_statement(
    stmt: &str,
    vars: &mut VarMap,
) -> Result<Vec<PsOp>, String> {
    let raw = stmt.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return Ok(Vec::new());
    }
    // 变量赋值（`-eq` 是比较不是赋值，先排除以免误判）
    if raw.starts_with('$') && raw.contains('=') && !raw.contains("-eq") {
        if let Some((name, expr)) = parse_assign(raw, vars) {
            vars.insert(name, expr);
            // 赋值语句本身不产生操作；同一语句里再带其它命令属未知形态，回退
            return Ok(Vec::new());
        }
        return Err(format!("无法识别的赋值: {raw}"));
    }
    // 枚举管道（v3-K1）：注册表子键 / CIM 设备类 → 原生枚举算子
    if (raw.starts_with("Get-ChildItem") || raw.starts_with("Get-CimInstance")) && raw.contains('|') {
        return parse_enum_pipe(raw, vars);
    }
    let Some(line) = strip_pipeline(raw) else {
        return Err(format!("不支持的管道: {raw}"));
    };
    // 位置实参拼接 `($a + $b)`（schtasks 任务名，v3-K1）
    let line = resolve_concat(line, vars);
    let line = resolve_vars(&line, vars)?;
    let cmd = parse_cmd(&line).ok_or_else(|| format!("无法解析语句: {raw}"))?;
    // 参数值取字面量：带引号 → 去引号（依赖展开则报错）；裸 token → 原样
    // （PS 允许 `-Name X` 这种裸参数，数据层大量使用）
    let lit = |v: &str, what: &str| -> Result<String, String> {
        let t = v.trim();
        if t.starts_with('\'') || t.starts_with('"') {
            unquote(t).ok_or_else(|| format!("{what} 非字面量: {v}"))
        } else if t.contains('$') || t.contains('`') {
            Err(format!("{what} 依赖展开: {v}"))
        } else {
            Ok(t.to_string())
        }
    };
    // 路径参数：去引号后交给 parse_ps_reg_path
    let path_arg = |v: &str| -> Result<String, String> {
        let t = v.trim();
        if t.starts_with('\'') || t.starts_with('"') {
            unquote(t).ok_or_else(|| format!("路径依赖展开: {v}"))
        } else if t.contains('$') {
            Err(format!("路径依赖变量: {v}"))
        } else {
            Ok(t.to_string())
        }
    };

    match cmd.name.as_str() {
        "New-ItemProperty" | "Set-ItemProperty" => {
            let path = path_arg(param(&cmd, "Path").ok_or("缺 -Path")?)?;
            let name = lit(param(&cmd, "Name").ok_or("缺 -Name")?, "-Name")?;
            let value = param(&cmd, "Value").unwrap_or_default().to_string();
            let ptype = param(&cmd, "PropertyType").unwrap_or_else(|| "String".into()).to_string();
            if !has_flag(&cmd, "Force") {
                return Err("New/Set-ItemProperty 必须带 -Force（键已存在时语义不同）".into());
            }
            let (hive, subkey) = parse_ps_reg_path(&path).ok_or_else(|| format!("路径不可识别: {path}"))?;
            let (kind, data) = encode_value(&ptype, &value, vars)?;
            Ok(vec![PsOp::ValueWrite { hive, subkey, name, kind, data }])
        }
        "Remove-ItemProperty" => {
            let path = path_arg(param(&cmd, "Path").ok_or("缺 -Path")?)?;
            let name = lit(param(&cmd, "Name").ok_or("缺 -Name")?, "-Name")?;
            let (hive, subkey) = parse_ps_reg_path(&path).ok_or_else(|| format!("路径不可识别: {path}"))?;
            Ok(vec![PsOp::ValueRemove { hive, subkey, name }])
        }
        "New-Item" => {
            let path = path_arg(param(&cmd, "Path").ok_or("缺 -Path")?)?;
            if !has_flag(&cmd, "Force") {
                return Err("New-Item 必须带 -Force".into());
            }
            let (hive, subkey) = parse_ps_reg_path(&path).ok_or_else(|| format!("路径不可识别: {path}"))?;
            Ok(vec![PsOp::KeyCreate { hive, subkey }])
        }
        "Remove-Item" => {
            let path = path_arg(param(&cmd, "Path").ok_or("缺 -Path")?)?;
            let recurse = has_flag(&cmd, "Recurse");
            if !has_flag(&cmd, "Force") {
                return Err("Remove-Item 必须带 -Force（隐藏/只读项会失败）".into());
            }
            let (hive, subkey) = parse_ps_reg_path(&path).ok_or_else(|| format!("路径不可识别: {path}"))?;
            Ok(vec![PsOp::KeyRemove { hive, subkey, recurse }])
        }
        "Stop-Service" => {
            let name = lit(param(&cmd, "Name").ok_or("缺 -Name")?, "-Name")?;
            Ok(vec![PsOp::SvcStop { name }])
        }
        "Disable-ScheduledTask" | "Enable-ScheduledTask" => {
            let name = lit(param(&cmd, "TaskName").ok_or("缺 -TaskName")?, "-TaskName")?;
            let path = match param(&cmd, "TaskPath") {
                Some(p) => Some(lit(p, "-TaskPath")?),
                None => None,
            };
            Ok(vec![PsOp::TaskChange { path, name, disable: cmd.name == "Disable-ScheduledTask" }])
        }
        "sc.exe" => {
            // `sc.exe config <svc> start= <n>`：位置参数 [config, <svc>, start=, <n>]
            if cmd.positional.len() != 4 || cmd.positional[0] != "config" {
                return Err(format!("sc.exe 只支持 `config <svc> start= <n>`: {raw}"));
            }
            let svc = unquote(&cmd.positional[1]).unwrap_or_else(|| cmd.positional[1].clone());
            let start_raw = unquote(&cmd.positional[3]).unwrap_or_else(|| cmd.positional[3].clone());
            let start = start_raw.trim();
            let n = match start {
                "disabled" | "4" => 4,
                "manual" | "3" => 3,
                "auto" | "automatic" | "2" => 2,
                "boot" | "0" => 0,
                "system" | "1" => 1,
                other => return Err(format!("未知服务启动类型: {other}")),
            };
            Ok(vec![PsOp::SvcSetStart { name: svc, start: n }])
        }
        "schtasks" => {
            // 位置式 `schtasks /change /tn <name> /disable|/enable`
            // （telemetry_optimize / tf_nvidia_telemetry 的形态，v3-K1）
            if cmd.positional.len() != 4
                || !cmd.positional[0].eq_ignore_ascii_case("/change")
                || !cmd.positional[1].eq_ignore_ascii_case("/tn")
            {
                return Err(format!("schtasks 只支持 /change /tn <name> /disable|/enable: {raw}"));
            }
            let name = unquote(&cmd.positional[2]).unwrap_or_else(|| cmd.positional[2].clone());
            let disable = match cmd.positional[3].as_str() {
                "/disable" | "/DISABLE" => true,
                "/enable" | "/ENABLE" => false,
                other => return Err(format!("schtasks 未知动作: {other}")),
            };
            Ok(vec![PsOp::TaskChange { path: None, name, disable }])
        }
        "powercfg" => {
            // v3-K1：ASPM 关闭链。只放行 powercfg（PINNED，system_tool 解析到
            // System32）；其它可执行程序不进本通道（编译与执行两侧双重把守）。
            if cmd.positional.is_empty() {
                return Err("powercfg 缺参数".into());
            }
            Ok(vec![PsOp::Spawn {
                program: "powercfg.exe".into(),
                args: cmd.positional.clone(),
            }])
        }
        other => Err(format!("不支持的 cmdlet: {other}")),
    }
}

/// -Value + -PropertyType → (kind, bytes)
fn encode_value(
    ptype: &str,
    value: &str,
    vars: &std::collections::HashMap<String, Expr>,
) -> Result<(u32, Vec<u8>), String> {
    // 变量形式的值（如 $zero / $nowFt）；resolve_vars 会把 Bytes 变量替换成哨兵
    if let Some(name) = value.trim().strip_prefix('$') {
        return match vars.get(name) {
            Some(Expr::Bytes(n)) => Ok((KIND_BINARY, vec![0u8; *n])),
            Some(Expr::BytesData(d)) => Ok((KIND_BINARY, d.clone())),
            Some(Expr::Str(s)) => Ok(sz_bytes(s)),
            _ => Err(format!("变量 ${name} 不能作 -Value")),
        };
    }
    if let Some(n) = value
        .trim()
        .strip_prefix("__BYTES_")
        .and_then(|s| s.strip_suffix("__"))
        .and_then(|s| s.parse::<usize>().ok())
    {
        return Ok((KIND_BINARY, vec![0u8; n]));
    }
    // 字节串 hex 哨兵（BytesData 变量经 resolve_vars 过墙的形态，v3-K1）
    if let Some(hex) = value
        .trim()
        .strip_prefix("__BYTESHEX_")
        .and_then(|s| s.strip_suffix("__"))
    {
        if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("字节哨兵畸形: {value}"));
        }
        let v = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| e.to_string())?;
        return Ok((KIND_BINARY, v));
    }
    // 内联字节字面量 `([byte[]](0x22,…))`（perf_exploit_protection_off，v3-K1）
    if let Some(inner) = value
        .trim()
        .strip_prefix("([byte[]](")
        .and_then(|s| s.strip_suffix("))"))
    {
        let data = parse_byte_list(inner).ok_or_else(|| format!("内联字节列表畸形: {value}"))?;
        return Ok((KIND_BINARY, data));
    }
    match ptype.trim().to_ascii_lowercase().as_str() {
        "dword" => {
            let n: i32 = unquote(value)
                .unwrap_or_else(|| value.to_string())
                .trim()
                .parse()
                .map_err(|_| format!("DWord 值不是整数: {value}"))?;
            Ok((KIND_DWORD, n.to_le_bytes().to_vec()))
        }
        "qword" => {
            let n: i64 = unquote(value)
                .unwrap_or_else(|| value.to_string())
                .trim()
                .parse()
                .map_err(|_| format!("QWord 值不是整数: {value}"))?;
            Ok((KIND_QWORD, n.to_le_bytes().to_vec()))
        }
        "binary" => {
            let hex = unquote(value).unwrap_or_else(|| value.to_string());
            let hex = hex.trim();
            if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("Binary 值畸形: {value}"));
            }
            let mut v = Vec::with_capacity(hex.len() / 2);
            for i in (0..hex.len()).step_by(2) {
                v.push(u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string())?);
            }
            Ok((KIND_BINARY, v))
        }
        "expandstring" => {
            let s = unquote(value).ok_or_else(|| format!("ExpandString 值非字面量: {value}"))?;
            let (_, bytes) = sz_bytes(&s);
            Ok((KIND_EXPAND_SZ, bytes))
        }
        // String / 其它标签一律按 SZ（与 New-ItemProperty 不带类型时的默认一致）
        _ => {
            let s = unquote(value).ok_or_else(|| format!("字符串值非字面量: {value}"))?;
            Ok(sz_bytes(&s))
        }
    }
}

fn sz_bytes(s: &str) -> (u32, Vec<u8>) {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    (KIND_SZ, v)
}

// ==================== 执行 ====================

/// 执行一组操作；任一失败即 Err（调用方据此把整条优化项报失败）。
/// 返回 PsInline 算子产生的 stdout 累积串（`@@RECYCLE@@` 协议行在其中，
/// 由 optimizer.rs 统一解析；纯原生操作不产生输出）。
pub fn execute(ops: &[PsOp]) -> Result<String, String> {
    let mut out = String::new();
    for op in ops {
        out.push_str(&exec_one(op)?);
    }
    Ok(out)
}

fn hive_handle(h: Hive) -> windows::Win32::System::Registry::HKEY {
    use windows::Win32::System::Registry::*;
    match h {
        Hive::Lm => HKEY_LOCAL_MACHINE,
        Hive::Cu => HKEY_CURRENT_USER,
        Hive::Cr => HKEY_CLASSES_ROOT,
        Hive::U => HKEY_USERS,
        Hive::Cc => HKEY_CURRENT_CONFIG,
    }
}

fn kind_of(v: u32) -> windows::Win32::System::Registry::REG_VALUE_TYPE {
    windows::Win32::System::Registry::REG_VALUE_TYPE(v)
}

fn hive_prefix(h: Hive) -> &'static str {
    match h {
        Hive::Lm => "HKLM",
        Hive::Cu => "HKCU",
        Hive::Cr => "HKCR",
        Hive::U => "HKU",
        Hive::Cc => "HKCC",
    }
}

fn exec_one(op: &PsOp) -> Result<String, String> {
    match op {
        PsOp::KeyCreate { hive, subkey } => {
            if native::reg_key_ensure(hive_handle(*hive), subkey) {
                Ok(String::new())
            } else {
                Err(format!("创建注册表键失败: {subkey}"))
            }
        }
        PsOp::KeyRemove { hive, subkey, recurse } => {
            if native::reg_key_remove(hive_handle(*hive), subkey, *recurse) {
                Ok(String::new())
            } else {
                Err(format!("删除注册表键失败: {subkey}"))
            }
        }
        PsOp::ValueWrite { hive, subkey, name, kind, data } => {
            if native::reg_restore_write(hive_handle(*hive), subkey, name, kind_of(*kind), data) {
                Ok(String::new())
            } else {
                Err(format!("写注册表值失败: {subkey}\\{name}"))
            }
        }
        PsOp::ValueRemove { hive, subkey, name } => {
            if native::reg_restore_delete(hive_handle(*hive), subkey, name) {
                Ok(String::new())
            } else {
                Err(format!("删注册表值失败: {subkey}\\{name}"))
            }
        }
        PsOp::SvcStop { name } => {
            native::service_stop_pub(name)?;
            Ok(String::new())
        }
        PsOp::SvcSetStart { name, start } => {
            native::service_set_start_pub(name, *start)?;
            Ok(String::new())
        }
        PsOp::TaskChange { path, name, disable } => {
            native::task_change(path.as_deref(), name, *disable)?;
            Ok(String::new())
        }
        PsOp::GuardedKeyExists { hive, subkey, ops } => {
            // 键不存在 = 功能没装，跳过（对齐 PS `if (Test-Path …)` 语义）
            if !native::reg_key_exists(hive_handle(*hive), subkey) {
                return Ok(String::new());
            }
            let mut out = String::new();
            for o in ops {
                out.push_str(&exec_one(o)?);
            }
            Ok(out)
        }
        PsOp::ForSubKey { hive, subkey, body, vars } => {
            // 键不存在 = 无迭代（PS Get-ChildItem -ErrorAction SilentlyContinue 语义）
            if !native::reg_key_exists(hive_handle(*hive), subkey) {
                return Ok(String::new());
            }
            let subs = native::reg_enum_subkeys_pub(hive_handle(*hive), subkey);
            let mut out = String::new();
            for name in subs {
                let full = format!("{}:\\{}\\{}", hive_prefix(*hive), subkey, name);
                let mut v = vars.clone();
                v.insert("_".into(), Expr::Str(full));
                // 编译期已探针干跑，此处理论上不可失败；仍如实上报
                for o in parse_block(body, &mut v)? {
                    out.push_str(&exec_one(&o)?);
                }
            }
            Ok(out)
        }
        PsOp::ForDevKey { class, body, vars } => {
            let mut out = String::new();
            for id in native::reg_enum_dev_ids(class) {
                let mut v = vars.clone();
                v.insert("_".into(), Expr::Str(id));
                for o in parse_block(body, &mut v)? {
                    out.push_str(&exec_one(&o)?);
                }
            }
            Ok(out)
        }
        PsOp::Spawn { program, args } => {
            // 编译期只从 "powercfg" 臂产生本算子；执行侧再核一次白名单（双保险）
            if !program.eq_ignore_ascii_case("powercfg.exe") {
                return Err(format!("Spawn 算子只允许 powercfg.exe，收到 {program}"));
            }
            let out = crate::engine::systembin::quiet_cmd(crate::engine::systembin::system_tool(program))
                .args(args)
                .output()
                .map_err(|e| format!("powercfg 执行失败: {e}"))?;
            if out.status.success() {
                Ok(String::new())
            } else {
                Err(format!(
                    "powercfg 退出码 {}",
                    out.status.code().unwrap_or(-1)
                ))
            }
        }
        PsOp::PsInline { script } => {
            // 逐字交给收件箱 Windows PowerShell（System32 自带，无需用户装 pwsh7）。
            // 脚本写私有 tmp（reparse 判拒），跑完即删；stdout 交回调用方解析
            // `@@RECYCLE@@` 协议（tf_onedrive 的目录回收走这里）。
            let dir = crate::engine::paths::temp_script_dir()?;
            std::fs::create_dir_all(&dir).map_err(|e| format!("创建私有 tmp 失败: {e}"))?;
            let path = dir.join(format!("optpsinline_{}.ps1", crate::engine::now_ms()));
            std::fs::write(&path, script.as_bytes()).map_err(|e| format!("写内联脚本失败: {e}"))?;
            let r = crate::pwsh::run_inbox_ps(&path, std::time::Duration::from_secs(300));
            let _ = std::fs::remove_file(&path);
            let out = r?;
            if out.timed_out {
                return Err("内联 PS 步骤执行超时（300s）".into());
            }
            if out.code != 0 {
                return Err(format!("内联 PS 步骤退出码 {}", out.code));
            }
            Ok(out.stdout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_literal_item_property() {
        let ops = compile(
            "New-ItemProperty -Path 'HKCU:\\Control Panel\\Mouse' -Name X -Value 1 -PropertyType DWord -Force | Out-Null",
        )
        .unwrap();
        assert_eq!(
            ops,
            vec![PsOp::ValueWrite {
                hive: Hive::Cu,
                subkey: "Control Panel\\Mouse".into(),
                name: "X".into(),
                kind: KIND_DWORD,
                data: 1i32.to_le_bytes().to_vec(),
            }]
        );
    }

    #[test]
    fn parses_var_assign_and_binary() {
        let ops = compile(
            "$zero = New-Object byte[] 40\n\
             $m = \"HKCU:\\Control Panel\\Mouse\"\n\
             New-ItemProperty -Path $m -Name SmoothMouseXCurve -Value $zero -PropertyType Binary -Force | Out-Null",
        )
        .unwrap();
        match &ops[0] {
            PsOp::ValueWrite { hive, subkey, name, kind, data } => {
                assert_eq!(
                    (*hive, subkey.as_str(), name.as_str()),
                    (Hive::Cu, "Control Panel\\Mouse", "SmoothMouseXCurve")
                );
                assert_eq!(*kind, KIND_BINARY);
                assert_eq!(data.len(), 40);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_test_path_guard_and_service() {
        let ops = compile(
            "$p = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Fax\"; \
             if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 4 -PropertyType DWord -Force | Out-Null; \
             Stop-Service -Name Fax -Force -ErrorAction SilentlyContinue }",
        )
        .unwrap();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            PsOp::GuardedKeyExists { hive, subkey, ops } => {
                assert_eq!(
                    (*hive, subkey.as_str()),
                    (Hive::Lm, "SYSTEM\\CurrentControlSet\\Services\\Fax")
                );
                assert_eq!(ops.len(), 2);
                assert!(matches!(&ops[1], PsOp::SvcStop { name } if name == "Fax"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_foreach_and_sc_config() {
        let ops = compile(
            "foreach ($n in @(\"SensrSvc\",\"StorSvc\")) { Stop-Service -Name $n -Force -ErrorAction SilentlyContinue; \
             sc.exe config $n start= disabled 2>$null | Out-Null }",
        )
        .unwrap();
        assert_eq!(ops.len(), 4, "2 服务 × (stop + config)，实际 {ops:?}");
        assert!(matches!(&ops[0], PsOp::SvcStop { name } if name == "SensrSvc"));
        assert!(matches!(&ops[1], PsOp::SvcSetStart { name, start } if name == "SensrSvc" && *start == 4));
        assert!(matches!(&ops[3], PsOp::SvcSetStart { name, start } if name == "StorSvc" && *start == 4));
    }

    #[test]
    fn parses_scheduled_task() {
        let ops = compile(
            "Disable-ScheduledTask -TaskPath \"\\Microsoft\\Windows\\Defrag\" -TaskName \"ScheduledDefrag\" -ErrorAction SilentlyContinue | Out-Null",
        )
        .unwrap();
        assert_eq!(
            ops,
            vec![PsOp::TaskChange {
                path: Some("\\Microsoft\\Windows\\Defrag".into()),
                name: "ScheduledDefrag".into(),
                disable: true,
            }]
        );
    }

    #[test]
    fn parses_key_create_and_remove() {
        let ops = compile(
            "New-Item -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\" -Force | Out-Null; \
             Remove-Item -Path \"HKCU:\\X\" -Recurse -Force",
        )
        .unwrap();
        assert!(matches!(
            &ops[0],
            PsOp::KeyCreate { hive, subkey }
                if *hive == Hive::Lm && subkey == "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"
        ));
        assert!(matches!(&ops[1], PsOp::KeyRemove { recurse: true, .. }));
    }

    /// fail-closed 是本模块的**第一原则**：白名单外的未知构造必须 Err，绝不猜。
    /// （v3-K1 后白名单内的构造会走 PsInline 逐字执行，所以这里全部改用
    /// **非白名单**的 cmdlet 来验证 fail-closed 边界。）
    #[test]
    fn rejects_unknown_constructs() {
        // 管道里不是 Out-Null（需要真求值）——头不在白名单
        assert!(compile("Get-Process | Where-Object { $_.Name }").is_err());
        // 未赋值的变量 + 非白名单 cmdlet
        assert!(compile("Invoke-Expression $undef").is_err());
        // 未知 cmdlet
        assert!(compile("Stop-Computer -Force").is_err());
        // 引号不闭合：原生拒绝；头（赋值 RHS 字符串字面量）在白名单 → PsInline
        // 逐字执行，由 PS 在运行期报语法错误（逐字 = 语义零改写，坏脚本坏在 PS 自己手里）
        let ops = compile("$p = \"HKLM:\\X").unwrap();
        assert!(matches!(&ops[0], PsOp::PsInline { .. }));
        // 引号不闭合 + 非白名单头 → Err（fail-closed 边界真正落点）
        assert!(compile("Get-Service \"HKLM:\\X").is_err());
        // 变量出现在参数值之外（Get-Service 不在白名单）
        assert!(compile("$a = Get-Service").is_err());
        // 引号内依赖展开的路径 —— 原生拒绝，但头在白名单 → PsInline 逐字执行
        // （语义零改写，这正是白名单存在的意义；这里只验证它编译成功且是单条 PsInline）
        let ops = compile(
            "New-ItemProperty -Path \"HKLM:\\$env:x\" -Name A -Value 1 -PropertyType DWord -Force",
        )
        .unwrap();
        assert!(matches!(&ops[0], PsOp::PsInline { .. }));
        // -Force 缺失：原生拒绝（键已存在时语义不同），头在白名单 → PsInline 逐字执行
        let ops =
            compile("New-ItemProperty -Path 'HKCU:\\X' -Name A -Value 1 -PropertyType DWord")
                .unwrap();
        assert!(matches!(&ops[0], PsOp::PsInline { .. }));
    }

    /// v3-K1：新原生构造的解析行为（foreach 变量列表 / 插值 / 拼接 / byte[] /
    /// 哈希表 / schtasks / powercfg / 枚举管道）
    #[test]
    fn parses_v3k1_constructs() {
        // foreach 变量列表 + 双引号插值
        let ops = compile(
            "$names = @(\"A\",\"B\")\nforeach ($n in $names) { $p = \"HKLM:\\SYSTEM\\Services\\$n\"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 4 -PropertyType DWord -Force | Out-Null } }",
        )
        .unwrap();
        assert!(matches!(&ops[0], PsOp::GuardedKeyExists { .. }));
        assert_eq!(ops.len(), 2);

        // schtasks 位置式 + 位置实参拼接
        let ops = compile(
            "$sfx = \"_{B2FE1952}\"\nforeach ($t in @(\"T1\",\"T2\")) { schtasks /change /tn ($t + $sfx) /disable 2>$null | Out-Null }",
        )
        .unwrap();
        assert!(matches!(&ops[0], PsOp::TaskChange { name, disable: true, .. } if name == "T1_{B2FE1952}"));
        assert_eq!(ops.len(), 2);

        // powercfg
        let ops = compile("powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0").unwrap();
        assert!(matches!(&ops[0], PsOp::Spawn { program, .. } if program == "powercfg.exe"));

        // [byte[]] 字面量 → Binary 值
        let ops = compile(
            "$p = \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\"\n$map = [byte[]](0x00,0x5b,0xe0)\nNew-ItemProperty -Path $p -Name \"Scancode Map\" -Value $map -PropertyType Binary -Force | Out-Null",
        )
        .unwrap();
        match &ops[0] {
            PsOp::ValueWrite { data, kind, .. } => {
                assert_eq!(*kind, KIND_BINARY);
                assert_eq!(data, &vec![0x00u8, 0x5b, 0xe0]);
            }
            other => panic!("{other:?}"),
        }

        // 哈希表 + $map.Keys + $map[$n]
        let ops = compile(
            "$map = @{ SensrSvc = 3; StorSvc = 2 }\nforeach ($n in $map.Keys) { $p = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n\"; if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value $map[$n] -PropertyType DWord -Force | Out-Null } }",
        )
        .unwrap();
        assert_eq!(ops.len(), 2);
        assert!(matches!(&ops[0], PsOp::GuardedKeyExists { .. }));

        // 注册表子键枚举管道 → ForSubKey
        let ops = compile(
            "$root = \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\"\nif (Test-Path $root) { Get-ChildItem $root | ForEach-Object { New-ItemProperty -Path $_.PSPath -Name Start -Value 0 -PropertyType DWord -Force | Out-Null } }",
        )
        .unwrap();
        match &ops[0] {
            PsOp::GuardedKeyExists { ops: inner, .. } => {
                assert!(matches!(&inner[0], PsOp::ForSubKey { .. }));
            }
            other => panic!("{other:?}"),
        }

        // CIM 设备枚举管道 → ForDevKey（体里的拼接 + Join-Path）
        let ops = compile(
            "Get-CimInstance Win32_VideoController | Where-Object { $_.PNPDeviceID -like \"PCI*\" } | ForEach-Object {\n  $enum = \"HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\\" + $_.PNPDeviceID\n  $msi = Join-Path $enum \"Device Parameters\\Interrupt Management\\MessageSignaledInterruptProperties\"\n  New-Item -Path $msi -Force | Out-Null\n  New-ItemProperty -Path $msi -Name MSISupported -Value 1 -PropertyType DWord -Force | Out-Null\n}",
        )
        .unwrap();
        assert!(matches!(&ops[0], PsOp::ForDevKey { class, .. } if class == "Display"));

        // PsInline：白名单内的原生不可编译构造（Appx 管道）
        let ops = compile(
            "Get-AppxPackage -AllUsers -Name \"*cortana*\" -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue",
        )
        .unwrap();
        assert!(matches!(&ops[0], PsOp::PsInline { .. }));
    }

    /// **数据驱动覆盖度量**：把优化项数据层里的全部 pwsh 步骤喂给解释器，
    /// 报告原生覆盖与 PsInline 分流。
    ///
    /// 审查 v3-M4：旧版只打印不断言，K1（S3 删 PS 兜底后 30 项必败）正是借着
    /// 「cargo test 全绿」溜过发布的 —— 现在钉死 **编译失败数必须为 0**：解释器
    /// 与白名单都不认的构造必须先扩这里，而不是写进数据层等运行时报错。
    /// 跑红时先看打印清单定位是哪条步骤。
    #[test]
    fn data_layer_coverage_report() {
        const OPTIONS_JSON: &str = include_str!("../../data/optimizer-runtime.json");
        let opts: Vec<serde_json::Value> =
            serde_json::from_str(OPTIONS_JSON).expect("optimizer-runtime.json 合法");
        let mut total = 0usize;
        let mut native_ok = 0usize;
        let mut inline = 0usize;
        let mut fallback: Vec<String> = Vec::new();
        for o in &opts {
            let id = o.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            for (phase, arr) in [
                ("steps", o.get("steps").and_then(|v| v.as_array())),
                ("restore", o.get("restore").and_then(|v| v.as_array())),
            ] {
                for (i, s) in arr.unwrap_or(&Vec::new()).iter().enumerate() {
                    let Some(body) = s.get("pwsh").and_then(|v| v.as_str()) else { continue };
                    total += 1;
                    match compile(body) {
                        Ok(ops) => {
                            assert!(!ops.is_empty(), "{id} [{phase}#{i}] 解析成空操作集");
                            if matches!(&ops[0], PsOp::PsInline { .. }) {
                                inline += 1;
                            } else {
                                native_ok += 1;
                            }
                        }
                        Err(reason) => fallback.push(format!("{id} [{phase}#{i}] {reason}")),
                    }
                }
            }
        }
        println!("\n=== v3-K1 pwsh 解释器覆盖（数据层实测） ===");
        println!("总 pwsh 步骤   : {total}");
        println!("原生执行       : {native_ok}");
        println!("PsInline（inbox PS 逐字执行）: {inline}");
        println!("编译失败       : {}", fallback.len());
        for f in &fallback {
            println!("  - {f}");
        }
        // 硬性断言（审查 v3-M4/K1）：编译失败必须为 0。兜底 PS 回退已随 S3 删除，
        // 编译不过的步骤 = 正向/还原必败的功能回归，必须在测试阶段红掉。
        assert_eq!(
            fallback.len(),
            0,
            "仍有 {} 条 pwsh 步骤不可编译（详见上方清单）：扩解释器或登记 PsInline 白名单",
            fallback.len()
        );
    }
}
