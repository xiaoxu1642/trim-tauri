//! pwsh 步骤的原生解释器（B11）
//!
//! **范围刻意收窄**：只认优化项数据层里实际出现的指令子集，且参数必须是**字面量**
//! （或由字面量赋值的简单变量）。任何不认识的 cmdlet、变量形态、表达式 → `Err`，
//! 由调用方把**整条优化项**回退 PS 执行 —— 宁可慢，不可错。
//!
//! 为什么不写成通用解释器：半懂不懂的执行 = 静默没执行却报成功，是本项目最忌讳的
//! 「假绿」。fail-closed 的收窄范围让这个模块的失败模式只有一种：回退到已经跑了
//! 三年的 PS 路径。
//!
//! 支持的指令（与数据层实测分布对应，见 tools/categorize-ps-steps.mjs）：
//! - `New-ItemProperty` / `Set-ItemProperty`（-Path/-Name/-Value/-PropertyType/-Force）
//! - `Remove-ItemProperty`（-Path/-Name）
//! - `New-Item`（-Path/-Force，仅注册表路径）  `Remove-Item`（-Path/-Recurse/-Force）
//! - `Stop-Service`（-Name/-Force）            `sc.exe config <svc> start= <n|disabled>`
//! - `Disable-ScheduledTask` / `Enable-ScheduledTask`（-TaskName/-TaskPath）
//! - `if (Test-Path $var) { … }`               `foreach ($n in @("a","b")) { … }`
//! - `$var = "字面量"` / `$var = 123` / `$var = New-Object byte[] N`

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
}

// REG_VALUE_TYPE 裸值（windows crate 的 REG_VALUE_TYPE(u32)）
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

/// 把一段源码按**顶层** `;` 或换行拆条（引号内与括号内的分号不算）
fn split_statements(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth_paren = 0i32;
    let mut in_sq = false;
    let mut in_dq = false;
    let mut start = 0usize;
    for (i, &c) in s.as_bytes().iter().enumerate() {
        match c {
            b'\'' if !in_dq => in_sq = !in_sq,
            b'"' if !in_sq => in_dq = !in_dq,
            b'(' if !in_sq && !in_dq => depth_paren += 1,
            b')' if !in_sq && !in_dq => depth_paren -= 1,
            b';' | b'\n' if !in_sq && !in_dq && depth_paren == 0 => {
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
#[derive(Debug, Clone)]
enum Expr {
    Str(String),
    Bytes(usize),
    List(Vec<String>),
}

fn parse_assign(stmt: &str) -> Option<(String, Expr)> {
    let (lhs, rhs) = stmt.split_once('=')?;
    let name = lhs.trim().strip_prefix('$')?.to_string();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    let rhs = rhs.trim();
    if let Some(s) = unquote(rhs) {
        return Some((name, Expr::Str(s)));
    }
    if !rhs.is_empty() && rhs.bytes().all(|b| b.is_ascii_digit()) {
        return Some((name, Expr::Str(rhs.to_string())));
    }
    if let Some(rest) = rhs.strip_prefix("New-Object") {
        let n = rest.trim().strip_prefix("byte[]")?.trim();
        let n = n.parse::<usize>().ok()?;
        return Some((name, Expr::Bytes(n)));
    }
    if rhs.starts_with("@(") && rhs.ends_with(')') {
        let inner = &rhs[2..rhs.len() - 1];
        let mut list = Vec::new();
        for part in split_commas(inner) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            list.push(unquote(part)?);
        }
        if list.is_empty() {
            return None;
        }
        return Some((name, Expr::List(list)));
    }
    None
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
        let next_if = trimmed.find("if (Test-Path");
        let next_fe = trimmed.find("foreach (");
        let next_block = match (next_if, next_fe) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
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
    let items = match parse_assign(&format!("$x = {list_src}")) {
        Some((_, Expr::List(l))) => l,
        _ => return Err("foreach 只支持 @(\"…\") 字符串字面量列表".into()),
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
fn resolve_vars(line: &str, vars: &std::collections::HashMap<String, Expr>) -> Result<String, String> {
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
                if let Some(name) = v.strip_prefix('$') {
                    match vars.get(name) {
                        Some(Expr::Str(s)) => {
                            out.push(format!("'{}'", s.replace('\'', "''")));
                            it.next();
                            continue;
                        }
                        Some(Expr::Bytes(n)) => {
                            out.push(format!("__BYTES_{n}__"));
                            it.next();
                            continue;
                        }
                        _ => return Err(format!("变量 ${name} 不是已赋值的字符串")),
                    }
                }
            }
            continue;
        }
        if let Some(name) = t.strip_prefix('$') {
            // 位置参数上的变量（sc.exe config $n …）
            match vars.get(name) {
                Some(Expr::Str(s)) => out.push(format!("'{}'", s.replace('\'', "''"))),
                _ => return Err(format!("变量 ${name} 不是已赋值的字符串")),
            }
            continue;
        }
        out.push(t);
    }
    Ok(out.join(" "))
}

/// 单条语句 → 0..n 个操作；赋值语句会**就地更新** vars（后续语句要用）
fn parse_statement(
    stmt: &str,
    vars: &mut std::collections::HashMap<String, Expr>,
) -> Result<Vec<PsOp>, String> {
    let raw = stmt.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return Ok(Vec::new());
    }
    // 变量赋值（`-eq` 是比较不是赋值，先排除以免误判）
    if raw.starts_with('$') && raw.contains('=') && !raw.contains("-eq") {
        if let Some((name, expr)) = parse_assign(raw) {
            vars.insert(name, expr);
            // 赋值语句本身不产生操作；同一语句里再带其它命令属未知形态，回退
            return Ok(Vec::new());
        }
        return Err(format!("无法识别的赋值: {raw}"));
    }
    let Some(line) = strip_pipeline(raw) else {
        return Err(format!("不支持的管道: {raw}"));
    };
    let line = resolve_vars(line, vars)?;
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

/// 执行一组操作；任一失败即 Err（调用方据此把整条优化项报失败）
pub fn execute(ops: &[PsOp]) -> Result<(), String> {
    for op in ops {
        exec_one(op)?;
    }
    Ok(())
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

fn exec_one(op: &PsOp) -> Result<(), String> {
    match op {
        PsOp::KeyCreate { hive, subkey } => {
            if native::reg_key_ensure(hive_handle(*hive), subkey) {
                Ok(())
            } else {
                Err(format!("创建注册表键失败: {subkey}"))
            }
        }
        PsOp::KeyRemove { hive, subkey, recurse } => {
            if native::reg_key_remove(hive_handle(*hive), subkey, *recurse) {
                Ok(())
            } else {
                Err(format!("删除注册表键失败: {subkey}"))
            }
        }
        PsOp::ValueWrite { hive, subkey, name, kind, data } => {
            if native::reg_restore_write(hive_handle(*hive), subkey, name, kind_of(*kind), data) {
                Ok(())
            } else {
                Err(format!("写注册表值失败: {subkey}\\{name}"))
            }
        }
        PsOp::ValueRemove { hive, subkey, name } => {
            if native::reg_restore_delete(hive_handle(*hive), subkey, name) {
                Ok(())
            } else {
                Err(format!("删注册表值失败: {subkey}\\{name}"))
            }
        }
        PsOp::SvcStop { name } => native::service_stop_pub(name),
        PsOp::SvcSetStart { name, start } => native::service_set_start_pub(name, *start),
        PsOp::TaskChange { path, name, disable } => native::task_change(path.as_deref(), name, *disable),
        PsOp::GuardedKeyExists { hive, subkey, ops } => {
            // 键不存在 = 功能没装，跳过（对齐 PS `if (Test-Path …)` 语义）
            if !native::reg_key_exists(hive_handle(*hive), subkey) {
                return Ok(());
            }
            for o in ops {
                exec_one(o)?;
            }
            Ok(())
        }
    }
}

/// 解析一个 pwsh 步骤体 → 操作列表；**任何不认识的构造都 Err**（调用方回退 PS）
pub fn compile(body: &str) -> Result<Vec<PsOp>, String> {
    parse_block(body, &mut std::collections::HashMap::new())
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

    /// fail-closed 是本模块的**第一原则**：不认识的构造必须 Err，绝不猜。
    #[test]
    fn rejects_unknown_constructs() {
        // 管道里不是 Out-Null（需要真求值）
        assert!(compile("Get-ChildItem HKLM:\\X | Where-Object { $_.Name }").is_err());
        // 依赖展开的双引号串
        assert!(compile("New-ItemProperty -Path \"HKLM:\\$env:x\" -Name A -Value 1 -PropertyType DWord -Force").is_err());
        // 未赋值的变量
        assert!(compile("New-ItemProperty -Path $undef -Name A -Value 1 -PropertyType DWord -Force").is_err());
        // 未知 cmdlet
        assert!(compile("Get-AppxPackage -Name X | Remove-AppxPackage").is_err());
        // -Force 缺失（键已存在时 PS 语义不同）
        assert!(compile("New-ItemProperty -Path 'HKCU:\\X' -Name A -Value 1 -PropertyType DWord").is_err());
        // 引号不闭合
        assert!(compile("$p = \"HKLM:\\X").is_err());
        // 变量出现在参数值之外
        assert!(compile("$a = Get-Service").is_err());
    }

    /// **数据驱动覆盖度量**：把优化项数据层里的全部 pwsh 步骤喂给解释器，
    /// 报告有多少能原生执行、多少仍需回退 PS。
    ///
    /// 只打印不断言具体数值 —— 数据层会随版本演进，硬钉数字会让下一次增删项误红。
    /// 真正要守住的是上面的 fail-closed 测试：**这里绝不允许出现「解析成功但语义存疑」**。
    /// 覆盖率报告同时写进 `tools/categorize-ps-steps.mjs` 的口径（人工比对用）。
    #[test]
    fn data_layer_coverage_report() {
        const OPTIONS_JSON: &str = include_str!("../../data/optimizer-runtime.json");
        let opts: Vec<serde_json::Value> =
            serde_json::from_str(OPTIONS_JSON).expect("optimizer-runtime.json 合法");
        let mut total = 0usize;
        let mut native_ok = 0usize;
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
                            native_ok += 1;
                            // 解析成功的不许是空操作集（空集 = 静默没执行，比 Err 更糟）
                            assert!(!ops.is_empty(), "{id} [{phase}#{i}] 解析成空操作集");
                        }
                        Err(reason) => fallback.push(format!("{id} [{phase}#{i}] {reason}")),
                    }
                }
            }
        }
        println!("\n=== B11 pwsh 原生解释器覆盖（数据层实测） ===");
        println!("总 pwsh 步骤: {total}");
        println!("可原生执行  : {native_ok}（{:.0}%）", 100.0 * native_ok as f64 / total.max(1) as f64);
        println!("仍回退 PS   : {}", fallback.len());
        for f in &fallback {
            println!("  - {f}");
        }
        // 唯一硬性断言：回退理由必须全部非空（不认识就是不认识，不许给空理由）
        assert!(fallback.iter().all(|f| !f.is_empty()));
    }
}
