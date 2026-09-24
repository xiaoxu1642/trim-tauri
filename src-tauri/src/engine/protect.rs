//! 受保护路径清单（C 批安全地基）
//!
//! 逐条移植 `src/main/ps-protect-path.js`（该文件自述为「受保护路径清单的唯一权威实现」）。
//! 为什么必须原样搬：清理脚本要删的路径来自「快照 items」，快照源自**可被外部写入的规则
//! JSON**（在线更新 + 未验签的自定义规则）。也就是说，能改规则文件 = 能让脚本递归删除
//! 任意路径。保护判定必须同时存在于 JS 侧（回收站/删除入口）与 PS 侧（EXECUTE 脚本内），
//! 三端（JS / PS / Rust 原生删除）必须同源，故 Rust 侧照搬同一份语义与同一份清单 JSON。
//!
//! 双语义（勿改回单语义，实测代价见原模块头注释）：
//! - `subtree`：目标 === 根 或 目标在根之下 → 拒。用于「整棵都不许碰」（应用自身数据、
//!   注册表配置单元）。
//! - `exact`  ：目标 === 根 或 根在目标之下（目标是根的祖先）→ 拒。用于「根本身不许端掉、
//!   但里面缓存照删」的容器（系统根、用户内容根）。
//! - `anyDrive`：任意盘符下同名目录整棵受保护（System Volume Information）。
//!
//! 已知局限（与原实现一致）：符号链接/junction 不解析；相对路径各自按 CWD 解析；
//! 注册表条目走独立的 excludeKeys 保护，不在文件系统清单内。

use std::sync::Mutex;


#[derive(Default, Clone)]
pub struct ProtectRoots {
    pub subtree: Vec<String>,
    pub exact: Vec<String>,
    pub any_drive: Vec<String>,
}

/// 归一化结果（对照 JS `normalizeForCompare` 的返回形状）
pub struct Norm {
    /// false = 归一化失败 → 调用方必须 fail-closed（判受保护）
    pub ok: bool,
    pub low: String,
    pub drive_root: bool,
    /// 归一化后仍含 8.3 短名（`~\d`）→ fail-closed
    pub short_name: bool,
}

static ROOTS: Mutex<Option<ProtectRoots>> = Mutex::new(None);

/// reparse point 判定：符号链接、junction、云占位符、NFS/LX 卷、WIM 归档**全部命中**。
///
/// 为什么不用 `file_type().is_symlink()`（审查 L12）：Windows 上 std 只对
/// `IO_REPARSE_TAG_MOUNT_POINT` 与 `_SYMLINK` 两种 tag 返回 true，而
/// `is_symlink=false && is_dir=true` 的非常规 reparse（OneDrive 云占位符等）会被判成
/// 普通目录并**递归进去** —— 那等于穿透到另一块存储上遍历/删除。属性位
/// `FILE_ATTRIBUTE_REPARSE_POINT`(0x400) 严格更强（附录 E 实测口径）。
/// 原生扫描器 `trim_finder::is_reparse` 用的是同一个属性位，此处对齐三端口径（U1）。
#[cfg(windows)]
pub fn is_reparse(md: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub fn is_reparse(md: &std::fs::Metadata) -> bool {
    md.file_type().is_symlink()
}

/// 环境变量取值（Windows 下 std::env::var 本身大小写不敏感，等价 JS 的三写法兜底）
fn env(name: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_default()
}

fn is_short_name(s: &str) -> bool {
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'~' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            return true;
        }
    }
    false
}

fn is_bare_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// 拆出不可折叠的前缀：盘符（`C:`）或 UNC（`\\server\share`），其余为可折叠体。
fn split_prefix(s: &str) -> (String, String) {
    let b = s.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return (s[..2].to_string(), s[2..].to_string());
    }
    if s.starts_with("\\\\") {
        let parts: Vec<&str> = s[2..]
            .split(|c| c == '\\' || c == '/')
            .filter(|c| !c.is_empty())
            .collect();
        if parts.len() >= 2 {
            return (format!("\\\\{}\\{}", parts[0], parts[1]), String::new());
        }
    }
    (String::new(), s.to_string())
}

/// 词法折叠 `.` 与 `..`（不触盘）。对齐 Node `path.resolve` 的折叠行为，
/// 也是「C:\Windows\..\Windows 类写法」不能绕过比较的前提。
fn fold_components(body: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for c in body.split(|c| c == '\\' || c == '/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c == ".." {
            out.pop();
            continue;
        }
        out.push(c);
    }
    out.join("\\")
}

/// 解析为绝对路径：相对路径按当前工作目录拼接（对照 JS path.resolve 的 CWD 基准）。
fn resolve_path(s: &str) -> Option<String> {
    let p = std::path::Path::new(s);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(p)
    };
    let text = abs.to_string_lossy().to_string();
    let (prefix, body) = split_prefix(&text);
    let folded = fold_components(&body);
    if prefix.is_empty() {
        Some(folded)
    } else if folded.is_empty() {
        Some(prefix)
    } else {
        Some(format!("{}\\{}", prefix, folded))
    }
}

/// 8.3 短名展开（v3.7.2 误杀修复）：先整条触盘，末端不存在则退化为
/// 「最深已存在祖先展开 + 保留剩余段」——与 JS `expandShortPathWin` 同策略。
/// 任何一步失败返回空串，由调用方保持 fail-closed。
fn expand_short_path(p: &str) -> String {
    let b = p.as_bytes();
    if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) {
        return String::new(); // 仅处理本地盘符路径，UNC/相对一律不展开（宁可多拦）
    }
    let full = trim_to_long_path(p);
    if !full.is_empty() {
        return full;
    }
    let segs: Vec<&str> = p.split(|c| c == '\\' || c == '/').filter(|c| !c.is_empty()).collect();
    if segs.len() < 2 {
        return String::new();
    }
    for i in (1..=segs.len() - 1).rev() {
        let head = segs[..i].join("\\");
        let head_has_drive = head.as_bytes().get(1) == Some(&b':');
        let probe = if head_has_drive { head.clone() } else { format!("{}\\{}", segs[0], head) };
        let long = trim_to_long_path(&probe);
        if long.is_empty() {
            continue;
        }
        let rest = &segs[i..];
        if rest.is_empty() {
            return long;
        }
        return format!("{}\\{}", long.trim_end_matches(['\\', '/']), rest.join("\\"));
    }
    String::new()
}

/// GetLongPathNameW 包装：成功返回长名，失败返回空串（与 JS realpathSync 失败对称）。
/// 注意行为差异（已登记）：realpathSync.native 还会解析符号链接/junction，
/// GetLongPathNameW 只展开短名。仅当路径含 `~\d` 时才会走到这里，故影响面限于
/// 「短名 + 链接」同时出现的路径，且此种情况仍由下面的二次短名判定兜底。
fn trim_to_long_path(p: &str) -> String {
    let out = trim_finder::to_long_path(p);
    if out == p {
        String::new()
    } else {
        out
    }
}

/// 对照 JS `normalizeForCompare`
pub fn normalize_for_compare(p: &str) -> Norm {
    let mut s = p.trim().to_string();
    let fail = || Norm { ok: false, low: String::new(), drive_root: false, short_name: false };
    if s.is_empty() {
        return fail();
    }
    // `\\?\` 前缀让 Win32 跳过路径解析，必须剥掉再比较，否则可绕过全部判定。
    // UNC（`\\server\share`）不剥。
    if s.starts_with("\\\\?\\") {
        s = s[4..].to_string();
    }
    // 裸盘符必须在 resolve 之前拦下：Node 会把 "C:" 当驱动器相对路径拼上 CWD。
    if is_bare_drive(&s) {
        return Norm { ok: true, low: s.to_lowercase(), drive_root: true, short_name: false };
    }
    let resolved = match resolve_path(&s) {
        Some(v) => v,
        None => return fail(),
    };
    s = resolved;
    // 8.3 短名先触盘展开；展开不掉 → fail-closed（与 PS 侧 GetFullPath 之后的判定同位）
    if is_short_name(&s) {
        let ex = expand_short_path(&s);
        if ex.is_empty() {
            return Norm { ok: false, low: String::new(), drive_root: false, short_name: true };
        }
        s = ex;
    }
    // 去尾部空白与点号（Win32 路径比较会忽略它们）
    let trimmed = s.trim_end_matches([' ', '.']).to_string();
    s = trimmed;
    while s.len() > 1 && (s.ends_with('\\') || s.ends_with('/')) {
        s.pop();
    }
    if is_bare_drive(&s) {
        return Norm { ok: true, low: s.to_lowercase(), drive_root: true, short_name: false };
    }
    let low = s.to_lowercase().replace('/', "\\");
    if is_short_name(&low) {
        return Norm { ok: false, low: String::new(), drive_root: false, short_name: true };
    }
    Norm { ok: true, low, drive_root: false, short_name: false }
}

/// 对照 JS `buildDefaultRoots`（只依赖环境变量，任何进程都能算出同一结果）
pub fn build_default_roots() -> ProtectRoots {
    let drive = {
        let d = env("SystemDrive");
        if d.is_empty() { "C:".to_string() } else { d.trim_end_matches('\\').to_string() }
    };
    let home = {
        // 对照 JS `env('USERPROFILE') || os.homedir()`：USERPROFILE 缺失时退到 HOMEDRIVE+HOMEPATH，
        // 仍取不到则留空——空值会在 norm() 里被丢弃，不会产生 "\Desktop" 这类伪根。
        let h = env("USERPROFILE");
        if !h.is_empty() {
            h
        } else {
            format!("{}{}", env("HOMEDRIVE"), env("HOMEPATH"))
        }
    };
    let appdata = {
        let a = env("APPDATA");
        if a.is_empty() { format!("{}\\AppData\\Roaming", home) } else { a }
    };
    let local_appdata = {
        let l = env("LOCALAPPDATA");
        if l.is_empty() { format!("{}\\AppData\\Local", home) } else { l }
    };
    let windir = {
        let w = env("WINDIR");
        if w.is_empty() { format!("{}\\Windows", drive) } else { w }
    };
    let programdata = {
        let p = env("PROGRAMDATA");
        if p.is_empty() { format!("{}\\ProgramData", drive) } else { p }
    };
    let norm = |list: Vec<String>| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for x in list {
            let n = normalize_for_compare(&x);
            if n.ok && !n.low.is_empty() && !out.contains(&n.low) {
                out.push(n.low);
            }
        }
        out
    };
    let pf = {
        let v = env("ProgramFiles");
        if v.is_empty() { format!("{}\\Program Files", drive) } else { v }
    };
    let pf86 = {
        let v = env("ProgramFiles(x86)");
        if v.is_empty() { format!("{}\\Program Files (x86)", drive) } else { v }
    };
    ProtectRoots {
        subtree: norm(vec![format!("{}\\Trim", appdata), format!("{}\\System32\\config", windir)]),
        exact: norm(vec![
            windir,
            pf,
            pf86,
            programdata,
            home.clone(),
            format!("{}\\Desktop", home),
            format!("{}\\Documents", home),
            format!("{}\\Downloads", home),
            appdata,
            local_appdata,
        ]),
        any_drive: vec!["system volume information".to_string()],
    }
}

/// 启动期补全：Electron 的 known folder 会被注册表/OneDrive 重定向，纯 env 推导覆盖不到。
pub fn configure(extra_subtree: &[String], extra_exact: &[String], extra_any_drive: &[String]) -> ProtectRoots {
    let roots = build_roots(extra_subtree, extra_exact, extra_any_drive);
    *ROOTS.lock().unwrap_or_else(|e| e.into_inner()) = Some(roots.clone());
    roots
}

/// 审查 M13：把「算清单」与「写全局缓存」拆开。
/// 原先 `configure()` 既返回清单又顺手覆盖 `ROOTS`，测试想拿一份扩展清单对拍，
/// 就必然污染同进程里并发跑的其它 protect 断言（它们读的是全局 `ROOTS`）。
/// 纯函数版本供测试与任何「只想要一份清单」的调用方使用，不碰全局状态。
fn build_roots(extra_subtree: &[String], extra_exact: &[String], extra_any_drive: &[String]) -> ProtectRoots {
    let mut roots = build_default_roots();
    for r in extra_subtree {
        let n = normalize_for_compare(r);
        if n.ok && !roots.subtree.contains(&n.low) {
            roots.subtree.push(n.low);
        }
    }
    for r in extra_exact {
        let n = normalize_for_compare(r);
        if n.ok && !roots.exact.contains(&n.low) {
            roots.exact.push(n.low);
        }
    }
    for r in extra_any_drive {
        let nm = r.trim().to_lowercase();
        if !nm.is_empty() && !roots.any_drive.contains(&nm) {
            roots.any_drive.push(nm);
        }
    }
    roots
}

/// 由 Tauri 的 known folder 补全清单（桌面/文档/下载可能被 OneDrive 接管，必须在主进程取真实值）
pub fn configure_from_app<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use tauri::Manager;
    let resolver = app.path();
    let mut exact: Vec<String> = Vec::new();
    for dir in [resolver.desktop_dir(), resolver.document_dir(), resolver.download_dir()] {
        if let Ok(p) = dir {
            exact.push(p.to_string_lossy().to_string());
        }
    }
    // 应用自身数据目录整棵不许碰（AppData 迁移后可能是 %APPDATA%\com.xiaoxu.trim）
    let subtree = vec![crate::engine::paths::app_data_dir().to_string_lossy().to_string()];
    configure(&subtree, &exact, &[]);
}

/// 当前清单（未配置时用环境变量推导的默认清单）
pub fn roots() -> ProtectRoots {
    let mut g = ROOTS.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(build_default_roots).clone()
}

/// 对照 JS `isPathProtected`：返回 true = 受保护（必须拒绝删除）
pub fn is_path_protected(p: &str) -> bool {
    is_path_protected_with(p, &roots())
}

pub fn is_path_protected_with(p: &str, r: &ProtectRoots) -> bool {
    let n = normalize_for_compare(p);
    if !n.ok || n.drive_root {
        return true;
    }
    let low = n.low;
    let bs = '\\';
    // 任意盘符下的同名目录整棵受保护（literal 比较，不走正则——原注释：正则要穿三层转义）
    for nm in &r.any_drive {
        if nm.is_empty() || low.len() < nm.len() + 3 {
            continue;
        }
        let b = low.as_bytes();
        if b.get(1) != Some(&b':') || b.get(2) != Some(&(bs as u8)) {
            continue;
        }
        let tail = &low[3..];
        if tail == nm.as_str() || tail.starts_with(&format!("{}\\", nm)) {
            return true;
        }
    }
    for t in &r.subtree {
        if low == *t || low.starts_with(&format!("{}\\", t)) {
            return true;
        }
    }
    for e in &r.exact {
        if low == *e || e.starts_with(&format!("{}\\", low)) {
            return true;
        }
    }
    false
}

/// 注入 PS / 原生删除的清单 JSON（元素已是归一化小写绝对路径，PS 只做字符串比较）。
/// 键顺序与 JS `JSON.stringify` 一致（subtree/exact/anyDrive），便于双侧对拍逐字节比较。
pub fn protected_roots_json() -> String {
    json_of(&roots())
}

pub fn json_of(r: &ProtectRoots) -> String {
    let arr = |v: &Vec<String>| serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string());
    format!(
        "{{\"subtree\":{},\"exact\":{},\"anyDrive\":{}}}",
        arr(&r.subtree),
        arr(&r.exact),
        arr(&r.any_drive)
    )
}

// ==================== 与 JS 权威实现的三端同源对拍（cargo test 门禁） ====================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// 夹具由 `node tools/gen-protect-parity.mjs` 用 JS 权威实现（ps-protect-path.js）生成：
    /// 含清单 JSON 与 38 条向量的判定结果。任何一处口径漂移都会在这里失败——
    /// 这是「JS 判拒、Rust 放行」这类静默漏防的唯一机器拦截点。
    const FIXTURE: &str = include_str!("../../../tools/fixtures/protect-parity.json");

    #[test]
    fn matches_js_authority() {
        let f: Value = serde_json::from_str(FIXTURE).expect("夹具解析失败");
        let extras = &f["extras"];
        let strvec = |v: &Value| -> Vec<String> {
            v.as_array()
                .map(|a| a.iter().filter_map(|s| s.as_str()).map(String::from).collect())
                .unwrap_or_default()
        };
        // 用纯函数版：测试不得覆盖全局 ROOTS，否则会与同进程并发的其它 protect 断言互相污染
        let roots = build_roots(
            &strvec(&extras["extraSubtree"]),
            &strvec(&extras["extraExact"]),
            &strvec(&extras["extraAnyDrive"]),
        );

        // ① 清单 JSON 逐字节一致（含键顺序，便于双侧对拍）
        assert_eq!(
            json_of(&roots),
            f["rootsJson"].as_str().unwrap(),
            "受保护清单 JSON 与 JS 权威实现不一致"
        );

        // ② 逐向量判定一致
        let mut diff: Vec<String> = Vec::new();
        for v in f["vectors"].as_array().unwrap() {
            let p = v["p"].as_str().unwrap();
            let expect = v["protected"].as_bool().unwrap();
            let got = is_path_protected_with(p, &roots);
            if got != expect {
                diff.push(format!(
                    "{:?}: JS={} Rust={}",
                    p,
                    if expect { "受保护" } else { "放行" },
                    if got { "受保护" } else { "放行" }
                ));
            }
        }
        assert!(diff.is_empty(), "判定口径与 JS 不一致：\n{}", diff.join("\n"));
    }
}