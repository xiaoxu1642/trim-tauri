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
//! 已知局限（与原实现一致）：符号链接/junction 不解析；相对路径各自按 CWD 解析。
//!
//! **注册表面另起一套**（见文件末尾「注册表禁删面」小节）：清理域历史上的 `excludeKeys`
//! 字段在执行侧没有过滤逻辑，已被 `check-cleanup-rule-contract.mjs` 禁用，注册表保护
//! 此前实际为空 —— 卸载残留规则库的 `reg_key` 走 `RegDeleteTreeW` 递归删树，一条
//! `HKLM\SOFTWARE` 就能端掉系统配置，故必须在结构上封死（方案 §4.1 实锤）。

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
///
/// v2-L4P-17（B-3）：UNC 的 **share 之后的体必须保留**并参与折叠——旧实现返回空体，
/// `\\srv\pub\Windows\System32` 会被塌成 `\\srv\pub`：受保护根若登记在 share 深处
/// （如企业文件夹重定向的 `\\srv\home$\user\Desktop`），塌短后的目标不再命中任何根
/// ⇒ protected→unprotected 翻转。JS 权威实现（ps-protect-path.js normalizeForCompare）
/// 历来保留完整 UNC 体，本函数对齐后三端口径一致（PS 模板由同一权威生成）。
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
            let body = parts[2..].join("\\");
            return (format!("\\\\{}\\{}", parts[0], parts[1]), body);
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
///
/// ⚠️ 盘符相对形态（`\Foo`，2026-10-04 审计 §4.10）：Rust `Path::is_absolute` 对它
/// 判 false ⇒ 这里拼 CWD；而 Windows 枚举/删除语义按「当前盘的根」解析——同一
/// 字符串两侧会算出不同目标。这条分叉**不在本函数修**（本函数的消费输入是各域
/// 已枚举/已展开的路径，把 CWD 拼接改成盘根拼接会波及五个域的比较口径）；
/// 删除链的闭合在共用展开口 `trim_finder::cleanup_scan::expand_glob_dirs` 与
/// `cleanup_execute` 的 fileKey/目录型守卫：盘符相对形态在枚举前就被拒绝并
/// 留痕，永远到不了删除步骤。
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
    // v2-L4P-17（B-3）：`\\?\UNC\` 是设备名形态的 UNC，先还原成 `\\server\share\…`
    // 再走 UNC 分支——无条件剥 4 字符会把 `\\?\UNC\srv\pub\x` 变成相对路径 `UNC\srv\pub\x`
    // 拼上 CWD，受保护根本身是 UNC 时（企业文件夹重定向）即 protected→unprotected。
    // 该形态是三端共有的口径缺口（JS 权威同样如此，vendor 只读不回改）；Tauri 侧
    // 判定统一走本函数，先在执行端收紧，向量进 parity 夹具钉住结论。
    if s.starts_with("\\\\?\\UNC\\") {
        s = format!("\\\\{}", &s[8..]);
    } else if s.starts_with("\\\\?\\") {
        s = s[4..].to_string();
    }
    // 2026-10-04（磁盘清理审计 §3.1）：`\\.\` 与 `\??\` 是**设备路径**，Win32 直接
    // 交给对象管理器、跳过常规路径解析。`\\.\C:\Users\<me>\Documents` 与
    // `C:\Users\<me>\Documents` 是同一棵树，但前者会一路穿过 split_prefix 的 UNC
    // 分支被归一化成字面量 `\\.\c:\users\…`，与任何根都不匹配 ⇒ 判定从
    // 「受保护」翻转成「放行」。本机实测该形态被 OS 承认：
    // `Get-Item -LiteralPath "\\.\$env:TEMP"` 正常返回绝对路径。
    //
    // 选**拒绝**而不是归一化：设备路径里还有 `\\.\PIPE\…`、`\\.\PhysicalDrive0`
    // 这类根本不按路径语义解释的形态，我们没有能力枚举它们是否安全。
    // 「无法判定 ⇒ 按受保护处理」正是本函数的 fail-closed 契约（`!n.ok` 即拦）。
    //
    // ⚠️ 与 JS 权威（vendor/upstream-js/src/main/ps-protect-path.js）**刻意分歧**：
    // 那侧同样漏了这两个前缀，但 vendor 只读不回改。沿用本段上一条的既定处置——
    // 「Tauri 侧判定统一走本函数，先在执行端收紧」，向量由本文件下方用例钉住，
    // 不塞进 JS 生成的 parity 夹具（塞进去会与 `matches_js_authority` 打架）。
    if s.starts_with("\\\\.\\") || s.starts_with("\\??\\") {
        return fail();
    }
    // v2-L4P-17（B-3）续：前导 `//`（正斜杠 UNC）。Node `path.win32.resolve` 把两个
    // 前导分隔符（不分方向）都认作 UNC 起点（实测 `//srv/pub/x` → `\\srv\pub\x`），
    // 而 Rust `Path::is_absolute` 只认反斜杠 ⇒ `//srv/...` 会被当相对路径拼 CWD，
    // 与 JS 权威发散。前置还原对齐三端。
    if s.starts_with("//") {
        s = format!("\\\\{}", &s[2..]);
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

/// 路径（目录或文件）是否落在**系统命名空间**：`%SystemRoot%` 本身或其一棵子树
/// （含 System32 / SysWOW64 / WinSxS —— 它们都住在 SystemRoot 下）。
///
/// v4 审查两处消费方共用此判据，禁止各写一份（§5.16/N6）：
/// - K02（残留扫描/执行）：`is_path_protected` 对 `%WINDIR%` 是 `exact` 语义、管不到
///   子孙，`c:\windows\system32` 会被判「不受保护」——系统目录不得进删除候选；
/// - K01（右键图标资源串 `@C:\…\x.dll,-1`）：白名单外一律不加载 DLL。
///
/// 前缀判定带分隔符（`C:\WindowsApps` 不是 `C:\Windows` 的子树）；不可判（空串 /
/// 取不到系统根）按拒处理（fail-closed）。明确**不覆盖** `%ProgramFiles%` /
/// `%ProgramData%`：那是合法程序安装位置。
pub fn is_system_namespace(p: &str) -> bool {
    let low = p.trim().replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase();
    if low.is_empty() {
        return true;
    }
    let sysroot = env("SystemRoot").replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase();
    if sysroot.is_empty() {
        return true;
    }
    low == sysroot || low.starts_with(&format!("{sysroot}\\"))
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

// ==================== 注册表禁删面（A1） ====================
//
// 为什么单独一套清单：`uninstall_residue_execute` 对 `reg_key` 走的是
// `native::reg_key_remove(hive, subkey, true)` → `RegDeleteTreeW`，**递归删整棵树**，
// 而目标字符串来自「可被外部替换 + 需过验签」的残留规则库 JSON。文件系统面有
// `is_path_protected` 挡着，注册表面此前一个判定都没有（方案 §4.1 的证据链），
// 于是 `{"kind":"reg_key","target":"HKLM\\SOFTWARE"}` 这类规则能通过全部现有门禁、
// 进候选列表、默认勾选并被执行。靠「规则库目前只有几条 sane 规则」「私钥只在发布机」
// 是人工纪律不是代码约束，且残留库一旦接上热更新就会被放大成全网扩散 —— 所以先硬否决。
//
// 三道判定（与文件系统清单的 subtree/exact 对称但更严，勿合并）：
// 1. `REG_SUBTREE_DENY`：目标等于该键**或位于其下** → 拒。用于「下面没有任何一层属于
//    单个产品的残留」的系统命名空间（COM 注册、策略、驱动与安全单元…）。
// 2. `REG_MICROSOFT_ROOTS` 默认拒绝：`…\SOFTWARE\Microsoft` 树下**整棵**属系统命名空间。
//    逐条枚举系统键永远会漏（`…\CurrentVersion\Explorer\Advanced` 这种用户态设置键就不在
//    任何竞品清单里），所以这里按「前缀命中即拒 + 白名单例外」反向表达；例外见
//    `REG_MICROSOFT_LEAF_ALLOW`（其下**再往下一层**是每程序自己的键才放行）。
// 3. `REG_CONTAINER_DENY`：目标等于该键**或其祖先是该键** → 拒。用于「容器本身不许端掉，
//    但容器里的产品叶键是合法残留」，例如 `…\CurrentVersion\Uninstall\<产品键>`。
// 另有 `REG_GENERIC_LEAF` 作横向兜底：末段是 Windows 命名空间名的目标一律拒。
// 刻意**不用**「hive 下至少 N 段」这类深度规则：那会误拒 `HKLM\SOFTWARE\ESET` 这种
// 两段就是产品键的合法目标（方案 §4.3 明确否掉的写法）。
//
// 只覆盖 `reg_key`（递归删树）。`reg_value` 是删单个值且执行前先整父键 export 备份，
// 候选只来自代码内固定反查（MuiCache / 防火墙规则 / BAM，U-2 拍板默认不勾），不经规则库。
// **约束**：`reg_value`/`shortcut` 一旦获准进入签名规则库（方案 Q8 当前为否），本判定
// 必须同时检查父键与值名，不能只比值名。
//
// 清单来源：按本工具实际支持的 HKLM/HKCU 两个 hive 逐项映射竞品保护面（Kudu
// `PROTECTED_DELETE_KEYS`），不是整份搬档；新增条目须同步
// `tools/fixtures/residue-contract.json` 的 `regVectors` 反例（Node 门禁与 Rust 各自
// 独立实现同一套断言，靠夹具钉住，见方案 §4.3 第三步）。

/// 整棵禁删的系统命名空间（已归一：大写、单 `\` 分隔、无首尾空白）
const REG_SUBTREE_DENY: &[&str] = &[
    // HKLM 根下的系统配置单元。`HKLM\SYSTEM` 一条即覆盖 CurrentControlSet\Services、
    // EventLog、FirewallPolicy\FirewallRules、bam\State 等（夹具里有逐条反例证明覆盖到）
    r"HKLM\SYSTEM",
    r"HKLM\SAM",
    r"HKLM\SECURITY",
    r"HKLM\BCD00000000",
    r"HKLM\COMPONENTS",
    r"HKLM\DRIVERS",
    r"HKLM\HARDWARE",
    // COM / 类型库 / MIME / 文件关联：删任意一层都是全局性破坏，不是某个产品的残留
    r"HKLM\SOFTWARE\CLASSES",
    r"HKCU\SOFTWARE\CLASSES",
    // 组策略（HKLM / HKCU / 32 位重定向三份）
    r"HKLM\SOFTWARE\POLICIES",
    r"HKCU\SOFTWARE\POLICIES",
    r"HKLM\SOFTWARE\WOW6432NODE\POLICIES",
    // 已注册应用与客户端命名空间（键与值由系统和浏览器写入）
    r"HKLM\SOFTWARE\CLIENTS",
    r"HKCU\SOFTWARE\CLIENTS",
    r"HKLM\SOFTWARE\REGISTEREDAPPLICATIONS",
    // 图形接口与 ODBC 驱动登记：机器级共享，不归属任何单一产品
    r"HKLM\SOFTWARE\ODBC",
    r"HKLM\SOFTWARE\KHRONOS",
    r"HKLM\SOFTWARE\OPENGL",
    // 用户环境与特殊文件夹指向（D4：环境层只报告不修改）
    r"HKCU\ENVIRONMENT",
    r"HKCU\NETWORK",
    r"HKCU\VOLATILE ENVIRONMENT",
];

/// `…\SOFTWARE\Microsoft` 树下**默认整棵禁删**（自启动 Run/RunOnce、Installer 台账、
/// Shell 扩展与 BHO、FileExts、MountPoints2、字体与 AppCompat 数据库、IFEO、Winlogon、
/// Windows Defender、策略与 WMI 仓库全在这一棵下面 —— 逐条枚举会漏，故反向表达）。
const REG_MICROSOFT_ROOTS: &[&str] = &[
    r"HKLM\SOFTWARE\MICROSOFT",
    r"HKLM\SOFTWARE\WOW6432NODE\MICROSOFT",
    r"HKCU\SOFTWARE\MICROSOFT",
];

/// Microsoft 树下唯一放行的例外：**其下再往下一层**是「每个程序自己的键」的那些容器。
/// 命中条件是「严格位于其下」，所以容器本身（`…\Uninstall`）仍被拒；再往下的
/// `…\Uninstall\<产品键>`、`…\Tracing\<exe>` 才可能放行（末段仍过 GENERIC_LEAF 判定）。
const REG_MICROSOFT_LEAF_ALLOW: &[&str] = &[
    r"HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL",
    r"HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL",
    r"HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL",
    r"HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS",
    r"HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS",
    r"HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS",
    r"HKLM\SOFTWARE\MICROSOFT\TRACING",
    r"HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\TRACING",
];

/// 容器本身及其祖先禁删、**其下产品专属叶键允许**（Microsoft 树外的三大软件根）
const REG_CONTAINER_DENY: &[&str] = &[
    r"HKLM\SOFTWARE",
    r"HKLM\SOFTWARE\WOW6432NODE",
    r"HKCU\SOFTWARE",
];

/// 末段是这些 Windows 命名空间名 → 该目标「只是把大类容器当目标」，不是产品专属叶键。
/// 这是对上面几张清单的横向兜底：清单没枚举到的命名空间容器（第三方厂商键里名叫
/// `Software`、`Classes`、`Tracing` 的）也进不来。比较时去空格 + 大写（`App Paths` → `APPPATHS`）。
const REG_GENERIC_LEAF: &[&str] = &[
    "SOFTWARE",
    "CLASSES",
    "MICROSOFT",
    "WINDOWS",
    "WINDOWSNT",
    "CURRENTVERSION",
    "UNINSTALL",
    "WOW6432NODE",
    "POLICIES",
    "RUN",
    "RUNONCE",
    "RUNONCEEX",
    "RUNSERVICES",
    "INSTALLER",
    "SHELL",
    "EXPLORER",
    "SHELLEXTENSIONS",
    "CONTEXTMENUHANDLERS",
    "BROWSERHELPEROBJECTS",
    "FILEEXTS",
    "AUTOPLAYHANDLERS",
    "MOUNTPOINTS2",
    "USERASSOCIATIONS",
    "WINLOGON",
    "TRACING",
    "FONTS",
    "FONTLINKS",
    "FONTSUBSTITUTES",
    "PROFILELIST",
    "SHAREDLLS",
    "IMAGEFILEEXECUTIONOPTIONS",
    "APPCOMPATFLAGS",
    "CLIENTS",
    "REGISTEREDAPPLICATIONS",
    "ENVIRONMENT",
    "NETWORK",
    "SHELLFOLDERS",
    "USERSHELLFOLDERS",
    "MUICACHE",
    "LOCALSETTINGS",
    "APPPATHS",
];

/// 归一化注册表目标为 `(hive, 子键段)`；hive 只认本工具支持的 HKLM / HKCU 两种写法。
/// 返回 None = 判不出来（未知或裸 hive 之外的写法、空段、`.`/`..`、含 NUL 或换行），
/// 调用方必须按拒绝处理 —— 与 `dir_delete_blocked` 的「读不到属性即拒」同口径。
fn normalize_reg_target(target: &str) -> Option<(String, Vec<String>)> {
    let t = target.trim();
    if t.is_empty() || t.contains('\0') || t.contains('\n') || t.contains('\r') {
        return None;
    }
    // 键名字符集里 '/' 合法，但 RegOpenKeyExW/RegDeleteTreeW 不把它当分隔符，
    // 所以「用 / 改写」只能骗过字符串判定、骗不过真实删除。按分隔符归一后判定只会更严。
    let segs: Vec<String> = t
        .replace('/', "\\")
        .split('\\')
        .map(|s| s.trim().to_uppercase())
        .collect();
    if segs.iter().any(|s| s.is_empty() || s == "." || s == "..") {
        return None;
    }
    let hive = match segs[0].as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => "HKLM",
        "HKCU" | "HKEY_CURRENT_USER" => "HKCU",
        // HKCR / HKU / HKCC / HKPT 等本工具不支持，也一律判不出来（执行侧本就打不开）
        _ => return None,
    };
    Some((hive.to_string(), segs[1..].to_vec()))
}

/// 归一化注册表键路径为 `HIVE\段\段`（大写、单 `\` 分隔、去首尾空白）。
///
/// 与 [`reg_target_block_reason`] 内部的归一化是**同一个实现**（AGENTS §5.16/N6 禁的就是
/// 「看起来等价的两套判据」）：R-2 的启动项窄口子要拿它去比「父键是否恰好是某条 Run 根」，
/// 自己再写一份大写/分隔符折叠，就会造出「A1 判它受保护、窄口子判它合格」这类假一致。
///
/// 返回 `None` = 判不出来（未知 hive、空段、`.`/`..`、含 NUL 或换行）——
/// 调用方必须按拒绝处理（与 `dir_delete_blocked` 的「读不到属性即拒」同口径）。
pub fn canonical_reg_key(target: &str) -> Option<String> {
    let (hive, rest) = normalize_reg_target(target)?;
    if rest.is_empty() {
        return Some(hive);
    }
    Some(format!("{}\\{}", hive, rest.join("\\")))
}

/// 目标是否落在 `…\SOFTWARE\Microsoft` 系统命名空间树内（含 32 位视图与 HKCU 三份）。
///
/// R-2（2026-10-07）用它作**反向兜底**：启动项删值窄口子只开六条 Run/RunOnce 根的具名值，
/// 其余落在 Microsoft 树下的 `reg_value` 目标（例如将来有人把 `RunOnceEx` 也扫进来）
/// 必须继续整棵拒绝 —— 否则「新增一个扫描组」就等于「无声多出一条注册表删除面」。
/// 归一化失败按「在内」处理（fail-closed）。
pub fn reg_in_microsoft_tree(target: &str) -> bool {
    let Some(canon) = canonical_reg_key(target) else {
        return true;
    };
    REG_MICROSOFT_ROOTS
        .iter()
        .any(|m| canon == **m || canon.starts_with(&format!("{m}\\")))
}

/// 注册表删除目标判定：返回 `Some(原因)` = 拒绝递归删除（原因进日志与明细行）。
pub fn reg_target_block_reason(target: &str) -> Option<String> {
    let (hive, rest) = match normalize_reg_target(target) {
        Some(v) => v,
        None => {
            return Some(
                "注册表目标无法判定（hive 只支持 HKLM/HKCU，且不允许空段或 . / ..）".to_string(),
            )
        }
    };
    if rest.is_empty() {
        return Some("注册表根单元（hive）整体禁止删除".to_string());
    }
    let canon = format!("{}\\{}", hive, rest.join("\\"));
    // ① 整棵禁删：等于清单键，或位于清单键之下
    for root in REG_SUBTREE_DENY {
        if canon == *root || canon.starts_with(&format!("{root}\\")) {
            return Some(format!("{canon} 位于系统级注册表单元 {root} 之下（整棵禁删）"));
        }
    }
    // ② Microsoft 树默认拒绝，只放行例外容器**再往下一层**的目标
    if let Some(mroot) = REG_MICROSOFT_ROOTS
        .iter()
        .find(|m| canon == **m || canon.starts_with(&format!("{m}\\")))
    {
        if !REG_MICROSOFT_LEAF_ALLOW
            .iter()
            .any(|a| canon.starts_with(&format!("{a}\\")))
        {
            return Some(format!(
                "{canon} 落在 {mroot} 系统命名空间内（该树默认整棵禁删，只有 Uninstall / App Paths / Tracing 下的产品键放行）"
            ));
        }
    }
    // ③ 容器本身及其祖先禁删（两张表都查祖先，避免依赖「上层容器已枚举全」这一假设）
    for deny in REG_SUBTREE_DENY.iter().chain(REG_CONTAINER_DENY.iter()) {
        if canon == **deny {
            return Some(format!("{canon} 本身是系统级容器键，不得整棵删除"));
        }
        if deny.starts_with(&format!("{canon}\\")) {
            return Some(format!("{canon} 是受保护容器 {deny} 的祖先，删除会端掉整个容器"));
        }
    }
    // ④ 末段是 Windows 命名空间 → 没有产品专属叶段（`HKLM\SOFTWARE\Microsoft` 之类
    //    不因「深度够了」而放行）
    let leaf: String = rest
        .last()
        .map(|s| s.replace(' ', ""))
        .unwrap_or_default();
    if REG_GENERIC_LEAF.contains(&leaf.as_str()) {
        let raw_leaf = rest.last().map(|s| s.as_str()).unwrap_or("");
        return Some(format!("{canon} 的末段「{raw_leaf}」是 Windows 命名空间，不是某个产品的专属键"));
    }
    None
}

/// 对照 `is_path_protected`：true = 受保护（必须拒绝递归删除）
pub fn is_reg_target_protected(target: &str) -> bool {
    reg_target_block_reason(target).is_some()
}

/// 清理域「通配清值」（`value:"*"`）的显式放行清单。
///
/// [`reg_target_block_reason`] 自述管辖语义是**递归删树**，但清理规则库里的 `value:"*"`
/// 是「把该键下所有值一次清空」，爆炸半径与删树同族（`rules.rs` 把两者并称"删树/通配形态"），
/// 所以一并过禁删面。例外只有下面这几条：它们**本身就是 MRU / 显示缓存容器**，清值就是该项
/// 语义的全部，键本身必须留着（删了 Explorer 会重建空键，等于白删）。而 `HKCU\Software\Classes`
/// 整棵在禁删面内 —— 通配清值若也一律拒，`shellMuiCache` 这条内置规则就没有合法写法了。
/// 新增条目要写清为什么不能用具名 `value` —— 否则应该改规则而不是加清单。
const CLEANUP_REG_WIPE_ALLOW: &[&str] = &[
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
    "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
];

/// 清理域 `regKeys` 删除前的禁删面判定 —— **装载侧与执行侧共用这一个函数**
/// （AGENTS §5.16/N6 禁的就是两处各一套判据）。
///
/// `wipe_all_values` = 规则写的是 `value:"*"`；删树（无 `value`）传 false 且**不吃**放行清单。
/// 具名单值删除（`value:"某名"`）不走本函数：它不在禁删面的管辖语义内，且删前整父键 export。
/// 大小写不在此处理 —— `normalize_reg_target` 已把段统一成大写再比对（`contract_tests` 有用例钉）。
pub fn cleanup_reg_wipe_block_reason(target: &str, wipe_all_values: bool) -> Option<String> {
    if wipe_all_values && CLEANUP_REG_WIPE_ALLOW.iter().any(|a| target.eq_ignore_ascii_case(a)) {
        return None;
    }
    reg_target_block_reason(target)
}

// ==================== 与 JS 权威实现的三端同源对拍（cargo test 门禁） ====================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// 夹具由 `node tools/gen-residue-fixture.mjs` 生成（A1 注册表保护 + A2 语义校验共用）。
    const REG_FIXTURE: &str = include_str!("../../../tools/fixtures/residue-contract.json");

    /// A1 与 Node 门禁的对拍：`check-residue-rule-contract.mjs` 用**同一份夹具**跑它自己的
    /// 独立实现（不跨语言调用 Rust）。任一侧口径漂移即红 —— 这是「JS 判拒、Rust 放行」
    /// 这类静默漏防的唯一机器拦截点（AGENTS.md §4：只会打印 ✓ 的断言不算验收）。
    #[test]
    fn reg_vectors_match_shared_fixture() {
        let f: Value = serde_json::from_str(REG_FIXTURE).expect("注册表保护夹具解析失败");
        let vectors = f["regVectors"].as_array().expect("夹具缺 regVectors");
        let mut diff: Vec<String> = Vec::new();
        let mut blocked = 0;
        for v in vectors {
            let target = v["target"].as_str().unwrap();
            let expect = v["blocked"].as_bool().unwrap();
            let got = reg_target_block_reason(target).is_some();
            if got {
                blocked += 1;
            }
            if got != expect {
                diff.push(format!(
                    "{target:?} ({}): 夹具要求{}，Rust 判为{}",
                    v["cls"].as_str().unwrap_or("?"),
                    if expect { "拒绝" } else { "放行" },
                    if got { "拒绝" } else { "放行" }
                ));
            }
        }
        assert!(
            vectors.len() >= 40 && blocked >= 30,
            "夹具向量数 {}（其中拒绝 {blocked}）过少，保护类别覆盖不足",
            vectors.len()
        );
        assert!(diff.is_empty(), "注册表保护判定与夹具不一致：\n{}", diff.join("\n"));
    }

    /// 放行回测单独立一条：这三条是**线上真实规则**用的键，收紧把它们误杀等于把
    /// 卸载残留功能打死（方案 §4.3 要求为当前合法规则建放行回测）。
    #[test]
    fn legit_product_keys_are_not_over_blocked() {
        for t in [
            r"HKLM\SOFTWARE\ESET",
            r"HKLM\SOFTWARE\360Safe",
            r"HKLM\SOFTWARE\Piriform",
            r"HKCU\Software\Tencent\WeChat",
            // 扫描器自身产出的最高置信候选：产品卸载键（Uninstall 容器只禁容器本身）
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VLC media player_is1",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme",
            r"HKLM\SOFTWARE\Microsoft\Tracing\acme_RASAPI32",
        ] {
            assert!(reg_target_block_reason(t).is_none(), "合法目标被误拒: {t}");
        }
    }

    /// 判定必须认得别名与改写：长写法 / 小写 / 斜杠 / 尾随分隔符不得绕过清单。
    #[test]
    fn reg_evasion_shapes_still_blocked() {
        for t in [
            "HKEY_LOCAL_MACHINE\\SOFTWARE",
            "hkey_local_machine\\software\\microsoft",
            "  HKLM\\SOFTWARE  ",
            "HKLM/SOFTWARE/Microsoft",
            r"HKLM\SOFTWARE\",
            r"HKLM\SOFTWARE\.\Microsoft",
            "HKCR\\Acme",
            "HKU\\S-1-5-21-0\\Software",
            "",
            "SOFTWARE\\Acme",
        ] {
            assert!(reg_target_block_reason(t).is_some(), "改写形态未被拒绝: {t:?}");
        }
    }

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

    /// v2-L4P-17（B-3）：UNC 三形态收敛 + 翻转向量回归。
    /// ① `\\?\UNC\` 设备名形态必须还原成 `\\server\share\…`（无条件剥 4 字符会变成
    /// 相对路径拼 CWD）；② split_prefix 必须保留 share 之后的体（塌成 share 根会让
    /// 登记在 share 深处的受保护根被绕过——企业文件夹重定向是真实场景）。
    /// 无 UNC 根时这些目标都应放行（与 parity 夹具同结论），翻转判定用注入根证明。
    #[test]
    fn unc_prefix_forms_converge_and_do_not_flip_protection() {
        // 三种写法归一后必须是同一条路径（与 JS 权威「保留完整 UNC 体」口径一致）
        let a = normalize_for_compare(r"\\srv\pub\Windows\System32");
        let b = normalize_for_compare(r"\\?\UNC\srv\pub\Windows\System32");
        let c = normalize_for_compare("//srv/pub/Windows/System32");
        for n in [&a, &b, &c] {
            assert!(n.ok, "UNC 形态归一失败");
        }
        assert_eq!(a.low, r"\\srv\pub\windows\system32", "plain UNC 体被丢弃: {}", a.low);
        assert_eq!(b.low, a.low, "\\?\\UNC\\ 形态未还原: {}", b.low);
        assert_eq!(c.low, a.low, "正斜杠 UNC 形态不一致: {}", c.low);

        // 翻转向量回归：受保护根本身是 UNC（企业重定向场景）时，share 深处根之下的
        // 目标无论以 plain 还是 \\?\UNC\ 形态提交都必须受保护；share 内根之外的目标放行。
        let r = build_roots(
            &[r"\\srv\home$\user\Desktop".to_string()],
            &[],
            &[],
        );
        assert!(is_path_protected_with(r"\\srv\home$\user\Desktop", &r));
        assert!(is_path_protected_with(r"\\srv\home$\user\Desktop\file.txt", &r));
        assert!(is_path_protected_with(r"\\?\UNC\srv\home$\user\Desktop\file.txt", &r),
            "\\?\\UNC\\ 形态绕过了 UNC 受保护根（protected→unprotected 翻转）");
        assert!(!is_path_protected_with(r"\\srv\pub\other\cache", &r),
            "同 share 根之外的目标被过度保护");
        // 无 UNC 根（默认清单）时：UNC 目标不命中任何本地根，放行（夹具同结论）
        assert!(!is_path_protected_with(r"\\srv\pub\Windows\System32", &roots()));
    }

    /// 2026-10-04 磁盘清理审计 §3.1：设备路径前缀不得翻转保护判定。
    ///
    /// 判据的形状是**同一条路径的两种写法必须同结论**——这比「某个具体输入被拒」
    /// 更强：只要 `\\.\C:\…\Documents` 放行而 `C:\…\Documents` 受保护，就是缺陷，
    /// 不管中间经过了几层归一化。改动归一化实现时这条会自动跟着走。
    #[test]
    fn 设备路径前缀不得把受保护翻成放行() {
        let r = build_roots(
            // 两个都放 subtree 位：extraExact 是**精确**匹配（见 build_roots 语义），
            // 放进去的话 `…\Documents\a.txt` 不命中，基线断言会假失败。
            &[
                r"C:\Users\tester\AppData\Local\Trim".to_string(),
                r"C:\Users\tester\Documents".to_string(),
            ],
            &[],
            &[],
        );
        // 基线：不带前缀的形态必须受保护（否则下面几条的对照无意义）
        assert!(
            is_path_protected_with(r"C:\Users\tester\Documents\a.txt", &r),
            "前提失效：普通形态本身就未被保护，夹具/根构造变了"
        );
        for spelling in [
            r"\\.\C:\Users\tester\Documents\a.txt",
            r"\??\C:\Users\tester\Documents\a.txt",
            r"\\.\C:\Users\tester\AppData\Local\Trim",
            r"\??\C:\Users\tester\AppData\Local\Trim",
        ] {
            assert!(
                is_path_protected_with(spelling, &r),
                "设备路径形态 `{spelling}` 被放行 —— 与不带前缀的同一路径结论相反，\
                 等于用一个前缀同时绕过「永久删除」与「保护清单」两道设计"
            );
        }
        // 归一化层必须判为「无法判定」（fail-closed），而不是归一成了别的路径
        for spelling in [r"\\.\C:\x", r"\??\C:\x", r"\\.\PIPE\foo", r"\\.\PhysicalDrive0"] {
            assert!(
                !normalize_for_compare(spelling).ok,
                "设备路径 `{spelling}` 被归一化成合法路径而不是拒绝 —— \
                 拒绝才是本函数的 fail-closed 契约（`!n.ok` ⇒ 调用方按受保护拦）"
            );
        }
        // 刻意**不**放进 matches_js_authority 的 parity 向量：JS 权威有同一缺口，
        // 塞进去会与 `!js.contains(...)` 打架；分歧与理由记在 normalize_for_compare
        // 的注释里，由本用例钉住 Rust 侧结论。
    }

    /// v4-K02/K01 共用判据：系统命名空间只覆盖 `%SystemRoot%` 子树（含 System32 /
    /// SysWOW64 / WinSxS），前缀必须带分隔符，合法安装位置不误伤，不可判按拒。
    /// 判红自证：把 is_system_namespace 改成恒 false ⇒ 本用例与 residue 的
    /// `classify_residue_op_gates_run_before_any_mutation` 同时红（已实测）。
    #[test]
    fn system_namespace_covers_root_subtree_only() {
        let drive = env("SystemDrive");
        let d = if drive.is_empty() { "C:".to_string() } else { drive.trim_end_matches('\\').to_string() };
        for hit in [
            format!("{d}\\Windows"),
            format!("{d}\\Windows\\System32"),
            format!("{d}\\Windows\\SysWOW64\\x"),
            format!("{d}/Windows/WinSxS"),
            format!("{d}\\Windows\\System32\\shell32.dll"),
        ] {
            assert!(is_system_namespace(&hit), "系统命名空间未拦: {hit}");
        }
        for miss in [
            format!("{d}\\WindowsApps"),
            format!("{d}\\Program Files\\Foo"),
            format!("{d}\\ProgramData\\Foo"),
            format!("{d}\\Apps\\Windows\\Foo"),
        ] {
            assert!(!is_system_namespace(&miss), "合法位置被误拦: {miss}");
        }
        assert!(is_system_namespace(""), "不可判按拒（fail-closed）");
    }
}