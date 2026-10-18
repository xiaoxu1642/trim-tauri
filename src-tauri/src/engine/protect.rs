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
    /// P1-05：凭据文件名模式（小写、'*' 段内通配），按路径每段匹配
    pub never_names: Vec<String>,
}

/// P1-05：凭据文件名默认清单（与 JS 权威 NEVER_NAMES 同源，静态与机器无关）。
/// 范围按用户裁定：`.env`、SSH/GPG、证书、云凭据。
fn default_never_names() -> Vec<String> {
    [
        ".env", ".env.*", "*.env",
        "id_rsa", "id_rsa_sk", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed25519_sk",
        "id_ed448", "id_x25519",
        "*.pem", "*.pfx", "*.p12", "*.key", "*.keystore", "*.jks",
        "*.pgp", "*.gpg", "*.asc",
        "*.kdb", "*.kdbx",
        "*.ovpn",
        ".htpasswd", ".netrc", ".npmrc", ".pypirc",
        "credentials", "credentials.json", "authorized_user.json",
        "service_account*.json", "*azureprofile.json",
        "terraform.tfstate", "terraform.tfstate.*",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// 仅含 `*` 的 glob 与文本是否相等（经典回溯算法，零正则依赖）。
/// `*` = 任意字符（含空）；其余逐字。
fn glob_match(pat: &str, text: &str) -> bool {
    let pb = pat.as_bytes();
    let tb = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti): (Option<usize>, usize) = (None, 0);
    while ti < tb.len() {
        if pi < pb.len() && pb[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if pi < pb.len() && pb[pi] == tb[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pb.len() && pb[pi] == b'*' {
        pi += 1;
    }
    pi == pb.len()
}

/// P1-05：路径任一段（文件名或祖先目录名）是否命中凭据模式。
fn never_name_blocked(low: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    low.split(|c| c == '\\' || c == '/')
        .filter(|s| !s.is_empty())
        .any(|seg| patterns.iter().any(|pat| glob_match(pat, seg)))
}

/// 归一化结果（对照 JS `normalizeForCompare` 的返回形状）
pub struct Norm {
    /// false = 归一化失败 → 调用方必须 fail-closed（判受保护）
    pub ok: bool,
    pub low: String,
    pub drive_root: bool,
    /// 归一化后仍含**无法证伪**的 8.3 短名（`~\d`）→ fail-closed
    /// （整条路径被系统展开成功时不算——那时波浪号是字面文件名，2026-10-12）
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

/// 解析为绝对路径：相对路径按进程 CWD 拼接（对照 JS path.resolve 的 CWD 基准）。
///
/// ⚠️ 盘符相对形态（`\Foo`，2026-10-04 审计 §4.10 曾裁定「不在本函数修」，v5-K02
/// 批次 1 修掉）：Rust `Path::is_absolute` 对它判 false ⇒ 旧实现拼 CWD，而 Win32
/// 枚举/删除语义按「当前盘的根」解析——同一字符串在判定侧与执行侧算出不同目标
/// （实测 `\Windows\System32` 的 `is_dir` = true，JS 权威 `path.win32.resolve`
/// 同样按盘根拼）。R2a 用注册表 `InstallLocation` 原串证伪了「消费输入都是已展开
/// 路径」这一前提：`\Windows\System32` 同时穿过 `is_path_protected` 与
/// `is_system_namespace` 两道闸。改为盘根拼接后三端（判定/执行/JS 权威）同口径。
fn resolve_path(s: &str) -> Option<String> {
    let p = std::path::Path::new(s);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else if s.starts_with('\\') || s.starts_with('/') {
        // 盘符相对：拼当前盘根（SystemDrive 缺失按 C:），与 Win32/JS 权威对齐
        let d = env("SystemDrive");
        let drive = if d.is_empty() { "C:".to_string() } else { d.trim_end_matches('\\').to_string() };
        std::path::PathBuf::from(format!("{drive}{s}"))
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(p),
            // 取不到 CWD 时不拼（旧 path_key 同口径：原串继续参与折叠）
            Err(_) => return Some(s.to_string()),
        }
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

/// 去尾部空白与点号（Win32 路径比较忽略它们）+ 尾分隔符（`C:\` → `C:`，
/// 但 `C:` 本身不被削成空串）。
fn trim_tail(s: &str) -> String {
    let mut t = s.trim_end_matches([' ', '.']).to_string();
    while t.len() > 1 && (t.ends_with('\\') || t.ends_with('/')) {
        t.pop();
    }
    t
}

/// Windows 命名空间形态分类（v6-K02 / P0-1）：归一口径的前置辨识，判据层与比较键层共用。
///
/// 为什么必须先分类再归一：`\\?\` verbatim 前缀下的形态**不全是盘符路径**——
/// `\\?\Volume{GUID}\...` 指向任意卷、`\\?\GLOBALROOT\...` 是内核命名空间别名，
/// 我们没有能力枚举它们折叠成普通盘符串后的真实指向。旧实现无脑剥前缀，剥完
/// `Volume{guid}\dir` 被当相对路径拼 CWD，同一字符串随进程工作目录漂移出不同结果。
enum WinForm {
    /// `\\?\X:\...` verbatim 盘符：OS 承认的同一目录，可折回普通盘符路径。
    VerbatimDrive,
    /// `\\?\UNC\server\share\...` verbatim UNC：可折回 `\\server\share\...`。
    VerbatimUnc,
    /// `\\?\` 下其余形态（Volume{GUID} / GLOBALROOT 等）：不可折回、不可比较。
    VerbatimOther,
    /// `\\.\` / `\??\` 设备路径：跳过常规路径解析，不可比较（2026-10-04 审计 §3.1 既定）。
    Device,
    /// 其余（普通盘符 / 普通 UNC / 相对路径）。
    Plain,
}

fn classify_form(s: &str) -> WinForm {
    if s.starts_with(r"\\?\") {
        let rest = &s[4..];
        // `\\?\UNC\server\share` 才是合法 verbatim UNC；`\\?\UNC` 截断形态按不可折回处理
        if rest.starts_with("UNC\\") && rest.len() > 4 {
            WinForm::VerbatimUnc
        } else if rest.as_bytes().get(1) == Some(&b':') {
            WinForm::VerbatimDrive
        } else {
            WinForm::VerbatimOther
        }
    } else if s.starts_with(r"\\.\") || s.starts_with(r"\??\") {
        WinForm::Device
    } else {
        WinForm::Plain
    }
}

/// 词法归一的**唯一实现**（v5-K02 批次 1 并轨，R6a-M02；v6-K02 / P0-1 拆可辨识形态）。
///
/// 此前仓内有两份词法归一：判据层 [`normalize_for_compare`]（protect）与比较键层
/// [`crate::engine::paths::path_key`]（paths），两者差在「设备路径是否拒 / 尾点尾
/// 空格是否去 / `//` 是否还原 / 盘符相对是否按盘根拼」——同一路径在两个域会算成
/// 两个键（P2-1 收敛掉的病换个位置复发）。本函数收敛为一份，两域共用。
///
/// 口径：
/// - verbatim 盘符 `\\?\C:\...` 折回 `C:\...`；verbatim UNC `\\?\UNC\srv\share\...`
///   折回 `\\srv\share\...`——两者 OS 语义与折回后完全一致，照旧参与折叠；
/// - **不可折回形态**（`\\?\Volume{...}` / `\\?\GLOBALROOT\...` / `\\.\` / `\??\`）
///   只做大小写归并、保留前缀字面直接返回：verbatim 路径 OS 不做任何规范化
///   （`..` 不折叠、`/` 不转换、尾点尾空格保留），键也必须逐字稳定——同形态归并、
///   绝不与普通盘符键塌并（塌并即 K02 穿闸）。是否 fail-closed 由调用方按域定
///   （判据层 [`normalize_for_compare`] 拒，比较键层保留字面键）；
/// - 普通路径：裸盘符按字面键 → 盘符相对按当前盘根、其余相对路径拼 CWD → 拆不可
///   折叠的根前缀（盘符 `X:` 或 UNC `\\server\share`）→ 折叠 `.` / `..` → 统一 `\`
///   → 去尾点尾空格与尾分隔符 → 小写。
///
/// 刻意**不做**的一件事：8.3 短名展开——触盘，只有安全判据需要。
pub fn normalize_lexical(p: &str) -> String {
    let s = p.trim();
    if s.is_empty() {
        return String::new();
    }
    if is_bare_drive(s) {
        return s.to_lowercase();
    }
    match classify_form(s) {
        // v6-K02（P0-1）：不可折回形态——见上方口径，字面键，不做任何组件折叠
        WinForm::VerbatimOther | WinForm::Device => s.to_lowercase(),
        WinForm::Plain => {
            let mut text = s.to_string();
            // 正斜杠 UNC 还原（//srv/pub/x），后续 resolve_path 只认 \ 开头的 UNC
            if text.starts_with("//") {
                text = format!("\\\\{}", &text[2..]);
            }
            let resolved = resolve_path(&text).unwrap_or_else(|| text.clone());
            trim_tail(&resolved).to_lowercase().replace('/', "\\")
        }
        WinForm::VerbatimUnc => {
            // \\?\UNC\srv\share\... → \\srv\share\...（OS 折回语义），其余走普通流程
            let text = format!("\\\\{}", &s[8..]);
            let resolved = resolve_path(&text).unwrap_or_else(|| text.clone());
            trim_tail(&resolved).to_lowercase().replace('/', "\\")
        }
        WinForm::VerbatimDrive => {
            // \\?\C:\... → C:\...（OS 折回语义），其余走普通流程
            let text = s[4..].to_string();
            let resolved = resolve_path(&text).unwrap_or_else(|| text.clone());
            trim_tail(&resolved).to_lowercase().replace('/', "\\")
        }
    }
}

/// 8.3 短名展开（v3.7.2 误杀修复；2026-10-12 二次修正）。返回
/// `Some(展开后的路径)` 或 `None`（展开不掉，调用方 fail-closed）：
///
/// - **整条成功**（GetLongPathName 对全路径成功，结果可与输入**相同**——输入本就
///   无 8.3 组件，`~\d` 是字面文件名）：直接采信。Windows 更新缓存
///   `Package_for_RollupFix~~26100…` 这类合成名此前被「结果与输入相同 ⇒ 视为失败」
///   整批误拒（实测 windowsDownloadCache 33639 个目标全灭）；
/// - **部分成功**（只探明到「最深已存在祖先」，剩余段原样保留）：重建后若**剩余段**
///   仍含 `~\d` 则返回 `None`（无法证明它不是短名 ⇒ fail-closed）；剩余段干净则采信
///   （>MAX_PATH 的长路径走这条，祖先链已被系统整段转成规范名）；
/// - **全失败**（不存在/无权限/API 报错）：`None`。
fn expand_short_path(p: &str) -> Option<String> {
    let b = p.as_bytes();
    if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) {
        return None; // 仅处理本地盘符路径，UNC/相对一律不展开（宁可多拦）
    }
    if let Some(full) = long_path_or_none(p) {
        return Some(full);
    }
    let segs: Vec<&str> = p.split(|c| c == '\\' || c == '/').filter(|c| !c.is_empty()).collect();
    if segs.len() < 2 {
        return None;
    }
    for i in (1..=segs.len() - 1).rev() {
        let head = segs[..i].join("\\");
        let head_has_drive = head.as_bytes().get(1) == Some(&b':');
        let probe = if head_has_drive { head.clone() } else { format!("{}\\{}", segs[0], head) };
        let Some(long) = long_path_or_none(&probe) else { continue };
        let rest = &segs[i..];
        if rest.is_empty() {
            return Some(long);
        }
        let rest_joined = rest.join("\\");
        // 未展开的剩余段带波浪号数字 ⇒ 可能是短名 ⇒ 无法证伪，fail-closed
        if is_short_name(&rest_joined) {
            return None;
        }
        return Some(format!("{}\\{}", long.trim_end_matches(['\\', '/']), rest_joined));
    }
    None
}

/// GetLongPathNameW 包装：成功返回长名，失败返回 None（与 JS realpathSync 失败对称）。
///
/// 2026-10-12：改走 `trim_finder::to_long_path_opt`——原实现把「成功但结果与输入
/// 相同」也折叠成空串（视作失败），把「路径本来就是长名、波浪号是字面名」误判成
/// 「展开不掉」（windowsDownloadCache 33639 个目标被误拒的直接原因，见
/// `expand_short_path` 注释）。底层同一 API、同一缓冲重试逻辑，只是不再吞掉成败之分。
/// 注意行为差异（已登记）：realpathSync.native 还会解析符号链接/junction，
/// GetLongPathNameW 只展开短名。仅当路径含 `~\d` 时才会走到这里，故影响面限于
/// 「短名 + 链接」同时出现的路径，且此种情况仍由剩余段二次判定兜底。
fn long_path_or_none(p: &str) -> Option<String> {
    trim_finder::to_long_path_opt(p)
}

/// 对照 JS `normalizeForCompare`
///
/// v5-K02 批次 1：词法部分收敛到 [`normalize_lexical`]（与 `paths::path_key` 共用），
/// 本函数只保留 protect 域特有的两层——设备路径 fail-closed（判据层安全策略）与
/// 8.3 短名触盘展开，再把结果包成 [`Norm`]。
pub fn normalize_for_compare(p: &str) -> Norm {
    let s0 = p.trim();
    let fail = || Norm { ok: false, low: String::new(), drive_root: false, short_name: false };
    if s0.is_empty() {
        return fail();
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
    // 必须在归一之前判：剥掉 verbatim 前缀后就再也看不出设备路径原形。
    //
    // v6-K02（P0-1）：同一契约扩到全部不可折回形态——`\\?\Volume{GUID}\...` 指向
    // 任意卷、`\\?\GLOBALROOT\...` 是内核命名空间别名，折叠成普通串等于瞎猜指向。
    // 实锤：旧实现把 `\\?\Volume{...}\dir` 剥成相对路径拼 CWD，随进程工作目录
    // 漂移；真实卷 GUID 在 OS 侧完全合法（`Test-Path` 为真），漏判即放行删除。
    // 分类统一收口在 [`classify_form`]，与比较键层同一辨识、两种处置
    // （本层拒，键层保字面键）。
    //
    // ⚠️ 与 JS 权威（vendor/upstream-js/src/main/ps-protect-path.js）**刻意分歧**：
    // 那侧同样漏了这些前缀，但 vendor 只读不回改。沿用本段上一条的既定处置——
    // 「Tauri 侧判定统一走本函数，先在执行端收紧」，向量由本文件下方用例钉住，
    // 不塞进 JS 生成的 parity 夹具（塞进去会与 `matches_js_authority` 打架）。
    if !matches!(
        classify_form(s0),
        WinForm::Plain | WinForm::VerbatimDrive | WinForm::VerbatimUnc
    ) {
        return fail();
    }
    let low0 = normalize_lexical(s0);
    if low0.is_empty() {
        return fail();
    }
    let mut s = low0;
    // 8.3 短名先触盘展开；展开不掉 → fail-closed（与 PS 侧 GetFullPath 之后的判定同位）。
    // 2026-10-12：成败判定收进 expand_short_path 内——整条展开成功即采信（结果可与
    // 输入相同：波浪号是字面名）；只有「仅祖先可展开、剩余段未展开且带波浪号」
    // 才失败。原先的「结果与输入相同即失败」把 Windows 更新缓存的 `~~26100`
    // 合成名整批误拒（实测 33639 个目标全灭），且不再需要事后二次 check。
    if is_short_name(&s) {
        match expand_short_path(&s) {
            Some(ex) => s = trim_tail(&ex).to_lowercase().replace('/', "\\"),
            None => return Norm { ok: false, low: String::new(), drive_root: false, short_name: true },
        }
    }
    if is_bare_drive(&s) {
        return Norm { ok: true, low: s.to_lowercase(), drive_root: true, short_name: false };
    }
    Norm { ok: true, low: s, drive_root: false, short_name: false }
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
        never_names: default_never_names(),
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
    // P1-05：凭据文件名逐段兜底
    if never_name_blocked(&low, &r.never_names) {
        return true;
    }
    false
}

/// Kudu S2（2026-10-16）：删除侧的「解析后最终路径」比较 —— 别名（junction / symlink /
/// 短名目录）指向受保护根时，纯字面比较拦不住。语义 = 在既有字面判定**之上**再加一条：
/// 把路径的**父目录**解析成最终真实路径（`canonicalize` 跟随链接），对解析结果重跑
/// 同一套字面判据；命中即视为受保护。调用点先跑字面版，本函数只做「加拦」，不放宽
/// 任何既有拒绝。
///
/// 为什么解析父目录：① 子树保护语义下，目标落在受保护子树 ⇔ 其父链命中；② 目标自身
/// 是链接的情形已由删除链的 reparse 闸拒绝（本函数不重复承担）；③ 可在外层按父目录 memo。
/// 解析失败（不存在/无权限）→ false：该路径随后必然在删除原语处撞 NotFound/AccessDenied
/// 的真实档，不构成绕过面。
///
/// v6-K02（P0-1）：canonicalize 返回的 verbatim 形态直接交给 [`is_path_protected`]，
/// 由 [`normalize_for_compare`] 统一折回——此处不再私有 strip_prefix。旧写法只剥
/// `\\?\` 不认 `\\?\UNC\`，把 `\\?\UNC\srv\share` 剥成 `UNC\srv\share` 相对串，
/// UNC 备份/共享场景的父目录保护判定整个失明。
pub fn final_path_protected(p: &str) -> bool {
    let Some(parent) = std::path::Path::new(p).parent() else {
        return false;
    };
    let Ok(resolved) = std::fs::canonicalize(parent) else {
        return false;
    };
    is_path_protected(&resolved.to_string_lossy())
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
///
/// v5-K02 批次 1（R2a-K01 / R6a-M01）：入参先过 [`normalize_for_compare`]——此前本
/// 函数只做 trim+小写，`\\?\C:\Windows\System32`（verbatim）、
/// `C:\Program Files\..\Windows\System32`（可折叠 `..`）、`\Windows\System32`
/// （盘符相对）三种同一目录的写法（`GetFileAttributesW` 实测 OS 全部认是目录）
/// 直接穿过本闸，与 `is_path_protected` 之间形成缝。归一失败（设备路径 / 展不掉
/// 的 8.3 短名）按拒处理，与 `is_path_protected` 的 fail-closed 同契约。
/// 系统根本身也过同一归一：env 值可能带尾杠 / 大小写 / verbatim 差异。
pub fn is_system_namespace(p: &str) -> bool {
    let n = normalize_for_compare(p);
    if !n.ok {
        return true;
    }
    let low = n.low;
    if low.is_empty() {
        return true;
    }
    let raw_root = env("SystemRoot");
    if raw_root.is_empty() {
        return true;
    }
    let rn = normalize_for_compare(&raw_root);
    if !rn.ok || rn.low.is_empty() {
        return true;
    }
    low == rn.low || low.starts_with(&format!("{}\\", rn.low))
}

/// 注入 PS / 原生删除的清单 JSON（元素已是归一化小写绝对路径，PS 只做字符串比较）。
/// 键顺序与 JS `JSON.stringify` 一致（subtree/exact/anyDrive），便于双侧对拍逐字节比较。
pub fn protected_roots_json() -> String {
    json_of(&roots())
}

pub fn json_of(r: &ProtectRoots) -> String {
    let arr = |v: &Vec<String>| serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string());
    format!(
        "{{\"subtree\":{},\"exact\":{},\"anyDrive\":{},\"neverNames\":{}}}",
        arr(&r.subtree),
        arr(&r.exact),
        arr(&r.any_drive),
        arr(&r.never_names)
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

        // ③ P1-05/S1：PS 端真实执行结果（psVectors）必须与 JS vectors.protected 逐项一致。
        // psVectors 是生成器实际跑 Windows PowerShell 得到的布尔数组；为 {error} 或缺项即红。
        let ps = f["psVectors"].as_array().expect(
            "夹具缺 psVectors（PS 端未真实执行或执行报错——重跑 node tools/gen-protect-parity.mjs）",
        );
        assert_eq!(ps.len(), f["vectors"].as_array().unwrap().len(),
            "psVectors 条数与 vectors 不符");
        for (i, (pv, v)) in ps.iter().zip(f["vectors"].as_array().unwrap()).enumerate() {
            let got = pv.as_bool().unwrap_or(false);
            let want = v["protected"].as_bool().unwrap();
            assert_eq!(got, want,
                "PS 端第 {i} 项与 JS 分歧（{}）：PS={} JS={}",
                v["p"].as_str().unwrap(), got, want);
        }
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

    /// 2026-10-12：字面波浪号名（Windows 更新缓存 `Package_for_RollupFix~~26100…` 这类
    /// 合成目录名）必须判「可判定」而不是被短名 fail-closed 误拒——修复前该形态
    /// 整批当展开失败（真机实测 windowsDownloadCache 33639 个目标全灭）。
    /// 判红自证：把 expand_short_path 的「整条成功即采信」改回「结果与输入相同即失败」
    /// ⇒ 本用例红（2026-10-12 实测）。
    #[test]
    fn literal_tilde_names_are_not_dropped_as_short_name_failures() {
        let dir = std::env::temp_dir().join(format!("trim-tilde-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Update~~26100.1")).unwrap();
        std::fs::write(dir.join("Update~~26100.1").join("f.txt"), b"x").unwrap();
        let p = dir.join("Update~~26100.1").join("f.txt");
        let n = normalize_for_compare(&p.to_string_lossy());
        assert!(n.ok, "字面波浪号不得被当作短名展开失败（应可判定）: ok={} short_name={}", n.ok, n.short_name);
        assert!(n.low.contains("update~~26100.1"), "归一化结果应保留字面名: {}", n.low);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 反向护栏：真实短名（8.3 别名）必须仍被展开成规范长名——修误拒不能顺手放掉
    /// 别名展开（否则「C:\PROGRA~1」这类别名又成保护面绕过通路）。别名不存在
    /// （卷级 8dot3name 被关）则如实 skip，不炸。判红方式：把 long_path_or_none
    /// 退化为「恒返回输入」⇒ 别名不再展开，规范化断言红。
    #[cfg(windows)]
    #[test]
    fn short_name_aliases_still_expand_to_canonical() {
        if !std::path::Path::new(r"C:\PROGRA~1").exists() {
            eprintln!("SKIP：本机 C: 卷未启用 8.3 短名（PROGRA~1 不存在），本用例未校验");
            return;
        }
        let n = normalize_for_compare(r"C:\PROGRA~1");
        assert!(n.ok, "真实短名必须可展开: short_name={}", n.short_name);
        assert_eq!(n.low, r"c:\program files", "短名别名应展开为规范长名: {}", n.low);
    }

    /// 2026-10-12 真机探针（只读）：真实 Windows 更新缓存路径（`~~26100` 合成名 +
    /// >MAX_PATH 长路径混合）必须判「可判定」且不被保护清单拦。样本缺失如实 skip。
    #[test]
    #[ignore = "真机读 C:\\Windows\\SoftwareDistribution\\Download 真实样本（只读，不删）"]
    fn live_update_cache_paths_are_decidable() {
        fn find_sample(p: &std::path::Path, depth: u32) -> Option<std::path::PathBuf> {
            if depth > 6 { return None; }
            for e in std::fs::read_dir(p).ok()?.flatten() {
                let ep = e.path();
                if ep.is_file() {
                    if ep.to_string_lossy().contains('~') { return Some(ep); }
                } else if ep.is_dir() {
                    if let Some(f) = find_sample(&ep, depth + 1) { return Some(f); }
                }
            }
            None
        }
        let Some(sample) = find_sample(
            std::path::Path::new(r"C:\Windows\SoftwareDistribution\Download"),
            0,
        ) else {
            eprintln!("SKIP：本机无 windowsDownloadCache 样本，探针未校验");
            return;
        };
        let s = sample.to_string_lossy().to_string();
        let n = normalize_for_compare(&s);
        assert!(n.ok, "真实更新缓存路径被误拒: {s}（ok={} short_name={}）", n.ok, n.short_name);
        assert!(!is_path_protected(&s), "更新缓存路径不应命中保护清单: {s}");
        eprintln!("样本通过（{} 字符）：{s} -> {}", s.len(), n.low);
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
        // v5-K02 批次 1（R2a-K01 / R6a-M01）：同一目录的非规范写法必须同样命中。
        // bypass-probe 修前实测：verbatim / 可折叠 `..` / 盘符相对三种形态
        // （`GetFileAttributesW` 实测 OS 全部认是同一目录）本判据全返 false，
        // 与 `is_path_protected` 之间形成缝 ⇒ System32 整棵能进残留删除清单。
        // 判据入口过 `normalize_for_compare` 后闭合。判红自证：把
        // `is_system_namespace` 里的归一调用删掉 ⇒ 本组三条全红。
        for hit in [
            format!(r"\\?\{d}\Windows\System32"),
            format!("{d}\\Program Files\\..\\Windows\\System32"),
            format!("{d}\\Windows\\..\\Windows\\System32"),
            r"\Windows\System32".to_string(), // 盘符相对：按当前盘根解析
            format!(r"\\?\{d}\Windows\System32\drivers\x.sys"),
            format!("{d}\\Windows\\System32\\"),   // 尾分隔符
            format!("{d}\\WINDOWS\\SYSTEM32"),     // 大小写
        ] {
            assert!(is_system_namespace(&hit), "非规范形态逃过系统命名空间判据: {hit}");
        }
        // 设备路径 fail-closed：判不出来 ⇒ 按拒（与 is_path_protected 同契约）
        for form in [r"\\.\C:\Windows", r"\??\C:\Windows"] {
            assert!(is_system_namespace(form), "设备路径必须 fail-closed: {form}");
        }
        assert!(is_system_namespace(""), "不可判按拒（fail-closed）");
    }

    /// v5-K02 批次 1（R6a-M02）：判据层与比较键层共用同一词法归一。
    /// `paths::path_key(p)` 必须等于 `normalize_for_compare(p).low`（非设备路径时）——
    /// 此前两份实现差在设备路径/尾点尾空格/`//`/盘符相对，同一路径算成两个键。
    /// 判红自证：把 path_key 改回独立折叠实现 ⇒ 尾点尾空格或 `//` 用例红。
    #[test]
    fn lexical_normalization_shared_between_judge_and_key() {
        for p in [
            r"C:\Windows\System32",
            r"\\?\C:\Windows\System32",
            r"\\?\UNC\srv\pub\x",
            r"//srv/pub/x",
            r"\\srv\pub\x",
            r"C:\A\B\..\C",
            r"C:/A/B/",
            r"c:\a\b. ",   // 尾点尾空格：Win32 比较时忽略
            r"C:\a\b\",
            r"C:",
        ] {
            let n = normalize_for_compare(p);
            assert!(n.ok, "{p} 应可判定");
            assert_eq!(
                crate::engine::paths::path_key(p),
                n.low,
                "{p} 在判据层与比较键层归一不一致"
            );
        }
        // 两域分工钉住：比较键永不失败（设备路径照旧折叠），判据层 fail-closed
        assert!(
            !normalize_for_compare(r"\\.\C:\x").ok,
            "判据层必须对设备路径 fail-closed"
        );
        assert!(
            !normalize_for_compare(r"\??\C:\x").ok,
            "判据层必须对 \\??\\ 设备路径 fail-closed"
        );
    }

    /// v6-K02（P0-1）：不可折回形态三向断言——判据层 fail-closed、比较键层字面稳定、
    /// 键空间不塌并。判红自证：把 normalize_lexical 的 VerbatimOther/Device 分支改回
    /// 「剥前缀放行」，本用例判据层三条与键塌并两条同时红。
    #[test]
    fn unverbatim_device_forms_fail_closed_and_keep_literal_keys() {
        let volume = r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\Windows\System32";
        let globalroot = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\System32";
        for form in [volume, globalroot] {
            // 判据层：不可比较 ⇒ fail-closed ⇒ 三道闸全拦
            let n = normalize_for_compare(form);
            assert!(!n.ok, "不可折回形态必须判不可比较: {form}");
            assert!(is_path_protected(form), "不可折回形态必须按受保护处理: {form}");
            assert!(is_system_namespace(form), "不可折回形态必须 fail-closed: {form}");
        }
        // 比较键层：保留前缀字面，同形态只做大小写归并
        assert_eq!(
            crate::engine::paths::path_key(volume),
            volume.to_lowercase(),
            "verbatim 键必须逐字稳定"
        );
        assert_eq!(
            crate::engine::paths::path_key(
                r"\\?\VOLUME{12345678-1234-1234-1234-123456789ABC}\WINDOWS\SYSTEM32"
            ),
            crate::engine::paths::path_key(volume),
            "同形态归并必须稳定"
        );
        // 绝不与普通盘符键塌并（K02 穿闸的最终防线）
        assert_ne!(
            crate::engine::paths::path_key(volume),
            crate::engine::paths::path_key(r"C:\Windows\System32"),
            "Volume 键不得塌并到普通盘符键"
        );
        assert_ne!(
            crate::engine::paths::path_key(r"\\?\GLOBALROOT\ArcName\C:"),
            crate::engine::paths::path_key(r"C:\"),
            "GLOBALROOT 不得折成普通盘符键"
        );
        // verbatim 语义：.. 不折叠——字面不同的两串就是两个键
        assert_ne!(
            crate::engine::paths::path_key(
                r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\a\..\b"
            ),
            crate::engine::paths::path_key(r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\b"),
        );
        // 设备路径维持既定 fail-closed；比较键字面保留（不再拼出随 CWD 漂移的荒谬键）
        assert!(!normalize_for_compare(r"\\.\C:\x").ok);
        assert!(!normalize_for_compare(r"\??\C:\x").ok);
        assert_eq!(crate::engine::paths::path_key(r"\\.\C:\x"), r"\\.\c:\x");
    }

    /// v6-K02（P0-1）：verbatim 盘符与 verbatim UNC 保持「可折回」——OS 同一目录、
    /// 判据同结论、键与折回形态一致（fileclean/finder 既有槽键口径不漂移）。
    /// 判红自证：把 VerbatimDrive/VerbatimUnc 分支改成不可折回，本用例全红。
    #[test]
    fn verbatim_drive_and_unc_still_fold_back() {
        for (verbatim, plain) in [
            (r"\\?\C:\Windows\System32", r"C:\Windows\System32"),
            (r"\\?\C:\Windows\..\Windows\System32", r"C:\Windows\System32"),
            (r"\\?\UNC\srv\pub\x", r"\\srv\pub\x"),
        ] {
            let nv = normalize_for_compare(verbatim);
            assert!(nv.ok, "可折回形态必须可判定: {verbatim}");
            assert_eq!(
                nv.low,
                normalize_for_compare(plain).low,
                "{verbatim} 折回后与普通形态不一致"
            );
            assert_eq!(
                crate::engine::paths::path_key(verbatim),
                crate::engine::paths::path_key(plain),
                "{verbatim} 键折回不一致"
            );
        }
        assert!(is_path_protected(r"\\?\C:\Windows"), "verbatim 盘符仍受保护");
    }

    /// v6-K02（P0-1）真机只读探针：真实卷 GUID 形态 OS 完全承认（is_dir 为真），
    /// 判定侧必须仍判不可比较——「OS 认得、我们比不了」正是 fail-closed 的存在理由。
    /// 需要 C: 卷 GUID（GetVolumeNameForVolumeMountPointW）；取不到显式 SKIP 并声明，
    /// 不假绿。判红自证：把 normalize_lexical 的 VerbatimOther 分支改回剥前缀，
    /// 归一拼出随 CWD 漂移的荒谬路径，fail-closed 与键不塌并两条断言双红。
    #[cfg(windows)]
    #[test]
    #[ignore = "真机：真实卷 GUID 形态穿越保护判定（只读，发布前人工跑）"]
    fn live_volume_guid_path_is_os_valid_but_uncomparable() {
        use windows::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW;
        let mount_w: Vec<u16> = "C:\\".encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = [0u16; 64];
        let got = unsafe {
            GetVolumeNameForVolumeMountPointW(
                windows::core::PCWSTR(mount_w.as_ptr()),
                &mut buf,
            )
        };
        if got.is_err() {
            eprintln!("SKIP：本机取不到 C: 卷 GUID（GetVolumeNameForVolumeMountPointW 失败），本节未校验");
            return;
        }
        let end = buf.iter().position(|&w| w == 0).expect("卷 GUID 路径缺 NUL 终止");
        let vol_root = String::from_utf16(&buf[..end]).expect("卷 GUID 路径非合法 UTF-16");
        assert!(
            vol_root.starts_with(r"\\?\Volume{") && vol_root.ends_with('\\'),
            "卷 GUID 形态异常: {vol_root}"
        );
        // OS 承认：卷根下的 Windows 目录真实存在（C 盘卷必有）
        let win_dir = format!("{}Windows", vol_root);
        assert!(
            std::path::Path::new(&win_dir).is_dir(),
            "样本缺失：{win_dir} 不是目录（探针未校验）"
        );
        // 判定 fail-closed：OS 认得 ≠ 我们比得了
        let n = normalize_for_compare(&win_dir);
        assert!(!n.ok, "真实卷 GUID 形态必须判不可比较: {win_dir}");
        assert!(
            is_path_protected(&win_dir),
            "真实卷 GUID 形态必须按受保护处理: {win_dir}"
        );
        assert_ne!(
            crate::engine::paths::path_key(&win_dir),
            crate::engine::paths::path_key(r"C:\Windows"),
            "真实卷 GUID 键塌并到普通盘符键"
        );
        eprintln!("样本通过（{vol_root}）：OS is_dir=true，判定 fail-closed，键不塌并");
    }

    /// v5-K02 批次 1 真机探针（只读）：真实盘上同一系统目录的四种写法
    /// （规范 / verbatim / 可折叠 `..` / 盘符相对）必须全部判「在系统命名空间」，
    /// 合法安装位置不误伤。`%SystemRoot%\System32` 真机必有；不写盘、不改系统。
    /// 判红自证：把 is_system_namespace 的归一删掉 ⇒ verbatim/dotdot/driverel 三条红。
    #[test]
    #[ignore = "真机：真实盘非规范形态穿越 is_system_namespace（只读，发布前人工跑）"]
    fn live_noncanonical_system_paths_are_judged_in_namespace() {
        let root = env("SystemRoot");
        assert!(!root.is_empty(), "SystemRoot 取不到");
        let sys32 = format!("{root}\\System32");
        assert!(
            std::path::Path::new(&sys32).is_dir(),
            "样本缺失：{sys32} 不是目录（探针未校验）"
        );
        for form in [
            sys32.clone(),
            format!(r"\\?\{sys32}"),
            format!(r"{root}\..\Windows\System32"),
            r"\Windows\System32".to_string(),
        ] {
            assert!(is_system_namespace(&form), "形态逃过系统命名空间判据: {form}");
        }
        // 反向：合法安装位置不误拦（Program Files 本身不是系统命名空间）
        let pf = env("ProgramFiles");
        if !pf.is_empty() {
            assert!(!is_system_namespace(&pf), "合法安装位置被误拦: {pf}");
        }
        eprintln!("样本通过（SystemRoot={root}，四形态同结论 + Program Files 不误拦）");
    }

    /// P1-05：glob 匹配的边界 —— 精确、首尾/中段通配、大小写无关靠调用前小写。
    #[test]
    fn glob_匹配覆盖精确与通配() {
        for (pat, text, want) in [
            (".env", ".env", true),
            (".env", "x.env", false),
            ("*.env", "probe.env", true),
            ("*.env", "env", false),
            (".env.*", ".env.local", true),
            (".env.*", ".env", false),
            ("service_account*.json", "service_account_key.json", true),
            ("service_account*.json", "service_account.json", true), // * 含空
            ("*azureprofile.json", "azureProfile.json".to_ascii_lowercase().as_str(), true),
            ("a*b*c", "axxbxxc", true),
            ("a*b*c", "axxcxxb", false),
        ] {
            assert_eq!(glob_match(pat, text), want, "{pat} vs {text}");
        }
    }

    /// P1-05：凭据文件名逐段命中（文件名/祖先目录），近形段不命中。
    #[test]
    fn 凭据文件名逐段兜底() {
        let p = default_never_names();
        // 文件名命中
        assert!(never_name_blocked(r"c:\users\me\.env", &p));
        assert!(never_name_blocked(r"c:\users\me\.ssh\id_rsa", &p));
        assert!(never_name_blocked(r"c:\certs\server.pem", &p));
        assert!(never_name_blocked(r"c:\gcp\service_account_1.json", &p));
        // 祖先目录名命中
        assert!(never_name_blocked(r"c:\proj\.env\lib\x.txt", &p));
        // 近形不命中
        assert!(!never_name_blocked(r"c:\proj\environment\config.json", &p));
        assert!(!never_name_blocked(r"c:\proj\env.local.txt", &p));
        assert!(!never_name_blocked(r"c:\normal\folder\file.txt", &p));
        // 空模式：不拦
        assert!(!never_name_blocked(r"c:\.env", &[]));
    }

    /// P1-05：清单非空且全部为小写（三端同源前提）。
    #[test]
    fn 默认凭据清单形状合法() {
        let p = default_never_names();
        assert!(p.len() >= 25, "清单条数异常: {}", p.len());
        for pat in &p {
            assert!(pat.chars().all(|c| !c.is_ascii_uppercase()), "模式必须小写: {pat}");
            assert!(!pat.contains('?'), "首版只支持 * 通配: {pat}");
        }
    }

    /// P1-05 真机探针：%USERPROFILE% 下造凭据诱饵，断言删除判定全部拦截（含清理/walk 入口）。
    #[test]
    #[ignore = "真机：%USERPROFILE% 下凭据诱饵（自建自清），发布前人工跑"]
    fn live_credential_decoys_blocked() {
        let home = env("USERPROFILE");
        assert!(!home.is_empty(), "USERPROFILE 取不到");
        let dir = std::path::PathBuf::from(format!(r"{home}\chillsweep-decoy-{}", std::process::id()));
        // 兜底清目录（panic 提前返回时也清）
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());

        let files = [
            r"probe.env",
            r".ssh\id_rsa",
            r"certs\server.pem",
            r".aws\credentials",
            r"proj\.env\lib\a.txt",
        ];
        for rel in files {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"decoy").unwrap();
            assert!(is_path_protected(&p.to_string_lossy()),
                "凭据诱饵未被拦截：{}", p.display());
        }
        // 近形普通文件不被拦截（防过度保护）
        let benign = dir.join(r"normal\environment\config.json");
        std::fs::create_dir_all(benign.parent().unwrap()).unwrap();
        std::fs::write(&benign, b"x").unwrap();
        assert!(!is_path_protected(&benign.to_string_lossy()),
            "近形普通文件被过度拦截");
    }

    /// Kudu S2（2026-10-16）：别名解析复检——junction / 短名父目录解析后指向受保护路径
    /// 时必须判拒；指向普通目录不得误报。mklink /J 免管理员；受限环境建不出来就显式 SKIP。
    #[test]
    fn kudu_s2_别名解析后指向受保护路径() {
        // ① 8.3 短名（若可用）：PROGRA~1 的父目录解析后落回 Program Files（exact 根）
        let pf = env("ProgramFiles");
        let pf = if pf.is_empty() { r"C:\Program Files".to_string() } else { pf };
        let drive = &pf[..2];
        if std::fs::symlink_metadata(format!(r"{drive}\PROGRA~1")).is_ok() {
            let probe = format!(r"{drive}\PROGRA~1\x.txt");
            assert!(final_path_protected(&probe), "短名父目录解析后应命中受保护路径: {probe}");
        } else {
            eprintln!("SKIP：本机无 PROGRA~1 短名，短名分支未校验");
        }

        // ② junction 指向受保护子树（%windir%\System32\config = subtree 根）
        let windir = env("WINDIR");
        let target = format!(r"{}\System32\config", if windir.is_empty() { r"C:\Windows".to_string() } else { windir });
        let dir = std::env::temp_dir().join(format!("trim-s2-alias-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());

        let link = dir.join("jlink");
        let ok = std::process::Command::new("cmd")
            .args(["/C", &format!(r#"mklink /J "{}" "{}""#, link.display(), target)])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("SKIP：建 junction 失败（受限环境），junction 分支未校验");
            return;
        }
        let probe = link.join("probe.txt");
        assert!(
            final_path_protected(&probe.to_string_lossy()),
            "junction 指向受保护子树时其下路径必须判受保护"
        );
        // ③ 对照：指向普通目录（temp 自身）的 junction 不得误报
        let link2 = dir.join("jlink2");
        let ok2 = std::process::Command::new("cmd")
            .args(["/C", &format!(r#"mklink /J "{}" "{}""#, link2.display(), dir.display())])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok2 {
            let probe2 = link2.join("sub").join("probe.txt");
            assert!(
                !final_path_protected(&probe2.to_string_lossy()),
                "指向普通目录的 junction 不得被误判受保护"
            );
        }
        // ④ 父目录不存在的路径不误报（解析失败 fail-open 到删除原语的真实档）
        let ghost = dir.join("no-such-dir").join("probe.txt");
        assert!(!final_path_protected(&ghost.to_string_lossy()), "不存在路径不得误报");
    }
}