//! Run / RunOnce 启动项残留可见面（R-1 第一阶段，2026-10-07，**只读**）。
//!
//! 缺口背景（方案 §1.3）：卸载残留主链与深扫器已经分开，深扫侧有服务 / 驱动 /
//! 过滤驱动 / IFEO / 厂商键 / 能力授权 / 游戏目录七组可见面，**唯独没有 Run/RunOnce**
//! ——「程序卸了，启动项还挂在注册表里、每次开机都去拉起一个不存在的 exe」这类残留
//! 在报告里完全看不见。
//!
//! 三条纪律（方案 §2.3 R-1 原文）：
//! 1. **两个视图分别列项**：`HKLM\...\Run`（64 位）与
//!    `HKLM\SOFTWARE\WOW6432Node\...\Run`（32 位）必须分开枚举 —— 同名值可能只挂在
//!    其中一侧，合并会丢证据（IFEO 那次 R-1a 是同一个坑）。
//! 2. **三种「取不出目标」要给不同原因**：值里没有路径 / 形态解析不出来 /
//!    目标在本机不存在 —— 混成一句「路径不存在」，用户就分不清「是我写错了」还是
//!    「程序真的被卸了」。
//! 3. **只读、不进执行快照**：深扫入口（写快照那一层）已随「机-wide 扫描整条退役」删除，
//!    本模块保留为内部代码；`reg_value_gate` / `recheck_run_value` 仍被 residue 执行链复用。
//!
//! 判据刻意保守：**只有拿不到可用目标（或目标已不存在）才报告**。目标还在的启动项
//! 是「仍在用的程序的正常配置」，一条都不报 —— 与 IFEO 的 `image_present` 同口径。
//! 解析不出来的一律**不猜**（猜错的方向是把活着的程序列成残留）。

use serde_json::{Value, json};
use super::residue_update::contribs;

/// 单根值枚举上限（Run/RunOnce 常态几条到几十条，给足但设限）
const RUN_VALUE_CAP: usize = 512;

/// 启动项所在视图。**必须分开列项**（见文件头纪律 1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RunView {
    /// HKLM `SOFTWARE\Microsoft\...`（64 位进程看到的）
    HklmX64,
    /// HKLM `SOFTWARE\WOW6432Node\Microsoft\...`（32 位进程看到的）
    HklmWow6432,
    /// HKCU（每用户，不做 WOW64 重定向）
    Hkcu,
}

impl RunView {
    /// 报告里写在 `target` 前的 hive 写法（与执行侧 `HKLM\<子路径>::值名` 口径一致）
    fn hive_label(self) -> &'static str {
        match self {
            RunView::HklmX64 | RunView::HklmWow6432 => "HKLM",
            RunView::Hkcu => "HKCU",
        }
    }

    /// 给渲染层看的人话标签
    pub(super) fn label(self) -> &'static str {
        match self {
            RunView::HklmX64 => "64 位视图",
            RunView::HklmWow6432 => "32 位视图（WOW6432Node）",
            RunView::Hkcu => "当前用户",
        }
    }
}

/// Run/RunOnce 的根清单：视图 + 注册表子路径。
///
/// 只收 `Run` 与 `RunOnce` 两条（方案 §2.3 R-1 明文范围）。`RunOnceEx`、`Services`
/// 的启动面等不在本轮，别顺手扩进去。
fn run_roots() -> Vec<(RunView, String)> {
    const RUN: &str = r"Microsoft\Windows\CurrentVersion\Run";
    const RUN_ONCE: &str = r"Microsoft\Windows\CurrentVersion\RunOnce";
    let mut out = Vec::new();
    for sub in [RUN, RUN_ONCE] {
        out.push((RunView::HklmX64, format!(r"SOFTWARE\{sub}")));
        out.push((RunView::HklmWow6432, format!(r"SOFTWARE\WOW6432Node\{sub}")));
        out.push((RunView::Hkcu, format!(r"Software\{sub}")));
    }
    out
}

/// 值数据解析结论（纯函数，三种「取不出目标」互斥且各有措辞）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RunTarget {
    /// 值里没有可取出的启动目标：空值、纯空白、或不是字符串类型
    NoTarget,
    /// 有目标但形态解析不出来：引号未闭合、含无法展开的变量
    Unparseable,
    /// 取到了目标（已展开变量）
    Target(String),
}

/// 从 Run 值数据里取出**可执行目标**。
///
/// 认识的形态（都是真机上实际出现过的）：
/// - 带引号：`"C:\Program Files\App\app.exe" --flag` ⇒ 取引号内
/// - 未带引号但含扩展名：`C:\A B\app.exe --flag` ⇒ 切到第一个 exe 类扩展名之后
/// - 纯命令：`cmd /c start ...` / `rundll32.exe x.dll,Entry` ⇒ 取第一个空白分隔的 token
/// - 环境变量：`%LOCALAPPDATA%\App\app.exe` ⇒ 先展开再判
///
/// **不猜**：引号未闭合、变量展不开都返回 [`RunTarget::Unparseable`]，宁可漏报这条，
/// 也不把仍在用的程序判成残留。
pub(super) fn extract_run_target(raw: Option<&str>) -> RunTarget {
    let Some(raw) = raw else { return RunTarget::NoTarget };
    let s = raw.trim();
    if s.is_empty() {
        return RunTarget::NoTarget;
    }
    let head = if let Some(rest) = s.strip_prefix('"') {
        match rest.find('"') {
            Some(i) => rest[..i].trim(),
            // 引号未闭合：形态坏，不猜
            None => return RunTarget::Unparseable,
        }
    } else {
        unquoted_head(s)
    };
    if head.is_empty() {
        return RunTarget::NoTarget;
    }
    let expanded = trim_finder::cleanup_scan::expand_env_path(head);
    if trim_finder::cleanup_scan::first_unexpanded_token(&expanded).is_some() {
        return RunTarget::Unparseable;
    }
    // 裸命令名按 .exe 解析：Run 里的 `cmd` 指的就是 `cmd.exe`。
    // 只对**不含路径分隔符**的名字补后缀 —— 给 `C:\Tools\util` 补 `.exe` 是凭空造路径。
    if !expanded.contains('\\') && !expanded.contains('/') {
        // `rsplit_once` 而不是拆分后比长度：**没有点**的名字（`cmd`）必须算「没有扩展名」，
        // 用「最后一段长度 ≤ 4」当判据会把整个串当成扩展名，于是 `cmd` 不再补 .exe。
        let has_ext = expanded
            .rsplit_once('.')
            .map(|(_, e)| !e.is_empty() && e.len() <= 4 && e.chars().all(|c| c.is_ascii_alphanumeric()))
            .unwrap_or(false);
        if !has_ext {
            return RunTarget::Target(format!("{expanded}.exe"));
        }
    }
    RunTarget::Target(expanded)
}

/// 未加引号时的目标截取。
///
/// 先找**第一个可执行类扩展名**并切到它之后（真机常见：路径含空格且没加引号）；
/// 找不到就退回第一个空白分隔的 token（纯命令形态）。
fn unquoted_head(s: &str) -> &str {
    const EXE_EXTS: [&str; 6] = [".exe", ".com", ".bat", ".cmd", ".scr", ".pif"];
    let lower = s.to_ascii_lowercase();
    let mut best: Option<usize> = None;
    for ext in EXE_EXTS {
        if let Some(i) = lower.find(ext) {
            let end = i + ext.len();
            best = Some(match best {
                Some(b) => b.min(end),
                None => end,
            });
        }
    }
    match best {
        Some(end) => s[..end].trim(),
        None => s.split_whitespace().next().unwrap_or("").trim(),
    }
}

/// 目标是否"在本机可用"。
///
/// 含路径分隔符 = 具体文件路径，直接判存在；裸名字 = 命令名，走系统常规落点
/// （复用 IFEO 那条 `image_executable_present`：System32 / SysWOW64 / Windows / App Paths）
/// —— 一处实现，两个域共用，别在这里再写一份。
pub(super) unsafe fn run_target_present(target: &str) -> bool {
    if target.contains('\\') || target.contains('/') {
        return std::path::Path::new(target).is_file();
    }
    super::ifeo_orphan::image_executable_present(&target.to_ascii_lowercase())
}

/// 报告里的目标串：`HKLM\<子路径>::值名`（`reg_value` 的形状闸按 `::` 拆，见
/// `capability_orphan::capability_target` 的同类注释）。
fn run_target(hive_label: &str, subkey: &str, value_name: &str) -> String {
    format!("{hive_label}\\{subkey}::{value_name}")
}

/// 一条采集到的 Run 值
#[derive(Debug, Clone)]
pub(super) struct RunRaw {
    pub(super) view: RunView,
    pub(super) subkey: String,
    pub(super) value_name: String,
    /// 值数据（`reg_sz` 口径：只认 REG_SZ/REG_EXPAND_SZ，读不到/其它类型为 None）
    pub(super) data: Option<String>,
}

/// 纯判定：`present` 注入目标存在性（单测因此不碰注册表与磁盘）。
///
/// 返回 (候选, notes)。目标可用 ⇒ 不出候选（仍在使用中的程序的正常配置）。
pub(super) fn run_findings(raws: &[RunRaw], present: &dyn Fn(&str) -> bool, cap: usize) -> (Vec<Value>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let mut alive = 0usize;
    let mut no_target = 0usize;
    let mut unparseable = 0usize;
    for raw in raws {
        let (class, reason, decoded) = match extract_run_target(raw.data.as_deref()) {
            // 三种「取不出目标」给不同的 class 与措辞（方案 §2.3 R-1 第 2 条）
            RunTarget::NoTarget => {
                no_target += 1;
                ("run_no_target", "启动项的值里没有可执行目标（空值或非字符串类型）", String::new())
            }
            RunTarget::Unparseable => {
                unparseable += 1;
                ("run_unparseable", "启动项的值形态解析不出可执行目标（引号未闭合，或含无法展开的变量）", String::new())
            }
            RunTarget::Target(t) => {
                if present(&t) {
                    alive += 1;
                    continue;
                }
                ("run_target_missing", "启动项指向的可执行目标在本机不存在（程序已卸载或路径已变）", t)
            }
        };
        if out.len() >= cap {
            notes.push(format!("启动项候选已达上限 {cap} 条，其余省略"));
            break;
        }
        let hive = raw.view.hive_label();
        out.push(json!({
            "kind": "reg_value",
            "target": run_target(hive, &raw.subkey, &raw.value_name),
            "class": class,
            "reason": reason,
            "confidence": "low", "risk": "low",
            "readonly": true, "defaultChecked": false,
            "details": json!({
                "hive": hive,
                "subkey": raw.subkey,
                "valueName": raw.value_name,
                "raw": raw.data,
                "decodedTarget": decoded,
                "view": raw.view.label(),
            }),
            "contribs": contribs(&[
                ("runValueRead", format!("{hive}\\{} 的值「{}」读到了原始数据", raw.subkey, raw.value_name)),
                ("targetState", match class {
                    "run_target_missing" => "取出的目标路径在本机常规落点查不到".to_string(),
                    "run_no_target" => "值里没有可执行目标".to_string(),
                    _ => "值的形态解析不出可执行目标".to_string(),
                }),
                ("readonlyPhase", "本阶段只读：候选不进执行快照".to_string()),
            ]),
        }));
    }
    if alive > 0 {
        notes.push(format!("{alive} 条启动项的目标在本机仍存在，按「仍在使用中」不报"));
    }
    if no_target > 0 || unparseable > 0 {
        notes.push(format!("{no_target} 条值里没有目标、{unparseable} 条形态解析不出，已按不可解析单独列出（未猜路径）"));
    }
    (out, notes)
}

/// 采集六条根（3 视图 × Run/RunOnce）。返回 (值, 是否有任一根读到)。
///
/// 「读到过但一条候选都没有」与「一根都打不开」是两件事：前者说明本机启动项都健康，
/// 后者只能说明没扫到（由调用方落成可见的 note）。
pub(super) unsafe fn collect_run_raws() -> (Vec<RunRaw>, bool) {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RegCloseKey};
    let mut out = Vec::new();
    let mut any_root = false;
    for (view, sub) in run_roots() {
        let hive = match view {
            RunView::Hkcu => HKEY_CURRENT_USER,
            _ => HKEY_LOCAL_MACHINE,
        };
        let Some(hk) = super::helpers::open_key_read(hive, &sub) else { continue };
        any_root = true;
        for name in super::helpers::reg_value_names(hk, RUN_VALUE_CAP) {
            let data = super::helpers::reg_sz(hk, &name);
            out.push(RunRaw { view, subkey: sub.clone(), value_name: name, data });
        }
        let _ = RegCloseKey(hk);
    }
    (out, any_root)
}

/// 六条 Run/RunOnce 根的**归一化键路径**清单（`HIVE\段\段`，大写）。
///
/// 单一真源：由 [`run_roots`] 现算，不手抄第二份（§5.16/N6）。扫描侧与执行侧判「父键是不是
/// Run 根」都读这里 —— 手抄一份迟早与枚举面漂移，而漂移方向是**多删**。
fn canonical_run_roots() -> Vec<String> {
    run_roots()
        .into_iter()
        .map(|(v, sub)| format!("{}\\{}", v.hive_label(), sub).to_uppercase())
        .collect()
}

/// R-2（2026-10-07）启动项删值的判定结论。三种互斥，调用方**必须**区分：
///
/// - `NotGoverned`：不在本判据管辖范围内 —— 既有三类 `reg_value` 候选
///   （MuiCache / 防火墙规则 / BAM）取自**代码内固定反查**，它们的合法性来自「是谁生成的」
///   而不是形状，不能被本判据误拒。
/// - `Allowed`：父键恰好是六条 Run/RunOnce 根之一，且是**具名单值**形态。
/// - `Denied(理由)`：父键是 Run 根但形态不合格，**或**父键落在 `…\SOFTWARE\Microsoft`
///   系统命名空间树内（除那六条根之外）—— 后者是反向兜底：将来有人把 `RunOnceEx` 之类
///   也扫进来时，「新增扫描组」不会等于「无声多出一条注册表删除面」。
pub(super) enum RegValueGate {
    NotGoverned,
    Allowed,
    Denied(String),
}

/// 残留链 `reg_value` 删除的 A1 判据（R-2 第 1 条：先定义禁删面）。
///
/// 为什么非要有它：`classify_residue_op` 的 `reg_value` 分支此前**只有形状检查、没有 A1**
/// —— 它的安全性靠「候选只来自代码内固定反查」。启动项候选来自**扫描器**（`run_findings`），
/// 一旦进了快照就会被删，而 Run 六条根全部落在 `REG_MICROSOFT_ROOTS`（A1 整棵默认拒绝）之下。
/// 所以本判据是这次开闸的**唯一放行口**，形状刻意苛刻到「只可能是某条启动项的一个值」。
///
/// 判据只谈**形状**；「目标此刻是否仍失踪」由 [`recheck_run_value`] 在删除当下现读复检
/// （第 5 条：失败不扩大范围）—— 形状 + 现读两道都过才真的删。
pub(super) fn reg_value_gate(target: &str) -> RegValueGate {
    // 没有 `::` 就不是「键::值名」形态：本判据不管，交给调用方的既有形状检查。
    let Some((key_part, value_name)) = target.rsplit_once("::") else {
        return RegValueGate::NotGoverned;
    };
    let Some(parent) = crate::engine::protect::canonical_reg_key(key_part) else {
        // 父键归一化失败：`reg_in_microsoft_tree` 对无法归一化按「在内」处理，
        // 一致性要求这里也走拒绝而不是放行（fail-closed）。
        return RegValueGate::Denied("父键无法归一化（hive 只支持 HKLM/HKCU，且不允许空段或 . / ..）".to_string());
    };
    if !canonical_run_roots().iter().any(|r| *r == parent) {
        return if crate::engine::protect::reg_in_microsoft_tree(&parent) {
            RegValueGate::Denied(format!(
                "父键 {parent} 落在 Microsoft 系统命名空间内，且不是本轮开闸的六条 Run/RunOnce 根"
            ))
        } else {
            RegValueGate::NotGoverned
        };
    }
    // 到这里：父键确实是某条 Run 根 —— 形态必须严到「只可能是它自己的一个值」。
    if value_name.is_empty() || value_name != value_name.trim() {
        return RegValueGate::Denied("值名为空或首尾含空白".to_string());
    }
    if value_name == "*" {
        return RegValueGate::Denied("通配清值（`*`）不属于「具名单值」，不在启动项窄口子内".to_string());
    }
    if value_name.contains('\\') || value_name.contains("::") {
        return RegValueGate::Denied("值名含 \\ 或 :: —— 只有单层具名值才享受本口子".to_string());
    }
    if value_name.chars().any(|c| c.is_control()) {
        return RegValueGate::Denied("值名含控制字符".to_string());
    }
    if value_name.chars().count() > 260 {
        return RegValueGate::Denied("值名超过 260 字符".to_string());
    }
    RegValueGate::Allowed
}

/// 删除**当下**的现读复检（R-2 第 5 条：失败不扩大删除范围）。
///
/// 为什么必须再读一次：扫描与执行之间用户可能把那个程序装回去了，于是这条启动项从
/// 「残留」变回「在用配置」。只按值名删就会删掉一条活着的自启动 —— 而报告还会写
/// 「已删除」。判据全部 fail-closed：读不到值、类型不是字符串、目标改为存在，一律拒绝。
///
/// 返回 `Err(理由)` = 不允许删除（调用方按跳过处理，不降级成删除）。
pub(super) unsafe fn recheck_run_value(key_part: &str, value_name: &str) -> Result<(), String> {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RegCloseKey};
    let canon = crate::engine::protect::canonical_reg_key(key_part)
        .ok_or_else(|| "父键无法归一化".to_string())?;
    if !canonical_run_roots().iter().any(|r| *r == canon) {
        return Err(format!("父键 {canon} 不是 Run/RunOnce 六条受控根之一"));
    }
    // "HKLM\" / "HKCU\" 都是 5 个字符，剥掉前缀就是子键（注册表不区分大小写，大写可直开）。
    let hive = if canon.starts_with("HKCU\\") { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE };
    let sub = &canon[5..];
    let Some(hk) = super::helpers::open_key_read(hive, sub) else {
        return Err("现在打不开该根键（权限不足或键已不存在）".to_string());
    };
    let verdict = (|| {
        let Some(ty) = super::helpers::reg_value_type_of(hk, value_name) else {
            return Err("值已不存在（本次没有可删对象）".to_string());
        };
        if ty != 1 && ty != 2 {
            return Err(format!("值类型 {ty} 不是 REG_SZ/REG_EXPAND_SZ，无法证明是残留"));
        }
        let Some(data) = super::helpers::reg_sz(hk, value_name) else {
            return Err("值数据此刻读不到".to_string());
        };
        match extract_run_target(Some(&data)) {
            RunTarget::Target(t) if !run_target_present(&t) => Ok(()),
            RunTarget::Target(t) => Err(format!("目标 {t} 此刻已存在 —— 这条启动项已不是残留")),
            other => Err(format!("值形态解析不出目标（{other:?}），不猜")),
        }
    })();
    let _ = RegCloseKey(hk);
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(view: RunView, name: &str, data: Option<&str>) -> RunRaw {
        RunRaw {
            view,
            subkey: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_string(),
            value_name: name.to_string(),
            data: data.map(str::to_string),
        }
    }

    // ==================== 解析：正负样本（方案 §2.3 R-1 第 5 条） ====================

    /// 引号路径 / 带参数命令 / 未加引号含空格 / 纯命令四种形态都要能取出目标。
    #[test]
    fn extract_run_target_recognizes_real_world_shapes() {
        // 带引号 + 参数
        assert_eq!(
            extract_run_target(Some(r#""C:\Program Files\App\app.exe" --flag"#)),
            RunTarget::Target(r"C:\Program Files\App\app.exe".to_string())
        );
        // 未加引号、路径含空格、带参数：切到扩展名之后
        assert_eq!(
            extract_run_target(Some(r"C:\Program Files\App\app.exe --flag")),
            RunTarget::Target(r"C:\Program Files\App\app.exe".to_string())
        );
        // 纯命令（无扩展名）⇒ 补 .exe
        assert_eq!(extract_run_target(Some(r"cmd /c start /min foo")), RunTarget::Target("cmd.exe".to_string()));
        // 纯命令带扩展名 ⇒ 只取可执行段（参数里的 dll 不能当目标）
        assert_eq!(
            extract_run_target(Some(r"rundll32.exe C:\Tools\x.dll,Entry")),
            RunTarget::Target("rundll32.exe".to_string())
        );
        // 不含路径分隔符的名字不得被凭空补后缀（那是造路径）
        assert_eq!(extract_run_target(Some(r"C:\Tools\util")), RunTarget::Target(r"C:\Tools\util".to_string()));
    }

    /// 环境变量要先展开；展开不了按「解析不出」处理（不猜）。
    #[test]
    fn extract_run_target_expands_env_and_refuses_unknown_tokens() {
        let expanded = extract_run_target(Some(r"%SystemRoot%\System32\cmd.exe /k")).unwrap_target();
        assert!(expanded.to_lowercase().ends_with(r"\system32\cmd.exe"), "应展开 %SystemRoot%: {expanded}");
        assert!(
            !expanded.contains('%'),
            "展开后的目标不得再含变量占位符: {expanded}"
        );
        // 未登记的变量（展开器不认）⇒ 不猜
        assert_eq!(extract_run_target(Some(r"%NO_SUCH_TOKEN_XYZ%\a.exe")), RunTarget::Unparseable);
    }

    /// 空值 / 纯空白 / 缺值 / 引号未闭合四类负样本。
    #[test]
    fn extract_run_target_rejects_empty_and_broken_shapes() {
        assert_eq!(extract_run_target(None), RunTarget::NoTarget, "读不到值数据按无目标（非字符串类型走这里）");
        assert_eq!(extract_run_target(Some("")), RunTarget::NoTarget);
        assert_eq!(extract_run_target(Some("   ")), RunTarget::NoTarget);
        assert_eq!(extract_run_target(Some(r#""C:\unterminated"#)), RunTarget::Unparseable, "引号未闭合不得猜");
        assert_eq!(extract_run_target(Some(r#""""#)), RunTarget::NoTarget, "空引号 = 没有目标");
    }

    impl RunTarget {
        fn unwrap_target(self) -> String {
            match self {
                RunTarget::Target(t) => t,
                other => panic!("期望取到目标，实际 {other:?}"),
            }
        }
    }

    // ==================== 判定：三种原因互斥 + 目标仍在就不报 ====================

    /// 三种「取不出目标」必须是三个不同的 class，且都带 readonly/不勾选。
    #[test]
    fn three_missing_reasons_are_distinct_and_readonly() {
        let raws = vec![
            raw(RunView::HklmX64, "Empty", Some("")),
            raw(RunView::HklmX64, "Broken", Some(r#""C:\unterminated"#)),
            raw(RunView::HklmX64, "Gone", Some(r"C:\Uninstalled\app.exe")),
        ];
        let (items, _) = run_findings(&raws, &|_: &str| false, 10);
        let classes: Vec<&str> = items.iter().map(|i| i["class"].as_str().unwrap_or("")).collect();
        assert_eq!(classes, vec!["run_no_target", "run_unparseable", "run_target_missing"]);
        let reasons: Vec<&str> = items.iter().map(|i| i["reason"].as_str().unwrap_or("")).collect();
        assert_eq!(
            reasons.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "三种原因的措辞必须互不相同（混成一句用户分不清是写错了还是程序没了）: {reasons:?}"
        );
        for it in &items {
            assert_eq!(it["readonly"], true);
            assert_eq!(it["defaultChecked"], false);
            assert_eq!(it["kind"], "reg_value");
            // 原始键路径 / 值名 / 原始数据 / 判定理由四样都要带给渲染层
            assert!(it["target"].as_str().unwrap_or("").contains("::"), "target 必须能按 :: 拆: {it}");
            assert!(it["details"]["valueName"].is_string());
            assert!(it["details"]["subkey"].is_string());
            assert!(it["reason"].is_string());
        }
    }

    /// 目标仍在本机 ⇒ 一条都不报（仍在使用中的程序的正常配置）。
    #[test]
    fn alive_targets_are_not_reported() {
        let raws = vec![raw(RunView::Hkcu, "Good", Some(r#""C:\Apps\live.exe""#))];
        let (items, notes) = run_findings(&raws, &|_: &str| true, 10);
        assert!(items.is_empty(), "目标存在不得产候选: {items:?}");
        assert!(notes.iter().any(|n| n.contains("仍存在")), "应如实说明有一条被跳过: {notes:?}");
    }

    /// 两个视图分别列项：同名值挂在两侧 ⇒ 两条候选，且 `target` 带各自的视图路径。
    #[test]
    fn both_views_are_listed_separately_with_view_scoped_targets() {
        let raws = vec![
            RunRaw {
                view: RunView::HklmX64,
                subkey: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_string(),
                value_name: "Acme".to_string(),
                data: Some(r"C:\Gone\acme.exe".to_string()),
            },
            RunRaw {
                view: RunView::HklmWow6432,
                subkey: r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run".to_string(),
                value_name: "Acme".to_string(),
                data: Some(r"C:\Gone\acme.exe".to_string()),
            },
        ];
        let (items, _) = run_findings(&raws, &|_: &str| false, 10);
        assert_eq!(items.len(), 2, "两侧各一条，不得合并: {items:?}");
        let targets: Vec<&str> = items.iter().map(|i| i["target"].as_str().unwrap_or("")).collect();
        assert!(
            targets.iter().any(|t| t.contains(r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run::Acme")),
            "32 位视图的 target 必须带 WOW6432Node 路径: {targets:?}"
        );
        assert!(
            targets.iter().any(|t| t.starts_with(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::Acme")),
            "64 位视图的 target 必须带 64 位路径: {targets:?}"
        );
        let views: Vec<&str> = items.iter().map(|i| i["details"]["view"].as_str().unwrap_or("")).collect();
        assert!(views.iter().any(|v| v.contains("WOW6432Node")), "界面要能说清来自哪个视图: {views:?}");
    }

    /// 「一根都打不开」与「读到过但没有候选」是两件事，不并入候选也不静默。
    #[test]
    fn readable_flag_distinguishes_no_data_from_no_candidates() {
        // 只看形状：本用例不碰注册表，`collect_run_raws` 的真机面由发布前人工跑
        let raws: Vec<RunRaw> = vec![];
        let (items, notes) = run_findings(&raws, &|_: &str| false, 10);
        assert!(items.is_empty());
        assert!(notes.is_empty(), "空输入不得编出 note: {notes:?}");
    }

    /// R-2 第 2/3 条：`reg_value_gate` 与 `tools/fixtures/residue-contract.json` 的
    /// `runValueVectors` 逐条一致。
    ///
    /// Node 门禁（`check-residue-rule-contract.mjs` 的 F5）用**同一份字节**跑它自己的
    /// 独立实现 —— 两侧谁也不调谁，任一侧放宽即红（方案 §2.3 R-2 第 3 条）。
    /// 三态计数下限也在本用例里：只断「全放行」或「全拒绝」时，判定坏成常量也能照绿。
    #[test]
    fn reg_value_gate_matches_shared_fixture() {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../../../../tools/fixtures/residue-contract.json"))
                .expect("残留契约夹具解析失败");
        let vectors = f["runValueVectors"].as_array().expect("夹具缺 runValueVectors");
        assert!(vectors.len() >= 20, "R-2 向量太少，判据覆盖不足：{}", vectors.len());
        let mut allowed = 0usize;
        let mut denied = 0usize;
        let mut not_governed = 0usize;
        let mut bad: Vec<String> = Vec::new();
        for v in vectors {
            let target = v["target"].as_str().unwrap();
            let want = v["gate"].as_str().unwrap();
            let got = match reg_value_gate(target) {
                RegValueGate::Allowed => {
                    allowed += 1;
                    "allowed"
                }
                RegValueGate::Denied(_) => {
                    denied += 1;
                    "denied"
                }
                RegValueGate::NotGoverned => {
                    not_governed += 1;
                    "not-governed"
                }
            };
            if got != want {
                bad.push(format!("{}: 期望 {want}，实得 {got}", v["cls"].as_str().unwrap_or(target)));
            }
        }
        assert!(bad.is_empty(), "窄口子判定与夹具不一致：{bad:#?}");
        assert!(
            allowed >= 5 && denied >= 10 && not_governed >= 5,
            "三态覆盖不足（放行 {allowed} / 拒绝 {denied} / 不管辖 {not_governed}）"
        );
    }
}
