//! 服务键残留扫描（v0.5.0 只读，方案 §2.1 / §3 `services_orphan`）。
//!
//! 为什么要单独一个扫描器：v1 只判「ImagePath 落点缺失」，而 NEAC 这类组件的真实形态是
//! 服务键在、`NeacSafe.sys` 在、还在 Running —— v1 的三条判据一条都不命中，于是用户在
//! 游戏早就不在了的机器上永远看不到它。方案 §2.1 把它收成第三类 `stale_live_service`。
//!
//! 三类互不混报（§2.1 的表）：
//! - `dead_landing`：落点全部缺失（与 `dead.rs` 同口径，但作用域是服务键）；
//! - `stale_live_service`：落点存在 + 对应程序查不在任何平台库清单里；
//! - `minifilter_after_key_deleted`：在 `minifilter_orphan.rs`，判据是挂载态不是键态。
//!
//! 两条不能省的闸门：
//! 1. **微软签名件永不进候选**（`authenticode::is_microsoft_signed`）。服务表里绝大多数是
//!    系统组件，少了这道闸，报告会被几百条系统服务淹掉，用户就看不见真正的那几条。
//! 2. **没有证据就不判「已卸载」**：平台清单没读全（`index_complete=false`）时，
//!    反作弊类只报「无法判定」，不报候选 —— 把仍在用的 ACE 驱动写成残留，等第二阶段
//!    接上删除链就是删用户正在玩的游戏。
//!
//! v0.5.0 只读：本文件不写快照（`RESIDUE_SNAPSHOTS`）、不产可执行目标。写快照会把候选
//! 送进 `uninstall_residue_execute` 的快照闸，那是第二阶段的口子，现在必须保持关着。

use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;
use super::authenticode;
use super::dead::dead_landing;
use super::game_platform_orphan::PlatformIndex;
use super::helpers::{open_key_read, reg_dword, reg_multi_sz, reg_sz};
use super::residue::reg_enum_subkeys;
use super::residue_update::contribs;

/// 服务表根（相对 HKLM）。A1 面里这棵整棵禁删，窄口子属第二阶段（方案 §2.3 / §6）。
pub(super) const SERVICES_ROOT: &str = r"SYSTEM\CurrentControlSet\Services";

/// 服务键枚举上限：本机实测常规量级 400~700，留三倍余量防爆但不设无限
const SERVICE_ENUM_CAP: usize = 2048;

/// `Services\<name>` 的只读采集结果（判定所需字段全在这里，判定本身是纯函数）。
#[derive(Debug, Clone)]
pub(super) struct ServiceEntry {
    pub(super) name: String,
    /// ImagePath 原串（可能带 `\??\`、`\SystemRoot`、`%SystemRoot%` 三种写法）
    pub(super) image_raw: String,
    /// `dead_landing` 解析出的落点；None = 解析不出（相对名 / `Device\` / 变量取不到）
    pub(super) landing: Option<String>,
    pub(super) start: Option<u32>,
    pub(super) svc_type: Option<u32>,
    pub(super) depends: Vec<String>,
}

impl ServiceEntry {
    /// 镜像文件名（小写、含扩展名），用于反作弊名单匹配。
    pub(super) fn image_stem_lc(&self) -> String {
        self.landing
            .as_deref()
            .or(if self.image_raw.is_empty() { None } else { Some(self.image_raw.as_str()) })
            .map(|p| {
                Path::new(p.trim_end_matches('\\'))
                    .file_name()
                    .map(|s| s.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }
}

/// 已知反作弊组件名单（方案 §2.2 点名的四家）。
///
/// 这张表**不是保护名单**，只是归属线索：命中的服务才会被追问「它对应的游戏还在不在库」，
/// 未命中且落点又不在游戏库根下的服务一律判「无法归因」。保护与否由平台清单决定。
const ANTICHEAT_MARKERS: &[(&str, &str)] = &[
    ("neac", "NEAC"),
    // 2026-10-07 用户拍板：'ace-' 前缀一网打尽 ACE 全系。补它之前只列了三个具名
    // （ace-game / ace_game / aceservice），本机实测「AntiCheatExpert Protection」
    // （镜像 ace-service64.exe）**不命中**——第 8 道「反作弊无条件拒」对它失明；
    // 内核驱动侧还有第 6 道兜底，用户态侧只剩「落点文件还在」这种一过性条件。
    // 代价如实登记：含 'ace-' 的普通服务名（race-engine 类）同样命中，方向是
    // 「拒绝而非误删」；本机全谱现算误伤为 0（含连字符的 race-/space-/trace- 名不存在）。
    ("ace-", "ACE"),
    ("sguard", "ACE"),
    ("ace-game", "ACE"),
    ("ace_game", "ACE"),
    ("aceservice", "ACE"),
    ("battleye", "BattlEye"),
    ("beservice", "BattlEye"),
    ("easyanticheat", "EAC"),
    ("eac_eos", "EAC"),
];

/// 服务名或镜像文件名命中的反作弊组件名（都没命中返回 None）。
pub(super) fn anticheat_marker(name: &str, image_stem: &str) -> Option<&'static str> {
    let n = name.to_lowercase();
    let i = image_stem.to_lowercase();
    ANTICHEAT_MARKERS.iter().find(|(k, _)| n.contains(*k) || i.contains(*k)).map(|(_, label)| *label)
}

const SERVICE_KEY_PFX: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\";

/// 形状判定（**纯**，可穷举测试）：合格则返回 Services 下那一层的服务名。
/// 只认 `CurrentControlSet`：改 `ControlSet001` 那份不生效，等于假还原。
fn service_key_name(target: &str) -> Option<&str> {
    let t = target.trim();
    if t.len() <= SERVICE_KEY_PFX.len() || !t[..SERVICE_KEY_PFX.len()].eq_ignore_ascii_case(SERVICE_KEY_PFX) {
        return None;
    }
    let name = &t[SERVICE_KEY_PFX.len()..];
    if name.is_empty() || name.contains('\\') {
        return None;
    }
    Some(name)
}

/// 形状不合格时的拒因（与 `service_key_name` 同一套前缀常量，不重复判据）。
fn service_key_shape_reject(target: &str) -> Option<String> {
    let t = target.trim();
    if t.len() > SERVICE_KEY_PFX.len() && t[..SERVICE_KEY_PFX.len()].eq_ignore_ascii_case(SERVICE_KEY_PFX) {
        let name = &t[SERVICE_KEY_PFX.len()..];
        if name.contains('\\') {
            return Some("服务键下面还有子键，本口子不递归删".to_string());
        }
        return Some("Services 下的服务名为空".to_string());
    }
    Some(format!("不是 {SERVICE_KEY_PFX}<服务名> 这种一层服务键形状"))
}

/// [`service_key_delete_block_reason`] 的形状预筛：执行侧用它决定「要不要现读注册表问一次」。
/// 只做大小写无关的前缀判断，不带任何语义 —— 语义全在判据函数里（§5.16 禁两套实现）。
/// `pub`（经 uninstall/mod.rs 再导出）的唯一理由：集成测试断「服务/驱动桶候选的 target
/// 命中窄口子形状」时必须调这同一个函数，手写前缀匹配就是第二套形状判据。
pub fn looks_like_service_key(target: &str) -> bool {
    service_key_name(target).is_some()
}

/// **服务键删除的唯一判据**：装载侧（深扫标记 deleteCapable）与执行侧
/// （`classify_residue_op` 的 A1 窄口子）必须调这同一个函数（AGENTS §5.16/N6）。
/// 返回 `None` = 允许进删除链；`Some(reason)` = 拒，reason 直接进报告与日志。
///
/// 这是本仓唯一一处「A1 禁删面 `HKLM\SYSTEM` 让路」的口子，所以每条都是**排除式**的：
/// 有一点不确定就拒。八道条件缺一不可 ——
/// 1. 形状：`HKLM\SYSTEM\CurrentControlSet\Services\<name>`，Services 下**恰好一层**，
///    且只认 `CurrentControlSet`（改 ControlSet001 那份不生效，等于假还原）；
/// 2. 键真的存在（不存在就没东西可删）；
/// 3. `ImagePath` 解析不出落点 ⇒ 拒。解析不出（相对名 / `Device\` / 变量取不到）
///    意味着对「它是什么」没有事实，只能留；
/// 4. 落点文件**还在** ⇒ 拒。本口子只处理「文件已经没了、键还挂着」这一类：
///    落点在的服务可能被 SCM、依赖方或计划任务正用着，判错方向不可逆；
/// 5. 落点在 `%windir%` 之下 ⇒ 拒。**这条是「微软组件」的替身判据**：文件已不存在就读不到
///    签名，`signature_known=false` 此时毫无信息量，而 Windows 自身组件的 ImagePath 必然
///    指向 System32/SysWOW64 —— 用路径挡，才不依赖一个此刻拿不到的证据；
/// 6. `Type` 是内核驱动(0x1)/文件系统驱动(0x2)，或 `Start` 是 boot(0)/system(1) ⇒ 拒。
///    这类键由会话早期加载器读，删了出问题就是蓝屏或起不来，与「清一条残留」的收益不成比例；
/// 7. 有 `DependOnService` ⇒ 拒。还有别的服务声明依赖它，「没人用」这条不成立；
/// 8. 命中反作弊名单（`ANTICHEAT_MARKERS`）⇒ 拒。无条件生效，不吃「清单读全」这种条件。
///
/// 提权（`is_admin()`）**不在这里判**：判据函数不该知道调用方的权限态，那一闸由执行侧
/// 在调完本函数之后再补一道（缺了它写 HKLM 会失败，不是安全问题）。
///
/// 本函数**现读注册表**，不读快照里缓存的结论：扫描与执行之间用户可能重装了游戏、
/// 也可能把服务重新起来了 —— 拿那一刻的事实去删这一刻的键，正是「按过期证据动系统」那类缺陷。
pub(super) unsafe fn service_key_delete_block_reason(target: &str) -> Option<String> {
    use std::path::Path;
    let name = match service_key_name(target) {
        Some(n) => n,
        None => return service_key_shape_reject(target),
    };
    let name = name.to_string();
    let Some(hk) = open_key_read(windows::Win32::System::Registry::HKEY_LOCAL_MACHINE, &format!(r"{SERVICES_ROOT}\{name}")) else {
        return Some("服务键打不开或已不存在".to_string());
    };
    let image_raw = reg_sz(hk, "ImagePath").unwrap_or_default();
    let start = reg_dword(hk, "Start");
    let svc_type = reg_dword(hk, "Type");
    let depends = reg_multi_sz(hk, "DependOnService");
    let _ = windows::Win32::System::Registry::RegCloseKey(hk);
    let landing = if image_raw.trim().is_empty() { None } else { dead_landing(&image_raw) };
    let Some(landing) = landing else {
        return Some(format!("ImagePath 解析不出落点（原串 {image_raw}），对「它是什么」没有事实"));
    };
    if Path::new(&landing).exists() {
        return Some(format!("落点仍然存在（{landing}），本口子只处理文件已失踪的键"));
    }
    // %windir% 取不到 ⇒ 第 5 道闸无法判 ⇒ 按不确定处理，拒
    let windir = std::env::var("SystemRoot").or_else(|_| std::env::var("WINDIR")).unwrap_or_default();
    if windir.trim().is_empty() {
        return Some("读不到 %SystemRoot%，无法判断落点是否属于 Windows 自身组件".to_string());
    }
    if landing.to_lowercase().starts_with(&windir.to_lowercase()) {
        return Some(format!("落点在系统目录内（{landing}），按 Windows 自身组件对待，不删"));
    }
    if matches!(svc_type, Some(0x1) | Some(0x2)) {
        return Some("服务类型是内核/文件系统驱动，删键的失败模式是启动期故障，不可接受".to_string());
    }
    if matches!(start, Some(0) | Some(1)) {
        return Some("启动类型是 boot/system，由会话早期加载，删键可能导致系统起不来".to_string());
    }
    if !depends.is_empty() {
        return Some(format!("仍有 {} 项依赖声明指向它，「没人用」不成立", depends.len()));
    }
    let stem = Path::new(&landing).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    if let Some(marker) = anticheat_marker(&name, &stem) {
        return Some(format!("命中反作弊名单（{marker}），无条件不删"));
    }
    None
}

/// 分类判定（纯函数，单测覆盖 §2.1 的三分类与两条闸门）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ServiceClass {
    /// 落点全部缺失
    DeadLanding,
    /// 落点存在，但对应程序查不在平台清单里
    StaleLiveService,
    /// 游戏仍在库 / 卸载键仍活 / 进程在跑 —— 保护，不进候选
    ProtectedInUse,
    /// 微软签名组件 —— 保护，不进候选
    MicrosoftComponent,
    /// 证据不足（ImagePath 解析不出、清单没读全、无法归因）—— 不报候选
    NoEvidence,
}

/// 判定输入。刻意全是已归约的布尔信号：让「哪条形据压过哪条」在单测里可直接摆。
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct ServiceSignals {
    /// ImagePath 能解析出落点
    pub(super) landing_resolved: bool,
    pub(super) landing_exists: bool,
    /// 签名读得出来且主体是微软。读不出签名 ⇒ false：判 `dead_landing` 不要求签名可读
    /// （落点已失踪时根本没有文件可问签名），而「不是微软件」这件事由 `microsoft_signed`
    /// 单独承担，不再用一个 `signature_known` 布尔位去区分两种 false
    pub(super) microsoft_signed: bool,
    /// 落点落在某个**在库**游戏的安装目录里
    pub(super) in_library_dir: bool,
    /// 落点落在平台库根下，但不在任何在库游戏目录里
    pub(super) under_library_root: bool,
    /// 命中反作弊名单
    pub(super) anticheat: bool,
    /// 三处平台清单本轮都读到了
    pub(super) index_complete: bool,
    /// 反作弊归属的游戏名在清单里查得到
    pub(super) game_named_present: bool,
    /// 该服务对应的卸载注册表项仍活着（原厂卸载没走完，程序还在）
    pub(super) uninstall_key_alive: bool,
    /// 服务镜像正在进程表里跑
    pub(super) process_running: bool,
}

/// 判据顺序（每一条都有理由，改动前先想清楚压的是哪条）：
/// 1. 解析不出落点 ⇒ 无证据；
/// 2. 微软签名 ⇒ 系统组件，永不进候选；
/// 3. 在库目录 / 卸载键仍活 / 进程在跑 ⇒ 在用保护；
/// 4. 落点不存在 ⇒ `dead_landing`；
/// 5. 落点在库根下但不在任何在库游戏目录里 ⇒ `stale_live_service`（最强的一条实据）；
/// 6. 反作弊组件 + 清单读全 + 游戏查不在库 ⇒ `stale_live_service`（NEAC 形态）；
/// 7. 其余 ⇒ 无法归因，不报。第 6 条要求 `index_complete`，就是为了不把
///    「读不到清单」伪装成「程序已卸载」。
pub(super) fn classify_service(s: &ServiceSignals) -> ServiceClass {
    if !s.landing_resolved {
        return ServiceClass::NoEvidence;
    }
    if s.microsoft_signed {
        return ServiceClass::MicrosoftComponent;
    }
    if s.landing_exists && (s.in_library_dir || s.uninstall_key_alive || s.process_running || (s.anticheat && s.game_named_present)) {
        return ServiceClass::ProtectedInUse;
    }
    if !s.landing_exists {
        return ServiceClass::DeadLanding;
    }
    if s.under_library_root {
        return ServiceClass::StaleLiveService;
    }
    if s.anticheat && s.index_complete && !s.game_named_present {
        return ServiceClass::StaleLiveService;
    }
    ServiceClass::NoEvidence
}

/// `ServiceClass` → 报告里的分类标签（前端按它分组，措辞只在这一处定义）
pub(super) fn class_label(c: ServiceClass) -> &'static str {
    match c {
        ServiceClass::DeadLanding => "dead_landing",
        ServiceClass::StaleLiveService => "stale_live_service",
        ServiceClass::ProtectedInUse => "protected_in_use",
        ServiceClass::MicrosoftComponent => "microsoft_component",
        ServiceClass::NoEvidence => "no_evidence",
    }
}

/// `Start` / `Type` 的中文标签（读不到就留空，不拿 0 当「手动」或「内核驱动」）。
pub(super) fn start_label(start: Option<u32>) -> Option<&'static str> {
    start.map(|v| match v {
        0 => "BOOT_START（开机早期）",
        1 => "SYSTEM_START（系统加载期）",
        2 => "AUTO_START（自动）",
        3 => "MANUAL（手动）",
        4 => "DISABLED（已禁用）",
        _ => "未知启动类型",
    })
}

pub(super) fn type_label(ty: Option<u32>) -> Option<&'static str> {
    // Type 是位标志与类型的混合体，常见取值就是下面五个；猜不出来如实写「其他」而不是
    // 拿 `& 0x03` 把 16/32（Win32 独立/共享进程）折成内核驱动。
    ty.map(|v| match v {
        1 => "内核驱动",
        2 => "自动加载驱动",
        4 => "文件系统驱动",
        16 => "独立进程服务",
        32 => "共享进程服务",
        _ => "其他类型",
    })
}

/// SCM 当前状态码（1=Stopped 2=Start Pending 4=Running 5=Continue Pending …）。
///
/// 刻意不复用 `engine::native::services` 那份：它的 `service_status` 是 `pub(super)`，
/// 跨不出 native 模块；而分层门禁禁的是下层反向引用上层，上层读下层是合法方向 ——
/// 这里要的只是一个只读状态码，自己开句柄比要求引擎层改可见性更省事。
/// 打不开 SCM（未提权读某些服务）返回 None，报告里如实写「状态读不到」。
pub(super) unsafe fn scm_state(name: &str) -> Option<u32> {
    use windows::Win32::System::Services::CloseServiceHandle;
    let scm = open_scm()?;
    let out = scm_state_with(scm, name);
    let _ = CloseServiceHandle(scm);
    out
}

/// 打开 SCM（一次）供批量查询复用；调用方用完负责 `CloseServiceHandle`。
///
/// M-12（审查 2026-10-07）：`scm_state` 原实现每次调用都 OpenSCManagerW + Close ——
/// 在服务残留扫描里是 per-service 的 N+1。批量场景改用本函数开一次、循环内复用。
pub(super) unsafe fn open_scm() -> Option<windows::Win32::System::Services::SC_HANDLE> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::{OpenSCManagerW, SC_MANAGER_CONNECT};
    OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT).ok()
}

/// 用**已有的** SCM 句柄查单个服务状态（不接管 scm 生命周期）。
pub(super) unsafe fn scm_state_with(
    scm: windows::Win32::System::Services::SC_HANDLE,
    name: &str,
) -> Option<u32> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenServiceW, QueryServiceStatus, SERVICE_QUERY_STATUS, SERVICE_STATUS,
    };
    let wide = super::helpers::to_wide(name);
    let svc = OpenServiceW(scm, PCWSTR(wide.as_ptr()), SERVICE_QUERY_STATUS).ok()?;
    let mut status: SERVICE_STATUS = std::mem::zeroed();
    let ok = QueryServiceStatus(svc, &mut status).is_ok();
    let _ = CloseServiceHandle(svc);
    ok.then_some(status.dwCurrentState.0)
}

pub(super) fn state_label(state: Option<u32>) -> &'static str {
    match state {
        Some(1) => "已停止",
        Some(2) => "正在启动",
        Some(3) => "正在停止",
        Some(4) => "运行中",
        Some(5) => "正在继续",
        Some(6) => "暂停中",
        Some(7) => "启动挂起",
        _ => "状态读不到（未提权或服务已不可打开）",
    }
}

/// 枚举服务表（只读）。返回 (条目, 是否至少读到一个键)。
///
/// `ok=false` = 连 `Services` 根都打不开，调用方必须整组不产候选并写 note：
/// 拿空清单去做「已卸载」判定，等于把全部服务算成残留。
pub(super) unsafe fn collect_service_entries(cap: usize) -> (Vec<ServiceEntry>, bool) {
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RegCloseKey};
    let names = reg_enum_subkeys(HKEY_LOCAL_MACHINE, SERVICES_ROOT, cap.min(SERVICE_ENUM_CAP));
    if names.is_empty() {
        return (Vec::new(), false);
    }
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let Some(hk) = open_key_read(HKEY_LOCAL_MACHINE, &format!("{SERVICES_ROOT}\\{name}")) else {
            continue;
        };
        let image_raw = reg_sz(hk, "ImagePath").unwrap_or_default();
        let landing = if image_raw.trim().is_empty() { None } else { dead_landing(&image_raw) };
        out.push(ServiceEntry {
            name,
            image_raw,
            landing,
            start: reg_dword(hk, "Start"),
            svc_type: reg_dword(hk, "Type"),
            depends: reg_multi_sz(hk, "DependOnService"),
        });
        let _ = RegCloseKey(hk);
    }
    (out, true)
}

/// 全部服务落点的归一集合（小写、去尾 `\`）—— `drivers_orphan` 用它反查未被引用的 sys。
pub(super) fn referenced_landings(entries: &[ServiceEntry]) -> HashSet<String> {
    entries
        .iter()
        .filter_map(|e| e.landing.as_deref())
        .map(|p| p.replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase())
        .collect()
}

/// 本组的扫描口径注释（写进 notes，让用户知道哪些保护是「读不出来」而不是「确认在用」）。
pub(super) fn protection_note(c: ServiceClass) -> Option<&'static str> {
    match c {
        ServiceClass::MicrosoftComponent => Some("微软签名组件，按系统件保护"),
        ServiceClass::ProtectedInUse => Some("对应程序仍在库 / 卸载键仍活 / 进程在跑，按在用保护"),
        _ => None,
    }
}

/// 产出服务类候选（纯函数部分已在上，这里只做拼装）。
///
/// `uninstall_alive_names` = 三根卸载键里的 DisplayName/KeyName 小写集合，用来判
/// 「这个服务所属的程序还在卸载列表里」；`process_dirs` = 运行进程镜像全路径（小写）。
pub(super) unsafe fn service_findings(
    entries: &[ServiceEntry],
    index: &PlatformIndex,
    uninstall_alive_names: &HashSet<String>,
    process_dirs: &Option<HashSet<String>>,
    cap: usize,
) -> (Vec<Value>, Vec<Value>, Vec<String>) {
    let mut candidates: Vec<Value> = Vec::new();
    let mut protected: Vec<Value> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut no_evidence = 0usize;
    // M-12（审查 2026-10-07）：SCM 句柄整轮开一次复用（原先每个服务都 Open/Close 一轮）。
    let scm = open_scm();
    for e in entries {
        let Some(landing) = e.landing.as_deref() else {
            if !e.image_raw.trim().is_empty() {
                no_evidence += 1;
            }
            continue;
        };
        let landing_exists = Path::new(landing).exists();
        let stem = e.image_stem_lc();
        let ac = anticheat_marker(&e.name, &stem);
        let owner = index.owner_of(landing);
        let signature_known = landing_exists && authenticode::signer_subject(landing).is_some();
        let microsoft_signed = landing_exists && authenticode::is_microsoft_signed(landing);
        // 卸载键是否还活着：服务名与卸载键 DisplayName 互含。用本域最短的那档阈值（2 字），
        // 因为这是「拿已知表里的名字撞已知表」，不是自由文本猜测 —— 见 residue.rs 的
        // NAME_MIN_EXACT 注释里那条中文产品名全军覆没的教训。
        let uninstall_key_alive = {
            let n = e.name.to_lowercase();
            n.len() >= 2 && uninstall_alive_names.iter().any(|d| d == &n || d.contains(&n) || n.contains(d.as_str()))
        };
        let process_running = process_dirs
            .as_ref()
            .map(|set| set.contains(&landing.to_ascii_lowercase()))
            .unwrap_or(false);
        let signals = ServiceSignals {
            landing_resolved: true,
            landing_exists,
            microsoft_signed,
            in_library_dir: owner.is_some(),
            under_library_root: owner.is_none() && index.under_library_root(landing),
            anticheat: ac.is_some(),
            index_complete: index.complete(),
            game_named_present: ac.map(|label| index.has_game_named(label)).unwrap_or(false),
            uninstall_key_alive,
            process_running,
        };
        let cls = classify_service(&signals);
        let target = format!("HKLM\\{SERVICES_ROOT}\\{}", e.name);
        let state = match scm {
            Some(h) => scm_state_with(h, &e.name),
            None => None,
        };
        let details = json!({
            "serviceName": e.name,
            "imagePath": e.image_raw,
            "landing": landing,
            "landingExists": landing_exists,
            "start": start_label(e.start),
            "type": type_label(e.svc_type),
            "depends": e.depends,
            "state": state_label(state),
            "rawState": state,
            "signer": if signature_known { authenticode::signer_label(landing) } else { "落点已不存在，未查签名".to_string() },
            "antiCheat": ac,
            "inLibraryGame": owner.map(|r| r.name.clone()),
        });
        match cls {
            ServiceClass::DeadLanding | ServiceClass::StaleLiveService => {
                if candidates.len() >= cap {
                    notes.push(format!("服务残留候选已达上限 {cap} 条，其余省略"));
                    break;
                }
                let stale = cls == ServiceClass::StaleLiveService;
                candidates.push(json!({
                    "kind": "reg_key", "target": target,
                    "class": class_label(cls),
                    "reason": if stale {
                        "服务键与二进制都还在，但对应游戏/程序在 Steam / Epic / WeGame 清单里都查不到（已卸载程序的常驻服务或驱动）"
                    } else {
                        "服务键还在，但 ImagePath 指向的二进制已不存在"
                    },
                    "confidence": if stale { "medium" } else { "high" },
                    "risk": "high",
                    "readonly": true, "defaultChecked": false,
                    "details": details,
                    "contribs": contribs(&[
                        ("serviceKeyAlive", format!("{SERVICES_ROOT}\\{} 仍可打开", e.name)),
                        ("landingState", if landing_exists { format!("落点存在：{landing}") } else { format!("落点不存在：{landing}") }),
                        ("platformIndex", if index.complete() { "三处平台清单均读到".to_string() } else { format!("清单不完整：{}", index.unreadable.join("、")) }),
                        ("antiCheat", ac.map(|a| format!("命中反作弊名单：{a}")).unwrap_or_else(|| "未命中反作弊名单".to_string())),
                    ]),
                }));
            }
            c => {
                if let Some(note) = protection_note(c) {
                    if candidates.len() + protected.len() < cap * 2 {
                        protected.push(json!({
                            "kind": "reg_key", "target": target,
                            "class": class_label(c),
                            "reason": note,
                            "readonly": true, "details": details,
                        }));
                    }
                } else {
                    no_evidence += 1;
                }
            }
        }
    }
    if no_evidence > 0 {
        notes.push(format!("{no_evidence} 个服务因证据不足未进候选（ImagePath 解析不出 / 无法归因到某个已卸载程序）"));
    }
    if let Some(dirs) = process_dirs {
        if dirs.is_empty() {
            notes.push("进程快照读到空集合，「镜像正在运行」这条保护本轮不可用".to_string());
        }
    } else {
        notes.push("进程快照取不到，「镜像正在运行」这条保护本轮不可用".to_string());
    }
    if let Some(h) = scm {
        use windows::Win32::System::Services::CloseServiceHandle;
        let _ = CloseServiceHandle(h);
    }
    (candidates, protected, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(f: impl FnOnce(&mut ServiceSignals)) -> ServiceSignals {
        let mut s = ServiceSignals::default();
        f(&mut s);
        s
    }

    #[test]
    fn unresolved_image_path_is_no_evidence() {
        // 落点解析不出来（相对名 / Device\）时，「不存在」不成立，任何分类都不给
        let s = sig(|x| {
            x.landing_resolved = false;
            x.landing_exists = false;
        });
        assert_eq!(classify_service(&s), ServiceClass::NoEvidence);
    }

    #[test]
    fn microsoft_signed_never_enters_candidates() {
        let s = sig(|x| {
            x.landing_resolved = true;
            x.landing_exists = false;
            x.microsoft_signed = true;
        });
        assert_eq!(classify_service(&s), ServiceClass::MicrosoftComponent);
    }

    #[test]
    fn missing_landing_is_dead_landing() {
        let s = sig(|x| {
            x.landing_resolved = true;
            x.landing_exists = false;
        });
        assert_eq!(classify_service(&s), ServiceClass::DeadLanding);
    }

    #[test]
    /// 方案 §6 的复现用例：服务键存在 + sys 存在 + 游戏不在库 ⇒ 必须报出候选
    fn neac_shape_reports_stale_live_service() {
        let s = sig(|x| {
            x.landing_resolved = true;
            x.landing_exists = true;
            x.anticheat = true;
            x.index_complete = true;
            x.game_named_present = false;
        });
        assert_eq!(classify_service(&s), ServiceClass::StaleLiveService);
    }

    #[test]
    /// 同一条证据，游戏仍在库 ⇒ 反过来必须保护（方案 §2.2 的条件保护）
    fn same_service_is_protected_while_game_in_library() {
        let s = sig(|x| {
            x.landing_resolved = true;
            x.landing_exists = true;
            x.anticheat = true;
            x.index_complete = true;
            x.game_named_present = true;
        });
        assert_eq!(classify_service(&s), ServiceClass::ProtectedInUse);
    }

    #[test]
    fn incomplete_index_does_not_claim_uninstalled() {
        // 清单没读全 ⇒ 不能说「游戏不在库」，只能落回无证据
        let s = sig(|x| {
            x.landing_resolved = true;
            x.landing_exists = true;
            x.anticheat = true;
            x.index_complete = false;
            x.game_named_present = false;
        });
        assert_eq!(classify_service(&s), ServiceClass::NoEvidence);
    }

    #[test]
    fn library_root_without_record_is_stale_live() {
        // 落点在 D:\SteamLibrary 下，但不在任何在库游戏目录里 —— 最强的 stale 实据
        let s = sig(|x| {
            x.landing_resolved = true;
            x.landing_exists = true;
            x.under_library_root = true;
            x.in_library_dir = false;
        });
        assert_eq!(classify_service(&s), ServiceClass::StaleLiveService);
    }

    #[test]
    fn running_image_or_live_uninstall_key_wins_over_stale() {
        let protections: [fn(&mut ServiceSignals); 3] = [
            |x| x.process_running = true,
            |x| x.uninstall_key_alive = true,
            |x| x.in_library_dir = true,
        ];
        for f in protections {
            let s = sig(|x| {
                x.landing_resolved = true;
                x.landing_exists = true;
                x.under_library_root = true;
                f(x);
            });
            assert_eq!(classify_service(&s), ServiceClass::ProtectedInUse);
        }
    }

    #[test]
    fn unknown_third_party_service_is_not_attributed() {
        // 普通第三方服务（活着的落点、库外、非反作弊）不是残留，不能报
        let s = sig(|x| {
            x.landing_resolved = true;
            x.landing_exists = true;
        });
        assert_eq!(classify_service(&s), ServiceClass::NoEvidence);
    }

    #[test]
    fn anticheat_markers_match_name_or_image_and_nothing_else() {
        assert_eq!(anticheat_marker("NeacSafe", ""), Some("NEAC"));
        assert_eq!(anticheat_marker("svc", "NeacSafe.sys"), Some("NEAC"));
        assert_eq!(anticheat_marker("BEService", ""), Some("BattlEye"));
        assert_eq!(anticheat_marker("EasyAntiCheat_EOS", ""), Some("EAC"));
        assert_eq!(anticheat_marker("GoogleUpdateExecution", "gemini.exe"), None);
        // 2026-10-07 拍板补的 'ace-' 前缀：用户态本体（镜像名）+ 内核驱动服务名都命中
        assert_eq!(anticheat_marker("svc", "ACE-Service64.exe"), Some("ACE"));
        assert_eq!(anticheat_marker("ACE-CORE102706", ""), Some("ACE"));
        // 无 'ace-' 子串的负例继续守住（space 开头的普通驱动不带连字符，不命中）
        assert_eq!(anticheat_marker("Spaceport", "spaceport.sys"), None);
        // 刻意承认 'ace-' 的泛化代价：含该子串的普通服务名同样命中（误拦方向安全，
        // 用户 2026-10-07 拍板接受）。想改匹配策略前先读懂这条断言。
        assert_eq!(anticheat_marker("race-engine", ""), Some("ACE"));
    }

    #[test]
    fn labels_do_not_fabricate_zero_as_known() {
        // 读不到留 None：把 0 当成「BOOT_START」会把读不到伪装成有把握
        assert_eq!(start_label(None), None);
        assert_eq!(type_label(None), None);
        assert_eq!(start_label(Some(4)), Some("DISABLED（已禁用）"));
        assert_eq!(type_label(Some(1)), Some("内核驱动"));
        assert_eq!(type_label(Some(4)), Some("文件系统驱动"));
        assert_eq!(type_label(Some(16)), Some("独立进程服务"));
        // 复合位标志（16|32=48）不该被折成某个单一类型冒充已知
        assert_eq!(type_label(Some(48)), Some("其他类型"));
        assert_eq!(state_label(None), "状态读不到（未提权或服务已不可打开）");
        assert_eq!(state_label(Some(4)), "运行中");
    }

    #[test]
    fn referenced_landings_are_normalized_for_reverse_lookup() {
        let e = |name: &str, landing: Option<&str>| ServiceEntry {
            name: name.to_string(),
            image_raw: landing.unwrap_or("").to_string(),
            landing: landing.map(|s| s.to_string()),
            start: None,
            svc_type: None,
            depends: Vec::new(),
        };
        let set = referenced_landings(&[e("A", Some(r"C:\Windows\System32\DRIVERS\x.sys")), e("B", Some("C:\\other\\Y.SYS")), e("C", None)]);
        assert!(set.contains(r"c:\windows\system32\drivers\x.sys"));
        assert!(set.contains(r"c:\other\y.sys"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn image_stem_prefers_resolved_landing() {
        let mut e = ServiceEntry {
            name: "svc".to_string(),
            image_raw: r"\SystemRoot\system32\drivers\NeacSafe.sys".to_string(),
            landing: Some(r"C:\Windows\system32\drivers\NeacSafe.sys".to_string()),
            start: None,
            svc_type: None,
            depends: Vec::new(),
        };
        assert_eq!(e.image_stem_lc(), "neacsafe.sys");
        e.landing = None;
        assert_eq!(e.image_stem_lc(), "neacsafe.sys");
    }

    #[test]
    fn services_root_is_the_narrow_scope_named_in_the_plan() {
        // 方案 §5 的窄口子开在这一棵上（v0.7.0 第三阶段已落地）。钉住扫描面与删除口
        // 走同一条路径，避免将来扫描器扫 A、口子开在 B。
        assert_eq!(SERVICES_ROOT, r"SYSTEM\CurrentControlSet\Services");
    }

    /// 形状判据穷举（纯函数，不碰注册表）：合格只有一种，其余全是拒。
    /// 特别钉三条：`ControlSet001` 不吃（改了不生效 = 假还原）、二级子键不吃（不递归）、
    /// 别的 hive 前缀不吃（HKCU 下没有服务键，写它只会静默失败）。
    #[test]
    fn service_key_shape_accepts_exactly_one_level_under_currentcontrolset() {
        assert_eq!(service_key_name(r"HKLM\SYSTEM\CurrentControlSet\Services\AcmeSvc").unwrap(), "AcmeSvc");
        assert_eq!(service_key_name(r"hklm\system\currentcontrolset\services\ACME").unwrap(), "ACME");
        let rejected = [
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            r"HKLM\SYSTEM\CurrentControlSet\Services\",
            r"HKLM\SYSTEM\CurrentControlSet\Services\Acme\Params",
            r"HKLM\SYSTEM\ControlSet001\Services\Acme",
            r"HKCU\SOFTWARE\Acme",
            r"HKLM\SYSTEM\CurrentControlSet\Serviceset\Acme",
            "",
        ];
        for t in rejected {
            assert_eq!(service_key_name(t), None, "形状判据误接受: {t:?}");
            assert!(!looks_like_service_key(t), "预筛与主判据不一致: {t:?}");
        }
        // 首尾空白：判据自己 trim，不接受「看着不对」的分裂口径
        assert_eq!(service_key_name("  HKLM\\SYSTEM\\CurrentControlSet\\Services\\Acme  ").unwrap(), "Acme");
        // 拒因要具体到「为什么」：报告与日志都靠这句话解释「为什么不给删」
        assert!(service_key_shape_reject(r"HKLM\SYSTEM\CurrentControlSet\Services\Acme\Params")
            .unwrap()
            .contains("子键"));
        assert!(service_key_shape_reject(r"HKLM\SYSTEM\ControlSet001\Services\Acme")
            .unwrap()
            .contains("CurrentControlSet"));
    }

    /// 预筛（执行侧用来决定要不要现读注册表）与主判据的形状段必须口径一致。
    #[test]
    fn shape_prefilter_and_main_predicate_agree() {
        for t in [
            r"HKLM\SYSTEM\CurrentControlSet\Services\Acme",
            r"HKLM\SYSTEM\CurrentControlSet\Services\Acme\Params",
            r"HKLM\SYSTEM\ControlSet001\Services\Acme",
            r"HKCU\SOFTWARE\Acme",
        ] {
            let pre = looks_like_service_key(t);
            let main_passes_shape = service_key_name(t).is_some();
            assert_eq!(pre, main_passes_shape, "预筛与主判据对 {t:?} 判得不一致: 预筛 {pre} / 主判据 {main_passes_shape}");
        }
    }

    /// **真机、只读**：Windows 自身的几条服务必须一律被拒（八道判据里至少命中一条）。
    /// 这条是窄口子最重要的负向保险：它证明「现读判据」真的在挡系统组件，
    /// 而不是只在假数据上成立。读 HKLM\...\Services 不需要管理员。
    #[test]
    fn real_windows_services_are_rejected() {
        for name in ["Winmgmt", "RpcSs", "Schedule", "BITS", "W32Time"] {
            let target = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}");
            let reason = unsafe { service_key_delete_block_reason(&target) };
            assert!(reason.is_some(), "系统服务 {name} 竟然被判成可删 —— 至少一条判据该挡住它");
            let r = reason.unwrap();
            let expected = ["仍然存在", "系统目录", "boot", "驱动", "依赖", "解析不出", "打不开"];
            assert!(
                expected.iter().any(|w| r.contains(w)),
                "{name} 的拒因不在预期集合里，判据可能已退化: {r}"
            );
        }
        // 正向对照的另一半：本机不存在的键也必须被拒（否则「键不存在」那道闸坏了，
        // 删除会静默假成功）
        let ghost =
            unsafe { service_key_delete_block_reason(r"HKLM\SYSTEM\CurrentControlSet\Services\TrimNoSuchSvc-9f3a") };
        assert!(ghost.is_some(), "不存在的键被判成可删: {ghost:?}");
    }
}
