//! A3 PnP 设备原生侧 —— **只读 spike**（v2-R5，2026-10-01）
//!
//! v2 R5 的次序是「枚举先行、删除最后、设备先 spike」，本模块只做第一步。
//! 目标步骤 `tf_dev_disable`（2026-10-11 起音频控制器/打印队列并入它的逐项清单，
//! 原 tf_dev_audio / tf_dev_printer 两项退役）是 `risk: medium`、设备可在设备管理器
//! 重新启用，但本模块仍**不调用** `CM_Disable_DevNode`（v2-R5 只做只读 spike），只回答：
//!
//! > 原生能不能复现 `Get-PnpDevice | Where { FriendlyName -eq X -and Status -eq 'OK' }`
//! > 这个**双条件**判定？
//!
//! 双条件是 v2 明令必须保留的（"不做只按名字匹配"）：只按 FriendlyName 匹配会把
//! 一个已停用/有问题的同名设备也选中，那正是"禁用错设备"的入口。
//!
//! 绑定面（逐条查过 windows 0.61.3 源码，不是推断）：
//! `CM_Get_Device_ID_List_SizeW` / `CM_Get_Device_ID_ListW` / `CM_Locate_DevNodeW` /
//! `CM_Get_DevNode_PropertyW` / `CM_Get_DevNode_Status` 都在
//! `Win32_Devices_DeviceAndDriverInstallation`，`DEVPKEY_Device_FriendlyName` 与
//! `DEVPROPTYPE` 在 `Win32_Devices_Properties`（**不是** Foundation —— 0.61 里
//! `DEVPROPKEY` 在 Foundation、`DEVPROPTYPE` 已挪到 Properties，容易记混）。
//!
//! 状态位刻意用 crate 常量而不是手写数字：本轮先按 `CM_DEVCORE_STARTED=0x1` /
//! `DN_HAS_PROBLEM=0x2` 写过一次，查源码才发现真实值是 `DN_STARTED=8` /
//! `DN_HAS_PROBLEM=1024` —— 手写常数在这里会把"已启动"判到 `DN_ROOT_ENUMERATED` 上，
//! 而这类错位不会报错，只会静默选中错的设备。
//!
//! ## spike 结论（本机 zh-CN Windows，2026-10-01 实跑，逐台 join 而非抽样）
//!
//! ① **能复现，但 `FriendlyName` 不是一个属性。** `Get-PnpDevice` 的 `FriendlyName` 列
//! = `DEVPKEY_Device_FriendlyName`（裁尾空格）非空则用它，否则退到
//! `DEVPKEY_Device_DeviceDesc`。本机 190 台在册设备里 41 台走前者、148 台走后者、
//! 1 台两者皆空 —— 41+148+1=190，无第三种来源。只读 `FriendlyName` 会漏掉 148 台。
//! ② **枚举范围与 `Status` 都能对齐。** `CM_Get_Device_ID_List`（不带 filter）返回 190 台
//! = `Get-PnpDevice -PresentOnly` 的 190 台；`Get-PnpDevice` 默认多出的 85 台**全部**是
//! `Status=Unknown`，永远不满足 `Status -eq 'OK'`，所以原生按在册设备查不丢目标。
//! `status_ok_of` 与 PS 侧 190/190 一致。
//! ③ **上游这三个步骤在中文 Windows 上本来就命中 0 台。** 步骤里的字面量是英文原名
//! （`High Definition Audio Controller` / `System Speaker` / `Root Print Queue`），
//! 而设备显示名是本地化的（本机实读 `High Definition Audio 控制器` / `系统扬声器`），
//! `-eq` 精确匹配不可能命中。原生移植**照搬这个口径**（同样命中 0），不在这里顺手把
//! 名字改成本地化写法 —— 那等于把一个多年静默的空操作变成"真的去禁用声卡控制器"，
//! 属高风险且 `restoreAvailable: False`，要改得先在产品侧单独拍板（登记进 v2 §7 R6 台账）。

use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Disable_DevNode, CM_Enable_DevNode, CM_Get_DevNode_PropertyW, CM_Get_DevNode_Status,
    CM_Get_Device_ID_ListW, CM_Get_Device_ID_List_SizeW, CM_Locate_DevNodeW,
    CM_DEVNODE_STATUS_FLAGS, CM_DISABLE_PERSIST, CM_LOCATE_DEVNODE_FLAGS, CM_PROB, DN_HAS_PROBLEM,
    DN_STARTED,
};
use windows::Win32::Devices::Properties::{
    DEVPKEY_Device_DeviceDesc, DEVPKEY_Device_FriendlyName, DEVPROPTYPE,
};
use windows::Win32::Foundation::DEVPROPKEY;

/// `Get-PnpDevice` 的 `Status -eq 'OK'` 在原生侧的等价判据。
///
/// 判据取「`DN_HAS_PROBLEM` 未置位」**且**「问题码为 0」两个条件。实机对照结果
/// （2026-10-01，本机在册 190 台逐台 join）：与 `Status` **190/190 一致**，
/// 其中 8 台问题码非零、13 台「无问题但未启动」也判 OK —— 与 PS 侧同口径。
///
/// 未把 `DN_STARTED` 纳入判据不是偷懒：实测纳进去就会与 PS 的 `OK` 分叉（169 vs 182）。
fn status_ok_of(raw_flags: u32, problem: u32) -> bool {
    let has_problem = raw_flags & DN_HAS_PROBLEM.0 != 0;
    !has_problem && problem == 0
}

/// 一个匹配到的设备实例。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevHit {
    /// CM 设备节点句柄（CM_Locate_DevNode 产物，禁用/启用时直接用）
    pub devinst: u32,
    /// 设备实例 ID（`PCI\VEN_8086&DEV_...` 这种），禁用时要的就是它
    pub instance: String,
    /// `DEVPKEY_Device_FriendlyName`
    pub friendly: String,
    /// `DEVPKEY_Device_DeviceDesc`。spike 期间带着它只为回答一个问题：
    /// `Get-PnpDevice` 的 `FriendlyName` 列到底取自哪个属性（实测见
    /// `live_probe_全量枚举与状态位对照` 的 three-count 输出）。
    pub desc: String,
    /// 与 `Get-PnpDevice` 的 `Status -eq 'OK'` 同口径
    pub status_ok: bool,
    /// `DN_STARTED`：设备已启动
    pub started: bool,
    /// `DN_HAS_PROBLEM`
    pub has_problem: bool,
    /// `CM_Get_DevNode_Status` 的问题码（0 = 无问题）
    pub problem: u32,
    /// 原始状态位，供实机对照时分辨「掩过没掩过」
    pub raw_flags: u32,
}

/// 解多字符串（double-NUL 结尾的 UTF-16 缓冲）。
///
/// 单独拆成纯函数是为了让单测能覆盖「空段 / 尾部双 NUL / 无终止 NUL」这三种形状，
/// 不必依赖本机插了什么设备 —— 这条解错的表现是"设备凭空少几台"，最难在实机上看出来。
fn parse_mult_sz(buf: &[u16]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        if buf[i] == 0 {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < buf.len() && buf[end] != 0 {
            end += 1;
        }
        out.push(String::from_utf16_lossy(&buf[i..end]));
        i = end + 1;
    }
    out
}

/// 枚举全部设备实例 ID。
fn device_ids() -> Result<Vec<String>, String> {
    unsafe {
        let mut len: u32 = 0;
        let r = CM_Get_Device_ID_List_SizeW(&mut len, PCWSTR::null(), 0);
        if r.0 != 0 {
            return Err(format!("取设备列表长度失败: CONFIGRET={}", r.0));
        }
        // 上限是防御：正常机器上千级别，异常返回值不该让这里分配几百 MB
        if len == 0 || len > 8_000_000 {
            return Err(format!("设备列表长度异常: {len}"));
        }
        let mut buf = vec![0u16; len as usize];
        let r = CM_Get_Device_ID_ListW(PCWSTR::null(), &mut buf, 0);
        if r.0 != 0 {
            return Err(format!("枚举设备列表失败: CONFIGRET={}", r.0));
        }
        Ok(parse_mult_sz(&buf))
    }
}

/// 两段式取一个字符串型设备属性；读不到（属性不存在 / 回执非预期 / 空串）一律 None。
///
/// 第一段（问长度）要同时接受 `CR_SUCCESS` 和 `CR_BUFFER_SMALL=26`：拿 NULL 缓冲问长度
/// 属"缓冲不够"，cfgmgr32 走的是后者。**只认 `r==0` 是本轮 spike 抓到的真错** ——
/// 那样全机设备的 FriendlyName 都被读成"没有"，双条件判定静默退化成"永远查不到设备"，
/// 既不报错也不崩溃，实机上只看得到 0 命中（`live_probe_全量枚举与状态位对照` 的
/// `named > 0` 断言就是为了钉住这一类错位）。
unsafe fn devprop_string(devinst: u32, key: &DEVPROPKEY) -> Option<String> {
    let mut ty = DEVPROPTYPE::default();
    let mut size: u32 = 0;
    let r = CM_Get_DevNode_PropertyW(devinst, key, &mut ty, None, &mut size, 0);
    if !matches!(r.0, 0 | 26) || size < 2 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let r = CM_Get_DevNode_PropertyW(
        devinst,
        key,
        &mut ty,
        Some(buf.as_mut_ptr()),
        &mut size,
        0,
    );
    if r.0 != 0 || size < 2 {
        return None;
    }
    let units: Vec<u16> = buf[..(size as usize).min(buf.len())]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    (!units.is_empty()).then(|| String::from_utf16_lossy(&units))
}

/// 取一个实例的 FriendlyName（没有则 None —— 确有设备根本没有这个属性，
/// 这正是"只按名字匹配"会漏判/误判的原因之一）。
unsafe fn friendly_of(devinst: u32) -> Option<String> {
    devprop_string(devinst, &DEVPKEY_Device_FriendlyName)
}

/// 取一个实例的 DeviceDesc（`Get-PnpDevice` 的 `Name`/`Description` 侧的属性）。
unsafe fn desc_of(devinst: u32) -> Option<String> {
    devprop_string(devinst, &DEVPKEY_Device_DeviceDesc)
}

/// `Get-PnpDevice` 的 `FriendlyName` 列在原生侧的等价取法 —— **不是**单个属性。
///
/// 实机 join 结论（2026-10-01，本机 190 台在册设备，逐台把原生读到的值与
/// `Get-PnpDevice` 输出对照）：`DEVPKEY_Device_FriendlyName` 去空格后非空就用它
/// （41 台），否则退到 `DEVPKEY_Device_DeviceDesc`（148 台），两者皆空 1 台 ——
/// **没有第三种来源**（148+41+1=190，且状态位 190/190 与 `Status` 一致）。
///
/// 这条不是风格问题：只读 `FriendlyName` 会把 148 台（含本域三个目标步骤要用的
/// `High Definition Audio 控制器`、`系统扬声器`）当成"不存在"，双条件判定静默退化。
/// ` FriendlyName ` 属性本身带尾随空格（CPU 那 16 台实测 `"…Processor           "`），
/// CIM 侧已裁掉，所以两边都得裁。
unsafe fn display_name_of(devinst: u32) -> String {
    if let Some(f) = friendly_of(devinst) {
        let t = f.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    desc_of(devinst).map(|d| d.trim().to_string()).unwrap_or_default()
}

/// 按 `Get-PnpDevice` 的 `FriendlyName` 口径（见 `display_name_of`）**精确**匹配
/// （大小写不敏感，等价于 PowerShell 的 `-eq`）查找设备实例，并带 `Status` 判定。
///
/// 刻意不做"包含匹配"或相似度：v2 要求双条件，而名字匹配一旦放宽，
/// 选中的可能就是另一个同名设备。
pub fn find_by_friendly_name(want: &str) -> Result<Vec<DevHit>, String> {
    let want_low = want.trim().to_lowercase();
    let ids = device_ids()?;
    let mut hits = Vec::new();
    for id in ids {
        if hits.len() >= 32 {
            break; // 防御：同名设备异常多时不无限收集
        }
        let wide: Vec<u16> = id.encode_utf16().chain(std::iter::once(0)).collect();
        let mut devinst = 0u32;
        unsafe {
            if CM_Locate_DevNodeW(&mut devinst, PCWSTR(wide.as_ptr()), CM_LOCATE_DEVNODE_FLAGS(0)).0 != 0 {
                continue;
            }
            let shown = display_name_of(devinst);
            if shown.to_lowercase() != want_low {
                continue;
            }
            let mut flags = CM_DEVNODE_STATUS_FLAGS::default();
            let mut problem = CM_PROB::default();
            if CM_Get_DevNode_Status(&mut flags, &mut problem, devinst, 0).0 != 0 {
                continue;
            }
            hits.push(DevHit {
                devinst,
                instance: id,
                started: flags.0 & DN_STARTED.0 != 0,
                has_problem: flags.0 & DN_HAS_PROBLEM.0 != 0,
                status_ok: status_ok_of(flags.0, problem.0),
                problem: problem.0,
                raw_flags: flags.0,
                friendly: friendly_of(devinst).map(|s| s.trim().to_string()).unwrap_or_default(),
                desc: desc_of(devinst).map(|s| s.trim().to_string()).unwrap_or_default(),
            });
        }
    }
    Ok(hits)
}

/// 全部设备的实例 ID + FriendlyName + 状态，供实机对照 `Get-PnpDevice` 全量计数。
/// 只是 spike 用的口径，不进生产路径（生产只按名字查那几台）。
#[allow(dead_code)] // 仅 live_probe 使用；不标会因"未使用"被零警告线卡住
pub fn enumerate_all() -> Result<Vec<DevHit>, String> {
    let ids = device_ids()?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let wide: Vec<u16> = id.encode_utf16().chain(std::iter::once(0)).collect();
        let mut devinst = 0u32;
        unsafe {
            if CM_Locate_DevNodeW(&mut devinst, PCWSTR(wide.as_ptr()), CM_LOCATE_DEVNODE_FLAGS(0)).0 != 0 {
                continue;
            }
            let mut flags = CM_DEVNODE_STATUS_FLAGS::default();
            let mut problem = CM_PROB::default();
            if CM_Get_DevNode_Status(&mut flags, &mut problem, devinst, 0).0 != 0 {
                continue;
            }
            out.push(DevHit {
                devinst,
                friendly: friendly_of(devinst).map(|s| s.trim().to_string()).unwrap_or_default(),
                desc: desc_of(devinst).map(|s| s.trim().to_string()).unwrap_or_default(),
                started: flags.0 & DN_STARTED.0 != 0,
                has_problem: flags.0 & DN_HAS_PROBLEM.0 != 0,
                status_ok: status_ok_of(flags.0, problem.0),
                problem: problem.0,
                raw_flags: flags.0,
                instance: id,
            });
        }
    }
    Ok(out)
}

// ==================== 写入面（2026-10-11：tf_dev_disable 原生化）====================

/// 一次 `@(` 区间的扫描结果（K08）。
struct NameArrayScan {
    /// 有效字面量（**未去重**，按出现顺序）
    raw: Vec<String>,
    /// 被丢弃的引号串数（含 `$` 展开/反引号/未闭合引号）——任何丢弃都让对账失败
    dropped: usize,
    /// 有 `@(` 找不到配对的闭合 `)`
    unterminated: bool,
}

/// 找 `@(` 区间的终点：**引号外、括号深度回到 0** 的那个 `)`（K08）。
///
/// 旧实现（v6-K08 病灶）在首个 `)` 处截断——设备名本身含 `)`（真实数据里 7 条
/// `WAN Miniport (IP)` 一类），`@("…(IP)", …)` 会被切成半截串并在那里结束，
/// 后面 9 条名字整批丢失，而调用方仍按「全做了」回执。
fn find_array_end(chars: &[char], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut j = start;
    while j < chars.len() {
        match chars[j] {
            '\'' | '"' => {
                // 跳过整段引号串：单引号里 `''` 是转义（不闭合），双引号里 `""` 同理
                let q = chars[j];
                j += 1;
                while j < chars.len() {
                    if chars[j] == q {
                        if j + 1 < chars.len() && chars[j + 1] == q {
                            j += 2;
                            continue;
                        }
                        break;
                    }
                    j += 1;
                }
                j += 1; // 越过闭合引号（越界时循环自然结束）
            }
            '(' => {
                depth += 1;
                j += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
                j += 1;
            }
            _ => j += 1,
        }
    }
    None
}

/// 区间内引号字面量抽取（K08）：按 PS 规则处理 `''`/`""` 转义；
/// 双引号里出现 `$` / 反引号 = 展开串，按「丢弃」计（设备名不会是展开串）。
fn extract_literals(seg: &[char], scan: &mut NameArrayScan) {
    let mut j = 0usize;
    while j < seg.len() {
        let q = seg[j];
        if q != '\'' && q != '"' {
            j += 1;
            continue;
        }
        j += 1;
        let mut raw = String::new();
        let mut valid = true;
        let mut closed = false;
        while j < seg.len() {
            if seg[j] == q {
                if j + 1 < seg.len() && seg[j + 1] == q {
                    raw.push(q);
                    j += 2;
                    continue;
                }
                closed = true;
                break;
            }
            if q == '"' && (seg[j] == '$' || seg[j] == '`') {
                valid = false;
            }
            raw.push(seg[j]);
            j += 1;
        }
        if valid && closed && !raw.trim().is_empty() {
            scan.raw.push(raw);
        } else {
            scan.dropped += 1;
        }
        j += 1;
    }
}

/// 扫描全部 `@(` 区间（K08）。
fn scan_name_arrays(script: &str) -> NameArrayScan {
    let chars: Vec<char> = script.chars().collect();
    let mut scan = NameArrayScan { raw: Vec::new(), dropped: 0, unterminated: false };
    let mut i = 0usize;
    while i + 1 < chars.len() {
        if chars[i] != '@' || chars[i + 1] != '(' {
            i += 1;
            continue;
        }
        let Some(end) = find_array_end(&chars, i + 2) else {
            scan.unterminated = true;
            break;
        };
        extract_literals(&chars[i + 2..end], &mut scan);
        i = end + 1;
    }
    scan
}

/// K08 对账用的**独立计数**：所有 `@(` 区间内成对引号字面量的原始条数（含重复）。
/// 与 [`scan_name_arrays`] 是两套遍历实现（这套只数「进入引号串」的次数），
/// 供 [`parse_name_array_checked`] 交叉核对——两套数不一致 = 解析器漏了名字。
pub fn count_name_array_literals(script: &str) -> usize {
    let chars: Vec<char> = script.chars().collect();
    let mut count = 0usize;
    let mut i = 0usize;
    while i + 1 < chars.len() {
        if chars[i] != '@' || chars[i + 1] != '(' {
            i += 1;
            continue;
        }
        let Some(end) = find_array_end(&chars, i + 2) else { break };
        // 区间内逐字符走：进入引号串计一次，`''`/`""` 视为串内转义不另计
        let mut j = i + 2;
        while j < end {
            let q = chars[j];
            if q == '\'' || q == '"' {
                count += 1;
                j += 1;
                while j < end {
                    if chars[j] == q {
                        if j + 1 < end && chars[j + 1] == q {
                            j += 2;
                            continue;
                        }
                        break;
                    }
                    j += 1;
                }
            }
            j += 1;
        }
        i = end + 1;
    }
    count
}

/// 从步骤脚本的 `@("a","b")` / `@('a','b')` 字面量里抽出设备名（K08：带对账）。
///
/// 对账三条（任一不满足即 `Err`，调用方必须 fail-closed，不得按「全做了」回执）：
///   ① 每个 `@(` 都必须有配对的闭合 `)`（按引号配对 + 括号深度，见 [`find_array_end`]）；
///   ② 不得有被丢弃的引号串（`$` 展开/反引号/未闭合）；
///   ③ 解析出的原始条数（去重前）必须等于 [`count_name_array_literals`] 的独立计数。
pub fn parse_name_array_checked(script: &str) -> Result<Vec<String>, String> {
    let scan = scan_name_arrays(script);
    if scan.unterminated {
        return Err("名字数组的 @( 没有配对的闭合括号（截断或畸形脚本），无法安全解析".to_string());
    }
    let literals = count_name_array_literals(script);
    if scan.dropped > 0 || scan.raw.len() != literals {
        return Err(format!(
            "名字数组对账失败：区间内引号字面量 {literals} 个，解析出 {} 个、丢弃 {} 个（含 $ 展开/未闭合）——拒绝按部分名单执行",
            scan.raw.len(),
            scan.dropped
        ));
    }
    // 去重保序（同一名字重复出现只禁一次）
    let mut out: Vec<String> = Vec::new();
    for n in scan.raw {
        if !out.iter().any(|x| *x == n) {
            out.push(n);
        }
    }
    Ok(out)
}

/// 兼容入口：解析不出来按空表返回（调用方的 fail-closed 判据仍是「空表不许全量」）。
pub fn parse_name_array(script: &str) -> Vec<String> {
    parse_name_array_checked(script).unwrap_or_default()
}

/// 一次设备批量状态变更的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PnpSetReport {
    /// 请求的名字数
    pub requested: usize,
    /// 命中 Status=OK 实例且 FFI 调用成功的实例数（一个名字可能对应多实例）
    pub changed_instances: usize,
    /// 没找到任何 Status=OK 实例的名字（跳过，不计失败；对齐 PS -ErrorAction SilentlyContinue）
    pub not_found: Vec<String>,
    /// FFI 返回非 CR_SUCCESS 的失败明细
    pub errors: Vec<String>,
}

impl PnpSetReport {
    /// 供执行层打印到 stdout 的一行摘要（无副作用机器上如实显示 0 命中）
    pub fn summary_line(&self, enable: bool) -> String {
        let verb = if enable { "启用" } else { "禁用" };
        let mut s = format!(
            "PnP {verb}：请求 {} 个名字 / {verb} {} 个实例",
            self.requested, self.changed_instances
        );
        if !self.not_found.is_empty() {
            s.push_str(&format!("（{} 个名字无 Status=OK 设备，已跳过）", self.not_found.len()));
        }
        s
    }
}

/// 按 FriendlyName 精确匹配（双条件：名字相等 + Status=OK）批量禁用/启用设备。
///
/// 与数据层 `Get-PnpDevice | Where { FriendlyName -eq $n -and Status -eq 'OK' } |
/// Disable-PnpDevice -Confirm:$false` 逐字同语义：已停用/有问题的同名设备不选中，
/// 同一个名字的多个实例逐个处理。禁用带 `CM_DISABLE_PERSIST`（重启后仍禁用，
/// 对齐 Disable-PnpDevice 的持久语义）。
///
/// 枚举层失败（CM_Get_Device_ID_List 等）整体返回 Err；个别设备 FFI 失败只进
/// `errors`，不中断其余设备（foreach + SilentlyContinue 语义）。
pub fn set_devices_enabled(names: &[String], enable: bool) -> Result<PnpSetReport, String> {
    let mut report = PnpSetReport {
        requested: names.len(),
        ..Default::default()
    };
    for name in names {
        // 空名字 fail-closed：find_by_friendly_name 按显示名精确匹配，空串会命中
        // FriendlyName/DeviceDesc 都为空的设备（实测 HTREE\ROOT\0 根节点就是），
        // 绝不能让"名字没解析出来"变成"禁用根设备"。
        if name.trim().is_empty() {
            report.errors.push("设备名为空（拒绝执行，请检查步骤脚本）".to_string());
            continue;
        }
        let hits = find_by_friendly_name(name)?;
        // 禁用只选 Status=OK 的（对齐 PS Where Status -eq 'OK'，不动已停用/有问题的设备）；
        // 启用**不能**加这个过滤——目标此刻正是被禁用状态（status_ok=false），
        // 过滤掉就永远启不回来（2026-10-11 真机往返抓到的假成功：not_found 计跳过、
        // errors 为空，设备实际没恢复）。对已启用设备再调一次 CM_Enable 是幂等的。
        let targets: Vec<&DevHit> = if enable {
            hits.iter().collect()
        } else {
            hits.iter().filter(|h| h.status_ok).collect()
        };
        if targets.is_empty() {
            report.not_found.push(name.clone());
            continue;
        }
        for h in targets {
            // SAFETY：devinst 来自同一次枚举的 CM_Locate_DevNode，系统保证句柄有效；
            // CM_Disable/Enable 只做设备状态位变更，不接受指针参数。
            let cr = unsafe {
                if enable {
                    CM_Enable_DevNode(h.devinst, 0)
                } else {
                    CM_Disable_DevNode(h.devinst, CM_DISABLE_PERSIST)
                }
            };
            if cr.0 == 0 {
                report.changed_instances += 1;
            } else {
                report.errors.push(format!(
                    "{}（{}）CONFIGRET={}",
                    name, h.instance, cr.0
                ));
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 多字符串解码覆盖空段与缺终止() {
        // 正常：两个条目 + 结尾双 NUL
        let a: Vec<u16> = "PCI\\A\0USB\\B\0\0".encode_utf16().collect();
        assert_eq!(parse_mult_sz(&a), vec!["PCI\\A", "USB\\B"]);
        // 前导/连续 NUL 不产出空串
        let b: Vec<u16> = "\0\0ROOT\\X\0\0".encode_utf16().collect();
        assert_eq!(parse_mult_sz(&b), vec!["ROOT\\X"]);
        // 缓冲区被截断（末条没有终止 NUL）也要收进来看见，不能静默丢
        let c: Vec<u16> = "ROOT\\Y".encode_utf16().collect();
        assert_eq!(parse_mult_sz(&c), vec!["ROOT\\Y"]);
        assert_eq!(parse_mult_sz(&[]), Vec::<String>::new());
    }

    #[test]
    fn 状态判定要求双条件() {
        assert!(status_ok_of(DN_STARTED.0, 0));
        // 有 DN_HAS_PROBLEM 位就不是 OK，哪怕 problem 被读成 0（防"只信 problem"）
        assert!(!status_ok_of(DN_STARTED.0 | DN_HAS_PROBLEM.0, 0));
        // 有问题码就不是 OK
        assert!(!status_ok_of(DN_STARTED.0, 22));
        // 没启动位但也没有问题 —— 按本判据仍算 OK，这正是 live probe 要对照的一条：
        // Get-PnpDevice 对停用设备给的是 Status=Error/Unknown 还是 OK，不靠猜。
        assert!(status_ok_of(0, 0));
    }

    /// 只读实跑：三个目标步骤的名字（上游写的是**英文原名**）加上它们在本机的
    /// 本地化写法，各查一遍并打印命中数 —— 打印出来就是为了记录"上游那几个英文名
    /// 在中文 Windows 上到底命中几台"这件事，不靠推断。
    ///
    /// 不断言命中数：命中 0 也是有效结论（见模块头的 A3 结论 ③）。
    #[test]
    #[ignore = "真实枚举全部 PnP 设备（只读），发布前门禁跑"]
    fn live_probe_按友好名枚举设备() {
        for want in [
            // 上游 optimizer-scripts.js 里的字面量
            "High Definition Audio Controller",
            "Root Print Queue",
            "System Speaker",
            // 同义设备在中文系统上的实际显示名
            "High Definition Audio 控制器",
            "系统扬声器",
        ] {
            let hits = find_by_friendly_name(want).unwrap_or_else(|e| panic!("{want}: 枚举失败 {e}"));
            let ok = hits.iter().filter(|h| h.status_ok).count();
            println!("{want}: 命中 {} 台，其中 Status=OK {ok} 台", hits.len());
            for h in hits.iter().take(3) {
                println!(
                    "   {} started={} has_problem_bit={} prob={} raw=0x{:X} F=[{}] D=[{}]",
                    h.instance, h.started, h.has_problem, h.problem, h.raw_flags, h.friendly, h.desc
                );
            }
        }
    }

    /// 只读实跑：全量枚举，打印三件事 ——
    /// ① 总台数 / `status_ok` 台数（与 `Get-PnpDevice -PresentOnly` 和 `Status -eq OK` 对照）
    /// ② `DEVPKEY_Device_FriendlyName` 与 `DEVPKEY_Device_DeviceDesc` 各自的非空台数
    ///    （这一条决定原生侧该拿哪个属性去复现 `Get-PnpDevice` 的 `FriendlyName` 列）
    /// ③ 每行 `ROW\t实例ID\tFriendlyName\tDeviceDesc\tstatus_ok`，供与 PS 输出做逐台 join
    ///
    /// 断言只写在**不依赖具体硬件**的量上：列表非空、实例 ID 不重复、属性非空率过半。
    #[test]
    #[ignore = "真实枚举全部 PnP 设备（只读，约数百台），发布前门禁跑"]
    fn live_probe_全量枚举与状态位对照() {
        let all = enumerate_all().expect("全量枚举失败");
        assert!(!all.is_empty(), "一台设备都枚举不到，说明绑定或调用姿势错了");
        let mut ids = all.iter().map(|h| h.instance.as_str()).collect::<Vec<_>>();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(n, ids.len(), "实例 ID 不应重复");
        let named = all.iter().filter(|h| !h.friendly.is_empty()).count();
        let desc = all.iter().filter(|h| !h.desc.is_empty()).count();
        let either = all.iter().filter(|h| !h.friendly.is_empty() || !h.desc.is_empty()).count();
        let ok = all.iter().filter(|h| h.status_ok).count();
        let started = all.iter().filter(|h| h.started).count();
        let prob = all.iter().filter(|h| h.problem != 0).count();
        println!(
            "原生枚举：总 {n} 台 / status_ok {ok} 台 / DN_STARTED 置位 {started} 台 / 问题码非零 {prob} 台"
        );
        println!("属性非空：FriendlyName {named} 台 / DeviceDesc {desc} 台 / 两者至少其一 {either} 台");
        for h in &all {
            println!(
                "ROW\t{}\t{}\t{}\t{}",
                h.instance,
                h.friendly.replace('\t', " "),
                h.desc.replace('\t', " "),
                if h.status_ok { "OK" } else { "NOTOK" }
            );
        }
        // 这两条与硬件无关，专治"属性读取姿势错了但全程不报错"：
        // 正常机器不可能一台都读不到名字，也不可能一半以上设备两个属性全空。
        assert!(named > 0, "全机设备读不到任何 FriendlyName —— 属性调用姿势错了，不是这台机器没设备");
        assert!(either * 2 >= n, "FriendlyName/DeviceDesc 两个属性同时缺失过半，属性侧不可用");
        // 回退链的**可判红**断言：找一台只有 DeviceDesc 的设备，按那个名字查必须命中它。
        // 本轮第一版就是只读 FriendlyName，在这里会返回 0 台（而且全程不报错）。
        let probe = all
            .iter()
            .find(|h| h.friendly.is_empty() && !h.desc.is_empty())
            .map(|h| (h.instance.clone(), h.desc.clone()));
        match probe {
            Some((instance, desc)) => {
                let hits = find_by_friendly_name(&desc).expect("按 DeviceDesc 回退名查询失败");
                assert!(
                    hits.iter().any(|h| h.instance == instance),
                    "设备 {instance} 的 FriendlyName 为空、DeviceDesc=[{desc}]，按该名字却查不到它 —— 回退链断了"
                );
                println!("回退链：按 DeviceDesc「{desc}」查到 {} 台，含源实例", hits.len());
            }
            None => println!("回退链：本机没有「FriendlyName 为空但有 DeviceDesc」的设备，本轮未覆盖（不算失败）"),
        }
    }

    #[test]
    fn 名字数组解析覆盖双单引号与去重() {
        // 数据层原脚本（全选，双引号、带 $names 赋值）
        let full = r#"$names = @("High Precision Event Timer","Microsoft GS Wavetable Synth","System Speaker")
foreach ($n in $names) { Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -eq $n -and $_.Status -eq "OK" } | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue }"#;
        assert_eq!(
            parse_name_array(full),
            vec![
                "High Precision Event Timer",
                "Microsoft GS Wavetable Synth",
                "System Speaker"
            ]
        );
        // subitems 重建脚本（子集，单引号）
        let picked = "$picked = @('System Speaker','Amdlog')\nforeach ($n in $picked) { Get-PnpDevice | Disable-PnpDevice }";
        assert_eq!(parse_name_array(picked), vec!["System Speaker", "Amdlog"]);
        // 同一名字重复出现（赋值 + 别处引用不产生重复项——这里只在一个 @() 内去重）
        assert_eq!(
            parse_name_array("@('a','a','b')"),
            vec!["a".to_string(), "b".to_string()]
        );
        // 没有 @( 数组 = 空（调用方必须 fail-closed，不能当成全量）
        assert!(parse_name_array("Disable-PnpDevice -Confirm:$false").is_empty());
        // 双引号里带 $ 展开的串不接受（设备名不该长这样）
        assert!(parse_name_array(r#"@("$env:X")"#).is_empty());
        // 单引号转义 '' → '
        assert_eq!(parse_name_array("@('a''b')"), vec!["a'b".to_string()]);
    }

    /// K08：名字里带 `)` 不得截断——旧实现在首个 `)` 处切段，`WAN Miniport (IP)`
    /// 一类名字会把后面的条目整批丢掉（真实数据 16/25）。
    /// 判红自证：把 `find_array_end` 改回「首个 `)` 即终点」⇒ 本用例红。
    #[test]
    fn 名字数组括号深度解析不吃名字里的右括号() {
        let script = r#"$names = @("WAN Miniport (IP)","WAN Miniport (IKEv2)","System Speaker")
foreach ($n in $names) { Get-PnpDevice | Where-Object { $_.FriendlyName -eq $n -and $_.Status -eq "OK" } | Disable-PnpDevice -Confirm:$false }"#;
        assert_eq!(
            parse_name_array_checked(script).expect("括号深度解析必须成功"),
            vec!["WAN Miniport (IP)", "WAN Miniport (IKEv2)", "System Speaker"]
        );
        // 对账的独立计数与解析条数一致（3 个引号字面量）
        assert_eq!(count_name_array_literals(script), 3);
        // 括号深度：名字里嵌套两层括号也不截断
        let nested = r#"@("A (B (C))","D")"#;
        assert_eq!(parse_name_array_checked(nested).unwrap(), vec!["A (B (C))", "D"]);
        // 截断形态（没有配对闭括号）⇒ Err，不得按空表继续
        assert!(parse_name_array_checked(r#"@("a","b""#).is_err(), "未闭合数组必须 Err");
        // 展开串 ⇒ Err（对账失败），parse_name_array 兼容入口回空表
        assert!(parse_name_array_checked(r#"@("$env:X")"#).is_err());
        assert!(parse_name_array(r#"@("$env:X")"#).is_empty());
    }

    /// K08 验收：**真实数据 25/25**（v6-A6 现算：旧实现 16/25，丢 9 条含 7 个带
    /// `)` 的 WAN Miniport）。数据文件本身是签名数据，本批只读不改（D5 拍板：
    /// 结构化 names 留技术债）。
    /// 判红自证：解析退回首个 `)` 截断 ⇒ 条数 16 ≠ 25 红。
    #[test]
    fn 真实设备名单数据解析二十五条() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data/optimizer-runtime.json");
        let raw = std::fs::read_to_string(&path).expect("读得到 data/optimizer-runtime.json");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("数据文件是合法 JSON");
        let entry = v
            .as_array()
            .expect("顶层是数组")
            .iter()
            .find(|e| e.get("id").and_then(|x| x.as_str()) == Some("tf_dev_disable"))
            .expect("找得到 tf_dev_disable 条目");
        let script = entry["steps"][0]["pwsh"].as_str().expect("步骤里有 pwsh 脚本");
        let names = parse_name_array_checked(script).expect("真实数据必须通过对账");
        assert_eq!(names.len(), 25, "真实数据 25 条名字，解析出 {}: {names:?}", names.len());
        assert_eq!(count_name_array_literals(script), 25, "独立计数也必须是 25");
        // A6 现算丢失的 9 条：7 个带 `)` 的 WAN Miniport + 两条排在截断点之后的
        for lost in [
            "WAN Miniport (IP)",
            "WAN Miniport (IKEv2)",
            "WAN Miniport (L2TP)",
            "WAN Miniport (PPPOE)",
            "WAN Miniport (PPTP)",
            "WAN Miniport (SSTP)",
            "WAN Miniport (Network Monitor)",
            "High Definition Audio Controller",
            "Root Print Queue",
        ] {
            assert!(names.iter().any(|n| n == lost), "丢名字了：{lost}");
        }
        // 首条与去重保序
        assert_eq!(names[0], "High Precision Event Timer");
    }

    /// 真机往返：找一台 Status=OK 的设备，禁用后立刻启用回来。
    ///
    /// 选「系统扬声器/System Speaker」（System 类实体设备），禁用无功能损失且可恢复；
    /// 刻意排除 `HTREE\ROOT\0` —— legacy Beep 驱动的 DeviceDesc 也叫 "Beep"，但它挂在
    /// 设备树根节点上，禁不掉（CR_ACCESS_DENIED），拿它做往返是假目标。机器上不存在
    /// 目标设备时打印跳过、不算失败。发布前门禁组跑。
    #[test]
    #[ignore = "真实禁用/启用设备（有副作用但自恢复），发布前门禁组跑"]
    fn live_probe_设备禁用启用往返() {
        let mut target: Option<(String, DevHit)> = None;
        for want in ["System Speaker", "系统扬声器"] {
            if let Ok(hits) = find_by_friendly_name(want) {
                if let Some(h) = hits
                    .into_iter()
                    .filter(|h| h.status_ok && h.instance != "HTREE\\ROOT\\0")
                    .next()
                {
                    target = Some((want.to_string(), h));
                    break;
                }
            }
        }
        let Some((want, h)) = target else {
            println!("本机没有可用于往返的蜂鸣器设备，跳过（不算失败）");
            return;
        };
        // 回查必须用查询名（want），不能用 h.friendly —— ACPI 扬声器的 FriendlyName
        // 属性为空（命中靠 DeviceDesc），空串会匹配到显示名也为空的根设备 HTREE\ROOT\0。
        let one = vec![want];
        let off = set_devices_enabled(&one, false).expect("禁用枚举失败");
        println!("禁用报告: {:?}", off);
        // 再查一次：它应当不再 Status=OK
        let after_off = find_by_friendly_name(&one[0]).unwrap_or_default();
        assert!(
            after_off.iter().all(|x| !x.status_ok || x.devinst != h.devinst),
            "禁用后设备仍 Status=OK"
        );
        let on = set_devices_enabled(&one, true).expect("启用枚举失败");
        println!("启用报告: {:?}", on);
        assert_eq!(on.errors.len(), 0, "恢复启用失败: {:?}", on.errors);
    }
}
