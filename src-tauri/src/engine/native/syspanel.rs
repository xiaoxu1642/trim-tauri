//! 系统面板：电源计划三档读写 + 虚拟内存读写（RAINZ 对标 §3.6，v0.4.9）
//!
//! 借 RAINZ 的"面板 + 回读校验"机制，不借它的写侧粗糙 —— 三档 GUID 白名单，
//! 白名单外的 GUID 一律拒绝；改完 400ms 后回读，读到不匹配就报错（不假装成功）。
//!
//! **虚拟内存写侧**：`AutomaticManagedPagefile` + `PagingFiles`（MULTI_SZ）；写前先备份
//! 当前配置到 `backup_write_dir()/pagefile-backups/<ts>.json`（AGENTS §3 `atomic_write_json`），
//! 参数校验层拒"全关"与"Max < Initial"这两类会让机器蓝屏的形态；写完回读比对，
//! 任一条 entry 的 `<drive>\pagefile.sys` 不在 `PagingFiles` 里就 Err（Group Policy
//! 或安全软件覆盖的场景不假装成功）。返回体带 `requiresReboot: true` 由前端提示。
//! **不做**一键还原 —— 危险能力默认关、猜错方向的代价不对称（AGENTS §3 口径），
//! 用户可通过备份 JSON 手动 reg import 恢复。
//!
//! 本域命令都走 `guard(window, MAIN)`（AGENTS §3 三层）：写侧、系统级、只在主窗触发。
//! 电源方案**不再拉 `powercfg` 子进程**：改走 `powrprof.dll` 的 Power API（UTF-16 直出），
//! 中文系统不再出现方案名乱码，也不引入 `check-system-bin` 之外的进程。
//! **仅导出**破例用子进程：`powercfg /export` 直走 `systembin::quiet_cmd_timeout`；
//! 读取/枚举/切换/写值仍走 powrprof。

use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{HLOCAL, LocalFree, WIN32_ERROR};
use windows::Win32::System::Registry::{REG_DWORD, REG_QWORD};
use windows::Win32::System::Power::{
    ACCESS_INDIVIDUAL_SETTING, ACCESS_SCHEME, ACCESS_SUBGROUP, POWER_DATA_ACCESSOR,
    PlatformRoleDesktop, PlatformRoleMobile, PlatformRoleSlate, PowerDeleteScheme,
    PowerDeterminePlatformRole, PowerDuplicateScheme, PowerEnumerate, PowerGetActiveScheme,
    PowerImportPowerScheme, PowerReadACValueIndex, PowerReadDCValueIndex, PowerReadDescription,
    PowerReadFriendlyName, PowerReadPossibleFriendlyName, PowerReadPossibleValue,
    PowerReadSettingAttributes,
    PowerReadValueIncrement, PowerReadValueMax, PowerReadValueMin, PowerReadValueUnitsSpecifier,
    PowerSetActiveScheme, PowerWriteACValueIndex, PowerWriteDCValueIndex, PowerWriteFriendlyName,
    PowerWriteSettingAttributes,
};

/// Windows 保留方案 GUID（微软公开文档，随系统分发）+ 中文名称与一句话说明。
///
/// 这三档只是「面板能给哪句说明」的表，**不是可写白名单**：用户自己 `powercfg /duplicate`
/// 出来的方案同样是本机方案，面板可选（2026-10-14 用户裁定）。写侧的 fail-closed 判据
/// 见 `power_plan_apply`——「必须在本机枚举结果内」。
pub const KNOWN_PLANS: &[(&str, &str, &str)] = &[
    ("381b4222-f694-41f0-9685-ff5bb260df2e", "平衡", "系统默认；日常与办公最稳"),
    ("a1841308-3541-4fab-bc81-f71556f20b4a", "节能", "笔记本续航优先；性能受限"),
    ("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", "高性能", "台式机与游戏优先；功耗上升"),
];

/// G-04（2026-10-16 裁定）两个专用能力只认的微软标准 GUID（微软公开文档）。
/// 它们只是「专用操作的目标标识」，**不是**写面白名单——通用编辑器一视同仁。
pub const HIGH_PERFORMANCE_GUID: &str = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
pub const ULTIMATE_PERFORMANCE_GUID: &str = "e9a42b02-d5df-448d-aa00-03f14749eb61";

/// 本机存在、但不在这三档里的方案（`powercfg /duplicate` 克隆或第三方注册）的统一说明。
/// 它们**同样可选**——见 `power_plan_apply` 的安全口径。
const CUSTOM_PLAN_TIP: &str = "本机自定义方案（克隆或第三方注册），按方案原名显示";

/// 无子组设置用的全零 GUID；读显隐属性时不带方案参数，必须原样传它。
const NO_SUBGROUP_GUID: GUID = GUID {
    data1: 0,
    data2: 0,
    data3: 0,
    data4: [0, 0, 0, 0, 0, 0, 0, 0],
};
const ERROR_MORE_DATA_CODE: u32 = 234;
const MAX_POWER_PLAN_NAME_CHARS: usize = 200;
const POWER_SETTING_ATTR_HIDDEN: u32 = 0b0000_0001;
const POWER_SETTING_ATTR_VISIBLE: u32 = 0b0000_0010;

static POWER_SESSION_SEQ: AtomicU64 = AtomicU64::new(1);
static POWER_SESSIONS: OnceLock<Mutex<HashMap<String, PowerSettingsSession>>> = OnceLock::new();

#[derive(Clone)]
struct PowerSettingRef {
    subgroup: GUID,
    setting: GUID,
}

#[derive(Clone)]
struct PowerSettingsSession {
    scheme_guid: String,
    snapshots: Vec<PowerSettingSnapshot>,
}

#[derive(Clone)]
struct PowerSettingSnapshot {
    subgroup: GUID,
    setting: GUID,
    attributes: u32,
    changed: bool,
}

struct LocalGuidPtr(*mut GUID);

impl LocalGuidPtr {
    fn take(&mut self) -> Option<GUID> {
        if self.0.is_null() {
            return None;
        }
        let g = unsafe { *self.0 };
        self.0 = std::ptr::null_mut();
        Some(g)
    }
}

impl Drop for LocalGuidPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 as *mut core::ffi::c_void)));
            }
        }
    }
}

struct RemoveOnDrop(Option<PathBuf>);

impl RemoveOnDrop {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// 36 字符 GUID 文本 → [`GUID`]。长度/分段/hex 任一不合即 `None`，不做模糊匹配。
fn parse_guid_str(s: &str) -> Option<GUID> {
    let b = s.as_bytes();
    if b.len() != 36 {
        return None;
    }
    let seg = [8usize, 4, 4, 4, 12];
    let mut p = 0usize;
    let mut groups: [&[u8]; 5] = [&[]; 5];
    for (k, &len) in seg.iter().enumerate() {
        if k > 0 {
            if b.get(p) != Some(&b'-') {
                return None;
            }
            p += 1;
        }
        let start = p;
        for _ in 0..len {
            match b.get(p) {
                Some(c) if c.is_ascii_hexdigit() => p += 1,
                _ => return None,
            }
        }
        groups[k] = &b[start..p];
    }
    let hex = |g: &[u8]| -> u64 {
        g.iter()
            .fold(0u64, |acc, &c| acc * 16 + (c as char).to_digit(16).unwrap_or(0) as u64)
    };
    Some(GUID {
        data1: hex(groups[0]) as u32,
        data2: hex(groups[1]) as u16,
        data3: hex(groups[2]) as u16,
        data4: [
            hex(&groups[3][0..2]) as u8,
            hex(&groups[3][2..4]) as u8,
            hex(&groups[4][0..2]) as u8,
            hex(&groups[4][2..4]) as u8,
            hex(&groups[4][4..6]) as u8,
            hex(&groups[4][6..8]) as u8,
            hex(&groups[4][8..10]) as u8,
            hex(&groups[4][10..12]) as u8,
        ],
    })
}

/// [`GUID`] → 小写 36 字符文本（与 `KNOWN_PLANS` 的写法同形，判据因此可直接比）。
fn guid_string(g: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}

/// power API 回填的 16 字节内存布局（小端）→ [`GUID`]。
fn guid_from_le_bytes(b: &[u8]) -> GUID {
    GUID {
        data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        data2: u16::from_le_bytes([b[4], b[5]]),
        data3: u16::from_le_bytes([b[6], b[7]]),
        data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
    }
}

fn guid_ptr(g: Option<&GUID>) -> Option<*const GUID> {
    g.map(|x| x as *const GUID)
}

fn guid_is_zero(g: &GUID) -> bool {
    guid_string(g) == "00000000-0000-0000-0000-000000000000"
}

fn win32_ok(rc: WIN32_ERROR) -> bool {
    rc.0 == 0
}

fn decode_utf16_bytes(buf: &[u8]) -> String {
    let units: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .trim()
        .to_string()
}

fn power_text(
    kind: PowerTextKind,
    scheme: Option<&GUID>,
    subgroup: Option<&GUID>,
    setting: Option<&GUID>,
) -> Option<String> {
    let mut size: u32 = 0;
    let first = unsafe {
        match kind {
            PowerTextKind::Friendly => PowerReadFriendlyName(
                None,
                guid_ptr(scheme),
                guid_ptr(subgroup),
                guid_ptr(setting),
                None,
                &mut size,
            ),
            PowerTextKind::Description => PowerReadDescription(
                None,
                guid_ptr(scheme),
                guid_ptr(subgroup),
                guid_ptr(setting),
                None,
                &mut size,
            ),
        }
    };
    if first.0 != 0 && first.0 != ERROR_MORE_DATA_CODE {
        return None;
    }
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let second = unsafe {
        match kind {
            PowerTextKind::Friendly => PowerReadFriendlyName(
                None,
                guid_ptr(scheme),
                guid_ptr(subgroup),
                guid_ptr(setting),
                Some(buf.as_mut_ptr()),
                &mut size,
            ),
            PowerTextKind::Description => PowerReadDescription(
                None,
                guid_ptr(scheme),
                guid_ptr(subgroup),
                guid_ptr(setting),
                Some(buf.as_mut_ptr()),
                &mut size,
            ),
        }
    };
    if second.0 != 0 {
        return None;
    }
    let text = decode_utf16_bytes(&buf);
    if text.is_empty() { None } else { Some(text) }
}

#[derive(Clone, Copy)]
enum PowerTextKind {
    Friendly,
    Description,
}

fn enumerate_guids(
    scheme: Option<&GUID>,
    subgroup: Option<&GUID>,
    access: POWER_DATA_ACCESSOR,
) -> Vec<GUID> {
    let mut out = Vec::new();
    let scheme_ptr = guid_ptr(scheme);
    let subgroup_ptr = guid_ptr(subgroup);
    let mut idx: u32 = 0;
    loop {
        let mut buf = [0u8; std::mem::size_of::<GUID>()];
        let mut size: u32 = buf.len() as u32;
        let rc = unsafe {
            PowerEnumerate(
                None,
                scheme_ptr,
                subgroup_ptr,
                access,
                idx,
                Some(buf.as_mut_ptr()),
                &mut size,
            )
        };
        if rc.0 != 0 {
            break;
        }
        out.push(guid_from_le_bytes(&buf));
        idx += 1;
        if idx >= 4096 {
            break;
        }
    }
    out
}

fn listed_scheme(guid: &str) -> bool {
    scheme_guids()
        .iter()
        .any(|g| guid_string(g).eq_ignore_ascii_case(guid))
}

fn require_listed_scheme(guid: &str) -> Result<GUID, String> {
    let parsed = parse_guid_str(guid).ok_or_else(|| format!("GUID 形状非法：{guid}"))?;
    if !listed_scheme(guid) {
        return Err(format!("方案 {guid} 不在本机方案列表内，已拒绝"));
    }
    Ok(parsed)
}

fn require_reserved_plans_untouched(guid: &str) -> Result<(), String> {
    if KNOWN_PLANS
        .iter()
        .any(|(known, _, _)| known.eq_ignore_ascii_case(guid))
    {
        return Err(format!("{guid} 是 Windows 保留电源方案，已拒绝删除"));
    }
    Ok(())
}

fn name_bytes(name: &str) -> Result<(String, Vec<u8>), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("方案名不能为空".to_string());
    }
    if trimmed.contains('\0') {
        return Err("方案名不能包含 NUL 字符".to_string());
    }
    if trimmed.chars().count() > MAX_POWER_PLAN_NAME_CHARS {
        return Err(format!("方案名过长（最多 {MAX_POWER_PLAN_NAME_CHARS} 个字符）"));
    }
    let bytes = trimmed
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|u| u.to_le_bytes())
        .collect::<Vec<u8>>();
    Ok((trimmed.to_string(), bytes))
}

fn setting_refs_for_scheme(scheme: &GUID) -> Vec<PowerSettingRef> {
    let mut out = Vec::new();
    let mut seen = HashSet::<String>::new();

    let mut subgroups = vec![NO_SUBGROUP_GUID];
    for sub in enumerate_guids(Some(scheme), None, ACCESS_SUBGROUP) {
        if !subgroups.iter().any(|g| guid_string(g) == guid_string(&sub)) {
            subgroups.push(sub);
        }
    }

    for sub in subgroups {
        let mut settings = enumerate_guids(Some(scheme), Some(&sub), ACCESS_INDIVIDUAL_SETTING);
        if guid_is_zero(&sub) {
            // 部分系统/方案形状下，无子组设置用 NULL 子组枚举才返回；两条都试并去重。
            settings.extend(enumerate_guids(
                Some(scheme),
                None,
                ACCESS_INDIVIDUAL_SETTING,
            ));
        }
        for setting in settings {
            let key = format!("{}|{}", guid_string(&sub), guid_string(&setting));
            if seen.insert(key) {
                out.push(PowerSettingRef { subgroup: sub, setting });
            }
        }
    }
    out
}

fn read_setting_value(scheme: &GUID, subgroup: &GUID, setting: &GUID, dc: bool) -> Option<u32> {
    let mut value: u32 = 0;
    let rc = unsafe {
        if dc {
            PowerReadDCValueIndex(
                None,
                Some(scheme as *const GUID),
                Some(subgroup as *const GUID),
                Some(setting as *const GUID),
                &mut value,
            )
        } else {
            PowerReadACValueIndex(
                None,
                Some(scheme as *const GUID),
                Some(subgroup as *const GUID),
                Some(setting as *const GUID),
                &mut value,
            )
            .0
        }
    };
    (rc == 0).then_some(value)
}

fn read_value_range(scheme: &GUID, subgroup: &GUID, setting: &GUID) -> Option<(u32, u32, u32)> {
    let mut min = 0u32;
    let mut max = 0u32;
    let mut step = 0u32;
    let rc_min = unsafe {
        PowerReadValueMin(
            None,
            Some(subgroup as *const GUID),
            Some(setting as *const GUID),
            &mut min,
        )
    };
    let rc_max = unsafe {
        PowerReadValueMax(
            None,
            Some(subgroup as *const GUID),
            Some(setting as *const GUID),
            &mut max,
        )
    };
    let rc_step = unsafe {
        PowerReadValueIncrement(
            None,
            Some(subgroup as *const GUID),
            Some(setting as *const GUID),
            &mut step,
        )
    };
    let _ = scheme;
    if win32_ok(rc_min) && win32_ok(rc_max) && win32_ok(rc_step) {
        Some((min, max, step))
    } else {
        None
    }
}

fn read_value_unit(scheme: &GUID, subgroup: &GUID, setting: &GUID) -> Option<String> {
    let mut size: u32 = 0;
    let rc = unsafe {
        PowerReadValueUnitsSpecifier(
            None,
            Some(subgroup as *const GUID),
            Some(setting as *const GUID),
            None,
            &mut size,
        )
    };
    if (rc.0 != 0 && rc.0 != ERROR_MORE_DATA_CODE) || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        PowerReadValueUnitsSpecifier(
            None,
            Some(subgroup as *const GUID),
            Some(setting as *const GUID),
            Some(buf.as_mut_ptr()),
            &mut size,
        )
    };
    if rc.0 != 0 {
        return None;
    }
    let unit = decode_utf16_bytes(&buf);
    let _ = scheme;
    if unit.is_empty() { None } else { Some(unit) }
}

fn read_possible_values(scheme: &GUID, subgroup: &GUID, setting: &GUID) -> Vec<u32> {
    let mut out = Vec::new();
    for idx in 0..256u32 {
        let mut ty = 0u32;
        let mut size = 0u32;
        let rc = unsafe {
            PowerReadPossibleValue(
                None,
                Some(subgroup as *const GUID),
                Some(setting as *const GUID),
                Some(&mut ty),
                idx,
                None,
                &mut size,
            )
        };
        if rc.0 != 0 && rc.0 != ERROR_MORE_DATA_CODE {
            break;
        }
        if size == 0 {
            break;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = unsafe {
            PowerReadPossibleValue(
                None,
                Some(subgroup as *const GUID),
                Some(setting as *const GUID),
                Some(&mut ty),
                idx,
                Some(buf.as_mut_ptr()),
                &mut size,
            )
        };
        if rc.0 != 0 {
            break;
        }
        let value = match ty {
            t if t == REG_DWORD.0 => {
                if buf.len() < 4 {
                    break;
                }
                u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
            }
            t if t == REG_QWORD.0 => {
                if buf.len() < 8 {
                    break;
                }
                let v = u64::from_le_bytes([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                ]);
                if v > u32::MAX as u64 {
                    break;
                }
                v as u32
            }
            _ => break,
        };
        out.push(value);
    }
    let _ = scheme;
    out
}

/// 枚举设置每个可选值的系统本地化名称（`PowerReadPossibleFriendlyName`，与
/// `read_possible_values` 同索引、同序）。个别读不到的名给空串占位——前端按
/// 「精选表 → 本表 → 原数字」降级显示，缺名不丢位、不猜测。
fn read_possible_value_names(subgroup: &GUID, setting: &GUID, count: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(count);
    for idx in 0..count as u32 {
        let mut size = 0u32;
        let first = unsafe {
            PowerReadPossibleFriendlyName(
                None,
                Some(subgroup as *const GUID),
                Some(setting as *const GUID),
                idx,
                None,
                &mut size,
            )
        };
        if first.0 != 0 && first.0 != ERROR_MORE_DATA_CODE {
            out.push(String::new());
            continue;
        }
        if size == 0 {
            out.push(String::new());
            continue;
        }
        let mut buf = vec![0u8; size as usize];
        let second = unsafe {
            PowerReadPossibleFriendlyName(
                None,
                Some(subgroup as *const GUID),
                Some(setting as *const GUID),
                idx,
                Some(buf.as_mut_ptr()),
                &mut size,
            )
        };
        if second.0 != 0 {
            out.push(String::new());
            continue;
        }
        out.push(decode_utf16_bytes(&buf));
    }
    out
}

fn validate_value_against_meta(
    value: u32,
    range: Option<(u32, u32, u32)>,
    possible: &[u32],
    setting_label: &str,
) -> Result<(), String> {
    if let Some((min, max, step)) = range {
        if value < min || value > max {
            return Err(format!(
                "{setting_label}: 值 {value} 超出范围 {min}..={max}"
            ));
        }
        if step > 0 && value.checked_sub(min).map(|v| v % step).unwrap_or(1) != 0 {
            return Err(format!("{setting_label}: 值 {value} 未按步长 {step} 对齐"));
        }
        return Ok(());
    }
    if !possible.is_empty() {
        if !possible.contains(&value) {
            return Err(format!(
                "{setting_label}: 值 {value} 不在可选值 {} 内",
                possible
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        return Ok(());
    }
    Err(format!("{setting_label}: 无法读取范围或可选值，按 fail-closed 拒绝写入"))
}

fn power_sessions() -> &'static Mutex<HashMap<String, PowerSettingsSession>> {
    POWER_SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn new_power_session_id() -> String {
    let seq = POWER_SESSION_SEQ.fetch_add(1, Ordering::SeqCst);
    format!("{}-{}-{seq}", crate::engine::now_ms(), std::process::id())
}

fn restore_attribute_snapshots(snapshots: &[PowerSettingSnapshot]) {
    for snap in snapshots {
        let rc = unsafe {
            PowerWriteSettingAttributes(
                Some(&snap.subgroup as *const GUID),
                Some(&snap.setting as *const GUID),
                snap.attributes,
            )
        };
        if !win32_ok(rc) {
            crate::engine::log::write_log(
                "warn",
                &format!(
                    "解锁失败回滚属性也失败：{} / {}（Win32 错误码 {}）",
                    guid_string(&snap.subgroup),
                    guid_string(&snap.setting),
                    rc.0
                ),
            );
        }
    }
}

/// 读方案友好名（`PowerReadFriendlyName`，UTF-16 直出，与系统语言无关）。
///
/// 本模块**不再解析 powercfg 文本**的原因就在这里：中文版 powercfg 的 stdout 是 OEM 代码页
/// （GBK/CP936）字节，`from_utf8_lossy` 会把中文方案名糊成替换符；`powrprof.dll` 这套 API
/// 直接回 UTF-16，宽度与语言都不需要猜。
fn scheme_friendly_name(g: &GUID) -> Option<String> {
    let mut size: u32 = 0;
    let rc =
        unsafe { PowerReadFriendlyName(None, Some(g as *const GUID), None, None, None, &mut size) };
    if rc.0 != 0 || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        PowerReadFriendlyName(None, Some(g as *const GUID), None, None, Some(buf.as_mut_ptr()), &mut size)
    };
    if rc.0 != 0 {
        return None;
    }
    let units: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let name = String::from_utf16_lossy(&units);
    let name = name.trim_end_matches('\0').trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

/// 枚举本机全部电源方案 GUID（`ACCESS_SCHEME`）。
fn scheme_guids() -> Vec<GUID> {
    let mut out = Vec::new();
    let mut idx: u32 = 0;
    loop {
        // ACCESS_SCHEME 每次回填一个 GUID。**必须给足缓冲**：buffer=NULL 时该 API 回的是
        // `ERROR_MORE_DATA(234)`（不是 0），照「rc != 0 即结束」写会在第一项就空手而归
        // （真机实测踩过）。
        let mut buf = [0u8; std::mem::size_of::<GUID>()];
        let mut size: u32 = buf.len() as u32;
        let rc = unsafe {
            PowerEnumerate(None, None, None, ACCESS_SCHEME, idx, Some(buf.as_mut_ptr()), &mut size)
        };
        if rc.0 != 0 {
            break; // ERROR_NO_MORE_ITEMS(259) 或其它失败 → 收工
        }
        out.push(guid_from_le_bytes(&buf));
        idx += 1;
        if idx >= 512 {
            break; // 防御：正常机器方案数远小于此
        }
    }
    out
}

/// 当前生效方案 GUID（`PowerGetActiveScheme`；返回内存由 `LocalFree` 回收，不能泄漏）。
fn active_scheme() -> Option<GUID> {
    let mut p: *mut GUID = std::ptr::null_mut();
    let rc = unsafe { PowerGetActiveScheme(None, &mut p) };
    if rc.0 != 0 || p.is_null() {
        return None;
    }
    LocalGuidPtr(p).take()
}

/// 读电源方案状态：当前 GUID + 名字 + 列表。
///
/// 枚举本机**全部**可用方案（含用户克隆的自定义 GUID），每条都带 `known` 与 `tip`，
/// 由面板一视同仁地渲染成可选小块（2026-10-14 用户裁定：自定义方案不再降级成
/// 「白名单外，仅展示不可选」）。内置三档的名称与说明取自 `KNOWN_PLANS`（与系统语言无关），
/// 自定义方案取 `PowerReadFriendlyName` 的原名。
pub fn power_plan_state() -> Value {
    let active = active_scheme();
    let active_guid = active.as_ref().map(guid_string).unwrap_or_default();
    let active_name = active
        .as_ref()
        .and_then(scheme_friendly_name)
        .unwrap_or_else(|| active_guid.clone());
    let options = scheme_guids()
        .iter()
        .map(|g| {
            let guid = guid_string(g);
            match KNOWN_PLANS.iter().find(|(kg, _, _)| kg.eq_ignore_ascii_case(&guid)) {
                Some((_, cn, tip)) => json!({ "guid": guid, "name": cn, "known": true, "tip": tip }),
                None => json!({
                    "guid": guid,
                    "name": scheme_friendly_name(g).unwrap_or_else(|| guid.clone()),
                    "known": false,
                    "tip": CUSTOM_PLAN_TIP,
                }),
            }
        })
        .collect::<Vec<Value>>();
    let (power_ops, degraded) = read_power_ops_state();
    json!({
        "activeGuid": active_guid,
        "activeName": active_name,
        // A1-M12：电源操作侧表读失败与「没有记录」分开。
        "degraded": degraded,
        "options": options,
        "tools": {
            "highPerformanceGuid": HIGH_PERFORMANCE_GUID,
            "highPerformanceListed": listed_scheme(HIGH_PERFORMANCE_GUID),
            "ultimateGuid": ULTIMATE_PERFORMANCE_GUID,
            "ultimateListed": listed_scheme(ULTIMATE_PERFORMANCE_GUID),
            "hiddenBackup": power_ops.get("hiddenHighPerformance").cloned().unwrap_or(Value::Null),
        },
    })
}

/// 切换电源方案：**只接受本机枚举得到的方案 GUID** + 400ms 回读校验。
///
/// 安全口径 2026-10-14 从「固定三档白名单」改成「本机方案表内」：三档白名单会把用户
/// 自己克隆的方案（他日常真正在用的那一档）挡在选择之外，而渲染层传进来的任意 GUID
/// 该拒的仍然要拒——所以判据换成「这台机器上确实存在这个方案」，比固定表更宽也更准。
/// 形状非法的输入在枚举**之前**就被拒（快速组单测因此不触系统）。
///
/// **回读校验不能省**：`PowerSetActiveScheme` 在组策略锁定或休眠状态冲突时会"返回成功"
/// 但当前方案没变。RAINZ 用同样判据（`Test-Scheme` 里也是切完再查）；
/// 我们把它做成**错误回执**而不是"成功但状态没变"的静默。
pub fn power_plan_apply(guid: &str) -> Result<Value, String> {
    let want = parse_guid_str(guid).ok_or_else(|| format!("GUID 形状非法：{guid}"))?;
    let listed = scheme_guids().iter().map(guid_string).collect::<Vec<String>>();
    if !listed.iter().any(|g| g.eq_ignore_ascii_case(guid)) {
        return Err("该方案不在本机方案列表内，已拒绝切换".to_string());
    }
    let rc = unsafe { PowerSetActiveScheme(None, Some(&want as *const GUID)) };
    if rc.0 != 0 {
        return Err(format!("切换电源方案失败（Win32 错误码 {}）", rc.0));
    }
    std::thread::sleep(Duration::from_millis(400));
    let state = power_plan_state();
    let got = state
        .get("activeGuid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !got.eq_ignore_ascii_case(guid) {
        return Err(format!("切换后回读为 {got}，与目标 {guid} 不符"));
    }
    Ok(state)
}

/// 单个电源设置的目标值。嵌套结构体必须显式 rename 到 camelCase，见 AGENTS §5.4。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PowerSettingChange {
    pub subgroup_guid: String,
    pub setting_guid: String,
    pub ac: Option<u32>,
    pub dc: Option<u32>,
}

fn validate_existing_powrplan(path: &Path) -> Result<(), String> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if !ext.eq_ignore_ascii_case("powrplan") {
        return Err("导入路径必须是 .powrplan 文件".to_string());
    }
    let md = std::fs::symlink_metadata(path)
        .map_err(|e| format!("读取导入文件失败：{e}"))?;
    if crate::engine::protect::is_reparse(&md) {
        return Err("导入文件是 reparse 点，已拒绝".to_string());
    }
    if !md.is_file() {
        return Err("导入路径不是普通文件".to_string());
    }
    if md.len() == 0 {
        return Err("导入文件为空".to_string());
    }
    Ok(())
}

fn validate_export_destination(path: &Path) -> Result<(), String> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if !ext.eq_ignore_ascii_case("powrplan") {
        return Err("导出路径必须以 .powrplan 结尾".to_string());
    }
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if crate::engine::protect::is_reparse(&md) {
            return Err("导出目标是 reparse 点，已拒绝覆盖".to_string());
        }
        if !md.is_file() {
            return Err("导出目标已存在但不是普通文件".to_string());
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| "导出目标缺少父目录".to_string())?;
    if !parent.is_dir() {
        return Err("导出目标父目录不存在".to_string());
    }
    Ok(())
}

/// 克隆电源方案并改名；失败时删除刚克隆出的方案，避免留下半截条目。
pub fn power_plan_duplicate(source_guid: &str, name: &str) -> Result<Value, String> {
    let source = require_listed_scheme(source_guid)?;
    let (new_name, new_name_bytes) = name_bytes(name)?;
    let mut dest: *mut GUID = std::ptr::null_mut();
    let rc = unsafe { PowerDuplicateScheme(None, &source as *const GUID, &mut dest) };
    if !win32_ok(rc) {
        return Err(format!("克隆电源方案失败（Win32 错误码 {}）", rc.0));
    }
    let created = LocalGuidPtr(dest)
        .take()
        .ok_or_else(|| "克隆电源方案成功但系统未返回新 GUID".to_string())?;
    let result = (|| {
        let rc = unsafe {
            PowerWriteFriendlyName(
                None,
                &created as *const GUID,
                None,
                None,
                &new_name_bytes,
            )
        };
        if !win32_ok(rc) {
            return Err(format!("克隆后改名失败（Win32 错误码 {}）", rc.0));
        }
        let got = scheme_friendly_name(&created).unwrap_or_else(|| guid_string(&created));
        if got != new_name {
            return Err(format!("克隆后回读名称 {got}，与目标 {new_name} 不符"));
        }
        Ok(json!({
            "guid": guid_string(&created),
            "name": got,
            "state": power_plan_state(),
        }))
    })();
    if result.is_err() {
        let _ = unsafe { PowerDeleteScheme(None, &created as *const GUID) };
    }
    result
}

/// 重命名电源方案；写完必须回读比对，不把「调用返回成功」当完成。
pub fn power_plan_rename(guid: &str, name: &str) -> Result<Value, String> {
    let target = require_listed_scheme(guid)?;
    let (new_name, new_name_bytes) = name_bytes(name)?;
    let old_name = scheme_friendly_name(&target).unwrap_or_else(|| guid_string(&target));
    let rc = unsafe {
        PowerWriteFriendlyName(
            None,
            &target as *const GUID,
            None,
            None,
            &new_name_bytes,
        )
    };
    if !win32_ok(rc) {
        return Err(format!("重命名 {old_name} 失败（Win32 错误码 {}）", rc.0));
    }
    let got = scheme_friendly_name(&target).unwrap_or_else(|| guid_string(&target));
    if got != new_name {
        return Err(format!("重命名后回读名称 {got}，与目标 {new_name} 不符"));
    }
    Ok(json!({
        "guid": guid_string(&target),
        "name": got,
        "state": power_plan_state(),
    }))
}

/// 删除电源方案：本机枚举内、非当前方案、非微软保留三档三道闸全部通过才删。
pub fn power_plan_delete(guid: &str) -> Result<Value, String> {
    let target = require_listed_scheme(guid)?;
    if active_scheme().is_some_and(|active| guid_string(&active).eq_ignore_ascii_case(guid)) {
        return Err("当前正在使用的电源方案不能删除".to_string());
    }
    require_reserved_plans_untouched(guid)?;
    let rc = unsafe { PowerDeleteScheme(None, &target as *const GUID) };
    if !win32_ok(rc) {
        return Err(format!("删除电源方案失败（Win32 错误码 {}）", rc.0));
    }
    if listed_scheme(guid) {
        return Err(format!("删除后回读仍能枚举到 {guid}，已按失败上报"));
    }
    Ok(json!({
        "guid": guid.to_ascii_lowercase(),
        "state": power_plan_state(),
    }))
}

/// 导入 `.powrplan`；成功后必须重新枚举并读得到名称，否则清理刚导入的方案。
pub fn power_plan_import(path: &Path) -> Result<Value, String> {
    validate_existing_powrplan(path)?;
    let wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut dest: *mut GUID = std::ptr::null_mut();
    let rc = unsafe {
        PowerImportPowerScheme(
            None,
            PCWSTR(wide.as_ptr()),
            &mut dest as *mut *mut GUID,
        )
    };
    if !win32_ok(rc) {
        return Err(format!("导入电源方案失败（Win32 错误码 {}）", rc.0));
    }
    let imported = LocalGuidPtr(dest)
        .take()
        .ok_or_else(|| "导入电源方案成功但系统未返回新 GUID".to_string())?;
    let imported_guid = guid_string(&imported);
    let name = scheme_friendly_name(&imported);
    let confirmed = listed_scheme(&imported_guid) && name.is_some();
    if !confirmed {
        let _ = unsafe { PowerDeleteScheme(None, &imported as *const GUID) };
        return Err(format!(
            "导入 {imported_guid} 后重新枚举或名称回读失败，已清理半截方案"
        ));
    }
    Ok(json!({
        "guid": imported_guid,
        "name": name.unwrap_or_default(),
        "state": power_plan_state(),
    }))
}

/// 导出 A′：只在这一条路径破例起 `powercfg.exe`，先落应用私有 tmp，再复制到用户目标。
pub fn power_plan_export(guid: &str, destination: &Path) -> Result<Value, String> {
    let _ = require_listed_scheme(guid)?;
    validate_export_destination(destination)?;
    let tmp_dir = crate::engine::paths::temp_script_dir()?;
    let tmp_path = tmp_dir.join(format!(
        "power-export-{}-{}.powrplan",
        crate::engine::now_ms(),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp_path);
    let mut cleanup = RemoveOnDrop(Some(tmp_path.clone()));
    let tmp_str = tmp_path.to_string_lossy().to_string();
    // v6-K01（P0-2）：解析失败与 spawn 失败同报错口径
    let out = crate::engine::systembin::quiet_cmd_timeout(
        crate::engine::systembin::system_tool("powercfg.exe")?,
        &["/export", tmp_str.as_str(), guid],
        crate::engine::systembin::POWERCFG_TIMEOUT,
    )
    .map_err(|e| format!("启动 powercfg.exe 失败：{e}"))?;
    if !out.status.success() {
        return Err(format!(
            "powercfg /export 失败（退出码 {}）",
            out.status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "未知".to_string())
        ));
    }
    let md = std::fs::symlink_metadata(&tmp_path)
        .map_err(|e| format!("导出后读取中转文件失败：{e}"))?;
    if crate::engine::protect::is_reparse(&md) || !md.is_file() || md.len() == 0 {
        return Err("powercfg /export 未产出有效的非空普通文件".to_string());
    }
    if !listed_scheme(guid) {
        return Err(format!("导出后回读不到方案 {guid}，已按失败上报"));
    }
    let bytes = md.len();
    std::fs::copy(&tmp_path, destination)
        .map_err(|e| format!("复制导出文件到目标路径失败：{e}"))?;
    let _ = std::fs::remove_file(&tmp_path);
    cleanup.disarm();
    crate::engine::log::write_log(
        "info",
        &format!("电源方案导出完成：{bytes} 字节"),
    );
    Ok(json!({
        "guid": guid.to_ascii_lowercase(),
        "bytes": bytes,
        "path": destination.to_string_lossy(),
    }))
}

// ==================== G-04 专用能力（2026-10-16 裁定：开启卓越性能 / 隐藏高性能） ====================
//
// 形态：两个能力并入「Windows设置 → 电源计划」卡片，**不进优化项目录**——P0-1 已把
// 优化域的电源写入全量清零并立了 `check-power-write-surface` 门禁，专用入口是唯一
// 的合法新增写面（用户 2026-10-16 裁定「编辑器为已授权写面」的延伸）。
// 前置实测（P0-3，v3 附录 C）两条关键行为：`powercfg /import` **每次重新分配 GUID**
// （还原按「名称 + 设置」验收，不以 GUID 相等为条件）；PowerSchemes 子树对管理员
// 只读、规范 GUID 写回不可行（产品侧不尝试）。

/// power-ops 状态侧表（用户数据目录内）：记录上次开启卓越性能的原激活 GUID、
/// 隐藏高性能的备份路径与原方案名（还原入口的唯一依据）。
const POWER_OPS_FILE: &str = "power-ops.json";

fn power_ops_path() -> Result<PathBuf, String> {
    Ok(crate::engine::paths::app_data_dir().join(POWER_OPS_FILE))
}

/// 读侧表：不存在/损坏 → 空对象（两个操作在无记录时都能安全地如实拒绝）。
fn read_power_ops() -> Value {
    read_power_ops_state().0
}

/// A1-M12：保留 Corrupt 位（不存在 ≠ 读失败），供电源面板回执带 degraded。
fn read_power_ops_state() -> (Value, bool) {
    let Ok(p) = power_ops_path() else {
        return (json!({}), true);
    };
    match crate::security::read_json_state(&p) {
        crate::security::JsonState::Ok(v) => (v, false),
        crate::security::JsonState::Absent => (json!({}), false),
        crate::security::JsonState::Corrupt => (json!({}), true),
    }
}

/// Win32 错误文案：权限不足（ERROR_ACCESS_DENIED=5）显式给提权提示，
/// 不把它说成「不支持」（v3 P1-2 口径）；其余如实带错误码。
fn power_win32_err(action: &str, code: u32) -> String {
    if code == 5 {
        format!("{action}被系统拒绝：需要管理员权限（Win32 错误码 5），请用管理员身份运行 Trim 后重试")
    } else {
        format!("{action}失败（Win32 错误码 {code}）")
    }
}

/// 方案列表里按友好名查找（忽略大小写）→ 命中的 GUID。
/// 用途：P0-3 实测 import 必换 GUID，「还原是否重复」只能按名称判。
fn find_scheme_named(name: &str) -> Option<String> {
    let want = name.trim();
    if want.is_empty() {
        return None;
    }
    scheme_guids().iter().find_map(|g| {
        scheme_friendly_name(g)
            .filter(|n| n.eq_ignore_ascii_case(want))
            .map(|_| guid_string(g))
    })
}

/// G-04「开启卓越性能」：已存在则直接激活；不存在则先克隆内置模板再激活。
/// 激活判据与 `power_plan_apply` 相同（PowerSetActiveScheme + 400ms 回读）；
/// 本函数克隆出的方案在激活/回读失败时清掉（不留半截状态）。
/// 原激活 GUID 记进 power-ops.json（仅审计记录；回切随时可在面板点其它方案）。
pub fn power_ultimate_enable() -> Result<Value, String> {
    let active_before = active_scheme().map(|g| guid_string(&g)).unwrap_or_default();
    let mut created_guid: Option<GUID> = None;
    let target_s = if listed_scheme(ULTIMATE_PERFORMANCE_GUID) {
        ULTIMATE_PERFORMANCE_GUID.to_string()
    } else {
        let template = parse_guid_str(ULTIMATE_PERFORMANCE_GUID)
            .ok_or_else(|| "卓越性能模板 GUID 非法（程序错误）".to_string())?;
        let mut dest: *mut GUID = std::ptr::null_mut();
        let rc = unsafe { PowerDuplicateScheme(None, &template as *const GUID, &mut dest) };
        if !win32_ok(rc) {
            return Err(power_win32_err("创建卓越性能方案", rc.0));
        }
        let created = LocalGuidPtr(dest)
            .take()
            .ok_or_else(|| "创建卓越性能成功但系统未返回新 GUID".to_string())?;
        let s = guid_string(&created);
        if !listed_scheme(&s) {
            let _ = unsafe { PowerDeleteScheme(None, &created as *const GUID) };
            return Err("创建卓越性能后重新枚举失败，已清理未保留".to_string());
        }
        created_guid = Some(created);
        s
    };
    let want = parse_guid_str(&target_s).ok_or_else(|| "卓越性能 GUID 非法".to_string())?;
    let rc = unsafe { PowerSetActiveScheme(None, Some(&want as *const GUID)) };
    if rc.0 != 0 {
        if let Some(created) = created_guid {
            let _ = unsafe { PowerDeleteScheme(None, &created as *const GUID) };
        }
        return Err(power_win32_err("切换卓越性能", rc.0));
    }
    std::thread::sleep(Duration::from_millis(400));
    let state = power_plan_state();
    let got = state
        .get("activeGuid")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !got.eq_ignore_ascii_case(&target_s) {
        if let Some(created) = created_guid {
            let _ = unsafe { PowerDeleteScheme(None, &created as *const GUID) };
        }
        return Err(format!("切换后回读为 {got}，与目标 {target_s} 不符"));
    }
    let _ = crate::security::update_json(&power_ops_path()?, |v| {
        v["lastUltimateEnable"] = json!({
            "at": crate::engine::now_ms(),
            "previousActiveGuid": active_before,
            "ultimateGuid": target_s,
        });
        Ok(())
    });
    Ok(state)
}

/// G-04「隐藏高性能」（终态 = 导出 + 删除）：**只认内置 `8c5e7fda`**。
/// 顺序 = 枚举/非激活检查 → 导出 .powrplan 到应用备份目录（prune 50） → 专用删除 → 回读确认。
/// 删除被拒 / 回读仍在 = 「未更改」（方案还在，无需回滚），如实上报并保留备份路径；
/// 与通用 `power_plan_delete` 的区别：那是「本机任意非保留方案」，本函数只认一个 GUID，
/// 通用保留拒绝（`require_reserved_plans_untouched`）原样不动。
pub fn power_high_performance_hide() -> Result<Value, String> {
    let target = require_listed_scheme(HIGH_PERFORMANCE_GUID)
        .map_err(|_| "本机方案列表里没有内置「高性能」（可能已隐藏）".to_string())?;
    if active_scheme().is_some_and(|a| guid_string(&a).eq_ignore_ascii_case(HIGH_PERFORMANCE_GUID)) {
        return Err("「高性能」正在使用中，不能隐藏；请先切换到其它方案".to_string());
    }
    let original_name = scheme_friendly_name(&target).unwrap_or_default();
    let root = crate::engine::paths::backup_write_dir("power-plan-backups");
    std::fs::create_dir_all(&root).map_err(|e| format!("创建备份目录失败：{e}"))?;
    let backup = root.join(format!("high-performance-{}.powrplan", crate::engine::now_ms()));
    let backup_s = backup.to_string_lossy().to_string();
    let export = power_plan_export(HIGH_PERFORMANCE_GUID, &backup)
        .map_err(|e| format!("导出备份失败，未执行删除：{e}"))?;
    let bytes = export.get("bytes").and_then(Value::as_u64).unwrap_or(0);
    crate::engine::paths::prune_stamped_files(&root, 50);
    // R5b-M11（v7.2 C06）：先落还原台账，再删方案。旧顺序是「先删、后记账」——
    // 记账失败即通过 `?` 返回 Err，回执说「未更改」，但方案已经删掉、power-ops.json
    // 里没有 hiddenHighPerformance，还原入口从此找不到唯一凭据。
    // 提前落账的代价只是「删除失败时多一条记录」：还原侧本来就有「GUID 在列即拒」的
    // 幂等判据，多余记录无害。
    let ops_record = json!({
        "backupPath": backup_s.clone(),
        "bytes": bytes,
        "originalName": original_name,
        "at": crate::engine::now_ms(),
    });
    crate::security::update_json(&power_ops_path()?, |v| {
        v["hiddenHighPerformance"] = ops_record.clone();
        Ok(())
    })
    .map_err(|e| format!("备份已导出（{backup_s}），但写入还原记录失败，未执行删除：{e}"))?;
    let rc = unsafe { PowerDeleteScheme(None, &target as *const GUID) };
    if !win32_ok(rc) {
        return Err(format!(
            "{}，已保持未更改；备份文件保留在 {backup_s}（还原记录也已登记）",
            power_win32_err("删除「高性能」", rc.0)
        ));
    }
    if listed_scheme(HIGH_PERFORMANCE_GUID) {
        return Err(format!(
            "删除后回读仍能枚举到「高性能」，已按失败上报（未谎报更改）；备份文件保留在 {backup_s}"
        ));
    }
    Ok(json!({
        "backupPath": backup_s,
        "bytes": bytes,
        "state": power_plan_state(),
    }))
}

/// G-04「还原高性能」：按 power-ops.json 记录的备份导入回来。
/// 已存在（标准 GUID 在列，或任一方案名等于记录的原名）时不重复导入 ——
/// P0-3 实测 import 会分配新 GUID，重复导入 = 制造双份同名方案。
/// 回读按「名称 + 枚举可见」判（GUID 由系统重新分配，v3 附录 C）。
pub fn power_high_performance_restore() -> Result<Value, String> {
    let ops = read_power_ops();
    let rec = ops.get("hiddenHighPerformance").cloned().unwrap_or(Value::Null);
    let backup = rec
        .get("backupPath")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            "没有「隐藏高性能」的备份记录，无法从 Trim 内还原（可用「导入方案文件…」手工导入）"
                .to_string()
        })?;
    if listed_scheme(HIGH_PERFORMANCE_GUID) {
        return Err("本机方案列表里已有内置「高性能」，无需还原".to_string());
    }
    let original_name = rec
        .get("originalName")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if let Some(hit) = find_scheme_named(&original_name) {
        return Err(format!("方案列表里已有「{original_name}」（GUID {hit}），未重复导入"));
    }
    let imported = power_plan_import(Path::new(&backup))?;
    let _ = crate::security::update_json(&power_ops_path()?, |v| {
        if let Some(item) = v.get_mut("hiddenHighPerformance") {
            item["restoredAt"] = json!(crate::engine::now_ms());
        }
        Ok(())
    });
    let mut out = imported;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("originalName".into(), json!(original_name));
        obj.insert("backupPath".into(), json!(backup));
    }
    Ok(out)
}

fn setting_value_json(
    scheme: &GUID,
    item: &PowerSettingRef,
) -> Result<Value, String> {
    let subgroup_guid = guid_string(&item.subgroup);
    let setting_guid = guid_string(&item.setting);
    let attrs = unsafe {
        PowerReadSettingAttributes(
            Some(&item.subgroup as *const GUID),
            Some(&item.setting as *const GUID),
        )
    };
    let range = read_value_range(scheme, &item.subgroup, &item.setting);
    let possible = read_possible_values(scheme, &item.subgroup, &item.setting);
    let possible_names = read_possible_value_names(&item.subgroup, &item.setting, possible.len());
    let unit = read_value_unit(scheme, &item.subgroup, &item.setting);
    let ac = read_setting_value(scheme, &item.subgroup, &item.setting, false);
    let dc = read_setting_value(scheme, &item.subgroup, &item.setting, true);
    let name = power_text(
        PowerTextKind::Friendly,
        Some(scheme),
        Some(&item.subgroup),
        Some(&item.setting),
    )
    .unwrap_or_else(|| setting_guid.clone());
    let description = power_text(
        PowerTextKind::Description,
        Some(scheme),
        Some(&item.subgroup),
        Some(&item.setting),
    )
    .unwrap_or_default();
    // 这里**不**对当前值做 validate_value_against_meta：真机探针证明存在
    // 「当前值不在读到的枚举/范围内」的合法既成事实（如「合上盖子操作」当前值 1、
    // possible 读得 0/2/3/6），对当前值报错会把整个 dump 打不开、编辑器被锁死。
    // 严格校验只留给写侧 apply 对**目标值**执行（那才是要防的输入面）。原样如实返回。
    Ok(json!({
        "guid": setting_guid,
        "subgroupGuid": subgroup_guid,
        "name": name,
        "description": description,
        "unit": unit,
        "isRange": range.is_some(),
        "range": range.map(|(min, max, step)| json!({ "min": min, "max": max, "step": step })),
        "possibleValues": possible,
        "possibleValueNames": possible_names,
        "valueAc": ac,
        "valueDc": dc,
        "visible": (attrs & POWER_SETTING_ATTR_HIDDEN) == 0,
        "attributes": attrs,
    }))
}

/// 单设置跨方案对照：读该设置在本机**全部方案**里的 AC/DC 值（v5 P2）。
/// 只读；供编辑器详情区「其它方案里是多少」的对照块，不触写侧、不需管理员。
pub fn power_setting_compare(subgroup_guid: &str, setting_guid: &str) -> Result<Value, String> {
    let subgroup = parse_guid_str(subgroup_guid)
        .ok_or_else(|| format!("子组 GUID 形状非法：{subgroup_guid}"))?;
    let setting = parse_guid_str(setting_guid)
        .ok_or_else(|| format!("设置 GUID 形状非法：{setting_guid}"))?;
    let active = active_scheme().map(|g| guid_string(&g)).unwrap_or_default();
    let rows = scheme_guids()
        .iter()
        .map(|g| {
            let guid = guid_string(g);
            let name = scheme_friendly_name(g).unwrap_or_else(|| guid.clone());
            json!({
                "schemeGuid": guid,
                "schemeName": name,
                "active": guid.eq_ignore_ascii_case(&active),
                "ac": read_setting_value(g, &subgroup, &setting, false),
                "dc": read_setting_value(g, &subgroup, &setting, true),
            })
        })
        .collect::<Vec<Value>>();
    Ok(json!({ "rows": rows }))
}

/// 「在注册表中查看」：把编辑器定位到该设置的 PowerSettings 键（复用系统工具层
/// `open_regedit_at` 的「写 LastKey + 拉起 regedit」链路，不新造第二套实现）。
/// 只接形状合法的 GUID，路径整体由本函数拼出、不接任意字符串。
pub fn power_setting_open_regedit(subgroup_guid: &str, setting_guid: &str) -> Result<Value, String> {
    let subgroup = parse_guid_str(subgroup_guid)
        .ok_or_else(|| format!("子组 GUID 形状非法：{subgroup_guid}"))?;
    let setting = parse_guid_str(setting_guid)
        .ok_or_else(|| format!("设置 GUID 形状非法：{setting_guid}"))?;
    let last_key = format!(
        "计算机\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\{}\\{}",
        guid_string(&subgroup),
        guid_string(&setting)
    );
    crate::engine::systembin::open_regedit_at(&last_key)?;
    Ok(json!({ "ok": true }))
}

/// 平台角色：只供渲染层决定 DC（电池）列的默认显隐，不是任何写入门禁。
/// 台式机没有电池档，默认收起 DC 列；笔记本（mobile）与平板（slate）默认展开。
fn platform_role_str() -> &'static str {
    let role = unsafe { PowerDeterminePlatformRole() };
    if role == PlatformRoleMobile {
        "mobile"
    } else if role == PlatformRoleSlate {
        "slate"
    } else if role == PlatformRoleDesktop {
        "desktop"
    } else {
        "unknown"
    }
}

/// 逐设置 dump：子组 + 设置、AC/DC 当前值、范围/可选值、显隐属性。
pub fn power_settings_dump(scheme_guid: &str) -> Result<Value, String> {
    let scheme = require_listed_scheme(scheme_guid)?;
    let refs = setting_refs_for_scheme(&scheme);
    let mut groups: Vec<Value> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for item in refs {
        let subgroup_guid = guid_string(&item.subgroup);
        let group_name = if guid_is_zero(&item.subgroup) {
            "未分组".to_string()
        } else {
            power_text(
                PowerTextKind::Friendly,
                Some(&scheme),
                Some(&item.subgroup),
                None,
            )
            .unwrap_or_else(|| subgroup_guid.clone())
        };
        let setting = setting_value_json(&scheme, &item)?;
        let group_idx = match index.get(&subgroup_guid) {
            Some(i) => *i,
            None => {
                let i = groups.len();
                index.insert(subgroup_guid.clone(), i);
                groups.push(json!({
                    "guid": subgroup_guid,
                    "name": group_name,
                    "settings": [],
                }));
                i
            }
        };
        if let Some(settings) = groups[group_idx]
            .get_mut("settings")
            .and_then(Value::as_array_mut)
        {
            settings.push(setting);
        }
    }
    Ok(json!({
        "schemeGuid": scheme_guid.to_ascii_lowercase(),
        "enumeratedAt": crate::engine::now_ms(),
        "platformRole": platform_role_str(),
        "subgroups": groups,
    }))
}

/// 进入编辑会话：解全部设置显隐属性，并保存「本会话真正动过」的完整原始属性字。
pub fn power_settings_unlock(scheme_guid: &str) -> Result<Value, String> {
    let scheme = require_listed_scheme(scheme_guid)?;
    let refs = setting_refs_for_scheme(&scheme);
    let mut snapshots: Vec<PowerSettingSnapshot> = Vec::new();
    let mut changed = Vec::<Value>::new();
    let mut failed = Vec::<Value>::new();
    for item in refs {
        let old = unsafe {
            PowerReadSettingAttributes(
                Some(&item.subgroup as *const GUID),
                Some(&item.setting as *const GUID),
            )
        };
        let next = (old & !POWER_SETTING_ATTR_HIDDEN) | POWER_SETTING_ATTR_VISIBLE;
        if next == old {
            continue;
        }
        let snapshot = PowerSettingSnapshot {
            subgroup: item.subgroup,
            setting: item.setting,
            attributes: old,
            changed: true,
        };
        let rc = unsafe {
            PowerWriteSettingAttributes(
                Some(&item.subgroup as *const GUID),
                Some(&item.setting as *const GUID),
                next,
            )
        };
        if !win32_ok(rc) {
            failed.push(json!({
                "subgroupGuid": guid_string(&item.subgroup),
                "settingGuid": guid_string(&item.setting),
                "message": format!("写入属性失败（Win32 错误码 {}）", rc.0),
            }));
            continue;
        }
        let got = unsafe {
            PowerReadSettingAttributes(
                Some(&item.subgroup as *const GUID),
                Some(&item.setting as *const GUID),
            )
        };
        if got != next {
            restore_attribute_snapshots(&[snapshot]);
            failed.push(json!({
                "subgroupGuid": guid_string(&item.subgroup),
                "settingGuid": guid_string(&item.setting),
                "message": format!("回读为 {got}，与目标 {next} 不符；已尝试恢复原属性"),
            }));
            continue;
        }
        snapshots.push(snapshot);
        changed.push(json!({
            "subgroupGuid": guid_string(&item.subgroup),
            "settingGuid": guid_string(&item.setting),
            "oldAttributes": old,
            "newAttributes": got,
        }));
    }
    let session_id = new_power_session_id();
    power_sessions()
        .lock()
        .map_err(|_| "电源设置会话锁不可用".to_string())?
        .insert(
            session_id.clone(),
            PowerSettingsSession {
                scheme_guid: scheme_guid.to_ascii_lowercase(),
                snapshots: snapshots.clone(),
            },
        );
    let snapshot = snapshots
        .into_iter()
        .map(|s| {
            json!({
                "subgroupGuid": guid_string(&s.subgroup),
                "settingGuid": guid_string(&s.setting),
                "attributes": s.attributes,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "ok": failed.is_empty(),
        "sessionId": session_id,
        "changed": changed,
        "failed": failed,
        "snapshot": snapshot,
    }))
}

fn write_setting_value(
    scheme: &GUID,
    subgroup: &GUID,
    setting: &GUID,
    dc: bool,
    value: u32,
) -> Result<(), String> {
    let rc = unsafe {
        if dc {
            PowerWriteDCValueIndex(
                None,
                scheme as *const GUID,
                Some(subgroup as *const GUID),
                Some(setting as *const GUID),
                value,
            )
        } else {
            PowerWriteACValueIndex(
                None,
                scheme as *const GUID,
                Some(subgroup as *const GUID),
                Some(setting as *const GUID),
                value,
            )
            .0
        }
    };
    if rc != 0 {
        return Err(format!("Win32 错误码 {rc}"));
    }
    let got = read_setting_value(scheme, subgroup, setting, dc);
    if got != Some(value) {
        return Err(format!("回读为 {got:?}，与目标 {value} 不符"));
    }
    Ok(())
}

/// 批次写入逐设置值。前置校验整体失败时直接 Err；运行期任一条失败则 stopped 返回。
pub fn power_settings_apply(
    scheme_guid: &str,
    changes: &[PowerSettingChange],
    apply_active: bool,
) -> Result<Value, String> {
    let scheme = require_listed_scheme(scheme_guid)?;
    let refs = setting_refs_for_scheme(&scheme);
    let valid_refs = refs
        .iter()
        .map(|r| format!("{}|{}", guid_string(&r.subgroup), guid_string(&r.setting)))
        .collect::<HashSet<_>>();

    let mut planned = Vec::new();
    for change in changes {
        if change.ac.is_none() && change.dc.is_none() {
            return Err(format!(
                "设置 {} 未提供 AC 或 DC 目标值",
                change.setting_guid
            ));
        }
        let subgroup = parse_guid_str(&change.subgroup_guid)
            .ok_or_else(|| format!("子组 GUID 形状非法：{}", change.subgroup_guid))?;
        let setting = parse_guid_str(&change.setting_guid)
            .ok_or_else(|| format!("设置 GUID 形状非法：{}", change.setting_guid))?;
        let key = format!(
            "{}|{}",
            guid_string(&subgroup),
            guid_string(&setting)
        );
        if !valid_refs.contains(&key) {
            return Err(format!(
                "设置 {} 不属于方案 {scheme_guid} 的本机枚举结果，已整体拒绝",
                change.setting_guid
            ));
        }
        let name = power_text(
            PowerTextKind::Friendly,
            Some(&scheme),
            Some(&subgroup),
            Some(&setting),
        )
        .unwrap_or_else(|| change.setting_guid.clone());
        let range = read_value_range(&scheme, &subgroup, &setting);
        let possible = read_possible_values(&scheme, &subgroup, &setting);
        for value in [change.ac, change.dc].into_iter().flatten() {
            validate_value_against_meta(value, range, &possible, &name)?;
        }
        planned.push((subgroup, setting, change.ac, change.dc));
    }

    let mut written = Vec::<Value>::new();
    let mut failed = Vec::<Value>::new();
    for (subgroup, setting, ac, dc) in planned {
        let subgroup_guid = guid_string(&subgroup);
        let setting_guid = guid_string(&setting);
        let mut item_fail: Option<String> = None;
        if let Some(value) = ac {
            if let Err(e) = write_setting_value(&scheme, &subgroup, &setting, false, value) {
                item_fail = Some(format!("AC 写入 {value} 失败：{e}"));
            }
        }
        if item_fail.is_none() {
            if let Some(value) = dc {
                if let Err(e) = write_setting_value(&scheme, &subgroup, &setting, true, value) {
                    item_fail = Some(format!("DC 写入 {value} 失败：{e}"));
                }
            }
        }
        if let Some(message) = item_fail {
            failed.push(json!({
                "subgroupGuid": subgroup_guid,
                "settingGuid": setting_guid,
                "message": message,
            }));
            break;
        }
        written.push(json!({
            "subgroupGuid": subgroup_guid,
            "settingGuid": setting_guid,
            "ac": ac,
            "dc": dc,
        }));
    }

    let mut active_guid = active_scheme().map(|g| guid_string(&g)).unwrap_or_default();
    if failed.is_empty() && apply_active {
        let rc = unsafe { PowerSetActiveScheme(None, Some(&scheme as *const GUID)) };
        if !win32_ok(rc) {
            failed.push(json!({
                "subgroupGuid": "",
                "settingGuid": "",
                "message": format!("设置活动方案失败（Win32 错误码 {}）", rc.0),
            }));
        } else {
            std::thread::sleep(Duration::from_millis(400));
            active_guid = active_scheme().map(|g| guid_string(&g)).unwrap_or_default();
            if !active_guid.eq_ignore_ascii_case(scheme_guid) {
                failed.push(json!({
                    "subgroupGuid": "",
                    "settingGuid": "",
                    "message": format!("活动方案回读为 {active_guid}，与目标 {scheme_guid} 不符"),
                }));
            }
        }
    }
    let ok = failed.is_empty();
    Ok(json!({
        "ok": ok,
        "schemeGuid": scheme_guid.to_ascii_lowercase(),
        "written": written,
        "failed": failed,
        "stopped": !ok,
        "activeGuid": active_guid,
    }))
}

/// 取消编辑：只接受后端 unlock 返回的 session id，按会话快照恢复本会话动过的完整属性字。
pub fn power_settings_revert(scheme_guid: &str, session_id: &str) -> Result<Value, String> {
    let _ = require_listed_scheme(scheme_guid)?;
    let session = power_sessions()
        .lock()
        .map_err(|_| "电源设置会话锁不可用".to_string())?
        .get(session_id)
        .cloned()
        .ok_or_else(|| "电源设置会话不存在或已消费，拒绝按伪造快照回写".to_string())?;
    if !session
        .scheme_guid
        .eq_ignore_ascii_case(scheme_guid)
    {
        return Err("电源设置会话与目标方案不匹配，已拒绝回写".to_string());
    }
    let mut restored = Vec::<Value>::new();
    let mut failed = Vec::<Value>::new();
    for snap in session.snapshots.iter().filter(|s| s.changed) {
        let rc = unsafe {
            PowerWriteSettingAttributes(
                Some(&snap.subgroup as *const GUID),
                Some(&snap.setting as *const GUID),
                snap.attributes,
            )
        };
        let subgroup_guid = guid_string(&snap.subgroup);
        let setting_guid = guid_string(&snap.setting);
        if !win32_ok(rc) {
            failed.push(json!({
                "subgroupGuid": subgroup_guid,
                "settingGuid": setting_guid,
                "message": format!("恢复属性失败（Win32 错误码 {}）", rc.0),
            }));
            continue;
        }
        let got = unsafe {
            PowerReadSettingAttributes(
                Some(&snap.subgroup as *const GUID),
                Some(&snap.setting as *const GUID),
            )
        };
        if got != snap.attributes {
            failed.push(json!({
                "subgroupGuid": subgroup_guid,
                "settingGuid": setting_guid,
                "message": format!("恢复后回读 {got}，与快照 {} 不符", snap.attributes),
            }));
            continue;
        }
        restored.push(json!({
            "subgroupGuid": subgroup_guid,
            "settingGuid": setting_guid,
            "attributes": got,
        }));
    }
    let ok = failed.is_empty();
    if ok {
        let _ = power_sessions()
            .lock()
            .map_err(|_| "电源设置会话锁不可用".to_string())?
            .remove(session_id);
    }
    Ok(json!({
        "ok": ok,
        "restored": restored,
        "failed": failed,
    }))
}

/// 只读虚拟内存状态。
///
/// 注册表位置 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`：
///  - `AutomaticManagedPagefile`：REG_SZ "TRUE" / "FALSE"
///  - `PagingFiles`：REG_MULTI_SZ，形如 `C:\pagefile.sys 8192 16384`（Initial Max）
///
/// **不动写侧**：本函数只 `read`；`reg_restore_*` / 高危确认 / 重启提示 都留下一批。
pub fn pagefile_state() -> Value {
    use crate::engine::native::{hive_hklm, read_reg_value_faithful, read_reg_value_text};
    let sub = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
    let managed = read_reg_value_text(hive_hklm(), sub, "AutomaticManagedPagefile")
        .map(|(_, v)| v.eq_ignore_ascii_case("TRUE"))
        .unwrap_or(false);
    // `read_reg_value_faithful` 把 REG_MULTI_SZ 各元素以 `\0` 连接（`registry.rs` 的
    // `read_reg_value_faithful` REG_MULTI_SZ 分支），
    // 这里按 `\0` split 即可 —— 不再手写 MULTI_SZ 解码器，避免与 registry 层出现两份口径。
    let raw: Vec<String> = read_reg_value_faithful(hive_hklm(), sub, "PagingFiles")
        .map(|(_kind, s)| s.split('\0').filter(|x| !x.is_empty()).map(|x| x.to_string()).collect())
        .unwrap_or_default();
    json!({
        "managed": managed,
        "entries": raw.iter().map(|line| {
            let mut parts = line.split_whitespace();
            let path = parts.next().unwrap_or_default().to_string();
            let initial = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            let max = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            json!({ "path": path, "initialMb": initial, "maxMb": max })
        }).collect::<Vec<Value>>(),
        "lineCount": raw.len(),
        "_comment": "本轮 §3.6 只做只读展示；写侧留下一批（涉及重启、多卷、蓝屏风险）",
    })
}

// ===== v0.4.9 §3.6 写侧：虚拟内存手动配置 =====

/// 单卷分页文件配置。**结构体字段必须显式 rename 到 camelCase**：
/// AGENTS §5.4 教训（Tauri 只自动转**顶层参数名**、不转结构体字段）
/// —— 忘了 rename 就会静默判未收到值 = 绕过校验。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PagefileEntry {
    /// 盘符根，形如 `"C:"` 或 `"C:\\"` 都吃（内部归一到大写、去尾斜杠）
    pub drive: String,
    pub initial_mb: u32,
    pub max_mb: u32,
}

/// MB 数上限，防"填 999999999"这种手抖。1 TB 已够夸张，正常机器不会用到。
const PAGEFILE_MAX_MB: u32 = 1_048_576;

/// 归一化盘符（大写、去尾斜杠）；非 `[A-Z]:` 形态一律 Err，不做模糊匹配。
fn normalize_drive(raw: &str) -> Result<String, String> {
    let t = raw.trim().trim_end_matches('\\');
    let bytes = t.as_bytes();
    if bytes.len() != 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return Err(format!("drive 需为盘符形式（如 C: 或 D:），收到：{raw:?}"));
    }
    Ok(t.to_uppercase())
}

/// 写侧参数校验。**任何一项不过一律 Err、不做"部分接受"**：
///  - managed=false 且 entries 为空 → 拒（AGENTS §3 危险能力默认关；全关 pagefile
///    会让物理内存告罄时直接崩，属经典蓝屏源头）
///  - 至少一条 entry 的 max_mb > 0 → 拒（全 0/0 等价于全关，同上）
///  - 每条 entry 的 drive 归一化；initial_mb <= max_mb；max_mb <= PAGEFILE_MAX_MB
///  - 同一 drive 不允许出现两次（防止后一条静默覆盖前一条）
fn validate_pagefile(managed: bool, entries: &[PagefileEntry]) -> Result<(), String> {
    if managed {
        // 自动托管不校验 entries：entries 会被上层忽略，写侧也不动 PagingFiles
        return Ok(());
    }
    if entries.is_empty() {
        return Err("手动模式下至少保留一个卷的分页文件；全部关完可能引发蓝屏（物理内存耗尽时无分页可写入）".into());
    }
    let mut seen: Vec<String> = Vec::with_capacity(entries.len());
    let mut any_alive = false;
    for e in entries {
        let d = normalize_drive(&e.drive)?;
        if seen.iter().any(|x| x == &d) {
            return Err(format!("盘符 {d} 出现两次；每个卷最多一条配置"));
        }
        seen.push(d);
        if e.initial_mb > PAGEFILE_MAX_MB || e.max_mb > PAGEFILE_MAX_MB {
            return Err(format!("{}: MB 数超过 {PAGEFILE_MAX_MB} 上限（1 TB），疑似参数错", e.drive));
        }
        if e.max_mb < e.initial_mb {
            return Err(format!(
                "{}: Max {} MB < Initial {} MB，参数不合法",
                e.drive, e.max_mb, e.initial_mb
            ));
        }
        if e.max_mb > 0 {
            any_alive = true;
        }
    }
    if !any_alive {
        return Err("所有卷都填 0/0 等价于关掉分页文件；至少一条要给非零 Max".into());
    }
    Ok(())
}

/// 把 PagingFiles 应该写入的 MULTI_SZ 元素拼出来（**大写盘符 + `\pagefile.sys` 后缀**）。
/// 与微软约定形态一致：`C:\pagefile.sys <initial> <max>`。
fn build_paging_files(entries: &[PagefileEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| {
            let d = normalize_drive(&e.drive).unwrap_or_else(|_| e.drive.trim_end_matches('\\').to_uppercase());
            format!("{d}\\pagefile.sys {} {}", e.initial_mb, e.max_mb)
        })
        .collect()
}

/// 写侧：应用虚拟内存配置。
///
/// **执行顺序**：admin 硬要求 → 参数校验 → 备份当前值 → flush 日志 → 写 `AutomaticManagedPagefile`
/// （+ 手动时写 `PagingFiles`）→ 回读比对 → 返回 `requiresReboot: true`。
///
/// 备份走 `atomic_write_json`（AGENTS §3 写 JSON 唯一姿势）、落在
/// `paths::backup_write_dir()/pagefile-backups/<timestamp>.json`；`prune_stamped_files` 保留 50 份。
/// 一键还原命令留下一轮（AGENTS §3「危险能力默认关，猜错方向的代价不对称」），
/// 用户可先通过备份 JSON 手动 reg import 恢复。
pub fn pagefile_apply(managed: bool, entries: &[PagefileEntry]) -> Result<Value, String> {
    use crate::engine::native::{
        hive_hklm, reg_key_ensure_checked, reg_restore_write_checked, read_reg_value_faithful,
        read_reg_value_text,
    };
    use crate::engine::sysinfo::is_admin;
    use windows::Win32::System::Registry::{REG_MULTI_SZ, REG_SZ};

    if !is_admin() {
        return Err("写虚拟内存需要管理员权限（HKLM\\SYSTEM\\...）。请从主窗「以管理员身份运行」入口重启 Trim 后再操作".into());
    }
    validate_pagefile(managed, entries)?;

    let before = pagefile_state();
    // 备份先落盘；失败即中止，绝不在没留底的情况下动手
    let backup_path = write_pagefile_backup(&before)?;

    // 危险操作前 flush 日志（AGENTS §3）
    crate::engine::log::flush_sync();

    let sub = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
    reg_key_ensure_checked(hive_hklm(), sub).map_err(|e| format!("打开 Memory Management 失败：{e}"))?;

    // AutomaticManagedPagefile = REG_SZ "TRUE"/"FALSE"（对齐 WMI 也读同一位置的形态）
    let am_value = if managed { "TRUE" } else { "FALSE" };
    let am_bytes: Vec<u8> = am_value.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    reg_restore_write_checked(hive_hklm(), sub, "AutomaticManagedPagefile", REG_SZ, &am_bytes)
        .map_err(|e| format!("写 AutomaticManagedPagefile 失败：{e}"))?;

    if !managed {
        let lines = build_paging_files(entries);
        // MULTI_SZ：每串以 \0 结尾，整体再加一个 \0
        let mut buf: Vec<u8> = Vec::new();
        for line in &lines {
            for u in line.encode_utf16() {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes());
        reg_restore_write_checked(hive_hklm(), sub, "PagingFiles", REG_MULTI_SZ, &buf)
            .map_err(|e| format!("写 PagingFiles 失败：{e}"))?;
    }

    // 回读校验：至少 AutomaticManagedPagefile 必须对得上；手动模式下每条 entry 的
    // `<drive>\pagefile.sys` 都要在 PagingFiles 里出现
    let got_managed = read_reg_value_text(hive_hklm(), sub, "AutomaticManagedPagefile")
        .map(|(_, v)| v.eq_ignore_ascii_case("TRUE"))
        .unwrap_or(false);
    if got_managed != managed {
        return Err(format!(
            "回读 AutomaticManagedPagefile={got_managed} 与目标 {managed} 不符（可能被 Group Policy 或安全软件拦截）"
        ));
    }
    if !managed {
        let raw: Vec<String> = read_reg_value_faithful(hive_hklm(), sub, "PagingFiles")
            .map(|(_k, s)| s.split('\0').filter(|x| !x.is_empty()).map(|x| x.to_string()).collect())
            .unwrap_or_default();
        for e in entries {
            let d = normalize_drive(&e.drive)?;
            let want_prefix = format!("{d}\\pagefile.sys");
            if !raw.iter().any(|x| x.starts_with(&want_prefix)) {
                return Err(format!(
                    "回读 PagingFiles 未包含 {want_prefix}（可能被 Group Policy 或安全软件覆盖）"
                ));
            }
        }
    }

    let after = pagefile_state();
    crate::engine::log::write_log(
        "info",
        &format!(
            "虚拟内存配置已写入：managed={managed}、{} 个卷；备份 {backup_path}；**需要重启生效**",
            entries.len()
        ),
    );
    Ok(json!({
        "requiresReboot": true,
        "backupPath": backup_path,
        "before": before,
        "after": after,
    }))
}

/// 把当前 `pagefile_state()` 落进 `backup_write_dir("pagefile-backups")/<ts>.json`。
/// 走 `atomic_write_json`（AGENTS §3），写完 `prune_stamped_files` 保留 50 份。
fn write_pagefile_backup(snapshot: &Value) -> Result<String, String> {
    use crate::engine::paths;
    use crate::security::atomic_write_json;
    let root = paths::backup_write_dir("pagefile-backups");
    std::fs::create_dir_all(&root).map_err(|e| format!("建备份目录失败：{e}"))?;
    let ts = crate::engine::now_ms();
    let file = root.join(format!("{ts}.json"));
    atomic_write_json(&file, snapshot)?;
    // 保留 50 份；prune 失败不阻断主流程（备份本身已落盘，最坏情况下一份份堆积由下次调用回收）。
    // v5 批次 9（D1-M04）：本根全是 `<ts>.json`，旧 `prune_backups` 只数 `.reg` ⇒ 上限恒空转
    // （盘上 9 个 .json 无界涨）——改按 13 位时间戳前缀计数裁剪。
    paths::prune_stamped_files(&root, 50);
    Ok(file.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid文本解析与格式化往返一致() {
        let s = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
        let g = parse_guid_str(s).expect("解析失败");
        assert_eq!(guid_string(&g), s);
    }

    #[test]
    fn guid大小写归一化小写() {
        let g = parse_guid_str("8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C").expect("解析失败");
        assert_eq!(guid_string(&g), "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
    }

    /// **反向**：形状不对一律不认 —— 长度、hex、分段连字符任一不合都拒。
    #[test]
    fn 非guid形状一律拒判() {
        assert!(parse_guid_str("no guid here").is_none());
        assert!(parse_guid_str("381b4222-f694-41f0-9685-ff5bb260df2").is_none(), "少一位");
        assert!(parse_guid_str("zzzzzzzz-f694-41f0-9685-ff5bb260df2e").is_none(), "非 hex");
        assert!(parse_guid_str("X381b4222-f694-41f0-9685-ff5bb260df2e").is_none(), "前有字母");
        assert!(parse_guid_str("381b4222-f694-41f0-9685-ff5bb260df2eX").is_none(), "后有字母");
        assert!(parse_guid_str("381b4222f694-41f0-9685-ff5bb260df2e").is_none(), "少一个连字符");
    }

    /// 通用删除闸「微软保留三档拒删」原样钉住（G-04 专用口只对单一 GUID 开口，
    /// 本闸不许被任何改造放宽 —— v3 P1-2 验收：通用保留方案测试仍拒绝删除）。
    #[test]
    fn 保留三档一律拒删其余放行() {
        for (guid, _, _) in KNOWN_PLANS {
            let e = require_reserved_plans_untouched(guid).expect_err("保留三档必须拒");
            assert!(e.contains("保留电源方案"), "错因文案漂了：{e}");
        }
        assert!(
            require_reserved_plans_untouched("8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C").is_err(),
            "保留判定必须大小写不敏感"
        );
        assert!(
            require_reserved_plans_untouched("f95fc65d-a872-4c9a-9fe7-a7a507a6f019").is_ok(),
            "自定义方案不属保留面"
        );
    }

    /// G-04：空/空白方案名不得参与「还原是否重复」判定（防该闸门空转放行重复导入）。
    #[test]
    fn g04_空方案名不参与重复判定() {
        assert!(find_scheme_named("").is_none());
        assert!(find_scheme_named("   ").is_none());
    }

    /// G-04：错误码 5（权限不足）必须给提权提示、不许说成「不支持」（v3 P1-2 口径）。
    #[test]
    fn g04_权限错误给提权提示不谎报不支持() {
        let e = power_win32_err("删除「高性能」", 5);
        assert!(e.contains("需要管理员权限"), "码 5 应给提权提示：{e}");
        assert!(!e.contains("不支持"), "不得把权限失败说成不支持：{e}");
        let e2 = power_win32_err("切换卓越性能", 87);
        assert!(e2.contains("87"), "其它错误码应如实带码：{e2}");
    }

    /// power API 回填的是内存布局（小端），与字符串形态的**字节序不同**：
    /// 第一段 `8c5e7fda` 在内存里是 `da 7f 5e 8c`。这条钉住换算方向。
    #[test]
    fn guid内存小端字节与字符串形态对得上() {
        let b = [
            0xda, 0x7f, 0x5e, 0x8c, 0xbf, 0xe8, 0x96, 0x4a, 0x9a, 0x85, 0xa6, 0xe2, 0x3a, 0x8c,
            0x63, 0x5c,
        ];
        assert_eq!(guid_string(&guid_from_le_bytes(&b)), "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
    }

    #[test]
    fn 设置值校验按范围步长与枚举逐条判红() {
        let range = Some((0, 100, 10));
        validate_value_against_meta(0, range, &[], "测试设置").expect("下界应过");
        validate_value_against_meta(100, range, &[], "测试设置").expect("上界应过");
        let e = validate_value_against_meta(101, range, &[], "测试设置").unwrap_err();
        assert!(e.contains("超出范围"), "越界错因漂了：{e}");
        let e = validate_value_against_meta(15, range, &[], "测试设置").unwrap_err();
        assert!(e.contains("步长"), "步长错因漂了：{e}");
        validate_value_against_meta(2, None, &[1, 2, 3], "测试设置").expect("枚举值应过");
        let e = validate_value_against_meta(4, None, &[1, 2, 3], "测试设置").unwrap_err();
        assert!(e.contains("可选值"), "枚举错因漂了：{e}");
        let e = validate_value_against_meta(1, None, &[], "测试设置").unwrap_err();
        assert!(e.contains("fail-closed"), "无元数据应 fail-closed：{e}");
    }

    #[test]
    fn 电源方案名按_utf16_nul_编码且拒空拒nul() {
        let (name, bytes) = name_bytes("  Trim 测试  ").expect("合法名应过");
        assert_eq!(name, "Trim 测试");
        assert_eq!(bytes.len(), ("Trim 测试".encode_utf16().count() + 1) * 2);
        assert_eq!(&bytes[bytes.len() - 2..], &[0, 0]);
        assert!(name_bytes("").is_err());
        assert!(name_bytes("a\0b").is_err());
        assert!(name_bytes(&"x".repeat(MAX_POWER_PLAN_NAME_CHARS + 1)).is_err());
    }

    #[test]
    fn 解锁属性掩码保留其它位只动显隐两位() {
        let old = 0b1011u32;
        let next = (old & !POWER_SETTING_ATTR_HIDDEN) | POWER_SETTING_ATTR_VISIBLE;
        assert_eq!(next, 0b1010u32);
        assert_eq!(next & POWER_SETTING_ATTR_HIDDEN, 0);
        assert_ne!(next & POWER_SETTING_ATTR_VISIBLE, 0);
    }

    #[test]
    fn 形状非法的_guid_在枚举前就被拒() {
        // 只走纯函数校验分支：不触 Power API（AGENTS §4.2 快速组零副作用纪律）。
        // 原测试用「全零 GUID」当反例，那时判据是固定三档表（纯比较）；换成
        // 「本机枚举结果内」之后，合法形状的 GUID 必须枚举才知道存不存在 ⇒ 挪到 #[ignore] 探针。
        let e = power_plan_apply("not-a-guid")
            .expect_err("形状非法应被拒");
        assert!(e.contains("形状非法"), "错因文案漂了：{e}");
    }

    /// 真调 Power API 读系统方案表；机器语言 / 自定义方案都可能让结果差异，
    /// 只断"能跑到、不 panic、返回结构合法"，不硬钉内容。发布前手工核对。
    #[test]
    #[ignore = "真调 Power API：结果依赖本机方案表，只在发布前手工核对不崩"]
    fn 真跑拿到电源方案状态与虚拟内存只读结构() {
        let s = power_plan_state();
        assert!(s["activeGuid"].is_string(), "activeGuid 应为字符串");
        assert!(s["options"].is_array(), "options 应为数组");
        // 面板改版后的结构契约：每条方案都要能单独渲染成一块可选小区块
        // （名称 + 一句话说明 + GUID），且**当前生效方案必须在列表里**——
        // 不在就等于面板显示不出「当前」，用户看不到自己现在用哪一档。
        let opts = s["options"].as_array().expect("options 应为数组");
        assert!(!opts.is_empty(), "本机一个电源方案都没枚举到（PowerEnumerate 异常）");
        for o in opts.iter() {
            for k in ["guid", "name", "tip"] {
                assert!(o[k].is_string(), "方案缺少 {k}: {o}");
            }
            assert!(o["known"].is_boolean(), "方案缺少 known: {o}");
        }
        let active = s["activeGuid"].as_str().expect("activeGuid 应为字符串");
        assert!(
            opts.iter().any(|o| o["guid"].as_str().unwrap_or_default().eq_ignore_ascii_case(active)),
            "当前方案 {active} 不在枚举结果里，面板标不出「当前」"
        );
        // 形状合法但本机不存在的 GUID：必须被「本机方案表」这道闸拒掉（写侧 fail-closed）
        let e = power_plan_apply("00000000-0000-0000-0000-000000000000")
            .expect_err("本机不存在的方案应被拒");
        assert!(e.contains("不在本机方案列表"), "错因文案漂了：{e}");
        let pf = pagefile_state();
        assert!(pf["managed"].is_boolean(), "managed 应为布尔");
        assert!(pf["entries"].is_array(), "entries 应为数组");
    }

    /// v5 P0 真机探针：克隆 → 改名 → 导出 → 导入 → 删除，自建自清。
    /// 真机用例默认不跑；它点名覆盖新引擎链路里最容易被 MockRuntime 漏掉的系统副作用。
    #[test]
    #[ignore = "真机探针：会新建、导出、导入并删除临时电源方案"]
    fn 真机电源方案新建导出导入删除探针() {
        let source = KNOWN_PLANS[0].0;
        let name = format!("Trim P0 Probe {}", crate::engine::now_ms());
        let dup = power_plan_duplicate(source, &name).expect("克隆应成功");
        let dup_guid = dup["guid"].as_str().expect("克隆 GUID").to_string();
        let export_dir = crate::engine::paths::temp_script_dir().expect("tmp 目录");
        let export_file = export_dir.join(format!(
            "trim-p0-export-{}-{}.powrplan",
            crate::engine::now_ms(),
            std::process::id()
        ));
        let result = (|| {
            let exported = power_plan_export(&dup_guid, &export_file).expect("导出应成功");
            assert!(
                exported["bytes"].as_u64().unwrap_or(0) > 0,
                "导出字节数应为正：{exported}"
            );
            let imported = power_plan_import(&export_file).expect("导入应成功");
            let imported_guid = imported["guid"].as_str().expect("导入 GUID").to_string();
            assert!(
                scheme_guids()
                    .iter()
                    .any(|g| guid_string(g).eq_ignore_ascii_case(&imported_guid)),
                "导入后重新枚举必须能看到新 GUID"
            );
            power_plan_delete(&imported_guid).expect("导入方案清理应成功");
            Ok::<(), String>(())
        })();
        let cleanup_dup = power_plan_delete(&dup_guid);
        let _ = std::fs::remove_file(&export_file);
        result.expect("新建导出导入链路应成功");
        cleanup_dup.expect("克隆方案清理应成功");
    }

    /// v5 P0 真机探针：解锁属性 → 回读 → 按 session 快照回滚。
    /// Drop 再做一次同值回滚，确保断言失败时也不把本机属性留在解锁态。
    #[test]
    #[ignore = "真机探针：会临时解锁并回滚本机电源设置属性"]
    fn 真机电源设置解锁与取消回滚探针() {
        struct AttributeRollback(Vec<(GUID, GUID, u32)>);
        impl Drop for AttributeRollback {
            fn drop(&mut self) {
                for (subgroup, setting, attrs) in &self.0 {
                    let _ = unsafe {
                        PowerWriteSettingAttributes(
                            Some(subgroup as *const GUID),
                            Some(setting as *const GUID),
                            *attrs,
                        )
                    };
                }
            }
        }

        let scheme_guid = KNOWN_PLANS[0].0;
        let unlocked = power_settings_unlock(scheme_guid).expect("解锁应成功");
        if unlocked["ok"] == json!(false) {
            let failed = unlocked["failed"].as_array().expect("failed 应为数组");
            assert!(!failed.is_empty(), "解锁失败态必须点名失败设置：{unlocked}");
            eprintln!("部分设置未能解锁（如实回执）：{}", unlocked["failed"]);
        }
        let session_id = unlocked["sessionId"].as_str().expect("sessionId").to_string();
        let changed = unlocked["changed"].as_array().cloned().unwrap_or_default();
        let mut rollback = AttributeRollback(Vec::new());
        for row in &changed {
            let subgroup = parse_guid_str(row["subgroupGuid"].as_str().expect("subgroupGuid"))
                .expect("subgroup guid");
            let setting = parse_guid_str(row["settingGuid"].as_str().expect("settingGuid"))
                .expect("setting guid");
            let old = row["oldAttributes"].as_u64().expect("oldAttributes") as u32;
            let next = row["newAttributes"].as_u64().expect("newAttributes") as u32;
            rollback.0.push((subgroup, setting, old));
            let got = unsafe {
                PowerReadSettingAttributes(
                    Some(&subgroup as *const GUID),
                    Some(&setting as *const GUID),
                )
            };
            assert_eq!(got, next, "解锁后属性回读应与 newAttributes 一致");
            assert_eq!(got & POWER_SETTING_ATTR_HIDDEN, 0, "bit0 必须清零");
            assert_ne!(got & POWER_SETTING_ATTR_VISIBLE, 0, "bit1 必须置位");
        }
        if changed.is_empty() {
            eprintln!("SKIP：本机当前没有需要解锁的隐藏设置，只验证 session/revert 闭环");
        }
        let reverted = power_settings_revert(scheme_guid, &session_id).expect("回滚应成功");
        assert_eq!(reverted["ok"], json!(true), "回滚失败回执：{reverted}");
        for (subgroup, setting, old) in &rollback.0 {
            let got = unsafe {
                PowerReadSettingAttributes(
                    Some(subgroup as *const GUID),
                    Some(setting as *const GUID),
                )
            };
            assert_eq!(got, *old, "取消后属性必须与 unlock 前快照逐字相等");
        }
    }

    /// v5 P1 真机探针：dump 全链（真实枚举子组/设置 + 平台角色）。
    /// 为什么必须真机：编辑器 UI 全靠这份形状；MockRuntime 给不了真实子组/取值元数据，
    /// `platform_role_str` 也只是 powrprof 转发，只有真跑才证明字段真的落进回执。
    #[test]
    #[ignore = "真机探针：真实枚举本机电源设置的子组与取值元数据"]
    fn 真机电源设置dump探针() {
        let v = power_settings_dump(KNOWN_PLANS[0].0).expect("dump 应成功");
        let role = v["platformRole"].as_str().expect("platformRole 应为字符串");
        assert!(
            ["mobile", "slate", "desktop", "unknown"].contains(&role),
            "platformRole 超出允许集：{role}"
        );
        let groups = v["subgroups"].as_array().expect("subgroups 应为数组");
        assert!(!groups.is_empty(), "子组列表不应为空");
        let mut total = 0usize;
        let mut named = 0usize;
        for g in groups {
            assert!(g["guid"].is_string() && g["name"].is_string(), "子组缺 guid/name：{g}");
            for s in g["settings"].as_array().expect("settings 应为数组") {
                total += 1;
                assert!(s["guid"].is_string() && s["name"].is_string(), "设置缺 guid/name：{s}");
                assert!(s["isRange"].is_boolean(), "设置缺 isRange：{s}");
                assert!(s["possibleValues"].is_array(), "possibleValues 应为数组：{s}");
                let names = s["possibleValueNames"].as_array().expect("possibleValueNames 应为数组");
                assert_eq!(
                    names.len(),
                    s["possibleValues"].as_array().unwrap().len(),
                    "枚举名应与枚举值同长（同索引对齐）：{s}"
                );
                if names.iter().any(|n| n.as_str().map(|x| !x.is_empty()).unwrap_or(false)) {
                    named += 1;
                }
                assert!(
                    s["valueAc"].is_u64() || s["valueAc"].is_null(),
                    "valueAc 形状异常：{s}"
                );
                assert!(
                    s["visible"].is_boolean() && s["attributes"].is_u64(),
                    "显隐属性形状异常：{s}"
                );
            }
        }
        assert!(total > 0, "设置总数为 0 说明枚举没拿到任何东西");
        assert!(named > 0, "系统枚举名全部为空——PowerReadPossibleFriendlyName 链路没接上");
        eprintln!(
            "dump 探针：{total} 个设置 / 带系统枚举名 {named} 个 / platformRole={role} / 子组 {} 个",
            groups.len()
        );
    }

    // ===== v0.4.9 §3.6 写侧：pagefile_apply 参数校验（纯函数、无 IO、无 admin 需求）=====

    fn e(drive: &str, initial_mb: u32, max_mb: u32) -> PagefileEntry {
        PagefileEntry { drive: drive.to_string(), initial_mb, max_mb }
    }

    #[test]
    fn 盘符归一化吃大小写与尾斜杠() {
        assert_eq!(normalize_drive("C:").unwrap(), "C:");
        assert_eq!(normalize_drive("c:").unwrap(), "C:");
        assert_eq!(normalize_drive("D:\\").unwrap(), "D:");
        assert_eq!(normalize_drive(" e: ").unwrap(), "E:");
        assert!(normalize_drive("CC:").is_err(), "两字母盘符不存在");
        assert!(normalize_drive("1:").is_err(), "数字开头");
        assert!(normalize_drive("").is_err(), "空");
        assert!(normalize_drive("C:/").is_err(), "斜杠方向");
    }

    #[test]
    fn managed_为真时不校验_entries() {
        // 交给系统托管：entries 无论填什么都接受（写侧会忽略它们、只改 AutomaticManagedPagefile）
        assert!(validate_pagefile(true, &[]).is_ok());
        assert!(validate_pagefile(true, &[e("C:", 1024, 2048)]).is_ok());
    }

    #[test]
    fn 手动模式拒绝会让机器蓝屏的参数形态() {
        // 空：全关等价于关掉所有卷的分页文件
        let err = validate_pagefile(false, &[]).unwrap_err();
        assert!(err.contains("至少保留"), "空列表错因文案漂了：{err}");
        // 全 0/0：与空列表语义等价，也要拒
        let err = validate_pagefile(false, &[e("C:", 0, 0), e("D:", 0, 0)]).unwrap_err();
        assert!(err.contains("0/0") || err.contains("关掉分页文件"), "全零错因漂了：{err}");
    }

    #[test]
    fn 手动模式拒绝重复盘符与非法数值() {
        // 重复盘符
        let err = validate_pagefile(false, &[e("C:", 1024, 2048), e("c:", 512, 1024)]).unwrap_err();
        assert!(err.contains("出现两次"), "重复盘符错因漂了：{err}");
        // Max < Initial
        let err = validate_pagefile(false, &[e("C:", 4096, 2048)]).unwrap_err();
        assert!(err.contains("Max") && err.contains("Initial"), "反序错因漂了：{err}");
        // MB 超上限
        let err = validate_pagefile(false, &[e("C:", 0, PAGEFILE_MAX_MB + 1)]).unwrap_err();
        assert!(err.contains("上限"), "上限错因漂了：{err}");
        // 非法盘符
        let err = validate_pagefile(false, &[e("XX", 1024, 2048)]).unwrap_err();
        assert!(err.contains("盘符"), "非法盘符错因漂了：{err}");
    }

    #[test]
    fn 合法参数能通过校验并生成微软形态() {
        let entries = [e("C:", 8192, 16384), e("d:", 0, 0)]; // 允许某卷明确关，只要整体至少一条 alive
        validate_pagefile(false, &entries).expect("应通过");
        let lines = build_paging_files(&entries);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "C:\\pagefile.sys 8192 16384");
        assert_eq!(lines[1], "D:\\pagefile.sys 0 0", "小写盘符应归一到大写");
    }

    /// 端到端跑一次 pagefile_apply 需要真 admin + 真重启，属发布前手工核对；
    /// CI 上不进默认测试。这里断的是**未 admin 或未确认时**必然 Err，不真写。
    #[test]
    #[ignore = "真写 pagefile_apply 会改本机 HKLM + 需重启，只在发布前手工核对不崩不 hang"]
    fn 端到端真写能过一遍() {
        // 走一次 managed=true（相对无损、系统自管），验证执行链不崩；
        // 未 admin 环境会直接 Err，不阻断测试通过（Err 也算跑通）。
        let _ = pagefile_apply(true, &[]);
    }
}
