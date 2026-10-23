//! 服务查询与启停原语（B8 服务域 + B11 的服务出口）。
//!
//! 独立成文件的原因：service_status / service_start_type_is 被 overview 体检、netcheck、
//! 维护任务等多域调用，是 native 里扇入最高的写侧 helper 之一。
//! `SVC_START_DISABLED` 暴露给调用方做比较，避免它们自己 import windows crate。


use windows::core::PCWSTR;
use windows::Win32::System::Services::{CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_STATUS};
use super::common::*;
// ==================== B8 netcheck_status：网络连通性检测 ====================


/// 查询服务状态（Running/Stopped 等）
pub(super) unsafe fn service_status(name: &str) -> Option<(u32, u32)> {
    // 返回 (currentState, startType)；startType 需要 QueryServiceConfig，简化为 0
    // v6-P2（R5/A5 panic 族）：旧写法 `if is_err { return }` + 紧跟 `.unwrap()`——
    // 不变量靠约定不靠类型。改结构化 match：句柄失败路径显式关上游句柄，unwrap 从
    // 生产面消失（与同文件 service_stop 的 map_err 口径一致）。
    let scm = match OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT) {
        Ok(h) => h,
        Err(_) => return None,
    };
    let name_w = to_wide(name);
    let svc = match OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_STATUS) {
        Ok(h) => h,
        Err(_) => {
            let _ = CloseServiceHandle(scm);
            return None;
        }
    };
    let mut status = SERVICE_STATUS::default();
    let ok = QueryServiceStatus(svc, &mut status as *mut _);
    let _ = CloseServiceHandle(svc);
    let _ = CloseServiceHandle(scm);
    if ok.is_err() { return None; }
    Some((status.dwCurrentState.0, 0))
}

/// 停止服务（`Stop-Service -Name X -Force` 的**动作**侧等价物）
///
/// 返回 win32 错误码而不是 bool：调用方需要区分「本来就停着 / 服务没装」与「真停不动」，
/// 这正是 v5 O-1 修掉的东西 —— 压成 bool 之后 1062 与 5（拒绝访问）长得一模一样。
/// `ControlService` 返回成功只代表停止请求被接受（可能还在 STOP_PENDING），故这里回读
/// 终态：最多等 1s，仍未停稳按成功返回（请求已受理，启动类型随后由 SvcSetStart 钉死）。
pub(super) unsafe fn service_stop(name: &str) -> Result<(), u32> {
    use windows::Win32::System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
        SERVICE_CONTROL_STOP, SERVICE_STOP, SERVICE_STATUS,
    };
    let scm = OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT)
        .map_err(|e| win32_of(&e))?;
    let name_w = to_wide(name);
    let svc = match OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_STOP) {
        Ok(s) => s,
        Err(e) => {
            let _ = CloseServiceHandle(scm);
            return Err(win32_of(&e));
        }
    };
    let mut status = SERVICE_STATUS::default();
    let r = ControlService(svc, SERVICE_CONTROL_STOP, &mut status).map_err(|e| win32_of(&e));
    if r.is_ok() {
        // 回读终态（1s / 50ms 一档）：只有真在运行的服务才会走到这里，代价可控
        for _ in 0..20 {
            if QueryServiceStatus(svc, &mut status).is_err() || status.dwCurrentState.0 == SVC_STOPPED {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if status.dwCurrentState.0 != SVC_STOPPED {
            crate::engine::log::write_log(
                "info",
                &format!("服务 {name} 停止请求已受理但 1s 内未停稳（state={}），按已受理记账", status.dwCurrentState.0),
            );
        }
    }
    let _ = CloseServiceHandle(svc);
    let _ = CloseServiceHandle(scm);
    r
}

/// HRESULT → win32 码。`HRESULT_FROM_WIN32(x)` = `0x8007xxxx`，低位段就是原码。
/// R9（2026-10-15）：卸载启动把 `ERROR_CANCELLED` 从 HRESULT 里折出来的口径也引这里
/// （`pub(crate)` + `mod.rs` re-export，与 to_wide 同姿势）——判「用户拒了 UAC」不许再写
/// 第二份折叠。
pub(crate) fn win32_of(e: &windows::core::Error) -> u32 {
    e.code().0 as u32 & 0x0000_FFFF
}

/// `SERVICE_STOPPED` / `ERROR_SERVICES_NOT_ACTIVE` / `ERROR_SERVICE_DOES_NOT_EXIST`
const SVC_STOPPED: u32 = 1;
const SVC_NOT_RUNNING: u32 = 1062;
const SVC_NOT_INSTALLED: u32 = 1060;

/// 设置服务启动类型。**数值以 windows crate 常量为真源**（0.61.3 实测）：
/// `SERVICE_AUTO_START = 2`（自动）/ `SERVICE_DEMAND_START = 3`（手动）/ `SERVICE_DISABLED = 4`（禁用）。
/// 另两档 `SERVICE_BOOT_START = 1` / `SERVICE_SYSTEM_START = 1` 数据层暂不使用。
///
/// 返回 win32 码而非 bool，理由同 [`service_stop`]：调用方要能区分「服务没装」与「改不动」。
pub(super) unsafe fn service_set_start_type(name: &str, start_type: u32) -> Result<(), u32> {
    use windows::Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, ChangeServiceConfigW, CloseServiceHandle,
        SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG, SERVICE_NO_CHANGE,
    };
    let scm = OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT)
        .map_err(|e| win32_of(&e))?;
    let name_w = to_wide(name);
    let svc = match OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_CHANGE_CONFIG) {
        Ok(s) => s,
        Err(e) => { let _ = CloseServiceHandle(scm); return Err(win32_of(&e)); }
    };
    // ChangeServiceConfigW: 不需要改的参数传 SERVICE_NO_CHANGE
    use windows::Win32::System::Services::{SERVICE_ERROR, ENUM_SERVICE_TYPE, SERVICE_START_TYPE};
    let r = ChangeServiceConfigW(
        svc,
        ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),  // dwServiceType
        SERVICE_START_TYPE(start_type),        // dwStartType
        SERVICE_ERROR(SERVICE_NO_CHANGE),      // dwErrorControl
        PCWSTR::default(),                     // lpBinaryPathName
        PCWSTR::default(),                     // lpLoadOrderGroup
        None,                                  // lpdwTagId
        PCWSTR::default(),                     // lpDependencies
        PCWSTR::default(),                     // lpServiceStartName
        PCWSTR::default(),                     // lpPassword
        PCWSTR::default(),                     // lpDisplayName
    ).map_err(|e| win32_of(&e));
    let _ = CloseServiceHandle(svc);
    let _ = CloseServiceHandle(scm);
    r
}

/// 服务启动类型（从 `SERVICE_BOOT_START` 到 `SERVICE_DISABLED` 的取值，数值以
/// windows crate 常量为真源）。
///
/// 返回 `None` = 服务不存在 / SCM 打不开 / 读配置失败。调用方必须自己决定
/// 「读不到」算不算拒绝——DISM 预检把 None 当「不可用」（fail-fast），
/// 而 `service_start_type_is` 沿用旧口径：服务没了不算「优化已生效」。
///
/// 2026-10-23：从 [`service_start_type_is`] 提取——DISM 前置检查需要区分
/// 「不存在」「已禁用」「手动/自动」，布尔判据给不出这三种。
pub fn service_start_type(name: &str) -> Option<u32> {
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
        QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
    };
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT).ok()?;
        let name_w = to_wide(name);
        let svc = match OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_CONFIG) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseServiceHandle(scm);
                return None;
            }
        };
        // 两段式：先取需要的字节数，再分配重查（QueryServiceConfigW 的标准用法）
        let mut needed = 0u32;
        let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
        let start = if needed == 0 {
            None
        } else {
            let mut buf = vec![0u8; needed as usize];
            let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
            QueryServiceConfigW(svc, Some(cfg), needed, &mut needed)
                .ok()
                .map(|_| (*cfg).dwStartType.0)
        };
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        start
    }
}

/// 服务启动类型是否等于期望值（B11：原 PS `Get-Service ... StartType -eq 'Disabled'` 的原生等价）
///
/// 走 `QueryServiceConfigW`（需要 `SERVICE_QUERY_CONFIG`，不是 `service_status` 用的
/// `SERVICE_QUERY_STATUS`）。服务不存在 = `false`：检测语义是「这项优化是否已生效」，
/// 服务没了当然不算生效。
pub fn service_start_type_is(name: &str, expected: u32) -> bool {
    service_start_type(name) == Some(expected)
}

/// 服务是否在本机存在（`sc query X` 的原生等价）
///
/// 存在性判据必须与「运行态」分开：R0-a 起 `{service, startType}` 形态**刻意不停服**，
/// 拿运行态当「这一步做成了吗」的判据会把它误判成失败。
pub fn service_exists(name: &str) -> bool {
    use windows::Win32::System::Services::{OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT};
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT) else {
            return false;
        };
        let name_w = to_wide(name);
        let svc = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_STATUS);
        let _ = CloseServiceHandle(scm);
        // v4 R5-M06：OpenServiceW 成功的句柄必须关 —— 旧实现 `.is_ok()` 直接丢弃句柄，
        // 而本函数挂在巡检热路径上（每个服务一次），一轮就是几十上百个句柄泄漏。
        match svc {
            Ok(h) => {
                let _ = CloseServiceHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

/// 服务「不存在（已卸载）或启动类型等于期望值」判据（2026-10-11 裁定 7：tf_defender 专用）。
///
/// 与 [`service_start_type_is`] 的唯一语义差别在「服务不存在」：
/// - 通用判据把不存在一律算 false（服务没了不等于「我这项优化生效了」）；
/// - 本判据把 **ERROR_SERVICE_DOES_NOT_EXIST(1060)** 显式算 true —— 对
///   「关闭系统防护」这类项，防护本体（WinDefend 服务）已被卸载时，产品语义就是
///   「防护已不在」，体检应显示已禁用，而不是 AND 链恒 false、永远报未优化。
///
/// fail-closed 边界：SCM 打不开、OpenService 因权限等**非 1060** 错误失败，一律 false，
/// 绝不把「读不到」报成「已卸载」。
pub fn service_absent_or_start_is(name: &str, expected: u32) -> bool {
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
        QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
    };
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT) else {
            return false;
        };
        let name_w = to_wide(name);
        let svc = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_CONFIG);
        let svc = match svc {
            Ok(h) => h,
            Err(e) => {
                let _ = CloseServiceHandle(scm);
                return win32_of(&e) == SVC_NOT_INSTALLED;
            }
        };
        let mut needed = 0u32;
        let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
        let verdict = if needed == 0 {
            false
        } else {
            let mut buf = vec![0u8; needed as usize];
            let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
            match QueryServiceConfigW(svc, Some(cfg), needed, &mut needed) {
                Ok(()) => (*cfg).dwStartType.0 == expected,
                Err(_) => false,
            }
        };
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        verdict
    }
}

/// `SERVICE_DISABLED`（供跨 crate 比较，避免调用方 import windows crate）
pub const SVC_START_DISABLED: u32 = windows::Win32::System::Services::SERVICE_DISABLED.0;

/// `SERVICE_DEMAND_START`（手动启动）。与 [`SVC_START_DISABLED`] 同理由导出。
pub const SVC_START_MANUAL: u32 = windows::Win32::System::Services::SERVICE_DEMAND_START.0;

/// `SERVICE_AUTO_START`（自动启动）。同上。
pub const SVC_START_AUTO: u32 = windows::Win32::System::Services::SERVICE_AUTO_START.0;

/// 数据层 `startType` 字符串 → `dwStartType` 期望值。
///
/// **fail-closed 是这里的设计要点**（R0-b 起 `startType` 是被执行链与检测侧共同消费
/// 的字段）：未知取值必须 `Err`，绝不能静默跳到某个默认值。旧实现里
/// `{service, startType}` 这种步骤走 service 分支时 `startType` **根本不被读取**，
/// 于是「改手动启动」被当成「停一下」执行并报成功 —— 而数据层 `label`/`desc` 都写着
/// 「不立即停止」。新增枚举值时若这里猜一个值，等于凭空造一个静默盲区。
pub fn start_type_from_label(label: &str) -> Result<u32, String> {
    match label {
        "manual" => Ok(SVC_START_MANUAL),
        "automatic" => Ok(SVC_START_AUTO),
        "disabled" => Ok(SVC_START_DISABLED),
        other => Err(format!(
            "未知 startType: {other}（合法值 manual / automatic / disabled）"
        )),
    }
}

/// win32 服务类错误码 → 人话（口径对齐 `pssteps::reg_err`：把码翻译成「为什么」）
fn svc_err(code: u32) -> String {
    match code {
        5 => "拒绝访问：停止/改写服务需要管理员权限".to_string(),
        1051 => "它还有依赖服务在跑，因此没能停下来（启动类型那一步不受影响，重启后按新启动类型生效）；\
                Trim 不连带停掉它的依赖服务——那会把正在用这些依赖的功能一起带走"
            .to_string(),
        1060 => "本机没有安装该服务（目标状态已达成）".to_string(),
        1062 => "服务本就未启动（目标状态已达成）".to_string(),
        1058 => "服务已被禁用、无法启动".to_string(),
        1077 => "上一次停止请求仍在进行中".to_string(),
        other => format!("win32={other}"),
    }
}

/// 停止服务（`Stop-Service -Name X -Force -ErrorAction SilentlyContinue` 的等价物）
///
/// **终态语义，不是动作语义**：优化项要的是「别在跑」。1062（本就未启动）与 1060（本机没装
/// 这个服务，如 Win11 24H2 已卸载 Fax）都等于目标已达成 → 判 Ok。数据层原文本来就写着
/// `-ErrorAction SilentlyContinue`，原生化时把这层语义丢了（v5 O-1）：于是「已生效」的项恒报
/// 「停止服务失败」，再叠加 `pssteps::execute()` 的首错中断，砍掉同一步骤余下的全部操作。
pub fn service_stop_pub(name: &str) -> Result<(), String> {
    unsafe {
        match service_stop(name) {
            Ok(()) => Ok(()),
            Err(c) if matches!(c, SVC_NOT_RUNNING | SVC_NOT_INSTALLED) => Ok(()),
            Err(c) => Err(format!("停止服务失败: {name} —— {}", svc_err(c))),
        }
    }
}

/// 设置服务启动类型（`sc.exe config X start= N 2>$null` 的等价物）
///
/// 同 [`service_stop_pub`] 的终态口径：服务没装（1060）= 它不会自己起来 = 目标已达成。
pub fn service_set_start_pub(name: &str, start: u32) -> Result<(), String> {
    unsafe {
        match service_set_start_type(name, start) {
            Ok(()) => Ok(()),
            Err(SVC_NOT_INSTALLED) => Ok(()),
            Err(c) => Err(format!("设置服务启动类型失败: {name} → {start} —— {}", svc_err(c))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// service_absent_or_start_is 的 1060「已卸载」分支真机探针（AGENTS §1.6 第二问：
    /// 走真实 SCM 的新判据必须配 #[ignore] 探针，不能只靠推断）。
    ///
    /// 验收机即「已卸载 Defender」的机器：此时 WinDefend 打开应得 1060，
    /// 特判必须为 true（UI 因此显示「已禁用」而不是「未优化」）。
    /// 普通机器（Defender 在、Start=2）上此断言应为 false —— 用 ignore 让两种
    /// 机器都按各自预期手动跑，不进快速组。
    #[ignore = "真机探针：WinDefend 状态因机而异（卸载机期望 true，普通机期望 false）"]
    #[test]
    fn defender_absent_or_disabled_probe() {
        let v = service_absent_or_start_is("WinDefend", SVC_START_DISABLED);
        eprintln!("WinDefend absent-or-disabled = {v}（卸载/已禁用机应为 true）");
        // 只断言调用本身不崩；true/false 的期望由验收人按机器形态核对输出。
        let _ = v;
    }

    /// 1060 分支的正向对照（任何机器都成立）：现造一个不可能存在的服务名，
    /// 必须落「已卸载=true」；这同时防「无论服务在不在都判 true」的假绿。
    #[ignore = "真机探针：读真实 SCM，但只读"]
    #[test]
    fn absent_branch_positive_control() {
        // ① 不存在的服务 → true（1060）
        assert!(
            service_absent_or_start_is("TrimNoSuchSvc_Probe_20261011", SVC_START_DISABLED),
            "不存在的服务必须判「已卸载=true」（1060 分支）"
        );
        // ② RpcSs 必然存在且通常为自动(2)，问「禁用(4)」必须 false —— 防止判据恒 true
        assert!(
            !service_absent_or_start_is("RpcSs", SVC_START_DISABLED),
            "RpcSs 存在且非禁用，必须判 false（防 1060 分支把所有服务都判 true）"
        );
    }
}
