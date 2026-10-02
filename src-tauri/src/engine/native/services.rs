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
    let scm = OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT);
    if scm.is_err() { return None; }
    let scm = scm.unwrap();
    let name_w = to_wide(name);
    let svc = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_STATUS);
    if svc.is_err() { let _ = CloseServiceHandle(scm); return None; }
    let svc = svc.unwrap();
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
fn win32_of(e: &windows::core::Error) -> u32 {
    e.code().0 as u32 & 0x0000_FFFF
}

/// `SERVICE_STOPPED` / `ERROR_SERVICES_NOT_ACTIVE` / `ERROR_SERVICE_DOES_NOT_EXIST`
const SVC_STOPPED: u32 = 1;
const SVC_NOT_RUNNING: u32 = 1062;
const SVC_NOT_INSTALLED: u32 = 1060;

/// 设置服务启动类型（SERVICE_DEMAND_START=Manual, SERVICE_DISABLED=Disabled, SERVICE_AUTO_START=Automatic）
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

/// 服务启动类型是否等于期望值（B11：原 PS `Get-Service ... StartType -eq 'Disabled'` 的原生等价）
///
/// 走 `QueryServiceConfigW`（需要 `SERVICE_QUERY_CONFIG`，不是 `service_status` 用的
/// `SERVICE_QUERY_STATUS`）。服务不存在 = `false`：检测语义是「这项优化是否已生效」，
/// 服务没了当然不算生效。
pub fn service_start_type_is(name: &str, expected: u32) -> bool {
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
        QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
    };
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT) else {
            return false;
        };
        let name_w = to_wide(name);
        let Ok(svc) = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_CONFIG) else {
            let _ = CloseServiceHandle(scm);
            return false;
        };
        // 两段式：先取需要的字节数，再分配重查（QueryServiceConfigW 的标准用法）
        let mut needed = 0u32;
        let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
        if needed == 0 {
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
            return false;
        }
        let mut buf = vec![0u8; needed as usize];
        let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        let ok = QueryServiceConfigW(svc, Some(cfg), needed, &mut needed).is_ok();
        let start = if ok { (*cfg).dwStartType.0 } else { u32::MAX };
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        ok && start == expected
    }
}

/// `SERVICE_DISABLED`（供跨 crate 比较，避免调用方 import windows crate）
pub const SVC_START_DISABLED: u32 = windows::Win32::System::Services::SERVICE_DISABLED.0;

/// win32 服务类错误码 → 人话（口径对齐 `pssteps::reg_err`：把码翻译成「为什么」）
fn svc_err(code: u32) -> String {
    match code {
        5 => "拒绝访问：停止/改写服务需要管理员权限".to_string(),
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
