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

/// 停止服务
pub(super) unsafe fn service_stop(name: &str) -> bool {
    use windows::Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, ControlService, CloseServiceHandle,
        SC_MANAGER_CONNECT, SERVICE_STOP, SERVICE_CONTROL_STOP, SERVICE_STATUS,
    };
    let scm = match OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let name_w = to_wide(name);
    let svc = match OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_STOP) {
        Ok(s) => s,
        Err(_) => { let _ = CloseServiceHandle(scm); return false; }
    };
    let mut status = SERVICE_STATUS::default();
    let ok = ControlService(svc, SERVICE_CONTROL_STOP, &mut status).is_ok();
    let _ = CloseServiceHandle(svc);
    let _ = CloseServiceHandle(scm);
    ok
}

/// 设置服务启动类型（SERVICE_DEMAND_START=Manual, SERVICE_DISABLED=Disabled, SERVICE_AUTO_START=Automatic）
pub(super) unsafe fn service_set_start_type(name: &str, start_type: u32) -> bool {
    use windows::Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, ChangeServiceConfigW, CloseServiceHandle,
        SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG, SERVICE_NO_CHANGE,
    };
    let scm = match OpenSCManagerW(PCWSTR::default(), PCWSTR::default(), SC_MANAGER_CONNECT) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let name_w = to_wide(name);
    let svc = match OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_CHANGE_CONFIG) {
        Ok(s) => s,
        Err(_) => { let _ = CloseServiceHandle(scm); return false; }
    };
    // ChangeServiceConfigW: 不需要改的参数传 SERVICE_NO_CHANGE
    use windows::Win32::System::Services::{SERVICE_ERROR, ENUM_SERVICE_TYPE, SERVICE_START_TYPE};
    let ok = ChangeServiceConfigW(
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
    ).is_ok();
    let _ = CloseServiceHandle(svc);
    let _ = CloseServiceHandle(scm);
    ok
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

/// 停止服务（`Stop-Service -Name X -Force` 的等价物）
pub fn service_stop_pub(name: &str) -> Result<(), String> {    unsafe {
        if service_stop(name) {
            Ok(())
        } else {
            Err(format!("停止服务失败: {name}"))
        }
    }
}

/// 设置服务启动类型（`sc.exe config X start= N` 的等价物）
pub fn service_set_start_pub(name: &str, start: u32) -> Result<(), String> {
    unsafe {
        if service_set_start_type(name, start) {
            Ok(())
        } else {
            Err(format!("设置服务启动类型失败: {name} → {start}"))
        }
    }
}
