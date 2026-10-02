//! memory:info / memory:processes —— 只读内存与进程采集（原 memory_info.ps1 / memory_processes.ps1）。
//! 输出 JSON 字段与原 PS 脚本逐字段兼容；纯只读，不写盘、不外呼。


use serde_json::{Value, json};
use super::common::*;
// ==================== memory:info ====================

/// 原生读取物理内存 / 页面文件 / Cache Bytes
///
/// 字段映射（对照 memory_info.ps1）：
/// - total/free/used/load ← GlobalMemoryStatusEx
/// - cache                 ← GetPerformanceInfo.SystemCache * PageSize
/// - pageTotal/pageUsed    ← GetPerformanceInfo.CommitLimit/CommitTotal 减去物理量
pub fn memory_info() -> Result<Value, String> {
    unsafe {
        use windows::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
        use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

        let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
        ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut ms).map_err(|_| "GlobalMemoryStatusEx 失败".to_string())?;

        let mut pi: PERFORMANCE_INFORMATION = std::mem::zeroed();
        GetPerformanceInfo(&mut pi, std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32)
            .map_err(|_| "GetPerformanceInfo 失败".to_string())?;

        let total = ms.ullTotalPhys;
        let free = ms.ullAvailPhys;
        let used = total.saturating_sub(free);
        let load = ms.dwMemoryLoad as i64;
        let page_size = pi.PageSize as u64;
        let cache = pi.SystemCache as u64 * page_size;
        let page_total = (pi.CommitLimit as u64)
            .saturating_sub(pi.PhysicalTotal as u64)
            * page_size;
        let page_used = (pi.CommitTotal as u64)
            .saturating_sub(pi.PhysicalAvailable as u64)
            * page_size;

        Ok(json!({
            "total": total,
            "free": free,
            "used": used,
            "load": load,
            "pageTotal": page_total,
            "pageUsed": page_used,
            "cache": cache,
        }))
    }
}

// ==================== memory:processes ====================

/// 进程快照项（对应 PS 输出的字段名：Id / ProcessName / mem / Path）
pub struct NativeProcess {
    pub pid: u32,
    pub name: String,
    pub working_set: u64,
    pub path: String,
}

/// 原生枚举进程列表，按 WorkingSetSize 降序，取前 300
pub fn memory_processes() -> Result<Vec<NativeProcess>, String> {
    unsafe {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        };

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|_| "CreateToolhelp32Snapshot 失败".to_string())?;

        let mut entries: Vec<NativeProcess> = Vec::new();
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                let pid = pe.th32ProcessID;
                let name = wide_str(pe.szExeFile.as_ptr());

                let mut working_set = 0u64;
                let mut path = String::new();

                if let Ok(proc) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                    let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
                    pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                    if GetProcessMemoryInfo(proc, &mut pmc, pmc.cb).is_ok() {
                        working_set = pmc.WorkingSetSize as u64;
                    }
                    let mut buf = [0u16; 1024];
                    let mut len = buf.len() as u32;
                    if QueryFullProcessImageNameW(
                        proc,
                        PROCESS_NAME_FORMAT(0),
                        PWSTR(buf.as_mut_ptr()),
                        &mut len,
                    )
                    .is_ok()
                    {
                        path = String::from_utf16_lossy(&buf[..len as usize]);
                    }
                    let _ = CloseHandle(proc);
                }

                entries.push(NativeProcess {
                    pid,
                    name,
                    working_set,
                    path,
                });

                pe = std::mem::zeroed();
                pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);

        entries.sort_by(|a, b| b.working_set.cmp(&a.working_set));
        entries.truncate(300);
        Ok(entries)
    }
}

