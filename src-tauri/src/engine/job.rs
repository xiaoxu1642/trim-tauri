//! 子进程 Job Object 收口（v7.2 P1 U-A5：pwsh 与 systembin 共用同一收树实现）。
//!
//! 刻意**不用** `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`：调用方的脚本/命令可能故意留下
//! 长命进程（清理收尾重启应用、资源管理器收尾拉起 explorer），正常结束时关句柄不能
//! 连带杀成员。只有超时才显式 `TerminateJobObject`。

use windows::Win32::Foundation::HANDLE;

/// 一次性 Job Object 句柄；Drop 只关句柄（**不**杀成员）。
pub(crate) struct ProcessJob(HANDLE);

impl ProcessJob {
    /// 建 job 并把**已 spawn 的子进程**放进去。任一步失败都返回 `Err`，调用方降级为
    /// 「只杀直接子进程」的旧行为 —— 建不了 job 不该让整条执行链失败。
    pub(crate) fn create_for(child_pid: u32) -> Result<Self, String> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };
        unsafe {
            let job = CreateJobObjectW(None, PCWSTR::null())
                .map_err(|e| format!("建 Job 失败: {e}"))?;
            // AssignProcessToJobObject 要求进程句柄带 PROCESS_SET_QUOTA | PROCESS_TERMINATE，
            // std::process::Child 自带的那个权限位不足，故按 PID 另开一个。
            // PID 复用窗口极小：就在 spawn 之后的这几微秒内，且子进程尚未退出。
            let proc = match OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                child_pid,
            ) {
                Ok(h) => h,
                Err(e) => {
                    let _ = CloseHandle(job);
                    return Err(format!("打开子进程句柄失败: {e}"));
                }
            };
            let assigned = AssignProcessToJobObject(job, proc);
            let _ = CloseHandle(proc);
            if let Err(e) = assigned {
                let _ = CloseHandle(job);
                return Err(format!("子进程入 Job 失败: {e}"));
            }
            Ok(Self(job))
        }
    }

    /// 终止 job 内**全部**进程（含子孙）。超时专用。
    /// 失败必须让调用方看见——「收树失败」与「收树成功」在回执上不能同形。
    pub(crate) fn terminate(&self) -> Result<(), String> {
        use windows::Win32::System::JobObjects::TerminateJobObject;
        unsafe { TerminateJobObject(self.0, 1).map_err(|e| format!("TerminateJobObject 失败: {e}")) }
    }
}

impl Drop for ProcessJob {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}
