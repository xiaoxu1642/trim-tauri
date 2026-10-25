//! `.lnk` 目标解析（IShellLinkW + IPersistFile）。
//!
//! 启动项扫描此前把 `.lnk` 文件本身当 `command`（`startup.rs` 旧注释「简化实现」），
//! 路径清单也不解析开始菜单快捷方式的目标。这里收成一份实现：
//! `GetPath` 取目标、`GetArguments` 取参数；失败/空目标返回 `None`，调用方保留原路径。
//!
//! COM 套间：调用线程可能已在 MTA（扫描线程池），`CoInitializeEx` 返回
//! `RPC_E_CHANGED_MODE` 时继续用现有套间，且**不**由本模块反初始化。

use std::path::Path;

use windows::core::{HSTRING, Interface};
use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED, STGM_READ,
};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

struct ComGuard(bool);

impl ComGuard {
    fn acquire() -> Option<Self> {
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if hr.is_ok() {
            Some(Self(true))
        } else if hr == RPC_E_CHANGED_MODE {
            // 线程已在其它套间：可用，但反初始化不归我们
            Some(Self(false))
        } else {
            None
        }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

/// 解析 `.lnk` 的目标（含参数）。失败、非快捷方式、空目标都返回 `None`。
pub fn resolve_lnk(path: &Path) -> Option<String> {
    let _com = ComGuard::acquire()?;
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let persist: IPersistFile = link.cast().ok()?;
        let h = HSTRING::from(path.to_string_lossy().to_string());
        persist.Load(&h, STGM_READ).ok()?;
        let mut buf = [0u16; 1024];
        link.GetPath(&mut buf, std::ptr::null_mut(), 0).ok()?;
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let target = String::from_utf16_lossy(&buf[..end]);
        if target.trim().is_empty() {
            return None;
        }
        let mut args_buf = [0u16; 1024];
        let args = if link.GetArguments(&mut args_buf).is_ok() {
            let aend = args_buf.iter().position(|&c| c == 0).unwrap_or(args_buf.len());
            String::from_utf16_lossy(&args_buf[..aend])
        } else {
            String::new()
        };
        Some(if args.trim().is_empty() { target } else { format!("{target} {args}") })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 自建一个 .lnk（目标用系统自带的 notepad.exe），解析结果必须命中目标。
    /// 判红自证：把 `GetPath` 换成空串 / 删掉 Load ⇒ 断言红。
    #[test]
    fn 解析自建快捷方式的目标() {
        let sb = crate::testutil::Sandbox::new("lnk-resolve");
        let lnk = sb.path().join("probe.lnk");
        let target = r"C:\Windows\notepad.exe";
        let _com = ComGuard::acquire().expect("COM 初始化");
        unsafe {
            let link: IShellLinkW =
                CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).expect("ShellLink");
            link.SetPath(&HSTRING::from(target)).expect("SetPath");
            let persist: IPersistFile = link.cast().expect("IPersistFile");
            persist
                .Save(&HSTRING::from(lnk.to_string_lossy().to_string()), true)
                .expect("Save");
        }
        let resolved = resolve_lnk(&lnk).expect("应解析出目标");
        assert!(
            resolved.to_lowercase().contains("notepad.exe"),
            "解析结果不含目标：{resolved}"
        );
    }

    /// 真机探针：解析用户启动文件夹里的真实 .lnk；分别测未初始化线程（STA）与 MTA。
    #[test]
    #[ignore = "真机探针：读取本机启动文件夹的 Ollama.lnk"]
    fn 解析真实快捷方式探针() {
        let p = std::path::PathBuf::from(std::env::var("APPDATA").unwrap_or_default())
            .join(r"Microsoft\Windows\Start Menu\Programs\Startup\Ollama.lnk");
        if !p.exists() {
            println!("SKIP：本机没有 Ollama.lnk");
            return;
        }
        println!("STA resolve={:?}", resolve_lnk(&p));
        let hr = unsafe { CoInitializeEx(None, windows::Win32::System::Com::COINIT_MULTITHREADED) };
        println!("MTA init hr={hr:?} resolve={:?}", resolve_lnk(&p));
        if hr.is_ok() {
            unsafe { CoUninitialize() };
        }
    }

}
