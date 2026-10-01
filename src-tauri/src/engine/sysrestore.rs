//! A11 还原点原生侧 —— **只读 spike**（v2-R4，2026-10-01）
//!
//! 要回答的问题只有一个：**原生 WMI 客户端能不能查还原点，以及「有 / 没有 / 查询失败」
//! 三种结果能不能分开**。现行实现走收件箱 PowerShell 的 `Get-ComputerRestorePoint`，
//! 本机实测报 `Provider load failure`（2026-10-01 只读复跑，见 `RpOutcome::Failed` 注释）。
//!
//! 这个失败发生在 **WMI 提供程序层，不是 PowerShell 层** —— 所以「原生化就能修好查询」
//! 是个错误前提。本模块存在的意义就是把它变成可验证的事实而不是推测：
//! 同一条 `SELECT * FROM SystemRestore`，换成原生 COM 客户端跑，看它到底回什么。
//!
//! ## spike 实测结论（2026-10-01 本机，Windows 11 26100 / PS 5.1.26100.7019）
//! ```text
//! 原生 COM 侧：CoInitializeEx ✓ → CoCreateInstance ✓ → ConnectServer("root\default") ✓
//!              → ExecQuery("SELECT * FROM SystemRestore") ✓ → Next ✗ 0x80041013
//!              （WBEM_E_NOT_SUPPORTED）
//! PowerShell 侧：Get-ComputerRestorePoint → Provider load failure
//! 旁证：Win32_ShadowStorage 枚举到 0 条 = 本机没有任何卷开启系统保护
//! ```
//! **结论：A11 的查询侧原生化在本机不可验证**，两侧失败原因同源（SR 提供程序 + 无保护卷），
//! 换 PS 为原生不会让查询变好，只会把「未验证的实现」当成「已完成的迁移」。
//! 因此按 v2-R4 的次序要求：**spike 通过之前生产路径一条不动** —— 查询与创建继续走
//! 收件箱 PowerShell（台账见 `tools/check-ps-callsites.mjs` 的 5 处 `run_inline_ps`），
//! 本模块只保留三态契约与探针，等一台**真的开了系统保护**的机器再复跑
//! `cargo test --lib live_probe_原生wmi查还原点 -- --ignored`。
//!
//! ## 三条实测出来的绑定事实（不是推断，逐条查过 windows 0.61 源码）
//! 1. `IWbemLocator` **只有 `ConnectServer`，没有 `CreateService`**；
//! 2. 全 crate **不导出 `CLSID_WbemLocator`**，只能手写 GUID 常量；
//! 3. 属性读取要 `VARIANT`，连带需要 `Win32_System_Variant` feature（两个 feature 都是新开的，
//!    已登记进方案依赖清单）。
//!
//! ## 刻意不做的事
//! - **不创建还原点**（`SRSetRestorePointW` 的静态可用性另见 `pwsh` 侧记录：本机
//!   `sfc.dll` 导出该符号，而 `srclient.dll` 在 System32/SysWOW64 都不存在）；
//! - 不接进任何 IPC 命令 —— spike 通过之前，生产路径一条都不动（v2 R4 的次序要求）。

use windows::core::{BSTR, GUID, HRESULT};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::Wmi::{
    IEnumWbemClassObject, IWbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
};

/// WbemLocator 的 CLSID。windows 0.61 不导出，值取自 WMI 文档的公开标识符
/// `{4590F811-1D3A-11D0-891F-00AA004B2E24}`。写错的症状是 `REGDB_E_CLASSNOTREG`，
/// 所以这个常量单独有一条断言钉着（见测试）。
const CLSID_WBEM_LOCATOR: GUID = GUID::from_u128(0x4590_F811_1D3A_11D0_891F_00AA004B2E24);

/// `IEnumWbemClassObject::Next` 的「一直等到有对象」超时值（`WBEM_INFINITE`）。
const WBEM_INFINITE: i32 = -1;

/// 一条还原点的最小可辨识信息。
///
/// spike 阶段只取 `GetObjectText` 的原文：属性级读取要 `VARIANT`，那是 spike 通过之后
/// 才值得引入的面（多一个 feature、多一处非 UTF-16 解码失败的可能）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpPoint {
    pub text: String,
}

/// 查询结果。**三态必须分开**——把「查询失败」渲染成「没有还原点」是 v2 R4 明令禁止的形态，
/// 那会让用户以为系统真的没有可回退点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpOutcome {
    /// 枚举到至少一条
    Found(Vec<RpPoint>),
    /// 枚举成功且确实零条（与 Failed 不同：这是「问到了，答案是空」）
    Empty,
    /// 某一阶段失败：带着阶段名与 HRESULT，供上层如实转述
    Failed { stage: &'static str, code: i32, message: String },
}

impl RpOutcome {
    /// 失败与空态必须能被上层区分开地判掉（渲染层据此走不同文案）
    pub fn is_failure(&self) -> bool {
        matches!(self, RpOutcome::Failed { .. })
    }
}

/// COM 初始化守卫：本模块可能被任意线程调用，`CoInitializeEx` 返回
/// `S_FALSE`（该线程已初始化）时**不能**在退出时 `CoUninitialize`，否则会把别人的
/// COM 状态拆了。只有本次真的完成了初始化才配对释放。
struct ComGuard {
    owned: bool,
}

impl ComGuard {
    fn new() -> Result<Self, HRESULT> {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        // S_OK = 本次初始化（要释放）；S_FALSE = 已初始化过（不释放）；其余 = 失败
        if hr.is_err() {
            return Err(hr);
        }
        Ok(Self { owned: hr.0 == 0 })
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.owned {
            unsafe { CoUninitialize() }
        }
    }
}

/// 只读查询本机还原点列表。不写注册表、不建还原点、不动任何系统状态。
pub fn query_restore_points() -> RpOutcome {
    let _com = match ComGuard::new() {
        Ok(g) => g,
        Err(hr) => {
            return RpOutcome::Failed {
                stage: "CoInitializeEx",
                code: hr.0,
                message: "COM 初始化失败".into(),
            }
        }
    };

    let locator: IWbemLocator = match unsafe {
        CoCreateInstance(&CLSID_WBEM_LOCATOR, None, CLSCTX_INPROC_SERVER)
    } {
        Ok(l) => l,
        Err(e) => {
            return RpOutcome::Failed {
                stage: "CoCreateInstance",
                code: e.code().0,
                message: format!("WbemLocator 创建失败: {e}"),
            }
        }
    };

    let empty = BSTR::new();
    let services = match unsafe {
        locator.ConnectServer(
            &BSTR::from("root\\default"),
            &empty,
            &empty,
            &empty,
            0,
            &empty,
            None,
        )
    } {
        Ok(s) => s,
        Err(e) => {
            return RpOutcome::Failed {
                stage: "ConnectServer",
                code: e.code().0,
                message: format!("连接 root\\default 失败: {e}"),
            }
        }
    };

    let enumerator: IEnumWbemClassObject = match unsafe {
        services.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from("SELECT * FROM SystemRestore"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
    } {
        Ok(e) => e,
        Err(err) => {
            // 本机预期落点：`Provider load failure`（0x80041032 WBEM_E_PROVIDER_NOT_LOADED 一类）。
            // 这一条正是「原生化修不好查询」的证据 —— 它和 PowerShell 无关。
            return RpOutcome::Failed {
                stage: "ExecQuery",
                code: err.code().0,
                message: format!("枚举 SystemRestore 失败: {err}"),
            }
        }
    };

    let mut points: Vec<RpPoint> = Vec::new();
    loop {
        let mut obj: [Option<windows::Win32::System::Wmi::IWbemClassObject>; 1] = [None];
        let mut fetched: u32 = 0;
        let hr: HRESULT = unsafe { enumerator.Next(WBEM_INFINITE, &mut obj, &mut fetched) };
        if hr.is_err() {
            return RpOutcome::Failed {
                stage: "Next",
                code: hr.0,
                message: "枚举还原点时中断".into(),
            };
        }
        if fetched == 0 {
            // WBEM_S_FALSE / WBEM_S_NO_MORE_DATA + 零条 = 问完了，答案是真没有
            break;
        }
        if let Some(o) = obj[0].take() {
            let text = unsafe { o.GetObjectText(0) }
                .map(|b| b.to_string())
                .unwrap_or_else(|e| format!("<GetObjectText 失败: {e}>"));
            points.push(RpPoint { text });
        }
        if points.len() >= 64 {
            break; // spike 不需要全量，够证明「能枚举」即可
        }
    }

    if points.is_empty() {
        RpOutcome::Empty
    } else {
        RpOutcome::Found(points)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CLSID 写错的症状是 `REGDB_E_CLASSNOTREG`（0x80040154），而那条错误和
    /// 「这台机器没有 WMI」长得一模一样 —— 所以先把常量本身钉住，别让排查从
    /// 「WMI 坏了」开始绕远。这条不依赖系统状态，可静默跑。
    #[test]
    fn wbem_locator_clsid_字面量正确() {
        assert_eq!(CLSID_WBEM_LOCATOR.data1, 0x4590_F811);
        assert_eq!(CLSID_WBEM_LOCATOR.data2, 0x1D3A);
        assert_eq!(CLSID_WBEM_LOCATOR.data3, 0x11D0);
        assert_eq!(
            CLSID_WBEM_LOCATOR.data4,
            [0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24]
        );
    }

    /// 三态判据的纯逻辑断言：`Empty` 与 `Failed` 不得混为一谈。
    /// 这条不碰系统，防的是以后有人把 `Failed` 折叠成 `Empty` 来"简化"渲染层分支。
    #[test]
    fn 失败态不得被当成空态() {
        let failed = RpOutcome::Failed {
            stage: "ExecQuery",
            code: 0x8004_1032u32 as i32,
            message: "提供程序加载失败".into(),
        };
        assert!(failed.is_failure());
        assert!(!matches!(failed, RpOutcome::Empty));
        assert!(!RpOutcome::Empty.is_failure());
    }

    /// 真机只读探针：回答「原生 WMI 客户端在这台机器上查 SystemRestore 到底回什么」。
    /// 只读，不建还原点、不写注册表。三态都算通过 —— 本用例要的是**打印出真实落点**，
    /// 而不是断言某个特定结果（换一台开了系统保护的机器结果就不同）。
    /// 唯一硬断言：不得返回「既非失败也非空也非有」的第四种形态，且失败必须带阶段名。
    #[test]
    #[ignore = "真实连接 WMI root\\default 枚举还原点（只读），发布前门禁跑"]
    fn live_probe_原生wmi查还原点() {
        match query_restore_points() {
            RpOutcome::Found(ps) => {
                println!("FOUND {} 条；首条原文：{}", ps.len(), ps[0].text);
                assert!(!ps[0].text.is_empty(), "枚举到对象但原文为空，说明 GetObjectText 用错了");
            }
            RpOutcome::Empty => println!("EMPTY：查询成功且确实零条"),
            RpOutcome::Failed { stage, code, message } => {
                println!("FAILED stage={stage} code=0x{:08X} msg={message}", code as u32);
                assert!(!stage.is_empty(), "失败必须带阶段名，否则无法定位是哪一步");
            }
        }
    }
}
