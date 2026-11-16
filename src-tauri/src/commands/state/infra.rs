//! infra 域的命令层共享状态槽（引用方：elevate / updater / netcheck / settings / lib.rs，以及引用方不在四域清单的散槽）。

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Mutex, OnceLock};

use serde_json::Value;

use crate::commands::updater::{Downloaded, Pending};

// ---- elevate.rs ----

/// 审查 2026-09-27 M9：提权请求防重入。此前连点两次会生成两个 nonce 原子覆写同一条
/// 握手记录——第一个监视线程认不出自己的 nonce，20s 超时后误报「未检测到新实例启动」，
/// 且可能弹出两个 UAC。用 AtomicBool 让并发第二个请求直接被拒；释放点覆盖全部退出
/// 路径（runas 失败 / 写状态失败），成功路径不显式复位——握手完成后本进程即将退出，
/// 新实例是全新的内存空间，复位反而可能放行「同进程内第三次点击」与让位流程竞争。
pub(crate) static ELEVATE_INFLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 提权重启后、建窗前面消费到的待编辑意图；只在首帧后交给渲染层一次。
pub(crate) struct PendingEditState {
    value: Mutex<Option<Value>>,
}

impl PendingEditState {
    pub(crate) fn new(value: Option<Value>) -> Self {
        Self {
            value: Mutex::new(value),
        }
    }

    pub(crate) fn take(&self) -> Option<Value> {
        self.value.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

// ---- updater.rs ----

pub(crate) static CHECKING: AtomicBool = AtomicBool::new(false);
/// 检查通过、等用户点下载的更新，连它**来自哪条线路**一起锁定（下载前要复验同一线路）
pub(crate) static PENDING: Mutex<Option<Pending>> = Mutex::new(None);
/// 已下载并验签通过、等用户点重启安装的包
pub(crate) static DOWNLOADED: Mutex<Option<Downloaded>> = Mutex::new(None);
/// 正在跑的下载任务句柄（取消走 abort，对齐上游 CancellationToken）。
///
/// **句柄只供 cancel 的 abort 用，「是否在下载」的判据是 [`DOWNLOADING`]**——
/// 技术债 T2 的收尾（2026-10-07）：原先 Option 的有无关兼职「下载中」语义，
/// 而任务闭包结束时置 None 与 spawn 返回后主线程置 Some 之间存在理论乱序（下载
/// 瞬时完成时闭包先跑），死句柄会盖回 Some 让守卫误判「下载中」。现在判据与句柄
/// 分离：标志由 spawn 前 store(true) 铺垫、闭包所有出口 store(false) 收尾，abort
/// 路径由 cancel 自己收尾——三个写点都不依赖句柄的存废，乱序不再影响判定。
pub(crate) static DOWNLOAD_TASK: Mutex<Option<tauri::async_runtime::JoinHandle<()>>> =
    Mutex::new(None);
/// 「下载正在进行」的权威标志（T2 收尾，见 [`DOWNLOAD_TASK`] 注释）。
pub(crate) static DOWNLOADING: AtomicBool = AtomicBool::new(false);
/// 静默检查线程句柄槽（审查 M-05）。用 OnceLock 而非裸 `Mutex`：本槽只在
/// `schedule_silent_check` 里写入，写入前无并发读，且不需要 `const fn` 新值。
pub(crate) static SILENT_CHECK_THREAD: OnceLock<Mutex<Option<std::thread::JoinHandle<()>>>> =
    OnceLock::new();

// ---- netcheck.rs ----

/// netcheck 快照（槽键 = `snapshot::domain_key(label, "netcheck")`）
pub(crate) static NETCHECK_SNAPSHOTS: Mutex<Option<HashMap<String, Value>>> = Mutex::new(None);

// ---- appearance.rs ----

/// 电池供电中（会话级降级判据，不改用户存储的偏好）
pub(crate) static ENV_ON_BATTERY: AtomicBool = AtomicBool::new(false);
/// 系统「透明效果」开关为开（读不到按开处理，不误降级）
pub(crate) static ENV_TRANSPARENCY_ON: AtomicBool = AtomicBool::new(true);
/// 电池降级是否**已由本机制施加**。接电时只还原自己降的那一次，避免覆盖用户切换
pub(crate) static BATTERY_SWAPPED: AtomicBool = AtomicBool::new(false);

// ---- misc.rs ----

/// DWM 注入工具检测结论（冷启动 12s 后回填）
pub(crate) static DWM_TOOL_HINT: Mutex<Option<String>> = Mutex::new(None);

// ---- system.rs ----

/// system:disk-type 的查询缓存
pub(crate) static SYSTEM_DISK_CACHE: Mutex<Option<serde_json::Value>> = Mutex::new(None);

// ---- settings.rs ----

/// CDP 远程调试开关的「当前进程真开着没」（`settings.rs` 的文件级 static）。
///
/// 登记在这里是因为它是**文件级** static（模块作用域可见、可被同模块任何代码取用），
/// 不适用「函数体内 static 才豁免」那条。取用面只有 `settings.rs` 内部（写：启动期
/// 定端口；读：`settings:cdp-get` / `settings:cdp-set` 的回执），不跨模块共享，
/// 因此按**叶子锁**纪律使用（无锁，只有 AtomicBool）。
///
/// 之所以搬进本文件（而不是留在 `settings.rs`）：本文件是命令层全局状态的**唯一清单**，
/// 文件级 static 漏登记 = 这句话失效；端口常量 `CDP_PORT` 仍留在 `settings.rs`
/// （它是常量不是状态），「端口 + 是否生效」两者的取用点都在 `settings.rs`。
pub(crate) static CDP_ACTIVE_NOW: AtomicBool = AtomicBool::new(false);
