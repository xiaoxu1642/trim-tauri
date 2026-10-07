//! 命令层共享状态集中登记（v3 审查 C-2，2026-10-07）
//!
//! 为什么集中：原先「命令层 file-scope 全局状态」散在 13 个 `commands/*.rs` 里，锁序约定
//! 只存在于各文件注释，审查时无法一处核对；现在**本文件就是命令层全局状态的唯一清单**，
//! 锁序纪律见下。
//!
//! 范围边界（刻意不搬的，别往这里顺手挪）：
//! - `engine/` / `pwsh/` / `security/` 落点的 static：依赖方向规定这些层不得依赖 commands
//!   （check-layering），搬过来会造反向依赖。
//! - 函数体内 `static CACHE`（如 `optimizer/catalog.rs`）：只在函数内可见，没有跨模块锁序问题。
//! - 与所属域访问器/守卫强绑定的（域内登记，仅点名不再搬）：
//!   `cleanup::state` 的 `CLEANUP_SNAPSHOTS` / `TRASH_FAILURES` / `LOCK_WHITELIST`、
//!   `cleanup::rules` 的 `RULES_CACHE` / `WATERMARK_HIGH`、
//!   `uninstall::helpers` 的 `RESIDUE_SNAPSHOTS`（设计注释：与取它的访问器同文件）、
//!   `optimizer::apply` 的 `OPT_RUN_INFLIGHT`、`optimizer::restore_point` 的 `RESTORE_INFLIGHT`
//!   （`pub(super)` 守卫，语义强绑定）。
//!
//! 锁序纪律：除 overview 的 `METRICS_LOCK → METRICS_CACHE` 一对（串行化采集，不得反向）
//! 外，其余条目一律按**叶子锁**使用——持锁期间不取本表其他锁。新增嵌套前先核调用链、
//! 在这里登记一行再写代码。长期方向是迁 `tauri::State` 注入（v3 C-2 备注），届时本文件
//! 即迁移清单。
//!
//! 为什么不用 `pub`：仅命令层（commands 树）消费；放 `pub(crate)` 防外部层误引形成反向依赖。

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Mutex, OnceLock};

use serde_json::Value;

use crate::commands::fileclean::Scope;
use crate::commands::finder::SnapEntry;
use crate::commands::memory::ProcInfo;
use crate::commands::realtime::Sampler;
use crate::commands::updater::{Downloaded, Pending};

// ---- finder.rs ----

/// label -> (规范化小写路径 -> 条目)。Electron 用 Map（插入序 + 按 ts 清理）；
/// 这里用 HashMap，清理时显式按 ts 排序，语义等价且查找 O(1)。
pub(crate) static FINDER_SNAPSHOTS: OnceLock<Mutex<HashMap<String, HashMap<String, SnapEntry>>>> =
    OnceLock::new();

// ---- fileclean.rs ----

/// fileclean:scan 结果快照（`label:type` -> Scope）
pub(crate) static FILECLEAN_SCOPES: Mutex<Option<HashMap<String, Scope>>> = Mutex::new(None);

// ---- elevate.rs ----

/// 审查 2026-09-27 M9：提权请求防重入。此前连点两次会生成两个 nonce 原子覆写同一条
/// 握手记录——第一个监视线程认不出自己的 nonce，20s 超时后误报「未检测到新实例启动」，
/// 且可能弹出两个 UAC。用 AtomicBool 让并发第二个请求直接被拒；释放点覆盖全部退出
/// 路径（runas 失败 / 写状态失败），成功路径不显式复位——握手完成后本进程即将退出，
/// 新实例是全新的内存空间，复位反而可能放行「同进程内第三次点击」与让位流程竞争。
pub(crate) static ELEVATE_INFLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// ---- overview.rs ----

/// metrics 结果缓存与串行锁。锁序：先 `METRICS_LOCK` 后 `METRICS_CACHE`（不得反向）。
pub(crate) static METRICS_CACHE: Mutex<Option<(i64, Value)>> = Mutex::new(None);
pub(crate) static METRICS_LOCK: Mutex<()> = Mutex::new(());
/// CPU 差分用上一拍原始计数（`cpuRaw`）。
/// 对照 main.js 5279-5290：原生引擎无状态，只输出原始 busy/idle 计数，
/// **差分必须由调用方持有**——首拍或计数回绕时 cpu 保持 null（渲染层显示 `--`）。
pub(crate) static CPU_PREV: Mutex<Option<(u64, u64)>> = Mutex::new(None);

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

// ---- memory.rs ----

/// 进程快照分槽（key = 调用窗口 label）。`Vec` 代替 `HashMap` 以支持 const 初始化。
pub(crate) static PROCESS_SNAPSHOTS: Mutex<Vec<(String, HashMap<i64, ProcInfo>)>> =
    Mutex::new(Vec::new());

// ---- netcheck.rs ----

/// netcheck 快照（按窗口 label 分槽）
pub(crate) static NETCHECK_SNAPSHOTS: Mutex<Option<HashMap<String, Value>>> = Mutex::new(None);

// ---- appearance.rs ----

/// 电池供电中（会话级降级判据，不改用户存储的偏好）
pub(crate) static ENV_ON_BATTERY: AtomicBool = AtomicBool::new(false);
/// 系统「透明效果」开关为开（读不到按开处理，不误降级）
pub(crate) static ENV_TRANSPARENCY_ON: AtomicBool = AtomicBool::new(true);
/// 电池降级是否**已由本机制施加**。接电时只还原自己降的那一次，避免覆盖用户切换
pub(crate) static BATTERY_SWAPPED: AtomicBool = AtomicBool::new(false);

// ---- maintenance.rs ----

/// 运行锁：Some(taskId) 表示已有任务在跑
pub(crate) static RUNNING: Mutex<Option<String>> = Mutex::new(None);

// ---- realtime.rs ----

pub(crate) static SAMPLER: Mutex<Option<Sampler>> = Mutex::new(None);
/// 采样器最近一帧（{ t, adapters:[{name,up,down,ifIndex}] }）
pub(crate) static LATEST: Mutex<Option<Value>> = Mutex::new(None);

// ---- misc.rs ----

/// DWM 注入工具检测结论（冷启动 12s 后回填）
pub(crate) static DWM_TOOL_HINT: Mutex<Option<String>> = Mutex::new(None);

// ---- system.rs ----

/// system:disk-type 的查询缓存
pub(crate) static SYSTEM_DISK_CACHE: Mutex<Option<serde_json::Value>> = Mutex::new(None);

// ---- runtimes.rs ----

/// 快照（按窗口 label 分槽，对齐 Electron runtimesSnapshots 的 sender.id 分槽）
pub(crate) static RUNTIMES_SNAPSHOTS: Mutex<Option<HashMap<String, Value>>> = Mutex::new(None);
