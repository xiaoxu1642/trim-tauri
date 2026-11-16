//! diagnostics 域的命令层共享状态槽（引用方：overview / realtime / diskbench）。

use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use serde_json::Value;

use crate::commands::realtime::Sampler;

// ---- overview.rs ----

/// metrics 结果缓存与串行锁。锁序：`METRICS_LOCK → METRICS_CACHE → CPU_PREV`（不得反向）。
/// 采集在 `METRICS_LOCK` 内串行，CPU 差分（[`CPU_PREV`]）在同一把锁的作用域内取用
/// —— `METRICS_LOCK → CPU_PREV` 是**允许的嵌套方向**；反向（先差分后采集）不得出现。
pub(crate) static METRICS_CACHE: Mutex<Option<(i64, Value)>> = Mutex::new(None);
pub(crate) static METRICS_LOCK: Mutex<()> = Mutex::new(());
/// CPU 差分用上一拍原始计数（`cpuRaw`）。
/// 对照 main.js 5279-5290：原生引擎无状态，只输出原始 busy/idle 计数，
/// **差分必须由调用方持有**——首拍或计数回绕时 cpu 保持 null（渲染层显示 `--`）。
pub(crate) static CPU_PREV: Mutex<Option<(u64, u64)>> = Mutex::new(None);

// ---- realtime.rs ----

pub(crate) static SAMPLER: Mutex<Option<Sampler>> = Mutex::new(None);
/// 采样器最近一帧（{ t, adapters:[{name,up,down,ifIndex}] }）
pub(crate) static LATEST: Mutex<Option<Value>> = Mutex::new(None);

// ---- diskbench.rs ----

/// 磁盘测速单飞位（v7.2 `R1d-M09`）：原生测速是独占读盘的长任务，并发两场时两份结果
/// 都不可信、进度事件互相插；超时后工作线程又不会中断（本域文件头记录的限制），
/// 所以第二场必须直接拒，不能靠「后跑的覆盖先跑的」。
pub(crate) static DISKBENCH_RUNNING: AtomicBool = AtomicBool::new(false);
/// 残留测试目录的世代号：让「超时后仍在写盘的那一场」与「本场的清理动作」不再共用
/// 一个固定目录名（清理只针对自己那一代，不去动别人正在写的目录）。
pub(crate) static DISKBENCH_GEN: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
