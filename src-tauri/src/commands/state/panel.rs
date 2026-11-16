//! panel 域的命令层共享状态槽（引用方：memory / maintenance / runtimes）。

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::Value;

use crate::commands::memory::ProcInfo;

// ---- memory.rs ----

/// 进程快照分槽（槽键 = `snapshot::domain_key(label, "process")`）。`Vec` 代替 `HashMap` 以支持 const 初始化。
pub(crate) static PROCESS_SNAPSHOTS: Mutex<Vec<(String, HashMap<i64, ProcInfo>)>> =
    Mutex::new(Vec::new());

// ---- maintenance.rs ----

/// 运行锁：Some(taskId) 表示已有任务在跑
pub(crate) static RUNNING: Mutex<Option<String>> = Mutex::new(None);

// ---- runtimes.rs ----

/// 快照（按窗口 label 分槽，对齐 Electron runtimesSnapshots 的 sender.id 分槽）
pub(crate) static RUNTIMES_SNAPSHOTS: Mutex<Option<HashMap<String, Value>>> = Mutex::new(None);
