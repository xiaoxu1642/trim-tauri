//! file_tools 域的命令层共享状态槽（引用方：finder / fileclean）。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::commands::fileclean::Scope;
use crate::commands::finder::SnapEntry;

// ---- finder.rs ----

/// label -> (规范化小写路径 -> 条目)。Electron 用 Map（插入序 + 按 ts 清理）；
/// 这里用 HashMap，清理时显式按 ts 排序，语义等价且查找 O(1)。
pub(crate) static FINDER_SNAPSHOTS: OnceLock<Mutex<HashMap<String, HashMap<String, SnapEntry>>>> =
    OnceLock::new();

// ---- fileclean.rs ----

/// fileclean:scan 结果快照（槽键 = `snapshot::domain_key(label, 清理类型)`）
pub(crate) static FILECLEAN_SCOPES: Mutex<Option<HashMap<String, Scope>>> = Mutex::new(None);
