// cleanup_scan.rs — 磁盘清理扫描引擎（P0 批次：pathPs 目录型条目 + dism 占位）
// 方案：《磁盘清理扫描 Rust 化方案》v1.1（本地资料区文档，不随仓库分发）
//
// 输入（方案 v1.1 输入通道定案）：
//   argv = ["cleanup", categories_json, configured_paths_json]（均为短参数，JSON 数组/对象）
//   stdin = 规则 JSON 全文（60KB 级，超 CreateProcessW 32767 字符命令行上限，故走 stdin）
// 输出：@@ITEM@@{json} 行协议，与 cleanup-scripts.js SCAN_SCRIPT 逐字段一致（UTF-8）。
// fail-closed：stdin 空/坏 JSON/结构不符 → stderr + exit 2（与 PS SCAN 致命守卫同口径）；
//   pathPs 表达式求值失败 → 跳过该条目（不回落表达式原文，审查 v2.2 D1 纪律）。
//
// 语义对齐基准（本机 PS 走 TrimFastSize.ListDeletable 快路径，Rust 按同口径实现）：
//   - ListDeletable：递归枚举无深度上限、跳 ReparsePoint（文件与目录，均不深入）、
//     IgnoreInaccessible（不可读子目录静默跳过）、目录不计数、独占打开探测（FileShare.None）
//   - Get-PathDeletableStats：三态出口（ok/missing），size/nfiles 只计探测通过的可删文件
//   - RULE_PATH_EVAL_PS：受限求值器逐字符对齐（含 depth 不回退的累计计数语义）
//   - D19 键名缺陷已修（2026-10-01 拍板）：candidatesPs/globCandidatesPs 分支自本日起按
//     库里的真键名生效；修复前读 candidates/globCandidates 恒死。修复前提是库里过宽候选
//     先收敛到叶子 Cache 目录（删除面不得借机扩大），登记处 tools/rule-schema.json crossTrack。
//
// P1/P2 待接入：fileKeys（枚举+pattern+去重+PLANFILE）、regKeys（winreg）、
//               blockedBy（Toolhelp32 进程枚举）、detect 的 reg 型检测。

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

// ==================== 输出汇聚：数据返回式入口（Tauri 进程内直调） ====================
// CLI 形态沿用「写 stdout/stderr + 进程退出」；Tauri 侧需要「一次调用拿回数据」的入口：
// 进程内直调既不能写 stdout（会进应用控制台），更不能 exit（`fatal` 会带走整个应用进程）。
//
// 手法（对既有 CLI 行为零影响）：
//   · out_line / err_line 在捕获模式下写内存，否则照旧写真实标准流；
//   · fatal 在捕获模式下改为 panic（载荷 FatalMarker），由 `capture` 的 catch_unwind
//     收成 exit code 2 + stderr 行；CLI 路径不进入捕获模式，仍是 flush→stderr→exit(2)；
//     N1a-M05：载荷**不是** FatalMarker 的 panic（引擎自己的越界/unwrap）另给一档退出码
//     `EXIT_ENGINE_PANIC=3`，并由 hook 把详情落进 CAP.err —— 旧写法把它也折成 2，
//     于是「引擎 bug」与「用户规则库不合法」在回执上长成一张脸；
//   · 输出字节与 fatal 的退出码因此**逐字不变**（stdout 全部先于 stderr，与原 fatal 的
//     flush 顺序一致）；唯一新增的分档是「引擎 panic」的 `EXIT_ENGINE_PANIC`（N1a-M05）。
//
// ⚠️ 本文件另有并行任务在改（Sink 化）：本块**只新增**，不改既有函数签名与内部语义。

struct Cap {
    out: String,
    err: String,
    active: bool,
    /// P2-④：逐行回调在场时为 true —— 此时**不再**往 `out` 里追加。
    ///
    /// 为什么可以丢：`out_line` 每行都已经同步交给调用方的 `on_line` 回调（生产路径 =
    /// `run_json(…, Some(hook))`，`scan_execute.rs` 逐行 `ingest_and_emit` 进结果槽），
    /// `out` 那份整程全量副本没有任何消费方 —— 调用点是 `let (code, _stdout, stderr)`，
    /// 全扫程驻留后被丢弃（按行协议每行约百字节量级线性放大，十万行级就是十 MB 量级、
    /// 百万行级到百 MB 量级）。无回调的 CLI 形态（`run` / `run_checklocked` /
    /// `checklocked_json`，以及 `tests/cleanup_scan_rule_diff.rs` 的对拍）必须照旧全量
    /// 攒进 `out` 并 `write_back` ⇒ 由这个开关区分，**逐字节行为不变**。
    discard_out: bool,
    /// N1a-M05：捕获期间 panic hook 是否已经落过「引擎 panic」行。
    /// `capture` 的 `Err` 分支据此决定要不要补一行兜底 —— 绝不许交出
    /// 「退出码非 0 + 空 stderr」那种什么都没说出口的回执。
    panic_traced: bool,
}

thread_local! {
    static CAP: std::cell::RefCell<Cap> = std::cell::RefCell::new(Cap {
        out: String::new(),
        err: String::new(),
        active: false,
        discard_out: false,
        panic_traced: false,
    });
    /// 逐行回调（数据返回式入口的可选参数；捕获模式下 out_line 顺带回调此行）
    static HOOK: std::cell::RefCell<Option<Box<dyn FnMut(&str)>>> = std::cell::RefCell::new(None);
}

/// 捕获串行锁：panic hook 是进程级的，同时只允许一次捕获
static CAP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// fatal 的 panic 载荷标记（只有它允许被静默吞掉，其余 panic 必须留痕）
struct FatalMarker;
/// 回执退出码：规则库/输入致命错（`fatal` 已落「致命: …」行）
const EXIT_FATAL: i32 = 2;
/// 回执退出码：引擎内部 panic（N1a-M05）。
/// 为什么必须与 `EXIT_FATAL` 分开：宿主唯一的判据是 `code != 0` + stderr 文本，
/// 同一个 2 让「扫描器 own 的 bug」与「用户规则库不合法」在回执层长成一张脸，
/// 而前者是要报障修引擎的、后者是要改规则的。
const EXIT_ENGINE_PANIC: i32 = 3;
static HOOK_ONCE: std::sync::Once = std::sync::Once::new();

/// 装一次转发 hook：FatalMarker 静默（fatal 自己落过行），其它 panic **既交回原 hook
/// 打印、又落进 CAP.err**（不吞真 bug，也不让真 bug 在捕获模式下变成无声回执）。
fn ensure_panic_hook() {
    HOOK_ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let is_fatal = info.payload().downcast_ref::<FatalMarker>().is_some();
            if !is_fatal {
                // N1a-M05：捕获模式下真 panic 只写进程真实 stderr 等于没写 ——
                // 本文件 err_line 的注释就写明「GUI 子系统进程没有控制台，那几个字直接蒸发」。
                // 这里**不能**用 `capturing()`：它走 `borrow()`，而 hook 恰恰可能在 CAP
                // 已被借用的时刻触发，二次 panic 落在 panic hook 里 = 直接 abort。
                record_panic_trace(info);
                prev(info);
            }
        }));
    });
}

/// 把 panic 详情写成一行留痕。刻意不走 `err_line`：hook 可能在 CAP 已被借用的
/// 时刻触发（例如 out_line 里炸），`borrow_mut` 会二次 panic 把现场彻底搞丢。
fn record_panic_trace(info: &std::panic::PanicHookInfo) {
    // `PanicHookInfo::message()` 至今仍是 unstable；稳定面只有 payload 家族。
    // `payload_as_str()` 覆盖 `panic!("...")` 与 `panic_any(&str)` 两种字符串载荷，
    // 其余载荷（自定义结构体）退化成占位文案 —— 留痕的价值在「有这一行」，不在载荷类型。
    let msg = info
        .payload_as_str()
        .map(str::to_string)
        .unwrap_or_else(|| "(panic 载荷不是字符串)".to_string());
    let loc = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "位置未知".to_string());
    let line = format!("[cleanup-scan] 引擎 panic（非规则库致命错）: {msg} @ {loc}");
    let _ = CAP.try_with(|c| {
        let mut cap = match c.try_borrow_mut() {
            Ok(g) => g,
            Err(_) => return,
        };
        // 非捕获态（CLI 之外的线程、或本线程没在跑扫描）不写内存，交给 prev 打真 stderr
        if !cap.active {
            return;
        }
        if !cap.panic_traced {
            // 行边界可信（N1a-L05 同一判据）：panic 消息本体可能带换行
            cap.err.push_str(&crate::util::diag_text(&line));
            cap.err.push('\n');
            cap.panic_traced = true;
        }
    });
}

fn capturing() -> bool {
    CAP.with(|c| c.borrow().active)
}

/// 输出一行到 stdout（捕获模式下进内存；两种情况都触发逐行回调）
///
/// ⚠️ **捕获模式 + 有逐行回调时 `cap.out` 是空的**（P2-④，见 [`Cap::discard_out`]）：
/// 那一行的去处只有回调一个，整程再攒一份全量副本从头到尾没人读。
/// 任何将来想消费 `run_json` 返回值里 stdout 的调用点，都必须先改掉这个开关 ——
/// 现在这么做会在生产环境（带回调）静默拿到空串。
fn out_line(line: &str) {
    CAP.with(|c| {
        let mut cap = c.borrow_mut();
        if cap.active {
            if !cap.discard_out {
                cap.out.push_str(line);
                cap.out.push('\n');
            }
        } else {
            println!("{}", line);
        }
    });
    let mut hook = HOOK.with(|h| h.borrow_mut().take());
    if let Some(f) = hook.as_mut() {
        f(line);
    }
    if hook.is_some() {
        HOOK.with(|h| *h.borrow_mut() = hook);
    }
}

/// 输出一行到 stderr（捕获模式下进内存）
///
/// **所有**面向人的诊断都必须走这里，不能用 `eprintln!`：
/// Tauri 侧调的是 `run_json`（捕获模式），`eprintln!` 写的是进程真实 stderr，
/// 而 GUI 子系统进程没有控制台，那几个字直接蒸发 —— 引擎「已按规则降级并留痕」
/// 的承诺就落空了。2026-10-04 磁盘清理审计 §3.2 把散落的 4 处 `eprintln!` 全部收编。
fn err_line(line: &str) {
    // N1a-L05：入站先压成单行（判据见 `util::diag_text`）。为什么包在出口而不是逐个
    // 调用点：诊断有 20+ 处拼接点，逐点包装挡不住「下一处新调用点忘了包」，而这里的
    // 语义本就是「一行 stderr」。留痕被路径/规则原文里的换行拆成两行，等于凭空多出
    // 一条不存在的诊断，人工对账与按行数判定的机检都会被带偏。
    // 干净文本走借用，不额外分配（read_dir 失败留痕可以一次上千条）。
    let owned;
    let line = if line.chars().any(|c| (c as u32) < 0x20) {
        owned = crate::util::diag_text(line);
        owned.as_str()
    } else {
        line
    };
    CAP.with(|c| {
        let mut cap = c.borrow_mut();
        if cap.active {
            cap.err.push_str(line);
            cap.err.push('\n');
        } else {
            eprintln!("{}", line);
        }
    });
}

/// 在捕获模式下执行 body → (exit_code, stdout, stderr)
///
/// ⚠️ `hook` 为 `Some` 时返回的 stdout 是**空串**（行只经回调交付，见
/// [`Cap::discard_out`]）；`hook` 为 `None`（CLI 与对拍入口）时 stdout 照旧全量。
fn capture(
    hook: Option<Box<dyn FnMut(&str)>>,
    body: impl FnMut() -> i32,
) -> (i32, String, String) {
    let _serial = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    ensure_panic_hook();
    let discard_out = hook.is_some();
    CAP.with(|c| {
        let mut cap = c.borrow_mut();
        cap.active = true;
        // P2-④ 的开关落位：带逐行回调 ⇒ 这一程不再往 `out` 里攒全量副本（见 [`Cap::discard_out`]）。
        // 这里写成 `false` 会让 `discard_out` 变成未用变量、并让
        // `捕获带回调时不攒stdout副本而无回调逐字节照旧` 判红（2026-10-14 实测过一次）。
        cap.discard_out = discard_out;
        // N1a-M05：每程复位，否则上一程的 hook 留痕会让本程跳过兜底行
        cap.panic_traced = false;
    });
    HOOK.with(|h| *h.borrow_mut() = hook);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    HOOK.with(|h| h.borrow_mut().take());
    // N1a-M05：只有 FatalMarker 才是「规则库/输入致命错」（fatal 已在 err_line 里落过
    // 「致命: …」行，回执 2 照旧）。其余 panic 是引擎自己的 bug，旧写法一律折成
    // `(2, "", "")`：hook 的字进了进程真实 stderr，GUI 子系统没有控制台 ⇒ 宿主只看到
    // 「原生扫描失败: 退出码 2」。这里改成 ① 分档退出码 ② 保证留痕非空。
    let engine_panic = matches!(&res, Err(e) if e.downcast_ref::<FatalMarker>().is_none());
    let code = match res {
        Ok(c) => c,
        Err(_) if engine_panic => EXIT_ENGINE_PANIC,
        Err(_) => EXIT_FATAL,
    };
    let (out, err) = CAP.with(|c| {
        let mut cap = c.borrow_mut();
        // 兜底：真 panic 但 hook 一行都没落下来（hook 被别的库抢占、或触发时 CAP 正被借用）
        // ⇒ 至少留一行，绝不交出「非 0 + 空 stderr」。
        if engine_panic && !cap.panic_traced && cap.err.is_empty() {
            cap.err
                .push_str("[cleanup-scan] 引擎 panic（非规则库致命错）: 未取到 panic 详情\n");
        }
        cap.active = false;
        // 复位：CAP 是 thread_local，下一次不带回调的捕获必须照旧全量攒 stdout
        cap.discard_out = false;
        (std::mem::take(&mut cap.out), std::mem::take(&mut cap.err))
    });
    (code, out, err)
}

/// 把捕获内容原样回写标准流（CLI 用；stdout 全量在前，与 fatal 的 flush 顺序一致）
fn write_back(out: &str, err: &str) {
    if !out.is_empty() {
        print!("{}", out);
    }
    let _ = std::io::stdout().flush();
    if !err.is_empty() {
        eprint!("{}", err);
    }
}

// ==================== Windows FFI：只读注册表 + 进程枚举（P1/P2 批次） ====================
// 零依赖原则延续 P0：手写 FFI 对齐项目现状（main.rs 回收站/is_reparse 同风格），
// 不引入 winreg/windows-sys crate（方案评审定案）。注册表仅 KEY_READ 只读访问。

#[cfg(windows)]
mod ffi {
    use std::collections::HashSet;
    // FFI 声明与结构体已集中到 `crate::util::ffi`（v3 C-3）；本模块只留 HKEY 常量与助手。
    use crate::util::ffi::{
        CloseHandle, CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        RegCloseKey, RegOpenKeyExW, RegQueryInfoKeyW,
    };
    use crate::util::to_wide;

    pub const HKEY_CLASSES_ROOT: isize = -2147483648; // 0x80000000
    pub const HKEY_CURRENT_USER: isize = -2147483647; // 0x80000001
    pub const HKEY_LOCAL_MACHINE: isize = -2147483646; // 0x80000002
    pub const HKEY_USERS: isize = -2147483645; // 0x80000003
    pub const HKEY_CURRENT_CONFIG: isize = -2147483643; // 0x80000005

    const KEY_READ: u32 = 0x0002_0019;
    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;

    /// Convert-RegPath 的 hive 映射（首个 '\' 前为缩写，大小写不敏感）
    fn map_hive(reg_path: &str) -> Option<(isize, &str)> {
        let idx = reg_path.find('\\')?;
        let hive = reg_path[..idx].to_ascii_uppercase();
        let rest = &reg_path[idx + 1..];
        let root = match hive.as_str() {
            "HKCU" => HKEY_CURRENT_USER,
            "HKLM" => HKEY_LOCAL_MACHINE,
            "HKCR" => HKEY_CLASSES_ROOT,
            "HKU" => HKEY_USERS,
            "HKCC" => HKEY_CURRENT_CONFIG,
            _ => return None,
        };
        Some((root, rest))
    }

    fn open_key(root: isize, subkey: &str) -> Option<isize> {
        let wide = to_wide(subkey);
        let mut hk: isize = 0;
        let rc = unsafe { RegOpenKeyExW(root, wide.as_ptr(), 0, KEY_READ, &mut hk) };
        if rc == 0 {
            Some(hk)
        } else {
            None
        }
    }

    /// Test-RegPathExists 口径：hive 映射失败或打开失败均视为不存在
    pub fn reg_key_exists(reg_path: &str) -> bool {
        let Some((root, subkey)) = map_hive(reg_path) else {
            return false;
        };
        let Some(hk) = open_key(root, subkey) else {
            return false;
        };
        unsafe {
            RegCloseKey(hk);
        }
        true
    }

    /// Measure-RegRule 的键规模：返回 (values 数, 子键数)（对齐 GetValueNames/Get-ChildItem 计数）
    pub fn reg_key_counts(reg_path: &str) -> Option<(u32, u32)> {
        let Some((root, subkey)) = map_hive(reg_path) else {
            return None;
        };
        let hk = open_key(root, subkey)?;
        let (mut subkeys, mut values) = (0u32, 0u32);
        let rc = unsafe {
            RegQueryInfoKeyW(
                hk,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut subkeys,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut values,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        unsafe {
            RegCloseKey(hk);
        }
        if rc == 0 {
            Some((values, subkeys))
        } else {
            None
        }
    }

    /// Get-Process 进程名集合等价物：Toolhelp 快照枚举 exe 名去 .exe 后缀（小写存，忽略大小写查）
    pub fn process_names() -> HashSet<String> {
        let mut out = HashSet::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap != -1 {
                let mut pe: PROCESSENTRY32W = std::mem::zeroed();
                pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32FirstW(snap, &mut pe) != 0 {
                    loop {
                        let len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe.szExeFile.len());
                        let exe = String::from_utf16_lossy(&pe.szExeFile[..len]).to_lowercase();
                        let name = exe.strip_suffix(".exe").unwrap_or(&exe).to_string();
                        if !name.is_empty() {
                            out.insert(name);
                        }
                        if Process32NextW(snap, &mut pe) == 0 {
                            break;
                        }
                    }
                }
                CloseHandle(snap);
            }
        }
        out
    }
}

#[cfg(not(windows))]
mod ffi {
    use std::collections::HashSet;
    pub fn reg_key_exists(_reg_path: &str) -> bool {
        false
    }
    pub fn reg_key_counts(_reg_path: &str) -> Option<(u32, u32)> {
        None
    }
    pub fn process_names() -> HashSet<String> {
        HashSet::new()
    }
}

// ==================== 最小 JSON 解析器 ====================
// 规则 JSON 是主进程 JSON.stringify 的机器产物（合法、无注释、数字不越界），
// P0 手写解析避免为此引入 serde 依赖（native-scanner 现仅 blake3/rayon；
// miniz_oxide 原为文档相似检测的 zip 解压依赖，该检测已于 2026-09-28 移除）。

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        if let Json::Obj(m) = self {
            m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        } else {
            None
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Json::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_arr(&self) -> Option<&Vec<Json>> {
        if let Json::Arr(a) = self {
            Some(a)
        } else {
            None
        }
    }
    /// PS 语义 @($x).Count 的近似：数组取长度，单个非空对象/值视为 1，null/缺失视为 0
    fn ps_count(&self) -> usize {
        match self {
            Json::Arr(a) => a.len(),
            Json::Null => 0,
            _ => 1,
        }
    }
}

struct Jp {
    s: Vec<char>,
    i: usize,
}

impl Jp {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], ' ' | '\t' | '\r' | '\n') {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        if self.i >= self.s.len() {
            return Err("JSON 意外结束".into());
        }
        match self.s[self.i] {
            '{' => self.object(),
            '[' => self.array(),
            '"' => Ok(Json::Str(self.string()?)),
            't' => self.lit("true", Json::Bool(true)),
            'f' => self.lit("false", Json::Bool(false)),
            'n' => self.lit("null", Json::Null),
            _ => self.number(),
        }
    }
    fn lit(&mut self, w: &str, v: Json) -> Result<Json, String> {
        for (k, c) in w.chars().enumerate() {
            if self.s.get(self.i + k) != Some(&c) {
                return Err(format!("字面量 {} 非法", w));
            }
        }
        self.i += w.chars().count();
        Ok(v)
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // 跳过开引号
        let mut out = String::new();
        loop {
            if self.i >= self.s.len() {
                return Err("字符串未闭合".into());
            }
            let c = self.s[self.i];
            self.i += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    if self.i >= self.s.len() {
                        return Err("转义未闭合".into());
                    }
                    let e = self.s[self.i];
                    self.i += 1;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000C}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let hi = self.hex4()?;
                            // 代理对：JSON.stringify 对增补平面字符输出 \uD8xx\uDCxx 成对转义
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.i + 1 < self.s.len()
                                    && self.s[self.i] == '\\'
                                    && self.s[self.i + 1] == 'u'
                                {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if (0xDC00..0xE000).contains(&lo) {
                                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                    } else {
                                        return Err("低代理区码点非法".into());
                                    }
                                } else {
                                    return Err("高代理后缺低代理".into());
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err("孤立低代理".into());
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err(format!("非法转义 \\{}", e)),
                    }
                }
                c => out.push(c),
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.s.len() {
            return Err("\\u 编码不完整".into());
        }
        let mut v = 0u32;
        for k in 0..4 {
            let d = self.s[self.i + k].to_digit(16).ok_or("\\u 编码非法")?;
            v = v * 16 + d;
        }
        self.i += 4;
        Ok(v)
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.s[self.i] == '-' {
            self.i += 1;
        }
        while self.i < self.s.len()
            && (self.s[self.i].is_ascii_digit()
                || matches!(self.s[self.i], '.' | 'e' | 'E' | '+' | '-'))
        {
            self.i += 1;
        }
        let txt: String = self.s[start..self.i].iter().collect();
        txt.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("数字非法: {}", txt))
    }
    fn array(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.i < self.s.len() && self.s[self.i] == ']' {
            self.i += 1;
            return Ok(Json::Arr(out));
        }
        loop {
            out.push(self.value()?);
            self.ws();
            if self.i >= self.s.len() {
                return Err("数组未闭合".into());
            }
            match self.s[self.i] {
                ',' => self.i += 1,
                ']' => {
                    self.i += 1;
                    return Ok(Json::Arr(out));
                }
                _ => return Err("数组分隔符非法".into()),
            }
        }
    }
    fn object(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut out: Vec<(String, Json)> = Vec::new();
        self.ws();
        if self.i < self.s.len() && self.s[self.i] == '}' {
            self.i += 1;
            return Ok(Json::Obj(out));
        }
        loop {
            self.ws();
            if self.i >= self.s.len() || self.s[self.i] != '"' {
                return Err("对象键必须为字符串".into());
            }
            let k = self.string()?;
            self.ws();
            if self.i >= self.s.len() || self.s[self.i] != ':' {
                return Err("对象缺冒号".into());
            }
            self.i += 1;
            let v = self.value()?;
            out.push((k, v));
            self.ws();
            if self.i >= self.s.len() {
                return Err("对象未闭合".into());
            }
            match self.s[self.i] {
                ',' => self.i += 1,
                '}' => {
                    self.i += 1;
                    return Ok(Json::Obj(out));
                }
                _ => return Err("对象分隔符非法".into()),
            }
        }
    }
}

pub fn parse_json(text: &str) -> Result<Json, String> {
    let mut p = Jp { s: text.chars().collect(), i: 0 };
    let v = p.value()?;
    p.ws();
    if p.i != p.s.len() {
        return Err("JSON 结尾有多余内容".into());
    }
    Ok(v)
}

// ==================== 受限路径表达式求值器（对齐 RULE_PATH_EVAL_PS） ====================
// 语法：表达式 := '(' 表达式 ')' | 项 ('+' 项)*；项 := '$env:' 标识符 | 单引号字面量（'' 转义撇号）
// 语义细节：未定义 $env:X 取空串（合法态，不算失败）；求值后必须消费全部输入；
//   depth 每次进入 Prim 累加且【不回退】（PS 原实现如此——超长拼接会在第 33 个项处 fail-closed）。

const RULE_PATH_MAX_DEPTH: u32 = 32;

struct EvSt {
    s: Vec<char>,
    i: usize,
    ok: bool,
    val: String,
    depth: u32,
}

fn ev_ws(st: &mut EvSt) {
    while st.i < st.s.len() && (st.s[st.i] == ' ' || st.s[st.i] == '\t') {
        st.i += 1;
    }
}

fn ev_prim(st: &mut EvSt) {
    st.depth += 1;
    if st.depth > RULE_PATH_MAX_DEPTH {
        st.ok = false;
        return;
    }
    ev_ws(st);
    if st.i >= st.s.len() {
        st.ok = false;
        return;
    }
    let c = st.s[st.i];
    if c == '(' {
        st.i += 1;
        ev_concat(st);
        if !st.ok {
            return;
        }
        ev_ws(st);
        if st.i >= st.s.len() || st.s[st.i] != ')' {
            st.ok = false;
            return;
        }
        st.i += 1;
        return;
    }
    if c == '\'' {
        st.i += 1;
        let mut sb = String::new();
        loop {
            if st.i >= st.s.len() {
                st.ok = false;
                return;
            }
            let ch = st.s[st.i];
            if ch == '\'' {
                if st.i + 1 < st.s.len() && st.s[st.i + 1] == '\'' {
                    sb.push('\'');
                    st.i += 2;
                    continue;
                }
                st.i += 1;
                break;
            }
            sb.push(ch);
            st.i += 1;
        }
        st.val = sb;
        return;
    }
    if c == '$' {
        // PS StartsWith('$env:') 为大小写敏感，$ENV: 前缀必须拒绝——逐字符对齐
        if st.s.len() - st.i < 5 {
            st.ok = false;
            return;
        }
        let head: String = st.s[st.i..st.i + 5].iter().collect();
        if head != "$env:" {
            st.ok = false;
            return;
        }
        st.i += 5;
        let start = st.i;
        while st.i < st.s.len() && (st.s[st.i].is_ascii_alphanumeric() || st.s[st.i] == '_') {
            st.i += 1;
        }
        if st.i == start {
            st.ok = false;
            return;
        }
        let name: String = st.s[start..st.i].iter().collect();
        // Windows env 查找大小写不敏感（std 走 GetEnvironmentVariableW，与 PS 同源）；
        // 未定义取空串（与 PowerShell 原生一致）
        let v = std::env::var_os(&name)
            .map(|v| v.to_string_lossy().to_string())
            .unwrap_or_default();
        st.val = v;
        return;
    }
    st.ok = false;
}

fn ev_concat(st: &mut EvSt) {
    ev_prim(st);
    if !st.ok {
        return;
    }
    let mut acc = st.val.clone();
    loop {
        let mut j = st.i;
        while j < st.s.len() && (st.s[j] == ' ' || st.s[j] == '\t') {
            j += 1;
        }
        if j < st.s.len() && st.s[j] == '+' {
            st.i = j + 1;
            ev_prim(st);
            if !st.ok {
                return;
            }
            acc.push_str(&st.val);
        } else {
            break;
        }
    }
    st.val = acc;
}

/// 求值成功返回路径（可能为空串），失败返回 None（调用方 fail-closed 跳过）
pub fn resolve_rule_path(expr: &str) -> Option<String> {
    if expr.is_empty() {
        return None;
    }
    let mut st = EvSt { s: expr.chars().collect(), i: 0, ok: true, val: String::new(), depth: 0 };
    ev_concat(&mut st);
    if !st.ok {
        return None;
    }
    let mut k = st.i;
    while k < st.s.len() && (st.s[k] == ' ' || st.s[k] == '\t') {
        k += 1;
    }
    if k != st.s.len() {
        return None;
    }
    Some(st.val)
}

// ==================== %ENV% 展开（对齐 Expand-EnvPath） ====================

/// 盘符相对路径判定（2026-10-04 审计 §4.10）：以**单个** `\` 或 `/` 开头、且不是
/// UNC / verbatim 设备前缀（`\\` 开头）的形态。
///
/// 为什么需要单一判据：Windows 把 `\Foo` 按「当前盘的根」解析（PS Get-ChildItem
/// 同语义），而 Rust `Path::is_absolute` 对它判 false（无 prefix）⇒ 保护侧
/// `protect::resolve_path` 会拼 `current_dir()`——同一字符串，扫描/执行侧枚举的是
/// 当前盘根下的 `\Foo`，保护侧比较的却是 `CWD\Foo`。落到删除链上就是「保护闸门
/// 比对的路径 ≠ 实际删除的路径」。这种形态只可能来自未定义环境变量的拼接
/// （`$env:UNDEF + '\Foo'`）——「当前盘」是进程 CWD 的偶然属性，不是规则作者的
/// 决定。扫描/执行两侧统一用本判据拒绝展开并留痕；**注册表路径不适用**（前导
/// `\` 在注册表面是 hive 相对形态，两码事）。
pub fn is_drive_relative(p: &str) -> bool {
    let b = p.as_bytes();
    if b.is_empty() || (b[0] != b'\\' && b[0] != b'/') {
        return false;
    }
    // `\\` 开头是 UNC / verbatim 前缀（`\\?\`、`\\.\`），不属于盘符相对
    !(b.len() >= 2 && (b[1] == b'\\' || b[1] == b'/'))
}

// %NAME% → 环境变量值；未定义或定义为空串时保持原文（便于在路径列直接看出配置问题）。
// 本函数是全仓唯一的 %VAR% 展开实现（P0 统一，规则库最终优化方案 2026-09-27）：
// src-tauri 执行侧的展开必须委托到这里，禁止再写第二份白名单展开器。
pub fn expand_env_path(p: &str) -> String {
    let ch: Vec<char> = p.chars().collect();
    let mut out = String::with_capacity(p.len());
    let mut i = 0usize;
    while i < ch.len() {
        if ch[i] == '%' {
            if let Some(j) = (i + 1..ch.len()).find(|&k| ch[k] == '%') {
                if j > i + 1 {
                    let name: String = ch[i + 1..j].iter().collect();
                    if let Some(v) = std::env::var_os(&name) {
                        if !v.is_empty() {
                            out.push_str(&v.to_string_lossy());
                            i = j + 1;
                            continue;
                        }
                    }
                }
            }
        }
        out.push(ch[i]);
        i += 1;
    }
    out
}

/// 检测展开后残留的 %TOKEN%（fail-closed 判据，P0 规则库最终优化方案 2026-09-27）。
///
/// `expand_env_path` 对未定义/空值变量保持原文，所以「展开成功」不能默认成立——
/// 扫描/执行两侧拿到展开结果后必须显式调用本函数：有残留即视为路径无效，
/// 扫描侧跳过（不进可清理结果），执行侧必须上报跳过/失败原因，禁止伪装成「成功 0 删」。
pub fn first_unexpanded_token(s: &str) -> Option<String> {
    let ch: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    while i < ch.len() {
        if ch[i] == '%' {
            if let Some(j) = (i + 1..ch.len()).find(|&k| ch[k] == '%') {
                if j > i + 1 {
                    return Some(ch[i + 1..j].iter().collect());
                }
            }
        }
        i += 1;
    }
    None
}

/// 未解析 %TOKEN% 的**统一留痕出口**（2026-10-04 审计 §4.8）。
///
/// `first_unexpanded_token` 此前只在 fileKeys 主路径被调用，其余 5 个路径字段
/// （detect[].path / fileKeys 版 detect 回退 / regKeys（detect 回退与 measure）、
/// excludePaths/excludeKeys、pathPs 的 configured 覆盖值）拿到未解析展开结果后
/// 静默按原文处理——方向安全（少报/不删），但违反「未解析 token 必须被
/// REPORTED」：用户看到的「配置了却永远 0 命中」没有任何对账依据。
///
/// **只留痕，不改判定**：各字段的既有 fail-closed 语义（跳过 / 按原文判不存在 /
/// 排除永不命中）原样保留，本函数只让「为什么 0 命中」可见。
fn report_unexpanded_token(field: &str, rule_id: &str, expanded: &str) {
    if let Some(tok) = first_unexpanded_token(expanded) {
        err_line(&format!(
            "[cleanup-scan] 规则 {rule_id} {field} 路径变量 %{tok}% 未解析，该字段按展开后原文处理（大概率永远不命中）"
        ));
    }
}

// ==================== 文件系统基础判定 ====================

/// Test-Path -LiteralPath（文件或目录均算存在；空串 false）
fn path_exists(p: &str) -> bool {
    if p.is_empty() {
        return false;
    }
    fs::metadata(p).is_ok()
}

/// Test-Path -PathType Container
fn is_container(p: &str) -> bool {
    if p.is_empty() {
        return false;
    }
    fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

/// 独占打开探测（对齐 .NET FileStream(Open, Read, None) / TrimFastSize.Deletable）：
/// 任一进程以不接受共享读的方式持有句柄 → 打开失败 → 不可删（保守口径）
fn file_deletable(p: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        match fs::OpenOptions::new().read(true).share_mode(0).open(p) {
            Ok(f) => f.metadata().is_ok(), // PS 侧打开后还读一次 Length，失败同判不可删
            Err(_) => false,
        }
    }
    #[cfg(not(windows))]
    {
        fs::File::open(p).is_ok()
    }
}

/// 扫描侧的可删资格（R10，2026-10-15）= 独占探测（`file_deletable`）+ **执行侧同一份
/// 保护清单**（`crate::scan::is_protected_path`，判据只此一份、六个枚举出口全走它，
/// §5.16/N6）。此前扫描侧零过滤：`System32\config\systemprofile\**` 这类目标
/// 「规则命中、执行侧恒拒、体积照报」。保护清单与执行侧同源注入（主进程
/// `protect::protected_roots_json()` → argv → `scan.rs` 的 `from_protect_json`，
/// 回收站链已在用同一份）；未注入时走 `default_from_env` 保守根集（CLI 手测兜底），
/// **不是「不过滤」**。
fn scan_deletable(p: &Path, protect: Option<&str>) -> bool {
    if crate::scan::is_protected_path(&p.to_string_lossy(), protect) {
        return false;
    }
    file_deletable(p)
}

/// FileInfo.Length 语义：存在且为文件返回长度（元数据读失败按不存在）
fn try_file_length(p: &Path) -> Option<u64> {
    match fs::metadata(p) {
        Ok(m) if m.is_file() => Some(m.len()),
        _ => None,
    }
}

/// 文件名通配（对齐 .NET FileSystemName.MatchesSimpleExpression ignoreCase=true）：
/// '*' 任意串（含空）、'?' 恰一字符；仅 P1 fileKeys 的 pattern 会用到非 '*' 模式。
/// P0-A2（2026-10-16）起提 pub：执行侧 `engine/native/cleanup.rs` 的 `glob_match`
/// 改为薄包装委托本函数——匹配器归一后这是全仓唯一实现（两侧曾各写一份且语义
/// 分叉：执行侧大小写敏感、只认第一个 `*`，见交接 §2.4）。
pub fn wildcard_match(name: &str, pattern: &str) -> bool {
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let (mut i, mut j) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while i < n.len() {
        if j < p.len() && (p[j] == '?' || p[j] == n[i]) {
            i += 1;
            j += 1;
        } else if j < p.len() && p[j] == '*' {
            star = j;
            mark = i;
            j += 1;
        } else if star != usize::MAX {
            j = star + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while j < p.len() && p[j] == '*' {
        j += 1;
    }
    j == p.len()
}

// ==================== ListDeletable 口径枚举（对齐 TrimFastSize.cs） ====================

pub struct DeletableResult {
    /// 可删文件清单（探测通过）。仅 `collect_files=true` 时填充。
    /// 第三位 = Kudu S2 的出生时间（UNIX 纳秒，0 = 读不到 = 无身份证基线）。
    /// 为什么把 birthtime 塞进同一个元组而不是让调用方再读一次 metadata：身份证基线的
    /// size 与出生时间必须来自**同一次读取**，否则两次读之间被改写的文件会拿到
    /// 「新 size + 旧出生」的混配，执行侧比对必然失配。
    pub files: Vec<(String, u64, u64)>, // 路径 / 字节 / birthtimeNs
    pub total: u64,                // 枚举到的全部文件数（被占用数 = total - deletable_count）
    /// 可删文件的**个数**与**字节和**，两种模式下都填。
    ///
    /// 为什么要有这两个字段（2026-10-04 磁盘清理审计 §3.3）：统计口径只需要计数与
    /// 求和，而 `files` 是「每文件一个堆String + 一次独占打开」。`%TEMP%` 里几十万
    /// 文件意味着几十万条常驻字符串，而 `get_path_deletable_stats` 算完就把它们
    /// 全丢掉。改成折叠累加后，统计路径**不再持有每文件的路径**。
    pub deletable_count: u64,
    pub deletable_bytes: u64,
    /// 因`FILE_ATTRIBUTE_REPARSE_POINT` 跳过的目录数（R1-2 留痕）。
    ///
    /// 为什么必须有：`Win11` 上 `C:\Users\<u>\AppData\Roaming\Application Data` 就是
    /// junction（指向 `..\Local\Application Data`）。跳过它是对的（深入会重复计数、
    /// 极端情况成环），但**静默跳过等于把「没扫」伪装成「没有」**—— 用户看到清理
    /// 候选偏少却不知道少在哪。这个计数是那句话。
    ///
    /// ⚠️ **只留痕、不参与任何判定**：`total` / `files` / 被占用数一律不看它。
    pub skipped_reparse: u64,
    /// 因权限/IO 失败读不到的目录数（A1-M02，v7.2 C06）。
    /// 与 `skipped_reparse` 并列呈现：候选比 Explorer 少时，除了 junction，
    /// 「有目录读不到」也必须有解释出口。
    pub unreadable_dirs: u64,
    /// 清单到达 `cap` 后仍有可删文件未收进 `files`。
    /// size / deletable_count 不受影响（仍按全量累加），只有**清单**被截断——
    /// 与 FkResult.truncated 同语义，外发字段名统一走 `filesTruncated`。
    pub files_truncated: bool,
}

/// 单遍递归枚举 + 探测。口径：跳 ReparsePoint（不深入）、目录不计数、
/// IgnoreInaccessible（不可读子目录静默跳过）。
/// 审查 L-9（2026-10-03）：原先「无深度上限」（对齐 PS `Get-ChildItem -Recurse`
/// 的无界递归）收窄为 `scan::MAX_WALK_DEPTH`——超限子目录整棵跳过并 stderr 留痕。
/// 清理候选宁可少报（fail-safe），也不冒病态深嵌套撑爆递归栈的险；正常目录树
/// （含 node_modules）远达不到该深度，对真实扫描结果无可观测影响。
/// minAge 时效护栏：够老判定的唯一入口是 [`AgeGuard`]（G-1），太新的文件不计入 total
/// （对齐 pattern 未命中的口径）。
/// 全局排除名单：命中前缀/全路径的文件不计入 total。
/// 保护清单（R10）：命中执行侧同源保护根的文件不计入**可删**（total 仍计）。
/// 单个目录内文件探测的并行执行器（2026-10-23 扫描提速）。
///
/// 为什么在这里并行：扫描的真实成本是逐文件 metadata + 保护判定 + 独占打开
/// （真机实测 windowsDownloadCache 5.4 万文件约 11.6s，几乎全在这一段；本机
/// 微基准 `file_deletable` 串行 17µs/文件、并行 4.4µs/文件）。**只并行同一目录内的
/// 文件探测**：目录递归仍在调用线程按原顺序进行，计数与 PLAN_CAP 预算的合并留在
/// 单线程——不引入跨线程共享状态，清单顺序仍是确定的（同目录按 readdir 顺序）。
///
/// 线程数封顶 8：这是 I/O + 实时防护过滤驱动的负载，并发过高只会把机械盘/杀软队列
/// 打散；池建不起来就退回串行（行为与旧实现一致）。
fn probe_files<T, F>(files: &[(std::path::PathBuf, String)], f: F) -> Vec<T>
where
    T: Send,
    F: Fn(&std::path::Path, &str) -> T + Sync + Send,
{
    fn pool() -> Option<&'static rayon::ThreadPool> {
        static POOL: std::sync::OnceLock<Option<rayon::ThreadPool>> = std::sync::OnceLock::new();
        POOL.get_or_init(|| {
            let n = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .clamp(1, 8);
            rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .thread_name(|i| format!("trim-scan-{i}"))
                .build()
                .ok()
        })
        .as_ref()
    }
    match pool() {
        Some(p) => p.install(|| {
            use rayon::prelude::*;
            files.par_iter().map(|(p, s)| f(p, s)).collect()
        }),
        None => files.iter().map(|(p, s)| f(p, s)).collect(),
    }
}

/// 元数据上的 reparse 判定（`crate::is_reparse` 吃的是 DirEntry；并行探测只有路径）。
/// 命名刻意避开 `is_reparse(` 形态：`check-scan-rule-diff` 的 R1-2a 按这个子串
/// 找「命中即丢弃」站点，helper 定义被算进去会造出假红。
fn md_reparse_flag(md: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        md.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        md.file_type().is_symlink()
    }
}

/// 单个文件的探测结果（并行段产出、主线程按 readdir 顺序合并）。
#[derive(Clone, Copy, Default)]
struct FileProbe {
    reparse: bool,
    size: u64,
    bt: u64,
    /// 通过 pattern 之外的过滤（年龄 + 排除名单）⇒ 计入 total
    counted: bool,
    /// 保护判定与独占打开都通过 ⇒ 计入 deletable / 可删清单
    deletable: bool,
}

/// 单文件探测的共享实现：整树预取与逐目录回退调用**同一份**判据（§5.16/N6）。
///
/// 返回 `None` = 元数据读不到。missing 的处置由调用方的回退闭包保留原口径
/// （`walk_deletable` 走 `old_enough_when_missing`，fk 遍历器直接丢弃）。
/// `skip_lock` 只豁免独占打开，不豁免 R10 保护判定（与三处遍历器原口径一致）。
fn probe_one(
    path: &Path,
    full: &str,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
    skip_lock: bool,
) -> Option<FileProbe> {
    let md = fs::symlink_metadata(path).ok()?;
    if md_reparse_flag(&md) {
        return Some(FileProbe { reparse: true, ..Default::default() });
    }
    if !guard.old_enough(&md) {
        return Some(FileProbe { counted: false, ..Default::default() });
    }
    let excluded = (!excl_dirs.is_empty() || !excl_files.is_empty())
        && path_excluded(excl_dirs, excl_files, &full.to_lowercase());
    if excluded {
        return Some(FileProbe { counted: false, ..Default::default() });
    }
    let deletable = if skip_lock {
        !crate::scan::is_protected_path(full, protect)
    } else {
        scan_deletable(path, protect)
    };
    Some(FileProbe {
        reparse: false,
        size: md.len(),
        bt: birthtime_ns(&md),
        counted: true,
        deletable,
    })
}

/// `walk_deletable` 的回退探测：与旧闭包逐条同口径（含 metadata 读不到时的
/// `old_enough_when_missing` 分支）。
fn walk_deletable_probe(
    path: &Path,
    full: &str,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
) -> FileProbe {
    if let Some(p) = probe_one(path, full, guard, excl_dirs, excl_files, protect, false) {
        return p;
    }
    // 元数据读不到：有护栏按太新；无护栏维持既有口径（后再做保护/独占判定）
    let old_enough = guard.old_enough_when_missing();
    let excluded = (!excl_dirs.is_empty() || !excl_files.is_empty())
        && path_excluded(excl_dirs, excl_files, &full.to_lowercase());
    let counted = old_enough && !excluded;
    FileProbe {
        reparse: false,
        size: 0,
        bt: 0,
        counted,
        deletable: counted && scan_deletable(path, protect),
    }
}

/// fk 遍历器的回退探测：metadata 读不到 = 全 false（与旧闭包一致）。
fn fk_walk_probe(
    path: &Path,
    full: &str,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
    skip_lock: bool,
) -> FileProbe {
    probe_one(path, full, guard, excl_dirs, excl_files, protect, skip_lock).unwrap_or_default()
}

/// 整树预取上限：超过此数不再收集，剩余文件回退到逐目录按需探测。
/// 取 2× 单条目上限：覆盖现库所有大树（最大 5.4 万），同时给无界树一个内存/IO 上界。
const PREFETCH_MAX_FILES: usize = 200_000;

/// 目录项快照（预取阶段生成；walker 直接消费，省掉第二遍 read_dir）。
///
/// 顺序 = 原 read_dir 顺序；`File` 已在 `snapshot_dir` 里按 pattern 过滤（未命中的
/// 文件原 walker 也是 `continue`，不影响任何计数）。
enum CachedEntry {
    File { path: std::path::PathBuf, full: String },
    Dir { path: std::path::PathBuf, reparse: bool },
    Other,
}

struct DirSnapshot {
    entries: Vec<CachedEntry>,
    /// 本目录枚举时命中的 reparse 目录/其他项数。walker 处理到该目录时一次加总，
    /// 保证「预算耗尽后不再下钻」时不会把未处理目录的计数算进去。
    skipped_reparse: u64,
    /// `Some` = 预取时该目录不可读；walker 按原口径计数并留痕，不静默丢。
    error: Option<String>,
}

#[derive(Default)]
struct WalkCache {
    dirs: std::collections::HashMap<std::path::PathBuf, DirSnapshot>,
    probes: std::collections::HashMap<std::path::PathBuf, FileProbe>,
}

/// 读一个目录并转成缓存条目。预取与 walker 的 live 回退共用这一份枚举实现，
/// 防止「两套目录分类」造成顺序/过滤分叉。
fn snapshot_dir(dir: &Path, all: bool, pattern: &str) -> Result<DirSnapshot, String> {
    let rd = fs::read_dir(dir).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut skipped_reparse = 0u64;
    for ent in rd.flatten() {
        let Ok(ft) = ent.file_type() else { continue };
        if ft.is_dir() {
            let reparse = crate::is_reparse(&ent);
            if reparse {
                skipped_reparse += 1;
            }
            out.push(CachedEntry::Dir { path: ent.path(), reparse });
        } else if ft.is_file() {
            let name = ent.file_name().to_string_lossy().to_string();
            if !all && !wildcard_match(&name, pattern) {
                continue;
            }
            let full = ent.path().to_string_lossy().to_string();
            out.push(CachedEntry::File { path: ent.path(), full });
        } else {
            let reparse = crate::is_reparse(&ent);
            if reparse {
                skipped_reparse += 1;
            }
            out.push(CachedEntry::Other);
        }
    }
    Ok(DirSnapshot { entries: out, skipped_reparse, error: None })
}

/// 整树预取：串行枚举目录、记录目录快照，并把匹配 pattern 的文件一次性并行探测。
///
/// **不改变遍历器的顺序/计数/截断**：递归、去重、PLAN_CAP 仍由原 walker 按原顺序执行；
/// walker 命中快照时直接用缓存条目与探测结果，不再二次 read_dir/metadata。
///
/// 时点差异：目录枚举与独占打开都发生在预取阶段，比旧实现略早。判据与函数未变，
/// 静态树上输出逐字节一致；动态占用变化仍由执行侧复检兜底。
fn prefetch_walk(
    root: &Path,
    all: bool,
    pattern: &str,
    recurse: bool,
    max_depth: usize,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
    skip_lock: bool,
) -> WalkCache {
    let mut cache = WalkCache::default();
    let mut files: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if files.len() >= PREFETCH_MAX_FILES {
            break;
        }
        match snapshot_dir(&dir, all, pattern) {
            Ok(snap) => {
                let mut subdirs: Vec<std::path::PathBuf> = Vec::new();
                for ent in &snap.entries {
                    match ent {
                        CachedEntry::Dir { path, reparse } => {
                            // 与 walker 同深度口径：下一层 >= max_depth 的目录不会再被读取
                            if !*reparse && recurse && depth + 1 < max_depth {
                                subdirs.push(path.clone());
                            }
                        }
                        CachedEntry::File { path, full, .. } => {
                            files.push((path.clone(), full.clone()));
                            if files.len() >= PREFETCH_MAX_FILES {
                                break;
                            }
                        }
                        CachedEntry::Other => {}
                    }
                }
                cache.dirs.insert(dir, snap);
                // 栈序只为调试可读；walker 的顺序由快照里的 readdir 顺序决定。
                for sub in subdirs.into_iter().rev() {
                    stack.push((sub, depth + 1));
                }
            }
            Err(e) => {
                cache.dirs.insert(dir, DirSnapshot { entries: Vec::new(), skipped_reparse: 0, error: Some(e) });
            }
        }
    }
    if !files.is_empty() {
        let probes: Vec<Option<FileProbe>> = probe_files(&files, |path, full| {
            probe_one(path, full, guard, excl_dirs, excl_files, protect, skip_lock)
        });
        for ((path, _), p) in files.into_iter().zip(probes) {
            if let Some(p) = p {
                cache.probes.insert(path, p);
            }
        }
    }
    cache
}

/// walker 的目录来源：预取快照命中 / live 回退 / 预取时的读失败。
enum DirView<'a> {
    Cached(&'a DirSnapshot),
    Live(DirSnapshot),
    Error(String),
}

impl DirView<'_> {
    fn entries(&self) -> &[CachedEntry] {
        match self {
            DirView::Cached(s) => &s.entries,
            DirView::Live(s) => &s.entries,
            DirView::Error(_) => &[],
        }
    }

    /// 本目录的 reparse 跳过计数：walker 处理到该目录时一次加总。
    fn skipped_reparse(&self) -> u64 {
        match self {
            DirView::Cached(s) => s.skipped_reparse,
            DirView::Live(s) => s.skipped_reparse,
            DirView::Error(_) => 0,
        }
    }
}

fn load_dir<'a>(cache: Option<&'a WalkCache>, dir: &Path, all: bool, pattern: &str) -> DirView<'a> {
    if let Some(c) = cache {
        if let Some(snap) = c.dirs.get(dir) {
            return match &snap.error {
                Some(e) => DirView::Error(e.clone()),
                None => DirView::Cached(snap),
            };
        }
    }
    match snapshot_dir(dir, all, pattern) {
        Ok(snap) => DirView::Live(snap),
        Err(e) => DirView::Error(e),
    }
}

fn walk_deletable(
    dir: &Path,
    all: bool,
    pattern: &str,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
    res: &mut DeletableResult,
    depth: usize,
    collect_files: bool,
    cap: Option<usize>,
    cache: Option<&WalkCache>,
) {
    if depth >= crate::scan::MAX_WALK_DEPTH {
        err_line(&format!("[trim-scanner] depth cap reached at {}", dir.display()));
        return;
    }
    let view = load_dir(cache, dir, all, pattern);
    if let DirView::Error(e) = &view {
        res.unreadable_dirs += 1;
        // v7.2-C03（N1a-M04）：「扫失败」与「确无结果」在输出上必须可分辨——
        // IgnoreInaccessible 语义保留（跳过继续），但 stderr 留痕。
        err_line(&format!(
            "[trim-scanner] read_dir {} 失败: {e}（该子树按不可达跳过，不进 total/可删）",
            dir.display()
        ));
        return;
    }
    // 本目录的 reparse 跳过数在枚举时已统计；只在本目录真正被处理时一次加总
    // （预算耗尽后不再下钻的目录不会被算进来）。
    res.skipped_reparse += view.skipped_reparse();
    let mut subdirs: Vec<std::path::PathBuf> = Vec::new();
    let mut files: Vec<(std::path::PathBuf, String)> = Vec::new();
    for ent in view.entries() {
        match ent {
            CachedEntry::Dir { path, reparse } => {
                // reparse 目录只留痕、不深入；普通目录待本层文件合并完后递归。
                if !*reparse {
                    subdirs.push(path.clone());
                }
            }
            // snapshot_dir 已按 pattern 过滤；未命中的文件原 walker 也是 continue。
            CachedEntry::File { path, full, .. } => files.push((path.clone(), full.clone())),
            CachedEntry::Other => {}
        }
    }
    // 逐文件探测：整树预取命中时直接取结果；有缺失才回退到并行/串行探测。
    // 合并仍按 readdir 顺序（计数器与清单顺序确定）。
    let probes: Vec<FileProbe> = match cache {
        Some(c) if files.iter().all(|(p, _)| c.probes.contains_key(p)) => {
            // `all(contains_key)` 已保证每个 key 存在；缓存本次遍历只读不改，
            // 这里用 unwrap_or_default 只是去掉生产面 unwrap（N10），不走 live 探测。
            files.iter().map(|(p, _)| c.probes.get(p).copied().unwrap_or_default()).collect()
        }
        Some(c) => probe_files(&files, |path, full| {
            c.probes
                .get(path)
                .copied()
                .unwrap_or_else(|| walk_deletable_probe(path, full, guard, excl_dirs, excl_files, protect))
        }),
        None => probe_files(&files, |path, full| {
            walk_deletable_probe(path, full, guard, excl_dirs, excl_files, protect)
        }),
    };
    for ((_, full), p) in files.iter().zip(probes) {
        if p.reparse {
            res.skipped_reparse += 1;
            continue;
        }
        if !p.counted {
            continue;
        }
        res.total += 1;
        if p.deletable {
            // 计数与字节和**两种模式都记**（统计口径的唯一数据源）；
            // 路径字符串只在真要交给调用方时才留（审计 §3.3）。
            res.deletable_count += 1;
            res.deletable_bytes += p.size;
            if collect_files {
                match cap {
                    Some(n) if res.files.len() >= n => res.files_truncated = true,
                    _ => res.files.push((full.clone(), p.size, p.bt)),
                }
            }
        }
    }
    for sub in subdirs {
        walk_deletable(&sub, all, pattern, guard, excl_dirs, excl_files, protect, res, depth + 1, collect_files, cap, cache);
    }
}

pub fn list_deletable(
    root_str: &str,
    pattern: &str,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
) -> DeletableResult {
    list_deletable_inner(root_str, pattern, guard, excl_dirs, excl_files, protect, true, None)
}

/// 带**清单上限**的收集模式（2026-10-23 新增，pathPs 整树条目专用）。
///
/// 为什么不直接复用 `list_deletable`：后者无界物化，`%TEMP%` / `%WINDIR%\Temp` 这类
/// 无界树会把几十万条堆字符串一次性留在内存里；而 PLAN_CAP 是**跨条目**预算
/// （单条目 10 万 / 全扫描 100 万），必须在枚举当场施加，不能"先全收再截断"——
/// 与 FkAcc 的预算施加姿势一致（§3.4 那条「上限必须在装配过程中生效」的教训）。
/// 超预算后 size / deletable_count 仍按全量累加（体积不能谎报），只有清单停止追加，
/// 并把 `files_truncated` 置真外发成 `filesTruncated`，让用户在确认环节看得见。
pub fn list_deletable_capped(
    root_str: &str,
    pattern: &str,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
    cap: usize,
) -> DeletableResult {
    list_deletable_inner(root_str, pattern, guard, excl_dirs, excl_files, protect, true, Some(cap))
}

/// 只算计数与字节和，**不持有每文件路径**（审计 §3.3）。
///
/// 统计口径（`get_path_deletable_stats`）是这个函数的唯一消费者，而它要的只是
/// `nfiles` 与 `size`。让它走 `files` 就是「为算一个和先造几十万条字符串，
/// 算完立刻全丢」—— 全程在 `spawn_blocking` 里持扫描互斥锁，而现库里有
/// `%TEMP%` / `%WINDIR%\Temp` / `%LOCALAPPDATA%\NVIDIA` 这类无界树。
pub fn list_deletable_stats(
    root_str: &str,
    pattern: &str,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
) -> DeletableResult {
    list_deletable_inner(root_str, pattern, guard, excl_dirs, excl_files, protect, false, None)
}

fn list_deletable_inner(
    root_str: &str,
    pattern: &str,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
    collect_files: bool,
    cap: Option<usize>,
) -> DeletableResult {
    let all = pattern.is_empty() || pattern == "*";
    let root = Path::new(root_str);
    // 根本身是文件（pattern='*'）：单文件口径（对齐 TryFileLength 分支）
    if all {
        if let Some(fl) = try_file_length(root) {
            // minAge：单文件同样要过时效护栏（够老判定与递归分支同一入口；
            // 有护栏且元数据读不到按太新，无护栏维持既有口径）
            let old_enough = guard.old_enough_path(root);
            let root_low = root.to_string_lossy().to_lowercase();
            let excluded = path_excluded(excl_dirs, excl_files, &root_low);
            let mut files = Vec::new();
            let mut deletable_count = 0u64;
            let mut deletable_bytes = 0u64;
            let mut files_truncated = false;
            if old_enough && !excluded && scan_deletable(root, protect) {
                deletable_count = 1;
                deletable_bytes = fl;
                if collect_files {
                    // 与递归分支同口径：size 与出生时间来自同一次 metadata 读取
                    let bt = fs::metadata(root).map(|m| birthtime_ns(&m)).unwrap_or(0);
                    if cap.unwrap_or(usize::MAX) == 0 {
                        files_truncated = true;
                    } else {
                        files.push((root_str.to_string(), fl, bt));
                    }
                }
            }
            return DeletableResult {
                files,
                total: if old_enough && !excluded { 1 } else { 0 },
                deletable_count,
                deletable_bytes,
                skipped_reparse: 0, // 单文件路径不枚举子项，无重解析点可跳
                unreadable_dirs: 0,
                files_truncated,
            };
        }
    }
    let mut res = DeletableResult {
        files: Vec::new(),
        total: 0,
        deletable_count: 0,
        deletable_bytes: 0,
        skipped_reparse: 0,
        unreadable_dirs: 0,
        files_truncated: false,
    };
    // 根不存在/不可访问 → 空结果（对齐 PS 侧 catch 空语义；根级失败由调用方探针另判 ok=false）
    // 整树预取：把逐文件 metadata/保护/独占打开提前并行做掉，遍历顺序仍由 walker 决定。
    let cache = prefetch_walk(
        root,
        all,
        pattern,
        true,
        crate::scan::MAX_WALK_DEPTH,
        guard,
        excl_dirs,
        excl_files,
        protect,
        false,
    );
    walk_deletable(root, all, pattern, guard, excl_dirs, excl_files, protect, &mut res, 0, collect_files, cap, Some(&cache));
    res
}

// ==================== Get-PathDeletableStats 口径（三态出口） ====================

// L6（2026-09-19）：missing / nfiles 是 Get-PathDeletableStats 的 PS 侧契约字段，
// Rust 当前调用方只消费 ok / size；保留字段以维持与 PS 口径的结构对等，显式豁免 dead_code。
#[derive(Default)]
#[allow(dead_code)]
pub struct PathStats {
    pub ok: bool,
    pub missing: bool,
    pub size: u64,
    pub nfiles: u64,
    pub locked: u64,
    /// 本次枚举因重解析点跳过的目录数（R1-2 留痕）。
    ///
    /// 这是「用户为什么觉得这个目录清理得少」的那句话：`AppData\Roaming\Application Data`
    /// 这类 junction被跳过后，size 天然小于 Explorer 显示的值 —— 界面必须自己说出来，
    /// 否则用户会以为扫描漏了。这里的值只做**呈现**，不进size/nfiles/locked 任何判定。
    pub skipped_reparse: u64,
    /// 因权限/IO 失败读不到的目录数（A1-M02，v7.2 C06）。
    pub unreadable_dirs: u64,
    /// 逐文件清单（路径 / 字节 / birthtimeNs）。仅 `get_path_deletable_stats` 的收集模式
    /// 填充；统计模式恒空（审计 §3.3 的口径不变）。
    pub files: Vec<(String, u64, u64)>,
    /// 清单受 PLAN_CAP 截断（size 仍是全量）。
    pub files_truncated: bool,
}

/// 目录型（pathPs）目标的三态统计。
///
/// `collect_files=true` 时同时产出逐文件清单（受 `cap` 约束）——2026-10-23 起 pathPs
/// 条目也要有身份证基线与跨条目去重依据，而**判据不许另写一份**（§5.16）：这里仍走
/// `list_deletable_*` 同一套枚举，只是把收集模式与预算开开。
fn get_path_deletable_stats(path: &str, guard: AgeGuard, protect: Option<&str>, collect_files: bool, cap: Option<usize>) -> PathStats {
    // 单文件目标在收集模式下也要出清单（身份证基线对它是同一件事），代价是多读一次 metadata
    let single_file_list = |size: u64| -> (Vec<(String, u64, u64)>, bool) {
        if !collect_files {
            return (Vec::new(), false);
        }
        if cap.unwrap_or(usize::MAX) == 0 {
            return (Vec::new(), true);
        }
        let bt = fs::metadata(path).map(|m| birthtime_ns(&m)).unwrap_or(0);
        (vec![(path.to_string(), size, bt)], false)
    };
    if path.is_empty() {
        return PathStats { missing: true, ..Default::default() };
    }
    let p = Path::new(path);
    // 存在性用同一套 API 判定（metadata 跟随链接，与 .NET Exists 同源）
    let is_dir = fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false);
    if !is_dir {
        if fs::metadata(p).map(|m| m.is_file()).unwrap_or(false) {
            if !scan_deletable(p, protect) {
                return PathStats { ok: true, missing: false, locked: 1, ..Default::default() };
            }
            return match fs::metadata(p) {
                Ok(m) => {
                    let (files, files_truncated) = single_file_list(m.len());
                    PathStats {
                        ok: true,
                        size: m.len(),
                        nfiles: 1,
                        files,
                        files_truncated,
                        ..Default::default()
                    }
                }
                Err(_) => PathStats { ok: false, unreadable_dirs: 1, ..Default::default() },
            };
        }
        // 既非目录也非文件 = 不存在
        return PathStats { ok: true, missing: true, ..Default::default() };
    }
    // 枚举探针：连一个子项都列不出 = 无法统计（ACL 拒绝 / 重解析目标异常），绝不报 0
    let probe_ok = fs::read_dir(p).and_then(|mut rd| rd.next().transpose()).is_ok();
    if !probe_ok {
        return PathStats { ok: false, unreadable_dirs: 1, ..Default::default() };
    }
    // U1-b（2026-10-01）：全局排除名单整链下线。本探针历史上也只吃全局名单（规则级
    // excludePaths 到这层已经丢了规则上下文），传空集即等价于「名单为空」。
    // nfiles / size 一律从 deletable_count / deletable_bytes 取，那是唯一数据源；
    // 两者口径必须恒等（下面有断言钉住），否则「列表说 N 个、统计说 M 个」会被
    // 用户读成扫描漏项。统计模式仍**不物化每文件路径**（审计 §3.3）；
    // 只有 pathPs 支从 2026-10-23 起要走清单，才切到带预算的收集模式（同一份枚举）。
    let res = if collect_files {
        list_deletable_capped(path, "*", guard, &[], &[], protect, cap.unwrap_or(usize::MAX))
    } else {
        list_deletable_stats(path, "*", guard, &[], &[], protect)
    };
    let nfiles = res.deletable_count;
    let size = res.deletable_bytes;
    PathStats {
        ok: true,
        missing: false,
        size,
        nfiles,
        locked: res.total - nfiles,
        skipped_reparse: res.skipped_reparse,
        unreadable_dirs: res.unreadable_dirs,
        files: res.files,
        files_truncated: res.files_truncated,
    }
}

// ==================== Resolve-GlobDirs 口径（目录通配逐段展开） ====================
// '*'/'?' 逐段展开（** 暂不支持），跳 ReparsePoint；裸盘符段修正为根目录。

fn join_path(r: &str, seg: &str) -> String {
    // 对齐 PS Join-Path：'C:\' 与 'C:\\' 归一为单反斜杠连接；根 '\' 相对当前盘
    if r == "\\" {
        format!("\\{}", seg)
    } else {
        format!("{}\\{}", r.trim_end_matches(['\\', '/']), seg)
    }
}

/// 列出 parent 下匹配通配段的目录（GCI -Directory [-Force]：跳 ReparsePoint；无 Force 时跳隐藏）
fn list_matching_dirs(parent: &str, seg: &str, force: bool, skipped_reparse: &mut u64, unreadable: &mut u64) -> Vec<String> {
    let pd = Path::new(parent);
    let mut out = Vec::new();
    let rd = match fs::read_dir(pd) {
        Ok(r) => r,
        // v7.2-C03（N1a-M04）：glob 段级列目录失败原先静默返回空 ⇒ 「展开为空」
        // 与「目录不可读」同形。留痕后按空返回（不改变展开语义）。
        Err(e) => {
            *unreadable += 1;
            err_line(&format!(
                "[trim-scanner] read_dir {} 失败: {e}（glob 段展开按空处理）",
                pd.display()
            ));
            return out;
        }
    };
    for ent in rd.flatten() {
        if crate::is_reparse(&ent) {
            *skipped_reparse += 1; // R1-2：留痕，不进 out（展开结果）判定
            continue;
        }
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if !ft.is_dir() {
            continue;
        }
        if !force {
            // GCI 无 -Force 时隐藏项不出现（system 属性不隐藏）
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if ent.metadata().map(|m| m.file_attributes() & 0x2 != 0).unwrap_or(false) {
                    continue;
                }
            }
        }
        let name = ent.file_name().to_string_lossy().to_string();
        if wildcard_match(&name, seg) {
            out.push(ent.path().to_string_lossy().to_string());
        }
    }
    out
}

/// `\\` 开头（UNC / verbatim）且含通配符：本展开器没有「共享根」概念，
/// 继续走分段逻辑只会把它当当前盘根下的相对路径（见 `expand_glob_dirs` 内守卫）。
fn is_unc_glob(p: &str) -> bool {
    (p.starts_with("\\\\") || p.starts_with("//")) && (p.contains('*') || p.contains('?'))
}

pub fn expand_glob_dirs(pattern: &str, force: bool) -> Vec<String> {
    // R1-2 留痕：本次展开跳过了多少重解析点目录。
    //
    // 为什么加这个函数：glob 展开是**用户可见的**——展开不出来就没法枚举，
    // 而通配段下藏着 junction（`%AppData%\Roaming\*` 就会撞上 Application Data）
    // 时，界面只显示「无匹配」而不说「跳过了 1 个 junction」，用户会去手工核对目录。
    //
    // 只读不写：局部变量，不回传也不进任何判定。调用方要呈现这句话需要新出口，
    // 那是渲染层的事（当前由 list_deletable / walk_fk_dll 那两条路径的
    // `skippedReparse` 字段承担呈现，本处只保证**不许静默**这件事在代码里可查）。
    let mut skipped_reparse = 0u64;
    let mut unreadable = 0u64;
    let expanded = expand_env_path(pattern);
    // §4.10：盘符相对形态（`\Foo`）按「当前盘根」解析，与保护侧 CWD 口径分叉——
    // 本函数是扫描侧展开口，与执行侧 `engine/native/cleanup.rs` 的 `expand_glob_dirs`
    // 各自拒绝。匹配器已统一（执行侧 glob_match 委托本 crate 的 wildcard_match）；
    // 两侧各保留一份展开实现，分隔符与根处理仍有差异（A2 装载端靠契约兜住），
    // 留痕后返回空集。
    if is_drive_relative(&expanded) {
        err_line(&format!(
            "[cleanup-scan] 盘符相对路径（{expanded}）无盘符语义（未定义环境变量拼接？），已拒绝展开（§4.10）"
        ));
        return Vec::new();
    }
    // N1a-U01：UNC 通配不属盘符相对（上一守卫刻意放过 `\\` 开头），但下面的分段逻辑
    // 没有 UNC 根概念 —— 首段会被当成「当前盘根」下的相对目录（`roots.push("\\")`），
    // 于是当前盘根恰好有同名目录时**静默改道本地**、没有时静默展开为空，两种都没有
    // 任何留痕。正确展开 UNC 通配需要先枚举共享根，超出本函数能力 ⇒ 显式拒绝。
    // 约束：只拒「`\\` 开头且含通配」；非通配 UNC 是合法路径，仍走上面的快路径原样返回。
    if is_unc_glob(&expanded) {
        err_line(&format!(
            "[cleanup-scan] UNC 通配路径（{expanded}）无法安全展开（会被按当前盘根相对路径解析），已拒绝"
        ));
        return Vec::new();
    }
    if !expanded.contains('*') {
        // 非通配快路径：目录直接回；**文件也要回**（2026-10-04 审计 §4.2）。
        //
        // 原先只认 `is_container`（即 is_dir），于是 `fileKeys` 里直指单个文件的条目
        // 在扫描侧永远展开不出东西 ⇒ 该条目 exists:false / size:0，界面上根本选不中。
        // 而执行侧（engine/native/cleanup.rs）本来是有单文件分支的，只是被
        // cleanup_root_ok 挡在前面成了死代码 —— 两处都不覆盖这个形态，属同族分叉。
        //
        // 「扫描能选中、执行能删」必须同时成立，这就是 A2 那条契约的由来。
        //
        // 重解析点**刻意不在这里判**：扫描侧判了只是少报（执行侧会独立再判一次），
        // 而在这里判会让「文件型目标」也承担目录型的 reparse 语义，两边口径更容易漂。
        // 上层 `walk_fk_dll` / `walk_fk_snapshot` 本来就只收文件（`continue` 掉非文件）。
        if is_container(&expanded) || path_exists(&expanded) {
            return vec![expanded];
        }
        return Vec::new();
    }
    let segments: Vec<&str> = expanded.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return Vec::new();
    }
    let mut roots: Vec<String> = Vec::new();
    let mut start = 0usize;
    if segments[0].ends_with(':') {
        roots.push(format!("{}\\", segments[0]));
        start = 1;
    } else {
        roots.push("\\".to_string());
    }
    for seg in &segments[start..] {
        let wild = seg.contains('*') || seg.contains('?');
        let mut next: Vec<String> = Vec::new();
        for r in &roots {
            if wild {
                for d in list_matching_dirs(r, seg, force, &mut skipped_reparse, &mut unreadable) {
                    next.push(d);
                }
            } else {
                let p = join_path(r, seg);
                if is_container(&p) {
                    next.push(p);
                }
            }
        }
        // Select-Object -Unique（字符串比较大小写不敏感，保序取首现）
        let mut seen: Vec<String> = Vec::new();
        next.retain(|p| {
            let l = p.to_lowercase();
            if seen.contains(&l) {
                false
            } else {
                seen.push(l);
                true
            }
        });
        if next.is_empty() {
            return Vec::new();
        }
        roots = next;
    }
    if skipped_reparse > 0 {
        err_line(&format!("[trim-scanner] glob 展开跳过 {skipped_reparse} 个重解析点目录（不深入以避免重复枚举）"));
    }
    if unreadable > 0 {
        err_line(&format!("[trim-scanner] glob 展开有 {unreadable} 个目录不可读（展开结果可能不完整）"));
    }
    roots
}

// ==================== checklocked 子命令（清理前占用检测，v3.3.4） ====================
// 输入：stdin JSON {"files":[{"path":"...","id":"..."}, ...]}（来自主进程扫描快照的计划清单）
// 输出：@@LOCKED@@{"path":"...","id":"...","apps":[...],"critical":[...]} 逐个被占用文件；
//       终止行 @@LOCKED_DONE@@{"scanned":N,"locked":M}
// 两段式探测：独占打开（FileShare.None，与 ListDeletable.Deletable 同口径）快速过滤 →
//   打不开且确实存在的文件逐个查 Restart Manager 拿占用进程应用名（per-file session，
//   RM 不提供 file→process 归属，locked 文件通常为少数，per-file 开销可接受）。

#[cfg(windows)]
mod rstrtmgr {
    const CCH_RM_SESSION_KEY: usize = 32;
    const ERROR_MORE_DATA: i32 = 234;

    // 结构、布局断言与 FFI 声明已上移 `crate::util::ffi`（v3 C-3）。
    use crate::util::ffi::{
        RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources, RmStartSession,
    };
    use crate::util::to_wide;

    /// Restart Manager 查询单个文件的占用者：返回进程列表（PID + 应用名 + 是否系统关键进程）。
    /// RM 不提供 file→process 归属，session 只注册本文件，结果即本文件占用者。
    pub struct RmProc {
        pub pid: u32,
        pub app: String,
        pub critical: bool,
    }

    pub fn query_lockers(path: &str) -> Vec<RmProc> {
        let mut out: Vec<RmProc> = Vec::new();
        unsafe {
            let mut sess: u32 = 0;
            let mut key = [0u16; CCH_RM_SESSION_KEY + 1];
            if RmStartSession(&mut sess, 0, key.as_mut_ptr()) != 0 {
                return out;
            }
            let wide = to_wide(path);
            let ptrs: Vec<*const u16> = vec![wide.as_ptr()];
            let rc = RmRegisterResources(sess, 1, ptrs.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null());
            if rc == 0 {
                let mut needed: u32 = 0;
                let mut count: u32 = 32;
                loop {
                    let mut buf: Vec<RM_PROCESS_INFO> = vec![std::mem::zeroed(); count as usize];
                    let mut reboot: u32 = 0;
                    let rc2 = RmGetList(sess, &mut needed, &mut count, buf.as_mut_ptr(), &mut reboot);
                    if rc2 == ERROR_MORE_DATA {
                        count = needed;
                        continue;
                    }
                    if rc2 == 0 {
                        buf.truncate(count as usize);
                        for pi in &buf {
                            let len = pi.strAppName.iter().position(|&c| c == 0).unwrap_or(pi.strAppName.len());
                            let app = String::from_utf16_lossy(&pi.strAppName[..len]);
                            if app.is_empty() {
                                continue;
                            }
                            // ApplicationType 1000 = RmCritical（系统关键进程，不提供结束入口）
                            out.push(RmProc { pid: pi.Process.dwProcessId, app, critical: pi.ApplicationType == 1000 });
                        }
                    }
                    break;
                }
            }
            RmEndSession(sess);
        }
        out
    }
}

#[cfg(not(windows))]
mod rstrtmgr {
    pub struct RmProc {
        pub pid: u32,
        pub app: String,
        pub critical: bool,
    }

    pub fn query_lockers(_path: &str) -> Vec<RmProc> {
        Vec::new()
    }
}

/// checklocked CLI 入口：stdin 读取 + 输出回写标准流（字节与迁移前逐字一致）
pub fn run_checklocked() -> i32 {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        fatal("stdin 读取失败");
    }
    let (code, out, err) = capture(None, || checklocked_body(&input));
    write_back(&out, &err);
    code
}

/// 数据返回式入口（Tauri 进程内直调）：输出收集进内存，不写 stdout、不 exit。
/// 返回 (exit_code, stdout, stderr)。
pub fn checklocked_json(stdin_text: &str) -> (i32, String, String) {
    capture(None, || checklocked_body(stdin_text))
}

/// v7.2-C03（N1a-M02）：占用检测单文件判定——true = 应查 RM 并输出 @@LOCKED@@。
/// 受保护文件恒 false：旧形态 `scan_deletable=false` 把「受保护」折叠进「被占用」
///（一律送 RM 查询并输出），其持有进程因此进主进程一次性 kill 白名单——保护面
/// 以「占用」的名义变成 kill 候选。独立成函数只为判据可测（破坏自证 §4.1）。
fn occupied_report_warranted(path: &str, protect: Option<&str>) -> bool {
    if crate::scan::is_protected_path(path, protect) {
        return false;
    }
    !file_deletable(Path::new(path))
}

/// checklocked 主流程：逐文件独占探测 → 被占用的查 RM → 行协议输出
fn checklocked_body(input: &str) -> i32 {
    if input.trim().is_empty() {
        fatal("占用检测输入为空");
    }
    let parsed = match parse_json(input) {
        Ok(p) => p,
        Err(e) => fatal(&format!("占用检测输入解析失败: {}", e)),
    };
    let Some(files) = parsed.get("files").and_then(|v| v.as_arr()) else {
        fatal("占用检测输入缺少 files 结构");
    };
    // R10（2026-10-15）：保护清单（可选）——占用检测的可删判定与扫描/执行侧同源
    let protect = parsed.get("protect").and_then(|v| v.as_str());
    let mut scanned: u64 = 0;
    let mut locked: u64 = 0;
    for f in files {
        let Some(path) = f.get("path").and_then(|v| v.as_str()) else { continue };
        if path.is_empty() {
            continue;
        }
        scanned += 1;
        // 目录跳过：目录本就无法以独占读打开（属正常），计划清单理论上只含文件，此处双保险
        if Path::new(path).metadata().map(|m| m.is_dir()).unwrap_or(false) {
            continue;
        }
        // 独占探测过滤：能独占打开（或已不存在）都不是「被占用」目标
        if Path::new(path).metadata().is_err() {
            continue; // 不存在 → 执行阶段自然跳过，不算占用
        }
        // v7.2-C03（N1a-M02）：受保护 ≠ 被占用——判定收进 [`occupied_report_warranted`]。
        if !occupied_report_warranted(path, protect) {
            continue;
        }
        let procs = rstrtmgr::query_lockers(path);
        let id = f.get("id").and_then(|v| v.as_str()).unwrap_or("");
        // procs 携带 PID：主进程 kill 白名单（仅非 critical）来源；RM 对同一进程重复返回，主进程按 pid 去重
        let procs_json = procs
            .iter()
            .map(|p| format!("{{\"pid\":{},\"app\":{},\"critical\":{}}}", p.pid, jstr(&p.app), if p.critical { "true" } else { "false" }))
            .collect::<Vec<_>>()
            .join(",");
        out_line(&format!(
            "@@LOCKED@@{{\"path\":{},\"id\":{},\"procs\":[{}]}}",
            jstr(path),
            jstr(id),
            procs_json
        ));
        locked += 1;
        flush_stdout();
    }
    out_line(&format!("@@LOCKED_DONE@@{{\"scanned\":{},\"locked\":{}}}", scanned, locked));
    flush_stdout();
    0
}

// ==================== 安装检测（Test-RuleDetect 口径） ====================

/// detect 回退链的「候选存在性」一档：`candidatesPs` / `globCandidatesPs` 任一条求值后
/// 在盘上存在即命中；一个候选都没有时返回 `None`（不替调用方编结论）。
///
/// 为什么要有这一档：库里有一类规则**没有固定根**，`pathPs` 写成空字面量 `''`，
/// 真实目录全靠候选自动发现（现算唯一一条：`wechatCache`，候选是新版
/// `Documents\xwechat_files\*\temp` 与旧版 `Documents\WeChat Files\*\FileStorage\Cache`）。
/// 回退链此前只走到「pathPs 求值 → `path_exists("")` = false」就收工，整条规则在
/// `test_rule_detect` 就被 continue ⇒ 候选再真实也永不生效（本机实测候选目录确有内容，
/// 条目却在列表里整条隐身）。存在性判据与主循环同源：`resolve_rule_path` / `path_exists` /
/// `expand_glob_dirs`，§4.10 的盘符相对形态同样按不存在处理，不在这里另立第二套口径。
fn detect_by_candidates(rule: &Json) -> Option<bool> {
    let rid = rule.get("id").and_then(|v| v.as_str()).unwrap_or("?");
    let mut saw_candidate = false;
    for key in ["candidatesPs", "globCandidatesPs"] {
        let Some(arr) = rule.get(key).and_then(|v| v.as_arr()) else { continue };
        for c in arr {
            let Some(ce) = c.as_str() else { continue };
            let Some(cp) = resolve_rule_path(ce) else { continue };
            saw_candidate = true;
            if cp.is_empty() {
                continue;
            }
            if is_drive_relative(&cp) {
                err_line(&format!(
                    "[cleanup-scan] 规则 {rid} {key} 求值为盘符相对路径（{cp}），detect 已按不存在处理（§4.10）"
                ));
                continue;
            }
            if cp.contains('*') {
                if !expand_glob_dirs(&cp, true).is_empty() {
                    return Some(true);
                }
            } else if path_exists(&cp) {
                return Some(true);
            }
        }
    }
    if saw_candidate { Some(false) } else { None }
}

fn test_rule_detect(rule: &Json) -> bool {
    let rid = rule.get("id").and_then(|v| v.as_str()).unwrap_or("?");
    if let Some(d) = rule.get("detect") {
        if d.ps_count() > 0 {
            if let Some(arr) = d.as_arr() {
                for c in arr {
                    let path = match c.get("path").and_then(|p| p.as_str()) {
                        Some(p) if !p.is_empty() => p,
                        _ => continue,
                    };
                    let is_reg = c.get("type").and_then(|t| t.as_str()) == Some("reg");
                    if is_reg {
                        // Test-RegPathExists(Expand-EnvPath(path))——只读注册表存在性判定
                        let expanded = expand_env_path(path);
                        report_unexpanded_token("detect[].path(reg)", rid, &expanded);
                        if ffi::reg_key_exists(&expanded) {
                            return true;
                        }
                    } else {
                        let p = expand_env_path(path);
                        report_unexpanded_token("detect[].path", rid, &p);
                        if is_drive_relative(&p) {
                            // §4.10：盘符相对形态两侧口径分叉，按「不可判定」处理（不命中）
                            err_line(&format!(
                                "[cleanup-scan] 规则 {rid} detect[].path 盘符相对路径（{p}），已按不存在处理（§4.10）"
                            ));
                        } else if p.contains('*') {
                            if !expand_glob_dirs(&p, true).is_empty() {
                                return true;
                            }
                        } else if path_exists(&p) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
    }
    // 无 detect → 退化主路径存在性判定：fileKeys 首键 > pathPs > regKeys，取不到恒命中
    if let Some(fk) = rule.get("fileKeys") {
        if fk.ps_count() > 0 {
            if let Some(arr) = fk.as_arr() {
                if let Some(first) = arr.first() {
                    if let Some(fp0) = first.get("path").and_then(|p| p.as_str()) {
                        let fp = expand_env_path(fp0);
                        report_unexpanded_token("fileKeys[0].path(detect回退)", rid, &fp);
                        if fp.contains('*') {
                            return !expand_glob_dirs(&fp, true).is_empty();
                        }
                        // §4.10：盘符相对形态在 detect 阶段就按「不存在」处理——
                        // path_exists 对它按当前盘根解析，会命中 CWD 偶然属性下的同名目录
                        if is_drive_relative(&fp) {
                            err_line(&format!(
                                "[cleanup-scan] 规则 {rid} fileKeys[0].path 为盘符相对路径（{fp}），detect 已按不存在处理（§4.10）"
                            ));
                            return false;
                        }
                        return path_exists(&fp);
                    }
                }
            }
        }
    }
    if let Some(pp) = rule.get("pathPs") {
        if let Some(expr) = pp.as_str() {
            match resolve_rule_path(expr) {
                Some(p) if !p.is_empty() => {
                    if is_drive_relative(&p) {
                        // §4.10：盘符相对形态按「不可判定」处理（不命中）
                        err_line(&format!(
                            "[cleanup-scan] 规则 {rid} pathPs 求值为盘符相对路径（{p}），已按不存在处理（§4.10）"
                        ));
                        return false;
                    }
                    return path_exists(&p);
                }
                // 求值为**空串**：`pathPs:"''"` 是「无固定根、靠候选自动发现」的空位占位，
                // 空串本身没有存在性可言 —— 判 false 会让整条规则在 detect 就 continue、
                // 候选再真也永不生效（2026-10-23 实测 wechatCache 就是这条）。改走候选档。
                Some(_) => {
                    if let Some(hit) = detect_by_candidates(rule) {
                        return hit;
                    }
                    // 连候选都没有：一条既不指向路径、又不说怎么发现的规则，按不命中收
                    // （不复活成「恒显示、执行 0 删」那种老形状）
                    err_line(&format!(
                        "[cleanup-scan] 规则 {rid} pathPs 求值为空且无任何候选，按不存在处理"
                    ));
                    return false;
                }
                // 表达式求值失败（受限语法）→ 保守命中，交给主循环 fail-closed 跳过
                None => return true,
            }
        }
    }
    if let Some(rk) = rule.get("regKeys") {
        if rk.ps_count() > 0 {
            if let Some(arr) = rk.as_arr() {
                if let Some(first) = arr.first() {
                    if let Some(rp0) = first.get("path").and_then(|p| p.as_str()) {
                        let rp = expand_env_path(rp0);
                        report_unexpanded_token("regKeys[0].path(detect回退)", rid, &rp);
                        return ffi::reg_key_exists(&rp);
                    }
                }
            }
        }
    }
    true
}

// ==================== blockedBy（Get-BlockedProcesses 口径，P1） ====================
// requiredStoppedProcesses 与一次枚举的进程名集合（忽略大小写）求交，命中者进 blockedBy

fn get_blocked(rule: &Json, running: &HashSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(arr) = rule.get("requiredStoppedProcesses").and_then(|v| v.as_arr()) {
        for pn in arr {
            if let Some(s) = pn.as_str() {
                if !s.is_empty() && running.contains(&s.to_lowercase()) {
                    out.push(s.to_string());
                }
            }
        }
    }
    out
}

// ==================== fileKeys 扫描（Get-FileKeyDeletable 口径，P1） ====================
// 两种模式（与 PS 分支逐语义对齐）：
//   DLL 模式（默认）：ListDeletable 口径——每文件独占探测后按 FullName 去重
//     （deletable 计数在去重【前】累加，size/清单在去重【后】累加），无深度上限；
//   快照模式（restartProcesses / excludeKeys / recurse:false 任一命中）：
//     Get-FileKeySnapshot 口径——先去重再计数（-Depth 24 + -Filter），restartProcesses
//     声明条目不做占用探测（执行侧会临时停占用进程，探测会把文件全部误判 locked）。
// PLAN_CAP（D13，方案 v1.1）：单条目 10 万 / 全扫描 100 万行，超限止推并标 filesTruncated。

// ==================== 时效护栏 minAge（P0-M5；G-1 年龄轴 2026-10-07） ====================
// 规则可声明 minAgeHours 或 minAgeDays（二者互斥，契约门禁 A9 钉死）加可选 ageAxis。
// 年龄口径 = 当前时间 − 元数据时间戳；早于 cutoff 才算够老。**解析与判定只有这一份实现**
// （AGENTS §5.16/N6）：扫描（本文件）与执行（engine::native::cleanup_execute）两侧共用，
// 防「扫描排除、执行照删」。
// G-1 收敛掉的分叉：旧实现两侧各有一份解析，双声明时扫描按「无护栏」、执行侧按 max——
// 同一份规则两个删除面。现在统一在 [`rule_age_guard`]。
// fail-closed（G-1 验收口径）：元数据读不到、时间戳在未来、字段非法一律按「太新」处理 ——
// 误删正在写入的文件不可逆，宁可少删。

/// 年龄轴：读哪个时间戳。
///
/// 缺省（规则不写 `ageAxis`）必须按 mtime 解释 —— G-1 明确禁止把缺省改成 ctime
/// （现有条目不得改变命中集合）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeAxis {
    Mtime,
    Ctime,
}

/// 解析规则的 `ageAxis` 字段：缺省/`mtime` → mtime，`ctime` → ctime，
/// 其余（含写成数组的「双轴」形态）→ None。非法枚举由契约门禁 A9 整包判红；
/// 运行期兜底见 [`AgeGuard::Invalid`]。
pub fn parse_age_axis(v: Option<&str>) -> Option<AgeAxis> {
    match v {
        None | Some("mtime") => Some(AgeAxis::Mtime),
        Some("ctime") => Some(AgeAxis::Ctime),
        Some(_) => None,
    }
}

/// 规则年龄护栏（G-1）：解析结果 + 判定本体。`Copy`，便于在递归枚举里逐层传参。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeGuard {
    /// 未声明 minAge*：无年龄护栏（既有口径，命中集合不变）
    Off,
    /// 已声明且可判定：元数据时间早于 `cutoff` 才算够老。
    ///
    /// `secs` 与 `cutoff` 同时保留：`cutoff` 是每个规则算一次的判定门槛（逐文件调
    /// `SystemTime::now()` 既慢又会随时间漂），`secs` 供 [`AgeGuard::tighten`] 做
    /// max 比较（G-2 全局策略要拿它和全局阈值取更严格的那个）。
    On {
        axis: AgeAxis,
        secs: u64,
        cutoff: std::time::SystemTime,
    },
    /// 声明了但字段非法（阈值非正/非数、轴枚举非法、有轴无阈值）：契约门禁 A9 判红并
    /// 整包拒绝，运行期兜底一律判「太新」—— 不许「字段读不懂 ⇒ 无护栏 ⇒ 照删」。
    Invalid,
}

impl AgeGuard {
    /// G-2 全局年龄策略：把规则阈值**只收紧不放宽**地并上全局阈值
    /// （最终门槛 = `max(规则阈值, 全局阈值)`）。
    ///
    /// 三条边界（方案 §2.1 G-2）：
    /// - `Off` 保持 `Off`：全局策略**只作用于已声明 minAge\* 的规则**，不给无护栏的规则
    ///   凭空加护栏（否则「关闭全局策略时命中集合与升级前一致」这条验收不成立）。
    /// - `Invalid` 保持 `Invalid`：已经是最严的那一档，不因全局策略变松。
    /// - `None` / `0` 表示**关闭**（不是「取消护栏」）：原样返回，规则自己的阈值继续生效。
    pub fn tighten(self, global_days: Option<u64>) -> AgeGuard {
        match (self, global_days) {
            (AgeGuard::On { axis, secs, .. }, Some(d)) if d > 0 => {
                let g = d.saturating_mul(86_400);
                let eff = secs.max(g);
                AgeGuard::On {
                    axis,
                    secs: eff,
                    cutoff: min_age_cutoff(eff),
                }
            }
            (g, _) => g,
        }
    }

    /// 元数据是否够老。fail-closed：轴对应的时间戳读不到（`modified`/`created` Err）⇒ false。
    pub fn old_enough(&self, m: &fs::Metadata) -> bool {
        let t = match self {
            AgeGuard::On { axis: AgeAxis::Mtime, .. } => m.modified(),
            AgeGuard::On { axis: AgeAxis::Ctime, .. } => m.created(),
            AgeGuard::Off => return true,
            AgeGuard::Invalid => return false,
        };
        self.old_enough_at(t.ok())
    }

    /// 元数据**读不到**时是否够老：无护栏（Off）维持既有口径（不受限），
    /// 有护栏（On/Invalid）fail-closed 判「太新」。
    ///
    /// 为什么要单独一条：旧调用点是 `cutoff.map(...).unwrap_or(false)`，即
    /// 「有护栏且读不到 ⇒ 太新」；改成共享判定后这层语义必须跟着护栏走，不能丢。
    pub fn old_enough_when_missing(&self) -> bool {
        matches!(self, AgeGuard::Off)
    }

    /// 判定本体（`None` = 时间戳读不到）。时间戳在未来/非法值同走 `t <= cutoff` ⇒ 太新。
    pub fn old_enough_at(&self, t: Option<std::time::SystemTime>) -> bool {
        match self {
            AgeGuard::Off => true,
            AgeGuard::Invalid => false,
            AgeGuard::On { cutoff, .. } => t.map(|t| t <= *cutoff).unwrap_or(false),
        }
    }

    /// 按路径取元数据并判定（判定与「读不到」兜底都收敛在这一处）。
    pub fn old_enough_path(&self, p: &Path) -> bool {
        match fs::metadata(p) {
            Ok(m) => self.old_enough(&m),
            Err(_) => self.old_enough_when_missing(),
        }
    }
}

/// 由规则的三个字段解析年龄护栏。入参是**已抽出的字段值**（两侧 JSON 类型不同：
/// 扫描侧 studjson::Json、执行侧 serde_json::Value —— 共享的是解析与判定口径，
/// 不是 JSON 解析器）。
///
/// - 无 minAge* 且无 ageAxis → [`AgeGuard::Off`]（无护栏，既有口径）
/// - 单声明 → 该值换算秒数；`minAgeDays = 24h 的整数倍`
/// - 双声明 → 取**更严格**（更大）的那个：门禁 A9 判红，运行期宁可少删
/// - 任一字段非法（非正/非有限/轴枚举非法/有轴无阈值）→ [`AgeGuard::Invalid`]
pub fn rule_age_guard(hours: Option<f64>, days: Option<f64>, axis: Option<&str>) -> AgeGuard {
    // 先过滤出「正有限数」；被过滤掉但**确实声明过**的值是非法值，必须 fail-closed
    let declared_bad = [hours, days]
        .into_iter()
        .flatten()
        .any(|n| !(n.is_finite() && n > 0.0));
    if declared_bad {
        return AgeGuard::Invalid;
    }
    let h = hours.filter(|n| n.is_finite() && *n > 0.0);
    let d = days.filter(|n| n.is_finite() && *n > 0.0);
    let secs = match (h, d) {
        (Some(h), Some(d)) => (h * 3600.0).max(d * 86400.0),
        (Some(h), None) => h * 3600.0,
        (None, Some(d)) => d * 86400.0,
        // 无阈值：未声明轴 = 无护栏（既有口径）；声明了轴 = 自相矛盾（门禁 A9 判红）
        (None, None) => {
            return if axis.is_some() { AgeGuard::Invalid } else { AgeGuard::Off };
        }
    };
    let Some(axis) = parse_age_axis(axis) else {
        return AgeGuard::Invalid;
    };
    AgeGuard::On {
        axis,
        secs: secs as u64,
        cutoff: min_age_cutoff(secs as u64),
    }
}

/// G-2 全局年龄策略的**文件名**（唯一真源）：写侧（`commands/cleanup/policy.rs`）与
/// 读侧（本文件的 [`global_min_age_file`]）都从这里取，别在两处各写一遍字面量。
pub const GLOBAL_MIN_AGE_FILE: &str = "cleanup-min-age-days.txt";

/// G-2 全局年龄策略文件的落点：`<数据根>\cleanup-min-age-days.txt`。
///
/// 为什么与 `empty-ignore.txt` 同落点、同「行文本」格式（而不是另开一份 JSON 配置）：
/// - 落点由宿主注入（`util::list_file_path` ⇒ 便携模式感知），扫描器不自己拼 `%APPDATA%`（N2）；
/// - 同域已有的策略文件都是行文本（空目录忽略名单），多开一种格式就多一处会漂的口径；
///   这里的内容就一行整数，不需要 JSON。
pub fn global_min_age_file() -> Option<std::path::PathBuf> {
    crate::util::list_file_path(GLOBAL_MIN_AGE_FILE)
}

/// 全局年龄阈值的**默认值**（天）：入口已改为隐藏式（2026-10-07 用户裁定），
/// 「从未设置过」不再等价于「关闭」，而是按 14 天收紧。
pub const DEFAULT_GLOBAL_MIN_AGE_DAYS: u64 = 14;

/// 读全局年龄阈值（天）。`None` = 关闭（不覆盖规则阈值）。
///
/// 只认**第一行**、必须是正整数。三种情形分开处理（2026-10-07 起）：
/// - 数据根未注入 ⇒ `None`（不猜路径，与 `empty-ignore.txt` 同口径，测试环境走这条）；
/// - 数据根已知但**文件不存在** ⇒ 默认 [`DEFAULT_GLOBAL_MIN_AGE_DAYS`]（入口已隐藏，
///   不设置 = 用默认值）；
/// - 文件存在 ⇒ 以文件为准（空文件 / 非法值 = 显式「关闭」，返回 `None`）。
///
/// 为什么不在这里把取值卡成 UI 档位（14/30）：全局策略**只能收紧**，
/// 手改成一个更大的值不会放宽删除面（方向安全）；卡档次会让「读了但看起来没生效」
/// 变成一处静默失效。非法/负值按关闭处理，同样不会放宽（关闭 = 不覆盖，不是取消护栏）。
pub fn load_global_min_age_days() -> Option<u64> {
    let f = global_min_age_file()?;
    match fs::read_to_string(&f) {
        Ok(text) => parse_global_min_age(&text),
        Err(_) => Some(DEFAULT_GLOBAL_MIN_AGE_DAYS),
    }
}

/// 策略文件文本 → 天数（纯函数，便于把「空文件 / 非法值 / 多行」这几类样本钉住）。
pub fn parse_global_min_age(text: &str) -> Option<u64> {
    let first = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    first.parse::<u64>().ok().filter(|d| *d > 0)
}

/// 从规则 JSON（本文件 studjson::Json）抽 minAge*/ageAxis 三个字段，调共享解析
/// [`rule_age_guard`]：扫描侧不得再写第二份换算（G-1 / AGENTS §5.16 N6）。
/// 只做「取字段」这一层胶水（JSON 类型两侧不同）；换算、轴解析、fail-closed 判定全在共享函数。
///
/// `global_min_age_days`（G-2）由调用方**每次扫描读一次**后逐层传入：逐条规则读文件是
/// N 次 IO，而进程内缓存会让「改了档次要重启才生效」—— 两种都不能接受。
/// 并法固定为 `max(规则阈值, 全局阈值)`（[`AgeGuard::tighten`]），只收紧不放宽。
fn rule_age_guard_of(rule: &Json, global_min_age_days: Option<u64>) -> AgeGuard {
    let num = |k: &str| match rule.get(k) {
        Some(Json::Num(n)) => Some(*n),
        _ => None,
    };
    rule_age_guard(
        num("minAgeHours"),
        num("minAgeDays"),
        rule.get("ageAxis").and_then(|v| v.as_str()),
    )
    .tighten(global_min_age_days)
}

/// 由秒数推 cutoff（现在 − secs）。
///
/// §5.1：`f64 as u64` 在天文数字下饱和到 `u64::MAX`，`SystemTime - Duration` 会
/// panic —— 且 panic 从 `cleanup_execute` 展开时清单**还没写盘**，已落盘的备份
/// 副本会变成无清单孤儿（可恢复删除变不可恢复）。改为 checked_sub：溢出时
/// 饱和到 `UNIX_EPOCH`。**方向说明**：门槛落在 1970 之前 ⇒ 任何真实文件都判「太新」
/// （宁可少删、且不 panic），是 minAge 变大时本就该有的方向（旧注释把这里写成
/// 「所有文件都够老」，与实际判定相反，G-1 一并订正）。
pub fn min_age_cutoff(secs: u64) -> std::time::SystemTime {
    std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(secs))
        .unwrap_or(std::time::UNIX_EPOCH)
}

/// 全路径（小写）是否被排除名单命中。
pub fn path_excluded(excl_dirs: &[String], excl_files: &[String], low: &str) -> bool {
    // 前缀判定按段边界、不分配临时串：旧写法每个排除目录都 `format!("{d}\\")`，
    // 一次扫描要按「文件数 × 排除项数」分配（2026-10-23 扫描提速）。
    let lb = low.as_bytes();
    excl_dirs.iter().any(|d| {
        let db = d.as_bytes();
        lb.len() > db.len() && lb[db.len()] == b'\\' && lb.starts_with(db)
    }) || excl_files.iter().any(|f| f == low)
}

/// excludePaths 条目按磁盘实况分类（2026-10-04 审计 §4.9）。
///
/// 原判据「`extension().is_some()` 即文件」把 `Vendor.Tool` 这类**带点目录**
/// routed 进文件表，而 `path_excluded` 对文件表只做精确相等匹配 ⇒ 该排除
/// 静默失效、整个子树照删——安全特性被静默关掉，且两侧同款所以没有分叉可查。
/// 现按磁盘实况分类：是目录进前缀表、是文件进精确表；磁盘上查不到的条目
/// 两表都进（两类物态各自有覆盖，排除面扩大的失败方向是「少删」，安全）。
/// 扫描侧与执行侧共用本函数，两侧口径不分叉。
///
/// 刻意用 `symlink_metadata`（不跟随重解析点）：排除一个 junction 时按其
/// 本相分类即可，子树是否可穿越由枚举层的 reparse 规则管，不归这里。
pub fn classify_exclude_entry(ep: &str, excl_dirs: &mut Vec<String>, excl_files: &mut Vec<String>) {
    match std::fs::symlink_metadata(Path::new(ep)) {
        Ok(md) if md.is_dir() => excl_dirs.push(ep.to_string()),
        Ok(_) => excl_files.push(ep.to_string()),
        Err(_) => {
            excl_dirs.push(ep.to_string());
            excl_files.push(ep.to_string());
        }
    }
}

// v7.2-C03（N1a-L01）：单一真源提升为 pub——主仓读侧（commands/cleanup/rules.rs）
// 改为 re-export 本常量，旧形态两侧各写一份字面量、无对拍，写侧改了读侧不会红。
pub const PLAN_CAP_PER_ITEM: usize = 100_000;
pub const PLAN_CAP_TOTAL: usize = 1_000_000;

struct FkResult {
    total_size: i64,
    count: i64,
    locked: i64,
    /// (路径, 大小, birthtimeNs)。第三位 = Kudu S2（2026-10-16）的「文件身份证」：
    /// 扫描时的出生时间纳秒（0 = 读不到 ⇒ 删除侧无基线不拦，父链复检仍兜底）。
    files: Vec<(String, u64, u64)>,
    truncated: bool,
    /// 因重解析点跳过的目录数（R1-2 留痕）。只透出呈现，**不进上面三个判定字段**。
    skipped_reparse: u64,
    /// A1-M01/M02（v7.2 C06）：`ok=false` = 所有候选根都读不到（size/exists 必须给 null，
    /// 不能拿 0/false 冒充「确无结果」）；`unreadable_dirs` = 子目录读失败计数。
    ok: bool,
    unreadable_dirs: u64,
}

struct FkAcc {
    seen: HashSet<String>,
    /// 同 FkResult.files（含 birthtimeNs）
    files: Vec<(String, u64, u64)>,
    total_count: i64,
    total_size: i64,
    deletable_count: i64,
    item_rows: usize,
    global_rows: usize,
    /// 遍历预算上限，构造时取生产常量（见 `FkAcc::new`）。
    ///
    /// 为什么做成字段而不是直接读常量（2026-10-04 审计 §3.4）：这个上限的行为
    /// ——「撞上限后是否真的停止下钻」——是本轮修复的核心，而生产值是 10 万 /
    /// 100 万行，**没有任何一条能在 CI 里跑完的用例能碰到它**。做成字段后
    /// 单测可以把阈值压到 3，用一棵树就验证早退逻辑；生产路径走 `FkAcc::new`
    /// 拿同样的常量，行为不变。
    item_cap: usize,
    global_cap: usize,
    truncated: bool,
    /// 因重解析点跳过的目录数（R1-2 留痕，与 ScanCtx / DeletableResult 同语义）。
    skipped_reparse: u64,
    /// 根级枚举尝试数 / 是否至少有一个根成功（A1-M01）。
    root_attempted: u64,
    root_ok: bool,
    /// 权限/IO 失败读不到的目录数（A1-M02）。
    unreadable_dirs: u64,
}

impl FkAcc {
    /// 生产构造：预算取 `PLAN_CAP_*` 常量。
    fn new(global_rows: usize) -> Self {
        Self {
            seen: HashSet::new(),
            files: Vec::new(),
            total_count: 0,
            total_size: 0,
            deletable_count: 0,
            item_rows: 0,
            global_rows,
            item_cap: PLAN_CAP_PER_ITEM,
            global_cap: PLAN_CAP_TOTAL,
            truncated: false,
            skipped_reparse: 0,
            root_attempted: 0,
            root_ok: false,
            unreadable_dirs: 0,
        }
    }

    /// 推入可删清单：受 PLAN_CAP 约束（推入即计数，超限标截断）
    fn push_budget(&mut self, full: String, size: u64, birthtime_ns: u64) {
        if self.item_rows >= self.item_cap || self.global_rows >= self.global_cap {
            self.truncated = true;
            return;
        }
        self.total_size += size as i64;
        self.files.push((full, size, birthtime_ns));
        self.item_rows += 1;
        self.global_rows += 1;
    }
}

/// Kudu S2（2026-10-16）：文件「身份证」的出生时间分量（UNIX 纪元起纳秒）。
/// 取自与 size 同一份 metadata（零额外 IO）；读不到/早于纪元 → 0（= 无基线，
/// 删除侧对 0 不拦；父链重解析复检仍兜底）。
fn birthtime_ns(md: &fs::Metadata) -> u64 {
    md.created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// 快照模式递归深度上限，**对齐 PS `Get-FileKeySnapshot -Depth 24`**。
///
/// 为什么不用 `scan::MAX_WALK_DEPTH`（64）：那个是防递归栈溢出的**工程护栏**，
/// 快照模式要对齐的是 PS 原实现的**语义口径**（第 25 层起不枚举）——两者目的不同，
/// 数值也不同。审查 L-25 只要求「超限要留痕」，口径本身不改（报告 §10.2 白名单第 6 条）。
const FK_SNAPSHOT_MAX_DEPTH: usize = 24;

#[allow(clippy::too_many_arguments)]
fn walk_fk_dll(
    dir: &Path,
    all: bool,
    pattern: &str,
    recurse: bool,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
    acc: &mut FkAcc,
    depth: usize,
    cache: Option<&WalkCache>,
) {
    // 审查 L-9：与 walk_deletable 同口径——超限子目录整棵跳过并 stderr 留痕，
    // 防病态深嵌套撑爆递归栈（原先无上限是对 PS 无界递归的口径）。
    if depth >= crate::scan::MAX_WALK_DEPTH {
        err_line(&format!("[trim-scanner] depth cap reached at {}", dir.display()));
        return;
    }
    // 遍历预算耗尽 ⇒ 整棵子树不再下钻（2026-10-04 磁盘清理审计 §3.4）。
    //
    // 为什么必须在这里停，而不是只靠 `push_budget` 的计数上限：
    // `push_budget` 只约束**输出行数**。`seen` 集合、`file_deletable` 的独占打开、
    // 以及目录遍历本身都不受限 —— 也就是 `PLAN_CAP` 声明的「单条目 10 万 /
    // 全扫描 100 万行，超限止推」**只对输出成立，对内存与 IO 不成立**：
    // 撞上限之后原本还要把剩下的整棵树走完，而 `seen` 还在继续增长。
    //
    // 现库里就有无界树：`cargoRegistryCache` 递归 `%USERPROFILE%\.cargo\registry\src`，
    // `jetbrainsCache`/`chromeCache` 以 `recurse: true` glob 用户缓存目录。
    if acc.truncated {
        return;
    }
    let view = load_dir(cache, dir, all, pattern);
    if let DirView::Error(e) = &view {
        acc.unreadable_dirs += 1;
        // v7.2-C03（N1a-M04）：留痕同 walk_deletable；depth==0 = fileKeys 根级，
        // 根级失败原先零探针 ⇒「扫失败」与「确无结果」在输出上长得一模一样，
        // 此行即根级 missing 探针。
        if depth == 0 {
            err_line(&format!(
                "[trim-scanner] fileKeys 根级 read_dir 失败: {}（{e}）——输出 0 条 ≠ 目录为空",
                dir.display()
            ));
        } else {
            err_line(&format!(
                "[trim-scanner] read_dir {} 失败: {e}（该子树按不可达跳过，不进 total/可删）",
                dir.display()
            ));
        }
        return;
    }
    if depth == 0 {
        acc.root_ok = true;
    }
    // 本目录的 reparse 跳过数在枚举时已统计；只在本目录真正被处理时一次加总。
    acc.skipped_reparse += view.skipped_reparse();
    let mut subdirs: Vec<std::path::PathBuf> = Vec::new();
    let mut files: Vec<(std::path::PathBuf, String)> = Vec::new();
    for ent in view.entries() {
        match ent {
            CachedEntry::Dir { path, reparse } => {
                if !*reparse && recurse {
                    subdirs.push(path.clone());
                }
            }
            CachedEntry::File { path, full, .. } => files.push((path.clone(), full.clone())),
            CachedEntry::Other => {}
        }
    }
    // 逐文件探测：整树预取命中时直接取结果；有缺失才回退到并行/串行探测。
    // 合并与 PLAN_CAP 预算仍留在调用线程按原顺序做。
    let probes: Vec<FileProbe> = match cache {
        Some(c) if files.iter().all(|(p, _)| c.probes.contains_key(p)) => {
            // `all(contains_key)` 已保证每个 key 存在；缓存本次遍历只读不改，
            // 这里用 unwrap_or_default 只是去掉生产面 unwrap（N10），不走 live 探测。
            files.iter().map(|(p, _)| c.probes.get(p).copied().unwrap_or_default()).collect()
        }
        Some(c) => probe_files(&files, |path, full| {
            c.probes
                .get(path)
                .copied()
                .unwrap_or_else(|| fk_walk_probe(path, full, guard, excl_dirs, excl_files, protect, false))
        }),
        None => probe_files(&files, |path, full| {
            fk_walk_probe(path, full, guard, excl_dirs, excl_files, protect, false)
        }),
    };
    for ((_, full_s), p) in files.iter().zip(probes) {
        if p.reparse {
            acc.skipped_reparse += 1;
            continue;
        }
        if !p.counted {
            continue;
        }
        acc.total_count += 1;
        if p.deletable {
            acc.deletable_count += 1; // 去重前累加（对齐 PS DLL 分支）
            if acc.seen.insert(full_s.to_lowercase()) {
                let before = acc.truncated;
                acc.push_budget(full_s.clone(), p.size, p.bt);
                if !before && acc.truncated {
                    // 只在**首次**翻转到截断时留一次痕：后续每层都打的话，
                    // 一次扫描能刷出上千行同样的日志，把真留痕淹掉。
                    err_line(&format!(
                        "[trim-scanner] PLAN_CAP 已耗尽（单条目上限 {PLAN_CAP_PER_ITEM} 行 / 全扫描 {PLAN_CAP_TOTAL} 行），\
                         剩余子树停止遍历（已记 filesTruncated）"
                    ));
                }
            }
        }
    }
    if acc.truncated {
        return;
    }
    for sub in subdirs {
        walk_fk_dll(&sub, all, pattern, recurse, guard, excl_dirs, excl_files, protect, acc, depth + 1, cache);
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_fk_snapshot(
    dir: &Path,
    all: bool,
    pattern: &str,
    recurse: bool,
    depth: usize,
    guard: AgeGuard,
    excl_dirs: &[String],
    excl_files: &[String],
    protect: Option<&str>,
    skip_lock: bool,
    acc: &mut FkAcc,
    cache: Option<&WalkCache>,
) {
    // 遍历预算耗尽 ⇒ 整棵子树不再下钻（2026-10-04 磁盘清理审计 §3.4，理由见
    // walk_fk_dll 里同一条注释）。快照模式的 `seen` 同样在无界增长。
    if acc.truncated {
        return;
    }
    let view = load_dir(cache, dir, all, pattern);
    if let DirView::Error(e) = &view {
        acc.unreadable_dirs += 1;
        // v7.2-C03（N1a-M04）：与 walk_fk_dll 同口径——根级（depth==0）失败给
        // 根级 missing 探针，子目录失败按不可达留痕。
        if depth == 0 {
            err_line(&format!(
                "[trim-scanner] fileKeys 根级 read_dir 失败: {}（{e}）——输出 0 条 ≠ 目录为空",
                dir.display()
            ));
        } else {
            err_line(&format!(
                "[trim-scanner] read_dir {} 失败: {e}（该子树按不可达跳过，不进 total/可删）",
                dir.display()
            ));
        }
        return;
    }
    if depth == 0 {
        acc.root_ok = true;
    }
    // 本目录的 reparse 跳过数在枚举时已统计；只在本目录真正被处理时一次加总。
    acc.skipped_reparse += view.skipped_reparse();
    let mut subdirs: Vec<std::path::PathBuf> = Vec::new();
    let mut files: Vec<(std::path::PathBuf, String)> = Vec::new();
    for ent in view.entries() {
        match ent {
            CachedEntry::Dir { path, reparse } => {
                if !*reparse && recurse {
                    subdirs.push(path.clone());
                }
            }
            CachedEntry::File { path, full, .. } => files.push((path.clone(), full.clone())),
            CachedEntry::Other => {}
        }
    }
    // 逐文件探测：整树预取命中时直接取结果；有缺失才回退到并行/串行探测。
    // seen/预算合并仍留主线程按原顺序做。
    let probes: Vec<FileProbe> = match cache {
        Some(c) if files.iter().all(|(p, _)| c.probes.contains_key(p)) => {
            // `all(contains_key)` 已保证每个 key 存在；缓存本次遍历只读不改，
            // 这里用 unwrap_or_default 只是去掉生产面 unwrap（N10），不走 live 探测。
            files.iter().map(|(p, _)| c.probes.get(p).copied().unwrap_or_default()).collect()
        }
        Some(c) => probe_files(&files, |path, full| {
            c.probes
                .get(path)
                .copied()
                .unwrap_or_else(|| fk_walk_probe(path, full, guard, excl_dirs, excl_files, protect, skip_lock))
        }),
        None => probe_files(&files, |path, full| {
            fk_walk_probe(path, full, guard, excl_dirs, excl_files, protect, skip_lock)
        }),
    };
    for ((_, full_s), p) in files.iter().zip(probes) {
        if p.reparse {
            acc.skipped_reparse += 1;
            continue;
        }
        if !p.counted {
            continue;
        }
        // 快照分支口径：先去重再计数（对齐 Get-FileKeySnapshot 的 seen.Add 前置）
        if !acc.seen.insert(full_s.to_lowercase()) {
            continue;
        }
        acc.total_count += 1;
        if p.deletable {
            acc.deletable_count += 1;
            let before = acc.truncated;
            acc.push_budget(full_s.clone(), p.size, p.bt);
            if !before && acc.truncated {
                // 首次翻转才留痕（理由同 walk_fk_dll 那处）
                err_line(&format!(
                    "[trim-scanner] PLAN_CAP 已耗尽（单条目上限 {PLAN_CAP_PER_ITEM} 行 / 全扫描 {PLAN_CAP_TOTAL} 行），\
                     剩余子树停止遍历（已记 filesTruncated）"
                ));
            }
        }
    }
    if acc.truncated {
        return;
    }
    for sub in subdirs {
        // 审查 L-25（2026-10-03 L4）：depth 上限的**口径**（24）对齐 PS
        // `Get-FileKeySnapshot -Depth 24`，不是缺陷（报告 §10.2 白名单第 6 条已
        // 裁定）；缺的是**留痕**——walk_deletable / walk_level / walk_fk_dll 三处
        // 超限都 eprintln，这里静默 `continue` ⇒ 「深处的文件没进清单」和
        // 「文件本来就不存在」在日志里长得一模一样。补齐 eprintln 与三处同格式。
        if depth < FK_SNAPSHOT_MAX_DEPTH {
            walk_fk_snapshot(&sub, all, pattern, recurse, depth + 1, guard, excl_dirs, excl_files, protect, skip_lock, acc, cache);
        } else {
            err_line(&format!(
                "[trim-scanner] depth cap {FK_SNAPSHOT_MAX_DEPTH} reached at {}",
                sub.display()
            ));
        }
    }
}

fn get_file_key_deletable(rule: &Json, global_rows: &mut usize, global_min_age_days: Option<u64>, protect: Option<&str>) -> FkResult {
    let rid = rule.get("id").and_then(|v| v.as_str()).unwrap_or("?");
    let skip_lock = rule.get("restartProcesses").map(|v| v.ps_count()).unwrap_or(0) > 0;
    // 规则级 excludePaths（C-2，2026-09-28 开门）：字符串数组，与全局排除名单同口径
    // （%VAR% 展开 / 目录=前缀排除、文件=精确排除，按磁盘实况分类，见
    // classify_exclude_entry —— 原按扩展名推断的判据会把带点目录误 routed，§4.9）。
    // v7.2-C03（N1a-L02）：excludeKeys 的读取点整组摘除——它已进 itemBannedKeys
    //（字段表单一真源），且门禁 A2 禁用回潮即红；旧形态本文件仍留 3 个读取点
    //（has_excl 计数 / snapshot_mode 分支 / 排除面构造）并影响分支选择，读侧
    // 与字段表真源从此分叉。排除语义统一走 excludePaths。
    let has_expaths = rule.get("excludePaths").map(|v| v.ps_count()).unwrap_or(0) > 0;
    let any_recurse_false = rule
        .get("fileKeys")
        .and_then(|v| v.as_arr())
        .map(|arr| arr.iter().any(|fk| fk.get("recurse") == Some(&Json::Bool(false))))
        .unwrap_or(false);
    let snapshot_mode = skip_lock || has_expaths || any_recurse_false;
    let guard = rule_age_guard_of(rule, global_min_age_days);
    // 规则级 excludePaths 的过滤面（excludeKeys 读取点已随 N1a-L02 摘除）。
    // U1-b（2026-10-01）：全局排除名单整链下线，这里不再有全局种子；
    // 执行侧 cleanup_execute 用同一谓词复核，两侧口径仍然一致。
    let mut excl_dirs: Vec<String> = Vec::new();
    let mut excl_files: Vec<String> = Vec::new();
    if let Some(arr) = rule.get("excludePaths").and_then(|v| v.as_arr()) {
        for ep0 in arr.iter().filter_map(|v| v.as_str()) {
            let ep = expand_env_path(ep0).trim_end_matches('\\').to_lowercase();
            if ep.is_empty() || ep.starts_with('#') {
                continue;
            }
            report_unexpanded_token("excludePaths[]", rid, &ep);
            // 分类按磁盘实况（§4.9）：禁再退回「按扩展名推断」——带点目录会被
            // routed 进文件表、排除静默失效、子树照删（check-scan-rule-diff E9 组钉着）
            classify_exclude_entry(&ep, &mut excl_dirs, &mut excl_files);
        }
    }

    let mut acc = FkAcc::new(*global_rows);

    if let Some(arr) = rule.get("fileKeys").and_then(|v| v.as_arr()) {
        for fk in arr {
            let Some(fp) = fk.get("path").and_then(|v| v.as_str()) else {
                continue;
            };
            if fp.is_empty() {
                continue;
            }
            // P0 fail-closed（规则库最终优化方案 2026-09-27）：无法展开的路径不得进入
            // 可清理结果。不再依赖「字面量 %TOKEN% 路径不存在」的隐式兜底——显式跳过并留痕，
            // 日志带规则 id 与原始模板，供「扫描命中、执行 0 删」类问题对账。
            if let Some(tok) = first_unexpanded_token(&expand_env_path(fp)) {
                err_line(&format!(
                    "[cleanup-scan] 规则 {} fileKey 路径变量 %{tok}% 未解析，已跳过（模板 {fp}）",
                    rule.get("id").and_then(|v| v.as_str()).unwrap_or("?")
                ));
                continue;
            }
            let pattern = fk.get("pattern").and_then(|v| v.as_str()).unwrap_or("*");
            let all = pattern.is_empty() || pattern == "*";
            let recurse = fk.get("recurse") != Some(&Json::Bool(false));
            for dir in expand_glob_dirs(fp, true) {
                acc.root_attempted += 1;
                // 单文件 fileKey（setupapi.dev.log / CatRoot2\dberr.txt 这类规则）：
                // walk_* 都是目录遍历器，对文件路径 read_dir 只会报 os error 267
                // 「目录名称无效」→ 条目恒 0 项，而执行侧的单文件分支能删。
                // 2026-10-23 真机日志里两条根级 read_dir 失败即此形态。
                if let Ok(md) = fs::symlink_metadata(&dir) {
                    if md.is_file() && !md_reparse_flag(&md) {
                        let name = Path::new(&dir)
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if !all && !wildcard_match(&name, pattern) {
                            continue;
                        }
                        if !guard.old_enough(&md) {
                            continue;
                        }
                        let low = dir.to_lowercase();
                        if path_excluded(&excl_dirs, &excl_files, &low) {
                            continue;
                        }
                        acc.root_ok = true;
                        if snapshot_mode {
                            if !acc.seen.insert(low) {
                                continue;
                            }
                            acc.total_count += 1;
                            if !crate::scan::is_protected_path(&dir, protect)
                                && (skip_lock || file_deletable(Path::new(&dir)))
                            {
                                acc.deletable_count += 1;
                                let before = acc.truncated;
                                acc.push_budget(dir.clone(), md.len(), birthtime_ns(&md));
                                if !before && acc.truncated {
                                    err_line(&format!(
                                        "[trim-scanner] PLAN_CAP 已耗尽（单条目上限 {PLAN_CAP_PER_ITEM} 行 / 全扫描 {PLAN_CAP_TOTAL} 行），\
                                         剩余子树停止遍历（已记 filesTruncated）"
                                    ));
                                }
                            }
                        } else {
                            acc.total_count += 1;
                            if scan_deletable(Path::new(&dir), protect) {
                                acc.deletable_count += 1;
                                if acc.seen.insert(low) {
                                    let before = acc.truncated;
                                    acc.push_budget(dir.clone(), md.len(), birthtime_ns(&md));
                                    if !before && acc.truncated {
                                        err_line(&format!(
                                            "[trim-scanner] PLAN_CAP 已耗尽（单条目上限 {PLAN_CAP_PER_ITEM} 行 / 全扫描 {PLAN_CAP_TOTAL} 行），\
                                             剩余子树停止遍历（已记 filesTruncated）"
                                        ));
                                    }
                                }
                            }
                        }
                        continue;
                    }
                }
                // snapshot 遍历器在 depth==24 仍会读取该目录（只在 24 处停止继续下钻），
                // 所以预取的“可读深度上界”是 25（开区间），不是 FK_SNAPSHOT_MAX_DEPTH。
                let max_depth = if snapshot_mode {
                    FK_SNAPSHOT_MAX_DEPTH + 1
                } else {
                    crate::scan::MAX_WALK_DEPTH
                };
                // 预算已耗尽：walker 会在第一行直接返回，预取纯属浪费（多根规则常见）。
                let cache = if acc.truncated {
                    WalkCache::default()
                } else {
                    prefetch_walk(
                        Path::new(&dir),
                        all,
                        pattern,
                        recurse,
                        max_depth,
                        guard,
                        &excl_dirs,
                        &excl_files,
                        protect,
                        if snapshot_mode { skip_lock } else { false },
                    )
                };
                if snapshot_mode {
                    walk_fk_snapshot(
                        Path::new(&dir), all, pattern, recurse, 0, guard,
                        &excl_dirs, &excl_files, protect, skip_lock, &mut acc, Some(&cache),
                    );
                } else {
                    walk_fk_dll(Path::new(&dir), all, pattern, recurse, guard, &excl_dirs, &excl_files, protect, &mut acc, 0, Some(&cache));
                }
            }
        }
    }

    *global_rows = acc.global_rows;
    // v3.7.2 短名口径对齐（P3 双引擎对拍）：PS 侧枚举出口（Get-ChildItem /
    // FileSystemEnumerable 的 ToFullPath）会把磁盘上已存在的短名组件展开成长名，
    // Rust read_dir 保留原样。PLANFILE 喂给 PS 执行阶段的保护闸，两侧字符串必须
    // 同口径——统一在枚举出口过 GetLongPathNameW 展开；目标不存在的原样保留。
    let file_count = acc.files.len() as i64;
    let files = acc
        .files
        .into_iter()
        // 性能优化 P1-A（v3 §5.2）：`to_long_path` 对**每个可删文件**都要付一次
        // GetLongPathNameW + ≥2 KB 零初始化缓冲 + 一次 from_utf16 分配
        //（PLAN_CAP_TOTAL=1e6 ⇒ 上限百万次、累计 2 GB 缓冲分配）。而现算规则库
        // 314 条根声明里 **0 条含 `~数字`**，read_dir 出来的已是长名 ⇒ 绝大多数调用恒等却贵。
        // 这里用同一份短名判据做前置短路（`util::contains_short_name`，与 scan 的
        // fail-closed 同源，不许另抄）。
        // 保守性两道：① 字面名真含 `~1` 时判据为 true ⇒ 照常展开，只会少省性能、不会漏展开；
        // ② 只对绝对路径跳过——GetLongPathNameW 会把相对输入**解析成绝对路径**，
        //   扫描出口虽然恒为绝对（walk 的 root 已展开），但把前提写进判据比依赖它更稳。
        .map(|(p, sz, bt)| {
            if Path::new(&p).is_absolute() && !crate::util::has_short_name_component(&p) {
                (p, sz, bt)
            } else {
                (crate::to_long_path(&p), sz, bt)
            }
        })
        .collect();
    FkResult {
        total_size: acc.total_size,
        count: file_count,
        locked: acc.total_count - acc.deletable_count,
        files,
        truncated: acc.truncated,
        skipped_reparse: acc.skipped_reparse,
        ok: acc.root_attempted == 0 || acc.root_ok,
        unreadable_dirs: acc.unreadable_dirs,
    }
}

// ==================== regKeys 扫描（Measure-RegRule 口径，P2） ====================
// 只做存在性 + 规模计数（删除留到执行阶段）：键存在计数 1，无 value 语义时
// 另加 values 数 + 子键数；value='*' 或具名时只数键本身。

/// F-2（2026-09-28 拍板）：规则级 excludePaths 对注册表目标的排除判定（扫描/执行两侧共用）。
/// 排除条目形态与 regKeys path 同源：`HIVE\KEY`（排除整键）或 `HIVE\KEY::VALUE`
/// （只排除该具名值）。归一口径：trim → %VAR% 展开 → 小写 → 去尾 `\`；注册表
/// 键/值名不区分大小写。键下子树保护**不支持**（RegDeleteTree 原子删树无法保留
/// 子键），带 :: 的排除只对具名值目标有意义——对树/通配形态目标是不可兑现语义，
/// 由契约门禁 A2 禁止该组合（回潮即红）。
pub fn reg_target_excluded(excludes: &[String], target: &str, value: Option<&str>) -> bool {
    let norm = |s: &str| expand_env_path(s.trim()).trim_end_matches('\\').to_lowercase();
    let t = norm(target);
    if t.is_empty() {
        return false;
    }
    let tv = value.map(|v| v.to_lowercase());
    for e in excludes {
        let en = norm(e);
        if en.is_empty() {
            continue;
        }
        match en.rsplit_once("::") {
            Some((ek, ev)) if !ek.is_empty() => {
                if t == ek && tv.as_deref() == Some(ev) {
                    return true;
                }
            }
            _ => {
                if t == en {
                    return true;
                }
            }
        }
    }
    false
}

fn measure_reg_rule(rule: &Json) -> (bool, i64) {
    let rid = rule.get("id").and_then(|v| v.as_str()).unwrap_or("?");
    let mut exists = false;
    let mut count: i64 = 0;
    if let Some(arr) = rule.get("regKeys").and_then(|v| v.as_arr()) {
        let excludes: Vec<String> = rule
            .get("excludePaths")
            .and_then(|v| v.as_arr())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        for rk in arr {
            let Some(path) = rk.get("path").and_then(|v| v.as_str()) else {
                continue;
            };
            let p = expand_env_path(path);
            report_unexpanded_token("regKeys[].path", rid, &p);
            let value = rk.get("value").and_then(|v| v.as_str()).unwrap_or("");
            let value_opt = if value.is_empty() { None } else { Some(value) };
            if reg_target_excluded(&excludes, &p, value_opt) {
                continue;
            }
            if !ffi::reg_key_exists(&p) {
                continue;
            }
            exists = true;
            count += 1;
            if value.is_empty() {
                continue;
            }
            if let Some((values, subkeys)) = ffi::reg_key_counts(&p) {
                count += values as i64 + subkeys as i64;
            }
        }
    }
    (exists, count)
}

// ==================== @@ITEM@@ 输出 ====================

fn jstr(s: &str) -> String {
    format!("\"{}\"", crate::json_escape(s))
}

fn jopt_str(v: Option<&str>) -> String {
    match v {
        Some(s) => jstr(s),
        None => "null".to_string(),
    }
}

fn emit_item(fields: &[(&str, String)]) {
    let body: Vec<String> = fields.iter().map(|(k, v)| format!("{}:{}", jstr(k), v)).collect();
    out_line(&format!("@@ITEM@@{{{}}}", body.join(",")));
}

fn emit_dism(id: &str, rule: &Json) {
    let name = rule.get("name").and_then(|v| v.as_str()).unwrap_or(id);
    emit_item(&[
        ("id", jstr(id)),
        ("name", jstr(name)),
        ("configuredPath", jstr("C:\\Windows\\WinSxS")),
        ("path", jstr("C:\\Windows\\WinSxS")),
        ("pathSource", jstr("configured")),
        ("pathCandidates", "[]".to_string()),
        ("autoPath", jstr("")),
        ("autoSize", "0".to_string()),
        ("size", "0".to_string()),
        ("risk", jopt_str(rule.get("risk").and_then(|v| v.as_str()))),
        ("exists", "true".to_string()),
        ("blockedBy", "[]".to_string()),
    ]);
}

/// 回收站条目的占位行（G-4 选项 B）。
///
/// 两条刻意的取值：
///   · `size` 恒 0 / `path` 恒空 —— 真实的条目数与体积**只有 Shell API
///     （`SHQueryRecycleBinW`）能权威回答**，引擎在这里报任何非零数字都是编的；
///     展示值由渲染层调 `cleanup:recycle-stats` 现查后覆盖。
///   · `exists` 恒 true —— 条目在 UI 上必须始终可见。扫描不产路径 ≠ 该入口消失，
///     否则用户再也点不到「清空回收站」。
fn emit_recycle_bin(id: &str, rule: &Json) {
    let name = rule.get("name").and_then(|v| v.as_str()).unwrap_or(id);
    emit_item(&[
        ("id", jstr(id)),
        ("name", jstr(name)),
        ("configuredPath", jstr("")),
        ("path", jstr("")),
        ("pathSource", jstr("shell")),
        ("pathCandidates", "[]".to_string()),
        ("autoPath", jstr("")),
        ("autoSize", "0".to_string()),
        ("size", "0".to_string()),
        ("risk", jopt_str(rule.get("risk").and_then(|v| v.as_str()))),
        ("exists", "true".to_string()),
        ("blockedBy", "[]".to_string()),
    ]);
}

/// 游戏运行库安装包占位行（2026-10-11 批次 B）。
///
/// 三条刻意的取值：
///   · `size` 恒 0 / `path` 恒空 —— 真实大小与文件清单由 Rust 主进程在
///     do_cleanup_scan 中调用 gameclean 收集器扫描后回填；引擎只发占位。
///   · `exists` 恒 true —— 条目必须始终可见（用户需要看到「有这三个入口」）。
///   · 平台归属不在引擎侧判定 —— 平台索引（vdf/acf）扫描是 Rust 侧独立逻辑，
///     引擎不需要知道哪个平台真的装了，统一发 true。
fn emit_game_redist(id: &str, rule: &Json) {
    let name = rule.get("name").and_then(|v| v.as_str()).unwrap_or(id);
    emit_item(&[
        ("id", jstr(id)),
        ("name", jstr(name)),
        ("configuredPath", jstr("")),
        ("path", jstr("")),
        ("pathSource", jstr("gameRedist")),
        ("pathCandidates", "[]".to_string()),
        ("autoPath", jstr("")),
        ("autoSize", "0".to_string()),
        ("size", "0".to_string()),
        ("risk", jopt_str(rule.get("risk").and_then(|v| v.as_str()))),
        ("exists", "true".to_string()),
        ("blockedBy", "[]".to_string()),
    ]);
}

// ==================== 主入口 ====================

/// 致命错误。CLI：flush stdout → stderr → exit(2)（与迁移前逐字一致）；
/// 捕获模式：stderr 进内存后用 panic 把控制权交回 `capture`（绝不能在宿主进程里 exit）。
fn fatal(msg: &str) -> ! {
    let cap = capturing();
    if !cap {
        let _ = std::io::stdout().flush();
    }
    err_line(&format!("[cleanup-scan] 致命: {}", msg));
    if cap {
        std::panic::panic_any(FatalMarker);
    }
    std::process::exit(EXIT_FATAL);
}

/// 数据返回式入口（Tauri 进程内直调）：输出收集进内存，绝不写 stdout、绝不 exit。
/// `on_line` 为逐行回调（不含换行），供调用方边扫边推进度事件。
/// 返回 (exit_code, stdout, stderr)。
///
/// ⚠️ **`on_line` 为 `Some` 时返回的 stdout 是空串**（P2-④）：每行已经逐条交给回调，
/// 再整程攒一份全量副本纯属死重（十万行级就是十 MB 量级驻留）。所以
/// **带回调的调用点不得消费 stdout** —— 现有唯一调用点 `commands/cleanup/scan_execute.rs`
/// 绑的是 `_stdout`。要读 stdout 就别传回调（CLI 形态 `run` 与对拍入口都是这样）。
pub fn run_json(
    argv: &[String],
    stdin_text: &str,
    on_line: Option<Box<dyn FnMut(&str)>>,
) -> (i32, String, String) {
    capture(on_line, || scan_body(argv, stdin_text))
}

/// cleanup CLI 入口：argv/stdin 校验顺序与迁移前一致，输出回写标准流
pub fn run(argv: &[String]) -> i32 {
    if argv.len() < 2 {
        fatal("cleanup 子命令参数不足：需要 categories JSON 与 configuredPaths JSON");
    }
    // 输入通道：规则 JSON 经 stdin 全量写入（方案 v1.1）；空/坏 JSON 一律 fail-closed
    let mut input = String::new();
    if iostdin_read(&mut input).is_err() {
        fatal("stdin 读取失败");
    }
    let (code, out, err) = capture(None, || scan_body(argv, &input));
    write_back(&out, &err);
    code
}

/// 逐条目耗时留痕（2026-10-23 扫描提速）。只记 ≥1s 的条目，避免 187 条刷屏；
/// 此前真机日志里只有「79 项 / 107 秒」一个总数，哪条慢全靠猜。Drop 形态保证
/// 所有 `continue` 出口都会记（循环体内分支很多，手放出口必漏）。
struct SlowRuleTimer {
    id: String,
    t0: std::time::Instant,
}

impl Drop for SlowRuleTimer {
    fn drop(&mut self) {
        let ms = self.t0.elapsed().as_millis();
        if ms >= 1000 {
            err_line(&format!("[cleanup-scan] 慢条目 {}: {}ms", self.id, ms));
        }
    }
}

/// argv = [categories_json, configured_paths_json, (可选) protect_json]；规则 JSON 由调用方读入
fn scan_body(argv: &[String], input: &str) -> i32 {
    // N1a-M05：`run_json` 的入口面不校 argv 长度（`run` 校，宿主直调与集成测试都不经过
    // `run`），而下面两处 `argv[0]/argv[1]` 是裸下标 ⇒ 少传一个参数就是越界 panic，
    // 正好落进「非 FatalMarker panic 无留痕」那条通道。检查必须落在**捕获体内**：
    // 在捕获体外调 `fatal` 走的是 `process::exit`，会把宿主进程一起带走。
    if argv.len() < 2 {
        fatal("参数不足：需要 categories JSON 与 configuredPaths JSON（run_json 入口同 CLI 口径）");
    }
    if input.trim().is_empty() {
        fatal("规则库解析失败：stdin 规则 JSON 为空");
    }
    let rules = match parse_json(input) {
        Ok(r) => r,
        Err(e) => fatal(&format!("规则库解析失败: {}", e)),
    };
    if rules.get("groups").and_then(|g| g.as_arr()).is_none() {
        fatal("规则库解析失败：缺少 groups 结构");
    }
    // id -> 规则条目映射（数据目录覆盖与自定义合并已在主进程完成）；同 id 后者覆盖（PS 哈希表语义）
    let mut rule_map: HashMap<&str, &Json> = HashMap::new();
    if let Some(groups) = rules.get("groups").and_then(|g| g.as_arr()) {
        for g in groups {
            if let Some(sgs) = g.get("subGroups").and_then(|s| s.as_arr()) {
                for sg in sgs {
                    if let Some(items) = sg.get("items").and_then(|i| i.as_arr()) {
                        for it in items {
                            if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
                                rule_map.insert(id, it);
                            }
                        }
                    }
                }
            } else if let Some(items) = g.get("items").and_then(|i| i.as_arr()) {
                for it in items {
                    if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
                        rule_map.insert(id, it);
                    }
                }
            }
        }
    }

    let categories = match parse_json(&argv[0]) {
        Ok(Json::Arr(a)) => a,
        _ => fatal("扫描分类参数解析失败"),
    };
    // R10（2026-10-15）：argv[2] = 注入的保护清单（主进程 `protect::protected_roots_json()`，
    // 与执行侧/回收站链同一份）。缺省（CLI 手测）由 `scan.rs` 走 default_from_env
    // 保守根集兜底——是「过滤面收窄」不是「不过滤」。
    let protect = argv.get(2).map(|s| s.as_str()).filter(|s| !s.is_empty());
    // G-2 全局年龄策略：**一次扫描读一次**，逐层传给年龄护栏构造（见 rule_age_guard_of 注释）
    let global_min_age_days = load_global_min_age_days();
    if categories.is_empty() {
        fatal("扫描分类参数解析失败：categories 为空");
    }
    let configured = match parse_json(&argv[1]) {
        Ok(c @ Json::Obj(_)) => c,
        _ => fatal("路径绑定配置解析失败"),
    };

    // 一次性取全量进程名（requiredStoppedProcesses 扫描侧探测，对齐 PS：循环外单次枚举）
    let running = ffi::process_names();
    // PLAN_CAP 全扫描计数（跨条目累计，D13 防呆上限）
    let mut plan_global_rows: usize = 0;

    for cat in &categories {
        let cat_id = match cat.as_str() {
            Some(s) => s,
            None => continue,
        };
        let rule = match rule_map.get(cat_id) {
            Some(r) => *r,
            None => continue,
        };
        let _slow = SlowRuleTimer { id: cat_id.to_string(), t0: std::time::Instant::now() };

        // special 分流（非路径型条目，方案 v2 §2.2 G-4 / §2.3）：
        //   · dism —— 组件清理，固定返回「可执行」状态（大小以实际执行结果为准）；
        //   · recycleBin —— **G-4 选项 B**：回收站改由渲染层的 Shell API 动作清空
        //     （cleanup:recycle-stats 查条目数与体积 / cleanup:empty-recycle-bin 走
        //     SHEmptyRecycleBinW）。扫描侧**刻意不枚举任何路径** —— 这条分支就是
        //     「`$Recycle.Bin` 不再作为普通清理目录交给永久删链」的引擎侧落点，
        //     删掉它会让旧条目的 pathPs 重新生效（见 rule 条目与 §2.2 G-4 第 4 条）。
        match rule.get("special").and_then(|v| v.as_str()) {
            Some("dism") => {
                emit_dism(cat_id, rule);
                flush_stdout();
                continue;
            }
            Some("recycleBin") => {
                emit_recycle_bin(cat_id, rule);
                flush_stdout();
                continue;
            }
            Some("gameRedist") => {
                emit_game_redist(cat_id, rule);
                flush_stdout();
                continue;
            }
            _ => {}
        }

        // 安装检测——目标应用未安装的条目直接不输出（渲染层扫描后隐藏）
        if !test_rule_detect(rule) {
            continue;
        }

        // blockedBy：requiredStoppedProcesses 扫描侧探测（只进协议做提示标注，不影响统计口径）
        let blocked_json = format!(
            "[{}]",
            get_blocked(rule, &running).iter().map(|s| jstr(s)).collect::<Vec<_>>().join(",")
        );

        // ---- 文件模式条目（fileKeys）：扫描即产「可删文件清单」（P1，D7/D13）----
        if rule.get("fileKeys").map(|f| f.ps_count()).unwrap_or(0) > 0 {
            let st = get_file_key_deletable(rule, &mut plan_global_rows, global_min_age_days, protect);
            let fk_arr = rule.get("fileKeys").and_then(|v| v.as_arr());
            let keys = fk_arr.map(|a| a.len()).unwrap_or(0);
            let display0 = fk_arr
                .and_then(|a| a.first())
                .and_then(|fk| fk.get("path"))
                .and_then(|p| p.as_str())
                .unwrap_or("");
            // 多键展示「首键路径 等 N 处」（首键取原始字符串，不做 env 展开）
            let display = if keys > 1 { format!("{} 等 {} 处", display0, keys) } else { display0.to_string() };
            let name = rule.get("name").and_then(|v| v.as_str());
            let mut fields: Vec<(&str, String)> = vec![
                ("id", jstr(cat_id)),
                ("name", jopt_str(name)),
                ("configuredPath", jstr(&display)),
                ("path", jstr(&display)),
                ("pathSource", jstr("rules")),
                ("pathCandidates", "[]".to_string()),
                ("autoPath", jstr("")),
                ("autoSize", "0".to_string()),
                ("size", if st.ok { st.total_size.to_string() } else { "null".to_string() }),
                ("fileCount", st.count.to_string()),
                ("lockedCount", st.locked.to_string()),
                // R1-2 留痕：跳过的重解析点目录数。**只呈现不进判定**——
                // size/fileCount/lockedCount 三者都不看它（见 walk_fk_dll 内注释）。
                // 缺了它，用户看到清理候选比 Explorer 算的少，却无从判断少在哪。
                ("skippedReparse", st.skipped_reparse.to_string()),
                // A1-M02：读不到的目录数，与 skippedReparse 并列呈现。
                ("skippedUnreadable", st.unreadable_dirs.to_string()),
                ("risk", jopt_str(rule.get("risk").and_then(|v| v.as_str()))),
                // A1-M01：所有候选根都读不到时，size 必须是 null（渲染层走「—」），
                // exists 也给 null；拿 0/false 冒充「确无结果」正是本条要修的缺口。
                ("exists", if !st.ok { "null".to_string() } else if st.count > 0 { "true".to_string() } else { "false".to_string() }),
                ("blockedBy", blocked_json),
            ];
            if !st.ok {
                fields.push(("sizeUnreadable", "true".to_string()));
            }
            if st.truncated {
                // 方案 v1.1：引擎侧 PLAN_CAP 截断标记（main.js 收集侧「只增不清」，字段兼容）
                fields.push(("filesTruncated", "true".to_string()));
            }
            emit_item(&fields);
            for (fp, size, bt) in &st.files {
                out_line(&format!(
                    "@@PLANFILE@@{{\"id\":{},\"path\":{},\"size\":{},\"birthtimeNs\":{}}}",
                    jstr(cat_id),
                    jstr(fp),
                    size,
                    bt
                ));
            }
            flush_stdout();
            continue;
        }

        // ---- 注册表条目（regKeys）：只做存在性 + 规模计数（P2）----
        if rule.get("regKeys").map(|f| f.ps_count()).unwrap_or(0) > 0 {
            let (exists, count) = measure_reg_rule(rule);
            let rk_arr = rule.get("regKeys").and_then(|v| v.as_arr());
            let keys = rk_arr.map(|a| a.len()).unwrap_or(0);
            let display0 = rk_arr
                .and_then(|a| a.first())
                .and_then(|rk| rk.get("path"))
                .and_then(|p| p.as_str())
                .unwrap_or("");
            let display = if keys > 1 { format!("{} 等 {} 处", display0, keys) } else { display0.to_string() };
            emit_item(&[
                ("id", jstr(cat_id)),
                ("name", jopt_str(rule.get("name").and_then(|v| v.as_str()))),
                ("configuredPath", jstr(&display)),
                ("path", jstr(&display)),
                ("pathSource", jstr("rules")),
                ("pathCandidates", "[]".to_string()),
                ("autoPath", jstr("")),
                ("autoSize", "0".to_string()),
                ("size", "null".to_string()),
                ("fileCount", "0".to_string()),
                ("regCount", count.to_string()),
                ("risk", jopt_str(rule.get("risk").and_then(|v| v.as_str()))),
                ("exists", if exists { "true" } else { "false" }.to_string()),
                ("blockedBy", blocked_json),
            ]);
            flush_stdout();
            continue;
        }

        // ---- 目录型条目（pathPs）----
        let expr = match rule.get("pathPs").and_then(|v| v.as_str()) {
            Some(e) if !e.is_empty() => e,
            _ => continue,
        };
        // 受限求值失败 fail-closed 跳过（严禁把表达式原文当路径——v2.2 D1 废除的旧兜底）
        let evaluated = match resolve_rule_path(expr) {
            Some(p) => p,
            None => {
                err_line(&format!("[cleanup-scan] [DIAG] stage=scan.pathPs mutation=skip detail={} pathPs 表达式不符合受限语法，已拒绝求值", cat_id));
                continue;
            }
        };
        // §4.10：盘符相对形态（`$env:UNDEF + '\Foo'` → `\Foo`）不枚举——
        // 「当前盘」是 CWD 的偶然属性，不是规则作者的决定
        if is_drive_relative(&evaluated) {
            err_line(&format!(
                "[cleanup-scan] [DIAG] stage=scan.pathPs mutation=skip detail={cat_id} pathPs 求值为盘符相对路径（{evaluated}），已拒绝枚举（§4.10）"
            ));
            continue;
        }
        let mut path = evaluated.clone();
        let evaluated_path = evaluated;
        let mut path_source = "configured".to_string();
        let mut path_candidates: Vec<String> = Vec::new();
        let mut auto_path = String::new();

        // 应用缓存优先采用设置页已确认的路径；没有确认路径时才走内置候选
        const CONFIG_KEY_MAP: [(&str, &str); 4] = [
            ("neteaseMusicCache", "neteaseCacheDir"),
            ("wechatCache", "wechatCacheDir"),
            ("douyinCache", "douyinCacheDir"),
            ("qqCache", "qqCacheDir"),
        ];
        let mut configured_value = configured
            .get(cat_id)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some((_, mapped)) = CONFIG_KEY_MAP.iter().find(|(k, _)| *k == cat_id) {
            configured_value = configured
                .get(mapped)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
        }
        if !configured_value.is_empty() {
            // §4.8：设置页存量配置值也可能带未解析 %TOKEN%（按原文永远 0 命中）——
            // 只留痕不拒用，让「为什么这项扫不出来」可对账
            report_unexpanded_token("configured", cat_id, &configured_value);
            path = configured_value;
            path_source = "configured".to_string();
        }

        // [D19 键名已对齐（2026-10-01 拍板修复）] 此前按缺陷原样读 `candidates`/`globCandidates`，
        // 而规则库真键名是 `candidatesPs`/`globCandidatesPs` ⇒ 恒死代码。修复前提是把库里
        // 过宽的候选先收敛到叶子 Cache 目录（qqCache/douyinCache 原候选含整个应用数据目录，
        // 原样翻键会净扩删除面）。同步登记处：tools/rule-schema.json crossTrack。
        if let Some(cands) = rule.get("candidatesPs") {
            if cands.ps_count() > 0 {
                if let Some(arr) = cands.as_arr() {
                    for cexpr in arr {
                        if let Some(ce) = cexpr.as_str() {
                            if let Some(cp) = resolve_rule_path(ce) {
                                // §4.10：盘符相对候选不进候选集（自动定位会按当前盘根枚举）
                                if is_drive_relative(&cp) {
                                    err_line(&format!(
                                        "[cleanup-scan] 条目 {cat_id} candidatesPs 求值为盘符相对路径（{cp}），已跳过（§4.10）"
                                    ));
                                    continue;
                                }
                                path_candidates.push(cp);
                            }
                        }
                    }
                }
                if !path_exists(&path) {
                    for candidate in &path_candidates {
                        if !candidate.is_empty() && path_exists(candidate) {
                            auto_path = candidate.clone();
                            path = candidate.clone();
                            path_source = "auto".to_string();
                            break;
                        }
                    }
                }
            }
        }
        if let Some(globs) = rule.get("globCandidatesPs") {
            if globs.ps_count() > 0 {
                if let Some(arr) = globs.as_arr() {
                    for gexpr in arr {
                        let Some(ge) = gexpr.as_str() else { continue };
                        let Some(pat) = resolve_rule_path(ge) else { continue };
                        // GCI -Path pat -Directory（无 -Force：隐藏目录不参与）取第一个匹配
                        let hit = expand_glob_dirs(&pat, false).into_iter().next();
                        if let Some(full) = hit {
                            if !path_exists(&path) {
                                auto_path = full.clone();
                                path = full.clone();
                                path_source = "auto".to_string();
                                path_candidates.push(full);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 目录型统计走可删口径：被占用文件不计入 size，locked 只进协议不进 UI。
        // minAge 时效护栏（P0-M5）：目录型规则的统计与执行侧同口径过滤太新文件。
        // 2026-10-23：本支同时**物化逐文件清单**（与 fileKeys 支共用 PLAN_CAP 预算），
        // 让 pathPs 条目也拿到身份证基线、并能参与跨条目精确去重。此前它们只有聚合 size，
        // `items[].files` 恒空 ⇒ 引擎 Kudu S2 的 identity 表对这些条目完全不生效
        //（「扫描后被替换」的护栏在该形状下静默失效、方向是放行），去重也只能按根前缀
        // 反查、把一个子条的字节整段扣给父条。超预算时 size 仍按全量（体积不谎报），
        // 清单截断位外发 `filesTruncated`，用户在确认环节看得见。
        let item_cap = PLAN_CAP_PER_ITEM.min(PLAN_CAP_TOTAL.saturating_sub(plan_global_rows));
        let stats = get_path_deletable_stats(
            &path,
            rule_age_guard_of(rule, global_min_age_days),
            protect,
            true,
            Some(item_cap),
        );
        plan_global_rows = plan_global_rows.saturating_add(stats.files.len());
        // 统计失败上报 size=null——渲染层对 null 走「—」分支，不用 0 B 冒充可清理
        let size_json = if stats.ok { stats.size.to_string() } else { "null".to_string() };
        // autoPath 命中时 size 即 autoPath 的大小，不再二次枚举
        let auto_size_json = if !auto_path.is_empty() && path == auto_path {
            size_json.clone()
        } else {
            "0".to_string()
        };
        let exists_json = if !stats.ok {
            "null".to_string()
        } else if path_exists(&path) {
            "true".to_string()
        } else {
            "false".to_string()
        };
        let name = rule.get("name").and_then(|v| v.as_str());
        let candidates_json = format!(
            "[{}]",
            path_candidates.iter().map(|c| jstr(c)).collect::<Vec<_>>().join(",")
        );

        let mut fields: Vec<(&str, String)> = vec![
            ("id", jstr(cat_id)),
            ("name", jopt_str(name)),
            ("configuredPath", jstr(&evaluated_path)),
            ("path", jstr(&path)),
            ("pathSource", jstr(&path_source)),
            ("pathCandidates", candidates_json),
            ("autoPath", jstr(&auto_path)),
            ("autoSize", auto_size_json),
            ("size", size_json),
            ("lockedCount", stats.locked.to_string()),
            // R1-2 留痕：跳过的重解析点目录数。渲染层据此在清理项上写明
            // 「已跳过 N 个 junction」，否则用户会以为扫描漏了（junction 指向别的子树，
            // 深入会重复计数甚至成环，跳过是对的，但对用户不可见就成了「少了」）。
            // **只呈现不进判定**：size/nfiles/locked 都不看它。
            ("skippedReparse", stats.skipped_reparse.to_string()),
            // A1-M02：读不到的目录数（与 fileKeys 分支同名同义）。
            ("skippedUnreadable", stats.unreadable_dirs.to_string()),
            ("risk", jopt_str(rule.get("risk").and_then(|v| v.as_str()))),
            ("exists", exists_json),
            ("blockedBy", blocked_json),
        ];
        if stats.files_truncated {
            // 与 fileKeys 支同名同义：清单被 PLAN_CAP 截断，确认环节必须告知
            // 「实际清理范围可能大于列出的清单」（渲染层 cleanup.js 有 filesTruncated 分支）。
            fields.push(("filesTruncated", "true".to_string()));
        }
        emit_item(&fields);
        for (fp, size, bt) in &stats.files {
            out_line(&format!(
                "@@PLANFILE@@{{\"id\":{},\"path\":{},\"size\":{},\"birthtimeNs\":{}}}",
                jstr(cat_id),
                jstr(fp),
                size,
                bt
            ));
        }
        flush_stdout();
    }
    0
}

fn iostdin_read(out: &mut String) -> std::io::Result<()> {
    std::io::stdin().read_to_string(out).map(|_| ())
}

fn flush_stdout() {
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
    /// N1a-U01 反例样本：当前盘根下一个**确实有子目录**的目录名。
    ///
    /// 不写死 `Windows`：测试不许依赖本机特定目录；拿运行时枚举结果当「UNC 首段」，
    /// 修复前它必然会被展开成该目录的子目录（非空），修复后固定为空集。
    fn drive_root_dir_with_subdir() -> Option<String> {
        for ent in std::fs::read_dir("\\").ok()?.flatten() {
            if !ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = ent.file_name().to_string_lossy().to_string();
            if name.contains('*') || name.contains('?') {
                continue;
            }
            let has_sub = std::fs::read_dir(ent.path())
                .ok()
                .map(|rd| rd.flatten().any(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false)))
                .unwrap_or(false);
            if has_sub {
                return Some(name);
            }
        }
        None
    }

    /// N1a-U01：UNC 通配必须显式拒绝（留诊断），非通配 UNC 不许被同一条守卫误伤。
    #[test]
    fn unc_glob_is_rejected_without_touching_plain_unc() {
        assert!(is_unc_glob(r"\\nas\share\*"));
        assert!(is_unc_glob("//nas/share/*.tmp"));
        assert!(!is_unc_glob(r"\\nas\share\folder"));
        assert!(!is_unc_glob(r"\Foo\*"));
        assert!(!is_unc_glob(r"C:\Foo\*"));

        let Some(name) = drive_root_dir_with_subdir() else {
            // 不用 eprintln：本文件的「诊断只走 err_line」门禁把测试代码也算语料。
            println!("SKIP：当前盘根没有带子目录的目录，UNC 通配反例未取证");
            return;
        };
        let pat = format!("\\\\{name}\\*");
        let (code, _out, err) = capture(None, || {
            let got = expand_glob_dirs(&pat, false);
            assert!(got.is_empty(), "UNC 通配被当作当前盘根相对路径展开: {got:?}");
            0
        });
        assert_eq!(code, 0);
        assert!(err.contains("UNC 通配"), "拒绝展开必须留可见诊断: {err}");

        let (_, _, err2) = capture(None, || {
            let _ = expand_glob_dirs(r"\\nas\share\folder", false);
            0
        });
        assert!(
            !err2.contains("UNC 通配"),
            "非通配 UNC 是合法路径，不许被这条守卫拒掉: {err2}"
        );
    }

    /// A1-M01/M02（v7.2 C06）：fileKeys 的 size/exists 三态出口与不可读计数必须保留。
    /// 源码形态断言：删掉任一出口，本条即红（最终数值由真机探针复核）。
    #[test]
    fn filekeys_unreadable_contract() {
        let src = include_str!("cleanup_scan.rs");
        assert!(
            src.contains("(\"skippedUnreadable\", st.unreadable_dirs.to_string())"),
            "fileKeys 少了不可读目录计数出口"
        );
        assert!(
            src.contains("if st.ok { st.total_size.to_string() } else { \"null\".to_string() }"),
            "fileKeys 的 size 在读失败时必须给 null"
        );
        assert!(src.contains("(\"exists\", if !st.ok"), "fileKeys 的 exists 在读失败时必须给 null");
        assert!(
            src.contains("(\"skippedUnreadable\", stats.unreadable_dirs.to_string())"),
            "pathPs 少了不可读目录计数出口"
        );
    }

    /// E5（2026-10-16）：规则表达式求值器的语义钉桩——src-tauri 的 `paths_scan` 已从自写
    /// 解析器改为委托本函数（同一判定两份实现正是 §5.16/N6 禁止的形态），这里是**唯一
    /// 实现**的规格；两侧此前均无直测，本用例把边界一次钉齐。
    #[test]
    fn resolve_rule_path_语义钉桩() {
        use super::resolve_rule_path;
        // 单引号字面量 + '' 转义
        assert_eq!(resolve_rule_path(r"'C:\Foo'").as_deref(), Some(r"C:\Foo"));
        assert_eq!(resolve_rule_path("'C:\\O''Brien'").as_deref(), Some("C:\\O'Brien"));
        // $env: 前缀大小写敏感（PS StartsWith 语义）；变量名可含字母数字与下划线
        assert_eq!(resolve_rule_path("$ENV:WINDIR"), None, "$ENV: 前缀必须拒");
        assert_eq!(resolve_rule_path("'a' + 'b'").as_deref(), Some("ab"));
        let w = std::env::var("WINDIR").unwrap_or_default();
        assert_eq!(
            resolve_rule_path("('a' + 'b') + $env:WINDIR").as_deref(),
            Some(format!("ab{w}").as_str()),
            "括号组 + 变量拼接"
        );
        // 未定义变量取空串（与 PowerShell 原生一致）：单独成表达式是 Some("")，
        // 由调用方按「空串不采（!resolved.is_empty()）」处理
        assert_eq!(resolve_rule_path("$env:TRIM_E5_NOT_SET_9f3a").as_deref(), Some(""));
        // 语法垃圾一律 None（fail-closed，不猜测）
        assert_eq!(resolve_rule_path("'a' 'b'"), None, "尾随残留必须拒");
        assert_eq!(resolve_rule_path("foo"), None);
        assert_eq!(resolve_rule_path(""), None);
        assert_eq!(resolve_rule_path("'unclosed"), None);
        // 深度上限 32：40 层必拒、5 层必放行（边界两侧各钉一条，不赌 off-by-one）
        assert_eq!(resolve_rule_path(&format!("{}'x'{}", "(".repeat(40), ")".repeat(40))), None, "深度超限应拒");
        assert_eq!(resolve_rule_path(&format!("{}'x'{}", "(".repeat(5), ")".repeat(5))).as_deref(), Some("x"), "常规嵌套应放行");
    }

    /// 2026-10-04 审计 §5.1：minAge 天文数字（minAgeDays > 20729 时 f64 as u64
    /// 饱和到 u64::MAX）不得 panic——改为饱和到 UNIX_EPOCH。panic 会从
    /// cleanup_execute 展开、发生在清单写盘之前，把可恢复删除变成不可恢复。
    #[test]
    fn min_age_cutoff_溢出饱和到epoch不panic() {
        let cutoff = min_age_cutoff(u64::MAX);
        assert_eq!(cutoff, std::time::UNIX_EPOCH, "溢出必须饱和到 epoch（门槛落在 1970 前 ⇒ 任何真实文件都判太新，宁可少删）");
        let normal = min_age_cutoff(3600);
        assert!(normal < std::time::SystemTime::now(), "常规秒数 cutoff 必须在过去");
        assert!(min_age_cutoff(0) <= std::time::SystemTime::now(), "0 秒 cutoff = 现在");
    }

    /// G-1（2026-10-07）：年龄护栏是**扫描/执行共用的唯一解析实现**，
    /// 这里钉住全部口径 —— 缺省轴、单轴换算、双声明取更严格、非法值 fail-closed。
    /// 任何一侧想「顺手」放宽删除面（比如把非法值按无护栏处理），先在这里红。
    #[test]
    fn age_guard_解析与判定口径() {
        // 轴解析：缺省 = mtime（G-1 明确禁止把缺省改成 ctime——旧条目命中集合必须不变）
        assert_eq!(parse_age_axis(None), Some(AgeAxis::Mtime));
        assert_eq!(parse_age_axis(Some("mtime")), Some(AgeAxis::Mtime));
        assert_eq!(parse_age_axis(Some("ctime")), Some(AgeAxis::Ctime));
        // 非法枚举（拼写近似 / 大小写 / 空串）一律 None：契约表枚举是字面量，不做模糊匹配
        assert_eq!(parse_age_axis(Some("birthtime")), None);
        assert_eq!(parse_age_axis(Some("Mtime")), None);
        assert_eq!(parse_age_axis(Some("")), None);

        // 无 minAge* 且无轴 ⇒ Off（既有口径：命中集合不变）
        assert_eq!(rule_age_guard(None, None, None), AgeGuard::Off);
        // 单声明换算（minAgeDays = 24h 的整数倍；轴上到护栏）
        assert!(matches!(
            rule_age_guard(Some(24.0), None, None),
            AgeGuard::On { axis: AgeAxis::Mtime, .. }
        ));
        assert!(matches!(
            rule_age_guard(None, Some(7.0), Some("ctime")),
            AgeGuard::On { axis: AgeAxis::Ctime, .. }
        ));
        // 双声明：门禁 A9 判红；运行期取**更严格**（2 天 > 24 小时）——宁可少删，
        // 且绝不能退化成 Off（旧扫描侧就是按「无护栏」处理，那是 G-1 消灭掉的分叉）
        match rule_age_guard(Some(24.0), Some(2.0), None) {
            AgeGuard::On { cutoff, .. } => assert!(
                cutoff <= min_age_cutoff(2 * 86400),
                "双声明必须取更严格的那个（门槛必须不晚于 2 天前）"
            ),
            other => panic!("双声明应得到 On（取更严格），实际 {other:?}"),
        }
        // 非法值一律 Invalid（fail-closed）：不许「读不懂 ⇒ 无护栏 ⇒ 照删」
        assert_eq!(rule_age_guard(Some(-1.0), None, None), AgeGuard::Invalid);
        assert_eq!(rule_age_guard(None, Some(0.0), None), AgeGuard::Invalid);
        assert_eq!(rule_age_guard(None, Some(f64::NAN), None), AgeGuard::Invalid);
        assert_eq!(rule_age_guard(None, None, Some("ctime")), AgeGuard::Invalid);
        assert_eq!(rule_age_guard(None, Some(7.0), Some("birthtime")), AgeGuard::Invalid);
    }

    /// G-1 fail-closed 判定本体：时间戳缺失/未来一律「太新」；护栏非法全拒；
    /// 「元数据读不到」按护栏有无分开（无护栏维持既有口径）。
    #[test]
    fn age_guard_判定本体_fail_closed() {
        let now = std::time::SystemTime::now();
        let ten_days_ago = now - std::time::Duration::from_secs(10 * 86400);
        let future = now + std::time::Duration::from_secs(3600);
        let guard = rule_age_guard(None, Some(7.0), None);
        assert!(guard.old_enough_at(Some(ten_days_ago)), "10 天前必须够老");
        assert!(!guard.old_enough_at(Some(now)), "刚写入必须判太新");
        assert!(!guard.old_enough_at(None), "时间戳读不到必须判太新（fail-closed）");
        assert!(!guard.old_enough_at(Some(future)), "时间戳在未来必须判太新（fail-closed）");
        // 无护栏：不过时间（既有口径）
        assert!(AgeGuard::Off.old_enough_at(Some(now)));
        assert!(AgeGuard::Off.old_enough_at(None));
        // 非法护栏：任何时间戳都不放行
        assert!(!AgeGuard::Invalid.old_enough_at(Some(ten_days_ago)));
        // 元数据读不到时的出口：有护栏按太新，无护栏维持既有口径
        assert!(!guard.old_enough_when_missing());
        assert!(!AgeGuard::Invalid.old_enough_when_missing());
        assert!(AgeGuard::Off.old_enough_when_missing());
    }

    /// G-1：扫描侧字段抽取（studjson::Json → 共享解析）必须认 ageAxis，
    /// 且缺省/非法取值与共享函数同结论（适配层不得再写一套判断）。
    #[test]
    fn rule_age_guard_of_识别年龄轴三字段() {
        let obj = |fields: Vec<(&str, Json)>| {
            Json::Obj(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
        };
        let r = obj(vec![("minAgeDays", Json::Num(7.0))]);
        assert!(matches!(rule_age_guard_of(&r, None), AgeGuard::On { axis: AgeAxis::Mtime, .. }), "缺省轴必须按 mtime");
        let r = obj(vec![("minAgeDays", Json::Num(7.0)), ("ageAxis", Json::Str("ctime".into()))]);
        assert!(matches!(rule_age_guard_of(&r, None), AgeGuard::On { axis: AgeAxis::Ctime, .. }), "声明 ctime 必须走创建时间");
        let r = obj(vec![("minAgeDays", Json::Num(7.0)), ("ageAxis", Json::Str("birthtime".into()))]);
        assert_eq!(rule_age_guard_of(&r, None), AgeGuard::Invalid, "非法轴必须与共享函数同判 Invalid");
        let r = obj(vec![("id", Json::Str("x".into()))]);
        assert_eq!(rule_age_guard_of(&r, None), AgeGuard::Off, "无 minAge* 必须是无护栏");
        // G-2：全局阈值只在规则**自己声明了** minAge* 时并上去，且只收紧
        let r = obj(vec![("minAgeDays", Json::Num(3.0))]);
        match rule_age_guard_of(&r, Some(14)) {
            AgeGuard::On { secs, .. } => assert_eq!(secs, 14 * 86_400, "全局阈值更大时必须由它生效"),
            other => panic!("应仍是 On，实际 {other:?}"),
        }
        match rule_age_guard_of(&r, Some(1)) {
            AgeGuard::On { secs, .. } => assert_eq!(secs, 3 * 86_400, "全局阈值更小时规则阈值生效（不放宽）"),
            other => panic!("应仍是 On，实际 {other:?}"),
        }
        assert_eq!(rule_age_guard_of(&obj(vec![("id", Json::Str("x".into()))]), Some(14)), AgeGuard::Off,
            "没声明 minAge* 的规则不因全局策略被加上护栏");
    }

    /// G-2（2026-10-07）：全局年龄策略只收紧不放宽，且三条边界都要成立。
    #[test]
    fn global_min_age_only_tightens() {
        let rule_guard = rule_age_guard(None, Some(3.0), None);
        let secs_of = |g: AgeGuard| match g {
            AgeGuard::On { secs, .. } => secs,
            other => panic!("期望 On，实际 {other:?}"),
        };
        assert_eq!(secs_of(rule_guard), 3 * 86_400);
        // 关闭（None / 0）：规则阈值原样生效 —— 「关闭 = 不覆盖」，不是「取消护栏」
        assert_eq!(secs_of(rule_guard.tighten(None)), 3 * 86_400);
        assert_eq!(secs_of(rule_guard.tighten(Some(0))), 3 * 86_400);
        // 全局更小 ⇒ 规则阈值生效（只收紧，决不放宽）
        assert_eq!(secs_of(rule_guard.tighten(Some(1))), 3 * 86_400);
        // 全局更大 ⇒ 全局阈值生效
        assert_eq!(secs_of(rule_guard.tighten(Some(14))), 14 * 86_400);
        assert_eq!(secs_of(rule_guard.tighten(Some(30))), 30 * 86_400);
        // Off / Invalid 不因全局策略改变（Off 不加护栏；Invalid 已是最严）
        assert_eq!(AgeGuard::Off.tighten(Some(30)), AgeGuard::Off);
        assert_eq!(AgeGuard::Invalid.tighten(Some(30)), AgeGuard::Invalid);
        // ctime 轴在收紧后必须保留（别在被 tighten 时丢轴）
        match rule_age_guard(None, Some(1.0), Some("ctime")).tighten(Some(30)) {
            AgeGuard::On { axis, .. } => assert_eq!(axis, AgeAxis::Ctime, "收紧不得把轴改回 mtime"),
            other => panic!("期望 On，实际 {other:?}"),
        }
    }

    /// G-2：策略文件文本的解析口径 —— 空文件 = 关闭，非法值 = 关闭（不是「无护栏」）。
    #[test]
    fn global_min_age_file_text_shapes() {
        assert_eq!(parse_global_min_age(""), None, "空文件 = 关闭");
        assert_eq!(parse_global_min_age("   \r\n"), None, "只有空白 = 关闭");
        assert_eq!(parse_global_min_age("14\r\n"), Some(14));
        assert_eq!(parse_global_min_age("\r\n30\r\n"), Some(30), "跳过空行取第一行非空");
        assert_eq!(parse_global_min_age("0"), None, "0 视为关闭（不覆盖规则阈值）");
        assert_eq!(parse_global_min_age("-7"), None, "负值 = 关闭，不得放宽删除面");
        assert_eq!(parse_global_min_age("abc"), None);
        assert_eq!(parse_global_min_age("14.5"), None, "小数不认（档位是整数天）");
    }

    use super::*;

    /// 2026-10-04 磁盘清理审计 §3.2：诊断通道不许有第二出口。
    ///
    /// 判据是**结构性**的而不是「某条诊断出现了没」：扫描侧任何面向人的留痕
    /// 都必须经 `err_line` 进内存捕获，Tauri 侧才拿得到。写 `eprintln!` 的话，
    /// 字会打到进程真实 stderr，而 GUI 子系统进程没有控制台 —— 字直接蒸发，
    /// 引擎「已按规则降级并留痕」的承诺落空，而且**不报任何错**。
    ///
    /// 这条之所以能机械复核：`native-scanner/tests/` 不并 workspace（AGENTS §5.11），
    /// 主仓 `cargo test` 跑不到本文件，只有 `node tools/check-scan-rule-diff.mjs`
    /// 包着跑 —— 所以断言必须写在这里，不能指望别的门禁顺手发现。
    ///
    /// ⚠️ **自指 `include_str!` 的重编陷阱**（实测踩了两次）：本用例读的就是本文件，
    /// 改完源码后 cargo 偶发沿用旧内容 ⇒ 明明改对了却报红。判红前若与源码对不上，
    /// 先 `(Get-Item src/cleanup_scan.rs).LastWriteTime = Get-Date` 强制重编再下结论。
    #[test]
    fn 诊断只走_err_line_不许有第二出口() {
        let src = include_str!("cleanup_scan.rs");
        // 剥注释后扫：`eprintln!` 在本文件只应剩 err_line 自己那一个 fallback。
        let no_comments: String = {
            let mut out = String::with_capacity(src.len());
            let mut rest = src;
            loop {
                let b = rest.find("/*");
                let l = rest.find("//");
                match (b, l) {
                    (Some(bi), Some(li)) if bi < li => {
                        out.push_str(&rest[..bi]);
                        match rest[bi..].find("*/") {
                            Some(e) => {
                                out.push_str(&rest[bi..bi + e + 2].replace(|c: char| c != '\n', " "));
                                rest = &rest[bi + e + 2..];
                            }
                            None => {
                                out.push_str(&rest[bi..].replace(|c: char| c != '\n', " "));
                                break;
                            }
                        }
                    }
                    (_, Some(li)) => {
                        out.push_str(&rest[..li]);
                        match rest[li..].find('\n') {
                            Some(e) => {
                                out.push_str(&rest[li..li + e].replace(|c: char| c != '\n', " "));
                                out.push('\n');
                                rest = &rest[li + e + 1..];
                            }
                            None => {
                                out.push_str(&rest[li..].replace(|c: char| c != '\n', " "));
                                break;
                            }
                        }
                    }
                    _ => {
                        out.push_str(rest);
                        break;
                    }
                }
            }
            out
        };
        // needle 动态拼：本测试自己的代码里也会出现那个词，静态字面量会把
        // 测试自己算成违规（第一版就这么假红了一次）。
        let needle = format!("eprint{}n!", "l");
        let hits: Vec<&str> = no_comments.lines().filter(|l| l.contains(needle.as_str())).collect();
        // 唯一允许的一处是 err_line 自己的非捕获分支 fallback。
        assert_eq!(
            hits.len(),
            1,
            "扫描侧诊断出现第二出口（直接打印到进程 stderr）：\n{}\n\
             必须走 err_line —— Tauri 走 run_json 捕获模式，GUI 子系统进程没有控制台，\
             直接打印的字会蒸发且不报错（审计 §3.2）",
            hits.join("\n")
        );
        assert!(
            hits[0].contains("line"),
            "剩下的唯一直接打印不在 err_line 的 fallback 里：{}",
            hits[0]
        );
        // 正向对照：引擎真的在用 err_line 记「变量未解析」这条关键降级
        assert!(
            no_comments.contains("err_line(&format!(\"[cleanup-scan]"),
            "引擎已不再用 err_line 记降级留痕 —— §3.2 依赖的那条通道被搬走了"
        );
    }

    /// 审查 L-9：超过 scan::MAX_WALK_DEPTH 的病态深嵌套不再下钻（防递归栈溢出）。
    /// 造 70 层嵌套、最深处放匹配文件：扫描必须正常返回，且只收浅层文件。
    #[test]
    fn walk_deletable_深度超限不再下钻() {
        let root = std::env::temp_dir().join(format!("trim-depth-del-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut deep = root.clone();
        for i in 0..70 {
            deep = deep.join(format!("d{i}"));
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("deep.tmp"), b"x").unwrap();
        fs::write(root.join("shallow.tmp"), b"x").unwrap();

        let mut res = DeletableResult {
            files: Vec::new(),
            total: 0,
            deletable_count: 0,
            deletable_bytes: 0,
            skipped_reparse: 0,
            unreadable_dirs: 0,
            files_truncated: false,
        };
        walk_deletable(&root, true, "*.tmp", AgeGuard::Off, &[], &[], None, &mut res, 0, true, None, None);
        assert_eq!(res.files.len(), 1, "浅层文件必须收到：{:?}", res.files);
        assert!(
            res.files.iter().all(|(p, _, _)| !p.contains("d69")),
            "超限深处的文件不得出现：{:?}", res.files
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// 2026-10-04 磁盘清理审计 §3.3：统计路径与列表路径**口径必须恒等**。
    ///
    /// 这条是 §3.3 那次改动的核心风险：`get_path_deletable_stats` 改成读
    /// `deletable_count`/`deletable_bytes` 而不是 `files.len()`/`sum()`。
    /// 两个数据源一旦漂移，用户看到的就是「列表里 N 个文件、体积统计却是 M」，
    /// 会被读成扫描漏项 —— 而这正是审计里那条「静默失效」的同族。
    #[test]
    fn 统计口径与列表口径逐项恒等() {
        let root = std::env::temp_dir().join(format!("trim-stats-parity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sub")).unwrap();
        for (name, body) in [
            ("a.tmp", b"aaaa".as_slice()),
            ("sub/b.tmp", b"bb".as_slice()),
            ("sub/c.log", b"cccccccc".as_slice()),
            ("d.txt", b"d".as_slice()),
        ] {
            fs::write(root.join(name), body).unwrap();
        }

        // pattern='*' 覆盖全部（统计口径固定用这个）
        let with_files = list_deletable(root.to_str().unwrap(), "*", AgeGuard::Off, &[], &[], None);
        let stats_only = list_deletable_stats(root.to_str().unwrap(), "*", AgeGuard::Off, &[], &[], None);

        assert_eq!(
            stats_only.deletable_count, with_files.files.len() as u64,
            "可删个数口径漂移：列表 {} vs 统计 {}",
            with_files.files.len(),
            stats_only.deletable_count
        );
        assert_eq!(
            stats_only.deletable_bytes,
            with_files.files.iter().map(|f| f.1).sum::<u64>(),
            "字节和口径漂移：列表 {} vs 统计 {}",
            with_files.files.iter().map(|f| f.1).sum::<u64>(),
            stats_only.deletable_bytes
        );
        assert_eq!(stats_only.total, with_files.total, "total 口径漂移");
        assert_eq!(stats_only.skipped_reparse, with_files.skipped_reparse, "reparse 留痕漂移");

        // 本次改动的**全部意义**在这一条：统计模式不得持有任何路径
        assert!(
            stats_only.files.is_empty(),
            "统计模式竟仍持有 {} 条路径 —— §3.3 的改动没生效",
            stats_only.files.len()
        );
        // 反向：列表模式必须仍拿得到路径（不能为了省内存把功能改没了）
        assert_eq!(with_files.files.len(), 4, "列表模式必须仍返回全部路径");

        let _ = fs::remove_dir_all(&root);
    }

    /// 目录型（pathPs）收集模式：必须出逐文件清单 + 与 size **同源**的出生时间，
    /// 且 PLAN_CAP 施加在枚举当场（size 仍全量、只有清单停）。
    ///
    /// 为什么要这条（2026-10-23）：pathPs 支历史上只回聚合 size，`items[].files` 恒空
    /// ⇒ 引擎 Kudu S2 的身份证表对这些条目完全不生效（护栏静默失效、方向是放行），
    /// 主进程的跨条目去重也只能按根前缀反查、把子条的字节整段扣给父条。
    /// 判红自证：① 把收集模式的 `collect_files` 传回 false ⇒ 第一条断言红；
    /// ② 把 `cap` 去掉 ⇒ 截断断言红；③ 出生时间改成再读一次 metadata 之外的口径 ⇒ 第三条红。
    #[test]
    fn 目录型收集模式出清单与身份证基线() {
        let root = std::env::temp_dir().join(format!("trim-ps-collect-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sub")).unwrap();
        for (name, body) in [
            ("a.bin", b"aaaa".as_slice()),
            ("sub/b.bin", b"bb".as_slice()),
            ("c.bin", b"ddd".as_slice()),
        ] {
            fs::write(root.join(name), body).unwrap();
        }
        let p = root.to_str().unwrap();

        // 统计模式口径必须一字不变（§3.3 那份约束不因物化而漂）
        let stat = get_path_deletable_stats(p, AgeGuard::Off, None, false, None);
        assert!(stat.ok && stat.files.is_empty() && !stat.files_truncated, "统计模式被改成持有路径");
        assert_eq!(stat.size, 4 + 2 + 3, "size 必须是全量字节和");
        assert_eq!(stat.nfiles, 3);

        // 收集模式：cap 给足 ⇒ 三条全出，且每条带与 size 同一次 metadata 的出生时间
        let full = get_path_deletable_stats(p, AgeGuard::Off, None, true, Some(10));
        assert!(full.ok, "收集模式必须与统计模式同判成功");
        assert_eq!(full.files.len(), 3, "清单必须收全：{:?}", full.files);
        assert!(!full.files_truncated, "未超预算不该标截断");
        assert_eq!(full.size, 9, "开收集模式后 size 口径不得变");
        for (path, size, bt) in &full.files {
            let m = fs::metadata(path).unwrap_or_else(|_| panic!("清单里的路径必须还在盘上: {path}"));
            assert_eq!(*size, m.len(), "逐文件字节与 metadata 不符: {path}");
            assert!(*bt > 0, "出生时间为 0 = 无身份证基线，护栏会静默失效: {path}");
            let exact = m
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
                .unwrap_or(0);
            assert_eq!(*bt, exact, "身份证基线必须与现读逐位相等（折位即整批拒删）: {path}");
        }

        // 预算施加在枚举当场：超出的文件不进清单，但 size/nfiles 仍按全量
        let capped = get_path_deletable_stats(p, AgeGuard::Off, None, true, Some(2));
        assert_eq!(capped.files.len(), 2, "清单必须停在 cap");
        assert!(capped.files_truncated, "超预算必须外发截断位，否则用户看不见「清单比实际少」");
        assert_eq!(capped.size, 9, "截断只影响清单，体积不许跟着谎报");
        assert_eq!(capped.nfiles, 3, "截断只影响清单，个数不许跟着谎报");

        // 预算为 0（跨条目 PLAN_CAP_TOTAL 耗尽的形状）：一条都不出，但必须标截断
        let zero = get_path_deletable_stats(p, AgeGuard::Off, None, true, Some(0));
        assert!(zero.files.is_empty() && zero.files_truncated && zero.size == 9, "零预算必须「空清单 + 截断 + 全量 size」三件齐");

        let _ = fs::remove_dir_all(&root);
    }

    /// detect 回退链的候选档（2026-10-23）：`pathPs:"''"` 是「无固定根、靠候选自动发现」的
    /// 空位占位（现算全库唯一一条 `wechatCache`），旧回退链走到 `path_exists("")` 就判不存在
    /// ⇒ 整条规则在 `test_rule_detect` 被 continue、候选再真也永不生效。
    /// 判红自证：① 删掉空串那一支的 `detect_by_candidates` 调用 ⇒ 第一条红（规则仍整条死）；
    /// ② 把候选档放宽成「有候选就命中」⇒ 第二条红（不许假复活成「恒显示、执行 0 删」）。
    #[test]
    fn detect_空路径条目改走候选存在性回退() {
        let root = std::env::temp_dir().join(format!("trim-detect-cand-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let here = root.to_str().unwrap().to_string();
        let q = |s: &str| Json::Str(format!("'{}'", s));
        let arr = |v: Vec<Json>| Json::Arr(v);
        let obj = |fields: Vec<(&str, Json)>| Json::Obj(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect());

        // ① 候选真实存在 ⇒ 命中（glob 形态与静态形态各一条）
        let by_glob = obj(vec![
            ("id", Json::Str("probe-glob".into())),
            ("pathPs", Json::Str("''".into())),
            ("globCandidatesPs", arr(vec![q(&format!(r"{}\sub*", here))])),
        ]);
        fs::create_dir_all(root.join("subdir")).unwrap();
        assert!(test_rule_detect(&by_glob), "候选（通配）真实存在时 detect 必须命中，否则整条规则永远隐身");
        let by_static = obj(vec![
            ("id", Json::Str("probe-static".into())),
            ("pathPs", Json::Str("''".into())),
            ("candidatesPs", arr(vec![q(&here)])),
        ]);
        assert!(test_rule_detect(&by_static), "候选（静态）存在时同样必须命中");

        // ② 候选都不存在 ⇒ 不命中（放宽就变成「恒显示、执行 0 删」那个老形状）
        let miss = obj(vec![
            ("id", Json::Str("probe-miss".into())),
            ("pathPs", Json::Str("''".into())),
            ("candidatesPs", arr(vec![q(&format!(r"{}\NoSuchDir", here))])),
            ("globCandidatesPs", arr(vec![q(&format!(r"{}\NoSuchGlob\*", here))])),
        ]);
        assert!(!test_rule_detect(&miss), "候选全不存在时不得命中");

        // ③ 空路径又没有任何候选 ⇒ 不命中（不替它编一个「恒命中」）
        let naked = obj(vec![
            ("id", Json::Str("probe-naked".into())),
            ("pathPs", Json::Str("''".into())),
        ]);
        assert!(!test_rule_detect(&naked), "既无指向又无发现方式时必须不命中");

        // ④ 正向对照：pathPs 非空时仍按它自己的存在性判，候选档不许插一手
        let normal_hit = obj(vec![
            ("id", Json::Str("probe-normal".into())),
            ("pathPs", q(&here)),
        ]);
        assert!(test_rule_detect(&normal_hit), "正常 pathPs 命中路径即命中");
        let normal_miss = obj(vec![
            ("id", Json::Str("probe-normal-miss".into())),
            ("pathPs", q(&format!(r"{}\NoSuchDir", here))),
            ("candidatesPs", arr(vec![q(&here)])),
        ]);
        assert!(!test_rule_detect(&normal_miss), "pathPs 非空却不存在时，不得靠候选把它救活（那是另一条规则的根）");

        let _ = fs::remove_dir_all(&root);
    }
    #[test]
    fn walk_fk_dll_深度超限不再下钻() {
        let root = std::env::temp_dir().join(format!("trim-depth-fk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut deep = root.clone();
        for i in 0..70 {
            deep = deep.join(format!("d{i}"));
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("deep.dll"), b"x").unwrap();
        fs::write(root.join("shallow.dll"), b"x").unwrap();

        let mut acc = FkAcc::new(0);
        walk_fk_dll(&root, true, "*.dll", true, AgeGuard::Off, &[], &[], None, &mut acc, 0, None);
        assert_eq!(acc.files.len(), 1, "浅层文件必须收到：{:?}", acc.files);
        assert!(
            acc.files.iter().all(|(p, _, _)| !p.contains("d69")),
            "超限深处的文件不得出现：{:?}", acc.files
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// 2026-10-04 磁盘清理审计 §3.4：遍历预算耗尽后**真的不再下钻**。
    ///
    /// 判据用「`total_count` 停在上限附近」而不是「`files.len()` 等于上限」——
    /// 后者在修复前也成立（`push_budget` 只让输出停在上限，遍历照旧继续），
    /// 所以它压根区分不出修没修。`total_count` 是**遍历量**的口径：撞上限后
    /// 立刻 return，剩下那棵树一个文件都不再 `metadata()`，它必须停在上限附近。
    ///
    /// 用 `max_item_rows=3` 而不是生产常量 10 万：这条要能在 CI 里跑完，
    /// 而它验的是「早退有没有发生」，与上限值无关（`push_budget` 的比较是
    /// `>=`，换成参数只是把阈值挪到能测的量级）。
    #[test]
    fn 遍历预算耗尽后不再下钻() {
        // 造一棵够深够宽的树：3 层 × 每层 8 个子目录 × 每个 4 个文件
        let root = std::env::temp_dir().join(format!("trim-walk-budget-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut dirs = vec![root.clone()];
        for level in 0..3 {
            let mut next = Vec::new();
            for d in &dirs {
                for i in 0..8 {
                    let sub = if level == 0 { d.clone() } else { d.join(format!("l{i}")) };
                    fs::create_dir_all(&sub).unwrap();
                    for f in 0..4 {
                        fs::write(sub.join(format!("f{f}.tmp")), b"x").unwrap();
                    }
                    next.push(sub);
                }
            }
            dirs = next;
            if dirs.len() > 64 {
                break;
            }
        }
        let total_files: usize = dirs.len() * 4;
        assert!(total_files > 50, "夹具太小，撞不到 3 的上限: {total_files}");

        // DLL 分支：把条目上限压到 3（生产是 10 万，跑不出来；见 item_cap 字段注释）
        let mut acc = FkAcc::new(0);
        acc.item_cap = 3;
        acc.global_cap = 3;
        walk_fk_dll(&root, true, "*.tmp", true, AgeGuard::Off, &[], &[], None, &mut acc, 0, None);
        assert!(acc.truncated, "撞上限必须标 truncated（否则界面不显示「已截断」）");
        assert_eq!(acc.files.len(), 3, "输出必须停在上限");
        assert!(
            acc.total_count <= 12,
            "遍历量必须远小于夹具的 {total_files} 个文件 —— \
             §3.4 未修的话这里会是 {total_files}（输出停在 3、遍历照旧走完整棵树）。实测 {}",
            acc.total_count
        );

        // 快照分支：同一棵树，同一断言
        let mut acc2 = FkAcc::new(0);
        acc2.item_cap = 3;
        acc2.global_cap = 3;
        walk_fk_snapshot(&root, true, "*.tmp", true, 0, AgeGuard::Off, &[], &[], None, true, &mut acc2, None);
        assert!(acc2.truncated, "快照分支撞上限必须标 truncated");
        assert_eq!(acc2.files.len(), 3, "快照分支输出必须停在上限");
        assert!(
            acc2.total_count <= 12,
            "快照分支遍历量必须远小于 {total_files}，实测 {}",
            acc2.total_count
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// 2026-10-04 审计 §4.9：分类器三态直测（目录→前缀表 / 文件→精确表 /
    /// 不存在→两表都进）。集成差分用例（tests/cleanup_scan_rule_diff.rs）钉接线，
    /// 本条钉三态语义本身——含「不存在两表都进」这个集成用例造不出来的形态。
    #[test]
    fn exclude_paths_分类器按实况分三态() {
        let root = std::env::temp_dir().join(format!("trim-excl-class-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("Vendor.Tool")).unwrap();
        fs::write(root.join("plain.log"), b"x").unwrap();

        // 带点**目录**：进前缀表
        let mut dirs: Vec<String> = Vec::new();
        let mut files: Vec<String> = Vec::new();
        let dot_dir = root.join("Vendor.Tool").to_string_lossy().to_lowercase();
        classify_exclude_entry(&dot_dir, &mut dirs, &mut files);
        assert!(dirs.contains(&dot_dir) && files.is_empty(), "带点目录必须进目录表: {dirs:?} / {files:?}");

        // 真**文件**：进精确表
        dirs.clear();
        files.clear();
        let file = root.join("plain.log").to_string_lossy().to_lowercase();
        classify_exclude_entry(&file, &mut dirs, &mut files);
        assert!(files.contains(&file) && dirs.is_empty(), "文件必须进文件表: {dirs:?} / {files:?}");

        // **不存在**的条目：两表都进——两类物态各自有覆盖，排除面扩大的失败方向是「少删」
        dirs.clear();
        files.clear();
        let ghost = root.join("no.such.thing").to_string_lossy().to_lowercase();
        classify_exclude_entry(&ghost, &mut dirs, &mut files);
        assert!(
            dirs.contains(&ghost) && files.contains(&ghost),
            "不存在的条目必须两表都进（物态未定前不许押单边）: {dirs:?} / {files:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// 性能优化 P1-A（v3 §5.2）的**等价前提证明**：枚举出口的短名前置短路要成立，
    /// 必须 `to_long_path`（=`GetLongPathNameW`）对「已是长名的绝对路径」是**恒等**——
    /// 该出口产出的 PLANFILE 喂给 PS 执行侧的保护闸，两侧字符串必须同口径
    ///（v3.7.2 P3 双引擎对拍结论），出口字符串漂一点就是保护面判漂移。
    ///
    /// 覆盖形状：大小写混写、中文、空格、含 `~` 但不跟数字（字面名）、多级深、超长名。
    /// 另附一条**取证而非断言**：相对输入 `.` 会不会被展开成绝对路径——
    /// 答案是会（打印出来），所以短路条件里加了 `is_absolute()`，不是可有可无的保险。
    #[test]
    #[ignore = "真机：需要落盘样本并触盘，非回归判据，复核该短路时手动 --ignored 跑"]
    fn to_long_path_对真实_planfile_形状恒等() {
        #[cfg(windows)]
        {
            // 夹具基目录必须先取长名。本机实测：`std::env::temp_dir()` 返回
            // `C:\Users\ADMINI~1\AppData\Local\Temp`——用户目录名本身就是 8.3 短名，
            // 直接拿它拼样本会让**每个**路径都被短名判据命中、全部走展开分支，
            // 恒等断言一次也跑不到（本探针第一版就是这样 checked=0 而判红的）。
            // 反过来这也证明短路条件没选错：含短名的路径确实存在于真实机器上，而它们照常被展开。
            let base = crate::to_long_path(&std::env::temp_dir().to_string_lossy());
            if crate::contains_short_name(&base) {
                println!("SKIP：本机临时目录展开后仍含短名（{base}），无法取恒等样本，本节未校验");
                return;
            }
            let dir = Path::new(&base).join(format!("trim-longpath-{}", std::process::id()));
            // 刻意不做「建之前先删」：目录名含进程 id、天然唯一，多余的一次删除原语调用
            // 只会让 check-delete-callsites 的棘轮白涨（那条门禁的方向就是删除出口只减不增）。
            fs::create_dir_all(&dir).expect("建沙箱目录");
            let deep = format!("深层目录{}", "层".repeat(24));
            let names = [
                "Plain.txt",
                "MIXEDcase.txt",
                "中文文件.txt",
                "With Space.txt",
                "tilde~name.txt",
                "a.b.c.d.txt",
                &deep,
            ];
            let mut checked = 0usize;
            let mut skipped_by_pred = 0usize;
            for n in names {
                let p = dir.join(n);
                fs::write(&p, b"x").expect("写样本");
                let s = p.to_string_lossy().to_string();
                assert!(Path::new(&s).is_absolute(), "夹具必须是绝对路径: {s}");
                if crate::contains_short_name(&s) {
                    // 判据说"该展开" ⇒ 走原分支，不属恒等断言范围
                    skipped_by_pred += 1;
                    continue;
                }
                let got = crate::to_long_path(&s);
                assert_eq!(
                    got, s,
                    "to_long_path 必须对该长名绝对路径恒等；出口字符串一改就动了 PS 侧保护闸的输入"
                );
                checked += 1;
            }
            assert!(checked >= 5, "恒等样本不足（checked={checked}），本探针未覆盖该形状");

            // 取证：相对输入是否被改写（这决定短路条件里的 is_absolute 是否多余）
            let rel = ".".to_string();
            let got_rel = crate::to_long_path(&rel);
            println!(
                "相对输入 {rel:?} 经 to_long_path = {got_rel:?} —— 恒等? {}",
                got_rel == rel
            );
            println!("恒等断言通过 {checked} 例，判据命中而走展开分支 {skipped_by_pred} 例");
            let _ = fs::remove_dir_all(&dir);
        }
        #[cfg(not(windows))]
        {
            // 刻意用 println! 而非 eprintln!：本文件的 `诊断只走_err_line_不许有第二出口`
            // 判据剥注释后按行数 eprintln!，生产侧只许 err_line 那一个 fallback。
            // cfg 分支不删源码文本，写 eprintln! 会被算成第二出口而判红（实测过）。
            println!("SKIP：本探针只在 Windows 上有意义（GetLongPathNameW 是 Win 侧 API）");
        }
    }

    /// 性能优化 P1 前置实测（v2 §三对 `file_deletable` 的原话是「修法须先量」）。
    ///
    /// 造 N 个真实小文件，分别计时 ① 只 `fs::metadata`、② 独占 open + close、
    /// ③ open + metadata + close（现实现）、④ ③ 的 rayon 并行版。只出数，不改判据：
    /// 数不出来「值得改」就不动手（AGENTS §4.1：没实测的收益不算收益）。
    #[test]
    #[ignore = "真机实测：落 3000 个磁盘文件并计时，非回归判据，取数时手动 --ignored 跑"]
    fn file_deletable_独占打开成本实测() {
        use std::time::Instant;
        const N: usize = 3000;
        let root = std::env::temp_dir().join(format!("trim-fd-probe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let mut paths = Vec::with_capacity(N);
        for i in 0..N {
            let p = root.join(format!("f{:05}.tmp", i));
            fs::write(&p, b"x").unwrap();
            paths.push(p);
        }

        let t0 = Instant::now();
        let mut hit = 0usize;
        for p in &paths {
            if fs::metadata(p).is_ok() {
                hit += 1;
            }
        }
        let stat = t0.elapsed();

        let t0 = Instant::now();
        for p in &paths {
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                if let Ok(_f) = fs::OpenOptions::new().read(true).share_mode(0).open(p) {
                    hit += 1;
                }
            }
            #[cfg(not(windows))]
            {
                if fs::File::open(p).is_ok() {
                    hit += 1;
                }
            }
        }
        let open_only = t0.elapsed();

        let t0 = Instant::now();
        for p in &paths {
            if super::file_deletable(p) {
                hit += 1;
            }
        }
        let current = t0.elapsed();

        let t0 = Instant::now();
        use rayon::prelude::*;
        let par = paths
            .par_iter()
            .filter(|p| super::file_deletable(p))
            .collect::<Vec<_>>();
        hit += par.len();
        let parallel = t0.elapsed();

        // 参照：同一个目录树的 read_dir 枚举本身要花多久（扫描的真实大头）
        let t0 = Instant::now();
        let entries = fs::read_dir(&root).map(|r| r.count()).unwrap_or(0);
        let readdir = t0.elapsed();

        let per = |d: std::time::Duration| d.as_micros() as f64 / N as f64;
        println!(
            "file_deletable 实测 N={N} 命中={hit} 目录枚举={entries}\n\
             ① 只 metadata      总 {:>9.1}ms  每文件 {:>6.1}µs\n\
             ② open+close      总 {:>9.1}ms  每文件 {:>6.1}µs\n\
             ③ 现实现(含 md)   总 {:>9.1}ms  每文件 {:>6.1}µs\n\
             ④ ③的并行版      总 {:>9.1}ms  每文件 {:>6.1}µs\n\
             参照 read_dir 一次 总 {:>9.1}ms\n\
             外推 1 万文件：③ {:>7.1}ms / ④ {:>7.1}ms",
            stat.as_secs_f64() * 1e3, per(stat),
            open_only.as_secs_f64() * 1e3, per(open_only),
            current.as_secs_f64() * 1e3, per(current),
            parallel.as_secs_f64() * 1e3, per(parallel),
            readdir.as_secs_f64() * 1e3,
            per(current) * 10000.0 / 1000.0,
            per(parallel) * 10000.0 / 1000.0,
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// 2026-10-23：单文件 fileKey（setupapi.dev.log / CatRoot2\dberr.txt 这类规则）必须
    /// 被扫到。旧实现拿文件路径喂 `walk_*`（目录遍历器），`read_dir` 报 os error 267
    /// 「目录名称无效」→ 条目恒 0 项，而执行侧单文件分支能删。
    /// 判红自证：删掉 `get_file_key_deletable` 里的单文件分支，count 立刻变 0。
    #[test]
    fn filekeys_单文件根必须进清单() {
        let root = std::env::temp_dir().join(format!("trim-fk-single-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let f = root.join("setupapi.dev.log");
        fs::write(&f, vec![b'x'; 1024]).unwrap();
        let file_s = f.to_string_lossy().replace('/', "\\");
        let rule = parse_json(&format!(
            r#"{{"id":"t","fileKeys":[{{"path":"{}"}}]}}"#,
            file_s.replace('\\', "\\\\")
        ))
        .unwrap();
        let st = get_file_key_deletable(&rule, &mut 0, None, None);
        assert_eq!(st.count, 1, "单文件根必须命中 1 项（旧实现恒 0）：{}", st.count);
        assert_eq!(st.files.len(), 1, "可删清单必须带上这个文件");
        assert!(st.files[0].0.ends_with("setupapi.dev.log"));
        assert_eq!(st.locked, 0, "未被占用的单文件不得记成 locked");
        // 反向对照：不存在的根仍按「根级 read_dir 失败」留痕，不许伪装成「有 1 项」
        let ghost = root.join("nope.log").to_string_lossy().replace('/', "\\");
        let rule2 = parse_json(&format!(
            r#"{{"id":"t","fileKeys":[{{"path":"{}"}}]}}"#,
            ghost.replace('\\', "\\\\")
        ))
        .unwrap();
        let st2 = get_file_key_deletable(&rule2, &mut 0, None, None);
        assert_eq!(st2.count, 0, "不存在的单文件根不得产出可删项");
        let _ = fs::remove_dir_all(&root);
    }

    /// 2026-10-23 扫描并行化：单个目录里几十个文件走并行探测，结果集必须与串行逐项
    /// 一致（数量、字节和、清单条数）。这里正向点名「全部命中」而不是「没报错」。
    #[test]
    fn 并行探测保持清单全集() {
        let root = std::env::temp_dir().join(format!("trim-par-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        const N: usize = 64;
        for i in 0..N {
            fs::write(root.join(format!("f{i:03}.tmp")), vec![b'x'; 10]).unwrap();
        }
        let rule = parse_json(&format!(
            r#"{{"id":"t","fileKeys":[{{"path":"{}"}}]}}"#,
            root.to_string_lossy().replace('\\', "\\\\")
        ))
        .unwrap();
        let st = get_file_key_deletable(&rule, &mut 0, None, None);
        assert_eq!(st.count, N as i64, "并行探测漏文件：{} != {N}", st.count);
        assert_eq!(st.files.len(), N, "可删清单必须与命中数一致");
        assert_eq!(st.total_size, (N * 10) as i64, "字节和必须与串行一致");
        assert_eq!(st.locked, 0, "普通临时文件不得记成 locked");
        let _ = fs::remove_dir_all(&root);
    }

    /// R10（2026-10-15）：保护清单按注入生效——把文件自身声明为 subtree 根，扫描侧必须
    /// 判不可删；同一文件不注入时必须可删（反向对照，防「过滤恒拒」假绿）。
    ///
    /// 注入根用 `crate::to_long_path` 展开后的小写形态：`%TEMP%` 可能是 8.3 短名
    /// （ADMINI~1），而判据侧先 `to_long_path` 再比对——两侧必须同一形态，否则这条
    /// 用例自己就会假红。
    #[test]
    fn 扫描侧保护过滤按注入清单生效() {
        let tmp = std::env::temp_dir().join(format!("trim-r10-inject-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join("probe.log");
        fs::write(&f, b"x").unwrap();

        let f_long = crate::to_long_path(&f.to_string_lossy()).to_lowercase();
        let injected = format!(
            "{{\"subtree\":[\"{}\"],\"exact\":[],\"anyDrive\":[],\"neverNames\":[]}}",
            f_long.replace('\\', "\\\\")
        );
        assert!(
            !scan_deletable(&f, Some(&injected)),
            "文件自身被注入为 subtree 根，扫描侧仍判可删 = 注入没生效"
        );
        assert!(
            scan_deletable(&f, None),
            "未注入时普通临时文件必须判可删（反向对照：防判据恒拒假绿）"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    /// R10 真机探针（`#[ignore]`，发版前实跑）：D2 受害面在**真实系统根**上的双向咬合——
    /// `System32\config` 是 protect 的 subtree 根，其下 `systemprofile\**` 必须被判不可删；
    /// 同一判据对普通临时文件必须放行（防「过滤过宽把一切都拒了」）。
    #[cfg(windows)]
    #[test]
    #[ignore = "真机探针：读真实 System32\\config 子树与真实临时文件"]
    fn 扫描侧保护过滤_真机探针() {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
        let victim = format!("{windir}\\System32\\config\\systemprofile\\AppData\\Local\\D3DSCache");
        assert!(
            !scan_deletable(Path::new(&victim), None),
            "System32\\config 子树必须被扫描侧判不可删（R10：此前零过滤、体积照报）: {victim}"
        );
        let tmp = std::env::temp_dir().join(format!("trim-r10-probe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join("probe.log");
        fs::write(&f, b"x").unwrap();
        assert!(
            scan_deletable(&f, None),
            "普通临时文件被保护过滤误拒 —— 判据过宽"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    /// P2-④ 的两态对照（可复跑）：捕获模式下 stdout 那份副本只按「有没有逐行回调」分岔。
    ///   · 无回调（CLI 的 `run` / `run_checklocked` / `checklocked_json`，以及对拍集成测试
    ///     `tests/cleanup_scan_rule_diff.rs` 走的 `run_json(.., None)`）：`out` 必须
    ///     **逐字节**等于「每行 + 换行」的拼接 —— `write_back` 吐出的字节因此一字未改；
    ///   · 有回调（生产路径 = `scan_execute.rs` 带 `Some(hook)`）：行逐条交付回调，
    ///     `out` 为空串，整程不再驻留一份没人读的全量副本。
    /// 三次捕获分别点名「全量」「逐条到达回调」「复位后照旧全量」，不靠「没报错」。
    #[test]
    fn 捕获带回调时不攒stdout副本而无回调逐字节照旧() {
        let lines = [
            "@@ITEM@@{\"id\":\"a\",\"files\":[]}",
            "@@PLANFILE@@{\"id\":\"a\",\"path\":\"C:\\\\tmp\",\"size\":1}",
            "@@LOCKED_DONE@@{\"scanned\":2,\"locked\":0}",
        ];
        let want: String = lines.iter().fold(String::new(), |mut acc, l| {
            acc.push_str(l);
            acc.push('\n');
            acc
        });

        // ① 无回调：out 全量，且与逐行拼接逐字节相同
        let (code, out, err) = capture(None, || {
            for l in lines.iter() {
                out_line(l);
            }
            0
        });
        assert_eq!(code, 0, "body 正常返回时退出码照旧");
        assert!(err.is_empty(), "本用例不写诊断，err 应为空：{err}");
        assert_eq!(out, want, "无回调形态的 stdout 必须逐字节照旧（CLI 的 write_back 依赖它）");

        // ② 有回调：每一行逐条到达回调，out 不再驻留副本
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = std::sync::Arc::clone(&got);
        let (code2, out2, _err2) = capture(
            Some(Box::new(move |l: &str| {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push(l.to_string());
            })),
            || {
                for l in lines.iter() {
                    out_line(l);
                }
                0
            },
        );
        assert_eq!(code2, 0);
        assert_eq!(
            got.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            lines.iter().map(|l| l.to_string()).collect::<Vec<String>>(),
            "回调必须逐条收到每一行（少一行就是丢了输出）"
        );
        assert!(
            out2.is_empty(),
            "带回调时 out 必须是空串（P2-④），实得长度 {}",
            out2.len()
        );

        // ③ 复位对照：紧接着一次无回调捕获必须照旧全量（thread_local 状态没被污染）
        let (code3, out3, _err3) = capture(None, || {
            out_line(lines[0]);
            0
        });
        assert_eq!(
            (code3, out3),
            (0, format!("{}\n", lines[0])),
            "capture 结束后必须复位，否则 CLI 路径会被连带改成不攒副本"
        );
    }

    /// v7.2-C03（N1a-M01）破坏自证：skip_lock（restartProcesses 声明）只豁免独占
    /// 探测，**不豁免 R10 保护闸**。受保护根下的文件即便声明 restartProcesses 也
    /// 不得进可删清单。破坏形态 = 恢复旧 `skip_lock || scan_deletable(..)` 短路
    ///（保护判据被整条旁路）⇒ deletable_count 变 1 ⇒ 本用例红。
    #[test]
    fn filekeys_skip_lock_不豁免保护闸() {
        let root = std::env::temp_dir().join(format!("trim-fk-prot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("victim.tmp"), b"x").unwrap();
        let root_s = root.to_string_lossy().replace('/', "\\");
        let root_key = root_s.to_lowercase();
        let root_key = root_key.trim_end_matches('\\').to_string();
        let protect = format!(
            r#"{{"subtree":["{}"],"exact":[],"anyDrive":[],"neverNames":[]}}"#,
            root_key.replace('\\', "\\\\")
        );
        // 注意：规则**不带 minAge***（AgeGuard::Off）——带 minAgeDays:0 会把 cutoff
        // 压到「现在」，新落盘的样本恒判太新 ⇒ 探针永不命中（假绿，P2-1 教训）。
        let rule = parse_json(&format!(
            r#"{{"id":"t","restartProcesses":["svc"],"fileKeys":[{{"path":"{}"}}]}}"#,
            root_s.replace('\\', "\\\\")
        ))
        .unwrap();
        let st = get_file_key_deletable(&rule, &mut 0, None, Some(&protect));
        assert!(
            st.files.is_empty(),
            "受保护根下的文件不得进可删清单（skip_lock 也不例外）：{:?}",
            st.files
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// v7.2-C03（N1a-M02）破坏自证：受保护文件不得报「被占用」（其持有进程不得
    /// 进 kill 白名单）；非受保护文件的两个方向都要保住——可独占打开 ⇒ 不报、
    /// 真被独占持有 ⇒ 照报（占用检测的正常面不许回归）。破坏形态 = 删掉
    /// [`occupied_report_warranted`] 里的保护早退 ⇒ 第一条断言红。
    #[test]
    fn checklocked_受保护文件不进占用报告() {
        let root = std::env::temp_dir().join(format!("trim-locked-prot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let f = root.join("busy.tmp");
        fs::write(&f, b"x").unwrap();
        let root_s = root.to_string_lossy().replace('/', "\\");
        let root_key = root_s.to_lowercase();
        let root_key = root_key.trim_end_matches('\\').to_string();
        let protect = format!(
            r#"{{"subtree":["{}"],"exact":[],"anyDrive":[],"neverNames":[]}}"#,
            root_key.replace('\\', "\\\\")
        );
        let f_s = f.to_string_lossy().replace('/', "\\");
        // 先用独占句柄把文件真正锁住：破坏态（保护早退被删）下 warranted =
        // !file_deletable = true，第一条断言才会红——文件没被锁住时打断前后同判
        //（探针必须先验证命中，P2-1 教训）。
        let hold = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&f)
                .unwrap()
        };
        assert!(
            !occupied_report_warranted(&f_s, Some(&protect)),
            "受保护文件不得报「被占用」（哪怕它真被独占持有）"
        );
        drop(hold);
        assert!(
            !occupied_report_warranted(&f_s, None),
            "非受保护且可独占打开的文件不算被占用"
        );
        let hold2 = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&f)
                .unwrap()
        };
        assert!(
            occupied_report_warranted(&f_s, None),
            "被独占持有的非受保护文件必须仍报占用（正常占用面）"
        );
        drop(hold2);
        let _ = fs::remove_dir_all(&root);
    }

    /// v7.2 W4（N1a-L05）破坏自证：诊断出口的入站单行化 —— 路径/规则原文里的换行
    /// 不得伪造出第二行留痕（`@@PLANFILE@@` 前缀一旦被伪造进 stderr，按行前缀对账的
    /// 人工与机检都会把它当成真输出）。
    /// 判红自证：删掉 `err_line` 里的 `diag_text` 包装 ⇒ `lines().count()` 变 2 当场红。
    #[test]
    fn err_line_把外部原文压成一行留痕() {
        let (code, _out, err) = capture(
            None,
            || {
                err_line("[cleanup-scan] 规则 r1 路径 C:\\temp\n@@PLANFILE@@{\"id\":\"r1\"} 未解析");
                0
            },
        );
        assert_eq!(code, 0, "本用例只验诊断通道");
        assert_eq!(
            err.lines().count(),
            1,
            "留痕被换行拆成两行（等于凭空多出一行 @@PLANFILE@@）：{err}"
        );
        assert!(err.contains("\\n"), "换行必须转义成字面 \\\\n：{err}");
        assert!(
            err.contains(r"C:\temp"),
            "留痕档位不该双写反斜杠（只中性化控制字符）：{err}"
        );
        // 干净文本一字不改（20+ 处既有留痕的逐字节口径不许被这条改动带跑）
        let (_c2, _o2, err2) = capture(
            None,
            || {
                err_line("[cleanup-scan] 普通留痕，无控制字符");
                0
            },
        );
        assert_eq!(err2, "[cleanup-scan] 普通留痕，无控制字符\n", "无控制字符时必须逐字节照旧");
    }

    /// v7.2 W4（N1a-M05）：捕获内三种出口必须分档，不许都折成「退出码 2 + 空 stderr」。
    /// 点名四件事：① 规则库致命错仍是 2 且带「致命:」行、不被说成引擎 bug；
    /// ② 真 panic 换档、带消息本体与触发位置；③ panic 消息自带换行也只落一行；
    /// ④ 上一程的状态不污染下一程（正常捕获仍 0 码、err 空、out 逐字节照旧）。
    /// 判红自证：把 `capture` 的 `Err(_) => EXIT_ENGINE_PANIC` 改回恒 2，②③ 同时红。
    #[test]
    fn 捕获内真panic留痕且与规则库致命错分退出码() {
        // ① 规则库致命错（载荷 FatalMarker）：回执码与留痕照旧
        let (code_fatal, _o, err_fatal) = capture(None, || fatal("stdin 规则 JSON 为空"));
        assert_eq!(
            code_fatal, EXIT_FATAL,
            "规则库致命错的回执码不得变（宿主与 CLI 都按它对账）"
        );
        assert_eq!(err_fatal.lines().count(), 1, "致命行必须只有一行：{err_fatal}");
        assert!(
            err_fatal.contains("致命: stdin 规则 JSON 为空"),
            "fatal 的留痕必须落进 CAP.err（不是进程 stderr）：{err_fatal}"
        );
        assert!(
            !err_fatal.contains("引擎 panic"),
            "规则库错不得被说成引擎 bug：{err_fatal}"
        );

        // ② 引擎真 panic（越界/unwrap 的形态）：换档 + 必须留痕
        let (code_panic, _o, err_panic) = capture(None, || panic!("故意的样本消息 42"));
        assert_eq!(
            code_panic, EXIT_ENGINE_PANIC,
            "真 panic 必须与规则库致命错分档，否则宿主分不清该修规则还是该修引擎：{code_panic}"
        );
        assert!(err_panic.contains("引擎 panic"), "留痕必须点名引擎 panic：{err_panic}");
        assert!(
            err_panic.contains("故意的样本消息 42"),
            "留痕必须带 panic 消息本体（否则无从对账）：{err_panic}"
        );
        assert!(
            err_panic.contains("cleanup_scan.rs"),
            "留痕必须带触发位置：{err_panic}"
        );
        assert!(
            !err_panic.contains("致命: "),
            "引擎 bug 不得伪装成规则库致命错：{err_panic}"
        );

        // ③ panic 消息自带换行 ⇒ 仍然只有一行（与 N1a-L05 同一条出口护栏）
        let (code3, _o, err3) = capture(None, || panic!("第一行\n第二行"));
        assert_eq!(code3, EXIT_ENGINE_PANIC);
        assert_eq!(err3.lines().count(), 1, "panic 留痕也不许多出第二行：{err3}");

        // ④ 复位对照：紧随其后的一次正常捕获必须干净
        let (code4, out4, err4) = capture(None, || {
            out_line("@@ITEM@@{}");
            0
        });
        assert_eq!(code4, 0);
        assert!(err4.is_empty(), "上一程的 panic 状态不得漏进本程：{err4}");
        assert_eq!(out4, "@@ITEM@@{}\n", "无回调形态的 stdout 必须逐字节照旧");
    }

    /// 真机逐条目计时：对真实规则库的每个条目单独跑一遍扫描，输出「总耗时 + 慢条目排名」。
    ///
    /// 为什么必须是独立条目而不是整库一次跑：整库只给一个总秒数，「哪条慢」全靠猜；
    /// 2026-10-23 真机日志（79 条 / 107 秒）就是这种无从下手的状态。本探针只出数，
    /// 不改任何判据；取数时 `cargo test --lib 扫描逐条耗时实测 -- --ignored --nocapture`。
    #[test]
    #[ignore = "真机实测：对真实规则库逐条目计时，非回归判据，取数时手动 --ignored 跑"]
    fn 扫描逐条耗时实测() {
        use std::time::Instant;
        let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../src-tauri/data/cleanup-rules.json");
        let Ok(rules_text) = fs::read_to_string(&rules_path) else {
            println!("SKIP：规则库不存在（{}）", rules_path.display());
            return;
        };
        let Ok(rules) = parse_json(&rules_text) else {
            println!("SKIP：规则库解析失败");
            return;
        };
        let mut ids: Vec<String> = Vec::new();
        if let Some(groups) = rules.get("groups").and_then(|g| g.as_arr()) {
            for g in groups {
                if let Some(sgs) = g.get("subGroups").and_then(|s| s.as_arr()) {
                    for sg in sgs {
                        if let Some(items) = sg.get("items").and_then(|i| i.as_arr()) {
                            for it in items {
                                if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
                                    ids.push(id.to_string());
                                }
                            }
                        }
                    }
                } else if let Some(items) = g.get("items").and_then(|i| i.as_arr()) {
                    for it in items {
                        if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
                            ids.push(id.to_string());
                        }
                    }
                }
            }
        }
        let mut rows: Vec<(u128, usize, String)> = Vec::new();
        let mut total = std::time::Duration::ZERO;
        for id in &ids {
            let cats = format!("[{}]", jstr(id));
            let t0 = Instant::now();
            let (code, out, err) = run_json(&[cats, "{}".to_string(), String::new()], &rules_text, None);
            let dt = t0.elapsed();
            total += dt;
            let rows_n = out.lines().filter(|l| l.starts_with("@@PLANFILE@@")).count();
            rows.push((dt.as_millis(), rows_n, format!("{id}（code={code}，stderr={} 行）", err.lines().count())));
        }
        rows.sort_by(|a, b| b.0.cmp(&a.0));
        println!("共 {} 条，总耗时 {:.1}s；最慢 25 条：", ids.len(), total.as_secs_f64());
        for (ms, n, name) in rows.iter().take(25) {
            println!("{ms:>7}ms  plan={n:<6} {name}");
        }
    }

    /// v7.2 W4（N1a-M05）：`run_json` 入口少传参数不得变成越界 panic（旧形态正好落进
    /// 「非 FatalMarker panic ⇒ 无留痕」那条通道）。检查落在捕获体内 ⇒ 走 fatal 一档。
    #[test]
    fn run_json_参数不足走致命档而不是越界() {
        let (code, _out, err) = run_json(&["[]".to_string()], "{}", None);
        assert_eq!(code, EXIT_FATAL, "参数不足必须是规则库/输入致命错那一档：{code}");
        assert!(err.contains("参数不足"), "必须说清缺什么：{err}");
        assert!(!err.contains("引擎 panic"), "不是引擎 bug：{err}");
        // 对照：参数够（stdin 空仍致命，但报的是规则库那条）
        let (code2, _o2, err2) = run_json(&["[]".to_string(), "{}".to_string()], "", None);
        assert_eq!(code2, EXIT_FATAL);
        assert!(err2.contains("stdin 规则 JSON 为空"), "对照未命中：{err2}");
    }

    /// P1-2 前置 golden：落盘小树，记录三个遍历器的**有序文件清单、计数、截断位**。
    ///
    /// 为什么先取 golden：目录级并行/预取只许提速，不许改输出顺序与 PLAN_CAP 边界。
    /// 临时根名带 PID，但打印的是相对路径；文件按固定顺序创建，NTFS readdir 顺序稳定。
    /// 取数：`cargo test --lib 遍历顺序与截断golden -- --ignored --nocapture`。
    #[test]
    #[ignore = "真机顺序/截断 golden：落盘小树，发布前手动跑"]
    fn 遍历顺序与截断golden_三遍历器() {
        let root = std::env::temp_dir().join(format!("trim-order-golden-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("s1").join("deep")).unwrap();
        fs::create_dir_all(root.join("s2")).unwrap();
        for (dir, name, size) in [
            (root.clone(), "a.txt", 1u8),
            (root.clone(), "b.txt", 2),
            (root.join("s1"), "c.txt", 3),
            (root.join("s1"), "d.txt", 4),
            (root.join("s1").join("deep"), "e.txt", 5),
            (root.join("s2"), "f.txt", 6),
        ] {
            fs::write(dir.join(name), vec![b'x'; size as usize]).unwrap();
        }
        let root_s = root.to_string_lossy().to_string();
        let rel = |p: &str| {
            p.strip_prefix(&root_s)
                .unwrap_or(p)
                .trim_start_matches('\\')
                .trim_start_matches('/')
                .replace('\\', "/")
        };

        let d = list_deletable_capped(
            &root_s,
            "*.txt",
            AgeGuard::Off,
            &[],
            &[],
            None,
            3,
        );
        let files: Vec<String> = d.files.iter().map(|(p, _, _)| rel(p)).collect();
        println!(
            "GOLDEN_WALK_DELETABLE files={files:?} total={} del={} bytes={} trunc={} reparse={} unreadable={}",
            d.total, d.deletable_count, d.deletable_bytes, d.files_truncated, d.skipped_reparse, d.unreadable_dirs
        );
        // 预取路径 vs 回退路径：同一棵树必须逐项一致（顺序、计数、截断位）。
        let mut d_fallback = DeletableResult {
            files: Vec::new(),
            total: 0,
            deletable_count: 0,
            deletable_bytes: 0,
            skipped_reparse: 0,
            unreadable_dirs: 0,
            files_truncated: false,
        };
        walk_deletable(&root, true, "*.txt", AgeGuard::Off, &[], &[], None, &mut d_fallback, 0, true, Some(3), None);
        assert_eq!(d_fallback.files, d.files, "预取与回退路径的文件顺序/内容必须一致");
        assert_eq!(
            (
                d_fallback.total,
                d_fallback.deletable_count,
                d_fallback.deletable_bytes,
                d_fallback.files_truncated,
                d_fallback.skipped_reparse,
                d_fallback.unreadable_dirs,
            ),
            (
                d.total,
                d.deletable_count,
                d.deletable_bytes,
                d.files_truncated,
                d.skipped_reparse,
                d.unreadable_dirs,
            ),
            "预取与回退路径的计数/截断必须一致"
        );

        let mut acc = FkAcc::new(0);
        acc.item_cap = 3;
        acc.global_cap = 100;
        walk_fk_dll(&root, true, "*.txt", true, AgeGuard::Off, &[], &[], None, &mut acc, 0, None);
        let files2: Vec<String> = acc.files.iter().map(|(p, _, _)| rel(p)).collect();
        println!(
            "GOLDEN_WALK_FK_DLL files={files2:?} total={} del={} trunc={}",
            acc.total_count, acc.deletable_count, acc.truncated
        );
        let cache_dll = prefetch_walk(
            &root, true, "*.txt", true, crate::scan::MAX_WALK_DEPTH,
            AgeGuard::Off, &[], &[], None, false,
        );
        let mut acc_c = FkAcc::new(0);
        acc_c.item_cap = 3;
        acc_c.global_cap = 100;
        walk_fk_dll(&root, true, "*.txt", true, AgeGuard::Off, &[], &[], None, &mut acc_c, 0, Some(&cache_dll));
        assert_eq!(acc_c.files, acc.files, "fk_dll 预取与回退路径的文件顺序/内容必须一致");
        assert_eq!(
            (acc_c.total_count, acc_c.deletable_count, acc_c.truncated),
            (acc.total_count, acc.deletable_count, acc.truncated),
            "fk_dll 预取与回退路径的计数/截断必须一致"
        );

        let mut acc2 = FkAcc::new(0);
        acc2.item_cap = 3;
        acc2.global_cap = 100;
        walk_fk_snapshot(
            &root,
            true,
            "*.txt",
            true,
            0,
            AgeGuard::Off,
            &[],
            &[],
            None,
            true,
            &mut acc2,
            None,
        );
        let files3: Vec<String> = acc2.files.iter().map(|(p, _, _)| rel(p)).collect();
        println!(
            "GOLDEN_WALK_FK_SNAPSHOT files={files3:?} total={} del={} trunc={}",
            acc2.total_count, acc2.deletable_count, acc2.truncated
        );
        let cache_snap = prefetch_walk(
            &root, true, "*.txt", true, FK_SNAPSHOT_MAX_DEPTH,
            AgeGuard::Off, &[], &[], None, true,
        );
        let mut acc2_c = FkAcc::new(0);
        acc2_c.item_cap = 3;
        acc2_c.global_cap = 100;
        walk_fk_snapshot(
            &root, true, "*.txt", true, 0, AgeGuard::Off, &[], &[], None, true, &mut acc2_c, Some(&cache_snap),
        );
        assert_eq!(acc2_c.files, acc2.files, "fk_snapshot 预取与回退路径的文件顺序/内容必须一致");
        assert_eq!(
            (acc2_c.total_count, acc2_c.deletable_count, acc2_c.truncated),
            (acc2.total_count, acc2.deletable_count, acc2.truncated),
            "fk_snapshot 预取与回退路径的计数/截断必须一致"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
