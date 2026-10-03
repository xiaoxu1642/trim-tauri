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
//   · 输出字节与退出码因此**逐字不变**（stdout 全部先于 stderr，与原 fatal 的 flush 顺序一致）。
//
// ⚠️ 本文件另有并行任务在改（Sink 化）：本块**只新增**，不改既有函数签名与内部语义。

struct Cap {
    out: String,
    err: String,
    active: bool,
}

thread_local! {
    static CAP: std::cell::RefCell<Cap> =
        std::cell::RefCell::new(Cap { out: String::new(), err: String::new(), active: false });
    /// 逐行回调（数据返回式入口的可选参数；捕获模式下 out_line 顺带回调此行）
    static HOOK: std::cell::RefCell<Option<Box<dyn FnMut(&str)>>> = std::cell::RefCell::new(None);
}

/// 捕获串行锁：panic hook 是进程级的，同时只允许一次捕获
static CAP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// fatal 的 panic 载荷标记（只有它允许被静默吞掉，其余 panic 仍走原 hook 打印）
struct FatalMarker;
static HOOK_ONCE: std::sync::Once = std::sync::Once::new();

/// 装一次转发 hook：FatalMarker 静默，其它 panic 交回原 hook（不吞真 bug）
fn ensure_panic_hook() {
    HOOK_ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info.payload().downcast_ref::<FatalMarker>().is_none() {
                prev(info);
            }
        }));
    });
}

fn capturing() -> bool {
    CAP.with(|c| c.borrow().active)
}

/// 输出一行到 stdout（捕获模式下进内存；两种情况都触发逐行回调）
fn out_line(line: &str) {
    CAP.with(|c| {
        let mut cap = c.borrow_mut();
        if cap.active {
            cap.out.push_str(line);
            cap.out.push('\n');
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
fn capture(
    hook: Option<Box<dyn FnMut(&str)>>,
    body: impl FnMut() -> i32,
) -> (i32, String, String) {
    let _serial = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    ensure_panic_hook();
    CAP.with(|c| c.borrow_mut().active = true);
    HOOK.with(|h| *h.borrow_mut() = hook);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    HOOK.with(|h| h.borrow_mut().take());
    let code = match res {
        Ok(c) => c,
        Err(_) => 2, // fatal 已在 err_line 里落过「致命: …」行
    };
    let (out, err) = CAP.with(|c| {
        let mut cap = c.borrow_mut();
        cap.active = false;
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
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    pub const HKEY_CLASSES_ROOT: isize = -2147483648; // 0x80000000
    pub const HKEY_CURRENT_USER: isize = -2147483647; // 0x80000001
    pub const HKEY_LOCAL_MACHINE: isize = -2147483646; // 0x80000002
    pub const HKEY_USERS: isize = -2147483645; // 0x80000003
    pub const HKEY_CURRENT_CONFIG: isize = -2147483643; // 0x80000005

    const KEY_READ: u32 = 0x0002_0019;
    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;

    #[link(name = "advapi32")]
    #[allow(non_snake_case)]
    extern "system" {
        fn RegOpenKeyExW(hKey: isize, lpSubKey: *const u16, ulOptions: u32, samDesired: u32, phkResult: *mut isize) -> i32;
        fn RegQueryInfoKeyW(
            hKey: isize, lpClass: *mut u16, lpcchClass: *mut u32, lpReserved: *mut u32,
            lpcSubKeys: *mut u32, lpcchMaxSubKeyLen: *mut u32, lpcchMaxClassLen: *mut u32,
            lpcValues: *mut u32, lpcchMaxValueNameLen: *mut u32, lpcbMaxValueLen: *mut u32,
            lpcbSecurityDescriptor: *mut u32, lpftLastWriteTime: *mut u64,
        ) -> i32;
        fn RegCloseKey(hKey: isize) -> i32;
    }

    #[link(name = "kernel32")]
    #[allow(non_snake_case)]
    extern "system" {
        fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> isize;
        fn Process32FirstW(hSnapshot: isize, lppe: *mut PROCESSENTRY32W) -> i32;
        fn Process32NextW(hSnapshot: isize, lppe: *mut PROCESSENTRY32W) -> i32;
        fn CloseHandle(hObject: isize) -> i32;
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct PROCESSENTRY32W {
        dwSize: u32,
        cntUsage: u32,
        th32ProcessID: u32,
        th32DefaultHeapID: usize,
        th32ModuleID: u32,
        cntThreads: u32,
        th32ParentProcessID: u32,
        pcPriClassBase: i32, // Win32 LONG（32 位）——误用 isize 会使 dwSize 多 4 字节，Process32FirstW 报 BAD_LENGTH
        dwFlags: u32,
        szExeFile: [u16; 260],
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

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
                        let len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
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

/// FileInfo.Length 语义：存在且为文件返回长度（元数据读失败按不存在）
fn try_file_length(p: &Path) -> Option<u64> {
    match fs::metadata(p) {
        Ok(m) if m.is_file() => Some(m.len()),
        _ => None,
    }
}

/// 文件名通配（对齐 .NET FileSystemName.MatchesSimpleExpression ignoreCase=true）：
/// '*' 任意串（含空）、'?' 恰一字符；仅 P1 fileKeys 的 pattern 会用到非 '*' 模式
fn wildcard_match(name: &str, pattern: &str) -> bool {
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
    pub files: Vec<(String, u64)>, // 可删文件（探测通过）。仅 collect_files=true 时填充
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
}

/// 单遍递归枚举 + 探测。口径：跳 ReparsePoint（不深入）、目录不计数、
/// IgnoreInaccessible（不可读子目录静默跳过）。
/// 审查 L-9（2026-10-03）：原先「无深度上限」（对齐 PS `Get-ChildItem -Recurse`
/// 的无界递归）收窄为 `scan::MAX_WALK_DEPTH`——超限子目录整棵跳过并 stderr 留痕。
/// 清理候选宁可少报（fail-safe），也不冒病态深嵌套撑爆递归栈的险；正常目录树
/// （含 node_modules）远达不到该深度，对真实扫描结果无可观测影响。
/// minAge 时效护栏：cutoff 命中时太新的文件不计入 total（对齐 pattern 未命中的口径）。
/// 全局排除名单：命中前缀/全路径的文件不计入 total。
fn walk_deletable(
    dir: &Path,
    all: bool,
    pattern: &str,
    cutoff: Option<std::time::SystemTime>,
    excl_dirs: &[String],
    excl_files: &[String],
    res: &mut DeletableResult,
    depth: usize,
    collect_files: bool,
) {
    if depth >= crate::scan::MAX_WALK_DEPTH {
        err_line(&format!("[trim-scanner] depth cap reached at {}", dir.display()));
        return;
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return, // IgnoreInaccessible
    };
    for ent in rd.flatten() {
        if crate::is_reparse(&ent) {
            res.skipped_reparse += 1; // R1-2：留痕，不参与 total/files 判定
            continue; // 文件与目录均跳过，且不深入重解析目录
        }
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk_deletable(&ent.path(), all, pattern, cutoff, excl_dirs, excl_files, res, depth + 1, collect_files);
            continue;
        }
        if !ft.is_file() {
            continue; // 目录项不参与统计（FindFirstFile 对目录 size 恒 0，与 GCI -File 同义）
        }
        let name = ent.file_name().to_string_lossy().to_string();
        if !all && !wildcard_match(&name, pattern) {
            continue; // 未命中 pattern：不计入 total（对齐 Skip() 在 total++ 之前）
        }
        let full = ent.path();
        if path_excluded(excl_dirs, excl_files, &full.to_string_lossy().to_lowercase()) {
            continue;
        }
        if cutoff.map(|c| !ent.metadata().map(|m| modified_before(&m, c)).unwrap_or(false)).unwrap_or(false) {
            continue; // 太新：不计入 total（fail-closed，metadata 读不到按太新处理）
        }
        res.total += 1;
        let size = ent.metadata().map(|m| m.len()).unwrap_or(0);
        if file_deletable(&full) {
            // 计数与字节和**两种模式都记**（统计口径的唯一数据源）；
            // 路径字符串只在真要交给调用方时才留（审计 §3.3）。
            res.deletable_count += 1;
            res.deletable_bytes += size;
            if collect_files {
                res.files.push((full.to_string_lossy().to_string(), size));
            }
        }
    }
}

pub fn list_deletable(
    root_str: &str,
    pattern: &str,
    cutoff: Option<std::time::SystemTime>,
    excl_dirs: &[String],
    excl_files: &[String],
) -> DeletableResult {
    list_deletable_inner(root_str, pattern, cutoff, excl_dirs, excl_files, true)
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
    cutoff: Option<std::time::SystemTime>,
    excl_dirs: &[String],
    excl_files: &[String],
) -> DeletableResult {
    list_deletable_inner(root_str, pattern, cutoff, excl_dirs, excl_files, false)
}

fn list_deletable_inner(
    root_str: &str,
    pattern: &str,
    cutoff: Option<std::time::SystemTime>,
    excl_dirs: &[String],
    excl_files: &[String],
    collect_files: bool,
) -> DeletableResult {
    let all = pattern.is_empty() || pattern == "*";
    let root = Path::new(root_str);
    // 根本身是文件（pattern='*'）：单文件口径（对齐 TryFileLength 分支）
    if all {
        if let Some(fl) = try_file_length(root) {
            // minAge：单文件同样要过时效护栏（mtime 读不到按太新处理）
            let old_enough = cutoff
                .map(|c| fs::metadata(root).map(|m| modified_before(&m, c)).unwrap_or(false))
                .unwrap_or(true);
            let root_low = root.to_string_lossy().to_lowercase();
            let excluded = path_excluded(excl_dirs, excl_files, &root_low);
            let mut files = Vec::new();
            let mut deletable_count = 0u64;
            let mut deletable_bytes = 0u64;
            if old_enough && !excluded && file_deletable(root) {
                deletable_count = 1;
                deletable_bytes = fl;
                if collect_files {
                    files.push((root_str.to_string(), fl));
                }
            }
            return DeletableResult {
                files,
                total: if old_enough && !excluded { 1 } else { 0 },
                deletable_count,
                deletable_bytes,
                skipped_reparse: 0, // 单文件路径不枚举子项，无重解析点可跳
            };
        }
    }
    let mut res = DeletableResult {
        files: Vec::new(),
        total: 0,
        deletable_count: 0,
        deletable_bytes: 0,
        skipped_reparse: 0,
    };
    // 根不存在/不可访问 → 空结果（对齐 PS 侧 catch 空语义；根级失败由调用方探针另判 ok=false）
    walk_deletable(root, all, pattern, cutoff, excl_dirs, excl_files, &mut res, 0, collect_files);
    res
}

// ==================== Get-PathDeletableStats 口径（三态出口） ====================

// L6（2026-09-19）：missing / nfiles 是 Get-PathDeletableStats 的 PS 侧契约字段，
// Rust 当前调用方只消费 ok / size；保留字段以维持与 PS 口径的结构对等，显式豁免 dead_code。
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
}

fn get_path_deletable_stats(path: &str, cutoff: Option<std::time::SystemTime>) -> PathStats {
    if path.is_empty() {
        return PathStats { ok: false, missing: true, size: 0, nfiles: 0, locked: 0, skipped_reparse: 0 };
    }
    let p = Path::new(path);
    // 存在性用同一套 API 判定（metadata 跟随链接，与 .NET Exists 同源）
    let is_dir = fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false);
    if !is_dir {
        if fs::metadata(p).map(|m| m.is_file()).unwrap_or(false) {
            if !file_deletable(p) {
                return PathStats { ok: true, missing: false, size: 0, nfiles: 0, locked: 1, skipped_reparse: 0 };
            }
            return match fs::metadata(p) {
                Ok(m) => PathStats { ok: true, missing: false, size: m.len(), nfiles: 1, locked: 0, skipped_reparse: 0 },
                Err(_) => PathStats { ok: false, missing: false, size: 0, nfiles: 0, locked: 0, skipped_reparse: 0 },
            };
        }
        // 既非目录也非文件 = 不存在
        return PathStats { ok: true, missing: true, size: 0, nfiles: 0, locked: 0, skipped_reparse: 0 };
    }
    // 枚举探针：连一个子项都列不出 = 无法统计（ACL 拒绝 / 重解析目标异常），绝不报 0
    let probe_ok = fs::read_dir(p).and_then(|mut rd| rd.next().transpose()).is_ok();
    if !probe_ok {
        return PathStats { ok: false, missing: false, size: 0, nfiles: 0, locked: 0, skipped_reparse: 0 };
    }
    // U1-b（2026-10-01）：全局排除名单整链下线。本探针历史上也只吃全局名单（规则级
    // excludePaths 到这层已经丢了规则上下文），传空集即等价于「名单为空」。
    // 统计口径走 list_deletable_stats：**不物化每文件路径**（审计 §3.3）。
    // nfiles / size 从 deletable_count / deletable_bytes 取，那是唯一数据源；
    // 两者口径必须恒等（下面有断言钉住），否则「列表说 N 个、统计说 M 个」会被
    // 用户读成扫描漏项。
    let res = list_deletable_stats(path, "*", cutoff, &[], &[]);
    let nfiles = res.deletable_count;
    let size = res.deletable_bytes;
    PathStats { ok: true, missing: false, size, nfiles, locked: res.total - nfiles, skipped_reparse: res.skipped_reparse }
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
fn list_matching_dirs(parent: &str, seg: &str, force: bool, skipped_reparse: &mut u64) -> Vec<String> {
    let pd = Path::new(parent);
    let mut out = Vec::new();
    let rd = match fs::read_dir(pd) {
        Ok(r) => r,
        Err(_) => return out,
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
    let expanded = expand_env_path(pattern);
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
                for d in list_matching_dirs(r, seg, force, &mut skipped_reparse) {
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
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const CCH_RM_MAX_APP_NAME: usize = 255;
    const CCH_RM_MAX_SERVICE_NAME_SHORT: usize = 63;
    const CCH_RM_SESSION_KEY: usize = 32;
    const ERROR_MORE_DATA: i32 = 234;

    // L6（2026-09-19）：Win32 结构体字段名必须与 SDK 原名逐字一致，重命名既不改变内存布局
    // 也破坏 #[repr(C)] 的可读性契约，故局部豁免 non_snake_case（改动字段名属于高危改动，禁止）。
    #[repr(C)]
    #[allow(non_snake_case)]
    struct RM_UNIQUE_PROCESS {
        dwProcessId: u32,
        // FILETIME 本体是 { DWORD low, DWORD high }，4 字节对齐、共 8 字节——
        // 用 u64 会引入 8 字节对齐 pad，使 strAppName 错位 4 字节（实测应用名丢首 2 字符）
        ProcessStartTimeLow: u32,
        ProcessStartTimeHigh: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct RM_PROCESS_INFO {
        Process: RM_UNIQUE_PROCESS,
        strAppName: [u16; CCH_RM_MAX_APP_NAME + 1],
        strServiceShortName: [u16; CCH_RM_MAX_SERVICE_NAME_SHORT + 1],
        ApplicationType: u32,
        TSSessionId: u32,
        bRestartable: i32,
        // 2026-09-30 实测：Windows 按 **668 字节**步长写这条记录，SDK 头文件那六个成员只推出 664。
        // 少这 4 字节的后果不是「显示难看」而是三件实事：① 第 i 条记录整体前移 4×i 字节，
        // 应用名前多出 2i 个乱码字符（用户看到的「偁aWindows 资源管理器」）；② `pid` 与
        // `ApplicationType` 跟着错位 ⇒ 结束进程拿的是错 PID、critical 判错；③ 按 664 申请的
        // 缓冲区被按 668 写满 ⇒ 越界写（72 条时越界 288 字节）。
        // 字段位置同样实测钉住：strAppName@12、strServiceShortName@524（服务短名干净）、
        // ApplicationType@652（lsass 读出 1000=RmCritical）、bRestartable@660。
        // 这个尾巴 DWORD 是什么微软没写进头文件，本模块不消费它，只负责让步长对齐。
        _reserved: u32,
    }

    impl Clone for RM_PROCESS_INFO {
        fn clone(&self) -> Self {
            unsafe { std::ptr::read(self) } // POD 结构体逐位复制（含数组字段，无堆所有权）
        }
    }

    // 布局不变式放编译期而不是 #[test]：native-scanner 是 path 依赖、非 workspace 成员，
    // 它的单测只有显式 --manifest-path 才跑，靠测试兜不住「有人改回六个成员」这种回归。
    const _: () = {
        if std::mem::size_of::<RM_PROCESS_INFO>() != 668 {
            panic!("RM_PROCESS_INFO 步长必须 668 字节：Windows 就按这个宽度写，错了会错位读名/pid 并越界写");
        }
        if std::mem::offset_of!(RM_PROCESS_INFO, strAppName) != 12 {
            panic!("strAppName 偏移必须是 12：RM_UNIQUE_PROCESS 是 DWORD+FILETIME 共 12 字节而非 16");
        }
        if std::mem::offset_of!(RM_PROCESS_INFO, ApplicationType) != 652 {
            panic!("ApplicationType 偏移必须是 652：critical 判定（==1000 RmCritical）按它读");
        }
    };

    #[link(name = "rstrtmgr")]
    #[allow(non_snake_case)]
    extern "system" {
        fn RmStartSession(pSessionHandle: *mut u32, dwSessionFlags: u32, strSessionKey: *mut u16) -> i32;
        fn RmRegisterResources(
            dwSessionHandle: u32, nFiles: u32, rgsFileNames: *const *const u16,
            nApplications: u32, rgApplications: *const RM_PROCESS_INFO,
            nServices: u32, rgsServiceNames: *const *const u16,
        ) -> i32;
        fn RmGetList(
            dwSessionHandle: u32, pnProcInfoNeeded: *mut u32, pnProcInfo: *mut u32,
            rgAffectedApps: *mut RM_PROCESS_INFO, lpdwRebootReasons: *mut u32,
        ) -> i32;
        fn RmEndSession(dwSessionHandle: u32) -> i32;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

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
                            let len = pi.strAppName.iter().position(|&c| c == 0).unwrap_or(0);
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
        if file_deletable(Path::new(path)) {
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

fn test_rule_detect(rule: &Json) -> bool {
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
                        if ffi::reg_key_exists(&expand_env_path(path)) {
                            return true;
                        }
                    } else {
                        let p = expand_env_path(path);
                        if p.contains('*') {
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
                        if fp.contains('*') {
                            return !expand_glob_dirs(&fp, true).is_empty();
                        }
                        return path_exists(&fp);
                    }
                }
            }
        }
    }
    if let Some(pp) = rule.get("pathPs") {
        if let Some(expr) = pp.as_str() {
            return match resolve_rule_path(expr) {
                Some(p) => path_exists(&p),
                // 表达式求值失败（受限语法）→ 保守命中，交给主循环 fail-closed 跳过
                None => true,
            };
        }
    }
    if let Some(rk) = rule.get("regKeys") {
        if rk.ps_count() > 0 {
            if let Some(arr) = rk.as_arr() {
                if let Some(first) = arr.first() {
                    if let Some(rp0) = first.get("path").and_then(|p| p.as_str()) {
                        return ffi::reg_key_exists(&expand_env_path(rp0));
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

// ==================== 时效护栏 minAge（P0-M5，竞品借鉴落地方案 §5） ====================
// 规则可声明 minAgeHours 或 minAgeDays（互斥，契约门禁 A9 钉死）。年龄口径 =
// 当前时间 − 文件**修改时间**；mtime 早于 cutoff 才算够老。mtime 读不到按「太新」
// 处理（fail-closed：误删正在写入的文件不可逆，宁可少删）。扫描（本文件）与执行
// （engine::native::cleanup_execute）两侧共用同一谓词，防「扫描排除、执行照删」。

/// 由秒数推 cutoff（现在 − secs）。Duration 溢出只在天文数字下发生，panic 可接受。
pub fn min_age_cutoff(secs: u64) -> std::time::SystemTime {
    std::time::SystemTime::now() - std::time::Duration::from_secs(secs)
}

/// 文件修改时间是否早于 cutoff（= 年龄达标）。mtime 读不到 ⇒ false（按太新处理）。
pub fn modified_before(m: &fs::Metadata, cutoff: std::time::SystemTime) -> bool {
    match m.modified() {
        Ok(t) => t <= cutoff,
        Err(_) => false,
    }
}

/// 解析规则的 minAge 字段为秒数。minAgeDays = 24h 的整数倍；非正数/非数字按缺失处理。
fn rule_min_age_secs(rule: &Json) -> Option<u64> {
    let pos = |v: &Json| match v {
        Json::Num(n) if *n > 0.0 => Some(*n),
        _ => None,
    };
    let h = rule.get("minAgeHours").and_then(pos);
    let d = rule.get("minAgeDays").and_then(pos);
    match (h, d) {
        (Some(h), None) => Some((h * 3600.0) as u64),
        (None, Some(d)) => Some((d * 86400.0) as u64),
        _ => None, // 双声明或全缺：门禁 A9 判双声明；全缺 = 无时效护栏
    }
}

/// 全路径（小写）是否被排除名单命中。
pub fn path_excluded(excl_dirs: &[String], excl_files: &[String], low: &str) -> bool {
    excl_dirs.iter().any(|d| low.starts_with(&format!("{}\\", d))) || excl_files.iter().any(|f| *f == low)
}

const PLAN_CAP_PER_ITEM: usize = 100_000;
const PLAN_CAP_TOTAL: usize = 1_000_000;

struct FkResult {
    total_size: i64,
    count: i64,
    locked: i64,
    files: Vec<(String, u64)>,
    truncated: bool,
    /// 因重解析点跳过的目录数（R1-2 留痕）。只透出呈现，**不进上面三个判定字段**。
    skipped_reparse: u64,
}

struct FkAcc {
    seen: HashSet<String>,
    files: Vec<(String, u64)>,
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
        }
    }

    /// 推入可删清单：受 PLAN_CAP 约束（推入即计数，超限标截断）
    fn push_budget(&mut self, full: String, size: u64) {
        if self.item_rows >= self.item_cap || self.global_rows >= self.global_cap {
            self.truncated = true;
            return;
        }
        self.total_size += size as i64;
        self.files.push((full, size));
        self.item_rows += 1;
        self.global_rows += 1;
    }
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
    cutoff: Option<std::time::SystemTime>,
    excl_dirs: &[String],
    excl_files: &[String],
    acc: &mut FkAcc,
    depth: usize,
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
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return, // IgnoreInaccessible
    };
    for ent in rd.flatten() {
        if crate::is_reparse(&ent) {
            acc.skipped_reparse += 1; // R1-2：留痕，不进 total_size/count/locked 判定
            continue;
        }
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            if recurse {
                walk_fk_dll(&ent.path(), all, pattern, recurse, cutoff, excl_dirs, excl_files, acc, depth + 1);
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        // minAge 时效护栏：太新的文件不计入 total（对齐 pattern 未命中的口径）
        let md = match ent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if cutoff.map(|c| !modified_before(&md, c)).unwrap_or(false) {
            continue;
        }
        let full_s = ent.path().to_string_lossy().to_string();
        let low = full_s.to_lowercase();
        // excludeKeys 过滤（dir 前缀 / file 全路径；PS 原语义只在快照分支生效，此处防御性保留，
        // 因 hasExcl 时调用方必选快照模式，本分支实际不含排除清单）
        if excl_dirs.iter().any(|d| low.starts_with(&format!("{}\\", d))) || excl_files.iter().any(|f| *f == low) {
            continue;
        }
        let name = ent.file_name().to_string_lossy().to_string();
        if !all && !wildcard_match(&name, pattern) {
            continue;
        }
        acc.total_count += 1;
        let size = md.len();
        if file_deletable(Path::new(&full_s)) {
            acc.deletable_count += 1; // 去重前累加（对齐 PS DLL 分支）
            if acc.seen.insert(low) {
                let before = acc.truncated;
                acc.push_budget(full_s, size);
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
}

#[allow(clippy::too_many_arguments)]
fn walk_fk_snapshot(
    dir: &Path,
    all: bool,
    pattern: &str,
    recurse: bool,
    depth: usize,
    cutoff: Option<std::time::SystemTime>,
    excl_dirs: &[String],
    excl_files: &[String],
    skip_lock: bool,
    acc: &mut FkAcc,
) {
    // 遍历预算耗尽 ⇒ 整棵子树不再下钻（2026-10-04 磁盘清理审计 §3.4，理由见
    // walk_fk_dll 里同一条注释）。快照模式的 `seen` 同样在无界增长。
    if acc.truncated {
        return;
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for ent in rd.flatten() {
        if crate::is_reparse(&ent) {
            acc.skipped_reparse += 1; // R1-2：留痕，不进 total_size/count/locked 判定
            continue;
        }
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            if recurse {
                // 审查 L-25（2026-10-03 L4）：depth 上限的**口径**（24）对齐 PS
                // `Get-FileKeySnapshot -Depth 24`，不是缺陷（报告 §10.2 白名单第 6 条已
                // 裁定）；缺的是**留痕**——walk_deletable / walk_level / walk_fk_dll 三处
                // 超限都 eprintln，这里静默 `continue` ⇒ 「深处的文件没进清单」和
                // 「文件本来就不存在」在日志里长得一模一样。补齐 eprintln 与三处同格式。
                if depth < FK_SNAPSHOT_MAX_DEPTH {
                    walk_fk_snapshot(&ent.path(), all, pattern, recurse, depth + 1, cutoff, excl_dirs, excl_files, skip_lock, acc);
                } else {
                    err_line(&format!(
                        "[trim-scanner] depth cap {FK_SNAPSHOT_MAX_DEPTH} reached at {}",
                        ent.path().display()
                    ));
                }
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let name = ent.file_name().to_string_lossy().to_string();
        if !all && !wildcard_match(&name, pattern) {
            continue;
        }
        // minAge 时效护栏：太新的文件不计入 total（对齐 pattern 未命中的口径）
        let md = match ent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if cutoff.map(|c| !modified_before(&md, c)).unwrap_or(false) {
            continue;
        }
        let full_s = ent.path().to_string_lossy().to_string();
        let low = full_s.to_lowercase();
        if excl_dirs.iter().any(|d| low.starts_with(&format!("{}\\", d))) {
            continue;
        }
        if excl_files.iter().any(|f| *f == low) {
            continue;
        }
        // 快照分支口径：先去重再计数（对齐 Get-FileKeySnapshot 的 seen.Add 前置）
        if !acc.seen.insert(low.clone()) {
            continue;
        }
        acc.total_count += 1;
        let size = md.len();
        if skip_lock || file_deletable(Path::new(&full_s)) {
            acc.deletable_count += 1;
            let before = acc.truncated;
            acc.push_budget(full_s, size);
            if !before && acc.truncated {
                // 首次翻转才留痕（理由同 walk_fk_dll 那处）
                err_line(&format!(
                    "[trim-scanner] PLAN_CAP 已耗尽（单条目上限 {PLAN_CAP_PER_ITEM} 行 / 全扫描 {PLAN_CAP_TOTAL} 行），\
                     剩余子树停止遍历（已记 filesTruncated）"
                ));
            }
        }
    }
}

fn get_file_key_deletable(rule: &Json, global_rows: &mut usize) -> FkResult {
    let skip_lock = rule.get("restartProcesses").map(|v| v.ps_count()).unwrap_or(0) > 0;
    let has_excl = rule.get("excludeKeys").map(|v| v.ps_count()).unwrap_or(0) > 0;
    // 规则级 excludePaths（C-2，2026-09-28 开门）：字符串数组，与全局排除名单同口径
    // （%VAR% 展开 / 有扩展名=文件全路径 / 否则=目录前缀）。excludeKeys（对象型、reg 面）
    // 仍被门禁 A2 禁用，回潮即红。走 excludePaths 同样要求快照模式（逐文件过滤必须在
    // 受控枚举里做，DLL 快照模式没有排除通道）。
    let has_expaths = rule.get("excludePaths").map(|v| v.ps_count()).unwrap_or(0) > 0;
    let any_recurse_false = rule
        .get("fileKeys")
        .and_then(|v| v.as_arr())
        .map(|arr| arr.iter().any(|fk| fk.get("recurse") == Some(&Json::Bool(false))))
        .unwrap_or(false);
    let snapshot_mode = skip_lock || has_excl || has_expaths || any_recurse_false;
    let cutoff = rule_min_age_secs(rule).map(min_age_cutoff);
    // 规则级 excludePaths 的过滤面（excludeKeys 本身仍被门禁 A2 禁用）。
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
            if Path::new(&ep).extension().is_some() {
                excl_files.push(ep);
            } else {
                excl_dirs.push(ep);
            }
        }
    }
    if let Some(arr) = rule.get("excludeKeys").and_then(|v| v.as_arr()) {
        for ex in arr {
            // reg 型排除键不属于文件过滤面（PS: -or -not $ex.path -or $ex.type -eq 'reg' → skip）
            if ex.get("type").and_then(|t| t.as_str()) == Some("reg") {
                continue;
            }
            let Some(ep0) = ex.get("path").and_then(|v| v.as_str()) else {
                continue;
            };
            let ep = expand_env_path(ep0).trim_end_matches('\\').to_lowercase();
            if ep.is_empty() {
                continue;
            }
            if ex.get("type").and_then(|t| t.as_str()) == Some("dir") {
                excl_dirs.push(ep);
            } else {
                excl_files.push(ep);
            }
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
                if snapshot_mode {
                    walk_fk_snapshot(
                        Path::new(&dir), all, pattern, recurse, 0, cutoff,
                        &excl_dirs, &excl_files, skip_lock, &mut acc,
                    );
                } else {
                    walk_fk_dll(Path::new(&dir), all, pattern, recurse, cutoff, &excl_dirs, &excl_files, &mut acc, 0);
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
        .map(|(p, sz)| (crate::to_long_path(&p), sz))
        .collect();
    FkResult {
        total_size: acc.total_size,
        count: file_count,
        locked: acc.total_count - acc.deletable_count,
        files,
        truncated: acc.truncated,
        skipped_reparse: acc.skipped_reparse,
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
    std::process::exit(2);
}

/// 数据返回式入口（Tauri 进程内直调）：输出收集进内存，绝不写 stdout、绝不 exit。
/// `on_line` 为逐行回调（不含换行），供调用方边扫边推进度事件。
/// 返回 (exit_code, stdout, stderr)。
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

/// argv = [categories_json, configured_paths_json]；规则 JSON 由调用方读入
fn scan_body(argv: &[String], input: &str) -> i32 {
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

        // DISM 组件清理：非路径型条目，固定返回「可执行」状态（大小以实际执行结果为准）
        if rule.get("special").and_then(|v| v.as_str()) == Some("dism") {
            emit_dism(cat_id, rule);
            flush_stdout();
            continue;
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
            let st = get_file_key_deletable(rule, &mut plan_global_rows);
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
                ("size", st.total_size.to_string()),
                ("fileCount", st.count.to_string()),
                ("lockedCount", st.locked.to_string()),
                // R1-2 留痕：跳过的重解析点目录数。**只呈现不进判定**——
                // size/fileCount/lockedCount 三者都不看它（见 walk_fk_dll 内注释）。
                // 缺了它，用户看到清理候选比 Explorer 算的少，却无从判断少在哪。
                ("skippedReparse", st.skipped_reparse.to_string()),
                ("risk", jopt_str(rule.get("risk").and_then(|v| v.as_str()))),
                ("exists", if st.count > 0 { "true" } else { "false" }.to_string()),
                ("blockedBy", blocked_json),
            ];
            if st.truncated {
                // 方案 v1.1：引擎侧 PLAN_CAP 截断标记（main.js 收集侧「只增不清」，字段兼容）
                fields.push(("filesTruncated", "true".to_string()));
            }
            emit_item(&fields);
            for (fp, size) in &st.files {
                out_line(&format!(
                    "@@PLANFILE@@{{\"id\":{},\"path\":{},\"size\":{}}}",
                    jstr(cat_id),
                    jstr(fp),
                    size
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
        let stats = get_path_deletable_stats(&path, rule_min_age_secs(rule).map(min_age_cutoff));
        // 统计失败上报 size=null——渲染层对 null 走「—」分支，不用 0 B 冒充可清理
        let size_json = if stats.ok { stats.size.to_string() } else { "null".to_string() };
        // autoPath 命中时 size 即 autoPath 的大小，不再二次枚举
        let auto_size_json = if !auto_path.is_empty() && path == auto_path {
            size_json.clone()
        } else {
            "0".to_string()
        };
        let exists_json = if path_exists(&path) { "true" } else { "false" }.to_string();
        let name = rule.get("name").and_then(|v| v.as_str());
        let candidates_json = format!(
            "[{}]",
            path_candidates.iter().map(|c| jstr(c)).collect::<Vec<_>>().join(",")
        );

        emit_item(&[
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
            ("risk", jopt_str(rule.get("risk").and_then(|v| v.as_str()))),
            ("exists", exists_json),
            ("blockedBy", blocked_json),
        ]);
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
        };
        walk_deletable(&root, true, "*.tmp", None, &[], &[], &mut res, 0, true);
        assert_eq!(res.files.len(), 1, "浅层文件必须收到：{:?}", res.files);
        assert!(
            res.files.iter().all(|(p, _)| !p.contains("d69")),
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
        let with_files = list_deletable(root.to_str().unwrap(), "*", None, &[], &[]);
        let stats_only = list_deletable_stats(root.to_str().unwrap(), "*", None, &[], &[]);

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

    /// 审查 L-9：walk_fk_dll 的 recurse 分支同受深度上限保护。
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
        walk_fk_dll(&root, true, "*.dll", true, None, &[], &[], &mut acc, 0);
        assert_eq!(acc.files.len(), 1, "浅层文件必须收到：{:?}", acc.files);
        assert!(
            acc.files.iter().all(|(p, _)| !p.contains("d69")),
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
        walk_fk_dll(&root, true, "*.tmp", true, None, &[], &[], &mut acc, 0);
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
        walk_fk_snapshot(&root, true, "*.tmp", true, 0, None, &[], &[], true, &mut acc2);
        assert!(acc2.truncated, "快照分支撞上限必须标 truncated");
        assert_eq!(acc2.files.len(), 3, "快照分支输出必须停在上限");
        assert!(
            acc2.total_count <= 12,
            "快照分支遍历量必须远小于 {total_files}，实测 {}",
            acc2.total_count
        );

        let _ = fs::remove_dir_all(&root);
    }
}
