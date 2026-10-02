//! 蓝屏（BugCheck）历史：转储文件枚举 + minidump 里的 bugcheck 码解析 + 转储策略只读。
//!
//! 对标 RAINZ DBUG 3.5.0 的 `bsod.ps1`（它读 minidump/全内存转储 + 事件 41/1001/6008），
//! 但**只借「做什么」**：这里全程**只读**，不收它的 `crashdumpconfig`（改
//! `CrashControl\CrashDumpEnabled` 属写侧，会改变系统崩溃时的行为，不在诊断域范围内）。
//!
//! 为什么不引依赖：内核 minidump 的头部与流目录是稳定的公开结构（`MINIDUMP_HEADER` /
//! `MINIDUMP_DIRECTORY` / `MINIDUMP_EXCEPTION_STREAM`），取 bugcheck 码只需要前几十字节
//! 的偏移计算，手写解析器足够且可控 —— 引一个 dump 解析 crate 只为取一个 u32 不划算，
//! 也让「执行面每个二进制都可审」这条本仓纪律多一个外部依赖。
//!
//! v0.4.9 起（RAINZ 对标 §3.1）：bugcheck 符号名不再是硬编码 31 条，而是
//! `include_str!("../../../data/bugcheck-codes.json")` 加载 88 条 + 6 条兜底归类。
//! 真源在 `tools/bugcheck-codes.source.mjs`；产物 ⇄ 源 的对拍钉在 `check-data-parity.mjs` P5，
//! 语义与「trim 旧 28 条硬编码全在新表里」的正向对照钉在 `check-bugcheck-codes.mjs`。
//! 之所以从 `static` 数组改成 `OnceLock` 里的解析结果：文案是中文长字符串 + 变长 causes，
//! `&'static` 数组写起来要么泄漏字符串、要么用 `phf` 之类额外依赖，`OnceLock` 一次反序列化
//! 拿到 `'static` 引用是这条链上最省的姿势（与 `rule_schema.rs::CONTRACT_JSON` 同形）。
//!
//! 已知缺口（如实标注，不做无声兜底）：
//!  - 事件日志时间线（Kernel-Power 41 / EventLog 6008 / WER 1001）未做 —— 需要
//!    `Win32_System_EventLog` feature（属新开 feature，按 §2 要登记依赖清单）。当前用
//!    转储文件的修改时间作为崩溃时间的近似值，够回答「最近一次什么时候崩的」。
//!  - 本机（`C:\Windows\Minidump` 为空、无 `MEMORY.DMP`）**没有真实转储可验**，
//!    解析器只有手工构造的合成转储用例覆盖；真机验证待有转储的机器。

use std::sync::OnceLock;

use serde::Deserialize;

const BUGCHECK_JSON: &str = include_str!("../../../data/bugcheck-codes.json");

/// `data/bugcheck-codes.json` 的整体形态。
///
/// `preserve_order` 关掉：这份表按 code 升序生成，运行期只按 code 查、不依赖键序。
#[derive(Debug, Deserialize)]
struct BugcheckPkg {
    entries: Vec<BugcheckEntry>,
    #[serde(rename = "fallbackRules")]
    fallback_rules: Vec<FallbackRule>,
    #[serde(rename = "fallbackDefault")]
    fallback_default: FallbackDefault,
}

/// 一条 bugcheck 的完整说明。字段与 source.mjs 一一对应。
#[derive(Debug, Clone, Deserialize)]
pub struct BugcheckEntry {
    pub code: u32,
    #[allow(dead_code)] // hex 目前由 `format!("0x{code:08X}")` 现算，字段留着方便日后前端展示
    pub hex: String,
    pub name: String,
    #[allow(dead_code)] // 目前渲染三段文本时不吃 cat；分类徽章是下一批的落点（对标 §3.1 前端扩展）
    pub cat: String,
    pub meaning: String,
    pub causes: Vec<String>,
    pub solution: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FallbackRule {
    #[allow(dead_code)] // id 只给 Node 侧门禁与调试时看；Rust 侧按 cat 反查 why 即可
    pub id: String,
    pub cat: String,
    pub why: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FallbackDefault {
    pub cat: String,
    pub meaning: String,
    pub solution: String,
}

/// 表加载失败时的兜底 pkg —— 空 entries + 只保留「不编造」默认文案。
///
/// 走这条路径的唯一场景：有人手改了 `data/bugcheck-codes.json` 让 JSON 语法不合法。
/// 那时 `check-data-parity` P5 早就判红、CI/门禁跑不到构建，但**运行时不许 panic**：
/// 一个诊断子系统的表读不出来不能把整个 app 拖崩。返回空表 + 兜底 = 用户看得到
/// "0x116 未收录"（诚实），但 app 还活着。
fn empty_pkg() -> BugcheckPkg {
    BugcheckPkg {
        entries: Vec::new(),
        fallback_rules: Vec::new(),
        fallback_default: FallbackDefault {
            cat: "unknown".to_string(),
            meaning: "蓝屏码库未能加载，无法给出针对性解释。".to_string(),
            solution: "重启 Trim 或反馈该问题；同一码短期反复出现时优先怀疑最近装/更过的驱动。".to_string(),
        },
    }
}

fn pkg() -> &'static BugcheckPkg {
    static PKG: OnceLock<BugcheckPkg> = OnceLock::new();
    PKG.get_or_init(|| match serde_json::from_str::<BugcheckPkg>(BUGCHECK_JSON) {
        Ok(p) => p,
        Err(e) => {
            // 与 `rule_schema.rs:33` 同姿势：加载失败是"数据文件手改坏了"级别的事故，
            // 走本仓自己的日志（不引入 log crate），并回空表让诊断子系统降级不崩。
            crate::engine::log::write_log("error", &format!("蓝屏码库加载失败（走兜底空表）：{e}"));
            empty_pkg()
        }
    })
}

/// 一条 bugcheck 的完整说明；未收录返回 `None`。
///
/// §5 R-1「不编造」：调用方拿到 `None` 时必须渲染成"0x{code:08X}（未收录）"，
/// 不许靠 cat/其他启发式给它凑一段假解释。
pub fn bugcheck_detail(code: u32) -> Option<&'static BugcheckEntry> {
    pkg().entries.iter().find(|e| e.code == code)
}

/// 一次归类兜底命中的结果。
///
/// 只给 cat + 一句 why（源自 `fallbackRules[i].why`），**不给**具体成因列表 ——
/// 未收录的码没有可信的 causes，编造会踩 §5 R-1「不声称已验证」。
#[derive(Debug, Clone)]
pub struct FallbackHit {
    pub cat: String,
    pub why: String,
    pub solution: String,
}

/// 未命中码表时的归类兜底。判据只看**码值区间**，不看参数 —— 参数在不同码里语义漂移
/// （例：0x1E 的 Param1 = 异常码、0x7F 的 Param1 = trap 号），拿参数当判据会误伤。
/// 兜底顺序即 `fallbackRules` 在源里的顺序（越具体越靠前）。都不命中则回默认。
pub fn classify_fallback(code: u32) -> FallbackHit {
    let p = pkg();
    // 兜底顺序即"具体优先"：PAGE_FAULT 族（含 0xD5/0xD6，它们在 0xC0-0xDF 段里但语义更窄）
    // 必须排在驱动段之前，否则会被驱动段区间吃掉。source.mjs 的 6 条兜底为什么按这个顺序写，
    // 这里就是那条顺序在 Rust 侧的镜像。
    let hit: Option<&str> = match code {
        0x50 | 0xD5 | 0xD6 => Some("memory"),
        0x124 | 0x9C | 0x80 => Some("hardware"),
        0x112..=0x141 => Some("video"),
        0x7B => Some("filesystem"),
        0xC0..=0xDF => Some("driver"),
        _ => None,
    };
    if let Some(cat) = hit {
        // 用 rule 的 why 当"方向"，solution 用默认的通用建议
        let why = p
            .fallback_rules
            .iter()
            .find(|r| r.cat == cat)
            .map(|r| r.why.clone())
            .unwrap_or_else(|| "按码值区间归到该分类".to_string());
        return FallbackHit {
            cat: cat.to_string(),
            why,
            solution: p.fallback_default.solution.clone(),
        };
    }
    FallbackHit {
        cat: p.fallback_default.cat.clone(),
        why: p.fallback_default.meaning.clone(),
        solution: p.fallback_default.solution.clone(),
    }
}

/// 把一条 bugcheck 详情渲染成三段文本（供 `overview_checkup` 的 detail 字段消费）。
///
/// 为什么用**换行分隔**而不是回结构化 JSON：`check_item` 的 detail 是 `String`，
/// 前端 `checkup-row-detail` 是 `<p>` 单段文本；引入子结构会牵动 checkup 契约与前端
/// 分块渲染，与本节"零新增 IPC、复用 checks 通道"的定位不符（对标 §3.1 落法 4）。
/// 前端 CSS 加 `white-space: pre-line` 让 `\n` 生效即可。
///
/// 段的写法与 AGENTS §9.3 保持一致：**不写"已验证"**，`solution` 一律"建议 / 优先怀疑"，
/// 因为这份表是通用排查方向、不是本机复现结论。
pub fn render_detail(entry: &BugcheckEntry) -> String {
    let mut s = String::new();
    s.push_str("含义：");
    s.push_str(&entry.meaning);
    s.push_str("\n常见成因：\n");
    for c in &entry.causes {
        s.push_str("· ");
        s.push_str(c);
        s.push('\n');
    }
    s.push_str("建议：");
    s.push_str(&entry.solution);
    s.trim_end().to_string()
}

/// 未收录码的兜底文案（诚实说明 + 通用建议 + 归类方向）。
pub fn render_fallback(code: u32, hit: &FallbackHit) -> String {
    format!(
        "含义：该码（0x{code:08X}）不在收录表中；按码值区间大致归到「{}」方向。\n建议：{}\n兜底依据：{}",
        hit.cat, hit.solution, hit.why
    )
}

/// 单次蓝屏的读出的关键信息
#[derive(Debug, Clone)]
pub struct CrashRecord {
    pub path: String,
    pub size: u64,
    pub mtime_ms: i64,
    pub bugcheck: Option<u32>,
    pub params: [u64; 4],
    /// 通过 ModuleListStream 地址区间匹配出的"出错模块名"（如 `nvlddmkm.sys`）。
    /// 未定位到时 None：无模块表 / 四个参数都不是有效内核地址 / 地址不落在任何模块。
    /// 全内存转储（`MEMORY.DMP`）只解出 bugcheck、不解模块表（要读内核符号才能定位），
    /// 走的就是这条 None。
    pub crash_module: Option<String>,
    /// 命中模块的那个参数值 —— 用户想核对"是哪个地址"时有用。
    pub crash_addr: Option<u64>,
}

/// 转储策略（只读）
#[derive(Debug, Clone, Default)]
pub struct CrashControl {
    /// 与 `read_reg_dword_opt` 同型（i64），避免有损转换
    pub enabled_value: Option<i64>,
    pub minidump_dir: Option<String>,
    pub dump_file: Option<String>,
    pub auto_reboot: Option<i64>,
}

impl CrashControl {
    /// `CrashDumpEnabled` 的取值语义（0=不转储，1=完整，2=内核，3=小内存转储，7=自动）
    pub fn mode_text(&self) -> &'static str {
        match self.enabled_value {
            Some(0) => "未启用（蓝屏不会留下转储）",
            Some(1) => "完整内存转储",
            Some(2) => "内核内存转储",
            Some(3) => "小内存转储（256 KB）",
            Some(7) => "自动（系统决定）",
            _ => "未知",
        }
    }
    pub fn dump_enabled(&self) -> bool {
        // 取不到值不当「已启用」——「查不到」不许等价于「安全」（同 §4 fail-closed 口径）
        matches!(self.enabled_value, Some(v) if v != 0)
    }
}

const MDMP_SIGNATURE: u32 = 0x504D_444D; // "MDMP"
const STREAM_MODULE_LIST: u32 = 4;
const STREAM_EXCEPTION: u32 = 6;

// DUMP_HEADER64（`MEMORY.DMP`，Windows 8+ x64 布局）：
//   +0x20 = 'PAGE'（LE u32 0x45474150）+0x28 = 'DUMP'（LE u32 0x504D5544）
//   +0x98 = BugCheckCode(u32)；+0xA0 = BugCheckParameter1..4(u64[4])
// 不读 x86/老 ARM 布局，本机 x64 用不到，且判据里加"两个 4 字节 magic 都要对"能避免
// 把 minidump 头误认成全内存转储头（两者都可能有 'PAGE'/'DUMP' 单串巧合）。
const FULL_DUMP_SIG_PAGE: u32 = 0x4547_4150;
const FULL_DUMP_SIG_DUMP: u32 = 0x504D_5544;
const FULL_DUMP_BUGCHECK_CODE_OFF: usize = 0x98;
const FULL_DUMP_BUGCHECK_PARAMS_OFF: usize = 0xA0;

fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd_u64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| {
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}

/// minidump 头部通用信息：`(stream_count, dir_rva, pointer_size)`。
/// PointerSize 决定 `MINIDUMP_MODULE` 结构步长（x86=108 / x64=124），也决定
/// `MINIDUMP_LOCATION_DESCRIPTOR` 是 8 字节还是 16 字节 —— 这是本文件里唯一的
/// 架构判据，不再另引 `MINIDUMP_SYSTEM_INFO`。
/// 畸形 stream 数与非法 pointer size 都直接判"不认"，不做部分成功。
fn minidump_meta(bytes: &[u8]) -> Option<(usize, usize, u32)> {
    if rd_u32(bytes, 0)? != MDMP_SIGNATURE {
        return None;
    }
    let streams = rd_u32(bytes, 8)? as usize;
    let dir_rva = rd_u32(bytes, 12)? as usize;
    let pointer_size = rd_u64(bytes, 32)? as u32;
    if streams == 0 || streams > 1024 {
        return None;
    }
    if pointer_size != 4 && pointer_size != 8 {
        return None;
    }
    Some((streams, dir_rva, pointer_size))
}

/// 在流目录里找指定 stream type，返回它的 DataSize 与 Rva。
fn find_stream(bytes: &[u8], want: u32) -> Option<(usize, usize)> {
    let (streams, dir_rva, _) = minidump_meta(bytes)?;
    for i in 0..streams {
        let off = dir_rva.checked_add(i.checked_mul(12)?)?;
        if rd_u32(bytes, off)? != want {
            continue;
        }
        let data_size = rd_u32(bytes, off + 4)? as usize;
        let rva = rd_u32(bytes, off + 8)? as usize;
        return Some((data_size, rva));
    }
    None
}

/// 从内核 minidump（含 `MEMORY.DMP` 这类内核转储）里取出 `(bugcheck 码, 4 个参数)`。
///
/// 布局（全部小端，偏移相对各结构起点）：
/// ```text
/// MINIDUMP_HEADER        0:Signature(u32) 4:Version 8:NumberOfStreams 12:StreamDirectoryRva
///                                                     32:PointerSize(u64)
/// MINIDUMP_DIRECTORY     +0:StreamType(u32) +4:DataSize(u32) +8:Rva(u32)   // 每项 12 字节
/// MINIDUMP_EXCEPTION     +0:ExceptionCode(u32) … +32:ExceptionInformation[15](u64)
/// → 异常流内 ExceptionCode 在流起点 +8，参数 1..4 在流起点 +40/+48/+56/+64
/// ```
///
/// 任何一处越界/签名不符都返回 `None`（不猜、不部分成功）。
pub fn parse_minidump_bugcheck(bytes: &[u8]) -> Option<(u32, [u64; 4])> {
    let (_, rva) = find_stream(bytes, STREAM_EXCEPTION)?;
    // MINIDUMP_EXCEPTION_STREAM: ThreadId(4) + __alignment(4) 之后是 MINIDUMP_EXCEPTION
    let code = rd_u32(bytes, rva.checked_add(8)?)?;
    let mut params = [0u64; 4];
    for (k, p) in params.iter_mut().enumerate() {
        *p = rd_u64(bytes, rva.checked_add(8 + 32 + k * 8)?)?;
    }
    Some((code, params))
}

/// 一个模块（驱动 / ntoskrnl 等）在转储里记录的基址与大小。
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u32,
}

/// 读 MINIDUMP_STRING：`DataLength(u32)` + UTF-16LE 字节。
/// 上限 4096 字节（≈2048 字符）：Windows 路径名不可能更长，超过就是畸形 RVA。
fn read_minidump_string(bytes: &[u8], rva: usize) -> Option<String> {
    let len_bytes = rd_u32(bytes, rva)? as usize;
    if len_bytes == 0 || len_bytes > 4096 || len_bytes % 2 != 0 {
        return None;
    }
    let start = rva.checked_add(4)?;
    let end = start.checked_add(len_bytes)?;
    let raw = bytes.get(start..end)?;
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// 解析 ModuleListStream（type=4）。返回按转储里出现顺序的模块列表。
///
/// `MINIDUMP_MODULE` 每项步长随 PointerSize 变：
/// ```text
/// BaseOfImage(u64) SizeOfImage(u32) CheckSum(u32) TimeDateStamp(u32) ModuleNameRva(u32)
/// VsFixedFileInfo(52B) CvRecord(8|16B) MiscRecord(8|16B) Reserved0(u64) Reserved1(u64)
/// → x86 108 / x64 124
/// ```
/// 头/数量字段：`MINIDUMP_MODULE_LIST { NumberOfModules(u32); Modules[] }`。
/// 上限 4096 项：内核 minidump 一般几百个模块，超过就是畸形计数。
pub fn parse_minidump_modules(bytes: &[u8]) -> Vec<ModuleInfo> {
    let (_, _, pointer_size) = match minidump_meta(bytes) {
        Some(m) => m,
        None => return Vec::new(),
    };
    let module_size = match pointer_size {
        4 => 108usize,
        8 => 124usize,
        _ => return Vec::new(),
    };
    let (_, list_rva) = match find_stream(bytes, STREAM_MODULE_LIST) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let count = match rd_u32(bytes, list_rva) {
        Some(c) => c as usize,
        None => return Vec::new(),
    };
    if count == 0 || count > 4096 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(count.min(512));
    for k in 0..count {
        let Some(off) = list_rva
            .checked_add(4)
            .and_then(|o| o.checked_add(k.checked_mul(module_size)?))
        else {
            break;
        };
        let Some(base) = rd_u64(bytes, off) else { break };
        let Some(size) = rd_u32(bytes, off + 8) else { break };
        let Some(name_rva) = rd_u32(bytes, off + 20) else { break };
        let name = read_minidump_string(bytes, name_rva as usize).unwrap_or_default();
        out.push(ModuleInfo { name, base, size });
    }
    out
}

/// 在四个 bugcheck 参数里找一个能落到某模块 `[base, base+size)` 区间内的地址。
///
/// 为什么遍历全部四个而不是硬编码"参数 X 才是出错地址"：
///  - 0xA/0xD1：参数 4 是出错地址、参数 1 是被访问地址
///  - 0x50：参数 0 是被访问地址
///  - 0x116：参数 1 是 GPU 设备对象指针、不一定落在模块区间
///  - 0x1E：参数 1 是出错指令地址
/// 不同码语义漂移；把四个都试一遍、取第一个命中的，是**保守且可解释**的策略
/// （Rainz 的 bsod.ps1 也是这个姿势）。都不命中就 None，不猜。
pub fn locate_crash_module(params: &[u64; 4], modules: &[ModuleInfo]) -> (Option<String>, Option<u64>) {
    for &addr in params {
        if addr == 0 {
            continue;
        }
        for m in modules {
            let end = m.base.saturating_add(m.size as u64);
            if addr >= m.base && addr < end {
                return (Some(m.name.clone()), Some(addr));
            }
        }
    }
    (None, None)
}

/// 从 `MEMORY.DMP`（全内存 / 内核转储）头部解出 bugcheck 码与四个参数。
///
/// **不解模块表**：全内存转储的模块链要靠 `_KdDebuggerDataBlock` + `PsLoadedModuleList`
/// 遍历，需要内核符号（PDB），不是"读前 N 字节"能拿到的 —— 那是 WinDbg 的活。
/// 诚实边界：这里只给码 + 四个参数，前端要区分"minidump vs full dump"由调用方看 path 尾缀判。
pub fn parse_full_dump_bugcheck(bytes: &[u8]) -> Option<(u32, [u64; 4])> {
    if rd_u32(bytes, 0x20)? != FULL_DUMP_SIG_PAGE {
        return None;
    }
    if rd_u32(bytes, 0x28)? != FULL_DUMP_SIG_DUMP {
        return None;
    }
    let code = rd_u32(bytes, FULL_DUMP_BUGCHECK_CODE_OFF)?;
    // 全零意味着"没崩过"或"结构版本差异"，不猜
    if code == 0 {
        return None;
    }
    let mut params = [0u64; 4];
    for (k, p) in params.iter_mut().enumerate() {
        *p = rd_u64(bytes, FULL_DUMP_BUGCHECK_PARAMS_OFF.checked_add(k.checked_mul(8)?)?)?;
    }
    Some((code, params))
}

/// bugcheck 码 → 英文名。**薄封装**：从 `data/bugcheck-codes.json` 查；未收录一律 `None`
/// 由调用方渲染成十六进制（§9.3：不拿推断当实测）。
///
/// 保留这个函数而不是让调用方直接 `bugcheck_detail(code).map(|e| e.name)`：
/// 上一版硬编码 31 条时的所有调用点与 4 条旧测试都吃 `Option<&'static str>`，
/// 签名不动它们一行不用改（对标 §3.1 落法 2）。
///
/// 现在生产路径已经改吃 `bugcheck_detail`（diagnostics.rs 需要完整三段），
/// 本函数只被测试与"未来可能的短名消费者"用到，故 `#[allow(dead_code)]`。
#[allow(dead_code)]
pub fn bugcheck_name(code: u32) -> Option<&'static str> {
    bugcheck_detail(code).map(|e| e.name.as_str())
}

/// 一次采集的完整结果（记录 + 策略 + 读取失败原因）
#[derive(Debug, Clone, Default)]
pub struct CrashHistory {
    /// 新的在前
    pub records: Vec<CrashRecord>,
    pub control: CrashControl,
    /// 转储目录存在但读不动时的原因；`None` = 没出错
    pub read_error: Option<String>,
}

/// 只读读取转储策略
///
/// 两个路径值用 `read_reg_value_text` 而不是 `read_reg_string`：`MinidumpDir` / `DumpFile`
/// 在本机与多数机器上是 **`REG_EXPAND_SZ`**（值形如 `%SystemRoot%\Minidump`），
/// `read_reg_string` 只接受 `REG_SZ`，会静默返回 None —— 那会让「读到了路径」与「没读到」
/// 在回执里长得一样，且展示的是未展开的 `%SystemRoot%` 而不是用户看得懂的绝对路径。
pub fn crash_control() -> CrashControl {
    use crate::engine::native::registry::{hive_hklm, read_reg_dword_opt, read_reg_value_text};
    let sub = "SYSTEM\\CurrentControlSet\\Control\\CrashControl";
    let text = |name: &str| {
        read_reg_value_text(hive_hklm(), sub, name)
            .map(|(_, v)| v)
            .filter(|v| !v.trim().is_empty())
    };
    CrashControl {
        enabled_value: read_reg_dword_opt(hive_hklm(), sub, "CrashDumpEnabled"),
        minidump_dir: text("MinidumpDir"),
        dump_file: text("DumpFile"),
        auto_reboot: read_reg_dword_opt(hive_hklm(), sub, "AutoReboot"),
    }
}

/// 读取一个转储文件时最多读多少字节
///
/// 小内存转储 ≤256 KB，头部与流目录在文件开头；`MEMORY.DMP` 可达数 GB，
/// 整文件读进来只为取一个 u32 是不能接受的（本机崩溃转储常见 1–8 GB）。
const MAX_DUMP_READ: u64 = 4 * 1024 * 1024;

fn read_dump_head(path: &std::path::Path, size: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let take = size.min(MAX_DUMP_READ) as usize;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; take];
    let mut got = 0usize;
    while got < take {
        match f.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return None,
        }
    }
    buf.truncate(got);
    Some(buf)
}

fn collect_from(path: &std::path::Path, out: &mut Vec<CrashRecord>) {
    let Ok(md) = std::fs::metadata(path) else { return };
    if !md.is_file() {
        return;
    }
    let size = md.len();
    let mtime_ms = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    // 一份 head 最多只解一次：先按 minidump 走（有流目录，能同时拿 bugcheck 与模块表），
    // 失败再按 DUMP_HEADER64 走（只拿 bugcheck，不拿模块）。二者互斥（signature 不同），
    // 不出现"都能解出但内容不一样"的歧义。
    let head = read_dump_head(path, size);
    let (bugcheck, params, modules) = match head.as_deref() {
        Some(b) => {
            if let Some((c, p)) = parse_minidump_bugcheck(b) {
                (Some(c), p, parse_minidump_modules(b))
            } else if let Some((c, p)) = parse_full_dump_bugcheck(b) {
                // 全内存/内核转储：只解 bugcheck；模块链要内核符号，本轮诚实不做
                (Some(c), p, Vec::new())
            } else {
                (None, [0; 4], Vec::new())
            }
        }
        None => (None, [0; 4], Vec::new()),
    };
    let (crash_module, crash_addr) = if modules.is_empty() {
        (None, None)
    } else {
        locate_crash_module(&params, &modules)
    };
    out.push(CrashRecord {
        path: path.display().to_string(),
        size,
        mtime_ms,
        bugcheck,
        params,
        crash_module,
        crash_addr,
    });
}

/// 枚举本机的崩溃转储并逐个取 bugcheck。
///
/// 目录与文件路径**取自 `CrashControl` 的实际配置**（`MinidumpDir` / `DumpFile`），
/// 取不到才回落 `%SystemRoot%` 下的默认位置 —— 用户改过转储落点时也能扫到。
pub fn crash_history() -> CrashHistory {
    let cc = crash_control();
    let sys_root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));

    let minidir = cc
        .minidump_dir
        .as_deref()
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| sys_root.join("Minidump"));

    let mut out: Vec<CrashRecord> = Vec::new();
    let mut read_error: Option<String> = None;

    match std::fs::read_dir(&minidir) {
        Ok(rd) => {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().map(|x| x.eq_ignore_ascii_case("dmp")).unwrap_or(false) {
                    collect_from(&p, &mut out);
                }
            }
        }
        Err(_) => {
            // 目录不存在是正常情况（从没蓝屏过）；存在却读不动才是异常
            if minidir.exists() {
                read_error = Some(format!("无法读取转储目录 {}", minidir.display()));
            }
        }
    }

    // 内核/完整内存转储
    let kernel_dump = cc
        .dump_file
        .as_deref()
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| sys_root.join("MEMORY.DMP"));
    // 小内存转储模式下 DumpFile 可能指向 MEMORY.DMP 而文件不存在；存在才收
    collect_from(&kernel_dump, &mut out);

    // 新的在前：崩溃时间近似取文件修改时间（事件日志时间线未做，见文件头缺口说明）
    out.sort_by(|a, b| b.mtime_ms.cmp(&a.mtime_ms));

    CrashHistory { records: out, control: cc, read_error }
}

/// 崩溃时间的可读化：相对现在多久之前。
///
/// 刻意用相对时间而不是绝对时间戳：崩溃检查要回答的是「最近一次是什么时候崩的」，
/// 而转储文件的修改时间只是**近似**的崩溃时间（见文件头缺口说明），精确到分钟会让人
/// 误以为它是权威时间；相对量既够用，也不必在此引入时区换算。
pub fn age_text(mtime_ms: i64, now_ms: i64) -> String {
    let d = now_ms.saturating_sub(mtime_ms);
    if d < 0 {
        return "时间戳晚于当前时间（时钟被调整过）".to_string();
    }
    let mins = d / 60_000;
    if mins < 1 {
        "刚刚".to_string()
    } else if mins < 60 {
        format!("{mins} 分钟前")
    } else if mins < 60 * 24 {
        format!("{} 小时前", mins / 60)
    } else {
        format!("{} 天前", mins / (60 * 24))
    }
}

// ===== v0.4.9 §3.3 崩溃事件时间线 =====

/// 一条与崩溃相关的系统事件（Kernel-Power 41 / EventLog 6008 / WER-BugCheck 1001）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub provider: String,
    pub event_id: u16,
    pub time_ms: i64,
    /// EventID=1001 时 `<Data>` 里通常带 `0x00000116` 之类的 bugcheck 码；其他事件 None。
    pub bugcheck: Option<u32>,
}

/// 从 `EvtRender` 输出的 XML 里抽字段。**纯函数**，无 Win32 依赖，可单测。
///
/// 不引 `quick-xml` 之类第三方：本文件里唯一"要解析 XML"的场景就是这三类事件的固定字段
/// （`EventID` / `Provider Name` / `TimeCreated SystemTime` / 第一个 `<Data>` 里的 0x 串），
/// 手写扫描比引第三方更**可审**（对标 §9.1 反向条款：不给产物加不可读依赖）。
/// 任一必需字段缺失即整体返回 None，让调用方跳过；不猜。
pub fn parse_event_xml(xml: &str) -> Option<EventRecord> {
    let event_id = xml_text_i32(xml, "EventID")? as u16;
    let time_ms = xml_time_ms(xml)?;
    let provider = xml_attr(xml, "Provider", "Name")?;
    let bugcheck = xml_data_hex0x(xml);
    Some(EventRecord {
        provider,
        event_id,
        time_ms,
        bugcheck,
    })
}

/// 抓 `<tag ... attr="value" .../>` 里的 value。
///
/// 支持单引号或双引号包裹的属性值：微软 EvtRender 输出实测是**双引号**，但测试夹具
/// 与人工样本常写成单引号，宽容处理避免"改 XML 引号风格 → 解析全 None" 这种脆弱。
fn xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = xml.find(&open)? + open.len();
    let rest = &xml[start..];
    let end = rest.find(['>', '/'])?;
    let head = &rest[..end];
    let key = format!("{attr}=");
    let ki = head.find(&key)? + key.len();
    let quote = *head.as_bytes().get(ki)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let val_start = ki + 1;
    let q = quote as char;
    let ve = head[val_start..].find(q)?;
    Some(head[val_start..val_start + ve].to_string())
}

fn xml_text_i32(xml: &str, tag: &str) -> Option<i32> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    xml[s..e].trim().parse::<i32>().ok()
}

/// `<TimeCreated SystemTime="2026-10-03T10:20:30.1234567Z"/>` → epoch ms。
///
/// 手工切固定宽度字段并走 `days_from_civil`（Howard Hinnant 算法）：只关心**相对时间**，
/// 亚秒与闰秒都不影响"最近 3 天前"这类展示；不引 chrono 是给一个字符串省一整层依赖。
fn xml_time_ms(xml: &str) -> Option<i64> {
    let s = xml_attr(xml, "TimeCreated", "SystemTime")?;
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |a: usize, z: usize| -> Option<i64> {
        std::str::from_utf8(&b[a..z]).ok()?.parse::<i64>().ok()
    };
    let y = num(0, 4)?;
    let mo = num(5, 7)?;
    let d = num(8, 10)?;
    let h = num(11, 13)?;
    let mi = num(14, 16)?;
    let se = num(17, 19)?;
    Some(days_from_civil(y, mo, d) * 86_400_000 + (h * 3600 + mi * 60 + se) * 1000)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    // Howard Hinnant《How to Find days_from_civil》：把 (Y,M,D) 转成距 1970-01-01 的天数。
    let yy = if m <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // 以 3 月为首
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 抓 `<Data>` 段里第一个 `0x...` 十六进制串（EventID=1001 里的 bugcheck 码）。
fn xml_data_hex0x(xml: &str) -> Option<u32> {
    let idx = xml.find("<Data")?;
    let rest = &xml[idx..];
    let hex_at = rest.find("0x")? + 2;
    let after = &rest[hex_at..];
    let mut n: u32 = 0;
    let mut any = false;
    for b in after.bytes() {
        let v = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'a'..=b'f' => (b - b'a') as u32 + 10,
            b'A'..=b'F' => (b - b'A') as u32 + 10,
            _ => break,
        };
        n = n.saturating_mul(16).saturating_add(v);
        any = true;
        if n > 0x00FF_FFFF {
            // bugcheck 通常 ≤ 8 位；防溢出（也顺带避开 `0xFFFFFFFFFFFFFFFF` 这类内核指针）
            break;
        }
    }
    if any { Some(n) } else { None }
}

/// 从 Windows 事件日志读近 `days_back` 天的崩溃相关事件。
///
/// 三类事件（对标报告 §3.3 落法）：
///  - **Kernel-Power 41**：意外关机（含蓝屏后重启）——「这台机器有一次崩溃式重启」的锚点
///  - **EventLog 6008**：上一次系统意外关机 —— 与 41 互补（41 是"发生了"、6008 是"重启后回看"）
///  - **Microsoft-Windows-WER-SystemErrorReporting 1001**：BugCheck 上报，`<Data>` 里带码
///
/// **失败一律返回空向量**（不 log::error! —— 每次 checkup 都跑，报错会灌脏"操作日志"）。
/// 判"能读到东西"的责任在调用方：拿空数组就按"无时间线可展示"处理，与 hist.records 独立。
/// 真机验证需要有一次 41/6008/1001 记录 —— 小旭的机器几乎肯定有（任何硬关机都会记），
/// 但 CI/测试机不一定，所以真跑用例进 `#[ignore]` 发布前门禁组。
pub fn event_timeline(days_back: u32) -> Vec<EventRecord> {
    use super::common::to_wide;
    use core::ffi::c_void;
    use windows::Win32::System::EventLog::{
        EvtClose, EvtCreateRenderContext, EvtNext, EvtQuery, EvtRender, EVT_HANDLE,
        EvtQueryChannelPath, EvtQueryReverseDirection, EvtRenderEventXml,
    };

    let ms_back = (days_back as i64).saturating_mul(86_400_000);
    // XPath：`EventID ∈ {41,6008,1001}` 且 `TimeCreated` 在近 N 天内。
    // `timediff(@SystemTime)` 单位是 100ns（FILETIME tick）—— 这里把 ms 换成 ticks。
    let ticks_back = ms_back.saturating_mul(10_000);
    let xpath = format!(
        "*[System[(EventID=41 or EventID=6008 or EventID=1001) and TimeCreated[timediff(@SystemTime) <= {ticks_back}]]]"
    );
    let channel = to_wide("System");
    let query_w = to_wide(&xpath);

    let mut out: Vec<EventRecord> = Vec::new();
    unsafe {
        let q = match EvtQuery(
            None,
            windows::core::PCWSTR(channel.as_ptr()),
            windows::core::PCWSTR(query_w.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        ) {
            Ok(h) => h,
            Err(_) => return out,
        };
        // EvtCreateRenderContext(Option<&[PCWSTR]>, flags=u32)：`None + 0` = 完整 XML 渲染
        let ctx = match EvtCreateRenderContext(None, 0) {
            Ok(c) => c,
            Err(_) => {
                let _ = EvtClose(q);
                return out;
            }
        };
        // 0.61 里 EvtNext 的 `events` 是 `&mut [isize]`（EVT_HANDLE 是 newtype(isize)，
        // 直接按 isize 数组接回来）；一次最多 8 条，够呈现"最近三条"。
        const BATCH: usize = 8;
        let mut handles: [isize; BATCH] = [0; BATCH];
        let mut returned: u32 = 0;
        let next = EvtNext(q, &mut handles, 3000, 0, &mut returned);
        if next.is_ok() {
            for i in 0..returned.min(BATCH as u32) as usize {
                let h = EVT_HANDLE(handles[i]);
                // 探长度 → 分配 → 再渲染
                let mut used = 0u32;
                let mut props = 0u32;
                let _ = EvtRender(
                    Some(ctx),
                    h,
                    EvtRenderEventXml.0,
                    0,
                    None,
                    &mut used,
                    &mut props,
                );
                if used == 0 {
                    let _ = EvtClose(h);
                    continue;
                }
                let mut buf: Vec<u16> = vec![0u16; used as usize / 2 + 1];
                let r = EvtRender(
                    Some(ctx),
                    h,
                    EvtRenderEventXml.0,
                    used,
                    Some(buf.as_mut_ptr() as *mut c_void),
                    &mut used,
                    &mut props,
                );
                let _ = EvtClose(h);
                if r.is_err() {
                    continue;
                }
                let s = String::from_utf16_lossy(&buf[..(used as usize / 2).saturating_sub(1)]);
                if let Some(rec) = parse_event_xml(&s) {
                    out.push(rec);
                }
            }
        }
        let _ = EvtClose(ctx);
        let _ = EvtClose(q);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工构造一个最小内核 minidump：头部（40 字节，PointerSize=x64） + 一个异常流目录项 + 异常记录。
    /// 本机没有真实转储可验，所以这个合成件是解析器唯一的行为证据（缺口已在文件头写明）。
    fn synth_dump(bugcheck: u32, params: [u64; 4]) -> Vec<u8> {
        let dir_rva = 40usize; // 头 40 字节
        let stream_rva = dir_rva + 12; // 目录项之后紧跟异常流
        let mut b = vec![0u8; stream_rva + 152];
        b[0..4].copy_from_slice(&MDMP_SIGNATURE.to_le_bytes());
        b[4..8].copy_from_slice(&0xA793u32.to_le_bytes()); // Version
        b[8..12].copy_from_slice(&1u32.to_le_bytes()); // NumberOfStreams
        b[12..16].copy_from_slice(&(dir_rva as u32).to_le_bytes());
        b[32..40].copy_from_slice(&8u64.to_le_bytes()); // PointerSize = 8 (x64)
        // 目录项
        b[dir_rva..dir_rva + 4].copy_from_slice(&STREAM_EXCEPTION.to_le_bytes());
        b[dir_rva + 4..dir_rva + 8].copy_from_slice(&152u32.to_le_bytes()); // DataSize
        b[dir_rva + 8..dir_rva + 12].copy_from_slice(&(stream_rva as u32).to_le_bytes());
        // 异常流：ThreadId(4) + alignment(4) + ExceptionCode
        b[stream_rva + 8..stream_rva + 12].copy_from_slice(&bugcheck.to_le_bytes());
        for (k, p) in params.iter().enumerate() {
            let o = stream_rva + 8 + 32 + k * 8;
            b[o..o + 8].copy_from_slice(&p.to_le_bytes());
        }
        b
    }

    #[test]
    fn 合成转储能读出_bugcheck_与四个参数() {
        let b = synth_dump(0x0000_007E, [0xFFFF_F800_1234_5678, 0xFFFF_F800_9ABC_DEF0, 0, 0]);
        let got = parse_minidump_bugcheck(&b).expect("合成转储应能解析");
        assert_eq!(got.0, 0x7E);
        assert_eq!(got.1[0], 0xFFFF_F800_1234_5678);
        assert_eq!(got.1[1], 0xFFFF_F800_9ABC_DEF0);
        assert_eq!(got.1[2], 0);
        assert_eq!(bugcheck_name(got.0), Some("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"));
    }

    /// 反向：签名不符 / 截断 / 流目录越界都必须回 None，不许猜出一个码。
    #[test]
    fn 畸形或截断的转储一律拒判() {
        // 签名不符
        let mut bad = synth_dump(0x7E, [0; 4]);
        bad[0] = 0;
        assert!(parse_minidump_bugcheck(&bad).is_none(), "签名不符仍解析出码");

        // 只有头部、没有目录
        let head_only = &synth_dump(0x7E, [0; 4])[..32];
        assert!(parse_minidump_bugcheck(head_only).is_none(), "截断到头部仍解析出码");

        // 流目录 RVA 指到文件之外
        let mut oob = synth_dump(0x7E, [0; 4]);
        oob[12..16].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(parse_minidump_bugcheck(&oob).is_none(), "越界 RVA 仍解析出码");

        // 流数畸形（0 / 超大）
        let mut zero = synth_dump(0x7E, [0; 4]);
        zero[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_minidump_bugcheck(&zero).is_none());
        let mut huge = synth_dump(0x7E, [0; 4]);
        huge[8..12].copy_from_slice(&99_999u32.to_le_bytes());
        assert!(parse_minidump_bugcheck(&huge).is_none());

        // PointerSize 只认 4/8；0 或 16 都不接（v0.4.9 §3.2：架构判据唯一入口，
        // 一旦放行非 4/8 就会算错模块步长，让整张模块表漂成随机字节）
        for bad in [0u64, 16, 0xFFFF_FFFF] {
            let mut b = synth_dump(0x7E, [0; 4]);
            b[32..40].copy_from_slice(&bad.to_le_bytes());
            assert!(
                parse_minidump_bugcheck(&b).is_none(),
                "PointerSize={bad} 仍解析出码"
            );
        }

        // 空输入
        assert!(parse_minidump_bugcheck(&[]).is_none());
    }

    #[test]
    fn 未收录的_bugcheck_码不编造名字() {
        assert_eq!(bugcheck_name(0x0000_1234), None);
        assert_eq!(bugcheck_name(0x0), None);
        // 已收录的几个常见码
        assert_eq!(bugcheck_name(0xA), Some("IRQL_NOT_LESS_OR_EQUAL"));
        assert_eq!(bugcheck_name(0x124), Some("WHEA_UNCORRECTABLE_ERROR"));
        assert_eq!(bugcheck_name(0x133), Some("DPC_WATCHDOG_VIOLATION"));
    }

    #[test]
    fn 转储未启用不算已启用() {
        // “查不到”不许等价于“已启用”（fail-closed）
        assert!(!CrashControl::default().dump_enabled());
        assert!(!CrashControl { enabled_value: Some(0), ..Default::default() }.dump_enabled());
        assert!(CrashControl { enabled_value: Some(3), ..Default::default() }.dump_enabled());
    }

    #[test]
    fn 崩溃时间相对量分档() {
        let now = 1_700_000_000_000i64;
        assert_eq!(age_text(now - 30_000, now), "刚刚");
        assert_eq!(age_text(now - 5 * 60_000, now), "5 分钟前");
        assert_eq!(age_text(now - 3 * 3_600_000, now), "3 小时前");
        assert_eq!(age_text(now - 2 * 86_400_000, now), "2 天前");
        // 时钟回拨不许产出「-3 天前」这种鬼话
        assert!(age_text(now + 60_000, now).contains("晚于当前时间"));
    }

    // ===== v0.4.9 蓝屏码库（RAINZ 对标 §3.1）=====

    #[test]
    fn 收录表的每条都有完整六字段() {
        // 反解 include_str! 的 JSON 并逐条检查：这是运行时的**结构合法性**证据。
        // 语义合法（长度上下限、code 不重复等）由 Node 侧 check-bugcheck-codes.mjs 钉；
        // Rust 侧只保证"能读到、字段齐"，避免 include_str! 打包时被裁空。
        assert!(
            !pkg().entries.is_empty(),
            "收录表为空 —— include_str! 路径错或 JSON 解析走了兜底空表"
        );
        for e in &pkg().entries {
            assert!(!e.name.is_empty(), "0x{:X} name 空", e.code);
            assert!(!e.cat.is_empty(), "0x{:X} cat 空", e.code);
            assert!(!e.meaning.is_empty(), "0x{:X} meaning 空", e.code);
            assert!(!e.causes.is_empty(), "0x{:X} causes 空", e.code);
            assert!(!e.solution.is_empty(), "0x{:X} solution 空", e.code);
        }
    }

    #[test]
    fn 常见码能查到含义() {
        let e = bugcheck_detail(0x116).expect("0x116 VIDEO_TDR_FAILURE 应收录");
        assert_eq!(e.name, "VIDEO_TDR_FAILURE");
        assert_eq!(e.cat, "video");
        assert!(e.meaning.contains("TDR"), "0x116 meaning 应讲 TDR：{}", e.meaning);
        assert!(e.solution.contains("nvlddmkm") || e.solution.contains("驱动"),
            "0x116 solution 应给具体动作：{}", e.solution);
    }

    #[test]
    fn 未收录码不编造含义() {
        // 拿一个几乎肯定不存在的假码；detail 必须 None，走 classify_fallback 也不给具体 causes
        assert!(bugcheck_detail(0x1234_5678).is_none());
        assert!(bugcheck_name(0x1234_5678).is_none());
        let hit = classify_fallback(0x1234_5678);
        assert_eq!(hit.cat, "unknown", "假码不该被兜底规则错误命中：{hit:?}");
    }

    #[test]
    fn 兜底归类按码值区间命中() {
        // 0xD1 已被具体码表命中；拿一个不在表里但**在** 0xC0-0xDF 段的假码测兜底通道
        let hit = classify_fallback(0xCD);
        assert_eq!(hit.cat, "driver", "0xC0-0xDF 段兜底应归到 driver：{hit:?}");
        // 0x113 具体表里有（VIDEO_DXGKRNL_FATAL_ERROR）；拿 0x114 测 video 兜底
        let hit = classify_fallback(0x114);
        assert_eq!(hit.cat, "video", "0x112-0x141 段兜底应归到 video：{hit:?}");
        // 0x124 具体表里有；拿 0x125 测 —— 0x125 也在表里（MANUALLY_INITIATED_CRASH），
        // 所以直接测一个 0x9C 附近的：0x9B 不在表、也不在区间，走默认
        let hit = classify_fallback(0x9B);
        assert_eq!(hit.cat, "unknown");
    }

    #[test]
    fn 三段渲染有分隔不换行不吞字() {
        let e = bugcheck_detail(0xD1).expect("0xD1 应收录");
        let s = render_detail(e);
        assert!(s.starts_with("含义："), "渲染要以「含义：」开头，实际：{}", &s[..20.min(s.len())]);
        assert!(s.contains("\n常见成因：\n"), "缺成因段：{s}");
        assert!(s.contains("\n建议："), "缺建议段：{s}");
        // causes 至少一条被渲染成 "· xxx"
        assert!(s.contains("· "), "causes 应渲染成圆点列表：{s}");
        // trim_end 生效：末尾不许拖 \n（前端 <p> 会显出多余空隙）
        assert!(!s.ends_with('\n'), "末尾不应留换行：{s}");
    }

    #[test]
    fn 兜底文案诚实说未收录() {
        let hit = classify_fallback(0x1234_5678);
        let s = render_fallback(0x1234_5678, &hit);
        assert!(s.contains("不在收录表"), "兜底要明说未收录：{s}");
        assert!(s.contains("0x12345678"), "兜底要带十六进制码：{s}");
    }

    /// 与旧硬编码 28 条对齐 —— Node 侧 `check-bugcheck-codes.mjs` 断言 ③ 的 Rust 侧镜像。
    /// 只测**能查到且名字对**：不测"未命中就 panic"（那走 bugcheck_name 返回 None 的正常路径）。
    #[test]
    fn 旧硬编码28条在新表里名字未漂() {
        let cases = [
            (0x0a, "IRQL_NOT_LESS_OR_EQUAL"),
            (0x18, "REFERENCE_BY_POINTER"),
            (0x1a, "MEMORY_MANAGEMENT"),
            (0x1e, "KMODE_EXCEPTION_NOT_HANDLED"),
            (0x3b, "SYSTEM_SERVICE_EXCEPTION"),
            (0x4e, "PFN_LIST_CORRUPT"),
            (0x50, "PAGE_FAULT_IN_NONPAGED_AREA"),
            (0x7e, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"),
            (0x7f, "UNEXPECTED_KERNEL_MODE_TRAP"),
            (0x9f, "DRIVER_POWER_STATE_FAILURE"),
            (0xa5, "ACPI_BIOS_ERROR"),
            (0xbe, "ATTEMPTED_WRITE_TO_READONLY_MEMORY"),
            (0xc2, "BAD_POOL_CALLER"),
            (0xc4, "DRIVER_VERIFIER_DETECTED_VIOLATION"),
            (0xc5, "DRIVER_CORRUPTED_AT_FAILURE"), // rename（对标 §5 R-1 允许）
            (0xd1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL"),
            (0xea, "THREAD_STUCK_IN_DEVICE_DRIVER"),
            (0xef, "CRITICAL_PROCESS_DIED"),
            (0xf4, "CRITICAL_OBJECT_TERMINATION"),
            (0x101, "CLOCK_WATCHDOG_TIMEOUT"),
            (0x124, "WHEA_UNCORRECTABLE_ERROR"),
            (0x133, "DPC_WATCHDOG_VIOLATION"),
            (0x139, "KERNEL_SECURITY_CHECK_FAILURE"),
            (0x13a, "KERNEL_MODE_HEAP_CORRUPTION"),
            (0x141, "VIDEO_ENGINE_TIMEOUT_DETECTED"),
            (0x144, "BUGCODE_NDIS_DRIVER"),
            (0x1ca, "SYNTHETIC_WATCHDOG_TIMEOUT"),
            (0xdead, "MANUALLY_INITIATED_CRASH"),
        ];
        for (code, want) in cases {
            assert_eq!(bugcheck_name(code), Some(want), "0x{:X} 名字漂了", code);
        }
    }

    // ===== v0.4.9 崩溃模块定位 + 全内存转储（RAINZ 对标 §3.2）=====

    /// 造一个带 ModuleListStream 的合成 minidump。x64 布局（PointerSize=8）→ 模块步长 124。
    /// 目录里两条流：Exception + ModuleList；模块名走 UTF-16LE + 4 字节长度前缀。
    fn synth_dump_with_modules(
        bugcheck: u32,
        params: [u64; 4],
        modules: &[(&str, u64, u32)],
    ) -> Vec<u8> {
        let n = modules.len();
        let dir_rva = 40usize;
        let exception_rva = dir_rva + 24; // 两个 12 字节目录项
        let module_list_rva = exception_rva + 152;
        let strings_start = module_list_rva + 4 + 124 * n;

        // 先把字符串区段拼出来（每段 = u32 字节长度 + UTF-16LE + NUL）
        let mut string_blob: Vec<u8> = Vec::new();
        let mut name_rvas: Vec<u32> = Vec::new();
        for (name, _, _) in modules {
            let off = (strings_start + string_blob.len()) as u32;
            name_rvas.push(off);
            let utf16: Vec<u16> = name.encode_utf16().collect();
            let byte_len = (utf16.len() * 2) as u32;
            string_blob.extend_from_slice(&byte_len.to_le_bytes());
            for u in &utf16 {
                string_blob.extend_from_slice(&u.to_le_bytes());
            }
            string_blob.extend_from_slice(&0u16.to_le_bytes()); // MINIDUMP_STRING 尾 NUL
        }

        let total = strings_start + string_blob.len();
        let mut b = vec![0u8; total];
        // 头
        b[0..4].copy_from_slice(&MDMP_SIGNATURE.to_le_bytes());
        b[4..8].copy_from_slice(&0xA793u32.to_le_bytes());
        b[8..12].copy_from_slice(&2u32.to_le_bytes()); // NumberOfStreams = 2
        b[12..16].copy_from_slice(&(dir_rva as u32).to_le_bytes());
        b[32..40].copy_from_slice(&8u64.to_le_bytes()); // PointerSize = 8 (x64)
        // 目录项 0：Exception
        b[dir_rva..dir_rva + 4].copy_from_slice(&STREAM_EXCEPTION.to_le_bytes());
        b[dir_rva + 4..dir_rva + 8].copy_from_slice(&152u32.to_le_bytes());
        b[dir_rva + 8..dir_rva + 12].copy_from_slice(&(exception_rva as u32).to_le_bytes());
        // 目录项 1：ModuleList
        let m1 = dir_rva + 12;
        b[m1..m1 + 4].copy_from_slice(&STREAM_MODULE_LIST.to_le_bytes());
        let list_size = 4 + 124 * n;
        b[m1 + 4..m1 + 8].copy_from_slice(&(list_size as u32).to_le_bytes());
        b[m1 + 8..m1 + 12].copy_from_slice(&(module_list_rva as u32).to_le_bytes());
        // 异常流：ThreadId(4) + alignment(4) + ExceptionCode + Params
        b[exception_rva + 8..exception_rva + 12].copy_from_slice(&bugcheck.to_le_bytes());
        for (k, p) in params.iter().enumerate() {
            let o = exception_rva + 8 + 32 + k * 8;
            b[o..o + 8].copy_from_slice(&p.to_le_bytes());
        }
        // 模块表：NumberOfModules(u32) + N * MINIDUMP_MODULE(124)
        b[module_list_rva..module_list_rva + 4].copy_from_slice(&(n as u32).to_le_bytes());
        for (i, (_, base, size)) in modules.iter().enumerate() {
            let mo = module_list_rva + 4 + i * 124;
            b[mo..mo + 8].copy_from_slice(&base.to_le_bytes());
            b[mo + 8..mo + 12].copy_from_slice(&size.to_le_bytes());
            b[mo + 20..mo + 24].copy_from_slice(&name_rvas[i].to_le_bytes());
        }
        // 字符串
        b[strings_start..].copy_from_slice(&string_blob);
        b
    }

    #[test]
    fn 合成模块表能读出名字与基址() {
        let b = synth_dump_with_modules(
            0xD1,
            [0; 4],
            &[
                ("ntoskrnl.exe", 0xFFFF_F803_1000_0000u64, 0x0100_0000u32),
                (
                    "\\SystemRoot\\System32\\drivers\\nvlddmkm.sys",
                    0xFFFF_F803_2000_0000u64,
                    0x0050_0000u32,
                ),
            ],
        );
        let mods = parse_minidump_modules(&b);
        assert_eq!(mods.len(), 2, "应有 2 个模块");
        assert_eq!(mods[0].name, "ntoskrnl.exe");
        assert_eq!(mods[0].base, 0xFFFF_F803_1000_0000u64);
        assert_eq!(mods[0].size, 0x0100_0000u32);
        assert!(mods[1].name.ends_with("nvlddmkm.sys"), "完整路径 {}", mods[1].name);
        // 两条流共存：Exception 仍能读；说明 find_stream 的循环没被 ModuleList 干扰
        let got = parse_minidump_bugcheck(&b).expect("有 ModuleList 时 Exception 仍可解");
        assert_eq!(got.0, 0xD1);
    }

    #[test]
    fn 地址命中模块区间时定位到出错模块() {
        let mods = vec![
            ModuleInfo { name: "ntoskrnl.exe".into(), base: 0x1000_0000, size: 0x0100_0000 },
            ModuleInfo { name: "nvlddmkm.sys".into(), base: 0x2000_0000, size: 0x0050_0000 },
        ];
        // 参数 3 落在第二个模块 [0x2000_0000, 0x2050_0000) 内
        let (name, addr) = locate_crash_module(&[0, 0, 0, 0x2010_0000], &mods);
        assert_eq!(name.as_deref(), Some("nvlddmkm.sys"));
        assert_eq!(addr, Some(0x2010_0000));
        // 半开区间边界：等于 base 命中，等于 base+size 不命中（右端点属于下一个模块）
        let (n1, _) = locate_crash_module(&[0x2000_0000, 0, 0, 0], &mods);
        assert_eq!(n1.as_deref(), Some("nvlddmkm.sys"), "base 边界应命中");
        let (n2, _) = locate_crash_module(&[0x2050_0000, 0, 0, 0], &mods);
        assert_eq!(n2, None, "base+size 右端点应不命中");
    }

    #[test]
    fn 无命中时不猜靠最近的模块() {
        let mods = vec![
            ModuleInfo { name: "ntoskrnl.exe".into(), base: 0x1000_0000, size: 0x0100_0000 },
        ];
        // 0x7FFF_FFFF 远在外面；0 也不该被当作命中（跳过）
        let (name, addr) = locate_crash_module(&[0, 0x7FFF_FFFF, 0, 0], &mods);
        assert_eq!(name, None, "无命中不许靠'最近的'凑");
        assert_eq!(addr, None);
        // 空模块表也 None（比如 full dump 里没解出模块表的情况）
        let (n, _) = locate_crash_module(&[0x1000_1000, 0, 0, 0], &[]);
        assert_eq!(n, None);
    }

    /// 造一个 DUMP_HEADER64（Windows 8+ x64 全内存/内核转储）头。
    /// 关键偏移：0x20 'PAGE' / 0x28 'DUMP' / 0x98 BugCheckCode / 0xA0.. Params。
    fn synth_full_dump(bugcheck: u32, params: [u64; 4]) -> Vec<u8> {
        let mut b = vec![0u8; 0x2000];
        b[0x20..0x24].copy_from_slice(&FULL_DUMP_SIG_PAGE.to_le_bytes());
        b[0x28..0x2c].copy_from_slice(&FULL_DUMP_SIG_DUMP.to_le_bytes());
        b[FULL_DUMP_BUGCHECK_CODE_OFF..FULL_DUMP_BUGCHECK_CODE_OFF + 4]
            .copy_from_slice(&bugcheck.to_le_bytes());
        for (k, p) in params.iter().enumerate() {
            let o = FULL_DUMP_BUGCHECK_PARAMS_OFF + k * 8;
            b[o..o + 8].copy_from_slice(&p.to_le_bytes());
        }
        b
    }

    #[test]
    fn 全内存转储头能解出bugcheck与四个参数() {
        let b = synth_full_dump(0x116, [0, 0xFFFF_F803_1234_5678, 0x99, 0]);
        let (code, ps) = parse_full_dump_bugcheck(&b).expect("合成 full dump 头应能解析");
        assert_eq!(code, 0x116);
        assert_eq!(ps[1], 0xFFFF_F803_1234_5678);
        assert_eq!(ps[2], 0x99);
    }

    #[test]
    fn 全内存转储签名或码不合法一律拒判() {
        // 只有 PAGE、没 DUMP（比如把别的 PAGE 开头文件误当转储）
        let mut b = synth_full_dump(0x116, [0; 4]);
        b[0x28..0x2c].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_full_dump_bugcheck(&b).is_none(), "缺 DUMP magic 仍解析");
        // BugCheckCode = 0（未崩过）
        let b0 = synth_full_dump(0, [0; 4]);
        assert!(parse_full_dump_bugcheck(&b0).is_none(), "全零码不许当作'崩过'");
        // 空输入 / 太短
        assert!(parse_full_dump_bugcheck(&[]).is_none());
        assert!(parse_full_dump_bugcheck(&[0u8; 64]).is_none());
        // **关键反向**：minidump 头不能误认成 full dump —— 两个 sig 检查必须互斥，
        // 否则一次采集会出双码、前端"码未读出"分支永远进不去
        let md = synth_dump(0x7E, [0; 4]);
        assert!(parse_full_dump_bugcheck(&md).is_none(), "minidump 头被当成 full dump 解");
    }

    // ===== v0.4.9 §3.3 事件时间线：XML 解析（纯函数，可测）=====

    /// 微软 EvtRender 输出的 XML 是这段形状（真实样本按 MSDN 文档 shape 手写）。
    const KERNEL_POWER_41: &str = r#"
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System>
            <Provider Name='Microsoft-Windows-Kernel-Power' Guid='{...}'/>
            <EventID>41</EventID>
            <Level>6</Level>
            <TimeCreated SystemTime='2026-10-01T08:15:23.4567890Z'/>
            <EventRecordID>12345</EventRecordID>
            <Channel>System</Channel>
          </System>
          <EventData>
            <Data>...</Data>
          </EventData>
        </Event>
    "#;

    const WER_1001: &str = r#"
        <Event>
          <System>
            <Provider Name='Microsoft-Windows-WER-SystemErrorReporting'/>
            <EventID>1001</EventID>
            <TimeCreated SystemTime='2026-10-02T22:11:00.000Z'/>
          </System>
          <EventData>
            <Data>1000009f,00000002,fffff80312345678,0000000000000000</Data>
            <Data>0x0000009f</Data>
            <Data>dump_abc.sys</Data>
          </EventData>
        </Event>
    "#;

    #[test]
    fn 事件xml能解析出id_provider_与时间戳() {
        let r = parse_event_xml(KERNEL_POWER_41).expect("41 事件应能解析");
        assert_eq!(r.event_id, 41);
        assert_eq!(r.provider, "Microsoft-Windows-Kernel-Power");
        assert!(r.bugcheck.is_none(), "41 事件里没有 0x 码");
        // 2026-10-01T08:15:23Z ≈ 1_790_867_723_000（手工核对：1777600000 秒 + 13 个月 ≈ 3.4e8 秒
        // 太粗；这里用"能算出接近当前 epoch"当断言，具体秒值不硬钉）
        assert!(r.time_ms > 1_700_000_000_000, "时间戳明显异常：{}", r.time_ms);
        assert!(r.time_ms < 2_000_000_000_000, "时间戳明显异常：{}", r.time_ms);
    }

    #[test]
    fn wer_1001事件能解析出bugcheck码() {
        let r = parse_event_xml(WER_1001).expect("1001 事件应能解析");
        assert_eq!(r.event_id, 1001);
        assert_eq!(r.provider, "Microsoft-Windows-WER-SystemErrorReporting");
        // 第一个 `<Data>` 里没有 0x 前缀（那是 "1000009f,...", 无 0x），
        // 第二个 `<Data>0x0000009f</Data>` 才是 bugcheck。xml_data_hex0x 从"第一个含 0x 的 Data"抓。
        assert_eq!(r.bugcheck, Some(0x9F));
    }

    #[test]
    fn 事件xml缺字段一律不猜() {
        // 无 EventID
        assert!(parse_event_xml("<Event><System><Provider Name='X'/></System></Event>").is_none());
        // 无 TimeCreated
        assert!(parse_event_xml(
            "<Event><System><Provider Name='X'/><EventID>41</EventID></System></Event>"
        )
        .is_none());
        // 无 Provider
        assert!(parse_event_xml(
            "<Event><System><EventID>41</EventID><TimeCreated SystemTime='2026-10-01T00:00:00Z'/></System></Event>"
        )
        .is_none());
        // 时间戳畸形
        assert!(parse_event_xml(
            "<Event><System><Provider Name='X'/><EventID>41</EventID><TimeCreated SystemTime='bad'/></System></Event>"
        )
        .is_none());
    }

    #[test]
    fn days_from_civil_对得上已知锚点() {
        // 手工核对：1970-01-01 距 2000-01-01 = 10957 天；2000→2026 有 7 个闰年 = 9497 天；
        // 2026-01-01 距 2026-10-01 = 273 天。合计 1970→2026-10-01 = 20727 天。
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
        assert_eq!(days_from_civil(2026, 10, 1), 20727);
        // 闰年 2 月末尾 + 3 月 1 日应差 1 天（算法以 3 月为首，跨界要正确）
        assert_eq!(days_from_civil(2024, 2, 29) + 1, days_from_civil(2024, 3, 1));
    }

    /// 真跑事件日志的验证用例：CI/其他机器上事件日志可能为空或权限不足，不进默认测试集。
    /// 发布前手工 `cargo test --lib -- --ignored bsod::tests::真跑事件日志能返回` —— 空向量也算过，
    /// 关键是**不 panic、不报"未实现"**。
    #[test]
    #[ignore = "真读 Windows 事件日志：结果依赖本机历史，只在发布前手工核对不崩不 hang"]
    fn 真跑事件日志能返回不panic() {
        let v = event_timeline(30);
        // 只断"调用链跑通"：任何一条都能通过；零条也通过（本机近 30 天无相关事件是正常状态）
        for rec in &v {
            // 时间戳在合理范围（不早于 2020-01-01、不晚于 2100）
            assert!(rec.time_ms > 1_577_836_800_000, "时间戳过老：{}", rec.time_ms);
            assert!(rec.time_ms < 4_102_444_800_000, "时间戳过新：{}", rec.time_ms);
            assert!(rec.event_id == 41 || rec.event_id == 6008 || rec.event_id == 1001,
                "不应拿到清单外的事件：{}", rec.event_id);
        }
        println!("event_timeline(30) = {} 条", v.len());
    }
}
