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
//! 已知缺口（如实标注，不做无声兜底）：
//!  - 事件日志时间线（Kernel-Power 41 / EventLog 6008 / WER 1001）未做 —— 需要
//!    `Win32_System_EventLog` feature（属新开 feature，按 §2 要登记依赖清单）。当前用
//!    转储文件的修改时间作为崩溃时间的近似值，够回答「最近一次什么时候崩的」。
//!  - 本机（`C:\Windows\Minidump` 为空、无 `MEMORY.DMP`）**没有真实转储可验**，
//!    解析器只有手工构造的合成转储用例覆盖；真机验证待有转储的机器。

/// 单次蓝屏的读出的关键信息
#[derive(Debug, Clone)]
pub struct CrashRecord {
    pub path: String,
    pub size: u64,
    pub mtime_ms: i64,
    pub bugcheck: Option<u32>,
    pub params: [u64; 4],
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
const STREAM_EXCEPTION: u32 = 6;

fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd_u64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| {
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}

/// 从内核 minidump（含 `MEMORY.DMP` 这类内核转储）里取出 `(bugcheck 码, 4 个参数)`。
///
/// 布局（全部小端，偏移相对各结构起点）：
/// ```text
/// MINIDUMP_HEADER        0:Signature(u32) 4:Version 8:NumberOfStreams 12:StreamDirectoryRva
/// MINIDUMP_DIRECTORY     +0:StreamType(u32) +4:DataSize(u32) +8:Rva(u32)   // 每项 12 字节
/// MINIDUMP_EXCEPTION     +0:ExceptionCode(u32) … +32:ExceptionInformation[15](u64)
/// → 异常流内 ExceptionCode 在流起点 +8，参数 1..4 在流起点 +40/+48/+56/+64
/// ```
///
/// 任何一处越界/签名不符都返回 `None`（不猜、不部分成功）。
pub fn parse_minidump_bugcheck(bytes: &[u8]) -> Option<(u32, [u64; 4])> {
    if rd_u32(bytes, 0)? != MDMP_SIGNATURE {
        return None;
    }
    let streams = rd_u32(bytes, 8)? as usize;
    let dir_rva = rd_u32(bytes, 12)? as usize;
    // 目录项 12 字节；给一个上限防御畸形值（正常内核转储流数是个位数）
    if streams == 0 || streams > 1024 {
        return None;
    }
    for i in 0..streams {
        let off = dir_rva.checked_add(i.checked_mul(12)?)?;
        if rd_u32(bytes, off)? != STREAM_EXCEPTION {
            continue;
        }
        let rva = rd_u32(bytes, off + 8)? as usize;
        // MINIDUMP_EXCEPTION_STREAM: ThreadId(4) + __alignment(4) 之后是 MINIDUMP_EXCEPTION
        let code = rd_u32(bytes, rva.checked_add(8)?)?;
        let mut params = [0u64; 4];
        for (k, p) in params.iter_mut().enumerate() {
            *p = rd_u64(bytes, rva.checked_add(8 + 32 + k * 8)?)?;
        }
        return Some((code, params));
    }
    None
}

/// bugcheck 码 → 英文名。**只是命名辅助**：未收录的码一律回 `None` 并由调用方渲染成十六进制，
/// 不编造解释（§9.3：不拿推断当实测）。
pub fn bugcheck_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x0000_000A => "IRQL_NOT_LESS_OR_EQUAL",
        0x0000_0018 => "REFERENCE_BY_POINTER",
        0x0000_001A => "MEMORY_MANAGEMENT",
        0x0000_001E => "KMODE_EXCEPTION_NOT_HANDLED",
        0x0000_003B => "SYSTEM_SERVICE_EXCEPTION",
        0x0000_004E => "PFN_LIST_CORRUPT",
        0x0000_0050 => "PAGE_FAULT_IN_NONPAGED_AREA",
        0x0000_007E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0x0000_007F => "UNEXPECTED_KERNEL_MODE_TRAP",
        0x0000_009F => "DRIVER_POWER_STATE_FAILURE",
        0x0000_00A5 => "ACPI_BIOS_ERROR",
        0x0000_00BE => "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
        0x0000_00C2 => "BAD_POOL_CALLER",
        0x0000_00C4 => "DRIVER_VERIFIER_DETECTED_VIOLATION",
        0x0000_00C5 => "DRIVER_OVERRAN_STACK_BUFFER",
        0x0000_00D1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0x0000_00EA => "THREAD_STUCK_IN_DEVICE_DRIVER",
        0x0000_00EF => "CRITICAL_PROCESS_DIED",
        0x0000_00F4 => "CRITICAL_OBJECT_TERMINATION",
        0x0000_0101 => "CLOCK_WATCHDOG_TIMEOUT",
        0x0000_0124 => "WHEA_UNCORRECTABLE_ERROR",
        0x0000_0133 => "DPC_WATCHDOG_VIOLATION",
        0x0000_0139 => "KERNEL_SECURITY_CHECK_FAILURE",
        0x0000_013A => "KERNEL_MODE_HEAP_CORRUPTION",
        0x0000_0141 => "VIDEO_ENGINE_TIMEOUT_DETECTED",
        0x0000_0144 => "BUGCODE_NDIS_DRIVER",
        0x0000_01CA => "SYNTHETIC_WATCHDOG_TIMEOUT",
        0x0000_DEAD => "MANUALLY_INITIATED_CRASH",
        0xC000_0218 => "STATUS_CANCELLED（用户态异常码被当作 bugcheck 读出）",
        _ => return None,
    })
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
    let parsed = read_dump_head(path, size).and_then(|b| parse_minidump_bugcheck(&b));
    out.push(CrashRecord {
        path: path.display().to_string(),
        size,
        mtime_ms,
        bugcheck: parsed.map(|(c, _)| c),
        params: parsed.map(|(_, p)| p).unwrap_or([0; 4]),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工构造一个最小内核 minidump：头部 + 一个异常流目录项 + 异常记录。
    /// 本机没有真实转储可验，所以这个合成件是解析器唯一的行为证据（缺口已在文件头写明）。
    fn synth_dump(bugcheck: u32, params: [u64; 4]) -> Vec<u8> {
        let dir_rva = 32usize; // 头之后紧跟一个目录项
        let stream_rva = 32 + 12; // 目录项之后紧跟异常流
        let mut b = vec![0u8; stream_rva + 152];
        b[0..4].copy_from_slice(&MDMP_SIGNATURE.to_le_bytes());
        b[4..8].copy_from_slice(&0xA793u32.to_le_bytes()); // Version
        b[8..12].copy_from_slice(&1u32.to_le_bytes()); // NumberOfStreams
        b[12..16].copy_from_slice(&(dir_rva as u32).to_le_bytes());
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
}
