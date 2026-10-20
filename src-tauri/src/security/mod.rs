//! 配置写入与密钥处理（对照 src/main/security.js）
//!
//! - `atomic_write_*`：临时文件 + 随机后缀 + fsync + rename（审查 L-5 的 4 字节随机后缀
//!   防同进程同毫秒并发写撞名导致 rename 覆盖）；
//! - `quarantine_file`：配置损坏先改名 `.corrupt-<ts>` 保留现场，再降级返回默认值——
//!   防止下一次保存直接覆盖损坏文件，事后可分析断电/磁盘错误根因（审查 4-1）；
//! - 密钥：`dpapi:v1:` 经 OSCrypt 主密钥解密；**绝不明文落盘**；发往渲染层前统一掩码，
//!   空值保持空串（表示未配置，不伪装成已配置），幂等（掩码重复调用结果不变）。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::safestorage;

/// 密钥掩码（与渲染层 API_KEY_MASK 同值）
pub const SECRET_MASK: &str = "••••••••";

/// 需加密/脱敏的字段名（与 JS 侧 SECRET_FIELDS 同源）
pub const SECRET_FIELDS: &[&str] = &[
    "apiKey",
    "aiApiKey",
    "baiduApiKey",
    "metasoApiKey",
    "zhihuApiKey",
    "zhihuAccessSecret",
];

static WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

/// 加密安全的随机十六进制串（`len_bytes` 字节 → **恒定** `2*len_bytes` 个小写 hex 字符）。
///
/// 审查 M-02（加固，非漏洞修复）：原先两处临时文件名后缀都用
/// `SystemTime` 纳秒低位 + `Atomic` 自增 + pid 拼接。纳秒**不是加密熵**
/// （只有 30 位、且同机进程可观测/推算时序），而这些临时文件里有一类会落到
/// **管理员上下文**（optimizer 提权链的 `.reg`、pwsh inbox 脚本）—— 能预判
/// 候选名就能抢先占位。改用 `BCryptGenRandom`（系统首选 CSPRNG、无需建句柄，
/// 与 DPAPI、GCM nonce 同源，见 `safestorage::random_nonce`）。
///
/// 失败时退回旧的弱熵混合值，但**仍定长**：契约是「N 字节进去、2N 个 hex 出来」，
/// 调用方（临时文件名拼装、固定宽度断言）不能因熵源不同而拿到不同长度的串。
///
/// 注意隔离强度**按调用点不同**（这条不能一概而论）：
/// - `write_temp_script` 用 `create_new(true)` + 重试，弱熵下也拿不到已存在的文件；
/// - [`atomic_write_file`] 同样用 `create_new(true)`（A6-L03）：临时名撞上已存在件
///   （含同名前缀的 reparse）时直接失败、不覆盖。
pub fn crypto_random_hex(len_bytes: usize) -> String {
    use windows::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let n = len_bytes.max(1);
    let mut buf = vec![0u8; n];
    // BCryptGenRandom 在 len=0 时成功但什么都不填，调用方传 0 没有意义——上面已兜到 ≥1。
    let status = unsafe { BCryptGenRandom(None, &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.0 == 0 {
        return hex_lower(&buf);
    }
    // CSPRNG 不可用（极少见）：混入旧的纳秒+序号+pid，再散列成定长输出。
    // 不直接格式化那个混合值 —— 那样长度会随纳秒位数漂移，破坏上面的契约。
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut seed = Vec::with_capacity(24);
    seed.extend_from_slice(&nanos.to_le_bytes());
    seed.extend_from_slice(&seq.to_le_bytes());
    seed.extend_from_slice(&pid.to_le_bytes());
    hex_lower(&fnv1a(&seed, n))
}

/// 小写 hex 编码（定长输出的唯一出口，避免各处各自 `format!` 出不同长度）。
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 一次性 FNV-1a（只为把变长输入压成定长输出，**不是**密码学哈希）。
/// 只在 [`crypto_random_hex`] 的 CSPRNG 降级路径上用到。
fn fnv1a(data: &[u8], out_len: usize) -> Vec<u8> {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut out = Vec::with_capacity(out_len);
    let mut h = OFFSET;
    let mut counter: u8 = 0;
    while out.len() < out_len {
        for b in data {
            h ^= *b as u64;
            h = h.wrapping_mul(PRIME);
        }
        // 超过 u64 输出长度时靠 counter 继续派生，避免无限循环
        h ^= counter as u64;
        h = h.wrapping_mul(PRIME);
        counter = counter.wrapping_add(1);
        out.extend_from_slice(&h.to_le_bytes());
    }
    out.truncate(out_len);
    out
}

fn random_suffix() -> String {
    crypto_random_hex(8)
}

/// 原子写文件：temp（同目录）→ fsync → rename 覆盖；失败清理临时件
/// 技术债 T5（v2 审查，2026-10-01 登记）**已于 2026-10-07 收尾**：rename 成功后对
/// 父目录 FlushFileBuffers（原生句柄，`FILE_FLAG_BACKUP_SEMANTICS` 打开目录——
/// std::fs 打不开目录句柄，这正是当初「补丁做不成」的原因，见 [`flush_dir_for_persistence`]）。
pub fn atomic_write_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or_else(|| "无效路径".to_string())?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let temp = dir.join(format!(".{name}.{}.tmp", random_suffix()));
    let mut opened = false;
    let result = (|| -> Result<(), String> {
        // A6-L03：create_new 只认「本次新建」的临时件；撞名（含 reparse）直接失败，
        // 不截断/不跟随别人预先放好的对象。
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        opened = true;
        f.write_all(contents).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        fs::rename(&temp, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        // 只有 open 成功过才可能留下自己的临时件；open 失败时绝不删别人的同名文件。
        if opened {
            let _ = fs::remove_file(&temp);
        }
        return result;
    }
    flush_dir_for_persistence(dir);
    Ok(())
}

/// 落目录项的断电持久性（T5 收尾）：rename 返回只保证本进程可见，断电极端场景下
/// 目录项可能不落盘。对父目录开写句柄后 `FlushFileBuffers` 把目录元数据刷盘。
/// **尽力而为**：此刻写本身已成功，flush 失败（权限/文件系统不支持/句柄打不开）
/// 只影响断电极端场景的持久性，不把一次成功的写改判成失败——那会让调用方把
/// 「实际已写好的配置」当「保存失败」重走一遍。
#[cfg(windows)]
fn flush_dir_for_persistence(dir: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_MODE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let opened = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };
    if let Ok(h) = opened {
        unsafe {
            let _ = FlushFileBuffers(h);
            let _ = CloseHandle(h);
        }
    }
}

#[cfg(not(windows))]
fn flush_dir_for_persistence(_dir: &Path) {}

/// 原子写 JSON（2 空格缩进，与 JS 侧 JSON.stringify(v, null, 2) 一致）
pub fn atomic_write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    atomic_write_file(path, text.as_bytes())
}

// v5-K01 批次 4（R7-M05，2026-10-13）：`read_json_or_quarantine` 整函数退役。
// 它的 IO 失败分支把「读不到」折叠成「空配置」（`Err(_) => json!({})`），读-改-写
// 链据此把基于空对象的合并结果整表覆写回盘且回执 success——用户唯一还原依据
// （optimizer-backups.json）与含 DPAPI 密文密钥的 settings.json 都在这条缝上。
// 消费方全部改走三态读器 [`read_json_state`]（对象形态）：`Absent` = 没有文件、
// `Corrupt` = 读了拿不到（解析失败已隔离、IO 失败只留痕不隔离——文件可能还在，
// 搬运会误伤），写侧一律 [`update_json`]（读失败绝不落到写）。
// 「只读缓存损坏静默降级」的 [`read_json_or_default`] 按 R7-W-5 裁定维持不变。

/// 读**只读缓存**（扫描结果、体检结果这类可重扫的产物）：损坏时静默返回空对象，不隔离。
///
/// 审查 M15：AGENTS §6 把两类文件分开 —— 用户配置损坏要留现场（走上面的 quarantine），
/// 而可重扫缓存损坏时重扫即恢复，隔离只会不断堆积 `<file>.corrupt-<ts>` 垃圾、
/// 还把「缓存过期」误报成「配置损坏」级别的 error 日志。
pub fn read_json_or_default(path: &Path) -> serde_json::Value {
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    }
}

/// JSON 文件读取的三态（v4 组 1 / R7-M01）：`Ok` 合法对象 / `Absent` 没有这个文件 /
/// `Corrupt` 读了但拿不到（IO 失败或解析失败；解析失败的现场已 quarantine）。
///
/// 为什么必须把三态分开：「读失败」与「没有配置」在旧实现里同归 `json!({})`，
/// 于是磁盘故障/权限异常的瞬间，一次看似正常的「保存」会把用户配置整表覆写成
/// 基于空对象的合并结果（settings.json 含 DPAPI 密文密钥，覆写即永久丢失），
/// 而且回执仍是 success:true —— 用户看不到任何异常。
pub enum JsonState {
    Ok(serde_json::Value),
    Absent,
    Corrupt,
}

/// 对象形态的文件一律走它（配置类：settings/appearance/paths/optimization-state…）。
pub fn read_json_state(path: &Path) -> JsonState {
    read_json_state_shape(path, false)
}

/// **数组形态**的三态读取（v4 修复 · 2026-10-09）：与 [`read_json_state`] 同判据、
/// 同三态语义，只是期望结构换成**裸数组**。
///
/// 为什么必须有它：`read_json_state` 对 `Ok(_)` 非对象一律判 `Corrupt`，而仓里有裸数组
/// 用户数据（启动项禁用台账 `disabled.json`、测速历史 `bench-history.json`）。R5-M03 的
/// 台账三态化与 R1-M03 的测速历史收口直接借用了对象版 ⇒ **合法数组被判损坏**：台账链
/// 每次启用/禁用都在读台账处中止（真机症状「能删除不能禁用」），测速历史的读恒空、
/// 写恒拒。数组消费者一律走本函数，不许再借用对象版。
pub fn read_json_array_state(path: &Path) -> JsonState {
    read_json_state_shape(path, true)
}

fn read_json_state_shape(path: &Path, want_array: bool) -> JsonState {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) => {
                let shape_ok = if want_array { v.is_array() } else { v.is_object() };
                if shape_ok {
                    JsonState::Ok(v)
                } else {
                    // R7-M04：结构不符按损坏处理但**留现场**（不隔离），必须留痕；
                    // update_json 的回执措辞依赖这条日志可查。
                    crate::engine::log::write_log(
                        "warn",
                        &format!(
                            "配置结构不符（期望{}）: {}",
                            if want_array { "数组" } else { "对象" },
                            path.display()
                        ),
                    );
                    JsonState::Corrupt
                }
            }
            Err(e) => {
                quarantine_file(path, &e.to_string());
                JsonState::Corrupt
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => JsonState::Absent,
        Err(e) => {
            crate::engine::log::write_log("warn", &format!("配置读取失败（未落盘、未隔离）: {} {e}", path.display()));
            JsonState::Corrupt
        }
    }
}

/// **读-改-写原语：读失败绝不落到写**（v4 组 1 / R7-M01，本仓读-改-写的唯一入口）。
///
/// 只有 `Ok`（合法对象）与 `Absent`（首次写入）才执行 `f` 并落盘；`Corrupt` 直接返回
/// `Err` —— 调用方负责如实回执/提示，**不得**降级成「基于空对象保存」。
/// `f` 返回 `Err` 时不落盘（校验失败的改动不许部分写出去）。
///
/// **全程串行化**（v4 P2-13 补）：并发调用会在「读同一份旧值」上互相覆盖（丢更新）——
/// P2-13 起渲染层对 settings.json 有三处 fire-and-forget 偏好写（玻璃档/鼠标拖尾/
/// 防恢复），同一秒内可并发落到同一文件；不串行化则「刚设的偏好静默丢失」而回执是
/// 成功。锁粒度为全局（落盘是毫秒级操作，按文件建锁表不值当）。
/// **约束：`f` 内不得再调 update_json 系**（非重入锁会死锁）——现有调用点均为单层写入。
static UPDATE_JSON_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn update_json<F>(path: &Path, f: F) -> Result<serde_json::Value, String>
where
    F: FnOnce(&mut serde_json::Value) -> Result<(), String>,
{
    // 中毒恢复取内值：闭包 panic 是 bug，但不该让此后所有配置写入永久失败
    let _guard = UPDATE_JSON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cur = match read_json_state(path) {        JsonState::Ok(v) => v,
        JsonState::Absent => serde_json::json!({}),
        JsonState::Corrupt => {
            return Err(format!(
                "配置读取失败（现场已保留/未隔离见日志），本次写入已拒绝: {}",
                path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
            ));
        }
    };
    f(&mut cur)?;
    atomic_write_json(path, &cur)?;
    Ok(cur)
}

/// 数组形态的读-改-写原语（R7-M07，v7.2 C06）。
///
/// 为什么必须有：`update_json` 内部硬编对象读器，`disabled.json` / `bench-history.json`
/// 这类裸数组台账的 RMW 只能由调用方自拼「三态闸 + 拒写 + 原子落盘 + 串行化」四件事
/// （`benchhistory.rs` 已复制过一遍，且没有锁）。这里复用**同一把** `UPDATE_JSON_LOCK`，
/// 选**数组**读器；`Corrupt` 一律拒写，别把「读失败」写成「空数组」。
pub fn update_json_array<F>(path: &Path, f: F) -> Result<Vec<serde_json::Value>, String>
where
    F: FnOnce(&mut Vec<serde_json::Value>) -> Result<(), String>,
{
    let _guard = UPDATE_JSON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cur = match read_json_array_state(path) {
        JsonState::Ok(serde_json::Value::Array(v)) => v,
        JsonState::Absent => Vec::new(),
        _ => {
            return Err(format!(
                "配置读取失败（现场已保留/未隔离见日志），本次写入已拒绝: {}",
                path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
            ));
        }
    };
    f(&mut cur)?;
    atomic_write_json(path, &serde_json::Value::Array(cur.clone()))?;
    Ok(cur)
}

/// 配置文件损坏隔离：改名 `<file>.corrupt-<ts>` 保留现场
pub fn quarantine_file(path: &Path, reason: &str) {
    if !path.exists() {
        return;
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    // R7-L09：prune_quarantined 只回收 `<*.json>.corrupt-*`；非 .json 的隔离件会永久留存，
    // 至少留一条 warn（今日生产者全是 .json，属形状防线）。
    if !name.ends_with(".json") {
        crate::engine::log::write_log(
            "warn",
            &format!("非 .json 文件被隔离（{name}）：不会被隔离件回收器清理"),
        );
    }
    let bak: PathBuf = path.with_file_name(quarantine_name_for(&name, ts));
    if fs::rename(path, &bak).is_ok() {
        crate::engine::log::write_log(
            "error",
            &format!("配置文件损坏已隔离: {name} -> {} ({reason})", bak.file_name().unwrap_or_default().to_string_lossy()),
        );
    } else {
        // R7-M04：改名失败也是「没保住现场」，不能静默；update_json 会按 Corrupt 拒写，
        // 用户回执里的「见日志」必须真能查到这条。
        crate::engine::log::write_log(
            "error",
            &format!("配置文件损坏但隔离改名失败: {name}（{reason}）"),
        );
    }
}

/// 隔离件命名（生产侧唯一出口）。
/// 刻意与消费侧 `quarantine_stamp` 成对：两者一旦漂移，隔离件就永远回收不掉，
/// 而这条链上没有任何报错会提醒（测试 `生产与消费命名必须成对` 钉住）。
fn quarantine_name_for(original: &str, ts_ms: u128) -> String {
    format!("{original}.corrupt-{ts_ms}")
}

/// 清理隔离件：`<原文件名>.json.corrupt-<毫秒>` 超过 30 天的删掉（审查 M15/G4）。
///
/// 为什么需要：`quarantine_file` 每次损坏都留下一个新文件，此前**没有任何回收路径** ——
/// 配置反复损坏（例如磁盘写满）时会在数据目录里堆一排永远没人读的 `.corrupt-*`。
///
/// **AGENTS §3「删除一律回收站优先」的唯一豁免就在这一句**（审查 v2-U3，2026-09-25 裁定）：
/// 这里用 `fs::remove_file` 永久删、不过回收站、也不过 `is_path_protected`，理由是
/// **件由本应用自己写出**（`quarantine_file` 产出、命名与本模块一一对应、内容已知是坏 JSON），
/// 用户从未创建过它、也没有任何"还原"语义挂在它身上；进回收站只是把一堆坏件搬到另一个位置。
/// 这条豁免**不外推**到任何用户数据 / 规则驱动的删除路径（常规清理链的永久删是另一回事，
/// 那是 v3.3.0 的产品裁定，见 AGENTS §3）。
///
/// 正因豁免掉了回收站这道后悔药，匹配式必须收到最紧（审查 v2-U3 的实际咬人面）：
/// 只认「**原文件名以 `.json` 结尾** + `.corrupt-<纯数字>`」，即本模块 `quarantine_file`
/// 唯一可能产出的形状。旧口径只要求 `*.corrupt-<数字>`，会把用户自己的
/// `notes.corrupt-123`（例如别的软件的坏件、或用户手工改名的备份）当垃圾永久删掉。
/// R7-L05：回收原子写遗留的 `.<name>.<hex>.tmp`（panic/断电/被杀时不会走失败分支）。
/// 只删 24h 前的普通文件，不跟随 reparse，限深 4 层。
pub fn prune_stale_atomic_temps(dir: &Path) -> usize {
    let now = SystemTime::now();
    let removed = prune_stale_temps_depth(dir, now, 0);
    if removed > 0 {
        crate::engine::log::write_log("info", &format!("已清理过期原子写临时件 {removed} 个"));
    }
    removed
}

fn prune_stale_temps_depth(dir: &Path, now: SystemTime, depth: usize) -> usize {
    if depth > 4 { return 0; }
    let Ok(entries) = fs::read_dir(dir) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(md) = fs::symlink_metadata(&p) else { continue };
        if md.is_dir() {
            if !crate::engine::protect::is_reparse(&md) {
                removed += prune_stale_temps_depth(&p, now, depth + 1);
            }
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !(name.starts_with('.') && name.ends_with(".tmp")) { continue; }
        let old = md.modified().ok().and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age > Duration::from_secs(24 * 60 * 60));
        if old && !crate::engine::protect::is_reparse(&md) && fs::remove_file(&p).is_ok() {
            removed += 1;
        }
    }
    removed
}

pub fn prune_quarantined(dir: &Path) -> usize {    let removed = prune_quarantined_in(dir, SystemTime::now());
    if removed > 0 {
        crate::engine::log::write_log("info", &format!("已清理过期隔离件 {removed} 个"));
    }
    removed
}

const QUARANTINE_KEEP: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// 执行体（不写日志，便于在一次性沙箱里断言真实删除行为而不污染应用日志目录）
///
/// R7-M03（v7.2 C11）：改**递归**扫描——4 个隔离产出点里 3 个落在子目录
/// （`cleanup/rules.json`、`uninstall/residue-rules.json`、`uninstall/residue-learned.json`，
/// 只有 `pending_delete` 的在根），单层 `read_dir` 看不见它们的 `<file>.corrupt-<ts>`，
/// 正是上文自述要消灭的「堆一排没人读的坏件」。机制照 pwsh 层 v2-L13 的先例
/// （递归 + 限深 + reparse 拒）；**裁根仍只传 `app_data_dir()`**（AGENTS §6 老根不裁）。
fn prune_quarantined_in(dir: &Path, now: SystemTime) -> usize {
    prune_quarantined_depth(dir, now, 0)
}

const QUARANTINE_SCAN_MAX_DEPTH: usize = 6;

fn prune_quarantined_depth(dir: &Path, now: SystemTime, depth: usize) -> usize {
    if depth > QUARANTINE_SCAN_MAX_DEPTH {
        return 0;
    }
    let now_ms = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let Ok(entries) = fs::read_dir(dir) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // 先递归子目录（隔离产出点是数据根下的 .json 本体，子目录里不会再有
        // 本模块的产出，但规则库的层级将来可能加深——限深 6 层足够且防失控）
        if entry.path().is_dir() {
            removed += prune_quarantined_depth(&entry.path(), now, depth + 1);
            continue;
        }
        let Some(ts) = quarantine_stamp(&name) else { continue };
        // 时间戳取文件名里的隔离时刻（不是 mtime）：复制/搬运过的件仍按原时刻判龄期
        if now_ms.saturating_sub(ts) > QUARANTINE_KEEP.as_millis() {
            // 只删普通文件、拒 reparse：链接件删掉等于删它指向的东西
            let safe = fs::symlink_metadata(entry.path())
                .map(|m| m.is_file() && !crate::engine::protect::is_reparse(&m))
                .unwrap_or(false);
            if safe && fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// 隔离件命名判定：命中则返回文件名里的毫秒时间戳。
/// 形状必须是 `<…….json>.corrupt-<纯数字>`（`quarantine_file` 的产出格式，逐字对齐）。
fn quarantine_stamp(name: &str) -> Option<u128> {
    let (stem, ts) = name.rsplit_once(".corrupt-")?;
    if !stem.ends_with(".json") || ts.is_empty() || !ts.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // 分隔符兜底（NTFS 文件名本容不下，不依赖上游侥幸）
    if name.contains(['/', '\\', ':']) {
        return None;
    }
    ts.parse::<u128>().ok()
}

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// 递归把 SECRET_FIELDS 字段做变换（对齐 transformSecrets）
pub fn transform_secrets(
    value: &serde_json::Value,
    transform: &dyn Fn(&str) -> String,
) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let new_v = if SECRET_FIELDS.contains(&k.as_str()) {
                    match v {
                        serde_json::Value::String(s) => {
                            serde_json::Value::String(transform(s))
                        }
                        other => {
                            // R7-L07：密钥字段不是字符串时既不能加密也不能掩码；
                            // 形状不能被静默洗白，至少留一条 warn。
                            crate::engine::log::write_log(
                                "warn",
                                &format!("密钥字段 {k} 不是字符串（实际 {}），按原形状递归处理", json_kind(other)),
                            );
                            transform_secrets(other, transform)
                        }
                    }
                } else {
                    transform_secrets(v, transform)
                };
                out.insert(k.clone(), new_v);
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items.iter().map(|i| transform_secrets(i, transform)).collect(),
        ),
        other => other.clone(),
    }
}

/// 树里是否存在任何 `SECRET_FIELDS` 键（审查 v3 裁定①的前置判据）。
///
/// 为什么要它：`transform_secrets` 是**整树重建**（每个对象新建 Map、每个值 clone），
/// 而它被夹在持全局 `UPDATE_JSON_LOCK` 的闭包里跑（`commands/settings.rs` 的
/// `update_settings`：解密一遍 + 加密一遍）。绝大多数 `settings.json` 根本没有密钥字段
/// （本机现算 696 B、零 secret 键），却照样付两遍全树克隆加一次主密钥读取。
/// 无该键时整棵变换按定义是恒等的 ⇒ 直接返回原值，既不遍历也不取密钥。
/// 判据只写这一份，加/解密两侧共用（AGENTS §5.16：同判定不许两套实现）。
fn has_secret_field(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(k, v)| {
            SECRET_FIELDS.contains(&k.as_str()) || has_secret_field(v)
        }),
        serde_json::Value::Array(items) => items.iter().any(has_secret_field),
        _ => false,
    }
}

/// 发往渲染层前的统一脱敏出口（掩码即未修改语义；空值保持空串）
pub fn mask_settings(settings: &serde_json::Value) -> serde_json::Value {
    transform_secrets(settings, &|v| {
        if v.is_empty() {
            String::new()
        } else {
            SECRET_MASK.to_string()
        }
    })
}

/// 加密出口（对照 JS `encryptSettings`）：把 SECRET_FIELDS 内**非空字符串**字段加密为
/// `dpapi:v1:` 密文；空值保持空串（= 未配置，与 JS `encryptSecret` 同语义）。
///
/// 与 JS 的差异只在**密钥来源**：JS 由 Electron safeStorage 提供 OSCrypt 主密钥；
/// 这里读 Local State 的 `os_crypt.encrypted_key`，拿不到时回落旧版「v10 + 裸 DPAPI」
/// 密文——两条路都绝不明文落盘，且 Electron 侧均可解（见 safestorage.rs）。
/// 加密失败（CryptProtectData 不可用）时返回 Err，调用方按 Electron 的
/// 「safeStorage 不可用 → 拒绝保存」同语义回 `success:false`。
pub fn encrypt_settings_with_oscrypt(settings: &serde_json::Value) -> Result<serde_json::Value, String> {
    // 无密钥字段 ⇒ 整棵变换恒等，跳过全树重建与主密钥读取（v3 裁定①，判据见 has_secret_field）
    if !has_secret_field(settings) {
        return Ok(settings.clone());
    }
    let key = safestorage::load_oscrypt_key().ok();
    // M-19：主密钥现在是 Zeroizing<Vec<u8>>，显式取切片传入。
    encrypt_secrets(settings, key.as_deref().map(|v| v.as_slice()))
}

fn encrypt_secrets(
    value: &serde_json::Value,
    key: Option<&[u8]>,
) -> Result<serde_json::Value, String> {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let new_v = if SECRET_FIELDS.contains(&k.as_str()) {
                    match v {
                        serde_json::Value::String(s) => {
                            // 已经是密文 ⇒ 原样透传。这条是密钥不可逆清空的修复：
                            // 主密钥暂不可读时 [`decrypt_settings_with_oscrypt`] 会保留
                            // 原密文（不再回落空串），随后被 fonts 等读-改-写命令整份保存；
                            // 若这里再包一层，密文会被二次加密而永久不可解。
                            if s.starts_with(safestorage::DPAPI_V1_PREFIX) {
                                serde_json::Value::String(s.clone())
                            } else {
                                serde_json::Value::String(
                                    safestorage::encrypt_dpapi_v1(s, key).map_err(|e| e.to_string())?,
                                )
                            }
                        }
                        other => encrypt_secrets(other, key)?,
                    }
                } else {
                    encrypt_secrets(v, key)?
                };
                out.insert(k.clone(), new_v);
            }
            Ok(serde_json::Value::Object(out))
        }
        serde_json::Value::Array(items) => Ok(serde_json::Value::Array(
            items
                .iter()
                .map(|i| encrypt_secrets(i, key))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        other => Ok(other.clone()),
    }
}

/// 解密一组遗留 dpapi:v1: 密钥（供 settings 域迁移使用）。
///
/// **解不开就保留原密文**，绝不回落空串：主密钥暂不可读（Local State 被移走/被锁）
/// 时回落空串，随后任意读-改-写命令（字体导入/移除/save-config）会把空串当
/// 「未配置」整份写回 ⇒ 用户密钥物理丢失且界面毫无异常。保留密文 + 加密侧透传
/// （见 `encrypt_secrets`）让读-改-写对密钥字段是无损的，等主密钥恢复后仍可解。
/// 旧格式 `v10 + 裸 DPAPI` 即便没有主密钥也能解开，所以恒带 `key.as_deref()` 尝试。
pub fn decrypt_settings_with_oscrypt(settings: &serde_json::Value) -> serde_json::Value {
    // 同 encrypt 侧：树里没有任何密钥字段时整棵变换恒等，直接返回（v3 裁定①）
    if !has_secret_field(settings) {
        return settings.clone();
    }
    let key = safestorage::load_oscrypt_key().ok();
    transform_secrets(settings, &|v| {
        if !v.starts_with(safestorage::DPAPI_V1_PREFIX) {
            return v.to_string();
        }
        safestorage::decrypt_dpapi_v1(v, key.as_deref().map(|k| k.as_slice()))
            .map_err(|e| {
                // R7-L06：保留密文是刻意（主密钥可能暂不可读），但失败原因必须留痕，
                // 否则用户只见「AI 不工作」。
                crate::engine::log::write_log("warn", &format!("密钥解密失败（保留原密文）: {e}"));
                e
            })
            .ok()
            .and_then(|b| String::from_utf8(b.to_vec()).ok())
            .unwrap_or_else(|| v.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一次性沙箱：唯一命名 + 结束自删。测试不得具备改动真实数据目录的能力。
    fn sandbox(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trim-security-test-{}-{tag}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ==================== 审查 v2-U3：永久删除出口的匹配面 ====================

    /// v5-K01 批次 4（R7-M05）：IO 失败（非 NotFound）≠ 空数据——update_json 拒写、
    /// 不隔离（文件可能还在，只是暂时读不到，搬运会误伤）、原路径不动。
    /// 用「同路径目录」模拟非 NotFound 的 IO 失败（read_to_string 对目录返回错误，
    /// 纯 std 可构造，不需要句柄控制）。判红自证：把 read_json_state_shape 的
    /// 非 NotFound 分支临时改成 Absent（模拟旧「IO 失败=没有配置」）⇒ update_json
    /// 会走 f + atomic_write（对目录失败）⇒ Err 消息不再是「本次写入已拒绝」⇒ 本用例红。
    #[test]
    fn update_json对io失败拒写且原路径不动() {
        let root = sandbox("io-fail");
        // ① 目录占位 = 非 NotFound IO 失败：拒写、不隔离、原路径不动
        let p = root.join("blocked.json");
        fs::create_dir(&p).unwrap();
        let err = update_json(&p, |v| {
            *v = serde_json::json!({ "x": 1 });
            Ok(())
        })
        .unwrap_err();
        assert!(err.contains("本次写入已拒绝"), "IO 失败必须以「拒写」回执: {err}");
        assert!(p.is_dir(), "原路径不得被动过（不隔离/不改名/不删）");
        // ② 反向钉：NotFound = 真没有 ⇒ 首写放行（Absent ≠ Corrupt）
        let q = root.join("fresh.json");
        let out = update_json(&q, |v| {
            *v = serde_json::json!({ "ok": true });
            Ok(())
        })
        .unwrap();
        assert_eq!(out["ok"], serde_json::json!(true), "NotFound 必须按首写放行");
        // ③ Corrupt（读到但解析失败）= 隔离保留现场 + 拒写；隔离件内容 = 原内容逐字节
        let c = root.join("corrupt.json");
        fs::write(&c, "{不是 json").unwrap();
        let err2 = update_json(&c, |_| Ok(())).unwrap_err();
        assert!(err2.contains("本次写入已拒绝"), "解析失败必须拒写: {err2}");
        let quarantined: Vec<String> = fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("corrupt.json.corrupt-"))
            .collect();
        assert_eq!(quarantined.len(), 1, "解析失败现场必须隔离保留: {quarantined:?}");
        assert_eq!(
            fs::read(root.join(&quarantined[0])).unwrap(),
            b"{\xe4\xb8\x8d\xe6\x98\xaf json".to_vec(),
            "隔离件必须保留原字节（现场可回看）"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// 审查 M-02：临时文件名后缀改走 CSPRNG 后，形状必须是**定长 hex**——
    /// 旧的纳秒+序号+pid 是变长十进制/十六进制混排，且字符集含 pid 形态。
    /// 这条断言点名「做到了什么」，不是「没报错」。
    #[test]
    fn 随机后缀是定长小写hex() {
        let s = crypto_random_hex(8);
        assert_eq!(s.len(), 16, "8 字节 ⇒ 16 个 hex 字符，实际 {s:?}");
        assert!(
            s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "只应是 0-9a-f，实际 {s:?}"
        );
    }

    /// 两次调用必须不同 —— 熵源真的换了才会恒成立；旧的纳秒低位在同一纳秒内
    /// 只会靠自增序号区分（形似不同、熵不同），这条钉住「不是伪随机」。
    #[test]
    fn 随机后缀两次不重复() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            seen.insert(crypto_random_hex(8));
        }
        assert_eq!(seen.len(), 64, "64 次调用出现重复，熵源可能退化");
    }

    /// 审查 v2-U3：永久删除出口的匹配面 ====================

    #[test]
    fn 隔离件匹配必须要求原名以json结尾() {
        // 本模块唯一产出的形状：quarantine_file 只隔离 *.json 配置
        assert_eq!(quarantine_stamp("appearance.json.corrupt-1711"), Some(1711));
        assert_eq!(
            quarantine_stamp("settings.json.corrupt-1758729600000"),
            Some(1758729600000)
        );
        // 用户自己的文件：旧口径（只要 `*.corrupt-<数字>`）会把它当垃圾永久删掉
        assert_eq!(quarantine_stamp("notes.corrupt-123"), None);
        assert_eq!(quarantine_stamp("README.corrupt-1758729600000"), None);
        // 时间段不纯是数字 / 为空 / 带路径分隔符 ⇒ 一律不认
        assert_eq!(quarantine_stamp("a.json.corrupt-12ab"), None);
        assert_eq!(quarantine_stamp("a.json.corrupt-"), None);
        assert_eq!(quarantine_stamp("sub/../x.json.corrupt-1"), None);
        // 反向：不得把「收紧」做成「连自己也认不出」——生产侧与消费侧命名必须成对
        assert_eq!(
            quarantine_stamp(&quarantine_name_for("paths.json", 1758729600000)),
            Some(1758729600000)
        );
    }

    #[test]
    fn 回收只动过期隔离件不碰用户文件() {
        let dir = sandbox("prune");
        let now = SystemTime::now();
        let now_ms = now.duration_since(UNIX_EPOCH).unwrap().as_millis();
        let old_ms = now_ms - (31 * 24 * 60 * 60 * 1000);
        let fresh_ms = now_ms - (10 * 24 * 60 * 60 * 1000);
        let expired = dir.join(quarantine_name_for("appearance.json", old_ms));
        let kept = dir.join(quarantine_name_for("settings.json", fresh_ms));
        let user_file = dir.join("notes.corrupt-123");
        let plain = dir.join("notes.txt");
        for p in [&expired, &kept, &user_file, &plain] {
            fs::write(p, b"x").unwrap();
        }
        // 子目录同名也不当文件删（这里是防 remove_file 走到目录上）
        let as_dir = dir.join(quarantine_name_for("system.json", old_ms));
        fs::create_dir_all(&as_dir).unwrap();

        assert_eq!(prune_quarantined_in(&dir, now), 1, "只该删掉那一个过期隔离件");
        assert!(!expired.exists());
        assert!(kept.exists(), "30 天内的隔离件要留（现场还在保留期）");
        assert!(user_file.exists(), "用户的 notes.corrupt-123 不得被删（v2-U3 咬人面）");
        assert!(plain.exists());
        assert!(as_dir.is_dir(), "目录不得被 remove_file 端掉");
        let _ = fs::remove_dir_all(&dir);
    }

    /// 2026-10-05 复核 P1：主密钥不可读时的密钥不可逆清空。
    ///
    /// 两条链路必须同时成立，缺一条就还是丢数据：
    /// · decrypt 解不开 ⇒ 保留原密文（不是空串）；
    /// · encrypt 见到密文 ⇒ 原样透传（不再套一层）。
    /// 合起来的效果：任意读-改-写（fonts 三处整份 load→save）对密钥字段是无损的。
    #[test]
    fn 解不开的密文既不回落空串也不被二次加密() {
        // 一个解不开的密文（缺主密钥 / 结构损坏都会走到 unwrap_or_else 那条）
        let ciphertext = "dpapi:v1:AAAA";
        let settings = serde_json::json!({
            "aiApiKey": ciphertext,
            "font": { "family": "MiSans" },
        });

        let decrypted = decrypt_settings_with_oscrypt(&settings);
        assert_eq!(
            decrypted.get("aiApiKey").and_then(|v| v.as_str()),
            Some(ciphertext),
            "解不开的密文必须原样保留，回落空串会让下一次保存把它覆盖掉",
        );
        // 非密钥字段不受影响
        assert_eq!(
            decrypted.pointer("/font/family").and_then(|v| v.as_str()),
            Some("MiSans"),
        );

        // 写回侧：密文透传，不能被再包一层（否则永久不可解）
        let reencrypted = encrypt_secrets(&decrypted, None).expect("透传不应失败");
        assert_eq!(
            reencrypted.get("aiApiKey").and_then(|v| v.as_str()),
            Some(ciphertext),
            "已是密文的值必须透传，二次加密会让密钥永久不可解",
        );

        // 正向对照：真·明文仍然会被加密（透传不能把整个加密出口变成摆设）
        let plain = serde_json::json!({ "aiApiKey": "sk-live-abc" });
        let enc = encrypt_settings_with_oscrypt(&plain).expect("明文加密不应失败");
        let got = enc.get("aiApiKey").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            got.starts_with(safestorage::DPAPI_V1_PREFIX) && got != "sk-live-abc",
            "明文密钥没有被加密（透传分支误吞了明文）：{got}",
        );
    }

    /// v4 组 1 / R7-M01：`update_json` 的「读失败绝不落到写」契约 ——
    /// Absent 允许首写 / Ok 读-改-写 / Corrupt 拒写且留隔离件 / f 失败不部分写。
    /// 判红自证：把 Corrupt 分支改成「当空对象继续」⇒ 第 3 组断言全红。
    #[test]
    fn update_json_never_writes_on_read_failure() {
        let dir = std::env::temp_dir().join(format!("trim-update-json-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("建临时目录");
        struct Clean(std::path::PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _clean = Clean(dir.clone());
        let f = dir.join("conf.json");

        // ① Absent ⇒ 允许首写
        update_json(&f, |v| {
            v["a"] = serde_json::json!(1);
            Ok(())
        })
        .expect("Absent 应允许首写");
        // ② Ok ⇒ 读-改-写（保留旧键）
        update_json(&f, |v| {
            v["b"] = serde_json::json!(2);
            Ok(())
        })
        .expect("Ok 应读-改-写");
        let text = std::fs::read_to_string(&f).expect("应已落盘");
        assert!(text.contains("\"a\"") && text.contains("\"b\""), "旧键必须保留: {text}");

        // ③ Corrupt（坏 JSON）⇒ 拒写 + 现场被隔离（改名 .corrupt-*，不是留在原地被覆写）
        std::fs::write(&f, "{ not json").expect("写坏件");
        let err = update_json(&f, |v| {
            v["c"] = serde_json::json!(3);
            Ok(())
        })
        .expect_err("损坏时必须拒写");
        assert!(err.contains("拒绝"), "回执应说明拒绝: {err}");
        assert!(!f.exists(), "损坏件应被隔离改名，而不是留在原地被下次写入覆写");
        let quarantined = std::fs::read_dir(&dir)
            .expect("读目录")
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains(".corrupt-"));
        assert!(quarantined, "隔离件必须留下（.corrupt-*）");

        // ④ 闭包返回 Err ⇒ 不落盘（校验失败的改动不许部分写出去）
        std::fs::write(&f, "{\"keep\":1}").expect("写探针");
        let _ = update_json(&f, |_v| Err("校验没过".to_string())).expect_err("f 失败应上抛");
        assert!(
            std::fs::read_to_string(&f).expect("读回").contains("\"keep\""),
            "f 失败时文件不得被改动"
        );
    }

    /// v4 P2-13 补：`update_json` 全程串行化 —— 两线程各 +1 共 N 次，终值必须恰好 2N。
    /// 不加锁时读-改-写交错必然丢更新（闭包内的 sleep 正是把「读→写」窗口拉宽，
    /// 让这条用例把丢更新判红）；加锁后结果确定。
    #[test]
    fn update_json_serializes_concurrent_writers() {
        let dir = std::env::temp_dir().join(format!("trim-update-json-conc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("建临时目录");
        struct Clean(std::path::PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _clean = Clean(dir.clone());
        let f = dir.join("counter.json");
        std::fs::write(&f, "{\"n\":0}").expect("写初值");

        let mut handles = Vec::new();
        for _ in 0..2 {
            let f = f.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..30 {
                    update_json(&f, |v| {
                        let n = v.get("n").and_then(|x| x.as_u64()).unwrap_or(0);
                        std::thread::sleep(std::time::Duration::from_micros(200));
                        v["n"] = serde_json::json!(n + 1);
                        Ok(())
                    })
                    .expect("并发写不应失败");
                }
            }));
        }
        for h in handles {
            h.join().expect("线程不得 panic");
        }
        let text = std::fs::read_to_string(&f).expect("读回");
        let v: serde_json::Value = serde_json::from_str(&text).expect("合法 JSON");
        assert_eq!(
            v["n"], serde_json::json!(60),
            "两线程各 30 次 +1，丢更新即红（终值 {text}）"
        );
    }

    /// v4 修复（2026-10-09）：对象/数组两把读器各认各的形态，**交叉即 Corrupt**。
    /// 防的正是「数组文件借用对象读器」这类回归 —— 启动项禁用台账与测速历史都是
    /// 裸数组，被对象版判损坏后，禁用/启用 100% 中止、测速历史读恒空。
    /// 判红自证：把 read_json_array_state 改回借 read_json_state ⇒ 前半组即红。
    #[test]
    fn json_state_readers_are_shape_specific() {
        let dir = std::env::temp_dir().join(format!("trim-json-shape-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("建临时目录");
        struct Clean(std::path::PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _clean = Clean(dir.clone());

        // ① 裸数组：数组读器 Ok、对象读器 Corrupt（后者正是回归的成因）
        let arr = dir.join("ledger.json");
        std::fs::write(&arr, "[{\"id\":\"x\"}]").expect("写数组");
        assert!(
            matches!(read_json_array_state(&arr), JsonState::Ok(serde_json::Value::Array(_))),
            "合法数组必须被数组读器接受"
        );
        assert!(
            matches!(read_json_state(&arr), JsonState::Corrupt),
            "对象读器对数组按损坏处理（留现场、不隔离）"
        );
        assert!(arr.exists(), "形态不符不得隔离原件");

        // ② 对象：对象读器 Ok、数组读器 Corrupt（对称）
        let obj = dir.join("conf.json");
        std::fs::write(&obj, "{\"a\":1}").expect("写对象");
        assert!(matches!(read_json_state(&obj), JsonState::Ok(_)));
        assert!(matches!(read_json_array_state(&obj), JsonState::Corrupt));

        // ③ 不存在：两把读器都 Absent（首次写入语义一致）
        let none = dir.join("nope.json");
        assert!(matches!(read_json_state(&none), JsonState::Absent));
        assert!(matches!(read_json_array_state(&none), JsonState::Absent));

        // ④ 坏 JSON：数组读器按损坏处理且现场被隔离（改名 .corrupt-*）
        let bad = dir.join("bad.json");
        std::fs::write(&bad, "[{}").expect("写坏件");
        assert!(matches!(read_json_array_state(&bad), JsonState::Corrupt));
        assert!(!bad.exists(), "解析失败的现场必须被隔离（改名）");
    }

    /// 审查 v3 裁定①的前置判据：**逐个点名**六个密钥键（与 JS 侧 `SECRET_FIELDS` 同源）
    /// 都必须被检出。这不是性能断言，是**安全断言**——`has_secret_field` 漏判任一键，
    /// 早退路径就会让该字段**明文落盘**，等于绕过「密钥不明文回渲染层/不落盘」这条红线。
    /// 末条反向对照（非登记名不得命中）保证判据不是「一律返回 true」蒙绿。
    #[test]
    fn has_secret_field_逐个点名密钥键() {
        assert_eq!(SECRET_FIELDS.len(), 6, "密钥键表条数变动要同步本用例与 JS 侧");
        // 用显式 Map 构造：`json!({ k: … })` 里裸 ident 会被当**字面量键名**而不是变量值，
        // 且 `&&str` 不满足 `String: From<_>`，用宏反而会写出恒真的好测试。
        for k in SECRET_FIELDS {
            let mut leaf = serde_json::Map::new();
            leaf.insert((*k).to_string(), serde_json::json!("sk-test"));
            let top = serde_json::Value::Object(leaf.clone());
            assert!(has_secret_field(&top), "顶层的 {k} 必须被检出");
            let mut wrap = serde_json::Map::new();
            wrap.insert("settings".to_string(), serde_json::Value::Object(leaf));
            let nested = serde_json::Value::Object(wrap);
            assert!(has_secret_field(&nested), "嵌套的 {k} 必须被检出，否则明文落盘");
        }
        // transform_secrets 会递归数组，判据也必须递归进去
        assert!(has_secret_field(&serde_json::json!([{ "apiKey": "x" }])));
        // 反向对照：形近但不在登记表里的名字不得命中（否则判据退化成“一律 true”也会绿）
        assert!(!has_secret_field(&serde_json::json!({ "api_key": "x", "keys": [] })));
    }

    /// R7-M07：数组形态的读-改-写原语——形状不符必须拒写且原文件不动，合法数组走同一把锁。
    #[test]
    fn update_json_array_形状安全且不改写损坏件() {
        let root = sandbox("array-rmw");
        let p = root.join("bench.json");
        fs::write(&p, "[{\"id\":1}]").unwrap();
        let out = update_json_array(&p, |a| {
            a.push(serde_json::json!({ "id": 2 }));
            Ok(())
        })
        .unwrap();
        assert_eq!(out.len(), 2, "闭包内的追加必须生效");
        let disk: serde_json::Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        assert!(disk.is_array(), "落盘必须仍是裸数组（不许被对象化）: {disk}");
        assert_eq!(disk.as_array().unwrap().len(), 2);

        // 形状不符（对象借数组读器）⇒ 三态闸判 Corrupt ⇒ 拒写，原文件逐字节不动
        let q = root.join("object.json");
        fs::write(&q, "{\"a\":1}").unwrap();
        let err = update_json_array(&q, |_| Ok(())).unwrap_err();
        assert!(err.contains("本次写入已拒绝"), "形状不符必须拒写: {err}");
        assert_eq!(fs::read_to_string(&q).unwrap(), "{\"a\":1}", "拒写时原文件不得被改");
        let _ = fs::remove_dir_all(&root);
    }

    /// 审查 v3 裁定①：树里没有密钥字段时，加/解密入口必须**恒等返回**且不触碰主密钥。
    /// 这条正是把「持全局 `UPDATE_JSON_LOCK` 期间读盘取密钥 + 全树重建」省掉的那一半
    /// （本机 `settings.json` 现算 696 B、零 secret 键，属绝大多数情形）。
    #[test]
    fn 无密钥字段时加解密入口恒等返回() {
        let plain = serde_json::json!({
            "theme": "light",
            "nested": { "liquidMotion": "standard", "list": [{ "path": "C:/x" }] }
        });
        assert!(!has_secret_field(&plain), "夹具里不该有密钥键");
        assert_eq!(decrypt_settings_with_oscrypt(&plain), plain, "无密钥字段时解密必须恒等");
        assert_eq!(
            encrypt_settings_with_oscrypt(&plain).expect("无密钥字段时加密不该失败"),
            plain,
            "无密钥字段时加密必须恒等"
        );
    }
}
