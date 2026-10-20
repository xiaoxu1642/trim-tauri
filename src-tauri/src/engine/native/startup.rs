//! B5 启动项：scan / toggle / delete / add + 「Trim 禁用台账」与备份文件归属。
//!
//! 台账（disabled.json / StartupApproved 位）是本域单一真相：读侧与写侧同在本文件，
//! backup_root_tests 随实现走，避免升级前后老根兜底逻辑被实现与测试分两头改。
//! 跨域共享的注册表 typed 读写在 `registry.rs`，路径与名清洗在 `common.rs`。


use crate::engine::systembin::system_tool;
use serde_json::{Value, json};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WRITE, REG_BINARY, REG_CREATED_NEW_KEY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_QWORD, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW};
use super::common::*;
use super::registry::*;
// ==================== B5：启动项扫描 ====================


/// 从命令行提取可执行路径（支持引号包裹）
fn extract_cmd_path(cmd: &str) -> String {
    let c = cmd.trim();
    if c.starts_with('"') {
        if let Some(idx) = c[1..].find('"') {
            return c[1..idx+1].to_string();
        }
    }
    if let Some(sp) = c.find(' ') {
        return c[..sp].to_string();
    }
    c.to_string()
}

/// 可启动文件后缀白名单：图标/定位只认真实落盘的这些类型，半截目录名混不进来。
const RUNNABLE_EXTS: &[&str] = &["exe", "com", "bat", "cmd", "vbs", "js", "scr", "lnk", "ps1", "cpl", "msc"];

/// 解释器宿主：这类行的真正程序在 Arguments 里（`/c x.exe` / `-File <脚本>.ps1` / rundll32 dll），
/// 命令本体只给得到解释器自己的图标。
const INTERPRETER_HOSTS: &[&str] = &[
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "conhost.exe", "explorer.exe",
];

fn ext_lc(p: &std::path::Path) -> String {
    p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase()
}

/// 已存在的可启动文件（allow_dll 仅给 rundll32 的 dll/cpl 开口）。
fn is_runnable_path(s: &str, allow_dll: bool) -> bool {
    let p = std::path::Path::new(s.trim_matches('"'));
    if !p.is_file() {
        return false;
    }
    let ext = ext_lc(p);
    RUNNABLE_EXTS.contains(&ext.as_str()) || (allow_dll && matches!(ext.as_str(), "dll" | "cpl"))
}

/// 在一行文本里找**真实存在**的可启动目标：
/// 1. 成对引号内（`"C:\Program Files\App\app.exe" /s` —— 注册表里最常见写法）；
/// 2. 逐词拼接的最长现存前缀（未加引号的 `C:\Program Files\App\app.exe /s`，
///    真机上抖音自启就是这个形态）。
/// 只认现存文件，找不到返 None —— 图标失败由前端回退默认，不许凭字符串形状猜。
fn find_existing_target(text: &str, allow_dll: bool) -> Option<String> {
    // ① 引号对：取第一个现存的（程序永远排在参数前面）
    let mut rest = text;
    while let Some(a) = rest.find('"') {
        if let Some(b) = rest[a + 1..].find('"') {
            let inner = &rest[a + 1..a + 1 + b];
            if is_runnable_path(inner, allow_dll) {
                return Some(inner.to_string());
            }
            rest = &rest[a + 1 + b + 1..];
        } else {
            break;
        }
    }
    // ② 逐词前缀：保留「最后一个命中的最长前缀」
    let stripped: String = text.chars().filter(|&c| c != '"').collect();
    let tokens: Vec<&str> = stripped.split_whitespace().collect();
    let mut hit: Option<String> = None;
    for k in 1..=tokens.len() {
        let cand = tokens[..k].join(" ");
        if is_runnable_path(&cand, allow_dll) {
            hit = Some(cand);
        }
    }
    hit
}

/// 启动项命令行 → 图标与「打开位置」用的真实目标路径（任务 XML 与注册表 Run 共用）。
///
/// 解析顺序：解释器宿主先翻参数里的程序 → 命令本体（引号/最长现存前缀）→ 裸名 + 工作目录。
/// 找不到返空串：调用方（任务扫描）据此回退默认图标；注册表分支为保持旧行为会回落到
/// [`extract_cmd_path`] 的粗切结果。
fn resolve_running_target(command: &str, arguments: &str, working_dir: &str) -> String {
    let cmd = expand_env(command.trim());
    let args = expand_env(arguments);
    let wd = expand_env(working_dir.trim());
    if cmd.is_empty() {
        return String::new();
    }

    // 命令本体是解释器宿主时，真正的程序/脚本藏在参数里（含命令行自带的后半截）
    let host_name = std::path::Path::new(&extract_cmd_path(&cmd).to_ascii_lowercase())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    if INTERPRETER_HOSTS.contains(&host_name.as_str()) {
        let allow_dll = host_name == "rundll32.exe";
        // 任务 XML 的参数是独立字段；注册表把参数拼在同一行，两种文本合起来找
        let mut tail = String::new();
        if let Some(sp) = cmd.find(char::is_whitespace) {
            tail.push_str(cmd[sp..].trim());
        }
        if !args.is_empty() {
            if !tail.is_empty() {
                tail.push(' ');
            }
            tail.push_str(args.trim());
        }
        if let Some(t) = find_existing_target(&tail, allow_dll) {
            return t;
        }
    }

    // 命令本体里就带着真实路径（绝大多数 Run 项与计划任务是这种）
    if let Some(t) = find_existing_target(&cmd, false) {
        return t;
    }

    // 裸名 + 工作目录（任务 XML 常见：Command=app.exe、WorkingDirectory=安装目录）
    if !cmd.chars().any(char::is_whitespace) && !wd.is_empty() {
        let joined = std::path::Path::new(&wd).join(&cmd);
        if is_runnable_path(&joined.to_string_lossy(), false) {
            return joined.to_string_lossy().into_owned();
        }
    }

    String::new()
}



/// 「启动项写的程序文件已经不在了」判据（注册表 Run 与计划任务**共用同一份**，AGENTS §5.16）。
///
/// 只对**已展开的绝对路径**下结论：
/// · 裸名（`OneDrive.exe`）要先走 PATH/App Paths 才谈得上存在，直接判「不存在」会把大半正常项
///   误标成可疑；
/// · 还带 `%VAR%` 的串根本没展开，`exists()` 当然为假，那不代表文件没了；
/// · **必须以可执行文件后缀结尾** —— 真机抓到的误判就是这条：注册表里写着
///   `C:\Program Files (x86)\ByteDance\douyin\douyin.exe --start_type=autorun`（裸路径带空格），
///   `extract_cmd_path` 按第一个空格切出 `C:\Program`，它不是「文件没了」而是「没切对」。
///   这个字段是给用户在界面上看的断言（「目标文件不存在」），宁可不下结论，
///   也不能给一个没证据的判断（红线依据-竞品反例 §9.3）。
/// 返回 `Some(原路径)` = 判据成立（文件确实不在）；`None` = 不下结论。
fn missing_target_of(cmd_path: &str) -> Option<String> {
    let p = cmd_path.trim().trim_matches('"');
    if p.is_empty() || p.contains('%') {
        return None;
    }
    let b = p.as_bytes();
    let is_drive_abs = b.len() >= 3 && b[1] == b':' && b[2] == b'\\' && p[..2].starts_with(|c: char| c.is_ascii_alphabetic());
    if !is_drive_abs && !p.starts_with(r"\\") {
        return None;
    }
    // 后缀闸：切错的半截路径（`C:\Program`）与目录名一律不作答
    let ext = std::path::Path::new(p)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    if !["exe", "com", "bat", "cmd", "vbs", "js", "msc", "scr", "lnk"].contains(&ext.as_str()) {
        return None;
    }
    if std::path::Path::new(p).exists() {
        None
    } else {
        Some(p.to_string())
    }
}


/// 读 StartupApproved blob，返回是否禁用（首字节 bit0=1）
unsafe fn read_startup_approved(hive: HKEY, subkey: &str, value_name: &str) -> Option<bool> {
    let base = match hive {
        h if h == HKEY_CURRENT_USER => r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
        _ => r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
    };
    let full = format!("{base}\\{subkey}");
    let fw = to_wide(&full);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(fw.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
        return None;
    }
    let result = reg_query_value(hk, value_name).map(|(ty, buf)| {
        if ty == REG_BINARY && !buf.is_empty() {
            (buf[0] & 1) == 1
        } else {
            false
        }
    });
    let _ = RegCloseKey(hk);
    result
}

/// 取文件发布者（CompanyName）
fn get_publisher(path: &str) -> String {
    if path.is_empty() { return String::new(); }
    // 简化实现：不实现 GetFileVersionInfoW，留空
    // 后续 S2 用 VerQueryValueW 实现
    String::new()
}

/// 任务 XML 文本解码：Windows 任务文件是 UTF-16LE(带 BOM)，少数导出件是 UTF-8
fn decode_task_xml(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let wide: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&wide)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// 取 `<tag>…</tag>` 的第一个文本内容（大小写按 Windows 写出形态精确匹配）
fn xml_first(text: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let Some(a) = text.find(&open) else { return String::new() };
    let rest = &text[a + open.len()..];
    let Some(b) = rest.find(&close) else { return String::new() };
    rest[..b].trim().to_string()
}

/// 递归枚举 `%SystemRoot%\System32\Tasks`，把「登录/开机触发」的任务收成启动项候选。
/// 跳过 `\Microsoft\` 子树（系统任务，与旧 schtasks 口径一致）。
/// R5a-L04 三修：根现读 `%SystemRoot%`（系统不在 C: 时旧写死根整块看不见）、
/// 目录判改 symlink_metadata + is_reparse（跟随链接会把枚举引出 Tasks 树）、
/// 深度上限 64（与 cleanup.rs ENGINE_WALK_MAX_DEPTH 同档，防环挂死）。
fn scan_task_files() -> Vec<Value> {
    const TASK_WALK_MAX_DEPTH: usize = 64;
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let root = std::path::Path::new(&sysroot).join(r"System32\Tasks");
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let p = entry.path();
            // 只信元数据形态：is_dir() 跟随重解析点，junction 段会把枚举引出任务树
            let is_dir = std::fs::symlink_metadata(&p)
                .map(|m| m.is_dir() && !crate::engine::protect::is_reparse(&m))
                .unwrap_or(false);
            if is_dir {
                if depth >= TASK_WALK_MAX_DEPTH { continue; }
                stack.push((p, depth + 1));
                continue;
            }
            let Ok(rel) = p.strip_prefix(&root) else { continue };
            let rel_str = rel.to_string_lossy().replace('/', "\\");
            if rel_str.starts_with("Microsoft\\") { continue; }
            let Ok(bytes) = std::fs::read(&p) else { continue };
            let text = decode_task_xml(&bytes);
            if !text.contains("<LogonTrigger") && !text.contains("<BootTrigger") { continue; }
            let task_path = match rel_str.rfind('\\') {
                Some(idx) => format!("\\{}", &rel_str[..=idx]),
                None => "\\".to_string(),
            };
            let task_name = rel_str.rsplit('\\').next().unwrap_or(&rel_str).to_string();
            let task_to_run = xml_first(&text, "Command");
            let task_args = xml_first(&text, "Arguments");
            let task_workdir = xml_first(&text, "WorkingDirectory");
            let enabled = !xml_first(&text, "Enabled").eq_ignore_ascii_case("false");
            let task_missing = missing_target_of(&extract_cmd_path(&task_to_run)).unwrap_or_default();
            // 图标/位置用的真实目标：任务被应用自禁用时 XML 的 Command 会被写成
            // 「by user disabled」这类标记串（GoogleUpdater/抖音真机如此），解析不出
            // 现存文件就留空——前端按空路径回退默认图标，不拿标记串冒充路径。
            let resolved_target = resolve_running_target(&task_to_run, &task_args, &task_workdir);
            out.push(json!({
                "id": format!("task|{task_path}{task_name}"),
                "name": task_name,
                "command": task_to_run,
                "source": "task",
                "hive": "",
                "regPath": "",
                "valueName": "",
                "valueType": "",
                "valueData": "",
                "valueDataB64": "",
                "valueDataArray": Vec::<String>::new(),
                "filePath": "",
                "taskPath": task_path,
                "taskName": task_name,
                "enabled": enabled,
                "location": format!("计划任务{}", task_path.trim_end_matches('\\')),
                "scope": "HKLM",
                "disabledBy": if !enabled { "system" } else { "" },
                "publisher": "",
                "resolvedPath": resolved_target,
                "missingTarget": task_missing,
            }));
        }
    }
    out
}

/// 启动项扫描（原 PS 时代脚本 startup_scan.ps1，已退役）
///
/// 注册表 Run/RunOnce + 启动文件夹 + StartupApproved + disabled.json 合并。
/// 8 条 Run/RunOnce 根（扫描枚举与台账启用恢复**共用同一份**）。
///
/// v5-K09 批次 5：启用链的恢复写回只允许落在这 8 个容器内，hive tag 必须与根
/// 成对匹配——此前扫描侧各自持有这份清单、启用臂没有任何容器校验，同用户篡改
/// `disabled.json`（%APPDATA% 可写）后，提权态可按台账凭据写任意 Run 值
/// （medium→admin 持久化原语）。fsDelete 侧本有 containment（commands/startup.rs
/// 的 backup-file 校验），台账链补上同源的一道。
const RUN_PATHS: &[(&str, HKEY, &str, &str, &str)] = &[
    ("HKCU", HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "注册表 · 当前用户\\Run", "HKCU"),
    ("HKCU", HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "注册表 · 当前用户\\RunOnce", "HKCU"),
    ("HKCU32", HKEY_CURRENT_USER, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "注册表 · 当前用户(32位)\\Run", "HKCU32"),
    ("HKCU32", HKEY_CURRENT_USER, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "注册表 · 当前用户(32位)\\RunOnce", "HKCU32"),
    ("HKLM", HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "注册表 · 所有用户\\Run", "HKLM"),
    ("HKLM", HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "注册表 · 所有用户\\RunOnce", "HKLM"),
    ("HKLM32", HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "注册表 · 所有用户(32位)\\Run", "HKLM32"),
    ("HKLM32", HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "注册表 · 所有用户(32位)\\RunOnce", "HKLM32"),
];

/// 两个启动文件夹根（扫描枚举与台账启用恢复**共用同一份**）。
///
/// v5-K09 批次 5：folder 启用的恢复目标（台账 `valueData`）必须落在其一之下——
/// fsDelete 侧同源 containment 的台账链补齐。
fn startup_folders() -> Vec<(String, &'static str, &'static str)> {
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let programdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    vec![
        (appdata, r"Microsoft\Windows\Start Menu\Programs\Startup", "启动文件夹 · 当前用户"),
        (programdata, r"Microsoft\Windows\Start Menu\Programs\StartUp", "启动文件夹 · 所有用户"),
    ]
}

/// v5-K09 批次 5：folder 启用的台账坐标准入（纯函数，可测）。
///
/// 两道：① containment——备份文件必须落在本域备份根（`startup-backup`，跨两根读
/// 候选与 fsDelete 同口径）内、恢复目标必须落在两个启动文件夹之一内（path_key
/// 归一后按组件边界比前缀，verbatim/盘符相对/`..` 形态统一折叠）；② 保护面——
/// 恢复目标不得命中 `is_path_protected`。任一不过即拒，**在 rename 之前**。
fn folder_restore_verdict(backup_path: &str, orig_path: &str) -> Result<(), String> {
    // ①a 备份文件必须在备份根内
    backup_in_root_verdict(backup_path)?;
    // ①b 恢复目标必须在两个启动文件夹之一内
    let orig_key = crate::engine::paths::path_key(orig_path);
    let in_folder = startup_folders().iter().any(|(base, sub, _)| {
        let dk = crate::engine::paths::path_key(&format!("{base}\\{sub}"));
        orig_key == dk || orig_key.starts_with(&format!("{dk}\\"))
    });
    if !in_folder {
        return Err("恢复目标不在本域启动文件夹内，已拒绝移回".into());
    }
    // ② 保护面
    if crate::engine::protect::is_path_protected(orig_path) {
        return Err("恢复目标命中受保护路径，已拒绝移回".into());
    }
    Ok(())
}

/// K04：备份路径必须落在本域备份根内（`backup_read_dirs("startup-backup")`，
/// 新根在前、老根兜底——与 fsDelete 白名单、台账读取同一份候选）。
///
/// 抽成公共判据是为了让启用臂（恢复移回）与删除臂（回收站删备份）认同一道：
/// 备份路径来自 `disabled.json`（%APPDATA% 可写），台账行被篡改时两道都必须拦。
///
/// 刻意**不跑** `is_path_protected`：备份根住在 `app_data_dir()` 下，而应用自身
/// 数据目录是 `configure_from_app` 登记的受保护子树（整棵不许碰）——对备份路径跑
/// 保护判定恒为 true，合法备份会被全拦（同 `appearance.rs:390` 踩过的坑）。
/// 备份区的「可动」由本 containment（只认本域备份根）单独授权。
fn backup_in_root_verdict(backup_path: &str) -> Result<(), String> {
    let backup_key = crate::engine::paths::path_key(backup_path);
    let in_backup_root = crate::engine::paths::backup_read_dirs("startup-backup")
        .iter()
        .any(|d| {
            let dk = crate::engine::paths::path_key(&d.to_string_lossy());
            backup_key == dk || backup_key.starts_with(&format!("{dk}\\"))
        });
    if !in_backup_root {
        return Err("备份文件不在本域启动备份根内，已拒绝".into());
    }
    Ok(())
}

/// K04：folder **禁用/删除臂**的源路径准入（纯函数，可测）。
///
/// 与启用臂的 [`folder_restore_verdict`] 同源：源路径必须落在两个启动文件夹之一内
/// （path_key 归一后按组件边界比前缀），且不得命中 `is_path_protected`。
///
/// 为什么禁用/删除臂也要这道：`disabled.json` 的记录会被 `startup_scan` 原样合并进
/// 扫描结果，命令层的快照校验只证明「id 来自上次扫描」——注入行自证一致；提权态下
/// 无 containment 即可把任意文件搬进备份目录（禁用臂 rename）或投回收站（删除臂
/// fsDelete），违 AGENTS §3「回收站链须先过 is_path_protected」。
fn folder_source_verdict(file_path: &str) -> Result<(), String> {
    let key = crate::engine::paths::path_key(file_path);
    if key.is_empty() {
        return Err("启动文件夹项路径为空，已拒绝".into());
    }
    let in_folder = startup_folders().iter().any(|(base, sub, _)| {
        let dk = crate::engine::paths::path_key(&format!("{base}\\{sub}"));
        key == dk || key.starts_with(&format!("{dk}\\"))
    });
    if !in_folder {
        return Err("源路径不在本域启动文件夹内，已拒绝".into());
    }
    if crate::engine::protect::is_path_protected(file_path) {
        return Err("源路径命中受保护路径，已拒绝".into());
    }
    Ok(())
}

/// v5-K09 批次 5：registry 臂的台账坐标准入（纯函数，可测）——**启用/禁用/删除
/// 三臂共用同一道**（v6-K04：此前只有启用臂过它，禁用/删除臂裸吃 regPath）。
/// 两道：hive tag 必须是本域四视图之一；子键必须命中四条 Run/RunOnce 根形态之一
/// （大小写不敏感）。tag 与根的「成对」在句柄层面无安全意义——HKLM32 与 HKLM
/// 解析同一个句柄、视图由 subkey 里的 WOW6432Node 决定——本判定锚定的是
/// 「改写只落在 8 容器之一」，tag 撒谎（HKCU32 配 64 位根）不越权、不拒。
fn registry_container_verdict(hive_tag: &str, subkey: &str) -> Result<(), String> {
    const TAGS: [&str; 4] = ["HKCU", "HKCU32", "HKLM", "HKLM32"];
    if !TAGS.iter().any(|t| hive_tag.eq_ignore_ascii_case(t)) {
        return Err("注册表项不在本域 Run/RunOnce 容器内，已拒绝".into());
    }
    if RUN_PATHS.iter().any(|(_, _, sk, _, _)| subkey.eq_ignore_ascii_case(sk)) {
        Ok(())
    } else {
        Err("注册表项不在本域 Run/RunOnce 容器内，已拒绝".into())
    }
}

/// K04：由**真实 hive**（regPath 解析结果）推导台账对账用的 tag。
/// 台账行自带的 hive/scope 只作对账、不作为授权（v6-K04：HKLM 前置门与真正
/// 写入的 hive 必须同源，否则台账行谎报 HKCU 即可骗过提权门）。
fn hive_tag_of(hive: HKEY, subkey: &str) -> &'static str {
    let is_wow32 = subkey.to_ascii_uppercase().contains("WOW6432NODE");
    match hive {
        h if h == HKEY_CURRENT_USER => if is_wow32 { "HKCU32" } else { "HKCU" },
        _ => if is_wow32 { "HKLM32" } else { "HKLM" },
    }
}

/// 计划任务直接解析 Tasks 目录 XML（schtasks /v 逐任务深查实测 60s+，2026-10-06 已替换）。
/// .lnk 目标解析和文件发布者留空（S2 完善）。
pub fn startup_scan() -> Result<Vec<Value>, String> {
    let mut results: Vec<Value> = Vec::new();

    unsafe {
        // ---------- 注册表 Run/RunOnce（8 路径） ----------
        for (hive_tag, hive, subkey, label, scope) in RUN_PATHS {
            let sk = to_wide(&subkey);
            let mut hk = HKEY::default();
            if RegOpenKeyExW(*hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
                continue;
            }
            let values = reg_enum_values(hk);
            for vp in values {
                if vp.is_empty() { continue; }
                let Some((ty, buf)) = reg_query_value(hk, &vp) else { continue; };
                let value_type = match ty {
                    REG_SZ => "String",
                    REG_EXPAND_SZ => "ExpandString",
                    REG_BINARY => "Binary",
                    REG_MULTI_SZ => "MultiString",
                    REG_DWORD => "DWord",
                    _ => "Unknown",
                };
                let mut value_data = String::new();
                let mut value_data_b64 = String::new();
                let mut value_data_arr: Vec<String> = Vec::new();
                let mut cmd_path = String::new();

                if ty == REG_BINARY {
                    value_data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &buf);
                } else if ty == REG_MULTI_SZ {
                    // MULTI_SZ: 双 null 结尾的宽字符串序列
                    let wide: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let mut start = 0;
                    for i in 0..wide.len() {
                        if wide[i] == 0 {
                            if i > start {
                                value_data_arr.push(String::from_utf16_lossy(&wide[start..i]));
                            }
                            start = i + 1;
                        }
                    }
                } else if ty == REG_SZ || ty == REG_EXPAND_SZ {
                    let wide: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
                    value_data = String::from_utf16_lossy(&wide[..end]);
                    if ty == REG_EXPAND_SZ {
                        value_data = expand_env(&value_data);
                    }
                    if !value_data.trim().is_empty() {
                        // 优先解析真实存在的目标（未加引号的带空格路径/解释器参数里的程序，
                        // 粗切会切成 `C:\Program` 导致图标与定位双双失败）；解析不出时
                        // 回落到 extract_cmd_path 原口径，OneDrive.exe 这类裸名行为不变。
                        let resolved = resolve_running_target(&value_data, "", "");
                        cmd_path = if resolved.is_empty() { extract_cmd_path(&value_data) } else { resolved };
                    }
                }

                if value_data.trim().is_empty() && value_data_b64.is_empty() && value_data_arr.is_empty() {
                    continue;
                }

                // StartupApproved：32 位视图的批准面在 `Run32` 子键（不是 `Run`），
                // hive 仍归主 hive。此前所有来源恒传 "Run"，32 位项禁用/启用写错键、
                // 回读自校验因为读的也是错键而恒过。
                let sa_hive = if hive_tag.starts_with("HKLM") { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER };
                let sa_subkey = if subkey.to_ascii_uppercase().contains("WOW6432NODE") { "Run32" } else { "Run" };
                // R5a-M01：RunOnce 与写侧 is_run_once 同判据——StartupApproved 没有
                // RunOnce 子键，读 `Run`/`Run32` 会撞上同名 Run 项的批准位，把
                // RunOnce 项的启用态显示成别人的。批准位对 RunOnce 是死数据，不采信。
                let is_run_once = subkey.to_ascii_uppercase().contains("RUNONCE");
                let sa_disabled = if is_run_once { None } else { read_startup_approved(sa_hive, sa_subkey, &vp) };
                let enabled = sa_disabled.map(|d| !d).unwrap_or(true);
                let disabled_by = if !enabled && sa_disabled.is_some() { "system" } else { "" };

                let reg_path_full = match *hive {
                    h if h == HKEY_CURRENT_USER => format!("HKEY_CURRENT_USER\\{subkey}"),
                    _ => format!("HKEY_LOCAL_MACHINE\\{subkey}"),
                };
                let missing = missing_target_of(&cmd_path).unwrap_or_default();

                results.push(json!({
                    "id": format!("reg|{reg_path_full}|{vp}"),
                    "name": vp,
                    "command": value_data,
                    "source": "registry",
                    "hive": hive_tag,
                    "regPath": reg_path_full,
                    "valueName": vp,
                    "valueType": value_type,
                    "valueData": value_data,
                    "valueDataB64": value_data_b64,
                    "valueDataArray": value_data_arr,
                    "filePath": "",
                    "taskPath": "",
                    "taskName": "",
                    "enabled": enabled,
                    "location": label,
                    "scope": scope,
                    "disabledBy": disabled_by,
                    "publisher": get_publisher(&cmd_path),
                    "resolvedPath": cmd_path,
                    // 目标已消失：只报事实（写在哪、找不着），不推断「是病毒」——见 missing_target_of
                    "missingTarget": missing,
                }));
            }
            let _ = RegCloseKey(hk);
        }

        // ---------- 启动文件夹（清单与台账启用恢复共用 startup_folders()，v5-K09） ----------
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        for (base, sub, label) in startup_folders() {
            let dir = std::path::Path::new(&base).join(sub);
            let Ok(entries) = std::fs::read_dir(&dir) else { continue; };
            let scope = if base == appdata { "HKCU" } else { "HKLM" };
            let sa_hive = if scope == "HKLM" { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER };
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.eq_ignore_ascii_case("desktop.ini") { continue; }
                let full_path = entry.path().to_string_lossy().to_string();
                let name_stem = entry.path().file_stem().and_then(|s| s.to_str()).unwrap_or(&fname).to_string();
                // 简化实现：.lnk 目标解析暂用文件路径（未做 IShellLink 深解析）
                let resolved = full_path.clone();
                // StartupApproved\StartupFolder：先按全名找，再按无扩展名找
                let sa_disabled = read_startup_approved(sa_hive, "StartupFolder", &fname)
                    .or_else(|| read_startup_approved(sa_hive, "StartupFolder", &name_stem));
                let enabled = sa_disabled.map(|d| !d).unwrap_or(true);
                let disabled_by = if !enabled && sa_disabled.is_some() { "system" } else { "" };
                results.push(json!({
                    "id": format!("folder|{full_path}"),
                    "name": name_stem,
                    "command": full_path,
                    "source": "folder",
                    "hive": scope,
                    "regPath": "",
                    "valueName": "",
                    "valueType": "",
                    "valueData": "",
                    "valueDataB64": "",
                    "valueDataArray": Vec::<String>::new(),
                    "filePath": full_path,
                    "taskPath": "",
                    "taskName": "",
                    "enabled": enabled,
                    "location": label,
                    "scope": scope,
                    "disabledBy": disabled_by,
                    "publisher": get_publisher(&resolved),
                    "resolvedPath": resolved,
                    // 启动文件夹的项是 read_dir 当场枚举出来的，文件必然在 —— 恒空，但三个来源同形状
                    "missingTarget": "",
                }));
            }
        }
    }

    // ---------- 计划任务（Tasks 目录 XML 直读） ----------
    // 2026-10-06 性能修复（用户报告「扫描一分钟还多」）：旧实现 `schtasks /query /v`
    // 会为**每个**任务做一次深查（本机数百任务 ⇒ 实测 60s+），而我们要的三件事
    // （触发类型 / 命令行 / 启用态）全部写在任务 XML 文件里 —— 纯文件读，毫秒级。
    // XML 按固定写出形态做子串判读，不引解析依赖（§2 零新增依赖）。
    results.extend(scan_task_files());

    // ---------- 合并 disabled.json ----------
    // 与 read_disabled_records 同一取本口径（`startup_ledger_file`）：两处读同一本账，
    // 一处认新根一处认老根就会出现「列表里有、恢复按钮说没有」
    if let Some(disabled_file) = startup_ledger_file() {
        if let Ok(text) = std::fs::read_to_string(&disabled_file) {
            if let Ok(records) = serde_json::from_str::<Vec<Value>>(&text) {
                for r in records {
                    let Some(id) = r.get("id").and_then(|v| v.as_str()) else { continue; };
                    if results.iter().any(|x| x.get("id").and_then(|v| v.as_str()) == Some(id)) { continue; }
                    let mut item = r.clone();
                    if let Some(o) = item.as_object_mut() {
                        o.insert("enabled".into(), json!(false));
                        o.insert("disabledBy".into(), json!("trim"));
                    }
                    results.push(item);
                }
            }
        }
    }

    Ok(results)
}

// ==================== B5 startup_toggle：启动项启用/禁用 ====================

fn startup_backup_dir() -> std::path::PathBuf {
    crate::engine::paths::backup_write_dir("startup-backup")
}

/// `disabled.json` 的候选（写入那份在前，历史老根那份兜底）。
fn startup_disabled_file_candidates() -> Vec<std::path::PathBuf> {
    crate::engine::paths::backup_read_dirs("startup-backup")
        .into_iter()
        .map(|d| d.join("disabled.json"))
        .collect()
}

/// 当前生效的那本禁用台账。
///
/// 为什么按修改时间而不是"新根优先"：收口前所有写入都落老根，而启动迁移只是**按名复制一次**，
/// 于是老根那份很可能比新根的副本新。新根优先会把用户后来禁用的项从列表里抹掉
/// （账在老根那本上），而「恢复」按钮读的是同一本账——界面会说没有禁用项，系统里却还禁用着。
fn startup_ledger_file() -> Option<std::path::PathBuf> {
    pick_newest_file(&startup_disabled_file_candidates())
}

fn startup_disabled_file() -> std::path::PathBuf {
    startup_backup_dir().join("disabled.json")
}

fn startup_files_dir() -> std::path::PathBuf {
    startup_backup_dir().join("files")
}

/// v2-M19 备份根收口的回归位：写入恒新根、读取带老根兜底。
#[cfg(test)]
mod missing_target_tests {
    use super::*;

    /// 判据只在「绝对路径 + 已展开」时下结论，其余一律不猜（这是给用户看的断言）。
    #[test]
    fn missing_target_only_judges_expanded_absolute_paths() {
        // 存在的那一侧用测试进程自己的 exe：它必然在，且不依赖本机装了什么软件
        let here = std::env::current_exe().expect("测试 exe 自己必然存在")
            .to_string_lossy().to_string();
        assert_eq!(missing_target_of(&here), None, "存在的文件被判成已消失");

        // 不存在的绝对路径 → 给结论，并把原路径带出去（界面要显示「写着哪个路径」）
        assert_eq!(
            missing_target_of(r"Z:\trim-no-such-dir\gone.exe").as_deref(),
            Some(r"Z:\trim-no-such-dir\gone.exe")
        );
        // 带引号的写法（注册表里常见）：先剥引号再判
        assert_eq!(
            missing_target_of("\"C:\\trim-no-such-dir\\gone.exe\"").as_deref(),
            Some(r"C:\trim-no-such-dir\gone.exe")
        );
        // 裸名要走 PATH/App Paths 才谈得上存在 —— 不下结论
        assert_eq!(missing_target_of("OneDrive.exe"), None);
        // 真机抓到的误判：`C:\Program Files (x86)\...\douyin.exe --start_type=autorun`
        // 被按第一个空格切成 `C:\Program`。它不是「文件没了」而是「没切对」，
        // 所以没有可执行后缀的一律不作答。
        assert_eq!(missing_target_of(r"C:\Program"), None);
        assert_eq!(missing_target_of(r"C:\Program Files (x86)"), None);
        // 有后缀且确实不在 → 给结论
        assert_eq!(
            missing_target_of(r"C:\trim-no-such-dir\douyin.exe").as_deref(),
            Some(r"C:\trim-no-such-dir\douyin.exe")
        );
        // 环境变量还没展开 —— 判 exists() 必然为假，那不代表文件没了
        assert_eq!(missing_target_of(r"%ProgramFiles%\Foo\bar.exe"), None);
        // 空串与纯空格
        assert_eq!(missing_target_of("   "), None);
        // UNC 也认（网络路径消失同样是事实）
        assert_eq!(
            missing_target_of(r"\\trim-none\share\a.exe").as_deref(),
            Some(r"\\trim-none\share\a.exe")
        );
    }

    /// 正向对照：把判据改坏成「一律说存在」时，上面的用例必须抓得到（防恒绿）。
    #[test]
    fn missing_target_probe_is_not_always_none() {
        assert!(missing_target_of(r"C:\trim-definitely-absent\x.exe").is_some());
    }
}

/// 启动命令行 → 真实目标解析（图标/「打开位置」用）。
/// 真机背景：任务 XML 自禁用标记 `by user disabled`、未加引号的带空格路径、
/// 解释器参数里藏程序，是计划任务项整页回退默认图标的三个来源（2026-10-06 截图实测）。
#[cfg(test)]
mod resolve_target_tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// 用例临时目录：Drop 时自动清空（断言 panic 的栈展开也会跑 Drop，不留垃圾）。
    /// 刻意做成守卫而不是每个用例手写 remove_dir_all——后者在 startup.rs 里每写一个
    /// 用例就多一处删除原语文本，会推高 check-delete-callsites 棘轮基线。
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(case: &str) -> TempDir {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "trim-resolve-{}-{}-{}",
                std::process::id(),
                case,
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).expect("临时目录");
            TempDir(p)
        }
        /// 在临时根下建一个（内容无关的）文件，返回反斜杠形态的绝对路径。
        fn touch(&self, rel: &str) -> String {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).expect("建父目录");
            fs::write(&p, b"x").expect("写临时文件");
            p.to_string_lossy().replace('/', "\\")
        }
        fn as_str(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn 引号包裹的真实程序直接命中() {
        let root = TempDir::new("quoted");
        let exe = root.touch("bin/app.exe");
        assert_eq!(resolve_running_target(&format!("\"{exe}\" /s"), "", ""), exe);
    }

    #[test]
    fn 未加引号的带空格路径按最长现存前缀命中() {
        // 真机抖音自启：`C:\Program Files (x86)\ByteDance\douyin\douyin.exe --start_type=autorun`
        let root = TempDir::new("spaces");
        let exe = root.touch("Program Files/App/app.exe");
        let line = format!("{exe} --start_type=autorun");
        assert_eq!(resolve_running_target(&line, "", ""), exe, "粗切只会得到半截 `C:\\Program`");
    }

    #[test]
    fn 应用自禁用标记串解析为空_不留假路径() {
        // GoogleUpdater / 抖音任务被应用自身禁用时，XML Command 被整串写成标记文本
        assert_eq!(resolve_running_target("by user disabled", "--wake --system", ""), "");
        assert_eq!(resolve_running_target("by user disabled", "--start-from=taskschd", ""), "");
        // 随便一个不存在的裸名同样不猜
        assert_eq!(resolve_running_target("OneDrive.exe", "", ""), "");
    }

    #[test]
    fn 解释器参数里的程序才是真目标() {
        let root = TempDir::new("host");
        let exe = root.touch("deep/app.exe");
        let ps1 = root.touch("scripts/run.ps1");
        // 宿主可以是裸名（不要求宿主自身存在）——任务 XML 里常见 cmd.exe 不带全路径
        assert_eq!(
            resolve_running_target("cmd.exe", &format!("/c \"{exe}\""), ""),
            exe,
            "cmd /c 后面的程序没被翻出来"
        );
        assert_eq!(
            resolve_running_target(
                "powershell.exe",
                &format!("-ExecutionPolicy Bypass -File \"{ps1}\""),
                "",
            ),
            ps1,
            "powershell -File 的脚本没被翻出来"
        );
    }

    #[test]
    fn 裸名命令配工作目录可命中() {
        let root = TempDir::new("workdir");
        let exe = root.touch("app.exe");
        assert_eq!(resolve_running_target("app.exe", "", &root.as_str()), exe);
    }

    #[test]
    fn 整行没有现存文件时返回空_由前端回退默认图标() {
        assert_eq!(resolve_running_target(r"Z:\no-such\a.exe /x", "", ""), "");
        assert_eq!(resolve_running_target("", "", ""), "");
    }

    /// 正向对照：解析器若被改成恒空实现，本用例必须红（防上面用例被恒空骗过）。
    #[test]
    fn 解析器不是恒空实现() {
        let root = TempDir::new("positive");
        let exe = root.touch("a.exe");
        assert!(!resolve_running_target(&format!("\"{exe}\""), "", "").is_empty());
    }
}

#[cfg(test)]
mod backup_root_tests {
    use super::*;

    #[test]
    fn startup_ledger_writes_data_root_and_reads_both() {
        let write = startup_disabled_file();
        assert!(
            write.starts_with(crate::engine::paths::app_data_dir()),
            "禁用台账写回了老根，便携实例的台账带不走: {write:?}"
        );
        let cands = startup_disabled_file_candidates();
        assert_eq!(cands[0], write, "读取候选的第一位必须就是写入那份，否则写完立刻读不到");
        assert!(cands.len() >= 2, "老根那份历史台账必须还在候选里: {cands:?}");
        assert!(
            !startup_deleted_dir().to_string_lossy().contains(r"\Trim\"),
            "删除备份又拼回 Electron 老根: {:?}",
            startup_deleted_dir()
        );
    }

    /// 台账取本口径：收口前写入全落老根，迁移只是**按名复制一次**，所以老根那份常常更新。
    /// 按"新根优先"会把用户后来禁用的项从界面里抹掉，而系统里它们仍然禁用着。
    #[test]
    fn ledger_takes_the_newest_copy_not_the_new_root() {
        use std::fs::File;
        use std::io::Write;
        use std::time::{Duration, SystemTime};
        let t = |secs: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        let root = std::env::temp_dir().join(format!("trim-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("new")).expect("临时目录");
        std::fs::create_dir_all(root.join("old")).expect("临时目录");
        let put = |dir: &str, secs: u64| -> std::path::PathBuf {
            let p = root.join(dir).join("disabled.json");
            let mut f = File::create(&p).expect("写台账");
            f.write_all(b"[]").expect("写台账");
            f.set_modified(t(secs)).expect("设时间");
            p
        };
        let new_copy = put("new", 1_700_000_000);
        let legacy_copy = put("old", 1_730_000_000);
        assert_eq!(
            pick_newest_file(&[new_copy.clone(), legacy_copy.clone()]).as_deref(),
            Some(legacy_copy.as_path()),
            "老根那份更新时必须认它，否则界面上看不到用户后来禁用的项"
        );
        // 同一时刻并列 → 偏向第一位（写入根），保证"刚写完立刻读"读到自己的写
        let a = put("new", 1_740_000_000);
        let b = put("old", 1_740_000_000);
        assert_eq!(pick_newest_file(&[a.clone(), b]).as_deref(), Some(a.as_path()));
        // 只剩一份 / 都不存在
        assert_eq!(pick_newest_file(&[a.clone()]).as_deref(), Some(a.as_path()));
        assert_eq!(
            pick_newest_file(&[root.join("nope").join("disabled.json")]),
            None,
            "一本都没有就是没有台账，不该回退到某个写死路径"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 两根都要收，且**跨根一起排时间**：只认一根就是 v2-M19 收口后的新病——
    /// 老根那批更早，新根这批才是"最近一次外设改动"，反过来也一样会挑错。
    #[test]
    fn peripheral_backup_scan_spans_both_roots_and_sorts_by_time() {
        use std::fs::File;
        use std::io::Write;
        use std::time::{Duration, SystemTime};
        let root = std::env::temp_dir().join(format!("trim-periph-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let current = root.join("current");
        let legacy = root.join("legacy");
        std::fs::create_dir_all(&current).expect("临时目录");
        std::fs::create_dir_all(&legacy).expect("临时目录");
        let put = |dir: &std::path::Path, name: &str, secs: u64| -> std::path::PathBuf {
            let p = dir.join(name);
            let mut f = File::create(&p).expect("写分片");
            f.write_all(b"Windows Registry Editor Version 5.00\r\n").expect("写分片");
            f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
                .expect("设时间");
            p
        };
        let older = put(&current, "backup_20260101_000000_1.reg", 1_700_000_000);
        let newer = put(&legacy, "backup_20260901_000000_1.reg", 1_730_000_000);
        put(&current, "notes.txt", 1_800_000_000);
        let got = collect_peripheral_backup_files(&[current.clone(), legacy.clone()]).0;
        assert_eq!(got.len(), 2, "两个根都要收且只认 backup_*.reg: {got:?}");
        assert_eq!(got[0], newer, "跨根必须一起排时间，否则还原挑到旧批次: {got:?}");
        assert_eq!(got[1], older);
        assert_eq!(
            collect_peripheral_backup_files(&[current]).0.len(),
            1,
            "少给一个根就少一批可还原的备份"
        );
        // A1-M05：非 NotFound 的 read_dir 失败必须计数（目录位置放了一个文件），
        // 让上层能把「读不动」与「没备份过」分开。
        let bogus = root.join("not-a-dir.reg");
        std::fs::write(&bogus, b"x").expect("写占位文件");
        let (files, unreadable) = collect_peripheral_backup_files(&[bogus]);
        assert!(files.is_empty());
        assert_eq!(unreadable, 1, "目录读失败必须计数: {unreadable}");
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// 读「本机被 Trim 禁用的启动项」台账（见 `startup_ledger_file` 的取本口径）。
///
/// v4 组 1（R5-M03）三态化：旧实现把「读失败 / 解析失败 / 结构非数组」一律归空数组，
/// 而消费链紧接着 `write_disabled_records(&records)` 把空集写回 —— **损坏即永久丢账**
/// （已禁用项在下次扫描被当成「未禁用」）。现在损坏返回 Err（现场已由 read_json_state
/// 隔离 + 留痕），调用方必须**拒绝本次操作**、不得写回。
///
/// v4 修复（2026-10-09）：台账是**裸数组**，必须走 `read_json_array_state` —— 此前
/// 借用对象版 `read_json_state`（对非对象一律判 Corrupt），合法数组被当损坏处理，
/// 启用/禁用 100% 在读台账处中止（真机症状「能删除不能禁用」，删除链不读台账）。
fn read_disabled_records() -> Result<Vec<Value>, String> {
    let Some(f) = startup_ledger_file() else { return Ok(Vec::new()) };
    match crate::security::read_json_array_state(&f) {
        crate::security::JsonState::Ok(Value::Array(arr)) => {
            Ok(arr.into_iter().filter(|v| !v.is_null()).collect())
        }
        crate::security::JsonState::Ok(_) => {
            crate::engine::log::write_log("warn", "启动项禁用台账结构异常（非数组），已按损坏处理（不写回）");
            Err("启动项禁用台账结构异常，已保留现场，本次未改动台账".into())
        }
        crate::security::JsonState::Corrupt => {
            Err("启动项禁用台账读取失败（现场已隔离/见日志），本次未改动台账".into())
        }
        crate::security::JsonState::Absent => Ok(Vec::new()),
    }
}

fn write_disabled_records(records: &[Value]) {
    let dir = startup_backup_dir();
    let _ = std::fs::create_dir_all(&dir);
    let f = startup_disabled_file();
    // 空台账写 `[]` 而不是删文件：删掉后「最近修改的那本」会回到老根那份历史账，
    // 用户已经启用回来的项会被再次报成「Trim 禁用的」（见 startup_ledger_file）。
    let payload = if records.is_empty() { Value::Array(Vec::new()) } else { Value::Array(records.to_vec()) };
    // v2-L4P-23（A-5）：改走原子写。原实现 File::create 直接截断——进程在写入中途
    // 崩溃/断电会留下半截 JSON，read_disabled_records 解析失败静默归空 ⇒ 启用回来的
    // 项凭空消失。写日志留痕（原子写失败 = 台账更新没生效，得让维护者看得见）。
    if let Err(e) = crate::security::atomic_write_json(&f, &payload) {
        crate::engine::log::write_log("warn", &format!("启动项禁用台账写入失败（保留旧账）: {e}"));
    }
}



/// StartupApproved 键路径。`subkey` = `Run` / `Run32` / `StartupFolder`——
/// 批准位按来源分键存放，写死 `Run` 会让 32 位项（Run32）被写错位置。
fn startup_approved_key(hive: HKEY, subkey: &str) -> String {
    if hive == HKEY_CURRENT_USER {
        format!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{subkey}")
    } else {
        format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{subkey}")
    }
}

/// 读 StartupApproved blob
unsafe fn read_approved_blob(hive: HKEY, subkey: &str, value_name: &str) -> Option<Vec<u8>> {
    let key = startup_approved_key(hive, subkey);
    let sk = to_wide(&key);
    let mut hk = HKEY::default();
    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() { return None; }
    let nm = to_wide(value_name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        let _ = RegCloseKey(hk); return None;
    }
    if ty != REG_BINARY || size == 0 { let _ = RegCloseKey(hk); return None; }
    let mut buf = vec![0u8; size as usize];
    let r = RegQueryValueExW(hk, PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size));
    let _ = RegCloseKey(hk);
    if r.is_err() { None } else { Some(buf) }
}

/// 写 StartupApproved blob，设置/清除 bit0，写后回读校验
unsafe fn set_approved_bit(hive: HKEY, subkey: &str, value_name: &str, disable: bool) -> Result<(), String> {
    let key = startup_approved_key(hive, subkey);
    // 确保键存在
    let sk = to_wide(&key);
    let mut hk = HKEY::default();
    let mut disp = REG_CREATED_NEW_KEY;
    if RegCreateKeyExW(hive, PCWSTR(sk.as_ptr()), None, PCWSTR::default(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut hk, Some(&mut disp)).is_err() {
        return Err("无法创建 StartupApproved 键".into());
    }
    // 读现有 blob
    let mut bytes = read_approved_blob(hive, subkey, value_name).unwrap_or_else(|| {
        let mut b = vec![0u8; 12];
        b[0] = 2; // 无记录时按启用起手
        b
    });
    if bytes.len() < 12 { bytes.resize(12, 0); }
    if disable { bytes[0] |= 1; } else { bytes[0] &= 0xFE; }
    let nm = to_wide(value_name);
    if RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_BINARY, Some(&bytes)).is_err() {
        let _ = RegCloseKey(hk);
        return Err("写 StartupApproved blob 失败".into());
    }
    let _ = RegCloseKey(hk);
    // 回读校验
    if let Some(back) = read_approved_blob(hive, subkey, value_name) {
        let got = back.first().map(|b| b & 1 == 1).unwrap_or(false);
        if got != disable {
            return Err("StartupApproved 回读不符（可能被策略或安全软件覆盖）".into());
        }
    }
    Ok(())
}



/// 启动项启用/禁用（原 PS 时代脚本 startup_enable.ps1 / startup_disable.ps1，已退役；S3）
///
/// 覆盖：注册表项（StartupApproved blob 为主，删值式为回退）、文件夹项（移动备份）、
/// 计划任务（schtasks /Change）。disabled.json 记账维护。
/// 启动项改写的进程级串行锁（2026-10-09）。
///
/// 为什么必须有：`startup_toggle` / `startup_delete` 的「读台账 → 逐项改 → 写回台账」
/// 是读-改-写窗口，两个并发调用（用户连点两次、或两次 IPC 重叠）会各读一份旧账、
/// 后写覆盖前写 —— 丢掉的正是「启用还原」的唯一依据（禁用项从此还原不回来）。
/// 锁粒度取整次操作（台账与注册表一起串行；两个真机探针用例并发跑也因此确定化）。
/// 扫描侧只读不锁：台账写入是原子的，读者看到的要么是旧账要么是新账，无撕裂。
static STARTUP_LEDGER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn startup_toggle(items: &[Value], enable: bool) -> Result<Value, String> {
    let _guard = STARTUP_LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        // v4 组 1（R5-M03）：台账损坏时不得用空集继续跑 —— 旧链在这里读空、循环照跑、
        // 最后 write 把空集写回（已禁用项整本记账永久丢失）。损坏即整批拒绝（fail-closed），
        // 现场已由 read_json_state 隔离 + 留痕。
        let mut records = match read_disabled_records() {
            Ok(r) => r,
            Err(msg) => return Err(format!("{msg}；为避免覆盖损坏台账，本次操作已中止")),
        };
        let mut results: Vec<Value> = Vec::new();
        let mut success = 0i64;
        let mut failed = 0i64;

        for item in items {
            let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let source = item.get("source").and_then(|v| v.as_str()).unwrap_or("").to_string();

            let result = match source.as_str() {
                "registry" => toggle_registry_item(item, enable, &mut records),
                "folder" => toggle_folder_item(item, enable, &mut records),
                "task" => toggle_task_item(item, enable),
                _ => Err("未知来源类型".into()),
            };

            match result {
                Ok(msg) => {
                    success += 1;
                    results.push(json!({"id": id, "name": name, "status": "ok", "message": msg}));
                }
                Err(e) => {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": e}));
                }
            }
        }

        write_disabled_records(&records);
        Ok(json!({"success": success, "failed": failed, "results": results}))
    }
}

unsafe fn toggle_registry_item(item: &Value, enable: bool, records: &mut Vec<Value>) -> Result<String, String> {
    let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let reg_path = item.get("regPath").and_then(|v| v.as_str()).unwrap_or("");
    let value_name = item.get("valueName").and_then(|v| v.as_str()).unwrap_or("");
    // K04：真实 hive 以 regPath 解析结果为准——台账行/快照自带的 hive 字段只作对账，
    // 不作为授权。旧写法按 item.hive 选句柄：台账谎报 HKCU 即可让 HKLM 路径的读写
    // 落进用户 hive（或反向骗过命令层按 item.hive 判的 HKLM 提权前置门）。
    let (hive, subkey) = parse_reg_path(reg_path).ok_or("注册表路径格式错误")?;
    let hive_tag = hive_tag_of(hive, &subkey);
    // 32 位 Run 项的批准位在 StartupApproved\Run32；写死了 Run 会既禁不掉该项，
    // 又可能误标同名 64 位项。回读校验与写入用同一个子键名，不再自证清白。
    let approved_subkey = if subkey.to_ascii_uppercase().contains("WOW6432NODE") { "Run32" } else { "Run" };
    // RunOnce 项**完全不碰批准位**（StartupApproved 没有 RunOnce 子键，系统约定只覆盖
    // Run/Run32/启动文件夹，2026-10-09 真机核实）：禁用走备份+删值、启用走台账恢复，
    // 写/清 blob 都是死数据（还可能给同名 Run 项留一条 02-… 的空批准位）。
    let is_run_once = subkey
        .rsplit('\\')
        .next()
        .map(|s| s.to_ascii_lowercase().starts_with("runonce"))
        .unwrap_or(false);

    if enable {
        // 启用：优先清 StartupApproved bit0（RunOnce 除外，见上）
        if reg_read_value_typed(hive, &subkey, value_name).is_some() {
            if !is_run_once {
                set_approved_bit(hive, approved_subkey, value_name, false)?;
            }
            records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
            return Ok("已启用".into());
        }
        // 值已被删除：从 disabled.json 恢复。
        // v5-K09 批次 5：台账凭据只对本域 8 条 Run/RunOnce 容器生效——快照条目的
        // hive/子键必须与 RUN_PATHS 成对命中，否则拒绝恢复（fsDelete 侧 containment
        // 同口径；此前启用臂无任何容器校验，提权态可按篡改台账写任意 Run 值）。
        // v6-K04：tag 改用 regPath 解析出的真实 hive（hive_tag_of），台账行自带的
        // hive 只作对账。
        registry_container_verdict(hive_tag, &subkey)?;
        let rec = records.iter().find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
            .cloned().ok_or("缺少启用记录，且注册表中已无该项")?;
        let kind_str = rec.get("valueType").and_then(|v| v.as_str()).unwrap_or("String");
        let kind = match kind_str {
            "ExpandString" => REG_EXPAND_SZ,
            "DWord" => REG_DWORD,
            "QWord" => REG_QWORD,
            "Binary" => REG_BINARY,
            "MultiString" => REG_MULTI_SZ,
            _ => REG_SZ,
        };
        let data: Vec<u8> = if kind_str == "Binary" {
            let b64 = rec.get("valueDataB64").and_then(|v| v.as_str()).unwrap_or("");
            base64_decode(b64).unwrap_or_default()
        } else if kind_str == "MultiString" {
            let arr = rec.get("valueDataArray").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let mut bytes = Vec::new();
            for s in arr {
                let text = s.as_str().unwrap_or("");
                let wide: Vec<u16> = text.encode_utf16().collect();
                for w in &wide { bytes.extend_from_slice(&w.to_le_bytes()); }
                bytes.extend_from_slice(&[0, 0]);
            }
            bytes.extend_from_slice(&[0, 0]);
            bytes
        } else if kind_str == "DWord" || kind_str == "QWord" {
            let val = rec.get("valueData").and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            if kind_str == "DWord" { (val as u32).to_le_bytes().to_vec() } else { val.to_le_bytes().to_vec() }
        } else {
            let text = rec.get("valueData").and_then(|v| v.as_str()).unwrap_or("");
            let wide: Vec<u16> = text.encode_utf16().collect();
            let mut bytes = Vec::new();
            for w in &wide { bytes.extend_from_slice(&w.to_le_bytes()); }
            bytes.extend_from_slice(&[0, 0]);
            bytes
        };
        if !reg_write_value(hive, &subkey, value_name, kind, &data) {
            return Err("回写未生效（可能需要管理员权限）".into());
        }
        records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
        Ok("已启用".into())
    } else {
        // 禁用：Run/Run32 优先写 StartupApproved blob；RunOnce **一律走备份+删值** ——
        // 批准位对 RunOnce 是死数据（判定见函数头 is_run_once）：界面显示「已禁用」
        // 而下次登录该程序照样执行一次。删值 + 记账后，扫描的 disabled.json 合并会把
        // 该项以「已禁用（Trim）」呈现，启用走同一本账恢复原值（与启动文件夹项同构）。
        //
        // v6-K04：禁用臂同样过容器准入（此前只有启用臂有）——提权态下台账/快照注入行
        // 可指向任意 Run 容器外的值，删值+备份即「任意注册表值删除」。
        registry_container_verdict(hive_tag, &subkey)?;
        if reg_read_value_typed(hive, &subkey, value_name).is_none() {
            return Err("注册表值不存在".into());
        }
        let approve_fail: Option<String> = if is_run_once {
            Some("RunOnce 项无系统批准位".to_string())
        } else {
            set_approved_bit(hive, approved_subkey, value_name, true).err()
        };
        match approve_fail {
            None => Ok("已禁用（注册表值保留，可随时还原）".into()),
            Some(why) => {
                // 回退：删值 + 备份（RunOnce 直接走这里）
                let (kind, data) = reg_read_value_typed(hive, &subkey, value_name)
                    .ok_or("读取注册表值失败")?;
                let kind_str = match kind {
                    REG_EXPAND_SZ => "ExpandString", REG_DWORD => "DWord", REG_QWORD => "QWord",
                    REG_BINARY => "Binary", REG_MULTI_SZ => "MultiString", _ => "String",
                };
                let (v_data, v_b64, v_arr) = if kind == REG_BINARY {
                    (String::new(), base64_encode(&data), Value::Array(vec![]))
                } else if kind == REG_MULTI_SZ {
                    let wide: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let parts: Vec<String> = wide.split(|&c| c == 0).filter(|s| !s.is_empty())
                        .map(|s| String::from_utf16_lossy(s)).collect();
                    (String::new(), String::new(), Value::Array(parts.into_iter().map(|s| json!(s)).collect()))
                } else if kind == REG_DWORD || kind == REG_QWORD {
                    // R5a-M08：畸形短值（REG_DWORD < 4 字节 / REG_QWORD < 8 字节）在旧
                    // 固定下标下越界 panic，整批启停中止、台账不落盘。备份必须忠实——
                    // 记不下的值不删（fail-closed 逐条报错，批内其余项继续）。
                    let need = if kind == REG_DWORD { 4usize } else { 8usize };
                    if data.len() < need {
                        return Err(format!(
                            "注册表值长度畸形（{} 仅 {} 字节），拒绝备份删除",
                            if kind == REG_DWORD { "REG_DWORD" } else { "REG_QWORD" },
                            data.len()
                        ));
                    }
                    let val = if kind == REG_DWORD { u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as i64 }
                        else { i64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]) };
                    (val.to_string(), String::new(), Value::Array(vec![]))
                } else {
                    let wide: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
                    (String::from_utf16_lossy(&wide[..end]), String::new(), Value::Array(vec![]))
                };
                if !reg_delete_value(hive, &subkey, value_name) {
                    return Err(if is_run_once { "删除 RunOnce 值失败".into() } else { why.clone() });
                }
                let rec = json!({
                    "id": id, "name": item.get("name"), "command": v_data,
                    "source": "registry",
                    // K04：台账行的 hive/scope 写**解析出的真实值**（对账用）。
                    // 旧写法原样抄 item 的字段——台账被篡改时账上记的 hive 与真正
                    // 写入的 hive 不一致，后续对账（needs_hklm 等）会按假值判。
                    "hive": hive_tag,
                    "regPath": reg_path,
                    "valueName": value_name, "valueType": kind_str,
                    "valueData": v_data, "valueDataB64": v_b64, "valueDataArray": v_arr,
                    "filePath": "", "taskPath": "", "taskName": "",
                    "location": item.get("location"),
                    "scope": if hive == HKEY_LOCAL_MACHINE { "HKLM" } else { "HKCU" },
                    "publisher": item.get("publisher"), "resolvedPath": item.get("resolvedPath"),
                });
                records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
                records.push(rec);
                Ok(if is_run_once {
                    "已禁用（RunOnce 项：备份后删除原值，可在列表中随时启用还原）".into()
                } else {
                    format!("已禁用（回退为删除值方式：{why}）")
                })
            }
        }
    }
}

unsafe fn toggle_folder_item(item: &Value, enable: bool, records: &mut Vec<Value>) -> Result<String, String> {
    let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let file_path = item.get("filePath").and_then(|v| v.as_str()).unwrap_or("");

    if enable {
        let rec = records.iter().find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
            .cloned().ok_or("缺少启用记录")?;
        let backup_path = rec.get("filePath").and_then(|v| v.as_str()).unwrap_or("");
        let orig_path = rec.get("valueData").and_then(|v| v.as_str()).unwrap_or("");
        if backup_path.is_empty() || !std::path::Path::new(backup_path).exists() {
            return Err("备份文件不存在".into());
        }
        // v5-K09 批次 5：台账坐标过准入（containment + 保护面），在 rename 之前拦——
        // 同用户篡改 disabled.json（%APPDATA% 可写）注入任意 move 坐标时，这里 fail-closed。
        folder_restore_verdict(backup_path, orig_path)?;
        if let Some(parent) = std::path::Path::new(orig_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::rename(backup_path, orig_path).map_err(|e| format!("移回失败: {e}"))?;
        if std::path::Path::new(orig_path).exists() {
            records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
            Ok("已启用".into())
        } else {
            Err("移回未生效".into())
        }
    } else {
        if !std::path::Path::new(file_path).exists() {
            return Err("文件不存在".into());
        }
        // K04：源路径 containment + 保护面，在 rename 之前——disabled.json 的记录会被
        // startup_scan 原样合并进扫描结果（%APPDATA% 可写），命令层快照校验只证明
        // 「id 来自上次扫描」；无这道闸，提权态可把任意存在文件 rename 进备份目录。
        folder_source_verdict(file_path)?;
        let files_dir = startup_files_dir();
        let _ = std::fs::create_dir_all(&files_dir);
        let stamp = backup_stamp();
        let safe_name: String = item.get("name").and_then(|v| v.as_str()).unwrap_or("item")
            .chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
        let ext = std::path::Path::new(file_path).extension()
            .and_then(|e| e.to_str()).unwrap_or("");
        // R5a-M03：备份名 = 批次时间戳 + 清洗显示名，同批次同名的两次禁用会解析出
        // 同一落点，而 Windows 的 rename 语义是覆盖——前一份还原凭据被静默毁掉。
        // 追加进程内单调序号：同一毫秒内也不重名（名字不被任何解析链消费，见 backup_stamp）。
        static BACKUP_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = BACKUP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut dest = files_dir.join(format!("{stamp}_{seq:04}_{safe_name}.{ext}"));
        while dest.exists() {
            let seq = BACKUP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            dest = files_dir.join(format!("{stamp}_{seq:04}_{safe_name}.{ext}"));
        }
        std::fs::rename(file_path, &dest).map_err(|e| format!("移动备份失败: {e}"))?;
        let rec = json!({
            "id": id, "name": item.get("name"), "command": file_path,
            "source": "folder", "hive": item.get("hive"), "regPath": "", "valueName": "",
            "valueType": "", "valueData": file_path, "valueDataB64": "", "valueDataArray": [],
            "filePath": dest.to_string_lossy().to_string(), "taskPath": "", "taskName": "",
            "location": item.get("location"), "scope": item.get("scope"),
            "publisher": item.get("publisher"), "resolvedPath": item.get("resolvedPath"),
        });
        records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id));
        records.push(rec);
        Ok("已禁用".into())
    }
}

unsafe fn toggle_task_item(item: &Value, enable: bool) -> Result<String, String> {
    let task_path = item.get("taskPath").and_then(|v| v.as_str()).unwrap_or("");
    let task_name = item.get("taskName").and_then(|v| v.as_str()).unwrap_or("");
    if task_name.is_empty() { return Err("缺少任务名".into()); }
    let full_name = format!("{task_path}{task_name}");
    let arg = if enable { "/ENABLE" } else { "/DISABLE" };
    // v6-K01（P0-2）：解析失败与 spawn 失败同报错口径
    let output = crate::engine::systembin::quiet_cmd_timeout(
        system_tool("schtasks")?,
        &["/Change", "/TN", &full_name, arg],
        crate::engine::systembin::SCHTASKS_TIMEOUT,
    ).map_err(|e| format!("schtasks 执行失败: {e}"))?;
    if output.status.success() {
        Ok(if enable { "已启用".into() } else { "已禁用".into() })
    } else {
        let stderr = crate::engine::systembin::decode_native_output(&output.stderr);
        Err(if stderr.is_empty() { "操作未生效（可能需要管理员权限）".into() } else { stderr })
    }
}

/// 备份文件名的时间戳（v4 R5-M08 改真源）。
///
/// 旧实现日期段恒 `19700101`（从不写真实日期）且 `+8` 硬编码——备份名只随「时分秒」
/// 变化：**不同天同一秒**的两次备份同名，`rename` 直接静默覆盖前一份。
/// 改走仓库时间真源 `now_ms()`（毫秒时间戳，定宽 13 位）：唯一性大升、不再手搓时区。
/// 名字不被任何解析链消费（台账存全路径），只影响人眼可读性。
fn backup_stamp() -> String {
    crate::engine::now_ms().to_string()
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 { result.push(CHARS[((n >> 6) & 63) as usize] as char); } else { result.push('='); }
        if chunk.len() > 2 { result.push(CHARS[(n & 63) as usize] as char); } else { result.push('='); }
    }
    result
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 { return None; }
        let mut n = 0u32;
        let mut valid = 4;
        for (i, &b) in chunk.iter().enumerate() {
            let v = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62, b'/' => 63,
                b'=' => { valid = i; break; }
                _ => return None,
            };
            n |= (v as u32) << (18 - i * 6);
        }
        result.push((n >> 16) as u8);
        if valid > 2 { result.push((n >> 8) as u8); }
        if valid > 3 { result.push(n as u8); }
    }
    Some(result)
}


// ==================== B5 startup_delete：启动项删除 ====================

fn startup_deleted_dir() -> std::path::PathBuf {
    let dir = crate::engine::paths::backup_write_dir("startup-backup").join("deleted");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// K04：folder 删除臂的两种结局（纯枚举，供测试断言用）。
#[derive(Debug)]
enum FolderDeletePlan {
    /// 台账登记过的备份文件本体（源文件已被禁用搬走）⇒ 回收站删备份。
    BackupFile(String),
    /// 还在的源文件 ⇒ 调用方先复制到 deleted/ 再回收站删源文件。
    StartupFile(String),
}

/// K04：folder 删除臂的逐项计划（纯函数，可测——不碰台账、不写盘）。
///
/// 与旧内联版的差别只有 containment：源路径限两个启动文件夹、备份路径限本域备份根，
/// 两个落点之外一律拒（逐条计数，不再静默 copy + 投回收站）。合法形态有两种：
/// ① 台账登记过的备份（源文件不在启动文件夹了）⇒ BackupFile；
/// ② 源文件还在 ⇒ StartupFile——它要么是启动文件夹里的活文件，要么是禁用后
///    不重扫直接删的形状（快照项 filePath 就是备份落点，住在本域备份根内）。
fn plan_folder_delete(item: &Value, records: &[Value]) -> Result<FolderDeletePlan, String> {
    let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let file_path = item.get("filePath").and_then(|v| v.as_str()).unwrap_or("");
    let rec = records.iter().find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id));
    let backup_path = rec.and_then(|r| r.get("filePath").and_then(|v| v.as_str())).unwrap_or("");

    // ① 台账登记过的备份（源文件已被禁用搬走、此刻不在启动文件夹里）
    if !backup_path.is_empty()
        && std::path::Path::new(backup_path).exists()
        && !std::path::Path::new(file_path).exists()
    {
        // 备份路径来自台账（%APPDATA% 可写），必须限在本域备份根内
        backup_in_root_verdict(backup_path)?;
        return Ok(FolderDeletePlan::BackupFile(backup_path.to_string()));
    }
    if !std::path::Path::new(file_path).exists() {
        return Err("文件不存在".into());
    }
    // ② 源文件还在：两个合法落点（启动文件夹 / 本域备份根）之外一律拒
    if folder_source_verdict(file_path).is_ok() || backup_in_root_verdict(file_path).is_ok() {
        return Ok(FolderDeletePlan::StartupFile(file_path.to_string()));
    }
    Err("源路径不在本域启动文件夹或备份根内，已拒绝".into())
}



/// 启动项删除（原 PS 时代脚本 startup_remove.ps1，已退役；S3）
///
/// 注册表：reg.exe export 备份整个键 + RegDeleteValueW 删值
/// 文件夹：复制到 deleted/ 备份，返回 fsDelete 由主进程回收站删除
/// 计划任务：schtasks /Query /XML 备份 + schtasks /Delete 删除
pub fn startup_delete(items: &[Value]) -> Result<Value, String> {
    let _guard = STARTUP_LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let deleted_dir = startup_deleted_dir();
    let stamp = crate::engine::now_ms().to_string();

    // 取本口径必须与读取链同一份（`startup_ledger_file` → 最近修改那本）：
    // 固定读新根会在老根存有历史账时形成两个「权威账本」——删除链改的那本
    // 不是界面/还原链读的那本，清空后老根历史还会复活。
    // v4 组 1（R5-M03）：台账损坏时整批拒绝（同 startup_toggle）——绝不用空集继续跑再写回。
    let mut records: Vec<Value> = match read_disabled_records() {
        Ok(r) => r,
        Err(msg) => return Err(format!("{msg}；为避免覆盖损坏台账，本次删除已中止")),
    };

    let mut results: Vec<Value> = Vec::new();
    let mut fs_delete: Vec<Value> = Vec::new();
    let mut success = 0i64;
    let mut failed = 0i64;

    for item in items {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let source = item.get("source").and_then(|v| v.as_str()).unwrap_or("");

        match source {
            "registry" => {
                let reg_path = item.get("regPath").and_then(|v| v.as_str()).unwrap_or("");
                let value_name = item.get("valueName").and_then(|v| v.as_str()).unwrap_or("");
                if reg_path.is_empty() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "缺少注册表路径"}));
                    continue;
                }
                let (hive, subkey) = match parse_reg_path(reg_path) {
                    Some(v) => v,
                    None => { failed += 1; results.push(json!({"id": id, "name": name, "status": "error", "message": "注册表路径格式错误"})); continue; }
                };
                // K04：删除臂同样过容器准入（此前只有启用臂有）——快照/台账行可指向
                // 任意 Run 容器外的值，export 备份 + RegDeleteValueW 即「任意注册表
                // 值删除」。真实 hive/scope 以 regPath 解析结果为准。
                if let Err(e) = registry_container_verdict(hive_tag_of(hive, &subkey), &subkey) {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": e}));
                    continue;
                }
                // 备份整个键到 .reg
                let safe = safe_name(&name);
                let reg_file = deleted_dir.join(format!("{stamp}_reg_{safe}.reg"));
                let hive_short = if hive == HKEY_LOCAL_MACHINE { "HKLM" } else { "HKCU" };
                let export_path = format!("{hive_short}\\{subkey}");
                // 审查 v3-L7：非 UTF-8 路径上 to_str() 为 None，记失败跳过而不是 panic
                let Some(reg_file_str) = reg_file.to_str() else {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "备份路径无法编码，未执行删除"}));
                    continue;
                };
                // v2-L4P-29（B-7）：备份类子进程统一走带超时入口，reg.exe 被拖住不再永久挂死
                // v6-K01（P0-2）：解析失败并进 is_err 分支（备份不完整绝不删值）
                let export_out = crate::engine::systembin::system_tool("reg.exe")
                    .map_err(std::io::Error::other)
                    .and_then(|exe| {
                        crate::engine::systembin::quiet_cmd_timeout(
                            exe,
                            &["export", &export_path, reg_file_str, "/y"],
                            crate::engine::systembin::REG_EXPORT_TIMEOUT,
                        )
                    });
                if export_out.is_err() || !reg_file.exists() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "注册表备份失败，未执行删除"}));
                    continue;
                }
                // 删值
                unsafe {
                    let sk = to_wide(&subkey);
                    let mut hk = HKEY::default();
                    if RegOpenKeyExW(hive, PCWSTR(sk.as_ptr()), Some(0), KEY_SET_VALUE, &mut hk).is_err() {
                        failed += 1;
                        results.push(json!({"id": id, "name": name, "status": "error", "message": "无法打开注册表键"}));
                        continue;
                    }
                    let nm = to_wide(value_name);
                    let _ = RegDeleteValueW(hk, PCWSTR(nm.as_ptr()));
                    let _ = RegCloseKey(hk);
                    // 回读
                    let sk2 = to_wide(&subkey);
                    let mut hk2 = HKEY::default();
                    let still_exists = if RegOpenKeyExW(hive, PCWSTR(sk2.as_ptr()), Some(0), KEY_READ, &mut hk2).is_ok() {
                        let nm2 = to_wide(value_name);
                        let mut ty = REG_VALUE_TYPE::default();
                        let mut size = 0u32;
                        let exists = RegQueryValueExW(hk2, PCWSTR(nm2.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_ok();
                        let _ = RegCloseKey(hk2);
                        exists
                    } else { false };
                    if still_exists {
                        failed += 1;
                        results.push(json!({"id": id, "name": name, "status": "error", "message": "删除未生效（可能需要管理员权限）"}));
                    } else {
                        // 从 disabled.json 移除记录
                        records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id.as_str()));
                        success += 1;
                        results.push(json!({"id": id, "name": name, "status": "ok", "message": "已删除（已备份注册表键）"}));
                    }
                }
            }
            "folder" => {
                // K04：逐项计划（纯函数，可测）——containment 在计划里判，失败逐条计数。
                match plan_folder_delete(item, &records) {
                    Ok(FolderDeletePlan::BackupFile(backup_path)) => {
                        // 台账登记过的备份文件（源文件已被禁用搬走过）：回收站删备份本体
                        fs_delete.push(json!({"id": id, "name": name, "path": backup_path, "kind": "backup-file"}));
                        records.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(id.as_str()));
                        results.push(json!({"id": id, "name": name, "status": "deferred", "message": "备份文件待主进程回收站删除"}));
                    }
                    Ok(FolderDeletePlan::StartupFile(src)) => {
                        // 备份到 deleted 目录（复制失败即失败，不送回收站）
                        let safe = safe_name(&name);
                        let ext = std::path::Path::new(&src).extension().and_then(|e| e.to_str()).unwrap_or("");
                        let dest = deleted_dir.join(format!("{stamp}_folder_{safe}.{ext}"));
                        if std::fs::copy(&src, &dest).is_err() {
                            failed += 1;
                            results.push(json!({"id": id, "name": name, "status": "error", "message": "文件备份失败"}));
                            continue;
                        }
                        fs_delete.push(json!({"id": id, "name": name, "path": src, "kind": "startup-file"}));
                        results.push(json!({"id": id, "name": name, "status": "deferred", "message": "已备份，待主进程回收站删除"}));
                    }
                    Err(msg) => {
                        failed += 1;
                        results.push(json!({"id": id, "name": name, "status": "error", "message": msg}));
                    }
                }
            }
            "task" => {
                let task_path = item.get("taskPath").and_then(|v| v.as_str()).unwrap_or("");
                let task_name = item.get("taskName").and_then(|v| v.as_str()).unwrap_or("");
                if task_name.is_empty() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "缺少任务名"}));
                    continue;
                }
                let tn = if task_path.is_empty() || task_path == "\\" { task_name.to_string() } else { format!("{}\\\\{}", task_path, task_name) };
                // 导出 XML 备份
                let safe = safe_name(&task_name);
                let xml_file = deleted_dir.join(format!("{stamp}_task_{safe}.xml"));
                let query_out = crate::engine::systembin::system_tool("schtasks")
                    .map_err(std::io::Error::other)
                    .and_then(|exe| {
                        crate::engine::systembin::quiet_cmd_timeout(
                            exe,
                            &["/Query", "/TN", &tn, "/XML"],
                            crate::engine::systembin::SCHTASKS_TIMEOUT,
                        )
                    });
                if let Ok(out) = query_out {
                    if out.status.success() {
                        // R5a-L05：任务 XML 是删除后唯一还原依据——裸 std::fs::write 半截
                        // 落盘也被 exists() 判「备份成功」，随后 schtasks /Delete 照删。
                        // 原子写 + 判 Result（与 manifest 同口径），失败走「备份失败，未执行删除」。
                        if let Err(e) = crate::security::atomic_write_file(&xml_file, &out.stdout) {
                            crate::engine::log::write_log("warn", &format!("任务 XML 备份写入失败（{tn}）: {e}"));
                        }
                    }
                }
                if !xml_file.exists() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "计划任务备份失败，未执行删除"}));
                    continue;
                }
                // 删除
                // v6-K01（P0-2）：解析失败并进 is_err 分支（与备份缺失同口径，未生效回执）
                let del_out = crate::engine::systembin::system_tool("schtasks")
                    .map_err(std::io::Error::other)
                    .and_then(|exe| {
                        crate::engine::systembin::quiet_cmd_timeout(
                            exe,
                            &["/Delete", "/TN", &tn, "/F"],
                            crate::engine::systembin::SCHTASKS_TIMEOUT,
                        )
                    });
                if del_out.is_err() || !del_out.unwrap().status.success() {
                    failed += 1;
                    results.push(json!({"id": id, "name": name, "status": "error", "message": "删除未生效（可能需要管理员权限）"}));
                } else {
                    success += 1;
                    results.push(json!({"id": id, "name": name, "status": "ok", "message": "已删除（已导出任务备份）"}));
                }
            }
            _ => {
                failed += 1;
                results.push(json!({"id": id, "name": name, "status": "error", "message": "未知来源类型"}));
            }
        }
    }

    // 写回禁用台账：空台账写 `[]` 而不是删文件（删掉后「最近修改的那本」会
    // 退回老根历史账，用户已清空的记录会复活）。写入恒落新根，等于顺带把
    // 老根那本迁移过来。
    write_disabled_records(&records);

    // v5 批次 9（D1-M05）：deleted 目录此前零 prune 无界涨——本批补上（按 13 位
    // 时间戳前缀计数，见 paths::prune_stamped_files；BACKUP_KEEP 同口径不新造数字）。
    crate::engine::paths::prune_stamped_files(&startup_deleted_dir(), crate::engine::paths::BACKUP_KEEP);

    Ok(json!({"success": success, "failed": failed, "results": results, "fsDelete": fs_delete}))
}
// ==================== B5 startup_add：新增启动项 ====================

/// 新增启动项（原 PS 时代脚本 startup_add.ps1，已退役；S3）
///
/// 写入 HKCU\Software\Microsoft\Windows\CurrentVersion\Run，值为带引号的路径。
/// 冲突检查：已存在同名启动项时返回原值，不覆盖。
/// 返回 Ok(None) 表示成功，Ok(Some(existing_value)) 表示冲突。
pub fn startup_add(path: &str, name: &str) -> Result<Option<String>, String> {
    unsafe {
        let key = r"Software\Microsoft\Windows\CurrentVersion\Run";
        let sk = to_wide(key);
        let mut hk = HKEY::default();
        let mut disp = REG_CREATED_NEW_KEY;
        if RegCreateKeyExW(HKEY_CURRENT_USER, PCWSTR(sk.as_ptr()), None, PCWSTR::default(),
            REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, None, &mut hk, Some(&mut disp)).is_err() {
            return Err("无法打开 Run 键".into());
        }
        // 冲突检查
        let nm = to_wide(name);
        if let Some(existing) = reg_read_string(hk, name) {
            if !existing.is_empty() {
                let _ = RegCloseKey(hk);
                return Ok(Some(existing));
            }
        }
        // 写入带引号的路径
        let value = format!("\"{path}\"");
        let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
        if RegSetValueExW(hk, PCWSTR(nm.as_ptr()), Some(0), REG_SZ, Some(&bytes)).is_err() {
            let _ = RegCloseKey(hk);
            return Err("写入注册表失败".into());
        }
        let _ = RegCloseKey(hk);
        Ok(None)
    }
}

#[cfg(test)]
mod k09_tests {
    use super::*;
    use serde_json::json;

    /// v5-K09 批次 5：folder 启用的台账坐标准入（containment + 保护面）。
    /// containment 是纯词法判定（path_key 归一 + 组件边界前缀），不需要文件存在；
    /// 判红自证：把 folder_restore_verdict 的备份根校验删掉 ⇒ ①③ 红；把启动文件夹
    /// 校验删掉 ⇒ ②④ 红。
    #[test]
    fn folder启用坐标准入_两道confinement加保护面() {
        let backup_root = crate::engine::paths::backup_read_dirs("startup-backup")[0]
            .to_string_lossy()
            .to_string();
        let folder_root = startup_folders()[0].clone();
        let ok_orig = format!("{}\\{}", folder_root.0, format!("{}\\probe.lnk", folder_root.1));
        // ① 合法形态：备份在根内 + 目标在启动文件夹内 ⇒ 放行
        assert!(folder_restore_verdict(&format!("{backup_root}\\1_probe.reg"), &ok_orig).is_ok());
        // ② verbatim 备份路径同样要命中（归一后同一实体不得靠前缀绕过）
        assert!(folder_restore_verdict(&format!(r"\\?\{backup_root}\1_probe.reg"), &ok_orig).is_ok());
        // ③ 越界备份：不在本域备份根内 ⇒ 拒
        let err = folder_restore_verdict(r"C:\Windows\Temp\evil.reg", &ok_orig).unwrap_err();
        assert!(err.contains("备份根"), "越界备份必须点名备份根: {err}");
        // ④ 越界恢复目标：不在两个启动文件夹内 ⇒ 拒（medium→admin move 原语的锚）
        let err = folder_restore_verdict(&format!("{backup_root}\\1_probe.reg"), r"C:\Windows\System32\evil.dll")
            .unwrap_err();
        assert!(err.contains("启动文件夹"), "越界恢复目标必须点名列表: {err}");
        // ⑤ 相邻前缀不得误放：StartupFoo 不是 Startup 的子树（组件边界）
        let evil = format!("{}\\{}", folder_root.0, format!("{}Foo\\evil.lnk", folder_root.1));
        assert!(folder_restore_verdict(&format!("{backup_root}\\1_probe.reg"), &evil).is_err());
    }

    /// v5-K09 批次 5：registry 臂的台账坐标准入——tag 限四视图、子键限四根形态。
    /// v6-K04：启用/禁用/删除三臂共用（改名 registry_container_verdict）。
    /// 判红自证：把 registry_container_verdict 改成恒 Ok ⇒ 全组红。
    #[test]
    fn registry坐标必须命中8根且tag限四视图() {
        assert!(registry_container_verdict("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run").is_ok());
        assert!(registry_container_verdict("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce").is_ok());
        assert!(registry_container_verdict("HKCU32", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run").is_ok());
        assert!(registry_container_verdict("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run").is_ok());
        assert!(registry_container_verdict("HKLM32", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce").is_ok());
        // 大小写不敏感（扫描产出与手改台账的形态都要按同一容器判）
        assert!(registry_container_verdict("hklm", r"software\MICROSOFT\Windows\CurrentVersion\Run").is_ok());
        // tag 撒谎（HKCU32 配 64 位根）不越权：句柄层 HKCU32≡HKCU，视图由 subkey 决定 ⇒ 放行
        assert!(registry_container_verdict("HKCU32", r"Software\Microsoft\Windows\CurrentVersion\Run").is_ok());
        // 相邻名字：RunX / RunOnceEx / RunServices 不是容器
        assert!(registry_container_verdict("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunX").is_err());
        assert!(registry_container_verdict("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices").is_err());
        // 完全越界：任何非 Run 容器、非法 tag 一律拒
        assert!(registry_container_verdict("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer").is_err());
        assert!(registry_container_verdict("HKLMX", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run").is_err());
        assert!(registry_container_verdict("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run").is_err());
    }

    /// K04：folder 禁用/删除臂的源路径准入——只放行两个启动文件夹之内的路径。
    /// 判红自证：把 folder_source_verdict 的 in_folder 判定改成恒 true ⇒ ②③④ 全红。
    #[test]
    fn folder源路径准入只放行启动文件夹内() {
        let (base, sub, _) = startup_folders()[0].clone();
        let root = format!("{base}\\{sub}");
        // ① 合法形态：启动文件夹内的文件放行
        assert!(folder_source_verdict(&format!(r"{root}\probe.lnk")).is_ok());
        // verbatim 形态归一后同一实体，不得靠前缀绕过
        assert!(folder_source_verdict(&format!(r"\\?\{root}\probe.lnk")).is_ok());
        // ② 越界源路径：任意存在文件都不在启动文件夹内 ⇒ 拒
        let err = folder_source_verdict(r"C:\Windows\System32\evil.dll").unwrap_err();
        assert!(err.contains("启动文件夹"), "越界源路径必须点名启动文件夹: {err}");
        // ③ 相邻前缀不得误放：StartupFoo 不是 Startup 的子树（组件边界）
        let evil = format!(r"{rootFoo}\evil.lnk", rootFoo = format!("{root}Foo"));
        assert!(folder_source_verdict(&evil).is_err(), "相邻前缀必须拒: {evil}");
        // ④ 空路径拒
        assert!(folder_source_verdict("").is_err());
    }

    /// K04 集成：越界台账投喂**禁用臂** ⇒ 拒绝且原文件不动（与启用臂同构）。
    /// 判红自证：去掉 toggle_folder_item 禁用臂里的 folder_source_verdict 调用 ⇒ 本用例红
    /// （evil 文件会被 rename 进备份目录）。
    #[test]
    fn 越界台账禁用被拒且原文件不动() {
        let root = std::env::temp_dir().join(format!("trim-k04-disable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let victim = root.join("evil.lnk");
        std::fs::write(&victim, b"x").unwrap(); // 「存在」但不在任何启动文件夹内
        let item = json!({ "id": "k04-probe", "name": "probe", "filePath": victim.to_string_lossy() });
        let mut records: Vec<Value> = Vec::new();
        let r = unsafe { toggle_folder_item(&item, false, &mut records) };
        let err = r.unwrap_err();
        assert!(err.contains("启动文件夹"), "越界源路径禁用必须被拒: {err}");
        assert!(victim.is_file(), "拒后原文件不得被动过");
        assert!(records.is_empty(), "拒后不得写台账");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// K04：folder 删除臂逐项计划——合法两形态与越界两拒绝。
    /// 判红自证：把 plan_folder_delete 里的 backup_in_root_verdict 调用删掉 ⇒ ② 红；
    /// 把 folder_source_verdict 调用删掉 ⇒ ③④ 的拒绝语义仍由 ④ 兜住，但 ② 的放行
    /// 语义（备份根内文件必须能删）会红——两道各有一个能判红的用例。
    #[test]
    fn folder删除计划_合法两形态与越界两拒绝() {
        let (base, sub, _) = startup_folders()[0].clone();
        let folder_root = format!("{base}\\{sub}");
        let backup_root = crate::engine::paths::backup_read_dirs("startup-backup")[0]
            .to_string_lossy()
            .to_string();
        let tmp = std::env::temp_dir().join(format!("trim-k04-delplan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        struct Cleanup(Vec<std::path::PathBuf>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for p in &self.0 {
                    if p.is_dir() {
                        let _ = std::fs::remove_dir_all(p);
                    } else {
                        let _ = std::fs::remove_file(p);
                    }
                }
            }
        }
        // 备份根里的样本文件自建自清（判据是纯词汇的，但计划的存在性分支要真文件）
        let probe = format!(r"{backup_root}\files\trim-k04-probe-{}.lnk", std::process::id());
        std::fs::create_dir_all(std::path::Path::new(&probe).parent().unwrap()).ok();
        std::fs::write(&probe, b"x").ok();
        let _cleanup = Cleanup(vec![tmp.clone(), std::path::PathBuf::from(&probe)]);

        // ① BackupFile：源文件已被禁用搬走（不在启动文件夹了），台账记着备份落点
        let item_gone = json!({ "id": "p1", "filePath": format!(r"{folder_root}\gone.lnk") });
        let rec = json!({ "id": "p1", "filePath": probe });
        match plan_folder_delete(&item_gone, std::slice::from_ref(&rec)) {
            Ok(FolderDeletePlan::BackupFile(p)) => assert_eq!(p, probe, "必须回收台账记的备份本体"),
            other => panic!("禁用后删除必须走 BackupFile，实得: {other:?}"),
        }

        // ② StartupFile（备份落点形态）：禁用后不重扫直接删——快照项 filePath 就是
        // 备份落点（真实存在、在本域备份根内），原样送回收站。
        let item_backup = json!({ "id": "p2", "filePath": probe });
        match plan_folder_delete(&item_backup, &[]) {
            Ok(FolderDeletePlan::StartupFile(p)) => assert_eq!(p, probe, "备份落点必须原样送回收站"),
            other => panic!("备份根内的备份文件必须按 StartupFile 放行，实得: {other:?}"),
        }

        // ③ 台账备份越界（不在本域备份根内）⇒ 拒（源文件不在时走 BackupFile 分支）
        let outside = tmp.join("outside-backup.lnk");
        std::fs::write(&outside, b"x").unwrap();
        let item3 = json!({ "id": "p3", "filePath": format!(r"{folder_root}\gone2.lnk") });
        let rec3 = json!({ "id": "p3", "filePath": outside.to_string_lossy() });
        let err = plan_folder_delete(&item3, std::slice::from_ref(&rec3)).unwrap_err();
        assert!(err.contains("备份根"), "越界备份必须拒: {err}");

        // ④ 源文件在、但既不在启动文件夹也不在备份根 ⇒ 拒（K04 主靶：投回收站）
        let victim = tmp.join("evil.lnk");
        std::fs::write(&victim, b"x").unwrap();
        let item4 = json!({ "id": "p4", "filePath": victim.to_string_lossy() });
        let err = plan_folder_delete(&item4, &[]).unwrap_err();
        assert!(err.contains("启动文件夹或备份根"), "越界源路径必须拒: {err}");

        // ⑤ 哪都不在且没有台账记录 ⇒ 按不存在拒
        let item5 = json!({ "id": "p5", "filePath": format!(r"{folder_root}\nope.lnk") });
        let err = plan_folder_delete(&item5, &[]).unwrap_err();
        assert_eq!(err, "文件不存在", "源与备份都不存在必须按不存在拒");
    }

    /// v5-K09 批次 5 集成：越界台账（备份不在本域备份根内）投喂启用 ⇒ 拒绝且原文件不动。
    /// 判红自证：去掉 toggle_folder_item 里的 folder_restore_verdict 调用 ⇒ 本用例红
    /// （evil.reg 会被 rename 到 System32 的伪造目标或以「移回失败」报错）。
    #[test]
    fn 越界台账启用被拒且原文件不动() {
        let root = std::env::temp_dir().join(format!("trim-k09-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let bf = root.join("evil.reg");
        std::fs::write(&bf, b"x").unwrap(); // 「存在」但不在本域备份根内
        let item = json!({ "id": "k09-probe", "name": "probe" });
        let rec = json!({
            "id": "k09-probe",
            "filePath": bf.to_string_lossy(),
            "valueData": r"C:\Windows\System32\evil.dll",
        });
        let mut records = vec![rec];
        let r = unsafe { toggle_folder_item(&item, true, &mut records) };
        let err = r.unwrap_err();
        assert!(err.contains("备份根"), "越界台账启用必须被拒: {err}");
        assert!(bf.is_file(), "拒后原备份文件不得被动过");
        assert!(!std::path::Path::new(r"C:\Windows\System32\evil.dll").exists(), "不得越界写入");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// v5-K09 批次 5 真机探针（只写自家台账、自建自清）：同用户篡改 disabled.json
    /// 注入越界 folder 坐标 ⇒ 启用必须被拒、System32 无残留、台账原样恢复。
    /// 台账为空（本机没有禁用记录）时 skip 声明，不假绿。
    #[test]
    #[ignore = "真机：篡改禁用台账后启用被拒（写自家台账，发布前人工跑）"]
    fn live_tampered_ledger_enable_is_rejected() {
        let ledger = crate::engine::paths::backup_read_dirs("startup-backup");
        let _ = ledger; // 台账位置经 startup_ledger_file()（read_disabled_records 内部判定）
        let original = read_disabled_records().ok();
        let Some(recs) = &original else {
            eprintln!("SKIP：台账不可读（本机无禁用记录或损坏），探针未校验");
            return;
        };
        let _ = recs;
        let probe_id = "trim-k09-live-probe";
        let forged = json!({
            "id": probe_id,
            "name": "k09-probe",
            "source": "folder",
            // 备份「存在」但不在本域备份根内（用 %TEMP% 造，自建自清）
            "filePath": std::env::temp_dir().join("trim-k09-live-forged.reg").to_string_lossy(),
            "valueData": r"C:\Windows\System32\trim-k09-should-not-exist.dll",
        });
        std::fs::write(
            std::env::temp_dir().join("trim-k09-live-forged.reg"),
            b"x",
        )
        .unwrap();
        let mut tampered = recs.clone();
        tampered.push(forged);
        write_disabled_records(&tampered);
        let items = json!([{ "id": probe_id, "name": "k09-probe", "source": "folder" }]);
        let r = startup_toggle(items.as_array().unwrap(), true);
        // 恢复台账（无论断言成败都要恢复——finally 语义）
        let restore = |recs: &Option<Vec<Value>>| {
            match recs {
                Some(v) => write_disabled_records(v),
                // 原本没有台账：写回空集（write_disabled_records 的正常形状）
                None => write_disabled_records(&[]),
            }
        };
        let msg = match &r {
            Ok(v) => v["results"][0]["message"].clone(),
            Err(e) => json!(e),
        };
        restore(&original);
        let _ = std::fs::remove_file(std::env::temp_dir().join("trim-k09-live-forged.reg"));
        assert!(
            msg.as_str().unwrap_or_default().contains("备份根") || msg.as_str().unwrap_or_default().contains("拒绝"),
            "篡改台账的启用必须被拒，实得: {msg}"
        );
        assert!(
            !std::path::Path::new(r"C:\Windows\System32\trim-k09-should-not-exist.dll").exists(),
            "越界恢复目标不得被创建"
        );
        eprintln!("探针通过：篡改台账启用被拒且台账已恢复（{msg}）");
    }
}
