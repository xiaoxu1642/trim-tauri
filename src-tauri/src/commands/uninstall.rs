//! commands/uninstall.rs — 卸载域 MVP（竞品借鉴落地方案 P0，2026-09-28）
//!
//! 方案边界（方案 §4.1，违反即回退）：
//! - 只做「看见已安装程序 → 调原厂卸载器 → 残留扫描/解释/受控清理」三步；
//! - 不做全量注册表清理器、不默认强删程序目录、不盲目静默卸载；
//! - 静默命令由构造器裁决（B1）：厂商 `QuietUninstallString` 优先，但必须先过严格闸
//!   （绝对路径 .exe、非 shell/脚本宿主、无重定向/管道/复合/变量替换、文件存在），
//!   不过闸则回退 msi/inno/nsis 白名单模板派生；命令串一律**后端现读注册表**，
//!   绝不信任渲染层回传的任何命令文本（防注入面）；
//! - 残留文件/目录回收站优先（`is_path_protected` 前置 + `trim_finder` 回收站），
//!   回收站失败不做永久删除兜底；注册表先 export 备份再删，备份失败整项拒绝；
//! - 残留执行只认**本次会话扫描快照**里的目标（任意单项不得绕过快照，方案 M4）。
//!
//! 注册（lib.rs generate_handler + CHANNEL_MAP + check-guard-tiers MUST_MAIN 同步落）：
//! ```text
//! commands::uninstall::uninstall_list,
//! commands::uninstall::uninstall_run,
//! commands::uninstall::uninstall_residue_scan,
//! commands::uninstall::uninstall_residue_execute,
//! ```

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};
use tauri::WebviewWindow;
use trim_finder::cleanup_scan;

use crate::engine::{delete_manifest, guard, log, protect, rules_signature};

/// 残留扫描快照：label -> (时间戳, findings)。执行只认快照内的 kind+target 组合。
static RESIDUE_SNAPSHOTS: OnceLock<Mutex<HashMap<String, (i64, Vec<Value>)>>> = OnceLock::new();

fn residue_snapshots() -> &'static Mutex<HashMap<String, (i64, Vec<Value>)>> {
    RESIDUE_SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ==================== 注册表读取助手（本文件自含，不动 native.rs 私有层） ====================

unsafe fn reg_sz(hk: windows::Win32::System::Registry::HKEY, name: &str) -> Option<String> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        return None;
    }
    if ty.0 != 1 && ty.0 != 2 {
        return None; // 只读 REG_SZ / REG_EXPAND_SZ
    }
    let mut buf = vec![0u8; size as usize];
    let ok = RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size)).is_ok();
    if !ok || size == 0 {
        return None;
    }
    let words: Vec<u16> = buf[..size as usize]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    Some(String::from_utf16_lossy(&words).trim().to_string())
}

unsafe fn reg_dword(hk: windows::Win32::System::Registry::HKEY, name: &str) -> Option<u32> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};
    let nm = to_wide(name);
    let mut ty = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    if RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), None, Some(&mut size)).is_err() {
        return None;
    }
    if ty.0 != 4 || size < 4 {
        return None; // 只认 REG_DWORD
    }
    let mut buf = [0u8; 4];
    let ok = RegQueryValueExW(hk, windows::core::PCWSTR(nm.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size)).is_ok();
    if !ok {
        return None;
    }
    Some(u32::from_le_bytes(buf))
}

/// 解析 "HKCU\..." / "HKLM\..." 前缀（与 engine::native::parse_reg_path 同口径，
/// 但只放行 HKCU/HKLM 两个 hive —— 残留清理面不覆盖 HKCR/HKU/HKCC）。
fn parse_reg_target(target: &str) -> Option<(windows::Win32::System::Registry::HKEY, String)> {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let t = target.trim();
    for (prefix, hive) in [
        ("HKEY_CURRENT_USER\\", HKEY_CURRENT_USER),
        ("HKCU\\", HKEY_CURRENT_USER),
        ("HKEY_LOCAL_MACHINE\\", HKEY_LOCAL_MACHINE),
        ("HKLM\\", HKEY_LOCAL_MACHINE),
    ] {
        if t.len() > prefix.len()
            && t[..prefix.len()].eq_ignore_ascii_case(prefix)
        {
            return Some((hive, t[prefix.len()..].trim_start_matches('\\').to_string()));
        }
    }
    None
}

/// Appx 包全名准入：只允许 `[A-Za-z0-9._-]`（PackageFullName 的合法字符集），
/// 喂给 PowerShell 前必须过这道闸（防引号/换行注入命令串）。
fn valid_appx_fullname(fullname: &str) -> bool {
    !fullname.is_empty()
        && fullname.len() <= 200
        && fullname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// 包全名 → 包系列名（PFN，U-4）：`Name_Version_Arch__PublisherId` → `Name_PublisherId`。
/// Name 可含下划线，Version（点分段）与 Arch（x64/x86/arm/neutral）不含下划线、
/// PublisherId（如 8wekyb3d8bbwe）也不含——所以去掉最后两段拼回即 Name。
/// 解析不出（结构不符）返回 None，调用方按空集处理。
fn package_family_name(fullname: &str) -> Option<String> {
    let (left, publisher) = fullname.rsplit_once("__")?;
    if publisher.is_empty() || publisher.contains('_') {
        return None;
    }
    let segs: Vec<&str> = left.split('_').collect();
    // 最少三段：Name（可含下划线，也可以是单段）+ Version + Arch
    if segs.len() < 3 {
        return None;
    }
    let name = segs[..segs.len() - 2].join("_");
    if name.is_empty() {
        return None;
    }
    Some(format!("{name}_{publisher}"))
}

/// 发行商串 → 友好显示（HiBit 口径）：`CN=OpenAI, O=...` 取 CN= 后首个逗号前的段。
fn friendly_publisher(publisher: &str) -> String {
    let p = publisher.trim();
    if let Some(rest) = p.strip_prefix("CN=").or_else(|| p.strip_prefix("cn=")) {
        let name = rest.split(',').next().unwrap_or(rest).trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }
    p.to_string()
}

/// Appx（Windows 应用商店应用）枚举（用户拍板 2026-09-28：「Windows应用」滑块）。
/// 走 inbox Windows PowerShell 5.1 的 Appx 模块（R0 起经统一入口 `pwsh::run_inbox_script`，
/// 与数据层 PsInline 同一咽喉：私有 tmp + BOM + Job Object + 超时收树），不新增裸 spawn。
/// 当前用户 scope（Get-AppxPackage 语义）。
/// 输出 UTF-8（命令内显式设 OutputEncoding，防止中文发行商按 OEM 码页乱码）。
///
/// 超时口径（R0，2026-10-01）：这两条原来是 `quiet_cmd(...).output()`，**没有任何超时** ——
/// Appx 模块首次加载本身就慢，子孙进程再占住管道即整条 IPC 永久挂住。
const APPX_ENUM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const APPX_REMOVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

fn enum_appx_packages() -> Result<Vec<Value>, String> {
    // Logo 取法（U-3 复检修真，2026-09-28）：Get-AppxPackage 对象**没有 Logo 属性**
    // （初版 Select Logo 恒空，前端从不请求）——真身在 manifest 的 Application/
    // VisualElements 元素的 **XML 属性** 上，PS 点号只取子元素不取属性，必须
    // GetAttribute。依次试 Square44x44/Square150x150/Logo/StoreLogo，跳过
    // ms-resource: 资源引用；manifest 写的是基准名（Logo.png），磁盘常只有
    // scale 变体（Logo.scale-200.png），不存在时同目录 stem*.png 兜底取最大。
    let script = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \
try { $out=@(); Get-AppxPackage | Where-Object { -not $_.IsFramework -and -not $_.NonRemovable } | ForEach-Object { $logo=''; \
try { $m = Get-AppxPackageManifest -Package $_ -ErrorAction Stop; $loc = $_.InstallLocation; \
foreach ($x in @($m.Package.Applications.Application)) { $ve = $x.VisualElements; if (-not $ve) { continue }; \
foreach ($k in @('Square44x44Logo','Square150x150Logo','Logo','StoreLogo')) { $v = $ve.GetAttribute($k); \
if ($v -and -not $v.StartsWith('ms-resource:') -and $loc) { $cand = Join-Path $loc ($v.Replace('/','\\')); \
if (-not (Test-Path -LiteralPath $cand)) { $dir = Split-Path $cand -Parent; $stem = [IO.Path]::GetFileNameWithoutExtension($cand); \
if (Test-Path -LiteralPath $dir) { $hit = Get-ChildItem -LiteralPath $dir -Filter ($stem + '*.png') -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1; if ($hit) { $cand = $hit.FullName } } }; \
if (Test-Path -LiteralPath $cand) { $logo = $cand; break } } }; if ($logo) { break } } } catch { }; \
$out += [pscustomobject]@{ Name=$_.Name; Publisher=$_.Publisher; Version=$_.Version; PackageFullName=$_.PackageFullName; InstallLocation=$_.InstallLocation; Logo=$logo } }; \
if ($out.Count -gt 0) { $out | ConvertTo-Json -Compress -Depth 2 }; exit 0 } \
catch { Write-Output ('ERR:' + $_.Exception.Message); exit 1 }";
    let out = crate::pwsh::run_inbox_script(script, APPX_ENUM_TIMEOUT, None)
        .map_err(|e| format!("powershell 启动失败: {e}"))?;
    let text = out.stdout.trim().to_string();
    if out.code != 0 {
        return Err(if out.timed_out {
            format!("Get-AppxPackage 超时（{}s）", APPX_ENUM_TIMEOUT.as_secs())
        } else if text.starts_with("ERR:") {
            text[4..].trim().to_string()
        } else {
            format!("Get-AppxPackage 失败（退出码 {}）", out.code)
        });
    }
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Appx 输出解析失败: {e}"))?;
    let items: Vec<Value> = match parsed {
        Value::Array(a) => a,
        obj @ Value::Object(_) => vec![obj], // 单包时 ConvertTo-Json 出对象而非数组
        _ => return Err("Appx 输出结构异常".to_string()),
    };
    Ok(items
        .into_iter()
        .filter_map(|p| {
            let fullname = p.get("PackageFullName")?.as_str()?.to_string();
            if !valid_appx_fullname(&fullname) {
                return None;
            }
            let publisher_raw = p.get("Publisher").and_then(|v| v.as_str()).unwrap_or("");
            let publisher = friendly_publisher(publisher_raw);
            let group = if publisher_raw.to_lowercase().contains("microsoft") { "system" } else { "third" };
            Some(json!({
                "id": format!("APPX|{fullname}"),
                "displayName": p.get("Name").and_then(|v| v.as_str()).unwrap_or(&fullname),
                "publisher": publisher,
                "displayVersion": p.get("Version").and_then(|v| v.as_str()).unwrap_or(""),
                "installLocation": p.get("InstallLocation").and_then(|v| v.as_str()).unwrap_or(""),
                "displayIcon": "",
                // U-3：Logo 资产路径（包安装目录下的 .png），前端经 uninstall:appx-logo
                // 懒加载转 dataURL；路径不存在/越界由命令侧校验兜底
                "logoPath": p.get("Logo").and_then(|v| v.as_str()).unwrap_or(""),
                "uninstallString": "",
                "quietUninstallString": "",
                "estimatedSizeKb": 0,
                "productCode": null,
                "installerKind": "appx",
                "group": group,
                // 枚举口径已过滤 NonRemovable（实机探针 2026-09-28：对齐 HiBit「可卸载商店应用」17 项量级）
                "removable": true,
            }))
        })
        .collect())
}

/// Appx「未注册到当前用户」补充枚举（HiBit §H6 借鉴项，2026-09-29）。
///
/// 为什么要这一路：`Get-AppxPackage` 是**当前用户**语义，看不到两类实际占盘的东西——
/// ① `AppxAllUserStore\Staged\` 下"已下载未注册"的包（占空间但不在使用中，恰恰最该清），
/// ② `AppxAllUserStore\Applications\` 下为**全用户预配**、当前用户没注册的包。
/// 本机实测结构（只读查得，非推断）：
/// `…\AppxAllUserStore\Staged\<家族名>\<包全名>` 带 `Path` 值指向包内 AppxManifest.xml；
/// `…\AppxAllUserStore\Applications\<包全名>` 直接以全名为键。
///
/// 三条纪律：
/// 1. **只读注册表，不提权、不执行**。这两类包当前用户的 `Remove-AppxPackage` 删不掉，
///    所以 `removable=false` 且不带卸载入口 —— 覆盖面不能顺手把执行面也放大
///    （刻意不改成 `-AllUsers` 裸命令，那正是本应用拒绝"透传参数面"的地方）。
/// 2. 包全名照过 `valid_appx_fullname`：注册表里的串也是外部输入，将来任何一条链把它
///    拼进命令时，这道闸必须已经生效过。
/// 3. 体积不给数：`WindowsApps` 的 ACL 标准用户读不了，读不出就返回 0 并在界面显示"——"，
///    不猜一个数冒充实测。
fn enum_appx_store_extras(seen: &std::collections::HashSet<String>) -> Vec<Value> {
    use crate::engine::native;
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

    const STORE: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore";
    let mut out: Vec<Value> = Vec::new();
    // (子树, 状态标签, 家族名层是否存在)：Staged 多一层家族名，Applications 直接是包全名
    for (sub, state, two_level) in [("Staged", "staged", true), ("Applications", "provisioned", false)] {
        for a in native::reg_enum_subkeys_pub(HKEY_LOCAL_MACHINE, &format!("{STORE}\\{sub}")) {
            let leaves: Vec<String> = if two_level {
                native::reg_enum_subkeys_pub(HKEY_LOCAL_MACHINE, &format!("{STORE}\\{sub}\\{a}"))
            } else {
                vec![a.clone()]
            };
            for full in leaves {
                if full.is_empty() || !valid_appx_fullname(&full) || seen.contains(&full) {
                    continue;
                }
                // 包全名 `<名>_<版本>_<架构>_<发行商>`：取下划线路径里的名字与版本做展示
                let segs: Vec<&str> = full.split('_').collect();
                let (name, version) = (
                    segs.first().copied().unwrap_or(full.as_str()),
                    segs.get(1).copied().unwrap_or(""),
                );
                // 注册表这一路的"发布商"段是 **发布者哈希**（`8wekyb3d8bbwe` 这种），
                // 不是 Get-AppxPackage 给的 `CN=Microsoft Corporation`。真机跑出来发现两件事：
                // 哈希直接上屏在厂商列显示成乱码样，且 `Microsoft.*` 包因哈希里不含 "microsoft"
                // 被归进「第三方」。哈希只有这一个已知映射，其余一律留空让界面出"——"，
                // 不拿哈希冒充厂商名，也不靠包名前缀去猜归属。
                const MS_PUBLISHER_HASH: &str = "8wekyb3d8bbwe";
                let publisher_raw = segs.last().copied().unwrap_or("");
                let publisher = if publisher_raw.eq_ignore_ascii_case(MS_PUBLISHER_HASH) {
                    "Microsoft Corporation".to_string()
                } else {
                    String::new()
                };
                let group = if publisher_raw.eq_ignore_ascii_case(MS_PUBLISHER_HASH) { "system" } else { "third" };
                let install = if two_level {
                    native::read_reg_value_text(
                        HKEY_LOCAL_MACHINE,
                        &format!("{STORE}\\{sub}\\{a}\\{full}"),
                        "Path",
                    )
                    .map(|(_, v)| v)
                    .unwrap_or_default()
                } else {
                    String::new()
                };
                let install_dir = match install.rsplit_once('\\') {
                    Some((dir, _)) if dir.ends_with("Packages") => dir.to_string(),
                    Some((dir, _)) => dir.to_string(),
                    None => String::new(),
                };
                if !install_dir.is_empty() {
                    // 再判一次：当前用户已注册的同名包会在上面 seen 里被跳过，这里挡的是
                    // 「同一个包全名在两个子树里都出现」的重叠，避免一行出两次
                    if out.iter().any(|r| r["id"].as_str() == Some(format!("APPX|{full}").as_str())) {
                        continue;
                    }
                }
                out.push(json!({
                    "id": format!("APPX|{full}"),
                    "displayName": name,
                    "publisher": publisher,
                    "displayVersion": version,
                    "installLocation": install_dir,
                    "displayIcon": "",
                    "logoPath": "",
                    "uninstallString": "",
                    "quietUninstallString": "",
                    "estimatedSizeKb": 0,
                    "productCode": null,
                    "installerKind": "appx",
                    "group": group,
                    // 关键差别：这一类当前用户删不掉，界面据此不给卸载按钮
                    "removable": false,
                    "appxState": state,
                    "reason": if state == "staged" {
                        "已下载但未注册到当前用户，Remove-AppxPackage 对它无效（需管理员按全用户面处理）"
                    } else {
                        "为全用户预配的包，当前用户未注册，不在可卸载列表内"
                    },
                }));
            }
        }
    }
    out
}

/// Appx 移除（当前用户，对齐 HiBit 的 `powershell Remove-AppxPackage` 实测口径）。
/// 返回 Ok(()) 或带原因的 Err。NonRemovable 的包系统会拒绝，由这里如实转述。
fn remove_appx(fullname: &str) -> Result<(), String> {
    let script = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \
try {{ Remove-AppxPackage -Package '{}' -ErrorAction Stop; exit 0 }} \
catch {{ Write-Output ('ERR:' + $_.Exception.Message); exit 1 }}",
        fullname
    );
    let out = crate::pwsh::run_inbox_script(&script, APPX_REMOVE_TIMEOUT, None)
        .map_err(|e| format!("powershell 启动失败: {e}"))?;
    if out.code == 0 {
        Ok(())
    } else {
        let text = out.stdout.trim().to_string();
        Err(if out.timed_out {
            format!(
                "Remove-AppxPackage 超时（{}s），子进程树已终止，可在卸载界面重试",
                APPX_REMOVE_TIMEOUT.as_secs()
            )
        } else if text.starts_with("ERR:") {
            text[4..].trim().to_string()
        } else {
            format!("Remove-AppxPackage 失败（退出码 {}）", out.code)
        })
    }
}

/// 卸载键路径准入：必须是 Uninstall 根下的直接子键路径，禁 %VAR%/..（防把任意键当卸载键删）
fn valid_uninstall_key_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.starts_with("software\\")
        && p.contains("microsoft\\windows\\currentversion\\uninstall\\")
        && !p.contains("..")
        && !p.contains('%')
}

// ==================== uninstall:list ====================

/// 安装器类型判定（方案 §4.2 installerKind）：
/// msi（UninstallString 走 msiexec）> inno（键名 _is1 / unins000.exe）>
/// nsis（卸载器名含 uninst/uninstall）> unknown。同时抽出 MSI 产品码 {GUID}。
fn detect_installer(key_name: &str, uninstall_string: &str) -> (&'static str, Option<String>) {
    let us = uninstall_string.to_lowercase();
    if us.contains("msiexec") {
        let guid = uninstall_string
            .find('{')
            .and_then(|s| uninstall_string[s..].find('}').map(|e| uninstall_string[s..=s + e].to_string()));
        return ("msi", guid);
    }
    if key_name.to_lowercase().ends_with("_is1") || us.contains("unins000.exe") {
        return ("inno", None);
    }
    let base = us.rsplit(['\\', '/']).next().unwrap_or("");
    if base.contains("uninst") || base.contains("uninstall") {
        return ("nsis", None);
    }
    ("unknown", None)
}

/// 注册表键最后写入时间（LastWriteTime）→ "YYYY-MM-DD"，失败/异常年份返回空串。
/// U-5 安装日期列的兜底口径：卸载键的 LastWriteTime 常发生在安装/更新写入时
/// （卸载键值自带 InstallDate 的程序极少），与 HiBit 同为近似值，UI 文案注明「约」。
unsafe fn reg_key_last_write_date(hk: windows::Win32::System::Registry::HKEY) -> String {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Registry::RegQueryInfoKeyW;
    use windows::Win32::System::Time::FileTimeToSystemTime;
    let mut ft = FILETIME::default();
    if RegQueryInfoKeyW(hk, None, None, None, None, None, None, None, None, None, None, Some(&mut ft)).is_err() {
        return String::new();
    }
    let mut st = windows::Win32::Foundation::SYSTEMTIME::default();
    if FileTimeToSystemTime(&ft, &mut st).is_err() || st.wYear < 1990 || st.wYear > 2100 {
        return String::new();
    }
    format!("{:04}-{:02}-{:02}", st.wYear, st.wMonth, st.wDay)
}

/// Unix 秒（卸载键 `InstallDate` 的存储口径）→ "YYYY-MM-DD"，不可信返回 None。
///
/// 装成纯函数是为了可测：`InstallDate` 由安装器自填，**0 与越界值是常态**（MSI 的
/// 某些壳、以及"字段存在但从没写过"的情况都会留 0），一旦直接信它，列表会显示
/// 1970-01-01 这种一眼假的日子；越界值（>2100）同样按不可信处理，让调用方退回
/// 键 LastWriteTime 那一档并照旧标「约」。
fn install_date_from_epoch(secs: u32) -> Option<String> {
    if secs == 0 {
        return None;
    }
    // Howard Hinnant 的 civil_from_days：不引时区库、不加依赖（AGENTS §2 零新增依赖）
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let mut y = yoe as i64 + era * 400;
    if m <= 2 {
        y += 1;
    }
    if !(1990..=2100).contains(&y) {
        return None;
    }
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

/// 枚举一个 hive 根下的卸载条目。root 不存在 → 空集。
/// 过滤口径（与 build_inventory 同源）：空 DisplayName / SystemComponent=1 /
/// ReleaseType 含 update|hotfix|security 的跳过（系统组件与更新不是「已安装程序」）。
unsafe fn enum_uninstall_root(hive: windows::Win32::System::Registry::HKEY, root: &str) -> Vec<Value> {
    use windows::Win32::System::Registry::{RegOpenKeyExW, RegCloseKey, KEY_READ};
    let mut out = Vec::new();
    for sub in crate::engine::native::reg_enum_subkeys_pub(hive, root) {
        let sub_path = format!("{root}\\{sub}");
        let sk = to_wide(&sub_path);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            continue;
        }
        let display_name = reg_sz(hk, "DisplayName").unwrap_or_default();
        let system_component = reg_dword(hk, "SystemComponent").unwrap_or(0);
        let release_type = reg_sz(hk, "ReleaseType").unwrap_or_default().to_lowercase();
        let display_version = reg_sz(hk, "DisplayVersion").unwrap_or_default();
        let publisher = reg_sz(hk, "Publisher").unwrap_or_default();
        let install_location = reg_sz(hk, "InstallLocation").unwrap_or_default();
        let display_icon = reg_sz(hk, "DisplayIcon").unwrap_or_default();
        let uninstall_string = reg_sz(hk, "UninstallString").unwrap_or_default();
        let quiet_uninstall_string = reg_sz(hk, "QuietUninstallString").unwrap_or_default();
        let estimated_size_kb = reg_dword(hk, "EstimatedSize").unwrap_or(0);
        // P1-D6（2026-10-01）：修改/修复入口判据与不可卸载声明。布尔一律按
        // 「值存在且 ==1」算 true（ARP 口径：声明缺失 = 不限制），缺失不丢条目。
        let modify_path = reg_sz(hk, "ModifyPath").unwrap_or_default();
        let no_modify = reg_dword(hk, "NoModify").unwrap_or(0) == 1;
        let no_repair = reg_dword(hk, "NoRepair").unwrap_or(0) == 1;
        let no_remove = reg_dword(hk, "NoRemove").unwrap_or(0) == 1;
        // 安装日期两档（V2 P1-D3）：装过 `InstallDate` 就按它报（安装器写下的值，不是猜的），
        // 缺失/为 0/越界才退回卸载键 LastWriteTime 那一档 —— 兜底口径与 U-5 一致，
        // 「约」标注沿用前端现状（前端不加精确/近似区分不影响正确性，只是少一分信息）
        let install_date_exact = reg_dword(hk, "InstallDate").and_then(install_date_from_epoch);
        let install_date = install_date_exact
            .clone()
            .unwrap_or_else(|| unsafe { reg_key_last_write_date(hk) });
        let _ = RegCloseKey(hk);

        if display_name.trim().is_empty() {
            continue;
        }
        if system_component == 1 {
            continue;
        }
        if release_type.contains("update") || release_type.contains("hotfix") || release_type.contains("security") {
            continue;
        }
        let (installer_kind, product_code) = detect_installer(&sub, &uninstall_string);
        out.push(json!({
            "id": format!("{}|{}", if hive == windows::Win32::System::Registry::HKEY_CURRENT_USER { "HKCU" } else { "HKLM" }, sub_path),
            "displayName": display_name,
            "publisher": publisher,
            "displayVersion": display_version,
            "installLocation": install_location,
            "displayIcon": display_icon,
            "uninstallString": uninstall_string,
            "quietUninstallString": quiet_uninstall_string,
            "modifyPath": modify_path,
            "noModify": no_modify,
            "noRepair": no_repair,
            "noRemove": no_remove,
            "estimatedSizeKb": estimated_size_kb,
            "installDate": install_date,
            "installDateExact": install_date_exact.is_some(),
            "productCode": product_code,
            "installerKind": installer_kind,
        }));
    }
    out
}

// ==================== B6 / B7：体积兜底与最近运行（2026-09-29，借鉴方案 P2） ====================

/// 有界目录体积扫描的上限。刻意有界：卸载清单里缺 `EstimatedSize` 的程序可能正装着
/// 整个游戏库，无界递归会把"打开页面"变成一次磁盘扫描。
const DIR_SIZE_FILE_CAP: usize = 20_000;
const DIR_SIZE_DEPTH_CAP: usize = 8;

/// 有界目录体积：返回 (字节数, 已访问文件数, 是否被上限截断)。
///
/// 三条不变量：
/// - 用 `symlink_metadata` 且跳过任何重解析点 —— 跟链接走会把别的目录算进来，
///   甚至在环上永不收敛（同一原因见 `dir_delete_blocked`）；
/// - 只统计文件字节，不折算目录项与簇对齐 —— 这是"估算"，UI 上也这么写；
/// - 触顶就返回 `partial=true`，绝不把截断值当成完整值。
fn bounded_dir_size(root: &Path) -> DirSize {
    bounded_dir_size_in(root, DIR_SIZE_FILE_CAP, DIR_SIZE_DEPTH_CAP)
}

/// 一次有界目录遍历的产出。`ads_*` 单列而不并进 `bytes`：ADS 是否真的额外占盘取决于
/// 簇对齐与压缩，混进本体就说不清"估"的是哪一个数。
#[derive(Debug, Default, PartialEq)]
struct DirSize {
    bytes: u64,
    files: usize,
    partial: bool,
    ads_bytes: u64,
    ads_streams: usize,
}

/// 上限抽成入参：真机阈值（2 万文件 / 8 层）在单测里跑不起，但截断语义必须能判红。
fn bounded_dir_size_in(root: &Path, file_cap: usize, depth_cap: usize) -> DirSize {
    let mut out = DirSize::default();
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for ent in rd.flatten() {
            let Ok(md) = ent.file_type() else { continue };
            if md.is_symlink() {
                continue;
            }
            let path = ent.path();
            if md.is_dir() {
                if depth + 1 >= depth_cap {
                    out.partial = true;
                    continue;
                }
                stack.push((path, depth + 1));
                continue;
            }
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_file() => {
                    // 触顶即整体收工：只跳出当前目录会留下一栈子目录继续 read_dir，
                    // 在 target/ 这种目录数巨大的树上等于没设上限。
                    if out.files >= file_cap {
                        out.partial = true;
                        return out;
                    }
                    out.bytes = out.bytes.saturating_add(m.len());
                    out.files += 1;
                    // HiBit §H5：一并累计命名数据流（下载来源标记 Zone.Identifier 之类）。
                    // 每个文件一次 FindFirstStreamW，量级被 file_cap 天然限制住。
                    let (ab, ac) = crate::engine::native::file_ads_bytes(&path);
                    out.ads_bytes = out.ads_bytes.saturating_add(ab);
                    out.ads_streams += ac;
                }
                _ => {}
            }
        }
    }
    out
}

/// uninstall:dir-size — 体积二级兜底（B6）。清单里 `EstimatedSize` 缺失时按安装目录估。
///
/// 档位取 MAIN：唯一调用方是主窗卸载页（与 `uninstall_list` 同档）。
/// 只读、不跟随重解析点、有界，因此不写日志也不建快照。
#[tauri::command]
pub fn uninstall_dir_size<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    path: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let root = Path::new(path.trim());
    // 只接受绝对路径且真实存在的目录：其余一律不扫（也不报错给攻击面探测者额外信息）
    if path.trim().is_empty() || !root.is_absolute() || !root.is_dir() {
        return json!({ "success": false, "message": "路径不可用" });
    }
    let ds = bounded_dir_size(root);
    json!({
        "success": true,
        "data": {
            "sizeKb": ds.bytes / 1024,
            "files": ds.files,
            "partial": ds.partial,
            // HiBit §H5：命名数据流单独回传。前端只在有条目时多讲一句，
            // 它解释的是「为什么删完释放的比显示的多/少」，不是本体体积
            "adsBytes": ds.ads_bytes,
            "adsStreams": ds.ads_streams,
        }
    })
}

/// 从 Prefetch 文件名解出主程序名（`OBS64.EXE-2F3A1B4C.pf` → `OBS64.EXE`）。
/// 认不出（无 8 位十六进制后缀、非 .pf）返回 None —— 宁可不显示也不猜。
fn prefetch_entry_exe(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".pf")?;
    let (exe, hash) = stem.rsplit_once('-')?;
    if exe.is_empty() || hash.len() != 8 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(exe.to_ascii_uppercase())
}

/// 建 Prefetch 索引：主程序名（大写）→ 最后运行时间（Unix 毫秒，取文件 mtime）。
///
/// 回空表有两种**都不代表"程序从未运行"**：非提权时 `C:\Windows\Prefetch` 读不到（ACL
/// 限制），以及本机干脆关掉了 Prefetch（`EnablePrefetcher=0` / SysMain 禁用 —— 开发机实测
/// 就是这种，目录只剩一个 ReadyBoot）。所以调用方只在拿得到时渲染，拿不到就什么都不显示。
fn prefetch_last_run_index() -> std::collections::HashMap<String, i64> {
    let mut out = std::collections::HashMap::new();
    let Some(windir) = std::env::var("SystemRoot").ok() else { return out };
    let dir = Path::new(&windir).join("Prefetch");
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for ent in rd.flatten() {
        let Some(exe) = prefetch_entry_exe(&ent.file_name().to_string_lossy()) else { continue };
        let Ok(md) = ent.metadata() else { continue };
        let Ok(modified) = md.modified() else { continue };
        let Ok(d) = modified.duration_since(std::time::UNIX_EPOCH) else { continue };
        let ms = d.as_millis() as i64;
        let e = out.entry(exe).or_insert(0i64);
        if ms > *e {
            *e = ms;
        }
    }
    out
}

/// 从 DisplayIcon 里取主程序 exe 名（`C:\Apps\Foo\foo.exe,0` → `FOO.EXE`）。
/// 取不到（无扩展名、指向 dll/ico）返回 None。
fn exe_name_from_display_icon(icon: &str) -> Option<String> {
    let head = icon.split(',').next().unwrap_or("").trim();
    if head.is_empty() {
        return None;
    }
    let base = Path::new(head).file_name()?.to_string_lossy().to_string();
    if !base.to_ascii_lowercase().ends_with(".exe") {
        return None;
    }
    Some(base.to_ascii_uppercase())
}


/// 桌面与开始菜单的 `.lnk` 索引：文件名主干（小写）→ 首个命中的完整路径。
///
/// 为什么要有第四图标源：不少程序在注册表 `DisplayIcon` 里留的是安装时那台机器上的路径
/// （或被搬过、或干脆指向一个通用 dll 的索引），前端拿它取不到图；真正带着正确图标的
/// 东西是桌面/开始菜单那个快捷方式 —— `SHGetFileInfoW` 会顺着 .lnk 解析到目标图标。
/// 只按**精确同名**匹配，不做相似度：图标是锦上添花，把别家程序的图标配到这一行上，
/// 比留一个占位方块更糟。
fn shortcut_icon_index() -> std::collections::HashMap<String, String> {
    fn walk(dir: &std::path::Path, depth: usize, out: &mut std::collections::HashMap<String, String>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(mt) = e.metadata() else { continue };
            if mt.is_dir() {
                if depth > 0 {
                    walk(&p, depth - 1, out);
                }
                continue;
            }
            let is_lnk = p
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("lnk"))
                .unwrap_or(false);
            if !is_lnk {
                continue;
            }
            let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else { continue };
            let key = stem.trim().to_lowercase();
            if !key.is_empty() {
                out.entry(key).or_insert_with(|| p.to_string_lossy().to_string());
            }
        }
    }
    let joined = |var: &str, tail: &str| -> Option<(std::path::PathBuf, usize)> {
        std::env::var(var)
            .ok()
            .map(|v| (std::path::PathBuf::from(v).join(tail), if tail.contains("Start Menu") { 4 } else { 0 }))
    };
    let mut roots: Vec<(std::path::PathBuf, usize)> = Vec::new();
    for spec in [
        joined("USERPROFILE", "Desktop"),
        joined("PUBLIC", "Desktop"),
        joined("APPDATA", r"Microsoft\Windows\Start Menu\Programs"),
        joined("PROGRAMDATA", r"Microsoft\Windows\Start Menu\Programs"),
    ] {
        if let Some(r) = spec {
            roots.push(r);
        }
    }
    let mut out = std::collections::HashMap::new();
    for (root, depth) in roots {
        walk(&root, depth, &mut out);
    }
    out
}

/// 卸载域·列表（方案 M1 + 用户拍板 2026-09-28）。
/// scope：user=传统 Win32 程序（HKLM 64+32 与 HKCU 三根合并去重，HiBit「程序名」83 项的口径）；
/// windows=Appx 商店应用（Get-AppxPackage，当前用户，分第三方/Windows 应用两组）。
#[tauri::command]
pub async fn uninstall_list<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    scope: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let scope = scope.to_lowercase();
    if !matches!(scope.as_str(), "user" | "windows") {
        return json!({ "success": false, "message": "未知范围：只支持 user / windows" });
    }
    // 注册表枚举 / Appx 枚举都是纯阻塞 IO，丢 blocking 池，避免占住 async worker。
    // 枚举失败显式上抛（空数组会被当成「没有程序」伪装成功）。
    let apps = tauri::async_runtime::spawn_blocking(move || -> Result<Vec<Value>, String> {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        if scope == "windows" {
            let mut rows = enum_appx_packages()?;
            // 未注册到当前用户的两类（staged / 全用户预配）补在同一列表里，
            // 但 removable=false ⇒ 前端不给卸载按钮（HiBit §H6：覆盖面不顺手放大执行面）
            let seen: std::collections::HashSet<String> = rows
                .iter()
                .filter_map(|r| {
                    r["id"].as_str().and_then(|s| s.strip_prefix("APPX|")).map(String::from)
                })
                .collect();
            rows.extend(enum_appx_store_extras(&seen));
            return Ok(rows);
        }
        let mut apps: Vec<Value> = Vec::new();
        unsafe {
            apps.extend(enum_uninstall_root(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"));
            apps.extend(enum_uninstall_root(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"));
            apps.extend(enum_uninstall_root(HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"));
        }
        // 跨根去重（HiBit 同口径）：同一程序常同时出现在 HKLM 64 位与 WOW6432Node 键下。
        // 键 = 显示名+版本（小写）；保留先出现者（HKCU 优先，用户级条目更贴近当前用户）。
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        apps.retain(|a| {
            let key = format!(
                "{}|{}",
                a["displayName"].as_str().unwrap_or("").to_lowercase(),
                a["displayVersion"].as_str().unwrap_or("")
            );
            seen.insert(key)
        });
        // B7：主程序最近运行时间（Prefetch 文件 mtime）。非提权时那个目录读不到，
        // 回空表即可 —— 前端按「没有这个信息」渲染，**不能**把空当成「从未运行」。
        let runs = prefetch_last_run_index();
        if !runs.is_empty() {
            for a in apps.iter_mut() {
                if let Some(exe) = a["displayIcon"].as_str().and_then(exe_name_from_display_icon) {
                    if let Some(ms) = runs.get(&exe) {
                        a["lastRunMs"] = json!(ms);
                    }
                }
            }
        }
        // 图标第四源挂到行上（前端按优先级尝试，取不到仍回退占位，不新增 IPC 通道）
        let links = shortcut_icon_index();
        for a in apps.iter_mut() {
            let name = a["displayName"].as_str().unwrap_or("").trim().to_lowercase();
            if let Some(p) = links.get(&name) {
                a["shortcutPath"] = json!(p);
            }
        }
        apps.sort_by(|a, b| {
            let an = a["displayName"].as_str().unwrap_or("").to_lowercase();
            let bn = b["displayName"].as_str().unwrap_or("").to_lowercase();
            an.cmp(&bn)
        });
        Ok(apps)
    })
    .await
    .unwrap_or_else(|e| Err(format!("枚举异常: {e}")));
    match apps {
        Ok(list) => json!({ "success": true, "data": { "apps": list } }),
        Err(e) => json!({ "success": false, "message": e }),
    }
}

// ==================== uninstall:run ====================

/// 把原厂卸载命令行拆成 (exe, args)。
/// 带引号取首段引号；msiexec 直接归一；其余在「首个 .exe」处切开（卸载串的 exe
/// 路径几乎总以 .exe 结尾，比按首个空格切更稳），都失败再退回首空格。
fn split_uninstall_cmd(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some((rest[..end].to_string(), rest[end + 1..].trim().to_string()));
    }
    let low = s.to_lowercase();
    if low.starts_with("msiexec") {
        let rest = s.get(7..).unwrap_or_default().trim().to_string();
        return Some(("msiexec.exe".to_string(), rest));
    }
    if let Some(idx) = low.find(".exe") {
        let exe = s[..idx + 4].to_string();
        let args = s[idx + 4..].trim().to_string();
        return Some((exe, args));
    }
    let sp = s.find(' ')?;
    Some((s[..sp].to_string(), s[sp + 1..].trim().to_string()))
}

/// 静默卸载只认白名单模板（方案 §4.3）：msi → msiexec /X{GUID} /qn /norestart；
/// inno → /VERYSILENT /SUPPRESSMSGBOXES /NORESTART；nsis → /S。其余一律拒绝。
fn build_silent_cmd(kind: &str, product_code: Option<&str>, exe: &str, raw_args: &str) -> Result<(String, String), String> {
    match kind {
        "msi" => {
            let Some(guid) = product_code else {
                return Err("MSI 产品码缺失，无法构造静默卸载".to_string());
            };
            if !guid.starts_with('{') || !guid.ends_with('}') || guid.contains('"') {
                return Err("MSI 产品码格式异常，拒绝执行".to_string());
            }
            Ok(("msiexec.exe".to_string(), format!("/X{guid} /qn /norestart")))
        }
        "inno" => Ok((exe.to_string(), "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART".to_string())),
        "nsis" => Ok((exe.to_string(), "/S".to_string())),
        _ => {
            let _ = raw_args;
            Err("该安装器类型不受静默白名单支持，请使用原厂卸载界面".to_string())
        }
    }
}

/// 直接当卸载目标就危险的宿主：这些进程会把自己收到的参数再解释一遍，参数里的
/// `|` `&` `$` 就不再是字面量。而静默串来自注册表，是**软件自己能写**的字段。
const QUIET_DENY_HOSTS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "reg.exe",
    "regsvr32.exe",
    "sc.exe",
    "conhost.exe",
];

/// 静默命令候选（方案 §6.4）：执行层只接受这个结构，**不接受未解析的注册表原文**。
struct SilentCandidate {
    exe: String,
    args: String,
    /// `vendor` = 厂商 QuietUninstallString；`whitelist` = 本地白名单模板派生
    source: &'static str,
    /// 厂商串被拒的原因（进日志，说明为什么退回白名单派生；None = 没试过或试通）
    vendor_reject: Option<String>,
}

/// 厂商静默串准入闸（B1 强约束）：只放行「单一绝对路径 exe + 字面参数」。
/// 返回 `Some(原因)` = 拒绝该串（调用方回退白名单派生，不是放弃静默）。
/// 存在性判定注入化：闸本身保持纯函数，单测不必造真文件。
fn quiet_string_reject_reason(
    exe: &str,
    args: &str,
    file_exists: &dyn Fn(&Path) -> bool,
) -> Option<String> {
    let exe_low = exe.to_lowercase();
    let name = exe_low.rsplit(['\\', '/']).next().unwrap_or("");
    if QUIET_DENY_HOSTS.contains(&name) {
        return Some(format!("{name} 是 shell/脚本宿主，参数会被二次解释"));
    }
    if !name.ends_with(".exe") {
        return Some("目标不是 .exe（.msi/.msp 一律走 msiexec 白名单派生）".to_string());
    }
    let b = exe.as_bytes();
    let abs = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
    if !abs {
        return Some("可执行文件不是绝对路径".to_string());
    }
    if exe.contains('"') || exe.contains('\'') {
        return Some("可执行文件路径含引号".to_string());
    }
    for c in ['<', '>', '|', '&', ';', '$', '`', '\n', '\r', '\0'] {
        if args.contains(c) {
            return Some(format!("参数含 {:?} 形态（重定向/管道/复合命令/变量替换）", c));
        }
    }
    // `%` 成对出现按变量替换处理：ShellExecuteEx 不会展开它，留着只会把「没展开的字面量」
    // 交给卸载器，行为不可证明；单个 % 属于合法文件名（如 100% 目录名）则放行。
    if args.matches('%').count() >= 2 {
        return Some("参数含 %VAR% 变量替换形态".to_string());
    }
    if args.matches('"').count() % 2 != 0 {
        return Some("参数引号未闭合".to_string());
    }
    if !file_exists(Path::new(exe)) {
        return Some("可执行文件不存在".to_string());
    }
    None
}

/// 静默命令裁决（B1）：厂商静默串优先于本地拼参数，但必须先过构造闸；
/// 构造失败或语义不明 → 记录原因并回退现有白名单派生（不永久放弃该程序的静默能力）。
fn pick_silent_candidate(
    kind: &str,
    product_code: Option<&str>,
    original: &(String, String),
    quiet: Option<&str>,
    file_exists: &dyn Fn(&Path) -> bool,
) -> Option<SilentCandidate> {
    let mut vendor_reject: Option<String> = None;
    if let Some(q) = quiet.map(str::trim).filter(|s| !s.is_empty()) {
        match split_uninstall_cmd(q) {
            None => vendor_reject = Some("厂商静默串解析不出可执行文件".to_string()),
            Some((qe, qa)) => match quiet_string_reject_reason(&qe, &qa, file_exists) {
                Some(reason) => vendor_reject = Some(reason),
                None => {
                    return Some(SilentCandidate { exe: qe, args: qa, source: "vendor", vendor_reject: None })
                }
            },
        }
    }
    build_silent_cmd(kind, product_code, &original.0, &original.1)
        .ok()
        .map(|(exe, args)| SilentCandidate { exe, args, source: "whitelist", vendor_reject })
}

/// 卸载器退出码语义分档（B2）：返回 (中文语义, 是否回退原厂卸载界面)。
///
/// 口径来源要分清：`0 / 3010 / 1605` 是 Trim 此前已特判的三档；`1602 / 1618 / 1603`
/// 的语义取自 MSI 官方错误码（`1602` 用户取消、`1618` 另一安装进行中、`1603` 内部错误），
/// **本机未用真实 MSI/NSIS 样本复现过**。因此：取消与并发**不再**自动重弹原厂界面
/// （用户既然取消就不再替他决定，自动重弹等于无视取消）；`1618` 只做提示、
/// 不做有界重试（重试策略要真机证据才定，方案 §5·B2 证据边界）。
/// NSIS 的 `1/2` 不特判：与通用码空间重叠，未确认前按「其它」走原回退路径。
fn classify_exit(code: u32) -> (&'static str, bool) {
    match code {
        0 => ("卸载成功", false),
        3010 => ("卸载成功，需重启完成", false),
        1605 => ("产品未安装（该卸载键已无对应产品）", false),
        1602 => ("用户取消", false),
        1618 => ("另一个安装或卸载正在进行，请稍后再试", false),
        1603 => ("安装器内部错误", true),
        _ => ("其它退出码", true),
    }
}

/// 安装器识别的第二条证据（B4）：仅在纯字符串判定为 `unknown` 时调用，且只探
/// Inno / NSIS 的**独有文件名**（固定候选、顶层不递归、不枚举目录，所以没有
/// 「目录太大」「枚举超时」这类成本面）。
///
/// 刻意**不把 `uninstall.exe` 认成 NSIS**：那名字太通用，认了就是把 `/S` 发给一个
/// 未知卸载器——识别可以弱，执行不能猜。存在性判定由调用方注入，便于单测不触盘。
fn second_evidence_kind(install_location: &str, file_exists: &dyn Fn(&Path) -> bool) -> Option<&'static str> {
    let loc = install_location.trim().trim_end_matches(['\\', '/']).to_string();
    if loc.is_empty() || loc.chars().count() > 260 || !loc.contains(':') {
        return None;
    }
    let base = Path::new(&loc);
    for (name, kind) in [("unins000.exe", "inno"), ("nsisunins.exe", "nsis")] {
        if file_exists(&base.join(name)) {
            return Some(kind);
        }
    }
    None
}

/// ShellExecuteEx 启动卸载器并等待退出。返回 (exitCode, 是否拿到进程句柄)。
/// 不加 RUNAS verb：卸载器自带 manifest 会按需弹 UAC（对齐 Trim 按需提权模型）。
unsafe fn shell_run_wait(exe: &str, args: &str) -> Result<u32, String> {
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::core::PCWSTR;

    let file = to_wide(exe);
    let params = if args.is_empty() { None } else { Some(to_wide(args)) };
    let mut sei: SHELLEXECUTEINFOW = core::mem::zeroed();
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile = PCWSTR(file.as_ptr());
    if let Some(p) = &params {
        sei.lpParameters = PCWSTR(p.as_ptr());
    }
    sei.nShow = 1; // SW_SHOWNORMAL
    ShellExecuteExW(&mut sei).map_err(|e| format!("启动卸载器失败: {e}"))?;
    let h = sei.hProcess;
    if h.is_invalid() {
        // 拿不到句柄（目标拒绝 NOCLOSEPROCESS 等）：无法等待，如实上报
        return Err("卸载器已启动但无法等待其完成（未返回进程句柄）".to_string());
    }
    WaitForSingleObject(h, INFINITE);
    let mut code: u32 = 0;
    let _ = GetExitCodeProcess(h, &mut code);
    let _ = windows::Win32::Foundation::CloseHandle(h);
    Ok(code)
}

// ==================== 卸载进程监视（2026-09-28 用户拍板） ====================
// Inno/NSIS 卸载器会把自身复制到临时目录后由副本继续（unins000.exe → au_.exe /
// un_a.exe），或经 UAC 提权拉起新进程——「启动句柄退出」≠「卸载结束」。原实现
// wait 提前返回，残留扫描在卸载器还在跑时就执行，只扫出一条“卸载键还在”。
// 口径：先等句柄退出，再 1s 间隔轮询（上限 15 分钟）：
//   · 卸载键消失 → 卸载完成；
//   · 卸载器家族进程全部退出且连续 3 轮稳定 → 结束（用户取消 / 静默完成）；
//   · 超时 → 如实返回键的现状。

/// 当前全系统进程名快照（小写；Toolhelp32，与 native-scanner ffi 同口径）
fn process_names_snapshot() -> std::collections::HashSet<String> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut out = std::collections::HashSet::new();
    unsafe {
        // windows 0.61 返回 Result<HANDLE>；失败按空快照处理（调用方走 3 轮稳定判定）
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                let len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
                out.insert(String::from_utf16_lossy(&pe.szExeFile[..len]).to_lowercase());
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snap);
    }
    out
}

/// 卸载器家族进程判定：启动的 exe 本名 + Inno/NSIS 临时副本/提权副本/MSI 引擎
fn is_uninstaller_process(name: &str, launched: &str) -> bool {
    if name == launched {
        return true;
    }
    name == "msiexec.exe"
        || name == "au_.exe"
        || name == "un_a.exe"
        || name.starts_with("unins")
        || name.starts_with("un_a")
}

// ==================== P2-D4 占用进程与第三方模块只读自检（2026-10-01） ====================
// Geek 的对应行为：撞上被安全软件注入的进程时明说「XX 与 avcuf64.dll 不兼容，请退出该
// 应用或禁用插件」。Trim 口径刻意收窄成只报事实：谁把目标文件当模块加载着、它还加载了
// 哪些非 Windows 目录的第三方模块。不判恶意、不自动结束任何进程——「注入」这个词本身
// 带指控味，文案统一说「第三方模块」，解释方向只点名安全软件这一种常见可能。
// 纯句柄占用（数据文件被打开读）模块枚举看不见，找不到时回退原有「可能被占用」文案。

/// 模块路径是否「第三方」：不在 Windows 目录、不在本应用自身目录。
/// 排除自身目录的理由：应用自己的 DLL 占着自己的卸载目标是常态，报出来是噪声。
fn is_third_party_module(module_path: &str) -> bool {
    fn under(dir_lower: &str, root: &str) -> bool {
        let r = root.trim_end_matches(['\\', '/']).to_lowercase();
        if r.is_empty() {
            return false;
        }
        // 完全相等也算在内：self_dir 场景里目录本身就可能直接等于根（模块文件
        // 就躺在这层目录），只认「下一个字符是分隔符」会把这层漏掉；
        // C:\Windows.old 这类跨段前缀仍由「下一个字符必须是分隔符」挡住。
        dir_lower.starts_with(&r)
            && matches!(
                dir_lower.as_bytes().get(r.len()),
                Some(b'\\') | Some(b'/') | None
            )
    }
    let lower = module_path.to_lowercase();
    let Some(dir) = lower.rsplit_once('\\').map(|(d, _)| d) else {
        return false;
    };
    if under(
        dir,
        &std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()),
    ) {
        return false;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(self_dir) = exe.parent().and_then(|p| p.to_str()) {
            if under(dir, self_dir) {
                return false;
            }
        }
    }
    true
}

/// 找出把 `target` 当模块加载着的进程（只读：ToolHelp 进程快照 + EnumProcessModulesEx）。
/// 返回 (pid, 进程名, 该进程加载的第三方模块名样例)。打不开的进程直接跳过——系统进程
/// 读不到模块是常态，不能因此把检查变成报错。单进程模块数截 512、样例截 8 个：这条
/// 检查只为拼一条提示文案，量再大也用不上。
fn module_lockers(target: &Path) -> Vec<(u32, String, Vec<String>)> {
    use windows::Win32::Foundation::{CloseHandle, HMODULE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    const MODULE_CAP: usize = 512;
    const SAMPLE_CAP: usize = 8;

    let want = target.to_string_lossy().to_lowercase();
    let mut out: Vec<(u32, String, Vec<String>)> = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snap, &mut pe).is_ok();
        while more {
            let pid = pe.th32ProcessID;
            let len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let exe = String::from_utf16_lossy(&pe.szExeFile[..len]);
            more = Process32NextW(snap, &mut pe).is_ok();
            if pid == 0 {
                continue;
            }
            let Ok(h) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) else {
                continue;
            };
            let mut locker = false;
            let mut third: Vec<String> = Vec::new();
            let mut needed = 0u32;
            // 两段式：先传空指针只取 cbNeeded（文档允许），再按实际模块数取一遍
            if EnumProcessModulesEx(h, std::ptr::null_mut(), 0, &mut needed, LIST_MODULES_ALL)
                .is_ok()
                && needed > 0
            {
                let size_of_hmodule = std::mem::size_of::<HMODULE>();
                let count = ((needed as usize) / size_of_hmodule).min(MODULE_CAP);
                let mut mods = vec![HMODULE::default(); count];
                let mut got = 0u32;
                if EnumProcessModulesEx(
                    h,
                    mods.as_mut_ptr(),
                    (count * size_of_hmodule) as u32,
                    &mut got,
                    LIST_MODULES_ALL,
                )
                .is_ok()
                {
                    let n = ((got as usize) / size_of_hmodule).min(mods.len());
                    let mut buf = [0u16; 1024];
                    for m in &mods[..n] {
                        let l = GetModuleFileNameExW(Some(h), Some(*m), &mut buf) as usize;
                        if l == 0 {
                            continue;
                        }
                        let path = String::from_utf16_lossy(&buf[..l]).to_lowercase();
                        if path == want {
                            locker = true;
                        }
                        if third.len() < SAMPLE_CAP && is_third_party_module(&path) {
                            let name = path.rsplit(['\\', '/']).next().unwrap_or(&path);
                            third.push(name.to_string());
                        }
                    }
                }
            }
            let _ = CloseHandle(h);
            if locker {
                out.push((pid, exe, third));
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// 删除失败行的占用说明：查得到模块级占用就点名进程与第三方模块样例，查不到回退原句。
fn occupancy_note(target: &Path) -> String {
    let Some((pid, exe, third)) = module_lockers(target).into_iter().next() else {
        return "删除失败（可能被占用）".to_string();
    };
    if third.is_empty() {
        return format!("删除失败：文件被 {exe}（PID {pid}）加载占用，可尝试退出该程序后重试");
    }
    format!(
        "删除失败：文件被 {exe}（PID {pid}）加载占用，该进程还加载了 {} 个非系统目录的第三方模块（{} 等，常见于安全软件）——可尝试退出该程序或暂时关闭其防护后重试",
        third.len(),
        third.join("、")
    )
}

/// 句柄退出后继续监视：返回 (stillListed, 是否超时放弃)。
fn watch_uninstaller(
    hive: windows::Win32::System::Registry::HKEY,
    key_path: &str,
    launched_exe: &str,
) -> (bool, bool) {
    let launched = launched_exe
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_lowercase();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15 * 60);
    let mut stable = 0u32;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        // 键消失 = 卸载完成（最早、最可靠的完成信号）
        if !crate::engine::native::reg_key_exists(hive, key_path) {
            return (false, false);
        }
        let any = process_names_snapshot()
            .iter()
            .any(|n| is_uninstaller_process(n, &launched));
        if any {
            stable = 0;
        } else {
            stable += 1;
            if stable >= 3 {
                // 卸载器家族进程已连续 3 秒绝迹：卸载结束（含用户取消）
                break;
            }
        }
        if std::time::Instant::now() > deadline {
            return (crate::engine::native::reg_key_exists(hive, key_path), true);
        }
    }
    (crate::engine::native::reg_key_exists(hive, key_path), false)
}

/// 卸载域·执行原厂卸载（方案 M2 + 用户拍板 2026-09-28）。
/// app_id 只当**寻址键**用：Win32 命令串一律现读注册表，不信任渲染层回传；
/// APPX 前缀走 Remove-AppxPackage（包全名过字符集白名单后内插，防注入）。
#[tauri::command]
pub async fn uninstall_run<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    app_id: String,
    // 已废弃（2026-09-28 二轮拍板）：静默勾选框删除，静默优先成为默认行为；参数保留兼容旧调用
    silent: Option<bool>,
) -> Value {
    let _ = silent;
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    // ---- Windows 应用（Appx）：Remove-AppxPackage，无静默/原厂 UI 之分 ----
    if let Some(fullname) = app_id.strip_prefix("APPX|") {
        if !valid_appx_fullname(fullname) {
            return json!({ "success": false, "message": "包全名格式非法" });
        }
        let fullname = fullname.to_string();
        let res = tauri::async_runtime::spawn_blocking(move || {
            log::flush_sync();
            remove_appx(&fullname)
        })
        .await;
        return match res {
            Ok(Ok(())) => json!({ "success": true, "data": {
                "exitCode": 0, "stillListed": false, "installerKind": "appx",
                "message": "已从当前用户移除该 Windows 应用",
            }}),
            Ok(Err(e)) => json!({ "success": false, "message": e }),
            Err(e) => json!({ "success": false, "message": format!("卸载执行异常: {e}") }),
        };
    }
    let Some((hive_str, key_path)) = app_id.split_once('|') else {
        return json!({ "success": false, "message": "app_id 格式错误" });
    };
    if !valid_uninstall_key_path(key_path) {
        return json!({ "success": false, "message": "app_id 不是合法的卸载键路径" });
    }
    let hive_str = hive_str.to_string();
    let key_path = key_path.to_string();
    let res = tauri::async_runtime::spawn_blocking(move || unsafe {
        use windows::Win32::System::Registry::{RegOpenKeyExW, RegCloseKey, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
        let (hive, hive_name) = if hive_str.eq_ignore_ascii_case("HKCU") {
            (HKEY_CURRENT_USER, "HKCU")
        } else if hive_str.eq_ignore_ascii_case("HKLM") {
            (HKEY_LOCAL_MACHINE, "HKLM")
        } else {
            return Err("app_id hive 只支持 HKCU/HKLM".to_string());
        };
        let sk = to_wide(&key_path);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return Err("卸载注册表键不存在（程序可能已被卸载）".to_string());
        }
        let display_name = reg_sz(hk, "DisplayName").unwrap_or_default();
        let uninstall_string = reg_sz(hk, "UninstallString").unwrap_or_default();
        let quiet_string = reg_sz(hk, "QuietUninstallString").unwrap_or_default();
        let install_location = reg_sz(hk, "InstallLocation").unwrap_or_default();
        let publisher = reg_sz(hk, "Publisher").unwrap_or_default();
        let key_name = key_path.rsplit('\\').next().unwrap_or("").to_string();
        let (mut kind, product_code) = detect_installer(&key_name, &uninstall_string);
        let _ = RegCloseKey(hk);
        // B4 第二证据：只在字符串判定不出类型时探测，且只认独有文件名（不猜通用名）
        if kind == "unknown" {
            if let Some(ev) = second_evidence_kind(&install_location, &|p| p.is_file()) {
                log::write_log(
                    "info",
                    &format!("uninstall_run {display_name}: 字符串判定 unknown，InstallLocation 第二证据判为 {ev}"),
                );
                kind = ev;
            }
        }

        if uninstall_string.trim().is_empty() {
            return Err("该程序没有 UninstallString，无法调用原厂卸载器".to_string());
        }
        // 静默优先（2026-09-28 二轮拍板，勾选框已删）：先厂商 QuietUninstallString
        // （必须过 B1 构造闸），再本地白名单派生；退出码按 B2 分档决定是否回退原厂界面。
        let original = split_uninstall_cmd(&uninstall_string)
            .ok_or_else(|| "UninstallString 无法解析出可执行文件".to_string())?;
        let candidate =
            pick_silent_candidate(kind, product_code.as_deref(), &original, Some(&quiet_string), &|p| p.is_file());
        let (mut exe, args, used_silent, silent_source) = match &candidate {
            Some(c) => (c.exe.clone(), c.args.clone(), true, c.source),
            None => (original.0.clone(), original.1.clone(), false, "none"),
        };
        if let Some(reason) = candidate.as_ref().and_then(|c| c.vendor_reject.as_ref()) {
            log::write_log(
                "info",
                &format!("uninstall_run {display_name}: 厂商 QuietUninstallString 被构造闸拒绝（{reason}），改用白名单派生"),
            );
        }
        let run_original_ui = || -> Result<u32, String> {
            log::flush_sync();
            shell_run_wait(&original.0, &original.1).map_err(|e| {
                log::write_log("error", &format!("uninstall_run {display_name}: 回退原厂卸载界面启动失败: {e}"));
                e
            })
        };
        // C2 所有权事件：在启动卸载器**之前**记 pending —— 此刻还不知道卸载会不会成功，
        // 所以只登记「用户打算卸它」这一事实。应用数据遗留判定要等复扫确认程序已消失、且原安装目录
        // ENOENT，才升级为 historical（Q9 拍板：取消/失败不回滚成"已卸载"，交给稳定期回收）。
        let mut owned_paths: Vec<String> = Vec::new();
        if !install_location.trim().is_empty() {
            owned_paths.push(install_location.trim().trim_end_matches('\\').to_string());
        }
        if let Some(parent) = Path::new(&original.0).parent() {
            let p = parent.to_string_lossy().to_string();
            if !p.is_empty() && !owned_paths.iter().any(|x| x.eq_ignore_ascii_case(&p)) {
                owned_paths.push(p);
            }
        }
        {
            let mut own_doc = ownership::load();
            let app_id = format!("{hive_name}|{key_path}");
            let recorded = ownership::record_pending(
                &mut own_doc,
                &app_id,
                &display_name,
                &publisher,
                install_location.trim(),
                &owned_paths,
                crate::engine::now_ms(),
                norm_name,
            );
            // HiBit §9.1 那条基线：卸载**之前**取一次厂商顶层键集合。之后扫描时
            // 「卸载前没有、现在有了」的键才可能是这程序自己写的配置键（卸载器不认的那批）。
            // 一个根都没枚举到就**不写基线**：空集合不是"这台机器没有厂商键"，写成基线会让
            // 下一轮差分把全部现存键算成新键。没有基线时那一类候选整段不出，目录候选不受影响。
            let footprinted = if recorded {
                let vendor = collect_vendor_keys();
                if vendor.is_empty() {
                    log::write_log(
                        "warn",
                        "卸载前厂商键基线未记录：三个 Software 根都枚举不到（不写空基线，否则下轮差分全是假候选）",
                    );
                    false
                } else {
                    ownership::set_footprint(&mut own_doc, &app_id, &vendor, crate::engine::now_ms())
                }
            } else {
                false
            };
            if recorded || footprinted {
                if let Err(e) = ownership::save(&own_doc) {
                    log::write_log("warn", &format!("所有权事件落盘失败（不影响卸载）: {e}"));
                }
            }
        }
        log::flush_sync(); // 危险操作前刷盘
        let mut fell_back = false;
        let mut exit_code = match shell_run_wait(&exe, &args) {
            Ok(code) => code,
            Err(e) if used_silent => {
                log::write_log(
                    "info",
                    &format!("uninstall_run {display_name}: 静默卸载启动失败（{e}），自动回退原厂卸载界面"),
                );
                fell_back = true;
                exe = original.0.clone();
                run_original_ui()?
            }
            Err(e) => {
                // 非白名单且厂商串不可用时本来就走原厂界面，启动失败即如实报错（原行为）
                log::write_log("error", &format!("uninstall_run {display_name}: {e}"));
                return Err(e);
            }
        };
        if used_silent && !fell_back {
            let (meaning, fall_back) = classify_exit(exit_code);
            if fall_back {
                log::write_log(
                    "info",
                    &format!("uninstall_run {display_name}: 静默卸载退出码 {exit_code}（{meaning}），自动回退原厂卸载界面"),
                );
                fell_back = true;
                exe = original.0.clone();
                exit_code = run_original_ui()?;
            } else {
                log::write_log(
                    "info",
                    &format!("uninstall_run {display_name}: 静默卸载退出码 {exit_code}（{meaning}），按分档不回退原厂界面"),
                );
            }
        }
        let (exit_meaning, _) = classify_exit(exit_code);

        // 进程监视（2026-09-28 用户拍板）：句柄退出 ≠ 卸载结束——继续轮询卸载键与
        // 卸载器家族进程，直到键消失或进程绝迹（上限 15 分钟）
        let (still_listed, timed_out) = watch_uninstaller(hive, &key_path, &exe);
        if still_listed {
            log::write_log(
                "warn",
                &format!(
                    "uninstall_run {display_name}: 卸载器退出（码 {exit_code}，监视{}）但卸载键仍在，原厂卸载可能未完成",
                    if timed_out { "超时" } else { "结束" }
                ),
            );
        } else {
            log::write_log("info", &format!("uninstall_run {display_name}: 卸载完成（码 {exit_code}）"));
        }
        Ok(json!({
            "exitCode": exit_code,
            "exitMeaning": exit_meaning,
            "silentSource": silent_source,
            "stillListed": still_listed,
            "installerKind": kind,
            "usedSilent": used_silent,
            "fellBack": fell_back,
            "message": if still_listed {
                if fell_back {
                    "静默卸载未完成，已回退原厂卸载界面；卸载器已退出但该程序仍在卸载列表中（可能未完成或已取消）".to_string()
                } else {
                    "卸载进程已结束，但该程序仍出现在卸载列表中（可能未完成或已取消）".to_string()
                }
            } else if fell_back {
                "静默卸载未完成，已自动回退原厂卸载界面并执行完毕".to_string()
            } else {
                format!("「{display_name}」的卸载器已执行完毕")
            },
            "_hive": hive_name,
        }))
    })
    .await;
    match res {
        Ok(Ok(data)) => json!({ "success": true, "data": data }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("卸载执行异常: {e}") }),
    }
}

// ==================== uninstall:residue-scan ====================

/// 应用名 → 归一化串（小写 + 折叠空白）。用于启发式目录匹配。
fn norm_name(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

// ==================== C3 名称阈值与产出上限（2026-09-28 收口） ====================
//
// 这些数字此前散在八九处（5 / 4 / 2 / 20 / 16），同一个"名字够不够长、能出多少条"的问题
// 在不同代码路径上答案不同，改一处忘一处就会让候选集自相矛盾。收在这张表里，每条写清判据。
//
// **刻意不做成"一个全局阈值"**：门槛高低应该跟"猜错的代价"绑定，所以按风险分三档。
// - `NAME_MIN_SIMILAR`：目录名互含。5 是实测经验值——短于此（如「QQ」「微信」）会命中
//   大量无关目录，而目录是整棵删（回收站可还原但仍是数据），误报不可接受。
// - `NAME_MIN_SHORTCUT`：快捷方式 stem 互含。比目录宽一档，因为删一个 .lnk 只影响开始菜单
//   入口，程序本体不动。
// - `NAME_MIN_RULE_WORD`：签名规则库条件组里的短词门槛。这是**人工维护的精确词表**，
//   与自由文本猜测不同风险面；配套的「三条件组至少两组」是 U-1 拍板口径（见 `RESIDUE_MATCH_GROUPS`），
//   那是条件组数不是字符数，不许并进这两档。
const NAME_MIN_SIMILAR: usize = 5;
const NAME_MIN_SHORTCUT: usize = 4;
const NAME_MIN_RULE_WORD: usize = 2;
/// 所有权链的**精确同名**门槛。2 而不是 5：那条链是 HashMap 精确查表（目录名归一后
/// 必须等于 owner 名），不是互含猜测，猜错代价与 `NAME_MIN_SIMILAR` 完全不同量级。
/// 沿用 5 的实际后果是中文产品名全军覆没 —— 「网易大神」4 字、「豆包」2 字、
/// 「永劫无间」4 字，全部被当成"名字太短"丢掉，档案里有 historical 记录却报
/// "没有已确认卸载完成的程序"（2026-09-28 真机实测暴露）。
const NAME_MIN_EXACT: usize = 2;
/// 名称类命中上限（目录与快捷方式共用）：启发式只是提示，膨胀会把用户判断力淹掉
const NAME_HIT_CAP: usize = 20;
/// 系统侧痕反查上限（MuiCache / BAM / 防火墙 / Tracing / JumpList 各自一条）
const SIDE_TRACE_CAP: usize = 20;
/// 参与反查的程序 exe 数量上限（collect_program_objects 的产出面）
const PROGRAM_EXE_CAP: usize = 16;

/// 同名多候选降级（C3 的后半）：同一归一化名字在**不同父目录**下命中多个结果时，
/// 无法判定哪一条才是这个程序自己的东西，整组降 low 并默认不勾。
fn name_is_ambiguous(hits: &[String]) -> bool {
    let mut parents: HashSet<String> = HashSet::new();
    for h in hits {
        if let Some(p) = Path::new(h).parent() {
            parents.insert(p.to_string_lossy().to_ascii_lowercase());
        }
    }
    parents.len() > 1
}

/// 启发式残留：应用名与 AppData/LocalAppData/ProgramData 一级目录名互含（双侧 ≥5 字符）。
/// 方案 §4.4：名称启发式置信度 low，默认不勾选，只作候选提示。
unsafe fn heuristic_dir_hits(app_name: &str) -> Vec<String> {
    let norm = norm_name(app_name);
    if norm.chars().count() < NAME_MIN_SIMILAR {
        return Vec::new(); // 名字太短误报率爆炸（如「QQ」会命中一堆目录）
    }
    let mut hits = Vec::new();
    for root in ["APPDATA", "LOCALAPPDATA", "PROGRAMDATA"] {
        let Ok(base) = std::env::var(root) else { continue };
        let Ok(rd) = std::fs::read_dir(&base) else { continue };
        for ent in rd.flatten() {
            if !ent.path().is_dir() {
                continue;
            }
            let dnorm = norm_name(&ent.file_name().to_string_lossy());
            if dnorm.chars().count() < NAME_MIN_SIMILAR {
                continue;
            }
            if dnorm == norm || (dnorm.contains(&norm) || norm.contains(&dnorm)) {
                hits.push(ent.path().to_string_lossy().to_string());
            }
            if hits.len() >= NAME_HIT_CAP {
                return hits; // 上限：启发式只是提示，不该膨胀
            }
        }
    }
    hits
}

/// 开始菜单快捷方式命中（用户拍板 2026-09-28：残留面板要有可清理项）：
/// 递归扫全体/当前用户两级开始菜单，.lnk 文件名含程序名即命中。上限 20 条。
fn start_menu_shortcut_hits(app_name: &str) -> Vec<String> {
    let norm = norm_name(app_name);
    if norm.chars().count() < 3 {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let roots: Vec<PathBuf> = [
        std::env::var_os("PROGRAMDATA").map(|p| PathBuf::from(p).join(r"Microsoft\Windows\Start Menu")),
        std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join(r"Microsoft\Windows\Start Menu")),
    ]
    .into_iter()
    .flatten()
    .collect();
    for root in roots {
        if hits.len() >= NAME_HIT_CAP {
            break;
        }
        // 迭代下钻，深度 ≤ 5（开始菜单层级浅，防符号链接打穿用 is_symlink 挡）
        let mut stack = vec![(root, 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for ent in rd.flatten() {
                let p = ent.path();
                if p.is_symlink() {
                    continue;
                }
                if p.is_dir() {
                    if depth < 5 {
                        stack.push((p, depth + 1));
                    }
                    continue;
                }
                if p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("lnk")) != Some(true) {
                    continue;
                }
                let stem = norm_name(&p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default());
                if stem.contains(&norm) || (norm.contains(&stem) && stem.chars().count() >= NAME_MIN_SHORTCUT) {
                    hits.push(p.to_string_lossy().to_string());
                    if hits.len() >= NAME_HIT_CAP {
                        return hits;
                    }
                }
            }
        }
    }
    hits
}

// ==================== 固定系统侧痕反查（U-2） ====================
// 原则：按「系统对象里记录的程序路径」反查，不按程序名猜。已知线索 = 卸载键的
// InstallLocation / UninstallString / DisplayIcon 推出的 exe 路径与安装目录。
// 全部来源置信度 medium、默认不勾（拍板口径见 uninstall_residue_scan 的文档注释）。

use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

/// 从卸载键线索收集「程序对象」：(exe 全路径集合, 安装目录)。
/// exe 来源 = UninstallString / DisplayIcon 解析 + 安装目录一级 *.exe 直查（上限 16）。
fn collect_program_objects(loc: &str, uninstall_string: &str, display_icon_src: &str) -> (Vec<String>, Option<String>) {
    let mut exes: Vec<String> = Vec::new();
    for src in [uninstall_string, display_icon_src] {
        if let Some((exe, _)) = split_uninstall_cmd(src) {
            let exe = exe.trim().to_string();
            // msiexec.exe 是系统组件：MSI 卸载走它不代表程序装在 System32，反查它只会误伤
            if !exe.is_empty()
                && exe.to_ascii_lowercase().ends_with(".exe")
                && !exe.to_ascii_lowercase().ends_with("\\msiexec.exe")
            {
                exes.push(exe);
            }
        }
    }
    let mut dir: Option<String> = None;
    if !loc.is_empty() && Path::new(loc).is_dir() {
        dir = Some(loc.to_string());
        if let Ok(rd) = std::fs::read_dir(loc) {
            for ent in rd.flatten().take(64) {
                let p = ent.path();
                if p.is_file()
                    && p.extension().map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false)
                {
                    exes.push(p.to_string_lossy().to_string());
                    if exes.len() >= PROGRAM_EXE_CAP {
                        break;
                    }
                }
            }
        }
    }
    (exes, dir)
}

/// 路径前缀命中：值名以已知 exe 开头（MuiCache 值名形如 `<exe>.FriendlyAppName`、
/// BAM 值名即完整 exe 路径），或落在安装目录整棵前缀下
fn trace_prefix_hit(name_lc: &str, exes_lc: &[String], dir_lc: &str) -> bool {
    exes_lc.iter().any(|e| name_lc.starts_with(e.as_str()))
        || (!dir_lc.is_empty() && name_lc.starts_with(&format!("{dir_lc}\\")))
}

/// 枚举注册表键的全部值（只收 REG_SZ / REG_EXPAND_SZ，返回 (值名, 数据)）。
/// 上限 cap 防爆（MuiCache/BAM 可上千条；枚举到 cap 即截断返回）。
unsafe fn reg_enum_sz_values(
    hive: windows::Win32::System::Registry::HKEY,
    subkey: &str,
    cap: usize,
) -> Vec<(String, String)> {
    use windows::Win32::System::Registry::{RegCloseKey, RegEnumValueW, RegOpenKeyExW, KEY_READ};
    if cap == 0 {
        return Vec::new();
    }
    let sk = to_wide(subkey);
    let mut hk = windows::Win32::System::Registry::HKEY::default();
    if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
        return Vec::new();
    }
    let mut out: Vec<(String, String)> = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name_buf = [0u16; 1024];
        let mut name_len = name_buf.len() as u32;
        let mut ty = 0u32; // windows 0.61 的 lptype 是 *mut u32：1=REG_SZ 2=REG_EXPAND_SZ
        let mut data_len = 0u32;
        // 先探类型与尺寸（lpData=None），只收字符串类；二进制/DWORD 值直接跳过
        let r = RegEnumValueW(
            hk, index,
            Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            None,
            Some(&mut ty),
            None,
            Some(&mut data_len),
        );
        if r.is_err() {
            break; // ERROR_NO_MORE_ITEMS 或访问异常都按枚举结束处理
        }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        index += 1;
        if name.is_empty() {
            continue;
        }
        if ty != 1 && ty != 2 {
            continue;
        }
        // 再取数据（data_len 为字节数，含终止 NUL）
        let mut buf = vec![0u8; data_len.max(2) as usize];
        let mut got = buf.len() as u32;
        let ok = RegEnumValueW(
            hk, index - 1,
            Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut got),
        )
        .is_ok();
        if !ok {
            continue;
        }
        let words: Vec<u16> = buf[..got as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&w| w != 0)
            .collect();
        out.push((name, String::from_utf16_lossy(&words)));
        if out.len() >= cap {
            break;
        }
    }
    let _ = RegCloseKey(hk);
    out
}

/// 枚举注册表键的全部子键名（上限 cap）
unsafe fn reg_enum_subkeys(
    hive: windows::Win32::System::Registry::HKEY,
    subkey: &str,
    cap: usize,
) -> Vec<String> {
    use windows::Win32::System::Registry::{RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, KEY_READ};
    if cap == 0 {
        return Vec::new();
    }
    let sk = to_wide(subkey);
    let mut hk = windows::Win32::System::Registry::HKEY::default();
    if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name_buf = [0u16; 260];
        let mut name_len = name_buf.len() as u32;
        let r = RegEnumKeyExW(
            hk, index,
            Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            None, None, None, None,
        );
        if r.is_err() {
            break;
        }
        index += 1;
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        if !name.is_empty() {
            out.push(name);
        }
        if out.len() >= cap {
            break;
        }
    }
    let _ = RegCloseKey(hk);
    out
}

/// MuiCache 残留值反查。目标格式 `HKCU\<键路径>::<值名>`（执行侧按 rsplit_once("::") 拆）。
unsafe fn muicache_hits(exes_lc: &[String], dir_lc: &str, cap: usize) -> Vec<String> {
    const SUBKEY: &str = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
    let mut out = Vec::new();
    for (name, _) in reg_enum_sz_values(HKEY_CURRENT_USER, SUBKEY, 4096) {
        if trace_prefix_hit(&name.to_ascii_lowercase(), exes_lc, dir_lc) {
            out.push(format!("HKCU\\{SUBKEY}::{name}"));
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

/// 防火墙规则反查：规则值数据形如 `...|App=C:\path\app.exe|...`，数据里含已知 exe/安装目录即命中。
unsafe fn firewall_hits(exes_lc: &[String], dir_lc: &str, cap: usize) -> Vec<String> {
    const SUBKEY: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    let mut out = Vec::new();
    for (name, data) in reg_enum_sz_values(HKEY_LOCAL_MACHINE, SUBKEY, 4096) {
        let dl = data.to_ascii_lowercase();
        let hit = exes_lc.iter().any(|e| dl.contains(e.as_str()))
            || (!dir_lc.is_empty() && dl.contains(&format!("{dir_lc}\\")));
        if hit {
            out.push(format!("HKLM\\{SUBKEY}::{name}"));
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

/// BAM（后台活动记录）反查：`bam\State\UserSettings\<SID>` 下值名 = 完整 exe 路径
/// （数据是执行序号 DWORD，不参与匹配）。
unsafe fn bam_hits(exes_lc: &[String], dir_lc: &str, cap: usize) -> Vec<String> {
    const ROOT: &str = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";
    let mut out = Vec::new();
    'outer: for sid in reg_enum_subkeys(HKEY_LOCAL_MACHINE, ROOT, 64) {
        for (name, _) in reg_enum_sz_values(HKEY_LOCAL_MACHINE, &format!("{ROOT}\\{sid}"), 256) {
            if trace_prefix_hit(&name.to_ascii_lowercase(), exes_lc, dir_lc) {
                out.push(format!("HKLM\\{ROOT}\\{sid}::{name}"));
                if out.len() >= cap {
                    break 'outer;
                }
            }
        }
    }
    out
}

/// Tracing 诊断跟踪项反查：`HKLM\SOFTWARE\Microsoft\Tracing\<exe 文件名>` 子键
/// （常见形如 `App.EXE`），按已知 exe 的文件名 stem 反查。
unsafe fn tracing_hits(exes_lc: &[String], cap: usize) -> Vec<String> {
    const ROOT: &str = r"SOFTWARE\Microsoft\Tracing";
    let mut stems: Vec<String> = exes_lc
        .iter()
        .filter_map(|e| {
            Path::new(e)
                .file_stem()
                .map(|s| s.to_string_lossy().to_ascii_lowercase())
        })
        .collect();
    stems.sort();
    stems.dedup();
    if stems.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for name in reg_enum_subkeys(HKEY_LOCAL_MACHINE, ROOT, 512) {
        let nl = name.to_ascii_lowercase();
        let stem = Path::new(&nl)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| nl.clone());
        if stems.contains(&nl) || stems.contains(&stem) {
            out.push(format!("HKLM\\{ROOT}\\{name}"));
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

/// JumpList 自动目标反查（对象级）：`.destinations-ms` 文件是 OLE 复合文档，
/// AppID 为不可逆哈希，无法按应用名映射——改为字节级包含判定：文件原始字节里
/// 出现安装目录 / exe 路径的 UTF-16LE 编码即命中（同前缀目录树的程序会共享命中，
/// 因此保持 medium + 默认不勾）。
fn jumplist_hits(exes_lc: &[String], dir_lc: &str, cap: usize) -> Vec<String> {
    let Some(base) = std::env::var_os("APPDATA") else {
        return Vec::new();
    };
    let root = PathBuf::from(base).join(r"Microsoft\Windows\Recent\AutomaticDestinations");
    let Ok(rd) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut needles: Vec<Vec<u8>> = Vec::new();
    let push_needle = |s: &str, needles: &mut Vec<Vec<u8>>| {
        if s.is_empty() {
            return;
        }
        needles.push(s.encode_utf16().flat_map(u16::to_le_bytes).collect());
    };
    push_needle(dir_lc, &mut needles);
    for e in exes_lc {
        push_needle(e, &mut needles);
    }
    if needles.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        let is_dest = p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase().ends_with("destinations-ms"))
            .unwrap_or(false);
        if !is_dest {
            continue;
        }
        // 正常目标文件 <1MB；超 4MB 视为异常直接跳过（防把巨型文件读进内存）
        let Ok(bytes) = std::fs::read(&p) else { continue };
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            continue;
        }
        if needles.iter().any(|n| {
            bytes
                .windows(n.len())
                .any(|w| w == n.as_slice())
        }) {
            out.push(p.to_string_lossy().to_string());
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

// ==================== 签名残留规则库（U-1） ====================
// 已知程序知识库：规则文件与 cleanup-rules.json 同款签名链（Ed25519 + 去掉 _sig 的
// 紧凑 JSON 规范化，rules_signature::verify_rules_text 验签）。数据目录规则优先于内置，
// 验签失败 / 版本低于防回滚下限一律 fail-closed 回退内置。
// 在线更新（A3，M3 批次）：cleanup 域的 HTTP 传输层已落地（`engine::winhttp` + 验签 +
// 原子落盘 + 水位线），残留库尚未接入。接入的**前置条件**是本文件 A1/A2 两道闸已生效
// （方案 §6.2：先硬否决与语义校验，再上远程分发），另有数据目录归属、是否建前端兜底
// 副本、版本语义等 7 项待拍板，未拍板前不得新增 `residue:update` 通道。

/// 内置残留规则库（编译期嵌入，与 data/uninstall-residue-rules.json 逐字节一致）
const BUILTIN_RESIDUE_RULES_JSON: &str = include_str!("../../data/uninstall-residue-rules.json");

/// 残留规则根目录（**读**）：新根 `app_data_dir()\uninstall`（便携模式跟着 exe 走），
/// 老根 `%APPDATA%\Trim\uninstall` 只作只读兜底 —— 2026-09-28 决策清单 D1=A，
/// 与清理库同一口径（两库必须一起收口，否则便携模式只对一半成立）。
pub fn residue_rules_dir() -> PathBuf {
    crate::engine::paths::data_subdir_for_read("uninstall")
}

/// **写入**专用根：恒新根，避免两个根各自持有一份规则与水位线。
fn residue_rules_write_dir() -> PathBuf {
    crate::engine::paths::data_subdir_for_write("uninstall")
}

fn residue_rules_file() -> PathBuf {
    crate::engine::paths::data_file_for_read("uninstall/residue-rules.json")
}

fn residue_watermark_file() -> PathBuf {
    crate::engine::paths::data_file_for_read("uninstall/residue-rules-watermark.json")
}

fn residue_watermark_write_file() -> PathBuf {
    residue_rules_write_dir().join("residue-rules-watermark.json")
}

/// 防回滚水位线读取（损坏/不可读按 0；口径同 cleanup::rules_watermark）
pub fn residue_watermark() -> f64 {
    let Ok(text) = std::fs::read_to_string(residue_watermark_file()) else {
        return 0.0;
    };
    let Ok(v) = serde_json::from_str::<Value>(&text) else {
        return 0.0;
    };
    v.get("rulesVersion").and_then(|x| x.as_f64()).unwrap_or(0.0)
}

/// 防回滚水位线写入（只升不降；在线更新链路接入时调用）
pub fn set_residue_watermark(version: f64) -> bool {
    if !version.is_finite() || version <= 0.0 || version <= residue_watermark() {
        return false;
    }
    let file = residue_watermark_write_file();
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let payload = json!({ "rulesVersion": version, "at": crate::engine::now_ms() });
    crate::security::atomic_write_json(&file, &payload).is_ok()
}

// ==================== A2 残留规则库语义校验（方案 §6.1） ====================
//
// 为什么必须存在：`load_residue_rules` 此前只做「验签 → JSON → rules 是数组 → 版本水位线」，
// 也就是**只证明这份文件出自发布机私钥**，不证明内容安全。而规则里的 `reg_key` 目标会被
// `RegDeleteTreeW` 递归删、`folder` 目标会进回收站，所以一条 `HKLM\SOFTWARE` 就够出事故。
// 人审与私钥纪律不是代码约束，热更新一上就是放大面 —— 故整包语义校验先于上链。
//
// 口径约束（勿单侧改）：
// - 失败一律**整包拒绝**并回退上一份可用规则（Q2 拍板）。不做「坏条目剔除、其余生效」，
//   那会让审核记录与线上行为不一致。
// - 本函数是**唯一运行期真源**；`tools/check-residue-rule-contract.mjs` 用同一组夹具
//   (`tools/fixtures/residue-contract.json`) 独立实现同一套断言，不跨语言调用 Rust。
// - 清理域与残留域字段规则不同，只共享「外层流程」（尺寸/验签/版本），不共享白名单。

/// 签名残留规则库允许的 kind（Q8 拍板：`reg_value` / `shortcut` 不放行。一旦放行，
/// 校验器、执行侧保护判定、夹具与备份策略必须同时改，不得出现「校验器放行、执行器不支持」）
const RESIDUE_RULE_KINDS: &[&str] = &["folder", "file", "reg_key"];
/// 本库显式允许的 `%TOKEN%`。`expand_env_path` 不做白名单（任意环境变量都展开），
/// 所以这里不收口等于放开「规则引用任何机器上的环境变量」。与 Node 门禁同名清单必须同集。
const RESIDUE_RULE_TOKENS: &[&str] = &[
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "COMMONPROGRAMFILES",
    "USERPROFILE",
    "WINDIR",
    "SYSTEMROOT",
];
const RESIDUE_TOP_FIELDS: &[&str] = &["rulesVersion", "prov", "rules", "_sig"];
const RESIDUE_PROV_FIELDS: &[&str] = &["sourceClass", "reviewedAt"];
const RESIDUE_RULE_FIELDS: &[&str] =
    &["id", "ver", "displayName", "publisher", "uninstallKey", "residue"];
const RESIDUE_ENTRY_FIELDS: &[&str] = &["kind", "target", "note"];
/// 匹配组「至少两组非空」是 U-1 拍板口径，Node 门禁同断言
const RESIDUE_MATCH_GROUPS: &[&str] = &["displayName", "publisher", "uninstallKey"];
const RESIDUE_MAX_RULES: usize = 400;
const RESIDUE_MAX_RESIDUE: usize = 64;
const RESIDUE_MAX_GROUP_ITEMS: usize = 32;
const RESIDUE_MAX_TARGET_LEN: usize = 260; // MAX_PATH：超过说明规则写坏了或被撑爆
const RESIDUE_MAX_TEXT_LEN: usize = 200; // id / note / 匹配词
const RESIDUE_MAX_SEGMENTS: usize = 32; // 路径段数与注册表键深度

/// 未知字段白名单检查（A5）： serde 手取字段时未知字段会被静默忽略，
/// 那等于「规则库里有一执行侧根本不认的字段」，审核记录与线上行为不一致。
fn unknown_fields<'a>(obj: &serde_json::Map<String, Value>, allow: &[&'a str]) -> Option<String> {
    obj.keys()
        .find(|k| !allow.contains(&k.as_str()))
        .map(|k| format!("未知字段 {k}"))
}

/// 字符串数组字段：字段可缺失（视为空组，「至少两组非空」另有断言），但类型不符必须 Err
/// —— 不许把 `null` / 对象 / 数字静默当空数组，那会静默改变命中口径。
fn str_array_field<'a>(obj: &'a Value, field: &str) -> Result<Vec<&'a str>, String> {
    let Some(v) = obj.get(field) else {
        return Ok(Vec::new());
    };
    let Some(arr) = v.as_array() else {
        return Err(format!("{field} 不是数组"));
    };
    if arr.len() > RESIDUE_MAX_GROUP_ITEMS {
        return Err(format!("{field} 条目数 {} 超上限 {RESIDUE_MAX_GROUP_ITEMS}", arr.len()));
    }
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let Some(s) = v.as_str() else {
            return Err(format!("{field} 含非字符串元素"));
        };
        if s.trim().is_empty() || s.chars().count() > RESIDUE_MAX_TEXT_LEN {
            return Err(format!("{field} 含空白或超长条目"));
        }
        out.push(s.trim());
    }
    Ok(out)
}

fn path_shape_problem(target: &str) -> Option<String> {
    if target.chars().count() > RESIDUE_MAX_TARGET_LEN {
        return Some("目标长度超过 260（MAX_PATH）".to_string());
    }
    if target.contains('*') || target.contains('?') {
        return Some("目标含通配符（残留规则只允许精确路径）".to_string());
    }
    if target.chars().any(|c| c == '\0' || c == '\n' || c == '\r' || c == '\t') {
        return Some("目标含控制字符".to_string());
    }
    None
}

/// 文件类目标形状：`%登记TOKEN%\非空子段` 或 盘符/UNC 绝对路径。
/// 禁 token 根（`%APPDATA%`）、尾随分隔符、`.`/`..` 段、路径中部二次变量替换。
fn file_target_problem(target: &str) -> Option<String> {
    if let Some(reason) = path_shape_problem(target) {
        return Some(reason);
    }
    let body = if let Some(rest) = target.strip_prefix('%') {
        let Some(end) = rest.find('%') else {
            return Some("变量名未闭合".to_string());
        };
        let token = &rest[..end];
        if token.is_empty() || !RESIDUE_RULE_TOKENS.iter().any(|t| t.eq_ignore_ascii_case(token)) {
            return Some(format!("变量 %{token}% 未登记（先确认展开器可解析再入白名单）"));
        }
        let tail = &rest[end + 1..];
        if tail.contains('%') {
            return Some("路径中不允许出现第二个变量替换".to_string());
        }
        if !tail.starts_with('\\') && !tail.starts_with('/') {
            return Some("变量后必须有分隔符与非空子段（禁止 token 根）".to_string());
        }
        tail[1..].to_string()
    } else {
        // 绝对路径两写法：`X:\...` 与 `\\server\share\...`
        let b = target.as_bytes();
        let drive_abs = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
        let unc_abs = target.starts_with("\\\\") && target.trim_start_matches('\\').contains('\\');
        if !drive_abs && !unc_abs {
            return Some("既不是登记变量的子路径，也不是绝对路径".to_string());
        }
        target.to_string()
    };
    let segs: Vec<&str> = body.split(|c| c == '\\' || c == '/').collect();
    if segs.iter().any(|s| s.is_empty() || *s == "." || *s == "..") {
        return Some("含空段、`.` 或 `..`（尾随分隔符同样命中）".to_string());
    }
    if segs.len() > RESIDUE_MAX_SEGMENTS {
        return Some(format!("路径段数 {} 超上限 {RESIDUE_MAX_SEGMENTS}", segs.len()));
    }
    None
}

/// 注册表目标：hive 合法 + 过 A1 保护判定 + 不放 reg_value 形态（`::值名`）
fn reg_target_problem(target: &str) -> Option<String> {
    if let Some(reason) = path_shape_problem(target) {
        return Some(reason);
    }
    if target.contains("::") || target.contains('%') {
        return Some("注册表目标不允许 `::值名` 或变量形态".to_string());
    }
    let Some((_, rest)) = parse_reg_target(target) else {
        return Some("hive 只支持 HKCU / HKLM".to_string());
    };
    let segs: Vec<&str> = rest.split('\\').collect();
    if segs.iter().any(|s| s.trim().is_empty()) {
        return Some("注册表路径含空段或尾随分隔符".to_string());
    }
    if segs.len() > RESIDUE_MAX_SEGMENTS {
        return Some(format!("注册表深度 {} 超上限 {RESIDUE_MAX_SEGMENTS}", segs.len()));
    }
    protect::reg_target_block_reason(target)
}

/// 整包语义校验。`Err(原因)` = 调用方必须拒绝这份规则库。
fn validate_residue_package(pkg: &Value) -> Result<(), String> {
    let Some(top) = pkg.as_object() else {
        return Err("规则包不是 JSON 对象".to_string());
    };
    if let Some(reason) = unknown_fields(top, RESIDUE_TOP_FIELDS) {
        return Err(format!("顶层 {reason}"));
    }
    let ver = pkg
        .get("rulesVersion")
        .and_then(Value::as_f64)
        .filter(|v| v.is_finite() && *v > 0.0)
        .ok_or_else(|| "rulesVersion 缺失、非数字或非正数".to_string())?;
    let prov = pkg
        .get("prov")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| "prov 缺失或为空（来源登记是审核链的一环）".to_string())?;
    for p in prov {
        let Some(obj) = p.as_object() else {
            return Err("prov 条目不是对象".to_string());
        };
        if let Some(reason) = unknown_fields(obj, RESIDUE_PROV_FIELDS) {
            return Err(format!("prov {reason}"));
        }
        for f in RESIDUE_PROV_FIELDS {
            let ok = obj
                .get(*f)
                .and_then(Value::as_str)
                .map(|s| !s.trim().is_empty() && s.chars().count() <= RESIDUE_MAX_TEXT_LEN)
                .unwrap_or(false);
            if !ok {
                return Err(format!("prov.{f} 缺失、非字符串或为空白"));
            }
        }
    }
    let rule_list = pkg
        .get("rules")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| "rules 缺失或为空数组".to_string())?;
    if rule_list.len() > RESIDUE_MAX_RULES {
        return Err(format!("规则条数 {} 超上限 {RESIDUE_MAX_RULES}", rule_list.len()));
    }
    let mut seen_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for rule in rule_list {
        let Some(obj) = rule.as_object() else {
            return Err("规则条目不是对象".to_string());
        };
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| {
                !s.is_empty()
                    && s.chars().count() <= RESIDUE_MAX_TEXT_LEN
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            })
            .ok_or_else(|| "规则 id 缺失、为空或含非 [A-Za-z0-9._-] 字符".to_string())?;
        if !seen_ids.insert(id) {
            return Err(format!("规则 id 重复: {id}"));
        }
        if let Some(reason) = unknown_fields(obj, RESIDUE_RULE_FIELDS) {
            return Err(format!("规则 {id}: {reason}"));
        }
        // 条目级版本戳必须与顶层一致（V2 P2-A1，与清理库同口径）：
        // 残留规则只有 6 条，但一旦开始按批补充，"这条是哪一版加的"必须能答
        match rule.get("ver").and_then(Value::as_f64) {
            None => {
                return Err(format!(
                    "规则 {id}: 缺条目级版本戳 ver（跑 tools/stamp-rule-ver.mjs --write 后重签）"
                ))
            }
            Some(vv) if (vv - ver).abs() > f64::EPSILON => {
                return Err(format!("规则 {id}: ver={vv} 与顶层 rulesVersion={ver} 不一致"))
            }
            Some(_) => {}
        }
        let mut hit_groups = 0;
        for g in RESIDUE_MATCH_GROUPS {
            let items = str_array_field(rule, g).map_err(|e| format!("规则 {id}: {e}"))?;
            if !items.is_empty() {
                hit_groups += 1;
            }
        }
        if hit_groups < 2 {
            return Err(format!(
                "规则 {id}: 三条件组只有 {hit_groups} 组非空，双条件命中是 U-1 拍板口径"
            ));
        }
        let Some(residue) = rule.get("residue").and_then(Value::as_array) else {
            return Err(format!("规则 {id}: residue 缺失或不是数组"));
        };
        if residue.is_empty() {
            return Err(format!("规则 {id}: residue 为空"));
        }
        if residue.len() > RESIDUE_MAX_RESIDUE {
            return Err(format!(
                "规则 {id}: residue 条数 {} 超上限 {RESIDUE_MAX_RESIDUE}",
                residue.len()
            ));
        }
        for entry in residue {
            let Some(obj) = entry.as_object() else {
                return Err(format!("规则 {id}: residue 条目不是对象"));
            };
            if let Some(reason) = unknown_fields(obj, RESIDUE_ENTRY_FIELDS) {
                return Err(format!("规则 {id}: residue {reason}"));
            }
            let kind = entry
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("规则 {id}: residue.kind 缺失或非字符串"))?;
            if !RESIDUE_RULE_KINDS.contains(&kind) {
                // 未知 kind 必须报错而不是静默跳过：静默跳过会让「执行侧不支持的字段」
                // 长期留在库里（方案 §6.1 三集合区分）
                return Err(format!("规则 {id}: 未知 kind {kind}（允许集 {RESIDUE_RULE_KINDS:?}）"));
            }
            let raw_target = entry
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("规则 {id}: residue.target 缺失或非字符串"))?;
            let target = raw_target.trim();
            if target.is_empty() || target != raw_target {
                return Err(format!("规则 {id}: residue.target 为空白或首尾含空白"));
            }
            let problem = match kind {
                "folder" | "file" => file_target_problem(target),
                "reg_key" => reg_target_problem(target),
                _ => Some("kind 不在允许集".to_string()),
            };
            if let Some(reason) = problem {
                return Err(format!("规则 {id}: {kind} 目标 {target} 不合规 — {reason}"));
            }
            let note_ok = entry
                .get("note")
                .and_then(Value::as_str)
                .map(|s| !s.trim().is_empty() && s.chars().count() <= RESIDUE_MAX_TEXT_LEN)
                .unwrap_or(false);
            if !note_ok {
                return Err(format!("规则 {id}: residue.note 缺失或为空白（面板 reason 要展示）"));
            }
        }
    }
    Ok(())
}

/// 残留规则库加载：数据目录（验签 + 防回滚 + A2 语义校验）→ 内置。fail-closed。
fn load_residue_rules() -> Option<Value> {
    let file = residue_rules_file();
    if file.is_file() {
        if let Ok(text) = std::fs::read_to_string(&file) {
            match rules_signature::verify_rules_text(&text) {
                Ok(()) => {
                    let parsed: Option<Value> = serde_json::from_str(&text).ok();
                    if let Some(v) = parsed {
                        let ver = v.get("rulesVersion").and_then(|x| x.as_f64()).unwrap_or(0.0);
                        let builtin_ver = serde_json::from_str::<Value>(BUILTIN_RESIDUE_RULES_JSON)
                            .ok()
                            .and_then(|b| b.get("rulesVersion").and_then(|x| x.as_f64()))
                            .unwrap_or(0.0);
                        let floor = builtin_ver.max(residue_watermark());
                        if floor > 0.0 && ver < floor {
                            log::write_log(
                                "warn",
                                &format!("数据目录残留规则版本({ver})低于防回滚下限({floor})，疑似旧签名文件重放，已回退内置规则库"),
                            );
                        } else if let Err(reason) = validate_residue_package(&v) {
                            // 验签通过但语义不合规：整包拒绝并隔离，避免每次扫描重复判同一份坏文件
                            log::write_log(
                                "error",
                                &format!("数据目录残留规则语义校验未通过，已整包拒绝并回退内置规则库: {reason}"),
                            );
                            crate::security::quarantine_file(&file, "residue-rules 语义校验未通过");
                        } else {
                            return Some(v);
                        }
                    } else {
                        log::write_log("warn", "数据目录残留规则 JSON 解析失败，已回退内置规则库");
                    }
                }
                Err(reason) => {
                    log::write_log(
                        "warn",
                        &format!("数据目录残留规则验签未通过，已回退内置规则库: {reason}"),
                    );
                }
            }
        }
    }
    let builtin: Value = match serde_json::from_str(BUILTIN_RESIDUE_RULES_JSON) {
        Ok(v) => v,
        Err(e) => {
            log::write_log("error", &format!("内置残留规则 JSON 解析失败: {e}"));
            return None;
        }
    };
    // 内置库同样过校验：数据文件由工具生成且发布前 `cargo test` 有对拍用例，
    // 这里失败说明仓库自身坏了，运行期只能停用规则（不给豁免通道）。
    if let Err(reason) = validate_residue_package(&builtin) {
        log::write_log("error", &format!("内置残留规则语义校验未通过，残留规则已停用: {reason}"));
        return None;
    }
    Some(builtin)
}

/// C4 贡献项：把「这一条为什么进候选」拆成离散因子，供渲染层逐条指认。
///
/// 借 BCU 的是**可解释性**，不是它的加权计分内核：浮点总分会让启发式看起来比实际更精确，
/// 而删除依据必须一条条数得出来。`code` 是稳定标识（单测与过滤按它寻址，不按文案寻址），
/// `text` 是给人看的那一句。纯展示字段——执行侧一律不消费它（方案 §6.3：展示/诊断字段
/// 不等于执行语义）。
fn contribs(items: &[(&str, String)]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|(code, text)| json!({ "code": code, "text": text }))
            .collect(),
    )
}

/// 条件组命中判定（U-1「双条件」拍板）：displayName / publisher / uninstallKey 三组里
/// **至少两组命中**才视为同一程序，单一维度弱相似不触发（防「QQ」类短名误伤全家桶）。
/// 返回 (候选集, 被 A1 硬否决的目标) —— 否决原因只在这里收集，由命令边界落日志：
/// 纯函数不留写盘副作用，`cargo test` 才不会把测试规则 id 写进用户的应用日志。
///
/// `learned` 决定证据等级：同一套命中逻辑跑在两份库上（签名库 / 本机学习库），
/// 学习库不签名、没人审，所以候选一律 `medium` + **不自动勾选**，且 reason 要交代来源。
/// 做成参数而不是「产出后再改字段」，是因为后写进来的字段一旦与产出侧分叉就没人会发现
/// （签名库那条 `defaultChecked: true` 就是靠这条链默认勾上的）。
fn residue_rules_hits(
    rules: &Value,
    display_name: &str,
    publisher: &str,
    key_path: &str,
    learned: bool,
) -> (Vec<Value>, Vec<String>) {
    let lib_label = if learned { "本机学习库" } else { "残留规则库" };
    let confidence = if learned { "medium" } else { "high" };
    let default_checked = !learned;
    let empty: Vec<Value> = Vec::new();
    let rule_list = rules.get("rules").and_then(|r| r.as_array()).unwrap_or(&empty);
    let name_norm = norm_name(display_name);
    let pub_lc = publisher.trim().to_lowercase();
    let key_lc = key_path.trim().to_lowercase();
    let mut out = Vec::new();
    let mut vetoed: Vec<String> = Vec::new();
    for rule in rule_list {
        let Some(id) = rule.get("id").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) else {
            continue;
        };
        // 双侧互含（沿用名称启发式的口径，但阈值放宽到 2：规则模式是人工维护的精确短词）
        let contains2 = |a: &str, b: &str| {
            let (a, b) = (a.trim(), b.trim());
            !a.is_empty() && !b.is_empty() && (a.contains(b) || b.contains(a))
        };
        let name_hit = rule
            .get("displayName")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter().filter_map(|p| p.as_str()).any(|p| {
                    let pn = norm_name(p);
                    pn.chars().count() >= NAME_MIN_RULE_WORD && contains2(&name_norm, &pn)
                })
            })
            .unwrap_or(false);
        let pub_hit = rule
            .get("publisher")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.as_str())
                    .any(|p| contains2(&pub_lc, &p.trim().to_lowercase()))
            })
            .unwrap_or(false);
        let key_hit = rule
            .get("uninstallKey")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter().filter_map(|p| p.as_str()).any(|p| {
                    let pl = p.trim().to_lowercase();
                    pl.chars().count() >= NAME_MIN_RULE_WORD && contains2(&key_lc, &pl)
                })
            })
            .unwrap_or(false);
        let hits = [name_hit, pub_hit, key_hit].iter().filter(|h| **h).count();
        if hits < 2 {
            continue;
        }
        // C4：把「哪几组条件命中」摊开成离散因子。双条件闸本身只说"够两组"，用户看不到
        // 是哪两组，就无法判断这条规则是不是靠「厂商名 + 一个短词」弱命中了自己别的产品。
        let mut why: Vec<(&str, String)> = Vec::new();
        if name_hit {
            why.push(("name", format!("程序名条件组命中：本机 DisplayName「{display_name}」")));
        }
        if pub_hit {
            why.push(("publisher", format!("发行商条件组命中：本机 Publisher「{publisher}」")));
        }
        if key_hit {
            why.push(("uninstallKey", format!("卸载键条件组命中：本机键路径「{key_path}」")));
        }
        // 条目级版本戳跟着候选走（V2 P2-A1）：反馈里能指认"这条候选是哪一版规则给的"，
        // 不必让用户去比对整库 rulesVersion。文案级改动，界面沿用既有 data-tip 位置。
        let rule_ver = rule.get("ver").and_then(Value::as_f64).unwrap_or(0.0);
        why.push((
            "ruleId",
            format!("来自{lib_label}规则 {id}（规则版本 {:.0}）", rule_ver),
        ));
        // 命中 → 展开 %VAR% 目标并做存在性判定：不存在的目标不出现在面板里
        for entry in rule.get("residue").and_then(|x| x.as_array()).unwrap_or(&empty) {
            let kind = entry.get("kind").and_then(|x| x.as_str()).unwrap_or("");
            let Some(target_raw) = entry.get("target").and_then(|x| x.as_str()) else {
                continue;
            };
            let note = entry.get("note").and_then(|x| x.as_str()).unwrap_or("");
            match kind {
                "folder" | "file" => {
                    let target = cleanup_scan::expand_env_path(target_raw);
                    // A4：变量没解析出来时，展开结果里还留着 `%X%`，这个路径必然不存在。
                    // 让它落到下面的「不存在」分支，等于把「本机没这个变量」说成
                    // 「程序没留这个目录」——清理链早就为这件事加了 first_unexpanded_token，
                    // 残留链此前一个调用点都没有，未展开目标就这么静默消失了。
                    if let Some(tok) = cleanup_scan::first_unexpanded_token(&target) {
                        vetoed.push(format!(
                            "规则 {id}: 目标 {target_raw} 含未解析变量 %{tok}%（本机取不到该变量），已跳过"
                        ));
                        continue;
                    }
                    let p = Path::new(&target);
                    let exists = if kind == "folder" { p.is_dir() } else { p.is_file() };
                    if !exists || protect::is_path_protected(&target) {
                        continue;
                    }
                    out.push(json!({
                        "kind": kind, "target": target,
                        "reason": format!("{lib_label}命中（{id}）：{note}"),
                        "confidence": confidence, "risk": "medium",
                        "defaultChecked": default_checked,
                        "ruleId": id, "ruleVer": rule_ver,
                        "contribs": contribs(&why),
                    }));
                }
                "reg_key" => {
                    let Some((hive, rest)) = parse_reg_target(target_raw) else {
                        continue;
                    };
                    // A1（方案 §4.1 实锤）：规则库里的 reg_key 目标此前只查「能不能解析 +
                    // 存不存在」，一条 `HKLM\SOFTWARE` 就能进候选列表并被默认勾选，执行侧
                    // 是 RegDeleteTreeW 递归删树。保护判定必须在产候选时就生效。
                    if let Some(reason) = protect::reg_target_block_reason(target_raw) {
                        vetoed.push(format!("残留规则 {id} 的注册表目标被硬否决（不入候选）: {reason}"));
                        continue;
                    }
                    if !crate::engine::native::reg_key_exists(hive, &rest) {
                        continue;
                    }
                    out.push(json!({
                        "kind": "reg_key", "target": target_raw,
                        "reason": format!("{lib_label}命中（{id}）：{note}"),
                        "confidence": confidence, "risk": "medium",
                        "defaultChecked": default_checked,
                        "ruleId": id, "ruleVer": rule_ver,
                        "contribs": contribs(&why),
                    }));
                }
                _ => continue,
            }
        }
    }
    (out, vetoed)
}

// ==================== A3 残留规则库在线更新（M3，决策清单 D3-D7） ====================
//
// 前置条件已由 M1 满足：A1 注册表硬否决 + A2 整包语义校验先落地，才允许把远程包接进分发。
// 顺序反过来（先上链再收口）等于让一条误签或私钥泄露后的坏规则自动扩散到所有装机。
//
// 与清理域的分工：**传输、验签、字节级原子落盘、水位线四段一律复用清理域已跑通的实现**
// （`cleanup::http_get_limited` / `rules_signature` / `security::atomic_write_file`），
// 只有「字段规则」和「尺寸量级」各留一份——两库内容量级不同，共用尺寸闸必然一边误拒、
// 一边放过。

/// 仓库内残留规则库路径（三条发布源共用清理域的同一拼装口，不抄第二份清单）
const RESIDUE_REPO_PATH: &str = "src-tauri/data/uninstall-residue-rules.json";
const RESIDUE_BUILTIN_LEN: usize = BUILTIN_RESIDUE_RULES_JSON.len();
/// 下限取「内置库一半」与 2048B 的较大者。刻意**不共用** `cleanup::RULES_MIN_SIZE = 4096`：
/// 残留库现在只有 6 条规则，删规则就可能掉到 4096B 以下，用清理域的下限会把合法包
/// 当成「异常响应」拒掉。下限的意义始终是探测截断/异常响应，不是质量线。
const RESIDUE_RULES_MIN_SIZE: usize = if RESIDUE_BUILTIN_LEN / 2 > 2048 {
    RESIDUE_BUILTIN_LEN / 2
} else {
    2048
};
/// 上限给合法增长留一个数量级以上的余量（内置约 5 KB → 512 KB 封顶）：
/// 收太紧会在规则库长到几十上百条后自我拒更，放到清理域的 2 MiB 又失去先拦超大响应的意义。
const RESIDUE_RULES_MAX_SIZE: usize = 512 * 1024;
const RESIDUE_DOWNLOAD_TIMEOUT_MS: u64 = 15000;

fn residue_source_urls() -> Vec<String> {
    crate::commands::cleanup::release_source_urls_for(RESIDUE_REPO_PATH)
}

/// 残留库更新源：用户覆盖源是**自己一份** `uninstall/update-source.json`（D6 拍板，
/// 不与清理库共用同名文件——两个同名文件长不同 schema 比多一个文件名更糟），
/// schema 与 headers 语义则完全共用清理域的解析器。
fn residue_sources() -> Vec<(String, Vec<(String, String)>)> {
    let user_file = crate::engine::paths::data_file_for_read("uninstall/update-source.json");
    crate::commands::cleanup::assemble_sources(
        crate::commands::cleanup::load_update_override(&user_file),
        &residue_source_urls(),
    )
}

/// 本地生效版本（数据目录那份被接受则用它，否则内置）——检查版本与防降级下限都以此为准
fn residue_local_version() -> f64 {
    let builtin = serde_json::from_str::<Value>(BUILTIN_RESIDUE_RULES_JSON)
        .ok()
        .and_then(|b| b.get("rulesVersion").and_then(|x| x.as_f64()))
        .unwrap_or(0.0);
    load_residue_rules()
        .and_then(|v| v.get("rulesVersion").and_then(|x| x.as_f64()))
        .unwrap_or(builtin)
}

/// 远程包校验（更新与「只查版本」共用同一条链）：尺寸 → 验签 → JSON → **语义** → 版本。
/// 语义校验调的就是装载侧那个 `validate_residue_package`——更新侧不写第二套字段规则，
/// 否则会出现「更新放行了、装载拒绝了」这种两头都自认正确的分叉。
/// 失败一律不落盘，因此这里不产生「半新半旧」的规则库状态。
fn verify_residue_remote_text(text: &str, floor: f64) -> Result<f64, String> {
    let len = text.chars().count();
    if len < RESIDUE_RULES_MIN_SIZE {
        return Err("内容过小，疑似异常响应".to_string());
    }
    if len > RESIDUE_RULES_MAX_SIZE {
        return Err("内容过大，疑似异常响应".to_string());
    }
    rules_signature::verify_rules_text(text)?;
    let parsed: Value = serde_json::from_str(text).map_err(|_| "JSON 解析失败".to_string())?;
    validate_residue_package(&parsed)?;
    let version = parsed
        .get("rulesVersion")
        .and_then(Value::as_f64)
        .ok_or_else(|| "缺少 rulesVersion".to_string())?;
    if floor > 0.0 && version < floor {
        return Err(format!(
            "下载版本({version})低于防回滚下限({floor})，疑似旧签名文件重放，已拒绝"
        ));
    }
    Ok(version)
}

/// 逐源取包并校验。返回 (版本, 原文, 命中的源)；全部失败时报最后一个原因。
/// 刻意不在这里落盘——更新与查版本共用它，查版本只读。
fn fetch_verified_residue_package() -> Result<(f64, String, String), String> {
    let floor = residue_local_version().max(residue_watermark());
    let sources = residue_sources();
    if sources.is_empty() {
        return Err("没有可用的更新源".to_string());
    }
    let mut last_err = String::new();
    let mut unreachable = 0;
    for (url, headers) in &sources {
        match crate::commands::cleanup::http_get_limited(
            url,
            headers,
            std::time::Duration::from_millis(RESIDUE_DOWNLOAD_TIMEOUT_MS),
            RESIDUE_RULES_MAX_SIZE,
            None,
        ) {
            Ok(text) => match verify_residue_remote_text(&text, floor) {
                Ok(version) => return Ok((version, text, url.clone())),
                Err(e) => last_err = e,
            },
            Err(e) => {
                unreachable += 1;
                last_err = e;
            }
        }
    }
    if unreachable == sources.len() {
        return Err(format!("所有发布源均不可达，最后一条: {last_err}"));
    }
    Err(format!("源可达但校验未通过，最后一条: {last_err}"))
}

/// uninstall:modify — 修改 / 修复入口（V2 P1-D6，2026-10-01；主窗档）
///
/// 与 uninstall_run 同一条纪律：app_id 只当寻址键，命令行**现读注册表**而不是信任
/// 渲染层早前传来的清单（那可能是旧快照）；NoModify/NoRepair 在执行时复判——
/// 清单说能改、键里已声明不能的场景以注册表为准。二者执行的都是 ModifyPath
/// （Windows「更改 / 修复」共用这一条命令行，MSI 产品会弹出维护对话框再分项），
/// mode 只影响拒绝文案与日志标签，不构造任何新命令行——「识别可以弱，执行不能猜」。
#[tauri::command]
pub async fn uninstall_modify<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    app_id: String,
    mode: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let Some((hive_str, key_path)) = app_id.split_once('|') else {
        return json!({ "success": false, "message": "app_id 格式错误" });
    };
    if !valid_uninstall_key_path(key_path) {
        return json!({ "success": false, "message": "app_id 不是合法的卸载键路径" });
    }
    let mode = match mode.as_deref() {
        Some("repair") => "repair",
        _ => "modify",
    };
    let hive_str = hive_str.to_string();
    let key_path = key_path.to_string();
    let res = tauri::async_runtime::spawn_blocking(move || unsafe {
        use windows::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
        };
        let (hive, _hive_name) = if hive_str.eq_ignore_ascii_case("HKCU") {
            (HKEY_CURRENT_USER, "HKCU")
        } else if hive_str.eq_ignore_ascii_case("HKLM") {
            (HKEY_LOCAL_MACHINE, "HKLM")
        } else {
            return Err("app_id hive 只支持 HKCU/HKLM".to_string());
        };
        let sk = to_wide(&key_path);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err()
        {
            return Err("卸载注册表键不存在（程序可能已被卸载）".to_string());
        }
        let display_name = reg_sz(hk, "DisplayName").unwrap_or_default();
        let modify_path = reg_sz(hk, "ModifyPath").unwrap_or_default();
        let no_modify = reg_dword(hk, "NoModify").unwrap_or(0);
        let no_repair = reg_dword(hk, "NoRepair").unwrap_or(0);
        let _ = RegCloseKey(hk);
        let label = if mode == "repair" { "修复" } else { "修改" };
        if modify_path.trim().is_empty() {
            return Err("该程序没有 ModifyPath，无法执行修改/修复".to_string());
        }
        if mode != "repair" && no_modify == 1 {
            return Err("该程序声明不支持更改（NoModify=1）".to_string());
        }
        if mode == "repair" && no_repair == 1 {
            return Err("该程序声明不支持修复（NoRepair=1）".to_string());
        }
        let (exe, args) = split_uninstall_cmd(&modify_path)
            .ok_or_else(|| "ModifyPath 无法解析出可执行文件".to_string())?;
        log::flush_sync();
        let code = shell_run_wait(&exe, &args).map_err(|e| {
            log::write_log(
                "error",
                &format!("uninstall_modify {display_name}: {label}启动失败: {e}"),
            );
            e
        })?;
        log::write_log(
            "info",
            &format!("uninstall_modify {display_name}: {label}完成，退出码 {code}"),
        );
        Ok(code)
    })
    .await;
    match res {
        Ok(Ok(code)) => json!({ "success": true, "data": { "exitCode": code, "mode": mode } }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("修改/修复执行异常: {e}") }),
    }
}

/// uninstall:check-residue-version — 只查版本，不写任何东西（主窗档）
#[tauri::command]
pub async fn uninstall_check_residue_version<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(|| match fetch_verified_residue_package() {
        Ok((version, _text, source)) => Ok((version, source)),
        Err(e) => Err(e),
    })
    .await;
    match res {
        Ok(Ok((version, source))) => {
            let current = residue_local_version();
            json!({ "success": true, "data": {
                "currentVersion": current, "remoteVersion": version,
                "newerAvailable": version > current, "source": source,
            }})
        }
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("检查残留规则版本异常: {e}") }),
    }
}

/// uninstall:update-residue-rules — 更新残留规则库（主窗档；显式动作，不做定时）。
/// 落盘必须是**字节级**原子写：重新序列化 JSON 会改键序/空白，而 `_sig` 是对原文本签的，
/// 重排就把合法包变成验签失败（清理域审查 M10 的同一条教训）。
#[tauri::command]
pub async fn uninstall_update_residue_rules<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(|| {
        let (version, text, source) = fetch_verified_residue_package()?;
        let dir = residue_rules_write_dir();
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建规则目录失败: {e}"))?;
        let target = residue_rules_write_dir().join("residue-rules.json");
        crate::security::atomic_write_file(&target, text.as_bytes())
            .map_err(|e| format!("写入残留规则失败: {e}"))?;
        // 水位线只在真的抬得动时记一笔；写失败不撤销本次更新（读取侧仍有验签与语义闸）
        let raised = set_residue_watermark(version);
        Ok::<(f64, String, bool), String>((version, source, raised))
    })
    .await;
    match res {
        Ok(Ok((version, source, raised))) => {
            log::write_log(
                "info",
                &format!(
                    "残留规则库已更新: rulesVersion={version} 源={source} 水位线={}",
                    if raised { "已抬升" } else { "未变(写入失败或不高于当前)" }
                ),
            );
            json!({ "success": true, "data": {
                "rulesVersion": version, "source": source,
                "message": format!("残留规则库已更新到 {version}"),
            }})
        }
        Ok(Err(e)) => {
            log::write_log("warn", &format!("残留规则库更新失败: {e}"));
            json!({ "success": false, "message": e })
        }
        Err(e) => json!({ "success": false, "message": format!("残留规则更新异常: {e}") }),
    }
}

// ==================== C2 卸载所有权历史（方案 §6.3） ====================
///
/// 目标不是"把所有没人认领的目录都列出来"，而是**只在证据链闭合时**把一个精确同名目录（或其中
/// 明确可弃的子目录）升级为候选。所以这里是一条单向状态机，不是一个缓存：
///
/// ```text
/// 用户确认卸载、执行卸载器之前  →  写 pending（此刻还不知道卸载会不会成功）
/// 应用数据遗留扫描时复扫当前程序清单     →  程序已消失且原 InstallLocation ENOENT  → historical
///                                  程序仍在清单                          → 继续 pending
///                                  pending 超稳定期（30 天）             → 移除
///                                  historical 的程序又回到清单（重装）   → 移除该记录
/// ```
///
/// 为什么不把"点击卸载"直接当成所有权事实：卸载会取消、会失败、会只删一半；
/// 把一次点击当成"这台机器上的这个目录属于它"会让后面所有判定建立在猜测上。
/// `leftover-owners` 类实现（Kudu）也是跨轮保存、合并后再确认的，不是一条即用即弃的记录。
mod ownership {
    use crate::commands::uninstall::footprint;
    use serde_json::{json, Value};
    use std::collections::HashSet;
    use std::path::Path;

    /// 数据文件 schema 版本（结构变化时递增；旧版本文件按损坏处理走隔离，不做兼容层）
    pub const SCHEMA_VERSION: u64 = 1;
    /// 记录上限：所有权历史只服务应用数据遗留判定，不该无限增长（每条记录都要参与复扫与匹配）
    pub const MAX_RECORDS: usize = 400;
    /// pending 稳定期：超过就按"卸载没继续/用户放弃了"回收。刻意**不做**成永久保留——
    /// 一条永远悬着的 pending 会让后面每次复扫都重跑判定，却没有产出候选的资格。
    pub const PENDING_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

    pub const STATE_PENDING: &str = "pending";
    pub const STATE_HISTORICAL: &str = "historical";

    pub fn empty_doc() -> Value {
        json!({ "schemaVersion": SCHEMA_VERSION, "owners": [], "ignored": [] })
    }

    pub fn file() -> std::path::PathBuf {
        crate::engine::paths::app_data_dir().join("uninstall-ownership.json")
    }

    /// 载入：文件缺失 = 空档（正常首次使用）；解析失败或结构不对 = 按损坏隔离后回空档。
    /// 隔离而不是"尽力解析"是因为这份数据会**驱动删除候选**，半损坏状态下的猜测不可接受。
    pub fn load() -> Value {
        let path = file();
        let Ok(text) = std::fs::read_to_string(&path) else {
            return empty_doc();
        };
        let parsed: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                crate::engine::log::write_log("warn", &format!("所有权历史解析失败，已隔离: {e}"));
                crate::security::quarantine_file(&path, "ownership JSON 解析失败");
                return empty_doc();
            }
        };
        if parsed.get("owners").and_then(Value::as_array).is_none()
            || parsed.get("schemaVersion").and_then(Value::as_u64) != Some(SCHEMA_VERSION)
        {
            crate::engine::log::write_log("warn", "所有权历史结构或 schema 版本不符，已隔离并重建空档");
            crate::security::quarantine_file(&path, "ownership 结构/版本不符");
            return empty_doc();
        }
        parsed
    }

    pub fn save(doc: &Value) -> Result<(), String> {
        crate::security::atomic_write_json(&file(), doc).map_err(|e| e.to_string())
    }

    fn owners_of_mut<'a>(doc: &'a mut Value) -> &'a mut Vec<Value> {
        doc["owners"].as_array_mut().expect("owners 必须是数组（load 已校验）")
    }

    pub fn is_ignored(doc: &Value, app_id: &str, display_name_norm: &str) -> bool {
        let Some(list) = doc.get("ignored").and_then(Value::as_array) else {
            return false;
        };
        list.iter().any(|i| {
            let id = i.get("appId").and_then(Value::as_str).unwrap_or("");
            let name = i.get("displayName").and_then(Value::as_str).unwrap_or("");
            (!id.is_empty() && id.eq_ignore_ascii_case(app_id))
                || (!name.is_empty() && !display_name_norm.is_empty() && name == display_name_norm)
        })
    }

    /// 卸载执行前写 pending 事件。已存在同 appId 时**刷新**而不是新增（重装/多次尝试是同一事实）；
    /// 命中忽略清单则完全不记（否则用户忽略了又被重新采纳）。
    pub fn record_pending(
        doc: &mut Value,
        app_id: &str,
        display_name: &str,
        publisher: &str,
        install_location: &str,
        owned_paths: &[String],
        now_ms: i64,
        name_norm: impl Fn(&str) -> String,
    ) -> bool {
        if app_id.is_empty() || is_ignored(doc, app_id, &name_norm(display_name)) {
            return false;
        }
        let owners = owners_of_mut(doc);
        if let Some(hit) = owners.iter_mut().find(|o| {
            o.get("appId").and_then(Value::as_str) == Some(app_id)
        }) {
            hit["displayName"] = json!(display_name);
            hit["publisher"] = json!(publisher);
            hit["installLocation"] = json!(install_location);
            hit["ownedPaths"] = json!(owned_paths);
            hit["state"] = json!(STATE_PENDING);
            hit["recordedAt"] = json!(now_ms);
            // 刷新即重新开始稳定期计时；上一轮的确认时间不再有意义
            hit.as_object_mut().map(|o| o.remove("confirmedAt"));
            return true;
        }
        owners.push(json!({
            "appId": app_id,
            "displayName": display_name,
            "publisher": publisher,
            "installLocation": install_location,
            "ownedPaths": owned_paths,
            "recordedAt": now_ms,
            "state": STATE_PENDING,
        }));
        true
    }

    /// 记/刷新某 owner 的**卸载前足迹基线**（HiBit §9.1 那条思路的落地位置）。
    ///
    /// 存的是卸载动作发生时 `HKCU\Software` / `HKLM\SOFTWARE` 下的厂商顶层键名集合。
    /// 卸载后复扫时，"清单里没了、但顶层多出一个厂商键且基线里没有"才是厂商自己写的配置键——
    /// 名称相似度那条路实测会把 `netease`（网易云音乐仍在装）这类共享厂商段误判成残留。
    ///
    /// `SCHEMA_VERSION` 刻意**不升**：这是纯增字段，老档案里没有 footprint 就当"没有基线"，
    /// 而升版本会触发 `load()` 的隔离重建，把用户本机已有的卸载记录一起丢掉。
    pub fn set_footprint(doc: &mut Value, app_id: &str, keys: &[String], now_ms: i64) -> bool {
        // 空基线一律不写：空集合不是"这台机器没有厂商键"，写成基线下一轮差分就会把
        // 全部现存键算成"卸载后才出现的新键"。调用方（uninstall_run）拿 false 去记日志。
        if keys.is_empty() {
            return false;
        }
        let Some(list) = doc.get_mut("owners").and_then(Value::as_array_mut) else {
            return false;
        };
        let Some(hit) = list.iter_mut().find(|o| {
            o.get("appId").and_then(Value::as_str) == Some(app_id)
        }) else {
            return false;
        };
        let capped = keys.len() > footprint::MAX_KEYS_PER_OWNER;
        let keep: Vec<String> = keys.iter().take(footprint::MAX_KEYS_PER_OWNER).cloned().collect();
        hit["footprint"] = json!({ "at": now_ms, "keys": keep, "capped": capped });
        true
    }

    /// 复扫：pending → historical、过期回收、重装的 historical 撤销。
    /// `install_exists` 注入探测（测试不碰盘）；返回 (升级为 historical 数, 移除数)。
    pub fn rescan(
        doc: &mut Value,
        current_app_ids: &HashSet<String>,
        now_ms: i64,
        install_exists: &dyn Fn(&Path) -> bool,
    ) -> (usize, usize) {
        let mut promoted = 0;
        let mut removed = 0;
        let owners = owners_of_mut(doc);
        owners.retain_mut(|o| {
            let app_id = o.get("appId").and_then(Value::as_str).unwrap_or("").to_string();
            let state = o.get("state").and_then(Value::as_str).unwrap_or("").to_string();
            let listed = current_app_ids.contains(&app_id);
            if state == STATE_HISTORICAL {
                if listed {
                    // 程序又回到清单 = 用户重装了它，这条"已卸载"事实不再成立
                    removed += 1;
                    return false;
                }
                return true;
            }
            if listed {
                return true; // 还在清单里：卸载没完成，继续 pending
            }
            let loc = o.get("installLocation").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let gone = loc.is_empty() || !install_exists(Path::new(&loc));
            if !gone {
                // 程序不在清单但安装目录还在：可能是卸载器半途退出，也可能是别的软件复用同目录。
                // 不升级、也不删事实，交给稳定期回收。
                return true;
            }
            let recorded = o.get("recordedAt").and_then(Value::as_i64).unwrap_or(now_ms);
            if now_ms - recorded > PENDING_TTL_MS {
                removed += 1;
                return false;
            }
            o["state"] = json!(STATE_HISTORICAL);
            o["confirmedAt"] = json!(now_ms);
            promoted += 1;
            true
        });
        // 上限裁剪：pending 有生命周期意义，优先裁最旧的 historical；
        // 全是 pending 仍超限时才动 pending（宁可丢历史也不无界增长）。
        let owners = owners_of_mut(doc);
        if owners.len() > MAX_RECORDS {
            let mut oldest_h: Option<(usize, i64)> = None;
            for (idx, o) in owners.iter().enumerate() {
                if o.get("state").and_then(Value::as_str) == Some(STATE_HISTORICAL) {
                    let at = o.get("confirmedAt").and_then(Value::as_i64).unwrap_or(0);
                    if oldest_h.map(|(_, c)| at < c).unwrap_or(true) {
                        oldest_h = Some((idx, at));
                    }
                }
            }
            if let Some((idx, _)) = oldest_h {
                owners.remove(idx);
            } else {
                owners.sort_by_key(|o| o.get("recordedAt").and_then(Value::as_i64).unwrap_or(0));
                while owners.len() > MAX_RECORDS {
                    owners.remove(0);
                }
            }
        }
        (promoted, removed)
    }

    /// 用户忽略某个 owner：移出 owners 并写进 ignored（按 appId 与归一化显示名双记，
    /// 因为同一款程序可能以不同 hive/子键再次出现在卸载清单里）。
    pub fn ignore(doc: &mut Value, app_id: &str, display_name: &str, now_ms: i64, name_norm: impl Fn(&str) -> String) {
        let name = name_norm(display_name);
        {
            let owners = owners_of_mut(doc);
            owners.retain(|o| o.get("appId").and_then(Value::as_str) != Some(app_id));
        }
        let list = doc["ignored"].as_array_mut().expect("ignored 必须是数组");
        if !list.iter().any(|i| i.get("appId").and_then(Value::as_str) == Some(app_id)) {
            list.push(json!({ "appId": app_id, "displayName": name, "addedAt": now_ms }));
        }
    }

    pub fn historical_owners(doc: &Value) -> Vec<Value> {
        doc.get("owners")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter(|o| o.get("state").and_then(Value::as_str) == Some(STATE_HISTORICAL)).cloned().collect())
            .unwrap_or_default()
    }
}

/// 应用数据遗留候选的判定与产出（C2-3）。
///
/// 三条硬约束，缺一条都不许出候选：
/// 1. **精确同名**（不是相似度）——目录末段归一后等于某 historical owner 的显示名或
///    其 installLocation 的 basename；
/// 2. **owner 唯一**——同一目录名被两个 historical owner 命中时无法判定归属，直接丢；
/// 3. **原安装目录必须 ENOENT**——还在就说明程序没卸完，不是应用数据遗留。
/// 另外再过三道环境闸：受保护路径、上级链重解析点（`dir_delete_blocked`）、
/// 运行中进程所在目录（与候选互为祖先或子孙即视为在用，正被使用的目录绝不提示删除）。
/// 产出默认只列**可弃子目录**（cache / logs 这类），且一律不勾选、置信度封顶 medium。
const ORPHAN_DISPOSABLE_SUBDIRS: &[&str] = &[
    "cache", "caches", "code cache", "gpucache", "gpu cache", "logs", "log", "tmp", "temp",
];
/// 应用数据遗留扫描的目录根：与启发式目录命中同三个根，只扫一层（不递归，成本可控）
const ORPHAN_SCAN_ROOTS: &[&str] = &["APPDATA", "LOCALAPPDATA", "PROGRAMDATA"];
const ORPHAN_MAX_CANDIDATES: usize = 40;

/// 当前全系统进程的可执行路径（小写全路径），用于「候选目录是否在运行进程祖先链上」。
/// 拿不到就返回空集 —— 但这条判定是**保护用户**的，取不到时按「全部拒绝出候选」处理更稳妥，
/// 所以调用方用 Option：None = 取不到快照，直接不产出该组候选。
fn running_process_dirs() -> Option<HashSet<String>> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut out = HashSet::new();
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pe.th32ProcessID).ok();
                if let Some(h) = h {
                    let mut buf: Vec<u16> = vec![0; 1024];
                    let mut len: u32 = buf.len() as u32;
                    let name = QueryFullProcessImageNameW(
                        h,
                        PROCESS_NAME_FORMAT(0),
                        windows::core::PWSTR(buf.as_mut_ptr()),
                        &mut len,
                    )
                    .map(|_| String::from_utf16_lossy(&buf[..len as usize]));
                    let _ = windows::Win32::Foundation::CloseHandle(h);
                    if let Ok(p) = name {
                        if let Some(parent) = Path::new(&p).parent() {
                            out.insert(parent.to_string_lossy().to_ascii_lowercase());
                        }
                    }
                }
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = snap;
        Some(out)
    }
}

/// 卸载前足迹基线的判据（HiBit §9.1「轻量安装监视」落到本应用能承受的形态）。
///
/// HiBit 在安装前记基线、安装后差分；本应用没有安装钩子，能拿到的同价证据是
/// **卸载动作那一刻**的顶层厂商键集合：卸载后程序不在了、清单里没有它、安装目录也没了，
/// 而某个厂商键是卸载前不存在、卸载后才出现的——那就是它自己写、卸载器不认的登记。
/// 名称相似度那条路实测不可用（本机 `NeteaseGodLike` 与仍在装的网易云音乐共享 `Netease` 段）。
mod footprint {
    use serde_json::Value;
    use std::collections::HashSet;

    /// 一条基线保留的顶层键上限（本机实测三根共 135 个名字，留一倍余量）。
    pub const MAX_KEYS_PER_OWNER: usize = 300;
    /// 单次扫描最多产出的厂商键候选，防止某台机器上出现异常膨胀。
    pub const MAX_CANDIDATES: usize = 40;

    /// 结构性容器：这些顶层键不是任何第三方程序的落点，出现在差集里也只可能是系统或
    /// 别的软件在这两次读之间动过手。判"残留"不值得为它们打扰用户。
    const DENY_ROOTS: &[&str] = &[
        "microsoft",
        "classes",
        "clients",
        "policies",
        "registeredapplications",
        "wow6432node",
        "khronos",
        "odbc",
        "oem",
        "setup",
        "volatile",
        "defaultuserenvironment",
        "appdatalow",
        "deviceinfo",
        "changetracker",
        "contextmenumgr",
        "roamingdevice",
        "capabilities",
    ];

    /// 顶层键名是否可能是某个程序的厂商键。
    ///
    /// GUID 形态（`14d8c5cd-3d3a-…`）在本机是 WebView2/Chromium 组件键，且系统随时可能新增，
    /// 一并挡掉：宁可漏一条厂商残留，不要把系统键列成"可删的残留"。
    pub fn is_vendor_key(name: &str) -> bool {
        let n = name.trim().to_ascii_lowercase();
        if n.chars().count() < 2 {
            return false;
        }
        if DENY_ROOTS.iter().any(|d| n.starts_with(d)) {
            return false;
        }
        let guid_shape = n.len() == 36
            && n.matches('-').count() == 4
            && n.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        !guid_shape
    }

    /// 卸载后才新出现的厂商键（大小写不敏感差集，顺序跟"当前"读到的顺序）。
    pub fn new_keys_since(baseline: &[String], current: &[String]) -> Vec<String> {
        let seen: HashSet<String> = baseline.iter().map(|k| k.to_ascii_lowercase()).collect();
        current
            .iter()
            .filter(|k| !seen.contains(&k.to_ascii_lowercase()))
            .cloned()
            .collect()
    }

    /// 归属判定用的 token：显示名、发布商、安装目录末段里能取到的短词。
    ///
    /// 只做**互含**、不做相似度：足迹差分已经证明"这键是卸完才出现的"，token 只回答
    /// "它是不是这个程序写的"；再加上模糊匹配就等于把猜测请回删除依据里（C3 同一口径）。
    pub fn tokens_of(owner: &Value) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut add = |raw: &str| {
            let s = raw.trim().to_ascii_lowercase();
            if s.chars().count() >= 2 && !out.contains(&s) {
                out.push(s);
            }
        };
        for field in ["displayName", "publisher"] {
            if let Some(v) = owner.get(field).and_then(Value::as_str) {
                add(v);
            }
        }
        if let Some(loc) = owner.get("installLocation").and_then(Value::as_str) {
            if let Some(base) = loc.trim().trim_end_matches(['\\', '/']).rsplit('\\').next() {
                add(base);
            }
        }
        if let Some(paths) = owner.get("ownedPaths").and_then(Value::as_array) {
            for p in paths.iter().filter_map(Value::as_str) {
                if let Some(base) = p.trim().trim_end_matches(['\\', '/']).rsplit('\\').next() {
                    add(base);
                }
            }
        }
        out
    }

    /// 键的末段是否与某程序的 token 互含（两侧都小写）。
    pub fn key_belongs_to(key: &str, tokens: &[String]) -> bool {
        let leaf = key.rsplit('\\').next().unwrap_or("").to_ascii_lowercase();
        if leaf.chars().count() < 2 {
            return false;
        }
        tokens.iter().any(|t| {
            t.chars().count() >= 2 && (leaf.contains(t.as_str()) || t.contains(leaf.as_str()))
        })
    }

    /// 从 owner 记录里取基线。**缺字段或被截断（capped）都当"没有可信基线"**：
    /// 基线不全时差集会把本来早就存在的键算成新键，那是把老键当残留删，代价不可接受。
    pub fn baseline_of(owner: &Value) -> Option<Vec<String>> {
        let fp = owner.get("footprint")?;
        if fp.get("capped").and_then(Value::as_bool).unwrap_or(true) {
            return None;
        }
        let keys = fp.get("keys").and_then(Value::as_array)?;
        Some(
            keys.iter()
                .filter_map(|k| k.as_str().map(String::from))
                .collect(),
        )
    }
}

/// 本机学习型残留库（HiBit §H3 借鉴项，2026-09-29）。
///
/// HiBit 的 `LocalDB.ini` 是「出厂内置 + 用户增量」两层：exe 里嵌一份出厂默认，
/// AppData 那份随使用增长。Trim 只有前者（`uninstall-residue-rules.json`：人工评审 +
/// 签名 + `prov.reviewedAt` 溯源），缺的就是第二层——同一台机器上卸载过一次的程序，
/// 下次再装再卸仍然要从头启发。本模块补那半层。
///
/// **schema 与签名库逐字段相同，因此运行期复用同一个 `validate_residue_package`**。
/// 这不是偷懒，是这批唯一的安全支点：学习库不签名、由本机自采，若给它一套自己的校验器，
/// 就等于开了「绕过人审与私钥也能进候选」的旁路——M1 批次封的正是同类洞
/// （一条签名规则 `reg_key: HKLM\SOFTWARE` 当时能过所有闸门并被默认勾选）。
/// 复用同一校验器 ⇒ 字段白名单、kind 允许集、目标形状、深度上限、双条件组、注册表禁删面
/// 一个都不少。代价是学不到 `learnedAt`/命中次数这类元数据（白名单不放）——
/// 淘汰改用「数组顺序即新旧」，不值得为一条统计字段把校验器分叉。
///
/// 与签名库不同的三处刻意收紧（因为证据等级更低）：
/// 1. `defaultChecked = false`、`confidence` 上限 `medium`（与 M4/M6 对本机自推候选的裁定一致）；
/// 2. 目标必须**可按归属核对**——路径里至少有一段与该程序的显示名/发行商/卸载键末段互含，
///    沿用 `footprint` 那条口径（只做互含、不做相似度）。没有归属判据时，
///    `%APPDATA%\Microsoft\Windows\Recent` 这类共享容器会被当成"这程序的残留"学进去；
/// 3. 注册表目标额外要求 hive 之下 ≥3 段（`HKCU\Software\Foo` 这种厂商顶层键不学）——
///    本机实测过共享厂商段误判（`Netease` 同时被网易云音乐命中）。
mod learned {
    use serde_json::{json, Value};
    use std::path::Path;

    use super::{
        footprint, norm_name, parse_reg_target, protect, validate_residue_package,
        RESIDUE_MAX_TEXT_LEN,
    };

    /// 学习库条数上限：一台机器不会装几百个待卸载程序，超了按新旧淘汰
    pub const MAX_RULES: usize = 120;
    /// 单程序记录的落点数上限（有些程序散落十几个目录，记满只会淹没面板）
    pub const MAX_RESIDUE_PER_RULE: usize = 16;
    /// 注册表学习深度下限：hive 之下至少三段。`HKCU\Software\Foo` 是厂商顶层键，
    /// 一个键名下可能住着全家桶，不给进学习库
    pub const REG_MIN_DEPTH: usize = 3;

    pub const LEARNED_SOURCE_CLASS: &str = "本机自采（未签名、未经人工评审）";

    fn file_write() -> std::path::PathBuf {
        super::residue_rules_write_dir().join("residue-learned.json")
    }

    /// 读取根：与规则库同一口径（新根优先，老根只读兜底）
    fn file_read() -> std::path::PathBuf {
        crate::engine::paths::data_file_for_read("uninstall/residue-learned.json")
    }

    pub fn empty_doc() -> Value {
        json!({
            "rulesVersion": 1.0,
            "prov": [{ "sourceClass": LEARNED_SOURCE_CLASS, "reviewedAt": "" }],
            "rules": []
        })
    }

    /// 纯函数：解析 + 复用签名库校验器。**任何一步失败都返回 Err**，由调用方决定隔离。
    /// 刻意不碰文件——这份数据驱动删除候选，测试里留写盘副作用会把用户本机档案判坏。
    pub fn from_text(text: &str) -> Result<Value, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("JSON 解析失败: {e}"))?;
        validate_residue_package(&v).map_err(|e| format!("学习库语义校验未通过: {e}"))?;
        Ok(v)
    }

    /// 载入。文件缺失 = 空（首次使用）；解析或语义不过 = 隔离后回空档。
    ///
    /// 与 `ownership::load` 同一立场：驱动删除候选的数据在半损坏状态下必须**停用**，
    /// 而不是尽力解析——「猜出来的残留」比「这一轮没提示」危险得多。
    pub fn load() -> Option<Value> {
        let path = file_read();
        let Ok(text) = std::fs::read_to_string(&path) else {
            return None;
        };
        match from_text(&text) {
            Ok(v) => Some(v),
            Err(reason) => {
                crate::engine::log::write_log("warn", &format!("{reason}，学习库已隔离停用: {:?}", path.file_name()));
                crate::security::quarantine_file(&path, "residue-learned 语义校验未通过");
                None
            }
        }
    }

    /// 落盘前先自校验：写入侧不把一份「装载时会被隔离」的文件留给下一轮扫描。
    /// 两头都判才是闭环——只判读侧的话，本函数的一个 bug 会直接毁掉用户本机全部学习记录。
    pub fn save(doc: &Value) -> Result<(), String> {
        validate_residue_package(doc).map_err(|e| format!("学习库落盘前校验未通过（已放弃写入）: {e}"))?;
        let path = file_write();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("创建学习库目录失败: {e}"))?;
        }
        crate::security::atomic_write_json(&path, doc).map_err(|e| e.to_string())
    }

    /// 学习库规则的稳定 id：`learned-` + (归一化程序名 + 卸载键末段) 的 sha256 前 12 位。
    /// 必须是纯 [a-z0-9-] —— 签名库校验器对 id 字符集有白名单，中文程序名不能直接当 id。
    pub fn rule_id(display_name: &str, key_path: &str) -> String {
        use sha2::{Digest as _, Sha256};
        let leaf = key_path.rsplit('\\').next().unwrap_or("").to_lowercase();
        let base = format!("{}|{}", norm_name(display_name), leaf);
        let hex: String = Sha256::digest(base.as_bytes())
            .iter()
            .take(6)
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("learned-{hex}")
    }

    /// 目标是否值得学。返回 `Some(原因)` = 拒学（不写进库，下一轮也不会再出这条候选）。
    ///
    /// 判据顺序有讲究：先看保护面（最硬），再看归属（学习库特有），最后看深度。
    /// 归属这一步是学习库与签名库的实质差别：签名库是人写「这个程序确实有这目录」，
    /// 学习库没人审，只能靠路径里有没有这程序的名字来自己交代。
    pub fn target_reject_reason(kind: &str, target: &str, tokens: &[String]) -> Option<String> {
        if target.trim().is_empty() || target.len() > 260 {
            return Some("目标为空或超过 MAX_PATH".to_string());
        }
        match kind {
            "reg_key" => {
                if let Some(r) = protect::reg_target_block_reason(target) {
                    return Some(format!("注册表禁删面: {r}"));
                }
                let Some((_, rest)) = parse_reg_target(target) else {
                    return Some("注册表目标无法解析".to_string());
                };
                let depth = rest.split('\\').filter(|s| !s.trim().is_empty()).count();
                if depth < REG_MIN_DEPTH {
                    return Some(format!("注册表深度 {depth} 低于下限 {REG_MIN_DEPTH}（厂商顶层键不学）"));
                }
            }
            "folder" | "file" => {
                if protect::is_path_protected(target) {
                    return Some("受保护路径".to_string());
                }
                let p = Path::new(target);
                // 盘根/父根一律不学：一旦学错，下一轮是整棵目录树进候选
                if p.parent().map(|x| x.parent().is_none()).unwrap_or(true) {
                    return Some("路径层级过浅".to_string());
                }
            }
            other => return Some(format!("不支持学习的 kind: {other}")),
        }
        // 归属核对：任一段与该程序 token 互含（与 footprint 同口径，不做相似度）
        let segs: Vec<String> = target
            .split(['\\', '/'])
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| s.chars().count() >= 2)
            .collect();
        if segs.is_empty() {
            return Some("路径没有可比对的段".to_string());
        }
        let owned = tokens.iter().any(|t| {
            let tl = t.trim().to_ascii_lowercase();
            tl.chars().count() >= 2 && segs.iter().any(|s| s.contains(&tl) || tl.contains(s.as_str()))
        });
        if !owned {
            return Some("路径里没有任何一段属于这程序（共享容器不学）".to_string());
        }
        None
    }

    /// 把「用户实际删掉的落点」并入库。返回新增条数。
    ///
    /// 三组条件必须同时给得出（`displayName` + `uninstallKey` 至少两组非空是签名库的
    /// U-1 口径，校验器会整包拒），拿不到归属身份就不学——宁可这条不沉淀。
    pub fn learn(
        doc: &mut Value,
        display_name: &str,
        publisher: &str,
        key_path: &str,
        entries: &[(&str, String)],
        now_ms: i64,
    ) -> usize {
        if entries.is_empty() || display_name.trim().is_empty() || key_path.trim().is_empty() {
            return 0;
        }
        // 归属 token 只能来自**程序身份**（显示名 / 发行商 / 卸载键末段）。刻意不喂 ownedPaths：
        // 那等于把候选路径自己的末段当成「属于这程序」的证据，任何目标都会命中自己，
        // 归属判定当场失效（写第一版时就踩在这里，被单测抓出来）。
        let key_leaf = key_path.rsplit('\\').next().unwrap_or(key_path).to_string();
        // 归属 token 只能来自**程序身份**（显示名 / 发行商 / 卸载键末段）。刻意不喂 ownedPaths：
        // 那等于把候选路径自己的末段当成「属于这程序」的证据，任何目标都会命中自己，
        // 归属判定当场失效（写第一版时踩在这里，判红自测已把这条缺陷装回去验证过会被抓到）。
        let tokens = footprint::tokens_of(&json!({
            "displayName": display_name,
            "publisher": publisher,
            "installLocation": format!("C:\\x\\{key_leaf}"),
        }));
        let id = rule_id(display_name, key_path);
        // 只留 kind 与目标形状都合规的落点
        let keep: Vec<(&str, String)> = entries
            .iter()
            .filter(|(k, t)| target_reject_reason(k, t, &tokens).is_none())
            .cloned()
            .collect();
        if keep.is_empty() {
            return 0;
        }
        // 先取库版本再可变借用 rules：条目级 ver 必须等于顶层 rulesVersion（V2 P2-A1）
        let doc_ver = doc
            .get("rulesVersion")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let Some(rules) = doc.get_mut("rules").and_then(Value::as_array_mut) else {
            return 0;
        };
        let stamp = super::delete_manifest::iso_now();
        let mut added = 0usize;
        let hit = rules.iter_mut().find(|r| r.get("id").and_then(Value::as_str) == Some(id.as_str()));
        match hit {
            Some(r) => {
                let Some(list) = r.get_mut("residue").and_then(Value::as_array_mut) else {
                    return 0;
                };
                for (k, t) in keep {
                    let dup = list.iter().any(|e| {
                        e.get("kind").and_then(Value::as_str) == Some(k)
                            && e.get("target").and_then(Value::as_str)
                                .map(|x| x.eq_ignore_ascii_case(&t))
                                .unwrap_or(false)
                    });
                    if dup {
                        continue;
                    }
                    list.push(json!({ "kind": k, "target": t, "note": learn_note(display_name, &stamp) }));
                    added += 1;
                }
                // 单程序上限按「先记的先出」裁，与整库淘汰同一策略，不引入时间戳字段
                while list.len() > MAX_RESIDUE_PER_RULE {
                    list.remove(0);
                }
            }
            None => {
                let residue: Vec<Value> = keep
                    .iter()
                    .map(|(k, t)| json!({ "kind": *k, "target": t.clone(), "note": learn_note(display_name, &stamp) }))
                    .collect();
                let mut pubarr: Vec<Value> = Vec::new();
                if !publisher.trim().is_empty() {
                    pubarr.push(json!(publisher.trim()));
                }
                // 条目级版本戳跟随本库这一版（V2 P2-A1 同口径）：学习库的 rulesVersion 固定 1.0，
                // 但签名库校验器要求每条都带着它，缺一条就整包拒 —— 这里不补就等于
                // 「学出来的规则永远装不回去」
                rules.push(json!({
                    "id": id,
                    "ver": doc_ver,
                    "displayName": [display_name.trim()],
                    "publisher": pubarr,
                    "uninstallKey": [key_leaf],
                    "residue": residue,
                }));
                added = residue.len();
                while rules.len() > MAX_RULES {
                    rules.remove(0);
                }
            }
        }
        // prov.reviewedAt 用「最近一次学习」当时间戳：校验器要求它非空且是字符串，
        // 而学习库没有人工评审事件可登记，如实写成本机自采时间比留个假评审日期诚实
        if let Some(prov) = doc.get_mut("prov").and_then(Value::as_array_mut) {
            prov.insert(
                0,
                json!({ "sourceClass": LEARNED_SOURCE_CLASS, "reviewedAt": format!("本机自采 {stamp}") }),
            );
            prov.truncate(1);
        }
        let _ = now_ms;
        added
    }

    fn learn_note(name: &str, stamp: &str) -> String {
        let mut s = format!("本机于 {stamp} 清理「{name}」时删掉的落点");
        if s.chars().count() > RESIDUE_MAX_TEXT_LEN {
            s = s.chars().take(RESIDUE_MAX_TEXT_LEN).collect();
        }
        s
    }
}

/// 候选目录是否与某个运行中进程的可执行路径在同一条链上。
/// **两个方向都要查**：候选是进程目录的祖先（端掉父目录会带走正在跑的程序）
/// 或候选就在进程目录里面（正被使用的子目录）——只查一边会漏掉另一半（Y5 实测）。
fn under_running_process(dir: &Path, procs: &HashSet<String>) -> bool {
    let cand = dir.to_string_lossy().to_ascii_lowercase();
    procs.iter().any(|p| path_within(p, &cand) || path_within(&cand, p))
}

/// `inner` 是否等于 `outer` 或位于其目录树内。**按路径段**比，不按裸前缀比：
/// `C:\Foo\bar` 与 `C:\Foobar` 都不算在 `C:\Foo` 里面，否则同级兄弟目录会被误判成在用。
fn path_within(inner: &str, outer: &str) -> bool {
    let i = inner.trim_end_matches(['\\', '/']);
    let o = outer.trim_end_matches(['\\', '/']);
    i == o || (i.starts_with(o) && matches!(i.as_bytes().get(o.len()), Some(b'\\') | Some(b'/')))
}

/// uninstall:orphan-scan — 卸载遗留扫描（应用数据目录 + 卸载后新增的厂商配置键；
/// 主窗档，只产候选，删除仍走 residue-execute）
#[tauri::command]
pub async fn uninstall_orphan_scan<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let res = tauri::async_runtime::spawn_blocking(move || unsafe {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        let now = crate::engine::now_ms();
        let mut doc = ownership::load();
        // ① 所有权档案为空 → 能力没被喂过事实，直接拒绝而不是伪装「没有应用数据遗留」
        if doc
            .get("owners")
            .and_then(Value::as_array)
            .map(|a| a.is_empty())
            .unwrap_or(true)
        {
            return (
                Vec::new(),
                "还没有卸载记录：应用数据遗留判定要靠「本机确实卸载过某程序」这条事实链，先卸载一次再来扫描".to_string(),
            );
        }
        // ② 复扫当前程序清单（获取失败必须拒扫，不能拿空清单把所有 pending 都升级成 historical）
        let mut current: Vec<Value> = Vec::new();
        for (hive, sub) in [
            (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ] {
            let rows = enum_uninstall_root(hive, sub);
            if rows.is_empty() && sub.contains("WOW6432Node") {
                continue; // 32 位视图在本机可能不存在，不算失败
            }
            if rows.is_empty() && sub.contains("Software\\Microsoft") && !sub.starts_with("SOFTWARE") {
                // HKCU 下没有用户级安装项是常见形态，同样不算取数失败
                continue;
            }
            current.extend(rows);
        }
        if current.is_empty() {
            return (Vec::new(), "当前程序清单获取失败，本次不做应用数据遗留判定（拿空清单去比对会把所有记录误判成已卸载）".to_string());
        }
        let ids: HashSet<String> = current
            .iter()
            .filter_map(|a| a.get("id").and_then(Value::as_str).map(String::from))
            .collect();
        // ③ pending → historical、过期回收、重装撤销（就地改档并落盘）
        let (promoted, removed) = ownership::rescan(&mut doc, &ids, now, &|p: &Path| p.exists());
        if promoted > 0 || removed > 0 {
            if let Err(e) = ownership::save(&doc) {
                crate::engine::log::write_log("warn", &format!("所有权历史写回失败: {e}"));
            }
        }
        // ④ 运行进程祖先链：取不到快照就不产出候选（这条是保护用户的判定，宁可不出）
        let Some(procs) = running_process_dirs() else {
            return (Vec::new(), "进程快照获取失败，本次不做应用数据遗留判定（无法确认候选目录是否正在被使用）".to_string());
        };
        // historical owner 的精确名 → owner 列表（同名多 owner 时用于「唯一归属」判定）
        let mut by_name: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();
        for o in ownership::historical_owners(&doc) {
            let mut keys: Vec<String> = Vec::new();
            if let Some(n) = o.get("displayName").and_then(Value::as_str) {
                let nn = norm_name(n);
                if nn.chars().count() >= NAME_MIN_EXACT {
                    keys.push(nn);
                }
            }
            if let Some(loc) = o.get("installLocation").and_then(Value::as_str) {
                if let Some(base) = loc.trim().trim_end_matches(['\\', '/']).rsplit('\\').next() {
                    let bn = norm_name(base);
                    if bn.chars().count() >= NAME_MIN_EXACT {
                        keys.push(bn);
                    }
                }
            }
            for k in keys {
                by_name.entry(k).or_default().push(o.clone());
            }
        }
        if by_name.is_empty() {
            return (Vec::new(), "还没有已确认卸载完成的程序（pending 尚未满足升级条件）".to_string());
        }

        let mut findings: Vec<Value> = Vec::new();
        for root in ORPHAN_SCAN_ROOTS {
            let Ok(base_raw) = std::env::var(root) else { continue };
            let Ok(rd) = std::fs::read_dir(&base_raw) else { continue };
            for ent in rd.flatten() {
                let dir = ent.path();
                if !dir.is_dir() {
                    continue;
                }
                let dname = norm_name(&ent.file_name().to_string_lossy());
                if dname.chars().count() < NAME_MIN_EXACT {
                    continue;
                }
                let Some(owners) = by_name.get(&dname) else { continue };
                // ⑤ 归属唯一：两个 historical owner 精确同名时无法判定这个目录归谁
                if owners.len() != 1 {
                    continue;
                }
                let owner = &owners[0];
                let owner_name = owner.get("displayName").and_then(Value::as_str).unwrap_or("").to_string();
                // ⑥ 原安装目录必须已不存在
                if let Some(loc) = owner.get("installLocation").and_then(Value::as_str) {
                    if !loc.trim().is_empty() && Path::new(loc.trim()).exists() {
                        continue;
                    }
                }
                let shown = dir.to_string_lossy().to_string();
                if protect::is_path_protected(&shown) || under_running_process(&dir, &procs) {
                    continue;
                }
                if let Some(reason) = crate::engine::native::dir_delete_blocked(&dir) {
                    crate::engine::log::write_log("info", &format!("应用数据遗留候选跳过 {shown}: {reason}"));
                    continue;
                }
                // ⑦ 默认只列可弃子目录，不端整个 profile
                let Ok(sub_rd) = std::fs::read_dir(&dir) else { continue };
                for sub in sub_rd.flatten() {
                    if !sub.path().is_dir() {
                        continue;
                    }
                    let sub_norm = norm_name(&sub.file_name().to_string_lossy());
                    if !ORPHAN_DISPOSABLE_SUBDIRS.contains(&sub_norm.as_str()) {
                        continue;
                    }
                    let sub_path = sub.path().to_string_lossy().to_string();
                    if protect::is_path_protected(&sub_path)
                        || under_running_process(&sub.path(), &procs)
                        || crate::engine::native::dir_delete_blocked(&sub.path()).is_some()
                    {
                        continue;
                    }
                    let why = contribs(&[
                        ("ownerUninstalled", format!(
                            "卸载记录「{owner_name}」已复扫确认：程序不在当前清单，且原安装目录已不存在",
                        )),
                        ("disposableSubdir", format!(
                            "子目录「{sub_norm}」属于可弃类别（cache / logs 一类），不是用户资料",
                        )),
                        ("envGates", "已通过保护路径、目录重解析点、运行进程同链三道环境闸".to_string()),
                    ]);
                    findings.push(json!({
                        "kind": "folder",
                        "target": sub_path,
                        "reason": format!("「{owner_name}」已确认卸载完成，其遗留可弃目录（所有权判定，不自动勾选）"),
                        "confidence": "medium",
                        "risk": "medium",
                        "defaultChecked": false,
                        "origin": "orphan",
                        "ownerName": owner_name,
                        // 忽略操作要按 owner 的卸载键寻址，前端从这字段取
                        "ownerAppId": owner.get("appId").and_then(Value::as_str).unwrap_or(""),
                        // C4：所有权链的证据是「一条闭合推理」，不写出来用户只能选择信或不信。
                        "contribs": why,
                    }));
                    if findings.len() >= ORPHAN_MAX_CANDIDATES {
                        break;
                    }
                }
            }
        }
        // ⑥ 厂商配置键足迹差分（HiBit §9.1 的落地形态）：卸载前基线里没有、现在出现、
        //    且键名对得上这个程序 token 的顶层键。三条同时成立才入候选——差集给**时序**证据，
        //    token 给**归属**证据；只靠名字猜会把仍在装的别家程序键端出来（本机 `Netease` 段实测）。
        //    这一类不成立时只跳过、不报错：目录候选已经产出，而收口前建的档案本来就没有基线字段。
        let vendor_now = collect_vendor_keys();
        let mut vendor_added = 0usize;
        if vendor_now.is_empty() {
            crate::engine::log::write_log(
                "warn",
                "厂商键足迹差分跳过：三个 Software 根都枚举不到（拿空清单差分等于凭空造候选）",
            );
        } else {
            for o in ownership::historical_owners(&doc) {
                let Some(base) = footprint::baseline_of(&o) else { continue };
                let tokens = footprint::tokens_of(&o);
                if tokens.is_empty() {
                    continue;
                }
                let owner_name = o.get("displayName").and_then(Value::as_str).unwrap_or("").to_string();
                let owner_app_id = o.get("appId").and_then(Value::as_str).unwrap_or("").to_string();
                for target in footprint::new_keys_since(&base, &vendor_now) {
                    if !footprint::key_belongs_to(&target, &tokens) {
                        continue;
                    }
                    if findings.len() >= ORPHAN_MAX_CANDIDATES || vendor_added >= footprint::MAX_CANDIDATES {
                        break;
                    }
                    // 与规则库链同一道硬闸：落在注册表禁删面的目标连原因都不给过（A1）
                    if let Some(reason) = protect::reg_target_block_reason(&target) {
                        crate::engine::log::write_log(
                            "warn",
                            &format!("厂商键足迹候选被硬否决（不入候选）: {target} — {reason}"),
                        );
                        continue;
                    }
                    let Some((hive, rest)) = parse_reg_target(&target) else { continue };
                    if !crate::engine::native::reg_key_exists(hive, &rest) {
                        continue; // 差分到候选之间键消失了：不列一条已经不存在的东西
                    }
                    vendor_added += 1;
                    let why = contribs(&[
                        (
                            "footprintBaseline",
                            format!("卸载动作发生前记下的 {} 个厂商顶层键里没有它", base.len()),
                        ),
                        (
                            "appearedAfterUninstall",
                            "本次复扫它仍存在，而该程序的卸载登记与原安装目录都已消失".to_string(),
                        ),
                        (
                            "ownerToken",
                            format!("键名与这程序的显示名/发行商/安装目录名互含：{}", tokens.join("、")),
                        ),
                    ]);
                    findings.push(json!({
                        "kind": "reg_key",
                        "target": target,
                        "reason": format!("「{owner_name}」卸载后新出现的厂商配置键（卸载前基线里没有，不自动勾选）"),
                        "confidence": "medium",
                        "risk": "medium",
                        "defaultChecked": false,
                        "origin": "orphan",
                        "ownerName": owner_name,
                        "ownerAppId": owner_app_id,
                        "contribs": why,
                    }));
                }
            }
        }
        (findings, String::new())
    })
    .await;
    match res {
        Ok((findings, note)) => {
            if !note.is_empty() {
                return json!({ "success": false, "message": note });
            }
            // 落进与本会话残留扫描同一个快照槽：执行侧的快照闸、A1 硬否决、
            // 目录重解析校验、回收站优先一律复用，不给应用数据遗留候选开第二条删除通道
            residue_snapshot_put(&label, "orphan", findings.clone());
            json!({ "success": true, "data": { "appName": "卸载遗留（应用数据与厂商配置键）", "findings": findings } })
        }
        Err(e) => json!({ "success": false, "message": format!("应用数据遗留扫描异常: {e}") }),
    }
}

/// uninstall:orphan-ignore — 用户判定某个历史 owner 不再提示（主窗档）
#[tauri::command]
pub async fn uninstall_orphan_ignore<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    app_id: String,
    display_name: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let Some((hive_str, key_path)) = app_id.split_once('|') else {
        return json!({ "success": false, "message": "app_id 格式错误" });
    };
    if !(hive_str.eq_ignore_ascii_case("HKCU") || hive_str.eq_ignore_ascii_case("HKLM")) {
        return json!({ "success": false, "message": "app_id hive 只支持 HKCU/HKLM" });
    }
    if !valid_uninstall_key_path(key_path) {
        return json!({ "success": false, "message": "app_id 不是合法的卸载键路径" });
    }
    let mut doc = ownership::load();
    ownership::ignore(&mut doc, &app_id, &display_name, crate::engine::now_ms(), |s| norm_name(s));
    match ownership::save(&doc) {
        Ok(()) => {
            log::write_log("info", &format!("应用数据遗留判定已忽略历史 owner: {display_name}（{app_id}）"));
            json!({ "success": true, "data": { "message": format!("已不再提示「{display_name}」的遗留数据") } })
        }
        Err(e) => json!({ "success": false, "message": format!("忽略记录写入失败: {e}") }),
    }
}

// ==================== 失效残留扫描（M6，用户拍板 2026-09-28） ====================
//
// 与 M4 的所有权链分工不同，两条链共用一个「残留扫描」面板但证据来源不同：
// - 程序残留（规则库）：知道是哪个程序，按签名规则找它的痕；
// - 失效残留（本模块）：不要求本机有卸载记录，判据只有一条 ——
//   注册表里记着的落点文件已经不存在**（程序不在了、键还留着指着一个不存在的东西）。
// - 应用数据遗留（所有权链）：仍然要「本机确实卸载过它」这条事实，
//   因为同名目录匹配本身不是证据；档案取不到时这一组自己说明取不到，
//   不再让整次扫描失败（那是把一条链的缺证据当成三条链的结论）。
//
// 三条硬约束（不随需求变）：
// 1. 一律 `defaultChecked: false`、置信度封顶 medium —— 落点缺失也可能是
//    移动盘/网络盘没插、程序被手工搬过位置，这些只有用户知道；
// 2. 候选必须过既有 `classify_residue_op`（快照闸 + A1 禁删面 + 先 export 备份 + 封条）。
//    **服务与设备两类已按用户裁定 2026-09-28 摘掉**：判据虽然也成立（二进制文件已丢失 /
//    设备当前不在场），但删除要提权走 SCM 与 SetupAPI，我们没有这块的实操经验，
//    误删一个服务或设备实例的代价远高于"多列出两类候选"的收益。要做也得先有
//    真机样本与回滚路径，不要在这里留半条通道。
// 3. 「沉睡多久」只展示不参与判定：键的 LastWriteTime 读不到就留空，
//    拿 0 当"很久没动过"会把读不到伪装成有把握。

/// 快照槽按 origin 分桶替换。
///
/// 为什么不能整槽覆盖：面板现在同时展示多组候选，先扫的那组会在后一次扫描后被
/// 快照闸判成「不在本次扫描快照中」，用户看到的勾选项点下去就报错。
/// M4 的应用数据遗留链其实已经有这个坑（它覆盖掉单程序残留的快照），一并收口。
fn residue_snapshot_put(label: &str, origin: &str, findings: Vec<Value>) {
    const SNAPSHOT_CAP: usize = 400;
    let mut store = residue_snapshots().lock().unwrap_or_else(|e| e.into_inner());
    let mut merged: Vec<Value> = store
        .get(label)
        .map(|(_, f)| {
            f.iter()
                .filter(|x| x.get("origin").and_then(Value::as_str) != Some(origin))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    merged.extend(findings);
    if merged.len() > SNAPSHOT_CAP {
        merged.truncate(SNAPSHOT_CAP);
    }
    store.insert(label.to_string(), (crate::engine::now_ms(), merged));
}

/// `%VAR%` 展开。**任一变量取不到就返回 None**：把没展开的串继续往下判，等于
/// 拿一个本机根本不存在的路径去判"落点已消失"，那是自己造出来的假阳性。
fn expand_pct(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        match tail.find('%') {
            Some(j) => {
                let name = &tail[..j];
                if name.is_empty() {
                    out.push('%');
                } else {
                    out.push_str(&std::env::var(name).ok()?);
                }
                rest = &tail[j + 1..];
            }
            None => {
                out.push('%');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    Some(out)
}

/// 从 `UninstallString` / 服务 `ImagePath` / App Paths 默认值里取出「它记着哪个文件」。
///
/// `None` = 判不出来（相对名、无扩展名、`Device\` 形态、变量展开不了），
/// 调用方必须把 None 当**无证据**而不是"不存在"。
/// 截参数的口径：带引号取引号内；不带引号就在第一个 `.exe/.dll/.sys` 之后切断
/// （注册表里没引号的路径只能靠扩展名边界分参数），且结果必须以这三种扩展名结尾。
fn dead_landing(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let s = s.strip_prefix(r"\??\").unwrap_or(s);
    // `\SystemRoot\system32\...` 是服务表里的常见写法（不是 %SystemRoot%）
    let rewritten;
    let s = if s
        .get(..11)
        .map(|p| p.eq_ignore_ascii_case(r"\SystemRoot"))
        .unwrap_or(false)
    {
        rewritten = format!("{}{}", std::env::var("SystemRoot").ok()?, &s[11..]);
        rewritten.as_str()
    } else {
        s
    };
    let expanded = expand_pct(s)?;
    let head = match expanded.strip_prefix('"') {
        Some(q) => q.split('"').next().unwrap_or("").to_string(),
        None => {
            let low = expanded.to_lowercase();
            let cut = [".exe", ".dll", ".sys"]
                .iter()
                .filter_map(|e| low.find(e).map(|i| i + e.len()))
                .min();
            match cut {
                Some(end) => expanded.chars().take(end).collect(),
                None => expanded.clone(),
            }
        }
    };
    let head = head.trim().to_string();
    if head.is_empty() {
        return None;
    }
    let b = head.as_bytes();
    let is_abs = (b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\')
        || head.starts_with(r"\\");
    if !is_abs {
        return None;
    }
    let low = head.to_lowercase();
    if !(low.ends_with(".exe") || low.ends_with(".dll") || low.ends_with(".sys")) {
        return None;
    }
    Some(head)
}

/// 落点集合是否「全部缺失」。空集合返回 false —— 没有落点就没有证据，不产候选。
fn landings_all_missing(lands: &[String], exists: &dyn Fn(&str) -> bool) -> bool {
    !lands.is_empty() && lands.iter().all(|p| !exists(p))
}

/// MSI 产品码形态的键名（`{GUID}`）：它的 `InstallLocation` 经常是空或错的，
/// 单靠一条落点判"程序已不在"不够，要求至少两条落点全部缺失。
fn is_msi_product_code(key_tail: &str) -> bool {
    let t = key_tail.trim_matches('{').trim_matches('}');
    t.len() == 36
        && t.matches('-').count() == 4
        && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// 卸载键候选（纯函数，单测注入存在性判定）
fn dead_uninstall_findings(
    raws: &[DeadUninstallRaw],
    exists: &dyn Fn(&str) -> bool,
    now: i64,
) -> Vec<Value> {
    let mut out = Vec::new();
    for r in raws {
        if r.name.trim().is_empty() {
            continue; // 没有显示名的条目用户无法判断是什么，不产候选
        }
        let mut lands: Vec<String> = Vec::new();
        let loc = r.install.trim().trim_end_matches(['\\', '/']);
        if !loc.is_empty() {
            lands.push(loc.to_string());
        }
        for raw in [&r.uninstall, &r.quiet] {
            if let Some(p) = dead_landing(raw) {
                if !lands.iter().any(|x| x.eq_ignore_ascii_case(&p)) {
                    lands.push(p);
                }
            }
        }
        let needed = if is_msi_product_code(&r.key) { 2 } else { 1 };
        if lands.len() < needed || !landings_all_missing(&lands, exists) {
            continue;
        }
        let dormant = dormant_delta(r.last_write_ms, now);
        // C4：证据一条条列出来。落点是这条判定的全部依据，只给一句「落点已全部不存在」
        // 用户既不知道查了哪几个路径，也无从发现「InstallLocation 本来就写错了」。
        let mut why: Vec<(&str, String)> =
            vec![("entry", format!("卸载登记仍在 {}\\{}", r.hive, r.path))];
        for p in &lands {
            why.push(("landingMissing", format!("落点已不存在：{p}")));
        }
        if needed > 1 {
            why.push((
                "msiRule",
                "MSI 产品码键：要求两条及以上落点全部缺失才入候选".to_string(),
            ));
        }
        match dormant.as_i64() {
            Some(ms) => why.push((
                "dormant",
                format!("键最后写入距今 {} 天（沉睡只展示，不参与判定）", ms / 86_400_000),
            )),
            None => why.push((
                "dormantUnknown",
                "读不到键最后写入时间，因此不显示沉睡时长".to_string(),
            )),
        }
        out.push(json!({
            "kind": "reg_key",
            "target": format!("{}\\{}", r.hive, r.path),
            "reason": format!("卸载项「{}」记着的落点已全部不存在（{}）", r.name, lands.join("；")),
            "confidence": if lands.len() >= 2 { "medium" } else { "low" },
            "risk": "medium",
            "defaultChecked": false,
            "origin": "dead",
            "deadClass": "uninstall",
            "deleteCapable": true,
            "testedPaths": lands,
            "contribs": contribs(&why),
            "dormantMs": dormant,
        }));
    }
    out
}

/// App Paths 候选：默认值指向的文件已不存在 → 该 `App Paths\<x.exe>` 子键是失效登记
fn dead_app_paths_findings(
    raws: &[DeadAppPathRaw],
    exists: &dyn Fn(&str) -> bool,
    now: i64,
) -> Vec<Value> {
    let mut out = Vec::new();
    for r in raws {
        let Some(p) = dead_landing(&r.value) else { continue };
        if exists(&p) {
            continue;
        }
        let dormant = dormant_delta(r.last_write_ms, now);
        let mut why: Vec<(&str, String)> = vec![
            ("entry", format!("App Paths 登记仍在 {}\\{}", r.hive, r.path)),
            ("targetMissing", format!("默认值指向的文件已不存在：{p}")),
        ];
        match dormant.as_i64() {
            Some(ms) => why.push((
                "dormant",
                format!("键最后写入距今 {} 天（沉睡只展示，不参与判定）", ms / 86_400_000),
            )),
            None => why.push((
                "dormantUnknown",
                "读不到键最后写入时间，因此不显示沉睡时长".to_string(),
            )),
        }
        out.push(json!({
            "kind": "reg_key",
            "target": format!("{}\\{}", r.hive, r.path),
            "reason": format!("App Paths「{}」指向 {}，该文件已不存在", r.key, p),
            "confidence": "low",
            "risk": "low",
            "defaultChecked": false,
            "origin": "dead",
            "deadClass": "appPaths",
            "deleteCapable": true,
            "testedPaths": [p],
            "contribs": contribs(&why),
            "dormantMs": dormant,
        }));
    }
    out
}
/// 沉睡时长（毫秒差）。读不到写入时间就返回 `None`，前端显示「未知」而不是"很久"。
fn dormant_delta(last_write_ms: Option<i64>, now: i64) -> Value {
    match last_write_ms {
        Some(t) if t > 0 && now > t => json!(now - t),
        _ => Value::Null,
    }
}

const DEAD_REG_CAP: usize = 120;

/// 卸载键原始行（枚举与判定分开，判定是纯函数）
struct DeadUninstallRaw {
    hive: String,
    key: String,
    path: String,
    name: String,
    install: String,
    uninstall: String,
    quiet: String,
    last_write_ms: Option<i64>,
}

struct DeadAppPathRaw {
    hive: String,
    key: String,
    path: String,
    value: String,
    last_write_ms: Option<i64>,
}

fn hive_of(label: &str) -> windows::Win32::System::Registry::HKEY {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    if label == "HKCU" {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    }
}

/// 采集三根下的卸载键原始字段（只读，不判定）
/// 三个根下的厂商顶层键（完整目标串，与执行侧 `HKCU\<子路径>` 的口径一致）。
///
/// 返回空 = 连根都枚举不到，调用方必须当成"读不到"而不是"这台机器没有厂商键"：
/// 拿空清单去做差分，会把所有现存键算成"卸载后才出现的新键"，那是凭空造出一批删除候选。
unsafe fn collect_vendor_keys() -> Vec<String> {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let mut out = Vec::new();
    for (label, hive, sub) in [
        ("HKCU", HKEY_CURRENT_USER, r"Software"),
        ("HKLM", HKEY_LOCAL_MACHINE, r"SOFTWARE"),
        ("HKLM", HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node"),
    ] {
        for name in reg_enum_subkeys(hive, sub, footprint::MAX_KEYS_PER_OWNER) {
            if !footprint::is_vendor_key(&name) {
                continue;
            }
            out.push(format!("{label}\\{sub}\\{name}"));
        }
    }
    out
}

unsafe fn collect_dead_uninstall_raws() -> Vec<DeadUninstallRaw> {
    const ROOTS: &[(&str, &str)] = &[
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ];
    let mut out = Vec::new();
    for (hive_label, root) in ROOTS {
        let hive = hive_of(hive_label);
        for sub in crate::engine::native::reg_enum_subkeys_pub(hive, root) {
            let path = format!("{root}\\{sub}");
            let rd = |v: &str| {
                crate::engine::native::read_reg_value_text(hive, &path, v)
                    .map(|(_, s)| s)
                    .unwrap_or_default()
            };
            let name = rd("DisplayName");
            let install = rd("InstallLocation");
            let uninstall = rd("UninstallString");
            let quiet = rd("QuietUninstallString");
            if name.is_empty() && install.is_empty() && uninstall.is_empty() {
                continue;
            }
            let last_write_ms = crate::engine::native::reg_key_last_write_ms(hive, &path);
            out.push(DeadUninstallRaw {
                hive: hive_label.to_string(),
                key: sub,
                path,
                name,
                install,
                uninstall,
                quiet,
                last_write_ms,
            });
        }
    }
    out
}

/// 采集 App Paths 默认值
unsafe fn collect_dead_app_path_raws() -> Vec<DeadAppPathRaw> {
    const ROOTS: &[(&str, &str)] = &[
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\App Paths"),
    ];
    let mut out = Vec::new();
    for (hive_label, root) in ROOTS {
        let hive = hive_of(hive_label);
        for sub in crate::engine::native::reg_enum_subkeys_pub(hive, root) {
            let path = format!("{root}\\{sub}");
            let value = crate::engine::native::read_reg_value_text(hive, &path, "")
                .map(|(_, s)| s)
                .unwrap_or_default();
            if value.trim().is_empty() {
                continue;
            }
            let last_write_ms = crate::engine::native::reg_key_last_write_ms(hive, &path);
            out.push(DeadAppPathRaw {
                hive: hive_label.to_string(),
                key: sub,
                path,
                value,
                last_write_ms,
            });
        }
    }
    out
}

/// uninstall:dead-scan — 失效残留扫描（主窗档；不依赖卸载事实，只产候选）
#[tauri::command]
pub async fn uninstall_dead_scan<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let res = tauri::async_runtime::spawn_blocking(move || unsafe {
        let now = crate::engine::now_ms();
        let exists = |p: &str| std::path::Path::new(p).exists();
        let mut notes: Vec<String> = Vec::new();

        let u_raws = collect_dead_uninstall_raws();
        let mut u = dead_uninstall_findings(&u_raws, &exists, now);
        if u_raws.is_empty() {
            notes.push("卸载项清单读取失败（注册表三根都打不开），本组结果不完整".to_string());
        }
        u.sort_by(|a, b| b["dormantMs"].as_i64().cmp(&a["dormantMs"].as_i64()));
        u.truncate(DEAD_REG_CAP);

        let a_raws = collect_dead_app_path_raws();
        let mut ap = dead_app_paths_findings(&a_raws, &exists, now);
        ap.sort_by(|a, b| b["dormantMs"].as_i64().cmp(&a["dormantMs"].as_i64()));
        ap.truncate(DEAD_REG_CAP);

        if a_raws.is_empty() {
            notes.push("App Paths 清单读取失败（三根都打不开或一条都没有），本组结果不完整".to_string());
        }
        // 采集计数单独回传：候选为 0 在干净机器上是合法结果，但「扫过多少条」为 0 一定是
        // 枚举链断了。真机用例靠这两个数判"扫过但确实没有"还是"根本没扫"。
        let scanned = json!({ "uninstallKeys": u_raws.len(), "appPathsKeys": a_raws.len() });
        let findings = u.into_iter().chain(ap).collect::<Vec<_>>();
        (findings, notes, scanned)
    })
    .await;
    match res {
        Ok((findings, notes, scanned)) => {
            residue_snapshot_put(&label, "dead", findings.clone());
            json!({ "success": true, "data": {
                "appName": "失效残留",
                "findings": findings,
                "notes": notes,
                "scanned": scanned,
            }})
        }
        Err(e) => json!({ "success": false, "message": format!("失效残留扫描异常: {e}") }),
    }
}

/// 卸载域·残留扫描（方案 M3 MVP + U-2 固定系统侧痕）。
/// 来源与置信度：卸载键仍在=high（reg_key）；InstallLocation 仍在=high（folder）；
/// 名称启发式=low（folder，默认不勾）；开始菜单快捷方式=medium（默认勾）；
/// 固定系统侧痕（U-2）=medium 全默认不勾（拍板口径 2026-09-28：侧痕删除无原厂依据，
/// 只作候选交用户逐项决定）。签名残留规则库按方案后置接入（U-1）。
#[tauri::command]
pub async fn uninstall_residue_scan<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    app_id: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let Some((hive_str, key_path)) = app_id.split_once('|') else {
        return json!({ "success": false, "message": "app_id 格式错误" });
    };
    // U-4（拍板 2026-09-28）：Appx 也参与残留扫描（Packages 应用数据遗留数据），先用包全名闸
    if hive_str.eq_ignore_ascii_case("APPX") {
        if !valid_appx_fullname(key_path) {
            return json!({ "success": false, "message": "app_id 不是合法的包全名" });
        }
    } else if !valid_uninstall_key_path(key_path) {
        return json!({ "success": false, "message": "app_id 不是合法的卸载键路径" });
    }
    let hive_str = hive_str.to_string();
    let key_path = key_path.to_string();
    let findings = tauri::async_runtime::spawn_blocking(move || unsafe {
        use windows::Win32::System::Registry::{RegOpenKeyExW, RegCloseKey, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
        // U-4（拍板 2026-09-28）：Appx 残留口径=Remove-AppxPackage 后
        // %LOCALAPPDATA%\Packages\<PFN> 的应用数据遗留应用数据。此前「不参与残留扫描」，
        // 小旭拍板并入：目录存在才入候选，进回收站（可还原），先过 is_path_protected。
        if hive_str.eq_ignore_ascii_case("APPX") {
            let Some(pfn) = package_family_name(&key_path) else {
                return (Vec::new(), "Windows 应用".to_string());
            };
            let base = std::env::var("LOCALAPPDATA").unwrap_or_default();
            if base.is_empty() {
                return (Vec::new(), "Windows 应用".to_string());
            }
            let dir = PathBuf::from(&base).join("Packages").join(&pfn);
            let mut findings: Vec<Value> = Vec::new();
            if dir.is_dir() && !protect::is_path_protected(&dir.to_string_lossy()) {
                findings.push(json!({
                    "kind": "folder", "target": dir.to_string_lossy(),
                    "reason": "Windows 应用已移除，其 %LOCALAPPDATA%\\Packages\\<包名> 应用数据成为应用数据遗留（进回收站，可还原）",
                    "confidence": "high", "risk": "low", "defaultChecked": true,
                    "contribs": contribs(&[
                        ("appxRemoved", format!("包 {pfn} 已从当前用户移除（清单里查不到）")),
                        ("pkgDataDir", format!("遗留位置由包名唯一确定：{}", dir.to_string_lossy())),
                    ]),
                }));
            }
            return (findings, pfn);
        }
        let (hive, full_target) = if hive_str.eq_ignore_ascii_case("HKCU") {
            (HKEY_CURRENT_USER, format!("HKCU\\{key_path}"))
        } else if hive_str.eq_ignore_ascii_case("HKLM") {
            (HKEY_LOCAL_MACHINE, format!("HKLM\\{key_path}"))
        } else {
            return (Vec::new(), String::new());
        };
        let sk = to_wide(&key_path);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(hive, windows::core::PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut hk).is_err() {
            return (Vec::new(), String::new());
        }
        let display_name = reg_sz(hk, "DisplayName").unwrap_or_default();
        let publisher = reg_sz(hk, "Publisher").unwrap_or_default();
        let install_location = reg_sz(hk, "InstallLocation").unwrap_or_default();
        let display_icon_src = reg_sz(hk, "DisplayIcon").unwrap_or_default();
        let uninstall_string = reg_sz(hk, "UninstallString").unwrap_or_default();
        let _ = RegCloseKey(hk);

        let mut findings: Vec<Value> = Vec::new();
        // 高置信：卸载键仍在（原厂卸载未完成/已取消的直接证据）
        if crate::engine::native::reg_key_exists(hive, &key_path) {
            let why = contribs(&[
                ("uninstallKeyAlive", format!("本次卸载后复查：{full_target} 仍能打开")),
            ]);
            findings.push(json!({
                "kind": "reg_key", "target": full_target,
                "reason": "卸载注册表项仍存在（原厂卸载可能未完成或已取消）",
                "confidence": "high", "risk": "medium", "defaultChecked": true,
                "contribs": why,
            }));
        }
        // 高置信：安装目录仍在
        let loc = install_location.trim().trim_end_matches('\\').to_string();
        if !loc.is_empty()
            && Path::new(&loc).is_dir()
            && !protect::is_path_protected(&loc)
        {
            let why = contribs(&[("installLocationAlive", format!("厂商写的安装目录仍在磁盘上：{loc}"))]);
            findings.push(json!({
                "kind": "folder", "target": loc,
                "reason": "InstallLocation 指向的安装目录仍存在",
                "confidence": "high", "risk": "medium", "defaultChecked": true,
                "contribs": why,
            }));
        }
        // 低置信：名称启发式（默认不勾，交用户判断）
        for p in heuristic_dir_hits(&display_name) {
            if protect::is_path_protected(&p) {
                continue;
            }
            let why = contribs(&[(
                "nameHeuristic",
                format!("目录名与「{display_name}」互含且长度达阈值（阈值 {NAME_MIN_SIMILAR} 字）"),
            )]);
            findings.push(json!({
                "kind": "folder", "target": p,
                "reason": format!("目录名与「{display_name}」高度相似（启发式，请人工确认后再删）"),
                "confidence": "low", "risk": "high", "defaultChecked": false,
                "contribs": why,
            }));
        }
        // 高置信补充：卸载器/图标指向的目录仍存在（InstallLocation 缺失时的主线索）
        for (from_value, src) in [("UninstallString", &uninstall_string), ("DisplayIcon", &display_icon_src)] {
            if src.trim().is_empty() {
                continue;
            }
            if let Some((exe, _)) = split_uninstall_cmd(src) {
                if let Some(parent) = Path::new(&exe).parent() {
                    let pd = parent.to_path_buf();
                    if pd.as_os_str().is_empty()
                        || !pd.is_dir()
                        || protect::is_path_protected(&pd.to_string_lossy())
                        || findings.iter().any(|f| {
                            f["kind"] == "folder"
                                && f["target"].as_str().map(|s| s.eq_ignore_ascii_case(&pd.to_string_lossy())).unwrap_or(false)
                        })
                    {
                        continue;
                    }
                    let why = contribs(&[(
                        "exeParent",
                        format!("{from_value} 指向的 exe 落在这家目录里：{}", pd.to_string_lossy()),
                    )]);
                    findings.push(json!({
                        "kind": "folder", "target": pd.to_string_lossy(),
                        "reason": "卸载器/图标指向的程序目录仍存在",
                        "confidence": "high", "risk": "medium", "defaultChecked": true,
                        "contribs": why,
                    }));
                }
            }
        }
        // 中置信：开始菜单快捷方式（文件名含程序名；删 .lnk 无害，默认勾选）
        // C3 同名多候选降级：同名快捷方式出现在多个父目录时无法判定哪条属于本程序，
        // 整组降 low 且不默认勾选（目录类启发式本来就是 low，不受这条影响）
        let shortcuts = start_menu_shortcut_hits(&display_name);
        let shortcut_ambiguous = name_is_ambiguous(&shortcuts);
        // C4：歧义降级要能把「到底是哪几个父目录各有同名快捷方式」指出来，否则用户只看到
        // 一句"出现在多个目录"，仍然不知道该信哪条。
        let shortcut_parents = {
            let mut v: Vec<String> = shortcuts
                .iter()
                .filter_map(|s| Path::new(s).parent().map(|p| p.to_string_lossy().to_string()))
                .collect();
            v.sort();
            v.dedup();
            v
        };
        for lnk in shortcuts {
            let mut items: Vec<(&str, String)> = vec![(
                "shortcutNameMatch",
                format!("快捷方式文件名与「{display_name}」同名（阈值 {NAME_MIN_SHORTCUT} 字）"),
            )];
            if shortcut_ambiguous {
                items.push((
                    "ambiguousParents",
                    format!("同名快捷方式分布在多个父目录，无法指认哪条属于本程序：{}", shortcut_parents.join("；")),
                ));
            }
            findings.push(json!({
                "kind": "shortcut", "target": lnk,
                "reason": format!("开始菜单快捷方式与「{display_name}」同名{}",
                    if shortcut_ambiguous { "（同名快捷方式出现在多个目录，请人工确认后再删）" } else { "" }),
                "confidence": if shortcut_ambiguous { "low" } else { "medium" },
                "risk": "low",
                "defaultChecked": !shortcut_ambiguous,
                "contribs": contribs(&items),
            }));
        }
        // 中置信（默认不勾）：固定系统侧痕反查（U-2）。按系统对象里记录的程序路径反查，
        // 不按程序名猜——已知线索只有卸载键推出的 exe 路径与安装目录。
        let (prog_exes, prog_dir) = collect_program_objects(&loc, &uninstall_string, &display_icon_src);
        let dir_lc = prog_dir
            .as_ref()
            .map(|d| d.trim_end_matches('\\').to_ascii_lowercase())
            .unwrap_or_default();
        let exes_lc: Vec<String> = prog_exes
            .iter()
            .map(|e| e.trim_end_matches('\\').to_ascii_lowercase())
            .collect();
        if !exes_lc.is_empty() || !dir_lc.is_empty() {
            // C4：侧痕反查的线索来源（安装目录 / exe 路径）比"命中了某个系统登记"更有用——
            // 用户要判断的是这条线索是不是这个程序留下的。
            let mut trace_src: Vec<(&str, String)> = Vec::new();
            if !dir_lc.is_empty() {
                trace_src.push(("traceByInstallDir", format!("按安装目录反查系统登记：{dir_lc}")));
            }
            if !exes_lc.is_empty() {
                trace_src.push((
                    "traceByExe",
                    format!("按 {} 条已知 exe 路径反查（取自卸载器/图标）", exes_lc.len()),
                ));
            }
            // 外层闭包整体处于 unsafe 块内，直接调用即可（内层再包 unsafe 会告警冗余）
            for target in muicache_hits(&exes_lc, &dir_lc, SIDE_TRACE_CAP) {
                let mut items = trace_src.clone();
                items.push(("muicacheHit", "MuiCache 里缓存了这个程序路径的友好名称".to_string()));
                findings.push(json!({
                    "kind": "reg_value", "target": target,
                    "reason": "MuiCache 残留值（系统缓存了此程序路径的友好名称）",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                    "contribs": contribs(&items),
                }));
            }
            for target in firewall_hits(&exes_lc, &dir_lc, SIDE_TRACE_CAP) {
                let mut items = trace_src.clone();
                items.push(("firewallHit", "防火墙规则里记着这个程序路径，规则已随程序失效".to_string()));
                findings.push(json!({
                    "kind": "reg_value", "target": target,
                    "reason": "防火墙规则引用此程序路径（程序已卸载，规则已失效）",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                    "contribs": contribs(&items),
                }));
            }
            for target in bam_hits(&exes_lc, &dir_lc, SIDE_TRACE_CAP) {
                let mut items = trace_src.clone();
                items.push(("bamHit", "BAM 后台执行管理里留着这个程序路径的执行记录".to_string()));
                findings.push(json!({
                    "kind": "reg_value", "target": target,
                    "reason": "BAM 后台执行记录引用此程序路径",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                    "contribs": contribs(&items),
                }));
            }
            for target in tracing_hits(&exes_lc, SIDE_TRACE_CAP) {
                let mut items = trace_src.clone();
                items.push(("tracingHit", "诊断跟踪子键以此程序的 exe 文件名命名".to_string()));
                findings.push(json!({
                    "kind": "reg_key", "target": target,
                    "reason": "Tracing 诊断跟踪项以此程序的 exe 命名",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                    "contribs": contribs(&items),
                }));
            }
            for target in jumplist_hits(&exes_lc, &dir_lc, SIDE_TRACE_CAP) {
                let mut items = trace_src.clone();
                items.push(("jumplistHit", "JumpList 自动目标缓存里留着这个程序的 exe 条目".to_string()));
                findings.push(json!({
                    "kind": "file", "target": target,
                    "reason": "JumpList 自动目标缓存引用此程序路径",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                    "contribs": contribs(&items),
                }));
            }
        }
        // 高置信：签名残留规则库命中（U-1）——已知程序知识库，双条件命中 +
        // 目标存在性判定后才出现；reg_key 删除走执行侧同款「先备份后删」
        if let Some(rules) = load_residue_rules() {
            let (rule_hits, vetoed) = residue_rules_hits(&rules, &display_name, &publisher, &key_path, false);
            findings.extend(rule_hits);
            // 硬否决在命令边界留痕：真机跑到这一行就说明签名规则库里躺着一处系统容器
            // （误签、私钥泄露或规则生成漏检），属异常而非常态，必须能在日志里查到。
            for line in vetoed {
                log::write_log("warn", &line);
            }
        }
        // 第二层：本机学习库（HiBit §H3）。同一套命中判定 + 同一个语义校验器，差别只在
        // 证据等级（不签名 ⇒ medium + 不自动勾选）。**签名库命中的同一目标不再出第二次**——
        // 重复行会把用户推向「勾两次才删得掉」的错觉，而面板里没有去重就等于两条独立证据。
        if let Some(learned_doc) = learned::load() {
            let (hits, vetoed) =
                residue_rules_hits(&learned_doc, &display_name, &publisher, &key_path, true);
            for line in vetoed {
                log::write_log("warn", &line);
            }
            for h in hits {
                let k = h["kind"].as_str().unwrap_or("").to_lowercase();
                let t = h["target"].as_str().unwrap_or("").to_lowercase();
                let dup = findings.iter().any(|f| {
                    f["kind"].as_str().unwrap_or("").to_lowercase() == k
                        && f["target"].as_str().unwrap_or("").to_lowercase() == t
                });
                if !dup {
                    findings.push(h);
                }
            }
        }
        (findings, display_name)
    })
    .await
    .unwrap_or((Vec::new(), String::new()));

    // 快照落槽：执行只认这份集合
    let (finding_list, app_name) = findings;
    let label = window.label().to_string();
    residue_snapshot_put(&label, "app", finding_list.clone());
    json!({ "success": true, "data": { "appName": app_name, "findings": finding_list } })
}

// ==================== uninstall:residue-execute ====================

/// 残留执行结果明细行
fn detail(kind: &str, target: &str, status: &str, message: &str) -> Value {
    json!({ "kind": kind, "target": target, "status": status, "message": message })
}

/// HiBit §H3 的回写侧：把这一轮用户**实际删掉**的落点沉淀进本机学习库。
///
/// 只学 status=="ok" 的行 —— 失败行学进去会让下一轮把「这台机器上删不掉的路径」
/// 当成已知残留反复推荐。归属身份（displayName / publisher / 卸载键末段）一律
/// **现读注册表**，不从渲染层回传：与 `uninstall_run` 同一条纪律（app_id 只当寻址键）。
/// 学不到（合成 MACHINE id、APPX 包、键已不存在、没有一条落点过得了归属判定）就整条不写，
/// 而不是写一份"大概是这样"的记录 —— 学习库是下一轮的删除建议来源。
fn learn_from_deletions(app_id: &str, details: &[Value]) -> usize {
    let Some((hive_str, key_path)) = app_id.split_once('|') else {
        return 0; // APPX|… 与 MACHINE|all 都没有卸载键身份，学不了
    };
    let reg_full = format!("{hive_str}\\{key_path}");
    let Some((hive, rest)) = parse_reg_target(&reg_full) else {
        return 0;
    };
    let read_sz = |name: &str| -> String {
        crate::engine::native::read_reg_value_text(hive, rest.as_str(), name)
            .map(|(_, v)| v)
            .unwrap_or_default()
    };
    let display_name = read_sz("DisplayName");
    let publisher = read_sz("Publisher");
    if display_name.trim().is_empty() {
        return 0; // 没有程序名就当双条件组的另一半也凑不齐，校验器会整包拒
    }
    // kind 口径对齐：执行明细里的目录行写作 `dir`（原生删除侧的回执），学习库 schema 要 `folder`
    let mut entries: Vec<(&str, String)> = Vec::new();
    for d in details {
        if d["status"].as_str() != Some("ok") {
            continue;
        }
        let raw_kind = d["kind"].as_str().unwrap_or("");
        let mapped = match raw_kind {
            "dir" | "folder" => "folder",
            "file" => "file",
            "reg_key" => "reg_key",
            _ => continue, // shortcut / reg_value 不在签名库允许集里，也不该出现在学习库里
        };
        let Some(t) = d["target"].as_str() else { continue };
        entries.push((mapped, t.to_string()));
    }
    if entries.is_empty() {
        return 0;
    }
    let mut doc = learned::load().unwrap_or_else(learned::empty_doc);
    let added = learned::learn(&mut doc, &display_name, &publisher, key_path, &entries, crate::engine::now_ms());
    if added == 0 {
        return 0;
    }
    match learned::save(&doc) {
        Ok(_) => added,
        Err(e) => {
            // 学习是附加价值：写失败只降级成「这次没学到」，绝不能把已经成功的清理判成失败
            log::write_log("warn", &format!("学习库回写失败（本轮清理结果不受影响）: {e}"));
            0
        }
    }
}

/// 残留执行的**单一变更入口**（D3）：变更阶段拿到的就是已判定完的目标。
enum ResidueOp {
    RegKey {
        target: String,
        hive: windows::Win32::System::Registry::HKEY,
        rest: String,
    },
    RegValue {
        target: String,
        key_part: String,
        hive: windows::Win32::System::Registry::HKEY,
        rest: String,
        value_name: String,
    },
    Path { kind: String, target: OsString },
}

/// 单个目标的只读判定结果。`Abort` = 整批拒绝（受保护路径的既有语义，不降级成单项跳过）。
enum OpVerdict {
    Ready(ResidueOp),
    Skip(String),
    Abort(String),
}

/// 残留执行链上**所有只读闸门的唯一落点**（D3）。
///
/// 为什么要收：`uninstall_residue_execute` 原本三段各写各的判定（reg_key 查 hive 解析 +
/// A1 硬否决 + 存在性；reg_value 查 `::` 形状；文件目录查保护路径 + 存在性 + C1 重解析），
/// 「谁查了哪几道闸」只能靠通读三段来确认 —— 这正是漏闸的形态。收进一个函数后，
/// 判定顺序 = 这一个函数的行序，变更代码里不再有 if 保护判断。
///
/// 方案 §5·D3 原文还有个 `mode="plan"`（干跑不落变更）。这里刻意**不做**成参数：
/// 现在没有任何调用方会传 plan，加了就是死分支；"判定与变更分离"这个目的已经由本函数达成，
/// UI 真需要预览时再显式加 mode，届时这条函数就是它的实现。
fn classify_residue_op(kind: &str, target: &str) -> OpVerdict {
    let skip = |m: &str| OpVerdict::Skip(m.to_string());
    match kind {
        "reg_key" => {
            let Some((hive, rest)) = parse_reg_target(target) else {
                return skip("注册表目标无法解析（只支持 HKCU/HKLM）");
            };
            // A1 执行侧硬闸（与扫描侧同一判定）：快照闸只证明「来自上次扫描」，
            // 证明不了「这个目标不该删」—— 危险候选本来就是扫描器按规则产出的。
            if let Some(reason) = protect::reg_target_block_reason(target) {
                log::write_log("warn", &format!("uninstall_residue_execute 拒绝注册表目标: {reason}"));
                // 状态只用既有的 skip：报告明细按 ok/fail/skip 三态渲染中文标签，
                // 新增 status 会在前端漏出英文字面量（uninstall.js:487）
                return OpVerdict::Skip(format!("已拒绝删除：{reason}"));
            }
            if !crate::engine::native::reg_key_exists(hive, &rest) {
                return skip("注册表项已不存在");
            }
            OpVerdict::Ready(ResidueOp::RegKey { target: target.to_string(), hive, rest })
        }
        // 注册表值：删单值前先整父键备份（U-2 侧痕面 MuiCache/防火墙/BAM）。
        // 值已不存在的幂等语义留给 `reg_restore_delete`（对齐 B11），这里不重复判存在性。
        "reg_value" => {
            let Some((key_part, value_name)) = target.rsplit_once("::") else {
                return skip("注册表值目标格式错误（缺 :: 值名分隔）");
            };
            if value_name.trim().is_empty() {
                return skip("注册表值名为空");
            }
            let Some((hive, rest)) = parse_reg_target(key_part) else {
                return skip("注册表目标无法解析（只支持 HKCU/HKLM）");
            };
            OpVerdict::Ready(ResidueOp::RegValue {
                target: target.to_string(),
                key_part: key_part.to_string(),
                hive,
                rest,
                value_name: value_name.to_string(),
            })
        }
        "folder" | "file" | "shortcut" => {
            let shown = target.to_string();
            if protect::is_path_protected(&shown) {
                log::write_log("warn", &format!("uninstall_residue_execute 拒绝: 受保护路径 {shown}"));
                return OpVerdict::Abort(format!("包含受保护的系统路径，已拒绝：{shown}"));
            }
            if std::fs::symlink_metadata(target).is_err() {
                // 原本这里是被静默滤掉（报告里连一行都没有），现按 skip 记因：
                // 「没删」与「不需要删」必须在批次报告里可区分
                return OpVerdict::Skip("目标已不存在（未执行删除）".to_string());
            }
            // C1（方案 §5·C1）：目录送删前过「自身→盘符根」逐层重解析点校验，与维护任务
            // (`native::maint_run`)、diskbench 同口径。上级被换成 junction 时回收站会顺着链接
            // 把链接目标整棵搬走。file / shortcut 不查：单文件删除只删链接本身，不递归。
            if kind == "folder" {
                if let Some(reason) = crate::engine::native::dir_delete_blocked(Path::new(target)) {
                    log::write_log("warn", &format!("uninstall_residue_execute 跳过目录 {shown}: {reason}"));
                    return OpVerdict::Skip(format!("已拒绝删除：{reason}"));
                }
            }
            OpVerdict::Ready(ResidueOp::Path { kind: kind.to_string(), target: OsString::from(target) })
        }
        other => OpVerdict::Skip(format!("未知残留类型 {other}，未执行")),
    }
}

/// 卸载域·残留执行（方案 M4）。
/// 硬约束：目标必须命中本会话快照（防伪造请求）；文件/目录回收站优先且
/// `is_path_protected` 前置、失败不永久删除兜底；注册表先 export 备份再删，
/// 备份失败该项拒绝；`reg_key` 删树前必须过 `protect::reg_target_block_reason`（A1，
/// 与扫描侧同判定）；`folder` 送删前必须过上级链重解析校验（C1）。
/// 批次报告落 uninstall-reports/<batch>.json。
#[tauri::command]
pub async fn uninstall_residue_execute<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    app_id: String,
    targets: Vec<Value>,
    // HiBit §H1：删前是否先把内容打进还原包。**默认关**（2026-09-29 用户裁定不做默认备份），
    // 由残留面板上的开关逐项决定；勾了却建包失败则整批不删（见下面 closure 开头）。
    backup: Option<bool>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    if targets.is_empty() || targets.len() > 200 {
        return json!({ "success": false, "message": "targets 为空或超过 200 项上限" });
    }
    let label = window.label().to_string();
    // 快照校验：kind+target 逐一命中（方案 M4 验收「任意单项不得绕过快照」）
    let snap: Vec<Value> = {
        let store = residue_snapshots().lock().unwrap_or_else(|e| e.into_inner());
        store.get(&label).map(|(_, f)| f.clone()).unwrap_or_default()
    };
    let wanted: Vec<(String, String)> = targets
        .iter()
        .map(|t| {
            (
                t.get("kind").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                t.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            )
        })
        .collect();
    if wanted.iter().any(|(k, t)| k.is_empty() || t.is_empty()) {
        return json!({ "success": false, "message": "targets 存在缺失 kind/target 的项" });
    }
    let known = |k: &str, t: &str| {
        snap.iter().any(|f| {
            f["kind"].as_str() == Some(k)
                && f["target"].as_str().map(|s| s.eq_ignore_ascii_case(t)).unwrap_or(false)
        })
    };
    let stale: Vec<&(String, String)> = wanted.iter().filter(|(k, t)| !known(k, t)).collect();
    if !stale.is_empty() {
        return json!({ "success": false, "message": format!("{} 项不在本次扫描快照中（目标已过期或请求被篡改），请重新扫描后再试", stale.len()) });
    }

    log::flush_sync(); // 危险操作前刷盘
    // 批次号在这里就定：还原包目录、批次报告、回执必须共用同一个 id，事后补生成会对不上
    let batch_id = delete_manifest::new_batch_id();
    let batch_for_pack = batch_id.clone();
    let want_backup = backup.unwrap_or(false);
    let app_id = app_id.clone();
    let report = tauri::async_runtime::spawn_blocking(move || {
        // 勾了备份却建包失败 ⇒ 整批不删。静默降级成「只删不备」是把用户的决定改成她没选的那件事
        let mut pack = match want_backup {
            true => match crate::engine::restore_pack::Pack::begin(&batch_for_pack) {
                Ok(p) => Some(p),
                Err(e) => return Err(format!("创建还原包失败，未执行任何删除: {e}")),
            },
            false => None,
        };
        let mut details: Vec<Value> = Vec::new();
        // D3：只读闸门先一次跑完（判定顺序集中在 classify_residue_op），下面的变更代码里
        // 不再出现任何保护判断 —— 「谁查了哪几道闸」从"通读三段"变成"看一个函数的行序"。
        let mut ops: Vec<ResidueOp> = Vec::new();
        for (kind, target) in &wanted {
            match classify_residue_op(kind, target) {
                OpVerdict::Ready(op) => ops.push(op),
                OpVerdict::Skip(msg) => details.push(detail(kind, target, "skip", &msg)),
                OpVerdict::Abort(msg) => return Err(msg),
            }
        }
        // 注册表项：先备份后删（与 cleanup 同一 export 通道，fail-closed）
        for op in &ops {
            let ResidueOp::RegKey { target, hive, rest } = op else { continue };
            let (kind, target, hive, rest) = ("reg_key", target.as_str(), *hive, rest.as_str());
            let backup_dir = uninstall_reg_backup_dir();
            let _ = std::fs::create_dir_all(&backup_dir);
            let file = backup_dir.join(format!("{}_{}.reg", crate::engine::now_ms(), rest.rsplit('\\').next().unwrap_or("key")));
            let Some(file_str) = file.to_str() else {
                details.push(detail(kind, target, "fail", "备份路径无法表示为文本，拒绝删除"));
                continue;
            };
            let export_path = format!("{}\\{rest}", target.split('\\').next().unwrap_or(""));
            let backup_ok = crate::engine::systembin::quiet_cmd(crate::engine::systembin::system_tool("reg.exe"))
                .args(["export", &export_path, file_str, "/y"])
                .output()
                .map(|o| o.status.success() && file.exists())
                .unwrap_or(false);
            if !backup_ok {
                details.push(detail(kind, target, "fail", "注册表备份失败，未执行删除（fail-closed）"));
                continue;
            }
            // D2：备份写成后落封条（此后列表/还原才对得上这份文件）
            write_reg_backup_seal(&file, target);
            // N3：写完裁一次保留上限。只裁新根，封条随主文件同删（paths::prune_backups）；
            // 刚写的这份是最新项，不会被自己裁掉。
            crate::engine::paths::prune_backups(&backup_dir, crate::engine::paths::BACKUP_KEEP);
            if let Some(p) = pack.as_mut() {
                let _ = p.include_reg_backup(&file);
            }
            if crate::engine::native::reg_key_remove(hive, rest, true) {
                details.push(detail(kind, target, "ok", "已删除（备份已留存）"));
            } else {
                details.push(detail(kind, target, "fail", "注册表删除失败"));
            }
        }

        // 注册表值：先备份整个父键再删单值（U-2 侧痕面：MuiCache/防火墙规则/BAM）。
        // 目标格式 `HKCU\<键路径>::<值名>`；删值复用 reg_restore_delete
        // （值已不存在 = 幂等成功，对齐 B11 语义）。
        for op in &ops {
            let ResidueOp::RegValue { target, key_part, hive, rest, value_name } = op else { continue };
            let (kind, target, hive, rest, value_name) =
                ("reg_value", target.as_str(), *hive, rest.as_str(), value_name.as_str());
            let backup_dir = uninstall_reg_backup_dir();
            let _ = std::fs::create_dir_all(&backup_dir);
            let leaf = rest.rsplit('\\').next().unwrap_or("key");
            let file = backup_dir.join(format!("{}_{}.reg", crate::engine::now_ms(), leaf));
            let Some(file_str) = file.to_str() else {
                details.push(detail(kind, target, "fail", "备份路径无法表示为文本，拒绝删除"));
                continue;
            };
            let backup_ok = crate::engine::systembin::quiet_cmd(crate::engine::systembin::system_tool("reg.exe"))
                .args(["export", key_part, file_str, "/y"])
                .output()
                .map(|o| o.status.success() && file.exists())
                .unwrap_or(false);
            if !backup_ok {
                details.push(detail(kind, target, "fail", "注册表备份失败，未执行删除（fail-closed）"));
                continue;
            }
            // D2：封条记的是**被备份的父键**（删单值前整父键导出，还原粒度也是父键）
            write_reg_backup_seal(&file, key_part);
            // N3：与 reg_key 分支同一口径裁保留上限（同一目录，两处都要裁，漏一处
            // 就等于"删值的备份不参与限额"，盘上照样无限涨）
            crate::engine::paths::prune_backups(&backup_dir, crate::engine::paths::BACKUP_KEEP);
            if let Some(p) = pack.as_mut() {
                // 副本只为「一批一个去处」；写注册表的还原入口仍然只有 uninstall_reg_backup_restore
                if let Err(e) = p.include_reg_backup(&file) {
                    details.push(detail(kind, target, "skip", &format!("{e}（.reg 原件仍在，可用原还原入口）")));
                }
            }
            if crate::engine::native::reg_restore_delete(hive, rest, value_name) {
                details.push(detail(kind, target, "ok", "已删除（备份已留存）"));
            } else {
                details.push(detail(kind, target, "fail", "注册表值删除失败"));
            }
        }

        // 文件/目录/快捷方式：回收站批量（trim_finder 三端同源删除，含 protect 注入）
        let paths: Vec<(String, OsString)> = ops
            .iter()
            .filter_map(|o| match o {
                ResidueOp::Path { kind, target } => Some((kind.clone(), target.clone())),
                _ => None,
            })
            .collect();
        // 勾了备份：先逐个入包，**入包失败的那一项不删**（与注册表「备份失败不删」同口径）。
        // 顺序很关键——先打包后删除，反过来就可能出现「文件已进回收站、包里没这条」
        let paths: Vec<(String, OsString)> = match pack.as_mut() {
            None => paths,
            Some(p) => {
                let mut keep: Vec<(String, OsString)> = Vec::new();
                for (k, t) in paths {
                    match p.add_target(Path::new(&t)) {
                        Ok(_) => keep.push((k, t)),
                        Err(e) => {
                            let s = t.to_string_lossy().to_string();
                            details.push(detail(&k, &s, "skip", &format!("还原包写入失败，未删除: {e}")));
                        }
                    }
                }
                keep
            }
        };
        if !paths.is_empty() {
            if let Some((_, target)) = paths
                .iter()
                .find(|(_, t)| protect::is_path_protected(&t.to_string_lossy()))
            {
                // 兜底重复检查：分类阶段已 Abort 过，这里再挡一次是为了让"整批拒绝"
                // 不依赖 classify 的实现细节（受保护路径出现即整批不动，语义不变）
                log::write_log("warn", &format!("uninstall_residue_execute 拒绝: 受保护路径 {}", target.to_string_lossy()));
                return Err(format!("包含受保护的系统路径，已拒绝：{}", target.to_string_lossy()));
            }
            let protect_json = protect::protected_roots_json();
            // 删除结果行解析 Sink：只收 @@ITEM@@ 行里的 delresult（对齐 finder 的 FinderSink 口径）
            struct RowSink(Mutex<Vec<Value>>);
            impl trim_finder::scan::Sink for RowSink {
                fn item(&self, _p: &Path, line: &str) {
                    let Some(body) = line.strip_prefix("@@ITEM@@") else { return };
                    let Ok(v) = trim_finder::cleanup_scan::parse_json(body) else { return };
                    if v.get("type").and_then(|t| t.as_str()) != Some("delresult") {
                        return;
                    }
                    let jnum = |j: Option<&trim_finder::cleanup_scan::Json>| -> u64 {
                        match j {
                            Some(trim_finder::cleanup_scan::Json::Num(n)) => *n as u64,
                            _ => 0,
                        }
                    };
                    self.0.lock().unwrap_or_else(|e| e.into_inner()).push(json!({
                        "kind": match v.get("kind").and_then(|k| k.as_str()) {
                            Some("dir") => "dir",
                            _ => "file",
                        },
                        "path": v.get("path").and_then(|p| p.as_str()).unwrap_or(""),
                        "status": v.get("status").and_then(|s| s.as_str()).unwrap_or(""),
                        "freed": jnum(v.get("freed")),
                    }));
                }
                fn progress(&self, _n: u64) {}
                fn scanned(&self, _n: u64) {}
                fn warn(&self, _m: &str) {}
                fn truncated(&self) {}
            }
            let sink = RowSink(Mutex::new(Vec::new()));
            let _ = trim_finder::scan::delete(&paths, Some(protect_json.as_str()), &sink);
            // P2-D4：只读占用自检只花在真正失败的文件行上，且最多查 3 个——模块枚举是
            // 全进程开销，为拼提示文案不值得在整批全败时查几十次；目录行不查（目录不是
            // 可加载模块，占用的也是里面的文件，逐个查反而把消息拉长）。
            let mut probe_budget = 3usize;
            for row in sink.0.into_inner().unwrap_or_default() {
                let ok = row["status"] == "ok";
                let message = if ok {
                    "已移入回收站".to_string()
                } else {
                    match row["kind"].as_str() {
                        Some("file") if probe_budget > 0 => {
                            probe_budget -= 1;
                            row["path"]
                                .as_str()
                                .map(|p| occupancy_note(Path::new(p)))
                                .unwrap_or_else(|| "删除失败".to_string())
                        }
                        _ => row["path"]
                            .as_str()
                            .map(|_| "删除失败（可能被占用）".to_string())
                            .unwrap_or_else(|| "删除失败".to_string()),
                    }
                };
                details.push(detail(
                    row["kind"].as_str().unwrap_or("file"),
                    row["path"].as_str().unwrap_or(""),
                    if ok { "ok" } else { "fail" },
                    &message,
                ));
            }
        }
        // 收尾：包要落 manifest 才算成。内容已删而包没写成 ⇒ 回执必须带 error，
        // 不能让用户以为「备份好了」
        let pack_out = match pack {
            Some(p) => match p.finish() {
                Ok(v) => Some(v),
                Err(e) => {
                    log::write_log("error", &format!("还原包收尾失败（文件已删，内容不可还原）: {e}"));
                    Some(json!({ "error": e }))
                }
            },
            None => None,
        };
        Ok((details, pack_out))
    })
    .await;

    match report {
        Ok(Ok((details, pack_out))) => {
            let ok_count = details.iter().filter(|d| d["status"] == "ok").count();
            let fail_count = details.iter().filter(|d| d["status"] == "fail").count();
            // 批次报告（方案 M4）：动作级明细落盘，失败如实呈现
            let report_path = crate::engine::paths::app_data_dir()
                .join("uninstall-reports")
                .join(format!("{batch_id}.json"));
            let _ = std::fs::create_dir_all(report_path.parent().unwrap_or(Path::new(".")));
            let _ = crate::security::atomic_write_json(
                &report_path,
                &json!({
                    "batchId": batch_id, "appId": app_id,
                    "time": delete_manifest::iso_now(),
                    "details": details,
                    // 报告里留一笔：还原包被保留策略裁掉后，报告仍能说明「当时备过什么」
                    "restorePack": pack_out,
                }),
            );
            log::write_log("info", &format!("uninstall_residue_execute {app_id}: 成功 {ok_count} 失败 {fail_count}（报告 {batch_id}）"));
            // HiBit §H3 回写：学到几条就记几条，0 条不写文件也不报错（学习是附加价值）。
            // 放在报告落盘之后：报告是「删了什么」的凭据，不能被学习链的不确定性挡住。
            let learned_added = learn_from_deletions(&app_id, &details);
            if learned_added > 0 {
                log::write_log("info", &format!("本机学习库新增 {learned_added} 条落点（下轮同程序残留直接命中）"));
            }
            json!({ "success": true, "data": {
                "details": details, "okCount": ok_count, "failCount": fail_count,
                "reportPath": report_path.to_string_lossy(),
                "restorePack": pack_out,
                "learnedAdded": learned_added,
            } })
        }
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("残留清理异常: {e}") }),
    }
}

// ==================== uninstall:reg-backup-*（D1 还原入口 + D2 封条） ====================
//
// 卸载残留的注册表删除一直是「先 export 再删」，但备份**只写不读**：删错了没有任何还原
// 入口，兜底承诺停在半路（方案 §5·D1）。这一节补列表与单项还原，并给每份备份加封条。
//
// 封条能做什么、不能做什么必须写清（Q3 拍板 + 方案 D2 的边界）：备份与封条同在
// **用户可写**的数据目录里，同一个用户（或以该用户身份跑的任意进程）可以同时改写两者，
// 所以封条只提升两类防护——半截写入/手工误改的**误污染检测**，和低权限单点篡改的**可发现性**。
// 真正的防伪需要 HKLM 侧常驻提权面，那是另一次拍板，不许在这里当成已经具备的能力。

/// 卸载域注册表备份目录：两处 export 与列表/还原共用同一入口，不再各拼一遍路径。
///
/// 写恒新根（`backup_write_dir`），**读跨两根**（`backup_read_entries` / `resolve_backup_file`）：
/// 卸载域的 `.reg` 是本仓新写的，老根理论上不该有；但 v0.2.6 之前该目录曾用
/// `app_data_dir().join(...)` 直拼，与 `backup_write_dir` 等价，故不影响实体。兜底读留着
/// 是为了与 cleanup 域同口径（那条域的旧批确实躺在 `%APPDATA%\Trim`，N1），
/// 别让"同一个还原界面"在两个域里对同一件事给出不同答案。
const UNINSTALL_REG_BACKUP_SUB: &str = "uninstall-reg-backup";

fn uninstall_reg_backup_dir() -> PathBuf {
    crate::engine::paths::backup_write_dir(UNINSTALL_REG_BACKUP_SUB)
}

/// 备份文件名准入：只认生成器产出的形状（`<毫秒>_<键末段>.reg`），
/// 路径穿越（`..` / `\` / `/`）与非 .reg 一律拒绝——还原是**写注册表**的通道
fn valid_uninstall_backup_name(name: &str) -> bool {
    let n = name.trim();
    n.len() > 4
        && n.len() <= 120
        && n.ends_with(".reg")
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

// 封条与 `.reg` 严格解析的**实现已移到 `engine::reg_backup`**（N9）：清理域那条还原链
// 面对的是同一个威胁模型（用户可写目录里的一份 .reg 被拿去写注册表），复制一份正则或
// 一份切分只会让两域口径再次分叉。本文件按名字直接用，调用点与用例都不用改。
use crate::engine::reg_backup::{reg_backup_seal_state, write_reg_backup_seal};

/// 把「跨根备份条目」渲染成列表项：文件名解析 + 封条核对 + 老根标记 + mtime 倒序。
///
/// 为什么单独成函数：这段逻辑决定"还原按钮有没有依据"，但它对着真实数据根测不准 ——
/// 本机有没有 `.reg` 备份会让用例变成"碰巧绿"（AGENTS §4.1 假绿教训）。拆出来才能拿
/// 临时目录当输入。
fn render_reg_backups(entries: Vec<(PathBuf, bool)>) -> Vec<Value> {
    let mut items: Vec<Value> = Vec::new();
    for (p, from_legacy) in entries {
        let Some(name) = p.file_name().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        if !valid_uninstall_backup_name(&name) || !p.is_file() {
            continue;
        }
        let Ok(meta) = p.metadata() else { continue };
        let (seal, seal_meta) = reg_backup_seal_state(&p);
        // 文件名形如 `{毫秒}_{键末段}.reg`：时间戳直接取首段，取不到就以 mtime 为准
        let stamp = name.split('_').next().unwrap_or("").parse::<i64>().unwrap_or(0);
        items.push(json!({
            "file": name,
            "stampMs": stamp,
            "keyLeaf": name.trim_end_matches(".reg").split_once('_').map(|(_, r)| r.to_string()).unwrap_or_default(),
            "mtimeMs": meta.modified().ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
            "sizeBytes": meta.len(),
            "seal": seal,
            // 老根那份必须标来源：它是升级前的唯一还原依据，不是当前版本偷偷写的
            "fromLegacy": from_legacy,
            "target": seal_meta.get("target").and_then(Value::as_str).unwrap_or(""),
        }));
    }
    items.sort_by(|a, b| b["mtimeMs"].as_i64().cmp(&a["mtimeMs"].as_i64()));
    items
}

/// uninstall:reg-backup-list — 卸载域注册表备份列表（只读；跨新根+老根，≤50 条按 mtime 倒序）
#[tauri::command]
pub fn uninstall_reg_backup_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let mut items = render_reg_backups(crate::engine::paths::backup_read_entries(
        UNINSTALL_REG_BACKUP_SUB,
    ));
    let total_count = items.len();
    items.truncate(50);
    json!({ "success": true, "data": { "backups": items, "totalCount": total_count } })
}

/// uninstall:reg-backup-restore — 把单个备份 import 回注册表（主窗专属）。
/// import 是「合并加回」不是「回滚快照」：只还原备份里存在的键/值，不删除此后产生的新数据。
/// 四道前置闸：文件名白名单 → 严格解析目标键 → 封条核对 → 目标含 HKLM 时必须已提权。
#[tauri::command]
pub fn uninstall_reg_backup_restore<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    file: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let name = file.trim().to_string();
    if !valid_uninstall_backup_name(&name) {
        return json!({ "success": false, "message": "备份文件名非法" });
    }
    // 还原侧与列表侧必须共用同一套跨根解析：列表能列出老根那份，还原就只能从同一根取，
    // 否则"看得见、点不动"（N1）
    let Some(path) =
        crate::engine::paths::resolve_backup_file(UNINSTALL_REG_BACKUP_SUB, &name)
    else {
        return json!({ "success": false, "message": "备份文件不存在" });
    };
    // 四道闸走公共件（N9）：清理域那条链现在调的是同一个函数，两域不可能再各写一套口径
    let crate::engine::reg_backup::RegBackupCheck { keys, seal } =
        match crate::engine::reg_backup::reg_backup_restore_guards(
            &path,
            &name,
            crate::engine::sysinfo::is_admin(),
        ) {
            Ok(c) => c,
            Err(msg) => return json!({ "success": false, "message": msg }),
        };
    log::flush_sync(); // 写注册表前刷盘
    // A6（v2-R4）：原生 `.reg` 写入替换 `reg.exe import`。上面四道闸原样跑，
    // .reg 文本格式与封条链未动；原先「成功 / 非零退出 / 调用失败」三分支
    // 在原生侧塌成 Ok/Err 两分支（外部进程的退出码这一层信息本身已不存在）。
    match crate::engine::reg_backup::reg_import_apply(&path) {
        Ok(stat) => {
            log::write_log(
                "info",
                &format!(
                    "卸载域注册表备份已还原: {name}（{} 个键，写入 {} 值、删除 {} 值、删键 {}）",
                    keys.len(),
                    stat.values_written,
                    stat.values_deleted,
                    stat.keys_deleted
                ),
            );
            json!({ "success": true, "data": {
                "restored": true, "keys": keys, "sealWasRecorded": seal == "ok",
                "message": "已按备份合并回注册表（只加回备份里存在的键/值）"
            }})
        }
        Err(e) => {
            log::write_log("error", &format!("卸载域备份还原失败: {name} {e}"));
            json!({ "success": false, "message": format!("还原写入失败: {e}") })
        }
    }
}

// ==================== uninstall:batch-*（HiBit §H1 还原包列表与整批还原） ====================
//
// 与 `uninstall_reg-backup-*` 的分工必须写清，否则后来者会以为这里也能还原注册表：
// 本节的 restore **只往磁盘写文件**，注册表还原仍然只有 `uninstall_reg_backup_restore`
// 那一条通道（文件名准入 → 严格 .reg 解析 → 从正文重取键路径复算禁删面 → 封条校验）。
// 给同一个危险动作开第二个入口，等于让四道闸变成「挑一条走」。

/// uninstall:batch-list —— 本机还原包（**MAIN 档**，与同门 `uninstall_reg_backup_list` 一致：
/// 只有主窗的备份弹窗调它，四子窗没有消费方，按 readonly 放行等于白给一个目录列举面）。
/// 带体积与「zip 是否还在」的自检，界面据此能说清「这个包点还原到底会不会成功」，
/// 而不是等用户点下去才报错。
#[tauri::command]
pub fn uninstall_batch_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    json!({
        "success": true,
        "data": {
            "packs": crate::engine::restore_pack::list(50),
            "totalBytes": crate::engine::restore_pack::total_bytes(),
        }
    })
}

/// uninstall:batch-restore —— 按 manifest 把整批内容写回原位置。
///
/// 档位 MAIN：它写磁盘，且入口只在主窗的备份弹窗（与 `uninstall_batch_list` 同档）。
/// 逐条判定都在 restore_pack::restore 里：
/// 路径准入（绝对 + 不含 .. + 非受保护 + 不落 %WINDIR%）→ zip 缺条目即失败 →
/// 哈希/字节数不符即失败 → 目标已存在且内容不同则**不覆盖**（那是「卸完又装了」，
/// 覆盖等于抢掉用户现在的文件）。
#[tauri::command]
pub async fn uninstall_batch_restore<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    batch_id: String,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(move || {
        crate::engine::restore_pack::restore(&batch_id)
    })
    .await;
    match res {
        Ok(Ok(v)) => json!({ "success": true, "data": v }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("还原包还原异常: {e}") }),
    }
}

// ==================== uninstall:report-*（U-6 批次报告查看入口） ====================

fn uninstall_reports_dir() -> PathBuf {
    crate::engine::paths::app_data_dir().join("uninstall-reports")
}

/// batch_id 准入：new_batch_id 形如 `2026-09-28T12-30-45-123Z`（ISO 去 :/.），
/// 字符集限定 [A-Za-z0-9-]（含 T/Z）——路径穿越（..、\、/）与非报告文件名一律拒绝。
fn valid_batch_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// uninstall:report-list — 列出残留清理批次报告（主窗档；只读；上限 50 条按时间倒序）
#[tauri::command]
pub fn uninstall_report_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let Ok(rd) = std::fs::read_dir(uninstall_reports_dir()) else {
        return json!({ "success": true, "data": { "reports": [] } });
    };
    let mut items: Vec<Value> = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if !valid_batch_id(stem) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        // 损坏的个别报告跳过不阻断整表；details 计数在列表页就给全，点开再看明细
        let (mut ok, mut fail, mut skip) = (0i64, 0i64, 0i64);
        for d in v.get("details").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            match d.get("status").and_then(|s| s.as_str()) {
                Some("ok") => ok += 1,
                Some("fail") => fail += 1,
                _ => skip += 1,
            }
        }
        items.push(json!({
            "batchId": stem,
            "time": v.get("time").cloned().unwrap_or(Value::Null),
            "appId": v.get("appId").cloned().unwrap_or(Value::Null),
            "okCount": ok, "failCount": fail, "skipCount": skip,
        }));
    }
    // 文件名即 ISO 时间戳，倒序 = 最新在前。
    // N8：必须**先全量收集再排序再截断**。NTFS 枚举序≈文件名升序，在循环里 `break` 到 50
    // 截走的是**最旧** 50 份，随后那次排序只是在旧账里排座次 ⇒ 批次一过 50，用户刚做完
    // 的那次清理报告就不在列表里（与 N1 同症状、不同成因）。
    items.sort_by(|a, b| {
        let ka = a["batchId"].as_str().unwrap_or("");
        let kb = b["batchId"].as_str().unwrap_or("");
        kb.cmp(ka)
    });
    let total_count = items.len();
    items.truncate(50);
    json!({ "success": true, "data": { "reports": items, "totalCount": total_count } })
}

/// uninstall:report-get — 读取单个批次报告（主窗档；只读；batch_id 过字符集闸防穿越）
#[tauri::command]
pub fn uninstall_report_get<R: tauri::Runtime>(window: WebviewWindow<R>, batch_id: String) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    if !valid_batch_id(&batch_id) {
        return json!({ "success": false, "message": "batchId 非法" });
    }
    let p = uninstall_reports_dir().join(format!("{batch_id}.json"));
    let Ok(text) = std::fs::read_to_string(&p) else {
        return json!({ "success": false, "message": "报告不存在或不可读" });
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(v) => json!({ "success": true, "data": v }),
        Err(_) => json!({ "success": false, "message": "报告 JSON 解析失败" }),
    }
}

/// uninstall:appx-logo — 读取 Appx Logo PNG → dataURL（U-3）。
/// SHGetFileInfoW 对 .png 只出「文件类型图标」，不是图像内容，故走直接读文件；
/// 准入收紧到 `\WindowsApps\` 下的 .png（Appx 安装资产），防变成任意文件读。
#[tauri::command]
pub fn uninstall_appx_logo<R: tauri::Runtime>(window: WebviewWindow<R>, logo_path: String) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let p = logo_path.trim();
    let pl = p.to_lowercase();
    let looks_ok = p.len() <= 1024
        && pl.ends_with(".png")
        && (pl.as_bytes().get(1) == Some(&b':') || pl.starts_with("\\\\"))
        && pl.contains("\\windowsapps\\");
    if !looks_ok {
        return json!({ "success": false, "message": "logo 路径不在 Appx 安装资产范围内" });
    }
    let path = PathBuf::from(p);
    let Ok(meta) = std::fs::metadata(&path) else {
        return json!({ "success": false, "message": "logo 文件不存在" });
    };
    if !meta.is_file() || meta.len() > 512 * 1024 {
        return json!({ "success": false, "message": "logo 文件缺失或超过 512KB 上限" });
    }
    match std::fs::read(&path) {
        Ok(bytes) => {
            use base64::Engine as _;
            // 形状对齐 paths:file-icon / paths:app-icon（顶层 dataUrl）——前端
            // fetchIcon 三分支统一判 resp.dataUrl，嵌套 data.dataUrl 永远判不中
            // （U-3 复检二轮实锤：枚举修好后图标仍不显示的真因）
            json!({
                "success": true,
                "dataUrl": format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(&bytes))
            })
        }
        Err(e) => json!({ "success": false, "message": format!("logo 读取失败: {e}") }),
    }
}

#[cfg(test)]
mod install_date_tier_tests {
    use super::install_date_from_epoch;

    /// 期望值全部用 `new Date(secs*1000).toISOString()` 独立算过一遍（不拿实现反推实现）
    #[test]
    fn epoch_换算与标准库一致() {
        let cases = [
            (1_609_459_200u32, "2021-01-01"),
            (1_000_000_000, "2001-09-09"),
            (1_582_934_400, "2020-02-29"), // 闰日
            (946_684_800, "2000-01-01"), // 千禧年
            (788_918_400, "1995-01-01"),
            (631_152_000, "1990-01-01"), // 下界含
        ];
        for (secs, want) in cases {
            assert_eq!(install_date_from_epoch(secs).as_deref(), Some(want), "secs={secs}");
        }
    }

    /// 「不可信」必须是 None，不能退成 1970-01-01 —— 那会被列表当成真实安装日期显示，
    /// 比空值更糟（用户会拿它判断"这程序多久没动了"）
    #[test]
    fn 不可信取值一律返回_none() {
        for secs in [0u32, 1, 86_399, 631_065_600 /* 1989-12-31 */, 4_133_980_800 /* 2101-01-01 */] {
            assert_eq!(install_date_from_epoch(secs), None, "secs={secs} 应判不可信");
        }
    }

    #[test]
    fn 两档顺序_装了安装日期值就不该退到键时间() {
        // 纯函数层能钉的只有这一半：调用方（enum_uninstall_root）先取本函数、
        // 拿不到才退 reg_key_last_write_date，且 installDateExact 反映来源。
        // 真机两档差异要看的证据是列表里同一程序「安装日期」与注册表键时间不一致时取前者。
        assert_eq!(install_date_from_epoch(1_609_459_200).as_deref(), Some("2021-01-01"));
        assert_eq!(install_date_from_epoch(0), None, "0 必须退回兜底档，否则 exact 标志会撒谎");
    }
}

#[cfg(test)]
mod uninstall_appx_tests {
    use super::*;

    /// 包全名是直接内插进 PowerShell 命令串的，字符集白名单是唯一注入防线。
    #[test]
    fn appx_fullname_charset_gate() {
        assert!(valid_appx_fullname("OpenAI.ChatGPT-Desktop_1.2025.123.0_x64__0000000000000"));
        assert!(valid_appx_fullname("Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe"));
        // 注入面：引号 / 分号 / 换行 / 非 ASCII 一律拒绝
        assert!(!valid_appx_fullname("a'; Remove-Item C:\\ -Recurse; '"));
        assert!(!valid_appx_fullname("a\"b"));
        assert!(!valid_appx_fullname("a\nb"));
        assert!(!valid_appx_fullname(""));
        assert!(!valid_appx_fullname("名字非法"));
    }

    /// U-4：包全名 → PFN。Name 含下划线（多段拼回）、Version/Arch 去尾两段；
    /// 结构不符返回 None。
    #[test]
    fn package_family_name_derivation() {
        assert_eq!(
            package_family_name("Microsoft.MicrosoftEdge.Stable_153.0.4234.32_neutral__8wekyb3d8bbwe"),
            Some("Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe".to_string())
        );
        assert_eq!(
            package_family_name("OpenAI.ChatGPT-Desktop_1.2025.123.0_x64__0000000000000"),
            Some("OpenAI.ChatGPT-Desktop_0000000000000".to_string())
        );
        // Name 自带下划线
        assert_eq!(
            package_family_name("Some_App.Name_1.0.0.0_x64__cafebabedeadbeef"),
            Some("Some_App.Name_cafebabedeadbeef".to_string())
        );
        // 结构不符：缺 __ / 缺 Version+Arch 段 / PublisherId 带下划线
        assert_eq!(package_family_name("NoDoubleUnderscore_1.0.0.0_x64"), None);
        assert_eq!(package_family_name("A_B__pub"), None);
        assert_eq!(package_family_name("A_1.0_x64__has_underscore"), None);
        assert_eq!(package_family_name(""), None);
    }

    /// 发行商友好化：CN= 取逗号前段；非 CN 形态原样保留。
    #[test]
    fn friendly_publisher_extracts_cn() {
        assert_eq!(friendly_publisher("CN=OpenAI, O=OpenAI, L=San Francisco"), "OpenAI");
        assert_eq!(friendly_publisher("CN=Microsoft Windows Store"), "Microsoft Windows Store");
        assert_eq!(friendly_publisher("Tencent"), "Tencent");
        assert_eq!(friendly_publisher(""), "");
    }

    /// R0（2026-10-01）：Appx 枚举从 `quiet_cmd(...).output()` + `-Command` 改走统一入口
    /// `pwsh::run_inbox_script`（`-File` + UTF-8 BOM + 120s 超时 + Job Object 收树）。
    /// MockRuntime 测不到真起进程的这一面，而 `-Command → -File` 恰恰是**语义可能变**的地方
    /// （脚本形态、`exit` 码传递、BOM），所以留一条只读实跑当发布前门禁。
    #[test]
    #[ignore = "真实起收件箱 PowerShell 枚举 Appx（只读、秒级），发布前门禁跑"]
    fn appx_枚举经统一入口交出可渲染列表() {
        let items = enum_appx_packages().expect("Get-AppxPackage 枚举失败：统一入口或脚本形态有问题");
        for it in &items {
            let id = it.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let fullname = id.strip_prefix("APPX|").unwrap_or_else(|| panic!("id 不是 APPX|PFN 形状: {id}"));
            assert!(valid_appx_fullname(fullname), "包全名没过字符集闸: {fullname}");
            // 渲染层直接读的字段必须是字符串（前端 .displayName 不做判空）
            for k in ["displayName", "publisher", "displayVersion", "installLocation", "logoPath"] {
                assert!(it.get(k).and_then(|v| v.as_str()).is_some(), "{k} 必须是字符串: {it}");
            }
            assert_eq!(it.get("installerKind").and_then(|v| v.as_str()), Some("appx"));
            assert_eq!(it.get("removable").and_then(|v| v.as_bool()), Some(true));
        }
        // 空列表在这台机器上是合法结果（没有可卸载的商店应用），不据此判失败；
        // 这条用例真正钉的是「调用成功 + 每一项都过形状」，脚本跑歪会直接 Err。
    }
}

// ==================== P1-B3 重启后删（2026-10-01 拍板） ====================
// 回收站失败的「文件」项可以降级为「重启后删除」：MoveFileEx(DELAY_UNTIL_REBOOT)
// 写进系统 PendingFileRenameOperations（PFRO），下次重启由会话管理器删除。
//
// 四条硬约束（2026-10-01 拍板口径，缺一不可）：
//   · 明示 + 单独确认：只处理用户在确认框里点过头的批次，绝不静默登记；
//   · 只限回收站失败项：本模块不提供任何"直接登记"入口，调用方（渲染层）只能把
//     residueExecute 回执里 status != ok 的文件行送进来；
//   · 可撤回：登记项记进本机 state 文件，撤回 = 把 PFRO 里的对应条目摘掉（重启前有效）；
//   · 待删清单可见：pending_list 把「还挂着 / 已被重启消费 / 文件已不在」三种状态分清。
// 这是**永久删除**（不进回收站），与 AGENTS §3 回收站优先的红线冲突，属 2026-10-01
// 显式拍板的受控例外（类比 v3.3.0 常规清理永久删那次裁定）。

const PENDING_DELETE_FILE: &str = "pending-delete.json";
const PFRO_SUBKEY: &str = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";
const PFRO_VALUE: &str = "PendingFileRenameOperations";

/// 登记 state 文件路径（数据目录下，含 legacy 迁移口径由 paths 统一管）
fn pending_delete_path() -> std::path::PathBuf {
    crate::engine::paths::app_data_dir().join(PENDING_DELETE_FILE)
}

fn pending_load() -> Value {
    let p = pending_delete_path();
    std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_str::<Value>(&String::from_utf8_lossy(&b)).ok())
        .filter(|v| v.get("version").and_then(Value::as_u64) == Some(1))
        .unwrap_or_else(|| json!({ "version": 1, "entries": [] }))
}

fn pending_save(doc: &Value) -> Result<(), String> {
    crate::security::atomic_write_json(&pending_delete_path(), doc)
}

/// MOVEFILE 失败错误码 → 中文分档（纯函数，可测）。ACCESS_DENIED 与 SHARING_VIOLATION
/// 必须分开说：前者是权限问题（提权重试有意义），后者是占用问题（提权没用）。
fn classify_pending_delete_error(win32_code: u32) -> &'static str {
    match win32_code {
        5 => "拒绝访问（权限不足，需管理员）",
        32 => "文件正被占用（共享冲突）",
        2 => "目标文件不存在",
        3 => "目标路径不存在",
        _ => "系统拒绝该操作",
    }
}

/// 读 PFRO（REG_MULTI_SZ）。缺失/为空按空表处理——首次登记时它经常还不存在。
fn read_pfro() -> Result<Vec<String>, String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_VALUE_TYPE,
    };
    unsafe {
        let sk = to_wide(PFRO_SUBKEY);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        let opened = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(sk.as_ptr()),
            Some(0),
            KEY_READ,
            &mut hk,
        );
        if opened.is_err() {
            return Err(format!("打开 PFRO 键失败: {opened:?}"));
        }
        let nm = to_wide(PFRO_VALUE);
        let mut ty = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        let q = RegQueryValueExW(
            hk,
            windows::core::PCWSTR(nm.as_ptr()),
            None,
            Some(&mut ty),
            None,
            Some(&mut size),
        );
        if q.is_err() {
            let _ = RegCloseKey(hk);
            return Ok(Vec::new()); // 值不存在 = 没有待重启操作
        }
        if ty.0 != 7 || size == 0 {
            let _ = RegCloseKey(hk);
            if ty.0 != 7 {
                return Err("PFRO 值类型异常（不是 REG_MULTI_SZ），拒绝改写".to_string());
            }
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        let ok = RegQueryValueExW(
            hk,
            windows::core::PCWSTR(nm.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        );
        let _ = RegCloseKey(hk);
        if ok.is_err() {
            return Err("读取 PFRO 失败".to_string());
        }
        // MULTI_SZ 形态：str\0str\0…\0\0。空串项是"删除"对的第二个元素，必须保留语义。
        let mut out: Vec<String> = Vec::new();
        let mut cur: Vec<u16> = Vec::new();
        let words: Vec<u16> = buf[..size as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        for w in words {
            if w == 0 {
                if cur.is_empty() && out.last().map(|s: &String| s.is_empty()).unwrap_or(false) {
                    break; // 连续两个 \0 = 表结束
                }
                out.push(String::from_utf16_lossy(&cur));
                cur.clear();
            } else {
                cur.push(w);
            }
        }
        Ok(out)
    }
}

/// 写回 PFRO（REG_MULTI_SZ）。需要管理员（Session Manager 键的 DACL 只给管理员写）。
fn write_pfro(entries: &[String]) -> Result<(), String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_MULTI_SZ,
    };
    let mut words: Vec<u16> = Vec::new();
    for e in entries {
        words.extend(to_wide(e)); // to_wide 自带结尾 NUL
    }
    if words.last() != Some(&0) {
        words.push(0);
    }
    words.push(0); // MULTI_SZ 以双 NUL 结束
    unsafe {
        let sk = to_wide(PFRO_SUBKEY);
        let mut hk = windows::Win32::System::Registry::HKEY::default();
        let opened = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(sk.as_ptr()),
            Some(0),
            KEY_SET_VALUE,
            &mut hk,
        );
        if opened.is_err() {
            // 5 = ERROR_ACCESS_DENIED：Session Manager 键的 DACL 只给管理员写
            let hint = if opened.0 == 5 {
                "（权限不足：登记/撤回重启后删除需要管理员权限，请以管理员身份运行 Trim）"
            } else {
                ""
            };
            return Err(format!("打开 PFRO 键失败: {opened:?}{hint}"));
        }
        let nm = to_wide(PFRO_VALUE);
            let r = RegSetValueExW(
            hk,
            windows::core::PCWSTR(nm.as_ptr()),
            None,
            REG_MULTI_SZ,
            Some(words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>().as_slice()),
        );
        let _ = RegCloseKey(hk);
        if r.is_err() {
            return Err(format!("写 PFRO 失败: {r:?}"));
        }
        Ok(())
    }
}

/// PFRO 里"删除 target"的登记形态：src=target、紧随其后的 dst 为空串。
fn pfro_has_delete(entries: &[String], target: &str) -> bool {
    let t = target.trim_end_matches(['\\', '/']).to_lowercase();
    entries
        .windows(2)
        .any(|w| w[1].is_empty() && w[0].trim_end_matches(['\\', '/']).to_lowercase() == t)
}

/// 从 PFRO 里摘掉"删除 targets 中任一路径"的整对（src+dst 一起删）。
fn pfro_strip_deletes(entries: Vec<String>, targets: &HashSet<String>) -> Vec<String> {
    let norm = |s: &str| s.trim_end_matches(['\\', '/']).to_lowercase();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < entries.len() {
        let is_ours = i + 1 < entries.len()
            && entries[i + 1].is_empty()
            && targets.contains(&norm(&entries[i]));
        if is_ours {
            i += 2; // 整对摘除
        } else {
            out.push(entries[i].clone());
            i += 1;
        }
    }
    out
}

/// 单批登记上限：口径对齐残留执行 `RESIDUE_MAX_GROUP_ITEMS=32`。PFRO 是系统级全局队列，
/// 登记逐条走 MoveFileExW，超大批次没有业务场景（可登记项天然来自「回收站删不掉」的少数派），
/// 只会拉长重启阶段会话管理器的消费时间（v2-B2，2026-10-01 复核）。
const PENDING_ADD_MAX_ITEMS: usize = 32;

/// uninstall:pending-add — 把回收站失败的文件项登记为重启后删除（主窗档）。
/// 只接受**文件**路径（PFRO 对非空目录的延迟删除并不可靠，登记了也删不掉，
/// 与其制造"已登记=会删掉"的错觉，不如入口就拒）。
#[tauri::command]
pub async fn uninstall_pending_add<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    targets: Vec<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    if targets.is_empty() {
        return json!({ "success": false, "message": "没有要登记的目标" });
    }
    // v2-B2：单批上限在入口拦，进 spawn_blocking 之前就整批拒绝——
    // 不给「先读 PFRO 才发现超批」的无效往返，也不留半批登记的中间态。
    if targets.len() > PENDING_ADD_MAX_ITEMS {
        return json!({
            "success": false,
            "message": format!("单批登记 {} 项超上限 {PENDING_ADD_MAX_ITEMS}，请分批登记", targets.len())
        });
    }
    let res = tauri::async_runtime::spawn_blocking(move || {
        // 先读 PFRO：登记前必须确认能写（权限不足在这里就暴露，不要等到"登记完才发现撤不回"）
        let mut pfro = read_pfro()?;
        let mut doc = pending_load();
        let entries = doc["entries"].as_array_mut().ok_or("登记文件损坏")?;
        let batch = format!(
            "p{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        let mut rows: Vec<Value> = Vec::new();
        let mut added = 0usize;
        for t in &targets {
            // v2-B1（2026-10-01 复核）：PFRO 登记是**永久删**出口（不进回收站，重启后由
            // 会话管理器执行），受保护路径判定必须在命令体内前置——渲染层 confirmDanger
            // 只是第一层，命令体内再判一次才与其余删除链同口径。刻意放在 is_file 之前：
            // 空串 / 盘符根 / 受保护根下的路径无论当前存在与否都拒，不给「登记窗口期
            // 路径状态变化」留缝，也与 protect 判定的 fail-closed 语义一致。
            if protect::is_path_protected(t) {
                rows.push(json!({ "target": t, "status": "skip", "message": "目标位于受保护路径（或无法归一化），拒绝登记重启后删除" }));
                continue;
            }
            let path = Path::new(t);
            if t.trim().is_empty() || !path.is_file() {
                rows.push(json!({ "target": t, "status": "skip", "message": "目标不是存在的文件（目录不支持重启后删）" }));
                continue;
            }
            let already = pfro_has_delete(&pfro, t)
                || entries.iter().any(|e| {
                    e["target"].as_str().map(|s| s.eq_ignore_ascii_case(t)).unwrap_or(false)
                });
            if already {
                rows.push(json!({ "target": t, "status": "skip", "message": "已登记过，不重复登记" }));
                continue;
            }
            use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
            // DELAY_UNTIL_REBOOT 只登记、立即返回；删除动作发生在下次重启的会话管理器阶段
            let moved = unsafe {
                MoveFileExW(
                    windows::core::PCWSTR(to_wide(t).as_ptr()),
                    None,
                    MOVEFILE_DELAY_UNTIL_REBOOT,
                )
            };
            match moved {
                Ok(()) => {
                    pfro.push(t.clone());
                    pfro.push(String::new());
                    entries.push(json!({ "target": t, "batchId": batch, "addedAt": batch.trim_start_matches('p') }));
                    rows.push(json!({ "target": t, "status": "ok", "message": "已登记，下次重启时删除" }));
                    added += 1;
                }
                Err(e) => {
                    let code = e.code().0 as u32 & 0xFFFF;
                    rows.push(json!({ "target": t, "status": "fail", "message": format!("{}（错误码 {code}）", classify_pending_delete_error(code)) }));
                }
            }
        }
        if added > 0 {
            write_pfro(&pfro)?;
            pending_save(&doc)?;
            log::flush_sync();
            log::write_log("warn", &format!("重启后删除：本批登记 {added} 项（永久删除，不进回收站）"));
        }
        Ok::<Vec<Value>, String>(rows)
    })
    .await;
    match res {
        Ok(Ok(rows)) => {
            let ok = rows.iter().filter(|r| r["status"] == "ok").count();
            json!({ "success": true, "data": { "added": ok, "details": rows } })
        }
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("登记执行异常: {e}") }),
    }
}

/// uninstall:pending-list — 待删清单（主窗档，只读）。
/// 三个状态分开：pending（PFRO 还挂着）/ consumed（重启已消费）/ missing（文件已不在）。
#[tauri::command]
pub async fn uninstall_pending_list<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<Value, String> {
        let doc = pending_load();
        let pfro = read_pfro()?;
        let rows: Vec<Value> = doc["entries"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|e| {
                let t = e["target"].as_str().unwrap_or_default().to_string();
                let pending = pfro_has_delete(&pfro, &t);
                let exists = Path::new(&t).is_file();
                let status = if pending {
                    "pending"
                } else if !exists {
                    "missing"
                } else {
                    "consumed"
                };
                json!({
                    "target": t,
                    "batchId": e["batchId"],
                    "addedAt": e["addedAt"],
                    "status": status,
                })
            })
            .collect();
        Ok(json!({ "entries": rows, "pfroReadable": true }))
    })
    .await;
    match res {
        Ok(Ok(v)) => json!({ "success": true, "data": v }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("读取失败: {e}") }),
    }
}

/// uninstall:pending-revoke — 撤回（主窗档）。不传 batchId = 撤回本机全部登记项。
/// 撤回动作本身要写 PFRO（管理员权限），失败时明确报错且不动 state —— 两边必须一致。
#[tauri::command]
pub async fn uninstall_pending_revoke<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    batch_id: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<usize, String> {
        let mut doc = pending_load();
        let scoped: HashSet<String> = doc["entries"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter(|e| batch_id.as_deref().map(|b| e["batchId"].as_str() == Some(b)).unwrap_or(true))
            .filter_map(|e| e["target"].as_str().map(|s| s.trim_end_matches(['\\', '/']).to_lowercase()))
            .collect();
        if scoped.is_empty() {
            return Ok(0usize);
        }
        let pfro = read_pfro()?;
        let stripped = pfro_strip_deletes(pfro, &scoped);
        write_pfro(&stripped)?;
        let remaining: Vec<Value> = doc["entries"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter(|e| {
                let t = e["target"]
                    .as_str()
                    .map(|s| s.trim_end_matches(['\\', '/']).to_lowercase())
                    .unwrap_or_default();
                !scoped.contains(&t)
            })
            .cloned()
            .collect();
        doc["entries"] = Value::Array(remaining);
        pending_save(&doc)?;
        log::flush_sync();
        log::write_log("info", &format!("重启后删除：撤回 {} 项登记", scoped.len()));
        Ok(scoped.len())
    })
    .await;
    match res {
        Ok(Ok(n)) => json!({ "success": true, "data": { "revoked": n } }),
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("撤回执行异常: {e}") }),
    }
}

#[cfg(test)]
mod residue_trace_tests {
    use super::*;

    /// P2-D4 的「第三方模块」口径：排除 Windows 目录与本应用自身目录，且前缀命中
    /// 不得跨路径段（C:\Windows.old 不能被 C:\Windows 前缀吃掉）。
    #[test]
    fn third_party_module_scope_excludes_system_and_self() {
        assert!(!is_third_party_module(r"C:\Windows\System32\kernel32.dll"));
        // 边界：Windows.old 不属于 C:\Windows 前缀段，必须算第三方
        assert!(is_third_party_module(r"C:\Windows.old\System32\app.dll"));
        assert!(is_third_party_module(
            r"C:\Program Files\AVAST Software\AV\avcuf64.dll"
        ));
        // 自身目录里的模块不算第三方（拿真机 current_exe 现算，不写死路径）
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let sample = dir.join("self_module.dll");
                assert!(!is_third_party_module(&sample.to_string_lossy()));
            }
        }
        // 非法/无目录形态一律不判第三方（模块枚举不会产这种值，防御性回 false）
        assert!(!is_third_party_module("kernel32.dll"));
    }

    /// U-2 反查的前缀语义：值名以已知 exe 开头（MuiCache `<exe>.xxx` / BAM 完整路径），
    /// 或落在安装目录前缀下；前缀命中不得跨「路径段」误放行。
    #[test]
    fn trace_prefix_hit_matches_exe_and_dir() {
        let exes = vec!["c:\\apps\\foo\\foo.exe".to_string()];
        assert!(trace_prefix_hit("c:\\apps\\foo\\foo.exe.FriendlyAppName", &exes, ""));
        assert!(trace_prefix_hit("c:\\apps\\foo\\foo.exe", &exes, ""));
        assert!(!trace_prefix_hit("c:\\apps\\foobar\\foo.exe", &exes, ""));
        assert!(trace_prefix_hit("c:\\apps\\foo\\helper.exe", &exes, "c:\\apps\\foo"));
        assert!(!trace_prefix_hit("c:\\apps\\foobar\\x.exe", &exes, "c:\\apps\\foo"));
        // 无目录线索时不能放行任意路径
        assert!(!trace_prefix_hit("d:\\elsewhere\\foo.exe", &exes, ""));
    }

    /// reg_value 目标格式往返：`HKCU\<键>::<值名>` 按 rsplit_once("::") 拆，
    /// 值名（完整路径）含 `:` 但不含 `::`，rsplit 保证只切最后一刀。
    #[test]
    fn reg_value_target_roundtrip() {
        let target = r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache::C:\Apps\Foo\Foo.exe.FriendlyAppName";
        let (key, val) = target.rsplit_once("::").unwrap();
        assert!(key.starts_with("HKCU\\") && key.contains("MuiCache"));
        assert_eq!(val, r"C:\Apps\Foo\Foo.exe.FriendlyAppName");
        // 无分隔 → None（执行侧按 skip 处理，不 panic）
        assert!(r"HKCU\Software\Foo".rsplit_once("::").is_none());
    }

    /// collect_program_objects：UninstallString / DisplayIcon 双来源提取 exe；
    /// DisplayIcon 的 `,图标索引` 后缀被剥掉；不存在的安装目录不进 dir。
    #[test]
    fn collect_program_objects_from_cmds() {
        let (exes, dir) = collect_program_objects(
            "",
            r#""C:\Apps\Foo\unins000.exe" /SILENT"#,
            r"C:\Apps\Foo\Foo.exe,0",
        );
        assert!(exes.iter().any(|e| e == r"C:\Apps\Foo\unins000.exe"));
        assert!(exes.iter().any(|e| e == r"C:\Apps\Foo\Foo.exe"));
        assert!(dir.is_none());
    }

    /// msiexec 形态不入 exe 集（msiexec.exe 是系统组件，反查它只会误伤）
    #[test]
    fn collect_program_objects_skips_msiexec() {
        let (exes, _) = collect_program_objects("", r"C:\Windows\System32\msiexec.exe /X{GUID}", "");
        assert!(exes.is_empty(), "msiexec 不该作为程序对象：{exes:?}");
    }

    /// U-1 + A2：内置残留规则库验签 + 整包语义校验自检（数据文件被改而 Node 门禁没跑时，
    /// `cargo test` 这一侧仍会抓住）。校验器就是运行期真身，不是测试专用的第二套口径。
    #[test]
    fn builtin_residue_rules_verify_and_contract() {
        let text = include_str!("../../data/uninstall-residue-rules.json");
        rules_signature::verify_rules_text(text).expect("内置残留规则库验签失败");
        let v: Value = serde_json::from_str(text).expect("内置残留规则库 JSON 解析失败");
        validate_residue_package(&v).expect("内置残留规则库语义校验未通过");
        let rules = v.get("rules").and_then(|r| r.as_array()).expect("rules 非数组");
        assert!(!rules.is_empty(), "rules 为空");
    }

    /// 夹具由 `node tools/gen-residue-fixture.mjs` 生成，与 `check-residue-rule-contract.mjs`
    /// 的独立实现共用（方案 §4.3 第三步 / §6.1：不跨语言调用，只靠同一组正反例钉口径）。
    /// 任何一侧放宽判定，另一侧就会在这里判红。
    #[test]
    fn residue_validator_matches_shared_fixture() {
        let raw = include_str!("../../../tools/fixtures/residue-contract.json");
        let f: Value = serde_json::from_str(raw).expect("残留契约夹具解析失败");
        let cases = f["packages"].as_array().expect("夹具缺 packages");
        let mut diff: Vec<String> = Vec::new();
        let mut rejected = 0;
        for c in cases {
            let label = c["label"].as_str().unwrap_or("?");
            let expect_ok = c["ok"].as_bool().unwrap_or(false);
            let got_ok = validate_residue_package(&c["pkg"]).is_ok();
            if !got_ok {
                rejected += 1;
            }
            if got_ok != expect_ok {
                diff.push(format!(
                    "{label}: 夹具要求{}，Rust 判为{}",
                    if expect_ok { "放行" } else { "整包拒绝" },
                    if got_ok { "放行" } else { "拒绝" }
                ));
            }
        }
        assert!(
            cases.len() >= 30 && rejected >= 25,
            "夹具用例数 {}（其中判红 {rejected}）过少，无法覆盖各保护类别",
            cases.len()
        );
        assert!(diff.is_empty(), "语义校验与夹具不一致：\n{}", diff.join("\n"));
    }

    /// A3 真网门禁（照 `cleanup::tests::rules_update_chain_verify` 的形状）：
    /// 逐源取包 → 验签 → 语义校验 → 版本比对，**只读不落盘**（不写用户数据目录）。
    /// 取不到源必须失败，不许 SKIP 当通过——`check-ps-substitution` 恒 SKIP 变死门禁是前车之鉴。
    /// 跑法：`cargo test --lib -- --ignored`
    #[test]
    #[ignore = "需要网络；发布前手动执行（只取包并校验，不落盘）"]
    fn residue_update_chain_verify() {
        let sources = residue_sources();
        assert!(!sources.is_empty(), "残留库没有可用更新源，本用例失去意义");
        let (version, text, source) =
            fetch_verified_residue_package().expect("至少一条源应能取到合签的残留规则包");
        assert!(version > 0.0, "rulesVersion 必须解析出来: {version}");
        assert!(text.contains("\"rules\""), "取回的不是规则包: {}B", text.len());
        let builtin_ver = serde_json::from_str::<Value>(BUILTIN_RESIDUE_RULES_JSON)
            .ok()
            .and_then(|b| b.get("rulesVersion").and_then(|x| x.as_f64()))
            .unwrap_or(0.0);
        assert!(
            version >= builtin_ver,
            "线上包版本({version})低于内置副本({builtin_ver})，发布链没跟上"
        );
        println!("[residue-update] 命中源={source} rulesVersion={version} 字节={}", text.len());
    }

    // ==================== C2 所有权状态机 / C3 阈值表 ====================

    fn ids_of(list: &[&str]) -> HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }
    const A_ID: &str = r"HKLM|SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Acme";

    /// 状态机全路径：pending 不被"点击卸载"直接升级成事实；程序消失且安装目录 ENOENT 才
    /// historical；目录还在就不升级；超稳定期回收；重装的 historical 撤销。
    #[test]
    fn ownership_state_machine_only_promotes_on_closed_evidence() {
        let norm = |s: &str| s.to_lowercase();
        let mut doc = ownership::empty_doc();
        assert!(ownership::record_pending(
            &mut doc, A_ID, "Acme", "Acme Corp", r"C:\Program Files\Acme", &[], 1000, norm
        ));
        assert_eq!(doc["owners"].as_array().unwrap().len(), 1);
        assert_eq!(doc["owners"][0]["state"], json!("pending"));
        // 再卸一次同一程序：刷新而不是叠记录
        assert!(ownership::record_pending(
            &mut doc, A_ID, "Acme", "Acme Corp", r"C:\Program Files\Acme", &[], 2000, norm
        ));
        assert_eq!(doc["owners"].as_array().unwrap().len(), 1, "同一 appId 必须刷新");
        assert_eq!(doc["owners"][0]["recordedAt"], json!(2000));

        // ① 程序仍在清单 → 继续 pending
        let exists_all = |_: &Path| true;
        let (p, r) = ownership::rescan(&mut doc, &ids_of(&[A_ID]), 3000, &exists_all);
        assert_eq!((p, r), (0, 0));
        assert_eq!(doc["owners"][0]["state"], json!("pending"));

        // ② 程序消失但安装目录还在 → 不升级（可能是半途退出/别人复用同目录）
        let (p, r) = ownership::rescan(&mut doc, &ids_of(&[]), 3000, &exists_all);
        assert_eq!((p, r), (0, 0), "安装目录仍在时不得升级");
        assert_eq!(doc["owners"][0]["state"], json!("pending"));

        // ③ 程序消失且目录 ENOENT → historical
        let gone = |_: &Path| false;
        let (p, r) = ownership::rescan(&mut doc, &ids_of(&[]), 3000, &gone);
        assert_eq!((p, r), (1, 0));
        assert_eq!(doc["owners"][0]["state"], json!("historical"));
        assert_eq!(doc["owners"][0]["confirmedAt"], json!(3000));

        // ④ 重装：historical 记录撤销（否则会被当成应用数据遗留来源）
        let (p, r) = ownership::rescan(&mut doc, &ids_of(&[A_ID]), 4000, &gone);
        assert_eq!((p, r), (0, 1));
        assert!(doc["owners"].as_array().unwrap().is_empty());

        // ⑤ pending 超稳定期 → 回收（卸载没继续的事实不该永久挂着）
        let mut doc2 = ownership::empty_doc();
        ownership::record_pending(&mut doc2, A_ID, "Acme", "", "", &[], 1000, norm);
        let later = 1000 + ownership::PENDING_TTL_MS + 1;
        let (_, removed) = ownership::rescan(&mut doc2, &ids_of(&[]), later, &exists_all);
        assert_eq!(removed, 1, "超稳定期的 pending 必须回收");
        assert!(doc2["owners"].as_array().unwrap().is_empty());
    }

    /// 忽略清单：既挡住后续再被记录，也让历史里的同一条消失（否则用户忽略了还反复出现）。
    #[test]
    fn ownership_ignore_stops_re_adopting_the_owner() {
        let norm = |s: &str| s.to_lowercase();
        let mut doc = ownership::empty_doc();
        ownership::record_pending(&mut doc, A_ID, "Acme", "", r"C:\Program Files\Acme", &[], 1000, norm);
        ownership::ignore(&mut doc, A_ID, "Acme", 2000, norm);
        assert!(doc["owners"].as_array().unwrap().is_empty(), "忽略后 owners 必须清空该条");
        assert!(ownership::is_ignored(&doc, A_ID, "acme"));
        assert!(
            !ownership::record_pending(&mut doc, A_ID, "Acme", "", "", &[], 3000, norm),
            "被忽略的 owner 不得重新记录"
        );
        // 同显示名、不同 hive 的条目也按名字挡住（同一款程序可能两处都有键）
        assert!(ownership::is_ignored(&doc, "HKCU|SOFTWARE\\x", "acme"));
    }

    /// 上限裁剪只动最旧的 historical，pending 有生命周期意义不被裁；
    /// 全是 pending 且超限时才动 pending（宁可丢历史也不无界增长）。
    /// HiBit §9.1 足迹差分的判据：时序（差集）+ 归属（token）+ 基线可信，三者缺一不可。
    #[test]
    fn footprint_diff_needs_timing_ownership_and_a_trustworthy_baseline() {
        let baseline = vec![
            r"HKCU\Software\Netease".to_string(),
            r"HKCU\Software\7-Zip".to_string(),
        ];
        let current = vec![
            r"HKCU\Software\Netease".to_string(),
            r"HKCU\Software\NETEASEGODLIKE".to_string(),
            r"HKCU\Software\Clash Verge Rev".to_string(),
        ];
        let fresh = footprint::new_keys_since(&baseline, &current);
        assert_eq!(fresh.len(), 2, "基线里没有的两条才算新增: {fresh:?}");
        let owner = json!({
            "displayName": "网易大神",
            "publisher": "Netease",
            "installLocation": r"C:\Games\GodLike",
            "ownedPaths": [r"C:\Games\GodLike\unins000.exe"]
        });
        let toks = footprint::tokens_of(&owner);
        assert!(
            footprint::key_belongs_to(r"HKCU\Software\NeteaseGodLike", &toks),
            "厂商段 + 产品段都在 token 里，这条必须有归属证据: {toks:?}"
        );
        assert!(
            !footprint::key_belongs_to(r"HKCU\Software\Clash Verge Rev", &toks),
            "别家程序的键不能算到这个 owner 头上"
        );
        // 基线缺失或被截断 = 不可信，差分侧必须整条跳过（不能拿半份基线去判"新键"）
        assert!(footprint::baseline_of(&json!({ "state": "historical" })).is_none());
        assert!(footprint::baseline_of(&json!({ "footprint": { "keys": [], "capped": true } })).is_none());
        assert_eq!(
            footprint::baseline_of(&json!({ "footprint": { "keys": ["a"], "capped": false } })),
            Some(vec!["a".to_string()])
        );
        // 结构性容器与 GUID 形态键都不是厂商落点
        for deny in [
            "Microsoft",
            "Classes",
            "WOW6432Node",
            "Policies",
            "RegisteredApplications",
            "appdatalow",
            "14d8c5cd-3d3a-5fb8-8746-849118a754ce",
            "x",
            "",
        ] {
            assert!(!footprint::is_vendor_key(deny), "{deny} 不该被当成厂商键");
        }
        assert!(footprint::is_vendor_key("NeteaseGodLike"));
        assert!(footprint::is_vendor_key("7-Zip"));
    }

    /// 基线写入的两个边界：owner 不在档里不写；超上限必须标 capped（差分侧据此拒产候选）。
    #[test]
    fn footprint_baseline_records_only_known_owner_and_flags_capped() {
        let mut doc = ownership::empty_doc();
        assert!(
            !ownership::set_footprint(&mut doc, "HKCU|X", &[r"HKCU\Software\X".to_string()], 1),
            "档里没有这个 owner 就不该凭空写基线"
        );
        let norm = |s: &str| s.to_lowercase();
        assert!(ownership::record_pending(
            &mut doc, "HKCU|X", "Acme", "", r"C:\Acme", &[], 1000, norm
        ));
        let many: Vec<String> = (0..=footprint::MAX_KEYS_PER_OWNER)
            .map(|i| format!(r"HKCU\Software\K{i}"))
            .collect();
        assert!(ownership::set_footprint(&mut doc, "HKCU|X", &many, 1500));
        let o = &doc["owners"][0];
        assert_eq!(o["footprint"]["capped"], json!(true), "超上限必须如实标截断");
        assert_eq!(
            o["footprint"]["keys"].as_array().unwrap().len(),
            footprint::MAX_KEYS_PER_OWNER
        );
        assert!(
            footprint::baseline_of(o).is_none(),
            "截断的基线不可信，差分必须跳过这一条"
        );
        assert!(ownership::set_footprint(&mut doc, "HKCU|X", &[r"HKCU\Software\Keep".to_string()], 2000));
        assert_eq!(
            footprint::baseline_of(&doc["owners"][0]),
            Some(vec![r"HKCU\Software\Keep".to_string()]),
            "刷新后要能读回，且 capped 标记跟着清掉"
        );
        // 空清单一律拒写：那会把"一个根都没枚举到"伪装成"这台机器没有厂商键"
        assert!(
            !ownership::set_footprint(&mut doc, "HKCU|X", &[], 2500),
            "空基线不能写进去，否则下一轮差分把全部现存键算成新键"
        );
        assert!(
            footprint::baseline_of(&doc["owners"][0]).unwrap().len() == 1,
            "被拒的写入不许留下半份基线"
        );
    }

    /// 真机足迹采集（`#[ignore]`）：三个 Software 根能枚举出厂商键集合，且**同一台机器上
    /// 连读两次的差集为空** —— 差分不稳定就说明采集在漂（排除表没生效或枚举被 cap 截断），
    /// 那这条链产出的"新键"全是假候选。
    #[test]
    #[ignore = "读注册表三个 Software 根，发布前门禁跑"]
    fn vendor_footprint_captures_real_keys_and_is_stable() {
        let a = unsafe { collect_vendor_keys() };
        assert!(
            a.len() >= 20,
            "本机实测三根有上百个顶层键，只取到 {} 条说明枚举或排除表坏了",
            a.len()
        );
        assert!(
            a.iter()
                .all(|k| k.starts_with(r"HKCU\Software\") || k.starts_with(r"HKLM\SOFTWARE\")),
            "目标串必须与执行侧同口径: {a:?}"
        );
        assert!(
            !a.iter().any(|k| k.to_lowercase().contains("\\microsoft")
                || k.to_lowercase().contains("\\classes")),
            "结构性容器漏排除: {a:?}"
        );
        let b = unsafe { collect_vendor_keys() };
        assert_eq!(
            footprint::new_keys_since(&a, &b),
            Vec::<String>::new(),
            "同一台机器连读两次不该差出新键"
        );
    }

    #[test]
    fn ownership_cap_prefers_dropping_oldest_historical() {
        let norm = |s: &str| s.to_lowercase();
        let pid = |i: usize| format!(r"HKLM|SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\P{i}");
        let mut doc = ownership::empty_doc();
        for i in 0..ownership::MAX_RECORDS {
            ownership::record_pending(
                &mut doc, &pid(i), "P", "", &format!(r"C:\Program Files\P{i}"), &[], 1000, norm,
            );
        }
        // ① 安装目录都还在 → 一条都不升级，也不裁（400 条刚好在上限内）
        let (p, r) = ownership::rescan(&mut doc, &ids_of(&[]), 1500, &|_: &Path| true);
        assert_eq!((p, r), (0, 0), "目录还在时不该有升级");
        assert_eq!(doc["owners"].as_array().unwrap().len(), ownership::MAX_RECORDS);

        // ② 越过上限：全部目录消失 → 升级为 historical，同时裁回上限
        ownership::record_pending(&mut doc, &pid(999), "P999", "", r"C:\Program Files\P999", &[], 1500, norm);
        let (p, _) = ownership::rescan(&mut doc, &ids_of(&[]), 1600, &|_: &Path| false);
        assert!(p >= 1, "目录消失后必须升级，实测 {p}");
        assert_eq!(
            doc["owners"].as_array().unwrap().len(),
            ownership::MAX_RECORDS,
            "超限必须裁回上限"
        );

        // ③ 混合形态：新进来的 pending 不许被裁，该裁的是最旧的 historical
        ownership::record_pending(&mut doc, &pid(1000), "Fresh", "", r"C:\Program Files\P1000", &[], 9000, norm);
        let (_, _) = ownership::rescan(&mut doc, &ids_of(&[]), 9500, &|p: &Path| {
            // 只有新记录的目录还在 → 它保持 pending，其余已在清单外且目录消失
            p.to_string_lossy().ends_with("P1000")
        });
        let owners = doc["owners"].as_array().unwrap();
        assert_eq!(owners.len(), ownership::MAX_RECORDS, "仍然超限即裁失败");
        assert!(
            owners.iter().any(|o| o["displayName"] == json!("Fresh") && o["state"] == json!("pending")),
            "新写入的 pending 被裁掉了"
        );
    }

    /// B6：体积兜底必须有界且诚实标注截断；不存在的目录与相对路径不接受。
    /// H5：顺带把命名数据流（ADS）算出来——这条是真跑 `FindFirstStreamW`，
    /// 不是打桩：ADS 的全部意义就是"本体之外还占着多少"，不落到真实文件系统上就验不到。
    #[test]
    fn bounded_dir_size_counts_files_and_flags_partial() {
        let dir = std::env::temp_dir().join(format!("trim-dirsize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub\\deep")).expect("临时目录");
        std::fs::write(dir.join("a.bin"), vec![b'1'; 1024]).expect("写文件");
        std::fs::write(dir.join("sub\\deep\\b.bin"), vec![b'2'; 2048]).expect("写文件");
        // 给 a.bin 挂一条 ADS（下载来源标记就是这个形状）。`文件:流名` 直接 open 即建流。
        let ads_body = b"ZoneId=0\r\nHostUrl=https://example.com/x";
        std::fs::write(dir.join("a.bin:Zone.Identifier"), ads_body.to_vec())
            .expect("写 ADS（非 NTFS 或策略禁用时本用例不适用）");
        let ds = bounded_dir_size(&dir);
        assert_eq!(ds.bytes, 3072, "两文件共 3072 字节: {}", ds.bytes);
        assert_eq!(ds.files, 2, "递归两层应数到两个文件");
        assert!(!ds.partial, "小规模不该报截断");
        assert_eq!(ds.ads_streams, 1, "应当只数到那一条命名流（默认流不计）: {ds:?}");
        assert_eq!(ds.ads_bytes as usize, ads_body.len(), "ADS 字节数必须与写入量一致: {ds:?}");
        // 文件数触顶：只数到上限个、必须标截断（哪个文件先被读到随枚举序变，所以只断上界）
        let ds1 = bounded_dir_size_in(&dir, 1, 8);
        assert_eq!(ds1.files, 1, "文件闸应把计数卡在上限");
        assert!(ds1.bytes < 3072, "截断后不该是完整金额: {}", ds1.bytes);
        assert!(ds1.partial, "有界截断却回 partial=false，UI 就会把半截值当完整值");
        // 层级触顶：sub/deep 在 depth=2，depth_cap=2 时进不去
        let ds2 = bounded_dir_size_in(&dir, 100, 2);
        assert!(ds2.partial, "深度闸命中必须上报截断");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// H6：`Staged` 子树**一个不漏**地进列表，且每一行都不可卸载。
    ///
    /// 期望值不写死、从注册表现算（`reg_enum_subkeys_pub` 与实现走的是同一份枚举）——
    /// 这样"漏读某一层"会当场红，而在没有商店包的机器上也不会靠 `count>0` 假装验过。
    #[test]
    fn appx_store_extras_covers_every_staged_package_and_is_never_removable() {
        use crate::engine::native;
        use std::collections::HashSet;
        use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
        const STORE: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore";

        let mut expected_staged = 0usize;
        let mut sample_family = String::new();
        for fam in native::reg_enum_subkeys_pub(HKEY_LOCAL_MACHINE, &format!(r"{STORE}\Staged")) {
            let kids = native::reg_enum_subkeys_pub(HKEY_LOCAL_MACHINE, &format!(r"{STORE}\Staged\{fam}"));
            if sample_family.is_empty() {
                sample_family = fam.clone();
            }
            expected_staged += kids.len();
        }

        let rows = enum_appx_store_extras(&HashSet::new());
        let staged = rows.iter().filter(|r| r["appxState"] == json!("staged")).count();
        assert_eq!(staged, expected_staged, "Staged 子树漏读（实现数 {staged} / 注册表数 {expected_staged}）");

        // 形状按渲染层消费口径断：`removable===false` 才是前端禁用按钮的判据，
        // 缺这个字段会被当成可卸载，等于把"当前用户删不掉"的包推去执行
        for r in &rows {
            assert_eq!(r["removable"], json!(false), "这一类必须显式不可卸载: {r}");
            let id = r["id"].as_str().unwrap_or("");
            let Some(full) = id.strip_prefix("APPX|") else {
                panic!("id 必须带 APPX| 前缀: {id}");
            };
            assert!(valid_appx_fullname(full), "包全名没过字符集闸: {full}");
            assert!(!r["reason"].as_str().unwrap_or("").is_empty(), "必须交代为什么不可卸载");
            // 发布商这一路是**哈希**不是 CN= 串：裸哈希上屏在厂商列看着像乱码，
            // 而且真机第一版因此把 `Microsoft.Services.Store.Engagement` 归进了「第三方」。
            let publ = r["publisher"].as_str().unwrap_or("—");
            assert!(!publ.contains("wekyb"), "发布商列出现裸哈希: {r}");
            if r["displayName"].as_str().unwrap_or("").to_lowercase().starts_with("microsoft") {
                assert_eq!(r["group"], json!("system"), "微软包被归成第三方: {r}");
            }
        }

        // 去重：已经在当前用户列表里的全名不得再出第二次（同一行出两次会被勾两次）
        if !sample_family.is_empty() {
            let kids = native::reg_enum_subkeys_pub(
                HKEY_LOCAL_MACHINE,
                &format!(r"{STORE}\Staged\{sample_family}"),
            );
            if let Some(first) = kids.first() {
                let mut seen = HashSet::new();
                seen.insert(first.clone());
                let again = enum_appx_store_extras(&seen);
                assert!(
                    again.iter().all(|r| r["id"] != json!(format!("APPX|{first}"))),
                    "seen 里的 {first} 又出了一次"
                );
            }
        }
    }

    #[test]
    fn prefetch_and_icon_parsers_refuse_guessing() {
        assert_eq!(prefetch_entry_exe("OBS64.EXE-2F3A1B4C.pf").as_deref(), Some("OBS64.EXE"));
        assert_eq!(prefetch_entry_exe("obs64.exe-2f3a1b4c.PF"), None, "扩展名大小写形态不认（Prefetch 全大写）");
        assert_eq!(prefetch_entry_exe("OBS64.EXE-2F3A1B4.pf"), None, "哈希位数不对不认");
        assert_eq!(prefetch_entry_exe("OBS64.EXE.pf"), None, "没有哈希段不认");
        assert_eq!(prefetch_entry_exe("readme.txt"), None);
        assert_eq!(exe_name_from_display_icon(r"C:\Apps\Foo\foo.exe,0").as_deref(), Some("FOO.EXE"));
        assert_eq!(exe_name_from_display_icon(r"C:\Apps\Foo\icon.dll,1"), None, "dll 不是主程序");
        assert_eq!(exe_name_from_display_icon(""), None);
    }

    /// C3：阈值表的排序本身就是判据（目录比快捷方式严），三条不许被"顺手统一"成一个数。
    #[test]
    fn name_threshold_table_keeps_risk_ordering() {
        assert!(
            NAME_MIN_SIMILAR > NAME_MIN_SHORTCUT,
            "整棵目录删除的门槛必须高于只删一个 .lnk 的门槛"
        );
        assert!(NAME_MIN_SHORTCUT >= NAME_MIN_RULE_WORD);
        assert_eq!(NAME_MIN_SIMILAR, 5);
        assert_eq!(NAME_MIN_SHORTCUT, 4);
        assert_eq!(NAME_MIN_RULE_WORD, 2, "2 是规则库短词门槛，与「至少两组条件」的 U-1 口径同源");
        // 精确同名那一档必须**低于**互含那一档：它是 HashMap 查表，不是猜测，
        // 沿用 5 会让所有 2-4 字中文产品名从所有权链上消失（2026-09-28 网易大神实测）。
        assert_eq!(NAME_MIN_EXACT, 2);
        assert!(
            NAME_MIN_EXACT < NAME_MIN_SIMILAR,
            "精确同名的容错应比互含猜测宽，不许被\"顺手统一\"回 5"
        );
        // 上限收口后各归一类：名称类 20、侧痕反查 20、exe 收集 16（三处不许再写死字面量）
        assert_eq!(NAME_HIT_CAP, 20);
        assert_eq!(SIDE_TRACE_CAP, 20);
        assert_eq!(PROGRAM_EXE_CAP, 16);
    }

    /// 同名多候选降级：判定依据是「父目录不同」，不是「条数多」——
    /// 同一目录下的多个子项不构成歧义。
    #[test]
    fn ambiguity_is_about_parents_not_counts() {
        assert!(!name_is_ambiguous(&[]));
        assert!(!name_is_ambiguous(&[r"C:\Program Files\Acme\a".to_string()]));
        assert!(
            !name_is_ambiguous(&[
                r"C:\Program Files\Acme\a".to_string(),
                r"C:\Program Files\Acme\b".to_string()
            ]),
            "同一父目录下的多条不构成归属歧义"
        );
        assert!(name_is_ambiguous(&[
            r"C:\Users\x\AppData\Roaming\Acme".to_string(),
            r"C:\Users\x\AppData\Local\Acme".to_string()
        ]));
    }

    /// A4 + A6：规则库目标里的 `%TOKEN%` 没解析出来时，必须报成「变量未解析」，
    /// 不能落到「目标不存在」那条分支上——后者是在告诉用户"这程序没留东西"，
    /// 而真相是"这台机器取不到这个变量"。同时钉住候选带 ruleId（面板要能回答谁产的）。
    #[test]
    fn residue_rule_unexpanded_token_is_reported_not_hidden() {
        let rules = json!({ "rules": [{
            "id": "residue-unexpanded-probe",
            "displayName": ["探针程序"],
            "publisher": ["ProbeSoft"],
            "uninstallKey": [],
            "residue": [
                { "kind": "folder", "target": r"%TRIM_NO_SUCH_VAR%\Data", "note": "未解析变量目标" },
                { "kind": "folder", "target": r"%APPDATA%\ProbeMissing-9f3a", "note": "解析成功但不存在" },
            ],
        }]});
        let (out, vetoed) = residue_rules_hits(&rules, "探针程序", "ProbeSoft", r"Software\X\Uninstall\Probe", false);
        assert!(out.is_empty(), "两条都不该出候选: {out:?}");
        let joined = vetoed.join("\n");
        assert!(
            joined.contains("未解析变量 %TRIM_NO_SUCH_VAR%"),
            "未展开目标必须显式报出变量名，实测 {vetoed:?}"
        );
        // 反面对照：变量解析成功、只是路径不存在 —— 不能被说成变量问题
        assert!(
            !joined.contains("ProbeMissing") && !joined.contains("%APPDATA%"),
            "已解析的目标不该进未解析清单: {vetoed:?}"
        );
        // 命中且存在 → 候选必须带 ruleId（A6）
        let dir = std::env::temp_dir();
        let rules2 = json!({ "rules": [{
            "id": "residue-ruleid-probe",
            "displayName": ["探针程序"],
            "publisher": ["ProbeSoft"],
            "uninstallKey": [],
            "residue": [{ "kind": "folder", "target": dir.to_string_lossy().to_string(), "note": "存在的目录" }],
        }]});
        let (out2, _) = residue_rules_hits(&rules2, "探针程序", "ProbeSoft", r"Software\X\Uninstall\Probe", false);
        assert_eq!(out2.len(), 1, "存在的目标应出候选: {out2:?}");
        assert_eq!(out2[0]["ruleId"], json!("residue-ruleid-probe"), "候选必须带 ruleId: {out2:?}");
    }

    /// 运行进程目录判定：候选与进程目录互为祖先/子孙都算在用；大小写与尾随分隔符不许绕过。
    #[test]
    fn running_process_ancestry_blocks_candidates() {
        let mut procs = HashSet::new();
        procs.insert(r"c:\program files\acme\bin".to_lowercase());
        assert!(under_running_process(Path::new(r"C:\Program Files\Acme"), &procs));
        assert!(under_running_process(Path::new(r"C:\Program Files\Acme\bin"), &procs));
        // 候选在运行进程目录**里面**：只查祖先就会漏掉这一半
        assert!(
            under_running_process(Path::new(r"C:\Program Files\Acme\bin\plugins"), &procs),
            "候选位于正在运行的进程目录之内，必须视为在用"
        );
        assert!(!under_running_process(Path::new(r"D:\Data\Other"), &procs));
        // 同盘但毫不相干的目录 —— M4 真机缺陷的回归钉：旧实现走 `dir.ancestors()`，
        // 走到 `C:\` 时任何进程路径都 starts_with 它，于是**全盘恒为在用**，
        // 应用数据遗留链在任何机器上都产不出一个候选（2026-09-29 探针实测暴露）。
        assert!(
            !under_running_process(Path::new(r"C:\Users\x\AppData\Local\SomeLeftover"), &procs),
            "同盘无关目录不得被判成在用"
        );
        // 同级兄弟前缀不许互相污染（裸字符串前缀比就会）
        let mut sib = HashSet::new();
        sib.insert(r"c:\program files\acmebackup".to_string());
        assert!(
            !under_running_process(Path::new(r"C:\Program Files\Acme"), &sib),
            r"按裸前缀比会把兄弟目录 acmebackup 误判进 Acme 的树里"
        );
        // 快照为空（取不到）时不该放行任何候选 —— 由调用方按 None 拒绝扫描
        assert!(!under_running_process(Path::new(r"C:\Program Files\Acme"), &HashSet::new()));
    }

    /// 可弃子目录清单必须与 norm_name 的输出同形（小写、无首尾空白）——
    /// 否则条目永远匹配不上，成了一条静默失效的白名单。
    #[test]
    fn disposable_subdir_names_are_normalized() {
        for name in ORPHAN_DISPOSABLE_SUBDIRS {
            assert_eq!(&norm_name(name), name, "清单里的 {name} 不是归一化形态，永远不会命中");
        }
        assert!(ORPHAN_SCAN_ROOTS.contains(&"LOCALAPPDATA"), "应用数据遗留扫描必须覆盖用户级数据根");
    }

    /// A1 扫描侧硬闸：受保护的注册表目标**不得进候选列表**。
    /// 快照闸只证明「来自上次扫描」，证明不了「不该删」—— 危险候选本来就是扫描器按
    /// 规则产出的，所以收口点必须在产候选这一层（方案 §4.1）。
    #[test]
    fn protected_reg_target_never_becomes_candidate() {
        let pkg = json!({
            "rulesVersion": 20260928,
            "prov": [{ "sourceClass": "test", "reviewedAt": "2026-09-28" }],
            "rules": [{
                "id": "fixture-evil",
                "displayName": ["EvilApp"],
                "publisher": ["EvilCorp"],
                "uninstallKey": ["EvilApp"],
                "residue": [
                    { "kind": "reg_key", "target": "HKLM\\SOFTWARE", "note": "整棵软件配置" },
                    { "kind": "reg_key", "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "note": "自启动" },
                    { "kind": "reg_key", "target": "HKLM\\SYSTEM", "note": "系统配置" }
                ]
            }]
        });
        let (hits, vetoed) = residue_rules_hits(&pkg, "EvilApp 1.0", "EvilCorp", "EvilApp", false);
        assert!(hits.is_empty(), "受保护注册表目标进入了候选列表: {hits:?}");
        assert_eq!(
            vetoed.len(),
            3,
            "三条危险目标都应各自给出否决原因（祖先/命名空间树/整棵禁删各一类）: {vetoed:?}"
        );
    }

    /// HiBit §H3 的全部安全支点：**学习库复用签名库那一个校验器**，不另开一套。
    /// 这条测试就是钉住它——哪天学习库加了自有字段（字段白名单不放）、或改了 kind，
    /// 这里当场红，而不是等装载时在用户机器上把整库隔离掉才发现。
    #[test]
    fn learned_doc_is_valid_under_the_signed_library_validator() {
        let mut doc = learned::empty_doc();
        let entries = vec![
            ("folder", r"C:\Users\me\AppData\Roaming\ProbeSoft\cache".to_string()),
            ("reg_key", r"HKCU\Software\ProbeSoft\Settings".to_string()),
        ];
        let n = learned::learn(
            &mut doc,
            "ProbeSoft 测试程序",
            "ProbeCorp",
            r"Software\X\Uninstall\ProbeSoft",
            &entries,
            1,
        );
        assert_eq!(n, 2, "两条落点都该学到: {doc}");
        validate_residue_package(&doc).expect("学习库文档必须过签名库同一个校验器");
        let rules = doc["rules"].as_array().cloned().unwrap_or_default();
        assert_eq!(rules.len(), 1);
        // 双条件组是 U-1 口径：displayName + uninstallKey 必须都在，缺一组校验器整包拒
        assert!(!rules[0]["displayName"].as_array().unwrap().is_empty());
        assert!(!rules[0]["uninstallKey"].as_array().unwrap().is_empty());
        let id = rules[0]["id"].as_str().unwrap_or("");
        assert!(
            id.starts_with("learned-") && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "学习库 id 不合签名库字符集白名单（中文名不能直接当 id）: {id}"
        );
        // 纯函数侧：坏 JSON 与语义不合都必须是 Err（装载侧据此隔离停用，不尽力解析）
        assert!(learned::from_text("not json").is_err());
        assert!(learned::from_text(r#"{"rulesVersion":1,"prov":[],"rules":[]}"#).is_err());
        assert!(learned::from_text(&doc.to_string()).is_ok(), "learn() 的产物必须能被 load 侧原样接受");
    }

    /// 学习库特有的三道收紧。缺任何一道，本机自采数据都会把「共享容器」或「厂商顶层键」
    /// 学成下次可直接勾选的残留——签名库有人审，学习库没有。
    #[test]
    fn learned_floor_rejects_shared_and_shallow_targets() {
        // token 必须是显示名的**真实小写形态**（`ProbeSoft` → `probesoft`）。第一版手写成
        // `probsoft`（少一个 e），实现被假断言判成错，我围着它调试了两轮 —— 归属类断言的
        // 期望值应由被测的同一条派生链给出，不要手抄字面量。
        let tokens = vec!["probesoft 测试程序".to_string(), "probcorp".to_string()];
        // 归属：路径里没有任何一段属于这程序 ⇒ 不学（Recent 是全家共享容器）
        assert!(learned::target_reject_reason(
            "folder",
            r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Recent",
            &tokens
        )
        .is_some());
        assert!(
            learned::target_reject_reason("folder", r"C:\Users\me\SomeRandomDir", &tokens).is_some(),
            "候选自己的末段不能当归属证据（第一版把 ownedPaths 喂进 token 集就在这里假过）"
        );
        assert!(
            learned::target_reject_reason("folder", r"C:\Users\me\AppData\Roaming\ProbeSoft\cache", &tokens)
                .is_none(),
            "有归属段就该放行，实得拒绝原因: {:?}",
            learned::target_reject_reason("folder", r"C:\Users\me\AppData\Roaming\ProbeSoft\cache", &tokens)
        );
        // 注册表深度：厂商顶层键（hive 之下 2 段）不学，三段才学
        assert!(learned::target_reject_reason("reg_key", r"HKCU\Software\ProbeSoft", &tokens).is_some());
        assert!(learned::target_reject_reason("reg_key", r"HKCU\Software\ProbeSoft\Settings", &tokens).is_none());
        // 禁删面：A1 那条清单**刻意没有深度规则**（有就会误拒 `HKLM\SOFTWARE\ESET` 这类
        // 合法二级产品键），所以 `HKLM\SOFTWARE\ProbeSoft\X` 该放行——它归属成立、深度够。
        // 真正必须拒的是整棵容器与命名空间树这两类。
        assert!(
            learned::target_reject_reason("reg_key", r"HKLM\SOFTWARE", &tokens).is_some(),
            "整棵 SOFTWARE 必须被禁删面拒"
        );
        assert!(learned::target_reject_reason(
            "reg_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            &tokens
        )
        .is_some());
        assert!(learned::target_reject_reason("reg_key", r"HKLM\SOFTWARE\ProbeSoft\X", &tokens).is_none());
        assert!(learned::target_reject_reason("shortcut", r"C:\x\ProbeSoft.lnk", &tokens).is_some());
    }

    /// 证据等级分岔必须**由参数产生**，不能靠产出后再改字段：签名库那条
    /// `defaultChecked: true` 正是靠这条链把候选默认勾上的，学习库若走同一条路，
    /// 「本机猜的」就会被界面当成「官方规则」推荐。
    #[test]
    fn learned_hits_are_never_auto_checked_while_signed_hits_are() {
        // 命中链要求目标**真实存在**（不存在的落点不该出现在面板里，这是生产语义），
        // 所以这里在临时目录下建一个真目录并挂 Drop 清掉；固定假路径会让两条链都空手而归，
        // 断言就退化成「什么都没发生也算过」。
        let dir = std::env::temp_dir().join(format!("trim-learn-{}", std::process::id()));
        let sub = dir.join("ProbeSoftCache");
        std::fs::create_dir_all(&sub).expect("建临时命中目标");
        struct Clean(std::path::PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _clean = Clean(dir.clone());
        let target = sub.to_string_lossy().to_string();

        let doc = json!({
            "rulesVersion": 1.0,
            "prov": [{ "sourceClass": learned::LEARNED_SOURCE_CLASS, "reviewedAt": "本机自采 x" }],
            "rules": [{
                "id": "learned-abc123",
                "displayName": ["ProbeSoft"],
                "publisher": ["ProbeCorp"],
                "uninstallKey": ["ProbeSoft"],
                "residue": [{ "kind": "folder", "target": target, "note": "本机自采" }]
            }]
        });
        let (learned_hits, _) = residue_rules_hits(
            &doc,
            "ProbeSoft",
            "ProbeCorp",
            r"Software\X\Uninstall\ProbeSoft",
            true,
        );
        assert_eq!(learned_hits.len(), 1, "学习库命中链断了: {learned_hits:?}");
        assert_eq!(learned_hits[0]["defaultChecked"], json!(false), "学习库候选不得默认勾选");
        assert_eq!(learned_hits[0]["confidence"], json!("medium"), "学习库证据上限是 medium");
        assert!(
            learned_hits[0]["reason"].as_str().unwrap_or("").contains("本机学习库"),
            "候选必须交代自己是本机学习库而不是官方规则: {}",
            learned_hits[0]["reason"]
        );
        // 同一份文档按签名库口径跑必须还是 high + 默认勾选——参数没分岔就是假绿
        let (signed_hits, _) = residue_rules_hits(
            &doc,
            "ProbeSoft",
            "ProbeCorp",
            r"Software\X\Uninstall\ProbeSoft",
            false,
        );
        assert_eq!(signed_hits.len(), 1);
        assert_eq!(signed_hits[0]["defaultChecked"], json!(true));
        assert_eq!(signed_hits[0]["confidence"], json!("high"));
    }

    /// 学不到东西的情形必须**整条不写**，而不是写一份下一轮会被校验器拒掉的文档。
    #[test]
    fn learn_skips_when_identity_or_targets_are_unusable() {
        let base = |name: &str, publisher: &str, entries: Vec<(&str, String)>| {
            let mut doc = learned::empty_doc();
            learned::learn(&mut doc, name, publisher, r"Software\X\Uninstall\ProbeSoft", &entries, 1)
        };
        assert_eq!(base("ProbeSoft", "ProbeCorp", vec![]), 0, "没有落点不写");
        assert_eq!(base("", "ProbeCorp", vec![("folder", r"C:\x\ProbeSoft".to_string())]), 0, "没有程序名不写");
        // 显示名 + 卸载键末段已经是两组，publisher 空不该把它判死
        assert!(
            base("ProbeSoft", "", vec![("folder", r"C:\x\ProbeSoft".to_string())]) > 0,
            "双条件组应成立"
        );
        // 全部落点过不了归属 ⇒ 一条都不学，且不留空规则（空 residue 会被校验器整包拒）
        let mut doc = learned::empty_doc();
        let n = learned::learn(
            &mut doc,
            "ProbeSoft",
            "ProbeCorp",
            r"Software\X\Uninstall\ProbeSoft",
            &[("folder", r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Recent".to_string())],
            1,
        );
        assert_eq!(n, 0, "无归属落点不该学: {doc}");
        assert!(doc["rules"].as_array().map(|a| a.is_empty()).unwrap_or(false), "不该留下空规则");
    }

    /// D3 + C1：残留执行的单一判定入口（不依赖真机）。判定收进 classify_residue_op 之后，
    /// 一个函数就能把六道只读闸全测到 —— 取代原先只覆盖目录重解析那一段的测试。
    /// D1/D2：备份文件名白名单与封条命名。还原是**写注册表**的通道，
    /// 文件名是唯一决定"读哪个文件去 import"的输入，必须挡住穿越与非 .reg。
    #[test]
    fn reg_backup_name_and_seal_paths_are_narrowed() {
        assert!(valid_uninstall_backup_name("1790561031234_ESET.reg"));
        assert!(valid_uninstall_backup_name("1790561031234_acme_RASAPI32.reg"));
        for bad in [
            "",
            "x.txt",
            "../1_x.reg",
            r"..\..\windows.reg",
            "a/b.reg",
            "a reg.reg",
            "1_x.reg.meta.json", // 封条自身不得被当成备份列出/还原
            &format!("{}.reg", "s".repeat(200)),
        ] {
            assert!(!valid_uninstall_backup_name(bad), "非法文件名被放行: {bad}");
        }
        // 封条同目录、后缀固定：人工核对时一眼能找到，列表按 .reg 收尾天然排除它
        let p = std::path::PathBuf::from(r"C:\x\1_a.reg");
        assert_eq!(
            crate::engine::reg_backup::reg_seal_path_for(&p),
            std::path::PathBuf::from(r"C:\x\1_a.reg.meta.json"),
        );
    }

    #[test]
    fn classify_residue_op_gates_run_before_any_mutation() {
        let skip_msg = |kind: &str, target: &str| -> Option<String> {
            match classify_residue_op(kind, target) {
                OpVerdict::Skip(m) => Some(m),
                OpVerdict::Ready(_) => panic!("{kind} 不该通过判定: {target}"),
                OpVerdict::Abort(m) => panic!("{kind} 不该整批拒绝: {m}"),
            }
        };
        let ghost = std::env::temp_dir().join("trim-no-such-dir-9f3a\\DataStore");
        let ghost_s = ghost.to_string_lossy().to_string();

        // ① 不存在的目录/文件：Skip 且给原因（原先被静默滤掉，批次报告里连一行都没有）
        assert!(skip_msg("folder", &ghost_s).unwrap_or_default().contains("不存在"));
        assert!(skip_msg("file", &ghost_s).unwrap_or_default().contains("不存在"));
        // ② 受保护路径：整批拒绝，不降级成单项跳过。用 %WINDIR% 而不是应用数据目录——
        // 后者只在 `configure_from_app()` 跑过之后才进 subtree 清单，单测环境里没有那一步
        let win = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
        match classify_residue_op("folder", &win) {
            OpVerdict::Abort(m) => assert!(m.contains("受保护"), "实测: {m}"),
            _ => panic!("系统根目录必须触发整批拒绝"),
        }
        // ③ A1 硬否决：受保护注册表容器 Skip 且带原因
        let m = skip_msg("reg_key", "HKLM\\SOFTWARE").unwrap_or_default();
        assert!(m.contains("已拒绝删除"), "实测: {m}");
        // ④ 合法形状但不存在的注册表键
        assert!(skip_msg(
            "reg_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TrimNoSuch-9f3a"
        )
        .unwrap_or_default()
        .contains("已不存在"));
        // ⑤ reg_value 形状闸：缺 :: 与值名为空都要出局
        assert!(skip_msg("reg_value", r"HKCU\Software\Acme").unwrap_or_default().contains("::"));
        assert!(skip_msg("reg_value", r"HKCU\Software\Acme::").unwrap_or_default().contains("为空"));
        // ⑥ 未知 kind 不静默放行
        assert!(skip_msg("whatever", r"C:\x").unwrap_or_default().contains("未知残留类型"));
        // ⑦ 真实系统目录（整条链非 reparse、不属保护面）应进入变更清单
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let sys32 = format!("{}\\Windows\\System32", drive.trim_end_matches('\\'));
        assert!(
            matches!(classify_residue_op("folder", &sys32), OpVerdict::Ready(_)),
            "真实系统目录被误拦: {sys32}"
        );
    }

    /// A3 更新链的校验序（尺寸 → 验签 → JSON → **语义** → 版本）。
    /// 正例直接用内置库原文：它是签过名的合法包，于是「happy path」不必联网、
    /// 也不需要在测试里造第二把私钥（私钥只在发布机 `~/.trim-signing/`）。
    #[test]
    fn residue_remote_package_gate_accepts_the_signed_builtin() {
        let builtin = include_str!("../../data/uninstall-residue-rules.json");
        let ver = verify_residue_remote_text(builtin, 0.0).expect("内置签名库必须能过更新链校验");
        assert!(ver > 0.0, "版本必须解析出来: {ver}");
        // 防降级：下限高于它就必须拒（重放旧签名包的路径）
        let err = verify_residue_remote_text(builtin, ver + 1.0).expect_err("低于下限必须拒绝");
        assert!(err.contains("防回滚下限"), "文案要指向防降级，实测: {err}");
    }

    /// 尺寸闸的两侧都要能判红；且**不共用清理域的 4096B 下限**——
    /// 残留库只有 6 条规则，共用会把合法的小包当异常响应拒了。
    #[test]
    fn residue_size_gates_reject_both_ends() {
        assert!(
            RESIDUE_RULES_MIN_SIZE < 4096 || RESIDUE_BUILTIN_LEN / 2 >= 4096,
            "下限与内置库量级脱节：内置 {RESIDUE_BUILTIN_LEN}B，下限 {RESIDUE_RULES_MIN_SIZE}B"
        );
        let small = "x".repeat(RESIDUE_RULES_MIN_SIZE - 1);
        let e1 = verify_residue_remote_text(&small, 0.0).expect_err("过小必须拒");
        assert!(e1.contains("过小"), "实测: {e1}");
        let big = "x".repeat(RESIDUE_RULES_MAX_SIZE + 1);
        let e2 = verify_residue_remote_text(&big, 0.0).expect_err("过大必须拒");
        assert!(e2.contains("过大"), "实测: {e2}");
    }

    /// 更新链必须先过语义校验（与装载侧同一个函数）：验签通过但字段不合规的包
    /// 不能因为「是更新流进来的」就放行——否则会出现更新放行、装载拒绝的分叉。
    #[test]
    fn residue_update_gate_calls_the_same_semantic_validator() {
        // 顶层塞一个未知字段：JSON 合法、尺寸够、但语义必拒（验签会先失败，
        // 所以这里直接断言校验器本身在这类包上判红，序位由上一条测试覆盖）
        let mut pkg: Value = serde_json::from_str(BUILTIN_RESIDUE_RULES_JSON).unwrap();
        pkg.as_object_mut().unwrap().insert("__smoke_extra".to_string(), json!(1));
        let err = validate_residue_package(&pkg).expect_err("未知字段必须整包拒");
        assert!(err.contains("未知字段"), "实测: {err}");
    }

    // ==================== M2 静默知识（B1 构造闸 / B2 分档 / B4 第二证据） ====================

    fn exists_all(_: &Path) -> bool {
        true
    }
    fn exists_none(_: &Path) -> bool {
        false
    }

    /// B1 构造闸：每一类「无法静态证明安全」的形态都要拒。逐类一条，缺一条就是漏一种绕过面
    /// —— 静默串来自注册表，是软件自己能写的字段，不能当成可信输入。
    #[test]
    fn quiet_string_gate_rejects_each_unsafe_shape() {
        let cases = [
            (r"C:\Windows\System32\cmd.exe".to_string(), "/c del C:\\x".to_string(), "宿主"),
            (
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
                "-Command Remove-Item".to_string(),
                "宿主",
            ),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S | more".to_string(), "管道"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S & calc".to_string(), "复合命令"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S && taskkill".to_string(), "复合命令"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S > C:\\x\\log.txt".to_string(), "重定向"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S < NUL".to_string(), "重定向"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S ; reboot".to_string(), "分号"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S $env:FOO".to_string(), "变量"),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S `whoami`".to_string(), "反引号"),
            (
                r"C:\Program Files\Foo\u.exe".to_string(),
                "/D=\"%ProgramFiles%\\Foo\"".to_string(),
                "变量替换",
            ),
            (r"C:\Program Files\Foo\u.exe".to_string(), "/S \"unclosed".to_string(), "引号"),
            ("unins000.exe".to_string(), "/S".to_string(), "绝对路径"),
            (r"\\server\share\u.exe".to_string(), "/S".to_string(), "绝对路径"),
            (r"C:\Program Files\Foo\setup.msi".to_string(), "/quiet".to_string(), ".exe"),
        ];
        for (exe, args, label) in cases {
            let reason = quiet_string_reject_reason(&exe, &args, &exists_all);
            assert!(
                reason.is_some(),
                "[{label}] 该形态必须被拒：exe={exe:?} args={args:?}"
            );
        }
        // 存在性也是闸的一部分：路径写法都对但文件不存在同样不放行
        assert!(
            quiet_string_reject_reason(r"C:\Program Files\Foo\u.exe", "/S", &exists_none).is_some(),
            "文件不存在的厂商串必须被拒"
        );
    }

    /// 正例：字面的「绝对路径 exe + 参数」必须放行，含 NSIS 常见的 `/D="路径"` 形态。
    #[test]
    fn quiet_string_gate_admits_literal_absolute_command() {
        for (exe, args) in [
            (r"C:\Program Files\Foo\unins000.exe", "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART"),
            (r"C:\Program Files (x86)\Foo\uninstall.exe", "/S /D=C:\\Program Files\\Foo"),
            (r"D:\Foo\u.exe", "/S /D=\"C:\\Program Files\\Foo Data\""),
        ] {
            assert_eq!(
                quiet_string_reject_reason(exe, args, &exists_all),
                None,
                "合法厂商串被误拒: {exe} {args}"
            );
        }
    }

    /// B1 优先级：厂商静默串存在且过闸 → 用它，不再本地拼参数（BCU silentIfAvailable 的口径）。
    #[test]
    fn vendor_quiet_string_wins_over_whitelist() {
        let original = (
            r"C:\Program Files\Foo\uninstall.exe".to_string(),
            "/S".to_string(),
        );
        let quiet = r#""C:\Program Files\Foo\unins000.exe" /VERYSILENT /NORESTART"#;
        let c = pick_silent_candidate("nsis", None, &original, Some(quiet), &exists_all).expect("应有静默候选");
        assert_eq!(c.source, "vendor", "厂商串过闸后必须优先于白名单派生");
        assert_eq!(c.exe, r"C:\Program Files\Foo\unins000.exe");
        assert_eq!(c.args, "/VERYSILENT /NORESTART");
        assert!(c.vendor_reject.is_none());
    }

    /// B1 回退：厂商串被拒 → 退回白名单派生并**留下拒绝原因**；两类都不可用 → None（原厂 UI）。
    #[test]
    fn rejected_vendor_falls_back_to_whitelist_then_to_original_ui() {
        let original = (r"C:\Program Files\Foo\unins000.exe".to_string(), String::new());
        let bad = r"C:\Windows\System32\cmd.exe /c C:\Program Files\Foo\unins000.exe /S";
        let c = pick_silent_candidate("inno", None, &original, Some(bad), &exists_all).expect("白名单派生要接住");
        assert_eq!(c.source, "whitelist");
        assert_eq!(c.args, "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART");
        let reason = c.vendor_reject.expect("必须记录厂商串被拒的原因");
        assert!(reason.contains("宿主"), "原因要点明是哪一类风险，实测: {reason}");

        // 非白名单类型 + 无可用厂商串 → 不猜静默，交回原厂界面
        assert!(
            pick_silent_candidate("unknown", None, &original, None, &exists_all).is_none(),
            "unknown 类型不得凭空造静默命令"
        );
        // MSI 仍按产品码派生（原行为不受 B1 影响）
        let msi = pick_silent_candidate(
            "msi",
            Some("{1D180B6A-C6AE-4D6E-A2A8-000000001001}"),
            &original,
            None,
            &exists_all,
        )
        .expect("msi 应产出静默候选");
        assert_eq!(msi.exe, "msiexec.exe");
        assert!(msi.args.starts_with("/X{1D180B6A") && msi.args.contains("/qn /norestart"));
    }

    /// B2 分档：语义与「是否回退原厂界面」成对钉住。
    /// 用户取消(1602) 与并发安装(1618) **不回退**（2026-09-28 裁定：取消是用户决定，
    /// 自动重弹界面等于无视取消；1618 的有界重试要真机证据才定）。
    #[test]
    fn exit_codes_classified_with_fallback_decision() {
        let cases = [
            (0u32, "卸载成功", false),
            (3010, "卸载成功，需重启完成", false),
            (1605, "产品未安装（该卸载键已无对应产品）", false),
            (1602, "用户取消", false),
            (1618, "另一个安装或卸载正在进行，请稍后再试", false),
            (1603, "安装器内部错误", true),
            // 未确认语义的码（含 NSIS 的 1/2）保持原行为：回退原厂界面
            (1, "其它退出码", true),
            (2, "其它退出码", true),
            (1619, "其它退出码", true),
        ];
        for (code, meaning, fall_back) in cases {
            let got = classify_exit(code);
            assert_eq!(got.0, meaning, "退出码 {code} 的语义文案漂移");
            assert_eq!(got.1, fall_back, "退出码 {code} 的回退决策应为 {fall_back}");
        }
    }

    /// B4 第二证据：只认独有文件名。`uninstall.exe` 太通用，认了就等于把 `/S` 发给
    /// 未知卸载器 —— 识别可以弱，执行不能猜。
    #[test]
    fn second_evidence_only_recognizes_own_names() {
        let by_name = |want: &'static str| move |p: &Path| {
            p.file_name().and_then(|n| n.to_str()) == Some(want)
        };
        assert_eq!(
            second_evidence_kind(r"C:\Program Files\Foo", &by_name("unins000.exe")),
            Some("inno")
        );
        assert_eq!(
            second_evidence_kind(r"C:\Program Files\Foo", &by_name("nsisunins.exe")),
            Some("nsis")
        );
        assert_eq!(
            second_evidence_kind(r"C:\Program Files\Foo", &by_name("uninstall.exe")),
            None,
            "通用名不得被当成 NSIS"
        );
        // 输入不可信：空串、无盘符、超长一律不探
        let exists_all2 = |_: &Path| true;
        assert!(second_evidence_kind("", &exists_all2).is_none());
        assert!(second_evidence_kind("Foo\\Bar", &exists_all2).is_none());
        assert!(second_evidence_kind(&format!("C:\\{}", "a".repeat(300)), &exists_all2).is_none());
        // 尾随分隔符不能把探测变成目录本身
        assert_eq!(
            second_evidence_kind(r"C:\Program Files\Foo\", &by_name("unins000.exe")),
            Some("inno")
        );
    }
    /// M6：注册表里记着的落点写法五花八门，解析必须"认不出就无证据"，
    /// 而不是"猜一个路径出来判它不存在"。下面每条都是真机见过的形态。
    #[test]
    fn dead_landing_parses_registry_forms() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let cases: &[(&str, Option<&str>)] = &[
            (r#""C:\Program Files\Foo\unins000.exe" /SILENT"#, Some(r"C:\Program Files\Foo\unins000.exe")),
            (r"C:\Program Files\AntiCheatExpert\ACE-CORE102706.sys", Some(r"C:\Program Files\AntiCheatExpert\ACE-CORE102706.sys")),
            (r"C:\Windows\System32\svchost.exe -k netsvcs", Some(r"C:\Windows\System32\svchost.exe")),
            (r"\??\C:\Windows\System32\drivers\ACEX.sys", Some(r"C:\Windows\System32\drivers\ACEX.sys")),
            (r"\\server\share\unins000.exe /S", Some(r"\\server\share\unins000.exe")),
            // 认不出的一律 None —— 把"判不出来"当成"不存在"就是假阳性的来源
            ("notepad.exe", None),
            (r"C:\Program Files\Foo\launcher", None),
            (r"cmd /c del C:\x", None),
            (r"%NO_SUCH_TRIM_VAR%\a.exe", None),
            ("", None),
        ];
        for (raw, want) in cases {
            assert_eq!(dead_landing(raw).as_deref(), *want, "落点解析不符: {raw:?}");
        }
        // %SystemRoot% 展开依赖本机环境，只断前缀不断全串
        let exp = dead_landing(r"%SystemRoot%\system32\foo.exe").unwrap_or_default();
        assert!(
            exp.to_lowercase().starts_with(&windir.to_lowercase()),
            "变量没展开: {exp}"
        );
        // 未闭合引号不许把整串（含参数）当路径
        assert_eq!(dead_landing(r#""C:\Program Files\Foo\unins000.exe /S"#), None);
    }

    /// M6 卸载项判据：全部落点缺失才算失效；MSI 产品码键要求两条落点。
    /// C4 的贡献项断言也挂在这里——这两个函数的判据是同一条证据链。
    #[test]
    fn dead_uninstall_needs_every_landing_missing() {
        let present: std::collections::HashSet<String> = [
            r"C:\Program Files\Alive",
            r"C:\Program Files\Alive\unins000.exe",
            r"C:\Program Files\Half\unins000.exe",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let exists = |p: &str| present.iter().any(|x| x.eq_ignore_ascii_case(p));
        let mk = |name: &str, key: &str, install: &str, un: &str| DeadUninstallRaw {
            hive: "HKLM".to_string(),
            key: key.to_string(),
            path: format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{key}"),
            name: name.to_string(),
            install: install.to_string(),
            uninstall: un.to_string(),
            quiet: String::new(),
            last_write_ms: Some(1_700_000_000_000),
        };
        let guid = "{1D4E2B7A-2F3C-4D5E-8A9B-0C1D2E3F4A5B}";
        let rows = vec![
            mk("Alive", "Alive", r"C:\Program Files\Alive", r"C:\Program Files\Alive\unins000.exe"),
            mk("Half", "Half", r"C:\Program Files\Half", r"C:\Program Files\Half\unins000.exe"),
            mk("Gone", "Gone", r"C:\Program Files\Gone", r"C:\Program Files\Gone\unins000.exe"),
            mk("NoLanding", "NoLanding", "", ""),
            mk("RelativeOnly", "RelativeOnly", "", "unins000.exe"),
            mk("", "Nameless", r"C:\Program Files\Nameless", r"C:\Program Files\Nameless\u.exe"),
            mk("MsiOne", guid, r"C:\Program Files\MsiOne", ""),
        ];
        let out = dead_uninstall_findings(&rows, &exists, 1_700_000_900_000);
        let targets: Vec<&str> = out.iter().map(|f| f["target"].as_str().unwrap_or("")).collect();
        assert_eq!(
            targets,
            vec![r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Gone"],
            "候选集合不符（半存活/无落点/相对名/无名/MSI 单证据都不该出）: {out:?}"
        );
        assert_eq!(out[0]["confidence"], json!("medium"), "两条落点全部缺失才给 medium");
        assert_eq!(out[0]["defaultChecked"], json!(false));
        assert_eq!(out[0]["deleteCapable"], json!(true));
        // MSI 键两条落点全部缺失才放行，且置信度按证据条数走
        let msi_two = mk("MsiTwo", guid, r"C:\Program Files\MsiTwo", r"C:\Program Files\MsiTwo\setup.exe /x");
        let out2 = dead_uninstall_findings(&[msi_two], &exists, 1_700_000_900_000);
        assert_eq!(out2.len(), 1, "MSI 键两条落点全缺应产出: {out2:?}");
        assert_eq!(out2[0]["confidence"], json!("medium"), "两条落点全缺给 medium: {out2:?}");
        // 普通键单条落点缺失即产出，但置信度只到 low
        let one = mk("OneLanding", "OneLanding", "", r"C:\Program Files\OneLanding\unins000.exe");
        let out3 = dead_uninstall_findings(&[one], &exists, 1_700_000_900_000);
        assert_eq!(out3.len(), 1, "普通键单条落点缺失就该产出: {out3:?}");
        assert_eq!(out3[0]["confidence"], json!("low"), "一条落点不给 medium: {out3:?}");
        // C4：贡献项按 code 断言（不按中文文案断言，改文案不该碎掉测试），每条都得有 text。
        let c = &out[0]["contribs"];
        let codes: Vec<&str> = c.as_array().unwrap().iter().map(|x| x["code"].as_str().unwrap_or("")).collect();
        assert_eq!(codes.iter().filter(|k| *k == &"landingMissing").count(), 2, "两条落点各一条: {c}");
        assert!(codes.contains(&"entry") && codes.contains(&"dormant"), "键位置与沉睡证据都要在: {c}");
        assert!(
            c.as_array().unwrap().iter().all(|x| !x["text"].as_str().unwrap_or("").is_empty()),
            "有 code 没 text 等于给用户一个看不懂的代号: {c}"
        );
        assert!(
            !codes.contains(&"msiRule"),
            "普通键不该出现 MSI 口径: {c}"
        );
        assert!(out2[0]["contribs"]
            .as_array().unwrap()
            .iter().any(|x| x["code"] == json!("msiRule")),
            "MSI 键要说明为什么要求两条落点: {}", out2[0]);
        let one_codes: Vec<&str> = out3[0]["contribs"].as_array().unwrap()
            .iter().map(|x| x["code"].as_str().unwrap_or("")).collect();
        assert_eq!(one_codes.iter().filter(|k| *k == &"landingMissing").count(), 1, "一条落点只该有一条证据: {one_codes:?}");
    }

    #[test]
    fn dead_app_paths_rows_target_only_their_own_key() {
        let raws = vec![
            DeadAppPathRaw {
                hive: "HKLM".to_string(),
                key: "foo.exe".to_string(),
                path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\foo.exe".to_string(),
                value: r"C:\Program Files\Foo\foo.exe".to_string(),
                last_write_ms: None,
            },
            DeadAppPathRaw {
                hive: "HKLM".to_string(),
                key: "bar.exe".to_string(),
                path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\bar.exe".to_string(),
                value: "bar.exe".to_string(),
                last_write_ms: None,
            },
            DeadAppPathRaw {
                hive: "HKLM".to_string(),
                key: "live.exe".to_string(),
                path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\live.exe".to_string(),
                value: r"C:\Windows\explorer.exe".to_string(),
                last_write_ms: None,
            },
        ];
        let out = dead_app_paths_findings(&raws, &|p| p.eq_ignore_ascii_case(r"C:\Windows\explorer.exe"), 1_700_000_900_000);
        assert_eq!(out.len(), 1, "只有落点确实缺失的那条该出候选: {out:?}");
        let target = out[0]["target"].as_str().unwrap_or("");
        assert_eq!(target, r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\foo.exe");
        assert_eq!(out[0]["deleteCapable"], json!(true));
        assert!(
            protect::reg_target_block_reason(target).is_none(),
            "M1 给 App Paths 留的例外放行没生效，本类候选会被执行侧全量拒杀: {target}"
        );
        // C4：读不到写入时间时明确给 dormantUnknown，不许出现"沉默即很久"那种暗示
        let codes: Vec<&str> = out[0]["contribs"].as_array().unwrap()
            .iter().map(|x| x["code"].as_str().unwrap_or("")).collect();
        assert!(codes.contains(&"entry") && codes.contains(&"targetMissing"), "键与缺失目标都要点名: {codes:?}");
        assert!(codes.contains(&"dormantUnknown"), "无写入时间不该编沉睡证据: {codes:?}");
        assert!(!codes.contains(&"dormant"), "{codes:?}");
    }

    /// 快照分桶：面板现在同时展示多组候选，整槽覆盖会让先扫那组在执行时被快照闸判过期。
    #[test]
    fn residue_snapshot_buckets_replace_only_their_own_origin() {
        let label = "test-snapshot-merge";
        residue_snapshot_put(label, "app", vec![json!({ "kind": "folder", "target": "C:\\a", "origin": "app" })]);
        residue_snapshot_put(label, "dead", vec![json!({ "kind": "reg_key", "target": "HKCU\\Software\\X", "origin": "dead" })]);
        let both: Vec<String> = residue_snapshots()
            .lock()
            .map(|g| g.get(label).cloned().unwrap_or_default().1)
            .unwrap_or_default()
            .iter()
            .map(|f| f["target"].as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(both.len(), 2, "两组扫描的候选必须共存: {both:?}");
        residue_snapshot_put(label, "dead", vec![json!({ "kind": "reg_key", "target": "HKCU\\Software\\Y", "origin": "dead" })]);
        let after: Vec<String> = residue_snapshots()
            .lock()
            .map(|g| g.get(label).cloned().unwrap_or_default().1)
            .unwrap_or_default()
            .iter()
            .map(|f| f["target"].as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(after.len(), 2, "重扫只换自己那一桶: {after:?}");
        assert!(after.iter().any(|t| t == "C:\\a"), "app 桶被误替换: {after:?}");
        assert!(after.iter().any(|t| t.ends_with("Software\\Y")), "dead 桶没换: {after:?}");
        assert!(!after.iter().any(|t| t.ends_with("Software\\X")), "dead 桶旧值残留: {after:?}");
        let _ = residue_snapshots().lock().map(|mut g| g.remove(label));
    }

    /// 沉睡时长：读不到就留未知。把 0 显示成"很久没动过"是把没把握说成有把握。
    #[test]
    fn dormant_stays_unknown_instead_of_looking_ancient() {
        assert_eq!(dormant_delta(None, 1_700_000_900_000), Value::Null);
        assert_eq!(dormant_delta(Some(0), 1_700_000_900_000), Value::Null);
        assert_eq!(dormant_delta(Some(1_700_000_900_001), 1_700_000_900_000), Value::Null, "时钟回拨不给负数");
        assert_eq!(dormant_delta(Some(1_700_000_000_000), 1_700_000_900_000), json!(900_000));
    }
}

#[cfg(test)]
mod backup_visibility_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn sandbox(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trim-backup-vis-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// mtime 必须显式设定：两个文件在同一毫秒内写完时，倒序断言会变成掷硬币，
    /// 于是"看起来稳定"的用例会在换机器时第一次红。
    fn touch(path: &Path, ms: u64) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_millis(ms)).unwrap();
    }

    /// N1：跨根列表必须把「来自老根」标出来，且**封条缺失也要列出**。
    /// 封条是 v0.2.6 才加的，升级前那批永远 missing —— 拒列就等于把用户唯一的
    /// 还原依据藏起来（这正是 v2-M14「已自动还原」空桩那一类：界面看不到 = 用户以为没有）。
    #[test]
    fn 跨根备份渲染标来源且缺封条仍列出() {
        let root = sandbox("render");
        let new = root.join("new");
        let legacy = root.join("legacy");
        std::fs::create_dir_all(&new).unwrap();
        std::fs::create_dir_all(&legacy).unwrap();
        let a = new.join("1700000000001_Alpha.reg");
        std::fs::write(&a, "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Alpha]\r\n\"X\"=dword:1\r\n").unwrap();
        write_reg_backup_seal(&a, "HKCU\\Software\\Alpha");
        touch(&a, 1_700_000_001_000);
        let b = legacy.join("1700000000002_Beta.reg");
        std::fs::write(&b, "Windows Registry Editor Version 5.00\r\n").unwrap();
        touch(&b, 1_700_000_002_000);
        // 杂项与非法名不得进列表（还原是按文件名找实体的通道）
        std::fs::write(legacy.join("readme.txt"), b"x").unwrap();

        let items = render_reg_backups(vec![(a.clone(), false), (b.clone(), true)]);
        assert_eq!(items.len(), 2, "两份都要列出，非法名那份被过滤: {items:?}");
        assert_eq!(items[0]["file"], "1700000000002_Beta.reg", "mtime 倒序");
        assert_eq!(items[0]["fromLegacy"], json!(true), "老根那份必须标来源");
        assert_eq!(items[0]["seal"], "missing", "无封条的老备份仍要可见");
        assert_eq!(items[1]["fromLegacy"], json!(false));
        assert_eq!(items[1]["seal"], "ok");
        assert_eq!(items[1]["target"], "HKCU\\Software\\Alpha");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 判红自测口径（AGENTS §4：只会打 ✓ 的不算验收）：
    /// 把 `from_legacy` 写死 false、或把 `!p.is_file()` 那道闸摘掉，本用例必须红。
    #[test]
    fn 渲染拒绝目录项与非文件条目() {
        let root = sandbox("reject");
        std::fs::create_dir_all(root.join("1700000000009_Dir.reg")).unwrap();
        let entries = vec![(root.join("1700000000009_Dir.reg"), false)];
        assert!(render_reg_backups(entries).is_empty(), "同名目录不得当备份列出——还原侧会按文件读它并失败");
        let _ = std::fs::remove_dir_all(&root);
    }
}


