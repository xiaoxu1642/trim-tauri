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

use std::collections::HashMap;
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
/// 走 inbox Windows PowerShell 5.1 的 Appx 模块（system_tool 白名单 + quiet_cmd，
/// 与 PsInline 执行器同通道），不新增裸 spawn。当前用户 scope（Get-AppxPackage 语义）。
/// 输出 UTF-8（命令内显式设 OutputEncoding，防止中文发行商按 OEM 码页乱码）。
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
    let out = crate::engine::systembin::quiet_cmd(crate::engine::systembin::system_tool("powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output()
        .map_err(|e| format!("powershell 启动失败: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() {
        return Err(if text.starts_with("ERR:") {
            text[4..].trim().to_string()
        } else {
            format!("Get-AppxPackage 失败（退出码 {}）", out.status.code().unwrap_or(-1))
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

/// Appx 移除（当前用户，对齐 HiBit 的 `powershell Remove-AppxPackage` 实测口径）。
/// 返回 Ok(()) 或带原因的 Err。NonRemovable 的包系统会拒绝，由这里如实转述。
fn remove_appx(fullname: &str) -> Result<(), String> {
    let script = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \
try {{ Remove-AppxPackage -Package '{}' -ErrorAction Stop; exit 0 }} \
catch {{ Write-Output ('ERR:' + $_.Exception.Message); exit 1 }}",
        fullname
    );
    let out = crate::engine::systembin::quiet_cmd(crate::engine::systembin::system_tool("powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .output()
        .map_err(|e| format!("powershell 启动失败: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Err(if text.starts_with("ERR:") {
            text[4..].trim().to_string()
        } else {
            format!("Remove-AppxPackage 失败（退出码 {}）", out.status.code().unwrap_or(-1))
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
        let install_date = unsafe { reg_key_last_write_date(hk) };
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
            "estimatedSizeKb": estimated_size_kb,
            "installDate": install_date,
            "productCode": product_code,
            "installerKind": installer_kind,
        }));
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
            return enum_appx_packages();
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

/// 启发式残留：应用名与 AppData/LocalAppData/ProgramData 一级目录名互含（双侧 ≥5 字符）。
/// 方案 §4.4：名称启发式置信度 low，默认不勾选，只作候选提示。
unsafe fn heuristic_dir_hits(app_name: &str) -> Vec<String> {
    let norm = norm_name(app_name);
    if norm.chars().count() < 5 {
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
            if dnorm.chars().count() < 5 {
                continue;
            }
            if dnorm == norm || (dnorm.contains(&norm) || norm.contains(&dnorm)) {
                hits.push(ent.path().to_string_lossy().to_string());
            }
            if hits.len() >= 20 {
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
        if hits.len() >= 20 {
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
                if stem.contains(&norm) || (norm.contains(&stem) && stem.chars().count() >= 4) {
                    hits.push(p.to_string_lossy().to_string());
                    if hits.len() >= 20 {
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
                    if exes.len() >= 16 {
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
const RESIDUE_RULE_FIELDS: &[&str] = &["id", "displayName", "publisher", "uninstallKey", "residue"];
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
    pkg.get("rulesVersion")
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

/// 条件组命中判定（U-1「双条件」拍板）：displayName / publisher / uninstallKey 三组里
/// **至少两组命中**才视为同一程序，单一维度弱相似不触发（防「QQ」类短名误伤全家桶）。
/// 返回 (候选集, 被 A1 硬否决的目标) —— 否决原因只在这里收集，由命令边界落日志：
/// 纯函数不留写盘副作用，`cargo test` 才不会把测试规则 id 写进用户的应用日志。
fn residue_rules_hits(
    rules: &Value,
    display_name: &str,
    publisher: &str,
    key_path: &str,
) -> (Vec<Value>, Vec<String>) {
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
                    pn.chars().count() >= 2 && contains2(&name_norm, &pn)
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
                    pl.chars().count() >= 2 && contains2(&key_lc, &pl)
                })
            })
            .unwrap_or(false);
        let hits = [name_hit, pub_hit, key_hit].iter().filter(|h| **h).count();
        if hits < 2 {
            continue;
        }
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
                    let p = Path::new(&target);
                    let exists = if kind == "folder" { p.is_dir() } else { p.is_file() };
                    if !exists || protect::is_path_protected(&target) {
                        continue;
                    }
                    out.push(json!({
                        "kind": kind, "target": target,
                        "reason": format!("残留规则库命中（{id}）：{note}"),
                        "confidence": "high", "risk": "medium", "defaultChecked": true,
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
                        "reason": format!("残留规则库命中（{id}）：{note}"),
                        "confidence": "high", "risk": "medium", "defaultChecked": true,
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
    // U-4（拍板 2026-09-28）：Appx 也参与残留扫描（Packages 孤儿数据），先用包全名闸
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
        // %LOCALAPPDATA%\Packages\<PFN> 的孤儿应用数据。此前「不参与残留扫描」，
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
                    "reason": "Windows 应用已移除，其 %LOCALAPPDATA%\\Packages\\<包名> 应用数据成为孤儿（进回收站，可还原）",
                    "confidence": "high", "risk": "low", "defaultChecked": true,
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
            findings.push(json!({
                "kind": "reg_key", "target": full_target,
                "reason": "卸载注册表项仍存在（原厂卸载可能未完成或已取消）",
                "confidence": "high", "risk": "medium", "defaultChecked": true,
            }));
        }
        // 高置信：安装目录仍在
        let loc = install_location.trim().trim_end_matches('\\').to_string();
        if !loc.is_empty()
            && Path::new(&loc).is_dir()
            && !protect::is_path_protected(&loc)
        {
            findings.push(json!({
                "kind": "folder", "target": loc,
                "reason": "InstallLocation 指向的安装目录仍存在",
                "confidence": "high", "risk": "medium", "defaultChecked": true,
            }));
        }
        // 低置信：名称启发式（默认不勾，交用户判断）
        for p in heuristic_dir_hits(&display_name) {
            if protect::is_path_protected(&p) {
                continue;
            }
            findings.push(json!({
                "kind": "folder", "target": p,
                "reason": format!("目录名与「{display_name}」高度相似（启发式，请人工确认后再删）"),
                "confidence": "low", "risk": "high", "defaultChecked": false,
            }));
        }
        // 高置信补充：卸载器/图标指向的目录仍存在（InstallLocation 缺失时的主线索）
        for src in [&uninstall_string, &display_icon_src] {
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
                    findings.push(json!({
                        "kind": "folder", "target": pd.to_string_lossy(),
                        "reason": "卸载器/图标指向的程序目录仍存在",
                        "confidence": "high", "risk": "medium", "defaultChecked": true,
                    }));
                }
            }
        }
        // 中置信：开始菜单快捷方式（文件名含程序名；删 .lnk 无害，默认勾选）
        for lnk in start_menu_shortcut_hits(&display_name) {
            findings.push(json!({
                "kind": "shortcut", "target": lnk,
                "reason": format!("开始菜单快捷方式与「{display_name}」同名"),
                "confidence": "medium", "risk": "low", "defaultChecked": true,
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
            // 外层闭包整体处于 unsafe 块内，直接调用即可（内层再包 unsafe 会告警冗余）
            for target in muicache_hits(&exes_lc, &dir_lc, 20) {
                findings.push(json!({
                    "kind": "reg_value", "target": target,
                    "reason": "MuiCache 残留值（系统缓存了此程序路径的友好名称）",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                }));
            }
            for target in firewall_hits(&exes_lc, &dir_lc, 20) {
                findings.push(json!({
                    "kind": "reg_value", "target": target,
                    "reason": "防火墙规则引用此程序路径（程序已卸载，规则已失效）",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                }));
            }
            for target in bam_hits(&exes_lc, &dir_lc, 20) {
                findings.push(json!({
                    "kind": "reg_value", "target": target,
                    "reason": "BAM 后台执行记录引用此程序路径",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                }));
            }
            for target in tracing_hits(&exes_lc, 20) {
                findings.push(json!({
                    "kind": "reg_key", "target": target,
                    "reason": "Tracing 诊断跟踪项以此程序的 exe 命名",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                }));
            }
            for target in jumplist_hits(&exes_lc, &dir_lc, 20) {
                findings.push(json!({
                    "kind": "file", "target": target,
                    "reason": "JumpList 自动目标缓存引用此程序路径",
                    "confidence": "medium", "risk": "low", "defaultChecked": false,
                }));
            }
        }
        // 高置信：签名残留规则库命中（U-1）——已知程序知识库，双条件命中 +
        // 目标存在性判定后才出现；reg_key 删除走执行侧同款「先备份后删」
        if let Some(rules) = load_residue_rules() {
            let (rule_hits, vetoed) = residue_rules_hits(&rules, &display_name, &publisher, &key_path);
            findings.extend(rule_hits);
            // 硬否决在命令边界留痕：真机跑到这一行就说明签名规则库里躺着一处系统容器
            // （误签、私钥泄露或规则生成漏检），属异常而非常态，必须能在日志里查到。
            for line in vetoed {
                log::write_log("warn", &line);
            }
        }
        (findings, display_name)
    })
    .await
    .unwrap_or((Vec::new(), String::new()));

    // 快照落槽：执行只认这份集合
    let (finding_list, app_name) = findings;
    let label = window.label().to_string();
    {
        let mut store = residue_snapshots().lock().unwrap_or_else(|e| e.into_inner());
        store.insert(label, (crate::engine::now_ms(), finding_list.clone()));
    }
    json!({ "success": true, "data": { "appName": app_name, "findings": finding_list } })
}

// ==================== uninstall:residue-execute ====================

/// 残留执行结果明细行
fn detail(kind: &str, target: &str, status: &str, message: &str) -> Value {
    json!({ "kind": kind, "target": target, "status": status, "message": message })
}

/// 把待送删目标按「目录级重解析点校验」拆成（可送删, 被拒项→拒因）。
///
/// 只对 `kind == "folder"` 生效：单个 file / shortcut 即使自身是重解析点，删除也只删掉
/// 链接本身，不会顺链接递归搬走目标内容；目录才会（OneDrive 占位文件因此不受这条闸影响）。
///
/// 为什么单独成函数而不是内联在命令里：它落在 `uninstall_residue_execute` 的窗口化命令内，
/// 不抽出来就没有任何单测能覆盖这条删除链（方案 §7 要求「不依赖真机」的回归网）。
fn partition_reparse_blocked(items: Vec<(String, OsString)>) -> (Vec<(String, OsString)>, Vec<(OsString, String)>) {
    let mut sendable = Vec::with_capacity(items.len());
    let mut blocked: Vec<(OsString, String)> = Vec::new();
    for (kind, target) in items {
        if kind == "folder" {
            if let Some(reason) = crate::engine::native::dir_delete_blocked(Path::new(&target)) {
                blocked.push((target, reason));
                continue;
            }
        }
        sendable.push((kind, target));
    }
    (sendable, blocked)
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
    let app_id = app_id.clone();
    let report = tauri::async_runtime::spawn_blocking(move || {
        let mut details: Vec<Value> = Vec::new();
        // 注册表项：先备份后删（与 cleanup 同一 export 通道，fail-closed）
        for (kind, target) in &wanted {
            if kind != "reg_key" {
                continue;
            }
            let Some((hive, rest)) = parse_reg_target(target) else {
                details.push(detail(kind, target, "skip", "注册表目标无法解析（只支持 HKCU/HKLM）"));
                continue;
            };
            // A1 执行侧硬闸（与扫描侧同一判定）：快照闸只证明「来自上次扫描」，
            // 证明不了「这个目标不该删」—— 危险候选本来就是扫描器按规则产出的。
            if let Some(reason) = protect::reg_target_block_reason(target) {
                log::write_log("warn", &format!("uninstall_residue_execute 拒绝注册表目标: {reason}"));
                // 状态只用既有的 skip：报告明细按 ok/fail/skip 三态渲染中文标签，
                // 新增 status 会在前端漏出英文字面量（uninstall.js:487）
                details.push(detail(kind, target, "skip", &format!("已拒绝删除：{reason}")));
                continue;
            }
            if !crate::engine::native::reg_key_exists(hive, &rest) {
                details.push(detail(kind, target, "skip", "注册表项已不存在"));
                continue;
            }
            let backup_dir = crate::engine::paths::app_data_dir().join("uninstall-reg-backup");
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
            if crate::engine::native::reg_key_remove(hive, &rest, true) {
                details.push(detail(kind, target, "ok", "已删除（备份已留存）"));
            } else {
                details.push(detail(kind, target, "fail", "注册表删除失败"));
            }
        }

        // 注册表值：先备份整个父键再删单值（U-2 侧痕面：MuiCache/防火墙规则/BAM）。
        // 目标格式 `HKCU\<键路径>::<值名>`；删值复用 reg_restore_delete
        // （值已不存在 = 幂等成功，对齐 B11 语义）。
        for (kind, target) in &wanted {
            if kind != "reg_value" {
                continue;
            }
            let Some((key_part, value_name)) = target.rsplit_once("::") else {
                details.push(detail(kind, target, "skip", "注册表值目标格式错误（缺 :: 值名分隔）"));
                continue;
            };
            if value_name.trim().is_empty() {
                details.push(detail(kind, target, "skip", "注册表值名为空"));
                continue;
            }
            let Some((hive, rest)) = parse_reg_target(key_part) else {
                details.push(detail(kind, target, "skip", "注册表目标无法解析（只支持 HKCU/HKLM）"));
                continue;
            };
            let backup_dir = crate::engine::paths::app_data_dir().join("uninstall-reg-backup");
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
            if crate::engine::native::reg_restore_delete(hive, &rest, value_name) {
                details.push(detail(kind, target, "ok", "已删除（备份已留存）"));
            } else {
                details.push(detail(kind, target, "fail", "注册表值删除失败"));
            }
        }

        // 文件/目录/快捷方式：保护判定 + 回收站（trim_finder 三端同源删除，含 protect 注入）
        let paths: Vec<(String, OsString)> = wanted
            .iter()
            .filter(|(k, _)| matches!(k.as_str(), "folder" | "file" | "shortcut"))
            .map(|(k, t)| (k.clone(), OsString::from(t)))
            .collect();
        if !paths.is_empty() {
            if let Some((_, target)) = paths
                .iter()
                .find(|(_, t)| protect::is_path_protected(&t.to_string_lossy()))
            {
                log::write_log("warn", &format!("uninstall_residue_execute 拒绝: 受保护路径 {}", target.to_string_lossy()));
                return Err(format!("包含受保护的系统路径，已拒绝：{}", target.to_string_lossy()));
            }
            // 预检：目标存在才送删
            let existing: Vec<(String, OsString)> = paths
                .into_iter()
                .filter(|(_, t)| std::fs::symlink_metadata(t).is_ok())
                .collect();
            // C1（方案 §5·C1）：目录送删前过「自身→盘符根」逐层重解析点校验，与维护任务
            // (`native::maint_run`)、diskbench 同口径。上级被换成 junction 时回收站会顺着链接
            // 把链接目标整棵搬走，「清残留」变成删数据。逐项判定、拒因写明细行，不整批失败。
            let (sendable, blocked) = partition_reparse_blocked(existing);
            for (target, reason) in blocked {
                let shown = target.to_string_lossy().to_string();
                log::write_log("warn", &format!("uninstall_residue_execute 跳过目录 {shown}: {reason}"));
                details.push(detail("folder", &shown, "skip", &format!("已拒绝删除：{reason}")));
            }
            if !sendable.is_empty() {
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
                let _ = trim_finder::scan::delete(&sendable, Some(protect_json.as_str()), &sink);
                for row in sink.0.into_inner().unwrap_or_default() {
                    let ok = row["status"] == "ok";
                    details.push(detail(
                        row["kind"].as_str().unwrap_or("file"),
                        row["path"].as_str().unwrap_or(""),
                        if ok { "ok" } else { "fail" },
                        if ok { "已移入回收站" } else { row["path"].as_str().map(|_| "删除失败（可能被占用）").unwrap_or("删除失败") },
                    ));
                }
            }
        }
        Ok(details)
    })
    .await;

    match report {
        Ok(Ok(details)) => {
            let ok_count = details.iter().filter(|d| d["status"] == "ok").count();
            let fail_count = details.iter().filter(|d| d["status"] == "fail").count();
            // 批次报告（方案 M4）：动作级明细落盘，失败如实呈现
            let batch_id = delete_manifest::new_batch_id();
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
                }),
            );
            log::write_log("info", &format!("uninstall_residue_execute {app_id}: 成功 {ok_count} 失败 {fail_count}（报告 {batch_id}）"));
            json!({ "success": true, "data": { "details": details, "okCount": ok_count, "failCount": fail_count, "reportPath": report_path.to_string_lossy() } })
        }
        Ok(Err(e)) => json!({ "success": false, "message": e }),
        Err(e) => json!({ "success": false, "message": format!("残留清理异常: {e}") }),
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
        if items.len() >= 50 {
            break;
        }
    }
    // 文件名即 ISO 时间戳，倒序 = 最新在前
    items.sort_by(|a, b| {
        let ka = a["batchId"].as_str().unwrap_or("");
        let kb = b["batchId"].as_str().unwrap_or("");
        kb.cmp(ka)
    });
    json!({ "success": true, "data": { "reports": items } })
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
}

#[cfg(test)]
mod residue_trace_tests {
    use super::*;

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
        let (hits, vetoed) = residue_rules_hits(&pkg, "EvilApp 1.0", "EvilCorp", "EvilApp");
        assert!(hits.is_empty(), "受保护注册表目标进入了候选列表: {hits:?}");
        assert_eq!(
            vetoed.len(),
            3,
            "三条危险目标都应各自给出否决原因（祖先/命名空间树/整棵禁删各一类）: {vetoed:?}"
        );
    }

    /// C1（不依赖真机）：残留目录送删前的重解析闸。
    /// 用「不存在」触发 fail-closed 分支，用「真实系统目录整条链」证明没有把功能废掉。
    #[test]
    fn residue_folder_reparse_gate_is_fail_closed() {
        let ghost = std::env::temp_dir().join("trim-no-such-dir-9f3a\\DataStore");
        let ghost_os = ghost.as_os_str().to_os_string();
        let (sendable, blocked) =
            partition_reparse_blocked(vec![("folder".to_string(), ghost_os.clone())]);
        assert!(sendable.is_empty(), "读不到属性的目录被放行: {sendable:?}");
        assert_eq!(blocked.len(), 1, "不存在目录必须按拒绝处理（查不到≠安全）");

        // 真实系统目录（自身到盘符根整条链都非 reparse）必须放行
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let sys32 = PathBuf::from(format!("{}\\Windows\\System32", drive.trim_end_matches('\\')));
        let (sendable, blocked) =
            partition_reparse_blocked(vec![("folder".to_string(), sys32.as_os_str().to_os_string())]);
        assert_eq!(blocked.len(), 0, "真实系统目录被误拦: {sys32:?}");
        assert_eq!(sendable.len(), 1, "真实系统目录应可送删");

        // file / shortcut 不受这条目录闸影响（单文件删除不会顺链接递归）
        let (sendable, blocked) = partition_reparse_blocked(vec![
            ("file".to_string(), ghost_os.clone()),
            ("shortcut".to_string(), ghost_os),
        ]);
        assert!(blocked.is_empty() && sendable.len() == 2, "目录闸误伤了 file/shortcut");
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
}
