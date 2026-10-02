//! AppX / Store 应用：枚举准入、卸载、logo 取回（原 UWP 通道）。
//!
//! `valid_appx_fullname` 的字符集闸口 [A-Za-z0-9._-] 必须先于任何喂给 pwsh 的地方生效
//! （HiBit 反例：用户输入直接拼进 Remove-AppxPackage 模板）。
//! 枚举/卸载超时常量随本域留在本文件；logo 命令走的是「只读文件字节」路径，不做写侧。

use crate::engine::guard;
use serde_json::{Value, json};
use std::path::PathBuf;
use tauri::WebviewWindow;
pub(super) fn valid_appx_fullname(fullname: &str) -> bool {
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
pub(super) fn package_family_name(fullname: &str) -> Option<String> {
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
pub(super) fn friendly_publisher(publisher: &str) -> String {
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
pub(super) const APPX_ENUM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
pub(super) const APPX_REMOVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub(super) fn enum_appx_packages() -> Result<Vec<Value>, String> {
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
pub(super) fn enum_appx_store_extras(seen: &std::collections::HashSet<String>) -> Vec<Value> {
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
pub(super) fn remove_appx(fullname: &str) -> Result<(), String> {
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
pub(super) mod uninstall_appx_tests {
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

