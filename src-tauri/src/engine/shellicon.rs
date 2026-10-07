//! Shell 图标提取（paths:app-icon / paths:file-icon / contextmenu:icons）
//!
//! 对照 Electron 的 `app.getFileIcon(path, { size: 'large' })` → `NativeImage.toDataURL()`：
//! SHGetFileInfoW 取大图标 HICON → GetDIBits 取 32 位 BGRA → 转 RGBA → PNG → dataURL。
//!
//! 两个实测要点：
//! 1. **掩码型图标**（旧式仅 1bpp 掩码、颜色位图 alpha 全 0）：直接用会整张透明。
//!    与 Chromium 同口径的兜底——alpha 全 0 时视为不透明（按掩码语义填满）。
//! 2. GetDIBits 需要 DC；传入 NULL 在部分驱动上返回 0 行，故显式取屏幕 DC 再释放。
//!
//! 两条取图标通道**不等价**，用哪条取决于要问谁：
//! - [`file_icon_data_url`]（SHGetFileInfoW）问的是**外壳**：给 .dll 返回的是「DLL 这个
//!   文件类型」的图标，和它内嵌了什么资源无关。
//! - [`first_icon_data_url`]（ExtractIconExW 索引 0）问的是**PE 资源**：返回文件内嵌的
//!   第一个图标。右键菜单 CLSID 图标要的是后者 —— 被替代的 .NET 通道
//!   `[System.Drawing.Icon]::ExtractAssociatedIcon($dll)` 实测就是内嵌首图标语义
//!   （shell32.dll / urlmon.dll 实机对拍见 `live_probe_两条通道与dotnet基线同尺寸`）。
//!
//! ## 磁盘缓存（2026-10-07）
//!
//! 两条公开入口共用一层 PNG 磁盘缓存（数据目录 `cache/icon-extract/<键>.png`）：
//! 提取一次落盘，之后同键直接读文件转 base64，整条 GDI 链不再走。动机：进程管理器
//! 是虚拟列表，滚动会反复重建行节点，同一 exe 之前每次都要全量重提取（外壳提取是
//! 走 shell 进程隔离的慢路径）；卸载列表的 localStorage 缓存只盖住它一个调用方且
//! 1MB 上限装不下几个图标。
//!
//! 键 = SHA-256(通道标签 + 小写路径 + mtime + size) 前 16 位，三个成分各有含义：
//! - **通道标签必须进键**：外壳与 PE 首图标对同一文件结果不同（见 live_probe 对拍），
//!   不进键就是两条通道互相发对方的图标（假缓存命中，比对拍基线还难查）；
//! - **mtime + size 只对文件参与**：应用升级替换 exe 后键自动换新，不会给新版本发旧
//!   图标（卸载列表前端键是 id|version，升级后会回来重新请求）；目录拿不到稳定修改
//!   时间且外壳恒发通用文件夹图标，只按路径；
//! - **小写化**：Win32 路径大小写不敏感，`C:\App\X.exe` 与 `c:\app\x.exe` 是同一图标。
//!
//! 失效与损坏一律静默降级（§6 只读缓存口径）：读失败或 PNG 魔数不符删文件回提取，
//! 写失败只影响这一次不重试。孤儿（升级后换键留下的旧文件）按写入计数批量回收。

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use windows::core::PCWSTR;
use windows::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO, BITMAPINFOHEADER,
    BI_RGB, DIB_RGB_COLORS, HBITMAP, HDC,
};
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows::Win32::UI::Shell::{
    ExtractIconExW, SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON,
};
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

/// 提取文件/目录图标并编码为 PNG dataURL（外壳视角：文件类型图标）。
/// 失败返回 Err（调用方按 `{success:false, dataUrl:null}` 回落，与 Electron 版一致）。
pub fn file_icon_data_url(path: &Path) -> Result<String, String> {
    icon_data_url_cached("shell", path, shell_icon_png)
}

/// 提取 **PE 内嵌的第一个图标**并编码为 PNG dataURL（资源视角）。
/// 右键菜单 CLSID 图标链用：`InprocServer32` 指向的 dll/exe 要显示它自己带的图标，
/// 不是「DLL 文件类型」图标。文件没有内嵌图标时返回 Err，由调用方决定回落姿势。
pub fn first_icon_data_url(path: &Path) -> Result<String, String> {
    icon_data_url_cached("pe-first", path, |p| {
        if !p.is_file() {
            return Err("路径不是已存在的文件".into());
        }
        first_icon_png(p)
    })
}

/// 两条通道共用的缓存包装。`channel` 进缓存键（同一文件两通道图标不同，见模块注释）。
/// 拿不到元数据（多半是不存在）时保持原判据直接提取并透传错误；提取失败不写缓存——
/// 失败原因可能瞬时（文件被占用），且失败路径本身就快，负缓存反而会钉死错误结果。
fn icon_data_url_cached<F>(channel: &str, path: &Path, extract: F) -> Result<String, String>
where
    F: Fn(&Path) -> Result<Vec<u8>, String>,
{
    let dir = icon_cache_dir();
    if let Some(key) = cache_key(channel, path) {
        if let Some(png) = cached_png(&dir, &key) {
            return encode_data_url(&png);
        }
        let png = extract(path)?;
        store_png(&dir, &key, &png);
        return encode_data_url(&png);
    }
    encode_data_url(&extract(path)?)
}

fn encode_data_url(png: &[u8]) -> Result<String, String> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(png);
    Ok(format!("data:image/png;base64,{b64}"))
}

fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

fn shell_icon_png(path: &Path) -> Result<Vec<u8>, String> {
    if !path.exists() {
        return Err("路径不存在".into());
    }
    let wide = to_wide(path);

    unsafe {
        let mut shfi = SHFILEINFOW::default();
        let ret = SHGetFileInfoW(
            PCWSTR(wide.as_ptr()),
            FILE_ATTRIBUTE_NORMAL,
            Some(&mut shfi),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_LARGEICON,
        );
        if ret == 0 || shfi.hIcon.is_invalid() {
            return Err("未能获取文件图标".into());
        }
        let hicon = shfi.hIcon;
        let result = hicon_to_png(hicon);
        let _ = DestroyIcon(hicon);
        result
    }
}

fn first_icon_png(path: &Path) -> Result<Vec<u8>, String> {
    let wide = to_wide(path);
    unsafe {
        // 索引 0 + 数量 1 = 只要第一个大图标；小图标槽位给 None 表示不取
        let mut hicon = HICON::default();
        let got = ExtractIconExW(PCWSTR(wide.as_ptr()), 0, Some(&mut hicon), None, 1);
        if got == 0 || hicon.is_invalid() {
            if !hicon.is_invalid() {
                let _ = DestroyIcon(hicon);
            }
            return Err("文件没有内嵌图标资源".into());
        }
        let result = hicon_to_png(hicon);
        let _ = DestroyIcon(hicon);
        result
    }
}

// ==================== PNG 磁盘缓存 ====================

const CACHE_DIR_REL: &str = "cache/icon-extract";
const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
/// 每累计 N 次成功写缓存做一次孤儿回收（读目录有 IO 代价，不逐次做）
const CACHE_PRUNE_EVERY: u64 = 64;
/// 触发回收的文件数水位
const CACHE_PRUNE_THRESHOLD: usize = 768;
/// 回收后保留的最新文件数（两次回收间最多新增 CACHE_PRUNE_EVERY 个，水位留有余量）
const CACHE_KEEP: usize = 512;

static CACHE_WRITES: AtomicU64 = AtomicU64::new(0);

fn icon_cache_dir() -> PathBuf {
    crate::engine::paths::data_subdir_for_write(CACHE_DIR_REL)
}

/// 缓存键：SHA-256(通道标签 + 小写路径 + mtime + size) 前 16 位小写 hex。
/// 目标不存在时返回 None——「键都没有」的路径必须走直接提取透传原错误，
/// 不能拿空键或残键去命中别的条目。
fn cache_key(channel: &str, path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    // mtime+size 只对文件参与（目录没有稳定修改时间，外壳对目录恒发通用文件夹图标）
    let (mtime, size) = if meta.is_file() {
        (
            meta.modified()
                .ok()?
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs(),
            meta.len(),
        )
    } else {
        (0, 0)
    };
    let lowered = path.to_string_lossy().to_lowercase();
    let full = crate::engine::hash::sha256_bytes(
        format!("{channel}\0{lowered}\0{mtime}\0{size}").as_bytes(),
    );
    Some(full[..16].to_string())
}

/// 读缓存。魔数不符按未命中处理并删文件——半截/损坏文件留在原地会让这个键永远命中坏数据。
fn cached_png(dir: &Path, key: &str) -> Option<Vec<u8>> {
    let file = dir.join(format!("{key}.png"));
    let bytes = std::fs::read(&file).ok()?;
    if !bytes.starts_with(&PNG_MAGIC) {
        let _ = std::fs::remove_file(&file);
        return None;
    }
    Some(bytes)
}

/// 写缓存（原子写，防并发半截文件）。写失败静默放弃：缓存是加速层，不是数据。
fn store_png(dir: &Path, key: &str, png: &[u8]) {
    let file = dir.join(format!("{key}.png"));
    if crate::security::atomic_write_file(&file, png).is_ok() {
        let n = CACHE_WRITES.fetch_add(1, Ordering::Relaxed);
        if (n + 1) % CACHE_PRUNE_EVERY == 0 {
            prune_icon_cache(dir);
        }
    }
}

/// 孤儿回收：应用升级换键后旧文件不再被命中，数量过水位时按修改时间删最旧。
/// 只认自己的命名形态（16 位小写 hex + `.png`），用户放进同目录的其它文件不碰。
fn prune_icon_cache(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_cache_file_name(p))
        .filter_map(|p| {
            let m = std::fs::metadata(&p).ok()?.modified().ok()?;
            Some((m, p))
        })
        .collect();
    if files.len() <= CACHE_PRUNE_THRESHOLD {
        return;
    }
    // mtime 双键排序：NTFS 时间戳有粗粒度，批量写入时大量文件同秒，纯 mtime 排序
    // 结果不稳定，断言与行为都会抖；文件名（键）作次序保证确定性。
    files.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let excess = files.len() - CACHE_KEEP;
    for (_, p) in files.iter().take(excess) {
        let _ = std::fs::remove_file(p);
    }
}

/// 16 位小写 hex + `.png`，与本模块 [`cache_key`] 的产出严格同形
fn is_cache_file_name(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| {
            n.len() == 20
                && n.ends_with(".png")
                && n[..16]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
}

/// HICON → 32 位 RGBA → PNG。调用方负责 `DestroyIcon`。
///
/// 刻意做成 unsafe：这里全程在解 Win32 句柄。抽成独立函数的代价是零，收益是两条取图标
/// 通道（外壳 / PE 资源）共用同一段位图与 alpha 处理，不会出现「一条修了掩码兜底、另一条没修」。
unsafe fn hicon_to_png(hicon: HICON) -> Result<Vec<u8>, String> {
    let mut info = ICONINFO::default();
    GetIconInfo(hicon, &mut info).map_err(|e| format!("GetIconInfo 失败: {e}"))?;

    let hbm_color: HBITMAP = info.hbmColor;
    let hbm_mask: HBITMAP = info.hbmMask;
    let cleanup = |hbm_color: HBITMAP, hbm_mask: HBITMAP| {
        if !hbm_color.is_invalid() {
            let _ = DeleteObject(hbm_color.into());
        }
        if !hbm_mask.is_invalid() {
            let _ = DeleteObject(hbm_mask.into());
        }
    };

    if hbm_color.is_invalid() {
        cleanup(hbm_color, hbm_mask);
        return Err("图标缺少颜色位图".into());
    }

    let mut bmp = BITMAP::default();
    if GetObjectW(
        hbm_color.into(),
        std::mem::size_of::<BITMAP>() as i32,
        Some(&mut bmp as *mut _ as *mut c_void),
    ) == 0
    {
        cleanup(hbm_color, hbm_mask);
        return Err("GetObject 读取位图信息失败".into());
    }
    let (w, h) = (bmp.bmWidth, bmp.bmHeight);
    if w <= 0 || h <= 0 {
        cleanup(hbm_color, hbm_mask);
        return Err("图标尺寸非法".into());
    }

    let mut bi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            // 负高度 = 自上而下，省去一次行翻转
            biHeight: -h,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut buf = vec![0u8; (w * h * 4) as usize];
    let hdc: HDC = GetDC(None);
    let got = GetDIBits(
        hdc,
        hbm_color,
        0,
        h as u32,
        Some(buf.as_mut_ptr() as *mut c_void),
        &mut bi,
        DIB_RGB_COLORS,
    );
    ReleaseDC(None, hdc);
    cleanup(hbm_color, hbm_mask);

    if got == 0 {
        return Err("GetDIBits 读取像素失败".into());
    }

    // BGRA → RGBA；掩码型图标 alpha 全 0 时按不透明兜底
    let mut all_zero_alpha = true;
    for px in buf.chunks_exact_mut(4) {
        px.swap(0, 2);
        if px[3] != 0 {
            all_zero_alpha = false;
        }
    }
    if all_zero_alpha {
        for px in buf.chunks_exact_mut(4) {
            px[3] = 255;
        }
    }

    encode_png(&buf, w as u32, h as u32)
}

fn encode_png(rgba: &[u8], w: u32, h: u32) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, w, h);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|e| e.to_string())?;
        writer.write_image_data(rgba).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 把 dataURL 解回 RGBA 并给出（宽, 高, 全字节和）。BGRA 与 RGBA 只是通道次序不同，
    /// 字节集合一致 ⇒ 字节和可与 .NET 侧同口径比对，用来判「两张图是不是同一张」而不是只判尺寸。
    fn rgba_stats(data_url: &str) -> Option<(u32, u32, u64)> {
        let b64 = data_url.strip_prefix("data:image/png;base64,")?;
        let png = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        let decoder = png::Decoder::new(std::io::Cursor::new(&png));
        let mut reader = decoder.read_info().ok()?;
        let mut buf = vec![0u8; reader.output_buffer_size()];
        let info = reader.next_frame(&mut buf).ok()?;
        Some((info.width, info.height, buf.iter().map(|b| *b as u64).sum()))
    }

    /// R1 对拍（v2 方案要求）：原生 `ExtractIconExW` 与被替换掉的 .NET
    /// `[System.Drawing.Icon]::ExtractAssociatedIcon` 是否同一语义。
    ///
    /// 2026-10-01 本机实机对拍（只读，两侧都按 32bpp 全字节求和；BGRA/RGBA 只是通道次序，
    /// 字节集合相同故可直接比）：
    /// ```text
    /// 文件            .NET ExtractAssociatedIcon   ExtractIconExW   SHGetFileInfoW
    /// shell32.dll     32x32 sum=625146             sum=625146 ✓     sum=592220 ✗
    /// explorer.exe    32x32 sum=604123             sum=604123 ✓     sum=604116 ✗
    /// urlmon.dll      32x32 sum=139251             sum=139251 ✓     sum=592220 ✗
    /// ```
    /// **结论：`ExtractIconExW` 索引 0 是等价替换**，三件全等；外壳通道三件全不等，且
    /// shell32.dll 与 urlmon.dll 拿到的是同一张图（sum=592220）—— 那正是「DLL 文件类型图标」，
    /// 证明 `SHGetFileInfoW` 问的不是 PE 内嵌资源。所以本模块两条通道都要保留，
    /// 但右键菜单 CLSID 图标只能走 [`first_icon_data_url`]。
    /// 尺寸与可解码性在这里断言；sum 是机器相关值（换 Windows  build/主题会变），只作打印基线。
    #[test]
    #[ignore = "真实调用 Win32 图标 API 并读系统 PE，发布前门禁跑"]
    fn live_probe_两条通道与dotnet基线同尺寸() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let files = [
            format!(r"{root}\System32\shell32.dll"),
            format!(r"{root}\explorer.exe"),
            format!(r"{root}\System32\urlmon.dll"),
        ];
        let mut probed = 0;
        for f in &files {
            let path = Path::new(f);
            if !path.is_file() {
                println!("{}: 缺件，跳过", path.file_name().unwrap_or_default().to_string_lossy());
                continue;
            }
            let first = first_icon_data_url(path).expect("PE 首图标通道失败");
            let shell = file_icon_data_url(path).expect("外壳图标通道失败");
            probed += 1;
            println!(
                "{}: ExtractIconExW={:?} SHGetFileInfoW={:?}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                rgba_stats(&first),
                rgba_stats(&shell)
            );
            assert!(first.starts_with("data:image/png;base64,"), "{f} 前缀不对");
            let (w, h, _) = rgba_stats(&first).unwrap_or((0, 0, 0));
            assert!([16, 32, 48, 256].contains(&w) && w == h, "{f} 首图标尺寸异常: {w}x{h}");
        }
        // 三件全缺件说明探测口径坏了（例如 SystemRoot 取空），这时"没有失败"不等于"通过"
        assert!(probed >= 2, "实机探测样本不足（probed={probed}），对拍结论不成立");
    }

    /// 不存在的文件必须 Err，不得交出空 dataURL（渲染层按 null 回落）。
    #[test]
    fn 缺件必须报错而不是交出空图() {
        assert!(first_icon_data_url(Path::new(r"C:\不存在\a.dll")).is_err());
        assert!(file_icon_data_url(Path::new(r"C:\不存在\a.dll")).is_err());
    }

    // ===== 磁盘缓存 =====

    #[test]
    fn 缓存键区分通道且对内容变化敏感() {
        let dir = std::env::temp_dir().join(format!("trim-icache-key-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("app.exe");
        std::fs::write(&p, b"hello").unwrap();

        let shell = cache_key("shell", &p).expect("键生成失败");
        let pe = cache_key("pe-first", &p).expect("键生成失败");
        assert_ne!(shell, pe, "同一文件两通道键必须不同——互串就是给调用方发另一条通道的图标");
        assert_eq!(
            cache_key("shell", &p).as_deref(),
            Some(shell.as_str()),
            "同态文件的键必须稳定，否则缓存永不命中"
        );
        assert_eq!(shell.len(), 16, "键长是 prune 文件名判据（16 hex + .png）的一半，改键长必须连改 is_cache_file_name");
        assert!(
            shell
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "键必须是小写 hex（prune 只认这个形态）"
        );

        // 应用升级替换 exe（size 变）后必须换键，不许给新版本发旧图标
        std::fs::write(&p, b"hello world").unwrap();
        let after = cache_key("shell", &p).expect("改写后键生成失败");
        assert_ne!(shell, after, "文件内容变化后键必须换新");

        // 目录拿不到 mtime 口径，只按路径生成键（外壳对目录恒发通用文件夹图标）
        let dir_key = cache_key("shell", &dir).expect("目录键生成失败");
        assert_eq!(dir_key.len(), 16);

        // 不存在的目标没有键——调用方走直接提取透传原错误，不许拿残键乱命中
        assert!(cache_key("shell", &dir.join("nope.exe")).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn 损坏缓存按未命中处理并删除() {
        let dir = std::env::temp_dir().join(format!("trim-icache-corrupt-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("abcd.png"), b"not a png").unwrap();
        assert!(cached_png(&dir, "abcd").is_none(), "非 PNG 字节不许当命中交出去");
        assert!(!dir.join("abcd.png").exists(), "损坏缓存必须被删，否则这个键永远命中坏文件");

        std::fs::write(dir.join("beef.png"), PNG_MAGIC).unwrap();
        assert!(cached_png(&dir, "beef").is_some(), "魔数合法即视为可服务（读取侧只设魔数闸）");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn 超水位回收最旧且不碰外来文件() {
        let dir = std::env::temp_dir().join(format!("trim-icache-prune-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let name = |i: usize| format!("{i:016x}.png");
        for i in 0..(CACHE_PRUNE_THRESHOLD + 10) {
            std::fs::write(dir.join(name(i)), PNG_MAGIC).unwrap();
        }
        // 外来文件：名字不是 16 hex 形态，不许被回收
        let outsider = dir.join("user-put-this.png");
        std::fs::write(&outsider, b"x").unwrap();

        prune_icon_cache(&dir);

        let left = std::fs::read_dir(&dir).unwrap().flatten().count();
        assert_eq!(
            left,
            CACHE_KEEP + 1,
            "回收后应只剩 CACHE_KEEP 个缓存文件 + 1 个外来文件"
        );
        // 文件名（键）是 mtime 相等时的次序：批量写入同秒时删的必须还是字典序最旧的那批
        assert!(!dir.join(name(0)).exists(), "最旧缓存必须先删");
        assert!(dir.join(name(CACHE_PRUNE_THRESHOLD + 9)).exists(), "最新缓存必须保留");
        assert!(outsider.exists(), "外来文件不许动");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 实机端到端（发布前门禁）：同一路径第二次提取必须来自磁盘缓存。
    /// 命中的证据 = 缓存文件落盘 + 两次返回逐字节一致；「是否真跳过了 GDI」由
    /// 键口径单测保证（键含 mtime/size，未变必同键）。提取本身的行为由上面的
    /// live_probe 覆盖，这里只验缓存层接入后语义没变。
    /// 样本刻意避开 live_probe 的三件（shell32/explorer/urlmon）：那条测试也走
    /// shell 通道且无缓存语义，两测并发首提取同一文件会偶发打挂 GDI 调用。
    #[test]
    #[ignore = "真实调用 Win32 图标 API 并写数据目录，发布前门禁跑"]
    fn 实机二次提取命中磁盘缓存() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let target = PathBuf::from(root).join("System32").join("notepad.exe");
        assert!(target.is_file(), "探测样本缺失：{}", target.display());

        let first = file_icon_data_url(&target).expect("首次提取失败");
        let key = cache_key("shell", &target).expect("键生成失败");
        let cached = icon_cache_dir().join(format!("{key}.png"));
        assert!(cached.is_file(), "首次提取后缓存文件必须落盘: {}", cached.display());

        let second = file_icon_data_url(&target).expect("二次提取失败");
        assert_eq!(first, second, "同键两次结果必须逐字节一致（第二次应来自缓存）");
    }
}