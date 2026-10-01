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

use std::ffi::c_void;
use std::path::Path;

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
    let png = shell_icon_png(path)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(png);
    Ok(format!("data:image/png;base64,{b64}"))
}

/// 提取 **PE 内嵌的第一个图标**并编码为 PNG dataURL（资源视角）。
/// 右键菜单 CLSID 图标链用：`InprocServer32` 指向的 dll/exe 要显示它自己带的图标，
/// 不是「DLL 文件类型」图标。文件没有内嵌图标时返回 Err，由调用方决定回落姿势。
pub fn first_icon_data_url(path: &Path) -> Result<String, String> {
    if !path.is_file() {
        return Err("路径不是已存在的文件".into());
    }
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
        let png = result?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(png);
        Ok(format!("data:image/png;base64,{b64}"))
    }
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
}