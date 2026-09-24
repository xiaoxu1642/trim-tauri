//! Shell 图标提取（paths:app-icon / paths:file-icon）
//!
//! 对照 Electron 的 `app.getFileIcon(path, { size: 'large' })` → `NativeImage.toDataURL()`：
//! SHGetFileInfoW 取大图标 HICON → GetDIBits 取 32 位 BGRA → 转 RGBA → PNG → dataURL。
//!
//! 两个实测要点：
//! 1. **掩码型图标**（旧式仅 1bpp 掩码、颜色位图 alpha 全 0）：直接用会整张透明。
//!    与 Chromium 同口径的兜底——alpha 全 0 时视为不透明（按掩码语义填满）。
//! 2. GetDIBits 需要 DC；传入 NULL 在部分驱动上返回 0 行，故显式取屏幕 DC 再释放。

use std::ffi::c_void;
use std::path::Path;

use base64::Engine;
use windows::core::PCWSTR;
use windows::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO, BITMAPINFOHEADER,
    BI_RGB, DIB_RGB_COLORS, HBITMAP, HDC,
};
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};

/// 提取文件/目录图标并编码为 PNG dataURL。
/// 失败返回 Err（调用方按 `{success:false, dataUrl:null}` 回落，与 Electron 版一致）。
pub fn file_icon_data_url(path: &Path) -> Result<String, String> {
    let png = extract_icon_png(path)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(png);
    Ok(format!("data:image/png;base64,{b64}"))
}

fn extract_icon_png(path: &Path) -> Result<Vec<u8>, String> {
    if !path.exists() {
        return Err("路径不存在".into());
    }
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

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

        let result = (|| -> Result<Vec<u8>, String> {
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
        })();

        let _ = DestroyIcon(hicon);
        result
    }
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