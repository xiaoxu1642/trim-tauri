// theme.js - 主题管理（恒浅色）
// v2.1（2026-09-10 需求变更）：应用固定为浅色模式，删除深浅切换与系统跟随；
// 保留 Mica 材质检测与外观设置（背景模糊度/预设背景/强调色渐变）。
(function () {
  'use strict';

  const IS_ELECTRON = !!window.api?.app;

  // 应用 Mica 模式（Electron + Windows 11 时背景透明，让原生 Mica 透出）
  function applyMicaMode(enabled) {
    document.body.classList.toggle('electron-mica', enabled);
  }

  function applyTheme() {
    // 恒浅色：只挂 theme-light（v2.8.0 清理死代码：无效的 theme-dark 移除语句已删除，
    // main.css 暗色玻璃 token 已同步删除）
    document.body.classList.add('theme-light');

    // 标题栏是独立系统表面，固定浅色
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', '#f7f8fb');

    ensureRingGradientDef();
  }

  // 审查 7-2：名实一致——本函数只在首次调用时创建 defs（之后幂等返回），非每次更新
  // 审查 5-2：环形进度渐变改走强调色 token（两 stop 同色保 url() 引用结构），主题/强调色切换自动跟随
  function ensureRingGradientDef() {
    let defs = document.getElementById('ringGradientDef');
    if (!defs) {
      defs = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      defs.setAttribute('width', '0');
      defs.setAttribute('height', '0');
      defs.style.position = 'absolute';
      defs.innerHTML = '<defs><linearGradient id="ringGradient" x1="0%" y1="0%" x2="100%" y2="100%">' +
        '<stop offset="0%" stop-color="var(--accent, #6A59C9)"/>' +
        '<stop offset="100%" stop-color="var(--accent, #6A59C9)"/>' +
        '</linearGradient></defs>';
      defs.id = 'ringGradientDef';
      document.body.appendChild(defs);
    }
  }

  window.theme = {
    apply: applyTheme,
    applyMicaMode
  };

  // 全局应用「设计系统」外观（背景模糊度 + 预设背景）：跨页面/启动即生效，
  // 与设置页共用 localStorage 键 'trim-appearance'，避免仅设置页生效。
  function applySkinAndPreset() {
    let ap = {};
    try { ap = JSON.parse(localStorage.getItem('trim-appearance') || '{}') || {}; } catch (e) {}
    // 背景模糊度（设置页整合4）：>0 挂 body[data-skin="glass"] 并按百分比缩放模糊半径
    // （100% = 26px，与原液态玻璃一致；与 pathbinding.js 的 GLASS_MAX_BLUR_PX 共用同一约定，
    // 改动需两处同步）。v3.0 全局玻璃化：0% 仅表示「无磨砂」，容器仍为玻璃 alpha
    // （表面 token 真源即玻璃值），不再有「经典不透明面板」态。旧 skin 键按 glass=100% / classic=0% 折算迁移。
    let blur = ap.bgBlur;
    let dirty = blur == null;
    if (dirty) {
      blur = 100;
      ap.bgBlur = blur;
      delete ap.skin;
    }
    // 首次启动（键不存在）的外观默认：预设壁纸 Doll·手办 + 壁纸模糊 20%。判据一律是
    // 「键不存在」而不是「值为空」——用户显式选过「无背景」存的是 ''、拖到 0% 存的是 0，
    // 那是选择不是缺省，覆盖它等于替用户改设置。落默认值同时写回，让设置页读到同一个值。
    if (ap.presetBg == null) {
      ap.presetBg = window.ds?.DEFAULT_PRESET_BG || '';
      dirty = true;
    }
    if (typeof ap.wallpaperBlur !== 'number') {
      ap.wallpaperBlur = window.ds?.DEFAULT_WALLPAPER_BLUR ?? 0;
      dirty = true;
    }
    if (dirty) {
      try { localStorage.setItem('trim-appearance', JSON.stringify(ap)); } catch (e) {}
    }
    if (blur > 0) {
      document.body.dataset.skin = 'glass';
      // 审查 5-5：上限与 pathbinding 共用 ds 常量（GLASS_MAX_BLUR_PX），消除两处硬编码漂移
      document.documentElement.style.setProperty('--glass-blur', (blur / 100 * (window.ds?.GLASS_MAX_BLUR_PX || 26)).toFixed(1) + 'px');
    } else {
      delete document.body.dataset.skin;
      document.documentElement.style.removeProperty('--glass-blur');
    }
    // 壁纸层模糊（--bg-blur）此前只有设置页脚本 pathbinding.js 会写，而它是进「设置」页
    // 才延迟加载 ⇒ 重启后没打开过设置页，壁纸一直是清晰的（存过的值和默认值都不生效）。
    // 启动期按同一套换算补上，设置页拖动时覆盖的是同一个属性。
    if (typeof ap.wallpaperBlur === 'number') {
      const wpMax = window.ds?.WALLPAPER_MAX_BLUR_PX || 20;
      document.documentElement.style.setProperty('--bg-blur', (ap.wallpaperBlur / 100 * wpMax).toFixed(1) + 'px');
    }
    if (ap.presetBg) document.body.dataset.presetBg = ap.presetBg;
    else delete document.body.dataset.presetBg;
  }

  // 初始化
  document.addEventListener('DOMContentLoaded', () => {
    // P3-1（审查 2026-10-07）：原为 async 处理器，reject 即浮动 Promise —— 启动期外观
    // 初始化会静默中断且不留痕。抽成命名函数 + 显式 catch 收口。
    initAppearance().catch((e) => {
      window.app?.log?.('warn', '主题初始化异常: ' + ((e && e.message) || e));
    });
  });

  async function initAppearance() {
    applyTheme();
    applySkinAndPreset();

    // Electron 模式：检测 Mica 支持，启用透明背景
    if (IS_ELECTRON && window.api?.app?.getInfo) {
      try {
        const info = await window.api.app.getInfo();
        // 无论系统是否支持 DWM 材质，都同步渲染层状态：不支持时仍使用
        // 对应的 CSS 表面作为可读回退，支持时再叠加原生 Mica/Acrylic。
        applyMicaMode(Boolean(info.micaEnabled));
        try {
          const resp = await window.api?.appearance?.getMaterial?.();
          if (resp && resp.material) {
            // 材质总开关关闭时按「无材质」落 dataset，与手动选择 none 观感一致（窗口界面升级3）
            document.body.dataset.material = resp.materialEnabled === false ? 'none' : resp.material;
          }
        } catch (e) {}
      } catch (e) {
        // 忽略
      }
    }
  }
})();
