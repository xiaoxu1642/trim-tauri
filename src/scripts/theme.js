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
  // 与设置页共用 localStorage 键 'winclean-appearance'，避免仅设置页生效。
  function applySkinAndPreset() {
    let ap = {};
    try { ap = JSON.parse(localStorage.getItem('winclean-appearance') || '{}') || {}; } catch (e) {}
    // 背景模糊度（设置页整合4）：>0 挂 body[data-skin="glass"] 并按百分比缩放模糊半径
    // （100% = 26px，与原液态玻璃一致；与 pathbinding.js 的 GLASS_MAX_BLUR_PX 共用同一约定，
    // 改动需两处同步）。v3.0 全局玻璃化：0% 仅表示「无磨砂」，容器仍为玻璃 alpha
    // （表面 token 真源即玻璃值），不再有「经典不透明面板」态。旧 skin 键按 glass=100% / classic=0% 折算迁移。
    let blur = ap.bgBlur;
    if (blur == null) {
      blur = 100;
      ap.bgBlur = blur;
      delete ap.skin;
      try { localStorage.setItem('winclean-appearance', JSON.stringify(ap)); } catch (e) {}
    }
    if (blur > 0) {
      document.body.dataset.skin = 'glass';
      // 审查 5-5：上限与 pathbinding 共用 ds 常量（GLASS_MAX_BLUR_PX），消除两处硬编码漂移
      document.documentElement.style.setProperty('--glass-blur', (blur / 100 * (window.ds?.GLASS_MAX_BLUR_PX || 26)).toFixed(1) + 'px');
    } else {
      delete document.body.dataset.skin;
      document.documentElement.style.removeProperty('--glass-blur');
    }
    if (ap.presetBg) document.body.dataset.presetBg = ap.presetBg;
    else delete document.body.dataset.presetBg;
  }

  // 初始化
  document.addEventListener('DOMContentLoaded', async () => {
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
  });
})();
