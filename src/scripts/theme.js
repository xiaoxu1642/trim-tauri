// theme.js - 主题管理（提案 V1：浅色缺省 + 外观镜像 theme 键可切深色）
// v2.1 曾固定浅色；2026-11-21 用户裁定恢复深色档（main.css :root 碳墨暗档重新可达）。
// 档位真源：appearance.json 的 theme 键（'light'|'dark'，经 pathbinding-appearance 族写），
// localStorage 镜像供首帧（theme-boot）；本文件负责 body 层同步、meta 跟随与后端回读采纳。
(function () {
  'use strict';

  // F3-L08：真实语义是「桥是否就绪」—— Tauri 轨下桥就绪即 true，与「是不是 Electron」
  // 无关；IS_ELECTRON 这个名字会让后来者把就绪判断误读成环境判断。
  const HAS_BRIDGE = !!window.api?.app;

  // 应用 Mica 模式（electron-mica 是历史沿用的类名；桥就绪且系统支持时背景透明，
  // 让原生 Mica 透出）
  function applyMicaMode(enabled) {
    document.body.classList.toggle('electron-mica', enabled);
  }

  function applyTheme() {
    // 档位由 html 类承载（theme-boot 已定级），body 镜像同一档——body 级 token 覆盖
    // html 级，两处必须同档，否则 body 静态类会把深色档静默盖回浅色。
    const dark = document.documentElement.classList.contains('theme-dark');
    document.body.classList.toggle('theme-dark', dark);
    document.body.classList.toggle('theme-light', !dark);

    // 标题栏是独立系统表面。F3-L12：主题色只有一个真源 —— main.css 的 --bg-app；
    // 这里从计算样式读出来再写 meta，不再在本文件里抄一份色值（抄一份 = 两处各说各话）。
    // 4 份 HTML 的静态 meta 由 theme-boot 之外的首帧路径供给，其值与 --bg-app 的对拍由
    // tools/check-css-tokens.mjs 断言（meta 与 token 不等即判红）。
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      const bgApp = getComputedStyle(document.documentElement).getPropertyValue('--bg-app').trim();
      if (bgApp) meta.setAttribute('content', bgApp);
    }
  }

  // 设置页「界面主题」下拉入口。镜像+增量推真源走外观族出口；族未就位的异常时序才直写
  // 镜像兜底（boot 侧同款例外，见 theme-boot.js 头注）。
  function setTheme(name) {
    const dark = name === 'dark';
    document.documentElement.classList.toggle('theme-dark', dark);
    document.documentElement.classList.toggle('theme-light', !dark);
    applyTheme();
    syncThemeSelect();
    try {
      if (window.pathbindingAppearance?.save) {
        const ap = window.pathbindingAppearance.load();
        ap.theme = dark ? 'dark' : 'light';
        window.pathbindingAppearance.save(ap);
        return;
      }
    } catch (_) {}
    try {
      const ap = JSON.parse(localStorage.getItem('trim-appearance') || '{}') || {};
      ap.theme = dark ? 'dark' : 'light';
      localStorage.setItem('trim-appearance', JSON.stringify(ap));
    } catch (_) {}
  }

  function syncThemeSelect() {
    const sel = document.getElementById('themeSelect');
    if (sel) sel.value = document.documentElement.classList.contains('theme-dark') ? 'dark' : 'light';
  }

  // 后端回读采纳（启动期一次）：真源与镜像分叉（镜像被清理 / 手改）时采纳真源。
  // 与 pathbinding-appearance 的 settings-enter 回读同口径：后端优先。
  async function reconcileThemeWithBackend() {
    if (!HAS_BRIDGE || !window.api?.appearance?.getPrefs) return;
    try {
      const resp = await window.api.appearance.getPrefs();
      const t = resp && resp.success === true ? resp.data?.theme : null;
      if ((t === 'dark' || t === 'light') &&
          !document.documentElement.classList.contains('theme-' + t)) {
        setTheme(t);
      }
    } catch (e) {
      window.app?.log?.('warn', '主题真源回读失败: ' + ((e && e.message) || e));
    }
  }

  window.theme = {
    apply: applyTheme,
    applyMicaMode,
    setTheme
  };

  // 全局应用「设计系统」外观（背景模糊度 + 预设背景）：跨页面/启动即生效，
  // 与设置页共用 localStorage 键 'trim-appearance'，避免仅设置页生效。
  function applySkinAndPreset() {
    let ap = {};
    try { ap = JSON.parse(localStorage.getItem('trim-appearance') || '{}') || {}; } catch (e) {}
    // 背景模糊度（设置页整合4）：>0 挂 body[data-skin="glass"] 并按百分比缩放模糊半径（100% = 26px，与原液态玻璃
    // 一致；与 pathbinding.js 的 GLASS_MAX_BLUR_PX 共用同一约定，改动需两处同步）。v3.0 全局玻璃化：0% 仅表示「无
    // 磨砂」，容器仍为玻璃 alpha（表面 token 真源即玻璃值），不再有「经典不透明面板」态。旧 skin 键按 glass=100%/classic=0% 折算迁移。
    let blur = ap.bgBlur;
    let dirty = blur == null;
    if (dirty) {
      blur = 100;
      ap.bgBlur = blur;
      delete ap.skin;
    }
    // 首次启动（键不存在）的外观默认：预设壁纸 Doll·手办 + 壁纸模糊 20%。判据一律是「键不存在」而不是「值为空」——
    // 用户显式选过「无背景」存的是 ''、拖到 0% 存的是 0，那是选择不是缺省，覆盖它等于替用户改设置。落默认值同时写回。
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
    // 壁纸层模糊（--bg-blur）此前只有设置页脚本 pathbinding.js 会写，而它是进「设置」页才延迟加载 ⇒ 重启后没打开过
    // 设置页，壁纸一直是清晰的（存过的值和默认值都不生效）。启动期按同一套换算补上，设置页拖动时覆盖的是同一个属性。
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

    // 提案 V1：设置页主题下拉的初值与绑定（静态节点，首屏脚本期内已存在）。
    const themeSelect = document.getElementById('themeSelect');
    if (themeSelect) {
      syncThemeSelect();
      themeSelect.addEventListener('change', () => setTheme(themeSelect.value));
    }
    // 后端回读采纳（异步，不阻塞首帧外观）
    reconcileThemeWithBackend();

    // 桥就绪：检测 Mica 支持，启用透明背景
    if (HAS_BRIDGE && window.api?.app?.getInfo) {
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
        } catch (e) {
          window.app?.log?.('warn', '读取窗口材质失败: ' + ((e && e.message) || e));
        }
      } catch (e) {
        window.app?.log?.('warn', '读取系统信息失败: ' + ((e && e.message) || e));
      }
    }
  }
})();
