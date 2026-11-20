// window-material.js - 子窗口主题同步（表面实色化后仅存主题镜像与失焦纱）
// 主窗口的同类逻辑在 theme.js；子窗口不加载 theme.js，这里补齐最小集：
//   1. 外观主题跟随：给 body 挂 theme-light / theme-dark（镜像 trim-appearance 的 theme 键，
//      主窗改主题经跨窗 storage 事件实时联动）
//   2. 窗口焦点状态：失焦时 body 挂 win-inactive（main.css 的失焦纱降低存在感）
// 材质链（electron-mica / data-material / 最大化不透明护栏 syncMaximized）已随表面实色化
// 整链退役（方案 v1.6 §5.6）：表面全部实色，不再依赖 DWM 材质与护栏分支。
// 挂载本件的窗口清单以 engine::guard::APP_WINDOWS 的子窗集合为准，不在此逐个点名
// （F3-M02：点名清单会随窗口退役腐烂，退役的预览窗例外句已删）。
(function () {
  'use strict';

  // F3-L08：真实语义是「桥是否就绪」—— Tauri 轨下桥就绪即 true，与「是不是 Electron」
  // 无关；IS_ELECTRON 这个名字会让后来者把就绪判断误读成环境判断。
  var HAS_BRIDGE = !!window.api?.app;

  // F3-L03：订阅返回值收账 + 退订出口。当前 init() 单次执行无叠加，出口属窗口级
  // 回收复用时的保险，不主动调用（与 modal.destroy 同口径：时机由调用方定）。
  var _ipcDisposers = [];
  function trackSubscription(unsub) {
    if (typeof unsub === 'function') _ipcDisposers.push(unsub);
  }
  function teardownSubscriptions() {
    while (_ipcDisposers.length) {
      try { _ipcDisposers.pop()(); } catch (e) { /* 重复退订无副作用，忽略 */ }
    }
  }

  function applyTheme() {
    // 提案 V1：子窗跟随外观镜像 theme 键（'dark' ⇒ theme-dark，其余恒浅色）。html 层在
    // head 同步脚本求值期定级；body 静态 theme-light 在 init（DOMContentLoaded）镜像同一档
    // ——body 级 token 覆盖 html 级，两处必须同档。主窗改主题经跨窗 storage 事件实时联动。
    var dark = readThemeMirror() === 'dark';
    document.documentElement.classList.toggle('theme-dark', dark);
    document.documentElement.classList.toggle('theme-light', !dark);
    if (document.body) {
      document.body.classList.toggle('theme-dark', dark);
      document.body.classList.toggle('theme-light', !dark);
    }
  }

  // 首帧时序例外（theme-boot.js 头注同款）：head 求值期外观族未加载，直读镜像键；子窗只读。
  function readThemeMirror() {
    try {
      return (JSON.parse(localStorage.getItem('trim-appearance') || '{}') || {}).theme || '';
    } catch (_) { return ''; }
  }

  function init() {
    applyTheme();
    // 主窗「界面主题」切换 → 镜像更新 → 跨窗 storage 事件 → 子窗实时跟随。
    // e.key 为空（clear）也重读一次：镜像整清意味着回到缺省浅色。
    window.addEventListener('storage', function (e) {
      if (!e.key || e.key === 'trim-appearance') applyTheme();
    });
    if (!HAS_BRIDGE) {
      return;
    }
    // v2.8.0：窗口焦点状态——失焦时 body 挂 win-inactive（视觉纱降低存在感）
    trackSubscription(window.api.window?.onFocusState?.(function (state) {
      document.body.classList.toggle('win-inactive', !(state && state.focused));
    }));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // F3-L03：退订出口（窗口级回收复用时由调用方按需调用；重复调用安全）
  window.windowMaterial = { teardownSubscriptions: teardownSubscriptions };
})();
