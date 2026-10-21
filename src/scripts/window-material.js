// window-material.js - 子窗口材质 / 主题同步
// 主窗口的同类逻辑在 theme.js；子窗口不加载 theme.js，这里补齐最小集：
//   1. 恒浅色：给 body 挂 theme-light（v2.1 应用固定浅色，不再跟随系统主题）
//   2. 按外观设置挂 electron-mica + data-material，让原生 Mica/亚克力透过半透明表面可见
//      （材质切换由主进程广播 appearance:material-changed，实时跟随主窗口设置）
// 挂载本件的窗口清单以 engine::guard::APP_WINDOWS 的子窗集合为准，不在此逐个点名
// （F3-M02：点名清单会随窗口退役腐烂，退役的预览窗例外句已删）。
(function () {
  'use strict';

  // F3-L08：真实语义是「桥是否就绪」—— Tauri 轨下桥就绪即 true，与「是不是 Electron」
  // 无关；IS_ELECTRON 这个名字会让后来者把就绪判断误读成环境判断。
  var HAS_BRIDGE = !!window.api?.app;
  // LG-4（2026-09-15）：DWM 材质支持位缓存——广播路径原先把 micaEnabled 写死 true，
  // 不支持原生 DWM 材质的机器（getInfo().micaEnabled=false）一旦主窗切档，子窗会被
  // 广播挂上 electron-mica 透明类而无原生垫底。支持位是机器能力，本会话内不变，
  // 初始握手取一次即可；getInfo 失败时按不支持回落（不透明 CSS 表面始终可用）。
  var dwmSupported = false;
  // 竞态兜底：广播若先于初始 Promise 返回（子窗启动瞬间恰逢主窗切档），
  // 初始回调以最新广播值为准，避免用陈旧存储值覆盖
  var lastBroadcast = null;

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
    // v2.8.0：清理死代码——应用恒挂 theme-light（「固定浅色」产品决策），
    // 不再执行无效的 theme-dark 移除语句（main.css 暗色玻璃 token 已同步删除）
    // 口径 v2·M6：三个子窗的 <body> 现在**静态**挂 theme-light（本行退成兜底，幂等）。
    // 原先只靠这里挂，首帧落的是 :root 暗色 token，子窗按钮会闪一帧深灰再变透明——
    // 「脚本必须及时执行才有的底」正是本次要消掉的时序依赖。
    document.body.classList.add('theme-light');
  }

  // material='none' 或系统不支持 DWM 材质时移除透明化类，回落不透明 CSS 表面
  function applyMaterial(material, micaEnabled) {
    if (micaEnabled && material && material !== 'none') {
      document.body.classList.add('electron-mica');
      document.body.dataset.material = material;
    } else {
      document.body.classList.remove('electron-mica');
      delete document.body.dataset.material;
    }
  }

  function init() {
    applyTheme();
    if (!HAS_BRIDGE) {
      return;
    }
    Promise.all([
      window.api.app.getInfo().catch(function () { return null; }),
      window.api.appearance?.getMaterial?.().catch(function () { return null; })
    ]).then(function (results) {
      var info = results[0];
      var mat = results[1];
      dwmSupported = !!(info && info.micaEnabled);
      // 材质总开关关闭时按「无材质」回落（窗口界面升级3）；
      // 广播已到（LG-4 竞态兜底）则以其为准
      var stored = (mat && mat.materialEnabled === false) ? 'none' : (mat && mat.material);
      applyMaterial(lastBroadcast != null ? lastBroadcast : stored, dwmSupported);
    });

    // 主进程广播：材质变化实时跟随（主窗设置页切换材质时子窗即时生效）
    // F3-L03：订阅返回值收账（退订出口见文件末尾 window.windowMaterial）
    trackSubscription(window.api.appearance?.onMaterialChanged?.(function (material) {
      // LG-4：受支持位约束——不支持 DWM 材质的机器不挂透明类，回落不透明 CSS 表面
      lastBroadcast = material;
      applyMaterial(material, dwmSupported);
    }));

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
