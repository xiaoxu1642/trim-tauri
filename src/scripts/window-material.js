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

  // F3-M02：子窗最大化不透明护栏（类名与 main.css 的 win-maximized 段同一口径）。
  // 三子窗保留原生装饰 ⇒ 用户可最大化，但此前 `win-maximized` 的生产者只有主窗 app.js：
  // 子窗最大化后 body.electron-mica 仍命中 main.css 的 :not(.win-maximized) 分支，--mat-veil 半透明
  // 面纱压在最大化期间可能失效的 DWM 材质层上（AGENTS §3：body.win-maximized 必须完全不透明）。
  // 判据不取 api.window.onResized 的 bounds.maximized：子窗 capabilities/subwindows.json 未给
  // core:window:allow-is-maximized（其描述写明该命令已删），桥接里 is_maximized 必然被拒并在 catch
  // 回落 maximized:false —— 订阅它只会永远挂不上类（假绿）。改用渲染层自证的等价判据：
  // 最大化时客户区宽度恰等于屏幕工作区宽度，高度只少掉原生标题栏（本机实测标准缩放、标准装饰，
  // 工作区 1920x1032、客户区 1920x1009，差 23 = 标题栏）。宽度卡死、高度留标题栏余量 ⇒
  // 只有「铺满工作区宽 + 接近满高」的窗口才判最大化；这种窗口本来也没有壁纸可透，按不透明处理无损失。
  // 若将来补回上述命令权限，应收敛回主窗的 is_maximized 判据。
  // WIDTH_TOLERANCE 是 DPI 取整容差；标题栏余量按 devicePixelRatio 换算（F3-M01-01：
  // 固定 64 在 278% 以上会小于实际标题栏，判据落空 ⇒ 最大化不挂 win-maximized）。
  // 23 是 100% 缩放下的标题栏实测高度，+8 留取整余量；64 下限保持标准缩放行为不变，
  // 96 上限覆盖 350%。每次判据现算：窗口跨显示器搬家时 devicePixelRatio 会变化。
  var WIDTH_TOLERANCE = 2;
  function captionAllowance() {
    var dpr = window.devicePixelRatio || 1;
    return Math.min(96, Math.max(64, Math.round(23 * dpr) + 8));
  }
  function syncMaximized() {
    var max = window.innerWidth >= window.screen.availWidth - WIDTH_TOLERANCE &&
              window.innerHeight >= window.screen.availHeight - captionAllowance();
    if (document.body.classList.contains('win-maximized') === max) return;
    document.body.classList.toggle('win-maximized', max);
    // 与主窗 app.js 的 onResized 同口径：强制一次回流，让合成器立即提交不透明帧，消除最大化/还原残帧
    void document.body.offsetHeight;
  }

  function init() {
    applyTheme();
    if (!HAS_BRIDGE) {
      return;
    }
    // F3-M02：窗口创建时可能已是最大化态，先对齐一次，再按 resize 实时跟随
    syncMaximized();
    window.addEventListener('resize', syncMaximized);
    // 尺寸监听与 IPC 订阅共用同一收账出口（teardownSubscriptions 一并摘除）
    trackSubscription(function () { window.removeEventListener('resize', syncMaximized); });
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
