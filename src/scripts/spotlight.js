// spotlight.js - 跟随聚光 · Spotlight（Motion.Lab spotlight-follow 改，窗口界面升级3）
// 仅作用于「选择块」：按钮(.btn) / 分段标签(.filter-tab) / 分类胶囊(.maint-tab) /
// 材质卡(.material-card) / 单选行(.radio-row)。光斑是一层绝对定位的 .spot-layer，
// radial 渐变按宿主圆角裁剪；坐标由 document 级事件委托写入 --spot-x/--spot-y，
// 不给元素逐个挂监听，动态渲染的列表按钮（复制/打开/清理该项等）同样生效。
// prefers-reduced-motion 实时求值：reduce 时不生成光斑、残留光斑立即熄灭（design-system 硬性约束 3）。
(function () {
  'use strict';

  // 审查v4-M1：reduced-motion 实时求值——原实现模块加载时固化并提前 return，
  // 运行中切换系统「减少动态效果」偏好永不生效
  function isReducedMotion() {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }

  var HOST_SELECTOR = '.btn, .filter-tab, .maint-tab, .material-card, .radio-row';
  var LAYER_CLASS = 'spot-layer';
  var current = null;

  function hostFromEvent(e) {
    var t = e.target;
    if (!t || !t.closest) return null;
    var host = t.closest(HOST_SELECTOR);
    if (!host || host.disabled) return null; // 禁用按钮不聚光（label 等无 disabled 属性，不受影响）
    return host;
  }

  function ensureLayer(host) {
    var layer = host.querySelector(':scope > .' + LAYER_CLASS);
    if (!layer) {
      layer = document.createElement('span');
      layer.className = LAYER_CLASS;
      layer.setAttribute('aria-hidden', 'true');
      host.appendChild(layer);
    }
    return layer;
  }

  function setCurrent(host) {
    if (current === host) return;
    if (current) current.classList.remove('spot-active');
    current = host;
    if (current) current.classList.add('spot-active');
  }

  document.addEventListener('pointermove', function (e) {
    if (isReducedMotion()) { setCurrent(null); return; }
    var host = hostFromEvent(e);
    setCurrent(host);
    if (!host) return;
    var r = host.getBoundingClientRect();
    host.style.setProperty('--spot-x', (e.clientX - r.left).toFixed(1) + 'px');
    host.style.setProperty('--spot-y', (e.clientY - r.top).toFixed(1) + 'px');
    ensureLayer(host);
  }, { passive: true });

  // 鼠标离开窗口 / 窗口失焦时熄灭光斑（滚动后元素位移由下一次 move 自动校正）
  document.addEventListener('pointerleave', function () { setCurrent(null); });
  window.addEventListener('blur', function () { setCurrent(null); });
})();
