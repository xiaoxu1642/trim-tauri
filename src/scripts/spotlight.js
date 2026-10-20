// spotlight.js - 跟随聚光 · Spotlight（Motion.Lab spotlight-follow 改，窗口界面升级3）
// 仅作用于「选择块」：按钮(.btn) / 分段标签(.filter-tab) / 分类胶囊(.maint-tab) /
// 材质卡(.material-card) / 单选行(.radio-row)。光斑是一层绝对定位的 .spot-layer，
// radial 渐变按宿主圆角裁剪；坐标由 document 级事件委托写入 --spot-x/--spot-y，
// 不给元素逐个挂监听，动态渲染的列表按钮（复制/打开/清理该项等）同样生效。
// prefers-reduced-motion 实时求值：reduce 时不生成光斑、残留光斑立即熄灭（design-system 硬性约束 3）。
(function () {
  'use strict';

  // 审查v4-M1：reduced-motion 实时求值——原实现模块加载时固化并提前 return，
  // 运行中切换系统「减少动态效果」偏好永不生效。
  // A3-L06：MediaQueryList 对象的缓存与实时求值统一由 ds.reducedMotion() 承担。
  function isReducedMotion() {
    return !!(window.ds && window.ds.reducedMotion && window.ds.reducedMotion());
  }

  var HOST_SELECTOR = '.btn, .filter-tab, .maint-tab, .material-card, .radio-row';
  var LAYER_CLASS = 'spot-layer';
  var current = null;
  // 性能 v3 ②：原实现每个 pointermove 都做「closest → getBoundingClientRect → 写两个
  // CSS 变量 → querySelector(':scope > .spot-layer')」，即每事件一次强制回流。
  // 现在几何快照与光斑层都按宿主缓存（换宿主才重量/重取），坐标写入走 rAF 合帧。
  var currentLayer = null;  // 当前宿主的光斑层（换宿主即作废，重进时再取）
  var currentRect = null;   // 进入宿主时量一次的几何快照
  var spotRaf = 0;
  var pendingX = 0, pendingY = 0;

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
    // 换宿主（含置空）即作废按宿主缓存的几何与光斑层，重进时重新量/重新取
    currentLayer = null;
    currentRect = null;
    if (current) current.classList.add('spot-active');
  }

  function applySpot() {
    spotRaf = 0;
    var host = current;
    if (!host) return;
    if (!currentRect) {
      var r = host.getBoundingClientRect();
      currentRect = { left: r.left, top: r.top };
    }
    host.style.setProperty('--spot-x', (pendingX - currentRect.left).toFixed(1) + 'px');
    host.style.setProperty('--spot-y', (pendingY - currentRect.top).toFixed(1) + 'px');
    // 光斑层只需存在一次（原实现每事件 querySelector 一趟）。parentNode 校验兜住
    // 「同一宿主节点被清空子节点」这类不换节点的重渲染，避免层丢了以后不再补。
    if (!currentLayer || currentLayer.parentNode !== host) currentLayer = ensureLayer(host);
  }

  document.addEventListener('pointermove', function (e) {
    if (isReducedMotion()) { setCurrent(null); return; }
    var host = hostFromEvent(e);
    setCurrent(host);
    if (!host) return;
    pendingX = e.clientX;
    pendingY = e.clientY;
    if (!spotRaf) spotRaf = requestAnimationFrame(applySpot);
  }, { passive: true });

  // 鼠标离开窗口 / 窗口失焦时熄灭光斑
  document.addEventListener('pointerleave', function () { setCurrent(null); });
  window.addEventListener('blur', function () { setCurrent(null); });
  // 滚动只作废几何快照（不灭光斑）：滚动后宿主的视口坐标变了，缓存的 rect 会失准，
  // 下一次 move 重量一次即可（原实现靠每事件重量自动校正，这里改成按需重量）。
  window.addEventListener('scroll', function () { currentRect = null; }, { passive: true, capture: true });
})();
