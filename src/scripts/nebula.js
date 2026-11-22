// nebula.js - 提案 V1：星云环境层（2026-11-21 用户裁定解除全屏环境画布红线）
// 与 aurora.js 同款纪律：装饰层由 JS 挂载（不进 HTML 结构面、不进无障碍树、子窗不挂）；
// 画布内部分辨率 0.6×、DPR≤1.5；重绘走低频节拍而不是 rAF 每帧——aurora 的实测教训
// （大图层每帧合成 = 渲染进程常驻单核近一成）对逐帧画布同样成立，百毫秒级一拍肉眼无台阶。
// hidden 暂停、RM 静态单帧。颜色实时取主题 token（暗/浅自动跟随）。
(function () {
  'use strict';

  var CANVAS_CLASS = 'nebula-canvas';
  var MARK = 'data-nebula';
  var TICK_MS = 120;
  var MAX_DPR = 1.5;
  var RES_SCALE = 0.6;
  var STAR_COUNT = 90;
  // 三团 blob：颜色 token、基准位置、漂移振幅（vw/vh 比例）、半径（占短边比）、alpha
  var BLOBS = [
    { v: '--accent', x: 0.24, y: 0.30, ax: 0.06, ay: 0.07, r: 0.52, a: 0.34 },
    { v: '--info', x: 0.78, y: 0.24, ax: 0.07, ay: 0.06, r: 0.44, a: 0.24 },
    { v: '--success', x: 0.52, y: 0.78, ax: 0.08, ay: 0.05, r: 0.48, a: 0.20 },
  ];
  var canvas = null;
  var ctx = null;
  var timer = 0;
  var stars = [];
  var pointer = { x: 0.5, y: 0.5, tx: 0.5, ty: 0.5 };

  function reduced() {
    try { return !!(window.ds && window.ds.reducedMotion && window.ds.reducedMotion()); } catch (e) { return false; }
  }

  function mount() {
    var layout = document.querySelector('.layout');
    if (!layout || layout.querySelector('[' + MARK + ']')) return;
    canvas = document.createElement('canvas');
    canvas.className = CANVAS_CLASS;
    canvas.setAttribute(MARK, '');
    canvas.setAttribute('aria-hidden', 'true');
    layout.insertBefore(canvas, layout.firstChild);
    ctx = canvas.getContext('2d');
    stars = [];
    for (var i = 0; i < STAR_COUNT; i++) {
      stars.push({ x: Math.random(), y: Math.random(), r: 0.5 + Math.random(), sp: 0.4 + Math.random() * 1.2, ph: Math.random() * 6.28 });
    }
    sizeCanvas();
  }

  function sizeCanvas() {
    if (!canvas) return;
    var dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR);
    canvas.width = Math.max(1, Math.round(canvas.clientWidth * RES_SCALE * dpr));
    canvas.height = Math.max(1, Math.round(canvas.clientHeight * RES_SCALE * dpr));
  }

  // "#6A59C9" → [106,89,201]；取不到 token（异常主题态）时跳过该 blob，画布不炸
  function tokenRGB(v) {
    var m = /^#([0-9a-f]{6})$/i.exec((getComputedStyle(document.documentElement).getPropertyValue(v) || '').trim());
    return m ? [parseInt(m[1].slice(0, 2), 16), parseInt(m[1].slice(2, 4), 16), parseInt(m[1].slice(4, 6), 16)] : null;
  }

  function draw(t, staticFrame) {
    if (!ctx) return;
    var W = canvas.width, H = canvas.height;
    if (!W || !H) return;
    pointer.x += (pointer.tx - pointer.x) * 0.04;
    pointer.y += (pointer.ty - pointer.y) * 0.04;
    var dark = document.documentElement.classList.contains('theme-dark');
    ctx.clearRect(0, 0, W, H);
    ctx.globalCompositeOperation = dark ? 'lighter' : 'source-over';
    var px = (pointer.x - 0.5) * 36 * RES_SCALE;
    var py = (pointer.y - 0.5) * 30 * RES_SCALE;
    for (var i = 0; i < BLOBS.length; i++) {
      var b = BLOBS[i];
      var rgb = tokenRGB(b.v);
      if (!rgb) continue;
      var cx = (b.x + Math.sin(t * 0.11 + i * 2.1) * b.ax) * W + px;
      var cy = (b.y + Math.cos(t * 0.09 + i * 1.7) * b.ay) * H + py;
      var r = b.r * Math.min(W, H);
      var g = ctx.createRadialGradient(cx, cy, 0, cx, cy, r);
      var al = staticFrame ? b.a * 0.7 : b.a * (dark ? 1 : 0.6);
      g.addColorStop(0, 'rgba(' + rgb[0] + ',' + rgb[1] + ',' + rgb[2] + ',' + al.toFixed(3) + ')');
      g.addColorStop(0.55, 'rgba(' + rgb[0] + ',' + rgb[1] + ',' + rgb[2] + ',' + (al * 0.4).toFixed(3) + ')');
      g.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, 6.283);
      ctx.fill();
    }
    var ink = dark ? '255,255,255' : tokenRGB('--fg-primary')?.join(',') || '41,37,54';
    for (var s = 0; s < stars.length; s++) {
      var st = stars[s];
      var a = staticFrame ? 0.3 : (0.14 + 0.34 * (0.5 + 0.5 * Math.sin(t * st.sp + st.ph))) * (dark ? 1 : 0.5);
      ctx.fillStyle = 'rgba(' + ink + ',' + a.toFixed(3) + ')';
      ctx.beginPath();
      ctx.arc(st.x * W, st.y * H, st.r * RES_SCALE * 1.4, 0, 6.283);
      ctx.fill();
    }
  }

  // F4c-01（2026-11-22 CDP 实测）：start 时判一次 reduced() 不够——运行中开
  // 「减少动态效果」后 tick 只看 hidden，星云仍持续重绘。改为 matchMedia change
  // 双向切换：进 RM 落静态单帧并停拍，退出 RM 重启动态拍（与 aurora 同口径）。
  var mqReduce = null;
  function reduceMQ() {
    if (!mqReduce) mqReduce = window.matchMedia('(prefers-reduced-motion: reduce)');
    return mqReduce;
  }
  function applyMotionMode() {
    if (!ctx) return;
    if (reduced()) {
      if (timer) { clearInterval(timer); timer = 0; }
      draw(3.2, true);
    } else if (!timer) {
      timer = setInterval(function () {
        if (document.hidden || !ctx) return;
        draw(performance.now() / 1000, false);
      }, TICK_MS);
    }
  }
  function onReduceChange() { applyMotionMode(); }
  function start() {
    mount();
    if (!ctx) return;
    // 节拍重绘而非 rAF：理由见文件头（aurora 实测教训）。hidden 时暂停。
    applyMotionMode();
    var mq = reduceMQ();
    if (mq.addEventListener) mq.addEventListener('change', onReduceChange);
    else if (mq.addListener) mq.addListener(onReduceChange);
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('resize', onResize);
    document.addEventListener('pointermove', onPointer, { passive: true });
  }
  function onVisibility() { /* 节拍内自判 hidden，无需额外处理 */ }
  function onResize() { sizeCanvas(); if (reduced()) draw(3.2, true); }
  function onPointer(e) {
    pointer.tx = e.clientX / Math.max(1, window.innerWidth);
    pointer.ty = e.clientY / Math.max(1, window.innerHeight);
  }

  // 与 mouse-trail.js 同款 readyState 守卫：本脚本由 app.js 的 IDLE_SCRIPTS 在首帧空闲后注入
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
