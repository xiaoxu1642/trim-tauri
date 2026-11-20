// Motion.Lab-inspired cursor trail（鼠标拖尾）
// 提案 V1 落地（2026-11-21 用户裁定）：光点轨迹升级为彗星拖尾——单 canvas + lighter
// 合成的渐隐圆点（640ms 生命期），颜色实时取 --accent（主题感知）；偏好键 / 开关 /
// RM 降级链路一字未动，只换渲染端。
(function () {
  'use strict';

  // P2-13（2026-10-09）：真源迁后端 settings.json 的 `mouseTrail` 键（AGENTS §0.2：
  // 配置真源在 %APPDATA%，localStorage 只是镜像）；KEY 那套本地键降级为同步初值 +
  // 迁移来源 + 镜像。
  const KEY = 'trim-mouse-trail';
  const THROTTLE_MS = 22;      // 生成节流（R3b 正控钉此常量；彗星 45Hz 采样形态足够）
  const POINT_LIFE_MS = 640;   // 单点生命期：渐隐总时长，出画即回收
  const MAX_POINTS = 48;       // 同屏点数上限：高速划圈时封顶，防 rAF 追积压
  // 审查v4-M1：reduced-motion 必须使用时实时求值，禁止模块加载时固化快照
  // （固化会导致运行中切换系统「减少动态效果」偏好永不生效，9.6-B8 / v4-M1）
  function isReducedMotion() {
    if (window.ds && typeof window.ds.reducedMotion === 'function') return !!window.ds.reducedMotion();
    if (window.ds && typeof window.ds.reducedMotionFallback === 'function') return !!window.ds.reducedMotionFallback();
    return true;
  }

  let enabled = false;
  let enabledPref = readLsPref();
  let prefDirty = false;
  let layer = null;
  let canvas = null;
  let ctx = null;
  let points = [];
  let rafId = 0;
  let last = 0;
  // 拖尾色缓存：--accent 是主题 token（暗/浅两套值），html 类名一变即失效重取。
  let trailColor = '106, 89, 201';
  let colorHostClass = '';

  function readLsPref() {
    try { return localStorage.getItem(KEY) === 'true'; } catch (_) { return false; }
  }
  function readEnabled() { return enabledPref === true; }
  function writeEnabled(value) {
    enabledPref = value === true;
    prefDirty = true;
    try { localStorage.setItem(KEY, String(enabledPref)); } catch (_) { /* 镜像写失败不影响（真源在后端） */ }
    try { window.api?.settings?.setPref?.('mouseTrail', enabledPref)?.catch?.(() => {}); } catch (_) { /* 真源写入失败按镜像工作 */ }
  }

  // 后端真源回读：boolean ⇒ 采纳并即时应用；非 boolean（未设置/坏值）⇒ 把本地现值
  // 一次性迁移上去。prefDirty 时跳过采纳（读回的是写入前的旧值）。
  (async function syncPref() {
    try {
      const resp = await window.api?.settings?.getPrefs?.();
      if (!resp || !resp.success || prefDirty) return;
      const v = resp.data?.mouseTrail;
      if (typeof v === 'boolean') {
        if (v !== enabledPref) {
          enabledPref = v;
          try { localStorage.setItem(KEY, String(v)); } catch (_) { /* 镜像写失败不影响（真源已就位） */ }
          setEnabled(v);
        }
      } else {
        writeEnabled(enabledPref); // 迁移：后端没有值，把本地现值推上去
      }
    } catch (_) { /* 真源不可用按本地镜像工作 */ }
  })();
  function ensureLayer() {
    if (layer && document.body.contains(layer)) return layer;
    layer = document.createElement('div');
    layer.className = 'mouse-trail-layer';
    layer.setAttribute('aria-hidden', 'true');
    canvas = document.createElement('canvas');
    ctx = canvas.getContext('2d');
    layer.appendChild(canvas);
    document.body.appendChild(layer);
    sizeCanvas();
    return layer;
  }
  function sizeCanvas() {
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.round(window.innerWidth * dpr));
    canvas.height = Math.max(1, Math.round(window.innerHeight * dpr));
    canvas.style.width = window.innerWidth + 'px';
    canvas.style.height = window.innerHeight + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  // --accent 形如 "#6A59C9"；解析失败沿用上次值（拖尾是装饰，取色失败不该炸）
  function refreshTrailColor() {
    const host = document.documentElement;
    const cls = host.className;
    if (cls === colorHostClass) return;
    colorHostClass = cls;
    const v = getComputedStyle(host).getPropertyValue('--accent').trim();
    const m = /^#([0-9a-f]{6})$/i.exec(v);
    if (m) {
      const n = parseInt(m[1], 16);
      trailColor = ((n >> 16) & 255) + ', ' + ((n >> 8) & 255) + ', ' + (n & 255);
    }
  }
  function drawFrame() {
    rafId = 0;
    if (!ctx || !enabled) { points = []; return; }
    const now = performance.now();
    refreshTrailColor();
    ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
    points = points.filter((p) => now - p.t < POINT_LIFE_MS);
    if (points.length) {
      // lighter 合成：圆点叠亮成彗星尾（提案 V1 形态；透明度按剩余生命期线性衰减）
      ctx.globalCompositeOperation = 'lighter';
      for (const p of points) {
        const k = 1 - (now - p.t) / POINT_LIFE_MS;
        ctx.fillStyle = 'rgba(' + trailColor + ', ' + (0.4 * k).toFixed(3) + ')';
        ctx.beginPath();
        ctx.arc(p.x, p.y, 1 + 7 * k, 0, 6.283);
        ctx.fill();
      }
      ctx.globalCompositeOperation = 'source-over';
    }
    // 无点即停 rAF：拖尾是纯装饰，空转循环是对电池的浪费（aurora.js 同款纪律）
    if (points.length) rafId = requestAnimationFrame(drawFrame);
    else if (canvas) ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
  }
  // F5-M04：勾选框显示的是**用户偏好**，生效态另算。旧实现把 checked 绑到生效态
  // （= !reduceMotion && 偏好），偏好为 ON 而系统开着「减少动态效果」时勾选框显示 OFF，
  // 用户点一下被 setEnabled 立即弹回，界面上没有任何一处说明原因——与同库液态玻璃
  // 「下拉必须仍显示用户选的那一档」的两态口径分叉。降级必须给原因。
  function syncToggleUi() {
    const toggle = document.getElementById('mouseTrailToggle');
    if (!toggle) return;
    toggle.checked = enabledPref === true;
    if (enabledPref === true && isReducedMotion()) {
      toggle.setAttribute('data-tip', '系统已开启「减少动态效果」，鼠标拖尾暂不生效');
    } else {
      // 不解释原因时撤掉本行覆盖，让宿主 label 上的功能说明显示出来
      toggle.removeAttribute('data-tip');
    }
  }
  function setEnabled(value) {
    enabled = !isReducedMotion() && Boolean(value);
    document.body.classList.toggle('mouse-trail-on', enabled);
    syncToggleUi();
    if (!enabled && layer) {
      // C6：关闭时彻底移除图层（原来只清空光点，空 div 一直挂在 DOM 里）
      if (rafId) cancelAnimationFrame(rafId);
      rafId = 0;
      points = [];
      layer.remove();
      layer = null;
      canvas = null;
      ctx = null;
    }
  }
  function spawn(x, y) {
    if (!enabled || isReducedMotion()) return;
    const now = performance.now();
    if (now - last < THROTTLE_MS) return;
    last = now;
    ensureLayer();
    points.push({ x, y, t: now });
    if (points.length > MAX_POINTS) points.shift();
    if (!rafId) rafId = requestAnimationFrame(drawFrame);
  }
  function init() {
    setEnabled(readEnabled());
    // 系统偏好运行中切换即时联动：开启→停用并移除图层（走 C6 路径清理节点），关闭→恢复
    const rmMQ = window.ds?.reducedMotionQuery?.();
    if (rmMQ) {
      const onChange = () => setEnabled(readEnabled());
      if (typeof rmMQ.addEventListener === 'function') rmMQ.addEventListener('change', onChange);
      else if (typeof rmMQ.addListener === 'function') rmMQ.addListener(onChange);
    }
    document.addEventListener('pointermove', (e) => {
      if (e.pointerType && e.pointerType !== 'mouse') return;
      spawn(e.clientX, e.clientY);
    }, { passive: true });
    // 彗星画布跟随窗口尺寸（DPR 换算在 sizeCanvas 内；图层不存在时是空操作）
    window.addEventListener('resize', sizeCanvas, { passive: true });
    const toggle = document.getElementById('mouseTrailToggle');
    toggle && toggle.addEventListener('change', () => {
      writeEnabled(toggle.checked);
      setEnabled(toggle.checked);
    });
  }

  // 审查 v3-M3：本脚本由 app.js 的 IDLE_SCRIPTS 在**首帧空闲后**动态注入，
  // 届时 DOMContentLoaded 早已发生——顶层注册该事件等于 init 永不执行
  //（「启用鼠标拖尾」开关静默失效）。与 updater-ui.js 同款 readyState 守卫。
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  window.mouseTrail = { setEnabled, isEnabled: () => enabled };
})();



