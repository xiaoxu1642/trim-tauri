// Motion.Lab-inspired cursor trail（鼠标拖尾）
// 软件范围内轻量紫色光点轨迹：节流生成、CSS 过渡淡出、双重保障移除节点。
(function () {
  'use strict';

  // P2-13（2026-10-09）：真源迁后端 settings.json 的 `mouseTrail` 键（AGENTS §0.2：
  // 配置真源在 %APPDATA%，localStorage 只是镜像）；KEY 那套本地键降级为同步初值 +
  // 迁移来源 + 镜像。
  const KEY = 'trim-mouse-trail';
  const THROTTLE_MS = 22;      // 生成节流
  // F5-L14（2026-10-21）：淡出时长不在本文件留第二本账——真源是 main-pages.css
  // `.mouse-trail-dot` 的 transition（旧注释写的 main.css 是错的文件名，且 520 与 CSS
  // 各写一份，任一侧改动都会静默漂移，症状是光点早摘（看得见半透明的点被抠掉）或晚摘）。
  // 改为首次生成时量一次 computed style 并缓存；FALLBACK 只在量不到时兜底，取值刻意
  // 偏大：晚摘不可见（此时 opacity 已归零）、早摘可见，所以宁长勿短。
  const FADE_FALLBACK_MS = 1500;
  let fadeMs = 0;
  // 审查v4-M1：reduced-motion 必须使用时实时求值，禁止模块加载时固化快照
  // （固化会导致运行中切换系统「减少动态效果」偏好永不生效，9.6-B8 / v4-M1）
  function isReducedMotion() {
    return !!(window.ds && window.ds.reducedMotion && window.ds.reducedMotion());
  }
  // 逗号分隔的 transition-duration 逐项解析取最长一段（多属性过渡要等最慢的那个）；
  // 单位可能是 s 也可能是 ms，必须按结尾单位换算，否则 0.52s 会算成 520000ms。
  function maxTransitionMs(spec) {
    let max = 0;
    String(spec || '').split(',').forEach((part) => {
      const s = part.trim();
      const v = parseFloat(s);
      if (!Number.isFinite(v) || v <= 0) return;
      const ms = /ms$/.test(s) ? v : v * 1000;
      if (ms > max) max = ms;
    });
    return max > 0 ? Math.round(max) : 0;
  }

  let enabled = false;
  let enabledPref = readLsPref();
  let prefDirty = false;
  let layer = null;
  let last = 0;

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
    document.body.appendChild(layer);
    return layer;
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
      layer.remove();
      layer = null;
    }
  }
  function spawn(x, y) {
    if (!enabled || isReducedMotion()) return;
    const now = performance.now();
    if (now - last < THROTTLE_MS) return;
    last = now;
    const host = ensureLayer();
    const dot = document.createElement('span');
    dot.className = 'mouse-trail-dot';
    const size = 4 + Math.random() * 4;
    dot.style.width = size + 'px';
    dot.style.height = size + 'px';
    dot.style.left = x + 'px';
    dot.style.top = y + 'px';
    host.appendChild(dot);

    const remove = () => { if (dot.parentNode) dot.remove(); };
    dot.addEventListener('transitionend', remove, { once: true });
    // 兜底：过渡被跳过（后台窗口、极端节流）时仍能回收节点，杜绝 DOM 累积。
    // 时长量一次即记账（含量不到的情形），避免每个光点都付一次 computed style 读。
    if (fadeMs === 0) {
      const measured = maxTransitionMs(getComputedStyle(dot).transitionDuration);
      fadeMs = measured > 0 ? measured : FADE_FALLBACK_MS;
    }
    setTimeout(remove, fadeMs + 260);
    // 强制回流，确保初始态被绘制后再切到淡出态，否则 transition 不会触发
    void dot.offsetWidth;
    dot.classList.add('is-fading');
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
    document.addEventListener('pointermove', (e) => spawn(e.clientX, e.clientY), { passive: true });
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



