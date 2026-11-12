// aurora.js - 极光琉璃 B-P3：氛围场挂载 + 首屏入场编排 + 数字滚动
//
// 分工：视觉形态全在 main.css「4c) 氛围场 / 4d) 入场编排」两段，本文件只做三件事
//   ① 往 .layout 里插 .aurora-field（三层装饰件，pointer-events:none，不进无障碍树）；
//   ② 在开屏退场之后挂 body.aurora-ready —— 入场动画的唯一开关；
//   ③ 概览页数字滚动：只对纯百分比文本做一次缓动过渡，其它内容一律不碰。
//
// 为什么等开屏退场、而不是等 `app:first-paint`：后者是 tauri-api.js 发给 Rust 的
// IPC 命令（`app_first_paint`），**不是 DOM 事件**，前端监听不到。开屏节点由
// splash.js 在 FLIP 落位结束后摘除，那一刻窗口早已 show（黑闪握手在 first-paint
// 就完成了），所以它既是「能看见界面」的准确信号，也天然不会抢跑握手。
//
// 为什么由本文件插 DOM 而不是写死在 index.html：氛围层是纯装饰，且只有主窗需要；
// 写进 HTML 会让 check-html-contract 的结构面多一个静态锚点，也让子窗（共用 main.css）
// 白白多一份无用节点。
//
// 降级：reduced-motion 下不插装饰层、不挂 aurora-ready（CSS 侧另有 RM 兜底，双保险）。
//
// 极光漂移为什么由 JS 低频推、而不是 CSS animation：
// 真机实测（debug 构建 + CDP + 渲染进程 CPU 采样，取数命令见本机资料区的
// 极光琉璃取证记录「漂移开销」一节）—— 三团 blur 光斑跑 CSS animation 时
// 渲染进程常驻单核近一成；去掉 blur、去掉 will-change、或把曲线换成 steps() 离散化都救不回来。
// 根因是大图层每帧合成，不是模糊本身 —— 所以「预烘焙静态图 + 缓慢 transform」那套降级
// 同样跑不掉。极光本来就是十几秒尺度的缓慢漂移，四分之一秒一拍足够平滑，
// 用合成器每帧去追它是纯浪费。CSS 侧因此不再挂 aurora-drift-* 动画。
(function () {
  'use strict';

  var FIELD_CLASS = 'aurora-field';
  var READY_CLASS = 'aurora-ready';
  var FIELD_MARK = 'data-aurora';
  // 漂移节拍：四分之一秒一拍。极光单程十几到三十几秒，这一拍下每帧位移不到零点二 vw，
  // 肉眼看不出台阶（帧间隔与位移量的取数命令见本机资料区的极光琉璃取证记录）。
  var DRIFT_TICK_MS = 250;
  // 三团光斑的轨迹参数：[振幅x(vw), 振幅y(vh), 相位, 周期倍数]
  var DRIFT_SPEC = [
    [4.2, 3.4, 0, 1],
    [3.6, 4.0, 2.1, 1.18],
    [3.2, 3.0, 4.2, 0.86],
  ];
  var driftTimer = 0;

  function reduced() {
    try {
      return !!(window.ds && window.ds.reducedMotion && window.ds.reducedMotion());
    } catch (e) {
      return false;
    }
  }

  // 装饰层：三层（blob 组 / conic 光带 / 噪点）+ 一层回压 veil。
  // 顺序即层序：blob → ribbon → veil → grain（veil 在 grain 之前，噪点才不会被压掉）。
  function mountField() {
    var layout = document.querySelector('.layout');
    if (!layout) return null;
    var existing = layout.querySelector('[' + FIELD_MARK + ']');
    if (existing) return existing;

    var field = document.createElement('div');
    field.className = FIELD_CLASS;
    field.setAttribute(FIELD_MARK, '');
    field.setAttribute('aria-hidden', 'true');

    var blobs = document.createElement('div');
    blobs.className = 'aurora-blobs';
    ['1', '2', '3'].forEach(function (n) {
      var b = document.createElement('span');
      b.className = 'aurora-blob aurora-blob-' + n;
      blobs.appendChild(b);
    });

    var ribbon = document.createElement('span');
    ribbon.className = 'aurora-ribbon';

    var veil = document.createElement('span');
    veil.className = 'aurora-veil';

    var grain = document.createElement('span');
    grain.className = 'aurora-grain';

    field.appendChild(blobs);
    field.appendChild(ribbon);
    field.appendChild(veil);
    field.appendChild(grain);
    // 必须是 .layout 的第一个子节点：后面 sidebar / main-content 都是 z-index:2，
    // 本层 z-index:0 自然垫底，插到末尾也成立，但放最前最不容易被将来新增的同级层挤掉。
    layout.insertBefore(field, layout.firstChild);
    return field;
  }

  // 数字滚动：把纯百分比文本从旧值缓动到新值。只处理「目标文本是单个百分比」
  // 且元素里没有子节点的情况 —— 概览卡片的值是纯文本，其它模块的复合文案一律跳过。
  //
  // 两条必须的护栏（第一版漏了第 ① 条，实测数值会在多个值之间来回乱跳）：
  //   ① 自写标记：动画每帧都在写 textContent，而监听它的 MutationObserver 会被自己的
  //      写入触发 —— 不加标记就会「读到中间态当新目标 → 再起一条动画」，多条 rAF 互相
  //      覆盖，数值来回震荡。
  //   ② 单飞：同一元素同时只允许一条动画，新目标到达时先取消旧的（否则旧动画收尾会把
  //      新值覆盖回旧目标）。
  var lastValues = new WeakMap();
  var selfWrite = new WeakSet();
  var running = new WeakMap();

  function writeText(el, text) {
    selfWrite.add(el);
    el.textContent = text;
  }

  function animatePercent(el, dur) {
    if (!el || el.children.length) return;
    var text = (el.textContent || '').trim();
    var m = /^(\d+(?:\.\d+)?)%$/.exec(text);
    if (!m) return;
    var to = parseFloat(m[1]);
    var from = lastValues.get(el);
    lastValues.set(el, to);
    if (from === undefined || !isFinite(from) || from === to) return;
    if (reduced()) return;

    var prev = running.get(el);
    if (prev) cancelAnimationFrame(prev);

    var started = 0;
    var decimals = m[1].indexOf('.') >= 0 ? 1 : 0;
    var raf = 0;
    function step(now) {
      if (!started) started = now;
      var t = Math.min(1, (now - started) / dur);
      // easeOutExpo：与 --ease-expo 同族，收尾极缓
      var e = t >= 1 ? 1 : 1 - Math.pow(2, -10 * t);
      writeText(el, (from + (to - from) * e).toFixed(decimals) + '%');
      if (t < 1) {
        raf = requestAnimationFrame(step);
        running.set(el, raf);
      } else {
        running.delete(el);
        writeText(el, to.toFixed(decimals) + '%');
      }
    }
    raf = requestAnimationFrame(step);
    running.set(el, raf);
  }

  function animateOverviewValues() {
    var ids = ['ovCpuValue', 'ovMemValue', 'ovDiskValue'];
    ids.forEach(function (id) {
      animatePercent(document.getElementById(id), 620);
    });
  }

  // 低频漂移：只写 transform（不读布局、不碰 opacity），按上面 DRIFT_TICK_MS 的节拍走。
  // 用 translate3d 让它留在合成层，但合成只在写的那一帧发生 —— 开销对比见
  // 本机资料区极光琉璃取证记录的「漂移开销」一节（取数命令在同文件）。
  function startDrift(field) {
    var blobs = field.querySelectorAll('.aurora-blob');
    if (!blobs.length || driftTimer) return;
    var t0 = 0;
    function tick() {
      // reduced-motion 中途被打开：立即停表并清掉位移，别让冻结的偏移留在屏上
      if (reduced()) {
        stopDrift(blobs);
        return;
      }
      t0 += DRIFT_TICK_MS / 1000;
      for (var i = 0; i < blobs.length; i++) {
        var s = DRIFT_SPEC[i] || DRIFT_SPEC[0];
        var phase = t0 * (Math.PI * 2 / (30 * s[3])) + s[2];
        blobs[i].style.transform =
          'translate3d(' + (Math.sin(phase) * s[0]).toFixed(2) + 'vw,' +
          (Math.cos(phase * 0.8) * s[1]).toFixed(2) + 'vh,0)';
      }
    }
    driftTimer = setInterval(tick, DRIFT_TICK_MS);
    // RM 被关掉后要能自己恢复：matchMedia 的 change 是实时事件，不必轮询。
    // 只在这一处监听，且只在「当前确实处于 RM」时才重启，避免和 stopDrift 互相打架。
    var mq = window.ds && window.ds.reducedMotionQuery && window.ds.reducedMotionQuery();
    if (mq && mq.addEventListener) {
      mq.addEventListener('change', function () {
        if (reduced() || driftTimer) return;
        startDrift(field);
      });
    }
  }

  function stopDrift(blobs) {
    if (driftTimer) {
      clearInterval(driftTimer);
      driftTimer = 0;
    }
    if (!blobs) return;
    for (var i = 0; i < blobs.length; i++) blobs[i].style.transform = '';
  }

  var readyDone = false;
  function markReady() {
    if (readyDone) return;
    readyDone = true;
    if (document.body.classList.contains(READY_CLASS)) return;
    document.body.classList.add(READY_CLASS);
    startDrift(document.querySelector('.' + FIELD_CLASS));
    animateOverviewValues();
  }

  // 开屏退场即入场：监听 #splash 被移除。无开屏结构（预览/异常）时退化为双 rAF。
  function whenSplashGone(cb) {
    var splash = document.getElementById('splash');
    if (!splash) {
      requestAnimationFrame(function () { requestAnimationFrame(cb); });
      return;
    }
    var obs = new MutationObserver(function () {
      if (document.getElementById('splash')) return;
      obs.disconnect();
      cb();
    });
    obs.observe(document.body, { childList: true });
  }

  function init() {
    if (reduced()) return;
    mountField();

    whenSplashGone(markReady);
    // 兜底：开屏被异常路径摘除（splash.js 的硬退兜底）或观察器没跑起来时，仍按时入场。
    setTimeout(markReady, 4000);

    // 概览指标按 overview.js 的轮询节奏重写文本；用观察器接住变化，避免改它的渲染链。
    ['ovCpuValue', 'ovMemValue', 'ovDiskValue'].forEach(function (id) {
      var el = document.getElementById(id);
      if (!el) return;
      new MutationObserver(function () {
        // 自己写的不算「新目标」：只消费一次标记就返回，否则动画会自己喂自己
        if (selfWrite.has(el)) {
          selfWrite.delete(el);
          return;
        }
        animatePercent(el, 620);
      })
        .observe(el, { childList: true, characterData: true, subtree: true });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
