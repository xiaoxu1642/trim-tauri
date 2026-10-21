// 3D 倾斜（Motion.Lab · three-d-tilt）
// 软件内所有白色容器随鼠标 3D 倾斜：事件委托实现，动态创建的容器同样生效
// 参数：最大倾角 7°（大面板保持克制）、透视 900px、回弹 0.5s
(function () {
  'use strict';

  var SELECTOR = [
    // 设置页外层 .settings-section 不倾斜，仅内层白色容器
    '.settings-entry-card',
    '.appearance-card',
    '.material-card',
    '.card-panel',
    '.overview-card',
    '.table-card',
    '.summary-card',
    '.metric-card',
    '.speed-card',
    '.benchmark-panel'
  ].join(',');

  // 启动项管理页的「启动项列表」面板不倾斜（需求指定），同页统计卡不受影响
  // 磁盘清理各扫描结果表格（重复文件/大文件/空文件）不加入 3D 倾斜
  var EXCLUDE_CONTAINS = '#startupList, .finder-table';

  var MAX_ANGLE = 7;        // 最大角度（°）
  var PERSPECTIVE = 900;    // 透视距离（px）
  // P3-5（F5-G-5）：曲线/时长进 token 值集（--ease-standard / --duration-slow），
  // 原 .5s cubic-bezier(0.2,0.8,0.2,1) 是 token 外的自造值
  var RESET_TRANSITION = 'transform .32s cubic-bezier(0.23, 1, 0.32, 1)';
  var MOVE_TRANSITION = 'transform .12s ease-out';

  var current = null;
  // 性能 v3 ②：原实现每个 mousemove 都做「matchMedia → closest → 全子树 querySelector →
  // getBoundingClientRect → 写 transform/transition」，即每事件一次强制回流。
  // 现在改成：rect 与排除判定都只在**换元素**时算一次（后者结果进 dataset），
  // 样式写入走 requestAnimationFrame 合帧（照本仓在库先例 liquid-glass.js 的 onPointerMove）。
  var currentRect = null;   // 进入元素时的一次几何快照
  var pendingEl = null;     // 待提交帧的目标（提交时要求它仍是 current）
  var pendingX = 0, pendingY = 0;
  var tiltRaf = 0;

  // M3（v3.6.5）N-4：剔除 base 中「旧的 transform 过渡片段」，而不是整条替换。
  // 原实现：base 只要含 'transform' 就把整个 base 丢掉 → 连带丢弃容器自带的
  // box-shadow / border-color 等过渡（表现为悬停时阴影/描边由渐变退化为瞬跳）。
  // 做法：按逗号分段，逐段判定属性名是否为 transform（含厂商前缀），是则丢弃该段，
  // 其余过渡（颜色/阴影/透明度等）原样保留。
  function stripTransformTransition(base) {
    if (!base) return '';
    return base.split(',')
      .map(function (seg) { return seg.trim(); })
      .filter(function (seg) {
        // 词边界匹配属性名，避免误伤 cubic-bezier/函数名里恰好出现的字样
        return !/^(?:-(?:webkit|moz|ms|o)-)?transform(?:[\s]|$)/.test(seg);
      })
      .filter(Boolean)
      .join(', ');
  }

  function setTransform(el, transform, transition) {
    // 保留容器已有的行内 transition；其中旧的 transform 片段先剔除再拼接（M3 N-4），
    // 其余过渡属性（box-shadow / border-color 等）原样保留。
    var base = el.dataset.tiltBase;
    if (base === undefined) {
      base = el.style.transition || '';
      el.dataset.tiltBase = base;
      delete el.dataset.tiltRest; // base 新建/变更 → 合并结果作废（下一句重算）
    }
    // stripTransformTransition 一次要付 4 趟数组（split/map/filter/filter/join），
    // 原先每次写样式都重算一遍；base 既已按元素缓存，合并结果同样按元素缓存（性能 v3 ②）
    var rest = el.dataset.tiltRest;
    if (rest === undefined) {
      rest = stripTransformTransition(base);
      el.dataset.tiltRest = rest;
    }
    var merged = rest ? transition + ', ' + rest : transition;
    el.style.transform = transform;
    el.style.transition = merged;
  }

  function reset(el) {
    if (!el) return;
    // reduced-motion 下复位直接清除姿态，不做 0.5s 过渡动画
    setTransform(el, '', isReducedMotion() ? 'none' : RESET_TRANSITION);
    el.style.willChange = '';
  }

  // 审查v4-M1：reduced-motion 改为事件回调内实时求值——原实现模块加载时求值一次，
  // reduce 时监听器根本不挂载（关闭偏好后永不生效），运行中开启偏好同样不生效。
  // A3-L06：MediaQueryList 对象的缓存与实时求值统一由 ds.reducedMotion() 承担。
  function isReducedMotion() {
    return !!(window.ds && window.ds.reducedMotion && window.ds.reducedMotion());
  }

  // 排除判定（面板内含「启动项列表 / 扫描结果表格」则整块不倾斜，需求指定）：
  // 原实现每个 mousemove 都做一次全子树 querySelector。这里按元素缓存结论，只在
  // 缓存缺失、或该元素**直接子节点数**变化时重查——两种表格/列表都由宿主卡片
  // innerHTML 整体注入（#dupTable / #anTable / #uninstallList / 启动项面板），注入即改
  // 直接子节点数；#startupList 是 index.html 静态节点，首查即得终值。
  function isExcludedCard(el) {
    var sig = String(el.childElementCount);
    if (el.dataset.tiltExcluded !== undefined && el.dataset.tiltExcludeSig === sig) {
      return el.dataset.tiltExcluded === '1';
    }
    var hit = !!(el.querySelector && el.querySelector(EXCLUDE_CONTAINS));
    el.dataset.tiltExcluded = hit ? '1' : '0';
    el.dataset.tiltExcludeSig = sig;
    return hit;
  }

  function clearTilt() {
    reset(current);
    current = null;
    currentRect = null;
    pendingEl = null;
  }

  function applyTilt() {
    tiltRaf = 0;
    var el = pendingEl;
    // 待提交帧与当前悬停脱节（换了元素 / 已复位 / 已离开窗口）时不写旧元素
    if (!el || el !== current) return;
    el.style.willChange = 'transform';
    setTransform(
      el,
      'perspective(' + PERSPECTIVE + 'px) rotateY(' + (pendingX * MAX_ANGLE * 2).toFixed(2) + 'deg) rotateX(' +
        (-pendingY * MAX_ANGLE * 2).toFixed(2) + 'deg)',
      MOVE_TRANSITION
    );
  }

  document.addEventListener('mousemove', function (e) {
    if (isReducedMotion()) { clearTilt(); return; }
    var el = e.target && e.target.closest ? e.target.closest(SELECTOR) : null;
    // 命中「启动项列表」/扫描结果表格所在面板时取消倾斜
    if (el && isExcludedCard(el)) el = null;
    if (el !== current) {
      // 先读后写：换元素时才量一次 rect，避免被紧随的 reset() 写脏而再触发回流
      var fresh = el ? el.getBoundingClientRect() : null;
      reset(current);
      current = el;
      currentRect = fresh ? { left: fresh.left, top: fresh.top, width: fresh.width, height: fresh.height } : null;
    }
    if (!el) return;

    var r = currentRect;
    if (!r || !r.width || !r.height) return;
    var x = (e.clientX - r.left) / r.width - 0.5;
    var y = (e.clientY - r.top) / r.height - 0.5;
    // 光标越出容器边界时不再倾斜（保持最后一次姿态由 CSS 回弹）
    if (x < -0.5 || x > 0.5 || y < -0.5 || y > 0.5) return;

    pendingEl = el; pendingX = x; pendingY = y;
    if (!tiltRaf) tiltRaf = requestAnimationFrame(applyTilt);
  }, { passive: true });

  // 滚动/离开窗口时复位，避免残留倾斜姿态（同时作废几何快照，下次进入重新量）
  window.addEventListener('scroll', clearTilt, { passive: true, capture: true });
  document.documentElement.addEventListener('mouseleave', clearTilt);

  // F5-L13：系统「减少动态效果」运行中打开时立刻归零，不能等下一次 mousemove。
  // 倾斜写的是**行内** transform，main.css 的 RM 归零段没有 !important 压不住它，
  // 归零前卡片一直保持倾斜姿态（will-change:transform 同样残留），表现为「偏好开了画面还歪着」。
  // MQL 对象统一走 ds.reducedMotionQuery()（A3-L06：不许各自再写 matchMedia）。
  (function bindReduceChange() {
    var mq = window.ds && window.ds.reducedMotionQuery ? window.ds.reducedMotionQuery() : null;
    if (!mq) return;
    var onChange = function () { if (isReducedMotion()) clearTilt(); };
    if (typeof mq.addEventListener === 'function') mq.addEventListener('change', onChange);
    else if (typeof mq.addListener === 'function') mq.addListener(onChange);
  })();
})();
