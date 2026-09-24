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
  // 磁盘清理各扫描结果表格（重复文件/大文件/空文件/AppData 瘦身）不加入 3D 倾斜
  var EXCLUDE_CONTAINS = '#startupList, .finder-table';

  var MAX_ANGLE = 7;        // 最大角度（°）
  var PERSPECTIVE = 900;    // 透视距离（px）
  var RESET_TRANSITION = 'transform .5s cubic-bezier(0.2, 0.8, 0.2, 1)';
  var MOVE_TRANSITION = 'transform .12s ease-out';

  var current = null;

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
    }
    var rest = stripTransformTransition(base);
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
  // reduce 时监听器根本不挂载（关闭偏好后永不生效），运行中开启偏好同样不生效
  function isReducedMotion() {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }

  document.addEventListener('mousemove', function (e) {
    if (isReducedMotion()) { reset(current); current = null; return; }
    var el = e.target && e.target.closest ? e.target.closest(SELECTOR) : null;
    // 命中「启动项列表」所在面板时取消倾斜
    if (el && el.querySelector && el.querySelector(EXCLUDE_CONTAINS)) el = null;
    if (el !== current) {
      reset(current);
      current = el;
    }
    if (!el) return;

    var r = el.getBoundingClientRect();
    if (!r.width || !r.height) return;
    var x = (e.clientX - r.left) / r.width - 0.5;
    var y = (e.clientY - r.top) / r.height - 0.5;
    // 光标越出容器边界时不再倾斜（保持最后一次姿态由 CSS 回弹）
    if (x < -0.5 || x > 0.5 || y < -0.5 || y > 0.5) return;

    el.style.willChange = 'transform';
    setTransform(
      el,
      'perspective(' + PERSPECTIVE + 'px) rotateY(' + (x * MAX_ANGLE * 2).toFixed(2) + 'deg) rotateX(' +
        (-y * MAX_ANGLE * 2).toFixed(2) + 'deg)',
      MOVE_TRANSITION
    );
  }, { passive: true });

  // 滚动/离开窗口时复位，避免残留倾斜姿态
  window.addEventListener('scroll', function () { reset(current); current = null; }, { passive: true, capture: true });
  document.documentElement.addEventListener('mouseleave', function () { reset(current); current = null; });
})();
