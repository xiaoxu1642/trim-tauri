// xtable.js - Windows 资源管理器风格详细信息表格通用辅助
// 提供：表头构建（排序指示 + 列宽拖拽）、排序辅助、单元格布局样式
(function () {
  'use strict';

  // 列宽注册表（key -> px，全局共享：同名列在不同表格间宽度一致）
  const colWidths = {};

  // 计算列布局（表头与数据行共用同一组 style，保证列对齐）
  function buildLayout(columns) {
    return columns.map(col => {
      const w = colWidths[col.key] || col.width;
      let style;
      if (w) {
        style = `width:${typeof w === 'number' ? w + 'px' : w};flex:0 0 auto;`;
      } else {
        style = 'flex:1 1 0;';
      }
      style += `min-width:${col.minWidth || 56}px;`;
      return { col, style };
    });
  }

  function sortIndicatorHtml(state, key) {
    if (state.key !== key) return '';
    return `<span class="xtable-sort-indicator">${state.dir === 'asc' ? '▲' : '▼'}</span>`;
  }

  // 渲染表头（columns: {key,label,width,sortable,resizable,align}）
  function renderHeader(columns, state, options) {
    const opts = options || {};
    const layout = buildLayout(columns);
    const cells = layout.map(({ col, style }) => {
      const sortable = col.sortable !== false;
      const align = col.align === 'end' ? 'end' : (col.align === 'center' ? 'center' : 'start');
      return `<div class="xtable-th${sortable ? ' sortable' : ''}${state && state.key === col.key ? ' sorted' : ''}${sortable ? '' : ' no-sort'}"
        data-col="${col.key}" style="${style}" data-align="${align}"${sortable ? ' data-tip="点击排序"' : ''}>
        <span class="xtable-th-label">${col.label}</span>
        ${sortable && state ? sortIndicatorHtml(state, col.key) : ''}
        ${col.resizable === false ? '' : `<span class="xtable-resizer" data-resize="${col.key}" data-tip="拖动调整列宽"></span>`}
      </div>`;
    }).join('');
    return `<div class="xtable-head${opts.compact ? ' xtable-head-compact' : ''}">${cells}</div>`;
  }

  // M2（v3.6.5）M2-4：表头交互改为幂等绑定。
  // 原实现每次调用都无条件 addEventListener：同一批 DOM 被重复绑定时，click 排序会被
  // 连续执行 N 次（方向反复翻转，表现为「点了没反应」），resizer 的 mousedown 也会并发
  // 挂上 N 组 document 级 move/up 监听（拖拽结束后只有最后一组被摘除）。
  // 现在每个节点只绑一次；state/onChange 由「容器注册表」在事件触发时动态取最新值，
  // 避免节点复用场景下闭包指向陈旧的排序状态。当前唯一调用方（cleanup.js）每次重渲染
  // 都用 innerHTML='' 重建节点，本改动不影响其行为，仅消除「调用方不清 DOM 时」的隐患。
  const headerContexts = new WeakMap();   // container -> { state, onChange }
  const headerBound = new WeakSet();      // 已挂过监听的表头/手柄节点

  // 自节点向上找最近的已注册容器（表头节点在 container 的子树内）
  function headerContextOf(node) {
    let el = node;
    while (el) {
      const ctx = headerContexts.get(el);
      if (ctx) return ctx;
      el = el.parentElement;
    }
    return null;
  }

  // 绑定表头交互：点击排序 + 拖拽列宽（幂等：重复调用不会重复绑定）
  function bindHeader(container, state, onChange) {
    if (!container) return;
    headerContexts.set(container, { state, onChange });

    container.querySelectorAll('.xtable-th.sortable').forEach(th => {
      if (headerBound.has(th)) return;
      headerBound.add(th);
      th.addEventListener('click', e => {
        if (e.target.closest('.xtable-resizer')) return;
        // 文字被选中时不触发排序（避免与复制操作冲突）
        const sel = window.getSelection ? window.getSelection().toString() : '';
        if (sel) return;
        const ctx = headerContextOf(th);
        if (!ctx || !ctx.state || typeof ctx.onChange !== 'function') return;
        const key = th.dataset.col;
        if (ctx.state.key === key) {
          ctx.state.dir = ctx.state.dir === 'asc' ? 'desc' : 'asc';
        } else {
          ctx.state.key = key;
          ctx.state.dir = 'asc';
        }
        ctx.onChange();
      });
    });

    container.querySelectorAll('.xtable-resizer').forEach(rz => {
      if (headerBound.has(rz)) return;
      headerBound.add(rz);
      rz.addEventListener('mousedown', e => {
        e.preventDefault();
        e.stopPropagation();
        const key = rz.dataset.resize;
        const th = rz.closest('.xtable-th');
        if (!th) return;
        const startX = e.clientX;
        const startW = th.getBoundingClientRect().width;
        const onMove = ev => {
          const w = Math.max(48, Math.round(startW + ev.clientX - startX));
          colWidths[key] = w;
          document.querySelectorAll(`.xtable-th[data-col="${key}"]`).forEach(o => {
            o.style.width = w + 'px';
            o.style.flex = '0 0 auto';
          });
        };
        const onUp = () => {
          document.removeEventListener('mousemove', onMove);
          document.removeEventListener('mouseup', onUp);
          document.body.classList.remove('xtable-resizing');
        };
        document.body.classList.add('xtable-resizing');
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
      });
    });
  }

  // 排序辅助：valueFns 为 {colKey: item => value}
  function sortItems(items, state, valueFns) {
    if (!state || !state.key) return items;
    const fn = valueFns[state.key];
    if (!fn) return items;
    const dir = state.dir === 'desc' ? -1 : 1;
    return [...items].sort((a, b) => {
      const va = fn(a);
      const vb = fn(b);
      if (va === null || va === undefined) return 1;
      if (vb === null || vb === undefined) return -1;
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
      return String(va).localeCompare(String(vb), 'zh-Hans-CN') * dir;
    });
  }

  // ==================== 分批渲染（render-batch，对齐 MangoDisk） ====================
  // 大表格分批插入 DOM：每帧一批（默认 50 行），首屏只渲染一批，
  // 剩余行折叠在「加载更多」按钮后，点击逐批追加（rAF 调度，不阻塞首帧绘制）。
  // opts:
  //   bodyEl     行容器（.xtable-body）
  //   rows       待渲染数据数组
  //   renderRow  (item, index) => 行 HTML 字符串
  //   batchSize  每批行数，默认 50
  //   onBatch    (start, end) 每批追加后的回调（逐行绑定事件的调用方用于绑定新行；
  //              已使用事件委托的调用方可省略）
  // 返回 { loadMore, rendered, done }；幂等：表格被重渲染（bodyEl 脱离文档）后任务自动作废。
  function createBatch(opts) {
    const bodyEl = opts.bodyEl;
    const rows = opts.rows || [];
    const renderRow = opts.renderRow;
    const batchSize = Math.max(1, opts.batchSize || 50);
    const onBatch = typeof opts.onBatch === 'function' ? opts.onBatch : null;
    let rendered = 0;
    let scheduled = false;

    function loadMore() {
      if (scheduled || rendered >= rows.length) return rendered < rows.length;
      scheduled = true;
      requestAnimationFrame(() => {
        scheduled = false;
        if (!bodyEl || !bodyEl.isConnected) return; // 表格已被重渲染，本次任务作废
        const start = rendered;
        const end = Math.min(start + batchSize, rows.length);
        let html = '';
        for (let i = start; i < end; i++) html += renderRow(rows[i], i);
        bodyEl.querySelector('.xtable-more')?.remove();
        if (html) bodyEl.insertAdjacentHTML('beforeend', html);
        rendered = end;
        if (rendered < rows.length) {
          const more = document.createElement('div');
          more.className = 'xtable-more';
          more.innerHTML = `<button class="btn btn-secondary btn-small" type="button">加载更多（还有 ${rows.length - rendered} 项）</button>`;
          more.querySelector('button').addEventListener('click', () => loadMore());
          bodyEl.appendChild(more);
        }
        if (onBatch) onBatch(start, end);
      });
      return true;
    }

    return {
      loadMore,
      get rendered() { return rendered; },
      get done() { return rendered >= rows.length; }
    };
  }

  // ==================== 中缝省略（middleEllipsis，对齐 MangoDisk） ====================
  // 超长路径/文件名保留首尾两端（首段定位信息 + 尾段文件名/扩展名），中段以「…」折叠。
  // 配合单元格 title 提示展示完整原文；CSS text-overflow 仍作为列宽不足时的兜底截断。
  // maxChars 为含省略号的总字符预算，默认 60；头部占 60%、尾部占 40%。
  function middleEllipsis(text, maxChars) {
    const s = String(text == null ? '' : text);
    const budget = Math.max(3, Math.floor(maxChars) || 60);
    if (s.length <= budget) return s;
    const keep = budget - 1;                            // 去掉省略号占位
    const head = Math.max(1, Math.round(keep * 0.6));   // 头部（目录定位）
    const tail = Math.max(1, keep - head);              // 尾部（文件名）
    return s.slice(0, head) + '…' + s.slice(s.length - tail);
  }

  // ==================== 虚拟滚动（windowing，对齐 MangoDisk） ====================
  // 只渲染视口附近的可见行，配合「总高占位 + 窗口平移」实现万级数据流畅滚动，
  // 取代「分批 + 加载更多」。要求调用方把目标容器设为固定高度可滚动区
  //（.xtable 加 .xtable-virtual 即可启用容器 max-height + overflow-y）。
  // opts:
  //   container  滚动容器元素（.xtable-body）
  //   rows       全部数据（引用同一数组；开启后会接管该数组的展示）
  //   renderRow  (item, index) => 行 HTML
  //   rowHeight  固定行高(px)，默认 40（配合 .xtable-row min-height）
  //   overscan   上下额外缓冲行数，默认 8
  // 返回 { render(newRows?)，scrollToTop() }；数据变化时调用 render() 重算高度并保位。
  function createVirtualList(container, opts) {
    const rows = opts.rows || [];
    const renderRow = opts.renderRow;
    const rowHeight = Math.max(28, opts.rowHeight || 40);
    const overscan = Math.max(4, opts.overscan || 8);
    let visibleStart = -1, visibleEnd = -1;
    let pending = false;
    let rafId = 0;
    let spacer = null;
    let windowEl = null;
    const total = () => rows.length;

    function renderWindow() {
      pending = false;
      if (!container || !container.isConnected) return;
      const n = total();
      const scrollTop = container.scrollTop || 0;
      const viewH = container.clientHeight || 0;
      const start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
      const end = Math.min(n, Math.ceil((scrollTop + viewH) / rowHeight) + overscan);
      if (start === visibleStart && end === visibleEnd && windowEl.childElementCount > 0) return;
      visibleStart = start;
      visibleEnd = end;
      windowEl.style.top = (start * rowHeight) + 'px';
      let html = '';
      for (let i = start; i < end; i++) html += renderRow(rows[i], i);
      windowEl.innerHTML = html;
    }

    const scheduleRender = () => {
      if (pending) return;
      pending = true;
      rafId = requestAnimationFrame(renderWindow);
    };

    spacer = document.createElement('div');
    spacer.className = 'xtable-vspacer';
    windowEl = document.createElement('div');
    windowEl.className = 'xtable-vwindow';
    spacer.appendChild(windowEl);
    container.textContent = '';
    container.style.setProperty('--vrow', rowHeight + 'px');
    // 创建时立即设置占位高度：若依赖首次 render() 才设置，折叠面板展开等场景下
    // spacer 高度为 0，视口内没有可渲染行，表现为「展开后看不到具体条目」
    spacer.style.height = Math.round(rows.length * rowHeight) + 'px';
    container.appendChild(spacer);
    container.addEventListener('scroll', scheduleRender, { passive: true });
    window.addEventListener('resize', scheduleRender);
    renderWindow();

    return {
      render(newRows) {
        if (newRows && newRows !== rows) {
          rows.length = 0;
          for (const r of newRows) rows.push(r);
        }
        spacer.style.height = Math.round(rows.length * rowHeight) + 'px';
        visibleStart = visibleEnd = -1;
        renderWindow();
      },
      scrollToTop() {
        container.scrollTop = 0;
        renderWindow();
      },
      destroy() {
        // 火眼眼审查 2026-09-14（LOW）：容器可能比虚拟列表活得更久，destroy 时
        // 补齐 scroll 监听解绑并取消挂起的 rAF，避免闭包与 spacer 泄漏
        if (rafId) { cancelAnimationFrame(rafId); rafId = 0; }
        pending = false;
        container.removeEventListener('scroll', scheduleRender);
        window.removeEventListener('resize', scheduleRender);
      }
    };
  }

  window.xtable = { renderHeader, bindHeader, sortItems, buildLayout, createBatch, createVirtualList, middleEllipsis };

  // ==================== 瀑布流（Masonry）布局引擎 ====================
  // 绝对定位放置：看板按当前顺序依次放入「最矮列」底部，列数按容器宽度自适应，
  // 1 列时单看板占满整行；容器高度 = 最高列；重排（resize/宽度变化）使用 FLIP 平滑过渡。
  window.kanbanMasonry = (function () {
    function capture(container, selector) {
      const map = new Map();
      container.querySelectorAll(selector).forEach(n => map.set(n, n.getBoundingClientRect()));
      return map;
    }

    function play(container, selector, first) {
      if (!first) return;
      container.querySelectorAll(selector).forEach(n => {
        const f = first.get(n);
        if (!f) return;
        const l = n.getBoundingClientRect();
        const dx = f.left - l.left;
        const dy = f.top - l.top;
        if (Math.abs(dx) < 1 && Math.abs(dy) < 1) return;
        // Web Animations API：transform 合成器动画（60fps），结束后自动无残留
        if (typeof n.animate === 'function') {
          n.animate(
            [{ transform: `translate(${dx}px, ${dy}px)` }, { transform: 'none' }],
            { duration: 300, easing: 'cubic-bezier(0.4, 0, 0.2, 1)' }
          );
        }
      });
    }

    // 计算并应用瀑布流布局（无动画）
    function layout(container, cardSelector, gap, minCard) {
      const cards = [...container.querySelectorAll(cardSelector)];
      const width = container.clientWidth;
      if (width <= 0 || !cards.length) {
        container.style.height = '0px';
        return;
      }
      const colCount = Math.max(1, Math.min(cards.length, Math.floor((width + gap) / (minCard + gap))));
      const colWidth = Math.floor((width - gap * (colCount - 1)) / colCount);
      const heights = new Array(colCount).fill(0);
      // 先统一设置宽度，保证测得的高度准确
      cards.forEach(card => { card.style.width = colWidth + 'px'; });
      cards.forEach(card => {
        const h = card.offsetHeight;
        let idx = 0;
        for (let i = 1; i < colCount; i++) { if (heights[i] < heights[idx]) idx = i; }
        card.style.left = Math.round(idx * (colWidth + gap)) + 'px';
        card.style.top = Math.round(heights[idx]) + 'px';
        heights[idx] += h + gap;
      });
      container.style.height = Math.max(...heights) + 'px';
    }

    // 绑定看板：getContainer() 每次返回当前布局容器（看板容器可能随重渲染重建）。
    // B7：用 ResizeObserver 替代原先 300ms 常驻轮询——容器尺寸变化才触发重排，
    // 彻底消除定时强制回流；容器随重渲染重建时在 check/relayout 里重新挂载观察。
    // 窗口 resize → 防抖 120ms 后重排（带 FLIP 动画）。
    // 返回 { relayout(animate), dispose() }：渲染层在重新渲染 DOM 后调用 relayout 立即布局，
    // 页面销毁时调用 dispose 释放观察器与监听。
    function attach(getContainer, cardSelector, opts) {
      const gap = (opts && opts.gap) != null ? opts.gap : 14;
      const minCard = (opts && opts.minCard) || 246;
      let lastW = -1;
      let ro = null;
      let roTarget = null;
      let resizeTimer = null;
      let disposed = false;
      function force(animate) {
        const container = getContainer();
        if (!container || !container.isConnected) return; // 未挂载直接跳过
        const w = container.clientWidth;
        if (w <= 0) return;               // 页面隐藏时不布局，留待可见后重排
        const cap = animate && lastW > 0 ? capture(container, cardSelector) : null;
        layout(container, cardSelector, gap, minCard);
        if (cap) play(container, cardSelector, cap);
        lastW = w;
      }
      function syncObserver() {
        if (disposed || typeof ResizeObserver !== 'function') return;
        const container = getContainer();
        if (!container || !container.isConnected) return;
        if (roTarget === container) return;
        if (!ro) ro = new ResizeObserver(() => check(false));
        if (roTarget) ro.unobserve(roTarget);
        roTarget = container;
        ro.observe(container);
      }
      function check(animate) {
        if (disposed) return;
        syncObserver();
        const container = getContainer();
        if (!container || !container.isConnected) return; // 未挂载直接跳过
        const w = container.clientWidth;
        if (w <= 0 || w === lastW) return; // 宽度未变化时跳过（重渲染由 relayout 强制布局）
        force(animate);
      }
      // LG-6（2026-09-15）：命名 resize 处理器，dispose 可解除绑定（原匿名箭头解绑不了）
      const onWindowResize = () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => check(true), 120); // resize 防抖 120ms
      };
      window.addEventListener('resize', onWindowResize, { passive: true });
      syncObserver();
      return {
        relayout(animate) { force(!!animate); syncObserver(); },
        dispose() {
          disposed = true;
          if (ro) { ro.disconnect(); ro = null; roTarget = null; }
          clearTimeout(resizeTimer);
          window.removeEventListener('resize', onWindowResize);
        }
      };
    }

    return { layout, attach };
  })();
})();
