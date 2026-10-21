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
      // P3-1（可达性）：可排序表头必须键盘可达并可播报排序态 —— tabindex=0 +
      // aria-sort（ascending/descending/none，仅排序型表头合法）+ role=columnheader；
      // 激活逻辑在 bindHeader 的 keydown 分支（与 click 走同一 applySort）。
      const ariaSort = state && state.key === col.key
        ? (state.dir === 'asc' ? 'ascending' : 'descending')
        : 'none';
      // F5-M05（P3-1 补全）：ARIA 规定 columnheader 必须被 row 拥有、row 必须被
      // table/grid 拥有——旧实现只给可排序列发 role，非排序列在行内是无角色子项，
      // 整棵树又缺 table 祖先，读屏可能把整块当普通 div 忽略，aria-sort 无人播报。
      // 表头单元格统一 role=columnheader；键盘可达（tabindex）与 aria-sort 仍只归
      // 可排序列。table 祖先与数据行的 role 由 bindHeader / createVirtualList 补挂
      // （行 HTML 在调用方手里，本库不重复渲染）。
      const a11y = ` role="columnheader"` + (sortable ? ` tabindex="0" aria-sort="${ariaSort}"` : '');
      // F5-L08：label 是调用方传入的文本，必须过 ds.esc 才能拼进 HTML（ds.js 是全仓
      // 转义唯一真源，AGENTS §2 禁本地转义表；两个宿主页面的加载序都是 ds 先于本库，
      // 已在 F5 分报告 §7.1 逐页核过）。col.key 仍按字面量插属性位：check-html-contract
      // 用 `data-col="${col.key}"` 字面量锚定「表头 data-col ⇄ 行单元 data-cell 同源」
      // 契约，且 key 的允许来源本就是调用方静态常量（现算唯一调用方 cleanup.js 的
      // COL_* 全为字面量）——要放宽 key 的转义必须先改那条门禁，不许库侧静默换形态。
      return `<div class="xtable-th${sortable ? ' sortable' : ''}${state && state.key === col.key ? ' sorted' : ''}${sortable ? '' : ' no-sort'}"
        data-col="${col.key}" style="${style}" data-align="${align}"${a11y}${sortable ? ' data-tip="点击排序"' : ''}>
        <span class="xtable-th-label">${window.ds.esc(col.label)}</span>
        ${sortable && state ? sortIndicatorHtml(state, col.key) : ''}
        ${col.resizable === false ? '' : `<span class="xtable-resizer" data-resize="${col.key}" data-tip="拖动调整列宽"></span>`}
      </div>`;
    }).join('');
    return `<div class="xtable-head${opts.compact ? ' xtable-head-compact' : ''}" role="row">${cells}</div>`;
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

  // F5-M03：拖拽会话必须全局单例。onMove/onUp 是每次 mousedown 新建的闭包，
  // 若上一轮 mouseup 因 alt-tab / 锁屏 / 系统菜单打断未送达，旧那组仍挂在
  // document 上——下一次拖拽（含换到另一列的 resizer）变成两组同写宽度，旧那组
  // 用已失效的 startX/startW 造成宽度跳变，body.xtable-resizing（col-resize 光标）
  // 也会残留。注册表放模块级（而不是每个 resizer 一份），换组前先拆旧组。
  let activeResize = null;

  // 绑定表头交互：点击排序 + 拖拽列宽（幂等：重复调用不会重复绑定）
  function bindHeader(container, state, onChange) {
    if (!container) return;
    headerContexts.set(container, { state, onChange });
    // F5-M05：宿主补 role=table（行 HTML 由调用方渲染，此处连同在场的行/单元格一起
    // 补挂角色，使 columnheader→row→table 祖先链闭合）；虚拟滚动窗口内后来重渲染的
    // 行由 createVirtualList 的渲染路径补（见 applyRowRoles）。
    if (!container.getAttribute('role')) container.setAttribute('role', 'table');
    applyRowRoles(container);

    container.querySelectorAll('.xtable-th.sortable').forEach(th => {
      if (headerBound.has(th)) return;
      headerBound.add(th);
      // P3-1：排序动作单一实现 —— click 与 keydown（Enter/Space）共用
      const applySort = () => {
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
      };
      th.addEventListener('click', e => {
        if (e.target.closest('.xtable-resizer')) return;
        // 文字被选中时不触发排序（避免与复制操作冲突）
        const sel = window.getSelection ? window.getSelection().toString() : '';
        if (sel) return;
        applySort();
      });
      // P3-1（可达性）：键盘 Enter/Space 与点击同路（Space 默认滚动，需拦掉）
      th.addEventListener('keydown', e => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        applySort();
      });
    });

    container.querySelectorAll('.xtable-resizer').forEach(rz => {
      if (headerBound.has(rz)) return;
      headerBound.add(rz);
      // F5-M03：拖拽会话全局单例（见 activeResize 声明处）
      rz.addEventListener('mousedown', e => {
        e.preventDefault();
        e.stopPropagation();
        const key = rz.dataset.resize;
        const th = rz.closest('.xtable-th');
        if (!th) return;
        if (activeResize) activeResize.teardown();
        const startX = e.clientX;
        const startW = th.getBoundingClientRect().width;
        const onMove = ev => {
          const w = Math.max(48, Math.round(startW + ev.clientX - startX));
          colWidths[key] = w;
          // 「表头与数据行共用同一组宽度」是 buildLayout 的列对齐不变量：已在场的行
          // 带着渲染当时写死的 px，只刷表头会让行留在旧宽（拖完即错位，再渲染才自愈）。
          // 行单元格带 data-cell（cleanup.js 渲染，与表头 data-col 同 key 同源，
          // check-html-contract 锚定），拖拽时两侧同步刷。
          document.querySelectorAll(`.xtable-th[data-col="${key}"], .xtable-td[data-cell="${key}"]`).forEach(o => {
            o.style.width = w + 'px';
            o.style.flex = '0 0 auto';
          });
        };
        const teardown = () => {
          document.removeEventListener('mousemove', onMove);
          document.removeEventListener('mouseup', onUp);
          document.body.classList.remove('xtable-resizing');
          activeResize = null;
        };
        const onUp = () => teardown();
        activeResize = { teardown };
        document.body.classList.add('xtable-resizing');
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
      });
    });
  }

  // F5-M05：为调用方渲染的行/单元格补 ARIA 角色（幂等：已带 role 的不覆盖）。
  // 只在宿主已有 role=table 的子树里调用——孤儿 row 同样是不闭合的 ARIA 形状。
  function applyRowRoles(root) {
    root.querySelectorAll('.xtable-row').forEach(r => { if (!r.getAttribute('role')) r.setAttribute('role', 'row'); });
    root.querySelectorAll('.xtable-td').forEach(c => { if (!c.getAttribute('role')) c.setAttribute('role', 'cell'); });
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

  // F5-L07：createBatch 已删除——「分批 + 加载更多」渲染路径被 createVirtualList
  // 全量取代后，它成了零调用方的死导出（现算全仓仅本文件内提及），文档契约
  //（batchSize/onBatch）无人履行还占 API 面；需要分批渲染时从 git 历史捞回。

  // ==================== 中缝省略（middleEllipsis，对齐 MangoDisk） ====================
  // 超长路径/文件名保留首尾两端（首段定位信息 + 尾段文件名/扩展名），中段以「…」折叠。
  // 完整原文由调用方放进单元格的 data-tip 提示展示（AGENTS §2：提示一律 data-tip，
  // 原生悬浮提示属性被 check-a11y 判禁；现算调用方 cleanup.js/processes.js 即此用法）。
  // CSS text-overflow 仍作为列宽不足时的兜底截断。
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
      // F5-M05：虚拟滚动的行在滚动中整窗重渲染，bindHeader 时补的 role 覆盖不到新行；
      // 仅当宿主已有 role=table（ARIA 形状成立，由 bindHeader 设置）时才补，避免
      // 在没有 table 祖先的表格（如进程管理页的自绘表头）里制造孤儿 row。
      if (container.closest('[role="table"]')) applyRowRoles(windowEl);
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

  window.xtable = { renderHeader, bindHeader, sortItems, buildLayout, createVirtualList, middleEllipsis };

  // ==================== 瀑布流（Masonry）布局引擎 ====================
  // 绝对定位放置：看板按当前顺序依次放入「最矮列」底部，列数按容器宽度自适应，
  // 1 列时单看板占满整行；容器高度 = 最高列；重排（resize/宽度变化）使用 FLIP 平滑过渡。
  window.kanbanMasonry = (function () {
    // F5-L10：RM 判定 fail-closed 收口——原 `window.ds?.reducedMotion?.()` 在 ds 缺席时
    // 得 undefined，FLIP 照飞。ds.reducedMotion() 是全仓统一真源（缓存 MQL、.matches
    // 实时读，ds.js 已导出）；ds 缺席/媒体查询异常时兜底自证 matchMedia，且判定失败
    // 一律按 reduce 处理（宁可不动画，不违背「RM 下无动画」红线）。
    function isReduceMotion() {
      if (window.ds && typeof window.ds.reducedMotion === 'function') return !!window.ds.reducedMotion();
      try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (_) { return true; }
    }

    function capture(container, selector) {
      const map = new Map();
      container.querySelectorAll(selector).forEach(n => map.set(n, n.getBoundingClientRect()));
      return map;
    }

    function play(container, selector, first) {
      if (!first) return;
      // M-4（2026-10-03 L3）：看板 FLIP 走 Web Animations API，CSS 的
      // prefers-reduced-motion 通配归零管不到 Element.animate()（独立时间线）。
      // 系统开「减少动态效果」时必须整体跳过，否则窗口宽度变化仍会平移 300ms。
      if (isReduceMotion()) return;
      container.querySelectorAll(selector).forEach(n => {
        const f = first.get(n);
        if (!f) return;
        const l = n.getBoundingClientRect();
        const dx = f.left - l.left;
        const dy = f.top - l.top;
        if (Math.abs(dx) < 1 && Math.abs(dy) < 1) return;
        // Web Animations API：transform 合成器动画（60fps），结束后自动无残留
        if (typeof n.animate === 'function') {
          // P3-5（F5-G-5）：曲线/时长进 token 值集 —— 原 cubic-bezier(0.4,0,0.2,1)
          // 正是雾屿 V1 已退役的 M2 legacy 曲线；时长取 --duration-slow（320ms）。
          n.animate(
            [{ transform: `translate(${dx}px, ${dy}px)` }, { transform: 'none' }],
            { duration: 320, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' }
          );
        }
      });
    }

    // 计算并应用瀑布流布局（无动画）
    function layout(container, cardSelector, gap, minCard, maxCols) {
      const cards = [...container.querySelectorAll(cardSelector)];
      const width = container.clientWidth;
      if (width <= 0 || !cards.length) {
        container.style.height = '0px';
        return;
      }
      let colCount = Math.max(1, Math.min(cards.length, Math.floor((width + gap) / (minCard + gap))));
      // maxCols：有的看板要的是「固定几列」而不是「塞得下几列算几列」——
      // 右键管理按软件分组后，列里要放「挂在哪些位置」这类附加信息，
      // 宽屏下自动列数会涨到四五列，行就被挤回原来那种窄条样子。
      if (maxCols && maxCols > 0) colCount = Math.min(colCount, maxCols);
      const colWidth = Math.floor((width - gap * (colCount - 1)) / colCount);
      const heights = new Array(colCount).fill(0);
      // F5-L09：三趟化——先统一写宽度，再单独一趟只读高度（趟内零写入，整趟只付
      // 一次强制回流），最后写定位。旧第二趟「读 offsetHeight ⇄ 写 left/top」逐张
      // 交错，每张卡片付一次回流；本仓其余批量动效（liquid-glass 两趟注释、tilt、
      // spotlight）都是同一纪律，此处是最后一处未收敛的。
      cards.forEach(card => { card.style.width = colWidth + 'px'; });
      const cardHeights = cards.map(card => card.offsetHeight);
      cards.forEach((card, i) => {
        let idx = 0;
        for (let j = 1; j < colCount; j++) { if (heights[j] < heights[idx]) idx = j; }
        card.style.left = Math.round(idx * (colWidth + gap)) + 'px';
        card.style.top = Math.round(heights[idx]) + 'px';
        heights[idx] += cardHeights[i] + gap;
      });
      container.style.height = Math.max(...heights) + 'px';
    }

    // 绑定看板：getContainer() 每次返回当前布局容器（看板容器可能随重渲染重建）。
    // B7：用 ResizeObserver 替代原先 300ms 常驻轮询——容器尺寸变化才触发重排，
    // 彻底消除定时强制回流；容器随重渲染重建时在 check/relayout 里重新挂载观察。
    // 窗口 resize → 防抖 120ms 后重排（带 FLIP 动画）。
    // 返回 { relayout(animate), dispose() }：渲染层在重新渲染 DOM 后调用 relayout 立即布局。
    // F5-L07：dispose 是设计好的回收口，但现算两处调用方（contextmenu.js / optimizer.js）
    // 均为页面生命周期单例且**未调用**——「页面销毁时调用 dispose」不是已履行的契约，
    // 只是待接入的接口；接入属调用方（白名单外）改动。API 保留：移除它会让将来接入
    // 页面销毁路径时无回收手段（window resize 监听与 RO 都靠它解绑）。
    function attach(getContainer, cardSelector, opts) {
      const gap = (opts && opts.gap) != null ? opts.gap : 14;
      const minCard = (opts && opts.minCard) || 246;
      const maxCols = (opts && opts.maxCols) || 0;
      let lastW = -1;
      let ro = null;
      let roTarget = null;
      let roFrame = 0;
      let resizeTimer = null;
      let disposed = false;
      function force(animate) {
        const container = getContainer();
        if (!container || !container.isConnected) return; // 未挂载直接跳过
        const w = container.clientWidth;
        if (w <= 0) return;               // 页面隐藏时不布局，留待可见后重排
        const cap = animate && lastW > 0 ? capture(container, cardSelector) : null;
        layout(container, cardSelector, gap, minCard, maxCols);
        if (cap) play(container, cardSelector, cap);
        lastW = w;
      }
      function syncObserver() {
        if (disposed || typeof ResizeObserver !== 'function') return;
        const container = getContainer();
        if (!container || !container.isConnected) return;
        if (roTarget === container) return;
        // 真 masonry 堆叠根因（真机目检 2026-09-28）：RO 回调原来走 check()，而 check
        // 在宽度未变时跳过——字体（MiSansVF 异步加载）就绪后卡片变高触发 RO 却被跳过，
        // 列内卡片堆叠，直到拖动窗口改变宽度才恢复。改为 RO 回调无条件 force：
        // 高度变化（内容/字体/折叠）同样需要重排；重排是幂等的，收敛后 RO 不再触发。
        // 但重排必须推到下一帧：layout() 会写「被观察容器自身」的 style.height，在回调里
        // 同步写等于在本帧的投递循环内又产生一条通知 → WebView2 抛
        // 「ResizeObserver loop completed with undelivered notifications」，2026-09-30
        // 日志里那条 ERROR 级「渲染层异常」就是它。rAF 只多一帧，force 幂等，不影响
        // 字体就绪后的那次重排。
        if (!ro) ro = new ResizeObserver(() => {
          if (disposed || roFrame) return;
          roFrame = requestAnimationFrame(() => { roFrame = 0; force(false); });
        });
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
          if (roFrame) { cancelAnimationFrame(roFrame); roFrame = 0; }
          if (ro) { ro.disconnect(); ro = null; roTarget = null; }
          clearTimeout(resizeTimer);
          window.removeEventListener('resize', onWindowResize);
        }
      };
    }

    return { layout, attach };
  })();
})();
