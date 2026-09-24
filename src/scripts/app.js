// app.js - 主应用逻辑
// 负责页面路由、模态框、Toast、IPC 桥接、设置
(function () {
  'use strict';

  // 启动黑闪修复：尽早触发首帧上报（内部等 DOMContentLoaded 后双 rAF 才真正发送，
  // 主进程收到后才显示主窗口，确保窗口出现即完整 UI）
  try { window.api?.window?.notifyFirstPaint?.(); } catch (e) {}

  // 侧边栏折叠/展开
  const SIDEBAR_KEY = 'winclean-sidebar-collapsed';

  function getSidebarCollapsed() {
    try { return localStorage.getItem(SIDEBAR_KEY) === 'true'; } catch (e) { return false; }
  }

  function setSidebarCollapsed(collapsed) {
    try { localStorage.setItem(SIDEBAR_KEY, String(collapsed)); } catch (e) {}
  }

  function applySidebarState(collapsed) {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;
    sidebar.classList.toggle('collapsed', collapsed);
  }

  function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;
    const collapsed = sidebar.classList.toggle('collapsed');
    setSidebarCollapsed(collapsed);
    // v3.2.0（侧边岛滑块）：折叠剧变菜单项尺寸/位置，滑块坐标必须立即重算（瞬切不动画）
    window.liquidBar?.refreshAll?.(false);
  }

  // Motion.Lab ripple-click：统一提供轻量按压反馈，采用事件委托覆盖动态创建的弹窗按钮。
  // 波纹节点绝对定位脱离文档流（见 main.css 的 .btn > .btn-ripple），
  // 并在 animationend 与兜底定时器双重保障下移除，避免 DOM 累积。
  var RIPPLE_DURATION = 480;
  function setupButtonMotion() {
    document.addEventListener('pointerdown', (event) => {
      const button = event.target?.closest?.('.btn');
      if (!button || button.disabled || button.getAttribute('aria-disabled') === 'true') return;
      // 偏好减弱动效时完全不建节点，避免 animationend 不触发造成的泄漏
      if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
      const rect = button.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      const ripple = document.createElement('span');
      ripple.className = 'btn-ripple';
      ripple.style.left = `${event.clientX - rect.left}px`;
      ripple.style.top = `${event.clientY - rect.top}px`;
      const diameter = Math.max(rect.width, rect.height) * 1.35;
      ripple.style.width = `${diameter}px`;
      ripple.style.height = `${diameter}px`;
      const remove = () => ripple.remove();
      ripple.addEventListener('animationend', remove, { once: true });
      // 兜底：若动画被浏览器跳过（标签页后台、reduced-motion 中途切换等），仍能清理节点
      setTimeout(remove, RIPPLE_DURATION + 200);
      button.appendChild(ripple);
    }, { passive: true });
  }

  // 侧边栏子菜单（父级条目箭头）展开/折叠状态持久化
  const NAVSUB_KEY_PREFIX = 'winclean-navsub-';

  // 返回 null 表示用户从未手动设置过；业务层据此决定默认展开策略
  function getNavSubExpanded(key) {
    try {
      const val = localStorage.getItem(NAVSUB_KEY_PREFIX + key);
      if (val === null) return null;
      return val === 'true';
    } catch (e) { return null; }
  }

  function setNavSubExpanded(key, expanded) {
    try { localStorage.setItem(NAVSUB_KEY_PREFIX + key, String(expanded)); } catch (e) {}
  }

  // 默认展开策略：所有父级分组默认折叠；右键管理分类树的展开/收起由页面切换驱动
  function getNavSubDefaultExpanded(key) {
    return false;
  }

  function applyNavSubState(key, expanded) {
    const item = document.querySelector(`[data-nav-toggle="${key}"]`);
    const submenu = document.querySelector(`[data-nav-submenu="${key}"]`);
    item?.classList.toggle('expanded', expanded);
    submenu?.classList.toggle('expanded', expanded);
    if (submenu) {
      // 展开时回填带缓冲的 max-height：内容高度 + 缓冲，避免展开后滚动条出现/文本回流导致的轻微裁切
      // （收起时清空内联样式，回退到 CSS 的 max-height:0）
      if (expanded) {
        // 只为内容高度增加少量缓冲，避免固定 600px 把侧栏黑底撑到页底。
        // 上限仍保留，防止极长分类树把底部设置区推出可视范围。
        submenu.style.maxHeight = Math.min(600, submenu.scrollHeight + 16) + 'px';
      } else {
        submenu.style.maxHeight = '';
      }
    }
    // v3.2.0（侧边岛滑块）：子菜单展开/收起推开下方菜单项，滑块坐标立即重算（瞬切不动画，
    // 选项切换的滑动动画由点击 .nav-item 的 click 捕获另行触发）
    window.liquidBar?.refreshAll?.(false);
  }

  function toggleNavSub(key) {
    const item = document.querySelector(`[data-nav-toggle="${key}"]`);
    const expanded = !item?.classList.contains('expanded');
    applyNavSubState(key, expanded);
    setNavSubExpanded(key, expanded);
    if (expanded) {
      // 展开后将子菜单滚动到导航可见区域，避免窗口较矮时看不到全部分类
      document.querySelector(`[data-nav-submenu="${key}"]`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
    return expanded;
  }

  // ==================== 渲染脚本按需加载（v3.7.0 议题五） ====================
  // 改造前：38 个 <script> 全部同步加载、全部在启动时 init()，首屏解析 ~813 KB，
  // 其中磁盘测速、网络检测、运行库修复、快捷指令等页面用户可能永远不进。
  // 改造后：非首屏脚本从 index.html 摘出，进入对应页面（或首帧空闲）时动态注入。
  // 选型说明：动态 <script> 注入与现有 CSP（script-src 'self'）完全兼容，
  // 无需把 25 个 IIFE 改成 ESM、无需构建步骤、零新增依赖（AGENTS.md §5 红线）。
  // 数组内按依赖顺序排列，先加载的先执行（如 modelpicker ← intro ← contextmenu）。
  const PAGE_SCRIPTS = {
    // 磁盘清理的首屏脚本（cleanup.js / fallback）已在 index.html 内；
    // 查找器子视图（重复/大文件/空文件/AppData）才需要 finder.js
    'cleanup-finder': ['scripts/finder.js'],
    // sysrestore.js 的入口按钮（btnSysRestore）挂在「系统优化」页内，故随 optimizer 一并加载
    optimizer: ['scripts/optimizer.js', 'scripts/sysrestore.js'],
    contextmenu: ['scripts/modelpicker.js', 'scripts/intro.js', 'scripts/contextmenu.js'],
    startup: ['scripts/modelpicker.js', 'scripts/intro.js', 'scripts/startup.js'],
    maintenance: ['scripts/maintenance.js'],
    memoryclean: ['scripts/modelpicker.js', 'scripts/intro.js', 'scripts/memoryclean.js'],
    diskbench: ['scripts/diskbench.js'],
    netspeed: ['scripts/netspeed-detector.js', 'scripts/realtime.js', 'scripts/netspeed.js'],
    netcheck: ['scripts/netcheck.js'],
    runtimes: ['scripts/runtimes.js'],
    quickcmds: ['scripts/quickcmds-data.js', 'scripts/quickcmds.js'],
    settings: ['scripts/pathbinding.js']
  };
  // 需要显式调用 init() 的模块：这些文件加载时不会自执行 init。
  // 未列入的是自初始化件（DOMContentLoaded 自执行或纯数据/工具）——再调一次会重复绑定监听器。
  const MODULES_NEEDING_INIT = new Set([
    'cleanup', 'contextmenu', 'deviceinfo', 'diskbench', 'fontmanager', 'intro',
    'maintenance', 'memoryclean', 'netcheck', 'netspeed', 'optimizer', 'overview',
    'pathbinding', 'quickcmds', 'realtime', 'runtimes', 'startup', 'sysrestore'
  ]);
  // 首帧后空闲加载：视觉增强 + 自动更新 UI（不阻塞首帧）。
  // pathbinding 也放这里——cleanup.js 的 QQ/微信文件清理会读它的路径配置，
  // 空闲期预取可避免用户点扫描时配置还没就位。
  const IDLE_SCRIPTS = [
    'scripts/mouse-trail.js',
    'scripts/tilt.js',
    'scripts/spotlight.js',
    'scripts/updater-ui.js',
    'scripts/pathbinding.js'
  ];
  const _scriptLoaded = new Set();
  const _scriptLoading = new Map();

  function loadScript(src) {
    if (_scriptLoaded.has(src)) return Promise.resolve();
    if (_scriptLoading.has(src)) return _scriptLoading.get(src); // 快速连点去重：同一 src 只注入一次
    const p = new Promise((resolve) => {
      const s = document.createElement('script');
      s.src = src;
      s.onload = () => { _scriptLoaded.add(src); _scriptLoading.delete(src); resolve(); };
      // 注入失败不能让 switchPage 永久挂起：标记失败并放行，页面自身会优雅降级
      s.onerror = () => {
        _scriptLoading.delete(src);
        console.warn('[Trim] 脚本加载失败: ' + src);
        resolve();
      };
      document.body.appendChild(s);
    });
    _scriptLoading.set(src, p);
    return p;
  }

  async function ensurePageScripts(page) {
    const list = PAGE_SCRIPTS[page];
    if (!list || !list.length) return;
    for (const src of list) {
      await loadScript(src); // 顺序加载，保证依赖序
      initModuleOf(src);
    }
  }

  // 脚本加载完成后补一次 init（此前由 app.js 启动时的 safeInit 统一调用，
  // 改成按需加载后必须在这里补，否则模块只挂了 window.X 却没绑任何事件）
  function initModuleOf(src) {
    const name = String(src).split('/').pop().replace(/\.js$/, '');
    if (!MODULES_NEEDING_INIT.has(name)) return;
    try { window[name]?.init?.(); } catch (e) { console.warn(`[Trim] 模块 ${name} 初始化失败:`, e); }
  }

  // 首帧空闲后预取的非关键脚本：视觉增强 + 自动更新 UI + 路径绑定。
  // pathbinding 放这里是因为 cleanup.js 的 QQ/微信文件清理要读它的路径配置。
  function scheduleIdleLoads() {
    const idle = window.requestIdleCallback || ((cb) => setTimeout(cb, 1000));
    idle(() => { IDLE_SCRIPTS.forEach((src) => loadScript(src).then(() => initModuleOf(src))); });
  }

  // 路由
  const ACTIVE_PAGE_KEY = 'winclean-active-page';

  // 磁盘清理五合一：原五个独立页面收拢为 page-cleanup 内的分段视图
  const CLEANUP_VIEWS = ['cleanup', 'cleanup-dups', 'cleanup-big', 'cleanup-empty', 'cleanup-appdata'];
  const CLEANUP_VIEW_KEY = 'winclean-cleanup-view';

  function getCleanupView() {
    try {
      const v = localStorage.getItem(CLEANUP_VIEW_KEY);
      return CLEANUP_VIEWS.indexOf(v) > -1 ? v : 'cleanup';
    } catch (e) { return 'cleanup'; }
  }

  function setCleanupView(name, persist = true) {
    const view = CLEANUP_VIEWS.indexOf(name) > -1 ? name : 'cleanup';
    const tabs = document.getElementById('cleanupTabs');
    tabs?.querySelectorAll('.filter-tab').forEach(t => {
      const on = t.dataset.cleanupView === view;
      t.classList.toggle('active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.cleanup-view').forEach(v => {
      v.classList.toggle('active', v.dataset.cleanupPanel === view);
    });
    // 操作行与分段栏同行（窗口界面升级3）：仅显示当前子视图的操作按钮
    document.querySelectorAll('.cleanup-toolbar-actions').forEach(el => {
      el.classList.toggle('active', el.dataset.actionsFor === view);
    });
    // 大标题简介跟随子视图切换
    const subtitle = document.getElementById('cleanupSubtitle');
    const tab = tabs?.querySelector(`.filter-tab[data-cleanup-view="${view}"]`);
    if (subtitle && tab?.dataset.subtitle) subtitle.textContent = tab.dataset.subtitle;
    if (persist) {
      try { localStorage.setItem(CLEANUP_VIEW_KEY, view); } catch (e) {}
    }
    // 查找器子视图：确保脚本已初始化（finder 内部幂等）
    if (view !== 'cleanup') window.finder?.ensureInit?.();
    // 带动画刷新液态滑块（升级3：修复切换分段无动效——此前 refreshAll(false)
    // 在点击动画调度之后执行并把 schedulePlace 改写为无动画落位）
    window.liquidBar?.refreshAll?.(true);
  }

  // v3.7.0：switchPage 改 async（需先 await 本页脚本加载）。外层吞掉异常，
  // 避免导航点击处未 await 的 Promise 变成 unhandledrejection。
  function switchPage(pageName) {
    return switchPageInner(pageName).catch((e) => { console.warn('[Trim] 切换页面失败:', e); });
  }

  async function switchPageInner(pageName) {
    // 磁盘清理五合一：旧子页地址（cleanup-dups 等）统一映射到主页并恢复对应分段
    let cleanupView = 'cleanup';
    if (CLEANUP_VIEWS.indexOf(pageName) > -1) {
      cleanupView = pageName === 'cleanup' ? getCleanupView() : pageName;
      setCleanupView(cleanupView, false);
      pageName = 'cleanup';
    }
    // v3.7.0 议题五：先补齐本页脚本，再执行页面进入逻辑（否则 load()/onEnter() 是空操作）
    await ensurePageScripts(pageName);
    if (cleanupView !== 'cleanup') {
      await ensurePageScripts('cleanup-finder');
      window.finder?.ensureInit?.();
    }
    // 持久化活跃页（窗口状态记忆：启动恢复上次页面）
    try { localStorage.setItem(ACTIVE_PAGE_KEY, pageName); } catch (e) {}
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.page === pageName);
    });
    document.querySelectorAll('.page').forEach(el => {
      el.classList.toggle('active', el.id === 'page-' + pageName);
    });
    document.querySelectorAll('.nav-subitem').forEach(el => {
      // 分类树子项（data-category）高亮由右键管理模块独立维护，切换页面不清除
      if (el.dataset.category !== undefined) return;
      el.classList.toggle('active', el.dataset.page === pageName);
    });
    const speedParent = document.querySelector('[data-nav-toggle="speed"]');
    if (speedParent) speedParent.classList.toggle('active', pageName === 'netspeed' || pageName === 'diskbench' || pageName === 'netcheck');

    // 页面进入逻辑
    // v3.7.0 议题五第 0 步：此处原本是裸变量（logger.load() / startup.load()），
    // 脚本未加载即 ReferenceError 并中断整个 app.js。改 window.xxx?. 后模块才可被移出首屏。
    if (pageName === 'logs') window.logger?.load?.();
    if (pageName === 'startup') window.startup?.load?.();
    if (pageName === 'quickcmds') window.quickcmds?.init?.();
    // v3.2.1：首次进入磁盘清理页自动检测规则库云端版本（右上角 toast 提示更新）
    if (pageName === 'cleanup') window.cleanup?.onPageEnter?.();
    if (pageName === 'memoryclean') {
      window.memoryclean?.loadInfo?.();
    }
    if (pageName === 'settings') { window.pathbinding?.init?.(); }
    // v3.7.0：「默认应用接管」页面与模块已整块删除（含专家模式），进页钩子随之移除
    // 运行库修复（v3.3.0）：首次进入自动扫描一次（只读）
    if (pageName === 'runtimes') window.runtimes?.onEnter?.();
    // 网络检测（v3.0）：进入页面展示上次结果（不自动重跑）
    if (pageName === 'netcheck') window.netcheck?.onEnter?.();
    // 实时网速（已并入网络测速页）：进入网络测速页启动采集，离开停止，避免后台空耗 CPU
    if (pageName === 'netspeed') window.realtime?.start?.();
    else window.realtime?.stop?.();
    // 系统概览：进入启动实时指标轮询，离开停止
    if (pageName === 'overview') window.overview?.start?.();
    else window.overview?.stop?.();
    // 网络测速：仅点击"开始测速"按钮后才加载网页；离开本页回收 iframe 与采样定时器
    if (pageName !== 'netspeed') window.netspeed?.stop?.();
    // 液态玻璃滑块：页面重新显示后重新对齐（隐藏页内的滑块尺寸此前为 0）
    // v3.3.0 修复「侧边岛切页无动效」：此处原为 refreshAll(false)，会在 click 捕获排好的
    // animate=true 落位帧之后把滑块瞬位到终点（lg-no-anim），动画被整体杀掉。
    // 改为 true：切页时侧边岛坐标必变 → 弹簧滑动；unchanged 的栏（如 cleanupTabs active 未变）
    // 由方案 A 的坐标判定跳过挤压，隐藏页 0 尺寸栏 placeThumb 自动跳过、待下次刷新。
    window.liquidBar?.refreshAll?.(true);
  }

  // 模态确认：统一代理到 modal.confirm（单一实现），支持 danger 红色二次确认。
  // options: { danger: boolean, dangerHint: string, warning: boolean, warningHint: string }
  // dangerHint 为纯文本红色警示、warningHint 为纯文本黄色警示，
  // 均由弹窗模板统一转义渲染；调用方禁止自行拼接 HTML（会被转义成字面文本）。
  function confirm(title, message, confirmText = '确认', cancelText = '取消', options = {}) {
    const opts = options || {};
    if (!window.modal?.confirm) {
      // 兜底：modal.js 未加载时退回原生确认框，保证确认链路不因脚本加载顺序中断
      return Promise.resolve(window.confirm(`${title || ''}\n\n${String(message || '')}`));
    }
    return window.modal.confirm({
      title,
      message,
      confirmText,
      cancelText,
      danger: !!opts.danger,
      dangerHint: String(opts.dangerHint || ''),
      warning: !!opts.warning,
      warningHint: String(opts.warningHint || '')
    });
  }

  // 高风险操作语义化入口（规范：高风险清理项、内存深度清理、高危优化项、
  // 删除类操作必须红色二次确认）。新增高危确认一律走这里，避免遗漏 danger 标记。
  function confirmDanger(title, message, confirmText = '确认', cancelText = '取消', dangerHint = '') {
    return confirm(title, message, confirmText, cancelText, { danger: true, dangerHint });
  }

  // D10：中风险操作语义化入口（黄色确认）。中风险清理项勾选清理前的二次确认，
  // 与高风险红色确认分级，视觉与文案均低一档。
  function confirmWarning(title, message, confirmText = '确认', cancelText = '取消', warningHint = '') {
    return confirm(title, message, confirmText, cancelText, { danger: false, warning: true, warningHint });
  }

  // 审查v4-L8：浏览器预览模式（preload 未注入 window.api）的全局提示横幅。
  // 一次性告知「当前为模拟展示」，替代逐条 [模拟] toast 前缀，避免用户把模拟结果当真。
  function showPreviewModeBanner() {
    if (document.getElementById('previewModeBanner')) return;
    const bar = document.createElement('div');
    bar.id = 'previewModeBanner';
    bar.className = 'preview-mode-banner';
    bar.setAttribute('role', 'alert');
    bar.textContent = '浏览器预览模式：未接入应用主进程，页面数据与操作结果均为模拟展示，不会产生实际变更';
    document.body.appendChild(bar);
  }

  // 应用状态（管理员权限等）
  const appState = { isAdmin: null };

  // 请求 UAC 提权（弹出系统 UAC 对话框，成功后应用以管理员重启）
  async function requestElevation(reason) {
    if (!window.api?.elevate) {
      toast('warning', '当前环境不支持权限提升');
      return false;
    }
    const ok = await confirm(
      '提升管理员权限',
      (reason || '部分操作需要管理员权限才能完成。') + '\n\n点击"提升权限"将弹出系统 UAC 确认框，应用会以管理员身份重启。',
      '提升权限',
      '取消'
    );
    if (!ok) return false;
    try {
      const resp = await window.api.elevate.request();
      if (resp.success) {
        toast('info', '提权成功，应用即将以管理员身份重启');
        return true;
      }
      toast('warning', resp.message || '提权请求已取消');
      return false;
    } catch (e) {
      toast('error', '提权失败: ' + e.message);
      return false;
    }
  }

  // Toast 通知
  // 活动中的 Toast 注册表（用于点击空白区域时关闭最顶层 Toast）
  const activeToasts = [];
  // v3.7.0 议题一：同屏最大可见数。容器无滚动、无 max-height 时，批量任务的 Toast
  // 会一路堆到视口下沿并遮挡内容（实测 8~10 条铺满右缘）。超出上限按 FIFO 挤出最旧的。
  const MAX_VISIBLE_TOASTS = 4;

  function toast(type, message, duration = 3000, options = {}) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const icons = {
      success: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>',
      error: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.47 10-10S17.53 2 12 2zm5 13.59L15.59 17 12 13.41 8.41 17 7 15.59 10.59 12 7 8.41 8.41 7 12 10.59 15.59 7 17 8.41 13.41 12 17 15.59z"/></svg>',
      warning: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>',
      info: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>'
    };

    const el = document.createElement('div');
    el.className = `toast ${type}${options.guide ? ' toast-guide' : ''}`;
    const messageHtml = escapeHtml(message).replace(/\n/g, '<br>');
    el.innerHTML = `
      <div class="toast-icon">${icons[type] || icons.info}</div>
      <div class="toast-message">
        ${options.title ? `<div class="toast-title">${escapeHtml(options.title)}</div>` : ''}
        <div>${messageHtml}</div>
      </div>
      ${options.closable ? '<button class="toast-close" type="button" aria-label="关闭通知" data-tip="关闭">&times;</button>' : ''}
    `;
    container.appendChild(el);

    let removeTimer;
    const entry = { el };
    entry.remove = () => {
      clearTimeout(removeTimer);
      const i = activeToasts.indexOf(entry);
      if (i > -1) activeToasts.splice(i, 1);
      if (el.classList.contains('removing')) return;
      el.classList.add('removing');
      // v3.5.1 动效审查 H4：出场动画 --duration-base 为 220ms，原先 200ms 就移除节点，
      // 尾巴被硬切；延到 260ms 留出余量（reduced-motion 下动画只剩 0.01ms，不影响）。
      setTimeout(() => el.remove(), 260);
    };
    activeToasts.push(entry);
    el.querySelector('.toast-close')?.addEventListener('click', entry.remove);
    removeTimer = setTimeout(entry.remove, duration);
    // v3.7.0：悬停暂停计时、移出后续 1.5s —— 用户正在读的提示不该被计时器抽走
    el.addEventListener('pointerenter', () => clearTimeout(removeTimer));
    el.addEventListener('pointerleave', () => {
      clearTimeout(removeTimer);
      removeTimer = setTimeout(entry.remove, 1500);
    });
    trimToasts();
    return entry;
  }

  // v3.7.0 议题一：FIFO 挤出最旧的 Toast，保证同屏不超过 MAX_VISIBLE_TOASTS。
  // 跳过 toast-shutdown（关闭流程提示不可手动关闭，也不参与挤出）。
  function trimToasts() {
    let guard = activeToasts.length + 1;
    while (activeToasts.length > MAX_VISIBLE_TOASTS && guard-- > 0) {
      const idx = activeToasts.findIndex((t) => t && t.el && !t.el.classList.contains('toast-shutdown'));
      if (idx < 0) return;
      const oldest = activeToasts[idx];
      if (typeof oldest.remove === 'function') oldest.remove();
      else { activeToasts.splice(idx, 1); try { oldest.el.remove(); } catch (_) { /* 已脱离文档 */ } }
    }
  }

  // v3.7.0：外部自管 Toast（如 optimizer 的进度 Toast）挂进同一注册表，
  // 让「点击空白关最顶层」够得到它，也让条数护栏能统一计数。
  function registerToast(entry) {
    if (!entry || !entry.el) return entry;
    activeToasts.push(entry);
    trimToasts();
    return entry;
  }
  function unregisterToast(entry) {
    if (!entry) return;
    const i = activeToasts.indexOf(entry);
    if (i > -1) activeToasts.splice(i, 1);
  }

  // 点击窗口内空白区域关闭最顶层 Toast（超时自动关闭逻辑保留，此为额外手动关闭方式）
  function dismissTopToastOnClick(e) {
    if (!activeToasts.length) return;
    const t = e.target;
    if (!(t instanceof Element)) return;
    // 点击交互控件 / 弹窗 / Toast 本体时保留原有功能，不触发关闭
    if (t.closest('button, a, input, select, textarea, label, .toast, .usage-backdrop, .preview-backdrop, .ctx-detail-backdrop, .nav-item, .nav-subitem, .filter-tab, .checkbox, .context-item, .category-item, .ctx-cat-header, [contenteditable]')) return;
    // 自顶向下找最近添加且未移除的 Toast（关闭流程 Toast 不可手动关闭）
    for (let i = activeToasts.length - 1; i >= 0; i--) {
      const entry = activeToasts[i];
      if (entry.el && !entry.el.classList.contains('toast-shutdown')) {
        entry.remove();
        return;
      }
    }
  }

  // 轻量 Markdown 渲染（支持标题/表格/列表/引用/粗体/行内代码/分隔线，满足 readme.md 需要）
  function renderMarkdown(md) {
    const escapeHtmlInline = (text) => escapeHtml(text)
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>');
    const lines = String(md || '').split(/\r?\n/);
    let html = '';
    let listType = null; // 'ol' | 'ul'
    let inTable = false;

    const closeList = () => {
      if (listType) { html += `</${listType}>`; listType = null; }
    };
    const closeTable = () => {
      if (inTable) { html += '</tbody></table>'; inTable = false; }
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].replace(/\r$/, '');
      const trimmed = line.trim();
      if (!trimmed) { closeList(); closeTable(); html += '\n'; continue; }

      // 分隔线
      if (/^(-{3,}|\*{3,})$/.test(trimmed)) { closeList(); closeTable(); html += '<hr>'; continue; }
      // 标题
      const hm = trimmed.match(/^(#{1,6})\s+(.*)$/);
      if (hm) { closeList(); closeTable(); const lv = hm[1].length; html += `<h${lv}>${escapeHtmlInline(hm[2])}</h${lv}>`; continue; }
      // 引用
      if (trimmed.startsWith('> ')) { closeList(); closeTable(); html += `<blockquote>${escapeHtmlInline(trimmed.slice(2))}</blockquote>`; continue; }
      // 表格：表头行 + 分隔行 + 数据行（一次性收集整块）
      if (trimmed.startsWith('|') && trimmed.endsWith('|') && i + 1 < lines.length) {
        const next = lines[i + 1].trim();
        const isSepNext = /^\|[\s:|-]+\|$/.test(next) && /-/.test(next);
        if (isSepNext) {
          closeList(); closeTable();
          const headerCells = trimmed.slice(1, -1).split('|').map(c => escapeHtmlInline(c.trim()));
          html += `<table><thead><tr>${headerCells.map(c => `<th>${c}</th>`).join('')}</tr></thead><tbody>`;
          inTable = true;
          i += 2; // 跳过表头行与分隔行
          while (i < lines.length) {
            const row = lines[i].trim();
            if (!(row.startsWith('|') && row.endsWith('|'))) break;
            const dataCells = row.slice(1, -1).split('|').map(c => escapeHtmlInline(c.trim()));
            html += `<tr>${dataCells.map(c => `<td>${c}</td>`).join('')}</tr>`;
            i++;
          }
          i--; // 外层 for 会再次 ++
          closeTable();
          continue;
        }
      }
      // 有序列表
      const olm = trimmed.match(/^\d+[.)]\s+(.*)$/);
      if (olm) { closeTable(); if (listType !== 'ol') { closeList(); html += '<ol>'; listType = 'ol'; } html += `<li>${escapeHtmlInline(olm[1])}</li>`; continue; }
      // 无序列表
      const uls = trimmed.match(/^[-*+]\s+(.*)$/);
      if (uls) { closeTable(); if (listType !== 'ul') { closeList(); html += '<ul>'; listType = 'ul'; } html += `<li>${escapeHtmlInline(uls[1])}</li>`; continue; }

      // 普通段落
      closeList(); closeTable();
      html += `<p>${escapeHtmlInline(trimmed)}</p>`;
    }
    closeList(); closeTable();
    return html;
  }

  async function showUsageGuide() {
    const backdrop = document.getElementById('usageBackdrop');
    if (!backdrop) return;
    backdrop.style.display = 'flex';
    const body = document.getElementById('usageBody');
    if (!window.api?.app?.readUsage) {
      body.innerHTML = '<div class="empty-state"><p>使用说明仅在 Electron 环境中可用</p></div>';
      return;
    }
    try {
      const resp = await window.api.app.readUsage();
      if (resp && resp.success) {
        body.innerHTML = renderMarkdown(resp.content);
      } else {
        body.innerHTML = `<div class="empty-state"><p>${escapeHtml((resp && resp.message) || '加载使用说明失败')}</p></div>`;
      }
    } catch (e) {
      body.innerHTML = `<div class="empty-state"><p>加载使用说明失败: ${escapeHtml(e.message)}</p></div>`;
    }
  }

  function closeUsageGuide() {
    const backdrop = document.getElementById('usageBackdrop');
    if (backdrop) backdrop.style.display = 'none';
  }

  function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
  }

  // 日志（暴露给其它模块）
  function log(level, message) {
    return window.logger?.write?.(level, message);
  }

  // 加载应用信息
  async function loadAppInfo() {
    if (!window.api?.app) {
      // 浏览器预览模式
      setInfo('infoVersion', '2.8.0');
      setInfo('infoPortable', '标准安装');
      setInfo('infoElectron', 'N/A');
      setInfo('infoNode', 'N/A');
      setInfo('infoChrome', navigator.userAgent.match(/Chrome\/([\d.]+)/)?.[1] || 'N/A');
      setInfo('infoOS', navigator.platform);
      setInfo('infoBuild', 'N/A');
      setInfo('infoFluent', '基础支持');
      setInfo('infoMica', '未启用');
      setInfo('infoUser', '本地用户');
      setInfo('infoAdmin', '否');
      return;
    }
    try {
      const info = await window.api.app.getInfo();
      setInfo('infoVersion', info.version);
      // v2.6.0（P2-9）：数据目录形态（程序目录存在 Trim.portable 标记 = 便携模式）
      setInfo('infoPortable', info.portable ? '便携模式（程序目录\\data）' : '标准安装（%APPDATA%\\Trim）');
      setInfo('infoElectron', info.electron);
      setInfo('infoNode', info.node);
      setInfo('infoChrome', info.chrome);
      setInfo('infoOS', `${info.osVersion} (${info.arch})`);
      setInfo('infoBuild', `Build ${info.osBuild || '未知'}`);
      const fluentText = { full: '完整支持 (Mica + Acrylic)', partial: '部分支持 (基础 Mica)', none: '不支持' };
      setInfo('infoFluent', fluentText[info.fluentSupport] || info.fluentSupport || '未知');
      setInfo('infoMica', info.micaEnabled ? '已启用（原生）' : '未启用');
      setInfo('infoUser', info.username);
      setInfo('infoAdmin', info.isAdmin ? '是 ✓' : '否 ✗');
      // 全局记录管理员状态（供清理失败时建议提权）
      appState.isAdmin = !!info.isAdmin;
    } catch (e) {
      console.error('加载应用信息失败:', e);
    }
  }

  function setInfo(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  // ==================== 关闭流程（v2.7.0） ====================
  // 关闭编排已全部移交主进程：点击 X → 窗口立即隐藏，断开连接/清理临时文件/保存日志
  // 等收尾在后台静默进行后自动退出。渲染层不再展示「感谢使用」Toast，也不发送
  // shutdown:complete（通道保留作扩展点，preload 白名单未动）。

  // 初始化
  async function init() {
    setupButtonMotion();
    // 恢复侧边栏折叠状态
    applySidebarState(getSidebarCollapsed());

    // 空状态 CTA：委托转发到目标按钮（如「立即扫描」→ btnScan / btnScanStartup）
    document.addEventListener('click', (e) => {
      const btn = e.target && e.target.closest ? e.target.closest('[data-empty-cta]') : null;
      if (!btn) return;
      const target = document.getElementById(btn.dataset.emptyCta);
      if (target) target.click();
    });

    // 侧边栏折叠/展开按钮
    document.getElementById('sidebarToggle')?.addEventListener('click', toggleSidebar);

    // 导航：父级条目点击标题主体仅切换页面（不展开子菜单）；
    // 展开/收起子菜单只响应箭头热区（.nav-parent-toggle）
    document.querySelectorAll('.nav-item').forEach(el => {
      el.addEventListener('click', () => {
        const toggle = el.dataset.navToggle;
        if (toggle) {
          // 侧边栏整体折叠时，先展开侧边栏
          if (document.getElementById('sidebar')?.classList.contains('collapsed')) {
            applySidebarState(false);
            setSidebarCollapsed(false);
            return;
          }
          // 点击标题主体仅切换页面
          switchPage(el.dataset.page);
          return;
        }
        switchPage(el.dataset.page);
      });
      const arrow = el.querySelector('.nav-parent-toggle');
      if (arrow) {
        arrow.addEventListener('click', (e) => {
          e.stopPropagation();
          if (el.dataset.navToggle) toggleNavSub(el.dataset.navToggle);
        });
      }
    });
    document.querySelectorAll('.nav-subitem').forEach(el => {
      // 剩余子项仅测速分组（磁盘清理/优化中心/右键管理的分类已收拢为页内分段栏）
      el.addEventListener('click', () => {
        switchPage(el.dataset.page);
      });
    });
    // 恢复各父级子菜单的展开/折叠状态（默认折叠；用户手动切换后持久保留）
    document.querySelectorAll('[data-nav-submenu]').forEach(sub => {
      const key = sub.dataset.navSubmenu;
      const saved = getNavSubExpanded(key);
      applyNavSubState(key, saved === null ? getNavSubDefaultExpanded(key) : saved);
    });

    // 侧边栏滚轮联动：鼠标悬停在导航区（含展开的子菜单）时，
    // 优先滚动侧边栏本身，直到侧边栏滚动到底/顶（全部功能显示完整），
    // 剩余增量再转发到主内容区，避免滚动被展开项"困住"。
    const navSection = document.querySelector('.nav-scroll');
    const mainContent = document.getElementById('mainContent');
    if (navSection && mainContent) {
      navSection.addEventListener('wheel', (e) => {
        let delta = e.deltaY;
        if (e.deltaMode === 1) delta *= 16;        // 行 → 像素
        else if (e.deltaMode === 2) delta *= mainContent.clientHeight; // 页 → 像素
        const maxNavScroll = navSection.scrollHeight - navSection.clientHeight;
        if (maxNavScroll <= 0) {
          // 侧边栏无可滚动空间：增量直接给主内容
          mainContent.scrollTop += delta;
          e.preventDefault();
          return;
        }
        // 先滚动侧边栏，边界外的剩余增量交给主内容
        const newTop = navSection.scrollTop + delta;
        if (newTop < 0) {
          mainContent.scrollTop += newTop; // 侧边栏到顶后，向上部分滚主内容
          navSection.scrollTop = 0;
        } else if (newTop > maxNavScroll) {
          const leftover = newTop - maxNavScroll;
          mainContent.scrollTop += leftover; // 侧边栏到底后，向下部分滚主内容
          navSection.scrollTop = maxNavScroll;
        } else {
          navSection.scrollTop = newTop;
        }
        e.preventDefault();
      }, { passive: false });
    }

    // 模态默认关闭（usage-modal 由各自创建逻辑处理 backdrop 点击关闭）

    // 点击空白区域关闭最顶层 Toast
    document.addEventListener('click', dismissTopToastOnClick);

    // ==================== 窗口尺寸变化修复（最大化/还原/手动缩放） ====================
    // 只强制一次布局回流，不给标题栏/主布局追加 transform 合成层；后者在
    // Electron 最大化后可能留下过期的 hit-test 缓存，导致鼠标事件落不到按钮。
    let resizeTimer = null;
    function forceHitTestRefresh() {
      void document.documentElement.offsetWidth;
      void document.body.offsetHeight;
      requestAnimationFrame(() => {
        void document.querySelector('.layout')?.offsetWidth;
        refreshCollapseHeights();
      });
    }
    function refreshCollapseHeights() {
      document.querySelectorAll(
        '.category-group:not(.collapsed) > .category-group-content, ' +
        '.sub-group:not(.collapsed) > .sub-group-content, ' +
        '.ctx-cat-group:not(.collapsed) > .ctx-cat-content, ' +
        '.nav-submenu.expanded'
      ).forEach(el => {
        el.style.maxHeight = el.scrollHeight + 'px';
      });
    }
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        forceHitTestRefresh();
      }, 120);
    });
    window.api?.window?.onResized?.((bounds) => {
      // Win11 27H2：最大化期间由渲染层自绘不透明底色，避免 DWM 材质层黑帧；
      // 强制一次回流促使合成器立即提交新帧，消除最大化/还原后的残帧。
      const isMax = !!(bounds && bounds.maximized);
      if (document.body.classList.contains('win-maximized') !== isMax) {
        document.body.classList.toggle('win-maximized', isMax);
        void document.body.offsetHeight;
      }
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(forceHitTestRefresh, 0);
    });

    // 日志页面
    document.getElementById('btnRefreshLog')?.addEventListener('click', () => window.logger?.load?.());
    document.getElementById('btnExportLog')?.addEventListener('click', () => window.logger?.export?.());
    document.getElementById('btnClearLog')?.addEventListener('click', () => window.logger?.clear?.());
    document.getElementById('btnUsageGuide')?.addEventListener('click', showUsageGuide);
    document.getElementById('btnUsageClose')?.addEventListener('click', closeUsageGuide);
    // 批次：外部链接（GitHub 主页）—— 走受控 IPC，主进程校验 https
    document.getElementById('btnGitHub')?.addEventListener('click', () => {
      try { window.api?.app?.openExternal('https://github.com/xiaoxu1642/Trim'); } catch (_) {}
    });
    // v3.1.0：123 云盘备用下载渠道——先复制提取码（剪贴板写入需窗口在前台，须先于 openExternal）再打开链接
    document.getElementById('btn123Pan')?.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText('1642');
        window.app?.toast?.('success', '提取码 1642 已复制');
      } catch (e) {
        window.app?.toast?.('warning', '提取码复制失败，请在网盘页手动输入 1642');
      }
      try { window.api?.app?.openExternal('https://1813260438.share.123pan.cn/123pan/AzxUVv-APFIh?pwd=1642#'); } catch (_) {}
    });
    const usageBackdrop = document.getElementById('usageBackdrop');
    usageBackdrop?.addEventListener('click', (e) => {
      if (e.target === usageBackdrop) closeUsageGuide();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && usageBackdrop && usageBackdrop.style.display === 'flex') {
        closeUsageGuide();
      }
    });

    // 加载应用信息
    loadAppInfo();

    // 内置 PowerShell 7 运行时状态反馈（v3.3.x）：后台解压期间给「正在准备运行环境」提示，
    // 完成后一次性收尾；用户已自装/已就绪时进来即 ready，不弹成功提示避免每次启动噪音。
    initPwshFeedback();

    // 初始化各模块
    // LG-7（2026-09-15）：页面模块 init 逐个 try/catch——此前裸调用，任一模块抛错会
    // 让 window.app 未及时挂载、所有 window.app?.toast?.() 静默变空操作，比卡死更难诊断。
    const safeInit = (mod, name) => { try { mod?.init?.(); } catch (e) { console.warn(`[Trim] 模块 ${name} 初始化失败:`, e); } };
    // v3.7.0 议题五：只初始化首屏已加载的模块；其余改到 ensurePageScripts 加载后按需 init。
    // 裸变量已在第 0 步统一改为 window.xxx?.，脚本缺席时只是空操作而不会中断 app.js。
    safeInit(window.cleanup, 'cleanup');
    safeInit(window.overview, 'overview');
    safeInit(window.deviceinfo, 'deviceinfo');
    safeInit(window.fontmanager, 'fontmanager');

    // 磁盘清理分段视图：分段栏点击切换（液态滑块由 liquid-glass.js 统一监听跟随）
    document.getElementById('cleanupTabs')?.addEventListener('click', async (e) => {
      const tab = e.target.closest('.filter-tab');
      if (!tab || tab.classList.contains('active')) return;
      const view = tab.dataset.cleanupView;
      // v3.7.0 议题五：查找器子视图需要 finder.js，进入视图前补齐（脚本内部 ensureInit 幂等）
      if (view && view !== 'cleanup') {
        await ensurePageScripts('cleanup-finder');
        window.finder?.ensureInit?.();
      }
      setCleanupView(view);
    });

    // 设置 - 切换动效：全局液态玻璃强度（完整 / 标准 / 磨砂 / 关闭，旧值 refract 自动迁移为 standard）
    const liquidSelect = document.getElementById('liquidMotionSelect');
    if (liquidSelect) {
      liquidSelect.value = window.liquidBar?.getMode?.() || 'standard';
      liquidSelect.addEventListener('change', () => {
        window.liquidBar?.setMode?.(liquidSelect.value);
      });
    }

    // 字体管理：启动时恢复已保存的字体 / 字重 / 字号设置（默认 MiSans · 400 · 16px）
    window.fontmanager?.restore?.();

    // 暴露给其它模块（须在页面模块启动逻辑之前，保证其可调用 app 能力）
    window.app = { toast, confirm, confirmDanger, confirmWarning, showPreviewModeBanner, log, switchPage, loadAppInfo, requestElevation, registerToast, unregisterToast, getState: () => appState };

    // 监听内置 pwsh 运行时状态：准备中→就绪/失败的一次性反馈（已就绪不弹）。
    // 解压期间主进程每 ~800ms 广播一次进度，晚订阅的渲染层仍能接到在途广播。
    function initPwshFeedback() {
      try {
        const api = window.api?.pwsh;
        if (!api || typeof api.onStatus !== 'function') return;
        let stage = null; // null | 'extracting' | 'ready' | 'error'
        let preparingEntry = null;
        const dismissPreparing = () => { try { preparingEntry?.remove(); } catch (_) {} preparingEntry = null; };
        const apply = (s) => {
          if (!s || typeof s.status !== 'string') return;
          if (s.status === 'extracting' && stage !== 'extracting') {
            stage = 'extracting';
            // duration=0 会立即移除，故用长时长模拟常驻 + 可手动关闭
            preparingEntry = toast('info', s.message || '正在准备 PowerShell 7 运行环境（首次约 10-30 秒）…', 120000, { closable: true });
          } else if (s.status === 'ready') {
            const wasPreparing = stage === 'extracting';
            dismissPreparing();
            if (wasPreparing) toast('success', 'PowerShell 7 运行环境已就绪');
            stage = 'ready';
          } else if (s.status === 'error' && stage !== 'error') {
            dismissPreparing();
            stage = 'error';
            toast('error', s.message || 'PowerShell 7 运行环境准备失败，请安装 PowerShell 7 后重试');
          }
        };
        const unsubscribe = api.onStatus(apply);
        api.getStatus().then((r) => { try { if (r && r.success && r.data) apply(r.data); } catch (_) {} }).catch(() => {});
        window.addEventListener('beforeunload', () => { try { unsubscribe(); } catch (_) {} });
      } catch (_) { /* 反馈属增强，失败不阻断页面 */ }
    }

    // 初始加载：恢复上次活跃页（窗口状态记忆），无记录则默认系统概览
    const lastPage = (() => { try { return localStorage.getItem(ACTIVE_PAGE_KEY); } catch (e) { return null; } })();
    // 磁盘清理五合一：旧子页地址（cleanup-dups 等）对应 page 已不存在，先归一化到主页
    const targetPage = lastPage && CLEANUP_VIEWS.indexOf(lastPage) > -1 ? 'cleanup' : lastPage;
    if (targetPage && targetPage !== 'overview' && document.getElementById('page-' + targetPage)) {
      // 审查 7-4：统一用归一化后的变量；switchPage 内部自会处理五合一旧地址。
      // v3.7.0：switchPage 已改 async（要先补齐本页脚本），此处必须 await——
      // 否则恢复的页面是 optimizer 时，下面的 overview.start() 会先跑起来。
      await switchPage(targetPage);
    } else if (document.getElementById('page-overview')?.classList.contains('active')) {
      window.overview?.start?.();
    }

    // 初始化日志
    setTimeout(() => log('info', '应用启动'), 500);

    // v2.7.0：关闭编排移交主进程，渲染层不再监听 app:shutdown（见文件上方关闭流程说明）

    // B5：提权重启后未检测到新实例时，主进程会保持当前实例运行并通知到这里
    if (window.api?.elevate?.onNotice) {
      window.api.elevate.onNotice(data => {
        toast('warning', (data && data.message) || '未检测到新实例启动，已保持当前运行状态');
      });
    }

    // 内存占用优化：窗口最小化/隐藏后主动回收渲染进程堆内存
    // （主进程经 js-flags --expose-gc 暴露 gc()，同时通过 memory:trim 通知；浏览器模式退化为 visibilitychange）
    const trimRendererMemory = () => { try { window.gc && window.gc(); } catch (e) {} };
    if (window.api?.app?.onMemoryTrim) {
      window.api.app.onMemoryTrim(trimRendererMemory);
    }
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') trimRendererMemory();
    });

    // v2.8.0：窗口焦点状态——失焦时 body 挂 win-inactive（视觉纱降低存在感）
    if (window.api?.window?.onFocusState) {
      window.api.window.onFocusState((state) => {
        document.body.classList.toggle('win-inactive', !(state && state.focused));
      });
    }

    // v2.8.0：第三方窗口美化工具兼容性提示（主进程启动后一次性检测的结果，无工具时不可见）
    if (window.api?.diag?.dwmConflict) {
      window.api.diag.dwmConflict().then((r) => {
        if (!r || !r.detected) return;
        const row = document.getElementById('diagDwmRow');
        const text = document.getElementById('diagDwmText');
        if (row) row.style.display = '';
        if (text) text.textContent = '检测到第三方窗口美化工具，旧版本可能导致窗口预览异常，建议更新到最新版本';
      }).catch(() => {});
    }

    // v3.7.0 议题五：首帧之后空闲预取非关键脚本（视觉增强 / 自动更新 UI / 路径绑定）
    scheduleIdleLoads();

    // v2.7.1：真实初始化完成——启动页（splash.js）监听此事件收尾进度并进入主界面，
    // 替代纯假进度等待；预览模式无监听方，派发无副作用
    try { window.dispatchEvent(new CustomEvent('trim:boot-ready')); } catch (e) {}
  }

  // 等待 DOM
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
