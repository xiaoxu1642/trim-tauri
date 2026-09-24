// ds.js - Trim Design-System 高频五件套 API（Badge / Progress / Slider / Switch）
// 行为规格参考 shadcn/ui（Radix）源码直译；视觉见 styles/ds.css（Fluent token）。
// Dialog（确认弹窗）的行为层在 modal.js 内实现（B10 焦点陷阱），不经过本文件。
// 零依赖、零框架；window.ds 暴露，任意窗口引入 ds.css + ds.js 即可使用。
(function () {
  'use strict';

  const ds = { version: '1.0.0' };

  function reducedMotion() {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }

  function escapeHtml(s) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(s == null ? '' : s).replace(/[&<>"']/g, m => map[m]);
  }

  // ---------- ① Badge ----------
  // 语义类型 → ds.css 变体类；文本经 textContent/转义，防注入。
  const BADGE_VARIANT = {
    ok: 'ok', success: 'ok',
    warn: 'warn', warning: 'warn',
    bad: 'bad', danger: 'bad',
    neutral: 'neutral', accent: 'accent'
  };

  function badge(type, text, { dotless = false, title = '', small = false } = {}) {
    const el = document.createElement('span');
    el.className = 'ds-badge ' + (BADGE_VARIANT[type] || 'neutral') + (dotless ? ' dotless' : '') + (small ? ' sm' : '');
    if (title) el.setAttribute('data-tip', title); // LG-3（2026-09-15）：data-tip 替代原生 title（下方委托收敛；badgeHtml 同款）
    el.textContent = text == null ? '' : String(text);
    return el;
  }

  function badgeHtml(type, text, { dotless = false, title = '', small = false } = {}) {
    const cls = 'ds-badge ' + (BADGE_VARIANT[type] || 'neutral') + (dotless ? ' dotless' : '') + (small ? ' sm' : '');
    return `<span class="${cls}"${title ? ` data-tip="${escapeHtml(title)}"` : ''}>${escapeHtml(text)}</span>`;
  }

  // ---------- ② Progress ----------
  // 线形：与 main.css .progress-bar/.progress-fill 结构配合，负责钳值与 ARIA 回填。
  function setFill(fillEl, pct) {
    if (!fillEl) return;
    const p = Math.max(0, Math.min(100, Number(pct) || 0));
    fillEl.style.width = p + '%';
    const host = fillEl.closest('[role="progressbar"]') || fillEl.parentElement;
    if (host && host.getAttribute('role') === 'progressbar') {
      host.setAttribute('aria-valuenow', String(Math.round(p)));
    }
  }

  // 环形：SVG stroke-dashoffset 实现；返回 { el, set(pct, text?, color?) }。
  // set 的 color 用于阈值变色（如内存占用 ≥70% 琥珀 / ≥90% 红），缺省保持强调色。
  function circle({ size = 56, stroke = 6, label = '进度', className = '' } = {}) {
    const s = Math.max(24, Number(size) || 56);
    const w = Math.max(2, Number(stroke) || 6);
    const r = (s - w) / 2;
    const c = 2 * Math.PI * r;

    const el = document.createElement('div');
    el.className = ('ds-ring ' + className).trim();
    el.style.width = el.style.height = s + 'px';
    el.setAttribute('role', 'progressbar');
    el.setAttribute('aria-label', label);
    el.setAttribute('aria-valuemin', '0');
    el.setAttribute('aria-valuemax', '100');
    el.setAttribute('aria-valuenow', '0');
    el.innerHTML =
      `<svg class="ds-ring-svg" width="${s}" height="${s}" viewBox="0 0 ${s} ${s}" aria-hidden="true">` +
      `<circle class="ds-ring-track" cx="${s / 2}" cy="${s / 2}" r="${r}" style="stroke-width:${w}"></circle>` +
      `<circle class="ds-ring-fill" cx="${s / 2}" cy="${s / 2}" r="${r}" style="stroke-width:${w}"></circle>` +
      `</svg><span class="ds-ring-text">--</span>`;

    const fill = el.querySelector('.ds-ring-fill');
    const text = el.querySelector('.ds-ring-text');
    fill.style.strokeDasharray = `${c} ${c}`;
    fill.style.strokeDashoffset = String(c);
    if (reducedMotion()) fill.style.transition = 'none';

    let value = null;
    return {
      el,
      get value() { return value; },
      set(pct, textOverride, color) {
        const p = Math.max(0, Math.min(100, Number(pct) || 0));
        fill.style.strokeDashoffset = String(c * (1 - p / 100));
        if (color) fill.style.stroke = color; else fill.style.stroke = '';
        el.setAttribute('aria-valuenow', String(Math.round(p)));
        text.textContent = textOverride != null ? String(textOverride) : Math.round(p) + '%';
        value = p;
      }
    };
  }

  // ---------- ③ Slider ----------
  // 维护 --val（轨道填充百分比）与 ARIA；只改样式变量，不干涉业务取值。
  function syncSlider(el) {
    if (!el || el.type !== 'range') return;
    const min = el.min === '' ? 0 : Number(el.min);
    const max = el.max === '' ? 100 : Number(el.max);
    const v = Number(el.value) || 0;
    const span = max - min;
    el.style.setProperty('--val', (span > 0 ? ((v - min) / span) * 100 : 0) + '%');
    el.setAttribute('aria-valuemin', String(min));
    el.setAttribute('aria-valuemax', String(max));
    el.setAttribute('aria-valuenow', String(v));
  }

  // 自动接管规则：仅初始化「裸 range」（无任何 class）——例如背景透明度滑块；
  // 已有专属样式的（fm-slider 等）一律不碰，需要时手动加 .ds-slider 类并调用 sync。
  function initSliders(root) {
    (root || document).querySelectorAll('input[type="range"]').forEach(el => {
      if (el.classList.length > 0 || el.__dsSlider) return;
      el.__dsSlider = true;
      el.classList.add('ds-slider');
      syncSlider(el);
      el.addEventListener('input', () => syncSlider(el));
    });
  }

  // ---------- ④ Switch ----------
  // 与 main.css 既有 .toggle-switch 标记结构完全一致，动态内容直接可用。
  function sw({ checked = false, label = '', title = '', id = '', onChange = null } = {}) {
    const wrap = document.createElement('label');
    wrap.className = 'toggle-switch';
    if (title) wrap.setAttribute('data-tip', title); // LG-3（2026-09-15）：data-tip 替代原生 title
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = !!checked;
    if (id) input.id = id;
    if (label) input.setAttribute('aria-label', label);
    const track = document.createElement('span');
    track.className = 'toggle-track';
    const thumb = document.createElement('span');
    thumb.className = 'toggle-thumb';
    track.appendChild(thumb);
    wrap.appendChild(input);
    wrap.appendChild(track);
    if (typeof onChange === 'function') {
      input.addEventListener('change', () => onChange(input.checked));
    }
    return {
      el: wrap,
      input,
      set(v) { input.checked = !!v; }
    };
  }

  // ---------- ⑤ Tooltip（data-tip 委托，替代原生 title 避免双气泡） ----------
  // 用法：<button data-tip="提示文本">…</button>。单例浮层：pointer 延迟 300ms、
  // focus 即时；边界自动上下翻转 + 水平钳制；Esc/滚动/外点即隐。
  const tooltip = { el: null, target: null, timer: null };

  function tooltipHide() {
    clearTimeout(tooltip.timer);
    tooltip.timer = null;
    if (tooltip.target) {
      tooltip.target.removeAttribute('aria-describedby');
      tooltip.target = null;
    }
    if (tooltip.el) tooltip.el.classList.remove('on');
  }

  function tooltipShow(target) {
    const text = target.getAttribute('data-tip');
    if (!text) return;
    if (!tooltip.el) {
      tooltip.el = document.createElement('div');
      tooltip.el.className = 'ds-tooltip';
      tooltip.el.setAttribute('role', 'tooltip');
      document.body.appendChild(tooltip.el);
    }
    tooltip.target = target;
    tooltip.el.id = tooltip.el.id || 'dsTooltipId';
    target.setAttribute('aria-describedby', tooltip.el.id);
    tooltip.el.textContent = text;
    const r = target.getBoundingClientRect();
    const vw = document.documentElement.clientWidth;
    const vh = document.documentElement.clientHeight;
    tooltip.el.classList.add('on');
    const tw = tooltip.el.offsetWidth;
    const th = tooltip.el.offsetHeight;
    let left = r.left + r.width / 2 - tw / 2;
    left = Math.max(8, Math.min(left, vw - tw - 8));
    let top = r.top - th - 8;                 // 默认在上方
    if (top < 8) top = r.bottom + 8;          // 上方放不下 → 翻到下方
    if (top + th > vh - 8) top = Math.max(8, vh - th - 8);
    tooltip.el.style.left = left + 'px';
    tooltip.el.style.top = top + 'px';
  }

  function tooltipSchedule(target) {
    clearTimeout(tooltip.timer);
    tooltip.timer = setTimeout(() => tooltipShow(target), 300);
  }

  document.addEventListener('pointerover', e => {
    const t = e.target.closest && e.target.closest('[data-tip]');
    if (t && t !== tooltip.target) tooltipSchedule(t);
    else if (!t) tooltipHide();
  });
  document.addEventListener('pointerdown', () => tooltipHide());
  document.addEventListener('focusin', e => {
    const t = e.target.closest && e.target.closest('[data-tip]');
    if (t) tooltipShow(t);                    // 键盘聚焦即时显示（无延迟）
  });
  document.addEventListener('focusout', () => tooltipHide());
  window.addEventListener('scroll', () => tooltipHide(), true);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') tooltipHide(); });

  // ---------- ⑥ DropdownMenu ----------
  // ds.menu({ trigger, items, onSelect, align }) → { open, close, destroy }
  // items: [{ label, value, danger?, disabled? }]；键盘：↑↓/Home/End 移动、Enter 确认、
  // Esc/Tab/外点关闭并还焦点；ARIA：menu/menuitem + aria-expanded/haspopup。
  function menu({ trigger, items, onSelect, align = 'start' } = {}) {
    let pop = null;
    let current = [];
    // trigger 缺失（页面无此元素）时返回空实现，保证调用方无需判空
    if (!trigger) {
      return { open() {}, close() {}, destroy() {}, get isOpen() { return false; } };
    }

    function close() {
      if (!pop) return;
      pop.remove();
      pop = null;
      trigger.setAttribute('aria-expanded', 'false');
      document.removeEventListener('pointerdown', onDocDown, true);
      document.removeEventListener('keydown', onKey, true);
      if (trigger instanceof HTMLElement) trigger.focus();
    }
    function onDocDown(e) {
      if (pop && !pop.contains(e.target) && e.target !== trigger && !trigger.contains(e.target)) close();
    }
    function choose(it) {
      close();
      if (typeof onSelect === 'function') onSelect(it.value, it);
    }
    function focusAt(idx) {
      const els = pop ? Array.from(pop.querySelectorAll('.ds-menu-item:not([aria-disabled="true"])')) : [];
      if (!els.length) return;
      const i = (idx + els.length) % els.length;
      els[i].focus();
    }
    function onKey(e) {
      if (!pop) return;
      const els = Array.from(pop.querySelectorAll('.ds-menu-item:not([aria-disabled="true"])'));
      const idx = els.indexOf(document.activeElement);
      if (e.key === 'Escape') { e.stopPropagation(); close(); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); focusAt(idx + 1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); focusAt(idx - 1); }
      else if (e.key === 'Home') { e.preventDefault(); focusAt(0); }
      else if (e.key === 'End') { e.preventDefault(); focusAt(els.length - 1); }
      else if (e.key === 'Tab') { close(); }
    }

    function open() {
      if (pop) { close(); return; }
      current = Array.isArray(items) ? items : [];
      pop = document.createElement('div');
      pop.className = 'ds-menu';
      pop.setAttribute('role', 'menu');
      pop.innerHTML = current.map(it => `
        <button type="button" class="ds-menu-item${it.danger ? ' danger' : ''}"
          role="menuitem" ${it.disabled ? 'aria-disabled="true"' : ''}
          data-menu-value="${escapeHtml(String(it.value == null ? '' : it.value))}">${escapeHtml(it.label)}</button>`).join('');
      document.body.appendChild(pop);
      const r = trigger.getBoundingClientRect();
      const vw = document.documentElement.clientWidth;
      const vh = document.documentElement.clientHeight;
      const pw = pop.offsetWidth;
      const ph = pop.offsetHeight;
      let left = align === 'end' ? r.right - pw : r.left;
      left = Math.max(8, Math.min(left, vw - pw - 8));
      let top = r.bottom + 6;
      if (top + ph > vh - 8) top = Math.max(8, r.top - ph - 6);
      pop.style.left = left + 'px';
      pop.style.top = top + 'px';
      trigger.setAttribute('aria-expanded', 'true');
      pop.addEventListener('click', e => {
        const btn = e.target.closest('.ds-menu-item');
        if (!btn || btn.getAttribute('aria-disabled') === 'true') return;
        const it = current.find(x => String(x.value == null ? '' : x.value) === btn.dataset.menuValue);
        if (it) choose(it);
      });
      document.addEventListener('pointerdown', onDocDown, true);
      document.addEventListener('keydown', onKey, true);
      focusAt(0);
    }

    trigger.setAttribute('aria-haspopup', 'menu');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.addEventListener('click', open);
    return {
      open,
      close,
      destroy() { close(); trigger.removeEventListener('click', open); },
      get isOpen() { return !!pop; }
    };
  }

  // ---------- ⑦ Skeleton（加载骨架） ----------
  // ds.skeletonRows(n)：列表型骨架（方图标 + 双行文字条），扫描/加载期间占位。
  function skeletonRows(n = 5) {
    const count = Math.max(1, Math.min(20, Number(n) || 5));
    let html = '<div class="ds-skeleton" aria-hidden="true">';
    for (let i = 0; i < count; i++) {
      const w = [92, 76, 84, 68, 88][i % 5];
      html += `<div class="ds-skeleton-row">
        <span class="ds-skeleton-block icon"></span>
        <span class="ds-skeleton-block line" style="width:${w}%"></span>
        <span class="ds-skeleton-block line short" style="width:12%"></span>
      </div>`;
    }
    return html + '</div>';
  }

  // ---------- ⑧ Accordion（为既有「collapsed class」折叠补 ARIA） ----------
  // 不改视觉逻辑，只同步 aria-expanded / aria-hidden；调用方仍用原来的 class 切换。
  function accordionEnhance(toggle, panel, { collapsedClass = 'collapsed' } = {}) {
    if (!toggle || !panel) return;
    const panelId = panel.id || 'ds-panel-' + Math.random().toString(36).slice(2, 7);
    panel.id = panelId;
    toggle.setAttribute('aria-controls', panelId);
    const sync = () => {
      const collapsed = panel.classList.contains(collapsedClass) || panel.style.display === 'none';
      toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      panel.setAttribute('aria-hidden', collapsed ? 'true' : 'false');
    };
    toggle.addEventListener('click', () => setTimeout(sync, 0));
    sync();
  }

  // ---------- ⑨ focusTrap（弹出层统一焦点管理） ----------
  // modal.js 与各自定义弹窗共用：打开时移焦点入容器（initialFocus 选择器优先），
  // Tab 循环限制在容器内，release() 时归还焦点。
  function focusTrap(container, { initialFocus = null, active = true } = {}) {
    if (!container) return { release() {} };
    const prevFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    function focusables() {
      // 弹窗链路存在 fixed 定位，offsetParent 不可靠，用 getClientRects 判可见
      return Array.from(container.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )).filter(n => !n.disabled && n.getClientRects().length > 0);
    }
    function onFocusIn() {
      if (!container.contains(document.activeElement)) {
        const target = focusables()[0];
        if (target) target.focus();
      }
    }
    function onKey(e) {
      if (e.key !== 'Tab') return;
      const f = focusables();
      if (!f.length) return;
      const first = f[0];
      const last = f[f.length - 1];
      const cur = document.activeElement;
      if (e.shiftKey && (cur === first || !container.contains(cur))) { last.focus(); e.preventDefault(); }
      else if (!e.shiftKey && (cur === last || !container.contains(cur))) { first.focus(); e.preventDefault(); }
    }
    function initial() {
      const target = (initialFocus && container.querySelector(initialFocus)) || focusables()[0];
      if (target instanceof HTMLElement) target.focus();
    }
    if (active) {
      container.addEventListener('focusin', onFocusIn);
      container.addEventListener('keydown', onKey);
      initial();
    }
    return {
      release() {
        container.removeEventListener('focusin', onFocusIn);
        container.removeEventListener('keydown', onKey);
        if (prevFocus && prevFocus.isConnected) prevFocus.focus();
      }
    };
  }

  // ---------- ⑩ 横向滚动容器滚轮映射 ----------
  // 需求：横向滚动条容器内，滚轮向下 = 内容向左滚（露出右侧），滚轮向上 = 向右滚。
  // 仅当元素实际横向可滚时才拦截 wheel（否则放行页面竖向滚动）。
  function hWheel(el) {
    if (!el || el.__dsHWheel) return el;
    el.__dsHWheel = true;
    el.addEventListener('wheel', e => {
      if (el.scrollWidth <= el.clientWidth + 1) return;
      const delta = Math.abs(e.deltaY) >= Math.abs(e.deltaX) ? e.deltaY : e.deltaX;
      if (!delta) return;
      e.preventDefault();
      el.scrollLeft += delta;
    }, { passive: false });
    return el;
  }
  // 自动接管：.filter-tabs--scroll（分段栏横向滚动变体）与显式标注的 .ds-hwheel
  function hWheelAll(root) {
    (root || document).querySelectorAll('.filter-tabs--scroll, .ds-hwheel').forEach(hWheel);
  }

  ds.badge = badge;
  ds.badgeHtml = badgeHtml;
  ds.progress = { setFill, circle };
  ds.slider = { sync: syncSlider, initAll: initSliders };
  ds.switch = sw;
  ds.tooltip = { show: tooltipShow, hide: tooltipHide };
  ds.menu = menu;
  ds.skeletonRows = skeletonRows;
  ds.accordion = { enhance: accordionEnhance };
  ds.focusTrap = focusTrap;
  ds.hWheel = hWheel;

  // 自动初始化（裸 range 接管 + 横向滚动容器滚轮映射）
  const boot = () => { initSliders(document); hWheelAll(document); };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }

  // 审查 5-5：背景模糊度百分比 → 玻璃模糊半径（px）换算上限，pathbinding 与 theme 共用
  ds.GLASS_MAX_BLUR_PX = 26;

  window.ds = ds;
})();
