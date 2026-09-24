// modal.js - 统一弹窗服务与弹窗 IPC 通道
// 1) IPC 接入：MutationObserver 监听 document.body，任何模块的弹窗
//    （动态增删的 *-backdrop 容器，或 #usageBackdrop 这类 display 切换的静态弹窗）
//    打开/关闭都会自动经 window.api.modal IPC 记录日志，各模块零改造；
// 2) 统一骨架：window.modal.create()/confirm() 生成与「设置 → 安装路径绑定」
//    一致的 usage-backdrop > usage-modal 三段式弹窗（header/body/footer），
//    供新弹窗直接复用。
(function () {
  'use strict';

  function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text == null ? '' : text).replace(/[&<>"']/g, m => map[m]);
  }

  // ---------- 空状态组件（扫描型页面统一空态视觉） ----------
  // 用法：emptyState({ icon, title, desc, cta: { text, target } })
  // icon: 'search' | 'box' | 'shield' | 'disk'；cta.target 为要触发的按钮 id，
  // 由 app.js 的全局委托点击转发到目标按钮（如 btnScan / btnScanStartup）。
  const EMPTY_ICONS = {
    search: '<path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>',
    box: '<path d="M20 2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h4v3l4-3h8c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 11H6v-2h12v2zm0-4H6V7h12v2z"/>',
    shield: '<path d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>',
    disk: '<path d="M6 2h12c1.1 0 2 .9 2 2v16c0 1.1-.9 2-2 2H6c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2zm6 2a6 6 0 1 0 0 12 6 6 0 0 0 0-12zm0 3a3 3 0 1 1 0 6 3 3 0 0 1 0-6zM6 18v2h2v-2H6zm4 0v2h2v-2h-2z"/>'
  };

  function emptyState({ icon = 'search', title = '', desc = '', cta = null } = {}) {
    const svgPath = EMPTY_ICONS[icon] || EMPTY_ICONS.search;
    return [
      '<div class="empty-state">',
      `<div class="empty-state-icon"><svg viewBox="0 0 24 24" width="28" height="28" fill="currentColor">${svgPath}</svg></div>`,
      title ? `<div class="empty-state-title">${escapeHtml(title)}</div>` : '',
      desc ? `<div class="empty-state-desc">${escapeHtml(desc)}</div>` : '',
      (cta && cta.text)
        ? `<div class="empty-state-cta"><button class="btn btn-primary" type="button" data-empty-cta="${escapeHtml(cta.target || '')}">${escapeHtml(cta.text)}</button></div>`
        : '',
      '</div>'
    ].join('');
  }

  function report(method, info) {
    try { window.api?.modal?.[method]?.(info || {}); } catch (e) { /* 日志失败不阻塞弹窗 */ }
  }

  function isModalNode(node) {
    return node.nodeType === 1 && node.classList &&
      Array.from(node.classList).some(c => c.endsWith('backdrop'));
  }

  function infoOf(node) {
    const title = node.querySelector('h2')?.textContent?.trim() || '';
    return { id: node.id || '', title: title.slice(0, 40) };
  }

  // ---------- 弹窗 IPC：监听全部弹窗的打开/关闭 ----------
  const visible = new WeakSet();

  function syncNode(node) {
    if (!isModalNode(node)) return;
    const shown = node.style.display !== 'none';
    if (shown && !visible.has(node)) {
      visible.add(node);
      report('open', infoOf(node));
    } else if (!shown && visible.has(node)) {
      visible.delete(node);
      report('close', infoOf(node));
    }
  }

  const observer = new MutationObserver(mutations => {
    for (const m of mutations) {
      if (m.type === 'attributes') {
        syncNode(m.target);
        continue;
      }
      m.addedNodes.forEach(node => syncNode(node));
      m.removedNodes.forEach(node => {
        if (isModalNode(node) && visible.has(node)) {
          visible.delete(node);
          report('close', infoOf(node));
        }
      });
    }
  });

  function startObserver() {
    observer.observe(document.body, { childList: true, attributes: true, attributeFilter: ['style'] });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startObserver);
  } else {
    startObserver();
  }

  // M2（v3.6.5）M2-5：补销毁契约——observer 与 DOMContentLoaded 监听原本没有解绑路径。
  // 约束/时机说明（不主动调用）：本模块的 MutationObserver 与弹窗 open/close 的 IPC 上报
  // 在渲染进程整个生命周期内都需要存在（弹窗可在任意时刻打开），静态下不存在「观察器
  // 可以安全摘除」的确定时机；因此这里只提供 destroy 契约（供窗口级回收复用），
  // 由调用方按需调用，不在此处猜测时机自行调用。重复调用安全。
  function stopObserver() {
    try { observer.disconnect(); } catch (e) { /* 尚未开始观察时断开无副作用 */ }
    document.removeEventListener('DOMContentLoaded', startObserver);
  }

  // ---------- 统一弹窗骨架工厂 ----------
  // opts: { id, title, bodyHtml, footerHtml, backdropClass, modalClass,
  //         bodyClass, footerClass, width, onRequestClose(reason)->false 可阻止关闭,
  //         iconSvg, metaHtml }（v3.2.0 弹窗统一批次：header 左侧可选图标 + 标题下元信息行，
  //         供优化中心详情等带徽章头的弹窗复用；iconSvg/metaHtml 为调用方生成的可信 HTML）
  // 返回 { backdrop, modal, body, footer, close() }；关闭时触发 opts.onClose(reason)
  function create(opts = {}) {
    const id = opts.id || 'modal-' + Date.now();
    document.getElementById(id)?.remove();

    const backdrop = document.createElement('div');
    backdrop.id = id;
    backdrop.className = 'usage-backdrop ' + (opts.backdropClass || '');

    const modalEl = document.createElement('div');
    modalEl.className = 'usage-modal ' + (opts.modalClass || '');
    modalEl.setAttribute('role', 'dialog');
    modalEl.setAttribute('aria-modal', 'true');
    modalEl.setAttribute('aria-labelledby', id + 'Title');
    if (opts.width) modalEl.style.maxWidth = typeof opts.width === 'number' ? opts.width + 'px' : String(opts.width);

    const useFooter = opts.footerHtml !== undefined;
    modalEl.innerHTML = `
      <div class="usage-header">
        ${opts.iconSvg ? `<span class="usage-header-icon" aria-hidden="true">${opts.iconSvg}</span>` : ''}
        <div class="usage-header-titlewrap">
          <h2 id="${id}Title">${escapeHtml(opts.title || '')}</h2>
          ${opts.metaHtml ? `<div class="usage-header-meta">${opts.metaHtml}</div>` : ''}
        </div>
        <button class="usage-close" type="button" data-tip="关闭" aria-label="关闭">&times;</button>
      </div>
      <div class="usage-body ${opts.bodyClass || ''}">${opts.bodyHtml || ''}</div>
      ${useFooter ? `<div class="usage-footer ${opts.footerClass || ''}">${opts.footerHtml}</div>` : ''}
    `;
    backdrop.appendChild(modalEl);
    document.body.appendChild(backdrop);

    let closed = false;
    let escHandler = null;

    // B10：焦点管理统一走 ds.focusTrap（design-system 单一实现）。
    // 打开时移焦点入弹窗（opts.initialFocus 选择器优先，高危确认聚焦「取消」）、
    // Tab 循环限制在弹窗内、关闭时归还焦点给触发元素；ds.js 缺席时优雅降级为无陷阱。
    const trap = (window.ds && typeof window.ds.focusTrap === 'function')
      ? window.ds.focusTrap(modalEl, { initialFocus: opts.initialFocus || null })
      : { release() {} };

    const ctrl = {
      backdrop,
      modal: modalEl,
      body: modalEl.querySelector('.usage-body'),
      footer: useFooter ? modalEl.querySelector('.usage-footer') : null,
      close() {
        if (closed) return;
        closed = true;
        document.removeEventListener('keydown', escHandler);
        backdrop.remove();
        trap.release();
        if (opts.onClose) opts.onClose('close');
      }
    };

    function requestClose(reason) {
      if (closed) return;
      if (opts.onRequestClose && opts.onRequestClose(reason) === false) return;
      ctrl.close();
    }

    modalEl.querySelector('.usage-close').addEventListener('click', () => requestClose('btn'));
    escHandler = e => { if (e.key === 'Escape') requestClose('esc'); };
    document.addEventListener('keydown', escHandler);
    backdrop.addEventListener('click', e => { if (e.target === backdrop) requestClose('backdrop'); });

    return ctrl;
  }

  // 便捷确认框：返回 Promise<boolean>（任意方式关闭都 resolve false）
  // danger=true 渲染红色确认按钮（规范要求：高风险操作必须红色二次确认）。
  // D10：warning=true 渲染黄色确认按钮（中风险操作），与 danger 互斥。
  // dangerHint/warningHint 为结构化警示文案：纯文本由模板统一转义渲染，
  // 调用方禁止自行拼接 HTML 字符串（会被 escapeHtml 转义成字面文本）。
  function confirm({ title = '确认', message = '', confirmText = '确认', cancelText = '取消', danger = false, warning = false, dangerHint = '', warningHint = '' }) {
    return new Promise(resolve => {
      let settled = false;
      const finish = v => { if (!settled) { settled = true; resolve(v); } };
      const severity = danger ? 'danger' : (warning ? 'warning' : '');
      const hintHtml = (dangerHint && danger) ? `
          <div class="confirm-danger-hint" role="alert"><svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg><span>${escapeHtml(dangerHint)}</span></div>
        ` : ((warningHint && warning) ? `
          <div class="confirm-warning-hint" role="alert"><svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg><span>${escapeHtml(warningHint)}</span></div>
        ` : '');
      const ctrl = create({
        // 每个确认框使用唯一 id：允许多个确认框并存（如连续的批量高危确认），
        // 避免固定 id 互相顶掉导致前一个 Promise 永不 resolve
        id: 'confirmModal-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6),
        title,
        bodyHtml: `<div class="confirm-message">${escapeHtml(message).replace(/\n/g, '<br>')}</div>${hintHtml}`,
        footerHtml: `
          <span class="model-picker-spacer"></span>
          <button class="btn btn-secondary" data-confirm="cancel" type="button">${escapeHtml(cancelText)}</button>
          <button class="btn ${severity === 'danger' ? 'btn-danger' : (severity === 'warning' ? 'btn-warning' : 'btn-primary')}" data-confirm="ok" type="button">${escapeHtml(confirmText)}</button>`,
        // B10：高危操作默认聚焦「取消」（防回车误触确认）；普通确认聚焦主按钮
        initialFocus: severity ? '[data-confirm="cancel"]' : '[data-confirm="ok"]',
        onClose() { finish(false); }
      });
      ctrl.footer.querySelector('[data-confirm="ok"]').addEventListener('click', () => { finish(true); ctrl.close(); });
      ctrl.footer.querySelector('[data-confirm="cancel"]').addEventListener('click', () => ctrl.close());
    });
  }

  // 关闭当前全部弹窗（退出/全局收起时用）
  function closeAll() {
    Array.from(document.body.children).forEach(node => {
      if (isModalNode(node) && node.style.display !== 'none') {
        node.style.display = 'none';
        if (visible.has(node)) visible.delete(node);
      }
    });
  }

  // M2（v3.6.5）M2-6：统一销毁契约（destroy 解绑 MutationObserver + DOMContentLoaded）
  window.modal = { create, confirm, closeAll, destroy: stopObserver };
  window.emptyState = emptyState;
})();
