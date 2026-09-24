// process-manager-window.js - 内存清理 → 「应用进程管理」独立窗口
// 承载运行进程列表（按路径分组 + 实例缩进的进程树），支持搜索、刷新、逐项/整体结束进程。
// 列表渲染与结束逻辑复用 processes.js（与「内存清理」页共享）。
// 注意：独立窗口未加载 app.js，故 confirm/toast 自行实现（统一使用 .usage-modal 样式）。
(function () {
  'use strict';

  function el(id) { return document.getElementById(id); }
  function escapeHtml(s) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(s == null ? '' : s).replace(/[&<>"']/g, m => map[m]);
  }

  function toast(type, message) {
    const host = el('pmGlobalHint');
    if (!host) return;
    host.textContent = message || '';
    host.style.color = type === 'error' ? 'var(--danger)'
      : type === 'success' ? 'var(--success)'
        : type === 'warning' ? 'var(--warning)' : 'var(--fg-tertiary)';
    if (message) setTimeout(() => { if (host.textContent === message) host.textContent = ''; }, 5000);
  }

  // 内置确认框（.usage-backdrop > .usage-modal 三段式）
  // 复核 PM-6/N3（2026-09-16）：结束进程不可逆，确认按钮改危险色 btn-danger（main.css 既有件），
  // 弹窗由调用方传 danger:true 时生效；普通确认仍用主色。
  function confirmDialog(title, message, confirmText = '确认', cancelText = '取消', { danger = false } = {}) {
    return new Promise(resolve => {
      const backdrop = document.createElement('div');
      backdrop.className = 'usage-backdrop';
      backdrop.innerHTML = `
        <div class="usage-modal" role="dialog" aria-modal="true" aria-labelledby="pmConfirmTitle">
          <div class="usage-header">
            <h2 id="pmConfirmTitle">${escapeHtml(title)}</h2>
            <button class="usage-close" type="button" data-tip="关闭" aria-label="关闭">&times;</button>
          </div>
          <div class="usage-body">${escapeHtml(message).replace(/\n/g, '<br>')}</div>
          <div class="usage-footer">
            <span class="model-picker-spacer"></span>
            <button class="btn btn-secondary" id="pmConfirmCancel" type="button">${escapeHtml(cancelText)}</button>
            <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" id="pmConfirmOk" type="button">${escapeHtml(confirmText)}</button>
          </div>
        </div>`;
      document.body.appendChild(backdrop);

      function cleanup(result) {
        document.removeEventListener('keydown', escHandler);
        backdrop.remove();
        resolve(result);
      }
      function escHandler(e) { if (e.key === 'Escape') cleanup(false); }

      backdrop.querySelector('#pmConfirmOk').addEventListener('click', () => cleanup(true));
      backdrop.querySelector('#pmConfirmCancel').addEventListener('click', () => cleanup(false));
      backdrop.querySelector('.usage-close').addEventListener('click', () => cleanup(false));
      backdrop.addEventListener('click', e => { if (e.target === backdrop) cleanup(false); });
      document.addEventListener('keydown', escHandler);
    });
  }

  let currentProcesses = [];

  function render() {
    const kw = (el('pmSearch') && el('pmSearch').value || '').trim();
    const root = el('pmBody');
    if (window.ProcessTools) {
      window.ProcessTools.renderTree(root, currentProcesses, { onKill, toast, filter: kw });
    }
    const total = (currentProcesses || []).length;
    const cnt = el('pmCount');
    if (cnt) cnt.textContent = total ? `${total} 个进程` : '无进程';
  }

  async function load() {
    try {
      currentProcesses = await window.ProcessTools.fetchProcesses();
    } catch (e) {
      toast('error', '读取进程列表失败：' + e.message);
      currentProcesses = [];
    }
    render();
  }

  // 结束进程（来自 processes.js 渲染的「结束进程 / 结束全部」按钮）
  async function onKill(pids, name, isGroup) {
    // 复核 PM-6/N3（2026-09-16）：确认文案补可执行文件路径（进程管理子窗此前只给名称/PID），
    // 用户能看到「要结束的到底是什么」再确认；分组场景取组内首个有路径的进程。
    let exePath = '';
    for (const pid of (pids || [])) {
      const proc = (currentProcesses || []).find(x => Number(x.Id) === Number(pid));
      const p = String((proc && proc.Path) || '').trim();
      if (p) { exePath = p; break; }
    }
    const pathLine = exePath ? `\n可执行文件：${exePath}` : '';
    const ok = await confirmDialog(
      '结束进程确认',
      isGroup
        ? `即将强制结束应用「${name}」的 ${pids.length} 个进程。${pathLine}\n\n未保存的数据可能丢失，是否继续？`
        : `即将强制结束进程「${name}」（PID ${pids[0]}）。${pathLine}\n\n未保存的数据可能丢失，是否继续？`,
      '结束进程',
      '取消',
      { danger: true }
    );
    if (!ok) return;
    await window.ProcessTools.killProcesses(pids, name, { confirm: null, toast });
    await load();
    reportProgress();
  }

  // 向主窗口推送本次操作后的统计，供「内存清理」页卡片中间区回显
  function reportProgress() {
    const total = (currentProcesses || []).length;
    if (window.api?.processManager?.report) {
      window.api.processManager.report({ totalCount: total, updatedAt: Date.now() });
    }
  }

  function closeWindow() {
    if (window.api?.processManager?.closeWindow) window.api.processManager.closeWindow();
    else window.close();
  }

  // 恒浅色（v2.1：应用固定浅色，不再跟随系统主题；v2.8.0 清理死代码不再 remove theme-dark）
  function applyTheme() {
    document.body.classList.add('theme-light');
  }

  function init() {
    el('pmCloseBtn')?.addEventListener('click', closeWindow);
    el('pmRefreshBtn')?.addEventListener('click', () => load());
    el('pmSearch')?.addEventListener('input', () => render());
    // PM-4（2026-09-15 v7）：确认框打开时 Esc 只关确认框，不再连窗口一起关。
  // 本监听先于 confirmDialog 的 escHandler 注册（脚本初始化序），守卫命中即跳过。
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    if (document.querySelector('.usage-backdrop')) return; // 确认框在开：交给它自己的 escHandler
    closeWindow();
  });
    applyTheme();
    load();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
