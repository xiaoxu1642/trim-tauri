// quickcmds.js - 快捷指令页（63 条系统快捷入口 / 8 分类）
// 数据：quickcmds-data.js（来自 old\快捷指令 解包分析）
// 执行：通过 IPC quickcmds:run 由主进程按白名单 spawn，渲染层不接触命令原文
(function () {
  'use strict';

  let activeCat = '全部';
  let keyword = '';

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // 分类图标与主题色（卡片左侧色块）
  const CAT_META = {
    '系统工具':     { color: '#6366C9', grad: 'linear-gradient(135deg,#8B8EE0,#5B5EC4)', icon: '<path d="M22.7 19l-9.1-9.1c.9-2.3.4-5-1.5-6.9-2-2-5-2.4-7.4-1.3L9 6 6 9 1.6 4.7C.4 7.1.9 10.1 2.9 12.1c1.9 1.9 4.6 2.4 6.9 1.5l9.1 9.1c.4.4 1 .4 1.4 0l2.3-2.3c.5-.4.5-1.1.1-1.4z"/>' },
    '硬件与设备':   { color: '#0EA5E9', grad: 'linear-gradient(135deg,#0EA5E9,#0284C7)', icon: '<path d="M21 2H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h7v2H8v2h8v-2h-2v-2h7c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H3V4h18v12z"/>' },
    '服务与进程':   { color: '#8B5CF6', grad: 'linear-gradient(135deg,#8B5CF6,#7C3AED)', icon: '<path d="M4 8h4V4H4v4zm6 12h4v-4h-4v4zm-6 0h4v-4H4v4zm0-6h4v-4H4v4zm6 0h4v-4h-4v4zm6-10v4h4V4h-4zm-6 4h4V4h-4v4zm6 6h4v-4h-4v4zm0 6h4v-4h-4v4z"/>' },
    '网络':         { color: '#16A34A', grad: 'linear-gradient(135deg,#16A34A,#15803D)', icon: '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>' },
    '程序和功能':   { color: '#D97706', grad: 'linear-gradient(135deg,#D97706,#B45309)', icon: '<path d="M4 8h4V4H4v4zm6 12h4v-4h-4v4zm-6 0h4v-4H4v4zm0-6h4v-4H4v4zm6 0h4v-4h-4v4zm6-10v4h4V4h-4zm-6 4h4V4h-4v4zm6 6h4v-4h-4v4zm0 6h4v-4h-4v4z"/>' },
    '辅助工具':     { color: '#0D9488', grad: 'linear-gradient(135deg,#0D9488,#0F766E)', icon: '<path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14h-4v-2h4v2zm0-4h-4v-2h4v2zm0-4h-4V7h4v2z"/>' },
    '维护与诊断':   { color: '#DC2626', grad: 'linear-gradient(135deg,#DC2626,#B91C1C)', icon: '<path d="M22.7 19l-9.1-9.1c.9-2.3.4-5-1.5-6.9-2-2-5-2.4-7.4-1.3L9 6 6 9 1.6 4.7C.4 7.1.9 10.1 2.9 12.1c1.9 1.9 4.6 2.4 6.9 1.5l9.1 9.1c.4.4 1 .4 1.4 0l2.3-2.3c.5-.4.5-1.1.1-1.4zM6.5 11.5a3 3 0 1 1 0-6 3 3 0 0 1 0 6z"/>' },
    '休眠唤醒排查': { color: '#4F46E5', grad: 'linear-gradient(135deg,#4F46E5,#4338CA)', icon: '<path d="M13 3h-2v10h2V3zm4.83 2.17l-1.42 1.42A6.99 6.99 0 0 1 19 12c0 3.87-3.13 7-7 7s-7-3.13-7-7c0-1.93.78-3.68 2.02-4.94L5.6 5.64A8.96 8.96 0 0 0 3 12a9 9 0 0 0 18 0c0-2.63-1.13-5-2.83-6.66l-1.34.83z"/>' }
  };

  function catIcon(cat) {
    const meta = CAT_META[cat] || CAT_META['系统工具'];
    return `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">${meta.icon}</svg>`;
  }

  function filtered() {
    const data = window.QUICKCMDS_DATA || {};
    const all = data.CMDS || [];
    const kw = keyword.trim().toLowerCase();
    return all.filter(c => {
      if (activeCat !== '全部' && c.cat !== activeCat) return false;
      if (!kw) return true;
      return c.name.toLowerCase().includes(kw) || c.desc.toLowerCase().includes(kw) || c.cat.includes(kw);
    });
  }

  function renderTabs() {
    const el = document.getElementById('qcTabs');
    if (!el) return;
    const data = window.QUICKCMDS_DATA || {};
    const cats = ['全部', ...(data.CATEGORIES || [])];
    const all = data.CMDS || [];
    el.innerHTML = cats.map(c => {
      const n = c === '全部' ? all.length : all.filter(x => x.cat === c).length;
      return `<button class="filter-tab${c === activeCat ? ' active' : ''}" data-qcat="${escapeHtml(c)}">${escapeHtml(c)}<span class="maint-tab-count">${n}</span></button>`;
    }).join('');
    el.querySelectorAll('[data-qcat]').forEach(btn => {
      btn.addEventListener('click', () => {
        activeCat = btn.dataset.qcat;
        renderTabs();
        renderList();
      });
    });
  }

  function renderList() {
    const el = document.getElementById('qcList');
    const countEl = document.getElementById('qcCount');
    if (!el) return;
    const list = filtered();
    if (countEl) countEl.textContent = `${list.length} 项`;

    if (!list.length) {
      el.innerHTML = `<div class="empty-state">
        <div class="empty-state-title">没有匹配的快捷指令</div>
        <div class="empty-state-desc">换个关键字或切换分类试试</div>
      </div>`;
      return;
    }

    el.innerHTML = list.map(c => {
      const meta = CAT_META[c.cat] || CAT_META['系统工具'];
      return `
        <div class="qc-card" data-id="${escapeHtml(c.id)}" data-tip="${escapeHtml(c.cmd)}">
          <div class="qc-icon" style="background:${meta.grad}">${catIcon(c.cat)}</div>
          <div class="qc-body">
            <div class="qc-name">${escapeHtml(c.name)}</div>
            <div class="qc-desc">${escapeHtml(c.desc)}</div>
          </div>
          <div class="qc-actions">
            <button class="btn btn-secondary btn-small" data-qcopy="${escapeHtml(c.id)}" data-tip="复制命令到剪贴板">复制</button>
            <button class="btn btn-primary btn-small" data-qrun="${escapeHtml(c.id)}" data-tip="打开「${escapeHtml(c.name)}」">打开</button>
          </div>
        </div>`;
    }).join('');

    el.querySelectorAll('[data-qrun]').forEach(btn => {
      btn.addEventListener('click', () => runCmd(btn.dataset.qrun));
    });
    el.querySelectorAll('[data-qcopy]').forEach(btn => {
      btn.addEventListener('click', () => copyCmd(btn.dataset.qcopy));
    });
  }

  async function runCmd(id) {
    const item = (window.QUICKCMDS_DATA?.CMDS || []).find(c => c.id === id);
    if (!item) return;
    if (!window.api?.quickCmds?.run) {
      window.app?.toast?.('warning', '浏览器预览模式不支持执行快捷指令');
      return;
    }
    try {
      const resp = await window.api.quickCmds.run(id);
      if (resp?.success) {
        window.app?.toast?.('success', `已打开「${item.name}」`);
        window.logger?.write?.('info', `快捷指令: ${item.name} (${item.cmd})`);
      } else {
        window.app?.toast?.('error', resp?.message || `打开「${item.name}」失败`);
      }
    } catch (e) {
      window.app?.toast?.('error', '执行失败：' + e.message);
    }
  }

  async function copyCmd(id) {
    const item = (window.QUICKCMDS_DATA?.CMDS || []).find(c => c.id === id);
    if (!item) return;
    try {
      await navigator.clipboard.writeText(item.cmd);
      window.app?.toast?.('success', '命令已复制：' + item.cmd);
    } catch (e) {
      window.app?.toast?.('error', '复制失败：' + e.message);
    }
  }

  function init() {
    const search = document.getElementById('qcSearch');
    search?.addEventListener('input', () => {
      keyword = search.value || '';
      renderList();
    });
    renderTabs();
    renderList();
  }

  window.quickcmds = { init };
})();
