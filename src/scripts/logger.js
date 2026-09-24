// logger.js - 日志模块
// 通过 IPC 写入主进程日志文件 + 渲染层显示
(function () {
  'use strict';

  const logViewer = () => document.getElementById('logViewer');

  function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
  }

  function formatLine(line) {
    // 格式: [2026-08-19 11:24:57] [INFO] message
    const m = line.match(/^\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)$/);
    if (!m) return `<div class="log-line"><span class="log-message">${escapeHtml(line)}</span></div>`;
    const [, time, level, message] = m;
    return `<div class="log-line">
      <span class="log-time">${escapeHtml(time)}</span>
      <span class="log-level ${level}">${escapeHtml(level)}</span>
      <span class="log-message">${escapeHtml(message)}</span>
    </div>`;
  }

  async function load() {
    const viewer = logViewer();
    if (!viewer) return;
    if (!window.api?.log) {
      viewer.innerHTML = '<div class="empty-state"><p>日志功能仅在 Electron 环境中可用</p></div>';
      return;
    }
    try {
      const content = await window.api.log.read();
      if (!content.trim()) {
        viewer.innerHTML = '<div class="empty-state"><p>暂无日志记录</p></div>';
        return;
      }
      // 内存优化：仅渲染最近 MAX_LINES 条，避免大日志撑爆 DOM
      const MAX_LINES = 800;
      const lines = content.trim().split('\n');
      const shown = lines.slice(-MAX_LINES).reverse(); // 保持最新在最上
      viewer.innerHTML = shown.map(formatLine).join('') +
        (lines.length > MAX_LINES ? `<div class="log-line"><span class="log-message">…（日志过长，仅显示最近 ${MAX_LINES} 条）</span></div>` : '');
    } catch (e) {
      // 审查 7-7：文本一律转义后插入（与项目「文本 API 一律转义」约束一致）
      viewer.innerHTML = `<div class="empty-state"><p>读取日志失败: ${escapeHtml(e.message)}</p></div>`;
    }
  }

  async function write(level, message) {
    if (window.api?.log) {
      try { await window.api.log.write(level, message); } catch (e) {}
    }
    console[level === 'error' ? 'error' : 'log'](`[${level}] ${message}`);
  }

  async function exportLog() {
    if (!window.api?.log) {
      window.app?.toast('error', '导出功能仅在 Electron 环境中可用');
      return;
    }
    const result = await window.api.log.export();
    if (result.success) {
      window.app?.toast('success', `日志已导出到: ${result.path}`);
    } else if (result.message !== '已取消') {
      window.app?.toast('error', result.message);
    }
  }

  function clear() {
    const viewer = logViewer();
    if (viewer) viewer.innerHTML = '<div class="empty-state"><p>日志已清空</p></div>';
    window.app?.toast('info', '日志显示已清空（实际文件保留在磁盘）');
  }

  window.logger = { load, write, export: exportLog, clear };
})();
