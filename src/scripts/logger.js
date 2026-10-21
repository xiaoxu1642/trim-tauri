// logger.js - 日志模块
(function () {
  'use strict';

  const logViewer = () => document.getElementById('logViewer');

  function escapeHtml(text) { return window.ds.esc(text); }

  function formatLine(line) {
    const m = line.match(/^\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)$/);
    if (!m) return `<div class="log-line"><span class="log-message">${escapeHtml(line)}</span></div>`;
    const [, time, level, message] = m;
    // 审查 L15：level 取自磁盘日志，是全仓唯一未转义就进 class 属性的外部文本 —— 一个引号就能逃出属性
    // 挂上任一 class。白名单比对后原样输出（表外一律退回中性的 log-level 基样式）。
    const levelCls = ['INFO', 'WARN', 'WARNING', 'ERROR', 'DEBUG'].includes(level) ? ` ${level}` : '';
    return `<div class="log-line">
      <span class="log-time">${escapeHtml(time)}</span>
      <span class="log-level${levelCls}">${escapeHtml(level)}</span>
      <span class="log-message">${escapeHtml(message)}</span>
    </div>`;
  }

  // F3-L10 写侧闸。后端的队列与合并窗（engine/log.rs 的 schedule_async_flush）在入队之后才生效，压的是
  // **落盘次数**；log:write 的**调用条数**一条没省（命令体同步、回传整行、返回值被这里丢掉），8192
  // 又只在刷盘失败的回队分支生效。放大源是 ds.js 的
  // 全局 rejection 兜底：每条拒绝直调本函数、自身不限流。窗口内前 QUOTA 条照常直发（顺序不变、零延迟），
  // 超出的按 error / 其余两档计数，在窗口边界与打开日志页时各补一条汇总，原文仍进 console —— 折叠不等于
  // 静默丢审计。
  const WIN_MS = 1000, QUOTA = 60;
  let winStart = 0, winUsed = 0, foldErr = 0, foldOther = 0;

  async function sendToMain(level, message) {
    if (!window.api?.log) return;
    try { await window.api.log.write(level, message); } catch (e) {}
  }

  function flushFolded() {
    const t = '条被限流折叠的渲染层日志未逐条落盘（原文见控制台）';
    if (foldErr) { const n = foldErr; foldErr = 0; sendToMain('error', `${n} ${t}`); }
    if (foldOther) { const n = foldOther; foldOther = 0; sendToMain('warn', `${n} ${t}`); }
  }

  async function write(level, message) {
    const now = Date.now();
    if (now - winStart >= WIN_MS) { flushFolded(); winStart = now; winUsed = 0; }
    if (++winUsed > QUOTA) {
      if (level === 'error') foldErr++; else foldOther++;
    } else {
      await sendToMain(level, message);
    }
    console[level === 'error' ? 'error' : 'log'](`[${level}] ${message}`);
  }

  async function load() {
    const viewer = logViewer();
    if (!viewer) return;
    if (!window.api?.log) {
      // v2-M21：走到这里说明桥未就绪（log:* 通道在本轨存在），不是"Electron 才有"
      viewer.innerHTML = '<div class="empty-state"><p>日志未能加载：本地接口未就绪（window.api 缺失），请重启应用后再试</p></div>';
      return;
    }
    try {
      flushFolded();                 // 汇总行不承诺被这次 read 看见（后端合并窗）
      const content = await window.api.log.read();
      if (!content.trim()) {
        viewer.innerHTML = '<div class="empty-state"><p>暂无日志记录</p></div>';
        return;
      }
      // 仅渲染最近 MAX_LINES 条，避免大日志撑爆 DOM
      const MAX_LINES = 800;
      const lines = content.trim().split('\n');
      const shown = lines.slice(-MAX_LINES).reverse(); // 保持最新在最上
      viewer.innerHTML = shown.map(formatLine).join('') +
        (lines.length > MAX_LINES ? `<div class="log-line"><span class="log-message">…（日志过长，仅显示最近 ${MAX_LINES} 条）</span></div>` : '');
    } catch (e) {
      // 审查 7-7：文本转义后插入
      viewer.innerHTML = `<div class="empty-state"><p>读取日志失败: ${escapeHtml(e.message)}</p></div>`;
    }
  }

  async function exportLog() {
    if (!window.api?.log) {
      window.app?.toast('error', '导出失败：本地接口未就绪（window.api 缺失），请重启应用后再试'); // v2-M21
      return;
    }
    // F3-M05：原生保存框的取消/IO 失败/文件占用走 reject 而非 success=false，旧代码整链静默 ⇒ 失败必须可见
    try {
      const result = await window.api.log.export();
      if (result.success) {
        window.app?.toast('success', `日志已导出到: ${result.path}`);
      } else if (result.message !== '已取消') {
        window.app?.toast('error', result.message);
      }
    } catch (e) {
      window.app?.toast('error', '导出日志失败：' + ((e && e.message) || e));
    }
  }

  function clear() {
    const viewer = logViewer();
    if (viewer) viewer.innerHTML = '<div class="empty-state"><p>日志已清空</p></div>';
    window.app?.toast('info', '日志显示已清空（实际文件保留在磁盘）');
  }

  window.logger = { load, write, export: exportLog, clear };
})();
