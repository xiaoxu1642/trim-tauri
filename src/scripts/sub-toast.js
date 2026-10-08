// sub-toast.js —— 独立子窗口轻量提示共用件（审查 L3 2026-10-01 NEW-6 收敛）
//
// 为什么独立成件而不是委托 window.app.toast：功能子窗**不加载 app.js**（刻意设计，
// 见 process-manager-window.js 头注），window.app
// 在子窗不存在。此前三窗各自复制一份本地 toast（NEW-6：重复实现），现收敛到这里，
// 各窗的 toast() 只剩一行薄委托。两种形态：
//   hintLine：写入窗内既有提示行宿主，按 type 染 token 色，5 秒后内容未变则清空
//             （models-window / process-manager-window 范式）；
//   stack   ：.toast-container + .toast 堆叠，4 秒自动退场（复用 main.css 既有的
//             .toast-container / .toast 件，宿主容器懒创建）。
// 全部 textContent 写入、颜色走 main.css token，与主窗 window.app.toast 口径一致。
// 预览窗的 toast 是单参信息条（pvFileInfo、无自动清除），属第四种最小形态，刻意维持独立。
// 加载序：本文件必须在各窗主脚本之前（与 ds.js 同层，由四份子窗 HTML 显式挂载）。
(function () {
  'use strict';

  var TYPE_COLORS = { error: 'var(--danger)', success: 'var(--success)', warning: 'var(--warning)' };

  // 提示行形态：宿主元素 id 由调用方给定（各窗 HTML 各有一行专属提示位）
  function hintLine(hostId, type, message) {
    var host = document.getElementById(hostId);
    if (!host) return;
    host.textContent = message || '';
    host.style.color = TYPE_COLORS[type] || 'var(--fg-tertiary)';
    if (message) {
      setTimeout(function () {
        if (host.textContent === message) host.textContent = '';
      }, 5000);
    }
  }

  // 堆叠形态：宿主容器缺失时懒创建
  function stack(type, message) {
    if (!message) return;
    var host = document.getElementById('subToastHost');
    if (!host) {
      host = document.createElement('div');
      host.id = 'subToastHost';
      host.className = 'toast-container';
      // P3-1（可达性）：运行时创建的提示容器也要能被读屏播报（主窗那份静态容器已有）
      host.setAttribute('role', 'status');
      host.setAttribute('aria-live', 'polite');
      host.setAttribute('aria-atomic', 'false');
      document.body.appendChild(host);
    }
    var el = document.createElement('div');
    el.className = 'toast ' + (['success', 'error', 'warning', 'info'].indexOf(type) !== -1 ? type : 'info');
    var text = document.createElement('div');
    text.className = 'toast-message';
    text.textContent = String(message);
    el.appendChild(text);
    host.appendChild(el);
    setTimeout(function () {
      el.classList.add('removing');
      setTimeout(function () { el.remove(); }, 300);
    }, 4000);
  }

  window.subToast = { hintLine: hintLine, stack: stack };
})();
