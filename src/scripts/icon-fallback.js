// B2：统一图标兜底。规范：所有图标统一从 src/assets/ico/ 加载（2026-09 目录梳理后唯一图标目录），
// Trim.ico 作为全场景统一兜底图标。进程管理 / 右键管理 / 启动项管理共用本模块，
// Trim.ico 的图标提取只发起一次 IPC 并缓存 dataUrl。
(function () {
  'use strict';
  let fallbackPromise = null;

  // 返回 Promise<string|null>：Trim.ico 的 dataUrl；API 不可用或提取失败时为 null
  function getFallbackUrl() {
    if (!fallbackPromise) {
      fallbackPromise = new Promise(resolve => {
        if (!window.api?.paths?.fileIcon) { resolve(null); return; }
        window.api.paths.fileIcon('src/assets/ico/Trim.ico')
          .then(r => resolve(r && r.success && r.dataUrl ? r.dataUrl : null))
          .catch(() => resolve(null));
      });
    }
    return fallbackPromise;
  }

  // 为容器内所有 [data-icon-fallback] 占位节点应用兜底图标：
  // IMG 节点直接补 src；其它节点（SVG 占位 span 等）替换为同 class 同尺寸的兜底 IMG。
  // 兜底图标提取失败时保持占位节点原样（调用方可自行保留降级展示）。
  async function applyFallbacks(root) {
    if (!root || !root.querySelectorAll) return;
    const targets = root.querySelectorAll('[data-icon-fallback]');
    if (!targets.length) return;
    const url = await getFallbackUrl();
    if (!url) return;
    targets.forEach(node => {
      node.removeAttribute('data-icon-fallback');
      if (node.tagName === 'IMG') {
        node.src = url;
        node.style.display = '';
      } else {
        const size = node.dataset.iconSize || 28;
        const img = document.createElement('img');
        img.src = url;
        img.alt = '';
        img.width = size;
        img.height = size;
        img.className = node.className;
        node.replaceWith(img);
      }
    });
  }

  window.iconFallback = { getFallbackUrl, applyFallbacks };
})();
