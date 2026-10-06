// B2：统一图标兜底。规范：所有图标统一从 src/assets/ico/ 加载（2026-09 目录梳理后唯一图标目录），
// Trim.ico 作为全场景统一兜底图标。进程管理 / 右键管理 / 启动项管理共用本模块。
//
// 取法（2026-10-06 订正）：Trim.ico 随前端产物同源交付（各 HTML 的 favicon 引的就是
// ./assets/ico/Trim.ico），直接用同源 URL 加载即可，**不要走 paths:file-icon**——那条 IPC
// 按文件系统路径 SHGetFileInfo，传入相对路径在生产环境（CWD=安装目录）必然取不到，
// 结果 dataUrl 恒为 null、兜底永远不生效（启动项整页只剩 SVG 地球色块的真机症状）。
// CSP img-src 'self' 放行同源图；缓存的是 URL 字符串，天然只算一次。
(function () {
  'use strict';
  const FALLBACK_ASSET = 'assets/ico/Trim.ico';
  let fallbackUrl = null;

  // 返回 Promise<string>：Trim.ico 的同源 URL（永不失败——文件缺失由 check-assets-used 拦）
  function getFallbackUrl() {
    if (!fallbackUrl) {
      fallbackUrl = new URL(FALLBACK_ASSET, document.baseURI || window.location.href).href;
    }
    return Promise.resolve(fallbackUrl);
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
