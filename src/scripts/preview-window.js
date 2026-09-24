// preview-window.js - 磁盘清理 → 文件清理 → 图片预览 独立窗口
// 由 cleanup.js 的应用内预览弹窗迁移而来：黑色背景居中展示图片，
// 支持缩放 / 旋转 / 上下张导航 / 删除。数据经 preview:data 由主窗口传入，
// 删除图片后通过 preview:image-deleted 通知主窗口刷新文件列表。
// 图片仍以 dataURL 经 window.api.fileclean.readImage 逐张加载。
(function () {
  'use strict';

  let images = [];       // [{filePath, name, size}]
  let index = 0;
  let zoom = 1;
  let rotation = 0;
  let itemName = '图片预览';

  function $id(id) { return document.getElementById(id); }
  function escapeHtml(s) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(s == null ? '' : s).replace(/[&<>"']/g, m => map[m]);
  }
  function formatSize(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, v = bytes;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i <= 1 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  }
  function toast(message) {
    const el = $id('pvFileInfo');
    if (el) el.textContent = message || '';
  }

  function applyTransform() {
    const img = $id('pvImage');
    if (!img) return;
    img.style.transform = `scale(${zoom}) rotate(${rotation}deg)`;
  }

  async function loadImage(i) {
    if (i < 0 || i >= images.length) return;
    index = i;
    zoom = 1;
    rotation = 0;

    const img = $id('pvImage');
    const loading = $id('pvLoading');
    const countEl = $id('pvCount');
    const fileInfoEl = $id('pvFileInfo');
    const zoomLabel = $id('pvZoomLabel');

    if (!img) return;
    img.style.display = 'none';
    loading.style.display = 'flex';
    loading.textContent = '正在加载图片…';

    if (countEl) countEl.textContent = `${index + 1} / ${images.length} 张图片`;
    if (zoomLabel) zoomLabel.textContent = '100%';
    applyTransform();

    const fileData = images[index];
    document.title = `${itemName} · ${fileData.name} (${index + 1}/${images.length})`;
    if (fileInfoEl) {
      fileInfoEl.textContent = `${fileData.name} · ${formatSize(fileData.size)}`;
      fileInfoEl.title = fileData.path || '';
    }

    try {
      if (window.api?.fileclean?.readImage) {
        const resp = await window.api.fileclean.readImage(fileData.path);
        if (resp.success) {
          img.src = resp.data;
          img.style.display = 'block';
          loading.style.display = 'none';
        } else {
          loading.textContent = '加载失败：' + (resp.message || '未知错误');
        }
      } else {
        img.src = `data:image/svg+xml,${encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300"><rect width="400" height="300" fill="#444"/><text x="200" y="150" fill="white" text-anchor="middle" font-size="16">预览模式 - ' + fileData.name + '</text></svg>')}`;
        img.style.display = 'block';
        loading.style.display = 'none';
      }
    } catch (e) {
      loading.textContent = '加载失败：' + e.message;
    }
  }

  function navigatePreview(direction) {
    const target = index + direction;
    if (target >= 0 && target < images.length) loadImage(target);
  }

  async function deleteCurrentImage() {
    const fileData = images[index];
    if (!fileData) return;

    // 审查v4-M5：删除类操作必须红色二次确认；预览窗没有 app.js，直接用 modal.confirm
    // （danger 渲染红色确认键、默认聚焦「取消」），modal.js 缺席时退回原生 confirm，
    // 保证确认链路不因脚本加载顺序中断
    const fileName = String(fileData.path || '').split('\\').pop() || fileData.path;
    let confirmed = false;
    if (window.modal?.confirm) {
      confirmed = await window.modal.confirm({
        title: '删除图片',
        message: `将删除「${fileName}」。\n文件将进入回收站，可在回收站还原。`,
        confirmText: '删除',
        cancelText: '取消',
        danger: true,
        dangerHint: '删除后主窗口的文件列表与容量统计将实时同步刷新。'
      });
    } else {
      confirmed = window.confirm(`将删除「${fileName}」（进入回收站，可在回收站还原）。\n是否继续？`);
    }
    if (!confirmed) return;

    let ok = false;
    try {
      if (window.api?.fileclean?.deleteFile) {
        const resp = await window.api.fileclean.deleteFile(fileData.path);
        ok = !!resp.success;
      } else {
        ok = true; // 浏览器预览模式模拟删除
      }
    } catch (e) {
      ok = false;
    }

    if (!ok) {
      toast('删除失败，请检查文件权限');
      return;
    }

    // 通知主窗口刷新文件列表
    if (window.api?.previewWindow?.notifyDeleted) {
      window.api.previewWindow.notifyDeleted(fileData.path);
    }

    images.splice(index, 1);
    if (images.length > 0) {
      const next = Math.min(index, images.length - 1);
      loadImage(next);
      toast('已删除（可在回收站还原）');
    } else {
      toast('图片已全部删除');
      closeWindow();
    }
  }

  function zoomPreview(delta) {
    zoom = Math.max(0.2, Math.min(5, zoom + delta));
    applyTransform();
    const label = $id('pvZoomLabel');
    if (label) label.textContent = Math.round(zoom * 100) + '%';
  }

  function resetZoom() {
    zoom = 1;
    rotation = 0;
    applyTransform();
    const label = $id('pvZoomLabel');
    if (label) label.textContent = '100%';
  }

  function rotatePreview() {
    rotation = (rotation + 90) % 360;
    applyTransform();
  }

  function closeWindow() {
    if (window.api?.previewWindow?.close) window.api.previewWindow.close();
    else window.close();
  }

  function keyHandler(e) {
    switch (e.key) {
      case 'ArrowLeft': navigatePreview(-1); break;
      case 'ArrowRight': navigatePreview(1); break;
      case 'Escape': closeWindow(); break;
      case '+': case '=': zoomPreview(0.2); break;
      case '-': zoomPreview(-0.2); break;
    }
  }

  function init() {
    $id('pvClose')?.addEventListener('click', closeWindow);
    $id('pvPrev')?.addEventListener('click', () => navigatePreview(-1));
    $id('pvNext')?.addEventListener('click', () => navigatePreview(1));
    $id('pvZoomIn')?.addEventListener('click', () => zoomPreview(0.2));
    $id('pvZoomOut')?.addEventListener('click', () => zoomPreview(-0.2));
    $id('pvZoomReset')?.addEventListener('click', resetZoom);
    $id('pvRotate')?.addEventListener('click', rotatePreview);
    $id('pvDelete')?.addEventListener('click', deleteCurrentImage);
    document.addEventListener('keydown', keyHandler);

    // 接收主窗口传入的图片数据
    window.api?.previewWindow?.onData?.((data) => {
      if (data && Array.isArray(data.images)) {
        images = data.images;
        itemName = data.itemName || '图片预览';
        const start = typeof data.index === 'number' ? data.index : 0;
        loadImage(start);
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();