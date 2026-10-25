// 首帧后空闲挂载「会变的状态面」的 live region（A3-M01 / P2-D 尾巴）。
// 为什么不写进 index.html：首屏预算 2026-10-22 已裁定不再上调（现算余量 < 50 B），
// 本文件走 IDLE_SCRIPTS，字节不计入首屏关键路径。
// 实时数值挂 off：它们每秒/每 2.5 秒刷新，polite 会让读屏持续播报；挂 off 表示
// 「跟随焦点可读、但不主动打断」，状态文字与计数才挂 polite（2026-10-26 小旭拍板）。
(() => {
  const POLITE_HOSTS = [
    // 进度块：宿主挂容器，label/value 是它的子节点，再挂一层会双重播报
    'dupProgressSection',
    'emptyProgressSection',
    'anProgressSection',
    // 计数与摘要
    'totalSize',
    'selectedCount',
    'dupGroupCount',
    'dupSize',
    'emptyCount',
    'emptyDirCount',
    'anTotalSize',
    'anCounts',
    'anElapsed',
    'memRegionCount',
    'optimizerSummary',
    'contextSummary',
    // 状态文字与提示
    'ovHealthCard',
    'ovHealthAdvice',
    'lockQueryResult',
    'startupDefendState',
    'qcCount',
    'cleanupAgeHint',
    'updaterCheckHint',
    'infoCdpState',
  ];
  const LIVE_OFF_HOSTS = [
    'memUseValue',
    'memFreeValue',
    'memPagefileValue',
    'memCacheValue',
    'realtimeDown',
    'realtimeUp',
    'realtimeLossDetail',
    'contextSelectedCount',
  ];
  const mount = (ids, mode) => {
    for (const id of ids) {
      const el = document.getElementById(id);
      if (!el) continue;
      if (mode === 'polite') el.setAttribute('role', 'status');
      el.setAttribute('aria-live', mode);
    }
  };
  mount(POLITE_HOSTS, 'polite');
  mount(LIVE_OFF_HOSTS, 'off');
})();
