// startup.js - 启动项管理模块
// 扫描注册表 Run/RunOnce、启动文件夹、登录/开机计划任务；支持禁用/启用（可逆）与备份后删除
(function () {
  'use strict';

  let items = [];
  let filter = 'all';
  let loading = false;
  // v3.7.0 议题二 P0：缓存来源与年龄（主进程 startup:scan 已回传 cached / cachedAt，
  // 此前渲染层完全没用这两个字段，导致 6 天前的缓存被当成实时数据显示）。
  let cacheInfo = { cached: false, cachedAt: 0 };
  // 幽灵项：上一次展示过的条目在本次真实重扫后不再出现（Run 值/计划任务已被外部删除）
  let ghosts = [];
  // 静默后台重扫在途标记，避免重复触发
  let silentScanning = false;

  const SOURCE_META = {
    registry: { label: '注册表', cls: 'reg', color: 'var(--accent)' },
    folder: { label: '启动文件夹', cls: 'folder', color: '#16A34A' },
    task: { label: '计划任务', cls: 'task', color: '#D97706' }
  };

  function el(id) { return document.getElementById(id); }

  function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
  }

  function truncate(text, len) {
    const s = String(text || '');
    return s.length > len ? s.slice(0, len) + '…' : s;
  }

  function getFiltered() {
    let base;
    if (filter === 'all') base = items;
    else if (filter === 'disabled') base = items.filter(i => !i.enabled);
    else base = items.filter(i => i.source === filter);
    // 幽灵项只在「全部」筛选下置底展示：它已不在当前系统里，不应污染分类/禁用筛选视图，
    // 也不参与顶部计数（计数仍以真实存在的 items 为准）。
    return (filter === 'all' && ghosts.length) ? base.concat(ghosts) : base;
  }

  // ==================== 防恢复机制 ====================
  // 用户禁用启动项后，若连续 3 次扫描发现该项仍被外部程序自动恢复（重新启用），
  // 则自动执行「删除 + 加入防恢复黑名单」；黑名单项再次出现时会被立即自动删除，
  // 从源头阻止程序反复创建该启动项。状态持久化在 localStorage。
  const DEFEND_KEY = 'winclean-startup-defend';     // { 指纹: { name, strikes } }
  const BLACKLIST_KEY = 'winclean-startup-blacklist'; // [指纹...]
  const DEFEND_STRIKES_LIMIT = 3;
  // SU-2（2026-09-15，S7）：防恢复自动删除总开关。原实现扫描到顽固恢复项即
  // 「静默删除 + 拉黑」，用户既无法关闭也无法预知；且用户经 Windows 原生 UI 主动
  // 重新启用会被误计为「外部恢复」。现改为：总开关可关 + 每次自动删除前逐条红色确认。
  const DEFEND_ENABLED_KEY = 'winclean-startup-defend-enabled'; // 总开关（默认开）

  function loadStore(key, fallback) {
    try {
      const v = JSON.parse(localStorage.getItem(key) || '');
      return v == null ? fallback : v;
    } catch (e) { return fallback; }
  }
  function saveStore(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) {}
  }
  function fpOf(item) {
    return [item.source || '', item.name || '', item.command || ''].join('|');
  }

  // SU-2（S7）：防恢复总开关读写 + 开关条 UI 同步
  function isDefendEnabled() { return loadStore(DEFEND_ENABLED_KEY, true) !== false; }
  function setDefendEnabled(v) { saveStore(DEFEND_ENABLED_KEY, !!v); }
  function updateDefendToggleUI() {
    const t = el('startupDefendToggle');
    if (t) t.checked = isDefendEnabled();
    const st = el('startupDefendState');
    if (st) { st.textContent = isDefendEnabled() ? '已开启' : '已关闭'; st.classList.toggle('off', !isDefendEnabled()); }
  }

  // SU-2（S7）：不可逆删除前逐条红色二次确认（modal 对 message 统一转义，可安全内插项名）。
  // 确认/取消、或确认助手缺失均返回 false（视为不删除），保证绝不静默删。
  async function confirmDefendDelete(itemName, reason) {
    if (typeof window.app?.confirmDanger !== 'function') return false;
    try {
      return await window.app.confirmDanger(
        '删除被拦截的启动项',
        `「${itemName}」${reason}\n\n删除后该项将不再随本次扫描保留；若程序再次自行创建，下次扫描将再次提示。是否删除？`,
        '删除',
        '取消',
        '此操作将删除该启动项（不可恢复，删除前请确认无需再随系统启动）'
      );
    } catch (e) { return false; }
  }

  // 扫描完成后调用：黑名单拦截 + 顽固恢复计数升级
  async function enforceStartupDefend() {
    if (!items.length || !window.api?.startup?.remove) return;
    // SU-2：总开关关闭 → 本次扫描只计数提示、不做任何自动删除
    if (!isDefendEnabled()) return;
    const blacklist = loadStore(BLACKLIST_KEY, []);
    const defend = loadStore(DEFEND_KEY, {});
    let changed = false;
    const autoDeleted = [];
    const escalated = [];

    // 1) 黑名单项再次出现（程序重新创建）→ 逐条红色确认后自动删除
    const blItems = items.filter(i => blacklist.includes(fpOf(i)));
    for (const it of blItems) {
      const name = it.name || '未命名';
      // SU-2：删除前逐条确认，取消则本次保留
      const ok = await confirmDefendDelete(name, '已在「防恢复」黑名单中，本次扫描又发现它被重新创建');
      if (!ok) { window.app?.log?.('info', `用户已取消删除黑名单启动项「${name}」`); continue; }
      try {
        await window.api.startup.remove([it]);
        autoDeleted.push(name);
        items = items.filter(i => fpOf(i) !== fpOf(it));
        changed = true;
      } catch (e) { window.app?.log?.('warn', `删除黑名单启动项「${name}」失败: ${e.message}`); /* 保留，下次扫描再次拦截 */ }
    }

    // 2) 被用户禁用的项又被外部恢复 → 累计计数，达到次数后逐条红色确认删除并拉黑
    for (const fp of Object.keys(defend)) {
      const it = items.find(i => fpOf(i) === fp);
      if (!it) continue; // 本扫描未出现
      if (it.enabled) {
        defend[fp] = { name: defend[fp]?.name || it.name || '未命名', strikes: (defend[fp]?.strikes || 0) + 1 };
        if (defend[fp].strikes >= DEFEND_STRIKES_LIMIT) {
          // SU-2：达到阈值后先逐条红色确认，再删除并拉黑；取消则保留计数，下次扫描再提示
          const ok = await confirmDefendDelete(defend[fp].name, `禁用后已连续 ${defend[fp].strikes} 次被外部自动恢复`);
          if (ok) {
            try {
              await window.api.startup.remove([it]);
              if (!blacklist.includes(fp)) blacklist.push(fp);
              escalated.push(defend[fp].name);
              items = items.filter(i => fpOf(i) !== fp);
              changed = true;
              delete defend[fp];
            } catch (e) { window.app?.log?.('warn', `删除顽固恢复启动项「${defend[fp].name}」失败: ${e.message}`); /* 删除失败保留计数，下次扫描再次尝试 */ }
          } else {
            window.app?.log?.('info', `用户已取消删除顽固恢复启动项「${defend[fp].name}」`);
          }
        } else {
          window.app?.log?.('warn', `启动项「${defend[fp].name}」禁用后第 ${defend[fp].strikes} 次被自动恢复（${DEFEND_STRIKES_LIMIT} 次将自动删除并拦截）`);
        }
        changed = true;
      }
    }
    saveStore(BLACKLIST_KEY, blacklist);
    saveStore(DEFEND_KEY, defend);
    if (autoDeleted.length) {
      window.app?.log?.('warn', `防恢复拦截：已自动删除黑名单启动项 ${autoDeleted.join('、')}`);
      window.app?.toast('warning', `防恢复拦截：已自动删除 ${autoDeleted.length} 个被阻止的启动项`);
    }
    if (escalated.length) {
      window.app?.log?.('warn', `防恢复机制：以下启动项连续 ${DEFEND_STRIKES_LIMIT} 次禁用后仍被恢复，已删除并加入黑名单：${escalated.join('、')}`);
      window.app?.toast('warning', `已删除并拦截 ${escalated.length} 个顽固恢复的启动项`);
    }
    if (changed) render();
  }

  // v3.2.1：refresh=false 优先读持久缓存（首启扫描一次落盘，之后一直读文件）；
  // true 强制重新扫描并覆盖缓存。启停/删除/添加后走 true 保证拿到最新状态。
  // CACHE_STALE_MS：缓存被视为"陈旧"的阈值。低于此值不打扰用户（也不触发后台重扫），
  // 高于此值展示年龄横幅并静默后台重扫。
  const CACHE_STALE_MS = 60 * 1000;

  function formatAge(ms) {
    if (!ms || ms < 0) return '未知时间';
    const min = Math.floor(ms / 60000);
    if (min < 1) return '刚刚';
    if (min < 60) return `${min} 分钟`;
    const hour = Math.floor(min / 60);
    if (hour < 24) return `${hour} 小时`;
    const day = Math.floor(hour / 24);
    return day < 30 ? `${day} 天` : `${Math.floor(day / 30)} 个月`;
  }

  function renderCacheBanner() {
    const banner = el('startupCacheBanner');
    if (!banner) return;
    // 仅当"当前屏幕上这批数据来自缓存且已陈旧"时提示；真实扫描后 cached=false 自动隐藏
    const stale = cacheInfo.cached && (Date.now() - (cacheInfo.cachedAt || 0)) >= CACHE_STALE_MS;
    banner.hidden = !stale;
    if (!stale) return;
    const text = el('startupCacheBannerText');
    const btn = el('btnStartupRescanNow');
    const busy = loading || silentScanning;
    if (text) text.textContent = `当前列表数据来自 ${formatAge(Date.now() - (cacheInfo.cachedAt || 0))}前的扫描，可能与系统现状不一致`;
    if (btn) { btn.disabled = busy; btn.textContent = busy ? '正在后台重新扫描…' : '立即重新扫描'; }
  }

  // silent=true：后台静默重扫（无骨架屏、无"扫描完成"Toast），用于消除缓存误导而不打断用户
  async function scan(refresh = false, silent = false) {
    if (loading) return;
    if (!window.api?.startup?.scan) {
      renderError('启动项管理仅在 Electron 环境中可用');
      return;
    }
    loading = true;
    if (silent) silentScanning = true;
    setScanBusy(!silent);
    renderCacheBanner();
    // 阶段二：扫描期间以骨架屏占位（ds.skeletonRows），完成后由 render()/renderError() 替换
    // 缓存命中时主进程立即返回，骨架屏一闪而过不影响体验
    const skeletonList = el('startupList');
    if (skeletonList && window.ds && refresh && !silent) skeletonList.innerHTML = window.ds.skeletonRows(6);
    try {
      const resp = await window.api.startup.scan(refresh);
      if (!resp || !resp.success) {
        // 静默重扫失败不覆盖屏幕上已有的（哪怕是缓存的）数据，只记日志
        if (silent) { window.app?.log?.('warn', `启动项后台重扫失败: ${(resp && resp.message) || '未知原因'}`); return; }
        renderError((resp && resp.message) || '扫描启动项失败');
        return;
      }
      const prevIds = new Set(items.map(i => i.id));
      const next = Array.isArray(resp.data) ? resp.data : [];
      // 按 启用状态 -> 来源 -> 名称 排序，禁用项置底
      next.sort((a, b) => {
        if (!!a.enabled !== !!b.enabled) return a.enabled ? -1 : 1;
        const src = (a.source || '').localeCompare(b.source || '');
        if (src) return src;
        return (a.name || '').localeCompare(b.name || '', 'zh');
      });
      // 幽灵项：本次为真实扫描（非缓存命中）且此前有数据时，凡旧列表有而新列表没有的，
      // 说明它在系统里已不存在（应用卸载 / 任务被删）。此前这类项会照常显示为「启用」，
      // 让用户去禁用一个不存在的目标（实测 YKLauncher、Google/Edge 更新任务即属此列）。
      if ((!resp.cached) && prevIds.size) {
        ghosts = items.filter(i => !next.some(n => n.id === i.id)).map(i => ({ ...i, _ghost: true }));
      } else if (!resp.cached) {
        ghosts = [];
      }
      items = next;
      cacheInfo = { cached: !!resp.cached, cachedAt: resp.cachedAt || (resp.cached ? Date.now() : 0) };
      // 防恢复机制：黑名单拦截 + 顽固恢复计数（可能自动删除并刷新列表）
      await enforceStartupDefend();
      render();
      if (!silent) window.app?.toast('success', `扫描完成，共发现 ${items.length} 项启动项`);
    } catch (e) {
      if (silent) { window.app?.log?.('warn', `启动项后台重扫异常: ${e.message}`); return; }
      renderError(`扫描启动项失败: ${e.message}`);
    } finally {
      loading = false;
      silentScanning = false;
      setScanBusy(false);
      renderCacheBanner();
    }
  }

  // v3.7.0 议题二 P0：进场先拿到缓存（瞬时），若缓存已陈旧则静默后台重扫覆盖。
  // 政策本身未变（仍是"首启扫描一次后读缓存"），只是不再让缓存冒充实时数据。
  async function load() {
    await scan(false);
    if (cacheInfo.cached && (Date.now() - (cacheInfo.cachedAt || 0)) >= CACHE_STALE_MS && !loading) {
      void scan(true, true);
    }
  }

  function setScanBusy(busy) {
    const btn = el('btnScanStartup');
    if (!btn) return;
    btn.disabled = busy;
    if (busy) {
      btn.dataset.orig = btn.innerHTML;
      btn.innerHTML = '扫描中…';
    } else if (btn.dataset.orig) {
      btn.innerHTML = btn.dataset.orig;
      delete btn.dataset.orig;
    }
  }

  function render() {
    const enabledCount = items.filter(i => i.enabled).length;
    const disabledCount = items.length - enabledCount;
    el('startupTotal').textContent = items.length;
    el('startupEnabled').textContent = enabledCount;
    el('startupDisabled').textContent = disabledCount;
    el('startupListCount').textContent = `${items.length} 项`;

    const listEl = el('startupList');
    const filtered = getFiltered();
    // 真实项为空但仍有幽灵项时，也要把幽灵项渲染出来（否则用户看不到"它们已消失"这条信息）
    if (!items.length && !ghosts.length) {
      listEl.innerHTML = window.emptyState
        ? window.emptyState({ icon: 'search', title: '尚未扫描启动项', desc: '扫描将检测启动文件夹、注册表 Run 键与计划任务中的开机自启项目', cta: { text: '立即扫描', target: 'btnScanStartup' } })
        : '<div class="empty-state"><p>点击右上角「扫描启动项」开始检测</p></div>';
      return;
    }
    if (!filtered.length) {
      listEl.innerHTML = window.emptyState
        ? window.emptyState({ icon: 'box', title: '当前筛选下没有启动项', desc: '尝试切换上方筛选条件，或重新扫描启动项' })
        : '<div class="empty-state"><p>当前筛选下没有启动项</p></div>';
      return;
    }

    listEl.innerHTML = filtered.map(i => {
      const meta = SOURCE_META[i.source] || SOURCE_META.registry;
      // v3.7.0 议题二 P0：幽灵项（缓存里还在、本次真实重扫后系统中已消失）单独着色，
      // 且不再给「禁用/启用/删除」按钮——目标已不存在，操作必然失败或误导。
      if (i._ghost) {
        const ghostBadge = window.ds
          ? window.ds.badgeHtml('danger', '已从系统消失', { small: true })
          : '<span class="startup-badge ghost">已从系统消失</span>';
        const gLoc = i.location || (SOURCE_META[i.source] || SOURCE_META.registry).label;
        return `
        <div class="startup-item ghost" data-id="${escapeHtml(i.id)}" data-ghost="1">
          <span class="startup-check" aria-hidden="true"></span>
          <div class="startup-item-icon ${meta.cls}">
            <svg class="startup-item-glyph" viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
          </div>
          <div class="startup-item-info">
            <div class="startup-item-title">${escapeHtml(i.name || '未命名')} ${ghostBadge}</div>
            <div class="startup-item-meta">${escapeHtml(gLoc)} · 本次扫描已不再出现该项，可能已被卸载或删除</div>
          </div>
          <div class="startup-item-ops"></div>
        </div>`;
      }
      // v3.7.0 议题二 P2：徽章从两态扩到四态——让「谁禁的」可见。
      // 此前只有「启用 / 已禁用」，被任务管理器禁用的项与被 Trim 禁用的项长得一样，
      // 用户无法判断该去哪里改回来。
      let badge;
      if (i.enabled) {
        badge = window.ds ? window.ds.badgeHtml('ok', '启用', { small: true }) : '<span class="startup-badge on">启用</span>';
      } else if (i.disabledBy === 'trim') {
        badge = window.ds ? window.ds.badgeHtml('warn', '已由 Trim 禁用', { small: true }) : '<span class="startup-badge off">已由 Trim 禁用</span>';
      } else if (i.disabledBy === 'system') {
        badge = window.ds ? window.ds.badgeHtml('warn', '已由系统禁用', { small: true }) : '<span class="startup-badge off">已由系统禁用</span>';
      } else {
        badge = window.ds ? window.ds.badgeHtml('warn', '已禁用', { small: true }) : '<span class="startup-badge off">已禁用</span>';
      }
      const cmd = i.command || '';
      const loc = i.location || meta.label;
      const pub = i.publisher ? `<span class="startup-item-pub" data-tip="发布者">${escapeHtml(i.publisher)}</span>` : '';
      const cmdHtml = cmd
        ? `<div class="startup-item-cmd" data-tip="${escapeHtml(cmd)}">${escapeHtml(truncate(cmd, 120))}</div>`
        : '';
      const locPath = i.resolvedPath || i.filePath || '';
      const locBtn = locPath
        ? `<button class="btn btn-small btn-opt-loc" data-id="${escapeHtml(i.id)}" data-path="${escapeHtml(locPath)}" data-tip="打开文件所在位置">位置</button>`
        : '';
      return `
        <div class="startup-item ${i.enabled ? '' : 'disabled'}" data-id="${escapeHtml(i.id)}">
          <input type="checkbox" class="startup-check startup-item-check" data-id="${escapeHtml(i.id)}" aria-label="选择 ${escapeHtml(i.name || '未命名')}">
          <div class="startup-item-icon ${meta.cls}">
            <svg class="startup-item-glyph" viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
            <img class="startup-item-icon-img" alt="" width="18" height="18" data-icon-path="${escapeHtml(locPath)}" hidden>
          </div>
          <div class="startup-item-info">
            <div class="startup-item-title">${escapeHtml(i.name || '未命名')} ${badge}</div>
            ${cmdHtml}
            <div class="startup-item-meta">${escapeHtml(loc)}${pub}</div>
          </div>
          <div class="startup-item-ops">
            ${locBtn}
            ${i.enabled
              ? `<button class="btn btn-small btn-opt-toggle off" data-id="${escapeHtml(i.id)}" data-act="disable" data-tip="禁用（可逆）">禁用</button>`
              : `<button class="btn btn-small btn-opt-toggle on" data-id="${escapeHtml(i.id)}" data-act="enable" data-tip="重新启用">启用</button>`}
            <button class="btn btn-small btn-opt-del" data-id="${escapeHtml(i.id)}" data-act="delete" data-tip="备份后删除">删除</button>
          </div>
        </div>`;
    }).join('') + `
      <div class="startup-list-ops">
        <button class="btn btn-secondary btn-small" id="btnStartupDisableBulk">禁用所选</button>
        <button class="btn btn-secondary btn-small" id="btnStartupEnableBulk">启用所选</button>
        <button class="btn btn-danger btn-small" id="btnStartupDeleteBulk">删除所选</button>
      </div>`;

    // B2：有路径的项提取真实程序图标，失败或无路径时统一兜底为 Trim.ico
    applyStartupIcons(listEl);
  }

  // 启动项图标异步应用：优先 fileIcon(项路径)，失败回退 Trim.ico（icon-fallback 共享缓存）；
  // 图标都不可用时保留源类型 SVG 色块作为降级展示。
  async function applyStartupIcons(container) {
    if (!container || !window.iconFallback || !window.api?.paths?.fileIcon) return;
    const imgs = container.querySelectorAll('.startup-item-icon-img');
    if (!imgs.length) return;
    const fallbackUrl = await window.iconFallback.getFallbackUrl();
    imgs.forEach(img => {
      if (img.dataset.iconDone) return;
      img.dataset.iconDone = '1';
      const p = img.getAttribute('data-icon-path');
      const show = (url) => {
        if (!url) return;
        img.src = url;
        img.hidden = false;
        const glyph = img.parentElement && img.parentElement.querySelector('.startup-item-glyph');
        if (glyph) glyph.style.display = 'none';
      };
      if (p) {
        window.api.paths.fileIcon(p)
          .then(r => show(r && r.success && r.dataUrl ? r.dataUrl : fallbackUrl))
          .catch(() => show(fallbackUrl));
      } else {
        show(fallbackUrl);
      }
    });
  }

  function renderError(msg) {
    el('startupTotal').textContent = '-';
    el('startupEnabled').textContent = '-';
    el('startupDisabled').textContent = '-';
    el('startupListCount').textContent = '0 项';
    el('startupList').innerHTML = `<div class="empty-state"><p>${escapeHtml(msg)}</p></div>`;
  }

  function getSelected() {
    const checked = Array.from(el('startupList').querySelectorAll('.startup-item-check:checked'));
    const ids = checked.map(c => c.dataset.id);
    const filtered = getFiltered();
    const sel = items.filter(i => filtered.some(f => f.id === i.id) && ids.includes(i.id));
    return sel;
  }

  function updateBatchButtons() {
    const sel = getSelected();
    const hasEnable = sel.some(i => !i.enabled);
    const hasDisable = sel.some(i => i.enabled);
    el('btnStartupDisable').disabled = !hasDisable;
    el('btnStartupEnable').disabled = !hasEnable;
    el('btnStartupDelete').disabled = !sel.length;
  }

  async function doToggle(selItems, enable) {
    if (!selItems.length) return;
    const act = enable ? '启用' : '禁用';
    const ok = await window.app.confirm(
      `${act}启动项`,
      `将${act}以下 ${selItems.length} 个启动项：\n${selItems.map(i => '· ' + i.name).join('\n')}\n\n${enable ? '（启用后该项将随系统启动运行）' : '（禁用后可随时重新启用，操作可逆）'}`,
      act,
      '取消'
    );
    if (!ok) return;
    try {
      const resp = await window.api.startup.toggle(selItems, enable);
      // 复核 N2（提权半闭环，2026-09-16）：HKLM/所有用户项未提权时服务端回传 needAdmin，
      // 此前只报部分失败、无提权入口；现在弹提权确认（对齐 runtimes 范式）
      if (resp && resp.needAdmin) {
        const elevated = await window.app?.requestElevation?.(`${act}这些启动项需要管理员权限（写入 HKLM 或所有用户范围）。`);
        if (elevated) window.app?.toast('info', '已获得管理员权限，请重新执行本操作');
        return;
      }
      const failed = resp && resp.failed ? resp.failed : 0;
      if (resp && resp.success) {
        window.app?.toast('success', `${act}完成，成功 ${resp.success || 0} 项`);
      } else {
        window.app?.toast('warning', `${act}部分失败：${failed} 项未生效`);
      }
      const failedIds = new Set((resp && resp.results || []).filter(r => r.status === 'error').map(r => r.id));
      // 防恢复跟踪：禁用成功 → 记录指纹；手动启用成功 → 清除跟踪
      if (!enable) {
        const defend = loadStore(DEFEND_KEY, {});
        selItems.forEach(i => {
          const r = (resp && resp.results || []).find(x => x.id === i.id);
          if (!r || r.status !== 'error') {
            const fp = fpOf(i);
            defend[fp] = { name: i.name || '未命名', strikes: defend[fp]?.strikes || 0 };
          }
        });
        saveStore(DEFEND_KEY, defend);
      } else {
        const defend = loadStore(DEFEND_KEY, {});
        selItems.forEach(i => { delete defend[fpOf(i)]; });
        saveStore(DEFEND_KEY, defend);
      }
      // 刷新：成功的项状态变更后重扫；失败项标记
      if (failedIds.size) {
        items.forEach(i => { if (failedIds.has(i.id)) i._flag = 'error'; });
        render();
      } else {
        await scan(true);
      }
    } catch (e) {
      window.app?.toast('error', `${act}失败: ${e.message}`);
    }
  }

  async function doDelete(selItems) {
    if (!selItems.length) return;
    // 删除类操作：规范要求红色二次确认
    const ok = await window.app.confirmDanger(
      '删除启动项',
      `将删除以下 ${selItems.length} 个启动项（删除前会自动备份）：\n${selItems.map(i => '· ' + i.name).join('\n')}`,
      '删除',
      '取消',
      '此操作不可逆，删除后需重新配置才能恢复。'
    );
    if (!ok) return;
    try {
      const resp = await window.api.startup.remove(selItems);
      // 复核 N2：提权半闭环收口（同 doToggle）
      if (resp && resp.needAdmin) {
        const elevated = await window.app?.requestElevation?.('删除这些启动项需要管理员权限（写入 HKLM 或所有用户范围）。');
        if (elevated) window.app?.toast('info', '已获得管理员权限，请重新执行删除');
        return;
      }
      if (resp && resp.success) {
        window.app?.toast('success', `删除完成，成功 ${resp.success || 0} 项`);
      } else {
        window.app?.toast('warning', `删除部分失败：${(resp && resp.failed) || 0} 项未生效`);
      }
      await scan(true);
    } catch (e) {
      window.app?.toast('error', `删除失败: ${e.message}`);
    }
  }

  async function openLocation(targetPath) {
    if (!targetPath) return;
    try {
      const resp = await window.api.startup.openLocation(targetPath);
      if (!resp || !resp.success) {
        window.app?.toast('warning', (resp && resp.message) || '打开位置失败');
      }
    } catch (e) {
      window.app?.toast('error', `打开位置失败: ${e.message}`);
    }
  }

  // ==================== 启动项简介 ====================
  // 点击行内「简介」按钮 → 弹窗展示本地内置简介；
  // 联网 AI 简介不会自动请求，需用户再次点击面板中的「获取AI简介」才调用所选大模型。
  // v3.2.0 弹窗统一批次：骨架改由 modal.js 工厂生成（原手写 backdrop 重复打开会留双实例、无焦点陷阱）
  function showIntro(item) {
    const sourceLabel = (item.source && SOURCE_META[item.source] ? SOURCE_META[item.source].label : '') || item.location || '';
    const ctrl = window.modal.create({
      id: 'startupIntroBackdrop',
      title: item.name || '未命名',
      bodyHtml: `
        <div class="startup-intro-meta">启动项 · ${escapeHtml(sourceLabel)}${item.publisher ? ' · ' + escapeHtml(item.publisher) : ''}</div>
        <div data-role="introMount"></div>`,
      bodyClass: 'startup-intro-body',
      footerHtml: `
        <span class="model-picker-spacer"></span>
        <button class="btn btn-primary" data-role="closeBtn" type="button">关闭</button>`,
      footerClass: 'startup-intro-footer'
    });
    ctrl.modal.classList.add('startup-intro-modal');
    ctrl.footer.querySelector('[data-role="closeBtn"]').addEventListener('click', () => ctrl.close());

    const mount = ctrl.body.querySelector('[data-role="introMount"]');
    if (window.intro?.mountIntroPanel) {
      window.intro.mountIntroPanel({ mount, scope: 'startup', name: item.name, company: item.publisher || '', item });
    } else {
      mount.innerHTML = '<div class="empty-state"><p>简介模块未加载</p></div>';
    }
  }

  async function addItem() {
    if (!window.api?.startup?.add) return;
    try {
      const resp = await window.api.startup.add();
      if (!resp) return;
      if (resp.canceled) return;
      if (!resp.success) {
        window.app?.toast('error', (resp && resp.message) || '添加启动项失败');
        return;
      }
      window.app?.toast('success', `已添加启动项：${resp.name || ''}`);
      await scan(true);
    } catch (e) {
      window.app?.toast('error', `添加启动项失败: ${e.message}`);
    }
  }

  function init() {
    // SU-2（S7）：防恢复总开关——关闭后只计数提示、不自动删除
    const defendToggle = el('startupDefendToggle');
    if (defendToggle) {
      defendToggle.checked = isDefendEnabled();
      defendToggle.addEventListener('change', () => {
        setDefendEnabled(defendToggle.checked);
        updateDefendToggleUI();
        window.app?.toast(defendToggle.checked ? 'success' : 'info', defendToggle.checked ? '已开启防恢复自动删除' : '已关闭防恢复自动删除，被拦截启动项将不再自动删除');
      });
    }
    updateDefendToggleUI();
    // 「重新扫描」= 强制真实扫描并覆盖缓存（v3.2.1 缓存政策）
    el('btnScanStartup')?.addEventListener('click', () => scan(true));
    // v3.7.0 议题二 P0：缓存年龄横幅上的一键重扫入口（与右上角按钮同一条真实扫描路径）
    el('btnStartupRescanNow')?.addEventListener('click', () => scan(true));
    el('btnAddStartup')?.addEventListener('click', () => addItem());
    el('startupSelectAll')?.addEventListener('change', (e) => {
      el('startupList').querySelectorAll('.startup-item-check').forEach(c => {
        c.checked = e.target.checked;
      });
      updateBatchButtons();
    });
    // 顶部批量按钮
    el('btnStartupDisable')?.addEventListener('click', () => doToggle(getSelected(), false));
    el('btnStartupEnable')?.addEventListener('click', () => doToggle(getSelected(), true));
    el('btnStartupDelete')?.addEventListener('click', () => doDelete(getSelected()));
    // 列表内事件委托（筛选变更后列表会重新渲染）
    el('startupList')?.addEventListener('click', (e) => {
      const locBtn = e.target.closest('.btn-opt-loc');
      if (locBtn) {
        openLocation(locBtn.dataset.path);
        return;
      }
      const delBtn = e.target.closest('.btn-opt-del');
      if (delBtn) {
        const item = items.find(i => i.id === delBtn.dataset.id);
        if (item) doDelete([item]);
        return;
      }
      const togBtn = e.target.closest('.btn-opt-toggle');
      if (togBtn) {
        const item = items.find(i => i.id === togBtn.dataset.id);
        if (item) doToggle([item], togBtn.dataset.act === 'enable');
        return;
      }
      const bulkBtn = e.target.closest('#btnStartupDisableBulk, #btnStartupEnableBulk, #btnStartupDeleteBulk');
      if (bulkBtn) {
        const sel = getSelected();
        if (bulkBtn.id === 'btnStartupDisableBulk') doToggle(sel, false);
        else if (bulkBtn.id === 'btnStartupEnableBulk') doToggle(sel, true);
        else if (bulkBtn.id === 'btnStartupDeleteBulk') doDelete(sel);
        return;
      }
      // 点击条目主体（非按钮/复选框区域）→ 弹出详细简介（含本地简介 + 联网 AI 简介）
      if (!e.target.closest('button, input, label')) {
        const row = e.target.closest('.startup-item');
        if (row) {
          const item = items.find(i => i.id === row.dataset.id);
          if (item) showIntro(item);
        }
      }
    });
    // 复选框变化 -> 更新批量按钮
    el('startupList')?.addEventListener('change', (e) => {
      if (e.target.classList.contains('startup-item-check')) updateBatchButtons();
    });
    // 筛选标签
    el('startupFilter')?.addEventListener('click', (e) => {
      const tab = e.target.closest('.filter-tab');
      if (!tab) return;
      el('startupFilter').querySelectorAll('.filter-tab').forEach(t => t.classList.toggle('active', t === tab));
      filter = tab.dataset.filter;
      el('startupSelectAll').checked = false;
      render();
    });
  }

  // load：进场读缓存 → 缓存陈旧则静默后台重扫（v3.7.0 议题二 P0）
  window.startup = { init, load };
})();
