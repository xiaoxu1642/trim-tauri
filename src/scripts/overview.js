// overview.js - 系统体检模块（v2.6.0 P1-6，原「系统概览」升级）
// 实时采集 CPU/内存/磁盘/开机时长，融合硬件信息；新增只读体检诊断
// （借鉴 Pavise SystemAudit：全部只读、每条结论自带证据等级、检测不出如实标「未验证」）
(function () {
  'use strict';

  const POLL_INTERVAL = 2000; // 实时指标轮询间隔(ms)
  const $ = id => document.getElementById(id);

  const state = {
    running: false,
    timer: null,
    hardwareLoaded: false,
    lastErrAt: 0,
    checkupLoaded: false,
    checkupBusy: false
  };

  // ===== 格式化工具 =====
  function fmtBytes(bytes) {
    if (!isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, v = bytes;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i <= 1 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  }
  function fmtPercent(p) { return (isFinite(p) ? Math.round(p) : 0) + '%'; }
  function escapeHtml(s) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(s == null ? '' : s).replace(/[&<>"']/g, m => map[m]);
  }
  // 进度条风险分档：>=90 危险(danger) / >=75 警告(warning) / 否则正常(accent)。
  // 颜色统一由 CSS 根据 data-level 取语义 token，不在 JS 内写死颜色。
  function setBar(id, percent) {
    const bar = $(id);
    if (!bar) return;
    const p = Math.max(0, Math.min(100, Number(percent) || 0));
    bar.style.width = p + '%';
    const level = p >= 90 ? 'danger' : p >= 75 ? 'warning' : 'normal';
    bar.setAttribute('data-level', level);
  }

  // ===== 系统健康度（纯展示层计算，不伪造业务结果）=====
  // 仅基于已有 CPU / 内存 / 系统盘占用；三项数据都缺失时返回 null（界面显示 -- / 待检测）。
  function computeHealth(cpu, memP, diskP) {
    const hasCpu = isFinite(cpu), hasMem = isFinite(memP), hasDisk = isFinite(diskP);
    if (!hasCpu && !hasMem && !hasDisk) return null;
    const c = hasCpu ? cpu : 0, m = hasMem ? memP : 0, dsk = hasDisk ? diskP : 0;
    let score = 100;
    const danger = [], warn = [];
    if (c >= 90) { score -= 25; danger.push('CPU 负载过高'); }
    else if (c >= 70) { score -= 12; warn.push('CPU 占用偏高'); }
    if (m >= 90) { score -= 25; danger.push('内存接近满载'); }
    else if (m >= 75) { score -= 12; warn.push('内存占用偏高'); }
    if (dsk >= 90) { score -= 20; danger.push('系统盘空间不足'); }
    else if (dsk >= 80) { score -= 10; warn.push('系统盘空间偏紧'); }
    score = Math.max(0, Math.min(100, Math.round(score)));
    const level = score < 70 ? 'bad' : score < 85 ? 'warn' : 'good';
    let advice = '状态良好，系统运行流畅';
    if (danger.length) advice = '建议尽快处理：' + danger[0];
    else if (warn.length) advice = '可优化：' + warn[0];
    return { score, level, advice };
  }

  function renderHealth(h, uptime) {
    const adviceEl = $('ovHealthAdvice');
    if (!adviceEl) return;
    // F3（2026-09-15）：此前恒写"状态良好"、丢弃 computeHealth 评分（误导 + 死代码）。
    // 现在如实展示：无数据 → 待检测；有数据 → 按等级着色并显示真实建议。
    const card = $('ovHealthCard');
    if (card) card.classList.remove('health-good', 'health-warn', 'health-bad');
    if (!h) {
      adviceEl.textContent = '待检测';
      if (card) card.classList.add('health-good');
      return;
    }
    adviceEl.textContent = h.advice || '状态良好';
    if (card) {
      const map = { good: 'health-good', warn: 'health-warn', bad: 'health-bad' };
      card.classList.add(map[h.level] || 'health-good');
    }
    const metaHint = $('ovHealthMetaHint');
    if (metaHint) metaHint.textContent = uptime ? ('已运行 ' + uptime) : '';
  }

  // ===== 实时指标渲染 =====
  function renderMetrics(data) {
    const d = data || {};
    const cpu = Number(d.cpu);
    const cpuEl = $('ovCpuValue');
    if (cpuEl) cpuEl.textContent = isFinite(cpu) ? fmtPercent(cpu) : '--';
    setBar('ovCpuBar', isFinite(cpu) ? cpu : 0);
    const cpuSub = $('ovCpuSub');
    if (cpuSub) cpuSub.textContent = (d.processes != null) ? ('进程 ' + d.processes) : '处理器实时负载';

    const mem = d.memory || {};
    const memP = Number(mem.percent);
    const memEl = $('ovMemValue');
    if (memEl) memEl.textContent = isFinite(memP) ? fmtPercent(memP) : '--';
    setBar('ovMemBar', isFinite(memP) ? memP : 0);
    const memSub = $('ovMemSub');
    if (memSub) memSub.textContent = (mem.total > 0) ? (fmtBytes(mem.used) + ' / ' + fmtBytes(mem.total)) : '内存占用';

    const primary = renderDisks(d.disks || []);
    const diskP = primary ? Number(primary.percent) : NaN;
    renderHealth(computeHealth(cpu, memP, diskP), d.uptime);
  }

  // 概览卡片布局：非最大化 2x2（两列两行），最大化一行展示全部
  function applyMaximizedLayout() {
    const metrics = document.querySelector('.overview-metrics');
    if (!metrics) return;
    metrics.classList.toggle('overview-maximized', state.maximized);
  }
  state.maximized = false;
  if (window.api?.window?.onResized) {
    window.api.window.onResized((bounds) => {
      state.maximized = !!(bounds && bounds.maximized);
      applyMaximizedLayout();
    });
  }

  function renderDisks(disks) {
    const valueEl = $('ovDiskValue');
    const labelEl = $('ovDiskLabel');
    const subEl = $('ovDiskSub');
    if (!disks || !disks.length) {
      if (valueEl) valueEl.textContent = '--';
      setBar('ovDiskBar', 0);
      if (labelEl) labelEl.textContent = '磁盘';
      if (subEl) subEl.textContent = '';
      return null;
    }
    // 优先系统盘(通常 C:)，否则取第一个磁盘作为主磁盘
    const primary = disks.find(d => /^c:/i.test(String(d.name || ''))) || disks[0];
    const p = Math.max(0, Math.min(100, Number(primary.percent) || 0));
    if (valueEl) valueEl.textContent = (primary.name || '磁盘') + ' ' + fmtPercent(p);
    if (labelEl) labelEl.textContent = '磁盘';
    if (subEl) subEl.textContent = fmtBytes(primary.used) + ' / ' + fmtBytes(primary.total);
    setBar('ovDiskBar', p);
    return primary;
  }

  // ===== 系统体检（v2.6.0 P1-6，只读诊断） =====
  // 状态徽章复用 ds-badge（ok/warn/bad/neutral），证据等级以文字标签展示。
  // v2.7.0：bad/warn 行加「去处理 / 忽略」——去处理跳对应功能页，忽略持久隐藏（可恢复）。
  const CHECKUP_STATUS_BADGE = { ok: 'ok', warn: 'warn', bad: 'bad', unknown: 'neutral' };
  const CHECKUP_STATUS_TEXT = { ok: '正常', warn: '注意', bad: '异常', unknown: '无法判定' };
  // 去处理跳转映射（跳目标必须是 index.html 导航里的 data-page 键；无应用内处理手段的项不提供）
  const CHECKUP_JUMP = {
    nonessential_services: { page: 'optimizer', tip: '前往电脑优化中心，按需禁用可精简服务' },
    startup_count: { page: 'startup', tip: '前往启动项管理，精简开机自启' },
    sys_drive_free: { page: 'cleanup', tip: '前往磁盘清理，释放系统盘空间' },
    power_plan: { page: 'quickcmds', tip: '前往快捷指令，打开「电源选项」调整计划' }
  };
  const CHECKUP_IGNORE_KEY = 'winclean-checkup-ignored';

  function loadIgnoredChecks() {
    try {
      const v = JSON.parse(localStorage.getItem(CHECKUP_IGNORE_KEY) || '[]');
      return Array.isArray(v) ? v.filter(x => typeof x === 'string') : [];
    } catch (e) { return []; }
  }

  function saveIgnoredChecks(list) {
    try { localStorage.setItem(CHECKUP_IGNORE_KEY, JSON.stringify(list)); } catch (e) {}
  }

  function checkupStatusBadge(status) {
    const type = CHECKUP_STATUS_BADGE[status] || 'neutral';
    const label = CHECKUP_STATUS_TEXT[status] || status;
    return window.ds && window.ds.badgeHtml
      ? window.ds.badgeHtml(type, label, { small: true })
      : `<span class="ds-badge ${type} sm">${escapeHtml(label)}</span>`;
  }

  function renderCheckup(checks) {
    const root = $('ovCheckupList');
    if (!root) return;
    if (!Array.isArray(checks) || !checks.length) {
      root.innerHTML = '<div class="empty-state"><p>本次体检未返回结论。</p></div>';
      return;
    }
    const ignored = new Set(loadIgnoredChecks());
    // 已忽略恢复入口（标题行右侧，仅当存在忽略项时显示）
    const legend = document.querySelector('.checkup-evidence-legend');
    if (legend) {
      const old = document.getElementById('checkupIgnoredRestore');
      if (old) old.remove();
      if (ignored.size > 0) {
        const restore = document.createElement('button');
        restore.type = 'button';
        restore.id = 'checkupIgnoredRestore';
        restore.className = 'btn-link checkup-restore-link';
        restore.dataset.tip = '恢复显示全部已忽略的体检条目';
        restore.textContent = `已忽略 ${ignored.size} 项，点击恢复`;
        restore.addEventListener('click', () => {
          saveIgnoredChecks([]);
          if (lastCheckupChecks) renderCheckup(lastCheckupChecks);
        });
        legend.insertAdjacentElement('afterend', restore);
      }
    }
    // 过滤已忽略；异常 > 注意 > 无法判定 > 正常 排序（问题项优先露出），同档保持主进程返回顺序
    const rank = { bad: 0, warn: 1, unknown: 2, ok: 3 };
    const sorted = checks
      .filter(c => c && c.id && !ignored.has(c.id))
      .sort((a, b) => (rank[a.status] ?? 3) - (rank[b.status] ?? 3));
    if (!sorted.length) {
      root.innerHTML = '<div class="empty-state"><p>全部条目均正常或已被忽略。</p></div>';
      return;
    }
    root.innerHTML = sorted.map(c => {
      const actionable = c.status === 'bad' || c.status === 'warn';
      const jump = CHECKUP_JUMP[c.id];
      const actions = `
          <span class="checkup-row-actions">
            <span class="checkup-row-evidence">${escapeHtml(c.evidence || '未验证')}</span>
            ${jump ? `<button type="button" class="checkup-btn" data-checkup-jump="${escapeHtml(jump.page)}" data-tip="${escapeHtml(jump.tip)}">去处理</button>` : ''}
            <button type="button" class="checkup-btn checkup-btn-ignore" data-checkup-ignore="${escapeHtml(c.id)}" data-tip="不再显示该条目（可随时在标题旁恢复）">忽略</button>
          </span>`;
      return `
      <div class="checkup-row row-card row-card-top" data-status="${escapeHtml(c.status || 'unknown')}">
        <div class="checkup-row-main">
          <div class="checkup-row-head">
            ${checkupStatusBadge(c.status)}
            <span class="checkup-row-title">${escapeHtml(c.title || '')}</span>
            <span class="checkup-row-value">${escapeHtml(c.value || '')}</span>
          </div>
          <p class="checkup-row-detail">${escapeHtml(c.detail || '')}</p>
        </div>
        ${actions}
      </div>`;
    }).join('');
    // 事件绑定：去处理 / 忽略（忽略持久化到 localStorage，重装/清缓存前一直生效）
    root.querySelectorAll('[data-checkup-jump]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const page = btn.dataset.checkupJump;
        if (page && window.app?.switchPage) window.app.switchPage(page);
      });
    });
    root.querySelectorAll('[data-checkup-ignore]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = btn.dataset.checkupIgnore;
        if (!id) return;
        const list = loadIgnoredChecks();
        if (!list.includes(id)) { list.push(id); saveIgnoredChecks(list); }
        renderCheckup(lastCheckupChecks || checks);
      });
    });
  }

  // 最近一次体检原始结果（忽略/恢复后免重扫重渲染）
  let lastCheckupChecks = null;

  async function loadCheckup(force) {
    if (state.checkupBusy) return;
    const root = $('ovCheckupList');
    if (!root) return;
    if (!window.api?.overview?.checkup) {
      // 浏览器预览模式：静态示例，保持布局一致
      lastCheckupChecks = [
        { id: 'cpu_topology', title: 'CPU 拓扑', status: 'ok', value: '8 核 16 线程', detail: '浏览器预览示例数据', evidence: '本机实测' },
        { id: 'memory_channels', title: '内存通道', status: 'warn', value: '1 条 / 16 GB', detail: '单通道运行，建议组双通道（预览示例）', evidence: '本机实测' },
        { id: 'sys_drive_free', title: '系统盘空间', status: 'bad', value: '剩余 8 GB（4%）', detail: '系统盘空间严重不足（预览示例）', evidence: '本机实测' },
        { id: 'disk_health', title: '磁盘健康', status: 'unknown', value: '无法读取', detail: '预览模式下不执行体检', evidence: '未验证' }
      ];
      renderCheckup(lastCheckupChecks);
      return;
    }
    state.checkupBusy = true;
    const btn = $('btnCheckupRerunText');
    if (btn) btn.textContent = '体检中…';
    if (force) root.innerHTML = '<div class="empty-state"><p>体检中…</p></div>';
    try {
      const resp = await window.api.overview.checkup({ refresh: !!force });
      if (!resp || !resp.success) throw new Error((resp && resp.message) || '体检失败');
      lastCheckupChecks = (resp.data && resp.data.checks) || [];
      renderCheckup(lastCheckupChecks);
      state.checkupLoaded = true;
    } catch (e) {
      root.innerHTML = `<div class="empty-state"><p>体检失败：${escapeHtml(e.message)}</p></div>`;
    } finally {
      state.checkupBusy = false;
      if (btn) btn.textContent = '重新体检';
    }
  }

  // ===== 硬件信息（首次扫描缓存，后期手动刷新才更新） =====
  async function loadHardware(force) {
    if (state.hardwareLoaded && !force) return;
    const el = $('ovHardwareRows');
    if (!el) return;
    if (!state.hardwareLoaded || force) el.innerHTML = '<div class="empty-state"><p>加载中...</p></div>';
    try {
      let data = null;
      let cachedAt = null;
      if (window.api?.overview?.hardware) {
        const resp = await window.api.overview.hardware({ refresh: !!force });
        if (!resp.success) throw new Error(resp.message);
        data = resp.data;
        cachedAt = resp.cachedAt || null;
      } else if (window.api?.device) {
        const resp = await window.api.device.scan();
        if (!resp.success) throw new Error(resp.message);
        data = resp.data;
      }
      const normalized = window.deviceinfo ? window.deviceinfo.normalize(data) : {};
      const rows = [
        ['系统', normalized.system], ['处理器', normalized.processor], ['显卡', normalized.graphics],
        ['主板', normalized.motherboard], ['硬盘', normalized.disks], ['显示器', normalized.monitors], ['内存', normalized.memory]
      ];
      if (cachedAt) {
        const t = new Date(cachedAt);
        rows.push(['信息更新于', t.toLocaleString('zh-CN', { hour12: false }) + '（点击刷新可更新）']);
      }
      el.innerHTML = rows.map(([label, value]) =>
        `<div class="device-info-row"><span class="device-info-label">${label}</span><span class="device-info-value">${escapeHtml(value || '--')}</span></div>`
      ).join('');
      state.hardwareLoaded = true;
    } catch (e) {
      el.innerHTML = `<div class="empty-state"><p>硬件信息加载失败：${escapeHtml(e.message)}</p></div>`;
    }
  }

  // ===== 采集 =====
  async function tick() {
    if (window.api?.overview) {
      try {
        const resp = await window.api.overview.metrics();
        if (!resp || !resp.success) throw new Error(resp?.message || '指标采集失败');
        renderMetrics(resp.data);
        if (!state.hardwareLoaded) loadHardware();
      } catch (e) {
        const now = Date.now();
        // 节流：10 秒内只提示一次，避免刷屏
        if (now - state.lastErrAt > 10000) {
          state.lastErrAt = now;
          window.app?.toast('error', '系统指标采集失败：' + (e?.message || e));
        }
      }
    } else {
      // 浏览器预览模式模拟数据
      renderMetrics({
        cpu: Math.round(20 + Math.random() * 40),
        memory: { total: 16 * 1073741824, free: 6 * 1073741824, used: 10 * 1073741824, percent: 62 },
        disks: [
          { name: 'C:', label: '', total: 476 * 1073741824, free: 210 * 1073741824, used: 266 * 1073741824, percent: 56 },
          { name: 'D:', label: '数据', total: 931 * 1073741824, free: 620 * 1073741824, used: 311 * 1073741824, percent: 33 }
        ],
        uptime: '2 天 5 小时 30 分钟',
        processes: 260,
        system: { caption: 'Microsoft Windows 11 专业工作站版', version: '10.0.28000', build: '2525', computerName: 'DESKTOP-XIAOXU', userName: 'xiaoxu' }
      });
      loadHardware();
    }
  }

  // ===== 控制 =====
  function start() {
    if (state.running) return;
    state.running = true;
    state.hardwareLoaded = false;
    applyMaximizedLayout();
    tick();
    // 硬件信息走主进程缓存（毫秒级），立即渲染，避免等首轮指标采集完成才加载
    loadHardware();
    // 系统体检：进页面自动执行一次（主进程 5 分钟缓存，重复进出不重复拉起 PowerShell）
    loadCheckup(false);
    state.timer = setInterval(tick, POLL_INTERVAL);
    window.app?.log('info', '系统体检实时监控启动');
  }

  function stop() {
    if (!state.running) return;
    state.running = false;
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
    window.app?.log('info', '系统体检实时监控停止');
  }

  function refresh() {
    loadHardware(true);
    loadCheckup(true); // 手动刷新强制重新体检
    tick();
  }

  // ==================== 系统信息彩蛋（v3.2.1） ====================
  // 设置页「系统信息」容器已隐藏（main.css #systemInfoSection display:none），
  // 入口改为首页「系统健康度」卡连点 7 次（2 秒窗口）弹出自绘弹窗展示。
  // 信息 DOM（含专家模式开关）整块从隐藏容器移入弹窗、关闭时移回——
  // 节点移动不丢失监听器，开关功能不受影响；数据仍由 app.js loadAppInfo 填充。
  let eggClicks = 0;
  let eggTimer = null;
  let eggModalCtrl = null;

  function openSystemInfoEgg() {
    if (eggModalCtrl) return;
    const infoBody = document.getElementById('systemInfoBody');
    if (!infoBody || !window.modal) {
      window.app?.toast?.('warning', '系统信息暂不可用');
      return;
    }
    eggModalCtrl = window.modal.create({
      id: 'systemInfoEggModal',
      title: '系统信息',
      bodyHtml: '<div class="system-info-egg-mount"></div>',
      footerHtml: `
        <span class="pw-last-scan">开发者信息入口</span>
        <span class="model-picker-spacer"></span>
        <button class="btn btn-primary" data-role="okBtn" type="button">关闭</button>`,
      onClose() {
        // 信息块移回隐藏容器（保持数据填充链路完整，弹窗可反复打开）
        const sec = document.getElementById('systemInfoSection');
        if (sec && infoBody && infoBody.parentElement !== sec) sec.appendChild(infoBody);
        eggModalCtrl = null;
      }
    });
    eggModalCtrl.body.querySelector('.system-info-egg-mount').appendChild(infoBody);
    eggModalCtrl.footer.querySelector('[data-role="okBtn"]').addEventListener('click', () => eggModalCtrl.close());
  }

  function init() {
    $('btnOverviewRefresh')?.addEventListener('click', refresh);
    $('btnCheckupRerun')?.addEventListener('click', () => loadCheckup(true));
    // 概览卡片整卡跳转：内存卡 → 内存清理，磁盘卡 → 磁盘清理（data-jump 指定目标页）
    document.querySelectorAll('.overview-jump-card').forEach(card => {
      const go = () => {
        const page = card.dataset.jump;
        if (page) window.app?.switchPage(page);
      };
      card.addEventListener('click', go);
      // 键盘可达：role=button + tabindex=0，Enter/Space 触发
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); }
      });
    });
    // 系统信息彩蛋：健康度卡 2 秒内连点 7 次
    $('ovHealthCard')?.addEventListener('click', () => {
      eggClicks++;
      clearTimeout(eggTimer);
      eggTimer = setTimeout(() => { eggClicks = 0; }, 2000);
      if (eggClicks >= 7) {
        eggClicks = 0;
        clearTimeout(eggTimer);
        openSystemInfoEgg();
      }
    });
  }

  window.overview = { init, start, stop, refresh };
})();
