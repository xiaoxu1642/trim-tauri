// overview.js - 系统概览模块
// 实时采集 CPU/内存/磁盘/开机时长，融合硬件信息。
// 历史：v2.6.0 曾在此挂「体检结论」只读诊断清单，2026-10-12 用户裁定全链路退役，
// 本文件回归纯实时指标 + 硬件信息展示。
(function () {
  'use strict';

  const POLL_INTERVAL = 2000; // 实时指标轮询间隔(ms)
  const $ = id => document.getElementById(id);

  const state = {
    running: false,
    timer: null,
    busy: false,            // 在途闸门（见 tick 的性能 v3 ④ 注释）
    hardwareLoaded: false,
    lastErrAt: 0
  };

  // ===== 格式化工具 =====
  function fmtBytes(bytes) { return window.ds.fmtBytes(bytes); } // 审查 M18：真源在 ds
  function fmtPercent(p) { return (isFinite(p) ? Math.round(p) : 0) + '%'; }
  function escapeHtml(s) { return window.ds.esc(s); }
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
    // 契约（overview.rs）写明首拍 cpu=null、渲染层显示 `--`；`Number(null)===0`
    // 会把「没有样本」画成「0% 负载」，所以先判 null 再转数字。
    const cpu = d.cpu == null ? NaN : Number(d.cpu);
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
    // 性能 v3 ④：in-flight 闸门。后端 overview_metrics 一旦慢于 POLL_INTERVAL(2000ms)，
    // setInterval 会把未完成的 async 调用一层层叠上去，每叠一份就多一次后端采集 +
    // 多一次 DOM 写（renderMetrics 全量重写卡片）。state 原先只有 running/timer，
    // 没有在途位；busy 由 try/finally 复位，抛错路径也不会把闸门焊死。
    if (state.busy) return;
    state.busy = true;
    try {
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
    } finally {
      state.busy = false;
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
    state.timer = setInterval(tick, POLL_INTERVAL);
    window.app?.log('info', '系统概览实时监控启动');
  }

  function stop() {
    if (!state.running) return;
    state.running = false;
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
    window.app?.log('info', '系统概览实时监控停止');
  }

  function refresh() {
    loadHardware(true);
    tick();
  }

  // ==================== 系统信息彩蛋（v3.2.1） ====================
  // 设置页「系统信息」容器已隐藏（main.css #systemInfoSection display:none），
  // 入口改为首页「系统健康度」卡连点 7 次（2 秒窗口）弹出自绘弹窗展示。
  // 信息 DOM 整块从隐藏容器移入弹窗、关闭时移回（专家模式开关已于 v3.7.0 随默认应用接管整块删除）——
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
