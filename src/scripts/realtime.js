// realtime.js - 实时网速监控模块
// 常驻监控本机网卡上行/下行流量与丢包率，Canvas 双曲线走势图
(function () {
  'use strict';

  // ===== 预留配置项 =====
  const STORAGE_KEY = 'winclean-realtime';   // localStorage 键
  const POLL_INTERVAL = 1500;                // 流量采样轮询间隔(ms)，可调
  const LOSS_INTERVAL = 5000;                // 丢包检测轮询间隔(ms)，可调
  const MAX_POINTS = 60;                     // 图表保留最大数据点数（时间窗口）
  // M2（v3.6.5）M2-2：记录模式采样数组的截断上限（保留最新 N 点，丢弃最老）。
  // 原实现只 push 不裁剪：长时间挂机记录时 recordSamples 会无上限增长（每点一个
  // {t,up,down} 对象，1.5s 一点，挂机一天即数万点常驻内存），且停止记录时对整数组做
  // Math.max(...samples.map(...)) 展开，点数过多会直接抛「Maximum call stack size exceeded」。
  // 7200 点 ≈ 3 小时 @1.5s，覆盖任何真实测速/观测场景，同时把展开量压在调用栈安全区内。
  const MAX_RECORD_POINTS = 7200;

  const $ = id => document.getElementById(id);

  // 复核 N3（测速，2026-09-16）：resize 监听改为具名函数。
  // 原匿名监听在 init 注册后永不解绑，页面多次切入/切出会堆叠监听器（每个闭包持有
  // canvas/state，内存泄漏 + 重复绘制）。
  function onWindowResize() { if (state.running) draw(); }
  // M2（v3.6.5）M2-1：绑定/解绑成对。resize 只在采集运行期间有意义（onWindowResize 内部
  // 也以 state.running 为门），故与 start/stop 同生命周期——离开网络测速页即解绑，
  // 不再常驻整个窗口生命周期。
  let resizeBound = false;
  function bindResize() {
    if (resizeBound) return;
    resizeBound = true;
    window.addEventListener('resize', onWindowResize);
  }
  function unbindResize() {
    if (!resizeBound) return;
    resizeBound = false;
    window.removeEventListener('resize', onWindowResize);
  }

  const state = {
    adapter: '',          // 选中网卡名（空 = 所有活动网卡聚合）
    paused: false,        // 是否暂停采集
    adapters: [],         // 本机网卡列表
    up: 0,                // 当前上传 B/s
    down: 0,              // 当前下载 B/s
    loss: { lossRate: 0, sent: 0, received: 0, latencyMs: 0, gateway: '' },
    history: [],          // [{ t, up, down }]
    running: false,
    sampleTimer: null,
    lossTimer: null,
    mockT: 0,
    lastErrAt: 0,         // 采集失败节流时间戳
    elevationAsked: false, // 是否已提示过提权
    recording: false,     // 是否正在记录网速数据
    recordStart: 0,       // 本次记录开始时间戳
    recordSamples: []     // 本次记录采样 [{ t, up, down }]（上限 MAX_RECORD_POINTS，超出丢最老）
  };

  // ===== 持久化 =====
  function loadStored() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const obj = JSON.parse(raw);
        if (obj && typeof obj === 'object') {
          if (typeof obj.adapter === 'string') state.adapter = obj.adapter;
          if (typeof obj.paused === 'boolean') state.paused = obj.paused;
        }
      }
    } catch (e) {}
  }
  function saveStored() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ adapter: state.adapter, paused: state.paused }));
    } catch (e) {}
  }

  // ===== 工具 =====
  function formatSpeed(bps) {
    if (!isFinite(bps) || bps < 0) bps = 0;
    if (bps >= 1073741824) return (bps / 1073741824).toFixed(2) + ' GB/s';
    if (bps >= 1048576) return (bps / 1048576).toFixed(1) + ' MB/s';
    if (bps >= 1024) return (bps / 1024).toFixed(1) + ' KB/s';
    return Math.round(bps) + ' B/s';
  }

  // 丢包风险等级（复用 绿/黄/红 三色规范）
  function lossRisk(rate) {
    if (!isFinite(rate) || rate <= 0) return { cls: 'low', text: '正常' };
    if (rate < 2) return { cls: 'medium', text: '轻微丢包' };
    return { cls: 'high', text: '严重丢包' };
  }

  function cssVar(name, fallback) {
    try {
      const v = getComputedStyle(document.body).getPropertyValue(name).trim();
      return v || fallback;
    } catch (e) { return fallback; }
  }

  // hex → rgba 填充色（用于曲线下方渐变，跟随强调色）
  function hexToFill(hex, alpha) {
    const m = /^#?([0-9a-f]{6})$/i.exec(String(hex || '').trim());
    if (!m) return hex;
    const n = parseInt(m[1], 16);
    return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
  }

  // ===== 指标卡渲染 =====
  function renderMetrics() {
    const down = $('realtimeDown');
    const up = $('realtimeUp');
    const loss = $('realtimeLoss');
    const risk = $('realtimeLossRisk');
    if (down) down.textContent = formatSpeed(state.down);
    if (up) up.textContent = formatSpeed(state.up);
    if (loss) loss.textContent = (isFinite(state.loss.lossRate) ? state.loss.lossRate : 0).toFixed(1) + '%';
    if (risk) {
      const r = lossRisk(state.loss.lossRate);
      risk.className = 'category-risk ' + r.cls;
      risk.textContent = r.text;
    }
    const detail = $('realtimeLossDetail');
    if (detail) {
      const g = state.loss;
      if (g.gateway) {
        detail.textContent = `网关 ${g.gateway} · 已收 ${g.received}/${g.sent} · 延迟 ${g.latencyMs} ms`;
      } else {
        detail.textContent = '未获取到默认网关，暂无法检测丢包';
      }
    }
  }

  // ===== 网卡枚举 =====
  async function loadAdapters() {
    const sel = $('realtimeAdapter');
    if (!sel) return;
    if (window.api?.realtime) {
      try {
        const resp = await window.api.realtime.adapters();
        if (resp && resp.success) {
          state.adapters = resp.adapters || [];
        } else {
          state.adapters = [];
        }
      } catch (e) {
        state.adapters = [];
      }
    } else {
      // 预览模式模拟网卡
      state.adapters = [
        { name: 'Realtek PCIe GbE Family Controller', connectionName: '以太网', description: 'Realtek PCIe GbE Family Controller', status: 'Up', mac: 'AA:BB:CC:DD:EE:01', linkSpeed: '1000000000' },
        { name: 'Intel(R) Wi-Fi 6 AX200', connectionName: 'WLAN', description: 'Intel(R) Wi-Fi 6 AX200', status: 'Up', mac: 'AA:BB:CC:DD:EE:02', linkSpeed: '866700000' }
      ];
    }
    renderAdapterSelect();
  }

  function renderAdapterSelect() {
    const sel = $('realtimeAdapter');
    if (!sel) return;
    const prev = sel.value || state.adapter;
    const options = ['<option value="">所有活动网卡（聚合）</option>'];
    state.adapters.forEach(a => {
      const label = a.connectionName ? `${a.connectionName}（${a.name}）` : a.name;
      const statusMark = a.status === 'Up' ? '' : '（未连接）';
      options.push(`<option value="${escapeAttr(a.name)}">${escapeHtml(label)}${escapeHtml(statusMark)}</option>`);
    });
    sel.innerHTML = options.join('');
    // 恢复选中：保存的网卡仍存在则保留，否则回退聚合
    const names = state.adapters.map(a => a.name);
    sel.value = names.includes(prev) ? prev : '';
    state.adapter = sel.value;
  }

  function escapeHtml(s) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(s == null ? '' : s).replace(/[&<>"']/g, m => map[m]);
  }
  function escapeAttr(s) {
    return String(s == null ? '' : s).replace(/"/g, '&quot;').replace(/</g, '&lt;');
  }

  // 名称归一化：忽略大小写与空白/下划线/连字符差异，提升跨机器网卡名匹配鲁棒性
  function norm(s) {
    return String(s == null ? '' : s).toLowerCase().replace(/\s+/g, '').replace(/[_\-]/g, '');
  }

  // ===== 采样 =====
  async function tick() {
    if (state.paused) return;
    let up = 0, down = 0;
    if (window.api?.realtime) {
      try {
        const resp = await window.api.realtime.sample();
        if (!resp || !resp.success) throw new Error(resp?.message || '采样失败');
        const list = resp.adapters || [];
        // 流式采样器基线窗口（约 1 秒）内无差值数据：跳过本拍，等待真实速率
        if (!list.length && !resp.t) return;
        if (state.adapter) {
          // 选中的可能为 name 或 connectionName（不同 Windows 计数器命名空间差异），双字段容错匹配
          const sel = state.adapters.find(a => norm(a.name) === norm(state.adapter));
          const accept = sel
            ? [norm(sel.name), norm(sel.connectionName)].filter(Boolean)
            : [norm(state.adapter)];
          const hit = list.find(a => accept.includes(norm(a.name)));
          if (hit) { up = hit.up || 0; down = hit.down || 0; }
          else { up = sum(list, 'up'); down = sum(list, 'down'); }
        } else {
          up = sum(list, 'up'); down = sum(list, 'down');
        }
      } catch (e) {
        handleSampleError(e);
        return;
      }
    } else {
      // 预览模式模拟流量
      state.mockT += POLL_INTERVAL / 1000;
      const phase = state.mockT * 0.6;
      down = (1.4 + Math.sin(phase) * 0.8 + Math.random() * 0.5) * 1048576;
      up = (0.5 + Math.sin(phase * 1.7 + 1) * 0.25 + Math.random() * 0.3) * 1048576;
      down = Math.max(0, down); up = Math.max(0, up);
    }
    state.up = up; state.down = down;
    pushPoint(up, down);
    renderMetrics();
    draw();
  }

  function sum(list, key) {
    return (list || []).reduce((acc, a) => acc + (Number(a[key]) || 0), 0);
  }

  function handleSampleError(err) {
    const now = Date.now();
    // 节流：10 秒内只提示一次，避免刷屏
    if (now - state.lastErrAt > 10000) {
      state.lastErrAt = now;
      window.app?.toast('error', '实时网速采集失败：' + (err?.message || err));
      // 非管理员运行时，采集失败提示提权（仅提示一次）
      if (!state.elevationAsked && window.app?.getState?.()?.isAdmin === false) {
        state.elevationAsked = true;
        setTimeout(() => {
          window.app?.requestElevation?.('实时网速采集失败，可能需要管理员权限。');
        }, 800);
      }
    }
  }

  // ===== 丢包检测 =====
  async function tickLoss() {
    if (state.paused) return;
    if (window.api?.realtime) {
      try {
        const resp = await window.api.realtime.loss();
        if (resp && resp.success) {
          state.loss = {
            lossRate: Number(resp.lossRate) || 0,
            sent: Number(resp.sent) || 0,
            received: Number(resp.received) || 0,
            latencyMs: Number(resp.latencyMs) || 0,
            gateway: resp.gateway || ''
          };
        }
      } catch (e) {
        // 丢包检测失败不阻断流量监控，静默
      }
    } else {
      // 预览模式模拟丢包
      const r = Math.random();
      const rate = r < 0.18 ? (Math.random() * 3) : (Math.random() * 0.4);
      state.loss = { lossRate: rate, sent: 3, received: rate === 0 ? 3 : 2, latencyMs: Math.round(8 + Math.random() * 30), gateway: '192.168.1.1' };
    }
    renderMetrics();
  }

  function pushPoint(up, down) {
    state.history.push({ t: Date.now(), up, down });
    if (state.history.length > MAX_POINTS) state.history.splice(0, state.history.length - MAX_POINTS);
    // 记录模式：同步累积原始全量采样（M2 起受 MAX_RECORD_POINTS 截断，避免长时间记录内存膨胀）
    if (state.recording) {
      state.recordSamples.push({ t: Date.now(), up, down });
      if (state.recordSamples.length > MAX_RECORD_POINTS) {
        state.recordSamples.splice(0, state.recordSamples.length - MAX_RECORD_POINTS);
      }
    }
  }

  // ===== 图表 =====
  function resizeCanvas() {
    const canvas = $('realtimeChart');
    if (!canvas) return null;
    const wrap = canvas.parentElement;
    const dpr = window.devicePixelRatio || 1;
    const w = wrap.clientWidth || 300;
    const h = wrap.clientHeight || 220;
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      canvas.style.width = w + 'px';
      canvas.style.height = h + 'px';
    }
    return { w, h, dpr };
  }

  function niceMax(v) {
    if (v <= 0) return 1024;
    const exp = Math.floor(Math.log10(v));
    const base = Math.pow(10, exp);
    const frac = v / base;
    const nice = frac <= 1 ? 1 : frac <= 2 ? 2 : frac <= 5 ? 5 : 10;
    return nice * base;
  }

  function draw() {
    try {
      drawInner();
    } catch (e) {
      // 绘制异常写入应用日志（节流），便于「日志」页排查图表不显示类问题
      const now = Date.now();
      if (now - (state.lastDrawErrAt || 0) > 10000) {
        state.lastDrawErrAt = now;
        window.app?.log('error', '实时走势图绘制异常: ' + (e?.message || e));
      }
    }
  }

  function drawInner() {
    const canvas = $('realtimeChart');
    if (!canvas) return;
    const dim = resizeCanvas();
    if (!dim) return;
    const ctx = canvas.getContext('2d');
    const { w, h, dpr } = dim;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const gridColor = cssVar('--border-default', 'rgba(0,0,0,0.08)');
    const textColor = cssVar('--fg-tertiary', '#888888');
    const downColor = cssVar('--accent', '#6A59C9');
    const upColor = cssVar('--success', '#16A34A');

    const padL = 56, padR = 12, padT = 10, padB = 22;
    const plotW = w - padL - padR;
    const plotH = h - padT - padB;

    // 空状态
    if (!state.history.length) {
      ctx.fillStyle = textColor;
      ctx.font = '12px "Segoe UI Variable", "Segoe UI", sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('等待采集数据…', w / 2, h / 2);
      return;
    }

    // Y 轴范围（自适应视图缩放）
    let maxVal = 1024;
    state.history.forEach(p => { maxVal = Math.max(maxVal, p.up, p.down); });
    maxVal = niceMax(maxVal * 1.15);

    // 网格 + Y 轴标签
    ctx.textAlign = 'right';
    ctx.font = '10px "Segoe UI Variable", "Segoe UI", sans-serif';
    const gridRows = 4;
    for (let i = 0; i <= gridRows; i++) {
      const y = padT + (plotH * i) / gridRows;
      const val = maxVal * (1 - i / gridRows);
      ctx.strokeStyle = gridColor;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(w - padR, y);
      ctx.stroke();
      ctx.fillStyle = textColor;
      ctx.fillText(formatSpeed(val), padL - 6, y + 3);
    }

    const n = state.history.length;
    const xAt = i => padL + (plotW * i) / Math.max(n - 1, 1);
    const yAt = v => padT + plotH * (1 - Math.min(v, maxVal) / maxVal);

    function drawSeries(key, color, fill) {
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.8;
      ctx.lineJoin = 'round';
      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        const x = xAt(i), y = yAt(state.history[i][key]);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.stroke();
      if (fill) {
        const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
        grad.addColorStop(0, fill);
        grad.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.lineTo(xAt(n - 1), padT + plotH);
        ctx.lineTo(xAt(0), padT + plotH);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();
      }
    }

    // 下载曲线（强调色）+ 上传曲线（绿）
    drawSeries('down', downColor, hexToFill(downColor, 0.18));
    drawSeries('up', upColor, null);

    // X 轴时间标签（首/中/尾）
    ctx.textAlign = 'center';
    ctx.fillStyle = textColor;
    const fmtT = ts => {
      const d = new Date(ts);
      const p = n => String(n).padStart(2, '0');
      return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    };
    const idxs = [0, Math.floor((n - 1) / 2), n - 1];
    idxs.forEach(i => {
      const x = xAt(i);
      ctx.fillText(fmtT(state.history[i].t), x, h - 6);
    });

    // 悬浮标记（若有）
    if (state.hoverIdx != null && state.history[state.hoverIdx]) {
      const x = xAt(state.hoverIdx);
      ctx.strokeStyle = textColor;
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(x, padT);
      ctx.lineTo(x, padT + plotH);
      ctx.stroke();
      ctx.setLineDash([]);
    }
  }

  // ===== 悬浮 tooltip =====
  function onChartMove(e) {
    const canvas = $('realtimeChart');
    const tip = $('realtimeTooltip');
    if (!canvas || !tip) return;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const dpr = window.devicePixelRatio || 1;
    const cw = rect.width;
    if (!state.history.length || cw <= 0) return;
    const idx = Math.round((x / cw) * (state.history.length - 1));
    const clamped = Math.max(0, Math.min(state.history.length - 1, idx));
    state.hoverIdx = clamped;
    const p = state.history[clamped];
    const d = new Date(p.t);
    const pad = n => String(n).padStart(2, '0');
    tip.innerHTML =
      `<div class="rt-tip-time">${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}</div>` +
      `<div class="rt-tip-row"><i class="rt-dot" style="background:var(--accent)"></i>下载 ${formatSpeed(p.down)}</div>` +
      `<div class="rt-tip-row"><i class="rt-dot" style="background:var(--success)"></i>上传 ${formatSpeed(p.up)}</div>`;
    tip.style.display = 'block';
    // 定位：贴近鼠标，避免溢出右边缘
    const tipW = 150;
    let left = x + 14;
    if (left + tipW > cw) left = x - tipW - 14;
    tip.style.left = left + 'px';
    tip.style.top = '8px';
    draw();
  }
  function hideTooltip() {
    const tip = $('realtimeTooltip');
    if (tip) tip.style.display = 'none';
    state.hoverIdx = null;
    draw();
  }

  // ===== 控制 =====
  function start() {
    if (state.running) return;
    state.running = true;
    // 首次进入：加载网卡 + 立即采样
    loadAdapters();
    tick();
    tickLoss();
    state.sampleTimer = setInterval(tick, POLL_INTERVAL);
    state.lossTimer = setInterval(tickLoss, LOSS_INTERVAL);
    // M2（v3.6.5）M2-1：采集运行期间才需要 resize 重绘，随启动绑定
    bindResize();
    updatePauseBtn();
    // 页面刚切入可见时容器尺寸才就绪，下一帧先画空图占位（避免「图表空白」观感）
    requestAnimationFrame(draw);
    const name = state.adapter || '所有活动网卡';
    window.app?.log('info', `实时网速监控启动（网卡：${name}）`);
  }

  function stop() {
    if (!state.running) return;
    state.running = false;
    if (state.sampleTimer) { clearInterval(state.sampleTimer); state.sampleTimer = null; }
    if (state.lossTimer) { clearInterval(state.lossTimer); state.lossTimer = null; }
    // M2（v3.6.5）M2-1：与 start() 的 bindResize 对称解绑，避免监听器随页面切换累积
    unbindResize();
    hideTooltip();
    // 离开页面时若正在记录，自动结束并保存报告，避免数据丢失
    if (state.recording) toggleRecord();
    window.app?.log('info', '实时网速监控停止');
  }

  function togglePause() {
    state.paused = !state.paused;
    saveStored();
    updatePauseBtn();
    if (!state.paused && state.running) {
      tick();
      tickLoss();
    }
    window.app?.log('info', state.paused ? '实时网速监控已暂停' : '实时网速监控已恢复');
  }

  function updatePauseBtn() {
    const btn = $('btnRealtimePause');
    if (!btn) return;
    btn.textContent = state.paused ? '继续' : '暂停';
  }

  function clearChart() {
    state.history = [];
    state.hoverIdx = null;
    // 清空图表同时放弃进行中的记录（不落盘）
    if (state.recording) {
      state.recording = false;
      state.recordSamples = [];
      state.recordStart = 0;
      updateRecordBtn();
      window.app?.toast('info', '正在记录的数据已一并清除');
    }
    hideTooltip();
    draw();
    window.app?.toast('info', '图表历史数据已清空');
  }

  // ==================== 网速记录与报告 ====================
  function updateRecordBtn() {
    const btn = $('btnRealtimeRecord');
    if (!btn) return;
    btn.classList.toggle('recording', state.recording);
    btn.innerHTML = state.recording
      ? '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M6 6h12v12H6z"/></svg> 停止记录'
      : '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M13 2.05v2.02c3.95.5 7 3.86 7 7.93s-3.05 7.43-7 7.93v2.02c5.05-.5 9-4.76 9-9.95s-3.95-9.45-9-9.95zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5v2c-1.66 0-3 1.34-3 3s1.34 3 3 3v2zm-1-8.95V5.05c-3.95.49-7 3.85-7 7.95s3.05 7.46 7 7.95v-2c-2.71-.48-5-2.86-5-5.95s2.29-5.47 5-5.95z"/></svg> 记录数据';
  }

  async function toggleRecord() {
    if (!state.recording) {
      // 开始记录
      state.recording = true;
      state.recordStart = Date.now();
      state.recordSamples = [];
      updateRecordBtn();
      window.app?.toast('success', '开始记录网速，再次点击「停止记录」生成报告');
      // 立即采一个点
      if (state.running) tick();
      return;
    }
    // 停止记录 → 生成并保存报告
    state.recording = false;
    updateRecordBtn();
    const samples = state.recordSamples.slice();
    state.recordSamples = [];
    if (samples.length < 2) {
      window.app?.toast('warning', '记录时间过短，未生成报告');
      return;
    }
    const durationSec = Math.round((samples[samples.length - 1].t - samples[0].t) / 1000);
    const maxDown = Math.max(...samples.map(s => s.down));
    const maxUp = Math.max(...samples.map(s => s.up));
    const minDown = Math.min(...samples.map(s => s.down));
    const minUp = Math.min(...samples.map(s => s.up));
    const avgDown = samples.reduce((a, s) => a + s.down, 0) / samples.length;
    const avgUp = samples.reduce((a, s) => a + s.up, 0) / samples.length;
    const report = {
      createdAt: new Date(samples[0].t).toISOString(),
      adapter: state.adapter || '所有活动网卡（聚合）',
      durationSec,
      maxDown, maxUp, minDown, minUp, avgDown, avgUp,
      samples
    };
    // 保存到缓存目录（7 天自动清理）
    let savedName = '';
    if (window.api?.realtime?.reportSave) {
      try {
        const resp = await window.api.realtime.reportSave(report);
        if (resp && resp.success) savedName = resp.name;
      } catch (e) { /* 保存失败仍可本地预览 */ }
    }
    window.app?.toast('success', savedName ? '网速报告已保存到缓存目录' : '网速报告生成完成');
    window.app?.log('info', `网速记录结束：持续 ${durationSec}s，下载峰值 ${formatSpeed(maxDown)}，上传峰值 ${formatSpeed(maxUp)}`);
    openReportModal(report, savedName);
  }

  // 统计卡 HTML
  function reportStatCard(label, value, accent) {
    return `<div class="rt-stat">
      <span class="rt-stat-label">${label}</span>
      <span class="rt-stat-value" style="color:${accent}">${value}</span>
    </div>`;
  }

  function fmtDuration(sec) {
    sec = Math.max(0, Math.round(sec || 0));
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    const p = n => String(n).padStart(2, '0');
    if (h > 0) return `${h} 时 ${p(m)} 分 ${p(s)} 秒`;
    if (m > 0) return `${m} 分 ${p(s)} 秒`;
    return `${s} 秒`;
  }

  // 折线图：samples 过多时按 canvas 像素聚合
  function drawReportChart(canvas, samples) {
    if (!canvas || !samples || !samples.length) return;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 600;
    const h = canvas.clientHeight || 240;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const gridColor = cssVar('--border-default', 'rgba(0,0,0,0.08)');
    const textColor = cssVar('--fg-tertiary', '#888888');
    const downColor = cssVar('--accent', '#6A59C9');
    const upColor = cssVar('--success', '#16A34A');

    const padL = 56, padR = 12, padT = 10, padB = 22;
    const plotW = w - padL - padR, plotH = h - padT - padB;

    let maxVal = 1024;
    samples.forEach(p => { maxVal = Math.max(maxVal, p.up, p.down); });
    maxVal = niceMax(maxVal * 1.15);

    // 网格 + Y 轴
    ctx.textAlign = 'right';
    ctx.font = '10px "Segoe UI Variable", "Segoe UI", sans-serif';
    for (let i = 0; i <= 4; i++) {
      const y = padT + (plotH * i) / 4;
      ctx.strokeStyle = gridColor;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(w - padR, y);
      ctx.stroke();
      ctx.fillStyle = textColor;
      ctx.fillText(formatSpeed(maxVal * (1 - i / 4)), padL - 6, y + 3);
    }

    const n = samples.length;
    const bucket = Math.max(1, Math.ceil(n / Math.max(plotW, 60)));
    const xs = [];
    for (let i = 0; i < n; i += bucket) {
      let ud = 0, uu = 0;
      for (let j = i; j < Math.min(n, i + bucket); j++) { ud = Math.max(ud, samples[j].down); uu = Math.max(uu, samples[j].up); }
      xs.push({ i, down: ud, up: uu });
    }
    const xAt = idx => padL + (plotW * idx) / Math.max(xs.length - 1, 1);
    const yAt = v => padT + plotH * (1 - Math.min(v, maxVal) / maxVal);

    function series(key, color) {
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.6;
      ctx.lineJoin = 'round';
      ctx.beginPath();
      xs.forEach((p, k) => {
        const x = xAt(k), y = yAt(p[key]);
        if (k === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }
    series('down', downColor);
    series('up', upColor);

    // X 轴：起/中/尾时间
    ctx.textAlign = 'center';
    ctx.fillStyle = textColor;
    const fmtT = ts => {
      const d = new Date(ts);
      const p = n => String(n).padStart(2, '0');
      return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    };
    const first = samples[0].t, last = samples[samples.length - 1].t;
    [[0, first], [xs.length >> 1, first + (last - first) / 2], [xs.length - 1, last]].forEach(([k, ts]) => {
      ctx.fillText(fmtT(ts), xAt(k), h - 6);
    });
  }

  function reportStatBody(report) {
    const avg = (report.durationSec > 0) ? Math.round(report.samples.length / Math.max(report.durationSec, 1) * 100) / 100 : 0;
    return `
      <div class="rt-report-head">
        <div class="rt-report-title">${escapeHtml(report.adapter || '所有活动网卡（聚合）')}</div>
        <div class="rt-report-meta">${escapeHtml(fmtTime(report.createdAt))} · 采样 ${report.samples.length} 个 · 平均 ${avg} 点/秒</div>
      </div>
      <div class="rt-stats-grid">
        ${reportStatCard('持续时间', fmtDuration(report.durationSec), 'var(--accent)')}
        ${reportStatCard('最高下载', formatSpeed(report.maxDown), 'var(--accent)')}
        ${reportStatCard('最高上传', formatSpeed(report.maxUp), 'var(--success)')}
        ${reportStatCard('最低下载', formatSpeed(report.minDown), 'var(--fg-secondary)')}
        ${reportStatCard('最低上传', formatSpeed(report.minUp), 'var(--fg-secondary)')}
        ${reportStatCard('平均下载', formatSpeed(report.avgDown), 'var(--fg-secondary)')}
        ${reportStatCard('平均上传', formatSpeed(report.avgUp), 'var(--fg-secondary)')}
      </div>
      <div class="rt-report-chart">
        <div class="rt-chart-legend">
          <span class="realtime-legend-item"><i class="rt-dot" style="background:var(--accent)"></i>下载</span>
          <span class="realtime-legend-item"><i class="rt-dot" style="background:var(--success)"></i>上传</span>
        </div>
        <canvas class="rt-report-canvas"></canvas>
      </div>`;
  }

  function fmtTime(iso) {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '-';
    const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  // v3.2.0 弹窗统一批次：报告弹窗骨架改由 modal.js 工厂生成（Esc/遮罩/× 关闭统一）
  function openReportModal(report, savedName) {
    closeReportBackdrops();
    const ctrl = window.modal.create({
      id: 'rtReportBackdrop',
      title: '网速记录报告',
      backdropClass: 'rt-report-backdrop',
      modalClass: 'rt-report-modal',
      bodyClass: 'rt-report-body',
      bodyHtml: `
          ${reportStatBody(report)}
          <p class="rt-report-note">${savedName ? '报告已保存至缓存目录 realtime-reports（保留 7 天）。' : '当前环境无法保存，仅展示本次记录。'}</p>`,
      footerHtml: `
          <span class="pw-last-scan"></span>
          <span class="model-picker-spacer"></span>
          <button class="btn btn-primary rt-close-btn" type="button">关闭</button>`
    });
    ctrl.footer.querySelector('.rt-close-btn').addEventListener('click', () => ctrl.close());
    // 渲染图表（等待布局完成）
    requestAnimationFrame(() => {
      const canvas = ctrl.backdrop.querySelector('.rt-report-canvas');
      drawReportChart(canvas, report.samples || []);
    });
  }

  async function openReportsModal() {
    let reports = [];
    if (window.api?.realtime?.reportList) {
      try {
        const resp = await window.api.realtime.reportList();
        if (resp && resp.success) reports = resp.reports || [];
      } catch (e) { /* 忽略 */ }
    }
    closeReportBackdrops();
    const ctrl = window.modal.create({
      id: 'rtReportsBackdrop',
      title: '历史网速报告',
      backdropClass: 'rt-report-backdrop',
      modalClass: 'rt-report-modal',
      bodyClass: 'rt-report-body',
      bodyHtml: `
          ${reports.length ? reports.map(r => `
            <div class="rt-report-row" data-name="${escapeAttr(r.name)}">
              <div class="rt-report-row-main">
                <div class="rt-report-row-title">${escapeHtml(fmtTime(r.createdAt))} · ${escapeHtml(fmtDuration(r.durationSec))}</div>
                <div class="rt-report-row-meta">下载峰值 ${formatSpeed(r.maxDown)} · 上传峰值 ${formatSpeed(r.maxUp)} · ${r.samples ? r.samples.length : 0} 个采样点</div>
              </div>
              <button class="btn btn-secondary btn-small rt-row-open" type="button">查看</button>
              <button class="btn btn-secondary btn-small rt-row-del" type="button">删除</button>
            </div>`).join('') : '<div class="empty-state"><p>暂无记录。点击实时网速页右上角「记录数据」，停止后自动生成报告。</p></div>'}`,
      footerHtml: `
          <span class="pw-last-scan">共 ${reports.length} 份 · 超 7 天自动清理</span>
          <span class="model-picker-spacer"></span>
          <button class="btn btn-secondary rt-clear-all" type="button">清空全部</button>
          <button class="btn btn-primary rt-close-btn" type="button">关闭</button>`
    });
    const backdrop = ctrl.backdrop;
    ctrl.footer.querySelector('.rt-close-btn').addEventListener('click', () => ctrl.close());
    // 查看详情
    backdrop.querySelectorAll('.rt-row-open').forEach(btn => {
      btn.addEventListener('click', () => {
        const row = btn.closest('.rt-report-row');
        const r = reports.find(x => x.name === row.dataset.name);
        if (r) openReportModal(r, r.name);
      });
    });
    // 删除单条
    backdrop.querySelectorAll('.rt-row-del').forEach(btn => {
      btn.addEventListener('click', async () => {
        const row = btn.closest('.rt-report-row');
        if (window.api?.realtime?.reportDelete) await window.api.realtime.reportDelete(row.dataset.name);
        row.remove();
        const cnt = backdrop.querySelectorAll('.rt-report-row').length;
        const foot = backdrop.querySelector('.pw-last-scan');
        if (foot) foot.textContent = cnt ? `共 ${cnt} 份 · 超 7 天自动清理` : '暂无记录';
      });
    });
    // 清空全部
    backdrop.querySelector('.rt-clear-all').addEventListener('click', async () => {
      if (window.api?.realtime?.reportClear) await window.api.realtime.reportClear();
      backdrop.querySelector('.rt-report-body').innerHTML = '<div class="empty-state"><p>已清空全部记录。</p></div>';
      const foot = backdrop.querySelector('.pw-last-scan');
      if (foot) foot.textContent = '共 0 份 · 超 7 天自动清理';
      window.app?.toast('success', '网速报告已全部清空');
    });
  }

  function closeReportBackdrops() {
    // v3.2.0：工厂弹窗关闭即销毁 DOM，此处兜底清理残留在文档中的报告弹窗
    document.querySelectorAll('.rt-report-backdrop').forEach(el => el.remove());
  }

  function init() {
    loadStored();
    const sel = $('realtimeAdapter');
    sel?.addEventListener('change', () => {
      state.adapter = sel.value;
      saveStored();
      const name = state.adapter || '所有活动网卡';
      window.app?.log('info', `切换监控网卡：${name}`);
      if (state.running) { tick(); tickLoss(); }
    });
    $('btnRealtimePause')?.addEventListener('click', togglePause);
    $('btnRealtimeClear')?.addEventListener('click', clearChart);
    $('btnRealtimeRecord')?.addEventListener('click', toggleRecord);
    $('btnRealtimeReports')?.addEventListener('click', openReportsModal);

    const canvas = $('realtimeChart');
    canvas?.addEventListener('mousemove', onChartMove);
    canvas?.addEventListener('mouseleave', hideTooltip);
    // M2（v3.6.5）M2-1：resize 监听改由 start()/stop() 成对开关（原先在 init 里绑定后
    // 永久常驻）。init 只负责首绘，页面未进入时不需响应窗口尺寸变化。

    // 初次绘制空状态
    draw();
    updatePauseBtn();
    updateRecordBtn();
  }

  // M2（v3.6.5）M2-6：统一销毁契约（模块退出语义）。
  // 与 stop() 的区别：stop 只停采集（页面切走即调用），destroy 额外解绑残留的 resize
  // 监听，供窗口/应用级回收时调用；重复调用安全（内部均为幂等判断）。
  function destroy() {
    stop();
    unbindResize();
  }

  window.realtime = { init, start, stop, destroy };
})();
