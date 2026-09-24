// netspeed.js - 网络测速模块（外部网站测速 + 本机流量检测耦合）
// 流量监测状态机：
//   idle      等待流量活动（页面加载会产生零散流量）
//   loading   首次检测到流量活动后强制等待 ≥8 秒，确保测速网页完全加载启动
//   armed     等待期结束后监听「大额流量迸发」（下载/上传瞬时速率越过迸发阈值）
//   recording 确认测速开始，持续记录上下行速率与网关延迟采样
//   recording 中先识别上传阶段，再以短窗口内上传速率骤降 5-10 MB/s 判定结束
//             并弹出自绘带宽报告（上传/下载/延迟三指标曲线可视化）。
// 设计动机：页面加载流量（图片/广告/脚本）易被误判为测速流量，8 秒加载等待 + 迸发
// 阈值双重过滤可显著降低误触发；延迟数据复用「实时网速」的网关 ping 通道。
(function () {
  'use strict';

  let loaded = false;

  // ==================== 测速流量检测状态 ====================
  // 通过监控网卡流量间接感知外嵌测速站点何时开始/结束（跨域下无法读 iframe 内部）
  let detectTimer = null;       // 采样定时器句柄
  let rec = null;              // 本次测速采样记录

  // 阈值与时长
  const SPIKE_BPS = 256 * 1024;   // 256 KB/s：活动判定阈值（方向任一越过即视为「有流量活动」）
  const BURST_BPS = 1024 * 1024;  // 1 MB/s：大额流量迸发阈值（确认测速真正开始）
  const PAGE_SETTLE_MS = 8000;    // 检测到流量活动后至少等待 8 秒，确保网页完全加载启动
  const POLL_MS = 800;            // 流量采样间隔
  const LATENCY_MS = 2000;        // 延迟采样间隔（recording 阶段）
  let tickInFlight = false;

  function sum(list, key) {
    return (list || []).reduce((acc, a) => acc + (Number(a[key]) || 0), 0);
  }

  // 聚合所有活动网卡的实时速率（与「实时网速」共用同一采样通道，避免重复常驻监控）
  async function sampleAgg() {
    if (!window.api?.realtime) return { up: 0, down: 0 };
    try {
      const resp = await window.api.realtime.sample();
      if (!resp || !resp.success) return { up: 0, down: 0 };
      const list = resp.adapters || [];
      return { up: sum(list, 'up'), down: sum(list, 'down') };
    } catch (e) {
      return { up: 0, down: 0 };
    }
  }

  // 延迟采样：ping 默认网关（复用 realtime:loss 通道），失败不中断测速记录
  async function sampleLatency() {
    if (!window.api?.realtime?.loss) return null;
    try {
      const resp = await window.api.realtime.loss();
      if (resp && resp.success && Number.isFinite(resp.latencyMs)) return resp.latencyMs;
      return null;
    } catch (e) {
      return null;
    }
  }

  // 单位换算：bytes/s -> 可读字符串
  function fmtSpeed(bps) {
    const v = Number(bps) || 0;
    if (v >= 1024 * 1024) return (v / 1024 / 1024).toFixed(2) + ' MB/s';
    if (v >= 1024) return (v / 1024).toFixed(1) + ' KB/s';
    return Math.round(v) + ' B/s';
  }
  function toMbps(bps) { return ((Number(bps) || 0) * 8 / 1e6).toFixed(1); }

  function setStatus(text) {
    const s = document.getElementById('externalTestSource');
    if (s) s.textContent = text;
  }

  // ==================== 视图切换（实时图表 ↔ 测速网页） ====================
  function showChartView() {
    const rt = document.getElementById('realtimeView');
    const tv = document.getElementById('externalTestView');
    if (rt) rt.style.display = '';
    if (tv) tv.style.display = 'none';
  }

  function showTestView() {
    const rt = document.getElementById('realtimeView');
    const tv = document.getElementById('externalTestView');
    if (rt) rt.style.display = 'none';
    if (tv) tv.style.display = '';
  }

  // ==================== 测速过程流量检测（状态机） ====================
  // M2（v3.6.5）M2-3：detectTimer 生命周期核对——唯一创建点是 beginDetect()，
  // 且其首行先 stopDetect() 复位（不会叠加定时器）。清理路径：finishDetect（测速结束）、
  // loadExternalTest（换站点/重载）、站点 change 处理器、window.netspeed.stop()
  // （离开网络测速页时由 app.js 调用）。即「创建前必先清、离开页面必清」，无遗留定时器。
  function stopDetect() {
    if (detectTimer) { clearInterval(detectTimer); detectTimer = null; }
    tickInFlight = false;
    rec = null;
  }

  function beginDetect() {
    stopDetect();
    const site = document.getElementById('externalTestSite');
    const label = site?.selectedOptions?.[0]?.textContent || 'SpeedTest.cn（推荐）';
    rec = {
      label,
      phase: 'idle',        // idle -> loading -> armed -> recording
      phaseSince: 0,        // 当前阶段进入时间
      startTime: null,      // recording 开始时间（即迸发确认时间）
      endTime: null,
      maxDown: 0, maxUp: 0,
      samples: [],          // [{ t, down, up, latency }]
      lastLatencyAt: 0,
      endReason: '',
      endDetector: window.netSpeedDetection?.createUploadEndDetector?.() || null
    };
    setStatus('测速流量检测已启动：请在下方网页内点击「开始测速」，软件将在页面加载完成后自动记录实测带宽…');
    detectTimer = setInterval(() => { void detectTick(); }, POLL_MS);
  }

  function enterPhase(phase) {
    rec.phase = phase;
    rec.phaseSince = Date.now();
  }

  async function detectTick() {
    if (!rec || tickInFlight) return;
    tickInFlight = true;
    const currentRec = rec;
    const { up, down } = await sampleAgg();
    if (!rec || rec !== currentRec) {
      tickInFlight = false;
      return;
    }
    const active = down > SPIKE_BPS || up > SPIKE_BPS;
    const burst = down > BURST_BPS || up > BURST_BPS;

    switch (currentRec.phase) {
      case 'idle':
        // 等待阶段：任何流量活动（网页开始加载）即进入 8 秒加载等待
        if (active) {
          enterPhase('loading');
          setStatus('检测到页面流量活动，等待网页完全加载（至少 8 秒）…');
        }
        break;

      case 'loading': {
        // 加载等待期：确保 ≥8 秒，期间若出现持续大流量迸发也提前确认（站点秒开场景）
        const waited = Date.now() - currentRec.phaseSince;
        if (burst && waited >= 3000) {
          startRecording(down, up);
        } else if (waited >= PAGE_SETTLE_MS) {
          enterPhase('armed');
          setStatus('网页加载完成，正在监听大额流量迸发（请在网页内点击「开始测速」）…');
        }
        break;
      }

      case 'armed':
        // 监听迸发：大额流量出现 → 确认测速开始
        if (burst) {
          startRecording(down, up);
        }
        break;

      case 'recording': {
        // 记录阶段：采样点 + 峰值 + 周期性延迟采样
        const now = Date.now();
        const t = now - currentRec.startTime;
        const point = { t, down, up, latency: null };
        currentRec.samples.push(point);
        currentRec.maxDown = Math.max(currentRec.maxDown, down);
        currentRec.maxUp = Math.max(currentRec.maxUp, up);
        if (t - currentRec.lastLatencyAt >= LATENCY_MS) {
          currentRec.lastLatencyAt = t;
          sampleLatency().then(l => { if (l != null) point.latency = l; });
        }

        // 结束只观察上传通道，避免下载与上传两个阶段之间的短暂停顿造成提前结束。
        // 阈值会按近期上传峰值在 5-10 MB/s 内自适应，并要求连续两个采样周期确认。
        const endState = currentRec.endDetector?.update({ time: now, elapsed: t, up });
        if (endState?.uploadStartedNow) {
          setStatus('已进入上传测速阶段，正在等待上传速率明显回落后自动结束…');
        }
        if (endState?.finish) {
          finishDetect(endState.reason);
        }
        break;
      }
    }
    tickInFlight = false;
  }

  function startRecording(down, up) {
    enterPhase('recording');
    rec.startTime = Date.now();
    rec.maxDown = down; rec.maxUp = up;
    rec.lastLatencyAt = 0;
    rec.endDetector?.update({ time: rec.startTime, elapsed: 0, up });
    setStatus('已确认大额流量迸发，正在记录实测速率与延迟…');
  }

  function finishDetect(reason) {
    if (!rec) return;
    rec.endTime = Date.now();
    rec.endReason = reason || '';
    const done = rec;
    stopDetect();
    // 测速流量结束：自动关闭网页，切回实时图表并展示本次测速结果
    showChartView();
    showReport(done);
  }

  // ==================== 测速报告弹窗（自绘） ====================
  // 测速结果保存至历史记录（复用实时网速报告存储：7 天自动清理）
  async function saveToHistory(r) {
    if (!window.api?.realtime?.reportSave || !r.samples.length) return false;
    const downs = r.samples.map(s => s.down);
    const ups = r.samples.map(s => s.up);
    try {
      const resp = await window.api.realtime.reportSave({
        createdAt: new Date(r.startTime || Date.now()).toISOString(),
        adapter: `测速站点：${r.label}`,
        durationSec: Math.round((r.endTime - r.startTime) / 1000),
        maxDown: r.maxDown, maxUp: r.maxUp,
        minDown: Math.min(...downs), minUp: Math.min(...ups),
        avgDown: downs.reduce((a, b) => a + b, 0) / downs.length,
        avgUp: ups.reduce((a, b) => a + b, 0) / ups.length,
        samples: r.samples.map(s => ({ t: (r.startTime || 0) + s.t, down: s.down, up: s.up }))
      });
      return !!(resp && resp.success);
    } catch (e) {
      return false;
    }
  }

  function showReport(r) {
    const durationSec = r.startTime ? Math.round((r.endTime - r.startTime) / 1000) : 0;
    // 延迟统计（仅统计有效采样）
    const lats = r.samples.filter(s => Number.isFinite(s.latency) && s.latency > 0).map(s => s.latency);
    const avgLat = lats.length ? Math.round(lats.reduce((a, b) => a + b, 0) / lats.length) : null;
    const minLat = lats.length ? Math.round(Math.min(...lats)) : null;
    // 异步保存历史记录，弹窗内提示保存结果
    let saved = false;
    saveToHistory(r).then(ok => {
      saved = ok;
      const note = document.getElementById('nsReportSaveNote');
      if (note) note.textContent = ok ? '本次测速结果已保存至历史记录（可在「查看报告」中查看，保留 7 天）。' : '本次测速结果未能保存到历史记录。';
    });
    const latStat = `
      <div class="rt-stat"><span class="rt-stat-label">平均延迟</span><span class="rt-stat-value" style="color:var(--warning,#E6A23C)">${avgLat != null ? avgLat + ' ms' : '—'}</span><span class="rt-stat-meta">${minLat != null ? '最低 ' + minLat + ' ms · 采样 ' + lats.length + ' 次' : '未获取到延迟采样'}</span></div>`;
    const body = `
      <div class="rt-report-head">
        <div class="rt-report-title">实测带宽（本机网卡流量采样）</div>
        <div class="rt-report-meta">测速站点：${escapeHtml(r.label)} · 测速耗时：${durationSec} 秒 · 采样 ${r.samples.length} 个 · 上传阶段结束</div>
      </div>
      <div class="rt-stats-grid">
        <div class="rt-stat"><span class="rt-stat-label">最大下载速率</span><span class="rt-stat-value" style="color:var(--accent)">${fmtSpeed(r.maxDown)}</span><span class="rt-stat-meta">约 ${toMbps(r.maxDown)} Mbps</span></div>
        <div class="rt-stat"><span class="rt-stat-label">最大上传速率</span><span class="rt-stat-value" style="color:var(--success)">${fmtSpeed(r.maxUp)}</span><span class="rt-stat-meta">约 ${toMbps(r.maxUp)} Mbps</span></div>
        ${latStat}
      </div>
      <div class="rt-report-chart">
        <div class="rt-chart-legend">
          <span class="realtime-legend-item"><i class="rt-dot" style="background:var(--accent)"></i>下载</span>
          <span class="realtime-legend-item"><i class="rt-dot" style="background:var(--success)"></i>上传</span>
          <span class="realtime-legend-item"><i class="rt-dot" style="background:var(--warning,#E6A23C)"></i>延迟(ms)</span>
        </div>
        <canvas class="rt-report-canvas" id="nsReportCanvas"></canvas>
      </div>
      <p class="rt-report-note" id="nsReportSaveNote">${saved ? '本次测速结果已保存至历史记录（可在「查看报告」中查看，保留 7 天）。' : '正在保存本次测速结果到历史记录…'}</p>`;

    const ctrl = window.modal?.create ? window.modal.create({
      id: 'nsReportModal',
      title: '带宽测速报告',
      bodyHtml: body,
      footerHtml: '',
      modalClass: 'rt-report-modal',
      width: 680
    }) : null;
    if (!ctrl) return;
    const canvas = document.getElementById('nsReportCanvas');
    if (canvas && r.samples.length > 1) drawReportChart(canvas, r.samples);
  }

  function drawReportChart(canvas, samples) {
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth || 620, H = canvas.clientHeight || 240;
    canvas.width = W * dpr; canvas.height = H * dpr;
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    // 速率（左轴）与延迟（右轴）独立归一化
    let maxSpd = 0, maxLat = 0;
    samples.forEach(p => {
      maxSpd = Math.max(maxSpd, p.down, p.up);
      if (Number.isFinite(p.latency) && p.latency > 0) maxLat = Math.max(maxLat, p.latency);
    });
    if (maxSpd <= 0) return;
    const pad = 8;
    const maxT = samples[samples.length - 1].t || 1;
    const x = t => pad + ((W - pad * 2) * t / maxT);
    const ySpd = v => H - pad - ((H - pad * 2) * Math.min(1, v / maxSpd));
    const yLat = v => H - pad - ((H - pad * 2) * Math.min(1, v / (maxLat || 1)));

    // 网格基线
    ctx.strokeStyle = 'rgba(128,128,128,.25)';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
      const gy = pad + (H - pad * 2) * i / 4;
      ctx.beginPath(); ctx.moveTo(pad, gy); ctx.lineTo(W - pad, gy); ctx.stroke();
    }
    ctx.strokeStyle = 'rgba(128,128,128,.35)';
    ctx.beginPath(); ctx.moveTo(pad, H - pad); ctx.lineTo(W - pad, H - pad); ctx.stroke();

    function series(getVal, getY, color, dashed) {
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      if (dashed) ctx.setLineDash([4, 3]); else ctx.setLineDash([]);
      ctx.beginPath();
      let started = false;
      samples.forEach(p => {
        const v = getVal(p);
        if (!Number.isFinite(v)) return;   // 延迟采样缺失点跳过（虚线断点）
        const px = x(p.t), py = getY(v);
        if (!started) { ctx.moveTo(px, py); started = true; } else ctx.lineTo(px, py);
      });
      ctx.stroke();
      ctx.setLineDash([]);
    }

    series(p => p.down, ySpd, getCssColor('--accent', '#7C86F2'), false);
    series(p => p.up, ySpd, getCssColor('--success', '#34D399'), false);
    if (maxLat > 0) series(p => p.latency, yLat, getCssColor('--warning', '#E6A23C'), true);
  }

  // 读取 CSS 变量实际色值（canvas 不支持 var()，需解析 computed style）
  function getCssColor(name, fallback) {
    try {
      const v = getComputedStyle(document.body).getPropertyValue(name).trim();
      return v || fallback;
    } catch (e) { return fallback; }
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[c]));
  }

  // ==================== 加载外部测速站点 ====================
  function loadExternalTest(withDetect) {
    const frame = document.getElementById('externalTestFrame');
    const site = document.getElementById('externalTestSite');
    const source = document.getElementById('externalTestSource');
    if (!frame || !site) return;
    const selectedUrl = site.value || 'https://www.speedtest.cn/';
    const selectedLabel = site.selectedOptions?.[0]?.textContent || 'SpeedTest.cn（推荐）';
    // 点击「开始测速」：自动从实时图表切换为测速网页
    if (withDetect) showTestView();
    frame.src = selectedUrl;
    if (source) source.textContent = `数据来源：${selectedLabel}，仅加载所选测试站点`;
    loaded = true;
    // 每次加载即进入流量检测模式（如已有旧检测先复位）
    stopDetect();
    if (withDetect) beginDetect();
  }

  function init() {
    // 默认展示实时网络图表视图
    showChartView();
    const site = document.getElementById('externalTestSite');
    // 切换站点：仅在已加载过测速页时刷新，未点击开始测速前不访问网页
    site?.addEventListener('change', () => {
      if (loaded) {
        stopDetect();
        loadExternalTest(false);
      }
    });
    document.getElementById('btnExternalTest')?.addEventListener('click', () => loadExternalTest(true));
    document.getElementById('btnRefreshTest')?.addEventListener('click', () => {
      if (loaded) loadExternalTest(false);
      else window.app?.toast('info', '尚未开始测速，请先点击「开始测速」加载测速网页');
    });
  }

  // 离开本页时回收资源：停止流量采样并卸载 iframe，避免外部测速页在后台持续占用内存/CPU
  function stop() {
    stopDetect();
    const frame = document.getElementById('externalTestFrame');
    if (frame && frame.src && !frame.src.startsWith('about:')) frame.src = 'about:blank';
    showChartView();
  }

  // M2（v3.6.5）M2-6：统一销毁契约。本模块不持有常驻 window 级监听（站点/按钮监听挂在
  // 静态 DOM 节点上，节点随文档存活），destroy 等价于 stop()，重复调用安全。
  function destroy() {
    stop();
  }

  window.netspeed = { init, loadExternalTest, stop, destroy };
})();
