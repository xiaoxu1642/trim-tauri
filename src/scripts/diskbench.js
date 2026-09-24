// diskbench.js - 磁盘测速模块
// 功能：基准测试、功能解释说明（MD）、历史测试记录管理
(function () {
  'use strict';
  let running = false;
  const MOCK = { sequentialRead: 7021.4, sequentialWrite: 6418.8, randomRead: 1263.7, randomWrite: 874.2, iops: 32350, latency: 0.031 };
  const $ = id => document.getElementById(id);

  function show(data) {
    const values = {
      diskSeqRead: `${Number(data.sequentialRead).toFixed(1)} MB/s`,
      diskSeqWrite: `${Number(data.sequentialWrite).toFixed(1)} MB/s`,
      diskRandomRead: `${Number(data.randomRead).toFixed(1)} MB/s`,
      diskRandomWrite: `${Number(data.randomWrite).toFixed(1)} MB/s`,
      diskIops: `${Math.round(data.iops)} IOPS`,
      diskLatency: `${Number(data.latency).toFixed(3)} ms`
    };
    Object.entries(values).forEach(([id, value]) => { if ($(id)) $(id).textContent = value; });
    if ($('diskBenchStatus')) $('diskBenchStatus').textContent = '测试完成';
  }

  // ==================== 测试执行 ====================
  // 阶段中文名（与后端 __PROG__ phase 对应）
  const PHASE_LABELS = { seqwrite: '顺序写入', seqread: '顺序读取', randread: '4K 随机读取', randwrite: '4K 随机写入' };
  let progressUnsub = null;

  function setProgress(percent, phase) {
    const status = $('diskBenchStatus');
    if (status) status.textContent = `${PHASE_LABELS[phase] || '测试中'}… ${percent}%`;
    const fill = document.getElementById('benchProgressFill');
    if (fill) fill.style.width = Math.max(0, Math.min(100, percent)) + '%';
  }

  function ensureProgressBar() {
    if (document.getElementById('benchProgress')) return;
    const panel = $('diskBenchStatus')?.closest('.benchmark-status-panel');
    if (!panel) return;
    const wrap = document.createElement('div');
    wrap.className = 'bench-progress';
    wrap.id = 'benchProgress';
    wrap.innerHTML = '<div class="bench-progress-fill" id="benchProgressFill"></div>';
    panel.appendChild(wrap);
  }

  function removeProgressBar() { document.getElementById('benchProgress')?.remove(); }

  async function run() {
    if (running) return;
    running = true;
    const button = $('btnDiskBench');
    if (button) button.disabled = true;
    if ($('diskBenchStatus')) $('diskBenchStatus').textContent = '准备测试...';
    ensureProgressBar();
    // 时长仅允许 4/8/16 秒，异常值回落 8 秒
    const rawDuration = Number($('diskDuration')?.value || 8);
    const duration = [4, 8, 16].includes(rawDuration) ? rawDuration : 8;
    const options = {
      path: ($('diskBenchPath')?.value || '').trim(), // 空路径由主进程白名单校验拒绝，不再回落硬编码开发机路径
      blockSize: Number($('diskBlockSize')?.value || 1048576),
      // v3.7.1 R1：QD=每线程在途上限、线程数真实生效（Rust OVERLAPPED 并发）；白名单与主进程一致
      queueDepth: [1, 8, 32].includes(Number($('diskQueueDepth')?.value)) ? Number($('diskQueueDepth').value) : 1,
      threads: [1, 4, 8].includes(Number($('diskThreads')?.value)) ? Number($('diskThreads').value) : 1,
      duration
    };
    // 订阅后端真实进度
    if (window.api?.diskbench?.onProgress) {
      progressUnsub = window.api.diskbench.onProgress(d => {
        if (d && typeof d.percent === 'number') setProgress(d.percent, d.phase);
      });
    }
    try {
      let result = MOCK;
      let engine = '';
      if (window.api?.diskbench) {
        const response = await window.api.diskbench.run(options);
        if (!response.success) throw new Error(response.message);
        result = response.data;
        engine = response.engine || '';
      } else {
        // 演示模式：按 3×duration 模拟进度
        const totalMs = duration * 3 * 1000;
        const started = Date.now();
        while (Date.now() - started < totalMs) {
          await new Promise(r => setTimeout(r, 200));
          const frac = (Date.now() - started) / totalMs;
          const pct = Math.min(99, Math.round(frac * 100));
          const phase = frac < 0.32 ? 'seqwrite' : frac < 0.64 ? 'seqread' : frac < 0.82 ? 'randread' : 'randwrite';
          setProgress(pct, phase);
        }
      }
      show(result);
      if ($('diskBenchStatus')) {
        // 引擎标识：原生 Rust 引擎结果与旧 PowerShell buffered 记录不可直接对比（nobuf 绕过文件系统缓存）
        $('diskBenchStatus').textContent = engine === 'rust' ? '测试完成（原生 Rust 引擎）'
          : engine === 'powershell' ? '测试完成（PowerShell 引擎）' : '测试完成';
      }
      window.app?.toast('success', '磁盘测速完成，测试文件已清理');
      // 保存历史记录
      saveHistoryRecord(result, options, engine);
    } catch (error) {
      if ($('diskBenchStatus')) $('diskBenchStatus').textContent = '测试失败';
      window.app?.toast('error', `磁盘测速失败：${error.message}`);
    } finally {
      running = false;
      if (button) button.disabled = false;
      if (progressUnsub) { progressUnsub(); progressUnsub = null; }
      removeProgressBar();
    }
  }

  // ==================== 历史记录 ====================
  async function saveHistoryRecord(result, options, engine = '') {
    if (!window.api?.benchHistory) return;
    try {
      await window.api.benchHistory.add({
        path: options.path,
        blockSize: options.blockSize,
        queueDepth: options.queueDepth,
        threads: options.threads,
        duration: options.duration,
        sequentialRead: result.sequentialRead,
        sequentialWrite: result.sequentialWrite,
        randomRead: result.randomRead,
        randomWrite: result.randomWrite,
        iops: result.iops,
        latency: result.latency,
        engine: engine || undefined // 仅 rust/powershell，主进程白名单校验
      });
    } catch (e) {
      console.error('保存测速历史失败:', e);
    }
  }

  function formatBlock(size) {
    if (size >= 1048576) return (size / 1048576) + ' MB';
    return (size / 1024) + ' KB';
  }

  function formatTime(iso) {
    try {
      const d = new Date(iso);
      const pad = n => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    } catch (e) { return iso; }
  }

  async function showHistory() {
    if (!window.api?.benchHistory) {
      window.app?.toast('info', '历史记录功能仅在应用模式下可用');
      return;
    }
    // 移除已有弹窗
    closeHistory();
    let records = [];
    try {
      const resp = await window.api.benchHistory.list();
      records = resp.success ? (resp.data || []) : [];
    } catch (e) {
      window.app?.toast('error', '读取历史记录失败: ' + e.message);
      return;
    }

    const backdrop = document.createElement('div');
    backdrop.className = 'preview-backdrop';
    backdrop.id = 'benchHistoryBackdrop';
    backdrop.innerHTML = `
      <div class="preview-modal bench-history-modal">
        <div class="preview-header">
          <div class="preview-header-info">
            <div class="preview-title">历史测试记录</div>
            <div class="preview-count">${records.length} 条记录</div>
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            ${records.length > 0 ? '<button class="btn btn-secondary btn-small" id="benchHistoryClear">清空全部</button>' : ''}
            <button class="preview-close" id="benchHistoryClose" data-tip="关闭">&times;</button>
          </div>
        </div>
        <div class="bench-history-body">
          ${records.length === 0 ? `
            <div class="bench-history-empty">
              <svg viewBox="0 0 24 24" width="48" height="48" fill="currentColor" opacity="0.3"><path d="M13 3c-4.97 0-9 4.03-9 9H1l3.89 3.89.07.14L8.9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42C8.27 19.99 10.51 21 13 21c4.97 0 9-4.03 9-9s-4.03-9-9-9zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg>
              <p>暂无测试记录，完成一次测试后自动保存</p>
            </div>
          ` : `
            <table class="bench-history-table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>测试路径</th>
                  <th>参数</th>
                  <th>顺序读</th>
                  <th>顺序写</th>
                  <th>4K随机读</th>
                  <th>IOPS</th>
                  <th>延迟</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                ${records.map(r => `
                  <tr data-record-id="${r.id}">
                    <td class="bench-history-time">${formatTime(r.timestamp)}</td>
                    <td class="bench-history-path" data-tip="${escapeHtml(r.path || '')}">${escapeHtml(r.path || '--')}</td>
                    <td>${formatBlock(r.blockSize)} / QD${r.queueDepth} / ${r.threads}T / ${r.duration}s${r.engine === 'rust' ? '（原生）' : r.engine === 'powershell' ? '（PS）' : ''}</td>
                    <td class="bench-history-val">${Number(r.sequentialRead).toFixed(1)} MB/s</td>
                    <td class="bench-history-val">${Number(r.sequentialWrite).toFixed(1)} MB/s</td>
                    <td class="bench-history-val">${Number(r.randomRead).toFixed(1)} MB/s</td>
                    <td class="bench-history-val">${Math.round(r.iops)}</td>
                    <td class="bench-history-val">${Number(r.latency).toFixed(3)} ms</td>
                    <td><button class="bench-history-delete" data-delete-id="${r.id}" data-tip="删除此记录">&times;</button></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `}
        </div>
      </div>
    `;
    document.body.appendChild(backdrop);

    $('benchHistoryClose')?.addEventListener('click', closeHistory);
    backdrop.addEventListener('click', e => {
      if (e.target === backdrop) closeHistory();
    });

    // 删除单条记录
    backdrop.querySelectorAll('[data-delete-id]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.deleteId;
        try {
          await window.api.benchHistory.delete(id);
          btn.closest('tr')?.remove();
          const countEl = backdrop.querySelector('.preview-count');
          const remaining = backdrop.querySelectorAll('tbody tr').length;
          if (countEl) countEl.textContent = `${remaining} 条记录`;
          if (remaining === 0) { closeHistory(); setTimeout(showHistory, 100); }
          window.app?.toast('success', '记录已删除');
        } catch (e) {
          window.app?.toast('error', '删除失败: ' + e.message);
        }
      });
    });

    // 清空全部
    $('benchHistoryClear')?.addEventListener('click', async () => {
      const ok = await window.app?.confirm('清空历史记录', '确定要删除全部测试记录吗？此操作不可恢复。', '清空');
      if (!ok) return;
      try {
        await window.api.benchHistory.clear();
        closeHistory();
        setTimeout(showHistory, 100);
        window.app?.toast('success', '历史记录已清空');
      } catch (e) {
        window.app?.toast('error', '清空失败: ' + e.message);
      }
    });
  }

  function closeHistory() {
    document.getElementById('benchHistoryBackdrop')?.remove();
  }

  function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
  }

  // ==================== 功能解释说明（MD 渲染） ====================
  let guideCache = null;

  // 轻量 Markdown 渲染器：标题/粗体/行内代码/表格/列表/引用/分隔线
  function renderMarkdown(md) {
    const lines = md.split(/\r?\n/);
    const html = [];
    let inTable = false;
    let tableRows = [];
    let inList = false;

    function flushTable() {
      if (!inTable) return;
      if (tableRows.length > 0) {
        // 第一行是表头，第二行是分隔线
        const header = tableRows[0];
        const bodyRows = tableRows.slice(2);
        html.push('<table class="guide-table"><thead><tr>' +
          header.map(c => `<th>${c}</th>`).join('') +
          '</tr></thead><tbody>' +
          bodyRows.map(r => '<tr>' + r.map(c => `<td>${c}</td>`).join('') + '</tr>').join('') +
          '</tbody></table>');
      }
      inTable = false;
      tableRows = [];
    }

    function flushList() {
      if (inList) { html.push('</ul>'); inList = false; }
    }

    function inline(text) {
      return escapeHtml(text)
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/`([^`]+)`/g, '<code>$1</code>');
    }

    for (const raw of lines) {
      const line = raw.trimEnd();
      // 表格行
      if (/^\s*\|.*\|\s*$/.test(line)) {
        const cells = line.trim().replace(/^\||\|$/g, '').split('|').map(c => inline(c.trim()));
        if (!inTable) { flushList(); inTable = true; }
        tableRows.push(cells);
        continue;
      }
      flushTable();

      // 分隔线
      if (/^---+\s*$/.test(line)) {
        flushList();
        html.push('<hr class="guide-hr">');
        continue;
      }
      // 标题
      const heading = line.match(/^(#{1,4})\s+(.*)$/);
      if (heading) {
        flushList();
        const level = Math.min(heading[1].length + 2, 6); // # -> h3，## -> h4
        html.push(`<h${level} class="guide-h${level}">${inline(heading[2])}</h${level}>`);
        continue;
      }
      // 引用
      const quote = line.match(/^>\s?(.*)$/);
      if (quote) {
        flushList();
        html.push(`<blockquote class="guide-quote">${inline(quote[1])}</blockquote>`);
        continue;
      }
      // 列表项
      const listItem = line.match(/^[-*]\s+(.*)$/);
      if (listItem) {
        if (!inList) { html.push('<ul class="guide-list">'); inList = true; }
        html.push(`<li>${inline(listItem[1])}</li>`);
        continue;
      }
      flushList();
      // 空行
      if (!line.trim()) continue;
      // 普通段落
      html.push(`<p class="guide-p">${inline(line)}</p>`);
    }
    flushTable();
    flushList();
    return html.join('\n');
  }

  async function showGuide() {
    try {
      if (!guideCache) {
        const resp = await fetch('assets/diskbench-guide.md');
        if (!resp.ok) throw new Error('MD 文件加载失败');
        guideCache = await resp.text();
      }
      // 使用 guide 风格 Toast 展示渲染后的 MD
      const container = document.getElementById('toastContainer');
      if (!container) return;
      const el = document.createElement('div');
      el.className = 'toast info toast-guide toast-bench-guide';
      el.innerHTML = `
        <div class="toast-icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M11 7h2v2h-2zm0 4h2v6h-2zm1-9C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z"/></svg></div>
        <div class="toast-message">
          <div class="toast-title">磁盘测速功能解释说明</div>
          <div class="guide-content">${renderMarkdown(guideCache)}</div>
        </div>
        <button class="toast-close" type="button" aria-label="关闭说明" data-tip="关闭">&times;</button>
      `;
      container.appendChild(el);
      const remove = () => {
        if (el.classList.contains('removing')) return;
        el.classList.add('removing');
        setTimeout(() => el.remove(), 200);
      };
      el.querySelector('.toast-close')?.addEventListener('click', remove);
      // 常驻显示直到用户关闭
    } catch (e) {
      window.app?.toast('error', '加载功能说明失败: ' + e.message);
    }
  }

  function init() {
    $('btnDiskBench')?.addEventListener('click', run);
    $('btnBenchGuide')?.addEventListener('click', showGuide);
    $('btnBenchHistory')?.addEventListener('click', showHistory);

    // 磁盘测速默认路径：自动检测当前用户 Downloads 目录（兼容任何机器/用户）
    // 旧的硬编码路径（如 C:\Users\16076\Downloads）不再使用
    const pathInput = $('diskBenchPath');
    const detectDownloads = () => {
      try {
        if (window.api?.app?.getInfo) {
          window.api.app.getInfo().then(info => {
            const home = info && info.homedir;
            if (home && pathInput) {
              const current = pathInput.value || '';
              if (!current || /16076/.test(current)) {
                pathInput.value = home.replace(/\\+$/, '') + '\\Downloads';
              }
            }
          }).catch(() => {});
        }
      } catch (e) {}
    };
    detectDownloads();
  }
  window.diskbench = { init, run };
})();
