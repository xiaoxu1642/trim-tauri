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

  // P1-6E①：档位外回落可以，但必须当场留一句告警跟着回执走。旧写法
  // `[1,8,32].includes(Number(v)) ? Number(v) : 1` 把「用户选了个不在档里的值」折成
  // 「他选了 1」，界面、历史记录、回执三处都看不出这次其实没按所选执行。
  const TIER_WARN = [];
  function pickTier(raw, tiers, fallback, label) {
    const n = Number(raw);
    if (tiers.includes(n)) return n;
    TIER_WARN.push(`${label}的 ${raw} 不是可选项，已按 ${fallback} 测试`);
    return fallback;
  }

  async function run() {
    if (running) return;
    running = true;
    TIER_WARN.length = 0;
    const button = $('btnDiskBench');
    if (button) button.disabled = true;
    if ($('diskBenchStatus')) $('diskBenchStatus').textContent = '准备测试...';
    ensureProgressBar();
    // L06：参数组装与进度订阅并入 try——原实现 running=true 之后、try 之前有约
    // 20 行可抛代码，一旦抛出 running 永久为 true、按钮永久禁用；finally 统一复位。
    try {
      // P1-6E 把时长收进 options 时,函数内的 duration 绑定一起消失了,而演示分支的
      // totalMs 还要读它 ⇒ 先取一次再进对象字面量（pickTier 带 TIER_WARN 副作用,不能取两次）
      const duration = pickTier($('diskDuration')?.value, [4, 8, 16], 8, '时长');
      const options = {
        path: ($('diskBenchPath')?.value || '').trim(), // 空路径由主进程白名单校验拒绝，不再回落硬编码开发机路径
        blockSize: pickTier($('diskBlockSize')?.value, [4096, 65536, 1048576], 1048576, '块大小'),
        // v3.7.1 R1：QD=每线程在途上限、线程数真实生效（Rust OVERLAPPED 并发）；白名单与主进程一致
        queueDepth: pickTier($('diskQueueDepth')?.value, [1, 8, 32], 1, '队列深度'),
        threads: pickTier($('diskThreads')?.value, [1, 4, 8], 1, '线程数'),
        duration
      };
      // 订阅后端真实进度
      if (window.api?.diskbench?.onProgress) {
        progressUnsub = window.api.diskbench.onProgress(d => {
          if (d && typeof d.percent === 'number') setProgress(d.percent, d.phase);
        });
      }
      let result = MOCK;
      let engine = '';
      const paramNotes = [];
      if (window.api?.diskbench) {
        const response = await window.api.diskbench.run(options);
        if (!response.success) throw new Error(response.message);
        result = response.data;
        engine = response.engine || '';
        // 主进程与原生动机的回落告警合成一份，前端不再各说各话
        if (Array.isArray(response.warn)) paramNotes.push(...response.warn);
      } else {
        // 演示模式：按 3×duration 模拟进度（数据与状态行都必须带「演示」标识，L03）
        engine = 'demo';
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
          : engine === 'powershell' ? '测试完成（PowerShell 引擎）'
          : engine === 'demo' ? '测试完成（演示数据，非本机实测）'
          : '测试完成';
      }
      paramNotes.push(...TIER_WARN);
      window.app?.toast('success', '磁盘测速完成，测试文件已清理');
      if (paramNotes.length) window.app?.toast('warning', `本次未按所选参数测试：${paramNotes.join('；')}`);
      // 保存历史记录
      saveHistoryRecord(result, options, engine);
    } catch (error) {
      if ($('diskBenchStatus')) $('diskBenchStatus').textContent = '测试失败';
      window.app?.toast('error', `磁盘测速失败：${error.message}`);
    } finally {
      running = false;
      if (button) button.disabled = false;
      // L06：unlisten 返回 Promise，包一层 catch——reject 不能再变成浮动拒绝
      if (progressUnsub) { Promise.resolve(progressUnsub()).catch(() => {}); progressUnsub = null; }
      removeProgressBar();
    }
  }

  // ==================== 历史记录 ====================
  async function saveHistoryRecord(result, options, engine = '') {
    // 演示数据不落历史：历史记录页没有引擎字段可标「演示」，落进去会被当成真实测速结果
    if (!window.api?.benchHistory || engine === 'demo') return;
    try {
      const receipt = await window.api.benchHistory.add({
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
      // 后端拒收是 Ok({success:false}) 出口（Promise 照常 resolve）⇒ 不看这一位就等于
      // 把「没落盘」念成「已保存」。渲染层 console 不进日志页，失败必须走 app.log。
      if (!receipt || receipt.success === false) {
        window.app?.log?.('warn', '保存测速历史失败：' + ((receipt && receipt.message) || '无回执'));
      }
    } catch (e) {
      window.app?.log?.('warn', '保存测速历史失败: ' + ((e && e.message) || e));
    }
  }

  // v6-K14：块大小走 ds.fmtBytes 唯一真源（原实现 MB 档用裸浮点：1.5 MB 能出
  // "1.549805 MB" 这种半成品精度）
  function formatBlock(size) { return window.ds.fmtBytes(size); }

  function formatTime(iso) {
    try {
      const d = new Date(iso);
      const pad = n => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    } catch (e) { return iso; }
  }

  // 历史测试记录弹窗（2026-10-22 用户点名改自绘弹窗骨架）：原先它自建一层皮，与
  // .usage-modal 并列成第二份弹窗实现——不套统一材质、z 层 2000 压在 confirm（10000）
  // 之下、Esc 与焦点圈闭全要自己写一遍。现收进 modal.js 工厂，那层皮随之下线。
  // ctrl 句柄留着是为了「再点一次先 close 上一份」：modal.create 对同 id 只 remove DOM、
  // 不走 close()，上一份挂在 document 上的 Esc 监听与 ds.focusTrap 就摘不干净。
  let historyCtrl = null;

  async function showHistory() {
    if (!window.api?.benchHistory) {
      window.app?.toast('info', '历史记录功能仅在应用模式下可用');
      return;
    }
    // 先收上一份再取数：与旧实现同一条「重开即刷新」路径
    if (historyCtrl) historyCtrl.close();
    let records = [];
    try {
      const resp = await window.api.benchHistory.list();
      // A1-M06：读失败与「确实没有记录」必须分开；旧实现把 success:false 折成空数组。
      if (!resp || !resp.success) {
        window.app?.toast('error', '读取历史记录失败：' + ((resp && resp.message) || '无回执'));
        return;
      }
      records = resp.data || [];
    } catch (e) {
      window.app?.toast('error', '读取历史记录失败: ' + e.message);
      return;
    }

    const ctrl = window.modal.create({
      id: 'benchHistoryBackdrop',
      title: '历史测试记录',
      metaHtml: `<span class="bench-history-count">${records.length} 条记录</span>`,
      bodyHtml: records.length === 0 ? `
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
                  <tr data-record-id="${window.ds.escAttr(String(r.id))}">
                    <td class="bench-history-time">${formatTime(r.timestamp)}</td>
                    <td class="bench-history-path" data-tip="${escapeHtml(r.path || '')}">${escapeHtml(r.path || '--')}</td>
                    <td>${formatBlock(r.blockSize)} / QD${r.queueDepth} / ${r.threads}T / ${r.duration}s${r.engine === 'rust' ? '（原生）' : r.engine === 'powershell' ? '（PS）' : ''}</td>
                    <td class="bench-history-val">${Number(r.sequentialRead).toFixed(1)} MB/s</td>
                    <td class="bench-history-val">${Number(r.sequentialWrite).toFixed(1)} MB/s</td>
                    <td class="bench-history-val">${Number(r.randomRead).toFixed(1)} MB/s</td>
                    <td class="bench-history-val">${Math.round(r.iops)}</td>
                    <td class="bench-history-val">${Number(r.latency).toFixed(3)} ms</td>
                    <td><button class="bench-history-delete" data-delete-id="${window.ds.escAttr(String(r.id))}" data-tip="删除此记录">&times;</button></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
      `,
      // 空表不给 footer：footerHtml === undefined 才是不建这层（传空串会留一条空白栏）
      footerHtml: records.length > 0
        ? '<button class="btn btn-secondary btn-small" type="button" data-history-clear data-tip="删除全部测试记录，不可恢复">清空全部</button>'
        : undefined,
      // 9 列表格的 min-content 实测 946px（时间戳 / 完整路径 / 五个数值列都不可折），
      // 加上 .usage-body 左右各 30px 内边距 ⇒ 1020 才不横向溢出；旧版 920 宽一直横向
      // 溢出 68px，只是以前没量过。窗口最小宽 1387（lib.rs MIN_WIDTH），放得下。
      width: 1020,
      onClose: () => { historyCtrl = null; },
    });
    historyCtrl = ctrl;

    // 删除单条记录
    ctrl.body.querySelectorAll('[data-delete-id]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.deleteId;
        try {
          const receipt = await window.api.benchHistory.delete(id);
          // 先看回执再改 DOM：旧实现无条件摘行 + 无条件报「已删除」，重开弹窗记录全回来
          if (!receipt || receipt.success === false) {
            window.app?.toast('error', '删除失败：' + ((receipt && receipt.message) || '无回执'));
            return;
          }
          btn.closest('tr')?.remove();
          const remaining = ctrl.body.querySelectorAll('tbody tr').length;
          const countEl = ctrl.modal.querySelector('.bench-history-count');
          if (countEl) countEl.textContent = `${remaining} 条记录`;
          // 删空要整体重开：footer（清空全部）与空态插图不是一个形状，逐条改 DOM 改不出来
          if (remaining === 0) { ctrl.close(); setTimeout(showHistory, 100); }
          window.app?.toast('success', '记录已删除');
        } catch (e) {
          window.app?.toast('error', '删除失败: ' + e.message);
        }
      });
    });

    // 清空全部
    ctrl.footer?.querySelector('[data-history-clear]')?.addEventListener('click', async () => {
      // 审查 v2-L6：清空全部记录是不可恢复的删除操作，原先用普通 confirm（无红色危险
      // 样式）。改走 confirmDanger（签名是位置参数，不是对象 + onOk）。
      const ok = await window.app?.confirmDanger?.(
        '清空测速历史',
        '确定要删除全部测试记录吗？此操作不可恢复。',
        '清空',
        '取消',
        '删除后无法从应用内恢复，历史图表将一并清空。'
      );
      if (!ok) return;
      try {
        const receipt = await window.api.benchHistory.clear();
        // 同删除支：清空失败时必须留住弹窗与记录，不能报「已清空」
        if (!receipt || receipt.success === false) {
          window.app?.toast('error', '清空失败：' + ((receipt && receipt.message) || '无回执'));
          return;
        }
        ctrl.close();
        setTimeout(showHistory, 100);
        window.app?.toast('success', '历史记录已清空');
      } catch (e) {
        window.app?.toast('error', '清空失败: ' + e.message);
      }
    });
  }

  function escapeHtml(text) { return window.ds.esc(text); }

  // ==================== 功能解释说明（MD 渲染） ====================
  let guideCache = null;
  // 2026-10-22 用户裁定：说明书从常驻 Toast 改成自绘弹窗。原先即便 M09 已把它挂进
  // Toast 台账，形态仍然是错的——一份长文档压在玻璃底上、透出下面的表单文字，读不动。
  // ctrl 句柄留着是为了「再点一次先 close 上一份」：modal.create 对同 id 只 remove DOM、
  // 不走 close()，上一份挂在 document 上的 Esc 监听与 ds.focusTrap 就摘不干净。
  let guideModalCtrl = null;

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
      // F4b-L04 能力对齐：与 app.js 的 renderMarkdown 同一行内语义——图片语法剔除
      // （CSP 的 img-src 不放行外链图，渲染出来是碎图）、http(s) 链接出锚点、其余
      // 链接降级纯文本。两份渲染器收敛成一份需 app.js 导出（白名单外，跨面待主 agent）。
      return escapeHtml(text)
        .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
        .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
        .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
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
    } catch (e) {
      window.app?.toast('error', '加载功能说明失败: ' + e.message);
      return;
    }
    if (guideModalCtrl) guideModalCtrl.close();
    // md 第一行是与弹窗标题同名的一级标题，正文里再出一遍是重复，掐掉
    const bodyMd = guideCache.replace(/^#\s+磁盘测速功能解释说明\s*\r?\n/, '');
    const ctrl = window.modal.create({
      id: 'benchGuideBackdrop',
      title: '磁盘测速功能解释说明',
      bodyHtml: `<div class="guide-content">${renderMarkdown(bodyMd)}</div>`,
      footerHtml: '<button class="btn btn-secondary" type="button" data-guide-close>知道了</button>',
      onClose: () => { guideModalCtrl = null; },
    });
    guideModalCtrl = ctrl;
    ctrl.footer?.querySelector('[data-guide-close]')?.addEventListener('click', () => ctrl.close());
    // 说明书里的外链必须走受控出口：webview 直接导航会被 CSP 与窗口策略拒掉，
    // 用户看到的是「点了没反应」（与 app.js 使用说明同一口径）。
    ctrl.body.querySelectorAll('.guide-content a[href]').forEach((a) => {
      a.addEventListener('click', async (ev) => {
        ev.preventDefault();
        const url = a.getAttribute('href') || '';
        if (!/^https?:\/\//i.test(url)) return;
        // openExternal 返回 Promise，同步 try/catch 抓不到 reject。
        try {
          await window.api?.app?.openExternal?.(url);
        } catch (e) {
          window.app?.toast?.('error', '打开链接失败：' + ((e && e.message) || e));
        }
      });
    });
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
              if (!current) {
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
