// finder.js - 磁盘清理 · Rust 原生查找器（重复/大文件/空）
// 三个子页共用一套「布尔进度 + @@PROGRESS:n@@ 上报管线」：
// 扫描走进程内原生引擎（trim-finder lib 直调，不再 spawn finder.exe），
// 进度以 finder:progress 事件推送，完成时一次性返回结果数组。
// 样式完全复用 .card / .table-card / .opt-* / .summary-card 主题语义。
// 2026-09-28：空文件/空目录结果分页渲染（每页 1000 条）——数万条一次挂 DOM 会卡死渲染层。
// AppData 瘦身子页已移除（并入后续统一磁盘分析，见竞品借鉴落地方案 P1）。
(function () {
  'use strict';

  let inited = false;
  let subscribed = false;

  // 空文件/空目录页每页渲染条数。再大单次 innerHTML 拼接 + DOM 解析就会秒级卡顿。
  const EMPTY_PAGE_SIZE = 1000;

  // 每个页签独立状态
  const st = {
    dups:    { results: [], selected: new Set(), scanning: false, deleting: false },
    big:     { results: [], selected: new Set(), scanning: false, deleting: false },
    // pageF/pageD：空文件/空目录各自独立的当前页码（两段列表分开翻页）
    empty:   { results: [], selected: new Set(), scanning: false, deleting: false, pageF: 1, pageD: 1 },
    // C-5 磁盘分析器：selected/results 仅复用通用按钮态；真实数据在 an.cache/trail
    an:      { results: [], selected: new Set(), scanning: false, deleting: false }
  };

  // 页签 -> 元素 id / 参数来源 / scanType 映射
  // 2026-09-28 六轮拍板：重复文件隐藏目录输入（内置默认）；大文件/空文件改盘符点选
  const CFG = {
    dups: {
      scanType: 'duplicates', kind: 'file',
      scanBtn: 'dupBtnScan', selectBtn: 'dupBtnSelect', deleteBtn: 'dupBtnDelete',
      minSizeSel: 'dupMinSize',
      progress: { section: 'dupProgressSection', label: 'dupProgressLabel', value: 'dupProgressValue', fill: 'dupProgressFill' },
      table: 'dupTable', groupCount: 'dupGroupCount', size: 'dupSize'
    },
    big: {
      scanType: 'bigfiles', kind: 'file',
      scanBtn: 'bigBtnScan', selectBtn: 'bigBtnSelect', deleteBtn: 'bigBtnDelete',
      drivesEl: 'bigDrives',
      progress: { section: 'bigProgressSection', label: 'bigProgressLabel', value: 'bigProgressValue', fill: 'bigProgressFill' },
      table: 'bigTable'
    },
    empty: {
      scanType: 'empty', kind: 'both',
      scanBtn: 'emptyBtnScan', selectBtn: 'emptyBtnSelect', deleteBtn: 'emptyBtnDelete',
      drivesEl: 'emptyDrives',
      progress: { section: 'emptyProgressSection', label: 'emptyProgressLabel', value: 'emptyProgressValue', fill: 'emptyProgressFill' },
      table: 'emptyTable', fileCount: 'emptyCount', dirCount: 'emptyDirCount'
    },
    // C-5：无 scanBtn（分析走 startAnalyzeRoots 自有流程）/无勾选删除（行内删除）
    an: {
      scanType: 'analyze',
      drivesEl: 'anDrives',
      progress: { section: 'anProgressSection', label: 'anProgressLabel', value: 'anProgressValue', fill: 'anProgressFill' },
      table: 'anTable'
    }
  };

  // 盘符点选状态：scanType -> Set(选中盘符，如 "C:")。默认全选固定盘（diskList 返回值）。
  const driveSel = { big: new Set(), empty: new Set(), an: new Set() };

  // 拉取固定盘并渲染胶囊点选器（默认全选；失败时保留「预置 C:」保底并显式报错，
  // 不让「点开始扫描没反应」——七轮真机反馈排查防御）。
  async function initDrivePicker(key) {
    const cfg = CFG[key];
    const box = document.getElementById(cfg.drivesEl);
    if (!box) return;
    // 保底：枚举前先预置 C:（默认全盘的最低形态）；枚举成功后刷新为全选
    driveSel[key].add('C:');
    box.innerHTML = '<span class="finder-pager-info">盘符枚举中…</span>';
    try {
      const resp = await window.api.system.diskList();
      if (!resp.success) throw new Error(resp.message || '盘符枚举失败');
      const drives = resp.data || [];
      if (!drives.length) {
        box.innerHTML = '<span class="finder-pager-info">未发现固定磁盘（按 C: 处理）</span>';
        renderDriveChips(key, box, ['C:']);
        return;
      }
      drives.forEach((d) => driveSel[key].add(d));
      renderDriveChips(key, box, drives);
    } catch (e) {
      box.innerHTML = `<span class="finder-pager-info">盘符枚举失败（按 C: 处理）：${esc(String(e.message || e))}</span>`;
      renderDriveChips(key, box, ['C:']);
    }
  }

  function renderDriveChips(key, box, drives) {
    box.innerHTML = drives.map((d) => `
      <span class="drive-chip ${driveSel[key].has(d) ? 'active' : ''}" data-drive="${esc(d)}" data-drive-for="${key}" role="checkbox" aria-checked="${driveSel[key].has(d)}">${esc(d)}</span>
    `).join('');
  }

  function onDriveClick(e) {
    const chip = e.target.closest('[data-drive]');
    if (!chip) return;
    const key = chip.dataset.driveFor;
    const d = chip.dataset.drive;
    if (!driveSel[key]) return;
    if (driveSel[key].has(d)) driveSel[key].delete(d); else driveSel[key].add(d);
    chip.classList.toggle('active', driveSel[key].has(d));
    chip.setAttribute('aria-checked', driveSel[key].has(d) ? 'true' : 'false');
  }

  function formatSize(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1);
    const v = bytes / Math.pow(k, i);
    return v.toFixed(v < 10 && i > 0 ? 2 : v < 100 && i > 0 ? 1 : 0) + ' ' + units[i];
  }

  function esc(s) { return window.ds.esc(s); }

  // Unix 秒 → YYYY-MM-DD（创建日期列，2026-09-28 用户要求；0/缺失显示 —）
  function fmtDate(ts) {
    const n = Number(ts);
    if (!n) return '—';
    const d = new Date(n * 1000);
    const p = (x) => String(x).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  }

  function middleEllipsis(s, max) {
    s = String(s || '');
    if (s.length <= max) return s;
    const keep = Math.floor((max - 1) / 2);
    return s.slice(0, keep) + '…' + s.slice(s.length - keep);
  }

  // 扫描根：big/empty/analyze 用盘符点选（选中盘 → "X:\"），dups 交后端内置默认目录
  function readPaths(cfg) {
    if (cfg.drivesEl) {
      const key = cfg.scanType === 'bigfiles' ? 'big' : (cfg.scanType === 'analyze' ? 'an' : 'empty');
      return [...driveSel[key]].map((d) => d + '\\');
    }
    return [];
  }

  function setProgress(cfg, percent, label) {
    const section = document.getElementById(cfg.progress.section);
    const fill = document.getElementById(cfg.progress.fill);
    const value = document.getElementById(cfg.progress.value);
    const lab = document.getElementById(cfg.progress.label);
    if (section) section.style.display = 'block';
    if (fill) fill.style.width = percent + '%';
    if (value) value.textContent = Math.round(percent) + '%';
    if (lab && label) lab.textContent = label;
  }

  function hideProgress(cfg) {
    const section = document.getElementById(cfg.progress.section);
    if (section) section.style.display = 'none';
  }

  // ==================== 自我安慰式进度（用户拍板 2026-09-28） ====================
  // 真百分比未知的扫描（空文件全树遍历）此前全程停在 2% 直到完成，观感是「卡死」。
  // 口径：启动后从 4% 缓慢爬升、渐近封顶 99%（越接近 99 步长越小），扫描完成才跳
  // 100% 收尾；真 progress 事件（dups/bigfiles 有）与心跳粗估值（E-1）只在**大于**
  // 当前伪值时抬升（bumpProgress 同时改 ticker 内部值，防下一拍伪值把进度拉回去）。
  const fakeTickers = {}; // scanType -> { id, v }

  function startFakeProgress(cfg) {
    stopFakeProgress(cfg);
    const s = { id: null, v: 4 };
    fakeTickers[cfg.scanType] = s;
    s.id = setInterval(() => {
      s.v = Math.min(99, s.v + Math.max(0.4, (99 - s.v) * 0.02));
      setProgress(cfg, s.v);
    }, 400);
  }

  function stopFakeProgress(cfg) {
    const s = fakeTickers[cfg.scanType];
    if (s) { clearInterval(s.id); delete fakeTickers[cfg.scanType]; }
  }

  function bumpProgress(cfg, target, label) {
    const s = fakeTickers[cfg.scanType];
    const cur = s ? s.v : 0;
    if (target > cur) {
      if (s) s.v = target;
      setProgress(cfg, target, label);
    }
  }

  // 主进程流式进度（@@PROGRESS:n@@ 管线终点）+ P0 心跳（@@SCANNED:n@@）
  function onProgress(p) {
    if (!p || !p.scanType) return;
    for (const key of Object.keys(CFG)) {
      if (CFG[key].scanType === p.scanType && st[key].scanning) {
        if (typeof p.scanned === 'number') {
          // E-1（2026-09-28 拍板）：心跳换算粗估百分比——总数未知，按全盘 ~60 万
          // 文件的饱和指数曲线折算（n=60万→约60%，封顶 95%），只升不降；真 progress
          // 事件仍优先（dups/big 的心跳与真进度同源时真值更准）。
          const rough = Math.min(95, 95 * (1 - Math.exp(-p.scanned / 600000)));
          const lab = document.getElementById(CFG[key].progress.label);
          const sec = document.getElementById(CFG[key].progress.section);
          if (sec) sec.style.display = 'block';
          const label = `扫描中... 约 ${Math.round(rough)}% · 已枚举 ${p.scanned.toLocaleString()} 个文件`;
          const s = fakeTickers[CFG[key].scanType];
          if (rough > (s ? s.v : 0)) bumpProgress(CFG[key], rough, label);
          else if (lab) lab.textContent = label; // 未超过伪值时只刷新文案，进度条不动
        } else if (typeof p.progress === 'number') {
          // 真 progress：大于当前伪值才覆盖（伪进度条口径见 startFakeProgress）
          bumpProgress(CFG[key], p.progress, `扫描中... ${Math.round(p.progress)}%`);
        }
      }
    }
  }

  function checkboxHtml(id, checked) {
    return `<span class="checkbox ${checked ? 'checked' : ''}" data-fcheck="${id}"></span>`;
  }

  function nameOf(path) {
    const s = String(path || '');
    const parts = s.split(/[\\/]/);
    return parts[parts.length - 1] || s;
  }

  // ==================== 重复文件 ====================
  // match 字段由扫描器输出：name=同名同大小（文件名优先命中）/ content=内容指纹相同。
  // 2026-09-28 七轮拍板：similar（文档内容相似）组已移除——不同名文件塞一组的明细不成立。
  const DUP_MATCH_LABEL = { content: '内容相同组', name: '同名文件组' };

  function renderDups() {
    const el = document.getElementById(CFG.dups.table);
    const cfg = CFG.dups;
    const s = st.dups;
    const dupItems = s.results.filter(r => r.type === 'duplicate');
    if (!dupItems.length) {
      el.innerHTML = '<div class="finder-empty">未发现重复、相似或同名文件，或尚未扫描</div>';
      return;
    }
    const groups = [];
    const gmap = new Map();
    for (const it of dupItems) {
      if (!gmap.has(it.group)) {
        const g = { id: it.group, size: it.size, match: it.match || 'content', sim: it.sim, rows: [] };
        gmap.set(it.group, g);
        groups.push(g);
      }
      gmap.get(it.group).rows.push(it);
    }
    let html = '';
    for (const g of groups) {
      const cands = g.rows.filter(r => r.role !== 'kept');
      const kept = g.rows.find(r => r.role === 'kept');
      const candSum = cands.reduce((a, r) => a + (r.size || 0), 0);
      let head = `${DUP_MATCH_LABEL[g.match] || '重复组'} · ${g.rows.length} 份`;
      if (g.match === 'content') head += ` · 每份 ${formatSize(g.size)}`;
      html += `<div class="finder-group-header">
        <span>${head}</span>
        <span class="finder-group-sum">保留 1 · 可释放 ${formatSize(candSum)}</span>
      </div>`;
      html += '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>名称 / 路径</th><th class="finder-col-size" style="width:110px">大小</th><th class="finder-col-size" style="width:90px">角色</th></tr></thead><tbody>';
      for (const r of g.rows) {
        const keepRole = r.role === 'kept';
        const checked = s.selected.has(r.path);
        html += `<tr class="${checked ? 'finder-row-selected' : ''}">
          <td>${keepRole ? '' : checkboxHtml('dup_' + esc(r.path), checked)}</td>
          <td><div class="finder-cell"><span class="finder-name-text">${esc(nameOf(r.path))}</span><span class="finder-name-text" style="opacity:.55">·</span><span class="finder-path-text" data-tip="${esc(r.path)}">${esc(middleEllipsis(r.path, 70))}</span></div></td>
          <td class="finder-col-size">${formatSize(r.size)}</td>
          <td class="finder-col-size"><span class="finder-role ${keepRole ? 'finder-role-kept' : 'finder-role-candidate'}">${keepRole ? '保留' : '可删'}</span></td>
        </tr>`;
      }
      html += '</tbody></table>';
    }
    el.innerHTML = html;
    refreshDupSummary();
    updateAllButtons();
  }

  function refreshDupSummary() {
    const cfg = CFG.dups;
    const s = st.dups;
    const dupItems = s.results.filter(r => r.type === 'duplicate');
    document.getElementById(cfg.groupCount).textContent = new Set(dupItems.filter(r => r.role !== 'kept').map(r => r.group)).size;
    const total = dupItems.reduce((a, r) => a + (r.role === 'kept' ? 0 : r.size), 0);
    document.getElementById(cfg.size).textContent = formatSize(total);
  }

  // ==================== 大文件 ====================
  // 2026-09-28 八轮：路径列可点击——explorer /select 定位到文件（复用 startup:openlocation）；
  // 表格 fixed 布局 + 大小列左侧隔离，长路径不再覆盖大小显示。
  function renderBig() {
    const el = document.getElementById(CFG.big.table);
    const cfg = CFG.big;
    const s = st.big;
    if (!s.results.length) {
      el.innerHTML = '<div class="finder-empty">尚未扫描。请选择磁盘后点击「开始扫描」</div>';
      return;
    }
    let html = '<table class="finder-table finder-table-fixed"><thead><tr><th style="width:34px"></th><th>名称 / 路径</th><th class="finder-col-size" style="width:130px">大小</th></tr></thead><tbody>';
    for (const r of s.results) {
      const checked = s.selected.has(r.path);
      html += `<tr class="${checked ? 'finder-row-selected' : ''}">
        <td>${checkboxHtml('big_' + esc(r.path), checked)}</td>
        <td><div class="finder-cell finder-reveal" data-reveal="${esc(r.path)}" data-tip="点击在资源管理器中定位该文件"><span class="finder-name-text">${esc(nameOf(r.path))}</span><span class="finder-name-text" style="opacity:.55">·</span><span class="finder-path-text" data-tip="${esc(r.path)}">${esc(middleEllipsis(r.path, 76))}</span></div></td>
        <td class="finder-col-size">${formatSize(r.size)}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
    updateAllButtons();
  }

  // ==================== 空文件 / 空目录 ====================
  // 2026-09-28：分页渲染。扫描可返回数万条（10 万级也曾出现），一次挂全部 DOM 会
  // 把渲染层卡死；每页只渲染 EMPTY_PAGE_SIZE 条，勾选集合仍作用于全部结果。
  // 2026-09-28 二轮：左右双栏容器（.empty-grid），左空文件右空目录，各自独立翻页。
  function pagerHtml(target, cur, pages) {
    return `<div class="finder-pager">
      <button type="button" class="btn btn-secondary btn-small" data-pg="${target}:prev" ${cur <= 1 ? 'disabled' : ''}>上一页</button>
      <span class="finder-pager-info">第 ${cur} / ${pages} 页 · 每页 ${EMPTY_PAGE_SIZE} 条</span>
      <button type="button" class="btn btn-secondary btn-small" data-pg="${target}:next" ${cur >= pages ? 'disabled' : ''}>下一页</button>
    </div>`;
  }

  function renderEmpty() {
    const cfg = CFG.empty;
    const s = st.empty;
    const files = s.results.filter(r => r.type === 'emptyfile');
    const dirs = s.results.filter(r => r.type === 'emptyfolder');
    // 汇总卡与双栏容器头的计数同步
    document.getElementById(cfg.fileCount).textContent = files.length;
    document.getElementById(cfg.dirCount).textContent = dirs.length;
    document.getElementById('emptyPaneCountFiles').textContent = files.length;
    document.getElementById('emptyPaneCountDirs').textContent = dirs.length;
    const boxF = document.getElementById('emptyFilesBox');
    const boxD = document.getElementById('emptyDirsBox');
    if (!s.results.length) {
      boxF.innerHTML = '<div class="finder-empty">未发现空文件，或尚未扫描</div>';
      boxD.innerHTML = '<div class="finder-empty">未发现空目录，或尚未扫描</div>';
      return;
    }
    // 页码越界校正（删除/重扫后集合变小）
    const pagesF = Math.max(1, Math.ceil(files.length / EMPTY_PAGE_SIZE));
    const pagesD = Math.max(1, Math.ceil(dirs.length / EMPTY_PAGE_SIZE));
    s.pageF = Math.min(Math.max(1, s.pageF), pagesF);
    s.pageD = Math.min(Math.max(1, s.pageD), pagesD);

    if (files.length) {
      let hf = '<table class="finder-table finder-table-fixed"><thead><tr><th style="width:34px"></th><th>名称 / 路径</th><th class="finder-col-size" style="width:110px">创建日期</th></tr></thead><tbody>';
      for (const r of files.slice((s.pageF - 1) * EMPTY_PAGE_SIZE, s.pageF * EMPTY_PAGE_SIZE)) {
        const checked = s.selected.has(r.path);
        hf += `<tr class="${checked ? 'finder-row-selected' : ''}"><td>${checkboxHtml('ef_' + esc(r.path), checked)}</td><td><div class="finder-cell"><span class="finder-name-text">${esc(nameOf(r.path))}</span><span class="finder-name-text" style="opacity:.55">·</span><span class="finder-path-text" data-tip="${esc(r.path)}">${esc(middleEllipsis(r.path, 70))}</span></div></td><td class="finder-col-size">${fmtDate(r.created)}</td></tr>`;
      }
      hf += '</tbody></table>';
      if (pagesF > 1) hf += pagerHtml('files', s.pageF, pagesF);
      boxF.innerHTML = hf;
    } else {
      boxF.innerHTML = '<div class="finder-empty">未发现空文件</div>';
    }

    if (dirs.length) {
      let hd = '<table class="finder-table finder-table-fixed"><thead><tr><th style="width:34px"></th><th>路径</th><th class="finder-col-size" style="width:110px">创建日期</th><th class="finder-col-size" style="width:80px">连带</th></tr></thead><tbody>';
      for (const r of dirs.slice((s.pageD - 1) * EMPTY_PAGE_SIZE, s.pageD * EMPTY_PAGE_SIZE)) {
        const nested = Number(r.nested) || 0;
        const checked = s.selected.has(r.path);
        const nestedCell = nested > 0
          ? `<span class="finder-name-text" data-tip="删除该目录会整树移入回收站，连带其下 ${nested} 个空子目录与树内的 0 字节文件（可在回收站还原）">${nested} 个</span>`
          : '<span class="finder-name-text" style="opacity:.55">—</span>';
        hd += `<tr class="${checked ? 'finder-row-selected' : ''}"><td>${checkboxHtml('ed_' + esc(r.path), checked)}</td><td><div class="finder-cell"><span class="finder-name-text">${esc(nameOf(r.path))}</span><span class="finder-name-text" style="opacity:.55">·</span><span class="finder-path-text" data-tip="${esc(r.path)}">${esc(middleEllipsis(r.path, 64))}</span></div></td><td class="finder-col-size">${fmtDate(r.created)}</td><td class="finder-col-size">${nestedCell}</td></tr>`;
      }
      hd += '</tbody></table>';
      if (pagesD > 1) hd += pagerHtml('dirs', s.pageD, pagesD);
      boxD.innerHTML = hd;
    } else {
      boxD.innerHTML = '<div class="finder-empty">未发现空目录</div>';
    }
    updateAllButtons();
  }

  const RENDER_FN = { dups: renderDups, big: renderBig, empty: renderEmpty, an: renderAn };

  // ==================== 磁盘分析器（C-5，2026-09-28 拍板） ====================
  // 逐层按需下钻：trail 为导航栈（节点 = {key,label,paths}），每层结果缓存在 cache
  // （key = paths.join('|')），返回/重入命中缓存不重扫。summary/ext 条目不进快照槽
  // （后端过滤），kind=dir 目录条目走 finder:delete 回收站链（含快照校验与已删除清单）。
  const an = {
    trail: [],        // [{key, label, paths:[...]}]
    cache: new Map(), // key -> {summary, dirs, exts}
    scanning: false
  };

  function anCurrent() { return an.trail[an.trail.length - 1] || null; }

  function anLayerKey(paths) { return paths.join('|'); }

  function anScanBtn(disabled) {
    const sb = document.getElementById('anBtnScan');
    if (sb) { sb.disabled = disabled; if (sb.querySelector('span')) sb.querySelector('span').textContent = disabled ? '分析中...' : '开始分析'; }
  }

  async function anFetch(paths, label) {
    const key = anLayerKey(paths);
    if (an.trail.length === 0 || anCurrent().key !== key) {
      an.trail.push({ key, label, paths });
      if (an.trail.length > 12) an.trail.shift(); // 面包屑深度上限防无限增长
    }
    renderAnBreadcrumb();
    if (an.cache.has(key)) { renderAn(); return; }
    await anScan(paths, key);
  }

  async function anScan(paths, key) {
    const cfg = CFG.an;
    if (an.scanning) return;
    an.scanning = true;
    st.an.scanning = true;
    anScanBtn(true);
    setProgress(cfg, 4, '分析中...');
    startFakeProgress(cfg);
    try {
      const resp = await window.api.finder.scan('analyze', { paths });
      if (!resp.success) throw new Error(resp.message || '分析失败');
      const items = resp.data || [];
      an.cache.set(key, {
        summary: items.find(r => r.kind === 'summary') || null,
        dirs: items.filter(r => r.kind === 'dir'),
        exts: items.filter(r => r.kind === 'ext')
      });
      stopFakeProgress(cfg);
      setProgress(cfg, 100, '分析完成');
      renderAn();
    } catch (e) {
      hideProgress(cfg);
      window.app?.toast?.('error', '分析失败: ' + e.message);
      // 失败回退：弹出本层节点，避免面包屑指向不存在的层
      if (an.trail.length && anCurrent().key === key) an.trail.pop();
      renderAnBreadcrumb();
    } finally {
      stopFakeProgress(cfg);
      an.scanning = false;
      st.an.scanning = false;
      anScanBtn(false);
      setTimeout(() => hideProgress(cfg), 600);
    }
  }

  function startAnalyzeRoots() {
    const paths = readPaths(CFG.an);
    if (!paths.length) {
      window.app?.toast?.('warning', '请至少选择一个要分析的磁盘');
      return;
    }
    anFetch(paths, paths.length > 1 ? `${paths.length} 个磁盘` : paths[0]);
  }

  function anDrill(path) {
    if (an.scanning || !path) return;
    anFetch([path], nameOf(path));
  }

  function anUp() {
    if (an.scanning || an.trail.length <= 1) return;
    an.trail.pop();
    renderAnBreadcrumb();
    renderAn();
  }

  function anGoto(idx) {
    if (an.scanning || idx < 0 || idx >= an.trail.length) return;
    an.trail = an.trail.slice(0, idx + 1);
    renderAnBreadcrumb();
    renderAn();
  }

  function anAppData() {
    if (an.scanning) return;
    // %LOCALAPPDATA% 由后端 finder_scan 的 expand_env_path 展开
    an.trail = [];
    anFetch(['%LOCALAPPDATA%'], 'AppData · Local');
  }

  async function anDelete(path) {
    if (an.scanning) return;
    const cur = anCurrent();
    const layer = cur ? an.cache.get(cur.key) : null;
    const row = layer && layer.dirs.find(r => r.path === path);
    const total = row ? row.size : 0;
    const ok = await window.app?.confirmDanger?.(
      '确认删除',
      `将把「${nameOf(path)}」整树移入回收站，共约 ${formatSize(total)}。`,
      '确认删除',
      '取消',
      '移入回收站（可在回收站还原）；删除会记入「已删除清单」。受保护的系统路径会被拒绝。'
    );
    if (!ok) return;
    try {
      const resp = await window.api.finder.delete([{ path, kind: 'dir' }]);
      if (!resp || (!resp.success && !resp.data)) throw new Error((resp && resp.message) || '删除失败');
      const removed = new Set((resp.data.details || []).filter(d => d.status === 'ok').map(d => d.path));
      if (removed.has(path)) {
        if (layer) layer.dirs = layer.dirs.filter(r => r.path !== path);
        renderAn();
        window.app?.toast?.('success', '已移入回收站（清空回收站后释放空间）');
      } else {
        window.app?.toast?.('warning', '删除失败（可能被占用）');
      }
    } catch (e) {
      window.app?.toast?.('error', '删除失败: ' + e.message);
    }
  }

  const AN_EXT_COLORS = ['var(--accent)', 'var(--success)', 'var(--warning)', 'var(--info)', 'var(--danger)'];

  function renderAnExt(layer) {
    const box = document.getElementById('anExtSection');
    if (!box) return;
    const exts = (layer && layer.exts) || [];
    if (!exts.length) { box.style.display = 'none'; return; }
    const total = exts.reduce((a, r) => a + r.size, 0) || 1;
    const top = exts.slice(0, 5);
    const segs = top.map((r, i) => {
      const pct = Math.round(r.size * 100 / total);
      return `<div style="width:${pct}%;background:${AN_EXT_COLORS[i] || 'var(--fg-tertiary)'}"></div>`;
    }).join('');
    const legend = top.map((r, i) => {
      const pct = Math.round(r.size * 100 / total);
      const color = AN_EXT_COLORS[i] || 'var(--fg-tertiary)';
      return `<span><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${color};margin-right:4px"></span>${esc(r.ext)} ${pct}% · ${formatSize(r.size)}</span>`;
    }).join('');
    box.style.display = 'flex';
    box.innerHTML = `<div style="flex:1;min-width:0">
      <div style="font-size:12px;opacity:.65;margin-bottom:6px">本层类型构成（子树扩展名聚合）</div>
      <div style="display:flex;height:12px;border-radius:6px;overflow:hidden">${segs}</div>
      <div style="display:flex;gap:14px;margin-top:6px;font-size:12px;flex-wrap:wrap;opacity:.85">${legend}</div>
    </div>`;
  }

  function renderAnBreadcrumb() {
    const box = document.getElementById('anBreadcrumb');
    if (!box) return;
    if (!an.trail.length) { box.style.display = 'none'; return; }
    box.style.display = 'flex';
    const parts = an.trail.map((n, i) => {
      const cur = i === an.trail.length - 1;
      return `<span class="finder-name-text ${cur ? '' : 'finder-reveal'}" ${cur ? 'style="font-weight:500"' : `style="color:var(--accent);cursor:pointer" data-an-goto="${i}"`} data-tip="${esc(n.paths.join(' | '))}">${esc(n.label)}</span>`;
    }).join('<span style="opacity:.5;margin:0 4px">▸</span>');
    const upBtn = an.trail.length > 1 ? '<button type="button" class="btn btn-secondary btn-small" data-an-up style="margin-left:auto">← 返回上级</button>' : '';
    box.innerHTML = parts + upBtn;
  }

  function renderAn() {
    const el = document.getElementById(CFG.an.table);
    const cur = anCurrent();
    const layer = cur ? an.cache.get(cur.key) : null;
    renderAnBreadcrumb();
    const sumEl = document.getElementById('anTotalSize');
    const cntEl = document.getElementById('anCounts');
    const elapEl = document.getElementById('anElapsed');
    const extBox = document.getElementById('anExtSection');
    if (!layer) {
      el.innerHTML = '<div class="finder-empty">尚未分析。请选择磁盘后点击「开始分析」，或点击「AppData 直达」</div>';
      if (sumEl) sumEl.textContent = '—';
      if (cntEl) cntEl.textContent = '—';
      if (elapEl) elapEl.textContent = '—';
      if (extBox) extBox.style.display = 'none';
      return;
    }
    const sm = layer.summary;
    if (sumEl) sumEl.textContent = sm ? formatSize(sm.size) : '—';
    if (cntEl) cntEl.textContent = sm ? `${Number(sm.dirCount).toLocaleString()} / ${Number(sm.fileCount).toLocaleString()}` : '—';
    if (elapEl) elapEl.textContent = sm ? `${(Number(sm.elapsedMs) / 1000).toFixed(1)} s` : '—';
    renderAnExt(layer);
    if (!layer.dirs.length) {
      el.innerHTML = '<div class="finder-empty">该层没有非空子目录</div>';
      return;
    }
    const total = (sm && sm.size > 0) ? sm.size : (layer.dirs.reduce((a, r) => a + r.size, 0) || 1);
    let html = '<table class="finder-table finder-table-fixed"><thead><tr><th>目录（点击名称下钻）</th><th class="finder-col-size" style="width:110px">大小</th><th style="width:130px">占比</th><th class="finder-col-size" style="width:130px">操作</th></tr></thead><tbody>';
    for (const r of layer.dirs) {
      const pct = Math.min(100, Math.round(r.size * 100 / total));
      html += `<tr>
        <td><div class="finder-cell"><span class="finder-name-text" data-an-drill="${esc(r.path)}" data-tip="点击下钻到 ${esc(r.path)}" style="color:var(--accent);cursor:pointer">${esc(nameOf(r.path))} ▸</span><span class="finder-path-text" style="opacity:.55" data-tip="${esc(r.path)}">${esc(middleEllipsis(r.path, 58))}</span></div></td>
        <td class="finder-col-size">${formatSize(r.size)}</td>
        <td><div style="height:6px;border-radius:3px;background:var(--accent-light)"><div style="height:6px;border-radius:3px;background:var(--accent);width:${pct}%"></div></div></td>
        <td class="finder-col-size"><span class="finder-reveal" data-reveal="${esc(r.path)}" data-tip="在资源管理器中定位" style="cursor:pointer">定位</span> · <span data-an-del="${esc(r.path)}" data-tip="整树移入回收站" style="cursor:pointer;color:var(--danger-text)">删除</span></td>
      </tr>`;
    }
    if (sm && sm.childrenTruncated === 'true') {
      html += `<tr><td colspan="4"><span class="finder-name-text" style="opacity:.6">子目录过多，仅显示最大的 200 个</span></td></tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  }

  // FD-3/FD-5（2026-09-15）：默认勾选与渲染解耦——原 render* 每次 selected.clear() 后重播种，
  // 覆盖「全选」「行内勾选」的用户选择（FD-5：空页全选后 nested=0 目录被重播种取消勾选），
  // 且 duplicates 对 similar/name 组（内容可能不同）也默认全勾（FD-3：一键删互相不同的文件）。
  // 改为扫描完成时按默认规则播种一次，render 只按 selected 现状渲染，不再重置。
  function seedSelection(key) {
    const s = st[key];
    s.selected.clear();
    if (key === 'dups') {
      // 仅「内容相同」组默认勾选可删项；similar/name 组内容可能不同，默认不勾，交用户确认
      s.results.forEach(r => {
        if (r.type === 'duplicate' && r.role !== 'kept' && r.match === 'content') s.selected.add(r.path);
      });
    } else if (key === 'big') {
      s.results.forEach(r => s.selected.add(r.path));
    } else if (key === 'empty') {
      // 空文件全勾；空目录仅默认勾选「连带空子目录」的父目录（nested>0），普通空目录交用户勾选
      s.results.forEach(r => {
        if (r.type === 'emptyfile') s.selected.add(r.path);
        else if (r.type === 'emptyfolder' && (Number(r.nested) || 0) > 0) s.selected.add(r.path);
      });
    }
  }

  // 收集每个页签当前选中的删除项 {path, kind}
  function selectedItems(key) {
    const cfg = CFG[key];
    const s = st[key];
    const kind = cfg.kind === 'dir' ? 'dir' : 'file';
    return s.results.filter(r => s.selected.has(r.path)).map(r => {
      const k = r.type === 'emptyfolder' ? 'dir' : kind;
      return { path: r.path, kind: k };
    });
  }

  function updateAllButtons() {
    for (const key of Object.keys(CFG)) {
      const db = document.getElementById(CFG[key].deleteBtn);
      const sb = document.getElementById(CFG[key].selectBtn);
      if (db) db.disabled = st[key].selected.size === 0 || st[key].scanning || st[key].deleting;
      if (sb) sb.disabled = st[key].results.length === 0 || st[key].scanning;
    }
  }

  async function runScan(key) {
    const cfg = CFG[key];
    const s = st[key];
    if (s.scanning) return;
    s.scanning = true;
    s.results = [];
    s.selected.clear();
    if (key === 'empty') { s.pageF = 1; s.pageD = 1; }
    const scanBtn = document.getElementById(cfg.scanBtn);
    if (scanBtn) { scanBtn.disabled = true; scanBtn.querySelector('span').textContent = '扫描中...'; }
    updateAllButtons();
    // 盘符点选页：一个盘都没选就直接拦下（空结果会被当成「盘很干净」误导）
    if (cfg.drivesEl && readPaths(cfg).length === 0) {
      window.app?.toast?.('warning', '请至少选择一个要扫描的磁盘');
      scanBtn.disabled = false;
      scanBtn.querySelector('span').textContent = '开始扫描';
      updateAllButtons();
      return;
    }
    // 自我安慰式进度：爬升封顶 99%，扫描完成才跳 100%（startFakeProgress 口径）
    setProgress(cfg, 4, '扫描中...');
    startFakeProgress(cfg);
    const opts = { paths: readPaths(cfg) };
    if (cfg.minSizeSel) opts.minSize = Number(document.getElementById(cfg.minSizeSel).value) || 0;
    try {
      const resp = await window.api.finder.scan(cfg.scanType, opts);
      if (!resp.success) throw new Error(resp.message || '扫描失败');
      s.results = resp.data || [];
      seedSelection(key);
      stopFakeProgress(cfg); // 先停伪进度再写 100%，防 ticker 在渲染期间把 100 覆盖回 99.x
      setProgress(cfg, 100, '扫描完成');
      render(key);
      // 审查 M8/B2：空结果不等于「没有重复」。原生侧读不到的目录会计进 errors、
      // 条目到上限会置 truncated，两者都必须显式说出来，否则用户会把「没权限看」
      // 当成「这个目录真干净」，进而相信清理结果是完整的。
      const notes = [];
      if (resp.truncated) notes.push('条目已达扫描上限，结果被截断');
      const errCount = Number(resp.errors) || 0;
      if (errCount > 0) notes.push(`${errCount} 处无法读取`);
      window.app?.toast?.(
        notes.length ? 'warning' : 'success',
        `扫描完成，找到 ${s.results.length} 项` + (notes.length ? `（${notes.join('；')}）` : '')
      );
    } catch (e) {
      hideProgress(cfg);
      window.app?.toast?.('error', '扫描失败: ' + e.message);
    } finally {
      stopFakeProgress(cfg);
      s.scanning = false;
      if (scanBtn) { scanBtn.disabled = false; scanBtn.querySelector('span').textContent = '开始扫描'; }
      updateAllButtons();
      setTimeout(() => hideProgress(cfg), 600);
    }
  }

  function render(key) { RENDER_FN[key](); }

  // 表格行内复选框点击（事件委托）+ 空页分页翻页 + 折叠栏目头 + 大文件定位 + 分析器下钻/删除
  function onTableClick(e, tableId, key) {
    // C-5 分析器：目录下钻 / 行内删除（先于 reveal 判定，属性集互不相交但顺序更稳）
    const drill = e.target.closest('[data-an-drill]');
    if (drill) { anDrill(drill.dataset.anDrill); return; }
    const anDel = e.target.closest('[data-an-del]');
    if (anDel) { anDelete(anDel.dataset.anDel); return; }
    // 大文件路径点击：资源管理器定位（explorer /select，复用 startup:openlocation 通道）
    const reveal = e.target.closest('[data-reveal]');
    if (reveal) {
      if (e.target.closest('[data-fcheck]')) return; // 点在复选框上不触发定位
      window.api.startup.openLocation(reveal.dataset.reveal).catch((err) => {
        window.app?.toast?.('error', '定位失败: ' + (err && err.message ? err.message : err));
      });
      return;
    }
    // 折叠栏目头（空文件/空目录手风琴，2026-09-28 五轮拍板；E-2：折叠态持久化）
    const toggle = e.target.closest('[data-empty-toggle]');
    if (toggle) {
      const pane = toggle.closest('.empty-pane');
      if (pane) {
        pane.classList.toggle('collapsed');
        const collapsed = pane.classList.contains('collapsed');
        toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        const saved = emptyCollapseState();
        if (pane.querySelector('#emptyFilesBox')) saved.files = collapsed;
        else if (pane.querySelector('#emptyDirsBox')) saved.dirs = collapsed;
        try { localStorage.setItem(EMPTY_COLLAPSE_KEY, JSON.stringify(saved)); } catch (_) { /* 存不进就算了 */ }
      }
      return;
    }
    const pg = e.target.closest('[data-pg]');
    if (pg) {
      if (pg.disabled) return;
      const [target, dir] = String(pg.dataset.pg).split(':');
      const s = st[key];
      if (key === 'empty') {
        const one = dir === 'prev' ? -1 : 1;
        if (target === 'files') s.pageF += one;
        else if (target === 'dirs') s.pageD += one;
        render(key);
      }
      return;
    }
    const t = e.target.closest('[data-fcheck]');
    if (!t) return;
    const id = t.dataset.fcheck;
    const idx = id.indexOf('_');
    const path = id.slice(idx + 1);
    const s = st[key];
    if (s.selected.has(path)) s.selected.delete(path); else s.selected.add(path);
    // 更新该行高亮 + 复选框
    const row = t.closest('tr');
    if (row) row.classList.toggle('finder-row-selected', s.selected.has(path));
    t.classList.toggle('checked', s.selected.has(path));
    if (key === 'dups') refreshDupSummary();
    updateAllButtons();
  }

  // 全选/勾选
  function onSelect(key) {
    const cfg = CFG[key];
    const s = st[key];
    if (key === 'dups') {
      // 「勾选重复项」只勾 candidate（角色非 kept）；0 字节等非 duplicate 项不参与本页
      s.results.forEach(r => { if (r.type === 'duplicate' && r.role !== 'kept') s.selected.add(r.path); });
    } else {
      s.results.forEach(r => s.selected.add(r.path));
    }
    render(key);
  }

  async function onDelete(key) {
    const cfg = CFG[key];
    const s = st[key];
    if (s.selected.size === 0 || s.deleting) return;
    const items = selectedItems(key);
    const total = s.results.filter(r => s.selected.has(r.path)).reduce((a, r) => a + (r.size || 0), 0);
    // 删除类操作：规范要求红色二次确认
    const ok = await window.app?.confirmDanger?.(
      '确认删除',
      items.length > 1
        ? `将删除选中的 ${items.length} 项，共约 ${formatSize(total)}。`
        : `将删除选中的 1 项，共约 ${formatSize(total)}。`,
      '确认删除',
      '取消',
      '默认移入回收站（可在回收站还原）；回收站不可用的位置会保留不删除并提示失败。删除项会记录在「已删除清单」中。'
    );
    if (!ok) return;
    s.deleting = true;
    const db = document.getElementById(cfg.deleteBtn);
    if (db) { db.disabled = true; db.querySelector('span').textContent = '删除中...'; }
    setProgress(cfg, 0, '开始删除...');
    try {
      const resp = await window.api.finder.delete(items);
      // 审查 FD-1（2026-09-15）：success 现表示「通道执行成功」，失败明细随 data 如实回传。
      // 仅当通道级失败（无 data）才抛错，避免把「部分失败」升级为整批错报（已删项必须照常移除）。
      if (!resp || (!resp.success && !resp.data)) throw new Error((resp && resp.message) || '删除失败');
      const data = resp.data || {};
      setProgress(cfg, 100, '删除完成');
      // 从结果中移除已删除项
      const removed = new Set((data.details || []).filter(d => d.status === 'ok').map(d => d.path));
      if (removed.size) s.results = s.results.filter(r => !removed.has(r.path));
      removed.forEach(p => s.selected.delete(p));
      render(key);
      const recycledCount = Number(data.recycled) || 0;
      const freedText = formatSize(data.totalFreed || 0);
      const okCount = Number(data.success) || 0;
      if (okCount > 0) {
        window.app?.toast?.('success', recycledCount > 0
          ? `删除完成！${recycledCount} 项已移入回收站（共 ${freedText}，清空回收站后释放）`
          : `删除完成！共 ${freedText}`);
      }
      if (Number(data.failed) > 0) window.app?.toast?.('warning', `${data.failed} 项删除失败（可能被占用）`);
    } catch (e) {
      hideProgress(cfg);
      window.app?.toast?.('error', '删除失败: ' + e.message);
    } finally {
      s.deleting = false;
      if (db) { db.disabled = s.selected.size === 0; db.querySelector('span').textContent = '删除选中'; }
      updateAllButtons();
      setTimeout(() => hideProgress(cfg), 600);
    }
  }

  // 已删除清单：查看最近删除项（含是否已进回收站），支持打开清单目录
  async function showDeleteManifest() {
    if (!window.api?.finder?.deleteManifest) {
      window.app?.toast?.('warning', '当前环境不支持查看删除清单');
      return;
    }
    let resp;
    try {
      resp = await window.api.finder.deleteManifest();
    } catch (e) {
      window.app?.toast?.('error', '读取删除清单失败: ' + e.message);
      return;
    }
    if (!resp || !resp.success) {
      window.app?.toast?.('error', (resp && resp.message) || '读取删除清单失败');
      return;
    }
    const items = Array.isArray(resp.data?.items) ? resp.data.items : [];
    const rows = items.slice(0, 50).map(it => `
      <tr>
        <td data-tip="${esc(it.path)}">${esc(middleEllipsis(it.path, 56))}</td>
        <td class="finder-col-size">${esc(formatSize(it.size))}</td>
        <td>${it.recycled ? '回收站' : '永久删除'}</td>
        <td>${esc(String(it.deletedAt || '').replace('T', ' ').slice(0, 19))}</td>
      </tr>`).join('');
    const ctrl = window.modal?.create?.({
      id: 'finderManifestModal',
      title: '已删除清单',
      width: 720,
      bodyHtml: items.length
        ? `<div class="confirm-message">最近删除的 ${items.length} 项（最多显示 50 条）。已进回收站的文件可在系统回收站中还原。</div>
           <div style="max-height:340px;overflow:auto;margin-top:10px">
             <table class="finder-table"><thead><tr><th>路径</th><th class="finder-col-size" style="width:90px">大小</th><th style="width:80px">方式</th><th style="width:150px">时间</th></tr></thead><tbody>${rows}</tbody></table>
           </div>`
        : `<div class="empty-state"><p>暂无删除记录。执行文件删除后会自动记录到 %APPDATA%\\Trim\\fileclean-backup\\。</p></div>`,
      footerHtml: `
        <span class="model-picker-spacer"></span>
        <button class="btn btn-secondary" data-manifest-dir type="button">打开清单目录</button>
        <button class="btn btn-primary" data-manifest-close type="button">关闭</button>`
    });
    if (!ctrl) return;
    ctrl.footer.querySelector('[data-manifest-dir]').addEventListener('click', async () => {
      // 审查 v2-L8：原先 `catch (e) {}` 整条吞掉 —— 通道缺席或后端失败时用户点了
      // 「打开清单目录」毫无反应，也不知该去哪找。失败必须显式反馈。
      try {
        await window.api.finder.openBackupDir();
      } catch (e) {
        window.app?.toast?.('error', '打开清单目录失败：' + (e && e.message ? e.message : e));
      }
    });
    ctrl.footer.querySelector('[data-manifest-close]').addEventListener('click', () => ctrl.close());
  }

  // E-2：空页手风琴折叠态持久化（localStorage；缺省=空文件展开、空目录折叠，
  // 与 index.html 静态默认一致）。pane 是静态容器，renderEmpty 不重建，init 时应用一次即可。
  const EMPTY_COLLAPSE_KEY = 'finder-empty-collapsed-v1';
  function emptyCollapseState() {
    try { return JSON.parse(localStorage.getItem(EMPTY_COLLAPSE_KEY)) || {}; } catch (_) { return {}; }
  }
  function applyEmptyCollapse() {
    const saved = emptyCollapseState();
    const pf = document.getElementById('emptyFilesBox')?.closest('.empty-pane');
    const pd = document.getElementById('emptyDirsBox')?.closest('.empty-pane');
    if (pf) pf.classList.toggle('collapsed', saved.files === true);
    if (pd) pd.classList.toggle('collapsed', saved.dirs !== false);
  }

  function bindEvents() {
    applyEmptyCollapse();
    for (const key of Object.keys(CFG)) {
      const cfg = CFG[key];
      document.getElementById(cfg.scanBtn)?.addEventListener('click', () => runScan(key));
      document.getElementById(cfg.selectBtn)?.addEventListener('click', () => onSelect(key));
      document.getElementById(cfg.deleteBtn)?.addEventListener('click', () => onDelete(key));
      // 表格复选框委托 + 分页翻页 + 折叠栏目头（dups/big 名为 dup/big；empty 用自己表 id）
      document.getElementById(cfg.table)?.addEventListener('click', e => onTableClick(e, cfg.table, key));
      // 盘符点选器（big/empty/an）：委托点击 + 拉取盘符渲染（默认全选）
      if (cfg.drivesEl) {
        document.getElementById(cfg.drivesEl)?.addEventListener('click', onDriveClick);
        initDrivePicker(key);
      }
    }
    // C-5 分析器：自有扫描/直达/面包屑导航
    document.getElementById('anBtnScan')?.addEventListener('click', startAnalyzeRoots);
    document.getElementById('anBtnAppData')?.addEventListener('click', anAppData);
    document.getElementById('anBreadcrumb')?.addEventListener('click', (e) => {
      const goto_ = e.target.closest('[data-an-goto]');
      if (goto_) { anGoto(Number(goto_.dataset.anGoto)); return; }
      if (e.target.closest('[data-an-up]')) anUp();
    });
    // 已删除清单入口（三个子页工具栏共用 data 属性委托）
    document.querySelectorAll('[data-finder-manifest]').forEach(btn => {
      btn.addEventListener('click', showDeleteManifest);
    });
    if (window.api?.finder?.onProgress && !subscribed) {
      subscribed = true;
      window.api.finder.onProgress(onProgress);
    }
  }

  function ensureInit() {
    if (inited) return;
    inited = true;
    bindEvents();
  }

  window.finder = { ensureInit };

  // 首帧后自动初始化（若 app.js 未触发，兜底）
  if (document.readyState !== 'loading') { ensureInit(); }
  else document.addEventListener('DOMContentLoaded', ensureInit);
})();