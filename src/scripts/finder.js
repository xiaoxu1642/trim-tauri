// finder.js - 磁盘清理 · Rust 原生查找器（重复/大文件/空/AppData）
// 四个子页共用一套「布尔进度 + @@PROGRESS:n@@ 上报管线」：
// 主进程 spawn finder.exe 并以 finder:progress 推送进度，扫描完成一次性返回结果数组。
// 样式完全复用 .card / .table-card / .opt-* / .summary-card 主题语义。
(function () {
  'use strict';

  let inited = false;
  let subscribed = false;

  // 每个页签独立状态
  const st = {
    dups:    { results: [], selected: new Set(), scanning: false, deleting: false },
    big:     { results: [], selected: new Set(), scanning: false, deleting: false },
    empty:   { results: [], selected: new Set(), scanning: false, deleting: false },
    appdata: { results: [], selected: new Set(), scanning: false, deleting: false }
  };

  // 页签 -> 元素 id / 参数来源 / scanType 映射
  const CFG = {
    dups: {
      scanType: 'duplicates', kind: 'file',
      scanBtn: 'dupBtnScan', selectBtn: 'dupBtnSelect', deleteBtn: 'dupBtnDelete',
      pathInput: 'dupPath', minSizeSel: 'dupMinSize',
      progress: { section: 'dupProgressSection', label: 'dupProgressLabel', value: 'dupProgressValue', fill: 'dupProgressFill' },
      table: 'dupTable', groupCount: 'dupGroupCount', size: 'dupSize'
    },
    big: {
      scanType: 'bigfiles', kind: 'file',
      scanBtn: 'bigBtnScan', selectBtn: 'bigBtnSelect', deleteBtn: 'bigBtnDelete',
      pathInput: 'bigPath', countSel: 'bigCount',
      progress: { section: 'bigProgressSection', label: 'bigProgressLabel', value: 'bigProgressValue', fill: 'bigProgressFill' },
      table: 'bigTable'
    },
    empty: {
      scanType: 'empty', kind: 'both',
      scanBtn: 'emptyBtnScan', selectBtn: 'emptyBtnSelect', deleteBtn: 'emptyBtnDelete',
      pathInput: 'emptyPath',
      progress: { section: 'emptyProgressSection', label: 'emptyProgressLabel', value: 'emptyProgressValue', fill: 'emptyProgressFill' },
      table: 'emptyTable', fileCount: 'emptyCount', dirCount: 'emptyDirCount'
    },
    appdata: {
      scanType: 'appdata', kind: 'dir',
      scanBtn: 'appdataBtnScan', selectBtn: 'appdataBtnSelect', deleteBtn: 'appdataBtnDelete',
      minSel: 'appdataMinSize',
      progress: { section: 'appdataProgressSection', label: 'appdataProgressLabel', value: 'appdataProgressValue', fill: 'appdataProgressFill' },
      table: 'appdataTable'
    }
  };

  function formatSize(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1);
    const v = bytes / Math.pow(k, i);
    return v.toFixed(v < 10 && i > 0 ? 2 : v < 100 && i > 0 ? 1 : 0) + ' ' + units[i];
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function middleEllipsis(s, max) {
    s = String(s || '');
    if (s.length <= max) return s;
    const keep = Math.floor((max - 1) / 2);
    return s.slice(0, keep) + '…' + s.slice(s.length - keep);
  }

  // 读取路径输入：逗号分隔 → 数组；「默认」为占位词，交给主进程解析内置目录
  function readPaths(cfg) {
    const el = document.getElementById(cfg.pathInput);
    if (!el) return [];
    return el.value.split(',').map(s => s.trim())
      .filter(s => s && s !== '默认' && s.toLowerCase() !== 'default');
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

  // 主进程流式进度（@@PROGRESS:n@@ 管线终点）+ P0 心跳（@@SCANNED:n@@）
  function onProgress(p) {
    if (!p || !p.scanType) return;
    for (const key of Object.keys(CFG)) {
      if (CFG[key].scanType === p.scanType && st[key].scanning) {
        if (typeof p.scanned === 'number') {
          // 心跳：只更新文案为「已枚举文件数」，进度条保持不动（百分比未到 100 不算完成）
          const lab = document.getElementById(CFG[key].progress.label);
          const sec = document.getElementById(CFG[key].progress.section);
          if (sec) sec.style.display = 'block';
          if (lab) lab.textContent = `扫描中... 已枚举 ${p.scanned.toLocaleString()} 个文件`;
        } else if (typeof p.progress === 'number') {
          setProgress(CFG[key], p.progress, `扫描中... ${Math.round(p.progress)}%`);
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
  // match 字段由 finder.exe 输出：content=内容指纹相同 / similar=文档内容相似 / name=文件名相同
  const DUP_MATCH_LABEL = { content: '内容相同组', similar: '相似文档组', name: '同名文件组' };

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
      if (g.match === 'similar' && g.sim) head += ` · 相似度 ${esc(String(g.sim))}`;
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
  function renderBig() {
    const el = document.getElementById(CFG.big.table);
    const cfg = CFG.big;
    const s = st.big;
    if (!s.results.length) {
      el.innerHTML = '<div class="finder-empty">尚未扫描。请选择目录后点击「开始扫描」</div>';
      return;
    }
    let html = '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>名称 / 路径</th><th class="finder-col-size" style="width:130px">大小</th></tr></thead><tbody>';
    for (const r of s.results) {
      const checked = s.selected.has(r.path);
      html += `<tr class="${checked ? 'finder-row-selected' : ''}">
        <td>${checkboxHtml('big_' + esc(r.path), checked)}</td>
        <td><div class="finder-cell"><span class="finder-name-text">${esc(nameOf(r.path))}</span><span class="finder-name-text" style="opacity:.55">·</span><span class="finder-path-text" data-tip="${esc(r.path)}">${esc(middleEllipsis(r.path, 76))}</span></div></td>
        <td class="finder-col-size">${formatSize(r.size)}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
    updateAllButtons();
  }

  // ==================== 空文件 / 空目录 ====================
  function renderEmpty() {
    const el = document.getElementById(CFG.empty.table);
    const cfg = CFG.empty;
    const s = st.empty;
    const files = s.results.filter(r => r.type === 'emptyfile');
    const dirs = s.results.filter(r => r.type === 'emptyfolder');
    document.getElementById(cfg.fileCount).textContent = files.length;
    document.getElementById(cfg.dirCount).textContent = dirs.length;
    if (!s.results.length) {
      el.innerHTML = '<div class="finder-empty">未发现空文件与空目录，或尚未扫描</div>';
      return;
    }
    let html = '';
    if (files.length) {
      html += '<div class="finder-group-header"><span>空文件（0 字节）· ' + files.length + ' 个</span></div>';
      html += '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>名称 / 路径</th></tr></thead><tbody>';
      for (const r of files) {
        const checked = s.selected.has(r.path);
        html += `<tr class="${checked ? 'finder-row-selected' : ''}"><td>${checkboxHtml('ef_' + esc(r.path), checked)}</td><td><div class="finder-cell"><span class="finder-name-text">${esc(nameOf(r.path))}</span><span class="finder-name-text" style="opacity:.55">·</span><span class="finder-path-text" data-tip="${esc(r.path)}">${esc(middleEllipsis(r.path, 80))}</span></div></td></tr>`;
      }
      html += '</tbody></table>';
    }
    if (dirs.length) {
      html += '<div class="finder-group-header"><span>空目录 · ' + dirs.length + ' 个</span><span class="finder-group-sum">删除空目录可释放少量空间，并可避免应用误判</span></div>';
      html += '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>路径</th><th style="width:110px">连带空目录</th></tr></thead><tbody>';
      for (const r of dirs) {
        const nested = Number(r.nested) || 0;
        const checked = s.selected.has(r.path);
        const nestedCell = nested > 0
          ? `<span class="finder-name-text" data-tip="删除该目录会一并移除其下 ${nested} 个空子目录">${nested} 个</span>`
          : '<span class="finder-name-text" style="opacity:.55">—</span>';
        html += `<tr class="${checked ? 'finder-row-selected' : ''}"><td>${checkboxHtml('ed_' + esc(r.path), checked)}</td><td><div class="finder-cell"><span class="finder-name-text">${esc(nameOf(r.path))}</span><span class="finder-name-text" style="opacity:.55">·</span><span class="finder-path-text" data-tip="${esc(r.path)}">${esc(middleEllipsis(r.path, 74))}</span></div></td><td class="finder-col-size">${nestedCell}</td></tr>`;
      }
      html += '</tbody></table>';
    }
    el.innerHTML = html;
    updateAllButtons();
  }

  // ==================== AppData ====================
  function renderAppdata() {
    const el = document.getElementById(CFG.appdata.table);
    const cfg = CFG.appdata;
    const s = st.appdata;
    if (!s.results.length) {
      el.innerHTML = '<div class="finder-empty">尚未统计。点击「开始统计」查看 AppData 大目录</div>';
      return;
    }
    // 含 LOCALAPPDATA 与 APPDATA 两类根；按 root 分组展示
    const byRoot = new Map();
    for (const r of s.results) {
      const root = r.root || '';
      if (!byRoot.has(root)) byRoot.set(root, []);
      byRoot.get(root).push(r);
    }
    let html = '';
    for (const [root, rows] of byRoot) {
      html += `<div class="finder-group-header"><span>${root || 'AppData'}</span><span class="finder-group-sum">${rows.length} 个目录</span></div>`;
      html += '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>应用目录</th><th class="finder-col-size" style="width:130px">占用</th></tr></thead><tbody>';
      for (const r of rows) {
        const checked = s.selected.has(r.path);
        html += `<tr class="${checked ? 'finder-row-selected' : ''}">
          <td>${checkboxHtml('ad_' + esc(r.path), checked)}</td>
          <td><div class="finder-cell"><span class="finder-name-text">${esc(nameOf(r.path))}</span><span class="finder-name-text" style="opacity:.55">·</span><span class="finder-path-text" data-tip="${esc(r.path)}">${esc(middleEllipsis(r.path, 60))}</span></div></td>
          <td class="finder-col-size">${formatSize(r.size)}</td>
        </tr>`;
      }
      html += '</tbody></table>';
    }
    el.innerHTML = html;
    updateAllButtons();
  }

  const RENDER_FN = { dups: renderDups, big: renderBig, empty: renderEmpty, appdata: renderAppdata };

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
    // appdata：默认不勾
  }

  // 收集每个页签当前选中的删除项 {path, kind}
  function selectedItems(key) {
    const cfg = CFG[key];
    const s = st[key];
    const kind = cfg.kind === 'dir' ? 'dir' : (cfg.kind === 'both' ? 'file' : 'file');
    return s.results.filter(r => s.selected.has(r.path)).map(r => {
      const k = r.type === 'emptyfolder' || r.type === 'appdata' ? 'dir' : (cfg.kind === 'dir' ? 'dir' : 'file');
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
    const scanBtn = document.getElementById(cfg.scanBtn);
    if (scanBtn) { scanBtn.disabled = true; scanBtn.querySelector('span').textContent = '扫描中...'; }
    updateAllButtons();
    setProgress(cfg, 2, '正在准备...');
    const opts = { paths: readPaths(cfg) };
    if (cfg.minSizeSel) opts.minSize = Number(document.getElementById(cfg.minSizeSel).value) || 0;
    if (cfg.minSel) opts.minSizeMb = Number(document.getElementById(cfg.minSel).value) || 10;
    if (cfg.countSel) opts.count = Number(document.getElementById(cfg.countSel).value) || 50;
    try {
      const resp = await window.api.finder.scan(cfg.scanType, opts);
      if (!resp.success) throw new Error(resp.message || '扫描失败');
      s.results = resp.data || [];
      seedSelection(key);
      setProgress(cfg, 100, '扫描完成');
      render(key);
      window.app?.toast?.('success', `扫描完成，找到 ${s.results.length} 项`);
    } catch (e) {
      hideProgress(cfg);
      window.app?.toast?.('error', '扫描失败: ' + e.message);
    } finally {
      s.scanning = false;
      if (scanBtn) { scanBtn.disabled = false; scanBtn.querySelector('span').textContent = cfg.scanType === 'appdata' ? '开始统计' : '开始扫描'; }
      updateAllButtons();
      setTimeout(() => hideProgress(cfg), 600);
    }
  }

  function render(key) { RENDER_FN[key](); }

  // 表格行内复选框点击（事件委托）
  function onTableClick(e, tableId, key) {
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
      try { await window.api.finder.openBackupDir(); } catch (e) {}
    });
    ctrl.footer.querySelector('[data-manifest-close]').addEventListener('click', () => ctrl.close());
  }

  function bindEvents() {
    for (const key of Object.keys(CFG)) {
      const cfg = CFG[key];
      document.getElementById(cfg.scanBtn)?.addEventListener('click', () => runScan(key));
      document.getElementById(cfg.selectBtn)?.addEventListener('click', () => onSelect(key));
      document.getElementById(cfg.deleteBtn)?.addEventListener('click', () => onDelete(key));
      // 表格复选框委托：dups/big 名为 dup/big；empty/appdata 用各自表 id
      document.getElementById(cfg.table)?.addEventListener('click', e => onTableClick(e, cfg.table, key));
    }
    // 已删除清单入口（四个子页工具栏共用 data 属性委托）
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